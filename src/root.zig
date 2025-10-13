//! GVault - Terminal Keychain Manager
//! A secure credential management library for terminal emulators

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const zcrypto = @import("zcrypto");

pub const ServerPatternKind = enum {
    exact,
    wildcard,
    regex,
    cidr,
};

pub const ServerPattern = struct {
    value: []const u8,
    kind: ServerPatternKind,
};

pub const PatternSpec = struct {
    value: []const u8,
    kind: ServerPatternKind = .exact,
};

// Storage module for persistent database
const storage = @import("storage.zig");
pub const Storage = storage;

// Secure memory module for mlock and secure zeroing
const secure_mem = @import("secure_mem.zig");

pub const GVaultError = error{
    InvalidPassphrase,
    VaultLocked,
    CredentialNotFound,
    EncryptionError,
    DecryptionError,
    InvalidCredentialType,
    StorageError,
    InvalidKDF,
    SaltGenerationError,
};

/// Key Derivation Function algorithms supported
pub const KDFAlgorithm = enum {
    argon2id, // Recommended - Post-2015 standard (RFC 9106)
    sha256, // Legacy compatibility
    sha512, // Legacy compatibility
    sha3_256, // Modern SHA-3 support
    sha3_512, // Modern SHA-3 support
};

/// Credential types supported by GVault
pub const CredentialType = enum {
    ssh_key, // ED25519, RSA, ECDSA
    gpg_key, // RSA, EdDSA
    api_token,
    password,
    certificate,
    server_config,
};

/// Unique identifier for credentials
pub const CredentialId = struct {
    bytes: [16]u8,

    pub fn generate() CredentialId {
        var id: CredentialId = undefined;
        crypto.random.bytes(&id.bytes);
        return id;
    }

    pub fn fromString(str: []const u8) !CredentialId {
        if (str.len != 32) return error.InvalidIdLength;
        var id: CredentialId = undefined;
        _ = std.fmt.hexToBytes(&id.bytes, str) catch return error.InvalidIdFormat;
        return id;
    }

    pub fn toString(self: CredentialId, buf: []u8) ![]u8 {
        if (buf.len < 32) return error.BufferTooSmall;
        const hex_string = std.fmt.bytesToHex(&self.bytes, .lower);
        @memcpy(buf[0..32], &hex_string);
        return buf[0..32];
    }
};

/// Metadata associated with credentials
pub const CredentialMetadata = struct {
    created: i64,
    last_used: ?i64,
    auto_load: bool,
    tags: ArrayList([]const u8),
    server_patterns: ?ArrayList(ServerPattern),

    pub fn init() CredentialMetadata {
        return CredentialMetadata{
            .created = std.time.timestamp(),
            .last_used = null,
            .auto_load = false,
            .tags = .{},
            .server_patterns = null,
        };
    }

    pub fn deinit(self: *CredentialMetadata, allocator: Allocator) void {
        for (self.tags.items) |tag| {
            allocator.free(tag);
        }
        self.tags.deinit(allocator);
        if (self.server_patterns) |*patterns| {
            for (patterns.items) |pattern| {
                allocator.free(pattern.value);
            }
            patterns.deinit(allocator);
            self.server_patterns = null;
        }
    }

    pub fn addServerPattern(self: *CredentialMetadata, allocator: Allocator, pattern: []const u8, kind: ServerPatternKind) !void {
        const pattern_copy = try allocator.dupe(u8, pattern);

        if (self.server_patterns) |*patterns| {
            try patterns.append(allocator, .{ .value = pattern_copy, .kind = kind });
        } else {
            var list = ArrayList(ServerPattern){};
            errdefer allocator.free(pattern_copy);
            try list.append(allocator, .{ .value = pattern_copy, .kind = kind });
            self.server_patterns = list;
        }
    }

    pub fn clearServerPatterns(self: *CredentialMetadata, allocator: Allocator) void {
        if (self.server_patterns) |*patterns| {
            for (patterns.items) |pat| {
                allocator.free(pat.value);
            }
            patterns.clearAndFree(allocator);
            self.server_patterns = null;
        }
    }
};

/// A stored credential with encrypted data
pub const Credential = struct {
    id: CredentialId,
    name: []const u8,
    type: CredentialType,
    encrypted_data: []const u8,
    metadata: CredentialMetadata,

    pub fn deinit(self: *Credential, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.encrypted_data);
        self.metadata.deinit(allocator);
    }
};

/// Main vault structure for secure credential storage
pub const Vault = struct {
    allocator: Allocator,
    vault_path: []const u8,
    master_key: ?[32]u8,
    salt: [32]u8, // Cryptographic salt for KDF
    kdf_algorithm: KDFAlgorithm,
    credentials: ArrayList(Credential),
    is_locked: bool,
    auto_lock_timeout: ?u32,
    db: ?*storage.VaultDatabase, // Persistent storage database

    pub fn init(allocator: Allocator, vault_path: []const u8) !Vault {
        // Create vault directory if it doesn't exist
        std.fs.cwd().makePath(vault_path) catch |err| {
            switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            }
        };

        // Generate cryptographic salt
        var salt: [32]u8 = undefined;
        crypto.random.bytes(&salt);

        // Initialize database
        const db_path = try std.fmt.allocPrint(allocator, "{s}/vault.db", .{vault_path});
        defer allocator.free(db_path);

        const db = try storage.VaultDatabase.init(allocator, db_path);

        // Try to load existing metadata
        const metadata = try db.loadMetadata();
        if (metadata) |meta| {
            var meta_copy = meta;
            defer meta_copy.deinit(db.allocator);

            // Existing vault - load salt and KDF from database
            @memcpy(&salt, meta.salt);
            const kdf = std.meta.stringToEnum(KDFAlgorithm, meta.kdf_algorithm) orelse .argon2id;

            return Vault{
                .allocator = allocator,
                .vault_path = try allocator.dupe(u8, vault_path),
                .master_key = null,
                .salt = salt,
                .kdf_algorithm = kdf,
                .credentials = .{},
                .is_locked = true,
                .auto_lock_timeout = if (meta.auto_lock_timeout) |t| @intCast(t) else null,
                .db = db,
            };
        }

        // New vault - save initial metadata
        var integrity_hash: [32]u8 = undefined;
        crypto.random.bytes(&integrity_hash);

        try db.upsertMetadata(.{
            .version = "0.1.0",
            .kdf_algorithm = @tagName(KDFAlgorithm.argon2id),
            .salt = &salt,
            .auto_lock_timeout = null,
            .integrity_hash = &integrity_hash,
        });

        return Vault{
            .allocator = allocator,
            .vault_path = try allocator.dupe(u8, vault_path),
            .master_key = null,
            .salt = salt,
            .kdf_algorithm = .argon2id, // Default to Argon2id (recommended)
            .credentials = .{},
            .is_locked = true,
            .auto_lock_timeout = null,
            .db = db,
        };
    }

    pub fn deinit(self: *Vault) void {
        self.lock();
        for (self.credentials.items) |*cred| {
            cred.deinit(self.allocator);
        }
        self.credentials.deinit(self.allocator);
        self.allocator.free(self.vault_path);

        // Close database connection
        if (self.db) |db| {
            db.deinit();
        }
    }

    /// Unlock the vault with a passphrase using configured KDF algorithm
    pub fn unlock(self: *Vault, passphrase: []const u8) !void {
        var master_key: [32]u8 = undefined;

        // Derive master key using selected algorithm
        switch (self.kdf_algorithm) {
            .argon2id => {
                // Argon2id - Recommended (RFC 9106)
                // Memory: 64MB, Time: 3 iterations, Parallelism: 4
                try crypto.pwhash.argon2.kdf(
                    self.allocator,
                    &master_key,
                    passphrase,
                    &self.salt,
                    .{ .t = 3, .m = 65536, .p = 4 },
                    .argon2id,
                );
            },
            .sha256 => {
                // SHA-256 - Legacy compatibility
                var hasher = crypto.hash.sha2.Sha256.init(.{});
                hasher.update(&self.salt);
                hasher.update(passphrase);
                hasher.final(&master_key);
            },
            .sha512 => {
                // SHA-512 - Legacy compatibility
                var hasher = crypto.hash.sha2.Sha512.init(.{});
                hasher.update(&self.salt);
                hasher.update(passphrase);
                var hash: [64]u8 = undefined;
                hasher.final(&hash);
                @memcpy(&master_key, hash[0..32]); // Use first 32 bytes
            },
            .sha3_256 => {
                // SHA3-256 - Modern alternative
                var hasher = crypto.hash.sha3.Sha3_256.init(.{});
                hasher.update(&self.salt);
                hasher.update(passphrase);
                hasher.final(&master_key);
            },
            .sha3_512 => {
                // SHA3-512 - Modern alternative
                var hasher = crypto.hash.sha3.Sha3_512.init(.{});
                hasher.update(&self.salt);
                hasher.update(passphrase);
                var hash: [64]u8 = undefined;
                hasher.final(&hash);
                @memcpy(&master_key, hash[0..32]); // Use first 32 bytes
            },
        }

        self.master_key = master_key;

        // Lock master key in memory to prevent swapping to disk
        if (self.master_key) |*key| {
            const ptr: [*]u8 = @ptrCast(key);
            secure_mem.lockMemory(ptr, 32) catch |err| {
                std.log.warn("Failed to lock master key in memory: {}", .{err});
            };
        }

        self.is_locked = false;

        // Load existing credentials
        try self.loadCredentials();
    }

    /// Lock the vault and clear sensitive data
    pub fn lock(self: *Vault) void {
        if (self.master_key) |*key| {
            const ptr: [*]u8 = @ptrCast(key);

            // Unlock memory before zeroing
            secure_mem.unlockMemory(ptr, 32) catch |err| {
                std.log.warn("Failed to unlock master key memory: {}", .{err});
            };

            // Securely zero the key memory using secure_mem module
            secure_mem.secureZero(ptr, 32);
            self.master_key = null;
        }

        // Clear credential data
        for (self.credentials.items) |*cred| {
            cred.deinit(self.allocator);
        }
        self.credentials.clearAndFree(self.allocator);

        self.is_locked = true;
    }

    /// Check if vault is unlocked
    pub fn isUnlocked(self: *Vault) bool {
        return !self.is_locked and self.master_key != null;
    }

    /// Set auto-lock timeout in seconds
    pub fn setAutoLock(self: *Vault, timeout_seconds: u32) void {
        self.auto_lock_timeout = timeout_seconds;
    }

    /// Change KDF algorithm (requires vault to be unlocked)
    pub fn setKDFAlgorithm(self: *Vault, algorithm: KDFAlgorithm) !void {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;
        self.kdf_algorithm = algorithm;
        try self.saveCredentials(); // Persist the change
    }

    /// Encrypt data using ChaCha20-Poly1305
    pub fn encrypt(self: *Vault, plaintext: []const u8, allocator: Allocator) ![]u8 {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        const key = self.master_key.?;
        var nonce: [12]u8 = undefined;
        crypto.random.bytes(&nonce);

        // Allocate space for nonce + ciphertext + tag
        const encrypted_size = nonce.len + plaintext.len + 16;
        var encrypted = try allocator.alloc(u8, encrypted_size);

        // Copy nonce to beginning
        @memcpy(encrypted[0..nonce.len], &nonce);

        // Encrypt data using zcrypto's ChaCha20-Poly1305
        const ciphertext = encrypted[nonce.len .. encrypted.len - 16];
        const tag = encrypted[encrypted.len - 16 ..];

        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext,
            tag[0..16],
            plaintext,
            &.{}, // No additional data
            nonce,
            key,
        );

        return encrypted;
    }

    /// Decrypt data using ChaCha20-Poly1305
    pub fn decrypt(self: *Vault, encrypted: []const u8, allocator: Allocator) ![]u8 {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;
        if (encrypted.len < 28) return GVaultError.DecryptionError; // nonce + tag minimum

        const key = self.master_key.?;
        const nonce = encrypted[0..12];
        const ciphertext = encrypted[12 .. encrypted.len - 16];
        const tag = encrypted[encrypted.len - 16 ..];

        const plaintext = try allocator.alloc(u8, ciphertext.len);

        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext,
            tag[0..16].*,
            &.{}, // No additional data
            nonce.*,
            key,
        ) catch {
            allocator.free(plaintext);
            return GVaultError.DecryptionError;
        };

        return plaintext;
    }

    /// Load credentials from storage
    fn loadCredentials(self: *Vault) !void {
        if (self.db == null) return;

        const db = self.db.?;

        // Load encrypted credentials from database
        var cred_rows = try db.loadCredentials(self.allocator);
        defer {
            for (cred_rows.items) |row| {
                self.allocator.free(row.credential_type);
                self.allocator.free(row.name);
                self.allocator.free(row.username);
                self.allocator.free(row.password);
                self.allocator.free(row.nonce);
                self.allocator.free(row.auth_tag);
            }
            cred_rows.deinit(self.allocator);
        }

        // Decrypt and reconstruct credentials
        for (cred_rows.items) |row| {
            // Reconstruct encrypted blob: nonce + ciphertext + tag
            const encrypted_data = try self.allocator.alloc(u8, row.nonce.len + row.username.len + row.auth_tag.len);
            @memcpy(encrypted_data[0..row.nonce.len], row.nonce);
            @memcpy(encrypted_data[row.nonce.len .. row.nonce.len + row.username.len], row.username);
            @memcpy(encrypted_data[row.nonce.len + row.username.len ..], row.auth_tag);

            // Parse credential type
            const cred_type = std.meta.stringToEnum(CredentialType, row.credential_type) orelse .password;

            // Load tags
            const tags = try db.loadCredentialTags(row.id, self.allocator);

            // Create credential ID from database ID (simplified for now)
            const id = CredentialId.generate();

            const credential = Credential{
                .id = id,
                .name = try self.allocator.dupe(u8, row.name),
                .type = cred_type,
                .encrypted_data = encrypted_data,
                .metadata = .{
                    .created = row.created_at,
                    .last_used = row.last_used,
                    .auto_load = false,
                    .tags = tags,
                    .server_patterns = null,
                },
            };

            try self.credentials.append(self.allocator, credential);
        }

        // Log audit event
        try db.logAudit(.{
            .event_type = "vault_unlock",
            .resource_type = null,
            .resource_id = null,
            .action = "load_credentials",
            .result = "success",
            .details = null,
            .ip_address = null,
            .user_agent = null,
        });
    }

    /// Save credentials to storage
    fn saveCredentials(self: *Vault) !void {
        if (self.db == null) return;

        const db = self.db.?;

        for (self.credentials.items) |cred| {
            // Extract nonce, ciphertext, and tag from encrypted_data
            if (cred.encrypted_data.len < 28) continue; // Invalid encrypted data

            const nonce = cred.encrypted_data[0..12];
            const ciphertext_len = cred.encrypted_data.len - 28; // Total - nonce(12) - tag(16)
            const ciphertext = cred.encrypted_data[12 .. 12 + ciphertext_len];
            const tag = cred.encrypted_data[cred.encrypted_data.len - 16 ..];

            // Save credential row
            const row = storage.CredentialRow{
                .id = 0, // Will be set by database
                .credential_type = @tagName(cred.type),
                .name = cred.name,
                .username = ciphertext, // Store ciphertext as username field
                .password = &[_]u8{}, // Empty for now
                .nonce = nonce,
                .auth_tag = tag,
                .created_at = cred.metadata.created,
                .modified_at = std.time.timestamp(),
                .last_used = cred.metadata.last_used,
            };

            const cred_id = try db.saveCredential(row);

            // Save tags
            for (cred.metadata.tags.items) |tag_name| {
                try db.saveCredentialTag(cred_id, tag_name);
            }
        }

        // Log audit event
        try db.logAudit(.{
            .event_type = "vault_save",
            .resource_type = null,
            .resource_id = null,
            .action = "save_credentials",
            .result = "success",
            .details = null,
            .ip_address = null,
            .user_agent = null,
        });
    }

    // CRUD Operations for Credentials

    /// Add a new credential to the vault
    pub fn addCredential(self: *Vault, name: []const u8, cred_type: CredentialType, data: []const u8) !CredentialId {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        const id = CredentialId.generate();
        const encrypted_data = try self.encrypt(data, self.allocator);

        const credential = Credential{
            .id = id,
            .name = try self.allocator.dupe(u8, name),
            .type = cred_type,
            .encrypted_data = encrypted_data,
            .metadata = CredentialMetadata.init(),
        };

        try self.credentials.append(self.allocator, credential);
        try self.saveCredentials();

        return id;
    }

    /// Get a credential by ID
    pub fn getCredential(self: *Vault, id: CredentialId) !Credential {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        for (self.credentials.items) |cred| {
            if (std.mem.eql(u8, &cred.id.bytes, &id.bytes)) {
                return cred;
            }
        }

        return GVaultError.CredentialNotFound;
    }

    /// Get decrypted credential data
    pub fn getCredentialData(self: *Vault, id: CredentialId) ![]u8 {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        const credential = try self.getCredential(id);
        return try self.decrypt(credential.encrypted_data, self.allocator);
    }

    /// Update a credential's data
    pub fn updateCredential(self: *Vault, id: CredentialId, new_data: []const u8) !void {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        for (self.credentials.items) |*cred| {
            if (std.mem.eql(u8, &cred.id.bytes, &id.bytes)) {
                // Free old encrypted data
                self.allocator.free(cred.encrypted_data);

                // Encrypt new data
                cred.encrypted_data = try self.encrypt(new_data, self.allocator);
                cred.metadata.last_used = std.time.timestamp();

                try self.saveCredentials();
                return;
            }
        }

        return GVaultError.CredentialNotFound;
    }

    /// Delete a credential
    pub fn deleteCredential(self: *Vault, id: CredentialId) !void {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        for (self.credentials.items, 0..) |cred, i| {
            if (std.mem.eql(u8, &cred.id.bytes, &id.bytes)) {
                var removed_cred = self.credentials.swapRemove(i);
                removed_cred.deinit(self.allocator);
                try self.saveCredentials();
                return;
            }
        }

        return GVaultError.CredentialNotFound;
    }

    /// Replace the pattern list associated with a credential used for host matching
    pub fn setCredentialPatterns(self: *Vault, id: CredentialId, patterns: []const PatternSpec) !void {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        for (self.credentials.items) |*cred| {
            if (std.mem.eql(u8, &cred.id.bytes, &id.bytes)) {
                cred.metadata.clearServerPatterns(self.allocator);
                errdefer cred.metadata.clearServerPatterns(self.allocator);

                for (patterns) |spec| {
                    try cred.metadata.addServerPattern(self.allocator, spec.value, spec.kind);
                }

                try self.saveCredentials();
                return;
            }
        }

        return GVaultError.CredentialNotFound;
    }

    /// List all credentials (returns metadata only, not decrypted data)
    pub fn listCredentials(self: *Vault, filter_type: ?CredentialType) ![]Credential {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        if (filter_type) |cred_type| {
            var filtered = ArrayList(Credential){};
            for (self.credentials.items) |cred| {
                if (cred.type == cred_type) {
                    try filtered.append(self.allocator, cred);
                }
            }
            return filtered.toOwnedSlice(self.allocator);
        }

        return try self.allocator.dupe(Credential, self.credentials.items);
    }

    /// Search credentials by name pattern
    pub fn searchCredentials(self: *Vault, pattern: []const u8) ![]Credential {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;

        var results = ArrayList(Credential){};
        for (self.credentials.items) |cred| {
            if (std.mem.indexOf(u8, cred.name, pattern) != null) {
                try results.append(self.allocator, cred);
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Release credential slice previously returned by list/search helpers
    pub fn freeCredentialSlice(self: *Vault, slice: []Credential) void {
        self.allocator.free(slice);
    }

    /// Free a buffer previously allocated by the vault allocator
    pub fn freeBuffer(self: *Vault, buffer: []u8) void {
        self.allocator.free(buffer);
    }

    /// Export a copy of the derived master key for secure caching
    pub fn exportMasterKey(self: *Vault) ![32]u8 {
        if (!self.isUnlocked()) return GVaultError.VaultLocked;
        return self.master_key orelse GVaultError.VaultLocked;
    }

    /// Hydrate the vault using a provided master key without prompting for passphrase
    pub fn hydrateWithMasterKey(self: *Vault, master_key: [32]u8) !void {
        if (!self.is_locked or self.master_key != null) {
            self.lock();
        }

        self.master_key = master_key;

        if (self.master_key) |*key| {
            const ptr: [*]u8 = @ptrCast(key);
            secure_mem.lockMemory(ptr, 32) catch |err| {
                std.log.warn("Failed to lock master key in memory: {}", .{err});
            };
        }

        self.is_locked = false;
        try self.loadCredentials();
    }
};

// Export main types and functions
pub const gvault = struct {
    pub const Vault = @This().Vault;
    pub const Credential = @This().Credential;
    pub const CredentialType = @This().CredentialType;
    pub const CredentialId = @This().CredentialId;
    pub const CredentialMetadata = @This().CredentialMetadata;
    pub const GVaultError = @This().GVaultError;
};

pub const session = struct {
    pub const PromptError = error{
        Timeout,
        Cancelled,
        Unavailable,
    };

    pub const SessionError = error{
        AlreadyInitialized,
        NotInitialized,
        PromptUnavailable,
        UnlockTimedOut,
        UnlockFailed,
        InvalidPassphrase,
        OutOfMemory,
    };

    pub const PromptRequest = struct {
        message: []const u8,
        timeout_ms: u64,
    };

    pub const PromptFn = *const fn (ctx: ?*anyopaque, allocator: Allocator, request: PromptRequest) PromptError![]const u8;

    pub const Prompt = struct {
        callback: PromptFn,
        ctx: ?*anyopaque = null,
        message: []const u8 = "🔐 Vault password: ",
    };

    pub const SessionConfig = struct {
        allocator: Allocator,
        vault_path: []const u8,
        unlock_timeout_ms: u64 = 5_000,
        inactivity_ttl_ns: ?u64 = std.time.ns_per_min * 15,
        allow_cached_unlock: bool = true,
        prompt: ?Prompt = null,
    };

    pub const AcquireOptions = struct {
        passphrase: ?[]const u8 = null,
        prompt: ?Prompt = null,
        timeout_ms: ?u64 = null,
        allow_cached: ?bool = null,
    };

    pub const SessionStatus = struct {
        is_initialized: bool,
        is_unlocked: bool,
        active_handles: usize,
        expires_at_ns: ?u64,
        allow_cached_unlock: bool,
    };

    pub const VaultSession = struct {
        vault: *Vault,

        pub fn getVault(self: *VaultSession) *Vault {
            return self.vault;
        }
    };

    const SecureByteBuffer = secure_mem.SecureBuffer(u8);

    const UnlockCache = struct {
        key: ?SecureByteBuffer = null,
        blob: ?SecureByteBuffer = null,
        blob_len: usize = 0,
        expires_at_ns: ?u64 = null,

        pub fn clear(self: *UnlockCache) void {
            if (self.blob) |*buf| {
                buf.deinit();
                self.blob = null;
            }
            if (self.key) |*buf| {
                buf.deinit();
                self.key = null;
            }
            self.blob_len = 0;
            self.expires_at_ns = null;
        }

        fn ensureKey(self: *UnlockCache, allocator: Allocator) !*SecureByteBuffer {
            if (self.key) |*buf| return buf;
            const new_buf = try SecureByteBuffer.init(allocator, 32);
            self.key = new_buf;
            return &self.key.?;
        }

        fn ensureBlob(self: *UnlockCache, allocator: Allocator) !*SecureByteBuffer {
            if (self.blob) |*buf| return buf;
            const new_buf = try SecureByteBuffer.init(allocator, 60);
            self.blob = new_buf;
            self.blob_len = 60;
            return &self.blob.?;
        }

        pub fn store(self: *UnlockCache, allocator: Allocator, master_key: []const u8, expires_at_ns: ?u64) !void {
            var key_buf = try self.ensureKey(allocator);
            var blob_buf = try self.ensureBlob(allocator);

            const key_slice = key_buf.slice();
            crypto.random.bytes(key_slice);

            const blob_slice = blob_buf.slice();
            const nonce_slice = blob_slice[0..12];
            const ciphertext_slice = blob_slice[12..44];
            const tag_slice = blob_slice[44..60];

            crypto.random.bytes(nonce_slice);

            var nonce: [12]u8 = undefined;
            @memcpy(&nonce, nonce_slice);

            var key_array: [32]u8 = undefined;
            @memcpy(&key_array, key_slice);

            crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                ciphertext_slice,
                tag_slice,
                master_key,
                &.{},
                nonce,
                key_array,
            );

            self.blob_len = 60;
            self.expires_at_ns = expires_at_ns;
        }

        pub fn tryRestore(self: *UnlockCache, now_ns: u64) ?[32]u8 {
            if (self.blob == null or self.key == null) return null;
            if (self.blob_len != 60) return null;

            if (self.expires_at_ns) |expiry| {
                if (now_ns >= expiry) {
                    self.clear();
                    return null;
                }
            }

            const blob_slice = self.blob.?.slice();
            const key_slice = self.key.?.slice();

            var nonce: [12]u8 = undefined;
            @memcpy(&nonce, blob_slice[0..12]);

            const ciphertext = blob_slice[12..44];
            const tag_slice = blob_slice[44..60];

            var key_array: [32]u8 = undefined;
            @memcpy(&key_array, key_slice);

            var tag_array: [16]u8 = undefined;
            @memcpy(&tag_array, tag_slice);

            var master_key: [32]u8 = undefined;
            crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                master_key[0..],
                ciphertext,
                tag_array,
                &.{},
                nonce,
                key_array,
            ) catch {
                self.clear();
                return null;
            };

            return master_key;
        }
    };

    const SessionState = struct {
        mutex: std.Thread.Mutex = .{},
        allocator: Allocator = undefined,
        initialized: bool = false,
        config: SessionConfig = undefined,
        vault: ?*Vault = null,
        session_active: bool = false,
        session: VaultSession = undefined,
        ref_count: usize = 0,
        last_used_ns: u64 = 0,
        cache: UnlockCache = .{},
    };

    const PassphraseInput = struct {
        slice: ?[]const u8 = null,
        owned: bool = false,
        allocator: ?Allocator = null,

        fn setOwned(self: *PassphraseInput, slice: []const u8, allocator: Allocator) void {
            self.dispose();
            self.slice = slice;
            self.owned = true;
            self.allocator = allocator;
        }

        fn dispose(self: *PassphraseInput) void {
            if (self.owned) {
                if (self.slice) |s| {
                    const mut = @constCast(s);
                    secure_mem.secureZero(mut.ptr, mut.len);
                    self.allocator.?.free(mut);
                }
            }
            self.slice = null;
            self.owned = false;
            self.allocator = null;
        }
    };

    var state = SessionState{};

    pub fn init(config: SessionConfig) SessionError!void {
        state.mutex.lock();
        defer state.mutex.unlock();

        if (state.initialized) return SessionError.AlreadyInitialized;

        const vault_ptr = config.allocator.create(Vault) catch {
            return SessionError.OutOfMemory;
        };
        errdefer config.allocator.destroy(vault_ptr);

        vault_ptr.* = Vault.init(config.allocator, config.vault_path) catch |err| {
            return mapVaultInitError(err);
        };

        state.allocator = config.allocator;
        state.config = config;
        state.vault = vault_ptr;
        state.initialized = true;
        state.session_active = false;
        state.ref_count = 0;
        state.last_used_ns = 0;
        state.cache.clear();
    }

    pub fn deinit() void {
        state.mutex.lock();
        defer state.mutex.unlock();

        if (!state.initialized) return;

        forceLockLocked();
        state.cache.clear();

        if (state.vault) |vault_ptr| {
            vault_ptr.lock();
            vault_ptr.deinit();
            state.allocator.destroy(vault_ptr);
            state.vault = null;
        }

        state.initialized = false;
        state.session_active = false;
        state.ref_count = 0;
        state.last_used_ns = 0;
    }

    pub fn acquire(allocator: Allocator, opts: AcquireOptions) SessionError!*VaultSession {
        _ = allocator;

        var passphrase_input = PassphraseInput{
            .slice = opts.passphrase,
            .owned = false,
            .allocator = null,
        };
        defer passphrase_input.dispose();

        const prompt_opt = opts.prompt orelse state.config.prompt;
        const allow_cached = opts.allow_cached orelse state.config.allow_cached_unlock;
        const timeout_ms = opts.timeout_ms orelse state.config.unlock_timeout_ms;

        while (true) {
            const now_ns = currentTimeNs();

            state.mutex.lock();

            if (!state.initialized) {
                state.mutex.unlock();
                return SessionError.NotInitialized;
            }

            maybeExpireLocked(now_ns);

            if (state.session_active) {
                state.ref_count += 1;
                state.last_used_ns = now_ns;
                const result = &state.session;
                state.mutex.unlock();
                return result;
            }

            if (allow_cached) {
                if (state.cache.tryRestore(now_ns)) |restored| {
                    var master_key = restored;
                    const vault_ptr = state.vault orelse {
                        state.cache.clear();
                        state.mutex.unlock();
                        return SessionError.NotInitialized;
                    };

                    const hydrate_res = vault_ptr.hydrateWithMasterKey(master_key);
                    secure_mem.secureZero(@ptrCast(&master_key), @sizeOf([32]u8));
                    hydrate_res catch |err| {
                        state.cache.clear();
                        state.mutex.unlock();
                        return mapVaultError(err);
                    };

                    activateSessionLocked(now_ns);
                    const result = &state.session;
                    state.mutex.unlock();
                    return result;
                }
            }

            if (passphrase_input.slice) |pass| {
                const unlock_result = unlockWithPassphraseLocked(pass, now_ns, allow_cached) catch |err| {
                    state.mutex.unlock();
                    return err;
                };
                state.mutex.unlock();
                return unlock_result;
            }

            if (prompt_opt == null) {
                state.mutex.unlock();
                return SessionError.PromptUnavailable;
            }

            const prompt = prompt_opt.?;
            const request = PromptRequest{
                .message = prompt.message,
                .timeout_ms = timeout_ms,
            };
            const prompt_allocator = state.allocator;
            state.mutex.unlock();

            const response = prompt.callback(prompt.ctx, prompt_allocator, request) catch |err| {
                return switch (err) {
                    PromptError.Timeout => SessionError.UnlockTimedOut,
                    PromptError.Cancelled => SessionError.UnlockTimedOut,
                    PromptError.Unavailable => SessionError.PromptUnavailable,
                };
            };

            passphrase_input.setOwned(response, prompt_allocator);
        }
    }

    pub fn release(session_ptr: *VaultSession) void {
        state.mutex.lock();
        defer state.mutex.unlock();

        if (!state.initialized) return;
        if (!state.session_active) return;
        if (session_ptr != &state.session) return;
        if (state.ref_count == 0) return;

        state.ref_count -= 1;
        state.last_used_ns = currentTimeNs();
    }

    pub fn lock() void {
        state.mutex.lock();
        defer state.mutex.unlock();

        if (!state.initialized) return;
        forceLockLocked();
        state.cache.clear();
    }

    pub fn status() SessionStatus {
        state.mutex.lock();
        defer state.mutex.unlock();

        if (!state.initialized) {
            return .{
                .is_initialized = false,
                .is_unlocked = false,
                .active_handles = 0,
                .expires_at_ns = null,
                .allow_cached_unlock = false,
            };
        }

        var expires: ?u64 = null;
        if (state.session_active) {
            if (state.config.inactivity_ttl_ns) |ttl| {
                expires = state.last_used_ns + ttl;
            }
        }

        return .{
            .is_initialized = true,
            .is_unlocked = state.session_active,
            .active_handles = state.ref_count,
            .expires_at_ns = expires,
            .allow_cached_unlock = state.config.allow_cached_unlock,
        };
    }

    fn currentTimeNs() u64 {
        const ts = std.time.nanoTimestamp();
        if (ts < 0) return 0;
        const positive = ts;
        return @as(u64, @intCast(positive));
    }

    fn maybeExpireLocked(now_ns: u64) void {
        if (!state.session_active) return;
        if (state.ref_count > 0) return;
        if (state.config.inactivity_ttl_ns) |ttl| {
            if (state.last_used_ns == 0) return;
            if (now_ns - state.last_used_ns >= ttl) {
                forceLockLocked();
                state.cache.clear();
            }
        }
    }

    fn forceLockLocked() void {
        if (!state.initialized) return;
        if (state.vault) |vault_ptr| {
            vault_ptr.lock();
        }
        state.session_active = false;
        state.ref_count = 0;
        state.last_used_ns = 0;
    }

    fn activateSessionLocked(now_ns: u64) void {
        state.session = .{ .vault = state.vault.? };
        state.session_active = true;
        state.ref_count = 1;
        state.last_used_ns = now_ns;
    }

    fn mapVaultError(err: anyerror) SessionError {
        if (err == GVaultError.InvalidPassphrase or err == error.InvalidPassphrase) {
            return SessionError.InvalidPassphrase;
        }
        if (err == error.OutOfMemory) {
            return SessionError.OutOfMemory;
        }
        return SessionError.UnlockFailed;
    }

    fn mapVaultInitError(err: anyerror) SessionError {
        return switch (err) {
            error.OutOfMemory => SessionError.OutOfMemory,
            else => SessionError.UnlockFailed,
        };
    }

    fn unlockWithPassphraseLocked(passphrase: []const u8, now_ns: u64, allow_cached: bool) SessionError!*VaultSession {
        const vault_ptr = state.vault orelse return SessionError.NotInitialized;

        var secure_pass = SecureByteBuffer.init(state.allocator, passphrase.len) catch {
            return SessionError.OutOfMemory;
        };
        defer secure_pass.deinit();
        std.mem.copyForwards(u8, secure_pass.slice(), passphrase);

        vault_ptr.unlock(secure_pass.slice()) catch |err| {
            if (err == error.InvalidPassphrase) {
                return SessionError.InvalidPassphrase;
            }
            if (err == error.OutOfMemory) {
                return SessionError.OutOfMemory;
            }
            return SessionError.UnlockFailed;
        };

        if (allow_cached and state.config.allow_cached_unlock) {
            var master_key = vault_ptr.exportMasterKey() catch |err| {
                return mapVaultError(err);
            };
            defer secure_mem.secureZero(@ptrCast(&master_key), @sizeOf([32]u8));
            const expiry = if (state.config.inactivity_ttl_ns) |ttl| now_ns + ttl else null;
            state.cache.store(state.allocator, master_key[0..], expiry) catch {
                state.cache.clear();
            };
        } else {
            state.cache.clear();
        }

        activateSessionLocked(now_ns);
        return &state.session;
    }
};

// Test the basic functionality
test "vault creation and locking" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var vault = try Vault.init(allocator, "/tmp/test_vault");
    defer vault.deinit();

    // Should start locked
    try testing.expect(!vault.isUnlocked());

    // Unlock with passphrase
    try vault.unlock("test_password");
    try testing.expect(vault.isUnlocked());

    // Lock again
    vault.lock();
    try testing.expect(!vault.isUnlocked());
}

test "encryption and decryption" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var vault = try Vault.init(allocator, "/tmp/test_vault");
    defer vault.deinit();

    try vault.unlock("test_password");

    const plaintext = "This is secret data";
    const encrypted = try vault.encrypt(plaintext, allocator);
    defer allocator.free(encrypted);

    const decrypted = try vault.decrypt(encrypted, allocator);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "credential ID generation" {
    const testing = std.testing;

    const id1 = CredentialId.generate();
    const id2 = CredentialId.generate();

    // IDs should be different
    try testing.expect(!std.mem.eql(u8, &id1.bytes, &id2.bytes));

    // Test string conversion
    var buf: [32]u8 = undefined;
    const id_str = try id1.toString(&buf);
    try testing.expect(id_str.len == 32);

    const parsed_id = try CredentialId.fromString(id_str);
    try testing.expectEqualSlices(u8, &id1.bytes, &parsed_id.bytes);
}
