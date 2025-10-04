//! GVault - Terminal Keychain Manager
//! A secure credential management library for terminal emulators

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const zcrypto = @import("zcrypto");

// Storage module for persistent database
const storage = @import("storage.zig");

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
    server_patterns: ?ArrayList([]const u8),

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
        self.tags.deinit(allocator);
        if (self.server_patterns) |*patterns| {
            patterns.deinit(allocator);
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
        const ciphertext = encrypted[nonce.len..encrypted.len - 16];
        const tag = encrypted[encrypted.len - 16..];

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
        const ciphertext = encrypted[12..encrypted.len - 16];
        const tag = encrypted[encrypted.len - 16..];

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
            @memcpy(encrypted_data[row.nonce.len..row.nonce.len + row.username.len], row.username);
            @memcpy(encrypted_data[row.nonce.len + row.username.len..], row.auth_tag);

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
            const ciphertext = cred.encrypted_data[12..12 + ciphertext_len];
            const tag = cred.encrypted_data[cred.encrypted_data.len - 16..];

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