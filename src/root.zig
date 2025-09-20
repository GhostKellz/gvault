//! GVault - Terminal Keychain Manager
//! A secure credential management library for terminal emulators

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const GVaultError = error{
    InvalidPassphrase,
    VaultLocked,
    CredentialNotFound,
    EncryptionError,
    DecryptionError,
    InvalidCredentialType,
    StorageError,
};

/// Credential types supported by GVault
pub const CredentialType = enum {
    ssh_key,
    gpg_key,
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

    pub fn init(allocator: Allocator) CredentialMetadata {
        _ = allocator; // TODO: Use allocator when we implement persistent storage
        return CredentialMetadata{
            .created = std.time.timestamp(),
            .last_used = null,
            .auto_load = false,
            .tags = ArrayList([]const u8){},
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
    credentials: ArrayList(Credential),
    is_locked: bool,
    auto_lock_timeout: ?u32,

    pub fn init(allocator: Allocator, vault_path: []const u8) !Vault {
        // Create vault directory if it doesn't exist
        std.fs.cwd().makePath(vault_path) catch |err| {
            switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            }
        };

        return Vault{
            .allocator = allocator,
            .vault_path = try allocator.dupe(u8, vault_path),
            .master_key = null,
            .credentials = ArrayList(Credential){},
            .is_locked = true,
            .auto_lock_timeout = null,
        };
    }

    pub fn deinit(self: *Vault) void {
        self.lock();
        for (self.credentials.items) |*cred| {
            cred.deinit(self.allocator);
        }
        self.credentials.deinit(self.allocator);
        self.allocator.free(self.vault_path);
    }

    /// Unlock the vault with a passphrase
    pub fn unlock(self: *Vault, passphrase: []const u8) !void {
        // Simple key derivation for prototype (TODO: use proper KDF)
        var master_key: [32]u8 = undefined;
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update("gvault_salt");
        hasher.update(passphrase);
        hasher.final(&master_key);

        self.master_key = master_key;
        self.is_locked = false;

        // Load existing credentials
        try self.loadCredentials();
    }

    /// Lock the vault and clear sensitive data
    pub fn lock(self: *Vault) void {
        if (self.master_key) |*key| {
            // Securely zero the key memory
            @memset(key, 0);
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
        // For now, this is a placeholder. In a full implementation,
        // this would read from a secure storage file format
        _ = self;
    }

    /// Save credentials to storage
    fn saveCredentials(self: *Vault) !void {
        // For now, this is a placeholder. In a full implementation,
        // this would save to a secure storage file format
        _ = self;
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
            .metadata = CredentialMetadata.init(self.allocator),
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