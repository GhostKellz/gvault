//! SSH Key Generation and Management
//!
//! Provides SSH key generation (Ed25519, RSA, ECDSA) and management
//! functionality for GVault, using zssh's crypto primitives.

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

// Import zssh for SSH crypto operations
const zssh = @import("zssh");

pub const SshKeyError = error{
    KeyGenerationFailed,
    InvalidKeyType,
    InvalidKeyFormat,
    KeyImportFailed,
    FingerprintFailed,
} || Allocator.Error;

/// Supported SSH key algorithms
pub const SshKeyAlgorithm = enum {
    ed25519,
    rsa_2048,
    rsa_4096,
    ecdsa_p256,
    ecdsa_p384,
    ecdsa_p521,

    pub fn toString(self: SshKeyAlgorithm) []const u8 {
        return switch (self) {
            .ed25519 => "ssh-ed25519",
            .rsa_2048 => "ssh-rsa-2048",
            .rsa_4096 => "ssh-rsa-4096",
            .ecdsa_p256 => "ecdsa-sha2-nistp256",
            .ecdsa_p384 => "ecdsa-sha2-nistp384",
            .ecdsa_p521 => "ecdsa-sha2-nistp521",
        };
    }

    pub fn fromString(algorithm: []const u8) ?SshKeyAlgorithm {
        if (std.mem.eql(u8, algorithm, "ssh-ed25519")) return .ed25519;
        if (std.mem.eql(u8, algorithm, "ssh-rsa-2048")) return .rsa_2048;
        if (std.mem.eql(u8, algorithm, "ssh-rsa-4096")) return .rsa_4096;
        if (std.mem.eql(u8, algorithm, "ecdsa-sha2-nistp256")) return .ecdsa_p256;
        if (std.mem.eql(u8, algorithm, "ecdsa-sha2-nistp384")) return .ecdsa_p384;
        if (std.mem.eql(u8, algorithm, "ecdsa-sha2-nistp521")) return .ecdsa_p521;
        return null;
    }
};

/// SSH key pair representation
pub const SshKeyPair = struct {
    algorithm: SshKeyAlgorithm,
    public_key: []u8,
    private_key: []u8,
    fingerprint: []u8,
    comment: []const u8,

    pub fn deinit(self: *SshKeyPair, allocator: Allocator) void {
        allocator.free(self.public_key);
        // Securely zero out private key before freeing
        @memset(self.private_key, 0);
        allocator.free(self.private_key);
        allocator.free(self.fingerprint);
        allocator.free(self.comment);
    }
};

/// SSH key generator
pub const SshKeyGenerator = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) SshKeyGenerator {
        return .{ .allocator = allocator };
    }

    /// Generate a new SSH key pair
    pub fn generate(
        self: *SshKeyGenerator,
        algorithm: SshKeyAlgorithm,
        comment: []const u8,
    ) !SshKeyPair {
        return switch (algorithm) {
            .ed25519 => try self.generateEd25519(comment),
            .ecdsa_p256 => try self.generateEcdsaP256(comment),
            .rsa_2048, .rsa_4096 => SshKeyError.KeyGenerationFailed, // RSA not yet implemented
            .ecdsa_p384, .ecdsa_p521 => SshKeyError.KeyGenerationFailed, // P-384/521 not yet implemented
        };
    }

    /// Generate Ed25519 SSH key pair (modern, recommended)
    fn generateEd25519(self: *SshKeyGenerator, comment: []const u8) !SshKeyPair {
        // Use std.crypto for Ed25519 key generation
        const key_pair = crypto.sign.Ed25519.KeyPair.generate();

        // Allocate and copy keys
        const public_key = try self.allocator.dupe(u8, &key_pair.public_key.bytes);
        errdefer self.allocator.free(public_key);

        const private_key = try self.allocator.dupe(u8, &key_pair.secret_key.bytes);
        errdefer {
            @memset(private_key, 0);
            self.allocator.free(private_key);
        }

        // Calculate SHA256 fingerprint
        const fingerprint = try self.calculateFingerprint(public_key);
        errdefer self.allocator.free(fingerprint);

        const comment_copy = try self.allocator.dupe(u8, comment);
        errdefer self.allocator.free(comment_copy);

        return SshKeyPair{
            .algorithm = .ed25519,
            .public_key = public_key,
            .private_key = private_key,
            .fingerprint = fingerprint,
            .comment = comment_copy,
        };
    }

    /// Generate ECDSA P-256 SSH key pair (NIST standard)
    fn generateEcdsaP256(self: *SshKeyGenerator, comment: []const u8) !SshKeyPair {
        // Use std.crypto for ECDSA P-256 key generation
        var seed: [32]u8 = undefined;
        crypto.random.bytes(&seed);

        const key_pair = try crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
        const public_key_bytes = key_pair.public_key.toUncompressedSec1();
        const private_key_bytes = key_pair.secret_key.toBytes();

        // Allocate and copy keys
        const public_key = try self.allocator.dupe(u8, &public_key_bytes);
        errdefer self.allocator.free(public_key);

        const private_key = try self.allocator.dupe(u8, &private_key_bytes);
        errdefer {
            @memset(private_key, 0);
            self.allocator.free(private_key);
        }

        // Calculate SHA256 fingerprint
        const fingerprint = try self.calculateFingerprint(public_key);
        errdefer self.allocator.free(fingerprint);

        const comment_copy = try self.allocator.dupe(u8, comment);
        errdefer self.allocator.free(comment_copy);

        return SshKeyPair{
            .algorithm = .ecdsa_p256,
            .public_key = public_key,
            .private_key = private_key,
            .fingerprint = fingerprint,
            .comment = comment_copy,
        };
    }

    /// Calculate SHA256 fingerprint for a public key
    fn calculateFingerprint(self: *SshKeyGenerator, public_key: []const u8) ![]u8 {
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(public_key, &hash, .{});

        // Format as hex string with colons (e.g., SHA256:ab:cd:ef:...)
        const hex_chars = "0123456789abcdef";
        const prefix = "SHA256:";
        const fingerprint_len = prefix.len + (hash.len * 3) - 1; // ab:cd:ef format

        const fingerprint = try self.allocator.alloc(u8, fingerprint_len);
        errdefer self.allocator.free(fingerprint);

        @memcpy(fingerprint[0..prefix.len], prefix);

        var offset: usize = prefix.len;
        for (hash, 0..) |byte, i| {
            if (i > 0) {
                fingerprint[offset] = ':';
                offset += 1;
            }
            fingerprint[offset] = hex_chars[byte >> 4];
            fingerprint[offset + 1] = hex_chars[byte & 0x0f];
            offset += 2;
        }

        return fingerprint;
    }

    /// Format public key as OpenSSH authorized_keys format
    pub fn formatPublicKey(
        self: *SshKeyGenerator,
        key_pair: *const SshKeyPair,
    ) ![]u8 {
        // Format: <algorithm> <base64-encoded-key> <comment>
        const algorithm_str = key_pair.algorithm.toString();

        // Base64 encode the public key
        const base64_encoder = std.base64.standard.Encoder;
        const encoded_len = base64_encoder.calcSize(key_pair.public_key.len);
        const encoded_key = try self.allocator.alloc(u8, encoded_len);
        defer self.allocator.free(encoded_key);

        const encoded = base64_encoder.encode(encoded_key, key_pair.public_key);

        // Combine: algorithm + space + encoded key + space + comment
        const total_len = algorithm_str.len + 1 + encoded.len + 1 + key_pair.comment.len;
        const formatted = try self.allocator.alloc(u8, total_len);

        var offset: usize = 0;
        @memcpy(formatted[offset..][0..algorithm_str.len], algorithm_str);
        offset += algorithm_str.len;

        formatted[offset] = ' ';
        offset += 1;

        @memcpy(formatted[offset..][0..encoded.len], encoded);
        offset += encoded.len;

        formatted[offset] = ' ';
        offset += 1;

        @memcpy(formatted[offset..][0..key_pair.comment.len], key_pair.comment);

        return formatted;
    }

    /// Format private key as OpenSSH private key format
    pub fn formatPrivateKey(
        self: *SshKeyGenerator,
        key_pair: *const SshKeyPair,
    ) ![]u8 {
        // OpenSSH private key format (simplified)
        const header = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
        const footer = "-----END OPENSSH PRIVATE KEY-----\n";

        // Base64 encode the private key
        const base64_encoder = std.base64.standard.Encoder;
        const encoded_len = base64_encoder.calcSize(key_pair.private_key.len);
        const encoded_key = try self.allocator.alloc(u8, encoded_len);
        defer self.allocator.free(encoded_key);

        const encoded = base64_encoder.encode(encoded_key, key_pair.private_key);

        // Combine header + encoded key + footer
        const total_len = header.len + encoded.len + 1 + footer.len;
        const formatted = try self.allocator.alloc(u8, total_len);

        var offset: usize = 0;
        @memcpy(formatted[offset..][0..header.len], header);
        offset += header.len;

        @memcpy(formatted[offset..][0..encoded.len], encoded);
        offset += encoded.len;

        formatted[offset] = '\n';
        offset += 1;

        @memcpy(formatted[offset..][0..footer.len], footer);

        return formatted;
    }
};

// Tests
test "SSH key generation - Ed25519" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var generator = SshKeyGenerator.init(allocator);
    var key_pair = try generator.generate(.ed25519, "test@gvault");
    defer key_pair.deinit(allocator);

    try testing.expect(key_pair.public_key.len == 32); // Ed25519 public key is 32 bytes
    try testing.expect(key_pair.private_key.len == 64); // Ed25519 private key is 64 bytes
    try testing.expect(key_pair.fingerprint.len > 0);
    try testing.expectEqualStrings("test@gvault", key_pair.comment);
}

test "SSH key generation - ECDSA P-256" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var generator = SshKeyGenerator.init(allocator);
    var key_pair = try generator.generate(.ecdsa_p256, "test@gvault");
    defer key_pair.deinit(allocator);

    try testing.expect(key_pair.public_key.len == 65); // Uncompressed P-256 public key
    try testing.expect(key_pair.private_key.len == 32); // P-256 private key is 32 bytes
    try testing.expect(key_pair.fingerprint.len > 0);
    try testing.expectEqualStrings("test@gvault", key_pair.comment);
}

test "SSH key fingerprint calculation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var generator = SshKeyGenerator.init(allocator);
    var key_pair = try generator.generate(.ed25519, "test@gvault");
    defer key_pair.deinit(allocator);

    // Fingerprint should start with "SHA256:"
    try testing.expect(std.mem.startsWith(u8, key_pair.fingerprint, "SHA256:"));
}

test "SSH public key formatting" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var generator = SshKeyGenerator.init(allocator);
    var key_pair = try generator.generate(.ed25519, "test@gvault");
    defer key_pair.deinit(allocator);

    const formatted = try generator.formatPublicKey(&key_pair);
    defer allocator.free(formatted);

    // Should start with algorithm name
    try testing.expect(std.mem.startsWith(u8, formatted, "ssh-ed25519 "));
    // Should end with comment
    try testing.expect(std.mem.endsWith(u8, formatted, " test@gvault"));
}

test "SSH private key formatting" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var generator = SshKeyGenerator.init(allocator);
    var key_pair = try generator.generate(.ed25519, "test@gvault");
    defer key_pair.deinit(allocator);

    const formatted = try generator.formatPrivateKey(&key_pair);
    defer allocator.free(formatted);

    // Should start with OpenSSH header
    try testing.expect(std.mem.startsWith(u8, formatted, "-----BEGIN OPENSSH PRIVATE KEY-----"));
    // Should end with OpenSSH footer
    try testing.expect(std.mem.endsWith(u8, formatted, "-----END OPENSSH PRIVATE KEY-----\n"));
}
