const std = @import("std");
const ssh_keys = @import("src/ssh_keys.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n🔐 GVault SSH Key Generation Test\n", .{});
    std.debug.print("==================================\n\n", .{});

    // Test Ed25519 key generation (modern, recommended)
    std.debug.print("Generating Ed25519 key pair...\n", .{});
    var generator = ssh_keys.SshKeyGenerator.init(allocator);

    var ed25519_key = try generator.generate(.ed25519, "gvault@test");
    defer ed25519_key.deinit(allocator);

    std.debug.print("✅ Ed25519 Key Generated:\n", .{});
    std.debug.print("   Algorithm: {s}\n", .{ed25519_key.algorithm.toString()});
    std.debug.print("   Public Key Size: {d} bytes\n", .{ed25519_key.public_key.len});
    std.debug.print("   Private Key Size: {d} bytes\n", .{ed25519_key.private_key.len});
    std.debug.print("   Fingerprint: {s}\n", .{ed25519_key.fingerprint});
    std.debug.print("   Comment: {s}\n\n", .{ed25519_key.comment});

    // Format public key
    const public_key_formatted = try generator.formatPublicKey(&ed25519_key);
    defer allocator.free(public_key_formatted);

    std.debug.print("📋 Public Key (OpenSSH format):\n", .{});
    std.debug.print("{s}\n\n", .{public_key_formatted});

    // Test ECDSA P-256 key generation
    std.debug.print("Generating ECDSA P-256 key pair...\n", .{});
    var ecdsa_key = try generator.generate(.ecdsa_p256, "gvault@test");
    defer ecdsa_key.deinit(allocator);

    std.debug.print("✅ ECDSA P-256 Key Generated:\n", .{});
    std.debug.print("   Algorithm: {s}\n", .{ecdsa_key.algorithm.toString()});
    std.debug.print("   Public Key Size: {d} bytes\n", .{ecdsa_key.public_key.len});
    std.debug.print("   Private Key Size: {d} bytes\n", .{ecdsa_key.private_key.len});
    std.debug.print("   Fingerprint: {s}\n", .{ecdsa_key.fingerprint});
    std.debug.print("   Comment: {s}\n\n", .{ecdsa_key.comment});

    std.debug.print("🎉 SSH key generation successful!\n", .{});
    std.debug.print("\n✅ Ready for integration with GVault vault storage\n", .{});
}
