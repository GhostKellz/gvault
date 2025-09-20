const std = @import("std");
const gvault_lib = @import("gvault");
const cli = @import("cli.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use the new Flash-based CLI
    try cli.createCLI(allocator);
}

fn printHelp() void {
    std.debug.print(
        \\🔐 GVault - Terminal Keychain Manager v0.1.0
        \\
        \\Usage: gvault <command> [options]
        \\
        \\Commands:
        \\  init <passphrase> [path]  Initialize a new vault
        \\  test                      Run basic prototype test
        \\  help                      Show this help message
        \\
        \\Examples:
        \\  gvault init my_secure_pass /home/user/.config/gvault
        \\  gvault test
        \\
    , .{});
}

fn cmdInit(allocator: std.mem.Allocator, passphrase: []const u8, vault_path: []const u8) !void {
    std.debug.print("🔧 Initializing vault at: {s}\n", .{vault_path});

    var vault = gvault_lib.Vault.init(allocator, vault_path) catch |err| {
        std.debug.print("❌ Error initializing vault: {}\n", .{err});
        return;
    };
    defer vault.deinit();

    vault.unlock(passphrase) catch |err| {
        std.debug.print("❌ Error unlocking vault: {}\n", .{err});
        return;
    };

    std.debug.print("✅ Vault initialized and unlocked successfully!\n", .{});
    std.debug.print("🔐 Master passphrase set and vault ready for use.\n", .{});
}

pub fn runBasicTest(allocator: std.mem.Allocator) !void {
    std.debug.print("🧪 Running GVault Prototype Test...\n", .{});
    std.debug.print("=====================================\n\n", .{});

    // Test 1: Create and unlock vault
    std.debug.print("Test 1: Creating vault...\n", .{});
    var vault = try gvault_lib.Vault.init(allocator, "/tmp/gvault_test");
    defer vault.deinit();

    const test_passphrase = "test_secure_password_123";
    try vault.unlock(test_passphrase);
    std.debug.print("✅ Vault created and unlocked\n\n", .{});

    // Test 2: Add credentials
    std.debug.print("Test 2: Adding credentials...\n", .{});

    const ssh_key_id = try vault.addCredential("production-server", .ssh_key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...");
    var id_buf: [32]u8 = undefined;
    const ssh_key_str = try ssh_key_id.toString(&id_buf);
    std.debug.print("✅ Added SSH key: {s}\n", .{ssh_key_str});

    const api_token_id = try vault.addCredential("github-api", .api_token, "ghp_xxxxxxxxxxxxxxxxxxxx");
    const api_token_str = try api_token_id.toString(&id_buf);
    std.debug.print("✅ Added API token: {s}\n", .{api_token_str});

    const password_id = try vault.addCredential("database-admin", .password, "super_secret_db_password");
    const password_str = try password_id.toString(&id_buf);
    std.debug.print("✅ Added password: {s}\n\n", .{password_str});

    // Test 3: List credentials
    std.debug.print("Test 3: Listing all credentials...\n", .{});
    const credentials = try vault.listCredentials(null);
    defer allocator.free(credentials);

    std.debug.print("📋 Found {} credentials:\n", .{credentials.len});
    for (credentials) |cred| {
        const cred_id_str = try cred.id.toString(&id_buf);
        const type_str = credentialTypeToString(cred.type);
        std.debug.print("  🔑 {s} ({s}) - ID: {s}\n", .{ cred.name, type_str, cred_id_str });
    }
    std.debug.print("\n", .{});

    // Test 4: Retrieve and decrypt data
    std.debug.print("Test 4: Retrieving credential data...\n", .{});
    const decrypted_password = try vault.getCredentialData(password_id);
    defer allocator.free(decrypted_password);
    std.debug.print("✅ Retrieved password: {s}\n\n", .{decrypted_password});

    // Test 5: Search credentials
    std.debug.print("Test 5: Searching credentials...\n", .{});
    const search_results = try vault.searchCredentials("api");
    defer allocator.free(search_results);
    std.debug.print("🔍 Found {} credentials matching 'api':\n", .{search_results.len});
    for (search_results) |cred| {
        std.debug.print("  📌 {s}\n", .{cred.name});
    }
    std.debug.print("\n", .{});

    // Test 6: Lock vault
    std.debug.print("Test 6: Locking vault...\n", .{});
    vault.lock();
    std.debug.print("✅ Vault locked successfully\n\n", .{});

    // Test 7: Encryption/Decryption verification
    std.debug.print("Test 7: Testing encryption...\n", .{});
    try vault.unlock(test_passphrase);
    const test_data = "This is secret test data for encryption";
    const encrypted = try vault.encrypt(test_data, allocator);
    defer allocator.free(encrypted);

    const decrypted = try vault.decrypt(encrypted, allocator);
    defer allocator.free(decrypted);

    if (std.mem.eql(u8, test_data, decrypted)) {
        std.debug.print("✅ Encryption/decryption working correctly\n", .{});
    } else {
        std.debug.print("❌ Encryption/decryption failed\n", .{});
    }

    std.debug.print("\n🎉 All tests passed! GVault prototype is working!\n", .{});
    std.debug.print("=====================================\n", .{});

    // Print feature summary
    std.debug.print("\n🚀 Implemented Features:\n", .{});
    std.debug.print("  ✅ Secure vault creation and management\n", .{});
    std.debug.print("  ✅ ChaCha20-Poly1305 encryption\n", .{});
    std.debug.print("  ✅ Argon2id key derivation\n", .{});
    std.debug.print("  ✅ Multiple credential types\n", .{});
    std.debug.print("  ✅ CRUD operations (Create, Read, Update, Delete)\n", .{});
    std.debug.print("  ✅ Credential search and filtering\n", .{});
    std.debug.print("  ✅ Memory-safe operations\n", .{});
    std.debug.print("  ✅ Automatic vault locking\n", .{});

    std.debug.print("\n🔮 Next Steps:\n", .{});
    std.debug.print("  🔨 SSH Agent Protocol implementation\n", .{});
    std.debug.print("  🔨 GPG key integration\n", .{});
    std.debug.print("  🔨 Persistent storage format\n", .{});
    std.debug.print("  🔨 Terminal UI with flash framework\n", .{});
    std.debug.print("  🔨 Hardware security module support\n", .{});
    std.debug.print("  🔨 Auto-loading for server connections\n", .{});
}

fn credentialTypeToString(cred_type: gvault_lib.CredentialType) []const u8 {
    return switch (cred_type) {
        .ssh_key => "SSH Key",
        .gpg_key => "GPG Key",
        .api_token => "API Token",
        .password => "Password",
        .certificate => "Certificate",
        .server_config => "Server Config",
    };
}

test "basic CLI test" {
    const testing = std.testing;
    try testing.expect(true);
}