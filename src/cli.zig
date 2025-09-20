//! Enhanced CLI for GVault using Flash framework
//! Provides rich subcommands and interactive features

const std = @import("std");
const flash = @import("flash");
const gvault_lib = @import("gvault");

var global_vault: ?gvault_lib.Vault = null;
var global_allocator: std.mem.Allocator = undefined;

// CLI Command Handlers

fn initHandler(ctx: flash.Context) flash.Error!void {
    const passphrase = ctx.getString("passphrase") orelse return flash.Error.MissingRequiredArgument;
    const vault_path = ctx.getString("path") orelse "/home/user/.config/gvault";
    const verbose = ctx.getFlag("verbose");

    if (verbose) {
        std.debug.print("🔧 Verbose mode: Initializing vault at: {s}\n", .{vault_path});
    }

    var vault = gvault_lib.Vault.init(global_allocator, vault_path) catch |err| {
        std.debug.print("❌ Error initializing vault: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    vault.unlock(passphrase) catch |err| {
        std.debug.print("❌ Error unlocking vault: {}\n", .{err});
        vault.deinit();
        return flash.Error.InvalidInput;
    };

    std.debug.print("✅ Vault initialized and unlocked at: {s}\n", .{vault_path});
    std.debug.print("🔐 Master passphrase set and vault ready for use.\n", .{});

    vault.deinit();
}

fn unlockHandler(ctx: flash.Context) flash.Error!void {
    const passphrase = ctx.getString("passphrase") orelse return flash.Error.MissingRequiredArgument;
    const vault_path = ctx.getString("path") orelse "/home/user/.config/gvault";
    const verbose = ctx.getFlag("verbose");

    if (verbose) {
        std.debug.print("🔧 Verbose mode: Unlocking vault at: {s}\n", .{vault_path});
    }

    if (global_vault) |*vault| {
        vault.deinit();
    }

    global_vault = gvault_lib.Vault.init(global_allocator, vault_path) catch |err| {
        std.debug.print("❌ Error initializing vault: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    global_vault.?.unlock(passphrase) catch |err| {
        std.debug.print("❌ Error unlocking vault: {}\n", .{err});
        if (global_vault) |*vault| {
            vault.deinit();
            global_vault = null;
        }
        return flash.Error.InvalidInput;
    };

    std.debug.print("🔓 Vault unlocked successfully\n", .{});
}

fn lockHandler(ctx: flash.Context) flash.Error!void {
    _ = ctx;

    if (global_vault) |*vault| {
        vault.lock();
        vault.deinit();
        global_vault = null;
        std.debug.print("🔒 Vault locked and secured\n", .{});
    } else {
        std.debug.print("💡 No vault is currently unlocked\n", .{});
    }
}

fn addHandler(ctx: flash.Context) flash.Error!void {
    if (global_vault == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const data = ctx.getString("data") orelse return flash.Error.MissingRequiredArgument;
    const cred_type_str = ctx.getString("type") orelse "password";
    const verbose = ctx.getFlag("verbose");

    const cred_type = parseCredentialType(cred_type_str) orelse {
        std.debug.print("❌ Invalid credential type '{s}'\n", .{cred_type_str});
        std.debug.print("Valid types: ssh_key, gpg_key, api_token, password, certificate, server_config\n", .{});
        return flash.Error.InvalidInput;
    };

    if (verbose) {
        std.debug.print("🔧 Adding {s} credential: {s}\n", .{ credentialTypeToString(cred_type), name });
    }

    const id = global_vault.?.addCredential(name, cred_type, data) catch |err| {
        std.debug.print("❌ Error adding credential: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    var id_buf: [32]u8 = undefined;
    const id_str = id.toString(&id_buf) catch "unknown";
    std.debug.print("✅ Added {s} '{s}' with ID: {s}\n", .{ credentialTypeToString(cred_type), name, id_str });
}

fn listHandler(ctx: flash.Context) flash.Error!void {
    if (global_vault == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const filter_type_str = ctx.getString("type");
    const verbose = ctx.getFlag("verbose");

    const filter_type = if (filter_type_str) |type_str| parseCredentialType(type_str) else null;

    const credentials = global_vault.?.listCredentials(filter_type) catch |err| {
        std.debug.print("❌ Error listing credentials: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer global_allocator.free(credentials);

    if (verbose) {
        std.debug.print("🔧 Verbose mode: Found {} credentials\n", .{credentials.len});
    }

    std.debug.print("📋 Stored Credentials:\n", .{});
    std.debug.print("────────────────────────────────────────\n", .{});

    if (credentials.len == 0) {
        std.debug.print("   (No credentials found)\n", .{});
        return;
    }

    for (credentials) |cred| {
        var id_buf: [32]u8 = undefined;
        const id_str = cred.id.toString(&id_buf) catch "unknown";
        const type_str = credentialTypeToString(cred.type);

        std.debug.print("🔑 {s}\n", .{cred.name});
        std.debug.print("   Type: {s}\n", .{type_str});
        if (verbose) {
            std.debug.print("   ID: {s}\n", .{id_str});
            std.debug.print("   Created: {}\n", .{cred.metadata.created});
        }
        std.debug.print("\n", .{});
    }
}

fn searchHandler(ctx: flash.Context) flash.Error!void {
    if (global_vault == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const pattern = ctx.getString("pattern") orelse return flash.Error.MissingRequiredArgument;
    const verbose = ctx.getFlag("verbose");

    if (verbose) {
        std.debug.print("🔧 Searching for pattern: '{s}'\n", .{pattern});
    }

    const results = global_vault.?.searchCredentials(pattern) catch |err| {
        std.debug.print("❌ Error searching credentials: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer global_allocator.free(results);

    std.debug.print("🔍 Found {} credentials matching '{s}':\n", .{ results.len, pattern });
    std.debug.print("────────────────────────────────────────\n", .{});

    if (results.len == 0) {
        std.debug.print("   (No matches found)\n", .{});
        return;
    }

    for (results) |cred| {
        const type_str = credentialTypeToString(cred.type);
        std.debug.print("📌 {s} ({s})\n", .{ cred.name, type_str });
    }
}

fn statusHandler(ctx: flash.Context) flash.Error!void {
    const verbose = ctx.getFlag("verbose");

    std.debug.print("⚡ GVault Status:\n", .{});
    std.debug.print("  Version: 0.1.0\n", .{});
    std.debug.print("  Built with: Zig 0.16+\n", .{});

    if (global_vault != null) {
        std.debug.print("  Vault Status: 🔓 Unlocked\n", .{});

        const credentials = global_vault.?.listCredentials(null) catch {
            std.debug.print("  Credentials: ❌ Error loading\n", .{});
            return;
        };
        defer global_allocator.free(credentials);

        std.debug.print("  Credentials: {} stored\n", .{credentials.len});

        if (verbose and credentials.len > 0) {
            std.debug.print("\n📊 Credential Breakdown:\n", .{});
            var counts = [_]u32{0} ** 6; // 6 credential types

            for (credentials) |cred| {
                const idx: usize = switch (cred.type) {
                    .ssh_key => 0,
                    .gpg_key => 1,
                    .api_token => 2,
                    .password => 3,
                    .certificate => 4,
                    .server_config => 5,
                };
                counts[idx] += 1;
            }

            const types = [_][]const u8{ "SSH Keys", "GPG Keys", "API Tokens", "Passwords", "Certificates", "Server Configs" };
            for (counts, types) |count, type_name| {
                if (count > 0) {
                    std.debug.print("  {s}: {}\n", .{ type_name, count });
                }
            }
        }
    } else {
        std.debug.print("  Vault Status: 🔒 Locked\n", .{});
    }

    std.debug.print("\n🚀 Features:\n", .{});
    std.debug.print("  ✅ ChaCha20-Poly1305 encryption\n", .{});
    std.debug.print("  ✅ Multiple credential types\n", .{});
    std.debug.print("  ✅ Search and filtering\n", .{});
    std.debug.print("  ✅ Memory-safe operations\n", .{});
    std.debug.print("  🔨 SSH Agent Protocol (coming soon)\n", .{});
    std.debug.print("  🔨 GPG integration (coming soon)\n", .{});
}

fn testHandler(ctx: flash.Context) flash.Error!void {
    const verbose = ctx.getFlag("verbose");

    if (verbose) {
        std.debug.print("🔧 Running comprehensive test suite...\n", .{});
    }

    // Run the same test as before but through Flash
    const runBasicTest = @import("main.zig").runBasicTest;
    runBasicTest(global_allocator) catch |err| {
        std.debug.print("❌ Test failed: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
}

// Helper functions

fn parseCredentialType(type_str: []const u8) ?gvault_lib.CredentialType {
    if (std.mem.eql(u8, type_str, "ssh_key")) return .ssh_key;
    if (std.mem.eql(u8, type_str, "gpg_key")) return .gpg_key;
    if (std.mem.eql(u8, type_str, "api_token")) return .api_token;
    if (std.mem.eql(u8, type_str, "password")) return .password;
    if (std.mem.eql(u8, type_str, "certificate")) return .certificate;
    if (std.mem.eql(u8, type_str, "server_config")) return .server_config;
    return null;
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

// Flash CLI Definition using chain API

pub fn createCLI(allocator: std.mem.Allocator) !void {
    global_allocator = allocator;

    // Vault management commands
    const init_cmd = flash.chain("init")
        .about("Initialize a new vault with master passphrase")
        .args(&.{
            flash.arg("passphrase", (flash.ArgumentConfig{})
                .withHelp("Master passphrase for the vault")
                .setRequired()),
            flash.arg("path", (flash.ArgumentConfig{})
                .withHelp("Path to vault directory")
                .withDefault(flash.ArgValue{ .string = "/home/user/.config/gvault" })),
        })
        .flags(&.{
            flash.flag("verbose", (flash.FlagConfig{})
                .withShort('v')
                .withHelp("Enable verbose output")),
        })
        .handler(initHandler);

    const unlock_cmd = flash.chain("unlock")
        .about("Unlock an existing vault")
        .args(&.{
            flash.arg("passphrase", (flash.ArgumentConfig{})
                .withHelp("Master passphrase for the vault")
                .setRequired()),
            flash.arg("path", (flash.ArgumentConfig{})
                .withHelp("Path to vault directory")
                .withDefault(flash.ArgValue{ .string = "/home/user/.config/gvault" })),
        })
        .flags(&.{
            flash.flag("verbose", (flash.FlagConfig{})
                .withShort('v')
                .withHelp("Enable verbose output")),
        })
        .handler(unlockHandler);

    const lock_cmd = flash.chain("lock")
        .about("Lock the current vault")
        .handler(lockHandler);

    // Credential management commands
    const add_cmd = flash.chain("add")
        .about("Add a new credential to the vault")
        .args(&.{
            flash.arg("name", (flash.ArgumentConfig{})
                .withHelp("Name for the credential")
                .setRequired()),
            flash.arg("data", (flash.ArgumentConfig{})
                .withHelp("The credential data (password, key, etc.)")
                .setRequired()),
            flash.arg("type", (flash.ArgumentConfig{})
                .withHelp("Type of credential (password, ssh_key, gpg_key, api_token, certificate, server_config)")
                .withDefault(flash.ArgValue{ .string = "password" })),
        })
        .flags(&.{
            flash.flag("verbose", (flash.FlagConfig{})
                .withShort('v')
                .withHelp("Enable verbose output")),
        })
        .handler(addHandler);

    const list_cmd = flash.chain("list")
        .about("List stored credentials")
        .args(&.{
            flash.arg("type", (flash.ArgumentConfig{})
                .withHelp("Filter by credential type")),
        })
        .flags(&.{
            flash.flag("verbose", (flash.FlagConfig{})
                .withShort('v')
                .withHelp("Show detailed information")),
        })
        .handler(listHandler);

    const search_cmd = flash.chain("search")
        .about("Search credentials by name pattern")
        .args(&.{
            flash.arg("pattern", (flash.ArgumentConfig{})
                .withHelp("Search pattern to match against credential names")
                .setRequired()),
        })
        .flags(&.{
            flash.flag("verbose", (flash.FlagConfig{})
                .withShort('v')
                .withHelp("Enable verbose output")),
        })
        .handler(searchHandler);

    // Utility commands
    const status_cmd = flash.chain("status")
        .about("Show vault and system status")
        .flags(&.{
            flash.flag("verbose", (flash.FlagConfig{})
                .withShort('v')
                .withHelp("Show detailed status information")),
        })
        .handler(statusHandler);

    const test_cmd = flash.chain("test")
        .about("Run comprehensive test suite")
        .flags(&.{
            flash.flag("verbose", (flash.FlagConfig{})
                .withShort('v')
                .withHelp("Enable verbose test output")),
        })
        .handler(testHandler);

    // Create main CLI with all commands
    const DemoCLI = flash.CLI(.{
        .name = "gvault",
        .version = "0.1.0",
        .about = "🔐 Terminal Keychain Manager - Secure credential storage for power users",
        .subcommand_required = false,
    });

    var cli = DemoCLI.init(allocator, (flash.CommandConfig{})
        .withAbout("Advanced credential management for terminal workflows")
        .withSubcommands(&.{
            init_cmd,
            unlock_cmd,
            lock_cmd,
            add_cmd,
            list_cmd,
            search_cmd,
            status_cmd,
            test_cmd,
        })
        .withHandler(defaultHandler));

    try cli.run();
}

fn defaultHandler(ctx: flash.Context) flash.Error!void {
    std.debug.print("🔐 GVault - Terminal Keychain Manager v0.1.0\n\n", .{});
    std.debug.print("⚡ Lightning-fast credential management for power users\n\n", .{});

    std.debug.print("Quick Start:\n", .{});
    std.debug.print("  gvault init <passphrase>     Initialize a new vault\n", .{});
    std.debug.print("  gvault unlock <passphrase>   Unlock your vault\n", .{});
    std.debug.print("  gvault add <name> <data>     Add a credential\n", .{});
    std.debug.print("  gvault list                  Show all credentials\n", .{});
    std.debug.print("  gvault status                Show vault status\n", .{});

    std.debug.print("\nExamples:\n", .{});
    std.debug.print("  gvault add github-token ghp_xxx --type=api_token\n", .{});
    std.debug.print("  gvault add prod-server ~/.ssh/id_ed25519 --type=ssh_key\n", .{});
    std.debug.print("  gvault search github\n", .{});
    std.debug.print("  gvault list --type=ssh_key --verbose\n", .{});

    std.debug.print("\n🚀 Future Features:\n", .{});
    std.debug.print("  • SSH Agent Protocol replacement\n", .{});
    std.debug.print("  • GPG key integration\n", .{});
    std.debug.print("  • Hardware security modules\n", .{});
    std.debug.print("  • Auto-loading for server patterns\n", .{});

    std.debug.print("\nRun 'gvault help' for full command reference.\n", .{});
    _ = ctx;
}