const std = @import("std");
const gvault = @import("gvault");
const session = gvault.session;
const pattern_engine = @import("pattern_engine.zig");

pub const ShellError = error{
    AlreadyInitialized,
    NotInitialized,
    PromptUnavailable,
    UnlockTimedOut,
    UnlockFailed,
    InvalidPassphrase,
    VaultLocked,
    CredentialNotFound,
    StorageError,
    Internal,
    OutOfMemory,
};

pub const CredentialInput = struct {
    name: []const u8,
    secret: []const u8,
    kind: gvault.CredentialType,
};

pub const PatternKind = gvault.ServerPatternKind;
pub const PatternSpecInput = gvault.PatternSpec;

pub const CredentialInfo = struct {
    id: gvault.CredentialId,
    name: []u8,
    kind: gvault.CredentialType,
};

pub const ManagedCredential = struct {
    id: gvault.CredentialId,
    name: []u8,
    kind: gvault.CredentialType,
    secret: []u8,
    match_kind: PatternKind = .exact,
    match_score: usize = 0,

    pub fn deinit(self: *ManagedCredential, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.secret);
    }
};

pub fn init(config: session.SessionConfig) ShellError!void {
    session.init(config) catch |err| {
        return mapSessionError(err);
    };
}

pub fn shutdown() void {
    session.deinit();
}

pub fn getCredentialForHost(
    allocator: std.mem.Allocator,
    hostname: []const u8,
    opts: session.AcquireOptions,
) ShellError!?ManagedCredential {
    const sess = session.acquire(allocator, opts) catch |err| {
        return mapSessionError(err);
    };
    defer session.release(sess);

    const vault = sess.getVault();

    const match = pattern_engine.resolveCredentialId(allocator, vault, hostname) catch |err| {
        return switch (err) {
            error.OutOfMemory => ShellError.OutOfMemory,
        };
    };

    if (match == null) return null;

    const match_result = match.?;

    const cred = vault.getCredential(match_result.credential_id) catch |err| {
        return mapVaultError(err);
    };
    const secret = vault.getCredentialData(cred.id) catch |err| {
        return mapVaultError(err);
    };
    defer vault.freeBuffer(secret);

    const name_copy = allocator.dupe(u8, cred.name) catch return ShellError.OutOfMemory;
    errdefer allocator.free(name_copy);

    const secret_copy = allocator.dupe(u8, secret) catch {
        allocator.free(name_copy);
        return ShellError.OutOfMemory;
    };

    return ManagedCredential{
        .id = cred.id,
        .name = name_copy,
        .kind = cred.type,
        .secret = secret_copy,
    .match_kind = match_result.kind,
        .match_score = match_result.score,
    };
}

pub fn listAllCredentials(
    allocator: std.mem.Allocator,
    opts: session.AcquireOptions,
) ShellError![]CredentialInfo {
    const sess = session.acquire(allocator, opts) catch |err| {
        return mapSessionError(err);
    };
    defer session.release(sess);

    const vault = sess.getVault();

    const credentials = vault.listCredentials(null) catch |err| {
        return mapVaultError(err);
    };
    defer vault.freeCredentialSlice(credentials);

    var infos = allocator.alloc(CredentialInfo, credentials.len) catch return ShellError.OutOfMemory;
    var filled: usize = 0;
    errdefer {
        for (infos[0..filled]) |info| {
            allocator.free(info.name);
        }
        allocator.free(infos);
    }

    for (credentials, 0..) |cred, idx| {
        const name_copy = allocator.dupe(u8, cred.name) catch {
            for (infos[0..filled]) |info| allocator.free(info.name);
            allocator.free(infos);
            return ShellError.OutOfMemory;
        };
        infos[idx] = .{
            .id = cred.id,
            .name = name_copy,
            .kind = cred.type,
        };
        filled = idx + 1;
    }

    return infos;
}

pub fn freeCredentialInfos(allocator: std.mem.Allocator, infos: []CredentialInfo) void {
    for (infos) |info| {
        allocator.free(info.name);
    }
    allocator.free(infos);
}

pub fn addCredential(
    allocator: std.mem.Allocator,
    input: CredentialInput,
    opts: session.AcquireOptions,
) ShellError!gvault.CredentialId {
    const sess = session.acquire(allocator, opts) catch |err| {
        return mapSessionError(err);
    };
    defer session.release(sess);

    const vault = sess.getVault();

    return vault.addCredential(input.name, input.kind, input.secret) catch |err| {
        return mapVaultError(err);
    };
}

pub fn updateCredential(
    allocator: std.mem.Allocator,
    id: gvault.CredentialId,
    new_secret: []const u8,
    opts: session.AcquireOptions,
) ShellError!void {
    const sess = session.acquire(allocator, opts) catch |err| {
        return mapSessionError(err);
    };
    defer session.release(sess);

    const vault = sess.getVault();

    vault.updateCredential(id, new_secret) catch |err| {
        return mapVaultError(err);
    };
}

pub fn deleteCredential(
    allocator: std.mem.Allocator,
    id: gvault.CredentialId,
    opts: session.AcquireOptions,
) ShellError!void {
    const sess = session.acquire(allocator, opts) catch |err| {
        return mapSessionError(err);
    };
    defer session.release(sess);

    const vault = sess.getVault();

    vault.deleteCredential(id) catch |err| {
        return mapVaultError(err);
    };
}

pub fn setCredentialPatterns(
    allocator: std.mem.Allocator,
    id: gvault.CredentialId,
    patterns: []const PatternSpecInput,
    opts: session.AcquireOptions,
) ShellError!void {
    const sess = session.acquire(allocator, opts) catch |err| {
        return mapSessionError(err);
    };
    defer session.release(sess);

    const vault = sess.getVault();

    vault.setCredentialPatterns(id, patterns) catch |err| {
        return mapVaultError(err);
    };
}

fn mapSessionError(err: session.SessionError) ShellError {
    return switch (err) {
        session.SessionError.AlreadyInitialized => ShellError.AlreadyInitialized,
        session.SessionError.NotInitialized => ShellError.NotInitialized,
        session.SessionError.PromptUnavailable => ShellError.PromptUnavailable,
        session.SessionError.UnlockTimedOut => ShellError.UnlockTimedOut,
        session.SessionError.InvalidPassphrase => ShellError.InvalidPassphrase,
        session.SessionError.UnlockFailed => ShellError.UnlockFailed,
        session.SessionError.OutOfMemory => ShellError.OutOfMemory,
    };
}

fn mapVaultError(err: anyerror) ShellError {
    return switch (err) {
        gvault.GVaultError.VaultLocked => ShellError.VaultLocked,
        gvault.GVaultError.CredentialNotFound => ShellError.CredentialNotFound,
        gvault.GVaultError.StorageError => ShellError.StorageError,
        error.OutOfMemory => ShellError.OutOfMemory,
        else => ShellError.Internal,
    };
}

test "shell api pattern-managed flow" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var path_buf: [128]u8 = undefined;
    const vault_path = try std.fmt.bufPrint(&path_buf, "/tmp/gvault_shell_api_test_{d}", .{std.time.timestamp()});

    std.fs.cwd().deleteTree(vault_path) catch {};

    var tmp_dir = try std.fs.cwd().makeOpenPath(vault_path, .{});
    defer tmp_dir.close();

    session.deinit(); // ensure clean slate

    try init(.{
        .allocator = allocator,
        .vault_path = vault_path,
        .prompt = null,
    });

    const acquire_opts = session.AcquireOptions{
        .passphrase = "test-passphrase",
    };

    // First unlock to seed master key
    const warm_session = try session.acquire(allocator, acquire_opts);
    session.release(warm_session);

    const cred_id = try addCredential(allocator, .{
        .name = "prod-server",
        .secret = "ssh-secret",
        .kind = gvault.CredentialType.ssh_key,
    }, acquire_opts);

    const patterns = [_]PatternSpecInput{
        .{ .value = "prod-server", .kind = .exact },
        .{ .value = "prod-*", .kind = .wildcard },
    };
    try setCredentialPatterns(allocator, cred_id, patterns[0..], acquire_opts);

    const info_list = try listAllCredentials(allocator, acquire_opts);
    defer freeCredentialInfos(allocator, info_list);
    try testing.expect(info_list.len == 1);
    try testing.expectEqual(cred_id.bytes, info_list[0].id.bytes);

    const maybe_cred = try getCredentialForHost(allocator, "prod-app-01", acquire_opts);
    try testing.expect(maybe_cred != null);
    var cred = maybe_cred.?;
    try testing.expectEqual(cred_id.bytes, cred.id.bytes);
    try testing.expectEqualStrings("ssh-secret", cred.secret);
    try testing.expectEqual(PatternKind.wildcard, cred.match_kind);
    try testing.expect(cred.match_score > 0);

    cred.deinit(allocator);

    try updateCredential(allocator, cred_id, "ssh-secret-updated", acquire_opts);

    const refreshed = try getCredentialForHost(allocator, "prod-app-01", acquire_opts);
    try testing.expect(refreshed != null);
    var updated = refreshed.?;
    defer updated.deinit(allocator);
    try testing.expectEqualStrings("ssh-secret-updated", updated.secret);

    try deleteCredential(allocator, cred_id, acquire_opts);

    const post_delete = try getCredentialForHost(allocator, "prod-app-01", acquire_opts);
    try testing.expect(post_delete == null);

    shutdown();

    std.fs.cwd().deleteTree(vault_path) catch {};
}
