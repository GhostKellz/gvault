const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const zqlite = @import("zqlite");

const StorageError = error{
    StorageInsertFailed,
    InvalidMetadata,
};

pub const VaultDatabase = struct {
    allocator: Allocator,
    db_allocator: Allocator,
    db_path: []const u8,
    integrity_key: [32]u8,
    conn: *zqlite.Connection,
    next_credential_id: i64,
    next_server_pattern_id: i64,

    pub fn init(allocator: Allocator, db_path: []const u8) !*VaultDatabase {
        const self = try allocator.create(VaultDatabase);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.db_allocator = std.heap.page_allocator;
        self.db_path = try allocator.dupe(u8, db_path);
        errdefer allocator.free(self.db_path);

        crypto.random.bytes(&self.integrity_key);

        self.conn = try zqlite.open(self.db_allocator, self.db_path);
        errdefer self.conn.close();

        try self.ensureSchema();

        self.next_credential_id = try self.computeNextId("credentials");
        self.next_server_pattern_id = try self.computeNextId("server_patterns");
        if (self.next_credential_id < 1) self.next_credential_id = 1;
        if (self.next_server_pattern_id < 1) self.next_server_pattern_id = 1;

        return self;
    }

    pub fn deinit(self: *VaultDatabase) void {
        @memset(&self.integrity_key, 0);
        self.conn.close();
        self.allocator.free(self.db_path);
        self.allocator.destroy(self);
    }

    pub fn loadMetadata(self: *VaultDatabase) !?VaultMetadata {
        var result = try self.conn.query(
            "SELECT version, kdf_algorithm, salt, auto_lock_timeout, integrity_hash, integrity_key FROM metadata WHERE id = 1",
        );
        defer result.deinit();

        if (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();

            const version_txt = row.getText(0) orelse return StorageError.InvalidMetadata;
            const kdf_txt = row.getText(1) orelse return StorageError.InvalidMetadata;
            const salt_hex = row.getText(2) orelse return StorageError.InvalidMetadata;
            const hash_hex = row.getText(4) orelse return StorageError.InvalidMetadata;
            const key_hex = row.getText(5) orelse return StorageError.InvalidMetadata;

            const salt = try hexToBytesAlloc(self.allocator, salt_hex);
            errdefer self.allocator.free(salt);

            const integrity_hash = try hexToBytesAlloc(self.allocator, hash_hex);
            errdefer self.allocator.free(integrity_hash);

            const integrity_key_bytes = try hexToFixedArray(key_hex, 32);
            self.integrity_key = integrity_key_bytes;

            const auto_lock = if (!row.isNull(3)) row.getInt(3) else null;

            return VaultMetadata{
                .version = try self.allocator.dupe(u8, version_txt),
                .kdf_algorithm = try self.allocator.dupe(u8, kdf_txt),
                .salt = salt,
                .auto_lock_timeout = auto_lock,
                .integrity_hash = integrity_hash,
            };
        }

        return null;
    }

    pub fn upsertMetadata(self: *VaultDatabase, metadata: VaultMetadata) !void {
        const salt_hex = try bytesToHexAlloc(self.allocator, metadata.salt);
        defer self.allocator.free(salt_hex);
        const salt_hex_const: []const u8 = salt_hex;

        const hash_hex = try bytesToHexAlloc(self.allocator, metadata.integrity_hash);
        defer self.allocator.free(hash_hex);
        const hash_hex_const: []const u8 = hash_hex;

        const key_hex = try bytesToHexAlloc(self.allocator, &self.integrity_key);
        defer self.allocator.free(key_hex);
        const key_hex_const: []const u8 = key_hex;

        var stmt = try self.conn.prepare(
            \\INSERT INTO metadata (id, version, kdf_algorithm, salt, auto_lock_timeout, integrity_hash, integrity_key)
            \\VALUES (1, ?, ?, ?, ?, ?, ?)
            \\ON CONFLICT(id) DO UPDATE SET
            \\  version = excluded.version,
            \\  kdf_algorithm = excluded.kdf_algorithm,
            \\  salt = excluded.salt,
            \\  auto_lock_timeout = excluded.auto_lock_timeout,
            \\  integrity_hash = excluded.integrity_hash,
            \\  integrity_key = excluded.integrity_key
        );
        defer stmt.deinit();

        try stmt.bind(0, metadata.version);
        try stmt.bind(1, metadata.kdf_algorithm);
        try stmt.bind(2, salt_hex_const);

        if (metadata.auto_lock_timeout) |timeout| {
            try stmt.bind(3, timeout);
        } else {
            try stmt.bindNull(3);
        }

        try stmt.bind(4, hash_hex_const);
        try stmt.bind(5, key_hex_const);

        var exec_result = try stmt.execute(self.conn);
        defer exec_result.deinit();
    }

    pub fn loadCredentials(self: *VaultDatabase, allocator: Allocator) !ArrayList(CredentialRow) {
        var creds = ArrayList(CredentialRow){};
        errdefer creds.deinit(allocator);

        var result = try self.conn.query(
            "SELECT id, credential_type, name, ciphertext, password, nonce, auth_tag, created_at, modified_at, last_used FROM credentials ORDER BY id",
        );
        defer result.deinit();

        while (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();

            const id = row.getInt(0) orelse 0;
            const type_txt = row.getText(1) orelse continue;
            const name_txt = row.getText(2) orelse continue;
            const cipher_hex = row.getText(3) orelse continue;
            const password_txt = row.getText(4) orelse "";
            const nonce_hex = row.getText(5) orelse continue;
            const tag_hex = row.getText(6) orelse continue;
            const created = row.getInt(7) orelse 0;
            const modified = row.getInt(8) orelse 0;
            const last_used = if (!row.isNull(9)) row.getInt(9) else null;

            const credential_type = try allocator.dupe(u8, type_txt);
            errdefer allocator.free(credential_type);

            const name = try allocator.dupe(u8, name_txt);
            errdefer allocator.free(name);

            const ciphertext = try hexToBytesAlloc(allocator, cipher_hex);
            errdefer allocator.free(ciphertext);

            const password = try allocator.dupe(u8, password_txt);
            errdefer allocator.free(password);

            const nonce = try hexToBytesAlloc(allocator, nonce_hex);
            errdefer allocator.free(nonce);

            const auth_tag = try hexToBytesAlloc(allocator, tag_hex);
            errdefer allocator.free(auth_tag);

            try creds.append(allocator, .{
                .id = id,
                .credential_type = credential_type,
                .name = name,
                .username = ciphertext,
                .password = password,
                .nonce = nonce,
                .auth_tag = auth_tag,
                .created_at = created,
                .modified_at = modified,
                .last_used = last_used,
            });
        }

        return creds;
    }

    pub fn saveCredential(self: *VaultDatabase, cred: CredentialRow) !i64 {
        const next_id = self.next_credential_id;
        self.next_credential_id += 1;

        const ciphertext_hex = try bytesToHexAlloc(self.allocator, cred.username);
        defer self.allocator.free(ciphertext_hex);
        const ciphertext_hex_const: []const u8 = ciphertext_hex;

        const nonce_hex = try bytesToHexAlloc(self.allocator, cred.nonce);
        defer self.allocator.free(nonce_hex);
        const nonce_hex_const: []const u8 = nonce_hex;

        const tag_hex = try bytesToHexAlloc(self.allocator, cred.auth_tag);
        defer self.allocator.free(tag_hex);
        const tag_hex_const: []const u8 = tag_hex;

        var stmt = try self.conn.prepare(
            \\INSERT INTO credentials (id, credential_type, name, ciphertext, password, nonce, auth_tag, created_at, modified_at, last_used)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        );
        defer stmt.deinit();

        try stmt.bind(0, next_id);
        try stmt.bind(1, cred.credential_type);
        try stmt.bind(2, cred.name);
        try stmt.bind(3, ciphertext_hex_const);
        try stmt.bind(4, cred.password);
        try stmt.bind(5, nonce_hex_const);
        try stmt.bind(6, tag_hex_const);
        try stmt.bind(7, cred.created_at);
        try stmt.bind(8, cred.modified_at);

        if (cred.last_used) |value| {
            try stmt.bind(9, value);
        } else {
            try stmt.bindNull(9);
        }

        var exec_result = try stmt.execute(self.conn);
        exec_result.deinit();
        return next_id;
    }

    pub fn loadCredentialTags(self: *VaultDatabase, credential_id: i64, allocator: Allocator) !ArrayList([]const u8) {
        var tags = ArrayList([]const u8){};
        errdefer tags.deinit(allocator);

        const sql = try std.fmt.allocPrint(self.allocator, "SELECT tag FROM credential_tags WHERE credential_id = {d} ORDER BY tag", .{credential_id});
        defer self.allocator.free(sql);

        var result = try self.conn.query(sql);
        defer result.deinit();

        while (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();
            const tag_txt = row.getText(0) orelse continue;
            const tag_copy = try allocator.dupe(u8, tag_txt);
            errdefer allocator.free(tag_copy);
            try tags.append(allocator, tag_copy);
        }

        return tags;
    }

    pub fn saveCredentialTag(self: *VaultDatabase, credential_id: i64, tag: []const u8) !void {
        var stmt = try self.conn.prepare("INSERT INTO credential_tags (credential_id, tag) VALUES (?, ?)");
        defer stmt.deinit();

        try stmt.bind(0, credential_id);
        try stmt.bind(1, tag);

        var exec_result = stmt.execute(self.conn) catch |err| {
            switch (err) {
                error.ConstraintViolation => return,
                else => return err,
            }
        };
        exec_result.deinit();
    }

    pub fn deleteCredential(self: *VaultDatabase, credential_id: i64) !void {
        var stmt_api_meta = try self.conn.prepare("DELETE FROM api_key_metadata WHERE credential_id = ?");
        defer stmt_api_meta.deinit();
        try stmt_api_meta.bind(0, credential_id);
        var api_meta_result = try stmt_api_meta.execute(self.conn);
        defer api_meta_result.deinit();

        var stmt_api_fields = try self.conn.prepare("DELETE FROM api_key_fields WHERE credential_id = ?");
        defer stmt_api_fields.deinit();
        try stmt_api_fields.bind(0, credential_id);
        var api_fields_result = try stmt_api_fields.execute(self.conn);
        defer api_fields_result.deinit();

        var stmt_tags = try self.conn.prepare("DELETE FROM credential_tags WHERE credential_id = ?");
        defer stmt_tags.deinit();
        try stmt_tags.bind(0, credential_id);
        var tags_result = try stmt_tags.execute(self.conn);
        defer tags_result.deinit();

        var stmt_patterns = try self.conn.prepare("DELETE FROM server_patterns WHERE credential_id = ?");
        defer stmt_patterns.deinit();
        try stmt_patterns.bind(0, credential_id);
        var patterns_result = try stmt_patterns.execute(self.conn);
        defer patterns_result.deinit();

        var stmt_credential = try self.conn.prepare("DELETE FROM credentials WHERE id = ?");
        defer stmt_credential.deinit();
        try stmt_credential.bind(0, credential_id);
        var credential_result = try stmt_credential.execute(self.conn);
        defer credential_result.deinit();
    }

    // API Key Metadata Storage Functions

    pub fn saveApiKeyMetadata(self: *VaultDatabase, credential_id: i64, provider: []const u8, expires_at: ?i64, last_rotated: ?i64, rotation_days: ?i64, project_id: ?[]const u8, region: ?[]const u8, environment: ?[]const u8, notes: ?[]const u8) !i64 {
        var stmt = try self.conn.prepare(
            \\INSERT INTO api_key_metadata (credential_id, provider, expires_at, last_rotated, rotation_days, project_id, region, environment, notes)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            \\ON CONFLICT(credential_id) DO UPDATE SET
            \\  provider = excluded.provider,
            \\  expires_at = excluded.expires_at,
            \\  last_rotated = excluded.last_rotated,
            \\  rotation_days = excluded.rotation_days,
            \\  project_id = excluded.project_id,
            \\  region = excluded.region,
            \\  environment = excluded.environment,
            \\  notes = excluded.notes
        );
        defer stmt.deinit();

        try stmt.bind(0, credential_id);
        try stmt.bind(1, provider);

        if (expires_at) |exp| {
            try stmt.bind(2, exp);
        } else {
            try stmt.bindNull(2);
        }

        if (last_rotated) |lr| {
            try stmt.bind(3, lr);
        } else {
            try stmt.bindNull(3);
        }

        if (rotation_days) |rd| {
            try stmt.bind(4, rd);
        } else {
            try stmt.bindNull(4);
        }

        if (project_id) |pid| {
            try stmt.bind(5, pid);
        } else {
            try stmt.bindNull(5);
        }

        if (region) |reg| {
            try stmt.bind(6, reg);
        } else {
            try stmt.bindNull(6);
        }

        if (environment) |env| {
            try stmt.bind(7, env);
        } else {
            try stmt.bindNull(7);
        }

        if (notes) |n| {
            try stmt.bind(8, n);
        } else {
            try stmt.bindNull(8);
        }

        var exec_result = try stmt.execute(self.conn);
        defer exec_result.deinit();

        // Return the api_key_metadata id (use manual tracking)
        // Note: In a production system, you'd query SELECT last_insert_rowid()
        return credential_id; // Return the credential ID for now
    }

    pub fn loadApiKeyMetadata(self: *VaultDatabase, credential_id: i64, allocator: Allocator) !?ApiKeyMetadataRow {
        const sql = try std.fmt.allocPrint(self.allocator, "SELECT id, provider, expires_at, last_rotated, rotation_days, project_id, region, environment, notes FROM api_key_metadata WHERE credential_id = {d}", .{credential_id});
        defer self.allocator.free(sql);

        var result = try self.conn.query(sql);
        defer result.deinit();

        if (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();

            const id = row.getInt(0) orelse 0;
            const provider = row.getText(1) orelse return null;
            const expires_at = if (!row.isNull(2)) row.getInt(2) else null;
            const last_rotated = if (!row.isNull(3)) row.getInt(3) else null;
            const rotation_days = if (!row.isNull(4)) row.getInt(4) else null;
            const project_id_txt = row.getText(5);
            const region_txt = row.getText(6);
            const environment_txt = row.getText(7);
            const notes_txt = row.getText(8);

            return ApiKeyMetadataRow{
                .id = id,
                .credential_id = credential_id,
                .provider = try allocator.dupe(u8, provider),
                .expires_at = expires_at,
                .last_rotated = last_rotated,
                .rotation_days = rotation_days,
                .project_id = if (project_id_txt) |pid| try allocator.dupe(u8, pid) else null,
                .region = if (region_txt) |reg| try allocator.dupe(u8, reg) else null,
                .environment = if (environment_txt) |env| try allocator.dupe(u8, env) else null,
                .notes = if (notes_txt) |n| try allocator.dupe(u8, n) else null,
            };
        }

        return null;
    }

    pub fn saveApiKeyScope(self: *VaultDatabase, api_key_metadata_id: i64, scope: []const u8) !void {
        var stmt = try self.conn.prepare("INSERT INTO api_key_scopes (api_key_metadata_id, scope) VALUES (?, ?)");
        defer stmt.deinit();

        try stmt.bind(0, api_key_metadata_id);
        try stmt.bind(1, scope);

        var exec_result = try stmt.execute(self.conn);
        defer exec_result.deinit();
    }

    pub fn loadApiKeyScopes(self: *VaultDatabase, api_key_metadata_id: i64, allocator: Allocator) !ArrayList([]const u8) {
        var scopes = ArrayList([]const u8){};
        errdefer scopes.deinit(allocator);

        const sql = try std.fmt.allocPrint(self.allocator, "SELECT scope FROM api_key_scopes WHERE api_key_metadata_id = {d} ORDER BY scope", .{api_key_metadata_id});
        defer self.allocator.free(sql);

        var result = try self.conn.query(sql);
        defer result.deinit();

        while (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();
            const scope_txt = row.getText(0) orelse continue;
            const scope_copy = try allocator.dupe(u8, scope_txt);
            errdefer allocator.free(scope_copy);
            try scopes.append(allocator, scope_copy);
        }

        return scopes;
    }

    pub fn saveApiKeyField(self: *VaultDatabase, credential_id: i64, field_name: []const u8, field_value: []const u8, env_var: ?[]const u8) !void {
        var stmt = try self.conn.prepare("INSERT INTO api_key_fields (credential_id, field_name, field_value, env_var) VALUES (?, ?, ?, ?)");
        defer stmt.deinit();

        try stmt.bind(0, credential_id);
        try stmt.bind(1, field_name);
        try stmt.bind(2, field_value);

        if (env_var) |ev| {
            try stmt.bind(3, ev);
        } else {
            try stmt.bindNull(3);
        }

        var exec_result = try stmt.execute(self.conn);
        defer exec_result.deinit();
    }

    pub fn loadApiKeyFields(self: *VaultDatabase, credential_id: i64, allocator: Allocator) !ArrayList(ApiKeyFieldRow) {
        var fields = ArrayList(ApiKeyFieldRow){};
        errdefer fields.deinit(allocator);

        const sql = try std.fmt.allocPrint(self.allocator, "SELECT id, field_name, field_value, env_var FROM api_key_fields WHERE credential_id = {d} ORDER BY id", .{credential_id});
        defer self.allocator.free(sql);

        var result = try self.conn.query(sql);
        defer result.deinit();

        while (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();

            const id = row.getInt(0) orelse 0;
            const field_name = row.getText(1) orelse continue;
            const field_value = row.getText(2) orelse continue;
            const env_var_txt = row.getText(3);

            try fields.append(allocator, .{
                .id = id,
                .credential_id = credential_id,
                .field_name = try allocator.dupe(u8, field_name),
                .field_value = try allocator.dupe(u8, field_value),
                .env_var = if (env_var_txt) |ev| try allocator.dupe(u8, ev) else null,
            });
        }

        return fields;
    }

    pub fn saveServerPattern(self: *VaultDatabase, pattern: ServerPatternRow) !i64 {
        const next_id = self.next_server_pattern_id;
        self.next_server_pattern_id += 1;

        var stmt = try self.conn.prepare(
            \\INSERT INTO server_patterns (id, name, hostname, port, protocol, credential_id, jump_host_id, created_at, modified_at)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        );
        defer stmt.deinit();

        try stmt.bind(0, next_id);
        try stmt.bind(1, pattern.name);
        try stmt.bind(2, pattern.hostname);
        try stmt.bind(3, pattern.port);
        try stmt.bind(4, pattern.protocol);

        if (pattern.credential_id) |cred_id| {
            try stmt.bind(5, cred_id);
        } else {
            try stmt.bindNull(5);
        }

        if (pattern.jump_host_id) |jump_id| {
            try stmt.bind(6, jump_id);
        } else {
            try stmt.bindNull(6);
        }

        try stmt.bind(7, pattern.created_at);
        try stmt.bind(8, pattern.modified_at);

        var exec_result = try stmt.execute(self.conn);
        exec_result.deinit();
        return next_id;
    }

    fn computeNextId(self: *VaultDatabase, table_name: []const u8) !i64 {
        const sql = try std.fmt.allocPrint(self.allocator, "SELECT id FROM {s} ORDER BY id DESC LIMIT 1", .{table_name});
        defer self.allocator.free(sql);

        var result = try self.conn.query(sql);
        defer result.deinit();

        if (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();

            if (row.getInt(0)) |id_int| {
                return id_int + 1;
            }

            if (row.getText(0)) |text| {
                return (std.fmt.parseInt(i64, text, 10) catch 0) + 1;
            }
        }

        return 1;
    }

    pub fn loadServerPatterns(self: *VaultDatabase, allocator: Allocator) !ArrayList(ServerPatternRow) {
        var patterns = ArrayList(ServerPatternRow){};
        errdefer patterns.deinit(allocator);

        var result = try self.conn.query(
            "SELECT id, name, hostname, port, protocol, credential_id, jump_host_id, created_at, modified_at FROM server_patterns ORDER BY id",
        );
        defer result.deinit();

        while (result.next()) |row_value| {
            var row = row_value;
            defer row.deinit();

            const id = row.getInt(0) orelse 0;
            const name_txt = row.getText(1) orelse "";
            const host_txt = row.getText(2) orelse "";
            const port = row.getInt(3) orelse 0;
            const protocol_txt = row.getText(4) orelse "ssh";
            const cred_id = if (!row.isNull(5)) row.getInt(5) else null;
            const jump_id = if (!row.isNull(6)) row.getInt(6) else null;
            const created = row.getInt(7) orelse 0;
            const modified = row.getInt(8) orelse 0;

            const name_copy = try allocator.dupe(u8, name_txt);
            errdefer allocator.free(name_copy);

            const host_copy = try allocator.dupe(u8, host_txt);
            errdefer allocator.free(host_copy);

            const protocol_copy = try allocator.dupe(u8, protocol_txt);
            errdefer allocator.free(protocol_copy);

            try patterns.append(allocator, .{
                .id = id,
                .name = name_copy,
                .hostname = host_copy,
                .port = port,
                .protocol = protocol_copy,
                .credential_id = cred_id,
                .jump_host_id = jump_id,
                .created_at = created,
                .modified_at = modified,
            });
        }

        return patterns;
    }

    pub fn logAudit(self: *VaultDatabase, event: AuditEvent) !void {
        var stmt = try self.conn.prepare(
            \\INSERT INTO audit_log (event_type, resource_type, resource_id, action, result, details, ip_address, user_agent, created_at)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        );
        defer stmt.deinit();

        try stmt.bind(0, event.event_type);

        if (event.resource_type) |resource_type| {
            try stmt.bind(1, resource_type);
        } else {
            try stmt.bindNull(1);
        }

        if (event.resource_id) |resource_id| {
            try stmt.bind(2, resource_id);
        } else {
            try stmt.bindNull(2);
        }

        try stmt.bind(3, event.action);
        try stmt.bind(4, event.result);

        if (event.details) |details| {
            try stmt.bind(5, details);
        } else {
            try stmt.bindNull(5);
        }

        if (event.ip_address) |ip| {
            try stmt.bind(6, ip);
        } else {
            try stmt.bindNull(6);
        }

        if (event.user_agent) |ua| {
            try stmt.bind(7, ua);
        } else {
            try stmt.bindNull(7);
        }

        try stmt.bind(8, std.time.timestamp());

        var exec_result = try stmt.execute(self.conn);
        defer exec_result.deinit();
    }

    pub fn computeIntegrityHash(self: *VaultDatabase, db_path: []const u8) ![32]u8 {
        const file = try std.fs.cwd().openFile(db_path, .{});
        defer file.close();

        const file_data = try file.readToEndAlloc(self.allocator, 100 * 1024 * 1024);
        defer self.allocator.free(file_data);

        var hash: [32]u8 = undefined;
        crypto.auth.hmac.sha2.HmacSha256.create(&hash, file_data, &self.integrity_key);

        return hash;
    }

    pub fn verifyIntegrity(self: *VaultDatabase, db_path: []const u8, expected_hash: []const u8) !bool {
        if (expected_hash.len != 32) return false;

        const computed_hash = try self.computeIntegrityHash(db_path);
        var expected: [32]u8 = undefined;
        @memcpy(expected[0..], expected_hash[0..32]);
        return crypto.utils.timingSafeEql([32]u8, computed_hash, expected);
    }

    pub fn updateIntegrityHash(self: *VaultDatabase, db_path: []const u8) !void {
        const hash = try self.computeIntegrityHash(db_path);
        const hash_hex = try bytesToHexAlloc(self.allocator, &hash);
        defer self.allocator.free(hash_hex);
        const hash_hex_const: []const u8 = hash_hex;

        var stmt = try self.conn.prepare("UPDATE metadata SET integrity_hash = ? WHERE id = 1");
        defer stmt.deinit();
        try stmt.bind(0, hash_hex_const);
        var exec_result = try stmt.execute(self.conn);
        defer exec_result.deinit();
    }

    fn ensureSchema(self: *VaultDatabase) !void {
        const statements = [_][]const u8{
            "CREATE TABLE IF NOT EXISTS metadata (\n" ++ "  id INTEGER PRIMARY KEY,\n" ++ "  version TEXT NOT NULL,\n" ++ "  kdf_algorithm TEXT NOT NULL,\n" ++ "  salt TEXT NOT NULL,\n" ++ "  auto_lock_timeout INTEGER,\n" ++ "  integrity_hash TEXT NOT NULL,\n" ++ "  integrity_key TEXT NOT NULL\n" ++ ");",
            "CREATE TABLE IF NOT EXISTS credentials (\n" ++ "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n" ++ "  credential_type TEXT NOT NULL,\n" ++ "  name TEXT NOT NULL,\n" ++ "  ciphertext TEXT NOT NULL,\n" ++ "  password TEXT,\n" ++ "  nonce TEXT NOT NULL,\n" ++ "  auth_tag TEXT NOT NULL,\n" ++ "  created_at INTEGER NOT NULL,\n" ++ "  modified_at INTEGER NOT NULL,\n" ++ "  last_used INTEGER\n" ++ ");",
            "CREATE TABLE IF NOT EXISTS credential_tags (\n" ++ "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n" ++ "  credential_id INTEGER NOT NULL,\n" ++ "  tag TEXT NOT NULL,\n" ++ "  UNIQUE(credential_id, tag)\n" ++ ");",
            "CREATE TABLE IF NOT EXISTS server_patterns (\n" ++ "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n" ++ "  name TEXT NOT NULL,\n" ++ "  hostname TEXT NOT NULL,\n" ++ "  port INTEGER NOT NULL,\n" ++ "  protocol TEXT NOT NULL,\n" ++ "  credential_id INTEGER,\n" ++ "  jump_host_id INTEGER,\n" ++ "  created_at INTEGER NOT NULL,\n" ++ "  modified_at INTEGER NOT NULL\n" ++ ");",
            "CREATE TABLE IF NOT EXISTS audit_log (\n" ++ "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n" ++ "  event_type TEXT NOT NULL,\n" ++ "  resource_type TEXT,\n" ++ "  resource_id INTEGER,\n" ++ "  action TEXT NOT NULL,\n" ++ "  result TEXT NOT NULL,\n" ++ "  details TEXT,\n" ++ "  ip_address TEXT,\n" ++ "  user_agent TEXT,\n" ++ "  created_at INTEGER NOT NULL\n" ++ ");",
            "CREATE TABLE IF NOT EXISTS api_key_metadata (\n" ++ "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n" ++ "  credential_id INTEGER NOT NULL UNIQUE,\n" ++ "  provider TEXT NOT NULL,\n" ++ "  expires_at INTEGER,\n" ++ "  last_rotated INTEGER,\n" ++ "  rotation_days INTEGER,\n" ++ "  project_id TEXT,\n" ++ "  region TEXT,\n" ++ "  environment TEXT,\n" ++ "  notes TEXT,\n" ++ "  FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE\n" ++ ");",
            "CREATE TABLE IF NOT EXISTS api_key_scopes (\n" ++ "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n" ++ "  api_key_metadata_id INTEGER NOT NULL,\n" ++ "  scope TEXT NOT NULL,\n" ++ "  FOREIGN KEY(api_key_metadata_id) REFERENCES api_key_metadata(id) ON DELETE CASCADE\n" ++ ");",
            "CREATE TABLE IF NOT EXISTS api_key_fields (\n" ++ "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n" ++ "  credential_id INTEGER NOT NULL,\n" ++ "  field_name TEXT NOT NULL,\n" ++ "  field_value TEXT NOT NULL,\n" ++ "  env_var TEXT,\n" ++ "  FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE\n" ++ ");",
        };

        self.conn.execute("BEGIN IMMEDIATE;") catch |err| {
            std.log.err("failed to begin schema transaction: {any}", .{err});
            return err;
        };
        errdefer self.conn.execute("ROLLBACK;") catch |rollback_err| {
            std.log.err("schema rollback failed: {any}", .{rollback_err});
        };

        for (statements) |sql| {
            self.conn.execute(sql) catch |err| {
                std.log.err("schema creation failed for statement: {s} -> {any}", .{ sql, err });
                return err;
            };
        }

        try self.conn.execute("COMMIT;");
    }
};

pub const VaultMetadata = struct {
    version: []const u8,
    kdf_algorithm: []const u8,
    salt: []const u8,
    auto_lock_timeout: ?i64,
    integrity_hash: []const u8,

    pub fn deinit(self: *VaultMetadata, allocator: Allocator) void {
        allocator.free(self.version);
        allocator.free(self.kdf_algorithm);
        allocator.free(self.salt);
        allocator.free(self.integrity_hash);
    }
};

pub const AuditEvent = struct {
    event_type: []const u8,
    resource_type: ?[]const u8,
    resource_id: ?i64,
    action: []const u8,
    result: []const u8,
    details: ?[]const u8,
    ip_address: ?[]const u8,
    user_agent: ?[]const u8,
};

pub const CredentialRow = struct {
    id: i64,
    credential_type: []const u8,
    name: []const u8,
    username: []const u8,
    password: []const u8,
    nonce: []const u8,
    auth_tag: []const u8,
    created_at: i64,
    modified_at: i64,
    last_used: ?i64,
};

pub const ServerPatternRow = struct {
    id: i64,
    name: []const u8,
    hostname: []const u8,
    port: i64,
    protocol: []const u8,
    credential_id: ?i64,
    jump_host_id: ?i64,
    created_at: i64,
    modified_at: i64,
};

pub const ApiKeyMetadataRow = struct {
    id: i64,
    credential_id: i64,
    provider: []const u8,
    expires_at: ?i64,
    last_rotated: ?i64,
    rotation_days: ?i64,
    project_id: ?[]const u8,
    region: ?[]const u8,
    environment: ?[]const u8,
    notes: ?[]const u8,

    pub fn deinit(self: *ApiKeyMetadataRow, allocator: Allocator) void {
        allocator.free(self.provider);
        if (self.project_id) |pid| allocator.free(pid);
        if (self.region) |reg| allocator.free(reg);
        if (self.environment) |env| allocator.free(env);
        if (self.notes) |n| allocator.free(n);
    }
};

pub const ApiKeyFieldRow = struct {
    id: i64,
    credential_id: i64,
    field_name: []const u8,
    field_value: []const u8,
    env_var: ?[]const u8,

    pub fn deinit(self: *ApiKeyFieldRow, allocator: Allocator) void {
        allocator.free(self.field_name);
        allocator.free(self.field_value);
        if (self.env_var) |ev| allocator.free(ev);
    }
};

fn bytesToHexAlloc(allocator: Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len == 0) return allocator.alloc(u8, 0);

    const hex_chars = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        out[i * 2] = hex_chars[byte >> 4];
        out[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return out;
}

fn hexToBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    if (hex.len == 0) return allocator.alloc(u8, 0);
    if (hex.len % 2 != 0) return error.InvalidCharacter;

    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);

    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hexToFixedArray(hex: []const u8, comptime expected_len: usize) ![expected_len]u8 {
    if (hex.len != expected_len * 2) return error.InvalidCharacter;
    var out: [expected_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(out[0..], hex);
    return out;
}
