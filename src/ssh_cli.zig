//! SSH Key CLI Handlers
//! Command handlers for the 'gvault ssh' subcommand group

const std = @import("std");
const flash = @import("flash");
const gvault_lib = @import("gvault");
const ssh_keys = @import("ssh_keys.zig");

// Reference to the main CLI's global state
const cli = @import("cli.zig");

fn getVault() ?*gvault_lib.Vault {
    return if (cli.global_vault) |*v| v else null;
}

fn getAllocator() std.mem.Allocator {
    return cli.global_allocator;
}

/// Handler for 'gvault ssh-keygen' - Generate a new SSH key
pub fn sshKeygenHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const algorithm_str = ctx.getString("algorithm") orelse "ed25519";
    const comment = ctx.getString("comment") orelse name;

    const algorithm = ssh_keys.SshKeyAlgorithm.fromString(algorithm_str) orelse {
        std.debug.print("❌ Invalid algorithm '{s}'\n", .{algorithm_str});
        std.debug.print("Valid algorithms: ssh-ed25519, ecdsa-sha2-nistp256\n", .{});
        return flash.Error.InvalidInput;
    };

    std.debug.print("🔐 Generating {s} SSH key: {s}\n", .{ algorithm.toString(), name });

    // Generate the key pair
    var generator = ssh_keys.SshKeyGenerator.init(getAllocator());
    var key_pair = generator.generate(algorithm, comment) catch |err| {
        std.debug.print("❌ Error generating SSH key: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer key_pair.deinit(getAllocator());

    // Store the private key in the vault (encrypted)
    const cred_id = getVault().?.addCredential(name, .ssh_key, key_pair.private_key) catch |err| {
        std.debug.print("❌ Error adding SSH key to vault: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    // Save SSH key metadata
    if (getVault().?.db) |db| {
        const db_cred_id = db.next_credential_id - 1;

        // Format public key as base64 for storage
        const base64_encoder = std.base64.standard.Encoder;
        const encoded_len = base64_encoder.calcSize(key_pair.public_key.len);
        const encoded_public_key = getAllocator().alloc(u8, encoded_len) catch |err| {
            std.debug.print("❌ Error encoding public key: {}\n", .{err});
            return flash.Error.InvalidInput;
        };
        defer getAllocator().free(encoded_public_key);

        const encoded = base64_encoder.encode(encoded_public_key, key_pair.public_key);

        _ = db.saveSshKeyMetadata(
            db_cred_id,
            algorithm.toString(),
            key_pair.fingerprint,
            comment,
            encoded,
            std.time.timestamp(),
        ) catch |err| {
            std.debug.print("⚠️  Warning: Failed to save SSH key metadata: {}\n", .{err});
        };
    }

    var id_buf: [32]u8 = undefined;
    const id_str = cred_id.toString(&id_buf) catch "unknown";

    std.debug.print("✅ Generated SSH key '{s}'\n", .{name});
    std.debug.print("   ID: {s}\n", .{id_str});
    std.debug.print("   Algorithm: {s}\n", .{algorithm.toString()});
    std.debug.print("   Fingerprint: {s}\n", .{key_pair.fingerprint});
    std.debug.print("\n", .{});
    std.debug.print("💡 Use 'gvault ssh-export {s}' to export the public key\n", .{name});
}

/// Handler for 'gvault ssh-list' - List SSH keys
pub fn sshListHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const verbose = ctx.getFlag("verbose");

    const credentials = getVault().?.listCredentials(.ssh_key) catch |err| {
        std.debug.print("❌ Error listing SSH keys: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer getAllocator().free(credentials);

    std.debug.print("🔑 SSH Keys:\n", .{});
    std.debug.print("────────────────────────────────────────\n", .{});

    if (credentials.len == 0) {
        std.debug.print("   (No SSH keys found)\n", .{});
        return;
    }

    const vault = getVault().?;
    var shown_count: usize = 0;

    for (credentials) |cred| {
        // Load metadata if available
        if (vault.db) |db| {
            var cred_rows = db.loadCredentials(getAllocator()) catch continue;
            defer {
                for (cred_rows.items) |row| {
                    getAllocator().free(row.credential_type);
                    getAllocator().free(row.name);
                    getAllocator().free(row.username);
                    getAllocator().free(row.password);
                    getAllocator().free(row.nonce);
                    getAllocator().free(row.auth_tag);
                }
                cred_rows.deinit(getAllocator());
            }

            for (cred_rows.items) |row| {
                if (!std.mem.eql(u8, row.name, cred.name)) continue;

                // Load SSH key metadata
                var ssh_meta = db.loadSshKeyMetadata(row.id, getAllocator()) catch continue;

                if (ssh_meta) |*meta| {
                    defer meta.deinit(getAllocator());

                    shown_count += 1;

                    std.debug.print("🔑 {s} ({s})\n", .{ cred.name, meta.algorithm });

                    if (meta.comment) |c| {
                        std.debug.print("   Comment: {s}\n", .{c});
                    }

                    std.debug.print("   Fingerprint: {s}\n", .{meta.fingerprint});

                    if (verbose) {
                        if (meta.last_rotated) |lr| {
                            const days_since = @divFloor(std.time.timestamp() - lr, 86400);
                            std.debug.print("   Created: {d} days ago\n", .{days_since});
                        }

                        // Show truncated public key
                        if (meta.public_key_data.len > 40) {
                            std.debug.print("   Public Key: {s}...\n", .{meta.public_key_data[0..40]});
                        } else {
                            std.debug.print("   Public Key: {s}\n", .{meta.public_key_data});
                        }
                    }

                    std.debug.print("\n", .{});
                }
            }
        }
    }

    if (shown_count == 0) {
        std.debug.print("   (No SSH keys with metadata)\n", .{});
    }
}

/// Handler for 'gvault ssh-export' - Export SSH public key
pub fn sshExportHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const output_file = ctx.getString("output");
    const format_str = ctx.getString("format") orelse "openssh";

    if (!std.mem.eql(u8, format_str, "openssh")) {
        std.debug.print("❌ Invalid format '{s}'. Currently only 'openssh' is supported.\n", .{format_str});
        return flash.Error.InvalidInput;
    }

    const vault = getVault().?;

    // Find the credential
    if (vault.db) |db| {
        var cred_rows = db.loadCredentials(getAllocator()) catch |err| {
            std.debug.print("❌ Error loading credentials: {}\n", .{err});
            return flash.Error.InvalidInput;
        };
        defer {
            for (cred_rows.items) |row| {
                getAllocator().free(row.credential_type);
                getAllocator().free(row.name);
                getAllocator().free(row.username);
                getAllocator().free(row.password);
                getAllocator().free(row.nonce);
                getAllocator().free(row.auth_tag);
            }
            cred_rows.deinit(getAllocator());
        }

        for (cred_rows.items) |row| {
            if (!std.mem.eql(u8, row.name, name)) continue;

            // Load SSH key metadata
            var ssh_meta = db.loadSshKeyMetadata(row.id, getAllocator()) catch |err| {
                std.debug.print("❌ Error loading SSH key metadata: {}\n", .{err});
                return flash.Error.InvalidInput;
            };

            if (ssh_meta) |*meta| {
                defer meta.deinit(getAllocator());

                // Format: <algorithm> <base64-key> <comment>
                const comment_part = if (meta.comment) |c| c else name;
                const formatted = std.fmt.allocPrint(
                    getAllocator(),
                    "{s} {s} {s}\n",
                    .{ meta.algorithm, meta.public_key_data, comment_part },
                ) catch |err| {
                    std.debug.print("❌ Error formatting public key: {}\n", .{err});
                    return flash.Error.InvalidInput;
                };
                defer getAllocator().free(formatted);

                if (output_file) |file_path| {
                    // Write to file
                    const file = std.fs.cwd().createFile(file_path, .{}) catch |err| {
                        std.debug.print("❌ Error creating file: {}\n", .{err});
                        return flash.Error.InvalidInput;
                    };
                    defer file.close();

                    file.writeAll(formatted) catch |err| {
                        std.debug.print("❌ Error writing to file: {}\n", .{err});
                        return flash.Error.InvalidInput;
                    };

                    std.debug.print("✅ Exported public key to {s}\n", .{file_path});
                } else {
                    // Print to stdout
                    std.debug.print("📋 Public Key for '{s}':\n", .{name});
                    std.debug.print("────────────────────────────────────────\n", .{});
                    std.debug.print("{s}", .{formatted});
                    std.debug.print("────────────────────────────────────────\n", .{});
                }

                return;
            }
        }
    }

    std.debug.print("❌ SSH key '{s}' not found\n", .{name});
}

/// Handler for 'gvault ssh-import' - Import an existing SSH key
pub fn sshImportHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const private_key_path = ctx.getString("path") orelse return flash.Error.MissingRequiredArgument;
    const comment = ctx.getString("comment") orelse name;

    // Read the private key file
    const file = std.fs.cwd().openFile(private_key_path, .{}) catch |err| {
        std.debug.print("❌ Error opening private key file: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer file.close();

    const file_stat = file.stat() catch |err| {
        std.debug.print("❌ Error getting file stats: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    const private_key_content = getAllocator().alloc(u8, file_stat.size) catch |err| {
        std.debug.print("❌ Error allocating memory: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    errdefer getAllocator().free(private_key_content);

    const bytes_read = file.readAll(private_key_content) catch |err| {
        std.debug.print("❌ Error reading private key file: {}\n", .{err});
        getAllocator().free(private_key_content);
        return flash.Error.InvalidInput;
    };

    if (bytes_read != file_stat.size) {
        std.debug.print("❌ File read incomplete\n", .{});
        getAllocator().free(private_key_content);
        return flash.Error.InvalidInput;
    }
    defer getAllocator().free(private_key_content);

    // Detect algorithm from file content
    const algorithm: ssh_keys.SshKeyAlgorithm = blk: {
        if (std.mem.indexOf(u8, private_key_content, "BEGIN OPENSSH PRIVATE KEY")) |_| {
            // OpenSSH format - need to detect type from content
            if (std.mem.indexOf(u8, private_key_content, "ssh-ed25519")) |_| {
                break :blk .ed25519;
            } else if (std.mem.indexOf(u8, private_key_content, "ecdsa-sha2-nistp256")) |_| {
                break :blk .ecdsa_p256;
            }
        }
        std.debug.print("❌ Cannot detect SSH key algorithm from file\n", .{});
        return flash.Error.InvalidInput;
    };

    std.debug.print("🔐 Importing {s} SSH key: {s}\n", .{ algorithm.toString(), name });

    // Store the private key in the vault (encrypted)
    const cred_id = getVault().?.addCredential(name, .ssh_key, private_key_content) catch |err| {
        std.debug.print("❌ Error adding SSH key to vault: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    // Try to read public key if it exists
    const public_key_path = std.fmt.allocPrint(getAllocator(), "{s}.pub", .{private_key_path}) catch |err| {
        std.debug.print("⚠️  Warning: Cannot generate public key path: {}\n", .{err});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };
    defer getAllocator().free(public_key_path);

    const pub_file = std.fs.cwd().openFile(public_key_path, .{}) catch {
        std.debug.print("⚠️  Warning: Public key file not found at {s}\n", .{public_key_path});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };
    defer pub_file.close();

    const pub_stat = pub_file.stat() catch {
        std.debug.print("⚠️  Warning: Cannot get public key file stats\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };

    const public_key_content = getAllocator().alloc(u8, pub_stat.size) catch {
        std.debug.print("⚠️  Warning: Cannot allocate memory for public key\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };
    errdefer getAllocator().free(public_key_content);

    _ = pub_file.readAll(public_key_content) catch {
        getAllocator().free(public_key_content);
        std.debug.print("⚠️  Warning: Cannot read public key file\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };
    defer getAllocator().free(public_key_content);

    // Parse public key to extract base64 part and calculate fingerprint
    var parts = std.mem.splitScalar(u8, public_key_content, ' ');
    _ = parts.next(); // algorithm
    const base64_key = parts.next() orelse {
        std.debug.print("⚠️  Warning: Cannot parse public key\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };

    // Decode base64 to calculate fingerprint
    const base64_decoder = std.base64.standard.Decoder;
    const decoded_len = base64_decoder.calcSizeForSlice(base64_key) catch {
        std.debug.print("⚠️  Warning: Cannot decode public key\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };

    const decoded_key = getAllocator().alloc(u8, decoded_len) catch {
        std.debug.print("⚠️  Warning: Cannot allocate for decoded key\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };
    defer getAllocator().free(decoded_key);

    base64_decoder.decode(decoded_key, base64_key) catch {
        std.debug.print("⚠️  Warning: Cannot decode public key\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };

    // Calculate fingerprint
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(decoded_key, &hash, .{});

    const hex_chars = "0123456789abcdef";
    const prefix = "SHA256:";
    const fingerprint_len = prefix.len + (hash.len * 3) - 1;

    const fingerprint = getAllocator().alloc(u8, fingerprint_len) catch {
        std.debug.print("⚠️  Warning: Cannot allocate fingerprint\n", .{});
        std.debug.print("✅ Imported SSH key '{s}' (without metadata)\n", .{name});
        return;
    };
    defer getAllocator().free(fingerprint);

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

    // Save SSH key metadata
    if (getVault().?.db) |db| {
        const db_cred_id = db.next_credential_id - 1;

        _ = db.saveSshKeyMetadata(
            db_cred_id,
            algorithm.toString(),
            fingerprint,
            comment,
            base64_key,
            std.time.timestamp(),
        ) catch |err| {
            std.debug.print("⚠️  Warning: Failed to save SSH key metadata: {}\n", .{err});
        };
    }

    var id_buf: [32]u8 = undefined;
    const id_str = cred_id.toString(&id_buf) catch "unknown";

    std.debug.print("✅ Imported SSH key '{s}'\n", .{name});
    std.debug.print("   ID: {s}\n", .{id_str});
    std.debug.print("   Algorithm: {s}\n", .{algorithm.toString()});
    std.debug.print("   Fingerprint: {s}\n", .{fingerprint});
}

/// Handler for 'gvault ssh-delete' - Delete an SSH key
pub fn sshDeleteHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const confirm = ctx.getFlag("confirm");

    if (!confirm) {
        std.debug.print("⚠️  This will permanently delete the SSH key '{s}'\n", .{name});
        std.debug.print("⚠️  Add --confirm flag to proceed\n", .{});
        return;
    }

    // Find and delete the credential
    const results = getVault().?.searchCredentials(name) catch |err| {
        std.debug.print("❌ Error searching for SSH key: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer getAllocator().free(results);

    if (results.len == 0) {
        std.debug.print("❌ SSH key '{s}' not found\n", .{name});
        return flash.Error.InvalidInput;
    }

    if (results.len > 1) {
        std.debug.print("❌ Multiple SSH keys match '{s}'. Please be more specific.\n", .{name});
        return flash.Error.InvalidInput;
    }

    getVault().?.deleteCredential(results[0].id) catch |err| {
        std.debug.print("❌ Error deleting SSH key: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    std.debug.print("✅ Deleted SSH key '{s}'\n", .{name});
}
