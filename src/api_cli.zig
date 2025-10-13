//! API Key CLI Handlers
//! Command handlers for the 'gvault api' subcommand group

const std = @import("std");
const flash = @import("flash");
const gvault_lib = @import("gvault");
const api_keys = @import("api_keys.zig");
const api_export = @import("api_export.zig");

// Reference to the main CLI's global state
const cli = @import("cli.zig");

fn getVault() ?*gvault_lib.Vault {
    return if (cli.global_vault) |*v| v else null;
}

fn getAllocator() std.mem.Allocator {
    return cli.global_allocator;
}

/// Handler for 'gvault api add' - Add a new API key
pub fn addApiKeyHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const provider_str = ctx.getString("provider") orelse "generic";
    const key_value = ctx.getString("key") orelse return flash.Error.MissingRequiredArgument;

    const provider = api_keys.Provider.fromString(provider_str) orelse {
        std.debug.print("❌ Invalid provider '{s}'\n", .{provider_str});
        std.debug.print("Valid providers: aws, github, stripe, openai, anthropic, google_cloud, azure, digitalocean, heroku, sendgrid, twilio, slack, discord, generic\n", .{});
        return flash.Error.InvalidInput;
    };

    const template = api_keys.getProviderTemplate(provider);
    const verbose = ctx.getFlag("verbose");
    const environment = ctx.getString("env");
    const project_id = ctx.getString("project");
    const region = ctx.getString("region");
    const expires_days = ctx.getString("expires-in-days");
    const notes = ctx.getString("notes");

    if (verbose) {
        std.debug.print("🔧 Adding {s} API key: {s}\n", .{ template.display_name, name });
    }

    // Create the credential
    const cred_id = getVault().?.addCredential(name, .api_token, key_value) catch |err| {
        std.debug.print("❌ Error adding API key: {}\n", .{err});
        return flash.Error.InvalidInput;
    };

    // Get the internal database ID (we need to extend vault API for this)
    // For now, we'll use a workaround - this should be improved
    if (getVault().?.db) |db| {
        // Calculate expiration timestamp if provided
        const expires_at: ?i64 = if (expires_days) |days_str|
            blk: {
                const days = std.fmt.parseInt(u32, days_str, 10) catch {
                    std.debug.print("❌ Invalid expires-in-days value\n", .{});
                    break :blk null;
                };
                const now = std.time.timestamp();
                break :blk now + (@as(i64, days) * 86400);
            }
        else
            null;

        // Use the last inserted credential ID
        const db_cred_id = db.next_credential_id - 1;

        // Save API key metadata
        const rotation_days: ?i64 = if (template.default_rotation_days) |days| @as(i64, days) else null;

        _ = db.saveApiKeyMetadata(
            db_cred_id,
            provider_str,
            expires_at,
            null, // last_rotated
            rotation_days,
            project_id,
            region,
            environment,
            notes,
        ) catch |err| {
            std.debug.print("⚠️  Warning: Failed to save API key metadata: {}\n", .{err});
        };

        // If this is a multi-field provider (like AWS), prompt for additional fields
        if (template.fields.len > 1) {
            std.debug.print("📝 This provider requires multiple fields:\n", .{});
            for (template.fields, 0..) |field, i| {
                if (i == 0) {
                    // First field was already provided as 'key'
                    _ = db.saveApiKeyField(db_cred_id, field.name, key_value, field.env_var) catch |err| {
                        std.debug.print("⚠️  Warning: Failed to save field: {}\n", .{err});
                    };
                    continue;
                }

                if (field.required) {
                    std.debug.print("  ⚠️  Required field '{s}' ({s}) - use 'gvault api add-field' to add it\n", .{ field.name, field.description });
                } else {
                    std.debug.print("  📌 Optional field '{s}' ({s})\n", .{ field.name, field.description });
                }
            }
        } else {
            // Single field - save it
            _ = db.saveApiKeyField(db_cred_id, template.fields[0].name, key_value, template.fields[0].env_var) catch |err| {
                std.debug.print("⚠️  Warning: Failed to save field: {}\n", .{err});
            };
        }
    }

    var id_buf: [32]u8 = undefined;
    const id_str = cred_id.toString(&id_buf) catch "unknown";

    std.debug.print("✅ Added {s} API key '{s}'\n", .{ template.display_name, name });
    std.debug.print("   ID: {s}\n", .{id_str});

    if (template.documentation_url) |url| {
        std.debug.print("   📚 Documentation: {s}\n", .{url});
    }

    if (template.default_rotation_days) |days| {
        std.debug.print("   🔄 Recommended rotation: every {d} days\n", .{days});
    }
}

/// Handler for 'gvault api list' - List API keys with expiration status
pub fn listApiKeysHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const verbose = ctx.getFlag("verbose");
    const expiring_soon = ctx.getFlag("expiring-soon");
    const expired_only = ctx.getFlag("expired");

    const provider_filter = ctx.getString("provider");

    const credentials = getVault().?.listCredentials(.api_token) catch |err| {
        std.debug.print("❌ Error listing API keys: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer getAllocator().free(credentials);

    std.debug.print("🔑 API Keys:\n", .{});
    std.debug.print("────────────────────────────────────────\n", .{});

    if (credentials.len == 0) {
        std.debug.print("   (No API keys found)\n", .{});
        return;
    }

    const vault = getVault().?;
    var shown_count: usize = 0;

    for (credentials) |cred| {
        // Load metadata if available
        if (vault.db) |db| {
            // Find credential ID from database
            // This is a workaround - we should improve the vault API
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

                // Load API key metadata
                var api_meta = db.loadApiKeyMetadata(row.id, getAllocator()) catch continue;

                if (api_meta) |*meta| {
                    defer meta.deinit(getAllocator());

                    // Apply filters
                    if (provider_filter) |pf| {
                        if (!std.mem.eql(u8, meta.provider, pf)) continue;
                    }

                    const is_expired = if (meta.expires_at) |exp| std.time.timestamp() >= exp else false;
                    const days_until_exp: ?i64 = if (meta.expires_at) |exp|
                        @divFloor(exp - std.time.timestamp(), 86400)
                    else
                        null;

                    if (expired_only and !is_expired) continue;
                    if (expiring_soon and days_until_exp != null) {
                        if (days_until_exp.? > 30 or days_until_exp.? < 0) continue;
                    }

                    shown_count += 1;

                    // Display the API key
                    const status_icon = if (is_expired) "❌" else if (days_until_exp != null and days_until_exp.? <= 30) "⚠️ " else "✅";

                    std.debug.print("{s} {s} ({s})\n", .{ status_icon, cred.name, meta.provider });

                    if (meta.environment) |env| {
                        std.debug.print("   Environment: {s}\n", .{env});
                    }

                    if (meta.expires_at) |_| {
                        if (is_expired) {
                            std.debug.print("   Status: EXPIRED\n", .{});
                        } else if (days_until_exp) |days| {
                            std.debug.print("   Expires in: {d} days\n", .{days});
                        }
                    } else {
                        std.debug.print("   Expires: Never\n", .{});
                    }

                    if (verbose) {
                        if (meta.project_id) |pid| {
                            std.debug.print("   Project: {s}\n", .{pid});
                        }
                        if (meta.region) |reg| {
                            std.debug.print("   Region: {s}\n", .{reg});
                        }

                        // Check rotation status
                        if (meta.rotation_days) |rot_days| {
                            const last_rotation = meta.last_rotated orelse row.created_at;
                            const days_since = @divFloor(std.time.timestamp() - last_rotation, 86400);
                            const needs_rotation = days_since >= rot_days;

                            if (needs_rotation) {
                                std.debug.print("   🔄 Rotation: DUE ({d} days overdue)\n", .{days_since - rot_days});
                            } else {
                                std.debug.print("   🔄 Next rotation: {d} days\n", .{rot_days - days_since});
                            }
                        }
                    }

                    std.debug.print("\n", .{});
                }
            }
        }
    }

    if (shown_count == 0) {
        std.debug.print("   (No API keys matching filters)\n", .{});
    }
}

/// Handler for 'gvault api export' - Export API key to various formats
pub fn exportApiKeyHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const format_str = ctx.getString("format") orelse "env";
    const output_file = ctx.getString("output");

    const format: api_keys.ExportFormat = blk: {
        if (std.mem.eql(u8, format_str, "env")) break :blk .env;
        if (std.mem.eql(u8, format_str, "json")) break :blk .json;
        if (std.mem.eql(u8, format_str, "dotenv") or std.mem.eql(u8, format_str, ".env")) break :blk .dotenv;
        if (std.mem.eql(u8, format_str, "yaml")) break :blk .yaml;

        std.debug.print("❌ Invalid format '{s}'. Use: env, json, dotenv, yaml\n", .{format_str});
        return flash.Error.InvalidInput;
    };

    // Find the credential by name
    const results = getVault().?.searchCredentials(name) catch |err| {
        std.debug.print("❌ Error searching for API key: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer getAllocator().free(results);

    if (results.len == 0) {
        std.debug.print("❌ API key '{s}' not found\n", .{name});
        return flash.Error.InvalidInput;
    }

    if (results.len > 1) {
        std.debug.print("❌ Multiple API keys match '{s}'. Please be more specific.\n", .{name});
        return flash.Error.InvalidInput;
    }

    const vault = getVault().?;

    // Load fields from database
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
            if (!std.mem.eql(u8, row.name, results[0].name)) continue;

            // Load API key fields
            var fields = db.loadApiKeyFields(row.id, getAllocator()) catch |err| {
                std.debug.print("❌ Error loading API key fields: {}\n", .{err});
                return flash.Error.InvalidInput;
            };
            defer {
                for (fields.items) |*field| {
                    field.deinit(getAllocator());
                }
                fields.deinit(getAllocator());
            }

            if (fields.items.len == 0) {
                std.debug.print("⚠️  No fields found for this API key\n", .{});
                return;
            }

            // Export the fields
            const content = api_export.exportFields(getAllocator(), fields.items, format) catch |err| {
                std.debug.print("❌ Error exporting API key: {}\n", .{err});
                return flash.Error.InvalidInput;
            };
            defer getAllocator().free(content);

            if (output_file) |file_path| {
                // Write to file
                api_export.exportToFile(getAllocator(), fields.items, file_path, format) catch |err| {
                    std.debug.print("❌ Error writing to file: {}\n", .{err});
                    return flash.Error.InvalidInput;
                };
                std.debug.print("✅ Exported to {s}\n", .{file_path});
            } else {
                // Print to stdout
                std.debug.print("📋 Exported API key '{s}':\n", .{name});
                std.debug.print("────────────────────────────────────────\n", .{});
                api_export.printToStdout(content) catch |err| {
                    std.debug.print("❌ Error printing export: {}\n", .{err});
                    return flash.Error.InvalidInput;
                };
                std.debug.print("────────────────────────────────────────\n", .{});
            }

            return;
        }
    }

    std.debug.print("❌ Failed to export API key\n", .{});
}

/// Handler for 'gvault api rotate' - Mark an API key as rotated
pub fn rotateApiKeyHandler(ctx: flash.Context) flash.Error!void {
    if (getVault() == null) {
        std.debug.print("❌ No vault loaded. Run 'gvault unlock' first.\n", .{});
        return flash.Error.InvalidInput;
    }

    const name = ctx.getString("name") orelse return flash.Error.MissingRequiredArgument;
    const new_key = ctx.getString("new-key");

    // Find the credential
    const results = getVault().?.searchCredentials(name) catch |err| {
        std.debug.print("❌ Error searching for API key: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer getAllocator().free(results);

    if (results.len == 0) {
        std.debug.print("❌ API key '{s}' not found\n", .{name});
        return flash.Error.InvalidInput;
    }

    const vault = getVault().?;

    // Update rotation timestamp
    if (vault.db) |db| {
        var cred_rows = db.loadCredentials(getAllocator()) catch return flash.Error.InvalidInput;
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
            if (!std.mem.eql(u8, row.name, results[0].name)) continue;

            // Load existing metadata
            var api_meta = db.loadApiKeyMetadata(row.id, getAllocator()) catch continue;

            if (api_meta) |*meta| {
                defer meta.deinit(getAllocator());

                // Update last_rotated timestamp
                _ = db.saveApiKeyMetadata(
                    row.id,
                    meta.provider,
                    meta.expires_at,
                    std.time.timestamp(), // last_rotated = now
                    meta.rotation_days,
                    meta.project_id,
                    meta.region,
                    meta.environment,
                    meta.notes,
                ) catch |err| {
                    std.debug.print("❌ Error updating rotation timestamp: {}\n", .{err});
                    return flash.Error.InvalidInput;
                };

                // If new key provided, update the credential
                if (new_key) |nk| {
                    vault.updateCredential(results[0].id, nk) catch |err| {
                        std.debug.print("❌ Error updating API key: {}\n", .{err});
                        return flash.Error.InvalidInput;
                    };
                    std.debug.print("✅ API key '{s}' rotated and updated\n", .{name});
                } else {
                    std.debug.print("✅ API key '{s}' marked as rotated\n", .{name});
                    std.debug.print("⚠️  Remember to update the actual key value with 'gvault api rotate {s} --new-key=<key>'\n", .{name});
                }

                if (meta.rotation_days) |days| {
                    std.debug.print("🔄 Next rotation due in {d} days\n", .{days});
                }

                return;
            }
        }
    }

    std.debug.print("❌ Failed to rotate API key\n", .{});
}

/// Handler for 'gvault api providers' - List available providers
pub fn listProvidersHandler(ctx: flash.Context) flash.Error!void {
    _ = ctx;

    std.debug.print("🏢 Available API Key Providers:\n", .{});
    std.debug.print("────────────────────────────────────────\n", .{});

    const providers = api_keys.listProviders(getAllocator()) catch |err| {
        std.debug.print("❌ Error listing providers: {}\n", .{err});
        return flash.Error.InvalidInput;
    };
    defer getAllocator().free(providers);

    for (providers) |provider| {
        const template = api_keys.getProviderTemplate(provider);
        std.debug.print("📌 {s}\n", .{template.display_name});
        std.debug.print("   ID: {s}\n", .{provider.toString()});
        std.debug.print("   Fields: {d}\n", .{template.fields.len});

        for (template.fields) |field| {
            const req = if (field.required) "required" else "optional";
            std.debug.print("     • {s} ({s}) - {s}\n", .{ field.name, req, field.description });
        }

        if (template.default_rotation_days) |days| {
            std.debug.print("   Rotation: {d} days\n", .{days});
        }

        if (template.documentation_url) |url| {
            std.debug.print("   Docs: {s}\n", .{url});
        }

        std.debug.print("\n", .{});
    }
}
