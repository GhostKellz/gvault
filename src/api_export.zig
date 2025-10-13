//! API Key Export Module
//! Handles exporting API keys in various formats (env, JSON, .env files, YAML)

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const api_keys = @import("api_keys.zig");
const gvault_lib = @import("gvault");
const Storage = gvault_lib.Storage;

pub const ExportError = error{
    InvalidFormat,
    EmptyFields,
    OutOfMemory,
};

/// Export a single key-value pair in the specified format
pub fn exportField(allocator: Allocator, name: []const u8, value: []const u8, format: api_keys.ExportFormat) ![]u8 {
    return switch (format) {
        .env => try std.fmt.allocPrint(allocator, "export {s}=\"{s}\"\n", .{ name, value }),
        .dotenv => try std.fmt.allocPrint(allocator, "{s}={s}\n", .{ name, value }),
        .json => try std.fmt.allocPrint(allocator, "  \"{s}\": \"{s}\"", .{ name, value }),
        .yaml => try std.fmt.allocPrint(allocator, "{s}: {s}\n", .{ name, value }),
    };
}

/// Export multiple fields to a complete file/output
pub fn exportFields(allocator: Allocator, fields: []const Storage.ApiKeyFieldRow, format: api_keys.ExportFormat) ![]u8 {
    if (fields.len == 0) return ExportError.EmptyFields;

    var buffer = ArrayList(u8){};
    errdefer buffer.deinit(allocator);

    // Add format-specific headers
    switch (format) {
        .json => try buffer.appendSlice(allocator, "{\n"),
        .yaml => try buffer.appendSlice(allocator, "# API Key Configuration\n"),
        .env, .dotenv => {},
    }

    // Export each field
    for (fields, 0..) |field, i| {
        const env_var_name = field.env_var orelse field.field_name;
        const line = try exportField(allocator, env_var_name, field.field_value, format);
        defer allocator.free(line);

        try buffer.appendSlice(allocator, line);

        // Add commas for JSON (except last item)
        if (format == .json and i < fields.len - 1) {
            try buffer.appendSlice(allocator, ",");
        }
        if (format == .json) {
            try buffer.appendSlice(allocator, "\n");
        }
    }

    // Add format-specific footers
    switch (format) {
        .json => try buffer.appendSlice(allocator, "}\n"),
        .yaml, .env, .dotenv => {},
    }

    return buffer.toOwnedSlice(allocator);
}

/// Export fields to a file
pub fn exportToFile(allocator: Allocator, fields: []const Storage.ApiKeyFieldRow, file_path: []const u8, format: api_keys.ExportFormat) !void {
    const content = try exportFields(allocator, fields, format);
    defer allocator.free(content);

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    try file.writeAll(content);
}

/// Create shell-compatible environment variable export
pub fn createShellExport(allocator: Allocator, fields: []const Storage.ApiKeyFieldRow) ![]u8 {
    return exportFields(allocator, fields, .env);
}

/// Create .env file content
pub fn createDotEnv(allocator: Allocator, fields: []const Storage.ApiKeyFieldRow) ![]u8 {
    return exportFields(allocator, fields, .dotenv);
}

/// Create JSON export
pub fn createJSON(allocator: Allocator, fields: []const Storage.ApiKeyFieldRow) ![]u8 {
    return exportFields(allocator, fields, .json);
}

/// Create YAML export
pub fn createYAML(allocator: Allocator, fields: []const Storage.ApiKeyFieldRow) ![]u8 {
    return exportFields(allocator, fields, .yaml);
}

/// Helper to print to stdout (for terminal export)
pub fn printToStdout(content: []const u8) !void {
    // Write directly to stdout using POSIX file descriptor
    const written = try std.posix.write(std.posix.STDOUT_FILENO, content);
    if (written != content.len) {
        return error.ShortWrite;
    }
}

/// Export with metadata comment header
pub fn exportWithMetadata(
    allocator: Allocator,
    fields: []const Storage.ApiKeyFieldRow,
    metadata: Storage.ApiKeyMetadataRow,
    format: api_keys.ExportFormat,
) ![]u8 {
    var buffer = ArrayList(u8){};
    errdefer buffer.deinit(allocator);

    // Add metadata header (as comments)
    const comment_prefix = switch (format) {
        .env, .dotenv, .yaml => "# ",
        .json => "// ", // Non-standard but useful
    };

    try buffer.appendSlice(allocator, try std.fmt.allocPrint(
        allocator,
        "{s}Provider: {s}\n",
        .{ comment_prefix, metadata.provider },
    ));

    if (metadata.environment) |env| {
        try buffer.appendSlice(allocator, try std.fmt.allocPrint(
            allocator,
            "{s}Environment: {s}\n",
            .{ comment_prefix, env },
        ));
    }

    if (metadata.project_id) |pid| {
        try buffer.appendSlice(allocator, try std.fmt.allocPrint(
            allocator,
            "{s}Project: {s}\n",
            .{ comment_prefix, pid },
        ));
    }

    if (metadata.expires_at) |exp| {
        const expires_date = formatTimestamp(exp);
        try buffer.appendSlice(allocator, try std.fmt.allocPrint(
            allocator,
            "{s}Expires: {s}\n",
            .{ comment_prefix, expires_date },
        ));
    }

    try buffer.appendSlice(allocator, try std.fmt.allocPrint(
        allocator,
        "{s}Generated: {s}\n",
        .{ comment_prefix, formatTimestamp(std.time.timestamp()) },
    ));

    try buffer.appendSlice(allocator, "\n");

    // Add the actual fields
    const fields_content = try exportFields(allocator, fields, format);
    defer allocator.free(fields_content);
    try buffer.appendSlice(allocator, fields_content);

    return buffer.toOwnedSlice(allocator);
}

/// Format Unix timestamp to human-readable date
fn formatTimestamp(timestamp: i64) []const u8 {
    // Simple ISO-like format (this is a placeholder - real impl would use proper date formatting)
    _ = timestamp;
    return "2025-10-12"; // TODO: Implement proper date formatting
}

/// Copy content to system clipboard (platform-specific)
pub fn copyToClipboard(content: []const u8) !void {
    // Platform-specific clipboard implementation
    if (@import("builtin").os.tag == .linux) {
        // Try xclip first, then xsel
        const result = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{ "xclip", "-selection", "clipboard" },
            .stdin_behavior = .{
                .Pipe = .{
                    .contents = content,
                },
            },
        }) catch {
            // Fall back to xsel
            _ = std.process.Child.run(.{
                .allocator = std.heap.page_allocator,
                .argv = &[_][]const u8{ "xsel", "--clipboard" },
                .stdin_behavior = .{
                    .Pipe = .{
                        .contents = content,
                    },
                },
            }) catch {
                return error.ClipboardUnavailable;
            };
            return;
        };
        if (result.term.Exited == 0) return;
        return error.ClipboardFailed;
    } else if (@import("builtin").os.tag == .macos) {
        _ = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{"pbcopy"},
            .stdin_behavior = .{
                .Pipe = .{
                    .contents = content,
                },
            },
        }) catch {
            return error.ClipboardUnavailable;
        };
    } else {
        return error.UnsupportedPlatform;
    }
}

/// Auto-clear clipboard after timeout (in seconds)
pub fn autoClearClipboard(delay_seconds: u32) !void {
    std.time.sleep(delay_seconds * std.time.ns_per_s);
    // Clear by copying empty string
    try copyToClipboard("");
}
