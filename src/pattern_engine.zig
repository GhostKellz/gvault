const std = @import("std");
const gvault = @import("gvault");

const Allocator = std.mem.Allocator;
const PatternKind = gvault.ServerPatternKind;
const ServerPattern = gvault.ServerPattern;

pub const PatternMatchError = error{
    OutOfMemory,
};

pub const MatchResult = struct {
    credential_id: gvault.CredentialId,
    kind: PatternKind,
    score: usize,
};

/// Resolve the best credential for a hostname according to configured server patterns.
/// Falls back to credential name exact match when no explicit pattern is provided.
pub fn resolveCredentialId(
    allocator: Allocator,
    vault: *gvault.Vault,
    hostname: []const u8,
) PatternMatchError!?MatchResult {
    if (hostname.len == 0) return null;

    const host_lower = try allocator.dupe(u8, hostname);
    defer allocator.free(host_lower);
    _ = std.ascii.lowerString(host_lower, hostname);

    const credentials = vault.listCredentials(null) catch |err| {
        switch (err) {
            error.OutOfMemory => return PatternMatchError.OutOfMemory,
            else => {
                std.log.warn("pattern_engine: unable to list credentials: {s}", .{@errorName(err)});
                return null;
            },
        }
    };
    defer vault.freeCredentialSlice(credentials);

    var best: ?MatchResult = null;

    for (credentials) |cred| {
        var matched = false;

        if (cred.metadata.server_patterns) |pattern_list| {
            for (pattern_list.items) |pattern| {
                const maybe_score = matchPattern(allocator, hostname, host_lower, pattern);
                if (maybe_score) |score| {
                    matched = true;
                    best = updateBest(best, cred.id, pattern.kind, score);
                }
            }
        }

        if (!matched) {
            const default_pattern = ServerPattern{ .value = cred.name, .kind = .exact };
            if (matchPattern(allocator, hostname, host_lower, default_pattern)) |score| {
                best = updateBest(best, cred.id, .exact, score);
            }
        }
    }

    return best;
}

fn updateBest(current: ?MatchResult, id: gvault.CredentialId, kind: PatternKind, score: usize) ?MatchResult {
    if (current) |best| {
        if (score > best.score) {
            return MatchResult{ .credential_id = id, .kind = kind, .score = score };
        }
        return best;
    }

    return MatchResult{ .credential_id = id, .kind = kind, .score = score };
}

fn matchPattern(
    allocator: Allocator,
    host_original: []const u8,
    host_lower: []const u8,
    pattern: ServerPattern,
) ?usize {
    return switch (pattern.kind) {
        .exact => matchExact(host_original, pattern.value),
        .wildcard => matchWildcard(allocator, host_lower, pattern.value) catch {
            std.log.warn("pattern_engine: failed wildcard match due to OOM", .{});
            return null;
        },
        .regex => matchRegex(allocator, host_original, pattern.value) catch |err| {
            std.log.warn("pattern_engine: invalid regex '{s}': {s}", .{ pattern.value, @errorName(err) });
            return null;
        },
        .cidr => matchCidr(host_original, pattern.value),
    };
}

fn matchExact(host: []const u8, pattern: []const u8) ?usize {
    if (!equalsIgnoreCase(host, pattern)) return null;
    return computeScore(.exact, pattern, pattern.len);
}

fn matchWildcard(allocator: Allocator, host_lower: []const u8, pattern: []const u8) !?usize {
    const lower = try allocator.dupe(u8, pattern);
    defer allocator.free(lower);
    _ = std.ascii.lowerString(lower, pattern);

    if (!wildcardMatch(lower, host_lower)) return null;

    const literals = countLiteralCharacters(pattern);
    return computeScore(.wildcard, pattern, literals);
}

fn matchRegex(allocator: Allocator, host: []const u8, pattern: []const u8) !?usize {
    const program = compileRegex(allocator, pattern) catch |err| {
        return switch (err) {
            error.OutOfMemory => PatternMatchError.OutOfMemory,
            else => {
                std.log.warn("pattern_engine: invalid regex '{s}': {s}", .{ pattern, @errorName(err) });
                return null;
            },
        };
    };
    defer allocator.free(program.buffer);

    if (!executeRegex(program.buffer[0..program.count], host)) return null;

    return computeScore(.regex, pattern, pattern.len);
}

const RegexCompileError = error{ OutOfMemory, InvalidPattern, TooManyRanges };

const Quantifier = enum { exactly_one, zero_or_one, zero_or_more, one_or_more };

const TokenKind = enum { literal, any, class };

const ClassRange = struct { start: u8, end: u8 };

const MaxClassRanges = 32;

const ClassRangeSet = struct {
    ranges: [MaxClassRanges]ClassRange = undefined,
    count: usize = 0,

    fn addRange(self: *ClassRangeSet, start_char: u8, end_char: u8) RegexCompileError!void {
        if (self.count >= MaxClassRanges) return RegexCompileError.TooManyRanges;
        const start = @min(start_char, end_char);
        const end = @max(start_char, end_char);
        self.ranges[self.count] = .{ .start = start, .end = end };
        self.count += 1;
    }

    fn matches(self: *const ClassRangeSet, c: u8) bool {
        var idx: usize = 0;
        while (idx < self.count) : (idx += 1) {
            const range = self.ranges[idx];
            if (c >= range.start and c <= range.end) return true;
        }
        return false;
    }
};

const Token = struct {
    kind: TokenKind = .literal,
    literal: u8 = 0,
    class_set: ClassRangeSet = .{},
    quant: Quantifier = .exactly_one,
};

const RegexProgram = struct {
    buffer: []Token,
    count: usize,
};

fn compileRegex(allocator: Allocator, pattern: []const u8) RegexCompileError!RegexProgram {
    var tokens_buffer = try allocator.alloc(Token, pattern.len);
    errdefer allocator.free(tokens_buffer);

    var count: usize = 0;
    var i: usize = 0;
    while (i < pattern.len) {
        var token = Token{};
        if (pattern[i] == '\\') {
            i += 1;
            if (i >= pattern.len) return RegexCompileError.InvalidPattern;
            token.kind = .literal;
            token.literal = pattern[i];
            i += 1;
        } else if (pattern[i] == '.') {
            token.kind = .any;
            i += 1;
        } else if (pattern[i] == '[') {
            i += 1;
            var set = ClassRangeSet{};
            if (i >= pattern.len) return RegexCompileError.InvalidPattern;
            while (i < pattern.len and pattern[i] != ']') {
                var start_char = pattern[i];
                if (start_char == '\\') {
                    i += 1;
                    if (i >= pattern.len) return RegexCompileError.InvalidPattern;
                    start_char = pattern[i];
                }
                i += 1;
                var end_char = start_char;
                if (i < pattern.len and pattern[i] == '-' and i + 1 < pattern.len and pattern[i + 1] != ']') {
                    i += 1;
                    var range_char = pattern[i];
                    if (range_char == '\\') {
                        i += 1;
                        if (i >= pattern.len) return RegexCompileError.InvalidPattern;
                        range_char = pattern[i];
                    }
                    end_char = range_char;
                    i += 1;
                }
                try set.addRange(start_char, end_char);
            }
            if (i >= pattern.len or pattern[i] != ']') return RegexCompileError.InvalidPattern;
            token.kind = .class;
            token.class_set = set;
            i += 1;
        } else {
            token.kind = .literal;
            token.literal = pattern[i];
            i += 1;
        }

        if (i < pattern.len) {
            switch (pattern[i]) {
                '*' => {
                    token.quant = .zero_or_more;
                    i += 1;
                },
                '+' => {
                    token.quant = .one_or_more;
                    i += 1;
                },
                '?' => {
                    token.quant = .zero_or_one;
                    i += 1;
                },
                else => {},
            }
        }

        tokens_buffer[count] = token;
        count += 1;
    }

    return RegexProgram{ .buffer = tokens_buffer, .count = count };
}

fn executeRegex(tokens: []const Token, text: []const u8) bool {
    return matchTokens(tokens, 0, text, 0);
}

fn matchTokens(tokens: []const Token, token_index: usize, text: []const u8, text_index: usize) bool {
    if (token_index == tokens.len) {
        return text_index == text.len;
    }

    const token = tokens[token_index];

    return switch (token.quant) {
        .exactly_one => if (text_index < text.len and tokenMatches(token, text[text_index]))
            matchTokens(tokens, token_index + 1, text, text_index + 1)
        else
            false,
        .zero_or_one => blk: {
            if (text_index < text.len and tokenMatches(token, text[text_index]) and
                matchTokens(tokens, token_index + 1, text, text_index + 1))
            {
                break :blk true;
            }
            break :blk matchTokens(tokens, token_index + 1, text, text_index);
        },
        .zero_or_more => matchZeroOrMore(tokens, token, token_index, text, text_index),
        .one_or_more => {
            if (text_index >= text.len or !tokenMatches(token, text[text_index])) return false;
            return matchZeroOrMore(tokens, token, token_index, text, text_index + 1);
        },
    };
}

fn matchZeroOrMore(
    tokens: []const Token,
    token: Token,
    token_index: usize,
    text: []const u8,
    text_index: usize,
) bool {
    var idx = text_index;
    while (true) {
        if (matchTokens(tokens, token_index + 1, text, idx)) return true;
        if (idx == text.len) break;
        if (!tokenMatches(token, text[idx])) break;
        idx += 1;
    }
    return false;
}

fn tokenMatches(token: Token, c: u8) bool {
    return switch (token.kind) {
        .literal => token.literal == c,
        .any => true,
        .class => token.class_set.matches(c),
    };
}

fn matchCidr(host: []const u8, pattern: []const u8) ?usize {
    const slash_index = std.mem.indexOfScalar(u8, pattern, '/') orelse return null;
    const base_str = pattern[0..slash_index];
    const prefix_str = pattern[slash_index + 1 ..];

    const base_ip = parseIPv4(base_str) orelse return null;
    const host_ip = parseIPv4(host) orelse return null;

    const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return null;
    if (prefix_len > 32) return null;

    const mask: u32 = if (prefix_len == 0) 0 else blk: {
    const shift: u5 = @intCast(32 - prefix_len);
        break :blk (~@as(u32, 0)) << shift;
    };
    if ((base_ip & mask) != (host_ip & mask)) return null;

    return computeScore(.cidr, pattern, prefix_len);
}

fn computeScore(kind: PatternKind, pattern: []const u8, detail: usize) usize {
    return switch (kind) {
        .exact => 4_000 + detail,
        .wildcard => 3_000 + detail,
        .regex => 2_000 + detail,
        .cidr => 1_000 + detail,
    } + pattern.len;
}

fn countLiteralCharacters(pattern: []const u8) usize {
    var count: usize = 0;
    for (pattern) |c| {
        if (c != '*' and c != '?') {
            count += 1;
        }
    }
    return count;
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn wildcardMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star_index: ?usize = null;
    var match_index: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == text[t] or pattern[p] == '?')) {
            p += 1;
            t += 1;
            continue;
        }

        if (p < pattern.len and pattern[p] == '*') {
            star_index = p;
            p += 1;
            match_index = t;
            continue;
        }

        if (star_index) |idx| {
            p = idx + 1;
            match_index += 1;
            t = match_index;
            continue;
        }

        return false;
    }

    while (p < pattern.len and pattern[p] == '*') {
        p += 1;
    }

    return p == pattern.len;
}

fn parseIPv4(text: []const u8) ?u32 {
    if (text.len == 0) return null;

    var parts: [4]u32 = undefined;
    var part_index: usize = 0;
    var start: usize = 0;

    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (text[i] == '.') {
            if (part_index >= 4) return null;
            const segment = text[start..i];
            parts[part_index] = parseIPv4Segment(segment) orelse return null;
            part_index += 1;
            start = i + 1;
        }
    }

    if (part_index != 3) return null;
    const last_segment = text[start..];
    parts[part_index] = parseIPv4Segment(last_segment) orelse return null;

    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

fn parseIPv4Segment(segment: []const u8) ?u32 {
    if (segment.len == 0 or segment.len > 3) return null;
    const value = std.fmt.parseInt(u10, segment, 10) catch return null;
    if (value > 255) return null;
    return value;
}

const testing = std.testing;

test "pattern engine resolves best match" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const tmp_path = try std.fmt.allocPrint(allocator, "/tmp/gvault_pattern_engine-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(tmp_path);

    var tmp_dir = try std.fs.cwd().makeOpenPath(tmp_path, .{});
    defer {
        tmp_dir.close();
        std.fs.cwd().deleteTree(tmp_path) catch {};
    }

    var vault = try gvault.Vault.init(allocator, tmp_path);
    defer vault.deinit();

    try vault.unlock("test-passphrase");

    const ssh_id = try vault.addCredential("prod-ssh", .ssh_key, "ssh-secret");
    const staging_id = try vault.addCredential("staging", .ssh_key, "staging-secret");
    const cidr_id = try vault.addCredential("corp-net", .api_token, "token");

    try vault.setCredentialPatterns(ssh_id, &.{
        .{ .value = "prod.example.com", .kind = .exact },
        .{ .value = "prod-*.example.com", .kind = .wildcard },
    });

    try vault.setCredentialPatterns(staging_id, &.{
        .{ .value = "staging-[0-9]+\\.example\\.com", .kind = .regex },
    });

    try vault.setCredentialPatterns(cidr_id, &.{
        .{ .value = "10.0.0.0/24", .kind = .cidr },
    });

    const result_exact = try resolveCredentialId(allocator, &vault, "prod.example.com");
    try testing.expect(result_exact != null);
    try testing.expectEqualSlices(u8, ssh_id.bytes[0..], result_exact.?.credential_id.bytes[0..]);

    const result_wildcard = try resolveCredentialId(allocator, &vault, "prod-db.example.com");
    try testing.expect(result_wildcard != null);
    try testing.expectEqualSlices(u8, ssh_id.bytes[0..], result_wildcard.?.credential_id.bytes[0..]);

    const result_regex = try resolveCredentialId(allocator, &vault, "staging-42.example.com");
    try testing.expect(result_regex != null);
    try testing.expectEqualSlices(u8, staging_id.bytes[0..], result_regex.?.credential_id.bytes[0..]);

    const result_cidr = try resolveCredentialId(allocator, &vault, "10.0.0.5");
    try testing.expect(result_cidr != null);
    try testing.expectEqualSlices(u8, cidr_id.bytes[0..], result_cidr.?.credential_id.bytes[0..]);

    const result_none = try resolveCredentialId(allocator, &vault, "unknown-host");
    try testing.expect(result_none == null);
}
