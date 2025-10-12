const std = @import("std");
const builtin = @import("builtin");

const posix_mem = switch (builtin.os.tag) {
    .linux, .freebsd, .openbsd, .netbsd, .dragonfly, .macos => struct {
        const c = @cImport({
            @cInclude("sys/mman.h");
        });

        pub fn mlock(addr: *const anyopaque, len: usize) i32 {
            return c.mlock(addr, len);
        }

        pub fn munlock(addr: *const anyopaque, len: usize) i32 {
            return c.munlock(addr, len);
        }
    },
    else => struct {},
};
/// Memory security utilities for sensitive data protection
/// Implements mlock() to prevent swapping and secure memory zeroing

/// Lock memory pages to prevent them from being swapped to disk
/// This is critical for sensitive data like encryption keys
pub fn lockMemory(ptr: [*]u8, len: usize) !void {
    if (len == 0) return;

    switch (builtin.os.tag) {
        .linux, .freebsd, .openbsd, .netbsd, .dragonfly, .macos => {
            // Use mlock to prevent swapping
            const addr = @as(*const anyopaque, @ptrCast(ptr));
            if (posix_mem.mlock(addr, len) != 0) {
                return error.MemoryLockFailed;
            }
        },
        .windows => {
            // Windows VirtualLock equivalent
            const kernel32 = @import("std").os.windows.kernel32;
            const result = kernel32.VirtualLock(ptr, len);
            if (result == 0) {
                return error.MemoryLockFailed;
            }
        },
        else => {
            // Platform doesn't support memory locking
            // Log warning but don't fail
            std.log.warn("Memory locking not supported on this platform", .{});
        },
    }
}

/// Unlock previously locked memory pages
pub fn unlockMemory(ptr: [*]u8, len: usize) !void {
    if (len == 0) return;

    switch (builtin.os.tag) {
        .linux, .freebsd, .openbsd, .netbsd, .dragonfly, .macos => {
            const addr = @as(*const anyopaque, @ptrCast(ptr));
            if (posix_mem.munlock(addr, len) != 0) {
                return error.MemoryUnlockFailed;
            }
        },
        .windows => {
            const kernel32 = @import("std").os.windows.kernel32;
            const result = kernel32.VirtualUnlock(ptr, len);
            if (result == 0) {
                return error.MemoryUnlockFailed;
            }
        },
        else => {},
    }
}

/// Securely zero memory with compiler optimization prevention
pub fn secureZero(ptr: [*]u8, len: usize) void {
    if (len == 0) return;

    // Use volatile writes to prevent compiler optimization
    const volatile_ptr: [*]volatile u8 = @ptrCast(@volatileCast(ptr));
    for (0..len) |i| {
        volatile_ptr[i] = 0;
    }
}

/// Secure buffer that automatically locks memory and zeros on deinit
pub fn SecureBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        data: []T,
        allocator: std.mem.Allocator,
        is_locked: bool,

        pub fn init(allocator: std.mem.Allocator, size: usize) !Self {
            const data = try allocator.alloc(T, size);
            errdefer allocator.free(data);

            var self = Self{
                .data = data,
                .allocator = allocator,
                .is_locked = false,
            };

            // Lock the memory
            try self.lock();

            return self;
        }

        pub fn lock(self: *Self) !void {
            if (self.is_locked) return;

            const mem_ptr: [*]u8 = @ptrCast(self.data.ptr);
            const len = self.data.len * @sizeOf(T);
            try lockMemory(mem_ptr, len);

            self.is_locked = true;
        }

        pub fn unlock(self: *Self) !void {
            if (!self.is_locked) return;

            const mem_ptr: [*]u8 = @ptrCast(self.data.ptr);
            const len = self.data.len * @sizeOf(T);
            try unlockMemory(mem_ptr, len);

            self.is_locked = false;
        }

        pub fn deinit(self: *Self) void {
            // Securely zero the memory
            const mem_ptr: [*]u8 = @ptrCast(self.data.ptr);
            const len = self.data.len * @sizeOf(T);
            secureZero(mem_ptr, len);

            // Unlock if locked
            self.unlock() catch {
                std.log.warn("Failed to unlock memory during deinit", .{});
            };

            // Free the memory
            self.allocator.free(self.data);
        }

        pub fn slice(self: *Self) []T {
            return self.data;
        }

        pub fn ptr(self: *Self) [*]T {
            return self.data.ptr;
        }
    };
}

/// Wrapper for sensitive fixed-size data (like encryption keys)
pub fn SecureKey(comptime size: usize) type {
    return struct {
        const Self = @This();

        data: [size]u8,
        is_locked: bool,

        pub fn init() !Self {
            var self = Self{
                .data = undefined,
                .is_locked = false,
            };

            // Lock the memory
            try self.lock();

            return self;
        }

        pub fn lock(self: *Self) !void {
            if (self.is_locked) return;

            const ptr: [*]u8 = &self.data;
            try lockMemory(ptr, size);

            self.is_locked = true;
        }

        pub fn unlock(self: *Self) !void {
            if (!self.is_locked) return;

            const ptr: [*]u8 = &self.data;
            try unlockMemory(ptr, size);

            self.is_locked = false;
        }

        pub fn deinit(self: *Self) void {
            // Securely zero the memory
            const ptr: [*]u8 = &self.data;
            secureZero(ptr, size);

            // Unlock if locked
            self.unlock() catch {
                std.log.warn("Failed to unlock key memory during deinit", .{});
            };
        }

        pub fn bytes(self: *Self) []u8 {
            return &self.data;
        }

        pub fn array(self: *Self) *[size]u8 {
            return &self.data;
        }
    };
}

test "memory locking" {
    const testing = std.testing;

    var data: [32]u8 = undefined;
    const ptr: [*]u8 = &data;

    try lockMemory(ptr, 32);
    try unlockMemory(ptr, 32);

    try testing.expect(true);
}

test "secure zero" {
    const testing = std.testing;

    var data = [_]u8{1} ** 32;
    const ptr: [*]u8 = &data;

    secureZero(ptr, 32);

    for (data) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "secure buffer" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var buffer = try SecureBuffer(u8).init(allocator, 1024);
    defer buffer.deinit();

    try testing.expect(buffer.is_locked);
    try testing.expectEqual(@as(usize, 1024), buffer.data.len);
}
