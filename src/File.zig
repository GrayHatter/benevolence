path: []const u8,
file: std.fs.File,
src: union(enum) {
    stdin: void,
    fbs: std.io.FixedBufferStream([]const u8),
},
mode: Mode,
only: ?parser.Format,
meta: std.fs.File.Metadata,
line_buffer: [4096]u8 = undefined,

const LogFile = @This();

pub const Mode = enum {
    /// file is unable to be read
    closed,
    /// process the whole file exactly once
    once,
    /// process new lines, do not reopen fd
    watch,
    /// process new lines, try to reopen fd on error
    follow,
};

pub fn init(path: []const u8, watch: Mode, only: ?parser.Format) !LogFile {
    const f = try std.fs.cwd().openFile(path, .{});
    const lf: LogFile = .{
        .path = path,
        .file = f,
        .src = .{
            .fbs = .{
                .buffer = try mmap(f),
                .pos = 0,
            },
        },
        .mode = watch,
        .only = only,
        .meta = try f.metadata(),
    };

    return lf;
}

pub fn initStdin() !LogFile {
    const in = std.io.getStdIn();
    return .{
        .path = "/dev/stdin",
        .file = in,
        .src = .{
            .stdin = {},
        },
        .mode = .watch,
        .only = null,
        .meta = try in.metadata(),
    };
}

pub fn reInit(lf: *LogFile) !void {
    if (lf.src == .stdin) return error.CantReopenStdin;
    if (lf.mode != .closed) lf.raze();
    const f = std.fs.cwd().openFile(lf.path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            log.err("Unable to reinit for {s} file not found.", .{lf.path});
            return;
        },
        else => return err,
    };
    lf.* = .{
        .path = lf.path,
        .only = lf.only,
        .file = lf.file,
        .meta = try lf.file.metadata(),
        .src = .{ .fbs = .{ .buffer = try mmap(f), .pos = 0 } },
        .mode = .follow,
    };
}

pub fn raze(lf: LogFile) void {
    lf.file.close();
    switch (lf.src) {
        .fbs => |fbs| std.posix.munmap(@alignCast(fbs.buffer)),
        else => {},
    }
    //lf.mode = .closed;
}

fn mmap(f: std.fs.File) ![]const u8 {
    const PROT = std.posix.PROT;
    const length = try f.getEndPos();
    if (length == 0) return &[0]u8{};
    const offset = 0;
    return std.posix.mmap(null, length, PROT.READ, .{ .TYPE = .SHARED }, f.handle, offset);
}

fn remap(lf: *LogFile) !void {
    const meta = try lf.file.metadata();
    if (meta.size() < lf.meta.size()) return error.Truncated;
    if (meta.size() == lf.meta.size()) {
        lf.meta = meta;
        return;
    }
    lf.src.fbs.buffer = try std.posix.mremap(
        @alignCast(@constCast(lf.src.fbs.buffer.ptr)),
        lf.src.fbs.buffer.len,
        meta.size(),
        .{ .MAYMOVE = true },
        null,
    );
    lf.meta = meta;
}

pub fn line(lf: *LogFile) !?[]const u8 {
    switch (lf.src) {
        .fbs => |*fbs| {
            if (fbs.pos == fbs.buffer.len) try lf.remap();
            var reader = fbs.reader();
            return try reader.readUntilDelimiterOrEof(&lf.line_buffer, '\n');
        },
        .stdin => {
            var pollfd: [1]std.os.linux.pollfd = .{.{
                .fd = lf.file.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            if (std.os.linux.poll(&pollfd, 1, 0) != 1) return null;
            var reader = lf.file.reader();
            return try reader.readUntilDelimiter(&lf.line_buffer, '\n');
        },
    }
}

const parser = @import("parser.zig");
const std = @import("std");
const log = std.log.scoped(.file);
