file: std.fs.File,
src: union(enum) {
    stdin: void,
    fbs: std.io.FixedBufferStream([]const u8),
},
watch: bool,
only: ?parser.Format,
meta: std.fs.File.Metadata,
line_buffer: [4096]u8 = undefined,

const LogFile = @This();

pub fn init(filename: []const u8, watch: bool, only: ?parser.Format) !LogFile {
    const f = try std.fs.cwd().openFile(filename, .{});
    const lf: LogFile = .{
        .file = f,
        .src = .{
            .fbs = .{
                .buffer = try mmap(f),
                .pos = 0,
            },
        },
        .watch = watch,
        .only = only,
        .meta = try f.metadata(),
    };

    return lf;
}

pub fn initStdin() !LogFile {
    const in = std.io.getStdIn();
    return .{
        .file = in,
        .src = .{
            .stdin = {},
        },
        .watch = true,
        .only = null,
        .meta = try in.metadata(),
    };
}

pub fn raze(lf: *LogFile) void {
    lf.watch = false;
    lf.file.close();
    switch (lf.src) {
        .fbs => |fbs| std.posix.munmap(@alignCast(fbs.buffer)),
        else => {},
    }
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
