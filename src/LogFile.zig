path: []const u8,
file: File,
reader: File.Reader,
mode: Mode,
size: u64,
only: ?parser.Format = null,
line_buffer: [0x2000]u8 = undefined,

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
    /// won't reopen
    stdin,
};

pub fn init(path: []const u8, watch: Mode, only: ?parser.Format, io: Io) !LogFile {
    const f = try Io.Dir.cwd().openFile(io, path, .{});
    const lf: LogFile = .{
        .path = path,
        .file = f,
        .reader = undefined,
        .size = 0,
        .mode = watch,
        .only = only,
    };

    return lf;
}

pub fn initReader(lf: *LogFile, io: Io) void {
    lf.reader = lf.file.reader(io, &lf.line_buffer);
    lf.size = lf.reader.size orelse 0;
}

pub fn initStdin() !LogFile {
    const in = File.stdin();
    return .{
        .path = "/dev/stdin",
        .file = in,
        .reader = undefined,
        .size = 0,
        .mode = .watch,
        .only = null,
    };
}

pub fn reInit(lf: *LogFile, io: Io) !void {
    switch (lf.mode) {
        .closed, .once, .stdin => return,
        .watch, .follow => lf.raze(io),
    }

    const f = Io.Dir.cwd().openFile(io, lf.path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            log.err("Unable to reinit for {s} file not found.", .{lf.path});
            return;
        },
        else => return err,
    };
    lf.file = f;
}

pub fn raze(lf: LogFile, io: Io) void {
    lf.file.close(io);
}

pub fn line(lf: *LogFile) !?[]const u8 {
    if (lf.mode == .stdin) {
        var pollfd: [1]std.os.linux.pollfd = .{.{
            .fd = lf.file.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (std.os.linux.poll(&pollfd, 1, 0) != 1) return null;
    }
    return lf.reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.EndOfStream => {
            // lf.checkAndRefollow();
            return null;
        },
        error.StreamTooLong => return err, // TODO, seek until \n then drop
        error.ReadFailed => return err,
    };
}

const parser = @import("parser.zig");
const std = @import("std");
const log = std.log.scoped(.file);
const Io = std.Io;
const File = Io.File;
