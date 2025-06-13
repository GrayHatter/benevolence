pub fn filter(line: []const u8) bool {
    return indexOf(u8, line, "imap-login:") != null;
}

pub fn parseAddr(line: []const u8) !Addr {
    if (indexOf(u8, line, ", rip=")) |i| {
        if (indexOfPos(u8, line, i + 6, ", lip=")) |j| {
            return try Addr.parse(line[i + 6 .. j]);
        }
    }
    return error.AddrNotFound;
}

pub fn parseTime(line: []const u8) !i64 {
    _ = line;
    return 0;
}

pub fn parseExtra(line: []const u8) ![]const u8 {
    _ = line;
    return "";
}

pub fn parseLine(line: []const u8) !?Line {
    return .{
        .src_addr = parseAddr(line) catch return null,
        .timestamp = try parseTime(line),
        .extra = try parseExtra(line),
    };
}

const std = @import("std");
const indexOf = std.mem.indexOf;
//const lastIndexOf = std.mem.lastIndexOf;
//const indexOfScalarPos = std.mem.indexOfScalarPos;
const indexOfPos = std.mem.indexOfPos;
const Addr = @import("../main.zig").Addr;
const Line = @import("../main.zig").Line;
