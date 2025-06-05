pub fn parseAddr(line: []const u8) !Addr {
    if (indexOf(u8, line, "Connection from ")) |i| {
        return try Addr.parse(line[i + 16 ..]);
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
const Addr = @import("../main.zig").Addr;
const Line = @import("../main.zig").Line;
