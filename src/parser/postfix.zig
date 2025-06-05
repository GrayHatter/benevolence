pub fn parseAddr(line: []const u8) !Addr {
    if (indexOf(u8, line, "unknown[")) |i| {
        if (indexOfScalarPos(u8, line, i, ']')) |j| {
            return try Addr.parse(line[i + 8 .. j]);
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

const std = @import("std");
const indexOf = std.mem.indexOf;
const indexOfScalarPos = std.mem.indexOfScalarPos;
const Addr = @import("../main.zig").Addr;
