pub fn parseAddr(line: []const u8) !Addr {
    return Addr.parse(line[0 .. indexOfScalar(u8, line, ' ') orelse return error.InvalidLogLine]);
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
const indexOfScalar = std.mem.indexOfScalar;
const Addr = @import("../main.zig").Addr;
