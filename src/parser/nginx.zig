pub fn filter(line: []const u8) bool {
    var dots: usize = 0;
    var idx: usize = 0;
    while (dots <= 3 and idx <= line.len) : (idx += 1) {
        switch (line[idx]) {
            '0'...'9' => continue,
            '.' => dots += 1,
            else => break,
        }
    }

    return line[idx] == ' ' and dots == 3;
}

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

pub fn parseLine(line: []const u8) !?Line {
    return .{
        .src_addr = parseAddr(line) catch return null,
        .timestamp = try parseTime(line),
        .extra = try parseExtra(line),
    };
}

const std = @import("std");
const indexOfScalar = std.mem.indexOfScalar;
const Addr = @import("../main.zig").Addr;
const Line = @import("../main.zig").Line;
