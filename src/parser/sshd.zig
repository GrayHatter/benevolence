pub const rules: []const Detection = &[_]Detection{
    .{ .hit = ": Connection closed by invalid user" },
    .{ .hit = ": Invalid user" },
};

pub fn filter(line: []const u8) bool {
    return indexOf(u8, line, "sshd-session[") != null;
}

pub fn parseAddr(line: []const u8) !Addr {
    if (indexOf(u8, line, "Connection from ")) |i| {
        return try Addr.parse(line[i + 16 ..]);
    }
    // Connection closed by invalid user ecoub 127.0.0.1 port 48556 [preauth]
    if (indexOf(u8, line, "Connection closed by invalid user ")) |i| {
        var start: usize = i + 34;
        while (start < line.len and line[start] != ' ') : (start += 1) {}
        start += 1;
        var end: usize = start;
        while (end < line.len) : (end += 1) {
            switch (line[end]) {
                '0'...'9', 'a'...'f', 'A'...'F', '.', ':' => continue,
                else => break,
            }
        }
        if (start < line.len and end < line.len) {
            return try Addr.parse(line[start..end]);
        }
    }
    //Invalid user ktabn from 127.0.0.1 port 55394
    if (indexOf(u8, line, "Invalid user ")) |i| {
        var start: usize = i + 13;
        if (indexOf(u8, line[start..], " from ")) |j| {
            start += j + 6;
            if (indexOf(u8, line[start..], " port ")) |end| {
                return try Addr.parse(line[start..][0..end]);
            }
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

pub fn parseLine(line: []const u8) !?Event {
    return .{
        .src_addr = parseAddr(line) catch return null,
        .timestamp = try parseTime(line),
        .extra = try parseExtra(line),
    };
}

const std = @import("std");
const indexOf = std.mem.indexOf;
const Addr = @import("../main.zig").Addr;
const Event = @import("../Event.zig");
const Detection = @import("../Detection.zig");
