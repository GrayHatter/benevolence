pub const rules: []const Detection = &[_]Detection{
    .{ .hit = ": Connection closed by invalid user" },
    .{ .hit = ": Invalid user" },
};

pub const trusted_rules: []const Detection = &.{
    .{ .hit = "]: Accepted publickey for " },
};

pub fn filter(line: []const u8) bool {
    return indexOfPos(u8, line, 0, "sshd-session[") != null;
}

pub fn parseAddr(line: []const u8) !Addr {
    if (indexOfPos(u8, line, 0, "Connection from ")) |i| {
        return try Addr.parse(line[i + 16 ..]);
    }
    // Connection closed by invalid user ecoub 127.0.0.1 port 48556 [preauth]
    if (indexOfPrefix(line, 0, "Connection closed by invalid user ")) |i_| {
        var i: usize = i_;
        while (i < line.len and line[i] != ' ') : (i += 1) {}
        i += 1;
        var end: usize = i;
        while (end < line.len) : (end += 1) {
            switch (line[end]) {
                '0'...'9', 'a'...'f', 'A'...'F', '.', ':' => continue,
                else => break,
            }
        }
        if (i < line.len and end < line.len) {
            return try Addr.parse(line[i..end]);
        }
    }
    //Invalid user ktabn from 127.0.0.1 port 55394
    if (indexOfPrefix(line, 0, "Invalid user ")) |i| {
        if (indexOfPrefix(line, i, " from ")) |start| {
            if (indexOfPos(u8, line, start, " port ")) |end| {
                return try Addr.parse(line[start..end]);
            }
        }
    }

    //Accepted publickey for grayhatter from 127.0.0.1 port 53142
    if (indexOfPrefix(line, 0, "]: Accepted publickey for ")) |i| {
        if (indexOfPrefix(line, i, " from ")) |start| {
            if (indexOfPos(u8, line, start, " port ")) |end| {
                return try Addr.parse(line[start..end]);
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
const indexOfPos = std.mem.indexOfPos;
const parser = @import("../parser.zig");
const indexOfPrefix = parser.indexOfPrefix;
const Addr = @import("../main.zig").Addr;
const Event = @import("../Event.zig");
const Detection = @import("../Detection.zig");
