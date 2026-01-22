pub const rules: []const Detection = &[_]Detection{
    .{ .hit = "SASL LOGIN authentication failed", .heat = 32, .ban_time = default },
    .{ .hit = "SASL PLAIN authentication failed", .heat = 32, .ban_time = default },
    .{ .hit = "NOQUEUE: lost connection after AUTH from", .heat = 8, .ban_time = default },
    .{ .hit = "improper command pipelining after CONNECT from ", .heat = 8, .ban_time = 30 },
    .{ .hit = "ehlo=1 auth=0/1 rset=1 quit=1 commands=3/4", .heat = 8 },
    .{ .hit = "] ehlo=1 auth=0/1 commands=", .heat = 8 },
    .{ .hit = "NOQUEUE: lost connection after CONNECT from unknown", .heat = 2, .ban_time = 3600 },

    .{ .hit = "Client host rejected: cannot find your reverse hostname", .prefix = &.{
        .{ .hit = " to=<banned_email@gr.ht>", .heat = 16, .ban_time = 3600 * 2 },
    }, .heat = 0, .ban_time = 0 },
    .{ .hit = "SSL_accept error from ", .prefix = &.{
        .{ .hit = "-1", .heat = 32, .ban_time = 10 },
    }, .heat = 2, .ban_time = 3600 },
};

pub const trusted_rules: []const Detection = &.{};

const default: u32 = 14 * 86400;

pub fn filter(line: []const u8) bool {
    if (find(u8, line, " mail.")) |i|
        return (startsWith(u8, line[i + 6 ..], "warn postfix/") or
            startsWith(u8, line[i + 6 ..], "info postfix/"));
    return false;
}

pub fn parseAddr(line: []const u8) !Addr {
    if (find(u8, line, "]: SASL PLAIN") orelse find(u8, line, "]: SASL LOGIN")) |j| {
        if (findLast(u8, line[0..j], "[")) |i| {
            return try Addr.parse(line[i + 1 .. j]);
        }
    } else if (findPrefix(line, 0, " from unknown[")) |i| {
        if (findScalarPos(u8, line, i, ']')) |j| {
            return try Addr.parse(line[i..j]);
        }
    } else if (cutSuffix(u8, line, "]: -1")) |cut| {
        if (findScalarLast(u8, cut, '[')) |i| {
            return try Addr.parse(cut[i + 1 ..]);
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
const find = std.mem.find;
const findLast = std.mem.findLast;
const findScalarLast = std.mem.findScalarLast;
const findScalarPos = std.mem.findScalarPos;
const startsWith = std.mem.startsWith;
const cutSuffix = std.mem.cutSuffix;
const parser = @import("../parser.zig");
const findPrefix = parser.findPrefix;
const Addr = @import("../main.zig").Addr;
const Event = @import("../Event.zig");
const Detection = @import("../Detection.zig");
