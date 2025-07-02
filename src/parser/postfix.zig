pub const rules: []const Detection = &[_]Detection{
    .{ .hit = "SASL LOGIN authentication failed", .heat = 10, .ban_time = default },
    .{ .hit = "SASL PLAIN authentication failed", .heat = 10, .ban_time = default },
    .{ .hit = "NOQUEUE: lost connection after AUTH from", .heat = 1, .ban_time = default },
    .{ .hit = "improper command pipelining after CONNECT from ", .ban_time = 30 },
};

const default: u32 = 14 * 86400;

pub fn filter(line: []const u8) bool {
    if (indexOf(u8, line, " mail.")) |i|
        return (startsWith(u8, line[i + 6 ..], "warn postfix/") or
            startsWith(u8, line[i + 6 ..], "info postfix/"));
    return false;
}

pub fn parseAddr(line: []const u8) !Addr {
    if (indexOf(u8, line, "]: SASL PLAIN") orelse indexOf(u8, line, "]: SASL LOGIN")) |j| {
        if (lastIndexOf(u8, line[0..j], "[")) |i| {
            return try Addr.parse(line[i + 1 .. j]);
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
const lastIndexOf = std.mem.lastIndexOf;
const indexOfScalarPos = std.mem.indexOfScalarPos;
const startsWith = std.mem.startsWith;
const Addr = @import("../main.zig").Addr;
const Event = @import("../Event.zig");
const Detection = @import("../Detection.zig");
