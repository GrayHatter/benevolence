pub const rules: []const Detection = &[_]Detection{
    .{ .hit = "SASL LOGIN authentication failed", .heat = 10 },
    .{ .hit = "SASL PLAIN authentication failed", .heat = 10 },
    .{ .hit = "NOQUEUE: lost connection after AUTH from", .heat = 1 },
};

pub fn filter(line: []const u8) bool {
    return indexOf(u8, line, " mail.warn postfix/") != null;
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
const Addr = @import("../main.zig").Addr;
const Event = @import("../Event.zig");
const Detection = @import("../Detection.zig");
