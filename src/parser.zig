pub const Format = enum {
    dovecot,
    nginx,
    postfix,
    sshd,

    pub const len = @typeInfo(Format).@"enum".fields.len;
    pub const fields: [len]Format = .{
        .dovecot,
        .nginx,
        .postfix,
        .sshd,
    };
};

pub const Filters: std.EnumArray(Format, *const fn ([]const u8) bool) = .init(.{
    .dovecot = dovecot.filter,
    .nginx = nginx.filter,
    .postfix = postfix.filter,
    .sshd = sshd.filter,
});

pub const dovecot = @import("parser/dovecot.zig");
pub const nginx = @import("parser/nginx.zig");
pub const postfix = @import("parser/postfix.zig");
pub const sshd = @import("parser/sshd.zig");

pub const Bound = struct {
    str: []const u8,
    index: usize,
};

pub fn boundedSearchRev(comptime pre: []const u8, comptime post: []const u8, line: []const u8) ?Bound {
    if (std.mem.indexOfPos(u8, line, post)) |j| {
        if (std.mem.lastIndexOf(u8, line[0..j], pre)) |i| {
            return .{ .str = line[i + pre.len .. j], .index = i + pre.len };
        }
    }
    return null;
}

pub fn boundedSearch(comptime pre: []const u8, comptime post: []const u8, line: []const u8) ?Bound {
    if (std.mem.indexOf(u8, line, pre)) |i| {
        if (std.mem.indexOfPos(u8, line, i, post)) |j| {
            return .{ .str = line[i + pre.len .. j], .index = i + pre.len };
        }
    }
    return null;
}

fn parseTimeSyslog(str: []const u8) !i64 {
    if (str.len < 14) return error.NotSysLogFmt;

    const current = std.time.timestamp();
    const esec = std.time.epoch.EpochSeconds{ .secs = @intCast(current) };
    const eday = esec.getEpochDay();
    const year_day = eday.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    var month: std.time.epoch.Month = undefined;
    inline for (@typeInfo(std.time.epoch.Month).@"enum".fields) |m_f| {
        if (eqlIgnoreCase(m_f.name, str[0..3])) {
            month = @enumFromInt(m_f.value);
            break;
        }
    } else return error.InvalidMonth;

    std.debug.print("{} {}", .{ month_day.month, month_day.day_index });
    std.debug.print("{}", .{month});
    return 0;
}

test parseTimeSyslog {
    if (true) return error.SkipZigTest;
    _ = try parseTimeSyslog("Jan 12 00:00:00 ");
}

const std = @import("std");
const eqlIgnoreCase = std.ascii.eqlIgnoreCase;
