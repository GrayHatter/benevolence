pub var enabled: bool = false;

const Event = union(enum) {
    banned: Banned,
    startup: Startup,
    signal: Signal,

    pub const Banned = struct {
        surface: []const u8,
        count: usize,
        src: ?[]const u8 = null,
    };

    pub const Startup = struct {
        filename: []const u8,
        count: usize,
    };

    pub const Signal = struct {
        sig: u6,
        str: []const u8 = "",
    };
};

const Facility = enum(u5) {
    // kernel = 0, // illegal from userspace
    user = 1,
    mail = 2,
    system = 3,
    auth = 4,
    syslogd = 5,
    printer = 6,
    network_news = 7,
    UUCP = 8,
    clock = 9,
    security = 10,
    FTP = 11,
    NTP = 12,
    log_audit = 13,
    log_alert = 14,
    clock2 = 15,
    local0 = 16,
    local1 = 17,
    local2 = 18,
    local3 = 19,
    local4 = 20,
    local5 = 21,
    local6 = 22,
    local7 = 23,
};

const Severity = enum(u3) {
    emergency = 0, // system is unusable
    alert = 1, // action must be taken immediately
    crit = 2, // critical conditions
    err = 3, // error conditions
    warning = 4, // warning conditions
    notice = 5, // normal but significant condition
    info = 6, // informational messages
    debug = 7, // debug-level messages

};

pub const Priority = packed struct(u8) {
    severity: Severity,
    facility: Facility,

    pub fn init(f: Facility, s: Severity) Priority {
        return .{
            .facility = f,
            .severity = s,
        };
    }

    pub fn cast(p: Priority) u8 {
        return @bitCast(p);
    }

    pub fn format(p: Priority, comptime s: []const u8, _: anytype, out: anytype) !void {
        _ = s;
        try out.print("{}", .{@as(u8, @bitCast(p))});
    }
};

pub fn log(evt: Event) !void {
    if (!enabled) return;

    const tag: []const u8 = "benevolence";
    const pid = std.os.linux.getpid();
    var b: [0x2ff]u8 = undefined;
    var buffer: std.ArrayListUnmanaged(u8) = .initBuffer(&b);
    var w = buffer.fixedWriter();

    var addr: sockaddr_unix = .{ .family = std.posix.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..8], "/dev/log");
    const addr_len: u32 = @sizeOf(std.posix.sockaddr.un);
    const s = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
    try std.posix.connect(s, @ptrCast(&addr), addr_len);
    defer std.posix.close(s);

    switch (evt) {
        .banned => |ban| {
            const pri: Priority = .init(.auth, .warning);
            try w.print(
                "<{}>{s}/{s}[{}]: {} banned",
                .{ pri, tag, ban.surface, pid, ban.count },
            );
            if (ban.src) |bansrc| {
                if (bansrc.len < 256) try w.print(" address: [{s}]", .{bansrc});
            }
        },
        .startup => |su| {
            const pri: Priority = .init(.auth, .info);
            try w.print(
                "<{}>{s}[{}]: startup: processed {} lines from {s}",
                .{ pri, tag, pid, su.count, su.filename },
            );
        },
        .signal => |sig| {
            const pri: Priority = .init(.auth, .warning);
            try w.print("<{}>{s}[{}]: signal: {s}[{}]", .{ pri, tag, pid, sig.str, sig.sig });
        },
    }
    _ = try std.posix.write(s, buffer.items);
}

const std = @import("std");
const sockaddr_unix = std.posix.sockaddr.un;
const bPrint = std.fmt.bufPrint;
