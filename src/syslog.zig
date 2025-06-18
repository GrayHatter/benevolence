pub var enabled: bool = false;

const Event = union(enum) {
    banned: Banned,

    pub const Banned = struct {
        surface: []const u8,
        count: usize,
        src: ?[]const u8 = null,
    };
};

const Facility = enum(u8) {
    // kernel = 0, // illegal from userspace
    user = 1 * 8,
    mail = 2 * 8,
    system = 3 * 8,
    auth = 4 * 8,
    syslogd = 5 * 8,
    printer = 6 * 8,
    network_news = 7 * 8,
    UUCP = 8 * 8,
    clock = 9 * 8,
    security = 10 * 8,
    FTP = 11 * 8,
    NTP = 12 * 8,
    log_audit = 13 * 8,
    log_alert = 14 * 8,
    clock2 = 15 * 8,
    local0 = 16 * 8,
    local1 = 17 * 8,
    local2 = 18 * 8,
    local3 = 19 * 8,
    local4 = 20 * 8,
    local5 = 21 * 8,
    local6 = 22 * 8,
    local7 = 23 * 8,
};

const Severity = enum(u4) {
    emergency = 0, // system is unusable
    alert = 1, // action must be taken immediately
    crit = 2, // critical conditions
    err = 3, // error conditions
    warning = 4, // warning conditions
    notice = 5, // normal but significant condition
    info = 6, // informational messages
    debug = 7, // debug-level messages

};

pub fn log(evt: Event) !void {
    if (!enabled) return;

    switch (evt) {
        .banned => |ban| {
            var b: [0x2ff]u8 = undefined;
            var buffer: std.ArrayListUnmanaged(u8) = .initBuffer(&b);
            var w = buffer.fixedWriter();
            const pri: u8 = @intFromEnum(Facility.auth) + @intFromEnum(Severity.warning);
            const tag: []const u8 = "benevolence";
            const pid = std.os.linux.getpid();
            try w.print("<{}> {s}[{}]: banned {} addr", .{ pri, tag, pid, ban.count });
            if (ban.src) |bansrc| {
                if (bansrc.len < 32) try w.print(" [{s}]", .{bansrc});
            }
            try w.print(" from {s}", .{ban.surface});

            var addr: std.posix.sockaddr.un = .{
                .family = std.posix.AF.UNIX,
                .path = @splat(0),
            };
            @memcpy(addr.path[0..8], "/dev/log");
            const s = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
            try std.posix.connect(
                s,
                @ptrCast(&addr),
                @as(std.posix.socklen_t, @intCast(@sizeOf(@TypeOf(addr)))),
            );
            defer std.posix.close(s);

            _ = try std.posix.write(s, buffer.items);
        },
    }
}

const std = @import("std");
const bPrint = std.fmt.bufPrint;
