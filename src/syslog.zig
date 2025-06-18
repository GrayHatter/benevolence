pub var enabled: bool = false;

const Event = union(enum) {
    banned: Banned,

    pub const Banned = struct {
        count: usize,
    };
};

pub fn log(evt: Event) !void {
    if (!enabled) return;

    switch (evt) {
        .banned => |ban| {
            var b: [0x2ff]u8 = undefined;
            const pri: u8 = 4 * 8 + 4;
            const tag: []const u8 = "benevolence";
            const pid = std.os.linux.getpid();
            const msg = try std.fmt.bufPrint(&b, "<{}> {s}[{}]: banned {}", .{ pri, tag, pid, ban.count });

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

            _ = try std.posix.write(s, msg);
        },
    }
}

const std = @import("std");
