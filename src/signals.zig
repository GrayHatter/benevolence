pub const Signal = enum(u6) {
    hup = @intFromEnum(SIG.HUP),
    quit = @intFromEnum(SIG.QUIT),
    usr1 = @intFromEnum(SIG.USR1),
    usr2 = @intFromEnum(SIG.USR2),
};

fn sigtimedwait(set: *const sigset_t, info: *siginfo, timeout: *const timespec) isize {
    //const sigsetsize: usize = @sizeOf(sigset_t);
    return @bitCast(std.os.linux.syscall4(
        .rt_sigtimedwait,
        @intFromPtr(set),
        @intFromPtr(info),
        @intFromPtr(timeout),
        NSIG / 8,
    ));
}

pub fn setDefaultMask() void {
    _ = std.posix.sigprocmask(std.os.linux.SIG.BLOCK, &sigset, null);
}

pub fn check(msec: isize) ?Signal {
    var info: siginfo = .{ .signo = undefined, .code = 0, .errno = 0, .fields = undefined };
    //const set: sigset_t = @splat(~@as(u32, 0));
    const timeout: timespec = .{ .sec = 0, .nsec = 1_000_000 * msec };
    const timed = sigtimedwait(&sigset, &info, &timeout);
    if (-timed != @intFromEnum(std.os.linux.E.AGAIN)) {
        return switch (info.signo) {
            SIG.HUP, SIG.QUIT, SIG.USR1, SIG.USR2 => |signo| @enumFromInt(@intFromEnum(signo)),
            else => {
                std.debug.print("unreachable signal returned by system\n", .{});
                return null;
            },
        };
    }
    return null;
}

fn defaultSigSetMask() sigset_t {
    var set: sigset_t = @splat(0);
    std.os.linux.sigaddset(&set, SIG.HUP);
    std.os.linux.sigaddset(&set, SIG.QUIT);
    std.os.linux.sigaddset(&set, SIG.USR1);
    std.os.linux.sigaddset(&set, SIG.USR2);
    return set;
}

const sigset: sigset_t = defaultSigSetMask();

const NSIG = std.os.linux.NSIG;
const SIG = std.os.linux.SIG;
const sigset_t = std.os.linux.sigset_t;
const siginfo = std.os.linux.siginfo_t;
const timespec = std.os.linux.timespec;

const std = @import("std");
