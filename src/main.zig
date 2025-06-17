fn usage(arg0: []const u8) noreturn {
    //
    std.debug.print(
        \\error: you're holding it wrong
        \\
        \\Usage: {s} [filename]
        \\
        \\Options:
        \\
        \\    --example                         Print an example nft config then exit
        \\    --exec                            Install banned elements into nft
        \\    --syslog                          Log ban events to syslog [logger]
        \\    --quiet                           Don't print rules
        \\    --dry-run                         Don't execute rules
        \\
        \\    --                                Use stdin
        \\    --watch           <filename>      Process and then tail for new data
        \\    --watch-all       <filename>      Process and then tail all following logs
        \\
        \\    --ban-time        <timeout>       Default time to ban a host [504h]
        \\
    , .{arg0});
    std.posix.exit(1);
}

const LogFile = struct {
    file: std.fs.File,
    src: union(enum) {
        stdin: void,
        fbs: std.io.FixedBufferStream([]const u8),
    },
    watch: bool,
    meta: std.fs.File.Metadata,
    line_buffer: [4096]u8 = undefined,

    pub fn init(filename: []const u8, watch: bool) !LogFile {
        const f = try std.fs.cwd().openFile(filename, .{});
        const lf: LogFile = .{
            .file = f,
            .src = .{
                .fbs = .{
                    .buffer = try mmap(f),
                    .pos = 0,
                },
            },
            .watch = watch,
            .meta = try f.metadata(),
        };

        return lf;
    }

    pub fn initStdin() !LogFile {
        const in = std.io.getStdIn();
        return .{
            .file = in,
            .src = .{
                .stdin = {},
            },
            .watch = true,
            .meta = try in.metadata(),
        };
    }

    pub fn raze(lf: *LogFile) void {
        lf.watch = false;
        lf.file.close();
        switch (lf.src) {
            .fbs => |fbs| std.posix.munmap(@alignCast(fbs.buffer)),
            else => {},
        }
    }

    fn mmap(f: std.fs.File) ![]const u8 {
        const PROT = std.posix.PROT;
        const length = try f.getEndPos();
        const offset = 0;
        return std.posix.mmap(null, length, PROT.READ, .{ .TYPE = .SHARED }, f.handle, offset);
    }

    fn remap(lf: *LogFile) !void {
        const meta = try lf.file.metadata();
        if (meta.size() < lf.meta.size()) return error.Truncated;
        if (meta.size() == lf.meta.size()) {
            lf.meta = meta;
            return;
        }
        lf.src.fbs.buffer = try std.posix.mremap(
            @alignCast(@constCast(lf.src.fbs.buffer.ptr)),
            lf.src.fbs.buffer.len,
            meta.size(),
            .{ .MAYMOVE = true },
            null,
        );
        lf.meta = meta;
    }

    pub fn line(lf: *LogFile) !?[]const u8 {
        switch (lf.src) {
            .fbs => |*fbs| {
                if (fbs.pos == fbs.buffer.len) try lf.remap();
                var reader = fbs.reader();
                return try reader.readUntilDelimiterOrEof(&lf.line_buffer, '\n');
            },
            .stdin => {
                var pollfd: [1]std.os.linux.pollfd = .{.{
                    .fd = lf.file.handle,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                if (std.os.linux.poll(&pollfd, 1, 0) != 1) return null;
                var reader = lf.file.reader();
                return try reader.readUntilDelimiter(&lf.line_buffer, '\n');
            },
        }
    }
};

var file_buf: [64]LogFile = undefined;
var syslog: bool = false;
var dryrun: bool = false;
var exec_rules: bool = false;

pub fn main() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    defer bw.flush() catch @panic("final flush failed");
    const stdout = bw.writer();

    var debug_a: std.heap.DebugAllocator(.{}) = .{};
    const a = debug_a.allocator();

    var args = std.process.args();
    const arg0 = args.next() orelse usage("wat?!");

    // TODO 20 ought to be enough for anyone
    var log_files: std.ArrayListUnmanaged(LogFile) = .initBuffer(&file_buf);

    var default_watch: bool = false;
    var quiet: bool = false;
    var to_buf: [32]u8 = @splat(' ');
    var timeout: []const u8 = "";

    while (args.next()) |arg| {
        if (log_files.items.len >= file_buf.len) {
            std.debug.print("PANIC: too many log files given\n", .{});
            usage(arg0);
        }
        if (startsWith(u8, arg, "--")) {
            if (eql(u8, arg, "--")) {
                log_files.appendAssumeCapacity(try .initStdin());
            } else if (eql(u8, arg, "--example")) {
                try stdout.writeAll(example_config.nft);
                return;
            } else if (eql(u8, arg, "--exec")) {
                exec_rules = true;
            } else if (eql(u8, arg, "--dry-run")) {
                dryrun = true;
            } else if (eql(u8, arg, "--quiet")) {
                quiet = true;
            } else if (eql(u8, arg, "--syslog")) {
                syslog = true;
            } else if (eql(u8, arg, "--ban-time")) {
                timeout = bufPrint(
                    &to_buf,
                    " timeout {s}",
                    .{args.next() orelse usage(arg0)},
                ) catch usage(arg0);
            } else if (eql(u8, arg, "--watch")) {
                const filename = args.next() orelse {
                    std.debug.print("error: --watch requires a filename\n", .{});
                    usage(arg0);
                };
                log_files.appendAssumeCapacity(try .init(filename, true));
            } else if (eql(u8, arg, "--watch-all")) {
                const filename = args.next() orelse {
                    std.debug.print("error: --watch-all requires a filename\n", .{});
                    usage(arg0);
                };
                log_files.appendAssumeCapacity(try .init(filename, true));
                default_watch = true;
            } else {
                usage(arg0);
            }
        } else {
            log_files.appendAssumeCapacity(try .init(arg, default_watch));
        }
    }

    if (log_files.items.len == 0) usage(arg0);

    for (log_files.items) |*file| {
        if (!file.watch) {
            var timer: std.time.Timer = try .start();
            const line_count = try readFile(a, file);
            const lap = timer.lap();
            std.debug.print("Done: {} lines in  {}ms\n", .{ line_count, lap / 1000_000 });
        }
    }

    if (exec_rules) {
        try execBanList(a, timeout);
    } else {
        if (!quiet) try printBanList(a, stdout.any(), timeout);
        try bw.flush();
    }

    var files_remaining: usize = 0;
    for (log_files.items) |*lf| {
        if (!lf.watch) {
            lf.raze();
        } else files_remaining += 1;
    }

    while (files_remaining > 0) {
        for (log_files.items) |*lf| {
            if (!lf.watch) continue;
            _ = readFile(a, lf) catch |err| {
                std.debug.print("err {}\n", .{err});
                lf.raze();
                files_remaining -|= 1;
                continue;
            };
        }

        if (ban_list_updated) {
            if (exec_rules) {
                try execBanList(a, timeout);
            } else {
                if (!quiet) try printBanList(a, stdout.any(), timeout);
                try bw.flush();
            }
            ban_list_updated = false;
        }
        sleep(500);
    }
}

fn genLists(a: Allocator, timeout: []const u8) ![3]std.ArrayListUnmanaged(u8) {
    var banlist_http: std.ArrayListUnmanaged(u8) = .{};
    var banlist_mail: std.ArrayListUnmanaged(u8) = .{};
    var banlist_sshd: std.ArrayListUnmanaged(u8) = .{};

    errdefer {
        banlist_http.deinit(a);
        banlist_mail.deinit(a);
        banlist_sshd.deinit(a);
    }

    var vals = baddies.iterator();
    while (vals.next()) |kv| {
        if (kv.value_ptr.banned) continue;
        if (kv.value_ptr.count.http >= 2) {
            var w = banlist_http.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, timeout });
        }
        if (kv.value_ptr.count.mail >= 2) {
            var w = banlist_mail.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, timeout });
        }
        if (kv.value_ptr.count.sshd >= 2) {
            var w = banlist_sshd.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, timeout });
        }
        kv.value_ptr.banned = true;
    }

    try banlist_http.appendSlice(a, " }");
    try banlist_mail.appendSlice(a, " }");
    try banlist_sshd.appendSlice(a, " }");
    banlist_http.items[0] = '{';
    banlist_mail.items[0] = '{';
    banlist_sshd.items[0] = '{';

    return .{
        banlist_http,
        banlist_mail,
        banlist_sshd,
    };
}

const SyslogEvent = union(enum) {
    banned: Banned,

    pub const Banned = struct {
        count: usize,
    };
};

fn syslogEvent(evt: SyslogEvent) !void {
    if (!syslog) return;

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

fn execBanList(a: Allocator, timeout: []const u8) !void {
    const cmd_base = [_][]const u8{
        "nft", "add", "element", "inet", "filter",
    };

    var http, var mail, var sshd = try genLists(a, timeout);
    defer {
        http.deinit(a);
        mail.deinit(a);
        sshd.deinit(a);
    }

    if (http.items.len > 4) {
        var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
            "abuse-http",
            http.items,
        }, a);
        child.expand_arg0 = .expand;
        if (!dryrun) _ = try child.spawnAndWait();
        try syslogEvent(.{
            .banned = .{ .count = std.mem.count(u8, http.items, ", ") + 1 },
        });
    }

    if (mail.items.len > 4) {
        var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
            "abuse-mail",
            mail.items,
        }, a);
        child.expand_arg0 = .expand;
        if (!dryrun) _ = try child.spawnAndWait();
        try syslogEvent(.{
            .banned = .{ .count = std.mem.count(u8, mail.items, ", ") + 1 },
        });
    }

    if (sshd.items.len > 4) {
        var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
            "abuse-sshd",
            sshd.items,
        }, a);
        child.expand_arg0 = .expand;
        if (!dryrun) _ = try child.spawnAndWait();
        try syslogEvent(.{
            .banned = .{ .count = std.mem.count(u8, sshd.items, ", ") + 1 },
        });
    }
}

fn printBanList(a: Allocator, stdout: std.io.AnyWriter, timeout: []const u8) !void {
    var http, var mail, var sshd = try genLists(a, timeout);
    defer {
        http.deinit(a);
        mail.deinit(a);
        sshd.deinit(a);
    }

    if (http.items.len > 2) {
        try stdout.print("nft add element inet filter abuse-http '{s}'\n", .{http.items[0..]});
    }

    if (mail.items.len > 2) {
        try stdout.print("nft add element inet filter abuse-mail '{s}'\n", .{mail.items[0..]});
    }

    if (sshd.items.len > 2) {
        try stdout.print("nft add element inet filter abuse-sshd '{s}'\n", .{sshd.items[0..]});
    }
}

fn readFile(a: Allocator, logfile: *LogFile) !usize {
    var line_count: usize = 0;

    while (try logfile.line()) |line| {
        line_count += 1;
        if (meaningful(line)) |m| {
            const res = try parseLine(m) orelse continue;

            var b: [0xff]u8 = undefined;
            const paddr = try std.fmt.bufPrint(&b, "{}", .{res.src_addr});

            ban_list_updated = true;
            const gop = try baddies.getOrPut(a, paddr);
            if (!gop.found_existing) {
                gop.key_ptr.* = try a.dupe(u8, paddr);
                gop.value_ptr.count = .zero;
            }
            gop.value_ptr.banned = false;
            switch (m.group) {
                .dovecot => gop.value_ptr.count.mail +|= 9,
                .nginx => gop.value_ptr.count.http +|= 1,
                .postfix => gop.value_ptr.count.mail +|= 1,
                .sshd => gop.value_ptr.count.sshd +|= 1,
            }
        }
    }
    return line_count;
}

const BanData = struct {
    count: Heat = .zero,
    banned: bool = false,

    pub const Heat = struct {
        http: u16,
        mail: u16,
        sshd: u16,

        pub const zero: Heat = .{
            .http = 0,
            .mail = 0,
            .sshd = 0,
        };
    };
};

var baddies: std.StringArrayHashMapUnmanaged(BanData) = .{};
var ban_list_updated: bool = false;
var goodies: std.StringArrayHashMapUnmanaged(BanData) = .{};

const Groups = std.EnumArray(parser.Group, []const Detection);

const Meaningful = struct {
    group: parser.Group,
    line: []const u8,
};

fn meaningful(line: []const u8) ?Meaningful {
    const rules: Groups = comptime .init(.{
        .dovecot = parser.dovecot.rules,
        .nginx = parser.nginx.rules,
        .postfix = parser.postfix.rules,
        .sshd = parser.sshd.rules,
    });

    inline for (parser.Group.fields) |fld| {
        if (parser.Filters.get(fld)(line)) {
            inline for (comptime rules.get(fld)) |rule| {
                if (indexOf(u8, line, rule.hit)) |_| {
                    return .{
                        .group = .dovecot,
                        .line = line,
                    };
                }
            }
        }
    }

    return null;
}

pub const Addr = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    fn getOct(comptime sep: u8, str: []const u8) !switch (sep) {
        '.' => u8,
        ':' => u16,
        else => @compileError("not implemented"),
    } {
        switch (sep) {
            '.' => {
                var idx: usize = 0;
                s: switch (str[idx]) {
                    '0'...'9' => {
                        idx += 1;
                        if (idx < str.len) continue :s str[idx];
                        continue :s '.';
                    },
                    '.', '\t', ' ' => return parseInt(u8, str[0..idx], 10),
                    else => return error.InvalidAddr,
                }
            },
            ':' => comptime unreachable,
            else => comptime unreachable,
        }
    }

    fn parseV4(str: []const u8) !Addr {
        var rest: []const u8 = str;
        const first = try getOct('.', rest);
        rest = rest[1 + (indexOfScalar(u8, rest, '.') orelse return error.InvalidAddr) ..];
        const second = try getOct('.', rest);
        rest = rest[1 + (indexOfScalar(u8, rest, '.') orelse return error.InvalidAddr) ..];
        const third = try getOct('.', rest);
        rest = rest[1 + (indexOfScalar(u8, rest, '.') orelse return error.InvalidAddr) ..];
        const forth = try getOct('.', rest);

        return .{ .ipv4 = .{ first, second, third, forth } };
    }

    fn parseV6(str: []const u8) !Addr {
        _ = str;
        return .{ .ipv6 = unreachable };
    }

    pub fn parse(str: []const u8) !Addr {
        if (indexOf(u8, str, ".")) |_| {
            return try parseV4(str);
        } else if (indexOf(u8, str, ":")) |_| {
            return try parseV6(str);
        } else return error.UnknownAddr;
    }

    pub fn format(
        addr: Addr,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        w: anytype,
    ) !void {
        switch (addr) {
            .ipv4 => |ip| return w.print("{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] }),
            .ipv6 => unreachable,
        }
    }
};

const Timestamp = packed struct(i64) {
    ts: i64,

    pub fn parse(str: []const u8) struct { ?Timestamp, usize } {
        _ = str;
        return .{ @bitCast(@as(i64, 0)), 0 };
    }
};

fn parseLine(mean: Meaningful) !?Event {
    return switch (mean.group) {
        .dovecot => parser.dovecot.parseLine(mean.line),
        .nginx => parser.nginx.parseLine(mean.line),
        .postfix => parser.postfix.parseLine(mean.line),
        .sshd => parser.sshd.parseLine(mean.line),
    };
}

test parseLine {
    const log_lines: []const Meaningful = &[_]Meaningful{
        .{
            .group = .postfix,
            .line =
            \\May 30 22:00:35 gr mail.warn postfix/smtps/smtpd[27561]: warning: unknown[117.217.120.52]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=gwe@gr.ht
            ,
        },
        .{
            .group = .nginx,
            .line =
            \\149.255.62.135 - - [29/May/2025:23:43:02 +0000] "GET /.well-known/acme-challenge/I2I61_4DQ3KA_0XG9NMR937P1-57Z3XQ HTTP/1.1" 200 47 "-" "Cpanel-HTTP-Client/1.0"
            ,
        },
        .{
            .group = .sshd,
            .line =
            \\May 29 15:21:53 gr auth.info sshd-session[25292]: banner exchange: Connection from 20.64.105.146 port 47144: invalid format
            ,
        },
        .{
            .group = .dovecot,
            .line =
            \\Jun 12 19:24:38 imap-login: Info: Login aborted: Connection closed (auth failed, 3 attempts in 15 secs) (auth_failed): user=<eft>, method=PLAIN, rip=80.51.181.144, lip=127.4.20.69, TLS, session=<25Nw4GQ3Ms9QM7WQ>
            ,
        },
    };

    const log_hits = &[_]Event{
        .{ .src_addr = .{ .ipv4 = [4]u8{ 117, 217, 120, 52 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 149, 255, 62, 135 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 20, 64, 105, 146 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 80, 51, 181, 144 } }, .timestamp = 0, .extra = "" },
    };

    for (log_lines, log_hits) |line, hit| {
        try std.testing.expectEqualDeep(hit, parseLine(line));
    }
}

fn sleep(ms: u64) void {
    std.time.sleep(ms * std.time.ns_per_ms);
}

const example_config = @import("example-config.zig");
const parser = @import("parser.zig");
const Event = @import("Event.zig");
const Detection = @import("Detection.zig");
const Actionable = @import("Actionable.zig");

const std = @import("std");
const Allocator = std.mem.Allocator;
const indexOf = std.mem.indexOf;
const indexOfAny = std.mem.indexOfAny;
const indexOfScalar = std.mem.indexOfScalar;
const indexOfScalarPos = std.mem.indexOfScalarPos;
const parseInt = std.fmt.parseInt;
const startsWith = std.mem.startsWith;
const eql = std.mem.eql;
const bufPrint = std.fmt.bufPrint;
