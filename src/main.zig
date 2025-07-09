fn usage(arg0: []const u8) noreturn {
    //
    std.debug.print(
        \\error: you're holding it wrong
        \\
        \\Usage: {s} [filename]
        \\
        \\Options:
        \\
        \\    -c                <filename>      Config file
        \\    -d                                Daemonize [fork to background]
        \\    -f                                Stay in foreground
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

var c: Config = .{};

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var debug_a: std.heap.GeneralPurposeAllocator(.{ .safety = true }) = .{};
    const a = debug_a.allocator();

    var args = std.process.args();
    const arg0 = args.next() orelse usage("wat?!");

    // This is a bug
    const args_file_limit = 20;
    var log_files: FileArray = try .initCapacity(a, args_file_limit);

    while (args.next()) |arg| {
        if (log_files.items.len >= args_file_limit) {
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
                if (c.dryrun == true) {
                    std.debug.print("error: --exec and --dry-run are incompatible\n", .{});
                    usage(arg0);
                }
                c.exec_rules = true;
            } else if (eql(u8, arg, "--dry-run")) {
                c.dryrun = true;
                c.exec_rules = false;
            } else if (eql(u8, arg, "--quiet")) {
                c.quiet = true;
            } else if (eql(u8, arg, "--syslog")) {
                syslog.enabled = true;
            } else if (eql(u8, arg, "--ban-time")) {
                const bantime = args.next() orelse usage(arg0);
                c.validateBantime(bantime) catch usage(arg0);
            } else if (eql(u8, arg, "--watch")) {
                const filename = args.next() orelse {
                    std.debug.print("error: --watch requires a filename\n", .{});
                    usage(arg0);
                };
                log_files.appendAssumeCapacity(try .init(filename, .follow, null));
            } else if (eql(u8, arg, "--watch-all")) {
                c.default_watch = .follow;
            } else {
                usage(arg0);
            }
        } else if (startsWith(u8, arg, "-")) {
            if (eql(u8, arg, "-c")) {
                c.config_arg = args.next() orelse {
                    std.debug.print("error: -c requires a filename\n", .{});
                    usage(arg0);
                };
            } else if (eql(u8, arg, "-f")) {
                c.damonize = false;
            } else if (eql(u8, arg, "-d")) {
                c.damonize = true;
            }
        } else {
            log_files.appendAssumeCapacity(try .init(arg, c.default_watch, null));
        }
    }

    if (c.config_arg) |ca| {
        try c.parse(a, ca, &log_files);
    }

    if (log_files.items.len == 0) usage(arg0);

    if (c.damonize != null and c.damonize.?) {
        const pid_file = c.pid_file orelse "/run/benevolence.pid";
        errdefer std.posix.exit(9);
        const pid = try std.posix.fork();
        if (pid > 0) {
            var f = try std.fs.cwd().createFile(pid_file, .{});
            var w = f.writer();
            try w.print("{}\n", .{pid});
            f.close();
            std.posix.exit(0);
        }
    }
    signals.setDefaultMask();

    try core(a, &log_files, stdout);
}

fn core(a: Allocator, log_files: *FileArray, stdout: anytype) !void {
    for (log_files.items) |*file| {
        var timer: std.time.Timer = try .start();
        const line_count = try drainFile(a, file);
        const lap = timer.lap();
        if (c.damonize orelse true) std.debug.print("Done: {} lines in  {}ms\n", .{ line_count, lap / 1000_000 });
    }

    if (c.exec_rules) {
        try execBanList(a);
    } else if (!c.quiet) {
        try printBanList(a, stdout.any());
    }

    for (0..log_files.items.len) |i| {
        while (i > log_files.items.len and log_files.items[i].mode == .once) {
            var lf = log_files.swapRemove(i);
            lf.raze();
        }
    }

    while (log_files.items.len > 0) {
        for (log_files.items) |*lf| {
            if (lf.mode == .closed) continue;
            _ = drainFile(a, lf) catch |err| {
                std.debug.print("err {}\n", .{err});
                lf.raze();
                continue;
            };
        }

        if (ban_list_updated) {
            if (c.exec_rules) {
                try execBanList(a);
            } else if (!c.quiet) {
                try printBanList(a, stdout.any());
            }
            ban_list_updated = false;
        }

        if (signals.check(200)) |sig| {
            std.debug.print("signaled {s}\n", .{@tagName(sig)});
            switch (sig) {
                .hup => {
                    try syslog.log(.{ .signal = .{ .sig = @intFromEnum(sig), .str = "SIGHUP" } });
                    for (log_files.items) |*lf| {
                        try lf.reInit();
                    }
                },
                .quit => {},
                .usr1, .usr2 => {},
            }
        }
    }
}

fn genLists(a: Allocator) ![3]std.ArrayListUnmanaged(u8) {
    const ts = std.time.timestamp();
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
        if (ts > kv.value_ptr.banned orelse ts) continue;
        if (kv.value_ptr.heat.http >= 2) {
            var w = banlist_http.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, c.bantime });
        }
        if (kv.value_ptr.heat.mail >= 2) {
            var w = banlist_mail.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, c.bantime });
        }
        if (kv.value_ptr.heat.sshd >= 2) {
            var w = banlist_sshd.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, c.bantime });
        }
        kv.value_ptr.banned = ts;
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

fn execList(comptime str: []const u8, a: Allocator, items: []const u8) !void {
    const cmd_base = [_][]const u8{
        "nft", "add", "element", "inet", "filter",
    };

    var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
        "abuse-" ++ str,
        items,
    }, a);
    child.expand_arg0 = .expand;
    if (!c.dryrun) _ = try child.spawnAndWait();
    const count = std.mem.count(u8, items, ", ") + 1;
    try syslog.log(.{
        .banned = .{ .count = count, .surface = str, .src = items },
    });
}

fn execBanList(a: Allocator) !void {
    var http, var mail, var sshd = try genLists(a);
    defer {
        http.deinit(a);
        mail.deinit(a);
        sshd.deinit(a);
    }

    if (http.items.len > 4) try execList("http", a, http.items);
    if (mail.items.len > 4) try execList("mail", a, mail.items);
    if (sshd.items.len > 4) try execList("sshd", a, sshd.items);
}

fn printBanList(a: Allocator, stdout: std.io.AnyWriter) !void {
    var http, var mail, var sshd = try genLists(a);
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

fn drainFile(a: Allocator, logfile: *File) !usize {
    var line_count: usize = 0;
    while (try logfile.line()) |line| {
        line_count += 1;
        if (meaningful(line)) |m| {
            const event = try parseLine(m) orelse continue;

            var b: [0xff]u8 = undefined;
            const paddr = try std.fmt.bufPrint(&b, "{}", .{event.src_addr});

            ban_list_updated = true;
            const gop = try baddies.getOrPut(a, paddr);
            if (!gop.found_existing) {
                gop.key_ptr.* = try a.dupe(u8, paddr);
                gop.value_ptr.* = .{};
            }
            if (gop.value_ptr.banned) |banned| {
                if (banned < std.time.timestamp() - 3) gop.value_ptr.banned = null;
            }
            switch (m.format) {
                .dovecot => {
                    gop.value_ptr.heat.mail +|= m.rule.heat;
                    gop.value_ptr.time.mail = @max(m.rule.ban_time orelse 0, gop.value_ptr.time.mail);
                },
                .nginx => {
                    gop.value_ptr.heat.http +|= m.rule.heat;
                    gop.value_ptr.time.http = @max(m.rule.ban_time orelse 0, gop.value_ptr.time.http);
                },
                .postfix => {
                    gop.value_ptr.heat.mail +|= m.rule.heat;
                    gop.value_ptr.time.mail = @max(m.rule.ban_time orelse 0, gop.value_ptr.time.mail);
                },
                .sshd => {
                    gop.value_ptr.heat.sshd +|= m.rule.heat;
                    gop.value_ptr.time.sshd = @max(m.rule.ban_time orelse 0, gop.value_ptr.time.sshd);
                },
            }
        }
    }
    return line_count;
}

const BanData = struct {
    heat: Heat = .zero,
    time: Time = .zero,
    banned: ?i64 = null,

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

    pub const Time = struct {
        http: u32,
        mail: u32,
        sshd: u32,

        pub const zero: Time = .{
            .http = 0,
            .mail = 0,
            .sshd = 0,
        };
    };
};

var baddies: std.StringArrayHashMapUnmanaged(BanData) = .{};
var ban_list_updated: bool = false;
var goodies: std.StringHashMapUnmanaged(void) = .{};

const Formats = std.EnumArray(parser.Format, []const Detection);

const Meaningful = struct {
    format: parser.Format,
    rule: Detection,
    line: []const u8,
};

fn meaningful(line: []const u8) ?Meaningful {
    const rules: Formats = comptime .init(.{
        .dovecot = parser.dovecot.rules,
        .nginx = parser.nginx.rules,
        .postfix = parser.postfix.rules,
        .sshd = parser.sshd.rules,
    });

    inline for (parser.Format.fields) |fld| {
        if (parser.Filters.get(fld)(line)) {
            inline for (comptime rules.get(fld)) |rule| {
                if (indexOf(u8, line, rule.hit)) |i| {
                    if (rule.tree) |tree| {
                        inline for (tree) |branch| {
                            if (indexOf(u8, line[i..], branch.hit)) |_| {
                                return .{
                                    .format = fld,
                                    .rule = rule,
                                    .line = line,
                                };
                            }
                        }
                    } else return .{
                        .format = fld,
                        .rule = rule,
                        .line = line,
                    };
                }
            }
        }
    }

    return null;
}

const Timestamp = packed struct(i64) {
    ts: i64,

    pub fn parse(str: []const u8) struct { ?Timestamp, usize } {
        _ = str;
        return .{ @bitCast(@as(i64, 0)), 0 };
    }
};

fn parseLine(mean: Meaningful) !?Event {
    return switch (mean.format) {
        .dovecot => parser.dovecot.parseLine(mean.line),
        .nginx => parser.nginx.parseLine(mean.line),
        .postfix => parser.postfix.parseLine(mean.line),
        .sshd => parser.sshd.parseLine(mean.line),
    };
}

test parseLine {
    const log_lines: []const Meaningful = &[_]Meaningful{
        .{
            .rule = .{ .hit = "" },
            .format = .postfix,
            .line =
            \\May 30 22:00:35 gr mail.warn postfix/smtps/smtpd[27561]: warning: unknown[117.217.120.52]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=gwe@gr.ht
            ,
        },
        .{
            .rule = .{ .hit = "" },
            .format = .postfix,
            .line =
            \\May 30 22:00:35 gr mail.info postfix/smtps/smtpd[27561]: warning: unknown[117.217.120.52]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=gwe@gr.ht
            ,
        },
        .{
            .rule = parser.postfix.rules[4],
            .format = .postfix,
            .line =
            \\Jul  3 00:46:09 gr mail.info postfix/smtp/smtpd[10108]: disconnect from unknown[77.90.185.6] ehlo=1 auth=0/1 rset=1 quit=1 commands=3/4
            ,
        },
        .{
            .rule = .{ .hit = "" },
            .format = .nginx,
            .line =
            \\149.255.62.135 - - [29/May/2025:23:43:02 +0000] "GET /.env HTTP/1.1" 200 47 "-" "Cpanel-HTTP-Client/1.0"
            ,
        },
        .{
            .rule = .{ .hit = "" },
            .format = .nginx,
            .line =
            \\185.177.72.104 - - [03/Jul/2025:21:06:55 +0000] "GET /.git/config HTTP/1.1" 404 181 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" "-"
            ,
        },

        .{
            .rule = .{ .hit = "" },
            .format = .sshd,
            .line =
            \\May 29 15:21:53 gr auth.info sshd-session[25292]: Connection closed by invalid user root 20.64.105.146 port 34292 [preauth]"
            ,
        },
        .{
            .rule = .{ .hit = "" },
            .format = .dovecot,
            .line =
            \\Jun 12 19:24:38 imap-login: Info: Login aborted: Connection closed (auth failed, 3 attempts in 15 secs) (auth_failed): user=<eft>, method=PLAIN, rip=80.51.181.144, lip=127.4.20.69, TLS, session=<25Nw4GQ3Ms9QM7WQ>
            ,
        },
    };

    for (log_lines) |ll| {
        try std.testing.expectEqual(ll.line, meaningful(ll.line).?.line);
    }

    const log_hits = &[_]Event{
        .{ .src_addr = .{ .ipv4 = [4]u8{ 117, 217, 120, 52 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 117, 217, 120, 52 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 77, 90, 185, 6 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 149, 255, 62, 135 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 185, 177, 72, 104 } }, .timestamp = 0, .extra = "" },
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

test {
    _ = &Config;
}

pub const Addr = net.Addr;

const signals = @import("signals.zig");
const Config = @import("Config.zig");
const example_config = @import("example-config.zig");
const syslog = @import("syslog.zig");
const parser = @import("parser.zig");
const Event = @import("Event.zig");
const Detection = @import("Detection.zig");
//const Actionable = @import("Actionable.zig");
const File = @import("File.zig");
const net = @import("net.zig");

const std = @import("std");
const Allocator = std.mem.Allocator;
const FileArray = std.ArrayListUnmanaged(File);
const indexOf = std.mem.indexOf;
const startsWith = std.mem.startsWith;
const eql = std.mem.eql;
