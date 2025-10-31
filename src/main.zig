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
        \\    --enable-trusted                  Enable auto trusted exemption list
        \\    --dry-run                         Don't execute rules  
    ++ if (builtin.mode == .Debug)
        \\    --debug-rules     <filename>      Print rule and matched hit to <filename> [not yet implemented]
    else
        "" ++
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

var dwb: [256]u8 = undefined;
var discarding: Writer.Discarding = .init(&dwb);
var discarding_writer: ?*Writer = &discarding.writer;
const builtin = @import("builtin");

fn debug_rule(detection: Detection, hit: []const u8, file: []const u8) !void {
    if (comptime builtin.mode != .Debug) return;

    discarding_writer.print("{s} -> {} [{s}]\n", .{ hit, detection, file });
}

pub fn main() !void {
    const stdout = std.fs.File.stdout();

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
            } else if (eql(u8, arg, "--enable-trusted")) {
                c.enable_trusted = true;
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
            var w = f.writer(&.{});
            try w.interface.print("{}\n", .{pid});
            f.close();
            std.posix.exit(0);
        }
    }
    signals.setDefaultMask();

    for (log_files.items) |*lf| {
        lf.initReader();
    }

    try core(a, &log_files, stdout);
}

fn core(a: Allocator, src_files: *FileArray, stdout: anytype) !void {
    for (src_files.items) |*file| {
        var timer: std.time.Timer = try .start();
        const line_count = try drainFile(a, file);
        const lap = timer.lap();
        if (c.damonize orelse true)
            std.debug.print("Done: {} lines in  {}ms\n", .{ line_count, lap / 1000_000 });
    }

    if (c.exec_rules) {
        try execBanList(a);
    } else if (!c.quiet) {
        var w_b: [0x800]u8 = undefined;
        var w = stdout.writer(&w_b);
        try printBanList(a, &w.interface);
    }

    var watch_list: FileArray = try .initCapacity(a, src_files.items.len);

    while (src_files.pop()) |file| {
        switch (file.mode) {
            .once, .closed, .stdin => {
                file.raze();
            },
            .watch, .follow => {
                watch_list.appendAssumeCapacity(file);
            },
        }
    }

    while (watch_list.items.len > 0) {
        for (watch_list.items) |*lf| {
            switch (lf.mode) {
                .closed => continue,
                .once => @panic("unreachable"),
                .watch, .follow, .stdin => {
                    _ = drainFile(a, lf) catch |err| {
                        std.debug.print("err {}\n", .{err});
                        lf.raze();
                    };
                },
            }
        }

        if (ban_list_updated) {
            if (c.exec_rules) {
                try execBanList(a);
            } else if (!c.quiet) {
                var w_b: [0x800]u8 = undefined;
                var w = stdout.writer(&w_b);
                try printBanList(a, &w.interface);
            }
            ban_list_updated = false;
        }

        if (signals.check(200)) |sig| {
            std.debug.print("signaled {s}\n", .{@tagName(sig)});
            switch (sig) {
                .hup => {
                    try syslog.log(.{ .signal = .{ .sig = @intFromEnum(sig), .str = "SIGHUP" } });
                    for (watch_list.items) |*lf| {
                        lf.reInit() catch |err| {
                            try syslog.log(.{ .err = .{
                                .err = @errorName(err),
                                .str = "Unable to restart on file",
                                .file = lf.path,
                            } });
                        };
                    }
                },
                .quit => {},
                .usr1, .usr2 => {},
            }
        }
    }
}

fn genLists(a: Allocator) ![3]ArrayList(u8) {
    const ts = std.time.timestamp();
    var banlist_http: ArrayList(u8) = .{};
    var banlist_mail: ArrayList(u8) = .{};
    var banlist_sshd: ArrayList(u8) = .{};

    errdefer {
        banlist_http.deinit(a);
        banlist_mail.deinit(a);
        banlist_sshd.deinit(a);
    }

    var vals = baddies.iterator();
    while (vals.next()) |kv| {
        if (ts > kv.value_ptr.banned orelse ts) continue;
        if (kv.value_ptr.heat.http >= 16) {
            var w = banlist_http.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, c.bantime });
        }
        if (kv.value_ptr.heat.mail >= 16) {
            var w = banlist_mail.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, c.bantime });
        }
        if (kv.value_ptr.heat.sshd >= 16) {
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

fn printBanList(a: Allocator, stdout: *std.Io.Writer) !void {
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

fn drainFile(a: Allocator, logfile: *LogFile) !usize {
    var line_count: usize = 0;
    while (try logfile.line()) |line| {
        line_count += 1;
        if (findHit(line)) |found| switch (found) {
            .abuse => |abuse| {
                const event = try parseLine(abuse) orelse continue;

                var b: [0xff]u8 = undefined;
                const paddr = try std.fmt.bufPrint(&b, "{f}", .{event.src_addr});
                if (trusted_addrs.contains(paddr)) {
                    try syslog.log(.{ .trustedabuse = .{ .addr = paddr } });
                    continue;
                }

                ban_list_updated = true;
                const gop = try baddies.getOrPut(a, paddr);
                if (!gop.found_existing) {
                    gop.key_ptr.* = try a.dupe(u8, paddr);
                    gop.value_ptr.* = .{};
                }
                if (gop.value_ptr.banned) |banned| {
                    if (banned < std.time.timestamp() - 3) gop.value_ptr.banned = null;
                }
                switch (abuse.format) {
                    .dovecot => {
                        gop.value_ptr.heat.mail +|= abuse.rule.heat;
                        gop.value_ptr.time.mail = @max(abuse.rule.ban_time orelse 0, gop.value_ptr.time.mail);
                    },
                    .nginx => {
                        gop.value_ptr.heat.http +|= abuse.rule.heat;
                        gop.value_ptr.time.http = @max(abuse.rule.ban_time orelse 0, gop.value_ptr.time.http);
                    },
                    .postfix => {
                        gop.value_ptr.heat.mail +|= abuse.rule.heat;
                        gop.value_ptr.time.mail = @max(abuse.rule.ban_time orelse 0, gop.value_ptr.time.mail);
                    },
                    .sshd => {
                        gop.value_ptr.heat.sshd +|= abuse.rule.heat;
                        gop.value_ptr.time.sshd = @max(abuse.rule.ban_time orelse 0, gop.value_ptr.time.sshd);
                    },
                }
            },
            .trusted => |trust| {
                if (!c.enable_trusted) continue;
                const event = try parseLine(trust) orelse continue;

                var b: [0xff]u8 = undefined;
                const paddr = try std.fmt.bufPrint(&b, "{f}", .{event.src_addr});
                const gop = try trusted_addrs.getOrPut(a, paddr);
                if (!gop.found_existing) {
                    try syslog.log(.{ .trusted = .{ .addr = paddr } });
                    gop.key_ptr.* = try a.dupe(u8, paddr);
                }
            },
        };
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
var trusted_addrs: std.StringHashMapUnmanaged(void) = .{};

const Formats = std.EnumArray(parser.Format, []const Detection);

const Meaningful = union(enum) {
    abuse: Meaning,
    trusted: Meaning,

    pub const Meaning = struct {
        format: parser.Format,
        rule: Detection,
        line: []const u8,
    };
};

fn scanRules(comptime fmt: parser.Format, line: []const u8) ?Meaningful.Meaning {
    const rules: Formats = comptime .init(.{
        .dovecot = parser.dovecot.rules,
        .nginx = parser.nginx.rules,
        .postfix = parser.postfix.rules,
        .sshd = parser.sshd.rules,
    });

    inline for (comptime rules.get(fmt)) |rule| {
        if (indexOf(u8, line, rule.hit)) |i| {
            if (rule.prefix) |prefix| {
                inline for (prefix) |branch| {
                    if (indexOf(u8, line[i..], branch.hit)) |_| {
                        return .{ .abuse = .{ .format = fmt, .rule = rule, .line = line } };
                    }
                }
            } else return .{ .abuse = .{ .format = fmt, .rule = rule, .line = line } };
        }
    }
}

fn findHit(line: []const u8) ?Meaningful {
    const rules: Formats = comptime .init(.{
        .dovecot = parser.dovecot.rules,
        .nginx = parser.nginx.rules,
        .postfix = parser.postfix.rules,
        .sshd = parser.sshd.rules,
    });

    const trusted_rules: Formats = comptime .init(.{
        .dovecot = parser.dovecot.trusted_rules,
        .nginx = parser.nginx.trusted_rules,
        .postfix = parser.postfix.trusted_rules,
        .sshd = parser.sshd.trusted_rules,
    });

    if (indexOf(u8, line, "auth.warn benevolence") != null) return null;

    inline for (parser.Format.fields) |pf_field| {
        if (parser.Filters.get(pf_field)(line)) {
            inline for (comptime rules.get(pf_field)) |rule| {
                if (indexOf(u8, line, rule.hit)) |i| {
                    if (rule.prefix) |prefix| {
                        inline for (prefix) |branch| {
                            if (indexOf(u8, line[i..], branch.hit)) |_| {
                                return .{ .abuse = .{ .format = pf_field, .rule = branch, .line = line } };
                            }
                        }
                    } else return .{ .abuse = .{ .format = pf_field, .rule = rule, .line = line } };
                }
            }
            inline for (comptime trusted_rules.get(pf_field)) |rule| {
                if (indexOf(u8, line, rule.hit)) |i| {
                    if (rule.prefix) |prefix| {
                        inline for (prefix) |branch| {
                            if (indexOf(u8, line[i..], branch.hit)) |_| {
                                return .{ .trusted = .{ .format = pf_field, .rule = rule, .line = line } };
                            }
                        }
                    } else return .{ .trusted = .{ .format = pf_field, .rule = rule, .line = line } };
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

fn parseLine(mean: Meaningful.Meaning) !?Event {
    return switch (mean.format) {
        .dovecot => parser.dovecot.parseLine(mean.line),
        .nginx => parser.nginx.parseLine(mean.line),
        .postfix => parser.postfix.parseLine(mean.line),
        .sshd => parser.sshd.parseLine(mean.line),
    };
}

test parseLine {
    const log_lines = &[_]Meaningful{
        .{ .abuse = .{
            .rule = parser.postfix.rules[1],
            .format = .postfix,
            .line = "May 30 22:00:35 gr mail.warn postfix/smtps/smtpd[27561]: warning: unknown[117.217.120.52]" ++
                ": SASL PLAIN authentication failed: (reason unavailable), sasl_username=gwe@gr.ht",
        } },
        .{ .abuse = .{
            .rule = parser.postfix.rules[1],
            .format = .postfix,
            .line = "May 30 22:00:35 gr mail.info postfix/smtps/smtpd[27561]: warning: " ++
                "unknown[117.217.120.52]: SASL PLAIN authentication failed: (reason unavailable)," ++
                "sasl_username=gwe@gr.ht",
        } },
        .{ .abuse = .{
            .rule = parser.postfix.rules[4],
            .format = .postfix,
            .line = "Jul  3 00:46:09 gr mail.info postfix/smtp/smtpd[10108]: disconnect from " ++
                "unknown[77.90.185.6] ehlo=1 auth=0/1 rset=1 quit=1 commands=3/4",
        } },
        .{ .abuse = .{
            .rule = parser.nginx.rules[0],
            .format = .nginx,
            .line = "149.255.62.135 - - [29/May/2025:23:43:02 +0000] \"GET /.env HTTP/1.1\" 200 " ++
                "47 \"-\" \"Cpanel-HTTP-Client/1.0\"",
        } },
        .{ .abuse = .{
            .rule = parser.nginx.rules[3].prefix.?[0],
            .format = .nginx,
            .line = "185.177.72.104 - - [03/Jul/2025:21:06:55 +0000] \"GET /.git/config HTTP/1.1\" " ++
                "404 181 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML," ++
                "like Gecko) Chrome/91.0.4472.124 Safari/537.36\" \"-\"",
        } },
        .{ .abuse = .{
            .rule = parser.sshd.rules[0],
            .format = .sshd,
            .line = "May 29 15:21:53 gr auth.info sshd-session[25292]: Connection closed by " ++
                "invalid user root 20.64.105.146 port 34292 [preauth]",
        } },
        .{ .abuse = .{
            .rule = parser.dovecot.rules[0],
            .format = .dovecot,
            .line = "Jun 12 19:24:38 imap-login: Info: Login aborted: Connection closed " ++
                "(auth failed, 3 attempts in 15 secs) (auth_failed): user=<eft>, method=PLAIN, rip=80.51.181.144, " ++
                "lip=127.4.20.69, TLS, session=<25Nw4GQ3Ms9QM7WQ>",
        } },
        .{ .abuse = .{
            .rule = parser.postfix.rules[7].prefix.?[0],
            .format = .postfix,
            .line = "Jul 31 17:13:38 gr mail.info postfix/smtp/smtpd[9566]: NOQUEUE: reject: RCPT from " ++
                "unknown[162.218.52.165]: 450 4.7.1 Client host rejected: cannot find your reverse hostname," ++
                " [162.218.52.165]; from=<bounce@jantool.org> to=<banned_email@gr.ht> proto=ESMTP helo=<mail1.jantool.org>",
        } },
        .{ .trusted = .{
            .rule = parser.sshd.trusted_rules[0],
            .format = .sshd,
            .line = "Jul 31 20:13:59 gr auth.info sshd-session[10237]: Accepted publickey for grayhatter" ++
                " from 127.42.0.69 port 53142 ssh2: ED25519 SHA256:ezIQDYy8JvgUcKabQeIrT1UK/xmtDdK04UrkckY+VAQ",
        } },
    };

    const log_hits = &[_]Event{
        .{ .src_addr = .{ .ipv4 = [4]u8{ 117, 217, 120, 52 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 117, 217, 120, 52 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 77, 90, 185, 6 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 149, 255, 62, 135 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 185, 177, 72, 104 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 20, 64, 105, 146 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 80, 51, 181, 144 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 162, 218, 52, 165 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 127, 42, 0, 69 } }, .timestamp = 0, .extra = "" },
    };

    for (log_lines, log_hits) |log, expected_hit| {
        const log_meaning = switch (log) {
            inline else => |m| m,
        };
        const hit = findHit(log_meaning.line);

        try std.testing.expectEqualDeep(log, hit);
        const meaning: Meaningful.Meaning = switch (hit.?) {
            inline else => |m| m,
        };
        try std.testing.expectEqualStrings(log_meaning.line, meaning.line);
        try std.testing.expectEqualDeep(expected_hit, parseLine(log_meaning));
        try std.testing.expectEqualDeep(log_meaning.rule, meaning.rule);
        try std.testing.expectEqualDeep(log_meaning.rule.heat, meaning.rule.heat);
    }
}

fn sleep(ms: u64) void {
    std.time.sleep(ms * std.time.ns_per_ms);
}

test {
    _ = &Config;
    _ = std.testing.refAllDecls(@This());
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
const LogFile = @import("LogFile.zig");
const net = @import("net.zig");

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;
const FileArray = ArrayList(LogFile);
const Writer = std.Io.Writer;
const indexOf = std.mem.indexOf;
const startsWith = std.mem.startsWith;
const eql = std.mem.eql;
