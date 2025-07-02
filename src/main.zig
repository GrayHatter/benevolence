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

var file_buf: [64]File = undefined;
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
    var log_files: std.ArrayListUnmanaged(File) = .initBuffer(&file_buf);

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
                syslog.enabled = true;
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
        if (kv.value_ptr.heat.http >= 2) {
            var w = banlist_http.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, timeout });
        }
        if (kv.value_ptr.heat.mail >= 2) {
            var w = banlist_mail.writer(a);
            try w.print(", {s}{s}", .{ kv.key_ptr.*, timeout });
        }
        if (kv.value_ptr.heat.sshd >= 2) {
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

fn execList(comptime str: []const u8, a: Allocator, items: []const u8) !void {
    const cmd_base = [_][]const u8{
        "nft", "add", "element", "inet", "filter",
    };

    var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
        "abuse-" ++ str,
        items,
    }, a);
    child.expand_arg0 = .expand;
    if (!dryrun) _ = try child.spawnAndWait();
    const count = std.mem.count(u8, items, ", ") + 1;
    try syslog.log(.{
        .banned = .{ .count = count, .surface = str, .src = items },
    });
}

fn execBanList(a: Allocator, timeout: []const u8) !void {
    var http, var mail, var sshd = try genLists(a, timeout);
    defer {
        http.deinit(a);
        mail.deinit(a);
        sshd.deinit(a);
    }

    if (http.items.len > 4) try execList("http", a, http.items);
    if (mail.items.len > 4) try execList("mail", a, mail.items);
    if (sshd.items.len > 4) try execList("sshd", a, sshd.items);
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

fn readFile(a: Allocator, logfile: *File) !usize {
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
                gop.value_ptr.heat = .zero;
                gop.value_ptr.time = .zero;
            }
            gop.value_ptr.banned = false;
            switch (m.group) {
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

const Groups = std.EnumArray(parser.Group, []const Detection);

const Meaningful = struct {
    group: parser.Group,
    rule: Detection,
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
                        .group = fld,
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
            .rule = .{ .hit = "" },
            .group = .postfix,
            .line =
            \\May 30 22:00:35 gr mail.warn postfix/smtps/smtpd[27561]: warning: unknown[117.217.120.52]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=gwe@gr.ht
            ,
        },
        .{
            .rule = .{ .hit = "" },
            .group = .nginx,
            .line =
            \\149.255.62.135 - - [29/May/2025:23:43:02 +0000] "GET /.well-known/acme-challenge/I2I61_4DQ3KA_0XG9NMR937P1-57Z3XQ HTTP/1.1" 200 47 "-" "Cpanel-HTTP-Client/1.0"
            ,
        },
        .{
            .rule = .{ .hit = "" },
            .group = .sshd,
            .line =
            \\May 29 15:21:53 gr auth.info sshd-session[25292]: banner exchange: Connection from 20.64.105.146 port 47144: invalid format
            ,
        },
        .{
            .rule = .{ .hit = "" },
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
const syslog = @import("syslog.zig");
const parser = @import("parser.zig");
const Event = @import("Event.zig");
const Detection = @import("Detection.zig");
const Actionable = @import("Actionable.zig");
const File = @import("File.zig");
const net = @import("net.zig");
pub const Addr = net.Addr;

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
