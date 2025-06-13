fn usage(arg0: []const u8) noreturn {
    //
    std.debug.print(
        \\error: you're holding it wrong
        \\
        \\Usage: {s} [filename]
        \\
        \\Options:
        \\
        \\    --example                 Print an example nft config then exit
        \\    --exec                    Install banned elements into nft
        \\
        \\    --watch     <filename>    Process and then tail for new data
        \\    --watch-all <filename>    Process and then tail all following logs
        \\
        \\    --quiet                   Don't print rules
        \\    --ban-timeout <timeout>   Default time to ban a host [504h]
        \\
    , .{arg0});
    std.posix.exit(1);
}

const LogFile = struct {
    file: std.fs.File,
    fbs: std.io.FixedBufferStream([]const u8),
    watch: bool,
    meta: std.fs.File.Metadata,
    line_buffer: [4096]u8 = undefined,

    pub fn init(filename: []const u8, watch: bool) !LogFile {
        const f = try std.fs.cwd().openFile(filename, .{});
        const lf: LogFile = .{
            .file = f,
            .fbs = .{
                .buffer = try mmap(f),
                .pos = 0,
            },
            .watch = watch,
            .meta = try f.metadata(),
        };

        return lf;
    }

    pub fn raze(lf: *LogFile) void {
        lf.watch = false;
        lf.file.close();
        std.posix.munmap(@alignCast(lf.fbs.buffer));
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
        lf.fbs.buffer = try std.posix.mremap(
            @alignCast(@constCast(lf.fbs.buffer.ptr)),
            lf.fbs.buffer.len,
            meta.size(),
            .{ .MAYMOVE = true },
            null,
        );
        lf.meta = meta;
    }

    pub fn line(lf: *LogFile) !?[]const u8 {
        if (lf.fbs.pos == lf.fbs.buffer.len) try lf.remap();

        var reader = lf.fbs.reader();
        return try reader.readUntilDelimiterOrEof(&lf.line_buffer, '\n');
    }
};

var file_buf: [64]LogFile = undefined;

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
    var exec_rules: bool = false;
    var quiet: bool = false;
    var to_buf: [32]u8 = @splat(' ');
    var timeout: []const u8 = "";

    while (args.next()) |arg| {
        if (log_files.items.len >= file_buf.len) {
            std.debug.print("PANIC: too many log files given\n", .{});
            usage(arg0);
        }
        if (startsWith(u8, arg, "--")) {
            if (eql(u8, arg, "--example")) {
                try stdout.writeAll(example_config.nft);
                return;
            } else if (eql(u8, arg, "--exec")) {
                exec_rules = true;
            } else if (eql(u8, arg, "--quiet")) {
                quiet = true;
            } else if (eql(u8, arg, "--ban-timeout")) {
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
            } else usage(arg0);
        } else {
            log_files.appendAssumeCapacity(try .init(arg, default_watch));
        }
    }

    if (log_files.items.len == 0) usage(arg0);

    for (log_files.items) |*file| {
        try readFile(a, file);
    }

    if (exec_rules) {
        try execBanList(a, timeout);
    } else {
        if (!quiet) try printBanList(a, stdout.any(), timeout);
        try bw.flush();
    }

    var count: usize = 0;
    for (log_files.items) |*lf| {
        if (!lf.watch) {
            lf.raze();
        } else count += 1;
    }

    var banned: usize = baddies.count();
    while (count > 0) {
        for (log_files.items) |*lf| {
            if (!lf.watch) continue;
            readFile(a, lf) catch |err| {
                std.debug.print("err {}\n", .{err});
                lf.raze();
                count -|= 1;
                continue;
            };
        }
        if (baddies.count() > banned) {
            if (exec_rules) {
                try execBanList(a, timeout);
            } else {
                if (!quiet) try printBanList(a, stdout.any(), timeout);
                try bw.flush();
            }
            banned = baddies.count();
        }
        std.time.sleep(1 * 1000 * 1000 * 1000);
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

    if (http.items.len > 2) {
        var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
            "abuse-http",
            http.items,
        }, a);
        child.expand_arg0 = .expand;
        _ = try child.spawnAndWait();
    }

    if (mail.items.len > 2) {
        var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
            "abuse-mail",
            mail.items,
        }, a);
        child.expand_arg0 = .expand;
        _ = try child.spawnAndWait();
    }

    if (sshd.items.len > 2) {
        var child: std.process.Child = .init(&cmd_base ++ [2][]const u8{
            "abuse-sshd",
            sshd.items,
        }, a);
        child.expand_arg0 = .expand;
        _ = try child.spawnAndWait();
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

fn readFile(a: Allocator, logfile: *LogFile) !void {
    var timer: std.time.Timer = try .start();
    var line_count: usize = 0;

    while (try logfile.line()) |line| {
        line_count += 1;
        if (meaningful(line)) |m| {
            const res = try parseLine(m) orelse continue;

            const paddr = try std.fmt.allocPrint(a, "{}", .{res.src_addr});
            const gop = try baddies.getOrPut(a, paddr);
            if (!gop.found_existing) {
                gop.key_ptr.* = try a.dupe(u8, paddr);
                gop.value_ptr.count = .zero;
            }
            switch (m.class) {
                .dovecot => gop.value_ptr.count.mail += 9,
                .nginx => gop.value_ptr.count.http += 1,
                .postfix => gop.value_ptr.count.mail += 1,
                .sshd => gop.value_ptr.count.sshd += 1,
            }
            //std.debug.print("found: {s}\n", .{m});
        }
    }

    const lap = timer.lap();
    std.debug.print("Done: {} lines in  {}ms\n", .{ line_count, lap / 1000_000 });
}

const BanData = struct {
    count: Count = .zero,

    pub const Count = struct {
        http: usize,
        mail: usize,
        sshd: usize,

        pub const zero: Count = .{ .http = 0, .mail = 0, .sshd = 0 };
    };
};

var baddies: std.StringHashMapUnmanaged(BanData) = .{};
var goodies: std.StringHashMapUnmanaged(BanData) = .{};

const Group = struct {
    dovecot: []const Detection,
    nginx: []const Detection,
    postfix: []const Detection,
    sshd: []const Detection,
};

const Detection = struct {
    hit: []const u8,
};

const Class = enum {
    dovecot,
    nginx,
    postfix,
    sshd,
};

const Meaningful = struct {
    class: Class,
    line: []const u8,
};

fn meaningful(line: []const u8) ?Meaningful {
    const rules: Group = .{
        .dovecot = &[_]Detection{
            .{ .hit = "(auth_failed): user" },
            .{ .hit = "Connection closed (auth failed," },
        },
        .nginx = &[_]Detection{
            .{ .hit = "/.env HTTP/" },
            .{ .hit = "PHP/eval-stdin.php HTTP/1.1\" 404" },
        },
        .postfix = &[_]Detection{
            .{ .hit = "SASL LOGIN authentication failed" },
            .{ .hit = "SASL PLAIN authentication failed" },
        },
        .sshd = &[_]Detection{
            .{ .hit = ": Connection closed by invalid user" },
            .{ .hit = ": Invalid user" },
        },
    };

    if (parser.dovecot.filter(line)) {
        inline for (rules.dovecot) |rule| {
            if (indexOf(u8, line, rule.hit)) |_| {
                return .{
                    .class = .dovecot,
                    .line = line,
                };
            }
        }
    } else if (parser.nginx.filter(line)) {
        inline for (rules.nginx) |rule| {
            if (indexOf(u8, line, rule.hit)) |_| {
                return .{
                    .class = .nginx,
                    .line = line,
                };
            }
        }
    } else if (parser.postfix.filter(line)) {
        inline for (rules.postfix) |rule| {
            if (indexOf(u8, line, rule.hit)) |_| {
                return .{
                    .class = .postfix,
                    .line = line,
                };
            }
        }
    } else if (parser.sshd.filter(line)) {
        inline for (rules.sshd) |rule| {
            if (indexOf(u8, line, rule.hit)) |_| {
                return .{
                    .class = .sshd,
                    .line = line,
                };
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

pub const Line = struct {
    src_addr: Addr,
    timestamp: i64,
    extra: []const u8,
};

fn parseLine(mean: Meaningful) !?Line {
    return switch (mean.class) {
        .dovecot => parser.dovecot.parseLine(mean.line),
        .nginx => parser.nginx.parseLine(mean.line),
        .postfix => parser.postfix.parseLine(mean.line),
        .sshd => parser.sshd.parseLine(mean.line),
    };
}

test parseLine {
    const log_lines: []const Meaningful = &[_]Meaningful{
        .{
            .class = .postfix,
            .line =
            \\May 30 22:00:35 gr mail.warn postfix/smtps/smtpd[27561]: warning: unknown[117.217.120.52]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=gwe@gr.ht
            ,
        },
        .{
            .class = .nginx,
            .line =
            \\149.255.62.135 - - [29/May/2025:23:43:02 +0000] "GET /.well-known/acme-challenge/I2I61_4DQ3KA_0XG9NMR937P1-57Z3XQ HTTP/1.1" 200 47 "-" "Cpanel-HTTP-Client/1.0"
            ,
        },
        .{
            .class = .sshd,
            .line =
            \\May 29 15:21:53 gr auth.info sshd-session[25292]: banner exchange: Connection from 20.64.105.146 port 47144: invalid format
            ,
        },
        .{
            .class = .dovecot,
            .line =
            \\Jun 12 19:24:38 imap-login: Info: Login aborted: Connection closed (auth failed, 3 attempts in 15 secs) (auth_failed): user=<eft>, method=PLAIN, rip=80.51.181.144, lip=127.4.20.69, TLS, session=<25Nw4GQ3Ms9QM7WQ>
            ,
        },
    };

    const log_hits = &[_]Line{
        .{ .src_addr = .{ .ipv4 = [4]u8{ 117, 217, 120, 52 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 149, 255, 62, 135 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 20, 64, 105, 146 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 80, 51, 181, 144 } }, .timestamp = 0, .extra = "" },
    };

    for (log_lines, log_hits) |line, hit| {
        try std.testing.expectEqualDeep(hit, parseLine(line));
    }
}

const example_config = @import("example-config.zig");
const parser = @import("parser.zig");

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
