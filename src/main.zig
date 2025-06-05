const nft_example_config: []const u8 =
    \\table inet filter {
    \\    set abuse {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\    set abuse-http {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\    set abuse-mail {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\    set abuse-sshd {
    \\        type ipv4_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\
    \\    set abuse-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\    set abuse-http-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\    set abuse-mail-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\    set abuse-sshd-v6 {
    \\        type ipv6_addr
    \\        flags interval, timeout
    \\        auto-merge
    \\        elements = { }
    \\    }
    \\
    \\
    \\    chain input {
    \\        type filter hook input priority 0; policy accept;
    \\
    \\        ip saddr @abuse tcp counter drop
    \\        ip saddr @abuse-http tcp dport { 80, 443 } counter reject with icmpx 3
    \\        ip saddr @abuse-mail tcp dport { 25, 143, 465, 587, 993, } counter reject with icmpx 3
    \\        ip saddr @abuse-sshd tcp dport 22 counter drop
    \\
    \\        ip6 saddr @abuse tcp counter drop
    \\        ip6 saddr @abuse-http-v6 tcp dport { 80, 443 } counter reject with icmpx 3
    \\        ip6 saddr @abuse-mail-v6 tcp dport { 25, 143, 465, 587, 993, } counter reject with icmpx 3
    \\        ip6 saddr @abuse-sshd-v6 tcp dport 22 counter drop
    \\
    \\        iifname "lo" accept comment "Accept any localhost traffic"
    \\        ct state { 0x2, 0x4 } accept comment "Accept traffic originated from us"
    \\        ip protocol 1 icmp type { 0, 3, 8, 11, 12 } accept comment "Accept ICMP"
    \\    }
    \\
    \\    chain forward {
    \\        type filter hook forward priority 0; policy accept;
    \\    }
    \\
    \\    chain output {
    \\        type filter hook output priority 0; policy accept;
    \\    }
    \\}
    \\
;

fn usage(arg0: []const u8) noreturn {
    //
    std.debug.print(
        \\error: you're holding it wrong
        \\  usage: {s} [filename]
        \\
        \\Options:
        \\
        \\    --example                 Print an example nft config then exit
        \\    --watch     [filename]    Process and then tail for new data
        \\    --watch-all [filename]    Process and then tail all following logs
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
        if (lf.fbs.buffer.len > 0) {
            return std.posix.munmap(@alignCast(lf.fbs.buffer));
        }
    }

    pub fn lineFromFile(lf: *LogFile) !?[]const u8 {
        const meta = try lf.file.metadata();
        if (meta.size() < lf.meta.size()) return error.Truncated;
        if (meta.size() == lf.meta.size() and lf.fbs.pos == meta.size()) return null;
        lf.meta = meta;
        var reader = lf.file.reader();
        if (try reader.readUntilDelimiterOrEof(&lf.line_buffer, '\n')) |data| {
            lf.fbs.pos += data.len;
            return data;
        }
        return null;
    }

    pub fn line(lf: *LogFile) !?[]const u8 {
        if (lf.fbs.buffer.len == 0) return lf.lineFromFile();
        var reader = lf.fbs.reader();
        return try reader.readUntilDelimiterOrEof(&lf.line_buffer, '\n') orelse {
            std.posix.munmap(@alignCast(lf.fbs.buffer));
            lf.fbs.buffer.len = 0;
            if (!lf.watch) return null;
            try lf.file.seekTo(lf.fbs.pos);
            return lf.lineFromFile();
        };
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

    while (args.next()) |arg| {
        if (log_files.items.len >= file_buf.len) {
            std.debug.print("PANIC: too many log files given\n", .{});
            usage(arg0);
        }
        if (startsWith(u8, arg, "--")) {
            if (eql(u8, arg, "--example")) {
                try stdout.writeAll(nft_example_config);
                return;
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
    for (log_files.items) |*file| {
        _ = try readFile(a, file);
    }

    var banlist_http: std.ArrayListUnmanaged(u8) = .{};
    var banlist_mail: std.ArrayListUnmanaged(u8) = .{};
    var banlist_sshd: std.ArrayListUnmanaged(u8) = .{};

    var vals = baddies.iterator();
    while (vals.next()) |kv| {
        if (kv.value_ptr.count < 2) continue;
        var w = switch (kv.value_ptr.class) {
            .nginx => &banlist_http.writer(a),
            .postfix => &banlist_mail.writer(a),
            .sshd => &banlist_sshd.writer(a),
        };
        try w.print(", {s}", .{kv.key_ptr.*});
    }

    if (banlist_http.items.len > 2) {
        try stdout.print("nft add element inet filter abuse-http '{{ {s} }}'\n", .{banlist_http.items[2..]});
    }

    if (banlist_mail.items.len > 2) {
        try stdout.print("nft add element inet filter abuse-mail '{{ {s} }}'\n", .{banlist_mail.items[2..]});
    }

    if (banlist_sshd.items.len > 2) {
        try stdout.print("nft add element inet filter abuse-sshd '{{ {s} }}'\n", .{banlist_sshd.items[2..]});
    }
    try bw.flush();

    var count: usize = 0;
    for (log_files.items) |*lf| {
        if (!lf.watch) {
            lf.raze();
        } else count += 1;
    }

    while (count > 0) {
        for (log_files.items) |*lf| {
            if (!lf.watch) continue;
            const new = readFile(a, lf) catch |err| {
                std.debug.print("err {}\n", .{err});

                lf.raze();
                count -|= 1;
                continue;
            };
            if (new) |n| std.debug.print("new ban {s}\n", .{n});
        }

        std.time.sleep(1 * 1000 * 1000 * 1000);
    }
}

fn readFile(a: Allocator, logfile: *LogFile) !?[]const u8 {
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
                gop.value_ptr.count = 1;
                gop.value_ptr.class = m.class;
                return gop.key_ptr.*;
            } else {
                gop.value_ptr.count += 1;
            }
            //std.debug.print("found: {s}\n", .{m});
        }
    }

    const lap = timer.lap();
    std.debug.print("Done: {} lines in  {}ms\n", .{ line_count, lap / 1000_000 });
    return null;
}

fn mmap(f: std.fs.File) ![]const u8 {
    const PROT = std.posix.PROT;

    const length = try f.getEndPos();
    const offset = 0;
    return std.posix.mmap(null, length, PROT.READ, .{ .TYPE = .SHARED }, f.handle, offset);
}

const BanData = struct {
    class: Class,
    count: usize,
};

var baddies: std.StringHashMapUnmanaged(BanData) = .{};
var goodies: std.StringHashMapUnmanaged(BanData) = .{};

const Detection = struct {
    class: Class,
    hit: []const u8,
};

const Class = enum {
    nginx,
    postfix,
    sshd,
};

const Meaningful = struct {
    class: Class,
    line: []const u8,
};

fn meaningful(line: []const u8) ?Meaningful {
    const interesting: []const Detection = &[_]Detection{
        .{
            .class = .postfix,
            .hit = "SASL LOGIN authentication failed",
        },
        .{
            .class = .nginx,
            .hit = "/.env HTTP/",
        },
        .{
            .class = .sshd,
            .hit = ": Connection closed by invalid user",
        },
        .{
            .class = .sshd,
            .hit = ": Invalid user",
        },
    };

    inline for (interesting) |dect| {
        if (std.mem.indexOf(u8, line, dect.hit)) |_| {
            return .{
                .class = dect.class,
                .line = line,
            };
        }
    } else {
        return null;
    }
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
    };

    const log_hits = &[_]Line{
        .{ .src_addr = .{ .ipv4 = [4]u8{ 117, 217, 120, 52 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 149, 255, 62, 135 } }, .timestamp = 0, .extra = "" },
        .{ .src_addr = .{ .ipv4 = [4]u8{ 20, 64, 105, 146 } }, .timestamp = 0, .extra = "" },
    };

    for (log_lines, log_hits) |line, hit| {
        try std.testing.expectEqualDeep(hit, parseLine(line));
    }
}

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
