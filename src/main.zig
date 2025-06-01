fn usage(arg0: []const u8) noreturn {
    //
    std.debug.print(
        \\ you're holding it wrong
        \\usage: {s} [filename]
        \\
    , .{arg0});
    std.posix.exit(1);
}

pub fn main() !void {
    var timer: std.time.Timer = try .start();
    var debug_a: std.heap.DebugAllocator(.{}) = .{};
    const a = debug_a.allocator();

    var args = std.process.args();
    const arg0 = args.next() orelse usage("wat?!");
    const in_filename = args.next() orelse usage(arg0);
    var in_file = try std.fs.cwd().openFile(in_filename, .{});
    defer in_file.close();
    const data = try mmap(in_file);
    var fbs = std.io.fixedBufferStream(data);
    var reader = fbs.reader();

    var line_count: usize = 0;

    var line_buf: [0xffff]u8 = undefined;
    var line_ = try reader.readUntilDelimiterOrEof(&line_buf, '\n');
    while (line_) |line| : (line_ = try reader.readUntilDelimiterOrEof(&line_buf, '\n')) {
        line_count += 1;
        if (meaningful(line)) |m| {
            const res = try parseLine(m) orelse continue;

            const paddr = try std.fmt.allocPrint(a, "{}", .{res.src_addr});
            const gop = try baddies.getOrPut(a, paddr);
            if (!gop.found_existing) {
                gop.key_ptr.* = try a.dupe(u8, paddr);
                gop.value_ptr.* = 0;
            } else {
                gop.value_ptr.* += 1;
            }
            //std.debug.print("found: {s}\n", .{m});
        }
    }

    var vals = baddies.iterator();
    while (vals.next()) |kv| {
        if (kv.value_ptr.* < 2) continue;
        std.debug.print("nft add element inet filter abuse-mail '{{ {s} }}'\n", .{kv.key_ptr.*});
        //std.debug.print("{s}  for {}'\n", .{ kv.key_ptr.*, kv.value_ptr.* });
    }
    const lap = timer.lap();
    std.debug.print("Done: {} lines in  {}ms\n", .{ line_count, lap / 1000_000 });
}

fn mmap(f: std.fs.File) ![]const u8 {
    const PROT = std.posix.PROT;

    try f.seekFromEnd(0);
    const length = try f.getPos();
    const offset = 0;
    return std.posix.mmap(null, length, PROT.READ, .{ .TYPE = .SHARED }, f.handle, offset);
}

var baddies: std.StringHashMapUnmanaged(usize) = .{};
var goodies: std.StringHashMapUnmanaged(usize) = .{};

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

const NginxParser = struct {
    pub fn parseAddr(line: []const u8) !Addr {
        return Addr.parse(line[0 .. indexOfScalar(u8, line, ' ') orelse return error.InvalidLogLine]);
    }

    pub fn parseTime(line: []const u8) !i64 {
        _ = line;
        return 0;
    }

    pub fn parseExtra(line: []const u8) ![]const u8 {
        _ = line;
        return "";
    }
};

const PostfixParser = struct {
    pub fn parseAddr(line: []const u8) !Addr {
        if (std.mem.indexOf(u8, line, "unknown[")) |i| {
            if (std.mem.indexOfScalarPos(u8, line, i, ']')) |j| {
                return try Addr.parse(line[i + 8 .. j]);
            }
        }
        return error.AddrNotFound;
    }

    pub fn parseTime(line: []const u8) !i64 {
        _ = line;
        return 0;
    }

    pub fn parseExtra(line: []const u8) ![]const u8 {
        _ = line;
        return "";
    }
};

const SshdParser = struct {
    pub fn parseAddr(line: []const u8) !Addr {
        if (std.mem.indexOf(u8, line, "Connection from ")) |i| {
            return try Addr.parse(line[i + 16 ..]);
        }
        return error.AddrNotFound;
    }

    pub fn parseTime(line: []const u8) !i64 {
        _ = line;
        return 0;
    }

    pub fn parseExtra(line: []const u8) ![]const u8 {
        _ = line;
        return "";
    }
};

fn meaningful(line: []const u8) ?Meaningful {
    const interesting: []const Detection = &[_]Detection{
        .{
            .class = .postfix,
            .hit = "SASL LOGIN authentication failed",
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

const Addr = union(enum) {
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
        return .{ .ipv6 = undefined };
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

const Line = struct {
    src_addr: Addr,
    timestamp: i64,
    extra: []const u8,
};

fn parseLine(mean: Meaningful) !?Line {
    return switch (mean.class) {
        .nginx => {
            return .{
                .src_addr = try NginxParser.parseAddr(mean.line),
                .timestamp = try NginxParser.parseTime(mean.line),
                .extra = try NginxParser.parseExtra(mean.line),
            };
        },

        .postfix => {
            return .{
                .src_addr = PostfixParser.parseAddr(mean.line) catch return null,
                .timestamp = try PostfixParser.parseTime(mean.line),
                .extra = try PostfixParser.parseExtra(mean.line),
            };
        },
        .sshd => {
            return .{
                .src_addr = try SshdParser.parseAddr(mean.line),
                .timestamp = try SshdParser.parseTime(mean.line),
                .extra = try SshdParser.parseExtra(mean.line),
            };
        },
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

const std = @import("std");
const Allocator = std.mem.Allocator;
const indexOf = std.mem.indexOf;
const indexOfAny = std.mem.indexOfAny;
const indexOfScalar = std.mem.indexOfScalar;
//const indexOfScalarPos = std.mem.indexOfScalarPos;
const parseInt = std.fmt.parseInt;
