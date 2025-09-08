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

    pub fn format(addr: Addr, w: *std.Io.Writer) !void {
        switch (addr) {
            .ipv4 => |ip| return w.print("{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] }),
            .ipv6 => unreachable,
        }
    }
};

const std = @import("std");
const indexOfScalar = std.mem.indexOfScalar;
const parseInt = std.fmt.parseInt;
const indexOf = std.mem.indexOf;
