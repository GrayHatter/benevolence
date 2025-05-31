pub fn main() !void {
    var timer: std.time.Timer = try .start();
    var debug_a: std.heap.DebugAllocator(.{}) = .{};
    const a = debug_a.allocator();

    var args = std.process.args();
    const arg0 = args.next() orelse return error.InvalidArgv;
    _ = arg0;
    const in_filename = args.next() orelse return error.InvalidArgv;
    var in_file = try std.fs.cwd().openFile(in_filename, .{});
    defer in_file.close();
    const data = try mmap(in_file);
    var fbs = std.io.fixedBufferStream(data);
    var reader = fbs.reader();

    var line_count: usize = 0;

    var line_buf: [0xffff]u8 = undefined;
    var line_ = try reader.readUntilDelimiterOrEof(&line_buf, '\n');
    while (line_) |line| {
        line_count += 1;
        if (meaningful(line)) |m| {
            try process(a, m);
            //std.debug.print("found: {s}\n", .{m});
        }
        line_ = try reader.readUntilDelimiterOrEof(&line_buf, '\n');
    }

    var vals = baddies.iterator();
    while (vals.next()) |kv| {
        if (kv.value_ptr.* < 5) continue;
        std.debug.print("found: {s} for {}\n", .{ kv.key_ptr.*, kv.value_ptr.* });
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

const interesting: []const Detection = &[_]Detection{
    .{ .class = .postfix, .hit = "SASL LOGIN authentication failed" },
};

const Class = enum {
    postfix,
    sshd,
};

const Meaningful = struct {
    class: Class,
    line: []const u8,
};

fn meaningful(line: []const u8) ?Meaningful {
    inline for (interesting) |dect| {
        if (std.mem.indexOf(u8, line, dect.hit)) |_| {
            return .{ .class = dect.class, .line = line };
        }
    } else {
        return null;
    }
}

fn process(a: Allocator, m: Meaningful) !void {
    if (std.mem.indexOf(u8, m.line, "unknown[")) |i| {
        if (std.mem.indexOfScalarPos(u8, m.line, i, ']')) |j| {
            const addr = m.line[i + 8 .. j];
            const gop = try baddies.getOrPut(a, addr);
            if (!gop.found_existing) {
                gop.key_ptr.* = try a.dupe(u8, addr);
                gop.value_ptr.* = 0;
            } else {
                gop.value_ptr.* += 1;
            }
        }
    }
}

const std = @import("std");
const Allocator = std.mem.Allocator;
