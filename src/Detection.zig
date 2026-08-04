hit: union(enum) {
    direct: []const u8,
    prefix: struct { []const u8, []const Detection },
},
opt: Options = .{},

const Detection = @This();

pub const Options = struct {
    heat: u16 = 16,
    decay: u16 = 0,
    ban_time: ?u32 = null,
};

pub fn rule(str: []const u8, o: Options) Detection {
    return .{
        .hit = .{ .direct = str },
        .opt = o,
    };
}

pub fn prefix(str: []const u8, rules: []const Detection, o: Options) Detection {
    return .{
        .hit = .{ .prefix = .{ str, rules } },
        .opt = o,
    };
}
