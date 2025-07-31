hit: []const u8,

prefix: ?[]const Detection = null,

heat: u16 = 16,
decay: u16 = 0,
ban_time: ?u32 = null,

const Detection = @This();
