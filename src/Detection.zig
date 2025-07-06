hit: []const u8,

tree: ?[]const Detection = null,

heat: u16 = 1,
decay: u16 = 0,
ban_time: ?u32 = null,

const Detection = @This();
