pub const Group = enum {
    dovecot,
    nginx,
    postfix,
    sshd,

    pub const len = @typeInfo(Group).@"enum".fields.len;
    pub const fields: [len]Group = .{
        .dovecot,
        .nginx,
        .postfix,
        .sshd,
    };
};

pub const Filters: std.EnumArray(Group, *const fn ([]const u8) bool) = .init(.{
    .dovecot = dovecot.filter,
    .nginx = nginx.filter,
    .postfix = postfix.filter,
    .sshd = sshd.filter,
});

pub const dovecot = @import("parser/dovecot.zig");
pub const nginx = @import("parser/nginx.zig");
pub const postfix = @import("parser/postfix.zig");
pub const sshd = @import("parser/sshd.zig");

const std = @import("std");
