default_watch: LogFile.Mode = .once,
damonize: ?bool = null,
quiet: bool = false,
bantime: []const u8 = "",
config_arg: ?[]const u8 = null,
dryrun: bool = false,
exec_rules: bool = false,
pid_file: ?[]const u8 = null,
enable_trusted: bool = false,

bantime_buffer: [64]u8 = @splat(' '),

const Config = @This();

pub fn validateBantime(cfg: *Config, bantime_w: []const u8) !void {
    const bantime = std.mem.trim(u8, bantime_w, " \t");
    for (bantime) |chr| switch (chr) {
        '0'...'9', 'd', 'h', 'm', 's' => {},
        else => return error.InvalidBanTimeString,
    };
    if (bantime.len > 0) {
        cfg.bantime = try bufPrint(&cfg.bantime_buffer, " timeout {s}", .{bantime});
    } else {
        // I've been burned by 0len pointer assignments
        cfg.bantime = try bufPrint(&cfg.bantime_buffer, "", .{});
    }
}

pub fn parse(c: *Config, a: Allocator, fname: []const u8, files: *FileArray) !void {
    const fd = std.fs.cwd().openFile(fname, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("Error config file missing {s}\n", .{fname});
            std.posix.exit(1);
        },
        else => return err,
    };
    if (try fd.getEndPos() == 0) return;
    const config = try std.posix.mmap(
        null,
        try fd.getEndPos(),
        std.posix.PROT.READ,
        .{ .TYPE = .SHARED },
        fd.handle,
        0,
    );
    fd.close();
    syslog.enabled = true;
    if (!c.dryrun) c.exec_rules = true;
    if (c.damonize == null) c.damonize = true;

    var fbs = std.io.FixedBufferStream([]const u8){ .buffer = config, .pos = 0 };
    var reader = fbs.reader();
    var line_buf: [2048]u8 = undefined;
    while (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) |line| {
        try c.parseLine(a, line, files);
    }
}

fn truthy(arg: []const u8) bool {
    for (&[_][]const u8{ "off", "disabled", "no", "false", "0" }) |str| {
        if (std.mem.eql(u8, arg, str)) return false;
    }
    return true;
}

fn parseLine(c: *Config, a: Allocator, full: []const u8, files: *FileArray) !void {
    const line = std.mem.trim(u8, full, " \t\n\r");
    if (line.len < 4) return;
    if (line[0] == '#') return;

    if (indexOf(u8, line, "=")) |argidx| {
        const arg: []const u8 = std.mem.trim(u8, line[argidx + 1 ..], " \t\n\r");
        if (arg.len == 0) return error.ConfigValueMissing;
        if (startsWith(u8, line, "file")) {
            try parseLineFile(a, files, null, arg);
        } else if (startsWith(u8, line, "sshd")) {
            try parseLineFile(a, files, .sshd, arg);
        } else if (startsWith(u8, line, "postfix")) {
            try parseLineFile(a, files, .postfix, arg);
        } else if (startsWith(u8, line, "nginx")) {
            try parseLineFile(a, files, .nginx, arg);
        } else if (startsWith(u8, line, "dovecot")) {
            try parseLineFile(a, files, .dovecot, arg);
        } else if (startsWith(u8, line, "bantime")) {
            try c.validateBantime(arg);
        } else if (startsWith(u8, line, "enable_trusted")) {
            c.enable_trusted = truthy(arg);
        }
    }

    if (startsWith(u8, line, "syslog")) {
        syslog.enabled = true; // TODO support false and disabled
    }
}

fn parseLineFile(a: Allocator, log_files: *FileArray, format: ?parser.Format, arg: []const u8) !void {
    if (arg[0] != '/') return error.ConfigPathNotAbsolute;
    if (indexOf(u8, arg, "*")) |i| {
        const prefix = arg[0..i];
        const postfix = arg[i + 1 ..];
        if (postfix.len > 0 and postfix[0] == '*') return error.NotImplemented;
        if (prefix[prefix.len - 1] != '/') return error.NotImplemented;
        const stat = try std.fs.cwd().statFile(prefix);
        if (stat.kind != .directory) return error.NotADir;
        var dir = try std.fs.cwd().openDir(prefix, .{ .iterate = true });
        defer dir.close();
        var itr = dir.iterate();
        while (try itr.next()) |subp| {
            if (subp.kind != .file) continue;
            if (!endsWith(u8, subp.name, postfix)) continue;
            const fname = try std.fmt.allocPrint(a, "{s}{s}", .{ prefix, subp.name });
            log_files.appendAssumeCapacity(try .init(fname, .follow, format));
        }
    } else log_files.appendAssumeCapacity(try .init(try a.dupe(u8, arg), .follow, format));
}

test parse {
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();

    const file_data =
        \\bantime = 30d
        \\file = /dev/null
        \\
        \\[files]
        \\sshd = /dev/null
        \\postfix = /dev/null
        \\nginx = /dev/null
        \\dovecot = /dev/null
        \\syslog = enabled
        \\syslog = /dev/null
        \\#file = /dev/null
        \\
        \\bantime = 14d
        \\
        \\
        \\
    ;

    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = file_data });

    var a = std.testing.allocator;
    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);

    var fbuf: [32]LogFile = undefined;
    var files: FileArray = .initBuffer(&fbuf);

    var c: Config = .{};
    try c.parse(std.testing.allocator, cfile, &files);
    try std.testing.expectEqual(@as(usize, 5), files.items.len);
    try std.testing.expectEqualStrings(" timeout 14d", c.bantime);
    try std.testing.expectEqual(true, syslog.enabled);
    for (files.items) |f| std.testing.allocator.free(f.path);
}

test "config trusted" {
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();
    const file_data =
        \\enable_trusted = enabled
        \\
    ;

    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = file_data });

    var a = std.testing.allocator;
    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);

    var c: Config = .{};
    try c.parse(std.testing.allocator, cfile, undefined);
    try std.testing.expectEqual(true, c.enable_trusted);
}

test "config untrusted" {
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();
    const file_data =
        \\enable_trusted = disabled
        \\
    ;

    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = file_data });

    var a = std.testing.allocator;
    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);
    var c: Config = .{};
    try c.parse(std.testing.allocator, cfile, undefined);
    try std.testing.expectEqual(false, c.enable_trusted);
}

test "config default" {
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();
    const file_data =
        \\enable_ = bleh
        \\
    ;

    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = file_data });

    var a = std.testing.allocator;
    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);
    var c: Config = .{};
    try c.parse(std.testing.allocator, cfile, undefined);
    try std.testing.expectEqual(false, c.enable_trusted);
}

test "parse multi" {
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();

    inline for (.{ "first", "second.log", "third.log", "forth.log" }) |fname| {
        try td.dir.writeFile(.{ .sub_path = fname, .data = "" });
    }

    var abs_buffer: [2048]u8 = undefined;
    const absp = try td.dir.realpath(".", &abs_buffer);
    var config_buffer: [2048]u8 = undefined;
    const config_data = try std.fmt.bufPrint(&config_buffer, "file = {s}/*.log\n", .{absp});
    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = config_data });

    var a = std.testing.allocator;
    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);

    var fbuf: [32]LogFile = undefined;
    var files: FileArray = .initBuffer(&fbuf);
    var c: Config = .{};
    try c.parse(std.testing.allocator, cfile, &files);
    try std.testing.expectEqual(@as(usize, 3), files.items.len);
    for (files.items) |f| std.testing.allocator.free(f.path);
}

const parser = @import("parser.zig");
const std = @import("std");
const Allocator = std.mem.Allocator;
const syslog = @import("syslog.zig");
const bufPrint = std.fmt.bufPrint;
const LogFile = @import("LogFile.zig");
const FileArray = std.ArrayListUnmanaged(LogFile);
const indexOf = std.mem.indexOf;
const startsWith = std.mem.startsWith;
const endsWith = std.mem.endsWith;
