default_watch: LogFile.Mode = .once,
damonize: ?bool = null,
quiet: bool = false,
bantime: []const u8 = "",
config_arg: ?[]const u8 = null,
dryrun: bool = false,
exec_rules: bool = false,
pid_file: ?[]const u8 = null,
enable_trusted: bool = false,
syslog: bool = true,

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

pub fn parse(c: *Config, fname: []const u8, files: *FileArray, a: Allocator, io: Io) !void {
    const fd = Io.Dir.cwd().openFile(io, fname, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("Error config file missing {s}\n", .{fname});
            std.posix.exit(1);
        },
        else => return err,
    };
    defer fd.close(io);
    if (!c.dryrun) c.exec_rules = true;
    if (c.damonize == null) c.damonize = true;

    var r_b: [0x8000]u8 = undefined;
    var reader = fd.reader(io, &r_b);
    while (reader.interface.takeDelimiterInclusive('\n')) |line| {
        try c.parseLine(line, files, a, io);
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }
}

fn truthy(arg: []const u8) bool {
    for (&[_][]const u8{ "off", "disabled", "no", "false", "0" }) |str| {
        if (std.mem.eql(u8, arg, str)) return false;
    }
    return true;
}

fn parseLine(c: *Config, full: []const u8, files: *FileArray, a: Allocator, io: Io) !void {
    const line = std.mem.trim(u8, full, " \t\n\r");
    if (line.len < 4) return;
    if (line[0] == '#') return;

    if (indexOf(u8, line, "=")) |argidx| {
        const arg: []const u8 = std.mem.trim(u8, line[argidx + 1 ..], " \t\n\r");
        if (arg.len == 0) return error.ConfigValueMissing;
        if (startsWith(u8, line, "file")) {
            try parseLineFile(files, null, arg, a, io);
        } else if (startsWith(u8, line, "sshd")) {
            try parseLineFile(files, .sshd, arg, a, io);
        } else if (startsWith(u8, line, "postfix")) {
            try parseLineFile(files, .postfix, arg, a, io);
        } else if (startsWith(u8, line, "nginx")) {
            try parseLineFile(files, .nginx, arg, a, io);
        } else if (startsWith(u8, line, "dovecot")) {
            try parseLineFile(files, .dovecot, arg, a, io);
        } else if (startsWith(u8, line, "bantime")) {
            try c.validateBantime(arg);
        } else if (startsWith(u8, line, "enable_trusted")) {
            c.enable_trusted = truthy(arg);
        }
    }

    if (startsWith(u8, line, "syslog")) {
        c.syslog = true; // TODO support false and disabled
    }
}

fn parseLineFile(log_files: *FileArray, format: ?parser.Format, arg: []const u8, a: Allocator, io: Io) !void {
    if (arg[0] != '/') return error.ConfigPathNotAbsolute;
    if (indexOf(u8, arg, "*")) |i| {
        const prefix = arg[0..i];
        const postfix = arg[i + 1 ..];
        if (postfix.len > 0 and postfix[0] == '*') return error.NotImplemented;
        if (prefix[prefix.len - 1] != '/') return error.NotImplemented;
        const stat = try std.fs.cwd().statFile(prefix);
        if (stat.kind != .directory) return error.NotADir;
        var dir = try Io.Dir.cwd().openDir(io, prefix, .{ .iterate = true });
        defer dir.close(io);
        var old: std.fs.Dir = .adaptFromNewApi(dir);
        var itr = old.iterate();
        while (try itr.next()) |subp| {
            if (subp.kind != .file) continue;
            if (!endsWith(u8, subp.name, postfix)) continue;
            const fname = try std.fmt.allocPrint(a, "{s}{s}", .{ prefix, subp.name });
            log_files.appendAssumeCapacity(try .init(fname, .follow, format, io));
        }
    } else log_files.appendAssumeCapacity(try .init(try a.dupe(u8, arg), .follow, format, io));
}

test parse {
    var a = std.testing.allocator;
    const io = std.testing.io;
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

    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);

    var fbuf: [32]LogFile = undefined;
    var files: FileArray = .initBuffer(&fbuf);

    var c: Config = .{};
    try c.parse(cfile, &files, a, io);
    try std.testing.expectEqual(@as(usize, 5), files.items.len);
    try std.testing.expectEqualStrings(" timeout 14d", c.bantime);
    try std.testing.expectEqual(true, c.syslog);
    for (files.items) |f| a.free(f.path);
}

test "config trusted" {
    var a = std.testing.allocator;
    const io = std.testing.io;
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();
    const file_data =
        \\enable_trusted = enabled
        \\
    ;

    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = file_data });

    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);

    var c: Config = .{};
    try c.parse(cfile, undefined, a, io);
    try std.testing.expectEqual(true, c.enable_trusted);
}

test "config untrusted" {
    var a = std.testing.allocator;
    const io = std.testing.io;
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();
    const file_data =
        \\enable_trusted = disabled
        \\
    ;

    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = file_data });

    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);
    var c: Config = .{};
    try c.parse(cfile, undefined, a, io);
    try std.testing.expectEqual(false, c.enable_trusted);
}

test "config default" {
    var a = std.testing.allocator;
    const io = std.testing.io;
    var td = std.testing.tmpDir(.{});
    defer td.cleanup();
    const file_data =
        \\enable_ = bleh
        \\
    ;

    try td.dir.writeFile(.{ .sub_path = "benv.conf", .data = file_data });

    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);
    var c: Config = .{};
    try c.parse(cfile, undefined, a, io);
    try std.testing.expectEqual(false, c.enable_trusted);
}

test "parse multi" {
    var a = std.testing.allocator;
    const io = std.testing.io;
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

    const cfile = try std.mem.join(a, "/", &[3][]const u8{ ".zig-cache/tmp", &td.sub_path, "benv.conf" });
    defer a.free(cfile);

    var fbuf: [32]LogFile = undefined;
    var files: FileArray = .initBuffer(&fbuf);
    var c: Config = .{};
    try c.parse(cfile, &files, a, io);
    try std.testing.expectEqual(@as(usize, 3), files.items.len);
    for (files.items) |f| a.free(f.path);
}

const parser = @import("parser.zig");
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const bufPrint = std.fmt.bufPrint;
const LogFile = @import("LogFile.zig");
const FileArray = std.ArrayListUnmanaged(LogFile);
const indexOf = std.mem.indexOf;
const startsWith = std.mem.startsWith;
const endsWith = std.mem.endsWith;
