var arg0: []const u8 = "wat?!";
var dbfilename: []const u8 = "./asn_cache.db";
var host: []const u8 = "localhost"; // this was never valid

pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const io = init.io;

    const stdout_fd = std.Io.File.stdout();
    var stdout_b: [2048]u8 = undefined;
    var stdout_w = stdout_fd.writer(io, &stdout_b);
    const stdout = &stdout_w.interface;
    defer stdout.flush() catch unreachable;
    const stderr_fd = std.Io.File.stderr();
    var stderr_b: [2048]u8 = undefined;
    var stderr_w = stderr_fd.writer(io, &stderr_b);
    const stderr = &stderr_w.interface;
    defer stderr.flush() catch unreachable;

    // This is a bug
    var args = init.minimal.args.iterate();
    arg0 = args.next() orelse usage("invocation error: no arg0? how'd you do that?!", stdout);

    var to_search_b: [50][]const u8 = undefined;
    var to_search_list: ArrayList([]const u8) = .initBuffer(&to_search_b);

    while (args.next()) |arg| {
        if (arg.len > 1 and arg[0] == '-' and arg[1] != '-') {
            usage(null, stderr);
        } else if (eql(u8, arg, "--help")) {
            usage("help", stdout);
        } else if (eql(u8, arg, "--db")) {
            dbfilename = args.next() orelse usage("--db used without filename", stderr);
        } else if (eql(u8, arg, "--host")) {
            host = args.next() orelse usage("--host used without hostname", stderr);
        } else {
            to_search_list.appendBounded(arg) catch usage("error: too many ASN given", stderr);
        }
    }

    var db_fd: std.Io.File = std.Io.Dir.cwd().createFile(io, dbfilename, .{
        .read = true,
        .truncate = false,
    }) catch usage("unable to open db file", stderr);
    defer db_fd.close(io);
    var dbf_b: [4096]u8 = undefined;
    var db_writer = db_fd.writer(io, &dbf_b);
    var db_w = &db_writer.interface;
    try db_writer.seekTo(try db_fd.length(io));
    defer db_w.flush() catch unreachable;

    for (to_search_list.items) |asn_str| {
        const asn = ASN.parse(asn_str) catch continue;

        const net_list: []const u8 = fetchNetList(asn, a, io) catch |err| {
            log.err("net list fetch error {}", .{err});
            continue;
        };
        defer a.free(net_list);

        const whois = fetchWhois(net_list, a, io) catch |err| {
            log.err("net list fetch error {}", .{err});
            continue;
        };

        for (whois) |who| {
            try db_w.print("{s} {f} {s}\n", .{ who.Prefix, asn, who.Org orelse "no org found" });
        }
    }
}

const ASN = enum(usize) {
    _,

    fn parse(str: []const u8) !ASN {
        if (str.len == 0)
            return error.NoASN;
        const strim = trim(u8, str, &std.ascii.whitespace);
        const raw = cutPrefix(u8, strim, "AS") orelse strim;
        const num: usize = std.fmt.parseInt(usize, raw, 10) catch return error.ParseError;
        return @enumFromInt(num);
    }

    pub fn format(asn: ASN, w: *Writer) !void {
        try w.print("AS{}", .{@intFromEnum(asn)});
    }

    test parse {
        const asn = try parse("AS1337");
        try std.testing.expectEqual(@as(ASN, @enumFromInt(1337)), asn);
    }
};

const NetList = struct {
    Prefix: []const u8,
    Count: usize,
    Total: usize,

    const Json = struct { prefixes: []NetList };
};

fn fetchNetList(asn: ASN, a: Allocator, io: Io) ![]const u8 {
    var path_b: [500]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_b, "/super-lg/report/api/v1/prefixes/originated/{}", .{@intFromEnum(asn)});
    const uri: std.Uri = .{
        .scheme = "https",
        .host = .{ .percent_encoded = host },
        .path = .{ .percent_encoded = path },
    };
    log.err("uri: {f}", .{uri.fmt(.all)});
    const blob = try fetchPayload(uri, null, a, io);
    const json = try std.json.parseFromSlice(NetList.Json, a, blob, .{ .ignore_unknown_fields = true });
    //defer json.deinit();
    var w: Io.Writer.Allocating = try .initCapacity(a, 20000);
    try w.writer.writeAll("{\"prefixes\":[");
    for (json.value.prefixes) |net| {
        log.err("found net {s}", .{net.Prefix});
        try w.writer.print("\"{s}\",", .{net.Prefix});
    }
    w.writer.undo(1); // I hate json :<
    try w.writer.writeAll("]}");
    return try w.toOwnedSlice();
}

const Whois = struct {
    Prefix: []const u8,
    Org: ?[]const u8 = null,

    countrydata: ?struct {
        Iso3166_Name: ?[]const u8 = null,
        CC: ?[]const u8 = null,
    } = null,
    CC: ?[]const u8 = null,
    RIRData: ?struct {} = null,
    bogondata: ?struct {} = null,

    const Json = struct { response: []Whois };

    pub fn format(who: Whois, w: *Writer) !void {
        try w.print("{s} ", .{who.Prefix});
        try w.print("{s} ", .{who.Org orelse "[no org]"});
        if (who.countrydata) |cd| {
            try w.print("[CD: name:{s}, cc: {s}] ", .{ cd.Iso3166_Name orelse "null", cd.CC orelse "null" });
        } else try w.writeAll("CD: missing ");
        try w.print("CC: {s} ", .{who.CC orelse "null"});
        if (who.RIRData) |_| {
            try w.print("Have RIR ", .{});
        } else try w.writeAll("No RIR ");
        if (who.bogondata) |_| {
            try w.print("Have bogon ", .{});
        } else try w.writeAll("No bogon ");
    }
};

fn fetchWhois(netlist: []const u8, a: Allocator, io: Io) ![]Whois {
    if (netlist.len == 0) return &.{};
    const uri: std.Uri = .{
        .scheme = "https",
        .host = .{ .percent_encoded = host },
        .path = .{ .percent_encoded = "/super-lg/report/api/v1/whois/prefixes" },
    };
    const blob = try fetchPayload(uri, netlist, a, io);
    const json = try std.json.parseFromSlice(Whois.Json, a, blob, .{ .ignore_unknown_fields = true });
    //defer json.deinit();
    for (json.value.response) |val| {
        log.err("{f}", .{val});
    }
    return json.value.response;
}

fn fetchPayload(uri: std.Uri, post: ?[]const u8, a: Allocator, io: Io) ![]const u8 {
    var w: Io.Writer.Allocating = .init(a);
    var client: std.http.Client = .{ .allocator = a, .io = io };
    const page = try client.fetch(.{
        .location = .{ .uri = uri },
        .headers = .{
            .user_agent = .{ .override = "curl/8.12.0" },
            .content_type = if (post) |_| .{ .override = "application/json" } else .omit,
        },
        .response_writer = &w.writer,
        .method = if (post) |_| .POST else .GET,
        .payload = post,
    });
    if (page.status != .ok) {
        log.err("Unable to fetch target: {f} [{}]", .{ uri.fmt(.all), page.status });
        return error.RequestFailed;
    }

    return w.toOwnedSlice();
}

fn usage(comptime errstr: ?[]const u8, w: *Writer) noreturn {
    const string: []const u8 = (if (errstr) |err| err else "error: you're holding it wrong") ++
        \\
        \\Usage: {s} <ANS String>
        \\
        \\Options:
        \\
        \\    --db      <filename>          <filename> will be used to load/store cached ANS data
        \\    --host    <domain.name>       Use this host instead of the default
        \\
    ;
    w.print(string, .{arg0}) catch unreachable;
    std.process.exit(1);
}

test "bquery" {
    _ = std.testing.refAllDecls(@This());
}

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;
const Writer = std.Io.Writer;
const log = std.log;
const indexOf = std.mem.indexOf;
const startsWith = std.mem.startsWith;
const eql = std.mem.eql;
const cutPrefix = std.mem.cutPrefix;
const trim = std.mem.trim;
const builtin = @import("builtin");
