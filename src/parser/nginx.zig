pub const rules: []const Detection = &[_]Detection{
    .{ .hit = "/.env HTTP/" },
    .{ .hit = "GET /.git/config " },
    .{ .hit = "PHP/eval-stdin.php HTTP/1." },
    .{ .hit = "GET /config.json HTTP/" },
    .{ .hit = "GET /_all_dbs HTTP/" },
    .{ .hit = "GET /.DS_Store HTTP/" },
    .{ .hit = "GET /.env HTTP/" },
    .{ .hit = "GET /.git/config HTTP/" },
    .{ .hit = "GET /.git/HEAD HTTP/" },
    .{ .hit = "GET /.aws/config HTTP" },
    .{ .hit = "GET /.aws/credentials HTTP" },
    .{ .hit = "GET /.vscode/sftp.json HTTP/" },
    .{ .hit = "GET /info.php HTTP/1.1\" 40" },
};

pub const rules_extra: []const Detection = &[_]Detection{
    .{ .hit = "GET /@vite/env HTTP/" },
    .{ .hit = "GET /actuator/env HTTP/" },
    .{ .hit = "GET /debug/default/view?panel=config HTTP/" },
    .{ .hit = "GET /v2/_catalog HTTP/" },
    .{ .hit = "GET /ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application HTTP/" },
    .{ .hit = "GET /server-status HTTP/" },
    .{ .hit = "/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties HTTP/" },
    .{ .hit = "GET /telescope/requests HTTP/" },
    .{ .hit = "GET /?rest_route=/wp/v2/users/ HTTP/" },
};

pub fn filter(line: []const u8) bool {
    var dots: usize = 0;
    var idx: usize = 0;
    while (dots <= 3 and idx <= line.len) : (idx += 1) {
        switch (line[idx]) {
            '0'...'9' => continue,
            '.' => dots += 1,
            else => break,
        }
    }

    return line[idx] == ' ' and dots == 3;
}

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

pub fn parseLine(line: []const u8) !?Event {
    return .{
        .src_addr = parseAddr(line) catch return null,
        .timestamp = try parseTime(line),
        .extra = try parseExtra(line),
    };
}

const std = @import("std");
const indexOfScalar = std.mem.indexOfScalar;
const Addr = @import("../main.zig").Addr;
const Event = @import("../Event.zig");
const Detection = @import("../Detection.zig");
