pub const rules: []const Detection = &[_]Detection{
    .rule("/.env HTTP/", .{}),
    .rule("PHP/eval-stdin.php HTTP/1.", .{}),
    .rule("../../etc/passwd HTTP/1", .{}),
    .prefix("GET /", &.{
        .rule("GET /.git/config ", .{}),
        .rule("GET /config.json HTTP/", .{}),
        .rule("GET /_all_dbs HTTP/", .{}),
        .rule("GET /.DS_Store HTTP/", .{}),
        .rule("GET /.env HTTP/", .{}),
        .rule("GET /app/.env HTTP/", .{}),
        .rule("GET /dev/.env HTTP/", .{}),
        .rule("GET /docker/.env HTTP/", .{}),
        .rule("GET /.git/config HTTP/", .{}),
        .rule("GET /.git/HEAD HTTP/", .{}),
        .rule("GET /.aws/config HTTP", .{}),
        .rule("GET /.aws/credentials HTTP", .{}),
        .rule("GET /.vscode/sftp.json HTTP/", .{}),
        .rule("GET /info.php HTTP/1.1\" 40", .{}),
        .rule("GET /phpinfo.php HTTP/1.1\" 40", .{}),
        .rule("GET /config/default.json HTTP", .{}),
        .rule("GET /app/config.json HTTP", .{}),
        .rule("GET /aws/config.json HTTP", .{}),
        .rule("GET /keys/config.json HTTP", .{}),
        .rule("GET /s3/config.json HTTP", .{}),
        .rule("GET /database.sql HTTP/", .{}),
        .rule("GET /.well-known/.well-known/ HTTP/", .{}),
        .rule("GET /.wp-cli/autoload_classmap.php HTTP/1", .{}),
        .rule("GET /1.php HTTP/1.1\" 404", .{}),
        .rule("GET /admin.php HTTP/1.1\" 404", .{}),
        .rule("GET /autoload_classmap.php HTTP/1", .{}),
        .rule("GET /wp-admin/css/colors/autoload_classmap.php HTTP/1", .{}),
    }, .{}),

    .rule("\"PROPFIND / HTTP", .{ .heat = 32, .ban_time = 7 * 86400 }),
    .rule("GET /db.php HTTP/1.1", .{ .heat = 32, .ban_time = 7 * 86400 }),
    .rule(
        \\.php HTTP/1.1" 404 146 "-" "-" "-"
    , .{ .heat = 32, .ban_time = 7 * 86400 }),

    .prefix("GET /", &.{.rule("/.ssh/id_rsa", .{})}, .{}),
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

pub const trusted_rules: []const Detection = &.{};

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
