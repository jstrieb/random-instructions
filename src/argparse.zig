const std = @import("std");

fn print_help(
    argv0: []const u8,
    T: type,
    allocator: std.mem.Allocator,
    stdout: @TypeOf(std.io.getStdOut().writer()),
) !void {
    try stdout.print("Usage: {s} [options]\n\n", .{argv0});
    try stdout.print("Options:\n", .{});
    inline for (@typeInfo(T).@"struct".fields) |field| {
        const flag = try allocator.dupe(u8, field.name);
        defer allocator.free(flag);
        std.mem.replaceScalar(u8, flag, '_', '-');
        switch (@typeInfo(strip_optional(field.type))) {
            .bool => try stdout.print("  --{s}\n", .{flag}),
            .int => try stdout.print(
                "  --{s} N\t\t(default {?any})\n",
                .{ flag, field.defaultValue() },
            ),
            else => unreachable,
        }
    }
}

fn strip_optional(T: type) type {
    const info = @typeInfo(T);
    if (info != .optional) return T;
    return strip_optional(info.optional.child);
}

pub fn parse_arguments(
    T: type,
    allocator: std.mem.Allocator,
    stdout: @TypeOf(std.io.getStdOut().writer()),
) !T {
    var result = T{};
    const all_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, all_args);
    var i: usize = 1;
    while (i < all_args.len) : (i += 1) {
        const arg = all_args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try print_help(all_args[0], T, allocator, stdout);
            return error.Help;
        }
        if (!std.mem.startsWith(u8, arg, "--")) {
            // TODO: Support short arguments
            continue;
        }
        std.mem.replaceScalar(u8, arg, '-', '_');
        inline for (@typeInfo(T).@"struct".fields) |field| {
            if (std.mem.eql(u8, arg[2..], field.name)) {
                switch (@typeInfo(strip_optional(field.type))) {
                    .bool => @field(result, field.name) = true,
                    .int => |t| {
                        @field(result, field.name) = switch (t.signedness) {
                            .unsigned => try std.fmt.parseUnsigned(
                                @Type(.{ .int = t }),
                                all_args[i + 1],
                                0,
                            ),
                            .signed => try std.fmt.parseSigned(
                                @Type(.{ .int = t }),
                                all_args[i + 1],
                                0,
                            ),
                        };
                        i += 1;
                    },
                    else => unreachable,
                }
            }
        }
    }
    return result;
}
