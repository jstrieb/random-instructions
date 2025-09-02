const std = @import("std");

var stdout = std.io.getStdOut().writer();

pub fn main() !void {
    try stdout.print("Testing!\n", .{});
}
