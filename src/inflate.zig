const std = @import("std");
const parse_arguments = @import("argparse.zig").parse_arguments;

var stdout: @TypeOf(std.io.getStdOut().writer()) = undefined;
var allocator: std.mem.Allocator = undefined;

var args: struct {
    total_iterations: usize = 10_000_000,
    buffer_size: usize = 128,

    const Self = @This();

    pub fn init() !Self {
        return try parse_arguments(Self, allocator, stdout);
    }
} = undefined;

fn loop() !void {
    const iterations = args.total_iterations;

    var random = random: {
        var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        var chacha = std.Random.ChaCha.init(seed);
        break :random chacha.random();
    };

    const in_buffer = try allocator.alloc(u8, args.buffer_size);
    defer allocator.free(in_buffer);
    const out_buffer = try allocator.alloc(u8, args.buffer_size * 1024);
    defer allocator.free(out_buffer);
    var in_stream = std.io.fixedBufferStream(in_buffer);
    var out_stream = std.io.fixedBufferStream(out_buffer);

    const errors = comptime errors: {
        const error_set = @typeInfo(
            @typeInfo(
                @TypeOf(std.compress.flate.inflate.decompress(
                    .raw,
                    in_stream.reader(),
                    out_stream.writer(),
                )),
            ).error_union.error_set,
        ).error_set.?;
        const num_errors = error_set.len;
        var result: [num_errors]anyerror = undefined;
        for (error_set, 0..) |err, i| {
            result[i] = @field(anyerror, err.name);
        }
        break :errors result;
    };
    var counts = [_]usize{0} ** errors.len;

    for (0..iterations) |_| {
        random.bytes(in_buffer);

        // in_buffer[0] &= 0b11111000;
        // in_buffer[0] |= 0b00000011;

        in_stream.seekTo(0) catch unreachable;
        out_stream.seekTo(0) catch unreachable;
        if (std.compress.flate.inflate.decompress(
            .raw,
            in_stream.reader(),
            out_stream.writer(),
        )) {
            // inflate_count += 1;
        } else |e| {
            const i = i: inline for (errors, 0..) |err, i| {
                if (@intFromError(err) == @intFromError(e)) break :i i;
            } else unreachable;
            counts[i] += 1;
        }
    }

    std.debug.print("Error,Count\r\n", .{});
    for (errors, counts) |e, c| {
        std.debug.print("{s},{d}\r\n", .{ @errorName(e), c });
    }
}

pub fn main() !void {
    stdout = std.io.getStdOut().writer();
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer std.debug.assert(gpa.deinit() != .leak);
    allocator = gpa.allocator();
    args = @TypeOf(args).init() catch |err| switch (err) {
        error.Help => return,
        else => return err,
    };

    try loop();
}
