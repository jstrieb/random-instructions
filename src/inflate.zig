const std = @import("std");
const parse_arguments = @import("argparse.zig").parse_arguments;

var stdout: @TypeOf(std.io.getStdOut().writer()) = undefined;
var allocator: std.mem.Allocator = undefined;

var args: struct {
    total_iterations: usize = 10_000_000,
    buffer_size: usize = 128,
    no_csv_header: bool = false,
    first_bits: ?u8 = null,
    num_bits: ?u3 = null,

    const Self = @This();

    pub fn init() !Self {
        return try parse_arguments(Self, allocator, stdout);
    }
} = undefined;

const errors = errors: {
    const error_set = @typeInfo(
        @typeInfo(
            @TypeOf(result: {
                var in_stream = std.io.fixedBufferStream(&[_]u8{});
                break :result std.compress.flate.inflate.decompress(
                    .raw,
                    in_stream.reader(),
                    std.io.NullWriter{ .context = {} },
                );
            }),
        ).error_union.error_set,
    ).error_set.?;
    const num_errors = error_set.len;
    var result: [num_errors]anyerror = undefined;
    for (error_set, 0..) |err, i| {
        result[i] = @field(anyerror, err.name);
    }
    break :errors result;
};

var results: struct {
    counts: [errors.len]usize = [_]usize{0} ** errors.len,
    successes: usize = 0,
    lock: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn update(
        self: *Self,
        new_counts: @TypeOf(self.counts),
        successes: usize,
    ) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.successes += successes;
        for (&self.counts, new_counts) |*old, new| {
            old.* += new;
        }
    }

    pub fn print(self: *Self, bits: ?u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        if (!args.no_csv_header) {
            try stdout.print("Error,Count,Bits\r\n", .{});
        }
        for (errors, self.counts) |e, c| {
            try stdout.print("{s},{d},{?d}\r\n", .{ @errorName(e), c, bits });
        }
        try stdout.print("Success,{d},{?d}\r\n", .{ self.successes, bits });
    }
} = .{};

fn loop(iterations: usize, first_bits: ?u8, num_bits: ?u3) !void {
    var random = random: {
        var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        var chacha = std.Random.ChaCha.init(seed);
        break :random chacha.random();
    };

    const in_buffer = try allocator.alloc(u8, args.buffer_size);
    defer allocator.free(in_buffer);
    var in_stream = std.io.fixedBufferStream(in_buffer);

    var inflate_count: usize = 0;
    var counts = [_]usize{0} ** errors.len;

    const and_mask = @as(u8, 0b1111_1111) << (num_bits orelse 0);
    const or_mask = (@as(u8, 0b1) << (num_bits orelse 0)) - 1;

    for (0..iterations) |_| {
        random.bytes(in_buffer);

        if (first_bits) |bits| {
            in_buffer[0] &= and_mask;
            in_buffer[0] |= (bits & or_mask);
        }

        in_stream.seekTo(0) catch unreachable;
        if (std.compress.flate.inflate.decompress(
            .raw,
            in_stream.reader(),
            std.io.NullWriter{ .context = {} },
        )) {
            inflate_count += 1;
        } else |e| {
            const i = i: inline for (errors, 0..) |err, i| {
                if (err == e) break :i i;
            } else unreachable;
            counts[i] += 1;
        }
    }

    results.update(counts, inflate_count);
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

    const thread_count = @min(std.Thread.getCpuCount() catch 1, 1024);
    var thread_buffer: [1024]std.Thread = undefined;
    const threads = thread_buffer[0..thread_count];
    const iterations = args.total_iterations / thread_count;

    for (threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(
            .{},
            loop,
            .{
                iterations + @as(
                    usize,
                    (if (i < args.total_iterations % thread_count) 1 else 0),
                ),
                args.first_bits,
                args.num_bits,
            },
        );
    }
    for (threads) |t| {
        t.join();
    }
    try results.print(args.first_bits);
}
