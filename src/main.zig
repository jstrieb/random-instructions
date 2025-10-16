const std = @import("std");
const parse_arguments = @import("argparse.zig").parse_arguments;
const Capstone = @import("capstone.zig");
const capstone_c = Capstone.capstone;

var stdout: @TypeOf(std.io.getStdOut().writer()) = undefined;
var allocator: std.mem.Allocator = undefined;

var args: struct {
    total_iterations: usize = 10_000_000,
    buffer_size: usize = 128,
    disassembly_threshold: usize = 90,
    csv: bool = false,
    no_csv_header: bool = false,
    all_architectures: bool = false,

    const Self = @This();

    pub fn init() !Self {
        return try parse_arguments(Self, allocator, stdout);
    }
} = undefined;

var results: struct {
    disasm_count: u64 = 0,
    inflate_count: u64 = 0,
    inflate_disasm_count: u64 = 0,
    lock: std.Thread.Mutex = .{},
    err: ?anyerror = null,
    architecture: []const u8,

    const Self = @This();

    pub fn update(
        self: *Self,
        disasm_count: u64,
        inflate_count: u64,
        inflate_disasm_count: u64,
    ) void {
        self.lock.lock();
        defer self.lock.unlock();

        self.disasm_count += disasm_count;
        self.inflate_count += inflate_count;
        self.inflate_disasm_count += inflate_disasm_count;
    }

    fn print(self: *Self) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (args.csv) {
            if (!args.no_csv_header) {
                try stdout.print("Type,Count,Size,Threshold,Architecture,Mode\r\n", .{});
            }
            try stdout.print("Total,{d},{d},{d},{s}\r\n", .{
                args.total_iterations,
                args.buffer_size,
                args.disassembly_threshold,
                self.architecture,
            });
            try stdout.print("Disassembled,{d},{d},{d},{s}\r\n", .{
                self.disasm_count,
                args.buffer_size,
                args.disassembly_threshold,
                self.architecture,
            });
            try stdout.print("Inflated,{d},{d},{d},{s}\r\n", .{
                self.inflate_count,
                args.buffer_size,
                args.disassembly_threshold,
                self.architecture,
            });
            try stdout.print("Both,{d},{d},{d},{s}\r\n", .{
                self.inflate_disasm_count,
                args.buffer_size,
                args.disassembly_threshold,
                self.architecture,
            });
        } else {
            try stdout.print("{s}\n", .{self.architecture});
            try stdout.print("{d:>10} Total\n", .{args.total_iterations});
            try stdout.print("{d:>10} Disassembled\n", .{self.disasm_count});
            try stdout.print("{d:>10} Inflated\n", .{self.inflate_count});
            try stdout.print(
                "{d:>10} Inflated then disassembled\n",
                .{self.inflate_disasm_count},
            );
        }
    }
} = undefined;

fn loop(arch: Capstone.Arch, iterations: usize, buffer_size: usize) !void {
    var cs: Capstone = undefined;
    cs = Capstone.init(arch.arch, arch.mode) catch |err| {
        results.lock.lock();
        defer results.lock.unlock();
        results.err = err;
        return;
    };
    defer cs.deinit();

    var random = random: {
        var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        var chacha = std.Random.ChaCha.init(seed);
        break :random chacha.random();
    };

    const in_buffer = try allocator.alloc(u8, buffer_size);
    defer allocator.free(in_buffer);
    const out_buffer = try allocator.alloc(u8, buffer_size * 1024);
    defer allocator.free(out_buffer);
    var in_stream = std.io.fixedBufferStream(in_buffer);
    var out_stream = std.io.fixedBufferStream(out_buffer);

    var disasm_count: u64 = 0;
    var inflate_count: u64 = 0;
    var inflate_disasm_count: u64 = 0;

    for (0..iterations) |_| {
        random.bytes(in_buffer);
        if (cs.disassemble(in_buffer) >= args.disassembly_threshold) {
            disasm_count += 1;
        }

        if (arch.arch == capstone_c.CS_ARCH_ARM and arch.mode == capstone_c.CS_MODE_THUMB) {
            in_stream.seekTo(0) catch unreachable;
            out_stream.seekTo(0) catch unreachable;
            if (std.compress.flate.inflate.decompress(
                .raw,
                in_stream.reader(),
                out_stream.writer(),
            )) {
                inflate_count += 1;
                const end = out_stream.getPos() catch unreachable;
                if (cs.disassemble(out_buffer[0..end]) >= args.disassembly_threshold) {
                    inflate_disasm_count += 1;
                }
            } else |_| {}
        }
    }

    results.update(disasm_count, inflate_count, inflate_disasm_count);
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

    const arches: []const Capstone.Arch = if (args.all_architectures)
        &Capstone.all_architectures
    else
        &[_]Capstone.Arch{
            .{
                .arch = capstone_c.CS_ARCH_ARM,
                .mode = capstone_c.CS_MODE_THUMB,
                .name = "CS_ARCH_ARM,CS_MODE_THUMB",
            },
        };

    const thread_count = @min(std.Thread.getCpuCount() catch 1, 1024);
    var thread_buffer: [1024]std.Thread = undefined;
    const threads = thread_buffer[0..thread_count];
    const iterations = args.total_iterations / thread_count;
    arches: for (arches) |arch| {
        results = .{ .architecture = arch.name };
        for (threads, 0..) |*t, i| {
            t.* = try std.Thread.spawn(
                .{},
                loop,
                .{
                    arch,
                    iterations + @as(
                        usize,
                        (if (i < args.total_iterations % thread_count) 1 else 0),
                    ),
                    args.buffer_size,
                },
            );
        }
        for (threads) |t| {
            t.join();
        }
        if (results.err) |err| switch (err) {
            error.CapstoneInitFailed => continue :arches,
            else => return err,
        } else {}
        try results.print();
    }
}

test {
    std.testing.refAllDecls(@This());
}
