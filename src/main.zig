const std = @import("std");
const capstone = @cImport({
    @cInclude("capstone/capstone.h");
});

var stdout = std.io.getStdOut().writer();
var allocator: std.mem.Allocator = undefined;

var args: struct {
    total_iterations: usize = 10_000_000,
    buffer_size: usize = 128,
    disassembly_threshold: usize = 90,
    csv: bool = false,

    const Self = @This();

    pub fn init() !Self {
        var result = Self{};
        const all_args = try std.process.argsAlloc(allocator);
        defer std.process.argsFree(allocator, all_args);
        var i: usize = 1;
        while (i < all_args.len) : (i += 1) {
            const arg = all_args[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                try stdout.print("Usage: {s} [options]\n\n", .{all_args[0]});
                try stdout.print("Options:\n", .{});
                inline for (@typeInfo(Self).@"struct".fields) |field| {
                    const flag = try allocator.dupe(u8, field.name);
                    defer allocator.free(flag);
                    std.mem.replaceScalar(u8, flag, '_', '-');
                    switch (field.type) {
                        bool => try stdout.print("  --{s}\n", .{flag}),
                        usize => try stdout.print(
                            "  --{s} N\t\t(default {?any})\n",
                            .{ flag, field.defaultValue() },
                        ),
                        else => unreachable,
                    }
                }
                return error.Help;
            }
            if (!std.mem.startsWith(u8, arg, "--")) {
                continue;
            }
            std.mem.replaceScalar(u8, arg, '-', '_');
            inline for (@typeInfo(Self).@"struct".fields) |field| {
                if (std.mem.eql(u8, arg[2..], field.name)) {
                    switch (field.type) {
                        bool => @field(result, field.name) = true,
                        usize => {
                            @field(result, field.name) =
                                try std.fmt.parseUnsigned(usize, all_args[i + 1], 0);
                            i += 1;
                        },
                        else => unreachable,
                    }
                }
            }
        }
        return result;
    }
} = .{};

var results: struct {
    disasm_count: u64 = 0,
    inflate_count: u64 = 0,
    inflate_disasm_count: u64 = 0,
    lock: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn update(self: *Self, disasm_count: u64, inflate_count: u64, inflate_disasm_count: u64) void {
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
            try stdout.print("Type,Count\r\n", .{});
            try stdout.print("Total,{d}\r\n", .{args.total_iterations});
            try stdout.print("Disassembled,{d}\r\n", .{self.disasm_count});
            try stdout.print("Inflated,{d}\r\n", .{self.inflate_count});
            try stdout.print("Both,{d}\r\n", .{self.inflate_disasm_count});
        } else {
            try stdout.print("{d:>10} Total\n", .{args.total_iterations});
            try stdout.print("{d:>10} Disassembled\n", .{self.disasm_count});
            try stdout.print("{d:>10} Inflated\n", .{self.inflate_count});
            try stdout.print(
                "{d:>10} Inflated then disassembled\n",
                .{self.inflate_disasm_count},
            );
        }
    }
} = .{};

fn Capstone(arch: capstone.cs_arch, mode: c_int) type {
    return struct {
        engine: capstone.csh,
        const Self = @This();

        pub fn init() !Self {
            var engine: capstone.csh = undefined;
            if (capstone.cs_open(arch, mode, &engine) != capstone.CS_ERR_OK) {
                return error.CapstoneInitFailed;
            }
            if (capstone.cs_option(
                engine,
                capstone.CS_OPT_SKIPDATA,
                capstone.CS_OPT_ON,
            ) != capstone.CS_ERR_OK) {
                return error.CapstoneInitFailed;
            }
            return .{ .engine = engine };
        }

        pub fn deinit(self: *Self) void {
            _ = capstone.cs_close(&self.engine);
        }

        pub fn disassemble(self: Self, b: []const u8) usize {
            if (b.len == 0) return 0;
            var instructions: [*c]capstone.cs_insn = undefined;
            const count = capstone.cs_disasm(
                self.engine,
                @ptrCast(b),
                b.len,
                0,
                0,
                &instructions,
            );
            defer capstone.cs_free(instructions, count);
            var instruction_bytes: usize = 0;
            for (instructions, 0..count) |i, _| {
                if (i.id != 0) {
                    instruction_bytes += i.size;
                }
            }
            return 100 * instruction_bytes / b.len;
        }
    };
}

test "basic disassembly" {
    var cs: Capstone(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB) = try .init();
    defer cs.deinit();

    try std.testing.expectEqual(100, cs.disassemble("\xe0\xf9\x4f\x07"));
    try std.testing.expectEqual(100, cs.disassemble("\x00\x00"));
    try std.testing.expectEqual(0, cs.disassemble("\x00"));
    try std.testing.expectEqual(50, cs.disassemble("\xff\xff\x00\x00"));
    try std.testing.expectEqual(50, cs.disassemble("\x00\x00\xff\xff\xff\xff\x00\x00"));
}

fn loop(iterations: usize, buffer_size: usize) !void {
    var cs: Capstone(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB) = try .init();
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

    results.update(disasm_count, inflate_count, inflate_disasm_count);
}

pub fn main() !void {
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
                iterations +
                    if (i < args.total_iterations % thread_count)
                        @as(usize, 1)
                    else
                        @as(usize, 0),
                args.buffer_size,
            },
        );
    }
    for (threads) |t| {
        t.join();
    }
    try results.print();
}
