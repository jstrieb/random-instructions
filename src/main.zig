const std = @import("std");
const capstone = @cImport({
    @cInclude("capstone/capstone.h");
});

var stdout = std.io.getStdOut().writer();
const total_iterations: usize = 10_000_000;

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

        try stdout.print("{d:>10} Total\n", .{total_iterations});
        try stdout.print("{d:>10} Disassembled\n", .{self.disasm_count});
        try stdout.print("{d:>10} Inflated\n", .{self.inflate_count});
        try stdout.print("{d:>10} Inflated then disassembled\n", .{self.inflate_disasm_count});
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
            return .{ .engine = engine };
        }

        pub fn deinit(self: *Self) void {
            _ = capstone.cs_close(&self.engine);
        }

        pub fn disassemble(self: Self, b: []const u8) bool {
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
            return count > 0;
        }
    };
}

test "basic disassembly" {
    var cs: Capstone(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB) = try .init();
    defer cs.deinit();

    try std.testing.expect(cs.disassemble("\xe0\xf9\x4f\x07"));
    try std.testing.expect(cs.disassemble("\x00\x00"));
    try std.testing.expect(!cs.disassemble("\x00"));
}

fn loop(iterations: usize) !void {
    var cs: Capstone(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB) = try .init();
    defer cs.deinit();

    var random = random: {
        var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        var chacha = std.Random.ChaCha.init(seed);
        break :random chacha.random();
    };

    var in_buffer: [128]u8 = undefined;
    var out_buffer: [64 * 1024]u8 = undefined;
    var in_stream = std.io.fixedBufferStream(&in_buffer);
    var out_stream = std.io.fixedBufferStream(&out_buffer);

    var disasm_count: u64 = 0;
    var inflate_count: u64 = 0;
    var inflate_disasm_count: u64 = 0;

    for (0..iterations) |_| {
        random.bytes(&in_buffer);
        if (cs.disassemble(&in_buffer)) {
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
            if (cs.disassemble(out_buffer[0..end])) {
                inflate_disasm_count += 1;
            }
        } else |_| {}
    }

    results.update(disasm_count, inflate_count, inflate_disasm_count);
}

pub fn main() !void {
    const thread_count = @min(std.Thread.getCpuCount() catch 1, 1024);
    var thread_buffer: [1024]std.Thread = undefined;
    const threads = thread_buffer[0..thread_count];
    const iterations = total_iterations / thread_count;
    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, loop, .{iterations});
    }
    for (threads) |t| {
        t.join();
    }
    try results.print();
}
