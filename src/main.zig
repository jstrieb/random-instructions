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
    no_csv_header: bool = false,
    all_architectures: bool = false,

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
                    switch (@typeInfo(field.type)) {
                        .bool => @field(result, field.name) = true,
                        .int => |t| {
                            @field(result, field.name) = switch (t.signedness) {
                                .unsigned => try std.fmt.parseUnsigned(
                                    field.type,
                                    all_args[i + 1],
                                    0,
                                ),
                                .signed => try std.fmt.parseSigned(
                                    field.type,
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
} = .{};

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

const Capstone = struct {
    engine: capstone.csh,
    const Self = @This();

    pub fn init(arch: capstone.cs_arch, mode: c_uint) !Self {
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

test "basic disassembly" {
    var cs: Capstone = try .init(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB);
    defer cs.deinit();

    try std.testing.expectEqual(100, cs.disassemble("\xe0\xf9\x4f\x07"));
    try std.testing.expectEqual(100, cs.disassemble("\x00\x00"));
    try std.testing.expectEqual(0, cs.disassemble("\x00"));
    try std.testing.expectEqual(50, cs.disassemble("\xff\xff\x00\x00"));
    try std.testing.expectEqual(50, cs.disassemble("\x00\x00\xff\xff\xff\xff\x00\x00"));
}

const Arch = struct {
    arch: capstone.cs_arch,
    mode: capstone.cs_mode,
    name: [:0]const u8,
};

const num_architectures: usize = num_architectures: {
    var result: usize = 0;
    @setEvalBranchQuota(1_000_000);
    for (@typeInfo(capstone).@"struct".decls) |decl| {
        if (std.mem.startsWith(u8, decl.name, "CS_ARCH_")) {
            result += 1;
        }
    }
    break :num_architectures result;
};

const modes: [num_architectures][]const []const u8 = modes: {
    var result: [num_architectures][]const []const u8 =
        .{&[_][]const u8{}} ** num_architectures;
    result[capstone.CS_ARCH_ARM] = &[_][]const u8{
        "CS_MODE_ARM",
        "CS_MODE_THUMB",
        "CS_MODE_MCLASS",
        "CS_MODE_V8",
    };
    result[capstone.CS_ARCH_MIPS] = &[_][]const u8{
        "CS_MODE_32",
        "CS_MODE_64",
    };
    result[capstone.CS_ARCH_X86] = &[_][]const u8{
        "CS_MODE_32",
        "CS_MODE_64",
    };
    result[capstone.CS_ARCH_PPC] = &[_][]const u8{
        "CS_MODE_32",
        "CS_MODE_64",
        "CS_MODE_QPX",
        "CS_MODE_PS",
    };
    result[capstone.CS_ARCH_SYSZ] = &[_][]const u8{
        "CS_MODE_LITTLE_ENDIAN",
    };
    result[capstone.CS_ARCH_XCORE] = &[_][]const u8{
        "CS_MODE_LITTLE_ENDIAN",
    };
    result[capstone.CS_ARCH_M68K] = &[_][]const u8{
        "CS_MODE_LITTLE_ENDIAN",
        "CS_MODE_M68K_000",
        "CS_MODE_M68K_010",
        "CS_MODE_M68K_020",
        "CS_MODE_M68K_030",
        "CS_MODE_M68K_040",
        "CS_MODE_M68K_060",
    };
    result[capstone.CS_ARCH_TMS320C64X] = &[_][]const u8{
        "CS_MODE_LITTLE_ENDIAN",
    };
    result[capstone.CS_ARCH_M680X] = &[_][]const u8{
        "CS_MODE_LITTLE_ENDIAN",
        "CS_MODE_M680X_6301",
        "CS_MODE_M680X_6309",
        "CS_MODE_M680X_6800",
        "CS_MODE_M680X_6801",
        "CS_MODE_M680X_6805",
        "CS_MODE_M680X_6808",
        "CS_MODE_M680X_6809",
        "CS_MODE_M680X_6811",
        "CS_MODE_M680X_CPU12",
        "CS_MODE_M680X_HCS08",
    };
    result[capstone.CS_ARCH_EVM] = &[_][]const u8{
        "CS_MODE_LITTLE_ENDIAN",
    };
    result[capstone.CS_ARCH_MOS65XX] = &[_][]const u8{
        "CS_MODE_MOS65XX_65C02",
        "CS_MODE_MOS65XX_W65C02",
        "CS_MODE_MOS65XX_65816",
        "CS_MODE_MOS65XX_65816_LONG_M",
        "CS_MODE_MOS65XX_65816_LONG_X",
        "CS_MODE_MOS65XX_65816_LONG_MX",
    };
    result[capstone.CS_ARCH_WASM] = &[_][]const u8{
        "CS_MODE_LITTLE_ENDIAN",
    };
    result[capstone.CS_ARCH_RISCV] = &[_][]const u8{
        "CS_MODE_RISCVC",
    };
    result[capstone.CS_ARCH_SH] = &[_][]const u8{
        "CS_MODE_SH2",
        "CS_MODE_SH3",
        "CS_MODE_SH4",
        "CS_MODE_SH4A",
        "CS_MODE_SHFPU",
        "CS_MODE_SHDSP",
    };
    result[capstone.CS_ARCH_TRICORE] = &[_][]const u8{
        "CS_MODE_TRICORE_120",
        "CS_MODE_TRICORE_160",
        "CS_MODE_TRICORE_161",
        "CS_MODE_TRICORE_162",
    };
    break :modes result;
};

const all_architectures = architectures: {
    var architectures: [
        num: {
            var result: usize = 0;
            for (modes) |mode| {
                result += mode.len;
            }
            break :num result;
        }
    ]Arch = undefined;
    var i: usize = 0;
    @setEvalBranchQuota(1_000_000);
    for (@typeInfo(capstone).@"struct".decls) |decl| {
        if (std.mem.startsWith(u8, decl.name, "CS_ARCH_")) {
            const arch = @field(capstone, decl.name);
            if (arch >= modes.len) continue;
            for (modes[arch]) |mode| {
                architectures[i] = Arch{
                    .arch = arch,
                    .mode = @field(capstone, mode),
                    .name = decl.name ++ "," ++ mode,
                };
                i += 1;
            }
        }
    }
    break :architectures architectures;
};

fn loop(arch: Arch, iterations: usize, buffer_size: usize) !void {
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

        if (arch.arch == capstone.CS_ARCH_ARM and arch.mode == capstone.CS_MODE_THUMB) {
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
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer std.debug.assert(gpa.deinit() != .leak);
    allocator = gpa.allocator();
    args = @TypeOf(args).init() catch |err| switch (err) {
        error.Help => return,
        else => return err,
    };

    const arches: []const Arch = if (args.all_architectures)
        &all_architectures
    else
        &[_]Arch{
            .{
                .arch = capstone.CS_ARCH_ARM,
                .mode = capstone.CS_MODE_THUMB,
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
        if (results.err) |err| switch (err) {
            error.CapstoneInitFailed => continue :arches,
            else => return err,
        } else {}
        try results.print();
    }
}
