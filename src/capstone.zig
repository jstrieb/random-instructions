const std = @import("std");
pub const capstone = @cImport({
    @cInclude("capstone/capstone.h");
});

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

test "basic disassembly" {
    var cs: Self = try .init(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB);
    defer cs.deinit();

    try std.testing.expectEqual(100, cs.disassemble("\xe0\xf9\x4f\x07"));
    try std.testing.expectEqual(100, cs.disassemble("\x00\x00"));
    try std.testing.expectEqual(0, cs.disassemble("\x00"));
    try std.testing.expectEqual(50, cs.disassemble("\xff\xff\x00\x00"));
    try std.testing.expectEqual(50, cs.disassemble("\x00\x00\xff\xff\xff\xff\x00\x00"));
}

pub const Arch = struct {
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

pub const all_architectures = architectures: {
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
