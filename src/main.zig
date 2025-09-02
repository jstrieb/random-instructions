const std = @import("std");
const capstone = @cImport({
    @cInclude("capstone/capstone.h");
});

var stdout = std.io.getStdOut().writer();

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

pub fn main() !void {
    try stdout.print("Testing!\n", .{});
}
