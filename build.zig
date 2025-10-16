const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });
    const static = (b.option(
        bool,
        "static",
        "Whether to link statically instead of dynamically",
    ) orelse false) or target.result.isMuslLibC();
    const force_rebuild_capstone = b.option(
        bool,
        "rebuild-capstone",
        "Whether to force rebuilding libcapstone",
    ) orelse false;

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const exe = b.addExecutable(.{
        .name = try std.mem.concat(b.allocator, u8, &[_][]const u8{
            "random_instructions",
            if (static) "_static" else "",
        }),
        .root_module = exe_mod,
        .linkage = if (static) .static else null,
    });

    // Build Capstone
    const capstone_dep = b.dependency("capstone", .{});
    // Note: this will fail if non-native Capstone is built first
    const libcapstone_exists =
        if (capstone_dep.path("").getPath3(b, null).access("libcapstone.a", .{}))
            true
        else |_|
            false;
    if (force_rebuild_capstone or !target.query.isNative() or !libcapstone_exists) {
        const capstone_clean = b.addSystemCommand(&.{
            "make", "clean", "-j",
        });
        capstone_clean.setCwd(capstone_dep.path(""));
        const target_triple = try target.result.zigTriple(b.allocator);
        const capstone_make = b.addSystemCommand(&.{
            "make",
            "-j",
            "CAPSTONE_BUILD_CORE_ONLY=yes",
            "CAPSTONE_STATIC=yes",
            "CAPSTONE_SHARED=no",
            "RANLIB=zig ranlib",
            "AR=zig ar",
            try std.fmt.allocPrint(
                b.allocator,
                "CC=zig cc -target {s}",
                .{target_triple},
            ),
            try std.fmt.allocPrint(
                b.allocator,
                "CXX=zig c++ -target {s}",
                .{target_triple},
            ),
            if (target.result.os.tag == .macos)
                try std.fmt.allocPrint(
                    b.allocator,
                    "LIBARCHS={s}",
                    .{@tagName(target.result.cpu.arch)},
                )
            else
                "LIBARCHS=",
        });
        capstone_make.step.dependOn(&capstone_clean.step);
        capstone_make.setCwd(capstone_dep.path(""));
        exe.step.dependOn(&capstone_make.step);
    }

    // Add the Capstone lib and include directories so we can import capstone.h
    // and link against the Capstone shared object or DLL
    exe.linkLibC();
    exe.addLibraryPath(capstone_dep.path(""));
    exe.linkSystemLibrary2("capstone", .{
        .needed = true,
        .preferred_link_mode = .static,
        // Prevent it from using the version of Capstone in /usr/lib
        .use_pkg_config = .no,
    });
    exe.addIncludePath(capstone_dep.path("include"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{ .root_module = exe_mod });
    const run_tests = b.addRunArtifact(exe_tests);
    run_tests.step.dependOn(b.getInstallStep());
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
