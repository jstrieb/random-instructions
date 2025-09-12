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

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const exe = b.addExecutable(.{
        .name = "random_instructions",
        .root_module = exe_mod,
        .linkage = if (static) .static else null,
    });

    // Build Capstone
    const capstone_dep = b.dependency("capstone", .{});
    const capstone_clean = b.addSystemCommand(&.{
        "make", "clean", "-j",
    });
    capstone_clean.setCwd(capstone_dep.path(""));
    const target_triple = try target.result.zigTriple(b.allocator);
    const build_dir = try std.fmt.allocPrint(
        b.allocator,
        "build-{s}",
        .{target_triple},
    );
    const capstone_cmake = b.addSystemCommand(&.{
        "cmake",
        "-DCMAKE_BUILD_TYPE=Release",
        try std.fmt.allocPrint(
            b.allocator,
            "-DBUILD_SHARED_LIBS={d}",
            .{if (static) @as(u32, 0) else @as(u32, 1)},
        ),
        try std.fmt.allocPrint(
            b.allocator,
            "-DBUILD_STATIC_LIBS={d}",
            .{if (static) @as(u32, 1) else @as(u32, 0)},
        ),
        "-DCAPSTONE_BUILD_TESTS=0",
        "-DCAPSTONE_BUILD_CSTEST=0",
        "-DCAPSTONE_BUILD_CSTOOL=0",
        "-B",
        build_dir,
    });
    capstone_cmake.step.dependOn(&capstone_clean.step);
    capstone_cmake.setEnvironmentVariable("CC", try std.fmt.allocPrint(
        b.allocator,
        "zig cc -target {s}",
        .{target_triple},
    ));
    capstone_cmake.setEnvironmentVariable("CXX", try std.fmt.allocPrint(
        b.allocator,
        "zig c++ -target {s}",
        .{target_triple},
    ));
    capstone_cmake.setCwd(capstone_dep.path(""));
    const capstone_make = b.addSystemCommand(&.{ "make", "-j" });
    capstone_make.setCwd(capstone_dep.path(build_dir));
    capstone_make.step.dependOn(&capstone_cmake.step);
    exe.step.dependOn(&capstone_make.step);

    // Add the Capstone lib and include directories so we can import capstone.h
    // and link against the Capstone shared object or DLL
    exe.linkLibC();
    exe.addLibraryPath(capstone_dep.path(build_dir));
    exe.linkSystemLibrary2("capstone", .{
        .needed = true,
        .preferred_link_mode = if (static) .static else .dynamic,
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
