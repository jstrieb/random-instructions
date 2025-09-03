const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const exe = b.addExecutable(.{
        .name = "random_instructions",
        .root_module = exe_mod,
    });

    // Build Capstone
    const capstone_dep = b.dependency("capstone", .{});
    const capstone_cmake = b.addSystemCommand(&.{
        "cmake",
        "-B",
        "build",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_SHARED_LIBS=1",
    });
    capstone_cmake.setCwd(capstone_dep.path(""));
    const capstone_make = b.addSystemCommand(&.{ "cmake", "--build", "build" });
    capstone_make.setCwd(capstone_dep.path(""));
    capstone_make.step.dependOn(&capstone_cmake.step);
    exe.step.dependOn(&capstone_make.step);

    // Add the Capstone lib and include directories so we can import capstone.h
    // and link against the Capstone shared object or DLL
    exe.addLibraryPath(capstone_dep.path("build"));
    exe.linkSystemLibrary("capstone");
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
