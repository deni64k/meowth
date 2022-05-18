const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const exe = b.addExecutable("meowth", "src/main.zig");
    exe.setBuildMode(mode);
    exe.setTarget(target);
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("c");
    exe.defineCMacro("OPENSSL_NO_FILENAMES", null);
    exe.addPackagePath("meowth", "lib/meowth.zig");
    exe.addPackagePath("zig-string", "vendor/zig-string-288ab2f/zig-string.zig");

    const install_exe = b.addInstallArtifact(exe);
    b.getInstallStep().dependOn(&install_exe.step);

    const run_step = std.build.RunStep.create(exe.builder, "Run meowth");
    run_step.addArtifactArg(exe);

    const step = b.step("run", "Runs the executable");
    step.dependOn(&run_step.step);

    const main_tests = b.addTest("src/main.zig");
    main_tests.linkSystemLibrary("crypto");
    main_tests.linkSystemLibrary("c");
    main_tests.defineCMacro("OPENSSL_NO_FILENAMES", null);
    main_tests.setBuildMode(mode);
    main_tests.addPackagePath("meowth", "lib/meowth.zig");
    main_tests.addPackagePath("zig-string", "vendor/zig-string-288ab2f/zig-string.zig");

    const lib_tests = b.addTest("lib/meowth.zig");
    lib_tests.linkSystemLibrary("crypto");
    lib_tests.linkSystemLibrary("c");
    lib_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
    test_step.dependOn(&lib_tests.step);
}
