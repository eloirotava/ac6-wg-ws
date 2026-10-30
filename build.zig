const std = @import("std");

// Padrao: Archer C5 v4 (MT7620A, MIPS 24KEc = mips32r2, sem FPU).
// Para testar no PC: zig build -Dtarget=native
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .arm,
            .os_tag = .linux,
            .abi = .musleabi,
            .cpu_model = .{ .explicit = &std.Target.arm.cpu.cortex_a7 },
        },
    });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const exe = b.addExecutable(.{
        .name = "wsudp",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = false,
        .unwind_tables = .none,
        .strip = optimize != .Debug,
    });
    b.installArtifact(exe);
}
