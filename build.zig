const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    _ = b.addPackage(std.build.Pkg{
        .name = "rlp",
        .path = "lib/rlp.zig",
    });

    _ = b.addPackage(std.build.Pkg{
        .name = "zig-string",
        .path = "vendor/zig-string-288ab2f/zig-string.zig",
    });
}
