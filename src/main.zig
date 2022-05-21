const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

const meowth = @import("meowth");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ctx = try meowth.crypto.Context.init();
    defer ctx.deinit();

    // TODO: Load the local node key from a file.
    var local = try meowth.crypto.Secp256k1.generate();
    defer local.deinit();
    _ = local;
    local.setConversion(false);

    {
        var remote = try meowth.crypto.Secp256k1.generate();
        defer remote.deinit();

        {
            const plaintext = "I am Alice!";
            std.debug.print("\t*** ECIES Alice ***\n", .{});

            var encrypted = try meowth.crypto.Ecies.encrypt(allocator, remote, plaintext);
            defer allocator.free(encrypted);
            std.debug.print("{x}\n", .{std.fmt.fmtSliceHexLower(encrypted)});

            std.debug.print("\t*** ECIES Bob ***\n", .{});
            var decrypted = try meowth.crypto.Ecies.decrypt(allocator, remote, encrypted);
            defer allocator.free(decrypted);
            std.debug.print("{s}\n", .{decrypted});
        }
    }

    return;
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
