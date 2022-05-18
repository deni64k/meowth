const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const openssl = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/rand.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/evp.h");
});

const meowth = @import("meowth");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ctx = meowth.crypto.Context.init() catch unreachable;
    defer ctx.deinit();

    var key: *openssl.EC_KEY = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1) orelse return error.CouldNotGetKey;
    if (openssl.EC_KEY_generate_key(key) != 1) {
        return error.CouldNotGenerateKey;
    }

    std.debug.print("key={any}\n", .{key});

    openssl.EC_KEY_set_conv_form(key, openssl.POINT_CONVERSION_COMPRESSED);

    {
        const pri_size = @intCast(usize, openssl.i2d_ECPrivateKey(key, 0));
        var pri: [:0]u8 = try allocator.allocSentinel(u8, pri_size, 0);
        defer allocator.free(pri);
        const pri_n = openssl.i2d_ECPrivateKey(key, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, pri)));

        std.debug.assert(pri_size == pri_n);
        std.debug.print("pri_size={d}\n", .{pri_size});
        std.debug.print("pri_n={d}\n", .{pri_n});
        std.debug.print("pri={any}\n", .{pri});
    }

    {
        const pubkey_size = @intCast(usize, openssl.i2o_ECPublicKey(key, 0));
        var pubkey: [:0]u8 = try allocator.allocSentinel(u8, pubkey_size, 0);
        defer allocator.free(pubkey);
        const pubkey_n = openssl.i2o_ECPublicKey(key, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, pubkey)));

        std.debug.assert(pubkey_size == pubkey_n);
        std.debug.print("pubkey_size={d}\n", .{pubkey_size});
        std.debug.print("pubkey_n={d}\n", .{pubkey_n});
        std.debug.print("pubkey={any}\n", .{pubkey});
    }

    {
        const message = "Hello, Ethereum!";

        var sig_size = openssl.ECDSA_size(key);
        std.debug.print("sig_size={d}\n", .{sig_size});
        var sig: [:0]u8 = try allocator.allocSentinel(u8, @intCast(usize, sig_size), 0);
        defer allocator.free(sig);
        const rv = openssl.ECDSA_sign(0, message, message.len, @ptrCast([*c]u8, sig), @ptrCast([*c]c_uint, &sig_size), key);

        std.debug.assert(rv == 1);
        std.debug.print("sig_size={d}\n", .{sig_size});
        std.debug.print("sig={any}\n", .{sig});

        const verified = openssl.ECDSA_verify(0, message, message.len, @ptrCast([*c]u8, sig), sig_size, key);
        std.debug.print("verified={d}\n", .{verified});
    }

    // meowth.params.ropstenBootnodes;

    return;
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
