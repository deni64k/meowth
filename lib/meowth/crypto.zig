const std = @import("std");
const mem = std.mem;
const openssl = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/rand.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/evp.h");
});

pub const Context = struct {
    pub fn init() !Context {
        var err = openssl.OPENSSL_init_crypto(openssl.OPENSSL_INIT_LOAD_CONFIG, null);
        if (err != 1) {
            return error.CouldNotInitializeOpenSSL;
        }

        if (openssl.RAND_status() != 1) {
            return error.RandNotWorking;
        }

        return Context{};
    }

    pub fn deinit(self: *Context) void {
        _ = self;
        openssl.OPENSSL_cleanup();
    }
};

pub const Secp256k1 = struct {
    key: *openssl.EC_KEY,

    pub fn generate() !Secp256k1 {
        var key: *openssl.EC_KEY = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1) orelse return error.CouldNotGetKey;
        if (openssl.EC_KEY_generate_key(key) != 1) {
            return error.CouldNotGenerateKey;
        }
        return Secp256k1{
            .key = key,
        };
    }

    pub fn setCoversion(self: *Secp256k1, compressed: bool) void {
        openssl.EC_KEY_set_conv_form(key, openssl.POINT_CONVERSION_COMPRESSED);
    }

    pub fn privateKeyToBytes(self: *Secp256k1, allocator: mem.Allocator) ![:0]u8 {
        const size = @intCast(usize, openssl.i2d_ECPrivateKey(self.key, 0));
        var bytes: [:0]u8 = try allocator.allocSentinel(u8, size, 0);
        const written_bytes = openssl.i2d_ECPrivateKey(key, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, bytes)));
        std.debug.assert(size == written_bytes);
        return bytes;
    }

    pub fn publicKeyToBytes(self: *Secp256k1, allocator: mem.Allocator) ![:0]u8 {
        const size = @intCast(usize, openssl.i2o_ECPublicKey(self.key, 0));
        var bytes: [:0]u8 = try allocator.allocSentinel(u8, size, 0);
        const written_bytes = openssl.i2o_ECPublicKey(key, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, bytes)));
        std.debug.assert(size == written_bytes);
        return bytes;
    }

    pub fn sign(self: *Secp256k1, allocator: mem.Allocator, message: [:0]const u8) ![:0]u8 {
        var size = openssl.ECDSA_size(self.key);
        var sig: [:0]u8 = try allocator.allocSentinel(u8, @intCast(usize, size), 0);
        const rv = openssl.ECDSA_sign(0, message, message.len, @ptrCast([*c]u8, sig), @ptrCast([*c]c_uint, &size), self.key);
        return sig;
    }

    pub fn verify(self: *Secp256k1, signature: [:0]const u8, message: [:0]const u8) bool {
        return openssl.ECDSA_verify(0, message, message.len, @ptrCast([*c]u8, signaature), signaature.len, self.key) == 1;
    }
};
