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

    pub fn fromPublicKey(pubkey: []const u8) !Secp256k1 {
        var key: *openssl.EC_KEY = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1) orelse return error.CouldNotGetKey;
        // var group = openssl.EC_KEY_get0_group(key);
        // var point = openssl.EC_POINT_new(group);
        // defer openssl.EC_POINT_free(point);

        // var rv = openssl.EC_POINT_oct2point(group, point, pubkey, pubkey.len, 0);

        var rv: c_int = undefined;
        if (pubkey.len == 64) {
            var full_pubkey: [65:0]u8 = undefined;
            full_pubkey[0] = 0x04;
            std.mem.copy(u8, full_pubkey[1..], pubkey);
            rv = openssl.EC_KEY_oct2key(key, @ptrCast([*c]const u8, &full_pubkey), full_pubkey.len, null);
        } else {
            rv = openssl.EC_KEY_oct2key(key, @ptrCast([*c]const u8, &pubkey), pubkey.len, null);
        }
        // TODO: Return an error.
        std.debug.assert(rv == 1);

        // EC_KEY_set_public_key(key, point);

        return Secp256k1{
            .key = key,
        };
    }

    pub fn fromPrivateKey(pubkey: []u8) !Secp256k1 {
        var key: *openssl.EC_KEY = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1) orelse return error.CouldNotGetKey;
        // var group = openssl.EC_KEY_get0_group(key);
        // var point = openssl.EC_POINT_new(group);
        // defer openssl.EC_POINT_free(point);

        var rv = openssl.EC_KEY_oct2priv(key, pubkey, pubkey.len, 0);
        // TODO: Return an error.
        std.assert.debug(rv == 1);

        // EC_KEY_set_private_key(key, point);

        // TODO: Generate the public key?
        // https://cpp.hotexamples.com/site/file?hash=0xba6cf0166b4dedd3bf5be11f369304ad16db731f7fc0c0c7a5cb84fd58fc4de2&fullName=luajit-android-master/lua-openssl/src/pkey.c&project=houzhenggang/luajit-android

        return Secp256k1{
            .key = key,
        };
    }

    pub fn deinit(self: *Secp256k1) void {
        openssl.EC_KEY_free(self.key);
    }

    pub fn setCoversion(self: *Secp256k1, compressed: bool) void {
        openssl.EC_KEY_set_conv_form(self.key, if (compressed) openssl.POINT_CONVERSION_COMPRESSED else openssl.POINT_CONVERSION_UNCOMPRESSED);
    }

    pub fn privateKeyToBytes(self: *Secp256k1, allocator: mem.Allocator) ![:0]u8 {
        const size = @intCast(usize, openssl.i2d_ECPrivateKey(self.key, 0));
        var bytes: [:0]u8 = try allocator.allocSentinel(u8, size, 0);
        const written_bytes = openssl.i2d_ECPrivateKey(self.key, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, bytes)));
        std.debug.assert(size == written_bytes);
        return bytes;
    }

    pub fn publicKeyToBytes(self: *Secp256k1, allocator: mem.Allocator) ![:0]u8 {
        const size = @intCast(usize, openssl.i2o_ECPublicKey(self.key, 0));
        var bytes: [:0]u8 = try allocator.allocSentinel(u8, size, 0);
        const written_bytes = openssl.i2o_ECPublicKey(self.key, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, bytes)));
        std.debug.assert(size == written_bytes);
        return bytes;
    }

    pub fn getKey(self: *const Secp256k1) ?*const openssl.EC_KEY {
        return self.key;
    }

    pub fn getGroup(self: *const Secp256k1) ?*const openssl.EC_GROUP {
        return openssl.EC_KEY_get0_group(self.key);
    }

    pub fn getPublicKey(self: *const Secp256k1) ?*const openssl.EC_POINT {
        return openssl.EC_KEY_get0_public_key(self.key);
    }

    pub fn sign(self: *Secp256k1, allocator: mem.Allocator, message: [:0]const u8) ![:0]u8 {
        var size = openssl.ECDSA_size(self.key);
        var sig: [:0]u8 = try allocator.allocSentinel(u8, @intCast(usize, size), 0);
        const rv = openssl.ECDSA_sign(0, message, @intCast(c_int, message.len), @ptrCast([*c]u8, sig), @ptrCast([*c]c_uint, &size), self.key);
        defer allocator.free(sig);
        std.debug.assert(rv == 1);
        var result: [:0]u8 = try allocator.allocSentinel(u8, @intCast(usize, size), 0);
        mem.copy(u8, result, sig[0..@intCast(usize, size)]);
        // TODO: realloc/shrink didn't work for some reason.
        // _ = allocator.realloc(sig, @intCast(usize, size)) catch |err| return err;
        // sig[@intCast(usize, size)] = '0';
        return result;
    }

    pub fn verify(self: *Secp256k1, signature: [:0]const u8, message: [:0]const u8) bool {
        return openssl.ECDSA_verify(0, message, @intCast(c_int, message.len), signature, @intCast(c_int, signature.len), self.key) == 1;
    }
};

pub const Handshake = struct {
    const AUTH_VSN = 4;

    local: Secp256k1,
    elocal: Secp256k1 = undefined,
    remote: Secp256k1,
    symkey: [*:0]u8,

    pub fn initiate(local: Secp256k1, remote: Secp256k1) !Handshake {
        const elocal = try Secp256k1.generate();
        const remote_pubkey_pt = remote.getPublicKey();

        var symkey_size = @divTrunc(openssl.EC_GROUP_get_degree(remote.getGroup()) + @as(c_int, 7), @as(c_int, 8));
        var symkey = openssl.OPENSSL_malloc(@intCast(usize, symkey_size + 1));
        symkey_size = openssl.ECDH_compute_key(symkey, @intCast(usize, symkey_size), remote_pubkey_pt, elocal.getKey(), null);

        var elocal_buf: [33:0]u8 = undefined;
        _ = openssl.EC_KEY_key2buf(elocal.getKey(), openssl.POINT_CONVERSION_COMPRESSED, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, &elocal_buf)), null);

        // NOTE: The private key is thrown away here...
        // With ECIES the transmitter EC key pair is a one time use only.

        return Handshake{
            .local = local,
            .remote = remote,
            .elocal = elocal,
            .symkey = @ptrCast([*:0]u8, symkey.?),
        };
    }

    pub fn reciever(local: Secp256k1, remote: Secp256k1) !Handshake {
        const remote_pubkey_pt = remote.getPublicKey();

        var symkey_size = @divTrunc(openssl.EC_GROUP_get_degree(remote.getGroup()) + @as(c_int, 7), @as(c_int, 8));
        var symkey = openssl.OPENSSL_malloc(@intCast(usize, symkey_size + 1));
        symkey_size = openssl.ECDH_compute_key(symkey, @intCast(usize, symkey_size), remote_pubkey_pt, local.getKey(), null);

        var local_buf: [33:0]u8 = undefined;
        _ = openssl.EC_KEY_key2buf(local.getKey(), openssl.POINT_CONVERSION_COMPRESSED, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, &local_buf)), null);

        // NOTE: The private key is thrown away here...
        // With ECIES the transmitter EC key pair is a one time use only.

        return Handshake{
            .local = local,
            .remote = remote,
            .symkey = @ptrCast([*:0]u8, symkey.?),
        };
    }

    pub fn deinit(self: *Handshake) void {
        openssl.OPENSSL_free(self.symkey);
    }
};
