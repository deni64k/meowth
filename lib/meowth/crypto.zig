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

//
// Used materials:
// * https://github.com/insanum/ecies/blob/master/ecies_openssl.c
// * https://github.com/ethereum/trinity/blob/master/p2p/ecies.py
// * https://github.com/ethereum/trinity/blob/master/p2p/auth.py
// * https://github.com/gballet/zig-secp-perf-openssl/blob/master/src/main.zig
//

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

    pub fn setConversion(self: *Secp256k1, compressed: bool) void {
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

    pub fn getKey(self: *const Secp256k1) *const openssl.EC_KEY {
        return self.key;
    }

    pub fn getGroup(self: *const Secp256k1) !*const openssl.EC_GROUP {
        return openssl.EC_KEY_get0_group(self.key) orelse error.CouldNotGetGroup;
    }

    pub fn getPublicKey(self: *const Secp256k1) !*const openssl.EC_POINT {
        return openssl.EC_KEY_get0_public_key(self.key) orelse error.CouldNotGetPoint;
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

pub const Ecies = struct {
    const auth_vsn = 4;

    pub fn generateShared(local: Secp256k1, remote: Secp256k1) ![*:0]u8 {
        const remote_pubkey_pt = try remote.getPublicKey();

        var symkey_size = @divTrunc(openssl.EC_GROUP_get_degree(try remote.getGroup()) + @as(c_int, 7), @as(c_int, 8));
        var symkey = openssl.OPENSSL_malloc(@intCast(usize, symkey_size + 1));
        symkey_size = openssl.ECDH_compute_key(symkey, @intCast(usize, symkey_size), remote_pubkey_pt, local.getKey(), null);

        // var local_buf: [33:0]u8 = undefined;
        // _ = openssl.EC_KEY_key2buf(local.getKey(), openssl.POINT_CONVERSION_COMPRESSED, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, &local_buf)), null);

        // NOTE: The private key is thrown away here...
        // With ECIES the transmitter EC key pair is a one time use only.

        return @ptrCast([*:0]u8, symkey.?);
    }

    pub fn freeShared(shared: [*:0]u8) void {
        openssl.OPENSSL_free(shared);
    }

    // NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
    //
    // Always uses SHA256.
    //
    pub fn concatKDF(z: []const u8, s1: []const u8) [32]u8 {
        const key_len = 16;
        const kd_len = key_len * 2;
        const hash_size = 32;
        const reps = @divTrunc(kd_len + 7, hash_size);

        var counter: u32 = 1;
        var out: [kd_len]u8 = undefined;
        var i: usize = 0;
        while (counter <= reps) : (counter += 1) {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(std.mem.asBytes(&std.mem.nativeToBig(u32, counter)));
            h.update(z);
            h.update(s1);
            var o: [32]u8 = undefined;
            // TODO: Write to out directly instead of using o.
            h.final(o[0..]);
            std.mem.copy(u8, out[((reps - i - 1) * hash_size)..((reps - i) * hash_size)], o[0..]);
            i += 1;
        }

        // var out: [32]u8 = undefined;
        // var h = std.crypto.Sha3_256.init(.{});
        // h.update(key);
        // h.final(out[0..]);
        return out;
    }

    // deriveKeys creates the encryption and MAC keys using concatKDF.
    //
    // Always uses SHA256.
    //
    pub fn deriveKeys(z: []const u8, s1: []const u8, out_ke: *[16]u8, out_km: *[16]u8) void {
        const kdf = Ecies.concatKDF(z, s1);
        std.mem.copy(u8, out_ke, kdf[0..out_ke.len]);
        std.mem.copy(u8, out_km, kdf[out_ke.len..]);
    }

    pub fn messageTag(in_km: [16]u8, message: []const u8, shared: []const u8) [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(in_km[0..]);
        var km: [32]u8 = undefined;
        h.final(km[0..]);

        var out: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&km);
        hmac.update(message[0..]);
        hmac.update(shared[0..]);
        hmac.final(out[0..]);

        return out;
    }

    // pub fn initatorPacket(self: *Ecies) []u8 {
    //     var hmac: [sha2.HmacSha256.mac_length]u8 = undefined;
    //     sha2.HmacSha256.create(out[0..], "The quick brown fox jumps over the lazy dog", "key");
    // }

    pub fn encryptAes(allocator: mem.Allocator, iv: [16:0]u8, symkey: []u8, plaintext: []const u8) ![]u8 {
        var ciphertext = try allocator.allocSentinel(u8, (plaintext.len + 0x0f) & ~@as(u8, 0x0f), 0);

        var ctx = openssl.EVP_CIPHER_CTX_new();
        defer openssl.EVP_CIPHER_CTX_free(ctx);

        var rv: c_int = undefined;
        rv = openssl.EVP_EncryptInit_ex(ctx, openssl.EVP_aes_128_ctr(), null, null, null);
        std.debug.assert(rv == 1);
        rv = openssl.EVP_EncryptInit_ex(ctx, null, null, @ptrCast([*c]const u8, &symkey), &iv);
        std.debug.assert(rv == 1);

        var ciphertext_len: usize = 0;
        var len: c_int = undefined;
        rv = openssl.EVP_EncryptUpdate(ctx, ciphertext, &len, @ptrCast([*c]const u8, plaintext), @intCast(c_int, plaintext.len));
        std.debug.assert(rv == 1);
        ciphertext_len += @intCast(usize, len);

        rv = openssl.EVP_EncryptFinal_ex(ctx, @ptrCast([*c]u8, &ciphertext[(ciphertext_len - 1)..]), &len);
        std.debug.assert(rv == 1);
        ciphertext_len += @intCast(usize, len);

        // TODO: Do I need it?
        // /* Get the authentication tag. */
        // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag);

        return ciphertext[0..ciphertext_len];
    }

    pub fn decryptAes(allocator: mem.Allocator, iv: [16:0]u8, symkey: []u8, ciphertext: []const u8) ![]const u8 {
        var plaintext = try allocator.allocSentinel(u8, ciphertext.len, 0);

        var rv: c_int = undefined;

        var ctx = openssl.EVP_CIPHER_CTX_new();
        defer openssl.EVP_CIPHER_CTX_free(ctx);

        rv = openssl.EVP_DecryptInit_ex(ctx, openssl.EVP_aes_128_ctr(), null, null, null);
        std.debug.assert(rv == 1);
        rv = openssl.EVP_CIPHER_CTX_ctrl(ctx, openssl.EVP_CTRL_GCM_SET_IVLEN, iv.len, null);
        rv = openssl.EVP_DecryptInit_ex(ctx, null, null, @ptrCast([*c]const u8, &symkey), &iv);
        std.debug.assert(rv == 1);

        var plaintext_len: usize = 0;
        var len: c_int = undefined;
        rv = openssl.EVP_DecryptUpdate(ctx, plaintext, &len, @ptrCast([*c]const u8, ciphertext), @intCast(c_int, ciphertext.len));
        std.debug.assert(rv == 1);
        plaintext_len += @intCast(usize, len);

        rv = openssl.EVP_DecryptFinal_ex(ctx, @ptrCast([*c]u8, &plaintext[(plaintext_len - 1)..]), &len);
        std.debug.assert(rv == 1);
        plaintext_len += @intCast(usize, len);

        return plaintext[0..plaintext_len];
    }

    pub fn encrypt(allocator: mem.Allocator, remote: Secp256k1, plaintext: []const u8) ![]u8 {
        var rv: c_int = undefined;
        var result = std.ArrayList(u8).init(allocator);
        var writer = result.writer();

        var ekey = try Secp256k1.generate();

        var ekeyBytes: [:0]u8 = try ekey.publicKeyToBytes(allocator);
        defer allocator.free(ekeyBytes);

        const shared = try Ecies.generateShared(ekey, remote);
        defer Ecies.freeShared(shared);

        var iv: [16:0]u8 = undefined;
        rv = openssl.RAND_pseudo_bytes(&iv, iv.len);
        std.debug.assert(rv == 1);

        var km: [16]u8 = undefined;
        var ke: [16]u8 = undefined;

        Ecies.deriveKeys(std.mem.span(shared), "", &ke, &km);

        const encrypted = try Ecies.encryptAes(allocator, iv, km[0..], plaintext);
        defer allocator.free(encrypted);

        const d = Ecies.messageTag(km, encrypted, "");

        // std.debug.print("ekeyBytes={d}\n", .{ekeyBytes});
        // std.debug.print("iv={d}\n", .{iv});
        // std.debug.print("encrypted={d}\n", .{encrypted});
        // std.debug.print("d={d}\n", .{d});

        _ = try writer.write(std.mem.span(ekeyBytes[0..]));
        _ = try writer.write(iv[0..]);
        _ = try writer.write(encrypted);
        _ = try writer.write(d[0..]);

        return result.items;
    }

    pub fn decrypt(allocator: mem.Allocator, local: Secp256k1, ciphertext: []const u8) ![]const u8 {
        // TODO: Just ciphertext[0..65] doesn't work.
        var ekey = try Secp256k1.fromPublicKey(ciphertext[1..65]);

        const shared = try Ecies.generateShared(local, ekey);
        defer Ecies.freeShared(shared);

        var iv: [16:0]u8 = undefined;
        std.mem.copy(u8, &iv, ciphertext[65..(65 + 16)]);

        var km: [16]u8 = undefined;
        var ke: [16]u8 = undefined;

        Ecies.deriveKeys(std.mem.span(shared), "", &ke, &km);

        const d = ciphertext[(ciphertext.len - 32)..];
        const encrypted = ciphertext[(65 + 16)..(ciphertext.len - 32)];
        const expected_d = Ecies.messageTag(km, encrypted, "");
        if (!std.mem.eql(u8, d, expected_d[0..]))
            return error.MessageTagMismatch;

        return try Ecies.decryptAes(allocator, iv, km[0..], encrypted);
    }
};

const testing = std.testing;

test "concatKDF" {
    const input = "input";
    const expected = "\x85\x8b\x19\x2f\xa2\xed\x43\x95\xe2\xbf\x88\xdd\x8d\x57\x70\xd6\x7d\xc2\x84\xee\x53\x9f\x12\xda\x8b\xce\xaa\x45\xd0\x6e\xba\xe0";

    const result = Ecies.concatKDF(input[0..], "");
    try testing.expectEqualStrings(result[0..], expected[0..]);
}

test "ecies" {
    const plaintext = "I am Alice!";

    var remote = try Secp256k1.generate();
    defer remote.deinit();

    var encrypted = try Ecies.encrypt(testing.allocator, remote, plaintext);
    defer testing.allocator.free(encrypted);

    var decrypted = try Ecies.decrypt(testing.allocator, remote, encrypted);
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(decrypted, plaintext);
}
