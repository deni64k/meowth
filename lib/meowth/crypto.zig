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

        var group = openssl.EC_KEY_get0_group(key) orelse return error.CouldNotGetGroup;
        var pt = openssl.EC_POINT_new(group) orelse return error.CouldNotAllocatePoint;
        // defer openssl.EC_POINT_free(pt);

        var rv: c_int = undefined;
        if (pubkey.len == 64) {
            var full_pubkey: [65:0]u8 = undefined;
            full_pubkey[0] = 0x04;
            std.mem.copy(u8, full_pubkey[1..], pubkey);
            rv = openssl.EC_POINT_oct2point(group, pt, @as([*c]const u8, full_pubkey[0..]), full_pubkey.len, null);
        } else {
            rv = openssl.EC_POINT_oct2point(group, pt, @as([*c]const u8, pubkey.ptr), pubkey.len, null);
        }
        // TODO: Return an error.
        std.debug.assert(rv == 1);

        _ = openssl.EC_KEY_set_public_key(key, pt);

        return Secp256k1{
            .key = key,
        };
    }

    pub fn fromPrivateKey(privkey: []const u8) !Secp256k1 {
        var key: *openssl.EC_KEY = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1) orelse return error.CouldNotGetKey;

        if (openssl.EC_KEY_oct2priv(key, @as([*c]const u8, privkey.ptr), privkey.len) != 1) {
            return error.CouldNotSetPrivateKey;
        }

        var ctx = openssl.BN_CTX_new();
        defer openssl.BN_CTX_free(ctx);

        var group = openssl.EC_KEY_get0_group(key) orelse return error.CouldNotGetGroup;
        var pubkey_pt = openssl.EC_POINT_new(group) orelse return error.CouldNotAllocatePoint;
        defer openssl.EC_POINT_free(pubkey_pt);

        var privkey_bn = openssl.EC_KEY_get0_private_key(key) orelse return error.CouldNotGetPrivateKey;
        if (openssl.EC_POINT_mul(group, pubkey_pt, privkey_bn, null, null, ctx) != 1) {
            return error.CouldNotCalculatePublicKey;
        }

        if (openssl.EC_KEY_set_public_key(key, pubkey_pt) != 1) {
            return error.CouldNotSetPublicKey;
        }

        if (openssl.EC_KEY_check_key(key) != 1) {
            return error.KeyVerificationFailed;
        }

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

    pub fn privateKeyToBytes(self: *const Secp256k1, allocator: mem.Allocator) ![]u8 {
        const size = @intCast(usize, openssl.EC_KEY_priv2oct(self.key, null, 0));
        var bytes = try allocator.allocSentinel(u8, size, 0);
        const rv = openssl.EC_KEY_priv2oct(self.key, @as([*c]u8, bytes), size);
        std.debug.assert(rv > 0);
        return bytes;
    }

    pub fn publicKeyToBytes(self: *const Secp256k1, allocator: mem.Allocator) ![]u8 {
        var group = openssl.EC_KEY_get0_group(self.key) orelse return error.CouldNotGetGroup;
        var pt = openssl.EC_KEY_get0_public_key(self.key) orelse return error.CouldNotGetPoint;

        const size = @intCast(usize, openssl.EC_POINT_point2oct(group, pt, openssl.POINT_CONVERSION_UNCOMPRESSED, null, 0, null));
        var bytes = try allocator.allocSentinel(u8, size, 0);
        const rv = openssl.EC_POINT_point2oct(group, pt, openssl.POINT_CONVERSION_UNCOMPRESSED, @as([*c]u8, bytes.ptr), size, null);
        std.debug.assert(rv > 0);
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
        var size = @intCast(c_uint, openssl.ECDSA_size(self.key));
        var sig: [:0]u8 = try allocator.allocSentinel(u8, @intCast(usize, size), 0);
        const rv = openssl.ECDSA_sign(0, message, @intCast(c_int, message.len), @as([*c]u8, sig.ptr), &size, self.key);
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
    pub fn generateShared(allocator: mem.Allocator, local: Secp256k1, remote: Secp256k1) ![]u8 {
        const remote_pubkey_pt = try remote.getPublicKey();

        var symkey_size = @divTrunc(openssl.EC_GROUP_get_degree(try remote.getGroup()) + @as(c_int, 7), @as(c_int, 8));
        var symkey = try allocator.allocSentinel(u8, @intCast(usize, symkey_size), 0);
        symkey_size = openssl.ECDH_compute_key(@as([*c]u8, symkey), @intCast(usize, symkey_size), remote_pubkey_pt, local.getKey(), null);

        // var local_buf: [33:0]u8 = undefined;
        // _ = openssl.EC_KEY_key2buf(local.getKey(), openssl.POINT_CONVERSION_COMPRESSED, @ptrCast([*c][*c]u8, &@ptrCast([*c]u8, &local_buf)), null);

        // NOTE: The private key is thrown away here...
        // With ECIES the transmitter EC key pair is a one time use only.

        return symkey;
    }

    // NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
    //
    // Always uses SHA256.
    //
    pub fn concatKDF(z: []const u8, s1: []const u8) [32]u8 {
        const key_len = 16;
        const kd_len = key_len * 2;
        const hash_size = 32;

        var counter: u32 = 1;
        var out: [kd_len]u8 = undefined;
        var written_bytes: usize = 0;
        while (written_bytes < kd_len) : (written_bytes += hash_size) {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(std.mem.asBytes(&std.mem.nativeToBig(u32, counter)));
            h.update(z);
            h.update(s1);
            h.final(@ptrCast(*[32]u8, out[written_bytes..(written_bytes + hash_size)].ptr));
            counter += 1;
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
    pub fn deriveKeys(z: []const u8, s1: []const u8, out_ke: *[16]u8, out_km: *[32]u8) void {
        const kdf = Ecies.concatKDF(z, s1);
        std.mem.copy(u8, out_ke, kdf[0..16]);

        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(kdf[16..]);
        h.final(out_km);
    }

    pub fn messageTag(km: [32]u8, iv: []const u8, message: []const u8, shared: []const u8) [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 {
        var out: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(km[0..]);
        // std.debug.print("messageTag: iv = {x}\n", .{std.fmt.fmtSliceHexLower(iv)});
        hmac.update(iv[0..]);
        // std.debug.print("messageTag: message = {x}\n", .{std.fmt.fmtSliceHexLower(message)});
        hmac.update(message[0..]);
        // std.debug.print("messageTag: shared = {x}\n", .{std.fmt.fmtSliceHexLower(shared)});
        hmac.update(shared[0..]);
        hmac.final(out[0..]);

        return out;
    }

    // pub fn initatorPacket(self: *Ecies) []u8 {
    //     var hmac: [sha2.HmacSha256.mac_length]u8 = undefined;
    //     sha2.HmacSha256.create(out[0..], "The quick brown fox jumps over the lazy dog", "key");
    // }

    pub fn encryptAes(allocator: mem.Allocator, iv: []u8, symkey: []u8, plaintext: []const u8) ![]u8 {
        var to_alloc: usize = plaintext.len & ~@as(usize, 0x0f);
        if (plaintext.len % 16 != 0) {
            to_alloc += 16;
        }
        var ciphertext = try allocator.allocSentinel(u8, to_alloc, 0);

        var ctx = openssl.EVP_CIPHER_CTX_new();
        defer openssl.EVP_CIPHER_CTX_free(ctx);

        var rv: c_int = undefined;
        rv = openssl.EVP_EncryptInit_ex(ctx, openssl.EVP_aes_128_ctr(), null, null, null);
        std.debug.assert(rv == 1);
        rv = openssl.EVP_EncryptInit_ex(ctx, null, null, @as([*c]const u8, symkey.ptr), @as([*c]u8, iv.ptr));
        std.debug.assert(rv == 1);

        var ciphertext_len: usize = 0;
        var len: c_int = undefined;
        rv = openssl.EVP_EncryptUpdate(ctx, ciphertext, &len, @as([*c]const u8, plaintext.ptr), @intCast(c_int, plaintext.len));
        std.debug.assert(rv == 1);
        ciphertext_len += @intCast(usize, len);

        rv = openssl.EVP_EncryptFinal_ex(ctx, @as([*c]u8, ciphertext[(ciphertext_len - 1)..].ptr), &len);
        std.debug.assert(rv == 1);
        ciphertext_len += @intCast(usize, len);

        // TODO: Do I need it?
        // /* Get the authentication tag. */
        // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag);

        return ciphertext[0..ciphertext_len];
    }

    pub fn decryptAes(allocator: mem.Allocator, iv: []u8, symkey: []u8, ciphertext: []const u8) ![]const u8 {
        var plaintext = try allocator.allocSentinel(u8, ciphertext.len, 0);

        var rv: c_int = undefined;

        var ctx = openssl.EVP_CIPHER_CTX_new();
        defer openssl.EVP_CIPHER_CTX_free(ctx);

        rv = openssl.EVP_DecryptInit_ex(ctx, openssl.EVP_aes_128_ctr(), null, null, null);
        std.debug.assert(rv == 1);
        rv = openssl.EVP_CIPHER_CTX_ctrl(ctx, openssl.EVP_CTRL_GCM_SET_IVLEN, @intCast(c_int, iv.len), null);
        rv = openssl.EVP_DecryptInit_ex(ctx, null, null, @as([*c]const u8, symkey.ptr), @as([*c]u8, iv.ptr));
        std.debug.assert(rv == 1);

        var plaintext_len: usize = 0;
        var len: c_int = undefined;
        rv = openssl.EVP_DecryptUpdate(ctx, plaintext, &len, @as([*c]const u8, ciphertext.ptr), @intCast(c_int, ciphertext.len));
        std.debug.assert(rv == 1);
        plaintext_len += @intCast(usize, len);

        rv = openssl.EVP_DecryptFinal_ex(ctx, @as([*c]u8, plaintext[(plaintext_len - 1)..].ptr), &len);
        std.debug.assert(rv == 1);
        plaintext_len += @intCast(usize, len);

        return plaintext[0..plaintext_len];
    }

    pub fn encrypt(
        allocator: mem.Allocator,
        ekey: Secp256k1,
        remote: Secp256k1,
        plaintext: []const u8,
        s1: []const u8,
        shared_mac_data: ?[]const u8,
    ) ![]u8 {
        var rv: c_int = undefined;
        var result = std.ArrayList(u8).init(allocator);
        var writer = result.writer();

        var ekeyBytes = try ekey.publicKeyToBytes(allocator);
        defer allocator.free(ekeyBytes);

        const shared = try Ecies.generateShared(allocator, ekey, remote);
        defer allocator.free(shared);

        var iv: [16]u8 = undefined;
        rv = openssl.RAND_pseudo_bytes(@as([*c]u8, &iv), iv.len);
        std.debug.assert(rv == 1);
        // std.debug.print("Ecies.encrypt: iv = {x}\n", .{std.fmt.fmtSliceHexLower(iv[0..])});

        var ke: [16]u8 = undefined;
        var km: [32]u8 = undefined;

        Ecies.deriveKeys(std.mem.span(shared), s1, &ke, &km);
        // std.debug.print("Ecies.encrypt: ke = {x}\n", .{std.fmt.fmtSliceHexLower(ke[0..])});
        // std.debug.print("Ecies.encrypt: km = {x}\n", .{std.fmt.fmtSliceHexLower(km[0..])});

        const encrypted = try Ecies.encryptAes(allocator, iv[0..], ke[0..], plaintext);
        defer allocator.free(encrypted);

        var encrypted_len_be = std.mem.nativeToBig(u16, @intCast(u16, encrypted.len + ekeyBytes.len + iv.len + 32));
        // std.debug.print("Ecies.encrypt: shared_mac_data = {x}\n", .{std.fmt.fmtSliceHexLower(shared_mac_data orelse "")});
        // std.debug.print("Ecies.encrypt: shared_mac_data = {x}\n", .{std.fmt.fmtSliceHexLower(shared_mac_data orelse std.mem.asBytes(&encrypted_len_be))});
        const d = Ecies.messageTag(km, std.mem.span(iv[0..]), encrypted, shared_mac_data orelse std.mem.asBytes(&encrypted_len_be));

        var written_bytes: usize = 0;
        written_bytes += try writer.write(std.mem.span(ekeyBytes[0..]));
        // std.debug.print("ecies.encrypt: Has written {d} bytes\n", .{written_bytes});
        written_bytes += try writer.write(iv[0..]);
        // std.debug.print("ecies.encrypt: Has written {d} bytes\n", .{written_bytes});
        written_bytes += try writer.write(encrypted);
        // std.debug.print("ecies.encrypt: Has written {d} bytes\n", .{written_bytes});
        written_bytes += try writer.write(d[0..]);
        // std.debug.print("ecies.encrypt: Has written {d} bytes\n", .{written_bytes});

        // std.debug.print("ecies.encrypt: result.items.len={d}\n", .{result.items.len});

        return result.items;
    }

    pub fn decrypt(
        allocator: mem.Allocator,
        local: Secp256k1,
        ciphertext: []const u8,
        s1: []const u8,
        shared_mac_data: ?[]const u8,
    ) ![]const u8 {
        var ekey = try Secp256k1.fromPublicKey(ciphertext[0..65]);
        defer ekey.deinit();
        // std.debug.print("Ecies.decrypt: ciphertext[0..65] = {x}\n", .{std.fmt.fmtSliceHexLower(ciphertext[0..65])});
        var epubkey = try ekey.publicKeyToBytes(allocator);
        defer allocator.free(epubkey);
        // std.debug.print("Ecies.decrypt: epubkey = {x}\n", .{std.fmt.fmtSliceHexLower(epubkey[0..])});

        const shared = try Ecies.generateShared(allocator, local, ekey);
        defer allocator.free(shared);
        // std.debug.print("Ecies.decrypt: shared = {x}\n", .{std.fmt.fmtSliceHexLower(shared[0..])});

        var iv: [16]u8 = undefined;
        std.mem.copy(u8, &iv, ciphertext[65..(65 + 16)]);
        // std.debug.print("Ecies.decrypt: iv = {x}\n", .{std.fmt.fmtSliceHexLower(iv[0..])});

        var ke: [16]u8 = undefined;
        var km: [32]u8 = undefined;

        Ecies.deriveKeys(shared, s1, &ke, &km);
        // std.debug.print("Ecies.decrypt: s1 = {x}\n", .{std.fmt.fmtSliceHexLower(s1)});
        // std.debug.print("Ecies.decrypt: ke = {x}\n", .{std.fmt.fmtSliceHexLower(ke[0..])});
        // std.debug.print("Ecies.decrypt: km = {x}\n", .{std.fmt.fmtSliceHexLower(km[0..])});

        const encrypted = ciphertext[(65 + 16)..(ciphertext.len - 32)];
        var encrypted_len_be = std.mem.nativeToBig(u16, @intCast(u16, encrypted.len));
        // _ = shared_mac_data;
        const d = ciphertext[(ciphertext.len - 32)..];
        const expected_d = Ecies.messageTag(km, iv[0..], encrypted, shared_mac_data orelse std.mem.asBytes(&encrypted_len_be));
        // std.debug.print("Ecies.decrypt: encrypted = {x}\n", .{std.fmt.fmtSliceHexLower(encrypted)});
        // std.debug.print("Ecies.decrypt: ciphertext.len = {d}\n", .{ciphertext.len});
        // std.debug.print("Ecies.decrypt: shared_mac_data = {x}\n", .{std.fmt.fmtSliceHexLower(shared_mac_data orelse std.mem.asBytes(&encrypted_len_be))});
        std.debug.print("Ecies.decrypt: d = {x}\n", .{std.fmt.fmtSliceHexLower(d)});
        std.debug.print("Ecies.decrypt: expected_d = {x}\n", .{std.fmt.fmtSliceHexLower(expected_d[0..])});
        if (!std.mem.eql(u8, d, expected_d[0..]))
            return error.MessageTagMismatch;

        return try Ecies.decryptAes(allocator, iv[0..], ke[0..], encrypted);
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

    var ekey = try Secp256k1.generate();
    defer ekey.deinit();
    var remote = try Secp256k1.generate();
    defer remote.deinit();

    var encrypted = try Ecies.encrypt(testing.allocator, ekey, remote, plaintext, "s1", "shared_mac_data");
    defer testing.allocator.free(encrypted);

    // std.debug.print("encrypted = {x}\n", .{std.fmt.fmtSliceHexLower(encrypted)});
    var decrypted = try Ecies.decrypt(testing.allocator, remote, encrypted, "s1", "shared_mac_data");
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(decrypted, plaintext);
}
