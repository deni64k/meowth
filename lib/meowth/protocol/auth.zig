const std = @import("std");
const mem = std.mem;

const meowth = @import("../../meowth.zig");

pub const Ack = struct {
    const ack_vsn = 4;

    pub const Packet = struct {
        pubkey: [64]u8,
        nonce: [32]u8,
        version: u32,
    };
};

pub const Auth = struct {
    const auth_vsn = 4;

    pub const Packet = struct {
        sig: [65]u8 = undefined,
        pubkey: [64]u8,
        nonce: [32]u8,
        version: u32,

        pub fn encode(allocator: std.mem.Allocator, remote: meowth.crypto.Secp256k1, nonce: ?[32]u8, writer: anytype) !void {
            var local = try meowth.crypto.Secp256k1.generate();
            defer local.deinit();
            local.setConversion(false);

            // var ekey = try meowth.crypto.Secp256k1.generate();
            var ekey = try meowth.crypto.Secp256k1.fromPrivateKey(privkey_a[0..]);
            defer ekey.deinit();
            var ekey_bytes = try ekey.publicKeyToBytes(allocator);
            defer allocator.free(ekey_bytes);
            var pubkey = try ekey.publicKeyToBytes(allocator);
            defer allocator.free(pubkey);

            var nonce_: [32]u8 = undefined;
            if (nonce) |v| {
                mem.copy(u8, nonce_[0..], v[0..32]);
            } else {
                // TODO: random
                mem.copy(u8, nonce_[0..], ("\x01" ** 32)[0..32]);
            }

            var shared = try meowth.crypto.Ecies.generateShared(allocator, ekey, remote);
            defer allocator.free(shared);
            var i: usize = 0;
            while (i < shared.len) : (i += 1) {
                shared[i] = shared[i] ^ nonce_[i];
            }

            var sha3 = std.crypto.hash.sha3.Sha3_256.init(.{});
            sha3.update(std.mem.span(shared));
            sha3.final(@as(*[32]u8, shared[0..32]));

            const shared_z = try allocator.dupeZ(u8, shared[0..]);
            defer allocator.free(shared_z);

            // const ekey_sig = try ekey.sign(allocator, shared_z);
            // defer allocator.free(ekey_sig);

            const ekey_sig = "\x29\x9c\xa6\xac\xfd\x35\xe3\xd7\x2d\x8b\xa3\xd1\xe2\xb6\x0b\x55\x61\xd5\xaf\x52\x18\xeb\x5b\xc1\x82\x04\x57\x69\xeb\x42\x26\x91\x0a\x30\x1a\xca\xe3\xb3\x69\xff\xfc\x4a\x48\x99\xd6\xb0\x25\x31\xe8\x9f\xd4\xfe\x36\xa2\xcf\x0d\x93\x60\x7b\xa4\x70\xb5\x0f\x78\x00";

            var packet = Packet{
                .sig = undefined,
                .pubkey = undefined,
                .nonce = undefined,
                .version = auth_vsn,
            };
            mem.copy(u8, packet.sig[0..], ekey_sig[0..65]);
            mem.copy(u8, packet.pubkey[0..], pubkey[1..65]);
            mem.copy(u8, packet.nonce[0..], nonce_[0..]);

            const rlp = try meowth.rlp.encodeAsList(allocator, packet);
            defer allocator.free(rlp);

            std.debug.print("Auth.Packet.encode: rlp = {x}\n", .{std.fmt.fmtSliceHexLower(rlp)});

            var padded_rlp = try allocator.alloc(u8, 322);
            defer allocator.free(padded_rlp);
            for (padded_rlp) |*x| {
                x.* = 0;
            }
            std.mem.copy(u8, padded_rlp[0..], rlp[0..]);

            // var padded_rlp_len_be = std.mem.nativeToBig(u16, @intCast(u16, padded_rlp.len));
            // var encrypted_packet = try meowth.crypto.Ecies.encrypt(allocator, ekey, remote, padded_rlp, "", std.mem.asBytes(&padded_rlp_len_be));
            var encrypted_packet = try meowth.crypto.Ecies.encrypt(allocator, ekey, remote, padded_rlp, "", null);
            defer allocator.free(encrypted_packet);

            const packet_len = encrypted_packet.len;
            _ = try writer.write(std.mem.asBytes(&std.mem.nativeToBig(u16, @intCast(u16, packet_len))));
            _ = try writer.write(encrypted_packet);
        }
    };
};

const testing = std.testing;

const privkey_a = meowth.common.hexToSlice("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee");
const privkey_b = meowth.common.hexToSlice("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
const eprivkey_a = meowth.common.hexToSlice("869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d");
const eprivkey_b = meowth.common.hexToSlice("e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4");
const nonce_a = meowth.common.hexToSlice("7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6");
const nonce_b = meowth.common.hexToSlice("559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd");
const npubkey_b = meowth.common.hexToSlice("04ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0");

// test "EIP-8 Auth Packet from A to B" {
//     var ctx = try meowth.crypto.Context.init();
//     defer ctx.deinit();

//     var key_a = try meowth.crypto.Secp256k1.fromPrivateKey(privkey_a[0..]);
//     defer key_a.deinit();
//     var key_b = try meowth.crypto.Secp256k1.fromPrivateKey(privkey_b[0..]);
//     defer key_b.deinit();
//     var ekey_a = try meowth.crypto.Secp256k1.fromPrivateKey(eprivkey_a[0..]);
//     defer ekey_a.deinit();
//     var ekey_b = try meowth.crypto.Secp256k1.fromPrivateKey(eprivkey_b[0..]);
//     defer ekey_b.deinit();
//     var nkey_b = try meowth.crypto.Secp256k1.fromPublicKey(npubkey_b[0..]);
//     defer nkey_b.deinit();

//     var buf = std.ArrayList(u8).init(testing.allocator);
//     defer buf.deinit();
//     try Auth.Packet.encode(testing.allocator, nkey_b, nonce_a, buf.writer());
//     std.debug.print("{x}\n", .{std.fmt.fmtSliceHexLower(buf.items)});

//     var pubkey_a = try key_a.publicKeyToBytes(testing.allocator);
//     defer testing.allocator.free(pubkey_a);
//     var pubkey_b = try key_b.publicKeyToBytes(testing.allocator);
//     defer testing.allocator.free(pubkey_b);
//     var epubkey_a = try ekey_a.publicKeyToBytes(testing.allocator);
//     defer testing.allocator.free(epubkey_a);
//     var epubkey_b = try ekey_b.publicKeyToBytes(testing.allocator);
//     defer testing.allocator.free(epubkey_b);
//     var npubkey_b_ = try nkey_b.publicKeyToBytes(testing.allocator);
//     defer testing.allocator.free(npubkey_b_);
//     std.debug.print("privkey_a = {x}\n", .{std.fmt.fmtSliceHexLower(privkey_a[0..])});
//     std.debug.print("privkey_b = {x}\n", .{std.fmt.fmtSliceHexLower(privkey_b[0..])});
//     std.debug.print("pubkey_a = {x}\n", .{std.fmt.fmtSliceHexLower(pubkey_a)});
//     std.debug.print("pubkey_b = {x}\n", .{std.fmt.fmtSliceHexLower(pubkey_b)});
//     std.debug.print("epubkey_a = {x}\n", .{std.fmt.fmtSliceHexLower(epubkey_a)});
//     std.debug.print("epubkey_b = {x}\n", .{std.fmt.fmtSliceHexLower(epubkey_b)});
//     std.debug.print("npubkey_b = {x}\n", .{std.fmt.fmtSliceHexLower(npubkey_b[0..])});
//     std.debug.print("npubkey_b_ = {x}\n", .{std.fmt.fmtSliceHexLower(npubkey_b_)});
// }

test "Decode EIP-8 Auth" {
    var ctx = try meowth.crypto.Context.init();
    defer ctx.deinit();

    var key_a = try meowth.crypto.Secp256k1.fromPrivateKey(privkey_a[0..]);
    defer key_a.deinit();
    var key_b = try meowth.crypto.Secp256k1.fromPrivateKey(privkey_b[0..]);
    defer key_b.deinit();
    var ekey_a = try meowth.crypto.Secp256k1.fromPrivateKey(eprivkey_a[0..]);
    defer ekey_a.deinit();
    var ekey_b = try meowth.crypto.Secp256k1.fromPrivateKey(eprivkey_b[0..]);
    defer ekey_b.deinit();
    var pubkey_a = try key_a.publicKeyToBytes(testing.allocator);
    defer testing.allocator.free(pubkey_a);
    var pubkey_b = try key_b.publicKeyToBytes(testing.allocator);
    defer testing.allocator.free(pubkey_b);
    var epubkey_a = try ekey_a.publicKeyToBytes(testing.allocator);
    defer testing.allocator.free(epubkey_a);
    var epubkey_b = try ekey_b.publicKeyToBytes(testing.allocator);
    defer testing.allocator.free(epubkey_b);
    std.debug.print("privkey_a = {x}\n", .{std.fmt.fmtSliceHexLower(privkey_a[0..])});
    std.debug.print("privkey_b = {x}\n", .{std.fmt.fmtSliceHexLower(privkey_b[0..])});
    std.debug.print("pubkey_a = {x}\n", .{std.fmt.fmtSliceHexLower(pubkey_a)});
    std.debug.print("pubkey_b = {x}\n", .{std.fmt.fmtSliceHexLower(pubkey_b)});
    std.debug.print("epubkey_a = {x}\n", .{std.fmt.fmtSliceHexLower(epubkey_a)});
    std.debug.print("epubkey_b = {x}\n", .{std.fmt.fmtSliceHexLower(epubkey_b)});

    {
        var encoded_pkt = std.ArrayList(u8).init(testing.allocator);
        defer encoded_pkt.deinit();
        try Auth.Packet.encode(testing.allocator, key_b, nonce_a, encoded_pkt.writer());
        std.debug.print("\n\nEncoded packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(encoded_pkt.items)});

        var decrypted = try meowth.crypto.Ecies.decrypt(testing.allocator, key_b, encoded_pkt.items[2..], "", encoded_pkt.items[0..2]);
        defer testing.allocator.free(decrypted);
        std.debug.print("\n\nDecrypted packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(decrypted)});

        var decrypted_pkt: Auth.Packet = undefined;
        try meowth.rlp.decodeAsList(testing.allocator, decrypted, &decrypted_pkt);

        std.debug.print("pkt.sig = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.sig[0..])});
        std.debug.print("pkt.pubkey = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.pubkey[0..])});
        std.debug.print("pkt.nonce = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.nonce[0..])});
        std.debug.print("pkt.version = {d}\n", .{decrypted_pkt.version});
    }

    var pkt = meowth.common.hexToSlice("01b304ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0d84ac74f6e475f1b8d56116b849634a8c458705bf83a626ea0384d4d7341aae591fae42ce6bd5c850bfe0b999a694a49bbbaf3ef6cda61110601d3b4c02ab6c30437257a6e0117792631a4b47c1d52fc0f8f89caadeb7d02770bf999cc147d2df3b62e1ffb2c9d8c125a3984865356266bca11ce7d3a688663a51d82defaa8aad69da39ab6d5470e81ec5f2a7a47fb865ff7cca21516f9299a07b1bc63ba56c7a1a892112841ca44b6e0034dee70c9adabc15d76a54f443593fafdc3b27af8059703f88928e199cb122362a4b35f62386da7caad09c001edaeb5f8a06d2b26fb6cb93c52a9fca51853b68193916982358fe1e5369e249875bb8d0d0ec36f917bc5e1eafd5896d46bd61ff23f1a863a8a8dcd54c7b109b771c8e61ec9c8908c733c0263440e2aa067241aaa433f0bb053c7b31a838504b148f570c0ad62837129e547678c5190341e4f1693956c3bf7678318e2d5b5340c9e488eefea198576344afbdf66db5f51204a6961a63ce072c8926c");
    _ = pkt;

    var ciphertext = pkt[2..];
    var decrypted = try meowth.crypto.Ecies.decrypt(testing.allocator, key_b, ciphertext, "", pkt[0..2]);
    defer testing.allocator.free(decrypted);

    std.debug.print("\n\nDecrypted packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(decrypted)});

    var decrypted_pkt: Auth.Packet = undefined;
    try meowth.rlp.decodeAsList(testing.allocator, decrypted, &decrypted_pkt);

    std.debug.print("pkt.sig = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.sig[0..])});
    std.debug.print("pkt.pubkey = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.pubkey[0..])});
    std.debug.print("pkt.nonce = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.nonce[0..])});
    std.debug.print("pkt.version = {d}\n", .{decrypted_pkt.version});
}
