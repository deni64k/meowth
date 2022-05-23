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
        const nonce_a = meowth.common.hexToSlice("7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6");

        const bootnode = meowth.params.ropstenBootnodes[1];
        const enode = try meowth.p2p.Enode.parse(bootnode);

        std.debug.print("\nTrying to connect to a bootnode: {s}\n", .{enode.ip});

        var remote = try meowth.crypto.Secp256k1.fromPublicKey(enode.id[0..]);
        defer remote.deinit();

        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try meowth.protocol.Auth.Packet.encode(allocator, remote, nonce_a, buf.writer());
        std.debug.print("\nSending auth packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(buf.items)});

        var stream = try std.net.tcpConnectToAddress(enode.ip);
        defer stream.close();

        var reader = stream.reader();
        var writer = stream.writer();

        // var written_bytes: usize = 0;
        // written_bytes += try writer.writeAll(buf.items);
        try writer.writeAll(buf.items);
        std.debug.print("Wrote {d} bytes to the socket\n", .{buf.items.len});

        // while (true) {
        var read_bytes: usize = 0;
        var read_buf: [4096]u8 = undefined;
        {
            std.debug.print("\nReading ack packet\n", .{});
            read_bytes = try reader.read(read_buf[0..]);
            read_bytes += try reader.read(read_buf[read_bytes..]);
            std.debug.print("Read {d} bytes from the socket\n", .{read_bytes});
            std.debug.print("Packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(read_buf[0..read_bytes])});

            const privkey_a = meowth.common.hexToSlice("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee");
            var ekey = try meowth.crypto.Secp256k1.fromPrivateKey(privkey_a[0..]);

            var ack_len = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, read_buf[0..2])) + 2;
            var encoded_pkt = read_buf[0..ack_len];
            std.debug.print("ACK Packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(encoded_pkt)});
            std.debug.print("ack_len={d} read_bytes={d}\n", .{ ack_len, read_bytes });
            var decrypted = try meowth.crypto.Ecies.decrypt(allocator, ekey, encoded_pkt[2..], "", encoded_pkt[0..2]);
            defer allocator.free(decrypted);
            std.debug.print("Decrypted packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(decrypted)});

            var decrypted_pkt: meowth.protocol.Ack.Packet = undefined;
            try meowth.rlp.decodeAsList(allocator, decrypted, &decrypted_pkt);

            std.debug.print("pkt.pubkey = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.pubkey[0..])});
            std.debug.print("pkt.nonce = {x}\n", .{std.fmt.fmtSliceHexLower(decrypted_pkt.nonce[0..])});
            std.debug.print("pkt.version = {d}\n", .{decrypted_pkt.version});

            var encoded_hello = read_buf[ack_len..];
            std.debug.print("\nReading Hello packet\n", .{});
            std.debug.print("Packet:\n{x}\n", .{std.fmt.fmtSliceHexLower(encoded_hello)});
        }
        // }
    }

    {
        var ekey = try meowth.crypto.Secp256k1.generate();
        defer ekey.deinit();
        var remote = try meowth.crypto.Secp256k1.generate();
        defer remote.deinit();

        {
            const plaintext = "I am Alice!";
            std.debug.print("\t*** ECIES Alice ***\n", .{});

            var encrypted = try meowth.crypto.Ecies.encrypt(allocator, ekey, remote, plaintext, "", "");
            defer allocator.free(encrypted);
            std.debug.print("{x}\n", .{std.fmt.fmtSliceHexLower(encrypted)});

            std.debug.print("\t*** ECIES Bob ***\n", .{});
            var decrypted = try meowth.crypto.Ecies.decrypt(allocator, remote, encrypted, "", "");
            defer allocator.free(decrypted);
            std.debug.print("{s}\n", .{decrypted});
        }

        {
            std.debug.print("\t*** Auth Packet ***\n", .{});

            var buf = std.ArrayList(u8).init(allocator);
            defer buf.deinit();
            try meowth.protocol.Auth.Packet.encode(allocator, remote, null, buf.writer());
            std.debug.print("{x}\n", .{std.fmt.fmtSliceHexLower(buf.items)});
        }
    }

    return;
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
