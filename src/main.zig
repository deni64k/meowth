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

    var key = try meowth.crypto.Secp256k1.generate();
    defer key.deinit();

    key.setCoversion(true);

    if (false) {
        var privkey: [:0]u8 = key.privateKeyToBytes(allocator) catch unreachable;
        defer allocator.free(privkey);

        std.debug.print("privkey.len={d}\n", .{privkey.len});
        std.debug.print("privkey={any}\n", .{privkey});
    }

    if (false) {
        var pubkey: [:0]u8 = try key.publicKeyToBytes(allocator);
        defer allocator.free(pubkey);

        std.debug.print("pubkey.len={d}\n", .{pubkey.len});
        std.debug.print("pubkey={any}\n", .{pubkey});
    }

    if (false) {
        const message = "Hello, Ethereum!";

        const signature = try key.sign(allocator, message);
        defer allocator.free(signature);

        std.debug.print("signature.len={d}\n", .{signature.len});
        std.debug.print("signature={any}\n", .{signature});

        const verified = key.verify(signature, message);
        std.debug.print("verified={any}\n", .{verified});
    }

    if (false) {
        const bootnode = meowth.params.ropstenBootnodes[0];
        const enode = try meowth.p2p.Enode.parse(bootnode);

        std.debug.print("Trying to connect to a bootnode: {s}\n", .{enode.ip});

        var remote = try meowth.crypto.Secp256k1.fromPublicKey(enode.id[0..]);
        defer remote.deinit();
        var auth = try meowth.crypto.Handshake.initiate(key, remote);
        defer auth.deinit();

        std.debug.print("Shared secret is {d}\n", .{auth.symkey});
    }

    {
        std.debug.print("\t*** Sender side ***\n", .{});

        var local = try meowth.crypto.Secp256k1.generate();
        defer local.deinit();
        var remote = try meowth.crypto.Secp256k1.generate();
        defer remote.deinit();
        var auth = try meowth.crypto.Handshake.initiate(local, remote);
        defer auth.deinit();

        {
            var buf: [:0]u8 = try auth.local.publicKeyToBytes(allocator);
            defer allocator.free(buf);

            std.debug.print("Node's public key={d}\n", .{buf});
        }
        {
            var buf: [:0]u8 = try auth.elocal.publicKeyToBytes(allocator);
            defer allocator.free(buf);

            std.debug.print("Ephemeral public key={d}\n", .{buf});
        }

        std.debug.print("Shared secret is {d}\n", .{auth.symkey});

        std.debug.print("\t*** Receiver side ***\n", .{});

        var reply = try meowth.crypto.Handshake.reciever(remote, auth.elocal);
        defer reply.deinit();

        {
            var buf: [:0]u8 = try reply.local.publicKeyToBytes(allocator);
            defer allocator.free(buf);

            std.debug.print("Receiver's public key={d}\n", .{buf});
        }

        std.debug.print("Shared secret is {d}\n", .{reply.symkey});
    }

    return;
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
