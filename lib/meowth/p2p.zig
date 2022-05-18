const std = @import("std");
const common = @import("common.zig");

const IP = union {
    ip4: [4]u8,
    ip6: [16]u8,
};

pub const EnodeError = error{
    InvalidFormat,
};

const enodePrefix = "enode://";

pub const Enode = struct {
    id: [64]u8,
    ip: std.net.Address,
    tcp_port: u16,
    udp_port: ?u16 = null,

    pub fn parse(s: []const u8) !Enode {
        if (!std.mem.startsWith(u8, s, enodePrefix)) {
            return EnodeError.InvalidFormat;
        }

        var enode = Enode{
            .id = undefined,
            .ip = undefined,
            .tcp_port = undefined,
            .udp_port = undefined,
        };
        var buf = s[0..];
        buf = buf[enodePrefix.len..];
        _ = try std.fmt.hexToBytes(&enode.id, buf[0..128]);
        buf = buf[(128 + 1)..];

        const ip_len = std.mem.indexOf(u8, buf, ":");
        if (ip_len == null) {
            return EnodeError.InvalidFormat;
        }
        const port_len = std.mem.indexOfAny(u8, buf[(ip_len.? + 1)..], "?+");
        const tcp_port = std.fmt.parseInt(u16, buf[(ip_len.? + 1)..], 10) catch {
            return EnodeError.InvalidFormat;
        };
        var udp_port: ?u16 = null;
        if (port_len != null) {
            // TODO
            udp_port = null;
        }

        const ip = std.net.Address.resolveIp(buf[0..ip_len.?], tcp_port) catch {
            return EnodeError.InvalidFormat;
        };
        enode.ip = ip;

        enode.tcp_port = tcp_port;

        return enode;
    }
};

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}

test "ParseGoerliEnode" {
    const enode = try Enode.parse("enode://a869b02cec167211fb4815a82941db2e7ed2936fd90e78619c53eb17753fcf0207463e3419c264e2a1dd8786de0df7e68cf99571ab8aeb7c4e51367ef186b1dd@51.15.116.226:30303");

    var buf: [100]u8 = undefined;
    var id: [64]u8 = undefined;
    var ip = try std.fmt.bufPrint(buf[0..], "{}", .{enode.ip});
    try testing.expectEqualStrings(enode.id[0..], try std.fmt.hexToBytes(&id, "a869b02cec167211fb4815a82941db2e7ed2936fd90e78619c53eb17753fcf0207463e3419c264e2a1dd8786de0df7e68cf99571ab8aeb7c4e51367ef186b1dd"));
    try testing.expectEqualStrings(ip, "51.15.116.226:30303");
}
