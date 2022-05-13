const mem = std.mem;
const std = @import("std");

pub fn encode(allocator: mem.Allocator, o: anytype) ![]const u8 {
    var rlp = RLP.init(allocator);
    defer rlp.deinit();

    _ = try rlp.encode(o);

    return rlp.buf.toOwnedSlice();
}

const RLP = struct {
    allocator: mem.Allocator,
    buf: std.ArrayList(u8),

    pub fn init(allocator: mem.Allocator) RLP {
        return RLP{
            .allocator = allocator,
            .buf = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *RLP) void {
        self.buf.deinit();
    }

    pub fn encode(self: *RLP, o: anytype) !usize {
        var len: usize = 0;

        const T = @TypeOf(o);
        switch (@typeInfo(T)) {
            .Bool => {},
            .ComptimeInt => {
                var integer = @intCast(u64, o);
                len += try self.writeInt(integer);
            },
            .Int => {
                len += try self.writeInt(o);
            },
            .Array => |t| {
                if (t.child != u8) {
                    len += try self.writeList(o);
                } else {
                    len += try self.writeString(o[0..]);
                }
            },
            .Pointer => |t| {
                if (t.size == .One) {
                    len += try self.encode(o.*);
                } else {
                    len += try self.writeString(o[0..]);
                }
            },
            else => unreachable,
        }

        return len;
    }

    fn writeInt(self: *RLP, integer: anytype) !usize {
        if (integer < 0x7f) {
            try self.buf.append(@truncate(u8, integer));
            return 1;
        }

        var len: u8 = undefined;
        if (integer <= 0xff) {
            len = 1;
        } else if (len <= 0xffff) {
            len = 2;
        } else if (len <= 0xffffff) {
            len = 3;
        } else if (len <= 0xffffffff) {
            len = 4;
        } else if (len <= 0xffffffffff) {
            len = 5;
        } else if (len <= 0xffffffffffff) {
            len = 6;
        } else if (len <= 0xffffffffffffff) {
            len = 7;
        } else if (len <= 0xffffffffffffffff) {
            len = 8;
        }
        try self.buf.append(len + 0x80);
        const be = mem.nativeToBig(u64, @intCast(u64, integer));
        const bs = mem.asBytes(&be);
        try self.buf.appendSlice(bs.*[(bs.len - len)..]);
        return 1 + @intCast(usize, len);
    }

    fn writeString(self: *RLP, bytes: []const u8) !usize {
        var prefix_raw: [9]u8 = undefined;
        const prefix = RLP.encodeLen(0x80, bytes.len, &prefix_raw);
        try self.buf.appendSlice(prefix);
        try self.buf.appendSlice(bytes);
        return prefix.len + bytes.len;
    }

    fn writeList(self: *RLP, list: anytype) !usize {
        var len: usize = 0;
        for (list) |x| {
            len += try self.encode(x);
        }
        var prefix_raw: [9]u8 = undefined;
        const prefix = RLP.encodeLen(0xc0, len, &prefix_raw);
        try self.buf.insertSlice(0, prefix);
        return prefix.len + len;
    }

    fn encodeLen(comptime offset: u8, len: usize, out: *[9]u8) []u8 {
        if (len <= 55) {
            out[0] = @truncate(u8, len) + offset;
            return out.*[0..1];
        }

        var len_be = mem.nativeToBig(u64, @intCast(u64, len));
        var len_bs = mem.asBytes(&len_be);
        var len_slice: []u8 = undefined;
        if (len <= 0xff) {
            len_slice = len_bs.*[7..];
        } else if (len <= 0xffff) {
            len_slice = len_bs.*[6..];
        } else if (len <= 0xffffff) {
            len_slice = len_bs.*[5..];
        } else if (len <= 0xffffffff) {
            len_slice = len_bs.*[4..];
        } else if (len <= 0xffffffffff) {
            len_slice = len_bs.*[3..];
        } else if (len <= 0xffffffffffff) {
            len_slice = len_bs.*[2..];
        } else if (len <= 0xffffffffffffff) {
            len_slice = len_bs.*[1..];
        } else if (len <= 0xffffffffffffffff) {
            len_slice = len_bs.*[0..];
        }
        out[0] = offset + @as(u8, 55) + @truncate(u8, len_slice.len);
        mem.copy(u8, out[1..9], len_slice);
        return out[0..(1 + len_slice.len)];
    }

    pub fn slice(self: *RLP) []const u8 {
        return self.buf.items;
    }
};

const testing = std.testing;

fn testEncode(expected: []const u8, value: anytype) !void {
    const encoded = try encode(testing.allocator, value);
    defer testing.allocator.free(encoded);
    try testing.expect(mem.eql(u8, encoded, expected));
}

test "TestEncode" {
    try testEncode("\x00", 0);
    try testEncode("\x0f", 15);
    try testEncode("\x82\x04\x00", 1024);
    try testEncode("\x83dog", "dog");
    try testEncode("\xc0", [_][]const u8{});
    // try testEncode("\xc7\xc0\xc1\xc0\xc3\xc0\xc1\xc0", [_][][]const u8{ [_][]const u8{}, [_][]const u8{[_][]const u8{}}, [_][]const u8{ [_][]const u8{}, [_][]const u8{[_][]const u8{}} } });
    try testEncode("\xc8\x83cat\x83dog", [_][]const u8{ "cat", "dog" });
    try testEncode("\xb8\x38Lorem ipsum dolor sit amet, consectetur adipisicing elit", "Lorem ipsum dolor sit amet, consectetur adipisicing elit");
}
