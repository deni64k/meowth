const mem = std.mem;
const std = @import("std");

// const RLP = struct {
//     allocator: mem.Allocator,
//     buf: std.ArrayList(u8),
//     len: usize = 0,

//     pub fn init(allocator: mem.Allocator) RLP {
//         return RLP{
//             .allocator = allocator,
//             .buf = std.ArrayList(u8).init(allocator),
//         };
//     }

//     pub fn deinit(self: *RLP) void {
//         self.buf.deinit();
//     }

//     pub fn encode(self: *RLP, o: anytype) !void {
//         const T = @TypeOf(o);
//         switch (@typeInfo(T)) {
//             .Bool => {},
//             .Int, .ComptimeInt => {
//                 if (o < 0x7f) {
//                     try self.buf.append(o);
//                     self.len += 1;
//                 } else {
//                     unreachable;
//                 }
//             },
//             else => unreachable,
//         }
//     }

//     pub fn slice(self: *RLP) []u8 {
//         return self.buf.items;
//     }
// };

const RLP = struct {
    allocator: mem.Allocator,
    buf: std.fifo.LinearFifo(u8, .Dynamic),

    pub fn init(allocator: mem.Allocator) RLP {
        return RLP{
            .allocator = allocator,
            .buf = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
        };
    }

    pub fn deinit(self: *RLP) void {
        self.buf.deinit();
    }

    pub fn encode(self: *RLP, o: anytype) !void {
        const T = @TypeOf(o);
        switch (@typeInfo(T)) {
            .Bool => {},
            .Int, .ComptimeInt => {
                if (o < 0x7f) {
                    try self.buf.writeItem(o);
                } else {
                    unreachable;
                }
            },
            .Array => |t| {
                if (t.child != u8) {
                    try self.writeList(o);
                } else if (o.len <= 55) {
                    try self.writeString(o[0..]);
                } else {
                    try self.writeLongString(o[0..]);
                }
            },
            .Pointer => |t| {
                if (t.size == .One) {
                    try self.encode(o.*);
                } else {
                    if (o.len <= 55) {
                        try self.writeString(o[0..]);
                    } else {
                        try self.writeLongString(o[0..]);
                    }
                }
            },
            else => unreachable,
        }
    }

    fn writeByte(self: *RLP, byte: u8) !void {
        std.debug.assert(byte <= 0x7f);
        return try self.buf.writeItem(byte);
    }

    fn writeString(self: *RLP, bytes: []const u8) !void {
        std.debug.assert(bytes.len <= 55);
        const len: u8 = 0x80 + @truncate(u8, bytes.len);
        try self.buf.writeItem(len);
        return try self.buf.write(bytes);
    }

    fn writeLongString(self: *RLP, bytes: []const u8) !void {
        std.debug.assert(bytes.len > 55);
        const len: u8 = 0xb8;

        var bytes_len_be: u64 = std.mem.nativeToLittle(u64, bytes.len);
        var bytes_len_slice: []u8 = undefined;
        if (bytes.len < 0xff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..1];
        } else if (bytes.len <= 0xffff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..2];
        } else if (bytes.len <= 0xffff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..3];
        } else if (bytes.len <= 0xffffff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..4];
        } else if (bytes.len <= 0xffffffff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..5];
        } else if (bytes.len <= 0xffffffffff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..6];
        } else if (bytes.len <= 0xffffffffffff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..7];
        } else if (bytes.len <= 0xffffffffffffff) {
            bytes_len_slice = mem.asBytes(&bytes_len_be).*[0..8];
        }
        try self.buf.writeItem(len + @truncate(u8, bytes_len_slice.len));
        try self.buf.write(bytes_len_slice);
        return try self.buf.write(bytes);
    }

    fn writeList(self: *RLP, list: anytype) !void {
        std.debug.assert(list.len <= 56);
        const len: u8 = 0xc0 + @truncate(u8, list.len);
        try self.buf.writeItem(len);
        for (list) |x| {
            try self.encode(x);
        }
    }

    pub fn slice(self: *RLP) []const u8 {
        return self.buf.readableSlice(0);
    }
};

pub fn encode(allocator: mem.Allocator, o: anytype) !void {
    const T = @TypeOf(o);
    switch (@typeInfo(T)) {
        .Bool => {},
        .Int, .ComptimeInt => {},
        else => unreachable,
    }
    var result: []u8 = try allocator.alloc(u8, 32);
    defer allocator.free(result);

    std.debug.print("result is {any}\n", .{result});
}

const expect = std.testing.expect;

test "EncodeInt" {
    const alloc = std.testing.allocator;
    try encode(alloc, 1);

    var rlp = RLP.init(alloc);
    defer rlp.deinit();
    try rlp.encode(1);
    try rlp.encode(42);
    try rlp.encode("abcd");
    try rlp.encode("ABCD");
    std.debug.print("rlp.slice is ", .{});

    for (rlp.slice()) |x| {
        std.debug.print("{x:0>2}", .{x});
    }
    std.debug.print("\n", .{});
}

test "EncodeDog" {
    const alloc = std.testing.allocator;

    var rlp = RLP.init(alloc);
    defer rlp.deinit();
    try rlp.encode("dog");
    std.debug.print("rlp.slice is ", .{});

    for (rlp.slice()) |x| {
        std.debug.print("{x:0>2}", .{x});
    }
    std.debug.print("\n", .{});
}

test "EncodeCatDog" {
    const alloc = std.testing.allocator;

    var rlp = RLP.init(alloc);
    defer rlp.deinit();
    const data: [2][]const u8 = [_][]const u8{ "cat", "dog" };
    try rlp.encode(data);
    std.debug.print("rlp.slice is ", .{});

    for (rlp.slice()) |x| {
        std.debug.print("{x:0>2}", .{x});
    }
    std.debug.print("\n", .{});
}

test "EncodeLoremIpsum" {
    const alloc = std.testing.allocator;

    var rlp = RLP.init(alloc);
    defer rlp.deinit();
    try rlp.encode("Lorem ipsum dolor sit amet, consectetur adipisicing elit");
    std.debug.print("rlp.slice is ", .{});

    for (rlp.slice()) |x| {
        std.debug.print("{x:0>2}", .{x});
    }
    std.debug.print("\n", .{});
}
