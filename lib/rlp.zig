const mem = std.mem;
const std = @import("std");

pub fn encode(allocator: mem.Allocator, o: anytype) ![]const u8 {
    var rlp = RLPEncoder.init(allocator);
    defer rlp.deinit();

    _ = try rlp.encode(o);

    return rlp.buf.toOwnedSlice();
}

pub fn decode(allocator: mem.Allocator, buf: []const u8, dest: anytype) !void {
    _ = dest;
    const P = @TypeOf(dest);
    std.debug.assert(std.meta.trait.isSingleItemPtr(P));
    //     @compileError("expected single item pointer, passed " ++ @typeName(P));

    var rlp = RLPDecoder.init(allocator);

    _ = try rlp.decode(buf, dest);
}

fn isArrayList(comptime T: type) ?type {
    return switch (@typeInfo(T)) {
        .Struct => {
            if (!@hasDecl(T, "Slice")) {
                return null;
            } else if (T != std.ArrayList(@typeInfo(T.Slice).Pointer.child)) {
                return null;
            } else {
                return @typeInfo(T.Slice).Pointer.child;
            }
        },
        else => return undefined,
    };
}

const RLPEncoder = struct {
    allocator: mem.Allocator,
    buf: std.ArrayList(u8),

    pub fn init(allocator: mem.Allocator) RLPEncoder {
        return RLPEncoder{
            .allocator = allocator,
            .buf = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *RLPEncoder) void {
        self.buf.deinit();
    }

    pub fn encode(self: *RLPEncoder, o: anytype) !usize {
        var written_bytes: usize = 0;

        const T = @TypeOf(o);
        switch (@typeInfo(T)) {
            .Bool => {},
            .ComptimeInt => {
                var integer = @intCast(u64, o);
                written_bytes += try self.writeInt(integer);
            },
            .Int => {
                written_bytes += try self.writeInt(o);
            },
            .Array => |t| {
                if (t.child != u8) {
                    written_bytes += try self.writeList(o);
                } else {
                    written_bytes += try self.writeString(o[0..]);
                }
            },
            .Pointer => |t| {
                if (t.size == .One) {
                    written_bytes += try self.encode(o.*);
                } else {
                    written_bytes += try self.writeString(o[0..]);
                }
            },
            .Struct => |t| {
                if (T == std.ArrayList(u8)) {
                    written_bytes += try self.writeArrayListU8(o);
                } else if (isArrayList(T)) |E| {
                    _ = E;
                    written_bytes += try self.writeArrayList(o);
                } else {
                    inline for (t.fields) |f| {
                        switch (f.field_type) {
                            std.mem.Allocator => {},
                            else => {
                                written_bytes += try self.encode(@field(o, f.name));
                            },
                        }
                    }
                }
            },
            else => unreachable,
        }

        return written_bytes;
    }

    fn writeInt(self: *RLPEncoder, integer: anytype) !usize {
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

    fn writeString(self: *RLPEncoder, bytes: []const u8) !usize {
        var prefix_raw: [9]u8 = undefined;
        const prefix = RLPEncoder.encodeLen(0x80, bytes.len, &prefix_raw);
        try self.buf.appendSlice(prefix);
        try self.buf.appendSlice(bytes);
        return prefix.len + bytes.len;
    }

    fn writeArrayListU8(self: *RLPEncoder, list: std.ArrayList(u8)) !usize {
        var buf: [9]u8 = undefined;
        const prefix = RLPEncoder.encodeLen(0x80, list.items.len, &buf);
        try self.buf.appendSlice(prefix);
        try self.buf.appendSlice(list.items);
        return prefix.len + list.items.len;
    }

    fn writeArrayList(self: *RLPEncoder, list: anytype) !usize {
        const buf_pos = self.buf.items.len;
        var written_bytes: usize = 0;
        for (list.items) |x| {
            written_bytes += try self.encode(x);
        }
        var buf: [9]u8 = undefined;
        const prefix = RLPEncoder.encodeLen(0xc0, written_bytes, &buf);
        try self.buf.insertSlice(buf_pos, prefix);
        return prefix.len + written_bytes;
    }

    fn writeList(self: *RLPEncoder, list: anytype) !usize {
        const buf_pos = self.buf.items.len;
        var len: usize = 0;
        for (list) |x| {
            len += try self.encode(x);
        }
        var prefix_raw: [9]u8 = undefined;
        const prefix = RLPEncoder.encodeLen(0xc0, len, &prefix_raw);
        try self.buf.insertSlice(buf_pos, prefix);
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

    pub fn slice(self: *RLPEncoder) []const u8 {
        return self.buf.items;
    }
};

const RLPDecoder = struct {
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) RLPDecoder {
        return RLPDecoder{
            .allocator = allocator,
        };
    }

    pub fn decode(self: *RLPDecoder, buf: []const u8, dest: anytype) !usize {
        _ = self;
        _ = buf;
        _ = dest;
        var read_bytes: usize = 0;

        const P = @TypeOf(dest);
        const T = @typeInfo(P).Pointer.child;
        switch (@typeInfo(T)) {
            .Bool => {
                var integer = undefined;
                read_bytes += try self.readInt(buf, &integer);
                dest.* = integer != 0;
            },
            .Int => {
                read_bytes += try self.readInt(buf, dest);
            },
            .Struct => |t| {
                if (T == std.ArrayList(u8)) {
                    read_bytes += try self.readString(buf, dest);
                } else if (isArrayList(T)) |E| {
                    _ = E;
                    read_bytes += try self.readArrayList(buf, dest);
                } else {
                    inline for (t.fields) |f| {
                        switch (f.field_type) {
                            std.mem.Allocator => {},
                            else => {
                                read_bytes += try self.decode(buf[read_bytes..], &@field(dest, f.name));
                            },
                        }
                    }
                }
            },
            else => unreachable,
        }

        return read_bytes;
    }

    pub fn readInt(_: *RLPDecoder, buf: []const u8, out: *u64) !usize {
        if (buf[0] < 0x7f) {
            out.* = buf[0];
            return 1;
        }

        if (buf[0] > 0xb7) {
            unreachable; // TODO
        }
        const len: usize = buf[0] - 0x80;
        var bytes = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
        std.mem.copy(u8, bytes[(8 - len)..], buf[1..len]);
        const value = std.mem.bytesAsValue(u64, &bytes);
        out.* = std.mem.bigToNative(u64, value.*);

        return 1 + len;
    }

    fn readString(self: *RLPDecoder, bytes: []const u8, out: *std.ArrayList(u8)) !usize {
        _ = self;
        var len: usize = undefined;
        var read_bytes = RLPDecoder.decodeLen(0x80, bytes, &len);

        out.clearRetainingCapacity();
        try out.appendSlice(bytes[read_bytes..(read_bytes + len)]);

        return read_bytes + len;
    }

    fn readArrayList(self: *RLPDecoder, bytes: []const u8, out: anytype) !usize {
        var len: usize = undefined;
        var read_bytes = RLPDecoder.decodeLen(0xc0, bytes, &len);

        out.clearRetainingCapacity();
        while (read_bytes < len) {
            var item = try out.addOne();
            if (isArrayList(@TypeOf(item.*))) |E| {
                item.* = std.ArrayList(E).init(out.allocator);
            }
            read_bytes += try self.decode(bytes[read_bytes..], item);
        }

        return read_bytes;
    }

    fn decodeLen(comptime offset: u8, bytes: []const u8, out: *u64) usize {
        var prefix = bytes[0] - offset;
        if (prefix <= 55) {
            out.* = prefix;
            return 1;
        }

        prefix -= 55;
        var len_raw = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
        std.mem.copy(u8, len_raw[(8 - prefix)..], bytes[1..prefix]);
        const value = std.mem.bytesAsValue(u64, &len_raw);
        out.* = std.mem.bigToNative(u64, value.*);

        return 1 + prefix;
    }
};

const testing = std.testing;

const CatDog = struct {
    allocator: mem.Allocator,
    items: std.ArrayList(std.ArrayList(u8)) = undefined,

    pub fn init(allocator: mem.Allocator) CatDog {
        return CatDog{
            .allocator = allocator,
            .items = std.ArrayList(std.ArrayList(u8)).init(allocator),
        };
    }

    pub fn deinit(self: *CatDog) void {
        for (self.items.items) |x|
            x.deinit();
        self.items.deinit();
    }
};

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
    try testEncode("\xc8\x83cat\x83dog", [_][]const u8{ "cat", "dog" });
    try testEncode("\xb8\x38Lorem ipsum dolor sit amet, consectetur adipisicing elit", "Lorem ipsum dolor sit amet, consectetur adipisicing elit");

    // TODO:
    // try testEncode("\xc7\xc0\xc1\xc0\xc3\xc0\xc1\xc0", [_][][]const u8{ [_][]const u8{}, [_][]const u8{[_][]const u8{}}, [_][]const u8{ [_][]const u8{}, [_][]const u8{[_][]const u8{}} } });
}

test "TestEncodeCatDogStruct" {
    var catdog = CatDog.init(testing.allocator);
    defer catdog.deinit();
    var cat = try catdog.items.addOne();
    cat.* = std.ArrayList(u8).init(testing.allocator);
    try cat.appendSlice("cat");
    var dog = try catdog.items.addOne();
    dog.* = std.ArrayList(u8).init(testing.allocator);
    try dog.appendSlice("dog");

    const encoded = try encode(testing.allocator, catdog);
    defer testing.allocator.free(encoded);

    try testing.expect(mem.eql(u8, encoded, "\xc8\x83cat\x83dog"));
}

test "TestDecode" {
    {
        var decoded: u64 = undefined;

        _ = try decode(testing.allocator, "\x82\x04\x00", &decoded);

        try testing.expect(decoded == 1024);
    }

    {
        var decoded = std.ArrayList(u8).init(testing.allocator);

        _ = try decode(testing.allocator, "\x83dog", &decoded);
        defer decoded.deinit();

        try testing.expect(mem.eql(u8, decoded.items, "dog"));
    }

    {
        var decoded = CatDog.init(testing.allocator);
        _ = try decode(testing.allocator, "\xc8\x83cat\x83dog", &decoded);
        defer decoded.deinit();

        try testing.expect(decoded.items.items.len == 2);
        try testing.expect(mem.eql(u8, decoded.items.items[0].items, "cat"));
        try testing.expect(mem.eql(u8, decoded.items.items[1].items, "dog"));
    }
}
