const std = @import("std");

fn HexToSliceReturnType(comptime hex: []const u8) type {
    if (hex.len < 2 or hex.len % 2 != 0)
        @compileError("Input " ++ hex ++ " must have at least two characters");

    if (hex[0] == '0' and hex[1] == 'x')
        return [hex.len / 2 - 1]u8;

    return [hex.len / 2]u8;
}

fn hexDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => unreachable,
    };
}

pub fn hexToSlice(comptime hex: []const u8) HexToSliceReturnType(hex) {
    comptime var i = 0;
    comptime var j = 0;
    if (hex.len < 2 or hex.len % 2 != 0)
        @compileError("Input " ++ hex ++ " must have at least two characters");

    if (hex[0] == '0' and hex[1] == 'x')
        i += 2;

    var result: HexToSliceReturnType(hex) = undefined;
    inline while (i < hex.len) : (i += 2) {
        const num = @truncate(u8, (hexDigit(hex[i])) << 4) + hexDigit(hex[i + 1]);
        result[j] = num;
        j += 1;
    }

    return result;
}

const testing = std.testing;

test "TestHexToSlice" {
    const hash = hexToSlice("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
    try testing.expectEqualStrings(hash[0..], "\xd4\xe5\x67\x40\xf8\x76\xae\xf8\xc0\x10\xb8\x6a\x40\xd5\xf5\x67\x45\xa1\x18\xd0\x90\x6a\x34\xe6\x9a\xec\x8c\x0d\xb1\xcb\x8f\xa3");
}
