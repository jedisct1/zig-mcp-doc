```
f8Encode(replacement_character, &buf) catch unreachable) == 3);
        break :blk buf;
    };

    var dest_i: usize = 0;
    const view = try Wtf8View.init(wtf8);
    var it = view.iterator();
    while (it.nextCodepointSlice()) |codepoint_slice| {
        // All surrogate codepoints are encoded as 3 bytes
        if (codepoint_slice.len == 3) {
            const codepoint = wtf8Decode(codepoint_slice) catch unreachable;
            if (isSurrogateCodepoint(codepoint)) {
                @memcpy(utf8[dest_i..][0..replacement_char_bytes.len], &replacement_char_bytes);
                dest_i += replacement_char_bytes.len;
                continue;
            }
        }
        if (!in_place) {
            @memcpy(utf8[dest_i..][0..codepoint_slice.len], codepoint_slice);
        }
        dest_i += codepoint_slice.len;
    }
}

pub fn wtf8ToUtf8LossyAlloc(allocator: mem.Allocator, wtf8: []const u8) error{ InvalidWtf8, OutOfMemory }![]u8 {
    const utf8 = try allocator.alloc(u8, wtf8.len);
    errdefer allocator.free(utf8);

    try wtf8ToUtf8Lossy(utf8, wtf8);

    return utf8;
}

pub fn wtf8ToUtf8LossyAllocZ(allocator: mem.Allocator, wtf8: []const u8) error{ InvalidWtf8, OutOfMemory }![:0]u8 {
    const utf8 = try allocator.allocSentinel(u8, wtf8.len, 0);
    errdefer allocator.free(utf8);

    try wtf8ToUtf8Lossy(utf8, wtf8);

    return utf8;
}

test wtf8ToUtf8Lossy {
    var buf: [32]u8 = undefined;

    const invalid_utf8 = "\xff";
    try testing.expectError(error.InvalidWtf8, wtf8ToUtf8Lossy(&buf, invalid_utf8));

    const ascii = "abcd";
    try wtf8ToUtf8Lossy(&buf, ascii);
    try testing.expectEqualStrings("abcd", buf[0..ascii.len]);

    const high_surrogate_half = "ab\xed\xa0\xbdcd";
    try wtf8ToUtf8Lossy(&buf, high_surrogate_half);
    try testing.expectEqualStrings("ab\u{FFFD}cd", buf[0..high_surrogate_half.len]);

    const low_surrogate_half = "ab\xed\xb2\xa9cd";
    try wtf8ToUtf8Lossy(&buf, low_surrogate_half);
    try testing.expectEqualStrings("ab\u{FFFD}cd", buf[0..low_surrogate_half.len]);

    // If the WTF-8 is not well-formed, each surrogate half is converted into a separate
    // replacement character instead of being interpreted as a surrogate pair.
    const encoded_surrogate_pair = "ab\xed\xa0\xbd\xed\xb2\xa9cd";
    try wtf8ToUtf8Lossy(&buf, encoded_surrogate_pair);
    try testing.expectEqualStrings("ab\u{FFFD}\u{FFFD}cd", buf[0..encoded_surrogate_pair.len]);

    // in place
    @memcpy(buf[0..low_surrogate_half.len], low_surrogate_half);
    const slice = buf[0..low_surrogate_half.len];
    try wtf8ToUtf8Lossy(slice, slice);
    try testing.expectEqualStrings("ab\u{FFFD}cd", slice);
}

test wtf8ToUtf8LossyAlloc {
    const invalid_utf8 = "\xff";
    try testing.expectError(error.InvalidWtf8, wtf8ToUtf8LossyAlloc(testing.allocator, invalid_utf8));

    {
        const ascii = "abcd";
        const utf8 = try wtf8ToUtf8LossyAlloc(testing.allocator, ascii);
        defer testing.allocator.free(utf8);
        try testing.expectEqualStrings("abcd", utf8);
    }

    {
        const surrogate_half = "ab\xed\xa0\xbdcd";
        const utf8 = try wtf8ToUtf8LossyAlloc(testing.allocator, surrogate_half);
        defer testing.allocator.free(utf8);
        try testing.expectEqualStrings("ab\u{FFFD}cd", utf8);
    }

    {
        // If the WTF-8 is not well-formed, each surrogate half is converted into a separate
        // replacement character instead of being interpreted as a surrogate pair.
        const encoded_surrogate_pair = "ab\xed\xa0\xbd\xed\xb2\xa9cd";
        const utf8 = try wtf8ToUtf8LossyAlloc(testing.allocator, encoded_surrogate_pair);
        defer testing.allocator.free(utf8);
        try testing.expectEqualStrings("ab\u{FFFD}\u{FFFD}cd", utf8);
    }
}

test wtf8ToUtf8LossyAllocZ {
    const invalid_utf8 = "\xff";
    try testing.expectError(error.InvalidWtf8, wtf8ToUtf8LossyAllocZ(testing.allocator, invalid_utf8));

    {
        const ascii = "abcd";
        const utf8 = try wtf8ToUtf8LossyAllocZ(testing.allocator, ascii);
        defer testing.allocator.free(utf8);
        try testing.expectEqualStrings("abcd", utf8);
    }

    {
        const surrogate_half = "ab\xed\xa0\xbdcd";
        const utf8 = try wtf8ToUtf8LossyAllocZ(testing.allocator, surrogate_half);
        defer testing.allocator.free(utf8);
        try testing.expectEqualStrings("ab\u{FFFD}cd", utf8);
    }

    {
        // If the WTF-8 is not well-formed, each surrogate half is converted into a separate
        // replacement character instead of being interpreted as a surrogate pair.
        const encoded_surrogate_pair = "ab\xed\xa0\xbd\xed\xb2\xa9cd";
        const utf8 = try wtf8ToUtf8LossyAllocZ(testing.allocator, encoded_surrogate_pair);
        defer testing.allocator.free(utf8);
        try testing.expectEqualStrings("ab\u{FFFD}\u{FFFD}cd", utf8);
    }
}

pub const Wtf16LeIterator = struct {
    bytes: []const u8,
    i: usize,

    pub fn init(s: []const u16) Wtf16LeIterator {
        return Wtf16LeIterator{
            .bytes = mem.sliceAsBytes(s),
            .i = 0,
        };
    }

    /// If the next codepoint is encoded by a surrogate pair, returns the
    /// codepoint that the surrogate pair represents.
    /// If the next codepoint is an unpaired surrogate, returns the codepoint
    /// of the unpaired surrogate.
    pub fn nextCodepoint(it: *Wtf16LeIterator) ?u21 {
        assert(it.i <= it.bytes.len);
        if (it.i == it.bytes.len) return null;
        var code_units: [2]u16 = undefined;
        code_units[0] = mem.readInt(u16, it.bytes[it.i..][0..2], .little);
        it.i += 2;
        surrogate_pair: {
            if (utf16IsHighSurrogate(code_units[0])) {
                if (it.i >= it.bytes.len) break :surrogate_pair;
                code_units[1] = mem.readInt(u16, it.bytes[it.i..][0..2], .little);
                const codepoint = utf16DecodeSurrogatePair(&code_units) catch break :surrogate_pair;
                it.i += 2;
                return codepoint;
            }
        }
        return code_units[0];
    }
};

test "non-well-formed WTF-8 does not roundtrip" {
    // This encodes the surrogate pair U+D83D U+DCA9.
    // The well-formed version of this would be U+1F4A9 which is \xF0\x9F\x92\xA9.
    const non_well_formed_wtf8 = "\xed\xa0\xbd\xed\xb2\xa9";

    var wtf16_buf: [2]u16 = undefined;
    const wtf16_len = try wtf8ToWtf16Le(&wtf16_buf, non_well_formed_wtf8);
    const wtf16 = wtf16_buf[0..wtf16_len];

    try testing.expectEqualSlices(u16, &[_]u16{
        mem.nativeToLittle(u16, 0xD83D), // high surrogate
        mem.nativeToLittle(u16, 0xDCA9), // low surrogate
    }, wtf16);

    var wtf8_buf: [4]u8 = undefined;
    const wtf8_len = wtf16LeToWtf8(&wtf8_buf, wtf16);
    const wtf8 = wtf8_buf[0..wtf8_len];

    // Converting to WTF-16 and back results in well-formed WTF-8,
    // but it does not match the input WTF-8
    try testing.expectEqualSlices(u8, "\xf0\x9f\x92\xa9", wtf8);
}

fn testRoundtripWtf8(wtf8: []const u8) !void {
    // Buffer
    {
        var wtf16_buf: [32]u16 = undefined;
        const wtf16_len = try wtf8ToWtf16Le(&wtf16_buf, wtf8);
        try testing.expectEqual(wtf16_len, calcWtf16LeLen(wtf8));
        try testing.expectEqual(false, checkWtf8ToWtf16LeOverflow(wtf8, &wtf16_buf));
        const wtf16 = wtf16_buf[0..wtf16_len];

        var roundtripped_buf: [32]u8 = undefined;
        const roundtripped_len = wtf16LeToWtf8(&roundtripped_buf, wtf16);
        const roundtripped = roundtripped_buf[0..roundtripped_len];

        try testing.expectEqualSlices(u8, wtf8, roundtripped);
    }
    // Alloc
    {
        const wtf16 = try wtf8ToWtf16LeAlloc(testing.allocator, wtf8);
        defer testing.allocator.free(wtf16);

        const roundtripped = try wtf16LeToWtf8Alloc(testing.allocator, wtf16);
        defer testing.allocator.free(roundtripped);

        try testing.expectEqualSlices(u8, wtf8, roundtripped);
    }
    // AllocZ
    {
        const wtf16 = try wtf8ToWtf16LeAllocZ(testing.allocator, wtf8);
        defer testing.allocator.free(wtf16);

        const roundtripped = try wtf16LeToWtf8AllocZ(testing.allocator, wtf16);
        defer testing.allocator.free(roundtripped);

        try testing.expectEqualSlices(u8, wtf8, roundtripped);
    }
}

test "well-formed WTF-8 roundtrips" {
    try testRoundtripWtf8("\xed\x9f\xbf"); // not a surrogate half
    try testRoundtripWtf8("\xed\xa0\xbd"); // high surrogate
    try testRoundtripWtf8("\xed\xb2\xa9"); // low surrogate
    try testRoundtripWtf8("\xed\xa0\xbd \xed\xb2\xa9"); // <high surrogate><space><low surrogate>
    try testRoundtripWtf8("\xed\xa0\x80\xed\xaf\xbf"); // <high surrogate><high surrogate>
    try testRoundtripWtf8("\xed\xa0\x80\xee\x80\x80"); // <high surrogate><not surrogate>
    try testRoundtripWtf8("\xed\x9f\xbf\xed\xb0\x80"); // <not surrogate><low surrogate>
    try testRoundtripWtf8("a\xed\xb0\x80"); // <not surrogate><low surrogate>
    try testRoundtripWtf8("\xf0\x9f\x92\xa9"); // U+1F4A9, encoded as a surrogate pair in WTF-16
}

fn testRoundtripWtf16(wtf16le: []const u16) !void {
    // Buffer
    {
        var wtf8_buf: [32]u8 = undefined;
        const wtf8_len = wtf16LeToWtf8(&wtf8_buf, wtf16le);
        const wtf8 = wtf8_buf[0..wtf8_len];

        var roundtripped_buf: [32]u16 = undefined;
        const roundtripped_len = try wtf8ToWtf16Le(&roundtripped_buf, wtf8);
        const roundtripped = roundtripped_buf[0..roundtripped_len];

        try testing.expectEqualSlices(u16, wtf16le, roundtripped);
    }
    // Alloc
    {
        const wtf8 = try wtf16LeToWtf8Alloc(testing.allocator, wtf16le);
        defer testing.allocator.free(wtf8);

        const roundtripped = try wtf8ToWtf16LeAlloc(testing.allocator, wtf8);
        defer testing.allocator.free(roundtripped);

        try testing.expectEqualSlices(u16, wtf16le, roundtripped);
    }
    // AllocZ
    {
        const wtf8 = try wtf16LeToWtf8AllocZ(testing.allocator, wtf16le);
        defer testing.allocator.free(wtf8);

        const roundtripped = try wtf8ToWtf16LeAllocZ(testing.allocator, wtf8);
        defer testing.allocator.free(roundtripped);

        try testing.expectEqualSlices(u16, wtf16le, roundtripped);
    }
}

test "well-formed WTF-16 roundtrips" {
    try testRoundtripWtf16(&[_]u16{
        mem.nativeToLittle(u16, 0xD83D), // high surrogate
        mem.nativeToLittle(u16, 0xDCA9), // low surrogate
    });
    try testRoundtripWtf16(&[_]u16{
        mem.nativeToLittle(u16, 0xD83D), // high surrogate
        mem.nativeToLittle(u16, ' '), // not surrogate
        mem.nativeToLittle(u16, 0xDCA9), // low surrogate
    });
    try testRoundtripWtf16(&[_]u16{
        mem.nativeToLittle(u16, 0xD800), // high surrogate
        mem.nativeToLittle(u16, 0xDBFF), // high surrogate
    });
    try testRoundtripWtf16(&[_]u16{
        mem.nativeToLittle(u16, 0xD800), // high surrogate
        mem.nativeToLittle(u16, 0xE000), // not surrogate
    });
    try testRoundtripWtf16(&[_]u16{
        mem.nativeToLittle(u16, 0xD7FF), // not surrogate
        mem.nativeToLittle(u16, 0xDC00), // low surrogate
    });
    try testRoundtripWtf16(&[_]u16{
        mem.nativeToLittle(u16, 0x61), // not surrogate
        mem.nativeToLittle(u16, 0xDC00), // low surrogate
    });
    try testRoundtripWtf16(&[_]u16{
        mem.nativeToLittle(u16, 0xDC00), // low surrogate
    });
}

/// Returns the length, in bytes, that would be necessary to encode the
/// given WTF-16 LE slice as WTF-8.
pub fn calcWtf8Len(wtf16le: []const u16) usize {
    var it = Wtf16LeIterator.init(wtf16le);
    var num_wtf8_bytes: usize = 0;
    while (it.nextCodepoint()) |codepoint| {
        // Note: If utf8CodepointSequenceLength is ever changed to error on surrogate
        // codepoints, then it would no longer be eligible to be used in this context.
        num_wtf8_bytes += utf8CodepointSequenceLength(codepoint) catch |err| switch (err) {
            error.CodepointTooLarge => unreachable,
        };
    }
    return num_wtf8_bytes;
}

fn testCalcWtf8Len() !void {
    const L = utf8ToUtf16LeStringLiteral;
    try testing.expectEqual(@as(usize, 1), calcWtf8Len(L("a")));
    try testing.expectEqual(@as(usize, 10), calcWtf8Len(L("abcdefghij")));
    // unpaired surrogate
    try testing.expectEqual(@as(usize, 3), calcWtf8Len(&[_]u16{
        mem.nativeToLittle(u16, 0xD800),
    }));
    try testing.expectEqual(@as(usize, 15), calcWtf8Len(L("こんにちは")));
    // First codepoints that are encoded as 1, 2, 3, and 4 bytes
    try testing.expectEqual(@as(usize, 1 + 2 + 3 + 4), calcWtf8Len(L("\u{0}\u{80}\u{800}\u{10000}")));
}

test "calculate wtf8 string length of given wtf16 string" {
    try testCalcWtf8Len();
    try comptime testCalcWtf8Len();
}
const std = @import("std");
const time = std.time;
const unicode = std.unicode;

const Timer = time.Timer;

const N = 1_000_000;

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

const ResultCount = struct {
    count: usize,
    throughput: u64,
};

fn benchmarkCodepointCount(buf: []const u8) !ResultCount {
    var timer = try Timer.start();

    const bytes = N * buf.len;

    const start = timer.lap();
    var i: usize = 0;
    var r: usize = undefined;
    while (i < N) : (i += 1) {
        r = try @call(
            .never_inline,
            std.unicode.utf8CountCodepoints,
            .{buf},
        );
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(@as(f64, @floatFromInt(bytes)) / elapsed_s));

    return ResultCount{ .count = r, .throughput = throughput };
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print("short ASCII strings\n", .{});
    {
        const result = try benchmarkCodepointCount("abc");
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("short Unicode strings\n", .{});
    {
        const result = try benchmarkCodepointCount("ŌŌŌ");
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("pure ASCII strings\n", .{});
    {
        const result = try benchmarkCodepointCount("hello" ** 16);
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("pure Unicode strings\n", .{});
    {
        const result = try benchmarkCodepointCount("こんにちは" ** 16);
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }

    try stdout.print("mixed ASCII/Unicode strings\n", .{});
    {
        const result = try benchmarkCodepointCount("Hyvää huomenta" ** 16);
        try stdout.print("  count: {:5} MiB/s [{d}]\n", .{ result.throughput / (1 * MiB), result.count });
    }
}
//! Uniform Resource Identifier (URI) parsing roughly adhering to <https://tools.ietf.org/html/rfc3986>.
//! Does not do perfect grammar and character class checking, but should be robust against URIs in the wild.

scheme: []const u8,
user: ?Component = null,
password: ?Component = null,
host: ?Component = null,
port: ?u16 = null,
path: Component = Component.empty,
query: ?Component = null,
fragment: ?Component = null,

pub const Component = union(enum) {
    /// Invalid characters in this component must be percent encoded
    /// before being printed as part of a URI.
    raw: []const u8,
    /// This component is already percent-encoded, it can be printed
    /// directly as part of a URI.
    percent_encoded: []const u8,

    pub const empty: Component = .{ .percent_encoded = "" };

    pub fn isEmpty(component: Component) bool {
        return switch (component) {
            .raw, .percent_encoded => |string| string.len == 0,
        };
    }

    /// Allocates the result with `arena` only if needed, so the result should not be freed.
    pub fn toRawMaybeAlloc(
        component: Component,
        arena: std.mem.Allocator,
    ) std.mem.Allocator.Error![]const u8 {
        return switch (component) {
            .raw => |raw| raw,
            .percent_encoded => |percent_encoded| if (std.mem.indexOfScalar(u8, percent_encoded, '%')) |_|
                try std.fmt.allocPrint(arena, "{raw}", .{component})
            else
                percent_encoded,
        };
    }

    pub fn format(
        component: Component,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (fmt_str.len == 0) {
            try writer.print("std.Uri.Component{{ .{s} = \"{}\" }}", .{
                @tagName(component),
                std.zig.fmtEscapes(switch (component) {
                    .raw, .percent_encoded => |string| string,
                }),
            });
        } else if (comptime std.mem.eql(u8, fmt_str, "raw")) switch (component) {
            .raw => |raw| try writer.writeAll(raw),
            .percent_encoded => |percent_encoded| {
                var start: usize = 0;
                var index: usize = 0;
                while (std.mem.indexOfScalarPos(u8, percent_encoded, index, '%')) |percent| {
                    index = percent + 1;
                    if (percent_encoded.len - index < 2) continue;
                    const percent_encoded_char =
                        std.fmt.parseInt(u8, percent_encoded[index..][0..2], 16) catch continue;
                    try writer.print("{s}{c}", .{
                        percent_encoded[start..percent],
                        percent_encoded_char,
                    });
                    start = percent + 3;
                    index = percent + 3;
                }
                try writer.writeAll(percent_encoded[start..]);
            },
        } else if (comptime std.mem.eql(u8, fmt_str, "%")) switch (component) {
            .raw => |raw| try percentEncode(writer, raw, isUnreserved),
            .percent_encoded => |percent_encoded| try writer.writeAll(percent_encoded),
        } else if (comptime std.mem.eql(u8, fmt_str, "user")) switch (component) {
            .raw => |raw| try percentEncode(writer, raw, isUserChar),
            .percent_encoded => |percent_encoded| try writer.writeAll(percent_encoded),
        } else if (comptime std.mem.eql(u8, fmt_str, "password")) switch (component) {
            .raw => |raw| try percentEncode(writer, raw, isPasswordChar),
            .percent_encoded => |percent_encoded| try writer.writeAll(percent_encoded),
        } else if (comptime std.mem.eql(u8, fmt_str, "host")) switch (component) {
            .raw => |raw| try percentEncode(writer, raw, isHostChar),
            .percent_encoded => |percent_encoded| try writer.writeAll(percent_encoded),
        } else if (comptime std.mem.eql(u8, fmt_str, "path")) switch (component) {
            .raw => |raw| try percentEncode(writer, raw, isPathChar),
            .percent_encoded => |percent_encoded| try writer.writeAll(percent_encoded),
        } else if (comptime std.mem.eql(u8, fmt_str, "query")) switch (component) {
            .raw => |raw| try percentEncode(writer, raw, isQueryChar),
            .percent_encoded => |percent_encoded| try writer.writeAll(percent_encoded),
        } else if (comptime std.mem.eql(u8, fmt_str, "fragment")) switch (component) {
            .raw => |raw| try percentEncode(writer, raw, isFragmentChar),
            .percent_encoded => |percent_encoded| try writer.writeAll(percent_encoded),
        } else @compileError("invalid format string '" ++ fmt_str ++ "'");
    }

    pub fn percentEncode(
        writer: anytype,
        raw: []const u8,
        comptime isValidChar: fn (u8) bool,
    ) @TypeOf(writer).Error!void {
        var start: usize = 0;
        for (raw, 0..) |char, index| {
            if (isValidChar(char)) continue;
            try writer.print("{s}%{X:0>2}", .{ raw[start..index], char });
            start = index + 1;
        }
        try writer.writeAll(raw[start..]);
    }
};

/// Percent decodes all %XX where XX is a valid hex number.
/// `output` may alias `input` if `output.ptr <= input.ptr`.
/// Mutates and returns a subslice of `output`.
pub fn percentDecodeBackwards(output: []u8, input: []const u8) []u8 {
    var input_index = input.len;
    var output_index = output.len;
    while (input_index > 0) {
        if (input_index >= 3) {
            const maybe_percent_encoded = input[input_index - 3 ..][0..3];
            if (maybe_percent_encoded[0] == '%') {
                if (std.fmt.parseInt(u8, maybe_percent_encoded[1..], 16)) |percent_encoded_char| {
                    input_index -= maybe_percent_encoded.len;
                    output_index -= 1;
                    output[output_index] = percent_encoded_char;
                    continue;
                } else |_| {}
            }
        }
        input_index -= 1;
        output_index -= 1;
        output[output_index] = input[input_index];
    }
    return output[output_index..];
}

/// Percent decodes all %XX where XX is a valid hex number.
/// Mutates and returns a subslice of `buffer`.
pub fn percentDecodeInPlace(buffer: []u8) []u8 {
    return percentDecodeBackwards(buffer, buffer);
}

pub const ParseError = error{ UnexpectedCharacter, InvalidFormat, InvalidPort };

/// Parses the URI or returns an error. This function is not compliant, but is required to parse
/// some forms of URIs in the wild, such as HTTP Location headers.
/// The return value will contain strings pointing into the original `text`.
/// Each component that is provided, will be non-`null`.
pub fn parseAfterScheme(scheme: []const u8, text: []const u8) ParseError!Uri {
    var reader = SliceReader{ .slice = text };

    var uri: Uri = .{ .scheme = scheme, .path = undefined };

    if (reader.peekPrefix("//")) a: { // authority part
        std.debug.assert(reader.get().? == '/');
        std.debug.assert(reader.get().? == '/');

        const authority = reader.readUntil(isAuthoritySeparator);
        if (authority.len == 0) {
            if (reader.peekPrefix("/")) break :a else return error.InvalidFormat;
        }

        var start_of_host: usize = 0;
        if (std.mem.indexOf(u8, authority, "@")) |index| {
            start_of_host = index + 1;
            const user_info = authority[0..index];

            if (std.mem.indexOf(u8, user_info, ":")) |idx| {
                uri.user = .{ .percent_encoded = user_info[0..idx] };
                if (idx < user_info.len - 1) { // empty password is also "no password"
                    uri.password = .{ .percent_encoded = user_info[idx + 1 ..] };
                }
            } else {
                uri.user = .{ .percent_encoded = user_info };
                uri.password = null;
            }
        }

        // only possible if uri consists of only `userinfo@`
        if (start_of_host >= authority.len) break :a;

        var end_of_host: usize = authority.len;

        // if  we see `]` first without `@`
        if (authority[start_of_host] == ']') {
            return error.InvalidFormat;
        }

        if (authority.len > start_of_host and authority[start_of_host] == '[') { // IPv6
            end_of_host = std.mem.lastIndexOf(u8, authority, "]") orelse return error.InvalidFormat;
            end_of_host += 1;

            if (std.mem.lastIndexOf(u8, authority, ":")) |index| {
                if (index >= end_of_host) { // if not part of the V6 address field
                    end_of_host = @min(end_of_host, index);
                    uri.port = std.fmt.parseInt(u16, authority[index + 1 ..], 10) catch return error.InvalidPort;
                }
            }
        } else if (std.mem.lastIndexOf(u8, authority, ":")) |index| {
            if (index >= start_of_host) { // if not part of the userinfo field
                end_of_host = @min(end_of_host, index);
                uri.port = std.fmt.parseInt(u16, authority[index + 1 ..], 10) catch return error.InvalidPort;
            }
        }

        if (start_of_host >= end_of_host) return error.InvalidFormat;
        uri.host = .{ .percent_encoded = authority[start_of_host..end_of_host] };
    }

    uri.path = .{ .percent_encoded = reader.readUntil(isPathSeparator) };

    if ((reader.peek() orelse 0) == '?') { // query part
        std.debug.assert(reader.get().? == '?');
        uri.query = .{ .percent_encoded = reader.readUntil(isQuerySeparator) };
    }

    if ((reader.peek() orelse 0) == '#') { // fragment part
        std.debug.assert(reader.get().? == '#');
        uri.fragment = .{ .percent_encoded = reader.readUntilEof() };
    }

    return uri;
}

pub const WriteToStreamOptions = struct {
    /// When true, include the scheme part of the URI.
    scheme: bool = false,

    /// When true, include the user and password part of the URI. Ignored if `authority` is false.
    authentication: bool = false,

    /// When true, include the authority part of the URI.
    authority: bool = false,

    /// When true, include the path part of the URI.
    path: bool = false,

    /// When true, include the query part of the URI. Ignored when `path` is false.
    query: bool = false,

    /// When true, include the fragment part of the URI. Ignored when `path` is false.
    fragment: bool = false,

    /// When true, include the port part of the URI. Ignored when `port` is null.
    port: bool = true,
};

pub fn writeToStream(
    uri: Uri,
    options: WriteToStreamOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    if (options.scheme) {
        try writer.print("{s}:", .{uri.scheme});
        if (options.authority and uri.host != null) {
            try writer.writeAll("//");
        }
    }
    if (options.authority) {
        if (options.authentication and uri.host != null) {
            if (uri.user) |user| {
                try writer.print("{user}", .{user});
                if (uri.password) |password| {
                    try writer.print(":{password}", .{password});
                }
                try writer.writeByte('@');
            }
        }
        if (uri.host) |host| {
            try writer.print("{host}", .{host});
            if (options.port) {
                if (uri.port) |port| try writer.print(":{d}", .{port});
            }
        }
    }
    if (options.path) {
        try writer.print("{path}", .{
            if (uri.path.isEmpty()) Uri.Component{ .percent_encoded = "/" } else uri.path,
        });
        if (options.query) {
            if (uri.query) |query| try writer.print("?{query}", .{query});
        }
        if (options.fragment) {
            if (uri.fragment) |fragment| try writer.print("#{fragment}", .{fragment});
        }
    }
}

pub fn format(
    uri: Uri,
    comptime fmt_str: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    const scheme = comptime std.mem.indexOfScalar(u8, fmt_str, ';') != null or fmt_str.len == 0;
    const authentication = comptime std.mem.indexOfScalar(u8, fmt_str, '@') != null or fmt_str.len == 0;
    const authority = comptime std.mem.indexOfScalar(u8, fmt_str, '+') != null or fmt_str.len == 0;
    const path = comptime std.mem.indexOfScalar(u8, fmt_str, '/') != null or fmt_str.len == 0;
    const query = comptime std.mem.indexOfScalar(u8, fmt_str, '?') != null or fmt_str.len == 0;
    const fragment = comptime std.mem.indexOfScalar(u8, fmt_str, '#') != null or fmt_str.len == 0;

    return writeToStream(uri, .{
        .scheme = scheme,
        .authentication = authentication,
        .authority = authority,
        .path = path,
        .query = query,
        .fragment = fragment,
    }, writer);
}

/// Parses the URI or returns an error.
/// The return value will contain strings pointing into the
/// original `text`. Each component that is provided, will be non-`null`.
pub fn parse(text: []const u8) ParseError!Uri {
    var reader: SliceReader = .{ .slice = text };
    const scheme = reader.readWhile(isSchemeChar);

    // after the scheme, a ':' must appear
    if (reader.get()) |c| {
        if (c != ':')
            return error.UnexpectedCharacter;
    } else {
        return error.InvalidFormat;
    }

    return parseAfterScheme(scheme, reader.readUntilEof());
}

pub const ResolveInPlaceError = ParseError || error{NoSpaceLeft};

/// Resolves a URI against a base URI, conforming to RFC 3986, Section 5.
/// Copies `new` to the beginning of `aux_buf.*`, allowing the slices to overlap,
/// then parses `new` as a URI, and then resolves the path in place.
/// If a merge needs to take place, the newly constructed path will be stored
/// in `aux_buf.*` just after the copied `new`, and `aux_buf.*` will be modified
/// to only contain the remaining unused space.
pub fn resolve_inplace(base: Uri, new: []const u8, aux_buf: *[]u8) ResolveInPlaceError!Uri {
    std.mem.copyForwards(u8, aux_buf.*, new);
    // At this point, new is an invalid pointer.
    const new_mut = aux_buf.*[0..new.len];
    aux_buf.* = aux_buf.*[new.len..];

    const new_parsed = parse(new_mut) catch |err|
        (parseAfterScheme("", new_mut) catch return err);
    // As you can see above, `new_mut` is not a const pointer.
    const new_path: []u8 = @constCast(new_parsed.path.percent_encoded);

    if (new_parsed.scheme.len > 0) return .{
        .scheme = new_parsed.scheme,
        .user = new_parsed.user,
        .password = new_parsed.password,
        .host = new_parsed.host,
        .port = new_parsed.port,
        .path = remove_dot_segments(new_path),
        .query = new_parsed.query,
        .fragment = new_parsed.fragment,
    };

    if (new_parsed.host) |host| return .{
        .scheme = base.scheme,
        .user = new_parsed.user,
        .password = new_parsed.password,
        .host = host,
        .port = new_parsed.port,
        .path = remove_dot_segments(new_path),
        .query = new_parsed.query,
        .fragment = new_parsed.fragment,
    };

    const path, const query = if (new_path.len == 0) .{
        base.path,
        new_parsed.query orelse base.query,
    } else if (new_path[0] == '/') .{
        remove_dot_segments(new_path),
        new_parsed.query,
    } else .{
        try merge_paths(base.path, new_path, aux_buf),
        new_parsed.query,
    };

    return .{
        .scheme = base.scheme,
        .user = base.user,
        .password = base.password,
        .host = base.host,
        .port = base.port,
        .path = path,
        .query = query,
        .fragment = new_parsed.fragment,
    };
}

/// In-place implementation of RFC 3986, Section 5.2.4.
fn remove_dot_segments(path: []u8) Component {
    var in_i: usize = 0;
    var out_i: usize = 0;
    while (in_i < path.len) {
        if (std.mem.startsWith(u8, path[in_i..], "./")) {
            in_i += 2;
        } else if (std.mem.startsWith(u8, path[in_i..], "../")) {
            in_i += 3;
        } else if (std.mem.startsWith(u8, path[in_i..], "/./")) {
            in_i += 2;
        } else if (std.mem.eql(u8, path[in_i..], "/.")) {
            in_i += 1;
            path[in_i] = '/';
        } else if (std.mem.startsWith(u8, path[in_i..], "/../")) {
            in_i += 3;
            while (out_i > 0) {
                out_i -= 1;
                if (path[out_i] == '/') break;
            }
        } else if (std.mem.eql(u8, path[in_i..], "/..")) {
            in_i += 2;
            path[in_i] = '/';
            while (out_i > 0) {
                out_i -= 1;
                if (path[out_i] == '/') break;
            }
        } else if (std.mem.eql(u8, path[in_i..], ".")) {
            in_i += 1;
        } else if (std.mem.eql(u8, path[in_i..], "..")) {
            in_i += 2;
        } else {
            while (true) {
                path[out_i] = path[in_i];
                out_i += 1;
                in_i += 1;
                if (in_i >= path.len or path[in_i] == '/') break;
            }
        }
    }
    return .{ .percent_encoded = path[0..out_i] };
}

test remove_dot_segments {
    {
        var buffer = "/a/b/c/./../../g".*;
        try std.testing.expectEqualStrings("/a/g", remove_dot_segments(&buffer).percent_encoded);
    }
}

/// 5.2.3. Merge Paths
fn merge_paths(base: Component, new: []u8, aux_buf: *[]u8) error{NoSpaceLeft}!Component {
    var aux = std.io.fixedBufferStream(aux_buf.*);
    if (!base.isEmpty()) {
        try aux.writer().print("{path}", .{base});
        aux.pos = std.mem.lastIndexOfScalar(u8, aux.getWritten(), '/') orelse
            return remove_dot_segments(new);
    }
    try aux.writer().print("/{s}", .{new});
    const merged_path = remove_dot_segments(aux.getWritten());
    aux_buf.* = aux_buf.*[merged_path.percent_encoded.len..];
    return merged_path;
}

const SliceReader = struct {
    const Self = @This();

    slice: []const u8,
    offset: usize = 0,

    fn get(self: *Self) ?u8 {
        if (self.offset >= self.slice.len)
            return null;
        const c = self.slice[self.offset];
        self.offset += 1;
        return c;
    }

    fn peek(self: Self) ?u8 {
        if (self.offset >= self.slice.len)
            return null;
        return self.slice[self.offset];
    }

    fn readWhile(self: *Self, comptime predicate: fn (u8) bool) []const u8 {
        const start = self.offset;
        var end = start;
        while (end < self.slice.len and predicate(self.slice[end])) {
            end += 1;
        }
        self.offset = end;
        return self.slice[start..end];
    }

    fn readUntil(self: *Self, comptime predicate: fn (u8) bool) []const u8 {
        const start = self.offset;
        var end = start;
        while (end < self.slice.len and !predicate(self.slice[end])) {
            end += 1;
        }
        self.offset = end;
        return self.slice[start..end];
    }

    fn readUntilEof(self: *Self) []const u8 {
        const start = self.offset;
        self.offset = self.slice.len;
        return self.slice[start..];
    }

    fn peekPrefix(self: Self, prefix: []const u8) bool {
        if (self.offset + prefix.len > self.slice.len)
            return false;
        return std.mem.eql(u8, self.slice[self.offset..][0..prefix.len], prefix);
    }
};

/// scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
fn isSchemeChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '+', '-', '.' => true,
        else => false,
    };
}

/// reserved    = gen-delims / sub-delims
fn isReserved(c: u8) bool {
    return isGenLimit(c) or isSubLimit(c);
}

/// gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
fn isGenLimit(c: u8) bool {
    return switch (c) {
        ':', ',', '?', '#', '[', ']', '@' => true,
        else => false,
    };
}

/// sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
///             / "*" / "+" / "," / ";" / "="
fn isSubLimit(c: u8) bool {
    return switch (c) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

/// unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

fn isUserChar(c: u8) bool {
    return isUnreserved(c) or isSubLimit(c);
}

fn isPasswordChar(c: u8) bool {
    return isUserChar(c) or c == ':';
}

fn isHostChar(c: u8) bool {
    return isPasswordChar(c) or c == '[' or c == ']';
}

fn isPathChar(c: u8) bool {
    return isUserChar(c) or c == '/' or c == ':' or c == '@';
}

fn isQueryChar(c: u8) bool {
    return isPathChar(c) or c == '?';
}

const isFragmentChar = isQueryChar;

fn isAuthoritySeparator(c: u8) bool {
    return switch (c) {
        '/', '?', '#' => true,
        else => false,
    };
}

fn isPathSeparator(c: u8) bool {
    return switch (c) {
        '?', '#' => true,
        else => false,
    };
}

fn isQuerySeparator(c: u8) bool {
    return switch (c) {
        '#' => true,
        else => false,
    };
}

test "basic" {
    const parsed = try parse("https://ziglang.org/download");
    try testing.expectEqualStrings("https", parsed.scheme);
    try testing.expectEqualStrings("ziglang.org", parsed.host.?.percent_encoded);
    try testing.expectEqualStrings("/download", parsed.path.percent_encoded);
    try testing.expectEqual(@as(?u16, null), parsed.port);
}

test "with port" {
    const parsed = try parse("http://example:1337/");
    try testing.expectEqualStrings("http", parsed.scheme);
    try testing.expectEqualStrings("example", parsed.host.?.percent_encoded);
    try testing.expectEqualStrings("/", parsed.path.percent_encoded);
    try testing.expectEqual(@as(?u16, 1337), parsed.port);
}

test "should fail gracefully" {
    try std.testing.expectError(error.InvalidFormat, parse("foobar://"));
}

test "file" {
    const parsed = try parse("file:///");
    try std.testing.expectEqualStrings("file", parsed.scheme);
    try std.testing.expectEqual(@as(?Component, null), parsed.host);
    try std.testing.expectEqualStrings("/", parsed.path.percent_encoded);

    const parsed2 = try parse("file:///an/absolute/path/to/something");
    try std.testing.expectEqualStrings("file", parsed2.scheme);
    try std.testing.expectEqual(@as(?Component, null), parsed2.host);
    try std.testing.expectEqualStrings("/an/absolute/path/to/something", parsed2.path.percent_encoded);

    const parsed3 = try parse("file://localhost/an/absolute/path/to/another/thing/");
    try std.testing.expectEqualStrings("file", parsed3.scheme);
    try std.testing.expectEqualStrings("localhost", parsed3.host.?.percent_encoded);
    try std.testing.expectEqualStrings("/an/absolute/path/to/another/thing/", parsed3.path.percent_encoded);
}

test "scheme" {
    try std.testing.expectEqualStrings("http", (try parse("http:_")).scheme);
    try std.testing.expectEqualStrings("scheme-mee", (try parse("scheme-mee:_")).scheme);
    try std.testing.expectEqualStrings("a.b.c", (try parse("a.b.c:_")).scheme);
    try std.testing.expectEqualStrings("ab+", (try parse("ab+:_")).scheme);
    try std.testing.expectEqualStrings("X+++", (try parse("X+++:_")).scheme);
    try std.testing.expectEqualStrings("Y+-.", (try parse("Y+-.:_")).scheme);
}

test "authority" {
    try std.testing.expectEqualStrings("hostname", (try parse("scheme://hostname")).host.?.percent_encoded);

    try std.testing.expectEqualStrings("hostname", (try parse("scheme://userinfo@hostname")).host.?.percent_encoded);
    try std.testing.expectEqualStrings("userinfo", (try parse("scheme://userinfo@hostname")).user.?.percent_encoded);
    try std.testing.expectEqual(@as(?Component, null), (try parse("scheme://userinfo@hostname")).password);
    try std.testing.expectEqual(@as(?Component, null), (try parse("scheme://userinfo@")).host);

    try std.testing.expectEqualStrings("hostname", (try parse("scheme://user:password@hostname")).host.?.percent_encoded);
    try std.testing.expectEqualStrings("user", (try parse("scheme://user:password@hostname")).user.?.percent_encoded);
    try std.testing.expectEqualStrings("password", (try parse("scheme://user:password@hostname")).password.?.percent_encoded);

    try std.testing.expectEqualStrings("hostname", (try parse("scheme://hostname:0")).host.?.percent_encoded);
    try std.testing.expectEqual(@as(u16, 1234), (try parse("scheme://hostname:1234")).port.?);

    try std.testing.expectEqualStrings("hostname", (try parse("scheme://userinfo@hostname:1234")).host.?.percent_encoded);
    try std.testing.expectEqual(@as(u16, 1234), (try parse("scheme://userinfo@hostname:1234")).port.?);
    try std.testing.expectEqualStrings("userinfo", (try parse("scheme://userinfo@hostname:1234")).user.?.percent_encoded);
    try std.testing.expectEqual(@as(?Component, null), (try parse("scheme://userinfo@hostname:1234")).password);

    try std.testing.expectEqualStrings("hostname", (try parse("scheme://user:password@hostname:1234")).host.?.percent_encoded);
    try std.testing.expectEqual(@as(u16, 1234), (try parse("scheme://user:password@hostname:1234")).port.?);
    try std.testing.expectEqualStrings("user", (try parse("scheme://user:password@hostname:1234")).user.?.percent_encoded);
    try std.testing.expectEqualStrings("password", (try parse("scheme://user:password@hostname:1234")).password.?.percent_encoded);
}

test "authority.password" {
    try std.testing.expectEqualStrings("username", (try parse("scheme://username@a")).user.?.percent_encoded);
    try std.testing.expectEqual(@as(?Component, null), (try parse("scheme://username@a")).password);

    try std.testing.expectEqualStrings("username", (try parse("scheme://username:@a")).user.?.percent_encoded);
    try std.testing.expectEqual(@as(?Component, null), (try parse("scheme://username:@a")).password);

    try std.testing.expectEqualStrings("username", (try parse("scheme://username:password@a")).user.?.percent_encoded);
    try std.testing.expectEqualStrings("password", (try parse("scheme://username:password@a")).password.?.percent_encoded);

    try std.testing.expectEqualStrings("username", (try parse("scheme://username::@a")).user.?.percent_encoded);
    try std.testing.expectEqualStrings(":", (try parse("scheme://username::@a")).password.?.percent_encoded);
}

fn testAuthorityHost(comptime hostlist: anytype) !void {
    inline for (hostlist) |hostname| {
        try std.testing.expectEqualStrings(hostname, (try parse("scheme://" ++ hostname)).host.?.percent_encoded);
    }
}

test "authority.dns-names" {
    try testAuthorityHost(.{
        "a",
        "a.b",
        "example.com",
        "www.example.com",
        "example.org.",
        "www.example.org.",
        "xn--nw2a.xn--j6w193g", // internationalized URI: 見.香港
        "fe80--1ff-fe23-4567-890as3.ipv6-literal.net",
    });
}

test "authority.IPv4" {
    try testAuthorityHost(.{
        "127.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "8.8.8.8",
        "1.2.3.4",
        "192.168.0.1",
        "10.42.0.0",
    });
}

test "authority.IPv6" {
    try testAuthorityHost(.{
        "[2001:db8:0:0:0:0:2:1]",
        "[2001:db8::2:1]",
        "[2001:db8:0000:1:1:1:1:1]",
        "[2001:db8:0:1:1:1:1:1]",
        "[0:0:0:0:0:0:0:0]",
        "[0:0:0:0:0:0:0:1]",
        "[::1]",
        "[::]",
        "[2001:db8:85a3:8d3:1319:8a2e:370:7348]",
        "[fe80::1ff:fe23:4567:890a%25eth2]",
        "[fe80::1ff:fe23:4567:890a]",
        "[fe80::1ff:fe23:4567:890a%253]",
        "[fe80:3::1ff:fe23:4567:890a]",
    });
}

test "RFC example 1" {
    const uri = "foo://example.com:8042/over/there?name=ferret#nose";
    try std.testing.expectEqual(Uri{
        .scheme = uri[0..3],
        .user = null,
        .password = null,
        .host = .{ .percent_encoded = uri[6..17] },
        .port = 8042,
        .path = .{ .percent_encoded = uri[22..33] },
        .query = .{ .percent_encoded = uri[34..45] },
        .fragment = .{ .percent_encoded = uri[46..50] },
    }, try parse(uri));
}

test "RFC example 2" {
    const uri = "urn:example:animal:ferret:nose";
    try std.testing.expectEqual(Uri{
        .scheme = uri[0..3],
        .user = null,
        .password = null,
        .host = null,
        .port = null,
        .path = .{ .percent_encoded = uri[4..] },
        .query = null,
        .fragment = null,
    }, try parse(uri));
}

// source:
// https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Examples
test "Examples from wikipedia" {
    const list = [_][]const u8{
        "https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top",
        "ldap://[2001:db8::7]/c=GB?objectClass?one",
        "mailto:John.Doe@example.com",
        "news:comp.infosystems.www.servers.unix",
        "tel:+1-816-555-1212",
        "telnet://192.0.2.16:80/",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        "http://a/b/c/d;p?q",
    };
    for (list) |uri| {
        _ = try parse(uri);
    }
}

// source:
// https://tools.ietf.org/html/rfc3986#section-5.4.1
test "Examples from RFC3986" {
    const list = [_][]const u8{
        "http://a/b/c/g",
        "http://a/b/c/g",
        "http://a/b/c/g/",
        "http://a/g",
        "http://g",
        "http://a/b/c/d;p?y",
        "http://a/b/c/g?y",
        "http://a/b/c/d;p?q#s",
        "http://a/b/c/g#s",
        "http://a/b/c/g?y#s",
        "http://a/b/c/;x",
        "http://a/b/c/g;x",
        "http://a/b/c/g;x?y#s",
        "http://a/b/c/d;p?q",
        "http://a/b/c/",
        "http://a/b/c/",
        "http://a/b/",
        "http://a/b/",
        "http://a/b/g",
        "http://a/",
        "http://a/",
        "http://a/g",
    };
    for (list) |uri| {
        _ = try parse(uri);
    }
}

test "Special test" {
    // This is for all of you code readers ♥
    _ = try parse("https://www.youtube.com/watch?v=dQw4w9WgXcQ&feature=youtu.be&t=0");
}

test "URI percent encoding" {
    try std.testing.expectFmt(
        "%5C%C3%B6%2F%20%C3%A4%C3%B6%C3%9F%20~~.adas-https%3A%2F%2Fcanvas%3A123%2F%23ads%26%26sad",
        "{%}",
        .{Component{ .raw = "\\ö/ äöß ~~.adas-https://canvas:123/#ads&&sad" }},
    );
}

test "URI percent decoding" {
    {
        const expected = "\\ö/ äöß ~~.adas-https://canvas:123/#ads&&sad";
        var input = "%5C%C3%B6%2F%20%C3%A4%C3%B6%C3%9F%20~~.adas-https%3A%2F%2Fcanvas%3A123%2F%23ads%26%26sad".*;

        try std.testing.expectFmt(expected, "{raw}", .{Component{ .percent_encoded = &input }});

        var output: [expected.len]u8 = undefined;
        try std.testing.expectEqualStrings(percentDecodeBackwards(&output, &input), expected);

        try std.testing.expectEqualStrings(expected, percentDecodeInPlace(&input));
    }

    {
        const expected = "/abc%";
        var input = expected.*;

        try std.testing.expectFmt(expected, "{raw}", .{Component{ .percent_encoded = &input }});

        var output: [expected.len]u8 = undefined;
        try std.testing.expectEqualStrings(percentDecodeBackwards(&output, &input), expected);

        try std.testing.expectEqualStrings(expected, percentDecodeInPlace(&input));
    }
}

test "URI query encoding" {
    const address = "https://objects.githubusercontent.com/?response-content-type=application%2Foctet-stream";
    const parsed = try Uri.parse(address);

    // format the URI to percent encode it
    try std.testing.expectFmt("/?response-content-type=application%2Foctet-stream", "{/?}", .{parsed});
}

test "format" {
    const uri: Uri = .{
        .scheme = "file",
        .user = null,
        .password = null,
        .host = null,
        .port = null,
        .path = .{ .raw = "/foo/bar/baz" },
        .query = null,
        .fragment = null,
    };
    try std.testing.expectFmt("file:/foo/bar/baz", "{;/?#}", .{uri});
}

test "URI malformed input" {
    try std.testing.expectError(error.InvalidFormat, std.Uri.parse("http://]["));
    try std.testing.expectError(error.InvalidFormat, std.Uri.parse("http://]@["));
    try std.testing.expectError(error.InvalidFormat, std.Uri.parse("http://lo]s\x85hc@[/8\x10?0Q"));
}

const std = @import("std.zig");
const testing = std.testing;
const Uri = @This();
const builtin = @import("builtin");
const std = @import("std.zig");
const math = std.math;

pub fn doClientRequest(default: usize, request: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    if (!builtin.valgrind_support) {
        return default;
    }

    const args = &[_]usize{ request, a1, a2, a3, a4, a5 };

    return switch (builtin.cpu.arch) {
        .arm, .armeb, .thumb, .thumbeb => asm volatile (
            \\ mov r12, r12, ror #3  ; mov r12, r12, ror #13
            \\ mov r12, r12, ror #29 ; mov r12, r12, ror #19
            \\ orr r10, r10, r10
            : [_] "={r3}" (-> usize),
            : [_] "{r4}" (args),
              [_] "{r3}" (default),
            : "cc", "memory"
        ),
        .aarch64, .aarch64_be => asm volatile (
            \\ ror x12, x12, #3  ; ror x12, x12, #13
            \\ ror x12, x12, #51 ; ror x12, x12, #61
            \\ orr x10, x10, x10
            : [_] "={x3}" (-> usize),
            : [_] "{x4}" (args),
              [_] "{x3}" (default),
            : "cc", "memory"
        ),
        .mips, .mipsel => asm volatile (
            \\ srl $0,  $0,  13
            \\ srl $0,  $0,  29
            \\ srl $0,  $0,  3
            \\ srl $0,  $0,  19
            \\ or  $13, $13, $13
            : [_] "={$11}" (-> usize),
            : [_] "{$12}" (args),
              [_] "{$11}" (default),
            : "memory"
        ),
        .mips64, .mips64el => asm volatile (
            \\ dsll $0,  $0,  3   ; dsll $0, $0, 13
            \\ dsll $0,  $0,  29  ; dsll $0, $0, 19
            \\ or   $13, $13, $13
            : [_] "={$11}" (-> usize),
            : [_] "{$12}" (args),
              [_] "{$11}" (default),
            : "memory"
        ),
        .powerpc, .powerpcle => asm volatile (
            \\ rlwinm 0, 0, 3,  0, 31 ; rlwinm 0, 0, 13, 0, 31
            \\ rlwinm 0, 0, 29, 0, 31 ; rlwinm 0, 0, 19, 0, 31
            \\ or     1, 1, 1
            : [_] "={r3}" (-> usize),
            : [_] "{r4}" (args),
              [_] "{r3}" (default),
            : "cc", "memory"
        ),
        .powerpc64, .powerpc64le => asm volatile (
            \\ rotldi 0, 0, 3  ; rotldi 0, 0, 13
            \\ rotldi 0, 0, 61 ; rotldi 0, 0, 51
            \\ or     1, 1, 1
            : [_] "={r3}" (-> usize),
            : [_] "{r4}" (args),
              [_] "{r3}" (default),
            : "cc", "memory"
        ),
        .s390x => asm volatile (
            \\ lr %%r15, %%r15
            \\ lr %%r1,  %%r1
            \\ lr %%r2,  %%r2
            \\ lr %%r3,  %%r3
            \\ lr %%r2,  %%r2
            : [_] "={r3}" (-> usize),
            : [_] "{r2}" (args),
              [_] "{r3}" (default),
            : "cc", "memory"
        ),
        .x86 => asm volatile (
            \\ roll  $3,    %%edi ; roll $13, %%edi
            \\ roll  $29,   %%edi ; roll $19, %%edi
            \\ xchgl %%ebx, %%ebx
            : [_] "={edx}" (-> usize),
            : [_] "{eax}" (args),
              [_] "{edx}" (default),
            : "cc", "memory"
        ),
        .x86_64 => asm volatile (
            \\ rolq  $3,    %%rdi ; rolq $13, %%rdi
            \\ rolq  $61,   %%rdi ; rolq $51, %%rdi
            \\ xchgq %%rbx, %%rbx
            : [_] "={rdx}" (-> usize),
            : [_] "{rax}" (args),
              [_] "{rdx}" (default),
            : "cc", "memory"
        ),
        else => default,
    };
}

pub const ClientRequest = enum(u32) {
    RunningOnValgrind = 4097,
    DiscardTranslations = 4098,
    ClientCall0 = 4353,
    ClientCall1 = 4354,
    ClientCall2 = 4355,
    ClientCall3 = 4356,
    CountErrors = 4609,
    GdbMonitorCommand = 4610,
    MalloclikeBlock = 4865,
    ResizeinplaceBlock = 4875,
    FreelikeBlock = 4866,
    CreateMempool = 4867,
    DestroyMempool = 4868,
    MempoolAlloc = 4869,
    MempoolFree = 4870,
    MempoolTrim = 4871,
    MoveMempool = 4872,
    MempoolChange = 4873,
    MempoolExists = 4874,
    Printf = 5121,
    PrintfBacktrace = 5122,
    PrintfValistByRef = 5123,
    PrintfBacktraceValistByRef = 5124,
    StackRegister = 5377,
    StackDeregister = 5378,
    StackChange = 5379,
    LoadPdbDebuginfo = 5633,
    MapIpToSrcloc = 5889,
    ChangeErrDisablement = 6145,
    VexInitForIri = 6401,
    InnerThreads = 6402,
};
pub fn ToolBase(base: [2]u8) u32 {
    return (@as(u32, base[0] & 0xff) << 24) | (@as(u32, base[1] & 0xff) << 16);
}
pub fn IsTool(base: [2]u8, code: usize) bool {
    return ToolBase(base) == (code & 0xffff0000);
}

fn doClientRequestExpr(default: usize, request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return doClientRequest(default, @as(usize, @intCast(@intFromEnum(request))), a1, a2, a3, a4, a5);
}

fn doClientRequestStmt(request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) void {
    _ = doClientRequestExpr(0, request, a1, a2, a3, a4, a5);
}

/// Returns the number of Valgrinds this code is running under.  That
/// is, 0 if running natively, 1 if running under Valgrind, 2 if
/// running under Valgrind which is running under another Valgrind,
/// etc.
pub fn runningOnValgrind() usize {
    return doClientRequestExpr(0, .RunningOnValgrind, 0, 0, 0, 0, 0);
}

test "works whether running on valgrind or not" {
    _ = runningOnValgrind();
}

/// Discard translation of code in the slice qzz.  Useful if you are debugging
/// a JITter or some such, since it provides a way to make sure valgrind will
/// retranslate the invalidated area.  Returns no value.
pub fn discardTranslations(qzz: []const u8) void {
    doClientRequestStmt(.DiscardTranslations, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

pub fn innerThreads(qzz: [*]u8) void {
    doClientRequestStmt(.InnerThreads, @intFromPtr(qzz), 0, 0, 0, 0);
}

pub fn nonSimdCall0(func: fn (usize) usize) usize {
    return doClientRequestExpr(0, .ClientCall0, @intFromPtr(func), 0, 0, 0, 0);
}

pub fn nonSimdCall1(func: fn (usize, usize) usize, a1: usize) usize {
    return doClientRequestExpr(0, .ClientCall1, @intFromPtr(func), a1, 0, 0, 0);
}

pub fn nonSimdCall2(func: fn (usize, usize, usize) usize, a1: usize, a2: usize) usize {
    return doClientRequestExpr(0, .ClientCall2, @intFromPtr(func), a1, a2, 0, 0);
}

pub fn nonSimdCall3(func: fn (usize, usize, usize, usize) usize, a1: usize, a2: usize, a3: usize) usize {
    return doClientRequestExpr(0, .ClientCall3, @intFromPtr(func), a1, a2, a3, 0);
}

/// Deprecated: use `nonSimdCall0`
pub const nonSIMDCall0 = nonSimdCall0;

/// Deprecated: use `nonSimdCall1`
pub const nonSIMDCall1 = nonSimdCall1;

/// Deprecated: use `nonSimdCall2`
pub const nonSIMDCall2 = nonSimdCall2;

/// Deprecated: use `nonSimdCall3`
pub const nonSIMDCall3 = nonSimdCall3;

/// Counts the number of errors that have been recorded by a tool.  Nb:
/// the tool must record the errors with VG_(maybe_record_error)() or
/// VG_(unique_error)() for them to be counted.
pub fn countErrors() usize {
    return doClientRequestExpr(0, // default return
        .CountErrors, 0, 0, 0, 0, 0);
}

pub fn mallocLikeBlock(mem: []u8, rzB: usize, is_zeroed: bool) void {
    doClientRequestStmt(.MalloclikeBlock, @intFromPtr(mem.ptr), mem.len, rzB, @intFromBool(is_zeroed), 0);
}

pub fn resizeInPlaceBlock(oldmem: []u8, newsize: usize, rzB: usize) void {
    doClientRequestStmt(.ResizeinplaceBlock, @intFromPtr(oldmem.ptr), oldmem.len, newsize, rzB, 0);
}

pub fn freeLikeBlock(addr: [*]u8, rzB: usize) void {
    doClientRequestStmt(.FreelikeBlock, @intFromPtr(addr), rzB, 0, 0, 0);
}

/// Create a memory pool.
pub const MempoolFlags = struct {
    pub const AutoFree = 1;
    pub const MetaPool = 2;
};
pub fn createMempool(pool: [*]u8, rzB: usize, is_zeroed: bool, flags: usize) void {
    doClientRequestStmt(.CreateMempool, @intFromPtr(pool), rzB, @intFromBool(is_zeroed), flags, 0);
}

/// Destroy a memory pool.
pub fn destroyMempool(pool: [*]u8) void {
    doClientRequestStmt(.DestroyMempool, @intFromPtr(pool), 0, 0, 0, 0);
}

/// Associate a piece of memory with a memory pool.
pub fn mempoolAlloc(pool: [*]u8, mem: []u8) void {
    doClientRequestStmt(.MempoolAlloc, @intFromPtr(pool), @intFromPtr(mem.ptr), mem.len, 0, 0);
}

/// Disassociate a piece of memory from a memory pool.
pub fn mempoolFree(pool: [*]u8, addr: [*]u8) void {
    doClientRequestStmt(.MempoolFree, @intFromPtr(pool), @intFromPtr(addr), 0, 0, 0);
}

/// Disassociate any pieces outside a particular range.
pub fn mempoolTrim(pool: [*]u8, mem: []u8) void {
    doClientRequestStmt(.MempoolTrim, @intFromPtr(pool), @intFromPtr(mem.ptr), mem.len, 0, 0);
}

/// Resize and/or move a piece associated with a memory pool.
pub fn moveMempool(poolA: [*]u8, poolB: [*]u8) void {
    doClientRequestStmt(.MoveMempool, @intFromPtr(poolA), @intFromPtr(poolB), 0, 0, 0);
}

/// Resize and/or move a piece associated with a memory pool.
pub fn mempoolChange(pool: [*]u8, addrA: [*]u8, mem: []u8) void {
    doClientRequestStmt(.MempoolChange, @intFromPtr(pool), @intFromPtr(addrA), @intFromPtr(mem.ptr), mem.len, 0);
}

/// Return if a mempool exists.
pub fn mempoolExists(pool: [*]u8) bool {
    return doClientRequestExpr(0, .MempoolExists, @intFromPtr(pool), 0, 0, 0, 0) != 0;
}

/// Mark a piece of memory as being a stack. Returns a stack id.
/// start is the lowest addressable stack byte, end is the highest
/// addressable stack byte.
pub fn stackRegister(stack: []u8) usize {
    return doClientRequestExpr(0, .StackRegister, @intFromPtr(stack.ptr), @intFromPtr(stack.ptr) + stack.len, 0, 0, 0);
}

/// Unmark the piece of memory associated with a stack id as being a stack.
pub fn stackDeregister(id: usize) void {
    doClientRequestStmt(.StackDeregister, id, 0, 0, 0, 0);
}

/// Change the start and end address of the stack id.
/// start is the new lowest addressable stack byte, end is the new highest
/// addressable stack byte.
pub fn stackChange(id: usize, newstack: []u8) void {
    doClientRequestStmt(.StackChange, id, @intFromPtr(newstack.ptr), @intFromPtr(newstack.ptr) + newstack.len, 0, 0);
}

// Load PDB debug info for Wine PE image_map.
// pub fn loadPdbDebuginfo(fd, ptr, total_size, delta) void {
//     doClientRequestStmt(.LoadPdbDebuginfo,
//         fd, ptr, total_size, delta,
//         0);
// }

/// Map a code address to a source file name and line number.  buf64
/// must point to a 64-byte buffer in the caller's address space. The
/// result will be dumped in there and is guaranteed to be zero
/// terminated.  If no info is found, the first byte is set to zero.
pub fn mapIpToSrcloc(addr: *const u8, buf64: [64]u8) usize {
    return doClientRequestExpr(0, .MapIpToSrcloc, @intFromPtr(addr), @intFromPtr(&buf64[0]), 0, 0, 0);
}

/// Disable error reporting for this thread.  Behaves in a stack like
/// way, so you can safely call this multiple times provided that
/// enableErrorReporting() is called the same number of times
/// to re-enable reporting.  The first call of this macro disables
/// reporting.  Subsequent calls have no effect except to increase the
/// number of enableErrorReporting() calls needed to re-enable
/// reporting.  Child threads do not inherit this setting from their
/// parents -- they are always created with reporting enabled.
pub fn disableErrorReporting() void {
    doClientRequestStmt(.ChangeErrDisablement, 1, 0, 0, 0, 0);
}

/// Re-enable error reporting. (see disableErrorReporting())
pub fn enableErrorReporting() void {
    doClientRequestStmt(.ChangeErrDisablement, math.maxInt(usize), 0, 0, 0, 0);
}

/// Execute a monitor command from the client program.
/// If a connection is opened with GDB, the output will be sent
/// according to the output mode set for vgdb.
/// If no connection is opened, output will go to the log output.
/// Returns 1 if command not recognised, 0 otherwise.
pub fn monitorCommand(command: [*]u8) bool {
    return doClientRequestExpr(0, .GdbMonitorCommand, @intFromPtr(command), 0, 0, 0, 0) != 0;
}

pub const memcheck = @import("valgrind/memcheck.zig");
pub const callgrind = @import("valgrind/callgrind.zig");
pub const cachegrind = @import("valgrind/cachegrind.zig");

test {
    _ = memcheck;
    _ = callgrind;
    _ = cachegrind;
}
const std = @import("../std.zig");
const valgrind = std.valgrind;

pub const ClientRequest = enum(usize) {
    StartInstrumentation = valgrind.ToolBase("CG".*),
    StopInstrumentation,
};

fn doClientRequestExpr(default: usize, request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return valgrind.doClientRequest(default, @as(usize, @intCast(@intFromEnum(request))), a1, a2, a3, a4, a5);
}

fn doClientRequestStmt(request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) void {
    _ = doClientRequestExpr(0, request, a1, a2, a3, a4, a5);
}

/// Start Cachegrind instrumentation if not already enabled. Use this in
/// combination with `std.valgrind.cachegrind.stopInstrumentation` and
/// `--instr-at-start` to measure only part of a client program's execution.
pub fn startInstrumentation() void {
    doClientRequestStmt(.StartInstrumentation, 0, 0, 0, 0, 0);
}

/// Stop Cachegrind instrumentation if not already disabled. Use this in
/// combination with `std.valgrind.cachegrind.startInstrumentation` and
/// `--instr-at-start` to measure only part of a client program's execution.
pub fn stopInstrumentation() void {
    doClientRequestStmt(.StopInstrumentation, 0, 0, 0, 0, 0);
}
const std = @import("../std.zig");
const valgrind = std.valgrind;

pub const ClientRequest = enum(usize) {
    DumpStats = valgrind.ToolBase("CT".*),
    ZeroStats,
    ToggleCollect,
    DumpStatsAt,
    StartInstrumentation,
    StopInstrumentation,
};

pub const CallgrindClientRequest = @compileError("std.valgrind.callgrind.CallgrindClientRequest renamed to std.valgrind.callgrind.ClientRequest");

fn doClientRequestExpr(default: usize, request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return valgrind.doClientRequest(default, @as(usize, @intCast(@intFromEnum(request))), a1, a2, a3, a4, a5);
}

fn doClientRequestStmt(request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) void {
    _ = doClientRequestExpr(0, request, a1, a2, a3, a4, a5);
}

/// Dump current state of cost centers, and zero them afterwards
pub fn dumpStats() void {
    doClientRequestStmt(.DumpStats, 0, 0, 0, 0, 0);
}

/// Dump current state of cost centers, and zero them afterwards.
/// The argument is appended to a string stating the reason which triggered
/// the dump. This string is written as a description field into the
/// profile data dump.
pub fn dumpStatsAt(pos_str: [*:0]const u8) void {
    doClientRequestStmt(.DumpStatsAt, @intFromPtr(pos_str), 0, 0, 0, 0);
}

/// Zero cost centers
pub fn zeroStats() void {
    doClientRequestStmt(.ZeroStats, 0, 0, 0, 0, 0);
}

/// Toggles collection state.
/// The collection state specifies whether the happening of events
/// should be noted or if they are to be ignored. Events are noted
/// by increment of counters in a cost center
pub fn toggleCollect() void {
    doClientRequestStmt(.ToggleCollect, 0, 0, 0, 0, 0);
}

/// Start full callgrind instrumentation if not already switched on.
/// When cache simulation is done, it will flush the simulated cache;
/// this will lead to an artificial cache warmup phase afterwards with
/// cache misses which would not have happened in reality.
pub fn startInstrumentation() void {
    doClientRequestStmt(.StartInstrumentation, 0, 0, 0, 0, 0);
}

/// Stop full callgrind instrumentation if not already switched off.
/// This flushes Valgrinds translation cache, and does no additional
/// instrumentation afterwards, which effectively will run at the same
/// speed as the "none" tool (ie. at minimal slowdown).
/// Use this to bypass Callgrind aggregation for uninteresting code parts.
/// To start Callgrind in this mode to ignore the setup phase, use
/// the option "--instr-atstart=no".
pub fn stopInstrumentation() void {
    doClientRequestStmt(.StopInstrumentation, 0, 0, 0, 0, 0);
}
const std = @import("../std.zig");
const testing = std.testing;
const valgrind = std.valgrind;

pub const ClientRequest = enum(usize) {
    MakeMemNoAccess = valgrind.ToolBase("MC".*),
    MakeMemUndefined,
    MakeMemDefined,
    Discard,
    CheckMemIsAddressable,
    CheckMemIsDefined,
    DoLeakCheck,
    CountLeaks,
    GetVbits,
    SetVbits,
    CreateBlock,
    MakeMemDefinedIfAddressable,
    CountLeakBlocks,
    EnableAddrErrorReportingInRange,
    DisableAddrErrorReportingInRange,
};

pub const MemCheckClientRequest = @compileError("std.valgrind.memcheck.MemCheckClientRequest renamed to std.valgrind.memcheck.ClientRequest");

fn doClientRequestExpr(default: usize, request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return valgrind.doClientRequest(default, @as(usize, @intCast(@intFromEnum(request))), a1, a2, a3, a4, a5);
}

fn doClientRequestStmt(request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) void {
    _ = doClientRequestExpr(0, request, a1, a2, a3, a4, a5);
}

/// Mark memory at qzz.ptr as unaddressable for qzz.len bytes.
pub fn makeMemNoAccess(qzz: []const u8) void {
    _ = doClientRequestExpr(0, // default return
        .MakeMemNoAccess, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Mark memory at qzz.ptr as addressable but undefined for qzz.len bytes.
pub fn makeMemUndefined(qzz: []const u8) void {
    _ = doClientRequestExpr(0, // default return
        .MakeMemUndefined, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Mark memory at qzz.ptr as addressable and defined or qzz.len bytes.
pub fn makeMemDefined(qzz: []const u8) void {
    _ = doClientRequestExpr(0, // default return
        .MakeMemDefined, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Similar to makeMemDefined except that addressability is
/// not altered: bytes which are addressable are marked as defined,
/// but those which are not addressable are left unchanged.
pub fn makeMemDefinedIfAddressable(qzz: []const u8) void {
    _ = doClientRequestExpr(0, // default return
        .MakeMemDefinedIfAddressable, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Create a block-description handle.  The description is an ascii
/// string which is included in any messages pertaining to addresses
/// within the specified memory range.  Has no other effect on the
/// properties of the memory range.
pub fn createBlock(qzz: []const u8, desc: [*:0]const u8) usize {
    return doClientRequestExpr(0, // default return
        .CreateBlock, @intFromPtr(qzz.ptr), qzz.len, @intFromPtr(desc), 0, 0);
}

/// Discard a block-description-handle. Returns 1 for an
/// invalid handle, 0 for a valid handle.
pub fn discard(blkindex: usize) bool {
    return doClientRequestExpr(0, // default return
        .Discard, 0, blkindex, 0, 0, 0) != 0;
}

/// Check that memory at qzz.ptr is addressable for qzz.len bytes.
/// If suitable addressability is not established, Valgrind prints an
/// error message and returns the address of the first offending byte.
/// Otherwise it returns zero.
pub fn checkMemIsAddressable(qzz: []const u8) usize {
    return doClientRequestExpr(0, .CheckMemIsAddressable, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Check that memory at qzz.ptr is addressable and defined for
/// qzz.len bytes.  If suitable addressability and definedness are not
/// established, Valgrind prints an error message and returns the
/// address of the first offending byte.  Otherwise it returns zero.
pub fn checkMemIsDefined(qzz: []const u8) usize {
    return doClientRequestExpr(0, .CheckMemIsDefined, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

/// Do a full memory leak check (like --leak-check=full) mid-execution.
pub fn doLeakCheck() void {
    doClientRequestStmt(.DoLeakCheck, 0, 0, 0, 0, 0);
}

/// Same as doLeakCheck() but only showing the entries for
/// which there was an increase in leaked bytes or leaked nr of blocks
/// since the previous leak search.
pub fn doAddedLeakCheck() void {
    doClientRequestStmt(.DoLeakCheck, 0, 1, 0, 0, 0);
}

/// Same as doAddedLeakCheck() but showing entries with
/// increased or decreased leaked bytes/blocks since previous leak
/// search.
pub fn doChangedLeakCheck() void {
    doClientRequestStmt(.DoLeakCheck, 0, 2, 0, 0, 0);
}

/// Do a summary memory leak check (like --leak-check=summary) mid-execution.
pub fn doQuickLeakCheck() void {
    doClientRequestStmt(.DoLeakCheck, 1, 0, 0, 0, 0);
}

/// Return number of leaked, dubious, reachable and suppressed bytes found by
/// all previous leak checks.
const CountResult = struct {
    leaked: usize,
    dubious: usize,
    reachable: usize,
    suppressed: usize,
};

pub fn countLeaks() CountResult {
    var res: CountResult = .{
        .leaked = 0,
        .dubious = 0,
        .reachable = 0,
        .suppressed = 0,
    };
    doClientRequestStmt(
        .CountLeaks,
        @intFromPtr(&res.leaked),
        @intFromPtr(&res.dubious),
        @intFromPtr(&res.reachable),
        @intFromPtr(&res.suppressed),
        0,
    );
    return res;
}

test countLeaks {
    try testing.expectEqual(
        @as(CountResult, .{
            .leaked = 0,
            .dubious = 0,
            .reachable = 0,
            .suppressed = 0,
        }),
        countLeaks(),
    );
}

pub fn countLeakBlocks() CountResult {
    var res: CountResult = .{
        .leaked = 0,
        .dubious = 0,
        .reachable = 0,
        .suppressed = 0,
    };
    doClientRequestStmt(
        .CountLeakBlocks,
        @intFromPtr(&res.leaked),
        @intFromPtr(&res.dubious),
        @intFromPtr(&res.reachable),
        @intFromPtr(&res.suppressed),
        0,
    );
    return res;
}

test countLeakBlocks {
    try testing.expectEqual(
        @as(CountResult, .{
            .leaked = 0,
            .dubious = 0,
            .reachable = 0,
            .suppressed = 0,
        }),
        countLeakBlocks(),
    );
}

/// Get the validity data for addresses zza and copy it
/// into the provided zzvbits array.  Return values:
///    0   if not running on valgrind
///    1   success
///    2   [previously indicated unaligned arrays;  these are now allowed]
///    3   if any parts of zzsrc/zzvbits are not addressable.
/// The metadata is not copied in cases 0, 2 or 3 so it should be
/// impossible to segfault your system by using this call.
pub fn getVbits(zza: []u8, zzvbits: []u8) u2 {
    std.debug.assert(zzvbits.len >= zza.len / 8);
    return @as(u2, @intCast(doClientRequestExpr(0, .GetVbits, @intFromPtr(zza.ptr), @intFromPtr(zzvbits.ptr), zza.len, 0, 0)));
}

/// Set the validity data for addresses zza, copying it
/// from the provided zzvbits array.  Return values:
///    0   if not running on valgrind
///    1   success
///    2   [previously indicated unaligned arrays;  these are now allowed]
///    3   if any parts of zza/zzvbits are not addressable.
/// The metadata is not copied in cases 0, 2 or 3 so it should be
/// impossible to segfault your system by using this call.
pub fn setVbits(zzvbits: []u8, zza: []u8) u2 {
    std.debug.assert(zzvbits.len >= zza.len / 8);
    return @as(u2, @intCast(doClientRequestExpr(0, .SetVbits, @intFromPtr(zza.ptr), @intFromPtr(zzvbits.ptr), zza.len, 0, 0)));
}

/// Disable and re-enable reporting of addressing errors in the
/// specified address range.
pub fn disableAddrErrorReportingInRange(qzz: []u8) usize {
    return doClientRequestExpr(0, // default return
        .DisableAddrErrorReportingInRange, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}

pub fn enableAddrErrorReportingInRange(qzz: []u8) usize {
    return doClientRequestExpr(0, // default return
        .EnableAddrErrorReportingInRange, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0);
}
///! Contains all constants and types representing the wasm
///! binary format, as specified by:
///! https://webassembly.github.io/spec/core/
const std = @import("std.zig");
const testing = std.testing;

/// Wasm instruction opcodes
///
/// All instructions are defined as per spec:
/// https://webassembly.github.io/spec/core/appendix/index-instructions.html
pub const Opcode = enum(u8) {
    @"unreachable" = 0x00,
    nop = 0x01,
    block = 0x02,
    loop = 0x03,
    @"if" = 0x04,
    @"else" = 0x05,
    end = 0x0B,
    br = 0x0C,
    br_if = 0x0D,
    br_table = 0x0E,
    @"return" = 0x0F,
    call = 0x10,
    call_indirect = 0x11,
    drop = 0x1A,
    select = 0x1B,
    local_get = 0x20,
    local_set = 0x21,
    local_tee = 0x22,
    global_get = 0x23,
    global_set = 0x24,
    i32_load = 0x28,
    i64_load = 0x29,
    f32_load = 0x2A,
    f64_load = 0x2B,
    i32_load8_s = 0x2C,
    i32_load8_u = 0x2D,
    i32_load16_s = 0x2E,
    i32_load16_u = 0x2F,
    i64_load8_s = 0x30,
    i64_load8_u = 0x31,
    i64_load16_s = 0x32,
    i64_load16_u = 0x33,
    i64_load32_s = 0x34,
    i64_load32_u = 0x35,
    i32_store = 0x36,
    i64_store = 0x37,
    f32_store = 0x38,
    f64_store = 0x39,
    i32_store8 = 0x3A,
    i32_store16 = 0x3B,
    i64_store8 = 0x3C,
    i64_store16 = 0x3D,
    i64_store32 = 0x3E,
    memory_size = 0x3F,
    memory_grow = 0x40,
    i32_const = 0x41,
    i64_const = 0x42,
    f32_const = 0x43,
    f64_const = 0x44,
    i32_eqz = 0x45,
    i32_eq = 0x46,
    i32_ne = 0x47,
    i32_lt_s = 0x48,
    i32_lt_u = 0x49,
    i32_gt_s = 0x4A,
    i32_gt_u = 0x4B,
    i32_le_s = 0x4C,
    i32_le_u = 0x4D,
    i32_ge_s = 0x4E,
    i32_ge_u = 0x4F,
    i64_eqz = 0x50,
    i64_eq = 0x51,
    i64_ne = 0x52,
    i64_lt_s = 0x53,
    i64_lt_u = 0x54,
    i64_gt_s = 0x55,
    i64_gt_u = 0x56,
    i64_le_s = 0x57,
    i64_le_u = 0x58,
    i64_ge_s = 0x59,
    i64_ge_u = 0x5A,
    f32_eq = 0x5B,
    f32_ne = 0x5C,
    f32_lt = 0x5D,
    f32_gt = 0x5E,
    f32_le = 0x5F,
    f32_ge = 0x60,
    f64_eq = 0x61,
    f64_ne = 0x62,
    f64_lt = 0x63,
    f64_gt = 0x64,
    f64_le = 0x65,
    f64_ge = 0x66,
    i32_clz = 0x67,
    i32_ctz = 0x68,
    i32_popcnt = 0x69,
    i32_add = 0x6A,
    i32_sub = 0x6B,
    i32_mul = 0x6C,
    i32_div_s = 0x6D,
    i32_div_u = 0x6E,
    i32_rem_s = 0x6F,
    i32_rem_u = 0x70,
    i32_and = 0x71,
    i32_or = 0x72,
    i32_xor = 0x73,
    i32_shl = 0x74,
    i32_shr_s = 0x75,
    i32_shr_u = 0x76,
    i32_rotl = 0x77,
    i32_rotr = 0x78,
    i64_clz = 0x79,
    i64_ctz = 0x7A,
    i64_popcnt = 0x7B,
    i64_add = 0x7C,
    i64_sub = 0x7D,
    i64_mul = 0x7E,
    i64_div_s = 0x7F,
    i64_div_u = 0x80,
    i64_rem_s = 0x81,
    i64_rem_u = 0x82,
    i64_and = 0x83,
    i64_or = 0x84,
    i64_xor = 0x85,
    i64_shl = 0x86,
    i64_shr_s = 0x87,
    i64_shr_u = 0x88,
    i64_rotl = 0x89,
    i64_rotr = 0x8A,
    f32_abs = 0x8B,
    f32_neg = 0x8C,
    f32_ceil = 0x8D,
    f32_floor = 0x8E,
    f32_trunc = 0x8F,
    f32_nearest = 0x90,
    f32_sqrt = 0x91,
    f32_add = 0x92,
    f32_sub = 0x93,
    f32_mul = 0x94,
    f32_div = 0x95,
    f32_min = 0x96,
    f32_max = 0x97,
    f32_copysign = 0x98,
    f64_abs = 0x99,
    f64_neg = 0x9A,
    f64_ceil = 0x9B,
    f64_floor = 0x9C,
    f64_trunc = 0x9D,
    f64_nearest = 0x9E,
    f64_sqrt = 0x9F,
    f64_add = 0xA0,
    f64_sub = 0xA1,
    f64_mul = 0xA2,
    f64_div = 0xA3,
    f64_min = 0xA4,
    f64_max = 0xA5,
    f64_copysign = 0xA6,
    i32_wrap_i64 = 0xA7,
    i32_trunc_f32_s = 0xA8,
    i32_trunc_f32_u = 0xA9,
    i32_trunc_f64_s = 0xAA,
    i32_trunc_f64_u = 0xAB,
    i64_extend_i32_s = 0xAC,
    i64_extend_i32_u = 0xAD,
    i64_trunc_f32_s = 0xAE,
    i64_trunc_f32_u = 0xAF,
    i64_trunc_f64_s = 0xB0,
    i64_trunc_f64_u = 0xB1,
    f32_convert_i32_s = 0xB2,
    f32_convert_i32_u = 0xB3,
    f32_convert_i64_s = 0xB4,
    f32_convert_i64_u = 0xB5,
    f32_demote_f64 = 0xB6,
    f64_convert_i32_s = 0xB7,
    f64_convert_i32_u = 0xB8,
    f64_convert_i64_s = 0xB9,
    f64_convert_i64_u = 0xBA,
    f64_promote_f32 = 0xBB,
    i32_reinterpret_f32 = 0xBC,
    i64_reinterpret_f64 = 0xBD,
    f32_reinterpret_i32 = 0xBE,
    f64_reinterpret_i64 = 0xBF,
    i32_extend8_s = 0xC0,
    i32_extend16_s = 0xC1,
    i64_extend8_s = 0xC2,
    i64_extend16_s = 0xC3,
    i64_extend32_s = 0xC4,

    misc_prefix = 0xFC,
    simd_prefix = 0xFD,
    atomics_prefix = 0xFE,
    _,
};

/// Opcodes that require a prefix `0xFC`.
/// Each opcode represents a varuint32, meaning
/// they are encoded as leb128 in binary.
pub const MiscOpcode = enum(u32) {
    i32_trunc_sat_f32_s = 0x00,
    i32_trunc_sat_f32_u = 0x01,
    i32_trunc_sat_f64_s = 0x02,
    i32_trunc_sat_f64_u = 0x03,
    i64_trunc_sat_f32_s = 0x04,
    i64_trunc_sat_f32_u = 0x05,
    i64_trunc_sat_f64_s = 0x06,
    i64_trunc_sat_f64_u = 0x07,
    memory_init = 0x08,
    data_drop = 0x09,
    memory_copy = 0x0A,
    memory_fill = 0x0B,
    table_init = 0x0C,
    elem_drop = 0x0D,
    table_copy = 0x0E,
    table_grow = 0x0F,
    table_size = 0x10,
    table_fill = 0x11,
    _,
};

/// Simd opcodes that require a prefix `0xFD`.
/// Each opcode represents a varuint32, meaning
/// they are encoded as leb128 in binary.
pub const SimdOpcode = enum(u32) {
    v128_load = 0x00,
    v128_load8x8_s = 0x01,
    v128_load8x8_u = 0x02,
    v128_load16x4_s = 0x03,
    v128_load16x4_u = 0x04,
    v128_load32x2_s = 0x05,
    v128_load32x2_u = 0x06,
    v128_load8_splat = 0x07,
    v128_load16_splat = 0x08,
    v128_load32_splat = 0x09,
    v128_load64_splat = 0x0A,
    v128_store = 0x0B,
    v128_const = 0x0C,
    i8x16_shuffle = 0x0D,
    i8x16_swizzle = 0x0E,
    i8x16_splat = 0x0F,
    i16x8_splat = 0x10,
    i32x4_splat = 0x11,
    i64x2_splat = 0x12,
    f32x4_splat = 0x13,
    f64x2_splat = 0x14,
    i8x16_extract_lane_s = 0x15,
    i8x16_extract_lane_u = 0x16,
    i8x16_replace_lane = 0x17,
    i16x8_extract_lane_s = 0x18,
    i16x8_extract_lane_u = 0x19,
    i16x8_replace_lane = 0x1A,
    i32x4_extract_lane = 0x1B,
    i32x4_replace_lane = 0x1C,
    i64x2_extract_lane = 0x1D,
    i64x2_replace_lane = 0x1E,
    f32x4_extract_lane = 0x1F,
    f32x4_replace_lane = 0x20,
    f64x2_extract_lane = 0x21,
    f64x2_replace_lane = 0x22,
    i8x16_eq = 0x23,
    i16x8_eq = 0x2D,
    i32x4_eq = 0x37,
    i8x16_ne = 0x24,
    i16x8_ne = 0x2E,
    i32x4_ne = 0x38,
    i8x16_lt_s = 0x25,
    i16x8_lt_s = 0x2F,
    i32x4_lt_s = 0x39,
    i8x16_lt_u = 0x26,
    i16x8_lt_u = 0x30,
    i32x4_lt_u = 0x3A,
    i8x16_gt_s = 0x27,
    i16x8_gt_s = 0x31,
    i32x4_gt_s = 0x3B,
    i8x16_gt_u = 0x28,
    i16x8_gt_u = 0x32,
    i32x4_gt_u = 0x3C,
    i8x16_le_s = 0x29,
    i16x8_le_s = 0x33,
    i32x4_le_s = 0x3D,
    i8x16_le_u = 0x2A,
    i16x8_le_u = 0x34,
    i32x4_le_u = 0x3E,
    i8x16_ge_s = 0x2B,
    i16x8_ge_s = 0x35,
    i32x4_ge_s = 0x3F,
    i8x16_ge_u = 0x2C,
    i16x8_ge_u = 0x36,
    i32x4_ge_u = 0x40,
    f32x4_eq = 0x41,
    f64x2_eq = 0x47,
    f32x4_ne = 0x42,
    f64x2_ne = 0x48,
    f32x4_lt = 0x43,
    f64x2_lt = 0x49,
    f32x4_gt = 0x44,
    f64x2_gt = 0x4A,
    f32x4_le = 0x45,
    f64x2_le = 0x4B,
    f32x4_ge = 0x46,
    f64x2_ge = 0x4C,
    v128_not = 0x4D,
    v128_and = 0x4E,
    v128_andnot = 0x4F,
    v128_or = 0x50,
    v128_xor = 0x51,
    v128_bitselect = 0x52,
    v128_any_true = 0x53,
    v128_load8_lane = 0x54,
    v128_load16_lane = 0x55,
    v128_load32_lane = 0x56,
    v128_load64_lane = 0x57,
    v128_store8_lane = 0x58,
    v128_store16_lane = 0x59,
    v128_store32_lane = 0x5A,
    v128_store64_lane = 0x5B,
    v128_load32_zero = 0x5C,
    v128_load64_zero = 0x5D,
    f32x4_demote_f64x2_zero = 0x5E,
    f64x2_promote_low_f32x4 = 0x5F,
    i8x16_abs = 0x60,
    i16x8_abs = 0x80,
    i32x4_abs = 0xA0,
    i64x2_abs = 0xC0,
    i8x16_neg = 0x61,
    i16x8_neg = 0x81,
    i32x4_neg = 0xA1,
    i64x2_neg = 0xC1,
    i8x16_popcnt = 0x62,
    i16x8_q15mulr_sat_s = 0x82,
    i8x16_all_true = 0x63,
    i16x8_all_true = 0x83,
    i32x4_all_true = 0xA3,
    i64x2_all_true = 0xC3,
    i8x16_bitmask = 0x64,
    i16x8_bitmask = 0x84,
    i32x4_bitmask = 0xA4,
    i64x2_bitmask = 0xC4,
    i8x16_narrow_i16x8_s = 0x65,
    i16x8_narrow_i32x4_s = 0x85,
    i8x16_narrow_i16x8_u = 0x66,
    i16x8_narrow_i32x4_u = 0x86,
    f32x4_ceil = 0x67,
    i16x8_extend_low_i8x16_s = 0x87,
    i32x4_extend_low_i16x8_s = 0xA7,
    i64x2_extend_low_i32x4_s = 0xC7,
    f32x4_floor = 0x68,
    i16x8_extend_high_i8x16_s = 0x88,
    i32x4_extend_high_i16x8_s = 0xA8,
    i64x2_extend_high_i32x4_s = 0xC8,
    f32x4_trunc = 0x69,
    i16x8_extend_low_i8x16_u = 0x89,
    i32x4_extend_low_i16x8_u = 0xA9,
    i64x2_extend_low_i32x4_u = 0xC9,
    f32x4_nearest = 0x6A,
    i16x8_extend_high_i8x16_u = 0x8A,
    i32x4_extend_high_i16x8_u = 0xAA,
    i64x2_extend_high_i32x4_u = 0xCA,
    i8x16_shl = 0x6B,
    i16x8_shl = 0x8B,
    i32x4_shl = 0xAB,
    i64x2_shl = 0xCB,
    i8x16_shr_s = 0x6C,
    i16x8_shr_s = 0x8C,
    i32x4_shr_s = 0xAC,
    i64x2_shr_s = 0xCC,
    i8x16_shr_u = 0x6D,
    i16x8_shr_u = 0x8D,
    i32x4_shr_u = 0xAD,
    i64x2_shr_u = 0xCD,
    i8x16_add = 0x6E,
    i16x8_add = 0x8E,
    i32x4_add = 0xAE,
    i64x2_add = 0xCE,
    i8x16_add_sat_s = 0x6F,
    i16x8_add_sat_s = 0x8F,
    i8x16_add_sat_u = 0x70,
    i16x8_add_sat_u = 0x90,
    i8x16_sub = 0x71,
    i16x8_sub = 0x91,
    i32x4_sub = 0xB1,
    i64x2_sub = 0xD1,
    i8x16_sub_sat_s = 0x72,
    i16x8_sub_sat_s = 0x92,
    i8x16_sub_sat_u = 0x73,
    i16x8_sub_sat_u = 0x93,
    f64x2_ceil = 0x74,
    f64x2_nearest = 0x94,
    f64x2_floor = 0x75,
    i16x8_mul = 0x95,
    i32x4_mul = 0xB5,
    i64x2_mul = 0xD5,
    i8x16_min_s = 0x76,
    i16x8_min_s = 0x96,
    i32x4_min_s = 0xB6,
    i64x2_eq = 0xD6,
    i8x16_min_u = 0x77,
    i16x8_min_u = 0x97,
    i32x4_min_u = 0xB7,
    i64x2_ne = 0xD7,
    i8x16_max_s = 0x78,
    i16x8_max_s = 0x98,
    i32x4_max_s = 0xB8,
    i64x2_lt_s = 0xD8,
    i8x16_max_u = 0x79,
    i16x8_max_u = 0x99,
    i32x4_max_u = 0xB9,
    i64x2_gt_s = 0xD9,
    f64x2_trunc = 0x7A,
    i32x4_dot_i16x8_s = 0xBA,
    i64x2_le_s = 0xDA,
    i8x16_avgr_u = 0x7B,
    i16x8_avgr_u = 0x9B,
    i64x2_ge_s = 0xDB,
    i16x8_extadd_pairwise_i8x16_s = 0x7C,
    i16x8_extmul_low_i8x16_s = 0x9C,
    i32x4_extmul_low_i16x8_s = 0xBC,
    i64x2_extmul_low_i32x4_s = 0xDC,
    i16x8_extadd_pairwise_i8x16_u = 0x7D,
    i16x8_extmul_high_i8x16_s = 0x9D,
    i32x4_extmul_high_i16x8_s = 0xBD,
    i64x2_extmul_high_i32x4_s = 0xDD,
    i32x4_extadd_pairwise_i16x8_s = 0x7E,
    i16x8_extmul_low_i8x16_u = 0x9E,
    i32x4_extmul_low_i16x8_u = 0xBE,
    i64x2_extmul_low_i32x4_u = 0xDE,
    i32x4_extadd_pairwise_i16x8_u = 0x7F,
    i16x8_extmul_high_i8x16_u = 0x9F,
    i32x4_extmul_high_i16x8_u = 0xBF,
    i64x2_extmul_high_i32x4_u = 0xDF,
    f32x4_abs = 0xE0,
    f64x2_abs = 0xEC,
    f32x4_neg = 0xE1,
    f64x2_neg = 0xED,
    f32x4_sqrt = 0xE3,
    f64x2_sqrt = 0xEF,
    f32x4_add = 0xE4,
    f64x2_add = 0xF0,
    f32x4_sub = 0xE5,
    f64x2_sub = 0xF1,
    f32x4_mul = 0xE6,
    f64x2_mul = 0xF2,
    f32x4_div = 0xE7,
    f64x2_div = 0xF3,
    f32x4_min = 0xE8,
    f64x2_min = 0xF4,
    f32x4_max = 0xE9,
    f64x2_max = 0xF5,
    f32x4_pmin = 0xEA,
    f64x2_pmin = 0xF6,
    f32x4_pmax = 0xEB,
    f64x2_pmax = 0xF7,
    i32x4_trunc_sat_f32x4_s = 0xF8,
    i32x4_trunc_sat_f32x4_u = 0xF9,
    f32x4_convert_i32x4_s = 0xFA,
    f32x4_convert_i32x4_u = 0xFB,
    i32x4_trunc_sat_f64x2_s_zero = 0xFC,
    i32x4_trunc_sat_f64x2_u_zero = 0xFD,
    f64x2_convert_low_i32x4_s = 0xFE,
    f64x2_convert_low_i32x4_u = 0xFF,

    // relaxed-simd opcodes
    i8x16_relaxed_swizzle = 0x100,
    i32x4_relaxed_trunc_f32x4_s = 0x101,
    i32x4_relaxed_trunc_f32x4_u = 0x102,
    i32x4_relaxed_trunc_f64x2_s_zero = 0x103,
    i32x4_relaxed_trunc_f64x2_u_zero = 0x104,
    f32x4_relaxed_madd = 0x105,
    f32x4_relaxed_nmadd = 0x106,
    f64x2_relaxed_madd = 0x107,
    f64x2_relaxed_nmadd = 0x108,
    i8x16_relaxed_laneselect = 0x109,
    i16x8_relaxed_laneselect = 0x10a,
    i32x4_relaxed_laneselect = 0x10b,
    i64x2_relaxed_laneselect = 0x10c,
    f32x4_relaxed_min = 0x10d,
    f32x4_relaxed_max = 0x10e,
    f64x2_relaxed_min = 0x10f,
    f64x2_relaxed_max = 0x110,
    i16x8_relaxed_q15mulr_s = 0x111,
    i16x8_relaxed_dot_i8x16_i7x16_s = 0x112,
    i32x4_relaxed_dot_i8x16_i7x16_add_s = 0x113,
    f32x4_relaxed_dot_bf16x8_add_f32x4 = 0x114,
};

/// Atomic opcodes that require a prefix `0xFE`.
/// Each opcode represents a varuint32, meaning
/// they are encoded as leb128 in binary.
pub const AtomicsOpcode = enum(u32) {
    memory_atomic_notify = 0x00,
    memory_atomic_wait32 = 0x01,
    memory_atomic_wait64 = 0x02,
    atomic_fence = 0x03,
    i32_atomic_load = 0x10,
    i64_atomic_load = 0x11,
    i32_atomic_load8_u = 0x12,
    i32_atomic_load16_u = 0x13,
    i64_atomic_load8_u = 0x14,
    i64_atomic_load16_u = 0x15,
    i64_atomic_load32_u = 0x16,
    i32_atomic_store = 0x17,
    i64_atomic_store = 0x18,
    i32_atomic_store8 = 0x19,
    i32_atomic_store16 = 0x1A,
    i64_atomic_store8 = 0x1B,
    i64_atomic_store16 = 0x1C,
    i64_atomic_store32 = 0x1D,
    i32_atomic_rmw_add = 0x1E,
    i64_atomic_rmw_add = 0x1F,
    i32_atomic_rmw8_add_u = 0x20,
    i32_atomic_rmw16_add_u = 0x21,
    i64_atomic_rmw8_add_u = 0x22,
    i64_atomic_rmw16_add_u = 0x23,
    i64_atomic_rmw32_add_u = 0x24,
    i32_atomic_rmw_sub = 0x25,
    i64_atomic_rmw_sub = 0x26,
    i32_atomic_rmw8_sub_u = 0x27A,
    i32_atomic_rmw16_sub_u = 0x28A,
    i64_atomic_rmw8_sub_u = 0x29A,
    i64_atomic_rmw16_sub_u = 0x2A,
    i64_atomic_rmw32_sub_u = 0x2B,
    i32_atomic_rmw_and = 0x2C,
    i64_atomic_rmw_and = 0x2D,
    i32_atomic_rmw8_and_u = 0x2E,
    i32_atomic_rmw16_and_u = 0x2F,
    i64_atomic_rmw8_and_u = 0x30,
    i64_atomic_rmw16_and_u = 0x31,
    i64_atomic_rmw32_and_u = 0x32,
    i32_atomic_rmw_or = 0x33,
    i64_atomic_rmw_or = 0x34,
    i32_atomic_rmw8_or_u = 0x35,
    i32_atomic_rmw16_or_u = 0x36,
    i64_atomic_rmw8_or_u = 0x37,
    i64_atomic_rmw16_or_u = 0x38,
    i64_atomic_rmw32_or_u = 0x39,
    i32_atomic_rmw_xor = 0x3A,
    i64_atomic_rmw_xor = 0x3B,
    i32_atomic_rmw8_xor_u = 0x3C,
    i32_atomic_rmw16_xor_u = 0x3D,
    i64_atomic_rmw8_xor_u = 0x3E,
    i64_atomic_rmw16_xor_u = 0x3F,
    i64_atomic_rmw32_xor_u = 0x40,
    i32_atomic_rmw_xchg = 0x41,
    i64_atomic_rmw_xchg = 0x42,
    i32_atomic_rmw8_xchg_u = 0x43,
    i32_atomic_rmw16_xchg_u = 0x44,
    i64_atomic_rmw8_xchg_u = 0x45,
    i64_atomic_rmw16_xchg_u = 0x46,
    i64_atomic_rmw32_xchg_u = 0x47,

    i32_atomic_rmw_cmpxchg = 0x48,
    i64_atomic_rmw_cmpxchg = 0x49,
    i32_atomic_rmw8_cmpxchg_u = 0x4A,
    i32_atomic_rmw16_cmpxchg_u = 0x4B,
    i64_atomic_rmw8_cmpxchg_u = 0x4C,
    i64_atomic_rmw16_cmpxchg_u = 0x4D,
    i64_atomic_rmw32_cmpxchg_u = 0x4E,
};

/// Enum representing all Wasm value types as per spec:
/// https://webassembly.github.io/spec/core/binary/types.html
pub const Valtype = enum(u8) {
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0x7D,
    f64 = 0x7C,
    v128 = 0x7B,
};

/// Reference types, where the funcref references to a function regardless of its type
/// and ref references an object from the embedder.
pub const RefType = enum(u8) {
    funcref = 0x70,
    externref = 0x6F,
};

/// Limits classify the size range of resizeable storage associated with memory types and table types.
pub const Limits = struct {
    flags: Flags,
    min: u32,
    max: u32,

    pub const Flags = packed struct(u8) {
        has_max: bool,
        is_shared: bool,
        reserved: u6 = 0,
    };
};

/// Initialization expressions are used to set the initial value on an object
/// when a wasm module is being loaded.
pub const InitExpression = union(enum) {
    i32_const: i32,
    i64_const: i64,
    f32_const: f32,
    f64_const: f64,
    global_get: u32,
};

/// Describes the layout of the memory where `min` represents
/// the minimal amount of pages, and the optional `max` represents
/// the max pages. When `null` will allow the host to determine the
/// amount of pages.
pub const Memory = struct {
    limits: Limits,
};

/// Wasm module sections as per spec:
/// https://webassembly.github.io/spec/core/binary/modules.html
pub const Section = enum(u8) {
    custom,
    type,
    import,
    function,
    table,
    memory,
    global,
    @"export",
    start,
    element,
    code,
    data,
    data_count,
    _,
};

/// The kind of the type when importing or exporting to/from the host environment.
/// https://webassembly.github.io/spec/core/syntax/modules.html
pub const ExternalKind = enum(u8) {
    function,
    table,
    memory,
    global,
};

/// Defines the enum values for each subsection id for the "Names" custom section
/// as described by:
/// https://webassembly.github.io/spec/core/appendix/custom.html?highlight=name#name-section
pub const NameSubsection = enum(u8) {
    module,
    function,
    local,
    label,
    type,
    table,
    memory,
    global,
    elem_segment,
    data_segment,
};

// type constants
pub const element_type: u8 = 0x70;
pub const function_type: u8 = 0x60;
pub const result_type: u8 = 0x40;

/// Represents a block which will not return a value
pub const BlockType = enum(u8) {
    empty = 0x40,
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0x7D,
    f64 = 0x7C,
    v128 = 0x7B,

    pub fn fromValtype(valtype: Valtype) BlockType {
        return @enumFromInt(@intFromEnum(valtype));
    }
};

// binary constants
pub const magic = [_]u8{ 0x00, 0x61, 0x73, 0x6D }; // \0asm
pub const version = [_]u8{ 0x01, 0x00, 0x00, 0x00 }; // version 1 (MVP)

// Each wasm page size is 64kB
pub const page_size = 64 * 1024;
pub const packages = struct {};
pub const root_deps: []const struct { []const u8, []const u8 } = &.{};
const std = @import("std");
/// Zig version. When writing code that supports multiple versions of Zig, prefer
/// feature detection (i.e. with `@hasDecl` or `@hasField`) over version checks.
pub const zig_version = std.SemanticVersion.parse(zig_version_string) catch unreachable;
pub const zig_version_string = "0.12.0-dev.1814+5c0d58b71f";
pub const zig_backend = std.builtin.CompilerBackend.stage2_llvm;

pub const output_mode = std.builtin.OutputMode.Exe;
pub const link_mode = std.builtin.LinkMode.Dynamic;
pub const is_test = false;
pub const single_threaded = false;
pub const abi = std.Target.Abi.none;
pub const cpu: std.Target.Cpu = .{
    .arch = .aarch64,
    .model = &std.Target.aarch64.cpu.apple_a14,
    .features = std.Target.aarch64.featureSet(&[_]std.Target.aarch64.Feature{
        .aes,
        .aggressive_fma,
        .alternate_sextload_cvt_f32_pattern,
        .altnzcv,
        .am,
        .arith_bcc_fusion,
        .arith_cbz_fusion,
        .ccdp,
        .ccidx,
        .ccpp,
        .complxnum,
        .contextidr_el2,
        .crc,
        .crypto,
        .disable_latency_sched_heuristic,
        .dit,
        .dotprod,
        .el2vmsa,
        .el3,
        .flagm,
        .fp16fml,
        .fp_armv8,
        .fptoint,
        .fullfp16,
        .fuse_address,
        .fuse_adrp_add,
        .fuse_aes,
        .fuse_arith_logic,
        .fuse_crypto_eor,
        .fuse_csel,
        .fuse_literals,
        .jsconv,
        .lor,
        .lse,
        .lse2,
        .mpam,
        .neon,
        .nv,
        .pan,
        .pan_rwv,
        .pauth,
        .perfmon,
        .predres,
        .ras,
        .rcpc,
        .rcpc_immo,
        .rdm,
        .sb,
        .sel2,
        .sha2,
        .sha3,
        .specrestrict,
        .ssbs,
        .tlb_rmi,
        .tracev8_4,
        .uaops,
        .v8_1a,
        .v8_2a,
        .v8_3a,
        .v8_4a,
        .v8a,
        .vh,
        .zcm,
        .zcz,
        .zcz_gp,
    }),
};
pub const os = std.Target.Os{
    .tag = .macos,
    .version_range = .{ .semver = .{
        .min = .{
            .major = 14,
            .minor = 2,
            .patch = 0,
        },
        .max = .{
            .major = 14,
            .minor = 2,
            .patch = 0,
        },
    }},
};
pub const target = std.Target{
    .cpu = cpu,
    .os = os,
    .abi = abi,
    .ofmt = object_format,
};
pub const object_format = std.Target.ObjectFormat.macho;
pub const mode = std.builtin.OptimizeMode.Debug;
pub const link_libc = true;
pub const link_libcpp = false;
pub const have_error_return_tracing = true;
pub const valgrind_support = false;
pub const sanitize_thread = false;
pub const position_independent_code = true;
pub const position_independent_executable = true;
pub const strip_debug_info = false;
pub const code_model = std.builtin.CodeModel.default;
pub const omit_frame_pointer = false;
const std = @import("std");
/// Zig version. When writing code that supports multiple versions of Zig, prefer
/// feature detection (i.e. with `@hasDecl` or `@hasField`) over version checks.
pub const zig_version = std.SemanticVersion.parse(zig_version_string) catch unreachable;
pub const zig_version_string = "0.12.0-dev.1817+3c9125277e";
pub const zig_backend = std.builtin.CompilerBackend.stage2_llvm;

pub const output_mode = std.builtin.OutputMode.Exe;
pub const link_mode = std.builtin.LinkMode.Dynamic;
pub const is_test = false;
pub const single_threaded = false;
pub const abi = std.Target.Abi.none;
pub const cpu: std.Target.Cpu = .{
    .arch = .aarch64,
    .model = &std.Target.aarch64.cpu.apple_a14,
    .features = std.Target.aarch64.featureSet(&[_]std.Target.aarch64.Feature{
        .aes,
        .aggressive_fma,
        .alternate_sextload_cvt_f32_pattern,
        .altnzcv,
        .am,
        .arith_bcc_fusion,
        .arith_cbz_fusion,
        .ccdp,
        .ccidx,
        .ccpp,
        .complxnum,
        .contextidr_el2,
        .crc,
        .crypto,
        .disable_latency_sched_heuristic,
        .dit,
        .dotprod,
        .el2vmsa,
        .el3,
        .flagm,
        .fp16fml,
        .fp_armv8,
        .fptoint,
        .fullfp16,
        .fuse_address,
        .fuse_adrp_add,
        .fuse_aes,
        .fuse_arith_logic,
        .fuse_crypto_eor,
        .fuse_csel,
        .fuse_literals,
        .jsconv,
        .lor,
        .lse,
        .lse2,
        .mpam,
        .neon,
        .nv,
        .pan,
        .pan_rwv,
        .pauth,
        .perfmon,
        .predres,
        .ras,
        .rcpc,
        .rcpc_immo,
        .rdm,
        .sb,
        .sel2,
        .sha2,
        .sha3,
        .specrestrict,
        .ssbs,
        .tlb_rmi,
        .tracev8_4,
        .uaops,
        .v8_1a,
        .v8_2a,
        .v8_3a,
        .v8_4a,
        .v8a,
        .vh,
        .zcm,
        .zcz,
        .zcz_gp,
    }),
};
pub const os = std.Target.Os{
    .tag = .macos,
    .version_range = .{ .semver = .{
        .min = .{
            .major = 14,
            .minor = 2,
            .patch = 0,
        },
        .max = .{
            .major = 14,
            .minor = 2,
            .patch = 0,
        },
    }},
};
pub const target = std.Target{
    .cpu = cpu,
    .os = os,
    .abi = abi,
    .ofmt = object_format,
};
pub const object_format = std.Target.ObjectFormat.macho;
pub const mode = std.builtin.OptimizeMode.Debug;
pub const link_libc = true;
pub const link_libcpp = false;
pub const have_error_return_tracing = true;
pub const valgrind_support = false;
pub const sanitize_thread = false;
pub const position_independent_code = true;
pub const position_independent_executable = true;
pub const strip_debug_info = false;
pub const code_model = std.builtin.CodeModel.default;
pub const omit_frame_pointer = false;
pub const packages = struct {};
pub const root_deps: []const struct { []const u8, []const u8 } = &.{};
//! Builds of the Zig compiler are distributed partly in source form. That
//! source lives here. These APIs are provided as-is and have absolutely no API
//! guarantees whatsoever.

pub const ErrorBundle = @import("zig/ErrorBundle.zig");
pub const Server = @import("zig/Server.zig");
pub const Client = @import("zig/Client.zig");
pub const Token = tokenizer.Token;
pub const Tokenizer = tokenizer.Tokenizer;
pub const string_literal = @import("zig/string_literal.zig");
pub const number_literal = @import("zig/number_literal.zig");
pub const primitives = @import("zig/primitives.zig");
pub const isPrimitive = primitives.isPrimitive;
pub const Ast = @import("zig/Ast.zig");
pub const AstGen = @import("zig/AstGen.zig");
pub const Zir = @import("zig/Zir.zig");
pub const Zoir = @import("zig/Zoir.zig");
pub const ZonGen = @import("zig/ZonGen.zig");
pub const system = @import("zig/system.zig");
pub const CrossTarget = @compileError("deprecated; use std.Target.Query");
pub const BuiltinFn = @import("zig/BuiltinFn.zig");
pub const AstRlAnnotate = @import("zig/AstRlAnnotate.zig");
pub const LibCInstallation = @import("zig/LibCInstallation.zig");
pub const WindowsSdk = @import("zig/WindowsSdk.zig");
pub const LibCDirs = @import("zig/LibCDirs.zig");
pub const target = @import("zig/target.zig");
pub const llvm = @import("zig/llvm.zig");

// Character literal parsing
pub const ParsedCharLiteral = string_literal.ParsedCharLiteral;
pub const parseCharLiteral = string_literal.parseCharLiteral;
pub const parseNumberLiteral = number_literal.parseNumberLiteral;

// Files needed by translate-c.
pub const c_builtins = @import("zig/c_builtins.zig");
pub const c_translation = @import("zig/c_translation.zig");

pub const SrcHasher = std.crypto.hash.Blake3;
pub const SrcHash = [16]u8;

pub const Color = enum {
    /// Determine whether stderr is a terminal or not automatically.
    auto,
    /// Assume stderr is not a terminal.
    off,
    /// Assume stderr is a terminal.
    on,

    pub fn get_tty_conf(color: Color) std.io.tty.Config {
        return switch (color) {
            .auto => std.io.tty.detectConfig(std.io.getStdErr()),
            .on => .escape_codes,
            .off => .no_color,
        };
    }

    pub fn renderOptions(color: Color) std.zig.ErrorBundle.RenderOptions {
        return .{
            .ttyconf = get_tty_conf(color),
        };
    }
};

/// There are many assumptions in the entire codebase that Zig source files can
/// be byte-indexed with a u32 integer.
pub const max_src_size = std.math.maxInt(u32);

pub fn hashSrc(src: []const u8) SrcHash {
    var out: SrcHash = undefined;
    SrcHasher.hash(src, &out, .{});
    return out;
}

pub fn srcHashEql(a: SrcHash, b: SrcHash) bool {
    return @as(u128, @bitCast(a)) == @as(u128, @bitCast(b));
}

pub fn hashName(parent_hash: SrcHash, sep: []const u8, name: []const u8) SrcHash {
    var out: SrcHash = undefined;
    var hasher = SrcHasher.init(.{});
    hasher.update(&parent_hash);
    hasher.update(sep);
    hasher.update(name);
    hasher.final(&out);
    return out;
}

pub const Loc = struct {
    line: usize,
    column: usize,
    /// Does not include the trailing newline.
    source_line: []const u8,

    pub fn eql(a: Loc, b: Loc) bool {
        return a.line == b.line and a.column == b.column and std.mem.eql(u8, a.source_line, b.source_line);
    }
};

pub fn findLineColumn(source: []const u8, byte_offset: usize) Loc {
    var line: usize = 0;
    var column: usize = 0;
    var line_start: usize = 0;
    var i: usize = 0;
    while (i < byte_offset) : (i += 1) {
        switch (source[i]) {
            '\n' => {
                line += 1;
                column = 0;
                line_start = i + 1;
            },
            else => {
                column += 1;
            },
        }
    }
    while (i < source.len and source[i] != '\n') {
        i += 1;
    }
    return .{
        .line = line,
        .column = column,
        .source_line = source[line_start..i],
    };
}

pub fn lineDelta(source: []const u8, start: usize, end: usize) isize {
    var line: isize = 0;
    if (end >= start) {
        for (source[start..end]) |byte| switch (byte) {
            '\n' => line += 1,
            else => continue,
        };
    } else {
        for (source[end..start]) |byte| switch (byte) {
            '\n' => line -= 1,
            else => continue,
        };
    }
    return line;
}

pub const BinNameOptions = struct {
    root_name: []const u8,
    target: std.Target,
    output_mode: std.builtin.OutputMode,
    link_mode: ?std.builtin.LinkMode = null,
    version: ?std.SemanticVersion = null,
};

/// Returns the standard file system basename of a binary generated by the Zig compiler.
pub fn binNameAlloc(allocator: Allocator, options: BinNameOptions) error{OutOfMemory}![]u8 {
    const root_name = options.root_name;
    const t = options.target;
    switch (t.ofmt) {
        .coff => switch (options.output_mode) {
            .Exe => return std.fmt.allocPrint(allocator, "{s}{s}", .{ root_name, t.exeFileExt() }),
            .Lib => {
                const suffix = switch (options.link_mode orelse .static) {
                    .static => ".lib",
                    .dynamic => ".dll",
                };
    ```
