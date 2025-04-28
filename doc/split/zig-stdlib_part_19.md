```
|node, i| {
                    // "list" is in order of increasing literal value.
                    self.codes[node.literal].set(@as(u16, @intCast(i)), 1);
                }
                return;
            }
            self.lfs = list;
            mem.sort(LiteralNode, self.lfs, {}, byFreq);

            // Get the number of literals for each bit count
            const bit_count = self.bitCounts(list, max_bits);
            // And do the assignment
            self.assignEncodingAndSize(bit_count, list);
        }

        pub fn bitLength(self: *Self, freq: []u16) u32 {
            var total: u32 = 0;
            for (freq, 0..) |f, i| {
                if (f != 0) {
                    total += @as(u32, @intCast(f)) * @as(u32, @intCast(self.codes[i].len));
                }
            }
            return total;
        }

        // Return the number of literals assigned to each bit size in the Huffman encoding
        //
        // This method is only called when list.len >= 3
        // The cases of 0, 1, and 2 literals are handled by special case code.
        //
        // list: An array of the literals with non-zero frequencies
        // and their associated frequencies. The array is in order of increasing
        // frequency, and has as its last element a special element with frequency
        // std.math.maxInt(i32)
        //
        // max_bits: The maximum number of bits that should be used to encode any literal.
        // Must be less than 16.
        //
        // Returns an integer array in which array[i] indicates the number of literals
        // that should be encoded in i bits.
        fn bitCounts(self: *Self, list: []LiteralNode, max_bits_to_use: usize) []u32 {
            var max_bits = max_bits_to_use;
            const n = list.len;
            const max_bits_limit = 16;

            assert(max_bits < max_bits_limit);

            // The tree can't have greater depth than n - 1, no matter what. This
            // saves a little bit of work in some small cases
            max_bits = @min(max_bits, n - 1);

            // Create information about each of the levels.
            // A bogus "Level 0" whose sole purpose is so that
            // level1.prev.needed == 0.  This makes level1.next_pair_freq
            // be a legitimate value that never gets chosen.
            var levels: [max_bits_limit]LevelInfo = mem.zeroes([max_bits_limit]LevelInfo);
            // leaf_counts[i] counts the number of literals at the left
            // of ancestors of the rightmost node at level i.
            // leaf_counts[i][j] is the number of literals at the left
            // of the level j ancestor.
            var leaf_counts: [max_bits_limit][max_bits_limit]u32 = mem.zeroes([max_bits_limit][max_bits_limit]u32);

            {
                var level = @as(u32, 1);
                while (level <= max_bits) : (level += 1) {
                    // For every level, the first two items are the first two characters.
                    // We initialize the levels as if we had already figured this out.
                    levels[level] = LevelInfo{
                        .level = level,
                        .last_freq = list[1].freq,
                        .next_char_freq = list[2].freq,
                        .next_pair_freq = list[0].freq + list[1].freq,
                        .needed = 0,
                    };
                    leaf_counts[level][level] = 2;
                    if (level == 1) {
                        levels[level].next_pair_freq = math.maxInt(i32);
                    }
                }
            }

            // We need a total of 2*n - 2 items at top level and have already generated 2.
            levels[max_bits].needed = 2 * @as(u32, @intCast(n)) - 4;

            {
                var level = max_bits;
                while (true) {
                    var l = &levels[level];
                    if (l.next_pair_freq == math.maxInt(i32) and l.next_char_freq == math.maxInt(i32)) {
                        // We've run out of both leaves and pairs.
                        // End all calculations for this level.
                        // To make sure we never come back to this level or any lower level,
                        // set next_pair_freq impossibly large.
                        l.needed = 0;
                        levels[level + 1].next_pair_freq = math.maxInt(i32);
                        level += 1;
                        continue;
                    }

                    const prev_freq = l.last_freq;
                    if (l.next_char_freq < l.next_pair_freq) {
                        // The next item on this row is a leaf node.
                        const next = leaf_counts[level][level] + 1;
                        l.last_freq = l.next_char_freq;
                        // Lower leaf_counts are the same of the previous node.
                        leaf_counts[level][level] = next;
                        if (next >= list.len) {
                            l.next_char_freq = maxNode().freq;
                        } else {
                            l.next_char_freq = list[next].freq;
                        }
                    } else {
                        // The next item on this row is a pair from the previous row.
                        // next_pair_freq isn't valid until we generate two
                        // more values in the level below
                        l.last_freq = l.next_pair_freq;
                        // Take leaf counts from the lower level, except counts[level] remains the same.
                        @memcpy(leaf_counts[level][0..level], leaf_counts[level - 1][0..level]);
                        levels[l.level - 1].needed = 2;
                    }

                    l.needed -= 1;
                    if (l.needed == 0) {
                        // We've done everything we need to do for this level.
                        // Continue calculating one level up. Fill in next_pair_freq
                        // of that level with the sum of the two nodes we've just calculated on
                        // this level.
                        if (l.level == max_bits) {
                            // All done!
                            break;
                        }
                        levels[l.level + 1].next_pair_freq = prev_freq + l.last_freq;
                        level += 1;
                    } else {
                        // If we stole from below, move down temporarily to replenish it.
                        while (levels[level - 1].needed > 0) {
                            level -= 1;
                            if (level == 0) {
                                break;
                            }
                        }
                    }
                }
            }

            // Somethings is wrong if at the end, the top level is null or hasn't used
            // all of the leaves.
            assert(leaf_counts[max_bits][max_bits] == n);

            var bit_count = self.bit_count[0 .. max_bits + 1];
            var bits: u32 = 1;
            const counts = &leaf_counts[max_bits];
            {
                var level = max_bits;
                while (level > 0) : (level -= 1) {
                    // counts[level] gives the number of literals requiring at least "bits"
                    // bits to encode.
                    bit_count[bits] = counts[level] - counts[level - 1];
                    bits += 1;
                    if (level == 0) {
                        break;
                    }
                }
            }
            return bit_count;
        }

        // Look at the leaves and assign them a bit count and an encoding as specified
        // in RFC 1951 3.2.2
        fn assignEncodingAndSize(self: *Self, bit_count: []u32, list_arg: []LiteralNode) void {
            var code = @as(u16, 0);
            var list = list_arg;

            for (bit_count, 0..) |bits, n| {
                code <<= 1;
                if (n == 0 or bits == 0) {
                    continue;
                }
                // The literals list[list.len-bits] .. list[list.len-bits]
                // are encoded using "bits" bits, and get the values
                // code, code + 1, ....  The code values are
                // assigned in literal order (not frequency order).
                const chunk = list[list.len - @as(u32, @intCast(bits)) ..];

                self.lns = chunk;
                mem.sort(LiteralNode, self.lns, {}, byLiteral);

                for (chunk) |node| {
                    self.codes[node.literal] = HuffCode{
                        .code = bitReverse(u16, code, @as(u5, @intCast(n))),
                        .len = @as(u16, @intCast(n)),
                    };
                    code += 1;
                }
                list = list[0 .. list.len - @as(u32, @intCast(bits))];
            }
        }
    };
}

fn maxNode() LiteralNode {
    return LiteralNode{
        .literal = math.maxInt(u16),
        .freq = math.maxInt(u16),
    };
}

pub fn huffmanEncoder(comptime size: u32) HuffmanEncoder(size) {
    return .{};
}

pub const LiteralEncoder = HuffmanEncoder(consts.max_num_frequencies);
pub const DistanceEncoder = HuffmanEncoder(consts.distance_code_count);
pub const CodegenEncoder = HuffmanEncoder(19);

// Generates a HuffmanCode corresponding to the fixed literal table
pub fn fixedLiteralEncoder() LiteralEncoder {
    var h: LiteralEncoder = undefined;
    var ch: u16 = 0;

    while (ch < consts.max_num_frequencies) : (ch += 1) {
        var bits: u16 = undefined;
        var size: u16 = undefined;
        switch (ch) {
            0...143 => {
                // size 8, 000110000  .. 10111111
                bits = ch + 48;
                size = 8;
            },
            144...255 => {
                // size 9, 110010000 .. 111111111
                bits = ch + 400 - 144;
                size = 9;
            },
            256...279 => {
                // size 7, 0000000 .. 0010111
                bits = ch - 256;
                size = 7;
            },
            else => {
                // size 8, 11000000 .. 11000111
                bits = ch + 192 - 280;
                size = 8;
            },
        }
        h.codes[ch] = HuffCode{ .code = bitReverse(u16, bits, @as(u5, @intCast(size))), .len = size };
    }
    return h;
}

pub fn fixedDistanceEncoder() DistanceEncoder {
    var h: DistanceEncoder = undefined;
    for (h.codes, 0..) |_, ch| {
        h.codes[ch] = HuffCode{ .code = bitReverse(u16, @as(u16, @intCast(ch)), 5), .len = 5 };
    }
    return h;
}

pub fn huffmanDistanceEncoder() DistanceEncoder {
    var distance_freq = [1]u16{0} ** consts.distance_code_count;
    distance_freq[0] = 1;
    // huff_distance is a static distance encoder used for huffman only encoding.
    // It can be reused since we will not be encoding distance values.
    var h: DistanceEncoder = .{};
    h.generate(distance_freq[0..], 15);
    return h;
}

fn byLiteral(context: void, a: LiteralNode, b: LiteralNode) bool {
    _ = context;
    return a.literal < b.literal;
}

fn byFreq(context: void, a: LiteralNode, b: LiteralNode) bool {
    _ = context;
    if (a.freq == b.freq) {
        return a.literal < b.literal;
    }
    return a.freq < b.freq;
}

test "generate a Huffman code from an array of frequencies" {
    var freqs: [19]u16 = [_]u16{
        8, // 0
        1, // 1
        1, // 2
        2, // 3
        5, // 4
        10, // 5
        9, // 6
        1, // 7
        0, // 8
        0, // 9
        0, // 10
        0, // 11
        0, // 12
        0, // 13
        0, // 14
        0, // 15
        1, // 16
        3, // 17
        5, // 18
    };

    var enc = huffmanEncoder(19);
    enc.generate(freqs[0..], 7);

    try testing.expectEqual(@as(u32, 141), enc.bitLength(freqs[0..]));

    try testing.expectEqual(@as(usize, 3), enc.codes[0].len);
    try testing.expectEqual(@as(usize, 6), enc.codes[1].len);
    try testing.expectEqual(@as(usize, 6), enc.codes[2].len);
    try testing.expectEqual(@as(usize, 5), enc.codes[3].len);
    try testing.expectEqual(@as(usize, 3), enc.codes[4].len);
    try testing.expectEqual(@as(usize, 2), enc.codes[5].len);
    try testing.expectEqual(@as(usize, 2), enc.codes[6].len);
    try testing.expectEqual(@as(usize, 6), enc.codes[7].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[8].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[9].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[10].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[11].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[12].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[13].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[14].len);
    try testing.expectEqual(@as(usize, 0), enc.codes[15].len);
    try testing.expectEqual(@as(usize, 6), enc.codes[16].len);
    try testing.expectEqual(@as(usize, 5), enc.codes[17].len);
    try testing.expectEqual(@as(usize, 3), enc.codes[18].len);

    try testing.expectEqual(@as(u16, 0x0), enc.codes[5].code);
    try testing.expectEqual(@as(u16, 0x2), enc.codes[6].code);
    try testing.expectEqual(@as(u16, 0x1), enc.codes[0].code);
    try testing.expectEqual(@as(u16, 0x5), enc.codes[4].code);
    try testing.expectEqual(@as(u16, 0x3), enc.codes[18].code);
    try testing.expectEqual(@as(u16, 0x7), enc.codes[3].code);
    try testing.expectEqual(@as(u16, 0x17), enc.codes[17].code);
    try testing.expectEqual(@as(u16, 0x0f), enc.codes[1].code);
    try testing.expectEqual(@as(u16, 0x2f), enc.codes[2].code);
    try testing.expectEqual(@as(u16, 0x1f), enc.codes[7].code);
    try testing.expectEqual(@as(u16, 0x3f), enc.codes[16].code);
}

test "generate a Huffman code for the fixed literal table specific to Deflate" {
    const enc = fixedLiteralEncoder();
    for (enc.codes) |c| {
        switch (c.len) {
            7 => {
                const v = @bitReverse(@as(u7, @intCast(c.code)));
                try testing.expect(v <= 0b0010111);
            },
            8 => {
                const v = @bitReverse(@as(u8, @intCast(c.code)));
                try testing.expect((v >= 0b000110000 and v <= 0b10111111) or
                    (v >= 0b11000000 and v <= 11000111));
            },
            9 => {
                const v = @bitReverse(@as(u9, @intCast(c.code)));
                try testing.expect(v >= 0b110010000 and v <= 0b111111111);
            },
            else => unreachable,
        }
    }
}

test "generate a Huffman code for the 30 possible relative distances (LZ77 distances) of Deflate" {
    const enc = fixedDistanceEncoder();
    for (enc.codes) |c| {
        const v = @bitReverse(@as(u5, @intCast(c.code)));
        try testing.expect(v <= 29);
        try testing.expect(c.len == 5);
    }
}

// Reverse bit-by-bit a N-bit code.
fn bitReverse(comptime T: type, value: T, n: usize) T {
    const r = @bitReverse(value);
    return r >> @as(math.Log2Int(T), @intCast(@typeInfo(T).int.bits - n));
}

test bitReverse {
    const ReverseBitsTest = struct {
        in: u16,
        bit_count: u5,
        out: u16,
    };

    const reverse_bits_tests = [_]ReverseBitsTest{
        .{ .in = 1, .bit_count = 1, .out = 1 },
        .{ .in = 1, .bit_count = 2, .out = 2 },
        .{ .in = 1, .bit_count = 3, .out = 4 },
        .{ .in = 1, .bit_count = 4, .out = 8 },
        .{ .in = 1, .bit_count = 5, .out = 16 },
        .{ .in = 17, .bit_count = 5, .out = 17 },
        .{ .in = 257, .bit_count = 9, .out = 257 },
        .{ .in = 29, .bit_count = 5, .out = 23 },
    };

    for (reverse_bits_tests) |h| {
        const v = bitReverse(u16, h.in, h.bit_count);
        try std.testing.expectEqual(h.out, v);
    }
}

test "fixedLiteralEncoder codes" {
    var al = std.ArrayList(u8).init(testing.allocator);
    defer al.deinit();
    var bw = std.io.bitWriter(.little, al.writer());

    const f = fixedLiteralEncoder();
    for (f.codes) |c| {
        try bw.writeBits(c.code, c.len);
    }
    try testing.expectEqualSlices(u8, &fixed_codes, al.items);
}

pub const fixed_codes = [_]u8{
    0b00001100, 0b10001100, 0b01001100, 0b11001100, 0b00101100, 0b10101100, 0b01101100, 0b11101100,
    0b00011100, 0b10011100, 0b01011100, 0b11011100, 0b00111100, 0b10111100, 0b01111100, 0b11111100,
    0b00000010, 0b10000010, 0b01000010, 0b11000010, 0b00100010, 0b10100010, 0b01100010, 0b11100010,
    0b00010010, 0b10010010, 0b01010010, 0b11010010, 0b00110010, 0b10110010, 0b01110010, 0b11110010,
    0b00001010, 0b10001010, 0b01001010, 0b11001010, 0b00101010, 0b10101010, 0b01101010, 0b11101010,
    0b00011010, 0b10011010, 0b01011010, 0b11011010, 0b00111010, 0b10111010, 0b01111010, 0b11111010,
    0b00000110, 0b10000110, 0b01000110, 0b11000110, 0b00100110, 0b10100110, 0b01100110, 0b11100110,
    0b00010110, 0b10010110, 0b01010110, 0b11010110, 0b00110110, 0b10110110, 0b01110110, 0b11110110,
    0b00001110, 0b10001110, 0b01001110, 0b11001110, 0b00101110, 0b10101110, 0b01101110, 0b11101110,
    0b00011110, 0b10011110, 0b01011110, 0b11011110, 0b00111110, 0b10111110, 0b01111110, 0b11111110,
    0b00000001, 0b10000001, 0b01000001, 0b11000001, 0b00100001, 0b10100001, 0b01100001, 0b11100001,
    0b00010001, 0b10010001, 0b01010001, 0b11010001, 0b00110001, 0b10110001, 0b01110001, 0b11110001,
    0b00001001, 0b10001001, 0b01001001, 0b11001001, 0b00101001, 0b10101001, 0b01101001, 0b11101001,
    0b00011001, 0b10011001, 0b01011001, 0b11011001, 0b00111001, 0b10111001, 0b01111001, 0b11111001,
    0b00000101, 0b10000101, 0b01000101, 0b11000101, 0b00100101, 0b10100101, 0b01100101, 0b11100101,
    0b00010101, 0b10010101, 0b01010101, 0b11010101, 0b00110101, 0b10110101, 0b01110101, 0b11110101,
    0b00001101, 0b10001101, 0b01001101, 0b11001101, 0b00101101, 0b10101101, 0b01101101, 0b11101101,
    0b00011101, 0b10011101, 0b01011101, 0b11011101, 0b00111101, 0b10111101, 0b01111101, 0b11111101,
    0b00010011, 0b00100110, 0b01001110, 0b10011010, 0b00111100, 0b01100101, 0b11101010, 0b10110100,
    0b11101001, 0b00110011, 0b01100110, 0b11001110, 0b10011010, 0b00111101, 0b01100111, 0b11101110,
    0b10111100, 0b11111001, 0b00001011, 0b00010110, 0b00101110, 0b01011010, 0b10111100, 0b01100100,
    0b11101001, 0b10110010, 0b11100101, 0b00101011, 0b01010110, 0b10101110, 0b01011010, 0b10111101,
    0b01100110, 0b11101101, 0b10111010, 0b11110101, 0b00011011, 0b00110110, 0b01101110, 0b11011010,
    0b10111100, 0b01100101, 0b11101011, 0b10110110, 0b11101101, 0b00111011, 0b01110110, 0b11101110,
    0b11011010, 0b10111101, 0b01100111, 0b11101111, 0b10111110, 0b11111101, 0b00000111, 0b00001110,
    0b00011110, 0b00111010, 0b01111100, 0b11100100, 0b11101000, 0b10110001, 0b11100011, 0b00100111,
    0b01001110, 0b10011110, 0b00111010, 0b01111101, 0b11100110, 0b11101100, 0b10111001, 0b11110011,
    0b00010111, 0b00101110, 0b01011110, 0b10111010, 0b01111100, 0b11100101, 0b11101010, 0b10110101,
    0b11101011, 0b00110111, 0b01101110, 0b11011110, 0b10111010, 0b01111101, 0b11100111, 0b11101110,
    0b10111101, 0b11111011, 0b00001111, 0b00011110, 0b00111110, 0b01111010, 0b11111100, 0b11100100,
    0b11101001, 0b10110011, 0b11100111, 0b00101111, 0b01011110, 0b10111110, 0b01111010, 0b11111101,
    0b11100110, 0b11101101, 0b10111011, 0b11110111, 0b00011111, 0b00111110, 0b01111110, 0b11111010,
    0b11111100, 0b11100101, 0b11101011, 0b10110111, 0b11101111, 0b00111111, 0b01111110, 0b11111110,
    0b11111010, 0b11111101, 0b11100111, 0b11101111, 0b10111111, 0b11111111, 0b00000000, 0b00100000,
    0b00001000, 0b00001100, 0b10000001, 0b11000010, 0b11100000, 0b00001000, 0b00100100, 0b00001010,
    0b10001101, 0b11000001, 0b11100010, 0b11110000, 0b00000100, 0b00100010, 0b10001001, 0b01001100,
    0b10100001, 0b11010010, 0b11101000, 0b00000011, 0b10000011, 0b01000011, 0b11000011, 0b00100011,
    0b10100011,
};
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const hfd = @import("huffman_decoder.zig");
const BitReader = @import("bit_reader.zig").BitReader;
const CircularBuffer = @import("CircularBuffer.zig");
const Container = @import("container.zig").Container;
const Token = @import("Token.zig");
const codegen_order = @import("consts.zig").huffman.codegen_order;

/// Decompresses deflate bit stream `reader` and writes uncompressed data to the
/// `writer` stream.
pub fn decompress(comptime container: Container, reader: anytype, writer: anytype) !void {
    var d = decompressor(container, reader);
    try d.decompress(writer);
}

/// Inflate decompressor for the reader type.
pub fn decompressor(comptime container: Container, reader: anytype) Decompressor(container, @TypeOf(reader)) {
    return Decompressor(container, @TypeOf(reader)).init(reader);
}

pub fn Decompressor(comptime container: Container, comptime ReaderType: type) type {
    // zlib has 4 bytes footer, lookahead of 4 bytes ensures that we will not overshoot.
    // gzip has 8 bytes footer so we will not overshoot even with 8 bytes of lookahead.
    // For raw deflate there is always possibility of overshot so we use 8 bytes lookahead.
    const lookahead: type = if (container == .zlib) u32 else u64;
    return Inflate(container, lookahead, ReaderType);
}

/// Inflate decompresses deflate bit stream. Reads compressed data from reader
/// provided in init. Decompressed data are stored in internal hist buffer and
/// can be accesses iterable `next` or reader interface.
///
/// Container defines header/footer wrapper around deflate bit stream. Can be
/// gzip or zlib.
///
/// Deflate bit stream consists of multiple blocks. Block can be one of three types:
///   * stored, non compressed, max 64k in size
///   * fixed, huffman codes are predefined
///   * dynamic, huffman code tables are encoded at the block start
///
/// `step` function runs decoder until internal `hist` buffer is full. Client
/// than needs to read that data in order to proceed with decoding.
///
/// Allocates 74.5K of internal buffers, most important are:
///   * 64K for history (CircularBuffer)
///   * ~10K huffman decoders (Literal and DistanceDecoder)
///
pub fn Inflate(comptime container: Container, comptime LookaheadType: type, comptime ReaderType: type) type {
    assert(LookaheadType == u32 or LookaheadType == u64);
    const BitReaderType = BitReader(LookaheadType, ReaderType);

    return struct {
        //const BitReaderType = BitReader(ReaderType);
        const F = BitReaderType.flag;

        bits: BitReaderType = .{},
        hist: CircularBuffer = .{},
        // Hashes, produces checkusm, of uncompressed data for gzip/zlib footer.
        hasher: container.Hasher() = .{},

        // dynamic block huffman code decoders
        lit_dec: hfd.LiteralDecoder = .{}, // literals
        dst_dec: hfd.DistanceDecoder = .{}, // distances

        // current read state
        bfinal: u1 = 0,
        block_type: u2 = 0b11,
        state: ReadState = .protocol_header,

        const ReadState = enum {
            protocol_header,
            block_header,
            block,
            protocol_footer,
            end,
        };

        const Self = @This();

        pub const Error = BitReaderType.Error || Container.Error || hfd.Error || error{
            InvalidCode,
            InvalidMatch,
            InvalidBlockType,
            WrongStoredBlockNlen,
            InvalidDynamicBlockHeader,
        };

        pub fn init(rt: ReaderType) Self {
            return .{ .bits = BitReaderType.init(rt) };
        }

        fn blockHeader(self: *Self) !void {
            self.bfinal = try self.bits.read(u1);
            self.block_type = try self.bits.read(u2);
        }

        fn storedBlock(self: *Self) !bool {
            self.bits.alignToByte(); // skip padding until byte boundary
            // everything after this is byte aligned in stored block
            var len = try self.bits.read(u16);
            const nlen = try self.bits.read(u16);
            if (len != ~nlen) return error.WrongStoredBlockNlen;

            while (len > 0) {
                const buf = self.hist.getWritable(len);
                try self.bits.readAll(buf);
                len -= @intCast(buf.len);
            }
            return true;
        }

        fn fixedBlock(self: *Self) !bool {
            while (!self.hist.full()) {
                const code = try self.bits.readFixedCode();
                switch (code) {
                    0...255 => self.hist.write(@intCast(code)),
                    256 => return true, // end of block
                    257...285 => try self.fixedDistanceCode(@intCast(code - 257)),
                    else => return error.InvalidCode,
                }
            }
            return false;
        }

        // Handles fixed block non literal (length) code.
        // Length code is followed by 5 bits of distance code.
        fn fixedDistanceCode(self: *Self, code: u8) !void {
            try self.bits.fill(5 + 5 + 13);
            const length = try self.decodeLength(code);
            const distance = try self.decodeDistance(try self.bits.readF(u5, F.buffered | F.reverse));
            try self.hist.writeMatch(length, distance);
        }

        inline fn decodeLength(self: *Self, code: u8) !u16 {
            if (code > 28) return error.InvalidCode;
            const ml = Token.matchLength(code);
            return if (ml.extra_bits == 0) // 0 - 5 extra bits
                ml.base
            else
                ml.base + try self.bits.readN(ml.extra_bits, F.buffered);
        }

        fn decodeDistance(self: *Self, code: u8) !u16 {
            if (code > 29) return error.InvalidCode;
            const md = Token.matchDistance(code);
            return if (md.extra_bits == 0) // 0 - 13 extra bits
                md.base
            else
                md.base + try self.bits.readN(md.extra_bits, F.buffered);
        }

        fn dynamicBlockHeader(self: *Self) !void {
            const hlit: u16 = @as(u16, try self.bits.read(u5)) + 257; // number of ll code entries present - 257
            const hdist: u16 = @as(u16, try self.bits.read(u5)) + 1; // number of distance code entries - 1
            const hclen: u8 = @as(u8, try self.bits.read(u4)) + 4; // hclen + 4 code lengths are encoded

            if (hlit > 286 or hdist > 30)
                return error.InvalidDynamicBlockHeader;

            // lengths for code lengths
            var cl_lens = [_]u4{0} ** 19;
            for (0..hclen) |i| {
                cl_lens[codegen_order[i]] = try self.bits.read(u3);
            }
            var cl_dec: hfd.CodegenDecoder = .{};
            try cl_dec.generate(&cl_lens);

            // decoded code lengths
            var dec_lens = [_]u4{0} ** (286 + 30);
            var pos: usize = 0;
            while (pos < hlit + hdist) {
                const sym = try cl_dec.find(try self.bits.peekF(u7, F.reverse));
                try self.bits.shift(sym.code_bits);
                pos += try self.dynamicCodeLength(sym.symbol, &dec_lens, pos);
            }
            if (pos > hlit + hdist) {
                return error.InvalidDynamicBlockHeader;
            }

            // literal code lengths to literal decoder
            try self.lit_dec.generate(dec_lens[0..hlit]);

            // distance code lengths to distance decoder
            try self.dst_dec.generate(dec_lens[hlit .. hlit + hdist]);
        }

        // Decode code length symbol to code length. Writes decoded length into
        // lens slice starting at position pos. Returns number of positions
        // advanced.
        fn dynamicCodeLength(self: *Self, code: u16, lens: []u4, pos: usize) !usize {
            if (pos >= lens.len)
                return error.InvalidDynamicBlockHeader;

            switch (code) {
                0...15 => {
                    // Represent code lengths of 0 - 15
                    lens[pos] = @intCast(code);
                    return 1;
                },
                16 => {
                    // Copy the previous code length 3 - 6 times.
                    // The next 2 bits indicate repeat length
                    const n: u8 = @as(u8, try self.bits.read(u2)) + 3;
                    if (pos == 0 or pos + n > lens.len)
                        return error.InvalidDynamicBlockHeader;
                    for (0..n) |i| {
                        lens[pos + i] = lens[pos + i - 1];
                    }
                    return n;
                },
                // Repeat a code length of 0 for 3 - 10 times. (3 bits of length)
                17 => return @as(u8, try self.bits.read(u3)) + 3,
                // Repeat a code length of 0 for 11 - 138 times (7 bits of length)
                18 => return @as(u8, try self.bits.read(u7)) + 11,
                else => return error.InvalidDynamicBlockHeader,
            }
        }

        // In larger archives most blocks are usually dynamic, so decompression
        // performance depends on this function.
        fn dynamicBlock(self: *Self) !bool {
            // Hot path loop!
            while (!self.hist.full()) {
                try self.bits.fill(15); // optimization so other bit reads can be buffered (avoiding one `if` in hot path)
                const sym = try self.decodeSymbol(&self.lit_dec);

                switch (sym.kind) {
                    .literal => self.hist.write(sym.symbol),
                    .match => { // Decode match backreference <length, distance>
                        // fill so we can use buffered reads
                        if (LookaheadType == u32)
                            try self.bits.fill(5 + 15)
                        else
                            try self.bits.fill(5 + 15 + 13);
                        const length = try self.decodeLength(sym.symbol);
                        const dsm = try self.decodeSymbol(&self.dst_dec);
                        if (LookaheadType == u32) try self.bits.fill(13);
                        const distance = try self.decodeDistance(dsm.symbol);
                        try self.hist.writeMatch(length, distance);
                    },
                    .end_of_block => return true,
                }
            }
            return false;
        }

        // Peek 15 bits from bits reader (maximum code len is 15 bits). Use
        // decoder to find symbol for that code. We then know how many bits is
        // used. Shift bit reader for that much bits, those bits are used. And
        // return symbol.
        fn decodeSymbol(self: *Self, decoder: anytype) !hfd.Symbol {
            const sym = try decoder.find(try self.bits.peekF(u15, F.buffered | F.reverse));
            try self.bits.shift(sym.code_bits);
            return sym;
        }

        fn step(self: *Self) !void {
            switch (self.state) {
                .protocol_header => {
                    try container.parseHeader(&self.bits);
                    self.state = .block_header;
                },
                .block_header => {
                    try self.blockHeader();
                    self.state = .block;
                    if (self.block_type == 2) try self.dynamicBlockHeader();
                },
                .block => {
                    const done = switch (self.block_type) {
                        0 => try self.storedBlock(),
                        1 => try self.fixedBlock(),
                        2 => try self.dynamicBlock(),
                        else => return error.InvalidBlockType,
                    };
                    if (done) {
                        self.state = if (self.bfinal == 1) .protocol_footer else .block_header;
                    }
                },
                .protocol_footer => {
                    self.bits.alignToByte();
                    try container.parseFooter(&self.hasher, &self.bits);
                    self.state = .end;
                },
                .end => {},
            }
        }

        /// Replaces the inner reader with new reader.
        pub fn setReader(self: *Self, new_reader: ReaderType) void {
            self.bits.forward_reader = new_reader;
            if (self.state == .end or self.state == .protocol_footer) {
                self.state = .protocol_header;
            }
        }

        // Reads all compressed data from the internal reader and outputs plain
        // (uncompressed) data to the provided writer.
        pub fn decompress(self: *Self, writer: anytype) !void {
            while (try self.next()) |buf| {
                try writer.writeAll(buf);
            }
        }

        /// Returns the number of bytes that have been read from the internal
        /// reader but not yet consumed by the decompressor.
        pub fn unreadBytes(self: Self) usize {
            // There can be no error here: the denominator is not zero, and
            // overflow is not possible since the type is unsigned.
            return std.math.divCeil(usize, self.bits.nbits, 8) catch unreachable;
        }

        // Iterator interface

        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try inflate.next()) |buf| { ... }
        pub fn next(self: *Self) Error!?[]const u8 {
            const out = try self.get(0);
            if (out.len == 0) return null;
            return out;
        }

        /// Returns decompressed data from internal sliding window buffer.
        /// Returned buffer can be any length between 0 and `limit` bytes. 0
        /// returned bytes means end of stream reached. With limit=0 returns as
        /// much data it can. It newer will be more than 65536 bytes, which is
        /// size of internal buffer.
        pub fn get(self: *Self, limit: usize) Error![]const u8 {
            while (true) {
                const out = self.hist.readAtMost(limit);
                if (out.len > 0) {
                    self.hasher.update(out);
                    return out;
                }
                if (self.state == .end) return out;
                try self.step();
            }
        }

        // Reader interface

        pub const Reader = std.io.Reader(*Self, Error, read);

        /// Returns the number of bytes read. It may be less than buffer.len.
        /// If the number of bytes read is 0, it means end of stream.
        /// End of stream is not an error condition.
        pub fn read(self: *Self, buffer: []u8) Error!usize {
            if (buffer.len == 0) return 0;
            const out = try self.get(buffer.len);
            @memcpy(buffer[0..out.len], out);
            return out.len;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

test "decompress" {
    const cases = [_]struct {
        in: []const u8,
        out: []const u8,
    }{
        // non compressed block (type 0)
        .{
            .in = &[_]u8{
                0b0000_0001, 0b0000_1100, 0x00, 0b1111_0011, 0xff, // deflate fixed buffer header len, nlen
                'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0x0a, // non compressed data
            },
            .out = "Hello world\n",
        },
        // fixed code block (type 1)
        .{
            .in = &[_]u8{
                0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, // deflate data block type 1
                0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00,
            },
            .out = "Hello world\n",
        },
        // dynamic block (type 2)
        .{
            .in = &[_]u8{
                0x3d, 0xc6, 0x39, 0x11, 0x00, 0x00, 0x0c, 0x02, // deflate data block type 2
                0x30, 0x2b, 0xb5, 0x52, 0x1e, 0xff, 0x96, 0x38,
                0x16, 0x96, 0x5c, 0x1e, 0x94, 0xcb, 0x6d, 0x01,
            },
            .out = "ABCDEABCD ABCDEABCD",
        },
    };
    for (cases) |c| {
        var fb = std.io.fixedBufferStream(c.in);
        var al = std.ArrayList(u8).init(testing.allocator);
        defer al.deinit();

        try decompress(.raw, fb.reader(), al.writer());
        try testing.expectEqualStrings(c.out, al.items);
    }
}

test "gzip decompress" {
    const cases = [_]struct {
        in: []const u8,
        out: []const u8,
    }{
        // non compressed block (type 0)
        .{
            .in = &[_]u8{
                0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // gzip header (10 bytes)
                0b0000_0001, 0b0000_1100, 0x00, 0b1111_0011, 0xff, // deflate fixed buffer header len, nlen
                'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0x0a, // non compressed data
                0xd5, 0xe0, 0x39, 0xb7, // gzip footer: checksum
                0x0c, 0x00, 0x00, 0x00, // gzip footer: size
            },
            .out = "Hello world\n",
        },
        // fixed code block (type 1)
        .{
            .in = &[_]u8{
                0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, // gzip header (10 bytes)
                0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, // deflate data block type 1
                0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00,
                0xd5, 0xe0, 0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00, // gzip footer (chksum, len)
            },
            .out = "Hello world\n",
        },
        // dynamic block (type 2)
        .{
            .in = &[_]u8{
                0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // gzip header (10 bytes)
                0x3d, 0xc6, 0x39, 0x11, 0x00, 0x00, 0x0c, 0x02, // deflate data block type 2
                0x30, 0x2b, 0xb5, 0x52, 0x1e, 0xff, 0x96, 0x38,
                0x16, 0x96, 0x5c, 0x1e, 0x94, 0xcb, 0x6d, 0x01,
                0x17, 0x1c, 0x39, 0xb4, 0x13, 0x00, 0x00, 0x00, // gzip footer (chksum, len)
            },
            .out = "ABCDEABCD ABCDEABCD",
        },
        // gzip header with name
        .{
            .in = &[_]u8{
                0x1f, 0x8b, 0x08, 0x08, 0xe5, 0x70, 0xb1, 0x65, 0x00, 0x03, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e,
                0x74, 0x78, 0x74, 0x00, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0xe1,
                0x02, 0x00, 0xd5, 0xe0, 0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00,
            },
            .out = "Hello world\n",
        },
    };
    for (cases) |c| {
        var fb = std.io.fixedBufferStream(c.in);
        var al = std.ArrayList(u8).init(testing.allocator);
        defer al.deinit();

        try decompress(.gzip, fb.reader(), al.writer());
        try testing.expectEqualStrings(c.out, al.items);
    }
}

test "zlib decompress" {
    const cases = [_]struct {
        in: []const u8,
        out: []const u8,
    }{
        // non compressed block (type 0)
        .{
            .in = &[_]u8{
                0x78, 0b10_0_11100, // zlib header (2 bytes)
                0b0000_0001, 0b0000_1100, 0x00, 0b1111_0011, 0xff, // deflate fixed buffer header len, nlen
                'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0x0a, // non compressed data
                0x1c, 0xf2, 0x04, 0x47, // zlib footer: checksum
            },
            .out = "Hello world\n",
        },
    };
    for (cases) |c| {
        var fb = std.io.fixedBufferStream(c.in);
        var al = std.ArrayList(u8).init(testing.allocator);
        defer al.deinit();

        try decompress(.zlib, fb.reader(), al.writer());
        try testing.expectEqualStrings(c.out, al.items);
    }
}

test "fuzzing tests" {
    const cases = [_]struct {
        input: []const u8,
        out: []const u8 = "",
        err: ?anyerror = null,
    }{
        .{ .input = "deflate-stream", .out = @embedFile("testdata/fuzz/deflate-stream.expect") }, // 0
        .{ .input = "empty-distance-alphabet01" },
        .{ .input = "empty-distance-alphabet02" },
        .{ .input = "end-of-stream", .err = error.EndOfStream },
        .{ .input = "invalid-distance", .err = error.InvalidMatch },
        .{ .input = "invalid-tree01", .err = error.IncompleteHuffmanTree }, // 5
        .{ .input = "invalid-tree02", .err = error.IncompleteHuffmanTree },
        .{ .input = "invalid-tree03", .err = error.IncompleteHuffmanTree },
        .{ .input = "lengths-overflow", .err = error.InvalidDynamicBlockHeader },
        .{ .input = "out-of-codes", .err = error.InvalidCode },
        .{ .input = "puff01", .err = error.WrongStoredBlockNlen }, // 10
        .{ .input = "puff02", .err = error.EndOfStream },
        .{ .input = "puff03", .out = &[_]u8{0xa} },
        .{ .input = "puff04", .err = error.InvalidCode },
        .{ .input = "puff05", .err = error.EndOfStream },
        .{ .input = "puff06", .err = error.EndOfStream },
        .{ .input = "puff08", .err = error.InvalidCode },
        .{ .input = "puff09", .out = "P" },
        .{ .input = "puff10", .err = error.InvalidCode },
        .{ .input = "puff11", .err = error.InvalidMatch },
        .{ .input = "puff12", .err = error.InvalidDynamicBlockHeader }, // 20
        .{ .input = "puff13", .err = error.IncompleteHuffmanTree },
        .{ .input = "puff14", .err = error.EndOfStream },
        .{ .input = "puff15", .err = error.IncompleteHuffmanTree },
        .{ .input = "puff16", .err = error.InvalidDynamicBlockHeader },
        .{ .input = "puff17", .err = error.MissingEndOfBlockCode }, // 25
        .{ .input = "fuzz1", .err = error.InvalidDynamicBlockHeader },
        .{ .input = "fuzz2", .err = error.InvalidDynamicBlockHeader },
        .{ .input = "fuzz3", .err = error.InvalidMatch },
        .{ .input = "fuzz4", .err = error.OversubscribedHuffmanTree },
        .{ .input = "puff18", .err = error.OversubscribedHuffmanTree }, // 30
        .{ .input = "puff19", .err = error.OversubscribedHuffmanTree },
        .{ .input = "puff20", .err = error.OversubscribedHuffmanTree },
        .{ .input = "puff21", .err = error.OversubscribedHuffmanTree },
        .{ .input = "puff22", .err = error.OversubscribedHuffmanTree },
        .{ .input = "puff23", .err = error.OversubscribedHuffmanTree }, // 35
        .{ .input = "puff24", .err = error.IncompleteHuffmanTree },
        .{ .input = "puff25", .err = error.OversubscribedHuffmanTree },
        .{ .input = "puff26", .err = error.InvalidDynamicBlockHeader },
        .{ .input = "puff27", .err = error.InvalidDynamicBlockHeader },
    };

    inline for (cases, 0..) |c, case_no| {
        var in = std.io.fixedBufferStream(@embedFile("testdata/fuzz/" ++ c.input ++ ".input"));
        var out = std.ArrayList(u8).init(testing.allocator);
        defer out.deinit();
        errdefer std.debug.print("test case failed {}\n", .{case_no});

        if (c.err) |expected_err| {
            try testing.expectError(expected_err, decompress(.raw, in.reader(), out.writer()));
        } else {
            try decompress(.raw, in.reader(), out.writer());
            try testing.expectEqualStrings(c.out, out.items);
        }
    }
}

test "bug 18966" {
    const input = @embedFile("testdata/fuzz/bug_18966.input");
    const expect = @embedFile("testdata/fuzz/bug_18966.expect");

    var in = std.io.fixedBufferStream(input);
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();

    try decompress(.gzip, in.reader(), out.writer());
    try testing.expectEqualStrings(expect, out.items);
}

test "bug 19895" {
    const input = &[_]u8{
        0b0000_0001, 0b0000_1100, 0x00, 0b1111_0011, 0xff, // deflate fixed buffer header len, nlen
        'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0x0a, // non compressed data
    };
    var in = std.io.fixedBufferStream(input);
    var decomp = decompressor(.raw, in.reader());
    var buf: [0]u8 = undefined;
    try testing.expectEqual(0, try decomp.read(&buf));
}
//! Lookup of the previous locations for the same 4 byte data. Works on hash of
//! 4 bytes data. Head contains position of the first match for each hash. Chain
//! points to the previous position of the same hash given the current location.

const std = @import("std");
const testing = std.testing;
const expect = testing.expect;
const consts = @import("consts.zig");

const Self = @This();

const prime4 = 0x9E3779B1; // 4 bytes prime number 2654435761
const chain_len = 2 * consts.history.len;

// Maps hash => first position
head: [consts.lookup.len]u16 = [_]u16{0} ** consts.lookup.len,
// Maps position => previous positions for the same hash value
chain: [chain_len]u16 = [_]u16{0} ** (chain_len),

// Calculates hash of the 4 bytes from data.
// Inserts `pos` position of that hash in the lookup tables.
// Returns previous location with the same hash value.
pub fn add(self: *Self, data: []const u8, pos: u16) u16 {
    if (data.len < 4) return 0;
    const h = hash(data[0..4]);
    return self.set(h, pos);
}

// Returns previous location with the same hash value given the current
// position.
pub fn prev(self: *Self, pos: u16) u16 {
    return self.chain[pos];
}

fn set(self: *Self, h: u32, pos: u16) u16 {
    const p = self.head[h];
    self.head[h] = pos;
    self.chain[pos] = p;
    return p;
}

// Slide all positions in head and chain for `n`
pub fn slide(self: *Self, n: u16) void {
    for (&self.head) |*v| {
        v.* -|= n;
    }
    var i: usize = 0;
    while (i < n) : (i += 1) {
        self.chain[i] = self.chain[i + n] -| n;
    }
}

// Add `len` 4 bytes hashes from `data` into lookup.
// Position of the first byte is `pos`.
pub fn bulkAdd(self: *Self, data: []const u8, len: u16, pos: u16) void {
    if (len == 0 or data.len < consts.match.min_length) {
        return;
    }
    var hb =
        @as(u32, data[3]) |
        @as(u32, data[2]) << 8 |
        @as(u32, data[1]) << 16 |
        @as(u32, data[0]) << 24;
    _ = self.set(hashu(hb), pos);

    var i = pos;
    for (4..@min(len + 3, data.len)) |j| {
        hb = (hb << 8) | @as(u32, data[j]);
        i += 1;
        _ = self.set(hashu(hb), i);
    }
}

// Calculates hash of the first 4 bytes of `b`.
fn hash(b: *const [4]u8) u32 {
    return hashu(@as(u32, b[3]) |
        @as(u32, b[2]) << 8 |
        @as(u32, b[1]) << 16 |
        @as(u32, b[0]) << 24);
}

fn hashu(v: u32) u32 {
    return @intCast((v *% prime4) >> consts.lookup.shift);
}

test add {
    const data = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03,
    };

    var h: Self = .{};
    for (data, 0..) |_, i| {
        const p = h.add(data[i..], @intCast(i));
        if (i >= 8 and i < 24) {
            try expect(p == i - 8);
        } else {
            try expect(p == 0);
        }
    }

    const v = Self.hash(data[2 .. 2 + 4]);
    try expect(h.head[v] == 2 + 16);
    try expect(h.chain[2 + 16] == 2 + 8);
    try expect(h.chain[2 + 8] == 2);
}

test bulkAdd {
    const data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

    // one by one
    var h: Self = .{};
    for (data, 0..) |_, i| {
        _ = h.add(data[i..], @intCast(i));
    }

    // in bulk
    var bh: Self = .{};
    bh.bulkAdd(data, data.len, 0);

    try testing.expectEqualSlices(u16, &h.head, &bh.head);
    try testing.expectEqualSlices(u16, &h.chain, &bh.chain);
}
//! Used in deflate (compression), holds uncompressed data form which Tokens are
//! produces. In combination with Lookup it is used to find matches in history data.
//!
const std = @import("std");
const consts = @import("consts.zig");

const expect = testing.expect;
const assert = std.debug.assert;
const testing = std.testing;

const hist_len = consts.history.len;
const buffer_len = 2 * hist_len;
const min_lookahead = consts.match.min_length + consts.match.max_length;
const max_rp = buffer_len - min_lookahead;

const Self = @This();

buffer: [buffer_len]u8 = undefined,
wp: usize = 0, // write position
rp: usize = 0, // read position
fp: isize = 0, // last flush position, tokens are build from fp..rp

/// Returns number of bytes written, or 0 if buffer is full and need to slide.
pub fn write(self: *Self, buf: []const u8) usize {
    if (self.rp >= max_rp) return 0; // need to slide

    const n = @min(buf.len, buffer_len - self.wp);
    @memcpy(self.buffer[self.wp .. self.wp + n], buf[0..n]);
    self.wp += n;
    return n;
}

/// Slide buffer for hist_len.
/// Drops old history, preserves between hist_len and hist_len - min_lookahead.
/// Returns number of bytes removed.
pub fn slide(self: *Self) u16 {
    assert(self.rp >= max_rp and self.wp >= self.rp);
    const n = self.wp - hist_len;
    @memcpy(self.buffer[0..n], self.buffer[hist_len..self.wp]);
    self.rp -= hist_len;
    self.wp -= hist_len;
    self.fp -= hist_len;
    return @intCast(n);
}

/// Data from the current position (read position). Those part of the buffer is
/// not converted to tokens yet.
fn lookahead(self: *Self) []const u8 {
    assert(self.wp >= self.rp);
    return self.buffer[self.rp..self.wp];
}

/// Returns part of the lookahead buffer. If should_flush is set no lookahead is
/// preserved otherwise preserves enough data for the longest match. Returns
/// null if there is not enough data.
pub fn activeLookahead(self: *Self, should_flush: bool) ?[]const u8 {
    const min: usize = if (should_flush) 0 else min_lookahead;
    const lh = self.lookahead();
    return if (lh.len > min) lh else null;
}

/// Advances read position, shrinks lookahead.
pub fn advance(self: *Self, n: u16) void {
    assert(self.wp >= self.rp + n);
    self.rp += n;
}

/// Returns writable part of the buffer, where new uncompressed data can be
/// written.
pub fn writable(self: *Self) []u8 {
    return self.buffer[self.wp..];
}

/// Notification of what part of writable buffer is filled with data.
pub fn written(self: *Self, n: usize) void {
    self.wp += n;
}

/// Finds match length between previous and current position.
/// Used in hot path!
pub fn match(self: *Self, prev_pos: u16, curr_pos: u16, min_len: u16) u16 {
    const max_len: usize = @min(self.wp - curr_pos, consts.match.max_length);
    // lookahead buffers from previous and current positions
    const prev_lh = self.buffer[prev_pos..][0..max_len];
    const curr_lh = self.buffer[curr_pos..][0..max_len];

    // If we already have match (min_len > 0),
    // test the first byte above previous len a[min_len] != b[min_len]
    // and then all the bytes from that position to zero.
    // That is likely positions to find difference than looping from first bytes.
    var i: usize = min_len;
    if (i > 0) {
        if (max_len <= i) return 0;
        while (true) {
            if (prev_lh[i] != curr_lh[i]) return 0;
            if (i == 0) break;
            i -= 1;
        }
        i = min_len;
    }
    while (i < max_len) : (i += 1)
        if (prev_lh[i] != curr_lh[i]) break;
    return if (i >= consts.match.min_length) @intCast(i) else 0;
}

/// Current position of non-compressed data. Data before rp are already converted
/// to tokens.
pub fn pos(self: *Self) u16 {
    return @intCast(self.rp);
}

/// Notification that token list is cleared.
pub fn flush(self: *Self) void {
    self.fp = @intCast(self.rp);
}

/// Part of the buffer since last flush or null if there was slide in between (so
/// fp becomes negative).
pub fn tokensBuffer(self: *Self) ?[]const u8 {
    assert(self.fp <= self.rp);
    if (self.fp < 0) return null;
    return self.buffer[@intCast(self.fp)..self.rp];
}

test match {
    const data = "Blah blah blah blah blah!";
    var win: Self = .{};
    try expect(win.write(data) == data.len);
    try expect(win.wp == data.len);
    try expect(win.rp == 0);

    // length between l symbols
    try expect(win.match(1, 6, 0) == 18);
    try expect(win.match(1, 11, 0) == 13);
    try expect(win.match(1, 16, 0) == 8);
    try expect(win.match(1, 21, 0) == 0);

    // position 15 = "blah blah!"
    // position 20 = "blah!"
    try expect(win.match(15, 20, 0) == 4);
    try expect(win.match(15, 20, 3) == 4);
    try expect(win.match(15, 20, 4) == 0);
}

test slide {
    var win: Self = .{};
    win.wp = Self.buffer_len - 11;
    win.rp = Self.buffer_len - 111;
    win.buffer[win.rp] = 0xab;
    try expect(win.lookahead().len == 100);
    try expect(win.tokensBuffer().?.len == win.rp);

    const n = win.slide();
    try expect(n == 32757);
    try expect(win.buffer[win.rp] == 0xab);
    try expect(win.rp == Self.hist_len - 111);
    try expect(win.wp == Self.hist_len - 11);
    try expect(win.lookahead().len == 100);
    try expect(win.tokensBuffer() == null);
}
const Token = @import("../Token.zig");

pub const TestCase = struct {
    tokens: []const Token,
    input: []const u8 = "", // File name of input data matching the tokens.
    want: []const u8 = "", // File name of data with the expected output with input available.
    want_no_input: []const u8 = "", // File name of the expected output when no input is available.
};

pub const testCases = blk: {
    @setEvalBranchQuota(4096 * 2);

    const L = Token.initLiteral;
    const M = Token.initMatch;
    const ml = M(1, 258); // Maximum length token. Used to reduce the size of writeBlockTests

    break :blk &[_]TestCase{
        TestCase{
            .input = "huffman-null-max.input",
            .want = "huffman-null-max.{s}.expect",
            .want_no_input = "huffman-null-max.{s}.expect-noinput",
            .tokens = &[_]Token{
                L(0x0), ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,     ml,     ml, ml, ml,
                ml,     ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, L(0x0), L(0x0),
            },
        },
        TestCase{
            .input = "huffman-pi.input",
            .want = "huffman-pi.{s}.expect",
            .want_no_input = "huffman-pi.{s}.expect-noinput",
            .tokens = &[_]Token{
                L('3'),     L('.'),     L('1'),     L('4'),     L('1'),     L('5'),     L('9'),     L('2'),
                L('6'),     L('5'),     L('3'),     L('5'),     L('8'),     L('9'),     L('7'),     L('9'),
                L('3'),     L('2'),     L('3'),     L('8'),     L('4'),     L('6'),     L('2'),     L('6'),
                L('4'),     L('3'),     L('3'),     L('8'),     L('3'),     L('2'),     L('7'),     L('9'),
                L('5'),     L('0'),     L('2'),     L('8'),     L('8'),     L('4'),     L('1'),     L('9'),
                L('7'),     L('1'),     L('6'),     L('9'),     L('3'),     L('9'),     L('9'),     L('3'),
                L('7'),     L('5'),     L('1'),     L('0'),     L('5'),     L('8'),     L('2'),     L('0'),
                L('9'),     L('7'),     L('4'),     L('9'),     L('4'),     L('4'),     L('5'),     L('9'),
                L('2'),     L('3'),     L('0'),     L('7'),     L('8'),     L('1'),     L('6'),     L('4'),
                L('0'),     L('6'),     L('2'),     L('8'),     L('6'),     L('2'),     L('0'),     L('8'),
                L('9'),     L('9'),     L('8'),     L('6'),     L('2'),     L('8'),     L('0'),     L('3'),
                L('4'),     L('8'),     L('2'),     L('5'),     L('3'),     L('4'),     L('2'),     L('1'),
                L('1'),     L('7'),     L('0'),     L('6'),     L('7'),     L('9'),     L('8'),     L('2'),
                L('1'),     L('4'),     L('8'),     L('0'),     L('8'),     L('6'),     L('5'),     L('1'),
                L('3'),     L('2'),     L('8'),     L('2'),     L('3'),     L('0'),     L('6'),     L('6'),
                L('4'),     L('7'),     L('0'),     L('9'),     L('3'),     L('8'),     L('4'),     L('4'),
                L('6'),     L('0'),     L('9'),     L('5'),     L('5'),     L('0'),     L('5'),     L('8'),
                L('2'),     L('2'),     L('3'),     L('1'),     L('7'),     L('2'),     L('5'),     L('3'),
                L('5'),     L('9'),     L('4'),     L('0'),     L('8'),     L('1'),     L('2'),     L('8'),
                L('4'),     L('8'),     L('1'),     L('1'),     L('1'),     L('7'),     L('4'),     M(127, 4),
                L('4'),     L('1'),     L('0'),     L('2'),     L('7'),     L('0'),     L('1'),     L('9'),
                L('3'),     L('8'),     L('5'),     L('2'),     L('1'),     L('1'),     L('0'),     L('5'),
                L('5'),     L('5'),     L('9'),     L('6'),     L('4'),     L('4'),     L('6'),     L('2'),
                L('2'),     L('9'),     L('4'),     L('8'),     L('9'),     L('5'),     L('4'),     L('9'),
                L('3'),     L('0'),     L('3'),     L('8'),     L('1'),     M(19, 4),   L('2'),     L('8'),
                L('8'),     L('1'),     L('0'),     L('9'),     L('7'),     L('5'),     L('6'),     L('6'),
                L('5'),     L('9'),     L('3'),     L('3'),     L('4'),     L('4'),     L('6'),     M(72, 4),
                L('7'),     L('5'),     L('6'),     L('4'),     L('8'),     L('2'),     L('3'),     L('3'),
                L('7'),     L('8'),     L('6'),     L('7'),     L('8'),     L('3'),     L('1'),     L('6'),
                L('5'),     L('2'),     L('7'),     L('1'),     L('2'),     L('0'),     L('1'),     L('9'),
                L('0'),     L('9'),     L('1'),     L('4'),     M(27, 4),   L('5'),     L('6'),     L('6'),
                L('9'),     L('2'),     L('3'),     L('4'),     L('6'),     M(179, 4),  L('6'),     L('1'),
                L('0'),     L('4'),     L('5'),     L('4'),     L('3'),     L('2'),     L('6'),     M(51, 4),
                L('1'),     L('3'),     L('3'),     L('9'),     L('3'),     L('6'),     L('0'),     L('7'),
                L('2'),     L('6'),     L('0'),     L('2'),     L('4'),     L('9'),     L('1'),     L('4'),
                L('1'),     L('2'),     L('7'),     L('3'),     L('7'),     L('2'),     L('4'),     L('5'),
                L('8'),     L('7'),     L('0'),     L('0'),     L('6'),     L('6'),     L('0'),     L('6'),
                L('3'),     L('1'),     L('5'),     L('5'),     L('8'),     L('8'),     L('1'),     L('7'),
                L('4'),     L('8'),     L('8'),     L('1'),     L('5'),     L('2'),     L('0'),     L('9'),
                L('2'),     L('0'),     L('9'),     L('6'),     L('2'),     L('8'),     L('2'),     L('9'),
                L('2'),     L('5'),     L('4'),     L('0'),     L('9'),     L('1'),     L('7'),     L('1'),
                L('5'),     L('3'),     L('6'),     L('4'),     L('3'),     L('6'),     L('7'),     L('8'),
                L('9'),     L('2'),     L('5'),     L('9'),     L('0'),     L('3'),     L('6'),     L('0'),
                L('0'),     L('1'),     L('1'),     L('3'),     L('3'),     L('0'),     L('5'),     L('3'),
                L('0'),     L('5'),     L('4'),     L('8'),     L('8'),     L('2'),     L('0'),     L('4'),
                L('6'),     L('6'),     L('5'),     L('2'),     L('1'),     L('3'),     L('8'),     L('4'),
                L('1'),     L('4'),     L('6'),     L('9'),     L('5'),     L('1'),     L('9'),     L('4'),
                L('1'),     L('5'),     L('1'),     L('1'),     L('6'),     L('0'),     L('9'),     L('4'),
                L('3'),     L('3'),     L('0'),     L('5'),     L('7'),     L('2'),     L('7'),     L('0'),
                L('3'),     L('6'),     L('5'),     L('7'),     L('5'),     L('9'),     L('5'),     L('9'),
                L('1'),     L('9'),     L('5'),     L('3'),     L('0'),     L('9'),     L('2'),     L('1'),
                L('8'),     L('6'),     L('1'),     L('1'),     L('7'),     M(234, 4),  L('3'),     L('2'),
                M(10, 4),   L('9'),     L('3'),     L('1'),     L('0'),     L('5'),     L('1'),     L('1'),
                L('8'),     L('5'),     L('4'),     L('8'),     L('0'),     L('7'),     M(271, 4),  L('3'),
                L('7'),     L('9'),     L('9'),     L('6'),     L('2'),     L('7'),     L('4'),     L('9'),
                L('5'),     L('6'),     L('7'),     L('3'),     L('5'),     L('1'),     L('8'),     L('8'),
                L('5'),     L('7'),     L('5'),     L('2'),     L('7'),     L('2'),     L('4'),     L('8'),
                L('9'),     L('1'),     L('2'),     L('2'),     L('7'),     L('9'),     L('3'),     L('8'),
                L('1'),     L('8'),     L('3'),     L('0'),     L('1'),     L('1'),     L('9'),     L('4'),
                L('9'),     L('1'),     L('2'),     L('9'),     L('8'),     L('3'),     L('3'),     L('6'),
                L('7'),     L('3'),     L('3'),     L('6'),     L('2'),     L('4'),     L('4'),     L('0'),
                L('6'),     L('5'),     L('6'),     L('6'),     L('4'),     L('3'),     L('0'),     L('8'),
                L('6'),     L('0'),     L('2'),     L('1'),     L('3'),     L('9'),     L('4'),     L('9'),
                L('4'),     L('6'),     L('3'),     L('9'),     L('5'),     L('2'),     L('2'),     L('4'),
                L('7'),     L('3'),     L('7'),     L('1'),     L('9'),     L('0'),     L('7'),     L('0'),
                L('2'),     L('1'),     L('7'),     L('9'),     L('8'),     M(154, 5),  L('7'),     L('0'),
                L('2'),     L('7'),     L('7'),     L('0'),     L('5'),     L('3'),     L('9'),     L('2'),
                L('1'),     L('7'),     L('1'),     L('7'),     L('6'),     L('2'),     L('9'),     L('3'),
                L('1'),     L('7'),     L('6'),     L('7'),     L('5'),     M(563, 5),  L('7'),     L('4'),
                L('8'),     L('1'),     M(7, 4),    L('6'),     L('6'),     L('9'),     L('4'),     L('0'),
                M(488, 4),  L('0'),     L('0'),     L('0'),     L('5'),     L('6'),     L('8'),     L('1'),
                L('2'),     L('7'),     L('1'),     L('4'),     L('5'),     L('2'),     L('6'),     L('3'),
                L('5'),     L('6'),     L('0'),     L('8'),     L('2'),     L('7'),     L('7'),     L('8'),
                L('5'),     L('7'),     L('7'),     L('1'),     L('3'),     L('4'),     L('2'),     L('7'),
                L('5'),     L('7'),     L('7'),     L('8'),     L('9'),     L('6'),     M(298, 4),  L('3'),
                L('6'),     L('3'),     L('7'),     L('1'),     L('7'),     L('8'),     L('7'),     L('2'),
                L('1'),     L('4'),     L('6'),     L('8'),     L('4'),     L('4'),     L('0'),     L('9'),
                L('0'),     L('1'),     L('2'),     L('2'),     L('4'),     L('9'),     L('5'),     L('3'),
                L('4'),     L('3'),     L('0'),     L('1'),     L('4'),     L('6'),     L('5'),     L('4'),
                L('9'),     L('5'),     L('8'),     L('5'),     L('3'),     L('7'),     L('1'),     L('0'),
                L('5'),     L('0'),     L('7'),     L('9'),     M(203, 4),  L('6'),     M(340, 4),  L('8'),
                L('9'),     L('2'),     L('3'),     L('5'),     L('4'),     M(458, 4),  L('9'),     L('5'),
                L('6'),     L('1'),     L('1'),     L('2'),     L('1'),     L('2'),     L('9'),     L('0'),
                L('2'),     L('1'),     L('9'),     L('6'),     L('0'),     L('8'),     L('6'),     L('4'),
                L('0'),     L('3'),     L('4'),     L('4'),     L('1'),     L('8'),     L('1'),     L('5'),
                L('9'),     L('8'),     L('1'),     L('3'),     L('6'),     L('2'),     L('9'),     L('7'),
                L('7'),     L('4'),     M(117, 4),  L('0'),     L('9'),     L('9'),     L('6'),     L('0'),
                L('5'),     L('1'),     L('8'),     L('7'),     L('0'),     L('7'),     L('2'),     L('1'),
                L('1'),     L('3'),     L('4'),     L('9'),     M(1, 5),    L('8'),     L('3'),     L('7'),
                L('2'),     L('9'),     L('7'),     L('8'),     L('0'),     L('4'),     L('9'),     L('9'),
                M(731, 4),  L('9'),     L('7'),     L('3'),     L('1'),     L('7'),     L('3'),     L('2'),
                L('8'),     M(395, 4),  L('6'),     L('3'),     L('1'),     L('8'),     L('5'),     M(770, 4),
                M(745, 4),  L('4'),     L('5'),     L('5'),     L('3'),     L('4'),     L('6'),     L('9'),
                L('0'),     L('8'),     L('3'),     L('0'),     L('2'),     L('6'),     L('4'),     L('2'),
                L('5'),     L('2'),     L('2'),     L('3'),     L('0'),     M(740, 4),  M(616, 4),  L('8'),
                L('5'),     L('0'),     L('3'),     L('5'),     L('2'),     L('6'),     L('1'),     L('9'),
                L('3'),     L('1'),     L('1'),     M(531, 4),  L('1'),     L('0'),     L('1'),     L('0'),
                L('0'),     L('0'),     L('3'),     L('1'),     L('3'),     L('7'),     L('8'),     L('3'),
                L('8'),     L('7'),     L('5'),     L('2'),     L('8'),     L('8'),     L('6'),     L('5'),
                L('8'),     L('7'),     L('5'),     L('3'),     L('3'),     L('2'),     L('0'),     L('8'),
                L('3'),     L('8'),     L('1'),     L('4'),     L('2'),     L('0'),     L('6'),     M(321, 4),
                M(300, 4),  L('1'),     L('4'),     L('7'),     L('3'),     L('0'),     L('3'),     L('5'),
                L('9'),     M(815, 5),  L('9'),     L('0'),     L('4'),     L('2'),     L('8'),     L('7'),
                L('5'),     L('5'),     L('4'),     L('6'),     L('8'),     L('7'),     L('3'),     L('1'),
                L('1'),     L('5'),     L('9'),     L('5'),     M(854, 4),  L('3'),     L('8'),     L('8'),
                L('2'),     L('3'),     L('5'),     L('3'),     L('7'),     L('8'),     L('7'),     L('5'),
                M(896, 5),  L('9'),     M(315, 4),  L('1'),     M(329, 4),  L('8'),     L('0'),     L('5'),
                L('3'),     M(395, 4),  L('2'),     L('2'),     L('6'),     L('8'),     L('0'),     L('6'),
                L('6'),     L('1'),     L('3'),     L('0'),     L('0'),     L('1'),     L('9'),     L('2'),
                L('7'),     L('8'),     L('7'),     L('6'),     L('6'),     L('1'),     L('1'),     L('1'),
                L('9'),     L('5'),     L('9'),     M(568, 4),  L('6'),     M(293, 5),  L('8'),     L('9'),
                L('3'),     L('8'),     L('0'),     L('9'),     L('5'),     L('2'),     L('5'),     L('7'),
                L('2'),     L('0'),     L('1'),     L('0'),     L('6'),     L('5'),     L('4'),     L('8'),
                L('5'),     L('8'),     L('6'),     L('3'),     L('2'),     L('7'),     M(155, 4),  L('9'),
                L('3'),     L('6'),     L('1'),     L('5'),     L('3'),     M(545, 4),  M(349, 5),  L('2'),
                L('3'),     L('0'),     L('3'),     L('0'),     L('1'),     L('9'),     L('5'),     L('2'),
                L('0'),     L('3'),     L('5'),     L('3'),     L('0'),     L('1'),     L('8'),     L('5'),
                L('2'),     M(370, 4),  M(118, 4),  L('3'),     L('6'),     L('2'),     L('2'),     L('5'),
                L('9'),     L('9'),     L('4'),     L('1'),     L('3'),     M(597, 4),  L('4'),     L('9'),
                L('7'),     L('2'),     L('1'),     L('7'),     M(223, 4),  L('3'),     L('4'),     L('7'),
                L('9'),     L('1'),     L('3'),     L('1'),     L('5'),     L('1'),     L('5'),     L('5'),
                L('7'),     L('4'),     L('8'),     L('5'),     L('7'),     L('2'),     L('4'),     L('2'),
                L('4'),     L('5'),     L('4'),     L('1'),     L('5'),     L('0'),     L('6'),     L('9'),
                M(320, 4),  L('8'),     L('2'),     L('9'),     L('5'),     L('3'),     L('3'),     L('1'),
                L('1'),     L('6'),     L('8'),     L('6'),     L('1'),     L('7'),     L('2'),     L('7'),
                L('8'),     M(824, 4),  L('9'),     L('0'),     L('7'),     L('5'),     L('0'),     L('9'),
                M(270, 4),  L('7'),     L('5'),     L('4'),     L('6'),     L('3'),     L('7'),     L('4'),
                L('6'),     L('4'),     L('9'),     L('3'),     L('9'),     L('3'),     L('1'),     L('9'),
                L('2'),     L('5'),     L('5'),     L('0'),     L('6'),     L('0'),     L('4'),     L('0'),
                L('0'),     L('9'),     M(620, 4),  L('1'),     L('6'),     L('7'),     L('1'),     L('1'),
                L('3'),     L('9'),     L('0'),     L('0'),     L('9'),     L('8'),     M(822, 4),  L('4'),
                L('0'),     L('1'),     L('2'),     L('8'),     L('5'),     L('8'),     L('3'),     L('6'),
                L('1'),     L('6'),     L('0'),     L('3'),     L('5'),     L('6'),     L('3'),     L('7'),
                L('0'),     L('7'),     L('6'),     L('6'),     L('0'),     L('1'),     L('0'),     L('4'),
                M(371, 4),  L('8'),     L('1'),     L('9'),     L('4'),     L('2'),     L('9'),     M(1055, 5),
                M(240, 4),  M(652, 4),  L('7'),     L('8'),     L('3'),     L('7'),     L('4'),     M(1193, 4),
                L('8'),     L('2'),     L('5'),     L('5'),     L('3'),     L('7'),     M(522, 5),  L('2'),
                L('6'),     L('8'),     M(47, 4),   L('4'),     L('0'),     L('4'),     L('7'),     M(466, 4),
                L('4'),     M(1206, 4), M(910, 4),  L('8'),     L('4'),     M(937, 4),  L('6'),     M(800, 6),
                L('3'),     L('3'),     L('1'),     L('3'),     L('6'),     L('7'),     L('7'),     L('0'),
                L('2'),     L('8'),     L('9'),     L('8'),     L('9'),     L('1'),     L('5'),     L('2'),
                M(99, 4),   L('5'),     L('2'),     L('1'),     L('6'),     L('2'),     L('0'),     L('5'),
                L('6'),     L('9'),     L('6'),     M(1042, 4), L('0'),     L('5'),     L('8'),     M(1144, 4),
                L('5'),     M(1177, 4), L('5'),     L('1'),     L('1'),     M(522, 4),  L('8'),     L('2'),
                L('4'),     L('3'),     L('0'),     L('0'),     L('3'),     L('5'),     L('5'),     L('8'),
                L('7'),     L('6'),     L('4'),     L('0'),     L('2'),     L('4'),     L('7'),     L('4'),
                L('9'),     L('6'),     L('4'),     L('7'),     L('3'),     L('2'),     L('6'),     L('3'),
                M(1087, 4), L('9'),     L('9'),     L('2'),     M(1100, 4), L('4'),     L('2'),     L('6'),
                L('9'),     M(710, 6),  L('7'),     M(471, 4),  L('4'),     M(1342, 4), M(1054, 4), L('9'),
                L('3'),     L('4'),     L('1'),     L('7'),     M(430, 4),  L('1'),     L('2'),     M(43, 4),
                L('4'),     M(415, 4),  L('1'),     L('5'),     L('0'),     L('3'),     L('0'),     L('2'),
                L('8'),     L('6'),     L('1'),     L('8'),     L('2'),     L('9'),     L('7'),     L('4'),
                L('5'),     L('5'),     L('5'),     L('7'),     L('0'),     L('6'),     L('7'),     L('4'),
                M(310, 4),  L('5'),     L('0'),     L('5'),     L('4'),     L('9'),     L('4'),     L('5'),
                L('8'),     M(454, 4),  L('9'),     M(82, 4),   L('5'),     L('6'),     M(493, 4),  L('7'),
                L('2'),     L('1'),     L('0'),     L('7'),     L('9'),     M(346, 4),  L('3'),     L('0'),
                M(267, 4),  L('3'),     L('2'),     L('1'),     L('1'),     L('6'),     L('5'),     L('3'),
                L('4'),     L('4'),     L('9'),     L('8'),     L('7'),     L('2'),     L('0'),     L('2'),
                L('7'),     M(284, 4),  L('0'),     L('2'),     L('3'),     L('6'),     L('4'),     M(559, 4),
                L('5'),     L('4'),     L('9'),     L('9'),     L('1'),     L('1'),     L('9'),     L('8'),
                M(1049, 4), L('4'),     M(284, 4),  L('5'),     L('3'),     L('5'),     L('6'),     L('6'),
                L('3'),     L('6'),     L('9'),     M(1105, 4), L('2'),     L('6'),     L('5'),     M(741, 4),
                L('7'),     L('8'),     L('6'),     L('2'),     L('5'),     L('5'),     L('1'),     M(987, 4),
                L('1'),     L('7'),     L('5'),     L('7'),     L('4'),     L('6'),     L('7'),     L('2'),
                L('8'),     L('9'),     L('0'),     L('9'),     L('7'),     L('7'),     L('7'),     L('7'),
                M(1108, 5), L('0'),     L('0'),     L('0'),     M(1534, 4), L('7'),     L('0'),     M(1248, 4),
                L('6'),     M(1002, 4), L('4'),     L('9'),     L('1'),     M(1055, 4), M(664, 4),  L('2'),
                L('1'),     L('4'),     L('7'),     L('7'),     L('2'),     L('3'),     L('5'),     L('0'),
                L('1'),     L('4'),     L('1'),     L('4'),     M(1604, 4), L('3'),     L('5'),     L('6'),
                M(1200, 4), L('1'),     L('6'),     L('1'),     L('3'),     L('6'),     L('1'),     L('1'),
                L('5'),     L('7'),     L('3'),     L('5'),     L('2'),     L('5'),     M(1285, 4), L('3'),
                L('4'),     M(92, 4),   L('1'),     L('8'),     M(1148, 4), L('8'),     L('4'),     M(1512, 4),
                L('3'),     L('3'),     L('2'),     L('3'),     L('9'),     L('0'),     L('7'),     L('3'),
                L('9'),     L('4'),     L('1'),     L('4'),     L('3'),     L('3'),     L('3'),     L('4'),
                L('5'),     L('4'),     L('7'),     L('7'),     L('6'),     L('2'),     L('4'),     M(579, 4),
                L('2'),     L('5'),     L('1'),     L('8'),     L('9'),     L('8'),     L('3'),     L('5'),
                L('6'),     L('9'),     L('4'),     L('8'),     L('5'),     L('5'),     L('6'),     L('2'),
                L('0'),     L('9'),     L('9'),     L('2'),     L('1'),     L('9'),     L('2'),     L('2'),
                L('2'),     L('1'),     L('8'),     L('4'),     L('2'),     L('7'),     M(575, 4),  L('2'),
                M(187, 4),  L('6'),     L('8'),     L('8'),     L('7'),     L('6'),     L('7'),     L('1'),
                L('7'),     L('9'),     L('0'),     M(86, 4),   L('0'),     M(263, 5),  L('6'),     L('6'),
                M(1000, 4), L('8'),     L('8'),     L('6'),     L('2'),     L('7'),     L('2'),     M(1757, 4),
                L('1'),     L('7'),     L('8'),     L('6'),     L('0'),     L('8'),     L('5'),     L('7'),
                M(116, 4),  L('3'),     M(765, 5),  L('7'),     L('9'),     L('7'),     L('6'),     L('6'),
                L('8'),     L('1'),     M(702, 4),  L('0'),     L('0'),     L('9'),     L('5'),     L('3'),
                L('8'),     L('8'),     M(1593, 4), L('3'),     M(1702, 4), L('0'),     L('6'),     L('8'),
                L('0'),     L('0'),     L('6'),     L('4'),     L('2'),     L('2'),     L('5'),     L('1'),
                L('2'),     L('5'),     L('2'),     M(1404, 4), L('7'),     L('3'),     L('9'),     L('2'),
                M(664, 4),  M(1141, 4), L('4'),     M(1716, 5), L('8'),     L('6'),     L('2'),     L('6'),
                L('9'),     L('4'),     L('5'),     M(486, 4),  L('4'),     L('1'),     L('9'),     L('6'),
                L('5'),     L('2'),     L('8'),     L('5'),     L('0'),     M(154, 4),  M(925, 4),  L('1'),
                L('8'),     L('6'),     L('3'),     M(447, 4),  L('4'),     M(341, 5),  L('2'),     L('0'),
                L('3'),     L('9'),     M(1420, 4), L('4'),     L('5'),     M(701, 4),  L('2'),     L('3'),
                L('7'),     M(1069, 4), L('6'),     M(1297, 4), L('5'),     L('6'),     M(1593, 4), L('7'),
                L('1'),     L('9'),     L('1'),     L('7'),     L('2'),     L('8'),     M(370, 4),  L('7'),
                L('6'),     L('4'),     L('6'),     L('5'),     L('7'),     L('5'),     L('7'),     L('3'),
                L('9'),     M(258, 4),  L('3'),     L('8'),     L('9'),     M(1865, 4), L('8'),     L('3'),
                L('2'),     L('6'),     L('4'),     L('5'),     L('9'),     L('9'),     L('5'),     L('8'),
                M(1704, 4), L('0'),     L('4'),     L('7'),     L('8'),     M(479, 4),  M(809, 4),  L('9'),
                M(46, 4),   L('6'),     L('4'),     L('0'),     L('7'),     L('8'),     L('9'),     L('5'),
                L('1'),     M(143, 4),  L('6'),     L('8'),     L('3'),     M(304, 4),  L('2'),     L('5'),
                L('9'),     L('5'),     L('7'),     L('0'),     M(1129, 4), L('8'),     L('2'),     L('2'),
                M(713, 4),  L('2'),     M(1564, 4), L('4'),     L('0'),     L('7'),     L('7'),     L('2'),
                L('6'),     L('7'),     L('1'),     L('9'),     L('4'),     L('7'),     L('8'),     M(794, 4),
                L('8'),     L('2'),     L('6'),     L('0'),     L('1'),     L('4'),     L('7'),     L('6'),
                L('9'),     L('9'),     L('0'),     L('9'),     M(1257, 4), L('0'),     L('1'),     L('3'),
                L('6'),     L('3'),     L('9'),     L('4'),     L('4'),     L('3'),     M(640, 4),  L('3'),
                L('0'),     M(262, 4),  L('2'),     L('0'),     L('3'),     L('4'),     L('9'),     L('6'),
                L('2'),     L('5'),     L('2'),     L('4'),     L('5'),     L('1'),     L('7'),     M(950, 4),
                L('9'),     L('6'),     L('5'),     L('1'),     L('4'),     L('3'),     L('1'),     L('4'),
                L('2'),     L('9'),     L('8'),     L('0'),     L('9'),     L('1'),     L('9'),     L('0'),
                L('6'),     L('5'),     L('9'),     L('2'),     M(643, 4),  L('7'),     L('2'),     L('2'),
                L('1'),     L('6'),     L('9'),     L('6'),     L('4'),     L('6'),     M(1050, 4), M(123, 4),
                L('5'),     M(1295, 4), L('4'),     M(1382, 5), L('8'),     M(1370, 4), L('9'),     L('7'),
                M(1404, 4), L('5'),     L('4'),     M(1182, 4), M(575, 4),  L('7'),     M(1627, 4), L('8'),
                L('4'),     L('6'),     L('8'),     L('1'),     L('3'),     M(141, 4),  L('6'),     L('8'),
                L('3'),     L('8'),     L('6'),     L('8'),     L('9'),     L('4'),     L('2'),     L('7'),
                L('7'),     L('4'),     L('1'),     L('5'),     L('5'),     L('9'),     L('9'),     L('1'),
                L('8'),     L('5'),     M(91, 4),   L('2'),     L('4'),     L('5'),     L('9'),     L('5'),
                L('3'),     L('9'),     L('5'),     L('9'),     L('4'),     L('3'),     L('1'),     M(1464, 4),
                L('7'),     M(19, 4),   L('6'),     L('8'),     L('0'),     L('8'),     L('4'),     L('5'),
                M(744, 4),  L('7'),     L('3'),     M(2079, 4), L('9'),     L('5'),     L('8'),     L('4'),
                L('8'),     L('6'),     L('5'),     L('3'),     L('8'),     M(1769, 4), L('6'),     L('2'),
                M(243, 4),  L('6'),     L('0'),     L('9'),     M(1207, 4), L('6'),     L('0'),     L('8'),
                L('0'),     L('5'),     L('1'),     L('2'),     L('4'),     L('3'),     L('8'),     L('8'),
                L('4'),     M(315, 4),  M(12, 4),   L('4'),     L('1'),     L('3'),     M(784, 4),  L('7'),
                L('6'),     L('2'),     L('7'),     L('8'),     M(834, 4),  L('7'),     L('1'),     L('5'),
                M(1436, 4), L('3'),     L('5'),     L('9'),     L('9'),     L('7'),     L('7'),     L('0'),
                L('0'),     L('1'),     L('2'),     L('9'),     M(1139, 4), L('8'),     L('9'),     L('4'),
                L('4'),     L('1'),     M(632, 4),  L('6'),     L('8'),     L('5'),     L('5'),     M(96, 4),
                L('4'),     L('0'),     L('6'),     L('3'),     M(2279, 4), L('2'),     L('0'),     L('7'),
                L('2'),     L('2'),     M(345, 4),  M(516, 5),  L('4'),     L('8'),     L('1'),     L('5'),
                L('8'),     M(518, 4),  M(511, 4),  M(635, 4),  M(665, 4),  L('3'),     L('9'),     L('4'),
                L('5'),     L('2'),     L('2'),     L('6'),     L('7'),     M(1175, 6), L('8'),     M(1419, 4),
                L('2'),     L('1'),     M(747, 4),  L('2'),     M(904, 4),  L('5'),     L('4'),     L('6'),
                L('6'),     L('6'),     M(1308, 4), L('2'),     L('3'),     L('9'),     L('8'),     L('6'),
                L('4'),     L('5'),     L('6'),     M(1221, 4), L('1'),     L('6'),     L('3'),     L('5'),
                M(596, 5),  M(2066, 4), L('7'),     M(2222, 4), L('9'),     L('8'),     M(1119, 4), L('9'),
                L('3'),     L('6'),     L('3'),     L('4'),     M(1884, 4), L('7'),     L('4'),     L('3'),
                L('2'),     L('4'),     M(1148, 4), L('1'),     L('5'),     L('0'),     L('7'),     L('6'),
                M(1212, 4), L('7'),     L('9'),     L('4'),     L('5'),     L('1'),     L('0'),     L('9'),
                M(63, 4),   L('0'),     L('9'),     L('4'),     L('0'),     M(1703, 4), L('8'),     L('8'),
                L('7'),     L('9'),     L('7'),     L('1'),     L('0'),     L('8'),     L('9'),     L('3'),
                M(2289, 4), L('6'),     L('9'),     L('1'),     L('3'),     L('6'),     L('8'),     L('6'),
                L('7'),     L('2'),     M(604, 4),  M(511, 4),  L('5'),     M(1344, 4), M(1129, 4), M(2050, 4),
                L('1'),     L('7'),     L('9'),     L('2'),     L('8'),     L('6'),     L('8'),     M(2253, 4),
                L('8'),     L('7'),     L('4'),     L('7'),     M(1951, 5), L('8'),     L('2'),     L('4'),
                M(2427, 4), L('8'),     M(604, 4),  L('7'),     L('1'),     L('4'),     L('9'),     L('0'),
                L('9'),     L('6'),     L('7'),     L('5'),     L('9'),     L('8'),     M(1776, 4), L('3'),
                L('6'),     L('5'),     M(309, 4),  L('8'),     L('1'),     M(93, 4),   M(1862, 4), M(2359, 4),
                L('6'),     L('8'),     L('2'),     L('9'),     M(1407, 4), L('8'),     L('7'),     L('2'),
                L('2'),     L('6'),     L('5'),     L('8'),     L('8'),     L('0'),     M(1554, 4), L('5'),
                M(586, 4),  L('4'),     L('2'),     L('7'),     L('0'),     L('4'),     L('7'),     L('7'),
                L('5'),     L('5'),     M(2079, 4), L('3'),     L('7'),     L('9'),     L('6'),     L('4'),
                L('1'),     L('4'),     L('5'),     L('1'),     L('5'),     L('2'),     M(1534, 4), L('2'),
                L('3'),     L('4'),     L('3'),     L('6'),     L('4'),     L('5'),     L('4'),     M(1503, 4),
                L('4'),     L('4'),     L('4'),     L('7'),     L('9'),     L('5'),     M(61, 4),   M(1316, 4),
                M(2279, 5), L('4'),     L('1'),     M(1323, 4), L('3'),     M(773, 4),  L('5'),     L('2'),
                L('3'),     L('1'),     M(2114, 5), L('1'),     L('6'),     L('6'),     L('1'),     M(2227, 4),
                L('5'),     L('9'),     L('6'),     L('9'),     L('5'),     L('3'),     L('6'),     L('2'),
                L('3'),     L('1'),     L('4'),     M(1536, 4), L('2'),     L('4'),     L('8'),     L('4'),
                L('9'),     L('3'),     L('7'),     L('1'),     L('8'),     L('7'),     L('1'),     L('1'),
                L('0'),     L('1'),     L('4'),     L('5'),     L('7'),     L('6'),     L('5'),     L('4'),
                M(1890, 4), L('0'),     L('2'),     L('7'),     L('9'),     L('9'),     L('3'),     L('4'),
                L('4'),     L('0'),     L('3'),     L('7'),     L('4'),     L('2'),     L('0'),     L('0'),
                L('7'),     M(2368, 4), L('7'),     L('8'),     L('5'),     L('3'),     L('9'),     L('0'),
                L('6'),     L('2'),     L('1'),     L('9'),     M(666, 5),  M(838, 4),  L('8'),     L('4'),
                L('7'),     M(979, 5),  L('8'),     L('3'),     L('3'),     L('2'),     L('1'),     L('4'),
                L('4'),     L('5'),     L('7'),     L('1'),     M(645, 4),  M(1911, 4), L('4'),     L('3'),
                L('5'),     L('0'),     M(2345, 4), M(1129, 4), L('5'),     L('3'),     L('1'),     L('9'),
                L('1'),     L('0'),     L('4'),     L('8'),     L('4'),     L('8'),     L('1'),     L('0'),
                L('0'),     L('5'),     L('3'),     L('7'),     L('0'),     L('6'),     M(2237, 4), M(1438, 5),
                M(1922, 5), L('1'),     M(1370, 4), L('7'),     M(796, 4),  L('5'),     M(2029, 4), M(1037, 4),
                L('6'),     L('3'),     M(2013, 5), L('4'),     M(2418, 4), M(847, 5),  M(1014, 5), L('8'),
                M(1326, 5), M(2184, 5), L('9'),     M(392, 4),  L('9'),     L('1'),     M(2255, 4), L('8'),
                L('1'),     L('4'),     L('6'),     L('7'),     L('5'),     L('1'),     M(1580, 4), L('1'),
                L('2'),     L('3'),     L('9'),     M(426, 6),  L('9'),     L('0'),     L('7'),     L('1'),
                L('8'),     L('6'),     L('4'),     L('9'),     L('4'),     L('2'),     L('3'),     L('1'),
                L('9'),     L('6'),     L('1'),     L('5'),     L('6'),     M(493, 4),  M(1725, 4), L('9'),
                L('5'),     M(2343, 4), M(1130, 4), M(284, 4),  L('6'),     L('0'),     L('3'),     L('8'),
                M(2598, 4), M(368, 4),  M(901, 4),  L('6'),     L('2'),     M(1115, 4), L('5'),     M(2125, 4),
                L('6'),     L('3'),     L('8'),     L('9'),     L('3'),     L('7'),     L('7'),     L('8'),
                L('7'),     M(2246, 4), M(249, 4),  L('9'),     L('7'),     L('9'),     L('2'),     L('0'),
                L('7'),     L('7'),     L('3'),     M(1496, 4), L('2'),     L('1'),     L('8'),     L('2'),
                L('5'),     L('6'),     M(2016, 4), L('6'),     L('6'),     M(1751, 4), L('4'),     L('2'),
                M(1663, 5), L('6'),     M(1767, 4), L('4'),     L('4'),     M(37, 4),   L('5'),     L('4'),
                L('9'),     L('2'),     L('0'),     L('2'),     L('6'),     L('0'),     L('5'),     M(2740, 4),
                M(997, 5),  L('2'),     L('0'),     L('1'),     L('4'),     L('9'),     M(1235, 4), L('8'),
                L('5'),     L('0'),     L('7'),     L('3'),     M(1434, 4), L('6'),     L('6'),     L('6'),
                L('0'),     M(405, 4),  L('2'),     L('4'),     L('3'),     L('4'),     L('0'),     M(136, 4),
                L('0'),     M(1900, 4), L('8'),     L('6'),     L('3'),     M(2391, 4), M(2021, 4), M(1068, 4),
                M(373, 4),  L('5'),     L('7'),     L('9'),     L('6'),     L('2'),     L('6'),     L('8'),
                L('5'),     L('6'),     M(321, 4),  L('5'),     L('0'),     L('8'),     M(1316, 4), L('5'),
                L('8'),     L('7'),     L('9'),     L('6'),     L('9'),     L('9'),     M(1810, 4), L('5'),
                L('7'),     L('4'),     M(2585, 4), L('8'),     L('4'),     L('0'),     M(2228, 4), L('1'),
                L('4'),     L('5'),     L('9'),     L('1'),     M(1933, 4), L('7'),     L('0'),     M(565, 4),
                L('0'),     L('1'),     M(3048, 4), L('1'),     L('2'),     M(3189, 4), L('0'),     M(964, 4),
                L('3'),     L('9'),     M(2859, 4), M(275, 4),  L('7'),     L('1'),     L('5'),     M(945, 4),
                L('4'),     L('2'),     L('0'),     M(3059, 5), L('9'),     M(3011, 4), L('0'),     L('7'),
                M(834, 4),  M(1942, 4), M(2736, 4), M(3171, 4), L('2'),     L('1'),     M(2401, 4), L('2'),
                L('5'),     L('1'),     M(1404, 4), M(2373, 4), L('9'),     L('2'),     M(435, 4),  L('8'),
                L('2'),     L('6'),     M(2919, 4), L('2'),     M(633, 4),  L('3'),     L('2'),     L('1'),
                L('5'),     L('7'),     L('9'),     L('1'),     L('9'),     L('8'),     L('4'),     L('1'),
                L('4'),     M(2172, 5), L('9'),     L('1'),     L('6'),     L('4'),     M(1769, 5), L('9'),
                M(2905, 5), M(2268, 4), L('7'),     L('2'),     L('2'),     M(802, 4),  L('5'),     M(2213, 4),
                M(322, 4),  L('9'),     L('1'),     L('0'),     M(189, 4),  M(3164, 4), L('5'),     L('2'),
                L('8'),     L('0'),     L('1'),     L('7'),     M(562, 4),  L('7'),     L('1'),     L('2'),
                M(2325, 4), L('8'),     L('3'),     L('2'),     M(884, 4),  L('1'),     M(1418, 4), L('0'),
                L('9'),     L('3'),     L('5'),     L('3'),     L('9'),     L('6'),     L('5'),     L('7'),
                M(1612, 4), L('1'),     L('0'),     L('8'),     L('3'),     M(106, 4),  L('5'),     L('1'),
                M(1915, 4), M(3419, 4), L('1'),     L('4'),     L('4'),     L('4'),     L('2'),     L('1'),
                L('0'),     L('0'),     M(515, 4),  L('0'),     L('3'),     M(413, 4),  L('1'),     L('1'),
                L('0'),     L('3'),     M(3202, 4), M(10, 4),   M(39, 4),   M(1539, 6), L('5'),     L('1'),
                L('6'),     M(1498, 4), M(2180, 5), M(2347, 4), L('5'),     M(3139, 5), L('8'),     L('5'),
                L('1'),     L('7'),     L('1'),     L('4'),     L('3'),     L('7'),     M(1542, 4), M(110, 4),
                L('1'),     L('5'),     L('5'),     L('6'),     L('5'),     L('0'),     L('8'),     L('8'),
                M(954, 4),  L('9'),     L('8'),     L('9'),     L('8'),     L('5'),     L('9'),     L('9'),
                L('8'),     L('2'),     L('3'),     L('8'),     M(464, 4),  M(2491, 4), L('3'),     M(365, 4),
                M(1087, 4), M(2500, 4), L('8'),     M(3590, 5), L('3'),     L('2'),     M(264, 4),  L('5'),
                M(774, 4),  L('3'),     M(459, 4),  L('9'),     M(1052, 4), L('9'),     L('8'),     M(2174, 4),
                L('4'),     M(3257, 4), L('7'),     M(1612, 4), L('0'),     L('7'),     M(230, 4),  L('4'),
                L('8'),     L('1'),     L('4'),     L('1'),     M(1338, 4), L('8'),     L('5'),     L('9'),
                L('4'),     L('6'),     L('1'),     M(3018, 4), L('8'),     L('0'),
            },
        },
        TestCase{
            .input = "huffman-rand-1k.input",
            .want = "huffman-rand-1k.{s}.expect",
            .want_no_input = "huffman-rand-1k.{s}.expect-noinput",
            .tokens = &[_]Token{
                L(0xf8), L(0x8b), L(0x96), L(0x76), L(0x48), L(0xd),  L(0x85), L(0x94), L(0x25), L(0x80), L(0xaf), L(0xc2), L(0xfe), L(0x8d),
                L(0xe8), L(0x20), L(0xeb), L(0x17), L(0x86), L(0xc9), L(0xb7), L(0xc5), L(0xde), L(0x6),  L(0xea), L(0x7d), L(0x18), L(0x8b),
                L(0xe7), L(0x3e), L(0x7),  L(0xda), L(0xdf), L(0xff), L(0x6c), L(0x73), L(0xde), L(0xcc), L(0xe7), L(0x6d), L(0x8d), L(0x4),
                L(0x19), L(0x49), L(0x7f), L(0x47), L(0x1f), L(0x48), L(0x15), L(0xb0), L(0xe8), L(0x9e), L(0xf2), L(0x31), L(0x59), L(0xde),
                L(0x34), L(0xb4), L(0x5b), L(0xe5), L(0xe0), L(0x9),  L(0x11), L(0x30), L(0xc2), L(0x88), L(0x5b), L(0x7c), L(0x5d), L(0x14),
                L(0x13), L(0x6f), L(0x23), L(0xa9), L(0xd),  L(0xbc), L(0x2d), L(0x23), L(0xbe), L(0xd9), L(0xed), L(0x75), L(0x4),  L(0x6c),
                L(0x99), L(0xdf), L(0xfd), L(0x70), L(0x66), L(0xe6), L(0xee), L(0xd9), L(0xb1), L(0x9e), L(0x6e), L(0x83), L(0x59), L(0xd5),
                L(0xd4), L(0x80), L(0x59), L(0x98), L(0x77), L(0x89), L(0x43), L(0x38), L(0xc9), L(0xaf), L(0x30), L(0x32), L(0x9a), L(0x20),
                L(0x1b), L(0x46), L(0x3d), L(0x67), L(0x6e), L(0xd7), L(0x72), L(0x9e), L(0x4e), L(0x21), L(0x4f), L(0xc6), L(0xe0), L(0xd4),
                L(0x7b), L(0x4),  L(0x8d), L(0xa5), L(0x3),  L(0xf6), L(0x5),  L(0x9b), L(0x6b), L(0xdc), L(0x2a), L(0x93), L(0x77), L(0x28),
                L(0xfd), L(0xb4), L(0x62), L(0xda), L(0x20), L(0xe7), L(0x1f), L(0xab), L(0x6b), L(0x51), L(0x43), L(0x39), L(0x2f), L(0xa0),
                L(0x92), L(0x1),  L(0x6c), L(0x75), L(0x3e), L(0xf4), L(0x35), L(0xfd), L(0x43), L(0x2e), L(0xf7), L(0xa4), L(0x75), L(0xda),
                L(0xea), L(0x9b), L(0xa),  L(0x64), L(0xb),  L(0xe0), L(0x23), L(0x29), L(0xbd), L(0xf7), L(0xe7), L(0x83), L(0x3c), L(0xfb),
                L(0xdf), L(0xb3), L(0xae), L(0x4f), L(0xa4), L(0x47), L(0x55), L(0x99), L(0xde), L(0x2f), L(0x96), L(0x6e), L(0x1c), L(0x43),
                L(0x4c), L(0x87), L(0xe2), L(0x7c), L(0xd9), L(0x5f), L(0x4c), L(0x7c), L(0xe8), L(0x90), L(0x3),  L(0xdb), L(0x30), L(0x95),
                L(0xd6), L(0x22), L(0xc),  L(0x47), L(0xb8), L(0x4d), L(0x6b), L(0xbd), L(0x24), L(0x11), L(0xab), L(0x2c), L(0xd7), L(0xbe),
                L(0x6e), L(0x7a), L(0xd6), L(0x8),  L(0xa3), L(0x98), L(0xd8), L(0xdd), L(0x15), L(0x6a), L(0xfa), L(0x93), L(0x30), L(0x1),
                L(0x25), L(0x1d), L(0xa2), L(0x74), L(0x86), L(0x4b), L(0x6a), L(0x95), L(0xe8), L(0xe1), L(0x4e), L(0xe),  L(0x76), L(0xb9),
                L(0x49), L(0xa9), L(0x5f), L(0xa0), L(0xa6), L(0x63), L(0x3c), L(0x7e), L(0x7e), L(0x20), L(0x13), L(0x4f), L(0xbb), L(0x66),
                L(0x92), L(0xb8), L(0x2e), L(0xa4), L(0xfa), L(0x48), L(0xcb), L(0xae), L(0xb9), L(0x3c), L(0xaf), L(0xd3), L(0x1f), L(0xe1),
                L(0xd5), L(0x8d), L(0x42), L(0x6d), L(0xf0), L(0xfc), L(0x8c), L(0xc),  L(0x0),  L(0xde), L(0x40), L(0xab), L(0x8b), L(0x47),
                L(0x97), L(0x4e), L(0xa8), L(0xcf), L(0x8e), L(0xdb), L(0xa6), L(0x8b), L(0x20), L(0x9),  L(0x84), L(0x7a), L(0x66), L(0xe5),
                L(0x98), L(0x29), L(0x2),  L(0x95), L(0xe6), L(0x38), L(0x32), L(0x60), L(0x3),  L(0xe3), L(0x9a), L(0x1e), L(0x54), L(0xe8),
                L(0x63), L(0x80), L(0x48), L(0x9c), L(0xe7), L(0x63), L(0x33), L(0x6e), L(0xa0), L(0x65), L(0x83), L(0xfa), L(0xc6), L(0xba),
                L(0x7a), L(0x43), L(0x71), L(0x5),  L(0xf5), L(0x68), L(0x69), L(0x85), L(0x9c), L(0xba), L(0x45), L(0xcd), L(0x6b), L(0xb),
                L(0x19), L(0xd1), L(0xbb), L(0x7f), L(0x70), L(0x85), L(0x92), L(0xd1), L(0xb4), L(0x64), L(0x82), L(0xb1), L(0xe4), L(0x62),
                L(0xc5), L(0x3c), L(0x46), L(0x1f), L(0x92), L(0x31), L(0x1c), L(0x4e), L(0x41), L(0x77), L(0xf7), L(0xe7), L(0x87), L(0xa2),
                L(0xf),  L(0x6e), L(0xe8), L(0x92), L(0x3),  L(0x6b), L(0xa),  L(0xe7), L(0xa9), L(0x3b), L(0x11), L(0xda), L(0x66), L(0x8a),
                L(0x29), L(0xda), L(0x79), L(0xe1), L(0x64), L(0x8d), L(0xe3), L(0x54), L(0xd4), L(0xf5), L(0xef), L(0x64), L(0x87), L(0x3b),
                L(0xf4), L(0xc2), L(0xf4), L(0x71), L(0x13), L(0xa9), L(0xe9), L(0xe0), L(0xa2), L(0x6),  L(0x14), L(0xab), L(0x5d), L(0xa7),
                L(0x96), L(0x0),  L(0xd6), L(0xc3), L(0xcc), L(0x57), L(0xed), L(0x39), L(0x6a), L(0x25), L(0xcd), L(0x76), L(0xea), L(0xba),
                L(0x3a), L(0xf2), L(0xa1), L(0x95), L(0x5d), L(0xe5), L(0x71), L(0xcf), L(0x9c), L(0x62), L(0x9e), L(0x6a), L(0xfa), L(0xd5),
                L(0x31), L(0xd1), L(0xa8), L(0x66), L(0x30), L(0x33), L(0xaa), L(0x51), L(0x17), L(0x13), L(0x82), L(0x99), L(0xc8), L(0x14),
                L(0x60), L(0x9f), L(0x4d), L(0x32), L(0x6d), L(0xda), L(0x19), L(0x26), L(0x21), L(0xdc), L(0x7e), L(0x2e), L(0x25), L(0x67),
                L(0x72), L(0xca), L(0xf),  L(0x92), L(0xcd), L(0xf6), L(0xd6), L(0xcb), L(0x97), L(0x8a), L(0x33), L(0x58), L(0x73), L(0x70),
                L(0x91), L(0x1d), L(0xbf), L(0x28), L(0x23), L(0xa3), L(0xc),  L(0xf1), L(0x83), L(0xc3), L(0xc8), L(0x56), L(0x77), L(0x68),
                L(0xe3), L(0x82), L(0xba), L(0xb9), L(0x57), L(0x56), L(0x57), L(0x9c), L(0xc3), L(0xd6), L(0x14), L(0x5),  L(0x3c), L(0xb1),
                L(0xaf), L(0x93), L(0xc8), L(0x8a), L(0x57), L(0x7f), L(0x53), L(0xfa), L(0x2f), L(0xaa), L(0x6e), L(0x66), L(0x83), L(0xfa),
                L(0x33), L(0xd1), L(0x21), L(0xab), L(0x1b), L(0x71), L(0xb4), L(0x7c), L(0xda), L(0xfd), L(0xfb), L(0x7f), L(0x20), L(0xab),
                L(0x5e), L(0xd5), L(0xca), L(0xfd), L(0xdd), L(0xe0), L(0xee), L(0xda), L(0xba), L(0xa8), L(0x27), L(0x99), L(0x97), L(0x69),
                L(0xc1), L(0x3c), L(0x82), L(0x8c), L(0xa),  L(0x5c), L(0x2d), L(0x5b), L(0x88), L(0x3e), L(0x34), L(0x35), L(0x86), L(0x37),
                L(0x46), L(0x79), L(0xe1), L(0xaa), L(0x19), L(0xfb), L(0xaa), L(0xde), L(0x15), L(0x9),  L(0xd),  L(0x1a), L(0x57), L(0xff),
                L(0xb5), L(0xf),  L(0xf3), L(0x2b), L(0x5a), L(0x6a), L(0x4d), L(0x19), L(0x77), L(0x71), L(0x45), L(0xdf), L(0x4f), L(0xb3),
                L(0xec), L(0xf1), L(0xeb), L(0x18), L(0x53), L(0x3e), L(0x3b), L(0x47), L(0x8),  L(0x9a), L(0x73), L(0xa0), L(0x5c), L(0x8c),
                L(0x5f), L(0xeb), L(0xf),  L(0x3a), L(0xc2), L(0x43), L(0x67), L(0xb4), L(0x66), L(0x67), L(0x80), L(0x58), L(0xe),  L(0xc1),
                L(0xec), L(0x40), L(0xd4), L(0x22), L(0x94), L(0xca), L(0xf9), L(0xe8), L(0x92), L(0xe4), L(0x69), L(0x38), L(0xbe), L(0x67),
                L(0x64), L(0xca), L(0x50), L(0xc7), L(0x6),  L(0x67), L(0x42), L(0x6e), L(0xa3), L(0xf0), L(0xb7), L(0x6c), L(0xf2), L(0xe8),
                L(0x5f), L(0xb1), L(0xaf), L(0xe7), L(0xdb), L(0xbb), L(0x77), L(0xb5), L(0xf8), L(0xcb), L(0x8),  L(0xc4), L(0x75), L(0x7e),
                L(0xc0), L(0xf9), L(0x1c), L(0x7f), L(0x3c), L(0x89), L(0x2f), L(0xd2), L(0x58), L(0x3a), L(0xe2), L(0xf8), L(0x91), L(0xb6),
                L(0x7b), L(0x24), L(0x27), L(0xe9), L(0xae), L(0x84), L(0x8b), L(0xde), L(0x74), L(0xac), L(0xfd), L(0xd9), L(0xb7), L(0x69),
                L(0x2a), L(0xec), L(0x32), L(0x6f), L(0xf0), L(0x92), L(0x84), L(0xf1), L(0x40), L(0xc),  L(0x8a), L(0xbc), L(0x39), L(0x6e),
                L(0x2e), L(0x73), L(0xd4), L(0x6e), L(0x8a), L(0x74), L(0x2a), L(0xdc), L(0x60), L(0x1f), L(0xa3), L(0x7),  L(0xde), L(0x75),
                L(0x8b), L(0x74), L(0xc8), L(0xfe), L(0x63), L(0x75), L(0xf6), L(0x3d), L(0x63), L(0xac), L(0x33), L(0x89), L(0xc3), L(0xf0),
                L(0xf8), L(0x2d), L(0x6b), L(0xb4), L(0x9e), L(0x74), L(0x8b), L(0x5c), L(0x33), L(0xb4), L(0xca), L(0xa8), L(0xe4), L(0x99),
                L(0xb6), L(0x90), L(0xa1), L(0xef), L(0xf),  L(0xd3), L(0x61), L(0xb2), L(0xc6), L(0x1a), L(0x94), L(0x7c), L(0x44), L(0x55),
                L(0xf4), L(0x45), L(0xff), L(0x9e), L(0xa5), L(0x5a), L(0xc6), L(0xa0), L(0xe8), L(0x2a), L(0xc1), L(0x8d), L(0x6f), L(0x34),
                L(0x11), L(0xb9), L(0xbe), L(0x4e), L(0xd9), L(0x87), L(0x97), L(0x73), L(0xcf), L(0x3d), L(0x23), L(0xae), L(0xd5), L(0x1a),
                L(0x5e), L(0xae), L(0x5d), L(0x6a), L(0x3),  L(0xf9), L(0x22), L(0xd),  L(0x10), L(0xd9), L(0x47), L(0x69), L(0x15), L(0x3f),
                L(0xee), L(0x52), L(0xa3), L(0x8),  L(0xd2), L(0x3c), L(0x51), L(0xf4), L(0xf8), L(0x9d), L(0xe4), L(0x98), L(0x89), L(0xc8),
                L(0x67), L(0x39), L(0xd5), L(0x5e), L(0x35), L(0x78), L(0x27), L(0xe8), L(0x3c), L(0x80), L(0xae), L(0x79), L(0x71), L(0xd2),
                L(0x93), L(0xf4), L(0xaa), L(0x51), L(0x12), L(0x1c), L(0x4b), L(0x1b), L(0xe5), L(0x6e), L(0x15), L(0x6f), L(0xe4), L(0xbb),
                L(0x51), L(0x9b), L(0x45), L(0x9f), L(0xf9), L(0xc4), L(0x8c), L(0x2a), L(0xfb), L(0x1a), L(0xdf), L(0x55), L(0xd3), L(0x48),
                L(0x93), L(0x27), L(0x1),  L(0x26), L(0xc2), L(0x6b), L(0x55), L(0x6d), L(0xa2), L(0xfb), L(0x84), L(0x8b), L(0xc9), L(0x9e),
                L(0x28), L(0xc2), L(0xef), L(0x1a), L(0x24), L(0xec), L(0x9b), L(0xae), L(0xbd), L(0x60), L(0xe9), L(0x15), L(0x35), L(0xee),
                L(0x42), L(0xa4), L(0x33), L(0x5b), L(0xfa), L(0xf),  L(0xb6), L(0xf7), L(0x1),  L(0xa6), L(0x2),  L(0x4c), L(0xca), L(0x90),
                L(0x58), L(0x3a), L(0x96), L(0x41), L(0xe7), L(0xcb), L(0x9),  L(0x8c), L(0xdb), L(0x85), L(0x4d), L(0xa8), L(0x89), L(0xf3),
                L(0xb5), L(0x8e), L(0xfd), L(0x75), L(0x5b), L(0x4f), L(0xed), L(0xde), L(0x3f), L(0xeb), L(0x38), L(0xa3), L(0xbe), L(0xb0),
                L(0x73), L(0xfc), L(0xb8), L(0x54), L(0xf7), L(0x4c), L(0x30), L(0x67), L(0x2e), L(0x38), L(0xa2), L(0x54), L(0x18), L(0xba),
                L(0x8),  L(0xbf), L(0xf2), L(0x39), L(0xd5), L(0xfe), L(0xa5), L(0x41), ```
