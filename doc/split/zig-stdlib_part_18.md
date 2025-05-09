```
its)));
                },
            }
        }

        /// Read n number of bits.
        /// Only buffered flag can be used in how.
        pub fn readN(self: *Self, n: u4, comptime how: u3) !u16 {
            switch (how) {
                0 => {
                    try self.fill(n);
                },
                flag.buffered => {},
                else => unreachable,
            }
            const mask: u16 = (@as(u16, 1) << n) - 1;
            const u: u16 = @as(u16, @truncate(self.bits)) & mask;
            try self.shift(n);
            return u;
        }

        /// Advance buffer for n bits.
        pub fn shift(self: *Self, n: Tshift) !void {
            if (n > self.nbits) return error.EndOfStream;
            self.bits >>= n;
            self.nbits -= n;
        }

        /// Skip n bytes.
        pub fn skipBytes(self: *Self, n: u16) !void {
            for (0..n) |_| {
                try self.fill(8);
                try self.shift(8);
            }
        }

        // Number of bits to align stream to the byte boundary.
        fn alignBits(self: *Self) u3 {
            return @intCast(self.nbits & 0x7);
        }

        /// Align stream to the byte boundary.
        pub fn alignToByte(self: *Self) void {
            const ab = self.alignBits();
            if (ab > 0) self.shift(ab) catch unreachable;
        }

        /// Skip zero terminated string.
        pub fn skipStringZ(self: *Self) !void {
            while (true) {
                if (try self.readF(u8, 0) == 0) break;
            }
        }

        /// Read deflate fixed fixed code.
        /// Reads first 7 bits, and then maybe 1 or 2 more to get full 7,8 or 9 bit code.
        /// ref: https://datatracker.ietf.org/doc/html/rfc1951#page-12
        ///         Lit Value    Bits        Codes
        ///          ---------    ----        -----
        ///            0 - 143     8          00110000 through
        ///                                   10111111
        ///          144 - 255     9          110010000 through
        ///                                   111111111
        ///          256 - 279     7          0000000 through
        ///                                   0010111
        ///          280 - 287     8          11000000 through
        ///                                   11000111
        pub fn readFixedCode(self: *Self) !u16 {
            try self.fill(7 + 2);
            const code7 = try self.readF(u7, flag.buffered | flag.reverse);
            if (code7 <= 0b0010_111) { // 7 bits, 256-279, codes 0000_000 - 0010_111
                return @as(u16, code7) + 256;
            } else if (code7 <= 0b1011_111) { // 8 bits, 0-143, codes 0011_0000 through 1011_1111
                return (@as(u16, code7) << 1) + @as(u16, try self.readF(u1, flag.buffered)) - 0b0011_0000;
            } else if (code7 <= 0b1100_011) { // 8 bit, 280-287, codes 1100_0000 - 1100_0111
                return (@as(u16, code7 - 0b1100000) << 1) + try self.readF(u1, flag.buffered) + 280;
            } else { // 9 bit, 144-255, codes 1_1001_0000 - 1_1111_1111
                return (@as(u16, code7 - 0b1100_100) << 2) + @as(u16, try self.readF(u2, flag.buffered | flag.reverse)) + 144;
            }
        }
    };
}

test "readF" {
    var fbs = std.io.fixedBufferStream(&[_]u8{ 0xf3, 0x48, 0xcd, 0xc9, 0x00, 0x00 });
    var br = bitReader(u64, fbs.reader());
    const F = BitReader64(@TypeOf(fbs.reader())).flag;

    try testing.expectEqual(@as(u8, 48), br.nbits);
    try testing.expectEqual(@as(u64, 0xc9cd48f3), br.bits);

    try testing.expect(try br.readF(u1, 0) == 0b0000_0001);
    try testing.expect(try br.readF(u2, 0) == 0b0000_0001);
    try testing.expectEqual(@as(u8, 48 - 3), br.nbits);
    try testing.expectEqual(@as(u3, 5), br.alignBits());

    try testing.expect(try br.readF(u8, F.peek) == 0b0001_1110);
    try testing.expect(try br.readF(u9, F.peek) == 0b1_0001_1110);
    try br.shift(9);
    try testing.expectEqual(@as(u8, 36), br.nbits);
    try testing.expectEqual(@as(u3, 4), br.alignBits());

    try testing.expect(try br.readF(u4, 0) == 0b0100);
    try testing.expectEqual(@as(u8, 32), br.nbits);
    try testing.expectEqual(@as(u3, 0), br.alignBits());

    try br.shift(1);
    try testing.expectEqual(@as(u3, 7), br.alignBits());
    try br.shift(1);
    try testing.expectEqual(@as(u3, 6), br.alignBits());
    br.alignToByte();
    try testing.expectEqual(@as(u3, 0), br.alignBits());

    try testing.expectEqual(@as(u64, 0xc9), br.bits);
    try testing.expectEqual(@as(u16, 0x9), try br.readN(4, 0));
    try testing.expectEqual(@as(u16, 0xc), try br.readN(4, 0));
}

test "read block type 1 data" {
    inline for ([_]type{ u64, u32 }) |T| {
        const data = [_]u8{
            0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, // deflate data block type 1
            0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00,
            0x0c, 0x01, 0x02, 0x03, //
            0xaa, 0xbb, 0xcc, 0xdd,
        };
        var fbs = std.io.fixedBufferStream(&data);
        var br = bitReader(T, fbs.reader());
        const F = BitReader(T, @TypeOf(fbs.reader())).flag;

        try testing.expectEqual(@as(u1, 1), try br.readF(u1, 0)); // bfinal
        try testing.expectEqual(@as(u2, 1), try br.readF(u2, 0)); // block_type

        for ("Hello world\n") |c| {
            try testing.expectEqual(@as(u8, c), try br.readF(u8, F.reverse) - 0x30);
        }
        try testing.expectEqual(@as(u7, 0), try br.readF(u7, 0)); // end of block
        br.alignToByte();
        try testing.expectEqual(@as(u32, 0x0302010c), try br.readF(u32, 0));
        try testing.expectEqual(@as(u16, 0xbbaa), try br.readF(u16, 0));
        try testing.expectEqual(@as(u16, 0xddcc), try br.readF(u16, 0));
    }
}

test "shift/fill" {
    const data = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    var fbs = std.io.fixedBufferStream(&data);
    var br = bitReader(u64, fbs.reader());

    try testing.expectEqual(@as(u64, 0x08_07_06_05_04_03_02_01), br.bits);
    try br.shift(8);
    try testing.expectEqual(@as(u64, 0x00_08_07_06_05_04_03_02), br.bits);
    try br.fill(60); // fill with 1 byte
    try testing.expectEqual(@as(u64, 0x01_08_07_06_05_04_03_02), br.bits);
    try br.shift(8 * 4 + 4);
    try testing.expectEqual(@as(u64, 0x00_00_00_00_00_10_80_70), br.bits);

    try br.fill(60); // fill with 4 bytes (shift by 4)
    try testing.expectEqual(@as(u64, 0x00_50_40_30_20_10_80_70), br.bits);
    try testing.expectEqual(@as(u8, 8 * 7 + 4), br.nbits);

    try br.shift(@intCast(br.nbits)); // clear buffer
    try br.fill(8); // refill with the rest of the bytes
    try testing.expectEqual(@as(u64, 0x00_00_00_00_00_08_07_06), br.bits);
}

test "readAll" {
    inline for ([_]type{ u64, u32 }) |T| {
        const data = [_]u8{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        };
        var fbs = std.io.fixedBufferStream(&data);
        var br = bitReader(T, fbs.reader());

        switch (T) {
            u64 => try testing.expectEqual(@as(u64, 0x08_07_06_05_04_03_02_01), br.bits),
            u32 => try testing.expectEqual(@as(u32, 0x04_03_02_01), br.bits),
            else => unreachable,
        }

        var out: [16]u8 = undefined;
        try br.readAll(out[0..]);
        try testing.expect(br.nbits == 0);
        try testing.expect(br.bits == 0);

        try testing.expectEqualSlices(u8, data[0..16], &out);
    }
}

test "readFixedCode" {
    inline for ([_]type{ u64, u32 }) |T| {
        const fixed_codes = @import("huffman_encoder.zig").fixed_codes;

        var fbs = std.io.fixedBufferStream(&fixed_codes);
        var rdr = bitReader(T, fbs.reader());

        for (0..286) |c| {
            try testing.expectEqual(c, try rdr.readFixedCode());
        }
        try testing.expect(rdr.nbits == 0);
    }
}

test "u32 leaves no bits on u32 reads" {
    const data = [_]u8{
        0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    var fbs = std.io.fixedBufferStream(&data);
    var br = bitReader(u32, fbs.reader());

    _ = try br.read(u3);
    try testing.expectEqual(29, br.nbits);
    br.alignToByte();
    try testing.expectEqual(24, br.nbits);
    try testing.expectEqual(0x04_03_02_01, try br.read(u32));
    try testing.expectEqual(0, br.nbits);
    try testing.expectEqual(0x08_07_06_05, try br.read(u32));
    try testing.expectEqual(0, br.nbits);

    _ = try br.read(u9);
    try testing.expectEqual(23, br.nbits);
    br.alignToByte();
    try testing.expectEqual(16, br.nbits);
    try testing.expectEqual(0x0e_0d_0c_0b, try br.read(u32));
    try testing.expectEqual(0, br.nbits);
}

test "u64 need fill after alignToByte" {
    const data = [_]u8{
        0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    // without fill
    var fbs = std.io.fixedBufferStream(&data);
    var br = bitReader(u64, fbs.reader());
    _ = try br.read(u23);
    try testing.expectEqual(41, br.nbits);
    br.alignToByte();
    try testing.expectEqual(40, br.nbits);
    try testing.expectEqual(0x06_05_04_03, try br.read(u32));
    try testing.expectEqual(8, br.nbits);
    try testing.expectEqual(0x0a_09_08_07, try br.read(u32));
    try testing.expectEqual(32, br.nbits);

    // fill after align ensures all bits filled
    fbs.reset();
    br = bitReader(u64, fbs.reader());
    _ = try br.read(u23);
    try testing.expectEqual(41, br.nbits);
    br.alignToByte();
    try br.fill(0);
    try testing.expectEqual(64, br.nbits);
    try testing.expectEqual(0x06_05_04_03, try br.read(u32));
    try testing.expectEqual(32, br.nbits);
    try testing.expectEqual(0x0a_09_08_07, try br.read(u32));
    try testing.expectEqual(0, br.nbits);
}
const std = @import("std");
const assert = std.debug.assert;

/// Bit writer for use in deflate (compression).
///
/// Has internal bits buffer of 64 bits and internal bytes buffer of 248 bytes.
/// When we accumulate 48 bits 6 bytes are moved to the bytes buffer. When we
/// accumulate 240 bytes they are flushed to the underlying inner_writer.
///
pub fn BitWriter(comptime WriterType: type) type {
    // buffer_flush_size indicates the buffer size
    // after which bytes are flushed to the writer.
    // Should preferably be a multiple of 6, since
    // we accumulate 6 bytes between writes to the buffer.
    const buffer_flush_size = 240;

    // buffer_size is the actual output byte buffer size.
    // It must have additional headroom for a flush
    // which can contain up to 8 bytes.
    const buffer_size = buffer_flush_size + 8;

    return struct {
        inner_writer: WriterType,

        // Data waiting to be written is bytes[0 .. nbytes]
        // and then the low nbits of bits.  Data is always written
        // sequentially into the bytes array.
        bits: u64 = 0,
        nbits: u32 = 0, // number of bits
        bytes: [buffer_size]u8 = undefined,
        nbytes: u32 = 0, // number of bytes

        const Self = @This();

        pub const Error = WriterType.Error || error{UnfinishedBits};

        pub fn init(writer: WriterType) Self {
            return .{ .inner_writer = writer };
        }

        pub fn setWriter(self: *Self, new_writer: WriterType) void {
            //assert(self.bits == 0 and self.nbits == 0 and self.nbytes == 0);
            self.inner_writer = new_writer;
        }

        pub fn flush(self: *Self) Error!void {
            var n = self.nbytes;
            while (self.nbits != 0) {
                self.bytes[n] = @as(u8, @truncate(self.bits));
                self.bits >>= 8;
                if (self.nbits > 8) { // Avoid underflow
                    self.nbits -= 8;
                } else {
                    self.nbits = 0;
                }
                n += 1;
            }
            self.bits = 0;
            _ = try self.inner_writer.write(self.bytes[0..n]);
            self.nbytes = 0;
        }

        pub fn writeBits(self: *Self, b: u32, nb: u32) Error!void {
            self.bits |= @as(u64, @intCast(b)) << @as(u6, @intCast(self.nbits));
            self.nbits += nb;
            if (self.nbits < 48)
                return;

            var n = self.nbytes;
            std.mem.writeInt(u64, self.bytes[n..][0..8], self.bits, .little);
            n += 6;
            if (n >= buffer_flush_size) {
                _ = try self.inner_writer.write(self.bytes[0..n]);
                n = 0;
            }
            self.nbytes = n;
            self.bits >>= 48;
            self.nbits -= 48;
        }

        pub fn writeBytes(self: *Self, bytes: []const u8) Error!void {
            var n = self.nbytes;
            if (self.nbits & 7 != 0) {
                return error.UnfinishedBits;
            }
            while (self.nbits != 0) {
                self.bytes[n] = @as(u8, @truncate(self.bits));
                self.bits >>= 8;
                self.nbits -= 8;
                n += 1;
            }
            if (n != 0) {
                _ = try self.inner_writer.write(self.bytes[0..n]);
            }
            self.nbytes = 0;
            _ = try self.inner_writer.write(bytes);
        }
    };
}
const std = @import("std");
const io = std.io;
const assert = std.debug.assert;

const hc = @import("huffman_encoder.zig");
const consts = @import("consts.zig").huffman;
const Token = @import("Token.zig");
const BitWriter = @import("bit_writer.zig").BitWriter;

pub fn blockWriter(writer: anytype) BlockWriter(@TypeOf(writer)) {
    return BlockWriter(@TypeOf(writer)).init(writer);
}

/// Accepts list of tokens, decides what is best block type to write. What block
/// type will provide best compression. Writes header and body of the block.
///
pub fn BlockWriter(comptime WriterType: type) type {
    const BitWriterType = BitWriter(WriterType);
    return struct {
        const codegen_order = consts.codegen_order;
        const end_code_mark = 255;
        const Self = @This();

        pub const Error = BitWriterType.Error;
        bit_writer: BitWriterType,

        codegen_freq: [consts.codegen_code_count]u16 = undefined,
        literal_freq: [consts.max_num_lit]u16 = undefined,
        distance_freq: [consts.distance_code_count]u16 = undefined,
        codegen: [consts.max_num_lit + consts.distance_code_count + 1]u8 = undefined,
        literal_encoding: hc.LiteralEncoder = .{},
        distance_encoding: hc.DistanceEncoder = .{},
        codegen_encoding: hc.CodegenEncoder = .{},
        fixed_literal_encoding: hc.LiteralEncoder,
        fixed_distance_encoding: hc.DistanceEncoder,
        huff_distance: hc.DistanceEncoder,

        pub fn init(writer: WriterType) Self {
            return .{
                .bit_writer = BitWriterType.init(writer),
                .fixed_literal_encoding = hc.fixedLiteralEncoder(),
                .fixed_distance_encoding = hc.fixedDistanceEncoder(),
                .huff_distance = hc.huffmanDistanceEncoder(),
            };
        }

        /// Flush intrenal bit buffer to the writer.
        /// Should be called only when bit stream is at byte boundary.
        ///
        /// That is after final block; when last byte could be incomplete or
        /// after stored block; which is aligned to the byte boundary (it has x
        /// padding bits after first 3 bits).
        pub fn flush(self: *Self) Error!void {
            try self.bit_writer.flush();
        }

        pub fn setWriter(self: *Self, new_writer: WriterType) void {
            self.bit_writer.setWriter(new_writer);
        }

        fn writeCode(self: *Self, c: hc.HuffCode) Error!void {
            try self.bit_writer.writeBits(c.code, c.len);
        }

        // RFC 1951 3.2.7 specifies a special run-length encoding for specifying
        // the literal and distance lengths arrays (which are concatenated into a single
        // array).  This method generates that run-length encoding.
        //
        // The result is written into the codegen array, and the frequencies
        // of each code is written into the codegen_freq array.
        // Codes 0-15 are single byte codes. Codes 16-18 are followed by additional
        // information. Code bad_code is an end marker
        //
        // num_literals: The number of literals in literal_encoding
        // num_distances: The number of distances in distance_encoding
        // lit_enc: The literal encoder to use
        // dist_enc: The distance encoder to use
        fn generateCodegen(
            self: *Self,
            num_literals: u32,
            num_distances: u32,
            lit_enc: *hc.LiteralEncoder,
            dist_enc: *hc.DistanceEncoder,
        ) void {
            for (self.codegen_freq, 0..) |_, i| {
                self.codegen_freq[i] = 0;
            }

            // Note that we are using codegen both as a temporary variable for holding
            // a copy of the frequencies, and as the place where we put the result.
            // This is fine because the output is always shorter than the input used
            // so far.
            var codegen = &self.codegen; // cache
            // Copy the concatenated code sizes to codegen. Put a marker at the end.
            var cgnl = codegen[0..num_literals];
            for (cgnl, 0..) |_, i| {
                cgnl[i] = @as(u8, @intCast(lit_enc.codes[i].len));
            }

            cgnl = codegen[num_literals .. num_literals + num_distances];
            for (cgnl, 0..) |_, i| {
                cgnl[i] = @as(u8, @intCast(dist_enc.codes[i].len));
            }
            codegen[num_literals + num_distances] = end_code_mark;

            var size = codegen[0];
            var count: i32 = 1;
            var out_index: u32 = 0;
            var in_index: u32 = 1;
            while (size != end_code_mark) : (in_index += 1) {
                // INVARIANT: We have seen "count" copies of size that have not yet
                // had output generated for them.
                const next_size = codegen[in_index];
                if (next_size == size) {
                    count += 1;
                    continue;
                }
                // We need to generate codegen indicating "count" of size.
                if (size != 0) {
                    codegen[out_index] = size;
                    out_index += 1;
                    self.codegen_freq[size] += 1;
                    count -= 1;
                    while (count >= 3) {
                        var n: i32 = 6;
                        if (n > count) {
                            n = count;
                        }
                        codegen[out_index] = 16;
                        out_index += 1;
                        codegen[out_index] = @as(u8, @intCast(n - 3));
                        out_index += 1;
                        self.codegen_freq[16] += 1;
                        count -= n;
                    }
                } else {
                    while (count >= 11) {
                        var n: i32 = 138;
                        if (n > count) {
                            n = count;
                        }
                        codegen[out_index] = 18;
                        out_index += 1;
                        codegen[out_index] = @as(u8, @intCast(n - 11));
                        out_index += 1;
                        self.codegen_freq[18] += 1;
                        count -= n;
                    }
                    if (count >= 3) {
                        // 3 <= count <= 10
                        codegen[out_index] = 17;
                        out_index += 1;
                        codegen[out_index] = @as(u8, @intCast(count - 3));
                        out_index += 1;
                        self.codegen_freq[17] += 1;
                        count = 0;
                    }
                }
                count -= 1;
                while (count >= 0) : (count -= 1) {
                    codegen[out_index] = size;
                    out_index += 1;
                    self.codegen_freq[size] += 1;
                }
                // Set up invariant for next time through the loop.
                size = next_size;
                count = 1;
            }
            // Marker indicating the end of the codegen.
            codegen[out_index] = end_code_mark;
        }

        const DynamicSize = struct {
            size: u32,
            num_codegens: u32,
        };

        // dynamicSize returns the size of dynamically encoded data in bits.
        fn dynamicSize(
            self: *Self,
            lit_enc: *hc.LiteralEncoder, // literal encoder
            dist_enc: *hc.DistanceEncoder, // distance encoder
            extra_bits: u32,
        ) DynamicSize {
            var num_codegens = self.codegen_freq.len;
            while (num_codegens > 4 and self.codegen_freq[codegen_order[num_codegens - 1]] == 0) {
                num_codegens -= 1;
            }
            const header = 3 + 5 + 5 + 4 + (3 * num_codegens) +
                self.codegen_encoding.bitLength(self.codegen_freq[0..]) +
                self.codegen_freq[16] * 2 +
                self.codegen_freq[17] * 3 +
                self.codegen_freq[18] * 7;
            const size = header +
                lit_enc.bitLength(&self.literal_freq) +
                dist_enc.bitLength(&self.distance_freq) +
                extra_bits;

            return DynamicSize{
                .size = @as(u32, @intCast(size)),
                .num_codegens = @as(u32, @intCast(num_codegens)),
            };
        }

        // fixedSize returns the size of dynamically encoded data in bits.
        fn fixedSize(self: *Self, extra_bits: u32) u32 {
            return 3 +
                self.fixed_literal_encoding.bitLength(&self.literal_freq) +
                self.fixed_distance_encoding.bitLength(&self.distance_freq) +
                extra_bits;
        }

        const StoredSize = struct {
            size: u32,
            storable: bool,
        };

        // storedSizeFits calculates the stored size, including header.
        // The function returns the size in bits and whether the block
        // fits inside a single block.
        fn storedSizeFits(in: ?[]const u8) StoredSize {
            if (in == null) {
                return .{ .size = 0, .storable = false };
            }
            if (in.?.len <= consts.max_store_block_size) {
                return .{ .size = @as(u32, @intCast((in.?.len + 5) * 8)), .storable = true };
            }
            return .{ .size = 0, .storable = false };
        }

        // Write the header of a dynamic Huffman block to the output stream.
        //
        //  num_literals: The number of literals specified in codegen
        //  num_distances: The number of distances specified in codegen
        //  num_codegens: The number of codegens used in codegen
        //  eof: Is it the end-of-file? (end of stream)
        fn dynamicHeader(
            self: *Self,
            num_literals: u32,
            num_distances: u32,
            num_codegens: u32,
            eof: bool,
        ) Error!void {
            const first_bits: u32 = if (eof) 5 else 4;
            try self.bit_writer.writeBits(first_bits, 3);
            try self.bit_writer.writeBits(num_literals - 257, 5);
            try self.bit_writer.writeBits(num_distances - 1, 5);
            try self.bit_writer.writeBits(num_codegens - 4, 4);

            var i: u32 = 0;
            while (i < num_codegens) : (i += 1) {
                const value = self.codegen_encoding.codes[codegen_order[i]].len;
                try self.bit_writer.writeBits(value, 3);
            }

            i = 0;
            while (true) {
                const code_word: u32 = @as(u32, @intCast(self.codegen[i]));
                i += 1;
                if (code_word == end_code_mark) {
                    break;
                }
                try self.writeCode(self.codegen_encoding.codes[@as(u32, @intCast(code_word))]);

                switch (code_word) {
                    16 => {
                        try self.bit_writer.writeBits(self.codegen[i], 2);
                        i += 1;
                    },
                    17 => {
                        try self.bit_writer.writeBits(self.codegen[i], 3);
                        i += 1;
                    },
                    18 => {
                        try self.bit_writer.writeBits(self.codegen[i], 7);
                        i += 1;
                    },
                    else => {},
                }
            }
        }

        fn storedHeader(self: *Self, length: usize, eof: bool) Error!void {
            assert(length <= 65535);
            const flag: u32 = if (eof) 1 else 0;
            try self.bit_writer.writeBits(flag, 3);
            try self.flush();
            const l: u16 = @intCast(length);
            try self.bit_writer.writeBits(l, 16);
            try self.bit_writer.writeBits(~l, 16);
        }

        fn fixedHeader(self: *Self, eof: bool) Error!void {
            // Indicate that we are a fixed Huffman block
            var value: u32 = 2;
            if (eof) {
                value = 3;
            }
            try self.bit_writer.writeBits(value, 3);
        }

        // Write a block of tokens with the smallest encoding. Will choose block type.
        // The original input can be supplied, and if the huffman encoded data
        // is larger than the original bytes, the data will be written as a
        // stored block.
        // If the input is null, the tokens will always be Huffman encoded.
        pub fn write(self: *Self, tokens: []const Token, eof: bool, input: ?[]const u8) Error!void {
            const lit_and_dist = self.indexTokens(tokens);
            const num_literals = lit_and_dist.num_literals;
            const num_distances = lit_and_dist.num_distances;

            var extra_bits: u32 = 0;
            const ret = storedSizeFits(input);
            const stored_size = ret.size;
            const storable = ret.storable;

            if (storable) {
                // We only bother calculating the costs of the extra bits required by
                // the length of distance fields (which will be the same for both fixed
                // and dynamic encoding), if we need to compare those two encodings
                // against stored encoding.
                var length_code: u16 = Token.length_codes_start + 8;
                while (length_code < num_literals) : (length_code += 1) {
                    // First eight length codes have extra size = 0.
                    extra_bits += @as(u32, @intCast(self.literal_freq[length_code])) *
                        @as(u32, @intCast(Token.lengthExtraBits(length_code)));
                }
                var distance_code: u16 = 4;
                while (distance_code < num_distances) : (distance_code += 1) {
                    // First four distance codes have extra size = 0.
                    extra_bits += @as(u32, @intCast(self.distance_freq[distance_code])) *
                        @as(u32, @intCast(Token.distanceExtraBits(distance_code)));
                }
            }

            // Figure out smallest code.
            // Fixed Huffman baseline.
            var literal_encoding = &self.fixed_literal_encoding;
            var distance_encoding = &self.fixed_distance_encoding;
            var size = self.fixedSize(extra_bits);

            // Dynamic Huffman?
            var num_codegens: u32 = 0;

            // Generate codegen and codegenFrequencies, which indicates how to encode
            // the literal_encoding and the distance_encoding.
            self.generateCodegen(
                num_literals,
                num_distances,
                &self.literal_encoding,
                &self.distance_encoding,
            );
            self.codegen_encoding.generate(self.codegen_freq[0..], 7);
            const dynamic_size = self.dynamicSize(
                &self.literal_encoding,
                &self.distance_encoding,
                extra_bits,
            );
            const dyn_size = dynamic_size.size;
            num_codegens = dynamic_size.num_codegens;

            if (dyn_size < size) {
                size = dyn_size;
                literal_encoding = &self.literal_encoding;
                distance_encoding = &self.distance_encoding;
            }

            // Stored bytes?
            if (storable and stored_size < size) {
                try self.storedBlock(input.?, eof);
                return;
            }

            // Huffman.
            if (@intFromPtr(literal_encoding) == @intFromPtr(&self.fixed_literal_encoding)) {
                try self.fixedHeader(eof);
            } else {
                try self.dynamicHeader(num_literals, num_distances, num_codegens, eof);
            }

            // Write the tokens.
            try self.writeTokens(tokens, &literal_encoding.codes, &distance_encoding.codes);
        }

        pub fn storedBlock(self: *Self, input: []const u8, eof: bool) Error!void {
            try self.storedHeader(input.len, eof);
            try self.bit_writer.writeBytes(input);
        }

        // writeBlockDynamic encodes a block using a dynamic Huffman table.
        // This should be used if the symbols used have a disproportionate
        // histogram distribution.
        // If input is supplied and the compression savings are below 1/16th of the
        // input size the block is stored.
        fn dynamicBlock(
            self: *Self,
            tokens: []const Token,
            eof: bool,
            input: ?[]const u8,
        ) Error!void {
            const total_tokens = self.indexTokens(tokens);
            const num_literals = total_tokens.num_literals;
            const num_distances = total_tokens.num_distances;

            // Generate codegen and codegenFrequencies, which indicates how to encode
            // the literal_encoding and the distance_encoding.
            self.generateCodegen(
                num_literals,
                num_distances,
                &self.literal_encoding,
                &self.distance_encoding,
            );
            self.codegen_encoding.generate(self.codegen_freq[0..], 7);
            const dynamic_size = self.dynamicSize(&self.literal_encoding, &self.distance_encoding, 0);
            const size = dynamic_size.size;
            const num_codegens = dynamic_size.num_codegens;

            // Store bytes, if we don't get a reasonable improvement.

            const stored_size = storedSizeFits(input);
            const ssize = stored_size.size;
            const storable = stored_size.storable;
            if (storable and ssize < (size + (size >> 4))) {
                try self.storedBlock(input.?, eof);
                return;
            }

            // Write Huffman table.
            try self.dynamicHeader(num_literals, num_distances, num_codegens, eof);

            // Write the tokens.
            try self.writeTokens(tokens, &self.literal_encoding.codes, &self.distance_encoding.codes);
        }

        const TotalIndexedTokens = struct {
            num_literals: u32,
            num_distances: u32,
        };

        // Indexes a slice of tokens followed by an end_block_marker, and updates
        // literal_freq and distance_freq, and generates literal_encoding
        // and distance_encoding.
        // The number of literal and distance tokens is returned.
        fn indexTokens(self: *Self, tokens: []const Token) TotalIndexedTokens {
            var num_literals: u32 = 0;
            var num_distances: u32 = 0;

            for (self.literal_freq, 0..) |_, i| {
                self.literal_freq[i] = 0;
            }
            for (self.distance_freq, 0..) |_, i| {
                self.distance_freq[i] = 0;
            }

            for (tokens) |t| {
                if (t.kind == Token.Kind.literal) {
                    self.literal_freq[t.literal()] += 1;
                    continue;
                }
                self.literal_freq[t.lengthCode()] += 1;
                self.distance_freq[t.distanceCode()] += 1;
            }
            // add end_block_marker token at the end
            self.literal_freq[consts.end_block_marker] += 1;

            // get the number of literals
            num_literals = @as(u32, @intCast(self.literal_freq.len));
            while (self.literal_freq[num_literals - 1] == 0) {
                num_literals -= 1;
            }
            // get the number of distances
            num_distances = @as(u32, @intCast(self.distance_freq.len));
            while (num_distances > 0 and self.distance_freq[num_distances - 1] == 0) {
                num_distances -= 1;
            }
            if (num_distances == 0) {
                // We haven't found a single match. If we want to go with the dynamic encoding,
                // we should count at least one distance to be sure that the distance huffman tree could be encoded.
                self.distance_freq[0] = 1;
                num_distances = 1;
            }
            self.literal_encoding.generate(&self.literal_freq, 15);
            self.distance_encoding.generate(&self.distance_freq, 15);
            return TotalIndexedTokens{
                .num_literals = num_literals,
                .num_distances = num_distances,
            };
        }

        // Writes a slice of tokens to the output followed by and end_block_marker.
        // codes for literal and distance encoding must be supplied.
        fn writeTokens(
            self: *Self,
            tokens: []const Token,
            le_codes: []hc.HuffCode,
            oe_codes: []hc.HuffCode,
        ) Error!void {
            for (tokens) |t| {
                if (t.kind == Token.Kind.literal) {
                    try self.writeCode(le_codes[t.literal()]);
                    continue;
                }

                // Write the length
                const le = t.lengthEncoding();
                try self.writeCode(le_codes[le.code]);
                if (le.extra_bits > 0) {
                    try self.bit_writer.writeBits(le.extra_length, le.extra_bits);
                }

                // Write the distance
                const oe = t.distanceEncoding();
                try self.writeCode(oe_codes[oe.code]);
                if (oe.extra_bits > 0) {
                    try self.bit_writer.writeBits(oe.extra_distance, oe.extra_bits);
                }
            }
            // add end_block_marker at the end
            try self.writeCode(le_codes[consts.end_block_marker]);
        }

        // Encodes a block of bytes as either Huffman encoded literals or uncompressed bytes
        // if the results only gains very little from compression.
        pub fn huffmanBlock(self: *Self, input: []const u8, eof: bool) Error!void {
            // Add everything as literals
            histogram(input, &self.literal_freq);

            self.literal_freq[consts.end_block_marker] = 1;

            const num_literals = consts.end_block_marker + 1;
            self.distance_freq[0] = 1;
            const num_distances = 1;

            self.literal_encoding.generate(&self.literal_freq, 15);

            // Figure out smallest code.
            // Always use dynamic Huffman or Store
            var num_codegens: u32 = 0;

            // Generate codegen and codegenFrequencies, which indicates how to encode
            // the literal_encoding and the distance_encoding.
            self.generateCodegen(
                num_literals,
                num_distances,
                &self.literal_encoding,
                &self.huff_distance,
            );
            self.codegen_encoding.generate(self.codegen_freq[0..], 7);
            const dynamic_size = self.dynamicSize(&self.literal_encoding, &self.huff_distance, 0);
            const size = dynamic_size.size;
            num_codegens = dynamic_size.num_codegens;

            // Store bytes, if we don't get a reasonable improvement.
            const stored_size_ret = storedSizeFits(input);
            const ssize = stored_size_ret.size;
            const storable = stored_size_ret.storable;

            if (storable and ssize < (size + (size >> 4))) {
                try self.storedBlock(input, eof);
                return;
            }

            // Huffman.
            try self.dynamicHeader(num_literals, num_distances, num_codegens, eof);
            const encoding = self.literal_encoding.codes[0..257];

            for (input) |t| {
                const c = encoding[t];
                try self.bit_writer.writeBits(c.code, c.len);
            }
            try self.writeCode(encoding[consts.end_block_marker]);
        }

        // histogram accumulates a histogram of b in h.
        fn histogram(b: []const u8, h: *[286]u16) void {
            // Clear histogram
            for (h, 0..) |_, i| {
                h[i] = 0;
            }

            var lh = h.*[0..256];
            for (b) |t| {
                lh[t] += 1;
            }
        }
    };
}

// tests
const expect = std.testing.expect;
const fmt = std.fmt;
const testing = std.testing;
const ArrayList = std.ArrayList;

const TestCase = @import("testdata/block_writer.zig").TestCase;
const testCases = @import("testdata/block_writer.zig").testCases;

// tests if the writeBlock encoding has changed.
test "write" {
    inline for (0..testCases.len) |i| {
        try testBlock(testCases[i], .write_block);
    }
}

// tests if the writeBlockDynamic encoding has changed.
test "dynamicBlock" {
    inline for (0..testCases.len) |i| {
        try testBlock(testCases[i], .write_dyn_block);
    }
}

test "huffmanBlock" {
    inline for (0..testCases.len) |i| {
        try testBlock(testCases[i], .write_huffman_block);
    }
    try testBlock(.{
        .tokens = &[_]Token{},
        .input = "huffman-rand-max.input",
        .want = "huffman-rand-max.{s}.expect",
    }, .write_huffman_block);
}

const TestFn = enum {
    write_block,
    write_dyn_block, // write dynamic block
    write_huffman_block,

    fn to_s(self: TestFn) []const u8 {
        return switch (self) {
            .write_block => "wb",
            .write_dyn_block => "dyn",
            .write_huffman_block => "huff",
        };
    }

    fn write(
        comptime self: TestFn,
        bw: anytype,
        tok: []const Token,
        input: ?[]const u8,
        final: bool,
    ) !void {
        switch (self) {
            .write_block => try bw.write(tok, final, input),
            .write_dyn_block => try bw.dynamicBlock(tok, final, input),
            .write_huffman_block => try bw.huffmanBlock(input.?, final),
        }
        try bw.flush();
    }
};

// testBlock tests a block against its references
//
// size
//  64K [file-name].input                  - input non compressed file
// 8.1K [file-name].golden                 -
//   78 [file-name].dyn.expect             - output with writeBlockDynamic
//   78 [file-name].wb.expect              - output with writeBlock
// 8.1K [file-name].huff.expect            - output with writeBlockHuff
//   78 [file-name].dyn.expect-noinput     - output with writeBlockDynamic when input is null
//   78 [file-name].wb.expect-noinput      - output with writeBlock when input is null
//
//   wb   - writeBlock
//   dyn  - writeBlockDynamic
//   huff - writeBlockHuff
//
fn testBlock(comptime tc: TestCase, comptime tfn: TestFn) !void {
    if (tc.input.len != 0 and tc.want.len != 0) {
        const want_name = comptime fmt.comptimePrint(tc.want, .{tfn.to_s()});
        const input = @embedFile("testdata/block_writer/" ++ tc.input);
        const want = @embedFile("testdata/block_writer/" ++ want_name);
        try testWriteBlock(tfn, input, want, tc.tokens);
    }

    if (tfn == .write_huffman_block) {
        return;
    }

    const want_name_no_input = comptime fmt.comptimePrint(tc.want_no_input, .{tfn.to_s()});
    const want = @embedFile("testdata/block_writer/" ++ want_name_no_input);
    try testWriteBlock(tfn, null, want, tc.tokens);
}

// Uses writer function `tfn` to write `tokens`, tests that we got `want` as output.
fn testWriteBlock(comptime tfn: TestFn, input: ?[]const u8, want: []const u8, tokens: []const Token) !void {
    var buf = ArrayList(u8).init(testing.allocator);
    var bw = blockWriter(buf.writer());
    try tfn.write(&bw, tokens, input, false);
    var got = buf.items;
    try testing.expectEqualSlices(u8, want, got); // expect writeBlock to yield expected result
    try expect(got[0] & 0b0000_0001 == 0); // bfinal is not set
    //
    // Test if the writer produces the same output after reset.
    buf.deinit();
    buf = ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    bw.setWriter(buf.writer());

    try tfn.write(&bw, tokens, input, true);
    try bw.flush();
    got = buf.items;

    try expect(got[0] & 1 == 1); // bfinal is set
    buf.items[0] &= 0b1111_1110; // remove bfinal bit, so we can run test slices
    try testing.expectEqualSlices(u8, want, got); // expect writeBlock to yield expected result
}
//! 64K buffer of uncompressed data created in inflate (decompression). Has enough
//! history to support writing match<length, distance>; copying length of bytes
//! from the position distance backward from current.
//!
//! Reads can return less than available bytes if they are spread across
//! different circles. So reads should repeat until get required number of bytes
//! or until returned slice is zero length.
//!
//! Note on deflate limits:
//!  * non-compressible block is limited to 65,535 bytes.
//!  * backward pointer is limited in distance to 32K bytes and in length to 258 bytes.
//!
//! Whole non-compressed block can be written without overlap. We always have
//! history of up to 64K, more then 32K needed.
//!
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const consts = @import("consts.zig").match;

const mask = 0xffff; // 64K - 1
const buffer_len = mask + 1; // 64K buffer

const Self = @This();

buffer: [buffer_len]u8 = undefined,
wp: usize = 0, // write position
rp: usize = 0, // read position

fn writeAll(self: *Self, buf: []const u8) void {
    for (buf) |c| self.write(c);
}

/// Write literal.
pub fn write(self: *Self, b: u8) void {
    assert(self.wp - self.rp < mask);
    self.buffer[self.wp & mask] = b;
    self.wp += 1;
}

/// Write match (back-reference to the same data slice) starting at `distance`
/// back from current write position, and `length` of bytes.
pub fn writeMatch(self: *Self, length: u16, distance: u16) !void {
    if (self.wp < distance or
        length < consts.base_length or length > consts.max_length or
        distance < consts.min_distance or distance > consts.max_distance)
    {
        return error.InvalidMatch;
    }
    assert(self.wp - self.rp < mask);

    var from: usize = self.wp - distance & mask;
    const from_end: usize = from + length;
    var to: usize = self.wp & mask;
    const to_end: usize = to + length;

    self.wp += length;

    // Fast path using memcpy
    if (from_end < buffer_len and to_end < buffer_len) // start and end at the same circle
    {
        var cur_len = distance;
        var remaining_len = length;
        while (cur_len < remaining_len) {
            @memcpy(self.buffer[to..][0..cur_len], self.buffer[from..][0..cur_len]);
            to += cur_len;
            remaining_len -= cur_len;
            cur_len = cur_len * 2;
        }
        @memcpy(self.buffer[to..][0..remaining_len], self.buffer[from..][0..remaining_len]);
        return;
    }

    // Slow byte by byte
    while (to < to_end) {
        self.buffer[to & mask] = self.buffer[from & mask];
        to += 1;
        from += 1;
    }
}

/// Returns writable part of the internal buffer of size `n` at most. Advances
/// write pointer, assumes that returned buffer will be filled with data.
pub fn getWritable(self: *Self, n: usize) []u8 {
    const wp = self.wp & mask;
    const len = @min(n, buffer_len - wp);
    self.wp += len;
    return self.buffer[wp .. wp + len];
}

/// Read available data. Can return part of the available data if it is
/// spread across two circles. So read until this returns zero length.
pub fn read(self: *Self) []const u8 {
    return self.readAtMost(buffer_len);
}

/// Read part of available data. Can return less than max even if there are
/// more than max decoded data.
pub fn readAtMost(self: *Self, limit: usize) []const u8 {
    const rb = self.readBlock(if (limit == 0) buffer_len else limit);
    defer self.rp += rb.len;
    return self.buffer[rb.head..rb.tail];
}

const ReadBlock = struct {
    head: usize,
    tail: usize,
    len: usize,
};

/// Returns position of continuous read block data.
fn readBlock(self: *Self, max: usize) ReadBlock {
    const r = self.rp & mask;
    const w = self.wp & mask;
    const n = @min(
        max,
        if (w >= r) w - r else buffer_len - r,
    );
    return .{
        .head = r,
        .tail = r + n,
        .len = n,
    };
}

/// Number of free bytes for write.
pub fn free(self: *Self) usize {
    return buffer_len - (self.wp - self.rp);
}

/// Full if largest match can't fit. 258 is largest match length. That much
/// bytes can be produced in single decode step.
pub fn full(self: *Self) bool {
    return self.free() < 258 + 1;
}

// example from: https://youtu.be/SJPvNi4HrWQ?t=3558
test writeMatch {
    var cb: Self = .{};

    cb.writeAll("a salad; ");
    try cb.writeMatch(5, 9);
    try cb.writeMatch(3, 3);

    try testing.expectEqualStrings("a salad; a salsal", cb.read());
}

test "writeMatch overlap" {
    var cb: Self = .{};

    cb.writeAll("a b c ");
    try cb.writeMatch(8, 4);
    cb.write('d');

    try testing.expectEqualStrings("a b c b c b c d", cb.read());
}

test readAtMost {
    var cb: Self = .{};

    cb.writeAll("0123456789");
    try cb.writeMatch(50, 10);

    try testing.expectEqualStrings("0123456789" ** 6, cb.buffer[cb.rp..cb.wp]);
    for (0..6) |i| {
        try testing.expectEqual(i * 10, cb.rp);
        try testing.expectEqualStrings("0123456789", cb.readAtMost(10));
    }
    try testing.expectEqualStrings("", cb.readAtMost(10));
    try testing.expectEqualStrings("", cb.read());
}

test Self {
    var cb: Self = .{};

    const data = "0123456789abcdef" ** (1024 / 16);
    cb.writeAll(data);
    try testing.expectEqual(@as(usize, 0), cb.rp);
    try testing.expectEqual(@as(usize, 1024), cb.wp);
    try testing.expectEqual(@as(usize, 1024 * 63), cb.free());

    for (0..62 * 4) |_|
        try cb.writeMatch(256, 1024); // write 62K

    try testing.expectEqual(@as(usize, 0), cb.rp);
    try testing.expectEqual(@as(usize, 63 * 1024), cb.wp);
    try testing.expectEqual(@as(usize, 1024), cb.free());

    cb.writeAll(data[0..200]);
    _ = cb.readAtMost(1024); // make some space
    cb.writeAll(data); // overflows write position
    try testing.expectEqual(@as(usize, 200 + 65536), cb.wp);
    try testing.expectEqual(@as(usize, 1024), cb.rp);
    try testing.expectEqual(@as(usize, 1024 - 200), cb.free());

    const rb = cb.readBlock(Self.buffer_len);
    try testing.expectEqual(@as(usize, 65536 - 1024), rb.len);
    try testing.expectEqual(@as(usize, 1024), rb.head);
    try testing.expectEqual(@as(usize, 65536), rb.tail);

    try testing.expectEqual(@as(usize, 65536 - 1024), cb.read().len); // read to the end of the buffer
    try testing.expectEqual(@as(usize, 200 + 65536), cb.wp);
    try testing.expectEqual(@as(usize, 65536), cb.rp);
    try testing.expectEqual(@as(usize, 65536 - 200), cb.free());

    try testing.expectEqual(@as(usize, 200), cb.read().len); // read the rest
}

test "write overlap" {
    var cb: Self = .{};
    cb.wp = cb.buffer.len - 15;
    cb.rp = cb.wp;

    cb.writeAll("0123456789");
    cb.writeAll("abcdefghij");

    try testing.expectEqual(cb.buffer.len + 5, cb.wp);
    try testing.expectEqual(cb.buffer.len - 15, cb.rp);

    try testing.expectEqualStrings("0123456789abcde", cb.read());
    try testing.expectEqualStrings("fghij", cb.read());

    try testing.expect(cb.wp == cb.rp);
}

test "writeMatch/read overlap" {
    var cb: Self = .{};
    cb.wp = cb.buffer.len - 15;
    cb.rp = cb.wp;

    cb.writeAll("0123456789");
    try cb.writeMatch(15, 5);

    try testing.expectEqualStrings("012345678956789", cb.read());
    try testing.expectEqualStrings("5678956789", cb.read());

    try cb.writeMatch(20, 25);
    try testing.expectEqualStrings("01234567895678956789", cb.read());
}
pub const deflate = struct {
    // Number of tokens to accumulate in deflate before starting block encoding.
    //
    // In zlib this depends on memlevel: 6 + memlevel, where default memlevel is
    // 8 and max 9 that gives 14 or 15 bits.
    pub const tokens = 1 << 15;
};

pub const match = struct {
    pub const base_length = 3; // smallest match length per the RFC section 3.2.5
    pub const min_length = 4; // min length used in this algorithm
    pub const max_length = 258;

    pub const min_distance = 1;
    pub const max_distance = 32768;
};

pub const history = struct {
    pub const len = match.max_distance;
};

pub const lookup = struct {
    pub const bits = 15;
    pub const len = 1 << bits;
    pub const shift = 32 - bits;
};

pub const huffman = struct {
    // The odd order in which the codegen code sizes are written.
    pub const codegen_order = [_]u32{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    // The number of codegen codes.
    pub const codegen_code_count = 19;

    // The largest distance code.
    pub const distance_code_count = 30;

    // Maximum number of literals.
    pub const max_num_lit = 286;

    // Max number of frequencies used for a Huffman Code
    // Possible lengths are codegen_code_count (19), distance_code_count (30) and max_num_lit (286).
    // The largest of these is max_num_lit.
    pub const max_num_frequencies = max_num_lit;

    // Biggest block size for uncompressed block.
    pub const max_store_block_size = 65535;
    // The special code used to mark the end of a block.
    pub const end_block_marker = 256;
};
//! Container of the deflate bit stream body. Container adds header before
//! deflate bit stream and footer after. It can bi gzip, zlib or raw (no header,
//! no footer, raw bit stream).
//!
//! Zlib format is defined in rfc 1950. Header has 2 bytes and footer 4 bytes
//! addler 32 checksum.
//!
//! Gzip format is defined in rfc 1952. Header has 10+ bytes and footer 4 bytes
//! crc32 checksum and 4 bytes of uncompressed data length.
//!
//!
//! rfc 1950: https://datatracker.ietf.org/doc/html/rfc1950#page-4
//! rfc 1952: https://datatracker.ietf.org/doc/html/rfc1952#page-5
//!

const std = @import("std");

pub const Container = enum {
    raw, // no header or footer
    gzip, // gzip header and footer
    zlib, // zlib header and footer

    pub fn size(w: Container) usize {
        return headerSize(w) + footerSize(w);
    }

    pub fn headerSize(w: Container) usize {
        return switch (w) {
            .gzip => 10,
            .zlib => 2,
            .raw => 0,
        };
    }

    pub fn footerSize(w: Container) usize {
        return switch (w) {
            .gzip => 8,
            .zlib => 4,
            .raw => 0,
        };
    }

    pub const list = [_]Container{ .raw, .gzip, .zlib };

    pub const Error = error{
        BadGzipHeader,
        BadZlibHeader,
        WrongGzipChecksum,
        WrongGzipSize,
        WrongZlibChecksum,
    };

    pub fn writeHeader(comptime wrap: Container, writer: anytype) !void {
        switch (wrap) {
            .gzip => {
                // GZIP 10 byte header (https://datatracker.ietf.org/doc/html/rfc1952#page-5):
                //  - ID1 (IDentification 1), always 0x1f
                //  - ID2 (IDentification 2), always 0x8b
                //  - CM (Compression Method), always 8 = deflate
                //  - FLG (Flags), all set to 0
                //  - 4 bytes, MTIME (Modification time), not used, all set to zero
                //  - XFL (eXtra FLags), all set to zero
                //  - OS (Operating System), 03 = Unix
                const gzipHeader = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };
                try writer.writeAll(&gzipHeader);
            },
            .zlib => {
                // ZLIB has a two-byte header (https://datatracker.ietf.org/doc/html/rfc1950#page-4):
                // 1st byte:
                //  - First four bits is the CINFO (compression info), which is 7 for the default deflate window size.
                //  - The next four bits is the CM (compression method), which is 8 for deflate.
                // 2nd byte:
                //  - Two bits is the FLEVEL (compression level). Values are: 0=fastest, 1=fast, 2=default, 3=best.
                //  - The next bit, FDICT, is set if a dictionary is given.
                //  - The final five FCHECK bits form a mod-31 checksum.
                //
                // CINFO = 7, CM = 8, FLEVEL = 0b10, FDICT = 0, FCHECK = 0b11100
                const zlibHeader = [_]u8{ 0x78, 0b10_0_11100 };
                try writer.writeAll(&zlibHeader);
            },
            .raw => {},
        }
    }

    pub fn writeFooter(comptime wrap: Container, hasher: *Hasher(wrap), writer: anytype) !void {
        var bits: [4]u8 = undefined;
        switch (wrap) {
            .gzip => {
                // GZIP 8 bytes footer
                //  - 4 bytes, CRC32 (CRC-32)
                //  - 4 bytes, ISIZE (Input SIZE) - size of the original (uncompressed) input data modulo 2^32
                std.mem.writeInt(u32, &bits, hasher.chksum(), .little);
                try writer.writeAll(&bits);

                std.mem.writeInt(u32, &bits, hasher.bytesRead(), .little);
                try writer.writeAll(&bits);
            },
            .zlib => {
                // ZLIB (RFC 1950) is big-endian, unlike GZIP (RFC 1952).
                // 4 bytes of ADLER32 (Adler-32 checksum)
                // Checksum value of the uncompressed data (excluding any
                // dictionary data) computed according to Adler-32
                // algorithm.
                std.mem.writeInt(u32, &bits, hasher.chksum(), .big);
                try writer.writeAll(&bits);
            },
            .raw => {},
        }
    }

    pub fn parseHeader(comptime wrap: Container, reader: anytype) !void {
        switch (wrap) {
            .gzip => try parseGzipHeader(reader),
            .zlib => try parseZlibHeader(reader),
            .raw => {},
        }
    }

    fn parseGzipHeader(reader: anytype) !void {
        const magic1 = try reader.read(u8);
        const magic2 = try reader.read(u8);
        const method = try reader.read(u8);
        const flags = try reader.read(u8);
        try reader.skipBytes(6); // mtime(4), xflags, os
        if (magic1 != 0x1f or magic2 != 0x8b or method != 0x08)
            return error.BadGzipHeader;
        // Flags description: https://www.rfc-editor.org/rfc/rfc1952.html#page-5
        if (flags != 0) {
            if (flags & 0b0000_0100 != 0) { // FEXTRA
                const extra_len = try reader.read(u16);
                try reader.skipBytes(extra_len);
            }
            if (flags & 0b0000_1000 != 0) { // FNAME
                try reader.skipStringZ();
            }
            if (flags & 0b0001_0000 != 0) { // FCOMMENT
                try reader.skipStringZ();
            }
            if (flags & 0b0000_0010 != 0) { // FHCRC
                try reader.skipBytes(2);
            }
        }
    }

    fn parseZlibHeader(reader: anytype) !void {
        const cm = try reader.read(u4);
        const cinfo = try reader.read(u4);
        _ = try reader.read(u8);
        if (cm != 8 or cinfo > 7) {
            return error.BadZlibHeader;
        }
    }

    pub fn parseFooter(comptime wrap: Container, hasher: *Hasher(wrap), reader: anytype) !void {
        switch (wrap) {
            .gzip => {
                try reader.fill(0);
                if (try reader.read(u32) != hasher.chksum()) return error.WrongGzipChecksum;
                if (try reader.read(u32) != hasher.bytesRead()) return error.WrongGzipSize;
            },
            .zlib => {
                const chksum: u32 = @byteSwap(hasher.chksum());
                if (try reader.read(u32) != chksum) return error.WrongZlibChecksum;
            },
            .raw => {},
        }
    }

    pub fn Hasher(comptime wrap: Container) type {
        const HasherType = switch (wrap) {
            .gzip => std.hash.Crc32,
            .zlib => std.hash.Adler32,
            .raw => struct {
                pub fn init() @This() {
                    return .{};
                }
            },
        };

        return struct {
            hasher: HasherType = HasherType.init(),
            bytes: usize = 0,

            const Self = @This();

            pub fn update(self: *Self, buf: []const u8) void {
                switch (wrap) {
                    .raw => {},
                    else => {
                        self.hasher.update(buf);
                        self.bytes += buf.len;
                    },
                }
            }

            pub fn chksum(self: *Self) u32 {
                switch (wrap) {
                    .raw => return 0,
                    else => return self.hasher.final(),
                }
            }

            pub fn bytesRead(self: *Self) u32 {
                return @truncate(self.bytes);
            }
        };
    }
};
const std = @import("std");
const io = std.io;
const assert = std.debug.assert;
const testing = std.testing;
const expect = testing.expect;
const print = std.debug.print;

const Token = @import("Token.zig");
const consts = @import("consts.zig");
const BlockWriter = @import("block_writer.zig").BlockWriter;
const Container = @import("container.zig").Container;
const SlidingWindow = @import("SlidingWindow.zig");
const Lookup = @import("Lookup.zig");

pub const Options = struct {
    level: Level = .default,
};

/// Trades between speed and compression size.
/// Starts with level 4: in [zlib](https://github.com/madler/zlib/blob/abd3d1a28930f89375d4b41408b39f6c1be157b2/deflate.c#L115C1-L117C43)
/// levels 1-3 are using different algorithm to perform faster but with less
/// compression. That is not implemented here.
pub const Level = enum(u4) {
    // zig fmt: off
    fast = 0xb,         level_4 = 4,
                        level_5 = 5,
    default = 0xc,      level_6 = 6,
                        level_7 = 7,
                        level_8 = 8,
    best = 0xd,         level_9 = 9,
    // zig fmt: on
};

/// Algorithm knobs for each level.
const LevelArgs = struct {
    good: u16, // Do less lookups if we already have match of this length.
    nice: u16, // Stop looking for better match if we found match with at least this length.
    lazy: u16, // Don't do lazy match find if got match with at least this length.
    chain: u16, // How many lookups for previous match to perform.

    pub fn get(level: Level) LevelArgs {
        // zig fmt: off
        return switch (level) {
            .fast,    .level_4 => .{ .good =  4, .lazy =   4, .nice =  16, .chain =   16 },
                      .level_5 => .{ .good =  8, .lazy =  16, .nice =  32, .chain =   32 },
            .default, .level_6 => .{ .good =  8, .lazy =  16, .nice = 128, .chain =  128 },
                      .level_7 => .{ .good =  8, .lazy =  32, .nice = 128, .chain =  256 },
                      .level_8 => .{ .good = 32, .lazy = 128, .nice = 258, .chain = 1024 },
            .best,    .level_9 => .{ .good = 32, .lazy = 258, .nice = 258, .chain = 4096 },
        };
        // zig fmt: on
    }
};

/// Compress plain data from reader into compressed stream written to writer.
pub fn compress(comptime container: Container, reader: anytype, writer: anytype, options: Options) !void {
    var c = try compressor(container, writer, options);
    try c.compress(reader);
    try c.finish();
}

/// Create compressor for writer type.
pub fn compressor(comptime container: Container, writer: anytype, options: Options) !Compressor(
    container,
    @TypeOf(writer),
) {
    return try Compressor(container, @TypeOf(writer)).init(writer, options);
}

/// Compressor type.
pub fn Compressor(comptime container: Container, comptime WriterType: type) type {
    const TokenWriterType = BlockWriter(WriterType);
    return Deflate(container, WriterType, TokenWriterType);
}

/// Default compression algorithm. Has two steps: tokenization and token
/// encoding.
///
/// Tokenization takes uncompressed input stream and produces list of tokens.
/// Each token can be literal (byte of data) or match (backrefernce to previous
/// data with length and distance). Tokenization accumulators 32K tokens, when
/// full or `flush` is called tokens are passed to the `block_writer`. Level
/// defines how hard (how slow) it tries to find match.
///
/// Block writer will decide which type of deflate block to write (stored, fixed,
/// dynamic) and encode tokens to the output byte stream. Client has to call
/// `finish` to write block with the final bit set.
///
/// Container defines type of header and footer which can be gzip, zlib or raw.
/// They all share same deflate body. Raw has no header or footer just deflate
/// body.
///
/// Compression algorithm explained in rfc-1951 (slightly edited for this case):
///
///   The compressor uses a chained hash table `lookup` to find duplicated
///   strings, using a hash function that operates on 4-byte sequences. At any
///   given point during compression, let XYZW be the next 4 input bytes
///   (lookahead) to be examined (not necessarily all different, of course).
///   First, the compressor examines the hash chain for XYZW. If the chain is
///   empty, the compressor simply writes out X as a literal byte and advances
///   one byte in the input. If the hash chain is not empty, indicating that the
///   sequence XYZW (or, if we are unlucky, some other 4 bytes with the same
///   hash function value) has occurred recently, the compressor compares all
///   strings on the XYZW hash chain with the actual input data sequence
///   starting at the current point, and selects the longest match.
///
///   To improve overall compression, the compressor defers the selection of
///   matches ("lazy matching"): after a match of length N has been found, the
///   compressor searches for a longer match starting at the next input byte. If
///   it finds a longer match, it truncates the previous match to a length of
///   one (thus producing a single literal byte) and then emits the longer
///   match. Otherwise, it emits the original match, and, as described above,
///   advances N bytes before continuing.
///
///
/// Allocates statically ~400K (192K lookup, 128K tokens, 64K window).
///
/// Deflate function accepts BlockWriterType so we can change that in test to test
/// just tokenization part.
///
fn Deflate(comptime container: Container, comptime WriterType: type, comptime BlockWriterType: type) type {
    return struct {
        lookup: Lookup = .{},
        win: SlidingWindow = .{},
        tokens: Tokens = .{},
        wrt: WriterType,
        block_writer: BlockWriterType,
        level: LevelArgs,
        hasher: container.Hasher() = .{},

        // Match and literal at the previous position.
        // Used for lazy match finding in processWindow.
        prev_match: ?Token = null,
        prev_literal: ?u8 = null,

        const Self = @This();

        pub fn init(wrt: WriterType, options: Options) !Self {
            const self = Self{
                .wrt = wrt,
                .block_writer = BlockWriterType.init(wrt),
                .level = LevelArgs.get(options.level),
            };
            try container.writeHeader(self.wrt);
            return self;
        }

        const FlushOption = enum { none, flush, final };

        // Process data in window and create tokens. If token buffer is full
        // flush tokens to the token writer. In the case of `flush` or `final`
        // option it will process all data from the window. In the `none` case
        // it will preserve some data for the next match.
        fn tokenize(self: *Self, flush_opt: FlushOption) !void {
            // flush - process all data from window
            const should_flush = (flush_opt != .none);

            // While there is data in active lookahead buffer.
            while (self.win.activeLookahead(should_flush)) |lh| {
                var step: u16 = 1; // 1 in the case of literal, match length otherwise
                const pos: u16 = self.win.pos();
                const literal = lh[0]; // literal at current position
                const min_len: u16 = if (self.prev_match) |m| m.length() else 0;

                // Try to find match at least min_len long.
                if (self.findMatch(pos, lh, min_len)) |match| {
                    // Found better match than previous.
                    try self.addPrevLiteral();

                    // Is found match length good enough?
                    if (match.length() >= self.level.lazy) {
                        // Don't try to lazy find better match, use this.
                        step = try self.addMatch(match);
                    } else {
                        // Store this match.
                        self.prev_literal = literal;
                        self.prev_match = match;
                    }
                } else {
                    // There is no better match at current pos then it was previous.
                    // Write previous match or literal.
                    if (self.prev_match) |m| {
                        // Write match from previous position.
                        step = try self.addMatch(m) - 1; // we already advanced 1 from previous position
                    } else {
                        // No match at previous position.
                        // Write previous literal if any, and remember this literal.
                        try self.addPrevLiteral();
                        self.prev_literal = literal;
                    }
                }
                // Advance window and add hashes.
                self.windowAdvance(step, lh, pos);
            }

            if (should_flush) {
                // In the case of flushing, last few lookahead buffers were smaller then min match len.
                // So only last literal can be unwritten.
                assert(self.prev_match == null);
                try self.addPrevLiteral();
                self.prev_literal = null;

                try self.flushTokens(flush_opt);
            }
        }

        fn windowAdvance(self: *Self, step: u16, lh: []const u8, pos: u16) void {
            // current position is already added in findMatch
            self.lookup.bulkAdd(lh[1..], step - 1, pos + 1);
            self.win.advance(step);
        }

        // Add previous literal (if any) to the tokens list.
        fn addPrevLiteral(self: *Self) !void {
            if (self.prev_literal) |l| try self.addToken(Token.initLiteral(l));
        }

        // Add match to the tokens list, reset prev pointers.
        // Returns length of the added match.
        fn addMatch(self: *Self, m: Token) !u16 {
            try self.addToken(m);
            self.prev_literal = null;
            self.prev_match = null;
            return m.length();
        }

        fn addToken(self: *Self, token: Token) !void {
            self.tokens.add(token);
            if (self.tokens.full()) try self.flushTokens(.none);
        }

        // Finds largest match in the history window with the data at current pos.
        fn findMatch(self: *Self, pos: u16, lh: []const u8, min_len: u16) ?Token {
            var len: u16 = min_len;
            // Previous location with the same hash (same 4 bytes).
            var prev_pos = self.lookup.add(lh, pos);
            // Last found match.
            var match: ?Token = null;

            // How much back-references to try, performance knob.
            var chain: usize = self.level.chain;
            if (len >= self.level.good) {
                // If we've got a match that's good enough, only look in 1/4 the chain.
                chain >>= 2;
            }

            // Hot path loop!
            while (prev_pos > 0 and chain > 0) : (chain -= 1) {
                const distance = pos - prev_pos;
                if (distance > consts.match.max_distance)
                    break;

                const new_len = self.win.match(prev_pos, pos, len);
                if (new_len > len) {
                    match = Token.initMatch(@intCast(distance), new_len);
                    if (new_len >= self.level.nice) {
                        // The match is good enough that we don't try to find a better one.
                        return match;
                    }
                    len = new_len;
                }
                prev_pos = self.lookup.prev(prev_pos);
            }

            return match;
        }

        fn flushTokens(self: *Self, flush_opt: FlushOption) !void {
            // Pass tokens to the token writer
            try self.block_writer.write(self.tokens.tokens(), flush_opt == .final, self.win.tokensBuffer());
            // Stored block ensures byte alignment.
            // It has 3 bits (final, block_type) and then padding until byte boundary.
            // After that everything is aligned to the boundary in the stored block.
            // Empty stored block is Ob000 + (0-7) bits of padding + 0x00 0x00 0xFF 0xFF.
            // Last 4 bytes are byte aligned.
            if (flush_opt == .flush) {
                try self.block_writer.storedBlock("", false);
            }
            if (flush_opt != .none) {
                // Safe to call only when byte aligned or it is OK to add
                // padding bits (on last byte of the final block).
                try self.block_writer.flush();
            }
            // Reset internal tokens store.
            self.tokens.reset();
            // Notify win that tokens are flushed.
            self.win.flush();
        }

        // Slide win and if needed lookup tables.
        fn slide(self: *Self) void {
            const n = self.win.slide();
            self.lookup.slide(n);
        }

        /// Compresses as much data as possible, stops when the reader becomes
        /// empty. It will introduce some output latency (reading input without
        /// producing all output) because some data are still in internal
        /// buffers.
        ///
        /// It is up to the caller to call flush (if needed) or finish (required)
        /// when is need to output any pending data or complete stream.
        ///
        pub fn compress(self: *Self, reader: anytype) !void {
            while (true) {
                // Fill window from reader
                const buf = self.win.writable();
                if (buf.len == 0) {
                    try self.tokenize(.none);
                    self.slide();
                    continue;
                }
                const n = try reader.readAll(buf);
                self.hasher.update(buf[0..n]);
                self.win.written(n);
                // Process window
                try self.tokenize(.none);
                // Exit when no more data in reader
                if (n < buf.len) break;
            }
        }

        /// Flushes internal buffers to the output writer. Outputs empty stored
        /// block to sync bit stream to the byte boundary, so that the
        /// decompressor can get all input data available so far.
        ///
        /// It is useful mainly in compressed network protocols, to ensure that
        /// deflate bit stream can be used as byte stream. May degrade
        /// compression so it should be used only when necessary.
        ///
        /// Completes the current deflate block and follows it with an empty
        /// stored block that is three zero bits plus filler bits to the next
        /// byte, followed by four bytes (00 00 ff ff).
        ///
        pub fn flush(self: *Self) !void {
            try self.tokenize(.flush);
        }

        /// Completes deflate bit stream by writing any pending data as deflate
        /// final deflate block. HAS to be called once all data are written to
        /// the compressor as a signal that next block has to have final bit
        /// set.
        ///
        pub fn finish(self: *Self) !void {
            try self.tokenize(.final);
            try container.writeFooter(&self.hasher, self.wrt);
        }

        /// Use another writer while preserving history. Most probably flush
        /// should be called on old writer before setting new.
        pub fn setWriter(self: *Self, new_writer: WriterType) void {
            self.block_writer.setWriter(new_writer);
            self.wrt = new_writer;
        }

        // Writer interface

        pub const Writer = io.Writer(*Self, Error, write);
        pub const Error = BlockWriterType.Error;

        /// Write `input` of uncompressed data.
        /// See compress.
        pub fn write(self: *Self, input: []const u8) !usize {
            var fbs = io.fixedBufferStream(input);
            try self.compress(fbs.reader());
            return input.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

// Tokens store
const Tokens = struct {
    list: [consts.deflate.tokens]Token = undefined,
    pos: usize = 0,

    fn add(self: *Tokens, t: Token) void {
        self.list[self.pos] = t;
        self.pos += 1;
    }

    fn full(self: *Tokens) bool {
        return self.pos == self.list.len;
    }

    fn reset(self: *Tokens) void {
        self.pos = 0;
    }

    fn tokens(self: *Tokens) []const Token {
        return self.list[0..self.pos];
    }
};

/// Creates huffman only deflate blocks. Disables Lempel-Ziv match searching and
/// only performs Huffman entropy encoding. Results in faster compression, much
/// less memory requirements during compression but bigger compressed sizes.
pub const huffman = struct {
    pub fn compress(comptime container: Container, reader: anytype, writer: anytype) !void {
        var c = try huffman.compressor(container, writer);
        try c.compress(reader);
        try c.finish();
    }

    pub fn Compressor(comptime container: Container, comptime WriterType: type) type {
        return SimpleCompressor(.huffman, container, WriterType);
    }

    pub fn compressor(comptime container: Container, writer: anytype) !huffman.Compressor(container, @TypeOf(writer)) {
        return try huffman.Compressor(container, @TypeOf(writer)).init(writer);
    }
};

/// Creates store blocks only. Data are not compressed only packed into deflate
/// store blocks. That adds 9 bytes of header for each block. Max stored block
/// size is 64K. Block is emitted when flush is called on on finish.
pub const store = struct {
    pub fn compress(comptime container: Container, reader: anytype, writer: anytype) !void {
        var c = try store.compressor(container, writer);
        try c.compress(reader);
        try c.finish();
    }

    pub fn Compressor(comptime container: Container, comptime WriterType: type) type {
        return SimpleCompressor(.store, container, WriterType);
    }

    pub fn compressor(comptime container: Container, writer: anytype) !store.Compressor(container, @TypeOf(writer)) {
        return try store.Compressor(container, @TypeOf(writer)).init(writer);
    }
};

const SimpleCompressorKind = enum {
    huffman,
    store,
};

fn simpleCompressor(
    comptime kind: SimpleCompressorKind,
    comptime container: Container,
    writer: anytype,
) !SimpleCompressor(kind, container, @TypeOf(writer)) {
    return try SimpleCompressor(kind, container, @TypeOf(writer)).init(writer);
}

fn SimpleCompressor(
    comptime kind: SimpleCompressorKind,
    comptime container: Container,
    comptime WriterType: type,
) type {
    const BlockWriterType = BlockWriter(WriterType);
    return struct {
        buffer: [65535]u8 = undefined, // because store blocks are limited to 65535 bytes
        wp: usize = 0,

        wrt: WriterType,
        block_writer: BlockWriterType,
        hasher: container.Hasher() = .{},

        const Self = @This();

        pub fn init(wrt: WriterType) !Self {
            const self = Self{
                .wrt = wrt,
                .block_writer = BlockWriterType.init(wrt),
            };
            try container.writeHeader(self.wrt);
            return self;
        }

        pub fn flush(self: *Self) !void {
            try self.flushBuffer(false);
            try self.block_writer.storedBlock("", false);
            try self.block_writer.flush();
        }

        pub fn finish(self: *Self) !void {
            try self.flushBuffer(true);
            try self.block_writer.flush();
            try container.writeFooter(&self.hasher, self.wrt);
        }

        fn flushBuffer(self: *Self, final: bool) !void {
            const buf = self.buffer[0..self.wp];
            switch (kind) {
                .huffman => try self.block_writer.huffmanBlock(buf, final),
                .store => try self.block_writer.storedBlock(buf, final),
            }
            self.wp = 0;
        }

        // Writes all data from the input reader of uncompressed data.
        // It is up to the caller to call flush or finish if there is need to
        // output compressed blocks.
        pub fn compress(self: *Self, reader: anytype) !void {
            while (true) {
                // read from rdr into buffer
                const buf = self.buffer[self.wp..];
                if (buf.len == 0) {
                    try self.flushBuffer(false);
                    continue;
                }
                const n = try reader.readAll(buf);
                self.hasher.update(buf[0..n]);
                self.wp += n;
                if (n < buf.len) break; // no more data in reader
            }
        }

        // Writer interface

        pub const Writer = io.Writer(*Self, Error, write);
        pub const Error = BlockWriterType.Error;

        // Write `input` of uncompressed data.
        pub fn write(self: *Self, input: []const u8) !usize {
            var fbs = io.fixedBufferStream(input);
            try self.compress(fbs.reader());
            return input.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

const builtin = @import("builtin");

test "tokenization" {
    const L = Token.initLiteral;
    const M = Token.initMatch;

    const cases = [_]struct {
        data: []const u8,
        tokens: []const Token,
    }{
        .{
            .data = "Blah blah blah blah blah!",
            .tokens = &[_]Token{ L('B'), L('l'), L('a'), L('h'), L(' '), L('b'), M(5, 18), L('!') },
        },
        .{
            .data = "ABCDEABCD ABCDEABCD",
            .tokens = &[_]Token{
                L('A'), L('B'),   L('C'), L('D'), L('E'), L('A'), L('B'), L('C'), L('D'), L(' '),
                L('A'), M(10, 8),
            },
        },
    };

    for (cases) |c| {
        inline for (Container.list) |container| { // for each wrapping

            var cw = io.countingWriter(io.null_writer);
            const cww = cw.writer();
            var df = try Deflate(container, @TypeOf(cww), TestTokenWriter).init(cww, .{});

            _ = try df.write(c.data);
            try df.flush();

            // df.token_writer.show();
            try expect(df.block_writer.pos == c.tokens.len); // number of tokens written
            try testing.expectEqualSlices(Token, df.block_writer.get(), c.tokens); // tokens match

            try testing.expectEqual(container.headerSize(), cw.bytes_written);
            try df.finish();
            try testing.expectEqual(container.size(), cw.bytes_written);
        }
    }
}

// Tests that tokens written are equal to expected token list.
const TestTokenWriter = struct {
    const Self = @This();

    pos: usize = 0,
    actual: [128]Token = undefined,

    pub fn init(_: anytype) Self {
        return .{};
    }
    pub fn write(self: *Self, tokens: []const Token, _: bool, _: ?[]const u8) !void {
        for (tokens) |t| {
            self.actual[self.pos] = t;
            self.pos += 1;
        }
    }

    pub fn storedBlock(_: *Self, _: []const u8, _: bool) !void {}

    pub fn get(self: *Self) []Token {
        return self.actual[0..self.pos];
    }

    pub fn show(self: *Self) void {
        print("\n", .{});
        for (self.get()) |t| {
            t.show();
        }
    }

    pub fn flush(_: *Self) !void {}
};

test "file tokenization" {
    const levels = [_]Level{ .level_4, .level_5, .level_6, .level_7, .level_8, .level_9 };
    const cases = [_]struct {
        data: []const u8, // uncompressed content
        // expected number of tokens producet in deflate tokenization
        tokens_count: [levels.len]usize = .{0} ** levels.len,
    }{
        .{
            .data = @embedFile("testdata/rfc1951.txt"),
            .tokens_count = .{ 7675, 7672, 7599, 7594, 7598, 7599 },
        },

        .{
            .data = @embedFile("testdata/block_writer/huffman-null-max.input"),
            .tokens_count = .{ 257, 257, 257, 257, 257, 257 },
        },
        .{
            .data = @embedFile("testdata/block_writer/huffman-pi.input"),
            .tokens_count = .{ 2570, 2564, 2564, 2564, 2564, 2564 },
        },
        .{
            .data = @embedFile("testdata/block_writer/huffman-text.input"),
            .tokens_count = .{ 235, 234, 234, 234, 234, 234 },
        },
        .{
            .data = @embedFile("testdata/fuzz/roundtrip1.input"),
            .tokens_count = .{ 333, 331, 331, 331, 331, 331 },
        },
        .{
            .data = @embedFile("testdata/fuzz/roundtrip2.input"),
            .tokens_count = .{ 334, 334, 334, 334, 334, 334 },
        },
    };

    for (cases) |case| { // for each case
        const data = case.data;

        for (levels, 0..) |level, i| { // for each compression level
            var original = io.fixedBufferStream(data);

            // buffer for decompressed data
            var al = std.ArrayList(u8).init(testing.allocator);
            defer al.deinit();
            const writer = al.writer();

            // create compressor
            const WriterType = @TypeOf(writer);
            const TokenWriter = TokenDecoder(@TypeOf(writer));
            var cmp = try Deflate(.raw, WriterType, TokenWriter).init(writer, .{ .level = level });

            // Stream uncompressed `original` data to the compressor. It will
            // produce tokens list and pass that list to the TokenDecoder. This
            // TokenDecoder uses CircularBuffer from inflate to convert list of
            // tokens back to the uncompressed stream.
            try cmp.compress(original.reader());
            try cmp.flush();
            const expected_count = case.tokens_count[i];
            const actual = cmp.block_writer.tokens_count;
            if (expected_count == 0) {
                print("actual token count {d}\n", .{actual});
            } else {
                try testing.expectEqual(expected_count, actual);
            }

            try testing.expectEqual(data.len, al.items.len);
            try testing.expectEqualSlices(u8, data, al.items);
        }
    }
}

fn TokenDecoder(comptime WriterType: type) type {
    return struct {
        const CircularBuffer = @import("CircularBuffer.zig");
        hist: CircularBuffer = .{},
        wrt: WriterType,
        tokens_count: usize = 0,

        const Self = @This();

        pub fn init(wrt: WriterType) Self {
            return .{ .wrt = wrt };
        }

        pub fn write(self: *Self, tokens: []const Token, _: bool, _: ?[]const u8) !void {
            self.tokens_count += tokens.len;
            for (tokens) |t| {
                switch (t.kind) {
                    .literal => self.hist.write(t.literal()),
                    .match => try self.hist.writeMatch(t.length(), t.distance()),
                }
                if (self.hist.free() < 285) try self.flushWin();
            }
            try self.flushWin();
        }

        pub fn storedBlock(_: *Self, _: []const u8, _: bool) !void {}

        fn flushWin(self: *Self) !void {
            while (true) {
                const buf = self.hist.read();
                if (buf.len == 0) break;
                try self.wrt.writeAll(buf);
            }
        }

        pub fn flush(_: *Self) !void {}
    };
}

test "store simple compressor" {
    const data = "Hello world!";
    const expected = [_]u8{
        0x1, // block type 0, final bit set
        0xc, 0x0, // len = 12
        0xf3, 0xff, // ~len
        'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', //
        //0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
    };

    var fbs = std.io.fixedBufferStream(data);
    var al = std.ArrayList(u8).init(testing.allocator);
    defer al.deinit();

    var cmp = try store.compressor(.raw, al.writer());
    try cmp.compress(fbs.reader());
    try cmp.finish();
    try testing.expectEqualSlices(u8, &expected, al.items);

    fbs.reset();
    try al.resize(0);

    // huffman only compresoor will also emit store block for this small sample
    var hc = try huffman.compressor(.raw, al.writer());
    try hc.compress(fbs.reader());
    try hc.finish();
    try testing.expectEqualSlices(u8, &expected, al.items);
}
const std = @import("std");
const testing = std.testing;

pub const Symbol = packed struct {
    pub const Kind = enum(u2) {
        literal,
        end_of_block,
        match,
    };

    symbol: u8 = 0, // symbol from alphabet
    code_bits: u4 = 0, // number of bits in code 0-15
    kind: Kind = .literal,

    code: u16 = 0, // huffman code of the symbol
    next: u16 = 0, // pointer to the next symbol in linked list
    // it is safe to use 0 as null pointer, when sorted 0 has shortest code and fits into lookup

    // Sorting less than function.
    pub fn asc(_: void, a: Symbol, b: Symbol) bool {
        if (a.code_bits == b.code_bits) {
            if (a.kind == b.kind) {
                return a.symbol < b.symbol;
            }
            return @intFromEnum(a.kind) < @intFromEnum(b.kind);
        }
        return a.code_bits < b.code_bits;
    }
};

pub const LiteralDecoder = HuffmanDecoder(286, 15, 9);
pub const DistanceDecoder = HuffmanDecoder(30, 15, 9);
pub const CodegenDecoder = HuffmanDecoder(19, 7, 7);

pub const Error = error{
    InvalidCode,
    OversubscribedHuffmanTree,
    IncompleteHuffmanTree,
    MissingEndOfBlockCode,
};

/// Creates huffman tree codes from list of code lengths (in `build`).
///
/// `find` then finds symbol for code bits. Code can be any length between 1 and
/// 15 bits. When calling `find` we don't know how many bits will be used to
/// find symbol. When symbol is returned it has code_bits field which defines
/// how much we should advance in bit stream.
///
/// Lookup table is used to map 15 bit int to symbol. Same symbol is written
/// many times in this table; 32K places for 286 (at most) symbols.
/// Small lookup table is optimization for faster search.
/// It is variation of the algorithm explained in [zlib](https://github.com/madler/zlib/blob/643e17b7498d12ab8d15565662880579692f769d/doc/algorithm.txt#L92)
/// with difference that we here use statically allocated arrays.
///
fn HuffmanDecoder(
    comptime alphabet_size: u16,
    comptime max_code_bits: u4,
    comptime lookup_bits: u4,
) type {
    const lookup_shift = max_code_bits - lookup_bits;

    return struct {
        // all symbols in alaphabet, sorted by code_len, symbol
        symbols: [alphabet_size]Symbol = undefined,
        // lookup table code -> symbol
        lookup: [1 << lookup_bits]Symbol = undefined,

        const Self = @This();

        /// Generates symbols and lookup tables from list of code lens for each symbol.
        pub fn generate(self: *Self, lens: []const u4) !void {
            try checkCompleteness(lens);

            // init alphabet with code_bits
            for (self.symbols, 0..) |_, i| {
                const cb: u4 = if (i < lens.len) lens[i] else 0;
                self.symbols[i] = if (i < 256)
                    .{ .kind = .literal, .symbol = @intCast(i), .code_bits = cb }
                else if (i == 256)
                    .{ .kind = .end_of_block, .symbol = 0xff, .code_bits = cb }
                else
                    .{ .kind = .match, .symbol = @intCast(i - 257), .code_bits = cb };
            }
            std.sort.heap(Symbol, &self.symbols, {}, Symbol.asc);

            // reset lookup table
            for (0..self.lookup.len) |i| {
                self.lookup[i] = .{};
            }

            // assign code to symbols
            // reference: https://youtu.be/9_YEGLe33NA?list=PLU4IQLU9e_OrY8oASHx0u3IXAL9TOdidm&t=2639
            var code: u16 = 0;
            var idx: u16 = 0;
            for (&self.symbols, 0..) |*sym, pos| {
                if (sym.code_bits == 0) continue; // skip unused
                sym.code = code;

                const next_code = code + (@as(u16, 1) << (max_code_bits - sym.code_bits));
                const next_idx = next_code >> lookup_shift;

                if (next_idx > self.lookup.len or idx >= self.lookup.len) break;
                if (sym.code_bits <= lookup_bits) {
                    // fill small lookup table
                    for (idx..next_idx) |j|
                        self.lookup[j] = sym.*;
                } else {
                    // insert into linked table starting at root
                    const root = &self.lookup[idx];
                    const root_next = root.next;
                    root.next = @intCast(pos);
                    sym.next = root_next;
                }

                idx = next_idx;
                code = next_code;
            }
        }

        /// Given the list of code lengths check that it represents a canonical
        /// Huffman code for n symbols.
        ///
        /// Reference: https://github.com/madler/zlib/blob/5c42a230b7b468dff011f444161c0145b5efae59/contrib/puff/puff.c#L340
        fn checkCompleteness(lens: []const u4) !void {
            if (alphabet_size == 286)
                if (lens[256] == 0) return error.MissingEndOfBlockCode;

            var count = [_]u16{0} ** (@as(usize, max_code_bits) + 1);
            var max: usize = 0;
            for (lens) |n| {
                if (n == 0) continue;
                if (n > max) max = n;
                count[n] += 1;
            }
            if (max == 0) // empty tree
                return;

            // check for an over-subscribed or incomplete set of lengths
            var left: usize = 1; // one possible code of zero length
            for (1..count.len) |len| {
                left <<= 1; // one more bit, double codes left
                if (count[len] > left)
                    return error.OversubscribedHuffmanTree;
                left -= count[len]; // deduct count from possible codes
            }
            if (left > 0) { // left > 0 means incomplete
                // incomplete code ok only for single length 1 code
                if (max_code_bits > 7 and max == count[0] + count[1]) return;
                return error.IncompleteHuffmanTree;
            }
        }

        /// Finds symbol for lookup table code.
        pub fn find(self: *Self, code: u16) !Symbol {
            // try to find in lookup table
            const idx = code >> lookup_shift;
            const sym = self.lookup[idx];
            if (sym.code_bits != 0) return sym;
            // if not use linked list of symbols with same prefix
            return self.findLinked(code, sym.next);
        }

        inline fn findLinked(self: *Self, code: u16, start: u16) !Symbol {
            var pos = start;
            while (pos > 0) {
                const sym = self.symbols[pos];
                const shift = max_code_bits - sym.code_bits;
                // compare code_bits number of upper bits
                if ((code ^ sym.code) >> shift == 0) return sym;
                pos = sym.next;
            }
            return error.InvalidCode;
        }
    };
}

test "init/find" {
    // example data from: https://youtu.be/SJPvNi4HrWQ?t=8423
    const code_lens = [_]u4{ 4, 3, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 3, 2 };
    var h: CodegenDecoder = .{};
    try h.generate(&code_lens);

    const expected = [_]struct {
        sym: Symbol,
        code: u16,
    }{
        .{
            .code = 0b00_00000,
            .sym = .{ .symbol = 3, .code_bits = 2 },
        },
        .{
            .code = 0b01_00000,
            .sym = .{ .symbol = 18, .code_bits = 2 },
        },
        .{
            .code = 0b100_0000,
            .sym = .{ .symbol = 1, .code_bits = 3 },
        },
        .{
            .code = 0b101_0000,
            .sym = .{ .symbol = 4, .code_bits = 3 },
        },
        .{
            .code = 0b110_0000,
            .sym = .{ .symbol = 17, .code_bits = 3 },
        },
        .{
            .code = 0b1110_000,
            .sym = .{ .symbol = 0, .code_bits = 4 },
        },
        .{
            .code = 0b1111_000,
            .sym = .{ .symbol = 16, .code_bits = 4 },
        },
    };

    // unused symbols
    for (0..12) |i| {
        try testing.expectEqual(0, h.symbols[i].code_bits);
    }
    // used, from index 12
    for (expected, 12..) |e, i| {
        try testing.expectEqual(e.sym.symbol, h.symbols[i].symbol);
        try testing.expectEqual(e.sym.code_bits, h.symbols[i].code_bits);
        const sym_from_code = try h.find(e.code);
        try testing.expectEqual(e.sym.symbol, sym_from_code.symbol);
    }

    // All possible codes for each symbol.
    // Lookup table has 126 elements, to cover all possible 7 bit codes.
    for (0b0000_000..0b0100_000) |c| // 0..32 (32)
        try testing.expectEqual(3, (try h.find(@intCast(c))).symbol);

    for (0b0100_000..0b1000_000) |c| // 32..64 (32)
        try testing.expectEqual(18, (try h.find(@intCast(c))).symbol);

    for (0b1000_000..0b1010_000) |c| // 64..80 (16)
        try testing.expectEqual(1, (try h.find(@intCast(c))).symbol);

    for (0b1010_000..0b1100_000) |c| // 80..96 (16)
        try testing.expectEqual(4, (try h.find(@intCast(c))).symbol);

    for (0b1100_000..0b1110_000) |c| // 96..112 (16)
        try testing.expectEqual(17, (try h.find(@intCast(c))).symbol);

    for (0b1110_000..0b1111_000) |c| // 112..120 (8)
        try testing.expectEqual(0, (try h.find(@intCast(c))).symbol);

    for (0b1111_000..0b1_0000_000) |c| // 120...128 (8)
        try testing.expectEqual(16, (try h.find(@intCast(c))).symbol);
}

test "encode/decode literals" {
    const LiteralEncoder = @import("huffman_encoder.zig").LiteralEncoder;

    for (1..286) |j| { // for all different number of codes
        var enc: LiteralEncoder = .{};
        // create frequencies
        var freq = [_]u16{0} ** 286;
        freq[256] = 1; // ensure we have end of block code
        for (&freq, 1..) |*f, i| {
            if (i % j == 0)
                f.* = @intCast(i);
        }

        // encoder from frequencies
        enc.generate(&freq, 15);

        // get code_lens from encoder
        var code_lens = [_]u4{0} ** 286;
        for (code_lens, 0..) |_, i| {
            code_lens[i] = @intCast(enc.codes[i].len);
        }
        // generate decoder from code lens
        var dec: LiteralDecoder = .{};
        try dec.generate(&code_lens);

        // expect decoder code to match original encoder code
        for (dec.symbols) |s| {
            if (s.code_bits == 0) continue;
            const c_code: u16 = @bitReverse(@as(u15, @intCast(s.code)));
            const symbol: u16 = switch (s.kind) {
                .literal => s.symbol,
                .end_of_block => 256,
                .match => @as(u16, s.symbol) + 257,
            };

            const c = enc.codes[symbol];
            try testing.expect(c.code == c_code);
        }

        // find each symbol by code
        for (enc.codes) |c| {
            if (c.len == 0) continue;

            const s_code: u15 = @bitReverse(@as(u15, @intCast(c.code)));
            const s = try dec.find(s_code);
            try testing.expect(s.code == s_code);
            try testing.expect(s.code_bits == c.len);
        }
    }
}
const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const sort = std.sort;
const testing = std.testing;

const consts = @import("consts.zig").huffman;

const LiteralNode = struct {
    literal: u16,
    freq: u16,
};

// Describes the state of the constructed tree for a given depth.
const LevelInfo = struct {
    // Our level.  for better printing
    level: u32,

    // The frequency of the last node at this level
    last_freq: u32,

    // The frequency of the next character to add to this level
    next_char_freq: u32,

    // The frequency of the next pair (from level below) to add to this level.
    // Only valid if the "needed" value of the next lower level is 0.
    next_pair_freq: u32,

    // The number of chains remaining to generate for this level before moving
    // up to the next level
    needed: u32,
};

// hcode is a huffman code with a bit code and bit length.
pub const HuffCode = struct {
    code: u16 = 0,
    len: u16 = 0,

    // set sets the code and length of an hcode.
    fn set(self: *HuffCode, code: u16, length: u16) void {
        self.len = length;
        self.code = code;
    }
};

pub fn HuffmanEncoder(comptime size: usize) type {
    return struct {
        codes: [size]HuffCode = undefined,
        // Reusable buffer with the longest possible frequency table.
        freq_cache: [consts.max_num_frequencies + 1]LiteralNode = undefined,
        bit_count: [17]u32 = undefined,
        lns: []LiteralNode = undefined, // sorted by literal, stored to avoid repeated allocation in generate
        lfs: []LiteralNode = undefined, // sorted by frequency, stored to avoid repeated allocation in generate

        const Self = @This();

        // Update this Huffman Code object to be the minimum code for the specified frequency count.
        //
        // freq  An array of frequencies, in which frequency[i] gives the frequency of literal i.
        // max_bits  The maximum number of bits to use for any literal.
        pub fn generate(self: *Self, freq: []u16, max_bits: u32) void {
            var list = self.freq_cache[0 .. freq.len + 1];
            // Number of non-zero literals
            var count: u32 = 0;
            // Set list to be the set of all non-zero literals and their frequencies
            for (freq, 0..) |f, i| {
                if (f != 0) {
                    list[count] = LiteralNode{ .literal = @as(u16, @intCast(i)), .freq = f };
                    count += 1;
                } else {
                    list[count] = LiteralNode{ .literal = 0x00, .freq = 0 };
                    self.codes[i].len = 0;
                }
            }
            list[freq.len] = LiteralNode{ .literal = 0x00, .freq = 0 };

            list = list[0..count];
            if (count <= 2) {
                // Handle the small cases here, because they are awkward for the general case code. With
                // two or fewer literals, everything has bit length 1.
                for (list, 0..) ```
