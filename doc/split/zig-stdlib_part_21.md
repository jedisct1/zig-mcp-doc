```
lsSection.Streams,
    literal_header: LiteralsSection.Header,
    huffman_tree: ?LiteralsSection.HuffmanTree,

    literal_written_count: usize,
    written_count: usize = 0,

    fn StateData(comptime max_accuracy_log: comptime_int) type {
        return struct {
            state: State,
            table: Table,
            accuracy_log: u8,

            const State = std.meta.Int(.unsigned, max_accuracy_log);
        };
    }

    pub fn init(
        literal_fse_buffer: []Table.Fse,
        match_fse_buffer: []Table.Fse,
        offset_fse_buffer: []Table.Fse,
    ) DecodeState {
        return DecodeState{
            .repeat_offsets = .{
                types.compressed_block.start_repeated_offset_1,
                types.compressed_block.start_repeated_offset_2,
                types.compressed_block.start_repeated_offset_3,
            },

            .offset = undefined,
            .match = undefined,
            .literal = undefined,

            .literal_fse_buffer = literal_fse_buffer,
            .match_fse_buffer = match_fse_buffer,
            .offset_fse_buffer = offset_fse_buffer,

            .fse_tables_undefined = true,

            .literal_written_count = 0,
            .literal_header = undefined,
            .literal_streams = undefined,
            .literal_stream_reader = undefined,
            .literal_stream_index = undefined,
            .huffman_tree = null,

            .written_count = 0,
        };
    }

    /// Prepare the decoder to decode a compressed block. Loads the literals
    /// stream and Huffman tree from `literals` and reads the FSE tables from
    /// `source`.
    ///
    /// Errors returned:
    ///   - `error.BitStreamHasNoStartBit` if the (reversed) literal bitstream's
    ///     first byte does not have any bits set
    ///   - `error.TreelessLiteralsFirst` `literals` is a treeless literals
    ///     section and the decode state does not have a Huffman tree from a
    ///     previous block
    ///   - `error.RepeatModeFirst` on the first call if one of the sequence FSE
    ///     tables is set to repeat mode
    ///   - `error.MalformedAccuracyLog` if an FSE table has an invalid accuracy
    ///   - `error.MalformedFseTable` if there are errors decoding an FSE table
    ///   - `error.EndOfStream` if `source` ends before all FSE tables are read
    pub fn prepare(
        self: *DecodeState,
        source: anytype,
        literals: LiteralsSection,
        sequences_header: SequencesSection.Header,
    ) !void {
        self.literal_written_count = 0;
        self.literal_header = literals.header;
        self.literal_streams = literals.streams;

        if (literals.huffman_tree) |tree| {
            self.huffman_tree = tree;
        } else if (literals.header.block_type == .treeless and self.huffman_tree == null) {
            return error.TreelessLiteralsFirst;
        }

        switch (literals.header.block_type) {
            .raw, .rle => {},
            .compressed, .treeless => {
                self.literal_stream_index = 0;
                switch (literals.streams) {
                    .one => |slice| try self.initLiteralStream(slice),
                    .four => |streams| try self.initLiteralStream(streams[0]),
                }
            },
        }

        if (sequences_header.sequence_count > 0) {
            try self.updateFseTable(source, .literal, sequences_header.literal_lengths);
            try self.updateFseTable(source, .offset, sequences_header.offsets);
            try self.updateFseTable(source, .match, sequences_header.match_lengths);
            self.fse_tables_undefined = false;
        }
    }

    /// Read initial FSE states for sequence decoding.
    ///
    /// Errors returned:
    ///   - `error.EndOfStream` if `bit_reader` does not contain enough bits.
    pub fn readInitialFseState(self: *DecodeState, bit_reader: *readers.ReverseBitReader) error{EndOfStream}!void {
        self.literal.state = try bit_reader.readBitsNoEof(u9, self.literal.accuracy_log);
        self.offset.state = try bit_reader.readBitsNoEof(u8, self.offset.accuracy_log);
        self.match.state = try bit_reader.readBitsNoEof(u9, self.match.accuracy_log);
    }

    fn updateRepeatOffset(self: *DecodeState, offset: u32) void {
        self.repeat_offsets[2] = self.repeat_offsets[1];
        self.repeat_offsets[1] = self.repeat_offsets[0];
        self.repeat_offsets[0] = offset;
    }

    fn useRepeatOffset(self: *DecodeState, index: usize) u32 {
        if (index == 1)
            std.mem.swap(u32, &self.repeat_offsets[0], &self.repeat_offsets[1])
        else if (index == 2) {
            std.mem.swap(u32, &self.repeat_offsets[0], &self.repeat_offsets[2]);
            std.mem.swap(u32, &self.repeat_offsets[1], &self.repeat_offsets[2]);
        }
        return self.repeat_offsets[0];
    }

    const DataType = enum { offset, match, literal };

    fn updateState(
        self: *DecodeState,
        comptime choice: DataType,
        bit_reader: *readers.ReverseBitReader,
    ) error{ MalformedFseBits, EndOfStream }!void {
        switch (@field(self, @tagName(choice)).table) {
            .rle => {},
            .fse => |table| {
                const data = table[@field(self, @tagName(choice)).state];
                const T = @TypeOf(@field(self, @tagName(choice))).State;
                const bits_summand = try bit_reader.readBitsNoEof(T, data.bits);
                const next_state = std.math.cast(
                    @TypeOf(@field(self, @tagName(choice))).State,
                    data.baseline + bits_summand,
                ) orelse return error.MalformedFseBits;
                @field(self, @tagName(choice)).state = next_state;
            },
        }
    }

    const FseTableError = error{
        MalformedFseTable,
        MalformedAccuracyLog,
        RepeatModeFirst,
        EndOfStream,
    };

    fn updateFseTable(
        self: *DecodeState,
        source: anytype,
        comptime choice: DataType,
        mode: SequencesSection.Header.Mode,
    ) !void {
        const field_name = @tagName(choice);
        switch (mode) {
            .predefined => {
                @field(self, field_name).accuracy_log =
                    @field(types.compressed_block.default_accuracy_log, field_name);

                @field(self, field_name).table =
                    @field(types.compressed_block, "predefined_" ++ field_name ++ "_fse_table");
            },
            .rle => {
                @field(self, field_name).accuracy_log = 0;
                @field(self, field_name).table = .{ .rle = try source.readByte() };
            },
            .fse => {
                var bit_reader = readers.bitReader(source);

                const table_size = try decodeFseTable(
                    &bit_reader,
                    @field(types.compressed_block.table_symbol_count_max, field_name),
                    @field(types.compressed_block.table_accuracy_log_max, field_name),
                    @field(self, field_name ++ "_fse_buffer"),
                );
                @field(self, field_name).table = .{
                    .fse = @field(self, field_name ++ "_fse_buffer")[0..table_size],
                };
                @field(self, field_name).accuracy_log = std.math.log2_int_ceil(usize, table_size);
            },
            .repeat => if (self.fse_tables_undefined) return error.RepeatModeFirst,
        }
    }

    const Sequence = struct {
        literal_length: u32,
        match_length: u32,
        offset: u32,
    };

    fn nextSequence(
        self: *DecodeState,
        bit_reader: *readers.ReverseBitReader,
    ) error{ InvalidBitStream, EndOfStream }!Sequence {
        const raw_code = self.getCode(.offset);
        const offset_code = std.math.cast(u5, raw_code) orelse {
            return error.InvalidBitStream;
        };
        const offset_value = (@as(u32, 1) << offset_code) + try bit_reader.readBitsNoEof(u32, offset_code);

        const match_code = self.getCode(.match);
        if (match_code >= types.compressed_block.match_length_code_table.len)
            return error.InvalidBitStream;
        const match = types.compressed_block.match_length_code_table[match_code];
        const match_length = match[0] + try bit_reader.readBitsNoEof(u32, match[1]);

        const literal_code = self.getCode(.literal);
        if (literal_code >= types.compressed_block.literals_length_code_table.len)
            return error.InvalidBitStream;
        const literal = types.compressed_block.literals_length_code_table[literal_code];
        const literal_length = literal[0] + try bit_reader.readBitsNoEof(u32, literal[1]);

        const offset = if (offset_value > 3) offset: {
            const offset = offset_value - 3;
            self.updateRepeatOffset(offset);
            break :offset offset;
        } else offset: {
            if (literal_length == 0) {
                if (offset_value == 3) {
                    const offset = self.repeat_offsets[0] - 1;
                    self.updateRepeatOffset(offset);
                    break :offset offset;
                }
                break :offset self.useRepeatOffset(offset_value);
            }
            break :offset self.useRepeatOffset(offset_value - 1);
        };

        if (offset == 0) return error.InvalidBitStream;

        return .{
            .literal_length = literal_length,
            .match_length = match_length,
            .offset = offset,
        };
    }

    fn executeSequenceSlice(
        self: *DecodeState,
        dest: []u8,
        write_pos: usize,
        sequence: Sequence,
    ) (error{MalformedSequence} || DecodeLiteralsError)!void {
        if (sequence.offset > write_pos + sequence.literal_length) return error.MalformedSequence;

        try self.decodeLiteralsSlice(dest[write_pos..], sequence.literal_length);
        const copy_start = write_pos + sequence.literal_length - sequence.offset;
        for (
            dest[write_pos + sequence.literal_length ..][0..sequence.match_length],
            dest[copy_start..][0..sequence.match_length],
        ) |*d, s| d.* = s;
        self.written_count += sequence.match_length;
    }

    fn executeSequenceRingBuffer(
        self: *DecodeState,
        dest: *RingBuffer,
        sequence: Sequence,
    ) (error{MalformedSequence} || DecodeLiteralsError)!void {
        if (sequence.offset > @min(dest.data.len, self.written_count + sequence.literal_length))
            return error.MalformedSequence;

        try self.decodeLiteralsRingBuffer(dest, sequence.literal_length);
        const copy_start = dest.write_index + dest.data.len - sequence.offset;
        const copy_slice = dest.sliceAt(copy_start, sequence.match_length);
        dest.writeSliceForwardsAssumeCapacity(copy_slice.first);
        dest.writeSliceForwardsAssumeCapacity(copy_slice.second);
        self.written_count += sequence.match_length;
    }

    const DecodeSequenceError = error{
        InvalidBitStream,
        EndOfStream,
        MalformedSequence,
        MalformedFseBits,
    } || DecodeLiteralsError;

    /// Decode one sequence from `bit_reader` into `dest`, written starting at
    /// `write_pos` and update FSE states if `last_sequence` is `false`.
    /// `prepare()` must be called for the block before attempting to decode
    /// sequences.
    ///
    /// Errors returned:
    ///   - `error.MalformedSequence` if the decompressed sequence would be
    ///     longer than `sequence_size_limit` or the sequence's offset is too
    ///     large
    ///   - `error.UnexpectedEndOfLiteralStream` if the decoder state's literal
    ///     streams do not contain enough literals for the sequence (this may
    ///     mean the literal stream or the sequence is malformed).
    ///   - `error.InvalidBitStream` if the FSE sequence bitstream is malformed
    ///   - `error.EndOfStream` if `bit_reader` does not contain enough bits
    ///   - `error.DestTooSmall` if `dest` is not large enough to holde the
    ///     decompressed sequence
    pub fn decodeSequenceSlice(
        self: *DecodeState,
        dest: []u8,
        write_pos: usize,
        bit_reader: *readers.ReverseBitReader,
        sequence_size_limit: usize,
        last_sequence: bool,
    ) (error{DestTooSmall} || DecodeSequenceError)!usize {
        const sequence = try self.nextSequence(bit_reader);
        const sequence_length = @as(usize, sequence.literal_length) + sequence.match_length;
        if (sequence_length > sequence_size_limit) return error.MalformedSequence;
        if (sequence_length > dest[write_pos..].len) return error.DestTooSmall;

        try self.executeSequenceSlice(dest, write_pos, sequence);
        if (!last_sequence) {
            try self.updateState(.literal, bit_reader);
            try self.updateState(.match, bit_reader);
            try self.updateState(.offset, bit_reader);
        }
        return sequence_length;
    }

    /// Decode one sequence from `bit_reader` into `dest`; see
    /// `decodeSequenceSlice`.
    pub fn decodeSequenceRingBuffer(
        self: *DecodeState,
        dest: *RingBuffer,
        bit_reader: anytype,
        sequence_size_limit: usize,
        last_sequence: bool,
    ) DecodeSequenceError!usize {
        const sequence = try self.nextSequence(bit_reader);
        const sequence_length = @as(usize, sequence.literal_length) + sequence.match_length;
        if (sequence_length > sequence_size_limit) return error.MalformedSequence;

        try self.executeSequenceRingBuffer(dest, sequence);
        if (!last_sequence) {
            try self.updateState(.literal, bit_reader);
            try self.updateState(.match, bit_reader);
            try self.updateState(.offset, bit_reader);
        }
        return sequence_length;
    }

    fn nextLiteralMultiStream(
        self: *DecodeState,
    ) error{BitStreamHasNoStartBit}!void {
        self.literal_stream_index += 1;
        try self.initLiteralStream(self.literal_streams.four[self.literal_stream_index]);
    }

    fn initLiteralStream(self: *DecodeState, bytes: []const u8) error{BitStreamHasNoStartBit}!void {
        try self.literal_stream_reader.init(bytes);
    }

    fn isLiteralStreamEmpty(self: *DecodeState) bool {
        switch (self.literal_streams) {
            .one => return self.literal_stream_reader.isEmpty(),
            .four => return self.literal_stream_index == 3 and self.literal_stream_reader.isEmpty(),
        }
    }

    const LiteralBitsError = error{
        BitStreamHasNoStartBit,
        UnexpectedEndOfLiteralStream,
    };
    fn readLiteralsBits(
        self: *DecodeState,
        bit_count_to_read: u16,
    ) LiteralBitsError!u16 {
        return self.literal_stream_reader.readBitsNoEof(u16, bit_count_to_read) catch bits: {
            if (self.literal_streams == .four and self.literal_stream_index < 3) {
                try self.nextLiteralMultiStream();
                break :bits self.literal_stream_reader.readBitsNoEof(u16, bit_count_to_read) catch
                    return error.UnexpectedEndOfLiteralStream;
            } else {
                return error.UnexpectedEndOfLiteralStream;
            }
        };
    }

    const DecodeLiteralsError = error{
        MalformedLiteralsLength,
        NotFound,
    } || LiteralBitsError;

    /// Decode `len` bytes of literals into `dest`.
    ///
    /// Errors returned:
    ///   - `error.MalformedLiteralsLength` if the number of literal bytes
    ///     decoded by `self` plus `len` is greater than the regenerated size of
    ///     `literals`
    ///   - `error.UnexpectedEndOfLiteralStream` and `error.NotFound` if there
    ///     are problems decoding Huffman compressed literals
    pub fn decodeLiteralsSlice(
        self: *DecodeState,
        dest: []u8,
        len: usize,
    ) DecodeLiteralsError!void {
        if (self.literal_written_count + len > self.literal_header.regenerated_size)
            return error.MalformedLiteralsLength;

        switch (self.literal_header.block_type) {
            .raw => {
                const literal_data = self.literal_streams.one[self.literal_written_count..][0..len];
                @memcpy(dest[0..len], literal_data);
                self.literal_written_count += len;
                self.written_count += len;
            },
            .rle => {
                for (0..len) |i| {
                    dest[i] = self.literal_streams.one[0];
                }
                self.literal_written_count += len;
                self.written_count += len;
            },
            .compressed, .treeless => {
                // const written_bytes_per_stream = (literals.header.regenerated_size + 3) / 4;
                const huffman_tree = self.huffman_tree orelse unreachable;
                const max_bit_count = huffman_tree.max_bit_count;
                const starting_bit_count = LiteralsSection.HuffmanTree.weightToBitCount(
                    huffman_tree.nodes[huffman_tree.symbol_count_minus_one].weight,
                    max_bit_count,
                );
                var bits_read: u4 = 0;
                var huffman_tree_index: usize = huffman_tree.symbol_count_minus_one;
                var bit_count_to_read: u4 = starting_bit_count;
                for (0..len) |i| {
                    var prefix: u16 = 0;
                    while (true) {
                        const new_bits = self.readLiteralsBits(bit_count_to_read) catch |err| {
                            return err;
                        };
                        prefix <<= bit_count_to_read;
                        prefix |= new_bits;
                        bits_read += bit_count_to_read;
                        const result = huffman_tree.query(huffman_tree_index, prefix) catch |err| {
                            return err;
                        };

                        switch (result) {
                            .symbol => |sym| {
                                dest[i] = sym;
                                bit_count_to_read = starting_bit_count;
                                bits_read = 0;
                                huffman_tree_index = huffman_tree.symbol_count_minus_one;
                                break;
                            },
                            .index => |index| {
                                huffman_tree_index = index;
                                const bit_count = LiteralsSection.HuffmanTree.weightToBitCount(
                                    huffman_tree.nodes[index].weight,
                                    max_bit_count,
                                );
                                bit_count_to_read = bit_count - bits_read;
                            },
                        }
                    }
                }
                self.literal_written_count += len;
                self.written_count += len;
            },
        }
    }

    /// Decode literals into `dest`; see `decodeLiteralsSlice()`.
    pub fn decodeLiteralsRingBuffer(
        self: *DecodeState,
        dest: *RingBuffer,
        len: usize,
    ) DecodeLiteralsError!void {
        if (self.literal_written_count + len > self.literal_header.regenerated_size)
            return error.MalformedLiteralsLength;

        switch (self.literal_header.block_type) {
            .raw => {
                const literals_end = self.literal_written_count + len;
                const literal_data = self.literal_streams.one[self.literal_written_count..literals_end];
                dest.writeSliceAssumeCapacity(literal_data);
                self.literal_written_count += len;
                self.written_count += len;
            },
            .rle => {
                for (0..len) |_| {
                    dest.writeAssumeCapacity(self.literal_streams.one[0]);
                }
                self.literal_written_count += len;
                self.written_count += len;
            },
            .compressed, .treeless => {
                // const written_bytes_per_stream = (literals.header.regenerated_size + 3) / 4;
                const huffman_tree = self.huffman_tree orelse unreachable;
                const max_bit_count = huffman_tree.max_bit_count;
                const starting_bit_count = LiteralsSection.HuffmanTree.weightToBitCount(
                    huffman_tree.nodes[huffman_tree.symbol_count_minus_one].weight,
                    max_bit_count,
                );
                var bits_read: u4 = 0;
                var huffman_tree_index: usize = huffman_tree.symbol_count_minus_one;
                var bit_count_to_read: u4 = starting_bit_count;
                for (0..len) |_| {
                    var prefix: u16 = 0;
                    while (true) {
                        const new_bits = try self.readLiteralsBits(bit_count_to_read);
                        prefix <<= bit_count_to_read;
                        prefix |= new_bits;
                        bits_read += bit_count_to_read;
                        const result = try huffman_tree.query(huffman_tree_index, prefix);

                        switch (result) {
                            .symbol => |sym| {
                                dest.writeAssumeCapacity(sym);
                                bit_count_to_read = starting_bit_count;
                                bits_read = 0;
                                huffman_tree_index = huffman_tree.symbol_count_minus_one;
                                break;
                            },
                            .index => |index| {
                                huffman_tree_index = index;
                                const bit_count = LiteralsSection.HuffmanTree.weightToBitCount(
                                    huffman_tree.nodes[index].weight,
                                    max_bit_count,
                                );
                                bit_count_to_read = bit_count - bits_read;
                            },
                        }
                    }
                }
                self.literal_written_count += len;
                self.written_count += len;
            },
        }
    }

    fn getCode(self: *DecodeState, comptime choice: DataType) u32 {
        return switch (@field(self, @tagName(choice)).table) {
            .rle => |value| value,
            .fse => |table| table[@field(self, @tagName(choice)).state].symbol,
        };
    }
};

/// Decode a single block from `src` into `dest`. The beginning of `src` must be
/// the start of the block content (i.e. directly after the block header).
/// Increments `consumed_count` by the number of bytes read from `src` to decode
/// the block and returns the decompressed size of the block.
///
/// Errors returned:
///
///   - `error.BlockSizeOverMaximum` if block's size is larger than 1 << 17 or
///     `dest[written_count..].len`
///   - `error.MalformedBlockSize` if `src.len` is smaller than the block size
///     and the block is a raw or compressed block
///   - `error.ReservedBlock` if the block is a reserved block
///   - `error.MalformedRleBlock` if the block is an RLE block and `src.len < 1`
///   - `error.MalformedCompressedBlock` if there are errors decoding a
///     compressed block
///   - `error.DestTooSmall` is `dest` is not large enough to hold the
///     decompressed block
pub fn decodeBlock(
    dest: []u8,
    src: []const u8,
    block_header: frame.Zstandard.Block.Header,
    decode_state: *DecodeState,
    consumed_count: *usize,
    block_size_max: usize,
    written_count: usize,
) (error{DestTooSmall} || Error)!usize {
    const block_size = block_header.block_size;
    if (block_size_max < block_size) return error.BlockSizeOverMaximum;
    switch (block_header.block_type) {
        .raw => {
            if (src.len < block_size) return error.MalformedBlockSize;
            if (dest[written_count..].len < block_size) return error.DestTooSmall;
            @memcpy(dest[written_count..][0..block_size], src[0..block_size]);
            consumed_count.* += block_size;
            decode_state.written_count += block_size;
            return block_size;
        },
        .rle => {
            if (src.len < 1) return error.MalformedRleBlock;
            if (dest[written_count..].len < block_size) return error.DestTooSmall;
            for (written_count..block_size + written_count) |write_pos| {
                dest[write_pos] = src[0];
            }
            consumed_count.* += 1;
            decode_state.written_count += block_size;
            return block_size;
        },
        .compressed => {
            if (src.len < block_size) return error.MalformedBlockSize;
            var bytes_read: usize = 0;
            const literals = decodeLiteralsSectionSlice(src[0..block_size], &bytes_read) catch
                return error.MalformedCompressedBlock;
            var fbs = std.io.fixedBufferStream(src[bytes_read..block_size]);
            const fbs_reader = fbs.reader();
            const sequences_header = decodeSequencesHeader(fbs_reader) catch
                return error.MalformedCompressedBlock;

            decode_state.prepare(fbs_reader, literals, sequences_header) catch
                return error.MalformedCompressedBlock;

            bytes_read += fbs.pos;

            var bytes_written: usize = 0;
            {
                const bit_stream_bytes = src[bytes_read..block_size];
                var bit_stream: readers.ReverseBitReader = undefined;
                bit_stream.init(bit_stream_bytes) catch return error.MalformedCompressedBlock;

                if (sequences_header.sequence_count > 0) {
                    decode_state.readInitialFseState(&bit_stream) catch
                        return error.MalformedCompressedBlock;

                    var sequence_size_limit = block_size_max;
                    for (0..sequences_header.sequence_count) |i| {
                        const write_pos = written_count + bytes_written;
                        const decompressed_size = decode_state.decodeSequenceSlice(
                            dest,
                            write_pos,
                            &bit_stream,
                            sequence_size_limit,
                            i == sequences_header.sequence_count - 1,
                        ) catch |err| switch (err) {
                            error.DestTooSmall => return error.DestTooSmall,
                            else => return error.MalformedCompressedBlock,
                        };
                        bytes_written += decompressed_size;
                        sequence_size_limit -= decompressed_size;
                    }
                }

                if (!bit_stream.isEmpty()) {
                    return error.MalformedCompressedBlock;
                }
            }

            if (decode_state.literal_written_count < literals.header.regenerated_size) {
                const len = literals.header.regenerated_size - decode_state.literal_written_count;
                if (len > dest[written_count + bytes_written ..].len) return error.DestTooSmall;
                decode_state.decodeLiteralsSlice(dest[written_count + bytes_written ..], len) catch
                    return error.MalformedCompressedBlock;
                bytes_written += len;
            }

            switch (decode_state.literal_header.block_type) {
                .treeless, .compressed => {
                    if (!decode_state.isLiteralStreamEmpty()) return error.MalformedCompressedBlock;
                },
                .raw, .rle => {},
            }

            consumed_count.* += block_size;
            return bytes_written;
        },
        .reserved => return error.ReservedBlock,
    }
}

/// Decode a single block from `src` into `dest`; see `decodeBlock()`. Returns
/// the size of the decompressed block, which can be used with `dest.sliceLast()`
/// to get the decompressed bytes. `error.BlockSizeOverMaximum` is returned if
/// the block's compressed or decompressed size is larger than `block_size_max`.
pub fn decodeBlockRingBuffer(
    dest: *RingBuffer,
    src: []const u8,
    block_header: frame.Zstandard.Block.Header,
    decode_state: *DecodeState,
    consumed_count: *usize,
    block_size_max: usize,
) Error!usize {
    const block_size = block_header.block_size;
    if (block_size_max < block_size) return error.BlockSizeOverMaximum;
    switch (block_header.block_type) {
        .raw => {
            if (src.len < block_size) return error.MalformedBlockSize;
            // dest may have length zero if block_size == 0, causing division by zero in
            // writeSliceAssumeCapacity()
            if (block_size > 0) {
                const data = src[0..block_size];
                dest.writeSliceAssumeCapacity(data);
                consumed_count.* += block_size;
                decode_state.written_count += block_size;
            }
            return block_size;
        },
        .rle => {
            if (src.len < 1) return error.MalformedRleBlock;
            for (0..block_size) |_| {
                dest.writeAssumeCapacity(src[0]);
            }
            consumed_count.* += 1;
            decode_state.written_count += block_size;
            return block_size;
        },
        .compressed => {
            if (src.len < block_size) return error.MalformedBlockSize;
            var bytes_read: usize = 0;
            const literals = decodeLiteralsSectionSlice(src[0..block_size], &bytes_read) catch
                return error.MalformedCompressedBlock;
            var fbs = std.io.fixedBufferStream(src[bytes_read..block_size]);
            const fbs_reader = fbs.reader();
            const sequences_header = decodeSequencesHeader(fbs_reader) catch
                return error.MalformedCompressedBlock;

            decode_state.prepare(fbs_reader, literals, sequences_header) catch
                return error.MalformedCompressedBlock;

            bytes_read += fbs.pos;

            var bytes_written: usize = 0;
            {
                const bit_stream_bytes = src[bytes_read..block_size];
                var bit_stream: readers.ReverseBitReader = undefined;
                bit_stream.init(bit_stream_bytes) catch return error.MalformedCompressedBlock;

                if (sequences_header.sequence_count > 0) {
                    decode_state.readInitialFseState(&bit_stream) catch
                        return error.MalformedCompressedBlock;

                    var sequence_size_limit = block_size_max;
                    for (0..sequences_header.sequence_count) |i| {
                        const decompressed_size = decode_state.decodeSequenceRingBuffer(
                            dest,
                            &bit_stream,
                            sequence_size_limit,
                            i == sequences_header.sequence_count - 1,
                        ) catch return error.MalformedCompressedBlock;
                        bytes_written += decompressed_size;
                        sequence_size_limit -= decompressed_size;
                    }
                }

                if (!bit_stream.isEmpty()) {
                    return error.MalformedCompressedBlock;
                }
            }

            if (decode_state.literal_written_count < literals.header.regenerated_size) {
                const len = literals.header.regenerated_size - decode_state.literal_written_count;
                decode_state.decodeLiteralsRingBuffer(dest, len) catch
                    return error.MalformedCompressedBlock;
                bytes_written += len;
            }

            switch (decode_state.literal_header.block_type) {
                .treeless, .compressed => {
                    if (!decode_state.isLiteralStreamEmpty()) return error.MalformedCompressedBlock;
                },
                .raw, .rle => {},
            }

            consumed_count.* += block_size;
            if (bytes_written > block_size_max) return error.BlockSizeOverMaximum;
            return bytes_written;
        },
        .reserved => return error.ReservedBlock,
    }
}

/// Decode a single block from `source` into `dest`. Literal and sequence data
/// from the block is copied into `literals_buffer` and `sequence_buffer`, which
/// must be large enough or `error.LiteralsBufferTooSmall` and
/// `error.SequenceBufferTooSmall` are returned (the maximum block size is an
/// upper bound for the size of both buffers). See `decodeBlock`
/// and `decodeBlockRingBuffer` for function that can decode a block without
/// these extra copies. `error.EndOfStream` is returned if `source` does not
/// contain enough bytes.
pub fn decodeBlockReader(
    dest: *RingBuffer,
    source: anytype,
    block_header: frame.Zstandard.Block.Header,
    decode_state: *DecodeState,
    block_size_max: usize,
    literals_buffer: []u8,
    sequence_buffer: []u8,
) !void {
    const block_size = block_header.block_size;
    var block_reader_limited = std.io.limitedReader(source, block_size);
    const block_reader = block_reader_limited.reader();
    if (block_size_max < block_size) return error.BlockSizeOverMaximum;
    switch (block_header.block_type) {
        .raw => {
            if (block_size == 0) return;
            const slice = dest.sliceAt(dest.write_index, block_size);
            try source.readNoEof(slice.first);
            try source.readNoEof(slice.second);
            dest.write_index = dest.mask2(dest.write_index + block_size);
            decode_state.written_count += block_size;
        },
        .rle => {
            const byte = try source.readByte();
            for (0..block_size) |_| {
                dest.writeAssumeCapacity(byte);
            }
            decode_state.written_count += block_size;
        },
        .compressed => {
            const literals = try decodeLiteralsSection(block_reader, literals_buffer);
            const sequences_header = try decodeSequencesHeader(block_reader);

            try decode_state.prepare(block_reader, literals, sequences_header);

            var bytes_written: usize = 0;
            {
                const size = try block_reader.readAll(sequence_buffer);
                var bit_stream: readers.ReverseBitReader = undefined;
                try bit_stream.init(sequence_buffer[0..size]);

                if (sequences_header.sequence_count > 0) {
                    if (sequence_buffer.len < block_reader_limited.bytes_left)
                        return error.SequenceBufferTooSmall;

                    decode_state.readInitialFseState(&bit_stream) catch
                        return error.MalformedCompressedBlock;

                    var sequence_size_limit = block_size_max;
                    for (0..sequences_header.sequence_count) |i| {
                        const decompressed_size = decode_state.decodeSequenceRingBuffer(
                            dest,
                            &bit_stream,
                            sequence_size_limit,
                            i == sequences_header.sequence_count - 1,
                        ) catch return error.MalformedCompressedBlock;
                        sequence_size_limit -= decompressed_size;
                        bytes_written += decompressed_size;
                    }
                }

                if (!bit_stream.isEmpty()) {
                    return error.MalformedCompressedBlock;
                }
            }

            if (decode_state.literal_written_count < literals.header.regenerated_size) {
                const len = literals.header.regenerated_size - decode_state.literal_written_count;
                decode_state.decodeLiteralsRingBuffer(dest, len) catch
                    return error.MalformedCompressedBlock;
                bytes_written += len;
            }

            switch (decode_state.literal_header.block_type) {
                .treeless, .compressed => {
                    if (!decode_state.isLiteralStreamEmpty()) return error.MalformedCompressedBlock;
                },
                .raw, .rle => {},
            }

            if (bytes_written > block_size_max) return error.BlockSizeOverMaximum;
            if (block_reader_limited.bytes_left != 0) return error.MalformedCompressedBlock;
            decode_state.literal_written_count = 0;
        },
        .reserved => return error.ReservedBlock,
    }
}

/// Decode the header of a block.
pub fn decodeBlockHeader(src: *const [3]u8) frame.Zstandard.Block.Header {
    const last_block = src[0] & 1 == 1;
    const block_type = @as(frame.Zstandard.Block.Type, @enumFromInt((src[0] & 0b110) >> 1));
    const block_size = ((src[0] & 0b11111000) >> 3) + (@as(u21, src[1]) << 5) + (@as(u21, src[2]) << 13);
    return .{
        .last_block = last_block,
        .block_type = block_type,
        .block_size = block_size,
    };
}

/// Decode the header of a block.
///
/// Errors returned:
///   - `error.EndOfStream` if `src.len < 3`
pub fn decodeBlockHeaderSlice(src: []const u8) error{EndOfStream}!frame.Zstandard.Block.Header {
    if (src.len < 3) return error.EndOfStream;
    return decodeBlockHeader(src[0..3]);
}

/// Decode a `LiteralsSection` from `src`, incrementing `consumed_count` by the
/// number of bytes the section uses.
///
/// Errors returned:
///   - `error.MalformedLiteralsHeader` if the header is invalid
///   - `error.MalformedLiteralsSection` if there are decoding errors
///   - `error.MalformedAccuracyLog` if compressed literals have invalid
///     accuracy
///   - `error.MalformedFseTable` if compressed literals have invalid FSE table
///   - `error.MalformedHuffmanTree` if there are errors decoding a Huffamn tree
///   - `error.EndOfStream` if there are not enough bytes in `src`
pub fn decodeLiteralsSectionSlice(
    src: []const u8,
    consumed_count: *usize,
) (error{ MalformedLiteralsHeader, MalformedLiteralsSection, EndOfStream } || huffman.Error)!LiteralsSection {
    var bytes_read: usize = 0;
    const header = header: {
        var fbs = std.io.fixedBufferStream(src);
        defer bytes_read = fbs.pos;
        break :header decodeLiteralsHeader(fbs.reader()) catch return error.MalformedLiteralsHeader;
    };
    switch (header.block_type) {
        .raw => {
            if (src.len < bytes_read + header.regenerated_size) return error.MalformedLiteralsSection;
            const stream = src[bytes_read..][0..header.regenerated_size];
            consumed_count.* += header.regenerated_size + bytes_read;
            return LiteralsSection{
                .header = header,
                .huffman_tree = null,
                .streams = .{ .one = stream },
            };
        },
        .rle => {
            if (src.len < bytes_read + 1) return error.MalformedLiteralsSection;
            const stream = src[bytes_read..][0..1];
            consumed_count.* += 1 + bytes_read;
            return LiteralsSection{
                .header = header,
                .huffman_tree = null,
                .streams = .{ .one = stream },
            };
        },
        .compressed, .treeless => {
            const huffman_tree_start = bytes_read;
            const huffman_tree = if (header.block_type == .compressed)
                try huffman.decodeHuffmanTreeSlice(src[bytes_read..], &bytes_read)
            else
                null;
            const huffman_tree_size = bytes_read - huffman_tree_start;
            const total_streams_size = std.math.sub(usize, header.compressed_size.?, huffman_tree_size) catch
                return error.MalformedLiteralsSection;

            if (src.len < bytes_read + total_streams_size) return error.MalformedLiteralsSection;
            const stream_data = src[bytes_read .. bytes_read + total_streams_size];

            const streams = try decodeStreams(header.size_format, stream_data);
            consumed_count.* += bytes_read + total_streams_size;
            return LiteralsSection{
                .header = header,
                .huffman_tree = huffman_tree,
                .streams = streams,
            };
        },
    }
}

/// Decode a `LiteralsSection` from `src`, incrementing `consumed_count` by the
/// number of bytes the section uses. See `decodeLiterasSectionSlice()`.
pub fn decodeLiteralsSection(
    source: anytype,
    buffer: []u8,
) !LiteralsSection {
    const header = try decodeLiteralsHeader(source);
    switch (header.block_type) {
        .raw => {
            if (buffer.len < header.regenerated_size) return error.LiteralsBufferTooSmall;
            try source.readNoEof(buffer[0..header.regenerated_size]);
            return LiteralsSection{
                .header = header,
                .huffman_tree = null,
                .streams = .{ .one = buffer },
            };
        },
        .rle => {
            buffer[0] = try source.readByte();
            return LiteralsSection{
                .header = header,
                .huffman_tree = null,
                .streams = .{ .one = buffer[0..1] },
            };
        },
        .compressed, .treeless => {
            var counting_reader = std.io.countingReader(source);
            const huffman_tree = if (header.block_type == .compressed)
                try huffman.decodeHuffmanTree(counting_reader.reader(), buffer)
            else
                null;
            const huffman_tree_size = @as(usize, @intCast(counting_reader.bytes_read));
            const total_streams_size = std.math.sub(usize, header.compressed_size.?, huffman_tree_size) catch
                return error.MalformedLiteralsSection;

            if (total_streams_size > buffer.len) return error.LiteralsBufferTooSmall;
            try source.readNoEof(buffer[0..total_streams_size]);
            const stream_data = buffer[0..total_streams_size];

            const streams = try decodeStreams(header.size_format, stream_data);
            return LiteralsSection{
                .header = header,
                .huffman_tree = huffman_tree,
                .streams = streams,
            };
        },
    }
}

fn decodeStreams(size_format: u2, stream_data: []const u8) !LiteralsSection.Streams {
    if (size_format == 0) {
        return .{ .one = stream_data };
    }

    if (stream_data.len < 6) return error.MalformedLiteralsSection;

    const stream_1_length: usize = std.mem.readInt(u16, stream_data[0..2], .little);
    const stream_2_length: usize = std.mem.readInt(u16, stream_data[2..4], .little);
    const stream_3_length: usize = std.mem.readInt(u16, stream_data[4..6], .little);

    const stream_1_start = 6;
    const stream_2_start = stream_1_start + stream_1_length;
    const stream_3_start = stream_2_start + stream_2_length;
    const stream_4_start = stream_3_start + stream_3_length;

    if (stream_data.len < stream_4_start) return error.MalformedLiteralsSection;

    return .{ .four = .{
        stream_data[stream_1_start .. stream_1_start + stream_1_length],
        stream_data[stream_2_start .. stream_2_start + stream_2_length],
        stream_data[stream_3_start .. stream_3_start + stream_3_length],
        stream_data[stream_4_start..],
    } };
}

/// Decode a literals section header.
///
/// Errors returned:
///   - `error.EndOfStream` if there are not enough bytes in `source`
pub fn decodeLiteralsHeader(source: anytype) !LiteralsSection.Header {
    const byte0 = try source.readByte();
    const block_type = @as(LiteralsSection.BlockType, @enumFromInt(byte0 & 0b11));
    const size_format = @as(u2, @intCast((byte0 & 0b1100) >> 2));
    var regenerated_size: u20 = undefined;
    var compressed_size: ?u18 = null;
    switch (block_type) {
        .raw, .rle => {
            switch (size_format) {
                0, 2 => {
                    regenerated_size = byte0 >> 3;
                },
                1 => regenerated_size = (byte0 >> 4) + (@as(u20, try source.readByte()) << 4),
                3 => regenerated_size = (byte0 >> 4) +
                    (@as(u20, try source.readByte()) << 4) +
                    (@as(u20, try source.readByte()) << 12),
            }
        },
        .compressed, .treeless => {
            const byte1 = try source.readByte();
            const byte2 = try source.readByte();
            switch (size_format) {
                0, 1 => {
                    regenerated_size = (byte0 >> 4) + ((@as(u20, byte1) & 0b00111111) << 4);
                    compressed_size = ((byte1 & 0b11000000) >> 6) + (@as(u18, byte2) << 2);
                },
                2 => {
                    const byte3 = try source.readByte();
                    regenerated_size = (byte0 >> 4) + (@as(u20, byte1) << 4) + ((@as(u20, byte2) & 0b00000011) << 12);
                    compressed_size = ((byte2 & 0b11111100) >> 2) + (@as(u18, byte3) << 6);
                },
                3 => {
                    const byte3 = try source.readByte();
                    const byte4 = try source.readByte();
                    regenerated_size = (byte0 >> 4) + (@as(u20, byte1) << 4) + ((@as(u20, byte2) & 0b00111111) << 12);
                    compressed_size = ((byte2 & 0b11000000) >> 6) + (@as(u18, byte3) << 2) + (@as(u18, byte4) << 10);
                },
            }
        },
    }
    return LiteralsSection.Header{
        .block_type = block_type,
        .size_format = size_format,
        .regenerated_size = regenerated_size,
        .compressed_size = compressed_size,
    };
}

/// Decode a sequences section header.
///
/// Errors returned:
///   - `error.ReservedBitSet` if the reserved bit is set
///   - `error.EndOfStream` if there are not enough bytes in `source`
pub fn decodeSequencesHeader(
    source: anytype,
) !SequencesSection.Header {
    var sequence_count: u24 = undefined;

    const byte0 = try source.readByte();
    if (byte0 == 0) {
        return SequencesSection.Header{
            .sequence_count = 0,
            .offsets = undefined,
            .match_lengths = undefined,
            .literal_lengths = undefined,
        };
    } else if (byte0 < 128) {
        sequence_count = byte0;
    } else if (byte0 < 255) {
        sequence_count = (@as(u24, (byte0 - 128)) << 8) + try source.readByte();
    } else {
        sequence_count = (try source.readByte()) + (@as(u24, try source.readByte()) << 8) + 0x7F00;
    }

    const compression_modes = try source.readByte();

    const matches_mode = @as(SequencesSection.Header.Mode, @enumFromInt((compression_modes & 0b00001100) >> 2));
    const offsets_mode = @as(SequencesSection.Header.Mode, @enumFromInt((compression_modes & 0b00110000) >> 4));
    const literal_mode = @as(SequencesSection.Header.Mode, @enumFromInt((compression_modes & 0b11000000) >> 6));
    if (compression_modes & 0b11 != 0) return error.ReservedBitSet;

    return SequencesSection.Header{
        .sequence_count = sequence_count,
        .offsets = offsets_mode,
        .match_lengths = matches_mode,
        .literal_lengths = literal_mode,
    };
}
const std = @import("std");
const assert = std.debug.assert;

const types = @import("../types.zig");
const Table = types.compressed_block.Table;

pub fn decodeFseTable(
    bit_reader: anytype,
    expected_symbol_count: usize,
    max_accuracy_log: u4,
    entries: []Table.Fse,
) !usize {
    const accuracy_log_biased = try bit_reader.readBitsNoEof(u4, 4);
    if (accuracy_log_biased > max_accuracy_log -| 5) return error.MalformedAccuracyLog;
    const accuracy_log = accuracy_log_biased + 5;

    var values: [256]u16 = undefined;
    var value_count: usize = 0;

    const total_probability = @as(u16, 1) << accuracy_log;
    var accumulated_probability: u16 = 0;

    while (accumulated_probability < total_probability) {
        // WARNING: The RFC is poorly worded, and would suggest std.math.log2_int_ceil is correct here,
        //          but power of two (remaining probabilities + 1) need max bits set to 1 more.
        const max_bits = std.math.log2_int(u16, total_probability - accumulated_probability + 1) + 1;
        const small = try bit_reader.readBitsNoEof(u16, max_bits - 1);

        const cutoff = (@as(u16, 1) << max_bits) - 1 - (total_probability - accumulated_probability + 1);

        const value = if (small < cutoff)
            small
        else value: {
            const value_read = small + (try bit_reader.readBitsNoEof(u16, 1) << (max_bits - 1));
            break :value if (value_read < @as(u16, 1) << (max_bits - 1))
                value_read
            else
                value_read - cutoff;
        };

        accumulated_probability += if (value != 0) value - 1 else 1;

        values[value_count] = value;
        value_count += 1;

        if (value == 1) {
            while (true) {
                const repeat_flag = try bit_reader.readBitsNoEof(u2, 2);
                if (repeat_flag + value_count > 256) return error.MalformedFseTable;
                for (0..repeat_flag) |_| {
                    values[value_count] = 1;
                    value_count += 1;
                }
                if (repeat_flag < 3) break;
            }
        }
        if (value_count == 256) break;
    }
    bit_reader.alignToByte();

    if (value_count < 2) return error.MalformedFseTable;
    if (accumulated_probability != total_probability) return error.MalformedFseTable;
    if (value_count > expected_symbol_count) return error.MalformedFseTable;

    const table_size = total_probability;

    try buildFseTable(values[0..value_count], entries[0..table_size]);
    return table_size;
}

fn buildFseTable(values: []const u16, entries: []Table.Fse) !void {
    const total_probability = @as(u16, @intCast(entries.len));
    const accuracy_log = std.math.log2_int(u16, total_probability);
    assert(total_probability <= 1 << 9);

    var less_than_one_count: usize = 0;
    for (values, 0..) |value, i| {
        if (value == 0) {
            entries[entries.len - 1 - less_than_one_count] = Table.Fse{
                .symbol = @as(u8, @intCast(i)),
                .baseline = 0,
                .bits = accuracy_log,
            };
            less_than_one_count += 1;
        }
    }

    var position: usize = 0;
    var temp_states: [1 << 9]u16 = undefined;
    for (values, 0..) |value, symbol| {
        if (value == 0 or value == 1) continue;
        const probability = value - 1;

        const state_share_dividend = std.math.ceilPowerOfTwo(u16, probability) catch
            return error.MalformedFseTable;
        const share_size = @divExact(total_probability, state_share_dividend);
        const double_state_count = state_share_dividend - probability;
        const single_state_count = probability - double_state_count;
        const share_size_log = std.math.log2_int(u16, share_size);

        for (0..probability) |i| {
            temp_states[i] = @as(u16, @intCast(position));
            position += (entries.len >> 1) + (entries.len >> 3) + 3;
            position &= entries.len - 1;
            while (position >= entries.len - less_than_one_count) {
                position += (entries.len >> 1) + (entries.len >> 3) + 3;
                position &= entries.len - 1;
            }
        }
        std.mem.sort(u16, temp_states[0..probability], {}, std.sort.asc(u16));
        for (0..probability) |i| {
            entries[temp_states[i]] = if (i < double_state_count) Table.Fse{
                .symbol = @as(u8, @intCast(symbol)),
                .bits = share_size_log + 1,
                .baseline = single_state_count * share_size + @as(u16, @intCast(i)) * 2 * share_size,
            } else Table.Fse{
                .symbol = @as(u8, @intCast(symbol)),
                .bits = share_size_log,
                .baseline = (@as(u16, @intCast(i)) - double_state_count) * share_size,
            };
        }
    }
}

test buildFseTable {
    const literals_length_default_values = [36]u16{
        5, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 3, 2, 2, 2, 2, 2,
        0, 0, 0, 0,
    };

    const match_lengths_default_values = [53]u16{
        2, 5, 4, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0,
        0, 0, 0, 0, 0,
    };

    const offset_codes_default_values = [29]u16{
        2, 2, 2, 2, 2, 2, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0,
    };

    var entries: [64]Table.Fse = undefined;
    try buildFseTable(&literals_length_default_values, &entries);
    try std.testing.expectEqualSlices(Table.Fse, types.compressed_block.predefined_literal_fse_table.fse, &entries);

    try buildFseTable(&match_lengths_default_values, &entries);
    try std.testing.expectEqualSlices(Table.Fse, types.compressed_block.predefined_match_fse_table.fse, &entries);

    try buildFseTable(&offset_codes_default_values, entries[0..32]);
    try std.testing.expectEqualSlices(Table.Fse, types.compressed_block.predefined_offset_fse_table.fse, entries[0..32]);
}
const std = @import("std");

const types = @import("../types.zig");
const LiteralsSection = types.compressed_block.LiteralsSection;
const Table = types.compressed_block.Table;

const readers = @import("../readers.zig");

const decodeFseTable = @import("fse.zig").decodeFseTable;

pub const Error = error{
    MalformedHuffmanTree,
    MalformedFseTable,
    MalformedAccuracyLog,
    EndOfStream,
};

fn decodeFseHuffmanTree(
    source: anytype,
    compressed_size: usize,
    buffer: []u8,
    weights: *[256]u4,
) !usize {
    var stream = std.io.limitedReader(source, compressed_size);
    var bit_reader = readers.bitReader(stream.reader());

    var entries: [1 << 6]Table.Fse = undefined;
    const table_size = decodeFseTable(&bit_reader, 256, 6, &entries) catch |err| switch (err) {
        error.MalformedAccuracyLog, error.MalformedFseTable => |e| return e,
        error.EndOfStream => return error.MalformedFseTable,
        else => |e| return e,
    };
    const accuracy_log = std.math.log2_int_ceil(usize, table_size);

    const amount = try stream.reader().readAll(buffer);
    var huff_bits: readers.ReverseBitReader = undefined;
    huff_bits.init(buffer[0..amount]) catch return error.MalformedHuffmanTree;

    return assignWeights(&huff_bits, accuracy_log, &entries, weights);
}

fn decodeFseHuffmanTreeSlice(src: []const u8, compressed_size: usize, weights: *[256]u4) !usize {
    if (src.len < compressed_size) return error.MalformedHuffmanTree;
    var stream = std.io.fixedBufferStream(src[0..compressed_size]);
    var counting_reader = std.io.countingReader(stream.reader());
    var bit_reader = readers.bitReader(counting_reader.reader());

    var entries: [1 << 6]Table.Fse = undefined;
    const table_size = decodeFseTable(&bit_reader, 256, 6, &entries) catch |err| switch (err) {
        error.MalformedAccuracyLog, error.MalformedFseTable => |e| return e,
        error.EndOfStream => return error.MalformedFseTable,
    };
    const accuracy_log = std.math.log2_int_ceil(usize, table_size);

    const start_index = std.math.cast(usize, counting_reader.bytes_read) orelse
        return error.MalformedHuffmanTree;
    const huff_data = src[start_index..compressed_size];
    var huff_bits: readers.ReverseBitReader = undefined;
    huff_bits.init(huff_data) catch return error.MalformedHuffmanTree;

    return assignWeights(&huff_bits, accuracy_log, &entries, weights);
}

fn assignWeights(
    huff_bits: *readers.ReverseBitReader,
    accuracy_log: u16,
    entries: *[1 << 6]Table.Fse,
    weights: *[256]u4,
) !usize {
    var i: usize = 0;
    var even_state: u32 = huff_bits.readBitsNoEof(u32, accuracy_log) catch return error.MalformedHuffmanTree;
    var odd_state: u32 = huff_bits.readBitsNoEof(u32, accuracy_log) catch return error.MalformedHuffmanTree;

    while (i < 254) {
        const even_data = entries[even_state];
        var read_bits: u16 = 0;
        const even_bits = huff_bits.readBits(u32, even_data.bits, &read_bits) catch unreachable;
        weights[i] = std.math.cast(u4, even_data.symbol) orelse return error.MalformedHuffmanTree;
        i += 1;
        if (read_bits < even_data.bits) {
            weights[i] = std.math.cast(u4, entries[odd_state].symbol) orelse return error.MalformedHuffmanTree;
            i += 1;
            break;
        }
        even_state = even_data.baseline + even_bits;

        read_bits = 0;
        const odd_data = entries[odd_state];
        const odd_bits = huff_bits.readBits(u32, odd_data.bits, &read_bits) catch unreachable;
        weights[i] = std.math.cast(u4, odd_data.symbol) orelse return error.MalformedHuffmanTree;
        i += 1;
        if (read_bits < odd_data.bits) {
            if (i == 255) return error.MalformedHuffmanTree;
            weights[i] = std.math.cast(u4, entries[even_state].symbol) orelse return error.MalformedHuffmanTree;
            i += 1;
            break;
        }
        odd_state = odd_data.baseline + odd_bits;
    } else return error.MalformedHuffmanTree;

    if (!huff_bits.isEmpty()) {
        return error.MalformedHuffmanTree;
    }

    return i + 1; // stream contains all but the last symbol
}

fn decodeDirectHuffmanTree(source: anytype, encoded_symbol_count: usize, weights: *[256]u4) !usize {
    const weights_byte_count = (encoded_symbol_count + 1) / 2;
    for (0..weights_byte_count) |i| {
        const byte = try source.readByte();
        weights[2 * i] = @as(u4, @intCast(byte >> 4));
        weights[2 * i + 1] = @as(u4, @intCast(byte & 0xF));
    }
    return encoded_symbol_count + 1;
}

fn assignSymbols(weight_sorted_prefixed_symbols: []LiteralsSection.HuffmanTree.PrefixedSymbol, weights: [256]u4) usize {
    for (0..weight_sorted_prefixed_symbols.len) |i| {
        weight_sorted_prefixed_symbols[i] = .{
            .symbol = @as(u8, @intCast(i)),
            .weight = undefined,
            .prefix = undefined,
        };
    }

    std.mem.sort(
        LiteralsSection.HuffmanTree.PrefixedSymbol,
        weight_sorted_prefixed_symbols,
        weights,
        lessThanByWeight,
    );

    var prefix: u16 = 0;
    var prefixed_symbol_count: usize = 0;
    var sorted_index: usize = 0;
    const symbol_count = weight_sorted_prefixed_symbols.len;
    while (sorted_index < symbol_count) {
        var symbol = weight_sorted_prefixed_symbols[sorted_index].symbol;
        const weight = weights[symbol];
        if (weight == 0) {
            sorted_index += 1;
            continue;
        }

        while (sorted_index < symbol_count) : ({
            sorted_index += 1;
            prefixed_symbol_count += 1;
            prefix += 1;
        }) {
            symbol = weight_sorted_prefixed_symbols[sorted_index].symbol;
            if (weights[symbol] != weight) {
                prefix = ((prefix - 1) >> (weights[symbol] - weight)) + 1;
                break;
            }
            weight_sorted_prefixed_symbols[prefixed_symbol_count].symbol = symbol;
            weight_sorted_prefixed_symbols[prefixed_symbol_count].prefix = prefix;
            weight_sorted_prefixed_symbols[prefixed_symbol_count].weight = weight;
        }
    }
    return prefixed_symbol_count;
}

fn buildHuffmanTree(weights: *[256]u4, symbol_count: usize) error{MalformedHuffmanTree}!LiteralsSection.HuffmanTree {
    var weight_power_sum_big: u32 = 0;
    for (weights[0 .. symbol_count - 1]) |value| {
        weight_power_sum_big += (@as(u16, 1) << value) >> 1;
    }
    if (weight_power_sum_big >= 1 << 11) return error.MalformedHuffmanTree;
    const weight_power_sum = @as(u16, @intCast(weight_power_sum_big));

    // advance to next power of two (even if weight_power_sum is a power of 2)
    // TODO: is it valid to have weight_power_sum == 0?
    const max_number_of_bits = if (weight_power_sum == 0) 1 else std.math.log2_int(u16, weight_power_sum) + 1;
    const next_power_of_two = @as(u16, 1) << max_number_of_bits;
    weights[symbol_count - 1] = std.math.log2_int(u16, next_power_of_two - weight_power_sum) + 1;

    var weight_sorted_prefixed_symbols: [256]LiteralsSection.HuffmanTree.PrefixedSymbol = undefined;
    const prefixed_symbol_count = assignSymbols(weight_sorted_prefixed_symbols[0..symbol_count], weights.*);
    const tree = LiteralsSection.HuffmanTree{
        .max_bit_count = max_number_of_bits,
        .symbol_count_minus_one = @as(u8, @intCast(prefixed_symbol_count - 1)),
        .nodes = weight_sorted_prefixed_symbols,
    };
    return tree;
}

pub fn decodeHuffmanTree(
    source: anytype,
    buffer: []u8,
) (@TypeOf(source).Error || Error)!LiteralsSection.HuffmanTree {
    const header = try source.readByte();
    var weights: [256]u4 = undefined;
    const symbol_count = if (header < 128)
        // FSE compressed weights
        try decodeFseHuffmanTree(source, header, buffer, &weights)
    else
        try decodeDirectHuffmanTree(source, header - 127, &weights);

    return buildHuffmanTree(&weights, symbol_count);
}

pub fn decodeHuffmanTreeSlice(
    src: []const u8,
    consumed_count: *usize,
) Error!LiteralsSection.HuffmanTree {
    if (src.len == 0) return error.MalformedHuffmanTree;
    const header = src[0];
    var bytes_read: usize = 1;
    var weights: [256]u4 = undefined;
    const symbol_count = if (header < 128) count: {
        // FSE compressed weights
        bytes_read += header;
        break :count try decodeFseHuffmanTreeSlice(src[1..], header, &weights);
    } else count: {
        var fbs = std.io.fixedBufferStream(src[1..]);
        defer bytes_read += fbs.pos;
        break :count try decodeDirectHuffmanTree(fbs.reader(), header - 127, &weights);
    };

    consumed_count.* += bytes_read;
    return buildHuffmanTree(&weights, symbol_count);
}

fn lessThanByWeight(
    weights: [256]u4,
    lhs: LiteralsSection.HuffmanTree.PrefixedSymbol,
    rhs: LiteralsSection.HuffmanTree.PrefixedSymbol,
) bool {
    // NOTE: this function relies on the use of a stable sorting algorithm,
    //       otherwise a special case of if (weights[lhs] == weights[rhs]) return lhs < rhs;
    //       should be added
    return weights[lhs.symbol] < weights[rhs.symbol];
}
const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const RingBuffer = std.RingBuffer;

const types = @import("types.zig");
const frame = types.frame;
const LiteralsSection = types.compressed_block.LiteralsSection;
const SequencesSection = types.compressed_block.SequencesSection;
const SkippableHeader = types.frame.Skippable.Header;
const ZstandardHeader = types.frame.Zstandard.Header;
const Table = types.compressed_block.Table;

pub const block = @import("decode/block.zig");

const readers = @import("readers.zig");

/// Returns `true` is `magic` is a valid magic number for a skippable frame
pub fn isSkippableMagic(magic: u32) bool {
    return frame.Skippable.magic_number_min <= magic and magic <= frame.Skippable.magic_number_max;
}

/// Returns the kind of frame at the beginning of `source`.
///
/// Errors returned:
///   - `error.BadMagic` if `source` begins with bytes not equal to the
///     Zstandard frame magic number, or outside the range of magic numbers for
///     skippable frames.
///   - `error.EndOfStream` if `source` contains fewer than 4 bytes
pub fn decodeFrameType(source: anytype) error{ BadMagic, EndOfStream }!frame.Kind {
    const magic = try source.readInt(u32, .little);
    return frameType(magic);
}

/// Returns the kind of frame associated to `magic`.
///
/// Errors returned:
///   - `error.BadMagic` if `magic` is not a valid magic number.
pub fn frameType(magic: u32) error{BadMagic}!frame.Kind {
    return if (magic == frame.Zstandard.magic_number)
        .zstandard
    else if (isSkippableMagic(magic))
        .skippable
    else
        error.BadMagic;
}

pub const FrameHeader = union(enum) {
    zstandard: ZstandardHeader,
    skippable: SkippableHeader,
};

pub const HeaderError = error{ BadMagic, EndOfStream, ReservedBitSet };

/// Returns the header of the frame at the beginning of `source`.
///
/// Errors returned:
///   - `error.BadMagic` if `source` begins with bytes not equal to the
///     Zstandard frame magic number, or outside the range of magic numbers for
///     skippable frames.
///   - `error.EndOfStream` if `source` contains fewer than 4 bytes
///   - `error.ReservedBitSet` if the frame is a Zstandard frame and any of the
///     reserved bits are set
pub fn decodeFrameHeader(source: anytype) (@TypeOf(source).Error || HeaderError)!FrameHeader {
    const magic = try source.readInt(u32, .little);
    const frame_type = try frameType(magic);
    switch (frame_type) {
        .zstandard => return FrameHeader{ .zstandard = try decodeZstandardHeader(source) },
        .skippable => return FrameHeader{
            .skippable = .{
                .magic_number = magic,
                .frame_size = try source.readInt(u32, .little),
            },
        },
    }
}

pub const ReadWriteCount = struct {
    read_count: usize,
    write_count: usize,
};

/// Decodes frames from `src` into `dest`; returns the length of the result.
/// The stream should not have extra trailing bytes - either all bytes in `src`
/// will be decoded, or an error will be returned. An error will be returned if
/// a Zstandard frame in `src` does not declare its content size.
///
/// Errors returned:
///   - `error.DictionaryIdFlagUnsupported` if a `src` contains a frame that
///     uses a dictionary
///   - `error.MalformedFrame` if a frame in `src` is invalid
///   - `error.UnknownContentSizeUnsupported` if a frame in `src` does not
///     declare its content size
pub fn decode(dest: []u8, src: []const u8, verify_checksum: bool) error{
    MalformedFrame,
    UnknownContentSizeUnsupported,
    DictionaryIdFlagUnsupported,
}!usize {
    var write_count: usize = 0;
    var read_count: usize = 0;
    while (read_count < src.len) {
        const counts = decodeFrame(dest, src[read_count..], verify_checksum) catch |err| {
            switch (err) {
                error.UnknownContentSizeUnsupported => return error.UnknownContentSizeUnsupported,
                error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
                else => return error.MalformedFrame,
            }
        };
        read_count += counts.read_count;
        write_count += counts.write_count;
    }
    return write_count;
}

/// Decodes a stream of frames from `src`; returns the decoded bytes. The stream
/// should not have extra trailing bytes - either all bytes in `src` will be
/// decoded, or an error will be returned.
///
/// Errors returned:
///   - `error.DictionaryIdFlagUnsupported` if a `src` contains a frame that
///     uses a dictionary
///   - `error.MalformedFrame` if a frame in `src` is invalid
///   - `error.OutOfMemory` if `allocator` cannot allocate enough memory
pub fn decodeAlloc(
    allocator: Allocator,
    src: []const u8,
    verify_checksum: bool,
    window_size_max: usize,
) error{ DictionaryIdFlagUnsupported, MalformedFrame, OutOfMemory }![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var read_count: usize = 0;
    while (read_count < src.len) {
        read_count += decodeFrameArrayList(
            allocator,
            &result,
            src[read_count..],
            verify_checksum,
            window_size_max,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
            else => return error.MalformedFrame,
        };
    }
    return result.toOwnedSlice();
}

/// Decodes the frame at the start of `src` into `dest`. Returns the number of
/// bytes read from `src` and written to `dest`. This function can only decode
/// frames that declare the decompressed content size.
///
/// Errors returned:
///   - `error.BadMagic` if the first 4 bytes of `src` is not a valid magic
///     number for a Zstandard or skippable frame
///   - `error.UnknownContentSizeUnsupported` if the frame does not declare the
///     uncompressed content size
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.ContentTooLarge` if `dest` is smaller than the uncompressed data
///     size declared by the frame header
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.maxInt(usize)`
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if any of the reserved bits of the frame header
///     are set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the actual size of decompressed data
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.SkippableSizeTooLarge` if the frame is skippable and reports a
///     size greater than `src.len`
pub fn decodeFrame(
    dest: []u8,
    src: []const u8,
    verify_checksum: bool,
) (error{
    BadMagic,
    UnknownContentSizeUnsupported,
    ContentTooLarge,
    ContentSizeTooLarge,
    WindowSizeUnknown,
    DictionaryIdFlagUnsupported,
    SkippableSizeTooLarge,
} || FrameError)!ReadWriteCount {
    var fbs = std.io.fixedBufferStream(src);
    switch (try decodeFrameType(fbs.reader())) {
        .zstandard => return decodeZstandardFrame(dest, src, verify_checksum),
        .skippable => {
            const content_size = try fbs.reader().readInt(u32, .little);
            if (content_size > std.math.maxInt(usize) - 8) return error.SkippableSizeTooLarge;
            const read_count = @as(usize, content_size) + 8;
            if (read_count > src.len) return error.SkippableSizeTooLarge;
            return ReadWriteCount{
                .read_count = read_count,
                .write_count = 0,
            };
        },
    }
}

/// Decodes the frame at the start of `src` into `dest`. Returns the number of
/// bytes read from `src`.
///
/// Errors returned:
///   - `error.BadMagic` if the first 4 bytes of `src` is not a valid magic
///     number for a Zstandard or skippable frame
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.WindowTooLarge` if the window size is larger than
///     `window_size_max`
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.maxInt(usize)`
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if any of the reserved bits of the frame header
///     are set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the actual size of decompressed data
///   - `error.OutOfMemory` if `allocator` cannot allocate enough memory
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.SkippableSizeTooLarge` if the frame is skippable and reports a
///     size greater than `src.len`
pub fn decodeFrameArrayList(
    allocator: Allocator,
    dest: *std.ArrayList(u8),
    src: []const u8,
    verify_checksum: bool,
    window_size_max: usize,
) (error{ BadMagic, OutOfMemory, SkippableSizeTooLarge } || FrameContext.Error || FrameError)!usize {
    var fbs = std.io.fixedBufferStream(src);
    const reader = fbs.reader();
    const magic = try reader.readInt(u32, .little);
    switch (try frameType(magic)) {
        .zstandard => return decodeZstandardFrameArrayList(
            allocator,
            dest,
            src,
            verify_checksum,
            window_size_max,
        ),
        .skippable => {
            const content_size = try fbs.reader().readInt(u32, .little);
            if (content_size > std.math.maxInt(usize) - 8) return error.SkippableSizeTooLarge;
            const read_count = @as(usize, content_size) + 8;
            if (read_count > src.len) return error.SkippableSizeTooLarge;
            return read_count;
        },
    }
}

/// Returns the frame checksum corresponding to the data fed into `hasher`
pub fn computeChecksum(hasher: *std.hash.XxHash64) u32 {
    const hash = hasher.final();
    return @as(u32, @intCast(hash & 0xFFFFFFFF));
}

const FrameError = error{
    ChecksumFailure,
    BadContentSize,
    EndOfStream,
    ReservedBitSet,
} || block.Error;

/// Decode a Zstandard frame from `src` into `dest`, returning the number of
/// bytes read from `src` and written to `dest`. The first four bytes of `src`
/// must be the magic number for a Zstandard frame.
///
/// Error returned:
///   - `error.UnknownContentSizeUnsupported` if the frame does not declare the
///     uncompressed content size
///   - `error.ContentTooLarge` if `dest` is smaller than the uncompressed data
///     size declared by the frame header
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.maxInt(usize)`
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if the reserved bit of the frame header is set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the actual size of decompressed data
pub fn decodeZstandardFrame(
    dest: []u8,
    src: []const u8,
    verify_checksum: bool,
) (error{
    UnknownContentSizeUnsupported,
    ContentTooLarge,
    ContentSizeTooLarge,
    WindowSizeUnknown,
    DictionaryIdFlagUnsupported,
} || FrameError)!ReadWriteCount {
    assert(std.mem.readInt(u32, src[0..4], .little) == frame.Zstandard.magic_number);
    var consumed_count: usize = 4;

    var frame_context = context: {
        var fbs = std.io.fixedBufferStream(src[consumed_count..]);
        const source = fbs.reader();
        const frame_header = try decodeZstandardHeader(source);
        consumed_count += fbs.pos;
        break :context FrameContext.init(
            frame_header,
            std.math.maxInt(usize),
            verify_checksum,
        ) catch |err| switch (err) {
            error.WindowTooLarge => unreachable,
            inline else => |e| return e,
        };
    };
    const counts = try decodeZStandardFrameBlocks(
        dest,
        src[consumed_count..],
        &frame_context,
    );
    return ReadWriteCount{
        .read_count = counts.read_count + consumed_count,
        .write_count = counts.write_count,
    };
}

pub fn decodeZStandardFrameBlocks(
    dest: []u8,
    src: []const u8,
    frame_context: *FrameContext,
) (error{ ContentTooLarge, UnknownContentSizeUnsupported } || FrameError)!ReadWriteCount {
    const content_size = frame_context.content_size orelse
        return error.UnknownContentSizeUnsupported;
    if (dest.len < content_size) return error.ContentTooLarge;

    var consumed_count: usize = 0;
    const written_count = decodeFrameBlocksInner(
        dest[0..content_size],
        src[consumed_count..],
        &consumed_count,
        if (frame_context.hasher_opt) |*hasher| hasher else null,
        frame_context.block_size_max,
    ) catch |err| switch (err) {
        error.DestTooSmall => return error.BadContentSize,
        inline else => |e| return e,
    };

    if (written_count != content_size) return error.BadContentSize;
    if (frame_context.has_checksum) {
        if (src.len < consumed_count + 4) return error.EndOfStream;
        const checksum = std.mem.readInt(u32, src[consumed_count..][0..4], .little);
        consumed_count += 4;
        if (frame_context.hasher_opt) |*hasher| {
            if (checksum != computeChecksum(hasher)) return error.ChecksumFailure;
        }
    }
    return ReadWriteCount{ .read_count = consumed_count, .write_count = written_count };
}

pub const FrameContext = struct {
    hasher_opt: ?std.hash.XxHash64,
    window_size: usize,
    has_checksum: bool,
    block_size_max: usize,
    content_size: ?usize,

    const Error = error{
        DictionaryIdFlagUnsupported,
        WindowSizeUnknown,
        WindowTooLarge,
        ContentSizeTooLarge,
    };
    /// Validates `frame_header` and returns the associated `FrameContext`.
    ///
    /// Errors returned:
    ///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
    ///   - `error.WindowSizeUnknown` if the frame does not have a valid window
    ///     size
    ///   - `error.WindowTooLarge` if the window size is larger than
    ///     `window_size_max` or `std.math.intMax(usize)`
    ///   - `error.ContentSizeTooLarge` if the frame header indicates a content
    ///     size larger than `std.math.maxInt(usize)`
    pub fn init(
        frame_header: ZstandardHeader,
        window_size_max: usize,
        verify_checksum: bool,
    ) Error!FrameContext {
        if (frame_header.descriptor.dictionary_id_flag != 0)
            return error.DictionaryIdFlagUnsupported;

        const window_size_raw = frameWindowSize(frame_header) orelse return error.WindowSizeUnknown;
        const window_size = if (window_size_raw > window_size_max)
            return error.WindowTooLarge
        else
            std.math.cast(usize, window_size_raw) orelse return error.WindowTooLarge;

        const should_compute_checksum =
            frame_header.descriptor.content_checksum_flag and verify_checksum;

        const content_size = if (frame_header.content_size) |size|
            std.math.cast(usize, size) orelse return error.ContentSizeTooLarge
        else
            null;

        return .{
            .hasher_opt = if (should_compute_checksum) std.hash.XxHash64.init(0) else null,
            .window_size = window_size,
            .has_checksum = frame_header.descriptor.content_checksum_flag,
            .block_size_max = @min(types.block_size_max, window_size),
            .content_size = content_size,
        };
    }
};

/// Decode a Zstandard from from `src` and return number of bytes read; see
/// `decodeZstandardFrame()`. The first four bytes of `src` must be the magic
/// number for a Zstandard frame.
///
/// Errors returned:
///   - `error.WindowSizeUnknown` if the frame does not have a valid window size
///   - `error.WindowTooLarge` if the window size is larger than
///     `window_size_max`
///   - `error.DictionaryIdFlagUnsupported` if the frame uses a dictionary
///   - `error.ContentSizeTooLarge` if the frame header indicates a content size
///     that is larger than `std.math.maxInt(usize)`
///   - `error.ChecksumFailure` if `verify_checksum` is true and the frame
///     contains a checksum that does not match the checksum of the decompressed
///     data
///   - `error.ReservedBitSet` if the reserved bit of the frame header is set
///   - `error.EndOfStream` if `src` does not contain a complete frame
///   - `error.OutOfMemory` if `allocator` cannot allocate enough memory
///   - an error in `block.Error` if there are errors decoding a block
///   - `error.BadContentSize` if the content size declared by the frame does
///     not equal the size of decompressed data
pub fn decodeZstandardFrameArrayList(
    allocator: Allocator,
    dest: *std.ArrayList(u8),
    src: []const u8,
    verify_checksum: bool,
    window_size_max: usize,
) (error{OutOfMemory} || FrameContext.Error || FrameError)!usize {
    assert(std.mem.readInt(u32, src[0..4], .little) == frame.Zstandard.magic_number);
    var consumed_count: usize = 4;

    var frame_context = context: {
        var fbs = std.io.fixedBufferStream(src[consumed_count..]);
        const source = fbs.reader();
        const frame_header = try decodeZstandardHeader(source);
        consumed_count += fbs.pos;
        break :context try FrameContext.init(frame_header, window_size_max, verify_checksum);
    };

    consumed_count += try decodeZstandardFrameBlocksArrayList(
        allocator,
        dest,
        src[consumed_count..],
        &frame_context,
    );
    return consumed_count;
}

pub fn decodeZstandardFrameBlocksArrayList(
    allocator: Allocator,
    dest: *std.ArrayList(u8),
    src: []const u8,
    frame_context: *FrameContext,
) (error{OutOfMemory} || FrameError)!usize {
    const initial_len = dest.items.len;

    var ring_buffer = try RingBuffer.init(allocator, frame_context.window_size);
    defer ring_buffer.deinit(allocator);

    // These tables take 7680 bytes
    var literal_fse_data: [types.compressed_block.table_size_max.literal]Table.Fse = undefined;
    var match_fse_data: [types.compressed_block.table_size_max.match]Table.Fse = undefined;
    var offset_fse_data: [types.compressed_block.table_size_max.offset]Table.Fse = undefined;

    var block_header = try block.decodeBlockHeaderSlice(src);
    var consumed_count: usize = 3;
    var decode_state = block.DecodeState.init(&literal_fse_data, &match_fse_data, &offset_fse_data);
    while (true) : ({
        block_header = try block.decodeBlockHeaderSlice(src[consumed_count..]);
        consumed_count += 3;
    }) {
        const written_size = try block.decodeBlockRingBuffer(
            &ring_buffer,
            src[consumed_count..],
            block_header,
            &decode_state,
            &consumed_count,
            frame_context.block_size_max,
        );
        if (frame_context.content_size) |size| {
            if (dest.items.len - initial_len > size) {
                return error.BadContentSize;
            }
        }
        if (written_size > 0) {
            const written_slice = ring_buffer.sliceLast(written_size);
            try dest.appendSlice(written_slice.first);
            try dest.appendSlice(written_slice.second);
            if (frame_context.hasher_opt) |*hasher| {
                hasher.update(written_slice.first);
                hasher.update(written_slice.second);
            }
        }
        if (block_header.last_block) break;
    }
    if (frame_context.content_size) |size| {
        if (dest.items.len - initial_len != size) {
            return error.BadContentSize;
        }
    }

    if (frame_context.has_checksum) {
        if (src.len < consumed_count + 4) return error.EndOfStream;
        const checksum = std.mem.readInt(u32, src[consumed_count..][0..4], .little);
        consumed_count += 4;
        if (frame_context.hasher_opt) |*hasher| {
            if (checksum != computeChecksum(hasher)) return error.ChecksumFailure;
        }
    }
    return consumed_count;
}

fn decodeFrameBlocksInner(
    dest: []u8,
    src: []const u8,
    consumed_count: *usize,
    hash: ?*std.hash.XxHash64,
    block_size_max: usize,
) (error{ EndOfStream, DestTooSmall } || block.Error)!usize {
    // These tables take 7680 bytes
    var literal_fse_data: [types.compressed_block.table_size_max.literal]Table.Fse = undefined;
    var match_fse_data: [types.compressed_block.table_size_max.match]Table.Fse = undefined;
    var offset_fse_data: [types.compressed_block.table_size_max.offset]Table.Fse = undefined;

    var block_header = try block.decodeBlockHeaderSlice(src);
    var bytes_read: usize = 3;
    defer consumed_count.* += bytes_read;
    var decode_state = block.DecodeState.init(&literal_fse_data, &match_fse_data, &offset_fse_data);
    var count: usize = 0;
    while (true) : ({
        block_header = try block.decodeBlockHeaderSlice(src[bytes_read..]);
        bytes_read += 3;
    }) {
        const written_size = try block.decodeBlock(
            dest,
            src[bytes_read..],
            block_header,
            &decode_state,
            &bytes_read,
            block_size_max,
            count,
        );
        if (hash) |hash_state| hash_state.update(dest[count .. count + written_size]);
        count += written_size;
        if (block_header.last_block) break;
    }
    return count;
}

/// Decode the header of a skippable frame. The first four bytes of `src` must
/// be a valid magic number for a skippable frame.
pub fn decodeSkippableHeader(src: *const [8]u8) SkippableHeader {
    const magic = std.mem.readInt(u32, src[0..4], .little);
    assert(isSkippableMagic(magic));
    const frame_size = std.mem.readInt(u32, src[4..8], .little);
    return .{
        .magic_number = magic,
        .frame_size = frame_size,
    };
}

/// Returns the window size required to decompress a frame, or `null` if it
/// cannot be determined (which indicates a malformed frame header).
pub fn frameWindowSize(header: ZstandardHeader) ?u64 {
    if (header.window_descriptor) |descriptor| {
        const exponent = (descriptor & 0b11111000) >> 3;
        const mantissa = descriptor & 0b00000111;
        const window_log = 10 + exponent;
        const window_base = @as(u64, 1) << @as(u6, @intCast(window_log));
        const window_add = (window_base / 8) * mantissa;
        return window_base + window_add;
    } else return header.content_size;
}

/// Decode the header of a Zstandard frame.
///
/// Errors returned:
///   - `error.ReservedBitSet` if any of the reserved bits of the header are set
///   - `error.EndOfStream` if `source` does not contain a complete header
pub fn decodeZstandardHeader(
    source: anytype,
) (@TypeOf(source).Error || error{ EndOfStream, ReservedBitSet })!ZstandardHeader {
    const descriptor = @as(ZstandardHeader.Descriptor, @bitCast(try source.readByte()));

    if (descriptor.reserved) return error.ReservedBitSet;

    var window_descriptor: ?u8 = null;
    if (!descriptor.single_segment_flag) {
        window_descriptor = try source.readByte();
    }

    var dictionary_id: ?u32 = null;
    if (descriptor.dictionary_id_flag > 0) {
        // if flag is 3 then field_size = 4, else field_size = flag
        const field_size = (@as(u4, 1) << descriptor.dictionary_id_flag) >> 1;
        dictionary_id = try source.readVarInt(u32, .little, field_size);
    }

    var content_size: ?u64 = null;
    if (descriptor.single_segment_flag or descriptor.content_size_flag > 0) {
        const field_size = @as(u4, 1) << descriptor.content_size_flag;
        content_size = try source.readVarInt(u64, .little, field_size);
        if (field_size == 2) content_size.? += 256;
    }

    const header = ZstandardHeader{
        .descriptor = descriptor,
        .window_descriptor = window_descriptor,
        .dictionary_id = dictionary_id,
        .content_size = content_size,
    };
    return header;
}

test {
    std.testing.refAllDecls(@This());
}
const std = @import("std");

pub const ReversedByteReader = struct {
    remaining_bytes: usize,
    bytes: []const u8,

    const Reader = std.io.Reader(*ReversedByteReader, error{}, readFn);

    pub fn init(bytes: []const u8) ReversedByteReader {
        return .{
            .bytes = bytes,
            .remaining_bytes = bytes.len,
        };
    }

    pub fn reader(self: *ReversedByteReader) Reader {
        return .{ .context = self };
    }

    fn readFn(ctx: *ReversedByteReader, buffer: []u8) !usize {
        if (ctx.remaining_bytes == 0) return 0;
        const byte_index = ctx.remaining_bytes - 1;
        buffer[0] = ctx.bytes[byte_index];
        // buffer[0] = @bitReverse(ctx.bytes[byte_index]);
        ctx.remaining_bytes = byte_index;
        return 1;
    }
};

/// A bit reader for reading the reversed bit streams used to encode
/// FSE compressed data.
pub const ReverseBitReader = struct {
    byte_reader: ReversedByteReader,
    bit_reader: std.io.BitReader(.big, ReversedByteReader.Reader),

    pub fn init(self: *ReverseBitReader, bytes: []const u8) error{BitStreamHasNoStartBit}!void {
        self.byte_reader = ReversedByteReader.init(bytes);
        self.bit_reader = std.io.bitReader(.big, self.byte_reader.reader());
        if (bytes.len == 0) return;
        var i: usize = 0;
        while (i < 8 and 0 == self.readBitsNoEof(u1, 1) catch unreachable) : (i += 1) {}
        if (i == 8) return error.BitStreamHasNoStartBit;
    }

    pub fn readBitsNoEof(self: *@This(), comptime U: type, num_bits: u16) error{EndOfStream}!U {
        return self.bit_reader.readBitsNoEof(U, num_bits);
    }

    pub fn readBits(self: *@This(), comptime U: type, num_bits: u16, out_bits: *u16) error{}!U {
        return try self.bit_reader.readBits(U, num_bits, out_bits);
    }

    pub fn alignToByte(self: *@This()) void {
        self.bit_reader.alignToByte();
    }

    pub fn isEmpty(self: ReverseBitReader) bool {
        return self.byte_reader.remaining_bytes == 0 and self.bit_reader.count == 0;
    }
};

pub fn BitReader(comptime Reader: type) type {
    return struct {
        underlying: std.io.BitReader(.little, Reader),

        pub fn readBitsNoEof(self: *@This(), comptime U: type, num_bits: u16) !U {
            return self.underlying.readBitsNoEof(U, num_bits);
        }

        pub fn readBits(self: *@This(), comptime U: type, num_bits: u16, out_bits: *u16) !U {
            return self.underlying.readBits(U, num_bits, out_bits);
        }

        pub fn alignToByte(self: *@This()) void {
            self.underlying.alignToByte();
        }
    };
}

pub fn bitReader(reader: anytype) BitReader(@TypeOf(reader)) {
    return .{ .underlying = std.io.bitReader(.little, reader) };
}
pub const block_size_max = 1 << 17;

pub const frame = struct {
    pub const Kind = enum { zstandard, skippable };

    pub const Zstandard = struct {
        pub const magic_number = 0xFD2FB528;

        header: Header,
        data_blocks: []Block,
        checksum: ?u32,

        pub const Header = struct {
            descriptor: Descriptor,
            window_descriptor: ?u8,
            dictionary_id: ?u32,
            content_size: ?u64,

            pub const Descriptor = packed struct {
                dictionary_id_flag: u2,
                content_checksum_flag: bool,
                reserved: bool,
                unused: bool,
                single_segment_flag: bool,
                content_size_flag: u2,
            };
        };

        pub const Block = struct {
            pub const Header = struct {
                last_block: bool,
                block_type: Block.Type,
                block_size: u21,
            };

            pub const Type = enum(u2) {
                raw,
                rle,
                compressed,
                reserved,
            };
        };
    };

    pub const Skippable = struct {
        pub const magic_number_min = 0x184D2A50;
        pub const magic_number_max = 0x184D2A5F;

        pub const Header = struct {
            magic_number: u32,
            frame_size: u32,
        };
    };
};

pub const compressed_block = struct {
    pub const LiteralsSection = struct {
        header: Header,
        huffman_tree: ?HuffmanTree,
        streams: Streams,

        pub const Streams = union(enum) {
            one: []const u8,
            four: [4][]const u8,
        };

        pub const Header = struct {
            block_type: BlockType,
            size_format: u2,
            regenerated_size: u20,
            compressed_size: ?u18,
        };

        pub const BlockType = enum(u2) {
            raw,
            rle,
            compressed,
            treeless,
        };

        pub const HuffmanTree = struct {
            max_bit_count: u4,
            symbol_count_minus_one: u8,
            nodes: [256]PrefixedSymbol,

            pub const PrefixedSymbol = struct {
                symbol: u8,
                prefix: u16,
                weight: u4,
            };

            pub const Result = union(enum) {
                symbol: u8,
                index: usize,
            };

            pub fn query(self: HuffmanTree, index: usize, prefix: u16) error{NotFound}!Result {
                var node = self.nodes[index];
                const weight = node.weight;
                var i: usize = index;
                while (node.weight == weight) {
                    if (node.prefix == prefix) return Result{ .symbol = node.symbol };
                    if (i == 0) return error.NotFound;
                    i -= 1;
                    node = self.nodes[i];
                }
                return Result{ .index = i };
            }

            pub fn weightToBitCount(weight: u4, max_bit_count: u4) u4 {
                return if (weight == 0) 0 else ((max_bit_count + 1) - weight);
            }
        };

        pub const StreamCount = enum { one, four };
        pub fn streamCount(size_format: u2, block_type: BlockType) StreamCount {
            return switch (block_type) {
                .raw, .rle => .one,
                .compressed, .treeless => if (size_format == 0) .one else .four,
            };
        }
    };

    pub const SequencesSection = struct {
        header: SequencesSection.Header,
        literals_length_table: Table,
        offset_table: Table,
        match_length_table: Table,

        pub const Header = struct {
            sequence_count: u24,
            match_lengths: Mode,
            offsets: Mode,
            literal_lengths: Mode,

            pub const Mode = enum(u2) {
                predefined,
                rle,
                fse,
                repeat,
            };
        };
    };

    pub const Table = union(enum) {
        fse: []const Fse,
        rle: u8,

        pub const Fse = struct {
            symbol: u8,
            baseline: u16,
            bits: u8,
        };
    };

    pub const literals_length_code_table = [36]struct { u32, u5 }{
        .{ 0, 0 },     .{ 1, 0 },      .{ 2, 0 },      .{ 3, 0 },
        .{ 4, 0 },     .{ 5, 0 },      .{ 6, 0 },      .{ 7, 0 },
        .{ 8, 0 },     .{ 9, 0 },      .{ 10, 0 },     .{ 11, 0 },
        .{ 12, 0 },    .{ 13, 0 },     .{ 14, 0 },     .{ 15, 0 },
        .{ 16, 1 },    .{ 18, 1 },     .{ 20, 1 },     .{ 22, 1 },
        .{ 24, 2 },    .{ 28, 2 },     .{ 32, 3 },     .{ 40, 3 },
        .{ 48, 4 },    .{ 64, 6 },     .{ 128, 7 },    .{ 256, 8 },
        .{ 512, 9 },   .{ 1024, 10 },  .{ 2048, 11 },  .{ 4096, 12 },
        .{ 8192, 13 }, .{ 16384, 14 }, .{ 32768, 15 }, .{ 65536, 16 },
    };

    pub const match_length_code_table = [53]struct { u32, u5 }{
        .{ 3, 0 },     .{ 4, 0 },     .{ 5, 0 },      .{ 6, 0 },      .{ 7, 0 },      .{ 8, 0 },
        .{ 9, 0 },     .{ 10, 0 },    .{ 11, 0 },     .{ 12, 0 },     .{ 13, 0 },     .{ 14, 0 },
        .{ 15, 0 },    .{ 16, 0 },    .{ 17, 0 },     .{ 18, 0 },     .{ 19, 0 },     .{ 20, 0 },
        .{ 21, 0 },    .{ 22, 0 },    .{ 23, 0 },     .{ 24, 0 },     .{ 25, 0 },     .{ 26, 0 },
        .{ 27, 0 },    .{ 28, 0 },    .{ 29, 0 },     .{ 30, 0 },     .{ 31, 0 },     .{ 32, 0 },
        .{ 33, 0 },    .{ 34, 0 },    .{ 35, 1 },     .{ 37, 1 },     .{ 39, 1 },     .{ 41, 1 },
        .{ 43, 2 },    .{ 47, 2 },    .{ 51, 3 },     .{ 59, 3 },     .{ 67, 4 },     .{ 83, 4 },
        .{ 99, 5 },    .{ 131, 7 },   .{ 259, 8 },    .{ 515, 9 },    .{ 1027, 10 },  .{ 2051, 11 },
        .{ 4099, 12 }, .{ 8195, 13 }, .{ 16387, 14 }, .{ 32771, 15 }, .{ 65539, 16 },
    };

    pub const literals_length_default_distribution = [36]i16{
        4,  3,  2,  2,  2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
        2,  2,  2,  2,  2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
        -1, -1, -1, -1,
    };

    pub const match_lengths_default_distribution = [53]i16{
        1,  4,  3,  2,  2,  2, 2, 2, 2, 1, 1, 1, 1, 1, 1,  1,
        1,  1,  1,  1,  1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1,
        1,  1,  1,  1,  1,  1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
        -1, -1, -1, -1, -1,
    };

    pub const offset_codes_default_distribution = [29]i16{
        1, 1, 1, 1, 1, 1, 2, 2, 2,  1,  1,  1,  1,  1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
    };

    pub const predefined_literal_fse_table = Table{
        .fse = &[64]Table.Fse{
            .{ .symbol = 0, .bits = 4, .baseline = 0 },
            .{ .symbol = 0, .bits = 4, .baseline = 16 },
            .{ .symbol = 1, .bits = 5, .baseline = 32 },
            .{ .symbol = 3, .bits = 5, .baseline = 0 },
            .{ .symbol = 4, .bits = 5, .baseline = 0 },
            .{ .symbol = 6, .bits = 5, .baseline = 0 },
            .{ .symbol = 7, .bits = 5, .baseline = 0 },
            .{ .symbol = 9, .bits = 5, .baseline = 0 },
            .{ .symbol = 10, .bits = 5, .baseline = 0 },
            .{ .symbol = 12, .bits = 5, .baseline = 0 },
            .{ .symbol = 14, .bits = 6, .baseline = 0 },
            .{ .symbol = 16, .bits = 5, .baseline = 0 },
            .{ .symbol = 18, .bits = 5, .baseline = 0 },
            .{ .symbol = 19, .bits = 5, .baseline = 0 },
            .{ .symbol = 21, .bits = 5, .baseline = 0 },
            .{ .symbol = 22, .bits = 5, .baseline = 0 },
            .{ .symbol = 24, .bits = 5, .baseline = 0 },
            .{ .symbol = 25, .bits = 5, .baseline = 32 },
            .{ .symbol = 26, .bits = 5, .baseline = 0 },
            .{ .symbol = 27, .bits = 6, .baseline = 0 },
            .{ .symbol = 29, .bits = 6, .baseline = 0 },
            .{ .symbol = 31, .bits = 6, .baseline = 0 },
            .{ .symbol = 0, .bits = 4, .baseline = 32 },
            .{ .symbol = 1, .bits = 4, .baseline = 0 },
            .{ .symbol = 2, .bits = 5, .baseline = 0 },
            .{ .symbol = 4, .bits = 5, .baseline = 32 },
            .{ .symbol = 5, .bits = 5, .baseline = 0 },
            .{ .symbol = 7, .bits = 5, .baseline = 32 },
            .{ .symbol = 8, .bits = 5, .baseline = 0 },
            .{ .symbol = 10, .bits = 5, .baseline = 32 },
            .{ .symbol = 11, .bits = 5, .baseline = 0 },
            .{ .symbol = 13, .bits = 6, .baseline = 0 },
            .{ .symbol = 16, .bits = 5, .baseline = 32 },
            .{ .symbol = 17, .bits = 5, .baseline = 0 },
            .{ .symbol = 19, .bits = 5, .baseline = 32 },
            .{ .symbol = 20, .bits = 5, .baseline = 0 },
            .{ .symbol = 22, .bits = 5, .baseline = 32 },
            .{ .symbol = 23, .bits = 5, .baseline = 0 },
            .{ .symbol = 25, .bits = 4, .baseline = 0 },
            .{ .symbol = 25, .bits = 4, .baseline = 16 },
            .{ .symbol = 26, .bits = 5, .baseline = 32 },
            .{ .symbol = 28, .bits = 6, .baseline = 0 },
            .{ .symbol = 30, .bits = 6, .baseline = 0 },
            .{ .symbol = 0, .bits = 4, .baseline = 48 },
            .{ .symbol = 1, .bits = 4, .baseline = 16 },
            .{ .symbol = 2, .bits = 5, .baseline = 32 },
            .{ .symbol = 3, .bits = 5, .baseline = 32 },
            .{ .symbol = 5, .bits = 5, .baseline = 32 },
            .{ .symbol = 6, .bits = 5, .baseline = 32 },
            .{ .symbol = 8, .bits = 5, .baseline = 32 },
            .{ .symbol = 9, .bits = 5, .baseline = 32 },
            .{ .symbol = 11, .bits = 5, .baseline = 32 },
            .{ .symbol = 12, .bits = 5, .baseline = 32 },
            .{ .symbol = 15, .bits = 6, .baseline = 0 },
            .{ .symbol = 17, .bits = 5, .baseline = 32 },
            .{ .symbol = 18, .bits = 5, .baseline = 32 },
            .{ .symbol = 20, .bits = 5, .baseline = 32 },
            .{ .symbol = 21, .bits = 5, .baseline = 32 },
            .{ .symbol = 23, .bits = 5, .baseline = 32 },
            .{ .symbol = 24, .bits```
