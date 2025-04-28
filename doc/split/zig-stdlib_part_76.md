```
var sentinel_array: [5:0]u16 = [_:0]u16{ 1, 2, 3, 4, 5 };
        try testing.expectEqualSlices(u16, sentinel_array[0..2], sliceTo(&sentinel_array, 3));
        try testing.expectEqualSlices(u16, &sentinel_array, sliceTo(&sentinel_array, 0));
        try testing.expectEqualSlices(u16, &sentinel_array, sliceTo(&sentinel_array, 99));
    }

    try testing.expectEqual(@as(?[]u8, null), sliceTo(@as(?[]u8, null), 0));
}

/// Private helper for sliceTo(). If you want the length, use sliceTo(foo, x).len
fn lenSliceTo(ptr: anytype, comptime end: std.meta.Elem(@TypeOf(ptr))) usize {
    switch (@typeInfo(@TypeOf(ptr))) {
        .pointer => |ptr_info| switch (ptr_info.size) {
            .one => switch (@typeInfo(ptr_info.child)) {
                .array => |array_info| {
                    if (array_info.sentinel()) |s| {
                        if (s == end) {
                            return indexOfSentinel(array_info.child, end, ptr);
                        }
                    }
                    return indexOfScalar(array_info.child, ptr, end) orelse array_info.len;
                },
                else => {},
            },
            .many => if (ptr_info.sentinel()) |s| {
                if (s == end) {
                    return indexOfSentinel(ptr_info.child, end, ptr);
                }
                // We're looking for something other than the sentinel,
                // but iterating past the sentinel would be a bug so we need
                // to check for both.
                var i: usize = 0;
                while (ptr[i] != end and ptr[i] != s) i += 1;
                return i;
            },
            .c => {
                assert(ptr != null);
                return indexOfSentinel(ptr_info.child, end, ptr);
            },
            .slice => {
                if (ptr_info.sentinel()) |s| {
                    if (s == end) {
                        return indexOfSentinel(ptr_info.child, s, ptr);
                    }
                }
                return indexOfScalar(ptr_info.child, ptr, end) orelse ptr.len;
            },
        },
        else => {},
    }
    @compileError("invalid type given to std.mem.sliceTo: " ++ @typeName(@TypeOf(ptr)));
}

test lenSliceTo {
    try testing.expect(lenSliceTo("aoeu", 0) == 4);

    {
        var array: [5]u16 = [_]u16{ 1, 2, 3, 4, 5 };
        try testing.expectEqual(@as(usize, 5), lenSliceTo(&array, 0));
        try testing.expectEqual(@as(usize, 3), lenSliceTo(array[0..3], 0));
        try testing.expectEqual(@as(usize, 2), lenSliceTo(&array, 3));
        try testing.expectEqual(@as(usize, 2), lenSliceTo(array[0..3], 3));

        const sentinel_ptr = @as([*:5]u16, @ptrCast(&array));
        try testing.expectEqual(@as(usize, 2), lenSliceTo(sentinel_ptr, 3));
        try testing.expectEqual(@as(usize, 4), lenSliceTo(sentinel_ptr, 99));

        const c_ptr = @as([*c]u16, &array);
        try testing.expectEqual(@as(usize, 2), lenSliceTo(c_ptr, 3));

        const slice: []u16 = &array;
        try testing.expectEqual(@as(usize, 2), lenSliceTo(slice, 3));
        try testing.expectEqual(@as(usize, 5), lenSliceTo(slice, 99));

        const sentinel_slice: [:5]u16 = array[0..4 :5];
        try testing.expectEqual(@as(usize, 2), lenSliceTo(sentinel_slice, 3));
        try testing.expectEqual(@as(usize, 4), lenSliceTo(sentinel_slice, 99));
    }
    {
        var sentinel_array: [5:0]u16 = [_:0]u16{ 1, 2, 3, 4, 5 };
        try testing.expectEqual(@as(usize, 2), lenSliceTo(&sentinel_array, 3));
        try testing.expectEqual(@as(usize, 5), lenSliceTo(&sentinel_array, 0));
        try testing.expectEqual(@as(usize, 5), lenSliceTo(&sentinel_array, 99));
    }
}

/// Takes a sentinel-terminated pointer and iterates over the memory to find the
/// sentinel and determine the length.
/// `[*c]` pointers are assumed to be non-null and 0-terminated.
pub fn len(value: anytype) usize {
    switch (@typeInfo(@TypeOf(value))) {
        .pointer => |info| switch (info.size) {
            .many => {
                const sentinel = info.sentinel() orelse
                    @compileError("invalid type given to std.mem.len: " ++ @typeName(@TypeOf(value)));
                return indexOfSentinel(info.child, sentinel, value);
            },
            .c => {
                assert(value != null);
                return indexOfSentinel(info.child, 0, value);
            },
            else => @compileError("invalid type given to std.mem.len: " ++ @typeName(@TypeOf(value))),
        },
        else => @compileError("invalid type given to std.mem.len: " ++ @typeName(@TypeOf(value))),
    }
}

test len {
    var array: [5]u16 = [_]u16{ 1, 2, 0, 4, 5 };
    const ptr = @as([*:4]u16, array[0..3 :4]);
    try testing.expect(len(ptr) == 3);
    const c_ptr = @as([*c]u16, ptr);
    try testing.expect(len(c_ptr) == 2);
}

const backend_supports_vectors = switch (builtin.zig_backend) {
    .stage2_llvm, .stage2_c => true,
    else => false,
};

pub fn indexOfSentinel(comptime T: type, comptime sentinel: T, p: [*:sentinel]const T) usize {
    var i: usize = 0;

    if (backend_supports_vectors and
        !std.debug.inValgrind() and // https://github.com/ziglang/zig/issues/17717
        !@inComptime() and
        (@typeInfo(T) == .int or @typeInfo(T) == .float) and std.math.isPowerOfTwo(@bitSizeOf(T)))
    {
        switch (@import("builtin").cpu.arch) {
            // The below branch assumes that reading past the end of the buffer is valid, as long
            // as we don't read into a new page. This should be the case for most architectures
            // which use paged memory, however should be confirmed before adding a new arch below.
            .aarch64, .x86, .x86_64 => if (std.simd.suggestVectorLength(T)) |block_len| {
                const page_size = std.heap.page_size_min;
                const block_size = @sizeOf(T) * block_len;
                const Block = @Vector(block_len, T);
                const mask: Block = @splat(sentinel);

                comptime assert(std.heap.page_size_min % @sizeOf(Block) == 0);
                assert(page_size % @sizeOf(Block) == 0);

                // First block may be unaligned
                const start_addr = @intFromPtr(&p[i]);
                const offset_in_page = start_addr & (page_size - 1);
                if (offset_in_page <= page_size - @sizeOf(Block)) {
                    // Will not read past the end of a page, full block.
                    const block: Block = p[i..][0..block_len].*;
                    const matches = block == mask;
                    if (@reduce(.Or, matches)) {
                        return i + std.simd.firstTrue(matches).?;
                    }

                    i += @divExact(std.mem.alignForward(usize, start_addr, block_size) - start_addr, @sizeOf(T));
                } else {
                    @branchHint(.unlikely);
                    // Would read over a page boundary. Per-byte at a time until aligned or found.
                    // 0.39% chance this branch is taken for 4K pages at 16b block length.
                    //
                    // An alternate strategy is to do read a full block (the last in the page) and
                    // mask the entries before the pointer.
                    while ((@intFromPtr(&p[i]) & (block_size - 1)) != 0) : (i += 1) {
                        if (p[i] == sentinel) return i;
                    }
                }

                assert(std.mem.isAligned(@intFromPtr(&p[i]), block_size));
                while (true) {
                    const block: *const Block = @ptrCast(@alignCast(p[i..][0..block_len]));
                    const matches = block.* == mask;
                    if (@reduce(.Or, matches)) {
                        return i + std.simd.firstTrue(matches).?;
                    }
                    i += block_len;
                }
            },
            else => {},
        }
    }

    while (p[i] != sentinel) {
        i += 1;
    }
    return i;
}

test "indexOfSentinel vector paths" {
    const Types = [_]type{ u8, u16, u32, u64 };
    const allocator = std.testing.allocator;
    const page_size = std.heap.page_size_min;

    inline for (Types) |T| {
        const block_len = std.simd.suggestVectorLength(T) orelse continue;

        // Allocate three pages so we guarantee a page-crossing address with a full page after
        const memory = try allocator.alloc(T, 3 * page_size / @sizeOf(T));
        defer allocator.free(memory);
        @memset(memory, 0xaa);

        // Find starting page-alignment = 0
        var start: usize = 0;
        const start_addr = @intFromPtr(&memory);
        start += (std.mem.alignForward(usize, start_addr, page_size) - start_addr) / @sizeOf(T);
        try testing.expect(start < page_size / @sizeOf(T));

        // Validate all sub-block alignments
        const search_len = page_size / @sizeOf(T);
        memory[start + search_len] = 0;
        for (0..block_len) |offset| {
            try testing.expectEqual(search_len - offset, indexOfSentinel(T, 0, @ptrCast(&memory[start + offset])));
        }
        memory[start + search_len] = 0xaa;

        // Validate page boundary crossing
        const start_page_boundary = start + (page_size / @sizeOf(T));
        memory[start_page_boundary + block_len] = 0;
        for (0..block_len) |offset| {
            try testing.expectEqual(2 * block_len - offset, indexOfSentinel(T, 0, @ptrCast(&memory[start_page_boundary - block_len + offset])));
        }
    }
}

/// Returns true if all elements in a slice are equal to the scalar value provided
pub fn allEqual(comptime T: type, slice: []const T, scalar: T) bool {
    for (slice) |item| {
        if (item != scalar) return false;
    }
    return true;
}

/// Remove a set of values from the beginning of a slice.
pub fn trimLeft(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    var begin: usize = 0;
    while (begin < slice.len and indexOfScalar(T, values_to_strip, slice[begin]) != null) : (begin += 1) {}
    return slice[begin..];
}

/// Remove a set of values from the end of a slice.
pub fn trimRight(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    var end: usize = slice.len;
    while (end > 0 and indexOfScalar(T, values_to_strip, slice[end - 1]) != null) : (end -= 1) {}
    return slice[0..end];
}

/// Remove a set of values from the beginning and end of a slice.
pub fn trim(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    var begin: usize = 0;
    var end: usize = slice.len;
    while (begin < end and indexOfScalar(T, values_to_strip, slice[begin]) != null) : (begin += 1) {}
    while (end > begin and indexOfScalar(T, values_to_strip, slice[end - 1]) != null) : (end -= 1) {}
    return slice[begin..end];
}

test trim {
    try testing.expectEqualSlices(u8, "foo\n ", trimLeft(u8, " foo\n ", " \n"));
    try testing.expectEqualSlices(u8, " foo", trimRight(u8, " foo\n ", " \n"));
    try testing.expectEqualSlices(u8, "foo", trim(u8, " foo\n ", " \n"));
    try testing.expectEqualSlices(u8, "foo", trim(u8, "foo", " \n"));
}

/// Linear search for the index of a scalar value inside a slice.
pub fn indexOfScalar(comptime T: type, slice: []const T, value: T) ?usize {
    return indexOfScalarPos(T, slice, 0, value);
}

/// Linear search for the last index of a scalar value inside a slice.
pub fn lastIndexOfScalar(comptime T: type, slice: []const T, value: T) ?usize {
    var i: usize = slice.len;
    while (i != 0) {
        i -= 1;
        if (slice[i] == value) return i;
    }
    return null;
}

pub fn indexOfScalarPos(comptime T: type, slice: []const T, start_index: usize, value: T) ?usize {
    if (start_index >= slice.len) return null;

    var i: usize = start_index;
    if (backend_supports_vectors and
        !std.debug.inValgrind() and // https://github.com/ziglang/zig/issues/17717
        !@inComptime() and
        (@typeInfo(T) == .int or @typeInfo(T) == .float) and std.math.isPowerOfTwo(@bitSizeOf(T)))
    {
        if (std.simd.suggestVectorLength(T)) |block_len| {
            // For Intel Nehalem (2009) and AMD Bulldozer (2012) or later, unaligned loads on aligned data result
            // in the same execution as aligned loads. We ignore older arch's here and don't bother pre-aligning.
            //
            // Use `std.simd.suggestVectorLength(T)` to get the same alignment as used in this function
            // however this usually isn't necessary unless your arch has a performance penalty due to this.
            //
            // This may differ for other arch's. Arm for example costs a cycle when loading across a cache
            // line so explicit alignment prologues may be worth exploration.

            // Unrolling here is ~10% improvement. We can then do one bounds check every 2 blocks
            // instead of one which adds up.
            const Block = @Vector(block_len, T);
            if (i + 2 * block_len < slice.len) {
                const mask: Block = @splat(value);
                while (true) {
                    inline for (0..2) |_| {
                        const block: Block = slice[i..][0..block_len].*;
                        const matches = block == mask;
                        if (@reduce(.Or, matches)) {
                            return i + std.simd.firstTrue(matches).?;
                        }
                        i += block_len;
                    }
                    if (i + 2 * block_len >= slice.len) break;
                }
            }

            // {block_len, block_len / 2} check
            inline for (0..2) |j| {
                const block_x_len = block_len / (1 << j);
                comptime if (block_x_len < 4) break;

                const BlockX = @Vector(block_x_len, T);
                if (i + block_x_len < slice.len) {
                    const mask: BlockX = @splat(value);
                    const block: BlockX = slice[i..][0..block_x_len].*;
                    const matches = block == mask;
                    if (@reduce(.Or, matches)) {
                        return i + std.simd.firstTrue(matches).?;
                    }
                    i += block_x_len;
                }
            }
        }
    }

    for (slice[i..], i..) |c, j| {
        if (c == value) return j;
    }
    return null;
}

test indexOfScalarPos {
    const Types = [_]type{ u8, u16, u32, u64 };

    inline for (Types) |T| {
        var memory: [64 / @sizeOf(T)]T = undefined;
        @memset(&memory, 0xaa);
        memory[memory.len - 1] = 0;

        for (0..memory.len) |i| {
            try testing.expectEqual(memory.len - i - 1, indexOfScalarPos(T, memory[i..], 0, 0).?);
        }
    }
}

pub fn indexOfAny(comptime T: type, slice: []const T, values: []const T) ?usize {
    return indexOfAnyPos(T, slice, 0, values);
}

pub fn lastIndexOfAny(comptime T: type, slice: []const T, values: []const T) ?usize {
    var i: usize = slice.len;
    while (i != 0) {
        i -= 1;
        for (values) |value| {
            if (slice[i] == value) return i;
        }
    }
    return null;
}

pub fn indexOfAnyPos(comptime T: type, slice: []const T, start_index: usize, values: []const T) ?usize {
    if (start_index >= slice.len) return null;
    for (slice[start_index..], start_index..) |c, i| {
        for (values) |value| {
            if (c == value) return i;
        }
    }
    return null;
}

/// Find the first item in `slice` which is not contained in `values`.
///
/// Comparable to `strspn` in the C standard library.
pub fn indexOfNone(comptime T: type, slice: []const T, values: []const T) ?usize {
    return indexOfNonePos(T, slice, 0, values);
}

/// Find the last item in `slice` which is not contained in `values`.
///
/// Like `strspn` in the C standard library, but searches from the end.
pub fn lastIndexOfNone(comptime T: type, slice: []const T, values: []const T) ?usize {
    var i: usize = slice.len;
    outer: while (i != 0) {
        i -= 1;
        for (values) |value| {
            if (slice[i] == value) continue :outer;
        }
        return i;
    }
    return null;
}

/// Find the first item in `slice[start_index..]` which is not contained in `values`.
/// The returned index will be relative to the start of `slice`, and never less than `start_index`.
///
/// Comparable to `strspn` in the C standard library.
pub fn indexOfNonePos(comptime T: type, slice: []const T, start_index: usize, values: []const T) ?usize {
    if (start_index >= slice.len) return null;
    outer: for (slice[start_index..], start_index..) |c, i| {
        for (values) |value| {
            if (c == value) continue :outer;
        }
        return i;
    }
    return null;
}

test indexOfNone {
    try testing.expect(indexOfNone(u8, "abc123", "123").? == 0);
    try testing.expect(lastIndexOfNone(u8, "abc123", "123").? == 2);
    try testing.expect(indexOfNone(u8, "123abc", "123").? == 3);
    try testing.expect(lastIndexOfNone(u8, "123abc", "123").? == 5);
    try testing.expect(indexOfNone(u8, "123123", "123") == null);
    try testing.expect(indexOfNone(u8, "333333", "123") == null);

    try testing.expect(indexOfNonePos(u8, "abc123", 3, "321") == null);
}

pub fn indexOf(comptime T: type, haystack: []const T, needle: []const T) ?usize {
    return indexOfPos(T, haystack, 0, needle);
}

/// Find the index in a slice of a sub-slice, searching from the end backwards.
/// To start looking at a different index, slice the haystack first.
/// Consider using `lastIndexOf` instead of this, which will automatically use a
/// more sophisticated algorithm on larger inputs.
pub fn lastIndexOfLinear(comptime T: type, haystack: []const T, needle: []const T) ?usize {
    if (needle.len > haystack.len) return null;
    var i: usize = haystack.len - needle.len;
    while (true) : (i -= 1) {
        if (mem.eql(T, haystack[i..][0..needle.len], needle)) return i;
        if (i == 0) return null;
    }
}

/// Consider using `indexOfPos` instead of this, which will automatically use a
/// more sophisticated algorithm on larger inputs.
pub fn indexOfPosLinear(comptime T: type, haystack: []const T, start_index: usize, needle: []const T) ?usize {
    if (needle.len > haystack.len) return null;
    var i: usize = start_index;
    const end = haystack.len - needle.len;
    while (i <= end) : (i += 1) {
        if (eql(T, haystack[i..][0..needle.len], needle)) return i;
    }
    return null;
}

test indexOfPosLinear {
    try testing.expectEqual(0, indexOfPosLinear(u8, "", 0, ""));
    try testing.expectEqual(0, indexOfPosLinear(u8, "123", 0, ""));

    try testing.expectEqual(null, indexOfPosLinear(u8, "", 0, "1"));
    try testing.expectEqual(0, indexOfPosLinear(u8, "1", 0, "1"));
    try testing.expectEqual(null, indexOfPosLinear(u8, "2", 0, "1"));
    try testing.expectEqual(1, indexOfPosLinear(u8, "21", 0, "1"));
    try testing.expectEqual(null, indexOfPosLinear(u8, "222", 0, "1"));

    try testing.expectEqual(null, indexOfPosLinear(u8, "", 0, "12"));
    try testing.expectEqual(null, indexOfPosLinear(u8, "1", 0, "12"));
    try testing.expectEqual(null, indexOfPosLinear(u8, "2", 0, "12"));
    try testing.expectEqual(0, indexOfPosLinear(u8, "12", 0, "12"));
    try testing.expectEqual(null, indexOfPosLinear(u8, "21", 0, "12"));
    try testing.expectEqual(1, indexOfPosLinear(u8, "212", 0, "12"));
    try testing.expectEqual(0, indexOfPosLinear(u8, "122", 0, "12"));
    try testing.expectEqual(1, indexOfPosLinear(u8, "212112", 0, "12"));
}

fn boyerMooreHorspoolPreprocessReverse(pattern: []const u8, table: *[256]usize) void {
    for (table) |*c| {
        c.* = pattern.len;
    }

    var i: usize = pattern.len - 1;
    // The first item is intentionally ignored and the skip size will be pattern.len.
    // This is the standard way Boyer-Moore-Horspool is implemented.
    while (i > 0) : (i -= 1) {
        table[pattern[i]] = i;
    }
}

fn boyerMooreHorspoolPreprocess(pattern: []const u8, table: *[256]usize) void {
    for (table) |*c| {
        c.* = pattern.len;
    }

    var i: usize = 0;
    // The last item is intentionally ignored and the skip size will be pattern.len.
    // This is the standard way Boyer-Moore-Horspool is implemented.
    while (i < pattern.len - 1) : (i += 1) {
        table[pattern[i]] = pattern.len - 1 - i;
    }
}

/// Find the index in a slice of a sub-slice, searching from the end backwards.
/// To start looking at a different index, slice the haystack first.
/// Uses the Reverse Boyer-Moore-Horspool algorithm on large inputs;
/// `lastIndexOfLinear` on small inputs.
pub fn lastIndexOf(comptime T: type, haystack: []const T, needle: []const T) ?usize {
    if (needle.len > haystack.len) return null;
    if (needle.len == 0) return haystack.len;

    if (!std.meta.hasUniqueRepresentation(T) or haystack.len < 52 or needle.len <= 4)
        return lastIndexOfLinear(T, haystack, needle);

    const haystack_bytes = sliceAsBytes(haystack);
    const needle_bytes = sliceAsBytes(needle);

    var skip_table: [256]usize = undefined;
    boyerMooreHorspoolPreprocessReverse(needle_bytes, skip_table[0..]);

    var i: usize = haystack_bytes.len - needle_bytes.len;
    while (true) {
        if (i % @sizeOf(T) == 0 and mem.eql(u8, haystack_bytes[i .. i + needle_bytes.len], needle_bytes)) {
            return @divExact(i, @sizeOf(T));
        }
        const skip = skip_table[haystack_bytes[i]];
        if (skip > i) break;
        i -= skip;
    }

    return null;
}

/// Uses Boyer-Moore-Horspool algorithm on large inputs; `indexOfPosLinear` on small inputs.
pub fn indexOfPos(comptime T: type, haystack: []const T, start_index: usize, needle: []const T) ?usize {
    if (needle.len > haystack.len) return null;
    if (needle.len < 2) {
        if (needle.len == 0) return start_index;
        // indexOfScalarPos is significantly faster than indexOfPosLinear
        return indexOfScalarPos(T, haystack, start_index, needle[0]);
    }

    if (!std.meta.hasUniqueRepresentation(T) or haystack.len < 52 or needle.len <= 4)
        return indexOfPosLinear(T, haystack, start_index, needle);

    const haystack_bytes = sliceAsBytes(haystack);
    const needle_bytes = sliceAsBytes(needle);

    var skip_table: [256]usize = undefined;
    boyerMooreHorspoolPreprocess(needle_bytes, skip_table[0..]);

    var i: usize = start_index * @sizeOf(T);
    while (i <= haystack_bytes.len - needle_bytes.len) {
        if (i % @sizeOf(T) == 0 and mem.eql(u8, haystack_bytes[i .. i + needle_bytes.len], needle_bytes)) {
            return @divExact(i, @sizeOf(T));
        }
        i += skip_table[haystack_bytes[i + needle_bytes.len - 1]];
    }

    return null;
}

test indexOf {
    try testing.expect(indexOf(u8, "one two three four five six seven eight nine ten eleven", "three four").? == 8);
    try testing.expect(lastIndexOf(u8, "one two three four five six seven eight nine ten eleven", "three four").? == 8);
    try testing.expect(indexOf(u8, "one two three four five six seven eight nine ten eleven", "two two") == null);
    try testing.expect(lastIndexOf(u8, "one two three four five six seven eight nine ten eleven", "two two") == null);

    try testing.expect(indexOf(u8, "one two three four five six seven eight nine ten", "").? == 0);
    try testing.expect(lastIndexOf(u8, "one two three four five six seven eight nine ten", "").? == 48);

    try testing.expect(indexOf(u8, "one two three four", "four").? == 14);
    try testing.expect(lastIndexOf(u8, "one two three two four", "two").? == 14);
    try testing.expect(indexOf(u8, "one two three four", "gour") == null);
    try testing.expect(lastIndexOf(u8, "one two three four", "gour") == null);
    try testing.expect(indexOf(u8, "foo", "foo").? == 0);
    try testing.expect(lastIndexOf(u8, "foo", "foo").? == 0);
    try testing.expect(indexOf(u8, "foo", "fool") == null);
    try testing.expect(lastIndexOf(u8, "foo", "lfoo") == null);
    try testing.expect(lastIndexOf(u8, "foo", "fool") == null);

    try testing.expect(indexOf(u8, "foo foo", "foo").? == 0);
    try testing.expect(lastIndexOf(u8, "foo foo", "foo").? == 4);
    try testing.expect(lastIndexOfAny(u8, "boo, cat", "abo").? == 6);
    try testing.expect(lastIndexOfScalar(u8, "boo", 'o').? == 2);
}

test "indexOf multibyte" {
    {
        // make haystack and needle long enough to trigger Boyer-Moore-Horspool algorithm
        const haystack = [1]u16{0} ** 100 ++ [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee, 0x00ff };
        const needle = [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee };
        try testing.expectEqual(indexOfPos(u16, &haystack, 0, &needle), 100);

        // check for misaligned false positives (little and big endian)
        const needleLE = [_]u16{ 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff };
        try testing.expectEqual(indexOfPos(u16, &haystack, 0, &needleLE), null);
        const needleBE = [_]u16{ 0xaacc, 0xbbdd, 0xccee, 0xddff, 0xee00 };
        try testing.expectEqual(indexOfPos(u16, &haystack, 0, &needleBE), null);
    }

    {
        // make haystack and needle long enough to trigger Boyer-Moore-Horspool algorithm
        const haystack = [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee, 0x00ff } ++ [1]u16{0} ** 100;
        const needle = [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee };
        try testing.expectEqual(lastIndexOf(u16, &haystack, &needle), 0);

        // check for misaligned false positives (little and big endian)
        const needleLE = [_]u16{ 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff };
        try testing.expectEqual(lastIndexOf(u16, &haystack, &needleLE), null);
        const needleBE = [_]u16{ 0xaacc, 0xbbdd, 0xccee, 0xddff, 0xee00 };
        try testing.expectEqual(lastIndexOf(u16, &haystack, &needleBE), null);
    }
}

test "indexOfPos empty needle" {
    try testing.expectEqual(indexOfPos(u8, "abracadabra", 5, ""), 5);
}

/// Returns the number of needles inside the haystack
/// needle.len must be > 0
/// does not count overlapping needles
pub fn count(comptime T: type, haystack: []const T, needle: []const T) usize {
    assert(needle.len > 0);
    var i: usize = 0;
    var found: usize = 0;

    while (indexOfPos(T, haystack, i, needle)) |idx| {
        i = idx + needle.len;
        found += 1;
    }

    return found;
}

test count {
    try testing.expect(count(u8, "", "h") == 0);
    try testing.expect(count(u8, "h", "h") == 1);
    try testing.expect(count(u8, "hh", "h") == 2);
    try testing.expect(count(u8, "world!", "hello") == 0);
    try testing.expect(count(u8, "hello world!", "hello") == 1);
    try testing.expect(count(u8, "   abcabc   abc", "abc") == 3);
    try testing.expect(count(u8, "udexdcbvbruhasdrw", "bruh") == 1);
    try testing.expect(count(u8, "foo bar", "o bar") == 1);
    try testing.expect(count(u8, "foofoofoo", "foo") == 3);
    try testing.expect(count(u8, "fffffff", "ff") == 3);
    try testing.expect(count(u8, "owowowu", "owowu") == 1);
}

/// Returns true if the haystack contains expected_count or more needles
/// needle.len must be > 0
/// does not count overlapping needles
//
/// See also: `containsAtLeastScalar`
pub fn containsAtLeast(comptime T: type, haystack: []const T, expected_count: usize, needle: []const T) bool {
    assert(needle.len > 0);
    if (expected_count == 0) return true;

    var i: usize = 0;
    var found: usize = 0;

    while (indexOfPos(T, haystack, i, needle)) |idx| {
        i = idx + needle.len;
        found += 1;
        if (found == expected_count) return true;
    }
    return false;
}

test containsAtLeast {
    try testing.expect(containsAtLeast(u8, "aa", 0, "a"));
    try testing.expect(containsAtLeast(u8, "aa", 1, "a"));
    try testing.expect(containsAtLeast(u8, "aa", 2, "a"));
    try testing.expect(!containsAtLeast(u8, "aa", 3, "a"));

    try testing.expect(containsAtLeast(u8, "radaradar", 1, "radar"));
    try testing.expect(!containsAtLeast(u8, "radaradar", 2, "radar"));

    try testing.expect(containsAtLeast(u8, "radarradaradarradar", 3, "radar"));
    try testing.expect(!containsAtLeast(u8, "radarradaradarradar", 4, "radar"));

    try testing.expect(containsAtLeast(u8, "   radar      radar   ", 2, "radar"));
    try testing.expect(!containsAtLeast(u8, "   radar      radar   ", 3, "radar"));
}

/// Returns true if the haystack contains expected_count or more needles
//
/// See also: `containsAtLeast`
pub fn containsAtLeastScalar(comptime T: type, haystack: []const T, expected_count: usize, needle: T) bool {
    if (expected_count == 0) return true;

    var found: usize = 0;

    for (haystack) |item| {
        if (item == needle) {
            found += 1;
            if (found == expected_count) return true;
        }
    }

    return false;
}

test containsAtLeastScalar {
    try testing.expect(containsAtLeastScalar(u8, "aa", 0, 'a'));
    try testing.expect(containsAtLeastScalar(u8, "aa", 1, 'a'));
    try testing.expect(containsAtLeastScalar(u8, "aa", 2, 'a'));
    try testing.expect(!containsAtLeastScalar(u8, "aa", 3, 'a'));

    try testing.expect(containsAtLeastScalar(u8, "adadda", 3, 'd'));
    try testing.expect(!containsAtLeastScalar(u8, "adadda", 4, 'd'));
}

/// Reads an integer from memory with size equal to bytes.len.
/// T specifies the return type, which must be large enough to store
/// the result.
pub fn readVarInt(comptime ReturnType: type, bytes: []const u8, endian: Endian) ReturnType {
    assert(@typeInfo(ReturnType).int.bits >= bytes.len * 8);
    const bits = @typeInfo(ReturnType).int.bits;
    const signedness = @typeInfo(ReturnType).int.signedness;
    const WorkType = std.meta.Int(signedness, @max(16, bits));
    var result: WorkType = 0;
    switch (endian) {
        .big => {
            for (bytes) |b| {
                result = (result << 8) | b;
            }
        },
        .little => {
            const ShiftType = math.Log2Int(WorkType);
            for (bytes, 0..) |b, index| {
                result = result | (@as(WorkType, b) << @as(ShiftType, @intCast(index * 8)));
            }
        },
    }
    return @as(ReturnType, @truncate(result));
}

test readVarInt {
    try testing.expect(readVarInt(u0, &[_]u8{}, .big) == 0x0);
    try testing.expect(readVarInt(u0, &[_]u8{}, .little) == 0x0);
    try testing.expect(readVarInt(u8, &[_]u8{0x12}, .big) == 0x12);
    try testing.expect(readVarInt(u8, &[_]u8{0xde}, .little) == 0xde);
    try testing.expect(readVarInt(u16, &[_]u8{ 0x12, 0x34 }, .big) == 0x1234);
    try testing.expect(readVarInt(u16, &[_]u8{ 0x12, 0x34 }, .little) == 0x3412);

    try testing.expect(readVarInt(i8, &[_]u8{0xff}, .big) == -1);
    try testing.expect(readVarInt(i8, &[_]u8{0xfe}, .little) == -2);
    try testing.expect(readVarInt(i16, &[_]u8{ 0xff, 0xfd }, .big) == -3);
    try testing.expect(readVarInt(i16, &[_]u8{ 0xfc, 0xff }, .little) == -4);

    // Return type can be oversized (bytes.len * 8 < @typeInfo(ReturnType).int.bits)
    try testing.expect(readVarInt(u9, &[_]u8{0x12}, .little) == 0x12);
    try testing.expect(readVarInt(u9, &[_]u8{0xde}, .big) == 0xde);
    try testing.expect(readVarInt(u80, &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x24 }, .big) == 0x123456789abcdef024);
    try testing.expect(readVarInt(u80, &[_]u8{ 0xec, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe }, .little) == 0xfedcba9876543210ec);

    try testing.expect(readVarInt(i9, &[_]u8{0xff}, .big) == 0xff);
    try testing.expect(readVarInt(i9, &[_]u8{0xfe}, .little) == 0xfe);
}

/// Loads an integer from packed memory with provided bit_count, bit_offset, and signedness.
/// Asserts that T is large enough to store the read value.
pub fn readVarPackedInt(
    comptime T: type,
    bytes: []const u8,
    bit_offset: usize,
    bit_count: usize,
    endian: std.builtin.Endian,
    signedness: std.builtin.Signedness,
) T {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const iN = std.meta.Int(.signed, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const read_size = (bit_count + (bit_offset % 8) + 7) / 8;
    const bit_shift = @as(u3, @intCast(bit_offset % 8));
    const pad = @as(Log2N, @intCast(@bitSizeOf(T) - bit_count));

    const lowest_byte = switch (endian) {
        .big => bytes.len - (bit_offset / 8) - read_size,
        .little => bit_offset / 8,
    };
    const read_bytes = bytes[lowest_byte..][0..read_size];

    if (@bitSizeOf(T) <= 8) {
        // These are the same shifts/masks we perform below, but adds `@truncate`/`@intCast`
        // where needed since int is smaller than a byte.
        const value = if (read_size == 1) b: {
            break :b @as(uN, @truncate(read_bytes[0] >> bit_shift));
        } else b: {
            const i: u1 = @intFromBool(endian == .big);
            const head = @as(uN, @truncate(read_bytes[i] >> bit_shift));
            const tail_shift = @as(Log2N, @intCast(@as(u4, 8) - bit_shift));
            const tail = @as(uN, @truncate(read_bytes[1 - i]));
            break :b (tail << tail_shift) | head;
        };
        switch (signedness) {
            .signed => return @as(T, @intCast((@as(iN, @bitCast(value)) << pad) >> pad)),
            .unsigned => return @as(T, @intCast((@as(uN, @bitCast(value)) << pad) >> pad)),
        }
    }

    // Copy the value out (respecting endianness), accounting for bit_shift
    var int: uN = 0;
    switch (endian) {
        .big => {
            for (read_bytes[0 .. read_size - 1]) |elem| {
                int = elem | (int << 8);
            }
            int = (read_bytes[read_size - 1] >> bit_shift) | (int << (@as(u4, 8) - bit_shift));
        },
        .little => {
            int = read_bytes[0] >> bit_shift;
            for (read_bytes[1..], 0..) |elem, i| {
                int |= (@as(uN, elem) << @as(Log2N, @intCast((8 * (i + 1) - bit_shift))));
            }
        },
    }
    switch (signedness) {
        .signed => return @as(T, @intCast((@as(iN, @bitCast(int)) << pad) >> pad)),
        .unsigned => return @as(T, @intCast((@as(uN, @bitCast(int)) << pad) >> pad)),
    }
}

test readVarPackedInt {
    const T = packed struct(u16) { a: u3, b: u7, c: u6 };
    var st = T{ .a = 1, .b = 2, .c = 4 };
    const b_field = readVarPackedInt(u64, std.mem.asBytes(&st), @bitOffsetOf(T, "b"), 7, builtin.cpu.arch.endian(), .unsigned);
    try std.testing.expectEqual(st.b, b_field);
}

/// Reads an integer from memory with bit count specified by T.
/// The bit count of T must be evenly divisible by 8.
/// This function cannot fail and cannot cause undefined behavior.
pub inline fn readInt(comptime T: type, buffer: *const [@divExact(@typeInfo(T).int.bits, 8)]u8, endian: Endian) T {
    const value: T = @bitCast(buffer.*);
    return if (endian == native_endian) value else @byteSwap(value);
}

test readInt {
    try testing.expect(readInt(u0, &[_]u8{}, .big) == 0x0);
    try testing.expect(readInt(u0, &[_]u8{}, .little) == 0x0);

    try testing.expect(readInt(u8, &[_]u8{0x32}, .big) == 0x32);
    try testing.expect(readInt(u8, &[_]u8{0x12}, .little) == 0x12);

    try testing.expect(readInt(u16, &[_]u8{ 0x12, 0x34 }, .big) == 0x1234);
    try testing.expect(readInt(u16, &[_]u8{ 0x12, 0x34 }, .little) == 0x3412);

    try testing.expect(readInt(u72, &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x24 }, .big) == 0x123456789abcdef024);
    try testing.expect(readInt(u72, &[_]u8{ 0xec, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe }, .little) == 0xfedcba9876543210ec);

    try testing.expect(readInt(i8, &[_]u8{0xff}, .big) == -1);
    try testing.expect(readInt(i8, &[_]u8{0xfe}, .little) == -2);

    try testing.expect(readInt(i16, &[_]u8{ 0xff, 0xfd }, .big) == -3);
    try testing.expect(readInt(i16, &[_]u8{ 0xfc, 0xff }, .little) == -4);

    try moreReadIntTests();
    try comptime moreReadIntTests();
}

fn readPackedIntLittle(comptime T: type, bytes: []const u8, bit_offset: usize) T {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @intCast(bit_offset % 8));

    const load_size = (bit_count + 7) / 8;
    const load_tail_bits = @as(u3, @intCast((load_size * 8) - bit_count));
    const LoadInt = std.meta.Int(.unsigned, load_size * 8);

    if (bit_count == 0)
        return 0;

    // Read by loading a LoadInt, and then follow it up with a 1-byte read
    // of the tail if bit_offset pushed us over a byte boundary.
    const read_bytes = bytes[bit_offset / 8 ..];
    const val = @as(uN, @truncate(readInt(LoadInt, read_bytes[0..load_size], .little) >> bit_shift));
    if (bit_shift > load_tail_bits) {
        const tail_bits = @as(Log2N, @intCast(bit_shift - load_tail_bits));
        const tail_byte = read_bytes[load_size];
        const tail_truncated = if (bit_count < 8) @as(uN, @truncate(tail_byte)) else @as(uN, tail_byte);
        return @as(T, @bitCast(val | (tail_truncated << (@as(Log2N, @truncate(bit_count)) -% tail_bits))));
    } else return @as(T, @bitCast(val));
}

fn readPackedIntBig(comptime T: type, bytes: []const u8, bit_offset: usize) T {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @intCast(bit_offset % 8));
    const byte_count = (@as(usize, bit_shift) + bit_count + 7) / 8;

    const load_size = (bit_count + 7) / 8;
    const load_tail_bits = @as(u3, @intCast((load_size * 8) - bit_count));
    const LoadInt = std.meta.Int(.unsigned, load_size * 8);

    if (bit_count == 0)
        return 0;

    // Read by loading a LoadInt, and then follow it up with a 1-byte read
    // of the tail if bit_offset pushed us over a byte boundary.
    const end = bytes.len - (bit_offset / 8);
    const read_bytes = bytes[(end - byte_count)..end];
    const val = @as(uN, @truncate(readInt(LoadInt, bytes[(end - load_size)..end][0..load_size], .big) >> bit_shift));
    if (bit_shift > load_tail_bits) {
        const tail_bits = @as(Log2N, @intCast(bit_shift - load_tail_bits));
        const tail_byte = if (bit_count < 8) @as(uN, @truncate(read_bytes[0])) else @as(uN, read_bytes[0]);
        return @as(T, @bitCast(val | (tail_byte << (@as(Log2N, @truncate(bit_count)) -% tail_bits))));
    } else return @as(T, @bitCast(val));
}

pub const readPackedIntNative = switch (native_endian) {
    .little => readPackedIntLittle,
    .big => readPackedIntBig,
};

pub const readPackedIntForeign = switch (native_endian) {
    .little => readPackedIntBig,
    .big => readPackedIntLittle,
};

/// Loads an integer from packed memory.
/// Asserts that buffer contains at least bit_offset + @bitSizeOf(T) bits.
pub fn readPackedInt(comptime T: type, bytes: []const u8, bit_offset: usize, endian: Endian) T {
    switch (endian) {
        .little => return readPackedIntLittle(T, bytes, bit_offset),
        .big => return readPackedIntBig(T, bytes, bit_offset),
    }
}

test readPackedInt {
    const T = packed struct(u16) { a: u3, b: u7, c: u6 };
    var st = T{ .a = 1, .b = 2, .c = 4 };
    const b_field = readPackedInt(u7, std.mem.asBytes(&st), @bitOffsetOf(T, "b"), builtin.cpu.arch.endian());
    try std.testing.expectEqual(st.b, b_field);
}

test "comptime read/write int" {
    comptime {
        var bytes: [2]u8 = undefined;
        writeInt(u16, &bytes, 0x1234, .little);
        const result = readInt(u16, &bytes, .big);
        try testing.expect(result == 0x3412);
    }
    comptime {
        var bytes: [2]u8 = undefined;
        writeInt(u16, &bytes, 0x1234, .big);
        const result = readInt(u16, &bytes, .little);
        try testing.expect(result == 0x3412);
    }
}

/// Writes an integer to memory, storing it in twos-complement.
/// This function always succeeds, has defined behavior for all inputs, but
/// the integer bit width must be divisible by 8.
pub inline fn writeInt(comptime T: type, buffer: *[@divExact(@typeInfo(T).int.bits, 8)]u8, value: T, endian: Endian) void {
    buffer.* = @bitCast(if (endian == native_endian) value else @byteSwap(value));
}

test writeInt {
    var buf0: [0]u8 = undefined;
    var buf1: [1]u8 = undefined;
    var buf2: [2]u8 = undefined;
    var buf9: [9]u8 = undefined;

    writeInt(u0, &buf0, 0x0, .big);
    try testing.expect(eql(u8, buf0[0..], &[_]u8{}));
    writeInt(u0, &buf0, 0x0, .little);
    try testing.expect(eql(u8, buf0[0..], &[_]u8{}));

    writeInt(u8, &buf1, 0x12, .big);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0x12}));
    writeInt(u8, &buf1, 0x34, .little);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0x34}));

    writeInt(u16, &buf2, 0x1234, .big);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0x12, 0x34 }));
    writeInt(u16, &buf2, 0x5678, .little);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0x78, 0x56 }));

    writeInt(u72, &buf9, 0x123456789abcdef024, .big);
    try testing.expect(eql(u8, buf9[0..], &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x24 }));
    writeInt(u72, &buf9, 0xfedcba9876543210ec, .little);
    try testing.expect(eql(u8, buf9[0..], &[_]u8{ 0xec, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe }));

    writeInt(i8, &buf1, -1, .big);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0xff}));
    writeInt(i8, &buf1, -2, .little);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0xfe}));

    writeInt(i16, &buf2, -3, .big);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0xff, 0xfd }));
    writeInt(i16, &buf2, -4, .little);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0xfc, 0xff }));
}

fn writePackedIntLittle(comptime T: type, bytes: []u8, bit_offset: usize, value: T) void {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @intCast(bit_offset % 8));

    const store_size = (@bitSizeOf(T) + 7) / 8;
    const store_tail_bits = @as(u3, @intCast((store_size * 8) - bit_count));
    const StoreInt = std.meta.Int(.unsigned, store_size * 8);

    if (bit_count == 0)
        return;

    // Write by storing a StoreInt, and then follow it up with a 1-byte tail
    // if bit_offset pushed us over a byte boundary.
    const write_bytes = bytes[bit_offset / 8 ..];
    const head = write_bytes[0] & ((@as(u8, 1) << bit_shift) - 1);

    var write_value = (@as(StoreInt, @as(uN, @bitCast(value))) << bit_shift) | @as(StoreInt, @intCast(head));
    if (bit_shift > store_tail_bits) {
        const tail_len = @as(Log2N, @intCast(bit_shift - store_tail_bits));
        write_bytes[store_size] &= ~((@as(u8, 1) << @as(u3, @intCast(tail_len))) - 1);
        write_bytes[store_size] |= @as(u8, @intCast((@as(uN, @bitCast(value)) >> (@as(Log2N, @truncate(bit_count)) -% tail_len))));
    } else if (bit_shift < store_tail_bits) {
        const tail_len = store_tail_bits - bit_shift;
        const tail = write_bytes[store_size - 1] & (@as(u8, 0xfe) << (7 - tail_len));
        write_value |= @as(StoreInt, tail) << (8 * (store_size - 1));
    }

    writeInt(StoreInt, write_bytes[0..store_size], write_value, .little);
}

fn writePackedIntBig(comptime T: type, bytes: []u8, bit_offset: usize, value: T) void {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @intCast(bit_offset % 8));
    const byte_count = (bit_shift + bit_count + 7) / 8;

    const store_size = (@bitSizeOf(T) + 7) / 8;
    const store_tail_bits = @as(u3, @intCast((store_size * 8) - bit_count));
    const StoreInt = std.meta.Int(.unsigned, store_size * 8);

    if (bit_count == 0)
        return;

    // Write by storing a StoreInt, and then follow it up with a 1-byte tail
    // if bit_offset pushed us over a byte boundary.
    const end = bytes.len - (bit_offset / 8);
    const write_bytes = bytes[(end - byte_count)..end];
    const head = write_bytes[byte_count - 1] & ((@as(u8, 1) << bit_shift) - 1);

    var write_value = (@as(StoreInt, @as(uN, @bitCast(value))) << bit_shift) | @as(StoreInt, @intCast(head));
    if (bit_shift > store_tail_bits) {
        const tail_len = @as(Log2N, @intCast(bit_shift - store_tail_bits));
        write_bytes[0] &= ~((@as(u8, 1) << @as(u3, @intCast(tail_len))) - 1);
        write_bytes[0] |= @as(u8, @intCast((@as(uN, @bitCast(value)) >> (@as(Log2N, @truncate(bit_count)) -% tail_len))));
    } else if (bit_shift < store_tail_bits) {
        const tail_len = store_tail_bits - bit_shift;
        const tail = write_bytes[0] & (@as(u8, 0xfe) << (7 - tail_len));
        write_value |= @as(StoreInt, tail) << (8 * (store_size - 1));
    }

    writeInt(StoreInt, write_bytes[(byte_count - store_size)..][0..store_size], write_value, .big);
}

pub const writePackedIntNative = switch (native_endian) {
    .little => writePackedIntLittle,
    .big => writePackedIntBig,
};

pub const writePackedIntForeign = switch (native_endian) {
    .little => writePackedIntBig,
    .big => writePackedIntLittle,
};

/// Stores an integer to packed memory.
/// Asserts that buffer contains at least bit_offset + @bitSizeOf(T) bits.
pub fn writePackedInt(comptime T: type, bytes: []u8, bit_offset: usize, value: T, endian: Endian) void {
    switch (endian) {
        .little => writePackedIntLittle(T, bytes, bit_offset, value),
        .big => writePackedIntBig(T, bytes, bit_offset, value),
    }
}

test writePackedInt {
    const T = packed struct(u16) { a: u3, b: u7, c: u6 };
    var st = T{ .a = 1, .b = 2, .c = 4 };
    writePackedInt(u7, std.mem.asBytes(&st), @bitOffsetOf(T, "b"), 0x7f, builtin.cpu.arch.endian());
    try std.testing.expectEqual(T{ .a = 1, .b = 0x7f, .c = 4 }, st);
}

/// Stores an integer to packed memory with provided bit_offset, bit_count, and signedness.
/// If negative, the written value is sign-extended.
pub fn writeVarPackedInt(bytes: []u8, bit_offset: usize, bit_count: usize, value: anytype, endian: std.builtin.Endian) void {
    const T = @TypeOf(value);
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));

    const bit_shift = @as(u3, @intCast(bit_offset % 8));
    const write_size = (bit_count + bit_shift + 7) / 8;
    const lowest_byte = switch (endian) {
        .big => bytes.len - (bit_offset / 8) - write_size,
        .little => bit_offset / 8,
    };
    const write_bytes = bytes[lowest_byte..][0..write_size];

    if (write_size == 0) {
        return;
    } else if (write_size == 1) {
        // Single byte writes are handled specially, since we need to mask bits
        // on both ends of the byte.
        const mask = (@as(u8, 0xff) >> @as(u3, @intCast(8 - bit_count)));
        const new_bits = @as(u8, @intCast(@as(uN, @bitCast(value)) & mask)) << bit_shift;
        write_bytes[0] = (write_bytes[0] & ~(mask << bit_shift)) | new_bits;
        return;
    }

    var remaining: T = value;

    // Iterate bytes forward for Little-endian, backward for Big-endian
    const delta: i2 = if (endian == .big) -1 else 1;
    const start = if (endian == .big) @as(isize, @intCast(write_bytes.len - 1)) else 0;

    var i: isize = start; // isize for signed index arithmetic

    // Write first byte, using a mask to protects bits preceding bit_offset
    const head_mask = @as(u8, 0xff) >> bit_shift;
    write_bytes[@intCast(i)] &= ~(head_mask << bit_shift);
    write_bytes[@intCast(i)] |= @as(u8, @intCast(@as(uN, @bitCast(remaining)) & head_mask)) << bit_shift;
    remaining = math.shr(T, remaining, @as(u4, 8) - bit_shift);
    i += delta;

    // Write bytes[1..bytes.len - 1]
    if (@bitSizeOf(T) > 8) {
        const loop_end = start + delta * (@as(isize, @intCast(write_size)) - 1);
        while (i != loop_end) : (i += delta) {
            write_bytes[@as(usize, @intCast(i))] = @as(u8, @truncate(@as(uN, @bitCast(remaining))));
            remaining >>= 8;
        }
    }

    // Write last byte, using a mask to protect bits following bit_offset + bit_count
    const following_bits = -%@as(u3, @truncate(bit_shift + bit_count));
    const tail_mask = (@as(u8, 0xff) << following_bits) >> following_bits;
    write_bytes[@as(usize, @intCast(i))] &= ~tail_mask;
    write_bytes[@as(usize, @intCast(i))] |= @as(u8, @intCast(@as(uN, @bitCast(remaining)) & tail_mask));
}

test writeVarPackedInt {
    const T = packed struct(u16) { a: u3, b: u7, c: u6 };
    var st = T{ .a = 1, .b = 2, .c = 4 };
    const value: u64 = 0x7f;
    writeVarPackedInt(std.mem.asBytes(&st), @bitOffsetOf(T, "b"), 7, value, builtin.cpu.arch.endian());
    try testing.expectEqual(T{ .a = 1, .b = value, .c = 4 }, st);
}

/// Swap the byte order of all the members of the fields of a struct
/// (Changing their endianness)
pub fn byteSwapAllFields(comptime S: type, ptr: *S) void {
    switch (@typeInfo(S)) {
        .@"struct" => {
            inline for (std.meta.fields(S)) |f| {
                switch (@typeInfo(f.type)) {
                    .@"struct" => |struct_info| if (struct_info.backing_integer) |Int| {
                        @field(ptr, f.name) = @bitCast(@byteSwap(@as(Int, @bitCast(@field(ptr, f.name)))));
                    } else {
                        byteSwapAllFields(f.type, &@field(ptr, f.name));
                    },
                    .array => byteSwapAllFields(f.type, &@field(ptr, f.name)),
                    .@"enum" => {
                        @field(ptr, f.name) = @enumFromInt(@byteSwap(@intFromEnum(@field(ptr, f.name))));
                    },
                    .bool => {},
                    .float => |float_info| {
                        @field(ptr, f.name) = @bitCast(@byteSwap(@as(std.meta.Int(.unsigned, float_info.bits), @bitCast(@field(ptr, f.name)))));
                    },
                    else => {
                        @field(ptr, f.name) = @byteSwap(@field(ptr, f.name));
                    },
                }
            }
        },
        .array => {
            for (ptr) |*item| {
                switch (@typeInfo(@TypeOf(item.*))) {
                    .@"struct", .array => byteSwapAllFields(@TypeOf(item.*), item),
                    .@"enum" => {
                        item.* = @enumFromInt(@byteSwap(@intFromEnum(item.*)));
                    },
                    .bool => {},
                    .float => |float_info| {
                        item.* = @bitCast(@byteSwap(@as(std.meta.Int(.unsigned, float_info.bits), @bitCast(item.*))));
                    },
                    else => {
                        item.* = @byteSwap(item.*);
                    },
                }
            }
        },
        else => @compileError("byteSwapAllFields expects a struct or array as the first argument"),
    }
}

test byteSwapAllFields {
    const T = extern struct {
        f0: u8,
        f1: u16,
        f2: u32,
        f3: [1]u8,
        f4: bool,
        f5: f32,
    };
    const K = extern struct {
        f0: u8,
        f1: T,
        f2: u16,
        f3: [1]u8,
        f4: bool,
        f5: f32,
    };
    var s = T{
        .f0 = 0x12,
        .f1 = 0x1234,
        .f2 = 0x12345678,
        .f3 = .{0x12},
        .f4 = true,
        .f5 = @as(f32, @bitCast(@as(u32, 0x4640e400))),
    };
    var k = K{
        .f0 = 0x12,
        .f1 = s,
        .f2 = 0x1234,
        .f3 = .{0x12},
        .f4 = false,
        .f5 = @as(f32, @bitCast(@as(u32, 0x45d42800))),
    };
    byteSwapAllFields(T, &s);
    byteSwapAllFields(K, &k);
    try std.testing.expectEqual(T{
        .f0 = 0x12,
        .f1 = 0x3412,
        .f2 = 0x78563412,
        .f3 = .{0x12},
        .f4 = true,
        .f5 = @as(f32, @bitCast(@as(u32, 0x00e44046))),
    }, s);
    try std.testing.expectEqual(K{
        .f0 = 0x12,
        .f1 = s,
        .f2 = 0x3412,
        .f3 = .{0x12},
        .f4 = false,
        .f5 = @as(f32, @bitCast(@as(u32, 0x0028d445))),
    }, k);
}

pub const tokenize = @compileError("deprecated; use tokenizeAny, tokenizeSequence, or tokenizeScalar");

/// Returns an iterator that iterates over the slices of `buffer` that are not
/// any of the items in `delimiters`.
///
/// `tokenizeAny(u8, "   abc|def ||  ghi  ", " |")` will return slices
/// for "abc", "def", "ghi", null, in that order.
///
/// If `buffer` is empty, the iterator will return null.
/// If none of `delimiters` exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `tokenizeSequence`, `tokenizeScalar`,
///           `splitSequence`,`splitAny`, `splitScalar`,
///           `splitBackwardsSequence`, `splitBackwardsAny`, and `splitBackwardsScalar`
pub fn tokenizeAny(comptime T: type, buffer: []const T, delimiters: []const T) TokenIterator(T, .any) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiters,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that are not
/// the sequence in `delimiter`.
///
/// `tokenizeSequence(u8, "<>abc><def<><>ghi", "<>")` will return slices
/// for "abc><def", "ghi", null, in that order.
///
/// If `buffer` is empty, the iterator will return null.
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
/// The delimiter length must not be zero.
///
/// See also: `tokenizeAny`, `tokenizeScalar`,
///           `splitSequence`,`splitAny`, and `splitScalar`
///           `splitBackwardsSequence`, `splitBackwardsAny`, and `splitBackwardsScalar`
pub fn tokenizeSequence(comptime T: type, buffer: []const T, delimiter: []const T) TokenIterator(T, .sequence) {
    assert(delimiter.len != 0);
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that are not
/// `delimiter`.
///
/// `tokenizeScalar(u8, "   abc def     ghi  ", ' ')` will return slices
/// for "abc", "def", "ghi", null, in that order.
///
/// If `buffer` is empty, the iterator will return null.
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `tokenizeAny`, `tokenizeSequence`,
///           `splitSequence`,`splitAny`, and `splitScalar`
///           `splitBackwardsSequence`, `splitBackwardsAny`, and `splitBackwardsScalar`
pub fn tokenizeScalar(comptime T: type, buffer: []const T, delimiter: T) TokenIterator(T, .scalar) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

test tokenizeScalar {
    var it = tokenizeScalar(u8, "   abc def   ghi  ", ' ');
    try testing.expect(eql(u8, it.next().?, "abc"));
    try testing.expect(eql(u8, it.peek().?, "def"));
    try testing.expect(eql(u8, it.next().?, "def"));
    try testing.expect(eql(u8, it.next().?, "ghi"));
    try testing.expect(it.next() == null);

    it = tokenizeScalar(u8, "..\\bob", '\\');
    try testing.expect(eql(u8, it.next().?, ".."));
    try testing.expect(eql(u8, "..", "..\\bob"[0..it.index]));
    try testing.expect(eql(u8, it.next().?, "bob"));
    try testing.expect(it.next() == null);

    it = tokenizeScalar(u8, "//a/b", '/');
    try testing.expect(eql(u8, it.next().?, "a"));
    try testing.expect(eql(u8, it.next().?, "b"));
    try testing.expect(eql(u8, "//a/b", "//a/b"[0..it.index]));
    try testing.expect(it.next() == null);

    it = tokenizeScalar(u8, "|", '|');
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    it = tokenizeScalar(u8, "", '|');
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    it = tokenizeScalar(u8, "hello", ' ');
    try testing.expect(eql(u8, it.next().?, "hello"));
    try testing.expect(it.next() == null);

    var it16 = tokenizeScalar(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("hello"),
        ' ',
    );
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("hello")));
    try testing.expect(it16.next() == null);
}

test tokenizeAny {
    var it = tokenizeAny(u8, "a|b,c/d e", " /,|");
    try testing.expect(eql(u8, it.next().?, "a"));
    try testing.expect(eql(u8, it.peek().?, "b"));
    try testing.expect(eql(u8, it.next().?, "b"));
    try testing.expect(eql(u8, it.next().?, "c"));
    try testing.expect(eql(u8, it.next().?, "d"));
    try testing.expect(eql(u8, it.next().?, "e"));
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    it = tokenizeAny(u8, "hello", "");
    try testing.expect(eql(u8, it.next().?, "hello"));
    try testing.expect(it.next() == null);

    var it16 = tokenizeAny(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("a|b,c/d e"),
        std.unicode.utf8ToUtf16LeStringLiteral(" /,|"),
    );
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("a")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("b")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("c")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("d")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("e")));
    try testing.expect(it16.next() == null);
}

test tokenizeSequence {
    var it = tokenizeSequence(u8, "a<>b<><>c><>d><", "<>");
    try testing.expectEqualStrings("a", it.next().?);
    try testing.expectEqualStrings("b", it.peek().?);
    try testing.expectEqualStrings("b", it.next().?);
    try testing.expectEqualStrings("c>", it.next().?);
    try testing.expectEqualStrings("d><", it.next().?);
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    var it16 = tokenizeSequence(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("a<>b<><>c><>d><"),
        std.unicode.utf8ToUtf16LeStringLiteral("<>"),
    );
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("a")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("b")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("c>")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("d><")));
    try testing.expect(it16.next() == null);
}

test "tokenize (reset)" {
    {
        var it = tokenizeAny(u8, "   abc def   ghi  ", " ");
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = tokenizeSequence(u8, "<><>abc<>def<><>ghi<>", "<>");
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = tokenizeScalar(u8, "   abc def   ghi  ", ' ');
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
}

pub const split = @compileError("deprecated; use splitSequence, splitAny, or splitScalar");

/// Returns an iterator that iterates over the slices of `buffer` that
/// are separated by the byte sequence in `delimiter`.
///
/// `splitSequence(u8, "abc||def||||ghi", "||")` will return slices
/// for "abc", "def", "", "ghi", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
/// The delimiter length must not be zero.
///
/// See also: `splitAny`, `splitScalar`, `splitBackwardsSequence`,
///           `splitBackwardsAny`,`splitBackwardsScalar`,
///           `tokenizeAny`, `tokenizeSequence`, and `tokenizeScalar`.
pub fn splitSequence(comptime T: type, buffer: []const T, delimiter: []const T) SplitIterator(T, .sequence) {
    assert(delimiter.len != 0);
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that
/// are separated by any item in `delimiters`.
///
/// `splitAny(u8, "abc,def||ghi", "|,")` will return slices
/// for "abc", "def", "", "ghi", null, in that order.
///
/// If none of `delimiters` exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `splitSequence`, `splitScalar`, `splitBackwardsSequence`,
///           `splitBackwardsAny`,`splitBackwardsScalar`,
///           `tokenizeAny`, `tokenizeSequence`, and `tokenizeScalar`.
pub fn splitAny(comptime T: type, buffer: []const T, delimiters: []const T) SplitIterator(T, .any) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiters,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that
/// are separated by `delimiter`.
///
/// `splitScalar(u8, "abc|def||ghi", '|')` will return slices
/// for "abc", "def", "", "ghi", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `splitSequence`, `splitAny`, `splitBackwardsSequence`,
///           `splitBackwardsAny`,`splitBackwardsScalar`,
///           `tokenizeAny`, `tokenizeSequence`, and `tokenizeScalar`.
pub fn splitScalar(comptime T: type, buffer: []const T, delimiter: T) SplitIterator(T, .scalar) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

test splitScalar {
    var it = splitScalar(u8, "abc|def||ghi", '|');
    try testing.expectEqualSlices(u8, it.rest(), "abc|def||ghi");
    try testing.expectEqualSlices(u8, it.first(), "abc");

    try testing.expectEqualSlices(u8, it.rest(), "def||ghi");
    try testing.expectEqualSlices(u8, it.peek().?, "def");
    try testing.expectEqualSlices(u8, it.next().?, "def");

    try testing.expectEqualSlices(u8, it.rest(), "|ghi");
    try testing.expectEqualSlices(u8, it.next().?, "");

    try testing.expectEqualSlices(u8, it.rest(), "ghi");
    try testing.expectEqualSlices(u8, it.peek().?, "ghi");
    try testing.expectEqualSlices(u8, it.next().?, "ghi");

    try testing.expectEqualSlices(u8, it.rest(), "");
    try testing.expect(it.peek() == null);
    try testing.expect(it.next() == null);

    it = splitScalar(u8, "", '|');
    try testing.expectEqualSlices(u8, it.first(), "");
    try testing.expect(it.next() == null);

    it = splitScalar(u8, "|", '|');
    try testing.expectEqualSlices(u8, it.first(), "");
    try testing.expectEqualSlices(u8, it.next().?, "");
    try testing.expect(it.peek() == null);
    try testing.expect(it.next() == null);

    it = splitScalar(u8, "hello", ' ');
    try testing.expectEqualSlices(u8, it.first(), "hello");
    try testing.expect(it.next() == null);

    var it16 = splitScalar(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("hello"),
        ' ',
    );
    try testing.expectEqualSlices(u16, it16.first(), std.unicode.utf8ToUtf16LeStringLiteral("hello"));
    try testing.expect(it16.next() == null);
}

test splitSequence {
    var it = splitSequence(u8, "a, b ,, c, d, e", ", ");
    try testing.expectEqualSlices(u8, it.first(), "a");
    try testing.expectEqualSlices(u8, it.rest(), "b ,, c, d, e");
    try testing.expectEqualSlices(u8, it.next().?, "b ,");
    try testing.expectEqualSlices(u8, it.next().?, "c");
    try testing.expectEqualSlices(u8, it.next().?, "d");
    try testing.expectEqualSlices(u8, it.next().?, "e");
    try testing.expect(it.next() == null);

    var it16 = splitSequence(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("a, b ,, c, d, e"),
        std.unicode.utf8ToUtf16LeStringLiteral(", "),
    );
    try testing.expectEqualSlices(u16, it16.first(), std.unicode.utf8ToUtf16LeStringLiteral("a"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("b ,"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("c"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("d"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("e"));
    try testing.expect(it16.next() == null);
}

test splitAny {
    var it = splitAny(u8, "a,b, c d e", ", ");
    try testing.expectEqualSlices(u8, it.first(), "a");
    try testing.expectEqualSlices(u8, it.rest(), "b, c d e");
    try testing.expectEqualSlices(u8, it.next().?, "b");
    try testing.expectEqualSlices(u8, it.next().?, "");
    try testing.expectEqualSlices(u8, it.next().?, "c");
    try testing.expectEqualSlices(u8, it.next().?, "d");
    try testing.expectEqualSlices(u8, it.next().?, "e");
    try testing.expect(it.next() == null);

    it = splitAny(u8, "hello", "");
    try testing.expect(eql(u8, it.next().?, "hello"));
    try testing.expect(it.next() == null);

    var it16 = splitAny(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("a,b, c d e"),
        std.unicode.utf8ToUtf16LeStringLiteral(", "),
    );
    try testing.expectEqualSlices(u16, it16.first(), std.unicode.utf8ToUtf16LeStringLiteral("a"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("b"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral(""));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("c"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("d"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("e"));
    try testing.expect(it16.next() == null);
}

test "split (reset)" {
    {
        var it = splitSequence(u8, "abc def ghi", " ");
        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = splitAny(u8, "abc def,ghi", " ,");
        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = splitScalar(u8, "abc def ghi", ' ');
        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
}

pub const splitBackwards = @compileError("deprecated; use splitBackwardsSequence, splitBackwardsAny, or splitBackwardsScalar");

/// Returns an iterator that iterates backwards over the slices of `buffer` that
/// are separated by the sequence in `delimiter`.
///
/// `splitBackwardsSequence(u8, "abc||def||||ghi", "||")` will return slices
/// for "ghi", "", "def", "abc", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
/// The delimiter length must not be zero.
///
/// See also: `splitBackwardsAny`, `splitBackwardsScalar`,
///           `splitSequence`, `splitAny`,`splitScalar`,
///           `tokenizeAny`, `tokenizeSequence`, and `tokenizeScalar`.
pub fn splitBackwardsSequence(comptime T: type, buffer: []const T, delimiter: []const T) SplitBackwardsIterator(T, .sequence) {
    assert(delimiter.len != 0);
    return .{
        .index = buffer.len,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

/// Returns an iterator that iterates backwards over the slices of `buffer` that
/// are separated by any item in `delimiters`.
///
/// `splitBackwardsAny(u8, "abc,def||ghi", "|,")` will return slices
/// for "ghi", "", "def", "abc", null, in that order.
///
/// If none of `delimiters` exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `splitBackwardsSequence`, `splitBackwardsScalar`,
///           `splitSequence`, `splitAny`,`splitScalar`,
///           `tokenizeAny`, `tokenizeSequence`, and `tokenizeScalar`.
pub fn splitBackwardsAny(comptime T: type, buffer: []const T, delimiters: []const T) SplitBackwardsIterator(T, .any) {
    return .{
        .index = buffer.len,
        .buffer = buffer,
        .delimiter = delimiters,
    };
}

/// Returns an iterator that iterates backwards over the slices of `buffer` that
/// are separated by `delimiter`.
///
/// `splitBackwardsScalar(u8, "abc|def||ghi", '|')` will return slices
/// for "ghi", "", "def", "abc", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `splitBackwardsSequence`, `splitBackwardsAny`,
///           `splitSequence`, `splitAny`,`splitScalar`,
///           `tokenizeAny`, `tokenizeSequence`, and `tokenizeScalar`.
pub fn splitBackwardsScalar(comptime T: type, buffer: []const T, delimiter: T) SplitBackwardsIterator(T, .scalar) {
    return .{
        .index = buffer.len,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

test splitBackwardsScalar {
    var it = splitBackwardsScalar(u8, "abc|def||ghi", '|');
    try testing.expectEqualSlices(u8, it.rest(), "abc|def||ghi");
    try testing.expectEqualSlices(u8, it.first(), "ghi");

    try testing.expectEqualSlices(u8, it.rest(), "abc|def|");
    try testing.expectEqualSlices(u8, it.next().?, "");

    try testing.expectEqualSlices(u8, it.rest(), "abc|def");
    try testing.expectEqualSlices(u8, it.next().?, "def");

    try testing.expectEqualSlices(u8, it.rest(), "abc");
    try testing.expectEqualSlices(u8, it.next().?, "abc");

    try testing.expectEqualSlices(u8, it.rest(), "");
    try testing.expect(it.next() == null);

    it = splitBackwardsScalar(u8, "", '|');
    try testing.expectEqualSlices(u8, it.first(), "");
    try testing.expect(it.next() == null);

    it = splitBackwardsScalar(u8, "|", '|');
    try testing.expectEqualSlices(u8, it.first(), "");
    try testing.expectEqualSlices(u8, it.next().?, "");
    try testing.expect(it.next() == null);

    it = splitBackwardsScalar(u8, "hello", ' ');
    try testing.expectEqualSlices(u8, it.first(), "hello");
    try testing.expect(it.next() == null);

    var it16 = splitBackwardsScalar(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("hello"),
        ' ',
    );
    try testing.expectEqualSlices(u16, it16.first(), std.unicode.utf8ToUtf16LeStringLiteral("hello"));
    try testing.expect(it16.next() == null);
}

test splitBackwardsSequence {
    var it = splitBackwardsSequence(u8, "a, b ,, c, d, e", ", ");
    try testing.expectEqualSlices(u8, it.rest(), "a, b ,, c, d, e");
    try testing.expectEqualSlices(u8, it.first(), "e");

    try testing.expectEqualSlices(u8, it.rest(), "a, b ,, c, d");
    try testing.expectEqualSlices(u8, it.next().?, "d");

    try testing.expectEqualSlices(u8, it.rest(), "a, b ,, c");
    try testing.expectEqualSlices(u8, it.next().?, "c");

    try testing.expectEqualSlices(u8, it.rest(), "a, b ,");
    try testing.expectEqualSlices(u8, it.next().?, "b ,");

    try testing.expectEqualSlices(u8, it.rest(), "a");
    try testing.expectEqualSlices(u8, it.next().?, "a");

    try testing.expectEqualSlices(u8, it.rest(), "");
    try testing.expect(it.next() == null);

    var it16 = splitBackwardsSequence(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("a, b ,, c, d, e"),
        std.unicode.utf8ToUtf16LeStringLiteral(", "),
    );
    try testing.expectEqualSlices(u16, it16.first(), std.unicode.utf8ToUtf16LeStringLiteral("e"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("d"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("c"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("b ,"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("a"));
    try testing.expect(it16.next() == null);
}

test splitBackwardsAny {
    var it = splitBackwardsAny(u8, "a,b, c d e", ", ");
    try testing.expectEqualSlices(u8, it.rest(), "a,b, c d e");
    try testing.expectEqualSlices(u8, it.first(), "e");

    try testing.expectEqualSlices(u8, it.rest(), "a,b, c d");
    try testing.expectEqualSlices(u8, it.next().?, "d");

    try testing.expectEqualSlices(u8, it.rest(), "a,b, c");
    try testing.expectEqualSlices(u8, it.next().?, "c");

    try testing.expectEqualSlices(u8, it.rest(), "a,b,");
    try testing.expectEqualSlices(u8, it.next().?, "");

    try testing.expectEqualSlices(u8, it.rest(), "a,b");
    try testing.expectEqualSlices(u8, it.next().?, "b");

    try testing.expectEqualSlices(u8, it.rest(), "a");
    try testing.expectEqualSlices(u8, it.next().?, "a");

    try testing.expectEqualSlices(u8, it.rest(), "");
    try testing.expect(it.next() == null);

    var it16 = splitBackwardsAny(
        u16,
        std.unicode.utf8ToUtf16LeStringLiteral("a,b, c d e"),
        std.unicode.utf8ToUtf16LeStringLiteral(", "),
    );
    try testing.expectEqualSlices(u16, it16.first(), std.unicode.utf8ToUtf16LeStringLiteral("e"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("d"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("c"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral(""));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("b"));
    try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("a"));
    try testing.expect(it16.next() == null);
}

test "splitBackwards (reset)" {
    {
        var it = splitBackwardsSequence(u8, "abc def ghi", " ");
        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(it.next() == null);
    }
    {
        var it = splitBackwardsAny(u8, "abc def,ghi", " ,");
        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(it.next() == null);
    }
    {
        var it = splitBackwardsScalar(u8, "abc def ghi", ' ');
        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(it.next() == null);
    }
}

/// Returns an iterator with a sliding window of slices for `buffer`.
/// The sliding window has length `size` and on every iteration moves
/// forward by `advance`.
///
/// Extract data for moving average with:
/// `window(u8, "abcdefg", 3, 1)` will return slices
/// "abc", "bcd", "cde", "def", "efg", null, in that order.
///
/// Chunk or split every N items with:
/// `window(u8, "abcdefg", 3, 3)` will return slices
/// "abc", "def", "g", null, in that order.
///
/// Pick every even index with:
/// `window(u8, "abcdefg", 1, 2)` will return slices
/// "a", "c", "e", "g" null, in that order.
///
/// The `size` and `advance` must be not be zero.
pub fn window(comptime T: type, buffer: []const T, size: usize, advance: usize) WindowIterator(T) {
    assert(size != 0);
    assert(advance != 0);
    return .{
        .index = 0,
        .buffer = buffer,
        .size = size,
        .advance = advance,
    };
}

test window {
    {
        // moving average size 3
        var it = window(u8, "abcdefg", 3, 1);
        try testing.expectEqualSlices(u8, it.next().?, "abc");
        try testing.expectEqualSlices(u8, it.next().?, "bcd");
        try testing.expectEqualSlices(u8, it.next().?, "cde");
        try testing.expectEqualSlices(u8, it.next().?, "def");
        try testing.expectEqualSlices(u8, it.next().?, "efg");
        try testing.expectEqual(it.next(), null);

        // multibyte
        var it16 = window(u16, std.unicode.utf8ToUtf16LeStringLiteral("abcdefg"), 3, 1);
        try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("abc"));
        try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("bcd"));
        try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("cde"));
        try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("def"));
        try testing.expectEqualSlices(u16, it16.next().?, std.unicode.utf8ToUtf16LeStringLiteral("efg"));
        try testing.expectEqual(it16.next(), null);
    }

    {
        // chunk/split every 3
        var it = window(u8, "abcdefg", 3, 3);
        try testing.expectEqualSlices(u8, it.next().?, "abc");
        try testing.expectEqualSlices(u8, it.next().?, "def");
        try testing.expectEqualSlices(u8, it.next().?, "g");
        try testing.expectEqual(it.next(), null);
    }

    {
        // pick even
        var it = window(u8, "abcdefg", 1, 2);
        try testing.expectEqualSlices(u8, it.next().?, "a");
        try testing.expectEqualSlices(u8, it.next().?, "c");
        try testing.expectEqualSlices(u8, it.next().?, "e");
        try testing.expectEqualSlices(u8, it.next().?, "g");
        try testing.expectEqual(it.next(), null);
    }

    {
        // empty
        var it = window(u8, "", 1, 1);
        try testing.expectEqualSlices(u8, it.next().?, "");
        try testing.expectEqual(it.next(), null);

        it = window(u8, "", 10, 1);
        try testing.expectEqualSlices(u8, it.next().?, "");
        try testing.expectEqual(it.next(), null);

        it = window(u8, "", 1, 10);
        try testing.expectEqualSlices(u8, it.next().?, "");
        try testing.expectEqual(it.next(), null);

        it = window(u8, "", 10, 10);
        try testing.expectEqualSlices(u8, it.next().?, "");
        try testing.expectEqual(it.next(), null);
    }

    {
        // first
        var it = window(u8, "abcdefg", 3, 3);
        try testing.expectEqualSlices(u8, it.first(), "abc");
        it.reset();
        try testing.expectEqualSlices(u8, it.next().?, "abc");
    }

    {
        // reset
        var it = window(u8, "abcdefg", 3, 3);
        try testing.expectEqualSlices(u8, it.next().?, "abc");
        try testing.expectEqualSlices(u8, it.next().?, "def");
        try testing.expectEqualSlices(u8, it.next().?, "g");
        try testing.expectEqual(it.next(), null);

        it.reset();
        try testing.expectEqualSlices(u8, it.next().?, "abc");
        try testing.expectEqualSlices(u8, it.next().?, "def");
        try testing.expectEqualSlices(u8, it.next().?, "g");
        try testing.expectEqual(it.next(), null);
    }
}

pub fn WindowIterator(comptime T: type) type {
    return struct {
        buffer: []const T,
        index: ?usize,
        size: usize,
        advance: usize,

        const Self = @This();

        /// Returns a slice of the first window.
        /// Call this only to get the first window and then use `next` to get
        /// all subsequent windows.
        /// Asserts that iteration has not begun.
        pub fn first(self: *Self) []const T {
            assert(self.index.? == 0);
            return self.next().?;
        }

        /// Returns a slice of the next window, or null if window is at end.
        pub fn next(self: *Self) ?[]const T {
            const start = self.index orelse return null;
            const next_index = start + self.advance;
            const end = if (start + self.size < self.buffer.len and next_index < self.buffer.len) blk: {
                self.index = next_index;
                break :blk start + self.size;
            } else blk: {
                self.index = null;
                break :blk self.buffer.len;
            };

            return self.buffer[start..end];
        }

        /// Resets the iterator to the initial window.
        pub fn reset(self: *Self) void {
            self.index = 0;
        }
    };
}

pub fn startsWith(comptime T: type, haystack: []const T, needle: []const T) bool {
    return if (needle.len > haystack.len) false else eql(T, haystack[0..needle.len], needle);
}

test startsWith {
    try testing.expect(startsWith(u8, "Bob", "Bo"));
    try testing.expect(!startsWith(u8, "Needle in haystack", "haystack"));
}

pub fn endsWith(comptime T: type, haystack: []const T, needle: []const T) bool {
    return if (needle.len > haystack.len) false else eql(T, haystack[haystack.len - needle.len ..], needle);
}

test endsWith {
    try testing.expect(endsWith(u8, "Needle in haystack", "haystack"));
    try testing.expect(!endsWith(u8, "Bob", "Bo"));
}

pub const DelimiterType = enum { sequence, any, scalar };

pub fn TokenIterator(comptime T: type, comptime delimiter_type: DelimiterType) type {
    return struct {
        buffer: []const T,
        delimiter: switch (delimiter_type) {
            .sequence, .any => []const T,
            .scalar => T,
        },
        index: usize,

        const Self = @This();

        /// Returns a slice of the current token, or null if tokenization is
        /// complete, and advances to the next token.
        pub fn next(self: *Self) ?[]const T {
            const result = self.peek() orelse return null;
            self.index += result.len;
            return result;
        }

        /// Returns a slice of the current token, or null if tokenization is
        /// complete. Does not advance to the next token.
        pub fn peek(self: *Self) ?[]const T {
            // move to beginning of token
            while (self.index < self.buffer.len and self.isDelimiter(self.index)) : (self.index += switch (delimiter_type) {
                .sequence => self.delimiter.len,
                .any, .scalar => 1,
            }) {}
            const start = self.index;
            if (start == self.buffer.len) {
                return null;
            }

            // move to end of token
            var end = start;
            while (end < self.buffer.len and !self.isDelimiter(end)) : (end += 1) {}

            return self.buffer[start..end];
        }

        /// Returns a slice of the remaining bytes. Does not affect iterator state.
        pub fn rest(self: Self) []const T {
            // move to beginning of token
            var index: usize = self.index;
            while (index < self.buffer.len and self.isDelimiter(index)) : (index += switch (delimiter_type) {
                .sequence => self.delimiter.len,
                .any, .scalar => 1,
            }) {}
            return self.buffer[index..];
        }

        /// Resets the iterator to the initial token.
        pub fn reset(self: *Self) void {
            self.index = 0;
        }

        fn isDelimiter(self: Self, index: usize) bool {
            switch (delimiter_type) {
                .sequence => return startsWith(T, self.buffer[index..], self.delimiter),
                .any => {
                    const item = self.buffer[index];
                    for (self.delimiter) |delimiter_item| {
                        if (item == delimiter_item) {
                            return true;
                        }
                    }
                    return false;
                },
                .scalar => return self.buffer[index] == self.delimiter,
            }
        }
    };
}

pub fn SplitIterator(comptime T: type, comptime delimiter_type: DelimiterType) type {
    return struct {
        buffer: []const T,
        index: ?usize,
        delimiter: switch (delimiter_type) {
            .sequence, .any => []const T,
            .scalar => T,
        },

        const Self = @This();

        /// Returns a slice of the first field.
        /// Call this only to get the first field and then use `next` to get all subsequent fields.
        /// Asserts that iteration has not begun.
        pub fn first(self: *Self) []const T {
            assert(self.index.? == 0);
            return self.next().?;
        }

        /// Returns a slice of the next field, or null if splitting is complete.
        pub fn next(self: *Self) ?[]const T {
            const start = self.index orelse return null;
            const end = if (switch (delimiter_type) {
                .sequence => indexOfPos(T, self.buffer, start, self.delimiter),
                .any => indexOfAnyPos(T, self.buffer, start, self.delimiter),
                .scalar => indexOfScalarPos(T, self.buffer, start, self.delimiter),
            }) |delim_start| blk: {
                self.index = delim_start + switch (delimiter_type) {
                    .sequence => self.delimiter.len,
                    .any, .scalar => 1,
                };
                break :blk delim_start;
            } else blk: {
                self.index = null;
                break :blk self.buffer.len;
            };
            return self.buffer[start..end];
        }

        /// Returns a slice of the next field, or null if splitting is complete.
        /// This method does not alter self.index.
        pub fn peek(self: *Self) ?[]const T {
            const start = self.index orelse return null;
            const end = if (switch (delimiter_type) {
                .sequence => indexOfPos(T, self.buffer, start, self.delimiter),
                .any => indexOfAnyPos(T, self.buffer, start, self.delimiter),
                .scalar => indexOfScalarPos(T, self.buffer, start, self.delimiter),
            }) |delim_start| delim_start else self.buffer.len;
            return self.buffer[start..end];
        }

        /// Returns a slice of the remaining bytes. Does not affect iterator state.
        pub fn rest(self: Self) []const T {
            const end = self.buffer.len;
            const start = self.index orelse end;
            return self.buffer[start..end];
        }

        /// Resets the iterator to the initial slice.
        pub fn reset(self: *Self) void {
            self.index = 0;
        }
    };
}

pub fn SplitBackwardsIterator(comptime T: type, comptime delimiter_type: DelimiterType) type {
    return struct {
        buffer: []const T,
        index: ?usize,
        delimiter: switch (delimiter_type) {
            .sequence, .any => []const T,
            .scalar => T,
        },

        const Self = @This();

        /// Returns a slice of the first field.
        /// Call this only to get the first field and then use `next` to get all subsequent fields.
        /// Asserts that iteration has not begun.
        pub fn first(self: *Self) []const T {
            assert(self.index.? == self.buffer.len);
            return self.next().?;
        }

        /// Returns a slice of the next field, or null if splitting is complete.
        pub fn next(self: *Self) ?[]const T {
            const end = self.index orelse return null;
            const start = if (switch (delimiter_type) {
                .sequence => lastIndexOf(T, self.buffer[0..end], self.delimiter),
                .any => lastIndexOfAny(T, self.buffer[0..end], self.delimiter),
                .scalar => lastIndexOfScalar(T, self.buffer[0..end], self.delimiter),
            }) |delim_start| blk: {
                self.index = delim_start;
                break :blk delim_start + switch (delimiter_type) {
                    .sequence => self.delimiter.len,
                    .any, .scalar => 1,
                };
            } else blk: {
                self.index = null;
                break :blk 0;
            };
            return self.buffer[start..end];
        }

        /// Returns a slice of the remaining bytes. Does not affect iterator state.
        pub fn rest(self: Self) []const T {
            const end = self.index orelse 0;
            return self.buffer[0..end];
        }

        /// Resets the iterator to the initial slice.
        pub fn reset(self: *Self) void {
            self.index = self.buffer.len;
        }
    };
}

/// Naively combines a series of slices with a separator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn join(allocator: Allocator, separator: []const u8, slices: []const []const u8) Allocator.Error![]u8 {
    return joinMaybeZ(allocator, separator, slices, false);
}

/// Naively combines a series of slices with a separator and null terminator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn joinZ(allocator: Allocator, separator: []const u8, slices: []const []const u8) Allocator.Error![:0]u8 {
    const out = try joinMaybeZ(allocator, separator, slices, true);
    return out[0 .. out.len - 1 :0];
}

fn joinMaybeZ(allocator: Allocator, separator: []const u8, slices: []const []const u8, zero: bool) Allocator.Error![]u8 {
    if (slices.len == 0) return if (zero) try allocator.dupe(u8, &[1]u8{0}) else &[0]u8{};

    const total_len = blk: {
        var sum: usize = separator.len * (slices.len - 1);
        for (slices) |slice| sum += slice.len;
        if (zero) sum += 1;
        break :blk sum;
    };

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    @memcpy(buf[0..slices[0].len], slices[0]);
    var buf_index: usize = slices[0].len;
    for (slices[1..]) |slice| {
        @memcpy(buf[buf_index .. buf_index + separator.len], separator);
        buf_index += separator.len;
        @memcpy(buf[buf_index .. buf_index + slice.len], slice);
        buf_index += slice.len;
    }

    if (zero) buf[buf.len - 1] = 0;

    // No need for shrink since buf is exactly the correct size.
    return buf;
}

test join {
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, ""));
    }
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{ "a", "b", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,b,c"));
    }
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{"a"});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a"));
    }
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{ "a", "", "b", "", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,,b,,c"));
    }
}

test joinZ {
    {
        const str = try joinZ(testing.allocator, ",", &[_][]const u8{});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, ""));
        try testing.expectEqual(str[str.len], 0);
    }
    {
        const str = try joinZ(testing.allocator, ",", &[_][]const u8{ "a", "b", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,b,c"));
        try testing.expectEqual(str[str.len], 0);
    }
    {
        const str = try joinZ(testing.allocator, ",", &[_][]const u8{"a"});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a"));
        try testing.expectEqual(str[str.len], 0);
    }
    {
        const str = try joinZ(testing.allocator, ",", &[_][]const u8{ "a", "", "b", "", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,,b,,c"));
        try testing.expectEqual(str[str.len], 0);
    }
}

/// Copies each T from slices into a new slice that exactly holds all the elements.
pub fn concat(allocator: Allocator, comptime T: type, slices: []const []const T) Allocator.Error![]T {
    return concatMaybeSentinel(allocator, T, slices, null);
}

/// Copies each T from slices into a new slice that exactly holds all the elements.
pub fn concatWithSentinel(allocator: Allocator, comptime T: type, slices: []const []const T, comptime s: T) Allocator.Error![:s]T {
    const ret = try concatMaybeSentinel(allocator, T, slices, s);
    return ret[0 .. ret.len - 1 :s];
}

/// Copies each T from slices into a new slice that exactly holds all the elements as well as the sentinel.
pub fn concatMaybeSentinel(allocator: Allocator, comptime T: type, slices: []const []const T, comptime s: ?T) Allocator.Error![]T {
    if (slices.len == 0) return if (s) |sentinel| try allocator.dupe(T, &[1]T{sentinel}) else &[0]T{};

    const total_len = blk: {
        var sum: usize = 0;
        for (slices) |slice| {
            sum += slice.len;
        }

        if (s) |_| {
            sum += 1;
        }

        break :blk sum;
    };

    const buf = try allocator.alloc(T, total_len);
    errdefer allocator.free(buf);

    var buf_index: usize = 0;
    for (slices) |slice| {
        @memcpy(buf[buf_index .. buf_index + slice.len], slice);
        buf_index += slice.len;
    }

    if (s) |sentinel| {
        buf[buf.len - 1] = sentinel;
    }

    // No need for shrink since buf is exactly the correct size.
    return buf;
}

test concat {
    {
        const str = try concat(testing.allocator, u8, &[_][]const u8{ "abc", "def", "ghi" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "abcdefghi"));
    }
    {
        const str = try concat(testing.allocator, u32, &[_][]const u32{
            &[_]u32{ 0, 1 },
            &[_]u32{ 2, 3, 4 },
            &[_]u32{},
            &[_]u32{5},
        });
        defer testing.allocator.free(str);
        try testing.expect(eql(u32, str, &[_]u32{ 0, 1, 2, 3, 4, 5 }));
    }
    {
        const str = try concatWithSentinel(testing.allocator, u8, &[_][]const u8{ "abc", "def", "ghi" }, 0);
        defer testing.allocator.free(str);
        try testing.expectEqualSentinel(u8, 0, str, "abcdefghi");
    }
    {
        const slice = try concatWithSentinel(testing.allocator, u8, &[_][]const u8{}, 0);
        defer testing.allocator.free(slice);
        try testing.expectEqualSentinel(u8, 0, slice, &[_:0]u8{});
    }
    {
        const slice = try concatWithSentinel(testing.allocator, u32, &[_][]const u32{
            &[_]u32{ 0, 1 },
            &[_]u32{ 2, 3, 4 },
            &[_]u32{},
            &[_]u32{5},
        }, 2);
        defer testing.allocator.free(slice);
        try testing.expectEqualSentinel(u32, 2, slice, &[_:2]u32{ 0, 1, 2, 3, 4, 5 });
    }
}

fn moreReadIntTests() !void {
    {
        const bytes = [_]u8{
            0x12,
            0x34,
            0x56,
            0x78,
        };
        try testing.expect(readInt(u32, &bytes, .big) == 0x12345678);
        try testing.expect(readInt(u32, &bytes, .big) == 0x12345678);
        try testing.expect(readInt(i32, &bytes, .big) == 0x12345678);
        try testing.expect(readInt(u32, &bytes, .little) == 0x78563412);
        try testing.expect(readInt(u32, &bytes, .little) == 0x78563412);
        try testing.expect(readInt(i32, &bytes, .little) == 0x78563412);
    }
    {
        const buf = [_]u8{
            0x00,
            0x00,
            0x12,
            0x34,
        };
        const answer = readInt(u32, &buf, .big);
        try testing.expect(answer == 0x00001234);
    }
    {
        const buf = [_]u8{
            0x12,
            0x34,
            0x00,
            0x00,
        };
        const answer = readInt(u32, &buf, .little);
        try testing.expect(answer == 0x00003412);
    }
    {
        const bytes = [_]u8{
            0xff,
            0xfe,
        };
        try testing.expect(readInt(u16, &bytes, .big) == 0xfffe);
        try testing.expect(readInt(i16, &bytes, .big) == -0x0002);
        try testing.expect(readInt(u16, &bytes, .little) == 0xfeff);
        try testing.expect(readInt(i16, &bytes, .little) == -0x0101);
    }
}

/// Returns the smallest number in a slice. O(n).
/// `slice` must not be empty.
pub fn min(comptime T: type, slice: []const T) T {
    assert(slice.len > 0);
    var best = slice[0];
    for (slice[1..]) |item| {
        best = @min(best, item);
    }
    return best;
}

test min {
    try testing.expectEqual(min(u8, "abcdefg"), 'a');
    try testing.expectEqual(min(u8, "bcdefga"), 'a');
    try testing.expectEqual(min(u8, "a"), 'a');
}

/// Returns the largest number in a slice. O(n).
/// `slice` must not be empty.
pub fn max(comptime T: type, slice: []const T) T {
    assert(slice.len > 0);
    var best = slice[0];
    for (slice[1..]) |item| {
        best = @max(best, item);
    }
    return best;
}

test max {
    try testing.expectEqual(max(u8, "abcdefg"), 'g');
    try testing.expectEqual(max(u8, "gabcdef"), 'g');
    try testing.expectEqual(max(u8, "g"), 'g');
}

/// Finds the smallest and largest number in a slice. O(n).
/// Returns an anonymous struct with the fields `min` and `max`.
/// `slice` must not be empty.
pub fn minMax(comptime T: type, slice: []const T) struct { T, T } {
    assert(slice.len > 0);
    var running_minimum = slice[0];
    var running_maximum = slice[0];
    for (slice[1..]) |item| {
        running_minimum = @min(running_minimum, item);
        running_maximum = @max(running_maximum, item);
    }
    return .{ running_minimum, running_maximum };
}

test minMax {
    {
        const actual_min, const actual_max = minMax(u8, "abcdefg");
        try testing.expectEqual(@as(u8, 'a'), actual_min);
        try testing.expectEqual(@as(u8, 'g'), actual_max);
    }
    {
        const actual_min, const actual_max = minMax(u8, "bcdefga");
        try testing.expectEqual(@as(u8, 'a'), actual_min);
        try testing.expectEqual(@as(u8, 'g'), actual_max);
    }
    {
        const actual_min, const actual_max = minMax(u8, "a");
        try testing.expectEqual(@as(u8, 'a'), actual_min);
        try testing.expectEqual(@as(u8, 'a'), actual_max);
    }
}

/// Returns the index of the smallest number in a slice. O(n).
/// `slice` must not be empty.
pub fn indexOfMin(comptime T: type, slice: []const T) usize {
    assert(slice.len > 0);
    var best = slice[0];
    var index: usize = 0;
    for (slice[1..], 0..) |item,```
