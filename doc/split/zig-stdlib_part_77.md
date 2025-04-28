```
 i| {
        if (item < best) {
            best = item;
            index = i + 1;
        }
    }
    return index;
}

test indexOfMin {
    try testing.expectEqual(indexOfMin(u8, "abcdefg"), 0);
    try testing.expectEqual(indexOfMin(u8, "bcdefga"), 6);
    try testing.expectEqual(indexOfMin(u8, "a"), 0);
}

/// Returns the index of the largest number in a slice. O(n).
/// `slice` must not be empty.
pub fn indexOfMax(comptime T: type, slice: []const T) usize {
    assert(slice.len > 0);
    var best = slice[0];
    var index: usize = 0;
    for (slice[1..], 0..) |item, i| {
        if (item > best) {
            best = item;
            index = i + 1;
        }
    }
    return index;
}

test indexOfMax {
    try testing.expectEqual(indexOfMax(u8, "abcdefg"), 6);
    try testing.expectEqual(indexOfMax(u8, "gabcdef"), 0);
    try testing.expectEqual(indexOfMax(u8, "a"), 0);
}

/// Finds the indices of the smallest and largest number in a slice. O(n).
/// Returns the indices of the smallest and largest numbers in that order.
/// `slice` must not be empty.
pub fn indexOfMinMax(comptime T: type, slice: []const T) struct { usize, usize } {
    assert(slice.len > 0);
    var minVal = slice[0];
    var maxVal = slice[0];
    var minIdx: usize = 0;
    var maxIdx: usize = 0;
    for (slice[1..], 0..) |item, i| {
        if (item < minVal) {
            minVal = item;
            minIdx = i + 1;
        }
        if (item > maxVal) {
            maxVal = item;
            maxIdx = i + 1;
        }
    }
    return .{ minIdx, maxIdx };
}

test indexOfMinMax {
    try testing.expectEqual(.{ 0, 6 }, indexOfMinMax(u8, "abcdefg"));
    try testing.expectEqual(.{ 1, 0 }, indexOfMinMax(u8, "gabcdef"));
    try testing.expectEqual(.{ 0, 0 }, indexOfMinMax(u8, "a"));
}

pub fn swap(comptime T: type, a: *T, b: *T) void {
    const tmp = a.*;
    a.* = b.*;
    b.* = tmp;
}

inline fn reverseVector(comptime N: usize, comptime T: type, a: []T) [N]T {
    var res: [N]T = undefined;
    inline for (0..N) |i| {
        res[i] = a[N - i - 1];
    }
    return res;
}

/// In-place order reversal of a slice
pub fn reverse(comptime T: type, items: []T) void {
    var i: usize = 0;
    const end = items.len / 2;
    if (backend_supports_vectors and
        !@inComptime() and
        @bitSizeOf(T) > 0 and
        std.math.isPowerOfTwo(@bitSizeOf(T)))
    {
        if (std.simd.suggestVectorLength(T)) |simd_size| {
            if (simd_size <= end) {
                const simd_end = end - (simd_size - 1);
                while (i < simd_end) : (i += simd_size) {
                    const left_slice = items[i .. i + simd_size];
                    const right_slice = items[items.len - i - simd_size .. items.len - i];

                    const left_shuffled: [simd_size]T = reverseVector(simd_size, T, left_slice);
                    const right_shuffled: [simd_size]T = reverseVector(simd_size, T, right_slice);

                    @memcpy(right_slice, &left_shuffled);
                    @memcpy(left_slice, &right_shuffled);
                }
            }
        }
    }

    while (i < end) : (i += 1) {
        swap(T, &items[i], &items[items.len - i - 1]);
    }
}

test reverse {
    {
        var arr = [_]i32{ 5, 3, 1, 2, 4 };
        reverse(i32, arr[0..]);
        try testing.expectEqualSlices(i32, &arr, &.{ 4, 2, 1, 3, 5 });
    }
    {
        var arr = [_]u0{};
        reverse(u0, arr[0..]);
        try testing.expectEqualSlices(u0, &arr, &.{});
    }
    {
        var arr = [_]i64{ 19, 17, 15, 13, 11, 9, 7, 5, 3, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18 };
        reverse(i64, arr[0..]);
        try testing.expectEqualSlices(i64, &arr, &.{ 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19 });
    }
    {
        var arr = [_][]const u8{ "a", "b", "c", "d" };
        reverse([]const u8, arr[0..]);
        try testing.expectEqualSlices([]const u8, &arr, &.{ "d", "c", "b", "a" });
    }
    {
        const MyType = union(enum) {
            a: [3]u8,
            b: u24,
            c,
        };
        var arr = [_]MyType{ .{ .a = .{ 0, 0, 0 } }, .{ .b = 0 }, .c };
        reverse(MyType, arr[0..]);
        try testing.expectEqualSlices(MyType, &arr, &([_]MyType{ .c, .{ .b = 0 }, .{ .a = .{ 0, 0, 0 } } }));
    }
}
fn ReverseIterator(comptime T: type) type {
    const Pointer = blk: {
        switch (@typeInfo(T)) {
            .pointer => |ptr_info| switch (ptr_info.size) {
                .one => switch (@typeInfo(ptr_info.child)) {
                    .array => |array_info| {
                        var new_ptr_info = ptr_info;
                        new_ptr_info.size = .many;
                        new_ptr_info.child = array_info.child;
                        new_ptr_info.sentinel_ptr = array_info.sentinel_ptr;
                        break :blk @Type(.{ .pointer = new_ptr_info });
                    },
                    else => {},
                },
                .slice => {
                    var new_ptr_info = ptr_info;
                    new_ptr_info.size = .many;
                    break :blk @Type(.{ .pointer = new_ptr_info });
                },
                else => {},
            },
            else => {},
        }
        @compileError("expected slice or pointer to array, found '" ++ @typeName(T) ++ "'");
    };
    const Element = std.meta.Elem(Pointer);
    const ElementPointer = @Type(.{ .pointer = ptr: {
        var ptr = @typeInfo(Pointer).pointer;
        ptr.size = .one;
        ptr.child = Element;
        ptr.sentinel_ptr = null;
        break :ptr ptr;
    } });
    return struct {
        ptr: Pointer,
        index: usize,
        pub fn next(self: *@This()) ?Element {
            if (self.index == 0) return null;
            self.index -= 1;
            return self.ptr[self.index];
        }
        pub fn nextPtr(self: *@This()) ?ElementPointer {
            if (self.index == 0) return null;
            self.index -= 1;
            return &self.ptr[self.index];
        }
    };
}

/// Iterates over a slice in reverse.
pub fn reverseIterator(slice: anytype) ReverseIterator(@TypeOf(slice)) {
    return .{ .ptr = slice.ptr, .index = slice.len };
}

test reverseIterator {
    {
        var it = reverseIterator("abc");
        try testing.expectEqual(@as(?u8, 'c'), it.next());
        try testing.expectEqual(@as(?u8, 'b'), it.next());
        try testing.expectEqual(@as(?u8, 'a'), it.next());
        try testing.expectEqual(@as(?u8, null), it.next());
    }
    {
        var array = [2]i32{ 3, 7 };
        const slice: []const i32 = &array;
        var it = reverseIterator(slice);
        try testing.expectEqual(@as(?i32, 7), it.next());
        try testing.expectEqual(@as(?i32, 3), it.next());
        try testing.expectEqual(@as(?i32, null), it.next());

        it = reverseIterator(slice);
        try testing.expect(*const i32 == @TypeOf(it.nextPtr().?));
        try testing.expectEqual(@as(?i32, 7), it.nextPtr().?.*);
        try testing.expectEqual(@as(?i32, 3), it.nextPtr().?.*);
        try testing.expectEqual(@as(?*const i32, null), it.nextPtr());

        const mut_slice: []i32 = &array;
        var mut_it = reverseIterator(mut_slice);
        mut_it.nextPtr().?.* += 1;
        mut_it.nextPtr().?.* += 2;
        try testing.expectEqual([2]i32{ 5, 8 }, array);
    }
    {
        var array = [2]i32{ 3, 7 };
        const ptr_to_array: *const [2]i32 = &array;
        var it = reverseIterator(ptr_to_array);
        try testing.expectEqual(@as(?i32, 7), it.next());
        try testing.expectEqual(@as(?i32, 3), it.next());
        try testing.expectEqual(@as(?i32, null), it.next());

        it = reverseIterator(ptr_to_array);
        try testing.expect(*const i32 == @TypeOf(it.nextPtr().?));
        try testing.expectEqual(@as(?i32, 7), it.nextPtr().?.*);
        try testing.expectEqual(@as(?i32, 3), it.nextPtr().?.*);
        try testing.expectEqual(@as(?*const i32, null), it.nextPtr());

        const mut_ptr_to_array: *[2]i32 = &array;
        var mut_it = reverseIterator(mut_ptr_to_array);
        mut_it.nextPtr().?.* += 1;
        mut_it.nextPtr().?.* += 2;
        try testing.expectEqual([2]i32{ 5, 8 }, array);
    }
}

/// In-place rotation of the values in an array ([0 1 2 3] becomes [1 2 3 0] if we rotate by 1)
/// Assumes 0 <= amount <= items.len
pub fn rotate(comptime T: type, items: []T, amount: usize) void {
    reverse(T, items[0..amount]);
    reverse(T, items[amount..]);
    reverse(T, items);
}

test rotate {
    var arr = [_]i32{ 5, 3, 1, 2, 4 };
    rotate(i32, arr[0..], 2);

    try testing.expect(eql(i32, &arr, &[_]i32{ 1, 2, 4, 5, 3 }));
}

/// Replace needle with replacement as many times as possible, writing to an output buffer which is assumed to be of
/// appropriate size. Use replacementSize to calculate an appropriate buffer size.
/// The needle must not be empty.
/// Returns the number of replacements made.
pub fn replace(comptime T: type, input: []const T, needle: []const T, replacement: []const T, output: []T) usize {
    // Empty needle will loop until output buffer overflows.
    assert(needle.len > 0);

    var i: usize = 0;
    var slide: usize = 0;
    var replacements: usize = 0;
    while (slide < input.len) {
        if (mem.startsWith(T, input[slide..], needle)) {
            @memcpy(output[i..][0..replacement.len], replacement);
            i += replacement.len;
            slide += needle.len;
            replacements += 1;
        } else {
            output[i] = input[slide];
            i += 1;
            slide += 1;
        }
    }

    return replacements;
}

test replace {
    var output: [29]u8 = undefined;
    var replacements = replace(u8, "All your base are belong to us", "base", "Zig", output[0..]);
    var expected: []const u8 = "All your Zig are belong to us";
    try testing.expect(replacements == 1);
    try testing.expectEqualStrings(expected, output[0..expected.len]);

    replacements = replace(u8, "Favor reading code over writing code.", "code", "", output[0..]);
    expected = "Favor reading  over writing .";
    try testing.expect(replacements == 2);
    try testing.expectEqualStrings(expected, output[0..expected.len]);

    // Empty needle is not allowed but input may be empty.
    replacements = replace(u8, "", "x", "y", output[0..0]);
    expected = "";
    try testing.expect(replacements == 0);
    try testing.expectEqualStrings(expected, output[0..expected.len]);

    // Adjacent replacements.

    replacements = replace(u8, "\\n\\n", "\\n", "\n", output[0..]);
    expected = "\n\n";
    try testing.expect(replacements == 2);
    try testing.expectEqualStrings(expected, output[0..expected.len]);

    replacements = replace(u8, "abbba", "b", "cd", output[0..]);
    expected = "acdcdcda";
    try testing.expect(replacements == 3);
    try testing.expectEqualStrings(expected, output[0..expected.len]);
}

/// Replace all occurrences of `match` with `replacement`.
pub fn replaceScalar(comptime T: type, slice: []T, match: T, replacement: T) void {
    for (slice) |*e| {
        if (e.* == match)
            e.* = replacement;
    }
}

/// Collapse consecutive duplicate elements into one entry.
pub fn collapseRepeatsLen(comptime T: type, slice: []T, elem: T) usize {
    if (slice.len == 0) return 0;
    var write_idx: usize = 1;
    var read_idx: usize = 1;
    while (read_idx < slice.len) : (read_idx += 1) {
        if (slice[read_idx - 1] != elem or slice[read_idx] != elem) {
            slice[write_idx] = slice[read_idx];
            write_idx += 1;
        }
    }
    return write_idx;
}

/// Collapse consecutive duplicate elements into one entry.
pub fn collapseRepeats(comptime T: type, slice: []T, elem: T) []T {
    return slice[0..collapseRepeatsLen(T, slice, elem)];
}

fn testCollapseRepeats(str: []const u8, elem: u8, expected: []const u8) !void {
    const mutable = try std.testing.allocator.dupe(u8, str);
    defer std.testing.allocator.free(mutable);
    try testing.expect(std.mem.eql(u8, collapseRepeats(u8, mutable, elem), expected));
}
test collapseRepeats {
    try testCollapseRepeats("", '/', "");
    try testCollapseRepeats("a", '/', "a");
    try testCollapseRepeats("/", '/', "/");
    try testCollapseRepeats("//", '/', "/");
    try testCollapseRepeats("/a", '/', "/a");
    try testCollapseRepeats("//a", '/', "/a");
    try testCollapseRepeats("a/", '/', "a/");
    try testCollapseRepeats("a//", '/', "a/");
    try testCollapseRepeats("a/a", '/', "a/a");
    try testCollapseRepeats("a//a", '/', "a/a");
    try testCollapseRepeats("//a///a////", '/', "/a/a/");
}

/// Calculate the size needed in an output buffer to perform a replacement.
/// The needle must not be empty.
pub fn replacementSize(comptime T: type, input: []const T, needle: []const T, replacement: []const T) usize {
    // Empty needle will loop forever.
    assert(needle.len > 0);

    var i: usize = 0;
    var size: usize = input.len;
    while (i < input.len) {
        if (mem.startsWith(T, input[i..], needle)) {
            size = size - needle.len + replacement.len;
            i += needle.len;
        } else {
            i += 1;
        }
    }

    return size;
}

test replacementSize {
    try testing.expect(replacementSize(u8, "All your base are belong to us", "base", "Zig") == 29);
    try testing.expect(replacementSize(u8, "Favor reading code over writing code.", "code", "") == 29);
    try testing.expect(replacementSize(u8, "Only one obvious way to do things.", "things.", "things in Zig.") == 41);

    // Empty needle is not allowed but input may be empty.
    try testing.expect(replacementSize(u8, "", "x", "y") == 0);

    // Adjacent replacements.
    try testing.expect(replacementSize(u8, "\\n\\n", "\\n", "\n") == 2);
    try testing.expect(replacementSize(u8, "abbba", "b", "cd") == 8);
}

/// Perform a replacement on an allocated buffer of pre-determined size. Caller must free returned memory.
pub fn replaceOwned(comptime T: type, allocator: Allocator, input: []const T, needle: []const T, replacement: []const T) Allocator.Error![]T {
    const output = try allocator.alloc(T, replacementSize(T, input, needle, replacement));
    _ = replace(T, input, needle, replacement, output);
    return output;
}

test replaceOwned {
    const gpa = std.testing.allocator;

    const base_replace = replaceOwned(u8, gpa, "All your base are belong to us", "base", "Zig") catch @panic("out of memory");
    defer gpa.free(base_replace);
    try testing.expect(eql(u8, base_replace, "All your Zig are belong to us"));

    const zen_replace = replaceOwned(u8, gpa, "Favor reading code over writing code.", " code", "") catch @panic("out of memory");
    defer gpa.free(zen_replace);
    try testing.expect(eql(u8, zen_replace, "Favor reading over writing."));
}

/// Converts a little-endian integer to host endianness.
pub fn littleToNative(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => x,
        .big => @byteSwap(x),
    };
}

/// Converts a big-endian integer to host endianness.
pub fn bigToNative(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => @byteSwap(x),
        .big => x,
    };
}

/// Converts an integer from specified endianness to host endianness.
pub fn toNative(comptime T: type, x: T, endianness_of_x: Endian) T {
    return switch (endianness_of_x) {
        .little => littleToNative(T, x),
        .big => bigToNative(T, x),
    };
}

/// Converts an integer which has host endianness to the desired endianness.
pub fn nativeTo(comptime T: type, x: T, desired_endianness: Endian) T {
    return switch (desired_endianness) {
        .little => nativeToLittle(T, x),
        .big => nativeToBig(T, x),
    };
}

/// Converts an integer which has host endianness to little endian.
pub fn nativeToLittle(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => x,
        .big => @byteSwap(x),
    };
}

/// Converts an integer which has host endianness to big endian.
pub fn nativeToBig(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => @byteSwap(x),
        .big => x,
    };
}

/// Returns the number of elements that, if added to the given pointer, align it
/// to a multiple of the given quantity, or `null` if one of the following
/// conditions is met:
/// - The aligned pointer would not fit the address space,
/// - The delta required to align the pointer is not a multiple of the pointee's
///   type.
pub fn alignPointerOffset(ptr: anytype, align_to: usize) ?usize {
    assert(isValidAlign(align_to));

    const T = @TypeOf(ptr);
    const info = @typeInfo(T);
    if (info != .pointer or info.pointer.size != .many)
        @compileError("expected many item pointer, got " ++ @typeName(T));

    // Do nothing if the pointer is already well-aligned.
    if (align_to <= info.pointer.alignment)
        return 0;

    // Calculate the aligned base address with an eye out for overflow.
    const addr = @intFromPtr(ptr);
    var ov = @addWithOverflow(addr, align_to - 1);
    if (ov[1] != 0) return null;
    ov[0] &= ~@as(usize, align_to - 1);

    // The delta is expressed in terms of bytes, turn it into a number of child
    // type elements.
    const delta = ov[0] - addr;
    const pointee_size = @sizeOf(info.pointer.child);
    if (delta % pointee_size != 0) return null;
    return delta / pointee_size;
}

/// Aligns a given pointer value to a specified alignment factor.
/// Returns an aligned pointer or null if one of the following conditions is
/// met:
/// - The aligned pointer would not fit the address space,
/// - The delta required to align the pointer is not a multiple of the pointee's
///   type.
pub fn alignPointer(ptr: anytype, align_to: usize) ?@TypeOf(ptr) {
    const adjust_off = alignPointerOffset(ptr, align_to) orelse return null;
    // Avoid the use of ptrFromInt to avoid losing the pointer provenance info.
    return @alignCast(ptr + adjust_off);
}

test alignPointer {
    const S = struct {
        fn checkAlign(comptime T: type, base: usize, align_to: usize, expected: usize) !void {
            const ptr: T = @ptrFromInt(base);
            const aligned = alignPointer(ptr, align_to);
            try testing.expectEqual(expected, @intFromPtr(aligned));
        }
    };

    try S.checkAlign([*]u8, 0x123, 0x200, 0x200);
    try S.checkAlign([*]align(4) u8, 0x10, 2, 0x10);
    try S.checkAlign([*]u32, 0x10, 2, 0x10);
    try S.checkAlign([*]u32, 0x4, 16, 0x10);
    // Misaligned.
    try S.checkAlign([*]align(1) u32, 0x3, 2, 0);
    // Overflow.
    try S.checkAlign([*]u32, math.maxInt(usize) - 3, 8, 0);
}

fn CopyPtrAttrs(
    comptime source: type,
    comptime size: std.builtin.Type.Pointer.Size,
    comptime child: type,
) type {
    const info = @typeInfo(source).pointer;
    return @Type(.{
        .pointer = .{
            .size = size,
            .is_const = info.is_const,
            .is_volatile = info.is_volatile,
            .is_allowzero = info.is_allowzero,
            .alignment = info.alignment,
            .address_space = info.address_space,
            .child = child,
            .sentinel_ptr = null,
        },
    });
}

fn AsBytesReturnType(comptime P: type) type {
    const pointer = @typeInfo(P).pointer;
    assert(pointer.size == .one);
    const size = @sizeOf(pointer.child);
    return CopyPtrAttrs(P, .one, [size]u8);
}

/// Given a pointer to a single item, returns a slice of the underlying bytes, preserving pointer attributes.
pub fn asBytes(ptr: anytype) AsBytesReturnType(@TypeOf(ptr)) {
    return @ptrCast(@alignCast(ptr));
}

test asBytes {
    const deadbeef = @as(u32, 0xDEADBEEF);
    const deadbeef_bytes = switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xEF\xBE\xAD\xDE",
    };

    try testing.expect(eql(u8, asBytes(&deadbeef), deadbeef_bytes));

    var codeface = @as(u32, 0xC0DEFACE);
    for (asBytes(&codeface)) |*b|
        b.* = 0;
    try testing.expect(codeface == 0);

    const S = packed struct {
        a: u8,
        b: u8,
        c: u8,
        d: u8,
    };

    const inst = S{
        .a = 0xBE,
        .b = 0xEF,
        .c = 0xDE,
        .d = 0xA1,
    };
    switch (native_endian) {
        .little => {
            try testing.expect(eql(u8, asBytes(&inst), "\xBE\xEF\xDE\xA1"));
        },
        .big => {
            try testing.expect(eql(u8, asBytes(&inst), "\xA1\xDE\xEF\xBE"));
        },
    }

    const ZST = struct {};
    const zero = ZST{};
    try testing.expect(eql(u8, asBytes(&zero), ""));
}

test "asBytes preserves pointer attributes" {
    const inArr: u32 align(16) = 0xDEADBEEF;
    const inPtr = @as(*align(16) const volatile u32, @ptrCast(&inArr));
    const outSlice = asBytes(inPtr);

    const in = @typeInfo(@TypeOf(inPtr)).pointer;
    const out = @typeInfo(@TypeOf(outSlice)).pointer;

    try testing.expectEqual(in.is_const, out.is_const);
    try testing.expectEqual(in.is_volatile, out.is_volatile);
    try testing.expectEqual(in.is_allowzero, out.is_allowzero);
    try testing.expectEqual(in.alignment, out.alignment);
}

/// Given any value, returns a copy of its bytes in an array.
pub fn toBytes(value: anytype) [@sizeOf(@TypeOf(value))]u8 {
    return asBytes(&value).*;
}

test toBytes {
    var my_bytes = toBytes(@as(u32, 0x12345678));
    switch (native_endian) {
        .big => try testing.expect(eql(u8, &my_bytes, "\x12\x34\x56\x78")),
        .little => try testing.expect(eql(u8, &my_bytes, "\x78\x56\x34\x12")),
    }

    my_bytes[0] = '\x99';
    switch (native_endian) {
        .big => try testing.expect(eql(u8, &my_bytes, "\x99\x34\x56\x78")),
        .little => try testing.expect(eql(u8, &my_bytes, "\x99\x56\x34\x12")),
    }
}

fn BytesAsValueReturnType(comptime T: type, comptime B: type) type {
    return CopyPtrAttrs(B, .one, T);
}

/// Given a pointer to an array of bytes, returns a pointer to a value of the specified type
/// backed by those bytes, preserving pointer attributes.
pub fn bytesAsValue(comptime T: type, bytes: anytype) BytesAsValueReturnType(T, @TypeOf(bytes)) {
    return @ptrCast(bytes);
}

test bytesAsValue {
    const deadbeef = @as(u32, 0xDEADBEEF);
    const deadbeef_bytes = switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xEF\xBE\xAD\xDE",
    };

    try testing.expect(deadbeef == bytesAsValue(u32, deadbeef_bytes).*);

    var codeface_bytes: [4]u8 = switch (native_endian) {
        .big => "\xC0\xDE\xFA\xCE",
        .little => "\xCE\xFA\xDE\xC0",
    }.*;
    const codeface = bytesAsValue(u32, &codeface_bytes);
    try testing.expect(codeface.* == 0xC0DEFACE);
    codeface.* = 0;
    for (codeface_bytes) |b|
        try testing.expect(b == 0);

    const S = packed struct {
        a: u8,
        b: u8,
        c: u8,
        d: u8,
    };

    const inst = S{
        .a = 0xBE,
        .b = 0xEF,
        .c = 0xDE,
        .d = 0xA1,
    };
    const inst_bytes = switch (native_endian) {
        .little => "\xBE\xEF\xDE\xA1",
        .big => "\xA1\xDE\xEF\xBE",
    };
    const inst2 = bytesAsValue(S, inst_bytes);
    try testing.expect(std.meta.eql(inst, inst2.*));
}

test "bytesAsValue preserves pointer attributes" {
    const inArr align(16) = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const inSlice = @as(*align(16) const volatile [4]u8, @ptrCast(&inArr))[0..];
    const outPtr = bytesAsValue(u32, inSlice);

    const in = @typeInfo(@TypeOf(inSlice)).pointer;
    const out = @typeInfo(@TypeOf(outPtr)).pointer;

    try testing.expectEqual(in.is_const, out.is_const);
    try testing.expectEqual(in.is_volatile, out.is_volatile);
    try testing.expectEqual(in.is_allowzero, out.is_allowzero);
    try testing.expectEqual(in.alignment, out.alignment);
}

/// Given a pointer to an array of bytes, returns a value of the specified type backed by a
/// copy of those bytes.
pub fn bytesToValue(comptime T: type, bytes: anytype) T {
    return bytesAsValue(T, bytes).*;
}
test bytesToValue {
    const deadbeef_bytes = switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xEF\xBE\xAD\xDE",
    };

    const deadbeef = bytesToValue(u32, deadbeef_bytes);
    try testing.expect(deadbeef == @as(u32, 0xDEADBEEF));
}

fn BytesAsSliceReturnType(comptime T: type, comptime bytesType: type) type {
    return CopyPtrAttrs(bytesType, .slice, T);
}

/// Given a slice of bytes, returns a slice of the specified type
/// backed by those bytes, preserving pointer attributes.
/// If `T` is zero-bytes sized, the returned slice has a len of zero.
pub fn bytesAsSlice(comptime T: type, bytes: anytype) BytesAsSliceReturnType(T, @TypeOf(bytes)) {
    // let's not give an undefined pointer to @ptrCast
    // it may be equal to zero and fail a null check
    if (bytes.len == 0 or @sizeOf(T) == 0) {
        return &[0]T{};
    }

    const cast_target = CopyPtrAttrs(@TypeOf(bytes), .many, T);

    return @as(cast_target, @ptrCast(bytes))[0..@divExact(bytes.len, @sizeOf(T))];
}

test bytesAsSlice {
    {
        const bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        const slice = bytesAsSlice(u16, bytes[0..]);
        try testing.expect(slice.len == 2);
        try testing.expect(bigToNative(u16, slice[0]) == 0xDEAD);
        try testing.expect(bigToNative(u16, slice[1]) == 0xBEEF);
    }
    {
        const bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        var runtime_zero: usize = 0;
        _ = &runtime_zero;
        const slice = bytesAsSlice(u16, bytes[runtime_zero..]);
        try testing.expect(slice.len == 2);
        try testing.expect(bigToNative(u16, slice[0]) == 0xDEAD);
        try testing.expect(bigToNative(u16, slice[1]) == 0xBEEF);
    }
}

test "bytesAsSlice keeps pointer alignment" {
    {
        var bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
        const numbers = bytesAsSlice(u32, bytes[0..]);
        try comptime testing.expect(@TypeOf(numbers) == []align(@alignOf(@TypeOf(bytes))) u32);
    }
    {
        var bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
        var runtime_zero: usize = 0;
        _ = &runtime_zero;
        const numbers = bytesAsSlice(u32, bytes[runtime_zero..]);
        try comptime testing.expect(@TypeOf(numbers) == []align(@alignOf(@TypeOf(bytes))) u32);
    }
}

test "bytesAsSlice on a packed struct" {
    const F = packed struct {
        a: u8,
    };

    const b: [1]u8 = .{9};
    const f = bytesAsSlice(F, &b);
    try testing.expect(f[0].a == 9);
}

test "bytesAsSlice with specified alignment" {
    var bytes align(4) = [_]u8{
        0x33,
        0x33,
        0x33,
        0x33,
    };
    const slice: []u32 = std.mem.bytesAsSlice(u32, bytes[0..]);
    try testing.expect(slice[0] == 0x33333333);
}

test "bytesAsSlice preserves pointer attributes" {
    const inArr align(16) = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const inSlice = @as(*align(16) const volatile [4]u8, @ptrCast(&inArr))[0..];
    const outSlice = bytesAsSlice(u16, inSlice);

    const in = @typeInfo(@TypeOf(inSlice)).pointer;
    const out = @typeInfo(@TypeOf(outSlice)).pointer;

    try testing.expectEqual(in.is_const, out.is_const);
    try testing.expectEqual(in.is_volatile, out.is_volatile);
    try testing.expectEqual(in.is_allowzero, out.is_allowzero);
    try testing.expectEqual(in.alignment, out.alignment);
}

test "bytesAsSlice with zero-bit element type" {
    {
        const bytes = [_]u8{};
        const slice = bytesAsSlice(void, &bytes);
        try testing.expectEqual(0, slice.len);
    }
    {
        const bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
        const slice = bytesAsSlice(u0, &bytes);
        try testing.expectEqual(0, slice.len);
    }
}

fn SliceAsBytesReturnType(comptime Slice: type) type {
    return CopyPtrAttrs(Slice, .slice, u8);
}

/// Given a slice, returns a slice of the underlying bytes, preserving pointer attributes.
pub fn sliceAsBytes(slice: anytype) SliceAsBytesReturnType(@TypeOf(slice)) {
    const Slice = @TypeOf(slice);

    // a slice of zero-bit values always occupies zero bytes
    if (@sizeOf(std.meta.Elem(Slice)) == 0) return &[0]u8{};

    // let's not give an undefined pointer to @ptrCast
    // it may be equal to zero and fail a null check
    if (slice.len == 0 and std.meta.sentinel(Slice) == null) return &[0]u8{};

    const cast_target = CopyPtrAttrs(Slice, .many, u8);

    return @as(cast_target, @ptrCast(slice))[0 .. slice.len * @sizeOf(std.meta.Elem(Slice))];
}

test sliceAsBytes {
    const bytes = [_]u16{ 0xDEAD, 0xBEEF };
    const slice = sliceAsBytes(bytes[0..]);
    try testing.expect(slice.len == 4);
    try testing.expect(eql(u8, slice, switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xAD\xDE\xEF\xBE",
    }));
}

test "sliceAsBytes with sentinel slice" {
    const empty_string: [:0]const u8 = "";
    const bytes = sliceAsBytes(empty_string);
    try testing.expect(bytes.len == 0);
}

test "sliceAsBytes with zero-bit element type" {
    const lots_of_nothing = [1]void{{}} ** 10_000;
    const bytes = sliceAsBytes(&lots_of_nothing);
    try testing.expect(bytes.len == 0);
}

test "sliceAsBytes packed struct at runtime and comptime" {
    const Foo = packed struct {
        a: u4,
        b: u4,
    };
    const S = struct {
        fn doTheTest() !void {
            var foo: Foo = undefined;
            var slice = sliceAsBytes(@as(*[1]Foo, &foo)[0..1]);
            slice[0] = 0x13;
            try testing.expect(foo.a == 0x3);
            try testing.expect(foo.b == 0x1);
        }
    };
    try S.doTheTest();
    try comptime S.doTheTest();
}

test "sliceAsBytes and bytesAsSlice back" {
    try testing.expect(@sizeOf(i32) == 4);

    var big_thing_array = [_]i32{ 1, 2, 3, 4 };
    const big_thing_slice: []i32 = big_thing_array[0..];

    const bytes = sliceAsBytes(big_thing_slice);
    try testing.expect(bytes.len == 4 * 4);

    bytes[4] = 0;
    bytes[5] = 0;
    bytes[6] = 0;
    bytes[7] = 0;
    try testing.expect(big_thing_slice[1] == 0);

    const big_thing_again = bytesAsSlice(i32, bytes);
    try testing.expect(big_thing_again[2] == 3);

    big_thing_again[2] = -1;
    try testing.expect(bytes[8] == math.maxInt(u8));
    try testing.expect(bytes[9] == math.maxInt(u8));
    try testing.expect(bytes[10] == math.maxInt(u8));
    try testing.expect(bytes[11] == math.maxInt(u8));
}

test "sliceAsBytes preserves pointer attributes" {
    const inArr align(16) = [2]u16{ 0xDEAD, 0xBEEF };
    const inSlice = @as(*align(16) const volatile [2]u16, @ptrCast(&inArr))[0..];
    const outSlice = sliceAsBytes(inSlice);

    const in = @typeInfo(@TypeOf(inSlice)).pointer;
    const out = @typeInfo(@TypeOf(outSlice)).pointer;

    try testing.expectEqual(in.is_const, out.is_const);
    try testing.expectEqual(in.is_volatile, out.is_volatile);
    try testing.expectEqual(in.is_allowzero, out.is_allowzero);
    try testing.expectEqual(in.alignment, out.alignment);
}

/// Round an address down to the next (or current) aligned address.
/// Unlike `alignForward`, `alignment` can be any positive number, not just a power of 2.
pub fn alignForwardAnyAlign(comptime T: type, addr: T, alignment: T) T {
    if (isValidAlignGeneric(T, alignment))
        return alignForward(T, addr, alignment);
    assert(alignment != 0);
    return alignBackwardAnyAlign(T, addr + (alignment - 1), alignment);
}

/// Round an address up to the next (or current) aligned address.
/// The alignment must be a power of 2 and greater than 0.
/// Asserts that rounding up the address does not cause integer overflow.
pub fn alignForward(comptime T: type, addr: T, alignment: T) T {
    assert(isValidAlignGeneric(T, alignment));
    return alignBackward(T, addr + (alignment - 1), alignment);
}

pub fn alignForwardLog2(addr: usize, log2_alignment: u8) usize {
    const alignment = @as(usize, 1) << @as(math.Log2Int(usize), @intCast(log2_alignment));
    return alignForward(usize, addr, alignment);
}

/// Force an evaluation of the expression; this tries to prevent
/// the compiler from optimizing the computation away even if the
/// result eventually gets discarded.
// TODO: use @declareSideEffect() when it is available - https://github.com/ziglang/zig/issues/6168
pub fn doNotOptimizeAway(val: anytype) void {
    if (@inComptime()) return;

    const max_gp_register_bits = @bitSizeOf(c_long);
    const t = @typeInfo(@TypeOf(val));
    switch (t) {
        .void, .null, .comptime_int, .comptime_float => return,
        .@"enum" => doNotOptimizeAway(@intFromEnum(val)),
        .bool => doNotOptimizeAway(@intFromBool(val)),
        .int => {
            const bits = t.int.bits;
            if (bits <= max_gp_register_bits and builtin.zig_backend != .stage2_c) {
                const val2 = @as(
                    std.meta.Int(t.int.signedness, @max(8, std.math.ceilPowerOfTwoAssert(u16, bits))),
                    val,
                );
                asm volatile (""
                    :
                    : [val2] "r" (val2),
                );
            } else doNotOptimizeAway(&val);
        },
        .float => {
            if ((t.float.bits == 32 or t.float.bits == 64) and builtin.zig_backend != .stage2_c) {
                asm volatile (""
                    :
                    : [val] "rm" (val),
                );
            } else doNotOptimizeAway(&val);
        },
        .pointer => {
            if (builtin.zig_backend == .stage2_c) {
                doNotOptimizeAwayC(val);
            } else {
                asm volatile (""
                    :
                    : [val] "m" (val),
                    : "memory"
                );
            }
        },
        .array => {
            if (t.array.len * @sizeOf(t.array.child) <= 64) {
                for (val) |v| doNotOptimizeAway(v);
            } else doNotOptimizeAway(&val);
        },
        else => doNotOptimizeAway(&val),
    }
}

/// .stage2_c doesn't support asm blocks yet, so use volatile stores instead
var deopt_target: if (builtin.zig_backend == .stage2_c) u8 else void = undefined;
fn doNotOptimizeAwayC(ptr: anytype) void {
    const dest = @as(*volatile u8, @ptrCast(&deopt_target));
    for (asBytes(ptr)) |b| {
        dest.* = b;
    }
    dest.* = 0;
}

test doNotOptimizeAway {
    comptime doNotOptimizeAway("test");

    doNotOptimizeAway(null);
    doNotOptimizeAway(true);
    doNotOptimizeAway(0);
    doNotOptimizeAway(0.0);
    doNotOptimizeAway(@as(u1, 0));
    doNotOptimizeAway(@as(u3, 0));
    doNotOptimizeAway(@as(u8, 0));
    doNotOptimizeAway(@as(u16, 0));
    doNotOptimizeAway(@as(u32, 0));
    doNotOptimizeAway(@as(u64, 0));
    doNotOptimizeAway(@as(u128, 0));
    doNotOptimizeAway(@as(u13, 0));
    doNotOptimizeAway(@as(u37, 0));
    doNotOptimizeAway(@as(u96, 0));
    doNotOptimizeAway(@as(u200, 0));
    doNotOptimizeAway(@as(f32, 0.0));
    doNotOptimizeAway(@as(f64, 0.0));
    doNotOptimizeAway([_]u8{0} ** 4);
    doNotOptimizeAway([_]u8{0} ** 100);
    doNotOptimizeAway(@as(std.builtin.Endian, .little));
}

test alignForward {
    try testing.expect(alignForward(usize, 1, 1) == 1);
    try testing.expect(alignForward(usize, 2, 1) == 2);
    try testing.expect(alignForward(usize, 1, 2) == 2);
    try testing.expect(alignForward(usize, 2, 2) == 2);
    try testing.expect(alignForward(usize, 3, 2) == 4);
    try testing.expect(alignForward(usize, 4, 2) == 4);
    try testing.expect(alignForward(usize, 7, 8) == 8);
    try testing.expect(alignForward(usize, 8, 8) == 8);
    try testing.expect(alignForward(usize, 9, 8) == 16);
    try testing.expect(alignForward(usize, 15, 8) == 16);
    try testing.expect(alignForward(usize, 16, 8) == 16);
    try testing.expect(alignForward(usize, 17, 8) == 24);
}

/// Round an address down to the previous (or current) aligned address.
/// Unlike `alignBackward`, `alignment` can be any positive number, not just a power of 2.
pub fn alignBackwardAnyAlign(comptime T: type, addr: T, alignment: T) T {
    if (isValidAlignGeneric(T, alignment))
        return alignBackward(T, addr, alignment);
    assert(alignment != 0);
    return addr - @mod(addr, alignment);
}

/// Round an address down to the previous (or current) aligned address.
/// The alignment must be a power of 2 and greater than 0.
pub fn alignBackward(comptime T: type, addr: T, alignment: T) T {
    assert(isValidAlignGeneric(T, alignment));
    // 000010000 // example alignment
    // 000001111 // subtract 1
    // 111110000 // binary not
    return addr & ~(alignment - 1);
}

/// Returns whether `alignment` is a valid alignment, meaning it is
/// a positive power of 2.
pub fn isValidAlign(alignment: usize) bool {
    return isValidAlignGeneric(usize, alignment);
}

/// Returns whether `alignment` is a valid alignment, meaning it is
/// a positive power of 2.
pub fn isValidAlignGeneric(comptime T: type, alignment: T) bool {
    return alignment > 0 and std.math.isPowerOfTwo(alignment);
}

pub fn isAlignedAnyAlign(i: usize, alignment: usize) bool {
    if (isValidAlign(alignment))
        return isAligned(i, alignment);
    assert(alignment != 0);
    return 0 == @mod(i, alignment);
}

pub fn isAlignedLog2(addr: usize, log2_alignment: u8) bool {
    return @ctz(addr) >= log2_alignment;
}

/// Given an address and an alignment, return true if the address is a multiple of the alignment
/// The alignment must be a power of 2 and greater than 0.
pub fn isAligned(addr: usize, alignment: usize) bool {
    return isAlignedGeneric(u64, addr, alignment);
}

pub fn isAlignedGeneric(comptime T: type, addr: T, alignment: T) bool {
    return alignBackward(T, addr, alignment) == addr;
}

test isAligned {
    try testing.expect(isAligned(0, 4));
    try testing.expect(isAligned(1, 1));
    try testing.expect(isAligned(2, 1));
    try testing.expect(isAligned(2, 2));
    try testing.expect(!isAligned(2, 4));
    try testing.expect(isAligned(3, 1));
    try testing.expect(!isAligned(3, 2));
    try testing.expect(!isAligned(3, 4));
    try testing.expect(isAligned(4, 4));
    try testing.expect(isAligned(4, 2));
    try testing.expect(isAligned(4, 1));
    try testing.expect(!isAligned(4, 8));
    try testing.expect(!isAligned(4, 16));
}

test "freeing empty string with null-terminated sentinel" {
    const empty_string = try testing.allocator.dupeZ(u8, "");
    testing.allocator.free(empty_string);
}

/// Returns a slice with the given new alignment,
/// all other pointer attributes copied from `AttributeSource`.
fn AlignedSlice(comptime AttributeSource: type, comptime new_alignment: usize) type {
    const info = @typeInfo(AttributeSource).pointer;
    return @Type(.{
        .pointer = .{
            .size = .slice,
            .is_const = info.is_const,
            .is_volatile = info.is_volatile,
            .is_allowzero = info.is_allowzero,
            .alignment = new_alignment,
            .address_space = info.address_space,
            .child = info.child,
            .sentinel_ptr = null,
        },
    });
}

/// Returns the largest slice in the given bytes that conforms to the new alignment,
/// or `null` if the given bytes contain no conforming address.
pub fn alignInBytes(bytes: []u8, comptime new_alignment: usize) ?[]align(new_alignment) u8 {
    const begin_address = @intFromPtr(bytes.ptr);
    const end_address = begin_address + bytes.len;

    const begin_address_aligned = mem.alignForward(usize, begin_address, new_alignment);
    const new_length = std.math.sub(usize, end_address, begin_address_aligned) catch |e| switch (e) {
        error.Overflow => return null,
    };
    const alignment_offset = begin_address_aligned - begin_address;
    return @alignCast(bytes[alignment_offset .. alignment_offset + new_length]);
}

/// Returns the largest sub-slice within the given slice that conforms to the new alignment,
/// or `null` if the given slice contains no conforming address.
pub fn alignInSlice(slice: anytype, comptime new_alignment: usize) ?AlignedSlice(@TypeOf(slice), new_alignment) {
    const bytes = sliceAsBytes(slice);
    const aligned_bytes = alignInBytes(bytes, new_alignment) orelse return null;

    const Element = @TypeOf(slice[0]);
    const slice_length_bytes = aligned_bytes.len - (aligned_bytes.len % @sizeOf(Element));
    const aligned_slice = bytesAsSlice(Element, aligned_bytes[0..slice_length_bytes]);
    return @alignCast(aligned_slice);
}

test "read/write(Var)PackedInt" {
    switch (builtin.cpu.arch) {
        // This test generates too much code to execute on WASI.
        // LLVM backend fails with "too many locals: locals exceed maximum"
        .wasm32, .wasm64 => return error.SkipZigTest,
        else => {},
    }

    const foreign_endian: Endian = if (native_endian == .big) .little else .big;
    const expect = std.testing.expect;
    var prng = std.Random.DefaultPrng.init(1234);
    const random = prng.random();

    @setEvalBranchQuota(10_000);
    inline for ([_]type{ u8, u16, u32, u128 }) |BackingType| {
        for ([_]BackingType{
            @as(BackingType, 0), // all zeros
            -%@as(BackingType, 1), // all ones
            random.int(BackingType), // random
            random.int(BackingType), // random
            random.int(BackingType), // random
        }) |init_value| {
            const uTs = [_]type{ u1, u3, u7, u8, u9, u10, u15, u16, u86 };
            const iTs = [_]type{ i1, i3, i7, i8, i9, i10, i15, i16, i86 };
            inline for (uTs ++ iTs) |PackedType| {
                if (@bitSizeOf(PackedType) > @bitSizeOf(BackingType))
                    continue;

                const iPackedType = std.meta.Int(.signed, @bitSizeOf(PackedType));
                const uPackedType = std.meta.Int(.unsigned, @bitSizeOf(PackedType));
                const Log2T = std.math.Log2Int(BackingType);

                const offset_at_end = @bitSizeOf(BackingType) - @bitSizeOf(PackedType);
                for ([_]usize{ 0, 1, 7, 8, 9, 10, 15, 16, 86, offset_at_end }) |offset| {
                    if (offset > offset_at_end or offset == @bitSizeOf(BackingType))
                        continue;

                    for ([_]PackedType{
                        ~@as(PackedType, 0), // all ones: -1 iN / maxInt uN
                        @as(PackedType, 0), // all zeros: 0 iN / 0 uN
                        @as(PackedType, @bitCast(@as(iPackedType, math.maxInt(iPackedType)))), // maxInt iN
                        @as(PackedType, @bitCast(@as(iPackedType, math.minInt(iPackedType)))), // maxInt iN
                        random.int(PackedType), // random
                        random.int(PackedType), // random
                    }) |write_value| {
                        { // Fixed-size Read/Write (Native-endian)

                            // Initialize Value
                            var value: BackingType = init_value;

                            // Read
                            const read_value1 = readPackedInt(PackedType, asBytes(&value), offset, native_endian);
                            try expect(read_value1 == @as(PackedType, @bitCast(@as(uPackedType, @truncate(value >> @as(Log2T, @intCast(offset)))))));

                            // Write
                            writePackedInt(PackedType, asBytes(&value), offset, write_value, native_endian);
                            try expect(write_value == @as(PackedType, @bitCast(@as(uPackedType, @truncate(value >> @as(Log2T, @intCast(offset)))))));

                            // Read again
                            const read_value2 = readPackedInt(PackedType, asBytes(&value), offset, native_endian);
                            try expect(read_value2 == write_value);

                            // Verify bits outside of the target integer are unmodified
                            const diff_bits = init_value ^ value;
                            if (offset != offset_at_end)
                                try expect(diff_bits >> @as(Log2T, @intCast(offset + @bitSizeOf(PackedType))) == 0);
                            if (offset != 0)
                                try expect(diff_bits << @as(Log2T, @intCast(@bitSizeOf(BackingType) - offset)) == 0);
                        }

                        { // Fixed-size Read/Write (Foreign-endian)

                            // Initialize Value
                            var value: BackingType = @byteSwap(init_value);

                            // Read
                            const read_value1 = readPackedInt(PackedType, asBytes(&value), offset, foreign_endian);
                            try expect(read_value1 == @as(PackedType, @bitCast(@as(uPackedType, @truncate(@byteSwap(value) >> @as(Log2T, @intCast(offset)))))));

                            // Write
                            writePackedInt(PackedType, asBytes(&value), offset, write_value, foreign_endian);
                            try expect(write_value == @as(PackedType, @bitCast(@as(uPackedType, @truncate(@byteSwap(value) >> @as(Log2T, @intCast(offset)))))));

                            // Read again
                            const read_value2 = readPackedInt(PackedType, asBytes(&value), offset, foreign_endian);
                            try expect(read_value2 == write_value);

                            // Verify bits outside of the target integer are unmodified
                            const diff_bits = init_value ^ @byteSwap(value);
                            if (offset != offset_at_end)
                                try expect(diff_bits >> @as(Log2T, @intCast(offset + @bitSizeOf(PackedType))) == 0);
                            if (offset != 0)
                                try expect(diff_bits << @as(Log2T, @intCast(@bitSizeOf(BackingType) - offset)) == 0);
                        }

                        const signedness = @typeInfo(PackedType).int.signedness;
                        const NextPowerOfTwoInt = std.meta.Int(signedness, try comptime std.math.ceilPowerOfTwo(u16, @bitSizeOf(PackedType)));
                        const ui64 = std.meta.Int(signedness, 64);
                        inline for ([_]type{ PackedType, NextPowerOfTwoInt, ui64 }) |U| {
                            { // Variable-size Read/Write (Native-endian)

                                if (@bitSizeOf(U) < @bitSizeOf(PackedType))
                                    continue;

                                // Initialize Value
                                var value: BackingType = init_value;

                                // Read
                                const read_value1 = readVarPackedInt(U, asBytes(&value), offset, @bitSizeOf(PackedType), native_endian, signedness);
                                try expect(read_value1 == @as(PackedType, @bitCast(@as(uPackedType, @truncate(value >> @as(Log2T, @intCast(offset)))))));

                                // Write
                                writeVarPackedInt(asBytes(&value), offset, @bitSizeOf(PackedType), @as(U, write_value), native_endian);
                                try expect(write_value == @as(PackedType, @bitCast(@as(uPackedType, @truncate(value >> @as(Log2T, @intCast(offset)))))));

                                // Read again
                                const read_value2 = readVarPackedInt(U, asBytes(&value), offset, @bitSizeOf(PackedType), native_endian, signedness);
                                try expect(read_value2 == write_value);

                                // Verify bits outside of the target integer are unmodified
                                const diff_bits = init_value ^ value;
                                if (offset != offset_at_end)
                                    try expect(diff_bits >> @as(Log2T, @intCast(offset + @bitSizeOf(PackedType))) == 0);
                                if (offset != 0)
                                    try expect(diff_bits << @as(Log2T, @intCast(@bitSizeOf(BackingType) - offset)) == 0);
                            }

                            { // Variable-size Read/Write (Foreign-endian)

                                if (@bitSizeOf(U) < @bitSizeOf(PackedType))
                                    continue;

                                // Initialize Value
                                var value: BackingType = @byteSwap(init_value);

                                // Read
                                const read_value1 = readVarPackedInt(U, asBytes(&value), offset, @bitSizeOf(PackedType), foreign_endian, signedness);
                                try expect(read_value1 == @as(PackedType, @bitCast(@as(uPackedType, @truncate(@byteSwap(value) >> @as(Log2T, @intCast(offset)))))));

                                // Write
                                writeVarPackedInt(asBytes(&value), offset, @bitSizeOf(PackedType), @as(U, write_value), foreign_endian);
                                try expect(write_value == @as(PackedType, @bitCast(@as(uPackedType, @truncate(@byteSwap(value) >> @as(Log2T, @intCast(offset)))))));

                                // Read again
                                const read_value2 = readVarPackedInt(U, asBytes(&value), offset, @bitSizeOf(PackedType), foreign_endian, signedness);
                                try expect(read_value2 == write_value);

                                // Verify bits outside of the target integer are unmodified
                                const diff_bits = init_value ^ @byteSwap(value);
                                if (offset != offset_at_end)
                                    try expect(diff_bits >> @as(Log2T, @intCast(offset + @bitSizeOf(PackedType))) == 0);
                                if (offset != 0)
                                    try expect(diff_bits << @as(Log2T, @intCast(@bitSizeOf(BackingType) - offset)) == 0);
                            }
                        }
                    }
                }
            }
        }
    }
}
//! The standard memory allocation interface.

const std = @import("../std.zig");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const Allocator = @This();
const builtin = @import("builtin");
const Alignment = std.mem.Alignment;

pub const Error = error{OutOfMemory};
pub const Log2Align = math.Log2Int(usize);

/// The type erased pointer to the allocator implementation.
///
/// Any comparison of this field may result in illegal behavior, since it may
/// be set to `undefined` in cases where the allocator implementation does not
/// have any associated state.
ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    /// Return a pointer to `len` bytes with specified `alignment`, or return
    /// `null` indicating the allocation failed.
    ///
    /// `ret_addr` is optionally provided as the first return address of the
    /// allocation call stack. If the value is `0` it means no return address
    /// has been provided.
    alloc: *const fn (*anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8,

    /// Attempt to expand or shrink memory in place.
    ///
    /// `memory.len` must equal the length requested from the most recent
    /// successful call to `alloc`, `resize`, or `remap`. `alignment` must
    /// equal the same value that was passed as the `alignment` parameter to
    /// the original `alloc` call.
    ///
    /// A result of `true` indicates the resize was successful and the
    /// allocation now has the same address but a size of `new_len`. `false`
    /// indicates the resize could not be completed without moving the
    /// allocation to a different address.
    ///
    /// `new_len` must be greater than zero.
    ///
    /// `ret_addr` is optionally provided as the first return address of the
    /// allocation call stack. If the value is `0` it means no return address
    /// has been provided.
    resize: *const fn (*anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool,

    /// Attempt to expand or shrink memory, allowing relocation.
    ///
    /// `memory.len` must equal the length requested from the most recent
    /// successful call to `alloc`, `resize`, or `remap`. `alignment` must
    /// equal the same value that was passed as the `alignment` parameter to
    /// the original `alloc` call.
    ///
    /// A non-`null` return value indicates the resize was successful. The
    /// allocation may have same address, or may have been relocated. In either
    /// case, the allocation now has size of `new_len`. A `null` return value
    /// indicates that the resize would be equivalent to allocating new memory,
    /// copying the bytes from the old memory, and then freeing the old memory.
    /// In such case, it is more efficient for the caller to perform the copy.
    ///
    /// `new_len` must be greater than zero.
    ///
    /// `ret_addr` is optionally provided as the first return address of the
    /// allocation call stack. If the value is `0` it means no return address
    /// has been provided.
    remap: *const fn (*anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8,

    /// Free and invalidate a region of memory.
    ///
    /// `memory.len` must equal the length requested from the most recent
    /// successful call to `alloc`, `resize`, or `remap`. `alignment` must
    /// equal the same value that was passed as the `alignment` parameter to
    /// the original `alloc` call.
    ///
    /// `ret_addr` is optionally provided as the first return address of the
    /// allocation call stack. If the value is `0` it means no return address
    /// has been provided.
    free: *const fn (*anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void,
};

pub fn noResize(
    self: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    _ = self;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = ret_addr;
    return false;
}

pub fn noRemap(
    self: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    ret_addr: usize,
) ?[*]u8 {
    _ = self;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = ret_addr;
    return null;
}

pub fn noFree(
    self: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    ret_addr: usize,
) void {
    _ = self;
    _ = memory;
    _ = alignment;
    _ = ret_addr;
}

/// This function is not intended to be called except from within the
/// implementation of an `Allocator`.
pub inline fn rawAlloc(a: Allocator, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
    return a.vtable.alloc(a.ptr, len, alignment, ret_addr);
}

/// This function is not intended to be called except from within the
/// implementation of an `Allocator`.
pub inline fn rawResize(a: Allocator, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
    return a.vtable.resize(a.ptr, memory, alignment, new_len, ret_addr);
}

/// This function is not intended to be called except from within the
/// implementation of an `Allocator`.
pub inline fn rawRemap(a: Allocator, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    return a.vtable.remap(a.ptr, memory, alignment, new_len, ret_addr);
}

/// This function is not intended to be called except from within the
/// implementation of an `Allocator`.
pub inline fn rawFree(a: Allocator, memory: []u8, alignment: Alignment, ret_addr: usize) void {
    return a.vtable.free(a.ptr, memory, alignment, ret_addr);
}

/// Returns a pointer to undefined memory.
/// Call `destroy` with the result to free the memory.
pub fn create(a: Allocator, comptime T: type) Error!*T {
    if (@sizeOf(T) == 0) {
        const ptr = comptime std.mem.alignBackward(usize, math.maxInt(usize), @alignOf(T));
        return @ptrFromInt(ptr);
    }
    const ptr: *T = @ptrCast(try a.allocBytesWithAlignment(.of(T), @sizeOf(T), @returnAddress()));
    return ptr;
}

/// `ptr` should be the return value of `create`, or otherwise
/// have the same address and alignment property.
pub fn destroy(self: Allocator, ptr: anytype) void {
    const info = @typeInfo(@TypeOf(ptr)).pointer;
    if (info.size != .one) @compileError("ptr must be a single item pointer");
    const T = info.child;
    if (@sizeOf(T) == 0) return;
    const non_const_ptr = @as([*]u8, @ptrCast(@constCast(ptr)));
    self.rawFree(non_const_ptr[0..@sizeOf(T)], .fromByteUnits(info.alignment), @returnAddress());
}

/// Allocates an array of `n` items of type `T` and sets all the
/// items to `undefined`. Depending on the Allocator
/// implementation, it may be required to call `free` once the
/// memory is no longer needed, to avoid a resource leak. If the
/// `Allocator` implementation is unknown, then correct code will
/// call `free` when done.
///
/// For allocating a single item, see `create`.
pub fn alloc(self: Allocator, comptime T: type, n: usize) Error![]T {
    return self.allocAdvancedWithRetAddr(T, null, n, @returnAddress());
}

pub fn allocWithOptions(
    self: Allocator,
    comptime Elem: type,
    n: usize,
    /// null means naturally aligned
    comptime optional_alignment: ?Alignment,
    comptime optional_sentinel: ?Elem,
) Error!AllocWithOptionsPayload(Elem, optional_alignment, optional_sentinel) {
    return self.allocWithOptionsRetAddr(Elem, n, optional_alignment, optional_sentinel, @returnAddress());
}

pub fn allocWithOptionsRetAddr(
    self: Allocator,
    comptime Elem: type,
    n: usize,
    /// null means naturally aligned
    comptime optional_alignment: ?Alignment,
    comptime optional_sentinel: ?Elem,
    return_address: usize,
) Error!AllocWithOptionsPayload(Elem, optional_alignment, optional_sentinel) {
    if (optional_sentinel) |sentinel| {
        const ptr = try self.allocAdvancedWithRetAddr(Elem, optional_alignment, n + 1, return_address);
        ptr[n] = sentinel;
        return ptr[0..n :sentinel];
    } else {
        return self.allocAdvancedWithRetAddr(Elem, optional_alignment, n, return_address);
    }
}

fn AllocWithOptionsPayload(comptime Elem: type, comptime alignment: ?Alignment, comptime sentinel: ?Elem) type {
    if (sentinel) |s| {
        return [:s]align(if (alignment) |a| a.toByteUnits() else @alignOf(Elem)) Elem;
    } else {
        return []align(if (alignment) |a| a.toByteUnits() else @alignOf(Elem)) Elem;
    }
}

/// Allocates an array of `n + 1` items of type `T` and sets the first `n`
/// items to `undefined` and the last item to `sentinel`. Depending on the
/// Allocator implementation, it may be required to call `free` once the
/// memory is no longer needed, to avoid a resource leak. If the
/// `Allocator` implementation is unknown, then correct code will
/// call `free` when done.
///
/// For allocating a single item, see `create`.
pub fn allocSentinel(
    self: Allocator,
    comptime Elem: type,
    n: usize,
    comptime sentinel: Elem,
) Error![:sentinel]Elem {
    return self.allocWithOptionsRetAddr(Elem, n, null, sentinel, @returnAddress());
}

pub fn alignedAlloc(
    self: Allocator,
    comptime T: type,
    /// null means naturally aligned
    comptime alignment: ?Alignment,
    n: usize,
) Error![]align(if (alignment) |a| a.toByteUnits() else @alignOf(T)) T {
    return self.allocAdvancedWithRetAddr(T, alignment, n, @returnAddress());
}

pub inline fn allocAdvancedWithRetAddr(
    self: Allocator,
    comptime T: type,
    /// null means naturally aligned
    comptime alignment: ?Alignment,
    n: usize,
    return_address: usize,
) Error![]align(if (alignment) |a| a.toByteUnits() else @alignOf(T)) T {
    const a = comptime (alignment orelse Alignment.fromByteUnits(@alignOf(T)));
    const ptr: [*]align(a.toByteUnits()) T = @ptrCast(try self.allocWithSizeAndAlignment(@sizeOf(T), a, n, return_address));
    return ptr[0..n];
}

fn allocWithSizeAndAlignment(
    self: Allocator,
    comptime size: usize,
    comptime alignment: Alignment,
    n: usize,
    return_address: usize,
) Error![*]align(alignment.toByteUnits()) u8 {
    const byte_count = math.mul(usize, size, n) catch return Error.OutOfMemory;
    return self.allocBytesWithAlignment(alignment, byte_count, return_address);
}

fn allocBytesWithAlignment(
    self: Allocator,
    comptime alignment: Alignment,
    byte_count: usize,
    return_address: usize,
) Error![*]align(alignment.toByteUnits()) u8 {
    if (byte_count == 0) {
        const ptr = comptime alignment.backward(math.maxInt(usize));
        return @as([*]align(alignment.toByteUnits()) u8, @ptrFromInt(ptr));
    }

    const byte_ptr = self.rawAlloc(byte_count, alignment, return_address) orelse return Error.OutOfMemory;
    @memset(byte_ptr[0..byte_count], undefined);
    return @alignCast(byte_ptr);
}

/// Request to modify the size of an allocation.
///
/// It is guaranteed to not move the pointer, however the allocator
/// implementation may refuse the resize request by returning `false`.
///
/// `allocation` may be an empty slice, in which case a new allocation is made.
///
/// `new_len` may be zero, in which case the allocation is freed.
pub fn resize(self: Allocator, allocation: anytype, new_len: usize) bool {
    const Slice = @typeInfo(@TypeOf(allocation)).pointer;
    const T = Slice.child;
    const alignment = Slice.alignment;
    if (new_len == 0) {
        self.free(allocation);
        return true;
    }
    if (allocation.len == 0) {
        return false;
    }
    const old_memory = mem.sliceAsBytes(allocation);
    // I would like to use saturating multiplication here, but LLVM cannot lower it
    // on WebAssembly: https://github.com/ziglang/zig/issues/9660
    //const new_len_bytes = new_len *| @sizeOf(T);
    const new_len_bytes = math.mul(usize, @sizeOf(T), new_len) catch return false;
    return self.rawResize(old_memory, .fromByteUnits(alignment), new_len_bytes, @returnAddress());
}

/// Request to modify the size of an allocation, allowing relocation.
///
/// A non-`null` return value indicates the resize was successful. The
/// allocation may have same address, or may have been relocated. In either
/// case, the allocation now has size of `new_len`. A `null` return value
/// indicates that the resize would be equivalent to allocating new memory,
/// copying the bytes from the old memory, and then freeing the old memory.
/// In such case, it is more efficient for the caller to perform those
/// operations.
///
/// `allocation` may be an empty slice, in which case `null` is returned,
/// unless `new_len` is also 0, in which case `allocation` is returned.
///
/// `new_len` may be zero, in which case the allocation is freed.
///
/// If the allocation's elements' type is zero bytes sized, `allocation.len` is set to `new_len`.
pub fn remap(self: Allocator, allocation: anytype, new_len: usize) t: {
    const Slice = @typeInfo(@TypeOf(allocation)).pointer;
    break :t ?[]align(Slice.alignment) Slice.child;
} {
    const Slice = @typeInfo(@TypeOf(allocation)).pointer;
    const T = Slice.child;

    const alignment = Slice.alignment;
    if (new_len == 0) {
        self.free(allocation);
        return allocation[0..0];
    }
    if (allocation.len == 0) {
        return null;
    }
    if (@sizeOf(T) == 0) {
        var new_memory = allocation;
        new_memory.len = new_len;
        return new_memory;
    }
    const old_memory = mem.sliceAsBytes(allocation);
    // I would like to use saturating multiplication here, but LLVM cannot lower it
    // on WebAssembly: https://github.com/ziglang/zig/issues/9660
    //const new_len_bytes = new_len *| @sizeOf(T);
    const new_len_bytes = math.mul(usize, @sizeOf(T), new_len) catch return null;
    const new_ptr = self.rawRemap(old_memory, .fromByteUnits(alignment), new_len_bytes, @returnAddress()) orelse return null;
    const new_memory: []align(alignment) u8 = @alignCast(new_ptr[0..new_len_bytes]);
    return mem.bytesAsSlice(T, new_memory);
}

/// This function requests a new byte size for an existing allocation, which
/// can be larger, smaller, or the same size as the old memory allocation.
///
/// If `new_n` is 0, this is the same as `free` and it always succeeds.
///
/// `old_mem` may have length zero, which makes a new allocation.
///
/// This function only fails on out-of-memory conditions, unlike:
/// * `remap` which returns `null` when the `Allocator` implementation cannot
///   do the realloc more efficiently than the caller
/// * `resize` which returns `false` when the `Allocator` implementation cannot
///   change the size without relocating the allocation.
pub fn realloc(self: Allocator, old_mem: anytype, new_n: usize) t: {
    const Slice = @typeInfo(@TypeOf(old_mem)).pointer;
    break :t Error![]align(Slice.alignment) Slice.child;
} {
    return self.reallocAdvanced(old_mem, new_n, @returnAddress());
}

pub fn reallocAdvanced(
    self: Allocator,
    old_mem: anytype,
    new_n: usize,
    return_address: usize,
) t: {
    const Slice = @typeInfo(@TypeOf(old_mem)).pointer;
    break :t Error![]align(Slice.alignment) Slice.child;
} {
    const Slice = @typeInfo(@TypeOf(old_mem)).pointer;
    const T = Slice.child;
    if (old_mem.len == 0) {
        return self.allocAdvancedWithRetAddr(T, .fromByteUnits(Slice.alignment), new_n, return_address);
    }
    if (new_n == 0) {
        self.free(old_mem);
        const ptr = comptime std.mem.alignBackward(usize, math.maxInt(usize), Slice.alignment);
        return @as([*]align(Slice.alignment) T, @ptrFromInt(ptr))[0..0];
    }

    const old_byte_slice = mem.sliceAsBytes(old_mem);
    const byte_count = math.mul(usize, @sizeOf(T), new_n) catch return Error.OutOfMemory;
    // Note: can't set shrunk memory to undefined as memory shouldn't be modified on realloc failure
    if (self.rawRemap(old_byte_slice, .fromByteUnits(Slice.alignment), byte_count, return_address)) |p| {
        const new_bytes: []align(Slice.alignment) u8 = @alignCast(p[0..byte_count]);
        return mem.bytesAsSlice(T, new_bytes);
    }

    const new_mem = self.rawAlloc(byte_count, .fromByteUnits(Slice.alignment), return_address) orelse
        return error.OutOfMemory;
    const copy_len = @min(byte_count, old_byte_slice.len);
    @memcpy(new_mem[0..copy_len], old_byte_slice[0..copy_len]);
    @memset(old_byte_slice, undefined);
    self.rawFree(old_byte_slice, .fromByteUnits(Slice.alignment), return_address);

    const new_bytes: []align(Slice.alignment) u8 = @alignCast(new_mem[0..byte_count]);
    return mem.bytesAsSlice(T, new_bytes);
}

/// Free an array allocated with `alloc`.
/// If memory has length 0, free is a no-op.
/// To free a single item, see `destroy`.
pub fn free(self: Allocator, memory: anytype) void {
    const Slice = @typeInfo(@TypeOf(memory)).pointer;
    const bytes = mem.sliceAsBytes(memory);
    const bytes_len = bytes.len + if (Slice.sentinel() != null) @sizeOf(Slice.child) else 0;
    if (bytes_len == 0) return;
    const non_const_ptr = @constCast(bytes.ptr);
    @memset(non_const_ptr[0..bytes_len], undefined);
    self.rawFree(non_const_ptr[0..bytes_len], .fromByteUnits(Slice.alignment), @returnAddress());
}

/// Copies `m` to newly allocated memory. Caller owns the memory.
pub fn dupe(allocator: Allocator, comptime T: type, m: []const T) Error![]T {
    const new_buf = try allocator.alloc(T, m.len);
    @memcpy(new_buf, m);
    return new_buf;
}

/// Copies `m` to newly allocated memory, with a null-terminated element. Caller owns the memory.
pub fn dupeZ(allocator: Allocator, comptime T: type, m: []const T) Error![:0]T {
    const new_buf = try allocator.alloc(T, m.len + 1);
    @memcpy(new_buf[0..m.len], m);
    new_buf[m.len] = 0;
    return new_buf[0..m.len :0];
}
const std = @import("std.zig");
const debug = std.debug;
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const root = @import("root");

pub const TrailerFlags = @import("meta/trailer_flags.zig").TrailerFlags;

const Type = std.builtin.Type;

test {
    _ = TrailerFlags;
}

/// Returns the variant of an enum type, `T`, which is named `str`, or `null` if no such variant exists.
pub fn stringToEnum(comptime T: type, str: []const u8) ?T {
    // Using StaticStringMap here is more performant, but it will start to take too
    // long to compile if the enum is large enough, due to the current limits of comptime
    // performance when doing things like constructing lookup maps at comptime.
    // TODO The '100' here is arbitrary and should be increased when possible:
    // - https://github.com/ziglang/zig/issues/4055
    // - https://github.com/ziglang/zig/issues/3863
    if (@typeInfo(T).@"enum".fields.len <= 100) {
        const kvs = comptime build_kvs: {
            const EnumKV = struct { []const u8, T };
            var kvs_array: [@typeInfo(T).@"enum".fields.len]EnumKV = undefined;
            for (@typeInfo(T).@"enum".fields, 0..) |enumField, i| {
                kvs_array[i] = .{ enumField.name, @field(T, enumField.name) };
            }
            break :build_kvs kvs_array[0..];
        };
        const map = std.StaticStringMap(T).initComptime(kvs);
        return map.get(str);
    } else {
        inline for (@typeInfo(T).@"enum".fields) |enumField| {
            if (mem.eql(u8, str, enumField.name)) {
                return @field(T, enumField.name);
            }
        }
        return null;
    }
}

test stringToEnum {
    const E1 = enum {
        A,
        B,
    };
    try testing.expect(E1.A == stringToEnum(E1, "A").?);
    try testing.expect(E1.B == stringToEnum(E1, "B").?);
    try testing.expect(null == stringToEnum(E1, "C"));
}

/// Returns the alignment of type T.
/// Note that if T is a pointer type the result is different than the one
/// returned by @alignOf(T).
/// If T is a pointer type the alignment of the type it points to is returned.
pub fn alignment(comptime T: type) comptime_int {
    return switch (@typeInfo(T)) {
        .optional => |info| switch (@typeInfo(info.child)) {
            .pointer, .@"fn" => alignment(info.child),
            else => @alignOf(T),
        },
        .pointer => |info| info.alignment,
        else => @alignOf(T),
    };
}

test alignment {
    try testing.expect(alignment(u8) == 1);
    try testing.expect(alignment(*align(1) u8) == 1);
    try testing.expect(alignment(*align(2) u8) == 2);
    try testing.expect(alignment([]align(1) u8) == 1);
    try testing.expect(alignment([]align(2) u8) == 2);
    try testing.expect(alignment(fn () void) > 0);
    try testing.expect(alignment(*const fn () void) > 0);
    try testing.expect(alignment(*align(128) const fn () void) == 128);
}

/// Given a parameterized type (array, vector, pointer, optional), returns the "child type".
pub fn Child(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .array => |info| info.child,
        .vector => |info| info.child,
        .pointer => |info| info.child,
        .optional => |info| info.child,
        else => @compileError("Expected pointer, optional, array or vector type, found '" ++ @typeName(T) ++ "'"),
    };
}

test Child {
    try testing.expect(Child([1]u8) == u8);
    try testing.expect(Child(*u8) == u8);
    try testing.expect(Child([]u8) == u8);
    try testing.expect(Child(?u8) == u8);
    try testing.expect(Child(@Vector(2, u8)) == u8);
}

/// Given a "memory span" type (array, slice, vector, or pointer to such), returns the "element type".
pub fn Elem(comptime T: type) type {
    switch (@typeInfo(T)) {
        .array => |info| return info.child,
        .vector => |info| return info.child,
        .pointer => |info| switch (info.size) {
            .one => switch (@typeInfo(info.child)) {
                .array => |array_info| return array_info.child,
                .vector => |vector_info| return vector_info.child,
                else => {},
            },
            .many, .c, .slice => return info.child,
        },
        .optional => |info| return Elem(info.child),
        else => {},
    }
    @compileError("Expected pointer, slice, array or vector type, found '" ++ @typeName(T) ++ "'");
}

test Elem {
    try testing.expect(Elem([1]u8) == u8);
    try testing.expect(Elem([*]u8) == u8);
    try testing.expect(Elem([]u8) == u8);
    try testing.expect(Elem(*[10]u8) == u8);
    try testing.expect(Elem(@Vector(2, u8)) == u8);
    try testing.expect(Elem(*@Vector(2, u8)) == u8);
    try testing.expect(Elem(?[*]u8) == u8);
}

/// Given a type which can have a sentinel e.g. `[:0]u8`, returns the sentinel value,
/// or `null` if there is not one.
/// Types which cannot possibly have a sentinel will be a compile error.
/// Result is always comptime-known.
pub inline fn sentinel(comptime T: type) ?Elem(T) {
    switch (@typeInfo(T)) {
        .array => |info| return info.sentinel(),
        .pointer => |info| {
            switch (info.size) {
                .many, .slice => return info.sentinel(),
                .one => switch (@typeInfo(info.child)) {
                    .array => |array_info| return array_info.sentinel(),
                    else => {},
                },
                else => {},
            }
        },
        else => {},
    }
    @compileError("type '" ++ @typeName(T) ++ "' cannot possibly have a sentinel");
}

test sentinel {
    try testSentinel();
    try comptime testSentinel();
}

fn testSentinel() !void {
    try testing.expectEqual(@as(u8, 0), sentinel([:0]u8).?);
    try testing.expectEqual(@as(u8, 0), sentinel([*:0]u8).?);
    try testing.expectEqual(@as(u8, 0), sentinel([5:0]u8).?);
    try testing.expectEqual(@as(u8, 0), sentinel(*const [5:0]u8).?);

    try testing.expect(sentinel([]u8) == null);
    try testing.expect(sentinel([*]u8) == null);
    try testing.expect(sentinel([5]u8) == null);
    try testing.expect(sentinel(*const [5]u8) == null);
}

/// Given a "memory span" type, returns the same type except with the given sentinel value.
pub fn Sentinel(comptime T: type, comptime sentinel_val: Elem(T)) type {
    switch (@typeInfo(T)) {
        .pointer => |info| switch (info.size) {
            .one => switch (@typeInfo(info.child)) {
                .array => |array_info| return @Type(.{
                    .pointer = .{
                        .size = info.size,
                        .is_const = info.is_const,
                        .is_volatile = info.is_volatile,
                        .alignment = info.alignment,
                        .address_space = info.address_space,
                        .child = @Type(.{
                            .array = .{
                                .len = array_info.len,
                                .child = array_info.child,
                                .sentinel_ptr = @as(?*const anyopaque, @ptrCast(&sentinel_val)),
                            },
                        }),
                        .is_allowzero = info.is_allowzero,
                        .sentinel_ptr = info.sentinel_ptr,
                    },
                }),
                else => {},
            },
            .many, .slice => return @Type(.{
                .pointer = .{
                    .size = info.size,
                    .is_const = info.is_const,
                    .is_volatile = info.is_volatile,
                    .alignment = info.alignment,
                    .address_space = info.address_space,
                    .child = info.child,
                    .is_allowzero = info.is_allowzero,
                    .sentinel_ptr = @as(?*const anyopaque, @ptrCast(&sentinel_val)),
                },
            }),
            else => {},
        },
        .optional => |info| switch (@typeInfo(info.child)) {
            .pointer => |ptr_info| switch (ptr_info.size) {
                .many => return @Type(.{
                    .optional = .{
                        .child = @Type(.{
                            .pointer = .{
                                .size = ptr_info.size,
                                .is_const = ptr_info.is_const,
                                .is_volatile = ptr_info.is_volatile,
                                .alignment = ptr_info.alignment,
                                .address_space = ptr_info.address_space,
                                .child = ptr_info.child,
                                .is_allowzero = ptr_info.is_allowzero,
                                .sentinel_ptr = @as(?*const anyopaque, @ptrCast(&sentinel_val)),
                            },
                        }),
                    },
                }),
                else => {},
            },
            else => {},
        },
        else => {},
    }
    @compileError("Unable to derive a sentinel pointer type from " ++ @typeName(T));
}

pub fn containerLayout(comptime T: type) Type.ContainerLayout {
    return switch (@typeInfo(T)) {
        .@"struct" => |info| info.layout,
        .@"union" => |info| info.layout,
        else => @compileError("expected struct or union type, found '" ++ @typeName(T) ++ "'"),
    };
}

test containerLayout {
    const S1 = struct {};
    const S2 = packed struct {};
    const S3 = extern struct {};
    const U1 = union {
        a: u8,
    };
    const U2 = packed union {
        a: u8,
    };
    const U3 = extern union {
        a: u8,
    };

    try testing.expect(containerLayout(S1) == .auto);
    try testing.expect(containerLayout(S2) == .@"packed");
    try testing.expect(containerLayout(S3) == .@"extern");
    try testing.expect(containerLayout(U1) == .auto);
    try testing.expect(containerLayout(U2) == .@"packed");
    try testing.expect(containerLayout(U3) == .@"extern");
}

/// Instead of this function, prefer to use e.g. `@typeInfo(foo).@"struct".decls`
/// directly when you know what kind of type it is.
pub fn declarations(comptime T: type) []const Type.Declaration {
    return switch (@typeInfo(T)) {
        .@"struct" => |info| info.decls,
        .@"enum" => |info| info.decls,
        .@"union" => |info| info.decls,
        .@"opaque" => |info| info.decls,
        else => @compileError("Expected struct, enum, union, or opaque type, found '" ++ @typeName(T) ++ "'"),
    };
}

test declarations {
    const E1 = enum {
        A,

        pub fn a() void {}
    };
    const S1 = struct {
        pub fn a() void {}
    };
    const U1 = union {
        b: u8,

        pub fn a() void {}
    };
    const O1 = opaque {
        pub fn a() void {}
    };

    const decls = comptime [_][]const Type.Declaration{
        declarations(E1),
        declarations(S1),
        declarations(U1),
        declarations(O1),
    };

    inline for (decls) |decl| {
        try testing.expect(decl.len == 1);
        try testing.expect(comptime mem.eql(u8, decl[0].name, "a"));
    }
}

pub fn declarationInfo(comptime T: type, comptime decl_name: []const u8) Type.Declaration {
    inline for (comptime declarations(T)) |decl| {
        if (comptime mem.eql(u8, decl.name, decl_name))
            return decl;
    }

    @compileError("'" ++ @typeName(T) ++ "' has no declaration '" ++ decl_name ++ "'");
}

test declarationInfo {
    const E1 = enum {
        A,

        pub fn a() void {}
    };
    const S1 = struct {
        pub fn a() void {}
    };
    const U1 = union {
        b: u8,

        pub fn a() void {}
    };

    const infos = comptime [_]Type.Declaration{
        declarationInfo(E1, "a"),
        declarationInfo(S1, "a"),
        declarationInfo(U1, "a"),
    };

    inline for (infos) |info| {
        try testing.expect(comptime mem.eql(u8, info.name, "a"));
    }
}
pub fn fields(comptime T: type) switch (@typeInfo(T)) {
    .@"struct" => []const Type.StructField,
    .@"union" => []const Type.UnionField,
    .@"enum" => []const Type.EnumField,
    .error_set => []const Type.Error,
    else => @compileError("Expected struct, union, error set or enum type, found '" ++ @typeName(T) ++ "'"),
} {
    return switch (@typeInfo(T)) {
        .@"struct" => |info| info.fields,
        .@"union" => |info| info.fields,
        .@"enum" => |info| info.fields,
        .error_set => |errors| errors.?, // must be non global error set
        else => @compileError("Expected struct, union, error set or enum type, found '" ++ @typeName(T) ++ "'"),
    };
}

test fields {
    const E1 = enum {
        A,
    };
    const E2 = error{A};
    const S1 = struct {
        a: u8,
    };
    const U1 = union {
        a: u8,
    };

    const e1f = comptime fields(E1);
    const e2f = comptime fields(E2);
    const sf = comptime fields(S1);
    const uf = comptime fields(U1);

    try testing.expect(e1f.len == 1);
    try testing.expect(e2f.len == 1);
    try testing.expect(sf.len == 1);
    try testing.expect(uf.len == 1);
    try testing.expect(mem.eql(u8, e1f[0].name, "A"));
    try testing.expect(mem.eql(u8, e2f[0].name, "A"));
    try testing.expect(mem.eql(u8, sf[0].name, "a"));
    try testing.expect(mem.eql(u8, uf[0].name, "a"));
    try testing.expect(comptime sf[0].type == u8);
    try testing.expect(comptime uf[0].type == u8);
}

pub fn fieldInfo(comptime T: type, comptime field: FieldEnum(T)) switch (@typeInfo(T)) {
    .@"struct" => Type.StructField,
    .@"union" => Type.UnionField,
    .@"enum" => Type.EnumField,
    .error_set => Type.Error,
    else => @compileError("Expected struct, union, error set or enum type, found '" ++ @typeName(T) ++ "'"),
} {
    return fields(T)[@intFromEnum(field)];
}

test fieldInfo {
    const E1 = enum {
        A,
    };
    const E2 = error{A};
    const S1 = struct {
        a: u8,
    };
    const U1 = union {
        a: u8,
    };

    const e1f = fieldInfo(E1, .A);
    const e2f = fieldInfo(E2, .A);
    const sf = fieldInfo(S1, .a);
    const uf = fieldInfo(U1, .a);

    try testing.expect(mem.eql(u8, e1f.name, "A"));
    try testing.expect(mem.eql(u8, e2f.name, "A"));
    try testing.expect(mem.eql(u8, sf.name, "a"));
    try testing.expect(mem.eql(u8, uf.name, "a"));
    try testing.expect(comptime sf.type == u8);
    try testing.expect(comptime uf.type == u8);
}

/// Deprecated: use @FieldType
pub fn FieldType(comptime T: type, comptime field: FieldEnum(T)) type {
    return @FieldType(T, @tagName(field));
}

test FieldType {
    const S = struct {
        a: u8,
        b: u16,
    };

    const U = union {
        c: u32,
        d: *const u8,
    };

    try testing.expect(FieldType(S, .a) == u8);
    try testing.expect(FieldType(S, .b) == u16);

    try testing.expect(FieldType(U, .c) == u32);
    try testing.expect(FieldType(U, .d) == *const u8);
}

pub fn fieldNames(comptime T: type) *const [fields(T).len][:0]const u8 {
    return comptime blk: {
        const fieldInfos = fields(T);
        var names: [fieldInfos.len][:0]const u8 = undefined;
        for (&names, fieldInfos) |*name, field| name.* = field.name;
        const final = names;
        break :blk &final;
    };
}

test fieldNames {
    const E1 = enum { A, B };
    const E2 = error{A};
    const S1 = struct {
        a: u8,
    };
    const U1 = union {
        a: u8,
        b: void,
    };

    const e1names = fieldNames(E1);
    const e2names = fieldNames(E2);
    const s1names = fieldNames(S1);
    const u1names = fieldNames(U1);

    try testing.expect(e1names.len == 2);
    try testing.expectEqualSlices(u8, e1names[0], "A");
    try testing.expectEqualSlices(u8, e1names[1], "B");
    try testing.expect(e2names.len == 1);
    try testing.expectEqualSlices(u8, e2names[0], "A");
    try testing.expect(s1names.len == 1);
    try testing.expectEqualSlices(u8, s1names[0], "a");
    try testing.expect(u1names.len == 2);
    try testing.expectEqualSlices(u8, u1names[0], "a");
    try testing.expectEqualSlices(u8, u1names[1], "b");
}

/// Given an enum or error set type, returns a pointer to an array containing all tags for that
/// enum or error set.
pub fn tags(comptime T: type) *const [fields(T).len]T {
    return comptime blk: {
        const fieldInfos = fields(T);
        var res: [fieldInfos.len]T = undefined;
        for (fieldInfos, 0..) |field, i| {
            res[i] = @field(T, field.name);
        }
        const final = res;
        break :blk &final;
    };
}

test tags {
    const E1 = enum { A, B };
    const E2 = error{A};

    const e1_tags = tags(E1);
    const e2_tags = tags(E2);

    try testing.expect(e1_tags.len == 2);
    try testing.expectEqual(E1.A, e1_tags[0]);
    try testing.expectEqual(E1.B, e1_tags[1]);
    try testing.expect(e2_tags.len == 1);
    try testing.expectEqual(E2.A, e2_tags[0]);
}

/// Returns an enum with a variant named after each field of `T`.
pub fn FieldEnum(comptime T: type) type {
    const field_infos = fields(T);

    if (field_infos.len == 0) {
        return @Type(.{
            .@"enum" = .{
                .tag_type = u0,
                .fields = &.{},
                .decls = &.{},
                .is_exhaustive = true,
            },
        });
    }

    if (@typeInfo(T) == .@"union") {
        if (@typeInfo(T).@"union".tag_type) |tag_type| {
            for (std.enums.values(tag_type), 0..) |v, i| {
                if (@intFromEnum(v) != i) break; // enum values not consecutive
                if (!std.mem.eql(u8, @tagName(v), field_infos[i].name)) break; // fields out of order
            } else {
                return tag_type;
            }
        }
    }

    var enumFields: [field_infos.len]std.builtin.Type.EnumField = undefined;
    var decls = [_]std.builtin.Type.Declaration{};
    inline for (field_infos, 0..) |field, i| {
        enumFields[i] = .{
            .name = field.name ++ "",
            .value = i,
        };
    }
    return @Type(.{
        .@"enum" = .{
            .tag_type = std.math.IntFittingRange(0, field_infos.len - 1),
            .fields = &enumFields,
            .decls = &decls,
            .is_exhaustive = true,
        },
    });
}

fn expectEqualEnum(expected: anytype, actual: @TypeOf(expected)) !void {
    // TODO: https://github.com/ziglang/zig/issues/7419
    // testing.expectEqual(@typeInfo(expected).@"enum", @typeInfo(actual).@"enum");
    try testing.expectEqual(
        @typeInfo(expected).@"enum".tag_type,
        @typeInfo(actual).@"enum".tag_type,
    );
    // For comparing decls and fields, we cannot use the meta eql function here
    // because the language does not guarantee that the slice pointers for field names
    // and decl names will be the same.
    comptime {
        const expected_fields = @typeInfo(expected).@"enum".fields;
        const actual_fields = @typeInfo(actual).@"enum".fields;
        if (expected_fields.len != actual_fields.len) return error.FailedTest;
        for (expected_fields, 0..) |expected_field, i| {
            const actual_field = actual_fields[i];
            try testing.expectEqual(expected_field.value, actual_field.value);
            try testing.expectEqualStrings(expected_field.name, actual_field.name);
        }
    }
    comptime {
        const expected_decls = @typeInfo(expected).@"enum".decls;
        const actual_decls = @typeInfo(actual).@"enum".decls;
        if (expected_decls.len != actual_decls.len) return error.FailedTest;
        for (expected_decls, 0..) |expected_decl, i| {
            const actual_decl = actual_decls[i];
            try testing.expectEqualStrings(expected_decl.name, actual_decl.name);
        }
    }
    try testing.expectEqual(
        @typeInfo(expected).@"enum".is_exhaustive,
        @typeInfo(actual).@"enum".is_exhaustive,
    );
}

test FieldEnum {
    try expectEqualEnum(enum {}, FieldEnum(struct {}));
    try expectEqualEnum(enum { a }, FieldEnum(struct { a: u8 }));
    try expectEqualEnum(enum { a, b, c }, FieldEnum(struct { a: u8, b: void, c: f32 }));
    try expectEqualEnum(enum { a, b, c }, FieldEnum(union { a: u8, b: void, c: f32 }));

    const Tagged = union(enum) { a: u8, b: void, c: f32 };
    try testing.expectEqual(Tag(Tagged), FieldEnum(Tagged));

    const Tag2 = enum { a, b, c };
    const Tagged2 = union(Tag2) { a: u8, b: void, c: f32 };
    try testing.expect(Tag(Tagged2) == FieldEnum(Tagged2));

    const Tag3 = enum(u8) { a, b, c = 7 };
    const Tagged3 = union(Tag3) { a: u8, b: void, c: f32 };
    try testing.expect(Tag(Tagged3) != FieldEnum(Tagged3));
}

pub fn DeclEnum(comptime T: type) type {
    const fieldInfos = std.meta.declarations(T);
    var enumDecls: [fieldInfos.len]std.builtin.Type.EnumField = undefined;
    var decls = [_]std.builtin.Type.Declaration{};
    inline for (fieldInfos, 0..) |field, i| {
        enumDecls[i] = .{ .name = field.name ++ "", .value = i };
    }
    return @Type(.{
        .@"enum" = .{
            .tag_type = std.math.IntFittingRange(0, if (fieldInfos.len == 0) 0 else fieldInfos.len - 1),
            .fields = &enumDecls,
            .decls = &decls,
            .is_exhaustive = true,
        },
    });
}

test DeclEnum {
    const A = struct {
        pub const a: u8 = 0;
    };
    const B = union {
        foo: void,

        pub const a: u8 = 0;
        pub const b: void = {};
        pub const c: f32 = 0;
    };
    const C = enum {
        bar,

        pub const a: u8 = 0;
        pub const b: void = {};
        pub const c: f32 = 0;
    };
    const D = struct {};

    try expectEqualEnum(enum { a }, DeclEnum(A));
    try expectEqualEnum(enum { a, b, c }, DeclEnum(B));
    try expectEqualEnum(enum { a, b, c }, DeclEnum(C));
    try expectEqualEnum(enum {}, DeclEnum(D));
}

pub fn Tag(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .@"enum" => |info| info.tag_type,
        .@"union" => |info| info.tag_type orelse @compileError(@typeName(T) ++ " has no tag type"),
        else => @compileError("expected enum or union type, found '" ++ @typeName(T) ++ "'"),
    };
}

test Tag {
    const E = enum(u8) {
        C = 33,
        D,
    };
    const U = union(E) {
        C: u8,
        D: u16,
    };

    try testing.expect(Tag(E) == u8);
    try testing.expect(Tag(U) == E);
}

/// Returns the active tag of a tagged union
pub fn activeTag(u: anytype) Tag(@TypeOf(u)) {
    const T = @TypeOf(u);
    return @as(Tag(T), u);
}

test activeTag {
    const UE = enum {
        Int,
        Float,
    };

    const U = union(UE) {
        Int: u32,
        Float: f32,
    };

    var u = U{ .Int = 32 };
    try testing.expect(activeTag(u) == UE.Int);

    u = U{ .Float = 112.9876 };
    try testing.expect(activeTag(u) == UE.Float);
}

/// Deprecated: Use @FieldType(U, tag_name)
const TagPayloadType = TagPayload;

/// Deprecated: Use @FieldType(U, tag_name)
pub fn TagPayloadByName(comptime U: type, comptime tag_name: []const u8) type {
    const info = @typeInfo(U).@"union";

    inline for (info.fields) |field_info| {
        if (comptime mem.eql(u8, field_info.name, tag_name))
            return field_info.type;
    }

    @compileError("no field '" ++ tag_name ++ "' in union '" ++ @typeName(U) ++ "'");
}

/// Deprecated: Use @FieldType(U, @tagName(tag))
pub fn TagPayload(comptime U: type, comptime tag: Tag(U)) type {
    return TagPayloadByName(U, @tagName(tag));
}

test TagPayload {
    const Event = union(enum) {
        Moved: struct {
            from: i32,
            to: i32,
        },
    };
    const MovedEvent = TagPayload(Event, Event.Moved);
    const e: Event = .{ .Moved = undefined };
    try testing.expect(MovedEvent == @TypeOf(e.Moved));
}

/// Compares two of any type for equality. Containers that do not support comparison
/// on their own are compared on a field-by-field basis. Pointers are not followed.
pub fn eql(a: anytype, b: @TypeOf(a)) bool {
    const T = @TypeOf(a);

    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            if (info.layout == .@"packed") return a == b;

            inline for (info.fields) |field_info| {
                if (!eql(@field(a, field_info.name), @field(b, field_info.name))) return false;
            }
            return true;
        },
        .error_union => {
            if (a) |a_p| {
                if (b) |b_p| return eql(a_p, b_p) else |_| return false;
            } else |a_e| {
                if (b) |_| return false else |b_e| return a_e == b_e;
            }
        },
        .@"union" => |info| {
            if (info.tag_type) |UnionTag| {
                const tag_a: UnionTag = a;
                const tag_b: UnionTag = b;
                if (tag_a != tag_b) return false;

                return switch (a) {
                    inline else => |val, tag| return eql(val, @field(b, @tagName(tag))),
                };
            }

            @compileError("cannot compare untagged union type " ++ @typeName(T));
        },
        .array => {
            if (a.len != b.len) return false;
            for (a, 0..) |e, i|
                if (!eql(e, b[i])) return false;
            return true;
        },
        .vector => |info| {
            var i: usize = 0;
            while (i < info.len) : (i += 1) {
                if (!eql(a[i], b[i])) return false;
            }
            return true;
        },
        .pointer => |info| {
            return switch (info.size) {
                .one, .many, .c => a == b,
                .slice => a.ptr == b.ptr and a.len == b.len,
            };
        },
        .optional => {
            if (a == null and b == null) return true;
            if (a == null or b == null) return false;
            return eql(a.?, b.?);
        },
        else => return a == b,
    }
}

test eql {
    const S = struct {
        a: u32,
        b: f64,
        c: [5]u8,
    };

    const U = union(enum) {
        s: S,
        f: ?f32,
    };

    const s_1 = S{
        .a = 134,
        .b = 123.3,
        .c = "12345".*,
    };

    var s_3 = S{
        .a = 134,
        .b = 123.3,
        .c = "12345".*,
    };

    const u_1 = U{ .f = 24 };
    const u_2 = U{ .s = s_1 };
    const u_3 = U{ .f = 24 };

    try testing.expect(eql(s_1, s_3));
    try testing.expect(eql(&s_1, &s_1));
    try testing.expect(!eql(&s_1, &s_3));
    try testing.expect(eql(u_1, u_3));
    try testing.expect(!eql(u_1, u_2));

    const a1 = "abcdef".*;
    const a2 = "abcdef".*;
    const a3 = "ghijkl".*;

    try testing.expect(eql(a1, a2));
    try testing.expect(!eql(a1, a3));

    const EU = struct {
        fn tst(err: bool) !u8 {
            if (err) return error.Error;
            return @as(u8, 5);
        }
    };

    try testing.expect(eql(EU.tst(true), EU.tst(true)));
    try testing.expect(eql(EU.tst(false), EU.tst(false)));
    try testing.expect(!eql(EU.tst(false), EU.tst(true)));

    const V = @Vector(4, u32);
    const v1: V = @splat(1);
    const v2: V = @splat(1);
    const v3: V = @splat(2);

    try testing.expect(eql(v1, v2));
    try testing.expect(!eql(v1, v3));

    const CU = union(enum) {
        a: void,
        b: void,
        c: comptime_int,
    };

    try testing.expect(eql(CU{ .a = {} }, .a));
    try testing.expect(!eql(CU{ .a = {} }, .b));
}

test intToEnum {
    const E1 = enum {
        A,
    };
    const E2 = enum {
        A,
        B,
    };
    const E3 = enum(i8) { A, _ };

    var zero: u8 = 0;
    var one: u16 = 1;
    _ = &zero;
    _ = &one;
    try testing.expect(intToEnum(E1, zero) catch unreachable == E1.A);
    try testing.expect(intToEnum(E2, one) catch unreachable == E2.B);
    try testing.expect(intToEnum(E3, zero) catch unreachable == E3.A);
    try testing.expect(intToEnum(E3, 127) catch unreachable == @as(E3, @enumFromInt(127)));
    try testing.expect(intToEnum(E3, -128) catch unreachable == @as(E3, @enumFromInt(-128)));
    try testing.expectError(error.InvalidEnumTag, intToEnum(E1, one));
    try testing.expectError(error.InvalidEnumTag, intToEnum(E3, 128));
    try testing.expectError(error.InvalidEnumTag, intToEnum(E3, -129));
}

pub const IntToEnumError = error{InvalidEnumTag};

pub fn intToEnum(comptime EnumTag: type, tag_int: anytype) IntToEnumError!EnumTag {
    const enum_info = @typeInfo(EnumTag).@"enum";

    if (!enum_info.is_exhaustive) {
        if (std.math.cast(enum_info.tag_type, tag_int)) |tag| {
            return @as(EnumTag, @enumFromInt(tag));
        }
        return error.InvalidEnumTag;
    }

    // We don't directly iterate over the fields of EnumTag, as that
    // would require an inline loop. Instead, we create an array of
    // values that is comptime-know, but can be iterated at runtime
    // without requiring an inline loop. This generates better
    // machine code.
    const values = comptime blk: {
        var result: [enum_info.fields.len]enum_info.tag_type = undefined;
        for (&result, enum_info.fields) |*dst, src| {
            dst.* = src.value;
        }
        break :blk result;
    };
    for (values) |v| {
        if (v == tag_int) return @enumFromInt(tag_int);
    }
    return error.InvalidEnumTag;
}

/// Given a type and a name, return the field index according to source order.
/// Returns `null` if the field is not found.
pub fn fieldIndex(comptime T: type, comptime name: []const u8) ?comptime_int {
    inline for (fields(T), 0..) |field, i| {
        if (mem.eql(u8, field.name, name))
            return i;
    }
    return null;
}

/// Returns a slice of pointers to public declarations of a namespace.
pub fn declList(comptime Namespace: type, comptime Decl: type) []const *const Decl {
    const S = struct {
        fn declNameLessThan(context: void, lhs: *const Decl, rhs: *const Decl) bool {
            _ = context;
            return mem.lessThan(u8, lhs.name, rhs.name);
        }
    };
    comptime {
        const decls = declarations(Namespace);
        var array: [decls.len]*const Decl = undefined;
        for (decls, 0..) |decl, i| {
            array[i] = &@field(Namespace, decl.name);
        }
        mem.sort(*const Decl, &array, {}, S.declNameLessThan);
        return &array;
    }
}

pub fn Int(comptime signedness: std.builtin.Signedness, comptime bit_count: u16) type {
    return @Type(.{
        .int = .{
            .signedness = signedness,
            .bits = bit_count,
        },
    });
}

pub fn Float(comptime bit_count: u8) type {
    return @Type(.{
        .float = .{ .bits = bit_count },
    });
}

test Float {
    try testing.expectEqual(f16, Float(16));
    try testing.expectEqual(f32, Float(32));
    try testing.expectEqual(f64, Float(64));
    try testing.expectEqual(f128, Float(128));
}

/// For a given function type, returns a tuple type which fields will
/// correspond to the argument types.
///
/// Examples:
/// - `ArgsTuple(fn () void)` ⇒ `tuple { }`
/// - `ArgsTuple(fn (a: u32) u32)` ⇒ `tuple { u32 }`
/// - `ArgsTuple(fn (a: u32, b: f16) noreturn)` ⇒ `tuple { u32, f16 }`
pub fn ArgsTuple(comptime Function: type) type {
    const info = @typeInfo(Function);
    if (info != .@"fn")
        @compileError("ArgsTuple expects a function type");

    const function_info = info.@"fn";
    if (function_info.is_var_args)
        @compileError("Cannot create ArgsTuple for variadic function");

    var argument_field_list: [function_info.params.len]type = undefined;
    inline for (function_info.params, 0..) |arg, i| {
        const T = arg.type orelse @compileError("cannot create ArgsTuple for function with an 'anytype' parameter");
        argument_field_list[i] = T;
    }

    return CreateUniqueTuple(argument_field_list.len, argument_field_list);
}

/// For a given anonymous list of types, returns a new tuple type
/// with those types as fields.
///
/// Examples:
/// - `Tuple(&[_]type {})` ⇒ `tuple { }`
/// - `Tuple(&[_]type {f32})` ⇒ `tuple { f32 }`
/// - `Tuple(&[_]type {f32,u32})` ⇒ `tuple { f32, u32 }`
pub fn Tuple(comptime types: []const type) type {
    return CreateUniqueTuple(types.len, types[0..types.len].*);
}

fn CreateUniqueTuple(comptime N: comptime_int, comptime types: [N]type) type {
    var tuple_fields: [types.len]std.builtin.Type.StructField = undefined;
    inline for (types, 0..) |T, i| {
        @setEvalBranchQuota(10_000);
        var num_buf: [128]u8 = undefined;
        tuple_fields[i] = .{
            .name = std.fmt.bufPrintZ(&num_buf, "{d}", .{i}) catch unreachable,
            .type = T,
        ```
