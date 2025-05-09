```
   if (std.Target.wasm.featureSetHas(cpu.features, .simd128)) break :blk 128;
        }
        return null;
    };
    if (vector_bit_size <= element_bit_size) return null;

    return @divExact(vector_bit_size, element_bit_size);
}

/// Suggests a target-dependant vector length for a given type, or null if scalars are recommended.
/// Not yet implemented for every CPU architecture.
pub fn suggestVectorLength(comptime T: type) ?comptime_int {
    return suggestVectorLengthForCpu(T, builtin.cpu);
}

test "suggestVectorLengthForCpu works with signed and unsigned values" {
    comptime var cpu = std.Target.Cpu.baseline(std.Target.Cpu.Arch.x86_64, builtin.os);
    comptime cpu.features.addFeature(@intFromEnum(std.Target.x86.Feature.avx512f));
    comptime cpu.features.populateDependencies(&std.Target.x86.all_features);
    const expected_len: usize = switch (builtin.zig_backend) {
        .stage2_x86_64 => 8,
        else => 16,
    };
    const signed_integer_len = suggestVectorLengthForCpu(i32, cpu).?;
    const unsigned_integer_len = suggestVectorLengthForCpu(u32, cpu).?;
    try std.testing.expectEqual(expected_len, unsigned_integer_len);
    try std.testing.expectEqual(expected_len, signed_integer_len);
}

fn vectorLength(comptime VectorType: type) comptime_int {
    return switch (@typeInfo(VectorType)) {
        .vector => |info| info.len,
        .array => |info| info.len,
        else => @compileError("Invalid type " ++ @typeName(VectorType)),
    };
}

/// Returns the smallest type of unsigned ints capable of indexing any element within the given vector type.
pub fn VectorIndex(comptime VectorType: type) type {
    return std.math.IntFittingRange(0, vectorLength(VectorType) - 1);
}

/// Returns the smallest type of unsigned ints capable of holding the length of the given vector type.
pub fn VectorCount(comptime VectorType: type) type {
    return std.math.IntFittingRange(0, vectorLength(VectorType));
}

/// Returns a vector containing the first `len` integers in order from 0 to `len`-1.
/// For example, `iota(i32, 8)` will return a vector containing `.{0, 1, 2, 3, 4, 5, 6, 7}`.
pub inline fn iota(comptime T: type, comptime len: usize) @Vector(len, T) {
    comptime {
        var out: [len]T = undefined;
        for (&out, 0..) |*element, i| {
            element.* = switch (@typeInfo(T)) {
                .int => @as(T, @intCast(i)),
                .float => @as(T, @floatFromInt(i)),
                else => @compileError("Can't use type " ++ @typeName(T) ++ " in iota."),
            };
        }
        return @as(@Vector(len, T), out);
    }
}

/// Returns a vector containing the same elements as the input, but repeated until the desired length is reached.
/// For example, `repeat(8, [_]u32{1, 2, 3})` will return a vector containing `.{1, 2, 3, 1, 2, 3, 1, 2}`.
pub fn repeat(comptime len: usize, vec: anytype) @Vector(len, std.meta.Child(@TypeOf(vec))) {
    const Child = std.meta.Child(@TypeOf(vec));

    return @shuffle(Child, vec, undefined, iota(i32, len) % @as(@Vector(len, i32), @splat(@intCast(vectorLength(@TypeOf(vec))))));
}

/// Returns a vector containing all elements of the first vector at the lower indices followed by all elements of the second vector
/// at the higher indices.
pub fn join(a: anytype, b: anytype) @Vector(vectorLength(@TypeOf(a)) + vectorLength(@TypeOf(b)), std.meta.Child(@TypeOf(a))) {
    const Child = std.meta.Child(@TypeOf(a));
    const a_len = vectorLength(@TypeOf(a));
    const b_len = vectorLength(@TypeOf(b));

    return @shuffle(Child, a, b, @as([a_len]i32, iota(i32, a_len)) ++ @as([b_len]i32, ~iota(i32, b_len)));
}

/// Returns a vector whose elements alternates between those of each input vector.
/// For example, `interlace(.{[4]u32{11, 12, 13, 14}, [4]u32{21, 22, 23, 24}})` returns a vector containing `.{11, 21, 12, 22, 13, 23, 14, 24}`.
pub fn interlace(vecs: anytype) @Vector(vectorLength(@TypeOf(vecs[0])) * vecs.len, std.meta.Child(@TypeOf(vecs[0]))) {
    // interlace doesn't work on MIPS, for some reason.
    // Notes from earlier debug attempt:
    //  The indices are correct. The problem seems to be with the @shuffle builtin.
    //  On MIPS, the test that interlaces small_base gives { 0, 2, 0, 0, 64, 255, 248, 200, 0, 0 }.
    //  Calling this with two inputs seems to work fine, but I'll let the compile error trigger for all inputs, just to be safe.
    if (builtin.cpu.arch.isMIPS()) @compileError("TODO: Find out why interlace() doesn't work on MIPS");

    const VecType = @TypeOf(vecs[0]);
    const vecs_arr = @as([vecs.len]VecType, vecs);
    const Child = std.meta.Child(@TypeOf(vecs_arr[0]));

    if (vecs_arr.len == 1) return vecs_arr[0];

    const a_vec_count = (1 + vecs_arr.len) >> 1;
    const b_vec_count = vecs_arr.len >> 1;

    const a = interlace(@as(*const [a_vec_count]VecType, @ptrCast(vecs_arr[0..a_vec_count])).*);
    const b = interlace(@as(*const [b_vec_count]VecType, @ptrCast(vecs_arr[a_vec_count..])).*);

    const a_len = vectorLength(@TypeOf(a));
    const b_len = vectorLength(@TypeOf(b));
    const len = a_len + b_len;

    const indices = comptime blk: {
        const Vi32 = @Vector(len, i32);
        const count_up = iota(i32, len);
        const cycle = @divFloor(count_up, @as(Vi32, @splat(@intCast(vecs_arr.len))));
        const select_mask = repeat(len, join(@as(@Vector(a_vec_count, bool), @splat(true)), @as(@Vector(b_vec_count, bool), @splat(false))));
        const a_indices = count_up - cycle * @as(Vi32, @splat(@intCast(b_vec_count)));
        const b_indices = shiftElementsRight(count_up - cycle * @as(Vi32, @splat(@intCast(a_vec_count))), a_vec_count, 0);
        break :blk @select(i32, select_mask, a_indices, ~b_indices);
    };

    return @shuffle(Child, a, b, indices);
}

/// The contents of `interlaced` is evenly split between vec_count vectors that are returned as an array. They "take turns",
/// receiving one element from `interlaced` at a time.
pub fn deinterlace(
    comptime vec_count: usize,
    interlaced: anytype,
) [vec_count]@Vector(
    vectorLength(@TypeOf(interlaced)) / vec_count,
    std.meta.Child(@TypeOf(interlaced)),
) {
    const vec_len = vectorLength(@TypeOf(interlaced)) / vec_count;
    const Child = std.meta.Child(@TypeOf(interlaced));

    var out: [vec_count]@Vector(vec_len, Child) = undefined;

    comptime var i: usize = 0; // for-loops don't work for this, apparently.
    inline while (i < out.len) : (i += 1) {
        const indices = comptime iota(i32, vec_len) * @as(@Vector(vec_len, i32), @splat(@intCast(vec_count))) + @as(@Vector(vec_len, i32), @splat(@intCast(i)));
        out[i] = @shuffle(Child, interlaced, undefined, indices);
    }

    return out;
}

pub fn extract(
    vec: anytype,
    comptime first: VectorIndex(@TypeOf(vec)),
    comptime count: VectorCount(@TypeOf(vec)),
) @Vector(count, std.meta.Child(@TypeOf(vec))) {
    const Child = std.meta.Child(@TypeOf(vec));
    const len = vectorLength(@TypeOf(vec));

    std.debug.assert(@as(comptime_int, @intCast(first)) + @as(comptime_int, @intCast(count)) <= len);

    return @shuffle(Child, vec, undefined, iota(i32, count) + @as(@Vector(count, i32), @splat(@intCast(first))));
}

test "vector patterns" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    const base = @Vector(4, u32){ 10, 20, 30, 40 };
    const other_base = @Vector(4, u32){ 55, 66, 77, 88 };

    const small_bases = [5]@Vector(2, u8){
        @Vector(2, u8){ 0, 1 },
        @Vector(2, u8){ 2, 3 },
        @Vector(2, u8){ 4, 5 },
        @Vector(2, u8){ 6, 7 },
        @Vector(2, u8){ 8, 9 },
    };

    try std.testing.expectEqual([6]u32{ 10, 20, 30, 40, 10, 20 }, repeat(6, base));
    try std.testing.expectEqual([8]u32{ 10, 20, 30, 40, 55, 66, 77, 88 }, join(base, other_base));
    try std.testing.expectEqual([2]u32{ 20, 30 }, extract(base, 1, 2));

    if (!builtin.cpu.arch.isMIPS()) {
        try std.testing.expectEqual([8]u32{ 10, 55, 20, 66, 30, 77, 40, 88 }, interlace(.{ base, other_base }));

        const small_braid = interlace(small_bases);
        try std.testing.expectEqual([10]u8{ 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 }, small_braid);
        try std.testing.expectEqual(small_bases, deinterlace(small_bases.len, small_braid));
    }
}

/// Joins two vectors, shifts them leftwards (towards lower indices) and extracts the leftmost elements into a vector the length of a and b.
pub fn mergeShift(a: anytype, b: anytype, comptime shift: VectorCount(@TypeOf(a, b))) @TypeOf(a, b) {
    const len = vectorLength(@TypeOf(a, b));

    return extract(join(a, b), shift, len);
}

/// Elements are shifted rightwards (towards higher indices). New elements are added to the left, and the rightmost elements are cut off
/// so that the length of the vector stays the same.
pub fn shiftElementsRight(vec: anytype, comptime amount: VectorCount(@TypeOf(vec)), shift_in: std.meta.Child(@TypeOf(vec))) @TypeOf(vec) {
    // It may be possible to implement shifts and rotates with a runtime-friendly slice of two joined vectors, as the length of the
    // slice would be comptime-known. This would permit vector shifts and rotates by a non-comptime-known amount.
    // However, I am unsure whether compiler optimizations would handle that well enough on all platforms.
    const V = @TypeOf(vec);
    const len = vectorLength(V);

    return mergeShift(@as(V, @splat(shift_in)), vec, len - amount);
}

/// Elements are shifted leftwards (towards lower indices). New elements are added to the right, and the leftmost elements are cut off
/// so that no elements with indices below 0 remain.
pub fn shiftElementsLeft(vec: anytype, comptime amount: VectorCount(@TypeOf(vec)), shift_in: std.meta.Child(@TypeOf(vec))) @TypeOf(vec) {
    const V = @TypeOf(vec);

    return mergeShift(vec, @as(V, @splat(shift_in)), amount);
}

/// Elements are shifted leftwards (towards lower indices). Elements that leave to the left will reappear to the right in the same order.
pub fn rotateElementsLeft(vec: anytype, comptime amount: VectorCount(@TypeOf(vec))) @TypeOf(vec) {
    return mergeShift(vec, vec, amount);
}

/// Elements are shifted rightwards (towards higher indices). Elements that leave to the right will reappear to the left in the same order.
pub fn rotateElementsRight(vec: anytype, comptime amount: VectorCount(@TypeOf(vec))) @TypeOf(vec) {
    return rotateElementsLeft(vec, vectorLength(@TypeOf(vec)) - amount);
}

pub fn reverseOrder(vec: anytype) @TypeOf(vec) {
    const Child = std.meta.Child(@TypeOf(vec));
    const len = vectorLength(@TypeOf(vec));

    return @shuffle(Child, vec, undefined, @as(@Vector(len, i32), @splat(@as(i32, @intCast(len)) - 1)) - iota(i32, len));
}

test "vector shifting" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    const base = @Vector(4, u32){ 10, 20, 30, 40 };

    try std.testing.expectEqual([4]u32{ 30, 40, 999, 999 }, shiftElementsLeft(base, 2, 999));
    try std.testing.expectEqual([4]u32{ 999, 999, 10, 20 }, shiftElementsRight(base, 2, 999));
    try std.testing.expectEqual([4]u32{ 20, 30, 40, 10 }, rotateElementsLeft(base, 1));
    try std.testing.expectEqual([4]u32{ 40, 10, 20, 30 }, rotateElementsRight(base, 1));
    try std.testing.expectEqual([4]u32{ 40, 30, 20, 10 }, reverseOrder(base));
}

pub fn firstTrue(vec: anytype) ?VectorIndex(@TypeOf(vec)) {
    const len = vectorLength(@TypeOf(vec));
    const IndexInt = VectorIndex(@TypeOf(vec));

    if (!@reduce(.Or, vec)) {
        return null;
    }
    const all_max: @Vector(len, IndexInt) = @splat(~@as(IndexInt, 0));
    const indices = @select(IndexInt, vec, iota(IndexInt, len), all_max);
    return @reduce(.Min, indices);
}

pub fn lastTrue(vec: anytype) ?VectorIndex(@TypeOf(vec)) {
    const len = vectorLength(@TypeOf(vec));
    const IndexInt = VectorIndex(@TypeOf(vec));

    if (!@reduce(.Or, vec)) {
        return null;
    }

    const all_zeroes: @Vector(len, IndexInt) = @splat(0);
    const indices = @select(IndexInt, vec, iota(IndexInt, len), all_zeroes);
    return @reduce(.Max, indices);
}

pub fn countTrues(vec: anytype) VectorCount(@TypeOf(vec)) {
    const len = vectorLength(@TypeOf(vec));
    const CountIntType = VectorCount(@TypeOf(vec));

    const all_ones: @Vector(len, CountIntType) = @splat(1);
    const all_zeroes: @Vector(len, CountIntType) = @splat(0);

    const one_if_true = @select(CountIntType, vec, all_ones, all_zeroes);
    return @reduce(.Add, one_if_true);
}

pub fn firstIndexOfValue(vec: anytype, value: std.meta.Child(@TypeOf(vec))) ?VectorIndex(@TypeOf(vec)) {
    const V = @TypeOf(vec);

    return firstTrue(vec == @as(V, @splat(value)));
}

pub fn lastIndexOfValue(vec: anytype, value: std.meta.Child(@TypeOf(vec))) ?VectorIndex(@TypeOf(vec)) {
    const V = @TypeOf(vec);

    return lastTrue(vec == @as(V, @splat(value)));
}

pub fn countElementsWithValue(vec: anytype, value: std.meta.Child(@TypeOf(vec))) VectorCount(@TypeOf(vec)) {
    const V = @TypeOf(vec);

    return countTrues(vec == @as(V, @splat(value)));
}

test "vector searching" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    const base = @Vector(8, u32){ 6, 4, 7, 4, 4, 2, 3, 7 };

    try std.testing.expectEqual(@as(?u3, 1), firstIndexOfValue(base, 4));
    try std.testing.expectEqual(@as(?u3, 4), lastIndexOfValue(base, 4));
    try std.testing.expectEqual(@as(?u3, null), lastIndexOfValue(base, 99));
    try std.testing.expectEqual(@as(u4, 3), countElementsWithValue(base, 4));
}

/// Same as prefixScan, but with a user-provided, mathematically associative function.
pub fn prefixScanWithFunc(
    comptime hop: isize,
    vec: anytype,
    /// The error type that `func` might return. Set this to `void` if `func` doesn't return an error union.
    comptime ErrorType: type,
    comptime func: fn (@TypeOf(vec), @TypeOf(vec)) if (ErrorType == void) @TypeOf(vec) else ErrorType!@TypeOf(vec),
    /// When one operand of the operation performed by `func` is this value, the result must equal the other operand.
    /// For example, this should be 0 for addition or 1 for multiplication.
    comptime identity: std.meta.Child(@TypeOf(vec)),
) if (ErrorType == void) @TypeOf(vec) else ErrorType!@TypeOf(vec) {
    // I haven't debugged this, but it might be a cousin of sorts to what's going on with interlace.
    if (builtin.cpu.arch.isMIPS()) @compileError("TODO: Find out why prefixScan doesn't work on MIPS");

    const len = vectorLength(@TypeOf(vec));

    if (hop == 0) @compileError("hop can not be 0; you'd be going nowhere forever!");
    const abs_hop = if (hop < 0) -hop else hop;

    var acc = vec;
    comptime var i = 0;
    inline while ((abs_hop << i) < len) : (i += 1) {
        const shifted = if (hop < 0) shiftElementsLeft(acc, abs_hop << i, identity) else shiftElementsRight(acc, abs_hop << i, identity);

        acc = if (ErrorType == void) func(acc, shifted) else try func(acc, shifted);
    }
    return acc;
}

/// Returns a vector whose elements are the result of performing the specified operation on the corresponding
/// element of the input vector and every hop'th element that came before it (or after, if hop is negative).
/// Supports the same operations as the @reduce() builtin. Takes O(logN) to compute.
/// The scan is not linear, which may affect floating point errors. This may affect the determinism of
/// algorithms that use this function.
pub fn prefixScan(comptime op: std.builtin.ReduceOp, comptime hop: isize, vec: anytype) @TypeOf(vec) {
    const VecType = @TypeOf(vec);
    const Child = std.meta.Child(VecType);

    const identity = comptime switch (@typeInfo(Child)) {
        .bool => switch (op) {
            .Or, .Xor => false,
            .And => true,
            else => @compileError("Invalid prefixScan operation " ++ @tagName(op) ++ " for vector of booleans."),
        },
        .int => switch (op) {
            .Max => std.math.minInt(Child),
            .Add, .Or, .Xor => 0,
            .Mul => 1,
            .And, .Min => std.math.maxInt(Child),
        },
        .float => switch (op) {
            .Max => -std.math.inf(Child),
            .Add => 0,
            .Mul => 1,
            .Min => std.math.inf(Child),
            else => @compileError("Invalid prefixScan operation " ++ @tagName(op) ++ " for vector of floats."),
        },
        else => @compileError("Invalid type " ++ @typeName(VecType) ++ " for prefixScan."),
    };

    const fn_container = struct {
        fn opFn(a: VecType, b: VecType) VecType {
            return if (Child == bool) switch (op) {
                .And => @select(bool, a, b, @as(VecType, @splat(false))),
                .Or => @select(bool, a, @as(VecType, @splat(true)), b),
                .Xor => a != b,
                else => unreachable,
            } else switch (op) {
                .And => a & b,
                .Or => a | b,
                .Xor => a ^ b,
                .Add => a + b,
                .Mul => a * b,
                .Min => @min(a, b),
                .Max => @max(a, b),
            };
        }
    };

    return prefixScanWithFunc(hop, vec, void, fn_container.opFn, identity);
}

test "vector prefix scan" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;
    if ((builtin.cpu.arch == .armeb or builtin.cpu.arch == .thumbeb) and builtin.zig_backend == .stage2_llvm) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/22060
    if (builtin.cpu.arch == .aarch64_be and builtin.zig_backend == .stage2_llvm) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/21893
    if (builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .hexagon) return error.SkipZigTest;

    if (builtin.cpu.arch.isMIPS()) return error.SkipZigTest;

    const int_base = @Vector(4, i32){ 11, 23, 9, -21 };
    const float_base = @Vector(4, f32){ 2, 0.5, -10, 6.54321 };
    const bool_base = @Vector(4, bool){ true, false, true, false };

    const ones: @Vector(32, u8) = @splat(1);

    try std.testing.expectEqual(iota(u8, 32) + ones, prefixScan(.Add, 1, ones));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 3, 1, 1 }, prefixScan(.And, 1, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 31, 31, -1 }, prefixScan(.Or, 1, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 28, 21, -2 }, prefixScan(.Xor, 1, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 34, 43, 22 }, prefixScan(.Add, 1, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 253, 2277, -47817 }, prefixScan(.Mul, 1, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 11, 9, -21 }, prefixScan(.Min, 1, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 23, 23, 23 }, prefixScan(.Max, 1, int_base));

    // Trying to predict all inaccuracies when adding and multiplying floats with prefixScans would be a mess, so we don't test those.
    try std.testing.expectEqual(@Vector(4, f32){ 2, 0.5, -10, -10 }, prefixScan(.Min, 1, float_base));
    try std.testing.expectEqual(@Vector(4, f32){ 2, 2, 2, 6.54321 }, prefixScan(.Max, 1, float_base));

    try std.testing.expectEqual(@Vector(4, bool){ true, true, false, false }, prefixScan(.Xor, 1, bool_base));
    try std.testing.expectEqual(@Vector(4, bool){ true, true, true, true }, prefixScan(.Or, 1, bool_base));
    try std.testing.expectEqual(@Vector(4, bool){ true, false, false, false }, prefixScan(.And, 1, bool_base));

    try std.testing.expectEqual(@Vector(4, i32){ 11, 23, 20, 2 }, prefixScan(.Add, 2, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 22, 11, -12, -21 }, prefixScan(.Add, -1, int_base));
    try std.testing.expectEqual(@Vector(4, i32){ 11, 23, 9, -10 }, prefixScan(.Add, 3, int_base));
}
//! A singly-linked list is headed by a single forward pointer. The elements
//! are singly-linked for minimum space and pointer manipulation overhead at
//! the expense of O(n) removal for arbitrary elements. New elements can be
//! added to the list after an existing element or at the head of the list.
//!
//! A singly-linked list may only be traversed in the forward direction.
//!
//! Singly-linked lists are useful under these conditions:
//! * Ability to preallocate elements / requirement of infallibility for
//!   insertion.
//! * Ability to allocate elements intrusively along with other data.
//! * Homogenous elements.

const std = @import("std.zig");
const debug = std.debug;
const assert = debug.assert;
const testing = std.testing;
const SinglyLinkedList = @This();

first: ?*Node = null,

/// This struct contains only a next pointer and not any data payload. The
/// intended usage is to embed it intrusively into another data structure and
/// access the data with `@fieldParentPtr`.
pub const Node = struct {
    next: ?*Node = null,

    pub fn insertAfter(node: *Node, new_node: *Node) void {
        new_node.next = node.next;
        node.next = new_node;
    }

    /// Remove the node after the one provided, returning it.
    pub fn removeNext(node: *Node) ?*Node {
        const next_node = node.next orelse return null;
        node.next = next_node.next;
        return next_node;
    }

    /// Iterate over the singly-linked list from this node, until the final
    /// node is found.
    ///
    /// This operation is O(N). Instead of calling this function, consider
    /// using a different data structure.
    pub fn findLast(node: *Node) *Node {
        var it = node;
        while (true) {
            it = it.next orelse return it;
        }
    }

    /// Iterate over each next node, returning the count of all nodes except
    /// the starting one.
    ///
    /// This operation is O(N). Instead of calling this function, consider
    /// using a different data structure.
    pub fn countChildren(node: *const Node) usize {
        var count: usize = 0;
        var it: ?*const Node = node.next;
        while (it) |n| : (it = n.next) {
            count += 1;
        }
        return count;
    }

    /// Reverse the list starting from this node in-place.
    ///
    /// This operation is O(N). Instead of calling this function, consider
    /// using a different data structure.
    pub fn reverse(indirect: *?*Node) void {
        if (indirect.* == null) {
            return;
        }
        var current: *Node = indirect.*.?;
        while (current.next) |next| {
            current.next = next.next;
            next.next = indirect.*;
            indirect.* = next;
        }
    }
};

pub fn prepend(list: *SinglyLinkedList, new_node: *Node) void {
    new_node.next = list.first;
    list.first = new_node;
}

pub fn remove(list: *SinglyLinkedList, node: *Node) void {
    if (list.first == node) {
        list.first = node.next;
    } else {
        var current_elm = list.first.?;
        while (current_elm.next != node) {
            current_elm = current_elm.next.?;
        }
        current_elm.next = node.next;
    }
}

/// Remove and return the first node in the list.
pub fn popFirst(list: *SinglyLinkedList) ?*Node {
    const first = list.first orelse return null;
    list.first = first.next;
    return first;
}

/// Iterate over all nodes, returning the count.
///
/// This operation is O(N). Consider tracking the length separately rather than
/// computing it.
pub fn len(list: SinglyLinkedList) usize {
    if (list.first) |n| {
        return 1 + n.countChildren();
    } else {
        return 0;
    }
}

test "basics" {
    const L = struct {
        data: u32,
        node: SinglyLinkedList.Node = .{},
    };
    var list: SinglyLinkedList = .{};

    try testing.expect(list.len() == 0);

    var one: L = .{ .data = 1 };
    var two: L = .{ .data = 2 };
    var three: L = .{ .data = 3 };
    var four: L = .{ .data = 4 };
    var five: L = .{ .data = 5 };

    list.prepend(&two.node); // {2}
    two.node.insertAfter(&five.node); // {2, 5}
    list.prepend(&one.node); // {1, 2, 5}
    two.node.insertAfter(&three.node); // {1, 2, 3, 5}
    three.node.insertAfter(&four.node); // {1, 2, 3, 4, 5}

    try testing.expect(list.len() == 5);

    // Traverse forwards.
    {
        var it = list.first;
        var index: u32 = 1;
        while (it) |node| : (it = node.next) {
            const l: *L = @fieldParentPtr("node", node);
            try testing.expect(l.data == index);
            index += 1;
        }
    }

    _ = list.popFirst(); // {2, 3, 4, 5}
    _ = list.remove(&five.node); // {2, 3, 4}
    _ = two.node.removeNext(); // {2, 4}

    try testing.expect(@as(*L, @fieldParentPtr("node", list.first.?)).data == 2);
    try testing.expect(@as(*L, @fieldParentPtr("node", list.first.?.next.?)).data == 4);
    try testing.expect(list.first.?.next.?.next == null);

    SinglyLinkedList.Node.reverse(&list.first);

    try testing.expect(@as(*L, @fieldParentPtr("node", list.first.?)).data == 4);
    try testing.expect(@as(*L, @fieldParentPtr("node", list.first.?.next.?)).data == 2);
    try testing.expect(list.first.?.next.?.next == null);
}
const std = @import("std.zig");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const math = std.math;

pub const Mode = enum { stable, unstable };

pub const block = @import("sort/block.zig").block;
pub const pdq = @import("sort/pdq.zig").pdq;
pub const pdqContext = @import("sort/pdq.zig").pdqContext;

/// Stable in-place sort. O(n) best case, O(pow(n, 2)) worst case.
/// O(1) memory (no allocator required).
/// Sorts in ascending order with respect to the given `lessThan` function.
pub fn insertion(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    const Context = struct {
        items: []T,
        sub_ctx: @TypeOf(context),

        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            return lessThanFn(ctx.sub_ctx, ctx.items[a], ctx.items[b]);
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return mem.swap(T, &ctx.items[a], &ctx.items[b]);
        }
    };
    insertionContext(0, items.len, Context{ .items = items, .sub_ctx = context });
}

/// Stable in-place sort. O(n) best case, O(pow(n, 2)) worst case.
/// O(1) memory (no allocator required).
/// `context` must have methods `swap` and `lessThan`,
/// which each take 2 `usize` parameters indicating the index of an item.
/// Sorts in ascending order with respect to `lessThan`.
pub fn insertionContext(a: usize, b: usize, context: anytype) void {
    assert(a <= b);

    var i = a + 1;
    while (i < b) : (i += 1) {
        var j = i;
        while (j > a and context.lessThan(j, j - 1)) : (j -= 1) {
            context.swap(j, j - 1);
        }
    }
}

/// Unstable in-place sort. O(n*log(n)) best case, worst case and average case.
/// O(1) memory (no allocator required).
/// Sorts in ascending order with respect to the given `lessThan` function.
pub fn heap(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    const Context = struct {
        items: []T,
        sub_ctx: @TypeOf(context),

        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            return lessThanFn(ctx.sub_ctx, ctx.items[a], ctx.items[b]);
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return mem.swap(T, &ctx.items[a], &ctx.items[b]);
        }
    };
    heapContext(0, items.len, Context{ .items = items, .sub_ctx = context });
}

/// Unstable in-place sort. O(n*log(n)) best case, worst case and average case.
/// O(1) memory (no allocator required).
/// `context` must have methods `swap` and `lessThan`,
/// which each take 2 `usize` parameters indicating the index of an item.
/// Sorts in ascending order with respect to `lessThan`.
pub fn heapContext(a: usize, b: usize, context: anytype) void {
    assert(a <= b);
    // build the heap in linear time.
    var i = a + (b - a) / 2;
    while (i > a) {
        i -= 1;
        siftDown(a, i, b, context);
    }

    // pop maximal elements from the heap.
    i = b;
    while (i > a) {
        i -= 1;
        context.swap(a, i);
        siftDown(a, a, i, context);
    }
}

fn siftDown(a: usize, target: usize, b: usize, context: anytype) void {
    var cur = target;
    while (true) {
        // When we don't overflow from the multiply below, the following expression equals (2*cur) - (2*a) + a + 1
        // The `+ a + 1` is safe because:
        //  for `a > 0` then `2a >= a + 1`.
        //  for `a = 0`, the expression equals `2*cur+1`. `2*cur` is an even number, therefore adding 1 is safe.
        var child = (math.mul(usize, cur - a, 2) catch break) + a + 1;

        // stop if we overshot the boundary
        if (!(child < b)) break;

        // `next_child` is at most `b`, therefore no overflow is possible
        const next_child = child + 1;

        // store the greater child in `child`
        if (next_child < b and context.lessThan(child, next_child)) {
            child = next_child;
        }

        // stop if the Heap invariant holds at `cur`.
        if (context.lessThan(child, cur)) break;

        // swap `cur` with the greater child,
        // move one step down, and continue sifting.
        context.swap(child, cur);
        cur = child;
    }
}

/// Use to generate a comparator function for a given type. e.g. `sort(u8, slice, {}, asc(u8))`.
pub fn asc(comptime T: type) fn (void, T, T) bool {
    return struct {
        pub fn inner(_: void, a: T, b: T) bool {
            return a < b;
        }
    }.inner;
}

/// Use to generate a comparator function for a given type. e.g. `sort(u8, slice, {}, desc(u8))`.
pub fn desc(comptime T: type) fn (void, T, T) bool {
    return struct {
        pub fn inner(_: void, a: T, b: T) bool {
            return a > b;
        }
    }.inner;
}

const asc_u8 = asc(u8);
const asc_i32 = asc(i32);
const desc_u8 = desc(u8);
const desc_i32 = desc(i32);

const sort_funcs = &[_]fn (comptime type, anytype, anytype, comptime anytype) void{
    block,
    pdq,
    insertion,
    heap,
};

const context_sort_funcs = &[_]fn (usize, usize, anytype) void{
    // blockContext,
    pdqContext,
    insertionContext,
    heapContext,
};

const IdAndValue = struct {
    id: usize,
    value: i32,

    fn lessThan(context: void, a: IdAndValue, b: IdAndValue) bool {
        _ = context;
        return a.value < b.value;
    }
};

test "stable sort" {
    const expected = [_]IdAndValue{
        IdAndValue{ .id = 0, .value = 0 },
        IdAndValue{ .id = 1, .value = 0 },
        IdAndValue{ .id = 2, .value = 0 },
        IdAndValue{ .id = 0, .value = 1 },
        IdAndValue{ .id = 1, .value = 1 },
        IdAndValue{ .id = 2, .value = 1 },
        IdAndValue{ .id = 0, .value = 2 },
        IdAndValue{ .id = 1, .value = 2 },
        IdAndValue{ .id = 2, .value = 2 },
    };

    var cases = [_][9]IdAndValue{
        [_]IdAndValue{
            IdAndValue{ .id = 0, .value = 0 },
            IdAndValue{ .id = 0, .value = 1 },
            IdAndValue{ .id = 0, .value = 2 },
            IdAndValue{ .id = 1, .value = 0 },
            IdAndValue{ .id = 1, .value = 1 },
            IdAndValue{ .id = 1, .value = 2 },
            IdAndValue{ .id = 2, .value = 0 },
            IdAndValue{ .id = 2, .value = 1 },
            IdAndValue{ .id = 2, .value = 2 },
        },
        [_]IdAndValue{
            IdAndValue{ .id = 0, .value = 2 },
            IdAndValue{ .id = 0, .value = 1 },
            IdAndValue{ .id = 0, .value = 0 },
            IdAndValue{ .id = 1, .value = 2 },
            IdAndValue{ .id = 1, .value = 1 },
            IdAndValue{ .id = 1, .value = 0 },
            IdAndValue{ .id = 2, .value = 2 },
            IdAndValue{ .id = 2, .value = 1 },
            IdAndValue{ .id = 2, .value = 0 },
        },
    };

    for (&cases) |*case| {
        block(IdAndValue, (case.*)[0..], {}, IdAndValue.lessThan);
        for (case.*, 0..) |item, i| {
            try testing.expect(item.id == expected[i].id);
            try testing.expect(item.value == expected[i].value);
        }
    }
}

test "stable sort fuzz testing" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const test_case_count = 10;

    for (0..test_case_count) |_| {
        const array_size = random.intRangeLessThan(usize, 0, 1000);
        const array = try testing.allocator.alloc(IdAndValue, array_size);
        defer testing.allocator.free(array);
        // Value is a small random numbers to create collisions.
        // Id is a  reverse index to make sure sorting function only uses provided `lessThan`.
        for (array, 0..) |*item, index| {
            item.* = .{
                .value = random.intRangeLessThan(i32, 0, 100),
                .id = array_size - index,
            };
        }
        block(IdAndValue, array, {}, IdAndValue.lessThan);
        if (array_size > 0) {
            for (array[0 .. array_size - 1], array[1..]) |x, y| {
                try testing.expect(x.value <= y.value);
                if (x.value == y.value) {
                    try testing.expect(x.id > y.id);
                }
            }
        }
    }
}

test "sort" {
    const u8cases = [_][]const []const u8{
        &[_][]const u8{
            "",
            "",
        },
        &[_][]const u8{
            "a",
            "a",
        },
        &[_][]const u8{
            "az",
            "az",
        },
        &[_][]const u8{
            "za",
            "az",
        },
        &[_][]const u8{
            "asdf",
            "adfs",
        },
        &[_][]const u8{
            "one",
            "eno",
        },
    };

    const i32cases = [_][]const []const i32{
        &[_][]const i32{
            &[_]i32{},
            &[_]i32{},
        },
        &[_][]const i32{
            &[_]i32{1},
            &[_]i32{1},
        },
        &[_][]const i32{
            &[_]i32{ 0, 1 },
            &[_]i32{ 0, 1 },
        },
        &[_][]const i32{
            &[_]i32{ 1, 0 },
            &[_]i32{ 0, 1 },
        },
        &[_][]const i32{
            &[_]i32{ 1, -1, 0 },
            &[_]i32{ -1, 0, 1 },
        },
        &[_][]const i32{
            &[_]i32{ 2, 1, 3 },
            &[_]i32{ 1, 2, 3 },
        },
        &[_][]const i32{
            &[_]i32{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 55, 32, 39, 58, 21, 88, 43, 22, 59 },
            &[_]i32{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 21, 22, 32, 39, 43, 55, 58, 59, 88 },
        },
    };

    inline for (sort_funcs) |sortFn| {
        for (u8cases) |case| {
            var buf: [20]u8 = undefined;
            const slice = buf[0..case[0].len];
            @memcpy(slice, case[0]);
            sortFn(u8, slice, {}, asc_u8);
            try testing.expect(mem.eql(u8, slice, case[1]));
        }

        for (i32cases) |case| {
            var buf: [20]i32 = undefined;
            const slice = buf[0..case[0].len];
            @memcpy(slice, case[0]);
            sortFn(i32, slice, {}, asc_i32);
            try testing.expect(mem.eql(i32, slice, case[1]));
        }
    }
}

test "sort descending" {
    const rev_cases = [_][]const []const i32{
        &[_][]const i32{
            &[_]i32{},
            &[_]i32{},
        },
        &[_][]const i32{
            &[_]i32{1},
            &[_]i32{1},
        },
        &[_][]const i32{
            &[_]i32{ 0, 1 },
            &[_]i32{ 1, 0 },
        },
        &[_][]const i32{
            &[_]i32{ 1, 0 },
            &[_]i32{ 1, 0 },
        },
        &[_][]const i32{
            &[_]i32{ 1, -1, 0 },
            &[_]i32{ 1, 0, -1 },
        },
        &[_][]const i32{
            &[_]i32{ 2, 1, 3 },
            &[_]i32{ 3, 2, 1 },
        },
    };

    inline for (sort_funcs) |sortFn| {
        for (rev_cases) |case| {
            var buf: [8]i32 = undefined;
            const slice = buf[0..case[0].len];
            @memcpy(slice, case[0]);
            sortFn(i32, slice, {}, desc_i32);
            try testing.expect(mem.eql(i32, slice, case[1]));
        }
    }
}

test "sort with context in the middle of a slice" {
    const Context = struct {
        items: []i32,

        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            return ctx.items[a] < ctx.items[b];
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return mem.swap(i32, &ctx.items[a], &ctx.items[b]);
        }
    };

    const i32cases = [_][]const []const i32{
        &[_][]const i32{
            &[_]i32{ 0, 1, 8, 3, 6, 5, 4, 2, 9, 7, 10, 55, 32, 39, 58, 21, 88, 43, 22, 59 },
            &[_]i32{ 50, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 22, 32, 39, 43, 55, 58, 59, 88 },
        },
    };

    const ranges = [_]struct { start: usize, end: usize }{
        .{ .start = 10, .end = 20 },
        .{ .start = 1, .end = 11 },
        .{ .start = 3, .end = 7 },
    };

    inline for (context_sort_funcs) |sortFn| {
        for (i32cases) |case| {
            for (ranges) |range| {
                var buf: [20]i32 = undefined;
                const slice = buf[0..case[0].len];
                @memcpy(slice, case[0]);
                sortFn(range.start, range.end, Context{ .items = slice });
                try testing.expectEqualSlices(i32, case[1][range.start..range.end], slice[range.start..range.end]);
            }
        }
    }
}

test "sort fuzz testing" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const test_case_count = 10;

    inline for (sort_funcs) |sortFn| {
        for (0..test_case_count) |_| {
            const array_size = random.intRangeLessThan(usize, 0, 1000);
            const array = try testing.allocator.alloc(i32, array_size);
            defer testing.allocator.free(array);
            // populate with random data
            for (array) |*item| {
                item.* = random.intRangeLessThan(i32, 0, 100);
            }
            sortFn(i32, array, {}, asc_i32);
            try testing.expect(isSorted(i32, array, {}, asc_i32));
        }
    }
}

/// Returns the index of an element in `items` returning `.eq` when given to `compareFn`.
/// - If there are multiple such elements, returns the index of any one of them.
/// - If there are no such elements, returns `null`.
///
/// `items` must be sorted in ascending order with respect to `compareFn`:
/// ```
/// [0]                                                   [len]
/// ┌───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┐
/// │.lt│.lt│ \ \ │.lt│.eq│.eq│ \ \ │.eq│.gt│.gt│ \ \ │.gt│
/// └───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┘
/// ├─────────────────┼─────────────────┼─────────────────┤
///  ↳ zero or more    ↳ zero or more    ↳ zero or more
///                   ├─────────────────┤
///                    ↳ if not null, returned
///                      index is in this range
/// ```
///
/// `O(log n)` time complexity.
///
/// See also: `lowerBound, `upperBound`, `partitionPoint`, `equalRange`.
pub fn binarySearch(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime compareFn: fn (@TypeOf(context), T) std.math.Order,
) ?usize {
    var low: usize = 0;
    var high: usize = items.len;

    while (low < high) {
        // Avoid overflowing in the midpoint calculation
        const mid = low + (high - low) / 2;
        switch (compareFn(context, items[mid])) {
            .eq => return mid,
            .gt => low = mid + 1,
            .lt => high = mid,
        }
    }
    return null;
}

test binarySearch {
    const S = struct {
        fn orderU32(context: u32, item: u32) std.math.Order {
            return std.math.order(context, item);
        }
        fn orderI32(context: i32, item: i32) std.math.Order {
            return std.math.order(context, item);
        }
        fn orderLength(context: usize, item: []const u8) std.math.Order {
            return std.math.order(context, item.len);
        }
    };
    const R = struct {
        b: i32,
        e: i32,

        fn r(b: i32, e: i32) @This() {
            return .{ .b = b, .e = e };
        }

        fn order(context: i32, item: @This()) std.math.Order {
            if (context < item.b) {
                return .lt;
            } else if (context > item.e) {
                return .gt;
            } else {
                return .eq;
            }
        }
    };

    try std.testing.expectEqual(null, binarySearch(u32, &[_]u32{}, @as(u32, 1), S.orderU32));
    try std.testing.expectEqual(0, binarySearch(u32, &[_]u32{1}, @as(u32, 1), S.orderU32));
    try std.testing.expectEqual(null, binarySearch(u32, &[_]u32{0}, @as(u32, 1), S.orderU32));
    try std.testing.expectEqual(null, binarySearch(u32, &[_]u32{1}, @as(u32, 0), S.orderU32));
    try std.testing.expectEqual(4, binarySearch(u32, &[_]u32{ 1, 2, 3, 4, 5 }, @as(u32, 5), S.orderU32));
    try std.testing.expectEqual(0, binarySearch(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 2), S.orderU32));
    try std.testing.expectEqual(1, binarySearch(i32, &[_]i32{ -7, -4, 0, 9, 10 }, @as(i32, -4), S.orderI32));
    try std.testing.expectEqual(3, binarySearch(i32, &[_]i32{ -100, -25, 2, 98, 99, 100 }, @as(i32, 98), S.orderI32));
    try std.testing.expectEqual(null, binarySearch(R, &[_]R{ R.r(-100, -50), R.r(-40, -20), R.r(-10, 20), R.r(30, 40) }, @as(i32, -45), R.order));
    try std.testing.expectEqual(2, binarySearch(R, &[_]R{ R.r(-100, -50), R.r(-40, -20), R.r(-10, 20), R.r(30, 40) }, @as(i32, 10), R.order));
    try std.testing.expectEqual(1, binarySearch(R, &[_]R{ R.r(-100, -50), R.r(-40, -20), R.r(-10, 20), R.r(30, 40) }, @as(i32, -20), R.order));
    try std.testing.expectEqual(2, binarySearch([]const u8, &[_][]const u8{ "", "abc", "1234", "vwxyz" }, @as(usize, 4), S.orderLength));
}

/// Returns the index of the first element in `items` that is greater than or equal to `context`,
/// as determined by `compareFn`. If no such element exists, returns `items.len`.
///
/// `items` must be sorted in ascending order with respect to `compareFn`:
/// ```
/// [0]                                                   [len]
/// ┌───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┐
/// │.lt│.lt│ \ \ │.lt│.eq│.eq│ \ \ │.eq│.gt│.gt│ \ \ │.gt│
/// └───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┘
/// ├─────────────────┼─────────────────┼─────────────────┤
///  ↳ zero or more    ↳ zero or more    ↳ zero or more
///                   ├───┤
///                    ↳ returned index
/// ```
///
/// `O(log n)` time complexity.
///
/// See also: `binarySearch`, `upperBound`, `partitionPoint`, `equalRange`.
pub fn lowerBound(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime compareFn: fn (@TypeOf(context), T) std.math.Order,
) usize {
    const S = struct {
        fn predicate(ctx: @TypeOf(context), item: T) bool {
            return compareFn(ctx, item).invert() == .lt;
        }
    };
    return partitionPoint(T, items, context, S.predicate);
}

test lowerBound {
    const S = struct {
        fn compareU32(context: u32, item: u32) std.math.Order {
            return std.math.order(context, item);
        }
        fn compareI32(context: i32, item: i32) std.math.Order {
            return std.math.order(context, item);
        }
        fn compareF32(context: f32, item: f32) std.math.Order {
            return std.math.order(context, item);
        }
    };
    const R = struct {
        val: i32,

        fn r(val: i32) @This() {
            return .{ .val = val };
        }

        fn compareFn(context: i32, item: @This()) std.math.Order {
            return std.math.order(context, item.val);
        }
    };

    try std.testing.expectEqual(0, lowerBound(u32, &[_]u32{}, @as(u32, 0), S.compareU32));
    try std.testing.expectEqual(0, lowerBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 0), S.compareU32));
    try std.testing.expectEqual(0, lowerBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 2), S.compareU32));
    try std.testing.expectEqual(2, lowerBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 5), S.compareU32));
    try std.testing.expectEqual(2, lowerBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 8), S.compareU32));
    try std.testing.expectEqual(6, lowerBound(u32, &[_]u32{ 2, 4, 7, 7, 7, 7, 16, 32, 64 }, @as(u32, 8), S.compareU32));
    try std.testing.expectEqual(2, lowerBound(u32, &[_]u32{ 2, 4, 8, 8, 8, 8, 16, 32, 64 }, @as(u32, 8), S.compareU32));
    try std.testing.expectEqual(5, lowerBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 64), S.compareU32));
    try std.testing.expectEqual(6, lowerBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 100), S.compareU32));
    try std.testing.expectEqual(2, lowerBound(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 5), S.compareI32));
    try std.testing.expectEqual(1, lowerBound(f32, &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, @as(f32, -33.4), S.compareF32));
    try std.testing.expectEqual(2, lowerBound(R, &[_]R{ R.r(-100), R.r(-40), R.r(-10), R.r(30) }, @as(i32, -20), R.compareFn));
}

/// Returns the index of the first element in `items` that is greater than `context`, as determined
/// by `compareFn`. If no such element exists, returns `items.len`.
///
/// `items` must be sorted in ascending order with respect to `compareFn`:
/// ```
/// [0]                                                   [len]
/// ┌───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┐
/// │.lt│.lt│ \ \ │.lt│.eq│.eq│ \ \ │.eq│.gt│.gt│ \ \ │.gt│
/// └───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┘
/// ├─────────────────┼─────────────────┼─────────────────┤
///  ↳ zero or more    ↳ zero or more    ↳ zero or more
///                                     ├───┤
///                                      ↳ returned index
/// ```
///
/// `O(log n)` time complexity.
///
/// See also: `binarySearch`, `lowerBound`, `partitionPoint`, `equalRange`.
pub fn upperBound(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime compareFn: fn (@TypeOf(context), T) std.math.Order,
) usize {
    const S = struct {
        fn predicate(ctx: @TypeOf(context), item: T) bool {
            return compareFn(ctx, item).invert() != .gt;
        }
    };
    return partitionPoint(T, items, context, S.predicate);
}

test upperBound {
    const S = struct {
        fn compareU32(context: u32, item: u32) std.math.Order {
            return std.math.order(context, item);
        }
        fn compareI32(context: i32, item: i32) std.math.Order {
            return std.math.order(context, item);
        }
        fn compareF32(context: f32, item: f32) std.math.Order {
            return std.math.order(context, item);
        }
    };
    const R = struct {
        val: i32,

        fn r(val: i32) @This() {
            return .{ .val = val };
        }

        fn compareFn(context: i32, item: @This()) std.math.Order {
            return std.math.order(context, item.val);
        }
    };

    try std.testing.expectEqual(0, upperBound(u32, &[_]u32{}, @as(u32, 0), S.compareU32));
    try std.testing.expectEqual(0, upperBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 0), S.compareU32));
    try std.testing.expectEqual(1, upperBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 2), S.compareU32));
    try std.testing.expectEqual(2, upperBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 5), S.compareU32));
    try std.testing.expectEqual(6, upperBound(u32, &[_]u32{ 2, 4, 7, 7, 7, 7, 16, 32, 64 }, @as(u32, 8), S.compareU32));
    try std.testing.expectEqual(6, upperBound(u32, &[_]u32{ 2, 4, 8, 8, 8, 8, 16, 32, 64 }, @as(u32, 8), S.compareU32));
    try std.testing.expectEqual(3, upperBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 8), S.compareU32));
    try std.testing.expectEqual(6, upperBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 64), S.compareU32));
    try std.testing.expectEqual(6, upperBound(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 100), S.compareU32));
    try std.testing.expectEqual(2, upperBound(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 5), S.compareI32));
    try std.testing.expectEqual(1, upperBound(f32, &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, @as(f32, -33.4), S.compareF32));
    try std.testing.expectEqual(2, upperBound(R, &[_]R{ R.r(-100), R.r(-40), R.r(-10), R.r(30) }, @as(i32, -20), R.compareFn));
}

/// Returns the index of the partition point of `items` in relation to the given predicate.
/// - If all elements of `items` satisfy the predicate the returned value is `items.len`.
///
/// `items` must contain a prefix for which all elements satisfy the predicate,
/// and beyond which none of the elements satisfy the predicate:
/// ```
/// [0]                                          [len]
/// ┌────┬────┬─/ /─┬────┬─────┬─────┬─/ /─┬─────┐
/// │true│true│ \ \ │true│false│false│ \ \ │false│
/// └────┴────┴─/ /─┴────┴─────┴─────┴─/ /─┴─────┘
/// ├────────────────────┼───────────────────────┤
///  ↳ zero or more       ↳ zero or more
///                      ├─────┤
///                       ↳ returned index
/// ```
///
/// `O(log n)` time complexity.
///
/// See also: `binarySearch`, `lowerBound, `upperBound`, `equalRange`.
pub fn partitionPoint(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime predicate: fn (@TypeOf(context), T) bool,
) usize {
    var low: usize = 0;
    var high: usize = items.len;

    while (low < high) {
        const mid = low + (high - low) / 2;
        if (predicate(context, items[mid])) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return low;
}

test partitionPoint {
    const S = struct {
        fn lowerU32(context: u32, item: u32) bool {
            return item < context;
        }
        fn lowerI32(context: i32, item: i32) bool {
            return item < context;
        }
        fn lowerF32(context: f32, item: f32) bool {
            return item < context;
        }
        fn lowerEqU32(context: u32, item: u32) bool {
            return item <= context;
        }
        fn lowerEqI32(context: i32, item: i32) bool {
            return item <= context;
        }
        fn lowerEqF32(context: f32, item: f32) bool {
            return item <= context;
        }
        fn isEven(_: void, item: u8) bool {
            return item % 2 == 0;
        }
    };

    try std.testing.expectEqual(0, partitionPoint(u32, &[_]u32{}, @as(u32, 0), S.lowerU32));
    try std.testing.expectEqual(0, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 0), S.lowerU32));
    try std.testing.expectEqual(0, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 2), S.lowerU32));
    try std.testing.expectEqual(2, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 5), S.lowerU32));
    try std.testing.expectEqual(2, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 8), S.lowerU32));
    try std.testing.expectEqual(6, partitionPoint(u32, &[_]u32{ 2, 4, 7, 7, 7, 7, 16, 32, 64 }, @as(u32, 8), S.lowerU32));
    try std.testing.expectEqual(2, partitionPoint(u32, &[_]u32{ 2, 4, 8, 8, 8, 8, 16, 32, 64 }, @as(u32, 8), S.lowerU32));
    try std.testing.expectEqual(5, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 64), S.lowerU32));
    try std.testing.expectEqual(6, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 100), S.lowerU32));
    try std.testing.expectEqual(2, partitionPoint(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 5), S.lowerI32));
    try std.testing.expectEqual(1, partitionPoint(f32, &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, @as(f32, -33.4), S.lowerF32));
    try std.testing.expectEqual(0, partitionPoint(u32, &[_]u32{}, @as(u32, 0), S.lowerEqU32));
    try std.testing.expectEqual(0, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 0), S.lowerEqU32));
    try std.testing.expectEqual(1, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 2), S.lowerEqU32));
    try std.testing.expectEqual(2, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 5), S.lowerEqU32));
    try std.testing.expectEqual(6, partitionPoint(u32, &[_]u32{ 2, 4, 7, 7, 7, 7, 16, 32, 64 }, @as(u32, 8), S.lowerEqU32));
    try std.testing.expectEqual(6, partitionPoint(u32, &[_]u32{ 2, 4, 8, 8, 8, 8, 16, 32, 64 }, @as(u32, 8), S.lowerEqU32));
    try std.testing.expectEqual(3, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 8), S.lowerEqU32));
    try std.testing.expectEqual(6, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 64), S.lowerEqU32));
    try std.testing.expectEqual(6, partitionPoint(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 100), S.lowerEqU32));
    try std.testing.expectEqual(2, partitionPoint(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 5), S.lowerEqI32));
    try std.testing.expectEqual(1, partitionPoint(f32, &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, @as(f32, -33.4), S.lowerEqF32));
    try std.testing.expectEqual(4, partitionPoint(u8, &[_]u8{ 0, 50, 14, 2, 5, 71 }, {}, S.isEven));
}

/// Returns a tuple of the lower and upper indices in `items` between which all
/// elements return `.eq` when given to `compareFn`.
/// - If no element in `items` returns `.eq`, both indices are the
/// index of the first element in `items` returning `.gt`.
/// - If no element in `items` returns `.gt`, both indices equal `items.len`.
///
/// `items` must be sorted in ascending order with respect to `compareFn`:
/// ```
/// [0]                                                   [len]
/// ┌───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┬───┬───┬─/ /─┬───┐
/// │.lt│.lt│ \ \ │.lt│.eq│.eq│ \ \ │.eq│.gt│.gt│ \ \ │.gt│
/// └───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┴───┴───┴─/ /─┴───┘
/// ├─────────────────┼─────────────────┼─────────────────┤
///  ↳ zero or more    ↳ zero or more    ↳ zero or more
///                   ├─────────────────┤
///                    ↳ returned range
/// ```
///
/// `O(log n)` time complexity.
///
/// See also: `binarySearch`, `lowerBound, `upperBound`, `partitionPoint`.
pub fn equalRange(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime compareFn: fn (@TypeOf(context), T) std.math.Order,
) struct { usize, usize } {
    var low: usize = 0;
    var high: usize = items.len;

    while (low < high) {
        const mid = low + (high - low) / 2;
        switch (compareFn(context, items[mid])) {
            .gt => {
                low = mid + 1;
            },
            .lt => {
                high = mid;
            },
            .eq => {
                return .{
                    low + std.sort.lowerBound(
                        T,
                        items[low..mid],
                        context,
                        compareFn,
                    ),
                    mid + std.sort.upperBound(
                        T,
                        items[mid..high],
                        context,
                        compareFn,
                    ),
                };
            },
        }
    }

    return .{ low, low };
}

test equalRange {
    const S = struct {
        fn orderU32(context: u32, item: u32) std.math.Order {
            return std.math.order(context, item);
        }
        fn orderI32(context: i32, item: i32) std.math.Order {
            return std.math.order(context, item);
        }
        fn orderF32(context: f32, item: f32) std.math.Order {
            return std.math.order(context, item);
        }
        fn orderLength(context: usize, item: []const u8) std.math.Order {
            return std.math.order(context, item.len);
        }
    };

    try std.testing.expectEqual(.{ 0, 0 }, equalRange(i32, &[_]i32{}, @as(i32, 0), S.orderI32));
    try std.testing.expectEqual(.{ 0, 0 }, equalRange(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 0), S.orderI32));
    try std.testing.expectEqual(.{ 0, 1 }, equalRange(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 2), S.orderI32));
    try std.testing.expectEqual(.{ 2, 2 }, equalRange(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 5), S.orderI32));
    try std.testing.expectEqual(.{ 2, 3 }, equalRange(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 8), S.orderI32));
    try std.testing.expectEqual(.{ 5, 6 }, equalRange(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 64), S.orderI32));
    try std.testing.expectEqual(.{ 6, 6 }, equalRange(i32, &[_]i32{ 2, 4, 8, 16, 32, 64 }, @as(i32, 100), S.orderI32));
    try std.testing.expectEqual(.{ 2, 6 }, equalRange(i32, &[_]i32{ 2, 4, 8, 8, 8, 8, 15, 22 }, @as(i32, 8), S.orderI32));
    try std.testing.expectEqual(.{ 2, 2 }, equalRange(u32, &[_]u32{ 2, 4, 8, 16, 32, 64 }, @as(u32, 5), S.orderU32));
    try std.testing.expectEqual(.{ 3, 5 }, equalRange(u32, &[_]u32{ 2, 3, 4, 5, 5 }, @as(u32, 5), S.orderU32));
    try std.testing.expectEqual(.{ 1, 1 }, equalRange(f32, &[_]f32{ -54.2, -26.7, 0.0, 56.55, 100.1, 322.0 }, @as(f32, -33.4), S.orderF32));
    try std.testing.expectEqual(.{ 3, 5 }, equalRange(
        []const u8,
        &[_][]const u8{ "Mars", "Venus", "Earth", "Saturn", "Uranus", "Mercury", "Jupiter", "Neptune" },
        @as(usize, 6),
        S.orderLength,
    ));
}

pub fn argMin(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) ?usize {
    if (items.len == 0) {
        return null;
    }

    var smallest = items[0];
    var smallest_index: usize = 0;
    for (items[1..], 0..) |item, i| {
        if (lessThan(context, item, smallest)) {
            smallest = item;
            smallest_index = i + 1;
        }
    }

    return smallest_index;
}

test argMin {
    try testing.expectEqual(@as(?usize, null), argMin(i32, &[_]i32{}, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 0), argMin(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 0), argMin(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 3), argMin(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 0), argMin(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 0), argMin(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 3), argMin(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn min(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime lessThan: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) ?T {
    const i = argMin(T, items, context, lessThan) orelse return null;
    return items[i];
}

test min {
    try testing.expectEqual(@as(?i32, null), min(i32, &[_]i32{}, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 1), min(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 1), min(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 2), min(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 1), min(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, -10), min(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 7), min(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn argMax(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime lessThan: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) ?usize {
    if (items.len == 0) {
        return null;
    }

    var biggest = items[0];
    var biggest_index: usize = 0;
    for (items[1..], 0..) |item, i| {
        if (lessThan(context, biggest, item)) {
            biggest = item;
            biggest_index = i + 1;
        }
    }

    return biggest_index;
}

test argMax {
    try testing.expectEqual(@as(?usize, null), argMax(i32, &[_]i32{}, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 0), argMax(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 4), argMax(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 0), argMax(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 0), argMax(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 2), argMax(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expectEqual(@as(?usize, 1), argMax(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn max(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime lessThan: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) ?T {
    const i = argMax(T, items, context, lessThan) orelse return null;
    return items[i];
}

test max {
    try testing.expectEqual(@as(?i32, null), max(i32, &[_]i32{}, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 1), max(i32, &[_]i32{1}, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 5), max(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 9), max(i32, &[_]i32{ 9, 3, 8, 2, 5 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 1), max(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 10), max(i32, &[_]i32{ -10, 1, 10 }, {}, asc_i32));
    try testing.expectEqual(@as(?i32, 3), max(i32, &[_]i32{ 6, 3, 5, 7, 6 }, {}, desc_i32));
}

pub fn isSorted(
    comptime T: type,
    items: []const T,
    context: anytype,
    comptime lessThan: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) bool {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        if (lessThan(context, items[i], items[i - 1])) {
            return false;
        }
    }

    return true;
}

test isSorted {
    try testing.expect(isSorted(i32, &[_]i32{}, {}, asc_i32));
    try testing.expect(isSorted(i32, &[_]i32{10}, {}, asc_i32));
    try testing.expect(isSorted(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, asc_i32));
    try testing.expect(isSorted(i32, &[_]i32{ -10, 1, 1, 1, 10 }, {}, asc_i32));

    try testing.expect(isSorted(i32, &[_]i32{}, {}, desc_i32));
    try testing.expect(isSorted(i32, &[_]i32{-20}, {}, desc_i32));
    try testing.expect(isSorted(i32, &[_]i32{ 3, 2, 1, 0, -1 }, {}, desc_i32));
    try testing.expect(isSorted(i32, &[_]i32{ 10, -10 }, {}, desc_i32));

    try testing.expect(isSorted(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, asc_i32));
    try testing.expect(isSorted(i32, &[_]i32{ 1, 1, 1, 1, 1 }, {}, desc_i32));

    try testing.expectEqual(false, isSorted(i32, &[_]i32{ 5, 4, 3, 2, 1 }, {}, asc_i32));
    try testing.expectEqual(false, isSorted(i32, &[_]i32{ 1, 2, 3, 4, 5 }, {}, desc_i32));

    try testing.expect(isSorted(u8, "abcd", {}, asc_u8));
    try testing.expect(isSorted(u8, "zyxw", {}, desc_u8));

    try testing.expectEqual(false, isSorted(u8, "abcd", {}, desc_u8));
    try testing.expectEqual(false, isSorted(u8, "zyxw", {}, asc_u8));

    try testing.expect(isSorted(u8, "ffff", {}, asc_u8));
    try testing.expect(isSorted(u8, "ffff", {}, desc_u8));
}
const builtin = @import("builtin");
const std = @import("../std.zig");
const sort = std.sort;
const math = std.math;
const mem = std.mem;

const Range = struct {
    start: usize,
    end: usize,

    fn init(start: usize, end: usize) Range {
        return Range{
            .start = start,
            .end = end,
        };
    }

    fn length(self: Range) usize {
        return self.end - self.start;
    }
};

const Iterator = struct {
    size: usize,
    power_of_two: usize,
    numerator: usize,
    decimal: usize,
    denominator: usize,
    decimal_step: usize,
    numerator_step: usize,

    fn init(size2: usize, min_level: usize) Iterator {
        const power_of_two = math.floorPowerOfTwo(usize, size2);
        const denominator = power_of_two / min_level;
        return Iterator{
            .numerator = 0,
            .decimal = 0,
            .size = size2,
            .power_of_two = power_of_two,
            .denominator = denominator,
            .decimal_step = size2 / denominator,
            .numerator_step = size2 % denominator,
        };
    }

    fn begin(self: *Iterator) void {
        self.numerator = 0;
        self.decimal = 0;
    }

    fn nextRange(self: *Iterator) Range {
        const start = self.decimal;

        self.decimal += self.decimal_step;
        self.numerator += self.numerator_step;
        if (self.numerator >= self.denominator) {
            self.numerator -= self.denominator;
            self.decimal += 1;
        }

        return Range{
            .start = start,
            .end = self.decimal,
        };
    }

    fn finished(self: *Iterator) bool {
        return self.decimal >= self.size;
    }

    fn nextLevel(self: *Iterator) bool {
        self.decimal_step += self.decimal_step;
        self.numerator_step += self.numerator_step;
        if (self.numerator_step >= self.denominator) {
            self.numerator_step -= self.denominator;
            self.decimal_step += 1;
        }

        return (self.decimal_step < self.size);
    }

    fn length(self: *Iterator) usize {
        return self.decimal_step;
    }
};

const Pull = struct {
    from: usize,
    to: usize,
    count: usize,
    range: Range,
};

/// Stable in-place sort. O(n) best case, O(n*log(n)) worst case and average case.
/// O(1) memory (no allocator required).
/// Sorts in ascending order with respect to the given `lessThan` function.
///
/// NOTE: The algorithm only works when the comparison is less-than or greater-than.
///       (See https://github.com/ziglang/zig/issues/8289)
pub fn block(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    const lessThan = if (builtin.mode == .Debug) struct {
        fn lessThan(ctx: @TypeOf(context), lhs: T, rhs: T) bool {
            const lt = lessThanFn(ctx, lhs, rhs);
            const gt = lessThanFn(ctx, rhs, lhs);
            std.debug.assert(!(lt and gt));
            return lt;
        }
    }.lessThan else lessThanFn;

    // Implementation ported from https://github.com/BonzaiThePenguin/WikiSort/blob/master/WikiSort.c
    var cache: [512]T = undefined;

    if (items.len < 4) {
        if (items.len == 3) {
            // hard coded insertion sort
            if (lessThan(context, items[1], items[0])) mem.swap(T, &items[0], &items[1]);
            if (lessThan(context, items[2], items[1])) {
                mem.swap(T, &items[1], &items[2]);
                if (lessThan(context, items[1], items[0])) mem.swap(T, &items[0], &items[1]);
            }
        } else if (items.len == 2) {
            if (lessThan(context, items[1], items[0])) mem.swap(T, &items[0], &items[1]);
        }
        return;
    }

    // sort groups of 4-8 items at a time using an unstable sorting network,
    // but keep track of the original item orders to force it to be stable
    // http://pages.ripco.net/~jgamble/nw.html
    var iterator = Iterator.init(items.len, 4);
    while (!iterator.finished()) {
        var order = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
        const range = iterator.nextRange();

        const sliced_items = items[range.start..];
        switch (range.length()) {
            8 => {
                swap(T, sliced_items, &order, 0, 1, context, lessThan);
                swap(T, sliced_items, &order, 2, 3, context, lessThan);
                swap(T, sliced_items, &order, 4, 5, context, lessThan);
                swap(T, sliced_items, &order, 6, 7, context, lessThan);
                swap(T, sliced_items, &order, 0, 2, context, lessThan);
                swap(T, sliced_items, &order, 1, 3, context, lessThan);
                swap(T, sliced_items, &order, 4, 6, context, lessThan);
                swap(T, sliced_items, &order, 5, 7, context, lessThan);
                swap(T, sliced_items, &order, 1, 2, context, lessThan);
                swap(T, sliced_items, &order, 5, 6, context, lessThan);
                swap(T, sliced_items, &order, 0, 4, context, lessThan);
                swap(T, sliced_items, &order, 3, 7, context, lessThan);
                swap(T, sliced_items, &order, 1, 5, context, lessThan);
                swap(T, sliced_items, &order, 2, 6, context, lessThan);
                swap(T, sliced_items, &order, 1, 4, context, lessThan);
                swap(T, sliced_items, &order, 3, 6, context, lessThan);
                swap(T, sliced_items, &order, 2, 4, context, lessThan);
                swap(T, sliced_items, &order, 3, 5, context, lessThan);
                swap(T, sliced_items, &order, 3, 4, context, lessThan);
            },
            7 => {
                swap(T, sliced_items, &order, 1, 2, context, lessThan);
                swap(T, sliced_items, &order, 3, 4, context, lessThan);
                swap(T, sliced_items, &order, 5, 6, context, lessThan);
                swap(T, sliced_items, &order, 0, 2, context, lessThan);
                swap(T, sliced_items, &order, 3, 5, context, lessThan);
                swap(T, sliced_items, &order, 4, 6, context, lessThan);
                swap(T, sliced_items, &order, 0, 1, context, lessThan);
                swap(T, sliced_items, &order, 4, 5, context, lessThan);
                swap(T, sliced_items, &order, 2, 6, context, lessThan);
                swap(T, sliced_items, &order, 0, 4, context, lessThan);
                swap(T, sliced_items, &order, 1, 5, context, lessThan);
                swap(T, sliced_items, &order, 0, 3, context, lessThan);
                swap(T, sliced_items, &order, 2, 5, context, lessThan);
                swap(T, sliced_items, &order, 1, 3, context, lessThan);
                swap(T, sliced_items, &order, 2, 4, context, lessThan);
                swap(T, sliced_items, &order, 2, 3, context, lessThan);
            },
            6 => {
                swap(T, sliced_items, &order, 1, 2, context, lessThan);
                swap(T, sliced_items, &order, 4, 5, context, lessThan);
                swap(T, sliced_items, &order, 0, 2, context, lessThan);
                swap(T, sliced_items, &order, 3, 5, context, lessThan);
                swap(T, sliced_items, &order, 0, 1, context, lessThan);
                swap(T, sliced_items, &order, 3, 4, context, lessThan);
                swap(T, sliced_items, &order, 2, 5, context, lessThan);
                swap(T, sliced_items, &order, 0, 3, context, lessThan);
                swap(T, sliced_items, &order, 1, 4, context, lessThan);
                swap(T, sliced_items, &order, 2, 4, context, lessThan);
                swap(T, sliced_items, &order, 1, 3, context, lessThan);
                swap(T, sliced_items, &order, 2, 3, context, lessThan);
            },
            5 => {
                swap(T, sliced_items, &order, 0, 1, context, lessThan);
                swap(T, sliced_items, &order, 3, 4, context, lessThan);
                swap(T, sliced_items, &order, 2, 4, context, lessThan);
                swap(T, sliced_items, &order, 2, 3, context, lessThan);
                swap(T, sliced_items, &order, 1, 4, context, lessThan);
                swap(T, sliced_items, &order, 0, 3, context, lessThan);
                swap(T, sliced_items, &order, 0, 2, context, lessThan);
                swap(T, sliced_items, &order, 1, 3, context, lessThan);
                swap(T, sliced_items, &order, 1, 2, context, lessThan);
            },
            4 => {
                swap(T, sliced_items, &order, 0, 1, context, lessThan);
                swap(T, sliced_items, &order, 2, 3, context, lessThan);
                swap(T, sliced_items, &order, 0, 2, context, lessThan);
                swap(T, sliced_items, &order, 1, 3, context, lessThan);
                swap(T, sliced_items, &order, 1, 2, context, lessThan);
            },
            else => {},
        }
    }
    if (items.len < 8) return;

    // then merge sort the higher levels, which can be 8-15, 16-31, 32-63, 64-127, etc.
    while (true) {
        // if every A and B block will fit into the cache, use a special branch
        // specifically for merging with the cache
        // (we use < rather than <= since the block size might be one more than
        // iterator.length())
        if (iterator.length() < cache.len) {
            // if four subarrays fit into the cache, it's faster to merge both
            // pairs of subarrays into the cache,
            // then merge the two merged subarrays from the cache back into the original array
            if ((iterator.length() + 1) * 4 <= cache.len and iterator.length() * 4 <= items.len) {
                iterator.begin();
                while (!iterator.finished()) {
                    // merge A1 and B1 into the cache
                    var A1 = iterator.nextRange();
                    var B1 = iterator.nextRange();
                    var A2 = iterator.nextRange();
                    var B2 = iterator.nextRange();

                    if (lessThan(context, items[B1.end - 1], items[A1.start])) {
                        // the two ranges are in reverse order, so copy them in reverse order into the cache
                        const a1_items = items[A1.start..A1.end];
                        @memcpy(cache[B1.length()..][0..a1_items.len], a1_items);
                        const b1_items = items[B1.start..B1.end];
                        @memcpy(cache[0..b1_items.len], b1_items);
                    } else if (lessThan(context, items[B1.start], items[A1.end - 1])) {
                        // these two ranges weren't already in order, so merge them into the cache
                        mergeInto(T, items, A1, B1, cache[0..], context, lessThan);
                    } else {
                        // if A1, B1, A2, and B2 are all in order, skip doing anything else
                        if (!lessThan(context, items[B2.start], items[A2.end - 1]) and !lessThan(context, items[A2.start], items[B1.end - 1])) continue;

                        // copy A1 and B1 into the cache in the same order
                        const a1_items = items[A1.start..A1.end];
                        @memcpy(cache[0..a1_items.len], a1_items);
                        const b1_items = items[B1.start..B1.end];
                        @memcpy(cache[A1.length()..][0..b1_items.len], b1_items);
                    }
                    A1 = Range.init(A1.start, B1.end);

                    // merge A2 and B2 into the cache
                    if (lessThan(context, items[B2.end - 1], items[A2.start])) {
                        // the two ranges are in reverse order, so copy them in reverse order into the cache
                        const a2_items = items[A2.start..A2.end];
                        @memcpy(cache[A1.length() + B2.length() ..][0..a2_items.len], a2_items);
                        const b2_items = items[B2.start..B2.end];
                        @memcpy(cache[A1.length()..][0..b2_items.len], b2_items);
                    } else if (lessThan(context, items[B2.start], items[A2.end - 1])) {
                        // these two ranges weren't already in order, so merge them into the cache
                        mergeInto(T, items, A2, B2, cache[A1.length()..], context, lessThan);
                    } else {
                        // copy A2 and B2 into the cache in the same order
                        const a2_items = items[A2.start..A2.end];
                        @memcpy(cache[A1.length()..][0..a2_items.len], a2_items);
                        const b2_items = items[B2.start..B2.end];
                        @memcpy(cache[A1.length() + A2.length() ..][0..b2_items.len], b2_items);
                    }
                    A2 = Range.init(A2.start, B2.end);

                    // merge A1 and A2 from the cache into the items
                    const A3 = Range.init(0, A1.length());
                    const B3 = Range.init(A1.length(), A1.length() + A2.length());

                    if (lessThan(context, cache[B3.end - 1], cache[A3.start])) {
                        // the two ranges are in reverse order, so copy them in reverse order into the items
                        const a3_items = cache[A3.start..A3.end];
                        @memcpy(items[A1.start + A2.length() ..][0..a3_items.len], a3_items);
                        const b3_items = cache[B3.start..B3.end];
                        @memcpy(items[A1.start..][0..b3_items.len], b3_items);
                    } else if (lessThan(context, cache[B3.start], cache[A3.end - 1])) {
                        // these two ranges weren't already in order, so merge them back into the items
                        mergeInto(T, cache[0..], A3, B3, items[A1.start..], context, lessThan);
                    } else {
                        // copy A3 and B3 into the items in the same order
                        const a3_items = cache[A3.start..A3.end];
                        @memcpy(items[A1.start..][0..a3_items.len], a3_items);
                        const b3_items = cache[B3.start..B3.end];
                        @memcpy(items[A1.start + A1.length() ..][0..b3_items.len], b3_items);
                    }
                }

                // we merged two levels at the same time, so we're done with this level already
                // (iterator.nextLevel() is called again at the bottom of this outer merge loop)
                _ = iterator.nextLevel();
            } else {
                iterator.begin();
                while (!iterator.finished()) {
                    const A = iterator.nextRange();
                    const B = iterator.nextRange();

                    if (lessThan(context, items[B.end - 1], items[A.start])) {
                        // the two ranges are in reverse order, so a simple rotation should fix it
                        mem.rotate(T, items[A.start..B.end], A.length());
                    } else if (lessThan(context, items[B.start], items[A.end - 1])) {
                        // these two ranges weren't already in order, so we'll need to merge them!
                        const a_items = items[A.start..A.end];
                        @memcpy(cache[0..a_items.len], a_items);
                        mergeExternal(T, items, A, B, cache[0..], context, lessThan);
                    }
                }
            }
        } else {
            // this is where the in-place merge logic starts!
            // 1. pull out two internal buffers each containing √A unique values
            //    1a. adjust block_size and buffer_size if we couldn't find enough unique values
            // 2. loop over the A and B subarrays within this level of the merge sort
            // 3. break A and B into blocks of size 'block_size'
            // 4. "tag" each of the A blocks with values from the first internal buffer
            // 5. roll the A blocks through the B blocks and drop/rotate them where they belong
            // 6. merge each A block with any B values that follow, using the cache or the second internal buffer
            // 7. sort the second internal buffer if it exists
            // 8. redistribute the two internal buffers back into the items
            var block_size: usize = math.sqrt(iterator.length());
            var buffer_size = iterator.length() / block_size + 1;

            // as an optimization, we really only need to pull out the internal buffers once for each level of merges
            // after that we can reuse the same buffers over and over, then redistribute it when we're finished with this level
            var A: Range = undefined;
            var B: Range = undefined;
            var index: usize = 0;
            var last: usize = 0;
            var count: usize = 0;
            var find: usize = 0;
            var start: usize = 0;
            var pull_index: usize = 0;
            var pull = [_]Pull{
                Pull{
                    .from = 0,
                    .to = 0,
                    .count = 0,
                    .range = Range.init(0, 0),
                },
                Pull{
                    .from = 0,
                    .to = 0,
                    .count = 0,
                    .range = Range.init(0, 0),
                },
            };

            var buffer1 = Range.init(0, 0);
            var buffer2 = Range.init(0, 0);

            // find two internal buffers of size 'buffer_size' each
            find = buffer_size + buffer_size;
            var find_separately = false;

            if (block_size <= cache.len) {
                // if every A block fits into the cache then we won't need the second internal buffer,
                // so we really only need to find 'buffer_size' unique values
                find = buffer_size;
            } else if (find > iterator.length()) {
                // we can't fit both buffers into the same A or B subarray, so find two buffers separately
                find = buffer_size;
                find_separately = true;
            }

            // we need to find either a single contiguous space containing 2√A unique values (which will be split up into two buffers of size √A each),
            // or we need to find one buffer of < 2√A unique values, and a second buffer of √A unique values,
            // OR if we couldn't find that many unique values, we need the largest possible buffer we can get

            // in the case where it couldn't find a single buffer of at least √A unique values,
            // all of the Merge steps must be replaced by a different merge algorithm (MergeInPlace)
            iterator.begin();
            while (!iterator.finished()) {
                A = iterator.nextRange();
                B = iterator.nextRange();

                // just store information about where the values will be pulled from and to,
                // as well as how many values there are, to create the two internal buffers

                // check A for the number of unique values we need to fill an internal buffer
                // these values will be pulled out to the start of A
                last = A.start;
                count = 1;
                while (count < find) : ({
                    last = index;
                    count += 1;
                }) {
                    index = findLastForward(T, items, items[last], Range.init(last + 1, A.end), find - count, context, lessThan);
                    if (index == A.end) break;
                }
                index = last;

                if (count >= buffer_size) {
                    // keep track of the range within the items where we'll need to "pull out" these values to create the internal buffer
                    pull[pull_index] = Pull{
                        .range = Range.init(A.start, B.end),
                        .count = count,
                        .from = index,
                        .to = A.start,
                    };
                    pull_index = 1;

                    if (count == buffer_size + buffer_size) {
                        // we were able to find a single contiguous section containing 2√A unique values,
                        // so this section can be used to contain both of the internal buffers we'll need
                        buffer1 = Range.init(A.start, A.start + buffer_size);
                        buffer2 = Range.init(A.start + buffer_size, A.start + count);
                        break;
                    } else if (find == buffer_size + buffer_size) {
                        // we found a buffer that contains at least √A unique values, but did not contain the full 2√A unique values,
                        // so we still need to find a second separate buffer of at least √A unique values
                        buffer1 = Range.init(A.start, A.start + count);
                        find = buffer_size;
                    } else if (block_size <= cache.len) {
                        // we found the first and only internal buffer that we need, so we're done!
                        buffer1 = Range.init(A.start, A.start + count);
                        break;
                    } else if (find_separately) {
                        // found one buffer, but now find the other one
                        buffer1 = Range.init(A.start, A.start + count);
                        find_separately = false;
                    } else {
                        // we found a second buffer in an 'A' subarray containing √A unique values, so we're done!
                        buffer2 = Range.init(A.start, A.start + count);
                        break;
                    }
                } else if (pull_index == 0 and count > buffer1.length()) {
                    // keep track of the largest buffer we were able to find
                    buffer1 = Range.init(A.start, A.start + count);
                    pull[pull_index] = Pull{
                        .range = Range.init(A.start, B.end),
                        .count = count,
                        .from = index,
                        .to = A.start,
                    };
                }

                // check B for the number of unique values we need to fill an internal buffer
                // these values will be pulled out to the end of B
                last = B.end - 1;
                count = 1;
                while (count < find) : ({
                    last = index - 1;
                    count += 1;
                }) {
                    index = findFirstBackward(T, items, items[last], Range.init(B.start, last), find - count, context, lessThan);
                    if (index == B.start) break;
                }
                index = last;

                if (count >= buffer_size) {
                    // keep track of the range within the items where we'll need to "pull out" these values to create the internal buffe
                    pull[pull_index] = Pull{
                        .range = Range.init(A.start, B.end),
                        .count = count,
                        .from = index,
                        .to = B.end,
                    };
                    pull_index = 1;

                    if (count == buffer_size + buffer_size) {
                        // we were able to find a single contiguous section containing 2√A unique values,
                        // so this section can be used to contain both of the internal buffers we'll need
                        buffer1 = Range.init(B.end - count, B.end - buffer_size);
                        buffer2 = Range.init(B.end - buffer_size, B.end);
                        break;
                    } else if (find == buffer_size + buffer_size) {
                        // we found a buffer that contains at least √A unique values, but did not contain the full 2√A unique values,
                        // so we still need to find a second separate buffer of at least √A unique values
                        buffer1 = Range.init(B.end - count, B.end);
                        find = buffer_size;
                    } else if (block_size <= cache.len) {
                        // we found the first and only internal buffer that we need, so we're done!
                        buffer1 = Range.init(B.end - count, B.end);
                        break;
                    } else if (find_separately) {
                        // found one buffer, but now find the other one
                        buffer1 = Range.init(B.end - count, B.end);
                        find_separately = false;
                    } else {
                        // buffer2 will be pulled out from a 'B' subarray, so if the first buffer was pulled out from the corresponding 'A' subarray,
                        // we need to adjust the end point for that A subarray so it knows to stop redistributing its values before reaching buffer2
                        if (pull[0].range.start == A.start) pull[0].range.end -= pull[1].count;

                        // we found a second buffer in an 'B' subarray containing √A unique values, so we're done!
                        buffer2 = Range.init(B.end - count, B.end);
                        break;
                    }
                } else if (pull_index == 0 and count > buffer1.length()) {
                    // keep track of the largest buffer we were able to find
                    buffer1 = Range.init(B.end - count, B.end);
                    pull[pull_index] = Pull{
                        .range = Range.init(A.start, B.end),
                        .count = count,
                        .from = index,
                        .to = B.end,
                    };
                }
            }

            // pull out the two ranges so we can use them as internal buffers
            pull_index = 0;
            while (pull_index < 2) : (pull_index += 1) {
                const length = pull[pull_index].count;

                if (pull[pull_index].to < pull[pull_index].from) {
                    // we're pulling the values out to the left, which means the start of an A subarray
                    index = pull[pull_index].from;
                    count = 1;
                    while (count < length) : (count += 1) {
                        index = findFirstBackward(T, items, items[index - 1], Range.init(pull[pull_index].to, pull[pull_index].from - (count - 1)), length - count, context, lessThan);
                        const range = Range.init(index + 1, pull[pull_index].from + 1);
                        mem.rotate(T, items[range.start..range.end], range.length() - count);
                        pull[pull_index].from = index + count;
                    }
                } else if (pull[pull_index].to > pull[pull_index].from) {
                    // we're pulling values out to the right, which means the end of a B subarray
                    index = pull[pull_index].from + 1;
                    count = 1;
                    while (count < length) : (count += 1) {
                        index = findLastForward(T, items, items[index], Range.init(index, pull[pull_index].to), length - count, context, lessThan);
                        const range = Range.init(pull[pull_index].from, index - 1);
                        mem.rotate(T, items[range.start..range.end], count);
                        pull[pull_index].from = index - 1 - count;
                    }
                }
            }

            // adjust block_size and buffer_size based on the values we were able to pull out
            buffer_size = buffer1.length();
            block_size = iterator.length() / buffer_size + 1;

            // the first buffer NEEDS to be large enough to tag each of the evenly sized A blocks,
            // so this was originally here to test the math for adjusting block_size above
            // assert((iterator.length() + 1)/block_size <= buffer_size);

            // now that the two internal buffers have been created, it's time to merge each A+B combination at this level of the merge sort!
            iterator.begin();
            while (!iterator.finished()) {
                A = iterator.nextRange();
                B = iterator.nextRange();

                // remove any parts of A or B that are being used by the internal buffers
                start = A.start;
                if (start == pull[0].range.start) {
                    if (pull[0].from > pull[0].to) {
                        A.start += pull[0].count;

                        // if the internal buffer takes up the entire A or B subarray, then there's nothing to merge
                        // this only happens for very small subarrays, like √4 = 2, 2 * (2 internal buffers) = 4,
                        // which also only happens when cache.len is small or 0 since it'd otherwise use MergeExternal
                        if (A.length() == 0) continue;
                    } else if (pull[0].from < pull[0].to) {
                        B.end -= pull[0].count;
                        if (B.length() == 0) continue;
                    }
                }
                if (start == pull[1].range.start) {
                    if (pull[1].from > pull[1].to) {
                        A.start += pull[1].count;
                        if (A.length() == 0) continue;
                    } else if (pull[1].from < pull[1].to) {
                        B.end -= pull[1].count;
                        if (B.length() == 0) continue;
                    }
                }

                if (lessThan(context, items[B.end - 1], items[A.start])) {
                    // the two ranges are in reverse order, so a simple rotation should fix it
                    mem.rotate(T, items[A.start..B.end], A.length());
                } else if (lessThan(context, items[A.end], items[A.end - 1])) {
                    // these two ranges weren't already in order, so we'll need to merge them!
                    var findA: usize = undefined;

                    // break the remainder of A into blocks. firstA is the uneven-sized first A block
                    var blockA = Range.init(A.start, A.end);
                    var firstA = Range.init(A.start, A.start + blockA.length() % block_size);

                    // swap the first value of each A block with the value in buffer1
                    var indexA = buffer1.start;
                    index = firstA.end;
                    while (index < blockA.end) : ({
                        indexA += 1;
                        index += block_size;
                    }) {
                        mem.swap(T, &items[indexA], &items[index]);
                    }

                    // start rolling the A blocks through the B blocks!
                    // whenever we leave an A block behind, we'll need to merge the previous A block with any B blocks that follow it, so track that information as well
                    var lastA = firstA;
                    var lastB = Range.init(0, 0);
                    var blockB = Range.init(B.start, B.start + @min(block_size, B.length()));
                    blockA.start += firstA.length();
                    indexA = buffer1.start;

                    // if the first unevenly sized A block fits into the cache, copy it there for when we go to Merge it
                    // otherwise, if the second buffer is available, block swap the contents into that
                    if (lastA.length() <= cache.len) {
                        const last_a_items = items[lastA.start..lastA.end];
                        @memcpy(cache[0..last_a_items.len], last_a_items);
                    } else if (buffer2.length() > 0) {
                        blockSwap(T, items, lastA.start, buffer2.start, lastA.length());
                    }

                    if (blockA.length() > 0) {
                        while (true) {
                            // if there's a previous B block and the first value of the minimum A block is <= the last value of the previous B block,
                            // then drop that minimum A block behind. or if there are no B blocks left then keep dropping the remaining A blocks.
                            if ((lastB.length() > 0 and !lessThan(context, items[lastB.end - 1], items[indexA])) or blockB.length() == 0) {
                                // figure out where to split the previous B block, and rotate it at the split
                                const B_split = binaryFirst(T, items, items[indexA], lastB, context, lessThan);
                                const B_remaining = lastB.end - B_split;

                                // swap the minimum A block to the beginning of the rolling A blocks
                                var minA = blockA.start;
                                findA = minA + block_size;
                                while (findA < blockA.end) : (findA += block_size) {
                                    if (lessThan(context, items[findA], items[minA])) {
                                        minA = findA;
                                    }
                                }
                                blockSwap(T, items, blockA.start, minA, block_size);

                                // swap the first item of the previous A block back with its original value, which is stored in buffer1
                                mem.swap(T, &items[blockA.start], &items[indexA]);
                                indexA += 1;

                                // locally merge the previous A block with the B values that follow it
                                // if lastA fits into the external cache we'll use that (with MergeExternal),
                                // or if the second internal buffer exists we'll use that (with MergeInternal),
                                // or failing that we'll use a strictly in-place merge algorithm (MergeInPlace)

                                if (lastA.length() <= cache.len) {
                                    mergeExternal(T, items, lastA, Range.init(lastA.end, B_split), cache[0..], context, lessThan);
                                } else if (buffer2.length() > 0) {
                                    mergeInternal(T, items, lastA, Range.init(lastA.end, B_split), buffer2, context, lessThan);
                                } else {
                                    mergeInPlace(T, items, lastA, Range.init(lastA.end, B_split), context, lessThan);
                                }

                                if (buffer2.length() > 0 or block_size <= cache.len) {
                                    // copy the previous A block into the cache or buffer2, since that's where we need it to be when we go to merge it anyway
                                    if (block_size <= cache.len) {
                                        @memcpy(cache[0..block_size], items[blockA.start..][0..block_size]);
                                    } else {
                                        blockSwap(T, items, blockA.start, buffer2.start, block_size);
                                    }

                                    // this is equivalent to rotating, but faster
                                    // the area normally taken up by the A block is either the contents of buffer2, or data we don't need anymore since we memcopied it
                                    // either way, we don't need to retain the order of those items,```
