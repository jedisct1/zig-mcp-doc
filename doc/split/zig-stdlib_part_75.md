```
}

inline fn log10_int_u8(x: u8) u32 {
    // For better performance, avoid branches by assembling the solution
    // in the bits above the low 8 bits.

    // Adding c1 to val gives 10 in the top bits for val < 10, 11 for val >= 10
    const C1: u32 = 0b11_00000000 - 10; // 758
    // Adding c2 to val gives 01 in the top bits for val < 100, 10 for val >= 100
    const C2: u32 = 0b10_00000000 - 100; // 412

    // Value of top bits:
    //            +c1  +c2  1&2
    //     0..=9   10   01   00 = 0
    //   10..=99   11   01   01 = 1
    // 100..=255   11   10   10 = 2
    return ((x + C1) & (x + C2)) >> 8;
}

inline fn less_than_5(x: u32) u32 {
    // Similar to log10u8, when adding one of these constants to val,
    // we get two possible bit patterns above the low 17 bits,
    // depending on whether val is below or above the threshold.
    const C1: u32 = 0b011_00000000000000000 - 10; // 393206
    const C2: u32 = 0b100_00000000000000000 - 100; // 524188
    const C3: u32 = 0b111_00000000000000000 - 1000; // 916504
    const C4: u32 = 0b100_00000000000000000 - 10000; // 514288

    // Value of top bits:
    //                +c1  +c2  1&2  +c3  +c4  3&4   ^
    //         0..=9  010  011  010  110  011  010  000 = 0
    //       10..=99  011  011  011  110  011  010  001 = 1
    //     100..=999  011  100  000  110  011  010  010 = 2
    //   1000..=9999  011  100  000  111  011  011  011 = 3
    // 10000..=99999  011  100  000  111  100  100  100 = 4
    return (((x + C1) & (x + C2)) ^ ((x + C3) & (x + C4))) >> 17;
}

test log10_int {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_llvm and comptime builtin.target.cpu.arch.isWasm()) return error.SkipZigTest; // TODO

    inline for (
        .{ u8, u16, u32, u64, u128, u256, u512 },
        .{ 2, 4, 9, 19, 38, 77, 154 },
    ) |T, max_exponent| {
        for (0..max_exponent + 1) |exponent_usize| {
            const exponent: std.math.Log2Int(T) = @intCast(exponent_usize);
            const power_of_ten = try std.math.powi(T, 10, exponent);

            if (exponent > 0) {
                try testing.expectEqual(exponent - 1, log10_int(power_of_ten - 9));
                try testing.expectEqual(exponent - 1, log10_int(power_of_ten - 1));
            }
            try testing.expectEqual(exponent, log10_int(power_of_ten));
            try testing.expectEqual(exponent, log10_int(power_of_ten + 1));
            try testing.expectEqual(exponent, log10_int(power_of_ten + 8));
        }
        try testing.expectEqual(max_exponent, log10_int(@as(T, std.math.maxInt(T))));
    }
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/log1pf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/log1p.c

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;

/// Returns the natural logarithm of 1 + x with greater accuracy when x is near zero.
///
/// Special Cases:
///  - log1p(+inf)  = +inf
///  - log1p(+-0)   = +-0
///  - log1p(-1)    = -inf
///  - log1p(x)     = nan if x < -1
///  - log1p(nan)   = nan
pub fn log1p(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => log1p_32(x),
        f64 => log1p_64(x),
        else => @compileError("log1p not implemented for " ++ @typeName(T)),
    };
}

fn log1p_32(x: f32) f32 {
    const ln2_hi = 6.9313812256e-01;
    const ln2_lo = 9.0580006145e-06;
    const Lg1: f32 = 0xaaaaaa.0p-24;
    const Lg2: f32 = 0xccce13.0p-25;
    const Lg3: f32 = 0x91e9ee.0p-25;
    const Lg4: f32 = 0xf89e26.0p-26;

    const u: u32 = @bitCast(x);
    const ix = u;
    var k: i32 = 1;
    var f: f32 = undefined;
    var c: f32 = undefined;

    // 1 + x < sqrt(2)+
    if (ix < 0x3ED413D0 or ix >> 31 != 0) {
        // x <= -1.0
        if (ix >= 0xBF800000) {
            // log1p(-1) = -inf
            if (x == -1.0) {
                return -math.inf(f32);
            }
            // log1p(x < -1) = nan
            else {
                return math.nan(f32);
            }
        }
        // |x| < 2^(-24)
        if ((ix << 1) < (0x33800000 << 1)) {
            // underflow if subnormal
            if (ix & 0x7F800000 == 0) {
                mem.doNotOptimizeAway(x * x);
            }
            return x;
        }
        // sqrt(2) / 2- <= 1 + x < sqrt(2)+
        if (ix <= 0xBE95F619) {
            k = 0;
            c = 0;
            f = x;
        }
    } else if (ix >= 0x7F800000) {
        return x;
    }

    if (k != 0) {
        const uf = 1 + x;
        var iu = @as(u32, @bitCast(uf));
        iu += 0x3F800000 - 0x3F3504F3;
        k = @as(i32, @intCast(iu >> 23)) - 0x7F;

        // correction to avoid underflow in c / u
        if (k < 25) {
            c = if (k >= 2) 1 - (uf - x) else x - (uf - 1);
            c /= uf;
        } else {
            c = 0;
        }

        // u into [sqrt(2)/2, sqrt(2)]
        iu = (iu & 0x007FFFFF) + 0x3F3504F3;
        f = @as(f32, @bitCast(iu)) - 1;
    }

    const s = f / (2.0 + f);
    const z = s * s;
    const w = z * z;
    const t1 = w * (Lg2 + w * Lg4);
    const t2 = z * (Lg1 + w * Lg3);
    const R = t2 + t1;
    const hfsq = 0.5 * f * f;
    const dk = @as(f32, @floatFromInt(k));

    return s * (hfsq + R) + (dk * ln2_lo + c) - hfsq + f + dk * ln2_hi;
}

fn log1p_64(x: f64) f64 {
    const ln2_hi: f64 = 6.93147180369123816490e-01;
    const ln2_lo: f64 = 1.90821492927058770002e-10;
    const Lg1: f64 = 6.666666666666735130e-01;
    const Lg2: f64 = 3.999999999940941908e-01;
    const Lg3: f64 = 2.857142874366239149e-01;
    const Lg4: f64 = 2.222219843214978396e-01;
    const Lg5: f64 = 1.818357216161805012e-01;
    const Lg6: f64 = 1.531383769920937332e-01;
    const Lg7: f64 = 1.479819860511658591e-01;

    const ix: u64 = @bitCast(x);
    const hx: u32 = @intCast(ix >> 32);
    var k: i32 = 1;
    var c: f64 = undefined;
    var f: f64 = undefined;

    // 1 + x < sqrt(2)
    if (hx < 0x3FDA827A or hx >> 31 != 0) {
        // x <= -1.0
        if (hx >= 0xBFF00000) {
            // log1p(-1) = -inf
            if (x == -1.0) {
                return -math.inf(f64);
            }
            // log1p(x < -1) = nan
            else {
                return math.nan(f64);
            }
        }
        // |x| < 2^(-53)
        if ((hx << 1) < (0x3CA00000 << 1)) {
            if ((hx & 0x7FF00000) == 0) {
                math.raiseUnderflow();
            }
            return x;
        }
        // sqrt(2) / 2- <= 1 + x < sqrt(2)+
        if (hx <= 0xBFD2BEC4) {
            k = 0;
            c = 0;
            f = x;
        }
    } else if (hx >= 0x7FF00000) {
        return x;
    }

    if (k != 0) {
        const uf = 1 + x;
        const hu = @as(u64, @bitCast(uf));
        var iu = @as(u32, @intCast(hu >> 32));
        iu += 0x3FF00000 - 0x3FE6A09E;
        k = @as(i32, @intCast(iu >> 20)) - 0x3FF;

        // correction to avoid underflow in c / u
        if (k < 54) {
            c = if (k >= 2) 1 - (uf - x) else x - (uf - 1);
            c /= uf;
        } else {
            c = 0;
        }

        // u into [sqrt(2)/2, sqrt(2)]
        iu = (iu & 0x000FFFFF) + 0x3FE6A09E;
        const iq = (@as(u64, iu) << 32) | (hu & 0xFFFFFFFF);
        f = @as(f64, @bitCast(iq)) - 1;
    }

    const hfsq = 0.5 * f * f;
    const s = f / (2.0 + f);
    const z = s * s;
    const w = z * z;
    const t1 = w * (Lg2 + w * (Lg4 + w * Lg6));
    const t2 = z * (Lg1 + w * (Lg3 + w * (Lg5 + w * Lg7)));
    const R = t2 + t1;
    const dk = @as(f64, @floatFromInt(k));

    return s * (hfsq + R) + (dk * ln2_lo + c) - hfsq + f + dk * ln2_hi;
}

test log1p {
    try expect(log1p(@as(f32, 0.0)) == log1p_32(0.0));
    try expect(log1p(@as(f64, 0.0)) == log1p_64(0.0));
}

test log1p_32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, log1p_32(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, log1p_32(0.2), 0.182322, epsilon));
    try expect(math.approxEqAbs(f32, log1p_32(0.8923), 0.637793, epsilon));
    try expect(math.approxEqAbs(f32, log1p_32(1.5), 0.916291, epsilon));
    try expect(math.approxEqAbs(f32, log1p_32(37.45), 3.649359, epsilon));
    try expect(math.approxEqAbs(f32, log1p_32(89.123), 4.501175, epsilon));
    try expect(math.approxEqAbs(f32, log1p_32(123123.234375), 11.720949, epsilon));
}

test log1p_64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, log1p_64(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, log1p_64(0.2), 0.182322, epsilon));
    try expect(math.approxEqAbs(f64, log1p_64(0.8923), 0.637793, epsilon));
    try expect(math.approxEqAbs(f64, log1p_64(1.5), 0.916291, epsilon));
    try expect(math.approxEqAbs(f64, log1p_64(37.45), 3.649359, epsilon));
    try expect(math.approxEqAbs(f64, log1p_64(89.123), 4.501175, epsilon));
    try expect(math.approxEqAbs(f64, log1p_64(123123.234375), 11.720949, epsilon));
}

test "log1p_32.special" {
    try expect(math.isPositiveInf(log1p_32(math.inf(f32))));
    try expect(math.isPositiveZero(log1p_32(0.0)));
    try expect(math.isNegativeZero(log1p_32(-0.0)));
    try expect(math.isNegativeInf(log1p_32(-1.0)));
    try expect(math.isNan(log1p_32(-2.0)));
    try expect(math.isNan(log1p_32(math.nan(f32))));
}

test "log1p_64.special" {
    try expect(math.isPositiveInf(log1p_64(math.inf(f64))));
    try expect(math.isPositiveZero(log1p_64(0.0)));
    try expect(math.isNegativeZero(log1p_64(-0.0)));
    try expect(math.isNegativeInf(log1p_64(-1.0)));
    try expect(math.isNan(log1p_64(-2.0)));
    try expect(math.isNan(log1p_64(math.nan(f64))));
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const math = std.math;
const expect = std.testing.expect;

/// Returns the base-2 logarithm of x.
///
/// Special Cases:
///  - log2(+inf)  = +inf
///  - log2(0)     = -inf
///  - log2(x)     = nan if x < 0
///  - log2(nan)   = nan
pub fn log2(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .comptime_float => {
            return @as(comptime_float, @log2(x));
        },
        .float => return @log2(x),
        .comptime_int => comptime {
            var x_shifted = x;
            // First, calculate floorPowerOfTwo(x)
            var shift_amt = 1;
            while (x_shifted >> (shift_amt << 1) != 0) shift_amt <<= 1;

            // Answer is in the range [shift_amt, 2 * shift_amt - 1]
            // We can find it in O(log(N)) using binary search.
            var result = 0;
            while (shift_amt != 0) : (shift_amt >>= 1) {
                if (x_shifted >> shift_amt != 0) {
                    x_shifted >>= shift_amt;
                    result += shift_amt;
                }
            }
            return result;
        },
        .int => |IntType| switch (IntType.signedness) {
            .signed => @compileError("log2 not implemented for signed integers"),
            .unsigned => return math.log2_int(T, x),
        },
        else => @compileError("log2 not implemented for " ++ @typeName(T)),
    }
}

test log2 {
    // https://github.com/ziglang/zig/issues/13703
    if (builtin.cpu.arch == .aarch64 and builtin.os.tag == .windows) return error.SkipZigTest;

    try expect(log2(@as(f32, 0.2)) == @log2(0.2));
    try expect(log2(@as(f64, 0.2)) == @log2(0.2));
    comptime {
        try expect(log2(1) == 0);
        try expect(log2(15) == 3);
        try expect(log2(16) == 4);
        try expect(log2(1 << 4073) == 4073);
    }
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectApproxEqAbs = std.testing.expectApproxEqAbs;

pub fn Modf(comptime T: type) type {
    return struct {
        fpart: T,
        ipart: T,
    };
}

/// Returns the integer and fractional floating-point numbers that sum to x. The sign of each
/// result is the same as the sign of x.
/// In comptime, may be used with comptime_float
///
/// Special Cases:
///  - modf(+-inf) = +-inf, nan
///  - modf(nan)   = nan, nan
pub fn modf(x: anytype) Modf(@TypeOf(x)) {
    const ipart = @trunc(x);
    return .{
        .ipart = ipart,
        .fpart = x - ipart,
    };
}

test modf {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        const epsilon: comptime_float = @max(1e-6, math.floatEps(T));

        var r: Modf(T) = undefined;

        r = modf(@as(T, 1.0));
        try expectEqual(1.0, r.ipart);
        try expectEqual(0.0, r.fpart);

        r = modf(@as(T, 0.34682));
        try expectEqual(0.0, r.ipart);
        try expectApproxEqAbs(@as(T, 0.34682), r.fpart, epsilon);

        r = modf(@as(T, 2.54576));
        try expectEqual(2.0, r.ipart);
        try expectApproxEqAbs(0.54576, r.fpart, epsilon);

        r = modf(@as(T, 3.9782));
        try expectEqual(3.0, r.ipart);
        try expectApproxEqAbs(0.9782, r.fpart, epsilon);
    }
}

/// Generate a namespace of tests for modf on values of the given type
fn ModfTests(comptime T: type) type {
    return struct {
        test "normal" {
            const epsilon: comptime_float = @max(1e-6, math.floatEps(T));
            var r: Modf(T) = undefined;

            r = modf(@as(T, 1.0));
            try expectEqual(1.0, r.ipart);
            try expectEqual(0.0, r.fpart);

            r = modf(@as(T, 0.34682));
            try expectEqual(0.0, r.ipart);
            try expectApproxEqAbs(0.34682, r.fpart, epsilon);

            r = modf(@as(T, 3.97812));
            try expectEqual(3.0, r.ipart);
            // account for precision error
            const expected_a: T = 3.97812 - @as(T, 3);
            try expectApproxEqAbs(expected_a, r.fpart, epsilon);

            r = modf(@as(T, 43874.3));
            try expectEqual(43874.0, r.ipart);
            // account for precision error
            const expected_b: T = 43874.3 - @as(T, 43874);
            try expectApproxEqAbs(expected_b, r.fpart, epsilon);

            r = modf(@as(T, 1234.340780));
            try expectEqual(1234.0, r.ipart);
            // account for precision error
            const expected_c: T = 1234.340780 - @as(T, 1234);
            try expectApproxEqAbs(expected_c, r.fpart, epsilon);
        }
        test "vector" {
            // Currently, a compiler bug is breaking the usage
            // of @trunc on @Vector types

            // TODO: Repopulate the below array and
            // remove the skip statement once this
            // bug is fixed

            // const widths = [_]comptime_int{ 1, 2, 3, 4, 8, 16 };
            const widths = [_]comptime_int{};

            if (widths.len == 0)
                return error.SkipZigTest;

            inline for (widths) |len| {
                const V: type = @Vector(len, T);
                var r: Modf(V) = undefined;

                r = modf(@as(V, @splat(1.0)));
                try expectEqual(@as(V, @splat(1.0)), r.ipart);
                try expectEqual(@as(V, @splat(0.0)), r.fpart);

                r = modf(@as(V, @splat(2.75)));
                try expectEqual(@as(V, @splat(2.0)), r.ipart);
                try expectEqual(@as(V, @splat(0.75)), r.fpart);

                r = modf(@as(V, @splat(0.2)));
                try expectEqual(@as(V, @splat(0.0)), r.ipart);
                try expectEqual(@as(V, @splat(0.2)), r.fpart);

                r = modf(std.simd.iota(T, len) + @as(V, @splat(0.5)));
                try expectEqual(std.simd.iota(T, len), r.ipart);
                try expectEqual(@as(V, @splat(0.5)), r.fpart);
            }
        }
        test "inf" {
            var r: Modf(T) = undefined;

            r = modf(math.inf(T));
            try expect(math.isPositiveInf(r.ipart) and math.isNan(r.fpart));

            r = modf(-math.inf(T));
            try expect(math.isNegativeInf(r.ipart) and math.isNan(r.fpart));
        }
        test "nan" {
            const r: Modf(T) = modf(math.nan(T));
            try expect(math.isNan(r.ipart) and math.isNan(r.fpart));
        }
    };
}

comptime {
    for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        _ = ModfTests(T);
    }
}
const std = @import("../std.zig");
const math = std.math;
const assert = std.debug.assert;
const expect = std.testing.expect;

/// Returns the next representable value after `x` in the direction of `y`.
///
/// Special cases:
///
/// - If `x == y`, `y` is returned.
/// - For floats, if either `x` or `y` is a NaN, a NaN is returned.
/// - For floats, if `x == 0.0` and `@abs(y) > 0.0`, the smallest subnormal number with the sign of
///   `y` is returned.
///
pub fn nextAfter(comptime T: type, x: T, y: T) T {
    return switch (@typeInfo(T)) {
        .int, .comptime_int => nextAfterInt(T, x, y),
        .float => nextAfterFloat(T, x, y),
        else => @compileError("expected int or non-comptime float, found '" ++ @typeName(T) ++ "'"),
    };
}

fn nextAfterInt(comptime T: type, x: T, y: T) T {
    comptime assert(@typeInfo(T) == .int or @typeInfo(T) == .comptime_int);
    return if (@typeInfo(T) == .int and @bitSizeOf(T) < 2)
        // Special case for `i0`, `u0`, `i1`, and `u1`.
        y
    else if (y > x)
        x + 1
    else if (y < x)
        x - 1
    else
        y;
}

// Based on nextafterf/nextafterl from mingw-w64 which are both public domain.
// <https://github.com/mingw-w64/mingw-w64/blob/e89de847dd3e05bb8e46344378ce3e124f4e7d1c/mingw-w64-crt/math/nextafterf.c>
// <https://github.com/mingw-w64/mingw-w64/blob/e89de847dd3e05bb8e46344378ce3e124f4e7d1c/mingw-w64-crt/math/nextafterl.c>

fn nextAfterFloat(comptime T: type, x: T, y: T) T {
    comptime assert(@typeInfo(T) == .float);
    if (x == y) {
        // Returning `y` ensures that (0.0, -0.0) returns -0.0 and that (-0.0, 0.0) returns 0.0.
        return y;
    }
    if (math.isNan(x) or math.isNan(y)) {
        return math.nan(T);
    }
    if (x == 0.0) {
        return if (y > 0.0)
            math.floatTrueMin(T)
        else
            -math.floatTrueMin(T);
    }
    if (@bitSizeOf(T) == 80) {
        // Unlike other floats, `f80` has an explicitly stored integer bit between the fractional
        // part and the exponent and thus requires special handling. This integer bit *must* be set
        // when the value is normal, an infinity or a NaN and *should* be cleared otherwise.

        const fractional_bits_mask = (1 << math.floatFractionalBits(f80)) - 1;
        const integer_bit_mask = 1 << math.floatFractionalBits(f80);
        const exponent_bits_mask = (1 << math.floatExponentBits(f80)) - 1;

        var x_parts = math.F80.fromFloat(x);

        // Bitwise increment/decrement the fractional part while also taking care to update the
        // exponent if we overflow the fractional part. This might flip the integer bit; this is
        // intentional.
        if ((x > 0.0) == (y > x)) {
            x_parts.fraction +%= 1;
            if (x_parts.fraction & fractional_bits_mask == 0) {
                x_parts.exp += 1;
            }
        } else {
            if (x_parts.fraction & fractional_bits_mask == 0) {
                x_parts.exp -= 1;
            }
            x_parts.fraction -%= 1;
        }

        // If the new value is normal or an infinity (indicated by at least one bit in the exponent
        // being set), the integer bit might have been cleared from an overflow, so we must ensure
        // that it remains set.
        if (x_parts.exp & exponent_bits_mask != 0) {
            x_parts.fraction |= integer_bit_mask;
        }
        // Otherwise, the new value is subnormal and the integer bit will have either flipped from
        // set to cleared (if the old value was normal) or remained cleared (if the old value was
        // subnormal), both of which are the outcomes we want.

        return x_parts.toFloat();
    } else {
        const Bits = std.meta.Int(.unsigned, @bitSizeOf(T));
        var x_bits: Bits = @bitCast(x);
        if ((x > 0.0) == (y > x)) {
            x_bits += 1;
        } else {
            x_bits -= 1;
        }
        return @bitCast(x_bits);
    }
}

test "int" {
    try expect(nextAfter(i0, 0, 0) == 0);
    try expect(nextAfter(u0, 0, 0) == 0);
    try expect(nextAfter(i1, 0, 0) == 0);
    try expect(nextAfter(i1, 0, -1) == -1);
    try expect(nextAfter(i1, -1, -1) == -1);
    try expect(nextAfter(i1, -1, 0) == 0);
    try expect(nextAfter(u1, 0, 0) == 0);
    try expect(nextAfter(u1, 0, 1) == 1);
    try expect(nextAfter(u1, 1, 1) == 1);
    try expect(nextAfter(u1, 1, 0) == 0);
    inline for (.{ i8, i16, i32, i64, i128, i333 }) |T| {
        try expect(nextAfter(T, 3, 7) == 4);
        try expect(nextAfter(T, 3, -7) == 2);
        try expect(nextAfter(T, -3, -7) == -4);
        try expect(nextAfter(T, -3, 7) == -2);
        try expect(nextAfter(T, 5, 5) == 5);
        try expect(nextAfter(T, -5, -5) == -5);
        try expect(nextAfter(T, 0, 0) == 0);
        try expect(nextAfter(T, math.minInt(T), math.minInt(T)) == math.minInt(T));
        try expect(nextAfter(T, math.maxInt(T), math.maxInt(T)) == math.maxInt(T));
    }
    inline for (.{ u8, u16, u32, u64, u128, u333 }) |T| {
        try expect(nextAfter(T, 3, 7) == 4);
        try expect(nextAfter(T, 7, 3) == 6);
        try expect(nextAfter(T, 5, 5) == 5);
        try expect(nextAfter(T, 0, 0) == 0);
        try expect(nextAfter(T, math.minInt(T), math.minInt(T)) == math.minInt(T));
        try expect(nextAfter(T, math.maxInt(T), math.maxInt(T)) == math.maxInt(T));
    }
    comptime {
        try expect(nextAfter(comptime_int, 3, 7) == 4);
        try expect(nextAfter(comptime_int, 3, -7) == 2);
        try expect(nextAfter(comptime_int, -3, -7) == -4);
        try expect(nextAfter(comptime_int, -3, 7) == -2);
        try expect(nextAfter(comptime_int, 5, 5) == 5);
        try expect(nextAfter(comptime_int, -5, -5) == -5);
        try expect(nextAfter(comptime_int, 0, 0) == 0);
        try expect(nextAfter(comptime_int, math.maxInt(u512), math.maxInt(u512)) == math.maxInt(u512));
    }
}

test "float" {
    @setEvalBranchQuota(4000);

    // normal -> normal
    try expect(nextAfter(f16, 0x1.234p0, 2.0) == 0x1.238p0);
    try expect(nextAfter(f16, 0x1.234p0, -2.0) == 0x1.230p0);
    try expect(nextAfter(f16, 0x1.234p0, 0x1.234p0) == 0x1.234p0);
    try expect(nextAfter(f16, -0x1.234p0, -2.0) == -0x1.238p0);
    try expect(nextAfter(f16, -0x1.234p0, 2.0) == -0x1.230p0);
    try expect(nextAfter(f16, -0x1.234p0, -0x1.234p0) == -0x1.234p0);
    try expect(nextAfter(f32, 0x1.001234p0, 2.0) == 0x1.001236p0);
    try expect(nextAfter(f32, 0x1.001234p0, -2.0) == 0x1.001232p0);
    try expect(nextAfter(f32, 0x1.001234p0, 0x1.001234p0) == 0x1.001234p0);
    try expect(nextAfter(f32, -0x1.001234p0, -2.0) == -0x1.001236p0);
    try expect(nextAfter(f32, -0x1.001234p0, 2.0) == -0x1.001232p0);
    try expect(nextAfter(f32, -0x1.001234p0, -0x1.001234p0) == -0x1.001234p0);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(nextAfter(T64, 0x1.0000000001234p0, 2.0) == 0x1.0000000001235p0);
        try expect(nextAfter(T64, 0x1.0000000001234p0, -2.0) == 0x1.0000000001233p0);
        try expect(nextAfter(T64, 0x1.0000000001234p0, 0x1.0000000001234p0) == 0x1.0000000001234p0);
        try expect(nextAfter(T64, -0x1.0000000001234p0, -2.0) == -0x1.0000000001235p0);
        try expect(nextAfter(T64, -0x1.0000000001234p0, 2.0) == -0x1.0000000001233p0);
        try expect(nextAfter(T64, -0x1.0000000001234p0, -0x1.0000000001234p0) == -0x1.0000000001234p0);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(nextAfter(T80, 0x1.0000000000001234p0, 2.0) == 0x1.0000000000001236p0);
        try expect(nextAfter(T80, 0x1.0000000000001234p0, -2.0) == 0x1.0000000000001232p0);
        try expect(nextAfter(T80, 0x1.0000000000001234p0, 0x1.0000000000001234p0) == 0x1.0000000000001234p0);
        try expect(nextAfter(T80, -0x1.0000000000001234p0, -2.0) == -0x1.0000000000001236p0);
        try expect(nextAfter(T80, -0x1.0000000000001234p0, 2.0) == -0x1.0000000000001232p0);
        try expect(nextAfter(T80, -0x1.0000000000001234p0, -0x1.0000000000001234p0) == -0x1.0000000000001234p0);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(nextAfter(T128, 0x1.0000000000000000000000001234p0, 2.0) == 0x1.0000000000000000000000001235p0);
        try expect(nextAfter(T128, 0x1.0000000000000000000000001234p0, -2.0) == 0x1.0000000000000000000000001233p0);
        try expect(nextAfter(T128, 0x1.0000000000000000000000001234p0, 0x1.0000000000000000000000001234p0) == 0x1.0000000000000000000000001234p0);
        try expect(nextAfter(T128, -0x1.0000000000000000000000001234p0, -2.0) == -0x1.0000000000000000000000001235p0);
        try expect(nextAfter(T128, -0x1.0000000000000000000000001234p0, 2.0) == -0x1.0000000000000000000000001233p0);
        try expect(nextAfter(T128, -0x1.0000000000000000000000001234p0, -0x1.0000000000000000000000001234p0) == -0x1.0000000000000000000000001234p0);
    }

    // subnormal -> subnormal
    try expect(nextAfter(f16, 0x0.234p-14, 1.0) == 0x0.238p-14);
    try expect(nextAfter(f16, 0x0.234p-14, -1.0) == 0x0.230p-14);
    try expect(nextAfter(f16, 0x0.234p-14, 0x0.234p-14) == 0x0.234p-14);
    try expect(nextAfter(f16, -0x0.234p-14, -1.0) == -0x0.238p-14);
    try expect(nextAfter(f16, -0x0.234p-14, 1.0) == -0x0.230p-14);
    try expect(nextAfter(f16, -0x0.234p-14, -0x0.234p-14) == -0x0.234p-14);
    try expect(nextAfter(f32, 0x0.001234p-126, 1.0) == 0x0.001236p-126);
    try expect(nextAfter(f32, 0x0.001234p-126, -1.0) == 0x0.001232p-126);
    try expect(nextAfter(f32, 0x0.001234p-126, 0x0.001234p-126) == 0x0.001234p-126);
    try expect(nextAfter(f32, -0x0.001234p-126, -1.0) == -0x0.001236p-126);
    try expect(nextAfter(f32, -0x0.001234p-126, 1.0) == -0x0.001232p-126);
    try expect(nextAfter(f32, -0x0.001234p-126, -0x0.001234p-126) == -0x0.001234p-126);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(nextAfter(T64, 0x0.0000000001234p-1022, 1.0) == 0x0.0000000001235p-1022);
        try expect(nextAfter(T64, 0x0.0000000001234p-1022, -1.0) == 0x0.0000000001233p-1022);
        try expect(nextAfter(T64, 0x0.0000000001234p-1022, 0x0.0000000001234p-1022) == 0x0.0000000001234p-1022);
        try expect(nextAfter(T64, -0x0.0000000001234p-1022, -1.0) == -0x0.0000000001235p-1022);
        try expect(nextAfter(T64, -0x0.0000000001234p-1022, 1.0) == -0x0.0000000001233p-1022);
        try expect(nextAfter(T64, -0x0.0000000001234p-1022, -0x0.0000000001234p-1022) == -0x0.0000000001234p-1022);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(nextAfter(T80, 0x0.0000000000001234p-16382, 1.0) == 0x0.0000000000001236p-16382);
        try expect(nextAfter(T80, 0x0.0000000000001234p-16382, -1.0) == 0x0.0000000000001232p-16382);
        try expect(nextAfter(T80, 0x0.0000000000001234p-16382, 0x0.0000000000001234p-16382) == 0x0.0000000000001234p-16382);
        try expect(nextAfter(T80, -0x0.0000000000001234p-16382, -1.0) == -0x0.0000000000001236p-16382);
        try expect(nextAfter(T80, -0x0.0000000000001234p-16382, 1.0) == -0x0.0000000000001232p-16382);
        try expect(nextAfter(T80, -0x0.0000000000001234p-16382, -0x0.0000000000001234p-16382) == -0x0.0000000000001234p-16382);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(nextAfter(T128, 0x0.0000000000000000000000001234p-16382, 1.0) == 0x0.0000000000000000000000001235p-16382);
        try expect(nextAfter(T128, 0x0.0000000000000000000000001234p-16382, -1.0) == 0x0.0000000000000000000000001233p-16382);
        try expect(nextAfter(T128, 0x0.0000000000000000000000001234p-16382, 0x0.0000000000000000000000001234p-16382) == 0x0.0000000000000000000000001234p-16382);
        try expect(nextAfter(T128, -0x0.0000000000000000000000001234p-16382, -1.0) == -0x0.0000000000000000000000001235p-16382);
        try expect(nextAfter(T128, -0x0.0000000000000000000000001234p-16382, 1.0) == -0x0.0000000000000000000000001233p-16382);
        try expect(nextAfter(T128, -0x0.0000000000000000000000001234p-16382, -0x0.0000000000000000000000001234p-16382) == -0x0.0000000000000000000000001234p-16382);
    }

    // normal -> normal (change in exponent)
    try expect(nextAfter(f16, 0x1.FFCp3, math.inf(f16)) == 0x1p4);
    try expect(nextAfter(f16, 0x1p4, -math.inf(f16)) == 0x1.FFCp3);
    try expect(nextAfter(f16, -0x1.FFCp3, -math.inf(f16)) == -0x1p4);
    try expect(nextAfter(f16, -0x1p4, math.inf(f16)) == -0x1.FFCp3);
    try expect(nextAfter(f32, 0x1.FFFFFEp3, math.inf(f32)) == 0x1p4);
    try expect(nextAfter(f32, 0x1p4, -math.inf(f32)) == 0x1.FFFFFEp3);
    try expect(nextAfter(f32, -0x1.FFFFFEp3, -math.inf(f32)) == -0x1p4);
    try expect(nextAfter(f32, -0x1p4, math.inf(f32)) == -0x1.FFFFFEp3);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(nextAfter(T64, 0x1.FFFFFFFFFFFFFp3, math.inf(T64)) == 0x1p4);
        try expect(nextAfter(T64, 0x1p4, -math.inf(T64)) == 0x1.FFFFFFFFFFFFFp3);
        try expect(nextAfter(T64, -0x1.FFFFFFFFFFFFFp3, -math.inf(T64)) == -0x1p4);
        try expect(nextAfter(T64, -0x1p4, math.inf(T64)) == -0x1.FFFFFFFFFFFFFp3);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(nextAfter(T80, 0x1.FFFFFFFFFFFFFFFEp3, math.inf(T80)) == 0x1p4);
        try expect(nextAfter(T80, 0x1p4, -math.inf(T80)) == 0x1.FFFFFFFFFFFFFFFEp3);
        try expect(nextAfter(T80, -0x1.FFFFFFFFFFFFFFFEp3, -math.inf(T80)) == -0x1p4);
        try expect(nextAfter(T80, -0x1p4, math.inf(T80)) == -0x1.FFFFFFFFFFFFFFFEp3);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(nextAfter(T128, 0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3, math.inf(T128)) == 0x1p4);
        try expect(nextAfter(T128, 0x1p4, -math.inf(T128)) == 0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3);
        try expect(nextAfter(T128, -0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3, -math.inf(T128)) == -0x1p4);
        try expect(nextAfter(T128, -0x1p4, math.inf(T128)) == -0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3);
    }

    // normal -> subnormal
    try expect(nextAfter(f16, 0x1p-14, -math.inf(f16)) == 0x0.FFCp-14);
    try expect(nextAfter(f16, -0x1p-14, math.inf(f16)) == -0x0.FFCp-14);
    try expect(nextAfter(f32, 0x1p-126, -math.inf(f32)) == 0x0.FFFFFEp-126);
    try expect(nextAfter(f32, -0x1p-126, math.inf(f32)) == -0x0.FFFFFEp-126);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(nextAfter(T64, 0x1p-1022, -math.inf(T64)) == 0x0.FFFFFFFFFFFFFp-1022);
        try expect(nextAfter(T64, -0x1p-1022, math.inf(T64)) == -0x0.FFFFFFFFFFFFFp-1022);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(nextAfter(T80, 0x1p-16382, -math.inf(T80)) == 0x0.FFFFFFFFFFFFFFFEp-16382);
        try expect(nextAfter(T80, -0x1p-16382, math.inf(T80)) == -0x0.FFFFFFFFFFFFFFFEp-16382);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(nextAfter(T128, 0x1p-16382, -math.inf(T128)) == 0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382);
        try expect(nextAfter(T128, -0x1p-16382, math.inf(T128)) == -0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382);
    }

    // subnormal -> normal
    try expect(nextAfter(f16, 0x0.FFCp-14, math.inf(f16)) == 0x1p-14);
    try expect(nextAfter(f16, -0x0.FFCp-14, -math.inf(f16)) == -0x1p-14);
    try expect(nextAfter(f32, 0x0.FFFFFEp-126, math.inf(f32)) == 0x1p-126);
    try expect(nextAfter(f32, -0x0.FFFFFEp-126, -math.inf(f32)) == -0x1p-126);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(nextAfter(T64, 0x0.FFFFFFFFFFFFFp-1022, math.inf(T64)) == 0x1p-1022);
        try expect(nextAfter(T64, -0x0.FFFFFFFFFFFFFp-1022, -math.inf(T64)) == -0x1p-1022);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(nextAfter(T80, 0x0.FFFFFFFFFFFFFFFEp-16382, math.inf(T80)) == 0x1p-16382);
        try expect(nextAfter(T80, -0x0.FFFFFFFFFFFFFFFEp-16382, -math.inf(T80)) == -0x1p-16382);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(nextAfter(T128, 0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382, math.inf(T128)) == 0x1p-16382);
        try expect(nextAfter(T128, -0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382, -math.inf(T128)) == -0x1p-16382);
    }

    // special values
    inline for (.{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        try expect(bitwiseEqual(T, nextAfter(T, 0.0, 0.0), 0.0));
        try expect(bitwiseEqual(T, nextAfter(T, 0.0, -0.0), -0.0));
        try expect(bitwiseEqual(T, nextAfter(T, -0.0, -0.0), -0.0));
        try expect(bitwiseEqual(T, nextAfter(T, -0.0, 0.0), 0.0));
        try expect(nextAfter(T, 0.0, math.inf(T)) == math.floatTrueMin(T));
        try expect(nextAfter(T, 0.0, -math.inf(T)) == -math.floatTrueMin(T));
        try expect(nextAfter(T, -0.0, -math.inf(T)) == -math.floatTrueMin(T));
        try expect(nextAfter(T, -0.0, math.inf(T)) == math.floatTrueMin(T));
        try expect(bitwiseEqual(T, nextAfter(T, math.floatTrueMin(T), 0.0), 0.0));
        try expect(bitwiseEqual(T, nextAfter(T, math.floatTrueMin(T), -0.0), 0.0));
        try expect(bitwiseEqual(T, nextAfter(T, math.floatTrueMin(T), -math.inf(T)), 0.0));
        try expect(bitwiseEqual(T, nextAfter(T, -math.floatTrueMin(T), -0.0), -0.0));
        try expect(bitwiseEqual(T, nextAfter(T, -math.floatTrueMin(T), 0.0), -0.0));
        try expect(bitwiseEqual(T, nextAfter(T, -math.floatTrueMin(T), math.inf(T)), -0.0));
        try expect(nextAfter(T, math.inf(T), math.inf(T)) == math.inf(T));
        try expect(nextAfter(T, math.inf(T), -math.inf(T)) == math.floatMax(T));
        try expect(nextAfter(T, math.floatMax(T), math.inf(T)) == math.inf(T));
        try expect(nextAfter(T, -math.inf(T), -math.inf(T)) == -math.inf(T));
        try expect(nextAfter(T, -math.inf(T), math.inf(T)) == -math.floatMax(T));
        try expect(nextAfter(T, -math.floatMax(T), -math.inf(T)) == -math.inf(T));
        try expect(math.isNan(nextAfter(T, 1.0, math.nan(T))));
        try expect(math.isNan(nextAfter(T, math.nan(T), 1.0)));
        try expect(math.isNan(nextAfter(T, math.nan(T), math.nan(T))));
        try expect(math.isNan(nextAfter(T, math.inf(T), math.nan(T))));
        try expect(math.isNan(nextAfter(T, -math.inf(T), math.nan(T))));
        try expect(math.isNan(nextAfter(T, math.nan(T), math.inf(T))));
        try expect(math.isNan(nextAfter(T, math.nan(T), -math.inf(T))));
    }
}

/// Helps ensure that 0.0 doesn't compare equal to -0.0.
fn bitwiseEqual(comptime T: type, x: T, y: T) bool {
    comptime assert(@typeInfo(T) == .float);
    const Bits = std.meta.Int(.unsigned, @bitSizeOf(T));
    return @as(Bits, @bitCast(x)) == @as(Bits, @bitCast(y));
}
// Ported from go, which is licensed under a BSD-3 license.
// https://golang.org/LICENSE
//
// https://golang.org/src/math/pow.go

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns x raised to the power of y (x^y).
///
/// Special Cases:
///  - pow(x, +-0)    = 1 for any x
///  - pow(1, y)      = 1 for any y
///  - pow(x, 1)      = x for any x
///  - pow(nan, y)    = nan
///  - pow(x, nan)    = nan
///  - pow(+-0, y)    = +-inf for y an odd integer < 0
///  - pow(+-0, -inf) = +inf
///  - pow(+-0, +inf) = +0
///  - pow(+-0, y)    = +inf for finite y < 0 and not an odd integer
///  - pow(+-0, y)    = +-0 for y an odd integer > 0
///  - pow(+-0, y)    = +0 for finite y > 0 and not an odd integer
///  - pow(-1, +-inf) = 1
///  - pow(x, +inf)   = +inf for |x| > 1
///  - pow(x, -inf)   = +0 for |x| > 1
///  - pow(x, +inf)   = +0 for |x| < 1
///  - pow(x, -inf)   = +inf for |x| < 1
///  - pow(+inf, y)   = +inf for y > 0
///  - pow(+inf, y)   = +0 for y < 0
///  - pow(-inf, y)   = pow(-0, -y)
///  - pow(x, y)      = nan for finite x < 0 and finite non-integer y
pub fn pow(comptime T: type, x: T, y: T) T {
    if (@typeInfo(T) == .int) {
        return math.powi(T, x, y) catch unreachable;
    }

    if (T != f32 and T != f64) {
        @compileError("pow not implemented for " ++ @typeName(T));
    }

    // pow(x, +-0) = 1      for all x
    // pow(1, y) = 1        for all y
    if (y == 0 or x == 1) {
        return 1;
    }

    // pow(nan, y) = nan    for all y
    // pow(x, nan) = nan    for all x
    if (math.isNan(x) or math.isNan(y)) {
        @branchHint(.unlikely);
        return math.nan(T);
    }

    // pow(x, 1) = x        for all x
    if (y == 1) {
        return x;
    }

    if (x == 0) {
        if (y < 0) {
            // pow(+-0, y) = +-inf  for y an odd integer
            if (isOddInteger(y)) {
                return math.copysign(math.inf(T), x);
            }
            // pow(+-0, y) = +inf   for y an even integer
            else {
                return math.inf(T);
            }
        } else {
            if (isOddInteger(y)) {
                return x;
            } else {
                return 0;
            }
        }
    }

    if (math.isInf(y)) {
        // pow(-1, inf) = 1     for all x
        if (x == -1) {
            return 1.0;
        }
        // pow(x, +inf) = +0    for |x| < 1
        // pow(x, -inf) = +0    for |x| > 1
        else if ((@abs(x) < 1) == math.isPositiveInf(y)) {
            return 0;
        }
        // pow(x, -inf) = +inf  for |x| < 1
        // pow(x, +inf) = +inf  for |x| > 1
        else {
            return math.inf(T);
        }
    }

    if (math.isInf(x)) {
        if (math.isNegativeInf(x)) {
            return pow(T, 1 / x, -y);
        }
        // pow(+inf, y) = +0    for y < 0
        else if (y < 0) {
            return 0;
        }
        // pow(+inf, y) = +0    for y > 0
        else if (y > 0) {
            return math.inf(T);
        }
    }

    // special case sqrt
    if (y == 0.5) {
        return @sqrt(x);
    }

    if (y == -0.5) {
        return 1 / @sqrt(x);
    }

    const r1 = math.modf(@abs(y));
    var yi = r1.ipart;
    var yf = r1.fpart;

    if (yf != 0 and x < 0) {
        return math.nan(T);
    }
    if (yi >= 1 << (@typeInfo(T).float.bits - 1)) {
        return @exp(y * @log(x));
    }

    // a = a1 * 2^ae
    var a1: T = 1.0;
    var ae: i32 = 0;

    // a *= x^yf
    if (yf != 0) {
        if (yf > 0.5) {
            yf -= 1;
            yi += 1;
        }
        a1 = @exp(yf * @log(x));
    }

    // a *= x^yi
    const r2 = math.frexp(x);
    var xe = r2.exponent;
    var x1 = r2.significand;

    var i = @as(std.meta.Int(.signed, @typeInfo(T).float.bits), @intFromFloat(yi));
    while (i != 0) : (i >>= 1) {
        const overflow_shift = math.floatExponentBits(T) + 1;
        if (xe < -(1 << overflow_shift) or (1 << overflow_shift) < xe) {
            // catch xe before it overflows the left shift below
            // Since i != 0 it has at least one bit still set, so ae will accumulate xe
            // on at least one more iteration, ae += xe is a lower bound on ae
            // the lower bound on ae exceeds the size of a float exp
            // so the final call to Ldexp will produce under/overflow (0/Inf)
            ae += xe;
            break;
        }
        if (i & 1 == 1) {
            a1 *= x1;
            ae += xe;
        }
        x1 *= x1;
        xe <<= 1;
        if (x1 < 0.5) {
            x1 += x1;
            xe -= 1;
        }
    }

    // a *= a1 * 2^ae
    if (y < 0) {
        a1 = 1 / a1;
        ae = -ae;
    }

    return math.scalbn(a1, ae);
}

fn isOddInteger(x: f64) bool {
    if (@abs(x) >= 1 << 53) {
        // From https://golang.org/src/math/pow.go
        // 1 << 53 is the largest exact integer in the float64 format.
        // Any number outside this range will be truncated before the decimal point and therefore will always be
        // an even integer.
        // Without this check and if x overflows i64 the @intFromFloat(r.ipart) conversion below will panic
        return false;
    }
    const r = math.modf(x);
    return r.fpart == 0.0 and @as(i64, @intFromFloat(r.ipart)) & 1 == 1;
}

test isOddInteger {
    try expect(isOddInteger(math.maxInt(i64) * 2) == false);
    try expect(isOddInteger(math.maxInt(i64) * 2 + 1) == false);
    try expect(isOddInteger(1 << 53) == false);
    try expect(isOddInteger(12.0) == false);
    try expect(isOddInteger(15.0) == true);
}

test pow {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, pow(f32, 0.0, 3.3), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, pow(f32, 0.8923, 3.3), 0.686572, epsilon));
    try expect(math.approxEqAbs(f32, pow(f32, 0.2, 3.3), 0.004936, epsilon));
    try expect(math.approxEqAbs(f32, pow(f32, 1.5, 3.3), 3.811546, epsilon));
    try expect(math.approxEqAbs(f32, pow(f32, 37.45, 3.3), 155736.703125, epsilon));
    try expect(math.approxEqAbs(f32, pow(f32, 89.123, 3.3), 2722489.5, epsilon));

    try expect(math.approxEqAbs(f64, pow(f64, 0.0, 3.3), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, pow(f64, 0.8923, 3.3), 0.686572, epsilon));
    try expect(math.approxEqAbs(f64, pow(f64, 0.2, 3.3), 0.004936, epsilon));
    try expect(math.approxEqAbs(f64, pow(f64, 1.5, 3.3), 3.811546, epsilon));
    try expect(math.approxEqAbs(f64, pow(f64, 37.45, 3.3), 155736.7160616, epsilon));
    try expect(math.approxEqAbs(f64, pow(f64, 89.123, 3.3), 2722490.231436, epsilon));
}

test "special" {
    const epsilon = 0.000001;

    try expect(pow(f32, 4, 0.0) == 1.0);
    try expect(pow(f32, 7, -0.0) == 1.0);
    try expect(pow(f32, 45, 1.0) == 45);
    try expect(pow(f32, -45, 1.0) == -45);
    try expect(math.isNan(pow(f32, math.nan(f32), 5.0)));
    try expect(math.isPositiveInf(pow(f32, -math.inf(f32), 0.5)));
    try expect(math.isPositiveInf(pow(f32, -0.0, -0.5)));
    try expect(pow(f32, -0.0, 0.5) == 0);
    try expect(math.isNan(pow(f32, 5.0, math.nan(f32))));
    try expect(math.isPositiveInf(pow(f32, 0.0, -1.0)));
    //expect(math.isNegativeInf(pow(f32, -0.0, -3.0))); TODO is this required?
    try expect(math.isPositiveInf(pow(f32, 0.0, -math.inf(f32))));
    try expect(math.isPositiveInf(pow(f32, -0.0, -math.inf(f32))));
    try expect(pow(f32, 0.0, math.inf(f32)) == 0.0);
    try expect(pow(f32, -0.0, math.inf(f32)) == 0.0);
    try expect(math.isPositiveInf(pow(f32, 0.0, -2.0)));
    try expect(math.isPositiveInf(pow(f32, -0.0, -2.0)));
    try expect(pow(f32, 0.0, 1.0) == 0.0);
    try expect(pow(f32, -0.0, 1.0) == -0.0);
    try expect(pow(f32, 0.0, 2.0) == 0.0);
    try expect(pow(f32, -0.0, 2.0) == 0.0);
    try expect(math.approxEqAbs(f32, pow(f32, -1.0, math.inf(f32)), 1.0, epsilon));
    try expect(math.approxEqAbs(f32, pow(f32, -1.0, -math.inf(f32)), 1.0, epsilon));
    try expect(math.isPositiveInf(pow(f32, 1.2, math.inf(f32))));
    try expect(math.isPositiveInf(pow(f32, -1.2, math.inf(f32))));
    try expect(pow(f32, 1.2, -math.inf(f32)) == 0.0);
    try expect(pow(f32, -1.2, -math.inf(f32)) == 0.0);
    try expect(pow(f32, 0.2, math.inf(f32)) == 0.0);
    try expect(pow(f32, -0.2, math.inf(f32)) == 0.0);
    try expect(math.isPositiveInf(pow(f32, 0.2, -math.inf(f32))));
    try expect(math.isPositiveInf(pow(f32, -0.2, -math.inf(f32))));
    try expect(math.isPositiveInf(pow(f32, math.inf(f32), 1.0)));
    try expect(pow(f32, math.inf(f32), -1.0) == 0.0);
    //expect(pow(f32, -math.inf(f32), 5.0) == pow(f32, -0.0, -5.0)); TODO support negative 0?
    try expect(pow(f32, -math.inf(f32), -5.2) == pow(f32, -0.0, 5.2));
    try expect(math.isNan(pow(f32, -1.0, 1.2)));
    try expect(math.isNan(pow(f32, -12.4, 78.5)));
}

test "overflow" {
    try expect(math.isPositiveInf(pow(f64, 2, 1 << 32)));
    try expect(pow(f64, 2, -(1 << 32)) == 0);
    try expect(math.isNegativeInf(pow(f64, -2, (1 << 32) + 1)));
    try expect(pow(f64, 0.5, 1 << 45) == 0);
    try expect(math.isPositiveInf(pow(f64, 0.5, -(1 << 45))));
}
// Based on Rust, which is licensed under the MIT license.
// https://github.com/rust-lang/rust/blob/360432f1e8794de58cd94f34c9c17ad65871e5b5/LICENSE-MIT
//
// https://github.com/rust-lang/rust/blob/360432f1e8794de58cd94f34c9c17ad65871e5b5/src/libcore/num/mod.rs#L3423

const std = @import("../std.zig");
const math = std.math;
const assert = std.debug.assert;
const testing = std.testing;

/// Returns the power of x raised by the integer y (x^y).
///
/// Errors:
///  - Overflow: Integer overflow or Infinity
///  - Underflow: Absolute value of result smaller than 1
/// Edge case rules ordered by precedence:
///  - powi(T, x, 0)   = 1 unless T is i1, i0, u0
///  - powi(T, 0, x)   = 0 when x > 0
///  - powi(T, 0, x)   = Overflow
///  - powi(T, 1, y)   = 1
///  - powi(T, -1, y)  = -1 for y an odd integer
///  - powi(T, -1, y)  = 1 unless T is i1, i0, u0
///  - powi(T, -1, y)  = Overflow
///  - powi(T, x, y)   = Overflow when y >= @bitSizeOf(x)
///  - powi(T, x, y)   = Underflow when y < 0
pub fn powi(comptime T: type, x: T, y: T) (error{
    Overflow,
    Underflow,
}!T) {
    const bit_size = @typeInfo(T).int.bits;

    // `y & 1 == 0` won't compile when `does_one_overflow`.
    const does_one_overflow = math.maxInt(T) < 1;
    const is_y_even = !does_one_overflow and y & 1 == 0;

    if (x == 1 or y == 0 or (x == -1 and is_y_even)) {
        if (does_one_overflow) {
            return error.Overflow;
        } else {
            return 1;
        }
    }

    if (x == -1) {
        return -1;
    }

    if (x == 0) {
        if (y > 0) {
            return 0;
        } else {
            // Infinity/NaN, not overflow in strict sense
            return error.Overflow;
        }
    }
    // x >= 2 or x <= -2 from this point
    if (y >= bit_size) {
        return error.Overflow;
    }
    if (y < 0) {
        return error.Underflow;
    }

    // invariant :
    // return value = powi(T, base, exp) * acc;

    var base = x;
    var exp = y;
    var acc: T = if (does_one_overflow) unreachable else 1;

    while (exp > 1) {
        if (exp & 1 == 1) {
            const ov = @mulWithOverflow(acc, base);
            if (ov[1] != 0) return error.Overflow;
            acc = ov[0];
        }

        exp >>= 1;

        const ov = @mulWithOverflow(base, base);
        if (ov[1] != 0) return error.Overflow;
        base = ov[0];
    }

    if (exp == 1) {
        const ov = @mulWithOverflow(acc, base);
        if (ov[1] != 0) return error.Overflow;
        acc = ov[0];
    }

    return acc;
}

test powi {
    try testing.expectError(error.Overflow, powi(i8, -66, 6));
    try testing.expectError(error.Overflow, powi(i16, -13, 13));
    try testing.expectError(error.Overflow, powi(i32, -32, 21));
    try testing.expectError(error.Overflow, powi(i64, -24, 61));
    try testing.expectError(error.Overflow, powi(i17, -15, 15));
    try testing.expectError(error.Overflow, powi(i42, -6, 40));

    try testing.expect((try powi(i8, -5, 3)) == -125);
    try testing.expect((try powi(i16, -16, 3)) == -4096);
    try testing.expect((try powi(i32, -91, 3)) == -753571);
    try testing.expect((try powi(i64, -36, 6)) == 2176782336);
    try testing.expect((try powi(i17, -2, 15)) == -32768);
    try testing.expect((try powi(i42, -5, 7)) == -78125);

    try testing.expect((try powi(u8, 6, 2)) == 36);
    try testing.expect((try powi(u16, 5, 4)) == 625);
    try testing.expect((try powi(u32, 12, 6)) == 2985984);
    try testing.expect((try powi(u64, 34, 2)) == 1156);
    try testing.expect((try powi(u17, 16, 3)) == 4096);
    try testing.expect((try powi(u42, 34, 6)) == 1544804416);

    try testing.expectError(error.Overflow, powi(i8, 120, 7));
    try testing.expectError(error.Overflow, powi(i16, 73, 15));
    try testing.expectError(error.Overflow, powi(i32, 23, 31));
    try testing.expectError(error.Overflow, powi(i64, 68, 61));
    try testing.expectError(error.Overflow, powi(i17, 15, 15));
    try testing.expectError(error.Overflow, powi(i42, 121312, 41));

    try testing.expectError(error.Overflow, powi(u8, 123, 7));
    try testing.expectError(error.Overflow, powi(u16, 2313, 15));
    try testing.expectError(error.Overflow, powi(u32, 8968, 31));
    try testing.expectError(error.Overflow, powi(u64, 2342, 63));
    try testing.expectError(error.Overflow, powi(u17, 2723, 16));
    try testing.expectError(error.Overflow, powi(u42, 8234, 41));

    const minInt = std.math.minInt;
    try testing.expect((try powi(i8, -2, 7)) == minInt(i8));
    try testing.expect((try powi(i16, -2, 15)) == minInt(i16));
    try testing.expect((try powi(i32, -2, 31)) == minInt(i32));
    try testing.expect((try powi(i64, -2, 63)) == minInt(i64));

    try testing.expectError(error.Underflow, powi(i8, 6, -2));
    try testing.expectError(error.Underflow, powi(i16, 5, -4));
    try testing.expectError(error.Underflow, powi(i32, 12, -6));
    try testing.expectError(error.Underflow, powi(i64, 34, -2));
    try testing.expectError(error.Underflow, powi(i17, 16, -3));
    try testing.expectError(error.Underflow, powi(i42, 34, -6));
}

test "powi.special" {
    try testing.expectError(error.Overflow, powi(i8, -2, 8));
    try testing.expectError(error.Overflow, powi(i16, -2, 16));
    try testing.expectError(error.Overflow, powi(i32, -2, 32));
    try testing.expectError(error.Overflow, powi(i64, -2, 64));
    try testing.expectError(error.Overflow, powi(i17, -2, 17));
    try testing.expectError(error.Overflow, powi(i17, -2, 16));
    try testing.expectError(error.Overflow, powi(i42, -2, 42));

    try testing.expect((try powi(i8, -1, 3)) == -1);
    try testing.expect((try powi(i16, -1, 2)) == 1);
    try testing.expect((try powi(i32, -1, 16)) == 1);
    try testing.expect((try powi(i64, -1, 6)) == 1);
    try testing.expect((try powi(i17, -1, 15)) == -1);
    try testing.expect((try powi(i42, -1, 7)) == -1);

    try testing.expect((try powi(u8, 1, 2)) == 1);
    try testing.expect((try powi(u16, 1, 4)) == 1);
    try testing.expect((try powi(u32, 1, 6)) == 1);
    try testing.expect((try powi(u64, 1, 2)) == 1);
    try testing.expect((try powi(u17, 1, 3)) == 1);
    try testing.expect((try powi(u42, 1, 6)) == 1);

    try testing.expectError(error.Overflow, powi(i8, 2, 7));
    try testing.expectError(error.Overflow, powi(i16, 2, 15));
    try testing.expectError(error.Overflow, powi(i32, 2, 31));
    try testing.expectError(error.Overflow, powi(i64, 2, 63));
    try testing.expectError(error.Overflow, powi(i17, 2, 16));
    try testing.expectError(error.Overflow, powi(i42, 2, 41));

    try testing.expectError(error.Overflow, powi(u8, 2, 8));
    try testing.expectError(error.Overflow, powi(u16, 2, 16));
    try testing.expectError(error.Overflow, powi(u32, 2, 32));
    try testing.expectError(error.Overflow, powi(u64, 2, 64));
    try testing.expectError(error.Overflow, powi(u17, 2, 17));
    try testing.expectError(error.Overflow, powi(u42, 2, 42));

    try testing.expect((try powi(u8, 6, 0)) == 1);
    try testing.expect((try powi(u16, 5, 0)) == 1);
    try testing.expect((try powi(u32, 12, 0)) == 1);
    try testing.expect((try powi(u64, 34, 0)) == 1);
    try testing.expect((try powi(u17, 16, 0)) == 1);
    try testing.expect((try powi(u42, 34, 0)) == 1);
}

test "powi.narrow" {
    try testing.expectError(error.Overflow, powi(u0, 0, 0));
    try testing.expectError(error.Overflow, powi(i0, 0, 0));
    try testing.expectError(error.Overflow, powi(i1, 0, 0));
    try testing.expectError(error.Overflow, powi(i1, -1, 0));
    try testing.expectError(error.Overflow, powi(i1, 0, -1));
    try testing.expect((try powi(i1, -1, -1)) == -1);
}
const std = @import("std");
const expect = std.testing.expect;

/// Returns a * FLT_RADIX ^ exp.
///
/// Zig only supports binary base IEEE-754 floats. Hence FLT_RADIX=2, and this is an alias for ldexp.
pub const scalbn = @import("ldexp.zig").ldexp;

test scalbn {
    // Verify we are using base 2.
    try expect(scalbn(@as(f16, 1.5), 4) == 24.0);
    try expect(scalbn(@as(f32, 1.5), 4) == 24.0);
    try expect(scalbn(@as(f64, 1.5), 4) == 24.0);
    try expect(scalbn(@as(f128, 1.5), 4) == 24.0);
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is negative or negative 0.
pub fn signbit(x: anytype) bool {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).float.bits);
    return @as(TBits, @bitCast(x)) >> (@bitSizeOf(T) - 1) != 0;
}

test signbit {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(!signbit(@as(T, 0.0)));
        try expect(!signbit(@as(T, 1.0)));
        try expect(signbit(@as(T, -2.0)));
        try expect(signbit(@as(T, -0.0)));
        try expect(!signbit(math.inf(T)));
        try expect(signbit(-math.inf(T)));
        try expect(!signbit(math.nan(T)));
        try expect(signbit(-math.nan(T)));
    }
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/sinhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/sinh.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const expo2 = @import("expo2.zig").expo2;
const maxInt = std.math.maxInt;

/// Returns the hyperbolic sine of x.
///
/// Special Cases:
///  - sinh(+-0)   = +-0
///  - sinh(+-inf) = +-inf
///  - sinh(nan)   = nan
pub fn sinh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => sinh32(x),
        f64 => sinh64(x),
        else => @compileError("sinh not implemented for " ++ @typeName(T)),
    };
}

// sinh(x) = (exp(x) - 1 / exp(x)) / 2
//         = (exp(x) - 1 + (exp(x) - 1) / exp(x)) / 2
//         = x + x^3 / 6 + o(x^5)
fn sinh32(x: f32) f32 {
    const u = @as(u32, @bitCast(x));
    const ux = u & 0x7FFFFFFF;
    const ax = @as(f32, @bitCast(ux));

    if (x == 0.0 or math.isNan(x)) {
        return x;
    }

    var h: f32 = 0.5;
    if (u >> 31 != 0) {
        h = -h;
    }

    // |x| < log(FLT_MAX)
    if (ux < 0x42B17217) {
        const t = math.expm1(ax);
        if (ux < 0x3F800000) {
            if (ux < 0x3F800000 - (12 << 23)) {
                return x;
            } else {
                return h * (2 * t - t * t / (t + 1));
            }
        }
        return h * (t + t / (t + 1));
    }

    // |x| > log(FLT_MAX) or nan
    return 2 * h * expo2(ax);
}

fn sinh64(x: f64) f64 {
    const u = @as(u64, @bitCast(x));
    const w = @as(u32, @intCast(u >> 32)) & (maxInt(u32) >> 1);
    const ax = @as(f64, @bitCast(u & (maxInt(u64) >> 1)));

    if (x == 0.0 or math.isNan(x)) {
        return x;
    }

    var h: f32 = 0.5;
    if (u >> 63 != 0) {
        h = -h;
    }

    // |x| < log(FLT_MAX)
    if (w < 0x40862E42) {
        const t = math.expm1(ax);
        if (w < 0x3FF00000) {
            if (w < 0x3FF00000 - (26 << 20)) {
                return x;
            } else {
                return h * (2 * t - t * t / (t + 1));
            }
        }
        // NOTE: |x| > log(0x1p26) + eps could be h * exp(x)
        return h * (t + t / (t + 1));
    }

    // |x| > log(DBL_MAX) or nan
    return 2 * h * expo2(ax);
}

test sinh {
    try expect(sinh(@as(f32, 1.5)) == sinh32(1.5));
    try expect(sinh(@as(f64, 1.5)) == sinh64(1.5));
}

test sinh32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, sinh32(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, sinh32(0.2), 0.201336, epsilon));
    try expect(math.approxEqAbs(f32, sinh32(0.8923), 1.015512, epsilon));
    try expect(math.approxEqAbs(f32, sinh32(1.5), 2.129279, epsilon));
    try expect(math.approxEqAbs(f32, sinh32(-0.0), -0.0, epsilon));
    try expect(math.approxEqAbs(f32, sinh32(-0.2), -0.201336, epsilon));
    try expect(math.approxEqAbs(f32, sinh32(-0.8923), -1.015512, epsilon));
    try expect(math.approxEqAbs(f32, sinh32(-1.5), -2.129279, epsilon));
}

test sinh64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, sinh64(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, sinh64(0.2), 0.201336, epsilon));
    try expect(math.approxEqAbs(f64, sinh64(0.8923), 1.015512, epsilon));
    try expect(math.approxEqAbs(f64, sinh64(1.5), 2.129279, epsilon));
    try expect(math.approxEqAbs(f64, sinh64(-0.0), -0.0, epsilon));
    try expect(math.approxEqAbs(f64, sinh64(-0.2), -0.201336, epsilon));
    try expect(math.approxEqAbs(f64, sinh64(-0.8923), -1.015512, epsilon));
    try expect(math.approxEqAbs(f64, sinh64(-1.5), -2.129279, epsilon));
}

test "sinh32.special" {
    try expect(math.isPositiveZero(sinh32(0.0)));
    try expect(math.isNegativeZero(sinh32(-0.0)));
    try expect(math.isPositiveInf(sinh32(math.inf(f32))));
    try expect(math.isNegativeInf(sinh32(-math.inf(f32))));
    try expect(math.isNan(sinh32(math.nan(f32))));
}

test "sinh64.special" {
    try expect(math.isPositiveZero(sinh64(0.0)));
    try expect(math.isNegativeZero(sinh64(-0.0)));
    try expect(math.isPositiveInf(sinh64(math.inf(f64))));
    try expect(math.isNegativeInf(sinh64(-math.inf(f64))));
    try expect(math.isNan(sinh64(math.nan(f64))));
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const TypeId = std.builtin.TypeId;
const maxInt = std.math.maxInt;

/// Returns the square root of x.
///
/// Special Cases:
///  - sqrt(+inf)  = +inf
///  - sqrt(+-0)   = +-0
///  - sqrt(x)     = nan if x < 0
///  - sqrt(nan)   = nan
/// TODO Decide if all this logic should be implemented directly in the @sqrt builtin function.
pub fn sqrt(x: anytype) Sqrt(@TypeOf(x)) {
    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .float, .comptime_float => return @sqrt(x),
        .comptime_int => comptime {
            if (x > maxInt(u128)) {
                @compileError("sqrt not implemented for comptime_int greater than 128 bits");
            }
            if (x < 0) {
                @compileError("sqrt on negative number");
            }
            return @as(T, sqrt_int(u128, x));
        },
        .int => |IntType| switch (IntType.signedness) {
            .signed => @compileError("sqrt not implemented for signed integers"),
            .unsigned => return sqrt_int(T, x),
        },
        else => @compileError("sqrt not implemented for " ++ @typeName(T)),
    }
}

fn sqrt_int(comptime T: type, value: T) Sqrt(T) {
    if (@typeInfo(T).int.bits <= 2) {
        return if (value == 0) 0 else 1; // shortcut for small number of bits to simplify general case
    } else {
        const bits = @typeInfo(T).int.bits;
        const max = math.maxInt(T);
        const minustwo = (@as(T, 2) ^ max) + 1; // unsigned int cannot represent -2
        var op = value;
        var res: T = 0;
        var one: T = 1 << ((bits - 1) & minustwo); // highest power of four that fits into T

        // "one" starts at the highest power of four <= than the argument.
        while (one > op) {
            one >>= 2;
        }

        while (one != 0) {
            const c = op >= res + one;
            if (c) op -= res + one;
            res >>= 1;
            if (c) res += one;
            one >>= 2;
        }

        return @as(Sqrt(T), @intCast(res));
    }
}

test sqrt_int {
    try expect(sqrt_int(u32, 3) == 1);
    try expect(sqrt_int(u32, 4) == 2);
    try expect(sqrt_int(u32, 5) == 2);
    try expect(sqrt_int(u32, 8) == 2);
    try expect(sqrt_int(u32, 9) == 3);
    try expect(sqrt_int(u32, 10) == 3);

    try expect(sqrt_int(u0, 0) == 0);
    try expect(sqrt_int(u1, 1) == 1);
    try expect(sqrt_int(u2, 3) == 1);
    try expect(sqrt_int(u3, 4) == 2);
    try expect(sqrt_int(u4, 8) == 2);
    try expect(sqrt_int(u4, 9) == 3);
}

/// Returns the return type `sqrt` will return given an operand of type `T`.
pub fn Sqrt(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .int => |int| @Type(.{ .int = .{ .signedness = .unsigned, .bits = (int.bits + 1) / 2 } }),
        else => T,
    };
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/tanhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/tanh.c

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;
const expo2 = @import("expo2.zig").expo2;
const maxInt = std.math.maxInt;

/// Returns the hyperbolic tangent of x.
///
/// Special Cases:
///  - tanh(+-0)   = +-0
///  - tanh(+-inf) = +-1
///  - tanh(nan)   = nan
pub fn tanh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => tanh32(x),
        f64 => tanh64(x),
        else => @compileError("tanh not implemented for " ++ @typeName(T)),
    };
}

// tanh(x) = (exp(x) - exp(-x)) / (exp(x) + exp(-x))
//         = (exp(2x) - 1) / (exp(2x) - 1 + 2)
//         = (1 - exp(-2x)) / (exp(-2x) - 1 + 2)
fn tanh32(x: f32) f32 {
    const u = @as(u32, @bitCast(x));
    const ux = u & 0x7FFFFFFF;
    const ax = @as(f32, @bitCast(ux));
    const sign = (u >> 31) != 0;

    var t: f32 = undefined;

    // |x| < log(3) / 2 ~= 0.5493 or nan
    if (ux > 0x3F0C9F54) {
        // |x| > 10
        if (ux > 0x41200000) {
            t = 1.0 + 0 / x;
        } else {
            t = math.expm1(2 * ax);
            t = 1 - 2 / (t + 2);
        }
    }
    // |x| > log(5 / 3) / 2 ~= 0.2554
    else if (ux > 0x3E82C578) {
        t = math.expm1(2 * ax);
        t = t / (t + 2);
    }
    // |x| >= 0x1.0p-126
    else if (ux >= 0x00800000) {
        t = math.expm1(-2 * ax);
        t = -t / (t + 2);
    }
    // |x| is subnormal
    else {
        mem.doNotOptimizeAway(ax * ax);
        t = ax;
    }

    return if (sign) -t else t;
}

fn tanh64(x: f64) f64 {
    const u = @as(u64, @bitCast(x));
    const ux = u & 0x7FFFFFFFFFFFFFFF;
    const w = @as(u32, @intCast(ux >> 32));
    const ax = @as(f64, @bitCast(ux));
    const sign = (u >> 63) != 0;

    var t: f64 = undefined;

    // |x| < log(3) / 2 ~= 0.5493 or nan
    if (w > 0x3FE193EA) {
        // |x| > 20 or nan
        if (w > 0x40340000) {
            t = 1.0 - 0 / ax;
        } else {
            t = math.expm1(2 * ax);
            t = 1 - 2 / (t + 2);
        }
    }
    // |x| > log(5 / 3) / 2 ~= 0.2554
    else if (w > 0x3FD058AE) {
        t = math.expm1(2 * ax);
        t = t / (t + 2);
    }
    // |x| >= 0x1.0p-1022
    else if (w >= 0x00100000) {
        t = math.expm1(-2 * ax);
        t = -t / (t + 2);
    }
    // |x| is subnormal
    else {
        mem.doNotOptimizeAway(@as(f32, @floatCast(ax)));
        t = ax;
    }

    return if (sign) -t else t;
}

test tanh {
    try expect(tanh(@as(f32, 1.5)) == tanh32(1.5));
    try expect(tanh(@as(f64, 1.5)) == tanh64(1.5));
}

test tanh32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, tanh32(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, tanh32(0.2), 0.197375, epsilon));
    try expect(math.approxEqAbs(f32, tanh32(0.8923), 0.712528, epsilon));
    try expect(math.approxEqAbs(f32, tanh32(1.5), 0.905148, epsilon));
    try expect(math.approxEqAbs(f32, tanh32(37.45), 1.0, epsilon));
    try expect(math.approxEqAbs(f32, tanh32(-0.8923), -0.712528, epsilon));
    try expect(math.approxEqAbs(f32, tanh32(-1.5), -0.905148, epsilon));
    try expect(math.approxEqAbs(f32, tanh32(-37.45), -1.0, epsilon));
}

test tanh64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, tanh64(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, tanh64(0.2), 0.197375, epsilon));
    try expect(math.approxEqAbs(f64, tanh64(0.8923), 0.712528, epsilon));
    try expect(math.approxEqAbs(f64, tanh64(1.5), 0.905148, epsilon));
    try expect(math.approxEqAbs(f64, tanh64(37.45), 1.0, epsilon));
    try expect(math.approxEqAbs(f64, tanh64(-0.8923), -0.712528, epsilon));
    try expect(math.approxEqAbs(f64, tanh64(-1.5), -0.905148, epsilon));
    try expect(math.approxEqAbs(f64, tanh64(-37.45), -1.0, epsilon));
}

test "tanh32.special" {
    try expect(math.isPositiveZero(tanh32(0.0)));
    try expect(math.isNegativeZero(tanh32(-0.0)));
    try expect(tanh32(math.inf(f32)) == 1.0);
    try expect(tanh32(-math.inf(f32)) == -1.0);
    try expect(math.isNan(tanh32(math.nan(f32))));
}

test "tanh64.special" {
    try expect(math.isPositiveZero(tanh64(0.0)));
    try expect(math.isNegativeZero(tanh64(-0.0)));
    try expect(tanh64(math.inf(f64)) == 1.0);
    try expect(tanh64(-math.inf(f64)) == -1.0);
    try expect(math.isNan(tanh64(math.nan(f64))));
}
const std = @import("std.zig");
const builtin = @import("builtin");
const debug = std.debug;
const assert = debug.assert;
const math = std.math;
const mem = @This();
const testing = std.testing;
const Endian = std.builtin.Endian;
const native_endian = builtin.cpu.arch.endian();

/// The standard library currently thoroughly depends on byte size
/// being 8 bits.  (see the use of u8 throughout allocation code as
/// the "byte" type.)  Code which depends on this can reference this
/// declaration.  If we ever try to port the standard library to a
/// non-8-bit-byte platform, this will allow us to search for things
/// which need to be updated.
pub const byte_size_in_bits = 8;

pub const Allocator = @import("mem/Allocator.zig");

/// Stored as a power-of-two.
pub const Alignment = enum(math.Log2Int(usize)) {
    @"1" = 0,
    @"2" = 1,
    @"4" = 2,
    @"8" = 3,
    @"16" = 4,
    @"32" = 5,
    @"64" = 6,
    _,

    pub fn toByteUnits(a: Alignment) usize {
        return @as(usize, 1) << @intFromEnum(a);
    }

    pub fn fromByteUnits(n: usize) Alignment {
        assert(std.math.isPowerOfTwo(n));
        return @enumFromInt(@ctz(n));
    }

    pub inline fn of(comptime T: type) Alignment {
        return comptime fromByteUnits(@alignOf(T));
    }

    pub fn order(lhs: Alignment, rhs: Alignment) std.math.Order {
        return std.math.order(@intFromEnum(lhs), @intFromEnum(rhs));
    }

    pub fn compare(lhs: Alignment, op: std.math.CompareOperator, rhs: Alignment) bool {
        return std.math.compare(@intFromEnum(lhs), op, @intFromEnum(rhs));
    }

    pub fn max(lhs: Alignment, rhs: Alignment) Alignment {
        return @enumFromInt(@max(@intFromEnum(lhs), @intFromEnum(rhs)));
    }

    pub fn min(lhs: Alignment, rhs: Alignment) Alignment {
        return @enumFromInt(@min(@intFromEnum(lhs), @intFromEnum(rhs)));
    }

    /// Return next address with this alignment.
    pub fn forward(a: Alignment, address: usize) usize {
        const x = (@as(usize, 1) << @intFromEnum(a)) - 1;
        return (address + x) & ~x;
    }

    /// Return previous address with this alignment.
    pub fn backward(a: Alignment, address: usize) usize {
        const x = (@as(usize, 1) << @intFromEnum(a)) - 1;
        return address & ~x;
    }

    /// Return whether address is aligned to this amount.
    pub fn check(a: Alignment, address: usize) bool {
        return @ctz(address) >= @intFromEnum(a);
    }
};

/// Detects and asserts if the std.mem.Allocator interface is violated by the caller
/// or the allocator.
pub fn ValidationAllocator(comptime T: type) type {
    return struct {
        const Self = @This();

        underlying_allocator: T,

        pub fn init(underlying_allocator: T) @This() {
            return .{
                .underlying_allocator = underlying_allocator,
            };
        }

        pub fn allocator(self: *Self) Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn getUnderlyingAllocatorPtr(self: *Self) Allocator {
            if (T == Allocator) return self.underlying_allocator;
            return self.underlying_allocator.allocator();
        }

        pub fn alloc(
            ctx: *anyopaque,
            n: usize,
            alignment: mem.Alignment,
            ret_addr: usize,
        ) ?[*]u8 {
            assert(n > 0);
            const self: *Self = @ptrCast(@alignCast(ctx));
            const underlying = self.getUnderlyingAllocatorPtr();
            const result = underlying.rawAlloc(n, alignment, ret_addr) orelse
                return null;
            assert(alignment.check(@intFromPtr(result)));
            return result;
        }

        pub fn resize(
            ctx: *anyopaque,
            buf: []u8,
            alignment: Alignment,
            new_len: usize,
            ret_addr: usize,
        ) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            assert(buf.len > 0);
            const underlying = self.getUnderlyingAllocatorPtr();
            return underlying.rawResize(buf, alignment, new_len, ret_addr);
        }

        pub fn remap(
            ctx: *anyopaque,
            buf: []u8,
            alignment: Alignment,
            new_len: usize,
            ret_addr: usize,
        ) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            assert(buf.len > 0);
            const underlying = self.getUnderlyingAllocatorPtr();
            return underlying.rawRemap(buf, alignment, new_len, ret_addr);
        }

        pub fn free(
            ctx: *anyopaque,
            buf: []u8,
            alignment: Alignment,
            ret_addr: usize,
        ) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            assert(buf.len > 0);
            const underlying = self.getUnderlyingAllocatorPtr();
            underlying.rawFree(buf, alignment, ret_addr);
        }

        pub fn reset(self: *Self) void {
            self.underlying_allocator.reset();
        }
    };
}

pub fn validationWrap(allocator: anytype) ValidationAllocator(@TypeOf(allocator)) {
    return ValidationAllocator(@TypeOf(allocator)).init(allocator);
}

test "Allocator basics" {
    try testing.expectError(error.OutOfMemory, testing.failing_allocator.alloc(u8, 1));
    try testing.expectError(error.OutOfMemory, testing.failing_allocator.allocSentinel(u8, 1, 0));
}

test "Allocator.resize" {
    const primitiveIntTypes = .{
        i8,
        u8,
        i16,
        u16,
        i32,
        u32,
        i64,
        u64,
        i128,
        u128,
        isize,
        usize,
    };
    inline for (primitiveIntTypes) |T| {
        var values = try testing.allocator.alloc(T, 100);
        defer testing.allocator.free(values);

        for (values, 0..) |*v, i| v.* = @as(T, @intCast(i));
        if (!testing.allocator.resize(values, values.len + 10)) return error.OutOfMemory;
        values = values.ptr[0 .. values.len + 10];
        try testing.expect(values.len == 110);
    }

    const primitiveFloatTypes = .{
        f16,
        f32,
        f64,
        f128,
    };
    inline for (primitiveFloatTypes) |T| {
        var values = try testing.allocator.alloc(T, 100);
        defer testing.allocator.free(values);

        for (values, 0..) |*v, i| v.* = @as(T, @floatFromInt(i));
        if (!testing.allocator.resize(values, values.len + 10)) return error.OutOfMemory;
        values = values.ptr[0 .. values.len + 10];
        try testing.expect(values.len == 110);
    }
}

test "Allocator alloc and remap with zero-bit type" {
    var values = try testing.allocator.alloc(void, 10);
    defer testing.allocator.free(values);

    try testing.expectEqual(10, values.len);
    const remaped = testing.allocator.remap(values, 200);
    try testing.expect(remaped != null);

    values = remaped.?;
    try testing.expectEqual(200, values.len);
}

/// Copy all of source into dest at position 0.
/// dest.len must be >= source.len.
/// If the slices overlap, dest.ptr must be <= src.ptr.
/// This function is deprecated; use @memmove instead.
pub fn copyForwards(comptime T: type, dest: []T, source: []const T) void {
    for (dest[0..source.len], source) |*d, s| d.* = s;
}

/// Copy all of source into dest at position 0.
/// dest.len must be >= source.len.
/// If the slices overlap, dest.ptr must be >= src.ptr.
/// This function is deprecated; use @memmove instead.
pub fn copyBackwards(comptime T: type, dest: []T, source: []const T) void {
    // TODO instead of manually doing this check for the whole array
    // and turning off runtime safety, the compiler should detect loops like
    // this and automatically omit safety checks for loops
    @setRuntimeSafety(false);
    assert(dest.len >= source.len);
    var i = source.len;
    while (i > 0) {
        i -= 1;
        dest[i] = source[i];
    }
}

/// Generally, Zig users are encouraged to explicitly initialize all fields of a struct explicitly rather than using this function.
/// However, it is recognized that there are sometimes use cases for initializing all fields to a "zero" value. For example, when
/// interfacing with a C API where this practice is more common and relied upon. If you are performing code review and see this
/// function used, examine closely - it may be a code smell.
/// Zero initializes the type.
/// This can be used to zero-initialize any type for which it makes sense. Structs will be initialized recursively.
pub fn zeroes(comptime T: type) T {
    switch (@typeInfo(T)) {
        .comptime_int, .int, .comptime_float, .float => {
            return @as(T, 0);
        },
        .@"enum" => {
            return @as(T, @enumFromInt(0));
        },
        .void => {
            return {};
        },
        .bool => {
            return false;
        },
        .optional, .null => {
            return null;
        },
        .@"struct" => |struct_info| {
            if (@sizeOf(T) == 0) return undefined;
            if (struct_info.layout == .@"extern") {
                var item: T = undefined;
                @memset(asBytes(&item), 0);
                return item;
            } else {
                var structure: T = undefined;
                inline for (struct_info.fields) |field| {
                    if (!field.is_comptime) {
                        @field(structure, field.name) = zeroes(field.type);
                    }
                }
                return structure;
            }
        },
        .pointer => |ptr_info| {
            switch (ptr_info.size) {
                .slice => {
                    if (ptr_info.sentinel()) |sentinel| {
                        if (ptr_info.child == u8 and sentinel == 0) {
                            return ""; // A special case for the most common use-case: null-terminated strings.
                        }
                        @compileError("Can't set a sentinel slice to zero. This would require allocating memory.");
                    } else {
                        return &[_]ptr_info.child{};
                    }
                },
                .c => {
                    return null;
                },
                .one, .many => {
                    if (ptr_info.is_allowzero) return @ptrFromInt(0);
                    @compileError("Only nullable and allowzero pointers can be set to zero.");
                },
            }
        },
        .array => |info| {
            return @splat(zeroes(info.child));
        },
        .vector => |info| {
            return @splat(zeroes(info.child));
        },
        .@"union" => |info| {
            if (info.layout == .@"extern") {
                var item: T = undefined;
                @memset(asBytes(&item), 0);
                return item;
            }
            @compileError("Can't set a " ++ @typeName(T) ++ " to zero.");
        },
        .enum_literal,
        .error_union,
        .error_set,
        .@"fn",
        .type,
        .noreturn,
        .undefined,
        .@"opaque",
        .frame,
        .@"anyframe",
        => {
            @compileError("Can't set a " ++ @typeName(T) ++ " to zero.");
        },
    }
}

test zeroes {
    const C_struct = extern struct {
        x: u32,
        y: u32 align(128),
    };

    var a = zeroes(C_struct);

    // Extern structs should have padding zeroed out.
    try testing.expectEqualSlices(u8, &[_]u8{0} ** @sizeOf(@TypeOf(a)), asBytes(&a));

    a.y += 10;

    try testing.expect(a.x == 0);
    try testing.expect(a.y == 10);

    const ZigStruct = struct {
        comptime comptime_field: u8 = 5,

        integral_types: struct {
            integer_0: i0,
            integer_8: i8,
            integer_16: i16,
            integer_32: i32,
            integer_64: i64,
            integer_128: i128,
            unsigned_0: u0,
            unsigned_8: u8,
            unsigned_16: u16,
            unsigned_32: u32,
            unsigned_64: u64,
            unsigned_128: u128,

            float_32: f32,
            float_64: f64,
        },

        pointers: struct {
            optional: ?*u8,
            c_pointer: [*c]u8,
            slice: []u8,
            nullTerminatedString: [:0]const u8,
        },

        array: [2]u32,
        vector_u32: @Vector(2, u32),
        vector_f32: @Vector(2, f32),
        vector_bool: @Vector(2, bool),
        optional_int: ?u8,
        empty: void,
        sentinel: [3:0]u8,
    };

    const b = zeroes(ZigStruct);
    try testing.expectEqual(@as(u8, 5), b.comptime_field);
    try testing.expectEqual(@as(i8, 0), b.integral_types.integer_0);
    try testing.expectEqual(@as(i8, 0), b.integral_types.integer_8);
    try testing.expectEqual(@as(i16, 0), b.integral_types.integer_16);
    try testing.expectEqual(@as(i32, 0), b.integral_types.integer_32);
    try testing.expectEqual(@as(i64, 0), b.integral_types.integer_64);
    try testing.expectEqual(@as(i128, 0), b.integral_types.integer_128);
    try testing.expectEqual(@as(u8, 0), b.integral_types.unsigned_0);
    try testing.expectEqual(@as(u8, 0), b.integral_types.unsigned_8);
    try testing.expectEqual(@as(u16, 0), b.integral_types.unsigned_16);
    try testing.expectEqual(@as(u32, 0), b.integral_types.unsigned_32);
    try testing.expectEqual(@as(u64, 0), b.integral_types.unsigned_64);
    try testing.expectEqual(@as(u128, 0), b.integral_types.unsigned_128);
    try testing.expectEqual(@as(f32, 0), b.integral_types.float_32);
    try testing.expectEqual(@as(f64, 0), b.integral_types.float_64);
    try testing.expectEqual(@as(?*u8, null), b.pointers.optional);
    try testing.expectEqual(@as([*c]u8, null), b.pointers.c_pointer);
    try testing.expectEqual(@as([]u8, &[_]u8{}), b.pointers.slice);
    try testing.expectEqual(@as([:0]const u8, ""), b.pointers.nullTerminatedString);
    for (b.array) |e| {
        try testing.expectEqual(@as(u32, 0), e);
    }
    try testing.expectEqual(@as(@TypeOf(b.vector_u32), @splat(0)), b.vector_u32);
    try testing.expectEqual(@as(@TypeOf(b.vector_f32), @splat(0.0)), b.vector_f32);
    if (!(builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .hexagon)) {
        try testing.expectEqual(@as(@TypeOf(b.vector_bool), @splat(false)), b.vector_bool);
    }
    try testing.expectEqual(@as(?u8, null), b.optional_int);
    for (b.sentinel) |e| {
        try testing.expectEqual(@as(u8, 0), e);
    }

    const C_union = extern union {
        a: u8,
        b: u32,
    };

    const c = zeroes(C_union);
    try testing.expectEqual(@as(u8, 0), c.a);
    try testing.expectEqual(@as(u32, 0), c.b);

    const comptime_union = comptime zeroes(C_union);
    try testing.expectEqual(@as(u8, 0), comptime_union.a);
    try testing.expectEqual(@as(u32, 0), comptime_union.b);

    // Ensure zero sized struct with fields is initialized correctly.
    _ = zeroes(struct { handle: void });
}

/// Initializes all fields of the struct with their default value, or zero values if no default value is present.
/// If the field is present in the provided initial values, it will have that value instead.
/// Structs are initialized recursively.
pub fn zeroInit(comptime T: type, init: anytype) T {
    const Init = @TypeOf(init);

    switch (@typeInfo(T)) {
        .@"struct" => |struct_info| {
            switch (@typeInfo(Init)) {
                .@"struct" => |init_info| {
                    if (init_info.is_tuple) {
                        if (init_info.fields.len > struct_info.fields.len) {
                            @compileError("Tuple initializer has more elements than there are fields in `" ++ @typeName(T) ++ "`");
                        }
                    } else {
                        inline for (init_info.fields) |field| {
                            if (!@hasField(T, field.name)) {
                                @compileError("Encountered an initializer for `" ++ field.name ++ "`, but it is not a field of " ++ @typeName(T));
                            }
                        }
                    }

                    var value: T = if (struct_info.layout == .@"extern") zeroes(T) else undefined;

                    inline for (struct_info.fields, 0..) |field, i| {
                        if (field.is_comptime) {
                            continue;
                        }

                        if (init_info.is_tuple and init_info.fields.len > i) {
                            @field(value, field.name) = @field(init, init_info.fields[i].name);
                        } else if (@hasField(@TypeOf(init), field.name)) {
                            switch (@typeInfo(field.type)) {
                                .@"struct" => {
                                    @field(value, field.name) = zeroInit(field.type, @field(init, field.name));
                                },
                                else => {
                                    @field(value, field.name) = @field(init, field.name);
                                },
                            }
                        } else if (field.defaultValue()) |val| {
                            @field(value, field.name) = val;
                        } else {
                            switch (@typeInfo(field.type)) {
                                .@"struct" => {
                                    @field(value, field.name) = std.mem.zeroInit(field.type, .{});
                                },
                                else => {
                                    @field(value, field.name) = std.mem.zeroes(@TypeOf(@field(value, field.name)));
                                },
                            }
                        }
                    }

                    return value;
                },
                else => {
                    @compileError("The initializer must be a struct");
                },
            }
        },
        else => {
            @compileError("Can't default init a " ++ @typeName(T));
        },
    }
}

test zeroInit {
    const I = struct {
        d: f64,
    };

    const S = struct {
        a: u32,
        b: ?bool,
        c: I,
        e: [3]u8,
        f: i64 = -1,
    };

    const s = zeroInit(S, .{
        .a = 42,
    });

    try testing.expectEqual(S{
        .a = 42,
        .b = null,
        .c = .{
            .d = 0,
        },
        .e = [3]u8{ 0, 0, 0 },
        .f = -1,
    }, s);

    const Color = struct {
        r: u8,
        g: u8,
        b: u8,
        a: u8,
    };

    const c = zeroInit(Color, .{ 255, 255 });
    try testing.expectEqual(Color{
        .r = 255,
        .g = 255,
        .b = 0,
        .a = 0,
    }, c);

    const Foo = struct {
        foo: u8 = 69,
        bar: u8,
    };

    const f = zeroInit(Foo, .{});
    try testing.expectEqual(Foo{
        .foo = 69,
        .bar = 0,
    }, f);

    const Bar = struct {
        foo: u32 = 666,
        bar: u32 = 420,
    };

    const b = zeroInit(Bar, .{69});
    try testing.expectEqual(Bar{
        .foo = 69,
        .bar = 420,
    }, b);

    const Baz = struct {
        foo: [:0]const u8 = "bar",
    };

    const baz1 = zeroInit(Baz, .{});
    try testing.expectEqual(Baz{}, baz1);

    const baz2 = zeroInit(Baz, .{ .foo = "zab" });
    try testing.expectEqualSlices(u8, "zab", baz2.foo);

    const NestedBaz = struct {
        bbb: Baz,
    };
    const nested_baz = zeroInit(NestedBaz, .{});
    try testing.expectEqual(NestedBaz{
        .bbb = Baz{},
    }, nested_baz);
}

pub fn sort(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    std.sort.block(T, items, context, lessThanFn);
}

pub fn sortUnstable(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    std.sort.pdq(T, items, context, lessThanFn);
}

/// TODO: currently this just calls `insertionSortContext`. The block sort implementation
/// in this file needs to be adapted to use the sort context.
pub fn sortContext(a: usize, b: usize, context: anytype) void {
    std.sort.insertionContext(a, b, context);
}

pub fn sortUnstableContext(a: usize, b: usize, context: anytype) void {
    std.sort.pdqContext(a, b, context);
}

/// Compares two slices of numbers lexicographically. O(n).
pub fn order(comptime T: type, lhs: []const T, rhs: []const T) math.Order {
    const n = @min(lhs.len, rhs.len);
    for (lhs[0..n], rhs[0..n]) |lhs_elem, rhs_elem| {
        switch (math.order(lhs_elem, rhs_elem)) {
            .eq => continue,
            .lt => return .lt,
            .gt => return .gt,
        }
    }
    return math.order(lhs.len, rhs.len);
}

/// Compares two many-item pointers with NUL-termination lexicographically.
pub fn orderZ(comptime T: type, lhs: [*:0]const T, rhs: [*:0]const T) math.Order {
    var i: usize = 0;
    while (lhs[i] == rhs[i] and lhs[i] != 0) : (i += 1) {}
    return math.order(lhs[i], rhs[i]);
}

test order {
    try testing.expect(order(u8, "abcd", "bee") == .lt);
    try testing.expect(order(u8, "abc", "abc") == .eq);
    try testing.expect(order(u8, "abc", "abc0") == .lt);
    try testing.expect(order(u8, "", "") == .eq);
    try testing.expect(order(u8, "", "a") == .lt);
}

test orderZ {
    try testing.expect(orderZ(u8, "abcd", "bee") == .lt);
    try testing.expect(orderZ(u8, "abc", "abc") == .eq);
    try testing.expect(orderZ(u8, "abc", "abc0") == .lt);
    try testing.expect(orderZ(u8, "", "") == .eq);
    try testing.expect(orderZ(u8, "", "a") == .lt);
}

/// Returns true if lhs < rhs, false otherwise
pub fn lessThan(comptime T: type, lhs: []const T, rhs: []const T) bool {
    return order(T, lhs, rhs) == .lt;
}

test lessThan {
    try testing.expect(lessThan(u8, "abcd", "bee"));
    try testing.expect(!lessThan(u8, "abc", "abc"));
    try testing.expect(lessThan(u8, "abc", "abc0"));
    try testing.expect(!lessThan(u8, "", ""));
    try testing.expect(lessThan(u8, "", "a"));
}

const eqlBytes_allowed = switch (builtin.zig_backend) {
    // The SPIR-V backend does not support the optimized path yet.
    .stage2_spirv64 => false,
    // The RISC-V does not support vectors.
    .stage2_riscv64 => false,
    // The naive memory comparison implementation is more useful for fuzzers to
    // find interesting inputs.
    else => !builtin.fuzz,
};

/// Returns true if and only if the slices have the same length and all elements
/// compare true using equality operator.
pub fn eql(comptime T: type, a: []const T, b: []const T) bool {
    if (!@inComptime() and @sizeOf(T) != 0 and std.meta.hasUniqueRepresentation(T) and
        eqlBytes_allowed)
    {
        return eqlBytes(sliceAsBytes(a), sliceAsBytes(b));
    }

    if (a.len != b.len) return false;
    if (a.len == 0 or a.ptr == b.ptr) return true;

    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}

test eql {
    try testing.expect(eql(u8, "abcd", "abcd"));
    try testing.expect(!eql(u8, "abcdef", "abZdef"));
    try testing.expect(!eql(u8, "abcdefg", "abcdef"));

    comptime {
        try testing.expect(eql(type, &.{ bool, f32 }, &.{ bool, f32 }));
        try testing.expect(!eql(type, &.{ bool, f32 }, &.{ f32, bool }));
        try testing.expect(!eql(type, &.{ bool, f32 }, &.{bool}));

        try testing.expect(eql(comptime_int, &.{ 1, 2, 3 }, &.{ 1, 2, 3 }));
        try testing.expect(!eql(comptime_int, &.{ 1, 2, 3 }, &.{ 3, 2, 1 }));
        try testing.expect(!eql(comptime_int, &.{1}, &.{ 1, 2 }));
    }

    try testing.expect(eql(void, &.{ {}, {} }, &.{ {}, {} }));
    try testing.expect(!eql(void, &.{{}}, &.{ {}, {} }));
}

/// std.mem.eql heavily optimized for slices of bytes.
fn eqlBytes(a: []const u8, b: []const u8) bool {
    comptime assert(eqlBytes_allowed);

    if (a.len != b.len) return false;
    if (a.len == 0 or a.ptr == b.ptr) return true;

    if (a.len <= 16) {
        if (a.len < 4) {
            const x = (a[0] ^ b[0]) | (a[a.len - 1] ^ b[a.len - 1]) | (a[a.len / 2] ^ b[a.len / 2]);
            return x == 0;
        }
        var x: u32 = 0;
        for ([_]usize{ 0, a.len - 4, (a.len / 8) * 4, a.len - 4 - ((a.len / 8) * 4) }) |n| {
            x |= @as(u32, @bitCast(a[n..][0..4].*)) ^ @as(u32, @bitCast(b[n..][0..4].*));
        }
        return x == 0;
    }

    // Figure out the fastest way to scan through the input in chunks.
    // Uses vectors when supported and falls back to usize/words when not.
    const Scan = if (std.simd.suggestVectorLength(u8)) |vec_size|
        struct {
            pub const size = vec_size;
            pub const Chunk = @Vector(size, u8);
            pub inline fn isNotEqual(chunk_a: Chunk, chunk_b: Chunk) bool {
                return @reduce(.Or, chunk_a != chunk_b);
            }
        }
    else
        struct {
            pub const size = @sizeOf(usize);
            pub const Chunk = usize;
            pub inline fn isNotEqual(chunk_a: Chunk, chunk_b: Chunk) bool {
                return chunk_a != chunk_b;
            }
        };

    inline for (1..6) |s| {
        const n = 16 << s;
        if (n <= Scan.size and a.len <= n) {
            const V = @Vector(n / 2, u8);
            var x = @as(V, a[0 .. n / 2].*) ^ @as(V, b[0 .. n / 2].*);
            x |= @as(V, a[a.len - n / 2 ..][0 .. n / 2].*) ^ @as(V, b[a.len - n / 2 ..][0 .. n / 2].*);
            const zero: V = @splat(0);
            return !@reduce(.Or, x != zero);
        }
    }
    // Compare inputs in chunks at a time (excluding the last chunk).
    for (0..(a.len - 1) / Scan.size) |i| {
        const a_chunk: Scan.Chunk = @bitCast(a[i * Scan.size ..][0..Scan.size].*);
        const b_chunk: Scan.Chunk = @bitCast(b[i * Scan.size ..][0..Scan.size].*);
        if (Scan.isNotEqual(a_chunk, b_chunk)) return false;
    }

    // Compare the last chunk using an overlapping read (similar to the previous size strategies).
    const last_a_chunk: Scan.Chunk = @bitCast(a[a.len - Scan.size ..][0..Scan.size].*);
    const last_b_chunk: Scan.Chunk = @bitCast(b[a.len - Scan.size ..][0..Scan.size].*);
    return !Scan.isNotEqual(last_a_chunk, last_b_chunk);
}

/// Compares two slices and returns the index of the first inequality.
/// Returns null if the slices are equal.
pub fn indexOfDiff(comptime T: type, a: []const T, b: []const T) ?usize {
    const shortest = @min(a.len, b.len);
    if (a.ptr == b.ptr)
        return if (a.len == b.len) null else shortest;
    var index: usize = 0;
    while (index < shortest) : (index += 1) if (a[index] != b[index]) return index;
    return if (a.len == b.len) null else shortest;
}

test indexOfDiff {
    try testing.expectEqual(indexOfDiff(u8, "one", "one"), null);
    try testing.expectEqual(indexOfDiff(u8, "one two", "one"), 3);
    try testing.expectEqual(indexOfDiff(u8, "one", "one two"), 3);
    try testing.expectEqual(indexOfDiff(u8, "one twx", "one two"), 6);
    try testing.expectEqual(indexOfDiff(u8, "xne", "one"), 0);
}

/// Takes a sentinel-terminated pointer and returns a slice preserving pointer attributes.
/// `[*c]` pointers are assumed to be 0-terminated and assumed to not be allowzero.
fn Span(comptime T: type) type {
    switch (@typeInfo(T)) {
        .optional => |optional_info| {
            return ?Span(optional_info.child);
        },
        .pointer => |ptr_info| {
            var new_ptr_info = ptr_info;
            switch (ptr_info.size) {
                .c => {
                    new_ptr_info.sentinel_ptr = &@as(ptr_info.child, 0);
                    new_ptr_info.is_allowzero = false;
                },
                .many => if (ptr_info.sentinel() == null) @compileError("invalid type given to std.mem.span: " ++ @typeName(T)),
                .one, .slice => @compileError("invalid type given to std.mem.span: " ++ @typeName(T)),
            }
            new_ptr_info.size = .slice;
            return @Type(.{ .pointer = new_ptr_info });
        },
        else => {},
    }
    @compileError("invalid type given to std.mem.span: " ++ @typeName(T));
}

test Span {
    try testing.expect(Span([*:1]u16) == [:1]u16);
    try testing.expect(Span(?[*:1]u16) == ?[:1]u16);
    try testing.expect(Span([*:1]const u8) == [:1]const u8);
    try testing.expect(Span(?[*:1]const u8) == ?[:1]const u8);
    try testing.expect(Span([*c]u16) == [:0]u16);
    try testing.expect(Span(?[*c]u16) == ?[:0]u16);
    try testing.expect(Span([*c]const u8) == [:0]const u8);
    try testing.expect(Span(?[*c]const u8) == ?[:0]const u8);
}

/// Takes a sentinel-terminated pointer and returns a slice, iterating over the
/// memory to find the sentinel and determine the length.
/// Pointer attributes such as const are preserved.
/// `[*c]` pointers are assumed to be non-null and 0-terminated.
pub fn span(ptr: anytype) Span(@TypeOf(ptr)) {
    if (@typeInfo(@TypeOf(ptr)) == .optional) {
        if (ptr) |non_null| {
            return span(non_null);
        } else {
            return null;
        }
    }
    const Result = Span(@TypeOf(ptr));
    const l = len(ptr);
    const ptr_info = @typeInfo(Result).pointer;
    if (ptr_info.sentinel()) |s| {
        return ptr[0..l :s];
    } else {
        return ptr[0..l];
    }
}

test span {
    var array: [5]u16 = [_]u16{ 1, 2, 3, 4, 5 };
    const ptr = @as([*:3]u16, array[0..2 :3]);
    try testing.expect(eql(u16, span(ptr), &[_]u16{ 1, 2 }));
    try testing.expectEqual(@as(?[:0]u16, null), span(@as(?[*:0]u16, null)));
}

/// Helper for the return type of sliceTo()
fn SliceTo(comptime T: type, comptime end: std.meta.Elem(T)) type {
    switch (@typeInfo(T)) {
        .optional => |optional_info| {
            return ?SliceTo(optional_info.child, end);
        },
        .pointer => |ptr_info| {
            var new_ptr_info = ptr_info;
            new_ptr_info.size = .slice;
            switch (ptr_info.size) {
                .one => switch (@typeInfo(ptr_info.child)) {
                    .array => |array_info| {
                        new_ptr_info.child = array_info.child;
                        // The return type must only be sentinel terminated if we are guaranteed
                        // to find the value searched for, which is only the case if it matches
                        // the sentinel of the type passed.
                        if (array_info.sentinel()) |s| {
                            if (end == s) {
                                new_ptr_info.sentinel_ptr = &end;
                            } else {
                                new_ptr_info.sentinel_ptr = null;
                            }
                        }
                    },
                    else => {},
                },
                .many, .slice => {
                    // The return type must only be sentinel terminated if we are guaranteed
                    // to find the value searched for, which is only the case if it matches
                    // the sentinel of the type passed.
                    if (ptr_info.sentinel()) |s| {
                        if (end == s) {
                            new_ptr_info.sentinel_ptr = &end;
                        } else {
                            new_ptr_info.sentinel_ptr = null;
                        }
                    }
                },
                .c => {
                    new_ptr_info.sentinel_ptr = &end;
                    // C pointers are always allowzero, but we don't want the return type to be.
                    assert(new_ptr_info.is_allowzero);
                    new_ptr_info.is_allowzero = false;
                },
            }
            return @Type(.{ .pointer = new_ptr_info });
        },
        else => {},
    }
    @compileError("invalid type given to std.mem.sliceTo: " ++ @typeName(T));
}

/// Takes a pointer to an array, a sentinel-terminated pointer, or a slice and iterates searching for
/// the first occurrence of `end`, returning the scanned slice.
/// If `end` is not found, the full length of the array/slice/sentinel terminated pointer is returned.
/// If the pointer type is sentinel terminated and `end` matches that terminator, the
/// resulting slice is also sentinel terminated.
/// Pointer properties such as mutability and alignment are preserved.
/// C pointers are assumed to be non-null.
pub fn sliceTo(ptr: anytype, comptime end: std.meta.Elem(@TypeOf(ptr))) SliceTo(@TypeOf(ptr), end) {
    if (@typeInfo(@TypeOf(ptr)) == .optional) {
        const non_null = ptr orelse return null;
        return sliceTo(non_null, end);
    }
    const Result = SliceTo(@TypeOf(ptr), end);
    const length = lenSliceTo(ptr, end);
    const ptr_info = @typeInfo(Result).pointer;
    if (ptr_info.sentinel()) |s| {
        return ptr[0..length :s];
    } else {
        return ptr[0..length];
    }
}

test sliceTo {
    try testing.expectEqualSlices(u8, "aoeu", sliceTo("aoeu", 0));

    {
        var array: [5]u16 = [_]u16{ 1, 2, 3, 4, 5 };
        try testing.expectEqualSlices(u16, &array, sliceTo(&array, 0));
        try testing.expectEqualSlices(u16, array[0..3], sliceTo(array[0..3], 0));
        try testing.expectEqualSlices(u16, array[0..2], sliceTo(&array, 3));
        try testing.expectEqualSlices(u16, array[0..2], sliceTo(array[0..3], 3));

        const sentinel_ptr = @as([*:5]u16, @ptrCast(&array));
        try testing.expectEqualSlices(u16, array[0..2], sliceTo(sentinel_ptr, 3));
        try testing.expectEqualSlices(u16, array[0..4], sliceTo(sentinel_ptr, 99));

        const optional_sentinel_ptr = @as(?[*:5]u16, @ptrCast(&array));
        try testing.expectEqualSlices(u16, array[0..2], sliceTo(optional_sentinel_ptr, 3).?);
        try testing.expectEqualSlices(u16, array[0..4], sliceTo(optional_sentinel_ptr, 99).?);

        const c_ptr = @as([*c]u16, &array);
        try testing.expectEqualSlices(u16, array[0..2], sliceTo(c_ptr, 3));

        const slice: []u16 = &array;
        try testing.expectEqualSlices(u16, array[0..2], sliceTo(slice, 3));
        try testing.expectEqualSlices(u16, &array, sliceTo(slice, 99));

        const sentinel_slice: [:5]u16 = array[0..4 :5];
        try testing.expectEqualSlices(u16, array[0..2], sliceTo(sentinel_slice, 3));
        try testing.expectEqualSlices(u16, array[0..4], sliceTo(sentinel_slice, 99));
    }
    {
        ```
