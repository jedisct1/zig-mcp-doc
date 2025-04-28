```
alue))));
    }

    return -%@as(MaskInt, @intCast(@intFromBool(value)));
}

test boolMask {
    const runTest = struct {
        fn runTest() !void {
            try testing.expectEqual(@as(u1, 0), boolMask(u1, false));
            try testing.expectEqual(@as(u1, 1), boolMask(u1, true));

            try testing.expectEqual(@as(i1, 0), boolMask(i1, false));
            try testing.expectEqual(@as(i1, -1), boolMask(i1, true));

            try testing.expectEqual(@as(u13, 0), boolMask(u13, false));
            try testing.expectEqual(@as(u13, 0x1FFF), boolMask(u13, true));

            try testing.expectEqual(@as(i13, 0), boolMask(i13, false));
            try testing.expectEqual(@as(i13, -1), boolMask(i13, true));

            try testing.expectEqual(@as(u32, 0), boolMask(u32, false));
            try testing.expectEqual(@as(u32, 0xFFFF_FFFF), boolMask(u32, true));

            try testing.expectEqual(@as(i32, 0), boolMask(i32, false));
            try testing.expectEqual(@as(i32, -1), boolMask(i32, true));
        }
    }.runTest;
    try runTest();
    try comptime runTest();
}

/// Return the mod of `num` with the smallest integer type
pub fn comptimeMod(num: anytype, comptime denom: comptime_int) IntFittingRange(0, denom - 1) {
    return @as(IntFittingRange(0, denom - 1), @intCast(@mod(num, denom)));
}

pub const F80 = struct {
    fraction: u64,
    exp: u16,

    pub fn toFloat(self: F80) f80 {
        const int = (@as(u80, self.exp) << 64) | self.fraction;
        return @as(f80, @bitCast(int));
    }

    pub fn fromFloat(x: f80) F80 {
        const int = @as(u80, @bitCast(x));
        return .{
            .fraction = @as(u64, @truncate(int)),
            .exp = @as(u16, @truncate(int >> 64)),
        };
    }
};

/// Returns -1, 0, or 1.
/// Supports integer and float types and vectors of integer and float types.
/// Unsigned integer types will always return 0 or 1.
/// Branchless.
pub inline fn sign(i: anytype) @TypeOf(i) {
    const T = @TypeOf(i);
    return switch (@typeInfo(T)) {
        .int, .comptime_int => @as(T, @intFromBool(i > 0)) - @as(T, @intFromBool(i < 0)),
        .float, .comptime_float => @as(T, @floatFromInt(@intFromBool(i > 0))) - @as(T, @floatFromInt(@intFromBool(i < 0))),
        .vector => |vinfo| blk: {
            switch (@typeInfo(vinfo.child)) {
                .int, .float => {
                    const zero: T = @splat(0);
                    const one: T = @splat(1);
                    break :blk @select(vinfo.child, i > zero, one, zero) - @select(vinfo.child, i < zero, one, zero);
                },
                else => @compileError("Expected vector of ints or floats, found " ++ @typeName(T)),
            }
        },
        else => @compileError("Expected an int, float or vector of one, found " ++ @typeName(T)),
    };
}

fn testSign() !void {
    // each of the following blocks checks the inputs
    // 2, -2, 0, { 2, -2, 0 } provide expected output
    // 1, -1, 0, { 1, -1, 0 } for the given T
    // (negative values omitted for unsigned types)
    {
        const T = i8;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, -1), sign(@as(T, -2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(3, T){ 1, -1, 0 }, sign(@Vector(3, T){ 2, -2, 0 }));
    }
    {
        const T = i32;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, -1), sign(@as(T, -2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(3, T){ 1, -1, 0 }, sign(@Vector(3, T){ 2, -2, 0 }));
    }
    {
        const T = i64;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, -1), sign(@as(T, -2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(3, T){ 1, -1, 0 }, sign(@Vector(3, T){ 2, -2, 0 }));
    }
    {
        const T = u8;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(2, T){ 1, 0 }, sign(@Vector(2, T){ 2, 0 }));
    }
    {
        const T = u32;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(2, T){ 1, 0 }, sign(@Vector(2, T){ 2, 0 }));
    }
    {
        const T = u64;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(2, T){ 1, 0 }, sign(@Vector(2, T){ 2, 0 }));
    }
    {
        const T = f16;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, -1), sign(@as(T, -2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(3, T){ 1, -1, 0 }, sign(@Vector(3, T){ 2, -2, 0 }));
    }
    {
        const T = f32;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, -1), sign(@as(T, -2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(3, T){ 1, -1, 0 }, sign(@Vector(3, T){ 2, -2, 0 }));
    }
    {
        const T = f64;
        try std.testing.expectEqual(@as(T, 1), sign(@as(T, 2)));
        try std.testing.expectEqual(@as(T, -1), sign(@as(T, -2)));
        try std.testing.expectEqual(@as(T, 0), sign(@as(T, 0)));
        try std.testing.expectEqual(@Vector(3, T){ 1, -1, 0 }, sign(@Vector(3, T){ 2, -2, 0 }));
    }

    // comptime_int
    try std.testing.expectEqual(-1, sign(-10));
    try std.testing.expectEqual(1, sign(10));
    try std.testing.expectEqual(0, sign(0));
    // comptime_float
    try std.testing.expectEqual(-1.0, sign(-10.0));
    try std.testing.expectEqual(1.0, sign(10.0));
    try std.testing.expectEqual(0.0, sign(0.0));
}

test sign {
    try testSign();
    try comptime testSign();
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/acosf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/acos.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns the arc-cosine of x.
///
/// Special cases:
///  - acos(x)   = nan if x < -1 or x > 1
pub fn acos(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => acos32(x),
        f64 => acos64(x),
        else => @compileError("acos not implemented for " ++ @typeName(T)),
    };
}

fn r32(z: f32) f32 {
    const pS0 = 1.6666586697e-01;
    const pS1 = -4.2743422091e-02;
    const pS2 = -8.6563630030e-03;
    const qS1 = -7.0662963390e-01;

    const p = z * (pS0 + z * (pS1 + z * pS2));
    const q = 1.0 + z * qS1;
    return p / q;
}

fn acos32(x: f32) f32 {
    const pio2_hi = 1.5707962513e+00;
    const pio2_lo = 7.5497894159e-08;

    const hx: u32 = @as(u32, @bitCast(x));
    const ix: u32 = hx & 0x7FFFFFFF;

    // |x| >= 1 or nan
    if (ix >= 0x3F800000) {
        if (ix == 0x3F800000) {
            if (hx >> 31 != 0) {
                return 2.0 * pio2_hi + 0x1.0p-120;
            } else {
                return 0.0;
            }
        } else {
            return math.nan(f32);
        }
    }

    // |x| < 0.5
    if (ix < 0x3F000000) {
        if (ix <= 0x32800000) { // |x| < 2^(-26)
            return pio2_hi + 0x1.0p-120;
        } else {
            return pio2_hi - (x - (pio2_lo - x * r32(x * x)));
        }
    }

    // x < -0.5
    if (hx >> 31 != 0) {
        const z = (1 + x) * 0.5;
        const s = @sqrt(z);
        const w = r32(z) * s - pio2_lo;
        return 2 * (pio2_hi - (s + w));
    }

    // x > 0.5
    const z = (1.0 - x) * 0.5;
    const s = @sqrt(z);
    const jx = @as(u32, @bitCast(s));
    const df = @as(f32, @bitCast(jx & 0xFFFFF000));
    const c = (z - df * df) / (s + df);
    const w = r32(z) * s + c;
    return 2 * (df + w);
}

fn r64(z: f64) f64 {
    const pS0: f64 = 1.66666666666666657415e-01;
    const pS1: f64 = -3.25565818622400915405e-01;
    const pS2: f64 = 2.01212532134862925881e-01;
    const pS3: f64 = -4.00555345006794114027e-02;
    const pS4: f64 = 7.91534994289814532176e-04;
    const pS5: f64 = 3.47933107596021167570e-05;
    const qS1: f64 = -2.40339491173441421878e+00;
    const qS2: f64 = 2.02094576023350569471e+00;
    const qS3: f64 = -6.88283971605453293030e-01;
    const qS4: f64 = 7.70381505559019352791e-02;

    const p = z * (pS0 + z * (pS1 + z * (pS2 + z * (pS3 + z * (pS4 + z * pS5)))));
    const q = 1.0 + z * (qS1 + z * (qS2 + z * (qS3 + z * qS4)));
    return p / q;
}

fn acos64(x: f64) f64 {
    const pio2_hi: f64 = 1.57079632679489655800e+00;
    const pio2_lo: f64 = 6.12323399573676603587e-17;

    const ux = @as(u64, @bitCast(x));
    const hx = @as(u32, @intCast(ux >> 32));
    const ix = hx & 0x7FFFFFFF;

    // |x| >= 1 or nan
    if (ix >= 0x3FF00000) {
        const lx = @as(u32, @intCast(ux & 0xFFFFFFFF));

        // acos(1) = 0, acos(-1) = pi
        if ((ix - 0x3FF00000) | lx == 0) {
            if (hx >> 31 != 0) {
                return 2 * pio2_hi + 0x1.0p-120;
            } else {
                return 0;
            }
        }

        return math.nan(f64);
    }

    // |x| < 0.5
    if (ix < 0x3FE00000) {
        // |x| < 2^(-57)
        if (ix <= 0x3C600000) {
            return pio2_hi + 0x1.0p-120;
        } else {
            return pio2_hi - (x - (pio2_lo - x * r64(x * x)));
        }
    }

    // x < -0.5
    if (hx >> 31 != 0) {
        const z = (1.0 + x) * 0.5;
        const s = @sqrt(z);
        const w = r64(z) * s - pio2_lo;
        return 2 * (pio2_hi - (s + w));
    }

    // x > 0.5
    const z = (1.0 - x) * 0.5;
    const s = @sqrt(z);
    const jx = @as(u64, @bitCast(s));
    const df = @as(f64, @bitCast(jx & 0xFFFFFFFF00000000));
    const c = (z - df * df) / (s + df);
    const w = r64(z) * s + c;
    return 2 * (df + w);
}

test acos {
    try expect(acos(@as(f32, 0.0)) == acos32(0.0));
    try expect(acos(@as(f64, 0.0)) == acos64(0.0));
}

test acos32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, acos32(0.0), 1.570796, epsilon));
    try expect(math.approxEqAbs(f32, acos32(0.2), 1.369438, epsilon));
    try expect(math.approxEqAbs(f32, acos32(0.3434), 1.220262, epsilon));
    try expect(math.approxEqAbs(f32, acos32(0.5), 1.047198, epsilon));
    try expect(math.approxEqAbs(f32, acos32(0.8923), 0.468382, epsilon));
    try expect(math.approxEqAbs(f32, acos32(-0.2), 1.772154, epsilon));
}

test acos64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, acos64(0.0), 1.570796, epsilon));
    try expect(math.approxEqAbs(f64, acos64(0.2), 1.369438, epsilon));
    try expect(math.approxEqAbs(f64, acos64(0.3434), 1.220262, epsilon));
    try expect(math.approxEqAbs(f64, acos64(0.5), 1.047198, epsilon));
    try expect(math.approxEqAbs(f64, acos64(0.8923), 0.468382, epsilon));
    try expect(math.approxEqAbs(f64, acos64(-0.2), 1.772154, epsilon));
}

test "acos32.special" {
    try expect(math.isNan(acos32(-2)));
    try expect(math.isNan(acos32(1.5)));
}

test "acos64.special" {
    try expect(math.isNan(acos64(-2)));
    try expect(math.isNan(acos64(1.5)));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/acoshf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/acosh.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns the hyperbolic arc-cosine of x.
///
/// Special cases:
///  - acosh(x)   = nan if x < 1
///  - acosh(nan) = nan
pub fn acosh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => acosh32(x),
        f64 => acosh64(x),
        else => @compileError("acosh not implemented for " ++ @typeName(T)),
    };
}

// acosh(x) = log(x + sqrt(x * x - 1))
fn acosh32(x: f32) f32 {
    const u = @as(u32, @bitCast(x));
    const i = u & 0x7FFFFFFF;

    // |x| < 2, invalid if x < 1 or nan
    if (i < 0x3F800000 + (1 << 23)) {
        return math.log1p(x - 1 + @sqrt((x - 1) * (x - 1) + 2 * (x - 1)));
    }
    // |x| < 0x1p12
    else if (i < 0x3F800000 + (12 << 23)) {
        return @log(2 * x - 1 / (x + @sqrt(x * x - 1)));
    }
    // |x| >= 0x1p12
    else {
        return @log(x) + 0.693147180559945309417232121458176568;
    }
}

fn acosh64(x: f64) f64 {
    const u = @as(u64, @bitCast(x));
    const e = (u >> 52) & 0x7FF;

    // |x| < 2, invalid if x < 1 or nan
    if (e < 0x3FF + 1) {
        return math.log1p(x - 1 + @sqrt((x - 1) * (x - 1) + 2 * (x - 1)));
    }
    // |x| < 0x1p26
    else if (e < 0x3FF + 26) {
        return @log(2 * x - 1 / (x + @sqrt(x * x - 1)));
    }
    // |x| >= 0x1p26 or nan
    else {
        return @log(x) + 0.693147180559945309417232121458176568;
    }
}

test acosh {
    try expect(acosh(@as(f32, 1.5)) == acosh32(1.5));
    try expect(acosh(@as(f64, 1.5)) == acosh64(1.5));
}

test acosh32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, acosh32(1.5), 0.962424, epsilon));
    try expect(math.approxEqAbs(f32, acosh32(37.45), 4.315976, epsilon));
    try expect(math.approxEqAbs(f32, acosh32(89.123), 5.183133, epsilon));
    try expect(math.approxEqAbs(f32, acosh32(123123.234375), 12.414088, epsilon));
}

test acosh64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, acosh64(1.5), 0.962424, epsilon));
    try expect(math.approxEqAbs(f64, acosh64(37.45), 4.315976, epsilon));
    try expect(math.approxEqAbs(f64, acosh64(89.123), 5.183133, epsilon));
    try expect(math.approxEqAbs(f64, acosh64(123123.234375), 12.414088, epsilon));
}

test "acosh32.special" {
    try expect(math.isNan(acosh32(math.nan(f32))));
    try expect(math.isNan(acosh32(0.5)));
}

test "acosh64.special" {
    try expect(math.isNan(acosh64(math.nan(f64))));
    try expect(math.isNan(acosh64(0.5)));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/asinf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/asin.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns the arc-sin of x.
///
/// Special Cases:
///  - asin(+-0) = +-0
///  - asin(x)   = nan if x < -1 or x > 1
pub fn asin(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => asin32(x),
        f64 => asin64(x),
        else => @compileError("asin not implemented for " ++ @typeName(T)),
    };
}

fn r32(z: f32) f32 {
    const pS0 = 1.6666586697e-01;
    const pS1 = -4.2743422091e-02;
    const pS2 = -8.6563630030e-03;
    const qS1 = -7.0662963390e-01;

    const p = z * (pS0 + z * (pS1 + z * pS2));
    const q = 1.0 + z * qS1;
    return p / q;
}

fn asin32(x: f32) f32 {
    const pio2 = 1.570796326794896558e+00;

    const hx: u32 = @as(u32, @bitCast(x));
    const ix: u32 = hx & 0x7FFFFFFF;

    // |x| >= 1
    if (ix >= 0x3F800000) {
        // |x| >= 1
        if (ix == 0x3F800000) {
            return x * pio2 + 0x1.0p-120; // asin(+-1) = +-pi/2 with inexact
        } else {
            return math.nan(f32); // asin(|x| > 1) is nan
        }
    }

    // |x| < 0.5
    if (ix < 0x3F000000) {
        // 0x1p-126 <= |x| < 0x1p-12
        if (ix < 0x39800000 and ix >= 0x00800000) {
            return x;
        } else {
            return x + x * r32(x * x);
        }
    }

    // 1 > |x| >= 0.5
    const z = (1 - @abs(x)) * 0.5;
    const s = @sqrt(z);
    const fx = pio2 - 2 * (s + s * r32(z));

    if (hx >> 31 != 0) {
        return -fx;
    } else {
        return fx;
    }
}

fn r64(z: f64) f64 {
    const pS0: f64 = 1.66666666666666657415e-01;
    const pS1: f64 = -3.25565818622400915405e-01;
    const pS2: f64 = 2.01212532134862925881e-01;
    const pS3: f64 = -4.00555345006794114027e-02;
    const pS4: f64 = 7.91534994289814532176e-04;
    const pS5: f64 = 3.47933107596021167570e-05;
    const qS1: f64 = -2.40339491173441421878e+00;
    const qS2: f64 = 2.02094576023350569471e+00;
    const qS3: f64 = -6.88283971605453293030e-01;
    const qS4: f64 = 7.70381505559019352791e-02;

    const p = z * (pS0 + z * (pS1 + z * (pS2 + z * (pS3 + z * (pS4 + z * pS5)))));
    const q = 1.0 + z * (qS1 + z * (qS2 + z * (qS3 + z * qS4)));
    return p / q;
}

fn asin64(x: f64) f64 {
    const pio2_hi: f64 = 1.57079632679489655800e+00;
    const pio2_lo: f64 = 6.12323399573676603587e-17;

    const ux = @as(u64, @bitCast(x));
    const hx = @as(u32, @intCast(ux >> 32));
    const ix = hx & 0x7FFFFFFF;

    // |x| >= 1 or nan
    if (ix >= 0x3FF00000) {
        const lx = @as(u32, @intCast(ux & 0xFFFFFFFF));

        // asin(1) = +-pi/2 with inexact
        if ((ix - 0x3FF00000) | lx == 0) {
            return x * pio2_hi + 0x1.0p-120;
        } else {
            return math.nan(f64);
        }
    }

    // |x| < 0.5
    if (ix < 0x3FE00000) {
        // if 0x1p-1022 <= |x| < 0x1p-26 avoid raising overflow
        if (ix < 0x3E500000 and ix >= 0x00100000) {
            return x;
        } else {
            return x + x * r64(x * x);
        }
    }

    // 1 > |x| >= 0.5
    const z = (1 - @abs(x)) * 0.5;
    const s = @sqrt(z);
    const r = r64(z);
    var fx: f64 = undefined;

    // |x| > 0.975
    if (ix >= 0x3FEF3333) {
        fx = pio2_hi - 2 * (s + s * r);
    } else {
        const jx = @as(u64, @bitCast(s));
        const df = @as(f64, @bitCast(jx & 0xFFFFFFFF00000000));
        const c = (z - df * df) / (s + df);
        fx = 0.5 * pio2_hi - (2 * s * r - (pio2_lo - 2 * c) - (0.5 * pio2_hi - 2 * df));
    }

    if (hx >> 31 != 0) {
        return -fx;
    } else {
        return fx;
    }
}

test asin {
    try expect(asin(@as(f32, 0.0)) == asin32(0.0));
    try expect(asin(@as(f64, 0.0)) == asin64(0.0));
}

test asin32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, asin32(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, asin32(0.2), 0.201358, epsilon));
    try expect(math.approxEqAbs(f32, asin32(-0.2), -0.201358, epsilon));
    try expect(math.approxEqAbs(f32, asin32(0.3434), 0.350535, epsilon));
    try expect(math.approxEqAbs(f32, asin32(0.5), 0.523599, epsilon));
    try expect(math.approxEqAbs(f32, asin32(0.8923), 1.102415, epsilon));
}

test asin64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, asin64(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, asin64(0.2), 0.201358, epsilon));
    try expect(math.approxEqAbs(f64, asin64(-0.2), -0.201358, epsilon));
    try expect(math.approxEqAbs(f64, asin64(0.3434), 0.350535, epsilon));
    try expect(math.approxEqAbs(f64, asin64(0.5), 0.523599, epsilon));
    try expect(math.approxEqAbs(f64, asin64(0.8923), 1.102415, epsilon));
}

test "asin32.special" {
    try expect(math.isPositiveZero(asin32(0.0)));
    try expect(math.isNegativeZero(asin32(-0.0)));
    try expect(math.isNan(asin32(-2)));
    try expect(math.isNan(asin32(1.5)));
}

test "asin64.special" {
    try expect(math.isPositiveZero(asin64(0.0)));
    try expect(math.isNegativeZero(asin64(-0.0)));
    try expect(math.isNan(asin64(-2)));
    try expect(math.isNan(asin64(1.5)));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/asinhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/asinh.c

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;
const maxInt = std.math.maxInt;

/// Returns the hyperbolic arc-sin of x.
///
/// Special Cases:
///  - asinh(+-0)   = +-0
///  - asinh(+-inf) = +-inf
///  - asinh(nan)   = nan
pub fn asinh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => asinh32(x),
        f64 => asinh64(x),
        else => @compileError("asinh not implemented for " ++ @typeName(T)),
    };
}

// asinh(x) = sign(x) * log(|x| + sqrt(x * x + 1)) ~= x - x^3/6 + o(x^5)
fn asinh32(x: f32) f32 {
    const u = @as(u32, @bitCast(x));
    const i = u & 0x7FFFFFFF;
    const s = u >> 31;

    var rx = @as(f32, @bitCast(i)); // |x|

    // |x| >= 0x1p12 or inf or nan
    if (i >= 0x3F800000 + (12 << 23)) {
        rx = @log(rx) + 0.69314718055994530941723212145817656;
    }
    // |x| >= 2
    else if (i >= 0x3F800000 + (1 << 23)) {
        rx = @log(2 * rx + 1 / (@sqrt(rx * rx + 1) + rx));
    }
    // |x| >= 0x1p-12, up to 1.6ulp error
    else if (i >= 0x3F800000 - (12 << 23)) {
        rx = math.log1p(rx + rx * rx / (@sqrt(rx * rx + 1) + 1));
    }
    // |x| < 0x1p-12, inexact if x != 0
    else {
        mem.doNotOptimizeAway(rx + 0x1.0p120);
    }

    return if (s != 0) -rx else rx;
}

fn asinh64(x: f64) f64 {
    const u = @as(u64, @bitCast(x));
    const e = (u >> 52) & 0x7FF;
    const s = u >> 63;

    var rx = @as(f64, @bitCast(u & (maxInt(u64) >> 1))); // |x|

    // |x| >= 0x1p26 or inf or nan
    if (e >= 0x3FF + 26) {
        rx = @log(rx) + 0.693147180559945309417232121458176568;
    }
    // |x| >= 2
    else if (e >= 0x3FF + 1) {
        rx = @log(2 * rx + 1 / (@sqrt(rx * rx + 1) + rx));
    }
    // |x| >= 0x1p-12, up to 1.6ulp error
    else if (e >= 0x3FF - 26) {
        rx = math.log1p(rx + rx * rx / (@sqrt(rx * rx + 1) + 1));
    }
    // |x| < 0x1p-12, inexact if x != 0
    else {
        mem.doNotOptimizeAway(rx + 0x1.0p120);
    }

    return if (s != 0) -rx else rx;
}

test asinh {
    try expect(asinh(@as(f32, 0.0)) == asinh32(0.0));
    try expect(asinh(@as(f64, 0.0)) == asinh64(0.0));
}

test asinh32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, asinh32(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, asinh32(-0.2), -0.198690, epsilon));
    try expect(math.approxEqAbs(f32, asinh32(0.2), 0.198690, epsilon));
    try expect(math.approxEqAbs(f32, asinh32(0.8923), 0.803133, epsilon));
    try expect(math.approxEqAbs(f32, asinh32(1.5), 1.194763, epsilon));
    try expect(math.approxEqAbs(f32, asinh32(37.45), 4.316332, epsilon));
    try expect(math.approxEqAbs(f32, asinh32(89.123), 5.183196, epsilon));
    try expect(math.approxEqAbs(f32, asinh32(123123.234375), 12.414088, epsilon));
}

test asinh64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, asinh64(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, asinh64(-0.2), -0.198690, epsilon));
    try expect(math.approxEqAbs(f64, asinh64(0.2), 0.198690, epsilon));
    try expect(math.approxEqAbs(f64, asinh64(0.8923), 0.803133, epsilon));
    try expect(math.approxEqAbs(f64, asinh64(1.5), 1.194763, epsilon));
    try expect(math.approxEqAbs(f64, asinh64(37.45), 4.316332, epsilon));
    try expect(math.approxEqAbs(f64, asinh64(89.123), 5.183196, epsilon));
    try expect(math.approxEqAbs(f64, asinh64(123123.234375), 12.414088, epsilon));
}

test "asinh32.special" {
    try expect(math.isPositiveZero(asinh32(0.0)));
    try expect(math.isNegativeZero(asinh32(-0.0)));
    try expect(math.isPositiveInf(asinh32(math.inf(f32))));
    try expect(math.isNegativeInf(asinh32(-math.inf(f32))));
    try expect(math.isNan(asinh32(math.nan(f32))));
}

test "asinh64.special" {
    try expect(math.isPositiveZero(asinh64(0.0)));
    try expect(math.isNegativeZero(asinh64(-0.0)));
    try expect(math.isPositiveInf(asinh64(math.inf(f64))));
    try expect(math.isNegativeInf(asinh64(-math.inf(f64))));
    try expect(math.isNan(asinh64(math.nan(f64))));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/atanf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/atan.c

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;

/// Returns the arc-tangent of x.
///
/// Special Cases:
///  - atan(+-0)   = +-0
///  - atan(+-inf) = +-pi/2
pub fn atan(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => atan32(x),
        f64 => atan64(x),
        else => @compileError("atan not implemented for " ++ @typeName(T)),
    };
}

fn atan32(x_: f32) f32 {
    const atanhi = [_]f32{
        4.6364760399e-01, // atan(0.5)hi
        7.8539812565e-01, // atan(1.0)hi
        9.8279368877e-01, // atan(1.5)hi
        1.5707962513e+00, // atan(inf)hi
    };

    const atanlo = [_]f32{
        5.0121582440e-09, // atan(0.5)lo
        3.7748947079e-08, // atan(1.0)lo
        3.4473217170e-08, // atan(1.5)lo
        7.5497894159e-08, // atan(inf)lo
    };

    const aT = [_]f32{
        3.3333328366e-01,
        -1.9999158382e-01,
        1.4253635705e-01,
        -1.0648017377e-01,
        6.1687607318e-02,
    };

    var x = x_;
    var ix: u32 = @as(u32, @bitCast(x));
    const sign = ix >> 31;
    ix &= 0x7FFFFFFF;

    // |x| >= 2^26
    if (ix >= 0x4C800000) {
        if (math.isNan(x)) {
            return x;
        } else {
            const z = atanhi[3] + 0x1.0p-120;
            return if (sign != 0) -z else z;
        }
    }

    var id: ?usize = undefined;

    // |x| < 0.4375
    if (ix < 0x3EE00000) {
        // |x| < 2^(-12)
        if (ix < 0x39800000) {
            if (ix < 0x00800000) {
                mem.doNotOptimizeAway(x * x);
            }
            return x;
        }
        id = null;
    } else {
        x = @abs(x);
        // |x| < 1.1875
        if (ix < 0x3F980000) {
            // 7/16 <= |x| < 11/16
            if (ix < 0x3F300000) {
                id = 0;
                x = (2.0 * x - 1.0) / (2.0 + x);
            }
            // 11/16 <= |x| < 19/16
            else {
                id = 1;
                x = (x - 1.0) / (x + 1.0);
            }
        } else {
            // |x| < 2.4375
            if (ix < 0x401C0000) {
                id = 2;
                x = (x - 1.5) / (1.0 + 1.5 * x);
            }
            // 2.4375 <= |x| < 2^26
            else {
                id = 3;
                x = -1.0 / x;
            }
        }
    }

    const z = x * x;
    const w = z * z;
    const s1 = z * (aT[0] + w * (aT[2] + w * aT[4]));
    const s2 = w * (aT[1] + w * aT[3]);

    if (id) |id_value| {
        const zz = atanhi[id_value] - ((x * (s1 + s2) - atanlo[id_value]) - x);
        return if (sign != 0) -zz else zz;
    } else {
        return x - x * (s1 + s2);
    }
}

fn atan64(x_: f64) f64 {
    const atanhi = [_]f64{
        4.63647609000806093515e-01, // atan(0.5)hi
        7.85398163397448278999e-01, // atan(1.0)hi
        9.82793723247329054082e-01, // atan(1.5)hi
        1.57079632679489655800e+00, // atan(inf)hi
    };

    const atanlo = [_]f64{
        2.26987774529616870924e-17, // atan(0.5)lo
        3.06161699786838301793e-17, // atan(1.0)lo
        1.39033110312309984516e-17, // atan(1.5)lo
        6.12323399573676603587e-17, // atan(inf)lo
    };

    const aT = [_]f64{
        3.33333333333329318027e-01,
        -1.99999999998764832476e-01,
        1.42857142725034663711e-01,
        -1.11111104054623557880e-01,
        9.09088713343650656196e-02,
        -7.69187620504482999495e-02,
        6.66107313738753120669e-02,
        -5.83357013379057348645e-02,
        4.97687799461593236017e-02,
        -3.65315727442169155270e-02,
        1.62858201153657823623e-02,
    };

    var x = x_;
    const ux: u64 = @bitCast(x);
    var ix: u32 = @intCast(ux >> 32);
    const sign = ix >> 31;
    ix &= 0x7FFFFFFF;

    // |x| >= 2^66
    if (ix >= 0x44100000) {
        if (math.isNan(x)) {
            return x;
        } else {
            const z = atanhi[3] + 0x1.0p-120;
            return if (sign != 0) -z else z;
        }
    }

    var id: ?usize = undefined;

    // |x| < 0.4375
    if (ix < 0x3FDC0000) {
        // |x| < 2^(-27)
        if (ix < 0x3E400000) {
            if (ix < 0x00100000) {
                mem.doNotOptimizeAway(@as(f32, @floatCast(x)));
            }
            return x;
        }
        id = null;
    } else {
        x = @abs(x);
        // |x| < 1.1875
        if (ix < 0x3FF30000) {
            // 7/16 <= |x| < 11/16
            if (ix < 0x3FE60000) {
                id = 0;
                x = (2.0 * x - 1.0) / (2.0 + x);
            }
            // 11/16 <= |x| < 19/16
            else {
                id = 1;
                x = (x - 1.0) / (x + 1.0);
            }
        } else {
            // |x| < 2.4375
            if (ix < 0x40038000) {
                id = 2;
                x = (x - 1.5) / (1.0 + 1.5 * x);
            }
            // 2.4375 <= |x| < 2^66
            else {
                id = 3;
                x = -1.0 / x;
            }
        }
    }

    const z = x * x;
    const w = z * z;
    const s1 = z * (aT[0] + w * (aT[2] + w * (aT[4] + w * (aT[6] + w * (aT[8] + w * aT[10])))));
    const s2 = w * (aT[1] + w * (aT[3] + w * (aT[5] + w * (aT[7] + w * aT[9]))));

    if (id) |id_value| {
        const zz = atanhi[id_value] - ((x * (s1 + s2) - atanlo[id_value]) - x);
        return if (sign != 0) -zz else zz;
    } else {
        return x - x * (s1 + s2);
    }
}

test atan {
    try expect(@as(u32, @bitCast(atan(@as(f32, 0.2)))) == @as(u32, @bitCast(atan32(0.2))));
    try expect(atan(@as(f64, 0.2)) == atan64(0.2));
}

test atan32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, atan32(0.2), 0.197396, epsilon));
    try expect(math.approxEqAbs(f32, atan32(-0.2), -0.197396, epsilon));
    try expect(math.approxEqAbs(f32, atan32(0.3434), 0.330783, epsilon));
    try expect(math.approxEqAbs(f32, atan32(0.8923), 0.728545, epsilon));
    try expect(math.approxEqAbs(f32, atan32(1.5), 0.982794, epsilon));
}

test atan64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, atan64(0.2), 0.197396, epsilon));
    try expect(math.approxEqAbs(f64, atan64(-0.2), -0.197396, epsilon));
    try expect(math.approxEqAbs(f64, atan64(0.3434), 0.330783, epsilon));
    try expect(math.approxEqAbs(f64, atan64(0.8923), 0.728545, epsilon));
    try expect(math.approxEqAbs(f64, atan64(1.5), 0.982794, epsilon));
}

test "atan32.special" {
    const epsilon = 0.000001;

    try expect(math.isPositiveZero(atan32(0.0)));
    try expect(math.isNegativeZero(atan32(-0.0)));
    try expect(math.approxEqAbs(f32, atan32(math.inf(f32)), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f32, atan32(-math.inf(f32)), -math.pi / 2.0, epsilon));
}

test "atan64.special" {
    const epsilon = 0.000001;

    try expect(math.isPositiveZero(atan64(0.0)));
    try expect(math.isNegativeZero(atan64(-0.0)));
    try expect(math.approxEqAbs(f64, atan64(math.inf(f64)), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f64, atan64(-math.inf(f64)), -math.pi / 2.0, epsilon));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/atan2f.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/atan2.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns the arc-tangent of y/x.
///
///      Special Cases:
/// |   y   |   x   | radians |
/// |-------|-------|---------|
/// |  fin  |  nan  |   nan   |
/// |  nan  |  fin  |   nan   |
/// |  +0   | >=+0  |   +0    |
/// |  -0   | >=+0  |   -0    |
/// |  +0   | <=-0  |   pi    |
/// |  -0   | <=-0  |  -pi    |
/// |  pos  |   0   |  +pi/2  |
/// |  neg  |   0   |  -pi/2  |
/// | +inf  | +inf  |  +pi/4  |
/// | -inf  | +inf  |  -pi/4  |
/// | +inf  | -inf  |  3pi/4  |
/// | -inf  | -inf  | -3pi/4  |
/// |  fin  | +inf  |    0    |
/// |  pos  | -inf  |  +pi    |
/// |  neg  | -inf  |  -pi    |
/// | +inf  |  fin  |  +pi/2  |
/// | -inf  |  fin  |  -pi/2  |
pub fn atan2(y: anytype, x: anytype) @TypeOf(x, y) {
    const T = @TypeOf(x, y);
    return switch (T) {
        f32 => atan2_32(y, x),
        f64 => atan2_64(y, x),
        else => @compileError("atan2 not implemented for " ++ @typeName(T)),
    };
}

fn atan2_32(y: f32, x: f32) f32 {
    const pi: f32 = 3.1415927410e+00;
    const pi_lo: f32 = -8.7422776573e-08;

    if (math.isNan(x) or math.isNan(y)) {
        return x + y;
    }

    var ix = @as(u32, @bitCast(x));
    var iy = @as(u32, @bitCast(y));

    // x = 1.0
    if (ix == 0x3F800000) {
        return math.atan(y);
    }

    // 2 * sign(x) + sign(y)
    const m = ((iy >> 31) & 1) | ((ix >> 30) & 2);
    ix &= 0x7FFFFFFF;
    iy &= 0x7FFFFFFF;

    if (iy == 0) {
        switch (m) {
            0, 1 => return y, // atan(+-0, +...)
            2 => return pi, // atan(+0, -...)
            3 => return -pi, // atan(-0, -...)
            else => unreachable,
        }
    }

    if (ix == 0) {
        if (m & 1 != 0) {
            return -pi / 2;
        } else {
            return pi / 2;
        }
    }

    if (ix == 0x7F800000) {
        if (iy == 0x7F800000) {
            switch (m) {
                0 => return pi / 4, // atan(+inf, +inf)
                1 => return -pi / 4, // atan(-inf, +inf)
                2 => return 3 * pi / 4, // atan(+inf, -inf)
                3 => return -3 * pi / 4, // atan(-inf, -inf)
                else => unreachable,
            }
        } else {
            switch (m) {
                0 => return 0.0, // atan(+..., +inf)
                1 => return -0.0, // atan(-..., +inf)
                2 => return pi, // atan(+..., -inf)
                3 => return -pi, // atan(-...f, -inf)
                else => unreachable,
            }
        }
    }

    // |y / x| > 0x1p26
    if (ix + (26 << 23) < iy or iy == 0x7F800000) {
        if (m & 1 != 0) {
            return -pi / 2;
        } else {
            return pi / 2;
        }
    }

    // z = atan(|y / x|) with correct underflow
    const z = z: {
        if ((m & 2) != 0 and iy + (26 << 23) < ix) {
            break :z 0.0;
        } else {
            break :z math.atan(@abs(y / x));
        }
    };

    switch (m) {
        0 => return z, // atan(+, +)
        1 => return -z, // atan(-, +)
        2 => return pi - (z - pi_lo), // atan(+, -)
        3 => return (z - pi_lo) - pi, // atan(-, -)
        else => unreachable,
    }
}

fn atan2_64(y: f64, x: f64) f64 {
    const pi: f64 = 3.1415926535897931160E+00;
    const pi_lo: f64 = 1.2246467991473531772E-16;

    if (math.isNan(x) or math.isNan(y)) {
        return x + y;
    }

    const ux: u64 = @bitCast(x);
    var ix: u32 = @intCast(ux >> 32);
    const lx: u32 = @intCast(ux & 0xFFFFFFFF);

    const uy: u64 = @bitCast(y);
    var iy: u32 = @intCast(uy >> 32);
    const ly: u32 = @intCast(uy & 0xFFFFFFFF);

    // x = 1.0
    if ((ix -% 0x3FF00000) | lx == 0) {
        return math.atan(y);
    }

    // 2 * sign(x) + sign(y)
    const m = ((iy >> 31) & 1) | ((ix >> 30) & 2);
    ix &= 0x7FFFFFFF;
    iy &= 0x7FFFFFFF;

    if (iy | ly == 0) {
        switch (m) {
            0, 1 => return y, // atan(+-0, +...)
            2 => return pi, // atan(+0, -...)
            3 => return -pi, // atan(-0, -...)
            else => unreachable,
        }
    }

    if (ix | lx == 0) {
        if (m & 1 != 0) {
            return -pi / 2;
        } else {
            return pi / 2;
        }
    }

    if (ix == 0x7FF00000) {
        if (iy == 0x7FF00000) {
            switch (m) {
                0 => return pi / 4, // atan(+inf, +inf)
                1 => return -pi / 4, // atan(-inf, +inf)
                2 => return 3 * pi / 4, // atan(+inf, -inf)
                3 => return -3 * pi / 4, // atan(-inf, -inf)
                else => unreachable,
            }
        } else {
            switch (m) {
                0 => return 0.0, // atan(+..., +inf)
                1 => return -0.0, // atan(-..., +inf)
                2 => return pi, // atan(+..., -inf)
                3 => return -pi, // atan(-...f, -inf)
                else => unreachable,
            }
        }
    }

    // |y / x| > 0x1p64
    if (ix +% (64 << 20) < iy or iy == 0x7FF00000) {
        if (m & 1 != 0) {
            return -pi / 2;
        } else {
            return pi / 2;
        }
    }

    // z = atan(|y / x|) with correct underflow
    const z = z: {
        if ((m & 2) != 0 and iy +% (64 << 20) < ix) {
            break :z 0.0;
        } else {
            break :z math.atan(@abs(y / x));
        }
    };

    switch (m) {
        0 => return z, // atan(+, +)
        1 => return -z, // atan(-, +)
        2 => return pi - (z - pi_lo), // atan(+, -)
        3 => return (z - pi_lo) - pi, // atan(-, -)
        else => unreachable,
    }
}

test atan2 {
    const y32: f32 = 0.2;
    const x32: f32 = 0.21;
    const y64: f64 = 0.2;
    const x64: f64 = 0.21;
    try expect(atan2(y32, x32) == atan2_32(0.2, 0.21));
    try expect(atan2(y64, x64) == atan2_64(0.2, 0.21));
}

test atan2_32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, atan2_32(0.0, 0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(0.2, 0.2), 0.785398, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-0.2, 0.2), -0.785398, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(0.2, -0.2), 2.356194, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-0.2, -0.2), -2.356194, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(0.34, -0.4), 2.437099, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(0.34, 1.243), 0.267001, epsilon));
}

test atan2_64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, atan2_64(0.0, 0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(0.2, 0.2), 0.785398, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-0.2, 0.2), -0.785398, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(0.2, -0.2), 2.356194, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-0.2, -0.2), -2.356194, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(0.34, -0.4), 2.437099, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(0.34, 1.243), 0.267001, epsilon));
}

test "atan2_32.special" {
    const epsilon = 0.000001;

    try expect(math.isNan(atan2_32(1.0, math.nan(f32))));
    try expect(math.isNan(atan2_32(math.nan(f32), 1.0)));
    try expect(atan2_32(0.0, 5.0) == 0.0);
    try expect(atan2_32(-0.0, 5.0) == -0.0);
    try expect(math.approxEqAbs(f32, atan2_32(0.0, -5.0), math.pi, epsilon));
    //expect(math.approxEqAbs(f32, atan2_32(-0.0, -5.0), -math.pi, .{.rel=0,.abs=epsilon})); TODO support negative zero?
    try expect(math.approxEqAbs(f32, atan2_32(1.0, 0.0), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(1.0, -0.0), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-1.0, 0.0), -math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-1.0, -0.0), -math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(math.inf(f32), math.inf(f32)), math.pi / 4.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-math.inf(f32), math.inf(f32)), -math.pi / 4.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(math.inf(f32), -math.inf(f32)), 3.0 * math.pi / 4.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-math.inf(f32), -math.inf(f32)), -3.0 * math.pi / 4.0, epsilon));
    try expect(atan2_32(1.0, math.inf(f32)) == 0.0);
    try expect(math.approxEqAbs(f32, atan2_32(1.0, -math.inf(f32)), math.pi, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-1.0, -math.inf(f32)), -math.pi, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(math.inf(f32), 1.0), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f32, atan2_32(-math.inf(f32), 1.0), -math.pi / 2.0, epsilon));
}

test "atan2_64.special" {
    const epsilon = 0.000001;

    try expect(math.isNan(atan2_64(1.0, math.nan(f64))));
    try expect(math.isNan(atan2_64(math.nan(f64), 1.0)));
    try expect(atan2_64(0.0, 5.0) == 0.0);
    try expect(atan2_64(-0.0, 5.0) == -0.0);
    try expect(math.approxEqAbs(f64, atan2_64(0.0, -5.0), math.pi, epsilon));
    //expect(math.approxEqAbs(f64, atan2_64(-0.0, -5.0), -math.pi, .{.rel=0,.abs=epsilon})); TODO support negative zero?
    try expect(math.approxEqAbs(f64, atan2_64(1.0, 0.0), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(1.0, -0.0), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-1.0, 0.0), -math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-1.0, -0.0), -math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(math.inf(f64), math.inf(f64)), math.pi / 4.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-math.inf(f64), math.inf(f64)), -math.pi / 4.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(math.inf(f64), -math.inf(f64)), 3.0 * math.pi / 4.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-math.inf(f64), -math.inf(f64)), -3.0 * math.pi / 4.0, epsilon));
    try expect(atan2_64(1.0, math.inf(f64)) == 0.0);
    try expect(math.approxEqAbs(f64, atan2_64(1.0, -math.inf(f64)), math.pi, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-1.0, -math.inf(f64)), -math.pi, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(math.inf(f64), 1.0), math.pi / 2.0, epsilon));
    try expect(math.approxEqAbs(f64, atan2_64(-math.inf(f64), 1.0), -math.pi / 2.0, epsilon));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/atanhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/atanh.c

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;
const maxInt = std.math.maxInt;

/// Returns the hyperbolic arc-tangent of x.
///
/// Special Cases:
///  - atanh(+-1) = +-inf with signal
///  - atanh(x)   = nan if |x| > 1 with signal
///  - atanh(nan) = nan
pub fn atanh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => atanh_32(x),
        f64 => atanh_64(x),
        else => @compileError("atanh not implemented for " ++ @typeName(T)),
    };
}

// atanh(x) = log((1 + x) / (1 - x)) / 2 = log1p(2x / (1 - x)) / 2 ~= x + x^3 / 3 + o(x^5)
fn atanh_32(x: f32) f32 {
    const u = @as(u32, @bitCast(x));
    const i = u & 0x7FFFFFFF;
    const s = u >> 31;

    var y = @as(f32, @bitCast(i)); // |x|

    if (y == 1.0) {
        return math.copysign(math.inf(f32), x);
    }

    if (u < 0x3F800000 - (1 << 23)) {
        if (u < 0x3F800000 - (32 << 23)) {
            // underflow
            if (u < (1 << 23)) {
                mem.doNotOptimizeAway(y * y);
            }
        }
        // |x| < 0.5
        else {
            y = 0.5 * math.log1p(2 * y + 2 * y * y / (1 - y));
        }
    } else {
        y = 0.5 * math.log1p(2 * (y / (1 - y)));
    }

    return if (s != 0) -y else y;
}

fn atanh_64(x: f64) f64 {
    const u: u64 = @bitCast(x);
    const e = (u >> 52) & 0x7FF;
    const s = u >> 63;

    var y: f64 = @bitCast(u & (maxInt(u64) >> 1)); // |x|

    if (y == 1.0) {
        return math.copysign(math.inf(f64), x);
    }

    if (e < 0x3FF - 1) {
        if (e < 0x3FF - 32) {
            // underflow
            if (e == 0) {
                mem.doNotOptimizeAway(@as(f32, @floatCast(y)));
            }
        }
        // |x| < 0.5
        else {
            y = 0.5 * math.log1p(2 * y + 2 * y * y / (1 - y));
        }
    } else {
        y = 0.5 * math.log1p(2 * (y / (1 - y)));
    }

    return if (s != 0) -y else y;
}

test atanh {
    try expect(atanh(@as(f32, 0.0)) == atanh_32(0.0));
    try expect(atanh(@as(f64, 0.0)) == atanh_64(0.0));
}

test atanh_32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, atanh_32(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, atanh_32(0.2), 0.202733, epsilon));
    try expect(math.approxEqAbs(f32, atanh_32(0.8923), 1.433099, epsilon));
}

test atanh_64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, atanh_64(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, atanh_64(0.2), 0.202733, epsilon));
    try expect(math.approxEqAbs(f64, atanh_64(0.8923), 1.433099, epsilon));
}

test "atanh32.special" {
    try expect(math.isPositiveInf(atanh_32(1)));
    try expect(math.isNegativeInf(atanh_32(-1)));
    try expect(math.isNan(atanh_32(1.5)));
    try expect(math.isNan(atanh_32(-1.5)));
    try expect(math.isNan(atanh_32(math.nan(f32))));
}

test "atanh64.special" {
    try expect(math.isPositiveInf(atanh_64(1)));
    try expect(math.isNegativeInf(atanh_64(-1)));
    try expect(math.isNan(atanh_64(1.5)));
    try expect(math.isNan(atanh_64(-1.5)));
    try expect(math.isNan(atanh_64(math.nan(f64))));
}
const std = @import("../std.zig");
const assert = std.debug.assert;

pub const Rational = @import("big/rational.zig").Rational;
pub const int = @import("big/int.zig");
pub const Limb = usize;
const limb_info = @typeInfo(Limb).int;
pub const SignedLimb = std.meta.Int(.signed, limb_info.bits);
pub const DoubleLimb = std.meta.Int(.unsigned, 2 * limb_info.bits);
pub const HalfLimb = std.meta.Int(.unsigned, limb_info.bits / 2);
pub const SignedDoubleLimb = std.meta.Int(.signed, 2 * limb_info.bits);
pub const Log2Limb = std.math.Log2Int(Limb);

comptime {
    assert(std.math.floorPowerOfTwo(usize, limb_info.bits) == limb_info.bits);
    assert(limb_info.signedness == .unsigned);
}

test {
    _ = int;
    _ = Rational;
    _ = Limb;
    _ = SignedLimb;
    _ = DoubleLimb;
    _ = SignedDoubleLimb;
    _ = Log2Limb;
}
const std = @import("../../std.zig");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Managed = std.math.big.int.Managed;
const Mutable = std.math.big.int.Mutable;
const Limb = std.math.big.Limb;
const SignedLimb = std.math.big.SignedLimb;
const DoubleLimb = std.math.big.DoubleLimb;
const SignedDoubleLimb = std.math.big.SignedDoubleLimb;
const calcTwosCompLimbCount = std.math.big.int.calcTwosCompLimbCount;
const maxInt = std.math.maxInt;
const minInt = std.math.minInt;

// NOTE: All the following tests assume the max machine-word will be 64-bit.
//
// They will still run on larger than this and should pass, but the multi-limb code-paths
// may be untested in some cases.

test "comptime_int set" {
    comptime var s = 0xefffffff00000001eeeeeeefaaaaaaab;
    var a = try Managed.initSet(testing.allocator, s);
    defer a.deinit();

    const s_limb_count = 128 / @typeInfo(Limb).int.bits;

    comptime var i: usize = 0;
    inline while (i < s_limb_count) : (i += 1) {
        const result = @as(Limb, s & maxInt(Limb));
        s >>= @typeInfo(Limb).int.bits / 2;
        s >>= @typeInfo(Limb).int.bits / 2;
        try testing.expectEqual(result, a.limbs[i]);
    }
}

test "comptime_int set negative" {
    var a = try Managed.initSet(testing.allocator, -10);
    defer a.deinit();

    try testing.expectEqual(10, a.limbs[0]);
    try testing.expectEqual(false, a.isPositive());
}

test "int set unaligned small" {
    var a = try Managed.initSet(testing.allocator, @as(u7, 45));
    defer a.deinit();

    try testing.expectEqual(45, a.limbs[0]);
    try testing.expectEqual(true, a.isPositive());
}

test "comptime_int to" {
    var a = try Managed.initSet(testing.allocator, 0xefffffff00000001eeeeeeefaaaaaaab);
    defer a.deinit();

    try testing.expectEqual(0xefffffff00000001eeeeeeefaaaaaaab, try a.toInt(u128));
}

test "sub-limb to" {
    var a = try Managed.initSet(testing.allocator, 10);
    defer a.deinit();

    try testing.expectEqual(10, try a.toInt(u8));
}

test "set negative minimum" {
    var a = try Managed.initSet(testing.allocator, @as(i64, minInt(i64)));
    defer a.deinit();

    try testing.expectEqual(minInt(i64), try a.toInt(i64));
}

test "set double-width maximum then zero" {
    var a = try Managed.initSet(testing.allocator, maxInt(DoubleLimb));
    defer a.deinit();
    try a.set(@as(DoubleLimb, 0));

    try testing.expectEqual(@as(DoubleLimb, 0), try a.toInt(DoubleLimb));
}

test "to target too small error" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff);
    defer a.deinit();

    try testing.expectError(error.TargetTooSmall, a.toInt(u8));
}

test "normalize" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try a.ensureCapacity(8);

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 3;
    a.limbs[3] = 0;
    a.normalize(4);
    try testing.expectEqual(3, a.len());

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 3;
    a.normalize(3);
    try testing.expectEqual(3, a.len());

    a.limbs[0] = 0;
    a.limbs[1] = 0;
    a.normalize(2);
    try testing.expectEqual(1, a.len());

    a.limbs[0] = 0;
    a.normalize(1);
    try testing.expectEqual(1, a.len());
}

test "normalize multi" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try a.ensureCapacity(8);

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 0;
    a.limbs[3] = 0;
    a.normalize(4);
    try testing.expectEqual(2, a.len());

    a.limbs[0] = 1;
    a.limbs[1] = 2;
    a.limbs[2] = 3;
    a.normalize(3);
    try testing.expectEqual(3, a.len());

    a.limbs[0] = 0;
    a.limbs[1] = 0;
    a.limbs[2] = 0;
    a.limbs[3] = 0;
    a.normalize(4);
    try testing.expectEqual(1, a.len());

    a.limbs[0] = 0;
    a.normalize(1);
    try testing.expectEqual(1, a.len());
}

test "parity" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try testing.expect(a.isEven());
    try testing.expect(!a.isOdd());

    try a.set(7);
    try testing.expect(!a.isEven());
    try testing.expect(a.isOdd());
}

test "bitcount + sizeInBaseUpperBound" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0b100);
    try testing.expectEqual(3, a.bitCountAbs());
    try testing.expect(a.sizeInBaseUpperBound(2) >= 3);
    try testing.expect(a.sizeInBaseUpperBound(10) >= 1);

    a.negate();
    try testing.expectEqual(3, a.bitCountAbs());
    try testing.expect(a.sizeInBaseUpperBound(2) >= 4);
    try testing.expect(a.sizeInBaseUpperBound(10) >= 2);

    try a.set(0xffffffff);
    try testing.expectEqual(32, a.bitCountAbs());
    try testing.expect(a.sizeInBaseUpperBound(2) >= 32);
    try testing.expect(a.sizeInBaseUpperBound(10) >= 10);

    try a.shiftLeft(&a, 5000);
    try testing.expectEqual(5032, a.bitCountAbs());
    try testing.expect(a.sizeInBaseUpperBound(2) >= 5032);
    a.setSign(false);

    try testing.expectEqual(5032, a.bitCountAbs());
    try testing.expect(a.sizeInBaseUpperBound(2) >= 5033);
}

test "bitcount/to" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try testing.expectEqual(0, a.bitCountTwosComp());

    try testing.expectEqual(0, try a.toInt(u0));
    try testing.expectEqual(0, try a.toInt(i0));

    try a.set(-1);
    try testing.expectEqual(1, a.bitCountTwosComp());
    try testing.expectEqual(-1, try a.toInt(i1));

    try a.set(-8);
    try testing.expectEqual(4, a.bitCountTwosComp());
    try testing.expectEqual(-8, try a.toInt(i4));

    try a.set(127);
    try testing.expectEqual(7, a.bitCountTwosComp());
    try testing.expectEqual(127, try a.toInt(u7));

    try a.set(-128);
    try testing.expectEqual(8, a.bitCountTwosComp());
    try testing.expectEqual(-128, try a.toInt(i8));

    try a.set(-129);
    try testing.expectEqual(9, a.bitCountTwosComp());
    try testing.expectEqual(-129, try a.toInt(i9));
}

test "fits" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try testing.expect(a.fits(u0));
    try testing.expect(a.fits(i0));

    try a.set(255);
    try testing.expect(!a.fits(u0));
    try testing.expect(!a.fits(u1));
    try testing.expect(!a.fits(i8));
    try testing.expect(a.fits(u8));
    try testing.expect(a.fits(u9));
    try testing.expect(a.fits(i9));

    try a.set(-128);
    try testing.expect(!a.fits(i7));
    try testing.expect(a.fits(i8));
    try testing.expect(a.fits(i9));
    try testing.expect(!a.fits(u9));

    try a.set(0x1ffffffffeeeeeeee);
    try testing.expect(!a.fits(u32));
    try testing.expect(!a.fits(u64));
    try testing.expect(a.fits(u65));
}

test "string set" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.setString(10, "120317241209124781241290847124");
    try testing.expectEqual(120317241209124781241290847124, try a.toInt(u128));
}

test "string negative" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.setString(10, "-1023");
    try testing.expectEqual(-1023, try a.toInt(i32));
}

test "string set number with underscores" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.setString(10, "__1_2_0_3_1_7_2_4_1_2_0_____9_1__2__4_7_8_1_2_4_1_2_9_0_8_4_7_1_2_4___");
    try testing.expectEqual(120317241209124781241290847124, try a.toInt(u128));
}

test "string set case insensitive number" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.setString(16, "aB_cD_eF");
    try testing.expectEqual(0xabcdef, try a.toInt(u32));
}

test "string set base 36" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.setString(36, "fifvthrv1mzt79ez9");
    try testing.expectEqual(123456789123456789123456789, try a.to(u128));
}

test "string set bad char error" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try testing.expectError(error.InvalidCharacter, a.setString(10, "x"));
}

test "string set bad base error" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    try testing.expectError(error.InvalidBase, a.setString(45, "10"));
}

test "twos complement limit set" {
    try testTwosComplementLimit(u64);
    try testTwosComplementLimit(i64);
    try testTwosComplementLimit(u1);
    try testTwosComplementLimit(i1);
    try testTwosComplementLimit(u0);
    try testTwosComplementLimit(i0);
    try testTwosComplementLimit(u65);
    try testTwosComplementLimit(i65);
}

fn testTwosComplementLimit(comptime T: type) !void {
    const int_info = @typeInfo(T).int;

    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.setTwosCompIntLimit(.max, int_info.signedness, int_info.bits);
    const max: T = maxInt(T);
    try testing.expectEqual(max, try a.toInt(T));

    try a.setTwosCompIntLimit(.min, int_info.signedness, int_info.bits);
    const min: T = minInt(T);
    try testing.expectEqual(min, try a.toInt(T));
}

test "string to" {
    var a = try Managed.initSet(testing.allocator, 120317241209124781241290847124);
    defer a.deinit();

    const as = try a.toString(testing.allocator, 10, .lower);
    defer testing.allocator.free(as);
    const es = "120317241209124781241290847124";

    try testing.expect(mem.eql(u8, as, es));
}

test "string to base base error" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff);
    defer a.deinit();

    try testing.expectError(error.InvalidBase, a.toString(testing.allocator, 45, .lower));
}

test "string to base 2" {
    var a = try Managed.initSet(testing.allocator, -0b1011);
    defer a.deinit();

    const as = try a.toString(testing.allocator, 2, .lower);
    defer testing.allocator.free(as);
    const es = "-1011";

    try testing.expect(mem.eql(u8, as, es));
}

test "string to base 16" {
    var a = try Managed.initSet(testing.allocator, 0xefffffff00000001eeeeeeefaaaaaaab);
    defer a.deinit();

    const as = try a.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(as);
    const es = "efffffff00000001eeeeeeefaaaaaaab";

    try testing.expect(mem.eql(u8, as, es));
}

test "string to base 36" {
    var a = try Managed.initSet(testing.allocator, 123456789123456789123456789);
    defer a.deinit();

    const as = try a.toString(testing.allocator, 36, .lower);
    defer testing.allocator.free(as);
    const es = "fifvthrv1mzt79ez9";

    try testing.expect(mem.eql(u8, as, es));
}

test "neg string to" {
    var a = try Managed.initSet(testing.allocator, -123907434);
    defer a.deinit();

    const as = try a.toString(testing.allocator, 10, .lower);
    defer testing.allocator.free(as);
    const es = "-123907434";

    try testing.expect(mem.eql(u8, as, es));
}

test "zero string to" {
    var a = try Managed.initSet(testing.allocator, 0);
    defer a.deinit();

    const as = try a.toString(testing.allocator, 10, .lower);
    defer testing.allocator.free(as);
    const es = "0";

    try testing.expect(mem.eql(u8, as, es));
}

test "clone" {
    var a = try Managed.initSet(testing.allocator, 1234);
    defer a.deinit();
    var b = try a.clone();
    defer b.deinit();

    try testing.expectEqual(1234, try a.toInt(u32));
    try testing.expectEqual(1234, try b.toInt(u32));

    try a.set(77);
    try testing.expectEqual(77, try a.toInt(u32));
    try testing.expectEqual(1234, try b.toInt(u32));
}

test "swap" {
    var a = try Managed.initSet(testing.allocator, 1234);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 5678);
    defer b.deinit();

    try testing.expectEqual(1234, try a.toInt(u32));
    try testing.expectEqual(5678, try b.toInt(u32));

    a.swap(&b);

    try testing.expectEqual(5678, try a.toInt(u32));
    try testing.expectEqual(1234, try b.toInt(u32));
}

test "to negative" {
    var a = try Managed.initSet(testing.allocator, -10);
    defer a.deinit();

    try testing.expectEqual(-10, try a.toInt(i32));
}

test "compare" {
    var a = try Managed.initSet(testing.allocator, -11);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 10);
    defer b.deinit();

    try testing.expectEqual(.gt, a.orderAbs(b));
    try testing.expectEqual(.lt, a.order(b));
}

test "compare similar" {
    var a = try Managed.initSet(testing.allocator, 0xffffffffeeeeeeeeffffffffeeeeeeee);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xffffffffeeeeeeeeffffffffeeeeeeef);
    defer b.deinit();

    try testing.expectEqual(.lt, a.orderAbs(b));
    try testing.expectEqual(.gt, b.orderAbs(a));
}

test "compare different limb size" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) + 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    try testing.expectEqual(.gt, a.orderAbs(b));
    try testing.expectEqual(.lt, b.orderAbs(a));
}

test "compare multi-limb" {
    var a = try Managed.initSet(testing.allocator, -0x7777777799999999ffffeeeeffffeeeeffffeeeef);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x7777777799999999ffffeeeeffffeeeeffffeeeee);
    defer b.deinit();

    try testing.expectEqual(.gt, a.orderAbs(b));
    try testing.expectEqual(.lt, a.order(b));
}

test "equality" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0xffffffff1);
    defer b.deinit();

    try testing.expect(a.eqlAbs(b));
    try testing.expect(!a.eql(b));
}

test "abs" {
    var a = try Managed.initSet(testing.allocator, -5);
    defer a.deinit();

    a.abs();
    try testing.expectEqual(5, try a.toInt(u32));

    a.abs();
    try testing.expectEqual(5, try a.toInt(u32));
}

test "negate" {
    var a = try Managed.initSet(testing.allocator, 5);
    defer a.deinit();

    a.negate();
    try testing.expectEqual(-5, try a.toInt(i32));

    a.negate();
    try testing.expectEqual(5, try a.toInt(i32));
}

test "add single-single" {
    var a = try Managed.initSet(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 5);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.add(&a, &b);

    try testing.expectEqual(55, try c.toInt(u32));
}

test "add multi-single" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) + 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();

    try c.add(&a, &b);
    try testing.expectEqual(maxInt(Limb) + 2, try c.toInt(DoubleLimb));

    try c.add(&b, &a);
    try testing.expectEqual(maxInt(Limb) + 2, try c.toInt(DoubleLimb));
}

test "add multi-multi" {
    var op1: u128 = 0xefefefef7f7f7f7f;
    var op2: u128 = 0xfefefefe9f9f9f9f;
    // These must be runtime-known to prevent this comparison being tautological, as the
    // compiler uses `std.math.big.int` internally to add these values at comptime.
    _ = .{ &op1, &op2 };
    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.add(&a, &b);

    try testing.expectEqual(op1 + op2, try c.toInt(u128));
}

test "add zero-zero" {
    var a = try Managed.initSet(testing.allocator, 0);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.add(&a, &b);

    try testing.expectEqual(0, try c.toInt(u32));
}

test "add alias multi-limb nonzero-zero" {
    const op1 = 0xffffffff777777771;
    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0);
    defer b.deinit();

    try a.add(&a, &b);

    try testing.expectEqual(op1, try a.toInt(u128));
}

test "add sign" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var one = try Managed.initSet(testing.allocator, 1);
    defer one.deinit();
    var two = try Managed.initSet(testing.allocator, 2);
    defer two.deinit();
    var neg_one = try Managed.initSet(testing.allocator, -1);
    defer neg_one.deinit();
    var neg_two = try Managed.initSet(testing.allocator, -2);
    defer neg_two.deinit();

    try a.add(&one, &two);
    try testing.expectEqual(3, try a.toInt(i32));

    try a.add(&neg_one, &two);
    try testing.expectEqual(1, try a.toInt(i32));

    try a.add(&one, &neg_two);
    try testing.expectEqual(-1, try a.toInt(i32));

    try a.add(&neg_one, &neg_two);
    try testing.expectEqual(-3, try a.toInt(i32));
}

test "add comptime scalar" {
    var a = try Managed.initSet(testing.allocator, 50);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.addScalar(&a, 5);

    try testing.expectEqual(55, try b.toInt(u32));
}

test "add scalar" {
    var a = try Managed.initSet(testing.allocator, 123);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.addScalar(&a, @as(u32, 31));

    try testing.expectEqual(154, try b.toInt(u32));
}

test "addWrap single-single, unsigned" {
    var a = try Managed.initSet(testing.allocator, maxInt(u17));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 10);
    defer b.deinit();

    const wrapped = try a.addWrap(&a, &b, .unsigned, 17);

    try testing.expect(wrapped);
    try testing.expectEqual(9, try a.toInt(u17));
}

test "subWrap single-single, unsigned" {
    var a = try Managed.initSet(testing.allocator, 0);
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, maxInt(u17));
    defer b.deinit();

    const wrapped = try a.subWrap(&a, &b, .unsigned, 17);

    try testing.expect(wrapped);
    try testing.expectEqual(1, try a.toInt(u17));
}

test "addWrap multi-multi, unsigned, limb aligned" {
    var a = try Managed.initSet(testing.allocator, maxInt(DoubleLimb));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, maxInt(DoubleLimb));
    defer b.deinit();

    const wrapped = try a.addWrap(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect(wrapped);
    try testing.expectEqual(maxInt(DoubleLimb) - 1, try a.toInt(DoubleLimb));
}

test "subWrap single-multi, unsigned, limb aligned" {
    var a = try Managed.initSet(testing.allocator, 10);
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, maxInt(DoubleLimb) + 100);
    defer b.deinit();

    const wrapped = try a.subWrap(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect(wrapped);
    try testing.expectEqual(maxInt(DoubleLimb) - 88, try a.toInt(DoubleLimb));
}

test "addWrap single-single, signed" {
    var a = try Managed.initSet(testing.allocator, maxInt(i21));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 1 + 1 + maxInt(u21));
    defer b.deinit();

    const wrapped = try a.addWrap(&a, &b, .signed, @bitSizeOf(i21));

    try testing.expect(wrapped);
    try testing.expectEqual(minInt(i21), try a.toInt(i21));
}

test "subWrap single-single, signed" {
    var a = try Managed.initSet(testing.allocator, minInt(i21));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    const wrapped = try a.subWrap(&a, &b, .signed, @bitSizeOf(i21));

    try testing.expect(wrapped);
    try testing.expectEqual(maxInt(i21), try a.toInt(i21));
}

test "addWrap multi-multi, signed, limb aligned" {
    var a = try Managed.initSet(testing.allocator, maxInt(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, maxInt(SignedDoubleLimb));
    defer b.deinit();

    const wrapped = try a.addWrap(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect(wrapped);
    try testing.expectEqual(-2, try a.toInt(SignedDoubleLimb));
}

test "subWrap single-multi, signed, limb aligned" {
    var a = try Managed.initSet(testing.allocator, minInt(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    const wrapped = try a.subWrap(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expect(wrapped);
    try testing.expectEqual(maxInt(SignedDoubleLimb), try a.toInt(SignedDoubleLimb));
}

test "addWrap returns normalized result" {
    var x = try Managed.initSet(testing.allocator, 0);
    defer x.deinit();
    var y = try Managed.initSet(testing.allocator, 0);
    defer y.deinit();

    // make them both non normalized "-0"
    x.setMetadata(false, 1);
    y.setMetadata(false, 1);

    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try testing.expect(!(try r.addWrap(&x, &y, .unsigned, 64)));
    try testing.expect(r.isPositive() and r.len() == 1 and r.limbs[0] == 0);
}

test "subWrap returns normalized result" {
    var x = try Managed.initSet(testing.allocator, 0);
    defer x.deinit();
    var y = try Managed.initSet(testing.allocator, 0);
    defer y.deinit();

    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try testing.expect(!(try r.subWrap(&x, &y, .unsigned, 64)));
    try testing.expect(r.isPositive() and r.len() == 1 and r.limbs[0] == 0);
}

test "addSat single-single, unsigned" {
    var a = try Managed.initSet(testing.allocator, maxInt(u17) - 5);
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 10);
    defer b.deinit();

    try a.addSat(&a, &b, .unsigned, 17);

    try testing.expectEqual(maxInt(u17), try a.toInt(u17));
}

test "subSat single-single, unsigned" {
    var a = try Managed.initSet(testing.allocator, 123);
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 4000);
    defer b.deinit();

    try a.subSat(&a, &b, .unsigned, 17);

    try testing.expectEqual(0, try a.toInt(u17));
}

test "addSat multi-multi, unsigned, limb aligned" {
    var a = try Managed.initSet(testing.allocator, maxInt(DoubleLimb));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, maxInt(DoubleLimb));
    defer b.deinit();

    try a.addSat(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expectEqual(maxInt(DoubleLimb), try a.toInt(DoubleLimb));
}

test "subSat single-multi, unsigned, limb aligned" {
    var a = try Managed.initSet(testing.allocator, 10);
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, maxInt(DoubleLimb) + 100);
    defer b.deinit();

    try a.subSat(&a, &b, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expectEqual(0, try a.toInt(DoubleLimb));
}

test "addSat single-single, signed" {
    var a = try Managed.initSet(testing.allocator, maxInt(i14));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    try a.addSat(&a, &b, .signed, @bitSizeOf(i14));

    try testing.expectEqual(maxInt(i14), try a.toInt(i14));
}

test "subSat single-single, signed" {
    var a = try Managed.initSet(testing.allocator, minInt(i21));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    try a.subSat(&a, &b, .signed, @bitSizeOf(i21));

    try testing.expectEqual(minInt(i21), try a.toInt(i21));
}

test "addSat multi-multi, signed, limb aligned" {
    var a = try Managed.initSet(testing.allocator, maxInt(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, maxInt(SignedDoubleLimb));
    defer b.deinit();

    try a.addSat(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expectEqual(maxInt(SignedDoubleLimb), try a.toInt(SignedDoubleLimb));
}

test "subSat single-multi, signed, limb aligned" {
    var a = try Managed.initSet(testing.allocator, minInt(SignedDoubleLimb));
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    try a.subSat(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expectEqual(minInt(SignedDoubleLimb), try a.toInt(SignedDoubleLimb));
}

test "sub single-single" {
    var a = try Managed.initSet(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 5);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expectEqual(45, try c.toInt(u32));
}

test "sub multi-single" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) + 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expectEqual(maxInt(Limb), try c.toInt(Limb));
}

test "sub multi-multi" {
    var op1: u128 = 0xefefefefefefefefefefefef;
    var op2: u128 = 0xabababababababababababab;
    _ = .{ &op1, &op2 };

    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expectEqual(op1 - op2, try c.toInt(u128));
}

test "sub equal" {
    var a = try Managed.initSet(testing.allocator, 0x11efefefefefefefefefefefef);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x11efefefefefefefefefefefef);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.sub(&a, &b);

    try testing.expectEqual(0, try c.toInt(u32));
}

test "sub sign" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var one = try Managed.initSet(testing.allocator, 1);
    defer one.deinit();
    var two = try Managed.initSet(testing.allocator, 2);
    defer two.deinit();
    var neg_one = try Managed.initSet(testing.allocator, -1);
    defer neg_one.deinit();
    var neg_two = try Managed.initSet(testing.allocator, -2);
    defer neg_two.deinit();

    try a.sub(&one, &two);
    try testing.expectEqual(-1, try a.toInt(i32));

    try a.sub(&neg_one, &two);
    try testing.expectEqual(-3, try a.toInt(i32));

    try a.sub(&one, &neg_two);
    try testing.expectEqual(3, try a.toInt(i32));

    try a.sub(&neg_one, &neg_two);
    try testing.expectEqual(1, try a.toInt(i32));

    try a.sub(&neg_two, &neg_one);
    try testing.expectEqual(-1, try a.toInt(i32));
}

test "mul single-single" {
    var a = try Managed.initSet(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 5);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expectEqual(250, try c.toInt(u64));
}

test "mul multi-single" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expectEqual(2 * maxInt(Limb), try c.toInt(DoubleLimb));
}

test "mul multi-multi" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var op1: u256 = 0x998888efefefefefefefef;
    var op2: u256 = 0x333000abababababababab;
    _ = .{ &op1, &op2 };

    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expectEqual(op1 * op2, try c.toInt(u256));
}

test "mul alias r with a" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 2);
    defer b.deinit();

    try a.mul(&a, &b);

    try testing.expectEqual(2 * maxInt(Limb), try a.toInt(DoubleLimb));
}

test "mul alias r with b" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 2);
    defer b.deinit();

    try a.mul(&b, &a);

    try testing.expectEqual(2 * maxInt(Limb), try a.toInt(DoubleLimb));
}

test "mul alias r with a and b" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer a.deinit();

    try a.mul(&a, &a);

    try testing.expectEqual(maxInt(Limb) * maxInt(Limb), try a.toInt(DoubleLimb));
}

test "mul a*0" {
    var a = try Managed.initSet(testing.allocator, 0xefefefefefefefef);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expectEqual(0, try c.toInt(u32));
}

test "mul 0*0" {
    var a = try Managed.initSet(testing.allocator, 0);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mul(&a, &b);

    try testing.expectEqual(0, try c.toInt(u32));
}

test "mul large" {
    var a = try Managed.initCapacity(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.initCapacity(testing.allocator, 100);
    defer b.deinit();
    var c = try Managed.initCapacity(testing.allocator, 100);
    defer c.deinit();

    // Generate a number that's large enough to cross the thresholds for the use
    // of subquadratic algorithms
    for (a.limbs) |*p| {
        p.* = maxInt(Limb);
    }
    a.setMetadata(true, 50);

    try b.mul(&a, &a);
    try c.sqr(&a);

    try testing.expect(b.eql(c));
}

test "mulWrap single-single unsigned" {
    var a = try Managed.initSet(testing.allocator, 1234);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 5678);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mulWrap(&a, &b, .unsigned, 17);

    try testing.expectEqual(59836, try c.toInt(u17));
}

test "mulWrap single-single signed" {
    var a = try Managed.initSet(testing.allocator, 1234);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -5678);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mulWrap(&a, &b, .signed, 17);

    try testing.expectEqual(-59836, try c.toInt(i17));
}

test "mulWrap multi-multi unsigned" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var op1: u256 = 0x998888efefefefefefefef;
    var op2: u256 = 0x333000abababababababab;
    _ = .{ &op1, &op2 };

    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mulWrap(&a, &b, .unsigned, 65);

    try testing.expectEqual((op1 * op2) & ((1 << 65) - 1), try c.toInt(u256));
}

test "mulWrap multi-multi signed" {
    switch (builtin.zig_backend) {
        .stage2_c => return error.SkipZigTest,
        else => {},
    }

    var a = try Managed.initSet(testing.allocator, maxInt(SignedDoubleLimb) - 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, maxInt(SignedDoubleLimb));
    defer b.deinit();

    var c = try Managed.init(testing.allocator);
    defer c.deinit();
    try c.mulWrap(&a, &b, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expectEqual(minInt(SignedDoubleLimb) + 2, try c.toInt(SignedDoubleLimb));
}

test "mulWrap large" {
    var a = try Managed.initCapacity(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.initCapacity(testing.allocator, 100);
    defer b.deinit();
    var c = try Managed.initCapacity(testing.allocator, 100);
    defer c.deinit();

    // Generate a number that's large enough to cross the thresholds for the use
    // of subquadratic algorithms
    for (a.limbs) |*p| {
        p.* = maxInt(Limb);
    }
    a.setMetadata(true, 50);

    const testbits = @bitSizeOf(Limb) * 64 + 45;

    try b.mulWrap(&a, &a, .signed, testbits);
    try c.sqr(&a);
    try c.truncate(&c, .signed, testbits);

    try testing.expect(b.eql(c));
}

test "div single-half no rem" {
    var a = try Managed.initSet(testing.allocator, 50);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 5);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(10, try q.toInt(u32));
    try testing.expectEqual(0, try r.toInt(u32));
}

test "div single-half with rem" {
    var a = try Managed.initSet(testing.allocator, 49);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 5);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(9, try q.toInt(u32));
    try testing.expectEqual(4, try r.toInt(u32));
}

test "div single-single no rem" {
    // assumes usize is <= 64 bits.
    var a = try Managed.initSet(testing.allocator, 1 << 52);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 1 << 35);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(131072, try q.toInt(u32));
    try testing.expectEqual(0, try r.toInt(u32));
}

test "div single-single with rem" {
    var a = try Managed.initSet(testing.allocator, (1 << 52) | (1 << 33));
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, (1 << 35));
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(131072, try q.toInt(u64));
    try testing.expectEqual(8589934592, try r.toInt(u64));
}

test "div multi-single no rem" {
    var op1: u128 = 0xffffeeeeddddcccc;
    var op2: u128 = 34;
    _ = .{ &op1, &op2 };

    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(op1 / op2, try q.toInt(u64));
    try testing.expectEqual(0, try r.toInt(u64));
}

test "div multi-single with rem" {
    var op1: u128 = 0xffffeeeeddddcccf;
    var op2: u128 = 34;
    _ = .{ &op1, &op2 };

    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(op1 / op2, try q.toInt(u64));
    try testing.expectEqual(3, try r.toInt(u64));
}

test "div multi>2-single" {
    var op1: u128 = 0xfefefefefefefefefefefefefefefefe;
    var op2: u128 = 0xefab8;
    _ = .{ &op1, &op2 };

    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(op1 / op2, try q.toInt(u128));
    try testing.expectEqual(0x3e4e, try r.toInt(u32));
}

test "div single-single q < r" {
    var a = try Managed.initSet(testing.allocator, 0x0078f432);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x01000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0, try q.toInt(u64));
    try testing.expectEqual(0x0078f432, try r.toInt(u64));
}

test "div single-single q == r" {
    var a = try Managed.initSet(testing.allocator, 10);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 10);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(1, try q.toInt(u64));
    try testing.expectEqual(0, try r.toInt(u64));
}

test "div q=0 alias" {
    var a = try Managed.initSet(testing.allocator, 3);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 10);
    defer b.deinit();

    try Managed.divTrunc(&a, &b, &a, &b);

    try testing.expectEqual(0, try a.toInt(u64));
    try testing.expectEqual(3, try b.toInt(u64));
}

test "div multi-multi q < r" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const op1 = 0x1ffffffff0078f432;
    const op2 = 0x1ffffffff01000000;
    var a = try Managed.initSet(testing.allocator, op1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, op2);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0, try q.toInt(u128));
    try testing.expectEqual(op1, try r.toInt(u128));
}

test "div trunc single-single +/+" {
    const u: i32 = 5;
    const v: i32 = 3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    // n = q * d + r
    // 5 = 1 * 3 + 2
    const eq = @divTrunc(u, v);
    const er = @mod(u, v);

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "div trunc single-single -/+" {
    const u: i32 = -5;
    const v: i32 = 3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    //  n = q *  d + r
    // -5 = 1 * -3 - 2
    const eq = -1;
    const er = -2;

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "div trunc single-single +/-" {
    const u: i32 = 5;
    const v: i32 = -3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    // n =  q *  d + r
    // 5 = -1 * -3 + 2
    const eq = -1;
    const er = 2;

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "div trunc single-single -/-" {
    const u: i32 = -5;
    const v: i32 = -3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    //  n = q *  d + r
    // -5 = 1 * -3 - 2
    const eq = 1;
    const er = -2;

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "divTrunc #15535" {
    var one = try Managed.initSet(testing.allocator, 1);
    defer one.deinit();
    var x = try Managed.initSet(testing.allocator, std.math.pow(u128, 2, 64));
    defer x.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    try q.divTrunc(&r, &x, &x);
    try testing.expectEqual(std.math.Order.lt, r.order(one));
}

test "divFloor #10932" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.setString(10, "40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.setString(10, "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    var mod = try Managed.init(testing.allocator);
    defer mod.deinit();

    try res.divFloor(&mod, &a, &b);

    const ress = try res.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(ress);
    try testing.expectEqualStrings("194bd136316c046d070b763396297bf8869a605030216b52597015902a172b2a752f62af1568dcd431602f03725bfa62b0be71ae86616210972c0126e173503011ca48c5747ff066d159c95e46b69cbb14c8fc0bd2bf0919f921be96463200000000000000000000000000000000000000000000000000000000000000000000000000000000", ress);
    try testing.expectEqual(0, try mod.toInt(i32));
}

test "divFloor #11166" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.setString(10, "10000007000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000870000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.setString(10, "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    var mod = try Managed.init(testing.allocator);
    defer mod.deinit();

    try res.divFloor(&mod, &a, &b);

    const ress = try res.toString(testing.allocator, 10, .lower);
    defer testing.allocator.free(ress);
    try testing.expectEqualStrings("1000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", ress);

    const mods = try mod.toString(testing.allocator, 10, .lower);
    defer testing.allocator.free(mods);
    try testing.expectEqualStrings("870000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", mods);
}

test "gcd #10932" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.setString(10, "3000000000000000000000000000000000000000000000000000000000000000000000001461501637330902918203684832716283019655932542975000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.setString(10, "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200001001500000000000000000100000000040000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000003000000000000000000000000000000000000000000000000000058715661000000000000000000000000000000000000023553252000000000180000000000000000000000000000000000000000000000000250000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001005000002000000000000000000000000000000000000000021000000001000000000000000000000000100000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000200000000000000000000004000000000000000000000000000000000000000000000301000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    try res.gcd(&a, &b);

    const ress = try res.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(ress);
    try testing.expectEqualStrings("1a974a5c9734476ff5a3604bcc678a756beacfc21b4427d1f2c1f56f5d4e411a162c56136e20000000000000000000000000000000", ress);
}

test "bitAnd #10932" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    try a.setString(10, "154954885951624787839743960731760616696");
    try b.setString(10, "55000000000915215865915724129619485917228346934191537590366734850266784978214506142389798064826139649163838075568111457203909393174933092857416500785632012953993352521899237655507306575657169267399324107627651067352600878339870446048204062696260567762088867991835386857942106708741836433444432529637331429212430394179472179237695833247299409249810963487516399177133175950185719220422442438098353430605822151595560743492661038899294517012784306863064670126197566982968906306814338148792888550378533207318063660581924736840687332023636827401670268933229183389040490792300121030647791095178823932734160000000000000000000000000000000000000555555550000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    try res.bitAnd(&a, &b);

    try testing.expectEqual(0, try res.toInt(i32));
}

test "bit And #19235" {
    var a = try Managed.initSet(testing.allocator, -0xffffffffffffffff);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x10000000000000000);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.bitAnd(&a, &b);

    try testing.expectEqual(0x10000000000000000, try r.toInt(i128));
}

test "div floor single-single +/+" {
    const u: i32 = 5;
    const v: i32 = 3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divFloor(&q, &r, &a, &b);

    //  n =  q *  d + r
    //  5 =  1 *  3 + 2
    const eq = 1;
    const er = 2;

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "div floor single-single -/+" {
    const u: i32 = -5;
    const v: i32 = 3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divFloor(&q, &r, &a, &b);

    //  n =  q *  d + r
    // -5 = -2 *  3 + 1
    const eq = -2;
    const er = 1;

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "div floor single-single +/-" {
    const u: i32 = 5;
    const v: i32 = -3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divFloor(&q, &r, &a, &b);

    //  n =  q *  d + r
    //  5 = -2 * -3 - 1
    const eq = -2;
    const er = -1;

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "div floor single-single -/-" {
    const u: i32 = -5;
    const v: i32 = -3;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divFloor(&q, &r, &a, &b);

    //  n =  q *  d + r
    // -5 =  2 * -3 + 1
    const eq = 1;
    const er = -2;

    try testing.expectEqual(eq, try q.toInt(i32));
    try testing.expectEqual(er, try r.toInt(i32));
}

test "div floor no remainder negative quotient" {
    const u: i32 = -0x80000000;
    const v: i32 = 1;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divFloor(&q, &r, &a, &b);

    try testing.expectEqual(-0x80000000, try q.toInt(i32));
    try testing.expectEqual(0, try r.toInt(i32));
}

test "div floor negative close to zero" {
    const u: i32 = -2;
    const v: i32 = 12;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divFloor(&q, &r, &a, &b);

    try testing.expectEqual(-1, try q.toInt(i32));
    try testing.expectEqual(10, try r.toInt(i32));
}

test "div floor positive close to zero" {
    const u: i32 = 10;
    const v: i32 = 12;

    var a = try Managed.initSet(testing.allocator, u);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, v);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divFloor(&q, &r, &a, &b);

    try testing.expectEqual(0, try q.toInt(i32));
    try testing.expectEqual(10, try r.toInt(i32));
}

test "div multi-multi with rem" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x8888999911110000ffffeeeeddddccccbbbbaaaa9999);
    defer a.deinit();
   ```
