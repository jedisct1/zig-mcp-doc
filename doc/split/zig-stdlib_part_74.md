```
    const fx: u64 = @bitCast(x);
    const hx: u32 = @intCast(fx >> 32);
    const lx: u32 = @truncate(fx);

    // cexp(0 + iy) = cos(y) + isin(y)
    if ((hx & 0x7fffffff) | lx == 0) {
        return Complex(f64).init(@cos(y), @sin(y));
    }

    if (hy >= 0x7ff00000) {
        // cexp(finite|nan +- i inf|nan) = nan + i nan
        if (lx != 0 or (hx & 0x7fffffff) != 0x7ff00000) {
            return Complex(f64).init(y - y, y - y);
        } // cexp(-inf +- i inf|nan) = 0 + i0
        else if (hx & 0x80000000 != 0) {
            return Complex(f64).init(0, 0);
        } // cexp(+inf +- i inf|nan) = inf + i nan
        else {
            return Complex(f64).init(x, y - y);
        }
    }

    // 709.7 <= x <= 1454.3 so must scale
    if (hx >= exp_overflow and hx <= cexp_overflow) {
        return ldexp_cexp(z, 0);
    } // - x < exp_overflow => exp(x) won't overflow (common)
    // - x > cexp_overflow, so exp(x) * s overflows for s > 0
    // - x = +-inf
    // - x = nan
    else {
        const exp_x = @exp(x);
        return Complex(f64).init(exp_x * @cos(y), exp_x * @sin(y));
    }
}

test exp32 {
    const tolerance_f32 = @sqrt(math.floatEps(f32));

    {
        const a = Complex(f32).init(5, 3);
        const c = exp(a);

        try testing.expectApproxEqRel(@as(f32, -1.46927917e+02), c.re, tolerance_f32);
        try testing.expectApproxEqRel(@as(f32, 2.0944065e+01), c.im, tolerance_f32);
    }

    {
        const a = Complex(f32).init(88.8, 0x1p-149);
        const c = exp(a);

        try testing.expectApproxEqAbs(math.inf(f32), c.re, tolerance_f32);
        try testing.expectApproxEqAbs(@as(f32, 5.15088629e-07), c.im, tolerance_f32);
    }
}

test exp64 {
    const tolerance_f64 = @sqrt(math.floatEps(f64));

    {
        const a = Complex(f64).init(5, 3);
        const c = exp(a);

        try testing.expectApproxEqRel(@as(f64, -1.469279139083189e+02), c.re, tolerance_f64);
        try testing.expectApproxEqRel(@as(f64, 2.094406620874596e+01), c.im, tolerance_f64);
    }

    {
        const a = Complex(f64).init(709.8, 0x1p-1074);
        const c = exp(a);

        try testing.expectApproxEqAbs(math.inf(f64), c.re, tolerance_f64);
        try testing.expectApproxEqAbs(@as(f64, 9.036659362159884e-16), c.im, tolerance_f64);
    }
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/complex/__cexpf.c
// https://git.musl-libc.org/cgit/musl/tree/src/complex/__cexp.c

const std = @import("../../std.zig");
const debug = std.debug;
const math = std.math;
const testing = std.testing;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns exp(z) scaled to avoid overflow.
pub fn ldexp_cexp(z: anytype, expt: i32) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);

    return switch (T) {
        f32 => ldexp_cexp32(z, expt),
        f64 => ldexp_cexp64(z, expt),
        else => unreachable,
    };
}

fn frexp_exp32(x: f32, expt: *i32) f32 {
    const k = 235; // reduction constant
    const kln2 = 162.88958740; // k * ln2

    const exp_x = @exp(x - kln2);
    const hx = @as(u32, @bitCast(exp_x));
    // TODO zig should allow this cast implicitly because it should know the value is in range
    expt.* = @as(i32, @intCast(hx >> 23)) - (0x7f + 127) + k;
    return @as(f32, @bitCast((hx & 0x7fffff) | ((0x7f + 127) << 23)));
}

fn ldexp_cexp32(z: Complex(f32), expt: i32) Complex(f32) {
    var ex_expt: i32 = undefined;
    const exp_x = frexp_exp32(z.re, &ex_expt);
    const exptf = expt + ex_expt;

    const half_expt1 = @divTrunc(exptf, 2);
    const scale1 = @as(f32, @bitCast((0x7f + half_expt1) << 23));

    const half_expt2 = exptf - half_expt1;
    const scale2 = @as(f32, @bitCast((0x7f + half_expt2) << 23));

    return Complex(f32).init(
        @cos(z.im) * exp_x * scale1 * scale2,
        @sin(z.im) * exp_x * scale1 * scale2,
    );
}

fn frexp_exp64(x: f64, expt: *i32) f64 {
    const k = 1799; // reduction constant
    const kln2 = 1246.97177782734161156; // k * ln2

    const exp_x = @exp(x - kln2);

    const fx = @as(u64, @bitCast(exp_x));
    const hx = @as(u32, @intCast(fx >> 32));
    const lx = @as(u32, @truncate(fx));

    expt.* = @as(i32, @intCast(hx >> 20)) - (0x3ff + 1023) + k;

    const high_word = (hx & 0xfffff) | ((0x3ff + 1023) << 20);
    return @as(f64, @bitCast((@as(u64, high_word) << 32) | lx));
}

fn ldexp_cexp64(z: Complex(f64), expt: i32) Complex(f64) {
    var ex_expt: i32 = undefined;
    const exp_x = frexp_exp64(z.re, &ex_expt);
    const exptf = @as(i64, expt + ex_expt);

    const half_expt1 = @divTrunc(exptf, 2);
    const scale1 = @as(f64, @bitCast((0x3ff + half_expt1) << (20 + 32)));

    const half_expt2 = exptf - half_expt1;
    const scale2 = @as(f64, @bitCast((0x3ff + half_expt2) << (20 + 32)));

    return Complex(f64).init(
        @cos(z.im) * exp_x * scale1 * scale2,
        @sin(z.im) * exp_x * scale1 * scale2,
    );
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the natural logarithm of z.
pub fn log(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const r = cmath.abs(z);
    const phi = cmath.arg(z);

    return Complex(T).init(@log(r), phi);
}

test log {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = log(a);

    try testing.expectApproxEqAbs(1.7631803, c.re, epsilon);
    try testing.expectApproxEqAbs(0.5404195, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns z raised to the complex power of c.
pub fn pow(z: anytype, s: anytype) Complex(@TypeOf(z.re, z.im, s.re, s.im)) {
    return cmath.exp(cmath.log(z).mul(s));
}

test pow {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const b = Complex(f32).init(2.3, -1.3);
    const c = pow(a, b);

    try testing.expectApproxEqAbs(58.049110, c.re, epsilon);
    try testing.expectApproxEqAbs(-101.003433, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the projection of z onto the riemann sphere.
pub fn proj(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);

    if (math.isInf(z.re) or math.isInf(z.im)) {
        return Complex(T).init(math.inf(T), math.copysign(@as(T, 0.0), z.re));
    }

    return Complex(T).init(z.re, z.im);
}

test proj {
    const a = Complex(f32).init(5, 3);
    const c = proj(a);

    try testing.expectEqual(5, c.re);
    try testing.expectEqual(3, c.im);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the sine of z.
pub fn sin(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const p = Complex(T).init(-z.im, z.re);
    const q = cmath.sinh(p);
    return Complex(T).init(q.im, -q.re);
}

test sin {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = sin(a);

    try testing.expectApproxEqAbs(-9.654126, c.re, epsilon);
    try testing.expectApproxEqAbs(2.8416924, c.im, epsilon);
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/complex/csinhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/complex/csinh.c

const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

const ldexp_cexp = @import("ldexp.zig").ldexp_cexp;

/// Returns the hyperbolic sine of z.
pub fn sinh(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    return switch (T) {
        f32 => sinh32(z),
        f64 => sinh64(z),
        else => @compileError("tan not implemented for " ++ @typeName(z)),
    };
}

fn sinh32(z: Complex(f32)) Complex(f32) {
    const x = z.re;
    const y = z.im;

    const hx = @as(u32, @bitCast(x));
    const ix = hx & 0x7fffffff;

    const hy = @as(u32, @bitCast(y));
    const iy = hy & 0x7fffffff;

    if (ix < 0x7f800000 and iy < 0x7f800000) {
        if (iy == 0) {
            return Complex(f32).init(math.sinh(x), y);
        }
        // small x: normal case
        if (ix < 0x41100000) {
            return Complex(f32).init(math.sinh(x) * @cos(y), math.cosh(x) * @sin(y));
        }

        // |x|>= 9, so cosh(x) ~= exp(|x|)
        if (ix < 0x42b17218) {
            // x < 88.7: exp(|x|) won't overflow
            const h = @exp(@abs(x)) * 0.5;
            return Complex(f32).init(math.copysign(h, x) * @cos(y), h * @sin(y));
        }
        // x < 192.7: scale to avoid overflow
        else if (ix < 0x4340b1e7) {
            const v = Complex(f32).init(@abs(x), y);
            const r = ldexp_cexp(v, -1);
            return Complex(f32).init(r.re * math.copysign(@as(f32, 1.0), x), r.im);
        }
        // x >= 192.7: result always overflows
        else {
            const h = 0x1p127 * x;
            return Complex(f32).init(h * @cos(y), h * h * @sin(y));
        }
    }

    if (ix == 0 and iy >= 0x7f800000) {
        return Complex(f32).init(math.copysign(@as(f32, 0.0), x * (y - y)), y - y);
    }

    if (iy == 0 and ix >= 0x7f800000) {
        if (hx & 0x7fffff == 0) {
            return Complex(f32).init(x, y);
        }
        return Complex(f32).init(x, math.copysign(@as(f32, 0.0), y));
    }

    if (ix < 0x7f800000 and iy >= 0x7f800000) {
        return Complex(f32).init(y - y, x * (y - y));
    }

    if (ix >= 0x7f800000 and (hx & 0x7fffff) == 0) {
        if (iy >= 0x7f800000) {
            return Complex(f32).init(x * x, x * (y - y));
        }
        return Complex(f32).init(x * @cos(y), math.inf(f32) * @sin(y));
    }

    return Complex(f32).init((x * x) * (y - y), (x + x) * (y - y));
}

fn sinh64(z: Complex(f64)) Complex(f64) {
    const x = z.re;
    const y = z.im;

    const fx: u64 = @bitCast(x);
    const hx: u32 = @intCast(fx >> 32);
    const lx: u32 = @truncate(fx);
    const ix = hx & 0x7fffffff;

    const fy: u64 = @bitCast(y);
    const hy: u32 = @intCast(fy >> 32);
    const ly: u32 = @truncate(fy);
    const iy = hy & 0x7fffffff;

    if (ix < 0x7ff00000 and iy < 0x7ff00000) {
        if (iy | ly == 0) {
            return Complex(f64).init(math.sinh(x), y);
        }
        // small x: normal case
        if (ix < 0x40360000) {
            return Complex(f64).init(math.sinh(x) * @cos(y), math.cosh(x) * @sin(y));
        }

        // |x|>= 22, so cosh(x) ~= exp(|x|)
        if (ix < 0x40862e42) {
            // x < 710: exp(|x|) won't overflow
            const h = @exp(@abs(x)) * 0.5;
            return Complex(f64).init(math.copysign(h, x) * @cos(y), h * @sin(y));
        }
        // x < 1455: scale to avoid overflow
        else if (ix < 0x4096bbaa) {
            const v = Complex(f64).init(@abs(x), y);
            const r = ldexp_cexp(v, -1);
            return Complex(f64).init(r.re * math.copysign(@as(f64, 1.0), x), r.im);
        }
        // x >= 1455: result always overflows
        else {
            const h = 0x1p1023 * x;
            return Complex(f64).init(h * @cos(y), h * h * @sin(y));
        }
    }

    if (ix | lx == 0 and iy >= 0x7ff00000) {
        return Complex(f64).init(math.copysign(@as(f64, 0.0), x * (y - y)), y - y);
    }

    if (iy | ly == 0 and ix >= 0x7ff00000) {
        if ((hx & 0xfffff) | lx == 0) {
            return Complex(f64).init(x, y);
        }
        return Complex(f64).init(x, math.copysign(@as(f64, 0.0), y));
    }

    if (ix < 0x7ff00000 and iy >= 0x7ff00000) {
        return Complex(f64).init(y - y, x * (y - y));
    }

    if (ix >= 0x7ff00000 and (hx & 0xfffff) | lx == 0) {
        if (iy >= 0x7ff00000) {
            return Complex(f64).init(x * x, x * (y - y));
        }
        return Complex(f64).init(x * @cos(y), math.inf(f64) * @sin(y));
    }

    return Complex(f64).init((x * x) * (y - y), (x + x) * (y - y));
}

test sinh32 {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = sinh(a);

    try testing.expectApproxEqAbs(-73.460617, c.re, epsilon);
    try testing.expectApproxEqAbs(10.472508, c.im, epsilon);
}

test sinh64 {
    const epsilon = math.floatEps(f64);
    const a = Complex(f64).init(5, 3);
    const c = sinh(a);

    try testing.expectApproxEqAbs(-73.46062169567367, c.re, epsilon);
    try testing.expectApproxEqAbs(10.472508533940392, c.im, epsilon);
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/complex/csqrtf.c
// https://git.musl-libc.org/cgit/musl/tree/src/complex/csqrt.c

const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the square root of z. The real and imaginary parts of the result have the same sign
/// as the imaginary part of z.
pub fn sqrt(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);

    return switch (T) {
        f32 => sqrt32(z),
        f64 => sqrt64(z),
        else => @compileError("sqrt not implemented for " ++ @typeName(T)),
    };
}

fn sqrt32(z: Complex(f32)) Complex(f32) {
    const x = z.re;
    const y = z.im;

    if (x == 0 and y == 0) {
        return Complex(f32).init(0, y);
    }
    if (math.isInf(y)) {
        return Complex(f32).init(math.inf(f32), y);
    }
    if (math.isNan(x)) {
        // raise invalid if y is not nan
        const t = (y - y) / (y - y);
        return Complex(f32).init(x, t);
    }
    if (math.isInf(x)) {
        // sqrt(inf + i nan)    = inf + nan i
        // sqrt(inf + iy)       = inf + i0
        // sqrt(-inf + i nan)   = nan +- inf i
        // sqrt(-inf + iy)      = 0 + inf i
        if (math.signbit(x)) {
            return Complex(f32).init(@abs(y - y), math.copysign(x, y));
        } else {
            return Complex(f32).init(x, math.copysign(y - y, y));
        }
    }

    // y = nan special case is handled fine below

    // double-precision avoids overflow with correct rounding.
    const dx = @as(f64, x);
    const dy = @as(f64, y);

    if (dx >= 0) {
        const t = @sqrt((dx + math.hypot(dx, dy)) * 0.5);
        return Complex(f32).init(
            @as(f32, @floatCast(t)),
            @as(f32, @floatCast(dy / (2.0 * t))),
        );
    } else {
        const t = @sqrt((-dx + math.hypot(dx, dy)) * 0.5);
        return Complex(f32).init(
            @as(f32, @floatCast(@abs(y) / (2.0 * t))),
            @as(f32, @floatCast(math.copysign(t, y))),
        );
    }
}

fn sqrt64(z: Complex(f64)) Complex(f64) {
    // may encounter overflow for im,re >= DBL_MAX / (1 + sqrt(2))
    const threshold = 0x1.a827999fcef32p+1022;

    var x = z.re;
    var y = z.im;

    if (x == 0 and y == 0) {
        return Complex(f64).init(0, y);
    }
    if (math.isInf(y)) {
        return Complex(f64).init(math.inf(f64), y);
    }
    if (math.isNan(x)) {
        // raise invalid if y is not nan
        const t = (y - y) / (y - y);
        return Complex(f64).init(x, t);
    }
    if (math.isInf(x)) {
        // sqrt(inf + i nan)    = inf + nan i
        // sqrt(inf + iy)       = inf + i0
        // sqrt(-inf + i nan)   = nan +- inf i
        // sqrt(-inf + iy)      = 0 + inf i
        if (math.signbit(x)) {
            return Complex(f64).init(@abs(y - y), math.copysign(x, y));
        } else {
            return Complex(f64).init(x, math.copysign(y - y, y));
        }
    }

    // y = nan special case is handled fine below

    // scale to avoid overflow
    var scale = false;
    if (@abs(x) >= threshold or @abs(y) >= threshold) {
        x *= 0.25;
        y *= 0.25;
        scale = true;
    }

    var result: Complex(f64) = undefined;
    if (x >= 0) {
        const t = @sqrt((x + math.hypot(x, y)) * 0.5);
        result = Complex(f64).init(t, y / (2.0 * t));
    } else {
        const t = @sqrt((-x + math.hypot(x, y)) * 0.5);
        result = Complex(f64).init(@abs(y) / (2.0 * t), math.copysign(t, y));
    }

    if (scale) {
        result.re *= 2;
        result.im *= 2;
    }

    return result;
}

test sqrt32 {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = sqrt(a);

    try testing.expectApproxEqAbs(2.3271174, c.re, epsilon);
    try testing.expectApproxEqAbs(0.6445742, c.im, epsilon);
}

test sqrt64 {
    const epsilon = math.floatEps(f64);
    const a = Complex(f64).init(5, 3);
    const c = sqrt(a);

    try testing.expectApproxEqAbs(2.3271175190399496, c.re, epsilon);
    try testing.expectApproxEqAbs(0.6445742373246469, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the tangent of z.
pub fn tan(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const q = Complex(T).init(-z.im, z.re);
    const r = cmath.tanh(q);
    return Complex(T).init(r.im, -r.re);
}

test tan {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = tan(a);

    try testing.expectApproxEqAbs(-0.002708233, c.re, epsilon);
    try testing.expectApproxEqAbs(1.0041647, c.im, epsilon);
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/complex/ctanhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/complex/ctanh.c

const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the hyperbolic tangent of z.
pub fn tanh(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    return switch (T) {
        f32 => tanh32(z),
        f64 => tanh64(z),
        else => @compileError("tan not implemented for " ++ @typeName(z)),
    };
}

fn tanh32(z: Complex(f32)) Complex(f32) {
    const x = z.re;
    const y = z.im;

    const hx = @as(u32, @bitCast(x));
    const ix = hx & 0x7fffffff;

    if (ix >= 0x7f800000) {
        if (ix & 0x7fffff != 0) {
            const r = if (y == 0) y else x * y;
            return Complex(f32).init(x, r);
        }
        const xx = @as(f32, @bitCast(hx - 0x40000000));
        const r = if (math.isInf(y)) y else @sin(y) * @cos(y);
        return Complex(f32).init(xx, math.copysign(@as(f32, 0.0), r));
    }

    if (!math.isFinite(y)) {
        const r = if (ix != 0) y - y else x;
        return Complex(f32).init(r, y - y);
    }

    // x >= 11
    if (ix >= 0x41300000) {
        const exp_mx = @exp(-@abs(x));
        return Complex(f32).init(math.copysign(@as(f32, 1.0), x), 4 * @sin(y) * @cos(y) * exp_mx * exp_mx);
    }

    // Kahan's algorithm
    const t = @tan(y);
    const beta = 1.0 + t * t;
    const s = math.sinh(x);
    const rho = @sqrt(1 + s * s);
    const den = 1 + beta * s * s;

    return Complex(f32).init((beta * rho * s) / den, t / den);
}

fn tanh64(z: Complex(f64)) Complex(f64) {
    const x = z.re;
    const y = z.im;

    const fx: u64 = @bitCast(x);
    // TODO: zig should allow this conversion implicitly because it can notice that the value necessarily
    // fits in range.
    const hx: u32 = @intCast(fx >> 32);
    const lx: u32 = @truncate(fx);
    const ix = hx & 0x7fffffff;

    if (ix >= 0x7ff00000) {
        if ((ix & 0xfffff) | lx != 0) {
            const r = if (y == 0) y else x * y;
            return Complex(f64).init(x, r);
        }

        const xx: f64 = @bitCast((@as(u64, hx - 0x40000000) << 32) | lx);
        const r = if (math.isInf(y)) y else @sin(y) * @cos(y);
        return Complex(f64).init(xx, math.copysign(@as(f64, 0.0), r));
    }

    if (!math.isFinite(y)) {
        const r = if (ix != 0) y - y else x;
        return Complex(f64).init(r, y - y);
    }

    // x >= 22
    if (ix >= 0x40360000) {
        const exp_mx = @exp(-@abs(x));
        return Complex(f64).init(math.copysign(@as(f64, 1.0), x), 4 * @sin(y) * @cos(y) * exp_mx * exp_mx);
    }

    // Kahan's algorithm
    const t = @tan(y);
    const beta = 1.0 + t * t;
    const s = math.sinh(x);
    const rho = @sqrt(1 + s * s);
    const den = 1 + beta * s * s;

    return Complex(f64).init((beta * rho * s) / den, t / den);
}

test tanh32 {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = tanh(a);

    try testing.expectApproxEqAbs(0.99991274, c.re, epsilon);
    try testing.expectApproxEqAbs(-0.00002536878, c.im, epsilon);
}

test tanh64 {
    const epsilon = math.floatEps(f64);
    const a = Complex(f64).init(5, 3);
    const c = tanh(a);

    try testing.expectApproxEqAbs(0.9999128201513536, c.re, epsilon);
    try testing.expectApproxEqAbs(-0.00002536867620767604, c.im, epsilon);
}

test "tanh64 musl" {
    const epsilon = math.floatEps(f64);
    const a = Complex(f64).init(std.math.inf(f64), std.math.inf(f64));
    const c = tanh(a);

    try testing.expectApproxEqAbs(1, c.re, epsilon);
    try testing.expectApproxEqAbs(0, c.im, epsilon);
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns a value with the magnitude of `magnitude` and the sign of `sign`.
pub fn copysign(magnitude: anytype, sign: @TypeOf(magnitude)) @TypeOf(magnitude) {
    const T = @TypeOf(magnitude);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).float.bits);
    const sign_bit_mask = @as(TBits, 1) << (@bitSizeOf(T) - 1);
    const mag = @as(TBits, @bitCast(magnitude)) & ~sign_bit_mask;
    const sgn = @as(TBits, @bitCast(sign)) & sign_bit_mask;
    return @as(T, @bitCast(mag | sgn));
}

test copysign {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(copysign(@as(T, 1.0), @as(T, 1.0)) == 1.0);
        try expect(copysign(@as(T, 2.0), @as(T, -2.0)) == -2.0);
        try expect(copysign(@as(T, -3.0), @as(T, 3.0)) == 3.0);
        try expect(copysign(@as(T, -4.0), @as(T, -4.0)) == -4.0);
        try expect(copysign(@as(T, 5.0), @as(T, -500.0)) == -5.0);
        try expect(copysign(math.inf(T), @as(T, -0.0)) == -math.inf(T));
        try expect(copysign(@as(T, 6.0), -math.nan(T)) == -6.0);
    }
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/coshf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/cosh.c

const std = @import("../std.zig");
const math = std.math;
const expo2 = @import("expo2.zig").expo2;
const expect = std.testing.expect;
const maxInt = std.math.maxInt;

/// Returns the hyperbolic cosine of x.
///
/// Special Cases:
///  - cosh(+-0)   = 1
///  - cosh(+-inf) = +inf
///  - cosh(nan)   = nan
pub fn cosh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => cosh32(x),
        f64 => cosh64(x),
        else => @compileError("cosh not implemented for " ++ @typeName(T)),
    };
}

// cosh(x) = (exp(x) + 1 / exp(x)) / 2
//         = 1 + 0.5 * (exp(x) - 1) * (exp(x) - 1) / exp(x)
//         = 1 + (x * x) / 2 + o(x^4)
fn cosh32(x: f32) f32 {
    const u = @as(u32, @bitCast(x));
    const ux = u & 0x7FFFFFFF;
    const ax = @as(f32, @bitCast(ux));

    // |x| < log(2)
    if (ux < 0x3F317217) {
        if (ux < 0x3F800000 - (12 << 23)) {
            math.raiseOverflow();
            return 1.0;
        }
        const t = math.expm1(ax);
        return 1 + t * t / (2 * (1 + t));
    }

    // |x| < log(FLT_MAX)
    if (ux < 0x42B17217) {
        const t = @exp(ax);
        return 0.5 * (t + 1 / t);
    }

    // |x| > log(FLT_MAX) or nan
    return expo2(ax);
}

fn cosh64(x: f64) f64 {
    const u = @as(u64, @bitCast(x));
    const w = @as(u32, @intCast(u >> 32)) & (maxInt(u32) >> 1);
    const ax = @as(f64, @bitCast(u & (maxInt(u64) >> 1)));

    // TODO: Shouldn't need this explicit check.
    if (x == 0.0) {
        return 1.0;
    }

    // |x| < log(2)
    if (w < 0x3FE62E42) {
        if (w < 0x3FF00000 - (26 << 20)) {
            if (x != 0) {
                math.raiseInexact();
            }
            return 1.0;
        }
        const t = math.expm1(ax);
        return 1 + t * t / (2 * (1 + t));
    }

    // |x| < log(DBL_MAX)
    if (w < 0x40862E42) {
        const t = @exp(ax);
        // NOTE: If x > log(0x1p26) then 1/t is not required.
        return 0.5 * (t + 1 / t);
    }

    // |x| > log(CBL_MAX) or nan
    return expo2(ax);
}

test cosh {
    try expect(cosh(@as(f32, 1.5)) == cosh32(1.5));
    try expect(cosh(@as(f64, 1.5)) == cosh64(1.5));
}

test cosh32 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, cosh32(0.0), 1.0, epsilon));
    try expect(math.approxEqAbs(f32, cosh32(0.2), 1.020067, epsilon));
    try expect(math.approxEqAbs(f32, cosh32(0.8923), 1.425225, epsilon));
    try expect(math.approxEqAbs(f32, cosh32(1.5), 2.352410, epsilon));
    try expect(math.approxEqAbs(f32, cosh32(-0.0), 1.0, epsilon));
    try expect(math.approxEqAbs(f32, cosh32(-0.2), 1.020067, epsilon));
    try expect(math.approxEqAbs(f32, cosh32(-0.8923), 1.425225, epsilon));
    try expect(math.approxEqAbs(f32, cosh32(-1.5), 2.352410, epsilon));
}

test cosh64 {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f64, cosh64(0.0), 1.0, epsilon));
    try expect(math.approxEqAbs(f64, cosh64(0.2), 1.020067, epsilon));
    try expect(math.approxEqAbs(f64, cosh64(0.8923), 1.425225, epsilon));
    try expect(math.approxEqAbs(f64, cosh64(1.5), 2.352410, epsilon));
    try expect(math.approxEqAbs(f64, cosh64(-0.0), 1.0, epsilon));
    try expect(math.approxEqAbs(f64, cosh64(-0.2), 1.020067, epsilon));
    try expect(math.approxEqAbs(f64, cosh64(-0.8923), 1.425225, epsilon));
    try expect(math.approxEqAbs(f64, cosh64(-1.5), 2.352410, epsilon));
}

test "cosh32.special" {
    try expect(cosh32(0.0) == 1.0);
    try expect(cosh32(-0.0) == 1.0);
    try expect(math.isPositiveInf(cosh32(math.inf(f32))));
    try expect(math.isPositiveInf(cosh32(-math.inf(f32))));
    try expect(math.isNan(cosh32(math.nan(f32))));
}

test "cosh64.special" {
    try expect(cosh64(0.0) == 1.0);
    try expect(cosh64(-0.0) == 1.0);
    try expect(math.isPositiveInf(cosh64(math.inf(f64))));
    try expect(math.isPositiveInf(cosh64(-math.inf(f64))));
    try expect(math.isNan(cosh64(math.nan(f64))));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/expmf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/expm.c

// TODO: Updated recently.

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;

/// Returns e raised to the power of x, minus 1 (e^x - 1). This is more accurate than exp(e, x) - 1
/// when x is near 0.
///
/// Special Cases:
///  - expm1(+inf) = +inf
///  - expm1(-inf) = -1
///  - expm1(nan)  = nan
pub fn expm1(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => expm1_32(x),
        f64 => expm1_64(x),
        else => @compileError("exp1m not implemented for " ++ @typeName(T)),
    };
}

fn expm1_32(x_: f32) f32 {
    if (math.isNan(x_))
        return math.nan(f32);

    const o_threshold: f32 = 8.8721679688e+01;
    const ln2_hi: f32 = 6.9313812256e-01;
    const ln2_lo: f32 = 9.0580006145e-06;
    const invln2: f32 = 1.4426950216e+00;
    const Q1: f32 = -3.3333212137e-2;
    const Q2: f32 = 1.5807170421e-3;

    var x = x_;
    const ux = @as(u32, @bitCast(x));
    const hx = ux & 0x7FFFFFFF;
    const sign = hx >> 31;

    // TODO: Shouldn't need this check explicitly.
    if (math.isNegativeInf(x)) {
        return -1.0;
    }

    // |x| >= 27 * ln2
    if (hx >= 0x4195B844) {
        // nan
        if (hx > 0x7F800000) {
            return x;
        }
        if (sign != 0) {
            return -1;
        }
        if (x > o_threshold) {
            x *= 0x1.0p127;
            return x;
        }
    }

    var hi: f32 = undefined;
    var lo: f32 = undefined;
    var c: f32 = undefined;
    var k: i32 = undefined;

    // |x| > 0.5 * ln2
    if (hx > 0x3EB17218) {
        // |x| < 1.5 * ln2
        if (hx < 0x3F851592) {
            if (sign == 0) {
                hi = x - ln2_hi;
                lo = ln2_lo;
                k = 1;
            } else {
                hi = x + ln2_hi;
                lo = -ln2_lo;
                k = -1;
            }
        } else {
            var kf = invln2 * x;
            if (sign != 0) {
                kf -= 0.5;
            } else {
                kf += 0.5;
            }

            k = @as(i32, @intFromFloat(kf));
            const t = @as(f32, @floatFromInt(k));
            hi = x - t * ln2_hi;
            lo = t * ln2_lo;
        }

        x = hi - lo;
        c = (hi - x) - lo;
    }
    // |x| < 2^(-25)
    else if (hx < 0x33000000) {
        if (hx < 0x00800000) {
            mem.doNotOptimizeAway(x * x);
        }
        return x;
    } else {
        k = 0;
    }

    const hfx = 0.5 * x;
    const hxs = x * hfx;
    const r1 = 1.0 + hxs * (Q1 + hxs * Q2);
    const t = 3.0 - r1 * hfx;
    var e = hxs * ((r1 - t) / (6.0 - x * t));

    // c is 0
    if (k == 0) {
        return x - (x * e - hxs);
    }

    e = x * (e - c) - c;
    e -= hxs;

    // exp(x) ~ 2^k (x_reduced - e + 1)
    if (k == -1) {
        return 0.5 * (x - e) - 0.5;
    }
    if (k == 1) {
        if (x < -0.25) {
            return -2.0 * (e - (x + 0.5));
        } else {
            return 1.0 + 2.0 * (x - e);
        }
    }

    const twopk = @as(f32, @bitCast(@as(u32, @intCast((0x7F +% k) << 23))));

    if (k < 0 or k > 56) {
        var y = x - e + 1.0;
        if (k == 128) {
            y = y * 2.0 * 0x1.0p127;
        } else {
            y = y * twopk;
        }

        return y - 1.0;
    }

    const uf = @as(f32, @bitCast(@as(u32, @intCast(0x7F -% k)) << 23));
    if (k < 23) {
        return (x - e + (1 - uf)) * twopk;
    } else {
        return (x - (e + uf) + 1) * twopk;
    }
}

fn expm1_64(x_: f64) f64 {
    if (math.isNan(x_))
        return math.nan(f64);

    const o_threshold: f64 = 7.09782712893383973096e+02;
    const ln2_hi: f64 = 6.93147180369123816490e-01;
    const ln2_lo: f64 = 1.90821492927058770002e-10;
    const invln2: f64 = 1.44269504088896338700e+00;
    const Q1: f64 = -3.33333333333331316428e-02;
    const Q2: f64 = 1.58730158725481460165e-03;
    const Q3: f64 = -7.93650757867487942473e-05;
    const Q4: f64 = 4.00821782732936239552e-06;
    const Q5: f64 = -2.01099218183624371326e-07;

    var x = x_;
    const ux = @as(u64, @bitCast(x));
    const hx = @as(u32, @intCast(ux >> 32)) & 0x7FFFFFFF;
    const sign = ux >> 63;

    if (math.isNegativeInf(x)) {
        return -1.0;
    }

    // |x| >= 56 * ln2
    if (hx >= 0x4043687A) {
        // exp1md(nan) = nan
        if (hx > 0x7FF00000) {
            return x;
        }
        // exp1md(-ve) = -1
        if (sign != 0) {
            return -1;
        }
        if (x > o_threshold) {
            math.raiseOverflow();
            return math.inf(f64);
        }
    }

    var hi: f64 = undefined;
    var lo: f64 = undefined;
    var c: f64 = undefined;
    var k: i32 = undefined;

    // |x| > 0.5 * ln2
    if (hx > 0x3FD62E42) {
        // |x| < 1.5 * ln2
        if (hx < 0x3FF0A2B2) {
            if (sign == 0) {
                hi = x - ln2_hi;
                lo = ln2_lo;
                k = 1;
            } else {
                hi = x + ln2_hi;
                lo = -ln2_lo;
                k = -1;
            }
        } else {
            var kf = invln2 * x;
            if (sign != 0) {
                kf -= 0.5;
            } else {
                kf += 0.5;
            }

            k = @as(i32, @intFromFloat(kf));
            const t = @as(f64, @floatFromInt(k));
            hi = x - t * ln2_hi;
            lo = t * ln2_lo;
        }

        x = hi - lo;
        c = (hi - x) - lo;
    }
    // |x| < 2^(-54)
    else if (hx < 0x3C900000) {
        if (hx < 0x00100000) {
            mem.doNotOptimizeAway(@as(f32, @floatCast(x)));
        }
        return x;
    } else {
        k = 0;
    }

    const hfx = 0.5 * x;
    const hxs = x * hfx;
    const r1 = 1.0 + hxs * (Q1 + hxs * (Q2 + hxs * (Q3 + hxs * (Q4 + hxs * Q5))));
    const t = 3.0 - r1 * hfx;
    var e = hxs * ((r1 - t) / (6.0 - x * t));

    // c is 0
    if (k == 0) {
        return x - (x * e - hxs);
    }

    e = x * (e - c) - c;
    e -= hxs;

    // exp(x) ~ 2^k (x_reduced - e + 1)
    if (k == -1) {
        return 0.5 * (x - e) - 0.5;
    }
    if (k == 1) {
        if (x < -0.25) {
            return -2.0 * (e - (x + 0.5));
        } else {
            return 1.0 + 2.0 * (x - e);
        }
    }

    const twopk = @as(f64, @bitCast(@as(u64, @intCast(0x3FF +% k)) << 52));

    if (k < 0 or k > 56) {
        var y = x - e + 1.0;
        if (k == 1024) {
            y = y * 2.0 * 0x1.0p1023;
        } else {
            y = y * twopk;
        }

        return y - 1.0;
    }

    const uf = @as(f64, @bitCast(@as(u64, @intCast(0x3FF -% k)) << 52));
    if (k < 20) {
        return (x - e + (1 - uf)) * twopk;
    } else {
        return (x - (e + uf) + 1) * twopk;
    }
}

test expm1 {
    try expect(expm1(@as(f32, 0.0)) == expm1_32(0.0));
    try expect(expm1(@as(f64, 0.0)) == expm1_64(0.0));
}

test expm1_32 {
    const epsilon = 0.000001;

    try expect(math.isPositiveZero(expm1_32(0.0)));
    try expect(math.approxEqAbs(f32, expm1_32(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f32, expm1_32(0.2), 0.221403, epsilon));
    try expect(math.approxEqAbs(f32, expm1_32(0.8923), 1.440737, epsilon));
    try expect(math.approxEqAbs(f32, expm1_32(1.5), 3.481689, epsilon));
}

test expm1_64 {
    const epsilon = 0.000001;

    try expect(math.isPositiveZero(expm1_64(0.0)));
    try expect(math.approxEqAbs(f64, expm1_64(0.0), 0.0, epsilon));
    try expect(math.approxEqAbs(f64, expm1_64(0.2), 0.221403, epsilon));
    try expect(math.approxEqAbs(f64, expm1_64(0.8923), 1.440737, epsilon));
    try expect(math.approxEqAbs(f64, expm1_64(1.5), 3.481689, epsilon));
}

test "expm1_32.special" {
    try expect(math.isPositiveInf(expm1_32(math.inf(f32))));
    try expect(expm1_32(-math.inf(f32)) == -1.0);
    try expect(math.isNan(expm1_32(math.nan(f32))));
}

test "expm1_64.special" {
    try expect(math.isPositiveInf(expm1_64(math.inf(f64))));
    try expect(expm1_64(-math.inf(f64)) == -1.0);
    try expect(math.isNan(expm1_64(math.nan(f64))));
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/__expo2f.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/__expo2.c

const math = @import("../math.zig");

/// Returns exp(x) / 2 for x >= log(maxFloat(T)).
pub fn expo2(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => expo2f(x),
        f64 => expo2d(x),
        else => @compileError("expo2 not implemented for " ++ @typeName(T)),
    };
}

fn expo2f(x: f32) f32 {
    const k: u32 = 235;
    const kln2 = 0x1.45C778p+7;

    const u = (0x7F + k / 2) << 23;
    const scale = @as(f32, @bitCast(u));
    return @exp(x - kln2) * scale * scale;
}

fn expo2d(x: f64) f64 {
    const k: u32 = 2043;
    const kln2 = 0x1.62066151ADD8BP+10;

    const u = (0x3FF + k / 2) << 20;
    const scale = @as(f64, @bitCast(@as(u64, u) << 32));
    return @exp(x - kln2) * scale * scale;
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

/// Creates a raw "1.0" mantissa for floating point type T. Used to dedupe f80 logic.
inline fn mantissaOne(comptime T: type) comptime_int {
    return if (@typeInfo(T).float.bits == 80) 1 << floatFractionalBits(T) else 0;
}

/// Creates floating point type T from an unbiased exponent and raw mantissa.
inline fn reconstructFloat(comptime T: type, comptime exponent: comptime_int, comptime mantissa: comptime_int) T {
    const TBits = @Type(.{ .int = .{ .signedness = .unsigned, .bits = @bitSizeOf(T) } });
    const biased_exponent = @as(TBits, exponent + floatExponentMax(T));
    return @as(T, @bitCast((biased_exponent << floatMantissaBits(T)) | @as(TBits, mantissa)));
}

/// Returns the number of bits in the exponent of floating point type T.
pub inline fn floatExponentBits(comptime T: type) comptime_int {
    comptime assert(@typeInfo(T) == .float);

    return switch (@typeInfo(T).float.bits) {
        16 => 5,
        32 => 8,
        64 => 11,
        80 => 15,
        128 => 15,
        else => @compileError("unknown floating point type " ++ @typeName(T)),
    };
}

/// Returns the number of bits in the mantissa of floating point type T.
pub inline fn floatMantissaBits(comptime T: type) comptime_int {
    comptime assert(@typeInfo(T) == .float);

    return switch (@typeInfo(T).float.bits) {
        16 => 10,
        32 => 23,
        64 => 52,
        80 => 64,
        128 => 112,
        else => @compileError("unknown floating point type " ++ @typeName(T)),
    };
}

/// Returns the number of fractional bits in the mantissa of floating point type T.
pub inline fn floatFractionalBits(comptime T: type) comptime_int {
    comptime assert(@typeInfo(T) == .float);

    // standard IEEE floats have an implicit 0.m or 1.m integer part
    // f80 is special and has an explicitly stored bit in the MSB
    // this function corresponds to `MANT_DIG - 1' from C
    return switch (@typeInfo(T).float.bits) {
        16 => 10,
        32 => 23,
        64 => 52,
        80 => 63,
        128 => 112,
        else => @compileError("unknown floating point type " ++ @typeName(T)),
    };
}

/// Returns the minimum exponent that can represent
/// a normalised value in floating point type T.
pub inline fn floatExponentMin(comptime T: type) comptime_int {
    return -floatExponentMax(T) + 1;
}

/// Returns the maximum exponent that can represent
/// a normalised value in floating point type T.
pub inline fn floatExponentMax(comptime T: type) comptime_int {
    return (1 << (floatExponentBits(T) - 1)) - 1;
}

/// Returns the smallest subnormal number representable in floating point type T.
pub inline fn floatTrueMin(comptime T: type) T {
    return reconstructFloat(T, floatExponentMin(T) - 1, 1);
}

/// Returns the smallest normal number representable in floating point type T.
pub inline fn floatMin(comptime T: type) T {
    return reconstructFloat(T, floatExponentMin(T), mantissaOne(T));
}

/// Returns the largest normal number representable in floating point type T.
pub inline fn floatMax(comptime T: type) T {
    const all1s_mantissa = (1 << floatMantissaBits(T)) - 1;
    return reconstructFloat(T, floatExponentMax(T), all1s_mantissa);
}

/// Returns the machine epsilon of floating point type T.
pub inline fn floatEps(comptime T: type) T {
    return reconstructFloat(T, -floatFractionalBits(T), mantissaOne(T));
}

/// Returns the local epsilon of floating point type T.
pub inline fn floatEpsAt(comptime T: type, x: T) T {
    switch (@typeInfo(T)) {
        .float => |F| {
            const U: type = @Type(.{ .int = .{ .signedness = .unsigned, .bits = F.bits } });
            const u: U = @bitCast(x);
            const y: T = @bitCast(u ^ 1);
            return @abs(x - y);
        },
        else => @compileError("floatEpsAt only supports floats"),
    }
}

/// Returns the value inf for floating point type T.
pub inline fn inf(comptime T: type) T {
    return reconstructFloat(T, floatExponentMax(T) + 1, mantissaOne(T));
}

/// Returns the canonical quiet NaN representation for floating point type T.
pub inline fn nan(comptime T: type) T {
    return reconstructFloat(
        T,
        floatExponentMax(T) + 1,
        mantissaOne(T) | 1 << (floatFractionalBits(T) - 1),
    );
}

/// Returns a signalling NaN representation for floating point type T.
///
/// TODO: LLVM is known to miscompile on some architectures to quiet NaN -
///       this is tracked by https://github.com/ziglang/zig/issues/14366
pub inline fn snan(comptime T: type) T {
    return reconstructFloat(
        T,
        floatExponentMax(T) + 1,
        mantissaOne(T) | 1 << (floatFractionalBits(T) - 2),
    );
}

test "float bits" {
    inline for ([_]type{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        // (1 +) for the sign bit, since it is separate from the other bits
        const size = 1 + floatExponentBits(T) + floatMantissaBits(T);
        try expect(@bitSizeOf(T) == size);

        // for machine epsilon, assert expmin <= -prec <= expmax
        try expect(floatExponentMin(T) <= -floatFractionalBits(T));
        try expect(-floatFractionalBits(T) <= floatExponentMax(T));
    }
}

test inf {
    const inf_u16: u16 = 0x7C00;
    const inf_u32: u32 = 0x7F800000;
    const inf_u64: u64 = 0x7FF0000000000000;
    const inf_u80: u80 = 0x7FFF8000000000000000;
    const inf_u128: u128 = 0x7FFF0000000000000000000000000000;
    try expectEqual(inf_u16, @as(u16, @bitCast(inf(f16))));
    try expectEqual(inf_u32, @as(u32, @bitCast(inf(f32))));
    try expectEqual(inf_u64, @as(u64, @bitCast(inf(f64))));
    try expectEqual(inf_u80, @as(u80, @bitCast(inf(f80))));
    try expectEqual(inf_u128, @as(u128, @bitCast(inf(f128))));
}

test nan {
    const qnan_u16: u16 = 0x7E00;
    const qnan_u32: u32 = 0x7FC00000;
    const qnan_u64: u64 = 0x7FF8000000000000;
    const qnan_u80: u80 = 0x7FFFC000000000000000;
    const qnan_u128: u128 = 0x7FFF8000000000000000000000000000;
    try expectEqual(qnan_u16, @as(u16, @bitCast(nan(f16))));
    try expectEqual(qnan_u32, @as(u32, @bitCast(nan(f32))));
    try expectEqual(qnan_u64, @as(u64, @bitCast(nan(f64))));
    try expectEqual(qnan_u80, @as(u80, @bitCast(nan(f80))));
    try expectEqual(qnan_u128, @as(u128, @bitCast(nan(f128))));
}

test snan {
    const snan_u16: u16 = 0x7D00;
    const snan_u32: u32 = 0x7FA00000;
    const snan_u64: u64 = 0x7FF4000000000000;
    const snan_u80: u80 = 0x7FFFA000000000000000;
    const snan_u128: u128 = 0x7FFF4000000000000000000000000000;
    try expectEqual(snan_u16, @as(u16, @bitCast(snan(f16))));
    try expectEqual(snan_u32, @as(u32, @bitCast(snan(f32))));
    try expectEqual(snan_u64, @as(u64, @bitCast(snan(f64))));
    try expectEqual(snan_u80, @as(u80, @bitCast(snan(f80))));
    try expectEqual(snan_u128, @as(u128, @bitCast(snan(f128))));
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectApproxEqAbs = std.testing.expectApproxEqAbs;

pub fn Frexp(comptime T: type) type {
    return struct {
        significand: T,
        exponent: i32,
    };
}

/// Breaks x into a normalized fraction and an integral power of two.
/// f == frac * 2^exp, with |frac| in the interval [0.5, 1).
///
/// Special Cases:
///  - frexp(+-0)   = +-0, 0
///  - frexp(+-inf) = +-inf, 0
///  - frexp(nan)   = nan, undefined
pub fn frexp(x: anytype) Frexp(@TypeOf(x)) {
    const T: type = @TypeOf(x);

    const bits: comptime_int = @typeInfo(T).float.bits;
    const Int: type = std.meta.Int(.unsigned, bits);

    const exp_bits: comptime_int = math.floatExponentBits(T);
    const mant_bits: comptime_int = math.floatMantissaBits(T);
    const frac_bits: comptime_int = math.floatFractionalBits(T);
    const exp_min: comptime_int = math.floatExponentMin(T);

    const ExpInt: type = std.meta.Int(.unsigned, exp_bits);
    const MantInt: type = std.meta.Int(.unsigned, mant_bits);
    const FracInt: type = std.meta.Int(.unsigned, frac_bits);

    const unreal_exponent: comptime_int = (1 << exp_bits) - 1;
    const bias: comptime_int = (1 << (exp_bits - 1)) - 2;
    const exp_mask: comptime_int = unreal_exponent << mant_bits;
    const zero_exponent: comptime_int = bias << mant_bits;
    const sign_mask: comptime_int = 1 << (bits - 1);
    const not_exp: comptime_int = ~@as(Int, exp_mask);
    const ones_place: comptime_int = mant_bits - frac_bits;
    const extra_denorm_shift: comptime_int = 1 - ones_place;

    var result: Frexp(T) = undefined;
    var v: Int = @bitCast(x);

    const m: MantInt = @truncate(v);
    const e: ExpInt = @truncate(v >> mant_bits);

    switch (e) {
        0 => {
            if (m != 0) {
                // subnormal
                const offset = @clz(m);
                const shift = offset + extra_denorm_shift;

                v &= sign_mask;
                v |= zero_exponent;
                v |= math.shl(MantInt, m, shift);

                result.exponent = exp_min - @as(i32, offset) + ones_place;
            } else {
                // +-0 = (+-0, 0)
                result.exponent = 0;
            }
        },
        unreal_exponent => {
            // +-nan -> {+-nan, undefined}
            result.exponent = undefined;

            // +-inf -> {+-inf, 0}
            if (@as(FracInt, @truncate(v)) == 0)
                result.exponent = 0;
        },
        else => {
            // normal
            v &= not_exp;
            v |= zero_exponent;
            result.exponent = @as(i32, e) - bias;
        },
    }

    result.significand = @bitCast(v);
    return result;
}

/// Generate a namespace of tests for frexp on values of the given type
fn FrexpTests(comptime Float: type) type {
    return struct {
        const T = Float;
        test "normal" {
            const epsilon = 1e-6;
            var r: Frexp(T) = undefined;

            r = frexp(@as(T, 1.3));
            try expectApproxEqAbs(0.65, r.significand, epsilon);
            try expectEqual(1, r.exponent);

            r = frexp(@as(T, 78.0234));
            try expectApproxEqAbs(0.609558, r.significand, epsilon);
            try expectEqual(7, r.exponent);

            r = frexp(@as(T, -1234.5678));
            try expectEqual(11, r.exponent);
            try expectApproxEqAbs(-0.602816, r.significand, epsilon);
        }
        test "max" {
            const exponent = math.floatExponentMax(T) + 1;
            const significand = 1.0 - math.floatEps(T) / 2;
            const r: Frexp(T) = frexp(math.floatMax(T));
            try expectEqual(exponent, r.exponent);
            try expectEqual(significand, r.significand);
        }
        test "min" {
            const exponent = math.floatExponentMin(T) + 1;
            const r: Frexp(T) = frexp(math.floatMin(T));
            try expectEqual(exponent, r.exponent);
            try expectEqual(0.5, r.significand);
        }
        test "subnormal" {
            const normal_min_exponent = math.floatExponentMin(T) + 1;
            const exponent = normal_min_exponent - math.floatFractionalBits(T);
            const r: Frexp(T) = frexp(math.floatTrueMin(T));
            try expectEqual(exponent, r.exponent);
            try expectEqual(0.5, r.significand);
        }
        test "zero" {
            var r: Frexp(T) = undefined;

            r = frexp(@as(T, 0.0));
            try expectEqual(0, r.exponent);
            try expect(math.isPositiveZero(r.significand));

            r = frexp(@as(T, -0.0));
            try expectEqual(0, r.exponent);
            try expect(math.isNegativeZero(r.significand));
        }
        test "inf" {
            var r: Frexp(T) = undefined;

            r = frexp(math.inf(T));
            try expectEqual(0, r.exponent);
            try expect(math.isPositiveInf(r.significand));

            r = frexp(-math.inf(T));
            try expectEqual(0, r.exponent);
            try expect(math.isNegativeInf(r.significand));
        }
        test "nan" {
            const r: Frexp(T) = frexp(math.nan(T));
            try expect(math.isNan(r.significand));
        }
    };
}

// Generate tests for each floating point type
comptime {
    for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        _ = FrexpTests(T);
    }
}

test frexp {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        const max_exponent = math.floatExponentMax(T) + 1;
        const min_exponent = math.floatExponentMin(T) + 1;
        const truemin_exponent = min_exponent - math.floatFractionalBits(T);

        var result: Frexp(T) = undefined;
        comptime var x: T = undefined;

        // basic usage
        // value -> {significand, exponent},
        // value == significand * (2 ^ exponent)
        x = 1234.5678;
        result = frexp(x);
        try expectEqual(11, result.exponent);
        try expectApproxEqAbs(0.602816, result.significand, 1e-6);
        try expectEqual(x, math.ldexp(result.significand, result.exponent));

        // float maximum
        x = math.floatMax(T);
        result = frexp(x);
        try expectEqual(max_exponent, result.exponent);
        try expectEqual(1.0 - math.floatEps(T) / 2, result.significand);
        try expectEqual(x, math.ldexp(result.significand, result.exponent));

        // float minimum
        x = math.floatMin(T);
        result = frexp(x);
        try expectEqual(min_exponent, result.exponent);
        try expectEqual(0.5, result.significand);
        try expectEqual(x, math.ldexp(result.significand, result.exponent));

        // float true minimum
        // subnormal -> {normal, exponent}
        x = math.floatTrueMin(T);
        result = frexp(x);
        try expectEqual(truemin_exponent, result.exponent);
        try expectEqual(0.5, result.significand);
        try expectEqual(x, math.ldexp(result.significand, result.exponent));

        // infinity -> {infinity, zero} (+)
        result = frexp(math.inf(T));
        try expectEqual(0, result.exponent);
        try expect(math.isPositiveInf(result.significand));

        // infinity -> {infinity, zero} (-)
        result = frexp(-math.inf(T));
        try expectEqual(0, result.exponent);
        try expect(math.isNegativeInf(result.significand));

        // zero -> {zero, zero} (+)
        result = frexp(@as(T, 0.0));
        try expectEqual(0, result.exponent);
        try expect(math.isPositiveZero(result.significand));

        // zero -> {zero, zero} (-)
        result = frexp(@as(T, -0.0));
        try expectEqual(0, result.exponent);
        try expect(math.isNegativeZero(result.significand));

        // nan -> {nan, undefined}
        result = frexp(math.nan(T));
        try expect(math.isNan(result.significand));
    }
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/tgamma.c

const builtin = @import("builtin");
const std = @import("../std.zig");

/// Returns the gamma function of x,
/// gamma(x) = factorial(x - 1) for integer x.
///
/// Special Cases:
///  - gamma(+-nan) = nan
///  - gamma(-inf)  = nan
///  - gamma(n)     = nan for negative integers
///  - gamma(-0.0)  = -inf
///  - gamma(+0.0)  = +inf
///  - gamma(+inf)  = +inf
pub fn gamma(comptime T: type, x: T) T {
    if (T != f32 and T != f64) {
        @compileError("gamma not implemented for " ++ @typeName(T));
    }
    // common integer case first
    if (x == @trunc(x)) {
        // gamma(-inf) = nan
        // gamma(n)    = nan for negative integers
        if (x < 0) {
            return std.math.nan(T);
        }
        // gamma(-0.0) = -inf
        // gamma(+0.0) = +inf
        if (x == 0) {
            return 1 / x;
        }
        if (x < integer_result_table.len) {
            const i = @as(u8, @intFromFloat(x));
            return @floatCast(integer_result_table[i]);
        }
    }
    // below this, result underflows, but has a sign
    // negative for (-1,  0)
    // positive for (-2, -1)
    // negative for (-3, -2)
    // ...
    const lower_bound = if (T == f64) -184 else -42;
    if (x < lower_bound) {
        return if (@mod(x, 2) > 1) -0.0 else 0.0;
    }
    // above this, result overflows
    // gamma(+inf) = +inf
    const upper_bound = if (T == f64) 172 else 36;
    if (x > upper_bound) {
        return std.math.inf(T);
    }

    const abs = @abs(x);
    // perfect precision here
    if (abs < 0x1p-54) {
        return 1 / x;
    }

    const base = abs + lanczos_minus_half;
    const exponent = abs - 0.5;
    // error of y for correction, see
    // https://github.com/python/cpython/blob/5dc79e3d7f26a6a871a89ce3efc9f1bcee7bb447/Modules/mathmodule.c#L286-L324
    const e = if (abs > lanczos_minus_half)
        base - abs - lanczos_minus_half
    else
        base - lanczos_minus_half - abs;
    const correction = lanczos * e / base;
    const initial = series(T, abs) * @exp(-base);

    // use reflection formula for negatives
    if (x < 0) {
        const reflected = -std.math.pi / (abs * sinpi(T, abs) * initial);
        const corrected = reflected - reflected * correction;
        const half_pow = std.math.pow(T, base, -0.5 * exponent);
        return corrected * half_pow * half_pow;
    } else {
        const corrected = initial + initial * correction;
        const half_pow = std.math.pow(T, base, 0.5 * exponent);
        return corrected * half_pow * half_pow;
    }
}

/// Returns the natural logarithm of the absolute value of the gamma function.
///
/// Special Cases:
///  - lgamma(+-nan) = nan
///  - lgamma(+-inf) = +inf
///  - lgamma(n)     = +inf for negative integers
///  - lgamma(+-0.0) = +inf
///  - lgamma(1)     = +0.0
///  - lgamma(2)     = +0.0
pub fn lgamma(comptime T: type, x: T) T {
    if (T != f32 and T != f64) {
        @compileError("gamma not implemented for " ++ @typeName(T));
    }
    // common integer case first
    if (x == @trunc(x)) {
        // lgamma(-inf)  = +inf
        // lgamma(n)     = +inf for negative integers
        // lgamma(+-0.0) = +inf
        if (x <= 0) {
            return std.math.inf(T);
        }
        // lgamma(1) = +0.0
        // lgamma(2) = +0.0
        if (x < integer_result_table.len) {
            const i = @as(u8, @intFromFloat(x));
            return @log(@as(T, @floatCast(integer_result_table[i])));
        }
        // lgamma(+inf) = +inf
        if (std.math.isPositiveInf(x)) {
            return x;
        }
    }

    const abs = @abs(x);
    // perfect precision here
    if (abs < 0x1p-54) {
        return -@log(abs);
    }
    // obvious approach when overflow is not a problem
    const upper_bound = if (T == f64) 128 else 26;
    if (abs < upper_bound) {
        return @log(@abs(gamma(T, x)));
    }

    const log_base = @log(abs + lanczos_minus_half) - 1;
    const exponent = abs - 0.5;
    const log_series = @log(series(T, abs));
    const initial = exponent * log_base + log_series - lanczos;

    // use reflection formula for negatives
    if (x < 0) {
        const reflected = std.math.pi / (abs * sinpi(T, abs));
        return @log(@abs(reflected)) - initial;
    }
    return initial;
}

// table of factorials for integer early return
// stops at 22 because 23 isn't representable with full precision on f64
const integer_result_table = [_]f64{
    std.math.inf(f64), // gamma(+0.0)
    1, // gamma(1)
    1, // ...
    2,
    6,
    24,
    120,
    720,
    5040,
    40320,
    362880,
    3628800,
    39916800,
    479001600,
    6227020800,
    87178291200,
    1307674368000,
    20922789888000,
    355687428096000,
    6402373705728000,
    121645100408832000,
    2432902008176640000,
    51090942171709440000, // gamma(22)
};

// "g" constant, arbitrary
const lanczos = 6.024680040776729583740234375;
const lanczos_minus_half = lanczos - 0.5;

fn series(comptime T: type, abs: T) T {
    const numerator = [_]T{
        23531376880.410759688572007674451636754734846804940,
        42919803642.649098768957899047001988850926355848959,
        35711959237.355668049440185451547166705960488635843,
        17921034426.037209699919755754458931112671403265390,
        6039542586.3520280050642916443072979210699388420708,
        1439720407.3117216736632230727949123939715485786772,
        248874557.86205415651146038641322942321632125127801,
        31426415.585400194380614231628318205362874684987640,
        2876370.6289353724412254090516208496135991145378768,
        186056.26539522349504029498971604569928220784236328,
        8071.6720023658162106380029022722506138218516325024,
        210.82427775157934587250973392071336271166969580291,
        2.5066282746310002701649081771338373386264310793408,
    };
    const denominator = [_]T{
        0,
        39916800,
        120543840,
        150917976,
        105258076,
        45995730,
        13339535,
        2637558,
        357423,
        32670,
        1925,
        66,
        1,
    };
    var num: T = 0;
    var den: T = 0;
    // split to avoid overflow
    if (abs < 8) {
        // big abs would overflow here
        for (0..numerator.len) |i| {
            num = num * abs + numerator[numerator.len - 1 - i];
            den = den * abs + denominator[numerator.len - 1 - i];
        }
    } else {
        // small abs would overflow here
        for (0..numerator.len) |i| {
            num = num / abs + numerator[i];
            den = den / abs + denominator[i];
        }
    }
    return num / den;
}

// precise sin(pi * x)
// but not for integer x or |x| < 2^-54, we handle those already
fn sinpi(comptime T: type, x: T) T {
    const xmod2 = @mod(x, 2); // [0, 2]
    const n = (@as(u8, @intFromFloat(4 * xmod2)) + 1) / 2; // {0, 1, 2, 3, 4}
    const y = xmod2 - 0.5 * @as(T, @floatFromInt(n)); // [-0.25, 0.25]
    return switch (n) {
        0, 4 => @sin(std.math.pi * y),
        1 => @cos(std.math.pi * y),
        2 => -@sin(std.math.pi * y),
        3 => -@cos(std.math.pi * y),
        else => unreachable,
    };
}

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectApproxEqRel = std.testing.expectApproxEqRel;

test gamma {
    inline for (&.{ f32, f64 }) |T| {
        const eps = @sqrt(std.math.floatEps(T));
        try expectApproxEqRel(@as(T, 120), gamma(T, 6), eps);
        try expectApproxEqRel(@as(T, 362880), gamma(T, 10), eps);
        try expectApproxEqRel(@as(T, 6402373705728000), gamma(T, 19), eps);

        try expectApproxEqRel(@as(T, 332.7590766955334570), gamma(T, 0.003), eps);
        try expectApproxEqRel(@as(T, 1.377260301981044573), gamma(T, 0.654), eps);
        try expectApproxEqRel(@as(T, 1.025393882573518478), gamma(T, 0.959), eps);

        try expectApproxEqRel(@as(T, 7.361898021467681690), gamma(T, 4.16), eps);
        try expectApproxEqRel(@as(T, 198337.2940287730753), gamma(T, 9.73), eps);
        try expectApproxEqRel(@as(T, 113718145797241.1666), gamma(T, 17.6), eps);

        try expectApproxEqRel(@as(T, -1.13860211111081424930673), gamma(T, -2.80), eps);
        try expectApproxEqRel(@as(T, 0.00018573407931875070158), gamma(T, -7.74), eps);
        try expectApproxEqRel(@as(T, -0.00000001647990903942825), gamma(T, -12.1), eps);
    }
}

test "gamma.special" {
    if (builtin.cpu.arch.isArm() and builtin.target.abi.float() == .soft) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/21234

    inline for (&.{ f32, f64 }) |T| {
        try expect(std.math.isNan(gamma(T, -std.math.nan(T))));
        try expect(std.math.isNan(gamma(T, std.math.nan(T))));
        try expect(std.math.isNan(gamma(T, -std.math.inf(T))));

        try expect(std.math.isNan(gamma(T, -4)));
        try expect(std.math.isNan(gamma(T, -11)));
        try expect(std.math.isNan(gamma(T, -78)));

        try expectEqual(-std.math.inf(T), gamma(T, -0.0));
        try expectEqual(std.math.inf(T), gamma(T, 0.0));

        try expect(std.math.isNegativeZero(gamma(T, -200.5)));
        try expect(std.math.isPositiveZero(gamma(T, -201.5)));
        try expect(std.math.isNegativeZero(gamma(T, -202.5)));

        try expectEqual(std.math.inf(T), gamma(T, 200));
        try expectEqual(std.math.inf(T), gamma(T, 201));
        try expectEqual(std.math.inf(T), gamma(T, 202));

        try expectEqual(std.math.inf(T), gamma(T, std.math.inf(T)));
    }
}

test lgamma {
    inline for (&.{ f32, f64 }) |T| {
        const eps = @sqrt(std.math.floatEps(T));
        try expectApproxEqRel(@as(T, @log(24.0)), lgamma(T, 5), eps);
        try expectApproxEqRel(@as(T, @log(20922789888000.0)), lgamma(T, 17), eps);
        try expectApproxEqRel(@as(T, @log(2432902008176640000.0)), lgamma(T, 21), eps);

        try expectApproxEqRel(@as(T, 2.201821590438859327), lgamma(T, 0.105), eps);
        try expectApproxEqRel(@as(T, 1.275416975248413231), lgamma(T, 0.253), eps);
        try expectApproxEqRel(@as(T, 0.130463884049976732), lgamma(T, 0.823), eps);

        try expectApproxEqRel(@as(T, 43.24395772148497989), lgamma(T, 21.3), eps);
        try expectApproxEqRel(@as(T, 110.6908958012102623), lgamma(T, 41.1), eps);
        try expectApproxEqRel(@as(T, 215.2123266224689711), lgamma(T, 67.4), eps);

        try expectApproxEqRel(@as(T, -122.605958469563489), lgamma(T, -43.6), eps);
        try expectApproxEqRel(@as(T, -278.633885462703133), lgamma(T, -81.4), eps);
        try expectApproxEqRel(@as(T, -333.247676253238363), lgamma(T, -93.6), eps);
    }
}

test "lgamma.special" {
    inline for (&.{ f32, f64 }) |T| {
        try expect(std.math.isNan(lgamma(T, -std.math.nan(T))));
        try expect(std.math.isNan(lgamma(T, std.math.nan(T))));

        try expectEqual(std.math.inf(T), lgamma(T, -std.math.inf(T)));
        try expectEqual(std.math.inf(T), lgamma(T, std.math.inf(T)));

        try expectEqual(std.math.inf(T), lgamma(T, -5));
        try expectEqual(std.math.inf(T), lgamma(T, -8));
        try expectEqual(std.math.inf(T), lgamma(T, -15));

        try expectEqual(std.math.inf(T), lgamma(T, -0.0));
        try expectEqual(std.math.inf(T), lgamma(T, 0.0));

        try expect(std.math.isPositiveZero(lgamma(T, 1)));
        try expect(std.math.isPositiveZero(lgamma(T, 2)));
    }
}
//! Greatest common divisor (https://mathworld.wolfram.com/GreatestCommonDivisor.html)
const std = @import("std");

/// Returns the greatest common divisor (GCD) of two unsigned integers (`a` and `b`) which are not both zero.
/// For example, the GCD of `8` and `12` is `4`, that is, `gcd(8, 12) == 4`.
pub fn gcd(a: anytype, b: anytype) @TypeOf(a, b) {
    const N = switch (@TypeOf(a, b)) {
        // convert comptime_int to some sized int type for @ctz
        comptime_int => std.math.IntFittingRange(@min(a, b), @max(a, b)),
        else => |T| T,
    };
    if (@typeInfo(N) != .int or @typeInfo(N).int.signedness != .unsigned) {
        @compileError("`a` and `b` must be usigned integers");
    }

    // using an optimised form of Stein's algorithm:
    // https://en.wikipedia.org/wiki/Binary_GCD_algorithm
    std.debug.assert(a != 0 or b != 0);

    if (a == 0) return b;
    if (b == 0) return a;

    var x: N = a;
    var y: N = b;

    const xz = @ctz(x);
    const yz = @ctz(y);
    const shift = @min(xz, yz);
    x >>= @intCast(xz);
    y >>= @intCast(yz);

    var diff = y -% x;
    while (diff != 0) : (diff = y -% x) {
        // ctz is invariant under negation, we
        // put it here to ease data dependencies,
        // makes the CPU happy.
        const zeros = @ctz(diff);
        if (x > y) diff = -%diff;
        y = @min(x, y);
        x = diff >> @intCast(zeros);
    }
    return y << @intCast(shift);
}

test gcd {
    const expectEqual = std.testing.expectEqual;

    try expectEqual(gcd(0, 5), 5);
    try expectEqual(gcd(5, 0), 5);
    try expectEqual(gcd(8, 12), 4);
    try expectEqual(gcd(12, 8), 4);
    try expectEqual(gcd(33, 77), 11);
    try expectEqual(gcd(77, 33), 11);
    try expectEqual(gcd(49865, 69811), 9973);
    try expectEqual(gcd(300_000, 2_300_000), 100_000);
    try expectEqual(gcd(90000000_000_000_000_000_000, 2), 2);
    try expectEqual(gcd(@as(u80, 90000000_000_000_000_000_000), 2), 2);
    try expectEqual(gcd(300_000, @as(u32, 2_300_000)), 100_000);
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const isNan = math.isNan;
const isInf = math.isInf;
const inf = math.inf;
const nan = math.nan;
const floatEpsAt = math.floatEpsAt;
const floatEps = math.floatEps;
const floatMin = math.floatMin;
const floatMax = math.floatMax;

/// Returns sqrt(x * x + y * y), avoiding unnecessary overflow and underflow.
///
/// Special Cases:
///
/// |   x   |   y   | hypot |
/// |-------|-------|-------|
/// | +-inf |  any  | +inf  |
/// |  any  | +-inf | +inf  |
/// |  nan  |  fin  |  nan  |
/// |  fin  |  nan  |  nan  |
pub fn hypot(x: anytype, y: anytype) @TypeOf(x, y) {
    const T = @TypeOf(x, y);
    switch (@typeInfo(T)) {
        .float => {},
        .comptime_float => return @sqrt(x * x + y * y),
        else => @compileError("hypot not implemented for " ++ @typeName(T)),
    }
    const lower = @sqrt(floatMin(T));
    const upper = @sqrt(floatMax(T) / 2);
    const incre = @sqrt(floatEps(T) / 2);
    const scale = floatEpsAt(T, incre);
    const hypfn = if (emulateFma(T)) hypotUnfused else hypotFused;
    var major: T = x;
    var minor: T = y;
    if (isInf(major) or isInf(minor)) return inf(T);
    if (isNan(major) or isNan(minor)) return nan(T);
    if (T == f16) return @floatCast(@sqrt(@mulAdd(f32, x, x, @as(f32, y) * y)));
    if (T == f32) return @floatCast(@sqrt(@mulAdd(f64, x, x, @as(f64, y) * y)));
    major = @abs(major);
    minor = @abs(minor);
    if (minor > major) {
        const tempo = major;
        major = minor;
        minor = tempo;
    }
    if (major * incre >= minor) return major;
    if (major > upper) return hypfn(T, major * scale, minor * scale) / scale;
    if (minor < lower) return hypfn(T, major / scale, minor / scale) * scale;
    return hypfn(T, major, minor);
}

inline fn emulateFma(comptime T: type) bool {
    // If @mulAdd lowers to the software implementation,
    // hypotUnfused should be used in place of hypotFused.
    // This takes an educated guess, but ideally we should
    // properly detect at comptime when that fallback will
    // occur.
    return (T == f128 or T == f80);
}

inline fn hypotFused(comptime F: type, x: F, y: F) F {
    const r = @sqrt(@mulAdd(F, x, x, y * y));
    const rr = r * r;
    const xx = x * x;
    const z = @mulAdd(F, -y, y, rr - xx) + @mulAdd(F, r, r, -rr) - @mulAdd(F, x, x, -xx);
    return r - z / (2 * r);
}

inline fn hypotUnfused(comptime F: type, x: F, y: F) F {
    const r = @sqrt(x * x + y * y);
    if (r <= 2 * y) { // 30deg or steeper
        const dx = r - y;
        const z = x * (2 * dx - x) + (dx - 2 * (x - y)) * dx;
        return r - z / (2 * r);
    } else { // shallower than 30 deg
        const dy = r - x;
        const z = 2 * dy * (x - 2 * y) + (4 * dy - y) * y + dy * dy;
        return r - z / (2 * r);
    }
}

const hypot_test_cases = .{
    .{ 0.0, -1.2, 1.2 },
    .{ 0.2, -0.34, 0.3944616584663203993612799816649560759946493601889826495362 },
    .{ 0.8923, 2.636890, 2.7837722899152509525110650481670176852603253522923737962880 },
    .{ 1.5, 5.25, 5.4600824169603887033229768686452745953332522619323580787836 },
    .{ 37.45, 159.835, 164.16372840856167640478217141034363907565754072954443805164 },
    .{ 89.123, 382.028905, 392.28687638576315875933966414927490685367196874260165618371 },
    .{ 123123.234375, 529428.707813, 543556.88524707706887251269205923830745438413088753096759371 },
};

test hypot {
    try expect(hypot(0.3, 0.4) == 0.5);
}

test "hypot.correct" {
    inline for (.{ f16, f32, f64, f128 }) |T| {
        inline for (hypot_test_cases) |v| {
            const a: T, const b: T, const c: T = v;
            try expect(math.approxEqRel(T, hypot(a, b), c, @sqrt(floatEps(T))));
        }
    }
}

test "hypot.precise" {
    inline for (.{ f16, f32, f64 }) |T| { // f128 seems to be 5 ulp
        inline for (hypot_test_cases) |v| {
            const a: T, const b: T, const c: T = v;
            try expect(math.approxEqRel(T, hypot(a, b), c, floatEps(T)));
        }
    }
}

test "hypot.special" {
    @setEvalBranchQuota(2000);
    inline for (.{ f16, f32, f64, f128 }) |T| {
        try expect(math.isNan(hypot(nan(T), 0.0)));
        try expect(math.isNan(hypot(0.0, nan(T))));

        try expect(math.isPositiveInf(hypot(inf(T), 0.0)));
        try expect(math.isPositiveInf(hypot(0.0, inf(T))));
        try expect(math.isPositiveInf(hypot(inf(T), nan(T))));
        try expect(math.isPositiveInf(hypot(nan(T), inf(T))));

        try expect(math.isPositiveInf(hypot(-inf(T), 0.0)));
        try expect(math.isPositiveInf(hypot(0.0, -inf(T))));
        try expect(math.isPositiveInf(hypot(-inf(T), nan(T))));
        try expect(math.isPositiveInf(hypot(nan(T), -inf(T))));
    }
}
// Ported from musl, which is MIT licensed.
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/ilogbl.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/ilogbf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/ilogb.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const maxInt = std.math.maxInt;
const minInt = std.math.minInt;

/// Returns the binary exponent of x as an integer.
///
/// Special Cases:
///  - ilogb(+-inf) = maxInt(i32)
///  - ilogb(+-0)   = minInt(i32)
///  - ilogb(nan)   = minInt(i32)
pub fn ilogb(x: anytype) i32 {
    const T = @TypeOf(x);
    return ilogbX(T, x);
}

pub const fp_ilogbnan = minInt(i32);
pub const fp_ilogb0 = minInt(i32);

fn ilogbX(comptime T: type, x: T) i32 {
    const typeWidth = @typeInfo(T).float.bits;
    const significandBits = math.floatMantissaBits(T);
    const exponentBits = math.floatExponentBits(T);

    const Z = std.meta.Int(.unsigned, typeWidth);

    const signBit = (@as(Z, 1) << (significandBits + exponentBits));
    const maxExponent = ((1 << exponentBits) - 1);
    const exponentBias = (maxExponent >> 1);

    const absMask = signBit - 1;

    const u = @as(Z, @bitCast(x)) & absMask;
    const e: i32 = @intCast(u >> significandBits);

    if (e == 0) {
        if (u == 0) {
            math.raiseInvalid();
            return fp_ilogb0;
        }

        // offset sign bit, exponent bits, and integer bit (if present) + bias
        const offset = 1 + exponentBits + @as(comptime_int, @intFromBool(T == f80)) - exponentBias;
        return offset - @as(i32, @intCast(@clz(u)));
    }

    if (e == maxExponent) {
        math.raiseInvalid();
        if (u > @as(Z, @bitCast(math.inf(T)))) {
            return fp_ilogbnan; // u is a NaN
        } else return maxInt(i32);
    }

    return e - exponentBias;
}

test "type dispatch" {
    try expect(ilogb(@as(f32, 0.2)) == ilogbX(f32, 0.2));
    try expect(ilogb(@as(f64, 0.2)) == ilogbX(f64, 0.2));
}

test "16" {
    try expect(ilogbX(f16, 0.0) == fp_ilogb0);
    try expect(ilogbX(f16, 0.5) == -1);
    try expect(ilogbX(f16, 0.8923) == -1);
    try expect(ilogbX(f16, 10.0) == 3);
    try expect(ilogbX(f16, -65504) == 15);
    try expect(ilogbX(f16, 2398.23) == 11);

    try expect(ilogbX(f16, 0x1p-1) == -1);
    try expect(ilogbX(f16, 0x1p-17) == -17);
    try expect(ilogbX(f16, 0x1p-24) == -24);
}

test "32" {
    try expect(ilogbX(f32, 0.0) == fp_ilogb0);
    try expect(ilogbX(f32, 0.5) == -1);
    try expect(ilogbX(f32, 0.8923) == -1);
    try expect(ilogbX(f32, 10.0) == 3);
    try expect(ilogbX(f32, -123984) == 16);
    try expect(ilogbX(f32, 2398.23) == 11);

    try expect(ilogbX(f32, 0x1p-1) == -1);
    try expect(ilogbX(f32, 0x1p-122) == -122);
    try expect(ilogbX(f32, 0x1p-127) == -127);
}

test "64" {
    try expect(ilogbX(f64, 0.0) == fp_ilogb0);
    try expect(ilogbX(f64, 0.5) == -1);
    try expect(ilogbX(f64, 0.8923) == -1);
    try expect(ilogbX(f64, 10.0) == 3);
    try expect(ilogbX(f64, -123984) == 16);
    try expect(ilogbX(f64, 2398.23) == 11);

    try expect(ilogbX(f64, 0x1p-1) == -1);
    try expect(ilogbX(f64, 0x1p-127) == -127);
    try expect(ilogbX(f64, 0x1p-1012) == -1012);
    try expect(ilogbX(f64, 0x1p-1023) == -1023);
}

test "80" {
    try expect(ilogbX(f80, 0.0) == fp_ilogb0);
    try expect(ilogbX(f80, 0.5) == -1);
    try expect(ilogbX(f80, 0.8923) == -1);
    try expect(ilogbX(f80, 10.0) == 3);
    try expect(ilogbX(f80, -123984) == 16);
    try expect(ilogbX(f80, 2398.23) == 11);

    try expect(ilogbX(f80, 0x1p-1) == -1);
    try expect(ilogbX(f80, 0x1p-127) == -127);
    try expect(ilogbX(f80, 0x1p-1023) == -1023);
    try expect(ilogbX(f80, 0x1p-16383) == -16383);
}

test "128" {
    try expect(ilogbX(f128, 0.0) == fp_ilogb0);
    try expect(ilogbX(f128, 0.5) == -1);
    try expect(ilogbX(f128, 0.8923) == -1);
    try expect(ilogbX(f128, 10.0) == 3);
    try expect(ilogbX(f128, -123984) == 16);
    try expect(ilogbX(f128, 2398.23) == 11);

    try expect(ilogbX(f128, 0x1p-1) == -1);
    try expect(ilogbX(f128, 0x1p-127) == -127);
    try expect(ilogbX(f128, 0x1p-1023) == -1023);
    try expect(ilogbX(f128, 0x1p-16383) == -16383);
}

test "16 special" {
    try expect(ilogbX(f16, math.inf(f16)) == maxInt(i32));
    try expect(ilogbX(f16, -math.inf(f16)) == maxInt(i32));
    try expect(ilogbX(f16, 0.0) == minInt(i32));
    try expect(ilogbX(f16, math.nan(f16)) == fp_ilogbnan);
}

test "32 special" {
    try expect(ilogbX(f32, math.inf(f32)) == maxInt(i32));
    try expect(ilogbX(f32, -math.inf(f32)) == maxInt(i32));
    try expect(ilogbX(f32, 0.0) == minInt(i32));
    try expect(ilogbX(f32, math.nan(f32)) == fp_ilogbnan);
}

test "64 special" {
    try expect(ilogbX(f64, math.inf(f64)) == maxInt(i32));
    try expect(ilogbX(f64, -math.inf(f64)) == maxInt(i32));
    try expect(ilogbX(f64, 0.0) == minInt(i32));
    try expect(ilogbX(f64, math.nan(f64)) == fp_ilogbnan);
}

test "80 special" {
    try expect(ilogbX(f80, math.inf(f80)) == maxInt(i32));
    try expect(ilogbX(f80, -math.inf(f80)) == maxInt(i32));
    try expect(ilogbX(f80, 0.0) == minInt(i32));
    try expect(ilogbX(f80, math.nan(f80)) == fp_ilogbnan);
}

test "128 special" {
    try expect(ilogbX(f128, math.inf(f128)) == maxInt(i32));
    try expect(ilogbX(f128, -math.inf(f128)) == maxInt(i32));
    try expect(ilogbX(f128, 0.0) == minInt(i32));
    try expect(ilogbX(f128, math.nan(f128)) == fp_ilogbnan);
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is a finite value.
pub fn isFinite(x: anytype) bool {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).float.bits);
    const remove_sign = ~@as(TBits, 0) >> 1;
    return @as(TBits, @bitCast(x)) & remove_sign < @as(TBits, @bitCast(math.inf(T)));
}

test isFinite {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        // normals
        try expect(isFinite(@as(T, 1.0)));
        try expect(isFinite(-@as(T, 1.0)));

        // zero & subnormals
        try expect(isFinite(@as(T, 0.0)));
        try expect(isFinite(@as(T, -0.0)));
        try expect(isFinite(math.floatTrueMin(T)));

        // other float limits
        try expect(isFinite(math.floatMin(T)));
        try expect(isFinite(math.floatMax(T)));

        // inf & nan
        try expect(!isFinite(math.inf(T)));
        try expect(!isFinite(-math.inf(T)));
        try expect(!isFinite(math.nan(T)));
        try expect(!isFinite(-math.nan(T)));
    }
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is an infinity, ignoring sign.
pub inline fn isInf(x: anytype) bool {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).float.bits);
    const remove_sign = ~@as(TBits, 0) >> 1;
    return @as(TBits, @bitCast(x)) & remove_sign == @as(TBits, @bitCast(math.inf(T)));
}

/// Returns whether x is an infinity with a positive sign.
pub inline fn isPositiveInf(x: anytype) bool {
    return x == math.inf(@TypeOf(x));
}

/// Returns whether x is an infinity with a negative sign.
pub inline fn isNegativeInf(x: anytype) bool {
    return x == -math.inf(@TypeOf(x));
}

test isInf {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(!isInf(@as(T, 0.0)));
        try expect(!isInf(@as(T, -0.0)));
        try expect(isInf(math.inf(T)));
        try expect(isInf(-math.inf(T)));
        try expect(!isInf(math.nan(T)));
        try expect(!isInf(-math.nan(T)));
    }
}

test isPositiveInf {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(!isPositiveInf(@as(T, 0.0)));
        try expect(!isPositiveInf(@as(T, -0.0)));
        try expect(isPositiveInf(math.inf(T)));
        try expect(!isPositiveInf(-math.inf(T)));
        try expect(!isInf(math.nan(T)));
        try expect(!isInf(-math.nan(T)));
    }
}

test isNegativeInf {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(!isNegativeInf(@as(T, 0.0)));
        try expect(!isNegativeInf(@as(T, -0.0)));
        try expect(!isNegativeInf(math.inf(T)));
        try expect(isNegativeInf(-math.inf(T)));
        try expect(!isInf(math.nan(T)));
        try expect(!isInf(-math.nan(T)));
    }
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const math = std.math;
const meta = std.meta;
const expect = std.testing.expect;

pub fn isNan(x: anytype) bool {
    return x != x;
}

/// TODO: LLVM is known to miscompile on some architectures to quiet NaN -
///       this is tracked by https://github.com/ziglang/zig/issues/14366
pub fn isSignalNan(x: anytype) bool {
    const T = @TypeOf(x);
    const U = meta.Int(.unsigned, @bitSizeOf(T));
    const quiet_signal_bit_mask = 1 << (math.floatFractionalBits(T) - 1);
    return isNan(x) and (@as(U, @bitCast(x)) & quiet_signal_bit_mask == 0);
}

test isNan {
    inline for ([_]type{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        try expect(isNan(math.nan(T)));
        try expect(isNan(-math.nan(T)));
        try expect(isNan(math.snan(T)));
        try expect(!isNan(@as(T, 1.0)));
        try expect(!isNan(@as(T, math.inf(T))));
    }
}

test isSignalNan {
    inline for ([_]type{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        // TODO: Signalling NaN values get converted to quiet NaN values in
        //       some cases where they shouldn't such that this can fail.
        //       See https://github.com/ziglang/zig/issues/14366
        if (!builtin.cpu.arch.isArm() and
            !builtin.cpu.arch.isAARCH64() and
            !builtin.cpu.arch.isMIPS32() and
            !builtin.cpu.arch.isPowerPC() and
            builtin.zig_backend != .stage2_c)
        {
            try expect(isSignalNan(math.snan(T)));
        }
        try expect(!isSignalNan(math.nan(T)));
        try expect(!isSignalNan(@as(T, 1.0)));
        try expect(!isSignalNan(math.inf(T)));
    }
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is neither zero, subnormal, infinity, or NaN.
pub fn isNormal(x: anytype) bool {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).float.bits);

    const increment_exp = 1 << math.floatMantissaBits(T);
    const remove_sign = ~@as(TBits, 0) >> 1;

    // We add 1 to the exponent, and if it overflows to 0 or becomes 1,
    // then it was all zeroes (subnormal) or all ones (special, inf/nan).
    // The sign bit is removed because all ones would overflow into it.
    // For f80, even though it has an explicit integer part stored,
    // the exponent effectively takes priority if mismatching.
    const value = @as(TBits, @bitCast(x)) +% increment_exp;
    return value & remove_sign >= (increment_exp << 1);
}

test isNormal {
    // TODO add `c_longdouble' when math.inf(T) supports it
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        const TBits = std.meta.Int(.unsigned, @bitSizeOf(T));

        // normals
        try expect(isNormal(@as(T, 1.0)));
        try expect(isNormal(math.floatMin(T)));
        try expect(isNormal(math.floatMax(T)));

        // subnormals
        try expect(!isNormal(@as(T, -0.0)));
        try expect(!isNormal(@as(T, 0.0)));
        try expect(!isNormal(@as(T, math.floatTrueMin(T))));

        // largest subnormal
        try expect(!isNormal(@as(T, @bitCast(~(~@as(TBits, 0) << math.floatFractionalBits(T))))));

        // non-finite numbers
        try expect(!isNormal(-math.inf(T)));
        try expect(!isNormal(math.inf(T)));
        try expect(!isNormal(math.nan(T)));

        // overflow edge-case (described in implementation, also see #10133)
        try expect(!isNormal(@as(T, @bitCast(~@as(TBits, 0)))));
    }
}
const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is positive zero.
pub inline fn isPositiveZero(x: anytype) bool {
    const T = @TypeOf(x);
    const bit_count = @typeInfo(T).float.bits;
    const TBits = std.meta.Int(.unsigned, bit_count);
    return @as(TBits, @bitCast(x)) == @as(TBits, 0);
}

/// Returns whether x is negative zero.
pub inline fn isNegativeZero(x: anytype) bool {
    const T = @TypeOf(x);
    const bit_count = @typeInfo(T).float.bits;
    const TBits = std.meta.Int(.unsigned, bit_count);
    return @as(TBits, @bitCast(x)) == @as(TBits, 1) << (bit_count - 1);
}

test isPositiveZero {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(isPositiveZero(@as(T, 0.0)));
        try expect(!isPositiveZero(@as(T, -0.0)));
        try expect(!isPositiveZero(math.floatMin(T)));
        try expect(!isPositiveZero(math.floatMax(T)));
        try expect(!isPositiveZero(math.inf(T)));
        try expect(!isPositiveZero(-math.inf(T)));
    }
}

test isNegativeZero {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(isNegativeZero(@as(T, -0.0)));
        try expect(!isNegativeZero(@as(T, 0.0)));
        try expect(!isNegativeZero(math.floatMin(T)));
        try expect(!isNegativeZero(math.floatMax(T)));
        try expect(!isNegativeZero(math.inf(T)));
        try expect(!isNegativeZero(-math.inf(T)));
    }
}
//! Least common multiple (https://mathworld.wolfram.com/LeastCommonMultiple.html)
const std = @import("std");

/// Returns the least common multiple (LCM) of two integers (`a` and `b`).
/// For example, the LCM of `8` and `12` is `24`, that is, `lcm(8, 12) == 24`.
/// If any of the arguments is zero, then the returned value is 0.
pub fn lcm(a: anytype, b: anytype) @TypeOf(a, b) {
    // Behavior from C++ and Python
    // If an argument is zero, then the returned value is 0.
    if (a == 0 or b == 0) return 0;
    return @abs(b) * (@abs(a) / std.math.gcd(@abs(a), @abs(b)));
}

test lcm {
    const expectEqual = std.testing.expectEqual;

    try expectEqual(lcm(0, 0), 0);
    try expectEqual(lcm(1, 0), 0);
    try expectEqual(lcm(-1, 0), 0);
    try expectEqual(lcm(0, 1), 0);
    try expectEqual(lcm(0, -1), 0);
    try expectEqual(lcm(7, 1), 7);
    try expectEqual(lcm(7, -1), 7);
    try expectEqual(lcm(8, 12), 24);
    try expectEqual(lcm(-23, 15), 345);
    try expectEqual(lcm(120, 84), 840);
    try expectEqual(lcm(84, -120), 840);
    try expectEqual(lcm(1216342683557601535506311712, 436522681849110124616458784), 16592536571065866494401400422922201534178938447014944);
}
const std = @import("std");
const math = std.math;
const Log2Int = std.math.Log2Int;
const assert = std.debug.assert;
const expect = std.testing.expect;

/// Returns x * 2^n.
pub fn ldexp(x: anytype, n: i32) @TypeOf(x) {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).float.bits);

    const exponent_bits = math.floatExponentBits(T);
    const mantissa_bits = math.floatMantissaBits(T);
    const fractional_bits = math.floatFractionalBits(T);

    const max_biased_exponent = 2 * math.floatExponentMax(T);
    const mantissa_mask = @as(TBits, (1 << mantissa_bits) - 1);

    const repr = @as(TBits, @bitCast(x));
    const sign_bit = repr & (1 << (exponent_bits + mantissa_bits));

    if (math.isNan(x) or !math.isFinite(x))
        return x;

    var exponent: i32 = @as(i32, @intCast((repr << 1) >> (mantissa_bits + 1)));
    if (exponent == 0)
        exponent += (@as(i32, exponent_bits) + @intFromBool(T == f80)) - @clz(repr << 1);

    if (n >= 0) {
        if (n > max_biased_exponent - exponent) {
            // Overflow. Return +/- inf
            return @as(T, @bitCast(@as(TBits, @bitCast(math.inf(T))) | sign_bit));
        } else if (exponent + n <= 0) {
            // Result is subnormal
            return @as(T, @bitCast((repr << @as(Log2Int(TBits), @intCast(n))) | sign_bit));
        } else if (exponent <= 0) {
            // Result is normal, but needs shifting
            var result = @as(TBits, @intCast(n + exponent)) << mantissa_bits;
            result |= (repr << @as(Log2Int(TBits), @intCast(1 - exponent))) & mantissa_mask;
            return @as(T, @bitCast(result | sign_bit));
        }

        // Result needs no shifting
        return @as(T, @bitCast(repr + (@as(TBits, @intCast(n)) << mantissa_bits)));
    } else {
        if (n <= -exponent) {
            if (n < -(mantissa_bits + exponent))
                return @as(T, @bitCast(sign_bit)); // Severe underflow. Return +/- 0

            // Result underflowed, we need to shift and round
            const shift = @as(Log2Int(TBits), @intCast(@min(-n, -(exponent + n) + 1)));
            const exact_tie: bool = @ctz(repr) == shift - 1;
            var result = repr & mantissa_mask;

            if (T != f80) // Include integer bit
                result |= @as(TBits, @intFromBool(exponent > 0)) << fractional_bits;
            result = @as(TBits, @intCast((result >> (shift - 1))));

            // Round result, including round-to-even for exact ties
            result = ((result + 1) >> 1) & ~@as(TBits, @intFromBool(exact_tie));
            return @as(T, @bitCast(result | sign_bit));
        }

        // Result is exact, and needs no shifting
        return @as(T, @bitCast(repr - (@as(TBits, @intCast(-n)) << mantissa_bits)));
    }
}

test ldexp {
    // subnormals
    try expect(ldexp(@as(f16, 0x1.1FFp14), -14 - 9 - 15) == math.floatTrueMin(f16));
    try expect(ldexp(@as(f32, 0x1.3FFFFFp-1), -126 - 22) == math.floatTrueMin(f32));
    try expect(ldexp(@as(f64, 0x1.7FFFFFFFFFFFFp-1), -1022 - 51) == math.floatTrueMin(f64));
    try expect(ldexp(@as(f80, 0x1.7FFFFFFFFFFFFFFEp-1), -16382 - 62) == math.floatTrueMin(f80));
    try expect(ldexp(@as(f128, 0x1.7FFFFFFFFFFFFFFFFFFFFFFFFFFFp-1), -16382 - 111) == math.floatTrueMin(f128));

    try expect(ldexp(math.floatMax(f32), -128 - 149) > 0.0);
    try expect(ldexp(math.floatMax(f32), -128 - 149 - 1) == 0.0);

    @setEvalBranchQuota(10_000);

    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        const fractional_bits = math.floatFractionalBits(T);

        const min_exponent = math.floatExponentMin(T);
        const max_exponent = math.floatExponentMax(T);
        const exponent_bias = max_exponent;

        // basic usage
        try expect(ldexp(@as(T, 1.5), 4) == 24.0);

        // normals -> subnormals
        try expect(math.isNormal(ldexp(@as(T, 1.0), min_exponent)));
        try expect(!math.isNormal(ldexp(@as(T, 1.0), min_exponent - 1)));

        // normals -> zero
        try expect(ldexp(@as(T, 1.0), min_exponent - fractional_bits) > 0.0);
        try expect(ldexp(@as(T, 1.0), min_exponent - fractional_bits - 1) == 0.0);

        // subnormals -> zero
        try expect(ldexp(math.floatTrueMin(T), 0) > 0.0);
        try expect(ldexp(math.floatTrueMin(T), -1) == 0.0);

        // Multiplications might flush the denormals to zero, esp. at
        // runtime, so we manually construct the constants here instead.
        const Z = std.meta.Int(.unsigned, @bitSizeOf(T));
        const EightTimesTrueMin = @as(T, @bitCast(@as(Z, 8)));
        const TwoTimesTrueMin = @as(T, @bitCast(@as(Z, 2)));

        // subnormals -> subnormals
        try expect(ldexp(math.floatTrueMin(T), 3) == EightTimesTrueMin);
        try expect(ldexp(EightTimesTrueMin, -2) == TwoTimesTrueMin);
        try expect(ldexp(EightTimesTrueMin, -3) == math.floatTrueMin(T));

        // subnormals -> normals (+)
        try expect(ldexp(math.floatTrueMin(T), fractional_bits) == math.floatMin(T));
        try expect(ldexp(math.floatTrueMin(T), fractional_bits - 1) == math.floatMin(T) * 0.5);

        // subnormals -> normals (-)
        try expect(ldexp(-math.floatTrueMin(T), fractional_bits) == -math.floatMin(T));
        try expect(ldexp(-math.floatTrueMin(T), fractional_bits - 1) == -math.floatMin(T) * 0.5);

        // subnormals -> float limits (+inf)
        try expect(math.isFinite(ldexp(math.floatTrueMin(T), max_exponent + exponent_bias + fractional_bits - 1)));
        try expect(ldexp(math.floatTrueMin(T), max_exponent + exponent_bias + fractional_bits) == math.inf(T));

        // subnormals -> float limits (-inf)
        try expect(math.isFinite(ldexp(-math.floatTrueMin(T), max_exponent + exponent_bias + fractional_bits - 1)));
        try expect(ldexp(-math.floatTrueMin(T), max_exponent + exponent_bias + fractional_bits) == -math.inf(T));

        // infinity -> infinity
        try expect(ldexp(math.inf(T), math.maxInt(i32)) == math.inf(T));
        try expect(ldexp(math.inf(T), math.minInt(i32)) == math.inf(T));
        try expect(ldexp(math.inf(T), max_exponent) == math.inf(T));
        try expect(ldexp(math.inf(T), min_exponent) == math.inf(T));
        try expect(ldexp(-math.inf(T), math.maxInt(i32)) == -math.inf(T));
        try expect(ldexp(-math.inf(T), math.minInt(i32)) == -math.inf(T));

        // extremely large n
        try expect(ldexp(math.floatMax(T), math.maxInt(i32)) == math.inf(T));
        try expect(ldexp(math.floatMax(T), -math.maxInt(i32)) == 0.0);
        try expect(ldexp(math.floatMax(T), math.minInt(i32)) == 0.0);
        try expect(ldexp(math.floatTrueMin(T), math.maxInt(i32)) == math.inf(T));
        try expect(ldexp(math.floatTrueMin(T), -math.maxInt(i32)) == 0.0);
        try expect(ldexp(math.floatTrueMin(T), math.minInt(i32)) == 0.0);
    }
}
const std = @import("../std.zig");
const math = std.math;
const testing = std.testing;
const assert = std.debug.assert;
const Log2Int = math.Log2Int;

/// Returns the logarithm of `x` for the provided `base`, rounding down to the nearest integer.
/// Asserts that `base > 1` and `x > 0`.
pub fn log_int(comptime T: type, base: T, x: T) Log2Int(T) {
    const valid = switch (@typeInfo(T)) {
        .comptime_int => true,
        .int => |IntType| IntType.signedness == .unsigned,
        else => false,
    };
    if (!valid) @compileError("log_int requires an unsigned integer, found " ++ @typeName(T));

    assert(base > 1 and x > 0);
    if (base == 2) return math.log2_int(T, x);

    // Let's denote by [y] the integer part of y.

    // Throughout the iteration the following invariant is preserved:
    //     power = base ^ exponent

    // Safety and termination.
    //
    // We never overflow inside the loop because when we enter the loop we have
    //     power <= [maxInt(T) / base]
    // therefore
    //     power * base <= maxInt(T)
    // is a valid multiplication for type `T` and
    //     exponent + 1 <= log(base, maxInt(T)) <= log2(maxInt(T)) <= maxInt(Log2Int(T))
    // is a valid addition for type `Log2Int(T)`.
    //
    // This implies also termination because power is strictly increasing,
    // hence it must eventually surpass [x / base] < maxInt(T) and we then exit the loop.

    var exponent: Log2Int(T) = 0;
    var power: T = 1;
    while (power <= x / base) {
        power *= base;
        exponent += 1;
    }

    // If we never entered the loop we must have
    //     [x / base] < 1
    // hence
    //     x <= [x / base] * base < base
    // thus the result is 0. We can then return exponent, which is still 0.
    //
    // Otherwise, if we entered the loop at least once,
    // when we exit the loop we have that power is exactly divisible by base and
    //     power / base <= [x / base] < power
    // hence
    //     power <= [x / base] * base <= x < power * base
    // This means that
    //     base^exponent <= x < base^(exponent+1)
    // hence the result is exponent.

    return exponent;
}

test "log_int" {
    @setEvalBranchQuota(2000);
    // Test all unsigned integers with 2, 3, ..., 64 bits.
    // We cannot test 0 or 1 bits since base must be > 1.
    inline for (2..64 + 1) |bits| {
        const T = @Type(.{ .int = .{ .signedness = .unsigned, .bits = @intCast(bits) } });

        // for base = 2, 3, ..., min(maxInt(T),1024)
        var base: T = 1;
        while (base < math.maxInt(T) and base <= 1024) {
            base += 1;

            // test that `log_int(T, base, 1) == 0`
            try testing.expectEqual(@as(Log2Int(T), 0), log_int(T, base, 1));

            // For powers `pow = base^exp > 1` that fit inside T,
            // test that `log_int` correctly detects the jump in the logarithm
            // from `log(pow-1) == exp-1` to `log(pow) == exp`.
            var exp: Log2Int(T) = 0;
            var pow: T = 1;
            while (pow <= math.maxInt(T) / base) {
                exp += 1;
                pow *= base;

                try testing.expectEqual(exp - 1, log_int(T, base, pow - 1));
                try testing.expectEqual(exp, log_int(T, base, pow));
            }
        }
    }
}

test "log_int vs math.log2" {
    const types = [_]type{ u2, u3, u4, u8, u16 };
    inline for (types) |T| {
        var n: T = 0;
        while (n < math.maxInt(T)) {
            n += 1;
            const special = math.log2_int(T, n);
            const general = log_int(T, 2, n);
            try testing.expectEqual(special, general);
        }
    }
}

test "log_int vs math.log10" {
    const types = [_]type{ u4, u5, u6, u8, u16 };
    inline for (types) |T| {
        var n: T = 0;
        while (n < math.maxInt(T)) {
            n += 1;
            const special = math.log10_int(n);
            const general = log_int(T, 10, n);
            try testing.expectEqual(special, general);
        }
    }
}

test "log_int at comptime" {
    const x = 59049; // 9 ** 5;
    comptime {
        if (math.log_int(comptime_int, 9, x) != 5) {
            @compileError("log(9, 59049) should be 5");
        }
    }
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/logf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/log.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns the logarithm of x for the provided base.
pub fn log(comptime T: type, base: T, x: T) T {
    if (base == 2) {
        return math.log2(x);
    } else if (base == 10) {
        return math.log10(x);
    } else if ((@typeInfo(T) == .float or @typeInfo(T) == .comptime_float) and base == math.e) {
        return @log(x);
    }

    const float_base = math.lossyCast(f64, base);
    switch (@typeInfo(T)) {
        .comptime_float => {
            return @as(comptime_float, @log(@as(f64, x)) / @log(float_base));
        },

        .comptime_int => {
            return @as(comptime_int, math.log_int(comptime_int, base, x));
        },

        .int => |IntType| switch (IntType.signedness) {
            .signed => @compileError("log not implemented for signed integers"),
            .unsigned => return @as(T, math.log_int(T, base, x)),
        },

        .float => {
            switch (T) {
                f32 => return @as(f32, @floatCast(@log(@as(f64, x)) / @log(float_base))),
                f64 => return @log(x) / @log(float_base),
                else => @compileError("log not implemented for " ++ @typeName(T)),
            }
        },

        else => {
            @compileError("log expects integer or float, found '" ++ @typeName(T) ++ "'");
        },
    }
}

test "log integer" {
    try expect(log(u8, 2, 0x1) == 0);
    try expect(log(u8, 2, 0x2) == 1);
    try expect(log(u16, 2, 0x72) == 6);
    try expect(log(u32, 2, 0xFFFFFF) == 23);
    try expect(log(u64, 2, 0x7FF0123456789ABC) == 62);
}

test "log float" {
    const epsilon = 0.000001;

    try expect(math.approxEqAbs(f32, log(f32, 6, 0.23947), -0.797723, epsilon));
    try expect(math.approxEqAbs(f32, log(f32, 89, 0.23947), -0.318432, epsilon));
    try expect(math.approxEqAbs(f64, log(f64, 123897, 12389216414), 1.981724596, epsilon));
}

test "log float_special" {
    try expect(log(f32, 2, 0.2301974) == math.log2(@as(f32, 0.2301974)));
    try expect(log(f32, 10, 0.2301974) == math.log10(@as(f32, 0.2301974)));

    try expect(log(f64, 2, 213.23019799993) == math.log2(@as(f64, 213.23019799993)));
    try expect(log(f64, 10, 213.23019799993) == math.log10(@as(f64, 213.23019799993)));
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const testing = std.testing;

/// Returns the base-10 logarithm of x.
///
/// Special Cases:
///  - log10(+inf)  = +inf
///  - log10(0)     = -inf
///  - log10(x)     = nan if x < 0
///  - log10(nan)   = nan
pub fn log10(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .comptime_float => {
            return @as(comptime_float, @log10(x));
        },
        .float => return @log10(x),
        .comptime_int => {
            return @as(comptime_int, @floor(@log10(@as(f64, x))));
        },
        .int => |IntType| switch (IntType.signedness) {
            .signed => @compileError("log10 not implemented for signed integers"),
            .unsigned => return log10_int(x),
        },
        else => @compileError("log10 not implemented for " ++ @typeName(T)),
    }
}

// Based on Rust, which is licensed under the MIT license.
// https://github.com/rust-lang/rust/blob/f63ccaf25f74151a5d8ce057904cd944074b01d2/LICENSE-MIT
//
// https://github.com/rust-lang/rust/blob/f63ccaf25f74151a5d8ce057904cd944074b01d2/library/core/src/num/int_log10.rs

/// Return the log base 10 of integer value x, rounding down to the
/// nearest integer.
pub fn log10_int(x: anytype) std.math.Log2Int(@TypeOf(x)) {
    const T = @TypeOf(x);
    const OutT = std.math.Log2Int(T);
    if (@typeInfo(T) != .int or @typeInfo(T).int.signedness != .unsigned)
        @compileError("log10_int requires an unsigned integer, found " ++ @typeName(T));

    std.debug.assert(x != 0);

    const bit_size = @typeInfo(T).int.bits;

    if (bit_size <= 8) {
        return @as(OutT, @intCast(log10_int_u8(x)));
    } else if (bit_size <= 16) {
        return @as(OutT, @intCast(less_than_5(x)));
    }

    var val = x;
    var log: u32 = 0;

    inline for (0..11) |i| {
        // Unnecessary branches should be removed by the compiler
        if (bit_size > (1 << (11 - i)) * 5 * @log2(10.0) and val >= pow10((1 << (11 - i)) * 5)) {
            const num_digits = (1 << (11 - i)) * 5;
            val /= pow10(num_digits);
            log += num_digits;
        }
    }

    if (val >= pow10(5)) {
        val /= pow10(5);
        log += 5;
    }

    return @as(OutT, @intCast(log + less_than_5(@as(u32, @intCast(val)))));
}

fn pow10(comptime y: comptime_int) comptime_int {
    if (y == 0) return 1;

    var squaring = 0;
    var s = 1;

    while (s <= y) : (s <<= 1) {
        squaring += 1;
    }

    squaring -= 1;

    var result = 10;

    for (0..squaring) |_| {
        result *= result;
    }

    const rest_exp = y - (1 << squaring);

    return result * pow10(rest_exp);
```
