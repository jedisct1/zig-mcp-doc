```
  var t2 = t1.sqn(10).mul(t1);
        t2 = t2.mul(t2.sqn(20)).sqn(10);
        t1 = t1.mul(t2);
        t2 = t1.sqn(50).mul(t1);
        return t1.mul(t2.mul(t2.sqn(100)).sqn(50)).sqn(5).mul(t0);
    }

    /// Return a^((p-5)/8) = a^(2^252-3)
    /// Used to compute square roots since we have p=5 (mod 8); see Cohen and Frey.
    pub fn pow2523(a: Fe) Fe {
        var t0 = a.mul(a.sq());
        var t1 = t0.mul(t0.sqn(2)).sq().mul(a);
        t0 = t1.sqn(5).mul(t1);
        var t2 = t0.sqn(5).mul(t1);
        t1 = t2.sqn(15).mul(t2);
        t2 = t1.sqn(30).mul(t1);
        t1 = t2.sqn(60).mul(t2);
        return t1.sqn(120).mul(t1).sqn(10).mul(t0).sqn(2).mul(a);
    }

    /// Return the absolute value of a field element
    pub fn abs(a: Fe) Fe {
        var r = a;
        r.cMov(a.neg(), @intFromBool(a.isNegative()));
        return r;
    }

    /// Return true if the field element is a square
    pub fn isSquare(a: Fe) bool {
        // Compute the Jacobi symbol x^((p-1)/2)
        const _11 = a.mul(a.sq());
        const _1111 = _11.mul(_11.sq().sq());
        const _11111111 = _1111.mul(_1111.sq().sq().sq().sq());
        const u = _11111111.sqn(2).mul(_11);
        const t = u.sqn(10).mul(u).sqn(10).mul(u);
        const t2 = t.sqn(30).mul(t);
        const t3 = t2.sqn(60).mul(t2);
        const t4 = t3.sqn(120).mul(t3).sqn(10).mul(u).sqn(3).mul(_11).sq();
        return @as(bool, @bitCast(@as(u1, @truncate(~(t4.toBytes()[1] & 1)))));
    }

    fn uncheckedSqrt(x2: Fe) Fe {
        var e = x2.pow2523();
        const p_root = e.mul(x2); // positive root
        const m_root = p_root.mul(Fe.sqrtm1); // negative root
        const m_root2 = m_root.sq();
        e = x2.sub(m_root2);
        var x = p_root;
        x.cMov(m_root, @intFromBool(e.isZero()));
        return x;
    }

    /// Compute the square root of `x2`, returning `error.NotSquare` if `x2` was not a square
    pub fn sqrt(x2: Fe) NotSquareError!Fe {
        const x2_copy = x2;
        const x = x2.uncheckedSqrt();
        const check = x.sq().sub(x2_copy);
        if (check.isZero()) {
            return x;
        }
        return error.NotSquare;
    }
};
const std = @import("std");
const fmt = std.fmt;

const EncodingError = std.crypto.errors.EncodingError;
const IdentityElementError = std.crypto.errors.IdentityElementError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const WeakPublicKeyError = std.crypto.errors.WeakPublicKeyError;

/// Group operations over Edwards25519.
pub const Ristretto255 = struct {
    /// The underlying elliptic curve.
    pub const Curve = @import("edwards25519.zig").Edwards25519;
    /// The underlying prime field.
    pub const Fe = Curve.Fe;
    /// Field arithmetic mod the order of the main subgroup.
    pub const scalar = Curve.scalar;
    /// Length in byte of an encoded element.
    pub const encoded_length: usize = 32;

    p: Curve,

    fn sqrtRatioM1(u: Fe, v: Fe) struct { ratio_is_square: u32, root: Fe } {
        const v3 = v.sq().mul(v); // v^3
        var x = v3.sq().mul(u).mul(v).pow2523().mul(v3).mul(u); // uv^3(uv^7)^((q-5)/8)
        const vxx = x.sq().mul(v); // vx^2
        const m_root_check = vxx.sub(u); // vx^2-u
        const p_root_check = vxx.add(u); // vx^2+u
        const f_root_check = u.mul(Fe.sqrtm1).add(vxx); // vx^2+u*sqrt(-1)
        const has_m_root = m_root_check.isZero();
        const has_p_root = p_root_check.isZero();
        const has_f_root = f_root_check.isZero();
        const x_sqrtm1 = x.mul(Fe.sqrtm1); // x*sqrt(-1)
        x.cMov(x_sqrtm1, @intFromBool(has_p_root) | @intFromBool(has_f_root));
        return .{ .ratio_is_square = @intFromBool(has_m_root) | @intFromBool(has_p_root), .root = x.abs() };
    }

    fn rejectNonCanonical(s: [encoded_length]u8) NonCanonicalError!void {
        if ((s[0] & 1) != 0) {
            return error.NonCanonical;
        }
        try Fe.rejectNonCanonical(s, false);
    }

    /// Reject the neutral element.
    pub inline fn rejectIdentity(p: Ristretto255) IdentityElementError!void {
        return p.p.rejectIdentity();
    }

    /// The base point (Ristretto is a curve in desguise).
    pub const basePoint = Ristretto255{ .p = Curve.basePoint };

    /// Decode a Ristretto255 representative.
    pub fn fromBytes(s: [encoded_length]u8) (NonCanonicalError || EncodingError)!Ristretto255 {
        try rejectNonCanonical(s);
        const s_ = Fe.fromBytes(s);
        const ss = s_.sq(); // s^2
        const u1_ = Fe.one.sub(ss); // (1-s^2)
        const u1u1 = u1_.sq(); // (1-s^2)^2
        const u2_ = Fe.one.add(ss); // (1+s^2)
        const u2u2 = u2_.sq(); // (1+s^2)^2
        const v = Fe.edwards25519d.mul(u1u1).neg().sub(u2u2); // -(d*u1^2)-u2^2
        const v_u2u2 = v.mul(u2u2); // v*u2^2

        const inv_sqrt = sqrtRatioM1(Fe.one, v_u2u2);
        var x = inv_sqrt.root.mul(u2_);
        const y = inv_sqrt.root.mul(x).mul(v).mul(u1_);
        x = x.mul(s_);
        x = x.add(x).abs();
        const t = x.mul(y);
        if ((1 - inv_sqrt.ratio_is_square) | @intFromBool(t.isNegative()) | @intFromBool(y.isZero()) != 0) {
            return error.InvalidEncoding;
        }
        const p: Curve = .{
            .x = x,
            .y = y,
            .z = Fe.one,
            .t = t,
        };
        return Ristretto255{ .p = p };
    }

    /// Encode to a Ristretto255 representative.
    pub fn toBytes(e: Ristretto255) [encoded_length]u8 {
        const p = &e.p;
        var u1_ = p.z.add(p.y); // Z+Y
        const zmy = p.z.sub(p.y); // Z-Y
        u1_ = u1_.mul(zmy); // (Z+Y)*(Z-Y)
        const u2_ = p.x.mul(p.y); // X*Y
        const u1_u2u2 = u2_.sq().mul(u1_); // u1*u2^2
        const inv_sqrt = sqrtRatioM1(Fe.one, u1_u2u2);
        const den1 = inv_sqrt.root.mul(u1_);
        const den2 = inv_sqrt.root.mul(u2_);
        const z_inv = den1.mul(den2).mul(p.t); // den1*den2*T
        const ix = p.x.mul(Fe.sqrtm1); // X*sqrt(-1)
        const iy = p.y.mul(Fe.sqrtm1); // Y*sqrt(-1)
        const eden = den1.mul(Fe.edwards25519sqrtamd); // den1/sqrt(a-d)
        const t_z_inv = p.t.mul(z_inv); // T*z_inv

        const rotate = @intFromBool(t_z_inv.isNegative());
        var x = p.x;
        var y = p.y;
        var den_inv = den2;
        x.cMov(iy, rotate);
        y.cMov(ix, rotate);
        den_inv.cMov(eden, rotate);

        const x_z_inv = x.mul(z_inv);
        const yneg = y.neg();
        y.cMov(yneg, @intFromBool(x_z_inv.isNegative()));

        return p.z.sub(y).mul(den_inv).abs().toBytes();
    }

    fn elligator(t: Fe) Curve {
        const r = t.sq().mul(Fe.sqrtm1); // sqrt(-1)*t^2
        const u = r.add(Fe.one).mul(Fe.edwards25519eonemsqd); // (r+1)*(1-d^2)
        var c = comptime Fe.one.neg(); // -1
        const v = c.sub(r.mul(Fe.edwards25519d)).mul(r.add(Fe.edwards25519d)); // (c-r*d)*(r+d)
        const ratio_sqrt = sqrtRatioM1(u, v);
        const wasnt_square = 1 - ratio_sqrt.ratio_is_square;
        var s = ratio_sqrt.root;
        const s_prime = s.mul(t).abs().neg(); // -|s*t|
        s.cMov(s_prime, wasnt_square);
        c.cMov(r, wasnt_square);

        const n = r.sub(Fe.one).mul(c).mul(Fe.edwards25519sqdmone).sub(v); // c*(r-1)*(d-1)^2-v
        const w0 = s.add(s).mul(v); // 2s*v
        const w1 = n.mul(Fe.edwards25519sqrtadm1); // n*sqrt(ad-1)
        const ss = s.sq(); // s^2
        const w2 = Fe.one.sub(ss); // 1-s^2
        const w3 = Fe.one.add(ss); // 1+s^2

        return .{ .x = w0.mul(w3), .y = w2.mul(w1), .z = w1.mul(w3), .t = w0.mul(w2) };
    }

    /// Map a 64-bit string into a Ristretto255 group element
    pub fn fromUniform(h: [64]u8) Ristretto255 {
        const p0 = elligator(Fe.fromBytes(h[0..32].*));
        const p1 = elligator(Fe.fromBytes(h[32..64].*));
        return Ristretto255{ .p = p0.add(p1) };
    }

    /// Double a Ristretto255 element.
    pub inline fn dbl(p: Ristretto255) Ristretto255 {
        return .{ .p = p.p.dbl() };
    }

    /// Add two Ristretto255 elements.
    pub inline fn add(p: Ristretto255, q: Ristretto255) Ristretto255 {
        return .{ .p = p.p.add(q.p) };
    }

    /// Multiply a Ristretto255 element with a scalar.
    /// Return error.WeakPublicKey if the resulting element is
    /// the identity element.
    pub inline fn mul(p: Ristretto255, s: [encoded_length]u8) (IdentityElementError || WeakPublicKeyError)!Ristretto255 {
        return Ristretto255{ .p = try p.p.mul(s) };
    }

    /// Return true if two Ristretto255 elements are equivalent
    pub fn equivalent(p: Ristretto255, q: Ristretto255) bool {
        const p_ = &p.p;
        const q_ = &q.p;
        const a = p_.x.mul(q_.y).equivalent(p_.y.mul(q_.x));
        const b = p_.y.mul(q_.y).equivalent(p_.x.mul(q_.x));
        return (@intFromBool(a) | @intFromBool(b)) != 0;
    }
};

test "ristretto255" {
    const p = Ristretto255.basePoint;
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&p.toBytes())}), "E2F2AE0A6ABC4E71A884A961C500515F58E30B6AA582DD8DB6A65945E08D2D76");

    var r: [Ristretto255.encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(r[0..], "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919");
    var q = try Ristretto255.fromBytes(r);
    q = q.dbl().add(p);
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&q.toBytes())}), "E882B131016B52C1D3337080187CF768423EFCCBB517BB495AB812C4160FF44E");

    const s = [_]u8{15} ++ [_]u8{0} ** 31;
    const w = try p.mul(s);
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&w.toBytes())}), "E0C418F7C8D9C4CDD7395B93EA124F3AD99021BB681DFC3302A9D99A2E53E64E");

    try std.testing.expect(p.dbl().dbl().dbl().dbl().equivalent(w.add(p)));

    const h = [_]u8{69} ** 32 ++ [_]u8{42} ** 32;
    const ph = Ristretto255.fromUniform(h);
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&ph.toBytes())}), "DCCA54E037A4311EFBEEF413ACD21D35276518970B7A61DC88F8587B493D5E19");
}
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

const NonCanonicalError = std.crypto.errors.NonCanonicalError;

/// The scalar field order.
pub const field_order: u256 = 7237005577332262213973186563042994240857116359379907606001950938285454250989;

/// A compressed scalar
pub const CompressedScalar = [32]u8;

/// Zero
pub const zero = [_]u8{0} ** 32;

const field_order_s = s: {
    var s: [32]u8 = undefined;
    mem.writeInt(u256, &s, field_order, .little);
    break :s s;
};

/// Reject a scalar whose encoding is not canonical.
pub fn rejectNonCanonical(s: CompressedScalar) NonCanonicalError!void {
    var c: u8 = 0;
    var n: u8 = 1;
    var i: usize = 31;
    while (true) : (i -= 1) {
        const xs = @as(u16, s[i]);
        const xfield_order_s = @as(u16, field_order_s[i]);
        c |= @as(u8, @intCast(((xs -% xfield_order_s) >> 8) & n));
        n &= @as(u8, @intCast(((xs ^ xfield_order_s) -% 1) >> 8));
        if (i == 0) break;
    }
    if (c == 0) {
        return error.NonCanonical;
    }
}

/// Reduce a scalar to the field size.
pub fn reduce(s: CompressedScalar) CompressedScalar {
    var scalar = Scalar.fromBytes(s);
    return scalar.toBytes();
}

/// Reduce a 64-bytes scalar to the field size.
pub fn reduce64(s: [64]u8) CompressedScalar {
    var scalar = ScalarDouble.fromBytes64(s);
    return scalar.toBytes();
}

/// Perform the X25519 "clamping" operation.
/// The scalar is then guaranteed to be a multiple of the cofactor.
pub inline fn clamp(s: *CompressedScalar) void {
    s[0] &= 248;
    s[31] = (s[31] & 127) | 64;
}

/// Return a*b (mod L)
pub fn mul(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return Scalar.fromBytes(a).mul(Scalar.fromBytes(b)).toBytes();
}

/// Return a*b+c (mod L)
pub fn mulAdd(a: CompressedScalar, b: CompressedScalar, c: CompressedScalar) CompressedScalar {
    return Scalar.fromBytes(a).mul(Scalar.fromBytes(b)).add(Scalar.fromBytes(c)).toBytes();
}

/// Return a*8 (mod L)
pub fn mul8(s: CompressedScalar) CompressedScalar {
    var x = Scalar.fromBytes(s);
    x = x.add(x);
    x = x.add(x);
    x = x.add(x);
    return x.toBytes();
}

/// Return a+b (mod L)
pub fn add(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return Scalar.fromBytes(a).add(Scalar.fromBytes(b)).toBytes();
}

/// Return -s (mod L)
pub fn neg(s: CompressedScalar) CompressedScalar {
    const fs: [64]u8 = field_order_s ++ [_]u8{0} ** 32;
    var sx: [64]u8 = undefined;
    sx[0..32].* = s;
    @memset(sx[32..], 0);
    var carry: u32 = 0;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        carry = @as(u32, fs[i]) -% sx[i] -% @as(u32, carry);
        sx[i] = @as(u8, @truncate(carry));
        carry = (carry >> 8) & 1;
    }
    return reduce64(sx);
}

/// Return (a-b) (mod L)
pub fn sub(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return add(a, neg(b));
}

/// Return a random scalar < L
pub fn random() CompressedScalar {
    return Scalar.random().toBytes();
}

/// A scalar in unpacked representation
pub const Scalar = struct {
    const Limbs = [5]u64;
    limbs: Limbs = undefined,

    /// Unpack a 32-byte representation of a scalar
    pub fn fromBytes(bytes: CompressedScalar) Scalar {
        var scalar = ScalarDouble.fromBytes32(bytes);
        return scalar.reduce(5);
    }

    /// Unpack a 64-byte representation of a scalar
    pub fn fromBytes64(bytes: [64]u8) Scalar {
        var scalar = ScalarDouble.fromBytes64(bytes);
        return scalar.reduce(5);
    }

    /// Pack a scalar into bytes
    pub fn toBytes(expanded: *const Scalar) CompressedScalar {
        var bytes: CompressedScalar = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            mem.writeInt(u64, bytes[i * 7 ..][0..8], expanded.limbs[i], .little);
        }
        mem.writeInt(u32, bytes[i * 7 ..][0..4], @intCast(expanded.limbs[i]), .little);
        return bytes;
    }

    /// Return true if the scalar is zero
    pub fn isZero(n: Scalar) bool {
        const limbs = n.limbs;
        return (limbs[0] | limbs[1] | limbs[2] | limbs[3] | limbs[4]) == 0;
    }

    /// Return x+y (mod L)
    pub fn add(x: Scalar, y: Scalar) Scalar {
        const carry0 = (x.limbs[0] + y.limbs[0]) >> 56;
        const t0 = (x.limbs[0] + y.limbs[0]) & 0xffffffffffffff;
        const t00 = t0;
        const c0 = carry0;
        const carry1 = (x.limbs[1] + y.limbs[1] + c0) >> 56;
        const t1 = (x.limbs[1] + y.limbs[1] + c0) & 0xffffffffffffff;
        const t10 = t1;
        const c1 = carry1;
        const carry2 = (x.limbs[2] + y.limbs[2] + c1) >> 56;
        const t2 = (x.limbs[2] + y.limbs[2] + c1) & 0xffffffffffffff;
        const t20 = t2;
        const c2 = carry2;
        const carry = (x.limbs[3] + y.limbs[3] + c2) >> 56;
        const t3 = (x.limbs[3] + y.limbs[3] + c2) & 0xffffffffffffff;
        const t30 = t3;
        const c3 = carry;
        const t4 = x.limbs[4] + y.limbs[4] + c3;

        const y01: u64 = 5175514460705773;
        const y11: u64 = 70332060721272408;
        const y21: u64 = 5342;
        const y31: u64 = 0;
        const y41: u64 = 268435456;

        const b5 = (t00 -% y01) >> 63;
        const t5 = ((b5 << 56) + t00) -% y01;
        const b0 = b5;
        const t01 = t5;
        const b6 = (t10 -% (y11 + b0)) >> 63;
        const t6 = ((b6 << 56) + t10) -% (y11 + b0);
        const b1 = b6;
        const t11 = t6;
        const b7 = (t20 -% (y21 + b1)) >> 63;
        const t7 = ((b7 << 56) + t20) -% (y21 + b1);
        const b2 = b7;
        const t21 = t7;
        const b8 = (t30 -% (y31 + b2)) >> 63;
        const t8 = ((b8 << 56) + t30) -% (y31 + b2);
        const b3 = b8;
        const t31 = t8;
        const b = (t4 -% (y41 + b3)) >> 63;
        const t = ((b << 56) + t4) -% (y41 + b3);
        const b4 = b;
        const t41 = t;

        const mask = (b4 -% 1);
        const z00 = t00 ^ (mask & (t00 ^ t01));
        const z10 = t10 ^ (mask & (t10 ^ t11));
        const z20 = t20 ^ (mask & (t20 ^ t21));
        const z30 = t30 ^ (mask & (t30 ^ t31));
        const z40 = t4 ^ (mask & (t4 ^ t41));

        return Scalar{ .limbs = .{ z00, z10, z20, z30, z40 } };
    }

    /// Return x*r (mod L)
    pub fn mul(x: Scalar, y: Scalar) Scalar {
        const xy000 = @as(u128, x.limbs[0]) * @as(u128, y.limbs[0]);
        const xy010 = @as(u128, x.limbs[0]) * @as(u128, y.limbs[1]);
        const xy020 = @as(u128, x.limbs[0]) * @as(u128, y.limbs[2]);
        const xy030 = @as(u128, x.limbs[0]) * @as(u128, y.limbs[3]);
        const xy040 = @as(u128, x.limbs[0]) * @as(u128, y.limbs[4]);
        const xy100 = @as(u128, x.limbs[1]) * @as(u128, y.limbs[0]);
        const xy110 = @as(u128, x.limbs[1]) * @as(u128, y.limbs[1]);
        const xy120 = @as(u128, x.limbs[1]) * @as(u128, y.limbs[2]);
        const xy130 = @as(u128, x.limbs[1]) * @as(u128, y.limbs[3]);
        const xy140 = @as(u128, x.limbs[1]) * @as(u128, y.limbs[4]);
        const xy200 = @as(u128, x.limbs[2]) * @as(u128, y.limbs[0]);
        const xy210 = @as(u128, x.limbs[2]) * @as(u128, y.limbs[1]);
        const xy220 = @as(u128, x.limbs[2]) * @as(u128, y.limbs[2]);
        const xy230 = @as(u128, x.limbs[2]) * @as(u128, y.limbs[3]);
        const xy240 = @as(u128, x.limbs[2]) * @as(u128, y.limbs[4]);
        const xy300 = @as(u128, x.limbs[3]) * @as(u128, y.limbs[0]);
        const xy310 = @as(u128, x.limbs[3]) * @as(u128, y.limbs[1]);
        const xy320 = @as(u128, x.limbs[3]) * @as(u128, y.limbs[2]);
        const xy330 = @as(u128, x.limbs[3]) * @as(u128, y.limbs[3]);
        const xy340 = @as(u128, x.limbs[3]) * @as(u128, y.limbs[4]);
        const xy400 = @as(u128, x.limbs[4]) * @as(u128, y.limbs[0]);
        const xy410 = @as(u128, x.limbs[4]) * @as(u128, y.limbs[1]);
        const xy420 = @as(u128, x.limbs[4]) * @as(u128, y.limbs[2]);
        const xy430 = @as(u128, x.limbs[4]) * @as(u128, y.limbs[3]);
        const xy440 = @as(u128, x.limbs[4]) * @as(u128, y.limbs[4]);
        const z00 = xy000;
        const z10 = xy010 + xy100;
        const z20 = xy020 + xy110 + xy200;
        const z30 = xy030 + xy120 + xy210 + xy300;
        const z40 = xy040 + xy130 + xy220 + xy310 + xy400;
        const z50 = xy140 + xy230 + xy320 + xy410;
        const z60 = xy240 + xy330 + xy420;
        const z70 = xy340 + xy430;
        const z80 = xy440;

        const carry0 = z00 >> 56;
        const t10 = @as(u64, @truncate(z00)) & 0xffffffffffffff;
        const c00 = carry0;
        const t00 = t10;
        const carry1 = (z10 + c00) >> 56;
        const t11 = @as(u64, @truncate((z10 + c00))) & 0xffffffffffffff;
        const c10 = carry1;
        const t12 = t11;
        const carry2 = (z20 + c10) >> 56;
        const t13 = @as(u64, @truncate((z20 + c10))) & 0xffffffffffffff;
        const c20 = carry2;
        const t20 = t13;
        const carry3 = (z30 + c20) >> 56;
        const t14 = @as(u64, @truncate((z30 + c20))) & 0xffffffffffffff;
        const c30 = carry3;
        const t30 = t14;
        const carry4 = (z40 + c30) >> 56;
        const t15 = @as(u64, @truncate((z40 + c30))) & 0xffffffffffffff;
        const c40 = carry4;
        const t40 = t15;
        const carry5 = (z50 + c40) >> 56;
        const t16 = @as(u64, @truncate((z50 + c40))) & 0xffffffffffffff;
        const c50 = carry5;
        const t50 = t16;
        const carry6 = (z60 + c50) >> 56;
        const t17 = @as(u64, @truncate((z60 + c50))) & 0xffffffffffffff;
        const c60 = carry6;
        const t60 = t17;
        const carry7 = (z70 + c60) >> 56;
        const t18 = @as(u64, @truncate((z70 + c60))) & 0xffffffffffffff;
        const c70 = carry7;
        const t70 = t18;
        const carry8 = (z80 + c70) >> 56;
        const t19 = @as(u64, @truncate((z80 + c70))) & 0xffffffffffffff;
        const c80 = carry8;
        const t80 = t19;
        const t90 = (@as(u64, @truncate(c80)));
        const r0 = t00;
        const r1 = t12;
        const r2 = t20;
        const r3 = t30;
        const r4 = t40;
        const r5 = t50;
        const r6 = t60;
        const r7 = t70;
        const r8 = t80;
        const r9 = t90;

        const m0: u64 = 5175514460705773;
        const m1: u64 = 70332060721272408;
        const m2: u64 = 5342;
        const m3: u64 = 0;
        const m4: u64 = 268435456;
        const mu0: u64 = 44162584779952923;
        const mu1: u64 = 9390964836247533;
        const mu2: u64 = 72057594036560134;
        const mu3: u64 = 72057594037927935;
        const mu4: u64 = 68719476735;

        const y_ = (r5 & 0xffffff) << 32;
        const x_ = r4 >> 24;
        const z01 = (x_ | y_);
        const y_0 = (r6 & 0xffffff) << 32;
        const x_0 = r5 >> 24;
        const z11 = (x_0 | y_0);
        const y_1 = (r7 & 0xffffff) << 32;
        const x_1 = r6 >> 24;
        const z21 = (x_1 | y_1);
        const y_2 = (r8 & 0xffffff) << 32;
        const x_2 = r7 >> 24;
        const z31 = (x_2 | y_2);
        const y_3 = (r9 & 0xffffff) << 32;
        const x_3 = r8 >> 24;
        const z41 = (x_3 | y_3);
        const q0 = z01;
        const q1 = z11;
        const q2 = z21;
        const q3 = z31;
        const q4 = z41;
        const xy001 = @as(u128, q0) * @as(u128, mu0);
        const xy011 = @as(u128, q0) * @as(u128, mu1);
        const xy021 = @as(u128, q0) * @as(u128, mu2);
        const xy031 = @as(u128, q0) * @as(u128, mu3);
        const xy041 = @as(u128, q0) * @as(u128, mu4);
        const xy101 = @as(u128, q1) * @as(u128, mu0);
        const xy111 = @as(u128, q1) * @as(u128, mu1);
        const xy121 = @as(u128, q1) * @as(u128, mu2);
        const xy131 = @as(u128, q1) * @as(u128, mu3);
        const xy14 = @as(u128, q1) * @as(u128, mu4);
        const xy201 = @as(u128, q2) * @as(u128, mu0);
        const xy211 = @as(u128, q2) * @as(u128, mu1);
        const xy221 = @as(u128, q2) * @as(u128, mu2);
        const xy23 = @as(u128, q2) * @as(u128, mu3);
        const xy24 = @as(u128, q2) * @as(u128, mu4);
        const xy301 = @as(u128, q3) * @as(u128, mu0);
        const xy311 = @as(u128, q3) * @as(u128, mu1);
        const xy32 = @as(u128, q3) * @as(u128, mu2);
        const xy33 = @as(u128, q3) * @as(u128, mu3);
        const xy34 = @as(u128, q3) * @as(u128, mu4);
        const xy401 = @as(u128, q4) * @as(u128, mu0);
        const xy41 = @as(u128, q4) * @as(u128, mu1);
        const xy42 = @as(u128, q4) * @as(u128, mu2);
        const xy43 = @as(u128, q4) * @as(u128, mu3);
        const xy44 = @as(u128, q4) * @as(u128, mu4);
        const z02 = xy001;
        const z12 = xy011 + xy101;
        const z22 = xy021 + xy111 + xy201;
        const z32 = xy031 + xy121 + xy211 + xy301;
        const z42 = xy041 + xy131 + xy221 + xy311 + xy401;
        const z5 = xy14 + xy23 + xy32 + xy41;
        const z6 = xy24 + xy33 + xy42;
        const z7 = xy34 + xy43;
        const z8 = xy44;

        const carry9 = z02 >> 56;
        const c01 = carry9;
        const carry10 = (z12 + c01) >> 56;
        const c11 = carry10;
        const carry11 = (z22 + c11) >> 56;
        const c21 = carry11;
        const carry12 = (z32 + c21) >> 56;
        const c31 = carry12;
        const carry13 = (z42 + c31) >> 56;
        const t24 = @as(u64, @truncate(z42 + c31)) & 0xffffffffffffff;
        const c41 = carry13;
        const t41 = t24;
        const carry14 = (z5 + c41) >> 56;
        const t25 = @as(u64, @truncate(z5 + c41)) & 0xffffffffffffff;
        const c5 = carry14;
        const t5 = t25;
        const carry15 = (z6 + c5) >> 56;
        const t26 = @as(u64, @truncate(z6 + c5)) & 0xffffffffffffff;
        const c6 = carry15;
        const t6 = t26;
        const carry16 = (z7 + c6) >> 56;
        const t27 = @as(u64, @truncate(z7 + c6)) & 0xffffffffffffff;
        const c7 = carry16;
        const t7 = t27;
        const carry17 = (z8 + c7) >> 56;
        const t28 = @as(u64, @truncate(z8 + c7)) & 0xffffffffffffff;
        const c8 = carry17;
        const t8 = t28;
        const t9 = @as(u64, @truncate(c8));

        const qmu4_ = t41;
        const qmu5_ = t5;
        const qmu6_ = t6;
        const qmu7_ = t7;
        const qmu8_ = t8;
        const qmu9_ = t9;
        const y_4 = (qmu5_ & 0xffffffffff) << 16;
        const x_4 = qmu4_ >> 40;
        const z03 = (x_4 | y_4);
        const y_5 = (qmu6_ & 0xffffffffff) << 16;
        const x_5 = qmu5_ >> 40;
        const z13 = (x_5 | y_5);
        const y_6 = (qmu7_ & 0xffffffffff) << 16;
        const x_6 = qmu6_ >> 40;
        const z23 = (x_6 | y_6);
        const y_7 = (qmu8_ & 0xffffffffff) << 16;
        const x_7 = qmu7_ >> 40;
        const z33 = (x_7 | y_7);
        const y_8 = (qmu9_ & 0xffffffffff) << 16;
        const x_8 = qmu8_ >> 40;
        const z43 = (x_8 | y_8);
        const qdiv0 = z03;
        const qdiv1 = z13;
        const qdiv2 = z23;
        const qdiv3 = z33;
        const qdiv4 = z43;
        const r01 = r0;
        const r11 = r1;
        const r21 = r2;
        const r31 = r3;
        const r41 = (r4 & 0xffffffffff);

        const xy00 = @as(u128, qdiv0) * @as(u128, m0);
        const xy01 = @as(u128, qdiv0) * @as(u128, m1);
        const xy02 = @as(u128, qdiv0) * @as(u128, m2);
        const xy03 = @as(u128, qdiv0) * @as(u128, m3);
        const xy04 = @as(u128, qdiv0) * @as(u128, m4);
        const xy10 = @as(u128, qdiv1) * @as(u128, m0);
        const xy11 = @as(u128, qdiv1) * @as(u128, m1);
        const xy12 = @as(u128, qdiv1) * @as(u128, m2);
        const xy13 = @as(u128, qdiv1) * @as(u128, m3);
        const xy20 = @as(u128, qdiv2) * @as(u128, m0);
        const xy21 = @as(u128, qdiv2) * @as(u128, m1);
        const xy22 = @as(u128, qdiv2) * @as(u128, m2);
        const xy30 = @as(u128, qdiv3) * @as(u128, m0);
        const xy31 = @as(u128, qdiv3) * @as(u128, m1);
        const xy40 = @as(u128, qdiv4) * @as(u128, m0);
        const carry18 = xy00 >> 56;
        const t29 = @as(u64, @truncate(xy00)) & 0xffffffffffffff;
        const c0 = carry18;
        const t01 = t29;
        const carry19 = (xy01 + xy10 + c0) >> 56;
        const t31 = @as(u64, @truncate(xy01 + xy10 + c0)) & 0xffffffffffffff;
        const c12 = carry19;
        const t110 = t31;
        const carry20 = (xy02 + xy11 + xy20 + c12) >> 56;
        const t32 = @as(u64, @truncate(xy02 + xy11 + xy20 + c12)) & 0xffffffffffffff;
        const c22 = carry20;
        const t210 = t32;
        const carry = (xy03 + xy12 + xy21 + xy30 + c22) >> 56;
        const t33 = @as(u64, @truncate(xy03 + xy12 + xy21 + xy30 + c22)) & 0xffffffffffffff;
        const c32 = carry;
        const t34 = t33;
        const t42 = @as(u64, @truncate(xy04 + xy13 + xy22 + xy31 + xy40 + c32)) & 0xffffffffff;

        const qmul0 = t01;
        const qmul1 = t110;
        const qmul2 = t210;
        const qmul3 = t34;
        const qmul4 = t42;
        const b5 = (r01 -% qmul0) >> 63;
        const t35 = ((b5 << 56) + r01) -% qmul0;
        const c1 = b5;
        const t02 = t35;
        const b6 = (r11 -% (qmul1 + c1)) >> 63;
        const t36 = ((b6 << 56) + r11) -% (qmul1 + c1);
        const c2 = b6;
        const t111 = t36;
        const b7 = (r21 -% (qmul2 + c2)) >> 63;
        const t37 = ((b7 << 56) + r21) -% (qmul2 + c2);
        const c3 = b7;
        const t211 = t37;
        const b8 = (r31 -% (qmul3 + c3)) >> 63;
        const t38 = ((b8 << 56) + r31) -% (qmul3 + c3);
        const c4 = b8;
        const t39 = t38;
        const b9 = (r41 -% (qmul4 + c4)) >> 63;
        const t43 = ((b9 << 40) + r41) -% (qmul4 + c4);
        const t44 = t43;
        const s0 = t02;
        const s1 = t111;
        const s2 = t211;
        const s3 = t39;
        const s4 = t44;

        const y01: u64 = 5175514460705773;
        const y11: u64 = 70332060721272408;
        const y21: u64 = 5342;
        const y31: u64 = 0;
        const y41: u64 = 268435456;

        const b10 = (s0 -% y01) >> 63;
        const t45 = ((b10 << 56) + s0) -% y01;
        const b0 = b10;
        const t0 = t45;
        const b11 = (s1 -% (y11 + b0)) >> 63;
        const t46 = ((b11 << 56) + s1) -% (y11 + b0);
        const b1 = b11;
        const t1 = t46;
        const b12 = (s2 -% (y21 + b1)) >> 63;
        const t47 = ((b12 << 56) + s2) -% (y21 + b1);
        const b2 = b12;
        const t2 = t47;
        const b13 = (s3 -% (y31 + b2)) >> 63;
        const t48 = ((b13 << 56) + s3) -% (y31 + b2);
        const b3 = b13;
        const t3 = t48;
        const b = (s4 -% (y41 + b3)) >> 63;
        const t = ((b << 56) + s4) -% (y41 + b3);
        const b4 = b;
        const t4 = t;
        const mask = (b4 -% @as(u64, @intCast(((1)))));
        const z04 = s0 ^ (mask & (s0 ^ t0));
        const z14 = s1 ^ (mask & (s1 ^ t1));
        const z24 = s2 ^ (mask & (s2 ^ t2));
        const z34 = s3 ^ (mask & (s3 ^ t3));
        const z44 = s4 ^ (mask & (s4 ^ t4));

        return Scalar{ .limbs = .{ z04, z14, z24, z34, z44 } };
    }

    /// Return x^2 (mod L)
    pub fn sq(x: Scalar) Scalar {
        return x.mul(x);
    }

    /// Square a scalar `n` times
    inline fn sqn(x: Scalar, comptime n: comptime_int) Scalar {
        var i: usize = 0;
        var t = x;
        while (i < n) : (i += 1) {
            t = t.sq();
        }
        return t;
    }

    /// Square and multiply
    fn sqn_mul(x: Scalar, comptime n: comptime_int, y: Scalar) Scalar {
        return x.sqn(n).mul(y);
    }

    /// Return the inverse of a scalar (mod L), or 0 if x=0.
    pub fn invert(x: Scalar) Scalar {
        const _10 = x.sq();
        const _11 = x.mul(_10);
        const _100 = x.mul(_11);
        const _1000 = _100.sq();
        const _1010 = _10.mul(_1000);
        const _1011 = x.mul(_1010);
        const _10000 = _1000.sq();
        const _10110 = _1011.sq();
        const _100000 = _1010.mul(_10110);
        const _100110 = _10000.mul(_10110);
        const _1000000 = _100000.sq();
        const _1010000 = _10000.mul(_1000000);
        const _1010011 = _11.mul(_1010000);
        const _1100011 = _10000.mul(_1010011);
        const _1100111 = _100.mul(_1100011);
        const _1101011 = _100.mul(_1100111);
        const _10010011 = _1000000.mul(_1010011);
        const _10010111 = _100.mul(_10010011);
        const _10111101 = _100110.mul(_10010111);
        const _11010011 = _10110.mul(_10111101);
        const _11100111 = _1010000.mul(_10010111);
        const _11101011 = _100.mul(_11100111);
        const _11110101 = _1010.mul(_11101011);
        return _1011.mul(_11110101).sqn_mul(126, _1010011).sqn_mul(9, _10).mul(_11110101)
            .sqn_mul(7, _1100111).sqn_mul(9, _11110101).sqn_mul(11, _10111101).sqn_mul(8, _11100111)
            .sqn_mul(9, _1101011).sqn_mul(6, _1011).sqn_mul(14, _10010011).sqn_mul(10, _1100011)
            .sqn_mul(9, _10010111).sqn_mul(10, _11110101).sqn_mul(8, _11010011).sqn_mul(8, _11101011);
    }

    /// Return a random scalar < L.
    pub fn random() Scalar {
        var s: [64]u8 = undefined;
        while (true) {
            crypto.random.bytes(&s);
            const n = Scalar.fromBytes64(s);
            if (!n.isZero()) {
                return n;
            }
        }
    }
};

const ScalarDouble = struct {
    const Limbs = [10]u64;
    limbs: Limbs = undefined,

    fn fromBytes64(bytes: [64]u8) ScalarDouble {
        var limbs: Limbs = undefined;
        var i: usize = 0;
        while (i < 9) : (i += 1) {
            limbs[i] = mem.readInt(u64, bytes[i * 7 ..][0..8], .little) & 0xffffffffffffff;
        }
        limbs[i] = @as(u64, bytes[i * 7]);
        return ScalarDouble{ .limbs = limbs };
    }

    fn fromBytes32(bytes: CompressedScalar) ScalarDouble {
        var limbs: Limbs = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            limbs[i] = mem.readInt(u64, bytes[i * 7 ..][0..8], .little) & 0xffffffffffffff;
        }
        limbs[i] = @as(u64, mem.readInt(u32, bytes[i * 7 ..][0..4], .little));
        @memset(limbs[5..], 0);
        return ScalarDouble{ .limbs = limbs };
    }

    fn toBytes(expanded_double: *ScalarDouble) CompressedScalar {
        return expanded_double.reduce(10).toBytes();
    }

    /// Barrett reduction
    fn reduce(expanded: *ScalarDouble, comptime limbs_count: usize) Scalar {
        const t = expanded.limbs;
        const t0 = if (limbs_count <= 0) 0 else t[0];
        const t1 = if (limbs_count <= 1) 0 else t[1];
        const t2 = if (limbs_count <= 2) 0 else t[2];
        const t3 = if (limbs_count <= 3) 0 else t[3];
        const t4 = if (limbs_count <= 4) 0 else t[4];
        const t5 = if (limbs_count <= 5) 0 else t[5];
        const t6 = if (limbs_count <= 6) 0 else t[6];
        const t7 = if (limbs_count <= 7) 0 else t[7];
        const t8 = if (limbs_count <= 8) 0 else t[8];
        const t9 = if (limbs_count <= 9) 0 else t[9];

        const m0: u64 = 5175514460705773;
        const m1: u64 = 70332060721272408;
        const m2: u64 = 5342;
        const m3: u64 = 0;
        const m4: u64 = 268435456;
        const mu0: u64 = 44162584779952923;
        const mu1: u64 = 9390964836247533;
        const mu2: u64 = 72057594036560134;
        const mu3: u64 = 0xffffffffffffff;
        const mu4: u64 = 68719476735;

        const y_ = (t5 & 0xffffff) << 32;
        const x_ = t4 >> 24;
        const z00 = x_ | y_;
        const y_0 = (t6 & 0xffffff) << 32;
        const x_0 = t5 >> 24;
        const z10 = x_0 | y_0;
        const y_1 = (t7 & 0xffffff) << 32;
        const x_1 = t6 >> 24;
        const z20 = x_1 | y_1;
        const y_2 = (t8 & 0xffffff) << 32;
        const x_2 = t7 >> 24;
        const z30 = x_2 | y_2;
        const y_3 = (t9 & 0xffffff) << 32;
        const x_3 = t8 >> 24;
        const z40 = x_3 | y_3;
        const q0 = z00;
        const q1 = z10;
        const q2 = z20;
        const q3 = z30;
        const q4 = z40;

        const xy000 = @as(u128, q0) * @as(u128, mu0);
        const xy010 = @as(u128, q0) * @as(u128, mu1);
        const xy020 = @as(u128, q0) * @as(u128, mu2);
        const xy030 = @as(u128, q0) * @as(u128, mu3);
        const xy040 = @as(u128, q0) * @as(u128, mu4);
        const xy100 = @as(u128, q1) * @as(u128, mu0);
        const xy110 = @as(u128, q1) * @as(u128, mu1);
        const xy120 = @as(u128, q1) * @as(u128, mu2);
        const xy130 = @as(u128, q1) * @as(u128, mu3);
        const xy14 = @as(u128, q1) * @as(u128, mu4);
        const xy200 = @as(u128, q2) * @as(u128, mu0);
        const xy210 = @as(u128, q2) * @as(u128, mu1);
        const xy220 = @as(u128, q2) * @as(u128, mu2);
        const xy23 = @as(u128, q2) * @as(u128, mu3);
        const xy24 = @as(u128, q2) * @as(u128, mu4);
        const xy300 = @as(u128, q3) * @as(u128, mu0);
        const xy310 = @as(u128, q3) * @as(u128, mu1);
        const xy32 = @as(u128, q3) * @as(u128, mu2);
        const xy33 = @as(u128, q3) * @as(u128, mu3);
        const xy34 = @as(u128, q3) * @as(u128, mu4);
        const xy400 = @as(u128, q4) * @as(u128, mu0);
        const xy41 = @as(u128, q4) * @as(u128, mu1);
        const xy42 = @as(u128, q4) * @as(u128, mu2);
        const xy43 = @as(u128, q4) * @as(u128, mu3);
        const xy44 = @as(u128, q4) * @as(u128, mu4);
        const z01 = xy000;
        const z11 = xy010 + xy100;
        const z21 = xy020 + xy110 + xy200;
        const z31 = xy030 + xy120 + xy210 + xy300;
        const z41 = xy040 + xy130 + xy220 + xy310 + xy400;
        const z5 = xy14 + xy23 + xy32 + xy41;
        const z6 = xy24 + xy33 + xy42;
        const z7 = xy34 + xy43;
        const z8 = xy44;

        const carry0 = z01 >> 56;
        const c00 = carry0;
        const carry1 = (z11 + c00) >> 56;
        const c10 = carry1;
        const carry2 = (z21 + c10) >> 56;
        const c20 = carry2;
        const carry3 = (z31 + c20) >> 56;
        const c30 = carry3;
        const carry4 = (z41 + c30) >> 56;
        const t103 = @as(u64, @as(u64, @truncate(z41 + c30))) & 0xffffffffffffff;
        const c40 = carry4;
        const t410 = t103;
        const carry5 = (z5 + c40) >> 56;
        const t104 = @as(u64, @as(u64, @truncate(z5 + c40))) & 0xffffffffffffff;
        const c5 = carry5;
        const t51 = t104;
        const carry6 = (z6 + c5) >> 56;
        const t105 = @as(u64, @as(u64, @truncate(z6 + c5))) & 0xffffffffffffff;
        const c6 = carry6;
        const t61 = t105;
        const carry7 = (z7 + c6) >> 56;
        const t106 = @as(u64, @as(u64, @truncate(z7 + c6))) & 0xffffffffffffff;
        const c7 = carry7;
        const t71 = t106;
        const carry8 = (z8 + c7) >> 56;
        const t107 = @as(u64, @as(u64, @truncate(z8 + c7))) & 0xffffffffffffff;
        const c8 = carry8;
        const t81 = t107;
        const t91 = @as(u64, @as(u64, @truncate(c8)));

        const qmu4_ = t410;
        const qmu5_ = t51;
        const qmu6_ = t61;
        const qmu7_ = t71;
        const qmu8_ = t81;
        const qmu9_ = t91;
        const y_4 = (qmu5_ & 0xffffffffff) << 16;
        const x_4 = qmu4_ >> 40;
        const z02 = x_4 | y_4;
        const y_5 = (qmu6_ & 0xffffffffff) << 16;
        const x_5 = qmu5_ >> 40;
        const z12 = x_5 | y_5;
        const y_6 = (qmu7_ & 0xffffffffff) << 16;
        const x_6 = qmu6_ >> 40;
        const z22 = x_6 | y_6;
        const y_7 = (qmu8_ & 0xffffffffff) << 16;
        const x_7 = qmu7_ >> 40;
        const z32 = x_7 | y_7;
        const y_8 = (qmu9_ & 0xffffffffff) << 16;
        const x_8 = qmu8_ >> 40;
        const z42 = x_8 | y_8;
        const qdiv0 = z02;
        const qdiv1 = z12;
        const qdiv2 = z22;
        const qdiv3 = z32;
        const qdiv4 = z42;
        const r0 = t0;
        const r1 = t1;
        const r2 = t2;
        const r3 = t3;
        const r4 = t4 & 0xffffffffff;

        const xy00 = @as(u128, qdiv0) * @as(u128, m0);
        const xy01 = @as(u128, qdiv0) * @as(u128, m1);
        const xy02 = @as(u128, qdiv0) * @as(u128, m2);
        const xy03 = @as(u128, qdiv0) * @as(u128, m3);
        const xy04 = @as(u128, qdiv0) * @as(u128, m4);
        const xy10 = @as(u128, qdiv1) * @as(u128, m0);
        const xy11 = @as(u128, qdiv1) * @as(u128, m1);
        const xy12 = @as(u128, qdiv1) * @as(u128, m2);
        const xy13 = @as(u128, qdiv1) * @as(u128, m3);
        const xy20 = @as(u128, qdiv2) * @as(u128, m0);
        const xy21 = @as(u128, qdiv2) * @as(u128, m1);
        const xy22 = @as(u128, qdiv2) * @as(u128, m2);
        const xy30 = @as(u128, qdiv3) * @as(u128, m0);
        const xy31 = @as(u128, qdiv3) * @as(u128, m1);
        const xy40 = @as(u128, qdiv4) * @as(u128, m0);
        const carry9 = xy00 >> 56;
        const t108 = @as(u64, @truncate(xy00)) & 0xffffffffffffff;
        const c0 = carry9;
        const t010 = t108;
        const carry10 = (xy01 + xy10 + c0) >> 56;
        const t109 = @as(u64, @truncate(xy01 + xy10 + c0)) & 0xffffffffffffff;
        const c11 = carry10;
        const t110 = t109;
        const carry11 = (xy02 + xy11 + xy20 + c11) >> 56;
        const t1010 = @as(u64, @truncate(xy02 + xy11 + xy20 + c11)) & 0xffffffffffffff;
        const c21 = carry11;
        const t210 = t1010;
        const carry = (xy03 + xy12 + xy21 + xy30 + c21) >> 56;
        const t1011 = @as(u64, @truncate(xy03 + xy12 + xy21 + xy30 + c21)) & 0xffffffffffffff;
        const c31 = carry;
        const t310 = t1011;
        const t411 = @as(u64, @truncate(xy04 + xy13 + xy22 + xy31 + xy40 + c31)) & 0xffffffffff;

        const qmul0 = t010;
        const qmul1 = t110;
        const qmul2 = t210;
        const qmul3 = t310;
        const qmul4 = t411;
        const b5 = (r0 -% qmul0) >> 63;
        const t1012 = ((b5 << 56) + r0) -% qmul0;
        const c1 = b5;
        const t011 = t1012;
        const b6 = (r1 -% (qmul1 + c1)) >> 63;
        const t1013 = ((b6 << 56) + r1) -% (qmul1 + c1);
        const c2 = b6;
        const t111 = t1013;
        const b7 = (r2 -% (qmul2 + c2)) >> 63;
        const t1014 = ((b7 << 56) + r2) -% (qmul2 + c2);
        const c3 = b7;
        const t211 = t1014;
        const b8 = (r3 -% (qmul3 + c3)) >> 63;
        const t1015 = ((b8 << 56) + r3) -% (qmul3 + c3);
        const c4 = b8;
        const t311 = t1015;
        const b9 = (r4 -% (qmul4 + c4)) >> 63;
        const t1016 = ((b9 << 40) + r4) -% (qmul4 + c4);
        const t412 = t1016;
        const s0 = t011;
        const s1 = t111;
        const s2 = t211;
        const s3 = t311;
        const s4 = t412;

        const y0: u64 = 5175514460705773;
        const y1: u64 = 70332060721272408;
        const y2: u64 = 5342;
        const y3: u64 = 0;
        const y4: u64 = 268435456;

        const b10 = (s0 -% y0) >> 63;
        const t1017 = ((b10 << 56) + s0) -% y0;
        const b0 = b10;
        const t01 = t1017;
        const b11 = (s1 -% (y1 + b0)) >> 63;
        const t1018 = ((b11 << 56) + s1) -% (y1 + b0);
        const b1 = b11;
        const t11 = t1018;
        const b12 = (s2 -% (y2 + b1)) >> 63;
        const t1019 = ((b12 << 56) + s2) -% (y2 + b1);
        const b2 = b12;
        const t21 = t1019;
        const b13 = (s3 -% (y3 + b2)) >> 63;
        const t1020 = ((b13 << 56) + s3) -% (y3 + b2);
        const b3 = b13;
        const t31 = t1020;
        const b = (s4 -% (y4 + b3)) >> 63;
        const t10 = ((b << 56) + s4) -% (y4 + b3);
        const b4 = b;
        const t41 = t10;
        const mask = b4 -% @as(u64, @as(u64, 1));
        const z03 = s0 ^ (mask & (s0 ^ t01));
        const z13 = s1 ^ (mask & (s1 ^ t11));
        const z23 = s2 ^ (mask & (s2 ^ t21));
        const z33 = s3 ^ (mask & (s3 ^ t31));
        const z43 = s4 ^ (mask & (s4 ^ t41));

        return Scalar{ .limbs = .{ z03, z13, z23, z33, z43 } };
    }
};

test "scalar25519" {
    const bytes: [32]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 255 };
    var x = Scalar.fromBytes(bytes);
    var y = x.toBytes();
    try rejectNonCanonical(y);
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&y)}), "1E979B917937F3DE71D18077F961F6CEFF01030405060708010203040506070F");

    const reduced = reduce(field_order_s);
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&reduced)}), "0000000000000000000000000000000000000000000000000000000000000000");
}

test "non-canonical scalar25519" {
    const too_targe: [32]u8 = .{ 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
    try std.testing.expectError(error.NonCanonical, rejectNonCanonical(too_targe));
}

test "mulAdd overflow check" {
    const a: [32]u8 = [_]u8{0xff} ** 32;
    const b: [32]u8 = [_]u8{0xff} ** 32;
    const c: [32]u8 = [_]u8{0xff} ** 32;
    const x = mulAdd(a, b, c);
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&x)}), "D14DF91389432C25AD60FF9791B9FD1D67BEF517D273ECCE3D9A307C1B419903");
}

test "scalar field inversion" {
    const bytes: [32]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    const x = Scalar.fromBytes(bytes);
    const inv = x.invert();
    const recovered_x = inv.invert();
    try std.testing.expectEqualSlices(u8, &bytes, &recovered_x.toBytes());
}

test "random scalar" {
    const s1 = random();
    const s2 = random();
    try std.testing.expect(!mem.eql(u8, &s1, &s2));
}

test "64-bit reduction" {
    const bytes = field_order_s ++ [_]u8{0} ** 32;
    const x = Scalar.fromBytes64(bytes);
    try std.testing.expect(x.isZero());
}
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;

const Sha512 = crypto.hash.sha2.Sha512;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

/// X25519 DH function.
pub const X25519 = struct {
    /// The underlying elliptic curve.
    pub const Curve = @import("curve25519.zig").Curve25519;
    /// Length (in bytes) of a secret key.
    pub const secret_length = 32;
    /// Length (in bytes) of a public key.
    pub const public_length = 32;
    /// Length (in bytes) of the output of the DH function.
    pub const shared_length = 32;
    /// Seed (for key pair creation) length in bytes.
    pub const seed_length = 32;

    /// An X25519 key pair.
    pub const KeyPair = struct {
        /// Public part.
        public_key: [public_length]u8,
        /// Secret part.
        secret_key: [secret_length]u8,

        /// Deterministically derive a key pair from a cryptograpically secure secret seed.
        ///
        /// Except in tests, applications should generally call `generate()` instead of this function.
        pub fn generateDeterministic(seed: [seed_length]u8) IdentityElementError!KeyPair {
            const kp = KeyPair{
                .public_key = try X25519.recoverPublicKey(seed),
                .secret_key = seed,
            };
            return kp;
        }

        /// Generate a new, random key pair.
        pub fn generate() KeyPair {
            var random_seed: [seed_length]u8 = undefined;
            while (true) {
                crypto.random.bytes(&random_seed);
                return generateDeterministic(random_seed) catch {
                    @branchHint(.unlikely);
                    continue;
                };
            }
        }

        /// Create a key pair from an Ed25519 key pair
        pub fn fromEd25519(ed25519_key_pair: crypto.sign.Ed25519.KeyPair) (IdentityElementError || EncodingError)!KeyPair {
            const seed = ed25519_key_pair.secret_key.seed();
            var az: [Sha512.digest_length]u8 = undefined;
            Sha512.hash(&seed, &az, .{});
            var sk = az[0..32].*;
            Curve.scalar.clamp(&sk);
            const pk = try publicKeyFromEd25519(ed25519_key_pair.public_key);
            return KeyPair{
                .public_key = pk,
                .secret_key = sk,
            };
        }
    };

    /// Compute the public key for a given private key.
    pub fn recoverPublicKey(secret_key: [secret_length]u8) IdentityElementError![public_length]u8 {
        const q = try Curve.basePoint.clampedMul(secret_key);
        return q.toBytes();
    }

    /// Compute the X25519 equivalent to an Ed25519 public eky.
    pub fn publicKeyFromEd25519(ed25519_public_key: crypto.sign.Ed25519.PublicKey) (IdentityElementError || EncodingError)![public_length]u8 {
        const pk_ed = try crypto.ecc.Edwards25519.fromBytes(ed25519_public_key.bytes);
        const pk = try Curve.fromEdwards25519(pk_ed);
        return pk.toBytes();
    }

    /// Compute the scalar product of a public key and a secret scalar.
    /// Note that the output should not be used as a shared secret without
    /// hashing it first.
    pub fn scalarmult(secret_key: [secret_length]u8, public_key: [public_length]u8) IdentityElementError![shared_length]u8 {
        const q = try Curve.fromBytes(public_key).clampedMul(secret_key);
        return q.toBytes();
    }
};

const htest = @import("../test.zig");

test "public key calculation from secret key" {
    var sk: [32]u8 = undefined;
    var pk_expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(sk[0..], "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    _ = try fmt.hexToBytes(pk_expected[0..], "f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50");
    const pk_calculated = try X25519.recoverPublicKey(sk);
    try std.testing.expectEqual(pk_calculated, pk_expected);
}

test "rfc7748 vector1" {
    const secret_key = [32]u8{ 0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4 };
    const public_key = [32]u8{ 0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c };

    const expected_output = [32]u8{ 0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52 };

    const output = try X25519.scalarmult(secret_key, public_key);
    try std.testing.expectEqual(output, expected_output);
}

test "rfc7748 vector2" {
    const secret_key = [32]u8{ 0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d };
    const public_key = [32]u8{ 0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93 };

    const expected_output = [32]u8{ 0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57 };

    const output = try X25519.scalarmult(secret_key, public_key);
    try std.testing.expectEqual(output, expected_output);
}

test "rfc7748 one iteration" {
    const initial_value = [32]u8{ 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const expected_output = [32]u8{ 0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79 };

    var k: [32]u8 = initial_value;
    var u: [32]u8 = initial_value;

    var i: usize = 0;
    while (i < 1) : (i += 1) {
        const output = try X25519.scalarmult(k, u);
        u = k;
        k = output;
    }

    try std.testing.expectEqual(k, expected_output);
}

test "rfc7748 1,000 iterations" {
    // These iteration tests are slow so we always skip them. Results have been verified.
    if (true) {
        return error.SkipZigTest;
    }

    const initial_value = [32]u8{ 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const expected_output = [32]u8{ 0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51 };

    var k: [32]u8 = initial_value.*;
    var u: [32]u8 = initial_value.*;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const output = try X25519.scalarmult(&k, &u);
        u = k;
        k = output;
    }

    try std.testing.expectEqual(k, expected_output);
}

test "rfc7748 1,000,000 iterations" {
    if (true) {
        return error.SkipZigTest;
    }

    const initial_value = [32]u8{ 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const expected_output = [32]u8{ 0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd, 0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f, 0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf, 0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24 };

    var k: [32]u8 = initial_value.*;
    var u: [32]u8 = initial_value.*;

    var i: usize = 0;
    while (i < 1000000) : (i += 1) {
        const output = try X25519.scalarmult(&k, &u);
        u = k;
        k = output;
    }

    try std.testing.expectEqual(k[0..], expected_output);
}

test "edwards25519 -> curve25519 map" {
    const ed_kp = try crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    const mont_kp = try X25519.KeyPair.fromEd25519(ed_kp);
    try htest.assertEqual("90e7595fc89e52fdfddce9c6a43d74dbf6047025ee0462d2d172e8b6a2841d6e", &mont_kp.secret_key);
    try htest.assertEqual("cc4f2cdb695dd766f34118eb67b98652fed1d8bc49c330b119bbfa8a64989378", &mont_kp.public_key);
}
//! AEGIS is a very fast authenticated encryption system built on top of the core AES function.
//!
//! The AEGIS-128* variants have a 128 bit key and a 128 bit nonce.
//! The AEGIS-256* variants have a 256 bit key and a 256 bit nonce.
//! All of them can compute 128 and 256 bit authentication tags.
//!
//! The AEGIS cipher family offers performance that significantly exceeds that of AES-GCM with
//! hardware support for parallelizable AES block encryption.
//!
//! On high-end Intel CPUs with AVX-512 support, AEGIS-128X4 and AEGIS-256X4 are the fastest options.
//! On other modern server, desktop and mobile CPUs, AEGIS-128X2 and AEGIS-256X2 are usually the fastest options.
//! AEGIS-128L and AEGIS-256 perform well on a broad range of platforms, including WebAssembly.
//!
//! Unlike with AES-GCM, nonces can be safely chosen at random with no practical limit when using AEGIS-256*.
//! AEGIS-128* also allows for more messages to be safely encrypted when using random nonces.
//!
//! Unless the associated data can be fully controled by an adversary, AEGIS is believed to be key-committing,
//! making it a safer choice than most other AEADs when the key has low entropy, or can be controlled by an attacker.
//!
//! Finally, leaking the state does not leak the key.
//!
//! https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const assert = std.debug.assert;
const AuthenticationError = crypto.errors.AuthenticationError;

/// AEGIS-128X4 with a 128 bit tag
pub const Aegis128X4 = Aegis128XGeneric(4, 128);
/// AEGIS-128X2 with a 128 bit tag
pub const Aegis128X2 = Aegis128XGeneric(2, 128);
/// AEGIS-128L with a 128 bit tag
pub const Aegis128L = Aegis128XGeneric(1, 128);

/// AEGIS-256X4 with a 128 bit tag
pub const Aegis256X4 = Aegis256XGeneric(4, 128);
/// AEGIS-256X2 with a 128 bit tag
pub const Aegis256X2 = Aegis256XGeneric(2, 128);
/// AEGIS-256 with a 128 bit tag
pub const Aegis256 = Aegis256XGeneric(1, 128);

/// AEGIS-128X4 with a 256 bit tag
pub const Aegis128X4_256 = Aegis128XGeneric(4, 256);
/// AEGIS-128X2 with a 256 bit tag
pub const Aegis128X2_256 = Aegis128XGeneric(2, 256);
/// AEGIS-128L with a 256 bit tag
pub const Aegis128L_256 = Aegis128XGeneric(1, 256);

/// AEGIS-256X4 with a 256 bit tag
pub const Aegis256X4_256 = Aegis256XGeneric(4, 256);
/// AEGIS-256X2 with a 256 bit tag
pub const Aegis256X2_256 = Aegis256XGeneric(2, 256);
/// AEGIS-256 with a 256 bit tag
pub const Aegis256_256 = Aegis256XGeneric(1, 256);

fn State128X(comptime degree: u7) type {
    return struct {
        const AesBlockVec = crypto.core.aes.BlockVec(degree);
        const State = @This();

        blocks: [8]AesBlockVec,

        const aes_block_length = AesBlockVec.block_length;
        const rate = aes_block_length * 2;
        const alignment = AesBlockVec.native_word_size;

        fn init(key: [16]u8, nonce: [16]u8) State {
            const c1 = AesBlockVec.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** degree);
            const c2 = AesBlockVec.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** degree);
            const key_block = AesBlockVec.fromBytes(&(key ** degree));
            const nonce_block = AesBlockVec.fromBytes(&(nonce ** degree));
            const blocks = [8]AesBlockVec{
                key_block.xorBlocks(nonce_block),
                c1,
                c2,
                c1,
                key_block.xorBlocks(nonce_block),
                key_block.xorBlocks(c2),
                key_block.xorBlocks(c1),
                key_block.xorBlocks(c2),
            };
            var state = State{ .blocks = blocks };
            if (degree > 1) {
                const context_block = ctx: {
                    var contexts_bytes = [_]u8{0} ** aes_block_length;
                    for (0..degree) |i| {
                        contexts_bytes[i * 16] = @intCast(i);
                        contexts_bytes[i * 16 + 1] = @intCast(degree - 1);
                    }
                    break :ctx AesBlockVec.fromBytes(&contexts_bytes);
                };
                for (0..10) |_| {
                    state.blocks[3] = state.blocks[3].xorBlocks(context_block);
                    state.blocks[7] = state.blocks[7].xorBlocks(context_block);
                    state.update(nonce_block, key_block);
                }
            } else {
                for (0..10) |_| {
                    state.update(nonce_block, key_block);
                }
            }
            return state;
        }

        inline fn update(state: *State, d1: AesBlockVec, d2: AesBlockVec) void {
            const blocks = &state.blocks;
            const tmp = blocks[7];
            comptime var i: usize = 7;
            inline while (i > 0) : (i -= 1) {
                blocks[i] = blocks[i - 1].encrypt(blocks[i]);
            }
            blocks[0] = tmp.encrypt(blocks[0]);
            blocks[0] = blocks[0].xorBlocks(d1);
            blocks[4] = blocks[4].xorBlocks(d2);
        }

        fn absorb(state: *State, src: *const [rate]u8) void {
            const msg0 = AesBlockVec.fromBytes(src[0..aes_block_length]);
            const msg1 = AesBlockVec.fromBytes(src[aes_block_length..rate]);
            state.update(msg0, msg1);
        }

        fn enc(state: *State, dst: *[rate]u8, src: *const [rate]u8) void {
            const blocks = &state.blocks;
            const msg0 = AesBlockVec.fromBytes(src[0..aes_block_length]);
            const msg1 = AesBlockVec.fromBytes(src[aes_block_length..rate]);
            var tmp0 = msg0.xorBlocks(blocks[6]).xorBlocks(blocks[1]);
            var tmp1 = msg1.xorBlocks(blocks[2]).xorBlocks(blocks[5]);
            tmp0 = tmp0.xorBlocks(blocks[2].andBlocks(blocks[3]));
            tmp1 = tmp1.xorBlocks(blocks[6].andBlocks(blocks[7]));
            dst[0..aes_block_length].* = tmp0.toBytes();
            dst[aes_block_length..rate].* = tmp1.toBytes();
            state.update(msg0, msg1);
        }

        fn dec(state: *State, dst: *[rate]u8, src: *const [rate]u8) void {
            const blocks = &state.blocks;
            var msg0 = AesBlockVec.fromBytes(src[0..aes_block_length]).xorBlocks(blocks[6]).xorBlocks(blocks[1]);
            var msg1 = AesBlockVec.fromBytes(src[aes_block_length..rate]).xorBlocks(blocks[2]).xorBlocks(blocks[5]);
            msg0 = msg0.xorBlocks(blocks[2].andBlocks(blocks[3]));
            msg1 = msg1.xorBlocks(blocks[6].andBlocks(blocks[7]));
            dst[0..aes_block_length].* = msg0.toBytes();
            dst[aes_block_length..rate].* = msg1.toBytes();
            state.update(msg0, msg1);
        }

        fn decLast(state: *State, dst: []u8, src: []const u8) void {
            const blocks = &state.blocks;
            const z0 = blocks[6].xorBlocks(blocks[1]).xorBlocks(blocks[2].andBlocks(blocks[3]));
            const z1 = blocks[2].xorBlocks(blocks[5]).xorBlocks(blocks[6].andBlocks(blocks[7]));
            var pad = [_]u8{0} ** rate;
            pad[0..aes_block_length].* = z0.toBytes();
            pad[aes_block_length..].* = z1.toBytes();
            for (pad[0..src.len], src) |*p, x| p.* ^= x;
            @memcpy(dst, pad[0..src.len]);
            @memset(pad[src.len..], 0);
            const msg0 = AesBlockVec.fromBytes(pad[0..aes_block_length]);
            const msg1 = AesBlockVec.fromBytes(pad[aes_block_length..rate]);
            state.update(msg0, msg1);
        }

        fn finalize(state: *State, comptime tag_bits: u9, adlen: usize, mlen: usize) [tag_bits / 8]u8 {
            const blocks = &state.blocks;
            var sizes: [aes_block_length]u8 = undefined;
            mem.writeInt(u64, sizes[0..8], @as(u64, adlen) * 8, .little);
            mem.writeInt(u64, sizes[8..16], @as(u64, mlen) * 8, .little);
            for (1..degree) |i| {
                @memcpy(sizes[i * 16 ..][0..16], sizes[0..16]);
            }
            const tmp = AesBlockVec.fromBytes(&sizes).xorBlocks(blocks[2]);
            for (0..7) |_| {
                state.update(tmp, tmp);
            }
            switch (tag_bits) {
                128 => {
                    var tag_multi = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).xorBlocks(blocks[4]).xorBlocks(blocks[5]).xorBlocks(blocks[6]).toBytes();
                    var tag = tag_multi[0..16].*;
                    @memcpy(tag[0..], tag_multi[0..16]);
                    for (1..degree) |d| {
                        for (0..16) |i| {
                            tag[i] ^= tag_multi[d * 16 + i];
                        }
                    }
                    return tag;
                },
                256 => {
                    const tag_multi_1 = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).toBytes();
                    const tag_multi_2 = blocks[4].xorBlocks(blocks[5]).xorBlocks(blocks[6]).xorBlocks(blocks[7]).toBytes();
                    var tag = tag_multi_1[0..16].* ++ tag_multi_2[0..16].*;
                    for (1..degree) |d| {
                        for (0..16) |i| {
                            tag[i] ^= tag_multi_1[d * 16 + i];
                            tag[i + 16] ^= tag_multi_2[d * 16 + i];
                        }
                    }
                    return tag;
                },
                else => unreachable,
            }
        }

        fn finalizeMac(state: *State, comptime tag_bits: u9, datalen: usize) [tag_bits / 8]u8 {
            const blocks = &state.blocks;
            var sizes: [aes_block_length]u8 = undefined;
            mem.writeInt(u64, sizes[0..8], @as(u64, datalen) * 8, .little);
            mem.writeInt(u64, sizes[8..16], tag_bits, .little);
            for (1..degree) |i| {
                @memcpy(sizes[i * 16 ..][0..16], sizes[0..16]);
            }
            var t = blocks[2].xorBlocks(AesBlockVec.fromBytes(&sizes));
            for (0..7) |_| {
                state.update(t, t);
            }
            if (degree > 1) {
                var v = [_]u8{0} ** rate;
                switch (tag_bits) {
                    128 => {
                        const tags = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).xorBlocks(blocks[4]).xorBlocks(blocks[5]).xorBlocks(blocks[6]).toBytes();
                        for (0..degree / 2) |d| {
                            v[0..16].* = tags[d * 32 ..][0..16].*;
                            v[rate / 2 ..][0..16].* = tags[d * 32 ..][16..32].*;
                            state.absorb(&v);
                        }
                    },
                    256 => {
                        const tags_0 = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).toBytes();
                        const tags_1 = blocks[4].xorBlocks(blocks[5]).xorBlocks(blocks[6]).xorBlocks(blocks[7]).toBytes();
                        for (1..degree) |d| {
                            v[0..16].* = tags_0[d * 16 ..][0..16].*;
                            v[rate / 2 ..][0..16].* = tags_1[d * 16 ..][0..16].*;
                            state.absorb(&v);
                        }
                    },
                    else => unreachable,
                }
                mem.writeInt(u64, sizes[0..8], degree, .little);
                mem.writeInt(u64, sizes[8..16], tag_bits, .little);
                t = blocks[2].xorBlocks(AesBlockVec.fromBytes(&sizes));
                for (0..7) |_| {
                    state.update(t, t);
                }
            }
            switch (tag_bits) {
                128 => {
                    const tags = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).xorBlocks(blocks[4]).xorBlocks(blocks[5]).xorBlocks(blocks[6]).toBytes();
                    return tags[0..16].*;
                },
                256 => {
                    const tags_0 = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).toBytes();
                    const tags_1 = blocks[4].xorBlocks(blocks[5]).xorBlocks(blocks[6]).xorBlocks(blocks[7]).toBytes();
                    return tags_0[0..16].* ++ tags_1[0..16].*;
                },
                else => unreachable,
            }
        }
    };
}

/// AEGIS is a very fast authenticated encryption system built on top of the core AES function.
///
/// The 128 bits variants of AEGIS have a 128 bit key and a 128 bit nonce.
///
/// https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/
fn Aegis128XGeneric(comptime degree: u7, comptime tag_bits: u9) type {
    comptime assert(degree > 0); // degree must be greater than 0
    comptime assert(tag_bits == 128 or tag_bits == 256); // tag must be 128 or 256 bits

    return struct {
        const State = State128X(degree);

        pub const tag_length = tag_bits / 8;
        pub const nonce_length = 16;
        pub const key_length = 16;
        pub const block_length = State.rate;

        const alignment = State.alignment;

        /// c: ciphertext: output buffer should be of size m.len
        /// tag: authentication tag: output MAC
        /// m: message
        /// ad: Associated Data
        /// npub: public nonce
        /// k: private key
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            assert(c.len == m.len);
            var state = State.init(key, npub);
            var src: [block_length]u8 align(alignment) = undefined;
            var dst: [block_length]u8 align(alignment) = undefined;
            var i: usize = 0;
            while (i + block_length <= ad.len) : (i += block_length) {
                state.absorb(ad[i..][0..block_length]);
            }
            if (ad.len % block_length != 0) {
                @memset(src[0..], 0);
                @memcpy(src[0 .. ad.len % block_length], ad[i..][0 .. ad.len % block_length]);
                state.absorb(&src);
            }
            i = 0;
            while (i + block_length <= m.len) : (i += block_length) {
                state.enc(c[i..][0..block_length], m[i..][0..block_length]);
            }
            if (m.len % block_length != 0) {
                @memset(src[0..], 0);
                @memcpy(src[0 .. m.len % block_length], m[i..][0 .. m.len % block_length]);
                state.enc(&dst, &src);
                @memcpy(c[i..][0 .. m.len % block_length], dst[0 .. m.len % block_length]);
            }
            tag.* = state.finalize(tag_bits, ad.len, m.len);
        }

        /// `m`: Message
        /// `c`: Ciphertext
        /// `tag`: Authentication tag
        /// `ad`: Associated data
        /// `npub`: Public nonce
        /// `k`: Private key
        /// Asserts `c.len == m.len`.
        ///
        /// Contents of `m` are undefined if an error is returned.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
            assert(c.len == m.len);
            var state = State.init(key, npub);
            var src: [block_length]u8 align(alignment) = undefined;
            var i: usize = 0;
            while (i + block_length <= ad.len) : (i += block_length) {
                state.absorb(ad[i..][0..block_length]);
            }
            if (ad.len % block_length != 0) {
                @memset(src[0..], 0);
                @memcpy(src[0 .. ad.len % block_length], ad[i..][0 .. ad.len % block_length]);
                state.absorb(&src);
            }
            i = 0;
            while (i + block_length <= m.len) : (i += block_length) {
                state.dec(m[i..][0..block_length], c[i..][0..block_length]);
            }
            if (m.len % block_length != 0) {
                state.decLast(m[i..], c[i..]);
            }
            var computed_tag = state.finalize(tag_bits, ad.len, m.len);
            const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!verify) {
                crypto.secureZero(u8, &computed_tag);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }
        }
    };
}

fn State256X(comptime degree: u7) type {
    return struct {
        const AesBlockVec = crypto.core.aes.BlockVec(degree);
        const State = @This();

        blocks: [6]AesBlockVec,

        const aes_block_length = AesBlockVec.block_length;
        const rate = aes_block_length;
        const alignment = AesBlockVec.native_word_size;

        fn init(key: [32]u8, nonce: [32]u8) State {
            const c1 = AesBlockVec.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** degree);
            const c2 = AesBlockVec.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** degree);
            const key_block1 = AesBlockVec.fromBytes(key[0..16] ** degree);
            const key_block2 = AesBlockVec.fromBytes(key[16..32] ** degree);
            const nonce_block1 = AesBlockVec.fromBytes(nonce[0..16] ** degree);
            const nonce_block2 = AesBlockVec.fromBytes(nonce[16..32] ** degree);
            const kxn1 = key_block1.xorBlocks(nonce_block1);
            const kxn2 = key_block2.xorBlocks(nonce_block2);
            const blocks = [6]AesBlockVec{
                kxn1,
                kxn2,
                c1,
                c2,
                key_block1.xorBlocks(c2),
                key_block2.xorBlocks(c1),
            };
            var state = State{ .blocks = blocks };
            if (degree > 1) {
                const context_block = ctx: {
                    var contexts_bytes = [_]u8{0} ** aes_block_length;
                    for (0..degree) |i| {
                        contexts_bytes[i * 16] = @intCast(i);
                        contexts_bytes[i * 16 + 1] = @intCast(degree - 1);
                    }
                    break :ctx AesBlockVec.fromBytes(&contexts_bytes);
                };
                for (0..4) |_| {
                    state.blocks[3] = state.blocks[3].xorBlocks(context_block);
                    state.blocks[5] = state.blocks[5].xorBlocks(context_block);
                    state.update(key_block1);
                    state.blocks[3] = state.blocks[3].xorBlocks(context_block);
                    state.blocks[5] = state.blocks[5].xorBlocks(context_block);
                    state.update(key_block2);
                    state.blocks[3] = state.blocks[3].xorBlocks(context_block);
                    state.blocks[5] = state.blocks[5].xorBlocks(context_block);
                    state.update(kxn1);
                    state.blocks[3] = state.blocks[3].xorBlocks(context_block);
                    state.blocks[5] = state.blocks[5].xorBlocks(context_block);
                    state.update(kxn2);
                }
            } else {
                for (0..4) |_| {
                    state.update(key_block1);
                    state.update(key_block2);
                    state.update(kxn1);
                    state.update(kxn2);
                }
            }
            return state;
        }

        inline fn update(state: *State, d: AesBlockVec) void {
            const blocks = &state.blocks;
            const tmp = blocks[5].encrypt(blocks[0]);
            comptime var i: usize = 5;
            inline while (i > 0) : (i -= 1) {
                blocks[i] = blocks[i - 1].encrypt(blocks[i]);
            }
            blocks[0] = tmp.xorBlocks(d);
        }

        fn absorb(state: *State, src: *const [rate]u8) void {
            const msg = AesBlockVec.fromBytes(src);
            state.update(msg);
        }

        fn enc(state: *State, dst: *[rate]u8, src: *const [rate]u8) void {
            const blocks = &state.blocks;
            const msg = AesBlockVec.fromBytes(src);
            var tmp = msg.xorBlocks(blocks[5]).xorBlocks(blocks[4]).xorBlocks(blocks[1]);
            tmp = tmp.xorBlocks(blocks[2].andBlocks(blocks[3]));
            dst.* = tmp.toBytes();
            state.update(msg);
        }

        fn dec(state: *State, dst: *[rate]u8, src: *const [rate]u8) void {
            const blocks = &state.blocks;
            var msg = AesBlockVec.fromBytes(src).xorBlocks(blocks[5]).xorBlocks(blocks[4]).xorBlocks(blocks[1]);
            msg = msg.xorBlocks(blocks[2].andBlocks(blocks[3]));
            dst.* = msg.toBytes();
            state.update(msg);
        }

        fn decLast(state: *State, dst: []u8, src: []const u8) void {
            const blocks = &state.blocks;
            const z = blocks[5].xorBlocks(blocks[4]).xorBlocks(blocks[1]).xorBlocks(blocks[2].andBlocks(blocks[3]));
            var pad = z.toBytes();
            for (pad[0..src.len], src) |*p, x| p.* ^= x;
            @memcpy(dst, pad[0..src.len]);
            @memset(pad[src.len..], 0);
            const msg = AesBlockVec.fromBytes(pad[0..]);
            state.update(msg);
        }

        fn finalize(state: *State, comptime tag_bits: u9, adlen: usize, mlen: usize) [tag_bits / 8]u8 {
            const blocks = &state.blocks;
            var sizes: [aes_block_length]u8 = undefined;
            mem.writeInt(u64, sizes[0..8], @as(u64, adlen) * 8, .little);
            mem.writeInt(u64, sizes[8..16], @as(u64, mlen) * 8, .little);
            for (1..degree) |i| {
                @memcpy(sizes[i * 16 ..][0..16], sizes[0..16]);
            }
            const tmp = AesBlockVec.fromBytes(&sizes).xorBlocks(blocks[3]);
            for (0..7) |_| {
                state.update(tmp);
            }
            switch (tag_bits) {
                128 => {
                    var tag_multi = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).xorBlocks(blocks[4]).xorBlocks(blocks[5]).toBytes();
                    var tag = tag_multi[0..16].*;
                    @memcpy(tag[0..], tag_multi[0..16]);
                    for (1..degree) |d| {
                        for (0..16) |i| {
                            tag[i] ^= tag_multi[d * 16 + i];
                        }
                    }
                    return tag;
                },
                256 => {
                    const tag_multi_1 = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).toBytes();
                    const tag_multi_2 = blocks[3].xorBlocks(blocks[4]).xorBlocks(blocks[5]).toBytes();
                    var tag = tag_multi_1[0..16].* ++ tag_multi_2[0..16].*;
                    for (1..degree) |d| {
                        for (0..16) |i| {
                            tag[i] ^= tag_multi_1[d * 16 + i];
                            tag[i + 16] ^= tag_multi_2[d * 16 + i];
                        }
                    }
                    return tag;
                },
                else => unreachable,
            }
        }

        fn finalizeMac(state: *State, comptime tag_bits: u9, datalen: usize) [tag_bits / 8]u8 {
            const blocks = &state.blocks;
            var sizes: [aes_block_length]u8 = undefined;
            mem.writeInt(u64, sizes[0..8], @as(u64, datalen) * 8, .little);
            mem.writeInt(u64, sizes[8..16], tag_bits, .little);
            for (1..degree) |i| {
                @memcpy(sizes[i * 16 ..][0..16], sizes[0..16]);
            }
            var t = blocks[3].xorBlocks(AesBlockVec.fromBytes(&sizes));
            for (0..7) |_| {
                state.update(t);
            }
            if (degree > 1) {
                var v = [_]u8{0} ** rate;
                switch (tag_bits) {
                    128 => {
                        const tags = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).xorBlocks(blocks[4]).xorBlocks(blocks[5]).toBytes();
                        for (1..degree) |d| {
                            v[0..16].* = tags[d * 16 ..][0..16].*;
                            state.absorb(&v);
                        }
                    },
                    256 => {
                        const tags_0 = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).toBytes();
                        const tags_1 = blocks[3].xorBlocks(blocks[4]).xorBlocks(blocks[5]).toBytes();
                        for (1..degree) |d| {
                            v[0..16].* = tags_0[d * 16 ..][0..16].*;
                            state.absorb(&v);
                            v[0..16].* = tags_1[d * 16 ..][0..16].*;
                            state.absorb(&v);
                        }
                    },
                    else => unreachable,
                }
                mem.writeInt(u64, sizes[0..8], degree, .little);
                mem.writeInt(u64, sizes[8..16], tag_bits, .little);
                t = blocks[3].xorBlocks(AesBlockVec.fromBytes(&sizes));
                for (0..7) |_| {
                    state.update(t);
                }
            }
            switch (tag_bits) {
                128 => {
                    const tags = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).xorBlocks(blocks[4]).xorBlocks(blocks[5]).toBytes();
                    return tags[0..16].*;
                },
                256 => {
                    const tags_0 = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).toBytes();
                    const tags_1 = blocks[3].xorBlocks(blocks[4]).xorBlocks(blocks[5]).toBytes();
                    return tags_0[0..16].* ++ tags_1[0..16].*;
                },
                else => unreachable,
            }
        }
    };
}

/// AEGIS is a very fast authenticated encryption system built on top of the core AES function.
///
/// The 256 bits variants of AEGIS have a 256 bit key and a 256 bit nonce.
///
/// https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/
fn Aegis256XGeneric(comptime degree: u7, comptime tag_bits: u9) type {
    comptime assert(degree > 0); // degree must be greater than 0
    comptime assert(tag_bits == 128 or tag_bits == 256); // tag must be 128 or 256 bits

    return struct {
        const State = State256X(degree);

        pub const tag_length = tag_bits / 8;
        pub const nonce_length = 32;
        pub const key_length = 32;
        pub const block_length = State.rate;

        const alignment = State.alignment;

        /// c: ciphertext: output buffer should be of size m.len
        /// tag: authentication tag: output MAC
        /// m: message
        /// ad: Associated Data
        /// npub: public nonce
        /// k: private key
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            assert(c.len == m.len);
            var state = State.init(key, npub);
            var src: [block_length]u8 align(alignment) = undefined;
            var dst: [block_length]u8 align(alignment) = undefined;
            var i: usize = 0;
            while (i + block_length <= ad.len) : (i += block_length) {
                state.enc(&dst, ad[i..][0..block_length]);
            }
            if (ad.len % block_length != 0) {
                @memset(src[0..], 0);
                @memcpy(src[0 .. ad.len % block_length], ad[i..][0 .. ad.len % block_length]);
                state.enc(&dst, &src);
            }
            i = 0;
            while (i + block_length <= m.len) : (i += block_length) {
                state.enc(c[i..][0..block_length], m[i..][0..block_length]);
            }
            if (m.len % block_length != 0) {
                @memset(src[0..], 0);
                @memcpy(src[0 .. m.len % block_length], m[i..][0 .. m.len % block_length]);
                state.enc(&dst, &src);
                @memcpy(c[i..][0 .. m.len % block_length], dst[0 .. m.len % block_length]);
            }
            tag.* = state.finalize(tag_bits, ad.len, m.len);
        }

        /// `m`: Message
        /// `c`: Ciphertext
        /// `tag`: Authentication tag
        /// `ad`: Associated data
        /// `npub`: Public nonce
        /// `k`: Private key
        /// Asserts `c.len == m.len`.
        ///
        /// Contents of `m` are undefined if an error is returned.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
            assert(c.len == m.len);
            var state = State.init(key, npub);
            var src: [block_length]u8 align(alignment) = undefined;
            var i: usize = 0;
            while (i + block_length <= ad.len) : (i += block_length) {
                state.absorb(ad[i..][0..block_length]);
            }
            if (ad.len % block_length != 0) {
                @memset(src[0..], 0);
                @memcpy(src[0 .. ad.len % block_length], ad[i..][0 .. ad.len % block_length]);
                state.absorb(&src);
            }
            i = 0;
            while (i + block_length <= m.len) : (i += block_length) {
                state.dec(m[i..][0..block_length], c[i..][0..block_length]);
            }
            if (m.len % block_length != 0) {
                state.decLast(m[i..], c[i..]);
            }
            var computed_tag = state.finalize(tag_bits, ad.len, m.len);
            const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!verify) {
                crypto.secureZero(u8, &computed_tag);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }
        }
    };
}

/// The `Aegis128X4Mac` message authentication function outputs 256 bit tags.
/// In addition to being extremely fast, its large state, non-linearity
/// and non-invertibility provides the following properties:
/// - 128 bit security, stronger than GHash/Polyval/Poly1305.
/// - Recovering the secret key from the state would require ~2^128 attempts,
///   which is infeasible for any practical adversary.
/// - It has a large security margin against internal collisions.
pub const Aegis128X4Mac = AegisMac(Aegis128X4_256);

/// The `Aegis128X2Mac` message authentication function outputs 256 bit tags.
/// In addition to being extremely fast, its large state, non-linearity
/// and non-invertibility provides the following properties:
/// - 128 bit security, stronger than GHash/Polyval/Poly1305.
/// - Recovering the secret key from the state would require ~2^128 attempts,
///   which is infeasible for any practical adversary.
/// - It has a large security margin against internal collisions.
pub const Aegis128X2Mac = AegisMac(Aegis128X2_256);

/// The `Aegis128LMac` message authentication function outputs 256 bit tags.
/// In addition to being extremely fast, its large state, non-linearity
/// and non-invertibility provides the following properties:
/// - 128 bit security, stronger than GHash/Polyval/Poly1305.
/// - Recovering the secret key from the state would require ~2^128 attempts,
///   which is infeasible for any practical adversary.
/// - It has a large security margin against internal collisions.
pub const Aegis128LMac = AegisMac(Aegis128L_256);

/// The `Aegis256X4Mac` message authentication function has a 256-bit key size,
/// and outputs 256 bit tags.
/// The key size is the main practical difference with `Aegis128X4Mac`.
/// AEGIS' large state, non-linearity and non-invertibility provides the
/// following properties:
/// - 256 bit security against forgery.
/// - Recovering the secret key from the state would require ~2^256 attempts,
///   which is infeasible for any practical adversary.
/// - It has a large security margin against internal collisions.
pub const Aegis256X4Mac = AegisMac(Aegis256X4_256);

/// The `Aegis256X2Mac` message authentication function has a 256-bit key size,
/// and outputs 256 bit tags.
/// The key size is the main practical difference with `Aegis128X2Mac`.
/// AEGIS' large state, non-linearity and non-invertibility provides the
/// following properties:
/// - 256 bit security against forgery.
/// - Recovering the secret key from the state would require ~2^256 attempts,
///   which is infeasible for any practical adversary.
/// - It has a large security margin against internal collisions.
pub const Aegis256X2Mac = AegisMac(Aegis256X2_256);

/// The `Aegis256Mac` message authentication function has a 256-bit key size,
/// and outputs 256 bit tags.
/// The key size is the main practical difference with `Aegis128LMac`.
/// AEGIS' large state, non-linearity and non-invertibility provides the
/// following properties:
/// - 256 bit security against forgery.
/// - Recovering the secret key from the state would require ~2^256 attempts,
///   which is infeasible for any practical adversary.
/// - It has a large security margin against internal collisions.
pub const Aegis256Mac = AegisMac(Aegis256_256);

/// AEGIS-128X4 MAC with 128-bit tags
pub const Aegis128X4Mac_128 = AegisMac(Aegis128X4);

/// AEGIS-128X2 MAC with 128-bit tags
pub const Aegis128X2Mac_128 = AegisMac(Aegis128X2);

/// AEGIS-128L MAC with 128-bit tags
pub const Aegis128LMac_128 = AegisMac(Aegis128L);

/// AEGIS-256X4 MAC with 128-bit tags
pub const Aegis256X4Mac_128 = AegisMac(Aegis256X4);

/// AEGIS-256X2 MAC with 128-bit tags
pub const Aegis256X2Mac_128 = AegisMac(Aegis256X2);

/// AEGIS-256 MAC with 128-bit tags
pub const Aegis256Mac_128 = AegisMac(Aegis256);

fn AegisMac(comptime T: type) type {
    return struct {
        const Mac = @This();

        pub const mac_length = T.tag_length;
        pub const key_length = T.key_length;
        pub const nonce_length = T.nonce_length;
        pub const block_length = T.block_length;

        state: T.State,
        buf: [block_length]u8 = undefined,
        off: usize = 0,
        msg_len: usize = 0,

        /// Initialize a state for the MAC function, with a key and a nonce
        pub fn initWithNonce(key: *const [key_length]u8, nonce: *const [nonce_length]u8) Mac {
            return Mac{
                .state = T.State.init(key.*, nonce.*),
            };
        }

        /// Initialize a state for the MAC function, with a default nonce
        pub fn init(key: *const [key_length]u8) Mac {
            return Mac{
                .state = T.State.init(key.*, [_]u8{0} ** nonce_length),
            };
        }

        /// Add data to the state
        pub fn update(self: *Mac, b: []const u8) void {
            self.msg_len += b.len;

            const len_partial = @min(b.len, block_length - self.off);
            @memcpy(self.buf[self.off..][0..len_partial], b[0..len_partial]);
            self.off += len_partial;
            if (self.off < block_length) {
                return;
            }
            self.state.absorb(&self.buf);

            var i = len_partial;
            self.off = 0;
            while (i + block_length * 2 <= b.len) : (i += block_length * 2) {
                self.state.absorb(b[i..][0..block_length]);
                self.state.absorb(b[i..][block_length .. block_length * 2]);
            }
            while (i + block_length <= b.len) : (i += block_length) {
                self.state.absorb(b[i..][0..block_length]);
            }
            if (i != b.len) {
                self.off = b.len - i;
                @memcpy(self.buf[0..self.off], b[i..]);
            }
        }

        /// Return an authentication tag for the current state
        pub fn final(self: *Mac, out: *[mac_length]u8) void {
            if (self.off > 0) {
                var pad = [_]u8{0} ** block_length;
                @memcpy(pad[0..self.off], self.buf[0..self.off]);
                self.state.absorb(&pad);
            }
            out.* = self.state.finalizeMac(T.tag_length * 8, self.msg_len);
        }

        /// Return an authentication tag for a message, a key and a nonce
        pub fn createWithNonce(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8, nonce: *const [nonce_length]u8) void {
            var ctx = Mac.initWithNonce(key, nonce);
            ctx.update(msg);
            ctx.final(out);
        }

        /// Return an authentication tag for a message and a key
        pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
            var ctx = Mac.init(key);
            ctx.update(msg);
            ctx.final(out);
        }

        pub const Error = error{};
        pub const Writer = std.io.Writer(*Mac, Error, write);

        fn write(self: *Mac, bytes: []const u8) Error!usize {
            self.update(bytes);
            return bytes.len;
        }

        pub fn writer(self: *Mac) Writer {
            return .{ .context = self };
        }
    };
}

const htest = @import("test.zig");
const testing = std.testing;

test "Aegis128L test vector 1" {
    const key: [Aegis128L.key_length]u8 = [_]u8{ 0x10, 0x01 } ++ [_]u8{0x00} ** 14;
    const nonce: [Aegis128L.nonce_length]u8 = [_]u8{ 0x10, 0x00, 0x02 } ++ [_]u8{0x00} ** 13;
    const ad = [8]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    const m = [32]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aegis128L.tag_length]u8 = undefined;

    Aegis128L.encrypt(&c, &tag, &m, &ad, nonce, key);
    try Aegis128L.decrypt(&m2, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &m, &m2);

    try htest.assertEqual("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84", &c);
    try htest.assertEqual("cc6f3372f6aa1bb82388d695c3962d9a", &tag);

    c[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis128L.decrypt(&m2, &c, tag, &ad, nonce, key));
    c[0] -%= 1;
    tag[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis128L.decrypt(&m2, &c, tag, &ad, nonce, key));
}

test "Aegis128L test vector 2" {
    const key: [Aegis128L.key_length]u8 = [_]u8{0x00} ** 16;
    const nonce: [Aegis128L.nonce_length]u8 = [_]u8{0x00} ** 16;
    const ad = [_]u8{};
    const m = [_]u8{0x00} ** 16;
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aegis128L.tag_length]u8 = undefined;

    Aegis128L.encrypt(&c, &tag, &m, &ad, nonce, key);
    try Aegis128L.decrypt(&m2, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &m, &m2);

    try htest.assertEqual("41de9000a7b5e40e2d68bb64d99ebb19", &c);
    try htest.assertEqual("f4d997cc9b94227ada4fe4165422b1c8", &tag);
}

test "Aegis128L test vector 3" {
    const key: [Aegis128L.key_length]u8 = [_]u8{0x00} ** 16;
    const nonce: [Aegis128L.nonce_length]u8 = [_]u8{0x00} ** 16;
    const ad = [_]u8{};
    const m = [_]u8{};
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aegis128L.tag_length]u8 = undefined;

    Aegis128L.encrypt(&c, &tag, &m, &ad, nonce, key);
    try Aegis128L.decrypt(&m2, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &m, &m2);

    try htest.assertEqual("83cc600dc4e3e7e62d4055826174f149", &tag);
}

test "Aegis128X2 test vector 1" {
    const key: [Aegis128X2.key_length]u8 = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const nonce: [Aegis128X2.nonce_length]u8 = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    var empty = [_]u8{};
    var tag: [Aegis128X2.tag_length]u8 = undefined;
    var tag256: [Aegis128X2_256.tag_length]u8 = undefined;

    Aegis128X2.encrypt(&empty, &tag, &empty, &empty, nonce, key);
    Aegis128X2_256.encrypt(&empty, &tag256, &empty, &empty, nonce, key);
    try htest.assertEqual("63117dc57756e402819a82e13eca8379", &tag);
    try htest.assertEqual("b92c71fdbd358b8a4de70b27631ace90cffd9b9cfba82028412bac41b4f53759", &tag256);
    tag[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis128X2.decrypt(&empty, &empty, tag, &empty, nonce, key));
    tag256[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis128X2_256.decrypt(&empty, &empty, tag256, &empty, nonce, key));
}

test "Aegis256 test vector 1" {
    const key: [Aegis256.key_length]u8 = [_]u8{ 0x10, 0x01 } ++ [_]u8{0x00} ** 30;
    const nonce: [Aegis256.nonce_length]u8 = [_]u8{ 0x10, 0x00, 0x02 } ++ [_]u8{0x00} ** 29;
    const ad = [8]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    const m = [32]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aegis256.tag_length]u8 = undefined;

    Aegis256.encrypt(&c, &tag, &m, &ad, nonce, key);
    try Aegis256.decrypt(&m2, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &m, &m2);

    try htest.assertEqual("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711", &c);
    try htest.assertEqual("8d86f91ee606e9ff26a01b64ccbdd91d", &tag);

    c[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis256.decrypt(&m2, &c, tag, &ad, nonce, key));
    c[0] -%= 1;
    tag[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis256.decrypt(&m2, &c, tag, &ad, nonce, key));
}

test "Aegis256 test vector 2" {
    const key: [Aegis256.key_length]u8 = [_]u8{0x00} ** 32;
    const nonce: [Aegis256.nonce_length]u8 = [_]u8{0x00} ** 32;
    const ad = [_]u8{};
    const m = [_]u8{0x00} ** 16;
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aegis256.tag_length]u8 = undefined;

    Aegis256.encrypt(&c, &tag, &m, &ad, nonce, key);
    try Aegis256.decrypt(&m2, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &m, &m2);

    try htest.assertEqual("b98f03a947807713d75a4fff9fc277a6", &c);
    try htest.assertEqual("478f3b50dc478ef7d5cf2d0f7cc13180", &tag);
}

test "Aegis256 test vector 3" {
    const key: [Aegis256.key_length]u8 = [_]u8{0x00} ** 32;
    const nonce: [Aegis256.nonce_length]u8 = [_]u8{0x00} ** 32;
    const ad = [_]u8{};
    const m = [_]u8{};
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aegis256.tag_length]u8 = undefined;

    Aegis256.encrypt(&c, &tag, &m, &ad, nonce, key);
    try Aegis256.decrypt(&m2, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &m, &m2);

    try htest.assertEqual("f7a0878f68bd083e8065354071fc27c3", &tag);
}

test "Aegis256X4 test vector 1" {
    const key: [Aegis256X4.key_length]u8 = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const nonce: [Aegis256X4.nonce_length]u8 = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
    var empty = [_]u8{};
    var tag: [Aegis256X4.tag_length]u8 = undefined;
    var tag256: [Aegis256X4_256.tag_length]u8 = undefined;

    Aegis256X4.encrypt(&empty, &tag, &empty, &empty, nonce, key);
    Aegis256X4_256.encrypt(&empty, &tag256, &empty, &empty, nonce, key);
    try htest.assertEqual("3b7fee6cee7bf17888ad11ed2397beb4", &tag);
    try htest.assertEqual("6093a1a8aab20ec635dc1ca71745b01b5bec4fc444c9ffbebd710d4a34d20eaf", &tag256);
    tag[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis256X4.decrypt(&empty, &empty, tag, &empty, nonce, key));
    tag256[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, Aegis256X4_256.decrypt(&empty, &empty, tag256, &empty, nonce, key));
}

test "Aegis MAC" {
    const key = [_]u8{0x00} ** Aegis128LMac.key_length;
    var msg: [64]u8 = undefined;
    for (&msg, 0..) |*m, i| {
        m.* = @as(u8, @truncate(i));
    }
    const st_init = Aegis128LMac.init(&key);
    var st = st_init;
    var tag: [Aegis128LMac.mac_length]u8 = undefined;

    st.update(msg[0..32]);
    st.update(msg[32..]);
    st.final(&tag);
    try htest.assertEqual("f5eb88d90b7d31c9a679eb94ed1374cd14816b19cdb77930d1a5158f8595983b", &tag);

    st = st_init;
    st.update(msg[0..31]);
    st.update(msg[31..]);
    st.final(&tag);
    try htest.assertEqual("f5eb88d90b7d31c9a679eb94ed1374cd14816b19cdb77930d1a5158f8595983b", &tag);

    st = st_init;
    st.update(msg[0..14]);
    st.update(msg[14..30]);
    st.update(msg[30..]);
    st.final(&tag);
    try htest.assertEqual("f5eb88d90b7d31c9a679eb94ed1374cd14816b19cdb77930d1a5158f8595983b", &tag);

    // An update whose size is not a multiple of the block size
    st = st_init;
    st.update(msg[0..33]);
    st.final(&tag);
    try htest.assertEqual("07b3ba5ad9ceee5ef1906e3396f0fa540fbcd2f33833ef97c35bdc2ae9ae0535", &tag);
}

test "AEGISMAC-128* test vectors" {
    const key = [_]u8{ 0x10, 0x01 } ++ [_]u8{0x00} ** (16 - 2);
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ [_]u8{0x00} ** (16 - 3);
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;

    Aegis128LMac.createWithNonce(&mac256, &msg, &key, &nonce);
    Aegis128LMac_128.createWithNonce(&mac128, &msg, &key, &nonce);
    try htest.assertEqual("d3f09b2842ad301687d6902c921d7818", &mac128);
    try htest.assertEqual("9490e7c89d420c9f37417fa625eb38e8cad53c5cbec55285e8499ea48377f2a3", &mac256);

    Aegis128X2Mac.createWithNonce(&mac256, &msg, &key, &nonce);
    Aegis128X2Mac_128.createWithNonce(&mac128, &msg, &key, &nonce);
    try htest.assertEqual("6873ee34e6b5c59143b6d35c5e4f2c6e", &mac128);
    try htest.assertEqual("afcba3fc2d63c8d6c7f2d63f3ec8fbbbaf022e15ac120e78ffa7755abccd959c", &mac256);

    Aegis128X4Mac.createWithNonce(&mac256, &msg, &key, &nonce);
    Aegis128X4Mac_128.createWithNonce(&mac128, &msg, &key, &nonce);
    try htest.assertEqual("c45a98fd9ab8956ce616eb008cfe4e53", &mac128);
    try htest.assertEqual("26fdc76f41b1da7aec7779f6e964beae8904e662f05aca8345ae3befb357412a", &mac256);
}

test "AEGISMAC-256* test vectors" {
    const key = [_]u8{ 0x10, 0x01 } ++ [_]u8{0x00} ** (32 - 2);
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ [_]u8{0x00} ** (32 - 3);
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;

    Aegis256Mac.createWithNonce(&mac256, &msg, &key, &nonce);
    Aegis256Mac_128.createWithNonce(&mac128, &msg, &key, &nonce);
    try htest.assertEqual("c08e20cfc56f27195a46c9cef5c162d4", &mac128);
    try htest.assertEqual("a5c906ede3d69545c11e20afa360b221f936e946ed2dba3d7c75ad6dc2784126", &mac256);

    Aegis256X2Mac.createWithNonce(&mac256, &msg, &key, &nonce);
    Aegis256X2Mac_128.createWithNonce(&mac128, &msg, &key, &nonce);
    try htest.assertEqual("fb319cb6dd728a764606fb14d37f2a5e", &mac128);
    try htest.assertEqual("0844b20ed5147ceae89c7a160263afd4b1382d6b154ecf560ce8a342cb6a8fd1", &mac256);

    Aegis256X4Mac.createWithNonce(&mac256, &msg, &key, &nonce);
    Aegis256X4Mac_128.createWi```
