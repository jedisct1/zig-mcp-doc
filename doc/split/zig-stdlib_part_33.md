```
 if (s == 0) break;
                            s -= 1;
                        },
                    }
                }
            } else {
                // Use a precomputation table for large exponents
                var pc = [1]Fe{x} ++ [_]Fe{self.zero} ** 14;
                if (x.montgomery == false) {
                    self.toMontgomery(&pc[0]) catch unreachable;
                }
                for (1..pc.len) |i| {
                    pc[i] = self.montgomeryMul(pc[i - 1], pc[0]);
                }
                var t0 = self.zero;
                var s = switch (endian) {
                    .big => 0,
                    .little => e.len - 1,
                };
                while (true) {
                    const b = e[s];
                    for ([_]u3{ 4, 0 }) |j| {
                        for (0..4) |_| {
                            out = self.montgomerySq(out);
                        }
                        const k = (b >> j) & 0b1111;
                        if (public or std.options.side_channels_mitigations == .none) {
                            if (k == 0) continue;
                            t0 = pc[k - 1];
                        } else {
                            for (pc, 0..) |t, i| {
                                t0.v.cmov(ct.eql(k, @as(u8, @truncate(i + 1))), t.v);
                            }
                        }
                        const t1 = self.montgomeryMul(out, t0);
                        if (public) {
                            @memcpy(out.v.limbs(), t1.v.limbsConst());
                        } else {
                            out.v.cmov(!ct.eql(k, 0), t1.v);
                        }
                    }
                    switch (endian) {
                        .big => {
                            s += 1;
                            if (s == e.len) break;
                        },
                        .little => {
                            if (s == 0) break;
                            s -= 1;
                        },
                    }
                }
            }
            self.fromMontgomery(&out) catch unreachable;
            return out;
        }

        /// Multiplies two field elements.
        pub fn mul(self: Self, x: Fe, y: Fe) Fe {
            if (x.montgomery != y.montgomery) {
                return self.montgomeryMul(x, y);
            }
            var a_ = x;
            if (x.montgomery == false) {
                self.toMontgomery(&a_) catch unreachable;
            } else {
                self.fromMontgomery(&a_) catch unreachable;
            }
            return self.montgomeryMul(a_, y);
        }

        /// Squares a field element.
        pub fn sq(self: Self, x: Fe) Fe {
            var out = x;
            if (x.montgomery == true) {
                self.fromMontgomery(&out) catch unreachable;
            }
            out = self.montgomerySq(out);
            out.montgomery = false;
            self.toMontgomery(&out) catch unreachable;
            return out;
        }

        /// Returns x^e (mod m) in constant time.
        pub fn pow(self: Self, x: Fe, e: Fe) NullExponentError!Fe {
            var buf: [Fe.encoded_bytes]u8 = undefined;
            e.toBytes(&buf, native_endian) catch unreachable;
            return self.powWithEncodedExponent(x, &buf, native_endian);
        }

        /// Returns x^e (mod m), assuming that the exponent is public.
        /// The function remains constant time with respect to `x`.
        pub fn powPublic(self: Self, x: Fe, e: Fe) NullExponentError!Fe {
            var e_normalized = Fe{ .v = e.v.normalize() };
            var buf_: [Fe.encoded_bytes]u8 = undefined;
            var buf = buf_[0 .. math.divCeil(usize, e_normalized.v.limbs_len * t_bits, 8) catch unreachable];
            e_normalized.toBytes(buf, .little) catch unreachable;
            const leading = @clz(e_normalized.v.limbsConst()[e_normalized.v.limbs_len - carry_bits]);
            buf = buf[0 .. buf.len - leading / 8];
            return self.powWithEncodedPublicExponent(x, buf, .little);
        }

        /// Returns x^e (mod m), with the exponent provided as a byte string.
        /// Exponents are usually small, so this function is faster than `powPublic` as a field element
        /// doesn't have to be created if a serialized representation is already available.
        ///
        /// If the exponent is public, `powWithEncodedPublicExponent()` can be used instead for a slight speedup.
        pub fn powWithEncodedExponent(self: Self, x: Fe, e: []const u8, endian: Endian) NullExponentError!Fe {
            return self.powWithEncodedExponentInternal(x, e, endian, false);
        }

        /// Returns x^e (mod m), the exponent being public and provided as a byte string.
        /// Exponents are usually small, so this function is faster than `powPublic` as a field element
        /// doesn't have to be created if a serialized representation is already available.
        ///
        /// If the exponent is secret, `powWithEncodedExponent` must be used instead.
        pub fn powWithEncodedPublicExponent(self: Self, x: Fe, e: []const u8, endian: Endian) NullExponentError!Fe {
            return self.powWithEncodedExponentInternal(x, e, endian, true);
        }
    };
}

const ct = if (std.options.side_channels_mitigations == .none) ct_unprotected else ct_protected;

const ct_protected = struct {
    // Returns x if on is true, otherwise y.
    fn select(on: bool, x: Limb, y: Limb) Limb {
        const mask = @as(Limb, 0) -% @intFromBool(on);
        return y ^ (mask & (y ^ x));
    }

    // Compares two values in constant time.
    fn eql(x: anytype, y: @TypeOf(x)) bool {
        const c1 = @subWithOverflow(x, y)[1];
        const c2 = @subWithOverflow(y, x)[1];
        return @as(bool, @bitCast(1 - (c1 | c2)));
    }

    // Compares two big integers in constant time, returning true if x < y.
    fn limbsCmpLt(x: anytype, y: @TypeOf(x)) bool {
        var c: u1 = 0;
        for (x.limbsConst(), y.limbsConst()) |x_limb, y_limb| {
            c = @truncate((x_limb -% y_limb -% c) >> t_bits);
        }
        return c != 0;
    }

    // Compares two big integers in constant time, returning true if x >= y.
    fn limbsCmpGeq(x: anytype, y: @TypeOf(x)) bool {
        return !limbsCmpLt(x, y);
    }

    // Multiplies two limbs and returns the result as a wide limb.
    fn mulWide(x: Limb, y: Limb) WideLimb {
        const half_bits = @typeInfo(Limb).int.bits / 2;
        const Half = meta.Int(.unsigned, half_bits);
        const x0 = @as(Half, @truncate(x));
        const x1 = @as(Half, @truncate(x >> half_bits));
        const y0 = @as(Half, @truncate(y));
        const y1 = @as(Half, @truncate(y >> half_bits));
        const w0 = math.mulWide(Half, x0, y0);
        const t = math.mulWide(Half, x1, y0) + (w0 >> half_bits);
        var w1: Limb = @as(Half, @truncate(t));
        const w2 = @as(Half, @truncate(t >> half_bits));
        w1 += math.mulWide(Half, x0, y1);
        const hi = math.mulWide(Half, x1, y1) + w2 + (w1 >> half_bits);
        const lo = x *% y;
        return .{ .hi = hi, .lo = lo };
    }
};

const ct_unprotected = struct {
    // Returns x if on is true, otherwise y.
    fn select(on: bool, x: Limb, y: Limb) Limb {
        return if (on) x else y;
    }

    // Compares two values in constant time.
    fn eql(x: anytype, y: @TypeOf(x)) bool {
        return x == y;
    }

    // Compares two big integers in constant time, returning true if x < y.
    fn limbsCmpLt(x: anytype, y: @TypeOf(x)) bool {
        const x_limbs = x.limbsConst();
        const y_limbs = y.limbsConst();
        assert(x_limbs.len == y_limbs.len);

        var i = x_limbs.len;
        while (i != 0) {
            i -= 1;
            if (x_limbs[i] != y_limbs[i]) {
                return x_limbs[i] < y_limbs[i];
            }
        }
        return false;
    }

    // Compares two big integers in constant time, returning true if x >= y.
    fn limbsCmpGeq(x: anytype, y: @TypeOf(x)) bool {
        return !limbsCmpLt(x, y);
    }

    // Multiplies two limbs and returns the result as a wide limb.
    fn mulWide(x: Limb, y: Limb) WideLimb {
        const wide = math.mulWide(Limb, x, y);
        return .{
            .hi = @as(Limb, @truncate(wide >> @typeInfo(Limb).int.bits)),
            .lo = @as(Limb, @truncate(wide)),
        };
    }
};

test "finite field arithmetic" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const M = Modulus(256);
    const m = try M.fromPrimitive(u256, 3429938563481314093726330772853735541133072814650493833233);
    var x = try M.Fe.fromPrimitive(u256, m, 80169837251094269539116136208111827396136208141182357733);
    var y = try M.Fe.fromPrimitive(u256, m, 24620149608466364616251608466389896540098571);

    const x_ = try x.toPrimitive(u256);
    try testing.expect((try M.Fe.fromPrimitive(@TypeOf(x_), m, x_)).eql(x));
    try testing.expectError(error.Overflow, x.toPrimitive(u50));

    const bits = m.bits();
    try testing.expectEqual(bits, 192);

    var x_y = m.mul(x, y);
    try testing.expectEqual(x_y.toPrimitive(u256), 1666576607955767413750776202132407807424848069716933450241);

    try m.toMontgomery(&x);
    x_y = m.mul(x, y);
    try testing.expectEqual(x_y.toPrimitive(u256), 1666576607955767413750776202132407807424848069716933450241);
    try m.fromMontgomery(&x);

    x = m.add(x, y);
    try testing.expectEqual(x.toPrimitive(u256), 80169837251118889688724602572728079004602598037722456304);
    x = m.sub(x, y);
    try testing.expectEqual(x.toPrimitive(u256), 80169837251094269539116136208111827396136208141182357733);

    const big = try Uint(512).fromPrimitive(u495, 77285373554113307281465049383342993856348131409372633077285373554113307281465049383323332333429938563481314093726330772853735541133072814650493833233);
    const reduced = m.reduce(big);
    try testing.expectEqual(reduced.toPrimitive(u495), 858047099884257670294681641776170038885500210968322054970);

    const x_pow_y = try m.powPublic(x, y);
    try testing.expectEqual(x_pow_y.toPrimitive(u256), 1631933139300737762906024873185789093007782131928298618473);
    try m.toMontgomery(&x);
    const x_pow_y2 = try m.powPublic(x, y);
    try m.fromMontgomery(&x);
    try testing.expect(x_pow_y2.eql(x_pow_y));
    try testing.expectError(error.NullExponent, m.powPublic(x, m.zero));

    try testing.expect(!x.isZero());
    try testing.expect(!y.isZero());
    try testing.expect(m.v.isOdd());

    const x_sq = m.sq(x);
    const x_sq2 = m.mul(x, x);
    try testing.expect(x_sq.eql(x_sq2));
    try m.toMontgomery(&x);
    const x_sq3 = m.sq(x);
    const x_sq4 = m.mul(x, x);
    try testing.expect(x_sq.eql(x_sq3));
    try testing.expect(x_sq3.eql(x_sq4));
    try m.fromMontgomery(&x);
}

fn testCt(ct_: anytype) !void {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const l0: Limb = 0;
    const l1: Limb = 1;
    try testing.expectEqual(l1, ct_.select(true, l1, l0));
    try testing.expectEqual(l0, ct_.select(false, l1, l0));
    try testing.expectEqual(false, ct_.eql(l1, l0));
    try testing.expectEqual(true, ct_.eql(l1, l1));

    const M = Modulus(256);
    const m = try M.fromPrimitive(u256, 3429938563481314093726330772853735541133072814650493833233);
    const x = try M.Fe.fromPrimitive(u256, m, 80169837251094269539116136208111827396136208141182357733);
    const y = try M.Fe.fromPrimitive(u256, m, 24620149608466364616251608466389896540098571);
    try testing.expectEqual(false, ct_.limbsCmpLt(x.v, y.v));
    try testing.expectEqual(true, ct_.limbsCmpGeq(x.v, y.v));

    try testing.expectEqual(WideLimb{ .hi = 0, .lo = 0x88 }, ct_.mulWide(1 << 3, (1 << 4) + 1));
}

test ct {
    try testCt(ct_protected);
    try testCt(ct_unprotected);
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

const Precomp = u128;

/// GHASH is a universal hash function that uses multiplication by a fixed
/// parameter within a Galois field.
///
/// It is not a general purpose hash function - The key must be secret, unpredictable and never reused.
///
/// GHASH is typically used to compute the authentication tag in the AES-GCM construction.
pub const Ghash = Hash(.big, true);

/// POLYVAL is a universal hash function that uses multiplication by a fixed
/// parameter within a Galois field.
///
/// It is not a general purpose hash function - The key must be secret, unpredictable and never reused.
///
/// POLYVAL is typically used to compute the authentication tag in the AES-GCM-SIV construction.
pub const Polyval = Hash(.little, false);

fn Hash(comptime endian: std.builtin.Endian, comptime shift_key: bool) type {
    return struct {
        const Self = @This();

        pub const block_length: usize = 16;
        pub const mac_length = 16;
        pub const key_length = 16;

        const pc_count = if (builtin.mode != .ReleaseSmall) 16 else 2;
        const agg_4_threshold = 22;
        const agg_8_threshold = 84;
        const agg_16_threshold = 328;

        // Before the Haswell architecture, the carryless multiplication instruction was
        // extremely slow. Even with 128-bit operands, using Karatsuba multiplication was
        // thus faster than a schoolbook multiplication.
        // This is no longer the case -- Modern CPUs, including ARM-based ones, have a fast
        // carryless multiplication instruction; using 4 multiplications is now faster than
        // 3 multiplications with extra shifts and additions.
        const mul_algorithm = if (builtin.cpu.arch == .x86) .karatsuba else .schoolbook;

        hx: [pc_count]Precomp,
        acc: u128 = 0,

        leftover: usize = 0,
        buf: [block_length]u8 align(16) = undefined,

        /// Initialize the GHASH state with a key, and a minimum number of block count.
        pub fn initForBlockCount(key: *const [key_length]u8, block_count: usize) Self {
            var h = mem.readInt(u128, key[0..16], endian);
            if (shift_key) {
                // Shift the key by 1 bit to the left & reduce for GCM.
                const carry = ((@as(u128, 0xc2) << 120) | 1) & (@as(u128, 0) -% (h >> 127));
                h = (h << 1) ^ carry;
            }
            var hx: [pc_count]Precomp = undefined;
            hx[0] = h;
            hx[1] = reduce(clsq128(hx[0])); // h^2

            if (builtin.mode != .ReleaseSmall) {
                hx[2] = reduce(clmul128(hx[1], h)); // h^3
                hx[3] = reduce(clsq128(hx[1])); // h^4 = h^2^2
                if (block_count >= agg_8_threshold) {
                    hx[4] = reduce(clmul128(hx[3], h)); // h^5
                    hx[5] = reduce(clsq128(hx[2])); // h^6 = h^3^2
                    hx[6] = reduce(clmul128(hx[5], h)); // h^7
                    hx[7] = reduce(clsq128(hx[3])); // h^8 = h^4^2
                }
                if (block_count >= agg_16_threshold) {
                    var i: usize = 8;
                    while (i < 16) : (i += 2) {
                        hx[i] = reduce(clmul128(hx[i - 1], h));
                        hx[i + 1] = reduce(clsq128(hx[i / 2]));
                    }
                }
            }
            return Self{ .hx = hx };
        }

        /// Initialize the GHASH state with a key.
        pub fn init(key: *const [key_length]u8) Self {
            return Self.initForBlockCount(key, math.maxInt(usize));
        }

        const Selector = enum { lo, hi, hi_lo };

        // Carryless multiplication of two 64-bit integers for x86_64.
        inline fn clmulPclmul(x: u128, y: u128, comptime half: Selector) u128 {
            switch (half) {
                .hi => {
                    const product = asm (
                        \\ vpclmulqdq $0x11, %[x], %[y], %[out]
                        : [out] "=x" (-> @Vector(2, u64)),
                        : [x] "x" (@as(@Vector(2, u64), @bitCast(x))),
                          [y] "x" (@as(@Vector(2, u64), @bitCast(y))),
                    );
                    return @as(u128, @bitCast(product));
                },
                .lo => {
                    const product = asm (
                        \\ vpclmulqdq $0x00, %[x], %[y], %[out]
                        : [out] "=x" (-> @Vector(2, u64)),
                        : [x] "x" (@as(@Vector(2, u64), @bitCast(x))),
                          [y] "x" (@as(@Vector(2, u64), @bitCast(y))),
                    );
                    return @as(u128, @bitCast(product));
                },
                .hi_lo => {
                    const product = asm (
                        \\ vpclmulqdq $0x10, %[x], %[y], %[out]
                        : [out] "=x" (-> @Vector(2, u64)),
                        : [x] "x" (@as(@Vector(2, u64), @bitCast(x))),
                          [y] "x" (@as(@Vector(2, u64), @bitCast(y))),
                    );
                    return @as(u128, @bitCast(product));
                },
            }
        }

        // Carryless multiplication of two 64-bit integers for ARM crypto.
        inline fn clmulPmull(x: u128, y: u128, comptime half: Selector) u128 {
            switch (half) {
                .hi => {
                    const product = asm (
                        \\ pmull2 %[out].1q, %[x].2d, %[y].2d
                        : [out] "=w" (-> @Vector(2, u64)),
                        : [x] "w" (@as(@Vector(2, u64), @bitCast(x))),
                          [y] "w" (@as(@Vector(2, u64), @bitCast(y))),
                    );
                    return @as(u128, @bitCast(product));
                },
                .lo => {
                    const product = asm (
                        \\ pmull %[out].1q, %[x].1d, %[y].1d
                        : [out] "=w" (-> @Vector(2, u64)),
                        : [x] "w" (@as(@Vector(2, u64), @bitCast(x))),
                          [y] "w" (@as(@Vector(2, u64), @bitCast(y))),
                    );
                    return @as(u128, @bitCast(product));
                },
                .hi_lo => {
                    const product = asm (
                        \\ pmull %[out].1q, %[x].1d, %[y].1d
                        : [out] "=w" (-> @Vector(2, u64)),
                        : [x] "w" (@as(@Vector(2, u64), @bitCast(x >> 64))),
                          [y] "w" (@as(@Vector(2, u64), @bitCast(y))),
                    );
                    return @as(u128, @bitCast(product));
                },
            }
        }

        /// clmulSoft128_64 is faster on platforms with no native 128-bit registers.
        const clmulSoft = switch (builtin.cpu.arch) {
            .wasm32, .wasm64 => clmulSoft128_64,
            else => if (std.simd.suggestVectorLength(u128) != null) clmulSoft128 else clmulSoft128_64,
        };

        // Software carryless multiplication of two 64-bit integers using native 128-bit registers.
        fn clmulSoft128(x_: u128, y_: u128, comptime half: Selector) u128 {
            const x = @as(u64, @truncate(if (half == .hi or half == .hi_lo) x_ >> 64 else x_));
            const y = @as(u64, @truncate(if (half == .hi) y_ >> 64 else y_));

            const x0 = x & 0x1111111111111110;
            const x1 = x & 0x2222222222222220;
            const x2 = x & 0x4444444444444440;
            const x3 = x & 0x8888888888888880;
            const y0 = y & 0x1111111111111111;
            const y1 = y & 0x2222222222222222;
            const y2 = y & 0x4444444444444444;
            const y3 = y & 0x8888888888888888;
            const z0 = (x0 * @as(u128, y0)) ^ (x1 * @as(u128, y3)) ^ (x2 * @as(u128, y2)) ^ (x3 * @as(u128, y1));
            const z1 = (x0 * @as(u128, y1)) ^ (x1 * @as(u128, y0)) ^ (x2 * @as(u128, y3)) ^ (x3 * @as(u128, y2));
            const z2 = (x0 * @as(u128, y2)) ^ (x1 * @as(u128, y1)) ^ (x2 * @as(u128, y0)) ^ (x3 * @as(u128, y3));
            const z3 = (x0 * @as(u128, y3)) ^ (x1 * @as(u128, y2)) ^ (x2 * @as(u128, y1)) ^ (x3 * @as(u128, y0));

            const x0_mask = @as(u64, 0) -% (x & 1);
            const x1_mask = @as(u64, 0) -% ((x >> 1) & 1);
            const x2_mask = @as(u64, 0) -% ((x >> 2) & 1);
            const x3_mask = @as(u64, 0) -% ((x >> 3) & 1);
            const extra = (x0_mask & y) ^ (@as(u128, x1_mask & y) << 1) ^
                (@as(u128, x2_mask & y) << 2) ^ (@as(u128, x3_mask & y) << 3);

            return (z0 & 0x11111111111111111111111111111111) ^
                (z1 & 0x22222222222222222222222222222222) ^
                (z2 & 0x44444444444444444444444444444444) ^
                (z3 & 0x88888888888888888888888888888888) ^ extra;
        }

        // Software carryless multiplication of two 32-bit integers.
        fn clmulSoft32(x: u32, y: u32) u64 {
            const mulWide = math.mulWide;
            const a0 = x & 0x11111111;
            const a1 = x & 0x22222222;
            const a2 = x & 0x44444444;
            const a3 = x & 0x88888888;
            const b0 = y & 0x11111111;
            const b1 = y & 0x22222222;
            const b2 = y & 0x44444444;
            const b3 = y & 0x88888888;
            const c0 = mulWide(u32, a0, b0) ^ mulWide(u32, a1, b3) ^ mulWide(u32, a2, b2) ^ mulWide(u32, a3, b1);
            const c1 = mulWide(u32, a0, b1) ^ mulWide(u32, a1, b0) ^ mulWide(u32, a2, b3) ^ mulWide(u32, a3, b2);
            const c2 = mulWide(u32, a0, b2) ^ mulWide(u32, a1, b1) ^ mulWide(u32, a2, b0) ^ mulWide(u32, a3, b3);
            const c3 = mulWide(u32, a0, b3) ^ mulWide(u32, a1, b2) ^ mulWide(u32, a2, b1) ^ mulWide(u32, a3, b0);
            return (c0 & 0x1111111111111111) | (c1 & 0x2222222222222222) | (c2 & 0x4444444444444444) | (c3 & 0x8888888888888888);
        }

        // Software carryless multiplication of two 128-bit integers using 64-bit registers.
        fn clmulSoft128_64(x_: u128, y_: u128, comptime half: Selector) u128 {
            const a = @as(u64, @truncate(if (half == .hi or half == .hi_lo) x_ >> 64 else x_));
            const b = @as(u64, @truncate(if (half == .hi) y_ >> 64 else y_));
            const a0 = @as(u32, @truncate(a));
            const a1 = @as(u32, @truncate(a >> 32));
            const b0 = @as(u32, @truncate(b));
            const b1 = @as(u32, @truncate(b >> 32));
            const lo = clmulSoft32(a0, b0);
            const hi = clmulSoft32(a1, b1);
            const mid = clmulSoft32(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
            const res_lo = lo ^ (mid << 32);
            const res_hi = hi ^ (mid >> 32);
            return @as(u128, res_lo) | (@as(u128, res_hi) << 64);
        }

        const I256 = struct {
            hi: u128,
            lo: u128,
            mid: u128,
        };

        inline fn xor256(x: *I256, y: I256) void {
            x.* = I256{
                .hi = x.hi ^ y.hi,
                .lo = x.lo ^ y.lo,
                .mid = x.mid ^ y.mid,
            };
        }

        // Square a 128-bit integer in GF(2^128).
        fn clsq128(x: u128) I256 {
            return .{
                .hi = clmul(x, x, .hi),
                .lo = clmul(x, x, .lo),
                .mid = 0,
            };
        }

        // Multiply two 128-bit integers in GF(2^128).
        inline fn clmul128(x: u128, y: u128) I256 {
            if (mul_algorithm == .karatsuba) {
                const x_hi = @as(u64, @truncate(x >> 64));
                const y_hi = @as(u64, @truncate(y >> 64));
                const r_lo = clmul(x, y, .lo);
                const r_hi = clmul(x, y, .hi);
                const r_mid = clmul(x ^ x_hi, y ^ y_hi, .lo) ^ r_lo ^ r_hi;
                return .{
                    .hi = r_hi,
                    .lo = r_lo,
                    .mid = r_mid,
                };
            } else {
                return .{
                    .hi = clmul(x, y, .hi),
                    .lo = clmul(x, y, .lo),
                    .mid = clmul(x, y, .hi_lo) ^ clmul(y, x, .hi_lo),
                };
            }
        }

        // Reduce a 256-bit representative of a polynomial modulo the irreducible polynomial x^128 + x^127 + x^126 + x^121 + 1.
        // This is done using Shay Gueron's black magic demysticated here:
        // https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html
        inline fn reduce(x: I256) u128 {
            const hi = x.hi ^ (x.mid >> 64);
            const lo = x.lo ^ (x.mid << 64);
            const p64 = (((1 << 121) | (1 << 126) | (1 << 127)) >> 64);
            const a = clmul(lo, p64, .lo);
            const b = ((lo << 64) | (lo >> 64)) ^ a;
            const c = clmul(b, p64, .lo);
            const d = ((b << 64) | (b >> 64)) ^ c;
            return d ^ hi;
        }

        const has_pclmul = std.Target.x86.featureSetHas(builtin.cpu.features, .pclmul);
        const has_avx = std.Target.x86.featureSetHas(builtin.cpu.features, .avx);
        const has_armaes = std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes);
        // C backend doesn't currently support passing vectors to inline asm.
        const clmul = if (builtin.cpu.arch == .x86_64 and builtin.zig_backend != .stage2_c and has_pclmul and has_avx) impl: {
            break :impl clmulPclmul;
        } else if (builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and has_armaes) impl: {
            break :impl clmulPmull;
        } else impl: {
            break :impl clmulSoft;
        };

        // Process 16 byte blocks.
        fn blocks(st: *Self, msg: []const u8) void {
            assert(msg.len % 16 == 0); // GHASH blocks() expects full blocks
            var acc = st.acc;

            var i: usize = 0;

            if (builtin.mode != .ReleaseSmall and msg.len >= agg_16_threshold * block_length) {
                // 16-blocks aggregated reduction
                while (i + 256 <= msg.len) : (i += 256) {
                    var u = clmul128(acc ^ mem.readInt(u128, msg[i..][0..16], endian), st.hx[15 - 0]);
                    comptime var j = 1;
                    inline while (j < 16) : (j += 1) {
                        xor256(&u, clmul128(mem.readInt(u128, msg[i..][j * 16 ..][0..16], endian), st.hx[15 - j]));
                    }
                    acc = reduce(u);
                }
            } else if (builtin.mode != .ReleaseSmall and msg.len >= agg_8_threshold * block_length) {
                // 8-blocks aggregated reduction
                while (i + 128 <= msg.len) : (i += 128) {
                    var u = clmul128(acc ^ mem.readInt(u128, msg[i..][0..16], endian), st.hx[7 - 0]);
                    comptime var j = 1;
                    inline while (j < 8) : (j += 1) {
                        xor256(&u, clmul128(mem.readInt(u128, msg[i..][j * 16 ..][0..16], endian), st.hx[7 - j]));
                    }
                    acc = reduce(u);
                }
            } else if (builtin.mode != .ReleaseSmall and msg.len >= agg_4_threshold * block_length) {
                // 4-blocks aggregated reduction
                while (i + 64 <= msg.len) : (i += 64) {
                    var u = clmul128(acc ^ mem.readInt(u128, msg[i..][0..16], endian), st.hx[3 - 0]);
                    comptime var j = 1;
                    inline while (j < 4) : (j += 1) {
                        xor256(&u, clmul128(mem.readInt(u128, msg[i..][j * 16 ..][0..16], endian), st.hx[3 - j]));
                    }
                    acc = reduce(u);
                }
            }
            // 2-blocks aggregated reduction
            while (i + 32 <= msg.len) : (i += 32) {
                var u = clmul128(acc ^ mem.readInt(u128, msg[i..][0..16], endian), st.hx[1 - 0]);
                comptime var j = 1;
                inline while (j < 2) : (j += 1) {
                    xor256(&u, clmul128(mem.readInt(u128, msg[i..][j * 16 ..][0..16], endian), st.hx[1 - j]));
                }
                acc = reduce(u);
            }
            // remaining blocks
            if (i < msg.len) {
                const u = clmul128(acc ^ mem.readInt(u128, msg[i..][0..16], endian), st.hx[0]);
                acc = reduce(u);
                i += 16;
            }
            assert(i == msg.len);
            st.acc = acc;
        }

        /// Absorb a message into the GHASH state.
        pub fn update(st: *Self, m: []const u8) void {
            var mb = m;

            if (st.leftover > 0) {
                const want = @min(block_length - st.leftover, mb.len);
                const mc = mb[0..want];
                for (mc, 0..) |x, i| {
                    st.buf[st.leftover + i] = x;
                }
                mb = mb[want..];
                st.leftover += want;
                if (st.leftover < block_length) {
                    return;
                }
                st.blocks(&st.buf);
                st.leftover = 0;
            }
            if (mb.len >= block_length) {
                const want = mb.len & ~(block_length - 1);
                st.blocks(mb[0..want]);
                mb = mb[want..];
            }
            if (mb.len > 0) {
                for (mb, 0..) |x, i| {
                    st.buf[st.leftover + i] = x;
                }
                st.leftover += mb.len;
            }
        }

        /// Zero-pad to align the next input to the first byte of a block
        pub fn pad(st: *Self) void {
            if (st.leftover == 0) {
                return;
            }
            var i = st.leftover;
            while (i < block_length) : (i += 1) {
                st.buf[i] = 0;
            }
            st.blocks(&st.buf);
            st.leftover = 0;
        }

        /// Compute the GHASH of the entire input.
        pub fn final(st: *Self, out: *[mac_length]u8) void {
            st.pad();
            mem.writeInt(u128, out[0..16], st.acc, endian);

            std.crypto.secureZero(u8, @as([*]u8, @ptrCast(st))[0..@sizeOf(Self)]);
        }

        /// Compute the GHASH of a message.
        pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
            var st = Self.init(key);
            st.update(msg);
            st.final(out);
        }
    };
}

const htest = @import("test.zig");

test "ghash" {
    const key = [_]u8{0x42} ** 16;
    const m = [_]u8{0x69} ** 256;

    var st = Ghash.init(&key);
    st.update(&m);
    var out: [16]u8 = undefined;
    st.final(&out);
    try htest.assertEqual("889295fa746e8b174bf4ec80a65dea41", &out);

    st = Ghash.init(&key);
    st.update(m[0..100]);
    st.update(m[100..]);
    st.final(&out);
    try htest.assertEqual("889295fa746e8b174bf4ec80a65dea41", &out);
}

test "ghash2" {
    var key: [16]u8 = undefined;
    var i: usize = 0;
    while (i < key.len) : (i += 1) {
        key[i] = @as(u8, @intCast(i * 15 + 1));
    }
    const tvs = [_]struct { len: usize, hash: [:0]const u8 }{
        .{ .len = 5263, .hash = "b9395f37c131cd403a327ccf82ec016a" },
        .{ .len = 1361, .hash = "8c24cb3664e9a36e32ddef0c8178ab33" },
        .{ .len = 1344, .hash = "015d7243b52d62eee8be33a66a9658cc" },
        .{ .len = 1000, .hash = "56e148799944193f351f2014ef9dec9d" },
        .{ .len = 512, .hash = "ca4882ce40d37546185c57709d17d1ca" },
        .{ .len = 128, .hash = "d36dc3aac16cfe21a75cd5562d598c1c" },
        .{ .len = 111, .hash = "6e2bea99700fd19cf1694e7b56543320" },
        .{ .len = 80, .hash = "aa28f4092a7cca155f3de279cf21aa17" },
        .{ .len = 16, .hash = "9d7eb5ed121a52a4b0996e4ec9b98911" },
        .{ .len = 1, .hash = "968a203e5c7a98b6d4f3112f4d6b89a7" },
        .{ .len = 0, .hash = "00000000000000000000000000000000" },
    };
    inline for (tvs) |tv| {
        var m: [tv.len]u8 = undefined;
        i = 0;
        while (i < m.len) : (i += 1) {
            m[i] = @as(u8, @truncate(i % 254 + 1));
        }
        var st = Ghash.init(&key);
        st.update(&m);
        var out: [16]u8 = undefined;
        st.final(&out);
        try htest.assertEqual(tv.hash, &out);
    }
}

test "polyval" {
    const key = [_]u8{0x42} ** 16;
    const m = [_]u8{0x69} ** 256;

    var st = Polyval.init(&key);
    st.update(&m);
    var out: [16]u8 = undefined;
    st.final(&out);
    try htest.assertEqual("0713c82b170eef25c8955ddf72c85ccb", &out);

    st = Polyval.init(&key);
    st.update(m[0..100]);
    st.update(m[100..]);
    st.final(&out);
    try htest.assertEqual("0713c82b170eef25c8955ddf72c85ccb", &out);
}
const std = @import("../std.zig");
const sha2 = std.crypto.hash.sha2;

/// The composition of two hash functions: H1 o H2, with the same API as regular hash functions.
///
/// The security level of a hash cascade doesn't exceed the security level of the weakest function.
///
/// However, Merkle–Damgård constructions such as SHA-256 are vulnerable to length-extension attacks,
/// where under some conditions, `H(x||e)` can be efficiently computed without knowing `x`.
/// The composition of two hash functions is a common defense against such attacks.
///
/// This is not necessary with modern hash functions, such as SHA-3, BLAKE2 and BLAKE3.
pub fn Composition(comptime H1: type, comptime H2: type) type {
    return struct {
        const Self = @This();

        H1: H1,
        H2: H2,

        /// The length of the hash output, in bytes.
        pub const digest_length = H1.digest_length;
        /// The block length, in bytes.
        pub const block_length = H1.block_length;

        /// Options for both hashes.
        pub const Options = struct {
            /// Options for H1.
            H1: H1.Options = .{},
            /// Options for H2.
            H2: H2.Options = .{},
        };

        /// Initialize the hash composition with the given options.
        pub fn init(options: Options) Self {
            return Self{ .H1 = H1.init(options.H1), .H2 = H2.init(options.H2) };
        }

        /// Compute H1(H2(b)).
        pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
            var d = Self.init(options);
            d.update(b);
            d.final(out);
        }

        /// Add content to the hash.
        pub fn update(d: *Self, b: []const u8) void {
            d.H2.update(b);
        }

        /// Compute the final hash for the accumulated content: H1(H2(b)).
        pub fn final(d: *Self, out: *[digest_length]u8) void {
            var H2_digest: [H2.digest_length]u8 = undefined;
            d.H2.final(&H2_digest);
            d.H1.update(&H2_digest);
            d.H1.final(out);
        }
    };
}

/// SHA-256(SHA-256())
pub const Sha256oSha256 = Composition(sha2.Sha256, sha2.Sha256);
/// SHA-384(SHA-384())
pub const Sha384oSha384 = Composition(sha2.Sha384, sha2.Sha384);
/// SHA-512(SHA-512())
pub const Sha512oSha512 = Composition(sha2.Sha512, sha2.Sha512);

test "Hash composition" {
    const Sha256 = sha2.Sha256;
    const msg = "test";

    var out: [Sha256oSha256.digest_length]u8 = undefined;
    Sha256oSha256.hash(msg, &out, .{});

    var t: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(msg, &t, .{});
    var out2: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&t, &out2, .{});

    try std.testing.expectEqualSlices(u8, &out, &out2);
}
const std = @import("../std.zig");
const assert = std.debug.assert;
const hmac = std.crypto.auth.hmac;
const mem = std.mem;

/// HKDF-SHA256
pub const HkdfSha256 = Hkdf(hmac.sha2.HmacSha256);

/// HKDF-SHA512
pub const HkdfSha512 = Hkdf(hmac.sha2.HmacSha512);

/// The Hkdf construction takes some source of initial keying material and
/// derives one or more uniform keys from it.
pub fn Hkdf(comptime Hmac: type) type {
    return struct {
        /// Length of a master key, in bytes.
        pub const prk_length = Hmac.mac_length;

        /// Return a master key from a salt and initial keying material.
        pub fn extract(salt: []const u8, ikm: []const u8) [prk_length]u8 {
            var prk: [prk_length]u8 = undefined;
            Hmac.create(&prk, ikm, salt);
            return prk;
        }

        /// Initialize the creation of a master key from a salt
        /// and keying material that can be added later, possibly in chunks.
        /// Example:
        /// ```
        /// var prk: [hkdf.prk_length]u8 = undefined;
        /// var hkdf = HkdfSha256.extractInit(salt);
        /// hkdf.update(ikm1);
        /// hkdf.update(ikm2);
        /// hkdf.final(&prk);
        /// ```
        pub fn extractInit(salt: []const u8) Hmac {
            return Hmac.init(salt);
        }

        /// Derive a subkey from a master key `prk` and a subkey description `ctx`.
        pub fn expand(out: []u8, ctx: []const u8, prk: [prk_length]u8) void {
            assert(out.len <= prk_length * 255); // output size is too large for the Hkdf construction
            var i: usize = 0;
            var counter = [1]u8{1};
            while (i + prk_length <= out.len) : (i += prk_length) {
                var st = Hmac.init(&prk);
                if (i != 0) {
                    st.update(out[i - prk_length ..][0..prk_length]);
                }
                st.update(ctx);
                st.update(&counter);
                st.final(out[i..][0..prk_length]);
                counter[0] +%= 1;
                assert(counter[0] != 1);
            }
            const left = out.len % prk_length;
            if (left > 0) {
                var st = Hmac.init(&prk);
                if (i != 0) {
                    st.update(out[i - prk_length ..][0..prk_length]);
                }
                st.update(ctx);
                st.update(&counter);
                var tmp: [prk_length]u8 = undefined;
                st.final(tmp[0..prk_length]);
                @memcpy(out[i..][0..left], tmp[0..left]);
            }
        }
    };
}

const htest = @import("test.zig");

test "Hkdf" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const context = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    const kdf = HkdfSha256;
    const prk = kdf.extract(&salt, &ikm);
    try htest.assertEqual("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", &prk);
    var out: [42]u8 = undefined;
    kdf.expand(&out, &context, prk);
    try htest.assertEqual("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", &out);

    var hkdf = kdf.extractInit(&salt);
    hkdf.update(&ikm);
    var prk2: [kdf.prk_length]u8 = undefined;
    hkdf.final(&prk2);
    try htest.assertEqual("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", &prk2);
}

test "Hkdf Sha3-512" {
    const sha3_512 = std.crypto.hash.sha3.Sha3_512;
    const hmac_sha3_512 = hmac.Hmac(sha3_512);
    const hkdf = Hkdf(hmac_sha3_512);
    const prk = hkdf.extract("", "");
    var out = [1]u8{0};
    hkdf.expand(out[0..], "", prk);
}
const std = @import("../std.zig");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;

pub const HmacMd5 = Hmac(crypto.hash.Md5);
pub const HmacSha1 = Hmac(crypto.hash.Sha1);

pub const sha2 = struct {
    pub const HmacSha224 = Hmac(crypto.hash.sha2.Sha224);
    pub const HmacSha256 = Hmac(crypto.hash.sha2.Sha256);
    pub const HmacSha384 = Hmac(crypto.hash.sha2.Sha384);
    pub const HmacSha512 = Hmac(crypto.hash.sha2.Sha512);
};

pub fn Hmac(comptime Hash: type) type {
    return struct {
        const Self = @This();
        pub const mac_length = Hash.digest_length;
        pub const key_length_min = 0;
        pub const key_length = mac_length; // recommended key length

        o_key_pad: [Hash.block_length]u8,
        hash: Hash,

        // HMAC(k, m) = H(o_key_pad || H(i_key_pad || msg)) where || is concatenation
        pub fn create(out: *[mac_length]u8, msg: []const u8, key: []const u8) void {
            var ctx = Self.init(key);
            ctx.update(msg);
            ctx.final(out);
        }

        pub fn init(key: []const u8) Self {
            var ctx: Self = undefined;
            var scratch: [Hash.block_length]u8 = undefined;
            var i_key_pad: [Hash.block_length]u8 = undefined;

            // Normalize key length to block size of hash
            if (key.len > Hash.block_length) {
                Hash.hash(key, scratch[0..mac_length], .{});
                @memset(scratch[mac_length..Hash.block_length], 0);
            } else if (key.len < Hash.block_length) {
                @memcpy(scratch[0..key.len], key);
                @memset(scratch[key.len..Hash.block_length], 0);
            } else {
                @memcpy(&scratch, key);
            }

            for (&ctx.o_key_pad, 0..) |*b, i| {
                b.* = scratch[i] ^ 0x5c;
            }

            for (&i_key_pad, 0..) |*b, i| {
                b.* = scratch[i] ^ 0x36;
            }

            ctx.hash = Hash.init(.{});
            ctx.hash.update(&i_key_pad);
            return ctx;
        }

        pub fn update(ctx: *Self, msg: []const u8) void {
            ctx.hash.update(msg);
        }

        pub fn final(ctx: *Self, out: *[mac_length]u8) void {
            var scratch: [mac_length]u8 = undefined;
            ctx.hash.final(&scratch);
            var ohash = Hash.init(.{});
            ohash.update(&ctx.o_key_pad);
            ohash.update(&scratch);
            ohash.final(out);
        }
    };
}

const htest = @import("test.zig");

test "md5" {
    var out: [HmacMd5.mac_length]u8 = undefined;
    HmacMd5.create(out[0..], "", "");
    try htest.assertEqual("74e6f7298a9c2d168935f58c001bad88", out[0..]);

    HmacMd5.create(out[0..], "The quick brown fox jumps over the lazy dog", "key");
    try htest.assertEqual("80070713463e7749b90c2dc24911e275", out[0..]);
}

test "sha1" {
    var out: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(out[0..], "", "");
    try htest.assertEqual("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d", out[0..]);

    HmacSha1.create(out[0..], "The quick brown fox jumps over the lazy dog", "key");
    try htest.assertEqual("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", out[0..]);
}

test "sha256" {
    var out: [sha2.HmacSha256.mac_length]u8 = undefined;
    sha2.HmacSha256.create(out[0..], "", "");
    try htest.assertEqual("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", out[0..]);

    sha2.HmacSha256.create(out[0..], "The quick brown fox jumps over the lazy dog", "key");
    try htest.assertEqual("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", out[0..]);
}
const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const Ascon = crypto.core.Ascon(.big);
const AuthenticationError = crypto.errors.AuthenticationError;

/// ISAPv2 is an authenticated encryption system hardened against side channels and fault attacks.
/// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/isap-spec-round2.pdf
///
/// Note that ISAP is not suitable for high-performance applications.
///
/// However:
/// - if allowing physical access to the device is part of your threat model,
/// - or if you need resistance against microcode/hardware-level side channel attacks,
/// - or if software-induced fault attacks such as rowhammer are a concern,
///
/// then you may consider ISAP for highly sensitive data.
pub const IsapA128A = struct {
    pub const key_length = 16;
    pub const nonce_length = 16;
    pub const tag_length: usize = 16;

    const iv1 = [_]u8{ 0x01, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c };
    const iv2 = [_]u8{ 0x02, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c };
    const iv3 = [_]u8{ 0x03, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c };

    st: Ascon,

    fn absorb(isap: *IsapA128A, m: []const u8) void {
        var i: usize = 0;
        while (true) : (i += 8) {
            const left = m.len - i;
            if (left >= 8) {
                isap.st.addBytes(m[i..][0..8]);
                isap.st.permute();
                if (left == 8) {
                    isap.st.addByte(0x80, 0);
                    isap.st.permute();
                    break;
                }
            } else {
                var padded = [_]u8{0} ** 8;
                @memcpy(padded[0..left], m[i..]);
                padded[left] = 0x80;
                isap.st.addBytes(&padded);
                isap.st.permute();
                break;
            }
        }
    }

    fn trickle(k: [16]u8, iv: [8]u8, y: []const u8, comptime out_len: usize) [out_len]u8 {
        var isap = IsapA128A{
            .st = Ascon.initFromWords(.{
                mem.readInt(u64, k[0..8], .big),
                mem.readInt(u64, k[8..16], .big),
                mem.readInt(u64, iv[0..8], .big),
                0,
                0,
            }),
        };
        isap.st.permute();

        var i: usize = 0;
        while (i < y.len * 8 - 1) : (i += 1) {
            const cur_byte_pos = i / 8;
            const cur_bit_pos: u3 = @truncate(7 - (i % 8));
            const cur_bit = ((y[cur_byte_pos] >> cur_bit_pos) & 1) << 7;
            isap.st.addByte(cur_bit, 0);
            isap.st.permuteR(1);
        }
        const cur_bit = (y[y.len - 1] & 1) << 7;
        isap.st.addByte(cur_bit, 0);
        isap.st.permute();

        var out: [out_len]u8 = undefined;
        isap.st.extractBytes(&out);
        isap.st.secureZero();
        return out;
    }

    fn mac(c: []const u8, ad: []const u8, npub: [16]u8, key: [16]u8) [16]u8 {
        var isap = IsapA128A{
            .st = Ascon.initFromWords(.{
                mem.readInt(u64, npub[0..8], .big),
                mem.readInt(u64, npub[8..16], .big),
                mem.readInt(u64, iv1[0..], .big),
                0,
                0,
            }),
        };
        isap.st.permute();

        isap.absorb(ad);
        isap.st.addByte(1, Ascon.block_bytes - 1);
        isap.absorb(c);

        var y: [16]u8 = undefined;
        isap.st.extractBytes(&y);
        const nb = trickle(key, iv2, y[0..], 16);
        isap.st.setBytes(&nb);
        isap.st.permute();

        var tag: [16]u8 = undefined;
        isap.st.extractBytes(&tag);
        isap.st.secureZero();
        return tag;
    }

    fn xor(out: []u8, in: []const u8, npub: [16]u8, key: [16]u8) void {
        debug.assert(in.len == out.len);

        const nb = trickle(key, iv3, npub[0..], 24);
        var isap = IsapA128A{
            .st = Ascon.initFromWords(.{
                mem.readInt(u64, nb[0..8], .big),
                mem.readInt(u64, nb[8..16], .big),
                mem.readInt(u64, nb[16..24], .big),
                mem.readInt(u64, npub[0..8], .big),
                mem.readInt(u64, npub[8..16], .big),
            }),
        };
        isap.st.permuteR(6);

        var i: usize = 0;
        while (true) : (i += 8) {
            const left = in.len - i;
            if (left >= 8) {
                isap.st.xorBytes(out[i..][0..8], in[i..][0..8]);
                if (left == 8) {
                    break;
                }
                isap.st.permuteR(6);
            } else {
                isap.st.xorBytes(out[i..], in[i..]);
                break;
            }
        }
        isap.st.secureZero();
    }

    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        xor(c, m, npub, key);
        tag.* = mac(c, ad, npub, key);
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
        var computed_tag = mac(c, ad, npub, key);
        const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
        if (!verify) {
            crypto.secureZero(u8, &computed_tag);
            @memset(m, undefined);
            return error.AuthenticationFailed;
        }
        xor(m, c, npub, key);
    }
};

test "ISAP" {
    const k = [_]u8{1} ** 16;
    const n = [_]u8{2} ** 16;
    var tag: [16]u8 = undefined;
    const ad = "ad";
    var msg = "test";
    var c: [msg.len]u8 = undefined;
    IsapA128A.encrypt(c[0..], &tag, msg[0..], ad, n, k);
    try testing.expect(mem.eql(u8, &[_]u8{ 0x8f, 0x68, 0x03, 0x8d }, c[0..]));
    try testing.expect(mem.eql(u8, &[_]u8{ 0x6c, 0x25, 0xe8, 0xe2, 0xe1, 0x1f, 0x38, 0xe9, 0x80, 0x75, 0xde, 0xd5, 0x2d, 0xb2, 0x31, 0x82 }, tag[0..]));
    try IsapA128A.decrypt(c[0..], c[0..], tag, ad, n, k);
    try testing.expect(mem.eql(u8, msg, c[0..]));
}
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const native_endian = builtin.cpu.arch.endian();
const mode = @import("builtin").mode;

/// The Keccak-f permutation.
pub fn KeccakF(comptime f: u11) type {
    comptime assert(f >= 200 and f <= 1600 and f % 200 == 0); // invalid bit size
    const T = std.meta.Int(.unsigned, f / 25);
    const Block = [25]T;

    const PI = [_]u5{
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    };

    return struct {
        const Self = @This();

        /// Number of bytes in the state.
        pub const block_bytes = f / 8;

        /// Maximum number of rounds for the given f parameter.
        pub const max_rounds = 12 + 2 * math.log2(f / 25);

        // Round constants
        const RC = rc: {
            const RC64 = [_]u64{
                0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
                0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
                0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
            };
            var rc: [max_rounds]T = undefined;
            for (&rc, RC64[0..max_rounds]) |*t, c| t.* = @as(T, @truncate(c));
            break :rc rc;
        };

        st: Block = [_]T{0} ** 25,

        /// Initialize the state from a slice of bytes.
        pub fn init(bytes: [block_bytes]u8) Self {
            var self: Self = undefined;
            inline for (&self.st, 0..) |*r, i| {
                r.* = mem.readInt(T, bytes[@sizeOf(T) * i ..][0..@sizeOf(T)], .little);
            }
            return self;
        }

        /// A representation of the state as bytes. The byte order is architecture-dependent.
        pub fn asBytes(self: *Self) *[block_bytes]u8 {
            return mem.asBytes(&self.st);
        }

        /// Byte-swap the entire state if the architecture doesn't match the required endianness.
        pub fn endianSwap(self: *Self) void {
            for (&self.st) |*w| {
                w.* = mem.littleToNative(T, w.*);
            }
        }

        /// Set bytes starting at the beginning of the state.
        pub fn setBytes(self: *Self, bytes: []const u8) void {
            var i: usize = 0;
            while (i + @sizeOf(T) <= bytes.len) : (i += @sizeOf(T)) {
                self.st[i / @sizeOf(T)] = mem.readInt(T, bytes[i..][0..@sizeOf(T)], .little);
            }
            if (i < bytes.len) {
                var padded = [_]u8{0} ** @sizeOf(T);
                @memcpy(padded[0 .. bytes.len - i], bytes[i..]);
                self.st[i / @sizeOf(T)] = mem.readInt(T, padded[0..], .little);
            }
        }

        /// XOR a byte into the state at a given offset.
        pub fn addByte(self: *Self, byte: u8, offset: usize) void {
            const z = @sizeOf(T) * @as(math.Log2Int(T), @truncate(offset % @sizeOf(T)));
            self.st[offset / @sizeOf(T)] ^= @as(T, byte) << z;
        }

        /// XOR bytes into the beginning of the state.
        pub fn addBytes(self: *Self, bytes: []const u8) void {
            var i: usize = 0;
            while (i + @sizeOf(T) <= bytes.len) : (i += @sizeOf(T)) {
                self.st[i / @sizeOf(T)] ^= mem.readInt(T, bytes[i..][0..@sizeOf(T)], .little);
            }
            if (i < bytes.len) {
                var padded = [_]u8{0} ** @sizeOf(T);
                @memcpy(padded[0 .. bytes.len - i], bytes[i..]);
                self.st[i / @sizeOf(T)] ^= mem.readInt(T, padded[0..], .little);
            }
        }

        /// Extract the first bytes of the state.
        pub fn extractBytes(self: *Self, out: []u8) void {
            var i: usize = 0;
            while (i + @sizeOf(T) <= out.len) : (i += @sizeOf(T)) {
                mem.writeInt(T, out[i..][0..@sizeOf(T)], self.st[i / @sizeOf(T)], .little);
            }
            if (i < out.len) {
                var padded = [_]u8{0} ** @sizeOf(T);
                mem.writeInt(T, padded[0..], self.st[i / @sizeOf(T)], .little);
                @memcpy(out[i..], padded[0 .. out.len - i]);
            }
        }

        /// XOR the first bytes of the state into a slice of bytes.
        pub fn xorBytes(self: *Self, out: []u8, in: []const u8) void {
            assert(out.len == in.len);

            var i: usize = 0;
            while (i + @sizeOf(T) <= in.len) : (i += @sizeOf(T)) {
                const x = mem.readInt(T, in[i..][0..@sizeOf(T)], native_endian) ^ mem.nativeToLittle(T, self.st[i / @sizeOf(T)]);
                mem.writeInt(T, out[i..][0..@sizeOf(T)], x, native_endian);
            }
            if (i < in.len) {
                var padded = [_]u8{0} ** @sizeOf(T);
                @memcpy(padded[0 .. in.len - i], in[i..]);
                const x = mem.readInt(T, &padded, native_endian) ^ mem.nativeToLittle(T, self.st[i / @sizeOf(T)]);
                mem.writeInt(T, &padded, x, native_endian);
                @memcpy(out[i..], padded[0 .. in.len - i]);
            }
        }

        /// Set the words storing the bytes of a given range to zero.
        pub fn clear(self: *Self, from: usize, to: usize) void {
            @memset(self.st[from / @sizeOf(T) .. (to + @sizeOf(T) - 1) / @sizeOf(T)], 0);
        }

        /// Clear the entire state, disabling compiler optimizations.
        pub fn secureZero(self: *Self) void {
            std.crypto.secureZero(T, &self.st);
        }

        inline fn round(self: *Self, rc: T) void {
            const st = &self.st;

            // theta
            var t = [_]T{0} ** 5;
            inline for (0..5) |i| {
                inline for (0..5) |j| {
                    t[i] ^= st[j * 5 + i];
                }
            }
            inline for (0..5) |i| {
                inline for (0..5) |j| {
                    st[j * 5 + i] ^= t[(i + 4) % 5] ^ math.rotl(T, t[(i + 1) % 5], 1);
                }
            }

            // rho+pi
            var last = st[1];
            comptime var rotc = 0;
            inline for (0..24) |i| {
                const x = PI[i];
                const tmp = st[x];
                rotc = (rotc + i + 1) % @bitSizeOf(T);
                st[x] = math.rotl(T, last, rotc);
                last = tmp;
            }
            inline for (0..5) |i| {
                inline for (0..5) |j| {
                    t[j] = st[i * 5 + j];
                }
                inline for (0..5) |j| {
                    st[i * 5 + j] = t[j] ^ (~t[(j + 1) % 5] & t[(j + 2) % 5]);
                }
            }

            // iota
            st[0] ^= rc;
        }

        /// Apply a (possibly) reduced-round permutation to the state.
        pub fn permuteR(self: *Self, comptime rounds: u5) void {
            var i = RC.len - rounds;
            while (i < RC.len - RC.len % 3) : (i += 3) {
                self.round(RC[i]);
                self.round(RC[i + 1]);
                self.round(RC[i + 2]);
            }
            while (i < RC.len) : (i += 1) {
                self.round(RC[i]);
            }
        }

        /// Apply a full-round permutation to the state.
        pub fn permute(self: *Self) void {
            self.permuteR(max_rounds);
        }
    };
}

/// A generic Keccak-P state.
pub fn State(comptime f: u11, comptime capacity: u11, comptime rounds: u5) type {
    comptime assert(f >= 200 and f <= 1600 and f % 200 == 0); // invalid state size
    comptime assert(capacity < f and capacity % 8 == 0); // invalid capacity size

    // In debug mode, track transitions to prevent insecure ones.
    const Op = enum { uninitialized, initialized, updated, absorb, squeeze };
    const TransitionTracker = if (mode == .Debug) struct {
        op: Op = .uninitialized,

        fn to(tracker: *@This(), next_op: Op) void {
            switch (next_op) {
                .updated => {
                    switch (tracker.op) {
                        .uninitialized => @panic("cannot permute before initializing"),
                        else => {},
                    }
                },
                .absorb => {
                    switch (tracker.op) {
                        .squeeze => @panic("cannot absorb right after squeezing"),
                        else => {},
                    }
                },
                .squeeze => {
                    switch (tracker.op) {
                        .uninitialized => @panic("cannot squeeze before initializing"),
                        .initialized => @panic("cannot squeeze right after initializing"),
                        .absorb => @panic("cannot squeeze right after absorbing"),
                        else => {},
                    }
                },
                .uninitialized => @panic("cannot transition to uninitialized"),
                .initialized => {},
            }
            tracker.op = next_op;
        }
    } else struct {
        // No-op in non-debug modes.
        inline fn to(tracker: *@This(), next_op: Op) void {
            _ = tracker; // no-op
            _ = next_op; // no-op
        }
    };

    return struct {
        const Self = @This();

        /// The block length, or rate, in bytes.
        pub const rate = KeccakF(f).block_bytes - capacity / 8;
        /// Keccak does not have any options.
        pub const Options = struct {};

        /// The input delimiter.
        delim: u8,

        offset: usize = 0,
        buf: [rate]u8 = undefined,

        st: KeccakF(f) = .{},

        transition: TransitionTracker = .{},

        /// Absorb a slice of bytes into the sponge.
        pub fn absorb(self: *Self, bytes: []const u8) void {
            self.transition.to(.absorb);
            var i: usize = 0;
            if (self.offset > 0) {
                const left = @min(rate - self.offset, bytes.len);
                @memcpy(self.buf[self.offset..][0..left], bytes[0..left]);
                self.offset += left;
                if (left == bytes.len) return;
                if (self.offset == rate) {
                    self.st.addBytes(self.buf[0..]);
                    self.st.permuteR(rounds);
                    self.offset = 0;
                }
                i = left;
            }
            while (i + rate < bytes.len) : (i += rate) {
                self.st.addBytes(bytes[i..][0..rate]);
                self.st.permuteR(rounds);
            }
            const left = bytes.len - i;
            if (left > 0) {
                @memcpy(self.buf[0..left], bytes[i..][0..left]);
            }
            self.offset = left;
        }

        /// Initialize the state from a slice of bytes.
        pub fn init(bytes: [f / 8]u8, delim: u8) Self {
            var st = Self{ .st = KeccakF(f).init(bytes), .delim = delim };
            st.transition.to(.initialized);
            return st;
        }

        /// Permute the state
        pub fn permute(self: *Self) void {
            if (mode == .Debug) {
                if (self.transition.op == .absorb and self.offset > 0) {
                    @panic("cannot permute with pending input - call fillBlock() or pad() instead");
                }
            }
            self.transition.to(.updated);
            self.st.permuteR(rounds);
            self.offset = 0;
        }

        /// Align the input to the rate boundary and permute.
        pub fn fillBlock(self: *Self) void {
            self.transition.to(.absorb);
            self.st.addBytes(self.buf[0..self.offset]);
            self.st.permuteR(rounds);
            self.offset = 0;
            self.transition.to(.updated);
        }

        /// Mark the end of the input.
        pub fn pad(self: *Self) void {
            self.transition.to(.absorb);
            self.st.addBytes(self.buf[0..self.offset]);
            if (self.offset == rate) {
                self.st.permuteR(rounds);
                self.offset = 0;
            }
            self.st.addByte(self.delim, self.offset);
            self.st.addByte(0x80, rate - 1);
            self.st.permuteR(rounds);
            self.offset = 0;
            self.transition.to(.updated);
        }

        /// Squeeze a slice of bytes from the sponge.
        /// The function can be called multiple times.
        pub fn squeeze(self: *Self, out: []u8) void {
            self.transition.to(.squeeze);
            var i: usize = 0;
            if (self.offset == rate) {
                self.st.permuteR(rounds);
            } else if (self.offset > 0) {
                @branchHint(.unlikely);
                var buf: [rate]u8 = undefined;
                self.st.extractBytes(buf[0..]);
                const left = @min(rate - self.offset, out.len);
                @memcpy(out[0..left], buf[self.offset..][0..left]);
                self.offset += left;
                if (left == out.len) return;
                if (self.offset == rate) {
                    self.offset = 0;
                    self.st.permuteR(rounds);
                }
                i = left;
            }
            while (i + rate < out.len) : (i += rate) {
                self.st.extractBytes(out[i..][0..rate]);
                self.st.permuteR(rounds);
            }
            const left = out.len - i;
            if (left > 0) {
                self.st.extractBytes(out[i..][0..left]);
            }
            self.offset = left;
        }
    };
}

test "Keccak-f800" {
    var st: KeccakF(800) = .{
        .st = .{
            0xE531D45D, 0xF404C6FB, 0x23A0BF99, 0xF1F8452F, 0x51FFD042, 0xE539F578, 0xF00B80A7,
            0xAF973664, 0xBF5AF34C, 0x227A2424, 0x88172715, 0x9F685884, 0xB15CD054, 0x1BF4FC0E,
            0x6166FA91, 0x1A9E599A, 0xA3970A1F, 0xAB659687, 0xAFAB8D68, 0xE74B1015, 0x34001A98,
            0x4119EFF3, 0x930A0E76, 0x87B28070, 0x11EFE996,
        },
    };
    st.permute();
    const expected: [25]u32 = .{
        0x75BF2D0D, 0x9B610E89, 0xC826AF40, 0x64CD84AB, 0xF905BDD6, 0xBC832835, 0x5F8001B9,
        0x15662CCE, 0x8E38C95E, 0x701FE543, 0x1B544380, 0x89ACDEFF, 0x51EDB5DE, 0x0E9702D9,
        0x6C19AA16, 0xA2913EEE, 0x60754E9A, 0x9819063C, 0xF4709254, 0xD09F9084, 0x772DA259,
        0x1DB35DF7, 0x5AA60162, 0x358825D5, 0xB3783BAB,
    };
    try std.testing.expectEqualSlices(u32, &st.st, &expected);
}

test "squeeze" {
    var st = State(800, 256, 22).init([_]u8{0x80} ** 100, 0x01);

    var out0: [15]u8 = undefined;
    var out1: [out0.len]u8 = undefined;
    st.permute();
    var st0 = st;
    st0.squeeze(out0[0..]);
    var st1 = st;
    st1.squeeze(out1[0 .. out1.len / 2]);
    st1.squeeze(out1[out1.len / 2 ..]);
    try std.testing.expectEqualSlices(u8, &out0, &out1);

    var out2: [100]u8 = undefined;
    var out3: [out2.len]u8 = undefined;
    var st2 = st;
    st2.squeeze(out2[0..]);
    var st3 = st;
    st3.squeeze(out3[0 .. out2.len / 2]);
    st3.squeeze(out3[out2.len / 2 ..]);
    try std.testing.expectEqualSlices(u8, &out2, &out3);
}
const std = @import("../std.zig");
const mem = std.mem;
const math = std.math;

const RoundParam = struct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    k: usize,
    s: u32,
    t: u32,
};

fn roundParam(a: usize, b: usize, c: usize, d: usize, k: usize, s: u32, t: u32) RoundParam {
    return RoundParam{
        .a = a,
        .b = b,
        .c = c,
        .d = d,
        .k = k,
        .s = s,
        .t = t,
    };
}

/// The MD5 function is now considered cryptographically broken.
/// Namely, it is trivial to find multiple inputs producing the same hash.
/// For a fast-performing, cryptographically secure hash function, see SHA512/256, BLAKE2 or BLAKE3.
pub const Md5 = struct {
    const Self = @This();
    pub const block_length = 64;
    pub const digest_length = 16;
    pub const Options = struct {};

    s: [4]u32,
    // Streaming Cache
    buf: [64]u8,
    buf_len: u8,
    total_len: u64,

    pub fn init(options: Options) Self {
        _ = options;
        return Self{
            .s = [_]u32{
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
            },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Md5.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

            d.round(&d.buf);
            d.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= b.len) : (off += 64) {
            d.round(b[off..][0..64]);
        }

        // Copy any remainder for next pass.
        const b_slice = b[off..];
        @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
        d.buf_len += @as(u8, @intCast(b_slice.len));

        // Md5 uses the bottom 64-bits for length padding
        d.total_len +%= b.len;
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        @memset(d.buf[d.buf_len..], 0);

        // Append padding bits.
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        // > 448 mod 512 so need to add an extra round to wrap around.
        if (64 - d.buf_len < 8) {
            d.round(d.buf[0..]);
            @memset(d.buf[0..], 0);
        }

        // Append message length.
        var i: usize = 1;
        var len = d.total_len >> 5;
        d.buf[56] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
        while (i < 8) : (i += 1) {
            d.buf[56 + i] = @as(u8, @intCast(len & 0xff));
            len >>= 8;
        }

        d.round(d.buf[0..]);

        for (d.s, 0..) |s, j| {
            mem.writeInt(u32, out[4 * j ..][0..4], s, .little);
        }
    }

    fn round(d: *Self, b: *const [64]u8) void {
        var s: [16]u32 = undefined;

        var i: usize = 0;
        while (i < 16) : (i += 1) {
            s[i] = mem.readInt(u32, b[i * 4 ..][0..4], .little);
        }

        var v: [4]u32 = [_]u32{
            d.s[0],
            d.s[1],
            d.s[2],
            d.s[3],
        };

        const round0 = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 0, 7, 0xD76AA478),
            roundParam(3, 0, 1, 2, 1, 12, 0xE8C7B756),
            roundParam(2, 3, 0, 1, 2, 17, 0x242070DB),
            roundParam(1, 2, 3, 0, 3, 22, 0xC1BDCEEE),
            roundParam(0, 1, 2, 3, 4, 7, 0xF57C0FAF),
            roundParam(3, 0, 1, 2, 5, 12, 0x4787C62A),
            roundParam(2, 3, 0, 1, 6, 17, 0xA8304613),
            roundParam(1, 2, 3, 0, 7, 22, 0xFD469501),
            roundParam(0, 1, 2, 3, 8, 7, 0x698098D8),
            roundParam(3, 0, 1, 2, 9, 12, 0x8B44F7AF),
            roundParam(2, 3, 0, 1, 10, 17, 0xFFFF5BB1),
            roundParam(1, 2, 3, 0, 11, 22, 0x895CD7BE),
            roundParam(0, 1, 2, 3, 12, 7, 0x6B901122),
            roundParam(3, 0, 1, 2, 13, 12, 0xFD987193),
            roundParam(2, 3, 0, 1, 14, 17, 0xA679438E),
            roundParam(1, 2, 3, 0, 15, 22, 0x49B40821),
        };
        inline for (round0) |r| {
            v[r.a] = v[r.a] +% (v[r.d] ^ (v[r.b] & (v[r.c] ^ v[r.d]))) +% r.t +% s[r.k];
            v[r.a] = v[r.b] +% math.rotl(u32, v[r.a], r.s);
        }

        const round1 = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 1, 5, 0xF61E2562),
            roundParam(3, 0, 1, 2, 6, 9, 0xC040B340),
            roundParam(2, 3, 0, 1, 11, 14, 0x265E5A51),
            roundParam(1, 2, 3, 0, 0, 20, 0xE9B6C7AA),
            roundParam(0, 1, 2, 3, 5, 5, 0xD62F105D),
            roundParam(3, 0, 1, 2, 10, 9, 0x02441453),
            roundParam(2, 3, 0, 1, 15, 14, 0xD8A1E681),
            roundParam(1, 2, 3, 0, 4, 20, 0xE7D3FBC8),
            roundParam(0, 1, 2, 3, 9, 5, 0x21E1CDE6),
            roundParam(3, 0, 1, 2, 14, 9, 0xC33707D6),
            roundParam(2, 3, 0, 1, 3, 14, 0xF4D50D87),
            roundParam(1, 2, 3, 0, 8, 20, 0x455A14ED),
            roundParam(0, 1, 2, 3, 13, 5, 0xA9E3E905),
            roundParam(3, 0, 1, 2, 2, 9, 0xFCEFA3F8),
            roundParam(2, 3, 0, 1, 7, 14, 0x676F02D9),
            roundParam(1, 2, 3, 0, 12, 20, 0x8D2A4C8A),
        };
        inline for (round1) |r| {
            v[r.a] = v[r.a] +% (v[r.c] ^ (v[r.d] & (v[r.b] ^ v[r.c]))) +% r.t +% s[r.k];
            v[r.a] = v[r.b] +% math.rotl(u32, v[r.a], r.s);
        }

        const round2 = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 5, 4, 0xFFFA3942),
            roundParam(3, 0, 1, 2, 8, 11, 0x8771F681),
            roundParam(2, 3, 0, 1, 11, 16, 0x6D9D6122),
            roundParam(1, 2, 3, 0, 14, 23, 0xFDE5380C),
            roundParam(0, 1, 2, 3, 1, 4, 0xA4BEEA44),
            roundParam(3, 0, 1, 2, 4, 11, 0x4BDECFA9),
            roundParam(2, 3, 0, 1, 7, 16, 0xF6BB4B60),
            roundParam(1, 2, 3, 0, 10, 23, 0xBEBFBC70),
            roundParam(0, 1, 2, 3, 13, 4, 0x289B7EC6),
            roundParam(3, 0, 1, 2, 0, 11, 0xEAA127FA),
            roundParam(2, 3, 0, 1, 3, 16, 0xD4EF3085),
            roundParam(1, 2, 3, 0, 6, 23, 0x04881D05),
            roundParam(0, 1, 2, 3, 9, 4, 0xD9D4D039),
            roundParam(3, 0, 1, 2, 12, 11, 0xE6DB99E5),
            roundParam(2, 3, 0, 1, 15, 16, 0x1FA27CF8),
            roundParam(1, 2, 3, 0, 2, 23, 0xC4AC5665),
        };
        inline for (round2) |r| {
            v[r.a] = v[r.a] +% (v[r.b] ^ v[r.c] ^ v[r.d]) +% r.t +% s[r.k];
            v[r.a] = v[r.b] +% math.rotl(u32, v[r.a], r.s);
        }

        const round3 = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 0, 6, 0xF4292244),
            roundParam(3, 0, 1, 2, 7, 10, 0x432AFF97),
            roundParam(2, 3, 0, 1, 14, 15, 0xAB9423A7),
            roundParam(1, 2, 3, 0, 5, 21, 0xFC93A039),
            roundParam(0, 1, 2, 3, 12, 6, 0x655B59C3),
            roundParam(3, 0, 1, 2, 3, 10, 0x8F0CCC92),
            roundParam(2, 3, 0, 1, 10, 15, 0xFFEFF47D),
            roundParam(1, 2, 3, 0, 1, 21, 0x85845DD1),
            roundParam(0, 1, 2, 3, 8, 6, 0x6FA87E4F),
            roundParam(3, 0, 1, 2, 15, 10, 0xFE2CE6E0),
            roundParam(2, 3, 0, 1, 6, 15, 0xA3014314),
            roundParam(1, 2, 3, 0, 13, 21, 0x4E0811A1),
            roundParam(0, 1, 2, 3, 4, 6, 0xF7537E82),
            roundParam(3, 0, 1, 2, 11, 10, 0xBD3AF235),
            roundParam(2, 3, 0, 1, 2, 15, 0x2AD7D2BB),
            roundParam(1, 2, 3, 0, 9, 21, 0xEB86D391),
        };
        inline for (round3) |r| {
            v[r.a] = v[r.a] +% (v[r.c] ^ (v[r.b] | ~v[r.d])) +% r.t +% s[r.k];
            v[r.a] = v[r.b] +% math.rotl(u32, v[r.a], r.s);
        }

        d.s[0] +%= v[0];
        d.s[1] +%= v[1];
        d.s[2] +%= v[2];
        d.s[3] +%= v[3];
    }
};

const htest = @import("test.zig");

test "single" {
    try htest.assertEqualHash(Md5, "d41d8cd98f00b204e9800998ecf8427e", "");
    try htest.assertEqualHash(Md5, "0cc175b9c0f1b6a831c399e269772661", "a");
    try htest.assertEqualHash(Md5, "900150983cd24fb0d6963f7d28e17f72", "abc");
    try htest.assertEqualHash(Md5, "f96b697d7cb7938d525a2f31aaf161d0", "message digest");
    try htest.assertEqualHash(Md5, "c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz");
    try htest.assertEqualHash(Md5, "d174ab98d277d9f5a5611c2c9f419d9f", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    try htest.assertEqualHash(Md5, "57edf4a22be3c955ac49da2e2107b67a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

test "streaming" {
    var h = Md5.init(.{});
    var out: [16]u8 = undefined;

    h.final(out[0..]);
    try htest.assertEqual("d41d8cd98f00b204e9800998ecf8427e", out[0..]);

    h = Md5.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual("900150983cd24fb0d6963f7d28e17f72", out[0..]);

    h = Md5.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);

    try htest.assertEqual("900150983cd24fb0d6963f7d28e17f72", out[0..]);
}

test "aligned final" {
    var block = [_]u8{0} ** Md5.block_length;
    var out: [Md5.digest_length]u8 = undefined;

    var h = Md5.init(.{});
    h.update(&block);
    h.final(out[0..]);
}
//! Implementation of the IND-CCA2 post-quantum secure key encapsulation mechanism (KEM)
//! ML-KEM (NIST FIPS-203 publication) and CRYSTALS-Kyber (v3.02/"draft00" CFRG draft).
//!
//! The namespace `d00` refers to the version currently implemented, in accordance with the CFRG draft.
//! The `nist` namespace refers to the FIPS-203 publication.
//!
//! Quoting from the CFRG I-D:
//!
//! Kyber is not a Diffie-Hellman (DH) style non-interactive key
//! agreement, but instead, Kyber is a Key Encapsulation Method (KEM).
//! In essence, a KEM is a Public-Key Encryption (PKE) scheme where the
//! plaintext cannot be specified, but is generated as a random key as
//! part of the encryption. A KEM can be transformed into an unrestricted
//! PKE using HPKE (RFC9180). On its own, a KEM can be used as a key
//! agreement method in TLS.
//!
//! Kyber is an IND-CCA2 secure KEM. It is constructed by applying a
//! Fujisaki--Okamato style transformation on InnerPKE, which is the
//! underlying IND-CPA secure Public Key Encryption scheme. We cannot
//! use InnerPKE directly, as its ciphertexts are malleable.
//!
//! ```
//!                     F.O. transform
//!     InnerPKE   ---------------------->   Kyber
//!     IND-CPA                              IND-CCA2
//! ```
//!
//! Kyber is a lattice-based scheme.  More precisely, its security is
//! based on the learning-with-errors-and-rounding problem in module
//! lattices (MLWER).  The underlying polynomial ring R (defined in
//! Section 5) is chosen such that multiplication is very fast using the
//! number theoretic transform (NTT, see Section 5.1.3).
//!
//! An InnerPKE private key is a vector _s_ over R of length k which is
//! _small_ in a particular way.  Here k is a security parameter akin to
//! the size of a prime modulus.  For Kyber512, which targets AES-128's
//! security level, the value of k is 2.
//!
//! The public key consists of two values:
//!
//! * _A_ a uniformly sampled k by k matrix over R _and_
//!
//! * _t = A s + e_, where e is a suitably small masking vector.
//!
//! Distinguishing between such A s + e and a uniformly sampled t is the
//! module learning-with-errors (MLWE) problem.  If that is hard, then it
//! is also hard to recover the private key from the public key as that
//! would allow you to distinguish between those two.
//!
//! To save space in the public key, A is recomputed deterministically
//! from a seed _rho_.
//!
//! A ciphertext for a message m under this public key is a pair (c_1,
//! c_2) computed roughly as follows:
//!
//! c_1 = Compress(A^T r + e_1, d_u)
//! c_2 = Compress(t^T r + e_2 + Decompress(m, 1), d_v)
//!
//! where
//!
//! * e_1, e_2 and r are small blinds;
//!
//! * Compress(-, d) removes some information, leaving d bits per
//!   coefficient and Decompress is such that Compress after Decompress
//!   does nothing and
//!
//! * d_u, d_v are scheme parameters.
//!
//! Distinguishing such a ciphertext and uniformly sampled (c_1, c_2) is
//! an example of the full MLWER problem, see section 4.4 of [KyberV302].
//!
//! To decrypt the ciphertext, one computes
//!
//! m = Compress(Decompress(c_2, d_v) - s^T Decompress(c_1, d_u), 1).
//!
//! It it not straight-forward to see that this formula is correct.  In
//! fact, there is negligible but non-zero probability that a ciphertext
//! does not decrypt correctly given by the DFP column in Table 4.  This
//! failure probability can be computed by a careful automated analysis
//! of the probabilities involved, see kyber_failure.py of [SecEst].
//!
//! [KyberV302](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
//! [I-D](https://github.com/bwesterb/draft-schwabe-cfrg-kyber)
//! [SecEst](https://github.com/pq-crystals/security-estimates)

// TODO
//
// - The bottleneck in Kyber are the various hash/xof calls:
//    - Optimize Zig's keccak implementation.
//    - Use SIMD to compute keccak in parallel.
// - Can we track bounds of coefficients using comptime types without
//   duplicating code?
// - Would be neater to have tests closer to the thing under test.
// - When generating a keypair, we have a copy of the inner public key with
//   its large matrix A in both the public key and the private key. In Go we
//   can just have a pointer in the private key to the public key, but
//   how do we do this elegantly in Zig?

const std = @import("std");
const builtin = @import("builtin");

const testing = std.testing;
const assert = std.debug.assert;
const crypto = std.crypto;
const errors = std.crypto.errors;
const math = std.math;
const mem = std.mem;
const RndGen = std.Random.DefaultPrng;
const sha3 = crypto.hash.sha3;

// Q is the parameter q ≡ 3329 = 2¹¹ + 2¹⁰ + 2⁸ + 1.
const Q: i16 = 3329;

// Montgomery R
const R: i32 = 1 << 16;

// Parameter n, degree of polynomials.
const N: usize = 256;

// Size of "small" vectors used in encryption blinds.
const eta2: u8 = 2;

const Params = struct {
    name: []const u8,

    // NIST ML-KEM variant instead of Kyber as originally submitted.
    ml_kem: bool = false,

    // Width and height of the matrix A.
    k: u8,

    // Size of "small" vectors used in private key and encryption blinds.
    eta1: u8,

    // How many bits to retain of u, the private-key independent part
    // of the ciphertext.
    du: u8,

    // How many bits to retain of v, the private-key dependent part
    // of the ciphertext.
    dv: u8,
};

pub const d00 = struct {
    pub const Kyber512 = Kyber(.{
        .name = "Kyber512",
        .k = 2,
        .eta1 = 3,
        .du = 10,
        .dv = 4,
    });

    pub const Kyber768 = Kyber(.{
        .name = "Kyber768",
        .k = 3,
        .eta1 = 2,
        .du = 10,
        .dv = 4,
    });

    pub const Kyber1024 = Kyber(.{
        .name = "Kyber1024",
        .k = 4,
        .eta1 = 2,
        .du = 11,
        .dv = 5,
    });
};

pub const nist = struct {
    pub const MLKem512 = Kyber(.{
        .name = "ML-KEM-512",
        .ml_kem = true,
        .k = 2,
        .eta1 = 3,
        .du = 10,
        .dv = 4,
    });

    pub const MLKem768 = Kyber(.{
        .name = "ML-KEM-768",
        .ml_kem = true,
        .k = 3,
        .eta1 = 2,
        .du = 10,
        .dv = 4,
    });

    pub const MLKem1024 = Kyber(.{
        .name = "ML-KEM-1024",
        .ml_kem = true,
        .k = 4,
        .eta1 = 2,
        .du = 11,
        .dv = 5,
    });
};

const modes = [_]type{
    d00.Kyber512,
    d00.Kyber768,
    d00.Kyber1024,
    nist.MLKem512,
    nist.MLKem768,
    nist.MLKem1024,
};
const h_length: usize = 32;
const inner_seed_length: usize = 32;
const common_encaps_seed_length: usize = 32;
const common_shared_key_size: usize = 32;

fn Kyber(comptime p: Params) type {
    return struct {
        // Size of a ciphertext, in bytes.
        pub const ciphertext_length = Poly.compressedSize(p.du) * p.k + Poly.compressedSize(p.dv);

        const Self = @This();
        const V = Vec(p.k);
        const M = Mat(p.k);

        /// Length (in bytes) of a shared secret.
        pub const shared_length = common_shared_key_size;
        /// Length (in bytes) of a seed for deterministic encapsulation.
        pub const encaps_seed_length = common_encaps_seed_length;
        /// Length (in bytes) of a seed for key generation.
        pub const seed_length: usize = inner_seed_length + shared_length;
        /// Algorithm name.
        pub const name = p.name;

        /// A shared secret, and an encapsulated (encrypted) representation of it.
        pub const EncapsulatedSecret = struct {
            shared_secret: [shared_length]u8,
            ciphertext: [ciphertext_length]u8,
        };

        /// A Kyber public key.
        pub const PublicKey = struct {
            pk: InnerPk,

            // Cached
            hpk: [h_length]u8, // H(pk)

            /// Size of a serialized representation of the key, in bytes.
            pub const bytes_length = InnerPk.bytes_length;

            /// Generates a shared secret, and encapsulates it for the public key.
            /// If `seed` is `null`, a random seed is used. This is recommended.
            /// If `seed` is set, encapsulation is deterministic.
            pub fn encaps(pk: PublicKey, seed_: ?[encaps_seed_length]u8) EncapsulatedSecret {
                var m: [inner_plaintext_length]u8 = undefined;

                if (seed_) |seed| {
                    if (p.ml_kem) {
                        @memcpy(&m, &seed);
                    } else {
                        // m = H(seed)
                        sha3.Sha3_256.hash(&seed, &m, .{});
                    }
                } else {
                    crypto.random.bytes(&m);
                }

                // (K', r) = G(m ‖ H(pk))
                var kr: [inner_plaintext_length + h_length]u8 = undefined;
                var g = sha3.Sha3_512.init(.{});
                g.update(&m);
                g.update(&pk.hpk);
                g.final(&kr);

                // c = innerEncrypt(pk, m, r)
                const ct = pk.pk.encrypt(&m, kr[32..64]);

                if (p.ml_kem) {
                    return EncapsulatedSecret{
                        .shared_secret = kr[0..shared_length].*, // ML-KEM: K = K'
                        .ciphertext = ct,
                    };
                } else {
                    // Compute H(c) and put in second slot of kr, which will be (K', H(c)).
                    sha3.Sha3_256.hash(&ct, kr[32..], .{});

                    var ss: [shared_length]u8 = undefined;
                    sha3.Shake256.hash(&kr, &ss, .{});
                    return EncapsulatedSecret{
                        .shared_secret = ss, // Kyber: K = KDF(K' ‖ H(c))
                        .ciphertext = ct,
                    };
                }
            }

            /// Serializes the key into a byte array.
            pub fn toBytes(pk: PublicKey) [bytes_length]u8 {
                return pk.pk.toBytes();
            }

            /// Deserializes the key from a byte array.
            pub fn fromBytes(buf: *const [bytes_length]u8) errors.NonCanonicalError!PublicKey {
                var ret: PublicKey = undefined;
                ret.pk = try InnerPk.fromBytes(buf[0..InnerPk.bytes_length]);
                sha3.Sha3_256.hash(buf, &ret.hpk, .{});
                return ret;
            }
        };

        /// A Kyber secret key.
        pub const SecretKey = struct {
            sk: InnerSk,
            pk: InnerPk,
            hpk: [h_length]u8, // H(pk)
            z: [shared_length]u8,

            /// Size of a serialized representation of the key, in bytes.
            pub const bytes_length: usize =
                InnerSk.bytes_length + InnerPk.bytes_length + h_length + shared_length;

            /// Decapsulates the shared secret within ct using the private key.
            pub fn decaps(sk: SecretKey, ct: *const [ciphertext_length]u8) ![shared_length]u8 {
                // m' = innerDec(ct)
                const m2 = sk.sk.decrypt(ct);

                // (K'', r') = G(m' ‖ H(pk))
                var kr2: [64]u8 = undefined;
                var g = sha3.Sha3_512.init(.{});
                g.update(&m2);
                g.update(&sk.hpk);
                g.final(&kr2);

                // ct' = innerEnc(pk, m', r')
                const ct2 = sk.pk.encrypt(&m2, kr2[32..64]);

                // Compute H(ct) and put in the second slot of kr2 which will be (K'', H(ct)).
                sha3.Sha3_256.hash(ct, kr2[32..], .{});

                // Replace K'' by z in the first slot of kr2 if ct ≠ ct'.
                cmov(32, kr2[0..32], sk.z, ctneq(ciphertext_length, ct.*, ct2));

                if (p.ml_kem) {
                    // ML-KEM: K = K''/z
                    return kr2[0..shared_length].*;
                } else {
                    // Kyber: K = KDF(K''/z ‖ H(c))
                    var ss: [shared_length]u8 = undefined;
                    sha3.Shake256.hash(&kr2, &ss, .{});
                    return ss;
                }
            }

            /// Serializes the key into a byte array.
            pub fn toBytes(sk: SecretKey) [bytes_length]u8 {
                return sk.sk.toBytes() ++ sk.pk.toBytes() ++ sk.hpk ++ sk.z;
            }

            /// Deserializes the key from a byte array.
            pub fn fromBytes(buf: *const [bytes_length]u8) errors.NonCanonicalError!SecretKey {
                var ret: SecretKey = undefined;
                comptime var s: usize = 0;
                ret.sk = InnerSk.fromBytes(buf[s .. s + InnerSk.bytes_length]);
                s += InnerSk.bytes_length;
                ret.pk = try InnerPk.fromBytes(buf[s .. s + InnerPk.bytes_length]);
                s += InnerPk.bytes_length;
                ret.hpk = buf[s..][0..h_length].*;
                s += h_length;
                ret.z = buf[s..][0..shared_length].*;
                return ret;
            }
        };

        /// A Kyber key pair.
        pub const KeyPair = struct {
            secret_key: SecretKey,
            public_key: PublicKey,

            /// Deterministically derive a key pair from a cryptograpically secure secret seed.
            ///
            /// Except in tests, applications should generally call `generate()` instead of this function.
            pub fn generateDeterministic(seed: [seed_length]u8) !KeyPair {
                var ret: KeyPair = undefined;
                ret.secret_key.z = seed[inner_seed_length..seed_length].*;

                // Generate inner key
                innerKeyFromSeed(
                    seed[0..inner_seed_length].*,
                    &ret.public_key.pk,
                    &ret.secret_key.sk,
                );
                ret.secret_key.pk = ret.public_key.pk;

                // Copy over z from seed.
                ret.secret_key.z = seed[inner_seed_length..seed_length].*;

                // Compute H(pk)
                sha3.Sha3_256.hash(&ret.public_key.pk.toBytes(), &ret.secret_key.hpk, .{});
                ret.public_key.hpk = ret.secret_key.hpk;

                return ret;
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
        };

        // Size of plaintexts of the in
        const inner_plaintext_length: usize = Poly.compressedSize(1);

        const InnerPk = struct {
            rho: [32]u8, // ρ, the seed for the matrix A
            th: V, // NTT(t), normalized

            // Cached values
            aT: M,

            const bytes_length = V.bytes_length + 32;

            fn encrypt(
                pk: InnerPk,
                pt: *const [inner_plaintext_length]u8,
                seed: *const [32]u8,
            ) [ciphertext_length]u8 {
                // Sample r, e₁ and e₂ appropriately
                const rh = V.noise(p.eta1, 0, seed).ntt().barrettReduce();
                const e1 = V.noise(eta2, p.k, seed);
                const e2 = Poly.noise(eta2, 2 * p.k, seed);

                // Next we compute u = Aᵀ r + e₁.  First Aᵀ.
                var u: V = undefined;
                for (0..p.k) |i| {
                    // Note that coefficients of r are bounded by q and those of Aᵀ
                    // are bounded by 4.5q and so their product is bounded by 2¹⁵q
                    // as required for multiplication.
                    u.ps[i] = pk.aT.vs[i].dotHat(rh);
                }

                // Aᵀ and r were not in Montgomery form, so the Montgomery
                // multiplications in the inner product added a factor R⁻¹ which
                // the InvNTT cancels out.
                u = u.barrettReduce().invNTT().add(e1).normalize();

                // Next, compute v = <t, r> + e₂ + Decompress_q(m, 1)
                const v = pk.th.dotHat(rh).barrettReduce().invNTT()
                    .add(Poly.decompress(1, pt)).add(e2).normalize();

                return u.compress(p.du) ++ v.compress(p.dv);
            }

            fn toBytes(pk: InnerPk) [bytes_length]u8 {
                return pk.th.toBytes() ++ pk.rho;
            }

            fn fromBytes(buf: *const [bytes_length]u8) errors.NonCanonicalError!InnerPk {
                var ret: InnerPk = undefined;

                const th_bytes = buf[0..V.bytes_length];
                ret.th = V.fromBytes(th_bytes).normalize();

                if (p.ml_kem) {
                    // Verify that the coefficients used a canonical representation.
                    if (!mem.eql(u8, &ret.th.toBytes(), th_bytes)) {
                        return error.NonCanonical;
                    }
                }

                ret.rho = buf[V.bytes_length..bytes_length].*;
                ret.aT = M.uniform(ret.rho, true);
                return ret;
            }
        };

        // Private key of the inner PKE
        const InnerSk = struct {
            sh: V, // NTT(s), normalized
            const bytes_length = V.bytes_length;

            fn decrypt(sk: InnerSk, ct: *const [ciphertext_length]u8) [inner_plaintext_length]u8 {
                const u = V.decompress(p.du, ct[0..comptime V.compressedSize(p.du)]);
                const v = Poly.decompress(
                    p.dv,
                    ct[comptime V.compressedSize(p.du)..ciphertext_length],
                );

                // Compute m = v - <s, u>
                return v.sub(sk.sh.dotHat(u.ntt()).barrettReduce().invNTT())
                    .normalize().compress(1);
            }

            fn toBytes(sk: InnerSk) [bytes_length]u8 {
                return sk.sh.toBytes();
            }

            fn fromBytes(buf: *const [bytes_length]u8) InnerSk {
                var ret: InnerSk = undefined;
                ret.sh = V.fromBytes(buf).normalize();
                return ret;
            }
        };

        // Derives inner PKE keypair from given seed.
        fn innerKeyFromSeed(seed: [inner_seed_length]u8, pk: *InnerPk, sk: *InnerSk) void {
            var expanded_seed: [64]u8 = undefined;
            var h = sha3.Sha3_512.init(.{});
            if (p.ml_kem) h.update(&[1]u8{p.k});
            h.update(&seed);
            h.final(&expanded_seed);
            pk.rho = expanded_seed[0..32].*;
            const sigma = expanded_seed[32..64];
            pk.aT = M.uniform(pk.rho, false); // Expand ρ to A; we'll transpose later on

            // Sample secret vector s.
            sk.sh = V.noise(p.eta1, 0, sigma).ntt().normalize();

            const eh = Vec(p.k).noise(p.eta1, p.k, sigma).ntt(); // sample blind e.
            var th: V = undefined;

            // Next, we compute t = A s + e.
            for (0..p.k) |i| {
                // Note that coefficients of s are bounded by q and those of A
                // are bounded by 4.5q and so their product is bounded by 2¹⁵q
                // as required for multiplication.
                // A and s were not in Montgomery form, so the Montgomery
                // multiplications in the inner product added a factor R⁻¹ which
                // we'll cancel out with toMont().  This will also ensure the
                // coefficients of th are bounded in absolute value by q.
                th.ps[i] = pk.aT.vs[i].dotHat(sk.sh).toMont();
            }

            pk.th = th.add(eh).normalize(); // bounded by 8q
            pk.aT = pk.aT.transpose();
        }
    };
}

// R mod q
const r_mod_q: i32 = @rem(@as(i32, R), Q);

// R² mod q
const r2_mod_q: i32 = @rem(r_mod_q * r_mod_q, Q);

// ζ is the degree 256 primitive root of unity used for the NTT.
const zeta: i16 = 17;

// (128)⁻¹ R². Used in inverse NTT.
const r2_over_128: i32 = @mod(invertMod(128, Q) * r2_mod_q, Q);

// zetas lists precomputed powers of the primitive root of unity in
// Montgomery representation used for the NTT:
//
//  zetas[i] = ζᵇʳᵛ⁽ⁱ⁾ R mod q
//
// where ζ = 17, brv(i) is the bitreversal of a 7-bit number and R=2¹⁶ mod q.
const zetas = computeZetas();

// invNTTReductions keeps track of which coefficients to apply Barrett
// reduction to in Poly.invNTT().
//
// Generated lazily: once a butterfly is computed which is about to
// overflow the i16, the largest coefficient is reduced.  If that is
// not enough, the other coefficient is reduced as well.
//
// This is actually optimal, as proven in https://eprint.iacr.org/2020/1377.pdf
// TODO generate comptime?
const inv_ntt_reductions = [_]i16{
    -1, // after layer 1
    -1, // after layer 2
    16,
    17,
    48,
    49,
    80,
    81,
    112,
    113,
    144,
    145,
    176,
    177,
    208,
    209,
    240, 241, -1, // after layer 3
    0,   1,   32,
    33,  34,  35,
    64,  65,  96,
    97,  98,  99,
    128, 129,
    160, 161, 162, 163, 192, 193, 224, 225, 226, 227, -1, // after layer 4
    2,   3,   66,  67,  68,  69,  70,  71,  130, 131, 194,
    195, 196, 197,
    198, 199, -1, // after layer 5
    4,   5,   6,
    7,   132, 133,
    134, 135, 136,
    137, 138, 139,
    140, 141,
    142, 143, -1, // after layer 6
    -1, //  after layer 7
};

test "invNTTReductions bounds" {
    // Checks whether the reductions proposed by invNTTReductions
    // don't overflow during invNTT().
    var xs = [_]i32{1} ** 256; // start at |x| ≤ q

    var r: usize = 0;
    var layer: math.Log2Int(usize) = 1;
    while (layer < 8) : (layer += 1) {
        const w = @as(usize, 1) << layer;
        var i: usize = 0;

        while (i + w < 256) {
            xs[i] = xs[i] + xs[i + w];
            try testing.expect(xs[i] <= 9); // we can't exceed 9q
            xs[i + w] = 1;
            i += 1;
            if (@mod(i, w) == 0) {
                i += w;
            }
        }

        while (true) {
            const j = inv_ntt_reductions[r];
            r += 1;
            if (j < 0) {
                break;
            }
            xs[@as(usize, @intCast(j))] = 1;
        }
    }
}

// Extended euclidean algorithm.
//
// For a, b finds x, y such that  x a + y b = gcd(a, b). Used to compute
// modular inverse.
fn eea(a: anytype, b: @TypeOf(a)) EeaResult(@TypeOf(a)) {
    if (a == 0) {
        return .{ .gcd = b, .x = 0, .y = 1 };
    }
    const r = eea(@rem(b, a), a);
    return .{ .gcd = r.gcd, .x = r.y - @divTrunc(b, a) * r.x, .y = r.x };
}

fn EeaResult(comptime T: type) type {
    return struct { gcd: T, x: T, y: T };
}

// Returns least common multiple of a and b.
fn lcm(a: anytype, b: @TypeOf(a)) @TypeOf(a) {
    const r = eea(a, b);
    return a * b / r.gcd;
}

// Invert modulo p.
fn invertMod(a: anytype, p: @TypeOf(a)) @TypeOf(a) {
    const r = eea(a, p);
    assert(r.gcd == 1);
    return r.x;
}

// Reduce mod q for testing.
fn modQ32(x: i32) i16 {
    var y = @as(i16, @intCast(@rem(x, @as(i32, Q))));
    if (y < 0) {
        y += Q;
    }
    return y;
}

// Given -2¹⁵ q ≤ x < 2¹⁵ q, returns -q < y < q with x 2⁻¹⁶ = y (mod q).
fn montReduce(x: i32) i16 {
    const qInv = comptime invertMod(@as(i32, Q), R);
    // This is Montgomery reduction with R=2¹⁶.
    //
    // Note gcd(2¹⁶, q) = 1 as q is prime.  Write q' := 62209 = q⁻¹ mod R.
    // First we compute
    //
    // m := ((x mod R) q') mod R
    //         = x q' mod R
    //    = int16(x q')
    //    = int16(int32(x) * int32(q'))
    //
    // Note that x q' might be as big as 2³² and could overflow the int32
    // multiplication in the last line.  However for any int32s a and b,
    // we have int32(int64(a)*int64(b)) = int32(a*b) and so the result is ok.
    const m: i16 = @truncate(@as(i32, @truncate(x *% qInv)));

    // Note that x - m q is divisible by R; indeed modulo R we have
    //
    //  x - m q ≡ x - x q' q ≡ x - x q⁻¹ q ≡ x - x = 0.
    //
    // We return y := (x - m q) / R.  Note that y is indeed correct as
    // modulo q we have
    //
    //  y ≡ x R⁻¹ - m q R⁻¹ = x R⁻¹
    //
    // and as both 2¹⁵ q ≤ m q, x < 2¹⁵ q, we have
    // 2¹⁶ q ≤ x - m q < 2¹⁶ and so q ≤ (x - m q) / R < q as desired.
    const yR = x - @as(i32, m) * @as(i32, Q);
    return @bitCast(@as(u16, @truncate(@as(u32, @bitCast(yR)) >> 16)));
}

test "Test montReduce" {
    var rnd = RndGen.init(0);
    for (0..1000) |_| {
        const bound = comptime @as(i32, Q) * (1 << 15);
        const x = rnd.random().intRangeLessThan(i32, -bound, bound);
        const y = montReduce(x);
        try testing.expect(-Q < y and y < Q);
        try testing.expectEqual(modQ32(x), modQ32(@as(i32, y) * R));
    }
}

// Given any x, return x R mod q where R=2¹⁶.
fn feToMont(x: i16) i16 {
    // Note |1353 x| ≤ 1353 2¹⁵ ≤ 13318 q ≤ 2¹⁵ q and so we're within
    // the bounds of montReduce.
    return montReduce(@as(i32, x) * r2_mod_q);
}

test "Test feToMont" {
    var x: i32 = -(1 << 15);
    while (x < 1 << 15) : (x += 1) {
        const y = feToMont(@as(i16, @intCast(x)));
        try testing.expectEqual(modQ32(@as(i32, y)), modQ32(x * r_mod_q));
    }
}

// Given any x, compute 0 ≤ y ≤ q with x = y (mod q).
//
// Beware: we might have feBarrettReduce(x) = q ≠ 0 for some x.  In fact,
// this happens if and only if x = -nq for some positive integer n.
fn feBarrettReduce(x: i16) i16 {
    // This is standard Barrett reduction.
    //
    // For any x we have x mod q = x - ⌊x/q⌋ q.  We will use 20159/2²⁶ as
    // an approximation of 1/q. Note that  0 ≤ 20159/2²⁶ - 1/q ≤ 0.135/2²⁶
    // and so | x 20156/2²⁶ - x/q | ≤ 2⁻¹⁰ for |x| ≤ 2¹⁶.  For all x
    // not a multiple of q, the number x/q is further than 1/q from any integer
    // and so ⌊x 20156/2²⁶⌋ = ⌊x/q⌋.  If x is a multiple of q and x is positive,
    // then x 20156/2²⁶ is larger than x/q so ⌊x 20156/2²⁶⌋ = ⌊x/q⌋ as well.
    // Finally, if x is negative multiple of q, then ⌊x 20156/2²⁶⌋ = ⌊x/q⌋-1.
    // Thus
    //                        [ q        if x=-nq for pos. integer n
```
