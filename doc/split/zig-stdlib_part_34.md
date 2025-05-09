```
    //  x - ⌊x 20156/2²⁶⌋ q = [
    //                        [ x mod q  otherwise
    //
    // To actually compute this, note that
    //
    //  ⌊x 20156/2²⁶⌋ = (20159 x) >> 26.
    return x -% @as(i16, @intCast((@as(i32, x) * 20159) >> 26)) *% Q;
}

test "Test Barrett reduction" {
    var x: i32 = -(1 << 15);
    while (x < 1 << 15) : (x += 1) {
        var y1 = feBarrettReduce(@as(i16, @intCast(x)));
        const y2 = @mod(@as(i16, @intCast(x)), Q);
        if (x < 0 and @rem(-x, Q) == 0) {
            y1 -= Q;
        }
        try testing.expectEqual(y1, y2);
    }
}

// Returns x if x < q and x - q otherwise.  Assumes x ≥ -29439.
fn csubq(x: i16) i16 {
    var r = x;
    r -= Q;
    r += (r >> 15) & Q;
    return r;
}

test "Test csubq" {
    var x: i32 = -29439;
    while (x < 1 << 15) : (x += 1) {
        const y1 = csubq(@as(i16, @intCast(x)));
        var y2 = @as(i16, @intCast(x));
        if (@as(i16, @intCast(x)) >= Q) {
            y2 -= Q;
        }
        try testing.expectEqual(y1, y2);
    }
}

// Compute a^s mod p.
fn mpow(a: anytype, s: @TypeOf(a), p: @TypeOf(a)) @TypeOf(a) {
    var ret: @TypeOf(a) = 1;
    var s2 = s;
    var a2 = a;

    while (true) {
        if (s2 & 1 == 1) {
            ret = @mod(ret * a2, p);
        }
        s2 >>= 1;
        if (s2 == 0) {
            break;
        }
        a2 = @mod(a2 * a2, p);
    }
    return ret;
}

// Computes zetas table used by ntt and invNTT.
fn computeZetas() [128]i16 {
    @setEvalBranchQuota(10000);
    var ret: [128]i16 = undefined;
    for (&ret, 0..) |*r, i| {
        const t = @as(i16, @intCast(mpow(@as(i32, zeta), @bitReverse(@as(u7, @intCast(i))), Q)));
        r.* = csubq(feBarrettReduce(feToMont(t)));
    }
    return ret;
}

// An element of our base ring R which are polynomials over ℤ_q
// modulo the equation Xᴺ = -1, where q=3329 and N=256.
//
// This type is also used to store NTT-transformed polynomials,
// see Poly.NTT().
//
// Coefficients aren't always reduced.  See Normalize().
const Poly = struct {
    cs: [N]i16,

    const bytes_length = N / 2 * 3;
    const zero: Poly = .{ .cs = .{0} ** N };

    fn add(a: Poly, b: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| {
            ret.cs[i] = a.cs[i] + b.cs[i];
        }
        return ret;
    }

    fn sub(a: Poly, b: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| {
            ret.cs[i] = a.cs[i] - b.cs[i];
        }
        return ret;
    }

    // For testing, generates a random polynomial with for each
    // coefficient |x| ≤ q.
    fn randAbsLeqQ(rnd: anytype) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| {
            ret.cs[i] = rnd.random().intRangeAtMost(i16, -Q, Q);
        }
        return ret;
    }

    // For testing, generates a random normalized polynomial.
    fn randNormalized(rnd: anytype) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| {
            ret.cs[i] = rnd.random().intRangeLessThan(i16, 0, Q);
        }
        return ret;
    }

    // Executes a forward "NTT" on p.
    //
    // Assumes the coefficients are in absolute value ≤q.  The resulting
    // coefficients are in absolute value ≤7q.  If the input is in Montgomery
    // form, then the result is in Montgomery form and so (by linearity of the NTT)
    // if the input is in regular form, then the result is also in regular form.
    fn ntt(a: Poly) Poly {
        // Note that ℤ_q does not have a primitive 512ᵗʰ root of unity (as 512
        // does not divide into q-1) and so we cannot do a regular NTT.  ℤ_q
        // does have a primitive 256ᵗʰ root of unity, the smallest of which
        // is ζ := 17.
        //
        // Recall that our base ring R := ℤ_q[x] / (x²⁵⁶ + 1).  The polynomial
        // x²⁵⁶+1 will not split completely (as its roots would be 512ᵗʰ roots
        // of unity.)  However, it does split almost (using ζ¹²⁸ = -1):
        //
        // x²⁵⁶ + 1 = (x²)¹²⁸ - ζ¹²⁸
        //          = ((x²)⁶⁴ - ζ⁶⁴)((x²)⁶⁴ + ζ⁶⁴)
        //          = ((x²)³² - ζ³²)((x²)³² + ζ³²)((x²)³² - ζ⁹⁶)((x²)³² + ζ⁹⁶)
        //          ⋮
        //          = (x² - ζ)(x² + ζ)(x² - ζ⁶⁵)(x² + ζ⁶⁵) … (x² + ζ¹²⁷)
        //
        // Note that the powers of ζ that appear (from the second line down) are
        // in binary
        //
        // 0100000 1100000
        // 0010000 1010000 0110000 1110000
        // 0001000 1001000 0101000 1101000 0011000 1011000 0111000 1111000
        //         …
        //
        // That is: brv(2), brv(3), brv(4), …, where brv(x) denotes the 7-bit
        // bitreversal of x.  These powers of ζ are given by the Zetas array.
        //
        // The polynomials x² ± ζⁱ are irreducible and coprime, hence by
        // the Chinese Remainder Theorem we know
        //
        //  ℤ_q[x]/(x²⁵⁶+1) → ℤ_q[x]/(x²-ζ) x … x  ℤ_q[x]/(x²+ζ¹²⁷)
        //
        // given by a ↦ ( a mod x²-ζ, …, a mod x²+ζ¹²⁷ )
        // is an isomorphism, which is the "NTT".  It can be efficiently computed by
        //
        //
        //  a ↦ ( a mod (x²)⁶⁴ - ζ⁶⁴, a mod (x²)⁶⁴ + ζ⁶⁴ )
        //    ↦ ( a mod (x²)³² - ζ³², a mod (x²)³² + ζ³²,
        //        a mod (x²)⁹⁶ - ζ⁹⁶, a mod (x²)⁹⁶ + ζ⁹⁶ )
        //
        //      et cetera
        // If N was 8 then this can be pictured in the following diagram:
        //
        //  https://cnx.org/resources/17ee4dfe517a6adda05377b25a00bf6e6c93c334/File0026.png
        //
        // Each cross is a Cooley-Tukey butterfly: it's the map
        //
        //  (a, b) ↦ (a + ζb, a - ζb)
        //
        // for the appropriate power ζ for that column and row group.
        var p = a;
        var k: usize = 0; // index into zetas

        var l = N >> 1;
        while (l > 1) : (l >>= 1) {
            // On the nᵗʰ iteration of the l-loop, the absolute value of the
            // coefficients are bounded by nq.

            // offset effectively loops over the row groups in this column; it is
            // the first row in the row group.
            var offset: usize = 0;
            while (offset < N - l) : (offset += 2 * l) {
                k += 1;
                const z = @as(i32, zetas[k]);

                // j loops over each butterfly in the row group.
                for (offset..offset + l) |j| {
                    const t = montReduce(z * @as(i32, p.cs[j + l]));
                    p.cs[j + l] = p.cs[j] - t;
                    p.cs[j] += t;
                }
            }
        }

        return p;
    }

    // Executes an inverse "NTT" on p and multiply by the Montgomery factor R.
    //
    // Assumes the coefficients are in absolute value ≤q.  The resulting
    // coefficients are in absolute value ≤q.  If the input is in Montgomery
    // form, then the result is in Montgomery form and so (by linearity)
    // if the input is in regular form, then the result is also in regular form.
    fn invNTT(a: Poly) Poly {
        var k: usize = 127; // index into zetas
        var r: usize = 0; // index into invNTTReductions
        var p = a;

        // We basically do the oppposite of NTT, but postpone dividing by 2 in the
        // inverse of the Cooley-Tukey butterfly and accumulate that into a big
        // division by 2⁷ at the end.  See the comments in the ntt() function.

        var l: usize = 2;
        while (l < N) : (l <<= 1) {
            var offset: usize = 0;
            while (offset < N - l) : (offset += 2 * l) {
                // As we're inverting, we need powers of ζ⁻¹ (instead of ζ).
                // To be precise, we need ζᵇʳᵛ⁽ᵏ⁾⁻¹²⁸. However, as ζ⁻¹²⁸ = -1,
                // we can use the existing zetas table instead of
                // keeping a separate invZetas table as in Dilithium.

                const minZeta = @as(i32, zetas[k]);
                k -= 1;

                for (offset..offset + l) |j| {
                    // Gentleman-Sande butterfly: (a, b) ↦ (a + b, ζ(a-b))
                    const t = p.cs[j + l] - p.cs[j];
                    p.cs[j] += p.cs[j + l];
                    p.cs[j + l] = montReduce(minZeta * @as(i32, t));

                    // Note that if we had |a| < αq and |b| < βq before the
                    // butterfly, then now we have |a| < (α+β)q and |b| < q.
                }
            }

            // We let the invNTTReductions instruct us which coefficients to
            // Barrett reduce.
            while (true) {
                const i = inv_ntt_reductions[r];
                r += 1;
                if (i < 0) {
                    break;
                }
                p.cs[@as(usize, @intCast(i))] = feBarrettReduce(p.cs[@as(usize, @intCast(i))]);
            }
        }

        for (0..N) |j| {
            // Note 1441 = (128)⁻¹ R².  The coefficients are bounded by 9q, so
            // as 1441 * 9 ≈ 2¹⁴ < 2¹⁵, we're within the required bounds
            // for montReduce().
            p.cs[j] = montReduce(r2_over_128 * @as(i32, p.cs[j]));
        }

        return p;
    }

    // Normalizes coefficients.
    //
    // Ensures each coefficient is in {0, …, q-1}.
    fn normalize(a: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| {
            ret.cs[i] = csubq(feBarrettReduce(a.cs[i]));
        }
        return ret;
    }

    // Put p in Montgomery form.
    fn toMont(a: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| {
            ret.cs[i] = feToMont(a.cs[i]);
        }
        return ret;
    }

    // Barret reduce coefficients.
    //
    // Beware, this does not fully normalize coefficients.
    fn barrettReduce(a: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| {
            ret.cs[i] = feBarrettReduce(a.cs[i]);
        }
        return ret;
    }

    fn compressedSize(comptime d: u8) usize {
        return @divTrunc(N * d, 8);
    }

    // Returns packed Compress_q(p, d).
    //
    // Assumes p is normalized.
    fn compress(p: Poly, comptime d: u8) [compressedSize(d)]u8 {
        @setEvalBranchQuota(10000);
        const q_over_2: u32 = comptime @divTrunc(Q, 2); // (q-1)/2
        const two_d_min_1: u32 = comptime (1 << d) - 1; // 2ᵈ-1
        var in_off: usize = 0;
        var out_off: usize = 0;

        const batch_size: usize = comptime lcm(@as(i16, d), 8);
        const in_batch_size: usize = comptime batch_size / d;
        const out_batch_size: usize = comptime batch_size / 8;

        const out_length: usize = comptime @divTrunc(N * d, 8);
        comptime assert(out_length * 8 == d * N);
        var out = [_]u8{0} ** out_length;

        while (in_off < N) {
            // First we compress into in.
            var in: [in_batch_size]u16 = undefined;
            inline for (0..in_batch_size) |i| {
                // Compress_q(x, d) = ⌈(2ᵈ/q)x⌋ mod⁺ 2ᵈ
                //                  = ⌊(2ᵈ/q)x+½⌋ mod⁺ 2ᵈ
                //                  = ⌊((x << d) + q/2) / q⌋ mod⁺ 2ᵈ
                //                  = DIV((x << d) + q/2, q) & ((1<<d) - 1)
                const t = @as(u24, @intCast(p.cs[in_off + i])) << d;
                // Division by invariant multiplication, equivalent to DIV(t + q/2, q).
                // A division may not be a constant-time operation, even with a constant denominator.
                // Here, side channels would leak information about the shared secret, see https://kyberslash.cr.yp.to
                // Multiplication, on the other hand, is a constant-time operation on the CPUs we currently support.
                comptime assert(d <= 11);
                comptime assert(((20642679 * @as(u64, Q)) >> 36) == 1);
                const u: u32 = @intCast((@as(u64, t + q_over_2) * 20642679) >> 36);
                in[i] = @intCast(u & two_d_min_1);
            }

            // Now we pack the d-bit integers from `in' into out as bytes.
            comptime var in_shift: usize = 0;
            comptime var j: usize = 0;
            comptime var i: usize = 0;
            inline while (i < in_batch_size) : (j += 1) {
                comptime var todo: usize = 8;
                inline while (todo > 0) {
                    const out_shift = comptime 8 - todo;
                    out[out_off + j] |= @as(u8, @truncate((in[i] >> in_shift) << out_shift));

                    const done = comptime @min(@min(d, todo), d - in_shift);
                    todo -= done;
                    in_shift += done;

                    if (in_shift == d) {
                        in_shift = 0;
                        i += 1;
                    }
                }
            }

            in_off += in_batch_size;
            out_off += out_batch_size;
        }

        return out;
    }

    // Set p to Decompress_q(m, d).
    fn decompress(comptime d: u8, in: *const [compressedSize(d)]u8) Poly {
        @setEvalBranchQuota(10000);
        const in_len = comptime @divTrunc(N * d, 8);
        comptime assert(in_len * 8 == d * N);
        var ret: Poly = undefined;
        var in_off: usize = 0;
        var out_off: usize = 0;

        const batch_size: usize = comptime lcm(@as(i16, d), 8);
        const in_batch_size: usize = comptime batch_size / 8;
        const out_batch_size: usize = comptime batch_size / d;

        while (out_off < N) {
            comptime var in_shift: usize = 0;
            comptime var j: usize = 0;
            comptime var i: usize = 0;
            inline while (i < out_batch_size) : (i += 1) {
                // First, unpack next coefficient.
                comptime var todo = d;
                var out: u16 = 0;

                inline while (todo > 0) {
                    const out_shift = comptime d - todo;
                    const m = comptime (1 << d) - 1;
                    out |= (@as(u16, in[in_off + j] >> in_shift) << out_shift) & m;

                    const done = comptime @min(@min(8, todo), 8 - in_shift);
                    todo -= done;
                    in_shift += done;

                    if (in_shift == 8) {
                        in_shift = 0;
                        j += 1;
                    }
                }

                // Decompress_q(x, d) = ⌈(q/2ᵈ)x⌋
                //                    = ⌊(q/2ᵈ)x+½⌋
                //                    = ⌊(qx + 2ᵈ⁻¹)/2ᵈ⌋
                //                    = (qx + (1<<(d-1))) >> d
                const qx = @as(u32, out) * @as(u32, Q);
                ret.cs[out_off + i] = @as(i16, @intCast((qx + (1 << (d - 1))) >> d));
            }

            in_off += in_batch_size;
            out_off += out_batch_size;
        }

        return ret;
    }

    // Returns the "pointwise" multiplication a o b.
    //
    // That is: invNTT(a o b) = invNTT(a) * invNTT(b).  Assumes a and b are in
    // Montgomery form.  Products between coefficients of a and b must be strictly
    // bounded in absolute value by 2¹⁵q.  a o b will be in Montgomery form and
    // bounded in absolute value by 2q.
    fn mulHat(a: Poly, b: Poly) Poly {
        // Recall from the discussion in ntt(), that a transformed polynomial is
        // an element of ℤ_q[x]/(x²-ζ) x … x  ℤ_q[x]/(x²+ζ¹²⁷);
        // that is: 128 degree-one polynomials instead of simply 256 elements
        // from ℤ_q as in the regular NTT.  So instead of pointwise multiplication,
        // we multiply the 128 pairs of degree-one polynomials modulo the
        // right equation:
        //
        //  (a₁ + a₂x)(b₁ + b₂x) = a₁b₁ + a₂b₂ζ' + (a₁b₂ + a₂b₁)x,
        //
        // where ζ' is the appropriate power of ζ.

        var p: Poly = undefined;
        var k: usize = 64;
        var i: usize = 0;
        while (i < N) : (i += 4) {
            const z = @as(i32, zetas[k]);
            k += 1;

            const a1b1 = montReduce(@as(i32, a.cs[i + 1]) * @as(i32, b.cs[i + 1]));
            const a0b0 = montReduce(@as(i32, a.cs[i]) * @as(i32, b.cs[i]));
            const a1b0 = montReduce(@as(i32, a.cs[i + 1]) * @as(i32, b.cs[i]));
            const a0b1 = montReduce(@as(i32, a.cs[i]) * @as(i32, b.cs[i + 1]));

            p.cs[i] = montReduce(a1b1 * z) + a0b0;
            p.cs[i + 1] = a0b1 + a1b0;

            const a3b3 = montReduce(@as(i32, a.cs[i + 3]) * @as(i32, b.cs[i + 3]));
            const a2b2 = montReduce(@as(i32, a.cs[i + 2]) * @as(i32, b.cs[i + 2]));
            const a3b2 = montReduce(@as(i32, a.cs[i + 3]) * @as(i32, b.cs[i + 2]));
            const a2b3 = montReduce(@as(i32, a.cs[i + 2]) * @as(i32, b.cs[i + 3]));

            p.cs[i + 2] = a2b2 - montReduce(a3b3 * z);
            p.cs[i + 3] = a2b3 + a3b2;
        }

        return p;
    }

    // Sample p from a centered binomial distribution with n=2η and p=½ - viz:
    // coefficients are in {-η, …, η} with probabilities
    //
    //  {ncr(0, 2η)/2^2η, ncr(1, 2η)/2^2η, …, ncr(2η,2η)/2^2η}
    fn noise(comptime eta: u8, nonce: u8, seed: *const [32]u8) Poly {
        var h = sha3.Shake256.init(.{});
        const suffix: [1]u8 = .{nonce};
        h.update(seed);
        h.update(&suffix);

        // The distribution at hand is exactly the same as that
        // of (a₁ + a₂ + … + a_η) - (b₁ + … + b_η) where a_i,b_i~U(1).
        // Thus we need 2η bits per coefficient.
        const buf_len = comptime 2 * eta * N / 8;
        var buf: [buf_len]u8 = undefined;
        h.squeeze(&buf);

        // buf is interpreted as a₁…a_ηb₁…b_ηa₁…a_ηb₁…b_η…. We process
        // multiple coefficients in one batch.

        const T = switch (builtin.target.cpu.arch) {
            .x86_64, .x86 => u32, // Generates better code on Intel CPUs
            else => u64, // u128 might be faster on some other CPUs.
        };

        comptime var batch_count: usize = undefined;
        comptime var batch_bytes: usize = undefined;
        comptime var mask: T = 0;
        comptime {
            batch_count = @bitSizeOf(T) / @as(usize, 2 * eta);
            while (@rem(N, batch_count) != 0 and batch_count > 0) : (batch_count -= 1) {}
            assert(batch_count > 0);
            assert(@rem(2 * eta * batch_count, 8) == 0);
            batch_bytes = 2 * eta * batch_count / 8;

            for (0..2 * eta * batch_count) |_| {
                mask <<= eta;
                mask |= 1;
            }
        }

        var ret: Poly = undefined;
        for (0..comptime N / batch_count) |i| {
            // Read coefficients into t. In the case of η=3,
            // we have t = a₁ + 2a₂ + 4a₃ + 8b₁ + 16b₂ + …
            var t: T = 0;
            inline for (0..batch_bytes) |j| {
                t |= @as(T, buf[batch_bytes * i + j]) << (8 * j);
            }

            // Accumulate `a's and `b's together by masking them out, shifting
            // and adding. For η=3, we have  d = a₁ + a₂ + a₃ + 8(b₁ + b₂ + b₃) + …
            var d: T = 0;
            inline for (0..eta) |j| {
                d += (t >> j) & mask;
            }

            // Extract each a and b separately and set coefficient in polynomial.
            inline for (0..batch_count) |j| {
                const mask2 = comptime (1 << eta) - 1;
                const a = @as(i16, @intCast((d >> (comptime (2 * j * eta))) & mask2));
                const b = @as(i16, @intCast((d >> (comptime ((2 * j + 1) * eta))) & mask2));
                ret.cs[batch_count * i + j] = a - b;
            }
        }

        return ret;
    }

    // Sample p uniformly from the given seed and x and y coordinates.
    fn uniform(seed: [32]u8, x: u8, y: u8) Poly {
        var h = sha3.Shake128.init(.{});
        const suffix: [2]u8 = .{ x, y };
        h.update(&seed);
        h.update(&suffix);

        const buf_len = sha3.Shake128.block_length; // rate SHAKE-128
        var buf: [buf_len]u8 = undefined;

        var ret: Poly = undefined;
        var i: usize = 0; // index into ret.cs
        outer: while (true) {
            h.squeeze(&buf);

            var j: usize = 0; // index into buf
            while (j < buf_len) : (j += 3) {
                const b0 = @as(u16, buf[j]);
                const b1 = @as(u16, buf[j + 1]);
                const b2 = @as(u16, buf[j + 2]);

                const ts: [2]u16 = .{
                    b0 | ((b1 & 0xf) << 8),
                    (b1 >> 4) | (b2 << 4),
                };

                inline for (ts) |t| {
                    if (t < Q) {
                        ret.cs[i] = @as(i16, @intCast(t));
                        i += 1;

                        if (i == N) {
                            break :outer;
                        }
                    }
                }
            }
        }

        return ret;
    }

    // Packs p.
    //
    // Assumes p is normalized (and not just Barrett reduced).
    fn toBytes(p: Poly) [bytes_length]u8 {
        var ret: [bytes_length]u8 = undefined;
        for (0..comptime N / 2) |i| {
            const t0 = @as(u16, @intCast(p.cs[2 * i]));
            const t1 = @as(u16, @intCast(p.cs[2 * i + 1]));
            ret[3 * i] = @as(u8, @truncate(t0));
            ret[3 * i + 1] = @as(u8, @truncate((t0 >> 8) | (t1 << 4)));
            ret[3 * i + 2] = @as(u8, @truncate(t1 >> 4));
        }
        return ret;
    }

    // Unpacks a Poly from buf.
    //
    // p will not be normalized; instead 0 ≤ p[i] < 4096.
    fn fromBytes(buf: *const [bytes_length]u8) Poly {
        var ret: Poly = undefined;
        for (0..comptime N / 2) |i| {
            const b0 = @as(i16, buf[3 * i]);
            const b1 = @as(i16, buf[3 * i + 1]);
            const b2 = @as(i16, buf[3 * i + 2]);
            ret.cs[2 * i] = b0 | ((b1 & 0xf) << 8);
            ret.cs[2 * i + 1] = (b1 >> 4) | b2 << 4;
        }
        return ret;
    }
};

// A vector of K polynomials.
fn Vec(comptime K: u8) type {
    return struct {
        ps: [K]Poly,

        const Self = @This();
        const bytes_length = K * Poly.bytes_length;

        fn compressedSize(comptime d: u8) usize {
            return Poly.compressedSize(d) * K;
        }

        fn ntt(a: Self) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                ret.ps[i] = a.ps[i].ntt();
            }
            return ret;
        }

        fn invNTT(a: Self) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                ret.ps[i] = a.ps[i].invNTT();
            }
            return ret;
        }

        fn normalize(a: Self) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                ret.ps[i] = a.ps[i].normalize();
            }
            return ret;
        }

        fn barrettReduce(a: Self) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                ret.ps[i] = a.ps[i].barrettReduce();
            }
            return ret;
        }

        fn add(a: Self, b: Self) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                ret.ps[i] = a.ps[i].add(b.ps[i]);
            }
            return ret;
        }

        fn sub(a: Self, b: Self) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                ret.ps[i] = a.ps[i].sub(b.ps[i]);
            }
            return ret;
        }

        // Samples v[i] from centered binomial distribution with the given η,
        // seed and nonce+i.
        fn noise(comptime eta: u8, nonce: u8, seed: *const [32]u8) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                ret.ps[i] = Poly.noise(eta, nonce + @as(u8, @intCast(i)), seed);
            }
            return ret;
        }

        // Sets p to the inner product of a and b using "pointwise" multiplication.
        //
        // See MulHat() and NTT() for a description of the multiplication.
        // Assumes a and b are in Montgomery form.  p will be in Montgomery form,
        // and its coefficients will be bounded in absolute value by 2kq.
        // If a and b are not in Montgomery form, then the action is the same
        // as "pointwise" multiplication followed by multiplying by R⁻¹, the inverse
        // of the Montgomery factor.
        fn dotHat(a: Self, b: Self) Poly {
            var ret: Poly = Poly.zero;
            for (0..K) |i| {
                ret = ret.add(a.ps[i].mulHat(b.ps[i]));
            }
            return ret;
        }

        fn compress(v: Self, comptime d: u8) [compressedSize(d)]u8 {
            const cs = comptime Poly.compressedSize(d);
            var ret: [compressedSize(d)]u8 = undefined;
            inline for (0..K) |i| {
                ret[i * cs .. (i + 1) * cs].* = v.ps[i].compress(d);
            }
            return ret;
        }

        fn decompress(comptime d: u8, buf: *const [compressedSize(d)]u8) Self {
            const cs = comptime Poly.compressedSize(d);
            var ret: Self = undefined;
            inline for (0..K) |i| {
                ret.ps[i] = Poly.decompress(d, buf[i * cs .. (i + 1) * cs]);
            }
            return ret;
        }

        /// Serializes the key into a byte array.
        fn toBytes(v: Self) [bytes_length]u8 {
            var ret: [bytes_length]u8 = undefined;
            inline for (0..K) |i| {
                ret[i * Poly.bytes_length .. (i + 1) * Poly.bytes_length].* = v.ps[i].toBytes();
            }
            return ret;
        }

        /// Deserializes the key from a byte array.
        fn fromBytes(buf: *const [bytes_length]u8) Self {
            var ret: Self = undefined;
            inline for (0..K) |i| {
                ret.ps[i] = Poly.fromBytes(
                    buf[i * Poly.bytes_length .. (i + 1) * Poly.bytes_length],
                );
            }
            return ret;
        }
    };
}

// A matrix of K vectors
fn Mat(comptime K: u8) type {
    return struct {
        const Self = @This();
        vs: [K]Vec(K),

        fn uniform(seed: [32]u8, comptime transposed: bool) Self {
            var ret: Self = undefined;
            var i: u8 = 0;
            while (i < K) : (i += 1) {
                var j: u8 = 0;
                while (j < K) : (j += 1) {
                    ret.vs[i].ps[j] = Poly.uniform(
                        seed,
                        if (transposed) i else j,
                        if (transposed) j else i,
                    );
                }
            }
            return ret;
        }

        // Returns transpose of A
        fn transpose(m: Self) Self {
            var ret: Self = undefined;
            for (0..K) |i| {
                for (0..K) |j| {
                    ret.vs[i].ps[j] = m.vs[j].ps[i];
                }
            }
            return ret;
        }
    };
}

// Returns `true` if a ≠ b.
fn ctneq(comptime len: usize, a: [len]u8, b: [len]u8) u1 {
    return 1 - @intFromBool(crypto.timing_safe.eql([len]u8, a, b));
}

// Copy src into dst given b = 1.
fn cmov(comptime len: usize, dst: *[len]u8, src: [len]u8, b: u1) void {
    const mask = @as(u8, 0) -% b;
    for (0..len) |i| {
        dst[i] ^= mask & (dst[i] ^ src[i]);
    }
}

test "MulHat" {
    var rnd = RndGen.init(0);

    for (0..100) |_| {
        const a = Poly.randAbsLeqQ(&rnd);
        const b = Poly.randAbsLeqQ(&rnd);

        const p2 = a.ntt().mulHat(b.ntt()).barrettReduce().invNTT().normalize();
        var p: Poly = undefined;

        @memset(&p.cs, 0);

        for (0..N) |i| {
            for (0..N) |j| {
                var v = montReduce(@as(i32, a.cs[i]) * @as(i32, b.cs[j]));
                var k = i + j;
                if (k >= N) {
                    // Recall Xᴺ = -1.
                    k -= N;
                    v = -v;
                }
                p.cs[k] = feBarrettReduce(v + p.cs[k]);
            }
        }

        p = p.toMont().normalize();

        try testing.expectEqual(p, p2);
    }
}

test "NTT" {
    var rnd = RndGen.init(0);

    for (0..1000) |_| {
        var p = Poly.randAbsLeqQ(&rnd);
        const q = p.toMont().normalize();
        p = p.ntt();

        for (0..N) |i| {
            try testing.expect(p.cs[i] <= 7 * Q and -7 * Q <= p.cs[i]);
        }

        p = p.normalize().invNTT();
        for (0..N) |i| {
            try testing.expect(p.cs[i] <= Q and -Q <= p.cs[i]);
        }

        p = p.normalize();

        try testing.expectEqual(p, q);
    }
}

test "Compression" {
    var rnd = RndGen.init(0);
    inline for (.{ 1, 4, 5, 10, 11 }) |d| {
        for (0..1000) |_| {
            const p = Poly.randNormalized(&rnd);
            const pp = p.compress(d);
            const pq = Poly.decompress(d, &pp).compress(d);
            try testing.expectEqual(pp, pq);
        }
    }
}

test "noise" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*s, i| {
        s.* = @as(u8, @intCast(i));
    }
    try testing.expectEqual(Poly.noise(3, 37, &seed).cs, .{
        0,  0,  1,  -1, 0,  2,  0,  -1, -1, 3,  0,  1,  -2, -2, 0,  1,  -2,
        1,  0,  -2, 3,  0,  0,  0,  1,  3,  1,  1,  2,  1,  -1, -1, -1, 0,
        1,  0,  1,  0,  2,  0,  1,  -2, 0,  -1, -1, -2, 1,  -1, -1, 2,  -1,
        1,  1,  2,  -3, -1, -1, 0,  0,  0,  0,  1,  -1, -2, -2, 0,  -2, 0,
        0,  0,  1,  0,  -1, -1, 1,  -2, 2,  0,  0,  2,  -2, 0,  1,  0,  1,
        1,  1,  0,  1,  -2, -1, -2, -1, 1,  0,  0,  0,  0,  0,  1,  0,  -1,
        -1, 0,  -1, 1,  0,  1,  0,  -1, -1, 0,  -2, 2,  0,  -2, 1,  -1, 0,
        1,  -1, -1, 2,  1,  0,  0,  -2, -1, 2,  0,  0,  0,  -1, -1, 3,  1,
        0,  1,  0,  1,  0,  2,  1,  0,  0,  1,  0,  1,  0,  0,  -1, -1, -1,
        0,  1,  3,  1,  0,  1,  0,  1,  -1, -1, -1, -1, 0,  0,  -2, -1, -1,
        2,  0,  1,  0,  1,  0,  2,  -2, 0,  1,  1,  -3, -1, -2, -1, 0,  1,
        0,  1,  -2, 2,  2,  1,  1,  0,  -1, 0,  -1, -1, 1,  0,  -1, 2,  1,
        -1, 1,  2,  -2, 1,  2,  0,  1,  2,  1,  0,  0,  2,  1,  2,  1,  0,
        2,  1,  0,  0,  -1, -1, 1,  -1, 0,  1,  -1, 2,  2,  0,  0,  -1, 1,
        1,  1,  1,  0,  0,  -2, 0,  -1, 1,  2,  0,  0,  1,  1,  -1, 1,  0,
        1,
    });
    try testing.expectEqual(Poly.noise(2, 37, &seed).cs, .{
        1,  0,  1,  -1, -1, -2, -1, -1, 2,  0,  -1, 0,  0,  -1,
        1,  1,  -1, 1,  0,  2,  -2, 0,  1,  2,  0,  0,  -1, 1,
        0,  -1, 1,  -1, 1,  2,  1,  1,  0,  -1, 1,  -1, -2, -1,
        1,  -1, -1, -1, 2,  -1, -1, 0,  0,  1,  1,  -1, 1,  1,
        1,  1,  -1, -2, 0,  1,  0,  0,  2,  1,  -1, 2,  0,  0,
        1,  1,  0,  -1, 0,  0,  -1, -1, 2,  0,  1,  -1, 2,  -1,
        -1, -1, -1, 0,  -2, 0,  2,  1,  0,  0,  0,  -1, 0,  0,
        0,  -1, -1, 0,  -1, -1, 0,  -1, 0,  0,  -2, 1,  1,  0,
        1,  0,  1,  0,  1,  1,  -1, 2,  0,  1,  -1, 1,  2,  0,
        0,  0,  0,  -1, -1, -1, 0,  1,  0,  -1, 2,  0,  0,  1,
        1,  1,  0,  1,  -1, 1,  2,  1,  0,  2,  -1, 1,  -1, -2,
        -1, -2, -1, 1,  0,  -2, -2, -1, 1,  0,  0,  0,  0,  1,
        0,  0,  0,  2,  2,  0,  1,  0,  -1, -1, 0,  2,  0,  0,
        -2, 1,  0,  2,  1,  -1, -2, 0,  0,  -1, 1,  1,  0,  0,
        2,  0,  1,  1,  -2, 1,  -2, 1,  1,  0,  2,  0,  -1, 0,
        -1, 0,  1,  2,  0,  1,  0,  -2, 1,  -2, -2, 1,  -1, 0,
        -1, 1,  1,  0,  0,  0,  1,  0,  -1, 1,  1,  0,  0,  0,
        0,  1,  0,  1,  -1, 0,  1,  -1, -1, 2,  0,  0,  1,  -1,
        0,  1,  -1, 0,
    });
}

test "uniform sampling" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*s, i| {
        s.* = @as(u8, @intCast(i));
    }
    try testing.expectEqual(Poly.uniform(seed, 1, 0).cs, .{
        797,  993,  161,  6,    2608, 2385, 2096, 2661, 1676, 247,  2440,
        342,  634,  194,  1570, 2848, 986,  684,  3148, 3208, 2018, 351,
        2288, 612,  1394, 170,  1521, 3119, 58,   596,  2093, 1549, 409,
        2156, 1934, 1730, 1324, 388,  446,  418,  1719, 2202, 1812, 98,
        1019, 2369, 214,  2699, 28,   1523, 2824, 273,  402,  2899, 246,
        210,  1288, 863,  2708, 177,  3076, 349,  44,   949,  854,  1371,
        957,  292,  2502, 1617, 1501, 254,  7,    1761, 2581, 2206, 2655,
        1211, 629,  1274, 2358, 816,  2766, 2115, 2985, 1006, 2433, 856,
        2596, 3192, 1,    1378, 2345, 707,  1891, 1669, 536,  1221, 710,
        2511, 120,  1176, 322,  1897, 2309, 595,  2950, 1171, 801,  1848,
        695,  2912, 1396, 1931, 1775, 2904, 893,  2507, 1810, 2873, 253,
        1529, 1047, 2615, 1687, 831,  1414, 965,  3169, 1887, 753,  3246,
        1937, 115,  2953, 586,  545,  1621, 1667, 3187, 1654, 1988, 1857,
        512,  1239, 1219, 898,  3106, 391,  1331, 2228, 3169, 586,  2412,
        845,  768,  156,  662,  478,  1693, 2632, 573,  2434, 1671, 173,
        969,  364,  1663, 2701, 2169, 813,  1000, 1471, 720,  2431, 2530,
        3161, 733,  1691, 527,  2634, 335,  26,   2377, 1707, 767,  3020,
        950,  502,  426,  1138, 3208, 2607, 2389, 44,   1358, 1392, 2334,
        875,  2097, 173,  1697, 2578, 942,  1817, 974,  1165, 2853, 1958,
        2973, 3282, 271,  1236, 1677, 2230, 673,  1554, 96,   242,  1729,
        2518, 1884, 2272, 71,   1382, 924,  1807, 1610, 456,  1148, 2479,
        2152, 238,  2208, 2329, 713,  1175, 1196, 757,  1078, 3190, 3169,
        708,  3117, 154,  1751, 3225, 1364, 154,  23,   2842, 1105, 1419,
        79,   5,    2013,
    });
}

test "Polynomial packing" {
    var rnd = RndGen.init(0);

    for (0..1000) |_| {
        const p = Poly.randNormalized(&rnd);
        try testing.expectEqual(Poly.fromBytes(&p.toBytes()), p);
    }
}

test "Test inner PKE" {
    var seed: [32]u8 = undefined;
    var pt: [32]u8 = undefined;
    for (&seed, &pt, 0..) |*s, *p, i| {
        s.* = @as(u8, @intCast(i));
        p.* = @as(u8, @intCast(i + 32));
    }
    inline for (modes) |mode| {
        for (0..10) |i| {
            var pk: mode.InnerPk = undefined;
            var sk: mode.InnerSk = undefined;
            seed[0] = @as(u8, @intCast(i));
            mode.innerKeyFromSeed(seed, &pk, &sk);
            for (0..10) |j| {
                seed[1] = @as(u8, @intCast(j));
                try testing.expectEqual(sk.decrypt(&pk.encrypt(&pt, &seed)), pt);
            }
        }
    }
}

test "Test happy flow" {
    var seed: [64]u8 = undefined;
    for (&seed, 0..) |*s, i| {
        s.* = @as(u8, @intCast(i));
    }
    inline for (modes) |mode| {
        for (0..10) |i| {
            seed[0] = @as(u8, @intCast(i));
            const kp = try mode.KeyPair.generateDeterministic(seed);
            const sk = try mode.SecretKey.fromBytes(&kp.secret_key.toBytes());
            try testing.expectEqual(sk, kp.secret_key);
            const pk = try mode.PublicKey.fromBytes(&kp.public_key.toBytes());
            try testing.expectEqual(pk, kp.public_key);
            for (0..10) |j| {
                seed[1] = @as(u8, @intCast(j));
                const e = pk.encaps(seed[0..32].*);
                try testing.expectEqual(e.shared_secret, try sk.decaps(&e.ciphertext));
            }
        }
    }
}

// Code to test NIST Known Answer Tests (KAT), see PQCgenKAT.c.

const sha2 = crypto.hash.sha2;

test "NIST KAT test" {
    inline for (.{
        .{ d00.Kyber512, "e9c2bd37133fcb40772f81559f14b1f58dccd1c816701be9ba6214d43baf4547" },
        .{ d00.Kyber1024, "89248f2f33f7f4f7051729111f3049c409a933ec904aedadf035f30fa5646cd5" },
        .{ d00.Kyber768, "a1e122cad3c24bc51622e4c242d8b8acbcd3f618fee4220400605ca8f9ea02c2" },
    }) |modeHash| {
        const mode = modeHash[0];
        var seed: [48]u8 = undefined;
        for (&seed, 0..) |*s, i| {
            s.* = @as(u8, @intCast(i));
        }
        var f = sha2.Sha256.init(.{});
        const fw = f.writer();
        var g = NistDRBG.init(seed);
        try std.fmt.format(fw, "# {s}\n\n", .{mode.name});
        for (0..100) |i| {
            g.fill(&seed);
            try std.fmt.format(fw, "count = {}\n", .{i});
            try std.fmt.format(fw, "seed = {s}\n", .{std.fmt.fmtSliceHexUpper(&seed)});
            var g2 = NistDRBG.init(seed);

            // This is not equivalent to g2.fill(kseed[:]). As the reference
            // implementation calls randombytes twice generating the keypair,
            // we have to do that as well.
            var kseed: [64]u8 = undefined;
            var eseed: [32]u8 = undefined;
            g2.fill(kseed[0..32]);
            g2.fill(kseed[32..64]);
            g2.fill(&eseed);
            const kp = try mode.KeyPair.generateDeterministic(kseed);
            const e = kp.public_key.encaps(eseed);
            const ss2 = try kp.secret_key.decaps(&e.ciphertext);
            try testing.expectEqual(ss2, e.shared_secret);
            try std.fmt.format(fw, "pk = {s}\n", .{std.fmt.fmtSliceHexUpper(&kp.public_key.toBytes())});
            try std.fmt.format(fw, "sk = {s}\n", .{std.fmt.fmtSliceHexUpper(&kp.secret_key.toBytes())});
            try std.fmt.format(fw, "ct = {s}\n", .{std.fmt.fmtSliceHexUpper(&e.ciphertext)});
            try std.fmt.format(fw, "ss = {s}\n\n", .{std.fmt.fmtSliceHexUpper(&e.shared_secret)});
        }

        var out: [32]u8 = undefined;
        f.final(&out);
        var outHex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&outHex, "{s}", .{std.fmt.fmtSliceHexLower(&out)});
        try testing.expectEqual(outHex, modeHash[1].*);
    }
}

const NistDRBG = struct {
    key: [32]u8,
    v: [16]u8,

    fn incV(g: *NistDRBG) void {
        var j: usize = 15;
        while (j >= 0) : (j -= 1) {
            if (g.v[j] == 255) {
                g.v[j] = 0;
            } else {
                g.v[j] += 1;
                break;
            }
        }
    }

    // AES256_CTR_DRBG_Update(pd, &g.key, &g.v).
    fn update(g: *NistDRBG, pd: ?[48]u8) void {
        var buf: [48]u8 = undefined;
        const ctx = crypto.core.aes.Aes256.initEnc(g.key);
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            g.incV();
            var block: [16]u8 = undefined;
            ctx.encrypt(&block, &g.v);
            buf[i * 16 ..][0..16].* = block;
        }
        if (pd) |p| {
            for (&buf, p) |*b, x| {
                b.* ^= x;
            }
        }
        g.key = buf[0..32].*;
        g.v = buf[32..48].*;
    }

    // randombytes.
    fn fill(g: *NistDRBG, out: []u8) void {
        var block: [16]u8 = undefined;
        var dst = out;

        const ctx = crypto.core.aes.Aes256.initEnc(g.key);
        while (dst.len > 0) {
            g.incV();
            ctx.encrypt(&block, &g.v);
            if (dst.len < 16) {
                @memcpy(dst, block[0..dst.len]);
                break;
            }
            dst[0..block.len].* = block;
            dst = dst[16..dst.len];
        }
        g.update(null);
    }

    fn init(seed: [48]u8) NistDRBG {
        var ret: NistDRBG = .{ .key = .{0} ** 32, .v = .{0} ** 16 };
        ret.update(seed);
        return ret;
    }
};
// Based on Go stdlib implementation

const std = @import("../std.zig");
const mem = std.mem;
const debug = std.debug;

/// Counter mode.
///
/// This mode creates a key stream by encrypting an incrementing counter using a block cipher, and adding it to the source material.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// As a result, applications should generally never use it directly, but only in a construction that includes a MAC.
pub fn ctr(comptime BlockCipher: anytype, block_cipher: BlockCipher, dst: []u8, src: []const u8, iv: [BlockCipher.block_length]u8, endian: std.builtin.Endian) void {
    debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var counter: [BlockCipher.block_length]u8 = undefined;
    var counterInt = mem.readInt(u128, &iv, endian);
    var i: usize = 0;

    const parallel_count = BlockCipher.block.parallel.optimal_parallel_blocks;
    const wide_block_length = parallel_count * 16;
    if (src.len >= wide_block_length) {
        var counters: [parallel_count * 16]u8 = undefined;
        while (i + wide_block_length <= src.len) : (i += wide_block_length) {
            comptime var j = 0;
            inline while (j < parallel_count) : (j += 1) {
                mem.writeInt(u128, counters[j * 16 .. j * 16 + 16], counterInt, endian);
                counterInt +%= 1;
            }
            block_cipher.xorWide(parallel_count, dst[i .. i + wide_block_length][0..wide_block_length], src[i .. i + wide_block_length][0..wide_block_length], counters);
        }
    }
    while (i + block_length <= src.len) : (i += block_length) {
        mem.writeInt(u128, &counter, counterInt, endian);
        counterInt +%= 1;
        block_cipher.xor(dst[i .. i + block_length][0..block_length], src[i .. i + block_length][0..block_length], counter);
    }
    if (i < src.len) {
        mem.writeInt(u128, &counter, counterInt, endian);
        var pad = [_]u8{0} ** block_length;
        const src_slice = src[i..];
        @memcpy(pad[0..src_slice.len], src_slice);
        block_cipher.xor(&pad, &pad, counter);
        const pad_slice = pad[0 .. src.len - i];
        @memcpy(dst[i..][0..pad_slice.len], pad_slice);
    }
}
const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const rotl = std.math.rotl;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;
const Lane = std.meta.Vector(4, u64);

pub const Morus = struct {
    pub const tag_length = 16;
    pub const nonce_length = 16;
    pub const key_length = 16;

    const State = [5]Lane;

    s: State,

    fn update(self: *Morus, input: Lane) void {
        const s = &self.s;
        s[0] = s[0] ^ s[3];
        s[0] = s[0] ^ (s[1] & s[2]);
        s[0] = rotl(Lane, s[0], 13);
        var t = Lane{ s[3][3], s[3][0], s[3][1], s[3][2] };
        s[3] = t;

        s[1] = s[1] ^ input;
        s[1] = s[1] ^ s[4];
        s[1] = s[1] ^ (s[2] & s[3]);
        s[1] = rotl(Lane, s[1], 46);
        t = Lane{ s[4][2], s[4][3], s[4][0], s[4][1] };
        s[4] = t;

        s[2] = s[2] ^ input;
        s[2] = s[2] ^ s[0];
        s[2] = s[2] ^ (s[3] & s[4]);
        s[2] = rotl(Lane, s[2], 38);
        t = Lane{ s[0][1], s[0][2], s[0][3], s[0][0] };
        s[0] = t;

        s[3] = s[3] ^ input;
        s[3] = s[3] ^ s[1];
        s[3] = s[3] ^ (s[4] & s[0]);
        s[3] = rotl(Lane, s[3], 7);
        t = Lane{ s[1][2], s[1][3], s[1][0], s[1][1] };
        s[1] = t;

        s[4] = s[4] ^ input;
        s[4] = s[4] ^ s[2];
        s[4] = s[4] ^ (s[0] & s[1]);
        s[4] = rotl(Lane, s[4], 4);
        t = Lane{ s[2][3], s[2][0], s[2][1], s[2][2] };
        s[2] = t;
    }

    fn init(k: [16]u8, iv: [16]u8) Morus {
        const c = [_]u8{
            0x0,  0x1,  0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
            0x73, 0xb5, 0x28, 0xdd,
        };
        const k0 = mem.readIntLittle(u64, k[0..8]);
        const k1 = mem.readIntLittle(u64, k[8..16]);
        const iv0 = mem.readIntLittle(u64, iv[0..8]);
        const iv1 = mem.readIntLittle(u64, iv[8..16]);
        const v0 = Lane{ iv0, iv1, 0, 0 };
        const v1 = Lane{ k0, k1, k0, k1 };
        const v2: Lane = @splat(~@as(u64, 0));
        const v3: Lane = @splat(@as(u64, 0));
        const v4 = Lane{
            mem.readIntLittle(u64, c[0..8]),
            mem.readIntLittle(u64, c[8..16]),
            mem.readIntLittle(u64, c[16..24]),
            mem.readIntLittle(u64, c[24..32]),
        };
        var self = Morus{ .s = State{ v0, v1, v2, v3, v4 } };
        var i: usize = 0;
        const zero: Lane = @splat(0);
        while (i < 16) : (i += 1) {
            self.update(zero);
        }
        self.s[1] ^= v1;
        return self;
    }

    fn enc(self: *Morus, xi: *const [32]u8) [32]u8 {
        const p = Lane{
            mem.readIntLittle(u64, xi[0..8]),
            mem.readIntLittle(u64, xi[8..16]),
            mem.readIntLittle(u64, xi[16..24]),
            mem.readIntLittle(u64, xi[24..32]),
        };
        const s = self.s;
        const c = p ^ s[0] ^ Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        var ci: [32]u8 = undefined;
        mem.writeIntLittle(u64, ci[0..8], c[0]);
        mem.writeIntLittle(u64, ci[8..16], c[1]);
        mem.writeIntLittle(u64, ci[16..24], c[2]);
        mem.writeIntLittle(u64, ci[24..32], c[3]);
        self.update(p);
        return ci;
    }

    fn dec(self: *Morus, ci: *const [32]u8) [32]u8 {
        const c = Lane{
            mem.readIntLittle(u64, ci[0..8]),
            mem.readIntLittle(u64, ci[8..16]),
            mem.readIntLittle(u64, ci[16..24]),
            mem.readIntLittle(u64, ci[24..32]),
        };
        const s = self.s;
        const p = c ^ s[0] ^ Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        var xi: [32]u8 = undefined;
        mem.writeIntLittle(u64, xi[0..8], p[0]);
        mem.writeIntLittle(u64, xi[8..16], p[1]);
        mem.writeIntLittle(u64, xi[16..24], p[2]);
        mem.writeIntLittle(u64, xi[24..32], p[3]);
        self.update(p);
        return xi;
    }

    fn decLast(self: *Morus, xn: []u8, cn: []const u8) void {
        var pad = [_]u8{0} ** 32;
        mem.copy(u8, pad[0..cn.len], cn);
        const c = Lane{
            mem.readIntLittle(u64, pad[0..8]),
            mem.readIntLittle(u64, pad[8..16]),
            mem.readIntLittle(u64, pad[16..24]),
            mem.readIntLittle(u64, pad[24..32]),
        };
        const s = self.s;
        var p = c ^ s[0] ^ Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        mem.writeIntLittle(u64, pad[0..8], p[0]);
        mem.writeIntLittle(u64, pad[8..16], p[1]);
        mem.writeIntLittle(u64, pad[16..24], p[2]);
        mem.writeIntLittle(u64, pad[24..32], p[3]);
        mem.set(u8, pad[cn.len..], 0);
        mem.copy(u8, xn, pad[0..cn.len]);
        p = Lane{
            mem.readIntLittle(u64, pad[0..8]),
            mem.readIntLittle(u64, pad[8..16]),
            mem.readIntLittle(u64, pad[16..24]),
            mem.readIntLittle(u64, pad[24..32]),
        };
        self.update(p);
    }

    fn finalize(self: *Morus, adlen: usize, mlen: usize) [16]u8 {
        const t = [4]u64{ @intCast(u64, adlen) * 8, @intCast(u64, mlen) * 8, 0, 0 };
        var s = &self.s;
        s[4] ^= s[0];
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            self.update(t);
        }
        s = &self.s;
        s[0] ^= Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        var tag: [16]u8 = undefined;
        mem.writeIntLittle(u64, tag[0..8], s[0][0]);
        mem.writeIntLittle(u64, tag[8..16], s[0][1]);
        return tag;
    }

    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, iv: [nonce_length]u8, k: [key_length]u8) void {
        assert(c.len == m.len);
        var morus = init(k, iv);

        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            _ = morus.enc(ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
            _ = morus.enc(&pad);
        }

        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            mem.copy(u8, c[i..][0..32], &morus.enc(m[i..][0..32]));
        }
        if (m.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. m.len % 32], m[i..]);
            mem.copy(u8, c[i..], morus.enc(&pad)[0 .. m.len % 32]);
        }

        tag.* = morus.finalize(ad.len, m.len);
    }

    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, iv: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);
        var morus = init(k, iv);

        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            _ = morus.enc(ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
            _ = morus.enc(&pad);
        }

        i = 0;
        while (i + 32 <= c.len) : (i += 32) {
            mem.copy(u8, m[i..][0..32], &morus.dec(c[i..][0..32]));
        }
        if (c.len % 32 != 0) {
            morus.decLast(m[i..], c[i..]);
        }

        const expected_tag = morus.finalize(ad.len, m.len);
        if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
            return error.AuthenticationFailed;
        }
    }
};

const testing = std.testing;
const fmt = std.fmt;

test "morus" {
    const k = "YELLOW SUBMARINE".*;
    const iv = [_]u8{0} ** 16;
    const ad = "Comment numero un";
    var m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var expected_tag: [Morus.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "fe0bf3ea600b0355eb535ddd35320e1b");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "712ae984433ceea0448a6a4f35afd46b42f42d69316e42aa54264dfd8951293b6ed676c9a813e7f42745e6210de9c82c4ac67fde57695c2d1e1f2f302682f118c6895915de8fa63de1bb798c7a178ce3290dfe3527c370a4c65be01ca55b7abb26b573ade9076cbf9b8c06acc750470a4524");
    var tag: [16]u8 = undefined;
    Morus.encrypt(&c, &tag, m, ad, iv, k);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    try testing.expectEqualSlices(u8, &expected_c, &c);
    try Morus.decrypt(&m2, &c, tag, ad, iv, k);
    try testing.expectEqualSlices(u8, m, &m2);
}
const std = @import("std");
const mem = std.mem;
const maxInt = std.math.maxInt;
const OutputTooLongError = std.crypto.errors.OutputTooLongError;
const WeakParametersError = std.crypto.errors.WeakParametersError;

// RFC 2898 Section 5.2
//
// FromSpec:
//
// PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
// example) to derive keys. The length of the derived key is essentially
// unbounded. (However, the maximum effective search space for the
// derived key may be limited by the structure of the underlying
// pseudorandom function. See Appendix B.1 for further discussion.)
// PBKDF2 is recommended for new applications.
//
// PBKDF2 (P, S, c, dk_len)
//
// Options:        PRF        underlying pseudorandom function (h_len
//                            denotes the length in octets of the
//                            pseudorandom function output)
//
// Input:          P          password, an octet string
//                 S          salt, an octet string
//                 c          iteration count, a positive integer
//                 dk_len      intended length in octets of the derived
//                            key, a positive integer, at most
//                            (2^32 - 1) * h_len
//
// Output:         DK         derived key, a dk_len-octet string

// Based on Apple's CommonKeyDerivation, based originally on code by Damien Bergamini.

/// Apply PBKDF2 to generate a key from a password.
///
/// PBKDF2 is defined in RFC 2898, and is a recommendation of NIST SP 800-132.
///
/// dk: Slice of appropriate size for generated key. Generally 16 or 32 bytes in length.
///             May be uninitialized. All bytes will be overwritten.
///             Maximum size is `maxInt(u32) * Hash.digest_length`
///             It is a programming error to pass buffer longer than the maximum size.
///
/// password: Arbitrary sequence of bytes of any length, including empty.
///
/// salt: Arbitrary sequence of bytes of any length, including empty. A common length is 8 bytes.
///
/// rounds: Iteration count. Must be greater than 0. Common values range from 1,000 to 100,000.
///         Larger iteration counts improve security by increasing the time required to compute
///         the dk. It is common to tune this parameter to achieve approximately 100ms.
///
/// Prf: Pseudo-random function to use. A common choice is `std.crypto.auth.hmac.sha2.HmacSha256`.
pub fn pbkdf2(dk: []u8, password: []const u8, salt: []const u8, rounds: u32, comptime Prf: type) (WeakParametersError || OutputTooLongError)!void {
    if (rounds < 1) return error.WeakParameters;

    const dk_len = dk.len;
    const h_len = Prf.mac_length;
    comptime std.debug.assert(h_len >= 1);

    // FromSpec:
    //
    //   1. If dk_len > maxInt(u32) * h_len, output "derived key too long" and
    //      stop.
    //
    if (dk_len / h_len >= maxInt(u32)) {
        // Counter starts at 1 and is 32 bit, so if we have to return more blocks, we would overflow
        return error.OutputTooLong;
    }

    // FromSpec:
    //
    //   2. Let l be the number of h_len-long blocks of bytes in the derived key,
    //      rounding up, and let r be the number of bytes in the last
    //      block
    //

    const blocks_count = @as(u32, @intCast(std.math.divCeil(usize, dk_len, h_len) catch unreachable));
    var r = dk_len % h_len;
    if (r == 0) {
        r = h_len;
    }

    // FromSpec:
    //
    //   3. For each block of the derived key apply the function F defined
    //      below to the password P, the salt S, the iteration count c, and
    //      the block index to compute the block:
    //
    //                T_1 = F (P, S, c, 1) ,
    //                T_2 = F (P, S, c, 2) ,
    //                ...
    //                T_l = F (P, S, c, l) ,
    //
    //      where the function F is defined as the exclusive-or sum of the
    //      first c iterates of the underlying pseudorandom function PRF
    //      applied to the password P and the concatenation of the salt S
    //      and the block index i:
    //
    //                F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
    //
    //  where
    //
    //            U_1 = PRF (P, S || INT (i)) ,
    //            U_2 = PRF (P, U_1) ,
    //            ...
    //            U_c = PRF (P, U_{c-1}) .
    //
    //  Here, INT (i) is a four-octet encoding of the integer i, most
    //  significant octet first.
    //
    //  4. Concatenate the blocks and extract the first dk_len octets to
    //  produce a derived key DK:
    //
    //            DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

    var block: u32 = 0;
    while (block < blocks_count) : (block += 1) {
        var prev_block: [h_len]u8 = undefined;
        var new_block: [h_len]u8 = undefined;

        // U_1 = PRF (P, S || INT (i))
        const block_index = mem.toBytes(mem.nativeToBig(u32, block + 1)); // Block index starts at 0001
        var ctx = Prf.init(password);
        ctx.update(salt);
        ctx.update(block_index[0..]);
        ctx.final(prev_block[0..]);

        // Choose portion of DK to write into (T_n) and initialize
        const offset = block * h_len;
        const block_len = if (block != blocks_count - 1) h_len else r;
        const dk_block: []u8 = dk[offset..][0..block_len];
        @memcpy(dk_block, prev_block[0..dk_block.len]);

        var i: u32 = 1;
        while (i < rounds) : (i += 1) {
            // U_c = PRF (P, U_{c-1})
            Prf.create(&new_block, prev_block[0..], password);
            prev_block = new_block;

            // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
            for (dk_block, 0..) |_, j| {
                dk_block[j] ^= new_block[j];
            }
        }
    }
}

const htest = @import("test.zig");
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

// RFC 6070 PBKDF2 HMAC-SHA1 Test Vectors

test "RFC 6070 one iteration" {
    const p = "password";
    const s = "salt";
    const c = 1;
    const dk_len = 20;

    var dk: [dk_len]u8 = undefined;

    try pbkdf2(&dk, p, s, c, HmacSha1);

    const expected = "0c60c80f961f0e71f3a9b524af6012062fe037a6";

    try htest.assertEqual(expected, dk[0..]);
}

test "RFC 6070 two iterations" {
    const p = "password";
    const s = "salt";
    const c = 2;
    const dk_len = 20;

    var dk: [dk_len]u8 = undefined;

    try pbkdf2(&dk, p, s, c, HmacSha1);

    const expected = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";

    try htest.assertEqual(expected, dk[0..]);
}

test "RFC 6070 4096 iterations" {
    const p = "password";
    const s = "salt";
    const c = 4096;
    const dk_len = 20;

    var dk: [dk_len]u8 = undefined;

    try pbkdf2(&dk, p, s, c, HmacSha1);

    const expected = "4b007901b765489abead49d926f721d065a429c1";

    try htest.assertEqual(expected, dk[0..]);
}

test "RFC 6070 16,777,216 iterations" {
    // These iteration tests are slow so we always skip them. Results have been verified.
    if (true) {
        return error.SkipZigTest;
    }

    const p = "password";
    const s = "salt";
    const c = 16777216;
    const dk_len = 20;

    var dk = [_]u8{0} ** dk_len;

    try pbkdf2(&dk, p, s, c, HmacSha1);

    const expected = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";

    try htest.assertEqual(expected, dk[0..]);
}

test "RFC 6070 multi-block salt and password" {
    const p = "passwordPASSWORDpassword";
    const s = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    const c = 4096;
    const dk_len = 25;

    var dk: [dk_len]u8 = undefined;

    try pbkdf2(&dk, p, s, c, HmacSha1);

    const expected = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";

    try htest.assertEqual(expected, dk[0..]);
}

test "RFC 6070 embedded NUL" {
    const p = "pass\x00word";
    const s = "sa\x00lt";
    const c = 4096;
    const dk_len = 16;

    var dk: [dk_len]u8 = undefined;

    try pbkdf2(&dk, p, s, c, HmacSha1);

    const expected = "56fa6aa75548099dcc37d7f03425e0c3";

    try htest.assertEqual(expected, dk[0..]);
}

test "Very large dk_len" {
    // This test allocates 8GB of memory and is expected to take several hours to run.
    if (true) {
        return error.SkipZigTest;
    }
    const p = "password";
    const s = "salt";
    const c = 1;
    const dk_len = 1 << 33;

    const dk = try std.testing.allocator.alloc(u8, dk_len);
    defer std.testing.allocator.free(dk);

    // Just verify this doesn't crash with an overflow
    try pbkdf2(dk, p, s, c, HmacSha1);
}
const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;
const meta = std.meta;

const NonCanonicalError = crypto.errors.NonCanonicalError;
const NotSquareError = crypto.errors.NotSquareError;

/// Parameters to create a finite field type.
pub const FieldParams = struct {
    fiat: type,
    field_order: comptime_int,
    field_bits: comptime_int,
    saturated_bits: comptime_int,
    encoded_length: comptime_int,
};

/// A field element, internally stored in Montgomery domain.
pub fn Field(comptime params: FieldParams) type {
    const fiat = params.fiat;
    const MontgomeryDomainFieldElement = fiat.MontgomeryDomainFieldElement;
    const NonMontgomeryDomainFieldElement = fiat.NonMontgomeryDomainFieldElement;

    return struct {
        const Fe = @This();

        limbs: MontgomeryDomainFieldElement,

        /// Field size.
        pub const field_order = params.field_order;

        /// Number of bits to represent the set of all elements.
        pub const field_bits = params.field_bits;

        /// Number of bits that can be saturated without overflowing.
        pub const saturated_bits = params.saturated_bits;

        /// Number of bytes required to encode an element.
        pub const encoded_length = params.encoded_length;

        /// Zero.
        pub const zero: Fe = Fe{ .limbs = mem.zeroes(MontgomeryDomainFieldElement) };

        /// One.
        pub const one = one: {
            var fe: Fe = undefined;
            fiat.setOne(&fe.limbs);
            break :one fe;
        };

        /// Reject non-canonical encodings of an element.
        pub fn rejectNonCanonical(s_: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!void {
            var s = if (endian == .little) s_ else orderSwap(s_);
            const field_order_s = comptime fos: {
                var fos: [encoded_length]u8 = undefined;
                mem.writeInt(std.meta.Int(.unsigned, encoded_length * 8), &fos, field_order, .little);
                break :fos fos;
            };
            if (crypto.timing_safe.compare(u8, &s, &field_order_s, .little) != .lt) {
                return error.NonCanonical;
            }
        }

        /// Swap the endianness of an encoded element.
        pub fn orderSwap(s: [encoded_length]u8) [encoded_length]u8 {
            var t = s;
            for (s, 0..) |x, i| t[t.len - 1 - i] = x;
            return t;
        }

        /// Unpack a field element.
        pub fn fromBytes(s_: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!Fe {
            const s = if (endian == .little) s_ else orderSwap(s_);
            try rejectNonCanonical(s, .little);
            var limbs_z: NonMontgomeryDomainFieldElement = undefined;
            fiat.fromBytes(&limbs_z, s);
            var limbs: MontgomeryDomainFieldElement = undefined;
            fiat.toMontgomery(&limbs, limbs_z);
            return Fe{ .limbs = limbs };
        }

        /// Pack a field element.
        pub fn toBytes(fe: Fe, endian: std.builtin.Endian) [encoded_length]u8 {
            var limbs_z: NonMontgomeryDomainFieldElement = undefined;
            fiat.fromMontgomery(&limbs_z, fe.limbs);
            var s: [encoded_length]u8 = undefined;
            fiat.toBytes(&s, limbs_z);
            return if (endian == .little) s else orderSwap(s);
        }

        /// Element as an integer.
        pub const IntRepr = meta.Int(.unsigned, params.field_bits);

        /// Create a field element from an integer.
        pub fn fromInt(comptime x: IntRepr) NonCanonicalError!Fe {
            var s: [encoded_length]u8 = undefined;
            mem.writeInt(IntRepr, &s, x, .little);
            return fromBytes(s, .little);
        }

        /// Return the field element as an integer.
        pub fn toInt(fe: Fe) IntRepr {
            const s = fe.toBytes(.little);
            return mem.readInt(IntRepr, &s, .little);
        }

        /// Return true if the field element is zero.
        pub fn isZero(fe: Fe) bool {
            var z: @TypeOf(fe.limbs[0]) = undefined;
            fiat.nonzero(&z, fe.limbs);
            return z == 0;
        }

        /// Return true if both field elements are equivalent.
        pub fn equivalent(a: Fe, b: Fe) bool {
            return a.sub(b).isZero();
        }

        /// Return true if the element is odd.
        pub fn isOdd(fe: Fe) bool {
            const s = fe.toBytes(.little);
            return @as(u1, @truncate(s[0])) != 0;
        }

        /// Conditonally replace a field element with `a` if `c` is positive.
        pub fn cMov(fe: *Fe, a: Fe, c: u1) void {
            fiat.selectznz(&fe.limbs, c, fe.limbs, a.limbs);
        }

        /// Add field elements.
        pub fn add(a: Fe, b: Fe) Fe {
            var fe: Fe = undefined;
            fiat.add(&fe.limbs, a.limbs, b.limbs);
            return fe;
        }

        /// Subtract field elements.
        pub fn sub(a: Fe, b: Fe) Fe {
            var fe: Fe = undefined;
            fiat.sub(&fe.limbs, a.limbs, b.limbs);
            return fe;
        }

        /// Double a field element.
        pub fn dbl(a: Fe) Fe {
            var fe: Fe = undefined;
            fiat.add(&fe.limbs, a.limbs, a.limbs);
            return fe;
        }

        /// Multiply field elements.
        pub fn mul(a: Fe, b: Fe) Fe {
            var fe: Fe = undefined;
            fiat.mul(&fe.limbs, a.limbs, b.limbs);
            return fe;
        }

        /// Square a field element.
        pub fn sq(a: Fe) Fe {
            var fe: Fe = undefined;
            fiat.square(&fe.limbs, a.limbs);
            return fe;
        }

        /// Square a field element n times.
        fn sqn(a: Fe, comptime n: comptime_int) Fe {
            var i: usize = 0;
            var fe = a;
            while (i < n) : (i += 1) {
                fe = fe.sq();
            }
            return fe;
        }

        /// Compute a^n.
        pub fn pow(a: Fe, comptime T: type, comptime n: T) Fe {
            var fe = one;
            var x: T = n;
            var t = a;
            while (true) {
                if (@as(u1, @truncate(x)) != 0) fe = fe.mul(t);
                x >>= 1;
                if (x == 0) break;
                t = t.sq();
            }
            return fe;
        }

        /// Negate a field element.
        pub fn neg(a: Fe) Fe {
            var fe: Fe = undefined;
            fiat.opp(&fe.limbs, a.limbs);
            return fe;
        }

        /// Return the inverse of a field element, or 0 if a=0.
        // Field inversion from https://eprint.iacr.org/2021/549.pdf
        pub fn invert(a: Fe) Fe {
            const iterations = (49 * field_bits + if (field_bits < 46) 80 else 57) / 17;
            const Limbs = @TypeOf(a.limbs);
            const Word = @TypeOf(a.limbs[0]);
            const XLimbs = [a.limbs.len + 1]Word;

            var d: Word = 1;
            var f = comptime blk: {
                var f: XLimbs = undefined;
                fiat.msat(&f);
                break :blk f;
            };
            var g: XLimbs = undefined;
            fiat.fromMontgomery(g[0..a.limbs.len], a.limbs);
            g[g.len - 1] = 0;

            var r = Fe.one.limbs;
            var v = Fe.zero.limbs;

            var out1: Word = undefined;
            var out2: XLimbs = undefined;
            var out3: XLimbs = undefined;
            var out4: Limbs = undefined;
            var out5: Limbs = undefined;

            var i: usize = 0;
            while (i < iterations - iterations % 2) : (i += 2) {
                fiat.divstep(&out1, &out2, &out3, &out4, &out5, d, f, g, v, r);
                fiat.divstep(&d, &f, &g, &v, &r, out1, out2, out3, out4, out5);
            }
            if (iterations % 2 != 0) {
                fiat.divstep(&out1, &out2, &out3, &out4, &out5, d, f, g, v, r);
                v = out4;
                f = out2;
            }
            var v_opp: Limbs = undefined;
            fiat.opp(&v_opp, v);
            fiat.selectznz(&v, @as(u1, @truncate(f[f.len - 1] >> (@bitSizeOf(Word) - 1))), v, v_opp);

            const precomp = blk: {
                var precomp: Limbs = undefined;
                fiat.divstepPrecomp(&precomp);
                break :blk precomp;
            };
            var fe: Fe = undefined;
            fiat.mul(&fe.limbs, v, precomp);
            return fe;
        }

        /// Return true if the field element is a square.
        pub fn isSquare(x2: Fe) bool {
            if (field_order == 115792089210356248762697446949407573530086143415290314195533631308867097853951) {
                const t110 = x2.mul(x2.sq()).sq();
                const t111 = x2.mul(t110);
                const t111111 = t111.mul(x2.mul(t110).sqn(3));
                const x15 = t111111.sqn(6).mul(t111111).sqn(3).mul(t111);
                const x16 = x15.sq().mul(x2);
                const x53 = x16.sqn(16).mul(x16).sqn(15);
                const x47 = x15.mul(x53);
                const ls = x47.mul(((x53.sqn(17).mul(x2)).sqn(143).mul(x47)).sqn(47)).sq().mul(x2);
                return ls.equivalent(Fe.one);
            } else if (field_order == 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319) {
                const t111 = x2.mul(x2.mul(x2.sq()).sq());
                const t111111 = t111.mul(t111.sqn(3));
                const t1111110 = t111111.sq();
                const t1111111 = x2.mul(t1111110);
                const x12 = t1111110.sqn(5).mul(t111111);
                const x31 = x12.sqn(12).mul(x12).sqn(7).mul(t1111111);
                const x32 = x31.sq().mul(x2);
                const x63 = x32.sqn(31).mul(x31);
                const x126 = x63.sqn(63).mul(x63);
                const ls = x126.sqn(126).mul(x126).sqn(3).mul(t111).sqn(33).mul(x32).sqn(95).mul(x31);
                return ls.equivalent(Fe.one);
            } else {
                const ls = x2.pow(std.meta.Int(.unsigned, field_bits), (field_order - 1) / 2); // Legendre symbol
                return ls.equivalent(Fe.one);
            }
        }

        // x=x2^((field_order+1)/4) w/ field order=3 (mod 4).
        fn uncheckedSqrt(x2: Fe) Fe {
            if (field_order % 4 != 3) @compileError("unimplemented");
            if (field_order == 115792089210356248762697446949407573530086143415290314195533631308867097853951) {
                const t11 = x2.mul(x2.sq());
                const t1111 = t11.mul(t11.sqn(2));
                const t11111111 = t1111.mul(t1111.sqn(4));
                const x16 = t11111111.sqn(8).mul(t11111111);
                return x16.sqn(16).mul(x16).sqn(32).mul(x2).sqn(96).mul(x2).sqn(94);
            } else if (field_order == 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319) {
                const t111 = x2.mul(x2.mul(x2.sq()).sq());
                const t111111 = t111.mul(t111.sqn(3));
                const t1111110 = t111111.sq();
                const t1111111 = x2.mul(t1111110);
                const x12 = t1111110.sqn(5).mul(t111111);
                const x31 = x12.sqn(12).mul(x12).sqn(7).mul(t1111111);
                const x32 = x31.sq().mul(x2);
                const x63 = x32.sqn(31).mul(x31);
                const x126 = x63.sqn(63).mul(x63);
                return x126.sqn(126).mul(x126).sqn(3).mul(t111).sqn(33).mul(x32).sqn(64).mul(x2).sqn(30);
            } else if (field_order == 115792089237316195423570985008687907853269984665640564039457584007908834671663) {
                const t11 = x2.mul(x2.sq());
                const t1111 = t11.mul(t11.sqn(2));
                const t11111 = x2.mul(t1111.sq());
                const t1111111 = t11.mul(t11111.sqn(2));
                const x11 = t1111111.sqn(4).mul(t1111);
                const x22 = x11.sqn(11).mul(x11);
                const x27 = x22.sqn(5).mul(t11111);
                const x54 = x27.sqn(27).mul(x27);
                const x108 = x54.sqn(54).mul(x54);
                return x108.sqn(108).mul(x108).sqn(7).mul(t1111111).sqn(23).mul(x22).sqn(6).mul(t11).sqn(2);
            } else {
                return x2.pow(std.meta.Int(.unsigned, field_bits), (field_order + 1) / 4);
            }
        }

        /// Compute the square root of `x2`, returning `error.NotSquare` if `x2` was not a square.
        pub fn sqrt(x2: Fe) NotSquareError!Fe {
            const x = x2.uncheckedSqrt();
            if (x.sq().equivalent(x2)) {
                return x;
            }
            return error.NotSquare;
        }
    };
}
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const meta = std.meta;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const NotSquareError = crypto.errors.NotSquareError;

/// Group operations over P256.
pub const P256 = struct {
    /// The underlying prime field.
    pub const Fe = @import("p256/field.zig").Fe;
    /// Field arithmetic mod the order of the main subgroup.
    pub const scalar = @import("p256/scalar.zig");

    x: Fe,
    y: Fe,
    z: Fe = Fe.one,

    is_base: bool = false,

    /// The P256 base point.
    pub const basePoint = P256{
        .x = Fe.fromInt(48439561293906451759052585252797914202762949526041747995844080717082404635286) catch unreachable,
        .y = Fe.fromInt(36134250956749795798585127919587881956611106672985015071877198253568414405109) catch unreachable,
        .z = Fe.one,
        .is_base = true,
    };

    /// The P256 neutral element.
    pub const identityElement = P256{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    pub const B = Fe.fromInt(41058363725152142129326129780047268409114441015993725554835256314039467401291) catch unreachable;

    /// Reject the neutral element.
    pub fn rejectIdentity(p: P256) IdentityElementError!void {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) & (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        if (is_identity != 0) {
            return error.IdentityElement;
        }
    }

    /// Create a point from affine coordinates after checking that they match the curve equation.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!P256 {
        const x = p.x;
        const y = p.y;
        const x3AxB = x.sq().mul(x).sub(x).sub(x).sub(x).add(B);
        const yy = y.sq();
        const on_curve = @intFromBool(x3AxB.equivalent(yy));
        const is_identity = @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) & @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
        if ((on_curve | is_identity) == 0) {
            return error.InvalidEncoding;
        }
        var ret = P256{ .x = x, .y = y, .z = Fe.one };
        ret.z.cMov(P256.identityElement.z, is_identity);
        return ret;
    }

    /// Create a point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [32]u8, ys: [32]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!P256 {
        const x = try Fe.fromBytes(xs, endian);
        const y = try Fe.fromBytes(ys, endian);
        return fromAffineCoordinates(.{ .x = x, .y = y });
    }

    /// Recover the Y coordinate from the X coordinate.
    pub fn recoverY(x: Fe, is_odd: bool) NotSquareError!Fe {
        const x3AxB = x.sq().mul(x).sub(x).sub(x).sub(x).add(B);
        var y = try x3AxB.sqrt();
        const yn = y.neg();
        y.cMov(yn, @intFromBool(is_odd) ^ @intFromBool(y.isOdd()));
        return y;
    }

    /// Deserialize a SEC1-encoded point.
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!P256 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoding_type = s[0];
        const encoded = s[1..];
        switch (encoding_type) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return P256.identityElement;
            },
            2, 3 => {
                if (encoded.len != 32) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y_is_odd = (encoding_type == 3);
                const y = try recoverY(x, y_is_odd);
                return P256{ .x = x, .y = y };
            },
            4 => {
                if (encoded.len != 64) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y = try Fe.fromBytes(encoded[32..64].*, .big);
                return P256.fromAffineCoordinates(.{ .x = x, .y = y });
            },
            else => return error.InvalidEncoding,
        }
    }

    /// Serialize a point using the compressed SEC-1 format.
    pub fn toCompressedSec1(p: P256) [33]u8 {
        var out: [33]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Serialize a point using the uncompressed SEC-1 format.
    pub fn toUncompressedSec1(p: P256) [65]u8 {
        var out: [65]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..33].* = xy.x.toBytes(.big);
        out[33..65].* = xy.y.toBytes(.big);
        return out;
    }

    /// Return a random point.
    pub fn random() P256 {
        const n = scalar.random(.little);
        return basePoint.mul(n, .little) catch unreachable;
    }

    /// Flip the sign of the X coordinate.
    pub fn neg(p: P256) P256 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// Double a P256 point.
    // Algorithm 6 from https://eprint.iacr.org/2015/1060.pdf
    pub fn dbl(p: P256) P256 {
        var t0 = p.x.sq();
        var t1 = p.y.sq();
        var t2 = p.z.sq();
        var t3 = p.x.mul(p.y);
        t3 = t3.dbl();
        var Z3 = p.x.mul(p.z);
        Z3 = Z3.add(Z3);
        var Y3 = B.mul(t2);
        Y3 = Y3.sub(Z3);
        var X3 = Y3.dbl();
        Y3 = X3.add(Y3);
        X3 = t1.sub(Y3);
        Y3 = t1.add(Y3);
        Y3 = X3.mul(Y3);
        X3 = X3.mul(t3);
        t3 = t2.dbl();
        t2 = t2.add(t3);
        Z3 = B.mul(Z3);
        Z3 = Z3.sub(t2);
        Z3 = Z3.sub(t0);
        t3 = Z3.dbl();
        Z3 = Z3.add(t3);
        t3 = t0.dbl();
        t0 = t3.add(t0);
        t0 = t0.sub(t2);
        t0 = t0.mul(Z3);
        Y3 = Y3.add(t0);
        t0 = p.y.mul(p.z);
        t0 = t0.dbl();
        Z3 = t0.mul(Z3);
        X3 = X3.sub(Z3);
        Z3 = t0.mul(t1);
        Z3 = Z3.dbl().dbl();
        return .{
            .x = X3,
            .y = Y3,
            .z = Z3,
        };
    }

    /// Add P256 points, the second being specified using affine coordinates.
    // Algorithm 5 from https://eprint.iacr.org/2015/1060.pdf
    pub fn addMixed(p: P256, q: AffineCoordinates) P256 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t3 = q.x.add(q.y);
        var t4 = p.x.add(p.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = q.y.mul(p.z);
        t4 = t4.add(p.y);
        var Y3 = q.x.mul(p.z);
        Y3 = Y3.add(p.x);
        var Z3 = B.mul(p.z);
        var X3 = Y3.sub(Z3);
        Z3 = X3.dbl();
        X3 = X3.add(Z3);
        Z3 = t1.sub(X3);
        X3 = t1.add(X3);
        Y3 = B.mul(Y3);
        t1 = p.z.dbl();
        var t2 = t1.add(p.z);
        Y3 = Y3.sub(t2);
        Y3 = Y3.sub(t0);
        t1 = Y3.dbl();
        Y3 = t1.add(Y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(Y3);
        t2 = t0.mul(Y3);
        Y3 = X3.mul(Z3);
        Y3 = Y3.add(t2);
        X3 = t3.mul(X3);
        X3 = X3.sub(t1);
        Z3 = t4.mul(Z3);
        t1 = t3.mul(t0);
        Z3 = Z3.add(t1);
        var ret = P256{
            .x = X3,
            .y = Y3,
            .z = Z3,
        };
        ret.cMov(p, @intFromBool(q.x.isZero()));
        return ret;
    }

    /// Add P256 points.
    // Algorithm 4 from https://eprint.iacr.org/2015/1060.pdf
    pub fn add(p: P256, q: P256) P256 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t2 = p.z.mul(q.z);
        var t3 = p.x.add(p.y);
        var t4 = q.x.add(q.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = p.y.add(p.z);
        var X3 = q.y.add(q.z);
        t4 = t4.mul(X3);
        X3 = t1.add(t2);
        t4 = t4.sub(X3);
        X3 = p.x.add(p.z);
        var Y3 = q.x.add(q.z);
        X3 = X3.mul(Y3);
        Y3 = t0.add(t2);
        Y3 = X3.sub(Y3);
        var Z3 = B.mul(t2);
        X3 = Y3.sub(Z3);
        Z3 = X3.dbl();
        X3 = X3.add(Z3);
        Z3 = t1.sub(X3);
        X3 = t1.add(X3);
        Y3 = B.mul(Y3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        Y3 = Y3.sub(t2);
        Y3 = Y3.sub(t0);
        t1 = Y3.dbl();
        Y3 = t1.add(Y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(Y3);
        t2 = t0.mul(Y3);
        Y3 = X3.mul(Z3);
        Y3 = Y3.add(t2);
        X3 = t3.mul(X3);
        X3 = X3.sub(t1);
        Z3 = t4.mul(Z3);
        t1 = t3.mul(t0);
        Z3 = Z3.add(t1);
        return .{
            .x = X3,
            .y = Y3,
            .z = Z3,
        };
    }

    /// Subtract P256 points.
    pub fn sub(p: P256, q: P256) P256 {
        return p.add(q.neg());
    }

    /// Subtract P256 points, the second being specified using affine coordinates.
    pub fn subMixed(p: P256, q: AffineCoordinates) P256 {
        return p.addMixed(q.neg());
    }

    /// Return affine coordinates.
    pub fn affineCoordinates(p: P256) AffineCoordinates {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) & (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        const zinv = p.z.invert();
        var ret = AffineCoordinates{
            .x = p.x.mul(zinv),
            .y = p.y.mul(zinv),
        };
        ret.cMov(AffineCoordinates.identityElement, is_identity);
        return ret;
    }

    /// Return true if both coordinate sets represent the same point.
    pub fn equivalent(a: P256, b: P256) bool {
        if (a.sub(b).rejectIdentity()) {
            return false;
        } else |_| {
            return true;
        }
    }

    fn cMov(p: *P256, a: P256, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    fn pcSelect(comptime n: usize, pc: *const [n]P256, b: u8) P256 {
        var t = P256.identityElement;
        comptime var i: u8 = 1;
        inline while (i < pc.len) : (i += 1) {
            t.cMov(pc[i], @as(u1, @truncate((@as(usize, b ^ i) -% 1) >> 8)));
        }
        return t;
    }

    fn slide(s: [32]u8) [2 * 32 + 1]i8 {
        var e: [2 * 32 + 1]i8 = undefined;
        for (s, 0..) |x, i| {
            e[i * 2 + 0] = @as(i8, @as(u4, @truncate(x)));
            e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
        }
        // Now, e[0..63] is between 0 and 15, e[63] is between 0 and 7
        var carry: i8 = 0;
        for (e[0..64]) |*x| {
            x.* += carry;
            carry = (x.* + 8) >> 4;
            x.* -= carry * 16;
            std.debug.assert(x.* >= -8 and x.* <= 8);
        }
        e[64] = carry;
        // Now, e[*] is between -8 and 8, including e[64]
        std.debug.assert(carry >= -8 and carry <= 8);
        return e;
    }

    fn pcMul(pc: *const [9]P256, s: [32]u8, comptime vartime: bool) IdentityElementError!P256 {
        std.debug.assert(vartime);
        const e = slide(s);
        var q = P256.identityElement;
        var pos = e.len - 1;
        while (true) : (pos -= 1) {
            const slot = e[pos];
            if (slot > 0) {
                q = q.add(pc[@as(usize, @intCast(slot))]);
            } else if (slot < 0) {
                q = q.sub(pc[@as(usize, @intCast(-slot))]);
            }
            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        try q.rejectIdentity();
        return q;
    }

    fn pcMul16(pc: *const [16]P256, s: [32]u8, comptime vartime: bool) IdentityElementError!P256 {
        var q = P256.identityElement;
        var pos: usize = 252;
        while (true) : (pos -= 4) {
            const slot = @as(u4, @truncate((s[pos >> 3] >> @as(u3, @truncate(pos)))));
            if (vartime) {
                if (slot != 0) {
                    q = q.add(pc[slot]);
                }
            } else {
                q = q.add(pcSelect(16, pc, slot));
            }
            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        try q.rejectIdentity();
        return q;
    }

    fn precompute(p: P256, comptime count: usize) [1 + count]P256 {
        var pc: [1 + count]P256 = undefined;
        pc[0] = P256.identityElement;
        pc[1] = p;
        var i: usize = 2;
        while (i <= count) : (i += 1) {
            pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
        }
        return pc;
    }

    const basePointPc = pc: {
        @setEvalBranchQuota(50000);
        break :pc precompute(P256.basePoint, 15);
    };

    /// Multiply an elliptic curve point by a scalar.
    /// Return error.IdentityElement if the result is the identity element.
    pub fn mul(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const s = if (endian == .little) s_ else Fe.orderSwap(s_);
        if (p.is_base) {
            return pcMul16(&basePointPc, s, false);
        }
        try p.rejectIdentity();
        const pc = precompute(p, 15);
        return pcMul16(&pc, s, false);
    }

    /// Multiply an elliptic curve point by a *PUBLIC* scalar *IN VARIABLE TIME*
    /// This can be used for signature verification.
    pub fn mulPublic(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const s = if (endian == .little) s_ else Fe.orderSwap(s_);
        if (p.is_base) {
            return pcMul16(&basePointPc, s, true);
        }
        try p.rejectIdentity();
        const pc = precompute(p, 8);
        return pcMul(&pc, s, true);
    }

    /// Double-base multiplication of public parameters - Compute (p1*s1)+(p2*s2) *IN VARIABLE TIME*
    /// This can be used for signature verification.
    pub fn mulDoubleBasePublic(p1: P256, s1_: [32]u8, p2: P256, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const s1 = if (endian == .little) s1_ else Fe.orderSwap(s1_);
        const s2 = if (endian == .little) s2_ else Fe.orderSwap(s2_);
        try p1.rejectIdentity();
        var pc1_array: [9]P256 = undefined;
        const pc1 = if (p1.is_base) basePointPc[0..9] else pc: {
            pc1_array = precompute(p1, 8);
            break :pc &pc1_array;
        };
        try p2.rejectIdentity();
        var pc2_array: [9]P256 = undefined;
        const pc2 = if (p2.is_base) basePointPc[0..9] else pc: {
            pc2_array = precompute(p2, 8);
            break :pc &pc2_array;
        };
        const e1 = slide(s1);
        const e2 = slide(s2);
        var q = P256.identityElement;
        var pos: usize = 2 * 32;
        while (true) : (pos -= 1) {
            const slot1 = e1[pos];
            if (slot1 > 0) {
                q = q.add(pc1[@as(usize, @intCast(slot1))]);
            } else if (slot1 < 0) {
                q = q.sub(pc1[@as(usize, @intCast(-slot1))]);
            }
            const slot2 = e2[pos];
            if (slot2 > 0) {
                q = q.add(pc2[@as(usize, @intCast(slot2))]);
            } else if (slot2 < 0) {
                q = q.sub(pc2[@as(usize, @intCast(-slot2))]);
            }
            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        try q.rejectIdentity();
        return q;
    }
};

/// A point in affine coordinates.
pub const AffineCoordinates = struct {
    x: P256.Fe,
    y: P256.Fe,

    /// Identity element in affine coordinates.
    pub const identityElement = AffineCoordinates{ .x = P256.identityElement.x, .y = P256.identityElement.y };

    fn cMov(p: *AffineCoordinates, a: AffineCoordinates, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
    }
};

test {
    _ = @import("tests/p256.zig");
}
const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("p256_64.zig"),
    .field_order = 115792089210356248762697446949407573530086143415290314195533631308867097853951,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});
// Autogenerated: 'src/ExtractionOCaml/word_by_word_montgomery' --lang Zig --internal-static --public-function-case camelCase --private-function-case camelCase --public-type-case UpperCamelCase --private-type-case UpperCamelCase --no-prefix-fiat --package-name p256 '' 64 '2^256 - 2^224 + 2^192 + 2^96 - 1' mul square add sub opp from_montgomery to_montgomery nonzero selectznz to_bytes from_bytes one msat divstep divstep_precomp
// curve description (via package name): p256
// machine_wordsize = 64 (from "64")
// requested operations: mul, square, add, sub, opp, from_montgomery, to_montgomery, nonzero, selectznz, to_bytes, from_bytes, one, msat, divstep, divstep_precomp
// m = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff (from "2^256 - 2^224 + 2^192 + 2^96 - 1")
//
// NOTE: In addition to the bounds specified above each function, all
//   functions synthesized for this Montgomery arithmetic require the
//   input to be strictly less than the prime modulus (m), and also
//   require the input to be in the unique saturated representation.
//   All functions also ensure that these two properties are true of
//   return values.
//
// Computed values:
//   eval z = z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192)
//   bytes_eval z = z[0]
//   + (z[1] << 8)
//   + (z[2] << 16)
//   + (z[3] << 24)
//   + (z[4] << 32)
//   + (z[5] << 40)
//   + (z[6] << 48)
//   + (z[7] << 56)
//   + (z[8] << 64)
//   + (z[9] << 72)
//   + (z[10] << 80)
//   + (z[11] << 88)
//   + (z[12] << 96)
//   + (z[13] << 104)
//   + (z[14] << 112)
//   + (z[15] << 120)
//   + (z[16] << 128)
//   + (z[17] << 136)
//   + (z[18] << 144)
//   + (z[19] << 152)
//   + (z[20] << 160)
//   + (z[21] << 168)
//   + (z[22] << 176)
//   + (z[23] << 184)
//   + (z[24] << 192)
//   + (z[25] << 200)
//   + (z[26] << 208)
//   + (z[27] << 216)
//   + (z[28] << 224)
//   + (z[29] << 232)
//   + (z[30] << 240)
//   + (z[31] << 248)
//   twos_complement_eval z = let x1 := z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) in
//                            if x1 & (2^256-1) < 2^255 then x1 & (2^256-1) else (x1 & (2^256-1)) - 2^256

const std = @import("std");
const mode = @import("builtin").mode; // Checked arithmetic is disabled in non-debug modes to avoid side channels

// The type MontgomeryDomainFieldElement is a field element in the Montgomery domain.
// Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub const MontgomeryDomainFieldElement = [4]u64;

// The type NonMontgomeryDomainFieldElement is a field element NOT in the Montgomery domain.
// Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub const NonMontgomeryDomainFieldElement = [4]u64;

/// The function addcarryxU64 is an addition with carry.
///
/// Postconditions:
///   out1 = (arg1 + arg2 + arg3) mod 2^64
///   out2 = ⌊(arg1 + arg2 + arg3) / 2^64⌋
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [0x0 ~> 0xffffffffffffffff]
///   arg3: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [0x0 ~> 0x1]
inline fn addcarryxU64(out1: *u64, out2: *u1, arg1: u1, arg2: u64, arg3: u64) void {
    const x = @as(u128, arg2) +% arg3 +% arg1;
    out1.* = @truncate(x);
    out2.* = @truncate(x >> 64);
}

/// The function subborrowxU64 is a subtraction with borrow.
///
/// Postconditions:
///   out1 = (-arg1 + arg2 + -arg3) mod 2^64
///   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^64⌋
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [0x0 ~> 0xffffffffffffffff]
///   arg3: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [0x0 ~> 0x1]
inline fn subborrowxU64(out1: *u64, out2: *u1, arg1: u1, arg2: u64, arg3: u64) void {
    const x = @as(u128, arg2) -% arg3 -% arg1;
    out1.* = @truncate(x);
    out2.* = @truncate(x >> 64);
}

/// The function mulxU64 is a multiplication, returning the full double-width result.
///
/// Postconditions:
///   out1 = (arg1 * arg2) mod 2^64
///   out2 = ⌊arg1 * arg2 / 2^64⌋
///
/// Input Bounds:
///   arg1: [0x0 ~> 0xffffffffffffffff]
///   arg2: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [0x0 ~> 0xffffffffffffffff]
inline fn mulxU64(out1: *u64, out2: *u64, arg1: u64, arg2: u64) void {
    @setRuntimeSafety(mode == .Debug);

    const x = @as(u128, arg1) * @as(u128, arg2);
    out1.* = @as(u64, @truncate(x));
    out2.* = @as(u64, @truncate(x >> 64));
}

/// The function cmovznzU64 is a single-word conditional move.
///
/// Postconditions:
///   out1 = (if arg1 = 0 then arg2 else arg3)
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [0x0 ~> 0xffffffffffffffff]
///   arg3: [0x0 ~> 0xffffffffffffffff]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
inline fn cmovznzU64(out1: *u64, arg1: u1, arg2: u64, arg3: u64) void {
    @setRuntimeSafety(mode == .Debug);

    const mask = 0 -% @as(u64, arg1);
    out1.* = (mask & arg3) | ((~mask) & arg2);
}

/// The function mul multiplies two field elements in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
///
pub fn mul(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement, arg2: MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = (arg1[1]);
    const x2 = (arg1[2]);
    const x3 = (arg1[3]);
    const x4 = (arg1[0]);
    var x5: u64 = undefined;
    var x6: u64 = undefined;
    mulxU64(&x5, &x6, x4, (arg2[3]));
    var x7: u64 = undefined;
    var x8: u64 = undefined;
    mulxU64(&x7, &x8, x4, (arg2[2]));
    var x9: u64 = undefined;
    var x10: u64 = undefined;
    mulxU64(&x9, &x10, x4, (arg2[1]));
    var x11: u64 = undefined;
    var x12: u64 = undefined;
    mulxU64(&x11, &x12, x4, (arg2[0]));
    var x13: u64 = undefined;
    var x14: u1 = undefined;
    addcarryxU64(&x13, &x14, 0x0, x12, x9);
    var x15: u64 = undefined;
    var x16: u1 = undefined;
    addcarryxU64(&x15, &x16, x14, x10, x7);
    var x17: u64 = undefined;
    var x18: u1 = undefined;
    addcarryxU64(&x17, &x18, x16, x8, x5);
    const x19 = (@as(u64, x18) + x6);
    var x20: u64 = undefined;
    var x21: u64 = undefined;
    mulxU64(&x20, &x21, x11, 0xffffffff00000001);
    var x22: u64 = undefined;
    var x23: u64 = undefined;
    mulxU64(&x22, &x23, x11, 0xffffffff);
    var x24: u64 = undefined;
    var x25: u64 = undefined;
    mulxU64(&x24, &x25, x11, 0xffffffffffffffff);
    var x26: u64 = undefined;
    var x27: u1 = undefined;
    addcarryxU64(&x26, &x27, 0x0, x25, x22);
    const x28 = (@as(u64, x27) + x23);
    var x29: u64 = undefined;
    var x30: u1 = undefined;
    addcarryxU64(&x29, &x30, 0x0, x11, x24);
    var x31: u64 = undefined;
    var x32: u1 = undefined;
    addcarryxU64(&x31, &x32, x30, x13, x26);
    var x33: u64 = undefined;
    var x34: u1 = undefined;
    addcarryxU64(&x33, &x34, x32, x15, x28);
    var x35: u64 = undefined;
    var x36: u1 = undefined;
    addcarryxU64(&x35, &x36, x34, x17, x20);
    var x37: u64 = undefined;
    var x38: u1 = undefined;
    addcarryxU64(&x37, &x38, x36, x19, x21);
    var x39: u64 = undefined;
    var x40: u64 = undefined;
    mulxU64(&x39, &x40, x1, (arg2[3]));
    var x41: u64 = undefined;
    var x42: u64 = undefined;
    mulxU64(&x41, &x42, x1, (arg2[2]));
    var x43: u64 = undefined;
    var x44: u64 = undefined;
    mulxU64(&x43, &x44, x1, (arg2[1]));
    var x45: u64 = undefined;
    var x46: u64 = undefined;
    mulxU64(&x45, &x46, x1, (arg2[0]));
    var x47: u64 = undefined;
    var x48: u1 = undefined;
    addcarryxU64(&x47, &x48, 0x0, x46, x43);
    var x49: u64 = undefined;
    var x50: u1 = undefined;
    addcarryxU64(&x49, &x50, x48, x44, x41);
    var x51: u64 = undefined;
    var x52: u1 = undefined;
    addcarryxU64(&x51, &x52, x50, x42, x39);
    const x53 = (@as(u64, x52) + x40);
    var x54: u64 = undefined;
    var x55: u1 = undefined;
    addcarryxU64(&x54, &x55, 0x0, x31, x45);
    var x56: u64 = undefined;
    var x57: u1 = undefined;
    addcarryxU64(&x56, &x57, x55, x33, x47);
    var x58: u64 = undefined;
    var x59: u1 = undefined;
    addcarryxU64(&x58, &x59, x57, x35, x49);
    var x60: u64 = undefined;
    var x61: u1 = undefined;
    addcarryxU64(&x60, &x61, x59, x37, x51);
    var x62: u64 = undefined;
    var x63: u1 = undefined;
    addcarryxU64(&x62, &x63, x61, @as(u64, x38), x53);
    var x64: u64 = undefined;
    var x65: u64 = undefined;
    mulxU64(&x64, &x65, x54, 0xffffffff00000001);
    var x66: u64 = undefined;
    var x67: u64 = undefined;
    mulxU64(&x66, &x67, x54, 0xffffffff);
    var x68: u64 = undefined;
    var x69: u64 = undefined;
    mulxU64(&x68, &x69, x54, 0xffffffffffffffff);
    var x70: u64 = undefined;
    var x71: u1 = undefined;
    addcarryxU64(&x70, &x71, 0x0, x69, x66);
    const x72 = (@as(u64, x71) + x67);
    var x73: u64 = undefined;
    var x74: u1 = undefined;
    addcarryxU64(&x73, &x74, 0x0, x54, x68);
    var x75: u64 = undefined;
    var x76: u1 = undefined;
    addcarryxU64(&x75, &x76, x74, x56, x70);
    var x77: u64 = undefined;
    var x78: u1 = undefined;
    addcarryxU64(&x77, &x78, x76, x58, x72);
    var x79: u64 = undefined;
    var x80: u1 = undefined;
    addcarryxU64(&x79, &x80, x78, x60, x64);
    var x81: u64 = undefined;
    var x82: u1 = undefined;
    addcarryxU64(&x81, &x82, x80, x62, x65);
    const x83 = (@as(u64, x82) + @as(u64, x63));
    var x84: u64 = undefined;
    var x85: u64 = undefined;
    mulxU64(&x84, &x85, x2, (arg2[3]));
    var x86: u64 = undefined;
    var x87: u64 = undefined;
    mulxU64(&x86, &x87, x2, (arg2[2]));
    var x88: u64 = undefined;
    var x89: u64 = undefined;
    mulxU64(&x88, &x89, x2, (arg2[1]));
    var x90: u64 = undefined;
    var x91: u64 = undefined;
    mulxU64(&x90, &x91, x2, (arg2[0]));
    var x92: u64 = undefined;
    var x93: u1 = undefined;
    addcarryxU64(&x92, &x93, 0x0, x91, x88);
    var x94: u64 = undefined;
    var x95: u1 = undefined;
    addcarryxU64(&x94, &x95, x93, x89, x86);
    var x96: u64 = undefined;
    var x97: u1 = undefined;
    addcarryxU64(&x96, &x97, x95, x87, x84);
    const x98 = (@as(u64, x97) + x85);
    var x99: u64 = undefined;
    var x100: u1 = undefined;
    addcarryxU64(&x99, &x100, 0x0, x75, x90);
    var x101: u64 = undefined;
    var x102: u1 = undefined;
    addcarryxU64(&x101, &x102, x100, x77, x92);
    var x103: u64 = undefined;
    var x104: u1 = undefined;
    addcarryxU64(&x103, &x104, x102, x79, x94);
    var x105: u64 = undefined;
    var x106: u1 = undefined;
    addcarryxU64(&x105, &x106, x104, x81, x96);
    var x107: u64 = undefined;
    var x108: u1 = undefined;
    addcarryxU64(&x107, &x108, x106, x83, x98);
    var x109: u64 = undefined;
    var x110: u64 = undefined;
    mulxU64(&x109, &x110, x99, 0xffffffff00000001);
    var x111: u64 = undefined;
    var x112: u64 = undefined;
    mulxU64(&x111, &x112, x99, 0xffffffff);
    var x113: u64 = undefined;
    var x114: u64 = undefined;
    mulxU64(&x113, &x114, x99, 0xffffffffffffffff);
    var x115: u64 = undefined;
    var x116: u1 = undefined;
    addcarryxU64(&x115, &x116, 0x0, x114, x111);
    const x117 = (@as(u64, x116) + x112);
    var x118: u64 = undefined;
    var x119: u1 = undefined;
    addcarryxU64(&x118, &x119, 0x0, x99, x113);
    var x120: u64 = undefined;
    var x121: u1 = undefined;
    addcarryxU64(&x120, &x121, x119, x101, x115);
    var x122: u64 = undefined;
    var x123: u1 = undefined;
    addcarryxU64(&x122, &x123, x121, x103, x117);
    var x124: u64 = undefined;
    var x125: u1 = undefined;
    addcarryxU64(&x124, &x125, x123, x105, x109);
    var x126: u64 = undefined;
    var x127: u1 = undefined;
    addcarryxU64(&x126, &x127, x125, x107, x110);
    const x128 = (@as(u64, x127) + @as(u64, x108));
    var x129: u64 = undefined;
    var x130: u64 = undefined;
    mulxU64(&x129, &x130, x3, (arg2[3]));
    var x131: u64 = undefined;
    var x132: u64 = undefined;
    mulxU64(&x131, &x132, x3, (arg2[2]));
    var x133: u64 = undefined;
    var x134: u64 = undefined;
    mulxU64(&x133, &x134, x3, (arg2[1]));
    var x13```
