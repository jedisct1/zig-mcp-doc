```
mut.len);
        }
    }

    /// r = ⌊√a⌋
    pub fn sqrt(rma: *Managed, a: *const Managed) !void {
        const bit_count = a.bitCountAbs();

        if (bit_count == 0) {
            try rma.set(0);
            rma.setMetadata(a.isPositive(), rma.len());
            return;
        }

        if (!a.isPositive()) {
            return error.SqrtOfNegativeNumber;
        }

        const needed_limbs = calcSqrtLimbsBufferLen(bit_count);
        const limbs_buffer = try rma.allocator.alloc(Limb, needed_limbs);
        defer rma.allocator.free(limbs_buffer);

        try rma.ensureCapacity((a.len() - 1) / 2 + 1);
        var m = rma.toMutable();
        m.sqrt(a.toConst(), limbs_buffer);
        rma.setMetadata(m.positive, m.len);
    }

    /// r = truncate(Int(signedness, bit_count), a)
    pub fn truncate(r: *Managed, a: *const Managed, signedness: Signedness, bit_count: usize) !void {
        try r.ensureCapacity(calcTwosCompLimbCount(bit_count));
        var m = r.toMutable();
        m.truncate(a.toConst(), signedness, bit_count);
        r.setMetadata(m.positive, m.len);
    }

    /// r = saturate(Int(signedness, bit_count), a)
    pub fn saturate(r: *Managed, a: *const Managed, signedness: Signedness, bit_count: usize) !void {
        try r.ensureCapacity(calcTwosCompLimbCount(bit_count));
        var m = r.toMutable();
        m.saturate(a.toConst(), signedness, bit_count);
        r.setMetadata(m.positive, m.len);
    }

    /// r = @popCount(a) with 2s-complement semantics.
    /// r and a may be aliases.
    pub fn popCount(r: *Managed, a: *const Managed, bit_count: usize) !void {
        try r.ensureCapacity(calcTwosCompLimbCount(bit_count));
        var m = r.toMutable();
        m.popCount(a.toConst(), bit_count);
        r.setMetadata(m.positive, m.len);
    }
};

/// Different operators which can be used in accumulation style functions
/// (llmulacc, llmulaccKaratsuba, llmulaccLong, llmulLimb). In all these functions,
/// a computed value is accumulated with an existing result.
const AccOp = enum {
    /// The computed value is added to the result.
    add,

    /// The computed value is subtracted from the result.
    sub,
};

/// Knuth 4.3.1, Algorithm M.
///
/// r = r (op) a * b
/// r MUST NOT alias any of a or b.
///
/// The result is computed modulo `r.len`. When `r.len >= a.len + b.len`, no overflow occurs.
fn llmulacc(comptime op: AccOp, opt_allocator: ?Allocator, r: []Limb, a: []const Limb, b: []const Limb) void {
    assert(r.len >= a.len);
    assert(r.len >= b.len);
    assert(!slicesOverlap(r, a));
    assert(!slicesOverlap(r, b));

    // Order greatest first.
    var x = a;
    var y = b;
    if (a.len < b.len) {
        x = b;
        y = a;
    }

    k_mul: {
        if (y.len > 48) {
            if (opt_allocator) |allocator| {
                llmulaccKaratsuba(op, allocator, r, x, y) catch |err| switch (err) {
                    error.OutOfMemory => break :k_mul, // handled below
                };
                return;
            }
        }
    }

    llmulaccLong(op, r, x, y);
}

/// Knuth 4.3.1, Algorithm M.
///
/// r = r (op) a * b
/// r MUST NOT alias any of a or b.
///
/// The result is computed modulo `r.len`. When `r.len >= a.len + b.len`, no overflow occurs.
fn llmulaccKaratsuba(
    comptime op: AccOp,
    allocator: Allocator,
    r: []Limb,
    a: []const Limb,
    b: []const Limb,
) error{OutOfMemory}!void {
    assert(r.len >= a.len);
    assert(a.len >= b.len);
    assert(!slicesOverlap(r, a));
    assert(!slicesOverlap(r, b));

    // Classical karatsuba algorithm:
    // a = a1 * B + a0
    // b = b1 * B + b0
    // Where a0, b0 < B
    //
    // We then have:
    // ab = a * b
    //    = (a1 * B + a0) * (b1 * B + b0)
    //    = a1 * b1 * B * B + a1 * B * b0 + a0 * b1 * B + a0 * b0
    //    = a1 * b1 * B * B + (a1 * b0 + a0 * b1) * B + a0 * b0
    //
    // Note that:
    // a1 * b0 + a0 * b1
    //    = (a1 + a0)(b1 + b0) - a1 * b1 - a0 * b0
    //    = (a0 - a1)(b1 - b0) + a1 * b1 + a0 * b0
    //
    // This yields:
    // ab = p2 * B^2 + (p0 + p1 + p2) * B + p0
    //
    // Where:
    // p0 = a0 * b0
    // p1 = (a0 - a1)(b1 - b0)
    // p2 = a1 * b1
    //
    // Note, (a0 - a1) and (b1 - b0) produce values -B < x < B, and so we need to mind the sign here.
    // We also have:
    // 0 <= p0 <= 2B
    // -2B <= p1 <= 2B
    //
    // Note, when B is a multiple of the limb size, multiplies by B amount to shifts or
    // slices of a limbs array.
    //
    // This function computes the result of the multiplication modulo r.len. This means:
    // - p2 and p1 only need to be computed modulo r.len - B.
    // - In the case of p2, p2 * B^2 needs to be added modulo r.len - 2 * B.

    const split = b.len / 2; // B

    const limbs_after_split = r.len - split; // Limbs to compute for p1 and p2.
    const limbs_after_split2 = r.len - split * 2; // Limbs to add for p2 * B^2.

    // For a0 and b0 we need the full range.
    const a0 = a[0..llnormalize(a[0..split])];
    const b0 = b[0..llnormalize(b[0..split])];

    // For a1 and b1 we only need `limbs_after_split` limbs.
    const a1 = blk: {
        var a1 = a[split..];
        a1.len = @min(llnormalize(a1), limbs_after_split);
        break :blk a1;
    };

    const b1 = blk: {
        var b1 = b[split..];
        b1.len = @min(llnormalize(b1), limbs_after_split);
        break :blk b1;
    };

    // Note that the above slices relative to `split` work because we have a.len > b.len.

    // We need some temporary memory to store intermediate results.
    // Note, we can reduce the amount of temporaries we need by reordering the computation here:
    // ab = p2 * B^2 + (p0 + p1 + p2) * B + p0
    //    = p2 * B^2 + (p0 * B + p1 * B + p2 * B) + p0
    //    = (p2 * B^2 + p2 * B) + (p0 * B + p0) + p1 * B

    // Allocate at least enough memory to be able to multiply the upper two segments of a and b, assuming
    // no overflow.
    const tmp = try allocator.alloc(Limb, a.len - split + b.len - split);
    defer allocator.free(tmp);

    // Compute p2.
    // Note, we don't need to compute all of p2, just enough limbs to satisfy r.
    const p2_limbs = @min(limbs_after_split, a1.len + b1.len);

    @memset(tmp[0..p2_limbs], 0);
    llmulacc(.add, allocator, tmp[0..p2_limbs], a1[0..@min(a1.len, p2_limbs)], b1[0..@min(b1.len, p2_limbs)]);
    const p2 = tmp[0..llnormalize(tmp[0..p2_limbs])];

    // Add p2 * B to the result.
    llaccum(op, r[split..], p2);

    // Add p2 * B^2 to the result if required.
    if (limbs_after_split2 > 0) {
        llaccum(op, r[split * 2 ..], p2[0..@min(p2.len, limbs_after_split2)]);
    }

    // Compute p0.
    // Since a0.len, b0.len <= split and r.len >= split * 2, the full width of p0 needs to be computed.
    const p0_limbs = a0.len + b0.len;
    @memset(tmp[0..p0_limbs], 0);
    llmulacc(.add, allocator, tmp[0..p0_limbs], a0, b0);
    const p0 = tmp[0..llnormalize(tmp[0..p0_limbs])];

    // Add p0 to the result.
    llaccum(op, r, p0);

    // Add p0 * B to the result. In this case, we may not need all of it.
    llaccum(op, r[split..], p0[0..@min(limbs_after_split, p0.len)]);

    // Finally, compute and add p1.
    // From now on we only need `limbs_after_split` limbs for a0 and b0, since the result of the
    // following computation will be added * B.
    const a0x = a0[0..@min(a0.len, limbs_after_split)];
    const b0x = b0[0..@min(b0.len, limbs_after_split)];

    const j0_sign = llcmp(a0x, a1);
    const j1_sign = llcmp(b1, b0x);

    if (j0_sign * j1_sign == 0) {
        // p1 is zero, we don't need to do any computation at all.
        return;
    }

    @memset(tmp, 0);

    // p1 is nonzero, so compute the intermediary terms j0 = a0 - a1 and j1 = b1 - b0.
    // Note that in this case, we again need some storage for intermediary results
    // j0 and j1. Since we have tmp.len >= 2B, we can store both
    // intermediaries in the already allocated array.
    const j0 = tmp[0 .. a.len - split];
    const j1 = tmp[a.len - split ..];

    // Ensure that no subtraction overflows.
    if (j0_sign == 1) {
        // a0 > a1.
        _ = llsubcarry(j0, a0x, a1);
    } else {
        // a0 < a1.
        _ = llsubcarry(j0, a1, a0x);
    }

    if (j1_sign == 1) {
        // b1 > b0.
        _ = llsubcarry(j1, b1, b0x);
    } else {
        // b1 > b0.
        _ = llsubcarry(j1, b0x, b1);
    }

    if (j0_sign * j1_sign == 1) {
        // If j0 and j1 are both positive, we now have:
        // p1 = j0 * j1
        // If j0 and j1 are both negative, we now have:
        // p1 = -j0 * -j1 = j0 * j1
        // In this case we can add p1 to the result using llmulacc.
        llmulacc(op, allocator, r[split..], j0[0..llnormalize(j0)], j1[0..llnormalize(j1)]);
    } else {
        // In this case either j0 or j1 is negative, an we have:
        // p1 = -(j0 * j1)
        // Now we need to subtract instead of accumulate.
        const inverted_op = if (op == .add) .sub else .add;
        llmulacc(inverted_op, allocator, r[split..], j0[0..llnormalize(j0)], j1[0..llnormalize(j1)]);
    }
}

/// r = r (op) a.
/// The result is computed modulo `r.len`.
fn llaccum(comptime op: AccOp, r: []Limb, a: []const Limb) void {
    if (op == .sub) {
        _ = llsubcarry(r, r, a);
        return;
    }

    assert(r.len != 0 and a.len != 0);
    assert(r.len >= a.len);

    var i: usize = 0;
    var carry: Limb = 0;

    while (i < a.len) : (i += 1) {
        const ov1 = @addWithOverflow(r[i], a[i]);
        r[i] = ov1[0];
        const ov2 = @addWithOverflow(r[i], carry);
        r[i] = ov2[0];
        carry = @as(Limb, ov1[1]) + ov2[1];
    }

    while ((carry != 0) and i < r.len) : (i += 1) {
        const ov = @addWithOverflow(r[i], carry);
        r[i] = ov[0];
        carry = ov[1];
    }
}

/// Returns -1, 0, 1 if |a| < |b|, |a| == |b| or |a| > |b| respectively for limbs.
pub fn llcmp(a: []const Limb, b: []const Limb) i8 {
    const a_len = llnormalize(a);
    const b_len = llnormalize(b);
    if (a_len < b_len) {
        return -1;
    }
    if (a_len > b_len) {
        return 1;
    }

    var i: usize = a_len - 1;
    while (i != 0) : (i -= 1) {
        if (a[i] != b[i]) {
            break;
        }
    }

    if (a[i] < b[i]) {
        return -1;
    } else if (a[i] > b[i]) {
        return 1;
    } else {
        return 0;
    }
}

/// r = r (op) y * xi
/// The result is computed modulo `r.len`. When `r.len >= a.len + b.len`, no overflow occurs.
fn llmulaccLong(comptime op: AccOp, r: []Limb, a: []const Limb, b: []const Limb) void {
    assert(r.len >= a.len);
    assert(a.len >= b.len);

    var i: usize = 0;
    while (i < b.len) : (i += 1) {
        _ = llmulLimb(op, r[i..], a, b[i]);
    }
}

/// r = r (op) y * xi
/// The result is computed modulo `r.len`.
/// Returns whether the operation overflowed.
fn llmulLimb(comptime op: AccOp, acc: []Limb, y: []const Limb, xi: Limb) bool {
    if (xi == 0) {
        return false;
    }

    const split = @min(y.len, acc.len);
    var a_lo = acc[0..split];
    var a_hi = acc[split..];

    switch (op) {
        .add => {
            var carry: Limb = 0;
            var j: usize = 0;
            while (j < a_lo.len) : (j += 1) {
                a_lo[j] = addMulLimbWithCarry(a_lo[j], y[j], xi, &carry);
            }

            j = 0;
            while ((carry != 0) and (j < a_hi.len)) : (j += 1) {
                const ov = @addWithOverflow(a_hi[j], carry);
                a_hi[j] = ov[0];
                carry = ov[1];
            }

            return carry != 0;
        },
        .sub => {
            var borrow: Limb = 0;
            var j: usize = 0;
            while (j < a_lo.len) : (j += 1) {
                a_lo[j] = subMulLimbWithBorrow(a_lo[j], y[j], xi, &borrow);
            }

            j = 0;
            while ((borrow != 0) and (j < a_hi.len)) : (j += 1) {
                const ov = @subWithOverflow(a_hi[j], borrow);
                a_hi[j] = ov[0];
                borrow = ov[1];
            }

            return borrow != 0;
        },
    }
}

/// returns the min length the limb could be.
fn llnormalize(a: []const Limb) usize {
    var j = a.len;
    while (j > 0) : (j -= 1) {
        if (a[j - 1] != 0) {
            break;
        }
    }

    // Handle zero
    return if (j != 0) j else 1;
}

/// Knuth 4.3.1, Algorithm S.
fn llsubcarry(r: []Limb, a: []const Limb, b: []const Limb) Limb {
    assert(a.len != 0 and b.len != 0);
    assert(a.len >= b.len);
    assert(r.len >= a.len);

    var i: usize = 0;
    var borrow: Limb = 0;

    while (i < b.len) : (i += 1) {
        const ov1 = @subWithOverflow(a[i], b[i]);
        r[i] = ov1[0];
        const ov2 = @subWithOverflow(r[i], borrow);
        r[i] = ov2[0];
        borrow = @as(Limb, ov1[1]) + ov2[1];
    }

    while (i < a.len) : (i += 1) {
        const ov = @subWithOverflow(a[i], borrow);
        r[i] = ov[0];
        borrow = ov[1];
    }

    return borrow;
}

fn llsub(r: []Limb, a: []const Limb, b: []const Limb) void {
    assert(a.len > b.len or (a.len == b.len and a[a.len - 1] >= b[b.len - 1]));
    assert(llsubcarry(r, a, b) == 0);
}

/// Knuth 4.3.1, Algorithm A.
fn lladdcarry(r: []Limb, a: []const Limb, b: []const Limb) Limb {
    assert(a.len != 0 and b.len != 0);
    assert(a.len >= b.len);
    assert(r.len >= a.len);

    var i: usize = 0;
    var carry: Limb = 0;

    while (i < b.len) : (i += 1) {
        const ov1 = @addWithOverflow(a[i], b[i]);
        r[i] = ov1[0];
        const ov2 = @addWithOverflow(r[i], carry);
        r[i] = ov2[0];
        carry = @as(Limb, ov1[1]) + ov2[1];
    }

    while (i < a.len) : (i += 1) {
        const ov = @addWithOverflow(a[i], carry);
        r[i] = ov[0];
        carry = ov[1];
    }

    return carry;
}

fn lladd(r: []Limb, a: []const Limb, b: []const Limb) void {
    assert(r.len >= a.len + 1);
    r[a.len] = lladdcarry(r, a, b);
}

/// Knuth 4.3.1, Exercise 16.
fn lldiv1(quo: []Limb, rem: *Limb, a: []const Limb, b: Limb) void {
    assert(a.len > 1 or a[0] >= b);
    assert(quo.len >= a.len);

    rem.* = 0;
    for (a, 0..) |_, ri| {
        const i = a.len - ri - 1;
        const pdiv = ((@as(DoubleLimb, rem.*) << limb_bits) | a[i]);

        if (pdiv == 0) {
            quo[i] = 0;
            rem.* = 0;
        } else if (pdiv < b) {
            quo[i] = 0;
            rem.* = @as(Limb, @truncate(pdiv));
        } else if (pdiv == b) {
            quo[i] = 1;
            rem.* = 0;
        } else {
            quo[i] = @as(Limb, @truncate(@divTrunc(pdiv, b)));
            rem.* = @as(Limb, @truncate(pdiv - (quo[i] *% b)));
        }
    }
}

fn lldiv0p5(quo: []Limb, rem: *Limb, a: []const Limb, b: HalfLimb) void {
    assert(a.len > 1 or a[0] >= b);
    assert(quo.len >= a.len);

    rem.* = 0;
    for (a, 0..) |_, ri| {
        const i = a.len - ri - 1;
        const ai_high = a[i] >> half_limb_bits;
        const ai_low = a[i] & ((1 << half_limb_bits) - 1);

        // Split the division into two divisions acting on half a limb each. Carry remainder.
        const ai_high_with_carry = (rem.* << half_limb_bits) | ai_high;
        const ai_high_quo = ai_high_with_carry / b;
        rem.* = ai_high_with_carry % b;

        const ai_low_with_carry = (rem.* << half_limb_bits) | ai_low;
        const ai_low_quo = ai_low_with_carry / b;
        rem.* = ai_low_with_carry % b;

        quo[i] = (ai_high_quo << half_limb_bits) | ai_low_quo;
    }
}

/// Performs r = a << shift and returns the amount of limbs affected
///
/// if a and r overlaps, then r.ptr >= a.ptr is asserted
/// r must have the capacity to store a << shift
fn llshl(r: []Limb, a: []const Limb, shift: usize) usize {
    std.debug.assert(a.len >= 1);
    if (slicesOverlap(a, r))
        std.debug.assert(@intFromPtr(r.ptr) >= @intFromPtr(a.ptr));

    if (shift == 0) {
        if (a.ptr != r.ptr)
            std.mem.copyBackwards(Limb, r[0..a.len], a);
        return a.len;
    }
    if (shift >= limb_bits) {
        const limb_shift = shift / limb_bits;

        const affected = llshl(r[limb_shift..], a, shift % limb_bits);
        @memset(r[0..limb_shift], 0);

        return limb_shift + affected;
    }

    // shift is guaranteed to be < limb_bits
    const bit_shift: Log2Limb = @truncate(shift);
    const opposite_bit_shift: Log2Limb = @truncate(limb_bits - bit_shift);

    // We only need the extra limb if the shift of the last element overflows.
    // This is useful for the implementation of `shiftLeftSat`.
    const overflows = a[a.len - 1] >> opposite_bit_shift != 0;
    if (overflows) {
        std.debug.assert(r.len >= a.len + 1);
    } else {
        std.debug.assert(r.len >= a.len);
    }

    var i: usize = a.len;
    if (overflows) {
        // r is asserted to be large enough above
        r[a.len] = a[a.len - 1] >> opposite_bit_shift;
    }
    while (i > 1) {
        i -= 1;
        r[i] = (a[i - 1] >> opposite_bit_shift) | (a[i] << bit_shift);
    }
    r[0] = a[0] << bit_shift;

    return a.len + @intFromBool(overflows);
}

/// Performs r = a >> shift and returns the amount of limbs affected
///
/// if a and r overlaps, then r.ptr <= a.ptr is asserted
/// r must have the capacity to store a >> shift
///
/// See tests below for examples of behaviour
fn llshr(r: []Limb, a: []const Limb, shift: usize) usize {
    if (slicesOverlap(a, r))
        std.debug.assert(@intFromPtr(r.ptr) <= @intFromPtr(a.ptr));

    if (a.len == 0) return 0;

    if (shift == 0) {
        std.debug.assert(r.len >= a.len);

        if (a.ptr != r.ptr)
            std.mem.copyForwards(Limb, r[0..a.len], a);
        return a.len;
    }
    if (shift >= limb_bits) {
        if (shift / limb_bits >= a.len) {
            r[0] = 0;
            return 1;
        }
        return llshr(r, a[shift / limb_bits ..], shift % limb_bits);
    }

    // shift is guaranteed to be < limb_bits
    const bit_shift: Log2Limb = @truncate(shift);
    const opposite_bit_shift: Log2Limb = @truncate(limb_bits - bit_shift);

    // special case, where there is a risk to set r to 0
    if (a.len == 1) {
        r[0] = a[0] >> bit_shift;
        return 1;
    }
    if (a.len == 0) {
        r[0] = 0;
        return 1;
    }

    // if the most significant limb becomes 0 after the shift
    const shrink = a[a.len - 1] >> bit_shift == 0;
    std.debug.assert(r.len >= a.len - @intFromBool(!shrink));

    var i: usize = 0;
    while (i < a.len - 1) : (i += 1) {
        r[i] = (a[i] >> bit_shift) | (a[i + 1] << opposite_bit_shift);
    }

    if (!shrink)
        r[i] = a[i] >> bit_shift;

    return a.len - @intFromBool(shrink);
}

// r = ~r
fn llnot(r: []Limb) void {
    for (r) |*elem| {
        elem.* = ~elem.*;
    }
}

// r = a | b with 2s complement semantics.
// r may alias.
// a and b must not be 0.
// Returns `true` when the result is positive.
// When b is positive, r requires at least `a.len` limbs of storage.
// When b is negative, r requires at least `b.len` limbs of storage.
fn llsignedor(r: []Limb, a: []const Limb, a_positive: bool, b: []const Limb, b_positive: bool) bool {
    assert(r.len >= a.len);
    assert(a.len >= b.len);

    if (a_positive and b_positive) {
        // Trivial case, result is positive.
        var i: usize = 0;
        while (i < b.len) : (i += 1) {
            r[i] = a[i] | b[i];
        }
        while (i < a.len) : (i += 1) {
            r[i] = a[i];
        }

        return true;
    } else if (!a_positive and b_positive) {
        // Result is negative.
        // r = (--a) | b
        //   = ~(-a - 1) | b
        //   = ~(-a - 1) | ~~b
        //   = ~((-a - 1) & ~b)
        //   = -(((-a - 1) & ~b) + 1)

        var i: usize = 0;
        var a_borrow: u1 = 1;
        var r_carry: u1 = 1;

        while (i < b.len) : (i += 1) {
            const ov1 = @subWithOverflow(a[i], a_borrow);
            a_borrow = ov1[1];
            const ov2 = @addWithOverflow(ov1[0] & ~b[i], r_carry);
            r[i] = ov2[0];
            r_carry = ov2[1];
        }

        // In order for r_carry to be nonzero at this point, ~b[i] would need to be
        // all ones, which would require b[i] to be zero. This cannot be when
        // b is normalized, so there cannot be a carry here.
        // Also, x & ~b can only clear bits, so (x & ~b) <= x, meaning (-a - 1) + 1 never overflows.
        assert(r_carry == 0);

        // With b = 0, we get (-a - 1) & ~0 = -a - 1.
        // Note, if a_borrow is zero we do not need to compute anything for
        // the higher limbs so we can early return here.
        while (i < a.len and a_borrow == 1) : (i += 1) {
            const ov = @subWithOverflow(a[i], a_borrow);
            r[i] = ov[0];
            a_borrow = ov[1];
        }

        assert(a_borrow == 0); // a was 0.

        return false;
    } else if (a_positive and !b_positive) {
        // Result is negative.
        // r = a | (--b)
        //   = a | ~(-b - 1)
        //   = ~~a | ~(-b - 1)
        //   = ~(~a & (-b - 1))
        //   = -((~a & (-b - 1)) + 1)

        var i: usize = 0;
        var b_borrow: u1 = 1;
        var r_carry: u1 = 1;

        while (i < b.len) : (i += 1) {
            const ov1 = @subWithOverflow(b[i], b_borrow);
            b_borrow = ov1[1];
            const ov2 = @addWithOverflow(~a[i] & ov1[0], r_carry);
            r[i] = ov2[0];
            r_carry = ov2[1];
        }

        // b is at least 1, so this should never underflow.
        assert(b_borrow == 0); // b was 0

        // x & ~a can only clear bits, so (x & ~a) <= x, meaning (-b - 1) + 1 never overflows.
        assert(r_carry == 0);

        // With b = 0 and b_borrow = 0, we get ~a & (0 - 0) = ~a & 0 = 0.
        // Omit setting the upper bytes, just deal with those when calling llsignedor.

        return false;
    } else {
        // Result is negative.
        // r = (--a) | (--b)
        //   = ~(-a - 1) | ~(-b - 1)
        //   = ~((-a - 1) & (-b - 1))
        //   = -(~(~((-a - 1) & (-b - 1))) + 1)
        //   = -((-a - 1) & (-b - 1) + 1)

        var i: usize = 0;
        var a_borrow: u1 = 1;
        var b_borrow: u1 = 1;
        var r_carry: u1 = 1;

        while (i < b.len) : (i += 1) {
            const ov1 = @subWithOverflow(a[i], a_borrow);
            a_borrow = ov1[1];
            const ov2 = @subWithOverflow(b[i], b_borrow);
            b_borrow = ov2[1];
            const ov3 = @addWithOverflow(ov1[0] & ov2[0], r_carry);
            r[i] = ov3[0];
            r_carry = ov3[1];
        }

        // b is at least 1, so this should never underflow.
        assert(b_borrow == 0); // b was 0

        // Can never overflow because in order for b_limb to be maxInt(Limb),
        // b_borrow would need to equal 1.

        // x & y can only clear bits, meaning x & y <= x and x & y <= y. This implies that
        // for x = a - 1 and y = b - 1, the +1 term would never cause an overflow.
        assert(r_carry == 0);

        // With b = 0 and b_borrow = 0 we get (-a - 1) & (0 - 0) = (-a - 1) & 0 = 0.
        // Omit setting the upper bytes, just deal with those when calling llsignedor.
        return false;
    }
}

// r = a & b with 2s complement semantics.
// r may alias.
// a and b must not be 0.
// Returns `true` when the result is positive.
// We assume `a.len >= b.len` here, so:
// 1. when b is positive, r requires at least `b.len` limbs of storage,
// 2. when b is negative but a is positive, r requires at least `a.len` limbs of storage,
// 3. when both a and b are negative, r requires at least `a.len + 1` limbs of storage.
fn llsignedand(r: []Limb, a: []const Limb, a_positive: bool, b: []const Limb, b_positive: bool) bool {
    assert(a.len != 0 and b.len != 0);
    assert(a.len >= b.len);
    assert(r.len >= if (b_positive) b.len else if (a_positive) a.len else a.len + 1);

    if (a_positive and b_positive) {
        // Trivial case, result is positive.
        var i: usize = 0;
        while (i < b.len) : (i += 1) {
            r[i] = a[i] & b[i];
        }

        // With b = 0 we have a & 0 = 0, so the upper bytes are zero.
        // Omit setting them here and simply discard them whenever
        // llsignedand is called.

        return true;
    } else if (!a_positive and b_positive) {
        // Result is positive.
        // r = (--a) & b
        //   = ~(-a - 1) & b

        var i: usize = 0;
        var a_borrow: u1 = 1;

        while (i < b.len) : (i += 1) {
            const ov = @subWithOverflow(a[i], a_borrow);
            a_borrow = ov[1];
            r[i] = ~ov[0] & b[i];
        }

        // With b = 0 we have ~(a - 1) & 0 = 0, so the upper bytes are zero.
        // Omit setting them here and simply discard them whenever
        // llsignedand is called.

        return true;
    } else if (a_positive and !b_positive) {
        // Result is positive.
        // r = a & (--b)
        //   = a & ~(-b - 1)

        var i: usize = 0;
        var b_borrow: u1 = 1;

        while (i < b.len) : (i += 1) {
            const ov = @subWithOverflow(b[i], b_borrow);
            b_borrow = ov[1];
            r[i] = a[i] & ~ov[0];
        }

        assert(b_borrow == 0); // b was 0

        // With b = 0 and b_borrow = 0 we have a & ~(0 - 0) = a & ~0 = a, so
        // the upper bytes are the same as those of a.

        while (i < a.len) : (i += 1) {
            r[i] = a[i];
        }

        return true;
    } else {
        // Result is negative.
        // r = (--a) & (--b)
        //   = ~(-a - 1) & ~(-b - 1)
        //   = ~((-a - 1) | (-b - 1))
        //   = -(((-a - 1) | (-b - 1)) + 1)

        var i: usize = 0;
        var a_borrow: u1 = 1;
        var b_borrow: u1 = 1;
        var r_carry: u1 = 1;

        while (i < b.len) : (i += 1) {
            const ov1 = @subWithOverflow(a[i], a_borrow);
            a_borrow = ov1[1];
            const ov2 = @subWithOverflow(b[i], b_borrow);
            b_borrow = ov2[1];
            const ov3 = @addWithOverflow(ov1[0] | ov2[0], r_carry);
            r[i] = ov3[0];
            r_carry = ov3[1];
        }

        // b is at least 1, so this should never underflow.
        assert(b_borrow == 0); // b was 0

        // With b = 0 and b_borrow = 0 we get (-a - 1) | (0 - 0) = (-a - 1) | 0 = -a - 1.
        while (i < a.len) : (i += 1) {
            const ov1 = @subWithOverflow(a[i], a_borrow);
            a_borrow = ov1[1];
            const ov2 = @addWithOverflow(ov1[0], r_carry);
            r[i] = ov2[0];
            r_carry = ov2[1];
        }

        assert(a_borrow == 0); // a was 0.

        // The final addition can overflow here, so we need to keep that in mind.
        r[i] = r_carry;

        return false;
    }
}

// r = a ^ b with 2s complement semantics.
// r may alias.
// a and b must not be -0.
// Returns `true` when the result is positive.
// If the sign of a and b is equal, then r requires at least `@max(a.len, b.len)` limbs are required.
// Otherwise, r requires at least `@max(a.len, b.len) + 1` limbs.
fn llsignedxor(r: []Limb, a: []const Limb, a_positive: bool, b: []const Limb, b_positive: bool) bool {
    assert(a.len != 0 and b.len != 0);
    assert(r.len >= a.len);
    assert(a.len >= b.len);

    // If a and b are positive, the result is positive and r = a ^ b.
    // If a negative, b positive, result is negative and we have
    // r = --(--a ^ b)
    //   = --(~(-a - 1) ^ b)
    //   = -(~(~(-a - 1) ^ b) + 1)
    //   = -(((-a - 1) ^ b) + 1)
    // Same if a is positive and b is negative, sides switched.
    // If both a and b are negative, the result is positive and we have
    // r = (--a) ^ (--b)
    //   = ~(-a - 1) ^ ~(-b - 1)
    //   = (-a - 1) ^ (-b - 1)
    // These operations can be made more generic as follows:
    // - If a is negative, subtract 1 from |a| before the xor.
    // - If b is negative, subtract 1 from |b| before the xor.
    // - if the result is supposed to be negative, add 1.

    var i: usize = 0;
    var a_borrow = @intFromBool(!a_positive);
    var b_borrow = @intFromBool(!b_positive);
    var r_carry = @intFromBool(a_positive != b_positive);

    while (i < b.len) : (i += 1) {
        const ov1 = @subWithOverflow(a[i], a_borrow);
        a_borrow = ov1[1];
        const ov2 = @subWithOverflow(b[i], b_borrow);
        b_borrow = ov2[1];
        const ov3 = @addWithOverflow(ov1[0] ^ ov2[0], r_carry);
        r[i] = ov3[0];
        r_carry = ov3[1];
    }

    while (i < a.len) : (i += 1) {
        const ov1 = @subWithOverflow(a[i], a_borrow);
        a_borrow = ov1[1];
        const ov2 = @addWithOverflow(ov1[0], r_carry);
        r[i] = ov2[0];
        r_carry = ov2[1];
    }

    // If both inputs don't share the same sign, an extra limb is required.
    if (a_positive != b_positive) {
        r[i] = r_carry;
    } else {
        assert(r_carry == 0);
    }

    assert(a_borrow == 0);
    assert(b_borrow == 0);

    return a_positive == b_positive;
}

/// r MUST NOT alias x.
fn llsquareBasecase(r: []Limb, x: []const Limb) void {
    const x_norm = x;
    assert(r.len >= 2 * x_norm.len + 1);
    assert(!slicesOverlap(r, x));

    // Compute the square of a N-limb bigint with only (N^2 + N)/2
    // multiplications by exploiting the symmetry of the coefficients around the
    // diagonal:
    //
    //           a   b   c *
    //           a   b   c =
    // -------------------
    //          ca  cb  cc +
    //      ba  bb  bc     +
    //  aa  ab  ac
    //
    // Note that:
    //  - Each mixed-product term appears twice for each column,
    //  - Squares are always in the 2k (0 <= k < N) column

    for (x_norm, 0..) |v, i| {
        // Accumulate all the x[i]*x[j] (with x!=j) products
        const overflow = llmulLimb(.add, r[2 * i + 1 ..], x_norm[i + 1 ..], v);
        assert(!overflow);
    }

    // Each product appears twice, multiply by 2
    _ = llshl(r, r[0 .. 2 * x_norm.len], 1);

    for (x_norm, 0..) |v, i| {
        // Compute and add the squares
        const overflow = llmulLimb(.add, r[2 * i ..], x[i..][0..1], v);
        assert(!overflow);
    }
}

/// Knuth 4.6.3
fn llpow(r: []Limb, a: []const Limb, b: u32, tmp_limbs: []Limb) void {
    var tmp1: []Limb = undefined;
    var tmp2: []Limb = undefined;

    // Multiplication requires no aliasing between the operand and the result
    // variable, use the output limbs and another temporary set to overcome this
    // limitation.
    // The initial assignment makes the result end in `r` so an extra memory
    // copy is saved, each 1 flips the index twice so it's only the zeros that
    // matter.
    const b_leading_zeros = @clz(b);
    const exp_zeros = @popCount(~b) - b_leading_zeros;
    if (exp_zeros & 1 != 0) {
        tmp1 = tmp_limbs;
        tmp2 = r;
    } else {
        tmp1 = r;
        tmp2 = tmp_limbs;
    }

    @memcpy(tmp1[0..a.len], a);
    @memset(tmp1[a.len..], 0);

    // Scan the exponent as a binary number, from left to right, dropping the
    // most significant bit set.
    // Square the result if the current bit is zero, square and multiply by a if
    // it is one.
    const exp_bits = 32 - 1 - b_leading_zeros;
    var exp = b << @as(u5, @intCast(1 + b_leading_zeros));

    var i: usize = 0;
    while (i < exp_bits) : (i += 1) {
        // Square
        @memset(tmp2, 0);
        llsquareBasecase(tmp2, tmp1[0..llnormalize(tmp1)]);
        mem.swap([]Limb, &tmp1, &tmp2);
        // Multiply by a
        const ov = @shlWithOverflow(exp, 1);
        exp = ov[0];
        if (ov[1] != 0) {
            @memset(tmp2, 0);
            llmulacc(.add, null, tmp2, tmp1[0..llnormalize(tmp1)], a);
            mem.swap([]Limb, &tmp1, &tmp2);
        }
    }
}

// Storage must live for the lifetime of the returned value
fn fixedIntFromSignedDoubleLimb(A: SignedDoubleLimb, storage: []Limb) Mutable {
    assert(storage.len >= 2);

    const A_is_positive = A >= 0;
    const Au = @as(DoubleLimb, @intCast(if (A < 0) -A else A));
    storage[0] = @as(Limb, @truncate(Au));
    storage[1] = @as(Limb, @truncate(Au >> limb_bits));
    return .{
        .limbs = storage[0..2],
        .positive = A_is_positive,
        .len = 2,
    };
}

fn slicesOverlap(a: []const Limb, b: []const Limb) bool {
    // there is no overlap if a.ptr + a.len <= b.ptr or b.ptr + b.len <= a.ptr
    return @intFromPtr(a.ptr + a.len) > @intFromPtr(b.ptr) and @intFromPtr(b.ptr + b.len) > @intFromPtr(a.ptr);
}

test {
    _ = @import("int_test.zig");
}

const testing_allocator = std.testing.allocator;
test "llshl shift by whole number of limb" {
    const padding = std.math.maxInt(Limb);

    var r: [10]Limb = @splat(padding);

    const A: Limb = @truncate(0xCCCCCCCCCCCCCCCCCCCCCCC);
    const B: Limb = @truncate(0x22222222222222222222222);

    const data = [2]Limb{ A, B };
    for (0..9) |i| {
        @memset(&r, padding);
        const len = llshl(&r, &data, i * @bitSizeOf(Limb));

        try std.testing.expectEqual(i + 2, len);
        try std.testing.expectEqualSlices(Limb, &data, r[i .. i + 2]);
        for (r[0..i]) |x|
            try std.testing.expectEqual(0, x);
        for (r[i + 2 ..]) |x|
            try std.testing.expectEqual(padding, x);
    }
}

test llshl {
    if (limb_bits != 64) return error.SkipZigTest;

    // 1 << 63
    const left_one = 0x8000000000000000;
    const maxint: Limb = 0xFFFFFFFFFFFFFFFF;

    // zig fmt: off
    try testOneShiftCase(.llshl, .{0,  &.{0},                               &.{0}});
    try testOneShiftCase(.llshl, .{0,  &.{1},                               &.{1}});
    try testOneShiftCase(.llshl, .{0,  &.{125484842448},                    &.{125484842448}});
    try testOneShiftCase(.llshl, .{0,  &.{0xdeadbeef},                      &.{0xdeadbeef}});
    try testOneShiftCase(.llshl, .{0,  &.{maxint},                          &.{maxint}});
    try testOneShiftCase(.llshl, .{0,  &.{left_one},                        &.{left_one}});
    try testOneShiftCase(.llshl, .{0,  &.{0, 1},                            &.{0, 1}});
    try testOneShiftCase(.llshl, .{0,  &.{1, 2},                            &.{1, 2}});
    try testOneShiftCase(.llshl, .{0,  &.{left_one, 1},                     &.{left_one, 1}});
    try testOneShiftCase(.llshl, .{1,  &.{0},                               &.{0}});
    try testOneShiftCase(.llshl, .{1,  &.{2},                               &.{1}});
    try testOneShiftCase(.llshl, .{1,  &.{250969684896},                    &.{125484842448}});
    try testOneShiftCase(.llshl, .{1,  &.{0x1bd5b7dde},                     &.{0xdeadbeef}});
    try testOneShiftCase(.llshl, .{1,  &.{0xfffffffffffffffe, 1},           &.{maxint}});
    try testOneShiftCase(.llshl, .{1,  &.{0, 1},                            &.{left_one}});
    try testOneShiftCase(.llshl, .{1,  &.{0, 2},                            &.{0, 1}});
    try testOneShiftCase(.llshl, .{1,  &.{2, 4},                            &.{1, 2}});
    try testOneShiftCase(.llshl, .{1,  &.{0, 3},                            &.{left_one, 1}});
    try testOneShiftCase(.llshl, .{5,  &.{32},                              &.{1}});
    try testOneShiftCase(.llshl, .{5,  &.{4015514958336},                   &.{125484842448}});
    try testOneShiftCase(.llshl, .{5,  &.{0x1bd5b7dde0},                    &.{0xdeadbeef}});
    try testOneShiftCase(.llshl, .{5,  &.{0xffffffffffffffe0, 0x1f},        &.{maxint}});
    try testOneShiftCase(.llshl, .{5,  &.{0, 16},                           &.{left_one}});
    try testOneShiftCase(.llshl, .{5,  &.{0, 32},                           &.{0, 1}});
    try testOneShiftCase(.llshl, .{5,  &.{32, 64},                          &.{1, 2}});
    try testOneShiftCase(.llshl, .{5,  &.{0, 48},                           &.{left_one, 1}});
    try testOneShiftCase(.llshl, .{64, &.{0, 1},                            &.{1}});
    try testOneShiftCase(.llshl, .{64, &.{0, 125484842448},                 &.{125484842448}});
    try testOneShiftCase(.llshl, .{64, &.{0, 0xdeadbeef},                   &.{0xdeadbeef}});
    try testOneShiftCase(.llshl, .{64, &.{0, maxint},                       &.{maxint}});
    try testOneShiftCase(.llshl, .{64, &.{0, left_one},                     &.{left_one}});
    try testOneShiftCase(.llshl, .{64, &.{0, 0, 1},                         &.{0, 1}});
    try testOneShiftCase(.llshl, .{64, &.{0, 1, 2},                         &.{1, 2}});
    try testOneShiftCase(.llshl, .{64, &.{0, left_one, 1},                  &.{left_one, 1}});
    try testOneShiftCase(.llshl, .{35, &.{0x800000000},                     &.{1}});
    try testOneShiftCase(.llshl, .{35, &.{13534986488655118336, 233},       &.{125484842448}});
    try testOneShiftCase(.llshl, .{35, &.{0xf56df77800000000, 6},           &.{0xdeadbeef}});
    try testOneShiftCase(.llshl, .{35, &.{0xfffffff800000000, 0x7ffffffff}, &.{maxint}});
    try testOneShiftCase(.llshl, .{35, &.{0, 17179869184},                  &.{left_one}});
    try testOneShiftCase(.llshl, .{35, &.{0, 0x800000000},                  &.{0, 1}});
    try testOneShiftCase(.llshl, .{35, &.{0x800000000, 0x1000000000},       &.{1, 2}});
    try testOneShiftCase(.llshl, .{35, &.{0, 0xc00000000},                  &.{left_one, 1}});
    try testOneShiftCase(.llshl, .{70, &.{0, 64},                           &.{1}});
    try testOneShiftCase(.llshl, .{70, &.{0, 8031029916672},                &.{125484842448}});
    try testOneShiftCase(.llshl, .{70, &.{0, 0x37ab6fbbc0},                 &.{0xdeadbeef}});
    try testOneShiftCase(.llshl, .{70, &.{0, 0xffffffffffffffc0, 63},       &.{maxint}});
    try testOneShiftCase(.llshl, .{70, &.{0, 0, 32},                        &.{left_one}});
    try testOneShiftCase(.llshl, .{70, &.{0, 0, 64},                        &.{0, 1}});
    try testOneShiftCase(.llshl, .{70, &.{0, 64, 128},                      &.{1, 2}});
    try testOneShiftCase(.llshl, .{70, &.{0, 0, 0x60},                      &.{left_one, 1}});
    // zig fmt: on
}

test "llshl shift 0" {
    const n = @bitSizeOf(Limb);
    if (n <= 20) return error.SkipZigTest;

    // zig fmt: off
    try testOneShiftCase(.llshl, .{0,   &.{0},    &.{0}});
    try testOneShiftCase(.llshl, .{1,   &.{0},    &.{0}});
    try testOneShiftCase(.llshl, .{5,   &.{0},    &.{0}});
    try testOneShiftCase(.llshl, .{13,  &.{0},    &.{0}});
    try testOneShiftCase(.llshl, .{20,  &.{0},    &.{0}});
    try testOneShiftCase(.llshl, .{0,   &.{0, 0}, &.{0, 0}});
    try testOneShiftCase(.llshl, .{2,   &.{0, 0}, &.{0, 0}});
    try testOneShiftCase(.llshl, .{7,   &.{0, 0}, &.{0, 0}});
    try testOneShiftCase(.llshl, .{11,  &.{0, 0}, &.{0, 0}});
    try testOneShiftCase(.llshl, .{19,  &.{0, 0}, &.{0, 0}});

    try testOneShiftCase(.llshl, .{0,   &.{0},                &.{0}});
    try testOneShiftCase(.llshl, .{n,   &.{0, 0},             &.{0}});
    try testOneShiftCase(.llshl, .{2*n, &.{0, 0, 0},          &.{0}});
    try testOneShiftCase(.llshl, .{3*n, &.{0, 0, 0, 0},       &.{0}});
    try testOneShiftCase(.llshl, .{4*n, &.{0, 0, 0, 0, 0},    &.{0}});
    try testOneShiftCase(.llshl, .{0,   &.{0, 0},             &.{0, 0}});
    try testOneShiftCase(.llshl, .{n,   &.{0, 0, 0},          &.{0, 0}});
    try testOneShiftCase(.llshl, .{2*n, &.{0, 0, 0, 0},       &.{0, 0}});
    try testOneShiftCase(.llshl, .{3*n, &.{0, 0, 0, 0, 0},    &.{0, 0}});
    try testOneShiftCase(.llshl, .{4*n, &.{0, 0, 0, 0, 0, 0}, &.{0, 0}});
    // zig fmt: on
}

test "llshr shift 0" {
    const n = @bitSizeOf(Limb);

    // zig fmt: off
    try testOneShiftCase(.llshr, .{0,   &.{0},    &.{0}});
    try testOneShiftCase(.llshr, .{1,   &.{0},    &.{0}});
    try testOneShiftCase(.llshr, .{5,   &.{0},    &.{0}});
    try testOneShiftCase(.llshr, .{13,  &.{0},    &.{0}});
    try testOneShiftCase(.llshr, .{20,  &.{0},    &.{0}});
    try testOneShiftCase(.llshr, .{0,   &.{0, 0}, &.{0, 0}});
    try testOneShiftCase(.llshr, .{2,   &.{0},    &.{0, 0}});
    try testOneShiftCase(.llshr, .{7,   &.{0},    &.{0, 0}});
    try testOneShiftCase(.llshr, .{11,  &.{0},    &.{0, 0}});
    try testOneShiftCase(.llshr, .{19,  &.{0},    &.{0, 0}});

    try testOneShiftCase(.llshr, .{n,   &.{0}, &.{0}});
    try testOneShiftCase(.llshr, .{2*n, &.{0}, &.{0}});
    try testOneShiftCase(.llshr, .{3*n, &.{0}, &.{0}});
    try testOneShiftCase(.llshr, .{4*n, &.{0}, &.{0}});
    try testOneShiftCase(.llshr, .{n,   &.{0}, &.{0, 0}});
    try testOneShiftCase(.llshr, .{2*n, &.{0}, &.{0, 0}});
    try testOneShiftCase(.llshr, .{3*n, &.{0}, &.{0, 0}});
    try testOneShiftCase(.llshr, .{4*n, &.{0}, &.{0, 0}});

    try testOneShiftCase(.llshr, .{1,  &.{}, &.{}});
    try testOneShiftCase(.llshr, .{2,  &.{}, &.{}});
    try testOneShiftCase(.llshr, .{64, &.{}, &.{}});
    // zig fmt: on
}

test "llshr to 0" {
    const n = @bitSizeOf(Limb);
    if (n != 64 and n != 32) return error.SkipZigTest;

    // zig fmt: off
    try testOneShiftCase(.llshr, .{1,   &.{0}, &.{0}});
    try testOneShiftCase(.llshr, .{1,   &.{0}, &.{1}});
    try testOneShiftCase(.llshr, .{5,   &.{0}, &.{1}});
    try testOneShiftCase(.llshr, .{65,  &.{0}, &.{0, 1}});
    try testOneShiftCase(.llshr, .{193, &.{0}, &.{0, 0, std.math.maxInt(Limb)}});
    try testOneShiftCase(.llshr, .{193, &.{0}, &.{std.math.maxInt(Limb), 1, std.math.maxInt(Limb)}});
    try testOneShiftCase(.llshr, .{193, &.{0}, &.{0xdeadbeef, 0xabcdefab, 0x1234}});
    // zig fmt: on
}

test "llshr single" {
    if (limb_bits != 64) return error.SkipZigTest;

    // 1 << 63
    const left_one = 0x8000000000000000;
    const maxint: Limb = 0xFFFFFFFFFFFFFFFF;

    // zig fmt: off
    try testOneShiftCase(.llshr, .{0,  &.{0},                  &.{0}});
    try testOneShiftCase(.llshr, .{0,  &.{1},                  &.{1}});
    try testOneShiftCase(.llshr, .{0,  &.{125484842448},       &.{125484842448}});
    try testOneShiftCase(.llshr, .{0,  &.{0xdeadbeef},         &.{0xdeadbeef}});
    try testOneShiftCase(.llshr, .{0,  &.{maxint},             &.{maxint}});
    try testOneShiftCase(.llshr, .{0,  &.{left_one},           &.{left_one}});
    try testOneShiftCase(.llshr, .{1,  &.{0},                  &.{0}});
    try testOneShiftCase(.llshr, .{1,  &.{1},                  &.{2}});
    try testOneShiftCase(.llshr, .{1,  &.{62742421224},        &.{125484842448}});
    try testOneShiftCase(.llshr, .{1,  &.{62742421223},        &.{125484842447}});
    try testOneShiftCase(.llshr, .{1,  &.{0x6f56df77},         &.{0xdeadbeef}});
    try testOneShiftCase(.llshr, .{1,  &.{0x7fffffffffffffff}, &.{maxint}});
    try testOneShiftCase(.llshr, .{1,  &.{0x4000000000000000}, &.{left_one}});
    try testOneShiftCase(.llshr, .{8,  &.{1},                  &.{256}});
    try testOneShiftCase(.llshr, .{8,  &.{490175165},          &.{125484842448}});
    try testOneShiftCase(.llshr, .{8,  &.{0xdeadbe},           &.{0xdeadbeef}});
    try testOneShiftCase(.llshr, .{8,  &.{0xffffffffffffff},   &.{maxint}});
    try testOneShiftCase(.llshr, .{8,  &.{0x80000000000000},   &.{left_one}});
    // zig fmt: on
}

test llshr {
    if (limb_bits != 64) return error.SkipZigTest;

    // 1 << 63
    const left_one = 0x8000000000000000;
    const maxint: Limb = 0xFFFFFFFFFFFFFFFF;

    // zig fmt: off
    try testOneShiftCase(.llshr, .{0,  &.{0, 0},                           &.{0, 0}});
    try testOneShiftCase(.llshr, .{0,  &.{0, 1},                           &.{0, 1}});
    try testOneShiftCase(.llshr, .{0,  &.{15, 1},                          &.{15, 1}});
    try testOneShiftCase(.llshr, .{0,  &.{987656565, 123456789456},        &.{987656565, 123456789456}});
    try testOneShiftCase(.llshr, .{0,  &.{0xfeebdaed, 0xdeadbeef},         &.{0xfeebdaed, 0xdeadbeef}});
    try testOneShiftCase(.llshr, .{0,  &.{1, maxint},                      &.{1, maxint}});
    try testOneShiftCase(.llshr, .{0,  &.{0, left_one},                    &.{0, left_one}});
    try testOneShiftCase(.llshr, .{1,  &.{0},                              &.{0, 0}});
    try testOneShiftCase(.llshr, .{1,  &.{left_one},                       &.{0, 1}});
    try testOneShiftCase(.llshr, .{1,  &.{0x8000000000000007},             &.{15, 1}});
    try testOneShiftCase(.llshr, .{1,  &.{493828282, 61728394728},         &.{987656565, 123456789456}});
    try testOneShiftCase(.llshr, .{1,  &.{0x800000007f75ed76, 0x6f56df77}, &.{0xfeebdaed, 0xdeadbeef}});
    try testOneShiftCase(.llshr, .{1,  &.{left_one, 0x7fffffffffffffff},   &.{1, maxint}});
    try testOneShiftCase(.llshr, .{1,  &.{0, 0x4000000000000000},          &.{0, left_one}});
    try testOneShiftCase(.llshr, .{64, &.{0},                              &.{0, 0}});
    try testOneShiftCase(.llshr, .{64, &.{1},                              &.{0, 1}});
    try testOneShiftCase(.llshr, .{64, &.{1},                              &.{15, 1}});
    try testOneShiftCase(.llshr, .{64, &.{123456789456},                   &.{987656565, 123456789456}});
    try testOneShiftCase(.llshr, .{64, &.{0xdeadbeef},                     &.{0xfeebdaed, 0xdeadbeef}});
    try testOneShiftCase(.llshr, .{64, &.{maxint},                         &.{1, maxint}});
    try testOneShiftCase(.llshr, .{64, &.{left_one},                       &.{0, left_one}});
    try testOneShiftCase(.llshr, .{72, &.{0},                              &.{0, 0}});
    try testOneShiftCase(.llshr, .{72, &.{0},                              &.{0, 1}});
    try testOneShiftCase(.llshr, .{72, &.{0},                              &.{15, 1}});
    try testOneShiftCase(.llshr, .{72, &.{482253083},                      &.{987656565, 123456789456}});
    try testOneShiftCase(.llshr, .{72, &.{0xdeadbe},                       &.{0xfeebdaed, 0xdeadbeef}});
    try testOneShiftCase(.llshr, .{72, &.{0xffffffffffffff},               &.{1, maxint}});
    try testOneShiftCase(.llshr, .{72, &.{0x80000000000000},               &.{0, left_one}});
    // zig fmt: on
}

const Case = struct { usize, []const Limb, []const Limb };

fn testOneShiftCase(comptime function: enum { llshr, llshl }, case: Case) !void {
    const func = if (function == .llshl) llshl else llshr;
    const shift_direction = if (function == .llshl) -1 else 1;

    try testOneShiftCaseNoAliasing(func, case);
    try testOneShiftCaseAliasing(func, case, shift_direction);
}

fn testOneShiftCaseNoAliasing(func: fn ([]Limb, []const Limb, usize) usize, case: Case) !void {
    const padding = std.math.maxInt(Limb);
    var r: [20]Limb = @splat(padding);

    const shift = case[0];
    const expected = case[1];
    const data = case[2];

    std.debug.assert(expected.len <= 20);

    const len = func(&r, data, shift);

    try std.testing.expectEqual(expected.len, len);
    try std.testing.expectEqualSlices(Limb, expected, r[0..len]);
    try std.testing.expect(mem.allEqual(Limb, r[len..], padding));
}

fn testOneShiftCaseAliasing(func: fn ([]Limb, []const Limb, usize) usize, case: Case, shift_direction: isize) !void {
    const padding = std.math.maxInt(Limb);
    var r: [60]Limb = @splat(padding);
    const base = 20;

    assert(shift_direction == 1 or shift_direction == -1);

    for (0..10) |limb_shift| {
        const shift = case[0];
        const expected = case[1];
        const data = case[2];

        std.debug.assert(expected.len <= 20);

        @memset(&r, padding);
        const final_limb_base: usize = @intCast(base + shift_direction * @as(isize, @intCast(limb_shift)));
        const written_data = r[final_limb_base..][0..data.len];
        @memcpy(written_data, data);

        const len = func(r[base..], written_data, shift);

        try std.testing.expectEqual(expected.len, len);
        try std.testing.expectEqualSlices(Limb, expected, r[base .. base + len]);
    }
}
const std = @import("../../std.zig");
const builtin = @import("builtin");
const debug = std.debug;
const math = std.math;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

const Limb = std.math.big.Limb;
const DoubleLimb = std.math.big.DoubleLimb;
const Int = std.math.big.int.Managed;
const IntConst = std.math.big.int.Const;

/// An arbitrary-precision rational number.
///
/// Memory is allocated as needed for operations to ensure full precision is kept. The precision
/// of a Rational is only bounded by memory.
///
/// Rational's are always normalized. That is, for a Rational r = p/q where p and q are integers,
/// gcd(p, q) = 1 always.
///
/// TODO rework this to store its own allocator and use a non-managed big int, to avoid double
/// allocator storage.
pub const Rational = struct {
    /// Numerator. Determines the sign of the Rational.
    p: Int,

    /// Denominator. Sign is ignored.
    q: Int,

    /// Create a new Rational. A small amount of memory will be allocated on initialization.
    /// This will be 2 * Int.default_capacity.
    pub fn init(a: Allocator) !Rational {
        var p = try Int.init(a);
        errdefer p.deinit();
        return Rational{
            .p = p,
            .q = try Int.initSet(a, 1),
        };
    }

    /// Frees all memory associated with a Rational.
    pub fn deinit(self: *Rational) void {
        self.p.deinit();
        self.q.deinit();
    }

    /// Set a Rational from a primitive integer type.
    pub fn setInt(self: *Rational, a: anytype) !void {
        try self.p.set(a);
        try self.q.set(1);
    }

    /// Set a Rational from a string of the form `A/B` where A and B are base-10 integers.
    pub fn setFloatString(self: *Rational, str: []const u8) !void {
        // TODO: Accept a/b fractions and exponent form
        if (str.len == 0) {
            return error.InvalidFloatString;
        }

        const State = enum {
            Integer,
            Fractional,
        };

        var state = State.Integer;
        var point: ?usize = null;

        var start: usize = 0;
        if (str[0] == '-') {
            start += 1;
        }

        for (str, 0..) |c, i| {
            switch (state) {
                State.Integer => {
                    switch (c) {
                        '.' => {
                            state = State.Fractional;
                            point = i;
                        },
                        '0'...'9' => {
                            // okay
                        },
                        else => {
                            return error.InvalidFloatString;
                        },
                    }
                },
                State.Fractional => {
                    switch (c) {
                        '0'...'9' => {
                            // okay
                        },
                        else => {
                            return error.InvalidFloatString;
                        },
                    }
                },
            }
        }

        // TODO: batch the multiplies by 10
        if (point) |i| {
            try self.p.setString(10, str[0..i]);

            const base = IntConst{ .limbs = &[_]Limb{10}, .positive = true };
            var local_buf: [@sizeOf(Limb) * Int.default_capacity]u8 align(@alignOf(Limb)) = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&local_buf);
            const base_managed = try base.toManaged(fba.allocator());

            var j: usize = start;
            while (j < str.len - i - 1) : (j += 1) {
                try self.p.ensureMulCapacity(self.p.toConst(), base);
                try self.p.mul(&self.p, &base_managed);
            }

            try self.q.setString(10, str[i + 1 ..]);
            try self.p.add(&self.p, &self.q);

            try self.q.set(1);
            var k: usize = i + 1;
            while (k < str.len) : (k += 1) {
                try self.q.mul(&self.q, &base_managed);
            }

            try self.reduce();
        } else {
            try self.p.setString(10, str[0..]);
            try self.q.set(1);
        }
    }

    /// Set a Rational from a floating-point value. The rational will have enough precision to
    /// completely represent the provided float.
    pub fn setFloat(self: *Rational, comptime T: type, f: T) !void {
        // Translated from golang.go/src/math/big/rat.go.
        debug.assert(@typeInfo(T) == .float);

        const UnsignedInt = std.meta.Int(.unsigned, @typeInfo(T).float.bits);
        const f_bits = @as(UnsignedInt, @bitCast(f));

        const exponent_bits = math.floatExponentBits(T);
        const exponent_bias = (1 << (exponent_bits - 1)) - 1;
        const mantissa_bits = math.floatMantissaBits(T);

        const exponent_mask = (1 << exponent_bits) - 1;
        const mantissa_mask = (1 << mantissa_bits) - 1;

        var exponent = @as(i16, @intCast((f_bits >> mantissa_bits) & exponent_mask));
        var mantissa = f_bits & mantissa_mask;

        switch (exponent) {
            exponent_mask => {
                return error.NonFiniteFloat;
            },
            0 => {
                // denormal
                exponent -= exponent_bias - 1;
            },
            else => {
                // normal
                mantissa |= 1 << mantissa_bits;
                exponent -= exponent_bias;
            },
        }

        var shift: i16 = mantissa_bits - exponent;

        // factor out powers of two early from rational
        while (mantissa & 1 == 0 and shift > 0) {
            mantissa >>= 1;
            shift -= 1;
        }

        try self.p.set(mantissa);
        self.p.setSign(f >= 0);

        try self.q.set(1);
        if (shift >= 0) {
            try self.q.shiftLeft(&self.q, @as(usize, @intCast(shift)));
        } else {
            try self.p.shiftLeft(&self.p, @as(usize, @intCast(-shift)));
        }

        try self.reduce();
    }

    /// Return a floating-point value that is the closest value to a Rational.
    ///
    /// The result may not be exact if the Rational is too precise or too large for the
    /// target type.
    pub fn toFloat(self: Rational, comptime T: type) !T {
        // Translated from golang.go/src/math/big/rat.go.
        // TODO: Indicate whether the result is not exact.
        debug.assert(@typeInfo(T) == .float);

        const fsize = @typeInfo(T).float.bits;
        const BitReprType = std.meta.Int(.unsigned, fsize);

        const msize = math.floatMantissaBits(T);
        const msize1 = msize + 1;
        const msize2 = msize1 + 1;

        const esize = math.floatExponentBits(T);
        const ebias = (1 << (esize - 1)) - 1;
        const emin = 1 - ebias;

        if (self.p.eqlZero()) {
            return 0;
        }

        // 1. left-shift a or sub so that a/b is in [1 << msize1, 1 << (msize2 + 1)]
        var exp = @as(isize, @intCast(self.p.bitCountTwosComp())) - @as(isize, @intCast(self.q.bitCountTwosComp()));

        var a2 = try self.p.clone();
        defer a2.deinit();

        var b2 = try self.q.clone();
        defer b2.deinit();

        const shift = msize2 - exp;
        if (shift >= 0) {
            try a2.shiftLeft(&a2, @as(usize, @intCast(shift)));
        } else {
            try b2.shiftLeft(&b2, @as(usize, @intCast(-shift)));
        }

        // 2. compute quotient and remainder
        var q = try Int.init(self.p.allocator);
        defer q.deinit();

        // unused
        var r = try Int.init(self.p.allocator);
        defer r.deinit();

        try Int.divTrunc(&q, &r, &a2, &b2);

        var mantissa = extractLowBits(q, BitReprType);
        var have_rem = r.len() > 0;

        // 3. q didn't fit in msize2 bits, redo division b2 << 1
        if (mantissa >> msize2 == 1) {
            if (mantissa & 1 == 1) {
                have_rem = true;
            }
            mantissa >>= 1;
            exp += 1;
        }
        if (mantissa >> msize1 != 1) {
            // NOTE: This can be hit if the limb size is small (u8/16).
            @panic("unexpected bits in result");
        }

        // 4. Rounding
        if (emin - msize <= exp and exp <= emin) {
            // denormal
            const shift1 = @as(math.Log2Int(BitReprType), @intCast(emin - (exp - 1)));
            const lost_bits = mantissa & ((@as(BitReprType, @intCast(1)) << shift1) - 1);
            have_rem = have_rem or lost_bits != 0;
            mantissa >>= shift1;
            exp = 2 - ebias;
        }

        // round q using round-half-to-even
        var exact = !have_rem;
        if (mantissa & 1 != 0) {
            exact = false;
            if (have_rem or (mantissa & 2 != 0)) {
                mantissa += 1;
                if (mantissa >= 1 << msize2) {
                    // 11...1 => 100...0
                    mantissa >>= 1;
                    exp += 1;
                }
            }
        }
        mantissa >>= 1;

        const f = math.scalbn(@as(T, @floatFromInt(mantissa)), @as(i32, @intCast(exp - msize1)));
        if (math.isInf(f)) {
            exact = false;
        }

        return if (self.p.isPositive()) f else -f;
    }

    /// Set a rational from an integer ratio.
    pub fn setRatio(self: *Rational, p: anytype, q: anytype) !void {
        try self.p.set(p);
        try self.q.set(q);

        self.p.setSign(@intFromBool(self.p.isPositive()) ^ @intFromBool(self.q.isPositive()) == 0);
        self.q.setSign(true);

        try self.reduce();

        if (self.q.eqlZero()) {
            @panic("cannot set rational with denominator = 0");
        }
    }

    /// Set a Rational directly from an Int.
    pub fn copyInt(self: *Rational, a: Int) !void {
        try self.p.copy(a.toConst());
        try self.q.set(1);
    }

    /// Set a Rational directly from a ratio of two Int's.
    pub fn copyRatio(self: *Rational, a: Int, b: Int) !void {
        try self.p.copy(a.toConst());
        try self.q.copy(b.toConst());

        self.p.setSign(@intFromBool(self.p.isPositive()) ^ @intFromBool(self.q.isPositive()) == 0);
        self.q.setSign(true);

        try self.reduce();
    }

    /// Make a Rational positive.
    pub fn abs(r: *Rational) void {
        r.p.abs();
    }

    /// Negate the sign of a Rational.
    pub fn negate(r: *Rational) void {
        r.p.negate();
    }

    /// Efficiently swap a Rational with another. This swaps the limb pointers and a full copy is not
    /// performed. The address of the limbs field will not be the same after this function.
    pub fn swap(r: *Rational, other: *Rational) void {
        r.p.swap(&other.p);
        r.q.swap(&other.q);
    }

    /// Returns math.Order.lt, math.Order.eq, math.Order.gt if a < b, a == b or
    /// a > b respectively.
    pub fn order(a: Rational, b: Rational) !math.Order {
        return cmpInternal(a, b, false);
    }

    /// Returns math.Order.lt, math.Order.eq, math.Order.gt if |a| < |b|, |a| ==
    /// |b| or |a| > |b| respectively.
    pub fn orderAbs(a: Rational, b: Rational) !math.Order {
        return cmpInternal(a, b, true);
    }

    // p/q > x/y iff p*y > x*q
    fn cmpInternal(a: Rational, b: Rational, is_abs: bool) !math.Order {
        // TODO: Would a div compare algorithm of sorts be viable and quicker? Can we avoid
        // the memory allocations here?
        var q = try Int.init(a.p.allocator);
        defer q.deinit();

        var p = try Int.init(b.p.allocator);
        defer p.deinit();

        try q.mul(&a.p, &b.q);
        try p.mul(&b.p, &a.q);

        return if (is_abs) q.orderAbs(p) else q.order(p);
    }

    /// rma = a + b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn add(rma: *Rational, a: Rational, b: Rational) !void {
        var r = rma;
        var aliased = rma.p.limbs.ptr == a.p.limbs.ptr or rma.p.limbs.ptr == b.p.limbs.ptr;

        var sr: Rational = undefined;
        if (aliased) {
            sr = try Rational.init(rma.p.allocator);
            r = &sr;
            aliased = true;
        }
        defer if (aliased) {
            rma.swap(r);
            r.deinit();
        };

        try r.p.mul(&a.p, &b.q);
        try r.q.mul(&b.p, &a.q);
        try r.p.add(&r.p, &r.q);

        try r.q.mul(&a.q, &b.q);
        try r.reduce();
    }

    /// rma = a - b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn sub(rma: *Rational, a: Rational, b: Rational) !void {
        var r = rma;
        var aliased = rma.p.limbs.ptr == a.p.limbs.ptr or rma.p.limbs.ptr == b.p.limbs.ptr;

        var sr: Rational = undefined;
        if (aliased) {
            sr = try Rational.init(rma.p.allocator);
            r = &sr;
            aliased = true;
        }
        defer if (aliased) {
            rma.swap(r);
            r.deinit();
        };

        try r.p.mul(&a.p, &b.q);
        try r.q.mul(&b.p, &a.q);
        try r.p.sub(&r.p, &r.q);

        try r.q.mul(&a.q, &b.q);
        try r.reduce();
    }

    /// rma = a * b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn mul(r: *Rational, a: Rational, b: Rational) !void {
        try r.p.mul(&a.p, &b.p);
        try r.q.mul(&a.q, &b.q);
        try r.reduce();
    }

    /// rma = a / b.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn div(r: *Rational, a: Rational, b: Rational) !void {
        if (b.p.eqlZero()) {
            @panic("division by zero");
        }

        try r.p.mul(&a.p, &b.q);
        try r.q.mul(&b.p, &a.q);
        try r.reduce();
    }

    /// Invert the numerator and denominator fields of a Rational. p/q => q/p.
    pub fn invert(r: *Rational) void {
        Int.swap(&r.p, &r.q);
    }

    // reduce r/q such that gcd(r, q) = 1
    fn reduce(r: *Rational) !void {
        var a = try Int.init(r.p.allocator);
        defer a.deinit();

        const sign = r.p.isPositive();
        r.p.abs();
        try a.gcd(&r.p, &r.q);
        r.p.setSign(sign);

        const one = IntConst{ .limbs = &[_]Limb{1}, .positive = true };
        if (a.toConst().order(one) != .eq) {
            var unused = try Int.init(r.p.allocator);
            defer unused.deinit();

            // TODO: divexact would be useful here
            // TODO: don't copy r.q for div
            try Int.divTrunc(&r.p, &unused, &r.p, &a);
            try Int.divTrunc(&r.q, &unused, &r.q, &a);
        }
    }
};

fn extractLowBits(a: Int, comptime T: type) T {
    debug.assert(@typeInfo(T) == .int);

    const t_bits = @typeInfo(T).int.bits;
    const limb_bits = @typeInfo(Limb).int.bits;
    if (t_bits <= limb_bits) {
        return @as(T, @truncate(a.limbs[0]));
    } else {
        var r: T = 0;
        comptime var i: usize = 0;

        // Remainder is always 0 since if t_bits >= limb_bits -> Limb | T and both
        // are powers of two.
        inline while (i < t_bits / limb_bits) : (i += 1) {
            r |= math.shl(T, a.limbs[i], i * limb_bits);
        }

        return r;
    }
}

test extractLowBits {
    var a = try Int.initSet(testing.allocator, 0x11112222333344441234567887654321);
    defer a.deinit();

    const a1 = extractLowBits(a, u8);
    try testing.expect(a1 == 0x21);

    const a2 = extractLowBits(a, u16);
    try testing.expect(a2 == 0x4321);

    const a3 = extractLowBits(a, u32);
    try testing.expect(a3 == 0x87654321);

    const a4 = extractLowBits(a, u64);
    try testing.expect(a4 == 0x1234567887654321);

    const a5 = extractLowBits(a, u128);
    try testing.expect(a5 == 0x11112222333344441234567887654321);
}

test "set" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.setInt(5);
    try testing.expect((try a.p.toInt(u32)) == 5);
    try testing.expect((try a.q.toInt(u32)) == 1);

    try a.setRatio(7, 3);
    try testing.expect((try a.p.toInt(u32)) == 7);
    try testing.expect((try a.q.toInt(u32)) == 3);

    try a.setRatio(9, 3);
    try testing.expect((try a.p.toInt(i32)) == 3);
    try testing.expect((try a.q.toInt(i32)) == 1);

    try a.setRatio(-9, 3);
    try testing.expect((try a.p.toInt(i32)) == -3);
    try testing.expect((try a.q.toInt(i32)) == 1);

    try a.setRatio(9, -3);
    try testing.expect((try a.p.toInt(i32)) == -3);
    try testing.expect((try a.q.toInt(i32)) == 1);

    try a.setRatio(-9, -3);
    try testing.expect((try a.p.toInt(i32)) == 3);
    try testing.expect((try a.q.toInt(i32)) == 1);
}

test "setFloat" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.setFloat(f64, 2.5);
    try testing.expect((try a.p.toInt(i32)) == 5);
    try testing.expect((try a.q.toInt(i32)) == 2);

    try a.setFloat(f32, -2.5);
    try testing.expect((try a.p.toInt(i32)) == -5);
    try testing.expect((try a.q.toInt(i32)) == 2);

    try a.setFloat(f32, 3.141593);

    //                = 3.14159297943115234375
    try testing.expect((try a.p.toInt(u32)) == 3294199);
    try testing.expect((try a.q.toInt(u32)) == 1048576);

    try a.setFloat(f64, 72.141593120712409172417410926841290461290467124);

    //                = 72.1415931207124145885245525278151035308837890625
    try testing.expect((try a.p.toInt(u128)) == 5076513310880537);
    try testing.expect((try a.q.toInt(u128)) == 70368744177664);
}

test "setFloatString" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.setFloatString("72.14159312071241458852455252781510353");

    //                  = 72.1415931207124145885245525278151035308837890625
    try testing.expect((try a.p.toInt(u128)) == 7214159312071241458852455252781510353);
    try testing.expect((try a.q.toInt(u128)) == 100000000000000000000000000000000000);
}

test "toFloat" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    // = 3.14159297943115234375
    try a.setRatio(3294199, 1048576);
    try testing.expect((try a.toFloat(f64)) == 3.14159297943115234375);

    // = 72.1415931207124145885245525278151035308837890625
    try a.setRatio(5076513310880537, 70368744177664);
    try testing.expect((try a.toFloat(f64)) == 72.141593120712409172417410926841290461290467124);
}

test "set/to Float round-trip" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const r = random.float(f64);
        try a.setFloat(f64, r);
        try testing.expect((try a.toFloat(f64)) == r);
    }
}

test "copy" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    var b = try Int.initSet(testing.allocator, 5);
    defer b.deinit();

    try a.copyInt(b);
    try testing.expect((try a.p.toInt(u32)) == 5);
    try testing.expect((try a.q.toInt(u32)) == 1);

    var c = try Int.initSet(testing.allocator, 7);
    defer c.deinit();
    var d = try Int.initSet(testing.allocator, 3);
    defer d.deinit();

    try a.copyRatio(c, d);
    try testing.expect((try a.p.toInt(u32)) == 7);
    try testing.expect((try a.q.toInt(u32)) == 3);

    var e = try Int.initSet(testing.allocator, 9);
    defer e.deinit();
    var f = try Int.initSet(testing.allocator, 3);
    defer f.deinit();

    try a.copyRatio(e, f);
    try testing.expect((try a.p.toInt(u32)) == 3);
    try testing.expect((try a.q.toInt(u32)) == 1);
}

test "negate" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.setInt(-50);
    try testing.expect((try a.p.toInt(i32)) == -50);
    try testing.expect((try a.q.toInt(i32)) == 1);

    a.negate();
    try testing.expect((try a.p.toInt(i32)) == 50);
    try testing.expect((try a.q.toInt(i32)) == 1);

    a.negate();
    try testing.expect((try a.p.toInt(i32)) == -50);
    try testing.expect((try a.q.toInt(i32)) == 1);
}

test "abs" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();

    try a.setInt(-50);
    try testing.expect((try a.p.toInt(i32)) == -50);
    try testing.expect((try a.q.toInt(i32)) == 1);

    a.abs();
    try testing.expect((try a.p.toInt(i32)) == 50);
    try testing.expect((try a.q.toInt(i32)) == 1);

    a.abs();
    try testing.expect((try a.p.toInt(i32)) == 50);
    try testing.expect((try a.q.toInt(i32)) == 1);
}

test "swap" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.setRatio(50, 23);
    try b.setRatio(17, 3);

    try testing.expect((try a.p.toInt(u32)) == 50);
    try testing.expect((try a.q.toInt(u32)) == 23);

    try testing.expect((try b.p.toInt(u32)) == 17);
    try testing.expect((try b.q.toInt(u32)) == 3);

    a.swap(&b);

    try testing.expect((try a.p.toInt(u32)) == 17);
    try testing.expect((try a.q.toInt(u32)) == 3);

    try testing.expect((try b.p.toInt(u32)) == 50);
    try testing.expect((try b.q.toInt(u32)) == 23);
}

test "order" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.setRatio(500, 231);
    try b.setRatio(18903, 8584);
    try testing.expect((try a.order(b)) == .lt);

    try a.setRatio(890, 10);
    try b.setRatio(89, 1);
    try testing.expect((try a.order(b)) == .eq);
}

test "order/orderAbs with negative" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.setRatio(1, 1);
    try b.setRatio(-2, 1);
    try testing.expect((try a.order(b)) == .gt);
    try testing.expect((try a.orderAbs(b)) == .lt);
}

test "add single-limb" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();

    try a.setRatio(500, 231);
    try b.setRatio(18903, 8584);
    try testing.expect((try a.order(b)) == .lt);

    try a.setRatio(890, 10);
    try b.setRatio(89, 1);
    try testing.expect((try a.order(b)) == .eq);
}

test "add" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();
    var r = try Rational.init(testing.allocator);
    defer r.deinit();

    try a.setRatio(78923, 23341);
    try b.setRatio(123097, 12441414);
    try a.add(a, b);

    try r.setRatio(984786924199, 290395044174);
    try testing.expect((try a.order(r)) == .eq);
}

test "sub" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();
    var r = try Rational.init(testing.allocator);
    defer r.deinit();

    try a.setRatio(78923, 23341);
    try b.setRatio(123097, 12441414);
    try a.sub(a, b);

    try r.setRatio(979040510045, 290395044174);
    try testing.expect((try a.order(r)) == .eq);
}

test "mul" {
    var a = try Rational.init(testing.allocator);
    defer a.deinit();
    var b = try Rational.init(testing.allocator);
    defer b.deinit();
    var r = try Rational.init(testing.allocator);
    defer r.deinit();

    try a.setRatio(78923, 23341);
    try b.setRatio(123097, 12441414);
    try a.mul(a, b);

    try r.setRatio(571481443, 17082061422);
    try testing.expect((try a.order(r)) == .eq);
}

test "div" {
    {
        var a = try Rational.init(testing.allocator);
        defer a.deinit();
        var b = try Rational.init(testing.allocator);
        defer b.deinit();
        var r = try Rational.init(testing.allocator);
        defer r.deinit();

        try a.setRatio(78923, 23341);
        try b.setRatio(123097, 12441414);
        try a.div(a, b);

        try r.setRatio(75531824394, 221015929);
        try testing.expect((try a.order(r)) == .eq);
    }

    {
        var a = try Rational.init(testing.allocator);
        defer a.deinit();
        var r = try Rational.init(testing.allocator);
        defer r.deinit();

        try a.setRatio(78923, 23341);
        a.invert();

        try r.setRatio(23341, 78923);
        try testing.expect((try a.order(r)) == .eq);

        try a.setRatio(-78923, 23341);
        a.invert();

        try r.setRatio(-23341, 78923);
        try testing.expect((try a.order(r)) == .eq);
    }
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/cbrtf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/cbrt.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns the cube root of x.
///
/// Special Cases:
///  - cbrt(+-0)   = +-0
///  - cbrt(+-inf) = +-inf
///  - cbrt(nan)   = nan
pub fn cbrt(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => cbrt32(x),
        f64 => cbrt64(x),
        else => @compileError("cbrt not implemented for " ++ @typeName(T)),
    };
}

fn cbrt32(x: f32) f32 {
    const B1: u32 = 709958130; // (127 - 127.0 / 3 - 0.03306235651) * 2^23
    const B2: u32 = 642849266; // (127 - 127.0 / 3 - 24 / 3 - 0.03306235651) * 2^23

    var u = @as(u32, @bitCast(x));
    var hx = u & 0x7FFFFFFF;

    // cbrt(nan, inf) = itself
    if (hx >= 0x7F800000) {
        return x + x;
    }

    // cbrt to ~5bits
    if (hx < 0x00800000) {
        // cbrt(+-0) = itself
        if (hx == 0) {
            return x;
        }
        u = @as(u32, @bitCast(x * 0x1.0p24));
        hx = u & 0x7FFFFFFF;
        hx = hx / 3 + B2;
    } else {
        hx = hx / 3 + B1;
    }

    u &= 0x80000000;
    u |= hx;

    // first step newton to 16 bits
    var t: f64 = @as(f32, @bitCast(u));
    var r: f64 = t * t * t;
    t = t * (@as(f64, x) + x + r) / (x + r + r);

    // second step newton to 47 bits
    r = t * t * t;
    t = t * (@as(f64, x) + x + r) / (x + r + r);

    return @as(f32, @floatCast(t));
}

fn cbrt64(x: f64) f64 {
    const B1: u32 = 715094163; // (1023 - 1023 / 3 - 0.03306235651 * 2^20
    const B2: u32 = 696219795; // (1023 - 1023 / 3 - 54 / 3 - 0.03306235651 * 2^20

    // |1 / cbrt(x) - p(x)| < 2^(23.5)
    const P0: f64 = 1.87595182427177009643;
    const P1: f64 = -1.88497979543377169875;
    const P2: f64 = 1.621429720105354466140;
    const P3: f64 = -0.758397934778766047437;
    const P4: f64 = 0.145996192886612446982;

    var u = @as(u64, @bitCast(x));
    var hx = @as(u32, @intCast(u >> 32)) & 0x7FFFFFFF;

    // cbrt(nan, inf) = itself
    if (hx >= 0x7FF00000) {
        return x + x;
    }

    // cbrt to ~5bits
    if (hx < 0x00100000) {
        u = @as(u64, @bitCast(x * 0x1.0p54));
        hx = @as(u32, @intCast(u >> 32)) & 0x7FFFFFFF;

        // cbrt(+-0) = itself
        if (hx == 0) {
            return x;
        }
        hx = hx / 3 + B2;
    } else {
        hx = hx / 3 + B1;
    }

    u &= 1 << 63;
    u |= @as(u64, hx) << 32;
    var t = @as(f64, @bitCast(u));

    // cbrt to 23 bits
    // cbrt(x) = t * cbrt(x / t^3) ~= t * P(t^3 / x)
    const r = (t * t) * (t / x);
    t = t * ((P0 + r * (P1 + r * P2)) + ((r * r) * r) * (P3 + r * P4));

    // Round t away from 0 to 23 bits
    u = @as(u64, @bitCast(t));
    u = (u + 0x80000000) & 0xFFFFFFFFC0000000;
    t = @as(f64, @bitCast(u));

    // one step newton to 53 bits
    const s = t * t;
    var q = x / s;
    const w = t + t;
    q = (q - t) / (w + q);

    return t + t * q;
}

test cbrt {
    try expect(cbrt(@as(f32, 0.0)) == cbrt32(0.0));
    try expect(cbrt(@as(f64, 0.0)) == cbrt64(0.0));
}

test cbrt32 {
    const epsilon = 0.000001;

    try expect(math.isPositiveZero(cbrt32(0.0)));
    try expect(math.approxEqAbs(f32, cbrt32(0.2), 0.584804, epsilon));
    try expect(math.approxEqAbs(f32, cbrt32(0.8923), 0.962728, epsilon));
    try expect(math.approxEqAbs(f32, cbrt32(1.5), 1.144714, epsilon));
    try expect(math.approxEqAbs(f32, cbrt32(37.45), 3.345676, epsilon));
    try expect(math.approxEqAbs(f32, cbrt32(123123.234375), 49.748501, epsilon));
}

test cbrt64 {
    const epsilon = 0.000001;

    try expect(math.isPositiveZero(cbrt64(0.0)));
    try expect(math.approxEqAbs(f64, cbrt64(0.2), 0.584804, epsilon));
    try expect(math.approxEqAbs(f64, cbrt64(0.8923), 0.962728, epsilon));
    try expect(math.approxEqAbs(f64, cbrt64(1.5), 1.144714, epsilon));
    try expect(math.approxEqAbs(f64, cbrt64(37.45), 3.345676, epsilon));
    try expect(math.approxEqAbs(f64, cbrt64(123123.234375), 49.748501, epsilon));
}

test "cbrt.special" {
    try expect(math.isPositiveZero(cbrt32(0.0)));
    try expect(@as(u32, @bitCast(cbrt32(-0.0))) == @as(u32, 0x80000000));
    try expect(math.isPositiveInf(cbrt32(math.inf(f32))));
    try expect(math.isNegativeInf(cbrt32(-math.inf(f32))));
    try expect(math.isNan(cbrt32(math.nan(f32))));
}

test "cbrt64.special" {
    try expect(math.isPositiveZero(cbrt64(0.0)));
    try expect(math.isNegativeZero(cbrt64(-0.0)));
    try expect(math.isPositiveInf(cbrt64(math.inf(f64))));
    try expect(math.isNegativeInf(cbrt64(-math.inf(f64))));
    try expect(math.isNan(cbrt64(math.nan(f64))));
}
const std = @import("../std.zig");
const testing = std.testing;
const math = std.math;

pub const abs = @import("complex/abs.zig").abs;
pub const acosh = @import("complex/acosh.zig").acosh;
pub const acos = @import("complex/acos.zig").acos;
pub const arg = @import("complex/arg.zig").arg;
pub const asinh = @import("complex/asinh.zig").asinh;
pub const asin = @import("complex/asin.zig").asin;
pub const atanh = @import("complex/atanh.zig").atanh;
pub const atan = @import("complex/atan.zig").atan;
pub const conj = @import("complex/conj.zig").conj;
pub const cosh = @import("complex/cosh.zig").cosh;
pub const cos = @import("complex/cos.zig").cos;
pub const exp = @import("complex/exp.zig").exp;
pub const log = @import("complex/log.zig").log;
pub const pow = @import("complex/pow.zig").pow;
pub const proj = @import("complex/proj.zig").proj;
pub const sinh = @import("complex/sinh.zig").sinh;
pub const sin = @import("complex/sin.zig").sin;
pub const sqrt = @import("complex/sqrt.zig").sqrt;
pub const tanh = @import("complex/tanh.zig").tanh;
pub const tan = @import("complex/tan.zig").tan;

/// A complex number consisting of a real an imaginary part. T must be a floating-point value.
pub fn Complex(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Real part.
        re: T,

        /// Imaginary part.
        im: T,

        /// Create a new Complex number from the given real and imaginary parts.
        pub fn init(re: T, im: T) Self {
            return Self{
                .re = re,
                .im = im,
            };
        }

        /// Returns the sum of two complex numbers.
        pub fn add(self: Self, other: Self) Self {
            return Self{
                .re = self.re + other.re,
                .im = self.im + other.im,
            };
        }

        /// Returns the subtraction of two complex numbers.
        pub fn sub(self: Self, other: Self) Self {
            return Self{
                .re = self.re - other.re,
                .im = self.im - other.im,
            };
        }

        /// Returns the product of two complex numbers.
        pub fn mul(self: Self, other: Self) Self {
            return Self{
                .re = self.re * other.re - self.im * other.im,
                .im = self.im * other.re + self.re * other.im,
            };
        }

        /// Returns the quotient of two complex numbers.
        pub fn div(self: Self, other: Self) Self {
            const re_num = self.re * other.re + self.im * other.im;
            const im_num = self.im * other.re - self.re * other.im;
            const den = other.re * other.re + other.im * other.im;

            return Self{
                .re = re_num / den,
                .im = im_num / den,
            };
        }

        /// Returns the complex conjugate of a number.
        pub fn conjugate(self: Self) Self {
            return Self{
                .re = self.re,
                .im = -self.im,
            };
        }

        /// Returns the negation of a complex number.
        pub fn neg(self: Self) Self {
            return Self{
                .re = -self.re,
                .im = -self.im,
            };
        }

        /// Returns the product of complex number and i=sqrt(-1)
        pub fn mulbyi(self: Self) Self {
            return Self{
                .re = -self.im,
                .im = self.re,
            };
        }

        /// Returns the reciprocal of a complex number.
        pub fn reciprocal(self: Self) Self {
            const m = self.re * self.re + self.im * self.im;
            return Self{
                .re = self.re / m,
                .im = -self.im / m,
            };
        }

        /// Returns the magnitude of a complex number.
        pub fn magnitude(self: Self) T {
            return @sqrt(self.re * self.re + self.im * self.im);
        }

        pub fn squaredMagnitude(self: Self) T {
            return self.re * self.re + self.im * self.im;
        }
    };
}

const epsilon = 0.0001;

test "add" {
    const a = Complex(f32).init(5, 3);
    const b = Complex(f32).init(2, 7);
    const c = a.add(b);

    try testing.expect(c.re == 7 and c.im == 10);
}

test "sub" {
    const a = Complex(f32).init(5, 3);
    const b = Complex(f32).init(2, 7);
    const c = a.sub(b);

    try testing.expect(c.re == 3 and c.im == -4);
}

test "mul" {
    const a = Complex(f32).init(5, 3);
    const b = Complex(f32).init(2, 7);
    const c = a.mul(b);

    try testing.expect(c.re == -11 and c.im == 41);
}

test "div" {
    const a = Complex(f32).init(5, 3);
    const b = Complex(f32).init(2, 7);
    const c = a.div(b);

    try testing.expect(math.approxEqAbs(f32, c.re, @as(f32, 31) / 53, epsilon) and
        math.approxEqAbs(f32, c.im, @as(f32, -29) / 53, epsilon));
}

test "conjugate" {
    const a = Complex(f32).init(5, 3);
    const c = a.conjugate();

    try testing.expect(c.re == 5 and c.im == -3);
}

test "neg" {
    const a = Complex(f32).init(5, 3);
    const c = a.neg();

    try testing.expect(c.re == -5 and c.im == -3);
}

test "mulbyi" {
    const a = Complex(f32).init(5, 3);
    const c = a.mulbyi();

    try testing.expect(c.re == -3 and c.im == 5);
}

test "reciprocal" {
    const a = Complex(f32).init(5, 3);
    const c = a.reciprocal();

    try testing.expect(math.approxEqAbs(f32, c.re, @as(f32, 5) / 34, epsilon) and
        math.approxEqAbs(f32, c.im, @as(f32, -3) / 34, epsilon));
}

test "magnitude" {
    const a = Complex(f32).init(5, 3);
    const c = a.magnitude();

    try testing.expect(math.approxEqAbs(f32, c, 5.83095, epsilon));
}

test "squaredMagnitude" {
    const a = Complex(f32).init(5, 3);
    const c = a.squaredMagnitude();

    try testing.expect(math.approxEqAbs(f32, c, math.pow(f32, a.magnitude(), 2), epsilon));
}

test {
    _ = @import("complex/abs.zig");
    _ = @import("complex/acosh.zig");
    _ = @import("complex/acos.zig");
    _ = @import("complex/arg.zig");
    _ = @import("complex/asinh.zig");
    _ = @import("complex/asin.zig");
    _ = @import("complex/atanh.zig");
    _ = @import("complex/atan.zig");
    _ = @import("complex/conj.zig");
    _ = @import("complex/cosh.zig");
    _ = @import("complex/cos.zig");
    _ = @import("complex/exp.zig");
    _ = @import("complex/log.zig");
    _ = @import("complex/pow.zig");
    _ = @import("complex/proj.zig");
    _ = @import("complex/sinh.zig");
    _ = @import("complex/sin.zig");
    _ = @import("complex/sqrt.zig");
    _ = @import("complex/tanh.zig");
    _ = @import("complex/tan.zig");
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the absolute value (modulus) of z.
pub fn abs(z: anytype) @TypeOf(z.re, z.im) {
    return math.hypot(z.re, z.im);
}

test abs {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = abs(a);
    try testing.expectApproxEqAbs(5.8309517, c, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the arc-cosine of z.
pub fn acos(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const q = cmath.asin(z);
    return Complex(T).init(@as(T, math.pi) / 2 - q.re, -q.im);
}

test acos {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = acos(a);

    try testing.expectApproxEqAbs(0.5469737, c.re, epsilon);
    try testing.expectApproxEqAbs(-2.4529128, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the hyperbolic arc-cosine of z.
pub fn acosh(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const q = cmath.acos(z);

    return if (math.signbit(z.im))
        Complex(T).init(q.im, -q.re)
    else
        Complex(T).init(-q.im, q.re);
}

test acosh {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = acosh(a);

    try testing.expectApproxEqAbs(2.4529128, c.re, epsilon);
    try testing.expectApproxEqAbs(0.5469737, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the angular component (in radians) of z.
pub fn arg(z: anytype) @TypeOf(z.re, z.im) {
    return math.atan2(z.im, z.re);
}

test arg {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = arg(a);
    try testing.expectApproxEqAbs(0.5404195, c, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

// Returns the arc-sine of z.
pub fn asin(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const x = z.re;
    const y = z.im;

    const p = Complex(T).init(1.0 - (x - y) * (x + y), -2.0 * x * y);
    const q = Complex(T).init(-y, x);
    const r = cmath.log(q.add(cmath.sqrt(p)));

    return Complex(T).init(r.im, -r.re);
}

test asin {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = asin(a);

    try testing.expectApproxEqAbs(1.0238227, c.re, epsilon);
    try testing.expectApproxEqAbs(2.4529128, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the hyperbolic arc-sine of z.
pub fn asinh(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const q = Complex(T).init(-z.im, z.re);
    const r = cmath.asin(q);
    return Complex(T).init(r.im, -r.re);
}

test asinh {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = asinh(a);

    try testing.expectApproxEqAbs(2.4598298, c.re, epsilon);
    try testing.expectApproxEqAbs(0.5339993, c.im, epsilon);
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/complex/catanf.c
// https://git.musl-libc.org/cgit/musl/tree/src/complex/catan.c

const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the arc-tangent of z.
pub fn atan(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    return switch (T) {
        f32 => atan32(z),
        f64 => atan64(z),
        else => @compileError("atan not implemented for " ++ @typeName(z)),
    };
}

fn redupif32(x: f32) f32 {
    const DP1 = 3.140625;
    const DP2 = 9.67502593994140625e-4;
    const DP3 = 1.509957990978376432e-7;

    var t = x / math.pi;
    if (t >= 0.0) {
        t += 0.5;
    } else {
        t -= 0.5;
    }

    const u: f32 = @trunc(t);
    return ((x - u * DP1) - u * DP2) - u * DP3;
}

fn atan32(z: Complex(f32)) Complex(f32) {
    const x = z.re;
    const y = z.im;

    const x2 = x * x;
    var a = 1.0 - x2 - (y * y);

    var t = 0.5 * math.atan2(2.0 * x, a);
    const w = redupif32(t);

    t = y - 1.0;
    a = x2 + t * t;

    t = y + 1.0;
    a = (x2 + (t * t)) / a;
    return Complex(f32).init(w, 0.25 * @log(a));
}

fn redupif64(x: f64) f64 {
    const DP1 = 3.14159265160560607910;
    const DP2 = 1.98418714791870343106e-9;
    const DP3 = 1.14423774522196636802e-17;

    var t = x / math.pi;
    if (t >= 0.0) {
        t += 0.5;
    } else {
        t -= 0.5;
    }

    const u: f64 = @trunc(t);
    return ((x - u * DP1) - u * DP2) - u * DP3;
}

fn atan64(z: Complex(f64)) Complex(f64) {
    const x = z.re;
    const y = z.im;

    const x2 = x * x;
    var a = 1.0 - x2 - (y * y);

    var t = 0.5 * math.atan2(2.0 * x, a);
    const w = redupif64(t);

    t = y - 1.0;
    a = x2 + t * t;

    t = y + 1.0;
    a = (x2 + (t * t)) / a;
    return Complex(f64).init(w, 0.25 * @log(a));
}

test atan32 {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = atan(a);

    try testing.expectApproxEqAbs(1.423679, c.re, epsilon);
    try testing.expectApproxEqAbs(0.086569, c.im, epsilon);
}

test atan64 {
    const epsilon = math.floatEps(f64);
    const a = Complex(f64).init(5, 3);
    const c = atan(a);

    try testing.expectApproxEqAbs(1.4236790442393028, c.re, epsilon);
    try testing.expectApproxEqAbs(0.08656905917945844, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the hyperbolic arc-tangent of z.
pub fn atanh(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const q = Complex(T).init(-z.im, z.re);
    const r = cmath.atan(q);
    return Complex(T).init(r.im, -r.re);
}

test atanh {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = atanh(a);

    try testing.expectApproxEqAbs(0.14694665, c.re, epsilon);
    try testing.expectApproxEqAbs(1.4808695, c.im, epsilon);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the complex conjugate of z.
pub fn conj(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    return Complex(T).init(z.re, -z.im);
}

test conj {
    const a = Complex(f32).init(5, 3);
    const c = a.conjugate();

    try testing.expectEqual(5, c.re);
    try testing.expectEqual(-3, c.im);
}
const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

/// Returns the cosine of z.
pub fn cos(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    const p = Complex(T).init(-z.im, z.re);
    return cmath.cosh(p);
}

test cos {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = cos(a);

    try testing.expectApproxEqAbs(2.8558152, c.re, epsilon);
    try testing.expectApproxEqAbs(9.606383, c.im, epsilon);
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/complex/ccoshf.c
// https://git.musl-libc.org/cgit/musl/tree/src/complex/ccosh.c

const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

const ldexp_cexp = @import("ldexp.zig").ldexp_cexp;

/// Returns the hyperbolic arc-cosine of z.
pub fn cosh(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);
    return switch (T) {
        f32 => cosh32(z),
        f64 => cosh64(z),
        else => @compileError("cosh not implemented for " ++ @typeName(z)),
    };
}

fn cosh32(z: Complex(f32)) Complex(f32) {
    const x = z.re;
    const y = z.im;

    const hx: u32 = @bitCast(x);
    const ix = hx & 0x7fffffff;

    const hy: u32 = @bitCast(y);
    const iy = hy & 0x7fffffff;

    if (ix < 0x7f800000 and iy < 0x7f800000) {
        if (iy == 0) {
            return Complex(f32).init(math.cosh(x), x * y);
        }
        // small x: normal case
        if (ix < 0x41100000) {
            return Complex(f32).init(math.cosh(x) * @cos(y), math.sinh(x) * @sin(y));
        }

        // |x|>= 9, so cosh(x) ~= exp(|x|)
        if (ix < 0x42b17218) {
            // x < 88.7: exp(|x|) won't overflow
            const h = @exp(@abs(x)) * 0.5;
            return Complex(f32).init(h * @cos(y), math.copysign(h, x) * @sin(y));
        }
        // x < 192.7: scale to avoid overflow
        else if (ix < 0x4340b1e7) {
            const v = Complex(f32).init(@abs(x), y);
            const r = ldexp_cexp(v, -1);
            return Complex(f32).init(r.re, r.im * math.copysign(@as(f32, 1.0), x));
        }
        // x >= 192.7: result always overflows
        else {
            const h = 0x1p127 * x;
            return Complex(f32).init(h * h * @cos(y), h * @sin(y));
        }
    }

    if (ix == 0 and iy >= 0x7f800000) {
        return Complex(f32).init(y - y, math.copysign(@as(f32, 0.0), x * (y - y)));
    }

    if (iy == 0 and ix >= 0x7f800000) {
        if (hx & 0x7fffff == 0) {
            return Complex(f32).init(x * x, math.copysign(@as(f32, 0.0), x) * y);
        }
        return Complex(f32).init(x * x, math.copysign(@as(f32, 0.0), (x + x) * y));
    }

    if (ix < 0x7f800000 and iy >= 0x7f800000) {
        return Complex(f32).init(y - y, x * (y - y));
    }

    if (ix >= 0x7f800000 and (hx & 0x7fffff) == 0) {
        if (iy >= 0x7f800000) {
            return Complex(f32).init(x * x, x * (y - y));
        }
        return Complex(f32).init((x * x) * @cos(y), x * @sin(y));
    }

    return Complex(f32).init((x * x) * (y - y), (x + x) * (y - y));
}

fn cosh64(z: Complex(f64)) Complex(f64) {
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

    // nearly non-exceptional case where x, y are finite
    if (ix < 0x7ff00000 and iy < 0x7ff00000) {
        if (iy | ly == 0) {
            return Complex(f64).init(math.cosh(x), x * y);
        }
        // small x: normal case
        if (ix < 0x40360000) {
            return Complex(f64).init(math.cosh(x) * @cos(y), math.sinh(x) * @sin(y));
        }

        // |x|>= 22, so cosh(x) ~= exp(|x|)
        if (ix < 0x40862e42) {
            // x < 710: exp(|x|) won't overflow
            const h = @exp(@abs(x)) * 0.5;
            return Complex(f64).init(h * @cos(y), math.copysign(h, x) * @sin(y));
        }
        // x < 1455: scale to avoid overflow
        else if (ix < 0x4096bbaa) {
            const v = Complex(f64).init(@abs(x), y);
            const r = ldexp_cexp(v, -1);
            return Complex(f64).init(r.re, r.im * math.copysign(@as(f64, 1.0), x));
        }
        // x >= 1455: result always overflows
        else {
            const h = 0x1p1023 * x;
            return Complex(f64).init(h * h * @cos(y), h * @sin(y));
        }
    }

    if (ix | lx == 0 and iy >= 0x7ff00000) {
        return Complex(f64).init(y - y, math.copysign(@as(f64, 0.0), x * (y - y)));
    }

    if (iy | ly == 0 and ix >= 0x7ff00000) {
        if ((hx & 0xfffff) | lx == 0) {
            return Complex(f64).init(x * x, math.copysign(@as(f64, 0.0), x) * y);
        }
        return Complex(f64).init(x * x, math.copysign(@as(f64, 0.0), (x + x) * y));
    }

    if (ix < 0x7ff00000 and iy >= 0x7ff00000) {
        return Complex(f64).init(y - y, x * (y - y));
    }

    if (ix >= 0x7ff00000 and (hx & 0xfffff) | lx == 0) {
        if (iy >= 0x7ff00000) {
            return Complex(f64).init(x * x, x * (y - y));
        }
        return Complex(f64).init(x * x * @cos(y), x * @sin(y));
    }

    return Complex(f64).init((x * x) * (y - y), (x + x) * (y - y));
}

test cosh32 {
    const epsilon = math.floatEps(f32);
    const a = Complex(f32).init(5, 3);
    const c = cosh(a);

    try testing.expectApproxEqAbs(-73.467300, c.re, epsilon);
    try testing.expectApproxEqAbs(10.471557, c.im, epsilon);
}

test cosh64 {
    const epsilon = math.floatEps(f64);
    const a = Complex(f64).init(5, 3);
    const c = cosh(a);

    try testing.expectApproxEqAbs(-73.46729221264526, c.re, epsilon);
    try testing.expectApproxEqAbs(10.471557674805572, c.im, epsilon);
}

test "cosh64 musl" {
    const epsilon = math.floatEps(f64);
    const a = Complex(f64).init(7.44648873421389e17, 1.6008058402057622e19);
    const c = cosh(a);

    try testing.expectApproxEqAbs(std.math.inf(f64), c.re, epsilon);
    try testing.expectApproxEqAbs(std.math.inf(f64), c.im, epsilon);
}
// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/complex/cexpf.c
// https://git.musl-libc.org/cgit/musl/tree/src/complex/cexp.c

const std = @import("../../std.zig");
const testing = std.testing;
const math = std.math;
const cmath = math.complex;
const Complex = cmath.Complex;

const ldexp_cexp = @import("ldexp.zig").ldexp_cexp;

/// Returns e raised to the power of z (e^z).
pub fn exp(z: anytype) Complex(@TypeOf(z.re, z.im)) {
    const T = @TypeOf(z.re, z.im);

    return switch (T) {
        f32 => exp32(z),
        f64 => exp64(z),
        else => @compileError("exp not implemented for " ++ @typeName(z)),
    };
}

fn exp32(z: Complex(f32)) Complex(f32) {
    const exp_overflow = 0x42b17218; // max_exp * ln2 ~= 88.72283955
    const cexp_overflow = 0x43400074; // (max_exp - min_denom_exp) * ln2

    const x = z.re;
    const y = z.im;

    const hy = @as(u32, @bitCast(y)) & 0x7fffffff;
    // cexp(x + i0) = exp(x) + i0
    if (hy == 0) {
        return Complex(f32).init(@exp(x), y);
    }

    const hx = @as(u32, @bitCast(x));
    // cexp(0 + iy) = cos(y) + isin(y)
    if ((hx & 0x7fffffff) == 0) {
        return Complex(f32).init(@cos(y), @sin(y));
    }

    if (hy >= 0x7f800000) {
        // cexp(finite|nan +- i inf|nan) = nan + i nan
        if ((hx & 0x7fffffff) != 0x7f800000) {
            return Complex(f32).init(y - y, y - y);
        } // cexp(-inf +- i inf|nan) = 0 + i0
        else if (hx & 0x80000000 != 0) {
            return Complex(f32).init(0, 0);
        } // cexp(+inf +- i inf|nan) = inf + i nan
        else {
            return Complex(f32).init(x, y - y);
        }
    }

    // 88.7 <= x <= 192 so must scale
    if (hx >= exp_overflow and hx <= cexp_overflow) {
        return ldexp_cexp(z, 0);
    } // - x < exp_overflow => exp(x) won't overflow (common)
    // - x > cexp_overflow, so exp(x) * s overflows for s > 0
    // - x = +-inf
    // - x = nan
    else {
        const exp_x = @exp(x);
        return Complex(f32).init(exp_x * @cos(y), exp_x * @sin(y));
    }
}

fn exp64(z: Complex(f64)) Complex(f64) {
    const exp_overflow = 0x40862e42; // high bits of max_exp * ln2 ~= 710
    const cexp_overflow = 0x4096b8e4; // (max_exp - min_denorm_exp) * ln2

    const x = z.re;
    const y = z.im;

    const fy: u64 = @bitCast(y);
    const hy: u32 = @intCast((fy >> 32) & 0x7fffffff);
    const ly: u32 = @truncate(fy);

    // cexp(x + i0) = exp(x) + i0
    if (hy | ly == 0) {
        return Complex(f64).init(@exp(x), y);
    }

```
