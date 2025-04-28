```
sitive) {
                // (a) - (-b) => a + b
                return r.addCarry(a, b.abs());
            } else {
                // (-a) - (b) => -a + -b
                return r.addCarry(a, b.negate());
            }
        } else if (a.positive) {
            if (a.order(b) != .lt) {
                // (a) - (b) => a - b
                const c = llsubcarry(r.limbs, a.limbs, b.limbs);
                r.normalize(a.limbs.len);
                r.positive = true;
                return c != 0;
            } else {
                // (a) - (b) => -b + a => -(b - a)
                const c = llsubcarry(r.limbs, b.limbs, a.limbs);
                r.normalize(b.limbs.len);
                r.positive = false;
                return c != 0;
            }
        } else {
            if (a.order(b) == .lt) {
                // (-a) - (-b) => -(a - b)
                const c = llsubcarry(r.limbs, a.limbs, b.limbs);
                r.normalize(a.limbs.len);
                r.positive = false;
                return c != 0;
            } else {
                // (-a) - (-b) => --b + -a => b - a
                const c = llsubcarry(r.limbs, b.limbs, a.limbs);
                r.normalize(b.limbs.len);
                r.positive = true;
                return c != 0;
            }
        }
    }

    /// r = a - b
    ///
    /// r, a and b may be aliases.
    ///
    /// Asserts the result fits in `r`. An upper bound on the number of limbs needed by
    /// r is `@max(a.limbs.len, b.limbs.len) + 1`. The +1 is not needed if both operands are positive.
    pub fn sub(r: *Mutable, a: Const, b: Const) void {
        r.add(a, b.negate());
    }

    /// r = a - b with 2s-complement wrapping semantics. Returns whether any overflow occurred.
    ///
    /// r, a and b may be aliases
    /// Asserts the result fits in `r`. An upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn subWrap(r: *Mutable, a: Const, b: Const, signedness: Signedness, bit_count: usize) bool {
        return r.addWrap(a, b.negate(), signedness, bit_count);
    }

    /// r = a - b with 2s-complement saturating semantics.
    /// r, a and b may be aliases.
    ///
    /// Assets the result fits in `r`. Upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn subSat(r: *Mutable, a: Const, b: Const, signedness: Signedness, bit_count: usize) void {
        r.addSat(a, b.negate(), signedness, bit_count);
    }

    /// rma = a * b
    ///
    /// `rma` may alias with `a` or `b`.
    /// `a` and `b` may alias with each other.
    ///
    /// Asserts the result fits in `rma`. An upper bound on the number of limbs needed by
    /// rma is given by `a.limbs.len + b.limbs.len`.
    ///
    /// `limbs_buffer` is used for temporary storage. The amount required is given by `calcMulLimbsBufferLen`.
    pub fn mul(rma: *Mutable, a: Const, b: Const, limbs_buffer: []Limb, allocator: ?Allocator) void {
        var buf_index: usize = 0;

        const a_copy = if (rma.limbs.ptr == a.limbs.ptr) blk: {
            const start = buf_index;
            @memcpy(limbs_buffer[buf_index..][0..a.limbs.len], a.limbs);
            buf_index += a.limbs.len;
            break :blk a.toMutable(limbs_buffer[start..buf_index]).toConst();
        } else a;

        const b_copy = if (rma.limbs.ptr == b.limbs.ptr) blk: {
            const start = buf_index;
            @memcpy(limbs_buffer[buf_index..][0..b.limbs.len], b.limbs);
            buf_index += b.limbs.len;
            break :blk b.toMutable(limbs_buffer[start..buf_index]).toConst();
        } else b;

        return rma.mulNoAlias(a_copy, b_copy, allocator);
    }

    /// rma = a * b
    ///
    /// `rma` may not alias with `a` or `b`.
    /// `a` and `b` may alias with each other.
    ///
    /// Asserts the result fits in `rma`. An upper bound on the number of limbs needed by
    /// rma is given by `a.limbs.len + b.limbs.len`.
    ///
    /// If `allocator` is provided, it will be used for temporary storage to improve
    /// multiplication performance. `error.OutOfMemory` is handled with a fallback algorithm.
    pub fn mulNoAlias(rma: *Mutable, a: Const, b: Const, allocator: ?Allocator) void {
        assert(rma.limbs.ptr != a.limbs.ptr); // illegal aliasing
        assert(rma.limbs.ptr != b.limbs.ptr); // illegal aliasing

        if (a.limbs.len == 1 and b.limbs.len == 1) {
            const ov = @mulWithOverflow(a.limbs[0], b.limbs[0]);
            rma.limbs[0] = ov[0];
            if (ov[1] == 0) {
                rma.len = 1;
                rma.positive = (a.positive == b.positive);
                return;
            }
        }

        @memset(rma.limbs[0 .. a.limbs.len + b.limbs.len], 0);

        llmulacc(.add, allocator, rma.limbs, a.limbs, b.limbs);

        rma.normalize(a.limbs.len + b.limbs.len);
        rma.positive = (a.positive == b.positive);
    }

    /// rma = a * b with 2s-complement wrapping semantics.
    ///
    /// `rma` may alias with `a` or `b`.
    /// `a` and `b` may alias with each other.
    ///
    /// Asserts the result fits in `rma`. An upper bound on the number of limbs needed by
    /// rma is given by `a.limbs.len + b.limbs.len`.
    ///
    /// `limbs_buffer` is used for temporary storage. The amount required is given by `calcMulWrapLimbsBufferLen`.
    pub fn mulWrap(
        rma: *Mutable,
        a: Const,
        b: Const,
        signedness: Signedness,
        bit_count: usize,
        limbs_buffer: []Limb,
        allocator: ?Allocator,
    ) void {
        var buf_index: usize = 0;
        const req_limbs = calcTwosCompLimbCount(bit_count);

        const a_copy = if (rma.limbs.ptr == a.limbs.ptr) blk: {
            const start = buf_index;
            const a_len = @min(req_limbs, a.limbs.len);
            @memcpy(limbs_buffer[buf_index..][0..a_len], a.limbs[0..a_len]);
            buf_index += a_len;
            break :blk a.toMutable(limbs_buffer[start..buf_index]).toConst();
        } else a;

        const b_copy = if (rma.limbs.ptr == b.limbs.ptr) blk: {
            const start = buf_index;
            const b_len = @min(req_limbs, b.limbs.len);
            @memcpy(limbs_buffer[buf_index..][0..b_len], b.limbs[0..b_len]);
            buf_index += b_len;
            break :blk a.toMutable(limbs_buffer[start..buf_index]).toConst();
        } else b;

        return rma.mulWrapNoAlias(a_copy, b_copy, signedness, bit_count, allocator);
    }

    /// rma = a * b with 2s-complement wrapping semantics.
    ///
    /// `rma` may not alias with `a` or `b`.
    /// `a` and `b` may alias with each other.
    ///
    /// Asserts the result fits in `rma`. An upper bound on the number of limbs needed by
    /// rma is given by `a.limbs.len + b.limbs.len`.
    ///
    /// If `allocator` is provided, it will be used for temporary storage to improve
    /// multiplication performance. `error.OutOfMemory` is handled with a fallback algorithm.
    pub fn mulWrapNoAlias(
        rma: *Mutable,
        a: Const,
        b: Const,
        signedness: Signedness,
        bit_count: usize,
        allocator: ?Allocator,
    ) void {
        assert(rma.limbs.ptr != a.limbs.ptr); // illegal aliasing
        assert(rma.limbs.ptr != b.limbs.ptr); // illegal aliasing

        const req_limbs = calcTwosCompLimbCount(bit_count);

        // We can ignore the upper bits here, those results will be discarded anyway.
        const a_limbs = a.limbs[0..@min(req_limbs, a.limbs.len)];
        const b_limbs = b.limbs[0..@min(req_limbs, b.limbs.len)];

        @memset(rma.limbs[0..req_limbs], 0);

        llmulacc(.add, allocator, rma.limbs, a_limbs, b_limbs);
        rma.normalize(@min(req_limbs, a.limbs.len + b.limbs.len));
        rma.positive = (a.positive == b.positive);
        rma.truncate(rma.toConst(), signedness, bit_count);
    }

    /// r = @bitReverse(a) with 2s-complement semantics.
    /// r and a may be aliases.
    ///
    /// Asserts the result fits in `r`. Upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn bitReverse(r: *Mutable, a: Const, signedness: Signedness, bit_count: usize) void {
        if (bit_count == 0) return;

        r.copy(a);

        const limbs_required = calcTwosCompLimbCount(bit_count);

        if (!a.positive) {
            r.positive = true; // Negate.
            r.bitNotWrap(r.toConst(), .unsigned, bit_count); // Bitwise NOT.
            r.addScalar(r.toConst(), 1); // Add one.
        } else if (limbs_required > a.limbs.len) {
            // Zero-extend to our output length
            for (r.limbs[a.limbs.len..limbs_required]) |*limb| {
                limb.* = 0;
            }
            r.len = limbs_required;
        }

        // 0b0..01..1000 with @log2(@sizeOf(Limb)) consecutive ones
        const endian_mask: usize = (@sizeOf(Limb) - 1) << 3;

        const bytes = std.mem.sliceAsBytes(r.limbs);

        var k: usize = 0;
        while (k < ((bit_count + 1) / 2)) : (k += 1) {
            var i = k;
            var rev_i = bit_count - i - 1;

            // This "endian mask" remaps a low (LE) byte to the corresponding high
            // (BE) byte in the Limb, without changing which limbs we are indexing
            if (native_endian == .big) {
                i ^= endian_mask;
                rev_i ^= endian_mask;
            }

            const bit_i = std.mem.readPackedInt(u1, bytes, i, .little);
            const bit_rev_i = std.mem.readPackedInt(u1, bytes, rev_i, .little);
            std.mem.writePackedInt(u1, bytes, i, bit_rev_i, .little);
            std.mem.writePackedInt(u1, bytes, rev_i, bit_i, .little);
        }

        // Calculate signed-magnitude representation for output
        if (signedness == .signed) {
            const last_bit = switch (native_endian) {
                .little => std.mem.readPackedInt(u1, bytes, bit_count - 1, .little),
                .big => std.mem.readPackedInt(u1, bytes, (bit_count - 1) ^ endian_mask, .little),
            };
            if (last_bit == 1) {
                r.bitNotWrap(r.toConst(), .unsigned, bit_count); // Bitwise NOT.
                r.addScalar(r.toConst(), 1); // Add one.
                r.positive = false; // Negate.
            }
        }
        r.normalize(r.len);
    }

    /// r = @byteSwap(a) with 2s-complement semantics.
    /// r and a may be aliases.
    ///
    /// Asserts the result fits in `r`. Upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(8*byte_count)`.
    pub fn byteSwap(r: *Mutable, a: Const, signedness: Signedness, byte_count: usize) void {
        if (byte_count == 0) return;

        r.copy(a);
        const limbs_required = calcTwosCompLimbCount(8 * byte_count);

        if (!a.positive) {
            r.positive = true; // Negate.
            r.bitNotWrap(r.toConst(), .unsigned, 8 * byte_count); // Bitwise NOT.
            r.addScalar(r.toConst(), 1); // Add one.
        } else if (limbs_required > a.limbs.len) {
            // Zero-extend to our output length
            for (r.limbs[a.limbs.len..limbs_required]) |*limb| {
                limb.* = 0;
            }
            r.len = limbs_required;
        }

        // 0b0..01..1 with @log2(@sizeOf(Limb)) trailing ones
        const endian_mask: usize = @sizeOf(Limb) - 1;

        var bytes = std.mem.sliceAsBytes(r.limbs);
        assert(bytes.len >= byte_count);

        var k: usize = 0;
        while (k < (byte_count + 1) / 2) : (k += 1) {
            var i = k;
            var rev_i = byte_count - k - 1;

            // This "endian mask" remaps a low (LE) byte to the corresponding high
            // (BE) byte in the Limb, without changing which limbs we are indexing
            if (native_endian == .big) {
                i ^= endian_mask;
                rev_i ^= endian_mask;
            }

            const byte_i = bytes[i];
            const byte_rev_i = bytes[rev_i];
            bytes[rev_i] = byte_i;
            bytes[i] = byte_rev_i;
        }

        // Calculate signed-magnitude representation for output
        if (signedness == .signed) {
            const last_byte = switch (native_endian) {
                .little => bytes[byte_count - 1],
                .big => bytes[(byte_count - 1) ^ endian_mask],
            };

            if (last_byte & (1 << 7) != 0) { // Check sign bit of last byte
                r.bitNotWrap(r.toConst(), .unsigned, 8 * byte_count); // Bitwise NOT.
                r.addScalar(r.toConst(), 1); // Add one.
                r.positive = false; // Negate.
            }
        }
        r.normalize(r.len);
    }

    /// r = @popCount(a) with 2s-complement semantics.
    /// r and a may be aliases.
    ///
    /// Assets the result fits in `r`. Upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn popCount(r: *Mutable, a: Const, bit_count: usize) void {
        r.copy(a);

        if (!a.positive) {
            r.positive = true; // Negate.
            r.bitNotWrap(r.toConst(), .unsigned, bit_count); // Bitwise NOT.
            r.addScalar(r.toConst(), 1); // Add one.
        }

        var sum: Limb = 0;
        for (r.limbs[0..r.len]) |limb| {
            sum += @popCount(limb);
        }
        r.set(sum);
    }

    /// rma = a * a
    ///
    /// `rma` may not alias with `a`.
    ///
    /// Asserts the result fits in `rma`. An upper bound on the number of limbs needed by
    /// rma is given by `2 * a.limbs.len + 1`.
    ///
    /// If `allocator` is provided, it will be used for temporary storage to improve
    /// multiplication performance. `error.OutOfMemory` is handled with a fallback algorithm.
    pub fn sqrNoAlias(rma: *Mutable, a: Const, opt_allocator: ?Allocator) void {
        _ = opt_allocator;
        assert(rma.limbs.ptr != a.limbs.ptr); // illegal aliasing

        @memset(rma.limbs, 0);

        llsquareBasecase(rma.limbs, a.limbs);

        rma.normalize(2 * a.limbs.len + 1);
        rma.positive = true;
    }

    /// q = a / b (rem r)
    ///
    /// a / b are floored (rounded towards 0).
    /// q may alias with a or b.
    ///
    /// Asserts there is enough memory to store q and r.
    /// The upper bound for r limb count is `b.limbs.len`.
    /// The upper bound for q limb count is given by `a.limbs`.
    ///
    /// `limbs_buffer` is used for temporary storage. The amount required is given by `calcDivLimbsBufferLen`.
    pub fn divFloor(
        q: *Mutable,
        r: *Mutable,
        a: Const,
        b: Const,
        limbs_buffer: []Limb,
    ) void {
        const sep = a.limbs.len + 2;
        var x = a.toMutable(limbs_buffer[0..sep]);
        var y = b.toMutable(limbs_buffer[sep..]);

        div(q, r, &x, &y);

        // Note, `div` performs truncating division, which satisfies
        // @divTrunc(a, b) * b + @rem(a, b) = a
        // so r = a - @divTrunc(a, b) * b
        // Note,  @rem(a, -b) = @rem(-b, a) = -@rem(a, b) = -@rem(-a, -b)
        // For divTrunc, we want to perform
        // @divFloor(a, b) * b + @mod(a, b) = a
        // Note:
        // @divFloor(-a, b)
        // = @divFloor(a, -b)
        // = -@divCeil(a, b)
        // = -@divFloor(a + b - 1, b)
        // = -@divTrunc(a + b - 1, b)

        // Note (1):
        // @divTrunc(a + b - 1, b) * b + @rem(a + b - 1, b) = a + b - 1
        // = @divTrunc(a + b - 1, b) * b + @rem(a - 1, b) = a + b - 1
        // = @divTrunc(a + b - 1, b) * b + @rem(a - 1, b) - b + 1 = a

        if (a.positive and b.positive) {
            // Positive-positive case, don't need to do anything.
        } else if (a.positive and !b.positive) {
            // a/-b -> q is negative, and so we need to fix flooring.
            // Subtract one to make the division flooring.

            // @divFloor(a, -b) * -b + @mod(a, -b) = a
            // If b divides a exactly, we have @divFloor(a, -b) * -b = a
            // Else, we have @divFloor(a, -b) * -b > a, so @mod(a, -b) becomes negative

            // We have:
            // @divFloor(a, -b) * -b + @mod(a, -b) = a
            // = -@divTrunc(a + b - 1, b) * -b + @mod(a, -b) = a
            // = @divTrunc(a + b - 1, b) * b + @mod(a, -b) = a

            // Substitute a for (1):
            // @divTrunc(a + b - 1, b) * b + @rem(a - 1, b) - b + 1 = @divTrunc(a + b - 1, b) * b + @mod(a, -b)
            // Yields:
            // @mod(a, -b) = @rem(a - 1, b) - b + 1
            // Note that `r` holds @rem(a, b) at this point.
            //
            // If @rem(a, b) is not 0:
            //   @rem(a - 1, b) = @rem(a, b) - 1
            //   => @mod(a, -b) = @rem(a, b) - 1 - b + 1 = @rem(a, b) - b
            // Else:
            //   @rem(a - 1, b) = @rem(a + b - 1, b) = @rem(b - 1, b) = b - 1
            //   => @mod(a, -b) = b - 1 - b + 1 = 0
            if (!r.eqlZero()) {
                q.addScalar(q.toConst(), -1);
                r.positive = true;
                r.sub(r.toConst(), y.toConst().abs());
            }
        } else if (!a.positive and b.positive) {
            // -a/b -> q is negative, and so we need to fix flooring.
            // Subtract one to make the division flooring.

            // @divFloor(-a, b) * b + @mod(-a, b) = a
            // If b divides a exactly, we have @divFloor(-a, b) * b = -a
            // Else, we have @divFloor(-a, b) * b < -a, so @mod(-a, b) becomes positive

            // We have:
            // @divFloor(-a, b) * b + @mod(-a, b) = -a
            // = -@divTrunc(a + b - 1, b) * b + @mod(-a, b) = -a
            // = @divTrunc(a + b - 1, b) * b - @mod(-a, b) = a

            // Substitute a for (1):
            // @divTrunc(a + b - 1, b) * b + @rem(a - 1, b) - b + 1 = @divTrunc(a + b - 1, b) * b - @mod(-a, b)
            // Yields:
            // @rem(a - 1, b) - b + 1 = -@mod(-a, b)
            // => -@mod(-a, b) = @rem(a - 1, b) - b + 1
            // => @mod(-a, b) = -(@rem(a - 1, b) - b + 1) = -@rem(a - 1, b) + b - 1
            //
            // If @rem(a, b) is not 0:
            //   @rem(a - 1, b) = @rem(a, b) - 1
            //   => @mod(-a, b) = -(@rem(a, b) - 1) + b - 1 = -@rem(a, b) + 1 + b - 1 = -@rem(a, b) + b
            // Else :
            //   @rem(a - 1, b) = b - 1
            //   => @mod(-a, b) = -(b - 1) + b - 1 = 0
            if (!r.eqlZero()) {
                q.addScalar(q.toConst(), -1);
                r.positive = false;
                r.add(r.toConst(), y.toConst().abs());
            }
        } else if (!a.positive and !b.positive) {
            // a/b -> q is positive, don't need to do anything to fix flooring.

            // @divFloor(-a, -b) * -b + @mod(-a, -b) = -a
            // If b divides a exactly, we have @divFloor(-a, -b) * -b = -a
            // Else, we have @divFloor(-a, -b) * -b > -a, so @mod(-a, -b) becomes negative

            // We have:
            // @divFloor(-a, -b) * -b + @mod(-a, -b) = -a
            // = @divTrunc(a, b) * -b + @mod(-a, -b) = -a
            // = @divTrunc(a, b) * b - @mod(-a, -b) = a

            // We also have:
            // @divTrunc(a, b) * b + @rem(a, b) = a

            // Substitute a:
            // @divTrunc(a, b) * b + @rem(a, b) = @divTrunc(a, b) * b - @mod(-a, -b)
            // => @rem(a, b) = -@mod(-a, -b)
            // => @mod(-a, -b) = -@rem(a, b)
            r.positive = false;
        }
    }

    /// q = a / b (rem r)
    ///
    /// a / b are truncated (rounded towards -inf).
    /// q may alias with a or b.
    ///
    /// Asserts there is enough memory to store q and r.
    /// The upper bound for r limb count is `b.limbs.len`.
    /// The upper bound for q limb count is given by `a.limbs.len`.
    ///
    /// `limbs_buffer` is used for temporary storage. The amount required is given by `calcDivLimbsBufferLen`.
    pub fn divTrunc(
        q: *Mutable,
        r: *Mutable,
        a: Const,
        b: Const,
        limbs_buffer: []Limb,
    ) void {
        const sep = a.limbs.len + 2;
        var x = a.toMutable(limbs_buffer[0..sep]);
        var y = b.toMutable(limbs_buffer[sep..]);

        div(q, r, &x, &y);
    }

    /// r = a << shift, in other words, r = a * 2^shift
    ///
    /// r and a may alias.
    ///
    /// Asserts there is enough memory to fit the result. The upper bound Limb count is
    /// `a.limbs.len + (shift / (@sizeOf(Limb) * 8))`.
    pub fn shiftLeft(r: *Mutable, a: Const, shift: usize) void {
        const new_len = llshl(r.limbs, a.limbs, shift);
        r.normalize(new_len);
        r.positive = a.positive;
    }

    /// r = a <<| shift with 2s-complement saturating semantics.
    ///
    /// r and a may alias.
    ///
    /// Asserts there is enough memory to fit the result. The upper bound Limb count is
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn shiftLeftSat(r: *Mutable, a: Const, shift: usize, signedness: Signedness, bit_count: usize) void {
        // Special case: When the argument is negative, but the result is supposed to be unsigned,
        // return 0 in all cases.
        if (!a.positive and signedness == .unsigned) {
            r.set(0);
            return;
        }

        // Check whether the shift is going to overflow. This is the case
        // when (in 2s complement) any bit above `bit_count - shift` is set in the unshifted value.
        // Note, the sign bit is not counted here.

        // Handle shifts larger than the target type. This also deals with
        // 0-bit integers.
        if (bit_count <= shift) {
            // In this case, there is only no overflow if `a` is zero.
            if (a.eqlZero()) {
                r.set(0);
            } else {
                r.setTwosCompIntLimit(if (a.positive) .max else .min, signedness, bit_count);
            }
            return;
        }

        const checkbit = bit_count - shift - @intFromBool(signedness == .signed);
        // If `checkbit` and more significant bits are zero, no overflow will take place.

        if (checkbit >= a.limbs.len * limb_bits) {
            // `checkbit` is outside the range of a, so definitely no overflow will take place. We
            // can defer to a normal shift.
            // Note that if `a` is normalized (which we assume), this checks for set bits in the upper limbs.

            // Note, in this case r should already have enough limbs required to perform the normal shift.
            // In this case the shift of the most significant limb may still overflow.
            r.shiftLeft(a, shift);
            return;
        } else if (checkbit < (a.limbs.len - 1) * limb_bits) {
            // `checkbit` is not in the most significant limb. If `a` is normalized the most significant
            // limb will not be zero, so in this case we need to saturate. Note that `a.limbs.len` must be
            // at least one according to normalization rules.

            r.setTwosCompIntLimit(if (a.positive) .max else .min, signedness, bit_count);
            return;
        }

        // Generate a mask with the bits to check in the most significant limb. We'll need to check
        // all bits with equal or more significance than checkbit.
        // const msb = @truncate(Log2Limb, checkbit);
        // const checkmask = (@as(Limb, 1) << msb) -% 1;

        if (a.limbs[a.limbs.len - 1] >> @as(Log2Limb, @truncate(checkbit)) != 0) {
            // Need to saturate.
            r.setTwosCompIntLimit(if (a.positive) .max else .min, signedness, bit_count);
            return;
        }

        // This shift should not be able to overflow, so invoke llshl and normalize manually
        // to avoid the extra required limb.
        const new_len = llshl(r.limbs, a.limbs, shift);
        r.normalize(new_len);
        r.positive = a.positive;
    }

    /// r = a >> shift
    /// r and a may alias.
    ///
    /// Asserts there is enough memory to fit the result. The upper bound Limb count is
    /// `a.limbs.len - (shift / (@bitSizeOf(Limb)))`.
    pub fn shiftRight(r: *Mutable, a: Const, shift: usize) void {
        const full_limbs_shifted_out = shift / limb_bits;
        const remaining_bits_shifted_out = shift % limb_bits;
        if (a.limbs.len <= full_limbs_shifted_out) {
            // Shifting negative numbers converges to -1 instead of 0
            if (a.positive) {
                r.len = 1;
                r.positive = true;
                r.limbs[0] = 0;
            } else {
                r.len = 1;
                r.positive = false;
                r.limbs[0] = 1;
            }
            return;
        }
        const nonzero_negative_shiftout = if (a.positive) false else nonzero: {
            for (a.limbs[0..full_limbs_shifted_out]) |x| {
                if (x != 0)
                    break :nonzero true;
            }
            if (remaining_bits_shifted_out == 0)
                break :nonzero false;
            const not_covered: Log2Limb = @intCast(limb_bits - remaining_bits_shifted_out);
            break :nonzero a.limbs[full_limbs_shifted_out] << not_covered != 0;
        };

        const new_len = llshr(r.limbs, a.limbs, shift);

        r.len = new_len;
        r.positive = a.positive;
        if (nonzero_negative_shiftout) r.addScalar(r.toConst(), -1);
        r.normalize(r.len);
    }

    /// r = ~a under 2s complement wrapping semantics.
    /// r may alias with a.
    ///
    /// Assets that r has enough limbs to store the result. The upper bound Limb count is
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn bitNotWrap(r: *Mutable, a: Const, signedness: Signedness, bit_count: usize) void {
        r.copy(a.negate());
        const negative_one = Const{ .limbs = &.{1}, .positive = false };
        _ = r.addWrap(r.toConst(), negative_one, signedness, bit_count);
    }

    /// r = a | b under 2s complement semantics.
    /// r may alias with a or b.
    ///
    /// a and b are zero-extended to the longer of a or b.
    ///
    /// Asserts that r has enough limbs to store the result. Upper bound is `@max(a.limbs.len, b.limbs.len)`.
    pub fn bitOr(r: *Mutable, a: Const, b: Const) void {
        // Trivial cases, llsignedor does not support zero.
        if (a.eqlZero()) {
            r.copy(b);
            return;
        } else if (b.eqlZero()) {
            r.copy(a);
            return;
        }

        if (a.limbs.len >= b.limbs.len) {
            r.positive = llsignedor(r.limbs, a.limbs, a.positive, b.limbs, b.positive);
            r.normalize(if (b.positive) a.limbs.len else b.limbs.len);
        } else {
            r.positive = llsignedor(r.limbs, b.limbs, b.positive, a.limbs, a.positive);
            r.normalize(if (a.positive) b.limbs.len else a.limbs.len);
        }
    }

    /// r = a & b under 2s complement semantics.
    /// r may alias with a or b.
    ///
    /// Asserts that r has enough limbs to store the result.
    /// If only a is positive, the upper bound is `a.limbs.len`.
    /// If only b is positive, the upper bound is `b.limbs.len`.
    /// If a and b are positive, the upper bound is `@min(a.limbs.len, b.limbs.len)`.
    /// If a and b are negative, the upper bound is `@max(a.limbs.len, b.limbs.len) + 1`.
    pub fn bitAnd(r: *Mutable, a: Const, b: Const) void {
        // Trivial cases, llsignedand does not support zero.
        if (a.eqlZero()) {
            r.copy(a);
            return;
        } else if (b.eqlZero()) {
            r.copy(b);
            return;
        }

        if (a.limbs.len >= b.limbs.len) {
            r.positive = llsignedand(r.limbs, a.limbs, a.positive, b.limbs, b.positive);
            r.normalize(if (b.positive) b.limbs.len else if (a.positive) a.limbs.len else a.limbs.len + 1);
        } else {
            r.positive = llsignedand(r.limbs, b.limbs, b.positive, a.limbs, a.positive);
            r.normalize(if (a.positive) a.limbs.len else if (b.positive) b.limbs.len else b.limbs.len + 1);
        }
    }

    /// r = a ^ b under 2s complement semantics.
    /// r may alias with a or b.
    ///
    /// Asserts that r has enough limbs to store the result. If a and b share the same signedness, the
    /// upper bound is `@max(a.limbs.len, b.limbs.len)`. Otherwise, if either a or b is negative
    /// but not both, the upper bound is `@max(a.limbs.len, b.limbs.len) + 1`.
    pub fn bitXor(r: *Mutable, a: Const, b: Const) void {
        // Trivial cases, because llsignedxor does not support negative zero.
        if (a.eqlZero()) {
            r.copy(b);
            return;
        } else if (b.eqlZero()) {
            r.copy(a);
            return;
        }

        if (a.limbs.len > b.limbs.len) {
            r.positive = llsignedxor(r.limbs, a.limbs, a.positive, b.limbs, b.positive);
            r.normalize(a.limbs.len + @intFromBool(a.positive != b.positive));
        } else {
            r.positive = llsignedxor(r.limbs, b.limbs, b.positive, a.limbs, a.positive);
            r.normalize(b.limbs.len + @intFromBool(a.positive != b.positive));
        }
    }

    /// rma may alias x or y.
    /// x and y may alias each other.
    /// Asserts that `rma` has enough limbs to store the result. Upper bound is
    /// `@min(x.limbs.len, y.limbs.len)`.
    ///
    /// `limbs_buffer` is used for temporary storage during the operation. When this function returns,
    /// it will have the same length as it had when the function was called.
    pub fn gcd(rma: *Mutable, x: Const, y: Const, limbs_buffer: *std.ArrayList(Limb)) !void {
        const prev_len = limbs_buffer.items.len;
        defer limbs_buffer.shrinkRetainingCapacity(prev_len);
        const x_copy = if (rma.limbs.ptr == x.limbs.ptr) blk: {
            const start = limbs_buffer.items.len;
            try limbs_buffer.appendSlice(x.limbs);
            break :blk x.toMutable(limbs_buffer.items[start..]).toConst();
        } else x;
        const y_copy = if (rma.limbs.ptr == y.limbs.ptr) blk: {
            const start = limbs_buffer.items.len;
            try limbs_buffer.appendSlice(y.limbs);
            break :blk y.toMutable(limbs_buffer.items[start..]).toConst();
        } else y;

        return gcdLehmer(rma, x_copy, y_copy, limbs_buffer);
    }

    /// q = a ^ b
    ///
    /// r may not alias a.
    ///
    /// Asserts that `r` has enough limbs to store the result. Upper bound is
    /// `calcPowLimbsBufferLen(a.bitCountAbs(), b)`.
    ///
    /// `limbs_buffer` is used for temporary storage.
    /// The amount required is given by `calcPowLimbsBufferLen`.
    pub fn pow(r: *Mutable, a: Const, b: u32, limbs_buffer: []Limb) void {
        assert(r.limbs.ptr != a.limbs.ptr); // illegal aliasing

        // Handle all the trivial cases first
        switch (b) {
            0 => {
                // a^0 = 1
                return r.set(1);
            },
            1 => {
                // a^1 = a
                return r.copy(a);
            },
            else => {},
        }

        if (a.eqlZero()) {
            // 0^b = 0
            return r.set(0);
        } else if (a.limbs.len == 1 and a.limbs[0] == 1) {
            // 1^b = 1 and -1^b = ±1
            r.set(1);
            r.positive = a.positive or (b & 1) == 0;
            return;
        }

        // Here a>1 and b>1
        const needed_limbs = calcPowLimbsBufferLen(a.bitCountAbs(), b);
        assert(r.limbs.len >= needed_limbs);
        assert(limbs_buffer.len >= needed_limbs);

        llpow(r.limbs, a.limbs, b, limbs_buffer);

        r.normalize(needed_limbs);
        r.positive = a.positive or (b & 1) == 0;
    }

    /// r = ⌊√a⌋
    ///
    /// r may alias a.
    ///
    /// Asserts that `r` has enough limbs to store the result. Upper bound is
    /// `(a.limbs.len - 1) / 2 + 1`.
    ///
    /// `limbs_buffer` is used for temporary storage.
    /// The amount required is given by `calcSqrtLimbsBufferLen`.
    pub fn sqrt(
        r: *Mutable,
        a: Const,
        limbs_buffer: []Limb,
    ) void {
        // Brent and Zimmermann, Modern Computer Arithmetic, Algorithm 1.13 SqrtInt
        // https://members.loria.fr/PZimmermann/mca/pub226.html
        var buf_index: usize = 0;
        var t = b: {
            const start = buf_index;
            buf_index += a.limbs.len;
            break :b Mutable.init(limbs_buffer[start..buf_index], 0);
        };
        var u = b: {
            const start = buf_index;
            const shift = (a.bitCountAbs() + 1) / 2;
            buf_index += 1 + ((shift / limb_bits) + 1);
            var m = Mutable.init(limbs_buffer[start..buf_index], 1);
            m.shiftLeft(m.toConst(), shift); // u must be >= ⌊√a⌋, and should be as small as possible for efficiency
            break :b m;
        };
        var s = b: {
            const start = buf_index;
            buf_index += u.limbs.len;
            break :b u.toConst().toMutable(limbs_buffer[start..buf_index]);
        };
        var rem = b: {
            const start = buf_index;
            buf_index += s.limbs.len;
            break :b Mutable.init(limbs_buffer[start..buf_index], 0);
        };

        while (true) {
            t.divFloor(&rem, a, s.toConst(), limbs_buffer[buf_index..]);
            t.add(t.toConst(), s.toConst());
            u.shiftRight(t.toConst(), 1);

            if (u.toConst().order(s.toConst()).compare(.gte)) {
                r.copy(s.toConst());
                return;
            }

            // Avoid copying u to s by swapping u and s
            const tmp_s = s;
            s = u;
            u = tmp_s;
        }
    }

    /// rma may not alias x or y.
    /// x and y may alias each other.
    /// Asserts that `rma` has enough limbs to store the result. Upper bound is given by `calcGcdNoAliasLimbLen`.
    ///
    /// `limbs_buffer` is used for temporary storage during the operation.
    pub fn gcdNoAlias(rma: *Mutable, x: Const, y: Const, limbs_buffer: *std.ArrayList(Limb)) !void {
        assert(rma.limbs.ptr != x.limbs.ptr); // illegal aliasing
        assert(rma.limbs.ptr != y.limbs.ptr); // illegal aliasing
        return gcdLehmer(rma, x, y, limbs_buffer);
    }

    fn gcdLehmer(result: *Mutable, xa: Const, ya: Const, limbs_buffer: *std.ArrayList(Limb)) !void {
        var x = try xa.toManaged(limbs_buffer.allocator);
        defer x.deinit();
        x.abs();

        var y = try ya.toManaged(limbs_buffer.allocator);
        defer y.deinit();
        y.abs();

        if (x.toConst().order(y.toConst()) == .lt) {
            x.swap(&y);
        }

        var t_big = try Managed.init(limbs_buffer.allocator);
        defer t_big.deinit();

        var r = try Managed.init(limbs_buffer.allocator);
        defer r.deinit();

        var tmp_x = try Managed.init(limbs_buffer.allocator);
        defer tmp_x.deinit();

        while (y.len() > 1 and !y.eqlZero()) {
            assert(x.isPositive() and y.isPositive());
            assert(x.len() >= y.len());

            var xh: SignedDoubleLimb = x.limbs[x.len() - 1];
            var yh: SignedDoubleLimb = if (x.len() > y.len()) 0 else y.limbs[x.len() - 1];

            var A: SignedDoubleLimb = 1;
            var B: SignedDoubleLimb = 0;
            var C: SignedDoubleLimb = 0;
            var D: SignedDoubleLimb = 1;

            while (yh + C != 0 and yh + D != 0) {
                const q = @divFloor(xh + A, yh + C);
                const qp = @divFloor(xh + B, yh + D);
                if (q != qp) {
                    break;
                }

                var t = A - q * C;
                A = C;
                C = t;
                t = B - q * D;
                B = D;
                D = t;

                t = xh - q * yh;
                xh = yh;
                yh = t;
            }

            if (B == 0) {
                // t_big = x % y, r is unused
                try r.divTrunc(&t_big, &x, &y);
                assert(t_big.isPositive());

                x.swap(&y);
                y.swap(&t_big);
            } else {
                var storage: [8]Limb = undefined;
                const Ap = fixedIntFromSignedDoubleLimb(A, storage[0..2]).toManaged(limbs_buffer.allocator);
                const Bp = fixedIntFromSignedDoubleLimb(B, storage[2..4]).toManaged(limbs_buffer.allocator);
                const Cp = fixedIntFromSignedDoubleLimb(C, storage[4..6]).toManaged(limbs_buffer.allocator);
                const Dp = fixedIntFromSignedDoubleLimb(D, storage[6..8]).toManaged(limbs_buffer.allocator);

                // t_big = Ax + By
                try r.mul(&x, &Ap);
                try t_big.mul(&y, &Bp);
                try t_big.add(&r, &t_big);

                // u = Cx + Dy, r as u
                try tmp_x.copy(x.toConst());
                try x.mul(&tmp_x, &Cp);
                try r.mul(&y, &Dp);
                try r.add(&x, &r);

                x.swap(&t_big);
                y.swap(&r);
            }
        }

        // euclidean algorithm
        assert(x.toConst().order(y.toConst()) != .lt);

        while (!y.toConst().eqlZero()) {
            try t_big.divTrunc(&r, &x, &y);
            x.swap(&y);
            y.swap(&r);
        }

        result.copy(x.toConst());
    }

    // Truncates by default.
    fn div(q: *Mutable, r: *Mutable, x: *Mutable, y: *Mutable) void {
        assert(!y.eqlZero()); // division by zero
        assert(q != r); // illegal aliasing

        const q_positive = (x.positive == y.positive);
        const r_positive = x.positive;

        if (x.toConst().orderAbs(y.toConst()) == .lt) {
            // q may alias x so handle r first.
            r.copy(x.toConst());
            r.positive = r_positive;

            q.set(0);
            return;
        }

        // Handle trailing zero-words of divisor/dividend. These are not handled in the following
        // algorithms.
        // Note, there must be a non-zero limb for either.
        // const x_trailing = std.mem.indexOfScalar(Limb, x.limbs[0..x.len], 0).?;
        // const y_trailing = std.mem.indexOfScalar(Limb, y.limbs[0..y.len], 0).?;

        const x_trailing = for (x.limbs[0..x.len], 0..) |xi, i| {
            if (xi != 0) break i;
        } else unreachable;

        const y_trailing = for (y.limbs[0..y.len], 0..) |yi, i| {
            if (yi != 0) break i;
        } else unreachable;

        const xy_trailing = @min(x_trailing, y_trailing);

        if (y.len - xy_trailing == 1) {
            const divisor = y.limbs[y.len - 1];

            // Optimization for small divisor. By using a half limb we can avoid requiring DoubleLimb
            // divisions in the hot code path. This may often require compiler_rt software-emulation.
            if (divisor < maxInt(HalfLimb)) {
                lldiv0p5(q.limbs, &r.limbs[0], x.limbs[xy_trailing..x.len], @as(HalfLimb, @intCast(divisor)));
            } else {
                lldiv1(q.limbs, &r.limbs[0], x.limbs[xy_trailing..x.len], divisor);
            }

            q.normalize(x.len - xy_trailing);
            q.positive = q_positive;

            r.len = 1;
            r.positive = r_positive;
        } else {
            // Shrink x, y such that the trailing zero limbs shared between are removed.
            var x0 = Mutable{
                .limbs = x.limbs[xy_trailing..],
                .len = x.len - xy_trailing,
                .positive = true,
            };

            var y0 = Mutable{
                .limbs = y.limbs[xy_trailing..],
                .len = y.len - xy_trailing,
                .positive = true,
            };

            divmod(q, r, &x0, &y0);
            q.positive = q_positive;

            r.positive = r_positive;
        }

        if (xy_trailing != 0 and r.limbs[r.len - 1] != 0) {
            // Manually shift here since we know its limb aligned.
            mem.copyBackwards(Limb, r.limbs[xy_trailing..], r.limbs[0..r.len]);
            @memset(r.limbs[0..xy_trailing], 0);
            r.len += xy_trailing;
        }
    }

    /// Handbook of Applied Cryptography, 14.20
    ///
    /// x = qy + r where 0 <= r < y
    /// y is modified but returned intact.
    fn divmod(
        q: *Mutable,
        r: *Mutable,
        x: *Mutable,
        y: *Mutable,
    ) void {
        // 0.
        // Normalize so that y[t] > b/2
        const lz = @clz(y.limbs[y.len - 1]);
        const norm_shift = if (lz == 0 and y.toConst().isOdd())
            limb_bits // Force an extra limb so that y is even.
        else
            lz;

        x.shiftLeft(x.toConst(), norm_shift);
        y.shiftLeft(y.toConst(), norm_shift);

        const n = x.len - 1;
        const t = y.len - 1;
        const shift = n - t;

        // 1.
        // for 0 <= j <= n - t, set q[j] to 0
        q.len = shift + 1;
        q.positive = true;
        @memset(q.limbs[0..q.len], 0);

        // 2.
        // while x >= y * b^(n - t):
        //    x -= y * b^(n - t)
        //    q[n - t] += 1
        // Note, this algorithm is performed only once if y[t] > base/2 and y is even, which we
        // enforced in step 0. This means we can replace the while with an if.
        // Note, multiplication by b^(n - t) comes down to shifting to the right by n - t limbs.
        // We can also replace x >= y * b^(n - t) by x/b^(n - t) >= y, and use shifts for that.
        {
            // x >= y * b^(n - t) can be replaced by x/b^(n - t) >= y.

            // 'divide' x by b^(n - t)
            var tmp = Mutable{
                .limbs = x.limbs[shift..],
                .len = x.len - shift,
                .positive = true,
            };

            if (tmp.toConst().order(y.toConst()) != .lt) {
                // Perform x -= y * b^(n - t)
                // Note, we can subtract y from x[n - t..] and get the result without shifting.
                // We can also re-use tmp which already contains the relevant part of x. Note that
                // this also edits x.
                // Due to the check above, this cannot underflow.
                tmp.sub(tmp.toConst(), y.toConst());

                // tmp.sub normalized tmp, but we need to normalize x now.
                x.limbs.len = tmp.limbs.len + shift;

                q.limbs[shift] += 1;
            }
        }

        // 3.
        // for i from n down to t + 1, do
        var i = n;
        while (i >= t + 1) : (i -= 1) {
            const k = i - t - 1;
            // 3.1.
            // if x_i == y_t:
            //   q[i - t - 1] = b - 1
            // else:
            //   q[i - t - 1] = (x[i] * b + x[i - 1]) / y[t]
            if (x.limbs[i] == y.limbs[t]) {
                q.limbs[k] = maxInt(Limb);
            } else {
                const q0 = (@as(DoubleLimb, x.limbs[i]) << limb_bits) | @as(DoubleLimb, x.limbs[i - 1]);
                const n0 = @as(DoubleLimb, y.limbs[t]);
                q.limbs[k] = @as(Limb, @intCast(q0 / n0));
            }

            // 3.2
            // while q[i - t - 1] * (y[t] * b + y[t - 1] > x[i] * b * b + x[i - 1] + x[i - 2]:
            //   q[i - t - 1] -= 1
            // Note, if y[t] > b / 2 this part is repeated no more than twice.

            // Extract from y.
            const y0 = if (t > 0) y.limbs[t - 1] else 0;
            const y1 = y.limbs[t];

            // Extract from x.
            // Note, big endian.
            const tmp0 = [_]Limb{
                x.limbs[i],
                if (i >= 1) x.limbs[i - 1] else 0,
                if (i >= 2) x.limbs[i - 2] else 0,
            };

            while (true) {
                // Ad-hoc 2x1 multiplication with q[i - t - 1].
                // Note, big endian.
                var tmp1 = [_]Limb{ 0, undefined, undefined };
                tmp1[2] = addMulLimbWithCarry(0, y0, q.limbs[k], &tmp1[0]);
                tmp1[1] = addMulLimbWithCarry(0, y1, q.limbs[k], &tmp1[0]);

                // Big-endian compare
                if (mem.order(Limb, &tmp1, &tmp0) != .gt)
                    break;

                q.limbs[k] -= 1;
            }

            // 3.3.
            // x -= q[i - t - 1] * y * b^(i - t - 1)
            // Note, we multiply by a single limb here.
            // The shift doesn't need to be performed if we add the result of the first multiplication
            // to x[i - t - 1].
            const underflow = llmulLimb(.sub, x.limbs[k..x.len], y.limbs[0..y.len], q.limbs[k]);

            // 3.4.
            // if x < 0:
            //   x += y * b^(i - t - 1)
            //   q[i - t - 1] -= 1
            // Note, we check for x < 0 using the underflow flag from the previous operation.
            if (underflow) {
                // While we didn't properly set the signedness of x, this operation should 'flow' it back to positive.
                llaccum(.add, x.limbs[k..x.len], y.limbs[0..y.len]);
                q.limbs[k] -= 1;
            }
        }

        x.normalize(x.len);
        q.normalize(q.len);

        // De-normalize r and y.
        r.shiftRight(x.toConst(), norm_shift);
        y.shiftRight(y.toConst(), norm_shift);
    }

    /// Truncate an integer to a number of bits, following 2s-complement semantics.
    /// `r` may alias `a`.
    ///
    /// Asserts `r` has enough storage to compute the result.
    /// The upper bound is `calcTwosCompLimbCount(a.len)`.
    pub fn truncate(r: *Mutable, a: Const, signedness: Signedness, bit_count: usize) void {
        // Handle 0-bit integers.
        if (bit_count == 0) {
            @branchHint(.unlikely);
            r.set(0);
            return;
        }

        const max_limbs = calcTwosCompLimbCount(bit_count);
        const sign_bit = @as(Limb, 1) << @truncate(bit_count - 1);
        const mask = @as(Limb, maxInt(Limb)) >> @truncate(-%bit_count);

        // Guess whether the result will have the same sign as `a`.
        //  * If the result will be signed zero, the guess is `true`.
        //  * If the result will be the minimum signed integer, the guess is `false`.
        //  * If the result will be unsigned zero, the guess is `a.positive`.
        //  * Otherwise the guess is correct.
        const same_sign_guess = switch (signedness) {
            .signed => max_limbs > a.limbs.len or a.limbs[max_limbs - 1] & sign_bit == 0,
            .unsigned => a.positive,
        };

        const abs_trunc_a: Const = .{
            .positive = true,
            .limbs = a.limbs[0..llnormalize(a.limbs[0..@min(a.limbs.len, max_limbs)])],
        };
        if (same_sign_guess or abs_trunc_a.eqlZero()) {
            // One of the following is true:
            //  * The result is zero.
            //  * The result is non-zero and has the same sign as `a`.
            r.copy(abs_trunc_a);
            if (max_limbs <= r.len) r.limbs[max_limbs - 1] &= mask;
            r.normalize(r.len);
            r.positive = a.positive or r.eqlZero();
        } else {
            // One of the following is true:
            //  * The result is the minimum signed integer.
            //  * The result is unsigned zero.
            //  * The result is non-zero and has the opposite sign as `a`.
            r.addScalar(abs_trunc_a, -1);
            llnot(r.limbs[0..r.len]);
            @memset(r.limbs[r.len..max_limbs], maxInt(Limb));
            r.limbs[max_limbs - 1] &= mask;
            r.normalize(max_limbs);
            r.positive = switch (signedness) {
                // The only value with the sign bit still set is the minimum signed integer.
                .signed => !a.positive and r.limbs[max_limbs - 1] & sign_bit == 0,
                .unsigned => !a.positive or r.eqlZero(),
            };
        }
    }

    /// Saturate an integer to a number of bits, following 2s-complement semantics.
    /// r may alias a.
    ///
    /// Asserts `r` has enough storage to store the result.
    /// The upper bound is `calcTwosCompLimbCount(a.len)`.
    pub fn saturate(r: *Mutable, a: Const, signedness: Signedness, bit_count: usize) void {
        if (!a.fitsInTwosComp(signedness, bit_count)) {
            r.setTwosCompIntLimit(if (r.positive) .max else .min, signedness, bit_count);
        }
    }

    /// Read the value of `x` from `buffer`.
    /// Asserts that `buffer` is large enough to contain a value of bit-size `bit_count`.
    ///
    /// The contents of `buffer` are interpreted as if they were the contents of
    /// @ptrCast(*[buffer.len]const u8, &x). Byte ordering is determined by `endian`
    /// and any required padding bits are expected on the MSB end.
    pub fn readTwosComplement(
        x: *Mutable,
        buffer: []const u8,
        bit_count: usize,
        endian: Endian,
        signedness: Signedness,
    ) void {
        return readPackedTwosComplement(x, buffer, 0, bit_count, endian, signedness);
    }

    /// Read the value of `x` from a packed memory `buffer`.
    /// Asserts that `buffer` is large enough to contain a value of bit-size `bit_count`
    /// at offset `bit_offset`.
    ///
    /// This is equivalent to loading the value of an integer with `bit_count` bits as
    /// if it were a field in packed memory at the provided bit offset.
    pub fn readPackedTwosComplement(
        x: *Mutable,
        buffer: []const u8,
        bit_offset: usize,
        bit_count: usize,
        endian: Endian,
        signedness: Signedness,
    ) void {
        if (bit_count == 0) {
            x.limbs[0] = 0;
            x.len = 1;
            x.positive = true;
            return;
        }

        // Check whether the input is negative
        var positive = true;
        if (signedness == .signed) {
            const total_bits = bit_offset + bit_count;
            const last_byte = switch (endian) {
                .little => ((total_bits + 7) / 8) - 1,
                .big => buffer.len - ((total_bits + 7) / 8),
            };

            const sign_bit = @as(u8, 1) << @as(u3, @intCast((total_bits - 1) % 8));
            positive = ((buffer[last_byte] & sign_bit) == 0);
        }

        // Copy all complete limbs
        var carry: u1 = 1;
        var limb_index: usize = 0;
        var bit_index: usize = 0;
        while (limb_index < bit_count / @bitSizeOf(Limb)) : (limb_index += 1) {
            // Read one Limb of bits
            var limb = mem.readPackedInt(Limb, buffer, bit_index + bit_offset, endian);
            bit_index += @bitSizeOf(Limb);

            // 2's complement (bitwise not, then add carry bit)
            if (!positive) {
                const ov = @addWithOverflow(~limb, carry);
                limb = ov[0];
                carry = ov[1];
            }
            x.limbs[limb_index] = limb;
        }

        // Copy the remaining bits
        if (bit_count != bit_index) {
            // Read all remaining bits
            var limb = switch (signedness) {
                .unsigned => mem.readVarPackedInt(Limb, buffer, bit_index + bit_offset, bit_count - bit_index, endian, .unsigned),
                .signed => b: {
                    const SLimb = std.meta.Int(.signed, @bitSizeOf(Limb));
                    const limb = mem.readVarPackedInt(SLimb, buffer, bit_index + bit_offset, bit_count - bit_index, endian, .signed);
                    break :b @as(Limb, @bitCast(limb));
                },
            };

            // 2's complement (bitwise not, then add carry bit)
            if (!positive) {
                const ov = @addWithOverflow(~limb, carry);
                assert(ov[1] == 0);
                limb = ov[0];
            }
            x.limbs[limb_index] = limb;

            limb_index += 1;
        }

        x.positive = positive;
        x.len = limb_index;
        x.normalize(x.len);
    }

    /// Normalize a possible sequence of leading zeros.
    ///
    /// [1, 2, 3, 4, 0] -> [1, 2, 3, 4]
    /// [1, 2, 0, 0, 0] -> [1, 2]
    /// [0, 0, 0, 0, 0] -> [0]
    pub fn normalize(r: *Mutable, length: usize) void {
        r.len = llnormalize(r.limbs[0..length]);
    }
};

/// A arbitrary-precision big integer, with a fixed set of immutable limbs.
pub const Const = struct {
    /// Raw digits. These are:
    ///
    /// * Little-endian ordered
    /// * limbs.len >= 1
    /// * Zero is represented as limbs.len == 1 with limbs[0] == 0.
    ///
    /// Accessing limbs directly should be avoided.
    limbs: []const Limb,
    positive: bool,

    /// The result is an independent resource which is managed by the caller.
    pub fn toManaged(self: Const, allocator: Allocator) Allocator.Error!Managed {
        const limbs = try allocator.alloc(Limb, @max(Managed.default_capacity, self.limbs.len));
        @memcpy(limbs[0..self.limbs.len], self.limbs);
        return Managed{
            .allocator = allocator,
            .limbs = limbs,
            .metadata = if (self.positive)
                self.limbs.len & ~Managed.sign_bit
            else
                self.limbs.len | Managed.sign_bit,
        };
    }

    /// Asserts `limbs` is big enough to store the value.
    pub fn toMutable(self: Const, limbs: []Limb) Mutable {
        @memcpy(limbs[0..self.limbs.len], self.limbs[0..self.limbs.len]);
        return .{
            .limbs = limbs,
            .positive = self.positive,
            .len = self.limbs.len,
        };
    }

    pub fn dump(self: Const) void {
        for (self.limbs[0..self.limbs.len]) |limb| {
            std.debug.print("{x} ", .{limb});
        }
        std.debug.print("len={} positive={}\n", .{ self.len, self.positive });
    }

    pub fn abs(self: Const) Const {
        return .{
            .limbs = self.limbs,
            .positive = true,
        };
    }

    pub fn negate(self: Const) Const {
        return .{
            .limbs = self.limbs,
            .positive = !self.positive,
        };
    }

    pub fn isOdd(self: Const) bool {
        return self.limbs[0] & 1 != 0;
    }

    pub fn isEven(self: Const) bool {
        return !self.isOdd();
    }

    /// Returns the number of bits required to represent the absolute value of an integer.
    pub fn bitCountAbs(self: Const) usize {
        return (self.limbs.len - 1) * limb_bits + (limb_bits - @clz(self.limbs[self.limbs.len - 1]));
    }

    /// Returns the number of bits required to represent the integer in twos-complement form.
    ///
    /// If the integer is negative the value returned is the number of bits needed by a signed
    /// integer to represent the value. If positive the value is the number of bits for an
    /// unsigned integer. Any unsigned integer will fit in the signed integer with bitcount
    /// one greater than the returned value.
    ///
    /// e.g. -127 returns 8 as it will fit in an i8. 127 returns 7 since it fits in a u7.
    pub fn bitCountTwosComp(self: Const) usize {
        var bits = self.bitCountAbs();

        // If the entire value has only one bit set (e.g. 0b100000000) then the negation in twos
        // complement requires one less bit.
        if (!self.positive) block: {
            bits += 1;

            if (@popCount(self.limbs[self.limbs.len - 1]) == 1) {
                for (self.limbs[0 .. self.limbs.len - 1]) |limb| {
                    if (@popCount(limb) != 0) {
                        break :block;
                    }
                }

                bits -= 1;
            }
        }

        return bits;
    }

    /// Returns the number of bits required to represent the integer in twos-complement form
    /// with the given signedness.
    pub fn bitCountTwosCompForSignedness(self: Const, signedness: std.builtin.Signedness) usize {
        return self.bitCountTwosComp() + @intFromBool(self.positive and signedness == .signed);
    }

    /// @popCount with two's complement semantics.
    ///
    /// This returns the number of 1 bits set when the value would be represented in
    /// two's complement with the given integer width (bit_count).
    /// This includes the leading sign bit, which will be set for negative values.
    ///
    /// Asserts that bit_count is enough to represent value in two's compliment
    /// and that the final result fits in a usize.
    /// Asserts that there are no trailing empty limbs on the most significant end,
    /// i.e. that limb count matches `calcLimbLen()` and zero is not negative.
    pub fn popCount(self: Const, bit_count: usize) usize {
        var sum: usize = 0;
        if (self.positive) {
            for (self.limbs) |limb| {
                sum += @popCount(limb);
            }
        } else {
            assert(self.fitsInTwosComp(.signed, bit_count));
            assert(self.limbs[self.limbs.len - 1] != 0);

            var remaining_bits = bit_count;
            var carry: u1 = 1;
            var add_res: Limb = undefined;

            // All but the most significant limb.
            for (self.limbs[0 .. self.limbs.len - 1]) |limb| {
                const ov = @addWithOverflow(~limb, carry);
                add_res = ov[0];
                carry = ov[1];
                sum += @popCount(add_res);
                remaining_bits -= limb_bits; // Asserted not to underflow by fitsInTwosComp
            }

            // The most significant limb may have fewer than @bitSizeOf(Limb) meaningful bits,
            // which we can detect with @clz().
            // There may also be fewer limbs than needed to fill bit_count.
            const limb = self.limbs[self.limbs.len - 1];
            const leading_zeroes = @clz(limb);
            // The most significant limb is asserted not to be all 0s (above),
            // so ~limb cannot be all 1s, and ~limb + 1 cannot overflow.
            sum += @popCount(~limb + carry);
            sum -= leading_zeroes; // All leading zeroes were flipped and added to sum, so undo those
            const remaining_ones = remaining_bits - (limb_bits - leading_zeroes); // All bits not covered by limbs
            sum += remaining_ones;
        }
        return sum;
    }

    pub fn fitsInTwosComp(self: Const, signedness: Signedness, bit_count: usize) bool {
        if (self.eqlZero()) {
            return true;
        }
        if (signedness == .unsigned and !self.positive) {
            return false;
        }
        return bit_count >= self.bitCountTwosCompForSignedness(signedness);
    }

    /// Returns whether self can fit into an integer of the requested type.
    pub fn fits(self: Const, comptime T: type) bool {
        const info = @typeInfo(T).int;
        return self.fitsInTwosComp(info.signedness, info.bits);
    }

    /// Returns the approximate size of the integer in the given base. Negative values accommodate for
    /// the minus sign. This is used for determining the number of characters needed to print the
    /// value. It is inexact and may exceed the given value by ~1-2 bytes.
    /// TODO See if we can make this exact.
    pub fn sizeInBaseUpperBound(self: Const, base: usize) usize {
        const bit_count = @as(usize, @intFromBool(!self.positive)) + self.bitCountAbs();
        return (bit_count / math.log2(base)) + 2;
    }

    pub const ConvertError = error{
        NegativeIntoUnsigned,
        TargetTooSmall,
    };

    /// Deprecated; use `toInt`.
    pub const to = toInt;

    /// Convert self to integer type T.
    ///
    /// Returns an error if self cannot be narrowed into the requested type without truncation.
    pub fn toInt(self: Const, comptime T: type) ConvertError!T {
        switch (@typeInfo(T)) {
            .int => |info| {
                // Make sure -0 is handled correctly.
                if (self.eqlZero()) return 0;

                const UT = std.meta.Int(.unsigned, info.bits);

                if (!self.fitsInTwosComp(info.signedness, info.bits)) {
                    return error.TargetTooSmall;
                }

                var r: UT = 0;

                if (@sizeOf(UT) <= @sizeOf(Limb)) {
                    r = @as(UT, @intCast(self.limbs[0]));
                } else {
                    for (self.limbs[0..self.limbs.len], 0..) |_, ri| {
                        const limb = self.limbs[self.limbs.len - ri - 1];
                        r <<= limb_bits;
                        r |= limb;
                    }
                }

                if (info.signedness == .unsigned) {
                    return if (self.positive) @as(T, @intCast(r)) else error.NegativeIntoUnsigned;
                } else {
                    if (self.positive) {
                        return @intCast(r);
                    } else {
                        if (math.cast(T, r)) |ok| {
                            return -ok;
                        } else {
                            return minInt(T);
                        }
                    }
                }
            },
            else => @compileError("expected int type, found '" ++ @typeName(T) ++ "'"),
        }
    }

    /// Convert self to float type T.
    pub fn toFloat(self: Const, comptime T: type) T {
        if (self.limbs.len == 0) return 0;

        const base = std.math.maxInt(std.math.big.Limb) + 1;
        var result: f128 = 0;
        var i: usize = self.limbs.len;
        while (i != 0) {
            i -= 1;
            const limb: f128 = @floatFromInt(self.limbs[i]);
            result = @mulAdd(f128, base, result, limb);
        }
        if (self.positive) {
            return @floatCast(result);
        } else {
            return @floatCast(-result);
        }
    }

    /// To allow `std.fmt.format` to work with this type.
    /// If the absolute value of integer is greater than or equal to `pow(2, 64 * @sizeOf(usize) * 8)`,
    /// this function will fail to print the string, printing "(BigInt)" instead of a number.
    /// This is because the rendering algorithm requires reversing a string, which requires O(N) memory.
    /// See `toString` and `toStringAlloc` for a way to print big integers without failure.
    pub fn format(
        self: Const,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = options;
        comptime var base = 10;
        comptime var case: std.fmt.Case = .lower;

        if (fmt.len == 0 or comptime mem.eql(u8, fmt, "d")) {
            base = 10;
            case = .lower;
        } else if (comptime mem.eql(u8, fmt, "b")) {
            base = 2;
            case = .lower;
        } else if (comptime mem.eql(u8, fmt, "x")) {
            base = 16;
            case = .lower;
        } else if (comptime mem.eql(u8, fmt, "X")) {
            base = 16;
            case = .upper;
        } else {
            std.fmt.invalidFmtError(fmt, self);
        }

        const available_len = 64;
        if (self.limbs.len > available_len)
            return out_stream.writeAll("(BigInt)");

        var limbs: [calcToStringLimbsBufferLen(available_len, base)]Limb = undefined;

        const biggest: Const = .{
            .limbs = &([1]Limb{comptime math.maxInt(Limb)} ** available_len),
            .positive = false,
        };
        var buf: [biggest.sizeInBaseUpperBound(base)]u8 = undefined;
        const len = self.toString(&buf, base, case, &limbs);
        return out_stream.writeAll(buf[0..len]);
    }

    /// Converts self to a string in the requested base.
    /// Caller owns returned memory.
    /// Asserts that `base` is in the range [2, 36].
    /// See also `toString`, a lower level function than this.
    pub fn toStringAlloc(self: Const, allocator: Allocator, base: u8, case: std.fmt.Case) Allocator.Error![]u8 {
        assert(base >= 2);
        assert(base <= 36);

        if (self.eqlZero()) {
            return allocator.dupe(u8, "0");
        }
        const string = try allocator.alloc(u8, self.sizeInBaseUpperBound(base));
        errdefer allocator.free(string);

        const limbs = try allocator.alloc(Limb, calcToStringLimbsBufferLen(self.limbs.len, base));
        defer allocator.free(limbs);

        return allocator.realloc(string, self.toString(string, base, case, limbs));
    }

    /// Converts self to a string in the requested base.
    /// Asserts that `base` is in the range [2, 36].
    /// `string` is a caller-provided slice of at least `sizeInBaseUpperBound` bytes,
    /// where the result is written to.
    /// Returns the length of the string.
    /// `limbs_buffer` is caller-provided memory for `toString` to use as a working area. It must have
    /// length of at least `calcToStringLimbsBufferLen`.
    /// In the case of power-of-two base, `limbs_buffer` is ignored.
    /// See also `toStringAlloc`, a higher level function than this.
    pub fn toString(self: Const, string: []u8, base: u8, case: std.fmt.Case, limbs_buffer: []Limb) usize {
        assert(base >= 2);
        assert(base <= 36);

        if (self.eqlZero()) {
            string[0] = '0';
            return 1;
        }

        var digits_len: usize = 0;

        // Power of two: can do a single pass and use masks to extract digits.
        if (math.isPowerOfTwo(base)) {
            const base_shift = math.log2_int(Limb, base);

            outer: for (self.limbs[0..self.limbs.len]) |limb| {
                var shift: usize = 0;
                while (shift < limb_bits) : (shift += base_shift) {
                    const r = @as(u8, @intCast((limb >> @as(Log2Limb, @intCast(shift))) & @as(Limb, base - 1)));
                    const ch = std.fmt.digitToChar(r, case);
                    string[digits_len] = ch;
                    digits_len += 1;
                    // If we hit the end, it must be all zeroes from here.
                    if (digits_len == string.len) break :outer;
                }
            }

            // Always will have a non-zero digit somewhere.
            while (string[digits_len - 1] == '0') {
                digits_len -= 1;
            }
        } else {
            // Non power-of-two: batch divisions per word size.
            // We use a HalfLimb here so the division uses the faster lldiv0p5 over lldiv1 codepath.
            const digits_per_limb = math.log(HalfLimb, base, maxInt(HalfLimb));
            var limb_base: Limb = 1;
            var j: usize = 0;
            while (j < digits_per_limb) : (j += 1) {
                limb_base *= base;
            }
            const b: Const = .{ .limbs = &[_]Limb{limb_base}, .positive = true };

            var q: Mutable = .{
                .limbs = limbs_buffer[0 .. self.limbs.len + 2],
                .positive = true, // Make absolute by ignoring self.positive.
                .len = self.limbs.len,
            };
            @memcpy(q.limbs[0..self.limbs.len], self.limbs);

            var r: Mutable = .{
                .limbs = limbs_buffer[q.limbs.len..][0..self.limbs.len],
                .positive = true,
                .len = 1,
            };
            r.limbs[0] = 0;

            const rest_of_the_limbs_buf = limbs_buffer[q.limbs.len + r.limbs.len ..];

            while (q.len >= 2) {
                // Passing an allocator here would not be helpful since this division is destroying
                // information, not creating it. [TODO citation needed]
                q.divTrunc(&r, q.toConst(), b, rest_of_the_limbs_buf);

                var r_word = r.limbs[0];
                var i: usize = 0;
                while (i < digits_per_limb) : (i += 1) {
                    const ch = std.fmt.digitToChar(@as(u8, @intCast(r_word % base)), case);
                    r_word /= base;
                    string[digits_len] = ch;
                    digits_len += 1;
                }
            }

            {
                assert(q.len == 1);

                var r_word = q.limbs[0];
                while (r_word != 0) {
                    const ch = std.fmt.digitToChar(@as(u8, @intCast(r_word % base)), case);
                    r_word /= base;
                    string[digits_len] = ch;
                    digits_len += 1;
                }
            }
        }

        if (!self.positive) {
            string[digits_len] = '-';
            digits_len += 1;
        }

        const s = string[0..digits_len];
        mem.reverse(u8, s);
        return s.len;
    }

    /// Write the value of `x` into `buffer`
    /// Asserts that `buffer` is large enough to store the value.
    ///
    /// `buffer` is filled so that its contents match what would be observed via
    /// @ptrCast(*[buffer.len]const u8, &x). Byte ordering is determined by `endian`,
    /// and any required padding bits are added on the MSB end.
    pub fn writeTwosComplement(x: Const, buffer: []u8, endian: Endian) void {
        return writePackedTwosComplement(x, buffer, 0, 8 * buffer.len, endian);
    }

    /// Write the value of `x` to a packed memory `buffer`.
    /// Asserts that `buffer` is large enough to contain a value of bit-size `bit_count`
    /// at offset `bit_offset`.
    ///
    /// This is equivalent to storing the value of an integer with `bit_count` bits as
    /// if it were a field in packed memory at the provided bit offset.
    pub fn writePackedTwosComplement(x: Const, buffer: []u8, bit_offset: usize, bit_count: usize, endian: Endian) void {
        assert(x.fitsInTwosComp(if (x.positive) .unsigned else .signed, bit_count));

        // Copy all complete limbs
        var carry: u1 = 1;
        var limb_index: usize = 0;
        var bit_index: usize = 0;
        while (limb_index < bit_count / @bitSizeOf(Limb)) : (limb_index += 1) {
            var limb: Limb = if (limb_index < x.limbs.len) x.limbs[limb_index] else 0;

            // 2's complement (bitwise not, then add carry bit)
            if (!x.positive) {
                const ov = @addWithOverflow(~limb, carry);
                limb = ov[0];
                carry = ov[1];
            }

            // Write one Limb of bits
            mem.writePackedInt(Limb, buffer, bit_index + bit_offset, limb, endian);
            bit_index += @bitSizeOf(Limb);
        }

        // Copy the remaining bits
        if (bit_count != bit_index) {
            var limb: Limb = if (limb_index < x.limbs.len) x.limbs[limb_index] else 0;

            // 2's complement (bitwise not, then add carry bit)
            if (!x.positive) limb = ~limb +% carry;

            // Write all remaining bits
            mem.writeVarPackedInt(buffer, bit_index + bit_offset, bit_count - bit_index, limb, endian);
        }
    }

    /// Returns `math.Order.lt`, `math.Order.eq`, `math.Order.gt` if
    /// `|a| < |b|`, `|a| == |b|`, or `|a| > |b|` respectively.
    pub fn orderAbs(a: Const, b: Const) math.Order {
        if (a.limbs.len < b.limbs.len) {
            return .lt;
        }
        if (a.limbs.len > b.limbs.len) {
            return .gt;
        }

        var i: usize = a.limbs.len - 1;
        while (i != 0) : (i -= 1) {
            if (a.limbs[i] != b.limbs[i]) {
                break;
            }
        }

        if (a.limbs[i] < b.limbs[i]) {
            return .lt;
        } else if (a.limbs[i] > b.limbs[i]) {
            return .gt;
        } else {
            return .eq;
        }
    }

    /// Returns `math.Order.lt`, `math.Order.eq`, `math.Order.gt` if `a < b`, `a == b` or `a > b` respectively.
    pub fn order(a: Const, b: Const) math.Order {
        if (a.positive != b.positive) {
            if (eqlZero(a) and eqlZero(b)) {
                return .eq;
            } else {
                return if (a.positive) .gt else .lt;
            }
        } else {
            const r = orderAbs(a, b);
            return if (a.positive) r else switch (r) {
                .lt => math.Order.gt,
                .eq => math.Order.eq,
                .gt => math.Order.lt,
            };
        }
    }

    /// Same as `order` but the right-hand operand is a primitive integer.
    pub fn orderAgainstScalar(lhs: Const, scalar: anytype) math.Order {
        // Normally we could just determine the number of limbs needed with calcLimbLen,
        // but that is not comptime-known when scalar is not a comptime_int.  Instead, we
        // use calcTwosCompLimbCount for a non-comptime_int scalar, which can be pessimistic
        // in the case that scalar happens to be small in magnitude within its type, but it
        // is well worth being able to use the stack and not needing an allocator passed in.
        // Note that Mutable.init still sets len to calcLimbLen(scalar) in any case.
        const limb_len = comptime switch (@typeInfo(@TypeOf(scalar))) {
            .comptime_int => calcLimbLen(scalar),
            .int => |info| calcTwosCompLimbCount(info.bits),
            else => @compileError("expected scalar to be an int"),
        };
        var limbs: [limb_len]Limb = undefined;
        const rhs = Mutable.init(&limbs, scalar);
        return order(lhs, rhs.toConst());
    }

    /// Returns true if `a == 0`.
    pub fn eqlZero(a: Const) bool {
        var d: Limb = 0;
        for (a.limbs) |limb| d |= limb;
        return d == 0;
    }

    /// Returns true if `|a| == |b|`.
    pub fn eqlAbs(a: Const, b: Const) bool {
        return orderAbs(a, b) == .eq;
    }

    /// Returns true if `a == b`.
    pub fn eql(a: Const, b: Const) bool {
        return order(a, b) == .eq;
    }

    /// Returns the number of leading zeros in twos-complement form.
    pub fn clz(a: Const, bits: Limb) Limb {
        // Limbs are stored in little-endian order but we need to iterate big-endian.
        if (!a.positive and !a.eqlZero()) return 0;
        var total_limb_lz: Limb = 0;
        var i: usize = a.limbs.len;
        const bits_per_limb = @bitSizeOf(Limb);
        while (i != 0) {
            i -= 1;
            const this_limb_lz = @clz(a.limbs[i]);
            total_limb_lz += this_limb_lz;
            if (this_limb_lz != bits_per_limb) break;
        }
        const total_limb_bits = a.limbs.len * bits_per_limb;
        return total_limb_lz + bits - total_limb_bits;
    }

    /// Returns the number of trailing zeros in twos-complement form.
    pub fn ctz(a: Const, bits: Limb) Limb {
        // Limbs are stored in little-endian order. Converting a negative number to twos-complement
        // flips all bits above the lowest set bit, which does not affect the trailing zero count.
        if (a.eqlZero()) return bits;
        var result: Limb = 0;
        for (a.limbs) |limb| {
            const limb_tz = @ctz(limb);
            result += limb_tz;
            if (limb_tz != @bitSizeOf(Limb)) break;
        }
        return @min(result, bits);
    }
};

/// An arbitrary-precision big integer along with an allocator which manages the memory.
///
/// Memory is allocated as needed to ensure operations never overflow. The range
/// is bounded only by available memory.
pub const Managed = struct {
    pub const sign_bit: usize = 1 << (@typeInfo(usize).int.bits - 1);

    /// Default number of limbs to allocate on creation of a `Managed`.
    pub const default_capacity = 4;

    /// Allocator used by the Managed when requesting memory.
    allocator: Allocator,

    /// Raw digits. These are:
    ///
    /// * Little-endian ordered
    /// * limbs.len >= 1
    /// * Zero is represent as Managed.len() == 1 with limbs[0] == 0.
    ///
    /// Accessing limbs directly should be avoided.
    limbs: []Limb,

    /// High bit is the sign bit. If set, Managed is negative, else Managed is positive.
    /// The remaining bits represent the number of limbs used by Managed.
    metadata: usize,

    /// Creates a new `Managed`. `default_capacity` limbs will be allocated immediately.
    /// The integer value after initializing is `0`.
    pub fn init(allocator: Allocator) !Managed {
        return initCapacity(allocator, default_capacity);
    }

    pub fn toMutable(self: Managed) Mutable {
        return .{
            .limbs = self.limbs,
            .positive = self.isPositive(),
            .len = self.len(),
        };
    }

    pub fn toConst(self: Managed) Const {
        return .{
            .limbs = self.limbs[0..self.len()],
            .positive = self.isPositive(),
        };
    }

    /// Creates a new `Managed` with value `value`.
    ///
    /// This is identical to an `init`, followed by a `set`.
    pub fn initSet(allocator: Allocator, value: anytype) !Managed {
        var s = try Managed.init(allocator);
        errdefer s.deinit();
        try s.set(value);
        return s;
    }

    /// Creates a new Managed with a specific capacity. If capacity < default_capacity then the
    /// default capacity will be used instead.
    /// The integer value after initializing is `0`.
    pub fn initCapacity(allocator: Allocator, capacity: usize) !Managed {
        return Managed{
            .allocator = allocator,
            .metadata = 1,
            .limbs = block: {
                const limbs = try allocator.alloc(Limb, @max(default_capacity, capacity));
                limbs[0] = 0;
                break :block limbs;
            },
        };
    }

    /// Returns the number of limbs currently in use.
    pub fn len(self: Managed) usize {
        return self.metadata & ~sign_bit;
    }

    /// Returns whether an Managed is positive.
    pub fn isPositive(self: Managed) bool {
        return self.metadata & sign_bit == 0;
    }

    /// Sets the sign of an Managed.
    pub fn setSign(self: *Managed, positive: bool) void {
        if (positive) {
            self.metadata &= ~sign_bit;
        } else {
            self.metadata |= sign_bit;
        }
    }

    /// Sets the length of an Managed.
    ///
    /// If setLen is used, then the Managed must be normalized to suit.
    pub fn setLen(self: *Managed, new_len: usize) void {
        self.metadata &= sign_bit;
        self.metadata |= new_len;
    }

    pub fn setMetadata(self: *Managed, positive: bool, length: usize) void {
        self.metadata = if (positive) length & ~sign_bit else length | sign_bit;
    }

    /// Ensures an Managed has enough space allocated for capacity limbs. If the Managed does not have
    /// sufficient capacity, the exact amount will be allocated. This occurs even if the requested
    /// capacity is only greater than the current capacity by one limb.
    pub fn ensureCapacity(self: *Managed, capacity: usize) !void {
        if (capacity <= self.limbs.len) {
            return;
        }
        self.limbs = try self.allocator.realloc(self.limbs, capacity);
    }

    /// Frees all associated memory.
    pub fn deinit(self: *Managed) void {
        self.allocator.free(self.limbs);
        self.* = undefined;
    }

    /// Returns a `Managed` with the same value. The returned `Managed` is a deep copy and
    /// can be modified separately from the original, and its resources are managed
    /// separately from the original.
    pub fn clone(other: Managed) !Managed {
        return other.cloneWithDifferentAllocator(other.allocator);
    }

    pub fn cloneWithDifferentAllocator(other: Managed, allocator: Allocator) !Managed {
        return Managed{
            .allocator = allocator,
            .metadata = other.metadata,
            .limbs = block: {
                const limbs = try allocator.alloc(Limb, other.len());
                @memcpy(limbs, other.limbs[0..other.len()]);
                break :block limbs;
            },
        };
    }

    /// Copies the value of the integer to an existing `Managed` so that they both have the same value.
    /// Extra memory will be allocated if the receiver does not have enough capacity.
    pub fn copy(self: *Managed, other: Const) !void {
        if (self.limbs.ptr == other.limbs.ptr) return;

        try self.ensureCapacity(other.limbs.len);
        @memcpy(self.limbs[0..other.limbs.len], other.limbs[0..other.limbs.len]);
        self.setMetadata(other.positive, other.limbs.len);
    }

    /// Efficiently swap a `Managed` with another. This swaps the limb pointers and a full copy is not
    /// performed. The address of the limbs field will not be the same after this function.
    pub fn swap(self: *Managed, other: *Managed) void {
        mem.swap(Managed, self, other);
    }

    /// Debugging tool: prints the state to stderr.
    pub fn dump(self: Managed) void {
        for (self.limbs[0..self.len()]) |limb| {
            std.debug.print("{x} ", .{limb});
        }
        std.debug.print("len={} capacity={} positive={}\n", .{ self.len(), self.limbs.len, self.isPositive() });
    }

    /// Negate the sign.
    pub fn negate(self: *Managed) void {
        self.metadata ^= sign_bit;
    }

    /// Make positive.
    pub fn abs(self: *Managed) void {
        self.metadata &= ~sign_bit;
    }

    pub fn isOdd(self: Managed) bool {
        return self.limbs[0] & 1 != 0;
    }

    pub fn isEven(self: Managed) bool {
        return !self.isOdd();
    }

    /// Returns the number of bits required to represent the absolute value of an integer.
    pub fn bitCountAbs(self: Managed) usize {
        return self.toConst().bitCountAbs();
    }

    /// Returns the number of bits required to represent the integer in twos-complement form.
    ///
    /// If the integer is negative the value returned is the number of bits needed by a signed
    /// integer to represent the value. If positive the value is the number of bits for an
    /// unsigned integer. Any unsigned integer will fit in the signed integer with bitcount
    /// one greater than the returned value.
    ///
    /// e.g. -127 returns 8 as it will fit in an i8. 127 returns 7 since it fits in a u7.
    pub fn bitCountTwosComp(self: Managed) usize {
        return self.toConst().bitCountTwosComp();
    }

    pub fn fitsInTwosComp(self: Managed, signedness: Signedness, bit_count: usize) bool {
        return self.toConst().fitsInTwosComp(signedness, bit_count);
    }

    /// Returns whether self can fit into an integer of the requested type.
    pub fn fits(self: Managed, comptime T: type) bool {
        return self.toConst().fits(T);
    }

    /// Returns the approximate size of the integer in the given base. Negative values accommodate for
    /// the minus sign. This is used for determining the number of characters needed to print the
    /// value. It is inexact and may exceed the given value by ~1-2 bytes.
    pub fn sizeInBaseUpperBound(self: Managed, base: usize) usize {
        return self.toConst().sizeInBaseUpperBound(base);
    }

    /// Sets an Managed to value. Value must be an primitive integer type.
    pub fn set(self: *Managed, value: anytype) Allocator.Error!void {
        try self.ensureCapacity(calcLimbLen(value));
        var m = self.toMutable();
        m.set(value);
        self.setMetadata(m.positive, m.len);
    }

    pub const ConvertError = Const.ConvertError;

    /// Deprecated; use `toInt`.
    pub const to = toInt;

    /// Convert self to integer type T.
    ///
    /// Returns an error if self cannot be narrowed into the requested type without truncation.
    pub fn toInt(self: Managed, comptime T: type) ConvertError!T {
        return self.toConst().toInt(T);
    }

    /// Convert self to float type T.
    pub fn toFloat(self: Managed, comptime T: type) T {
        return self.toConst().toFloat(T);
    }

    /// Set self from the string representation `value`.
    ///
    /// `value` must contain only digits <= `base` and is case insensitive.  Base prefixes are
    /// not allowed (e.g. 0x43 should simply be 43).  Underscores in the input string are
    /// ignored and can be used as digit separators.
    ///
    /// Returns an error if memory could not be allocated or `value` has invalid digits for the
    /// requested base.
    ///
    /// self's allocator is used for temporary storage to boost multiplication performance.
    pub fn setString(self: *Managed, base: u8, value: []const u8) !void {
        if (base < 2 or base > 36) return error.InvalidBase;
        try self.ensureCapacity(calcSetStringLimbCount(base, value.len));
        const limbs_buffer = try self.allocator.alloc(Limb, calcSetStringLimbsBufferLen(base, value.len));
        defer self.allocator.free(limbs_buffer);
        var m = self.toMutable();
        try m.setString(base, value, limbs_buffer, self.allocator);
        self.setMetadata(m.positive, m.len);
    }

    /// Set self to either bound of a 2s-complement integer.
    /// Note: The result is still sign-magnitude, not twos complement! In order to convert the
    /// result to twos complement, it is sufficient to take the absolute value.
    pub fn setTwosCompIntLimit(
        r: *Managed,
        limit: TwosCompIntLimit,
        signedness: Signedness,
        bit_count: usize,
    ) !void {
        try r.ensureCapacity(calcTwosCompLimbCount(bit_count));
        var m = r.toMutable();
        m.setTwosCompIntLimit(limit, signedness, bit_count);
        r.setMetadata(m.positive, m.len);
    }

    /// Converts self to a string in the requested base. Memory is allocated from the provided
    /// allocator and not the one present in self.
    pub fn toString(self: Managed, allocator: Allocator, base: u8, case: std.fmt.Case) ![]u8 {
        if (base < 2 or base > 36) return error.InvalidBase;
        return self.toConst().toStringAlloc(allocator, base, case);
    }

    /// To allow `std.fmt.format` to work with `Managed`.
    /// If the absolute value of integer is greater than or equal to `pow(2, 64 * @sizeOf(usize) * 8)`,
    /// this function will fail to print the string, printing "(BigInt)" instead of a number.
    /// This is because the rendering algorithm requires reversing a string, which requires O(N) memory.
    /// See `toString` and `toStringAlloc` for a way to print big integers without failure.
    pub fn format(
        self: Managed,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        return self.toConst().format(fmt, options, out_stream);
    }

    /// Returns math.Order.lt, math.Order.eq, math.Order.gt if |a| < |b|, |a| ==
    /// |b| or |a| > |b| respectively.
    pub fn orderAbs(a: Managed, b: Managed) math.Order {
        return a.toConst().orderAbs(b.toConst());
    }

    /// Returns math.Order.lt, math.Order.eq, math.Order.gt if a < b, a == b or a > b
    /// respectively.
    pub fn order(a: Managed, b: Managed) math.Order {
        return a.toConst().order(b.toConst());
    }

    /// Returns true if a == 0.
    pub fn eqlZero(a: Managed) bool {
        return a.toConst().eqlZero();
    }

    /// Returns true if |a| == |b|.
    pub fn eqlAbs(a: Managed, b: Managed) bool {
        return a.toConst().eqlAbs(b.toConst());
    }

    /// Returns true if a == b.
    pub fn eql(a: Managed, b: Managed) bool {
        return a.toConst().eql(b.toConst());
    }

    /// Normalize a possible sequence of leading zeros.
    ///
    /// [1, 2, 3, 4, 0] -> [1, 2, 3, 4]
    /// [1, 2, 0, 0, 0] -> [1, 2]
    /// [0, 0, 0, 0, 0] -> [0]
    pub fn normalize(r: *Managed, length: usize) void {
        assert(length > 0);
        assert(length <= r.limbs.len);

        var j = length;
        while (j > 0) : (j -= 1) {
            if (r.limbs[j - 1] != 0) {
                break;
            }
        }

        // Handle zero
        r.setLen(if (j != 0) j else 1);
    }

    /// r = a + scalar
    ///
    /// r and a may be aliases.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn addScalar(r: *Managed, a: *const Managed, scalar: anytype) Allocator.Error!void {
        try r.ensureAddScalarCapacity(a.toConst(), scalar);
        var m = r.toMutable();
        m.addScalar(a.toConst(), scalar);
        r.setMetadata(m.positive, m.len);
    }

    /// r = a + b
    ///
    /// r, a and b may be aliases.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn add(r: *Managed, a: *const Managed, b: *const Managed) Allocator.Error!void {
        try r.ensureAddCapacity(a.toConst(), b.toConst());
        var m = r.toMutable();
        m.add(a.toConst(), b.toConst());
        r.setMetadata(m.positive, m.len);
    }

    /// r = a + b with 2s-complement wrapping semantics. Returns whether any overflow occurred.
    ///
    /// r, a and b may be aliases.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn addWrap(
        r: *Managed,
        a: *const Managed,
        b: *const Managed,
        signedness: Signedness,
        bit_count: usize,
    ) Allocator.Error!bool {
        try r.ensureTwosCompCapacity(bit_count);
        var m = r.toMutable();
        const wrapped = m.addWrap(a.toConst(), b.toConst(), signedness, bit_count);
        r.setMetadata(m.positive, m.len);
        return wrapped;
    }

    /// r = a + b with 2s-complement saturating semantics.
    ///
    /// r, a and b may be aliases.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn addSat(r: *Managed, a: *const Managed, b: *const Managed, signedness: Signedness, bit_count: usize) Allocator.Error!void {
        try r.ensureTwosCompCapacity(bit_count);
        var m = r.toMutable();
        m.addSat(a.toConst(), b.toConst(), signedness, bit_count);
        r.setMetadata(m.positive, m.len);
    }

    /// r = a - b
    ///
    /// r, a and b may be aliases.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn sub(r: *Managed, a: *const Managed, b: *const Managed) !void {
        try r.ensureCapacity(@max(a.len(), b.len()) + 1);
        var m = r.toMutable();
        m.sub(a.toConst(), b.toConst());
        r.setMetadata(m.positive, m.len);
    }

    /// r = a - b with 2s-complement wrapping semantics. Returns whether any overflow occurred.
    ///
    /// r, a and b may be aliases.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn subWrap(
        r: *Managed,
        a: *const Managed,
        b: *const Managed,
        signedness: Signedness,
        bit_count: usize,
    ) Allocator.Error!bool {
        try r.ensureTwosCompCapacity(bit_count);
        var m = r.toMutable();
        const wrapped = m.subWrap(a.toConst(), b.toConst(), signedness, bit_count);
        r.setMetadata(m.positive, m.len);
        return wrapped;
    }

    /// r = a - b with 2s-complement saturating semantics.
    ///
    /// r, a and b may be aliases.
    ///
    /// Returns an error if memory could not be allocated.
    pub fn subSat(
        r: *Managed,
        a: *const Managed,
        b: *const Managed,
        signedness: Signedness,
        bit_count: usize,
    ) Allocator.Error!void {
        try r.ensureTwosCompCapacity(bit_count);
        var m = r.toMutable();
        m.subSat(a.toConst(), b.toConst(), signedness, bit_count);
        r.setMetadata(m.positive, m.len);
    }

    /// rma = a * b
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    ///
    /// rma's allocator is used for temporary storage to speed up the multiplication.
    pub fn mul(rma: *Managed, a: *const Managed, b: *const Managed) !void {
        var alias_count: usize = 0;
        if (rma.limbs.ptr == a.limbs.ptr)
            alias_count += 1;
        if (rma.limbs.ptr == b.limbs.ptr)
            alias_count += 1;
        try rma.ensureMulCapacity(a.toConst(), b.toConst());
        var m = rma.toMutable();
        if (alias_count == 0) {
            m.mulNoAlias(a.toConst(), b.toConst(), rma.allocator);
        } else {
            const limb_count = calcMulLimbsBufferLen(a.len(), b.len(), alias_count);
            const limbs_buffer = try rma.allocator.alloc(Limb, limb_count);
            defer rma.allocator.free(limbs_buffer);
            m.mul(a.toConst(), b.toConst(), limbs_buffer, rma.allocator);
        }
        rma.setMetadata(m.positive, m.len);
    }

    /// rma = a * b with 2s-complement wrapping semantics.
    ///
    /// rma, a and b may be aliases. However, it is more efficient if rma does not alias a or b.
    ///
    /// Returns an error if memory could not be allocated.
    ///
    /// rma's allocator is used for temporary storage to speed up the multiplication.
    pub fn mulWrap(
        rma: *Managed,
        a: *const Managed,
        b: *const Managed,
        signedness: Signedness,
        bit_count: usize,
    ) !void {
        var alias_count: usize = 0;
        if (rma.limbs.ptr == a.limbs.ptr)
            alias_count += 1;
        if (rma.limbs.ptr == b.limbs.ptr)
            alias_count += 1;

        try rma.ensureTwosCompCapacity(bit_count);
        var m = rma.toMutable();
        if (alias_count == 0) {
            m.mulWrapNoAlias(a.toConst(), b.toConst(), signedness, bit_count, rma.allocator);
        } else {
            const limb_count = calcMulWrapLimbsBufferLen(bit_count, a.len(), b.len(), alias_count);
            const limbs_buffer = try rma.allocator.alloc(Limb, limb_count);
            defer rma.allocator.free(limbs_buffer);
            m.mulWrap(a.toConst(), b.toConst(), signedness, bit_count, limbs_buffer, rma.allocator);
        }
        rma.setMetadata(m.positive, m.len);
    }

    pub fn ensureTwosCompCapacity(r: *Managed, bit_count: usize) !void {
        try r.ensureCapacity(calcTwosCompLimbCount(bit_count));
    }

    pub fn ensureAddScalarCapacity(r: *Managed, a: Const, scalar: anytype) !void {
        try r.ensureCapacity(@max(a.limbs.len, calcLimbLen(scalar)) + 1);
    }

    pub fn ensureAddCapacity(r: *Managed, a: Const, b: Const) !void {
        try r.ensureCapacity(@max(a.limbs.len, b.limbs.len) + 1);
    }

    pub fn ensureMulCapacity(rma: *Managed, a: Const, b: Const) !void {
        try rma.ensureCapacity(a.limbs.len + b.limbs.len + 1);
    }

    /// q = a / b (rem r)
    ///
    /// a / b are floored (rounded towards 0).
    ///
    /// Returns an error if memory could not be allocated.
    pub fn divFloor(q: *Managed, r: *Managed, a: *const Managed, b: *const Managed) !void {
        try q.ensureCapacity(a.len());
        try r.ensureCapacity(b.len());
        var mq = q.toMutable();
        var mr = r.toMutable();
        const limbs_buffer = try q.allocator.alloc(Limb, calcDivLimbsBufferLen(a.len(), b.len()));
        defer q.allocator.free(limbs_buffer);
        mq.divFloor(&mr, a.toConst(), b.toConst(), limbs_buffer);
        q.setMetadata(mq.positive, mq.len);
        r.setMetadata(mr.positive, mr.len);
    }

    /// q = a / b (rem r)
    ///
    /// a / b are truncated (rounded towards -inf).
    ///
    /// Returns an error if memory could not be allocated.
    pub fn divTrunc(q: *Managed, r: *Managed, a: *const Managed, b: *const Managed) !void {
        try q.ensureCapacity(a.len());
        try r.ensureCapacity(b.len());
        var mq = q.toMutable();
        var mr = r.toMutable();
        const limbs_buffer = try q.allocator.alloc(Limb, calcDivLimbsBufferLen(a.len(), b.len()));
        defer q.allocator.free(limbs_buffer);
        mq.divTrunc(&mr, a.toConst(), b.toConst(), limbs_buffer);
        q.setMetadata(mq.positive, mq.len);
        r.setMetadata(mr.positive, mr.len);
    }

    /// r = a << shift, in other words, r = a * 2^shift
    /// r and a may alias.
    pub fn shiftLeft(r: *Managed, a: *const Managed, shift: usize) !void {
        try r.ensureCapacity(a.len() + (shift / limb_bits) + 1);
        var m = r.toMutable();
        m.shiftLeft(a.toConst(), shift);
        r.setMetadata(m.positive, m.len);
    }

    /// r = a <<| shift with 2s-complement saturating semantics.
    /// r and a may alias.
    pub fn shiftLeftSat(r: *Managed, a: *const Managed, shift: usize, signedness: Signedness, bit_count: usize) !void {
        try r.ensureTwosCompCapacity(bit_count);
        var m = r.toMutable();
        m.shiftLeftSat(a.toConst(), shift, signedness, bit_count);
        r.setMetadata(m.positive, m.len);
    }

    /// r = a >> shift
    /// r and a may alias.
    pub fn shiftRight(r: *Managed, a: *const Managed, shift: usize) !void {
        if (a.len() <= shift / limb_bits) {
            // Shifting negative numbers converges to -1 instead of 0
            if (a.isPositive()) {
                r.metadata = 1;
                r.limbs[0] = 0;
            } else {
                r.metadata = 1;
                r.setSign(false);
                r.limbs[0] = 1;
            }
            return;
        }

        try r.ensureCapacity(a.len() - (shift / limb_bits));
        var m = r.toMutable();
        m.shiftRight(a.toConst(), shift);
        r.setMetadata(m.positive, m.len);
    }

    /// r = ~a under 2s-complement wrapping semantics.
    /// r and a may alias.
    pub fn bitNotWrap(r: *Managed, a: *const Managed, signedness: Signedness, bit_count: usize) !void {
        try r.ensureTwosCompCapacity(bit_count);
        var m = r.toMutable();
        m.bitNotWrap(a.toConst(), signedness, bit_count);
        r.setMetadata(m.positive, m.len);
    }

    /// r = a | b
    ///
    /// a and b are zero-extended to the longer of a or b.
    pub fn bitOr(r: *Managed, a: *const Managed, b: *const Managed) !void {
        try r.ensureCapacity(@max(a.len(), b.len()));
        var m = r.toMutable();
        m.bitOr(a.toConst(), b.toConst());
        r.setMetadata(m.positive, m.len);
    }

    /// r = a & b
    pub fn bitAnd(r: *Managed, a: *const Managed, b: *const Managed) !void {
        const cap = if (a.len() >= b.len())
            if (b.isPositive()) b.len() else if (a.isPositive()) a.len() else a.len() + 1
        else if (a.isPositive()) a.len() else if (b.isPositive()) b.len() else b.len() + 1;

        try r.ensureCapacity(cap);
        var m = r.toMutable();
        m.bitAnd(a.toConst(), b.toConst());
        r.setMetadata(m.positive, m.len);
    }

    /// r = a ^ b
    pub fn bitXor(r: *Managed, a: *const Managed, b: *const Managed) !void {
        const cap = @max(a.len(), b.len()) + @intFromBool(a.isPositive() != b.isPositive());
        try r.ensureCapacity(cap);

        var m = r.toMutable();
        m.bitXor(a.toConst(), b.toConst());
        r.setMetadata(m.positive, m.len);
    }

    /// rma may alias x or y.
    /// x and y may alias each other.
    ///
    /// rma's allocator is used for temporary storage to boost multiplication performance.
    pub fn gcd(rma: *Managed, x: *const Managed, y: *const Managed) !void {
        try rma.ensureCapacity(@min(x.len(), y.len()));
        var m = rma.toMutable();
        var limbs_buffer = std.ArrayList(Limb).init(rma.allocator);
        defer limbs_buffer.deinit();
        try m.gcd(x.toConst(), y.toConst(), &limbs_buffer);
        rma.setMetadata(m.positive, m.len);
    }

    /// r = a * a
    pub fn sqr(rma: *Managed, a: *const Managed) !void {
        const needed_limbs = 2 * a.len() + 1;

        if (rma.limbs.ptr == a.limbs.ptr) {
            var m = try Managed.initCapacity(rma.allocator, needed_limbs);
            errdefer m.deinit();
            var m_mut = m.toMutable();
            m_mut.sqrNoAlias(a.toConst(), rma.allocator);
            m.setMetadata(m_mut.positive, m_mut.len);

            rma.deinit();
            rma.swap(&m);
        } else {
            try rma.ensureCapacity(needed_limbs);
            var rma_mut = rma.toMutable();
            rma_mut.sqrNoAlias(a.toConst(), rma.allocator);
            rma.setMetadata(rma_mut.positive, rma_mut.len);
        }
    }

    pub fn pow(rma: *Managed, a: *const Managed, b: u32) !void {
        const needed_limbs = calcPowLimbsBufferLen(a.bitCountAbs(), b);

        const limbs_buffer = try rma.allocator.alloc(Limb, needed_limbs);
        defer rma.allocator.free(limbs_buffer);

        if (rma.limbs.ptr == a.limbs.ptr) {
            var m = try Managed.initCapacity(rma.allocator, needed_limbs);
            errdefer m.deinit();
            var m_mut = m.toMutable();
            m_mut.pow(a.toConst(), b, limbs_buffer);
            m.setMetadata(m_mut.positive, m_mut.len);

            rma.deinit();
            rma.swap(&m);
        } else {
            try rma.ensureCapacity(needed_limbs);
            var rma_mut = rma.toMutable();
            rma_mut.pow(a.toConst(), b, limbs_buffer);
            rma.setMetadata(rma_mut.positive, rma_```
