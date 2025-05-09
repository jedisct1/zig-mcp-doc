```
ate(v)))),
        f128 => @as(f128, @bitCast(v)),
        else => unreachable,
    };
}

/// Represents a parsed floating point value as its components.
pub fn Number(comptime T: type) type {
    return struct {
        exponent: i64,
        mantissa: mantissaType(T),
        negative: bool,
        /// More than max_mantissa digits were found during parse
        many_digits: bool,
        /// The number was a hex-float (e.g. 0x1.234p567)
        hex: bool,
    };
}

/// Determine if 8 bytes are all decimal digits.
/// This does not care about the order in which the bytes were loaded.
pub fn isEightDigits(v: u64) bool {
    const a = v +% 0x4646_4646_4646_4646;
    const b = v -% 0x3030_3030_3030_3030;
    return ((a | b) & 0x8080_8080_8080_8080) == 0;
}

pub fn isDigit(c: u8, comptime base: u8) bool {
    std.debug.assert(base == 10 or base == 16);

    return if (base == 10)
        '0' <= c and c <= '9'
    else
        '0' <= c and c <= '9' or 'a' <= c and c <= 'f' or 'A' <= c and c <= 'F';
}

/// Returns the underlying storage type used for the mantissa of floating-point type.
/// The output unsigned type must have at least as many bits as the input floating-point type.
pub fn mantissaType(comptime T: type) type {
    return switch (T) {
        f16, f32, f64 => u64,
        f80, f128 => u128,
        else => unreachable,
    };
}
const std = @import("std");
const math = std.math;
const common = @import("common.zig");
const FloatInfo = @import("FloatInfo.zig");
const BiasedFp = common.BiasedFp;
const Number = common.Number;

/// Compute a float using an extended-precision representation.
///
/// Fast conversion of a the significant digits and decimal exponent
/// a float to an extended representation with a binary float. This
/// algorithm will accurately parse the vast majority of cases,
/// and uses a 128-bit representation (with a fallback 192-bit
/// representation).
///
/// This algorithm scales the exponent by the decimal exponent
/// using pre-computed powers-of-5, and calculates if the
/// representation can be unambiguously rounded to the nearest
/// machine float. Near-halfway cases are not handled here,
/// and are represented by a negative, biased binary exponent.
///
/// The algorithm is described in detail in "Daniel Lemire, Number Parsing
/// at a Gigabyte per Second" in section 5, "Fast Algorithm", and
/// section 6, "Exact Numbers And Ties", available online:
/// <https://arxiv.org/abs/2101.11408.pdf>.
pub fn convertEiselLemire(comptime T: type, q: i64, w_: u64) ?BiasedFp(f64) {
    std.debug.assert(T == f16 or T == f32 or T == f64);
    var w = w_;
    const float_info = FloatInfo.from(T);

    // Short-circuit if the value can only be a literal 0 or infinity.
    if (w == 0 or q < float_info.smallest_power_of_ten) {
        return BiasedFp(f64).zero();
    } else if (q > float_info.largest_power_of_ten) {
        return BiasedFp(f64).inf(T);
    }

    // Normalize our significant digits, so the most-significant bit is set.
    const lz = @clz(@as(u64, @bitCast(w)));
    w = math.shl(u64, w, lz);

    const r = computeProductApprox(q, w, float_info.mantissa_explicit_bits + 3);
    if (r.lo == 0xffff_ffff_ffff_ffff) {
        // If we have failed to approximate w x 5^-q with our 128-bit value.
        // Since the addition of 1 could lead to an overflow which could then
        // round up over the half-way point, this can lead to improper rounding
        // of a float.
        //
        // However, this can only occur if q ∈ [-27, 55]. The upper bound of q
        // is 55 because 5^55 < 2^128, however, this can only happen if 5^q > 2^64,
        // since otherwise the product can be represented in 64-bits, producing
        // an exact result. For negative exponents, rounding-to-even can
        // only occur if 5^-q < 2^64.
        //
        // For detailed explanations of rounding for negative exponents, see
        // <https://arxiv.org/pdf/2101.11408.pdf#section.9.1>. For detailed
        // explanations of rounding for positive exponents, see
        // <https://arxiv.org/pdf/2101.11408.pdf#section.8>.
        const inside_safe_exponent = q >= -27 and q <= 55;
        if (!inside_safe_exponent) {
            return null;
        }
    }

    const upper_bit = @as(i32, @intCast(r.hi >> 63));
    var mantissa = math.shr(u64, r.hi, upper_bit + 64 - @as(i32, @intCast(float_info.mantissa_explicit_bits)) - 3);
    var power2 = power(@as(i32, @intCast(q))) + upper_bit - @as(i32, @intCast(lz)) - float_info.minimum_exponent;
    if (power2 <= 0) {
        if (-power2 + 1 >= 64) {
            // Have more than 64 bits below the minimum exponent, must be 0.
            return BiasedFp(f64).zero();
        }
        // Have a subnormal value.
        mantissa = math.shr(u64, mantissa, -power2 + 1);
        mantissa += mantissa & 1;
        mantissa >>= 1;
        power2 = @intFromBool(mantissa >= (1 << float_info.mantissa_explicit_bits));
        return BiasedFp(f64){ .f = mantissa, .e = power2 };
    }

    // Need to handle rounding ties. Normally, we need to round up,
    // but if we fall right in between and and we have an even basis, we
    // need to round down.
    //
    // This will only occur if:
    //  1. The lower 64 bits of the 128-bit representation is 0.
    //      IE, 5^q fits in single 64-bit word.
    //  2. The least-significant bit prior to truncated mantissa is odd.
    //  3. All the bits truncated when shifting to mantissa bits + 1 are 0.
    //
    // Or, we may fall between two floats: we are exactly halfway.
    if (r.lo <= 1 and
        q >= float_info.min_exponent_round_to_even and
        q <= float_info.max_exponent_round_to_even and
        mantissa & 3 == 1 and
        math.shl(u64, mantissa, (upper_bit + 64 - @as(i32, @intCast(float_info.mantissa_explicit_bits)) - 3)) == r.hi)
    {
        // Zero the lowest bit, so we don't round up.
        mantissa &= ~@as(u64, 1);
    }

    // Round-to-even, then shift the significant digits into place.
    mantissa += mantissa & 1;
    mantissa >>= 1;
    if (mantissa >= 2 << float_info.mantissa_explicit_bits) {
        // Rounding up overflowed, so the carry bit is set. Set the
        // mantissa to 1 (only the implicit, hidden bit is set) and
        // increase the exponent.
        mantissa = 1 << float_info.mantissa_explicit_bits;
        power2 += 1;
    }

    // Zero out the hidden bit
    mantissa &= ~(@as(u64, 1) << float_info.mantissa_explicit_bits);
    if (power2 >= float_info.infinite_power) {
        // Exponent is above largest normal value, must be infinite
        return BiasedFp(f64).inf(T);
    }

    return BiasedFp(f64){ .f = mantissa, .e = power2 };
}

/// Calculate a base 2 exponent from a decimal exponent.
/// This uses a pre-computed integer approximation for
/// log2(10), where 217706 / 2^16 is accurate for the
/// entire range of non-finite decimal exponents.
fn power(q: i32) i32 {
    return ((q *% (152170 + 65536)) >> 16) + 63;
}

const U128 = struct {
    lo: u64,
    hi: u64,

    pub fn new(lo: u64, hi: u64) U128 {
        return .{ .lo = lo, .hi = hi };
    }

    pub fn mul(a: u64, b: u64) U128 {
        const x = @as(u128, a) * b;
        return .{
            .hi = @as(u64, @truncate(x >> 64)),
            .lo = @as(u64, @truncate(x)),
        };
    }
};

// This will compute or rather approximate w * 5**q and return a pair of 64-bit words
// approximating the result, with the "high" part corresponding to the most significant
// bits and the low part corresponding to the least significant bits.
fn computeProductApprox(q: i64, w: u64, comptime precision: usize) U128 {
    std.debug.assert(q >= eisel_lemire_smallest_power_of_five);
    std.debug.assert(q <= eisel_lemire_largest_power_of_five);
    std.debug.assert(precision <= 64);

    const mask = if (precision < 64)
        0xffff_ffff_ffff_ffff >> precision
    else
        0xffff_ffff_ffff_ffff;

    // 5^q < 2^64, then the multiplication always provides an exact value.
    // That means whenever we need to round ties to even, we always have
    // an exact value.
    const index = @as(usize, @intCast(q - @as(i64, @intCast(eisel_lemire_smallest_power_of_five))));
    const pow5 = eisel_lemire_table_powers_of_five_128[index];

    // Only need one multiplication as long as there is 1 zero but
    // in the explicit mantissa bits, +1 for the hidden bit, +1 to
    // determine the rounding direction, +1 for if the computed
    // product has a leading zero.
    var first = U128.mul(w, pow5.lo);
    if (first.hi & mask == mask) {
        // Need to do a second multiplication to get better precision
        // for the lower product. This will always be exact
        // where q is < 55, since 5^55 < 2^128. If this wraps,
        // then we need to need to round up the hi product.
        const second = U128.mul(w, pow5.hi);

        first.lo +%= second.hi;
        if (second.hi > first.lo) {
            first.hi += 1;
        }
    }

    return .{ .lo = first.lo, .hi = first.hi };
}

// Eisel-Lemire tables ~10Kb
const eisel_lemire_smallest_power_of_five = -342;
const eisel_lemire_largest_power_of_five = 308;
const eisel_lemire_table_powers_of_five_128 = [_]U128{
    U128.new(0xeef453d6923bd65a, 0x113faa2906a13b3f), // 5^-342
    U128.new(0x9558b4661b6565f8, 0x4ac7ca59a424c507), // 5^-341
    U128.new(0xbaaee17fa23ebf76, 0x5d79bcf00d2df649), // 5^-340
    U128.new(0xe95a99df8ace6f53, 0xf4d82c2c107973dc), // 5^-339
    U128.new(0x91d8a02bb6c10594, 0x79071b9b8a4be869), // 5^-338
    U128.new(0xb64ec836a47146f9, 0x9748e2826cdee284), // 5^-337
    U128.new(0xe3e27a444d8d98b7, 0xfd1b1b2308169b25), // 5^-336
    U128.new(0x8e6d8c6ab0787f72, 0xfe30f0f5e50e20f7), // 5^-335
    U128.new(0xb208ef855c969f4f, 0xbdbd2d335e51a935), // 5^-334
    U128.new(0xde8b2b66b3bc4723, 0xad2c788035e61382), // 5^-333
    U128.new(0x8b16fb203055ac76, 0x4c3bcb5021afcc31), // 5^-332
    U128.new(0xaddcb9e83c6b1793, 0xdf4abe242a1bbf3d), // 5^-331
    U128.new(0xd953e8624b85dd78, 0xd71d6dad34a2af0d), // 5^-330
    U128.new(0x87d4713d6f33aa6b, 0x8672648c40e5ad68), // 5^-329
    U128.new(0xa9c98d8ccb009506, 0x680efdaf511f18c2), // 5^-328
    U128.new(0xd43bf0effdc0ba48, 0x212bd1b2566def2), // 5^-327
    U128.new(0x84a57695fe98746d, 0x14bb630f7604b57), // 5^-326
    U128.new(0xa5ced43b7e3e9188, 0x419ea3bd35385e2d), // 5^-325
    U128.new(0xcf42894a5dce35ea, 0x52064cac828675b9), // 5^-324
    U128.new(0x818995ce7aa0e1b2, 0x7343efebd1940993), // 5^-323
    U128.new(0xa1ebfb4219491a1f, 0x1014ebe6c5f90bf8), // 5^-322
    U128.new(0xca66fa129f9b60a6, 0xd41a26e077774ef6), // 5^-321
    U128.new(0xfd00b897478238d0, 0x8920b098955522b4), // 5^-320
    U128.new(0x9e20735e8cb16382, 0x55b46e5f5d5535b0), // 5^-319
    U128.new(0xc5a890362fddbc62, 0xeb2189f734aa831d), // 5^-318
    U128.new(0xf712b443bbd52b7b, 0xa5e9ec7501d523e4), // 5^-317
    U128.new(0x9a6bb0aa55653b2d, 0x47b233c92125366e), // 5^-316
    U128.new(0xc1069cd4eabe89f8, 0x999ec0bb696e840a), // 5^-315
    U128.new(0xf148440a256e2c76, 0xc00670ea43ca250d), // 5^-314
    U128.new(0x96cd2a865764dbca, 0x380406926a5e5728), // 5^-313
    U128.new(0xbc807527ed3e12bc, 0xc605083704f5ecf2), // 5^-312
    U128.new(0xeba09271e88d976b, 0xf7864a44c633682e), // 5^-311
    U128.new(0x93445b8731587ea3, 0x7ab3ee6afbe0211d), // 5^-310
    U128.new(0xb8157268fdae9e4c, 0x5960ea05bad82964), // 5^-309
    U128.new(0xe61acf033d1a45df, 0x6fb92487298e33bd), // 5^-308
    U128.new(0x8fd0c16206306bab, 0xa5d3b6d479f8e056), // 5^-307
    U128.new(0xb3c4f1ba87bc8696, 0x8f48a4899877186c), // 5^-306
    U128.new(0xe0b62e2929aba83c, 0x331acdabfe94de87), // 5^-305
    U128.new(0x8c71dcd9ba0b4925, 0x9ff0c08b7f1d0b14), // 5^-304
    U128.new(0xaf8e5410288e1b6f, 0x7ecf0ae5ee44dd9), // 5^-303
    U128.new(0xdb71e91432b1a24a, 0xc9e82cd9f69d6150), // 5^-302
    U128.new(0x892731ac9faf056e, 0xbe311c083a225cd2), // 5^-301
    U128.new(0xab70fe17c79ac6ca, 0x6dbd630a48aaf406), // 5^-300
    U128.new(0xd64d3d9db981787d, 0x92cbbccdad5b108), // 5^-299
    U128.new(0x85f0468293f0eb4e, 0x25bbf56008c58ea5), // 5^-298
    U128.new(0xa76c582338ed2621, 0xaf2af2b80af6f24e), // 5^-297
    U128.new(0xd1476e2c07286faa, 0x1af5af660db4aee1), // 5^-296
    U128.new(0x82cca4db847945ca, 0x50d98d9fc890ed4d), // 5^-295
    U128.new(0xa37fce126597973c, 0xe50ff107bab528a0), // 5^-294
    U128.new(0xcc5fc196fefd7d0c, 0x1e53ed49a96272c8), // 5^-293
    U128.new(0xff77b1fcbebcdc4f, 0x25e8e89c13bb0f7a), // 5^-292
    U128.new(0x9faacf3df73609b1, 0x77b191618c54e9ac), // 5^-291
    U128.new(0xc795830d75038c1d, 0xd59df5b9ef6a2417), // 5^-290
    U128.new(0xf97ae3d0d2446f25, 0x4b0573286b44ad1d), // 5^-289
    U128.new(0x9becce62836ac577, 0x4ee367f9430aec32), // 5^-288
    U128.new(0xc2e801fb244576d5, 0x229c41f793cda73f), // 5^-287
    U128.new(0xf3a20279ed56d48a, 0x6b43527578c1110f), // 5^-286
    U128.new(0x9845418c345644d6, 0x830a13896b78aaa9), // 5^-285
    U128.new(0xbe5691ef416bd60c, 0x23cc986bc656d553), // 5^-284
    U128.new(0xedec366b11c6cb8f, 0x2cbfbe86b7ec8aa8), // 5^-283
    U128.new(0x94b3a202eb1c3f39, 0x7bf7d71432f3d6a9), // 5^-282
    U128.new(0xb9e08a83a5e34f07, 0xdaf5ccd93fb0cc53), // 5^-281
    U128.new(0xe858ad248f5c22c9, 0xd1b3400f8f9cff68), // 5^-280
    U128.new(0x91376c36d99995be, 0x23100809b9c21fa1), // 5^-279
    U128.new(0xb58547448ffffb2d, 0xabd40a0c2832a78a), // 5^-278
    U128.new(0xe2e69915b3fff9f9, 0x16c90c8f323f516c), // 5^-277
    U128.new(0x8dd01fad907ffc3b, 0xae3da7d97f6792e3), // 5^-276
    U128.new(0xb1442798f49ffb4a, 0x99cd11cfdf41779c), // 5^-275
    U128.new(0xdd95317f31c7fa1d, 0x40405643d711d583), // 5^-274
    U128.new(0x8a7d3eef7f1cfc52, 0x482835ea666b2572), // 5^-273
    U128.new(0xad1c8eab5ee43b66, 0xda3243650005eecf), // 5^-272
    U128.new(0xd863b256369d4a40, 0x90bed43e40076a82), // 5^-271
    U128.new(0x873e4f75e2224e68, 0x5a7744a6e804a291), // 5^-270
    U128.new(0xa90de3535aaae202, 0x711515d0a205cb36), // 5^-269
    U128.new(0xd3515c2831559a83, 0xd5a5b44ca873e03), // 5^-268
    U128.new(0x8412d9991ed58091, 0xe858790afe9486c2), // 5^-267
    U128.new(0xa5178fff668ae0b6, 0x626e974dbe39a872), // 5^-266
    U128.new(0xce5d73ff402d98e3, 0xfb0a3d212dc8128f), // 5^-265
    U128.new(0x80fa687f881c7f8e, 0x7ce66634bc9d0b99), // 5^-264
    U128.new(0xa139029f6a239f72, 0x1c1fffc1ebc44e80), // 5^-263
    U128.new(0xc987434744ac874e, 0xa327ffb266b56220), // 5^-262
    U128.new(0xfbe9141915d7a922, 0x4bf1ff9f0062baa8), // 5^-261
    U128.new(0x9d71ac8fada6c9b5, 0x6f773fc3603db4a9), // 5^-260
    U128.new(0xc4ce17b399107c22, 0xcb550fb4384d21d3), // 5^-259
    U128.new(0xf6019da07f549b2b, 0x7e2a53a146606a48), // 5^-258
    U128.new(0x99c102844f94e0fb, 0x2eda7444cbfc426d), // 5^-257
    U128.new(0xc0314325637a1939, 0xfa911155fefb5308), // 5^-256
    U128.new(0xf03d93eebc589f88, 0x793555ab7eba27ca), // 5^-255
    U128.new(0x96267c7535b763b5, 0x4bc1558b2f3458de), // 5^-254
    U128.new(0xbbb01b9283253ca2, 0x9eb1aaedfb016f16), // 5^-253
    U128.new(0xea9c227723ee8bcb, 0x465e15a979c1cadc), // 5^-252
    U128.new(0x92a1958a7675175f, 0xbfacd89ec191ec9), // 5^-251
    U128.new(0xb749faed14125d36, 0xcef980ec671f667b), // 5^-250
    U128.new(0xe51c79a85916f484, 0x82b7e12780e7401a), // 5^-249
    U128.new(0x8f31cc0937ae58d2, 0xd1b2ecb8b0908810), // 5^-248
    U128.new(0xb2fe3f0b8599ef07, 0x861fa7e6dcb4aa15), // 5^-247
    U128.new(0xdfbdcece67006ac9, 0x67a791e093e1d49a), // 5^-246
    U128.new(0x8bd6a141006042bd, 0xe0c8bb2c5c6d24e0), // 5^-245
    U128.new(0xaecc49914078536d, 0x58fae9f773886e18), // 5^-244
    U128.new(0xda7f5bf590966848, 0xaf39a475506a899e), // 5^-243
    U128.new(0x888f99797a5e012d, 0x6d8406c952429603), // 5^-242
    U128.new(0xaab37fd7d8f58178, 0xc8e5087ba6d33b83), // 5^-241
    U128.new(0xd5605fcdcf32e1d6, 0xfb1e4a9a90880a64), // 5^-240
    U128.new(0x855c3be0a17fcd26, 0x5cf2eea09a55067f), // 5^-239
    U128.new(0xa6b34ad8c9dfc06f, 0xf42faa48c0ea481e), // 5^-238
    U128.new(0xd0601d8efc57b08b, 0xf13b94daf124da26), // 5^-237
    U128.new(0x823c12795db6ce57, 0x76c53d08d6b70858), // 5^-236
    U128.new(0xa2cb1717b52481ed, 0x54768c4b0c64ca6e), // 5^-235
    U128.new(0xcb7ddcdda26da268, 0xa9942f5dcf7dfd09), // 5^-234
    U128.new(0xfe5d54150b090b02, 0xd3f93b35435d7c4c), // 5^-233
    U128.new(0x9efa548d26e5a6e1, 0xc47bc5014a1a6daf), // 5^-232
    U128.new(0xc6b8e9b0709f109a, 0x359ab6419ca1091b), // 5^-231
    U128.new(0xf867241c8cc6d4c0, 0xc30163d203c94b62), // 5^-230
    U128.new(0x9b407691d7fc44f8, 0x79e0de63425dcf1d), // 5^-229
    U128.new(0xc21094364dfb5636, 0x985915fc12f542e4), // 5^-228
    U128.new(0xf294b943e17a2bc4, 0x3e6f5b7b17b2939d), // 5^-227
    U128.new(0x979cf3ca6cec5b5a, 0xa705992ceecf9c42), // 5^-226
    U128.new(0xbd8430bd08277231, 0x50c6ff782a838353), // 5^-225
    U128.new(0xece53cec4a314ebd, 0xa4f8bf5635246428), // 5^-224
    U128.new(0x940f4613ae5ed136, 0x871b7795e136be99), // 5^-223
    U128.new(0xb913179899f68584, 0x28e2557b59846e3f), // 5^-222
    U128.new(0xe757dd7ec07426e5, 0x331aeada2fe589cf), // 5^-221
    U128.new(0x9096ea6f3848984f, 0x3ff0d2c85def7621), // 5^-220
    U128.new(0xb4bca50b065abe63, 0xfed077a756b53a9), // 5^-219
    U128.new(0xe1ebce4dc7f16dfb, 0xd3e8495912c62894), // 5^-218
    U128.new(0x8d3360f09cf6e4bd, 0x64712dd7abbbd95c), // 5^-217
    U128.new(0xb080392cc4349dec, 0xbd8d794d96aacfb3), // 5^-216
    U128.new(0xdca04777f541c567, 0xecf0d7a0fc5583a0), // 5^-215
    U128.new(0x89e42caaf9491b60, 0xf41686c49db57244), // 5^-214
    U128.new(0xac5d37d5b79b6239, 0x311c2875c522ced5), // 5^-213
    U128.new(0xd77485cb25823ac7, 0x7d633293366b828b), // 5^-212
    U128.new(0x86a8d39ef77164bc, 0xae5dff9c02033197), // 5^-211
    U128.new(0xa8530886b54dbdeb, 0xd9f57f830283fdfc), // 5^-210
    U128.new(0xd267caa862a12d66, 0xd072df63c324fd7b), // 5^-209
    U128.new(0x8380dea93da4bc60, 0x4247cb9e59f71e6d), // 5^-208
    U128.new(0xa46116538d0deb78, 0x52d9be85f074e608), // 5^-207
    U128.new(0xcd795be870516656, 0x67902e276c921f8b), // 5^-206
    U128.new(0x806bd9714632dff6, 0xba1cd8a3db53b6), // 5^-205
    U128.new(0xa086cfcd97bf97f3, 0x80e8a40eccd228a4), // 5^-204
    U128.new(0xc8a883c0fdaf7df0, 0x6122cd128006b2cd), // 5^-203
    U128.new(0xfad2a4b13d1b5d6c, 0x796b805720085f81), // 5^-202
    U128.new(0x9cc3a6eec6311a63, 0xcbe3303674053bb0), // 5^-201
    U128.new(0xc3f490aa77bd60fc, 0xbedbfc4411068a9c), // 5^-200
    U128.new(0xf4f1b4d515acb93b, 0xee92fb5515482d44), // 5^-199
    U128.new(0x991711052d8bf3c5, 0x751bdd152d4d1c4a), // 5^-198
    U128.new(0xbf5cd54678eef0b6, 0xd262d45a78a0635d), // 5^-197
    U128.new(0xef340a98172aace4, 0x86fb897116c87c34), // 5^-196
    U128.new(0x9580869f0e7aac0e, 0xd45d35e6ae3d4da0), // 5^-195
    U128.new(0xbae0a846d2195712, 0x8974836059cca109), // 5^-194
    U128.new(0xe998d258869facd7, 0x2bd1a438703fc94b), // 5^-193
    U128.new(0x91ff83775423cc06, 0x7b6306a34627ddcf), // 5^-192
    U128.new(0xb67f6455292cbf08, 0x1a3bc84c17b1d542), // 5^-191
    U128.new(0xe41f3d6a7377eeca, 0x20caba5f1d9e4a93), // 5^-190
    U128.new(0x8e938662882af53e, 0x547eb47b7282ee9c), // 5^-189
    U128.new(0xb23867fb2a35b28d, 0xe99e619a4f23aa43), // 5^-188
    U128.new(0xdec681f9f4c31f31, 0x6405fa00e2ec94d4), // 5^-187
    U128.new(0x8b3c113c38f9f37e, 0xde83bc408dd3dd04), // 5^-186
    U128.new(0xae0b158b4738705e, 0x9624ab50b148d445), // 5^-185
    U128.new(0xd98ddaee19068c76, 0x3badd624dd9b0957), // 5^-184
    U128.new(0x87f8a8d4cfa417c9, 0xe54ca5d70a80e5d6), // 5^-183
    U128.new(0xa9f6d30a038d1dbc, 0x5e9fcf4ccd211f4c), // 5^-182
    U128.new(0xd47487cc8470652b, 0x7647c3200069671f), // 5^-181
    U128.new(0x84c8d4dfd2c63f3b, 0x29ecd9f40041e073), // 5^-180
    U128.new(0xa5fb0a17c777cf09, 0xf468107100525890), // 5^-179
    U128.new(0xcf79cc9db955c2cc, 0x7182148d4066eeb4), // 5^-178
    U128.new(0x81ac1fe293d599bf, 0xc6f14cd848405530), // 5^-177
    U128.new(0xa21727db38cb002f, 0xb8ada00e5a506a7c), // 5^-176
    U128.new(0xca9cf1d206fdc03b, 0xa6d90811f0e4851c), // 5^-175
    U128.new(0xfd442e4688bd304a, 0x908f4a166d1da663), // 5^-174
    U128.new(0x9e4a9cec15763e2e, 0x9a598e4e043287fe), // 5^-173
    U128.new(0xc5dd44271ad3cdba, 0x40eff1e1853f29fd), // 5^-172
    U128.new(0xf7549530e188c128, 0xd12bee59e68ef47c), // 5^-171
    U128.new(0x9a94dd3e8cf578b9, 0x82bb74f8301958ce), // 5^-170
    U128.new(0xc13a148e3032d6e7, 0xe36a52363c1faf01), // 5^-169
    U128.new(0xf18899b1bc3f8ca1, 0xdc44e6c3cb279ac1), // 5^-168
    U128.new(0x96f5600f15a7b7e5, 0x29ab103a5ef8c0b9), // 5^-167
    U128.new(0xbcb2b812db11a5de, 0x7415d448f6b6f0e7), // 5^-166
    U128.new(0xebdf661791d60f56, 0x111b495b3464ad21), // 5^-165
    U128.new(0x936b9fcebb25c995, 0xcab10dd900beec34), // 5^-164
    U128.new(0xb84687c269ef3bfb, 0x3d5d514f40eea742), // 5^-163
    U128.new(0xe65829b3046b0afa, 0xcb4a5a3112a5112), // 5^-162
    U128.new(0x8ff71a0fe2c2e6dc, 0x47f0e785eaba72ab), // 5^-161
    U128.new(0xb3f4e093db73a093, 0x59ed216765690f56), // 5^-160
    U128.new(0xe0f218b8d25088b8, 0x306869c13ec3532c), // 5^-159
    U128.new(0x8c974f7383725573, 0x1e414218c73a13fb), // 5^-158
    U128.new(0xafbd2350644eeacf, 0xe5d1929ef90898fa), // 5^-157
    U128.new(0xdbac6c247d62a583, 0xdf45f746b74abf39), // 5^-156
    U128.new(0x894bc396ce5da772, 0x6b8bba8c328eb783), // 5^-155
    U128.new(0xab9eb47c81f5114f, 0x66ea92f3f326564), // 5^-154
    U128.new(0xd686619ba27255a2, 0xc80a537b0efefebd), // 5^-153
    U128.new(0x8613fd0145877585, 0xbd06742ce95f5f36), // 5^-152
    U128.new(0xa798fc4196e952e7, 0x2c48113823b73704), // 5^-151
    U128.new(0xd17f3b51fca3a7a0, 0xf75a15862ca504c5), // 5^-150
    U128.new(0x82ef85133de648c4, 0x9a984d73dbe722fb), // 5^-149
    U128.new(0xa3ab66580d5fdaf5, 0xc13e60d0d2e0ebba), // 5^-148
    U128.new(0xcc963fee10b7d1b3, 0x318df905079926a8), // 5^-147
    U128.new(0xffbbcfe994e5c61f, 0xfdf17746497f7052), // 5^-146
    U128.new(0x9fd561f1fd0f9bd3, 0xfeb6ea8bedefa633), // 5^-145
    U128.new(0xc7caba6e7c5382c8, 0xfe64a52ee96b8fc0), // 5^-144
    U128.new(0xf9bd690a1b68637b, 0x3dfdce7aa3c673b0), // 5^-143
    U128.new(0x9c1661a651213e2d, 0x6bea10ca65c084e), // 5^-142
    U128.new(0xc31bfa0fe5698db8, 0x486e494fcff30a62), // 5^-141
    U128.new(0xf3e2f893dec3f126, 0x5a89dba3c3efccfa), // 5^-140
    U128.new(0x986ddb5c6b3a76b7, 0xf89629465a75e01c), // 5^-139
    U128.new(0xbe89523386091465, 0xf6bbb397f1135823), // 5^-138
    U128.new(0xee2ba6c0678b597f, 0x746aa07ded582e2c), // 5^-137
    U128.new(0x94db483840b717ef, 0xa8c2a44eb4571cdc), // 5^-136
    U128.new(0xba121a4650e4ddeb, 0x92f34d62616ce413), // 5^-135
    U128.new(0xe896a0d7e51e1566, 0x77b020baf9c81d17), // 5^-134
    U128.new(0x915e2486ef32cd60, 0xace1474dc1d122e), // 5^-133
    U128.new(0xb5b5ada8aaff80b8, 0xd819992132456ba), // 5^-132
    U128.new(0xe3231912d5bf60e6, 0x10e1fff697ed6c69), // 5^-131
    U128.new(0x8df5efabc5979c8f, 0xca8d3ffa1ef463c1), // 5^-130
    U128.new(0xb1736b96b6fd83b3, 0xbd308ff8a6b17cb2), // 5^-129
    U128.new(0xddd0467c64bce4a0, 0xac7cb3f6d05ddbde), // 5^-128
    U128.new(0x8aa22c0dbef60ee4, 0x6bcdf07a423aa96b), // 5^-127
    U128.new(0xad4ab7112eb3929d, 0x86c16c98d2c953c6), // 5^-126
    U128.new(0xd89d64d57a607744, 0xe871c7bf077ba8b7), // 5^-125
    U128.new(0x87625f056c7c4a8b, 0x11471cd764ad4972), // 5^-124
    U128.new(0xa93af6c6c79b5d2d, 0xd598e40d3dd89bcf), // 5^-123
    U128.new(0xd389b47879823479, 0x4aff1d108d4ec2c3), // 5^-122
    U128.new(0x843610cb4bf160cb, 0xcedf722a585139ba), // 5^-121
    U128.new(0xa54394fe1eedb8fe, 0xc2974eb4ee658828), // 5^-120
    U128.new(0xce947a3da6a9273e, 0x733d226229feea32), // 5^-119
    U128.new(0x811ccc668829b887, 0x806357d5a3f525f), // 5^-118
    U128.new(0xa163ff802a3426a8, 0xca07c2dcb0cf26f7), // 5^-117
    U128.new(0xc9bcff6034c13052, 0xfc89b393dd02f0b5), // 5^-116
    U128.new(0xfc2c3f3841f17c67, 0xbbac2078d443ace2), // 5^-115
    U128.new(0x9d9ba7832936edc0, 0xd54b944b84aa4c0d), // 5^-114
    U128.new(0xc5029163f384a931, 0xa9e795e65d4df11), // 5^-113
    U128.new(0xf64335bcf065d37d, 0x4d4617b5ff4a16d5), // 5^-112
    U128.new(0x99ea0196163fa42e, 0x504bced1bf8e4e45), // 5^-111
    U128.new(0xc06481fb9bcf8d39, 0xe45ec2862f71e1d6), // 5^-110
    U128.new(0xf07da27a82c37088, 0x5d767327bb4e5a4c), // 5^-109
    U128.new(0x964e858c91ba2655, 0x3a6a07f8d510f86f), // 5^-108
    U128.new(0xbbe226efb628afea, 0x890489f70a55368b), // 5^-107
    U128.new(0xeadab0aba3b2dbe5, 0x2b45ac74ccea842e), // 5^-106
    U128.new(0x92c8ae6b464fc96f, 0x3b0b8bc90012929d), // 5^-105
    U128.new(0xb77ada0617e3bbcb, 0x9ce6ebb40173744), // 5^-104
    U128.new(0xe55990879ddcaabd, 0xcc420a6a101d0515), // 5^-103
    U128.new(0x8f57fa54c2a9eab6, 0x9fa946824a12232d), // 5^-102
    U128.new(0xb32df8e9f3546564, 0x47939822dc96abf9), // 5^-101
    U128.new(0xdff9772470297ebd, 0x59787e2b93bc56f7), // 5^-100
    U128.new(0x8bfbea76c619ef36, 0x57eb4edb3c55b65a), // 5^-99
    U128.new(0xaefae51477a06b03, 0xede622920b6b23f1), // 5^-98
    U128.new(0xdab99e59958885c4, 0xe95fab368e45eced), // 5^-97
    U128.new(0x88b402f7fd75539b, 0x11dbcb0218ebb414), // 5^-96
    U128.new(0xaae103b5fcd2a881, 0xd652bdc29f26a119), // 5^-95
    U128.new(0xd59944a37c0752a2, 0x4be76d3346f0495f), // 5^-94
    U128.new(0x857fcae62d8493a5, 0x6f70a4400c562ddb), // 5^-93
    U128.new(0xa6dfbd9fb8e5b88e, 0xcb4ccd500f6bb952), // 5^-92
    U128.new(0xd097ad07a71f26b2, 0x7e2000a41346a7a7), // 5^-91
    U128.new(0x825ecc24c873782f, 0x8ed400668c0c28c8), // 5^-90
    U128.new(0xa2f67f2dfa90563b, 0x728900802f0f32fa), // 5^-89
    U128.new(0xcbb41ef979346bca, 0x4f2b40a03ad2ffb9), // 5^-88
    U128.new(0xfea126b7d78186bc, 0xe2f610c84987bfa8), // 5^-87
    U128.new(0x9f24b832e6b0f436, 0xdd9ca7d2df4d7c9), // 5^-86
    U128.new(0xc6ede63fa05d3143, 0x91503d1c79720dbb), // 5^-85
    U128.new(0xf8a95fcf88747d94, 0x75a44c6397ce912a), // 5^-84
    U128.new(0x9b69dbe1b548ce7c, 0xc986afbe3ee11aba), // 5^-83
    U128.new(0xc24452da229b021b, 0xfbe85badce996168), // 5^-82
    U128.new(0xf2d56790ab41c2a2, 0xfae27299423fb9c3), // 5^-81
    U128.new(0x97c560ba6b0919a5, 0xdccd879fc967d41a), // 5^-80
    U128.new(0xbdb6b8e905cb600f, 0x5400e987bbc1c920), // 5^-79
    U128.new(0xed246723473e3813, 0x290123e9aab23b68), // 5^-78
    U128.new(0x9436c0760c86e30b, 0xf9a0b6720aaf6521), // 5^-77
    U128.new(0xb94470938fa89bce, 0xf808e40e8d5b3e69), // 5^-76
    U128.new(0xe7958cb87392c2c2, 0xb60b1d1230b20e04), // 5^-75
    U128.new(0x90bd77f3483bb9b9, 0xb1c6f22b5e6f48c2), // 5^-74
    U128.new(0xb4ecd5f01a4aa828, 0x1e38aeb6360b1af3), // 5^-73
    U128.new(0xe2280b6c20dd5232, 0x25c6da63c38de1b0), // 5^-72
    U128.new(0x8d590723948a535f, 0x579c487e5a38ad0e), // 5^-71
    U128.new(0xb0af48ec79ace837, 0x2d835a9df0c6d851), // 5^-70
    U128.new(0xdcdb1b2798182244, 0xf8e431456cf88e65), // 5^-69
    U128.new(0x8a08f0f8bf0f156b, 0x1b8e9ecb641b58ff), // 5^-68
    U128.new(0xac8b2d36eed2dac5, 0xe272467e3d222f3f), // 5^-67
    U128.new(0xd7adf884aa879177, 0x5b0ed81dcc6abb0f), // 5^-66
    U128.new(0x86ccbb52ea94baea, 0x98e947129fc2b4e9), // 5^-65
    U128.new(0xa87fea27a539e9a5, 0x3f2398d747b36224), // 5^-64
    U128.new(0xd29fe4b18e88640e, 0x8eec7f0d19a03aad), // 5^-63
    U128.new(0x83a3eeeef9153e89, 0x1953cf68300424ac), // 5^-62
    U128.new(0xa48ceaaab75a8e2b, 0x5fa8c3423c052dd7), // 5^-61
    U128.new(0xcdb02555653131b6, 0x3792f412cb06794d), // 5^-60
    U128.new(0x808e17555f3ebf11, 0xe2bbd88bbee40bd0), // 5^-59
    U128.new(0xa0b19d2ab70e6ed6, 0x5b6aceaeae9d0ec4), // 5^-58
    U128.new(0xc8de047564d20a8b, 0xf245825a5a445275), // 5^-57
    U128.new(0xfb158592be068d2e, 0xeed6e2f0f0d56712), // 5^-56
    U128.new(0x9ced737bb6c4183d, 0x55464dd69685606b), // 5^-55
    U128.new(0xc428d05aa4751e4c, 0xaa97e14c3c26b886), // 5^-54
    U128.new(0xf53304714d9265df, 0xd53dd99f4b3066a8), // 5^-53
    U128.new(0x993fe2c6d07b7fab, 0xe546a8038efe4029), // 5^-52
    U128.new(0xbf8fdb78849a5f96, 0xde98520472bdd033), // 5^-51
    U128.new(0xef73d256a5c0f77c, 0x963e66858f6d4440), // 5^-50
    U128.new(0x95a8637627989aad, 0xdde7001379a44aa8), // 5^-49
    U128.new(0xbb127c53b17ec159, 0x5560c018580d5d52), // 5^-48
    U128.new(0xe9d71b689dde71af, 0xaab8f01e6e10b4a6), // 5^-47
    U128.new(0x9226712162ab070d, 0xcab3961304ca70e8), // 5^-46
    U128.new(0xb6b00d69bb55c8d1, 0x3d607b97c5fd0d22), // 5^-45
    U128.new(0xe45c10c42a2b3b05, 0x8cb89a7db77c506a), // 5^-44
    U128.new(0x8eb98a7a9a5b04e3, 0x77f3608e92adb242), // 5^-43
    U128.new(0xb267ed1940f1c61c, 0x55f038b237591ed3), // 5^-42
    U128.new(0xdf01e85f912e37a3, 0x6b6c46dec52f6688), // 5^-41
    U128.new(0x8b61313bbabce2c6, 0x2323ac4b3b3da015), // 5^-40
    U128.new(0xae397d8aa96c1b77, 0xabec975e0a0d081a), // 5^-39
    U128.new(0xd9c7dced53c72255, 0x96e7bd358c904a21), // 5^-38
    U128.new(0x881cea14545c7575, 0x7e50d64177da2e54), // 5^-37
    U128.new(0xaa242499697392d2, 0xdde50bd1d5d0b9e9), // 5^-36
    U128.new(0xd4ad2dbfc3d07787, 0x955e4ec64b44e864), // 5^-35
    U128.new(0x84ec3c97da624ab4, 0xbd5af13bef0b113e), // 5^-34
    U128.new(0xa6274bbdd0fadd61, 0xecb1ad8aeacdd58e), // 5^-33
    U128.new(0xcfb11ead453994ba, 0x67de18eda5814af2), // 5^-32
    U128.new(0x81ceb32c4b43fcf4, 0x80eacf948770ced7), // 5^-31
    U128.new(0xa2425ff75e14fc31, 0xa1258379a94d028d), // 5^-30
    U128.new(0xcad2f7f5359a3b3e, 0x96ee45813a04330), // 5^-29
    U128.new(0xfd87b5f28300ca0d, 0x8bca9d6e188853fc), // 5^-28
    U128.new(0x9e74d1b791e07e48, 0x775ea264cf55347e), // 5^-27
    U128.new(0xc612062576589dda, 0x95364afe032a819e), // 5^-26
    U128.new(0xf79687aed3eec551, 0x3a83ddbd83f52205), // 5^-25
    U128.new(0x9abe14cd44753b52, 0xc4926a9672793543), // 5^-24
    U128.new(0xc16d9a0095928a27, 0x75b7053c0f178294), // 5^-23
    U128.new(0xf1c90080baf72cb1, 0x5324c68b12dd6339), // 5^-22
    U128.new(0x971da05074da7bee, 0xd3f6fc16ebca5e04), // 5^-21
    U128.new(0xbce5086492111aea, 0x88f4bb1ca6bcf585), // 5^-20
    U128.new(0xec1e4a7db69561a5, 0x2b31e9e3d06c32e6), // 5^-19
    U128.new(0x9392ee8e921d5d07, 0x3aff322e62439fd0), // 5^-18
    U128.new(0xb877aa3236a4b449, 0x9befeb9fad487c3), // 5^-17
    U128.new(0xe69594bec44de15b, 0x4c2ebe687989a9b4), // 5^-16
    U128.new(0x901d7cf73ab0acd9, 0xf9d37014bf60a11), // 5^-15
    U128.new(0xb424dc35095cd80f, 0x538484c19ef38c95), // 5^-14
    U128.new(0xe12e13424bb40e13, 0x2865a5f206b06fba), // 5^-13
    U128.new(0x8cbccc096f5088cb, 0xf93f87b7442e45d4), // 5^-12
    U128.new(0xafebff0bcb24aafe, 0xf78f69a51539d749), // 5^-11
    U128.new(0xdbe6fecebdedd5be, 0xb573440e5a884d1c), // 5^-10
    U128.new(0x89705f4136b4a597, 0x31680a88f8953031), // 5^-9
    U128.new(0xabcc77118461cefc, 0xfdc20d2b36ba7c3e), // 5^-8
    U128.new(0xd6bf94d5e57a42bc, 0x3d32907604691b4d), // 5^-7
    U128.new(0x8637bd05af6c69b5, 0xa63f9a49c2c1b110), // 5^-6
    U128.new(0xa7c5ac471b478423, 0xfcf80dc33721d54), // 5^-5
    U128.new(0xd1b71758e219652b, 0xd3c36113404ea4a9), // 5^-4
    U128.new(0x83126e978d4fdf3b, 0x645a1cac083126ea), // 5^-3
    U128.new(0xa3d70a3d70a3d70a, 0x3d70a3d70a3d70a4), // 5^-2
    U128.new(0xcccccccccccccccc, 0xcccccccccccccccd), // 5^-1
    U128.new(0x8000000000000000, 0x0), // 5^0
    U128.new(0xa000000000000000, 0x0), // 5^1
    U128.new(0xc800000000000000, 0x0), // 5^2
    U128.new(0xfa00000000000000, 0x0), // 5^3
    U128.new(0x9c40000000000000, 0x0), // 5^4
    U128.new(0xc350000000000000, 0x0), // 5^5
    U128.new(0xf424000000000000, 0x0), // 5^6
    U128.new(0x9896800000000000, 0x0), // 5^7
    U128.new(0xbebc200000000000, 0x0), // 5^8
    U128.new(0xee6b280000000000, 0x0), // 5^9
    U128.new(0x9502f90000000000, 0x0), // 5^10
    U128.new(0xba43b74000000000, 0x0), // 5^11
    U128.new(0xe8d4a51000000000, 0x0), // 5^12
    U128.new(0x9184e72a00000000, 0x0), // 5^13
    U128.new(0xb5e620f480000000, 0x0), // 5^14
    U128.new(0xe35fa931a0000000, 0x0), // 5^15
    U128.new(0x8e1bc9bf04000000, 0x0), // 5^16
    U128.new(0xb1a2bc2ec5000000, 0x0), // 5^17
    U128.new(0xde0b6b3a76400000, 0x0), // 5^18
    U128.new(0x8ac7230489e80000, 0x0), // 5^19
    U128.new(0xad78ebc5ac620000, 0x0), // 5^20
    U128.new(0xd8d726b7177a8000, 0x0), // 5^21
    U128.new(0x878678326eac9000, 0x0), // 5^22
    U128.new(0xa968163f0a57b400, 0x0), // 5^23
    U128.new(0xd3c21bcecceda100, 0x0), // 5^24
    U128.new(0x84595161401484a0, 0x0), // 5^25
    U128.new(0xa56fa5b99019a5c8, 0x0), // 5^26
    U128.new(0xcecb8f27f4200f3a, 0x0), // 5^27
    U128.new(0x813f3978f8940984, 0x4000000000000000), // 5^28
    U128.new(0xa18f07d736b90be5, 0x5000000000000000), // 5^29
    U128.new(0xc9f2c9cd04674ede, 0xa400000000000000), // 5^30
    U128.new(0xfc6f7c4045812296, 0x4d00000000000000), // 5^31
    U128.new(0x9dc5ada82b70b59d, 0xf020000000000000), // 5^32
    U128.new(0xc5371912364ce305, 0x6c28000000000000), // 5^33
    U128.new(0xf684df56c3e01bc6, 0xc732000000000000), // 5^34
    U128.new(0x9a130b963a6c115c, 0x3c7f400000000000), // 5^35
    U128.new(0xc097ce7bc90715b3, 0x4b9f100000000000), // 5^36
    U128.new(0xf0bdc21abb48db20, 0x1e86d40000000000), // 5^37
    U128.new(0x96769950b50d88f4, 0x1314448000000000), // 5^38
    U128.new(0xbc143fa4e250eb31, 0x17d955a000000000), // 5^39
    U128.new(0xeb194f8e1ae525fd, 0x5dcfab0800000000), // 5^40
    U128.new(0x92efd1b8d0cf37be, 0x5aa1cae500000000), // 5^41
    U128.new(0xb7abc627050305ad, 0xf14a3d9e40000000), // 5^42
    U128.new(0xe596b7b0c643c719, 0x6d9ccd05d0000000), // 5^43
    U128.new(0x8f7e32ce7bea5c6f, 0xe4820023a2000000), // 5^44
    U128.new(0xb35dbf821ae4f38b, 0xdda2802c8a800000), // 5^45
    U128.new(0xe0352f62a19e306e, 0xd50b2037ad200000), // 5^46
    U128.new(0x8c213d9da502de45, 0x4526f422cc340000), // 5^47
    U128.new(0xaf298d050e4395d6, 0x9670b12b7f410000), // 5^48
    U128.new(0xdaf3f04651d47b4c, 0x3c0cdd765f114000), // 5^49
    U128.new(0x88d8762bf324cd0f, 0xa5880a69fb6ac800), // 5^50
    U128.new(0xab0e93b6efee0053, 0x8eea0d047a457a00), // 5^51
    U128.new(0xd5d238a4abe98068, 0x72a4904598d6d880), // 5^52
    U128.new(0x85a36366eb71f041, 0x47a6da2b7f864750), // 5^53
    U128.new(0xa70c3c40a64e6c51, 0x999090b65f67d924), // 5^54
    U128.new(0xd0cf4b50cfe20765, 0xfff4b4e3f741cf6d), // 5^55
    U128.new(0x82818f1281ed449f, 0xbff8f10e7a8921a4), // 5^56
    U128.new(0xa321f2d7226895c7, 0xaff72d52192b6a0d), // 5^57
    U128.new(0xcbea6f8ceb02bb39, 0x9bf4f8a69f764490), // 5^58
    U128.new(0xfee50b7025c36a08, 0x2f236d04753d5b4), // 5^59
    U128.new(0x9f4f2726179a2245, 0x1d762422c946590), // 5^60
    U128.new(0xc722f0ef9d80aad6, 0x424d3ad2b7b97ef5), // 5^61
    U128.new(0xf8ebad2b84e0d58b, 0xd2e0898765a7deb2), // 5^62
    U128.new(0x9b934c3b330c8577, 0x63cc55f49f88eb2f), // 5^63
    U128.new(0xc2781f49ffcfa6d5, 0x3cbf6b71c76b25fb), // 5^64
    U128.new(0xf316271c7fc3908a, 0x8bef464e3945ef7a), // 5^65
    U128.new(0x97edd871cfda3a56, 0x97758bf0e3cbb5ac), // 5^66
    U128.new(0xbde94e8e43d0c8ec, 0x3d52eeed1cbea317), // 5^67
    U128.new(0xed63a231d4c4fb27, 0x4ca7aaa863ee4bdd), // 5^68
    U128.new(0x945e455f24fb1cf8, 0x8fe8caa93e74ef6a), // 5^69
    U128.new(0xb975d6b6ee39e436, 0xb3e2fd538e122b44), // 5^70
    U128.new(0xe7d34c64a9c85d44, 0x60dbbca87196b616), // 5^71
    U128.new(0x90e40fbeea1d3a4a, 0xbc8955e946fe31cd), // 5^72
    U128.new(0xb51d13aea4a488dd, 0x6babab6398bdbe41), // 5^73
    U128.new(0xe264589a4dcdab14, 0xc696963c7eed2dd1), // 5^74
    U128.new(0x8d7eb76070a08aec, 0xfc1e1de5cf543ca2), // 5^75
    U128.new(0xb0de65388cc8ada8, 0x3b25a55f43294bcb), // 5^76
    U128.new(0xdd15fe86affad912, 0x49ef0eb713f39ebe), // 5^77
    U128.new(0x8a2dbf142dfcc7ab, 0x6e3569326c784337), // 5^78
    U128.new(0xacb92ed9397bf996, 0x49c2c37f07965404), // 5^79
    U128.new(0xd7e77a8f87daf7fb, 0xdc33745ec97be906), // 5^80
    U128.new(0x86f0ac99b4e8dafd, 0x69a028bb3ded71a3), // 5^81
    U128.new(0xa8acd7c0222311bc, 0xc40832ea0d68ce0c), // 5^82
    U128.new(0xd2d80db02aabd62b, 0xf50a3fa490c30190), // 5^83
    U128.new(0x83c7088e1aab65db, 0x792667c6da79e0fa), // 5^84
    U128.new(0xa4b8cab1a1563f52, 0x577001b891185938), // 5^85
    U128.new(0xcde6fd5e09abcf26, 0xed4c0226b55e6f86), // 5^86
    U128.new(0x80b05e5ac60b6178, 0x544f8158315b05b4), // 5^87
    U128.new(0xa0dc75f1778e39d6, 0x696361ae3db1c721), // 5^88
    U128.new(0xc913936dd571c84c, 0x3bc3a19cd1e38e9), // 5^89
    U128.new(0xfb5878494ace3a5f, 0x4ab48a04065c723), // 5^90
    U128.new(0x9d174b2dcec0e47b, 0x62eb0d64283f9c76), // 5^91
    U128.new(0xc45d1df942711d9a, 0x3ba5d0bd324f8394), // 5^92
    U128.new(0xf5746577930d6500, 0xca8f44ec7ee36479), // 5^93
    U128.new(0x9968bf6abbe85f20, 0x7e998b13cf4e1ecb), // 5^94
    U128.new(0xbfc2ef456ae276e8, 0x9e3fedd8c321a67e), // 5^95
    U128.new(0xefb3ab16c59b14a2, 0xc5cfe94ef3ea101e), // 5^96
    U128.new(0x95d04aee3b80ece5, 0xbba1f1d158724a12), // 5^97
    U128.new(0xbb445da9ca61281f, 0x2a8a6e45ae8edc97), // 5^98
    U128.new(0xea1575143cf97226, 0xf52d09d71a3293bd), // 5^99
    U128.new(0x924d692ca61be758, 0x593c2626705f9c56), // 5^100
    U128.new(0xb6e0c377cfa2e12e, 0x6f8b2fb00c77836c), // 5^101
    U128.new(0xe498f455c38b997a, 0xb6dfb9c0f956447), // 5^102
    U128.new(0x8edf98b59a373fec, 0x4724bd4189bd5eac), // 5^103
    U128.new(0xb2977ee300c50fe7, 0x58edec91ec2cb657), // 5^104
    U128.new(0xdf3d5e9bc0f653e1, 0x2f2967b66737e3ed), // 5^105
    U128.new(0x8b865b215899f46c, 0xbd79e0d20082ee74), // 5^106
    U128.new(0xae67f1e9aec07187, 0xecd8590680a3aa11), // 5^107
    U128.new(0xda01ee641a708de9, 0xe80e6f4820cc9495), // 5^108
    U128.new(0x884134fe908658b2, 0x3109058d147fdcdd), // 5^109
    U128.new(0xaa51823e34a7eede, 0xbd4b46f0599fd415), // 5^110
    U128.new(0xd4e5e2cdc1d1ea96, 0x6c9e18ac7007c91a), // 5^111
    U128.new(0x850fadc09923329e, 0x3e2cf6bc604ddb0), // 5^112
    U128.new(0xa6539930bf6bff45, 0x84db8346b786151c), // 5^113
    U128.new(0xcfe87f7cef46ff16, 0xe612641865679a63), // 5^114
    U128.new(0x81f14fae158c5f6e, 0x4fcb7e8f3f60c07e), // 5^115
    U128.new(0xa26da3999aef7749, 0xe3be5e330f38f09d), // 5^116
    U128.new(0xcb090c8001ab551c, 0x5cadf5bfd3072cc5), // 5^117
    U128.new(0xfdcb4fa002162a63, 0x73d9732fc7c8f7f6), // 5^118
    U128.new(0x9e9f11c4014dda7e, 0x2867e7fddcdd9afa), // 5^119
    U128.new(0xc646d63501a1511d, 0xb281e1fd541501b8), // 5^120
    U128.new(0xf7d88bc24209a565, 0x1f225a7ca91a4226), // 5^121
    U128.new(0x9ae757596946075f, 0x3375788de9b06958), // 5^122
    U128.new(0xc1a12d2fc3978937, 0x52d6b1641c83ae), // 5^123
    U128.new(0xf209787bb47d6b84, 0xc0678c5dbd23a49a), // 5^124
    U128.new(0x9745eb4d50ce6332, 0xf840b7ba963646e0), // 5^125
    U128.new(0xbd176620a501fbff, 0xb650e5a93bc3d898), // 5^126
    U128.new(0xec5d3fa8ce427aff, 0xa3e51f138ab4cebe), // 5^127
    U128.new(0x93ba47c980e98cdf, 0xc66f336c36b10137), // 5^128
    U128.new(0xb8a8d9bbe123f017, 0xb80b0047445d4184), // 5^129
    U128.new(0xe6d3102ad96cec1d, 0xa60dc059157491e5), // 5^130
    U128.new(0x9043ea1ac7e41392, 0x87c89837ad68db2f), // 5^131
    U128.new(0xb454e4a179dd1877, 0x29babe4598c311fb), // 5^132
    U128.new(0xe16a1dc9d8545e94, 0xf4296dd6fef3d67a), // 5^133
    U128.new(0x8ce2529e2734bb1d, 0x1899e4a65f58660c), // 5^134
    U128.new(0xb01ae745b101e9e4, 0x5ec05dcff72e7f8f), // 5^135
    U128.new(0xdc21a1171d42645d, 0x76707543f4fa1f73), // 5^136
    U128.new(0x899504ae72497eba, 0x6a06494a791c53a8), // 5^137
    U128.new(0xabfa45da0edbde69, 0x487db9d17636892), // 5^138
    U128.new(0xd6f8d7509292d603, 0x45a9d2845d3c42b6), // 5^139
    U128.new(0x865b86925b9bc5c2, 0xb8a2392ba45a9b2), // 5^140
    U128.new(0xa7f26836f282b732, 0x8e6cac7768d7141e), // 5^141
    U128.new(0xd1ef0244af2364ff, 0x3207d795430cd926), // 5^142
    U128.new(0x8335616aed761f1f, 0x7f44e6bd49e807b8), // 5^143
    U128.new(0xa402b9c5a8d3a6e7, 0x5f16206c9c6209a6), // 5^144
    U128.new(0xcd036837130890a1, 0x36dba887c37a8c0f), // 5^145
    U128.new(0x802221226be55a64, 0xc2494954da2c9789), // 5^146
    U128.new(0xa02aa96b06deb0fd, 0xf2db9baa10b7bd6c), // 5^147
    U128.new(0xc83553c5c8965d3d, 0x6f92829494e5acc7), // 5^148
    U128.new(0xfa42a8b73abbf48c, 0xcb772339ba1f17f9), // 5^149
    U128.new(0x9c69a97284b578d7, 0xff2a760414536efb), // 5^150
    U128.new(0xc38413cf25e2d70d, 0xfef5138519684aba), // 5^151
    U128.new(0xf46518c2ef5b8cd1, 0x7eb258665fc25d69), // 5^152
    U128.new(0x98bf2f79d5993802, 0xef2f773ffbd97a61), // 5^153
    U128.new(0xbeeefb584aff8603, 0xaafb550ffacfd8fa), // 5^154
    U128.new(0xeeaaba2e5dbf6784, 0x95ba2a53f983cf38), // 5^155
    U128.new(0x952ab45cfa97a0b2, 0xdd945a747bf26183), // 5^156
    U128.new(0xba756174393d88df, 0x94f971119aeef9e4), // 5^157
    U128.new(0xe912b9d1478ceb17, 0x7a37cd5601aab85d), // 5^158
    U128.new(0x91abb422ccb812ee, 0xac62e055c10ab33a), // 5^159
    U128.new(0xb616a12b7fe617aa, 0x577b986b314d6009), // 5^160
    U128.new(0xe39c49765fdf9d94, 0xed5a7e85fda0b80b), // 5^161
    U128.new(0x8e41ade9fbebc27d, 0x14588f13be847307), // 5^162
    U128.new(0xb1d219647ae6b31c, 0x596eb2d8ae258fc8), // 5^163
    U128.new(0xde469fbd99a05fe3, 0x6fca5f8ed9aef3bb), // 5^164
    U128.new(0x8aec23d680043bee, 0x25de7bb9480d5854), // 5^165
    U128.new(0xada72ccc20054ae9, 0xaf561aa79a10ae6a), // 5^166
    U128.new(0xd910f7ff28069da4, 0x1b2ba1518094da04), // 5^167
    U128.new(0x87aa9aff79042286, 0x90fb44d2f05d0842), // 5^168
    U128.new(0xa99541bf57452b28, 0x353a1607ac744a53), // 5^169
    U128.new(0xd3fa922f2d1675f2, 0x42889b8997915ce8), // 5^170
    U128.new(0x847c9b5d7c2e09b7, 0x69956135febada11), // 5^171
    U128.new(0xa59bc234db398c25, 0x43fab9837e699095), // 5^172
    U128.new(0xcf02b2c21207ef2e, 0x94f967e45e03f4bb), // 5^173
    U128.new(0x8161afb94b44f57d, 0x1d1be0eebac278f5), // 5^174
    U128.new(0xa1ba1ba79e1632dc, 0x6462d92a69731732), // 5^175
    U128.new(0xca28a291859bbf93, 0x7d7b8f7503cfdcfe), // 5^176
    U128.new(0xfcb2cb35e702af78, 0x5cda735244c3d43e), // 5^177
    U128.new(0x9defbf01b061adab, 0x3a0888136afa64a7), // 5^178
    U128.new(0xc56baec21c7a1916, 0x88aaa1845b8fdd0), // 5^179
    U128.new(0xf6c69a72a3989f5b, 0x8aad549e57273d45), // 5^180
    U128.new(0x9a3c2087a63f6399, 0x36ac54e2f678864b), // 5^181
    U128.new(0xc0cb28a98fcf3c7f, 0x84576a1bb416a7dd), // 5^182
    U128.new(0xf0fdf2d3f3c30b9f, 0x656d44a2a11c51d5), // 5^183
    U128.new(0x969eb7c47859e743, 0x9f644ae5a4b1b325), // 5^184
    U128.new(0xbc4665b596706114, 0x873d5d9f0dde1fee), // 5^185
    U128.new(0xeb57ff22fc0c7959, 0xa90cb506d155a7ea), // 5^186
    U128.new(0x9316ff75dd87cbd8, 0x9a7f12442d588f2), // 5^187
    U128.new(0xb7dcbf5354e9bece, 0xc11ed6d538aeb2f), // 5^188
    U128.new(0xe5d3ef282a242e81, 0x8f1668c8a86da5fa), // 5^189
    U128.new(0x8fa475791a569d10, 0xf96e017d694487bc), // 5^190
    U128.new(0xb38d92d760ec4455, 0x37c981dcc395a9ac), // 5^191
    U128.new(0xe070f78d3927556a, 0x85bbe253f47b1417), // 5^192
    U128.new(0x8c469ab843b89562, 0x93956d7478ccec8e), // 5^193
    U128.new(0xaf58416654a6babb, 0x387ac8d1970027b2), // 5^194
    U128.new(0xdb2e51bfe9d0696a, 0x6997b05fcc0319e), // 5^195
    U128.new(0x88fcf317f22241e2, 0x441fece3bdf81f03), // 5^196
    U128.new(0xab3c2fddeeaad25a, 0xd527e81cad7626c3), // 5^197
    U128.new(0xd60b3bd56a5586f1, 0x8a71e223d8d3b074), // 5^198
    U128.new(0x85c7056562757456, 0xf6872d5667844e49), // 5^199
    U128.new(0xa738c6bebb12d16c, 0xb428f8ac016561db), // 5^200
    U128.new(0xd106f86e69d785c7, 0xe13336d701beba52), // 5^201
    U128.new(0x82a45b450226b39c, 0xecc0024661173473), // 5^202
    U128.new(0xa34d721642b06084, 0x27f002d7f95d0190), // 5^203
    U128.new(0xcc20ce9bd35c78a5, 0x31ec038df7b441f4), // 5^204
    U128.new(0xff290242c83396ce, 0x7e67047175a15271), // 5^205
    U128.new(0x9f79a169bd203e41, 0xf0062c6e984d386), // 5^206
    U128.new(0xc75809c42c684dd1, 0x52c07b78a3e60868), // 5^207
    U128.new(0xf92e0c3537826145, 0xa7709a56ccdf8a82), // 5^208
    U128.new(0x9bbcc7a142b17ccb, 0x88a66076400bb691), // 5^209
    U128.new(0xc2abf989935ddbfe, 0x6acff893d00ea435), // 5^210
    U128.new(0xf356f7ebf83552fe, 0x583f6b8c4124d43), // 5^211
    U128.new(0x98165af37b2153de, 0xc3727a337a8b704a), // 5^212
    U128.new(0xbe1bf1b059e9a8d6, 0x744f18c0592e4c5c), // 5^213
    U128.new(0xeda2ee1c7064130c, 0x1162def06f79df73), // 5^214
    U128.new(0x9485d4d1c63e8be7, 0x8addcb5645ac2ba8), // 5^215
    U128.new(0xb9a74a0637ce2ee1, 0x6d953e2bd7173692), // 5^216
    U128.new(0xe8111c87c5c1ba99, 0xc8fa8db6ccdd0437), // 5^217
    U128.new(0x910ab1d4db9914a0, 0x1d9c9892400a22a2), // 5^218
    U128.new(0xb54d5e4a127f59c8, 0x2503beb6d00cab4b), // 5^219
    U128.new(0xe2a0b5dc971f303a, 0x2e44ae64840fd61d), // 5^220
    U128.new(0x8da471a9de737e24, 0x5ceaecfed289e5d2), // 5^221
    U128.new(0xb10d8e1456105dad, 0x7425a83e872c5f47), // 5^222
    U128.new(0xdd50f1996b947518, 0xd12f124e28f77719), // 5^223
    U128.new(0x8a5296ffe33cc92f, 0x82bd6b70d99aaa6f), // 5^224
    U128.new(0xace73cbfdc0bfb7b, 0x636cc64d1001550b), // 5^225
    U128.new(0xd8210befd30efa5a, 0x3c47f7e05401aa4e), // 5^226
    U128.new(0x8714a775e3e95c78, 0x65acfaec34810a71), // 5^227
    U128.new(0xa8d9d1535ce3b396, 0x7f1839a741a14d0d), // 5^228
    U128.new(0xd31045a8341ca07c, 0x1ede48111209a050), // 5^229
    U128.new(0x83ea2b892091e44d, 0x934aed0aab460432), // 5^230
    U128.new(0xa4e4b66b68b65d60, 0xf81da84d5617853f), // 5^231
    U128.new(0xce1de40642e3f4b9, 0x36251260ab9d668e), // 5^232
    U128.new(0x80d2ae83e9ce78f3, 0xc1d72b7c6b426019), // 5^233
    U128.new(0xa1075a24e4421730, 0xb24cf65b8612f81f), // 5^234
    U128.new(0xc94930ae1d529cfc, 0xdee033f26797b627), // 5^235
    U128.new(0xfb9b7cd9a4a7443c, 0x169840ef017da3b1), // 5^236
    U128.new(0x9d412e0806e88aa5, 0x8e1f289560ee864e), // 5^237
    U128.new(0xc491798a08a2ad4e, 0xf1a6f2bab92a27e2), // 5^238
    U128.new(0xf5b5d7ec8acb58a2, 0xae10af696774b1db), // 5^239
    U128.new(0x9991a6f3d6bf1765, 0xacca6da1e0a8ef29), // 5^240
    U128.new(0xbff610b0cc6edd3f, 0x17fd090a58d32af3), // 5^241
    U128.new(0xeff394dcff8a948e, 0xddfc4b4cef07f5b0), // 5^242
    U128.new(0x95f83d0a1fb69cd9, 0x4abdaf101564f98e), // 5^243
    U128.new(0xbb764c4ca7a4440f, 0x9d6d1ad41abe37f1), // 5^244
    U128.new(0xea53df5fd18d5513, 0x84c86189216dc5ed), // 5^245
    U128.new(0x92746b9be2f8552c, 0x32fd3cf5b4e49bb4), // 5^246
    U128.new(0xb7118682dbb66a77, 0x3fbc8c33221dc2a1), // 5^247
    U128.new(0xe4d5e82392a40515, 0xfabaf3feaa5334a), // 5^248
    U128.new(0x8f05b1163ba6832d, 0x29cb4d87f2a7400e), // 5^249
    U128.new(0xb2c71d5bca9023f8, 0x743e20e9ef511012), // 5^250
    U128.new(0xdf78e4b2bd342cf6, 0x914da9246b255416), // 5^251
    U128.new(0x8bab8eefb6409c1a, 0x1ad089b6c2f7548e), // 5^252
    U128.new(0xae9672aba3d0c320, 0xa184ac2473b529b1), // 5^253
    U128.new(0xda3c0f568cc4f3e8, 0xc9e5d72d90a2741e), // 5^254
    U128.new(0x8865899617fb1871, 0x7e2fa67c7a658892), // 5^255
    U128.new(0xaa7eebfb9df9de8d, 0xddbb901b98feeab7), // 5^256
    U128.new(0xd51ea6fa85785631, 0x552a74227f3ea565), // 5^257
    U128.new(0x8533285c936b35de, 0xd53a88958f87275f), // 5^258
    U128.new(0xa67ff273b8460356, 0x8a892abaf368f137), // 5^259
    U128.new(0xd01fef10a657842c, 0x2d2b7569b0432d85), // 5^260
    U128.new(0x8213f56a67f6b29b, 0x9c3b29620e29fc73), // 5^261
    U128.new(0xa298f2c501f45f42, 0x8349f3ba91b47b8f), // 5^262
    U128.new(0xcb3f2f7642717713, 0x241c70a936219a73), // 5^263
    U128.new(0xfe0efb53d30dd4d7, 0xed238cd383aa0110), // 5^264
    U128.new(0x9ec95d1463e8a506, 0xf4363804324a40aa), // 5^265
    U128.new(0xc67bb4597ce2ce48, 0xb143c6053edcd0d5), // 5^266
    U128.new(0xf81aa16fdc1b81da, 0xdd94b7868e94050a), // 5^267
    U128.new(0x9b10a4e5e9913128, 0xca7cf2b4191c8326), // 5^268
    U128.new(0xc1d4ce1f63f57d72, 0xfd1c2f611f63a3f0), // 5^269
    U128.new(0xf24a01a73cf2dccf, 0xbc633b39673c8cec), // 5^270
    U128.new(0x976e41088617ca01, 0xd5be0503e085d813), // 5^271
    U128.new(0xbd49d14aa79dbc82, 0x4b2d8644d8a74e18), // 5^272
    U128.new(0xec9c459d51852ba2, 0xddf8e7d60ed1219e), // 5^273
    U128.new(0x93e1ab8252f33b45, 0xcabb90e5c942b503), // 5^274
    U128.new(0xb8da1662e7b00a17, 0x3d6a751f3b936243), // 5^275
    U128.new(0xe7109bfba19c0c9d, 0xcc512670a783ad4), // 5^276
    U128.new(0x906a617d450187e2, 0x27fb2b80668b24c5), // 5^277
    U128.new(0xb484f9dc9641e9da, 0xb1f9f660802dedf6), // 5^278
    U128.new(0xe1a63853bbd26451, 0x5e7873f8a0396973), // 5^279
    U128.new(0x8d07e33455637eb2, 0xdb0b487b6423e1e8), // 5^280
    U128.new(0xb049dc016abc5e5f, 0x91ce1a9a3d2cda62), // 5^281
    U128.new(0xdc5c5301c56b75f7, 0x7641a140cc7810fb), // 5^282
    U128.new(0x89b9b3e11b6329ba, 0xa9e904c87fcb0a9d), // 5^283
    U128.new(0xac2820d9623bf429, 0x546345fa9fbdcd44), // 5^284
    U128.new(0xd732290fbacaf133, 0xa97c177947ad4095), // 5^285
    U128.new(0x867f59a9d4bed6c0, 0x49ed8eabcccc485d), // 5^286
    U128.new(0xa81f301449ee8c70, 0x5c68f256bfff5a74), // 5^287
    U128.new(0xd226fc195c6a2f8c, 0x73832eec6fff3111), // 5^288
    U128.new(0x83585d8fd9c25db7, 0xc831fd53c5ff7eab), // 5^289
    U128.new(0xa42e74f3d032f525, 0xba3e7ca8b77f5e55), // 5^290
    U128.new(0xcd3a1230c43fb26f, 0x28ce1bd2e55f35eb), // 5^291
    U128.new(0x80444b5e7aa7cf85, 0x7980d163cf5b81b3), // 5^292
    U128.new(0xa0555e361951c366, 0xd7e105bcc332621f), // 5^293
    U128.new(0xc86ab5c39fa63440, 0x8dd9472bf3fefaa7), // 5^294
    U128.new(0xfa856334878fc150, 0xb14f98f6f0feb951), // 5^295
    U128.new(0x9c935e00d4b9d8d2, 0x6ed1bf9a569f33d3), // 5^296
    U128.new(0xc3b8358109e84f07, 0xa862f80ec4700c8), // 5^297
    U128.new(0xf4a642e14c6262c8, 0xcd27bb612758c0fa), // 5^298
    U128.new(0x98e7e9cccfbd7dbd, 0x8038d51cb897789c), // 5^299
    U128.new(0xbf21e44003acdd2c, 0xe0470a63e6bd56c3), // 5^300
    U128.new(0xeeea5d5004981478, 0x1858ccfce06cac74), // 5^301
    U128.new(0x95527a5202df0ccb, 0xf37801e0c43ebc8), // 5^302
    U128.new(0xbaa718e68396cffd, 0xd30560258f54e6ba), // 5^303
    U128.new(0xe950df20247c83fd, 0x47c6b82ef32a2069), // 5^304
    U128.new(0x91d28b7416cdd27e, 0x4cdc331d57fa5441), // 5^305
    U128.new(0xb6472e511c81471d, 0xe0133fe4adf8e952), // 5^306
    U128.new(0xe3d8f9e563a198e5, 0x58180fddd97723a6), // 5^307
    U128.new(0x8e679c2f5e44ff8f, 0x570f09eaa7ea7648), // 5^308
};
//! Representation of a float as the significant digits and exponent.
//! The fast path algorithm using machine-sized integers and floats.
//!
//! This only works if both the mantissa and the exponent can be exactly
//! represented as a machine float, since IEE-754 guarantees no rounding
//! will occur.
//!
//! There is an exception: disguised fast-path cases, where we can shift
//! powers-of-10 from the exponent to the significant digits.

const std = @import("std");
const math = std.math;
const common = @import("common.zig");
const FloatInfo = @import("FloatInfo.zig");
const Number = common.Number;
const floatFromU64 = common.floatFromU64;

fn isFastPath(comptime T: type, n: Number(T)) bool {
    const info = FloatInfo.from(T);

    return info.min_exponent_fast_path <= n.exponent and
        n.exponent <= info.max_exponent_fast_path_disguised and
        n.mantissa <= info.max_mantissa_fast_path and
        !n.many_digits;
}

// upper bound for tables is floor(mantissaDigits(T) / log2(5))
// for f64 this is floor(53 / log2(5)) = 22.
//
// Must have max_disguised_fast_path - max_exponent_fast_path entries. (82 - 48 = 34 for f128)
fn fastPow10(comptime T: type, i: usize) T {
    return switch (T) {
        f16 => ([8]f16{
            1e0, 1e1, 1e2, 1e3, 1e4, 0, 0, 0,
        })[i & 7],

        f32 => ([16]f32{
            1e0, 1e1, 1e2,  1e3, 1e4, 1e5, 1e6, 1e7,
            1e8, 1e9, 1e10, 0,   0,   0,   0,   0,
        })[i & 15],

        f64 => ([32]f64{
            1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,
            1e8,  1e9,  1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
            1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22, 0,
            0,    0,    0,    0,    0,    0,    0,    0,
        })[i & 31],

        f80 => ([32]f80{
            1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,
            1e8,  1e9,  1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
            1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22, 1e23,
            1e24, 1e25, 1e26, 1e27, 0,    0,    0,    0,
        })[i & 31],

        f128 => ([64]f128{
            1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,
            1e8,  1e9,  1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
            1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22, 1e23,
            1e24, 1e25, 1e26, 1e27, 1e28, 1e29, 1e30, 1e31,
            1e32, 1e33, 1e34, 1e35, 1e36, 1e37, 1e38, 1e39,
            1e40, 1e41, 1e42, 1e43, 1e44, 1e45, 1e46, 1e47,
            1e48, 0,    0,    0,    0,    0,    0,    0,
            0,    0,    0,    0,    0,    0,    0,    0,
        })[i & 63],

        else => unreachable,
    };
}

fn fastIntPow10(comptime T: type, i: usize) T {
    return switch (T) {
        u64 => ([16]u64{
            1,             10,             100,             1000,
            10000,         100000,         1000000,         10000000,
            100000000,     1000000000,     10000000000,     100000000000,
            1000000000000, 10000000000000, 100000000000000, 1000000000000000,
        })[i],

        u128 => ([35]u128{
            1,                                   10,
            100,                                 1000,
            10000,                               100000,
            1000000,                             10000000,
            100000000,                           1000000000,
            10000000000,                         100000000000,
            1000000000000,                       10000000000000,
            100000000000000,                     1000000000000000,
            10000000000000000,                   100000000000000000,
            1000000000000000000,                 10000000000000000000,
            100000000000000000000,               1000000000000000000000,
            10000000000000000000000,             100000000000000000000000,
            1000000000000000000000000,           10000000000000000000000000,
            100000000000000000000000000,         1000000000000000000000000000,
            10000000000000000000000000000,       100000000000000000000000000000,
            1000000000000000000000000000000,     10000000000000000000000000000000,
            100000000000000000000000000000000,   1000000000000000000000000000000000,
            10000000000000000000000000000000000,
        })[i],

        else => unreachable,
    };
}

pub fn convertFast(comptime T: type, n: Number(T)) ?T {
    const MantissaT = common.mantissaType(T);

    if (!isFastPath(T, n)) {
        return null;
    }

    // TODO: x86 (no SSE/SSE2) requires x87 FPU to be setup correctly with fldcw
    const info = FloatInfo.from(T);

    var value: T = 0;
    if (n.exponent <= info.max_exponent_fast_path) {
        // normal fast path
        value = @as(T, @floatFromInt(n.mantissa));
        value = if (n.exponent < 0)
            value / fastPow10(T, @as(usize, @intCast(-n.exponent)))
        else
            value * fastPow10(T, @as(usize, @intCast(n.exponent)));
    } else {
        // disguised fast path
        const shift = n.exponent - info.max_exponent_fast_path;
        const mantissa = math.mul(MantissaT, n.mantissa, fastIntPow10(MantissaT, @as(usize, @intCast(shift)))) catch return null;
        if (mantissa > info.max_mantissa_fast_path) {
            return null;
        }
        value = @as(T, @floatFromInt(mantissa)) * fastPow10(T, info.max_exponent_fast_path);
    }

    if (n.negative) {
        value = -value;
    }
    return value;
}
//! Conversion of hex-float representation into an accurate value.
//
// Derived from golang strconv/atof.go.

const std = @import("std");
const math = std.math;
const common = @import("common.zig");
const Number = common.Number;
const floatFromUnsigned = common.floatFromUnsigned;

// converts the form 0xMMM.NNNpEEE.
//
// MMM.NNN = mantissa
// EEE = exponent
//
// MMM.NNN is stored as an integer, the exponent is offset.
pub fn convertHex(comptime T: type, n_: Number(T)) T {
    const MantissaT = common.mantissaType(T);
    var n = n_;

    if (n.mantissa == 0) {
        return if (n.negative) -0.0 else 0.0;
    }

    const max_exp = math.floatExponentMax(T);
    const min_exp = math.floatExponentMin(T);
    const mantissa_bits = math.floatMantissaBits(T);
    const fractional_bits = math.floatFractionalBits(T);
    const exp_bits = math.floatExponentBits(T);
    const exp_bias = min_exp - 1;

    // mantissa now implicitly divided by 2^fractional_bits
    n.exponent += fractional_bits;

    // Shift mantissa and exponent to bring representation into float range.
    // Eventually we want a mantissa with a leading 1-bit followed by mantbits other bits.
    // For rounding, we need two more, where the bottom bit represents
    // whether that bit or any later bit was non-zero.
    // (If the mantissa has already lost non-zero bits, trunc is true,
    // and we OR in a 1 below after shifting left appropriately.)
    while (n.mantissa != 0 and n.mantissa >> (mantissa_bits + 2) == 0) {
        n.mantissa <<= 1;
        n.exponent -= 1;
    }
    if (n.many_digits) {
        n.mantissa |= 1;
    }
    while (n.mantissa >> (1 + fractional_bits + 2) != 0) {
        n.mantissa = (n.mantissa >> 1) | (n.mantissa & 1);
        n.exponent += 1;
    }

    // If exponent is too negative,
    // denormalize in hopes of making it representable.
    // (The -2 is for the rounding bits.)
    while (n.mantissa > 1 and n.exponent < min_exp - 2) {
        n.mantissa = (n.mantissa >> 1) | (n.mantissa & 1);
        n.exponent += 1;
    }

    // Round using two bottom bits.
    var round = n.mantissa & 3;
    n.mantissa >>= 2;
    round |= n.mantissa & 1; // round to even (round up if mantissa is odd)
    n.exponent += 2;
    if (round == 3) {
        n.mantissa += 1;
        if (n.mantissa == 1 << (1 + fractional_bits)) {
            n.mantissa >>= 1;
            n.exponent += 1;
        }
    }

    // Denormal or zero
    if (n.mantissa >> fractional_bits == 0) {
        n.exponent = exp_bias;
    }

    // Infinity and range error
    if (n.exponent > max_exp) {
        return math.inf(T);
    }

    var bits = n.mantissa & ((1 << mantissa_bits) - 1);
    bits |= @as(MantissaT, @intCast((n.exponent - exp_bias) & ((1 << exp_bits) - 1))) << mantissa_bits;
    if (n.negative) {
        bits |= 1 << (mantissa_bits + exp_bits);
    }
    return floatFromUnsigned(T, MantissaT, bits);
}
const std = @import("std");
const math = std.math;
const common = @import("common.zig");
const BiasedFp = common.BiasedFp;
const Decimal = @import("decimal.zig").Decimal;
const mantissaType = common.mantissaType;

const max_shift = 60;
const num_powers = 19;
const powers = [_]u8{ 0, 3, 6, 9, 13, 16, 19, 23, 26, 29, 33, 36, 39, 43, 46, 49, 53, 56, 59 };

pub fn getShift(n: usize) usize {
    return if (n < num_powers) powers[n] else max_shift;
}

/// Parse the significant digits and biased, binary exponent of a float.
///
/// This is a fallback algorithm that uses a big-integer representation
/// of the float, and therefore is considerably slower than faster
/// approximations. However, it will always determine how to round
/// the significant digits to the nearest machine float, allowing
/// use to handle near half-way cases.
///
/// Near half-way cases are halfway between two consecutive machine floats.
/// For example, the float `16777217.0` has a bitwise representation of
/// `100000000000000000000000 1`. Rounding to a single-precision float,
/// the trailing `1` is truncated. Using round-nearest, tie-even, any
/// value above `16777217.0` must be rounded up to `16777218.0`, while
/// any value before or equal to `16777217.0` must be rounded down
/// to `16777216.0`. These near-halfway conversions therefore may require
/// a large number of digits to unambiguously determine how to round.
///
/// The algorithms described here are based on "Processing Long Numbers Quickly",
/// available here: <https://arxiv.org/pdf/2101.11408.pdf#section.11>.
///
/// Note that this function needs a lot of stack space and is marked
/// cold to hint against inlining into the caller.
pub fn convertSlow(comptime T: type, s: []const u8) BiasedFp(T) {
    @branchHint(.cold);

    const MantissaT = mantissaType(T);
    const min_exponent = -(1 << (math.floatExponentBits(T) - 1)) + 1;
    const infinite_power = (1 << math.floatExponentBits(T)) - 1;
    const fractional_bits = math.floatFractionalBits(T);

    var d = Decimal(T).parse(s); // no need to recheck underscores
    if (d.num_digits == 0 or d.decimal_point < Decimal(T).min_exponent) {
        return BiasedFp(T).zero();
    } else if (d.decimal_point >= Decimal(T).max_exponent) {
        return BiasedFp(T).inf(T);
    }

    var exp2: i32 = 0;
    // Shift right toward (1/2 .. 1]
    while (d.decimal_point > 0) {
        const n = @as(usize, @intCast(d.decimal_point));
        const shift = getShift(n);
        d.rightShift(shift);
        if (d.decimal_point < -Decimal(T).decimal_point_range) {
            return BiasedFp(T).zero();
        }
        exp2 += @as(i32, @intCast(shift));
    }
    //  Shift left toward (1/2 .. 1]
    while (d.decimal_point <= 0) {
        const shift = blk: {
            if (d.decimal_point == 0) {
                break :blk switch (d.digits[0]) {
                    5...9 => break,
                    0, 1 => @as(usize, 2),
                    else => 1,
                };
            } else {
                const n = @as(usize, @intCast(-d.decimal_point));
                break :blk getShift(n);
            }
        };
        d.leftShift(shift);
        if (d.decimal_point > Decimal(T).decimal_point_range) {
            return BiasedFp(T).inf(T);
        }
        exp2 -= @as(i32, @intCast(shift));
    }
    // We are now in the range [1/2 .. 1] but the binary format uses [1 .. 2]
    exp2 -= 1;
    while (min_exponent + 1 > exp2) {
        var n = @as(usize, @intCast((min_exponent + 1) - exp2));
        if (n > max_shift) {
            n = max_shift;
        }
        d.rightShift(n);
        exp2 += @as(i32, @intCast(n));
    }
    if (exp2 - min_exponent >= infinite_power) {
        return BiasedFp(T).inf(T);
    }

    // Shift the decimal to the hidden bit, and then round the value
    // to get the high mantissa+1 bits.
    d.leftShift(fractional_bits + 1);
    var mantissa = d.round();
    if (mantissa >= (@as(MantissaT, 1) << (fractional_bits + 1))) {
        // Rounding up overflowed to the carry bit, need to
        // shift back to the hidden bit.
        d.rightShift(1);
        exp2 += 1;
        mantissa = d.round();
        if ((exp2 - min_exponent) >= infinite_power) {
            return BiasedFp(T).inf(T);
        }
    }
    var power2 = exp2 - min_exponent;
    if (mantissa < (@as(MantissaT, 1) << fractional_bits)) {
        power2 -= 1;
    }
    // Zero out all the bits above the mantissa bits.
    mantissa &= (@as(MantissaT, 1) << math.floatMantissaBits(T)) - 1;
    return .{ .f = mantissa, .e = power2 };
}
const std = @import("std");
const math = std.math;
const common = @import("common.zig");
const FloatStream = @import("FloatStream.zig");
const isEightDigits = @import("common.zig").isEightDigits;
const mantissaType = common.mantissaType;

// Arbitrary-precision decimal class for fallback algorithms.
//
// This is only used if the fast-path (native floats) and
// the Eisel-Lemire algorithm are unable to unambiguously
// determine the float.
//
// The technique used is "Simple Decimal Conversion", developed
// by Nigel Tao and Ken Thompson. A detailed description of the
// algorithm can be found in "ParseNumberF64 by Simple Decimal Conversion",
// available online: <https://nigeltao.github.io/blog/2020/parse-number-f64-simple.html>.
//
// Big-decimal implementation. We do not use the big.Int routines since we only require a maximum
// fixed region of memory. Further, we require only a small subset of operations.
//
// This accepts a floating point parameter and will generate a Decimal which can correctly parse
// the input with sufficient accuracy. Internally this means either a u64 mantissa (f16, f32 or f64)
// or a u128 mantissa (f128).
pub fn Decimal(comptime T: type) type {
    const MantissaT = mantissaType(T);
    std.debug.assert(MantissaT == u64 or MantissaT == u128);

    return struct {
        const Self = @This();

        /// The maximum number of digits required to unambiguously round a float.
        ///
        /// For a double-precision IEEE-754 float, this required 767 digits,
        /// so we store the max digits + 1.
        ///
        /// We can exactly represent a float in base `b` from base 2 if
        /// `b` is divisible by 2. This function calculates the exact number of
        /// digits required to exactly represent that float.
        ///
        /// According to the "Handbook of Floating Point Arithmetic",
        /// for IEEE754, with emin being the min exponent, p2 being the
        /// precision, and b being the base, the number of digits follows as:
        ///
        /// `−emin + p2 + ⌊(emin + 1) log(2, b) − log(1 − 2^(−p2), b)⌋`
        ///
        /// For f32, this follows as:
        ///     emin = -126
        ///     p2 = 24
        ///
        /// For f64, this follows as:
        ///     emin = -1022
        ///     p2 = 53
        ///
        /// For f128, this follows as:
        ///     emin = -16383
        ///     p2 = 112
        ///
        /// In Python:
        ///     `-emin + p2 + math.floor((emin+ 1)*math.log(2, b)-math.log(1-2**(-p2), b))`
        pub const max_digits = if (MantissaT == u64) 768 else 11564;
        /// The max digits that can be exactly represented in a 64-bit integer.
        pub const max_digits_without_overflow = if (MantissaT == u64) 19 else 38;
        pub const decimal_point_range = if (MantissaT == u64) 2047 else 32767;
        pub const min_exponent = if (MantissaT == u64) -324 else -4966;
        pub const max_exponent = if (MantissaT == u64) 310 else 4934;
        pub const max_decimal_digits = if (MantissaT == u64) 18 else 37;

        /// The number of significant digits in the decimal.
        num_digits: usize,
        /// The offset of the decimal point in the significant digits.
        decimal_point: i32,
        /// If the number of significant digits stored in the decimal is truncated.
        truncated: bool,
        /// buffer of the raw digits, in the range [0, 9].
        digits: [max_digits]u8,

        pub fn new() Self {
            return .{
                .num_digits = 0,
                .decimal_point = 0,
                .truncated = false,
                .digits = [_]u8{0} ** max_digits,
            };
        }

        /// Append a digit to the buffer
        pub fn tryAddDigit(self: *Self, digit: u8) void {
            if (self.num_digits < max_digits) {
                self.digits[self.num_digits] = digit;
            }
            self.num_digits += 1;
        }

        /// Trim trailing zeroes from the buffer
        pub fn trim(self: *Self) void {
            // All of the following calls to `Self::trim` can't panic because:
            //
            //  1. `parse_decimal` sets `num_digits` to a max of `max_digits`.
            //  2. `right_shift` sets `num_digits` to `write_index`, which is bounded by `num_digits`.
            //  3. `left_shift` `num_digits` to a max of `max_digits`.
            //
            // Trim is only called in `right_shift` and `left_shift`.
            std.debug.assert(self.num_digits <= max_digits);
            while (self.num_digits != 0 and self.digits[self.num_digits - 1] == 0) {
                self.num_digits -= 1;
            }
        }

        pub fn round(self: *Self) MantissaT {
            if (self.num_digits == 0 or self.decimal_point < 0) {
                return 0;
            } else if (self.decimal_point > max_decimal_digits) {
                return math.maxInt(MantissaT);
            }

            const dp = @as(usize, @intCast(self.decimal_point));
            var n: MantissaT = 0;

            var i: usize = 0;
            while (i < dp) : (i += 1) {
                n *= 10;
                if (i < self.num_digits) {
                    n += @as(MantissaT, self.digits[i]);
                }
            }

            var round_up = false;
            if (dp < self.num_digits) {
                round_up = self.digits[dp] >= 5;
                if (self.digits[dp] == 5 and dp + 1 == self.num_digits) {
                    round_up = self.truncated or ((dp != 0) and (1 & self.digits[dp - 1] != 0));
                }
            }
            if (round_up) {
                n += 1;
            }
            return n;
        }

        /// Computes decimal * 2^shift.
        pub fn leftShift(self: *Self, shift: usize) void {
            if (self.num_digits == 0) {
                return;
            }
            const num_new_digits = self.numberOfDigitsLeftShift(shift);
            var read_index = self.num_digits;
            var write_index = self.num_digits + num_new_digits;
            var n: MantissaT = 0;
            while (read_index != 0) {
                read_index -= 1;
                write_index -= 1;
                n += math.shl(MantissaT, self.digits[read_index], shift);

                const quotient = n / 10;
                const remainder = n - (10 * quotient);
                if (write_index < max_digits) {
                    self.digits[write_index] = @as(u8, @intCast(remainder));
                } else if (remainder > 0) {
                    self.truncated = true;
                }
                n = quotient;
            }
            while (n > 0) {
                write_index -= 1;

                const quotient = n / 10;
                const remainder = n - (10 * quotient);
                if (write_index < max_digits) {
                    self.digits[write_index] = @as(u8, @intCast(remainder));
                } else if (remainder > 0) {
                    self.truncated = true;
                }
                n = quotient;
            }

            self.num_digits += num_new_digits;
            if (self.num_digits > max_digits) {
                self.num_digits = max_digits;
            }
            self.decimal_point += @as(i32, @intCast(num_new_digits));
            self.trim();
        }

        /// Computes decimal * 2^-shift.
        pub fn rightShift(self: *Self, shift: usize) void {
            var read_index: usize = 0;
            var write_index: usize = 0;
            var n: MantissaT = 0;
            while (math.shr(MantissaT, n, shift) == 0) {
                if (read_index < self.num_digits) {
                    n = (10 * n) + self.digits[read_index];
                    read_index += 1;
                } else if (n == 0) {
                    return;
                } else {
                    while (math.shr(MantissaT, n, shift) == 0) {
                        n *= 10;
                        read_index += 1;
                    }
                    break;
                }
            }

            self.decimal_point -= @as(i32, @intCast(read_index)) - 1;
            if (self.decimal_point < -decimal_point_range) {
                self.num_digits = 0;
                self.decimal_point = 0;
                self.truncated = false;
                return;
            }

            const mask = math.shl(MantissaT, 1, shift) - 1;
            while (read_index < self.num_digits) {
                const new_digit = @as(u8, @intCast(math.shr(MantissaT, n, shift)));
                n = (10 * (n & mask)) + self.digits[read_index];
                read_index += 1;
                self.digits[write_index] = new_digit;
                write_index += 1;
            }
            while (n > 0) {
                const new_digit = @as(u8, @intCast(math.shr(MantissaT, n, shift)));
                n = 10 * (n & mask);
                if (write_index < max_digits) {
                    self.digits[write_index] = new_digit;
                    write_index += 1;
                } else if (new_digit > 0) {
                    self.truncated = true;
                }
            }
            self.num_digits = write_index;
            self.trim();
        }

        /// Parse a bit integer representation of the float as a decimal.
        // We do not verify underscores in this path since these will have been verified
        // via parse.parseNumber so can assume the number is well-formed.
        // This code-path does not have to handle hex-floats since these will always be handled via another
        // function prior to this.
        pub fn parse(s: []const u8) Self {
            var d = Self.new();
            var stream = FloatStream.init(s);

            stream.skipChars("0_");
            while (stream.scanDigit(10)) |digit| {
                d.tryAddDigit(digit);
            }

            if (stream.firstIs(".")) {
                stream.advance(1);
                const marker = stream.offsetTrue();

                // Skip leading zeroes
                if (d.num_digits == 0) {
                    stream.skipChars("0");
                }

                while (stream.hasLen(8) and d.num_digits + 8 < max_digits) {
                    const v = stream.readU64Unchecked();
                    if (!isEightDigits(v)) {
                        break;
                    }
                    std.mem.writeInt(u64, d.digits[d.num_digits..][0..8], v - 0x3030_3030_3030_3030, .little);
                    d.num_digits += 8;
                    stream.advance(8);
                }

                while (stream.scanDigit(10)) |digit| {
                    d.tryAddDigit(digit);
                }
                d.decimal_point = @as(i32, @intCast(marker)) - @as(i32, @intCast(stream.offsetTrue()));
            }
            if (d.num_digits != 0) {
                // Ignore trailing zeros if any
                var n_trailing_zeros: usize = 0;
                var i = stream.offsetTrue() - 1;
                while (true) {
                    if (s[i] == '0') {
                        n_trailing_zeros += 1;
                    } else if (s[i] != '.') {
                        break;
                    }

                    i -= 1;
                    if (i == 0) break;
                }
                d.decimal_point += @as(i32, @intCast(n_trailing_zeros));
                d.num_digits -= n_trailing_zeros;
                d.decimal_point += @as(i32, @intCast(d.num_digits));
                if (d.num_digits > max_digits) {
                    d.truncated = true;
                    d.num_digits = max_digits;
                }
            }
            if (stream.firstIsLower("e")) {
                stream.advance(1);
                var neg_exp = false;
                if (stream.firstIs("-")) {
                    neg_exp = true;
                    stream.advance(1);
                } else if (stream.firstIs("+")) {
                    stream.advance(1);
                }
                var exp_num: i32 = 0;
                while (stream.scanDigit(10)) |digit| {
                    if (exp_num < 0x10000) {
                        exp_num = 10 * exp_num + digit;
                    }
                }
                d.decimal_point += if (neg_exp) -exp_num else exp_num;
            }

            var i = d.num_digits;
            while (i < max_digits_without_overflow) : (i += 1) {
                d.digits[i] = 0;
            }

            return d;
        }

        // Compute the number decimal digits introduced by a base-2 shift. This is performed
        // by storing the leading digits of 1/2^i = 5^i and using these along with the cut-off
        // value to quickly determine the decimal shift from binary.
        //
        // See also https://github.com/golang/go/blob/go1.15.3/src/strconv/decimal.go#L163 for
        // another description of the method.
        pub fn numberOfDigitsLeftShift(self: *Self, shift: usize) usize {
            const ShiftCutoff = struct {
                delta: u8,
                cutoff: []const u8,
            };

            // Leading digits of 1/2^i = 5^i.
            //
            // ```
            // import math
            //
            // bits = 128
            // for i in range(bits):
            //     log2 = math.log(2)/math.log(10)
            //     print(f'.{{ .delta = {int(log2*i+1)}, .cutoff = "{5**i}" }}, // {2**i}')
            // ```
            const pow2_to_pow5_table = [_]ShiftCutoff{
                .{ .delta = 0, .cutoff = "" },
                .{ .delta = 1, .cutoff = "5" }, // 2
                .{ .delta = 1, .cutoff = "25" }, // 4
                .{ .delta = 1, .cutoff = "125" }, // 8
                .{ .delta = 2, .cutoff = "625" }, // 16
                .{ .delta = 2, .cutoff = "3125" }, // 32
                .{ .delta = 2, .cutoff = "15625" }, // 64
                .{ .delta = 3, .cutoff = "78125" }, // 128
                .{ .delta = 3, .cutoff = "390625" }, // 256
                .{ .delta = 3, .cutoff = "1953125" }, // 512
                .{ .delta = 4, .cutoff = "9765625" }, // 1024
                .{ .delta = 4, .cutoff = "48828125" }, // 2048
                .{ .delta = 4, .cutoff = "244140625" }, // 4096
                .{ .delta = 4, .cutoff = "1220703125" }, // 8192
                .{ .delta = 5, .cutoff = "6103515625" }, // 16384
                .{ .delta = 5, .cutoff = "30517578125" }, // 32768
                .{ .delta = 5, .cutoff = "152587890625" }, // 65536
                .{ .delta = 6, .cutoff = "762939453125" }, // 131072
                .{ .delta = 6, .cutoff = "3814697265625" }, // 262144
                .{ .delta = 6, .cutoff = "19073486328125" }, // 524288
                .{ .delta = 7, .cutoff = "95367431640625" }, // 1048576
                .{ .delta = 7, .cutoff = "476837158203125" }, // 2097152
                .{ .delta = 7, .cutoff = "2384185791015625" }, // 4194304
                .{ .delta = 7, .cutoff = "11920928955078125" }, // 8388608
                .{ .delta = 8, .cutoff = "59604644775390625" }, // 16777216
                .{ .delta = 8, .cutoff = "298023223876953125" }, // 33554432
                .{ .delta = 8, .cutoff = "1490116119384765625" }, // 67108864
                .{ .delta = 9, .cutoff = "7450580596923828125" }, // 134217728
                .{ .delta = 9, .cutoff = "37252902984619140625" }, // 268435456
                .{ .delta = 9, .cutoff = "186264514923095703125" }, // 536870912
                .{ .delta = 10, .cutoff = "931322574615478515625" }, // 1073741824
                .{ .delta = 10, .cutoff = "4656612873077392578125" }, // 2147483648
                .{ .delta = 10, .cutoff = "23283064365386962890625" }, // 4294967296
                .{ .delta = 10, .cutoff = "116415321826934814453125" }, // 8589934592
                .{ .delta = 11, .cutoff = "582076609134674072265625" }, // 17179869184
                .{ .delta = 11, .cutoff = "2910383045673370361328125" }, // 34359738368
                .{ .delta = 11, .cutoff = "14551915228366851806640625" }, // 68719476736
                .{ .delta = 12, .cutoff = "72759576141834259033203125" }, // 137438953472
                .{ .delta = 12, .cutoff = "363797880709171295166015625" }, // 274877906944
                .{ .delta = 12, .cutoff = "1818989403545856475830078125" }, // 549755813888
                .{ .delta = 13, .cutoff = "9094947017729282379150390625" }, // 1099511627776
                .{ .delta = 13, .cutoff = "45474735088646411895751953125" }, // 2199023255552
                .{ .delta = 13, .cutoff = "227373675443232059478759765625" }, // 4398046511104
                .{ .delta = 13, .cutoff = "1136868377216160297393798828125" }, // 8796093022208
                .{ .delta = 14, .cutoff = "5684341886080801486968994140625" }, // 17592186044416
                .{ .delta = 14, .cutoff = "28421709430404007434844970703125" }, // 35184372088832
                .{ .delta = 14, .cutoff = "142108547152020037174224853515625" }, // 70368744177664
                .{ .delta = 15, .cutoff = "710542735760100185871124267578125" }, // 140737488355328
                .{ .delta = 15, .cutoff = "3552713678800500929355621337890625" }, // 281474976710656
                .{ .delta = 15, .cutoff = "17763568394002504646778106689453125" }, // 562949953421312
                .{ .delta = 16, .cutoff = "88817841970012523233890533447265625" }, // 1125899906842624
                .{ .delta = 16, .cutoff = "444089209850062616169452667236328125" }, // 2251799813685248
                .{ .delta = 16, .cutoff = "2220446049250313080847263336181640625" }, // 4503599627370496
                .{ .delta = 16, .cutoff = "11102230246251565404236316680908203125" }, // 9007199254740992
                .{ .delta = 17, .cutoff = "55511151231257827021181583404541015625" }, // 18014398509481984
                .{ .delta = 17, .cutoff = "277555756156289135105907917022705078125" }, // 36028797018963968
                .{ .delta = 17, .cutoff = "1387778780781445675529539585113525390625" }, // 72057594037927936
                .{ .delta = 18, .cutoff = "6938893903907228377647697925567626953125" }, // 144115188075855872
                .{ .delta = 18, .cutoff = "34694469519536141888238489627838134765625" }, // 288230376151711744
                .{ .delta = 18, .cutoff = "173472347597680709441192448139190673828125" }, // 576460752303423488
                .{ .delta = 19, .cutoff = "867361737988403547205962240695953369140625" }, // 1152921504606846976
                .{ .delta = 19, .cutoff = "4336808689942017736029811203479766845703125" }, // 2305843009213693952
                .{ .delta = 19, .cutoff = "21684043449710088680149056017398834228515625" }, // 4611686018427387904
                .{ .delta = 19, .cutoff = "108420217248550443400745280086994171142578125" }, // 9223372036854775808
                .{ .delta = 20, .cutoff = "542101086242752217003726400434970855712890625" }, // 18446744073709551616
                .{ .delta = 20, .cutoff = "2710505431213761085018632002174854278564453125" }, // 36893488147419103232
                .{ .delta = 20, .cutoff = "13552527156068805425093160010874271392822265625" }, // 73786976294838206464
                .{ .delta = 21, .cutoff = "67762635780344027125465800054371356964111328125" }, // 147573952589676412928
                .{ .delta = 21, .cutoff = "338813178901720135627329000271856784820556640625" }, // 295147905179352825856
                .{ .delta = 21, .cutoff = "1694065894508600678136645001359283924102783203125" }, // 590295810358705651712
                .{ .delta = 22, .cutoff = "8470329472543003390683225006796419620513916015625" }, // 1180591620717411303424
                .{ .delta = 22, .cutoff = "42351647362715016953416125033982098102569580078125" }, // 2361183241434822606848
                .{ .delta = 22, .cutoff = "211758236813575084767080625169910490512847900390625" }, // 4722366482869645213696
                .{ .delta = 22, .cutoff = "1058791184067875423835403125849552452564239501953125" }, // 9444732965739290427392
                .{ .delta = 23, .cutoff = "5293955920339377119177015629247762262821197509765625" }, // 18889465931478580854784
                .{ .delta = 23, .cutoff = "26469779601696885595885078146238811314105987548828125" }, // 37778931862957161709568
                .{ .delta = 23, .cutoff = "132348898008484427979425390731194056570529937744140625" }, // 75557863725914323419136
                .{ .delta = 24, .cutoff = "661744490042422139897126953655970282852649688720703125" }, // 151115727451828646838272
                .{ .delta = 24, .cutoff = "3308722450212110699485634768279851414263248443603515625" }, // 302231454903657293676544
                .{ .delta = 24, .cutoff = "16543612251060553497428173841399257071316242218017578125" }, // 604462909807314587353088
                .{ .delta = 25, .cutoff = "82718061255302767487140869206996285356581211090087890625" }, // 1208925819614629174706176
                .{ .delta = 25, .cutoff = "413590306276513837435704346034981426782906055450439453125" }, // 2417851639229258349412352
                .{ .delta = 25, .cutoff = "2067951531382569187178521730174907133914530277252197265625" }, // 4835703278458516698824704
                .{ .delta = 25, .cutoff = "10339757656912845935892608650874535669572651386260986328125" }, // 9671406556917033397649408
                .{ .delta = 26, .cutoff = "51698788284564229679463043254372678347863256931304931640625" }, // 19342813113834066795298816
                .{ .delta = 26, .cutoff = "258493941422821148397315216271863391739316284656524658203125" }, // 38685626227668133590597632
                .{ .delta = 26, .cutoff = "1292469707114105741986576081359316958696581423282623291015625" }, // 77371252455336267181195264
                .{ .delta = 27, .cutoff = "6462348535570528709932880406796584793482907116413116455078125" }, // 154742504910672534362390528
                .{ .delta = 27, .cutoff = "32311742677852643549664402033982923967414535582065582275390625" }, // 309485009821345068724781056
                .{ .delta = 27, .cutoff = "161558713389263217748322010169914619837072677910327911376953125" }, // 618970019642690137449562112
                .{ .delta = 28, .cutoff = "807793566946316088741610050849573099185363389551639556884765625" }, // 1237940039285380274899124224
                .{ .delta = 28, .cutoff = "4038967834731580443708050254247865495926816947758197784423828125" }, // 2475880078570760549798248448
                .{ .delta = 28, .cutoff = "20194839173657902218540251271239327479634084738790988922119140625" }, // 4951760157141521099596496896
                .{ .delta = 28, .cutoff = "100974195868289511092701256356196637398170423693954944610595703125" }, // 9903520314283042199192993792
                .{ .delta = 29, .cutoff = "504870979341447555463506281780983186990852118469774723052978515625" }, // 19807040628566084398385987584
                .{ .delta = 29, .cutoff = "2524354896707237777317531408904915934954260592348873615264892578125" }, // 39614081257132168796771975168
                .{ .delta = 29, .cutoff = "12621774483536188886587657044524579674771302961744368076324462890625" }, // 79228162514264337593543950336
                .{ .delta = 30, .cutoff = "63108872417680944432938285222622898373856514808721840381622314453125" }, // 158456325028528675187087900672
                .{ .delta = 30, .cutoff = "315544362088404722164691426113114491869282574043609201908111572265625" }, // 316912650057057350374175801344
                .{ .delta = 30, .cutoff = "1577721810442023610823457130565572459346412870218046009540557861328125" }, // 633825300114114700748351602688
                .{ .delta = 31, .cutoff = "7888609052210118054117285652827862296732064351090230047702789306640625" }, // 1267650600228229401496703205376
                .{ .delta = 31, .cutoff = "39443045261050590270586428264139311483660321755451150238513946533203125" }, // 2535301200456458802993406410752
                .{ .delta = 31, .cutoff = "197215226305252951352932141320696557418301608777255751192569732666015625" }, // 5070602400912917605986812821504
                .{ .delta = 32, .cutoff = "986076131526264756764660706603482787091508043886278755962848663330078125" }, // 10141204801825835211973625643008
                .{ .delta = 32, .cutoff = "4930380657631323783823303533017413935457540219431393779814243316650390625" }, // 20282409603651670423947251286016
                .{ .delta = 32, .cutoff = "24651903288156618919116517665087069677287701097156968899071216583251953125" }, // 40564819207303340847894502572032
                .{ .delta = 32, .cutoff = "123259516440783094595582588325435348386438505485784844495356082916259765625" }, // 81129638414606681695789005144064
                .{ .delta = 33, .cutoff = "616297582203915472977912941627176741932192527428924222476780414581298828125" }, // 162259276829213363391578010288128
                .{ .delta = 33, .cutoff = "3081487911019577364889564708135883709660962637144621112383902072906494140625" }, // 324518553658426726783156020576256
                .{ .delta = 33, .cutoff = "15407439555097886824447823540679418548304813185723105561919510364532470703125" }, // 649037107316853453566312041152512
                .{ .delta = 34, .cutoff = "77037197775489434122239117703397092741524065928615527809597551822662353515625" }, // 1298074214633706907132624082305024
                .{ .delta = 34, .cutoff = "385185988877447170611195588516985463707620329643077639047987759113311767578125" }, // 2596148429267413814265248164610048
                .{ .delta = 34, .cutoff = "1925929944387235853055977942584927318538101648215388195239938795566558837890625" }, // 5192296858534827628530496329220096
                .{ .delta = 35, .cutoff = "9629649721936179265279889712924636592690508241076940976199693977832794189453125" }, // 10384593717069655257060992658440192
                .{ .delta = 35, .cutoff = "48148248609680896326399448564623182963452541205384704880998469889163970947265625" }, // 20769187434139310514121985316880384
                .{ .delta = 35, .cutoff = "240741243048404481631997242823115914817262706026923524404992349445819854736328125" }, // 41538374868278621028243970633760768
                .{ .delta = 35, .cutoff = "1203706215242022408159986214115579574086313530134617622024961747229099273681640625" }, // 83076749736557242056487941267521536
                .{ .delta = 36, .cutoff = "6018531076210112040799931070577897870431567650673088110124808736145496368408203125" }, // 166153499473114484112975882535043072
                .{ .delta = 36, .cutoff = "30092655381050560203999655352889489352157838253365440550624043680727481842041015625" }, // 332306998946228968225951765070086144
                .{ .delta = 36, .cutoff = "150463276905252801019998276764447446760789191266827202753120218403637409210205078125" }, // 664613997892457936451903530140172288
                .{ .delta = 37, .cutoff = "752316384526264005099991383822237233803945956334136013765601092018187046051025390625" }, // 1329227995784915872903807060280344576
                .{ .delta = 37, .cutoff = "3761581922631320025499956919111186169019729781670680068828005460090935230255126953125" }, // 2658455991569831745807614120560689152
                .{ .delta = 37, .cutoff = "18807909613156600127499784595555930845098648908353400344140027300454676151275634765625" }, // 5316911983139663491615228241121378304
                .{ .delta = 38, .cutoff = "94039548065783000637498922977779654225493244541767001720700136502273380756378173828125" }, // 10633823966279326983230456482242756608
                .{ .delta = 38, .cutoff = "470197740328915003187494614888898271127466222708835008603500682511366903781890869140625" }, // 21267647932558653966460912964485513216
                .{ .delta = 38, .cutoff = "2350988701644575015937473074444491355637331113544175043017503412556834518909454345703125" }, // 42535295865117307932921825928971026432
                .{ .delta = 38, .cutoff = "11754943508222875079687365372222456778186655567720875215087517062784172594547271728515625" }, // 85070591730234615865843651857942052864
                .{ .delta = 39, .cutoff = "58774717541114375398436826861112283890933277838604376075437585313920862972736358642578125" }, // 170141183460469231731687303715884105728
            };

            std.debug.assert(shift < pow2_to_pow5_table.len);
            const x = pow2_to_pow5_table[shift];

            // Compare leading digits of current to check if lexicographically less than cutoff.
            for (x.cutoff, 0..) |p5, i| {
                if (i >= self.num_digits) {
                    return x.delta - 1;
                } else if (self.digits[i] == p5 - '0') { // digits are stored as integers
                    continue;
                } else if (self.digits[i] < p5 - '0') {
                    return x.delta - 1;
                } else {
                    return x.delta;
                }
                return x.delta;
            }
            return x.delta;
        }
    };
}
const std = @import("std");
const Self = @This();

// Minimum exponent that for a fast path case, or `-⌊(MANTISSA_EXPLICIT_BITS+1)/log2(5)⌋`
min_exponent_fast_path: comptime_int,

// Maximum exponent that for a fast path case, or `⌊(MANTISSA_EXPLICIT_BITS+1)/log2(5)⌋`
max_exponent_fast_path: comptime_int,

// Maximum exponent that can be represented for a disguised-fast path case.
// This is `MAX_EXPONENT_FAST_PATH + ⌊(MANTISSA_EXPLICIT_BITS+1)/log2(10)⌋`
max_exponent_fast_path_disguised: comptime_int,

// Maximum mantissa for the fast-path (`1 << 53` for f64).
max_mantissa_fast_path: comptime_int,

// Smallest decimal exponent for a non-zero value. Including subnormals.
smallest_power_of_ten: comptime_int,

// Largest decimal exponent for a non-infinite value.
largest_power_of_ten: comptime_int,

// The number of bits in the significand, *excluding* the hidden bit.
mantissa_explicit_bits: comptime_int,

// Minimum exponent value `-(1 << (EXP_BITS - 1)) + 1`.
minimum_exponent: comptime_int,

// Round-to-even only happens for negative values of q
// when q ≥ −4 in the 64-bit case and when q ≥ −17 in
// the 32-bitcase.
//
// When q ≥ 0,we have that 5^q ≤ 2m+1. In the 64-bit case,we
// have 5^q ≤ 2m+1 ≤ 2^54 or q ≤ 23. In the 32-bit case,we have
// 5^q ≤ 2m+1 ≤ 2^25 or q ≤ 10.
//
// When q < 0, we have w ≥ (2m+1)×5^−q. We must have that w < 2^64
// so (2m+1)×5^−q < 2^64. We have that 2m+1 > 2^53 (64-bit case)
// or 2m+1 > 2^24 (32-bit case). Hence,we must have 2^53×5^−q < 2^64
// (64-bit) and 2^24×5^−q < 2^64 (32-bit). Hence we have 5^−q < 2^11
// or q ≥ −4 (64-bit case) and 5^−q < 2^40 or q ≥ −17 (32-bitcase).
//
// Thus we have that we only need to round ties to even when
// we have that q ∈ [−4,23](in the 64-bit case) or q∈[−17,10]
// (in the 32-bit case). In both cases,the power of five(5^|q|)
// fits in a 64-bit word.
min_exponent_round_to_even: comptime_int,
max_exponent_round_to_even: comptime_int,

// Largest exponent value `(1 << EXP_BITS) - 1`.
infinite_power: comptime_int,

// Following should compute based on derived calculations where possible.
pub fn from(comptime T: type) Self {
    return switch (T) {
        f16 => .{
            // Fast-Path
            .min_exponent_fast_path = -4,
            .max_exponent_fast_path = 4,
            .max_exponent_fast_path_disguised = 7,
            .max_mantissa_fast_path = 2 << std.math.floatMantissaBits(T),
            // Slow + Eisel-Lemire
            .mantissa_explicit_bits = std.math.floatFractionalBits(T),
            .infinite_power = 0x1f,
            // Eisel-Lemire
            .smallest_power_of_ten = -26, // TODO: refine, fails one test
            .largest_power_of_ten = 4,
            .minimum_exponent = -15,
            // w >= (2m+1) * 5^-q and w < 2^64
            // => 2m+1 > 2^11
            // => 2^11*5^-q < 2^64
            // => 5^-q < 2^53
            // => q >= -23
            .min_exponent_round_to_even = -22,
            .max_exponent_round_to_even = 5,
        },
        f32 => .{
            // Fast-Path
            .min_exponent_fast_path = -10,
            .max_exponent_fast_path = 10,
            .max_exponent_fast_path_disguised = 17,
            .max_mantissa_fast_path = 2 << std.math.floatMantissaBits(T),
            // Slow + Eisel-Lemire
            .mantissa_explicit_bits = std.math.floatFractionalBits(T),
            .infinite_power = 0xff,
            // Eisel-Lemire
            .smallest_power_of_ten = -65,
            .largest_power_of_ten = 38,
            .minimum_exponent = -127,
            .min_exponent_round_to_even = -17,
            .max_exponent_round_to_even = 10,
        },
        f64 => .{
            // Fast-Path
            .min_exponent_fast_path = -22,
            .max_exponent_fast_path = 22,
            .max_exponent_fast_path_disguised = 37,
            .max_mantissa_fast_path = 2 << std.math.floatMantissaBits(T),
            // Slow + Eisel-Lemire
            .mantissa_explicit_bits = std.math.floatMantissaBits(T),
            .infinite_power = 0x7ff,
            // Eisel-Lemire
            .smallest_power_of_ten = -342,
            .largest_power_of_ten = 308,
            .minimum_exponent = -1023,
            .min_exponent_round_to_even = -4,
            .max_exponent_round_to_even = 23,
        },
        f80 => .{
            // Fast-Path
            .min_exponent_fast_path = -27,
            .max_exponent_fast_path = 27,
            .max_exponent_fast_path_disguised = 46,
            .max_mantissa_fast_path = 2 << std.math.floatMantissaBits(T),
            // Slow + Eisel-Lemire
            .mantissa_explicit_bits = std.math.floatFractionalBits(T),
            .infinite_power = 0x7fff,
            // Eisel-Lemire.
            // NOTE: Not yet tested (no f80 eisel-lemire implementation)
            .smallest_power_of_ten = -4966,
            .largest_power_of_ten = 4932,
            .minimum_exponent = -16382,
            // 2^65 * 5^-q < 2^80
            // 5^-q < 2^15
            // => q >= -6
            .min_exponent_round_to_even = -6,
            .max_exponent_round_to_even = 28,
        },
        f128 => .{
            // Fast-Path
            .min_exponent_fast_path = -48,
            .max_exponent_fast_path = 48,
            .max_exponent_fast_path_disguised = 82,
            .max_mantissa_fast_path = 2 << std.math.floatMantissaBits(T),
            // Slow + Eisel-Lemire
            .mantissa_explicit_bits = std.math.floatFractionalBits(T),
            .infinite_power = 0x7fff,
            // Eisel-Lemire.
            // NOTE: Not yet tested (no f128 eisel-lemire implementation)
            .smallest_power_of_ten = -4966,
            .largest_power_of_ten = 4932,
            .minimum_exponent = -16382,
            // 2^113 * 5^-q < 2^128
            // 5^-q < 2^15
            // => q >= -6
            .min_exponent_round_to_even = -6,
            .max_exponent_round_to_even = 49,
        },
        else => unreachable,
    };
}
//! A wrapper over a byte-slice, providing useful methods for parsing string floating point values.

const std = @import("std");
const FloatStream = @This();
const common = @import("common.zig");

slice: []const u8,
offset: usize,
underscore_count: usize,

pub fn init(s: []const u8) FloatStream {
    return .{ .slice = s, .offset = 0, .underscore_count = 0 };
}

// Returns the offset from the start *excluding* any underscores that were found.
pub fn offsetTrue(self: FloatStream) usize {
    return self.offset - self.underscore_count;
}

pub fn reset(self: *FloatStream) void {
    self.offset = 0;
    self.underscore_count = 0;
}

pub fn len(self: FloatStream) usize {
    if (self.offset > self.slice.len) {
        return 0;
    }
    return self.slice.len - self.offset;
}

pub fn hasLen(self: FloatStream, n: usize) bool {
    return self.offset + n <= self.slice.len;
}

pub fn firstUnchecked(self: FloatStream) u8 {
    return self.slice[self.offset];
}

pub fn first(self: FloatStream) ?u8 {
    return if (self.hasLen(1))
        return self.firstUnchecked()
    else
        null;
}

pub fn isEmpty(self: FloatStream) bool {
    return !self.hasLen(1);
}

pub fn firstIs(self: FloatStream, comptime cs: []const u8) bool {
    if (self.first()) |ok| {
        inline for (cs) |c| if (ok == c) return true;
    }
    return false;
}

pub fn firstIsLower(self: FloatStream, comptime cs: []const u8) bool {
    if (self.first()) |ok| {
        inline for (cs) |c| if (ok | 0x20 == c) return true;
    }
    return false;
}

pub fn firstIsDigit(self: FloatStream, comptime base: u8) bool {
    comptime std.debug.assert(base == 10 or base == 16);

    if (self.first()) |ok| {
        return common.isDigit(ok, base);
    }
    return false;
}

pub fn advance(self: *FloatStream, n: usize) void {
    self.offset += n;
}

pub fn skipChars(self: *FloatStream, comptime cs: []const u8) void {
    while (self.firstIs(cs)) : (self.advance(1)) {}
}

pub fn readU64Unchecked(self: FloatStream) u64 {
    return ```
