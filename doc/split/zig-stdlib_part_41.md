```
ffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn msat(out1: *[5]u64) void {
    @setRuntimeSafety(mode == .Debug);

    out1[0] = 0xbfd25e8cd0364141;
    out1[1] = 0xbaaedce6af48a03b;
    out1[2] = 0xfffffffffffffffe;
    out1[3] = 0xffffffffffffffff;
    out1[4] = 0x0;
}

/// The function divstep computes a divstep.
///
/// Preconditions:
///   0 ≤ eval arg4 < m
///   0 ≤ eval arg5 < m
/// Postconditions:
///   out1 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then 1 - arg1 else 1 + arg1)
///   twos_complement_eval out2 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then twos_complement_eval arg3 else twos_complement_eval arg2)
///   twos_complement_eval out3 = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then ⌊(twos_complement_eval arg3 - twos_complement_eval arg2) / 2⌋ else ⌊(twos_complement_eval arg3 + (twos_complement_eval arg3 mod 2) * twos_complement_eval arg2) / 2⌋)
///   eval (from_montgomery out4) mod m = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then (2 * eval (from_montgomery arg5)) mod m else (2 * eval (from_montgomery arg4)) mod m)
///   eval (from_montgomery out5) mod m = (if 0 < arg1 ∧ (twos_complement_eval arg3) is odd then (eval (from_montgomery arg4) - eval (from_montgomery arg4)) mod m else (eval (from_montgomery arg5) + (twos_complement_eval arg3 mod 2) * eval (from_montgomery arg4)) mod m)
///   0 ≤ eval out5 < m
///   0 ≤ eval out5 < m
///   0 ≤ eval out2 < m
///   0 ≤ eval out3 < m
///
/// Input Bounds:
///   arg1: [0x0 ~> 0xffffffffffffffff]
///   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn divstep(out1: *u64, out2: *[5]u64, out3: *[5]u64, out4: *[4]u64, out5: *[4]u64, arg1: u64, arg2: [5]u64, arg3: [5]u64, arg4: [4]u64, arg5: [4]u64) void {
    @setRuntimeSafety(mode == .Debug);

    var x1: u64 = undefined;
    var x2: u1 = undefined;
    addcarryxU64(&x1, &x2, 0x0, (~arg1), 0x1);
    const x3 = (@as(u1, @truncate((x1 >> 63))) & @as(u1, @truncate(((arg3[0]) & 0x1))));
    var x4: u64 = undefined;
    var x5: u1 = undefined;
    addcarryxU64(&x4, &x5, 0x0, (~arg1), 0x1);
    var x6: u64 = undefined;
    cmovznzU64(&x6, x3, arg1, x4);
    var x7: u64 = undefined;
    cmovznzU64(&x7, x3, (arg2[0]), (arg3[0]));
    var x8: u64 = undefined;
    cmovznzU64(&x8, x3, (arg2[1]), (arg3[1]));
    var x9: u64 = undefined;
    cmovznzU64(&x9, x3, (arg2[2]), (arg3[2]));
    var x10: u64 = undefined;
    cmovznzU64(&x10, x3, (arg2[3]), (arg3[3]));
    var x11: u64 = undefined;
    cmovznzU64(&x11, x3, (arg2[4]), (arg3[4]));
    var x12: u64 = undefined;
    var x13: u1 = undefined;
    addcarryxU64(&x12, &x13, 0x0, 0x1, (~(arg2[0])));
    var x14: u64 = undefined;
    var x15: u1 = undefined;
    addcarryxU64(&x14, &x15, x13, 0x0, (~(arg2[1])));
    var x16: u64 = undefined;
    var x17: u1 = undefined;
    addcarryxU64(&x16, &x17, x15, 0x0, (~(arg2[2])));
    var x18: u64 = undefined;
    var x19: u1 = undefined;
    addcarryxU64(&x18, &x19, x17, 0x0, (~(arg2[3])));
    var x20: u64 = undefined;
    var x21: u1 = undefined;
    addcarryxU64(&x20, &x21, x19, 0x0, (~(arg2[4])));
    var x22: u64 = undefined;
    cmovznzU64(&x22, x3, (arg3[0]), x12);
    var x23: u64 = undefined;
    cmovznzU64(&x23, x3, (arg3[1]), x14);
    var x24: u64 = undefined;
    cmovznzU64(&x24, x3, (arg3[2]), x16);
    var x25: u64 = undefined;
    cmovznzU64(&x25, x3, (arg3[3]), x18);
    var x26: u64 = undefined;
    cmovznzU64(&x26, x3, (arg3[4]), x20);
    var x27: u64 = undefined;
    cmovznzU64(&x27, x3, (arg4[0]), (arg5[0]));
    var x28: u64 = undefined;
    cmovznzU64(&x28, x3, (arg4[1]), (arg5[1]));
    var x29: u64 = undefined;
    cmovznzU64(&x29, x3, (arg4[2]), (arg5[2]));
    var x30: u64 = undefined;
    cmovznzU64(&x30, x3, (arg4[3]), (arg5[3]));
    var x31: u64 = undefined;
    var x32: u1 = undefined;
    addcarryxU64(&x31, &x32, 0x0, x27, x27);
    var x33: u64 = undefined;
    var x34: u1 = undefined;
    addcarryxU64(&x33, &x34, x32, x28, x28);
    var x35: u64 = undefined;
    var x36: u1 = undefined;
    addcarryxU64(&x35, &x36, x34, x29, x29);
    var x37: u64 = undefined;
    var x38: u1 = undefined;
    addcarryxU64(&x37, &x38, x36, x30, x30);
    var x39: u64 = undefined;
    var x40: u1 = undefined;
    subborrowxU64(&x39, &x40, 0x0, x31, 0xbfd25e8cd0364141);
    var x41: u64 = undefined;
    var x42: u1 = undefined;
    subborrowxU64(&x41, &x42, x40, x33, 0xbaaedce6af48a03b);
    var x43: u64 = undefined;
    var x44: u1 = undefined;
    subborrowxU64(&x43, &x44, x42, x35, 0xfffffffffffffffe);
    var x45: u64 = undefined;
    var x46: u1 = undefined;
    subborrowxU64(&x45, &x46, x44, x37, 0xffffffffffffffff);
    var x47: u64 = undefined;
    var x48: u1 = undefined;
    subborrowxU64(&x47, &x48, x46, @as(u64, x38), 0x0);
    const x49 = (arg4[3]);
    const x50 = (arg4[2]);
    const x51 = (arg4[1]);
    const x52 = (arg4[0]);
    var x53: u64 = undefined;
    var x54: u1 = undefined;
    subborrowxU64(&x53, &x54, 0x0, 0x0, x52);
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    subborrowxU64(&x55, &x56, x54, 0x0, x51);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    subborrowxU64(&x57, &x58, x56, 0x0, x50);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    subborrowxU64(&x59, &x60, x58, 0x0, x49);
    var x61: u64 = undefined;
    cmovznzU64(&x61, x60, 0x0, 0xffffffffffffffff);
    var x62: u64 = undefined;
    var x63: u1 = undefined;
    addcarryxU64(&x62, &x63, 0x0, x53, (x61 & 0xbfd25e8cd0364141));
    var x64: u64 = undefined;
    var x65: u1 = undefined;
    addcarryxU64(&x64, &x65, x63, x55, (x61 & 0xbaaedce6af48a03b));
    var x66: u64 = undefined;
    var x67: u1 = undefined;
    addcarryxU64(&x66, &x67, x65, x57, (x61 & 0xfffffffffffffffe));
    var x68: u64 = undefined;
    var x69: u1 = undefined;
    addcarryxU64(&x68, &x69, x67, x59, x61);
    var x70: u64 = undefined;
    cmovznzU64(&x70, x3, (arg5[0]), x62);
    var x71: u64 = undefined;
    cmovznzU64(&x71, x3, (arg5[1]), x64);
    var x72: u64 = undefined;
    cmovznzU64(&x72, x3, (arg5[2]), x66);
    var x73: u64 = undefined;
    cmovznzU64(&x73, x3, (arg5[3]), x68);
    const x74 = @as(u1, @truncate((x22 & 0x1)));
    var x75: u64 = undefined;
    cmovznzU64(&x75, x74, 0x0, x7);
    var x76: u64 = undefined;
    cmovznzU64(&x76, x74, 0x0, x8);
    var x77: u64 = undefined;
    cmovznzU64(&x77, x74, 0x0, x9);
    var x78: u64 = undefined;
    cmovznzU64(&x78, x74, 0x0, x10);
    var x79: u64 = undefined;
    cmovznzU64(&x79, x74, 0x0, x11);
    var x80: u64 = undefined;
    var x81: u1 = undefined;
    addcarryxU64(&x80, &x81, 0x0, x22, x75);
    var x82: u64 = undefined;
    var x83: u1 = undefined;
    addcarryxU64(&x82, &x83, x81, x23, x76);
    var x84: u64 = undefined;
    var x85: u1 = undefined;
    addcarryxU64(&x84, &x85, x83, x24, x77);
    var x86: u64 = undefined;
    var x87: u1 = undefined;
    addcarryxU64(&x86, &x87, x85, x25, x78);
    var x88: u64 = undefined;
    var x89: u1 = undefined;
    addcarryxU64(&x88, &x89, x87, x26, x79);
    var x90: u64 = undefined;
    cmovznzU64(&x90, x74, 0x0, x27);
    var x91: u64 = undefined;
    cmovznzU64(&x91, x74, 0x0, x28);
    var x92: u64 = undefined;
    cmovznzU64(&x92, x74, 0x0, x29);
    var x93: u64 = undefined;
    cmovznzU64(&x93, x74, 0x0, x30);
    var x94: u64 = undefined;
    var x95: u1 = undefined;
    addcarryxU64(&x94, &x95, 0x0, x70, x90);
    var x96: u64 = undefined;
    var x97: u1 = undefined;
    addcarryxU64(&x96, &x97, x95, x71, x91);
    var x98: u64 = undefined;
    var x99: u1 = undefined;
    addcarryxU64(&x98, &x99, x97, x72, x92);
    var x100: u64 = undefined;
    var x101: u1 = undefined;
    addcarryxU64(&x100, &x101, x99, x73, x93);
    var x102: u64 = undefined;
    var x103: u1 = undefined;
    subborrowxU64(&x102, &x103, 0x0, x94, 0xbfd25e8cd0364141);
    var x104: u64 = undefined;
    var x105: u1 = undefined;
    subborrowxU64(&x104, &x105, x103, x96, 0xbaaedce6af48a03b);
    var x106: u64 = undefined;
    var x107: u1 = undefined;
    subborrowxU64(&x106, &x107, x105, x98, 0xfffffffffffffffe);
    var x108: u64 = undefined;
    var x109: u1 = undefined;
    subborrowxU64(&x108, &x109, x107, x100, 0xffffffffffffffff);
    var x110: u64 = undefined;
    var x111: u1 = undefined;
    subborrowxU64(&x110, &x111, x109, @as(u64, x101), 0x0);
    var x112: u64 = undefined;
    var x113: u1 = undefined;
    addcarryxU64(&x112, &x113, 0x0, x6, 0x1);
    const x114 = ((x80 >> 1) | ((x82 << 63) & 0xffffffffffffffff));
    const x115 = ((x82 >> 1) | ((x84 << 63) & 0xffffffffffffffff));
    const x116 = ((x84 >> 1) | ((x86 << 63) & 0xffffffffffffffff));
    const x117 = ((x86 >> 1) | ((x88 << 63) & 0xffffffffffffffff));
    const x118 = ((x88 & 0x8000000000000000) | (x88 >> 1));
    var x119: u64 = undefined;
    cmovznzU64(&x119, x48, x39, x31);
    var x120: u64 = undefined;
    cmovznzU64(&x120, x48, x41, x33);
    var x121: u64 = undefined;
    cmovznzU64(&x121, x48, x43, x35);
    var x122: u64 = undefined;
    cmovznzU64(&x122, x48, x45, x37);
    var x123: u64 = undefined;
    cmovznzU64(&x123, x111, x102, x94);
    var x124: u64 = undefined;
    cmovznzU64(&x124, x111, x104, x96);
    var x125: u64 = undefined;
    cmovznzU64(&x125, x111, x106, x98);
    var x126: u64 = undefined;
    cmovznzU64(&x126, x111, x108, x100);
    out1.* = x112;
    out2[0] = x7;
    out2[1] = x8;
    out2[2] = x9;
    out2[3] = x10;
    out2[4] = x11;
    out3[0] = x114;
    out3[1] = x115;
    out3[2] = x116;
    out3[3] = x117;
    out3[4] = x118;
    out4[0] = x119;
    out4[1] = x120;
    out4[2] = x121;
    out4[3] = x122;
    out5[0] = x123;
    out5[1] = x124;
    out5[2] = x125;
    out5[3] = x126;
}

/// The function divstepPrecomp returns the precomputed value for Bernstein-Yang-inversion (in montgomery form).
///
/// Postconditions:
///   eval (from_montgomery out1) = ⌊(m - 1) / 2⌋^(if ⌊log2 m⌋ + 1 < 46 then ⌊(49 * (⌊log2 m⌋ + 1) + 80) / 17⌋ else ⌊(49 * (⌊log2 m⌋ + 1) + 57) / 17⌋)
///   0 ≤ eval out1 < m
///
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn divstepPrecomp(out1: *[4]u64) void {
    @setRuntimeSafety(mode == .Debug);

    out1[0] = 0xd7431a4d2b9cb4e9;
    out1[1] = 0xab67d35a32d9c503;
    out1[2] = 0xadf6c7e5859ce35f;
    out1[3] = 0x615441451df6c379;
}
const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

const P256 = @import("../p256.zig").P256;

test "p256 ECDH key exchange" {
    const dha = P256.scalar.random(.little);
    const dhb = P256.scalar.random(.little);
    const dhA = try P256.basePoint.mul(dha, .little);
    const dhB = try P256.basePoint.mul(dhb, .little);
    const shareda = try dhA.mul(dhb, .little);
    const sharedb = try dhB.mul(dha, .little);
    try testing.expect(shareda.equivalent(sharedb));
}

test "p256 point from affine coordinates" {
    const xh = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    const yh = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
    var xs: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&xs, xh);
    var ys: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&ys, yh);
    var p = try P256.fromSerializedAffineCoordinates(xs, ys, .big);
    try testing.expect(p.equivalent(P256.basePoint));
}

test "p256 test vectors" {
    const expected = [_][]const u8{
        "0000000000000000000000000000000000000000000000000000000000000000",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
        "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
        "51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed",
        "b01a172a76a4602c92d3242cb897dde3024c740debb215b4c6b0aae93c2291a9",
        "8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3",
        "62d9779dbee9b0534042742d3ab54cadc1d238980fce97dbb4dd9dc1db6fb393",
        "ea68d7b6fedf0b71878938d51d71f8729e0acb8c2c6df8b3d79e8a4b90949ee0",
    };
    var p = P256.identityElement;
    for (expected) |xh| {
        const x = p.affineCoordinates().x;
        p = p.add(P256.basePoint);
        var xs: [32]u8 = undefined;
        _ = try fmt.hexToBytes(&xs, xh);
        try testing.expectEqualSlices(u8, &x.toBytes(.big), &xs);
    }
}

test "p256 test vectors - doubling" {
    const expected = [_][]const u8{
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
        "62d9779dbee9b0534042742d3ab54cadc1d238980fce97dbb4dd9dc1db6fb393",
    };
    var p = P256.basePoint;
    for (expected) |xh| {
        const x = p.affineCoordinates().x;
        p = p.dbl();
        var xs: [32]u8 = undefined;
        _ = try fmt.hexToBytes(&xs, xh);
        try testing.expectEqualSlices(u8, &x.toBytes(.big), &xs);
    }
}

test "p256 compressed sec1 encoding/decoding" {
    const p = P256.random();
    const s = p.toCompressedSec1();
    const q = try P256.fromSec1(&s);
    try testing.expect(p.equivalent(q));
}

test "p256 uncompressed sec1 encoding/decoding" {
    const p = P256.random();
    const s = p.toUncompressedSec1();
    const q = try P256.fromSec1(&s);
    try testing.expect(p.equivalent(q));
}

test "p256 public key is the neutral element" {
    const n = P256.scalar.Scalar.zero.toBytes(.little);
    const p = P256.random();
    try testing.expectError(error.IdentityElement, p.mul(n, .little));
}

test "p256 public key is the neutral element (public verification)" {
    const n = P256.scalar.Scalar.zero.toBytes(.little);
    const p = P256.random();
    try testing.expectError(error.IdentityElement, p.mulPublic(n, .little));
}

test "p256 field element non-canonical encoding" {
    const s = [_]u8{0xff} ** 32;
    try testing.expectError(error.NonCanonical, P256.Fe.fromBytes(s, .little));
}

test "p256 neutral element decoding" {
    try testing.expectError(error.InvalidEncoding, P256.fromAffineCoordinates(.{ .x = P256.Fe.zero, .y = P256.Fe.zero }));
    const p = try P256.fromAffineCoordinates(.{ .x = P256.Fe.zero, .y = P256.Fe.one });
    try testing.expectError(error.IdentityElement, p.rejectIdentity());
}

test "p256 double base multiplication" {
    const p1 = P256.basePoint;
    const p2 = P256.basePoint.dbl();
    const s1 = [_]u8{0x01} ** 32;
    const s2 = [_]u8{0x02} ** 32;
    const pr1 = try P256.mulDoubleBasePublic(p1, s1, p2, s2, .little);
    const pr2 = (try p1.mul(s1, .little)).add(try p2.mul(s2, .little));
    try testing.expect(pr1.equivalent(pr2));
}

test "p256 double base multiplication with large scalars" {
    const p1 = P256.basePoint;
    const p2 = P256.basePoint.dbl();
    const s1 = [_]u8{0xee} ** 32;
    const s2 = [_]u8{0xdd} ** 32;
    const pr1 = try P256.mulDoubleBasePublic(p1, s1, p2, s2, .little);
    const pr2 = (try p1.mul(s1, .little)).add(try p2.mul(s2, .little));
    try testing.expect(pr1.equivalent(pr2));
}

test "p256 scalar inverse" {
    const expected = "3b549196a13c898a6f6e84dfb3a22c40a8b9b17fb88e408ea674e451cd01d0a6";
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, expected);

    const scalar = try P256.scalar.Scalar.fromBytes(.{
        0x94, 0xa1, 0xbb, 0xb1, 0x4b, 0x90, 0x6a, 0x61, 0xa2, 0x80, 0xf2, 0x45, 0xf9, 0xe9, 0x3c, 0x7f,
        0x3b, 0x4a, 0x62, 0x47, 0x82, 0x4f, 0x5d, 0x33, 0xb9, 0x67, 0x07, 0x87, 0x64, 0x2a, 0x68, 0xde,
    }, .big);
    const inverse = scalar.invert();
    try std.testing.expectEqualSlices(u8, &out, &inverse.toBytes(.big));
}

test "p256 scalar parity" {
    try std.testing.expect(P256.scalar.Scalar.zero.isOdd() == false);
    try std.testing.expect(P256.scalar.Scalar.one.isOdd());
    try std.testing.expect(P256.scalar.Scalar.one.dbl().isOdd() == false);
}
const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

const P384 = @import("../p384.zig").P384;

test "p384 ECDH key exchange" {
    const dha = P384.scalar.random(.little);
    const dhb = P384.scalar.random(.little);
    const dhA = try P384.basePoint.mul(dha, .little);
    const dhB = try P384.basePoint.mul(dhb, .little);
    const shareda = try dhA.mul(dhb, .little);
    const sharedb = try dhB.mul(dha, .little);
    try testing.expect(shareda.equivalent(sharedb));
}

test "p384 point from affine coordinates" {
    const xh = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
    const yh = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
    var xs: [48]u8 = undefined;
    _ = try fmt.hexToBytes(&xs, xh);
    var ys: [48]u8 = undefined;
    _ = try fmt.hexToBytes(&ys, yh);
    var p = try P384.fromSerializedAffineCoordinates(xs, ys, .big);
    try testing.expect(p.equivalent(P384.basePoint));
}

test "p384 test vectors" {
    const expected = [_][]const u8{
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "08D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
        "077A41D4606FFA1464793C7E5FDC7D98CB9D3910202DCD06BEA4F240D3566DA6B408BBAE5026580D02D7E5C70500C831",
        "138251CD52AC9298C1C8AAD977321DEB97E709BD0B4CA0ACA55DC8AD51DCFC9D1589A1597E3A5120E1EFD631C63E1835",
        "11DE24A2C251C777573CAC5EA025E467F208E51DBFF98FC54F6661CBE56583B037882F4A1CA297E60ABCDBC3836D84BC",
        "627BE1ACD064D2B2226FE0D26F2D15D3C33EBCBB7F0F5DA51CBD41F26257383021317D7202FF30E50937F0854E35C5DF",
        "283C1D7365CE4788F29F8EBF234EDFFEAD6FE997FBEA5FFA2D58CC9DFA7B1C508B05526F55B9EBB2040F05B48FB6D0E1",
        "1692778EA596E0BE75114297A6FA383445BF227FBE58190A900C3C73256F11FB5A3258D6F403D5ECE6E9B269D822C87D",
        "8F0A39A4049BCB3EF1BF29B8B025B78F2216F7291E6FD3BAC6CB1EE285FB6E21C388528BFEE2B9535C55E4461079118B",
        "A669C5563BD67EEC678D29D6EF4FDE864F372D90B79B9E88931D5C29291238CCED8E85AB507BF91AA9CB2D13186658FB",
    };
    var p = P384.identityElement;
    for (expected) |xh| {
        const x = p.affineCoordinates().x;
        p = p.add(P384.basePoint);
        var xs: [48]u8 = undefined;
        _ = try fmt.hexToBytes(&xs, xh);
        try testing.expectEqualSlices(u8, &x.toBytes(.big), &xs);
    }
}

test "p384 test vectors - doubling" {
    const expected = [_][]const u8{
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "08D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
        "138251CD52AC9298C1C8AAD977321DEB97E709BD0B4CA0ACA55DC8AD51DCFC9D1589A1597E3A5120E1EFD631C63E1835",
        "1692778EA596E0BE75114297A6FA383445BF227FBE58190A900C3C73256F11FB5A3258D6F403D5ECE6E9B269D822C87D",
    };
    var p = P384.basePoint;
    for (expected) |xh| {
        const x = p.affineCoordinates().x;
        p = p.dbl();
        var xs: [48]u8 = undefined;
        _ = try fmt.hexToBytes(&xs, xh);
        try testing.expectEqualSlices(u8, &x.toBytes(.big), &xs);
    }
}

test "p384 compressed sec1 encoding/decoding" {
    const p = P384.random();
    const s0 = p.toUncompressedSec1();
    const s = p.toCompressedSec1();
    try testing.expectEqualSlices(u8, s0[1..49], s[1..49]);
    const q = try P384.fromSec1(&s);
    try testing.expect(p.equivalent(q));
}

test "p384 uncompressed sec1 encoding/decoding" {
    const p = P384.random();
    const s = p.toUncompressedSec1();
    const q = try P384.fromSec1(&s);
    try testing.expect(p.equivalent(q));
}

test "p384 public key is the neutral element" {
    const n = P384.scalar.Scalar.zero.toBytes(.little);
    const p = P384.random();
    try testing.expectError(error.IdentityElement, p.mul(n, .little));
}

test "p384 public key is the neutral element (public verification)" {
    const n = P384.scalar.Scalar.zero.toBytes(.little);
    const p = P384.random();
    try testing.expectError(error.IdentityElement, p.mulPublic(n, .little));
}

test "p384 field element non-canonical encoding" {
    const s = [_]u8{0xff} ** 48;
    try testing.expectError(error.NonCanonical, P384.Fe.fromBytes(s, .little));
}

test "p384 neutral element decoding" {
    try testing.expectError(error.InvalidEncoding, P384.fromAffineCoordinates(.{ .x = P384.Fe.zero, .y = P384.Fe.zero }));
    const p = try P384.fromAffineCoordinates(.{ .x = P384.Fe.zero, .y = P384.Fe.one });
    try testing.expectError(error.IdentityElement, p.rejectIdentity());
}

test "p384 double base multiplication" {
    const p1 = P384.basePoint;
    const p2 = P384.basePoint.dbl();
    const s1 = [_]u8{0x01} ** 48;
    const s2 = [_]u8{0x02} ** 48;
    const pr1 = try P384.mulDoubleBasePublic(p1, s1, p2, s2, .little);
    const pr2 = (try p1.mul(s1, .little)).add(try p2.mul(s2, .little));
    try testing.expect(pr1.equivalent(pr2));
}

test "p384 double base multiplication with large scalars" {
    const p1 = P384.basePoint;
    const p2 = P384.basePoint.dbl();
    const s1 = [_]u8{0xee} ** 48;
    const s2 = [_]u8{0xdd} ** 48;
    const pr1 = try P384.mulDoubleBasePublic(p1, s1, p2, s2, .little);
    const pr2 = (try p1.mul(s1, .little)).add(try p2.mul(s2, .little));
    try testing.expect(pr1.equivalent(pr2));
}

test "p384 scalar inverse" {
    const expected = "a3cc705f33b5679a66e76ce66e68055c927c5dba531b2837b18fe86119511091b54d733f26b2e7a0f6fa2e7ea21ca806";
    var out: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, expected);

    const scalar = try P384.scalar.Scalar.fromBytes(.{
        0x94, 0xa1, 0xbb, 0xb1, 0x4b, 0x90, 0x6a, 0x61, 0xa2, 0x80, 0xf2, 0x45, 0xf9, 0xe9, 0x3c, 0x7f,
        0x3b, 0x4a, 0x62, 0x47, 0x82, 0x4f, 0x5d, 0x33, 0xb9, 0x67, 0x07, 0x87, 0x64, 0x2a, 0x68, 0xde,
        0x38, 0x36, 0xe8, 0x0f, 0xa2, 0x84, 0x6b, 0x4e, 0xf3, 0x9a, 0x02, 0x31, 0x24, 0x41, 0x22, 0xca,
    }, .big);
    const inverse = scalar.invert();
    const inverse2 = inverse.invert();
    try testing.expectEqualSlices(u8, &out, &inverse.toBytes(.big));
    try testing.expect(inverse2.equivalent(scalar));

    const sq = scalar.sq();
    const sqr = try sq.sqrt();
    try testing.expect(sqr.equivalent(scalar));
}

test "p384 scalar parity" {
    try std.testing.expect(P384.scalar.Scalar.zero.isOdd() == false);
    try std.testing.expect(P384.scalar.Scalar.one.isOdd());
    try std.testing.expect(P384.scalar.Scalar.one.dbl().isOdd() == false);
}
const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

const Secp256k1 = @import("../secp256k1.zig").Secp256k1;

test "secp256k1 ECDH key exchange" {
    const dha = Secp256k1.scalar.random(.little);
    const dhb = Secp256k1.scalar.random(.little);
    const dhA = try Secp256k1.basePoint.mul(dha, .little);
    const dhB = try Secp256k1.basePoint.mul(dhb, .little);
    const shareda = try dhA.mul(dhb, .little);
    const sharedb = try dhB.mul(dha, .little);
    try testing.expect(shareda.equivalent(sharedb));
}

test "secp256k1 ECDH key exchange including public multiplication" {
    const dha = Secp256k1.scalar.random(.little);
    const dhb = Secp256k1.scalar.random(.little);
    const dhA = try Secp256k1.basePoint.mul(dha, .little);
    const dhB = try Secp256k1.basePoint.mulPublic(dhb, .little);
    const shareda = try dhA.mul(dhb, .little);
    const sharedb = try dhB.mulPublic(dha, .little);
    try testing.expect(shareda.equivalent(sharedb));
}

test "secp256k1 point from affine coordinates" {
    const xh = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const yh = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    var xs: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&xs, xh);
    var ys: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&ys, yh);
    var p = try Secp256k1.fromSerializedAffineCoordinates(xs, ys, .big);
    try testing.expect(p.equivalent(Secp256k1.basePoint));
}

test "secp256k1 test vectors" {
    const expected = [_][]const u8{
        "0000000000000000000000000000000000000000000000000000000000000000",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
        "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
        "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
        "2f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
        "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
    };
    var p = Secp256k1.identityElement;
    for (expected) |xh| {
        const x = p.affineCoordinates().x;
        p = p.add(Secp256k1.basePoint);
        var xs: [32]u8 = undefined;
        _ = try fmt.hexToBytes(&xs, xh);
        try testing.expectEqualSlices(u8, &x.toBytes(.big), &xs);
    }
}

test "secp256k1 test vectors - doubling" {
    const expected = [_][]const u8{
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
        "2f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
        "e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
    };
    var p = Secp256k1.basePoint;
    for (expected) |xh| {
        const x = p.affineCoordinates().x;
        p = p.dbl();
        var xs: [32]u8 = undefined;
        _ = try fmt.hexToBytes(&xs, xh);
        try testing.expectEqualSlices(u8, &x.toBytes(.big), &xs);
    }
}

test "secp256k1 compressed sec1 encoding/decoding" {
    const p = Secp256k1.random();
    const s = p.toCompressedSec1();
    const q = try Secp256k1.fromSec1(&s);
    try testing.expect(p.equivalent(q));
}

test "secp256k1 uncompressed sec1 encoding/decoding" {
    const p = Secp256k1.random();
    const s = p.toUncompressedSec1();
    const q = try Secp256k1.fromSec1(&s);
    try testing.expect(p.equivalent(q));
}

test "secp256k1 public key is the neutral element" {
    const n = Secp256k1.scalar.Scalar.zero.toBytes(.little);
    const p = Secp256k1.random();
    try testing.expectError(error.IdentityElement, p.mul(n, .little));
}

test "secp256k1 public key is the neutral element (public verification)" {
    const n = Secp256k1.scalar.Scalar.zero.toBytes(.little);
    const p = Secp256k1.random();
    try testing.expectError(error.IdentityElement, p.mulPublic(n, .little));
}

test "secp256k1 field element non-canonical encoding" {
    const s = [_]u8{0xff} ** 32;
    try testing.expectError(error.NonCanonical, Secp256k1.Fe.fromBytes(s, .little));
}

test "secp256k1 neutral element decoding" {
    try testing.expectError(error.InvalidEncoding, Secp256k1.fromAffineCoordinates(.{ .x = Secp256k1.Fe.zero, .y = Secp256k1.Fe.zero }));
    const p = try Secp256k1.fromAffineCoordinates(.{ .x = Secp256k1.Fe.zero, .y = Secp256k1.Fe.one });
    try testing.expectError(error.IdentityElement, p.rejectIdentity());
}

test "secp256k1 double base multiplication" {
    const p1 = Secp256k1.basePoint;
    const p2 = Secp256k1.basePoint.dbl();
    const s1 = [_]u8{0x01} ** 32;
    const s2 = [_]u8{0x02} ** 32;
    const pr1 = try Secp256k1.mulDoubleBasePublic(p1, s1, p2, s2, .little);
    const pr2 = (try p1.mul(s1, .little)).add(try p2.mul(s2, .little));
    try testing.expect(pr1.equivalent(pr2));
}

test "secp256k1 scalar inverse" {
    const expected = "08d0684a0fe8ea978b68a29e4b4ffdbd19eeb59db25301cf23ecbe568e1f9822";
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, expected);

    const scalar = try Secp256k1.scalar.Scalar.fromBytes(.{
        0x94, 0xa1, 0xbb, 0xb1, 0x4b, 0x90, 0x6a, 0x61, 0xa2, 0x80, 0xf2, 0x45, 0xf9, 0xe9, 0x3c, 0x7f,
        0x3b, 0x4a, 0x62, 0x47, 0x82, 0x4f, 0x5d, 0x33, 0xb9, 0x67, 0x07, 0x87, 0x64, 0x2a, 0x68, 0xde,
    }, .big);
    const inverse = scalar.invert();
    try std.testing.expectEqualSlices(u8, &out, &inverse.toBytes(.big));
}

test "secp256k1 scalar parity" {
    try std.testing.expect(Secp256k1.scalar.Scalar.zero.isOdd() == false);
    try std.testing.expect(Secp256k1.scalar.Scalar.one.isOdd());
    try std.testing.expect(Secp256k1.scalar.Scalar.one.dbl().isOdd() == false);
}
// https://github.com/P-H-C/phc-string-format

const std = @import("std");
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const meta = std.meta;

const fields_delimiter = "$";
const fields_delimiter_scalar = '$';
const version_param_name = "v";
const params_delimiter = ",";
const params_delimiter_scalar = ',';
const kv_delimiter = "=";
const kv_delimiter_scalar = '=';

pub const Error = std.crypto.errors.EncodingError || error{NoSpaceLeft};

const B64Decoder = std.base64.standard_no_pad.Decoder;
const B64Encoder = std.base64.standard_no_pad.Encoder;

/// A wrapped binary value whose maximum size is `max_len`.
///
/// This type must be used whenever a binary value is encoded in a PHC-formatted string.
/// This includes `salt`, `hash`, and any other binary parameters such as keys.
///
/// Once initialized, the actual value can be read with the `constSlice()` function.
pub fn BinValue(comptime max_len: usize) type {
    return struct {
        const Self = @This();
        const capacity = max_len;
        const max_encoded_length = B64Encoder.calcSize(max_len);

        buf: [max_len]u8 = undefined,
        len: usize = 0,

        /// Wrap an existing byte slice
        pub fn fromSlice(slice: []const u8) Error!Self {
            if (slice.len > capacity) return Error.NoSpaceLeft;
            var bin_value: Self = undefined;
            @memcpy(bin_value.buf[0..slice.len], slice);
            bin_value.len = slice.len;
            return bin_value;
        }

        /// Return the slice containing the actual value.
        pub fn constSlice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn fromB64(self: *Self, str: []const u8) !void {
            const len = B64Decoder.calcSizeForSlice(str) catch return Error.InvalidEncoding;
            if (len > self.buf.len) return Error.NoSpaceLeft;
            B64Decoder.decode(&self.buf, str) catch return Error.InvalidEncoding;
            self.len = len;
        }

        fn toB64(self: *const Self, buf: []u8) ![]const u8 {
            const value = self.constSlice();
            const len = B64Encoder.calcSize(value.len);
            if (len > buf.len) return Error.NoSpaceLeft;
            return B64Encoder.encode(buf, value);
        }
    };
}

/// Deserialize a PHC-formatted string into a structure `HashResult`.
///
/// Required field in the `HashResult` structure:
///   - `alg_id`: algorithm identifier
/// Optional, special fields:
///   - `alg_version`: algorithm version (unsigned integer)
///   - `salt`: salt
///   - `hash`: output of the hash function
///
/// Other fields will also be deserialized from the function parameters section.
pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult {
    if (@hasField(HashResult, version_param_name)) {
        @compileError("Field name '" ++ version_param_name ++ "'' is reserved for the algorithm version");
    }

    var out = mem.zeroes(HashResult);
    var it = mem.splitScalar(u8, str, fields_delimiter_scalar);
    var set_fields: usize = 0;

    while (true) {
        // Read the algorithm identifier
        if ((it.next() orelse return Error.InvalidEncoding).len != 0) return Error.InvalidEncoding;
        out.alg_id = it.next() orelse return Error.InvalidEncoding;
        set_fields += 1;

        // Read the optional version number
        var field = it.next() orelse break;
        if (kvSplit(field)) |opt_version| {
            if (mem.eql(u8, opt_version.key, version_param_name)) {
                if (@hasField(HashResult, "alg_version")) {
                    const value_type_info = switch (@typeInfo(@TypeOf(out.alg_version))) {
                        .optional => |opt| @typeInfo(opt.child),
                        else => |t| t,
                    };
                    out.alg_version = fmt.parseUnsigned(
                        @Type(value_type_info),
                        opt_version.value,
                        10,
                    ) catch return Error.InvalidEncoding;
                    set_fields += 1;
                }
                field = it.next() orelse break;
            }
        } else |_| {}

        // Read optional parameters
        var has_params = false;
        var it_params = mem.splitScalar(u8, field, params_delimiter_scalar);
        while (it_params.next()) |params| {
            const param = kvSplit(params) catch break;
            var found = false;
            inline for (comptime meta.fields(HashResult)) |p| {
                if (mem.eql(u8, p.name, param.key)) {
                    switch (@typeInfo(p.type)) {
                        .int => @field(out, p.name) = fmt.parseUnsigned(
                            p.type,
                            param.value,
                            10,
                        ) catch return Error.InvalidEncoding,
                        .pointer => |ptr| {
                            if (!ptr.is_const) @compileError("Value slice must be constant");
                            @field(out, p.name) = param.value;
                        },
                        .@"struct" => try @field(out, p.name).fromB64(param.value),
                        else => std.debug.panic(
                            "Value for [{s}] must be an integer, a constant slice or a BinValue",
                            .{p.name},
                        ),
                    }
                    set_fields += 1;
                    found = true;
                    break;
                }
            }
            if (!found) return Error.InvalidEncoding; // An unexpected parameter was found in the string
            has_params = true;
        }

        // No separator between an empty parameters set and the salt
        if (has_params) field = it.next() orelse break;

        // Read an optional salt
        if (@hasField(HashResult, "salt")) {
            try out.salt.fromB64(field);
            set_fields += 1;
        } else {
            return Error.InvalidEncoding;
        }

        // Read an optional hash
        field = it.next() orelse break;
        if (@hasField(HashResult, "hash")) {
            try out.hash.fromB64(field);
            set_fields += 1;
        } else {
            return Error.InvalidEncoding;
        }
        break;
    }

    // Check that all the required fields have been set, excluding optional values and parameters
    // with default values
    var expected_fields: usize = 0;
    inline for (comptime meta.fields(HashResult)) |p| {
        if (@typeInfo(p.type) != .optional and p.default_value_ptr == null) {
            expected_fields += 1;
        }
    }
    if (set_fields < expected_fields) return Error.InvalidEncoding;

    return out;
}

/// Serialize parameters into a PHC string.
///
/// Required field for `params`:
///   - `alg_id`: algorithm identifier
/// Optional, special fields:
///   - `alg_version`: algorithm version (unsigned integer)
///   - `salt`: salt
///   - `hash`: output of the hash function
///
/// `params` can also include any additional parameters.
pub fn serialize(params: anytype, str: []u8) Error![]const u8 {
    var buf = io.fixedBufferStream(str);
    try serializeTo(params, buf.writer());
    return buf.getWritten();
}

/// Compute the number of bytes required to serialize `params`
pub fn calcSize(params: anytype) usize {
    var buf = io.countingWriter(io.null_writer);
    serializeTo(params, buf.writer()) catch unreachable;
    return @as(usize, @intCast(buf.bytes_written));
}

fn serializeTo(params: anytype, out: anytype) !void {
    const HashResult = @TypeOf(params);

    if (@hasField(HashResult, version_param_name)) {
        @compileError("Field name '" ++ version_param_name ++ "'' is reserved for the algorithm version");
    }

    try out.writeAll(fields_delimiter);
    try out.writeAll(params.alg_id);

    if (@hasField(HashResult, "alg_version")) {
        if (@typeInfo(@TypeOf(params.alg_version)) == .optional) {
            if (params.alg_version) |alg_version| {
                try out.print(
                    "{s}{s}{s}{}",
                    .{ fields_delimiter, version_param_name, kv_delimiter, alg_version },
                );
            }
        } else {
            try out.print(
                "{s}{s}{s}{}",
                .{ fields_delimiter, version_param_name, kv_delimiter, params.alg_version },
            );
        }
    }

    var has_params = false;
    inline for (comptime meta.fields(HashResult)) |p| {
        if (comptime !(mem.eql(u8, p.name, "alg_id") or
            mem.eql(u8, p.name, "alg_version") or
            mem.eql(u8, p.name, "hash") or
            mem.eql(u8, p.name, "salt")))
        {
            const value = @field(params, p.name);
            try out.writeAll(if (has_params) params_delimiter else fields_delimiter);
            if (@typeInfo(p.type) == .@"struct") {
                var buf: [@TypeOf(value).max_encoded_length]u8 = undefined;
                try out.print("{s}{s}{s}", .{ p.name, kv_delimiter, try value.toB64(&buf) });
            } else {
                try out.print(
                    if (@typeInfo(@TypeOf(value)) == .pointer) "{s}{s}{s}" else "{s}{s}{}",
                    .{ p.name, kv_delimiter, value },
                );
            }
            has_params = true;
        }
    }

    var has_salt = false;
    if (@hasField(HashResult, "salt")) {
        var buf: [@TypeOf(params.salt).max_encoded_length]u8 = undefined;
        try out.print("{s}{s}", .{ fields_delimiter, try params.salt.toB64(&buf) });
        has_salt = true;
    }

    if (@hasField(HashResult, "hash")) {
        var buf: [@TypeOf(params.hash).max_encoded_length]u8 = undefined;
        if (!has_salt) try out.writeAll(fields_delimiter);
        try out.print("{s}{s}", .{ fields_delimiter, try params.hash.toB64(&buf) });
    }
}

// Split a `key=value` string into `key` and `value`
fn kvSplit(str: []const u8) !struct { key: []const u8, value: []const u8 } {
    var it = mem.splitScalar(u8, str, kv_delimiter_scalar);
    const key = it.first();
    const value = it.next() orelse return Error.InvalidEncoding;
    return .{ .key = key, .value = value };
}

test "phc format - encoding/decoding" {
    const Input = struct {
        str: []const u8,
        HashResult: type,
    };
    const inputs = [_]Input{
        .{
            .str = "$argon2id$v=19$key=a2V5,m=4096,t=0,p=1$X1NhbHQAAAAAAAAAAAAAAA$bWh++MKN1OiFHKgIWTLvIi1iHicmHH7+Fv3K88ifFfI",
            .HashResult = struct {
                alg_id: []const u8,
                alg_version: u16,
                key: BinValue(16),
                m: usize,
                t: u64,
                p: u32,
                salt: BinValue(16),
                hash: BinValue(32),
            },
        },
        .{
            .str = "$scrypt$v=1$ln=15,r=8,p=1$c2FsdHNhbHQ$dGVzdHBhc3M",
            .HashResult = struct {
                alg_id: []const u8,
                alg_version: ?u30,
                ln: u6,
                r: u30,
                p: u30,
                salt: BinValue(16),
                hash: BinValue(16),
            },
        },
        .{
            .str = "$scrypt",
            .HashResult = struct { alg_id: []const u8 },
        },
        .{ .str = "$scrypt$v=1", .HashResult = struct { alg_id: []const u8, alg_version: u16 } },
        .{
            .str = "$scrypt$ln=15,r=8,p=1",
            .HashResult = struct { alg_id: []const u8, alg_version: ?u30, ln: u6, r: u30, p: u30 },
        },
        .{
            .str = "$scrypt$c2FsdHNhbHQ",
            .HashResult = struct { alg_id: []const u8, salt: BinValue(16) },
        },
        .{
            .str = "$scrypt$v=1$ln=15,r=8,p=1$c2FsdHNhbHQ",
            .HashResult = struct {
                alg_id: []const u8,
                alg_version: u16,
                ln: u6,
                r: u30,
                p: u30,
                salt: BinValue(16),
            },
        },
        .{
            .str = "$scrypt$v=1$ln=15,r=8,p=1",
            .HashResult = struct { alg_id: []const u8, alg_version: ?u30, ln: u6, r: u30, p: u30 },
        },
        .{
            .str = "$scrypt$v=1$c2FsdHNhbHQ$dGVzdHBhc3M",
            .HashResult = struct {
                alg_id: []const u8,
                alg_version: u16,
                salt: BinValue(16),
                hash: BinValue(16),
            },
        },
        .{
            .str = "$scrypt$v=1$c2FsdHNhbHQ",
            .HashResult = struct { alg_id: []const u8, alg_version: u16, salt: BinValue(16) },
        },
        .{
            .str = "$scrypt$c2FsdHNhbHQ$dGVzdHBhc3M",
            .HashResult = struct { alg_id: []const u8, salt: BinValue(16), hash: BinValue(16) },
        },
    };
    inline for (inputs) |input| {
        const v = try deserialize(input.HashResult, input.str);
        var buf: [input.str.len]u8 = undefined;
        const s1 = try serialize(v, &buf);
        try std.testing.expectEqualSlices(u8, input.str, s1);
    }
}

test "phc format - empty input string" {
    const s = "";
    const v = deserialize(struct { alg_id: []const u8 }, s);
    try std.testing.expectError(Error.InvalidEncoding, v);
}

test "phc format - hash without salt" {
    const s = "$scrypt";
    const v = deserialize(struct { alg_id: []const u8, hash: BinValue(16) }, s);
    try std.testing.expectError(Error.InvalidEncoding, v);
}

test "phc format - calcSize" {
    const s = "$scrypt$v=1$ln=15,r=8,p=1$c2FsdHNhbHQ$dGVzdHBhc3M";
    const v = try deserialize(struct {
        alg_id: []const u8,
        alg_version: u16,
        ln: u6,
        r: u30,
        p: u30,
        salt: BinValue(8),
        hash: BinValue(8),
    }, s);
    try std.testing.expectEqual(calcSize(v), s.len);
}
const std = @import("../std.zig");
const mem = std.mem;
const mulWide = std.math.mulWide;

pub const Poly1305 = struct {
    pub const block_length: usize = 16;
    pub const mac_length = 16;
    pub const key_length = 32;

    // constant multiplier (from the secret key)
    r: [2]u64,
    // accumulated hash
    h: [3]u64 = [_]u64{ 0, 0, 0 },
    // random number added at the end (from the secret key)
    end_pad: [2]u64,
    // how many bytes are waiting to be processed in a partial block
    leftover: usize = 0,
    // partial block buffer
    buf: [block_length]u8 align(16) = undefined,

    pub fn init(key: *const [key_length]u8) Poly1305 {
        return Poly1305{
            .r = [_]u64{
                mem.readInt(u64, key[0..8], .little) & 0x0ffffffc0fffffff,
                mem.readInt(u64, key[8..16], .little) & 0x0ffffffc0ffffffc,
            },
            .end_pad = [_]u64{
                mem.readInt(u64, key[16..24], .little),
                mem.readInt(u64, key[24..32], .little),
            },
        };
    }

    inline fn add(a: u64, b: u64, c: u1) struct { u64, u1 } {
        const v1 = @addWithOverflow(a, b);
        const v2 = @addWithOverflow(v1[0], c);
        return .{ v2[0], v1[1] | v2[1] };
    }

    inline fn sub(a: u64, b: u64, c: u1) struct { u64, u1 } {
        const v1 = @subWithOverflow(a, b);
        const v2 = @subWithOverflow(v1[0], c);
        return .{ v2[0], v1[1] | v2[1] };
    }

    fn blocks(st: *Poly1305, m: []const u8, comptime last: bool) void {
        const hibit: u64 = if (last) 0 else 1;
        const r0 = st.r[0];
        const r1 = st.r[1];

        var h0 = st.h[0];
        var h1 = st.h[1];
        var h2 = st.h[2];

        var i: usize = 0;

        while (i + block_length <= m.len) : (i += block_length) {
            const in0 = mem.readInt(u64, m[i..][0..8], .little);
            const in1 = mem.readInt(u64, m[i + 8 ..][0..8], .little);

            // Add the input message to H
            var v = @addWithOverflow(h0, in0);
            h0 = v[0];
            v = add(h1, in1, v[1]);
            h1 = v[0];
            h2 +%= v[1] +% hibit;

            // Compute H * R
            const m0 = mulWide(u64, h0, r0);
            const h1r0 = mulWide(u64, h1, r0);
            const h0r1 = mulWide(u64, h0, r1);
            const h2r0 = mulWide(u64, h2, r0);
            const h1r1 = mulWide(u64, h1, r1);
            const m3 = mulWide(u64, h2, r1);
            const m1 = h1r0 +% h0r1;
            const m2 = h2r0 +% h1r1;

            const t0 = @as(u64, @truncate(m0));
            v = @addWithOverflow(@as(u64, @truncate(m1)), @as(u64, @truncate(m0 >> 64)));
            const t1 = v[0];
            v = add(@as(u64, @truncate(m2)), @as(u64, @truncate(m1 >> 64)), v[1]);
            const t2 = v[0];
            v = add(@as(u64, @truncate(m3)), @as(u64, @truncate(m2 >> 64)), v[1]);
            const t3 = v[0];

            // Partial reduction
            h0 = t0;
            h1 = t1;
            h2 = t2 & 3;

            // Add c*(4+1)
            const cclo = t2 & ~@as(u64, 3);
            const cchi = t3;
            v = @addWithOverflow(h0, cclo);
            h0 = v[0];
            v = add(h1, cchi, v[1]);
            h1 = v[0];
            h2 +%= v[1];
            const cc = (cclo | (@as(u128, cchi) << 64)) >> 2;
            v = @addWithOverflow(h0, @as(u64, @truncate(cc)));
            h0 = v[0];
            v = add(h1, @as(u64, @truncate(cc >> 64)), v[1]);
            h1 = v[0];
            h2 +%= v[1];
        }
        st.h = [_]u64{ h0, h1, h2 };
    }

    pub fn update(st: *Poly1305, m: []const u8) void {
        var mb = m;

        // handle leftover
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
            st.blocks(&st.buf, false);
            st.leftover = 0;
        }

        // process full blocks
        if (mb.len >= block_length) {
            const want = mb.len & ~(block_length - 1);
            st.blocks(mb[0..want], false);
            mb = mb[want..];
        }

        // store leftover
        if (mb.len > 0) {
            for (mb, 0..) |x, i| {
                st.buf[st.leftover + i] = x;
            }
            st.leftover += mb.len;
        }
    }

    /// Zero-pad to align the next input to the first byte of a block
    pub fn pad(st: *Poly1305) void {
        if (st.leftover == 0) {
            return;
        }
        @memset(st.buf[st.leftover..], 0);
        st.blocks(&st.buf, false);
        st.leftover = 0;
    }

    pub fn final(st: *Poly1305, out: *[mac_length]u8) void {
        if (st.leftover > 0) {
            var i = st.leftover;
            st.buf[i] = 1;
            i += 1;
            @memset(st.buf[i..], 0);
            st.blocks(&st.buf, true);
        }

        var h0 = st.h[0];
        var h1 = st.h[1];
        const h2 = st.h[2];

        // H - (2^130 - 5)
        var v = @subWithOverflow(h0, 0xfffffffffffffffb);
        const h_p0 = v[0];
        v = sub(h1, 0xffffffffffffffff, v[1]);
        const h_p1 = v[0];
        v = sub(h2, 0x0000000000000003, v[1]);

        // Final reduction, subtract 2^130-5 from H if H >= 2^130-5
        const mask = @as(u64, v[1]) -% 1;
        h0 ^= mask & (h0 ^ h_p0);
        h1 ^= mask & (h1 ^ h_p1);

        // Add the first half of the key, we intentionally don't use @addWithOverflow() here.
        st.h[0] = h0 +% st.end_pad[0];
        const c = ((h0 & st.end_pad[0]) | ((h0 | st.end_pad[0]) & ~st.h[0])) >> 63;
        st.h[1] = h1 +% st.end_pad[1] +% c;

        mem.writeInt(u64, out[0..8], st.h[0], .little);
        mem.writeInt(u64, out[8..16], st.h[1], .little);

        std.crypto.secureZero(u8, @as([*]u8, @ptrCast(st))[0..@sizeOf(Poly1305)]);
    }

    pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
        var st = Poly1305.init(key);
        st.update(msg);
        st.final(out);
    }
};

test "rfc7439 vector1" {
    const expected_mac = "\xa8\x06\x1d\xc1\x30\x51\x36\xc6\xc2\x2b\x8b\xaf\x0c\x01\x27\xa9";

    const msg = "Cryptographic Forum Research Group";
    const key = "\x85\xd6\xbe\x78\x57\x55\x6d\x33\x7f\x44\x52\xfe\x42\xd5\x06\xa8" ++
        "\x01\x03\x80\x8a\xfb\x0d\xb2\xfd\x4a\xbf\xf6\xaf\x41\x49\xf5\x1b";

    var mac: [16]u8 = undefined;
    Poly1305.create(mac[0..], msg, key);

    try std.testing.expectEqualSlices(u8, expected_mac, &mac);
}

test "requiring a final reduction" {
    const expected_mac = [_]u8{ 25, 13, 249, 42, 164, 57, 99, 60, 149, 181, 74, 74, 13, 63, 121, 6 };
    const msg = [_]u8{ 253, 193, 249, 146, 70, 6, 214, 226, 131, 213, 241, 116, 20, 24, 210, 224, 65, 151, 255, 104, 133 };
    const key = [_]u8{ 190, 63, 95, 57, 155, 103, 77, 170, 7, 98, 106, 44, 117, 186, 90, 185, 109, 118, 184, 24, 69, 41, 166, 243, 119, 132, 151, 61, 52, 43, 64, 250 };
    var mac: [16]u8 = undefined;
    Poly1305.create(mac[0..], &msg, &key);
    try std.testing.expectEqualSlices(u8, &expected_mac, &mac);
}
const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const State = struct {
    blocks: [7]AesBlock,
    k0: AesBlock,
    k1: AesBlock,

    const rounds = 16;

    fn init(key: [RoccaS.key_length]u8, nonce: [RoccaS.nonce_length]u8) State {
        const z0 = AesBlock.fromBytes(&[_]u8{ 205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66 });
        const z1 = AesBlock.fromBytes(&[_]u8{ 188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181 });
        const k0 = AesBlock.fromBytes(key[0..16]);
        const k1 = AesBlock.fromBytes(key[16..32]);
        const zero = AesBlock.fromBytes(&([_]u8{0} ** 16));
        const nonce_block = AesBlock.fromBytes(&nonce);

        const blocks = [7]AesBlock{
            k1,
            nonce_block,
            z0,
            k0,
            z1,
            nonce_block.xorBlocks(k1),
            zero,
        };
        var state = State{ .blocks = blocks, .k0 = k0, .k1 = k1 };
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            state.update(z0, z1);
        }
        return state;
    }

    inline fn update(state: *State, x0: AesBlock, x1: AesBlock) void {
        const blocks = &state.blocks;
        const next: [7]AesBlock = .{
            blocks[6].xorBlocks(blocks[1]),
            blocks[0].encrypt(x0),
            blocks[1].encrypt(blocks[0]),
            blocks[2].encrypt(blocks[6]),
            blocks[3].encrypt(x1),
            blocks[4].encrypt(blocks[3]),
            blocks[5].encrypt(blocks[4]),
        };
        state.blocks = next;
    }

    fn enc(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const msg0 = AesBlock.fromBytes(src[0..16]);
        const msg1 = AesBlock.fromBytes(src[16..32]);
        const tmp0 = blocks[3].xorBlocks(blocks[5]).encrypt(blocks[0]).xorBlocks(msg0);
        const tmp1 = blocks[4].xorBlocks(blocks[6]).encrypt(blocks[2]).xorBlocks(msg1);
        dst[0..16].* = tmp0.toBytes();
        dst[16..32].* = tmp1.toBytes();
        state.update(msg0, msg1);
    }

    fn dec(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const c0 = AesBlock.fromBytes(src[0..16]);
        const c1 = AesBlock.fromBytes(src[16..32]);
        const msg0 = blocks[3].xorBlocks(blocks[5]).encrypt(blocks[0]).xorBlocks(c0);
        const msg1 = blocks[4].xorBlocks(blocks[6]).encrypt(blocks[2]).xorBlocks(c1);
        dst[0..16].* = msg0.toBytes();
        dst[16..32].* = msg1.toBytes();
        state.update(msg0, msg1);
    }

    fn decPartial(state: *State, dst: []u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const c0 = AesBlock.fromBytes(src[0..16]);
        const c1 = AesBlock.fromBytes(src[16..32]);
        const msg0 = blocks[3].xorBlocks(blocks[5]).encrypt(blocks[0]).xorBlocks(c0);
        const msg1 = blocks[4].xorBlocks(blocks[6]).encrypt(blocks[2]).xorBlocks(c1);
        var padded: [32]u8 = undefined;
        padded[0..16].* = msg0.toBytes();
        padded[16..32].* = msg1.toBytes();
        mem.set(u8, padded[dst.len..], 0);
        mem.copy(u8, dst, padded[0..dst.len]);
        state.update(AesBlock.fromBytes(padded[0..16]), AesBlock.fromBytes(padded[16..32]));
    }

    fn mac(state: *State, adlen: usize, mlen: usize) [32]u8 {
        var blocks = &state.blocks;
        blocks[1] = blocks[1].xorBlocks(state.k0);
        blocks[2] = blocks[2].xorBlocks(state.k1);
        var adlen_bytes: [16]u8 = undefined;
        var mlen_bytes: [16]u8 = undefined;
        mem.writeIntLittle(u128, &adlen_bytes, adlen * 8);
        mem.writeIntLittle(u128, &mlen_bytes, mlen * 8);
        const adlen_block = AesBlock.fromBytes(&adlen_bytes);
        const mlen_block = AesBlock.fromBytes(&mlen_bytes);
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            state.update(adlen_block, mlen_block);
        }
        var tag: [32]u8 = undefined;
        tag[0..16].* = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).toBytes();
        tag[16..32].* = blocks[4].xorBlocks(blocks[5]).xorBlocks(blocks[6]).toBytes();
        return tag;
    }
};

/// ROCCA-S is a very fast authenticated encryption system built on top of the core AES function.
///
/// It has a 256 bit key, a 128 bit nonce, and processes 256 bit message blocks.
/// It was designed to fully exploit the parallelism and built-in AES support of recent Intel and ARM CPUs.
///
/// https://www.ietf.org/archive/id/draft-nakano-rocca-s-01.html
pub const RoccaS = struct {
    pub const tag_length = 32;
    pub const nonce_length = 16;
    pub const key_length = 32;

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [32]u8 align(16) = undefined;
        var dst: [32]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            state.enc(&dst, ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 32], ad[i .. i + ad.len % 32]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            state.enc(c[i..][0..32], m[i..][0..32]);
        }
        if (m.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 32], m[i .. i + m.len % 32]);
            state.enc(&dst, &src);
            mem.copy(u8, c[i .. i + m.len % 32], dst[0 .. m.len % 32]);
        }
        tag.* = state.mac(ad.len, m.len);
    }

    /// m: message: output buffer should be of size c.len
    /// c: ciphertext
    /// tag: authentication tag
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [32]u8 align(16) = undefined;
        var dst: [32]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            state.enc(&dst, ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 32], ad[i .. i + ad.len % 32]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            state.dec(m[i..][0..32], c[i..][0..32]);
        }
        if (m.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 32], c[i .. i + m.len % 32]);
            state.decPartial(m[i .. i + m.len % 32], &src);
        }
        const computed_tag = state.mac(ad.len, m.len);
        var acc: u8 = 0;
        for (computed_tag, 0..) |_, j| {
            acc |= (computed_tag[j] ^ tag[j]);
        }
        if (acc != 0) {
            mem.set(u8, m, 0xaa);
            return error.AuthenticationFailed;
        }
    }
};

const testing = std.testing;

test "empty test" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    var c = [_]u8{};
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "d70bfa63d7658fb527b6c6ceb43f11b1696044eb4dbd9d3db83de552b61551b0");
    RoccaS.encrypt(&c, &tag, "", "", nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
}

test "basic test" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const mlen = 1000;
    var tag: [RoccaS.tag_length]u8 = undefined;

    const allocator = std.testing.allocator;
    var m = try allocator.alloc(u8, mlen);
    defer allocator.free(m);
    mem.set(u8, m[0..], 0x41);

    RoccaS.encrypt(m[0..], &tag, m[0..], "associated data", nonce, key);
    try RoccaS.decrypt(m[0..], m[0..], tag, "associated data", nonce, key);

    for (m) |x| {
        try testing.expectEqual(x, 0x41);
    }
}

test "test vector 1" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const ad = [_]u8{0} ** 32;
    var m = [_]u8{0} ** 64;
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}

test "test vector 2" {
    const key = [_]u8{1} ** 32;
    const nonce = [_]u8{1} ** 16;
    const ad = [_]u8{1} ** 32;
    var m = [_]u8{0} ** 64;
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "8c6e84a97d9c729a1d291bafae1fe82aca97fd9b3a80256a4d57a18bd3d15951");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "6f983ab45ff43b83d91b0c393b91df3d339fc7811568af8bdbc6c3fa02519caa9514054c70bd4c45ea047ac196f880d19025fbbea500c83bf484acc396c36193");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}

test "test vector 3" {
    var key: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&key, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    var nonce: [16]u8 = undefined;
    _ = try fmt.hexToBytes(&nonce, "0123456789abcdef0123456789abcdef");
    var ad: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&ad, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    var m = [_]u8{0} ** 64;
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "80adbd5b4d3913d0e4b6938c5bac3cc20d67a85e0a93e6f92ecfe5f328ae44ff");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "8638fdd10710982215671146036e9f74bc15c4279de4f8d983c376dd5a8908a1ef5b5aceabaaa7e8e7d4db8119e206ec215172bed7dfeb5ad5501a6b33f5b94b");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}

test "test vector 4" {
    const key = [_]u8{0x11} ** 16 ++ [_]u8{0x22} ** 16;
    const nonce = [_]u8{0x44} ** 16;
    var ad: [18]u8 = undefined;
    _ = try fmt.hexToBytes(&ad, "808182838485868788898a8b8c8d8e8f9091");
    var m: [64]u8 = undefined;
    _ = try fmt.hexToBytes(&m, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "3fe3ca4f00b8e0f3f5cf049454678439fae5ff079c863ccc0948513e21d2409d");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "8627c5771a07ea4e5bdb278c81e97da7d56fbb0870c04e93ffc273ac8015b9d6dbacd40417a4512c9e49cea2d4844f53ee1c862e8b742cf8c4cd30569d5b563d");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}
const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const State = struct {
    blocks: [8]AesBlock,

    const rounds = 20;

    fn init(key: [32]u8, nonce: [16]u8) State {
        var z0b: [16]u8 = undefined;
        var z1b: [16]u8 = undefined;
        mem.writeIntLittle(u128, &z0b, 0x428a2f98d728ae227137449123ef65cd);
        mem.writeIntLittle(u128, &z1b, 0xb5c0fbcfec4d3b2fe9b5dba58189dbbc);
        const z0 = AesBlock.fromBytes(&z0b);
        const z1 = AesBlock.fromBytes(&z1b);
        const k0 = AesBlock.fromBytes(key[0..16]);
        const k1 = AesBlock.fromBytes(key[16..32]);
        const zero = AesBlock.fromBytes(&([_]u8{0} ** 16));
        const nonce_block = AesBlock.fromBytes(&nonce);

        const blocks = [8]AesBlock{
            k1,
            nonce_block,
            z0,
            z1,
            nonce_block.xorBlocks(k1),
            zero,
            k0,
            zero,
        };
        var state = State{ .blocks = blocks };
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            state.update(z0, z1);
        }
        return state;
    }

    inline fn update(state: *State, x0: AesBlock, x1: AesBlock) void {
        const blocks = &state.blocks;
        const next: [8]AesBlock = .{
            blocks[7].xorBlocks(x0),
            blocks[0].encrypt(blocks[7]),
            blocks[1].xorBlocks(blocks[6]),
            blocks[2].encrypt(blocks[1]),
            blocks[3].xorBlocks(x1),
            blocks[4].encrypt(blocks[3]),
            blocks[5].encrypt(blocks[4]),
            blocks[0].xorBlocks(blocks[6]),
        };
        state.blocks = next;
    }

    fn enc(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const msg0 = AesBlock.fromBytes(src[0..16]);
        const msg1 = AesBlock.fromBytes(src[16..32]);
        const tmp0 = blocks[1].encrypt(blocks[5]).xorBlocks(msg0);
        const tmp1 = blocks[0].xorBlocks(blocks[4]).encrypt(blocks[2]).xorBlocks(msg1);
        dst[0..16].* = tmp0.toBytes();
        dst[16..32].* = tmp1.toBytes();
        state.update(msg0, msg1);
    }

    fn dec(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const msg0 = AesBlock.fromBytes(src[0..16]);
        const msg1 = AesBlock.fromBytes(src[16..32]);
        const tmp0 = blocks[1].encrypt(blocks[5]).xorBlocks(msg0);
        const tmp1 = blocks[0].xorBlocks(blocks[4]).encrypt(blocks[2]).xorBlocks(msg1);
        dst[0..16].* = tmp0.toBytes();
        dst[16..32].* = tmp1.toBytes();
        state.update(tmp0, tmp1);
    }

    fn decLast(state: *State, dst: []u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const msg0 = AesBlock.fromBytes(src[0..16]);
        const msg1 = AesBlock.fromBytes(src[16..32]);
        const tmp0 = blocks[1].encrypt(blocks[5]).xorBlocks(msg0);
        const tmp1 = blocks[0].xorBlocks(blocks[4]).encrypt(blocks[2]).xorBlocks(msg1);
        var padded: [32]u8 = undefined;
        padded[0..16].* = tmp0.toBytes();
        padded[16..32].* = tmp1.toBytes();
        mem.set(u8, padded[dst.len..], 0);
        mem.copy(u8, dst, padded[0..dst.len]);
        state.update(AesBlock.fromBytes(padded[0..16]), AesBlock.fromBytes(padded[16..32]));
    }

    fn mac(state: *State, adlen: usize, mlen: usize) [16]u8 {
        const blocks = &state.blocks;
        var adlen_bytes: [16]u8 = undefined;
        var mlen_bytes: [16]u8 = undefined;
        mem.writeIntLittle(u128, &adlen_bytes, adlen * 8);
        mem.writeIntLittle(u128, &mlen_bytes, mlen * 8);
        const adlen_block = AesBlock.fromBytes(&adlen_bytes);
        const mlen_block = AesBlock.fromBytes(&mlen_bytes);
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            state.update(adlen_block, mlen_block);
        }
        return blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3])
            .xorBlocks(blocks[4]).xorBlocks(blocks[5]).xorBlocks(blocks[6]).xorBlocks(blocks[7])
            .toBytes();
    }
};

/// ROCCA is a very fast authenticated encryption system built on top of the core AES function.
///
/// It has a 256 bit key, a 128 bit nonce, and processes 256 bit message blocks.
/// It was designed to fully exploit the parallelism and built-in AES support of recent Intel and ARM CPUs.
///
/// https://tosc.iacr.org/index.php/ToSC/article/download/8904/8480/
pub const Rocca = struct {
    pub const tag_length = 16;
    pub const nonce_length = 16;
    pub const key_length = 32;

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [32]u8 align(16) = undefined;
        var dst: [32]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            state.enc(&dst, ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 32], ad[i .. i + ad.len % 32]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            state.enc(c[i..][0..32], m[i..][0..32]);
        }
        if (m.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 32], m[i .. i + m.len % 32]);
            state.enc(&dst, &src);
            mem.copy(u8, c[i .. i + m.len % 32], dst[0 .. m.len % 32]);
        }
        tag.* = state.mac(ad.len, m.len);
    }

    /// m: message: output buffer should be of size c.len
    /// c: ciphertext
    /// tag: authentication tag
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [32]u8 align(16) = undefined;
        var dst: [32]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            state.enc(&dst, ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 32], ad[i .. i + ad.len % 32]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            state.dec(m[i..][0..32], c[i..][0..32]);
        }
        if (m.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 32], c[i .. i + m.len % 32]);
            state.decLast(dst[0 .. m.len % 32], &src);
        }
        const computed_tag = state.mac(ad.len, m.len);
        var acc: u8 = 0;
        for (computed_tag, 0..) |_, j| {
            acc |= (computed_tag[j] ^ tag[j]);
        }
        if (acc != 0) {
            mem.set(u8, m, 0xaa);
            return error.AuthenticationFailed;
        }
    }
};

const testing = std.testing;

test "basic test" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const mlen = 1000;
    var tag: [Rocca.tag_length]u8 = undefined;

    const allocator = std.testing.allocator;
    var m = try allocator.alloc(u8, mlen);
    defer allocator.free(m);
    mem.set(u8, m[0..], 0x41);

    Rocca.encrypt(m[0..], &tag, m[0..], "associated data", nonce, key);
    try Rocca.decrypt(m[0..], m[0..], tag, "associated data", nonce, key);

    try testing.expectEqual(m[0], 0x41);
}
const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;

const Poly1305 = crypto.onetimeauth.Poly1305;
const Blake2b = crypto.hash.blake2.Blake2b;
const X25519 = crypto.dh.X25519;

const AuthenticationError = crypto.errors.AuthenticationError;
const IdentityElementError = crypto.errors.IdentityElementError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

/// The Salsa cipher with 20 rounds.
pub const Salsa20 = Salsa(20);

/// The XSalsa cipher with 20 rounds.
pub const XSalsa20 = XSalsa(20);

fn SalsaVecImpl(comptime rounds: comptime_int) type {
    return struct {
        const Lane = @Vector(4, u32);
        const Half = @Vector(2, u32);
        const BlockVec = [4]Lane;

        fn initContext(key: [8]u32, d: [4]u32) BlockVec {
            const c = "expand 32-byte k";
            const constant_le = comptime [4]u32{
                mem.readInt(u32, c[0..4], .little),
                mem.readInt(u32, c[4..8], .little),
                mem.readInt(u32, c[8..12], .little),
                mem.readInt(u32, c[12..16], .little),
            };
            return BlockVec{
                Lane{ key[0], key[1], key[2], key[3] },
                Lane{ key[4], key[5], key[6], key[7] },
                Lane{ constant_le[0], constant_le[1], constant_le[2], constant_le[3] },
                Lane{ d[0], d[1], d[2], d[3] },
            };
        }

        inline fn salsaCore(x: *BlockVec, input: BlockVec, comptime feedback: bool) void {
            const n1n2n3n0 = Lane{ input[3][1], input[3][2], input[3][3], input[3][0] };
            const n1n2 = Half{ n1n2n3n0[0], n1n2n3n0[1] };
            const n3n0 = Half{ n1n2n3n0[2], n1n2n3n0[3] };
            const k0k1 = Half{ input[0][0], input[0][1] };
            const k2k3 = Half{ input[0][2], input[0][3] };
            const k4k5 = Half{ input[1][0], input[1][1] };
            const k6k7 = Half{ input[1][2], input[1][3] };
            const n0k0 = Half{ n3n0[1], k0k1[0] };
            const k0n0 = Half{ n0k0[1], n0k0[0] };
            const k4k5k0n0 = Lane{ k4k5[0], k4k5[1], k0n0[0], k0n0[1] };
            const k1k6 = Half{ k0k1[1], k6k7[0] };
            const k6k1 = Half{ k1k6[1], k1k6[0] };
            const n1n2k6k1 = Lane{ n1n2[0], n1n2[1], k6k1[0], k6k1[1] };
            const k7n3 = Half{ k6k7[1], n3n0[0] };
            const n3k7 = Half{ k7n3[1], k7n3[0] };
            const k2k3n3k7 = Lane{ k2k3[0], k2k3[1], n3k7[0], n3k7[1] };

            var diag0 = input[2];
            var diag1 = @shuffle(u32, k4k5k0n0, undefined, [_]i32{ 1, 2, 3, 0 });
            var diag2 = @shuffle(u32, n1n2k6k1, undefined, [_]i32{ 1, 2, 3, 0 });
            var diag3 = @shuffle(u32, k2k3n3k7, undefined, [_]i32{ 1, 2, 3, 0 });

            const start0 = diag0;
            const start1 = diag1;
            const start2 = diag2;
            const start3 = diag3;

            var i: usize = 0;
            while (i < rounds) : (i += 2) {
                diag3 ^= math.rotl(Lane, diag1 +% diag0, 7);
                diag2 ^= math.rotl(Lane, diag0 +% diag3, 9);
                diag1 ^= math.rotl(Lane, diag3 +% diag2, 13);
                diag0 ^= math.rotl(Lane, diag2 +% diag1, 18);

                diag3 = @shuffle(u32, diag3, undefined, [_]i32{ 3, 0, 1, 2 });
                diag2 = @shuffle(u32, diag2, undefined, [_]i32{ 2, 3, 0, 1 });
                diag1 = @shuffle(u32, diag1, undefined, [_]i32{ 1, 2, 3, 0 });

                diag1 ^= math.rotl(Lane, diag3 +% diag0, 7);
                diag2 ^= math.rotl(Lane, diag0 +% diag1, 9);
                diag3 ^= math.rotl(Lane, diag1 +% diag2, 13);
                diag0 ^= math.rotl(Lane, diag2 +% diag3, 18);

                diag1 = @shuffle(u32, diag1, undefined, [_]i32{ 3, 0, 1, 2 });
                diag2 = @shuffle(u32, diag2, undefined, [_]i32{ 2, 3, 0, 1 });
                diag3 = @shuffle(u32, diag3, undefined, [_]i32{ 1, 2, 3, 0 });
            }

            if (feedback) {
                diag0 +%= start0;
                diag1 +%= start1;
                diag2 +%= start2;
                diag3 +%= start3;
            }

            const x0x1x10x11 = Lane{ diag0[0], diag1[1], diag0[2], diag1[3] };
            const x12x13x6x7 = Lane{ diag1[0], diag2[1], diag1[2], diag2[3] };
            const x8x9x2x3 = Lane{ diag2[0], diag3[1], diag2[2], diag3[3] };
            const x4x5x14x15 = Lane{ diag3[0], diag0[1], diag3[2], diag0[3] };

            x[0] = Lane{ x0x1x10x11[0], x0x1x10x11[1], x8x9x2x3[2], x8x9x2x3[3] };
            x[1] = Lane{ x4x5x14x15[0], x4x5x14x15[1], x12x13x6x7[2], x12x13x6x7[3] };
            x[2] = Lane{ x8x9x2x3[0], x8x9x2x3[1], x0x1x10x11[2], x0x1x10x11[3] };
            x[3] = Lane{ x12x13x6x7[0], x12x13x6x7[1], x4x5x14x15[2], x4x5x14x15[3] };
        }

        fn hashToBytes(out: *[64]u8, x: BlockVec) void {
            var i: usize = 0;
            while (i < 4) : (i += 1) {
                mem.writeInt(u32, out[16 * i + 0 ..][0..4], x[i][0], .little);
                mem.writeInt(u32, out[16 * i + 4 ..][0..4], x[i][1], .little);
                mem.writeInt(u32, out[16 * i + 8 ..][0..4], x[i][2], .little);
                mem.writeInt(u32, out[16 * i + 12 ..][0..4], x[i][3], .little);
            }
        }

        fn salsaXor(out: []u8, in: []const u8, key: [8]u32, d: [4]u32) void {
            var ctx = initContext(key, d);
            var x: BlockVec = undefined;
            var buf: [64]u8 = undefined;
            var i: usize = 0;
            while (i + 64 <= in.len) : (i += 64) {
                salsaCore(x[0..], ctx, true);
                hashToBytes(buf[0..], x);
                var xout = out[i..];
                const xin = in[i..];
                var j: usize = 0;
                while (j < 64) : (j += 1) {
                    xout[j] = xin[j];
                }
                j = 0;
                while (j < 64) : (j += 1) {
                    xout[j] ^= buf[j];
                }
                ctx[3][2] +%= 1;
                if (ctx[3][2] == 0) {
                    ctx[3][3] += 1;
                }
            }
            if (i < in.len) {
                salsaCore(x[0..], ctx, true);
                hashToBytes(buf[0..], x);

                var xout = out[i..];
                const xin = in[i..];
                var j: usize = 0;
                while (j < in.len % 64) : (j += 1) {
                    xout[j] = xin[j] ^ buf[j];
                }
            }
        }

        fn hsalsa(input: [16]u8, key: [32]u8) [32]u8 {
            var c: [4]u32 = undefined;
            for (c, 0..) |_, i| {
                c[i] = mem.readInt(u32, input[4 * i ..][0..4], .little);
            }
            const ctx = initContext(keyToWords(key), c);
            var x: BlockVec = undefined;
            salsaCore(x[0..], ctx, false);
            var out: [32]u8 = undefined;
            mem.writeInt(u32, out[0..4], x[0][0], .little);
            mem.writeInt(u32, out[4..8], x[1][1], .little);
            mem.writeInt(u32, out[8..12], x[2][2], .little);
            mem.writeInt(u32, out[12..16], x[3][3], .little);
            mem.writeInt(u32, out[16..20], x[1][2], .little);
            mem.writeInt(u32, out[20..24], x[1][3], .little);
            mem.writeInt(u32, out[24..28], x[2][0], .little);
            mem.writeInt(u32, out[28..32], x[2][1], .little);
            return out;
        }
    };
}

fn SalsaNonVecImpl(comptime rounds: comptime_int) type {
    return struct {
        const BlockVec = [16]u32;

        fn initContext(key: [8]u32, d: [4]u32) BlockVec {
            const c = "expand 32-byte k";
            const constant_le = comptime [4]u32{
                mem.readInt(u32, c[0..4], .little),
                mem.readInt(u32, c[4..8], .little),
                mem.readInt(u32, c[8..12], .little),
                mem.readInt(u32, c[12..16], .little),
            };
            return BlockVec{
                constant_le[0], key[0],         key[1],         key[2],
                key[3],         constant_le[1], d[0],           d[1],
                d[2],           d[3],           constant_le[2], key[4],
                key[5],         key[6],         key[7],         constant_le[3],
            };
        }

        const QuarterRound = struct {
            a: usize,
            b: usize,
            c: usize,
            d: u6,
        };

        inline fn Rp(a: usize, b: usize, c: usize, d: u6) QuarterRound {
            return QuarterRound{
                .a = a,
                .b = b,
                .c = c,
                .d = d,
            };
        }

        inline fn salsaCore(x: *BlockVec, input: BlockVec, comptime feedback: bool) void {
            const arx_steps = comptime [_]QuarterRound{
                Rp(4, 0, 12, 7),   Rp(8, 4, 0, 9),    Rp(12, 8, 4, 13),   Rp(0, 12, 8, 18),
                Rp(9, 5, 1, 7),    Rp(13, 9, 5, 9),   Rp(1, 13, 9, 13),   Rp(5, 1, 13, 18),
                Rp(14, 10, 6, 7),  Rp(2, 14, 10, 9),  Rp(6, 2, 14, 13),   Rp(10, 6, 2, 18),
                Rp(3, 15, 11, 7),  Rp(7, 3, 15, 9),   Rp(11, 7, 3, 13),   Rp(15, 11, 7, 18),
                Rp(1, 0, 3, 7),    Rp(2, 1, 0, 9),    Rp(3, 2, 1, 13),    Rp(0, 3, 2, 18),
                Rp(6, 5, 4, 7),    Rp(7, 6, 5, 9),    Rp(4, 7, 6, 13),    Rp(5, 4, 7, 18),
                Rp(11, 10, 9, 7),  Rp(8, 11, 10, 9),  Rp(9, 8, 11, 13),   Rp(10, 9, 8, 18),
                Rp(12, 15, 14, 7), Rp(13, 12, 15, 9), Rp(14, 13, 12, 13), Rp(15, 14, 13, 18),
            };
            x.* = input;
            var j: usize = 0;
            while (j < rounds) : (j += 2) {
                inline for (arx_steps) |r| {
                    x[r.a] ^= math.rotl(u32, x[r.b] +% x[r.c], r.d);
                }
            }
            if (feedback) {
                j = 0;
                while (j < 16) : (j += 1) {
                    x[j] +%= input[j];
                }
            }
        }

        fn hashToBytes(out: *[64]u8, x: BlockVec) void {
            for (x, 0..) |w, i| {
                mem.writeInt(u32, out[i * 4 ..][0..4], w, .little);
            }
        }

        fn salsaXor(out: []u8, in: []const u8, key: [8]u32, d: [4]u32) void {
            var ctx = initContext(key, d);
            var x: BlockVec = undefined;
            var buf: [64]u8 = undefined;
            var i: usize = 0;
            while (i + 64 <= in.len) : (i += 64) {
                salsaCore(x[0..], ctx, true);
                hashToBytes(buf[0..], x);
                var xout = out[i..];
                const xin = in[i..];
                var j: usize = 0;
                while (j < 64) : (j += 1) {
                    xout[j] = xin[j];
                }
                j = 0;
                while (j < 64) : (j += 1) {
                    xout[j] ^= buf[j];
                }
                const ov = @addWithOverflow(ctx[8], 1);
                ctx[8] = ov[0];
                ctx[9] += ov[1];
            }
            if (i < in.len) {
                salsaCore(x[0..], ctx, true);
                hashToBytes(buf[0..], x);

                var xout = out[i..];
                const xin = in[i..];
                var j: usize = 0;
                while (j < in.len % 64) : (j += 1) {
                    xout[j] = xin[j] ^ buf[j];
                }
            }
        }

        fn hsalsa(input: [16]u8, key: [32]u8) [32]u8 {
            var c: [4]u32 = undefined;
            for (c, 0..) |_, i| {
                c[i] = mem.readInt(u32, input[4 * i ..][0..4], .little);
            }
            const ctx = initContext(keyToWords(key), c);
            var x: BlockVec = undefined;
            salsaCore(x[0..], ctx, false);
            var out: [32]u8 = undefined;
            mem.writeInt(u32, out[0..4], x[0], .little);
            mem.writeInt(u32, out[4..8], x[5], .little);
            mem.writeInt(u32, out[8..12], x[10], .little);
            mem.writeInt(u32, out[12..16], x[15], .little);
            mem.writeInt(u32, out[16..20], x[6], .little);
            mem.writeInt(u32, out[20..24], x[7], .little);
            mem.writeInt(u32, out[24..28], x[8], .little);
            mem.writeInt(u32, out[28..32], x[9], .little);
            return out;
        }
    };
}

const SalsaImpl = if (builtin.cpu.arch == .x86_64)
    SalsaVecImpl
else
    SalsaNonVecImpl;

fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        k[i] = mem.readInt(u32, key[i * 4 ..][0..4], .little);
    }
    return k;
}

fn extend(comptime rounds: comptime_int, key: [32]u8, nonce: [24]u8) struct { key: [32]u8, nonce: [8]u8 } {
    return .{
        .key = SalsaImpl(rounds).hsalsa(nonce[0..16].*, key),
        .nonce = nonce[16..24].*,
    };
}

/// The Salsa stream cipher.
pub fn Salsa(comptime rounds: comptime_int) type {
    return struct {
        /// Nonce length in bytes.
        pub const nonce_length = 8;
        /// Key length in bytes.
        pub const key_length = 32;

        /// Add the output of the Salsa stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn xor(out: []u8, in: []const u8, counter: u64, key: [key_length]u8, nonce: [nonce_length]u8) void {
            debug.assert(in.len == out.len);

            var d: [4]u32 = undefined;
            d[0] = mem.readInt(u32, nonce[0..4], .little);
            d[1] = mem.readInt(u32, nonce[4..8], .little);
            d[2] = @as(u32, @truncate(counter));
            d[3] = @as(u32, @truncate(counter >> 32));
            SalsaImpl(rounds).salsaXor(out, in, keyToWords(key), d);
        }
    };
}

/// The XSalsa stream cipher.
pub fn XSalsa(comptime rounds: comptime_int) type {
    return struct {
        /// Nonce length in bytes.
        pub const nonce_length = 24;
        /// Key length in bytes.
        pub const key_length = 32;

        /// Add the output of the XSalsa stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn xor(out: []u8, in: []const u8, counter: u64, key: [key_length]u8, nonce: [nonce_length]u8) void {
            const extended = extend(rounds, key, nonce);
            Salsa(rounds).xor(out, in, counter, extended.key, extended.nonce);
        }
    };
}

/// The XSalsa stream cipher, combined with the Poly1305 MAC
pub const XSalsa20Poly1305 = struct {
    /// Authentication tag length in bytes.
    pub const tag_length = Poly1305.mac_length;
    /// Nonce length in bytes.
    pub const nonce_length = XSalsa20.nonce_length;
    /// Key length in bytes.
    pub const key_length = XSalsa20.key_length;

    const rounds = 20;

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        debug.assert(c.len == m.len);
        const extended = extend(rounds, k, npub);
        var block0 = [_]u8{0} ** 64;
        const mlen0 = @min(32, m.len);
        @memcpy(block0[32..][0..mlen0], m[0..mlen0]);
        Salsa20.xor(block0[0..], block0[0..], 0, extended.key, extended.nonce);
        @memcpy(c[0..mlen0], block0[32..][0..mlen0]);
        Salsa20.xor(c[mlen0..], m[mlen0..], 1, extended.key, extended.nonce);
        var mac = Poly1305.init(block0[0..32]);
        mac.update(ad);
        mac.update(c);
        mac.final(tag);
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
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        debug.assert(c.len == m.len);
        const extended = extend(rounds, k, npub);
        var block0 = [_]u8{0} ** 64;
        const mlen0 = @min(32, c.len);
        @memcpy(block0[32..][0..mlen0], c[0..mlen0]);
        Salsa20.xor(block0[0..], block0[0..], 0, extended.key, extended.nonce);
        var mac = Poly1305.init(block0[0..32]);
        mac.update(ad);
        mac.update(c);
        var computed_tag: [tag_length]u8 = undefined;
        mac.final(&computed_tag);

        const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
        if (!verify) {
            crypto.secureZero(u8, &computed_tag);
            @memset(m, undefined);
            return error.AuthenticationFailed;
        }
        @memcpy(m[0..mlen0], block0[32..][0..mlen0]);
        Salsa20.xor(m[mlen0..], c[mlen0..], 1, extended.key, extended.nonce);
    }
};

/// NaCl-compatible secretbox API.
///
/// A secretbox contains both an encrypted message and an authentication tag to verify that it hasn't been tampered with.
/// A secret key shared by all the recipients must be already known in order to use this API.
///
/// Nonces are 192-bit large and can safely be chosen with a random number generator.
pub const SecretBox = struct {
    /// Key length in bytes.
    pub const key_length = XSalsa20Poly1305.key_length;
    /// Nonce length in bytes.
    pub const nonce_length = XSalsa20Poly1305.nonce_length;
    /// Authentication tag length in bytes.
    pub const tag_length = XSalsa20Poly1305.tag_length;

    /// Encrypt and authenticate `m` using a nonce `npub` and a key `k`.
    /// `c` must be exactly `tag_length` longer than `m`, as it will store both the ciphertext and the authentication tag.
    pub fn seal(c: []u8, m: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        debug.assert(c.len == tag_length + m.len);
        XSalsa20Poly1305.encrypt(c[tag_length..], c[0..tag_length], m, "", npub, k);
    }

    /// Verify and decrypt `c` using a nonce `npub` and a key `k`.
    /// `m` must be exactly `tag_length` smaller than `c`, as `c` includes an authentication tag in addition to the encrypted message.
    pub fn open(m: []u8, c: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        if (c.len < tag_length) {
            return error.AuthenticationFailed;
        }
        debug.assert(m.len == c.len - tag_length);
        return XSalsa20Poly1305.decrypt(m, c[tag_length..], c[0..tag_length].*, "", npub, k);
    }
};

/// NaCl-compatible box API.
///
/// A secretbox contains both an encrypted message and an authentication tag to verify that it hasn't been tampered with.
/// This construction uses public-key cryptography. A shared secret doesn't have to be known in advance by both parties.
/// Instead, a message is encrypted using a sender's secret key and a recipient's public key,
/// and is decrypted using the recipient's secret key and the sender's public key.
///
/// Nonces are 192-bit large and can safely be chosen with a random number generator.
pub const Box = struct {
    /// Public key length in bytes.
    pub const public_length = X25519.public_length;
    /// Secret key length in bytes.
    pub const secret_length = X25519.secret_length;
    /// Shared key length in bytes.
    pub const shared_length = XSalsa20Poly1305.key_length;
    /// Seed (for key pair creation) length in bytes.
    pub const seed_length = X25519.seed_length;
    /// Nonce length in bytes.
    pub const nonce_length = XSalsa20Poly1305.nonce_length;
    /// Authentication tag length in bytes.
    pub const tag_length = XSalsa20Poly1305.tag_length;

    /// A key pair.
    pub const KeyPair = X25519.KeyPair;

    /// Compute a secret suitable for `secretbox` given a recipient's public key and a sender's secret key.
    pub fn createSharedSecret(public_key: [public_length]u8, secret_key: [secret_length]u8) (IdentityElementError || WeakPublicKeyError)![shared_length]u8 {
        const p = try X25519.scalarmult(secret_key, public_key);
        const zero = [_]u8{0} ** 16;
        return SalsaImpl(20).hsalsa(zero, p);
    }

    /// Encrypt and authenticate a message using a recipient's public key `public_key` and a sender's `secret_key`.
    pub fn seal(c: []u8, m: []const u8, npub: [nonce_length]u8, public_key: [public_length]u8, secret_key: [secret_length]u8) (IdentityElementError || WeakPublicKeyError)!void {
        const shared_key = try createSharedSecret(public_key, secret_key);
        return SecretBox.seal(c, m, npub, shared_key);
    }

    /// Verify and decrypt a message using a recipient's secret key `public_key` and a sender's `public_key`.
    pub fn open(m: []u8, c: []const u8, npub: [nonce_length]u8, public_key: [public_length]u8, secret_key: [secret_length]u8) (IdentityElementError || WeakPublicKeyError || AuthenticationError)!void {
        const shared_key = try createSharedSecret(public_key, secret_key);
        return SecretBox.open(m, c, npub, shared_key);
    }
};

/// libsodium-compatible sealed boxes
///
/// Sealed boxes are designed to anonymously send messages to a recipient given their public key.
/// Only the recipient can decrypt these messages, using their private key.
/// While the recipient can verify the integrity of the message, it cannot verify the identity of the sender.
///
/// A message is encrypted using an ephemeral key pair, whose secret part is destroyed right after the encryption process.
pub const SealedBox = struct {
    pub const public_length = Box.public_length;
    pub const secret_length = Box.secret_length;
    pub const seed_length = Box.seed_length;
    pub const seal_length = Box.public_length + Box.tag_length;

    /// A key pair.
    pub const KeyPair = Box.KeyPair;

    fn createNonce(pk1: [public_length]u8, pk2: [public_length]u8) [Box.nonce_length]u8 {
        var hasher = Blake2b(Box.nonce_length * 8).init(.{});
        hasher.update(&pk1);
        hasher.update(&pk2);
        var nonce: [Box.nonce_length]u8 = undefined;
        hasher.final(&nonce);
        return nonce;
    }

    /// Encrypt a message `m` for a recipient whose public key is `public_key`.
    /// `c` must be `seal_length` bytes larger than `m`, so that the required metadata can be added.
    pub fn seal(c: []u8, m: []const u8, public_key: [public_length]u8) (WeakPublicKeyError || IdentityElementError)!void {
        debug.assert(c.len == m.len + seal_length);
        var ekp = KeyPair.generate();
        const nonce = createNonce(ekp.public_key, public_key);
        c[0..public_length].* = ekp.public_key;
        try Box.seal(c[Box.public_length..], m, nonce, public_key, ekp.secret_key);
        crypto.secureZero(u8, ekp.secret_key[0..]);
    }

    /// Decrypt a message using a key pair.
    /// `m` must be exactly `seal_length` bytes smaller than `c`, as `c` also includes metadata.
    pub fn open(m: []u8, c: []const u8, keypair: KeyPair) (IdentityElementError || WeakPublicKeyError || AuthenticationError)!void {
        if (c.len < seal_length) {
            return error.AuthenticationFailed;
        }
        const epk = c[0..public_length];
        const nonce = createNonce(epk.*, keypair.public_key);
        return Box.open(m, c[public_length..], nonce, epk.*, keypair.secret_key);
    }
};

const htest = @import("test.zig");

test "(x)salsa20" {
    const key = [_]u8{0x69} ** 32;
    const nonce = [_]u8{0x42} ** 8;
    const msg = [_]u8{0} ** 20;
    var c: [msg.len]u8 = undefined;

    Salsa20.xor(&c, msg[0..], 0, key, nonce);
    try htest.assertEqual("30ff9933aa6534ff5207142593cd1fca4b23bdd8", c[0..]);

    const extended_nonce = [_]u8{0x42} ** 24;
    XSalsa20.xor(&c, msg[0..], 0, key, extended_nonce);
    try htest.assertEqual("b4ab7d82e750ec07644fa3281bce6cd91d4243f9", c[0..]);
}

test "xsalsa20poly1305" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var key: [XSalsa20Poly1305.key_length]u8 = undefined;
    var nonce: [XSalsa20Poly1305.nonce_length]u8 = undefined;
    var tag: [XSalsa20Poly1305.tag_length]u8 = undefined;
    crypto.random.bytes(&msg);
    crypto.random.bytes(&key);
    crypto.random.bytes(&nonce);

    XSalsa20Poly1305.encrypt(c[0..], &tag, msg[0..], "ad", nonce, key);
    try XSalsa20Poly1305.decrypt(msg2[0..], c[0..], tag, "ad", nonce, key);
}

test "xsalsa20poly1305 secretbox" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var key: [XSalsa20Poly1305.key_length]u8 = undefined;
    var nonce: [Box.nonce_length]u8 = undefined;
    var boxed: [msg.len + Box.tag_length]u8 = undefined;
    crypto.random.bytes(&msg);
    crypto.random.bytes(&key);
    crypto.random.bytes(&nonce);

    SecretBox.seal(boxed[0..], msg[0..], nonce, key);
    try SecretBox.open(msg2[0..], boxed[0..], nonce, key);
}

test "xsalsa20poly1305 box" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var nonce: [Box.nonce_length]u8 = undefined;
    var boxed: [msg.len + Box.tag_length]u8 = undefined;
    crypto.random.bytes(&msg);
    crypto.random.bytes(&nonce);

    const kp1 = Box.KeyPair.generate();
    const kp2 = Box.KeyPair.generate();
    try Box.seal(boxed[0..], msg[0..], nonce, kp1.public_key, kp2.secret_key);
    try Box.open(msg2[0..], boxed[0..], nonce, kp2.public_key, kp1.secret_key);
}

test "xsalsa20poly1305 sealedbox" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var boxed: [msg.len + SealedBox.seal_length]u8 = undefined;
    crypto.random.bytes(&msg);

    const kp = Box.KeyPair.generate();
    try SealedBox.seal(boxed[0..], msg[0..], kp.public_key);
    try SealedBox.open(msg2[0..], boxed[0..], kp);
}

test "secretbox twoblocks" {
    const key = [_]u8{ 0xc9, 0xc9, 0x4d, 0xcf, 0x68, 0xbe, 0x00, 0xe4, 0x7f, 0xe6, 0x13, 0x26, 0xfc, 0xc4, 0x2f, 0xd0, 0xdb, 0x93, 0x91, 0x1c, 0x09, 0x94, 0x89, 0xe1, 0x1b, 0x88, 0x63, 0x18, 0x86, 0x64, 0x8b, 0x7b };
    const nonce = [_]u8{ 0xa4, 0x33, 0xe9, 0x0a, 0x07, 0x68, 0x6e, 0x9a, 0x2b, 0x6d, 0xd4, 0x59, 0x04, 0x72, 0x3e, 0xd3, 0x8a, 0x67, 0x55, 0xc7, 0x9e, 0x3e, 0x77, 0xdc };
    const msg = [_]u8{'a'} ** 97;
    var ciphertext: [msg.len + SecretBox.tag_length]u8 = undefined;
    SecretBox.seal(&ciphertext, &msg, nonce, key);
    try htest.assertEqual("b05760e217288ba079caa2fd57fd3701784974ffcfda20fe523b89211ad8af065a6eb37cdb29d51aca5bd75dafdd21d18b044c54bb7c526cf576c94ee8900f911ceab0147e82b667a28c52d58ceb29554ff45471224d37b03256b01c119b89ff6d36855de8138d103386dbc9d971f52261", &ciphertext);
}
// https://tools.ietf.org/html/rfc7914
// https://github.com/golang/crypto/blob/master/scrypt/scrypt.go
// https://github.com/Tarsnap/scrypt

const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const io = std.io;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const pwhash = crypto.pwhash;

const phc_format = @import("phc_encoding.zig");

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const KdfError = pwhash.KdfError;
const HasherError = pwhash.HasherError;
const EncodingError = phc_format.Error;
const Error = pwhash.Error;

const max_size = math.maxInt(usize);
const max_int = max_size >> 1;
const default_salt_len = 32;
const default_hash_len = 32;
const max_salt_len = 64;
const max_hash_len = 64;

fn blockCopy(dst: []align(16) u32, src: []align(16) const u32, n: usize) void {
    @memcpy(dst[0 .. n * 16], src[0 .. n * 16]);
}

fn blockXor(dst: []align(16) u32, src: []align(16) const u32, n: usize) void {
    for (src[0 .. n * 16], 0..) |v, i| {
        dst[i] ^= v;
    }
}

const QuarterRound = struct { a: usize, b: usize, c: usize, d: u6 };

fn Rp(a: usize, b: usize, c: usize, d: u6) QuarterRound {
    return QuarterRound{ .a = a, .b = b, .c = c, .d = d };
}

fn salsa8core(b: *align(16) [16]u32) void {
    const arx_steps = comptime [_]QuarterRound{
        Rp(4, 0, 12, 7),   Rp(8, 4, 0, 9),    Rp(12, 8, 4, 13),   Rp(0, 12, 8, 18),
        Rp(9, 5, 1, 7),    Rp(13, 9, 5, 9),   Rp(1, 13, 9, 13),   Rp(5, 1, 13, 18),
        Rp(14, 10, 6, 7),  Rp(2, 14, 10, 9),  Rp(6, 2, 14, 13),   Rp(10, 6, 2, 18),
        Rp(3, 15, 11, 7),  Rp(7, 3, 15, 9),   Rp(11, 7, 3, 13),   Rp(15, 11, 7, 18),
        Rp(1, 0, 3, 7),    Rp(2, 1, 0, 9),    Rp(3, 2, 1, 13),    Rp(0, 3, 2, 18),
        Rp(6, 5, 4, 7),    Rp(7, 6, 5, 9),    Rp(4, 7, 6, 13),    Rp(5, 4, 7, 18),
        Rp(11, 10, 9, 7),  Rp(8, 11, 10, 9),  Rp(9, 8, 11, 13),   Rp(10, 9, 8, 18),
        Rp(12, 15, 14, 7), Rp(13, 12, 15, 9), Rp(14, 13, 12, 13), Rp(15, ```
