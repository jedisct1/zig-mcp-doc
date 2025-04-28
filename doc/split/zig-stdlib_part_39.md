```
rg2[0]), (arg3[0]));
    var x2: u64 = undefined;
    cmovznzU64(&x2, arg1, (arg2[1]), (arg3[1]));
    var x3: u64 = undefined;
    cmovznzU64(&x3, arg1, (arg2[2]), (arg3[2]));
    var x4: u64 = undefined;
    cmovznzU64(&x4, arg1, (arg2[3]), (arg3[3]));
    var x5: u64 = undefined;
    cmovznzU64(&x5, arg1, (arg2[4]), (arg3[4]));
    var x6: u64 = undefined;
    cmovznzU64(&x6, arg1, (arg2[5]), (arg3[5]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
    out1[5] = x6;
}

/// The function toBytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..47]
///
/// Input Bounds:
///   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
pub fn toBytes(out1: *[48]u8, arg1: [6]u64) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = (arg1[5]);
    const x2 = (arg1[4]);
    const x3 = (arg1[3]);
    const x4 = (arg1[2]);
    const x5 = (arg1[1]);
    const x6 = (arg1[0]);
    const x7 = @as(u8, @truncate((x6 & 0xff)));
    const x8 = (x6 >> 8);
    const x9 = @as(u8, @truncate((x8 & 0xff)));
    const x10 = (x8 >> 8);
    const x11 = @as(u8, @truncate((x10 & 0xff)));
    const x12 = (x10 >> 8);
    const x13 = @as(u8, @truncate((x12 & 0xff)));
    const x14 = (x12 >> 8);
    const x15 = @as(u8, @truncate((x14 & 0xff)));
    const x16 = (x14 >> 8);
    const x17 = @as(u8, @truncate((x16 & 0xff)));
    const x18 = (x16 >> 8);
    const x19 = @as(u8, @truncate((x18 & 0xff)));
    const x20 = @as(u8, @truncate((x18 >> 8)));
    const x21 = @as(u8, @truncate((x5 & 0xff)));
    const x22 = (x5 >> 8);
    const x23 = @as(u8, @truncate((x22 & 0xff)));
    const x24 = (x22 >> 8);
    const x25 = @as(u8, @truncate((x24 & 0xff)));
    const x26 = (x24 >> 8);
    const x27 = @as(u8, @truncate((x26 & 0xff)));
    const x28 = (x26 >> 8);
    const x29 = @as(u8, @truncate((x28 & 0xff)));
    const x30 = (x28 >> 8);
    const x31 = @as(u8, @truncate((x30 & 0xff)));
    const x32 = (x30 >> 8);
    const x33 = @as(u8, @truncate((x32 & 0xff)));
    const x34 = @as(u8, @truncate((x32 >> 8)));
    const x35 = @as(u8, @truncate((x4 & 0xff)));
    const x36 = (x4 >> 8);
    const x37 = @as(u8, @truncate((x36 & 0xff)));
    const x38 = (x36 >> 8);
    const x39 = @as(u8, @truncate((x38 & 0xff)));
    const x40 = (x38 >> 8);
    const x41 = @as(u8, @truncate((x40 & 0xff)));
    const x42 = (x40 >> 8);
    const x43 = @as(u8, @truncate((x42 & 0xff)));
    const x44 = (x42 >> 8);
    const x45 = @as(u8, @truncate((x44 & 0xff)));
    const x46 = (x44 >> 8);
    const x47 = @as(u8, @truncate((x46 & 0xff)));
    const x48 = @as(u8, @truncate((x46 >> 8)));
    const x49 = @as(u8, @truncate((x3 & 0xff)));
    const x50 = (x3 >> 8);
    const x51 = @as(u8, @truncate((x50 & 0xff)));
    const x52 = (x50 >> 8);
    const x53 = @as(u8, @truncate((x52 & 0xff)));
    const x54 = (x52 >> 8);
    const x55 = @as(u8, @truncate((x54 & 0xff)));
    const x56 = (x54 >> 8);
    const x57 = @as(u8, @truncate((x56 & 0xff)));
    const x58 = (x56 >> 8);
    const x59 = @as(u8, @truncate((x58 & 0xff)));
    const x60 = (x58 >> 8);
    const x61 = @as(u8, @truncate((x60 & 0xff)));
    const x62 = @as(u8, @truncate((x60 >> 8)));
    const x63 = @as(u8, @truncate((x2 & 0xff)));
    const x64 = (x2 >> 8);
    const x65 = @as(u8, @truncate((x64 & 0xff)));
    const x66 = (x64 >> 8);
    const x67 = @as(u8, @truncate((x66 & 0xff)));
    const x68 = (x66 >> 8);
    const x69 = @as(u8, @truncate((x68 & 0xff)));
    const x70 = (x68 >> 8);
    const x71 = @as(u8, @truncate((x70 & 0xff)));
    const x72 = (x70 >> 8);
    const x73 = @as(u8, @truncate((x72 & 0xff)));
    const x74 = (x72 >> 8);
    const x75 = @as(u8, @truncate((x74 & 0xff)));
    const x76 = @as(u8, @truncate((x74 >> 8)));
    const x77 = @as(u8, @truncate((x1 & 0xff)));
    const x78 = (x1 >> 8);
    const x79 = @as(u8, @truncate((x78 & 0xff)));
    const x80 = (x78 >> 8);
    const x81 = @as(u8, @truncate((x80 & 0xff)));
    const x82 = (x80 >> 8);
    const x83 = @as(u8, @truncate((x82 & 0xff)));
    const x84 = (x82 >> 8);
    const x85 = @as(u8, @truncate((x84 & 0xff)));
    const x86 = (x84 >> 8);
    const x87 = @as(u8, @truncate((x86 & 0xff)));
    const x88 = (x86 >> 8);
    const x89 = @as(u8, @truncate((x88 & 0xff)));
    const x90 = @as(u8, @truncate((x88 >> 8)));
    out1[0] = x7;
    out1[1] = x9;
    out1[2] = x11;
    out1[3] = x13;
    out1[4] = x15;
    out1[5] = x17;
    out1[6] = x19;
    out1[7] = x20;
    out1[8] = x21;
    out1[9] = x23;
    out1[10] = x25;
    out1[11] = x27;
    out1[12] = x29;
    out1[13] = x31;
    out1[14] = x33;
    out1[15] = x34;
    out1[16] = x35;
    out1[17] = x37;
    out1[18] = x39;
    out1[19] = x41;
    out1[20] = x43;
    out1[21] = x45;
    out1[22] = x47;
    out1[23] = x48;
    out1[24] = x49;
    out1[25] = x51;
    out1[26] = x53;
    out1[27] = x55;
    out1[28] = x57;
    out1[29] = x59;
    out1[30] = x61;
    out1[31] = x62;
    out1[32] = x63;
    out1[33] = x65;
    out1[34] = x67;
    out1[35] = x69;
    out1[36] = x71;
    out1[37] = x73;
    out1[38] = x75;
    out1[39] = x76;
    out1[40] = x77;
    out1[41] = x79;
    out1[42] = x81;
    out1[43] = x83;
    out1[44] = x85;
    out1[45] = x87;
    out1[46] = x89;
    out1[47] = x90;
}

/// The function fromBytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
///
/// Preconditions:
///   0 ≤ bytes_eval arg1 < m
/// Postconditions:
///   eval out1 mod m = bytes_eval arg1 mod m
///   0 ≤ eval out1 < m
///
/// Input Bounds:
///   arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn fromBytes(out1: *[6]u64, arg1: [48]u8) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = (@as(u64, (arg1[47])) << 56);
    const x2 = (@as(u64, (arg1[46])) << 48);
    const x3 = (@as(u64, (arg1[45])) << 40);
    const x4 = (@as(u64, (arg1[44])) << 32);
    const x5 = (@as(u64, (arg1[43])) << 24);
    const x6 = (@as(u64, (arg1[42])) << 16);
    const x7 = (@as(u64, (arg1[41])) << 8);
    const x8 = (arg1[40]);
    const x9 = (@as(u64, (arg1[39])) << 56);
    const x10 = (@as(u64, (arg1[38])) << 48);
    const x11 = (@as(u64, (arg1[37])) << 40);
    const x12 = (@as(u64, (arg1[36])) << 32);
    const x13 = (@as(u64, (arg1[35])) << 24);
    const x14 = (@as(u64, (arg1[34])) << 16);
    const x15 = (@as(u64, (arg1[33])) << 8);
    const x16 = (arg1[32]);
    const x17 = (@as(u64, (arg1[31])) << 56);
    const x18 = (@as(u64, (arg1[30])) << 48);
    const x19 = (@as(u64, (arg1[29])) << 40);
    const x20 = (@as(u64, (arg1[28])) << 32);
    const x21 = (@as(u64, (arg1[27])) << 24);
    const x22 = (@as(u64, (arg1[26])) << 16);
    const x23 = (@as(u64, (arg1[25])) << 8);
    const x24 = (arg1[24]);
    const x25 = (@as(u64, (arg1[23])) << 56);
    const x26 = (@as(u64, (arg1[22])) << 48);
    const x27 = (@as(u64, (arg1[21])) << 40);
    const x28 = (@as(u64, (arg1[20])) << 32);
    const x29 = (@as(u64, (arg1[19])) << 24);
    const x30 = (@as(u64, (arg1[18])) << 16);
    const x31 = (@as(u64, (arg1[17])) << 8);
    const x32 = (arg1[16]);
    const x33 = (@as(u64, (arg1[15])) << 56);
    const x34 = (@as(u64, (arg1[14])) << 48);
    const x35 = (@as(u64, (arg1[13])) << 40);
    const x36 = (@as(u64, (arg1[12])) << 32);
    const x37 = (@as(u64, (arg1[11])) << 24);
    const x38 = (@as(u64, (arg1[10])) << 16);
    const x39 = (@as(u64, (arg1[9])) << 8);
    const x40 = (arg1[8]);
    const x41 = (@as(u64, (arg1[7])) << 56);
    const x42 = (@as(u64, (arg1[6])) << 48);
    const x43 = (@as(u64, (arg1[5])) << 40);
    const x44 = (@as(u64, (arg1[4])) << 32);
    const x45 = (@as(u64, (arg1[3])) << 24);
    const x46 = (@as(u64, (arg1[2])) << 16);
    const x47 = (@as(u64, (arg1[1])) << 8);
    const x48 = (arg1[0]);
    const x49 = (x47 + @as(u64, x48));
    const x50 = (x46 + x49);
    const x51 = (x45 + x50);
    const x52 = (x44 + x51);
    const x53 = (x43 + x52);
    const x54 = (x42 + x53);
    const x55 = (x41 + x54);
    const x56 = (x39 + @as(u64, x40));
    const x57 = (x38 + x56);
    const x58 = (x37 + x57);
    const x59 = (x36 + x58);
    const x60 = (x35 + x59);
    const x61 = (x34 + x60);
    const x62 = (x33 + x61);
    const x63 = (x31 + @as(u64, x32));
    const x64 = (x30 + x63);
    const x65 = (x29 + x64);
    const x66 = (x28 + x65);
    const x67 = (x27 + x66);
    const x68 = (x26 + x67);
    const x69 = (x25 + x68);
    const x70 = (x23 + @as(u64, x24));
    const x71 = (x22 + x70);
    const x72 = (x21 + x71);
    const x73 = (x20 + x72);
    const x74 = (x19 + x73);
    const x75 = (x18 + x74);
    const x76 = (x17 + x75);
    const x77 = (x15 + @as(u64, x16));
    const x78 = (x14 + x77);
    const x79 = (x13 + x78);
    const x80 = (x12 + x79);
    const x81 = (x11 + x80);
    const x82 = (x10 + x81);
    const x83 = (x9 + x82);
    const x84 = (x7 + @as(u64, x8));
    const x85 = (x6 + x84);
    const x86 = (x5 + x85);
    const x87 = (x4 + x86);
    const x88 = (x3 + x87);
    const x89 = (x2 + x88);
    const x90 = (x1 + x89);
    out1[0] = x55;
    out1[1] = x62;
    out1[2] = x69;
    out1[3] = x76;
    out1[4] = x83;
    out1[5] = x90;
}

/// The function setOne returns the field element one in the Montgomery domain.
///
/// Postconditions:
///   eval (from_montgomery out1) mod m = 1 mod m
///   0 ≤ eval out1 < m
///
pub fn setOne(out1: *MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    out1[0] = 0x1313e695333ad68d;
    out1[1] = 0xa7e5f24db74f5885;
    out1[2] = 0x389cb27e0bc8d220;
    out1[3] = 0x0;
    out1[4] = 0x0;
    out1[5] = 0x0;
}

/// The function msat returns the saturated representation of the prime modulus.
///
/// Postconditions:
///   twos_complement_eval out1 = m
///   0 ≤ eval out1 < m
///
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn msat(out1: *[7]u64) void {
    @setRuntimeSafety(mode == .Debug);

    out1[0] = 0xecec196accc52973;
    out1[1] = 0x581a0db248b0a77a;
    out1[2] = 0xc7634d81f4372ddf;
    out1[3] = 0xffffffffffffffff;
    out1[4] = 0xffffffffffffffff;
    out1[5] = 0xffffffffffffffff;
    out1[6] = 0x0;
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
///   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
///   out2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out4: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   out5: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn divstep(out1: *u64, out2: *[7]u64, out3: *[7]u64, out4: *[6]u64, out5: *[6]u64, arg1: u64, arg2: [7]u64, arg3: [7]u64, arg4: [6]u64, arg5: [6]u64) void {
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
    cmovznzU64(&x12, x3, (arg2[5]), (arg3[5]));
    var x13: u64 = undefined;
    cmovznzU64(&x13, x3, (arg2[6]), (arg3[6]));
    var x14: u64 = undefined;
    var x15: u1 = undefined;
    addcarryxU64(&x14, &x15, 0x0, 0x1, (~(arg2[0])));
    var x16: u64 = undefined;
    var x17: u1 = undefined;
    addcarryxU64(&x16, &x17, x15, 0x0, (~(arg2[1])));
    var x18: u64 = undefined;
    var x19: u1 = undefined;
    addcarryxU64(&x18, &x19, x17, 0x0, (~(arg2[2])));
    var x20: u64 = undefined;
    var x21: u1 = undefined;
    addcarryxU64(&x20, &x21, x19, 0x0, (~(arg2[3])));
    var x22: u64 = undefined;
    var x23: u1 = undefined;
    addcarryxU64(&x22, &x23, x21, 0x0, (~(arg2[4])));
    var x24: u64 = undefined;
    var x25: u1 = undefined;
    addcarryxU64(&x24, &x25, x23, 0x0, (~(arg2[5])));
    var x26: u64 = undefined;
    var x27: u1 = undefined;
    addcarryxU64(&x26, &x27, x25, 0x0, (~(arg2[6])));
    var x28: u64 = undefined;
    cmovznzU64(&x28, x3, (arg3[0]), x14);
    var x29: u64 = undefined;
    cmovznzU64(&x29, x3, (arg3[1]), x16);
    var x30: u64 = undefined;
    cmovznzU64(&x30, x3, (arg3[2]), x18);
    var x31: u64 = undefined;
    cmovznzU64(&x31, x3, (arg3[3]), x20);
    var x32: u64 = undefined;
    cmovznzU64(&x32, x3, (arg3[4]), x22);
    var x33: u64 = undefined;
    cmovznzU64(&x33, x3, (arg3[5]), x24);
    var x34: u64 = undefined;
    cmovznzU64(&x34, x3, (arg3[6]), x26);
    var x35: u64 = undefined;
    cmovznzU64(&x35, x3, (arg4[0]), (arg5[0]));
    var x36: u64 = undefined;
    cmovznzU64(&x36, x3, (arg4[1]), (arg5[1]));
    var x37: u64 = undefined;
    cmovznzU64(&x37, x3, (arg4[2]), (arg5[2]));
    var x38: u64 = undefined;
    cmovznzU64(&x38, x3, (arg4[3]), (arg5[3]));
    var x39: u64 = undefined;
    cmovznzU64(&x39, x3, (arg4[4]), (arg5[4]));
    var x40: u64 = undefined;
    cmovznzU64(&x40, x3, (arg4[5]), (arg5[5]));
    var x41: u64 = undefined;
    var x42: u1 = undefined;
    addcarryxU64(&x41, &x42, 0x0, x35, x35);
    var x43: u64 = undefined;
    var x44: u1 = undefined;
    addcarryxU64(&x43, &x44, x42, x36, x36);
    var x45: u64 = undefined;
    var x46: u1 = undefined;
    addcarryxU64(&x45, &x46, x44, x37, x37);
    var x47: u64 = undefined;
    var x48: u1 = undefined;
    addcarryxU64(&x47, &x48, x46, x38, x38);
    var x49: u64 = undefined;
    var x50: u1 = undefined;
    addcarryxU64(&x49, &x50, x48, x39, x39);
    var x51: u64 = undefined;
    var x52: u1 = undefined;
    addcarryxU64(&x51, &x52, x50, x40, x40);
    var x53: u64 = undefined;
    var x54: u1 = undefined;
    subborrowxU64(&x53, &x54, 0x0, x41, 0xecec196accc52973);
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    subborrowxU64(&x55, &x56, x54, x43, 0x581a0db248b0a77a);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    subborrowxU64(&x57, &x58, x56, x45, 0xc7634d81f4372ddf);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    subborrowxU64(&x59, &x60, x58, x47, 0xffffffffffffffff);
    var x61: u64 = undefined;
    var x62: u1 = undefined;
    subborrowxU64(&x61, &x62, x60, x49, 0xffffffffffffffff);
    var x63: u64 = undefined;
    var x64: u1 = undefined;
    subborrowxU64(&x63, &x64, x62, x51, 0xffffffffffffffff);
    var x65: u64 = undefined;
    var x66: u1 = undefined;
    subborrowxU64(&x65, &x66, x64, @as(u64, x52), 0x0);
    const x67 = (arg4[5]);
    const x68 = (arg4[4]);
    const x69 = (arg4[3]);
    const x70 = (arg4[2]);
    const x71 = (arg4[1]);
    const x72 = (arg4[0]);
    var x73: u64 = undefined;
    var x74: u1 = undefined;
    subborrowxU64(&x73, &x74, 0x0, 0x0, x72);
    var x75: u64 = undefined;
    var x76: u1 = undefined;
    subborrowxU64(&x75, &x76, x74, 0x0, x71);
    var x77: u64 = undefined;
    var x78: u1 = undefined;
    subborrowxU64(&x77, &x78, x76, 0x0, x70);
    var x79: u64 = undefined;
    var x80: u1 = undefined;
    subborrowxU64(&x79, &x80, x78, 0x0, x69);
    var x81: u64 = undefined;
    var x82: u1 = undefined;
    subborrowxU64(&x81, &x82, x80, 0x0, x68);
    var x83: u64 = undefined;
    var x84: u1 = undefined;
    subborrowxU64(&x83, &x84, x82, 0x0, x67);
    var x85: u64 = undefined;
    cmovznzU64(&x85, x84, 0x0, 0xffffffffffffffff);
    var x86: u64 = undefined;
    var x87: u1 = undefined;
    addcarryxU64(&x86, &x87, 0x0, x73, (x85 & 0xecec196accc52973));
    var x88: u64 = undefined;
    var x89: u1 = undefined;
    addcarryxU64(&x88, &x89, x87, x75, (x85 & 0x581a0db248b0a77a));
    var x90: u64 = undefined;
    var x91: u1 = undefined;
    addcarryxU64(&x90, &x91, x89, x77, (x85 & 0xc7634d81f4372ddf));
    var x92: u64 = undefined;
    var x93: u1 = undefined;
    addcarryxU64(&x92, &x93, x91, x79, x85);
    var x94: u64 = undefined;
    var x95: u1 = undefined;
    addcarryxU64(&x94, &x95, x93, x81, x85);
    var x96: u64 = undefined;
    var x97: u1 = undefined;
    addcarryxU64(&x96, &x97, x95, x83, x85);
    var x98: u64 = undefined;
    cmovznzU64(&x98, x3, (arg5[0]), x86);
    var x99: u64 = undefined;
    cmovznzU64(&x99, x3, (arg5[1]), x88);
    var x100: u64 = undefined;
    cmovznzU64(&x100, x3, (arg5[2]), x90);
    var x101: u64 = undefined;
    cmovznzU64(&x101, x3, (arg5[3]), x92);
    var x102: u64 = undefined;
    cmovznzU64(&x102, x3, (arg5[4]), x94);
    var x103: u64 = undefined;
    cmovznzU64(&x103, x3, (arg5[5]), x96);
    const x104 = @as(u1, @truncate((x28 & 0x1)));
    var x105: u64 = undefined;
    cmovznzU64(&x105, x104, 0x0, x7);
    var x106: u64 = undefined;
    cmovznzU64(&x106, x104, 0x0, x8);
    var x107: u64 = undefined;
    cmovznzU64(&x107, x104, 0x0, x9);
    var x108: u64 = undefined;
    cmovznzU64(&x108, x104, 0x0, x10);
    var x109: u64 = undefined;
    cmovznzU64(&x109, x104, 0x0, x11);
    var x110: u64 = undefined;
    cmovznzU64(&x110, x104, 0x0, x12);
    var x111: u64 = undefined;
    cmovznzU64(&x111, x104, 0x0, x13);
    var x112: u64 = undefined;
    var x113: u1 = undefined;
    addcarryxU64(&x112, &x113, 0x0, x28, x105);
    var x114: u64 = undefined;
    var x115: u1 = undefined;
    addcarryxU64(&x114, &x115, x113, x29, x106);
    var x116: u64 = undefined;
    var x117: u1 = undefined;
    addcarryxU64(&x116, &x117, x115, x30, x107);
    var x118: u64 = undefined;
    var x119: u1 = undefined;
    addcarryxU64(&x118, &x119, x117, x31, x108);
    var x120: u64 = undefined;
    var x121: u1 = undefined;
    addcarryxU64(&x120, &x121, x119, x32, x109);
    var x122: u64 = undefined;
    var x123: u1 = undefined;
    addcarryxU64(&x122, &x123, x121, x33, x110);
    var x124: u64 = undefined;
    var x125: u1 = undefined;
    addcarryxU64(&x124, &x125, x123, x34, x111);
    var x126: u64 = undefined;
    cmovznzU64(&x126, x104, 0x0, x35);
    var x127: u64 = undefined;
    cmovznzU64(&x127, x104, 0x0, x36);
    var x128: u64 = undefined;
    cmovznzU64(&x128, x104, 0x0, x37);
    var x129: u64 = undefined;
    cmovznzU64(&x129, x104, 0x0, x38);
    var x130: u64 = undefined;
    cmovznzU64(&x130, x104, 0x0, x39);
    var x131: u64 = undefined;
    cmovznzU64(&x131, x104, 0x0, x40);
    var x132: u64 = undefined;
    var x133: u1 = undefined;
    addcarryxU64(&x132, &x133, 0x0, x98, x126);
    var x134: u64 = undefined;
    var x135: u1 = undefined;
    addcarryxU64(&x134, &x135, x133, x99, x127);
    var x136: u64 = undefined;
    var x137: u1 = undefined;
    addcarryxU64(&x136, &x137, x135, x100, x128);
    var x138: u64 = undefined;
    var x139: u1 = undefined;
    addcarryxU64(&x138, &x139, x137, x101, x129);
    var x140: u64 = undefined;
    var x141: u1 = undefined;
    addcarryxU64(&x140, &x141, x139, x102, x130);
    var x142: u64 = undefined;
    var x143: u1 = undefined;
    addcarryxU64(&x142, &x143, x141, x103, x131);
    var x144: u64 = undefined;
    var x145: u1 = undefined;
    subborrowxU64(&x144, &x145, 0x0, x132, 0xecec196accc52973);
    var x146: u64 = undefined;
    var x147: u1 = undefined;
    subborrowxU64(&x146, &x147, x145, x134, 0x581a0db248b0a77a);
    var x148: u64 = undefined;
    var x149: u1 = undefined;
    subborrowxU64(&x148, &x149, x147, x136, 0xc7634d81f4372ddf);
    var x150: u64 = undefined;
    var x151: u1 = undefined;
    subborrowxU64(&x150, &x151, x149, x138, 0xffffffffffffffff);
    var x152: u64 = undefined;
    var x153: u1 = undefined;
    subborrowxU64(&x152, &x153, x151, x140, 0xffffffffffffffff);
    var x154: u64 = undefined;
    var x155: u1 = undefined;
    subborrowxU64(&x154, &x155, x153, x142, 0xffffffffffffffff);
    var x156: u64 = undefined;
    var x157: u1 = undefined;
    subborrowxU64(&x156, &x157, x155, @as(u64, x143), 0x0);
    var x158: u64 = undefined;
    var x159: u1 = undefined;
    addcarryxU64(&x158, &x159, 0x0, x6, 0x1);
    const x160 = ((x112 >> 1) | ((x114 << 63) & 0xffffffffffffffff));
    const x161 = ((x114 >> 1) | ((x116 << 63) & 0xffffffffffffffff));
    const x162 = ((x116 >> 1) | ((x118 << 63) & 0xffffffffffffffff));
    const x163 = ((x118 >> 1) | ((x120 << 63) & 0xffffffffffffffff));
    const x164 = ((x120 >> 1) | ((x122 << 63) & 0xffffffffffffffff));
    const x165 = ((x122 >> 1) | ((x124 << 63) & 0xffffffffffffffff));
    const x166 = ((x124 & 0x8000000000000000) | (x124 >> 1));
    var x167: u64 = undefined;
    cmovznzU64(&x167, x66, x53, x41);
    var x168: u64 = undefined;
    cmovznzU64(&x168, x66, x55, x43);
    var x169: u64 = undefined;
    cmovznzU64(&x169, x66, x57, x45);
    var x170: u64 = undefined;
    cmovznzU64(&x170, x66, x59, x47);
    var x171: u64 = undefined;
    cmovznzU64(&x171, x66, x61, x49);
    var x172: u64 = undefined;
    cmovznzU64(&x172, x66, x63, x51);
    var x173: u64 = undefined;
    cmovznzU64(&x173, x157, x144, x132);
    var x174: u64 = undefined;
    cmovznzU64(&x174, x157, x146, x134);
    var x175: u64 = undefined;
    cmovznzU64(&x175, x157, x148, x136);
    var x176: u64 = undefined;
    cmovznzU64(&x176, x157, x150, x138);
    var x177: u64 = undefined;
    cmovznzU64(&x177, x157, x152, x140);
    var x178: u64 = undefined;
    cmovznzU64(&x178, x157, x154, x142);
    out1.* = x158;
    out2[0] = x7;
    out2[1] = x8;
    out2[2] = x9;
    out2[3] = x10;
    out2[4] = x11;
    out2[5] = x12;
    out2[6] = x13;
    out3[0] = x160;
    out3[1] = x161;
    out3[2] = x162;
    out3[3] = x163;
    out3[4] = x164;
    out3[5] = x165;
    out3[6] = x166;
    out4[0] = x167;
    out4[1] = x168;
    out4[2] = x169;
    out4[3] = x170;
    out4[4] = x171;
    out4[5] = x172;
    out5[0] = x173;
    out5[1] = x174;
    out5[2] = x175;
    out5[3] = x176;
    out5[4] = x177;
    out5[5] = x178;
}

/// The function divstepPrecomp returns the precomputed value for Bernstein-Yang-inversion (in montgomery form).
///
/// Postconditions:
///   eval (from_montgomery out1) = ⌊(m - 1) / 2⌋^(if ⌊log2 m⌋ + 1 < 46 then ⌊(49 * (⌊log2 m⌋ + 1) + 80) / 17⌋ else ⌊(49 * (⌊log2 m⌋ + 1) + 57) / 17⌋)
///   0 ≤ eval out1 < m
///
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn divstepPrecomp(out1: *[6]u64) void {
    @setRuntimeSafety(mode == .Debug);

    out1[0] = 0x49589ae0e6045b6a;
    out1[1] = 0x3c9a5352870040ed;
    out1[2] = 0xdacb097e977dc242;
    out1[3] = 0xb5ab30a6d1ecbe36;
    out1[4] = 0x97d7a1081f959973;
    out1[5] = 0x2ba012f8d27192bc;
}
const std = @import("std");
const common = @import("../common.zig");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;

const Field = common.Field;

const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// Number of bytes required to encode a scalar.
pub const encoded_length = 48;

/// A compressed scalar, in canonical form.
pub const CompressedScalar = [encoded_length]u8;

const Fe = Field(.{
    .fiat = @import("p384_scalar_64.zig"),
    .field_order = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643,
    .field_bits = 384,
    .saturated_bits = 384,
    .encoded_length = encoded_length,
});

/// The scalar field order.
pub const field_order = Fe.field_order;

/// Reject a scalar whose encoding is not canonical.
pub fn rejectNonCanonical(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!void {
    return Fe.rejectNonCanonical(s, endian);
}

/// Reduce a 64-bytes scalar to the field size.
pub fn reduce64(s: [64]u8, endian: std.builtin.Endian) CompressedScalar {
    return Scalar.fromBytes64(s, endian).toBytes(endian);
}

/// Return a*b (mod L)
pub fn mul(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return a*b+c (mod L)
pub fn mulAdd(a: CompressedScalar, b: CompressedScalar, c: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).add(try Scalar.fromBytes(c, endian)).toBytes(endian);
}

/// Return a+b (mod L)
pub fn add(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).add(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return -s (mod L)
pub fn neg(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(s, endian)).neg().toBytes(endian);
}

/// Return (a-b) (mod L)
pub fn sub(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).sub(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return a random scalar
pub fn random(endian: std.builtin.Endian) CompressedScalar {
    return Scalar.random().toBytes(endian);
}

/// A scalar in unpacked representation.
pub const Scalar = struct {
    fe: Fe,

    /// Zero.
    pub const zero = Scalar{ .fe = Fe.zero };

    /// One.
    pub const one = Scalar{ .fe = Fe.one };

    /// Unpack a serialized representation of a scalar.
    pub fn fromBytes(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!Scalar {
        return Scalar{ .fe = try Fe.fromBytes(s, endian) };
    }

    /// Reduce a 512 bit input to the field size.
    pub fn fromBytes64(s: [64]u8, endian: std.builtin.Endian) Scalar {
        const t = ScalarDouble.fromBytes(512, s, endian);
        return t.reduce(512);
    }

    /// Pack a scalar into bytes.
    pub fn toBytes(n: Scalar, endian: std.builtin.Endian) CompressedScalar {
        return n.fe.toBytes(endian);
    }

    /// Return true if the scalar is zero..
    pub fn isZero(n: Scalar) bool {
        return n.fe.isZero();
    }

    /// Return true if the scalar is odd.
    pub fn isOdd(n: Scalar) bool {
        return n.fe.isOdd();
    }

    /// Return true if a and b are equivalent.
    pub fn equivalent(a: Scalar, b: Scalar) bool {
        return a.fe.equivalent(b.fe);
    }

    /// Compute x+y (mod L)
    pub fn add(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.add(y.fe) };
    }

    /// Compute x-y (mod L)
    pub fn sub(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.sub(y.fe) };
    }

    /// Compute 2n (mod L)
    pub fn dbl(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.dbl() };
    }

    /// Compute x*y (mod L)
    pub fn mul(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.mul(y.fe) };
    }

    /// Compute x^2 (mod L)
    pub fn sq(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.sq() };
    }

    /// Compute x^n (mod L)
    pub fn pow(a: Scalar, comptime T: type, comptime n: T) Scalar {
        return Scalar{ .fe = a.fe.pow(n) };
    }

    /// Compute -x (mod L)
    pub fn neg(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.neg() };
    }

    /// Compute x^-1 (mod L)
    pub fn invert(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.invert() };
    }

    /// Return true if n is a quadratic residue mod L.
    pub fn isSquare(n: Scalar) bool {
        return n.fe.isSquare();
    }

    /// Return the square root of L, or NotSquare if there isn't any solutions.
    pub fn sqrt(n: Scalar) NotSquareError!Scalar {
        return Scalar{ .fe = try n.fe.sqrt() };
    }

    /// Return a random scalar < L.
    pub fn random() Scalar {
        var s: [64]u8 = undefined;
        while (true) {
            crypto.random.bytes(&s);
            const n = Scalar.fromBytes64(s, .little);
            if (!n.isZero()) {
                return n;
            }
        }
    }
};

const ScalarDouble = struct {
    x1: Fe,
    x2: Fe,

    fn fromBytes(comptime bits: usize, s_: [bits / 8]u8, endian: std.builtin.Endian) ScalarDouble {
        debug.assert(bits > 0 and bits <= 512 and bits >= Fe.saturated_bits and bits <= Fe.saturated_bits * 2);

        var s = s_;
        if (endian == .big) {
            for (s_, 0..) |x, i| s[s.len - 1 - i] = x;
        }
        var t = ScalarDouble{ .x1 = undefined, .x2 = Fe.zero };
        {
            var b = [_]u8{0} ** encoded_length;
            const len = @min(s.len, 32);
            b[0..len].* = s[0..len].*;
            t.x1 = Fe.fromBytes(b, .little) catch unreachable;
        }
        if (s_.len >= 32) {
            var b = [_]u8{0} ** encoded_length;
            const len = @min(s.len - 32, 32);
            b[0..len].* = s[32..][0..len].*;
            t.x2 = Fe.fromBytes(b, .little) catch unreachable;
        }
        return t;
    }

    fn reduce(expanded: ScalarDouble, comptime bits: usize) Scalar {
        debug.assert(bits > 0 and bits <= Fe.saturated_bits * 3 and bits <= 512);
        var fe = expanded.x1;
        if (bits >= 256) {
            const st1 = Fe.fromInt(1 << 256) catch unreachable;
            fe = fe.add(expanded.x2.mul(st1));
        }
        return Scalar{ .fe = fe };
    }
};
const std = @import("std");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const NotSquareError = crypto.errors.NotSquareError;

/// Group operations over secp256k1.
pub const Secp256k1 = struct {
    /// The underlying prime field.
    pub const Fe = @import("secp256k1/field.zig").Fe;
    /// Field arithmetic mod the order of the main subgroup.
    pub const scalar = @import("secp256k1/scalar.zig");

    x: Fe,
    y: Fe,
    z: Fe = Fe.one,

    is_base: bool = false,

    /// The secp256k1 base point.
    pub const basePoint = Secp256k1{
        .x = Fe.fromInt(55066263022277343669578718895168534326250603453777594175500187360389116729240) catch unreachable,
        .y = Fe.fromInt(32670510020758816978083085130507043184471273380659243275938904335757337482424) catch unreachable,
        .z = Fe.one,
        .is_base = true,
    };

    /// The secp256k1 neutral element.
    pub const identityElement = Secp256k1{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    pub const B = Fe.fromInt(7) catch unreachable;

    pub const Endormorphism = struct {
        const lambda: u256 = 37718080363155996902926221483475020450927657555482586988616620542887997980018;
        const beta: u256 = 55594575648329892869085402983802832744385952214688224221778511981742606582254;

        const lambda_s = s: {
            var buf: [32]u8 = undefined;
            mem.writeInt(u256, &buf, Endormorphism.lambda, .little);
            break :s buf;
        };

        pub const SplitScalar = struct {
            r1: [32]u8,
            r2: [32]u8,
        };

        /// Compute r1 and r2 so that k = r1 + r2*lambda (mod L).
        pub fn splitScalar(s: [32]u8, endian: std.builtin.Endian) NonCanonicalError!SplitScalar {
            const b1_neg_s = comptime s: {
                var buf: [32]u8 = undefined;
                mem.writeInt(u256, &buf, 303414439467246543595250775667605759171, .little);
                break :s buf;
            };
            const b2_neg_s = comptime s: {
                var buf: [32]u8 = undefined;
                mem.writeInt(u256, &buf, scalar.field_order - 64502973549206556628585045361533709077, .little);
                break :s buf;
            };
            const k = mem.readInt(u256, &s, endian);

            const t1 = math.mulWide(u256, k, 21949224512762693861512883645436906316123769664773102907882521278123970637873);
            const t2 = math.mulWide(u256, k, 103246583619904461035481197785446227098457807945486720222659797044629401272177);

            const c1 = @as(u128, @truncate(t1 >> 384)) + @as(u1, @truncate(t1 >> 383));
            const c2 = @as(u128, @truncate(t2 >> 384)) + @as(u1, @truncate(t2 >> 383));

            var buf: [32]u8 = undefined;

            mem.writeInt(u256, &buf, c1, .little);
            const c1x = try scalar.mul(buf, b1_neg_s, .little);

            mem.writeInt(u256, &buf, c2, .little);
            const c2x = try scalar.mul(buf, b2_neg_s, .little);

            const r2 = try scalar.add(c1x, c2x, .little);

            var r1 = try scalar.mul(r2, lambda_s, .little);
            r1 = try scalar.sub(s, r1, .little);

            return SplitScalar{ .r1 = r1, .r2 = r2 };
        }
    };

    /// Reject the neutral element.
    pub fn rejectIdentity(p: Secp256k1) IdentityElementError!void {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) & (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        if (is_identity != 0) {
            return error.IdentityElement;
        }
    }

    /// Create a point from affine coordinates after checking that they match the curve equation.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!Secp256k1 {
        const x = p.x;
        const y = p.y;
        const x3B = x.sq().mul(x).add(B);
        const yy = y.sq();
        const on_curve = @intFromBool(x3B.equivalent(yy));
        const is_identity = @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) & @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
        if ((on_curve | is_identity) == 0) {
            return error.InvalidEncoding;
        }
        var ret = Secp256k1{ .x = x, .y = y, .z = Fe.one };
        ret.z.cMov(Secp256k1.identityElement.z, is_identity);
        return ret;
    }

    /// Create a point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [32]u8, ys: [32]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!Secp256k1 {
        const x = try Fe.fromBytes(xs, endian);
        const y = try Fe.fromBytes(ys, endian);
        return fromAffineCoordinates(.{ .x = x, .y = y });
    }

    /// Recover the Y coordinate from the X coordinate.
    pub fn recoverY(x: Fe, is_odd: bool) NotSquareError!Fe {
        const x3B = x.sq().mul(x).add(B);
        var y = try x3B.sqrt();
        const yn = y.neg();
        y.cMov(yn, @intFromBool(is_odd) ^ @intFromBool(y.isOdd()));
        return y;
    }

    /// Deserialize a SEC1-encoded point.
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!Secp256k1 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoding_type = s[0];
        const encoded = s[1..];
        switch (encoding_type) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return Secp256k1.identityElement;
            },
            2, 3 => {
                if (encoded.len != 32) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y_is_odd = (encoding_type == 3);
                const y = try recoverY(x, y_is_odd);
                return Secp256k1{ .x = x, .y = y };
            },
            4 => {
                if (encoded.len != 64) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y = try Fe.fromBytes(encoded[32..64].*, .big);
                return Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y });
            },
            else => return error.InvalidEncoding,
        }
    }

    /// Serialize a point using the compressed SEC-1 format.
    pub fn toCompressedSec1(p: Secp256k1) [33]u8 {
        var out: [33]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Serialize a point using the uncompressed SEC-1 format.
    pub fn toUncompressedSec1(p: Secp256k1) [65]u8 {
        var out: [65]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..33].* = xy.x.toBytes(.big);
        out[33..65].* = xy.y.toBytes(.big);
        return out;
    }

    /// Return a random point.
    pub fn random() Secp256k1 {
        const n = scalar.random(.little);
        return basePoint.mul(n, .little) catch unreachable;
    }

    /// Flip the sign of the X coordinate.
    pub fn neg(p: Secp256k1) Secp256k1 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// Double a secp256k1 point.
    // Algorithm 9 from https://eprint.iacr.org/2015/1060.pdf
    pub fn dbl(p: Secp256k1) Secp256k1 {
        var t0 = p.y.sq();
        var Z3 = t0.dbl();
        Z3 = Z3.dbl();
        Z3 = Z3.dbl();
        var t1 = p.y.mul(p.z);
        var t2 = p.z.sq();
        // b3 = (2^2)^2 + 2^2 + 1
        const t2_4 = t2.dbl().dbl();
        t2 = t2_4.dbl().dbl().add(t2_4).add(t2);
        var X3 = t2.mul(Z3);
        var Y3 = t0.add(t2);
        Z3 = t1.mul(Z3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        t0 = t0.sub(t2);
        Y3 = t0.mul(Y3);
        Y3 = X3.add(Y3);
        t1 = p.x.mul(p.y);
        X3 = t0.mul(t1);
        X3 = X3.dbl();
        return .{
            .x = X3,
            .y = Y3,
            .z = Z3,
        };
    }

    /// Add secp256k1 points, the second being specified using affine coordinates.
    // Algorithm 8 from https://eprint.iacr.org/2015/1060.pdf
    pub fn addMixed(p: Secp256k1, q: AffineCoordinates) Secp256k1 {
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
        var X3 = t0.dbl();
        t0 = X3.add(t0);
        // b3 = (2^2)^2 + 2^2 + 1
        const t2_4 = p.z.dbl().dbl();
        var t2 = t2_4.dbl().dbl().add(t2_4).add(p.z);
        var Z3 = t1.add(t2);
        t1 = t1.sub(t2);
        const Y3_4 = Y3.dbl().dbl();
        Y3 = Y3_4.dbl().dbl().add(Y3_4).add(Y3);
        X3 = t4.mul(Y3);
        t2 = t3.mul(t1);
        X3 = t2.sub(X3);
        Y3 = Y3.mul(t0);
        t1 = t1.mul(Z3);
        Y3 = t1.add(Y3);
        t0 = t0.mul(t3);
        Z3 = Z3.mul(t4);
        Z3 = Z3.add(t0);

        var ret = Secp256k1{
            .x = X3,
            .y = Y3,
            .z = Z3,
        };
        ret.cMov(p, @intFromBool(q.x.isZero()));
        return ret;
    }

    /// Add secp256k1 points.
    // Algorithm 7 from https://eprint.iacr.org/2015/1060.pdf
    pub fn add(p: Secp256k1, q: Secp256k1) Secp256k1 {
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
        X3 = t0.dbl();
        t0 = X3.add(t0);
        // b3 = (2^2)^2 + 2^2 + 1
        const t2_4 = t2.dbl().dbl();
        t2 = t2_4.dbl().dbl().add(t2_4).add(t2);
        var Z3 = t1.add(t2);
        t1 = t1.sub(t2);
        const Y3_4 = Y3.dbl().dbl();
        Y3 = Y3_4.dbl().dbl().add(Y3_4).add(Y3);
        X3 = t4.mul(Y3);
        t2 = t3.mul(t1);
        X3 = t2.sub(X3);
        Y3 = Y3.mul(t0);
        t1 = t1.mul(Z3);
        Y3 = t1.add(Y3);
        t0 = t0.mul(t3);
        Z3 = Z3.mul(t4);
        Z3 = Z3.add(t0);

        return .{
            .x = X3,
            .y = Y3,
            .z = Z3,
        };
    }

    /// Subtract secp256k1 points.
    pub fn sub(p: Secp256k1, q: Secp256k1) Secp256k1 {
        return p.add(q.neg());
    }

    /// Subtract secp256k1 points, the second being specified using affine coordinates.
    pub fn subMixed(p: Secp256k1, q: AffineCoordinates) Secp256k1 {
        return p.addMixed(q.neg());
    }

    /// Return affine coordinates.
    pub fn affineCoordinates(p: Secp256k1) AffineCoordinates {
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
    pub fn equivalent(a: Secp256k1, b: Secp256k1) bool {
        if (a.sub(b).rejectIdentity()) {
            return false;
        } else |_| {
            return true;
        }
    }

    fn cMov(p: *Secp256k1, a: Secp256k1, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    fn pcSelect(comptime n: usize, pc: *const [n]Secp256k1, b: u8) Secp256k1 {
        var t = Secp256k1.identityElement;
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

    fn pcMul(pc: *const [9]Secp256k1, s: [32]u8, comptime vartime: bool) IdentityElementError!Secp256k1 {
        std.debug.assert(vartime);
        const e = slide(s);
        var q = Secp256k1.identityElement;
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

    fn pcMul16(pc: *const [16]Secp256k1, s: [32]u8, comptime vartime: bool) IdentityElementError!Secp256k1 {
        var q = Secp256k1.identityElement;
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

    fn precompute(p: Secp256k1, comptime count: usize) [1 + count]Secp256k1 {
        var pc: [1 + count]Secp256k1 = undefined;
        pc[0] = Secp256k1.identityElement;
        pc[1] = p;
        var i: usize = 2;
        while (i <= count) : (i += 1) {
            pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
        }
        return pc;
    }

    const basePointPc = pc: {
        @setEvalBranchQuota(50000);
        break :pc precompute(Secp256k1.basePoint, 15);
    };

    /// Multiply an elliptic curve point by a scalar.
    /// Return error.IdentityElement if the result is the identity element.
    pub fn mul(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
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
    pub fn mulPublic(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) (IdentityElementError || NonCanonicalError)!Secp256k1 {
        const s = if (endian == .little) s_ else Fe.orderSwap(s_);
        const zero = comptime scalar.Scalar.zero.toBytes(.little);
        if (mem.eql(u8, &zero, &s)) {
            return error.IdentityElement;
        }
        const pc = precompute(p, 8);
        var lambda_p = try pcMul(&pc, Endormorphism.lambda_s, true);
        var split_scalar = try Endormorphism.splitScalar(s, .little);
        var px = p;

        // If a key is negative, flip the sign to keep it half-sized,
        // and flip the sign of the Y point coordinate to compensate.
        if (split_scalar.r1[split_scalar.r1.len / 2] != 0) {
            split_scalar.r1 = scalar.neg(split_scalar.r1, .little) catch zero;
            px = px.neg();
        }
        if (split_scalar.r2[split_scalar.r2.len / 2] != 0) {
            split_scalar.r2 = scalar.neg(split_scalar.r2, .little) catch zero;
            lambda_p = lambda_p.neg();
        }
        return mulDoubleBasePublicEndo(px, split_scalar.r1, lambda_p, split_scalar.r2);
    }

    // Half-size double-base public multiplication when using the curve endomorphism.
    // Scalars must be in little-endian.
    // The second point is unlikely to be the generator, so don't even try to use the comptime table for it.
    fn mulDoubleBasePublicEndo(p1: Secp256k1, s1: [32]u8, p2: Secp256k1, s2: [32]u8) IdentityElementError!Secp256k1 {
        var pc1_array: [9]Secp256k1 = undefined;
        const pc1 = if (p1.is_base) basePointPc[0..9] else pc: {
            pc1_array = precompute(p1, 8);
            break :pc &pc1_array;
        };
        const pc2 = precompute(p2, 8);
        std.debug.assert(s1[s1.len / 2] == 0);
        std.debug.assert(s2[s2.len / 2] == 0);
        const e1 = slide(s1);
        const e2 = slide(s2);
        var q = Secp256k1.identityElement;
        var pos: usize = 2 * 32 / 2; // second half is all zero
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

    /// Double-base multiplication of public parameters - Compute (p1*s1)+(p2*s2) *IN VARIABLE TIME*
    /// This can be used for signature verification.
    pub fn mulDoubleBasePublic(p1: Secp256k1, s1_: [32]u8, p2: Secp256k1, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        const s1 = if (endian == .little) s1_ else Fe.orderSwap(s1_);
        const s2 = if (endian == .little) s2_ else Fe.orderSwap(s2_);
        try p1.rejectIdentity();
        var pc1_array: [9]Secp256k1 = undefined;
        const pc1 = if (p1.is_base) basePointPc[0..9] else pc: {
            pc1_array = precompute(p1, 8);
            break :pc &pc1_array;
        };
        try p2.rejectIdentity();
        var pc2_array: [9]Secp256k1 = undefined;
        const pc2 = if (p2.is_base) basePointPc[0..9] else pc: {
            pc2_array = precompute(p2, 8);
            break :pc &pc2_array;
        };
        const e1 = slide(s1);
        const e2 = slide(s2);
        var q = Secp256k1.identityElement;
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
    x: Secp256k1.Fe,
    y: Secp256k1.Fe,

    /// Identity element in affine coordinates.
    pub const identityElement = AffineCoordinates{ .x = Secp256k1.identityElement.x, .y = Secp256k1.identityElement.y };

    fn cMov(p: *AffineCoordinates, a: AffineCoordinates, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
    }
};

test {
    if (@import("builtin").zig_backend == .stage2_c) return error.SkipZigTest;

    _ = @import("tests/secp256k1.zig");
}
const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("secp256k1_64.zig"),
    .field_order = 115792089237316195423570985008687907853269984665640564039457584007908834671663,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});
const std = @import("std");
const common = @import("../common.zig");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;

const Field = common.Field;

const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// Number of bytes required to encode a scalar.
pub const encoded_length = 32;

/// A compressed scalar, in canonical form.
pub const CompressedScalar = [encoded_length]u8;

const Fe = Field(.{
    .fiat = @import("secp256k1_scalar_64.zig"),
    .field_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = encoded_length,
});

/// The scalar field order.
pub const field_order = Fe.field_order;

/// Reject a scalar whose encoding is not canonical.
pub fn rejectNonCanonical(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!void {
    return Fe.rejectNonCanonical(s, endian);
}

/// Reduce a 48-bytes scalar to the field size.
pub fn reduce48(s: [48]u8, endian: std.builtin.Endian) CompressedScalar {
    return Scalar.fromBytes48(s, endian).toBytes(endian);
}

/// Reduce a 64-bytes scalar to the field size.
pub fn reduce64(s: [64]u8, endian: std.builtin.Endian) CompressedScalar {
    return Scalar.fromBytes64(s, endian).toBytes(endian);
}

/// Return a*b (mod L)
pub fn mul(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return a*b+c (mod L)
pub fn mulAdd(a: CompressedScalar, b: CompressedScalar, c: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).add(try Scalar.fromBytes(c, endian)).toBytes(endian);
}

/// Return a+b (mod L)
pub fn add(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).add(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return -s (mod L)
pub fn neg(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(s, endian)).neg().toBytes(endian);
}

/// Return (a-b) (mod L)
pub fn sub(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).sub(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return a random scalar
pub fn random(endian: std.builtin.Endian) CompressedScalar {
    return Scalar.random().toBytes(endian);
}

/// A scalar in unpacked representation.
pub const Scalar = struct {
    fe: Fe,

    /// Zero.
    pub const zero = Scalar{ .fe = Fe.zero };

    /// One.
    pub const one = Scalar{ .fe = Fe.one };

    /// Unpack a serialized representation of a scalar.
    pub fn fromBytes(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!Scalar {
        return Scalar{ .fe = try Fe.fromBytes(s, endian) };
    }

    /// Reduce a 384 bit input to the field size.
    pub fn fromBytes48(s: [48]u8, endian: std.builtin.Endian) Scalar {
        const t = ScalarDouble.fromBytes(384, s, endian);
        return t.reduce(384);
    }

    /// Reduce a 512 bit input to the field size.
    pub fn fromBytes64(s: [64]u8, endian: std.builtin.Endian) Scalar {
        const t = ScalarDouble.fromBytes(512, s, endian);
        return t.reduce(512);
    }

    /// Pack a scalar into bytes.
    pub fn toBytes(n: Scalar, endian: std.builtin.Endian) CompressedScalar {
        return n.fe.toBytes(endian);
    }

    /// Return true if the scalar is zero..
    pub fn isZero(n: Scalar) bool {
        return n.fe.isZero();
    }

    /// Return true if the scalar is odd.
    pub fn isOdd(n: Scalar) bool {
        return n.fe.isOdd();
    }

    /// Return true if a and b are equivalent.
    pub fn equivalent(a: Scalar, b: Scalar) bool {
        return a.fe.equivalent(b.fe);
    }

    /// Compute x+y (mod L)
    pub fn add(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.add(y.fe) };
    }

    /// Compute x-y (mod L)
    pub fn sub(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.sub(y.fe) };
    }

    /// Compute 2n (mod L)
    pub fn dbl(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.dbl() };
    }

    /// Compute x*y (mod L)
    pub fn mul(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.mul(y.fe) };
    }

    /// Compute x^2 (mod L)
    pub fn sq(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.sq() };
    }

    /// Compute x^n (mod L)
    pub fn pow(a: Scalar, comptime T: type, comptime n: T) Scalar {
        return Scalar{ .fe = a.fe.pow(n) };
    }

    /// Compute -x (mod L)
    pub fn neg(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.neg() };
    }

    /// Compute x^-1 (mod L)
    pub fn invert(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.invert() };
    }

    /// Return true if n is a quadratic residue mod L.
    pub fn isSquare(n: Scalar) bool {
        return n.fe.isSquare();
    }

    /// Return the square root of L, or NotSquare if there isn't any solutions.
    pub fn sqrt(n: Scalar) NotSquareError!Scalar {
        return Scalar{ .fe = try n.fe.sqrt() };
    }

    /// Return a random scalar < L.
    pub fn random() Scalar {
        var s: [48]u8 = undefined;
        while (true) {
            crypto.random.bytes(&s);
            const n = Scalar.fromBytes48(s, .little);
            if (!n.isZero()) {
                return n;
            }
        }
    }
};

const ScalarDouble = struct {
    x1: Fe,
    x2: Fe,
    x3: Fe,

    fn fromBytes(comptime bits: usize, s_: [bits / 8]u8, endian: std.builtin.Endian) ScalarDouble {
        debug.assert(bits > 0 and bits <= 512 and bits >= Fe.saturated_bits and bits <= Fe.saturated_bits * 3);

        var s = s_;
        if (endian == .big) {
            for (s_, 0..) |x, i| s[s.len - 1 - i] = x;
        }
        var t = ScalarDouble{ .x1 = undefined, .x2 = Fe.zero, .x3 = Fe.zero };
        {
            var b = [_]u8{0} ** encoded_length;
            const len = @min(s.len, 24);
            b[0..len].* = s[0..len].*;
            t.x1 = Fe.fromBytes(b, .little) catch unreachable;
        }
        if (s_.len >= 24) {
            var b = [_]u8{0} ** encoded_length;
            const len = @min(s.len - 24, 24);
            b[0..len].* = s[24..][0..len].*;
            t.x2 = Fe.fromBytes(b, .little) catch unreachable;
        }
        if (s_.len >= 48) {
            var b = [_]u8{0} ** encoded_length;
            const len = s.len - 48;
            b[0..len].* = s[48..][0..len].*;
            t.x3 = Fe.fromBytes(b, .little) catch unreachable;
        }
        return t;
    }

    fn reduce(expanded: ScalarDouble, comptime bits: usize) Scalar {
        debug.assert(bits > 0 and bits <= Fe.saturated_bits * 3 and bits <= 512);
        var fe = expanded.x1;
        if (bits >= 192) {
            const st1 = Fe.fromInt(1 << 192) catch unreachable;
            fe = fe.add(expanded.x2.mul(st1));
            if (bits >= 384) {
                const st2 = st1.sq();
                fe = fe.add(expanded.x3.mul(st2));
            }
        }
        return Scalar{ .fe = fe };
    }
};
// Autogenerated: 'src/ExtractionOCaml/word_by_word_montgomery' --lang Zig --internal-static --public-function-case camelCase --private-function-case camelCase --public-type-case UpperCamelCase --private-type-case UpperCamelCase --no-prefix-fiat --package-name secp256k1 '' 64 '2^256 - 2^32 - 977' mul square add sub opp from_montgomery to_montgomery nonzero selectznz to_bytes from_bytes one msat divstep divstep_precomp
// curve description (via package name): secp256k1
// machine_wordsize = 64 (from "64")
// requested operations: mul, square, add, sub, opp, from_montgomery, to_montgomery, nonzero, selectznz, to_bytes, from_bytes, one, msat, divstep, divstep_precomp
// m = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f (from "2^256 - 2^32 - 977")
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
//   bytes_eval z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24) + (z[4] << 32) + (z[5] << 40) + (z[6] << 48) + (z[7] << 56) + (z[8] << 64) + (z[9] << 72) + (z[10] << 80) + (z[11] << 88) + (z[12] << 96) + (z[13] << 104) + (z[14] << 112) + (z[15] << 120) + (z[16] << 128) + (z[17] << 136) + (z[18] << 144) + (z[19] << 152) + (z[20] << 160) + (z[21] << 168) + (z[22] << 176) + (z[23] << 184) + (z[24] << 192) + (z[25] << 200) + (z[26] << 208) + (z[27] << 216) + (z[28] << 224) + (z[29] << 232) + (z[30] << 240) + (z[31] << 248)
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
    mulxU64(&x20, &x21, x11, 0xd838091dd2253531);
    var x22: u64 = undefined;
    var x23: u64 = undefined;
    mulxU64(&x22, &x23, x20, 0xffffffffffffffff);
    var x24: u64 = undefined;
    var x25: u64 = undefined;
    mulxU64(&x24, &x25, x20, 0xffffffffffffffff);
    var x26: u64 = undefined;
    var x27: u64 = undefined;
    mulxU64(&x26, &x27, x20, 0xffffffffffffffff);
    var x28: u64 = undefined;
    var x29: u64 = undefined;
    mulxU64(&x28, &x29, x20, 0xfffffffefffffc2f);
    var x30: u64 = undefined;
    var x31: u1 = undefined;
    addcarryxU64(&x30, &x31, 0x0, x29, x26);
    var x32: u64 = undefined;
    var x33: u1 = undefined;
    addcarryxU64(&x32, &x33, x31, x27, x24);
    var x34: u64 = undefined;
    var x35: u1 = undefined;
    addcarryxU64(&x34, &x35, x33, x25, x22);
    const x36 = (@as(u64, x35) + x23);
    var x37: u64 = undefined;
    var x38: u1 = undefined;
    addcarryxU64(&x37, &x38, 0x0, x11, x28);
    var x39: u64 = undefined;
    var x40: u1 = undefined;
    addcarryxU64(&x39, &x40, x38, x13, x30);
    var x41: u64 = undefined;
    var x42: u1 = undefined;
    addcarryxU64(&x41, &x42, x40, x15, x32);
    var x43: u64 = undefined;
    var x44: u1 = undefined;
    addcarryxU64(&x43, &x44, x42, x17, x34);
    var x45: u64 = undefined;
    var x46: u1 = undefined;
    addcarryxU64(&x45, &x46, x44, x19, x36);
    var x47: u64 = undefined;
    var x48: u64 = undefined;
    mulxU64(&x47, &x48, x1, (arg2[3]));
    var x49: u64 = undefined;
    var x50: u64 = undefined;
    mulxU64(&x49, &x50, x1, (arg2[2]));
    var x51: u64 = undefined;
    var x52: u64 = undefined;
    mulxU64(&x51, &x52, x1, (arg2[1]));
    var x53: u64 = undefined;
    var x54: u64 = undefined;
    mulxU64(&x53, &x54, x1, (arg2[0]));
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    addcarryxU64(&x55, &x56, 0x0, x54, x51);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    addcarryxU64(&x57, &x58, x56, x52, x49);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    addcarryxU64(&x59, &x60, x58, x50, x47);
    const x61 = (@as(u64, x60) + x48);
    var x62: u64 = undefined;
    var x63: u1 = undefined;
    addcarryxU64(&x62, &x63, 0x0, x39, x53);
    var x64: u64 = undefined;
    var x65: u1 = undefined;
    addcarryxU64(&x64, &x65, x63, x41, x55);
    var x66: u64 = undefined;
    var x67: u1 = undefined;
    addcarryxU64(&x66, &x67, x65, x43, x57);
    var x68: u64 = undefined;
    var x69: u1 = undefined;
    addcarryxU64(&x68, &x69, x67, x45, x59);
    var x70: u64 = undefined;
    var x71: u1 = undefined;
    addcarryxU64(&x70, &x71, x69, @as(u64, x46), x61);
    var x72: u64 = undefined;
    var x73: u64 = undefined;
    mulxU64(&x72, &x73, x62, 0xd838091dd2253531);
    var x74: u64 = undefined;
    var x75: u64 = undefined;
    mulxU64(&x74, &x75, x72, 0xffffffffffffffff);
    var x76: u64 = undefined;
    var x77: u64 = undefined;
    mulxU64(&x76, &x77, x72, 0xffffffffffffffff);
    var x78: u64 = undefined;
    var x79: u64 = undefined;
    mulxU64(&x78, &x79, x72, 0xffffffffffffffff);
    var x80: u64 = undefined;
    var x81: u64 = undefined;
    mulxU64(&x80, &x81, x72, 0xfffffffefffffc2f);
    var x82: u64 = undefined;
    var x83: u1 = undefined;
    addcarryxU64(&x82, &x83, 0x0, x81, x78);
    var x84: u64 = undefined;
    var x85: u1 = undefined;
    addcarryxU64(&x84, &x85, x83, x79, x76);
    var x86: u64 = undefined;
    var x87: u1 = undefined;
    addcarryxU64(&x86, &x87, x85, x77, x74);
    const x88 = (@as(u64, x87) + x75);
    var x89: u64 = undefined;
    var x90: u1 = undefined;
    addcarryxU64(&x89, &x90, 0x0, x62, x80);
    var x91: u64 = undefined;
    var x92: u1 = undefined;
    addcarryxU64(&x91, &x92, x90, x64, x82);
    var x93: u64 = undefined;
    var x94: u1 = undefined;
    addcarryxU64(&x93, &x94, x92, x66, x84);
    var x95: u64 = undefined;
    var x96: u1 = undefined;
    addcarryxU64(&x95, &x96, x94, x68, x86);
    var x97: u64 = undefined;
    var x98: u1 = undefined;
    addcarryxU64(&x97, &x98, x96, x70, x88);
    const x99 = (@as(u64, x98) + @as(u64, x71));
    var x100: u64 = undefined;
    var x101: u64 = undefined;
    mulxU64(&x100, &x101, x2, (arg2[3]));
    var x102: u64 = undefined;
    var x103: u64 = undefined;
    mulxU64(&x102, &x103, x2, (arg2[2]));
    var x104: u64 = undefined;
    var x105: u64 = undefined;
    mulxU64(&x104, &x105, x2, (arg2[1]));
    var x106: u64 = undefined;
    var x107: u64 = undefined;
    mulxU64(&x106, &x107, x2, (arg2[0]));
    var x108: u64 = undefined;
    var x109: u1 = undefined;
    addcarryxU64(&x108, &x109, 0x0, x107, x104);
    var x110: u64 = undefined;
    var x111: u1 = undefined;
    addcarryxU64(&x110, &x111, x109, x105, x102);
    var x112: u64 = undefined;
    var x113: u1 = undefined;
    addcarryxU64(&x112, &x113, x111, x103, x100);
    const x114 = (@as(u64, x113) + x101);
    var x115: u64 = undefined;
    var x116: u1 = undefined;
    addcarryxU64(&x115, &x116, 0x0, x91, x106);
    var x117: u64 = undefined;
    var x118: u1 = undefined;
    addcarryxU64(&x117, &x118, x116, x93, x108);
    var x119: u64 = undefined;
    var x120: u1 = undefined;
    addcarryxU64(&x119, &x120, x118, x95, x110);
    var x121: u64 = undefined;
    var x122: u1 = undefined;
    addcarryxU64(&x121, &x122, x120, x97, x112);
    var x123: u64 = undefined;
    var x124: u1 = undefined;
    addcarryxU64(&x123, &x124, x122, x99, x114);
    var x125: u64 = undefined;
    var x126: u64 = undefined;
    mulxU64(&x125, &x126, x115, 0xd838091dd2253531);
    var x127: u64 = undefined;
    var x128: u64 = undefined;
    mulxU64(&x127, &x128, x125, 0xffffffffffffffff);
    var x129: u64 = undefined;
    var x130: u64 = undefined;
    mulxU64(&x129, &x130, x125, 0xffffffffffffffff);
    var x131: u64 = undefined;
    var x132: u64 = undefined;
    mulxU64(&x131, &x132, x125, 0xffffffffffffffff);
    var x133: u64 = undefined;
    var x134: u64 = undefined;
    mulxU64(&x133, &x134, x125, 0xfffffffefffffc2f);
    var x135: u64 = undefined;
    var x136: u1 = undefined;
    addcarryxU64(&x135, &x136, 0x0, x134, x131);
    var x137: u64 = undefined;
    var x138: u1 = undefined;
    addcarryxU64(&x137, &x138, x136, x132, x129);
    var x139: u64 = undefined;
    var x140: u1 = undefined;
    addcarryxU64(&x139, &x140, x138, x130, x127);
    const x141 = (@as(u64, x140) + x128);
    var x142: u64 = undefined;
    var x143: u1 = undefined;
    addcarryxU64(&x142, &x143, 0x0, x115, x133);
    var x144: u64 = undefined;
    var x145: u1 = undefined;
    addcarryxU64(&x144, &x145, x143, x117, x135);
    var x146: u64 = undefined;
    var x147: u1 = undefined;
    addcarryxU64(&x146, &x147, x145, x119, x137);
    var x148: u64 = undefined;
    var x149: u1 = undefined;
    addcarryxU64(&x148, &x149, x147, x121, x139);
    var x150: u64 = undefined;
    var x151: u1 = undefined;
    addcarryxU64(&x150, &x151, x149, x123, x141);
    const x152 = (@as(u64, x151) + @as(u64, x124));
    var x153: u64 = undefined;
    var x154: u64 = undefined;
    mulxU64(&x153, &x154, x3, (arg2[3]));
    var x155: u64 = undefined;
    var x156: u64 = undefined;
    mulxU64(&x155, &x156, x3, (arg2[2]));
    var x157: u64 = undefined;
    var x158: u64 = undefined;
    mulxU64(&x157, &x158, x3, (arg2[1]));
    var x159: u64 = undefined;
    var x160: u64 = undefined;
    mulxU64(&x159, &x160, x3, (arg2[0]));
    var x161: u64 = undefined;
    var x162: u1 = undefined;
    addcarryxU64(&x161, &x162, 0x0, x160, x157);
    var x163: u64 = undefined;
    var x164: u1 = undefined;
    addcarryxU64(&x163, &x164, x162, x158, x155);
    var x165: u64 = undefined;
    var x166: u1 = undefined;
    addcarryxU64(&x165, &x166, x164, x156, x153);
    const x167 = (@as(u64, x166) + x154);
    var x168: u64 = undefined;
    var x169: u1 = undefined;
    addcarryxU64(&x168, &x169, 0x0, x144, x159);
    var x170: u64 = undefined;
    var x171: u1 = undefined;
    addcarryxU64(&x170, &x171, x169, x146, x161);
    var x172: u64 = undefined;
    var x173: u1 = undefined;
    addcarryxU64(&x172, &x173, x171, x148, x163);
    var x174: u64 = undefined;
    var x175: u1 = undefined;
    addcarryxU64(&x174, &x175, x173, x150, x165);
    var x176: u64 = undefined;
    var x177: u1 = undefined;
    addcarryxU64(&x176, &x177, x175, x152, x167);
    var x178: u64 = undefined;
    var x179: u64 = undefined;
    mulxU64(&x178, &x179, x168, 0xd838091dd2253531);
    var x180: u64 = undefined;
    var x181: u64 = undefined;
    mulxU64(&x180, &x181, x178, 0xffffffffffffffff);
    var x182: u64 = undefined;
    var x183: u64 = undefined;
    mulxU64(&x182, &x183, x178, 0xffffffffffffffff);
    var x184: u64 = undefined;
    var x185: u64 = undefined;
    mulxU64(&x184, &x185, x178, 0xffffffffffffffff);
    var x186: u64 = undefined;
    var x187: u64 = undefined;
    mulxU64(&x186, &x187, x178, 0xfffffffefffffc2f);
    var x188: u64 = undefined;
    var x189: u1 = undefined;
    addcarryxU64(&x188, &x189, 0x0, x187, x184);
    var x190: u64 = undefined;
    var x191: u1 = undefined;
    addcarryxU64(&x190, &x191, x189, x185, x182);
    var x192: u64 = undefined;
    var x193: u1 = undefined;
    addcarryxU64(&x192, &x193, x191, x183, x180);
    const x194 = (@as(u64, x193) + x181);
    var x195: u64 = undefined;
    var x196: u1 = undefined;
    addcarryxU64(&x195, &x196, 0x0, x168, x186);
    var x197: u64 = undefined;
    var x198: u1 = undefined;
    addcarryxU64(&x197, &x198, x196, x170, x188);
    var x199: u64 = undefined;
    var x200: u1 = undefined;
    addcarryxU64(&x199, &x200, x198, x172, x190);
    var x201: u64 = undefined;
    var x202: u1 = undefined;
    addcarryxU64(&x201, &x202, x200, x174, x192);
    var x203: u64 = undefined;
    var x204: u1 = undefined;
    addcarryxU64(&x203, &x204, x202, x176, x194);
    const x205 = (@as(u64, x204) + @as(u64, x177));
    var x206: u64 = undefined;
    var x207: u1 = undefined;
    subborrowxU64(&x206, &x207, 0x0, x197, 0xfffffffefffffc2f);
    var x208: u64 = undefined;
    var x209: u1 = undefined;
    subborrowxU64(&x208, &x209, x207, x199, 0xffffffffffffffff);
    var x210: u64 = undefined;
    var x211: u1 = undefined;
    subborrowxU64(&x210, &x211, x209, x201, 0xffffffffffffffff);
    var x212: u64 = undefined;
    var x213: u1 = undefined;
    subborrowxU64(&x212, &x213, x211, x203, 0xffffffffffffffff);
    var x214: u64 = undefined;
    var x215: u1 = undefined;
    subborrowxU64(&x214, &x215, x213, x205, 0x0);
    var x216: u64 = undefined;
    cmovznzU64(&x216, x215, x206, x197);
    var x217: u64 = undefined;
    cmovznzU64(&x217, x215, x208, x199);
    var x218: u64 = undefined;
    cmovznzU64(&x218, x215, x210, x201);
    var x219: u64 = undefined;
    cmovznzU64(&x219, x215, x212, x203);
    out1[0] = x216;
    out1[1] = x217;
    out1[2] = x218;
    out1[3] = x219;
}

/// The function square squares a field element in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg1)) mod m
///   0 ≤ eval out1 < m
///
pub fn square(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = (arg1[1]);
    const x2 = (arg1[2]);
    const x3 = (arg1[3]);
    const x4 = (arg1[0]);
    var x5: u64 = undefined;
    var x6: u64 = undefined;
    mulxU64(&x5, &x6, x4, (arg1[3]));
    var x7: u64 = undefined;
    var x8: u64 = undefined;
    mulxU64(&x7, &x8, x4, (arg1[2]));
    var x9: u64 = undefined;
    var x10: u64 = undefined;
    mulxU64(&x9, &x10, x4, (arg1[1]));
    var x11: u64 = undefined;
    var x12: u64 = undefined;
    mulxU64(&x11, &x12, x4, (arg1[0]));
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
    mulxU64(&x20, &x21, x11, 0xd838091dd2253531);
    var x22: u64 = undefined;
    var x23: u64 = undefined;
    mulxU64(&x22, &x23, x20, 0xffffffffffffffff);
    var x24: u64 = undefined;
    var x25: u64 = undefined;
    mulxU64(&x24, &x25, x20, 0xffffffffffffffff);
    var x26: u64 = undefined;
    var x27: u64 = undefined;
    mulxU64(&x26, &x27, x20, 0xffffffffffffffff);
    var x28: u64 = undefined;
    var x29: u64 = undefined;
    mulxU64(&x28, &x29, x20, 0xfffffffefffffc2f);
    var x30: u64 = undefined;
    var x31: u1 = undefined;
    addcarryxU64(&x30, &x31, 0x0, x29, x26);
    var x32: u64 = undefined;
    var x33: u1 = undefined;
    addcarryxU64(&x32, &x33, x31, x27, x24);
    var x34: u64 = undefined;
    var x35: u1 = undefined;
    addcarryxU64(&x34, &x35, x33, x25, x22);
    const x36 = (@as(u64, x35) + x23);
    var x37: u64 = undefined;
    var x38: u1 = undefined;
    addcarryxU64(&x37, &x38, 0x0, x11, x28);
    var x39: u64 = undefined;
    var x40: u1 = undefined;
    addcarryxU64(&x39, &x40, x38, x13, x30);
    var x41: u64 = undefined;
    var x42: u1 = undefined;
    addcarryxU64(&x41, &x42, x40, x15, x32);
    var x43: u64 = undefined;
    var x44: u1 = undefined;
    addcarryxU64(&x43, &x44, x42, x17, x34);
    var x45: u64 = undefined;
    var x46: u1 = undefined;
    addcarryxU64(&x45, &x46, x44, x19, x36);
    var x47: u64 = undefined;
    var x48: u64 = undefined;
    mulxU64(&x47, &x48, x1, (arg1[3]));
    var x49: u64 = undefined;
    var x50: u64 = undefined;
    mulxU64(&x49, &x50, x1, (arg1[2]));
    var x51: u64 = undefined;
    var x52: u64 = undefined;
    mulxU64(&x51, &x52, x1, (arg1[1]));
    var x53: u64 = undefined;
    var x54: u64 = undefined;
    mulxU64(&x53, &x54, x1, (arg1[0]));
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    addcarryxU64(&x55, &x56, 0x0, x54, x51);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    addcarryxU64(&x57, &x58, x56, x52, x49);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    addcarryxU64(&x59, &x60, x58, x50, x47);
    const x61 = (@as(u64, x60) + x48);
    var x62: u64 = undefined;
    var x63: u1 = undefined;
    addcarryxU64(&x62, &x63, 0x0, x39, x53);
    var x64: u64 = undefined;
    var x65: u1 = undefined;
    addcarryxU64(&x64, &x65, x63, x41, x55);
    var x66: u64 = undefined;
    var x67: u1 = undefined;
    addcarryxU64(&x66, &x67, x65, x43, x57);
    var x68: u64 = undefined;
    var x69: u1 = undefined;
    addcarryxU64(&x68, &x69, x67, x45, x59);
    var x70: u64 = undefined;
    var x71: u1 = undefined;
    addcarryxU64(&x70, &x71, x69, @as(u64, x46), x61);
    var x72: u64 = undefined;
    var x73: u64 = undefined;
    mulxU64(&x72, &x73, x62, 0xd838091dd2253531);
    var x74: u64 = undefined;
    var x75: u64 = undefined;
    mulxU64(&x74, &x75, x72, 0xffffffffffffffff);
    var x76: u64 = undefined;
    var x77: u64 = undefined;
    mulxU64(&x76, &x77, x72, 0xffffffffffffffff);
    var x78: u64 = undefined;
    var x79: u64 = undefined;
    mulxU64(&x78, &x79, x72, 0xffffffffffffffff);
    var x80: u64 = undefined;
    var x81: u64 = undefined;
    mulxU64(&x80, &x81, x72, 0xfffffffefffffc2f);
    var x82: u64 = undefined;
    var x83: u1 = undefined;
    addcarryxU64(&x82, &x83, 0x0, x81, x78);
    var x84: u64 = undefined;
    var x85: u1 = undefined;
    addcarryxU64(&x84, &x85, x83, x79, x76);
    var x86: u64 = undefined;
    var x87: u1 = undefined;
    addcarryxU64(&x86, &x87, x85, x77, x74);
    const x88 = (@as(u64, x87) + x75);
    var x89: u64 = undefined;
    var x90: u1 = undefined;
    addcarryxU64(&x89, &x90, 0x0, x62, x80);
    var x91: u64 = undefined;
    var x92: u1 = undefined;
    addcarryxU64(&x91, &x92, x90, x64, x82);
    var x93: u64 = undefined;
    var x94: u1 = undefined;
    addcarryxU64(&x93, &x94, x92, x66, x84);
    var x95: u64 = undefined;
    var x96: u1 = undefined;
    addcarryxU64(&x95, &x96, x94, x68, x86);
    var x97: u64 = undefined;
    var x98: u1 = undefined;
    addcarryxU64(&x97, &x98, x96, x70, x88);
    const x99 = (@as(u64, x98) + @as(u64, x71));
    var x100: u64 = undefined;
    var x101: u64 = undefined;
    mulxU64(&x100, &x101, x2, (arg1[3]));
    var x102: u64 = undefined;
    var x103: u64 = undefined;
    mulxU64(&x102, &x103, x2, (arg1[2]));
    var x104: u64 = undefined;
    var x105: u64 = undefined;
    mulxU64(&x104, &x105, x2, (arg1[1]));
    var x106: u64 = undefined;
    var x107: u64 = undefined;
    mulxU64(&x106, &x107, x2, (arg1[0]));
    var x108: u64 = undefined;
    var x109: u1 = undefined;
    addcarryxU64(&x108, &x109, 0x0, x107, x104);
    var x110: u64 = undefined;
    var x111: u1 = undefined;
    addcarryxU64(&x110, &x111, x109, x105, x102);
    var x112: u64 = undefined;
    var x113: u1 = undefined;
    addcarryxU64(&x112, &x113, x111, x103, x100);
    const x114 = (@as(u64, x113) + x101);
    var x115: u64 = undefined;
    var x116: u1 = undefined;
    addcarryxU64(&x115, &x116, 0x0, x91, x106);
    var x117: u64 = undefined;
    var x118: u1 = undefined;
    addcarryxU64(&x117, &x118, x116, x93, x108);
    var x119: u64 = undefined;
    var x120: u1 = undefined;
    addcarryxU64(&x119, &x120, x118, x95, x110);
    var x121: u64 = undefined;
    var x122: u1 = undefined;
    addcarryxU64(&x121, &x122, x120, x97, x112);
    var x123: u64 = undefined;
    var x124: u1 = undefined;
    addcarryxU64(&x123, &x124, x122, x99, x114);
    var x125: u64 = undefined;
    var x126: u64 = undefined;
    mulxU64(&x125, &x126, x115, 0xd838091dd2253531);
    var x127: u64 = undefined;
    var x128: u64 = undefined;
    mulxU64(&x127, &x128, x125, 0xffffffffffffffff);
    var x129: u64 = undefined;
    var x130: u64 = undefined;
    mulxU64(&x129, &x130, x125, 0xffffffffffffffff);
    var x131: u64 = undefined;
    var x132: u64 = undefined;
    mulxU64(&x131, &x132, x125, 0xffffffffffffffff);
    var x133: u64 = undefined;
    var x134: u64 = undefined;
    mulxU64(&x133, &x134, x125, 0xfffffffefffffc2f);
    var x135: u64 = undefined;
    var x136: u1 = undefined;
    addcarryxU64(&x135, &x136, 0x0, x134, x131);
    var x137: u64 = undefined;
    var x138: u1 = undefined;
    addcarryxU64(&x137, &x138, x136, x132, x129);
    var x139: u64 = undefined;
    var x140: u1 = undefined;
    addcarryxU64(&x139, &x140, x138, x130, x127);
    const x141 = (@as(u64, x140) + x128);
    var x142: u64 = undefined;
    var x143: u1 = undefined;
    addcarryxU64(&x142, &x143, 0x0, x115, x133);
    var x144: u64 = undefined;
    var x145: u1 = undefined;
    addcarryxU64(&x144, &x145, x143, x117, x135);
    var x146: u64 = undefined;
    var x147: u1 = undefined;
    addcarryxU64(&x146, &x147, x145, x119, x137);
    var x148: u64 = undefined;
    var x149: u1 = undefined;
    addcarryxU64(&x148, &x149, x147, x121, x139);
    var x150: u64 = undefined;
    var x151: u1 = undefined;
    addcarryxU64(&x150, &x151, x149, x123, x141);
    const x152 = (@as(u64, x151) + @as(u64, x124));
    var x153: u64 = undefined;
    var x154: u64 = undefined;
    mulxU64(&x153, &x154, x3, (arg1[3]));
    var x155: u64 = undefined;
    var x156: u64 = undefined;
    mulxU64(&x155, &x156, x3, (arg1[2]));
    var x157: u64 = undefined;
    var x158: u64 = undefined;
    mulxU64(&x157, &x158, x3, (arg1[1]));
    var x159: u64 = undefined;
    var x160: u64 = undefined;
    mulxU64(&x159, &x160, x3, (arg1[0]));
    var x161: u64 = undefined;
    var x162: u1 = undefined;
    addcarryxU64(&x161, &x162, 0x0, x160, x157);
    var x163: u64 = undefined;
    var x164: u1 = undefined;
    addcarryxU64(&x163, &x164, x162, x158, x155);
    var x165: u64 = undefined;
    var x166: u1 = undefined;
    addcarryxU64(&x165, &x166, x164, x156, x153);
    const x167 = (@as(u64, x166) + x154);
    var x168: u64 = undefined;
    var x169: u1 = undefined;
    addcarryxU64(&x168, &x169, 0x0, x144, x159);
    var x170: u64 = undefined;
    var x171: u1 = undefined;
    addcarryxU64(&x170, &x171, x169, x146, x161);
    var x172: u64 = undefined;
    var x173: u1 = undefined;
    addcarryxU64(&x172, &x173, x171, x148, x163);
    var x174: u64 = undefined;
    var x175: u1 = undefined;
    addcarryxU64(&x174, &x175, x173, x150, x165);
    var x176: u64 = undefined;
    var x177: u1 = undefined;
    addcarryxU64(&x176, &x177, x175, x152, x167);
    var x178: u64 = undefined;
    var x179: u64 = undefined;
    mulxU64(&x178, &x179, x168, 0xd838091dd2253531);
    var x180: u64 = undefined;
    var x181: u64 = undefined;
    mulxU64(&x180, &x181, x178, 0xffffffffffffffff);
    var x182: u64 = undefined;
    var x183: u64 = undefined;
    mulxU64(&x182, &x183, x178, 0xffffffffffffffff);
    var x184: u64 = undefined;
    var x185: u64 = undefined;
    mulxU64(&x184, &x185, x178, 0xffffffffffffffff);
    var x186: u64 = undefined;
    var x187: u64 = undefined;
    mulxU64(&x186, &x187, x178, 0xfffffffefffffc2f);
    var x188: u64 = undefined;
    var x189: u1 = undefined;
    addcarryxU64(&x188, &x189, 0x0, x187, x184);
    var x190: u64 = undefined;
    var x191: u1 = undefined;
    addcarryxU64(&x190, &x191, x189, x185, x182);
    var x192: u64 = undefined;
    var x193: u1 = undefined;
    addcarryxU64(&x192, &x193, x191, x183, x180);
    const x194 = (@as(u64, x193) + x181);
    var x195: u64 = undefined;
    var x196: u1 = undefined;
    addcarryxU64(&x195, &x196, 0x0, x168, x186);
    var x197: u64 = undefined;
    var x198: u1 = undefined;
    addcarryxU64(&x197, &x198, x196, x170, x188);
    var x199: u64 = undefined;
    var x200: u1 = undefined;
    addcarryxU64(&x199, &x200, x198, x172, x190);
    var x201: u64 = undefined;
    var x202: u1 = undefined;
    addcarryxU64(&x201, &x202, x200, x174, x192);
    var x203: u64 = undefined;
    var x204: u1 = undefined;
    addcarryxU64(&x203, &x204, x202, x176, x194);
    const x205 = (@as(u64, x204) + @as(u64, x177));
    var x206: u64 = undefined;
    var x207: u1 = undefined;
    subborrowxU64(&x206, &x207, 0x0, x197, 0xfffffffefffffc2f);
    var x208: u64 = undefined;
    var x209: u1 = undefined;
    subborrowxU64(&x208, &x209, x207, x199, 0xffffffffffffffff);
    var x210: u64 = undefined;
    var x211: u1 = undefined;
    subborrowxU64(&x210, &x211, x209, x201, 0xffffffffffffffff);
    var x212: u64 = undefined;
    var x213: u1 = undefined;
    subborrowxU64(&x212, &x213, x211, x203, 0xffffffffffffffff);
    var x214: u64 = undefined;
    var x215: u1 = undefined;
    subborrowxU64(&x214, &x215, x213, x205, 0x0);
    var x216: u64 = undefined;
    cmovznzU64(&x216, x215, x206, x197);
    var x217: u64 = undefined;
    cmovznzU64(&x217, x215, x208, x199);
    var x218: u64 = undefined;
    cmovznzU64(&x218, x215, x210, x201);
    var x219: u64 = undefined;
    cmovznzU64(&x219, x215, x212, x203);
    out1[0] = x216;
    out1[1] = x217;
    out1[2] = x218;
    out1[3] = x219;
}

/// The function add adds two field elements in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) + eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
///
pub fn add(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement, arg2: MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    var x1: u64 = undefined;
    var x2: u1 = undefined;
    addcarryxU64(&x1, &x2, 0x0, (arg1[0]), (arg2[0]));
    var x3: u64 = undefined;
    var x4: u1 = undefined;
    addcarryxU64(&x3, &x4, x2, (arg1[1]), (arg2[1]));
    var x5: u64 = undefined;
    var x6: u1 = undefined;
    addcarryxU64(&x5, &x6, x4, (arg1[2]), (arg2[2]));
    var x7: u64 = undefined;
    var x8: u1 = undefined;
    addcarryxU64(&x7, &x8, x6, (arg1[3]), (arg2[3]));
    var x9: u64 = undefined;
    var x10: u1 = undefined;
    subborrowxU64(&x9, &x10, 0x0, x1, 0xfffffffefffffc2f);
    var x11: u64 = undefined;
    var x12: u1 = undefined;
    subborrowxU64(&x11, &x12, x10, x3, 0xffffffffffffffff);
    var x13: u64 = undefined;
    var x14: u1 = undefined;
    subborrowxU64(&x13, &x14, x12, x5, 0xffffffffffffffff);
    var x15: u64 = undefined;
    var x16: u1 = undefined;
    subborrowxU64(&x15, &x16, x14, x7, 0xffffffffffffffff);
    var x17: u64 = undefined;
    var x18: u1 = undefined;
    subborrowxU64(&x17, &x18, x16, @as(u64, x8), 0x0);
    var x19: u64 = undefined;
    cmovznzU64(&x19, x18, x9, x1);
    var x20: u64 = undefined;
    cmovznzU64(&x20, x18, x11, x3);
    var x21: u64 = undefined;
    cmovznzU64(&x21, x18, x13, x5);
    var x22: u64 = undefined;
    cmovznzU64(&x22, x18, x15, x7);
    out1[0] = x19;
    out1[1] = x20;
    out1[2] = x21;
    out1[3] = x22;
}

/// The function sub subtracts two field elements in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) - eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
///
pub fn sub(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement, arg2: MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    var x1: u64 = undefined;
    var x2: u1 = undefined;
    subborrowxU64(&x1, &x2, 0x0, (arg1[0]), (arg2[0]));
    var x3: u64 = undefined;
    var x4: u1 = undefined;
    subborrowxU64(&x3, &x4, x2, (arg1[1]), (arg2[1]));
    var x5: u64 = undefined;
    var x6: u1 = undefined;
    subborrowxU64(&x5, &x6, x4, (arg1[2]), (arg2[2]));
    var x7: u64 = undefined;
    var x8: u1 = undefined;
    subborrowxU64(&x7, &x8, x6, (arg1[3]), (arg2[3]));
    var x9: u64 = undefined;
    cmovznzU64(&x9, x8, 0x0, 0xffffffffffffffff);
    var x10: u64 = undefined;
    var x11: u1 = undefined;
    addcarryxU64(&x10, &x11, 0x0, x1, (x9 & 0xfffffffefffffc2f));
    var x12: u64 = undefined;
    var x13: u1 = undefined;
    addcarryxU64(&x12, &x13, x11, x3, x9);
    var x14: u64 = undefined;
    var x15: u1 = undefined;
    addcarryxU64(&x14, &x15, x13, x5, x9);
    var x16: u64 = undefined;
    var x17: u1 = undefined;
    addcarryxU64(&x16, &x17, x15, x7, x9);
    out1[0] = x10;
    out1[1] = x12;
    out1[2] = x14;
    out1[3] = x16;
}

/// The function opp negates a field element in the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = -eval (from_montgomery arg1) mod m
///   0 ≤ eval out1 < m
///
pub fn opp(out1: *MontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    var x1: u64 = undefined;
    var x2: u1 = undefined;
    subborrowxU64(&x1, &x2, 0x0, 0x0, (arg1[0]));
    var x3: u64 = undefined;
    var x4: u1 = undefined;
    subborrowxU64(&x3, &x4, x2, 0x0, (arg1[1]));
    var x5: u64 = undefined;
    var x6: u1 = undefined;
    subborrowxU64(&x5, &x6, x4, 0x0, (arg1[2]));
    var x7: u64 = undefined;
    var x8: u1 = undefined;
    subborrowxU64(&x7, &x8, x6, 0x0, (arg1[3]));
    var x9: u64 = undefined;
    cmovznzU64(&x9, x8, 0x0, 0xffffffffffffffff);
    var x10: u64 = undefined;
    var x11: u1 = undefined;
    addcarryxU64(&x10, &x11, 0x0, x1, (x9 & 0xfffffffefffffc2f));
    var x12: u64 = undefined;
    var x13: u1 = undefined;
    addcarryxU64(&x12, &x13, x11, x3, x9);
    var x14: u64 = undefined;
    var x15: u1 = undefined;
    addcarryxU64(&x14, &x15, x13, x5, x9);
    var x16: u64 = undefined;
    var x17: u1 = undefined;
    addcarryxU64(&x16, &x17, x15, x7, x9);
    out1[0] = x10;
    out1[1] = x12;
    out1[2] = x14;
    out1[3] = x16;
}

/// The function fromMontgomery translates a field element out of the Montgomery domain.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   eval out1 mod m = (eval arg1 * ((2^64)⁻¹ mod m)^4) mod m
///   0 ≤ eval out1 < m
///
pub fn fromMontgomery(out1: *NonMontgomeryDomainFieldElement, arg1: MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = (arg1[0]);
    var x2: u64 = undefined;
    var x3: u64 = undefined;
    mulxU64(&x2, &x3, x1, 0xd838091dd2253531);
    var x4: u64 = undefined;
    var x5: u64 = undefined;
    mulxU64(&x4, &x5, x2, 0xffffffffffffffff);
    var x6: u64 = undefined;
    var x7: u64 = undefined;
    mulxU64(&x6, &x7, x2, 0xffffffffffffffff);
    var x8: u64 = undefined;
    var x9: u64 = undefined;
    mulxU64(&x8, &x9, x2, 0xffffffffffffffff);
    var x10: u64 = undefined;
    var x11: u64 = undefined;
    mulxU64(&x10, &x11, x2, 0xfffffffefffffc2f);
    var x12: u64 = undefined;
    var x13: u1 = undefined;
    addcarryxU64(&x12, &x13, 0x0, x11, x8);
    var x14: u64 = undefined;
    var x15: u1 = undefined;
    addcarryxU64(&x14, &x15, x13, x9, x6);
    var x16: u64 = undefined;
    var x17: u1 = undefined;
    addcarryxU64(&x16, &x17, x15, x7, x4);
    var x18: u64 = undefined;
    var x19: u1 = undefined;
    addcarryxU64(&x18, &x19, 0x0, x1, x10);
    var x20: u64 = undefined;
    var x21: u1 = undefined;
    addcarryxU64(&x20, &x21, x19, 0x0, x12);
    var x22: u64 = undefined;
    var x23: u1 = undefined;
    addcarryxU64(&x22, &x23, x21, 0x0, x14);
    var x24: u64 = undefined;
    var x25: u1 = undefined;
    addcarryxU64(&x24, &x25, x23, 0x0, x16);
    var x26: u64 = undefined;
    var x27: u1 = undefined;
    addcarryxU64(&x26, &x27, x25, 0x0, (@as(u64, x17) + x5));
    var x28: u64 = undefined;
    var x29: u1 = undefined;
    addcarryxU64(&x28, &x29, 0x0, x20, (arg1[1]));
    var x30: u64 = undefined;
    var x31: u1 = undefined;
    addcarryxU64(&x30, &x31, x29, x22, 0x0);
    var x32: u64 = undefined;
    var x33: u1 = undefined;
    addcarryxU64(&x32, &x33, x31, x24, 0x0);
    var x34: u64 = undefined;
    var x35: u1 = undefined;
    addcarryxU64(&x34, &x35, x33, x26, 0x0);
    var x36: u64 = undefined;
    var x37: u64 = undefined;
    mulxU64(&x36, &x37, x28, 0xd838091dd2253531);
    var x38: u64 = undefined;
    var x39: u64 = undefined;
    mulxU64(&x38, &x39, x36, 0xffffffffffffffff);
    var x40: u64 = undefined;
    var x41: u64 = undefined;
    mulxU64(&x40, &x41, x36, 0xffffffffffffffff);
    var x42: u64 = undefined;
    var x43: u64 = undefined;
    mulxU64(&x42, &x43, x36, 0xffffffffffffffff);
    var x44: u64 = undefined;
    var x45: u64 = undefined;
    mulxU64(&x44, &x45, x36, 0xfffffffefffffc2f);
    var x46: u64 = undefined;
    var x47: u1 = undefined;
    addcarryxU64(&x46, &x47, 0x0, x45, x42);
    var x48: u64 = undefined;
    var x49: u1 = undefined;
    addcarryxU64(&x48, &x49, x47, x43, x40);
    var x50: u64 = undefined;
    var x51: u1 = undefined;
    addcarryxU64(&x50, &x51, x49, x41, x38);
    var x52: u64 = undefined;
    var x53: u1 = undefined;
    addcarryxU64(&x52, &x53, 0x0, x28, x44);
    var x54: u64 = undefined;
    var x55: u1 = undefined;
    addcarryxU64(&x54, &x55, x53, x30, x46);
    var x56: u64 = undefined;
    var x57: u1 = undefined;
    addcarry```
