```
ed;
    var x34: u1 = undefined;
    addcarryxU64(&x33, &x34, x32, x24, x21);
    var x35: u64 = undefined;
    var x36: u1 = undefined;
    addcarryxU64(&x35, &x36, 0x0, x11, x27);
    var x37: u64 = undefined;
    var x38: u1 = undefined;
    addcarryxU64(&x37, &x38, x36, x13, x29);
    var x39: u64 = undefined;
    var x40: u1 = undefined;
    addcarryxU64(&x39, &x40, x38, x15, x31);
    var x41: u64 = undefined;
    var x42: u1 = undefined;
    addcarryxU64(&x41, &x42, x40, x17, x33);
    var x43: u64 = undefined;
    var x44: u1 = undefined;
    addcarryxU64(&x43, &x44, x42, (@as(u64, x18) + x6), (@as(u64, x34) + x22));
    var x45: u64 = undefined;
    var x46: u64 = undefined;
    mulxU64(&x45, &x46, x1, 0x66e12d94f3d95620);
    var x47: u64 = undefined;
    var x48: u64 = undefined;
    mulxU64(&x47, &x48, x1, 0x2845b2392b6bec59);
    var x49: u64 = undefined;
    var x50: u64 = undefined;
    mulxU64(&x49, &x50, x1, 0x4699799c49bd6fa6);
    var x51: u64 = undefined;
    var x52: u64 = undefined;
    mulxU64(&x51, &x52, x1, 0x83244c95be79eea2);
    var x53: u64 = undefined;
    var x54: u1 = undefined;
    addcarryxU64(&x53, &x54, 0x0, x52, x49);
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    addcarryxU64(&x55, &x56, x54, x50, x47);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    addcarryxU64(&x57, &x58, x56, x48, x45);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    addcarryxU64(&x59, &x60, 0x0, x37, x51);
    var x61: u64 = undefined;
    var x62: u1 = undefined;
    addcarryxU64(&x61, &x62, x60, x39, x53);
    var x63: u64 = undefined;
    var x64: u1 = undefined;
    addcarryxU64(&x63, &x64, x62, x41, x55);
    var x65: u64 = undefined;
    var x66: u1 = undefined;
    addcarryxU64(&x65, &x66, x64, x43, x57);
    var x67: u64 = undefined;
    var x68: u64 = undefined;
    mulxU64(&x67, &x68, x59, 0xccd1c8aaee00bc4f);
    var x69: u64 = undefined;
    var x70: u64 = undefined;
    mulxU64(&x69, &x70, x67, 0xffffffff00000000);
    var x71: u64 = undefined;
    var x72: u64 = undefined;
    mulxU64(&x71, &x72, x67, 0xffffffffffffffff);
    var x73: u64 = undefined;
    var x74: u64 = undefined;
    mulxU64(&x73, &x74, x67, 0xbce6faada7179e84);
    var x75: u64 = undefined;
    var x76: u64 = undefined;
    mulxU64(&x75, &x76, x67, 0xf3b9cac2fc632551);
    var x77: u64 = undefined;
    var x78: u1 = undefined;
    addcarryxU64(&x77, &x78, 0x0, x76, x73);
    var x79: u64 = undefined;
    var x80: u1 = undefined;
    addcarryxU64(&x79, &x80, x78, x74, x71);
    var x81: u64 = undefined;
    var x82: u1 = undefined;
    addcarryxU64(&x81, &x82, x80, x72, x69);
    var x83: u64 = undefined;
    var x84: u1 = undefined;
    addcarryxU64(&x83, &x84, 0x0, x59, x75);
    var x85: u64 = undefined;
    var x86: u1 = undefined;
    addcarryxU64(&x85, &x86, x84, x61, x77);
    var x87: u64 = undefined;
    var x88: u1 = undefined;
    addcarryxU64(&x87, &x88, x86, x63, x79);
    var x89: u64 = undefined;
    var x90: u1 = undefined;
    addcarryxU64(&x89, &x90, x88, x65, x81);
    var x91: u64 = undefined;
    var x92: u1 = undefined;
    addcarryxU64(&x91, &x92, x90, ((@as(u64, x66) + @as(u64, x44)) + (@as(u64, x58) + x46)), (@as(u64, x82) + x70));
    var x93: u64 = undefined;
    var x94: u64 = undefined;
    mulxU64(&x93, &x94, x2, 0x66e12d94f3d95620);
    var x95: u64 = undefined;
    var x96: u64 = undefined;
    mulxU64(&x95, &x96, x2, 0x2845b2392b6bec59);
    var x97: u64 = undefined;
    var x98: u64 = undefined;
    mulxU64(&x97, &x98, x2, 0x4699799c49bd6fa6);
    var x99: u64 = undefined;
    var x100: u64 = undefined;
    mulxU64(&x99, &x100, x2, 0x83244c95be79eea2);
    var x101: u64 = undefined;
    var x102: u1 = undefined;
    addcarryxU64(&x101, &x102, 0x0, x100, x97);
    var x103: u64 = undefined;
    var x104: u1 = undefined;
    addcarryxU64(&x103, &x104, x102, x98, x95);
    var x105: u64 = undefined;
    var x106: u1 = undefined;
    addcarryxU64(&x105, &x106, x104, x96, x93);
    var x107: u64 = undefined;
    var x108: u1 = undefined;
    addcarryxU64(&x107, &x108, 0x0, x85, x99);
    var x109: u64 = undefined;
    var x110: u1 = undefined;
    addcarryxU64(&x109, &x110, x108, x87, x101);
    var x111: u64 = undefined;
    var x112: u1 = undefined;
    addcarryxU64(&x111, &x112, x110, x89, x103);
    var x113: u64 = undefined;
    var x114: u1 = undefined;
    addcarryxU64(&x113, &x114, x112, x91, x105);
    var x115: u64 = undefined;
    var x116: u64 = undefined;
    mulxU64(&x115, &x116, x107, 0xccd1c8aaee00bc4f);
    var x117: u64 = undefined;
    var x118: u64 = undefined;
    mulxU64(&x117, &x118, x115, 0xffffffff00000000);
    var x119: u64 = undefined;
    var x120: u64 = undefined;
    mulxU64(&x119, &x120, x115, 0xffffffffffffffff);
    var x121: u64 = undefined;
    var x122: u64 = undefined;
    mulxU64(&x121, &x122, x115, 0xbce6faada7179e84);
    var x123: u64 = undefined;
    var x124: u64 = undefined;
    mulxU64(&x123, &x124, x115, 0xf3b9cac2fc632551);
    var x125: u64 = undefined;
    var x126: u1 = undefined;
    addcarryxU64(&x125, &x126, 0x0, x124, x121);
    var x127: u64 = undefined;
    var x128: u1 = undefined;
    addcarryxU64(&x127, &x128, x126, x122, x119);
    var x129: u64 = undefined;
    var x130: u1 = undefined;
    addcarryxU64(&x129, &x130, x128, x120, x117);
    var x131: u64 = undefined;
    var x132: u1 = undefined;
    addcarryxU64(&x131, &x132, 0x0, x107, x123);
    var x133: u64 = undefined;
    var x134: u1 = undefined;
    addcarryxU64(&x133, &x134, x132, x109, x125);
    var x135: u64 = undefined;
    var x136: u1 = undefined;
    addcarryxU64(&x135, &x136, x134, x111, x127);
    var x137: u64 = undefined;
    var x138: u1 = undefined;
    addcarryxU64(&x137, &x138, x136, x113, x129);
    var x139: u64 = undefined;
    var x140: u1 = undefined;
    addcarryxU64(&x139, &x140, x138, ((@as(u64, x114) + @as(u64, x92)) + (@as(u64, x106) + x94)), (@as(u64, x130) + x118));
    var x141: u64 = undefined;
    var x142: u64 = undefined;
    mulxU64(&x141, &x142, x3, 0x66e12d94f3d95620);
    var x143: u64 = undefined;
    var x144: u64 = undefined;
    mulxU64(&x143, &x144, x3, 0x2845b2392b6bec59);
    var x145: u64 = undefined;
    var x146: u64 = undefined;
    mulxU64(&x145, &x146, x3, 0x4699799c49bd6fa6);
    var x147: u64 = undefined;
    var x148: u64 = undefined;
    mulxU64(&x147, &x148, x3, 0x83244c95be79eea2);
    var x149: u64 = undefined;
    var x150: u1 = undefined;
    addcarryxU64(&x149, &x150, 0x0, x148, x145);
    var x151: u64 = undefined;
    var x152: u1 = undefined;
    addcarryxU64(&x151, &x152, x150, x146, x143);
    var x153: u64 = undefined;
    var x154: u1 = undefined;
    addcarryxU64(&x153, &x154, x152, x144, x141);
    var x155: u64 = undefined;
    var x156: u1 = undefined;
    addcarryxU64(&x155, &x156, 0x0, x133, x147);
    var x157: u64 = undefined;
    var x158: u1 = undefined;
    addcarryxU64(&x157, &x158, x156, x135, x149);
    var x159: u64 = undefined;
    var x160: u1 = undefined;
    addcarryxU64(&x159, &x160, x158, x137, x151);
    var x161: u64 = undefined;
    var x162: u1 = undefined;
    addcarryxU64(&x161, &x162, x160, x139, x153);
    var x163: u64 = undefined;
    var x164: u64 = undefined;
    mulxU64(&x163, &x164, x155, 0xccd1c8aaee00bc4f);
    var x165: u64 = undefined;
    var x166: u64 = undefined;
    mulxU64(&x165, &x166, x163, 0xffffffff00000000);
    var x167: u64 = undefined;
    var x168: u64 = undefined;
    mulxU64(&x167, &x168, x163, 0xffffffffffffffff);
    var x169: u64 = undefined;
    var x170: u64 = undefined;
    mulxU64(&x169, &x170, x163, 0xbce6faada7179e84);
    var x171: u64 = undefined;
    var x172: u64 = undefined;
    mulxU64(&x171, &x172, x163, 0xf3b9cac2fc632551);
    var x173: u64 = undefined;
    var x174: u1 = undefined;
    addcarryxU64(&x173, &x174, 0x0, x172, x169);
    var x175: u64 = undefined;
    var x176: u1 = undefined;
    addcarryxU64(&x175, &x176, x174, x170, x167);
    var x177: u64 = undefined;
    var x178: u1 = undefined;
    addcarryxU64(&x177, &x178, x176, x168, x165);
    var x179: u64 = undefined;
    var x180: u1 = undefined;
    addcarryxU64(&x179, &x180, 0x0, x155, x171);
    var x181: u64 = undefined;
    var x182: u1 = undefined;
    addcarryxU64(&x181, &x182, x180, x157, x173);
    var x183: u64 = undefined;
    var x184: u1 = undefined;
    addcarryxU64(&x183, &x184, x182, x159, x175);
    var x185: u64 = undefined;
    var x186: u1 = undefined;
    addcarryxU64(&x185, &x186, x184, x161, x177);
    var x187: u64 = undefined;
    var x188: u1 = undefined;
    addcarryxU64(&x187, &x188, x186, ((@as(u64, x162) + @as(u64, x140)) + (@as(u64, x154) + x142)), (@as(u64, x178) + x166));
    var x189: u64 = undefined;
    var x190: u1 = undefined;
    subborrowxU64(&x189, &x190, 0x0, x181, 0xf3b9cac2fc632551);
    var x191: u64 = undefined;
    var x192: u1 = undefined;
    subborrowxU64(&x191, &x192, x190, x183, 0xbce6faada7179e84);
    var x193: u64 = undefined;
    var x194: u1 = undefined;
    subborrowxU64(&x193, &x194, x192, x185, 0xffffffffffffffff);
    var x195: u64 = undefined;
    var x196: u1 = undefined;
    subborrowxU64(&x195, &x196, x194, x187, 0xffffffff00000000);
    var x197: u64 = undefined;
    var x198: u1 = undefined;
    subborrowxU64(&x197, &x198, x196, @as(u64, x188), @as(u64, 0x0));
    var x199: u64 = undefined;
    cmovznzU64(&x199, x198, x189, x181);
    var x200: u64 = undefined;
    cmovznzU64(&x200, x198, x191, x183);
    var x201: u64 = undefined;
    cmovznzU64(&x201, x198, x193, x185);
    var x202: u64 = undefined;
    cmovznzU64(&x202, x198, x195, x187);
    out1[0] = x199;
    out1[1] = x200;
    out1[2] = x201;
    out1[3] = x202;
}

/// The function nonzero outputs a single non-zero word if the input is non-zero and zero otherwise.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   out1 = 0 ↔ eval (from_montgomery arg1) mod m = 0
///
/// Input Bounds:
///   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [0x0 ~> 0xffffffffffffffff]
pub fn nonzero(out1: *u64, arg1: [4]u64) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = ((arg1[0]) | ((arg1[1]) | ((arg1[2]) | (arg1[3]))));
    out1.* = x1;
}

/// The function selectznz is a multi-limb conditional select.
///
/// Postconditions:
///   eval out1 = (if arg1 = 0 then eval arg2 else eval arg3)
///
/// Input Bounds:
///   arg1: [0x0 ~> 0x1]
///   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
///   arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn selectznz(out1: *[4]u64, arg1: u1, arg2: [4]u64, arg3: [4]u64) void {
    @setRuntimeSafety(mode == .Debug);

    var x1: u64 = undefined;
    cmovznzU64(&x1, arg1, (arg2[0]), (arg3[0]));
    var x2: u64 = undefined;
    cmovznzU64(&x2, arg1, (arg2[1]), (arg3[1]));
    var x3: u64 = undefined;
    cmovznzU64(&x3, arg1, (arg2[2]), (arg3[2]));
    var x4: u64 = undefined;
    cmovznzU64(&x4, arg1, (arg2[3]), (arg3[3]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
}

/// The function toBytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
///
/// Preconditions:
///   0 ≤ eval arg1 < m
/// Postconditions:
///   out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..31]
///
/// Input Bounds:
///   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
pub fn toBytes(out1: *[32]u8, arg1: [4]u64) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = (arg1[3]);
    const x2 = (arg1[2]);
    const x3 = (arg1[1]);
    const x4 = (arg1[0]);
    const x5 = @as(u8, @truncate((x4 & @as(u64, 0xff))));
    const x6 = (x4 >> 8);
    const x7 = @as(u8, @truncate((x6 & @as(u64, 0xff))));
    const x8 = (x6 >> 8);
    const x9 = @as(u8, @truncate((x8 & @as(u64, 0xff))));
    const x10 = (x8 >> 8);
    const x11 = @as(u8, @truncate((x10 & @as(u64, 0xff))));
    const x12 = (x10 >> 8);
    const x13 = @as(u8, @truncate((x12 & @as(u64, 0xff))));
    const x14 = (x12 >> 8);
    const x15 = @as(u8, @truncate((x14 & @as(u64, 0xff))));
    const x16 = (x14 >> 8);
    const x17 = @as(u8, @truncate((x16 & @as(u64, 0xff))));
    const x18 = @as(u8, @truncate((x16 >> 8)));
    const x19 = @as(u8, @truncate((x3 & @as(u64, 0xff))));
    const x20 = (x3 >> 8);
    const x21 = @as(u8, @truncate((x20 & @as(u64, 0xff))));
    const x22 = (x20 >> 8);
    const x23 = @as(u8, @truncate((x22 & @as(u64, 0xff))));
    const x24 = (x22 >> 8);
    const x25 = @as(u8, @truncate((x24 & @as(u64, 0xff))));
    const x26 = (x24 >> 8);
    const x27 = @as(u8, @truncate((x26 & @as(u64, 0xff))));
    const x28 = (x26 >> 8);
    const x29 = @as(u8, @truncate((x28 & @as(u64, 0xff))));
    const x30 = (x28 >> 8);
    const x31 = @as(u8, @truncate((x30 & @as(u64, 0xff))));
    const x32 = @as(u8, @truncate((x30 >> 8)));
    const x33 = @as(u8, @truncate((x2 & @as(u64, 0xff))));
    const x34 = (x2 >> 8);
    const x35 = @as(u8, @truncate((x34 & @as(u64, 0xff))));
    const x36 = (x34 >> 8);
    const x37 = @as(u8, @truncate((x36 & @as(u64, 0xff))));
    const x38 = (x36 >> 8);
    const x39 = @as(u8, @truncate((x38 & @as(u64, 0xff))));
    const x40 = (x38 >> 8);
    const x41 = @as(u8, @truncate((x40 & @as(u64, 0xff))));
    const x42 = (x40 >> 8);
    const x43 = @as(u8, @truncate((x42 & @as(u64, 0xff))));
    const x44 = (x42 >> 8);
    const x45 = @as(u8, @truncate((x44 & @as(u64, 0xff))));
    const x46 = @as(u8, @truncate((x44 >> 8)));
    const x47 = @as(u8, @truncate((x1 & @as(u64, 0xff))));
    const x48 = (x1 >> 8);
    const x49 = @as(u8, @truncate((x48 & @as(u64, 0xff))));
    const x50 = (x48 >> 8);
    const x51 = @as(u8, @truncate((x50 & @as(u64, 0xff))));
    const x52 = (x50 >> 8);
    const x53 = @as(u8, @truncate((x52 & @as(u64, 0xff))));
    const x54 = (x52 >> 8);
    const x55 = @as(u8, @truncate((x54 & @as(u64, 0xff))));
    const x56 = (x54 >> 8);
    const x57 = @as(u8, @truncate((x56 & @as(u64, 0xff))));
    const x58 = (x56 >> 8);
    const x59 = @as(u8, @truncate((x58 & @as(u64, 0xff))));
    const x60 = @as(u8, @truncate((x58 >> 8)));
    out1[0] = x5;
    out1[1] = x7;
    out1[2] = x9;
    out1[3] = x11;
    out1[4] = x13;
    out1[5] = x15;
    out1[6] = x17;
    out1[7] = x18;
    out1[8] = x19;
    out1[9] = x21;
    out1[10] = x23;
    out1[11] = x25;
    out1[12] = x27;
    out1[13] = x29;
    out1[14] = x31;
    out1[15] = x32;
    out1[16] = x33;
    out1[17] = x35;
    out1[18] = x37;
    out1[19] = x39;
    out1[20] = x41;
    out1[21] = x43;
    out1[22] = x45;
    out1[23] = x46;
    out1[24] = x47;
    out1[25] = x49;
    out1[26] = x51;
    out1[27] = x53;
    out1[28] = x55;
    out1[29] = x57;
    out1[30] = x59;
    out1[31] = x60;
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
///   arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn fromBytes(out1: *[4]u64, arg1: [32]u8) void {
    @setRuntimeSafety(mode == .Debug);

    const x1 = (@as(u64, (arg1[31])) << 56);
    const x2 = (@as(u64, (arg1[30])) << 48);
    const x3 = (@as(u64, (arg1[29])) << 40);
    const x4 = (@as(u64, (arg1[28])) << 32);
    const x5 = (@as(u64, (arg1[27])) << 24);
    const x6 = (@as(u64, (arg1[26])) << 16);
    const x7 = (@as(u64, (arg1[25])) << 8);
    const x8 = (arg1[24]);
    const x9 = (@as(u64, (arg1[23])) << 56);
    const x10 = (@as(u64, (arg1[22])) << 48);
    const x11 = (@as(u64, (arg1[21])) << 40);
    const x12 = (@as(u64, (arg1[20])) << 32);
    const x13 = (@as(u64, (arg1[19])) << 24);
    const x14 = (@as(u64, (arg1[18])) << 16);
    const x15 = (@as(u64, (arg1[17])) << 8);
    const x16 = (arg1[16]);
    const x17 = (@as(u64, (arg1[15])) << 56);
    const x18 = (@as(u64, (arg1[14])) << 48);
    const x19 = (@as(u64, (arg1[13])) << 40);
    const x20 = (@as(u64, (arg1[12])) << 32);
    const x21 = (@as(u64, (arg1[11])) << 24);
    const x22 = (@as(u64, (arg1[10])) << 16);
    const x23 = (@as(u64, (arg1[9])) << 8);
    const x24 = (arg1[8]);
    const x25 = (@as(u64, (arg1[7])) << 56);
    const x26 = (@as(u64, (arg1[6])) << 48);
    const x27 = (@as(u64, (arg1[5])) << 40);
    const x28 = (@as(u64, (arg1[4])) << 32);
    const x29 = (@as(u64, (arg1[3])) << 24);
    const x30 = (@as(u64, (arg1[2])) << 16);
    const x31 = (@as(u64, (arg1[1])) << 8);
    const x32 = (arg1[0]);
    const x33 = (x31 + @as(u64, x32));
    const x34 = (x30 + x33);
    const x35 = (x29 + x34);
    const x36 = (x28 + x35);
    const x37 = (x27 + x36);
    const x38 = (x26 + x37);
    const x39 = (x25 + x38);
    const x40 = (x23 + @as(u64, x24));
    const x41 = (x22 + x40);
    const x42 = (x21 + x41);
    const x43 = (x20 + x42);
    const x44 = (x19 + x43);
    const x45 = (x18 + x44);
    const x46 = (x17 + x45);
    const x47 = (x15 + @as(u64, x16));
    const x48 = (x14 + x47);
    const x49 = (x13 + x48);
    const x50 = (x12 + x49);
    const x51 = (x11 + x50);
    const x52 = (x10 + x51);
    const x53 = (x9 + x52);
    const x54 = (x7 + @as(u64, x8));
    const x55 = (x6 + x54);
    const x56 = (x5 + x55);
    const x57 = (x4 + x56);
    const x58 = (x3 + x57);
    const x59 = (x2 + x58);
    const x60 = (x1 + x59);
    out1[0] = x39;
    out1[1] = x46;
    out1[2] = x53;
    out1[3] = x60;
}

/// The function setOne returns the field element one in the Montgomery domain.
///
/// Postconditions:
///   eval (from_montgomery out1) mod m = 1 mod m
///   0 ≤ eval out1 < m
///
pub fn setOne(out1: *MontgomeryDomainFieldElement) void {
    @setRuntimeSafety(mode == .Debug);

    out1[0] = 0xc46353d039cdaaf;
    out1[1] = 0x4319055258e8617b;
    out1[2] = @as(u64, 0x0);
    out1[3] = 0xffffffff;
}

/// The function msat returns the saturated representation of the prime modulus.
///
/// Postconditions:
///   twos_complement_eval out1 = m
///   0 ≤ eval out1 < m
///
/// Output Bounds:
///   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub fn msat(out1: *[5]u64) void {
    @setRuntimeSafety(mode == .Debug);

    out1[0] = 0xf3b9cac2fc632551;
    out1[1] = 0xbce6faada7179e84;
    out1[2] = 0xffffffffffffffff;
    out1[3] = 0xffffffff00000000;
    out1[4] = @as(u64, 0x0);
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
    addcarryxU64(&x1, &x2, 0x0, (~arg1), @as(u64, 0x1));
    const x3 = @as(u1, @truncate((x1 >> 63))) & @as(u1, @truncate(((arg3[0]) & @as(u64, 0x1))));
    var x4: u64 = undefined;
    var x5: u1 = undefined;
    addcarryxU64(&x4, &x5, 0x0, (~arg1), @as(u64, 0x1));
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
    addcarryxU64(&x12, &x13, 0x0, @as(u64, 0x1), (~(arg2[0])));
    var x14: u64 = undefined;
    var x15: u1 = undefined;
    addcarryxU64(&x14, &x15, x13, @as(u64, 0x0), (~(arg2[1])));
    var x16: u64 = undefined;
    var x17: u1 = undefined;
    addcarryxU64(&x16, &x17, x15, @as(u64, 0x0), (~(arg2[2])));
    var x18: u64 = undefined;
    var x19: u1 = undefined;
    addcarryxU64(&x18, &x19, x17, @as(u64, 0x0), (~(arg2[3])));
    var x20: u64 = undefined;
    var x21: u1 = undefined;
    addcarryxU64(&x20, &x21, x19, @as(u64, 0x0), (~(arg2[4])));
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
    subborrowxU64(&x39, &x40, 0x0, x31, 0xf3b9cac2fc632551);
    var x41: u64 = undefined;
    var x42: u1 = undefined;
    subborrowxU64(&x41, &x42, x40, x33, 0xbce6faada7179e84);
    var x43: u64 = undefined;
    var x44: u1 = undefined;
    subborrowxU64(&x43, &x44, x42, x35, 0xffffffffffffffff);
    var x45: u64 = undefined;
    var x46: u1 = undefined;
    subborrowxU64(&x45, &x46, x44, x37, 0xffffffff00000000);
    var x47: u64 = undefined;
    var x48: u1 = undefined;
    subborrowxU64(&x47, &x48, x46, @as(u64, x38), @as(u64, 0x0));
    const x49 = (arg4[3]);
    const x50 = (arg4[2]);
    const x51 = (arg4[1]);
    const x52 = (arg4[0]);
    var x53: u64 = undefined;
    var x54: u1 = undefined;
    subborrowxU64(&x53, &x54, 0x0, @as(u64, 0x0), x52);
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    subborrowxU64(&x55, &x56, x54, @as(u64, 0x0), x51);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    subborrowxU64(&x57, &x58, x56, @as(u64, 0x0), x50);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    subborrowxU64(&x59, &x60, x58, @as(u64, 0x0), x49);
    var x61: u64 = undefined;
    cmovznzU64(&x61, x60, @as(u64, 0x0), 0xffffffffffffffff);
    var x62: u64 = undefined;
    var x63: u1 = undefined;
    addcarryxU64(&x62, &x63, 0x0, x53, (x61 & 0xf3b9cac2fc632551));
    var x64: u64 = undefined;
    var x65: u1 = undefined;
    addcarryxU64(&x64, &x65, x63, x55, (x61 & 0xbce6faada7179e84));
    var x66: u64 = undefined;
    var x67: u1 = undefined;
    addcarryxU64(&x66, &x67, x65, x57, x61);
    var x68: u64 = undefined;
    var x69: u1 = undefined;
    addcarryxU64(&x68, &x69, x67, x59, (x61 & 0xffffffff00000000));
    var x70: u64 = undefined;
    cmovznzU64(&x70, x3, (arg5[0]), x62);
    var x71: u64 = undefined;
    cmovznzU64(&x71, x3, (arg5[1]), x64);
    var x72: u64 = undefined;
    cmovznzU64(&x72, x3, (arg5[2]), x66);
    var x73: u64 = undefined;
    cmovznzU64(&x73, x3, (arg5[3]), x68);
    const x74 = @as(u1, @truncate((x22 & @as(u64, 0x1))));
    var x75: u64 = undefined;
    cmovznzU64(&x75, x74, @as(u64, 0x0), x7);
    var x76: u64 = undefined;
    cmovznzU64(&x76, x74, @as(u64, 0x0), x8);
    var x77: u64 = undefined;
    cmovznzU64(&x77, x74, @as(u64, 0x0), x9);
    var x78: u64 = undefined;
    cmovznzU64(&x78, x74, @as(u64, 0x0), x10);
    var x79: u64 = undefined;
    cmovznzU64(&x79, x74, @as(u64, 0x0), x11);
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
    cmovznzU64(&x90, x74, @as(u64, 0x0), x27);
    var x91: u64 = undefined;
    cmovznzU64(&x91, x74, @as(u64, 0x0), x28);
    var x92: u64 = undefined;
    cmovznzU64(&x92, x74, @as(u64, 0x0), x29);
    var x93: u64 = undefined;
    cmovznzU64(&x93, x74, @as(u64, 0x0), x30);
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
    subborrowxU64(&x102, &x103, 0x0, x94, 0xf3b9cac2fc632551);
    var x104: u64 = undefined;
    var x105: u1 = undefined;
    subborrowxU64(&x104, &x105, x103, x96, 0xbce6faada7179e84);
    var x106: u64 = undefined;
    var x107: u1 = undefined;
    subborrowxU64(&x106, &x107, x105, x98, 0xffffffffffffffff);
    var x108: u64 = undefined;
    var x109: u1 = undefined;
    subborrowxU64(&x108, &x109, x107, x100, 0xffffffff00000000);
    var x110: u64 = undefined;
    var x111: u1 = undefined;
    subborrowxU64(&x110, &x111, x109, @as(u64, x101), @as(u64, 0x0));
    var x112: u64 = undefined;
    var x113: u1 = undefined;
    addcarryxU64(&x112, &x113, 0x0, x6, @as(u64, 0x1));
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

    out1[0] = 0xd739262fb7fcfbb5;
    out1[1] = 0x8ac6f75d20074414;
    out1[2] = 0xc67428bfb5e3c256;
    out1[3] = 0x444962f2eda7aedf;
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
pub const encoded_length = 32;

/// A compressed scalar, in canonical form.
pub const CompressedScalar = [encoded_length]u8;

const Fe = Field(.{
    .fiat = @import("p256_scalar_64.zig"),
    .field_order = 115792089210356248762697446949407573529996955224135760342422259061068512044369,
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
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const meta = std.meta;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const NotSquareError = crypto.errors.NotSquareError;

/// Group operations over P384.
pub const P384 = struct {
    /// The underlying prime field.
    pub const Fe = @import("p384/field.zig").Fe;
    /// Field arithmetic mod the order of the main subgroup.
    pub const scalar = @import("p384/scalar.zig");

    x: Fe,
    y: Fe,
    z: Fe = Fe.one,

    is_base: bool = false,

    /// The P384 base point.
    pub const basePoint = P384{
        .x = Fe.fromInt(26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087) catch unreachable,
        .y = Fe.fromInt(8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871) catch unreachable,
        .z = Fe.one,
        .is_base = true,
    };

    /// The P384 neutral element.
    pub const identityElement = P384{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    pub const B = Fe.fromInt(27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575) catch unreachable;

    /// Reject the neutral element.
    pub fn rejectIdentity(p: P384) IdentityElementError!void {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) & (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        if (is_identity != 0) {
            return error.IdentityElement;
        }
    }

    /// Create a point from affine coordinates after checking that they match the curve equation.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!P384 {
        const x = p.x;
        const y = p.y;
        const x3AxB = x.sq().mul(x).sub(x).sub(x).sub(x).add(B);
        const yy = y.sq();
        const on_curve = @intFromBool(x3AxB.equivalent(yy));
        const is_identity = @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) & @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
        if ((on_curve | is_identity) == 0) {
            return error.InvalidEncoding;
        }
        var ret = P384{ .x = x, .y = y, .z = Fe.one };
        ret.z.cMov(P384.identityElement.z, is_identity);
        return ret;
    }

    /// Create a point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [48]u8, ys: [48]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!P384 {
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
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!P384 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoding_type = s[0];
        const encoded = s[1..];
        switch (encoding_type) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return P384.identityElement;
            },
            2, 3 => {
                if (encoded.len != 48) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..48].*, .big);
                const y_is_odd = (encoding_type == 3);
                const y = try recoverY(x, y_is_odd);
                return P384{ .x = x, .y = y };
            },
            4 => {
                if (encoded.len != 96) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..48].*, .big);
                const y = try Fe.fromBytes(encoded[48..96].*, .big);
                return P384.fromAffineCoordinates(.{ .x = x, .y = y });
            },
            else => return error.InvalidEncoding,
        }
    }

    /// Serialize a point using the compressed SEC-1 format.
    pub fn toCompressedSec1(p: P384) [49]u8 {
        var out: [49]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Serialize a point using the uncompressed SEC-1 format.
    pub fn toUncompressedSec1(p: P384) [97]u8 {
        var out: [97]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..49].* = xy.x.toBytes(.big);
        out[49..97].* = xy.y.toBytes(.big);
        return out;
    }

    /// Return a random point.
    pub fn random() P384 {
        const n = scalar.random(.little);
        return basePoint.mul(n, .little) catch unreachable;
    }

    /// Flip the sign of the X coordinate.
    pub fn neg(p: P384) P384 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// Double a P384 point.
    // Algorithm 6 from https://eprint.iacr.org/2015/1060.pdf
    pub fn dbl(p: P384) P384 {
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

    /// Add P384 points, the second being specified using affine coordinates.
    // Algorithm 5 from https://eprint.iacr.org/2015/1060.pdf
    pub fn addMixed(p: P384, q: AffineCoordinates) P384 {
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
        var ret = P384{
            .x = X3,
            .y = Y3,
            .z = Z3,
        };
        ret.cMov(p, @intFromBool(q.x.isZero()));
        return ret;
    }

    /// Add P384 points.
    // Algorithm 4 from https://eprint.iacr.org/2015/1060.pdf
    pub fn add(p: P384, q: P384) P384 {
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

    /// Subtract P384 points.
    pub fn sub(p: P384, q: P384) P384 {
        return p.add(q.neg());
    }

    /// Subtract P384 points, the second being specified using affine coordinates.
    pub fn subMixed(p: P384, q: AffineCoordinates) P384 {
        return p.addMixed(q.neg());
    }

    /// Return affine coordinates.
    pub fn affineCoordinates(p: P384) AffineCoordinates {
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
    pub fn equivalent(a: P384, b: P384) bool {
        if (a.sub(b).rejectIdentity()) {
            return false;
        } else |_| {
            return true;
        }
    }

    fn cMov(p: *P384, a: P384, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    fn pcSelect(comptime n: usize, pc: *const [n]P384, b: u8) P384 {
        var t = P384.identityElement;
        comptime var i: u8 = 1;
        inline while (i < pc.len) : (i += 1) {
            t.cMov(pc[i], @as(u1, @truncate((@as(usize, b ^ i) -% 1) >> 8)));
        }
        return t;
    }

    fn slide(s: [48]u8) [2 * 48 + 1]i8 {
        var e: [2 * 48 + 1]i8 = undefined;
        for (s, 0..) |x, i| {
            e[i * 2 + 0] = @as(i8, @as(u4, @truncate(x)));
            e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
        }
        // Now, e[0..63] is between 0 and 15, e[63] is between 0 and 7
        var carry: i8 = 0;
        for (e[0..96]) |*x| {
            x.* += carry;
            carry = (x.* + 8) >> 4;
            x.* -= carry * 16;
            std.debug.assert(x.* >= -8 and x.* <= 8);
        }
        e[96] = carry;
        // Now, e[*] is between -8 and 8, including e[64]
        std.debug.assert(carry >= -8 and carry <= 8);
        return e;
    }

    fn pcMul(pc: *const [9]P384, s: [48]u8, comptime vartime: bool) IdentityElementError!P384 {
        std.debug.assert(vartime);
        const e = slide(s);
        var q = P384.identityElement;
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

    fn pcMul16(pc: *const [16]P384, s: [48]u8, comptime vartime: bool) IdentityElementError!P384 {
        var q = P384.identityElement;
        var pos: usize = 380;
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

    fn precompute(p: P384, comptime count: usize) [1 + count]P384 {
        var pc: [1 + count]P384 = undefined;
        pc[0] = P384.identityElement;
        pc[1] = p;
        var i: usize = 2;
        while (i <= count) : (i += 1) {
            pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
        }
        return pc;
    }

    const basePointPc = pc: {
        @setEvalBranchQuota(70000);
        break :pc precompute(P384.basePoint, 15);
    };

    /// Multiply an elliptic curve point by a scalar.
    /// Return error.IdentityElement if the result is the identity element.
    pub fn mul(p: P384, s_: [48]u8, endian: std.builtin.Endian) IdentityElementError!P384 {
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
    pub fn mulPublic(p: P384, s_: [48]u8, endian: std.builtin.Endian) IdentityElementError!P384 {
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
    pub fn mulDoubleBasePublic(p1: P384, s1_: [48]u8, p2: P384, s2_: [48]u8, endian: std.builtin.Endian) IdentityElementError!P384 {
        const s1 = if (endian == .little) s1_ else Fe.orderSwap(s1_);
        const s2 = if (endian == .little) s2_ else Fe.orderSwap(s2_);
        try p1.rejectIdentity();
        var pc1_array: [9]P384 = undefined;
        const pc1 = if (p1.is_base) basePointPc[0..9] else pc: {
            pc1_array = precompute(p1, 8);
            break :pc &pc1_array;
        };
        try p2.rejectIdentity();
        var pc2_array: [9]P384 = undefined;
        const pc2 = if (p2.is_base) basePointPc[0..9] else pc: {
            pc2_array = precompute(p2, 8);
            break :pc &pc2_array;
        };
        const e1 = slide(s1);
        const e2 = slide(s2);
        var q = P384.identityElement;
        var pos: usize = 2 * 48;
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
    x: P384.Fe,
    y: P384.Fe,

    /// Identity element in affine coordinates.
    pub const identityElement = AffineCoordinates{ .x = P384.identityElement.x, .y = P384.identityElement.y };

    fn cMov(p: *AffineCoordinates, a: AffineCoordinates, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
    }
};

test {
    if (@import("builtin").zig_backend == .stage2_c) return error.SkipZigTest;

    _ = @import("tests/p384.zig");
}
const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("p384_64.zig"),
    .field_order = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
    .field_bits = 384,
    .saturated_bits = 384,
    .encoded_length = 48,
});
// Autogenerated: 'src/ExtractionOCaml/word_by_word_montgomery' --lang Zig --internal-static --public-function-case camelCase --private-function-case camelCase --public-type-case UpperCamelCase --private-type-case UpperCamelCase --no-prefix-fiat --package-name p384 '' 64 '2^384 - 2^128 - 2^96 + 2^32 - 1' mul square add sub opp from_montgomery to_montgomery nonzero selectznz to_bytes from_bytes one msat divstep divstep_precomp
// curve description (via package name): p384
// machine_wordsize = 64 (from "64")
// requested operations: mul, square, add, sub, opp, from_montgomery, to_montgomery, nonzero, selectznz, to_bytes, from_bytes, one, msat, divstep, divstep_precomp
// m = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff (from "2^384 - 2^128 - 2^96 + 2^32 - 1")
//
// NOTE: In addition to the bounds specified above each function, all
//   functions synthesized for this Montgomery arithmetic require the
//   input to be strictly less than the prime modulus (m), and also
//   require the input to be in the unique saturated representation.
//   All functions also ensure that these two properties are true of
//   return values.
//
// Computed values:
//   eval z = z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) + (z[4] << 256) + (z[5] << 0x140)
//   bytes_eval z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24) + (z[4] << 32) + (z[5] << 40) + (z[6] << 48) + (z[7] << 56) + (z[8] << 64) + (z[9] << 72) + (z[10] << 80) + (z[11] << 88) + (z[12] << 96) + (z[13] << 104) + (z[14] << 112) + (z[15] << 120) + (z[16] << 128) + (z[17] << 136) + (z[18] << 144) + (z[19] << 152) + (z[20] << 160) + (z[21] << 168) + (z[22] << 176) + (z[23] << 184) + (z[24] << 192) + (z[25] << 200) + (z[26] << 208) + (z[27] << 216) + (z[28] << 224) + (z[29] << 232) + (z[30] << 240) + (z[31] << 248) + (z[32] << 256) + (z[33] << 0x108) + (z[34] << 0x110) + (z[35] << 0x118) + (z[36] << 0x120) + (z[37] << 0x128) + (z[38] << 0x130) + (z[39] << 0x138) + (z[40] << 0x140) + (z[41] << 0x148) + (z[42] << 0x150) + (z[43] << 0x158) + (z[44] << 0x160) + (z[45] << 0x168) + (z[46] << 0x170) + (z[47] << 0x178)
//   twos_complement_eval z = let x1 := z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) + (z[4] << 256) + (z[5] << 0x140) in
//                            if x1 & (2^384-1) < 2^383 then x1 & (2^384-1) else (x1 & (2^384-1)) - 2^384

const std = @import("std");
const mode = @import("builtin").mode; // Checked arithmetic is disabled in non-debug modes to avoid side channels

// The type MontgomeryDomainFieldElement is a field element in the Montgomery domain.
// Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub const MontgomeryDomainFieldElement = [6]u64;

// The type NonMontgomeryDomainFieldElement is a field element NOT in the Montgomery domain.
// Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
pub const NonMontgomeryDomainFieldElement = [6]u64;

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
    const x4 = (arg1[4]);
    const x5 = (arg1[5]);
    const x6 = (arg1[0]);
    var x7: u64 = undefined;
    var x8: u64 = undefined;
    mulxU64(&x7, &x8, x6, (arg2[5]));
    var x9: u64 = undefined;
    var x10: u64 = undefined;
    mulxU64(&x9, &x10, x6, (arg2[4]));
    var x11: u64 = undefined;
    var x12: u64 = undefined;
    mulxU64(&x11, &x12, x6, (arg2[3]));
    var x13: u64 = undefined;
    var x14: u64 = undefined;
    mulxU64(&x13, &x14, x6, (arg2[2]));
    var x15: u64 = undefined;
    var x16: u64 = undefined;
    mulxU64(&x15, &x16, x6, (arg2[1]));
    var x17: u64 = undefined;
    var x18: u64 = undefined;
    mulxU64(&x17, &x18, x6, (arg2[0]));
    var x19: u64 = undefined;
    var x20: u1 = undefined;
    addcarryxU64(&x19, &x20, 0x0, x18, x15);
    var x21: u64 = undefined;
    var x22: u1 = undefined;
    addcarryxU64(&x21, &x22, x20, x16, x13);
    var x23: u64 = undefined;
    var x24: u1 = undefined;
    addcarryxU64(&x23, &x24, x22, x14, x11);
    var x25: u64 = undefined;
    var x26: u1 = undefined;
    addcarryxU64(&x25, &x26, x24, x12, x9);
    var x27: u64 = undefined;
    var x28: u1 = undefined;
    addcarryxU64(&x27, &x28, x26, x10, x7);
    const x29 = (@as(u64, x28) + x8);
    var x30: u64 = undefined;
    var x31: u64 = undefined;
    mulxU64(&x30, &x31, x17, 0x100000001);
    var x32: u64 = undefined;
    var x33: u64 = undefined;
    mulxU64(&x32, &x33, x30, 0xffffffffffffffff);
    var x34: u64 = undefined;
    var x35: u64 = undefined;
    mulxU64(&x34, &x35, x30, 0xffffffffffffffff);
    var x36: u64 = undefined;
    var x37: u64 = undefined;
    mulxU64(&x36, &x37, x30, 0xffffffffffffffff);
    var x38: u64 = undefined;
    var x39: u64 = undefined;
    mulxU64(&x38, &x39, x30, 0xfffffffffffffffe);
    var x40: u64 = undefined;
    var x41: u64 = undefined;
    mulxU64(&x40, &x41, x30, 0xffffffff00000000);
    var x42: u64 = undefined;
    var x43: u64 = undefined;
    mulxU64(&x42, &x43, x30, 0xffffffff);
    var x44: u64 = undefined;
    var x45: u1 = undefined;
    addcarryxU64(&x44, &x45, 0x0, x43, x40);
    var x46: u64 = undefined;
    var x47: u1 = undefined;
    addcarryxU64(&x46, &x47, x45, x41, x38);
    var x48: u64 = undefined;
    var x49: u1 = undefined;
    addcarryxU64(&x48, &x49, x47, x39, x36);
    var x50: u64 = undefined;
    var x51: u1 = undefined;
    addcarryxU64(&x50, &x51, x49, x37, x34);
    var x52: u64 = undefined;
    var x53: u1 = undefined;
    addcarryxU64(&x52, &x53, x51, x35, x32);
    const x54 = (@as(u64, x53) + x33);
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    addcarryxU64(&x55, &x56, 0x0, x17, x42);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    addcarryxU64(&x57, &x58, x56, x19, x44);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    addcarryxU64(&x59, &x60, x58, x21, x46);
    var x61: u64 = undefined;
    var x62: u1 = undefined;
    addcarryxU64(&x61, &x62, x60, x23, x48);
    var x63: u64 = undefined;
    var x64: u1 = undefined;
    addcarryxU64(&x63, &x64, x62, x25, x50);
    var x65: u64 = undefined;
    var x66: u1 = undefined;
    addcarryxU64(&x65, &x66, x64, x27, x52);
    var x67: u64 = undefined;
    var x68: u1 = undefined;
    addcarryxU64(&x67, &x68, x66, x29, x54);
    var x69: u64 = undefined;
    var x70: u64 = undefined;
    mulxU64(&x69, &x70, x1, (arg2[5]));
    var x71: u64 = undefined;
    var x72: u64 = undefined;
    mulxU64(&x71, &x72, x1, (arg2[4]));
    var x73: u64 = undefined;
    var x74: u64 = undefined;
    mulxU64(&x73, &x74, x1, (arg2[3]));
    var x75: u64 = undefined;
    var x76: u64 = undefined;
    mulxU64(&x75, &x76, x1, (arg2[2]));
    var x77: u64 = undefined;
    var x78: u64 = undefined;
    mulxU64(&x77, &x78, x1, (arg2[1]));
    var x79: u64 = undefined;
    var x80: u64 = undefined;
    mulxU64(&x79, &x80, x1, (arg2[0]));
    var x81: u64 = undefined;
    var x82: u1 = undefined;
    addcarryxU64(&x81, &x82, 0x0, x80, x77);
    var x83: u64 = undefined;
    var x84: u1 = undefined;
    addcarryxU64(&x83, &x84, x82, x78, x75);
    var x85: u64 = undefined;
    var x86: u1 = undefined;
    addcarryxU64(&x85, &x86, x84, x76, x73);
    var x87: u64 = undefined;
    var x88: u1 = undefined;
    addcarryxU64(&x87, &x88, x86, x74, x71);
    var x89: u64 = undefined;
    var x90: u1 = undefined;
    addcarryxU64(&x89, &x90, x88, x72, x69);
    const x91 = (@as(u64, x90) + x70);
    var x92: u64 = undefined;
    var x93: u1 = undefined;
    addcarryxU64(&x92, &x93, 0x0, x57, x79);
    var x94: u64 = undefined;
    var x95: u1 = undefined;
    addcarryxU64(&x94, &x95, x93, x59, x81);
    var x96: u64 = undefined;
    var x97: u1 = undefined;
    addcarryxU64(&x96, &x97, x95, x61, x83);
    var x98: u64 = undefined;
    var x99: u1 = undefined;
    addcarryxU64(&x98, &x99, x97, x63, x85);
    var x100: u64 = undefined;
    var x101: u1 = undefined;
    addcarryxU64(&x100, &x101, x99, x65, x87);
    var x102: u64 = undefined;
    var x103: u1 = undefined;
    addcarryxU64(&x102, &x103, x101, x67, x89);
    var x104: u64 = undefined;
    var x105: u1 = undefined;
    addcarryxU64(&x104, &x105, x103, @as(u64, x68), x91);
    var x106: u64 = undefined;
    var x107: u64 = undefined;
    mulxU64(&x106, &x107, x92, 0x100000001);
    var x108: u64 = undefined;
    var x109: u64 = undefined;
    mulxU64(&x108, &x109, x106, 0xffffffffffffffff);
    var x110: u64 = undefined;
    var x111: u64 = undefined;
    mulxU64(&x110, &x111, x106, 0xffffffffffffffff);
    var x112: u64 = undefined;
    var x113: u64 = undefined;
    mulxU64(&x112, &x113, x106, 0xffffffffffffffff);
    var x114: u64 = undefined;
    var x115: u64 = undefined;
    mulxU64(&x114, &x115, x106, 0xfffffffffffffffe);
    var x116: u64 = undefined;
    var x117: u64 = undefined;
    mulxU64(&x116, &x117, x106, 0xffffffff00000000);
    var x118: u64 = undefined;
    var x119: u64 = undefined;
    mulxU64(&x118, &x119, x106, 0xffffffff);
    var x120: u64 = undefined;
    var x121: u1 = undefined;
    addcarryxU64(&x120, &x121, 0x0, x119, x116);
    var x122: u64 = undefined;
    var x123: u1 = undefined;
    addcarryxU64(&x122, &x123, x121, x117, x114);
    var x124: u64 = undefined;
    var x125: u1 = undefined;
    addcarryxU64(&x124, &x125, x123, x115, x112);
    var x126: u64 = undefined;
    var x127: u1 = undefined;
    addcarryxU64(&x126, &x127, x125, x113, x110);
    var x128: u64 = undefined;
    var x129: u1 = undefined;
    addcarryxU64(&x128, &x129, x127, x111, x108);
    const x130 = (@as(u64, x129) + x109);
    var x131: u64 = undefined;
    var x132: u1 = undefined;
    addcarryxU64(&x131, &x132, 0x0, x92, x118);
    var x133: u64 = undefined;
    var x134: u1 = undefined;
    addcarryxU64(&x133, &x134, x132, x94, x120);
    var x135: u64 = undefined;
    var x136: u1 = undefined;
    addcarryxU64(&x135, &x136, x134, x96, x122);
    var x137: u64 = undefined;
    var x138: u1 = undefined;
    addcarryxU64(&x137, &x138, x136, x98, x124);
    var x139: u64 = undefined;
    var x140: u1 = undefined;
    addcarryxU64(&x139, &x140, x138, x100, x126);
    var x141: u64 = undefined;
    var x142: u1 = undefined;
    addcarryxU64(&x141, &x142, x140, x102, x128);
    var x143: u64 = undefined;
    var x144: u1 = undefined;
    addcarryxU64(&x143, &x144, x142, x104, x130);
    const x145 = (@as(u64, x144) + @as(u64, x105));
    var x146: u64 = undefined;
    var x147: u64 = undefined;
    mulxU64(&x146, &x147, x2, (arg2[5]));
    var x148: u64 = undefined;
    var x149: u64 = undefined;
    mulxU64(&x148, &x149, x2, (arg2[4]));
    var x150: u64 = undefined;
    var x151: u64 = undefined;
    mulxU64(&x150, &x151, x2, (arg2[3]));
    var x152: u64 = undefined;
    var x153: u64 = undefined;
    mulxU64(&x152, &x153, x2, (arg2[2]));
    var x154: u64 = undefined;
    var x155: u64 = undefined;
    mulxU64(&x154, &x155, x2, (arg2[1]));
    var x156: u64 = undefined;
    var x157: u64 = undefined;
    mulxU64(&x156, &x157, x2, (arg2[0]));
    var x158: u64 = undefined;
    var x159: u1 = undefined;
    addcarryxU64(&x158, &x159, 0x0, x157, x154);
    var x160: u64 = undefined;
    var x161: u1 = undefined;
    addcarryxU64(&x160, &x161, x159, x155, x152);
    var x162: u64 = undefined;
    var x163: u1 = undefined;
    addcarryxU64(&x162, &x163, x161, x153, x150);
    var x164: u64 = undefined;
    var x165: u1 = undefined;
    addcarryxU64(&x164, &x165, x163, x151, x148);
    var x166: u64 = undefined;
    var x167: u1 = undefined;
    addcarryxU64(&x166, &x167, x165, x149, x146);
    const x168 = (@as(u64, x167) + x147);
    var x169: u64 = undefined;
    var x170: u1 = undefined;
    addcarryxU64(&x169, &x170, 0x0, x133, x156);
    var x171: u64 = undefined;
    var x172: u1 = undefined;
    addcarryxU64(&x171, &x172, x170, x135, x158);
    var x173: u64 = undefined;
    var x174: u1 = undefined;
    addcarryxU64(&x173, &x174, x172, x137, x160);
    var x175: u64 = undefined;
    var x176: u1 = undefined;
    addcarryxU64(&x175, &x176, x174, x139, x162);
    var x177: u64 = undefined;
    var x178: u1 = undefined;
    addcarryxU64(&x177, &x178, x176, x141, x164);
    var x179: u64 = undefined;
    var x180: u1 = undefined;
    addcarryxU64(&x179, &x180, x178, x143, x166);
    var x181: u64 = undefined;
    var x182: u1 = undefined;
    addcarryxU64(&x181, &x182, x180, x145, x168);
    var x183: u64 = undefined;
    var x184: u64 = undefined;
    mulxU64(&x183, &x184, x169, 0x100000001);
    var x185: u64 = undefined;
    var x186: u64 = undefined;
    mulxU64(&x185, &x186, x183, 0xffffffffffffffff);
    var x187: u64 = undefined;
    var x188: u64 = undefined;
    mulxU64(&x187, &x188, x183, 0xffffffffffffffff);
    var x189: u64 = undefined;
    var x190: u64 = undefined;
    mulxU64(&x189, &x190, x183, 0xffffffffffffffff);
    var x191: u64 = undefined;
    var x192: u64 = undefined;
    mulxU64(&x191, &x192, x183, 0xfffffffffffffffe);
    var x193: u64 = undefined;
    var x194: u64 = undefined;
    mulxU64(&x193, &x194, x183, 0xffffffff00000000);
    var x195: u64 = undefined;
    var x196: u64 = undefined;
    mulxU64(&x195, &x196, x183, 0xffffffff);
    var x197: u64 = undefined;
    var x198: u1 = undefined;
    addcarryxU64(&x197, &x198, 0x0, x196, x193);
    var x199: u64 = undefined;
    var x200: u1 = undefined;
    addcarryxU64(&x199, &x200, x198, x194, x191);
    var x201: u64 = undefined;
    var x202: u1 = undefined;
    addcarryxU64(&x201, &x202, x200, x192, x189);
    var x203: u64 = undefined;
    var x204: u1 = undefined;
    addcarryxU64(&x203, &x204, x202, x190, x187);
    var x205: u64 = undefined;
    var x206: u1 = undefined;
    addcarryxU64(&x205, &x206, x204, x188, x185);
    const x207 = (@as(u64, x206) + x186);
    var x208: u64 = undefined;
    var x209: u1 = undefined;
    addcarryxU64(&x208, &x209, 0x0, x169, x195);
    var x210: u64 = undefined;
    var x211: u1 = undefined;
    addcarryxU64(&x210, &x211, x209, x171, x197);
    var x212: u64 = undefined;
    var x213: u1 = undefined;
    addcarryxU64(&x212, &x213, x211, x173, x199);
    var x214: u64 = undefined;
    var x215: u1 = undefined;
    addcarryxU64(&x214, &x215, x213, x175, x201);
    var x216: u64 = undefined;
    var x217: u1 = undefined;
    addcarryxU64(&x216, &x217, x215, x177, x203);
    var x218: u64 = undefined;
    var x219: u1 = undefined;
    addcarryxU64(&x218, &x219, x217, x179, x205);
    var x220: u64 = undefined;
    var x221: u1 = undefined;
    addcarryxU64(&x220, &x221, x219, x181, x207);
    const x222 = (@as(u64, x221) + @as(u64, x182));
    var x223: u64 = undefined;
    var x224: u64 = undefined;
    mulxU64(&x223, &x224, x3, (arg2[5]));
    var x225: u64 = undefined;
    var x226: u64 = undefined;
    mulxU64(&x225, &x226, x3, (arg2[4]));
    var x227: u64 = undefined;
    var x228: u64 = undefined;
    mulxU64(&x227, &x228, x3, (arg2[3]));
    var x229: u64 = undefined;
    var x230: u64 = undefined;
    mulxU64(&x229, &x230, x3, (arg2[2]));
    var x231: u64 = undefined;
    var x232: u64 = undefined;
    mulxU64(&x231, &x232, x3, (arg2[1]));
    var x233: u64 = undefined;
    var x234: u64 = undefined;
    mulxU64(&x233, &x234, x3, (arg2[0]));
    var x235: u64 = undefined;
    var x236: u1 = undefined;
    addcarryxU64(&x235, &x236, 0x0, x234, x231);
    var x237: u64 = undefined;
    var x238: u1 = undefined;
    addcarryxU64(&x237, &x238, x236, x232, x229);
    var x239: u64 = undefined;
    var x240: u1 = undefined;
    addcarryxU64(&x239, &x240, x238, x230, x227);
    var x241: u64 = undefined;
    var x242: u1 = undefined;
    addcarryxU64(&x241, &x242, x240, x228, x225);
    var x243: u64 = undefined;
    var x244: u1 = undefined;
    addcarryxU64(&x243, &x244, x242, x226, x223);
    const x245 = (@as(u64, x244) + x224);
    var x246: u64 = undefined;
    var x247: u1 = undefined;
    addcarryxU64(&x246, &x247, 0x0, x210, x233);
    var x248: u64 = undefined;
    var x249: u1 = undefined;
    addcarryxU64(&x248, &x249, x247, x212, x235);
    var x250: u64 = undefined;
    var x251: u1 = undefined;
    addcarryxU64(&x250, &x251, x249, x214, x237);
    var x252: u64 = undefined;
    var x253: u1 = undefined;
    addcarryxU64(&x252, &x253, x251, x216, x239);
    var x254: u64 = undefined;
    var x255: u1 = undefined;
    addcarryxU64(&x254, &x255, x253, x218, x241);
    var x256: u64 = undefined;
    var x257: u1 = undefined;
    addcarryxU64(&x256, &x257, x255, x220, x243);
    var x258: u64 = undefined;
    var x259: u1 = undefined;
    addcarryxU64(&x258, &x259, x257, x222, x245);
    var x260: u64 = undefined;
    var x261: u64 = undefined;
    mulxU64(&x260, &x261, x246, 0x100000001);
    var x262: u64 = undefined;
    var x263: u64 = undefined;
    mulxU64(&x262, &x263, x260, 0xffffffffffffffff);
    var x264: u64 = undefined;
    var x265: u64 = undefined;
    mulxU64(&x264, &x265, x260, 0xffffffffffffffff);
    var x266: u64 = undefined;
    var x267: u64 = undefined;
    mulxU64(&x266, &x267, x260, 0xffffffffffffffff);
    var x268: u64 = undefined;
    var x269: u64 = undefined;
    mulxU64(&x268, &x269, x260, 0xfffffffffffffffe);
    var x270: u64 = undefined;
    var x271: u64 = undefined;
    mulxU64(&x270, &x271, x260, 0xffffffff00000000);
    var x272: u64 = undefined;
    var x273: u64 = undefined;
    mulxU64(&x272, &x273, x260, 0xffffffff);
    var x274: u64 = undefined;
    var x275: u1 = undefined;
    addcarryxU64(&x274, &x275, 0x0, x273, x270);
    var x276: u64 = undefined;
    var x277: u1 = undefined;
    addcarryxU64(&x276, &x277, x275, x271, x268);
    var x278: u64 = undefined;
    var x279: u1 = undefined;
    addcarryxU64(&x278, &x279, x277, x269, x266);
    var x280: u64 = undefined;
    var x281: u1 = undefined;
    addcarryxU64(&x280, &x281, x279, x267, x264);
    var x282: u64 = undefined;
    var x283: u1 = undefined;
    addcarryxU64(&x282, &x283, x281, x265, x262);
    const x284 = (@as(u64, x283) + x263);
    var x285: u64 = undefined;
    var x286: u1 = undefined;
    addcarryxU64(&x285, &x286, 0x0, x246, x272);
    var x287: u64 = undefined;
    var x288: u1 = undefined;
    addcarryxU64(&x287, &x288, x286, x248, x274);
    var x289: u64 = undefined;
    var x290: u1 = undefined;
    addcarryxU64(&x289, &x290, x288, x250, x276);
    var x291: u64 = undefined;
    var x292: u1 = undefined;
    addcarryxU64(&x291, &x292, x290, x252, x278);
    var x293: u64 = undefined;
    var x294: u1 = undefined;
    addcarryxU64(&x293, &x294, x292, x254, x280);
    var x295: u64 = undefined;
    var x296: u1 = undefined;
    addcarryxU64(&x295, &x296, x294, x256, x282);
    var x297: u64 = undefined;
    var x298: u1 = undefined;
    addcarryxU64(&x297, &x298, x296, x258, x284);
    const x299 = (@as(u64, x298) + @as(u64, x259));
    var x300: u64 = undefined;
    var x301: u64 = undefined;
    mulxU64(&x300, &x301, x4, (arg2[5]));
    var x302: u64 = undefined;
    var x303: u64 = undefined;
    mulxU64(&x302, &x303, x4, (arg2[4]));
    var x304: u64 = undefined;
    var x305: u64 = undefined;
    mulxU64(&x304, &x305, x4, (arg2[3]));
    var x306: u64 = undefined;
    var x307: u64 = undefined;
    mulxU64(&x306, &x307, x4, (arg2[2]));
    var x308: u64 = undefined;
    var x309: u64 = undefined;
    mulxU64(&x308, &x309, x4, (arg2[1]));
    var x310: u64 = undefined;
    var x311: u64 = undefined;
    mulxU64(&x310, &x311, x4, (arg2[0]));
    var x312: u64 = undefined;
    var x313: u1 = undefined;
    addcarryxU64(&x312, &x313, 0x0, x311, x308);
    var x314: u64 = undefined;
    var x315: u1 = undefined;
    addcarryxU64(&x314, &x315, x313, x309, x306);
    var x316: u64 = undefined;
    var x317: u1 = undefined;
    addcarryxU64(&x316, &x317, x315, x307, x304);
    var x318: u64 = undefined;
    var x319: u1 = undefined;
    addcarryxU64(&x318, &x319, x317, x305, x302);
    var x320: u64 = undefined;
    var x321: u1 = undefined;
    addcarryxU64(&x320, &x321, x319, x303, x300);
    const x322 = (@as(u64, x321) + x301);
    var x323: u64 = undefined;
    var x324: u1 = undefined;
    addcarryxU64(&x323, &x324, 0x0, x287, x310);
    var x325: u64 = undefined;
    var x326: u1 = undefined;
    addcarryxU64(&x325, &x326, x324, x289, x312);
    var x327: u64 = undefined;
    var x328: u1 = undefined;
    addcarryxU64(&x327, &x328, x326, x291, x314);
    var x329: u64 = undefined;
    var x330: u1 = undefined;
    addcarryxU64(&x329, &x330, x328, x293, x316);
    var x331: u64 = undefined;
    var x332: u1 = undefined;
    addcarryxU64(&x331, &x332, x330, x295, x318);
    var x333: u64 = undefined;
    var x334: u1 = undefined;
    addcarryxU64(&x333, &x334, x332, x297, x320);
    var x335: u64 = undefined;
    var x336: u1 = undefined;
    addcarryxU64(&x335, &x336, x334, x299, x322);
    var x337: u64 = undefined;
    var x338: u64 = undefined;
    mulxU64(&x337, &x338, x323, 0x100000001);
    var x339: u64 = undefined;
    var x340: u64 = undefined;
    mulxU64(&x339, &x340, x337, 0xffffffffffffffff);
    var x341: u64 = undefined;
    var x342: u64 = undefined;
    mulxU64(&x341, &x342, x337, 0xffffffffffffffff);
    var x343: u64 = undefined;
    var x344: u64 = undefined;
    mulxU64(&x343, &x344, x337, 0xffffffffffffffff);
    var x345: u64 = undefined;
    var x346: u64 = undefined;
    mulxU64(&x345, &x346, x337, 0xfffffffffffffffe);
    var x347: u64 = undefined;
    var x348: u64 = undefined;
    mulxU64(&x347, &x348, x337, 0xffffffff00000000);
    var x349: u64 = undefined;
    var x350: u64 = undefined;
    mulxU64(&x349, &x350, x337, 0xffffffff);
    var x351: u64 = undefined;
    var x352: u1 = undefined;
    addcarryxU64(&x351, &x352, 0x0, x350, x347);
    var x353: u64 = undefined;
    var x354: u1 = undefined;
    addcarryxU64(&x353, &x354, x352, x348, x345);
    var x355: u64 = undefined;
    var x356: u1 = undefined;
    addcarryxU64(&x355, &x356, x354, x346, x343);
    var x357: u64 = undefined;
    var x358: u1 = undefined;
    addcarryxU64(&x357, &x358, x356, x344, x341);
    var x359: u64 = undefined;
    var x360: u1 = undefined;
    addcarryxU64(&x359, &x360, x358, x342, x339);
    const x361 = (@as(u64, x360) + x340);
    var x362: u64 = undefined;
    var x363: u1 = undefined;
    addcarryxU64(&x362, &x363, 0x0, x323, x349);
    var x364: u64 = undefined;
    var x365: u1 = undefined;
    addcarryxU64(&x364, &x365, x363, x325, x351);
    var x366: u64 = undefined;
    var x367: u1 = undefined;
    addcarryxU64(&x366, &x367, x365, x327, x353);
    var x368: u64 = undefined;
    var x369: u1 = undefined;
    addcarryxU64(&x368, &x369, x367, x329, x355);
    var x370: u64 = undefined;
    var x371: u1 = undefined;
    addcarryxU64(&x370, &x371, x369, x331, x357);
    var x372: u64 = undefined;
    var x373: u1 = undefined;
    addcarryxU64(&x372, &x373, x371, x333, x359);
    var x374: u64 = undefined;
    var x375: u1 = undefined;
    addcarryxU64(&x374, &x375, x373, x335, x361);
    const x376 = (@as(u64, x375) + @as(u64, x336));
    var x377: u64 = undefined;
    var x378: u64 = undefined;
    mulxU64(&x377, &x378, x5, (arg2[5]));
    var x379: u64 = undefined;
    var x380: u64 = undefined;
    mulxU64(&x379, &x380, x5, (arg2[4]));
    var x381: u64 = undefined;
    var x382: u64 = undefined;
    mulxU64(&x381, &x382, x5, (arg2[3]));
    var x383: u64 = undefined;
    var x384: u64 = undefined;
    mulxU64(&x383, &x384, x5, (arg2[2]));
    var x385: u64 = undefined;
    var x386: u64 = undefined;
    mulxU64(&x385, &x386, x5, (arg2[1]));
    var x387: u64 = undefined;
    var x388: u64 = undefined;
    mulxU64(&x387, &x388, x5, (arg2[0]));
    var x389: u64 = undefined;
    var x390: u1 = undefined;
    addcarryxU64(&x389, &x390, 0x0, x388, x385);
    var x391: u64 = undefined;
    var x392: u1 = undefined;
    addcarryxU64(&x391, &x392, x390, x386, x383);
    var x393: u64 = undefined;
    var x394: u1 = undefined;
    addcarryxU64(&x393, &x394, x392, x384, x381);
    var x395: u64 = undefined;
    var x396: u1 = undefined;
    addcarryxU64(&x395, &x396, x394, x382, x379);
    var x397: u64 = undefined;
    var x398: u1 = undefined;
    addcarryxU64(&x397, &x398, x396, x380, x377);
    const x399 = (@as(u64, x398) + x378);
    var x400: u64 = undefined;
    var x401: u1 = undefined;
    addcarryxU64(&x400, &x401, 0x0, x364, x387);
    var x402: u64 = undefined;
    var x403: u1 = undefined;
    addcarryxU64(&x402, &x403, x401, x366, x389);
    var x404: u64 = undefined;
    var x405: u1 = undefined;
    addcarryxU64(&x404, &x405, x403, x368, x391);
    var x406: u64 = undefined;
    var x407: u1 = undefined;
    addcarryxU64(&x406, &x407, x405, x370, x393);
    var x408: u64 = undefined;
    var x409: u1 = undefined;
    addcarryxU64(&x408, &x409, x407, x372, x395);
    var x410: u64 = undefined;
    var x411: u1 = undefined;
    addcarryxU64(&x410, &x411, x409, x374, x397);
    var x412: u64 = undefined;
    var x413: u1 = undefined;
    addcarryxU64(&x412, &x413, x411, x376, x399);
    var x414: u64 = undefined;
    var x415: u64 = undefined;
    mulxU64(&x414, &x415, x400, 0x100000001);
    var x416: u64 = undefined;
    var x417: u64 = undefined;
    mulxU64(&x416, &x417, x414, 0xffffffffffffffff);
    var x418: u64 = undefined;
    var x419: u64 = undefined;
    mulxU64(&x418, &x419, x414, 0xffffffffffffffff);
    var x420: u64 = undefined;
    var x421: u64 = undefined;
    mulxU64(&x420, &x421, x414, 0xffffffffffffffff);
    var x422: u64 = undefined;
    var x423: u64 = undefined;
    mulxU64(&x422, &x423, x414, 0xfffffffffffffffe);
    var x424: u64 = undefined;
    var x425: u64 = undefined;
    mulxU64(&x424, &x425, x414, 0xffffffff00000000);
    var x426: u64 = undefined;
    var x427: u64 = undefined;
    mulxU64(&x426, &x427, x414, 0xffffffff);
    var x428: u64 = undefined;
    var x429: u1 = undefined;
    addcarryxU64(&x428, &x429, 0x0, x427, x424);
    var x430: u64 = undefined;
    var x431: u1 = undefined;
    addcarryxU64(&x430, &x431, x429, x425, x422);
    var x432: u64 = undefined;
    var x433: u1 = undefined;
    addcarryxU64(&x432, &x433, x431, x423, x420);
    var x434: u64 = undefined;
    var x435: u1 = undefined;
    addcarryxU64(&x434, &x435, x433, x421, x418);
    var x436: u64 = undefined;
    var x437: u1 = undefined;
    addcarryxU64(&x436, &x437, x435, x419, x416);
    const x438 = (@as(u64, x437) + x417);
    var x439: u64 = undefined;
    var x440: u1 = undefined;
    addcarryxU64(&x439, &x440, 0x0, x400, x426);
    var x441: u64 = undefined;
    var x442: u1 = undefined;
    addcarryxU64(&x441, &x442, x440, x402, x428);
    var x443: u64 = undefined;
    var x444: u1 = undefined;
    addcarryxU64(&x443, &x444, x442, x404, x430);
    var x445: u64 = undefined;
    var x446: u1 = undefined;
    addcarryxU64(&x445, &x446, x444, x406, x432);
    var x447: u64 = undefined;
    var x448: u1 = undefined;
    addcarryxU64(&x447, &x448, x446, x408, x434);
    var x449: u64 = undefined;
    var x450: u1 = undefined;
    addcarryxU64(&x449, &x450, x448, x410, x436);
    var x451: u64 = undefined;
    var x452: u1 = undefined;
    addcarryxU64(&x451, &x452, x450, x412, x438);
    const x453 = (@as(u64, x452) + @as(u64, x413));
    var x454: u64 = undefined;
    var x455: u1 = undefined;
    subborrowxU64(&x454, &x455, 0x0, x441, 0xffffffff);
    var x456: u64 = undefined;
    var x457: u1 = undefined;
    subborrowxU64(&x456, &x457, x455, x443, 0xffffffff00000000);
    var x458: u64 = undefined;
    var x459: u1 = undefined;
    subborrowxU64(&x458, &x459, x457, x445, 0xfffffffffffffffe);
    var x460: u64 = undefined;
    var x461: u1 = undefined;
    subborrowxU64(&x460, &x461, x459, x447, 0xffffffffffffffff);
    var x462: u64 = undefined;
    var x463: u1 = undefined;
    subborrowxU64(&x462, &x463, x461, x449, 0xffffffffffffffff);
    var x464: u64 = undefined;
    var x465: u1 = undefined;
    subborrowxU64(&x464, &x465, x463, x451, 0xffffffffffffffff);
    var x466: u64 = undefined;
    var x467: u1 = undefined;
    subborrowxU64(&x466, &x467, x465, x453, 0x0);
    var x468: u64 = undefined;
    cmovznzU64(&x468, x467, x454, x441);
    var x469: u64 = undefined;
    cmovznzU64(&x469, x467, x456, x443);
    var x470: u64 = undefined;
    cmovznzU64(&x470, x467, x458, x445);
    var x471: u64 = undefined;
    cmovznzU64(&x471, x467, x460, x447);
    var x472: u64 = undefined;
    cmovznzU64(&x472, x467, x462, x449);
    var x473: u64 = undefined;
    cmovznzU64(&x473, x467, x464, x451);
    out1[0] = x468;
    out1[1] = x469;
    out1[2] = x470;
    out1[3] = x471;
    out1[4] = x472;
    out1[5] = x473;
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
    const x4 = (arg1[4]);
    const x5 = (arg1[5]);
    const x6 = (arg1[0]);
    var x7: u64 = undefined;
    var x8: u64 = undefined;
    mulxU64(&x7, &x8, x6, (arg1[5]));
    var x9: u64 = undefined;
    var x10: u64 = undefined;
    mulxU64(&x9, &x10, x6, (arg1[4]));
    var x11: u64 = undefined;
    var x12: u64 = undefined;
    mulxU64(&x11, &x12, x6, (arg1[3]));
    var x13: u64 = undefined;
    var x14: u64 = undefined;
    mulxU64(&x13, &x14, x6, (arg1[2]));
    var x15: u64 = undefined;
    var x16: u64 = undefined;
    mulxU64(&x15, &x16, x6, (arg1[1]));
    var x17: u64 = undefined;
    var x18: u64 = undefined;
    mulxU64(&x17, &x18, x6, (arg1[0]));
    var x19: u64 = undefined;
    var x20: u1 = undefined;
    addcarryxU64(&x19, &x20, 0x0, x18, x15);
    var x21: u64 = undefined;
    var x22: u1 = undefined;
    addcarryxU64(&x21, &x22, x20, x16, x13);
    var x23: u64 = undefined;
    var x24: u1 = undefined;
    addcarryxU64(&x23, &x24, x22, x14, x11);
    var x25: u64 = undefined;
    var x26: u1 = undefined;
    addcarryxU64(&x25, &x26, x24, x12, x9);
    var x27: u64 = undefined;
    var x28: u1 = undefined;
    addcarryxU64(&x27, &x28, x26, x10, x7);
    const x29 = (@as(u64, x28) + x8);
    var x30: u64 = undefined;
    var x31: u64 = undefined;
    mulxU64(&x30, &x31, x17, 0x100000001);
    var x32: u64 = undefined;
    var x33: u64 = undefined;
    mulxU64(&x32, &x33, x30, 0xffffffffffffffff);
    var x34: u64 = undefined;
    var x35: u64 = undefined;
    mulxU64(&x34, &x35, x30, 0xffffffffffffffff);
    var x36: u64 = undefined;
    var x37: u64 = undefined;
    mulxU64(&x36, &x37, x30, 0xffffffffffffffff);
    var x38: u64 = undefined;
    var x39: u64 = undefined;
    mulxU64(&x38, &x39, x30, 0xfffffffffffffffe);
    var x40: u64 = undefined;
    var x41: u64 = undefined;
    mulxU64(&x40, &x41, x30, 0xffffffff00000000);
    var x42: u64 = undefined;
    var x43: u64 = undefined;
    mulxU64(&x42, &x43, x30, 0xffffffff);
    var x44: u64 = undefined;
    var x45: u1 = undefined;
    addcarryxU64(&x44, &x45, 0x0, x43, x40);
    var x46: u64 = undefined;
    var x47: u1 = undefined;
    addcarryxU64(&x46, &x47, x45, x41, x38);
    var x48: u64 = undefined;
    var x49: u1 = undefined;
    addcarryxU64(&x48, &x49, x47, x39, x36);
    var x50: u64 = undefined;
    var x51: u1 = undefined;
    addcarryxU64(&x50, &x51, x49, x37, x34);
    var x52: u64 = undefined;
    var x53: u1 = undefined;
    addcarryxU64(&x52, &x53, x51, x35, x32);
    const x54 = (@as(u64, x53) + x33);
    var x55: u64 = undefined;
    var x56: u1 = undefined;
    addcarryxU64(&x55, &x56, 0x0, x17, x42);
    var x57: u64 = undefined;
    var x58: u1 = undefined;
    addcarryxU64(&x57, &x58, x56, x19, x44);
    var x59: u64 = undefined;
    var x60: u1 = undefined;
    addcarryxU64(&x59, &x60, x58, x21, x46);
    var x61: u64 = undefined;
    var x62: u1 = undefined;
    addcarryxU64(&x61, &x62, x60, x23, x48);
    var x63: u64 = undefined;
    var x64: u1 = undefined;
    addcarryxU64(&x63, &x64, x62, x25, x50);
    var x65: u64 = undefined;
    var x66: u1 = undefined;
    addcarryxU64(&x65, &x66, x64, x27, x52);
    var x67: u64 = undefined;
    var x68: u1 = undefined;
    addcarryxU64(&x67, &x68, x66, x29, x54);
    var x69: u64 = undefined;
    var x70: u64 = undefined;
    mulxU64(&x69, &x70, x1, (arg1[5]));
    var x71: u64 = undefined;
    var x72: u64 = undefined;
    mulxU64(&x71, &x72, x1, (arg1[4]));
    var x73: u64 = undefined;
    var x74: u64 = undefined;
    mulxU64(&x73, &x74, x1, (arg1[3]));
    var x75: u64 = undefined;
    var x76: u64 = undefined;
    mulxU64(&x75, &x76, x1, (arg1[2]));
    var x77: u64 = undefined;
    var x78: u64 = undefined;
    mulxU64(&x77, &x78, x1, (arg1[1]));
    var x79: u64 = undefined;
    var x80: u64 = undefined;
    mulxU64(&x79, &x80, x1, (arg1[0]));
    var x81: u64 = undefined;
    var x82: u1 = undefined;
    addcarryxU64(&x81, &x82, 0x0, x80, x77);
    var x83: u64 = undefined;
    var x84: u1 = undefined;
    addcarryxU64(&x83, &x84, x82, x78, x75);
    var x85: u64 = undefined;
    var x86: u1 = undefined;
    addcarryxU64(&x85, &x86, x84, x76, x73);
    var x87: u64 = undefined;
    var x88: u1 = undefined;
    addcarryxU64(&x87, &x88, x86, x74, x71);
    var x89: u64 = undefined;
    var x90: u1 = undefined;
    addcarryxU64(&x89, &x90, x88, x72, x69);
    const x91 = (@as(u64, x90) + x70);
    var x92: u64 = undefined;
    var x93: u1 = undefined;
    addcarryxU64(&x92, &x93, 0x0, x57, x79);
    var x94: u64 = undefined;
    var x95: u1 = undefined;
    addcarryxU64(&x94, &x95, x93, x59, x81);
    var x96: u64 = undefined;
    var x97: u1 = undefined;
    addcarryxU64(&x96, &x97, x95, x61, x83);
    var x98: u64 = undefined;
    var x99: u1 = undefined;
    addcarryxU64(&x98, &x99, x97, x63, x85);
    var x100: u64 = undefined;
    var x101: u1 = undefined;
    addcarryxU64(&x100, &x101, x99, x65, x87);
    var x102: u64 = undefined;
    var x103: u1 = undefined;
    addcarryxU64(&x102, &x103, x101, x67, x89);
    var x104: u64 = undefined;
    var x105: u1 = undefined;
    addcarryxU64(&x104, &x105, x103, @as(u64, x68), x91);
    var x106: u64 = undefined;
    var x107: u64 = undefined;
    mulxU64(&x106, &x107, x92, 0x100000001);
    var x108: u64 = undefined;
    var x109: u64 = undefined;
    mulxU64(&x108, &x109, x106, 0xffffffffffffffff);
    var x110: u64 = undefined;
    var x111: u64 = undefined;
    mulxU64(&x110, &x111, x106, 0xffffffffffffffff);
    var x112: u64 = undefined;
    var x113: u64 = undefined;
    mulxU64(&x112, &x113, x106, 0xffffffffffffffff);
    var x114: u64 = undefined;
    var x115: u64 = undefined;
    mulxU64(&x114, &x115, x106, 0xfffffffffffffffe);
    var x116: u64 = undefined;
    var x117: u64 = undefined;
    mulxU64(&x116, &x117, x106, 0xffffffff00000000);
    var x118: u64 = undefined;
    var x119: u64 = undefined;
    mulxU64(&x118, &x119, x106, 0xffffffff);
    var x120: u64 = undefined;
    var x121: u1 = undefined;
    addcarryxU64(&x120, &x121, 0x0, x119, x116);
    var x122: u64 = undefined;
    var x123: u1 = undefined;
    addcarryxU64(&x122, &x123, x121, x117, x114);
    var x124: u64 = undefined;
    var x125: u1 = undefined;
    addcarryxU64(&x124, &x125, x123, x115, x112);
    var x126: u64 = undefined;
    var x127: u1 = undefined;
    addcarryxU64(&x126, &x127, x125, x113, x110);
    var x128: u64 = undefined;
    var x129: u1 = undefined;
    addcarryxU64(&x128, &x129, x127, x111, x108);
    const x130 = (@as(u64, x129) + x109);
    var x131: u64 = undefined;
    var x132: u1 = undefined;
    addcarryxU64(&x131, &x132, 0x0, x92, x118);
    var x133: u64 = undefined;
    var x134: u1 = undefined;
    addcarryxU64(&x133, &x134, x132, x94, x120);
    var x135: u64 = undefined;
    var x136: u1 = undefined;
    addcarryxU64(&x135, &x136, x134, x96, x122);
    var x137: u64 = undefined;
    var x138: u1 = undefined;
    addcarryxU64(&x137, &x138, x136, x98, x124);
    var x139: u64 = undefined;
    var x140: u1 = undefined;
    addcarryxU64(&x139, &x140, x138, x100, x126);
    var x141: u64 = undefined;
    var x142: u1 = undefined;
    addcarryxU64(&x141, &x142, x140, x102, x128);
    var x143: u64 = undefined;
    var x144: u1 = undefined;
    addcarryxU64(&x143, &x144, x142, x104, x130);
    const x145 = (@as(u64, x144) + @as(u64, x105));
    var x146: u64 = undefined;
    var x147: u64 = undefined;
    mulxU64(&x146, &x147, x2, (arg1[5]));
    var x148: u64 = undefined;
    var x149: u64 = undefined;
    mulxU64(&x148, &x149, x2, (arg1[4]));
    var x150: u64 = undefined;
    var x151: u64 = undefined;
    mulxU64(&x150, &x151, x2, (arg1[3]));
    var x152: u64 = undefined;
    var x153: u64 = undefined;
    mulxU64(&x152, &x153, x2, (arg1[2]));
    var x154: u64 = undefined;
    var x155: u64 = undefined;
    mulxU64(&x154, &x155, x2, (arg1[1]));
    var x156: u64 = undefined;
    var x157: u64 = undefined;
    mulxU64(&x156, &x157, x2, (arg1[0]));
    var x158: u64 = undefined;
    var x159: u1 = undefined;
    addcarryxU64(&x158, &x159, 0x0, x157, x154);
    var x160: u64 = undefined;
    var x161: u1 = undefined;
    addcarryxU64(&x160, &x161, x159, x155, x152);
    var x162: u64 = undefined;
    var x163: u1 = undefined;
    addcarryxU64(&x162, &x163, x161, x153, x150);
    var x164: u64 = undefined;
    var x165: u1 = undefined;
    addcarryxU64(&x164, &x165, x163, x151, x148);
    var x166: u64 = undefined;
    var x167: u1 = undefined;
    addcarryxU64(&x166, &x167, x165, x149, x146);
    const x168 = (@as(u64, x167) + x147);
    var x169: u64 = undefined;
    var x170: u1 = undefined;
    addcarryxU64(&x169, &x170, 0x0, x133, x156);
    var x171: u64 = undefined;
    var x172: u1 = undefined;
    addcarryxU64(&x171, &x172, x170, x135, x158);
    var x173: u64 = undefined;
    var x174: u1 = undefined;
    addcarryxU64(&x173, &x174, x172, x137, x160);
    var x175: u64 = undefined;
    var x176: u1 = undefined;
    addcarryxU64(&x175, &x176, x174, x139, x162);
    var x177: u64 = undefined;
    var x178: u1 = undefined;
    addcarryxU64(&x177, &x178, x176, x141, x164);
    var x179: u64 = undefined;
    var x180: u1 = undefined;
    addcarryxU64(&x179, &x180, x178, x143, x166);
    var x181: u64 = undefined;
    var x182: u1 = undefined;
    addcarryxU64(&x181, &x182, x180, x145, x168);
    var x183: u64 = undefined;
    var x184: u64 = undefined;
    mulxU64(&x183, &x184, x169, 0x100000001);
    var x185: u64 = undefined;
    var x186: u64 = undefined;
    mulxU64(&x185, &x186, x183, 0xffffffffffffffff);
    var x187: u64 = undefined;
    var x188: u64 = undefined;
    mulxU64(&x187, &x188, x183, 0xffffffffffffffff);
    var x189: u64 = undefined;
    var x190: u64 = undefined;
    mulxU64(&x189, &x190, x183, 0xffffffffffffffff);
    var x191: u64 = undefined;
    var x192: u64 = undefined;
    mulxU64(&x191, &x192, x183, 0xfffffffffffffffe);
    var x193: u64 = undefined;
    var x194: u64 = undefined;
    mulxU64(&x193, &x194, x183, 0xffffffff00000000);
    var x195: u64 = undefined;
    var x196: u64 = undefined;
    mulxU64(&x195, &x196, x183, 0xffffffff);
    var x197: u64 = undefined;
    var x198: u1 = undefined;
    addcarryxU64(&x197, &x198, 0x0, x196, x193);
    var x199: u64 = undefined;
    var x200: u1 = undefined;
    addcarryxU64(&x199, &x200, x198, x194, x191);
    var x201: u64 = undefined;
    var x202: u1 = undefined;
    addcarryxU64(&x201, &x202, x200, x192, x189);
    var x203: u64 = undefined;
    var x204: u1 = undefined;
    addcarryxU64(&x203, &x204, x202, x190, x187);
    var x205: u64 = undefined;
    var x206: u1 = undefined;
    addcarryxU64(&x205, &x206, x204, x188, x185);
    const x207 = (@as(u64, x206) + x186);
    var x208: u64 = undefined;
    var x209: u1 = undefined;
    addcarryxU64(&x208, &x209, 0x0, x169, x195);
    var x210: u64 = undefined;
    var x211: u1 = undefined;
    addcarryxU64(&x210, &x211, x209, x171, x197);
    var x212: u64 = undefined;
    var x213: u1 = undefined;
    addcarryxU64(&x212, &x213, x211, x173, x199);
    var x214: u64 = undefined;
    var x215: u1 = undefined;
    addcarryxU64(&x214, &x215, x213, x175, x201);
    var x216: u64 = undefined;
    var x217: u1 = undefined;
    addcarryxU64(&x216, &x217, x215, x177, x203);
    var x218: u64 = undefined;
    var x219: u1 = undefined;
    addcarryxU64(&x218, &x219, x217, x179, x205);
    var x220: u64 = undefined;
    var x221: u1 = undefined;
    addcarryxU64(&x220, &x221, x219, x181, x207);
    const x222 = (@as(u64, x221) + @as(u64, x182));
    var x223: u64 = undefined;
    var x224: u64 = undefined;
    mulxU64(&x223, &x224, x3, (arg1[5]));
    var x225: u64 = undefined;
    var x226: u64 = undefined;
    mulxU64(&x225, &x226, x3, (arg1[4]));
    var x227: u64 = undefined;
    var x228: u64 = undefined;
    mulxU64(&x227, &x228, x3, (arg1[3]));
    var x229: u64 = undefined;
    var x230: u64 = undefined;
    mulxU64(&x229, &x230, x3, (arg1[2]));
    var x231: u64 = undefined;
    var x232: u64 ```
