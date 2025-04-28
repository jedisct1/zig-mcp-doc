```
thNonce(&mac128, &msg, &key, &nonce);
    try htest.assertEqual("a51f9bc5beae60cce77f0dbc60761edd", &mac128);
    try htest.assertEqual("b36a16ef07c36d75a91f437502f24f545b8dfa88648ed116943c29fead3bf10c", &mac256);
}
const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const has_vaes = std.Target.x86.featureSetHas(builtin.cpu.features, .vaes);
const AesBlockX2 = if (builtin.cpu.arch == .x86_64 and has_vaes) IntelAesBlockX2 else GenericAesBlockX2;

pub const IntelAesBlockX2 = struct {
    const Self = @This();
    const BlockVec = @Vector(4, u64);
    repr: BlockVec,

    pub inline fn fromBytes(bytes: *const [32]u8) Self {
        const repr = mem.bytesToValue(BlockVec, bytes);
        return Self{ .repr = repr };
    }

    pub inline fn toBytes(block: Self) [32]u8 {
        return mem.toBytes(block.repr);
    }

    pub inline fn xorBytes(block: Self, bytes: *const [32]u8) [32]u8 {
        const x = block.repr ^ fromBytes(bytes).repr;
        return mem.toBytes(x);
    }

    pub inline fn encrypt(block: Self, round_key: Self) Self {
        return Self{
            .repr = asm (
                \\ vaesenc %[rk], %[in], %[out]
                : [out] "=x" (-> BlockVec),
                : [in] "x" (block.repr),
                  [rk] "x" (round_key.repr),
            ),
        };
    }

    pub inline fn xorBlocks(block1: Self, block2: Self) Self {
        return Self{ .repr = block1.repr ^ block2.repr };
    }

    pub inline fn andBlocks(block1: Self, block2: Self) Self {
        return Self{ .repr = block1.repr & block2.repr };
    }

    pub inline fn orBlocks(block1: Self, block2: Self) Self {
        return Self{ .repr = block1.repr | block2.repr };
    }
};

pub const GenericAesBlockX2 = struct {
    const Self = @This();
    const BlockVec = crypto.core.aes.Block;
    repr: [2]BlockVec,

    pub inline fn fromBytes(bytes: *const [32]u8) Self {
        return Self{ .repr = .{
            BlockVec.fromBytes(bytes[0..16]),
            BlockVec.fromBytes(bytes[16..32]),
        } };
    }

    pub inline fn toBytes(block: Self) [32]u8 {
        var out: [32]u8 = undefined;
        mem.copy(u8, out[0..16], &block.repr[0].toBytes());
        mem.copy(u8, out[16..32], &block.repr[1].toBytes());
        return out;
    }

    pub inline fn xorBytes(block: Self, bytes: *const [32]u8) [32]u8 {
        return BlockVec{
            .repr = .{
                block.repr[0].xorBytes(bytes[0..16]),
                block.repr[1].xorBytes(bytes[16..32]),
            },
        };
    }

    pub inline fn encrypt(block: Self, round_key: Self) Self {
        return Self{
            .repr = .{
                block.repr[0].encrypt(round_key.repr[0]),
                block.repr[1].encrypt(round_key.repr[1]),
            },
        };
    }

    pub inline fn xorBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].xorBlocks(block2.repr[0]),
                block1.repr[1].xorBlocks(block2.repr[1]),
            },
        };
    }

    pub inline fn andBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].andBlocks(block2.repr[0]),
                block1.repr[1].andBlocks(block2.repr[1]),
            },
        };
    }

    pub inline fn orBlocks(block1: Self, block2: Self) Self {
        return Self{
            .repr = .{
                block1.repr[0].orBlocks(block2.repr[0]),
                block1.repr[1].orBlocks(block2.repr[1]),
            },
        };
    }
};

pub const Aegis128X = struct {
    pub const key_length: usize = 16;
    pub const nonce_length: usize = 16;
    pub const tag_length: usize = 16;
    pub const ad_max_length: usize = 1 << 61;
    pub const msg_max_length: usize = 1 << 61;
    pub const ct_max_length: usize = msg_max_length + tag_length;

    const State = [8]AesBlockX2;

    s: State,

    inline fn aesround(in: AesBlockX2, rk: AesBlockX2) AesBlockX2 {
        return in.encrypt(rk);
    }

    fn update(self: *Aegis128X, m0: AesBlockX2, m1: AesBlockX2) void {
        const s = self.s;
        self.s = State{
            aesround(s[7], s[0].xorBlocks(m0)),
            aesround(s[0], s[1]),
            aesround(s[1], s[2]),
            aesround(s[2], s[3]),
            aesround(s[3], s[4].xorBlocks(m1)),
            aesround(s[4], s[5]),
            aesround(s[5], s[6]),
            aesround(s[6], s[7]),
        };
    }

    fn init(key: [key_length]u8, nonce: [nonce_length]u8) Aegis128X {
        const c0 = AesBlockX2.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 } ** 2);
        const c1 = AesBlockX2.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd } ** 2);

        var key_x2 = key ** 2;
        var nonce_x2 = nonce ** 2;
        const key_block = AesBlockX2.fromBytes(&key_x2);
        const nonce_block = AesBlockX2.fromBytes(&nonce_x2);

        const x = c0.xorBlocks(AesBlockX2.fromBytes(&[_]u8{0x0} ** 15 ++ &[_]u8{0x01} ++ [_]u8{0x0} ** 15 ++ &[_]u8{0x02}));

        var self = Aegis128X{ .s = State{
            key_block.xorBlocks(nonce_block),
            c1,
            c0,
            c1,
            key_block.xorBlocks(nonce_block),
            key_block.xorBlocks(c0),
            key_block.xorBlocks(c1),
            key_block.xorBlocks(x),
        } };
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            self.update(nonce_block, key_block);
        }
        return self;
    }

    fn enc(self: *Aegis128X, xi: *const [64]u8) [64]u8 {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        const t0 = AesBlockX2.fromBytes(xi[0..32]);
        const t1 = AesBlockX2.fromBytes(xi[32..64]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        self.update(t0, t1);
        var ci: [64]u8 = undefined;
        mem.copy(u8, ci[0..32], &out0.toBytes());
        mem.copy(u8, ci[32..64], &out1.toBytes());
        return ci;
    }

    fn dec(self: *Aegis128X, ci: *const [64]u8) [64]u8 {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        const t0 = AesBlockX2.fromBytes(ci[0..32]);
        const t1 = AesBlockX2.fromBytes(ci[32..64]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        self.update(out0, out1);
        var xi: [64]u8 = undefined;
        mem.copy(u8, xi[0..32], &out0.toBytes());
        mem.copy(u8, xi[32..64], &out1.toBytes());
        return xi;
    }

    fn decLast(self: *Aegis128X, xn: []u8, cn: []const u8) void {
        const s = self.s;
        const z0 = s[6].xorBlocks(s[1]).xorBlocks(s[2].andBlocks(s[3]));
        const z1 = s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7]));
        var pad = [_]u8{0} ** 64;
        mem.copy(u8, pad[0..cn.len], cn);
        const t0 = AesBlockX2.fromBytes(pad[0..32]);
        const t1 = AesBlockX2.fromBytes(pad[32..64]);
        const out0 = t0.xorBlocks(z0);
        const out1 = t1.xorBlocks(z1);
        mem.copy(u8, pad[0..32], &out0.toBytes());
        mem.copy(u8, pad[32..64], &out1.toBytes());
        mem.copy(u8, xn, pad[0..cn.len]);
        mem.set(u8, pad[cn.len..], 0);
        const v0 = AesBlockX2.fromBytes(pad[0..32]);
        const v1 = AesBlockX2.fromBytes(pad[32..64]);
        self.update(v0, v1);
    }

    fn finalize(self: *Aegis128X, ad_len: usize, msg_len: usize) [tag_length]u8 {
        var s = &self.s;
        var b: [32]u8 = undefined;
        mem.writeIntLittle(u64, b[0..8], @intCast(u64, ad_len) * 8);
        mem.writeIntLittle(u64, b[8..16], @intCast(u64, msg_len) * 8);
        mem.copy(u8, b[16..32], b[0..16]);
        const t = s[2].xorBlocks(AesBlockX2.fromBytes(&b));
        var i: usize = 0;
        while (i < 7) : (i += 1) {
            self.update(t, t);
        }
        const tag32 = s[0].xorBlocks(s[1]).xorBlocks(s[2]).xorBlocks(s[3]).xorBlocks(s[4]).xorBlocks(s[5]).xorBlocks(s[6]).toBytes();
        var tag: [tag_length]u8 = undefined;
        for (tag, 0..) |_, j| {
            tag[j] = tag32[j] ^ tag32[j + 16];
        }
        return tag;
    }

    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        const tag_ = _encrypt(c, m, ad, key, npub);
        mem.copy(u8, tag, &tag_);
    }

    pub fn _encrypt(
        ct: []u8,
        msg: []const u8,
        ad: []const u8,
        key: [key_length]u8,
        nonce: [nonce_length]u8,
    ) [tag_length]u8 {
        assert(msg.len <= msg_max_length);
        assert(ad.len <= ad_max_length);
        assert(ct.len == msg.len);
        var aegis = init(key, nonce);

        var i: usize = 0;
        while (i + 64 <= ad.len) : (i += 64) {
            _ = aegis.enc(ad[i..][0..64]);
        }
        if (ad.len % 64 != 0) {
            var pad = [_]u8{0} ** 64;
            mem.copy(u8, pad[0 .. ad.len % 64], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 64 <= msg.len) : (i += 64) {
            mem.copy(u8, ct[i..][0..64], &aegis.enc(msg[i..][0..64]));
        }
        if (msg.len % 64 != 0) {
            var pad = [_]u8{0} ** 64;
            mem.copy(u8, pad[0 .. msg.len % 64], msg[i..]);
            mem.copy(u8, ct[i..], aegis.enc(&pad)[0 .. msg.len % 64]);
        }

        return aegis.finalize(ad.len, msg.len);
    }

    pub fn decrypt(
        m: []u8,
        c: []const u8,
        tag: [tag_length]u8,
        ad: []const u8,
        npub: [nonce_length]u8,
        key: [key_length]u8,
    ) AuthenticationError!void {
        return _decrypt(m, c, tag, ad, key, npub);
    }

    pub fn _decrypt(
        msg: []u8,
        ct: []const u8,
        tag: [tag_length]u8,
        ad: []const u8,
        key: [key_length]u8,
        nonce: [nonce_length]u8,
    ) AuthenticationError!void {
        assert(ct.len <= ct_max_length);
        assert(ad.len <= ad_max_length);
        assert(ct.len == msg.len);
        var aegis = init(key, nonce);

        var i: usize = 0;
        while (i + 64 <= ad.len) : (i += 64) {
            _ = aegis.enc(ad[i..][0..64]);
        }
        if (ad.len % 64 != 0) {
            var pad = [_]u8{0} ** 64;
            mem.copy(u8, pad[0 .. ad.len % 64], ad[i..]);
            _ = aegis.enc(&pad);
        }

        i = 0;
        while (i + 64 <= ct.len) : (i += 64) {
            mem.copy(u8, msg[i..][0..64], &aegis.dec(ct[i..][0..64]));
        }
        if (ct.len % 64 != 0) {
            aegis.decLast(msg[i..], ct[i..]);
        }

        const expected_tag = aegis.finalize(ad.len, msg.len);
        if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
            crypto.utils.secureZero(u8, msg);
            return error.AuthenticationFailed;
        }
    }
};
const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const debug = std.debug;
const Ghash = std.crypto.onetimeauth.Ghash;
const math = std.math;
const mem = std.mem;
const modes = crypto.core.modes;
const AuthenticationError = crypto.errors.AuthenticationError;

pub const Aes128Gcm = AesGcm(crypto.core.aes.Aes128);
pub const Aes256Gcm = AesGcm(crypto.core.aes.Aes256);

fn AesGcm(comptime Aes: anytype) type {
    debug.assert(Aes.block.block_length == 16);

    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 12;
        pub const key_length = Aes.key_bits / 8;

        const zeros = [_]u8{0} ** 16;

        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            debug.assert(c.len == m.len);
            debug.assert(m.len <= 16 * ((1 << 32) - 2));

            const aes = Aes.initEnc(key);
            var h: [16]u8 = undefined;
            aes.encrypt(&h, &zeros);

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            aes.encrypt(&t, &j);

            const block_count = (math.divCeil(usize, ad.len, Ghash.block_length) catch unreachable) + (math.divCeil(usize, c.len, Ghash.block_length) catch unreachable) + 1;
            var mac = Ghash.initForBlockCount(&h, block_count);
            mac.update(ad);
            mac.pad();

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(aes), aes, c, m, j, .big);
            mac.update(c[0..m.len][0..]);
            mac.pad();

            var final_block = h;
            mem.writeInt(u64, final_block[0..8], @as(u64, ad.len) * 8, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, m.len) * 8, .big);
            mac.update(&final_block);
            mac.final(tag);
            for (t, 0..) |x, i| {
                tag[i] ^= x;
            }
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

            const aes = Aes.initEnc(key);
            var h: [16]u8 = undefined;
            aes.encrypt(&h, &zeros);

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
            aes.encrypt(&t, &j);

            const block_count = (math.divCeil(usize, ad.len, Ghash.block_length) catch unreachable) + (math.divCeil(usize, c.len, Ghash.block_length) catch unreachable) + 1;
            var mac = Ghash.initForBlockCount(&h, block_count);
            mac.update(ad);
            mac.pad();

            mac.update(c);
            mac.pad();

            var final_block = h;
            mem.writeInt(u64, final_block[0..8], @as(u64, ad.len) * 8, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, m.len) * 8, .big);
            mac.update(&final_block);
            var computed_tag: [Ghash.mac_length]u8 = undefined;
            mac.final(&computed_tag);
            for (t, 0..) |x, i| {
                computed_tag[i] ^= x;
            }

            const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!verify) {
                crypto.secureZero(u8, &computed_tag);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }

            mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
            modes.ctr(@TypeOf(aes), aes, m, c, j, .big);
        }
    };
}

const htest = @import("test.zig");
const testing = std.testing;

test "Aes256Gcm - Empty message and no associated data" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const ad = "";
    const m = "";
    var c: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try htest.assertEqual("6b6ff610a16fa4cd59f1fb7903154e92", &tag);
}

test "Aes256Gcm - Associated data only" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const m = "";
    const ad = "Test with associated data";
    var c: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try htest.assertEqual("262ed164c2dfb26e080a9d108dd9dd4c", &tag);
}

test "Aes256Gcm - Message only" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const m = "Test with message only";
    const ad = "";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try Aes256Gcm.decrypt(&m2, &c, tag, ad, nonce, key);
    try testing.expectEqualSlices(u8, m[0..], m2[0..]);

    try htest.assertEqual("5ca1642d90009fea33d01f78cf6eefaf01d539472f7c", &c);
    try htest.assertEqual("07cd7fc9103e2f9e9bf2dfaa319caff4", &tag);
}

test "Aes256Gcm - Message and associated data" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const m = "Test with message";
    const ad = "Test with associated data";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try Aes256Gcm.decrypt(&m2, &c, tag, ad, nonce, key);
    try testing.expectEqualSlices(u8, m[0..], m2[0..]);

    try htest.assertEqual("5ca1642d90009fea33d01f78cf6eefaf01", &c);
    try htest.assertEqual("64accec679d444e2373bd9f6796c0d2c", &tag);
}
const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const aes = crypto.core.aes;
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const AuthenticationError = crypto.errors.AuthenticationError;

pub const Aes128Ocb = AesOcb(aes.Aes128);
pub const Aes256Ocb = AesOcb(aes.Aes256);

const Block = [16]u8;

/// AES-OCB (RFC 7253 - https://competitions.cr.yp.to/round3/ocbv11.pdf)
fn AesOcb(comptime Aes: anytype) type {
    const EncryptCtx = aes.AesEncryptCtx(Aes);
    const DecryptCtx = aes.AesDecryptCtx(Aes);

    return struct {
        pub const key_length = Aes.key_bits / 8;
        pub const nonce_length: usize = 12;
        pub const tag_length: usize = 16;

        const Lx = struct {
            star: Block align(16),
            dol: Block align(16),
            table: [56]Block align(16) = undefined,
            upto: usize,

            inline fn double(l: Block) Block {
                const l_ = mem.readInt(u128, &l, .big);
                const l_2 = (l_ << 1) ^ (0x87 & -%(l_ >> 127));
                var l2: Block = undefined;
                mem.writeInt(u128, &l2, l_2, .big);
                return l2;
            }

            fn precomp(lx: *Lx, upto: usize) []const Block {
                const table = &lx.table;
                assert(upto < table.len);
                var i = lx.upto;
                while (i + 1 <= upto) : (i += 1) {
                    table[i + 1] = double(table[i]);
                }
                lx.upto = upto;
                return lx.table[0 .. upto + 1];
            }

            fn init(aes_enc_ctx: EncryptCtx) Lx {
                const zeros = [_]u8{0} ** 16;
                var star: Block = undefined;
                aes_enc_ctx.encrypt(&star, &zeros);
                const dol = double(star);
                var lx = Lx{ .star = star, .dol = dol, .upto = 0 };
                lx.table[0] = double(dol);
                return lx;
            }
        };

        fn hash(aes_enc_ctx: EncryptCtx, lx: *Lx, a: []const u8) Block {
            const full_blocks: usize = a.len / 16;
            const x_max = if (full_blocks > 0) math.log2_int(usize, full_blocks) else 0;
            const lt = lx.precomp(x_max);
            var sum = [_]u8{0} ** 16;
            var offset = [_]u8{0} ** 16;
            var i: usize = 0;
            while (i < full_blocks) : (i += 1) {
                xorWith(&offset, lt[@ctz(i + 1)]);
                var e = xorBlocks(offset, a[i * 16 ..][0..16].*);
                aes_enc_ctx.encrypt(&e, &e);
                xorWith(&sum, e);
            }
            const leftover = a.len % 16;
            if (leftover > 0) {
                xorWith(&offset, lx.star);
                var padded = [_]u8{0} ** 16;
                @memcpy(padded[0..leftover], a[i * 16 ..][0..leftover]);
                padded[leftover] = 1;
                var e = xorBlocks(offset, padded);
                aes_enc_ctx.encrypt(&e, &e);
                xorWith(&sum, e);
            }
            return sum;
        }

        fn getOffset(aes_enc_ctx: EncryptCtx, npub: [nonce_length]u8) Block {
            var nx = [_]u8{0} ** 16;
            nx[0] = @as(u8, @intCast(@as(u7, @truncate(tag_length * 8)) << 1));
            nx[16 - nonce_length - 1] = 1;
            nx[nx.len - nonce_length ..].* = npub;

            const bottom: u6 = @truncate(nx[15]);
            nx[15] &= 0xc0;
            var ktop_: Block = undefined;
            aes_enc_ctx.encrypt(&ktop_, &nx);
            const ktop = mem.readInt(u128, &ktop_, .big);
            const stretch = (@as(u192, ktop) << 64) | @as(u192, @as(u64, @truncate(ktop >> 64)) ^ @as(u64, @truncate(ktop >> 56)));
            var offset: Block = undefined;
            mem.writeInt(u128, &offset, @as(u128, @truncate(stretch >> (64 - @as(u7, bottom)))), .big);
            return offset;
        }

        const has_aesni = std.Target.x86.featureSetHas(builtin.cpu.features, .aes);
        const has_armaes = std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes);
        const wb: usize = if ((builtin.cpu.arch == .x86_64 and has_aesni) or (builtin.cpu.arch == .aarch64 and has_armaes)) 4 else 0;

        /// c: ciphertext: output buffer should be of size m.len
        /// tag: authentication tag: output MAC
        /// m: message
        /// ad: Associated Data
        /// npub: public nonce
        /// k: secret key
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            assert(c.len == m.len);

            const aes_enc_ctx = Aes.initEnc(key);
            const full_blocks: usize = m.len / 16;
            const x_max = if (full_blocks > 0) math.log2_int(usize, full_blocks) else 0;
            var lx = Lx.init(aes_enc_ctx);
            const lt = lx.precomp(x_max);

            var offset = getOffset(aes_enc_ctx, npub);
            var sum = [_]u8{0} ** 16;
            var i: usize = 0;

            while (wb > 0 and i + wb <= full_blocks) : (i += wb) {
                var offsets: [wb]Block align(16) = undefined;
                var es: [16 * wb]u8 align(16) = undefined;
                var j: usize = 0;
                while (j < wb) : (j += 1) {
                    xorWith(&offset, lt[@ctz(i + 1 + j)]);
                    offsets[j] = offset;
                    const p = m[(i + j) * 16 ..][0..16].*;
                    es[j * 16 ..][0..16].* = xorBlocks(p, offsets[j]);
                    xorWith(&sum, p);
                }
                aes_enc_ctx.encryptWide(wb, &es, &es);
                j = 0;
                while (j < wb) : (j += 1) {
                    const e = es[j * 16 ..][0..16].*;
                    c[(i + j) * 16 ..][0..16].* = xorBlocks(e, offsets[j]);
                }
            }
            while (i < full_blocks) : (i += 1) {
                xorWith(&offset, lt[@ctz(i + 1)]);
                const p = m[i * 16 ..][0..16].*;
                var e = xorBlocks(p, offset);
                aes_enc_ctx.encrypt(&e, &e);
                c[i * 16 ..][0..16].* = xorBlocks(e, offset);
                xorWith(&sum, p);
            }
            const leftover = m.len % 16;
            if (leftover > 0) {
                xorWith(&offset, lx.star);
                var pad = offset;
                aes_enc_ctx.encrypt(&pad, &pad);
                for (m[i * 16 ..], 0..) |x, j| {
                    c[i * 16 + j] = pad[j] ^ x;
                }
                var e = [_]u8{0} ** 16;
                @memcpy(e[0..leftover], m[i * 16 ..][0..leftover]);
                e[leftover] = 0x80;
                xorWith(&sum, e);
            }
            var e = xorBlocks(xorBlocks(sum, offset), lx.dol);
            aes_enc_ctx.encrypt(&e, &e);
            tag.* = xorBlocks(e, hash(aes_enc_ctx, &lx, ad));
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

            const aes_enc_ctx = Aes.initEnc(key);
            const aes_dec_ctx = DecryptCtx.initFromEnc(aes_enc_ctx);
            const full_blocks: usize = m.len / 16;
            const x_max = if (full_blocks > 0) math.log2_int(usize, full_blocks) else 0;
            var lx = Lx.init(aes_enc_ctx);
            const lt = lx.precomp(x_max);

            var offset = getOffset(aes_enc_ctx, npub);
            var sum = [_]u8{0} ** 16;
            var i: usize = 0;

            while (wb > 0 and i + wb <= full_blocks) : (i += wb) {
                var offsets: [wb]Block align(16) = undefined;
                var es: [16 * wb]u8 align(16) = undefined;
                var j: usize = 0;
                while (j < wb) : (j += 1) {
                    xorWith(&offset, lt[@ctz(i + 1 + j)]);
                    offsets[j] = offset;
                    const q = c[(i + j) * 16 ..][0..16].*;
                    es[j * 16 ..][0..16].* = xorBlocks(q, offsets[j]);
                }
                aes_dec_ctx.decryptWide(wb, &es, &es);
                j = 0;
                while (j < wb) : (j += 1) {
                    const p = xorBlocks(es[j * 16 ..][0..16].*, offsets[j]);
                    m[(i + j) * 16 ..][0..16].* = p;
                    xorWith(&sum, p);
                }
            }
            while (i < full_blocks) : (i += 1) {
                xorWith(&offset, lt[@ctz(i + 1)]);
                const q = c[i * 16 ..][0..16].*;
                var e = xorBlocks(q, offset);
                aes_dec_ctx.decrypt(&e, &e);
                const p = xorBlocks(e, offset);
                m[i * 16 ..][0..16].* = p;
                xorWith(&sum, p);
            }
            const leftover = m.len % 16;
            if (leftover > 0) {
                xorWith(&offset, lx.star);
                var pad = offset;
                aes_enc_ctx.encrypt(&pad, &pad);
                for (c[i * 16 ..], 0..) |x, j| {
                    m[i * 16 + j] = pad[j] ^ x;
                }
                var e = [_]u8{0} ** 16;
                @memcpy(e[0..leftover], m[i * 16 ..][0..leftover]);
                e[leftover] = 0x80;
                xorWith(&sum, e);
            }
            var e = xorBlocks(xorBlocks(sum, offset), lx.dol);
            aes_enc_ctx.encrypt(&e, &e);
            var computed_tag = xorBlocks(e, hash(aes_enc_ctx, &lx, ad));
            const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!verify) {
                crypto.secureZero(u8, &computed_tag);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }
        }
    };
}

inline fn xorBlocks(x: Block, y: Block) Block {
    var z: Block = x;
    for (&z, 0..) |*v, i| {
        v.* = x[i] ^ y[i];
    }
    return z;
}

inline fn xorWith(x: *Block, y: Block) void {
    for (x, 0..) |*v, i| {
        v.* ^= y[i];
    }
}

const hexToBytes = std.fmt.hexToBytes;

test "AesOcb test vector 1" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var k: [Aes128Ocb.key_length]u8 = undefined;
    var nonce: [Aes128Ocb.nonce_length]u8 = undefined;
    var tag: [Aes128Ocb.tag_length]u8 = undefined;
    _ = try hexToBytes(&k, "000102030405060708090A0B0C0D0E0F");
    _ = try hexToBytes(&nonce, "BBAA99887766554433221100");

    var c: [0]u8 = undefined;
    Aes128Ocb.encrypt(&c, &tag, "", "", nonce, k);

    var expected_tag: [tag.len]u8 = undefined;
    _ = try hexToBytes(&expected_tag, "785407BFFFC8AD9EDCC5520AC9111EE6");

    var m: [0]u8 = undefined;
    try Aes128Ocb.decrypt(&m, "", tag, "", nonce, k);
}

test "AesOcb test vector 2" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var k: [Aes128Ocb.key_length]u8 = undefined;
    var nonce: [Aes128Ocb.nonce_length]u8 = undefined;
    var tag: [Aes128Ocb.tag_length]u8 = undefined;
    var ad: [40]u8 = undefined;
    _ = try hexToBytes(&k, "000102030405060708090A0B0C0D0E0F");
    _ = try hexToBytes(&ad, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");
    _ = try hexToBytes(&nonce, "BBAA9988776655443322110E");

    var c: [0]u8 = undefined;
    Aes128Ocb.encrypt(&c, &tag, "", &ad, nonce, k);

    var expected_tag: [tag.len]u8 = undefined;
    _ = try hexToBytes(&expected_tag, "C5CD9D1850C141E358649994EE701B68");

    var m: [0]u8 = undefined;
    try Aes128Ocb.decrypt(&m, &c, tag, &ad, nonce, k);
}

test "AesOcb test vector 3" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var k: [Aes128Ocb.key_length]u8 = undefined;
    var nonce: [Aes128Ocb.nonce_length]u8 = undefined;
    var tag: [Aes128Ocb.tag_length]u8 = undefined;
    var m: [40]u8 = undefined;
    var c: [m.len]u8 = undefined;
    _ = try hexToBytes(&k, "000102030405060708090A0B0C0D0E0F");
    _ = try hexToBytes(&m, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");
    _ = try hexToBytes(&nonce, "BBAA9988776655443322110F");

    Aes128Ocb.encrypt(&c, &tag, &m, "", nonce, k);

    var expected_c: [c.len]u8 = undefined;
    var expected_tag: [tag.len]u8 = undefined;
    _ = try hexToBytes(&expected_tag, "479AD363AC366B95A98CA5F3000B1479");
    _ = try hexToBytes(&expected_c, "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E");

    var m2: [m.len]u8 = undefined;
    try Aes128Ocb.decrypt(&m2, &c, tag, "", nonce, k);
    assert(mem.eql(u8, &m, &m2));
}

test "AesOcb test vector 4" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var k: [Aes128Ocb.key_length]u8 = undefined;
    var nonce: [Aes128Ocb.nonce_length]u8 = undefined;
    var tag: [Aes128Ocb.tag_length]u8 = undefined;
    var m: [40]u8 = undefined;
    var ad = m;
    var c: [m.len]u8 = undefined;
    _ = try hexToBytes(&k, "000102030405060708090A0B0C0D0E0F");
    _ = try hexToBytes(&m, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");
    _ = try hexToBytes(&nonce, "BBAA99887766554433221104");

    Aes128Ocb.encrypt(&c, &tag, &m, &ad, nonce, k);

    var expected_c: [c.len]u8 = undefined;
    var expected_tag: [tag.len]u8 = undefined;
    _ = try hexToBytes(&expected_tag, "3AD7A4FF3835B8C5701C1CCEC8FC3358");
    _ = try hexToBytes(&expected_c, "571D535B60B277188BE5147170A9A22C");

    var m2: [m.len]u8 = undefined;
    try Aes128Ocb.decrypt(&m2, &c, tag, &ad, nonce, k);
    assert(mem.eql(u8, &m, &m2));
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const testing = std.testing;

const has_aesni = std.Target.x86.featureSetHas(builtin.cpu.features, .aes);
const has_avx = std.Target.x86.featureSetHas(builtin.cpu.features, .avx);
const has_armaes = std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes);
// C backend doesn't currently support passing vectors to inline asm.
const impl = if (builtin.cpu.arch == .x86_64 and builtin.zig_backend != .stage2_c and has_aesni and has_avx) impl: {
    break :impl @import("aes/aesni.zig");
} else if (builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and has_armaes)
impl: {
    break :impl @import("aes/armcrypto.zig");
} else impl: {
    break :impl @import("aes/soft.zig");
};

/// `true` if AES is backed by hardware (AES-NI on x86_64, ARM Crypto Extensions on AArch64).
/// Software implementations are much slower, and should be avoided if possible.
pub const has_hardware_support =
    (builtin.cpu.arch == .x86_64 and has_aesni and has_avx) or
    (builtin.cpu.arch == .aarch64 and has_armaes);

pub const Block = impl.Block;
pub const BlockVec = impl.BlockVec;
pub const AesEncryptCtx = impl.AesEncryptCtx;
pub const AesDecryptCtx = impl.AesDecryptCtx;
pub const Aes128 = impl.Aes128;
pub const Aes256 = impl.Aes256;

test "ctr" {
    // NIST SP 800-38A pp 55-58
    const ctr = @import("modes.zig").ctr;

    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    const in = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const exp_out = [_]u8{
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
    };

    var out: [exp_out.len]u8 = undefined;
    const ctx = Aes128.initEnc(key);
    ctr(AesEncryptCtx(Aes128), ctx, out[0..], in[0..], iv, std.builtin.Endian.big);
    try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
}

test "encrypt" {
    // Appendix B
    {
        const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
        const in = [_]u8{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
        const exp_out = [_]u8{ 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

        var out: [exp_out.len]u8 = undefined;
        var ctx = Aes128.initEnc(key);
        ctx.encrypt(out[0..], in[0..]);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }

    // Appendix C.3
    {
        const key = [_]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        const in = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
        const exp_out = [_]u8{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

        var out: [exp_out.len]u8 = undefined;
        var ctx = Aes256.initEnc(key);
        ctx.encrypt(out[0..], in[0..]);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }
}

test "decrypt" {
    // Appendix B
    {
        const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
        const in = [_]u8{ 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
        const exp_out = [_]u8{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

        var out: [exp_out.len]u8 = undefined;
        var ctx = Aes128.initDec(key);
        ctx.decrypt(out[0..], in[0..]);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }

    // Appendix C.3
    {
        const key = [_]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        const in = [_]u8{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
        const exp_out = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

        var out: [exp_out.len]u8 = undefined;
        var ctx = Aes256.initDec(key);
        ctx.decrypt(out[0..], in[0..]);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }
}

test "expand 128-bit key" {
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const exp_enc = [_]*const [32:0]u8{
        "2b7e151628aed2a6abf7158809cf4f3c", "a0fafe1788542cb123a339392a6c7605", "f2c295f27a96b9435935807a7359f67f", "3d80477d4716fe3e1e237e446d7a883b", "ef44a541a8525b7fb671253bdb0bad00", "d4d1c6f87c839d87caf2b8bc11f915bc", "6d88a37a110b3efddbf98641ca0093fd", "4e54f70e5f5fc9f384a64fb24ea6dc4f", "ead27321b58dbad2312bf5607f8d292f", "ac7766f319fadc2128d12941575c006e", "d014f9a8c9ee2589e13f0cc8b6630ca6",
    };
    const exp_dec = [_]*const [32:0]u8{
        "d014f9a8c9ee2589e13f0cc8b6630ca6", "0c7b5a631319eafeb0398890664cfbb4", "df7d925a1f62b09da320626ed6757324", "12c07647c01f22c7bc42d2f37555114a", "6efcd876d2df54807c5df034c917c3b9", "6ea30afcbc238cf6ae82a4b4b54a338d", "90884413d280860a12a128421bc89739", "7c1f13f74208c219c021ae480969bf7b", "cc7505eb3e17d1ee82296c51c9481133", "2b3708a7f262d405bc3ebdbf4b617d62", "2b7e151628aed2a6abf7158809cf4f3c",
    };
    const enc = Aes128.initEnc(key);
    const dec = Aes128.initDec(key);
    var exp: [16]u8 = undefined;

    for (enc.key_schedule.round_keys, 0..) |round_key, i| {
        _ = try std.fmt.hexToBytes(&exp, exp_enc[i]);
        try testing.expectEqualSlices(u8, &exp, &round_key.toBytes());
    }
    for (dec.key_schedule.round_keys, 0..) |round_key, i| {
        _ = try std.fmt.hexToBytes(&exp, exp_dec[i]);
        try testing.expectEqualSlices(u8, &exp, &round_key.toBytes());
    }
}

test "expand 256-bit key" {
    const key = [_]u8{
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,
        0x09, 0x14, 0xdf, 0xf4,
    };
    const exp_enc = [_]*const [32:0]u8{
        "603deb1015ca71be2b73aef0857d7781", "1f352c073b6108d72d9810a30914dff4", "9ba354118e6925afa51a8b5f2067fcde",
        "a8b09c1a93d194cdbe49846eb75d5b9a", "d59aecb85bf3c917fee94248de8ebe96", "b5a9328a2678a647983122292f6c79b3",
        "812c81addadf48ba24360af2fab8b464", "98c5bfc9bebd198e268c3ba709e04214", "68007bacb2df331696e939e46c518d80",
        "c814e20476a9fb8a5025c02d59c58239", "de1369676ccc5a71fa2563959674ee15", "5886ca5d2e2f31d77e0af1fa27cf73c3",
        "749c47ab18501ddae2757e4f7401905a", "cafaaae3e4d59b349adf6acebd10190d", "fe4890d1e6188d0b046df344706c631e",
    };
    const exp_dec = [_]*const [32:0]u8{
        "fe4890d1e6188d0b046df344706c631e", "ada23f4963e23b2455427c8a5c709104", "57c96cf6074f07c0706abb07137f9241",
        "b668b621ce40046d36a047ae0932ed8e", "34ad1e4450866b367725bcc763152946", "32526c367828b24cf8e043c33f92aa20",
        "c440b289642b757227a3d7f114309581", "d669a7334a7ade7a80c8f18fc772e9e3", "25ba3c22a06bc7fb4388a28333934270",
        "54fb808b9c137949cab22ff547ba186c", "6c3d632985d1fbd9e3e36578701be0f3", "4a7459f9c8e8f9c256a156bc8d083799",
        "42107758e9ec98f066329ea193f8858b", "8ec6bff6829ca03b9e49af7edba96125", "603deb1015ca71be2b73aef0857d7781",
    };
    const enc = Aes256.initEnc(key);
    const dec = Aes256.initDec(key);
    var exp: [16]u8 = undefined;

    for (enc.key_schedule.round_keys, 0..) |round_key, i| {
        _ = try std.fmt.hexToBytes(&exp, exp_enc[i]);
        try testing.expectEqualSlices(u8, &exp, &round_key.toBytes());
    }
    for (dec.key_schedule.round_keys, 0..) |round_key, i| {
        _ = try std.fmt.hexToBytes(&exp, exp_dec[i]);
        try testing.expectEqualSlices(u8, &exp, &round_key.toBytes());
    }
}
const std = @import("../../std.zig");
const builtin = @import("builtin");
const mem = std.mem;
const debug = std.debug;

const has_vaes = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .vaes);
const has_avx512f = builtin.cpu.arch == .x86_64 and builtin.zig_backend != .stage2_x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f);

/// A single AES block.
pub const Block = struct {
    const Repr = @Vector(2, u64);

    /// The length of an AES block in bytes.
    pub const block_length: usize = 16;

    /// Internal representation of a block.
    repr: Repr,

    /// Convert a byte sequence into an internal representation.
    pub inline fn fromBytes(bytes: *const [16]u8) Block {
        const repr = mem.bytesToValue(Repr, bytes);
        return Block{ .repr = repr };
    }

    /// Convert the internal representation of a block into a byte sequence.
    pub inline fn toBytes(block: Block) [16]u8 {
        return mem.toBytes(block.repr);
    }

    /// XOR the block with a byte sequence.
    pub inline fn xorBytes(block: Block, bytes: *const [16]u8) [16]u8 {
        const x = block.repr ^ fromBytes(bytes).repr;
        return mem.toBytes(x);
    }

    /// Encrypt a block with a round key.
    pub inline fn encrypt(block: Block, round_key: Block) Block {
        return Block{
            .repr = asm (
                \\ vaesenc %[rk], %[in], %[out]
                : [out] "=x" (-> Repr),
                : [in] "x" (block.repr),
                  [rk] "x" (round_key.repr),
            ),
        };
    }

    /// Encrypt a block with the last round key.
    pub inline fn encryptLast(block: Block, round_key: Block) Block {
        return Block{
            .repr = asm (
                \\ vaesenclast %[rk], %[in], %[out]
                : [out] "=x" (-> Repr),
                : [in] "x" (block.repr),
                  [rk] "x" (round_key.repr),
            ),
        };
    }

    /// Decrypt a block with a round key.
    pub inline fn decrypt(block: Block, inv_round_key: Block) Block {
        return Block{
            .repr = asm (
                \\ vaesdec %[rk], %[in], %[out]
                : [out] "=x" (-> Repr),
                : [in] "x" (block.repr),
                  [rk] "x" (inv_round_key.repr),
            ),
        };
    }

    /// Decrypt a block with the last round key.
    pub inline fn decryptLast(block: Block, inv_round_key: Block) Block {
        return Block{
            .repr = asm (
                \\ vaesdeclast %[rk], %[in], %[out]
                : [out] "=x" (-> Repr),
                : [in] "x" (block.repr),
                  [rk] "x" (inv_round_key.repr),
            ),
        };
    }

    /// Apply the bitwise XOR operation to the content of two blocks.
    pub inline fn xorBlocks(block1: Block, block2: Block) Block {
        return Block{ .repr = block1.repr ^ block2.repr };
    }

    /// Apply the bitwise AND operation to the content of two blocks.
    pub inline fn andBlocks(block1: Block, block2: Block) Block {
        return Block{ .repr = block1.repr & block2.repr };
    }

    /// Apply the bitwise OR operation to the content of two blocks.
    pub inline fn orBlocks(block1: Block, block2: Block) Block {
        return Block{ .repr = block1.repr | block2.repr };
    }

    /// Perform operations on multiple blocks in parallel.
    pub const parallel = struct {
        const cpu = std.Target.x86.cpu;

        /// The recommended number of AES encryption/decryption to perform in parallel for the chosen implementation.
        pub const optimal_parallel_blocks = switch (builtin.cpu.model) {
            &cpu.westmere, &cpu.goldmont => 3,
            &cpu.cannonlake, &cpu.skylake, &cpu.skylake_avx512, &cpu.tremont, &cpu.goldmont_plus, &cpu.cascadelake => 4,
            &cpu.icelake_client, &cpu.icelake_server, &cpu.tigerlake, &cpu.rocketlake, &cpu.alderlake => 6,
            &cpu.haswell, &cpu.broadwell => 7,
            &cpu.sandybridge, &cpu.ivybridge => 8,
            &cpu.znver1, &cpu.znver2, &cpu.znver3, &cpu.znver4 => 8,
            else => 8,
        };

        /// Encrypt multiple blocks in parallel, each their own round key.
        pub inline fn encryptParallel(comptime count: usize, blocks: [count]Block, round_keys: [count]Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].encrypt(round_keys[i]);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel, each their own round key.
        pub inline fn decryptParallel(comptime count: usize, blocks: [count]Block, round_keys: [count]Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].decrypt(round_keys[i]);
            }
            return out;
        }

        /// Encrypt multiple blocks in parallel with the same round key.
        pub inline fn encryptWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].encrypt(round_key);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel with the same round key.
        pub inline fn decryptWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].decrypt(round_key);
            }
            return out;
        }

        /// Encrypt multiple blocks in parallel with the same last round key.
        pub inline fn encryptLastWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].encryptLast(round_key);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel with the same last round key.
        pub inline fn decryptLastWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].decryptLast(round_key);
            }
            return out;
        }
    };
};

/// A fixed-size vector of AES blocks.
/// All operations are performed in parallel, using SIMD instructions when available.
pub fn BlockVec(comptime blocks_count: comptime_int) type {
    return struct {
        const Self = @This();

        /// The number of AES blocks the target architecture can process with a single instruction.
        pub const native_vector_size = w: {
            if (has_avx512f and blocks_count % 4 == 0) break :w 4;
            if (has_vaes and blocks_count % 2 == 0) break :w 2;
            break :w 1;
        };

        /// The size of the AES block vector that the target architecture can process with a single instruction, in bytes.
        pub const native_word_size = native_vector_size * 16;

        const native_words = blocks_count / native_vector_size;

        const Repr = @Vector(native_vector_size * 2, u64);

        /// Internal representation of a block vector.
        repr: [native_words]Repr,

        /// Length of the block vector in bytes.
        pub const block_length: usize = blocks_count * 16;

        /// Convert a byte sequence into an internal representation.
        pub inline fn fromBytes(bytes: *const [blocks_count * 16]u8) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = mem.bytesToValue(Repr, bytes[i * native_word_size ..][0..native_word_size]);
            }
            return out;
        }

        /// Convert the internal representation of a block vector into a byte sequence.
        pub inline fn toBytes(block_vec: Self) [blocks_count * 16]u8 {
            var out: [blocks_count * 16]u8 = undefined;
            inline for (0..native_words) |i| {
                out[i * native_word_size ..][0..native_word_size].* = mem.toBytes(block_vec.repr[i]);
            }
            return out;
        }

        /// XOR the block vector with a byte sequence.
        pub inline fn xorBytes(block_vec: Self, bytes: *const [blocks_count * 16]u8) [blocks_count * 16]u8 {
            var x: Self = undefined;
            inline for (0..native_words) |i| {
                x.repr[i] = block_vec.repr[i] ^ mem.bytesToValue(Repr, bytes[i * native_word_size ..][0..native_word_size]);
            }
            return x.toBytes();
        }

        /// Apply the forward AES operation to the block vector with a vector of round keys.
        pub inline fn encrypt(block_vec: Self, round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = asm (
                    \\ vaesenc %[rk], %[in], %[out]
                    : [out] "=x" (-> Repr),
                    : [in] "x" (block_vec.repr[i]),
                      [rk] "x" (round_key_vec.repr[i]),
                );
            }
            return out;
        }

        /// Apply the forward AES operation to the block vector with a vector of last round keys.
        pub inline fn encryptLast(block_vec: Self, round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = asm (
                    \\ vaesenclast %[rk], %[in], %[out]
                    : [out] "=x" (-> Repr),
                    : [in] "x" (block_vec.repr[i]),
                      [rk] "x" (round_key_vec.repr[i]),
                );
            }
            return out;
        }

        /// Apply the inverse AES operation to the block vector with a vector of round keys.
        pub inline fn decrypt(block_vec: Self, inv_round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = asm (
                    \\ vaesdec %[rk], %[in], %[out]
                    : [out] "=x" (-> Repr),
                    : [in] "x" (block_vec.repr[i]),
                      [rk] "x" (inv_round_key_vec.repr[i]),
                );
            }
            return out;
        }

        /// Apply the inverse AES operation to the block vector with a vector of last round keys.
        pub inline fn decryptLast(block_vec: Self, inv_round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = asm (
                    \\ vaesdeclast %[rk], %[in], %[out]
                    : [out] "=x" (-> Repr),
                    : [in] "x" (block_vec.repr[i]),
                      [rk] "x" (inv_round_key_vec.repr[i]),
                );
            }
            return out;
        }

        /// Apply the bitwise XOR operation to the content of two block vectors.
        pub inline fn xorBlocks(block_vec1: Self, block_vec2: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i] ^ block_vec2.repr[i];
            }
            return out;
        }

        /// Apply the bitwise AND operation to the content of two block vectors.
        pub inline fn andBlocks(block_vec1: Self, block_vec2: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i] & block_vec2.repr[i];
            }
            return out;
        }

        /// Apply the bitwise OR operation to the content of two block vectors.
        pub inline fn orBlocks(block_vec1: Self, block_vec2: Block) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i] | block_vec2.repr[i];
            }
            return out;
        }
    };
}

fn KeySchedule(comptime Aes: type) type {
    std.debug.assert(Aes.rounds == 10 or Aes.rounds == 14);
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();

        const Repr = Aes.block.Repr;

        round_keys: [rounds + 1]Block,

        fn drc(comptime second: bool, comptime rc: u8, t: Repr, tx: Repr) Repr {
            var s: Repr = undefined;
            var ts: Repr = undefined;
            return asm (
                \\ vaeskeygenassist %[rc], %[t], %[s]
                \\ vpslldq $4, %[tx], %[ts]
                \\ vpxor   %[ts], %[tx], %[r]
                \\ vpslldq $8, %[r], %[ts]
                \\ vpxor   %[ts], %[r], %[r]
                \\ vpshufd %[mask], %[s], %[ts]
                \\ vpxor   %[ts], %[r], %[r]
                : [r] "=&x" (-> Repr),
                  [s] "=&x" (s),
                  [ts] "=&x" (ts),
                : [rc] "n" (rc),
                  [t] "x" (t),
                  [tx] "x" (tx),
                  [mask] "n" (@as(u8, if (second) 0xaa else 0xff)),
            );
        }

        fn expand128(t1: *Block) Self {
            var round_keys: [11]Block = undefined;
            const rcs = [_]u8{ 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
            inline for (rcs, 0..) |rc, round| {
                round_keys[round] = t1.*;
                t1.repr = drc(false, rc, t1.repr, t1.repr);
            }
            round_keys[rcs.len] = t1.*;
            return Self{ .round_keys = round_keys };
        }

        fn expand256(t1: *Block, t2: *Block) Self {
            var round_keys: [15]Block = undefined;
            const rcs = [_]u8{ 1, 2, 4, 8, 16, 32 };
            round_keys[0] = t1.*;
            inline for (rcs, 0..) |rc, round| {
                round_keys[round * 2 + 1] = t2.*;
                t1.repr = drc(false, rc, t2.repr, t1.repr);
                round_keys[round * 2 + 2] = t1.*;
                t2.repr = drc(true, rc, t1.repr, t2.repr);
            }
            round_keys[rcs.len * 2 + 1] = t2.*;
            t1.repr = drc(false, 64, t2.repr, t1.repr);
            round_keys[rcs.len * 2 + 2] = t1.*;
            return Self{ .round_keys = round_keys };
        }

        /// Invert the key schedule.
        pub fn invert(key_schedule: Self) Self {
            const round_keys = &key_schedule.round_keys;
            var inv_round_keys: [rounds + 1]Block = undefined;
            inv_round_keys[0] = round_keys[rounds];
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                inv_round_keys[i] = Block{
                    .repr = asm (
                        \\ vaesimc %[rk], %[inv_rk]
                        : [inv_rk] "=x" (-> Repr),
                        : [rk] "x" (round_keys[rounds - i].repr),
                    ),
                };
            }
            inv_round_keys[rounds] = round_keys[0];
            return Self{ .round_keys = inv_round_keys };
        }
    };
}

/// A context to perform encryption using the standard AES key schedule.
pub fn AesEncryptCtx(comptime Aes: type) type {
    std.debug.assert(Aes.key_bits == 128 or Aes.key_bits == 256);
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();
        pub const block = Aes.block;
        pub const block_length = block.block_length;
        key_schedule: KeySchedule(Aes),

        /// Create a new encryption context with the given key.
        pub fn init(key: [Aes.key_bits / 8]u8) Self {
            var t1 = Block.fromBytes(key[0..16]);
            const key_schedule = if (Aes.key_bits == 128) ks: {
                break :ks KeySchedule(Aes).expand128(&t1);
            } else ks: {
                var t2 = Block.fromBytes(key[16..32]);
                break :ks KeySchedule(Aes).expand256(&t1, &t2);
            };
            return Self{
                .key_schedule = key_schedule,
            };
        }

        /// Encrypt a single block.
        pub fn encrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(src).xorBlocks(round_keys[0]);
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                t = t.encrypt(round_keys[i]);
            }
            t = t.encryptLast(round_keys[rounds]);
            dst.* = t.toBytes();
        }

        /// Encrypt+XOR a single block.
        pub fn xor(ctx: Self, dst: *[16]u8, src: *const [16]u8, counter: [16]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(&counter).xorBlocks(round_keys[0]);
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                t = t.encrypt(round_keys[i]);
            }
            t = t.encryptLast(round_keys[rounds]);
            dst.* = t.xorBytes(src);
        }

        /// Encrypt multiple blocks, possibly leveraging parallelization.
        pub fn encryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var ts: [count]Block = undefined;
            comptime var j = 0;
            inline while (j < count) : (j += 1) {
                ts[j] = Block.fromBytes(src[j * 16 .. j * 16 + 16][0..16]).xorBlocks(round_keys[0]);
            }
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                ts = Block.parallel.encryptWide(count, ts, round_keys[i]);
            }
            ts = Block.parallel.encryptLastWide(count, ts, round_keys[i]);
            j = 0;
            inline while (j < count) : (j += 1) {
                dst[16 * j .. 16 * j + 16].* = ts[j].toBytes();
            }
        }

        /// Encrypt+XOR multiple blocks, possibly leveraging parallelization.
        pub fn xorWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8, counters: [16 * count]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var ts: [count]Block = undefined;
            comptime var j = 0;
            inline while (j < count) : (j += 1) {
                ts[j] = Block.fromBytes(counters[j * 16 .. j * 16 + 16][0..16]).xorBlocks(round_keys[0]);
            }
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                ts = Block.parallel.encryptWide(count, ts, round_keys[i]);
            }
            ts = Block.parallel.encryptLastWide(count, ts, round_keys[i]);
            j = 0;
            inline while (j < count) : (j += 1) {
                dst[16 * j .. 16 * j + 16].* = ts[j].xorBytes(src[16 * j .. 16 * j + 16]);
            }
        }
    };
}

/// A context to perform decryption using the standard AES key schedule.
pub fn AesDecryptCtx(comptime Aes: type) type {
    std.debug.assert(Aes.key_bits == 128 or Aes.key_bits == 256);
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();
        pub const block = Aes.block;
        pub const block_length = block.block_length;
        key_schedule: KeySchedule(Aes),

        /// Create a decryption context from an existing encryption context.
        pub fn initFromEnc(ctx: AesEncryptCtx(Aes)) Self {
            return Self{
                .key_schedule = ctx.key_schedule.invert(),
            };
        }

        /// Create a new decryption context with the given key.
        pub fn init(key: [Aes.key_bits / 8]u8) Self {
            const enc_ctx = AesEncryptCtx(Aes).init(key);
            return initFromEnc(enc_ctx);
        }

        /// Decrypt a single block.
        pub fn decrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            const inv_round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(src).xorBlocks(inv_round_keys[0]);
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                t = t.decrypt(inv_round_keys[i]);
            }
            t = t.decryptLast(inv_round_keys[rounds]);
            dst.* = t.toBytes();
        }

        /// Decrypt multiple blocks, possibly leveraging parallelization.
        pub fn decryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
            const inv_round_keys = ctx.key_schedule.round_keys;
            var ts: [count]Block = undefined;
            comptime var j = 0;
            inline while (j < count) : (j += 1) {
                ts[j] = Block.fromBytes(src[j * 16 .. j * 16 + 16][0..16]).xorBlocks(inv_round_keys[0]);
            }
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                ts = Block.parallel.decryptWide(count, ts, inv_round_keys[i]);
            }
            ts = Block.parallel.decryptLastWide(count, ts, inv_round_keys[i]);
            j = 0;
            inline while (j < count) : (j += 1) {
                dst[16 * j .. 16 * j + 16].* = ts[j].toBytes();
            }
        }
    };
}

/// AES-128 with the standard key schedule.
pub const Aes128 = struct {
    pub const key_bits: usize = 128;
    pub const rounds = ((key_bits - 64) / 32 + 8);
    pub const block = Block;

    /// Create a new context for encryption.
    pub fn initEnc(key: [key_bits / 8]u8) AesEncryptCtx(Aes128) {
        return AesEncryptCtx(Aes128).init(key);
    }

    /// Create a new context for decryption.
    pub fn initDec(key: [key_bits / 8]u8) AesDecryptCtx(Aes128) {
        return AesDecryptCtx(Aes128).init(key);
    }
};

/// AES-256 with the standard key schedule.
pub const Aes256 = struct {
    pub const key_bits: usize = 256;
    pub const rounds = ((key_bits - 64) / 32 + 8);
    pub const block = Block;

    /// Create a new context for encryption.
    pub fn initEnc(key: [key_bits / 8]u8) AesEncryptCtx(Aes256) {
        return AesEncryptCtx(Aes256).init(key);
    }

    /// Create a new context for decryption.
    pub fn initDec(key: [key_bits / 8]u8) AesDecryptCtx(Aes256) {
        return AesDecryptCtx(Aes256).init(key);
    }
};
const std = @import("../../std.zig");
const mem = std.mem;
const debug = std.debug;

/// A single AES block.
pub const Block = struct {
    const Repr = @Vector(2, u64);

    pub const block_length: usize = 16;

    /// Internal representation of a block.
    repr: Repr,

    /// Convert a byte sequence into an internal representation.
    pub inline fn fromBytes(bytes: *const [16]u8) Block {
        const repr = mem.bytesToValue(Repr, bytes);
        return Block{ .repr = repr };
    }

    /// Convert the internal representation of a block into a byte sequence.
    pub inline fn toBytes(block: Block) [16]u8 {
        return mem.toBytes(block.repr);
    }

    /// XOR the block with a byte sequence.
    pub inline fn xorBytes(block: Block, bytes: *const [16]u8) [16]u8 {
        const x = block.repr ^ fromBytes(bytes).repr;
        return mem.toBytes(x);
    }

    const zero = @Vector(2, u64){ 0, 0 };

    /// Encrypt a block with a round key.
    pub inline fn encrypt(block: Block, round_key: Block) Block {
        return Block{
            .repr = (asm (
                \\ mov   %[out].16b, %[in].16b
                \\ aese  %[out].16b, %[zero].16b
                \\ aesmc %[out].16b, %[out].16b
                : [out] "=&x" (-> Repr),
                : [in] "x" (block.repr),
                  [zero] "x" (zero),
            )) ^ round_key.repr,
        };
    }

    /// Encrypt a block with the last round key.
    pub inline fn encryptLast(block: Block, round_key: Block) Block {
        return Block{
            .repr = (asm (
                \\ mov   %[out].16b, %[in].16b
                \\ aese  %[out].16b, %[zero].16b
                : [out] "=&x" (-> Repr),
                : [in] "x" (block.repr),
                  [zero] "x" (zero),
            )) ^ round_key.repr,
        };
    }

    /// Decrypt a block with a round key.
    pub inline fn decrypt(block: Block, inv_round_key: Block) Block {
        return Block{
            .repr = (asm (
                \\ mov   %[out].16b, %[in].16b
                \\ aesd  %[out].16b, %[zero].16b
                \\ aesimc %[out].16b, %[out].16b
                : [out] "=&x" (-> Repr),
                : [in] "x" (block.repr),
                  [zero] "x" (zero),
            )) ^ inv_round_key.repr,
        };
    }

    /// Decrypt a block with the last round key.
    pub inline fn decryptLast(block: Block, inv_round_key: Block) Block {
        return Block{
            .repr = (asm (
                \\ mov   %[out].16b, %[in].16b
                \\ aesd  %[out].16b, %[zero].16b
                : [out] "=&x" (-> Repr),
                : [in] "x" (block.repr),
                  [zero] "x" (zero),
            )) ^ inv_round_key.repr,
        };
    }

    /// Apply the bitwise XOR operation to the content of two blocks.
    pub inline fn xorBlocks(block1: Block, block2: Block) Block {
        return Block{ .repr = block1.repr ^ block2.repr };
    }

    /// Apply the bitwise AND operation to the content of two blocks.
    pub inline fn andBlocks(block1: Block, block2: Block) Block {
        return Block{ .repr = block1.repr & block2.repr };
    }

    /// Apply the bitwise OR operation to the content of two blocks.
    pub inline fn orBlocks(block1: Block, block2: Block) Block {
        return Block{ .repr = block1.repr | block2.repr };
    }

    /// Perform operations on multiple blocks in parallel.
    pub const parallel = struct {
        /// The recommended number of AES encryption/decryption to perform in parallel for the chosen implementation.
        pub const optimal_parallel_blocks = 6;

        /// Encrypt multiple blocks in parallel, each their own round key.
        pub inline fn encryptParallel(comptime count: usize, blocks: [count]Block, round_keys: [count]Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].encrypt(round_keys[i]);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel, each their own round key.
        pub inline fn decryptParallel(comptime count: usize, blocks: [count]Block, round_keys: [count]Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].decrypt(round_keys[i]);
            }
            return out;
        }

        /// Encrypt multiple blocks in parallel with the same round key.
        pub inline fn encryptWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].encrypt(round_key);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel with the same round key.
        pub inline fn decryptWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].decrypt(round_key);
            }
            return out;
        }

        /// Encrypt multiple blocks in parallel with the same last round key.
        pub inline fn encryptLastWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].encryptLast(round_key);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel with the same last round key.
        pub inline fn decryptLastWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            comptime var i = 0;
            var out: [count]Block = undefined;
            inline while (i < count) : (i += 1) {
                out[i] = blocks[i].decryptLast(round_key);
            }
            return out;
        }
    };
};

/// A fixed-size vector of AES blocks.
/// All operations are performed in parallel, using SIMD instructions when available.
pub fn BlockVec(comptime blocks_count: comptime_int) type {
    return struct {
        const Self = @This();

        /// The number of AES blocks the target architecture can process with a single instruction.
        pub const native_vector_size = 1;

        /// The size of the AES block vector that the target architecture can process with a single instruction, in bytes.
        pub const native_word_size = native_vector_size * 16;

        const native_words = blocks_count;

        /// Internal representation of a block vector.
        repr: [native_words]Block,

        /// Length of the block vector in bytes.
        pub const block_length: usize = blocks_count * 16;

        /// Convert a byte sequence into an internal representation.
        pub inline fn fromBytes(bytes: *const [blocks_count * 16]u8) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = Block.fromBytes(bytes[i * native_word_size ..][0..native_word_size]);
            }
            return out;
        }

        /// Convert the internal representation of a block vector into a byte sequence.
        pub inline fn toBytes(block_vec: Self) [blocks_count * 16]u8 {
            var out: [blocks_count * 16]u8 = undefined;
            inline for (0..native_words) |i| {
                out[i * native_word_size ..][0..native_word_size].* = block_vec.repr[i].toBytes();
            }
            return out;
        }

        /// XOR the block vector with a byte sequence.
        pub inline fn xorBytes(block_vec: Self, bytes: *const [blocks_count * 16]u8) [32]u8 {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].xorBytes(bytes[i * native_word_size ..][0..native_word_size]);
            }
            return out;
        }

        /// Apply the forward AES operation to the block vector with a vector of round keys.
        pub inline fn encrypt(block_vec: Self, round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].encrypt(round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the forward AES operation to the block vector with a vector of last round keys.
        pub inline fn encryptLast(block_vec: Self, round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].encryptLast(round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the inverse AES operation to the block vector with a vector of round keys.
        pub inline fn decrypt(block_vec: Self, inv_round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].decrypt(inv_round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the inverse AES operation to the block vector with a vector of last round keys.
        pub inline fn decryptLast(block_vec: Self, inv_round_key_vec: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].decryptLast(inv_round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the bitwise XOR operation to the content of two block vectors.
        pub inline fn xorBlocks(block_vec1: Self, block_vec2: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i].xorBlocks(block_vec2.repr[i]);
            }
            return out;
        }

        /// Apply the bitwise AND operation to the content of two block vectors.
        pub inline fn andBlocks(block_vec1: Self, block_vec2: Self) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i].andBlocks(block_vec2.repr[i]);
            }
            return out;
        }

        /// Apply the bitwise OR operation to the content of two block vectors.
        pub inline fn orBlocks(block_vec1: Self, block_vec2: Block) Self {
            var out: Self = undefined;
            inline for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i].orBlocks(block_vec2.repr[i]);
            }
            return out;
        }
    };
}

fn KeySchedule(comptime Aes: type) type {
    std.debug.assert(Aes.rounds == 10 or Aes.rounds == 14);
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();

        const Repr = Aes.block.Repr;

        const zero = @Vector(2, u64){ 0, 0 };
        const mask1 = @Vector(16, u8){ 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12 };
        const mask2 = @Vector(16, u8){ 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15 };

        round_keys: [rounds + 1]Block,

        fn drc128(comptime rc: u8, t: Repr) Repr {
            var v1: Repr = undefined;
            var v2: Repr = undefined;
            var v3: Repr = undefined;
            var v4: Repr = undefined;

            return asm (
                \\ movi %[v2].4s, %[rc]
                \\ tbl  %[v4].16b, {%[t].16b}, %[mask].16b
                \\ ext  %[r].16b, %[zero].16b, %[t].16b, #12
                \\ aese %[v4].16b, %[zero].16b
                \\ eor  %[v2].16b, %[r].16b, %[v2].16b
                \\ ext  %[r].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v2].16b, %[t].16b
                \\ ext  %[v3].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v1].16b, %[r].16b
                \\ eor  %[r].16b, %[v1].16b, %[v3].16b
                \\ eor  %[r].16b, %[r].16b, %[v4].16b
                : [r] "=&x" (-> Repr),
                  [v1] "=&x" (v1),
                  [v2] "=&x" (v2),
                  [v3] "=&x" (v3),
                  [v4] "=&x" (v4),
                : [rc] "N" (rc),
                  [t] "x" (t),
                  [zero] "x" (zero),
                  [mask] "x" (mask1),
            );
        }

        fn drc256(comptime second: bool, comptime rc: u8, t: Repr, tx: Repr) Repr {
            var v1: Repr = undefined;
            var v2: Repr = undefined;
            var v3: Repr = undefined;
            var v4: Repr = undefined;

            return asm (
                \\ movi %[v2].4s, %[rc]
                \\ tbl  %[v4].16b, {%[t].16b}, %[mask].16b
                \\ ext  %[r].16b, %[zero].16b, %[tx].16b, #12
                \\ aese %[v4].16b, %[zero].16b
                \\ eor  %[v1].16b, %[tx].16b, %[r].16b
                \\ ext  %[r].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v1].16b, %[r].16b
                \\ ext  %[v3].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v1].16b, %[v2].16b
                \\ eor  %[v1].16b, %[v1].16b, %[v3].16b
                \\ eor  %[r].16b, %[v1].16b, %[v4].16b
                : [r] "=&x" (-> Repr),
                  [v1] "=&x" (v1),
                  [v2] "=&x" (v2),
                  [v3] "=&x" (v3),
                  [v4] "=&x" (v4),
                : [rc] "N" (if (second) @as(u8, 0) else rc),
                  [t] "x" (t),
                  [tx] "x" (tx),
                  [zero] "x" (zero),
                  [mask] "x" (if (second) mask2 else mask1),
            );
        }

        fn expand128(t1: *Block) Self {
            var round_keys: [11]Block = undefined;
            const rcs = [_]u8{ 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
            inline for (rcs, 0..) |rc, round| {
                round_keys[round] = t1.*;
                t1.repr = drc128(rc, t1.repr);
            }
            round_keys[rcs.len] = t1.*;
            return Self{ .round_keys = round_keys };
        }

        fn expand256(t1: *Block, t2: *Block) Self {
            var round_keys: [15]Block = undefined;
            const rcs = [_]u8{ 1, 2, 4, 8, 16, 32 };
            round_keys[0] = t1.*;
            inline for (rcs, 0..) |rc, round| {
                round_keys[round * 2 + 1] = t2.*;
                t1.repr = drc256(false, rc, t2.repr, t1.repr);
                round_keys[round * 2 + 2] = t1.*;
                t2.repr = drc256(true, rc, t1.repr, t2.repr);
            }
            round_keys[rcs.len * 2 + 1] = t2.*;
            t1.repr = drc256(false, 64, t2.repr, t1.repr);
            round_keys[rcs.len * 2 + 2] = t1.*;
            return Self{ .round_keys = round_keys };
        }

        /// Invert the key schedule.
        pub fn invert(key_schedule: Self) Self {
            const round_keys = &key_schedule.round_keys;
            var inv_round_keys: [rounds + 1]Block = undefined;
            inv_round_keys[0] = round_keys[rounds];
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                inv_round_keys[i] = Block{
                    .repr = asm (
                        \\ aesimc %[inv_rk].16b, %[rk].16b
                        : [inv_rk] "=x" (-> Repr),
                        : [rk] "x" (round_keys[rounds - i].repr),
                    ),
                };
            }
            inv_round_keys[rounds] = round_keys[0];
            return Self{ .round_keys = inv_round_keys };
        }
    };
}

/// A context to perform encryption using the standard AES key schedule.
pub fn AesEncryptCtx(comptime Aes: type) type {
    std.debug.assert(Aes.key_bits == 128 or Aes.key_bits == 256);
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();
        pub const block = Aes.block;
        pub const block_length = block.block_length;
        key_schedule: KeySchedule(Aes),

        /// Create a new encryption context with the given key.
        pub fn init(key: [Aes.key_bits / 8]u8) Self {
            var t1 = Block.fromBytes(key[0..16]);
            const key_schedule = if (Aes.key_bits == 128) ks: {
                break :ks KeySchedule(Aes).expand128(&t1);
            } else ks: {
                var t2 = Block.fromBytes(key[16..32]);
                break :ks KeySchedule(Aes).expand256(&t1, &t2);
            };
            return Self{
                .key_schedule = key_schedule,
            };
        }

        /// Encrypt a single block.
        pub fn encrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(src).xorBlocks(round_keys[0]);
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                t = t.encrypt(round_keys[i]);
            }
            t = t.encryptLast(round_keys[rounds]);
            dst.* = t.toBytes();
        }

        /// Encrypt+XOR a single block.
        pub fn xor(ctx: Self, dst: *[16]u8, src: *const [16]u8, counter: [16]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(&counter).xorBlocks(round_keys[0]);
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                t = t.encrypt(round_keys[i]);
            }
            t = t.encryptLast(round_keys[rounds]);
            dst.* = t.xorBytes(src);
        }

        /// Encrypt multiple blocks, possibly leveraging parallelization.
        pub fn encryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var ts: [count]Block = undefined;
            comptime var j = 0;
            inline while (j < count) : (j += 1) {
                ts[j] = Block.fromBytes(src[j * 16 .. j * 16 + 16][0..16]).xorBlocks(round_keys[0]);
            }
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                ts = Block.parallel.encryptWide(count, ts, round_keys[i]);
            }
            ts = Block.parallel.encryptLastWide(count, ts, round_keys[i]);
            j = 0;
            inline while (j < count) : (j += 1) {
                dst[16 * j .. 16 * j + 16].* = ts[j].toBytes();
            }
        }

        /// Encrypt+XOR multiple blocks, possibly leveraging parallelization.
        pub fn xorWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8, counters: [16 * count]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var ts: [count]Block = undefined;
            comptime var j = 0;
            inline while (j < count) : (j += 1) {
                ts[j] = Block.fromBytes(counters[j * 16 .. j * 16 + 16][0..16]).xorBlocks(round_keys[0]);
            }
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                ts = Block.parallel.encryptWide(count, ts, round_keys[i]);
            }
            ts = Block.parallel.encryptLastWide(count, ts, round_keys[i]);
            j = 0;
            inline while (j < count) : (j += 1) {
                dst[16 * j .. 16 * j + 16].* = ts[j].xorBytes(src[16 * j .. 16 * j + 16]);
            }
        }
    };
}

/// A context to perform decryption using the standard AES key schedule.
pub fn AesDecryptCtx(comptime Aes: type) type {
    std.debug.assert(Aes.key_bits == 128 or Aes.key_bits == 256);
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();
        pub const block = Aes.block;
        pub const block_length = block.block_length;
        key_schedule: KeySchedule(Aes),

        /// Create a decryption context from an existing encryption context.
        pub fn initFromEnc(ctx: AesEncryptCtx(Aes)) Self {
            return Self{
                .key_schedule = ctx.key_schedule.invert(),
            };
        }

        /// Create a new decryption context with the given key.
        pub fn init(key: [Aes.key_bits / 8]u8) Self {
            const enc_ctx = AesEncryptCtx(Aes).init(key);
            return initFromEnc(enc_ctx);
        }

        /// Decrypt a single block.
        pub fn decrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            const inv_round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(src).xorBlocks(inv_round_keys[0]);
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                t = t.decrypt(inv_round_keys[i]);
            }
            t = t.decryptLast(inv_round_keys[rounds]);
            dst.* = t.toBytes();
        }

        /// Decrypt multiple blocks, possibly leveraging parallelization.
        pub fn decryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
            const inv_round_keys = ctx.key_schedule.round_keys;
            var ts: [count]Block = undefined;
            comptime var j = 0;
            inline while (j < count) : (j += 1) {
                ts[j] = Block.fromBytes(src[j * 16 .. j * 16 + 16][0..16]).xorBlocks(inv_round_keys[0]);
            }
            comptime var i = 1;
            inline while (i < rounds) : (i += 1) {
                ts = Block.parallel.decryptWide(count, ts, inv_round_keys[i]);
            }
            ts = Block.parallel.decryptLastWide(count, ts, inv_round_keys[i]);
            j = 0;
            inline while (j < count) : (j += 1) {
                dst[16 * j .. 16 * j + 16].* = ts[j].toBytes();
            }
        }
    };
}

/// AES-128 with the standard key schedule.
pub const Aes128 = struct {
    pub const key_bits: usize = 128;
    pub const rounds = ((key_bits - 64) / 32 + 8);
    pub const block = Block;

    /// Create a new context for encryption.
    pub fn initEnc(key: [key_bits / 8]u8) AesEncryptCtx(Aes128) {
        return AesEncryptCtx(Aes128).init(key);
    }

    /// Create a new context for decryption.
    pub fn initDec(key: [key_bits / 8]u8) AesDecryptCtx(Aes128) {
        return AesDecryptCtx(Aes128).init(key);
    }
};

/// AES-256 with the standard key schedule.
pub const Aes256 = struct {
    pub const key_bits: usize = 256;
    pub const rounds = ((key_bits - 64) / 32 + 8);
    pub const block = Block;

    /// Create a new context for encryption.
    pub fn initEnc(key: [key_bits / 8]u8) AesEncryptCtx(Aes256) {
        return AesEncryptCtx(Aes256).init(key);
    }

    /// Create a new context for decryption.
    pub fn initDec(key: [key_bits / 8]u8) AesDecryptCtx(Aes256) {
        return AesDecryptCtx(Aes256).init(key);
    }
};
const std = @import("../../std.zig");
const math = std.math;
const mem = std.mem;

const side_channels_mitigations = std.options.side_channels_mitigations;

/// A single AES block.
pub const Block = struct {
    const Repr = [4]u32;

    pub const block_length: usize = 16;

    /// Internal representation of a block.
    repr: Repr align(16),

    /// Convert a byte sequence into an internal representation.
    pub inline fn fromBytes(bytes: *const [16]u8) Block {
        const s0 = mem.readInt(u32, bytes[0..4], .little);
        const s1 = mem.readInt(u32, bytes[4..8], .little);
        const s2 = mem.readInt(u32, bytes[8..12], .little);
        const s3 = mem.readInt(u32, bytes[12..16], .little);
        return Block{ .repr = Repr{ s0, s1, s2, s3 } };
    }

    /// Convert the internal representation of a block into a byte sequence.
    pub inline fn toBytes(block: Block) [16]u8 {
        var bytes: [16]u8 = undefined;
        mem.writeInt(u32, bytes[0..4], block.repr[0], .little);
        mem.writeInt(u32, bytes[4..8], block.repr[1], .little);
        mem.writeInt(u32, bytes[8..12], block.repr[2], .little);
        mem.writeInt(u32, bytes[12..16], block.repr[3], .little);
        return bytes;
    }

    /// XOR the block with a byte sequence.
    pub inline fn xorBytes(block: Block, bytes: *const [16]u8) [16]u8 {
        const block_bytes = block.toBytes();
        var x: [16]u8 = undefined;
        comptime var i: usize = 0;
        inline while (i < 16) : (i += 1) {
            x[i] = block_bytes[i] ^ bytes[i];
        }
        return x;
    }

    /// Encrypt a block with a round key.
    pub inline fn encrypt(block: Block, round_key: Block) Block {
        const s0 = block.repr[0];
        const s1 = block.repr[1];
        const s2 = block.repr[2];
        const s3 = block.repr[3];

        var x: [4]u32 = undefined;
        x = table_lookup(&table_encrypt, @as(u8, @truncate(s0)), @as(u8, @truncate(s1 >> 8)), @as(u8, @truncate(s2 >> 16)), @as(u8, @truncate(s3 >> 24)));
        var t0 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = table_lookup(&table_encrypt, @as(u8, @truncate(s1)), @as(u8, @truncate(s2 >> 8)), @as(u8, @truncate(s3 >> 16)), @as(u8, @truncate(s0 >> 24)));
        var t1 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = table_lookup(&table_encrypt, @as(u8, @truncate(s2)), @as(u8, @truncate(s3 >> 8)), @as(u8, @truncate(s0 >> 16)), @as(u8, @truncate(s1 >> 24)));
        var t2 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = table_lookup(&table_encrypt, @as(u8, @truncate(s3)), @as(u8, @truncate(s0 >> 8)), @as(u8, @truncate(s1 >> 16)), @as(u8, @truncate(s2 >> 24)));
        var t3 = x[0] ^ x[1] ^ x[2] ^ x[3];

        t0 ^= round_key.repr[0];
        t1 ^= round_key.repr[1];
        t2 ^= round_key.repr[2];
        t3 ^= round_key.repr[3];

        return Block{ .repr = Repr{ t0, t1, t2, t3 } };
    }

    /// Encrypt a block with a round key *WITHOUT ANY PROTECTION AGAINST SIDE CHANNELS*
    pub inline fn encryptUnprotected(block: Block, round_key: Block) Block {
        const s0 = block.repr[0];
        const s1 = block.repr[1];
        const s2 = block.repr[2];
        const s3 = block.repr[3];

        var x: [4]u32 = undefined;
        x = .{
            table_encrypt[0][@as(u8, @truncate(s0))],
            table_encrypt[1][@as(u8, @truncate(s1 >> 8))],
            table_encrypt[2][@as(u8, @truncate(s2 >> 16))],
            table_encrypt[3][@as(u8, @truncate(s3 >> 24))],
        };
        var t0 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = .{
            table_encrypt[0][@as(u8, @truncate(s1))],
            table_encrypt[1][@as(u8, @truncate(s2 >> 8))],
            table_encrypt[2][@as(u8, @truncate(s3 >> 16))],
            table_encrypt[3][@as(u8, @truncate(s0 >> 24))],
        };
        var t1 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = .{
            table_encrypt[0][@as(u8, @truncate(s2))],
            table_encrypt[1][@as(u8, @truncate(s3 >> 8))],
            table_encrypt[2][@as(u8, @truncate(s0 >> 16))],
            table_encrypt[3][@as(u8, @truncate(s1 >> 24))],
        };
        var t2 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = .{
            table_encrypt[0][@as(u8, @truncate(s3))],
            table_encrypt[1][@as(u8, @truncate(s0 >> 8))],
            table_encrypt[2][@as(u8, @truncate(s1 >> 16))],
            table_encrypt[3][@as(u8, @truncate(s2 >> 24))],
        };
        var t3 = x[0] ^ x[1] ^ x[2] ^ x[3];

        t0 ^= round_key.repr[0];
        t1 ^= round_key.repr[1];
        t2 ^= round_key.repr[2];
        t3 ^= round_key.repr[3];

        return Block{ .repr = Repr{ t0, t1, t2, t3 } };
    }

    /// Encrypt a block with the last round key.
    pub inline fn encryptLast(block: Block, round_key: Block) Block {
        const s0 = block.repr[0];
        const s1 = block.repr[1];
        const s2 = block.repr[2];
        const s3 = block.repr[3];

        // Last round uses s-box directly and XORs to produce output.
        var x: [4]u8 = undefined;
        x = sbox_lookup(&sbox_encrypt, @as(u8, @truncate(s0)), @as(u8, @truncate(s1 >> 8)), @as(u8, @truncate(s2 >> 16)), @as(u8, @truncate(s3 >> 24)));
        var t0 = mem.readInt(u32, &x, .little);
        x = sbox_lookup(&sbox_encrypt, @as(u8, @truncate(s1)), @as(u8, @truncate(s2 >> 8)), @as(u8, @truncate(s3 >> 16)), @as(u8, @truncate(s0 >> 24)));
        var t1 = mem.readInt(u32, &x, .little);
        x = sbox_lookup(&sbox_encrypt, @as(u8, @truncate(s2)), @as(u8, @truncate(s3 >> 8)), @as(u8, @truncate(s0 >> 16)), @as(u8, @truncate(s1 >> 24)));
        var t2 = mem.readInt(u32, &x, .little);
        x = sbox_lookup(&sbox_encrypt, @as(u8, @truncate(s3)), @as(u8, @truncate(s0 >> 8)), @as(u8, @truncate(s1 >> 16)), @as(u8, @truncate(s2 >> 24)));
        var t3 = mem.readInt(u32, &x, .little);

        t0 ^= round_key.repr[0];
        t1 ^= round_key.repr[1];
        t2 ^= round_key.repr[2];
        t3 ^= round_key.repr[3];

        return Block{ .repr = Repr{ t0, t1, t2, t3 } };
    }

    /// Decrypt a block with a round key.
    pub inline fn decrypt(block: Block, round_key: Block) Block {
        const s0 = block.repr[0];
        const s1 = block.repr[1];
        const s2 = block.repr[2];
        const s3 = block.repr[3];

        var x: [4]u32 = undefined;
        x = table_lookup(&table_decrypt, @as(u8, @truncate(s0)), @as(u8, @truncate(s3 >> 8)), @as(u8, @truncate(s2 >> 16)), @as(u8, @truncate(s1 >> 24)));
        var t0 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = table_lookup(&table_decrypt, @as(u8, @truncate(s1)), @as(u8, @truncate(s0 >> 8)), @as(u8, @truncate(s3 >> 16)), @as(u8, @truncate(s2 >> 24)));
        var t1 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = table_lookup(&table_decrypt, @as(u8, @truncate(s2)), @as(u8, @truncate(s1 >> 8)), @as(u8, @truncate(s0 >> 16)), @as(u8, @truncate(s3 >> 24)));
        var t2 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = table_lookup(&table_decrypt, @as(u8, @truncate(s3)), @as(u8, @truncate(s2 >> 8)), @as(u8, @truncate(s1 >> 16)), @as(u8, @truncate(s0 >> 24)));
        var t3 = x[0] ^ x[1] ^ x[2] ^ x[3];

        t0 ^= round_key.repr[0];
        t1 ^= round_key.repr[1];
        t2 ^= round_key.repr[2];
        t3 ^= round_key.repr[3];

        return Block{ .repr = Repr{ t0, t1, t2, t3 } };
    }

    /// Decrypt a block with a round key *WITHOUT ANY PROTECTION AGAINST SIDE CHANNELS*
    pub inline fn decryptUnprotected(block: Block, round_key: Block) Block {
        const s0 = block.repr[0];
        const s1 = block.repr[1];
        const s2 = block.repr[2];
        const s3 = block.repr[3];

        var x: [4]u32 = undefined;
        x = .{
            table_decrypt[0][@as(u8, @truncate(s0))],
            table_decrypt[1][@as(u8, @truncate(s3 >> 8))],
            table_decrypt[2][@as(u8, @truncate(s2 >> 16))],
            table_decrypt[3][@as(u8, @truncate(s1 >> 24))],
        };
        var t0 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = .{
            table_decrypt[0][@as(u8, @truncate(s1))],
            table_decrypt[1][@as(u8, @truncate(s0 >> 8))],
            table_decrypt[2][@as(u8, @truncate(s3 >> 16))],
            table_decrypt[3][@as(u8, @truncate(s2 >> 24))],
        };
        var t1 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = .{
            table_decrypt[0][@as(u8, @truncate(s2))],
            table_decrypt[1][@as(u8, @truncate(s1 >> 8))],
            table_decrypt[2][@as(u8, @truncate(s0 >> 16))],
            table_decrypt[3][@as(u8, @truncate(s3 >> 24))],
        };
        var t2 = x[0] ^ x[1] ^ x[2] ^ x[3];
        x = .{
            table_decrypt[0][@as(u8, @truncate(s3))],
            table_decrypt[1][@as(u8, @truncate(s2 >> 8))],
            table_decrypt[2][@as(u8, @truncate(s1 >> 16))],
            table_decrypt[3][@as(u8, @truncate(s0 >> 24))],
        };
        var t3 = x[0] ^ x[1] ^ x[2] ^ x[3];

        t0 ^= round_key.repr[0];
        t1 ^= round_key.repr[1];
        t2 ^= round_key.repr[2];
        t3 ^= round_key.repr[3];

        return Block{ .repr = Repr{ t0, t1, t2, t3 } };
    }

    /// Decrypt a block with the last round key.
    pub inline fn decryptLast(block: Block, round_key: Block) Block {
        const s0 = block.repr[0];
        const s1 = block.repr[1];
        const s2 = block.repr[2];
        const s3 = block.repr[3];

        // Last round uses s-box directly and XORs to produce output.
        var x: [4]u8 = undefined;
        x = sbox_lookup(&sbox_decrypt, @as(u8, @truncate(s0)), @as(u8, @truncate(s3 >> 8)), @as(u8, @truncate(s2 >> 16)), @as(u8, @truncate(s1 >> 24)));
        var t0 = mem.readInt(u32, &x, .little);
        x = sbox_lookup(&sbox_decrypt, @as(u8, @truncate(s1)), @as(u8, @truncate(s0 >> 8)), @as(u8, @truncate(s3 >> 16)), @as(u8, @truncate(s2 >> 24)));
        var t1 = mem.readInt(u32, &x, .little);
        x = sbox_lookup(&sbox_decrypt, @as(u8, @truncate(s2)), @as(u8, @truncate(s1 >> 8)), @as(u8, @truncate(s0 >> 16)), @as(u8, @truncate(s3 >> 24)));
        var t2 = mem.readInt(u32, &x, .little);
        x = sbox_lookup(&sbox_decrypt, @as(u8, @truncate(s3)), @as(u8, @truncate(s2 >> 8)), @as(u8, @truncate(s1 >> 16)), @as(u8, @truncate(s0 >> 24)));
        var t3 = mem.readInt(u32, &x, .little);

        t0 ^= round_key.repr[0];
        t1 ^= round_key.repr[1];
        t2 ^= round_key.repr[2];
        t3 ^= round_key.repr[3];

        return Block{ .repr = Repr{ t0, t1, t2, t3 } };
    }

    /// Apply the bitwise XOR operation to the content of two blocks.
    pub inline fn xorBlocks(block1: Block, block2: Block) Block {
        var x: Repr = undefined;
        comptime var i = 0;
        inline while (i < 4) : (i += 1) {
            x[i] = block1.repr[i] ^ block2.repr[i];
        }
        return Block{ .repr = x };
    }

    /// Apply the bitwise AND operation to the content of two blocks.
    pub inline fn andBlocks(block1: Block, block2: Block) Block {
        var x: Repr = undefined;
        comptime var i = 0;
        inline while (i < 4) : (i += 1) {
            x[i] = block1.repr[i] & block2.repr[i];
        }
        return Block{ .repr = x };
    }

    /// Apply the bitwise OR operation to the content of two blocks.
    pub inline fn orBlocks(block1: Block, block2: Block) Block {
        var x: Repr = undefined;
        comptime var i = 0;
        inline while (i < 4) : (i += 1) {
            x[i] = block1.repr[i] | block2.repr[i];
        }
        return Block{ .repr = x };
    }

    /// Perform operations on multiple blocks in parallel.
    pub const parallel = struct {
        /// The recommended number of AES encryption/decryption to perform in parallel for the chosen implementation.
        pub const optimal_parallel_blocks = 1;

        /// Encrypt multiple blocks in parallel, each their own round key.
        pub fn encryptParallel(comptime count: usize, blocks: [count]Block, round_keys: [count]Block) [count]Block {
            var i = 0;
            var out: [count]Block = undefined;
            while (i < count) : (i += 1) {
                out[i] = blocks[i].encrypt(round_keys[i]);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel, each their own round key.
        pub fn decryptParallel(comptime count: usize, blocks: [count]Block, round_keys: [count]Block) [count]Block {
            var i = 0;
            var out: [count]Block = undefined;
            while (i < count) : (i += 1) {
                out[i] = blocks[i].decrypt(round_keys[i]);
            }
            return out;
        }

        /// Encrypt multiple blocks in parallel with the same round key.
        pub fn encryptWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            var i = 0;
            var out: [count]Block = undefined;
            while (i < count) : (i += 1) {
                out[i] = blocks[i].encrypt(round_key);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel with the same round key.
        pub fn decryptWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            var i = 0;
            var out: [count]Block = undefined;
            while (i < count) : (i += 1) {
                out[i] = blocks[i].decrypt(round_key);
            }
            return out;
        }

        /// Encrypt multiple blocks in parallel with the same last round key.
        pub fn encryptLastWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            var i = 0;
            var out: [count]Block = undefined;
            while (i < count) : (i += 1) {
                out[i] = blocks[i].encryptLast(round_key);
            }
            return out;
        }

        /// Decrypt multiple blocks in parallel with the same last round key.
        pub fn decryptLastWide(comptime count: usize, blocks: [count]Block, round_key: Block) [count]Block {
            var i = 0;
            var out: [count]Block = undefined;
            while (i < count) : (i += 1) {
                out[i```
