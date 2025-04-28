```
] = blocks[i].decryptLast(round_key);
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
            for (0..native_words) |i| {
                out.repr[i] = Block.fromBytes(bytes[i * native_word_size ..][0..native_word_size]);
            }
            return out;
        }

        /// Convert the internal representation of a block vector into a byte sequence.
        pub inline fn toBytes(block_vec: Self) [blocks_count * 16]u8 {
            var out: [blocks_count * 16]u8 = undefined;
            for (0..native_words) |i| {
                out[i * native_word_size ..][0..native_word_size].* = block_vec.repr[i].toBytes();
            }
            return out;
        }

        /// XOR the block vector with a byte sequence.
        pub inline fn xorBytes(block_vec: Self, bytes: *const [blocks_count * 16]u8) [32]u8 {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].xorBytes(bytes[i * native_word_size ..][0..native_word_size]);
            }
            return out;
        }

        /// Apply the forward AES operation to the block vector with a vector of round keys.
        pub inline fn encrypt(block_vec: Self, round_key_vec: Self) Self {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].encrypt(round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the forward AES operation to the block vector with a vector of last round keys.
        pub inline fn encryptLast(block_vec: Self, round_key_vec: Self) Self {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].encryptLast(round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the inverse AES operation to the block vector with a vector of round keys.
        pub inline fn decrypt(block_vec: Self, inv_round_key_vec: Self) Self {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].decrypt(inv_round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the inverse AES operation to the block vector with a vector of last round keys.
        pub inline fn decryptLast(block_vec: Self, inv_round_key_vec: Self) Self {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec.repr[i].decryptLast(inv_round_key_vec.repr[i]);
            }
            return out;
        }

        /// Apply the bitwise XOR operation to the content of two block vectors.
        pub inline fn xorBlocks(block_vec1: Self, block_vec2: Self) Self {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i].xorBlocks(block_vec2.repr[i]);
            }
            return out;
        }

        /// Apply the bitwise AND operation to the content of two block vectors.
        pub inline fn andBlocks(block_vec1: Self, block_vec2: Self) Self {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i].andBlocks(block_vec2.repr[i]);
            }
            return out;
        }

        /// Apply the bitwise OR operation to the content of two block vectors.
        pub inline fn orBlocks(block_vec1: Self, block_vec2: Block) Self {
            var out: Self = undefined;
            for (0..native_words) |i| {
                out.repr[i] = block_vec1.repr[i].orBlocks(block_vec2.repr[i]);
            }
            return out;
        }
    };
}

fn KeySchedule(comptime Aes: type) type {
    std.debug.assert(Aes.rounds == 10 or Aes.rounds == 14);
    const key_length = Aes.key_bits / 8;
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();
        const words_in_key = key_length / 4;

        round_keys: [rounds + 1]Block,

        // Key expansion algorithm. See FIPS-197, Figure 11.
        fn expandKey(key: [key_length]u8) Self {
            const subw = struct {
                // Apply sbox_encrypt to each byte in w.
                fn func(w: u32) u32 {
                    const x = sbox_lookup(&sbox_key_schedule, @as(u8, @truncate(w)), @as(u8, @truncate(w >> 8)), @as(u8, @truncate(w >> 16)), @as(u8, @truncate(w >> 24)));
                    return mem.readInt(u32, &x, .little);
                }
            }.func;

            var round_keys: [rounds + 1]Block = undefined;
            comptime var i: usize = 0;
            inline while (i < words_in_key) : (i += 1) {
                round_keys[i / 4].repr[i % 4] = mem.readInt(u32, key[4 * i ..][0..4], .big);
            }
            inline while (i < round_keys.len * 4) : (i += 1) {
                var t = round_keys[(i - 1) / 4].repr[(i - 1) % 4];
                if (i % words_in_key == 0) {
                    t = subw(std.math.rotl(u32, t, 8)) ^ (@as(u32, powx[i / words_in_key - 1]) << 24);
                } else if (words_in_key > 6 and i % words_in_key == 4) {
                    t = subw(t);
                }
                round_keys[i / 4].repr[i % 4] = round_keys[(i - words_in_key) / 4].repr[(i - words_in_key) % 4] ^ t;
            }
            i = 0;
            inline while (i < round_keys.len * 4) : (i += 1) {
                round_keys[i / 4].repr[i % 4] = @byteSwap(round_keys[i / 4].repr[i % 4]);
            }
            return Self{ .round_keys = round_keys };
        }

        /// Invert the key schedule.
        pub fn invert(key_schedule: Self) Self {
            const round_keys = &key_schedule.round_keys;
            var inv_round_keys: [rounds + 1]Block = undefined;
            const total_words = 4 * round_keys.len;
            var i: usize = 0;
            while (i < total_words) : (i += 4) {
                const ei = total_words - i - 4;
                comptime var j: usize = 0;
                inline while (j < 4) : (j += 1) {
                    var rk = round_keys[(ei + j) / 4].repr[(ei + j) % 4];
                    if (i > 0 and i + 4 < total_words) {
                        const x = sbox_lookup(&sbox_key_schedule, @as(u8, @truncate(rk >> 24)), @as(u8, @truncate(rk >> 16)), @as(u8, @truncate(rk >> 8)), @as(u8, @truncate(rk)));
                        const y = table_lookup(&table_decrypt, x[3], x[2], x[1], x[0]);
                        rk = y[0] ^ y[1] ^ y[2] ^ y[3];
                    }
                    inv_round_keys[(i + j) / 4].repr[(i + j) % 4] = rk;
                }
            }
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
            const key_schedule = KeySchedule(Aes).expandKey(key);
            return Self{
                .key_schedule = key_schedule,
            };
        }

        /// Encrypt a single block.
        pub fn encrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(src).xorBlocks(round_keys[0]);
            comptime var i = 1;
            if (side_channels_mitigations == .full) {
                inline while (i < rounds) : (i += 1) {
                    t = t.encrypt(round_keys[i]);
                }
            } else {
                inline while (i < 5) : (i += 1) {
                    t = t.encrypt(round_keys[i]);
                }
                inline while (i < rounds - 1) : (i += 1) {
                    t = t.encryptUnprotected(round_keys[i]);
                }
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
            if (side_channels_mitigations == .full) {
                inline while (i < rounds) : (i += 1) {
                    t = t.encrypt(round_keys[i]);
                }
            } else {
                inline while (i < 5) : (i += 1) {
                    t = t.encrypt(round_keys[i]);
                }
                inline while (i < rounds - 1) : (i += 1) {
                    t = t.encryptUnprotected(round_keys[i]);
                }
                t = t.encrypt(round_keys[i]);
            }
            t = t.encryptLast(round_keys[rounds]);
            dst.* = t.xorBytes(src);
        }

        /// Encrypt multiple blocks, possibly leveraging parallelization.
        pub fn encryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
            var i: usize = 0;
            while (i < count) : (i += 1) {
                ctx.encrypt(dst[16 * i .. 16 * i + 16][0..16], src[16 * i .. 16 * i + 16][0..16]);
            }
        }

        /// Encrypt+XOR multiple blocks, possibly leveraging parallelization.
        pub fn xorWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8, counters: [16 * count]u8) void {
            var i: usize = 0;
            while (i < count) : (i += 1) {
                ctx.xor(dst[16 * i .. 16 * i + 16][0..16], src[16 * i .. 16 * i + 16][0..16], counters[16 * i .. 16 * i + 16][0..16].*);
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
            if (side_channels_mitigations == .full) {
                inline while (i < rounds) : (i += 1) {
                    t = t.decrypt(inv_round_keys[i]);
                }
            } else {
                inline while (i < 5) : (i += 1) {
                    t = t.decrypt(inv_round_keys[i]);
                }
                inline while (i < rounds - 1) : (i += 1) {
                    t = t.decryptUnprotected(inv_round_keys[i]);
                }
                t = t.decrypt(inv_round_keys[i]);
            }
            t = t.decryptLast(inv_round_keys[rounds]);
            dst.* = t.toBytes();
        }

        /// Decrypt multiple blocks, possibly leveraging parallelization.
        pub fn decryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
            var i: usize = 0;
            while (i < count) : (i += 1) {
                ctx.decrypt(dst[16 * i .. 16 * i + 16][0..16], src[16 * i .. 16 * i + 16][0..16]);
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

// constants

// Rijndael's irreducible polynomial.
const poly: u9 = 1 << 8 | 1 << 4 | 1 << 3 | 1 << 1 | 1 << 0; // x⁸ + x⁴ + x³ + x + 1

// Powers of x mod poly in GF(2).
const powx = init: {
    var array: [16]u8 = undefined;

    var value = 1;
    for (&array) |*power| {
        power.* = value;
        value = mul(value, 2);
    }

    break :init array;
};

const sbox_encrypt align(64) = generateSbox(false); // S-box for encryption
const sbox_key_schedule align(64) = generateSbox(false); // S-box only for key schedule, so that it uses distinct L1 cache entries than the S-box used for encryption
const sbox_decrypt align(64) = generateSbox(true); // S-box for decryption
const table_encrypt align(64) = generateTable(false); // 4-byte LUTs for encryption
const table_decrypt align(64) = generateTable(true); // 4-byte LUTs for decryption

// Generate S-box substitution values.
fn generateSbox(invert: bool) [256]u8 {
    @setEvalBranchQuota(10000);

    var sbox: [256]u8 = undefined;

    var p: u8 = 1;
    var q: u8 = 1;
    for (sbox) |_| {
        p = mul(p, 3);
        q = mul(q, 0xf6); // divide by 3

        var value: u8 = q ^ 0x63;
        value ^= math.rotl(u8, q, 1);
        value ^= math.rotl(u8, q, 2);
        value ^= math.rotl(u8, q, 3);
        value ^= math.rotl(u8, q, 4);

        if (invert) {
            sbox[value] = p;
        } else {
            sbox[p] = value;
        }
    }

    if (invert) {
        sbox[0x63] = 0x00;
    } else {
        sbox[0x00] = 0x63;
    }

    return sbox;
}

// Generate lookup tables.
fn generateTable(invert: bool) [4][256]u32 {
    @setEvalBranchQuota(50000);

    var table: [4][256]u32 = undefined;

    for (generateSbox(invert), 0..) |value, index| {
        table[0][index] = math.shl(u32, mul(value, if (invert) 0xb else 0x3), 24);
        table[0][index] |= math.shl(u32, mul(value, if (invert) 0xd else 0x1), 16);
        table[0][index] |= math.shl(u32, mul(value, if (invert) 0x9 else 0x1), 8);
        table[0][index] |= mul(value, if (invert) 0xe else 0x2);

        table[1][index] = math.rotl(u32, table[0][index], 8);
        table[2][index] = math.rotl(u32, table[0][index], 16);
        table[3][index] = math.rotl(u32, table[0][index], 24);
    }

    return table;
}

// Multiply a and b as GF(2) polynomials modulo poly.
fn mul(a: u8, b: u8) u8 {
    @setEvalBranchQuota(30000);

    var i: u8 = a;
    var j: u9 = b;
    var s: u9 = 0;

    while (i > 0) : (i >>= 1) {
        if (i & 1 != 0) {
            s ^= j;
        }

        j *= 2;
        if (j & 0x100 != 0) {
            j ^= poly;
        }
    }

    return @as(u8, @truncate(s));
}

const cache_line_bytes = std.atomic.cache_line;

fn sbox_lookup(sbox: *align(64) const [256]u8, idx0: u8, idx1: u8, idx2: u8, idx3: u8) [4]u8 {
    if (side_channels_mitigations == .none) {
        return [4]u8{
            sbox[idx0],
            sbox[idx1],
            sbox[idx2],
            sbox[idx3],
        };
    } else {
        const stride = switch (side_channels_mitigations) {
            .none => unreachable,
            .basic => sbox.len / 4,
            .medium => @min(sbox.len, 2 * cache_line_bytes),
            .full => @min(sbox.len, cache_line_bytes),
        };
        const of0 = idx0 % stride;
        const of1 = idx1 % stride;
        const of2 = idx2 % stride;
        const of3 = idx3 % stride;
        var t: [4][sbox.len / stride]u8 align(64) = undefined;
        var i: usize = 0;
        while (i < t[0].len) : (i += 1) {
            const tx = sbox[i * stride ..];
            t[0][i] = tx[of0];
            t[1][i] = tx[of1];
            t[2][i] = tx[of2];
            t[3][i] = tx[of3];
        }
        std.mem.doNotOptimizeAway(t);
        return [4]u8{
            t[0][idx0 / stride],
            t[1][idx1 / stride],
            t[2][idx2 / stride],
            t[3][idx3 / stride],
        };
    }
}

fn table_lookup(table: *align(64) const [4][256]u32, idx0: u8, idx1: u8, idx2: u8, idx3: u8) [4]u32 {
    if (side_channels_mitigations == .none) {
        return [4]u32{
            table[0][idx0],
            table[1][idx1],
            table[2][idx2],
            table[3][idx3],
        };
    } else {
        const table_len: usize = 256;
        const stride = switch (side_channels_mitigations) {
            .none => unreachable,
            .basic => table_len / 4,
            .medium => @max(1, @min(table_len, 2 * cache_line_bytes / 4)),
            .full => @max(1, @min(table_len, cache_line_bytes / 4)),
        };
        const of0 = idx0 % stride;
        const of1 = idx1 % stride;
        const of2 = idx2 % stride;
        const of3 = idx3 % stride;
        var t: [4][table_len / stride]u32 align(64) = undefined;
        var i: usize = 0;
        while (i < t[0].len) : (i += 1) {
            const tx = table[0][i * stride ..];
            t[0][i] = tx[of0];
            t[1][i] = tx[of1];
            t[2][i] = tx[of2];
            t[3][i] = tx[of3];
        }
        std.mem.doNotOptimizeAway(t);
        return [4]u32{
            t[0][idx0 / stride],
            math.rotl(u32, (&t[1])[idx1 / stride], 8),
            math.rotl(u32, (&t[2])[idx2 / stride], 16),
            math.rotl(u32, (&t[3])[idx3 / stride], 24),
        };
    }
}
const std = @import("std");
const AesBlock = std.crypto.core.aes.Block;

pub const Areion512 = struct {
    const Self = @This();

    pub const block_length = 32;
    pub const digest_length = 32;
    pub const Options = struct {};

    blocks: [4]AesBlock = blocks: {
        const ints = [_]u128{ 0x0, 0x0, 0x6a09e667bb67ae853c6ef372a54ff53a, 0x510e527f9b05688c1f83d9ab5be0cd19 };
        var blocks: [ints.len]AesBlock = undefined;
        for (&blocks, ints) |*rc, v| {
            var b: [16]u8 = undefined;
            std.mem.writeIntLittle(u128, &b, v);
            rc.* = AesBlock.fromBytes(&b);
        }
        break :blocks blocks;
    },

    pub fn fromBytes(bytes: [64]u8) Self {
        var blocks: [4]AesBlock = undefined;
        inline for (&blocks, 0..) |*b, i| {
            b.* = AesBlock.fromBytes(bytes[i * 16 ..][0..16]);
        }
        return Self{ .blocks = blocks };
    }

    pub fn absorb(self: *Self, bytes: [32]u8) void {
        self.blocks[0] = AesBlock.fromBytes(bytes[0 * 16 ..][0..16]);
        self.blocks[1] = AesBlock.fromBytes(bytes[1 * 16 ..][0..16]);
    }

    pub fn squeeze(bytes: *[32]u8, self: Self) void {
        @memcpy(bytes[0 * 16 ..][0..16], &self.blocks[2].toBytes());
        @memcpy(bytes[1 * 16 ..][0..16], &self.blocks[3].toBytes());
    }

    pub fn toBytes(self: Self) [64]u8 {
        var bytes: [64]u8 = undefined;
        for (self.blocks, 0..) |b, i| {
            @memcpy(bytes[i * 16 ..][0..16], &b.toBytes());
        }
        return bytes;
    }

    pub fn permute(self: *Self) void {
        const rcs = comptime rcs: {
            const ints = [15]u128{
                0x243f6a8885a308d313198a2e03707344, 0xa4093822299f31d0082efa98ec4e6c89, 0x452821e638d01377be5466cf34e90c6c, 0xc0ac29b7c97c50dd3f84d5b5b5470917, 0x9216d5d98979fb1bd1310ba698dfb5ac, 0x2ffd72dbd01adfb7b8e1afed6a267e96, 0xba7c9045f12c7f9924a19947b3916cf7, 0x801f2e2858efc16636920d871574e690, 0xa458fea3f4933d7e0d95748f728eb658, 0x718bcd5882154aee7b54a41dc25a59b5, 0x9c30d5392af26013c5d1b023286085f0, 0xca417918b8db38ef8e79dcb0603a180e, 0x6c9e0e8bb01e8a3ed71577c1bd314b27, 0x78af2fda55605c60e65525f3aa55ab94, 0x5748986263e8144055ca396a2aab10b6,
            };
            var rcs: [ints.len]AesBlock = undefined;
            for (&rcs, ints) |*rc, v| {
                var b: [16]u8 = undefined;
                std.mem.writeIntLittle(u128, &b, v);
                rc.* = AesBlock.fromBytes(&b);
            }
            break :rcs rcs;
        };
        const rc0 = comptime rc0: {
            const b = [_]u8{0} ** 16;
            break :rc0 AesBlock.fromBytes(&b);
        };
        inline for (rcs) |rc| {
            const x0 = self.blocks[0].encrypt(self.blocks[1]);
            const x1 = self.blocks[2].encryptLast(rc).encrypt(rc0);
            const x2 = self.blocks[2].encrypt(self.blocks[3]);
            const x3 = self.blocks[0].encryptLast(rc0);
            self.blocks = [4]AesBlock{ x0, x1, x2, x3 };
        }
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        _ = options;

        var state = Self{};
        const end = b.len - b.len % 32;
        var i: usize = 0;
        while (i < end) : (i += 32) {
            state.absorb(b[i..][0..32].*);
            state.permute();
        }
        var padded = [_]u8{0} ** 32;
        const left = b.len - end;
        @memcpy(padded[0..left], b[end..]);
        padded[b.len - end] = 0x80;
        const bits = b.len * 8;
        if (left < 32 - 8) {
            std.mem.writeIntBig(u64, padded[32 - 8 ..], bits);
        } else {
            state.absorb(padded);
            state.permute();
            @memset(&padded, 0);
            std.mem.writeIntBig(u64, padded[32 - 8 ..], bits);
        }
        state.absorb(padded);
        state.permute();
        state.squeeze(out);
    }
};

test "permutation" {
    const input = [_]u8{0} ** 64;
    var state = Areion512.fromBytes(input);
    state.permute();
    const out = state.toBytes();
    std.debug.print("{s}\n", .{std.fmt.bytesToHex(out, .lower)});
    try std.testing.expect(false);
}
// https://datatracker.ietf.org/doc/rfc9106
// https://github.com/golang/crypto/tree/master/argon2
// https://github.com/P-H-C/phc-winner-argon2

const std = @import("std");
const builtin = @import("builtin");

const blake2 = crypto.hash.blake2;
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const phc_format = pwhash.phc_format;
const pwhash = crypto.pwhash;

const Thread = std.Thread;
const Blake2b512 = blake2.Blake2b512;
const Blocks = std.ArrayListAligned([block_length]u64, .@"16");
const H0 = [Blake2b512.digest_length + 8]u8;

const EncodingError = crypto.errors.EncodingError;
const KdfError = pwhash.KdfError;
const HasherError = pwhash.HasherError;
const Error = pwhash.Error;

const version = 0x13;
const block_length = 128;
const sync_points = 4;
const max_int = 0xffff_ffff;

const default_salt_len = 32;
const default_hash_len = 32;
const max_salt_len = 64;
const max_hash_len = 64;

/// Argon2 type
pub const Mode = enum {
    /// Argon2d is faster and uses data-depending memory access, which makes it highly resistant
    /// against GPU cracking attacks and suitable for applications with no threats from side-channel
    /// timing attacks (eg. cryptocurrencies).
    argon2d,

    /// Argon2i instead uses data-independent memory access, which is preferred for password
    /// hashing and password-based key derivation, but it is slower as it makes more passes over
    /// the memory to protect from tradeoff attacks.
    argon2i,

    /// Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and
    /// data-independent memory accesses, which gives some of Argon2i's resistance to side-channel
    /// cache timing attacks and much of Argon2d's resistance to GPU cracking attacks.
    argon2id,
};

/// Argon2 parameters
pub const Params = struct {
    const Self = @This();

    /// A [t]ime cost, which defines the amount of computation realized and therefore the execution
    /// time, given in number of iterations.
    t: u32,

    /// A [m]emory cost, which defines the memory usage, given in kibibytes.
    m: u32,

    /// A [p]arallelism degree, which defines the number of parallel threads.
    p: u24,

    /// The [secret] parameter, which is used for keyed hashing. This allows a secret key to be input
    /// at hashing time (from some external location) and be folded into the value of the hash. This
    /// means that even if your salts and hashes are compromised, an attacker cannot brute-force to
    /// find the password without the key.
    secret: ?[]const u8 = null,

    /// The [ad] parameter, which is used to fold any additional data into the hash value. Functionally,
    /// this behaves almost exactly like the secret or salt parameters; the ad parameter is folding
    /// into the value of the hash. However, this parameter is used for different data. The salt
    /// should be a random string stored alongside your password. The secret should be a random key
    /// only usable at hashing time. The ad is for any other data.
    ad: ?[]const u8 = null,

    /// Baseline parameters for interactive logins using argon2i type
    pub const interactive_2i = Self.fromLimits(4, 33554432);
    /// Baseline parameters for normal usage using argon2i type
    pub const moderate_2i = Self.fromLimits(6, 134217728);
    /// Baseline parameters for offline usage using argon2i type
    pub const sensitive_2i = Self.fromLimits(8, 536870912);

    /// Baseline parameters for interactive logins using argon2id type
    pub const interactive_2id = Self.fromLimits(2, 67108864);
    /// Baseline parameters for normal usage using argon2id type
    pub const moderate_2id = Self.fromLimits(3, 268435456);
    /// Baseline parameters for offline usage using argon2id type
    pub const sensitive_2id = Self.fromLimits(4, 1073741824);

    /// Recommended parameters for argon2id type according to the
    /// [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
    pub const owasp_2id = Self{ .t = 2, .m = 19 * 1024, .p = 1 };

    /// Create parameters from ops and mem limits, where mem_limit given in bytes
    pub fn fromLimits(ops_limit: u32, mem_limit: usize) Self {
        const m = mem_limit / 1024;
        std.debug.assert(m <= max_int);
        return .{ .t = ops_limit, .m = @as(u32, @intCast(m)), .p = 1 };
    }
};

fn initHash(
    password: []const u8,
    salt: []const u8,
    params: Params,
    dk_len: usize,
    mode: Mode,
) H0 {
    var h0: H0 = undefined;
    var parameters: [24]u8 = undefined;
    var tmp: [4]u8 = undefined;
    var b2 = Blake2b512.init(.{});
    mem.writeInt(u32, parameters[0..4], params.p, .little);
    mem.writeInt(u32, parameters[4..8], @as(u32, @intCast(dk_len)), .little);
    mem.writeInt(u32, parameters[8..12], params.m, .little);
    mem.writeInt(u32, parameters[12..16], params.t, .little);
    mem.writeInt(u32, parameters[16..20], version, .little);
    mem.writeInt(u32, parameters[20..24], @intFromEnum(mode), .little);
    b2.update(&parameters);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(password.len)), .little);
    b2.update(&tmp);
    b2.update(password);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(salt.len)), .little);
    b2.update(&tmp);
    b2.update(salt);
    const secret = params.secret orelse "";
    std.debug.assert(secret.len <= max_int);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(secret.len)), .little);
    b2.update(&tmp);
    b2.update(secret);
    const ad = params.ad orelse "";
    std.debug.assert(ad.len <= max_int);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(ad.len)), .little);
    b2.update(&tmp);
    b2.update(ad);
    b2.final(h0[0..Blake2b512.digest_length]);
    return h0;
}

fn blake2bLong(out: []u8, in: []const u8) void {
    const H = Blake2b512;
    var outlen_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &outlen_bytes, @as(u32, @intCast(out.len)), .little);

    var out_buf: [H.digest_length]u8 = undefined;

    if (out.len <= H.digest_length) {
        var h = H.init(.{ .expected_out_bits = out.len * 8 });
        h.update(&outlen_bytes);
        h.update(in);
        h.final(&out_buf);
        @memcpy(out, out_buf[0..out.len]);
        return;
    }

    var h = H.init(.{});
    h.update(&outlen_bytes);
    h.update(in);
    h.final(&out_buf);
    var out_slice = out;
    out_slice[0 .. H.digest_length / 2].* = out_buf[0 .. H.digest_length / 2].*;
    out_slice = out_slice[H.digest_length / 2 ..];

    var in_buf: [H.digest_length]u8 = undefined;
    while (out_slice.len > H.digest_length) {
        in_buf = out_buf;
        H.hash(&in_buf, &out_buf, .{});
        out_slice[0 .. H.digest_length / 2].* = out_buf[0 .. H.digest_length / 2].*;
        out_slice = out_slice[H.digest_length / 2 ..];
    }
    in_buf = out_buf;
    H.hash(&in_buf, &out_buf, .{ .expected_out_bits = out_slice.len * 8 });
    @memcpy(out_slice, out_buf[0..out_slice.len]);
}

fn initBlocks(
    blocks: *Blocks,
    h0: *H0,
    memory: u32,
    threads: u24,
) void {
    var block0: [1024]u8 = undefined;
    var lane: u24 = 0;
    while (lane < threads) : (lane += 1) {
        const j = lane * (memory / threads);
        mem.writeInt(u32, h0[Blake2b512.digest_length + 4 ..][0..4], lane, .little);

        mem.writeInt(u32, h0[Blake2b512.digest_length..][0..4], 0, .little);
        blake2bLong(&block0, h0);
        for (&blocks.items[j + 0], 0..) |*v, i| {
            v.* = mem.readInt(u64, block0[i * 8 ..][0..8], .little);
        }

        mem.writeInt(u32, h0[Blake2b512.digest_length..][0..4], 1, .little);
        blake2bLong(&block0, h0);
        for (&blocks.items[j + 1], 0..) |*v, i| {
            v.* = mem.readInt(u64, block0[i * 8 ..][0..8], .little);
        }
    }
}

fn processBlocks(
    allocator: mem.Allocator,
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
) KdfError!void {
    const lanes = memory / threads;
    const segments = lanes / sync_points;

    if (builtin.single_threaded or threads == 1) {
        processBlocksSt(blocks, time, memory, threads, mode, lanes, segments);
    } else {
        try processBlocksMt(allocator, blocks, time, memory, threads, mode, lanes, segments);
    }
}

fn processBlocksSt(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
    lanes: u32,
    segments: u32,
) void {
    var n: u32 = 0;
    while (n < time) : (n += 1) {
        var slice: u32 = 0;
        while (slice < sync_points) : (slice += 1) {
            var lane: u24 = 0;
            while (lane < threads) : (lane += 1) {
                processSegment(blocks, time, memory, threads, mode, lanes, segments, n, slice, lane);
            }
        }
    }
}

fn processBlocksMt(
    allocator: mem.Allocator,
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
    lanes: u32,
    segments: u32,
) KdfError!void {
    var threads_list = try std.ArrayList(Thread).initCapacity(allocator, threads);
    defer threads_list.deinit();

    var n: u32 = 0;
    while (n < time) : (n += 1) {
        var slice: u32 = 0;
        while (slice < sync_points) : (slice += 1) {
            var lane: u24 = 0;
            while (lane < threads) : (lane += 1) {
                const thread = try Thread.spawn(.{}, processSegment, .{
                    blocks, time, memory, threads, mode, lanes, segments, n, slice, lane,
                });
                threads_list.appendAssumeCapacity(thread);
            }
            lane = 0;
            while (lane < threads) : (lane += 1) {
                threads_list.items[lane].join();
            }
            threads_list.clearRetainingCapacity();
        }
    }
}

fn processSegment(
    blocks: *Blocks,
    passes: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
    lanes: u32,
    segments: u32,
    n: u32,
    slice: u32,
    lane: u24,
) void {
    var addresses align(16) = [_]u64{0} ** block_length;
    var in align(16) = [_]u64{0} ** block_length;
    const zero align(16) = [_]u64{0} ** block_length;
    if (mode == .argon2i or (mode == .argon2id and n == 0 and slice < sync_points / 2)) {
        in[0] = n;
        in[1] = lane;
        in[2] = slice;
        in[3] = memory;
        in[4] = passes;
        in[5] = @intFromEnum(mode);
    }
    var index: u32 = 0;
    if (n == 0 and slice == 0) {
        index = 2;
        if (mode == .argon2i or mode == .argon2id) {
            in[6] += 1;
            processBlock(&addresses, &in, &zero);
            processBlock(&addresses, &addresses, &zero);
        }
    }
    var offset = lane * lanes + slice * segments + index;
    var random: u64 = 0;
    while (index < segments) : ({
        index += 1;
        offset += 1;
    }) {
        var prev = offset -% 1;
        if (index == 0 and slice == 0) {
            prev +%= lanes;
        }
        if (mode == .argon2i or (mode == .argon2id and n == 0 and slice < sync_points / 2)) {
            if (index % block_length == 0) {
                in[6] += 1;
                processBlock(&addresses, &in, &zero);
                processBlock(&addresses, &addresses, &zero);
            }
            random = addresses[index % block_length];
        } else {
            random = blocks.items[prev][0];
        }
        const new_offset = indexAlpha(random, lanes, segments, threads, n, slice, lane, index);
        processBlockXor(&blocks.items[offset], &blocks.items[prev], &blocks.items[new_offset]);
    }
}

fn processBlock(
    out: *align(16) [block_length]u64,
    in1: *align(16) const [block_length]u64,
    in2: *align(16) const [block_length]u64,
) void {
    processBlockGeneric(out, in1, in2, false);
}

fn processBlockXor(
    out: *[block_length]u64,
    in1: *const [block_length]u64,
    in2: *const [block_length]u64,
) void {
    processBlockGeneric(out, in1, in2, true);
}

fn processBlockGeneric(
    out: *[block_length]u64,
    in1: *const [block_length]u64,
    in2: *const [block_length]u64,
    comptime xor: bool,
) void {
    var t: [block_length]u64 = undefined;
    for (&t, 0..) |*v, i| {
        v.* = in1[i] ^ in2[i];
    }
    var i: usize = 0;
    while (i < block_length) : (i += 16) {
        blamkaGeneric(t[i..][0..16]);
    }
    i = 0;
    var buffer: [16]u64 = undefined;
    while (i < block_length / 8) : (i += 2) {
        var j: usize = 0;
        while (j < block_length / 8) : (j += 2) {
            buffer[j] = t[j * 8 + i];
            buffer[j + 1] = t[j * 8 + i + 1];
        }
        blamkaGeneric(&buffer);
        j = 0;
        while (j < block_length / 8) : (j += 2) {
            t[j * 8 + i] = buffer[j];
            t[j * 8 + i + 1] = buffer[j + 1];
        }
    }
    if (xor) {
        for (t, 0..) |v, j| {
            out[j] ^= in1[j] ^ in2[j] ^ v;
        }
    } else {
        for (t, 0..) |v, j| {
            out[j] = in1[j] ^ in2[j] ^ v;
        }
    }
}

const QuarterRound = struct { a: usize, b: usize, c: usize, d: usize };

fn Rp(a: usize, b: usize, c: usize, d: usize) QuarterRound {
    return .{ .a = a, .b = b, .c = c, .d = d };
}

fn fBlaMka(x: u64, y: u64) u64 {
    const xy = @as(u64, @as(u32, @truncate(x))) * @as(u64, @as(u32, @truncate(y)));
    return x +% y +% 2 *% xy;
}

fn blamkaGeneric(x: *[16]u64) void {
    const rounds = comptime [_]QuarterRound{
        Rp(0, 4, 8, 12),
        Rp(1, 5, 9, 13),
        Rp(2, 6, 10, 14),
        Rp(3, 7, 11, 15),
        Rp(0, 5, 10, 15),
        Rp(1, 6, 11, 12),
        Rp(2, 7, 8, 13),
        Rp(3, 4, 9, 14),
    };
    inline for (rounds) |r| {
        x[r.a] = fBlaMka(x[r.a], x[r.b]);
        x[r.d] = math.rotr(u64, x[r.d] ^ x[r.a], 32);
        x[r.c] = fBlaMka(x[r.c], x[r.d]);
        x[r.b] = math.rotr(u64, x[r.b] ^ x[r.c], 24);
        x[r.a] = fBlaMka(x[r.a], x[r.b]);
        x[r.d] = math.rotr(u64, x[r.d] ^ x[r.a], 16);
        x[r.c] = fBlaMka(x[r.c], x[r.d]);
        x[r.b] = math.rotr(u64, x[r.b] ^ x[r.c], 63);
    }
}

fn finalize(
    blocks: *Blocks,
    memory: u32,
    threads: u24,
    out: []u8,
) void {
    const lanes = memory / threads;
    var lane: u24 = 0;
    while (lane < threads - 1) : (lane += 1) {
        for (blocks.items[(lane * lanes) + lanes - 1], 0..) |v, i| {
            blocks.items[memory - 1][i] ^= v;
        }
    }
    var block: [1024]u8 = undefined;
    for (blocks.items[memory - 1], 0..) |v, i| {
        mem.writeInt(u64, block[i * 8 ..][0..8], v, .little);
    }
    blake2bLong(out, &block);
}

fn indexAlpha(
    rand: u64,
    lanes: u32,
    segments: u32,
    threads: u24,
    n: u32,
    slice: u32,
    lane: u24,
    index: u32,
) u32 {
    var ref_lane = @as(u32, @intCast(rand >> 32)) % threads;
    if (n == 0 and slice == 0) {
        ref_lane = lane;
    }
    var m = 3 * segments;
    var s = ((slice + 1) % sync_points) * segments;
    if (lane == ref_lane) {
        m += index;
    }
    if (n == 0) {
        m = slice * segments;
        s = 0;
        if (slice == 0 or lane == ref_lane) {
            m += index;
        }
    }
    if (index == 0 or lane == ref_lane) {
        m -= 1;
    }
    var p = @as(u64, @as(u32, @truncate(rand)));
    p = (p * p) >> 32;
    p = (p * m) >> 32;
    return ref_lane * lanes + @as(u32, @intCast(((s + m - (p + 1)) % lanes)));
}

/// Derives a key from the password, salt, and argon2 parameters.
///
/// Derived key has to be at least 4 bytes length.
///
/// Salt has to be at least 8 bytes length.
pub fn kdf(
    allocator: mem.Allocator,
    derived_key: []u8,
    password: []const u8,
    salt: []const u8,
    params: Params,
    mode: Mode,
) KdfError!void {
    if (derived_key.len < 4) return KdfError.WeakParameters;
    if (derived_key.len > max_int) return KdfError.OutputTooLong;

    if (password.len > max_int) return KdfError.WeakParameters;
    if (salt.len < 8 or salt.len > max_int) return KdfError.WeakParameters;
    if (params.t < 1 or params.p < 1) return KdfError.WeakParameters;
    if (params.m / 8 < params.p) return KdfError.WeakParameters;

    var h0 = initHash(password, salt, params, derived_key.len, mode);
    const memory = @max(
        params.m / (sync_points * params.p) * (sync_points * params.p),
        2 * sync_points * params.p,
    );

    var blocks = try Blocks.initCapacity(allocator, memory);
    defer blocks.deinit();

    blocks.appendNTimesAssumeCapacity([_]u64{0} ** block_length, memory);

    initBlocks(&blocks, &h0, memory, params.p);
    try processBlocks(allocator, &blocks, params.t, memory, params.p, mode);
    finalize(&blocks, memory, params.p, derived_key);
}

const PhcFormatHasher = struct {
    const BinValue = phc_format.BinValue;

    const HashResult = struct {
        alg_id: []const u8,
        alg_version: ?u32,
        m: u32,
        t: u32,
        p: u24,
        salt: BinValue(max_salt_len),
        hash: BinValue(max_hash_len),
    };

    pub fn create(
        allocator: mem.Allocator,
        password: []const u8,
        params: Params,
        mode: Mode,
        buf: []u8,
    ) HasherError![]const u8 {
        if (params.secret != null or params.ad != null) return HasherError.InvalidEncoding;

        var salt: [default_salt_len]u8 = undefined;
        crypto.random.bytes(&salt);

        var hash: [default_hash_len]u8 = undefined;
        try kdf(allocator, &hash, password, &salt, params, mode);

        return phc_format.serialize(HashResult{
            .alg_id = @tagName(mode),
            .alg_version = version,
            .m = params.m,
            .t = params.t,
            .p = params.p,
            .salt = try BinValue(max_salt_len).fromSlice(&salt),
            .hash = try BinValue(max_hash_len).fromSlice(&hash),
        }, buf);
    }

    pub fn verify(
        allocator: mem.Allocator,
        str: []const u8,
        password: []const u8,
    ) HasherError!void {
        const hash_result = try phc_format.deserialize(HashResult, str);

        const mode = std.meta.stringToEnum(Mode, hash_result.alg_id) orelse
            return HasherError.PasswordVerificationFailed;
        if (hash_result.alg_version) |v| {
            if (v != version) return HasherError.InvalidEncoding;
        }
        const params = Params{ .t = hash_result.t, .m = hash_result.m, .p = hash_result.p };

        const expected_hash = hash_result.hash.constSlice();
        var hash_buf: [max_hash_len]u8 = undefined;
        if (expected_hash.len > hash_buf.len) return HasherError.InvalidEncoding;
        const hash = hash_buf[0..expected_hash.len];

        try kdf(allocator, hash, password, hash_result.salt.constSlice(), params, mode);
        if (!mem.eql(u8, hash, expected_hash)) return HasherError.PasswordVerificationFailed;
    }
};

/// Options for hashing a password.
///
/// Allocator is required for argon2.
///
/// Only phc encoding is supported.
pub const HashOptions = struct {
    allocator: ?mem.Allocator,
    params: Params,
    mode: Mode = .argon2id,
    encoding: pwhash.Encoding = .phc,
};

/// Compute a hash of a password using the argon2 key derivation function.
/// The function returns a string that includes all the parameters required for verification.
pub fn strHash(
    password: []const u8,
    options: HashOptions,
    out: []u8,
) Error![]const u8 {
    const allocator = options.allocator orelse return Error.AllocatorRequired;
    switch (options.encoding) {
        .phc => return PhcFormatHasher.create(
            allocator,
            password,
            options.params,
            options.mode,
            out,
        ),
        .crypt => return Error.InvalidEncoding,
    }
}

/// Options for hash verification.
///
/// Allocator is required for argon2.
pub const VerifyOptions = struct {
    allocator: ?mem.Allocator,
};

/// Verify that a previously computed hash is valid for a given password.
pub fn strVerify(
    str: []const u8,
    password: []const u8,
    options: VerifyOptions,
) Error!void {
    const allocator = options.allocator orelse return Error.AllocatorRequired;
    return PhcFormatHasher.verify(allocator, str, password);
}

test "argon2d" {
    const password = [_]u8{0x01} ** 32;
    const salt = [_]u8{0x02} ** 16;
    const secret = [_]u8{0x03} ** 8;
    const ad = [_]u8{0x04} ** 12;

    var dk: [32]u8 = undefined;
    try kdf(
        std.testing.allocator,
        &dk,
        &password,
        &salt,
        .{ .t = 3, .m = 32, .p = 4, .secret = &secret, .ad = &ad },
        .argon2d,
    );

    const want = [_]u8{
        0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97,
        0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94,
        0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1,
        0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb,
    };
    try std.testing.expectEqualSlices(u8, &dk, &want);
}

test "argon2i" {
    const password = [_]u8{0x01} ** 32;
    const salt = [_]u8{0x02} ** 16;
    const secret = [_]u8{0x03} ** 8;
    const ad = [_]u8{0x04} ** 12;

    var dk: [32]u8 = undefined;
    try kdf(
        std.testing.allocator,
        &dk,
        &password,
        &salt,
        .{ .t = 3, .m = 32, .p = 4, .secret = &secret, .ad = &ad },
        .argon2i,
    );

    const want = [_]u8{
        0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa,
        0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1,
        0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2,
        0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8,
    };
    try std.testing.expectEqualSlices(u8, &dk, &want);
}

test "argon2id" {
    const password = [_]u8{0x01} ** 32;
    const salt = [_]u8{0x02} ** 16;
    const secret = [_]u8{0x03} ** 8;
    const ad = [_]u8{0x04} ** 12;

    var dk: [32]u8 = undefined;
    try kdf(
        std.testing.allocator,
        &dk,
        &password,
        &salt,
        .{ .t = 3, .m = 32, .p = 4, .secret = &secret, .ad = &ad },
        .argon2id,
    );

    const want = [_]u8{
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
        0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
        0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
    };
    try std.testing.expectEqualSlices(u8, &dk, &want);
}

test "kdf" {
    const password = "password";
    const salt = "somesalt";

    const TestVector = struct {
        mode: Mode,
        time: u32,
        memory: u32,
        threads: u8,
        hash: []const u8,
    };
    const test_vectors = [_]TestVector{
        .{
            .mode = .argon2i,
            .time = 1,
            .memory = 64,
            .threads = 1,
            .hash = "b9c401d1844a67d50eae3967dc28870b22e508092e861a37",
        },
        .{
            .mode = .argon2d,
            .time = 1,
            .memory = 64,
            .threads = 1,
            .hash = "8727405fd07c32c78d64f547f24150d3f2e703a89f981a19",
        },
        .{
            .mode = .argon2id,
            .time = 1,
            .memory = 64,
            .threads = 1,
            .hash = "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb",
        },
        .{
            .mode = .argon2i,
            .time = 2,
            .memory = 64,
            .threads = 1,
            .hash = "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64",
        },
        .{
            .mode = .argon2d,
            .time = 2,
            .memory = 64,
            .threads = 1,
            .hash = "3be9ec79a69b75d3752acb59a1fbb8b295a46529c48fbb75",
        },
        .{
            .mode = .argon2id,
            .time = 2,
            .memory = 64,
            .threads = 1,
            .hash = "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7",
        },
        .{
            .mode = .argon2i,
            .time = 2,
            .memory = 64,
            .threads = 2,
            .hash = "2089f3e78a799720f80af806553128f29b132cafe40d059f",
        },
        .{
            .mode = .argon2d,
            .time = 2,
            .memory = 64,
            .threads = 2,
            .hash = "68e2462c98b8bc6bb60ec68db418ae2c9ed24fc6748a40e9",
        },
        .{
            .mode = .argon2id,
            .time = 2,
            .memory = 64,
            .threads = 2,
            .hash = "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362",
        },
        .{
            .mode = .argon2i,
            .time = 3,
            .memory = 256,
            .threads = 2,
            .hash = "f5bbf5d4c3836af13193053155b73ec7476a6a2eb93fd5e6",
        },
        .{
            .mode = .argon2d,
            .time = 3,
            .memory = 256,
            .threads = 2,
            .hash = "f4f0669218eaf3641f39cc97efb915721102f4b128211ef2",
        },
        .{
            .mode = .argon2id,
            .time = 3,
            .memory = 256,
            .threads = 2,
            .hash = "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b",
        },
        .{
            .mode = .argon2i,
            .time = 4,
            .memory = 4096,
            .threads = 4,
            .hash = "a11f7b7f3f93f02ad4bddb59ab62d121e278369288a0d0e7",
        },
        .{
            .mode = .argon2d,
            .time = 4,
            .memory = 4096,
            .threads = 4,
            .hash = "935598181aa8dc2b720914aa6435ac8d3e3a4210c5b0fb2d",
        },
        .{
            .mode = .argon2id,
            .time = 4,
            .memory = 4096,
            .threads = 4,
            .hash = "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a",
        },
        .{
            .mode = .argon2i,
            .time = 4,
            .memory = 1024,
            .threads = 8,
            .hash = "0cdd3956aa35e6b475a7b0c63488822f774f15b43f6e6e17",
        },
        .{
            .mode = .argon2d,
            .time = 4,
            .memory = 1024,
            .threads = 8,
            .hash = "83604fc2ad0589b9d055578f4d3cc55bc616df3578a896e9",
        },
        .{
            .mode = .argon2id,
            .time = 4,
            .memory = 1024,
            .threads = 8,
            .hash = "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f",
        },
        .{
            .mode = .argon2i,
            .time = 2,
            .memory = 64,
            .threads = 3,
            .hash = "5cab452fe6b8479c8661def8cd703b611a3905a6d5477fe6",
        },
        .{
            .mode = .argon2d,
            .time = 2,
            .memory = 64,
            .threads = 3,
            .hash = "22474a423bda2ccd36ec9afd5119e5c8949798cadf659f51",
        },
        .{
            .mode = .argon2id,
            .time = 2,
            .memory = 64,
            .threads = 3,
            .hash = "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079",
        },
        .{
            .mode = .argon2i,
            .time = 3,
            .memory = 1024,
            .threads = 6,
            .hash = "d236b29c2b2a09babee842b0dec6aa1e83ccbdea8023dced",
        },
        .{
            .mode = .argon2d,
            .time = 3,
            .memory = 1024,
            .threads = 6,
            .hash = "a3351b0319a53229152023d9206902f4ef59661cdca89481",
        },
        .{
            .mode = .argon2id,
            .time = 3,
            .memory = 1024,
            .threads = 6,
            .hash = "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016",
        },
    };
    for (test_vectors) |v| {
        var want: [24]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, v.hash);

        var dk: [24]u8 = undefined;
        try kdf(
            std.testing.allocator,
            &dk,
            password,
            salt,
            .{ .t = v.time, .m = v.memory, .p = v.threads },
            v.mode,
        );

        try std.testing.expectEqualSlices(u8, &dk, &want);
    }
}

test "phc format hasher" {
    const allocator = std.testing.allocator;
    const password = "testpass";

    var buf: [128]u8 = undefined;
    const hash = try PhcFormatHasher.create(
        allocator,
        password,
        .{ .t = 3, .m = 32, .p = 4 },
        .argon2id,
        &buf,
    );
    try PhcFormatHasher.verify(allocator, hash, password);
}

test "password hash and password verify" {
    const allocator = std.testing.allocator;
    const password = "testpass";

    var buf: [128]u8 = undefined;
    const hash = try strHash(
        password,
        .{ .allocator = allocator, .params = .{ .t = 3, .m = 32, .p = 4 } },
        &buf,
    );
    try strVerify(hash, password, .{ .allocator = allocator });
}

test "kdf derived key length" {
    const allocator = std.testing.allocator;

    const password = "testpass";
    const salt = "saltsalt";
    const params = Params{ .t = 3, .m = 32, .p = 4 };
    const mode = Mode.argon2id;

    var dk1: [11]u8 = undefined;
    try kdf(allocator, &dk1, password, salt, params, mode);

    var dk2: [77]u8 = undefined;
    try kdf(allocator, &dk2, password, salt, params, mode);

    var dk3: [111]u8 = undefined;
    try kdf(allocator, &dk3, password, salt, params, mode);
}
const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AsconState = crypto.core.Ascon(.Big);
const AuthenticationError = crypto.errors.AuthenticationError;

const rate = 16;

const AeadState128a = struct {
    const Self = @This();

    p: AsconState,
    k1: u64,
    k2: u64,

    fn init(key: [16]u8, nonce: [16]u8) Self {
        const k1 = mem.readIntBig(u64, key[0..8]);
        const k2 = mem.readIntBig(u64, key[8..][0..8]);
        const n1 = mem.readIntBig(u64, nonce[0..8]);
        const n2 = mem.readIntBig(u64, nonce[8..][0..8]);
        const words: [5]u64 = .{ 0x80800c0800000000, k1, k2, n1, n2 };
        var p = AsconState.initFromWords(words);
        p.permute();
        p.st[3] ^= k1;
        p.st[4] ^= k2;
        return Self{ .k1 = k1, .k2 = k2, .p = p };
    }

    fn absorbAd(self: *Self, src: []const u8) void {
        if (src.len > 0) {
            var i: usize = 0;
            while (i + rate <= src.len) : (i += 16) {
                self.p.addBytes(src[i..][0..16]);
                self.p.permuteR(8);
            }
            var padded = [_]u8{0} ** 16;
            mem.copy(u8, &padded, src[i..]);
            padded[src.len - i] = 0x80;
            self.p.addBytes(&padded);
            self.p.permuteR(8);
        }
        self.p.st[4] ^= 0x01;
    }

    fn enc(self: *Self, dst: []u8, src: []const u8) void {
        assert(src.len == dst.len);
        var i: usize = 0;
        while (i + rate <= src.len) : (i += 16) {
            self.p.addBytes(src[i..][0..16]);
            self.p.extractBytes(dst[i..][0..16]);
            self.p.permuteR(8);
        }
        var padded = [_]u8{0} ** 16;
        mem.copy(u8, &padded, src[i..]);
        padded[i % 16] = 0x80;
        self.p.addBytes(&padded);
        self.p.extractBytes(dst[i..]);
    }

    fn dec(self: *Self, dst: []u8, src: []const u8) void {
        assert(dst.len == src.len);
        var i: usize = 0;
        while (i + rate <= dst.len) : (i += 16) {
            self.p.xorBytes(dst[i..][0..16], src[i..][0..16]);
            self.p.addBytes(dst[i..][0..16]);
            self.p.permuteR(8);
        }
        self.p.xorBytes(dst[i..], src[i..]);
        self.p.addBytes(dst[i..]);
        self.p.addByte(0x80, i % 16);
    }

    fn mac(self: *Self) [16]u8 {
        self.p.st[2] ^= self.k1;
        self.p.st[3] ^= self.k2;
        self.p.permute();
        self.p.st[3] ^= self.k1;
        self.p.st[4] ^= self.k2;

        var tag: [16]u8 = undefined;
        mem.writeIntBig(u64, tag[0..8], self.p.st[3]);
        mem.writeIntBig(u64, tag[8..][0..8], self.p.st[4]);
        return tag;
    }
};

pub const AsconAead128a = struct {
    pub const tag_length = 16;
    pub const nonce_length = 16;
    pub const key_length = 16;
    pub const block_length = 16;

    const State = AeadState128a;

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        assert(c.len == m.len);
        var st = State.init(key, npub);
        st.absorbAd(ad);
        st.enc(c, m);
        mem.copy(u8, tag[0..], st.mac()[0..]);
    }

    /// m: message: output buffer should be of size c.len
    /// c: ciphertext
    /// tag: authentication tag
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);
        var st = State.init(key, npub);
        st.absorbAd(ad);
        st.dec(m, c);
        if (!crypto.utils.timingSafeEql([16]u8, st.mac(), tag)) {
            @memset(m.ptr, undefined, m.len);
            return error.AuthenticationFailed;
        }
    }
};

pub fn main() !void {
    const key = [_]u8{0x42} ** 16;
    const npub = [_]u8{0x69} ** 16;
    var st = AeadState128a.init(key, npub);
    const m = "testABCDTESTabcd";
    const ad = "testabcdTESTABCD";
    var c = [_]u8{0} ** m.len;
    st.absorbAd(ad);
    st.enc(&c, m);
    _ = st.mac();
    std.debug.print("{any} {any}\n", .{ st.p.st[3], st.p.st[4] });

    var tag: [16]u8 = undefined;
    AsconAead128a.encrypt(&c, &tag, m, ad, npub, key);
    var m2: [c.len]u8 = undefined;
    try AsconAead128a.decrypt(&m2, &c, tag, ad, npub, key);
}
//! Ascon is a 320-bit permutation, selected as new standard for lightweight cryptography
//! in the NIST Lightweight Cryptography competition (2019–2023).
//! https://csrc.nist.gov/pubs/sp/800/232/ipd
//!
//! The permutation is compact, and optimized for timing and side channel resistance,
//! making it a good choice for embedded applications.
//!
//! It is not meant to be used directly, but as a building block for symmetric cryptography.

const std = @import("std");
const builtin = @import("builtin");
const debug = std.debug;
const mem = std.mem;
const testing = std.testing;
const rotr = std.math.rotr;
const native_endian = builtin.cpu.arch.endian();

/// An Ascon state.
///
/// The state is represented as 5 64-bit words.
///
/// The original NIST submission (v1.2) serializes these words as big-endian,
/// but NIST SP 800-232 switched to a little-endian representation.
/// Software implementations are free to use native endianness with no security degradation.
pub fn State(comptime endian: std.builtin.Endian) type {
    return struct {
        const Self = @This();

        /// Number of bytes in the state.
        pub const block_bytes = 40;

        const Block = [5]u64;

        st: Block,

        /// Initialize the state from a slice of bytes.
        pub fn init(initial_state: [block_bytes]u8) Self {
            var state = Self{ .st = undefined };
            @memcpy(state.asBytes(), &initial_state);
            state.endianSwap();
            return state;
        }

        /// Initialize the state from u64 words in native endianness.
        pub fn initFromWords(initial_state: [5]u64) Self {
            return .{ .st = initial_state };
        }

        /// Initialize the state for Ascon XOF
        pub fn initXof() Self {
            return Self{ .st = Block{
                0xb57e273b814cd416,
                0x2b51042562ae2420,
                0x66a3a7768ddf2218,
                0x5aad0a7a8153650c,
                0x4f3e0e32539493b6,
            } };
        }

        /// Initialize the state for Ascon XOFa
        pub fn initXofA() Self {
            return Self{ .st = Block{
                0x44906568b77b9832,
                0xcd8d6cae53455532,
                0xf7b5212756422129,
                0x246885e1de0d225b,
                0xa8cb5ce33449973f,
            } };
        }

        /// A representation of the state as bytes. The byte order is architecture-dependent.
        pub fn asBytes(self: *Self) *[block_bytes]u8 {
            return mem.asBytes(&self.st);
        }

        /// Byte-swap the entire state if the architecture doesn't match the required endianness.
        pub fn endianSwap(self: *Self) void {
            for (&self.st) |*w| {
                w.* = mem.toNative(u64, w.*, endian);
            }
        }

        /// Set bytes starting at the beginning of the state.
        pub fn setBytes(self: *Self, bytes: []const u8) void {
            var i: usize = 0;
            while (i + 8 <= bytes.len) : (i += 8) {
                self.st[i / 8] = mem.readInt(u64, bytes[i..][0..8], endian);
            }
            if (i < bytes.len) {
                var padded = [_]u8{0} ** 8;
                @memcpy(padded[0 .. bytes.len - i], bytes[i..]);
                self.st[i / 8] = mem.readInt(u64, padded[0..], endian);
            }
        }

        /// XOR a byte into the state at a given offset.
        pub fn addByte(self: *Self, byte: u8, offset: usize) void {
            const z = switch (endian) {
                .big => 64 - 8 - 8 * @as(u6, @truncate(offset % 8)),
                .little => 8 * @as(u6, @truncate(offset % 8)),
            };
            self.st[offset / 8] ^= @as(u64, byte) << z;
        }

        /// XOR bytes into the beginning of the state.
        pub fn addBytes(self: *Self, bytes: []const u8) void {
            var i: usize = 0;
            while (i + 8 <= bytes.len) : (i += 8) {
                self.st[i / 8] ^= mem.readInt(u64, bytes[i..][0..8], endian);
            }
            if (i < bytes.len) {
                var padded = [_]u8{0} ** 8;
                @memcpy(padded[0 .. bytes.len - i], bytes[i..]);
                self.st[i / 8] ^= mem.readInt(u64, padded[0..], endian);
            }
        }

        /// Extract the first bytes of the state.
        pub fn extractBytes(self: *Self, out: []u8) void {
            var i: usize = 0;
            while (i + 8 <= out.len) : (i += 8) {
                mem.writeInt(u64, out[i..][0..8], self.st[i / 8], endian);
            }
            if (i < out.len) {
                var padded = [_]u8{0} ** 8;
                mem.writeInt(u64, padded[0..], self.st[i / 8], endian);
                @memcpy(out[i..], padded[0 .. out.len - i]);
            }
        }

        /// XOR the first bytes of the state into a slice of bytes.
        pub fn xorBytes(self: *Self, out: []u8, in: []const u8) void {
            debug.assert(out.len == in.len);

            var i: usize = 0;
            while (i + 8 <= in.len) : (i += 8) {
                const x = mem.readInt(u64, in[i..][0..8], native_endian) ^ mem.nativeTo(u64, self.st[i / 8], endian);
                mem.writeInt(u64, out[i..][0..8], x, native_endian);
            }
            if (i < in.len) {
                var padded = [_]u8{0} ** 8;
                @memcpy(padded[0 .. in.len - i], in[i..]);
                const x = mem.readInt(u64, &padded, native_endian) ^ mem.nativeTo(u64, self.st[i / 8], endian);
                mem.writeInt(u64, &padded, x, native_endian);
                @memcpy(out[i..], padded[0 .. in.len - i]);
            }
        }

        /// Set the words storing the bytes of a given range to zero.
        pub fn clear(self: *Self, from: usize, to: usize) void {
            @memset(self.st[from / 8 .. (to + 7) / 8], 0);
        }

        /// Clear the entire state, disabling compiler optimizations.
        pub fn secureZero(self: *Self) void {
            std.crypto.secureZero(u64, &self.st);
        }

        /// Apply a reduced-round permutation to the state.
        pub inline fn permuteR(state: *Self, comptime rounds: u4) void {
            const rks = [16]u64{ 0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b };
            inline for (rks[rks.len - rounds ..]) |rk| {
                state.round(rk);
            }
        }

        /// Apply a full-round permutation to the state.
        pub inline fn permute(state: *Self) void {
            state.permuteR(12);
        }

        /// Apply a permutation to the state and prevent backtracking.
        /// The rate is expressed in bytes and must be a multiple of the word size (8).
        pub inline fn permuteRatchet(state: *Self, comptime rounds: u4, comptime rate: u6) void {
            const capacity = block_bytes - rate;
            debug.assert(capacity > 0 and capacity % 8 == 0); // capacity must be a multiple of 64 bits
            var mask: [capacity / 8]u64 = undefined;
            inline for (&mask, state.st[state.st.len - mask.len ..]) |*m, x| m.* = x;
            state.permuteR(rounds);
            inline for (mask, state.st[state.st.len - mask.len ..]) |m, *x| x.* ^= m;
        }

        // Core Ascon permutation.
        inline fn round(state: *Self, rk: u64) void {
            const x = &state.st;
            x[2] ^= rk;

            x[0] ^= x[4];
            x[4] ^= x[3];
            x[2] ^= x[1];
            var t: Block = .{
                x[0] ^ (~x[1] & x[2]),
                x[1] ^ (~x[2] & x[3]),
                x[2] ^ (~x[3] & x[4]),
                x[3] ^ (~x[4] & x[0]),
                x[4] ^ (~x[0] & x[1]),
            };
            t[1] ^= t[0];
            t[3] ^= t[2];
            t[0] ^= t[4];

            x[2] = t[2] ^ rotr(u64, t[2], 6 - 1);
            x[3] = t[3] ^ rotr(u64, t[3], 17 - 10);
            x[4] = t[4] ^ rotr(u64, t[4], 41 - 7);
            x[0] = t[0] ^ rotr(u64, t[0], 28 - 19);
            x[1] = t[1] ^ rotr(u64, t[1], 61 - 39);
            x[2] = t[2] ^ rotr(u64, x[2], 1);
            x[3] = t[3] ^ rotr(u64, x[3], 10);
            x[4] = t[4] ^ rotr(u64, x[4], 7);
            x[0] = t[0] ^ rotr(u64, x[0], 19);
            x[1] = t[1] ^ rotr(u64, x[1], 39);
            x[2] = ~x[2];
        }
    };
}

test "ascon" {
    const Ascon = State(.big);
    const bytes = [_]u8{0x01} ** Ascon.block_bytes;
    var st = Ascon.init(bytes);
    var out: [Ascon.block_bytes]u8 = undefined;
    st.permute();
    st.extractBytes(&out);
    const expected1 = [_]u8{ 148, 147, 49, 226, 218, 221, 208, 113, 186, 94, 96, 10, 183, 219, 119, 150, 169, 206, 65, 18, 215, 97, 78, 106, 118, 81, 211, 150, 52, 17, 117, 64, 216, 45, 148, 240, 65, 181, 90, 180 };
    try testing.expectEqualSlices(u8, &expected1, &out);
    st.clear(0, 10);
    st.extractBytes(&out);
    const expected2 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 169, 206, 65, 18, 215, 97, 78, 106, 118, 81, 211, 150, 52, 17, 117, 64, 216, 45, 148, 240, 65, 181, 90, 180 };
    try testing.expectEqualSlices(u8, &expected2, &out);
    st.addByte(1, 5);
    st.addByte(2, 5);
    st.extractBytes(&out);
    const expected3 = [_]u8{ 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 169, 206, 65, 18, 215, 97, 78, 106, 118, 81, 211, 150, 52, 17, 117, 64, 216, 45, 148, 240, 65, 181, 90, 180 };
    try testing.expectEqualSlices(u8, &expected3, &out);
    st.addBytes(&bytes);
    st.extractBytes(&out);
    const expected4 = [_]u8{ 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 168, 207, 64, 19, 214, 96, 79, 107, 119, 80, 210, 151, 53, 16, 116, 65, 217, 44, 149, 241, 64, 180, 91, 181 };
    try testing.expectEqualSlices(u8, &expected4, &out);
}
const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const debug = std.debug;
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;
const pwhash = crypto.pwhash;
const testing = std.testing;
const HmacSha512 = crypto.auth.hmac.sha2.HmacSha512;
const Sha512 = crypto.hash.sha2.Sha512;

const phc_format = @import("phc_encoding.zig");

const KdfError = pwhash.KdfError;
const HasherError = pwhash.HasherError;
const EncodingError = phc_format.Error;
const Error = pwhash.Error;

const salt_length: usize = 16;
const salt_str_length: usize = 22;
const ct_str_length: usize = 31;
const ct_length: usize = 24;
const dk_length: usize = ct_length - 1;

/// Length (in bytes) of a password hash in crypt encoding
pub const hash_length: usize = 60;

pub const State = struct {
    sboxes: [4][256]u32 = [4][256]u32{
        .{
            0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
            0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
            0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
            0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
            0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
            0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
            0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
            0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
            0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
            0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
            0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
            0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
            0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
            0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
            0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
            0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
            0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
            0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
            0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
            0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
            0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
            0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
            0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
            0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
            0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
            0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
            0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
            0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
            0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
            0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
            0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
            0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
            0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
            0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
            0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
            0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
            0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
            0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
            0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
            0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
            0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
            0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
            0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
            0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
            0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
            0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
            0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
            0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
            0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
            0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
            0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
            0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
            0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
            0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
            0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
            0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
            0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
            0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
            0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
            0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
            0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
            0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
            0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
            0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a,
        },
        .{
            0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
            0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
            0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
            0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
            0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
            0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
            0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
            0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
            0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
            0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
            0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
            0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
            0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
            0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
            0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
            0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
            0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
            0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
            0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
            0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
            0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
            0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
            0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
            0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
            0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
            0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
            0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
            0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
            0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
            0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
            0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
            0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
            0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
            0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
            0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
            0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
            0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
            0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
            0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
            0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
            0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
            0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
            0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
            0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
            0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
            0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
            0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
            0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
            0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
            0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
            0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
            0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
            0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
            0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
            0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
            0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
            0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
            0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
            0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
            0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
            0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
            0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
            0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
            0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7,
        },
        .{
            0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
            0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
            0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
            0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
            0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
            0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
            0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
            0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
            0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
            0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
            0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
            0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
            0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
            0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
            0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
            0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
            0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
            0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
            0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
            0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
            0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
            0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
            0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
            0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
            0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
            0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
            0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
            0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
            0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
            0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
            0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
            0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
            0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
            0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
            0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
            0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
            0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
            0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
            0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
            0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
            0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
            0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
            0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
            0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
            0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
            0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
            0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
            0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
            0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
            0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
            0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
            0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
            0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
            0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
            0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
            0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
            0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
            0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
            0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
            0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
            0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
            0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
            0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
            0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,
        },
        .{
            0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
            0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
            0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
            0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
            0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
            0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
            0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
            0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
            0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
            0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
            0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
            0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
            0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
            0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
            0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
            0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
            0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
            0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
            0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
            0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
            0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
            0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
            0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
            0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
            0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
            0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
            0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
            0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
            0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
            0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
            0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
            0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
            0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
            0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
            0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
            0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
            0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
            0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
            0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
            0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
            0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
            0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
            0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
            0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
            0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
            0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
            0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
            0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
            0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
            0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
            0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
            0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
            0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
            0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
            0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
            0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
            0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
            0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
            0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
            0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
            0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
            0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
            0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
            0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6,
        },
    },
    subkeys: [18]u32 = [18]u32{
        0x243f6a88, 0x85a308d3, 0x13198a2e,
        0x03707344, 0xa4093822, 0x299f31d0,
        0x082efa98, 0xec4e6c89, 0x452821e6,
        0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5,
        0xb5470917, 0x9216d5d9, 0x8979fb1b,
    },

    fn toWord(data: []const u8, current: *usize) u32 {
        var t: u32 = 0;
        var j = current.*;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            if (j >= data.len) j = 0;
            t = (t << 8) | data[j];
            j += 1;
        }
        current.* = j;
        return t;
    }

    fn expand0(state: *State, key: []const u8) void {
        var i: usize = 0;
        var j: usize = 0;
        while (i < state.subkeys.len) : (i += 1) {
            state.subkeys[i] ^= toWord(key, &j);
        }

        var halves = Halves{ .l = 0, .r = 0 };
        i = 0;
        while (i < 18) : (i += 2) {
            state.encipher(&halves);
            state.subkeys[i] = halves.l;
            state.subkeys[i + 1] = halves.r;
        }

        i = 0;
        while (i < 4) : (i += 1) {
            var k: usize = 0;
            while (k < 256) : (k += 2) {
                state.encipher(&halves);
                state.sboxes[i][k] = halves.l;
                state.sboxes[i][k + 1] = halves.r;
            }
        }
    }

    fn expand(state: *State, data: []const u8, key: []const u8) void {
        var i: usize = 0;
        var j: usize = 0;
        while (i < state.subkeys.len) : (i += 1) {
            state.subkeys[i] ^= toWord(key, &j);
        }

        var halves = Halves{ .l = 0, .r = 0 };
        i = 0;
        j = 0;
        while (i < 18) : (i += 2) {
            halves.l ^= toWord(data, &j);
            halves.r ^= toWord(data, &j);
            state.encipher(&halves);
            state.subkeys[i] = halves.l;
            state.subkeys[i + 1] = halves.r;
        }

        i = 0;
        while (i < 4) : (i += 1) {
            var k: usize = 0;
            while (k < 256) : (k += 2) {
                halves.l ^= toWord(data, &j);
                halves.r ^= toWord(data, &j);
                state.encipher(&halves);
                state.sboxes[i][k] = halves.l;
                state.sboxes[i][k + 1] = halves.r;
            }
        }
    }

    const Halves = struct { l: u32, r: u32 };

    fn halfRound(state: *const State, i: u32, j: u32, n: usize) u32 {
        var r = state.sboxes[0][@as(u8, @truncate(j >> 24))];
        r +%= state.sboxes[1][@as(u8, @truncate(j >> 16))];
        r ^= state.sboxes[2][@as(u8, @truncate(j >> 8))];
        r +%= state.sboxes[3][@as(u8, @truncate(j))];
        return i ^ r ^ state.subkeys[n];
    }

    fn encipher(state: *const State, halves: *Halves) void {
        halves.l ^= state.subkeys[0];
        comptime var i = 1;
        inline while (i < 16) : (i += 2) {
            halves.r = state.halfRound(halves.r, halves.l, i);
            halves.l = state.halfRound(halves.l, halves.r, i + 1);
        }
        const halves_last = Halves{ .l = halves.r ^ state.subkeys[i], .r = halves.l };
        halves.* = halves_last;
    }

    fn encrypt(state: *const State, data: []u32) void {
        debug.assert(data.len % 2 == 0);
        var i: usize = 0;
        while (i < data.len) : (i += 2) {
            var halves = Halves{ .l = data[i], .r = data[i + 1] };
            state.encipher(&halves);
            data[i] = halves.l;
            data[i + 1] = halves.r;
        }
    }
};

/// bcrypt parameters
pub const Params = struct {
    const Self = @This();

    /// log2 of the number of rounds
    rounds_log: u6,

    /// As originally defined, bcrypt silently truncates passwords to 72 bytes.
    /// In order to overcome this limitation, if `silently_truncate_password` is set to `false`,
    /// long passwords will be automatically pre-hashed using HMAC-SHA512 before being passed to bcrypt.
    /// Only set `silently_truncate_password` to `true` for compatibility with traditional bcrypt implementations,
    /// or if you want to handle the truncation yourself.
    silently_truncate_password: bool,

    /// Minimum recommended parameters according to the
    /// [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
    pub const owasp = Self{ .rounds_log = 10, .silently_truncate_password = false };
};

fn bcryptWithTruncation(
    password: []const u8,
    salt: [salt_length]u8,
    params: Params,
) [dk_length]u8 {
    var state = State{};
    var password_buf: [73]u8 = undefined;
    const trimmed_len = @min(password.len, password_buf.len - 1);
    @memcpy(password_buf[0..trimmed_len], password[0..trimmed_len]);
    password_buf[trimmed_len] = 0;
    const passwordZ = password_buf[0 .. trimmed_len + 1];
    state.expand(salt[0..], passwordZ);

    const rounds: u64 = @as(u64, 1) << params.rounds_log;
    var k: u64 = 0;
    while (k < rounds) : (k += 1) {
        state.expand0(passwordZ);
        state.expand0(salt[0..]);
    }
    crypto.secureZero(u8, &password_buf);

    var cdata = [6]u32{ 0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274 }; // "OrpheanBeholderScryDoubt"
    k = 0;
    while (k < 64) : (k += 1) {
        state.encrypt(&cdata);
    }

    var ct: [ct_length]u8 = undefined;
    for (cdata, 0..) |c, i| {
        mem.writeInt(u32, ct[i * 4 ..][0..4], c, .big);
    }
    return ct[0..dk_length].*;
}

/// Compute a hash of a password using 2^rounds_log rounds of the bcrypt key stretching function.
/// bcrypt is a computationally expensive and cache-hard function, explicitly designed to slow down exhaustive searches.
///
/// The function returns the hash as a `dk_length` byte array, that doesn't include anything besides the hash output.
///
/// This function was designed for password storage, not for key derivation.
/// For key derivation, use `bcrypt.pbkdf()` or `bcrypt.opensshKdf()` instead.
pub fn bcrypt(
    password: []const u8,
    salt: [salt_length]u8,
    params: Params,
) [dk_length]u8 {
    if (password.len <= 72 or params.silently_truncate_password) {
        return bcryptWithTruncation(password, salt, params);
    }

    var pre_hash: [HmacSha512.mac_length]u8 = undefined;
    HmacSha512.create(&pre_hash, password, &salt);

    const Encoder = crypt_format.Codec.Encoder;
    var pre_hash_b64: [Encoder.calcSize(pre_hash.len)]u8 = undefined;
    _ = Encoder.encode(&pre_hash_b64, &pre_hash);

    return bcryptWithTruncation(&pre_hash_b64, salt, params);
}

const pbkdf_prf = struct {
    const Self = @This();
    pub const mac_length = 32;

    hasher: Sha512,
    sha2pass: [Sha512.digest_length]u8,

    pub fn create(out: *[mac_length]u8, msg: []const u8, key: []const u8) void {
        var ctx = Self.init(key);
        ctx.update(msg);
        ctx.final(out);
    }

    pub fn init(key: []const u8) Self {
        var self: Self = undefined;
        self.hasher = Sha512.init(.{});
        Sha512.hash(key, &self.sha2pass, .{});
        return self;
    }

    pub fn update(self: *Self, msg: []const u8) void {
        self.hasher.update(msg);
    }

    pub fn final(self: *Self, out: *[mac_length]u8) void {
        var sha2salt: [Sha512.digest_length]u8 = undefined;
        self.hasher.final(&sha2salt);
        out.* = hash(self.sha2pass, sha2salt);
    }

    /// Matches OpenBSD function
    /// https://github.com/openbsd/src/blob/6df1256b7792691e66c2ed9d86a8c103069f9e34/lib/libutil/bcrypt_pbkdf.c#L98
    pub fn hash(sha2pass: [Sha512.digest_length]u8, sha2salt: [Sha512.digest_length]u8) [32]u8 {
        var cdata: [8]u32 = undefined;
        {
            const ciphertext = "OxychromaticBlowfishSwatDynamite";
            var j: usize = 0;
            for (&cdata) |*v| {
                v.* = State.toWord(ciphertext, &j);
            }
        }

        var state = State{};

        { // key expansion
            state.expand(&sha2salt, &sha2pass);
            var i: usize = 0;
            while (i < 64) : (i += 1) {
                state.expand0(&sha2salt);
                state.expand0(&sha2pass);
            }
        }

        { // encryption
            var i: usize = 0;
            while (i < 64) : (i += 1) {
                state.encrypt(&cdata);
            }
        }

        // copy out
        var out: [32]u8 = undefined;
        for (cdata, 0..) |v, i| {
            std.mem.writeInt(u32, out[4 * i ..][0..4], v, .little);
        }

        // zap
        crypto.secureZero(u32, &cdata);
        crypto.secureZero(u32, &state.subkeys);

        return out;
    }
};

/// bcrypt-pbkdf is a key derivation function based on bcrypt.
///
/// Unlike the password hashing function `bcrypt`, this function doesn't silently truncate passwords longer than 72 bytes.
pub fn pbkdf(pass: []const u8, salt: []const u8, key: []u8, rounds: u32) !void {
    try crypto.pwhash.pbkdf2(key, pass, salt, rounds, pbkdf_prf);
}

/// The function used in OpenSSH to derive encryption keys from passphrases.
///
/// This implementation is compatible with the OpenBSD implementation (https://github.com/openbsd/src/blob/master/lib/libutil/bcrypt_pbkdf.c).
pub fn opensshKdf(pass: []const u8, salt: []const u8, key: []u8, rounds: u32) !void {
    var tmp: [32]u8 = undefined;
    var tmp2: [32]u8 = undefined;
    if (rounds < 1 or pass.len == 0 or salt.len == 0 or key.len == 0 or key.len > tmp.len * tmp.len) {
        return error.InvalidInput;
    }
    var sha2pass: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(pass, &sha2pass, .{});
    const stride = (key.len + tmp.len - 1) / tmp.len;
    var amt = (key.len + stride - 1) / stride;
    if (math.shr(usize, key.len, 32) >= amt) {
        return error.InvalidInput;
    }
    var key_remainder = key.len;
    var count: u32 = 1;
    while (key_remainder > 0) : (count += 1) {
        var count_salt: [4]u8 = undefined;
        std.mem.writeInt(u32, count_salt[0..], count, .big);
        var sha2salt: [Sha512.digest_length]u8 = undefined;
        var h = Sha512.init(.{});
        h.update(salt);
        h.update(&count_salt);
        h.final(&sha2salt);
        tmp2 = pbkdf_prf.hash(sha2pass, sha2salt);
        tmp = tmp2;
        for (1..rounds) |_| {
            Sha512.hash(&tmp2, &sha2salt, .{});
            tmp2 = pbkdf_prf.hash(sha2pass, sha2salt);
            for (&tmp, tmp2) |*o, t| o.* ^= t;
        }
        amt = @min(amt, key_remainder);
        key_remainder -= for (0..amt) |i| {
            const dest = i * stride + (count - 1);
            if (dest >= key.len) break i;
            key[dest] = tmp[i];
        } else amt;
    }
    crypto.secureZero(u8, &tmp);
    crypto.secureZero(u8, &tmp2);
    crypto.secureZero(u8, &sha2pass);
}

const crypt_format = struct {
    /// String prefix for bcrypt
    pub const prefix = "$2";

    // bcrypt has its own variant of base64, with its own alphabet and no padding
    const bcrypt_alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".*;
    const Codec = struct { Encoder: base64.Base64Encoder, Decoder: base64.Base64Decoder }{
        .Encoder = base64.Base64Encoder.init(bcrypt_alphabet, null),
        .Decoder = base64.Base64Decoder.init(bcrypt_alphabet, null),
    };

    fn strHashInternal(
        password: []const u8,
        salt: [salt_length]u8,
        params: Params,
    ) [hash_length]u8 {
        var dk = bcrypt(password, salt, params);

        var salt_str: [salt_str_length]u8 = undefined;
        _ = Codec.Encoder.encode(salt_str[0..], salt[0..]);

        var ct_str: [ct_str_length]u8 = undefined;
        _ = Codec.Encoder.encode(ct_str[0..], dk[0..]);

        var s_buf: [hash_length]u8 = undefined;
        const s = fmt.bufPrint(
            s_buf[0..],
            "{s}b${d}{d}${s}{s}",
            .{ prefix, params.rounds_log / 10, params.rounds_log % 10, salt_str, ct_str },
        ) catch unreachable;
        debug.assert(s.len == s_buf.len);
        return s_buf;
    }
};

/// Hash and verify passwords using the PHC format.
const PhcFormatHasher = struct {
    const alg_id = "bcrypt";
    const BinValue = phc_format.BinValue;

    const HashResult = struct {
        alg_id: []const u8,
        r: u6,
        salt: BinValue(salt_length),
        hash: BinValue(dk_length),
    };

    /// Return a non-deterministic hash of the password encoded as a PHC-format string
    fn create(
        password: []const u8,
        params: Params,
        buf: []u8,
    ) HasherError![]const u8 {
        var salt: [salt_length]u8 = undefined;
        crypto.random.bytes(&salt);

        const hash = bcrypt(password, salt, params);

        return phc_format.serialize(HashResult{
            .alg_id = alg_id,
            .r = params.rounds_log,
            .salt = try BinValue(salt_length).fromSlice(&salt),
            .hash = try BinValue(dk_length).fromSlice(&hash),
        }, buf);
    }

    /// Verify a password against a PHC-format encoded string
    fn verify(
        str: []const u8,
        password: []const u8,
        silently_truncate_password: bool,
    ) HasherError!void {
        const hash_result = try phc_format.deserialize(HashResult, str);

        if (!mem.eql(u8, hash_result.alg_id, alg_id)) return HasherError.PasswordVerificationFailed;
        if (hash_result.salt.len != salt_length or hash_result.hash.len != dk_length)
            return HasherError.InvalidEncoding;

        const params = Params{
            .rounds_log = hash_result.r,
            .silently_truncate_password = silently_truncate_password,
        };
        const hash = bcrypt(password, hash_result.salt.buf, params);
        const expected_hash = hash_result.hash.constSlice();

        if (!mem.eql(u8, &hash, expected_hash)) return HasherError.PasswordVerificationFailed;
    }
};

/// Hash and verify passwords using the modular crypt format.
const CryptFormatHasher = struct {
    /// Length of a string returned by the create() function
    const pwhash_str_length: usize = hash_length;

    /// Return a non-deterministic hash of the password encoded into the modular crypt format
    fn create(
        password: []const u8,
        params: Params,
        buf: []u8,
    ) HasherError![]const u8 {
        if (buf.len < pwhash_str_length) return HasherError.NoSpaceLeft;

        var salt: [salt_length]u8 = undefined;
        crypto.random.bytes(&salt);

        const hash = crypt_format.strHashInternal(password, salt, params);
        @memcpy(buf[0..hash.len], &hash);

        return buf[0..pwhash_str_length];
    }

    /// Verify a password against a string in modular crypt format
    fn verify(
        str: []const u8,
        password: []const u8,
        silently_truncate_password: bool,
    ) HasherError!void {
        if (str.len != pwhash_str_length or str[3] != '$' or str[6] != '$')
            return HasherError.InvalidEncoding;

        const rounds_log_str = str[4..][0..2];
        const rounds_log = fmt.parseInt(u6, rounds_log_str[0..], 10) catch
            return HasherError.InvalidEncoding;

        const salt_str = str[7..][0..salt_str_length];
        var salt: [salt_length]u8 = undefined;
        crypt_format.Codec.Decoder.decode(salt[0..], salt_str[0..]) catch return HasherError.InvalidEncoding;

        const wanted_s = crypt_format.strHashInternal(password, salt, .{
            .rounds_log = rounds_log,
            .silently_truncate_password = silently_truncate_password,
        });
        if (!mem.eql(u8, wanted_s[0..], str[0..])) return HasherError.PasswordVerificationFailed;
    }
};

/// Options for hashing a password.
pub const HashOptions = struct {
    /// For `bcrypt`, that can be left to `null`.
    allocator: ?mem.Allocator = null,
    /// Internal bcrypt parameters.
    params: Params,
    /// Encoding to use for the output of the hash function.
    encoding: pwhash.Encoding,
};

/// Compute a hash of a password using 2^rounds_log rounds of the bcrypt key stretching function.
/// bcrypt is a computationally expensive and cache-hard function, explicitly designed to slow down exhaustive searches.
///
/// The function returns a string that includes all the parameters required for verification.
///
/// IMPORTANT: by design, bcrypt silently truncates passwords to 72 bytes.
/// If this is an issue for your application, set the `silently_truncate_password` option to `false`.
pub fn strHash(
    password: []const u8,
    options: HashOptions,
    out: []u8,
) Error![]const u8 {
    switch (options.encoding) {
        .phc => return PhcFormatHasher.create(password, options.params, out),
        .crypt => return CryptFormatHasher.create(password, options.params, out),
    }
}

/// Options for hash verification.
pub const VerifyOptions = struct {
    /// For `bcrypt`, that can be left to `null`.
    allocator: ?mem.Allocator = null,
    /// Whether to silently truncate the password to 72 bytes, or pr```
