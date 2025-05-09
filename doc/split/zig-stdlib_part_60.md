```
 = v *% m;
        k1 ^= k1 >> 47;
        k1 *%= m;
        h1 ^= k1;
        h1 *%= m;
        h1 ^= h1 >> 47;
        h1 *%= m;
        h1 ^= h1 >> 47;
        return h1;
    }
};

pub const Murmur3_32 = struct {
    const Self = @This();

    fn rotl32(x: u32, comptime r: u32) u32 {
        return (x << r) | (x >> (32 - r));
    }

    pub fn hash(str: []const u8) u32 {
        return @call(.always_inline, Self.hashWithSeed, .{ str, default_seed });
    }

    pub fn hashWithSeed(str: []const u8, seed: u32) u32 {
        const c1: u32 = 0xcc9e2d51;
        const c2: u32 = 0x1b873593;
        const len: u32 = @truncate(str.len);
        var h1: u32 = seed;
        for (@as([*]align(1) const u32, @ptrCast(str.ptr))[0..(len >> 2)]) |v| {
            var k1: u32 = v;
            if (native_endian == .big)
                k1 = @byteSwap(k1);
            k1 *%= c1;
            k1 = rotl32(k1, 15);
            k1 *%= c2;
            h1 ^= k1;
            h1 = rotl32(h1, 13);
            h1 *%= 5;
            h1 +%= 0xe6546b64;
        }
        {
            var k1: u32 = 0;
            const offset = len & 0xfffffffc;
            const rest = len & 3;
            if (rest == 3) {
                k1 ^= @as(u32, @intCast(str[offset + 2])) << 16;
            }
            if (rest >= 2) {
                k1 ^= @as(u32, @intCast(str[offset + 1])) << 8;
            }
            if (rest >= 1) {
                k1 ^= @as(u32, @intCast(str[offset + 0]));
                k1 *%= c1;
                k1 = rotl32(k1, 15);
                k1 *%= c2;
                h1 ^= k1;
            }
        }
        h1 ^= len;
        h1 ^= h1 >> 16;
        h1 *%= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *%= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }

    pub fn hashUint32(v: u32) u32 {
        return @call(.always_inline, Self.hashUint32WithSeed, .{ v, default_seed });
    }

    pub fn hashUint32WithSeed(v: u32, seed: u32) u32 {
        const c1: u32 = 0xcc9e2d51;
        const c2: u32 = 0x1b873593;
        const len: u32 = 4;
        var h1: u32 = seed;
        var k1: u32 = undefined;
        k1 = v *% c1;
        k1 = rotl32(k1, 15);
        k1 *%= c2;
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 *%= 5;
        h1 +%= 0xe6546b64;
        h1 ^= len;
        h1 ^= h1 >> 16;
        h1 *%= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *%= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }

    pub fn hashUint64(v: u64) u32 {
        return @call(.always_inline, Self.hashUint64WithSeed, .{ v, default_seed });
    }

    pub fn hashUint64WithSeed(v: u64, seed: u32) u32 {
        const c1: u32 = 0xcc9e2d51;
        const c2: u32 = 0x1b873593;
        const len: u32 = 8;
        var h1: u32 = seed;
        var k1: u32 = undefined;
        k1 = @as(u32, @truncate(v)) *% c1;
        k1 = rotl32(k1, 15);
        k1 *%= c2;
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 *%= 5;
        h1 +%= 0xe6546b64;
        k1 = @as(u32, @truncate(v >> 32)) *% c1;
        k1 = rotl32(k1, 15);
        k1 *%= c2;
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 *%= 5;
        h1 +%= 0xe6546b64;
        h1 ^= len;
        h1 ^= h1 >> 16;
        h1 *%= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *%= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }
};

const verify = @import("verify.zig");

test "murmur2_32" {
    const v0: u32 = 0x12345678;
    const v1: u64 = 0x1234567812345678;
    const v0le: u32, const v1le: u64 = switch (native_endian) {
        .little => .{ v0, v1 },
        .big => .{ @byteSwap(v0), @byteSwap(v1) },
    };
    try testing.expectEqual(Murmur2_32.hash(@as([*]const u8, @ptrCast(&v0le))[0..4]), Murmur2_32.hashUint32(v0));
    try testing.expectEqual(Murmur2_32.hash(@as([*]const u8, @ptrCast(&v1le))[0..8]), Murmur2_32.hashUint64(v1));
}

test "murmur2_32 smhasher" {
    const Test = struct {
        fn do() !void {
            try testing.expectEqual(verify.smhasher(Murmur2_32.hashWithSeed), 0x27864C1E);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    try comptime Test.do();
}

test "murmur2_64" {
    const v0: u32 = 0x12345678;
    const v1: u64 = 0x1234567812345678;
    const v0le: u32, const v1le: u64 = switch (native_endian) {
        .little => .{ v0, v1 },
        .big => .{ @byteSwap(v0), @byteSwap(v1) },
    };
    try testing.expectEqual(Murmur2_64.hash(@as([*]const u8, @ptrCast(&v0le))[0..4]), Murmur2_64.hashUint32(v0));
    try testing.expectEqual(Murmur2_64.hash(@as([*]const u8, @ptrCast(&v1le))[0..8]), Murmur2_64.hashUint64(v1));
}

test "mumur2_64 smhasher" {
    const Test = struct {
        fn do() !void {
            try std.testing.expectEqual(verify.smhasher(Murmur2_64.hashWithSeed), 0x1F0D3804);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    try comptime Test.do();
}

test "murmur3_32" {
    const v0: u32 = 0x12345678;
    const v1: u64 = 0x1234567812345678;
    const v0le: u32, const v1le: u64 = switch (native_endian) {
        .little => .{ v0, v1 },
        .big => .{ @byteSwap(v0), @byteSwap(v1) },
    };
    try testing.expectEqual(Murmur3_32.hash(@as([*]const u8, @ptrCast(&v0le))[0..4]), Murmur3_32.hashUint32(v0));
    try testing.expectEqual(Murmur3_32.hash(@as([*]const u8, @ptrCast(&v1le))[0..8]), Murmur3_32.hashUint64(v1));
}

test "mumur3_32 smhasher" {
    const Test = struct {
        fn do() !void {
            try std.testing.expectEqual(verify.smhasher(Murmur3_32.hashWithSeed), 0xB0F57EE3);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    try comptime Test.do();
}
const std = @import("std");

const readInt = std.mem.readInt;
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const RAPID_SEED: u64 = 0xbdd89aa982704029;
const RAPID_SECRET: [3]u64 = .{ 0x2d358dccaa6c78a5, 0x8bb84b93962eacc9, 0x4b33a62ed433d4a3 };

pub fn hash(seed: u64, input: []const u8) u64 {
    const sc = RAPID_SECRET;
    const len = input.len;
    var a: u64 = 0;
    var b: u64 = 0;
    var k = input;
    var is: [3]u64 = .{ seed, 0, 0 };

    is[0] ^= mix(seed ^ sc[0], sc[1]) ^ len;

    if (len <= 16) {
        if (len >= 4) {
            const d: u64 = ((len & 24) >> @intCast(len >> 3));
            const e = len - 4;
            a = (r32(k) << 32) | r32(k[e..]);
            b = ((r32(k[d..]) << 32) | r32(k[(e - d)..]));
        } else if (len > 0)
            a = (@as(u64, k[0]) << 56) | (@as(u64, k[len >> 1]) << 32) | @as(u64, k[len - 1]);
    } else {
        var remain = len;
        if (len > 48) {
            is[1] = is[0];
            is[2] = is[0];
            while (remain >= 96) {
                inline for (0..6) |i| {
                    const m1 = r64(k[8 * i * 2 ..]);
                    const m2 = r64(k[8 * (i * 2 + 1) ..]);
                    is[i % 3] = mix(m1 ^ sc[i % 3], m2 ^ is[i % 3]);
                }
                k = k[96..];
                remain -= 96;
            }
            if (remain >= 48) {
                inline for (0..3) |i| {
                    const m1 = r64(k[8 * i * 2 ..]);
                    const m2 = r64(k[8 * (i * 2 + 1) ..]);
                    is[i] = mix(m1 ^ sc[i], m2 ^ is[i]);
                }
                k = k[48..];
                remain -= 48;
            }

            is[0] ^= is[1] ^ is[2];
        }

        if (remain > 16) {
            is[0] = mix(r64(k) ^ sc[2], r64(k[8..]) ^ is[0] ^ sc[1]);
            if (remain > 32) {
                is[0] = mix(r64(k[16..]) ^ sc[2], r64(k[24..]) ^ is[0]);
            }
        }

        a = r64(input[len - 16 ..]);
        b = r64(input[len - 8 ..]);
    }

    a ^= sc[1];
    b ^= is[0];
    mum(&a, &b);
    return mix(a ^ sc[0] ^ len, b ^ sc[1]);
}

test "RapidHash.hash" {
    const bytes: []const u8 = "abcdefgh" ** 128;

    const sizes: [13]u64 = .{ 0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024 };

    const outcomes: [13]u64 = .{
        0x5a6ef77074ebc84b,
        0xc11328477bc0f5d1,
        0x5644ac035e40d569,
        0x347080fbf5fcd81,
        0x56b66b8dc802bcc,
        0xb6bf9055973aac7c,
        0xed56d62eead1e402,
        0xc19072d767da8ffb,
        0x89bb40a9928a4f0d,
        0xe0af7c5e7b6e29fd,
        0x9a3ed35fbedfa11a,
        0x4c684b2119ca19fb,
        0x4b575f5bf25600d6,
    };

    var success: bool = true;
    for (sizes, outcomes) |s, e| {
        const r = hash(RAPID_SEED, bytes[0..s]);

        expectEqual(e, r) catch |err| {
            std.debug.print("Failed on {d}: {!}\n", .{ s, err });
            success = false;
        };
    }
    try expect(success);
}

inline fn mum(a: *u64, b: *u64) void {
    const r = @as(u128, a.*) * b.*;
    a.* = @truncate(r);
    b.* = @truncate(r >> 64);
}

inline fn mix(a: u64, b: u64) u64 {
    var copy_a = a;
    var copy_b = b;
    mum(&copy_a, &copy_b);
    return copy_a ^ copy_b;
}

inline fn r64(p: []const u8) u64 {
    return readInt(u64, p[0..8], .little);
}

inline fn r32(p: []const u8) u64 {
    return readInt(u32, p[0..4], .little);
}
const std = @import("std");

fn hashMaybeSeed(comptime hash_fn: anytype, seed: anytype, buf: []const u8) @typeInfo(@TypeOf(hash_fn)).@"fn".return_type.? {
    const HashFn = @typeInfo(@TypeOf(hash_fn)).@"fn";
    if (HashFn.params.len > 1) {
        if (@typeInfo(HashFn.params[0].type.?) == .int) {
            return hash_fn(@intCast(seed), buf);
        } else {
            return hash_fn(buf, @intCast(seed));
        }
    } else {
        return hash_fn(buf);
    }
}

fn initMaybeSeed(comptime Hash: anytype, seed: anytype) Hash {
    const HashFn = @typeInfo(@TypeOf(Hash.init)).@"fn";
    if (HashFn.params.len == 1) {
        return Hash.init(@intCast(seed));
    } else {
        return Hash.init();
    }
}

// Returns a verification code, the same as used by SMHasher.
//
// Hash keys of the form {0}, {0,1}, {0,1,2}... up to N=255, using 256-N as seed.
// First four-bytes of the hash, interpreted as little-endian is the verification code.
pub fn smhasher(comptime hash_fn: anytype) u32 {
    const HashFnTy = @typeInfo(@TypeOf(hash_fn)).@"fn";
    const HashResult = HashFnTy.return_type.?;
    const hash_size = @sizeOf(HashResult);

    var buf: [256]u8 = undefined;
    var buf_all: [256 * hash_size]u8 = undefined;

    for (0..256) |i| {
        buf[i] = @intCast(i);
        const h = hashMaybeSeed(hash_fn, 256 - i, buf[0..i]);
        std.mem.writeInt(HashResult, buf_all[i * hash_size ..][0..hash_size], h, .little);
    }

    return @truncate(hashMaybeSeed(hash_fn, 0, buf_all[0..]));
}

pub fn iterativeApi(comptime Hash: anytype) !void {
    // Sum(1..32) = 528
    var buf: [528]u8 = [_]u8{0} ** 528;
    var len: usize = 0;
    const seed = 0;

    var hasher = initMaybeSeed(Hash, seed);
    for (1..32) |i| {
        const r = hashMaybeSeed(Hash.hash, seed, buf[0 .. len + i]);
        hasher.update(buf[len..][0..i]);
        const f1 = hasher.final();
        const f2 = hasher.final();
        if (f1 != f2) return error.IterativeHashWasNotIdempotent;
        if (f1 != r) return error.IterativeHashDidNotMatchDirect;
        len += i;
    }
}
const std = @import("std");

pub const Wyhash = struct {
    const secret = [_]u64{
        0xa0761d6478bd642f,
        0xe7037ed1a0b428db,
        0x8ebc6af09c88c6e3,
        0x589965cc75374cc3,
    };

    a: u64,
    b: u64,
    state: [3]u64,
    total_len: usize,

    buf: [48]u8,
    buf_len: usize,

    pub fn init(seed: u64) Wyhash {
        var self = Wyhash{
            .a = undefined,
            .b = undefined,
            .state = undefined,
            .total_len = 0,
            .buf = undefined,
            .buf_len = 0,
        };

        self.state[0] = seed ^ mix(seed ^ secret[0], secret[1]);
        self.state[1] = self.state[0];
        self.state[2] = self.state[0];
        return self;
    }

    // This is subtly different from other hash function update calls. Wyhash requires the last
    // full 48-byte block to be run through final1 if is exactly aligned to 48-bytes.
    pub fn update(self: *Wyhash, input: []const u8) void {
        self.total_len += input.len;

        if (input.len <= 48 - self.buf_len) {
            @memcpy(self.buf[self.buf_len..][0..input.len], input);
            self.buf_len += input.len;
            return;
        }

        var i: usize = 0;

        if (self.buf_len > 0) {
            i = 48 - self.buf_len;
            @memcpy(self.buf[self.buf_len..][0..i], input[0..i]);
            self.round(&self.buf);
            self.buf_len = 0;
        }

        while (i + 48 < input.len) : (i += 48) {
            self.round(input[i..][0..48]);
        }

        const remaining_bytes = input[i..];
        if (remaining_bytes.len < 16 and i >= 48) {
            const rem = 16 - remaining_bytes.len;
            @memcpy(self.buf[self.buf.len - rem ..], input[i - rem .. i]);
        }
        @memcpy(self.buf[0..remaining_bytes.len], remaining_bytes);
        self.buf_len = remaining_bytes.len;
    }

    pub fn final(self: *Wyhash) u64 {
        var input: []const u8 = self.buf[0..self.buf_len];
        var newSelf = self.shallowCopy(); // ensure idempotency

        if (self.total_len <= 16) {
            newSelf.smallKey(input);
        } else {
            var offset: usize = 0;
            if (self.buf_len < 16) {
                var scratch: [16]u8 = undefined;
                const rem = 16 - self.buf_len;
                @memcpy(scratch[0..rem], self.buf[self.buf.len - rem ..][0..rem]);
                @memcpy(scratch[rem..][0..self.buf_len], self.buf[0..self.buf_len]);

                // Same as input but with additional bytes preceding start in case of a short buffer
                input = &scratch;
                offset = rem;
            }

            newSelf.final0();
            newSelf.final1(input, offset);
        }

        return newSelf.final2();
    }

    // Copies the core wyhash state but not any internal buffers.
    inline fn shallowCopy(self: *Wyhash) Wyhash {
        return .{
            .a = self.a,
            .b = self.b,
            .state = self.state,
            .total_len = self.total_len,
            .buf = undefined,
            .buf_len = undefined,
        };
    }

    inline fn smallKey(self: *Wyhash, input: []const u8) void {
        std.debug.assert(input.len <= 16);

        if (input.len >= 4) {
            const end = input.len - 4;
            const quarter = (input.len >> 3) << 2;
            self.a = (read(4, input[0..]) << 32) | read(4, input[quarter..]);
            self.b = (read(4, input[end..]) << 32) | read(4, input[end - quarter ..]);
        } else if (input.len > 0) {
            self.a = (@as(u64, input[0]) << 16) | (@as(u64, input[input.len >> 1]) << 8) | input[input.len - 1];
            self.b = 0;
        } else {
            self.a = 0;
            self.b = 0;
        }
    }

    inline fn round(self: *Wyhash, input: *const [48]u8) void {
        inline for (0..3) |i| {
            const a = read(8, input[8 * (2 * i) ..]);
            const b = read(8, input[8 * (2 * i + 1) ..]);
            self.state[i] = mix(a ^ secret[i + 1], b ^ self.state[i]);
        }
    }

    inline fn read(comptime bytes: usize, data: []const u8) u64 {
        std.debug.assert(bytes <= 8);
        const T = std.meta.Int(.unsigned, 8 * bytes);
        return @as(u64, std.mem.readInt(T, data[0..bytes], .little));
    }

    inline fn mum(a: *u64, b: *u64) void {
        const x = @as(u128, a.*) *% b.*;
        a.* = @as(u64, @truncate(x));
        b.* = @as(u64, @truncate(x >> 64));
    }

    inline fn mix(a_: u64, b_: u64) u64 {
        var a = a_;
        var b = b_;
        mum(&a, &b);
        return a ^ b;
    }

    inline fn final0(self: *Wyhash) void {
        self.state[0] ^= self.state[1] ^ self.state[2];
    }

    // input_lb must be at least 16-bytes long (in shorter key cases the smallKey function will be
    // used instead). We use an index into a slice to for comptime processing as opposed to if we
    // used pointers.
    inline fn final1(self: *Wyhash, input_lb: []const u8, start_pos: usize) void {
        std.debug.assert(input_lb.len >= 16);
        std.debug.assert(input_lb.len - start_pos <= 48);
        const input = input_lb[start_pos..];

        var i: usize = 0;
        while (i + 16 < input.len) : (i += 16) {
            self.state[0] = mix(read(8, input[i..]) ^ secret[1], read(8, input[i + 8 ..]) ^ self.state[0]);
        }

        self.a = read(8, input_lb[input_lb.len - 16 ..][0..8]);
        self.b = read(8, input_lb[input_lb.len - 8 ..][0..8]);
    }

    inline fn final2(self: *Wyhash) u64 {
        self.a ^= secret[1];
        self.b ^= self.state[0];
        mum(&self.a, &self.b);
        return mix(self.a ^ secret[0] ^ self.total_len, self.b ^ secret[1]);
    }

    pub fn hash(seed: u64, input: []const u8) u64 {
        var self = Wyhash.init(seed);

        if (input.len <= 16) {
            self.smallKey(input);
        } else {
            var i: usize = 0;
            if (input.len >= 48) {
                while (i + 48 < input.len) : (i += 48) {
                    self.round(input[i..][0..48]);
                }
                self.final0();
            }
            self.final1(input, i);
        }

        self.total_len = input.len;
        return self.final2();
    }
};

const verify = @import("verify.zig");
const expectEqual = std.testing.expectEqual;

const TestVector = struct {
    expected: u64,
    seed: u64,
    input: []const u8,
};

// Run https://github.com/wangyi-fudan/wyhash/blob/77e50f267fbc7b8e2d09f2d455219adb70ad4749/test_vector.cpp directly.
const vectors = [_]TestVector{
    .{ .seed = 0, .expected = 0x409638ee2bde459, .input = "" },
    .{ .seed = 1, .expected = 0xa8412d091b5fe0a9, .input = "a" },
    .{ .seed = 2, .expected = 0x32dd92e4b2915153, .input = "abc" },
    .{ .seed = 3, .expected = 0x8619124089a3a16b, .input = "message digest" },
    .{ .seed = 4, .expected = 0x7a43afb61d7f5f40, .input = "abcdefghijklmnopqrstuvwxyz" },
    .{ .seed = 5, .expected = 0xff42329b90e50d58, .input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
    .{ .seed = 6, .expected = 0xc39cab13b115aad3, .input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890" },
};

test "test vectors" {
    for (vectors) |e| {
        try expectEqual(e.expected, Wyhash.hash(e.seed, e.input));
    }
}

test "test vectors at comptime" {
    comptime {
        for (vectors) |e| {
            try expectEqual(e.expected, Wyhash.hash(e.seed, e.input));
        }
    }
}

test "smhasher" {
    const Test = struct {
        fn do() !void {
            try expectEqual(verify.smhasher(Wyhash.hash), 0xBD5E840C);
        }
    };
    try Test.do();
    @setEvalBranchQuota(50000);
    try comptime Test.do();
}

test "iterative api" {
    const Test = struct {
        fn do() !void {
            try verify.iterativeApi(Wyhash);
        }
    };
    try Test.do();
    @setEvalBranchQuota(50000);
    try comptime Test.do();
}

test "iterative maintains last sixteen" {
    const input = "Z" ** 48 ++ "01234567890abcdefg";
    const seed = 0;

    for (0..17) |i| {
        const payload = input[0 .. input.len - i];
        const non_iterative_hash = Wyhash.hash(seed, payload);

        var wh = Wyhash.init(seed);
        wh.update(payload);
        const iterative_hash = wh.final();

        try expectEqual(non_iterative_hash, iterative_hash);
    }
}
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const expectEqual = std.testing.expectEqual;
const native_endian = builtin.cpu.arch.endian();

const rotl = std.math.rotl;

pub const XxHash64 = struct {
    accumulator: Accumulator,
    seed: u64,
    buf: [32]u8,
    buf_len: usize,
    byte_count: usize,

    const prime_1 = 0x9E3779B185EBCA87; // 0b1001111000110111011110011011000110000101111010111100101010000111
    const prime_2 = 0xC2B2AE3D27D4EB4F; // 0b1100001010110010101011100011110100100111110101001110101101001111
    const prime_3 = 0x165667B19E3779F9; // 0b0001011001010110011001111011000110011110001101110111100111111001
    const prime_4 = 0x85EBCA77C2B2AE63; // 0b1000010111101011110010100111011111000010101100101010111001100011
    const prime_5 = 0x27D4EB2F165667C5; // 0b0010011111010100111010110010111100010110010101100110011111000101

    const Accumulator = struct {
        acc1: u64,
        acc2: u64,
        acc3: u64,
        acc4: u64,

        fn init(seed: u64) Accumulator {
            return .{
                .acc1 = seed +% prime_1 +% prime_2,
                .acc2 = seed +% prime_2,
                .acc3 = seed,
                .acc4 = seed -% prime_1,
            };
        }

        fn updateEmpty(self: *Accumulator, input: anytype, comptime unroll_count: usize) usize {
            var i: usize = 0;

            if (unroll_count > 0) {
                const unrolled_bytes = unroll_count * 32;
                while (i + unrolled_bytes <= input.len) : (i += unrolled_bytes) {
                    inline for (0..unroll_count) |j| {
                        self.processStripe(input[i + j * 32 ..][0..32]);
                    }
                }
            }

            while (i + 32 <= input.len) : (i += 32) {
                self.processStripe(input[i..][0..32]);
            }

            return i;
        }

        fn processStripe(self: *Accumulator, buf: *const [32]u8) void {
            self.acc1 = round(self.acc1, mem.readInt(u64, buf[0..8], .little));
            self.acc2 = round(self.acc2, mem.readInt(u64, buf[8..16], .little));
            self.acc3 = round(self.acc3, mem.readInt(u64, buf[16..24], .little));
            self.acc4 = round(self.acc4, mem.readInt(u64, buf[24..32], .little));
        }

        fn merge(self: Accumulator) u64 {
            var acc = rotl(u64, self.acc1, 1) +% rotl(u64, self.acc2, 7) +%
                rotl(u64, self.acc3, 12) +% rotl(u64, self.acc4, 18);
            acc = mergeAccumulator(acc, self.acc1);
            acc = mergeAccumulator(acc, self.acc2);
            acc = mergeAccumulator(acc, self.acc3);
            acc = mergeAccumulator(acc, self.acc4);
            return acc;
        }

        fn mergeAccumulator(acc: u64, other: u64) u64 {
            const a = acc ^ round(0, other);
            const b = a *% prime_1;
            return b +% prime_4;
        }
    };

    fn finalize(
        unfinished: u64,
        byte_count: usize,
        partial: anytype,
    ) u64 {
        std.debug.assert(partial.len < 32);
        var acc = unfinished +% @as(u64, byte_count) +% @as(u64, partial.len);

        switch (partial.len) {
            inline 0, 1, 2, 3 => |count| {
                inline for (0..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 4, 5, 6, 7 => |count| {
                acc = finalize4(acc, partial[0..4]);
                inline for (4..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 8, 9, 10, 11 => |count| {
                acc = finalize8(acc, partial[0..8]);
                inline for (8..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 12, 13, 14, 15 => |count| {
                acc = finalize8(acc, partial[0..8]);
                acc = finalize4(acc, partial[8..12]);
                inline for (12..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 16, 17, 18, 19 => |count| {
                acc = finalize8(acc, partial[0..8]);
                acc = finalize8(acc, partial[8..16]);
                inline for (16..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 20, 21, 22, 23 => |count| {
                acc = finalize8(acc, partial[0..8]);
                acc = finalize8(acc, partial[8..16]);
                acc = finalize4(acc, partial[16..20]);
                inline for (20..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 24, 25, 26, 27 => |count| {
                acc = finalize8(acc, partial[0..8]);
                acc = finalize8(acc, partial[8..16]);
                acc = finalize8(acc, partial[16..24]);
                inline for (24..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 28, 29, 30, 31 => |count| {
                acc = finalize8(acc, partial[0..8]);
                acc = finalize8(acc, partial[8..16]);
                acc = finalize8(acc, partial[16..24]);
                acc = finalize4(acc, partial[24..28]);
                inline for (28..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            else => unreachable,
        }
    }

    fn finalize8(v: u64, bytes: *const [8]u8) u64 {
        var acc = v;
        const lane = mem.readInt(u64, bytes, .little);
        acc ^= round(0, lane);
        acc = rotl(u64, acc, 27) *% prime_1;
        acc +%= prime_4;
        return acc;
    }

    fn finalize4(v: u64, bytes: *const [4]u8) u64 {
        var acc = v;
        const lane = @as(u64, mem.readInt(u32, bytes, .little));
        acc ^= lane *% prime_1;
        acc = rotl(u64, acc, 23) *% prime_2;
        acc +%= prime_3;
        return acc;
    }

    fn finalize1(v: u64, byte: u8) u64 {
        var acc = v;
        const lane = @as(u64, byte);
        acc ^= lane *% prime_5;
        acc = rotl(u64, acc, 11) *% prime_1;
        return acc;
    }

    fn avalanche(value: u64) u64 {
        var result = value ^ (value >> 33);
        result *%= prime_2;
        result ^= result >> 29;
        result *%= prime_3;
        result ^= result >> 32;

        return result;
    }

    pub fn init(seed: u64) XxHash64 {
        return XxHash64{
            .accumulator = Accumulator.init(seed),
            .seed = seed,
            .buf = undefined,
            .buf_len = 0,
            .byte_count = 0,
        };
    }

    pub fn update(self: *XxHash64, input: anytype) void {
        if (input.len < 32 - self.buf_len) {
            @memcpy(self.buf[self.buf_len..][0..input.len], input);
            self.buf_len += input.len;
            return;
        }

        var i: usize = 0;

        if (self.buf_len > 0) {
            i = 32 - self.buf_len;
            @memcpy(self.buf[self.buf_len..][0..i], input[0..i]);
            self.accumulator.processStripe(&self.buf);
            self.byte_count += self.buf_len;
        }

        i += self.accumulator.updateEmpty(input[i..], 32);
        self.byte_count += i;

        const remaining_bytes = input[i..];
        @memcpy(self.buf[0..remaining_bytes.len], remaining_bytes);
        self.buf_len = remaining_bytes.len;
    }

    fn round(acc: u64, lane: u64) u64 {
        const a = acc +% (lane *% prime_2);
        const b = rotl(u64, a, 31);
        return b *% prime_1;
    }

    pub fn final(self: *XxHash64) u64 {
        const unfinished = if (self.byte_count < 32)
            self.seed +% prime_5
        else
            self.accumulator.merge();

        return finalize(unfinished, self.byte_count, self.buf[0..self.buf_len]);
    }

    const Size = enum {
        small,
        large,
        unknown,
    };

    pub fn hash(seed: u64, input: anytype) u64 {
        if (input.len < 32) {
            return finalize(seed +% prime_5, 0, input);
        } else {
            var hasher = Accumulator.init(seed);
            const i = hasher.updateEmpty(input, 0);
            return finalize(hasher.merge(), i, input[i..]);
        }
    }
};

pub const XxHash32 = struct {
    accumulator: Accumulator,
    seed: u32,
    buf: [16]u8,
    buf_len: usize,
    byte_count: usize,

    const prime_1 = 0x9E3779B1; // 0b10011110001101110111100110110001
    const prime_2 = 0x85EBCA77; // 0b10000101111010111100101001110111
    const prime_3 = 0xC2B2AE3D; // 0b11000010101100101010111000111101
    const prime_4 = 0x27D4EB2F; // 0b00100111110101001110101100101111
    const prime_5 = 0x165667B1; // 0b00010110010101100110011110110001

    const Accumulator = struct {
        acc1: u32,
        acc2: u32,
        acc3: u32,
        acc4: u32,

        fn init(seed: u32) Accumulator {
            return .{
                .acc1 = seed +% prime_1 +% prime_2,
                .acc2 = seed +% prime_2,
                .acc3 = seed,
                .acc4 = seed -% prime_1,
            };
        }

        fn updateEmpty(self: *Accumulator, input: anytype, comptime unroll_count: usize) usize {
            var i: usize = 0;

            if (unroll_count > 0) {
                const unrolled_bytes = unroll_count * 16;
                while (i + unrolled_bytes <= input.len) : (i += unrolled_bytes) {
                    inline for (0..unroll_count) |j| {
                        self.processStripe(input[i + j * 16 ..][0..16]);
                    }
                }
            }

            while (i + 16 <= input.len) : (i += 16) {
                self.processStripe(input[i..][0..16]);
            }

            return i;
        }

        fn processStripe(self: *Accumulator, buf: *const [16]u8) void {
            self.acc1 = round(self.acc1, mem.readInt(u32, buf[0..4], .little));
            self.acc2 = round(self.acc2, mem.readInt(u32, buf[4..8], .little));
            self.acc3 = round(self.acc3, mem.readInt(u32, buf[8..12], .little));
            self.acc4 = round(self.acc4, mem.readInt(u32, buf[12..16], .little));
        }

        fn merge(self: Accumulator) u32 {
            return rotl(u32, self.acc1, 1) +% rotl(u32, self.acc2, 7) +%
                rotl(u32, self.acc3, 12) +% rotl(u32, self.acc4, 18);
        }
    };

    pub fn init(seed: u32) XxHash32 {
        return XxHash32{
            .accumulator = Accumulator.init(seed),
            .seed = seed,
            .buf = undefined,
            .buf_len = 0,
            .byte_count = 0,
        };
    }

    pub fn update(self: *XxHash32, input: []const u8) void {
        if (input.len < 16 - self.buf_len) {
            @memcpy(self.buf[self.buf_len..][0..input.len], input);
            self.buf_len += input.len;
            return;
        }

        var i: usize = 0;

        if (self.buf_len > 0) {
            i = 16 - self.buf_len;
            @memcpy(self.buf[self.buf_len..][0..i], input[0..i]);
            self.accumulator.processStripe(&self.buf);
            self.byte_count += self.buf_len;
            self.buf_len = 0;
        }

        i += self.accumulator.updateEmpty(input[i..], 16);
        self.byte_count += i;

        const remaining_bytes = input[i..];
        @memcpy(self.buf[0..remaining_bytes.len], remaining_bytes);
        self.buf_len = remaining_bytes.len;
    }

    fn round(acc: u32, lane: u32) u32 {
        const a = acc +% (lane *% prime_2);
        const b = rotl(u32, a, 13);
        return b *% prime_1;
    }

    pub fn final(self: *XxHash32) u32 {
        const unfinished = if (self.byte_count < 16)
            self.seed +% prime_5
        else
            self.accumulator.merge();

        return finalize(unfinished, self.byte_count, self.buf[0..self.buf_len]);
    }

    fn finalize(unfinished: u32, byte_count: usize, partial: anytype) u32 {
        std.debug.assert(partial.len < 16);
        var acc = unfinished +% @as(u32, @intCast(byte_count)) +% @as(u32, @intCast(partial.len));

        switch (partial.len) {
            inline 0, 1, 2, 3 => |count| {
                inline for (0..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 4, 5, 6, 7 => |count| {
                acc = finalize4(acc, partial[0..4]);
                inline for (4..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 8, 9, 10, 11 => |count| {
                acc = finalize4(acc, partial[0..4]);
                acc = finalize4(acc, partial[4..8]);
                inline for (8..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            inline 12, 13, 14, 15 => |count| {
                acc = finalize4(acc, partial[0..4]);
                acc = finalize4(acc, partial[4..8]);
                acc = finalize4(acc, partial[8..12]);
                inline for (12..count) |i| acc = finalize1(acc, partial[i]);
                return avalanche(acc);
            },
            else => unreachable,
        }

        return avalanche(acc);
    }

    fn finalize4(v: u32, bytes: *const [4]u8) u32 {
        var acc = v;
        const lane = mem.readInt(u32, bytes, .little);
        acc +%= lane *% prime_3;
        acc = rotl(u32, acc, 17) *% prime_4;
        return acc;
    }

    fn finalize1(v: u32, byte: u8) u32 {
        var acc = v;
        const lane = @as(u32, byte);
        acc +%= lane *% prime_5;
        acc = rotl(u32, acc, 11) *% prime_1;
        return acc;
    }

    fn avalanche(value: u32) u32 {
        var acc = value ^ value >> 15;
        acc *%= prime_2;
        acc ^= acc >> 13;
        acc *%= prime_3;
        acc ^= acc >> 16;

        return acc;
    }

    pub fn hash(seed: u32, input: anytype) u32 {
        if (input.len < 16) {
            return finalize(seed +% prime_5, 0, input);
        } else {
            var hasher = Accumulator.init(seed);
            const i = hasher.updateEmpty(input, 0);
            return finalize(hasher.merge(), i, input[i..]);
        }
    }
};

pub const XxHash3 = struct {
    const Block = @Vector(8, u64);
    const default_secret: [192]u8 = .{
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
        0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
        0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
        0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
        0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
        0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
        0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
        0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
        0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
        0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
        0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
        0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
    };

    const prime_mx1 = 0x165667919E3779F9;
    const prime_mx2 = 0x9FB21C651E98DF25;

    inline fn avalanche(mode: union(enum) { h3, h64, rrmxmx: u64 }, x0: u64) u64 {
        switch (mode) {
            .h3 => {
                const x1 = (x0 ^ (x0 >> 37)) *% prime_mx1;
                return x1 ^ (x1 >> 32);
            },
            .h64 => {
                const x1 = (x0 ^ (x0 >> 33)) *% XxHash64.prime_2;
                const x2 = (x1 ^ (x1 >> 29)) *% XxHash64.prime_3;
                return x2 ^ (x2 >> 32);
            },
            .rrmxmx => |len| {
                const x1 = (x0 ^ rotl(u64, x0, 49) ^ rotl(u64, x0, 24)) *% prime_mx2;
                const x2 = (x1 ^ ((x1 >> 35) +% len)) *% prime_mx2;
                return x2 ^ (x2 >> 28);
            },
        }
    }

    inline fn fold(a: u64, b: u64) u64 {
        const wide: [2]u64 = @bitCast(@as(u128, a) *% b);
        return wide[0] ^ wide[1];
    }

    inline fn swap(x: anytype) @TypeOf(x) {
        return if (native_endian == .big) @byteSwap(x) else x;
    }

    inline fn disableAutoVectorization(x: anytype) void {
        if (!@inComptime()) asm volatile (""
            :
            : [x] "r" (x),
        );
    }

    inline fn mix16(seed: u64, input: []const u8, secret: []const u8) u64 {
        const blk: [4]u64 = @bitCast([_][16]u8{ input[0..16].*, secret[0..16].* });
        disableAutoVectorization(seed);

        return fold(
            swap(blk[0]) ^ (swap(blk[2]) +% seed),
            swap(blk[1]) ^ (swap(blk[3]) -% seed),
        );
    }

    const Accumulator = extern struct {
        consumed: usize = 0,
        seed: u64,
        secret: [192]u8 = undefined,
        state: Block = Block{
            XxHash32.prime_3,
            XxHash64.prime_1,
            XxHash64.prime_2,
            XxHash64.prime_3,
            XxHash64.prime_4,
            XxHash32.prime_2,
            XxHash64.prime_5,
            XxHash32.prime_1,
        },

        inline fn init(seed: u64) Accumulator {
            var self = Accumulator{ .seed = seed };
            for (
                std.mem.bytesAsSlice(Block, &self.secret),
                std.mem.bytesAsSlice(Block, &default_secret),
            ) |*dst, src| {
                dst.* = swap(swap(src) +% Block{
                    seed, @as(u64, 0) -% seed,
                    seed, @as(u64, 0) -% seed,
                    seed, @as(u64, 0) -% seed,
                    seed, @as(u64, 0) -% seed,
                });
            }
            return self;
        }

        inline fn round(
            noalias state: *Block,
            noalias input_block: *align(1) const Block,
            noalias secret_block: *align(1) const Block,
        ) void {
            const data = swap(input_block.*);
            const mixed = data ^ swap(secret_block.*);
            state.* +%= (mixed & @as(Block, @splat(0xffffffff))) *% (mixed >> @splat(32));
            state.* +%= @shuffle(u64, data, undefined, [_]i32{ 1, 0, 3, 2, 5, 4, 7, 6 });
        }

        fn accumulate(noalias self: *Accumulator, blocks: []align(1) const Block) void {
            const secret = std.mem.bytesAsSlice(u64, self.secret[self.consumed * 8 ..]);
            for (blocks, secret[0..blocks.len]) |*input_block, *secret_block| {
                @prefetch(@as([*]const u8, @ptrCast(input_block)) + 320, .{});
                round(&self.state, input_block, @ptrCast(secret_block));
            }
        }

        fn scramble(self: *Accumulator) void {
            const secret_block: Block = @bitCast(self.secret[192 - @sizeOf(Block) .. 192].*);
            self.state ^= self.state >> @splat(47);
            self.state ^= swap(secret_block);
            self.state *%= @as(Block, @splat(XxHash32.prime_1));
        }

        fn consume(noalias self: *Accumulator, input_blocks: []align(1) const Block) void {
            const blocks_per_scramble = 1024 / @sizeOf(Block);
            std.debug.assert(self.consumed <= blocks_per_scramble);

            var blocks = input_blocks;
            var blocks_until_scramble = blocks_per_scramble - self.consumed;
            while (blocks.len >= blocks_until_scramble) {
                self.accumulate(blocks[0..blocks_until_scramble]);
                self.scramble();

                self.consumed = 0;
                blocks = blocks[blocks_until_scramble..];
                blocks_until_scramble = blocks_per_scramble;
            }

            self.accumulate(blocks);
            self.consumed += blocks.len;
        }

        fn digest(noalias self: *Accumulator, total_len: u64, noalias last_block: *align(1) const Block) u64 {
            const secret_block = self.secret[192 - @sizeOf(Block) - 7 ..][0..@sizeOf(Block)];
            round(&self.state, last_block, @ptrCast(secret_block));

            const merge_block: Block = @bitCast(self.secret[11 .. 11 + @sizeOf(Block)].*);
            self.state ^= swap(merge_block);

            var result = XxHash64.prime_1 *% total_len;
            inline for (0..4) |i| {
                result +%= fold(self.state[i * 2], self.state[i * 2 + 1]);
            }
            return avalanche(.h3, result);
        }
    };

    // Public API - Oneshot

    pub fn hash(seed: u64, input: anytype) u64 {
        const secret = &default_secret;
        if (input.len > 240) return hashLong(seed, input);
        if (input.len > 128) return hash240(seed, input, secret);
        if (input.len > 16) return hash128(seed, input, secret);
        if (input.len > 8) return hash16(seed, input, secret);
        if (input.len > 3) return hash8(seed, input, secret);
        if (input.len > 0) return hash3(seed, input, secret);

        const flip: [2]u64 = @bitCast(secret[56..72].*);
        const key = swap(flip[0]) ^ swap(flip[1]);
        return avalanche(.h64, seed ^ key);
    }

    fn hash3(seed: u64, input: anytype, noalias secret: *const [192]u8) u64 {
        @branchHint(.unlikely);
        std.debug.assert(input.len > 0 and input.len < 4);

        const flip: [2]u32 = @bitCast(secret[0..8].*);
        const blk: u32 = @bitCast([_]u8{
            input[input.len - 1],
            @truncate(input.len),
            input[0],
            input[input.len / 2],
        });

        const key = @as(u64, swap(flip[0]) ^ swap(flip[1])) +% seed;
        return avalanche(.h64, key ^ swap(blk));
    }

    fn hash8(seed: u64, input: anytype, noalias secret: *const [192]u8) u64 {
        @branchHint(.cold);
        std.debug.assert(input.len >= 4 and input.len <= 8);

        const flip: [2]u64 = @bitCast(secret[8..24].*);
        const blk: [2]u32 = @bitCast([_][4]u8{
            input[0..4].*,
            input[input.len - 4 ..][0..4].*,
        });

        const mixed = seed ^ (@as(u64, @byteSwap(@as(u32, @truncate(seed)))) << 32);
        const key = (swap(flip[0]) ^ swap(flip[1])) -% mixed;
        const combined = (@as(u64, swap(blk[0])) << 32) +% swap(blk[1]);
        return avalanche(.{ .rrmxmx = input.len }, key ^ combined);
    }

    fn hash16(seed: u64, input: anytype, noalias secret: *const [192]u8) u64 {
        @branchHint(.unlikely);
        std.debug.assert(input.len > 8 and input.len <= 16);

        const flip: [4]u64 = @bitCast(secret[24..56].*);
        const blk: [2]u64 = @bitCast([_][8]u8{
            input[0..8].*,
            input[input.len - 8 ..][0..8].*,
        });

        const lo = swap(blk[0]) ^ ((swap(flip[0]) ^ swap(flip[1])) +% seed);
        const hi = swap(blk[1]) ^ ((swap(flip[2]) ^ swap(flip[3])) -% seed);
        const combined = @as(u64, input.len) +% @byteSwap(lo) +% hi +% fold(lo, hi);
        return avalanche(.h3, combined);
    }

    fn hash128(seed: u64, input: anytype, noalias secret: *const [192]u8) u64 {
        @branchHint(.unlikely);
        std.debug.assert(input.len > 16 and input.len <= 128);

        var acc = XxHash64.prime_1 *% @as(u64, input.len);
        inline for (0..4) |i| {
            const in_offset = 48 - (i * 16);
            const scrt_offset = 96 - (i * 32);
            if (input.len > scrt_offset) {
                acc +%= mix16(seed, input[in_offset..], secret[scrt_offset..]);
                acc +%= mix16(seed, input[input.len - (in_offset + 16) ..], secret[scrt_offset + 16 ..]);
            }
        }
        return avalanche(.h3, acc);
    }

    fn hash240(seed: u64, input: anytype, noalias secret: *const [192]u8) u64 {
        @branchHint(.unlikely);
        std.debug.assert(input.len > 128 and input.len <= 240);

        var acc = XxHash64.prime_1 *% @as(u64, input.len);
        inline for (0..8) |i| {
            acc +%= mix16(seed, input[i * 16 ..], secret[i * 16 ..]);
        }

        var acc_end = mix16(seed, input[input.len - 16 ..], secret[136 - 17 ..]);
        for (8..(input.len / 16)) |i| {
            acc_end +%= mix16(seed, input[i * 16 ..], secret[((i - 8) * 16) + 3 ..]);
            disableAutoVectorization(i);
        }

        acc = avalanche(.h3, acc) +% acc_end;
        return avalanche(.h3, acc);
    }

    noinline fn hashLong(seed: u64, input: []const u8) u64 {
        @branchHint(.unlikely);
        std.debug.assert(input.len >= 240);

        const block_count = ((input.len - 1) / @sizeOf(Block)) * @sizeOf(Block);
        const last_block = input[input.len - @sizeOf(Block) ..][0..@sizeOf(Block)];

        var acc = Accumulator.init(seed);
        acc.consume(std.mem.bytesAsSlice(Block, input[0..block_count]));
        return acc.digest(input.len, @ptrCast(last_block));
    }

    // Public API - Streaming

    buffered: usize = 0,
    buffer: [256]u8 = undefined,
    total_len: usize = 0,
    accumulator: Accumulator,

    pub fn init(seed: u64) XxHash3 {
        return .{ .accumulator = Accumulator.init(seed) };
    }

    pub fn update(self: *XxHash3, input: anytype) void {
        self.total_len += input.len;
        std.debug.assert(self.buffered <= self.buffer.len);

        // Copy the input into the buffer if we haven't filled it up yet.
        const remaining = self.buffer.len - self.buffered;
        if (input.len <= remaining) {
            @memcpy(self.buffer[self.buffered..][0..input.len], input);
            self.buffered += input.len;
            return;
        }

        // Input will overflow the buffer. Fill up the buffer with some input and consume it.
        var consumable: []const u8 = input;
        if (self.buffered > 0) {
            @memcpy(self.buffer[self.buffered..], consumable[0..remaining]);
            consumable = consumable[remaining..];

            self.accumulator.consume(std.mem.bytesAsSlice(Block, &self.buffer));
            self.buffered = 0;
        }

        // The input isn't small enough to fit in the buffer. Consume it directly.
        if (consumable.len > self.buffer.len) {
            const block_count = ((consumable.len - 1) / @sizeOf(Block)) * @sizeOf(Block);
            self.accumulator.consume(std.mem.bytesAsSlice(Block, consumable[0..block_count]));
            consumable = consumable[block_count..];

            // In case we consume all remaining input, write the last block to end of the buffer
            // to populate the last_block_copy in final() similar to hashLong()'s last_block.
            @memcpy(
                self.buffer[self.buffer.len - @sizeOf(Block) .. self.buffer.len],
                (consumable.ptr - @sizeOf(Block))[0..@sizeOf(Block)],
            );
        }

        // Copy in any remaining input into the buffer.
        std.debug.assert(consumable.len <= self.buffer.len);
        @memcpy(self.buffer[0..consumable.len], consumable);
        self.buffered = consumable.len;
    }

    pub fn final(self: *XxHash3) u64 {
        std.debug.assert(self.buffered <= self.total_len);
        std.debug.assert(self.buffered <= self.buffer.len);

        // Use Oneshot hashing for smaller sizes as it doesn't use Accumulator like hashLong.
        if (self.total_len <= 240) {
            return hash(self.accumulator.seed, self.buffer[0..self.total_len]);
        }

        // Make a copy of the Accumulator state in case `self` needs to update() / be used later.
        var accumulator_copy = self.accumulator;
        var last_block_copy: [@sizeOf(Block)]u8 = undefined;

        // Digest the last block onthe Accumulator copy.
        return accumulator_copy.digest(self.total_len, last_block: {
            if (self.buffered >= @sizeOf(Block)) {
                const block_count = ((self.buffered - 1) / @sizeOf(Block)) * @sizeOf(Block);
                accumulator_copy.consume(std.mem.bytesAsSlice(Block, self.buffer[0..block_count]));
                break :last_block @ptrCast(self.buffer[self.buffered - @sizeOf(Block) ..][0..@sizeOf(Block)]);
            } else {
                const remaining = @sizeOf(Block) - self.buffered;
                @memcpy(last_block_copy[0..remaining], self.buffer[self.buffer.len - remaining ..][0..remaining]);
                @memcpy(last_block_copy[remaining..][0..self.buffered], self.buffer[0..self.buffered]);
                break :last_block @ptrCast(&last_block_copy);
            }
        });
    }
};

const verify = @import("verify.zig");

fn testExpect(comptime H: type, seed: anytype, input: []const u8, expected: u64) !void {
    try expectEqual(expected, H.hash(seed, input));

    var hasher = H.init(seed);
    hasher.update(input);
    try expectEqual(expected, hasher.final());
}

test "xxhash3" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    const H = XxHash3;
    // Non-Seeded Tests
    try testExpect(H, 0, "", 0x2d06800538d394c2);
    try testExpect(H, 0, "a", 0xe6c632b61e964e1f);
    try testExpect(H, 0, "abc", 0x78af5f94892f3950);
    try testExpect(H, 0, "message", 0x0b1ca9b8977554fa);
    try testExpect(H, 0, "message digest", 0x160d8e9329be94f9);
    try testExpect(H, 0, "abcdefghijklmnopqrstuvwxyz", 0x810f9ca067fbb90c);
    try testExpect(H, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0x643542bb51639cb2);
    try testExpect(H, 0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0x7f58aa2520c681f9);
    try testExpect(H, 0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678", 0xb66ea795b5edc38c);
    try testExpect(H, 0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 0x8845e0b1b57330de);
    try testExpect(H, 0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123123", 0xf031f373d63c5653);
    try testExpect(H, 0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xf1bf601f9d868dce);

    // Seeded Tests
    try testExpect(H, 1, "", 0x4dc5b0cc826f6703);
    try testExpect(H, 1, "a", 0xd2f6d0996f37a720);
    try testExpect(H, 1, "abc", 0x6b4467b443c76228);
    try testExpect(H, 1, "message", 0x73fb1cf20d561766);
    try testExpect(H, 1, "message digest", 0xfe71a82a70381174);
    try testExpect(H, 1, "abcdefghijklmnopqrstuvwxyz", 0x902a2c2d016a37ba);
    try testExpect(H, 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0xbf552e540c5c6882);
    try testExpect(H, 1, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xf2ca33235a6b865b);
    try testExpect(H, 1, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678", 0x6ef5cf958ba52c4);
    try testExpect(H, 1, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xfbc5f9c53d21cb2f);
    try testExpect(H, 1, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123123", 0x48682aca3b1c5c18);
    try testExpect(H, 1, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 0x3903c5437fc4e726);
}

test "xxhash3 smhasher" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    const Test = struct {
        fn do() !void {
            try expectEqual(verify.smhasher(XxHash3.hash), 0x9a636405);
        }
    };
    try Test.do();
    @setEvalBranchQuota(75000);
    comptime try Test.do();
}

test "xxhash3 iterative api" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    const Test = struct {
        fn do() !void {
            try verify.iterativeApi(XxHash3);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    comptime try Test.do();
}

test "xxhash64" {
    const H = XxHash64;
    try testExpect(H, 0, "", 0xef46db3751d8e999);
    try testExpect(H, 0, "a", 0xd24ec4f1a98c6e5b);
    try testExpect(H, 0, "abc", 0x44bc2cf5ad770999);
    try testExpect(H, 0, "message digest", 0x066ed728fceeb3be);
    try testExpect(H, 0, "abcdefghijklmnopqrstuvwxyz", 0xcfe1f278fa89835c);
    try testExpect(H, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0xaaa46907d3047814);
    try testExpect(H, 0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xe04a477f19ee145d);
}

test "xxhash64 smhasher" {
    const Test = struct {
        fn do() !void {
            try expectEqual(verify.smhasher(XxHash64.hash), 0x024B7CF4);
        }
    };
    try Test.do();
    @setEvalBranchQuota(75000);
    comptime try Test.do();
}

test "xxhash64 iterative api" {
    const Test = struct {
        fn do() !void {
            try verify.iterativeApi(XxHash64);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    comptime try Test.do();
}

test "xxhash32" {
    const H = XxHash32;

    try testExpect(H, 0, "", 0x02cc5d05);
    try testExpect(H, 0, "a", 0x550d7456);
    try testExpect(H, 0, "abc", 0x32d153ff);
    try testExpect(H, 0, "message digest", 0x7c948494);
    try testExpect(H, 0, "abcdefghijklmnopqrstuvwxyz", 0x63a14d5f);
    try testExpect(H, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0x9c285e64);
    try testExpect(H, 0, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0x9c05f475);
}

test "xxhash32 smhasher" {
    const Test = struct {
        fn do() !void {
            try expectEqual(verify.smhasher(XxHash32.hash), 0xBA88B743);
        }
    };
    try Test.do();
    @setEvalBranchQuota(85000);
    comptime try Test.do();
}

test "xxhash32 iterative api" {
    const Test = struct {
        fn do() !void {
            try verify.iterativeApi(XxHash32);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    comptime try Test.do();
}
const std = @import("std.zig");
const builtin = @import("builtin");
const root = @import("root");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const c = std.c;
const Allocator = std.mem.Allocator;
const windows = std.os.windows;
const Alignment = std.mem.Alignment;

pub const ArenaAllocator = @import("heap/arena_allocator.zig").ArenaAllocator;
pub const SmpAllocator = @import("heap/SmpAllocator.zig");
pub const FixedBufferAllocator = @import("heap/FixedBufferAllocator.zig");
pub const PageAllocator = @import("heap/PageAllocator.zig");
pub const SbrkAllocator = @import("heap/sbrk_allocator.zig").SbrkAllocator;
pub const ThreadSafeAllocator = @import("heap/ThreadSafeAllocator.zig");
pub const WasmAllocator = @import("heap/WasmAllocator.zig");

pub const DebugAllocatorConfig = @import("heap/debug_allocator.zig").Config;
pub const DebugAllocator = @import("heap/debug_allocator.zig").DebugAllocator;
pub const Check = enum { ok, leak };
/// Deprecated; to be removed after 0.14.0 is tagged.
pub const GeneralPurposeAllocatorConfig = DebugAllocatorConfig;
/// Deprecated; to be removed after 0.14.0 is tagged.
pub const GeneralPurposeAllocator = DebugAllocator;

const memory_pool = @import("heap/memory_pool.zig");
pub const MemoryPool = memory_pool.MemoryPool;
pub const MemoryPoolAligned = memory_pool.MemoryPoolAligned;
pub const MemoryPoolExtra = memory_pool.MemoryPoolExtra;
pub const MemoryPoolOptions = memory_pool.Options;

/// TODO Utilize this on Windows.
pub var next_mmap_addr_hint: ?[*]align(page_size_min) u8 = null;

/// comptime-known minimum page size of the target.
///
/// All pointers from `mmap` or `VirtualAlloc` are aligned to at least
/// `page_size_min`, but their actual alignment may be bigger.
///
/// This value can be overridden via `std.options.page_size_min`.
///
/// On many systems, the actual page size can only be determined at runtime
/// with `pageSize`.
pub const page_size_min: usize = std.options.page_size_min orelse (page_size_min_default orelse
    @compileError(@tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag) ++ " has unknown page_size_min; populate std.options.page_size_min"));

/// comptime-known maximum page size of the target.
///
/// Targeting a system with a larger page size may require overriding
/// `std.options.page_size_max`, as well as providing a corresponding linker
/// option.
///
/// The actual page size can only be determined at runtime with `pageSize`.
pub const page_size_max: usize = std.options.page_size_max orelse (page_size_max_default orelse if (builtin.os.tag == .freestanding or builtin.os.tag == .other)
    @compileError("freestanding/other page_size_max must provided with std.options.page_size_max")
else
    @compileError(@tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag) ++ " has unknown page_size_max; populate std.options.page_size_max"));

/// If the page size is comptime-known, return value is comptime.
/// Otherwise, calls `std.options.queryPageSize` which by default queries the
/// host operating system at runtime.
pub inline fn pageSize() usize {
    if (page_size_min == page_size_max) return page_size_min;
    return std.options.queryPageSize();
}

test pageSize {
    assert(std.math.isPowerOfTwo(pageSize()));
}

/// The default implementation of `std.options.queryPageSize`.
/// Asserts that the page size is within `page_size_min` and `page_size_max`
pub fn defaultQueryPageSize() usize {
    const global = struct {
        var cached_result: std.atomic.Value(usize) = .init(0);
    };
    var size = global.cached_result.load(.unordered);
    if (size > 0) return size;
    size = switch (builtin.os.tag) {
        .linux => if (builtin.link_libc) @intCast(std.c.sysconf(@intFromEnum(std.c._SC.PAGESIZE))) else std.os.linux.getauxval(std.elf.AT_PAGESZ),
        .driverkit, .ios, .macos, .tvos, .visionos, .watchos => blk: {
            const task_port = std.c.mach_task_self();
            // mach_task_self may fail "if there are any resource failures or other errors".
            if (task_port == std.c.TASK_NULL)
                break :blk 0;
            var info_count = std.c.TASK_VM_INFO_COUNT;
            var vm_info: std.c.task_vm_info_data_t = undefined;
            vm_info.page_size = 0;
            _ = std.c.task_info(
                task_port,
                std.c.TASK_VM_INFO,
                @as(std.c.task_info_t, @ptrCast(&vm_info)),
                &info_count,
            );
            assert(vm_info.page_size != 0);
            break :blk @intCast(vm_info.page_size);
        },
        .windows => blk: {
            var info: std.os.windows.SYSTEM_INFO = undefined;
            std.os.windows.kernel32.GetSystemInfo(&info);
            break :blk info.dwPageSize;
        },
        else => if (builtin.link_libc)
            @intCast(std.c.sysconf(@intFromEnum(std.c._SC.PAGESIZE)))
        else if (builtin.os.tag == .freestanding or builtin.os.tag == .other)
            @compileError("unsupported target: freestanding/other")
        else
            @compileError("pageSize on " ++ @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag) ++ " is not supported without linking libc, using the default implementation"),
    };

    assert(size >= page_size_min);
    assert(size <= page_size_max);
    global.cached_result.store(size, .unordered);

    return size;
}

test defaultQueryPageSize {
    if (builtin.cpu.arch.isWasm()) return error.SkipZigTest;
    assert(std.math.isPowerOfTwo(defaultQueryPageSize()));
}

const CAllocator = struct {
    comptime {
        if (!builtin.link_libc) {
            @compileError("C allocator is only available when linking against libc");
        }
    }

    const vtable: Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub const supports_malloc_size = @TypeOf(malloc_size) != void;
    pub const malloc_size = if (@TypeOf(c.malloc_size) != void)
        c.malloc_size
    else if (@TypeOf(c.malloc_usable_size) != void)
        c.malloc_usable_size
    else if (@TypeOf(c._msize) != void)
        c._msize
    else {};

    pub const supports_posix_memalign = switch (builtin.os.tag) {
        .dragonfly, .netbsd, .freebsd, .solaris, .openbsd, .linux, .macos, .ios, .tvos, .watchos, .visionos => true,
        else => false,
    };

    fn getHeader(ptr: [*]u8) *[*]u8 {
        return @alignCast(@ptrCast(ptr - @sizeOf(usize)));
    }

    fn alignedAlloc(len: usize, alignment: Alignment) ?[*]u8 {
        const alignment_bytes = alignment.toByteUnits();
        if (supports_posix_memalign) {
            // The posix_memalign only accepts alignment values that are a
            // multiple of the pointer size
            const effective_alignment = @max(alignment_bytes, @sizeOf(usize));

            var aligned_ptr: ?*anyopaque = undefined;
            if (c.posix_memalign(&aligned_ptr, effective_alignment, len) != 0)
                return null;

            return @ptrCast(aligned_ptr);
        }

        // Thin wrapper around regular malloc, overallocate to account for
        // alignment padding and store the original malloc()'ed pointer before
        // the aligned address.
        const unaligned_ptr = @as([*]u8, @ptrCast(c.malloc(len + alignment_bytes - 1 + @sizeOf(usize)) orelse return null));
        const unaligned_addr = @intFromPtr(unaligned_ptr);
        const aligned_addr = mem.alignForward(usize, unaligned_addr + @sizeOf(usize), alignment_bytes);
        const aligned_ptr = unaligned_ptr + (aligned_addr - unaligned_addr);
        getHeader(aligned_ptr).* = unaligned_ptr;

        return aligned_ptr;
    }

    fn alignedFree(ptr: [*]u8) void {
        if (supports_posix_memalign) {
            return c.free(ptr);
        }

        const unaligned_ptr = getHeader(ptr).*;
        c.free(unaligned_ptr);
    }

    fn alignedAllocSize(ptr: [*]u8) usize {
        if (supports_posix_memalign) {
            return CAllocator.malloc_size(ptr);
        }

        const unaligned_ptr = getHeader(ptr).*;
        const delta = @intFromPtr(ptr) - @intFromPtr(unaligned_ptr);
        return CAllocator.malloc_size(unaligned_ptr) - delta;
    }

    fn alloc(
        _: *anyopaque,
        len: usize,
        alignment: Alignment,
        return_address: usize,
    ) ?[*]u8 {
        _ = return_address;
        assert(len > 0);
        return alignedAlloc(len, alignment);
    }

    fn resize(
        _: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        _ = alignment;
        _ = return_address;
        if (new_len <= buf.len) {
            return true;
        }
        if (CAllocator.supports_malloc_size) {
            const full_len = alignedAllocSize(buf.ptr);
            if (new_len <= full_len) {
                return true;
            }
        }
        return false;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        // realloc would potentially return a new allocation that does not
        // respect the original alignment.
        return if (resize(context, memory, alignment, new_len, return_address)) memory.ptr else null;
    }

    fn free(
        _: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        return_address: usize,
    ) void {
        _ = alignment;
        _ = return_address;
        alignedFree(buf.ptr);
    }
};

/// Supports the full Allocator interface, including alignment, and exploiting
/// `malloc_usable_size` if available. For an allocator that directly calls
/// `malloc`/`free`, see `raw_c_allocator`.
pub const c_allocator: Allocator = .{
    .ptr = undefined,
    .vtable = &CAllocator.vtable,
};

/// Asserts allocations are within `@alignOf(std.c.max_align_t)` and directly
/// calls `malloc`/`free`. Does not attempt to utilize `malloc_usable_size`.
/// This allocator is safe to use as the backing allocator with
/// `ArenaAllocator` for example and is more optimal in such a case than
/// `c_allocator`.
pub const raw_c_allocator: Allocator = .{
    .ptr = undefined,
    .vtable = &raw_c_allocator_vtable,
};
const raw_c_allocator_vtable: Allocator.VTable = .{
    .alloc = rawCAlloc,
    .resize = rawCResize,
    .remap = rawCRemap,
    .free = rawCFree,
};

fn rawCAlloc(
    context: *anyopaque,
    len: usize,
    alignment: Alignment,
    return_address: usize,
) ?[*]u8 {
    _ = context;
    _ = return_address;
    assert(alignment.compare(.lte, comptime .fromByteUnits(@alignOf(std.c.max_align_t))));
    // Note that this pointer cannot be aligncasted to max_align_t because if
    // len is < max_align_t then the alignment can be smaller. For example, if
    // max_align_t is 16, but the user requests 8 bytes, there is no built-in
    // type in C that is size 8 and has 16 byte alignment, so the alignment may
    // be 8 bytes rather than 16. Similarly if only 1 byte is requested, malloc
    // is allowed to return a 1-byte aligned pointer.
    return @ptrCast(c.malloc(len));
}

fn rawCResize(
    context: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    return_address: usize,
) bool {
    _ = context;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = return_address;
    return false;
}

fn rawCRemap(
    context: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    _ = context;
    _ = alignment;
    _ = return_address;
    return @ptrCast(c.realloc(memory.ptr, new_len));
}

fn rawCFree(
    context: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    return_address: usize,
) void {
    _ = context;
    _ = alignment;
    _ = return_address;
    c.free(memory.ptr);
}

/// On operating systems that support memory mapping, this allocator makes a
/// syscall directly for every allocation and free.
///
/// Otherwise, it falls back to the preferred singleton for the target.
///
/// Thread-safe.
pub const page_allocator: Allocator = if (@hasDecl(root, "os") and
    @hasDecl(root.os, "heap") and
    @hasDecl(root.os.heap, "page_allocator"))
    root.os.heap.page_allocator
else if (builtin.target.cpu.arch.isWasm()) .{
    .ptr = undefined,
    .vtable = &WasmAllocator.vtable,
} else if (builtin.target.os.tag == .plan9) .{
    .ptr = undefined,
    .vtable = &SbrkAllocator(std.os.plan9.sbrk).vtable,
} else .{
    .ptr = undefined,
    .vtable = &PageAllocator.vtable,
};

pub const smp_allocator: Allocator = .{
    .ptr = undefined,
    .vtable = &SmpAllocator.vtable,
};

/// This allocator is fast, small, and specific to WebAssembly. In the future,
/// this will be the implementation automatically selected by
/// `GeneralPurposeAllocator` when compiling in `ReleaseSmall` mode for wasm32
/// and wasm64 architectures.
/// Until then, it is available here to play with.
pub const wasm_allocator: Allocator = .{
    .ptr = undefined,
    .vtable = &WasmAllocator.vtable,
};

/// Returns a `StackFallbackAllocator` allocating using either a
/// `FixedBufferAllocator` on an array of size `size` and falling back to
/// `fallback_allocator` if that fails.
pub fn stackFallback(comptime size: usize, fallback_allocator: Allocator) StackFallbackAllocator(size) {
    return StackFallbackAllocator(size){
        .buffer = undefined,
        .fallback_allocator = fallback_allocator,
        .fixed_buffer_allocator = undefined,
    };
}

/// An allocator that attempts to allocate using a
/// `FixedBufferAllocator` using an array of size `size`. If the
/// allocation fails, it will fall back to using
/// `fallback_allocator`. Easily created with `stackFallback`.
pub fn StackFallbackAllocator(comptime size: usize) type {
    return struct {
        const Self = @This();

        buffer: [size]u8,
        fallback_allocator: Allocator,
        fixed_buffer_allocator: FixedBufferAllocator,
        get_called: if (std.debug.runtime_safety) bool else void =
            if (std.debug.runtime_safety) false else {},

        /// This function both fetches a `Allocator` interface to this
        /// allocator *and* resets the internal buffer allocator.
        pub fn get(self: *Self) Allocator {
            if (std.debug.runtime_safety) {
                assert(!self.get_called); // `get` called multiple times; instead use `const allocator = stackFallback(N).get();`
                self.get_called = true;
            }
            self.fixed_buffer_allocator = FixedBufferAllocator.init(self.buffer[0..]);
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        /// Unlike most std allocators `StackFallbackAllocator` modifies
        /// its internal state before returning an implementation of
        /// the`Allocator` interface and therefore also doesn't use
        /// the usual `.allocator()` method.
        pub const allocator = @compileError("use 'const allocator = stackFallback(N).get();' instead");

        fn alloc(
            ctx: *anyopaque,
            len: usize,
            alignment: Alignment,
            ra: usize,
        ) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return FixedBufferAllocator.alloc(&self.fixed_buffer_allocator, len, alignment, ra) orelse
                return self.fallback_allocator.rawAlloc(len, alignment, ra);
        }

        fn resize(
            ctx: *anyopaque,
            buf: []u8,
            alignment: Alignment,
            new_len: usize,
            ra: usize,
        ) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (self.fixed_buffer_allocator.ownsPtr(buf.ptr)) {
                return FixedBufferAllocator.resize(&self.fixed_buffer_allocator, buf, alignment, new_len, ra);
            } else {
                return self.fallback_allocator.rawResize(buf, alignment, new_len, ra);
            }
        }

        fn remap(
            context: *anyopaque,
            memory: []u8,
            alignment: Alignment,
            new_len: usize,
            return_address: usize,
        ) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.fixed_buffer_allocator.ownsPtr(memory.ptr)) {
                return FixedBufferAllocator.remap(&self.fixed_buffer_allocator, memory, alignment, new_len, return_address);
            } else {
                return self.fallback_allocator.rawRemap(memory, alignment, new_len, return_address);
            }
        }

        fn free(
            ctx: *anyopaque,
            buf: []u8,
            alignment: Alignment,
            ra: usize,
        ) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (self.fixed_buffer_allocator.ownsPtr(buf.ptr)) {
                return FixedBufferAllocator.free(&self.fixed_buffer_allocator, buf, alignment, ra);
            } else {
                return self.fallback_allocator.rawFree(buf, alignment, ra);
            }
        }
    };
}

test c_allocator {
    if (builtin.link_libc) {
        try testAllocator(c_allocator);
        try testAllocatorAligned(c_allocator);
        try testAllocatorLargeAlignment(c_allocator);
        try testAllocatorAlignedShrink(c_allocator);
    }
}

test raw_c_allocator {
    if (builtin.link_libc) {
        try testAllocator(raw_c_allocator);
    }
}

test smp_allocator {
    if (builtin.single_threaded) return;
    try testAllocator(smp_allocator);
    try testAllocatorAligned(smp_allocator);
    try testAllocatorLargeAlignment(smp_allocator);
    try testAllocatorAlignedShrink(smp_allocator);
}

test PageAllocator {
    const allocator = page_allocator;
    try testAllocator(allocator);
    try testAllocatorAligned(allocator);
    if (!builtin.target.cpu.arch.isWasm()) {
        try testAllocatorLargeAlignment(allocator);
        try testAllocatorAlignedShrink(allocator);
    }

    if (builtin.os.tag == .windows) {
        const slice = try allocator.alignedAlloc(u8, .fromByteUnits(page_size_min), 128);
        slice[0] = 0x12;
        slice[127] = 0x34;
        allocator.free(slice);
    }
    {
        var buf = try allocator.alloc(u8, pageSize() + 1);
        defer allocator.free(buf);
        buf = try allocator.realloc(buf, 1); // shrink past the page boundary
    }
}

test ArenaAllocator {
    var arena_allocator = ArenaAllocator.init(page_allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    try testAllocator(allocator);
    try testAllocatorAligned(allocator);
    try testAllocatorLargeAlignment(allocator);
    try testAllocatorAlignedShrink(allocator);
}

test "StackFallbackAllocator" {
    {
        var stack_allocator = stackFallback(4096, std.testing.allocator);
        try testAllocator(stack_allocator.get());
    }
    {
        var stack_allocator = stackFallback(4096, std.testing.allocator);
        try testAllocatorAligned(stack_allocator.get());
    }
    {
        var stack_allocator = stackFallback(4096, std.testing.allocator);
        try testAllocatorLargeAlignment(stack_allocator.get());
    }
    {
        var stack_allocator = stackFallback(4096, std.testing.allocator);
        try testAllocatorAlignedShrink(stack_allocator.get());
    }
}

/// This one should not try alignments that exceed what C malloc can handle.
pub fn testAllocator(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = validationAllocator.allocator();

    var slice = try allocator.alloc(*i32, 100);
    try testing.expect(slice.len == 100);
    for (slice, 0..) |*item, i| {
        item.* = try allocator.create(i32);
        item.*.* = @as(i32, @intCast(i));
    }

    slice = try allocator.realloc(slice, 20000);
    try testing.expect(slice.len == 20000);

    for (slice[0..100], 0..) |item, i| {
        try testing.expect(item.* == @as(i32, @intCast(i)));
        allocator.destroy(item);
    }

    if (allocator.resize(slice, 50)) {
        slice = slice[0..50];
        if (allocator.resize(slice, 25)) {
            slice = slice[0..25];
            try testing.expect(allocator.resize(slice, 0));
            slice = slice[0..0];
            slice = try allocator.realloc(slice, 10);
            try testing.expect(slice.len == 10);
        }
    }
    allocator.free(slice);

    // Zero-length allocation
    const empty = try allocator.alloc(u8, 0);
    allocator.free(empty);
    // Allocation with zero-sized types
    const zero_bit_ptr = try allocator.create(u0);
    zero_bit_ptr.* = 0;
    allocator.destroy(zero_bit_ptr);
    const zero_len_array = try allocator.create([0]u64);
    allocator.destroy(zero_len_array);

    const oversize = try allocator.alignedAlloc(u32, null, 5);
    try testing.expect(oversize.len >= 5);
    for (oversize) |*item| {
        item.* = 0xDEADBEEF;
    }
    allocator.free(oversize);
}

pub fn testAllocatorAligned(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = validationAllocator.allocator();

    // Test a few alignment values, smaller and bigger than the type's one
    inline for ([_]Alignment{ .@"1", .@"2", .@"4", .@"8", .@"16", .@"32", .@"64" }) |alignment| {
        // initial
        var slice = try allocator.alignedAlloc(u8, alignment, 10);
        try testing.expect(slice.len == 10);
        // grow
        slice = try allocator.realloc(slice, 100);
        try testing.expect(slice.len == 100);
        if (allocator.resize(slice, 10)) {
            slice = slice[0..10];
        }
        try testing.expect(allocator.resize(slice, 0));
        slice = slice[0..0];
        // realloc from zero
        slice = try allocator.realloc(slice, 100);
        try testing.expect(slice.len == 100);
        if (allocator.resize(slice, 10)) {
            slice = slice[0..10];
        }
        try testing.expect(allocator.resize(slice, 0));
    }
}

pub fn testAllocatorLargeAlignment(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = validationAllocator.allocator();

    const large_align: usize = page_size_min / 2;

    var align_mask: usize = undefined;
    align_mask = @shlWithOverflow(~@as(usize, 0), @as(Allocator.Log2Align, @ctz(large_align)))[0];

    var slice = try allocator.alignedAlloc(u8, .fromByteUnits(large_align), 500);
    try testing.expect(@intFromPtr(slice.ptr) & align_mask == @intFromPtr(slice.ptr));

    if (allocator.resize(slice, 100)) {
        slice = slice[0..100];
    }

    slice = try allocator.realloc(slice, 5000);
    try testing.expect(@intFromPtr(slice.ptr) & align_mask == @intFromPtr(slice.ptr));

    if (allocator.resize(slice, 10)) {
        slice = slice[0..10];
    }

    slice = try allocator.realloc(slice, 20000);
    try testing.expect(@intFromPtr(slice.ptr) & align_mask == @intFromPtr(slice.ptr));

    allocator.free(slice);
}

pub fn testAllocatorAlignedShrink(base_allocator: mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = validationAllocator.allocator();

    var debug_buffer: [1000]u8 = undefined;
    var fib = FixedBufferAllocator.init(&debug_buffer);
    const debug_allocator = fib.allocator();

    const alloc_size = pageSize() * 2 + 50;
    var slice = try allocator.alignedAlloc(u8, .@"16", alloc_size);
    defer allocator.free(slice);

    var stuff_to_free = std.ArrayList([]align(16) u8).init(debug_allocator);
    // On Windows, VirtualAlloc returns addresses aligned to a 64K boundary,
    // which is 16 pages, hence the 32. This test may require to increase
    // the size of the allocations feeding the `allocator` parameter if they
    // fail, because of this high over-alignment we want to have.
    while (@intFromPtr(slice.ptr) == mem.alignForward(usize, @intFromPtr(slice.ptr), pageSize() * 32)) {
        try stuff_to_free.append(slice);
        slice = try allocator.alignedAlloc(u8, .@"16", alloc_size);
    }
    while (stuff_to_free.pop()) |item| {
        allocator.free(item);
    }
    slice[0] = 0x12;
    slice[60] = 0x34;

    slice = try allocator.reallocAdvanced(slice, alloc_size / 2, 0);
    try testing.expect(slice[0] == 0x12);
    try testing.expect(slice[60] == 0x34);
}

const page_size_min_default: ?usize = switch (builtin.os.tag) {
    .driverkit, .ios, .macos, .tvos, .visionos, .watchos => switch (builtin.cpu.arch) {
        .x86_64 => 4 << 10,
        .aarch64 => 16 << 10,
        else => null,
    },
    .windows => switch (builtin.cpu.arch) {
        // -- <https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200>
        .x86, .x86_64 => 4 << 10,
        // SuperH => 4 << 10,
        .mips, .mipsel, .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => 4 << 10,
        // DEC Alpha => 8 << 10,
        // Itanium => 8 << 10,
        .thumb, .thumbeb, .arm, .armeb, .aarch64, .aarch64_be => 4 << 10,
        else => null,
    },
    .wasi => switch (builtin.cpu.arch) {
        .wasm32, .wasm64 => 64 << 10,
        else => null,
    },
    // https://github.com/tianocore/edk2/blob/b158dad150bf02879668f72ce306445250838201/MdePkg/Include/Uefi/UefiBaseType.h#L180-L187
    .uefi => 4 << 10,
    .freebsd => switch (builtin.cpu.arch) {
        // FreeBSD/sys/*
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .riscv32, .riscv64 => 4 << 10,
        else => null,
    },
    .netbsd => switch (builtin.cpu.arch) {
        // NetBSD/sys/arch/*
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .mips, .mipsel, .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .sparc => 4 << 10,
        .sparc64 => 8 << 10,
        .riscv32, .riscv64 => 4 << 10,
        // Sun-2
        .m68k => 2 << 10,
        else => null,
    },
    .dragonfly => switch (builtin.cpu.arch) {
        .x86, .x86_64 => 4 << 10,
        else => null,
    },
    .openbsd => switch (builtin.cpu.arch) {
        // OpenBSD/sys/arch/*
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb, .aarch64, .aarch64_be => 4 << 10,
        .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .riscv64 => 4 << 10,
        .sparc64 => 8 << 10,
        else => null,
    },
    .solaris, .illumos => switch (builtin.cpu.arch) {
        // src/uts/*/sys/machparam.h
        .x86, .x86_64 => 4 << 10,
        .sparc, .sparc64 => 8 << 10,
        else => null,
    },
    .fuchsia => switch (builtin.cpu.arch) {
        // fuchsia/kernel/arch/*/include/arch/defines.h
        .x86_64 => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .riscv64 => 4 << 10,
        else => null,
    },
    // https://github.com/SerenityOS/serenity/blob/62b938b798dc009605b5df8a71145942fc53808b/Kernel/API/POSIX/sys/limits.h#L11-L13
    .serenity => 4 << 10,
    .haiku => switch (builtin.cpu.arch) {
        // haiku/headers/posix/arch/*/limits.h
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .m68k => 4 << 10,
        .mips, .mipsel, .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .riscv64 => 4 << 10,
        .sparc64 => 8 << 10,
        .x86, .x86_64 => 4 << 10,
        else => null,
    },
    .hurd => switch (builtin.cpu.arch) {
        // gnumach/*/include/mach/*/vm_param.h
        .x86, .x86_64 => 4 << 10,
        .aarch64 => null,
        else => null,
    },
    .plan9 => switch (builtin.cpu.arch) {
        // 9front/sys/src/9/*/mem.h
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .mips, .mipsel, .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => 4 << 10,
        .sparc => 4 << 10,
        else => null,
    },
    .ps3 => switch (builtin.cpu.arch) {
        // cell/SDK_doc/en/html/C_and_C++_standard_libraries/stdlib.html
        .powerpc64 => 1 << 20, // 1 MiB
        else => null,
    },
    .ps4 => switch (builtin.cpu.arch) {
        // https://github.com/ps4dev/ps4sdk/blob/4df9d001b66ae4ec07d9a51b62d1e4c5e270eecc/include/machine/param.h#L95
        .x86, .x86_64 => 4 << 10,
        else => null,
    },
    .ps5 => switch (builtin.cpu.arch) {
        // https://github.com/PS5Dev/PS5SDK/blob/a2e03a2a0231a3a3397fa6cd087a01ca6d04f273/include/machine/param.h#L95
        .x86, .x86_64 => 16 << 10,
        else => null,
    },
    // system/lib/libc/musl/arch/emscripten/bits/limits.h
    .emscripten => 64 << 10,
    .linux => switch (builtin.cpu.arch) {
        // Linux/arch/*/Kconfig
        .arc => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .csky => 4 << 10,
        .hexagon => 4 << 10,
        .loongarch32, .loongarch64 => 4 << 10,
        .m68k => 4 << 10,
        .mips, .mipsel, .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .riscv32, .riscv64 => 4 << 10,
        .s390x => 4 << 10,
        .sparc => 4 << 10,
        .sparc64 => 8 << 10,
        .x86, .x86_64 => 4 << 10,
        .xtensa => 4 << 10,
        else => null,
    },
    .freestanding, .other => switch (builtin.cpu.arch) {
        .wasm32, .wasm64 => 64 << 10,
        .x86, .x86_64 => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        else => null,
    },
    else => null,
};

const page_size_max_default: ?usize = switch (builtin.os.tag) {
    .driverkit, .ios, .macos, .tvos, .visionos, .watchos => switch (builtin.cpu.arch) {
        .x86_64 => 4 << 10,
        .aarch64 => 16 << 10,
        else => null,
    },
    .windows => switch (builtin.cpu.arch) {
        // -- <https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200>
        .x86, .x86_64 => 4 << 10,
        // SuperH => 4 << 10,
        .mips, .mipsel, .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => 4 << 10,
        // DEC Alpha => 8 << 10,
        // Itanium => 8 << 10,
        .thumb, .thumbeb, .arm, .armeb, .aarch64, .aarch64_be => 4 << 10,
        else => null,
    },
    .wasi => switch (builtin.cpu.arch) {
        .wasm32, .wasm64 => 64 << 10,
        else => null,
    },
    // https://github.com/tianocore/edk2/blob/b158dad150bf02879668f72ce306445250838201/MdePkg/Include/Uefi/UefiBaseType.h#L180-L187
    .uefi => 4 << 10,
    .freebsd => switch (builtin.cpu.arch) {
        // FreeBSD/sys/*
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .riscv32, .riscv64 => 4 << 10,
        else => null,
    },
    .netbsd => switch (builtin.cpu.arch) {
        // NetBSD/sys/arch/*
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 64 << 10,
        .mips, .mipsel, .mips64, .mips64el => 16 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 16 << 10,
        .sparc => 8 << 10,
        .sparc64 => 8 << 10,
        .riscv32, .riscv64 => 4 << 10,
        .m68k => 8 << 10,
        else => null,
    },
    .dragonfly => switch (builtin.cpu.arch) {
        .x86, .x86_64 => 4 << 10,
        else => null,
    },
    .openbsd => switch (builtin.cpu.arch) {
        // OpenBSD/sys/arch/*
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb, .aarch64, .aarch64_be => 4 << 10,
        .mips64, .mips64el => 16 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .riscv64 => 4 << 10,
        .sparc64 => 8 << 10,
        else => null,
    },
    .solaris, .illumos => switch (builtin.cpu.arch) {
        // src/uts/*/sys/machparam.h
        .x86, .x86_64 => 4 << 10,
        .sparc, .sparc64 => 8 << 10,
        else => null,
    },
    .fuchsia => switch (builtin.cpu.arch) {
        // fuchsia/kernel/arch/*/include/arch/defines.h
        .x86_64 => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .riscv64 => 4 << 10,
        else => null,
    },
    // https://github.com/SerenityOS/serenity/blob/62b938b798dc009605b5df8a71145942fc53808b/Kernel/API/POSIX/sys/limits.h#L11-L13
    .serenity => 4 << 10,
    .haiku => switch (builtin.cpu.arch) {
        // haiku/headers/posix/arch/*/limits.h
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 4 << 10,
        .m68k => 4 << 10,
        .mips, .mipsel, .mips64, .mips64el => 4 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 4 << 10,
        .riscv64 => 4 << 10,
        .sparc64 => 8 << 10,
        .x86, .x86_64 => 4 << 10,
        else => null,
    },
    .hurd => switch (builtin.cpu.arch) {
        // gnumach/*/include/mach/*/vm_param.h
        .x86, .x86_64 => 4 << 10,
        .aarch64 => null,
        else => null,
    },
    .plan9 => switch (builtin.cpu.arch) {
        // 9front/sys/src/9/*/mem.h
        .x86, .x86_64 => 4 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 64 << 10,
        .mips, .mipsel, .mips64, .mips64el => 16 << 10,
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => 4 << 10,
        .sparc => 4 << 10,
        else => null,
    },
    .ps3 => switch (builtin.cpu.arch) {
        // cell/SDK_doc/en/html/C_and_C++_standard_libraries/stdlib.html
        .powerpc64 => 1 << 20, // 1 MiB
        else => null,
    },
    .ps4 => switch (builtin.cpu.arch) {
        // https://github.com/ps4dev/ps4sdk/blob/4df9d001b66ae4ec07d9a51b62d1e4c5e270eecc/include/machine/param.h#L95
        .x86, .x86_64 => 4 << 10,
        else => null,
    },
    .ps5 => switch (builtin.cpu.arch) {
        // https://github.com/PS5Dev/PS5SDK/blob/a2e03a2a0231a3a3397fa6cd087a01ca6d04f273/include/machine/param.h#L95
        .x86, .x86_64 => 16 << 10,
        else => null,
    },
    // system/lib/libc/musl/arch/emscripten/bits/limits.h
    .emscripten => 64 << 10,
    .linux => switch (builtin.cpu.arch) {
        // Linux/arch/*/Kconfig
        .arc => 16 << 10,
        .thumb, .thumbeb, .arm, .armeb => 4 << 10,
        .aarch64, .aarch64_be => 64 << 10,
        .csky => 4 << 10,
        .hexagon => 256 << 10,
        .loongarch32, .loongarch64 => 64 << 10,
        .m68k => 8 << 10,
        .mips, .mipsel, .mips64, .mips64el => 64 << 10,
        .powerpc, .powerpc64, .powerpc64le, .powerpcle => 256 << 10,
        .riscv32, .riscv64 => 4 << 10,
        .s390x => 4 << 10,
        .sparc => 4 << 10,
        .sparc64 => 8 << 10,
        .x86, .x86_64 => 4 << 10,
        .xtensa => 4 << 10,
        else => null,
    },
    .freestanding => switch (builtin.cpu.arch) {
        .wasm32, .wasm64 => 64 << 10,
        else => null,
    },
    else => null,
};

test {
    _ = @import("heap/memory_pool.zig");
    _ = ArenaAllocator;
    _ = GeneralPurposeAllocator;
    _ = FixedBufferAllocator;
    _ = ThreadSafeAllocator;
    _ = SbrkAllocator;
    if (builtin.target.cpu.arch.isWasm()) {
        _ = WasmAllocator;
    }
    if (!builtin.single_threaded) _ = smp_allocator;
}
const std = @import("../std.zig");
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

/// This allocator takes an existing allocator, wraps it, and provides an interface where
/// you can allocate and then free it all together. Calls to free an individual item only
/// free the item if it was the most recent allocation, otherwise calls to free do
/// nothing.
pub const ArenaAllocator = struct {
    child_allocator: Allocator,
    state: State,

    /// Inner state of ArenaAllocator. Can be stored rather than the entire ArenaAllocator
    /// as a memory-saving optimization.
    pub const State = struct {
        buffer_list: std.SinglyLinkedList = .{},
        end_index: usize = 0,

        pub fn promote(self: State, child_allocator: Allocator) ArenaAllocator {
            return .{
                .child_allocator = child_allocator,
                .state = self,
            };
        }
    };

    pub fn allocator(self: *ArenaAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    const BufNode = struct {
        data: usize,
        node: std.SinglyLinkedList.Node = .{},
    };
    const BufNode_alignment: Alignment = .fromByteUnits(@alignOf(BufNode));

    pub fn init(child_allocator: Allocator) ArenaAllocator {
        return (State{}).promote(child_allocator);
    }

    pub fn deinit(self: ArenaAllocator) void {
        // NOTE: When changing this, make sure `reset()` is adjusted accordingly!

        var it = self.state.buffer_list.first;
        while (it) |node| {
            // this has to occur before the free because the free frees node
            const next_it = node.next;
            const buf_node: *BufNode = @fieldParentPtr("node", node);
            const alloc_buf = @as([*]u8, @ptrCast(buf_node))[0..buf_node.data];
            self.child_allocator.rawFree(alloc_buf, BufNode_alignment, @returnAddress());
            it = next_it;
        }
    }

    pub const ResetMode = union(enum) {
        /// Releases all allocated memory in the arena.
        free_all,
        /// This will pre-heat the arena for future allocations by allocating a
        /// large enough buffer for all previously done allocations.
        /// Preheating will speed up the allocation process by invoking the backing allocator
        /// less often than before. If `reset()` is used in a loop, this means that after the
        /// biggest operation, no memory allocations are performed anymore.
        retain_capacity,
        /// This is the same as `retain_capacity`, but the memory will be shrunk to
        /// this value if it exceeds the limit.
        retain_with_limit: usize,
    };
    /// Queries the current memory use of this arena.
    /// This will **not** include the storage required for internal keeping.
    pub fn queryCapacity(self: ArenaAllocator) usize {
        var size: usize = 0;
        var it = self.state.buffer_list.fir```
