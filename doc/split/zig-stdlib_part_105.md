```
rtions, 0..) |p, index| {
        accumulator += p;
        if (point < accumulator) return index;
    } else unreachable;
}

/// Convert a random integer 0 <= random_int <= maxValue(T),
/// into an integer 0 <= result < less_than.
/// This function introduces a minor bias.
pub fn limitRangeBiased(comptime T: type, random_int: T, less_than: T) T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    const bits = @typeInfo(T).int.bits;

    // adapted from:
    //   http://www.pcg-random.org/posts/bounded-rands.html
    //   "Integer Multiplication (Biased)"
    const m = math.mulWide(T, random_int, less_than);
    return @intCast(m >> bits);
}

/// Returns the smallest of `Index` and `usize`.
fn MinArrayIndex(comptime Index: type) type {
    const index_info = @typeInfo(Index).int;
    assert(index_info.signedness == .unsigned);
    return if (index_info.bits >= @typeInfo(usize).int.bits) usize else Index;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("Random/test.zig");
}
//! CSPRNG based on the Reverie construction, a permutation-based PRNG
//! with forward security, instantiated with the Ascon(128,12,8) permutation.
//!
//! Compared to ChaCha, this PRNG has a much smaller state, and can be
//! a better choice for constrained environments.
//!
//! References:
//! - A Robust and Sponge-Like PRNG with Improved Efficiency https://eprint.iacr.org/2016/886.pdf
//! - Ascon https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf

const std = @import("std");
const mem = std.mem;
const Self = @This();

const Ascon = std.crypto.core.Ascon(.little);

state: Ascon,

const rate = 16;
pub const secret_seed_length = 32;

/// The seed must be uniform, secret and `secret_seed_length` bytes long.
pub fn init(secret_seed: [secret_seed_length]u8) Self {
    var self = Self{ .state = Ascon.initXof() };
    self.addEntropy(&secret_seed);
    return self;
}

/// Inserts entropy to refresh the internal state.
pub fn addEntropy(self: *Self, bytes: []const u8) void {
    comptime std.debug.assert(secret_seed_length % rate == 0);
    var i: usize = 0;
    while (i + rate < bytes.len) : (i += rate) {
        self.state.addBytes(bytes[i..][0..rate]);
        self.state.permuteR(8);
    }
    if (i != bytes.len) self.state.addBytes(bytes[i..]);
    self.state.permute();
}

/// Returns a `std.Random` structure backed by the current RNG.
pub fn random(self: *Self) std.Random {
    return std.Random.init(self, fill);
}

/// Fills the buffer with random bytes.
pub fn fill(self: *Self, buf: []u8) void {
    var i: usize = 0;
    while (true) {
        const left = buf.len - i;
        const n = @min(left, rate);
        self.state.extractBytes(buf[i..][0..n]);
        if (left == 0) break;
        self.state.permuteR(8);
        i += n;
    }
    self.state.permuteRatchet(6, rate);
}
// zig run -O ReleaseFast --zig-lib-dir ../.. benchmark.zig

const std = @import("std");
const builtin = @import("builtin");
const time = std.time;
const Timer = time.Timer;
const Random = std.Random;

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

const Rng = struct {
    ty: type,
    name: []const u8,
    init_u8s: ?[]const u8 = null,
    init_u64: ?u64 = null,
};

const prngs = [_]Rng{
    Rng{
        .ty = Random.Isaac64,
        .name = "isaac64",
        .init_u64 = 0,
    },
    Rng{
        .ty = Random.Pcg,
        .name = "pcg",
        .init_u64 = 0,
    },
    Rng{
        .ty = Random.RomuTrio,
        .name = "romutrio",
        .init_u64 = 0,
    },
    Rng{
        .ty = Random.Sfc64,
        .name = "sfc64",
        .init_u64 = 0,
    },
    Rng{
        .ty = Random.Xoroshiro128,
        .name = "xoroshiro128",
        .init_u64 = 0,
    },
    Rng{
        .ty = Random.Xoshiro256,
        .name = "xoshiro256",
        .init_u64 = 0,
    },
};

const csprngs = [_]Rng{
    Rng{
        .ty = Random.Ascon,
        .name = "ascon",
        .init_u8s = &[_]u8{0} ** 32,
    },
    Rng{
        .ty = Random.ChaCha,
        .name = "chacha",
        .init_u8s = &[_]u8{0} ** 32,
    },
};

const Result = struct {
    throughput: u64,
};

const long_block_size: usize = 8 * 8192;
const short_block_size: usize = 8;

pub fn benchmark(comptime H: anytype, bytes: usize, comptime block_size: usize) !Result {
    var rng = blk: {
        if (H.init_u8s) |init| {
            break :blk H.ty.init(init[0..].*);
        }
        if (H.init_u64) |init| {
            break :blk H.ty.init(init);
        }
        break :blk H.ty.init();
    };

    var block: [block_size]u8 = undefined;

    var offset: usize = 0;
    var timer = try Timer.start();
    const start = timer.lap();
    while (offset < bytes) : (offset += block.len) {
        rng.fill(block[0..]);
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(@as(f64, @floatFromInt(bytes)) / elapsed_s));

    std.debug.assert(rng.random().int(u64) != 0);

    return Result{
        .throughput = throughput,
    };
}

fn usage() void {
    std.debug.print(
        \\throughput_test [options]
        \\
        \\Options:
        \\  --filter    [test-name]
        \\  --count     [int]
        \\  --prngs-only
        \\  --csprngs-only
        \\  --short-only
        \\  --long-only
        \\  --help
        \\
    , .{});
}

fn mode(comptime x: comptime_int) comptime_int {
    return if (builtin.mode == .Debug) x / 64 else x;
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var buffer: [1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(buffer[0..]);
    const args = try std.process.argsAlloc(fixed.allocator());

    var filter: ?[]u8 = "";
    var count: usize = mode(128 * MiB);
    var bench_prngs = true;
    var bench_csprngs = true;
    var bench_long = true;
    var bench_short = true;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--mode")) {
            try stdout.print("{}\n", .{builtin.mode});
            return;
        } else if (std.mem.eql(u8, args[i], "--filter")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.process.exit(1);
            }

            filter = args[i];
        } else if (std.mem.eql(u8, args[i], "--count")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.process.exit(1);
            }

            const c = try std.fmt.parseUnsigned(usize, args[i], 10);
            count = c * MiB;
        } else if (std.mem.eql(u8, args[i], "--csprngs-only")) {
            bench_prngs = false;
        } else if (std.mem.eql(u8, args[i], "--prngs-only")) {
            bench_csprngs = false;
        } else if (std.mem.eql(u8, args[i], "--short-only")) {
            bench_long = false;
        } else if (std.mem.eql(u8, args[i], "--long-only")) {
            bench_short = false;
        } else if (std.mem.eql(u8, args[i], "--help")) {
            usage();
            return;
        } else {
            usage();
            std.process.exit(1);
        }
    }

    if (bench_prngs) {
        if (bench_long) {
            inline for (prngs) |R| {
                if (filter == null or std.mem.indexOf(u8, R.name, filter.?) != null) {
                    try stdout.print("{s} (long outputs)\n", .{R.name});
                    const result_long = try benchmark(R, count, long_block_size);
                    try stdout.print("    {:5} MiB/s\n", .{result_long.throughput / (1 * MiB)});
                }
            }
        }
        if (bench_short) {
            inline for (prngs) |R| {
                if (filter == null or std.mem.indexOf(u8, R.name, filter.?) != null) {
                    try stdout.print("{s} (short outputs)\n", .{R.name});
                    const result_short = try benchmark(R, count, short_block_size);
                    try stdout.print("    {:5} MiB/s\n", .{result_short.throughput / (1 * MiB)});
                }
            }
        }
    }
    if (bench_csprngs) {
        if (bench_long) {
            inline for (csprngs) |R| {
                if (filter == null or std.mem.indexOf(u8, R.name, filter.?) != null) {
                    try stdout.print("{s} (cryptographic, long outputs)\n", .{R.name});
                    const result_long = try benchmark(R, count, long_block_size);
                    try stdout.print("    {:5} MiB/s\n", .{result_long.throughput / (1 * MiB)});
                }
            }
        }
        if (bench_short) {
            inline for (csprngs) |R| {
                if (filter == null or std.mem.indexOf(u8, R.name, filter.?) != null) {
                    try stdout.print("{s} (cryptographic, short outputs)\n", .{R.name});
                    const result_short = try benchmark(R, count, short_block_size);
                    try stdout.print("    {:5} MiB/s\n", .{result_short.throughput / (1 * MiB)});
                }
            }
        }
    }
}
//! CSPRNG based on the ChaCha8 stream cipher, with forward security.
//!
//! References:
//! - Fast-key-erasure random-number generators https://blog.cr.yp.to/20170723-random.html

const std = @import("std");
const mem = std.mem;
const Self = @This();

const Cipher = std.crypto.stream.chacha.ChaCha8IETF;

const State = [8 * Cipher.block_length]u8;

state: State,
offset: usize,

const nonce = [_]u8{0} ** Cipher.nonce_length;

pub const secret_seed_length = Cipher.key_length;

/// The seed must be uniform, secret and `secret_seed_length` bytes long.
pub fn init(secret_seed: [secret_seed_length]u8) Self {
    var self = Self{ .state = undefined, .offset = 0 };
    Cipher.stream(&self.state, 0, secret_seed, nonce);
    return self;
}

/// Inserts entropy to refresh the internal state.
pub fn addEntropy(self: *Self, bytes: []const u8) void {
    var i: usize = 0;
    while (i + Cipher.key_length <= bytes.len) : (i += Cipher.key_length) {
        Cipher.xor(
            self.state[0..Cipher.key_length],
            self.state[0..Cipher.key_length],
            0,
            bytes[i..][0..Cipher.key_length].*,
            nonce,
        );
    }
    if (i < bytes.len) {
        var k = [_]u8{0} ** Cipher.key_length;
        const src = bytes[i..];
        @memcpy(k[0..src.len], src);
        Cipher.xor(
            self.state[0..Cipher.key_length],
            self.state[0..Cipher.key_length],
            0,
            k,
            nonce,
        );
    }
    self.refill();
}

/// Returns a `std.Random` structure backed by the current RNG.
pub fn random(self: *Self) std.Random {
    return std.Random.init(self, fill);
}

// Refills the buffer with random bytes, overwriting the previous key.
fn refill(self: *Self) void {
    Cipher.stream(&self.state, 0, self.state[0..Cipher.key_length].*, nonce);
    self.offset = 0;
}

/// Fills the buffer with random bytes.
pub fn fill(self: *Self, buf_: []u8) void {
    const bytes = self.state[Cipher.key_length..];
    var buf = buf_;

    const avail = bytes.len - self.offset;
    if (avail > 0) {
        // Bytes from the current block
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], bytes[self.offset..][0..n]);
        @memset(bytes[self.offset..][0..n], 0);
        buf = buf[n..];
        self.offset += n;
    }
    if (buf.len == 0) return;

    self.refill();

    // Full blocks
    while (buf.len >= bytes.len) {
        @memcpy(buf[0..bytes.len], bytes);
        buf = buf[bytes.len..];
        self.refill();
    }

    // Remaining bytes
    if (buf.len > 0) {
        @memcpy(buf, bytes[0..buf.len]);
        @memset(bytes[0..buf.len], 0);
        self.offset = buf.len;
    }
}
//! ISAAC64 - http://www.burtleburtle.net/bob/rand/isaacafa.html
//!
//! Follows the general idea of the implementation from here with a few shortcuts.
//! https://doc.rust-lang.org/rand/src/rand/prng/isaac64.rs.html

const std = @import("std");
const mem = std.mem;
const Isaac64 = @This();

r: [256]u64,
m: [256]u64,
a: u64,
b: u64,
c: u64,
i: usize,

pub fn init(init_s: u64) Isaac64 {
    var isaac = Isaac64{
        .r = undefined,
        .m = undefined,
        .a = undefined,
        .b = undefined,
        .c = undefined,
        .i = undefined,
    };

    // seed == 0 => same result as the unseeded reference implementation
    isaac.seed(init_s, 1);
    return isaac;
}

pub fn random(self: *Isaac64) std.Random {
    return std.Random.init(self, fill);
}

fn step(self: *Isaac64, mix: u64, base: usize, comptime m1: usize, comptime m2: usize) void {
    const x = self.m[base + m1];
    self.a = mix +% self.m[base + m2];

    const y = self.a +% self.b +% self.m[@as(usize, @intCast((x >> 3) % self.m.len))];
    self.m[base + m1] = y;

    self.b = x +% self.m[@as(usize, @intCast((y >> 11) % self.m.len))];
    self.r[self.r.len - 1 - base - m1] = self.b;
}

fn refill(self: *Isaac64) void {
    const midpoint = self.r.len / 2;

    self.c +%= 1;
    self.b +%= self.c;

    {
        var i: usize = 0;
        while (i < midpoint) : (i += 4) {
            self.step(~(self.a ^ (self.a << 21)), i + 0, 0, midpoint);
            self.step(self.a ^ (self.a >> 5), i + 1, 0, midpoint);
            self.step(self.a ^ (self.a << 12), i + 2, 0, midpoint);
            self.step(self.a ^ (self.a >> 33), i + 3, 0, midpoint);
        }
    }

    {
        var i: usize = 0;
        while (i < midpoint) : (i += 4) {
            self.step(~(self.a ^ (self.a << 21)), i + 0, midpoint, 0);
            self.step(self.a ^ (self.a >> 5), i + 1, midpoint, 0);
            self.step(self.a ^ (self.a << 12), i + 2, midpoint, 0);
            self.step(self.a ^ (self.a >> 33), i + 3, midpoint, 0);
        }
    }

    self.i = 0;
}

fn next(self: *Isaac64) u64 {
    if (self.i >= self.r.len) {
        self.refill();
    }

    const value = self.r[self.i];
    self.i += 1;
    return value;
}

fn seed(self: *Isaac64, init_s: u64, comptime rounds: usize) void {
    // We ignore the multi-pass requirement since we don't currently expose full access to
    // seeding the self.m array completely.
    @memset(self.m[0..], 0);
    self.m[0] = init_s;

    // prescrambled golden ratio constants
    var a = [_]u64{
        0x647c4677a2884b7c,
        0xb9f8b322c73ac862,
        0x8c0ea5053d4712a0,
        0xb29b2e824a595524,
        0x82f053db8355e0ce,
        0x48fe4a0fa5a09315,
        0xae985bf2cbfc89ed,
        0x98f5704f6c44c0ab,
    };

    comptime var i: usize = 0;
    inline while (i < rounds) : (i += 1) {
        var j: usize = 0;
        while (j < self.m.len) : (j += 8) {
            comptime var x1: usize = 0;
            inline while (x1 < 8) : (x1 += 1) {
                a[x1] +%= self.m[j + x1];
            }

            a[0] -%= a[4];
            a[5] ^= a[7] >> 9;
            a[7] +%= a[0];
            a[1] -%= a[5];
            a[6] ^= a[0] << 9;
            a[0] +%= a[1];
            a[2] -%= a[6];
            a[7] ^= a[1] >> 23;
            a[1] +%= a[2];
            a[3] -%= a[7];
            a[0] ^= a[2] << 15;
            a[2] +%= a[3];
            a[4] -%= a[0];
            a[1] ^= a[3] >> 14;
            a[3] +%= a[4];
            a[5] -%= a[1];
            a[2] ^= a[4] << 20;
            a[4] +%= a[5];
            a[6] -%= a[2];
            a[3] ^= a[5] >> 17;
            a[5] +%= a[6];
            a[7] -%= a[3];
            a[4] ^= a[6] << 14;
            a[6] +%= a[7];

            comptime var x2: usize = 0;
            inline while (x2 < 8) : (x2 += 1) {
                self.m[j + x2] = a[x2];
            }
        }
    }

    @memset(self.r[0..], 0);
    self.a = 0;
    self.b = 0;
    self.c = 0;
    self.i = self.r.len; // trigger refill on first value
}

pub fn fill(self: *Isaac64, buf: []u8) void {
    var i: usize = 0;
    const aligned_len = buf.len - (buf.len & 7);

    // Fill complete 64-byte segments
    while (i < aligned_len) : (i += 8) {
        var n = self.next();
        comptime var j: usize = 0;
        inline while (j < 8) : (j += 1) {
            buf[i + j] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }

    // Fill trailing, ignoring excess (cut the stream).
    if (i != buf.len) {
        var n = self.next();
        while (i < buf.len) : (i += 1) {
            buf[i] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
}

test "sequence" {
    var r = Isaac64.init(0);

    // from reference implementation
    const seq = [_]u64{
        0xf67dfba498e4937c,
        0x84a5066a9204f380,
        0xfee34bd5f5514dbb,
        0x4d1664739b8f80d6,
        0x8607459ab52a14aa,
        0x0e78bc5a98529e49,
        0xfe5332822ad13777,
        0x556c27525e33d01a,
        0x08643ca615f3149f,
        0xd0771faf3cb04714,
        0x30e86f68a37b008d,
        0x3074ebc0488a3adf,
        0x270645ea7a2790bc,
        0x5601a0a8d3763c6a,
        0x2f83071f53f325dd,
        0xb9090f3d42d2d2ea,
    };

    for (seq) |s| {
        try std.testing.expect(s == r.next());
    }
}

test fill {
    var r = Isaac64.init(0);

    // from reference implementation
    const seq = [_]u64{
        0xf67dfba498e4937c,
        0x84a5066a9204f380,
        0xfee34bd5f5514dbb,
        0x4d1664739b8f80d6,
        0x8607459ab52a14aa,
        0x0e78bc5a98529e49,
        0xfe5332822ad13777,
        0x556c27525e33d01a,
        0x08643ca615f3149f,
        0xd0771faf3cb04714,
        0x30e86f68a37b008d,
        0x3074ebc0488a3adf,
        0x270645ea7a2790bc,
        0x5601a0a8d3763c6a,
        0x2f83071f53f325dd,
        0xb9090f3d42d2d2ea,
    };

    for (seq) |s| {
        var buf0: [8]u8 = undefined;
        var buf1: [7]u8 = undefined;
        std.mem.writeInt(u64, &buf0, s, .little);
        r.fill(&buf1);
        try std.testing.expect(std.mem.eql(u8, buf0[0..7], buf1[0..]));
    }
}
//! PCG32 - http://www.pcg-random.org/
//!
//! PRNG

const std = @import("std");
const Pcg = @This();

const default_multiplier = 6364136223846793005;

s: u64,
i: u64,

pub fn init(init_s: u64) Pcg {
    var pcg = Pcg{
        .s = undefined,
        .i = undefined,
    };

    pcg.seed(init_s);
    return pcg;
}

pub fn random(self: *Pcg) std.Random {
    return std.Random.init(self, fill);
}

fn next(self: *Pcg) u32 {
    const l = self.s;
    self.s = l *% default_multiplier +% (self.i | 1);

    const xor_s: u32 = @truncate(((l >> 18) ^ l) >> 27);
    const rot: u32 = @intCast(l >> 59);

    return (xor_s >> @as(u5, @intCast(rot))) | (xor_s << @as(u5, @intCast((0 -% rot) & 31)));
}

fn seed(self: *Pcg, init_s: u64) void {
    // Pcg requires 128-bits of seed.
    var gen = std.Random.SplitMix64.init(init_s);
    self.seedTwo(gen.next(), gen.next());
}

fn seedTwo(self: *Pcg, init_s: u64, init_i: u64) void {
    self.s = 0;
    self.i = (init_s << 1) | 1;
    self.s = self.s *% default_multiplier +% self.i;
    self.s +%= init_i;
    self.s = self.s *% default_multiplier +% self.i;
}

pub fn fill(self: *Pcg, buf: []u8) void {
    var i: usize = 0;
    const aligned_len = buf.len - (buf.len & 3);

    // Complete 4 byte segments.
    while (i < aligned_len) : (i += 4) {
        var n = self.next();
        comptime var j: usize = 0;
        inline while (j < 4) : (j += 1) {
            buf[i + j] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }

    // Remaining. (cuts the stream)
    if (i != buf.len) {
        var n = self.next();
        while (i < buf.len) : (i += 1) {
            buf[i] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
}

test "sequence" {
    var r = Pcg.init(0);
    const s0: u64 = 0x9394bf54ce5d79de;
    const s1: u64 = 0x84e9c579ef59bbf7;
    r.seedTwo(s0, s1);

    const seq = [_]u32{
        2881561918,
        3063928540,
        1199791034,
        2487695858,
        1479648952,
        3247963454,
    };

    for (seq) |s| {
        try std.testing.expect(s == r.next());
    }
}

test fill {
    var r = Pcg.init(0);
    const s0: u64 = 0x9394bf54ce5d79de;
    const s1: u64 = 0x84e9c579ef59bbf7;
    r.seedTwo(s0, s1);

    const seq = [_]u32{
        2881561918,
        3063928540,
        1199791034,
        2487695858,
        1479648952,
        3247963454,
    };

    var i: u32 = 0;
    while (i < seq.len) : (i += 2) {
        var buf0: [8]u8 = undefined;
        std.mem.writeInt(u32, buf0[0..4], seq[i], .little);
        std.mem.writeInt(u32, buf0[4..8], seq[i + 1], .little);

        var buf1: [7]u8 = undefined;
        r.fill(&buf1);

        try std.testing.expect(std.mem.eql(u8, buf0[0..7], buf1[0..]));
    }
}
// Website: romu-random.org
// Reference paper:   http://arxiv.org/abs/2002.11331
// Beware: this PRNG is trivially predictable. While fast, it should *never* be used for cryptographic purposes.

const std = @import("std");
const math = std.math;
const RomuTrio = @This();

x_state: u64,
y_state: u64,
z_state: u64, // set to nonzero seed

pub fn init(init_s: u64) RomuTrio {
    var x = RomuTrio{ .x_state = undefined, .y_state = undefined, .z_state = undefined };
    x.seed(init_s);
    return x;
}

pub fn random(self: *RomuTrio) std.Random {
    return std.Random.init(self, fill);
}

fn next(self: *RomuTrio) u64 {
    const xp = self.x_state;
    const yp = self.y_state;
    const zp = self.z_state;
    self.x_state = 15241094284759029579 *% zp;
    self.y_state = yp -% xp;
    self.y_state = std.math.rotl(u64, self.y_state, 12);
    self.z_state = zp -% yp;
    self.z_state = std.math.rotl(u64, self.z_state, 44);
    return xp;
}

pub fn seedWithBuf(self: *RomuTrio, buf: [24]u8) void {
    const seed_buf = @as([3]u64, @bitCast(buf));
    self.x_state = seed_buf[0];
    self.y_state = seed_buf[1];
    self.z_state = seed_buf[2];
}

pub fn seed(self: *RomuTrio, init_s: u64) void {
    // RomuTrio requires 192-bits of seed.
    var gen = std.Random.SplitMix64.init(init_s);

    self.x_state = gen.next();
    self.y_state = gen.next();
    self.z_state = gen.next();
}

pub fn fill(self: *RomuTrio, buf: []u8) void {
    var i: usize = 0;
    const aligned_len = buf.len - (buf.len & 7);

    // Complete 8 byte segments.
    while (i < aligned_len) : (i += 8) {
        var n = self.next();
        comptime var j: usize = 0;
        inline while (j < 8) : (j += 1) {
            buf[i + j] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }

    // Remaining. (cuts the stream)
    if (i != buf.len) {
        var n = self.next();
        while (i < buf.len) : (i += 1) {
            buf[i] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
}

test "sequence" {
    // Unfortunately there does not seem to be an official test sequence.
    var r = RomuTrio.init(0);

    const seq = [_]u64{
        16294208416658607535,
        13964609475759908645,
        4703697494102998476,
        3425221541186733346,
        2285772463536419399,
        9454187757529463048,
        13695907680080547496,
        8328236714879408626,
        12323357569716880909,
        12375466223337721820,
    };

    for (seq) |s| {
        try std.testing.expectEqual(s, r.next());
    }
}

test fill {
    // Unfortunately there does not seem to be an official test sequence.
    var r = RomuTrio.init(0);

    const seq = [_]u64{
        16294208416658607535,
        13964609475759908645,
        4703697494102998476,
        3425221541186733346,
        2285772463536419399,
        9454187757529463048,
        13695907680080547496,
        8328236714879408626,
        12323357569716880909,
        12375466223337721820,
    };

    for (seq) |s| {
        var buf0: [8]u8 = undefined;
        var buf1: [7]u8 = undefined;
        std.mem.writeInt(u64, &buf0, s, .little);
        r.fill(&buf1);
        try std.testing.expect(std.mem.eql(u8, buf0[0..7], buf1[0..]));
    }
}

test "buf seeding test" {
    const buf0 = @as([24]u8, @bitCast([3]u64{ 16294208416658607535, 13964609475759908645, 4703697494102998476 }));
    const resulting_state = .{ .x = 16294208416658607535, .y = 13964609475759908645, .z = 4703697494102998476 };
    var r = RomuTrio.init(0);
    r.seedWithBuf(buf0);
    try std.testing.expect(r.x_state == resulting_state.x);
    try std.testing.expect(r.y_state == resulting_state.y);
    try std.testing.expect(r.z_state == resulting_state.z);
}
//! Sfc64 pseudo-random number generator from Practically Random.
//! Fastest engine of pracrand and smallest footprint.
//! See http://pracrand.sourceforge.net/

const std = @import("std");
const math = std.math;
const Sfc64 = @This();

a: u64 = undefined,
b: u64 = undefined,
c: u64 = undefined,
counter: u64 = undefined,

const Rotation = 24;
const RightShift = 11;
const LeftShift = 3;

pub fn init(init_s: u64) Sfc64 {
    var x = Sfc64{};

    x.seed(init_s);
    return x;
}

pub fn random(self: *Sfc64) std.Random {
    return std.Random.init(self, fill);
}

fn next(self: *Sfc64) u64 {
    const tmp = self.a +% self.b +% self.counter;
    self.counter += 1;
    self.a = self.b ^ (self.b >> RightShift);
    self.b = self.c +% (self.c << LeftShift);
    self.c = math.rotl(u64, self.c, Rotation) +% tmp;
    return tmp;
}

fn seed(self: *Sfc64, init_s: u64) void {
    self.a = init_s;
    self.b = init_s;
    self.c = init_s;
    self.counter = 1;
    var i: u32 = 0;
    while (i < 12) : (i += 1) {
        _ = self.next();
    }
}

pub fn fill(self: *Sfc64, buf: []u8) void {
    var i: usize = 0;
    const aligned_len = buf.len - (buf.len & 7);

    // Complete 8 byte segments.
    while (i < aligned_len) : (i += 8) {
        var n = self.next();
        comptime var j: usize = 0;
        inline while (j < 8) : (j += 1) {
            buf[i + j] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }

    // Remaining. (cuts the stream)
    if (i != buf.len) {
        var n = self.next();
        while (i < buf.len) : (i += 1) {
            buf[i] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
}

test "sequence" {
    // Unfortunately there does not seem to be an official test sequence.
    var r = Sfc64.init(0);

    const seq = [_]u64{
        0x3acfa029e3cc6041,
        0xf5b6515bf2ee419c,
        0x1259635894a29b61,
        0xb6ae75395f8ebd6,
        0x225622285ce302e2,
        0x520d28611395cb21,
        0xdb909c818901599d,
        0x8ffd195365216f57,
        0xe8c4ad5e258ac04a,
        0x8f8ef2c89fdb63ca,
        0xf9865b01d98d8e2f,
        0x46555871a65d08ba,
        0x66868677c6298fcd,
        0x2ce15a7e6329f57d,
        0xb2f1833ca91ca79,
        0x4b0890ac9bf453ca,
    };

    for (seq) |s| {
        try std.testing.expectEqual(s, r.next());
    }
}

test fill {
    // Unfortunately there does not seem to be an official test sequence.
    var r = Sfc64.init(0);

    const seq = [_]u64{
        0x3acfa029e3cc6041,
        0xf5b6515bf2ee419c,
        0x1259635894a29b61,
        0xb6ae75395f8ebd6,
        0x225622285ce302e2,
        0x520d28611395cb21,
        0xdb909c818901599d,
        0x8ffd195365216f57,
        0xe8c4ad5e258ac04a,
        0x8f8ef2c89fdb63ca,
        0xf9865b01d98d8e2f,
        0x46555871a65d08ba,
        0x66868677c6298fcd,
        0x2ce15a7e6329f57d,
        0xb2f1833ca91ca79,
        0x4b0890ac9bf453ca,
    };

    for (seq) |s| {
        var buf0: [8]u8 = undefined;
        var buf1: [7]u8 = undefined;
        std.mem.writeInt(u64, &buf0, s, .little);
        r.fill(&buf1);
        try std.testing.expect(std.mem.eql(u8, buf0[0..7], buf1[0..]));
    }
}
//! Generator to extend 64-bit seed values into longer sequences.
//!
//! The number of cycles is thus limited to 64-bits regardless of the engine, but this
//! is still plenty for practical purposes.

const SplitMix64 = @This();

s: u64,

pub fn init(seed: u64) SplitMix64 {
    return SplitMix64{ .s = seed };
}

pub fn next(self: *SplitMix64) u64 {
    self.s +%= 0x9e3779b97f4a7c15;

    var z = self.s;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}
const std = @import("../std.zig");
const math = std.math;
const Random = std.Random;
const DefaultPrng = Random.DefaultPrng;
const SplitMix64 = Random.SplitMix64;
const DefaultCsprng = Random.DefaultCsprng;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const SequentialPrng = struct {
    const Self = @This();
    next_value: u8,

    pub fn init() Self {
        return Self{
            .next_value = 0,
        };
    }

    pub fn random(self: *Self) Random {
        return Random.init(self, fill);
    }

    pub fn fill(self: *Self, buf: []u8) void {
        for (buf) |*b| {
            b.* = self.next_value;
        }
        self.next_value +%= 1;
    }
};

/// Do not use this PRNG! It is meant to be predictable, for the purposes of test reproducibility and coverage.
/// Its output is just a repeat of a user-specified byte pattern.
/// Name is a reference to this comic: https://dilbert.com/strip/2001-10-25
const Dilbert = struct {
    pattern: []const u8 = undefined,
    curr_idx: usize = 0,

    pub fn init(pattern: []const u8) !Dilbert {
        if (pattern.len == 0)
            return error.EmptyPattern;
        var self = Dilbert{};
        self.pattern = pattern;
        self.curr_idx = 0;
        return self;
    }

    pub fn random(self: *Dilbert) Random {
        return Random.init(self, fill);
    }

    pub fn fill(self: *Dilbert, buf: []u8) void {
        for (buf) |*byte| {
            byte.* = self.pattern[self.curr_idx];
            self.curr_idx = (self.curr_idx + 1) % self.pattern.len;
        }
    }

    test "Dilbert fill" {
        var r = try Dilbert.init("9nine");

        const seq = [_]u64{
            0x396E696E65396E69,
            0x6E65396E696E6539,
            0x6E696E65396E696E,
            0x65396E696E65396E,
            0x696E65396E696E65,
        };

        for (seq) |s| {
            var buf0: [8]u8 = undefined;
            var buf1: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf0, s, .big);
            r.fill(&buf1);
            try std.testing.expect(std.mem.eql(u8, buf0[0..], buf1[0..]));
        }
    }
};

test "Random int" {
    try testRandomInt();
    try comptime testRandomInt();
}
fn testRandomInt() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    try expect(random.int(u0) == 0);

    rng.next_value = 0;
    try expect(random.int(u1) == 0);
    try expect(random.int(u1) == 1);
    try expect(random.int(u2) == 2);
    try expect(random.int(u2) == 3);
    try expect(random.int(u2) == 0);

    rng.next_value = 0xff;
    try expect(random.int(u8) == 0xff);
    rng.next_value = 0x11;
    try expect(random.int(u8) == 0x11);

    rng.next_value = 0xff;
    try expect(random.int(u32) == 0xffffffff);
    rng.next_value = 0x11;
    try expect(random.int(u32) == 0x11111111);

    rng.next_value = 0xff;
    try expect(random.int(i32) == -1);
    rng.next_value = 0x11;
    try expect(random.int(i32) == 0x11111111);

    rng.next_value = 0xff;
    try expect(random.int(i8) == -1);
    rng.next_value = 0x11;
    try expect(random.int(i8) == 0x11);

    rng.next_value = 0xff;
    try expect(random.int(u33) == 0x1ffffffff);
    rng.next_value = 0xff;
    try expect(random.int(i1) == -1);
    rng.next_value = 0xff;
    try expect(random.int(i2) == -1);
    rng.next_value = 0xff;
    try expect(random.int(i33) == -1);
}

test "Random boolean" {
    try testRandomBoolean();
    try comptime testRandomBoolean();
}
fn testRandomBoolean() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    try expect(random.boolean() == false);
    try expect(random.boolean() == true);
    try expect(random.boolean() == false);
    try expect(random.boolean() == true);
}

test "Random enum" {
    try testRandomEnumValue();
    try comptime testRandomEnumValue();
}
fn testRandomEnumValue() !void {
    const TestEnum = enum {
        First,
        Second,
        Third,
    };
    var rng = SequentialPrng.init();
    const random = rng.random();
    rng.next_value = 0;
    try expect(random.enumValue(TestEnum) == TestEnum.First);
    try expect(random.enumValue(TestEnum) == TestEnum.First);
    try expect(random.enumValue(TestEnum) == TestEnum.First);
}

test "Random intLessThan" {
    @setEvalBranchQuota(10000);
    try testRandomIntLessThan();
    try comptime testRandomIntLessThan();
}
fn testRandomIntLessThan() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    rng.next_value = 0xff;
    try expect(random.uintLessThan(u8, 4) == 3);
    try expect(rng.next_value == 0);
    try expect(random.uintLessThan(u8, 4) == 0);
    try expect(rng.next_value == 1);

    rng.next_value = 0;
    try expect(random.uintLessThan(u64, 32) == 0);

    // trigger the bias rejection code path
    rng.next_value = 0;
    try expect(random.uintLessThan(u8, 3) == 0);
    // verify we incremented twice
    try expect(rng.next_value == 2);

    rng.next_value = 0xff;
    try expect(random.intRangeLessThan(u8, 0, 0x80) == 0x7f);
    rng.next_value = 0xff;
    try expect(random.intRangeLessThan(u8, 0x7f, 0xff) == 0xfe);

    rng.next_value = 0xff;
    try expect(random.intRangeLessThan(i8, 0, 0x40) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.intRangeLessThan(i8, -0x40, 0x40) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.intRangeLessThan(i8, -0x80, 0) == -1);

    rng.next_value = 0xff;
    try expect(random.intRangeLessThan(i3, -4, 0) == -1);
    rng.next_value = 0xff;
    try expect(random.intRangeLessThan(i3, -2, 2) == 1);
}

test "Random intAtMost" {
    @setEvalBranchQuota(10000);
    try testRandomIntAtMost();
    try comptime testRandomIntAtMost();
}
fn testRandomIntAtMost() !void {
    var rng = SequentialPrng.init();
    const random = rng.random();

    rng.next_value = 0xff;
    try expect(random.uintAtMost(u8, 3) == 3);
    try expect(rng.next_value == 0);
    try expect(random.uintAtMost(u8, 3) == 0);

    // trigger the bias rejection code path
    rng.next_value = 0;
    try expect(random.uintAtMost(u8, 2) == 0);
    // verify we incremented twice
    try expect(rng.next_value == 2);

    rng.next_value = 0xff;
    try expect(random.intRangeAtMost(u8, 0, 0x7f) == 0x7f);
    rng.next_value = 0xff;
    try expect(random.intRangeAtMost(u8, 0x7f, 0xfe) == 0xfe);

    rng.next_value = 0xff;
    try expect(random.intRangeAtMost(i8, 0, 0x3f) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.intRangeAtMost(i8, -0x40, 0x3f) == 0x3f);
    rng.next_value = 0xff;
    try expect(random.intRangeAtMost(i8, -0x80, -1) == -1);

    rng.next_value = 0xff;
    try expect(random.intRangeAtMost(i3, -4, -1) == -1);
    rng.next_value = 0xff;
    try expect(random.intRangeAtMost(i3, -2, 1) == 1);

    try expect(random.uintAtMost(u0, 0) == 0);
}

test "Random Biased" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();
    // Not thoroughly checking the logic here.
    // Just want to execute all the paths with different types.

    try expect(random.uintLessThanBiased(u1, 1) == 0);
    try expect(random.uintLessThanBiased(u32, 10) < 10);
    try expect(random.uintLessThanBiased(u64, 20) < 20);

    try expect(random.uintAtMostBiased(u0, 0) == 0);
    try expect(random.uintAtMostBiased(u1, 0) <= 0);
    try expect(random.uintAtMostBiased(u32, 10) <= 10);
    try expect(random.uintAtMostBiased(u64, 20) <= 20);

    try expect(random.intRangeLessThanBiased(u1, 0, 1) == 0);
    try expect(random.intRangeLessThanBiased(i1, -1, 0) == -1);
    try expect(random.intRangeLessThanBiased(u32, 10, 20) >= 10);
    try expect(random.intRangeLessThanBiased(i32, 10, 20) >= 10);
    try expect(random.intRangeLessThanBiased(u64, 20, 40) >= 20);
    try expect(random.intRangeLessThanBiased(i64, 20, 40) >= 20);

    // uncomment for broken module error:
    //expect(random.intRangeAtMostBiased(u0, 0, 0) == 0);
    try expect(random.intRangeAtMostBiased(u1, 0, 1) >= 0);
    try expect(random.intRangeAtMostBiased(i1, -1, 0) >= -1);
    try expect(random.intRangeAtMostBiased(u32, 10, 20) >= 10);
    try expect(random.intRangeAtMostBiased(i32, 10, 20) >= 10);
    try expect(random.intRangeAtMostBiased(u64, 20, 40) >= 20);
    try expect(random.intRangeAtMostBiased(i64, 20, 40) >= 20);
}

test "splitmix64 sequence" {
    var r = SplitMix64.init(0xaeecf86f7878dd75);

    const seq = [_]u64{
        0x5dbd39db0178eb44,
        0xa9900fb66b397da3,
        0x5c1a28b1aeebcf5c,
        0x64a963238f776912,
        0xc6d4177b21d1c0ab,
        0xb2cbdbdb5ea35394,
    };

    for (seq) |s| {
        try expect(s == r.next());
    }
}

// Actual Random helper function tests, pcg engine is assumed correct.
test "Random float correctness" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const val1 = random.float(f32);
        try expect(val1 >= 0.0);
        try expect(val1 < 1.0);

        const val2 = random.float(f64);
        try expect(val2 >= 0.0);
        try expect(val2 < 1.0);
    }
}

// Check the "astronomically unlikely" code paths.
test "Random float coverage" {
    var prng = try Dilbert.init(&[_]u8{0});
    const random = prng.random();

    const rand_f64 = random.float(f64);
    const rand_f32 = random.float(f32);

    try expect(rand_f32 == 0.0);
    try expect(rand_f64 == 0.0);
}

test "Random float chi-square goodness of fit" {
    const num_numbers = 100000;
    const num_buckets = 1000;

    var f32_hist = std.AutoHashMap(u32, u32).init(std.testing.allocator);
    defer f32_hist.deinit();
    var f64_hist = std.AutoHashMap(u64, u32).init(std.testing.allocator);
    defer f64_hist.deinit();

    var prng = DefaultPrng.init(0);
    const random = prng.random();

    var i: usize = 0;
    while (i < num_numbers) : (i += 1) {
        const rand_f32 = random.float(f32);
        const rand_f64 = random.float(f64);
        const f32_put = try f32_hist.getOrPut(@as(u32, @intFromFloat(rand_f32 * @as(f32, @floatFromInt(num_buckets)))));
        if (f32_put.found_existing) {
            f32_put.value_ptr.* += 1;
        } else {
            f32_put.value_ptr.* = 1;
        }
        const f64_put = try f64_hist.getOrPut(@as(u32, @intFromFloat(rand_f64 * @as(f64, @floatFromInt(num_buckets)))));
        if (f64_put.found_existing) {
            f64_put.value_ptr.* += 1;
        } else {
            f64_put.value_ptr.* = 1;
        }
    }

    var f32_total_variance: f64 = 0;
    var f64_total_variance: f64 = 0;

    {
        var j: u32 = 0;
        while (j < num_buckets) : (j += 1) {
            const count = @as(f64, @floatFromInt((if (f32_hist.get(j)) |v| v else 0)));
            const expected = @as(f64, @floatFromInt(num_numbers)) / @as(f64, @floatFromInt(num_buckets));
            const delta = count - expected;
            const variance = (delta * delta) / expected;
            f32_total_variance += variance;
        }
    }

    {
        var j: u64 = 0;
        while (j < num_buckets) : (j += 1) {
            const count = @as(f64, @floatFromInt((if (f64_hist.get(j)) |v| v else 0)));
            const expected = @as(f64, @floatFromInt(num_numbers)) / @as(f64, @floatFromInt(num_buckets));
            const delta = count - expected;
            const variance = (delta * delta) / expected;
            f64_total_variance += variance;
        }
    }

    // Accept p-values >= 0.05.
    // Critical value is calculated by opening a Python interpreter and running:
    // scipy.stats.chi2.isf(0.05, num_buckets - 1)
    const critical_value = 1073.6426506574246;
    try expect(f32_total_variance < critical_value);
    try expect(f64_total_variance < critical_value);
}

test "Random shuffle" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();

    var seq = [_]u8{ 0, 1, 2, 3, 4 };
    var seen = [_]bool{false} ** 5;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        random.shuffle(u8, seq[0..]);
        seen[seq[0]] = true;
        try expect(sumArray(seq[0..]) == 10);
    }

    // we should see every entry at the head at least once
    for (seen) |e| {
        try expect(e == true);
    }
}

fn sumArray(s: []const u8) u32 {
    var r: u32 = 0;
    for (s) |e|
        r += e;
    return r;
}

test "Random range" {
    var prng = DefaultPrng.init(0);
    const random = prng.random();

    try testRange(random, -4, 3);
    try testRange(random, -4, -1);
    try testRange(random, 10, 14);
    try testRange(random, -0x80, 0x7f);
}

fn testRange(r: Random, start: i8, end: i8) !void {
    try testRangeBias(r, start, end, true);
    try testRangeBias(r, start, end, false);
}
fn testRangeBias(r: Random, start: i8, end: i8, biased: bool) !void {
    const count = @as(usize, @intCast(@as(i32, end) - @as(i32, start)));
    var values_buffer = [_]bool{false} ** 0x100;
    const values = values_buffer[0..count];
    var i: usize = 0;
    while (i < count) {
        const value: i32 = if (biased) r.intRangeLessThanBiased(i8, start, end) else r.intRangeLessThan(i8, start, end);
        const index = @as(usize, @intCast(value - start));
        if (!values[index]) {
            i += 1;
            values[index] = true;
        }
    }
}

test "CSPRNG" {
    var secret_seed: [DefaultCsprng.secret_seed_length]u8 = undefined;
    std.crypto.random.bytes(&secret_seed);
    var csprng = DefaultCsprng.init(secret_seed);
    const random = csprng.random();
    const a = random.int(u64);
    const b = random.int(u64);
    const c = random.int(u64);
    try expect(a ^ b ^ c != 0);
}

test "Random weightedIndex" {
    // Make sure weightedIndex works for various integers and floats
    inline for (.{ u64, i4, f32, f64 }) |T| {
        var prng = DefaultPrng.init(0);
        const random = prng.random();

        const proportions = [_]T{ 2, 1, 1, 2 };
        var counts = [_]f64{ 0, 0, 0, 0 };

        const n_trials: u64 = 10_000;
        var i: usize = 0;
        while (i < n_trials) : (i += 1) {
            const pick = random.weightedIndex(T, &proportions);
            counts[pick] += 1;
        }

        // We expect the first and last counts to be roughly 2x the second and third
        const approxEqRel = std.math.approxEqRel;
        // Define "roughly" to be within 10%
        const tolerance = 0.1;
        try std.testing.expect(approxEqRel(f64, counts[0], counts[1] * 2, tolerance));
        try std.testing.expect(approxEqRel(f64, counts[1], counts[2], tolerance));
        try std.testing.expect(approxEqRel(f64, counts[2] * 2, counts[3], tolerance));
    }
}
//! Xoroshiro128+ - http://xoroshiro.di.unimi.it/
//!
//! PRNG

const std = @import("std");
const math = std.math;
const Xoroshiro128 = @This();

s: [2]u64,

pub fn init(init_s: u64) Xoroshiro128 {
    var x = Xoroshiro128{ .s = undefined };

    x.seed(init_s);
    return x;
}

pub fn random(self: *Xoroshiro128) std.Random {
    return std.Random.init(self, fill);
}

pub fn next(self: *Xoroshiro128) u64 {
    const s0 = self.s[0];
    var s1 = self.s[1];
    const r = s0 +% s1;

    s1 ^= s0;
    self.s[0] = math.rotl(u64, s0, @as(u8, 55)) ^ s1 ^ (s1 << 14);
    self.s[1] = math.rotl(u64, s1, @as(u8, 36));

    return r;
}

// Skip 2^64 places ahead in the sequence
pub fn jump(self: *Xoroshiro128) void {
    var s0: u64 = 0;
    var s1: u64 = 0;

    const table = [_]u64{
        0xbeac0467eba5facb,
        0xd86b048b86aa9922,
    };

    inline for (table) |entry| {
        var b: usize = 0;
        while (b < 64) : (b += 1) {
            if ((entry & (@as(u64, 1) << @as(u6, @intCast(b)))) != 0) {
                s0 ^= self.s[0];
                s1 ^= self.s[1];
            }
            _ = self.next();
        }
    }

    self.s[0] = s0;
    self.s[1] = s1;
}

pub fn seed(self: *Xoroshiro128, init_s: u64) void {
    // Xoroshiro requires 128-bits of seed.
    var gen = std.Random.SplitMix64.init(init_s);

    self.s[0] = gen.next();
    self.s[1] = gen.next();
}

pub fn fill(self: *Xoroshiro128, buf: []u8) void {
    var i: usize = 0;
    const aligned_len = buf.len - (buf.len & 7);

    // Complete 8 byte segments.
    while (i < aligned_len) : (i += 8) {
        var n = self.next();
        comptime var j: usize = 0;
        inline while (j < 8) : (j += 1) {
            buf[i + j] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }

    // Remaining. (cuts the stream)
    if (i != buf.len) {
        var n = self.next();
        while (i < buf.len) : (i += 1) {
            buf[i] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
}

test "sequence" {
    var r = Xoroshiro128.init(0);
    r.s[0] = 0xaeecf86f7878dd75;
    r.s[1] = 0x01cd153642e72622;

    const seq1 = [_]u64{
        0xb0ba0da5bb600397,
        0x18a08afde614dccc,
        0xa2635b956a31b929,
        0xabe633c971efa045,
        0x9ac19f9706ca3cac,
        0xf62b426578c1e3fb,
    };

    for (seq1) |s| {
        try std.testing.expect(s == r.next());
    }

    r.jump();

    const seq2 = [_]u64{
        0x95344a13556d3e22,
        0xb4fb32dafa4d00df,
        0xb2011d9ccdcfe2dd,
        0x05679a9b2119b908,
        0xa860a1da7c9cd8a0,
        0x658a96efe3f86550,
    };

    for (seq2) |s| {
        try std.testing.expect(s == r.next());
    }
}

test fill {
    var r = Xoroshiro128.init(0);
    r.s[0] = 0xaeecf86f7878dd75;
    r.s[1] = 0x01cd153642e72622;

    const seq = [_]u64{
        0xb0ba0da5bb600397,
        0x18a08afde614dccc,
        0xa2635b956a31b929,
        0xabe633c971efa045,
        0x9ac19f9706ca3cac,
        0xf62b426578c1e3fb,
    };

    for (seq) |s| {
        var buf0: [8]u8 = undefined;
        var buf1: [7]u8 = undefined;
        std.mem.writeInt(u64, &buf0, s, .little);
        r.fill(&buf1);
        try std.testing.expect(std.mem.eql(u8, buf0[0..7], buf1[0..]));
    }
}
//! Xoshiro256++ - http://xoroshiro.di.unimi.it/
//!
//! PRNG

const std = @import("std");
const math = std.math;
const Xoshiro256 = @This();

s: [4]u64,

pub fn init(init_s: u64) Xoshiro256 {
    var x = Xoshiro256{
        .s = undefined,
    };

    x.seed(init_s);
    return x;
}

pub fn random(self: *Xoshiro256) std.Random {
    return std.Random.init(self, fill);
}

pub fn next(self: *Xoshiro256) u64 {
    const r = math.rotl(u64, self.s[0] +% self.s[3], 23) +% self.s[0];

    const t = self.s[1] << 17;

    self.s[2] ^= self.s[0];
    self.s[3] ^= self.s[1];
    self.s[1] ^= self.s[2];
    self.s[0] ^= self.s[3];

    self.s[2] ^= t;

    self.s[3] = math.rotl(u64, self.s[3], 45);

    return r;
}

// Skip 2^128 places ahead in the sequence
pub fn jump(self: *Xoshiro256) void {
    var s: u256 = 0;

    var table: u256 = 0x39abdc4529b1661ca9582618e03fc9aad5a61266f0c9392c180ec6d33cfd0aba;

    while (table != 0) : (table >>= 1) {
        if (@as(u1, @truncate(table)) != 0) {
            s ^= @as(u256, @bitCast(self.s));
        }
        _ = self.next();
    }

    self.s = @as([4]u64, @bitCast(s));
}

pub fn seed(self: *Xoshiro256, init_s: u64) void {
    // Xoshiro requires 256-bits of seed.
    var gen = std.Random.SplitMix64.init(init_s);

    self.s[0] = gen.next();
    self.s[1] = gen.next();
    self.s[2] = gen.next();
    self.s[3] = gen.next();
}

pub fn fill(self: *Xoshiro256, buf: []u8) void {
    var i: usize = 0;
    const aligned_len = buf.len - (buf.len & 7);

    // Complete 8 byte segments.
    while (i < aligned_len) : (i += 8) {
        var n = self.next();
        comptime var j: usize = 0;
        inline while (j < 8) : (j += 1) {
            buf[i + j] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }

    // Remaining. (cuts the stream)
    if (i != buf.len) {
        var n = self.next();
        while (i < buf.len) : (i += 1) {
            buf[i] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
}

test "sequence" {
    if (@import("builtin").zig_backend == .stage2_c) return error.SkipZigTest;

    var r = Xoshiro256.init(0);

    const seq1 = [_]u64{
        0x53175d61490b23df,
        0x61da6f3dc380d507,
        0x5c0fdf91ec9a7bfc,
        0x02eebf8c3bbe5e1a,
        0x7eca04ebaf4a5eea,
        0x0543c37757f08d9a,
    };

    for (seq1) |s| {
        try std.testing.expect(s == r.next());
    }

    r.jump();

    const seq2 = [_]u64{
        0xae1db5c5e27807be,
        0xb584c6a7fd8709fe,
        0xc46a0ee9330fb6e,
        0xdc0c9606f49ed76e,
        0x1f5bb6540f6651fb,
        0x72fa2ca734601488,
    };

    for (seq2) |s| {
        try std.testing.expect(s == r.next());
    }
}

test fill {
    var r = Xoshiro256.init(0);

    const seq = [_]u64{
        0x53175d61490b23df,
        0x61da6f3dc380d507,
        0x5c0fdf91ec9a7bfc,
        0x02eebf8c3bbe5e1a,
        0x7eca04ebaf4a5eea,
        0x0543c37757f08d9a,
    };

    for (seq) |s| {
        var buf0: [8]u8 = undefined;
        var buf1: [7]u8 = undefined;
        std.mem.writeInt(u64, &buf0, s, .little);
        r.fill(&buf1);
        try std.testing.expect(std.mem.eql(u8, buf0[0..7], buf1[0..]));
    }
}
//! Implements [ZIGNOR][1] (Jurgen A. Doornik, 2005, Nuffield College, Oxford).
//!
//! [1]: https://www.doornik.com/research/ziggurat.pdf
//!
//! rust/rand used as a reference;
//!
//! NOTE: This seems interesting but reference code is a bit hard to grok:
//! https://sbarral.github.io/etf.

const std = @import("../std.zig");
const builtin = @import("builtin");
const math = std.math;
const Random = std.Random;

pub fn next_f64(random: Random, comptime tables: ZigTable) f64 {
    while (true) {
        // We manually construct a float from parts as we can avoid an extra random lookup here by
        // using the unused exponent for the lookup table entry.
        const bits = random.int(u64);
        const i = @as(usize, @as(u8, @truncate(bits)));

        const u = blk: {
            if (tables.is_symmetric) {
                // Generate a value in the range [2, 4) and scale into [-1, 1)
                const repr = ((0x3ff + 1) << 52) | (bits >> 12);
                break :blk @as(f64, @bitCast(repr)) - 3.0;
            } else {
                // Generate a value in the range [1, 2) and scale into (0, 1)
                const repr = (0x3ff << 52) | (bits >> 12);
                break :blk @as(f64, @bitCast(repr)) - (1.0 - math.floatEps(f64) / 2.0);
            }
        };

        const x = u * tables.x[i];
        const test_x = if (tables.is_symmetric) @abs(x) else x;

        // equivalent to |u| < tables.x[i+1] / tables.x[i] (or u < tables.x[i+1] / tables.x[i])
        if (test_x < tables.x[i + 1]) {
            return x;
        }

        if (i == 0) {
            return tables.zero_case(random, u);
        }

        // equivalent to f1 + DRanU() * (f0 - f1) < 1
        if (tables.f[i + 1] + (tables.f[i] - tables.f[i + 1]) * random.float(f64) < tables.pdf(x)) {
            return x;
        }
    }
}

pub const ZigTable = struct {
    r: f64,
    x: [257]f64,
    f: [257]f64,

    // probability density function used as a fallback
    pdf: fn (f64) f64,
    // whether the distribution is symmetric
    is_symmetric: bool,
    // fallback calculation in the case we are in the 0 block
    zero_case: fn (Random, f64) f64,
};

// zigNorInit
pub fn ZigTableGen(
    comptime is_symmetric: bool,
    comptime r: f64,
    comptime v: f64,
    comptime f: fn (f64) f64,
    comptime f_inv: fn (f64) f64,
    comptime zero_case: fn (Random, f64) f64,
) ZigTable {
    var tables: ZigTable = undefined;

    tables.is_symmetric = is_symmetric;
    tables.r = r;
    tables.pdf = f;
    tables.zero_case = zero_case;

    tables.x[0] = v / f(r);
    tables.x[1] = r;

    for (tables.x[2..256], 0..) |*entry, i| {
        const last = tables.x[2 + i - 1];
        entry.* = f_inv(v / last + f(last));
    }
    tables.x[256] = 0;

    for (tables.f[0..], 0..) |*entry, i| {
        entry.* = f(tables.x[i]);
    }

    return tables;
}

// N(0, 1)
pub const NormDist = blk: {
    @setEvalBranchQuota(30000);
    break :blk ZigTableGen(true, norm_r, norm_v, norm_f, norm_f_inv, norm_zero_case);
};

pub const norm_r = 3.6541528853610088;
pub const norm_v = 0.00492867323399;

pub fn norm_f(x: f64) f64 {
    return @exp(-x * x / 2.0);
}
pub fn norm_f_inv(y: f64) f64 {
    return @sqrt(-2.0 * @log(y));
}
pub fn norm_zero_case(random: Random, u: f64) f64 {
    var x: f64 = 1;
    var y: f64 = 0;

    while (-2.0 * y < x * x) {
        x = @log(random.float(f64)) / norm_r;
        y = @log(random.float(f64));
    }

    if (u < 0) {
        return x - norm_r;
    } else {
        return norm_r - x;
    }
}

test "normal dist smoke test" {
    // Hardcode 0 as the seed because it's possible a seed exists that fails
    // this test.
    var prng = Random.DefaultPrng.init(0);
    const random = prng.random();

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        _ = random.floatNorm(f64);
    }
}

// Exp(1)
pub const ExpDist = blk: {
    @setEvalBranchQuota(30000);
    break :blk ZigTableGen(false, exp_r, exp_v, exp_f, exp_f_inv, exp_zero_case);
};

pub const exp_r = 7.69711747013104972;
pub const exp_v = 0.0039496598225815571993;

pub fn exp_f(x: f64) f64 {
    return @exp(-x);
}
pub fn exp_f_inv(y: f64) f64 {
    return -@log(y);
}
pub fn exp_zero_case(random: Random, _: f64) f64 {
    return exp_r - @log(random.float(f64));
}

test "exp dist smoke test" {
    var prng = Random.DefaultPrng.init(0);
    const random = prng.random();

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        _ = random.floatExp(f64);
    }
}

test {
    _ = NormDist;
}
//! This ring buffer stores read and write indices while being able to utilise
//! the full backing slice by incrementing the indices modulo twice the slice's
//! length and reducing indices modulo the slice's length on slice access. This
//! means that whether the ring buffer is full or empty can be distinguished by
//! looking at the difference between the read and write indices without adding
//! an extra boolean flag or having to reserve a slot in the buffer.
//!
//! This ring buffer has not been implemented with thread safety in mind, and
//! therefore should not be assumed to be suitable for use cases involving
//! separate reader and writer threads.

const Allocator = @import("std").mem.Allocator;
const assert = @import("std").debug.assert;
const copyForwards = @import("std").mem.copyForwards;

const RingBuffer = @This();

data: []u8,
read_index: usize,
write_index: usize,

pub const Error = error{ Full, ReadLengthInvalid };

/// Allocate a new `RingBuffer`; `deinit()` should be called to free the buffer.
pub fn init(allocator: Allocator, capacity: usize) Allocator.Error!RingBuffer {
    const bytes = try allocator.alloc(u8, capacity);
    return RingBuffer{
        .data = bytes,
        .write_index = 0,
        .read_index = 0,
    };
}

/// Free the data backing a `RingBuffer`; must be passed the same `Allocator` as
/// `init()`.
pub fn deinit(self: *RingBuffer, allocator: Allocator) void {
    allocator.free(self.data);
    self.* = undefined;
}

/// Returns `index` modulo the length of the backing slice.
pub fn mask(self: RingBuffer, index: usize) usize {
    return index % self.data.len;
}

/// Returns `index` modulo twice the length of the backing slice.
pub fn mask2(self: RingBuffer, index: usize) usize {
    return index % (2 * self.data.len);
}

/// Write `byte` into the ring buffer. Returns `error.Full` if the ring
/// buffer is full.
pub fn write(self: *RingBuffer, byte: u8) Error!void {
    if (self.isFull()) return error.Full;
    self.writeAssumeCapacity(byte);
}

/// Write `byte` into the ring buffer. If the ring buffer is full, the
/// oldest byte is overwritten.
pub fn writeAssumeCapacity(self: *RingBuffer, byte: u8) void {
    self.data[self.mask(self.write_index)] = byte;
    self.write_index = self.mask2(self.write_index + 1);
}

/// Write `bytes` into the ring buffer. Returns `error.Full` if the ring
/// buffer does not have enough space, without writing any data.
/// Uses memcpy and so `bytes` must not overlap ring buffer data.
pub fn writeSlice(self: *RingBuffer, bytes: []const u8) Error!void {
    if (self.len() + bytes.len > self.data.len) return error.Full;
    self.writeSliceAssumeCapacity(bytes);
}

/// Write `bytes` into the ring buffer. If there is not enough space, older
/// bytes will be overwritten.
/// Uses memcpy and so `bytes` must not overlap ring buffer data.
pub fn writeSliceAssumeCapacity(self: *RingBuffer, bytes: []const u8) void {
    assert(bytes.len <= self.data.len);
    const data_start = self.mask(self.write_index);
    const part1_data_end = @min(data_start + bytes.len, self.data.len);
    const part1_len = part1_data_end - data_start;
    @memcpy(self.data[data_start..part1_data_end], bytes[0..part1_len]);

    const remaining = bytes.len - part1_len;
    const to_write = @min(remaining, remaining % self.data.len + self.data.len);
    const part2_bytes_start = bytes.len - to_write;
    const part2_bytes_end = @min(part2_bytes_start + self.data.len, bytes.len);
    const part2_len = part2_bytes_end - part2_bytes_start;
    @memcpy(self.data[0..part2_len], bytes[part2_bytes_start..part2_bytes_end]);
    if (part2_bytes_end != bytes.len) {
        const part3_len = bytes.len - part2_bytes_end;
        @memcpy(self.data[0..part3_len], bytes[part2_bytes_end..bytes.len]);
    }
    self.write_index = self.mask2(self.write_index + bytes.len);
}

/// Write `bytes` into the ring buffer. Returns `error.Full` if the ring
/// buffer does not have enough space, without writing any data.
/// Uses copyForwards and can write slices from this RingBuffer into itself.
pub fn writeSliceForwards(self: *RingBuffer, bytes: []const u8) Error!void {
    if (self.len() + bytes.len > self.data.len) return error.Full;
    self.writeSliceForwardsAssumeCapacity(bytes);
}

/// Write `bytes` into the ring buffer. If there is not enough space, older
/// bytes will be overwritten.
/// Uses copyForwards and can write slices from this RingBuffer into itself.
pub fn writeSliceForwardsAssumeCapacity(self: *RingBuffer, bytes: []const u8) void {
    assert(bytes.len <= self.data.len);
    const data_start = self.mask(self.write_index);
    const part1_data_end = @min(data_start + bytes.len, self.data.len);
    const part1_len = part1_data_end - data_start;
    copyForwards(u8, self.data[data_start..], bytes[0..part1_len]);

    const remaining = bytes.len - part1_len;
    const to_write = @min(remaining, remaining % self.data.len + self.data.len);
    const part2_bytes_start = bytes.len - to_write;
    const part2_bytes_end = @min(part2_bytes_start + self.data.len, bytes.len);
    copyForwards(u8, self.data[0..], bytes[part2_bytes_start..part2_bytes_end]);
    if (part2_bytes_end != bytes.len)
        copyForwards(u8, self.data[0..], bytes[part2_bytes_end..bytes.len]);
    self.write_index = self.mask2(self.write_index + bytes.len);
}

/// Consume a byte from the ring buffer and return it. Returns `null` if the
/// ring buffer is empty.
pub fn read(self: *RingBuffer) ?u8 {
    if (self.isEmpty()) return null;
    return self.readAssumeLength();
}

/// Consume a byte from the ring buffer and return it; asserts that the buffer
/// is not empty.
pub fn readAssumeLength(self: *RingBuffer) u8 {
    assert(!self.isEmpty());
    const byte = self.data[self.mask(self.read_index)];
    self.read_index = self.mask2(self.read_index + 1);
    return byte;
}

/// Reads first `length` bytes written to the ring buffer into `dest`; Returns
/// Error.ReadLengthInvalid if length greater than ring or dest length
/// Uses memcpy and so `dest` must not overlap ring buffer data.
pub fn readFirst(self: *RingBuffer, dest: []u8, length: usize) Error!void {
    if (length > self.len() or length > dest.len) return error.ReadLengthInvalid;
    self.readFirstAssumeLength(dest, length);
}

/// Reads first `length` bytes written to the ring buffer into `dest`;
/// Asserts that length not greater than ring buffer or dest length
/// Uses memcpy and so `dest` must not overlap ring buffer data.
pub fn readFirstAssumeLength(self: *RingBuffer, dest: []u8, length: usize) void {
    assert(length <= self.len() and length <= dest.len);
    const slice = self.sliceAt(self.read_index, length);
    slice.copyTo(dest);
    self.read_index = self.mask2(self.read_index + length);
}

/// Reads last `length` bytes written to the ring buffer into `dest`; Returns
/// Error.ReadLengthInvalid if length greater than ring or dest length
/// Uses memcpy and so `dest` must not overlap ring buffer data.
/// Reduces write index by `length`.
pub fn readLast(self: *RingBuffer, dest: []u8, length: usize) Error!void {
    if (length > self.len() or length > dest.len) return error.ReadLengthInvalid;
    self.readLastAssumeLength(dest, length);
}

/// Reads last `length` bytes written to the ring buffer into `dest`;
/// Asserts that length not greater than ring buffer or dest length
/// Uses memcpy and so `dest` must not overlap ring buffer data.
/// Reduces write index by `length`.
pub fn readLastAssumeLength(self: *RingBuffer, dest: []u8, length: usize) void {
    assert(length <= self.len() and length <= dest.len);
    const slice = self.sliceLast(length);
    slice.copyTo(dest);
    self.write_index = if (self.write_index >= self.data.len)
        self.write_index - length
    else
        self.mask(self.write_index + self.data.len - length);
}

/// Returns `true` if the ring buffer is empty and `false` otherwise.
pub fn isEmpty(self: RingBuffer) bool {
    return self.write_index == self.read_index;
}

/// Returns `true` if the ring buffer is full and `false` otherwise.
pub fn isFull(self: RingBuffer) bool {
    return self.mask2(self.write_index + self.data.len) == self.read_index;
}

/// Returns the length of data available for reading
pub fn len(self: RingBuffer) usize {
    const wrap_offset = 2 * self.data.len * @intFromBool(self.write_index < self.read_index);
    const adjusted_write_index = self.write_index + wrap_offset;
    return adjusted_write_index - self.read_index;
}

/// A `Slice` represents a region of a ring buffer. The region is split into two
/// sections as the ring buffer data will not be contiguous if the desired
/// region wraps to the start of the backing slice.
pub const Slice = struct {
    first: []u8,
    second: []u8,

    /// Copy data from `self` into `dest`
    pub fn copyTo(self: Slice, dest: []u8) void {
        @memcpy(dest[0..self.first.len], self.first);
        @memcpy(dest[self.first.len..][0..self.second.len], self.second);
    }
};

/// Returns a `Slice` for the region of the ring buffer starting at
/// `self.mask(start_unmasked)` with the specified length.
pub fn sliceAt(self: RingBuffer, start_unmasked: usize, length: usize) Slice {
    assert(length <= self.data.len);
    const slice1_start = self.mask(start_unmasked);
    const slice1_end = @min(self.data.len, slice1_start + length);
    const slice1 = self.data[slice1_start..slice1_end];
    const slice2 = self.data[0 .. length - slice1.len];
    return Slice{
        .first = slice1,
        .second = slice2,
    };
}

/// Returns a `Slice` for the last `length` bytes written to the ring buffer.
/// Does not check that any bytes have been written into the region.
pub fn sliceLast(self: RingBuffer, length: usize) Slice {
    return self.sliceAt(self.write_index + self.data.len - length, length);
}
const std = @import("std.zig");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const Allocator = std.mem.Allocator;

// Imagine that `fn at(self: *Self, index: usize) &T` is a customer asking for a box
// from a warehouse, based on a flat array, boxes ordered from 0 to N - 1.
// But the warehouse actually stores boxes in shelves of increasing powers of 2 sizes.
// So when the customer requests a box index, we have to translate it to shelf index
// and box index within that shelf. Illustration:
//
// customer indexes:
// shelf 0:  0
// shelf 1:  1  2
// shelf 2:  3  4  5  6
// shelf 3:  7  8  9 10 11 12 13 14
// shelf 4: 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
// shelf 5: 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62
// ...
//
// warehouse indexes:
// shelf 0:  0
// shelf 1:  0  1
// shelf 2:  0  1  2  3
// shelf 3:  0  1  2  3  4  5  6  7
// shelf 4:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
// shelf 5:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
// ...
//
// With this arrangement, here are the equations to get the shelf index and
// box index based on customer box index:
//
// shelf_index = floor(log2(customer_index + 1))
// shelf_count = ceil(log2(box_count + 1))
// box_index = customer_index + 1 - 2 ** shelf
// shelf_size = 2 ** shelf_index
//
// Now we complicate it a little bit further by adding a preallocated shelf, which must be
// a power of 2:
// prealloc=4
//
// customer indexes:
// prealloc:  0  1  2  3
//  shelf 0:  4  5  6  7  8  9 10 11
//  shelf 1: 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27
//  shelf 2: 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59
// ...
//
// warehouse indexes:
// prealloc:  0  1  2  3
//  shelf 0:  0  1  2  3  4  5  6  7
//  shelf 1:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
//  shelf 2:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
// ...
//
// Now the equations are:
//
// shelf_index = floor(log2(customer_index + prealloc)) - log2(prealloc) - 1
// shelf_count = ceil(log2(box_count + prealloc)) - log2(prealloc) - 1
// box_index = customer_index + prealloc - 2 ** (log2(prealloc) + 1 + shelf)
// shelf_size = prealloc * 2 ** (shelf_index + 1)

/// This is a stack data structure where pointers to indexes have the same lifetime as the data structure
/// itself, unlike ArrayList where append() invalidates all existing element pointers.
/// The tradeoff is that elements are not guaranteed to be contiguous. For that, use ArrayList.
/// Note however that most elements are contiguous, making this data structure cache-friendly.
///
/// Because it never has to copy elements from an old location to a new location, it does not require
/// its elements to be copyable, and it avoids wasting memory when backed by an ArenaAllocator.
/// Note that the append() and pop() convenience methods perform a copy, but you can instead use
/// addOne(), at(), setCapacity(), and shrinkCapacity() to avoid copying items.
///
/// This data structure has O(1) append and O(1) pop.
///
/// It supports preallocated elements, making it especially well suited when the expected maximum
/// size is small. `prealloc_item_count` must be 0, or a power of 2.
pub fn SegmentedList(comptime T: type, comptime prealloc_item_count: usize) type {
    return struct {
        const Self = @This();
        const ShelfIndex = std.math.Log2Int(usize);

        const prealloc_exp: ShelfIndex = blk: {
            // we don't use the prealloc_exp constant when prealloc_item_count is 0
            // but lazy-init may still be triggered by other code so supply a value
            if (prealloc_item_count == 0) {
                break :blk 0;
            } else {
                assert(std.math.isPowerOfTwo(prealloc_item_count));
                const value = std.math.log2_int(usize, prealloc_item_count);
                break :blk value;
            }
        };

        prealloc_segment: [prealloc_item_count]T = undefined,
        dynamic_segments: [][*]T = &[_][*]T{},
        len: usize = 0,

        pub const prealloc_count = prealloc_item_count;

        fn AtType(comptime SelfType: type) type {
            if (@typeInfo(SelfType).pointer.is_const) {
                return *const T;
            } else {
                return *T;
            }
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.freeShelves(allocator, @as(ShelfIndex, @intCast(self.dynamic_segments.len)), 0);
            allocator.free(self.dynamic_segments);
            self.* = undefined;
        }

        pub fn at(self: anytype, i: usize) AtType(@TypeOf(self)) {
            assert(i < self.len);
            return self.uncheckedAt(i);
        }

        pub fn count(self: Self) usize {
            return self.len;
        }

        pub fn append(self: *Self, allocator: Allocator, item: T) Allocator.Error!void {
            const new_item_ptr = try self.addOne(allocator);
            new_item_ptr.* = item;
        }

        pub fn appendSlice(self: *Self, allocator: Allocator, items: []const T) Allocator.Error!void {
            for (items) |item| {
                try self.append(allocator, item);
            }
        }

        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;

            const index = self.len - 1;
            const result = uncheckedAt(self, index).*;
            self.len = index;
            return result;
        }

        pub fn addOne(self: *Self, allocator: Allocator) Allocator.Error!*T {
            const new_length = self.len + 1;
            try self.growCapacity(allocator, new_length);
            const result = uncheckedAt(self, self.len);
            self.len = new_length;
            return result;
        }

        /// Reduce length to `new_len`.
        /// Invalidates pointers for the elements at index new_len and beyond.
        pub fn shrinkRetainingCapacity(self: *Self, new_len: usize) void {
            assert(new_len <= self.len);
            self.len = new_len;
        }

        /// Invalidates all element pointers.
        pub fn clearRetainingCapacity(self: *Self) void {
            self.len = 0;
        }

        /// Invalidates all element pointers.
        pub fn clearAndFree(self: *Self, allocator: Allocator) void {
            self.setCapacity(allocator, 0) catch unreachable;
            self.len = 0;
        }

        /// Grows or shrinks capacity to match usage.
        /// TODO update this and related methods to match the conventions set by ArrayList
        pub fn setCapacity(self: *Self, allocator: Allocator, new_capacity: usize) Allocator.Error!void {
            if (prealloc_item_count != 0) {
                if (new_capacity <= @as(usize, 1) << (prealloc_exp + @as(ShelfIndex, @intCast(self.dynamic_segments.len)))) {
                    return self.shrinkCapacity(allocator, new_capacity);
                }
            }
            return self.growCapacity(allocator, new_capacity);
        }

        /// Only grows capacity, or retains current capacity.
        pub fn growCapacity(self: *Self, allocator: Allocator, new_capacity: usize) Allocator.Error!void {
            const new_cap_shelf_count = shelfCount(new_capacity);
            const old_shelf_count = @as(ShelfIndex, @intCast(self.dynamic_segments.len));
            if (new_cap_shelf_count <= old_shelf_count) return;

            const new_dynamic_segments = try allocator.alloc([*]T, new_cap_shelf_count);
            errdefer allocator.free(new_dynamic_segments);

            var i: ShelfIndex = 0;
            while (i < old_shelf_count) : (i += 1) {
                new_dynamic_segments[i] = self.dynamic_segments[i];
            }
            errdefer while (i > old_shelf_count) : (i -= 1) {
                allocator.free(new_dynamic_segments[i][0..shelfSize(i)]);
            };
            while (i < new_cap_shelf_count) : (i += 1) {
                new_dynamic_segments[i] = (try allocator.alloc(T, shelfSize(i))).ptr;
            }

            allocator.free(self.dynamic_segments);
            self.dynamic_segments = new_dynamic_segments;
        }

        /// Only shrinks capacity or retains current capacity.
        /// It may fail to reduce the capacity in which case the capacity will remain unchanged.
        pub fn shrinkCapacity(self: *Self, allocator: Allocator, new_capacity: usize) void {
            if (new_capacity <= prealloc_item_count) {
                const len = @as(ShelfIndex, @intCast(self.dynamic_segments.len));
                self.freeShelves(allocator, len, 0);
                allocator.free(self.dynamic_segments);
                self.dynamic_segments = &[_][*]T{};
                return;
            }

            const new_cap_shelf_count = shelfCount(new_capacity);
            const old_shelf_count = @as(ShelfIndex, @intCast(self.dynamic_segments.len));
            assert(new_cap_shelf_count <= old_shelf_count);
            if (new_cap_shelf_count == old_shelf_count) return;

            // freeShelves() must be called before resizing the dynamic
            // segments, but we don't know if resizing the dynamic segments
            // will work until we try it. So we must allocate a fresh memory
            // buffer in order to reduce capacity.
            const new_dynamic_segments = allocator.alloc([*]T, new_cap_shelf_count) catch return;
            self.freeShelves(allocator, old_shelf_count, new_cap_shelf_count);
            if (allocator.resize(self.dynamic_segments, new_cap_shelf_count)) {
                // We didn't need the new memory allocation after all.
                self.dynamic_segments = self.dynamic_segments[0..new_cap_shelf_count];
                allocator.free(new_dynamic_segments);
            } else {
                // Good thing we allocated that new memory slice.
                @memcpy(new_dynamic_segments, self.dynamic_segments[0..new_cap_shelf_count]);
                allocator.free(self.dynamic_segments);
                self.dynamic_segments = new_dynamic_segments;
            }
        }

        pub fn shrink(self: *Self, new_len: usize) void {
            assert(new_len <= self.len);
            // TODO take advantage of the new realloc semantics
            self.len = new_len;
        }

        pub fn writeToSlice(self: *Self, dest: []T, start: usize) void {
            const end = start + dest.len;
            assert(end <= self.len);

            var i = start;
            if (end <= prealloc_item_count) {
                const src = self.prealloc_segment[i..end];
                @memcpy(dest[i - start ..][0..src.len], src);
                return;
            } else if (i < prealloc_item_count) {
                const src = self.prealloc_segment[i..];
                @memcpy(dest[i - start ..][0..src.len], src);
                i = prealloc_item_count;
            }

            while (i < end) {
                const shelf_index = shelfIndex(i);
                const copy_start = boxIndex(i, shelf_index);
                const copy_end = @min(shelfSize(shelf_index), copy_start + end - i);
                const src = self.dynamic_segments[shelf_index][copy_start..copy_end];
                @memcpy(dest[i - start ..][0..src.len], src);
                i += (copy_end - copy_start);
            }
        }

        pub fn uncheckedAt(self: anytype, index: usize) AtType(@TypeOf(self)) {
            if (index < prealloc_item_count) {
                return &self.prealloc_segment[index];
            }
            const shelf_index = shelfIndex(index);
            const box_index = boxIndex(index, shelf_index);
            return &self.dynamic_segments[shelf_index][box_index];
        }

        fn shelfCount(box_count: usize) ShelfIndex {
            if (prealloc_item_count == 0) {
                return log2_int_ceil(usize, box_count + 1);
            }
            return log2_int_ceil(usize, box_count + prealloc_item_count) - prealloc_exp - 1;
        }

        fn shelfSize(shelf_index: ShelfIndex) usize {
            if (prealloc_item_count == 0) {
                return @as(usize, 1) << shelf_index;
            }
            return @as(usize, 1) << (shelf_index + (prealloc_exp + 1));
        }

        fn shelfIndex(list_index: usize) ShelfIndex {
            if (prealloc_item_count == 0) {
                return std.math.log2_int(usize, list_index + 1);
            }
            return std.math.log2_int(usize, list_index + prealloc_item_count) - prealloc_exp - 1;
        }

        fn boxIndex(list_index: usize, shelf_index: ShelfIndex) usize {
            if (prealloc_item_count == 0) {
                return (list_index + 1) - (@as(usize, 1) << shelf_index);
            }
            return list_index + prealloc_item_count - (@as(usize, 1) << ((prealloc_exp + 1) + shelf_index));
        }

        fn freeShelves(self: *Self, allocator: Allocator, from_count: ShelfIndex, to_count: ShelfIndex) void {
            var i = from_count;
            while (i != to_count) {
                i -= 1;
                allocator.free(self.dynamic_segments[i][0..shelfSize(i)]);
            }
        }

        pub const Iterator = BaseIterator(*Self, *T);
        pub const ConstIterator = BaseIterator(*const Self, *const T);
        fn BaseIterator(comptime SelfType: type, comptime ElementPtr: type) type {
            return struct {
                list: SelfType,
                index: usize,
                box_index: usize,
                shelf_index: ShelfIndex,
                shelf_size: usize,

                pub fn next(it: *@This()) ?ElementPtr {
                    if (it.index >= it.list.len) return null;
                    if (it.index < prealloc_item_count) {
                        const ptr = &it.list.prealloc_segment[it.index];
                        it.index += 1;
                        if (it.index == prealloc_item_count) {
                            it.box_index = 0;
                            it.shelf_index = 0;
                            it.shelf_size = prealloc_item_count * 2;
                        }
                        return ptr;
                    }

                    const ptr = &it.list.dynamic_segments[it.shelf_index][it.box_index];
                    it.index += 1;
                    it.box_index += 1;
                    if (it.box_index == it.shelf_size) {
                        it.shelf_index += 1;
                        it.box_index = 0;
                        it.shelf_size *= 2;
                    }
                    return ptr;
                }

                pub fn prev(it: *@This()) ?ElementPtr {
                    if (it.index == 0) return null;

                    it.index -= 1;
                    if (it.index < prealloc_item_count) return &it.list.prealloc_segment[it.index];

                    if (it.box_index == 0) {
                        it.shelf_index -= 1;
                        it.shelf_size /= 2;
                        it.box_index = it.shelf_size - 1;
                    } else {
                        it.box_index -= 1;
                    }

                    return &it.list.dynamic_segments[it.shelf_index][it.box_index];
                }

                pub fn peek(it: *@This()) ?ElementPtr {
                    if (it.index >= it.list.len)
                        return null;
                    if (it.index < prealloc_item_count)
                        return &it.list.prealloc_segment[it.index];

                    return &it.list.dynamic_segments[it.shelf_index][it.box_index];
                }

                pub fn set(it: *@This(), index: usize) void {
                    it.index = index;
                    if (index < prealloc_item_count) return;
                    it.shelf_index = shelfIndex(index);
                    it.box_index = boxIndex(index, it.shelf_index);
                    it.shelf_size = shelfSize(it.shelf_index);
                }
            };
        }

        pub fn iterator(self: *Self, start_index: usize) Iterator {
            var it = Iterator{
                .list = self,
                .index = undefined,
                .shelf_index = undefined,
                .box_index = undefined,
                .shelf_size = undefined,
            };
            it.set(start_index);
            return it;
        }

        pub fn constIterator(self: *const Self, start_index: usize) ConstIterator {
            var it = ConstIterator{
                .list = self,
                .index = undefined,
                .shelf_index = undefined,
                .box_index = undefined,
                .shelf_size = undefined,
            };
            it.set(start_index);
            return it;
        }
    };
}

test "basic usage" {
    try testSegmentedList(0);
    try testSegmentedList(1);
    try testSegmentedList(2);
    try testSegmentedList(4);
    try testSegmentedList(8);
    try testSegmentedList(16);
}

fn testSegmentedList(comptime prealloc: usize) !void {
    var list = SegmentedList(i32, prealloc){};
    defer list.deinit(testing.allocator);

    {
        var i: usize = 0;
        while (i < 100) : (i += 1) {
            try list.append(testing.allocator, @as(i32, @intCast(i + 1)));
            try testing.expect(list.len == i + 1);
        }
    }

    {
        var i: usize = 0;
        while (i < 100) : (i += 1) {
            try testing.expect(list.at(i).* == @as(i32, @intCast(i + 1)));
        }
    }

    {
        var it = list.iterator(0);
        var x: i32 = 0;
        while (it.next()) |item| {
            x += 1;
            try testing.expect(item.* == x);
        }
        try testing.expect(x == 100);
        while (it.prev()) |item| : (x -= 1) {
            try testing.expect(item.* == x);
        }
        try testing.expect(x == 0);
    }

    {
        var it = list.constIterator(0);
        var x: i32 = 0;
        while (it.next()) |item| {
            x += 1;
            try testing.expect(item.* == x);
        }
        try testing.expect(x == 100);
        while (it.prev()) |item| : (x -= 1) {
            try testing.expect(item.* == x);
        }
        try testing.expect(x == 0);
    }

    try testing.expect(list.pop().? == 100);
    try testing.expect(list.len == 99);

    try list.appendSlice(testing.allocator, &[_]i32{ 1, 2, 3 });
    try testing.expect(list.len == 102);
    try testing.expect(list.pop().? == 3);
    try testing.expect(list.pop().? == 2);
    try testing.expect(list.pop().? == 1);
    try testing.expect(list.len == 99);

    try list.appendSlice(testing.allocator, &[_]i32{});
    try testing.expect(list.len == 99);

    {
        var i: i32 = 99;
        while (list.pop()) |item| : (i -= 1) {
            try testing.expect(item == i);
            list.shrinkCapacity(testing.allocator, list.len);
        }
    }

    {
        var control: [100]i32 = undefined;
        var dest: [100]i32 = undefined;

        var i: i32 = 0;
        while (i < 100) : (i += 1) {
            try list.append(testing.allocator, i + 1);
            control[@as(usize, @intCast(i))] = i + 1;
        }

        @memset(dest[0..], 0);
        list.writeToSlice(dest[0..], 0);
        try testing.expect(mem.eql(i32, control[0..], dest[0..]));

        @memset(dest[0..], 0);
        list.writeToSlice(dest[50..], 50);
        try testing.expect(mem.eql(i32, control[50..], dest[50..]));
    }

    try list.setCapacity(testing.allocator, 0);
}

test "clearRetainingCapacity" {
    var list = SegmentedList(i32, 1){};
    defer list.deinit(testing.allocator);

    try list.appendSlice(testing.allocator, &[_]i32{ 4, 5 });
    list.clearRetainingCapacity();
    try list.append(testing.allocator, 6);
    try testing.expect(list.at(0).* == 6);
    try testing.expect(list.len == 1);
    list.clearRetainingCapacity();
    try testing.expect(list.len == 0);
}

/// TODO look into why this std.math function was changed in
/// fc9430f56798a53f9393a697f4ccd6bf9981b970.
fn log2_int_ceil(comptime T: type, x: T) std.math.Log2Int(T) {
    assert(x != 0);
    const log2_val = std.math.log2_int(T, x);
    if (@as(T, 1) << log2_val == x)
        return log2_val;
    return log2_val + 1;
}
//! A software version formatted according to the Semantic Versioning 2.0.0 specification.
//!
//! See: https://semver.org

const std = @import("std");
const Version = @This();

major: usize,
minor: usize,
patch: usize,
pre: ?[]const u8 = null,
build: ?[]const u8 = null,

pub const Range = struct {
    min: Version,
    max: Version,

    pub fn includesVersion(self: Range, ver: Version) bool {
        if (self.min.order(ver) == .gt) return false;
        if (self.max.order(ver) == .lt) return false;
        return true;
    }

    /// Checks if system is guaranteed to be at least `version` or older than `version`.
    /// Returns `null` if a runtime check is required.
    pub fn isAtLeast(self: Range, ver: Version) ?bool {
        if (self.min.order(ver) != .lt) return true;
        if (self.max.order(ver) == .lt) return false;
        return null;
    }
};

pub fn order(lhs: Version, rhs: Version) std.math.Order {
    if (lhs.major < rhs.major) return .lt;
    if (lhs.major > rhs.major) return .gt;
    if (lhs.minor < rhs.minor) return .lt;
    if (lhs.minor > rhs.minor) return .gt;
    if (lhs.patch < rhs.patch) return .lt;
    if (lhs.patch > rhs.patch) return .gt;
    if (lhs.pre != null and rhs.pre == null) return .lt;
    if (lhs.pre == null and rhs.pre == null) return .eq;
    if (lhs.pre == null and rhs.pre != null) return .gt;

    // Iterate over pre-release identifiers until a difference is found.
    var lhs_pre_it = std.mem.splitScalar(u8, lhs.pre.?, '.');
    var rhs_pre_it = std.mem.splitScalar(u8, rhs.pre.?, '.');
    while (true) {
        const next_lid = lhs_pre_it.next();
        const next_rid = rhs_pre_it.next();

        // A larger set of pre-release fields has a higher precedence than a smaller set.
        if (next_lid == null and next_rid != null) return .lt;
        if (next_lid == null and next_rid == null) return .eq;
        if (next_lid != null and next_rid == null) return .gt;

        const lid = next_lid.?; // Left identifier
        const rid = next_rid.?; // Right identifier

        // Attempt to parse identifiers as numbers. Overflows are checked by parse.
        const lnum: ?usize = std.fmt.parseUnsigned(usize, lid, 10) catch |err| switch (err) {
            error.InvalidCharacter => null,
            error.Overflow => unreachable,
        };
        const rnum: ?usize = std.fmt.parseUnsigned(usize, rid, 10) catch |err| switch (err) {
            error.InvalidCharacter => null,
            error.Overflow => unreachable,
        };

        // Numeric identifiers always have lower precedence than non-numeric identifiers.
        if (lnum != null and rnum == null) return .lt;
        if (lnum == null and rnum != null) return .gt;

        // Identifiers consisting of only digits are compared numerically.
        // Identifiers with letters or hyphens are compared lexically in ASCII sort order.
        if (lnum != null and rnum != null) {
            if (lnum.? < rnum.?) return .lt;
            if (lnum.? > rnum.?) return .gt;
        } else {
            const ord = std.mem.order(u8, lid, rid);
            if (ord != .eq) return ord;
        }
    }
}

pub fn parse(text: []const u8) !Version {
    // Parse the required major, minor, and patch numbers.
    const extra_index = std.mem.indexOfAny(u8, text, "-+");
    const required = text[0..(extra_index orelse text.len)];
    var it = std.mem.splitScalar(u8, required, '.');
    var ver = Version{
        .major = try parseNum(it.first()),
        .minor = try parseNum(it.next() orelse return error.InvalidVersion),
        .patch = try parseNum(it.next() orelse return error.InvalidVersion),
    };
    if (it.next() != null) return error.InvalidVersion;
    if (extra_index == null) return ver;

    // Slice optional pre-release or build metadata components.
    const extra: []const u8 = text[extra_index.?..text.len];
    if (extra[0] == '-') {
        const build_index = std.mem.indexOfScalar(u8, extra, '+');
        ver.pre = extra[1..(build_index orelse extra.len)];
        if (build_index) |idx| ver.build = extra[(idx + 1)..];
    } else {
        ver.build = extra[1..];
    }

    // Check validity of optional pre-release identifiers.
    // See: https://semver.org/#spec-item-9
    if (ver.pre) |pre| {
        it = std.mem.splitScalar(u8, pre, '.');
        while (it.next()) |id| {
            // Identifiers MUST NOT be empty.
            if (id.len == 0) return error.InvalidVersion;

            // Identifiers MUST comprise only ASCII alphanumerics and hyphens [0-9A-Za-z-].
            for (id) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return error.InvalidVersion;

            // Numeric identifiers MUST NOT include leading zeroes.
            const is_num = for (id) |c| {
                if (!std.ascii.isDigit(c)) break false;
            } else true;
            if (is_num) _ = try parseNum(id);
        }
    }

    // Check validity of optional build metadata identifiers.
    // See: https://semver.org/#spec-item-10
    if (ver.build) |build| {
        it = std.mem.splitScalar(u8, build, '.');
        while (it.next()) |id| {
            // Identifiers MUST NOT be empty.
            if (id.len == 0) return error.InvalidVersion;

            // Identifiers MUST comprise only ASCII alphanumerics and hyphens [0-9A-Za-z-].
            for (id) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return error.InvalidVersion;
        }
    }

    return ver;
}

fn parseNum(text: []const u8) error{ InvalidVersion, Overflow }!usize {
    // Leading zeroes are not allowed.
    if (text.len > 1 and text[0] == '0') return error.InvalidVersion;

    return std.fmt.parseUnsigned(usize, text, 10) catch |err| switch (err) {
        error.InvalidCharacter => return error.InvalidVersion,
        error.Overflow => return error.Overflow,
    };
}

pub fn format(
    self: Version,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    out_stream: anytype,
) !void {
    _ = options;
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
    try std.fmt.format(out_stream, "{d}.{d}.{d}", .{ self.major, self.minor, self.patch });
    if (self.pre) |pre| try std.fmt.format(out_stream, "-{s}", .{pre});
    if (self.build) |build| try std.fmt.format(out_stream, "+{s}", .{build});
}

const expect = std.testing.expect;
const expectError = std.testing.expectError;

test format {
    // Many of these test strings are from https://github.com/semver/semver.org/issues/59#issuecomment-390854010.

    // Valid version strings should be accepted.
    for ([_][]const u8{
        "0.0.4",
        "1.2.3",
        "10.20.30",
        "1.1.2-prerelease+meta",
        "1.1.2+meta",
        "1.1.2+meta-valid",
        "1.0.0-alpha",
        "1.0.0-beta",
        "1.0.0-alpha.beta",
        "1.0.0-alpha.beta.1",
        "1.0.0-alpha.1",
        "1.0.0-alpha0.valid",
        "1.0.0-alpha.0valid",
        "1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay",
        "1.0.0-rc.1+build.1",
        "2.0.0-rc.1+build.123",
        "1.2.3-beta",
        "10.2.3-DEV-SNAPSHOT",
        "1.2.3-SNAPSHOT-123",
        "1.0.0",
        "2.0.0",
        "1.1.7",
        "2.0.0+build.1848",
        "2.0.1-alpha.1227",
        "1.0.0-alpha+beta",
        "1.2.3----RC-SNAPSHOT.12.9.1--.12+788",
        "1.2.3----R-S.12.9.1--.12+meta",
        "1.2.3----RC-SNAPSHOT.12.9.1--.12",
        "1.0.0+0.build.1-rc.10000aaa-kk-0.1",
        "5.4.0-1018-raspi",
        "5.7.123",
    }) |valid| try std.testing.expectFmt(valid, "{}", .{try parse(valid)});

    // Invalid version strings should be rejected.
    for ([_][]const u8{
        "",
        "1",
        "1.2",
        "1.2.3-0123",
        "1.2.3-0123.0123",
        "1.1.2+.123",
        "+invalid",
        "-invalid",
        "-invalid+invalid",
        "-invalid.01",
        "alpha",
        "alpha.beta",
        "alpha.beta.1",
        "alpha.1",
        "alpha+beta",
        "alpha_beta",
        "alpha.",
        "alpha..",
        "beta\\",
        "1.0.0-alpha_beta",
        "-alpha.",
        "1.0.0-alpha..",
        "1.0.0-alpha..1",
        "1.0.0-alpha...1",
        "1.0.0-alpha....1",
        "1.0.0-alpha.....1",
        "1.0.0-alpha......1",
        "1.0.0-alpha.......1",
        "01.1.1",
        "1.01.1",
        "1.1.01",
        "1.2",
        "1.2.3.DEV",
        "1.2-SNAPSHOT",
        "1.2.31.2.3----RC-SNAPSHOT.12.09.1--..12+788",
        "1.2-RC-SNAPSHOT",
        "-1.0.3-gamma+b7718",
        "+justmeta",
        "9.8.7+meta+meta",
        "9.8.7-whatever+meta+meta",
        "2.6.32.11-svn21605",
        "2.11.2(0.329/5/3)",
        "2.13-DEVELOPMENT",
        "2.3-35",
        "1a.4",
        "3.b1.0",
        "1.4beta",
        "2.7.pre",
        "0..3",
        "8.008.",
        "01...",
        "55",
        "foobar",
        "",
        "-1",
        "+4",
        ".",
        "....3",
    }) |invalid| try expectError(error.InvalidVersion, parse(invalid));

    // Valid version string that may overflow.
    const big_valid = "99999999999999999999999.999999999999999999.99999999999999999";
    if (parse(big_valid)) |ver| {
        try std.testing.expectFmt(big_valid, "{}", .{ver});
    } else |err| try expect(err == error.Overflow);

    // Invalid version string that may overflow.
    const big_invalid = "99999999999999999999999.999999999999999999.99999999999999999----RC-SNAPSHOT.12.09.1--------------------------------..12";
    if (parse(big_invalid)) |ver| std.debug.panic("expected error, found {}", .{ver}) else |_| {}
}

test "precedence" {
    // SemVer 2 spec 11.2 example: 1.0.0 < 2.0.0 < 2.1.0 < 2.1.1.
    try expect(order(try parse("1.0.0"), try parse("2.0.0")) == .lt);
    try expect(order(try parse("2.0.0"), try parse("2.1.0")) == .lt);
    try expect(order(try parse("2.1.0"), try parse("2.1.1")) == .lt);

    // SemVer 2 spec 11.3 example: 1.0.0-alpha < 1.0.0.
    try expect(order(try parse("1.0.0-alpha"), try parse("1.0.0")) == .lt);

    // SemVer 2 spec 11.4 example: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta <
    // 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0.
    try expect(order(try parse("1.0.0-alpha"), try parse("1.0.0-alpha.1")) == .lt);
    try expect(order(try parse("1.0.0-alpha.1"), try parse("1.0.0-alpha.beta")) == .lt);
    try expect(order(try parse("1.0.0-alpha.beta"), try parse("1.0.0-beta")) == .lt);
    try expect(order(try parse("1.0.0-beta"), try parse("1.0.0-beta.2")) == .lt);
    try expect(order(try parse("1.0.0-beta.2"), try parse("1.0.0-beta.11")) == .lt);
    try expect(order(try parse("1.0.0-beta.11"), try parse("1.0.0-rc.1")) == .lt);
    try expect(order(try parse("1.0.0-rc.1"), try parse("1.0.0")) == .lt);
}

test "zig_version" {
    // An approximate Zig build that predates this test.
    const older_version: Version = .{ .major = 0, .minor = 8, .patch = 0, .pre = "dev.874" };

    // Simulated compatibility check using Zig version.
    const compatible = comptime @import("builtin").zig_version.order(older_version) == .gt;
    if (!compatible) @compileError("zig_version test failed");
}
//! SIMD (Single Instruction; Multiple Data) convenience functions.
//!
//! May offer a potential boost in performance on some targets by performing
//! the same operation on multiple elements at once.
//!
//! Some functions are known to not work on MIPS.

const std = @import("std");
const builtin = @import("builtin");

pub fn suggestVectorLengthForCpu(comptime T: type, comptime cpu: std.Target.Cpu) ?comptime_int {
    // This is guesswork, if you have better suggestions can add it or edit the current here
    const element_bit_size = @max(8, std.math.ceilPowerOfTwo(u16, @bitSizeOf(T)) catch unreachable);
    const vector_bit_size: u16 = blk: {
        if (cpu.arch.isX86()) {
            if (T == bool and std.Target.x86.featureSetHas(cpu.features, .prefer_mask_registers)) return 64;
            if (builtin.zig_backend != .stage2_x86_64 and std.Target.x86.featureSetHas(cpu.features, .avx512f) and !std.Target.x86.featureSetHasAny(cpu.features, .{ .prefer_256_bit, .prefer_128_bit })) break :blk 512;
            if (std.Target.x86.featureSetHasAny(cpu.features, .{ .prefer_256_bit, .avx2 }) and !std.Target.x86.featureSetHas(cpu.features, .prefer_128_bit)) break :blk 256;
            if (std.Target.x86.featureSetHas(cpu.features, .sse)) break :blk 128;
            if (std.Target.x86.featureSetHasAny(cpu.features, .{ .mmx, .@"3dnow" })) break :blk 64;
        } else if (cpu.arch.isArm()) {
            if (std.Target.arm.featureSetHas(cpu.features, .neon)) break :blk 128;
        } else if (cpu.arch.isAARCH64()) {
            // SVE allows up to 2048 bits in the specification, as of 2022 the most powerful machine has implemented 512-bit
            // I think is safer to just be on 128 until is more common
            // TODO: Check on this return when bigger values are more common
            if (std.Target.aarch64.featureSetHas(cpu.features, .sve)) break :blk 128;
            if (std.Target.aarch64.featureSetHas(cpu.features, .neon)) break :blk 128;
        } else if (cpu.arch.isPowerPC()) {
            if (std.Target.powerpc.featureSetHas(cpu.features, .altivec)) break :blk 128;
        } else if (cpu.arch.isMIPS()) {
            if (std.Target.mips.featureSetHas(cpu.features, .msa)) break :blk 128;
            // TODO: Test MIPS capability to handle bigger vectors
            //       In theory MDMX and by extension mips3d have 32 registers of 64 bits which can use in parallel
            //       for multiple processing, but I don't know what's optimal here, if using
            //       the 2048 bits or using just 64 per vector or something in between
            if (std.Target.mips.featureSetHas(cpu.features, std.Target.mips.Feature.mips3d)) break :blk 64;
        } else if (cpu.arch.isRISCV()) {
            // In RISC-V Vector Registers are length agnostic so there's no good way to determine the best size.
            // The usual vector length in most RISC-V cpus is 256 bits, however it can get to multiple kB.
            if (std.Target.riscv.featureSetHas(cpu.features, .v)) {
                var vec_bit_length: u32 = 256;
                if (std.Target.riscv.featureSetHas(cpu.features, .zvl32b)) {
                    vec_bit_length = 32;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl64b)) {
                    vec_bit_length = 64;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl128b)) {
                    vec_bit_length = 128;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl256b)) {
                    vec_bit_length = 256;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl512b)) {
                    vec_bit_length = 512;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl1024b)) {
                    vec_bit_length = 1024;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl2048b)) {
                    vec_bit_length = 2048;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl4096b)) {
                    vec_bit_length = 4096;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl8192b)) {
                    vec_bit_length = 8192;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl16384b)) {
                    vec_bit_length = 16384;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl32768b)) {
                    vec_bit_length = 32768;
                } else if (std.Target.riscv.featureSetHas(cpu.features, .zvl65536b)) {
                    vec_bit_length = 65536;
                }
                break :blk vec_bit_length;
            }
        } else if (cpu.arch.isSPARC()) {
            // TODO: Test Sparc capability to handle bigger vectors
            //       In theory Sparc have 32 registers of 64 bits which can use in parallel
            //       for multiple processing, but I don't know what's optimal here, if using
            //       the 2048 bits or using just 64 per vector or something in between
            if (std.Target.sparc.featureSetHasAny(cpu.features, .{ .vis, .vis2, .vis3 })) break :blk 64;
        } else if (cpu.arch.isWasm()) {
         ```
