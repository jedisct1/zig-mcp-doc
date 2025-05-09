```
utoHashStrat or providing your own hash function instead.");
    }

    hash(hasher, key, .Shallow);
}

const testing = std.testing;
const Wyhash = std.hash.Wyhash;

fn testHash(key: anytype) u64 {
    // Any hash could be used here, for testing autoHash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .Shallow);
    return hasher.final();
}

fn testHashShallow(key: anytype) u64 {
    // Any hash could be used here, for testing autoHash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .Shallow);
    return hasher.final();
}

fn testHashDeep(key: anytype) u64 {
    // Any hash could be used here, for testing autoHash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .Deep);
    return hasher.final();
}

fn testHashDeepRecursive(key: anytype) u64 {
    // Any hash could be used here, for testing autoHash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .DeepRecursive);
    return hasher.final();
}

test "typeContainsSlice" {
    comptime {
        try testing.expect(!typeContainsSlice(std.meta.Tag(std.builtin.Type)));

        try testing.expect(typeContainsSlice([]const u8));
        try testing.expect(!typeContainsSlice(u8));
        const A = struct { x: []const u8 };
        const B = struct { a: A };
        const C = struct { b: B };
        const D = struct { x: u8 };
        try testing.expect(typeContainsSlice(A));
        try testing.expect(typeContainsSlice(B));
        try testing.expect(typeContainsSlice(C));
        try testing.expect(!typeContainsSlice(D));
    }
}

test "hash pointer" {
    const array = [_]u32{ 123, 123, 123 };
    const a = &array[0];
    const b = &array[1];
    const c = &array[2];
    const d = a;

    try testing.expect(testHashShallow(a) == testHashShallow(d));
    try testing.expect(testHashShallow(a) != testHashShallow(c));
    try testing.expect(testHashShallow(a) != testHashShallow(b));

    try testing.expect(testHashDeep(a) == testHashDeep(a));
    try testing.expect(testHashDeep(a) == testHashDeep(c));
    try testing.expect(testHashDeep(a) == testHashDeep(b));

    try testing.expect(testHashDeepRecursive(a) == testHashDeepRecursive(a));
    try testing.expect(testHashDeepRecursive(a) == testHashDeepRecursive(c));
    try testing.expect(testHashDeepRecursive(a) == testHashDeepRecursive(b));
}

test "hash slice shallow" {
    // Allocate one array dynamically so that we're assured it is not merged
    // with the other by the optimization passes.
    const array1 = try std.testing.allocator.create([6]u32);
    defer std.testing.allocator.destroy(array1);
    array1.* = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const array2 = [_]u32{ 1, 2, 3, 4, 5, 6 };
    // TODO audit deep/shallow - maybe it has the wrong behavior with respect to array pointers and slices
    var runtime_zero: usize = 0;
    _ = &runtime_zero;
    const a = array1[runtime_zero..];
    const b = array2[runtime_zero..];
    const c = array1[runtime_zero..3];
    try testing.expect(testHashShallow(a) == testHashShallow(a));
    try testing.expect(testHashShallow(a) != testHashShallow(array1));
    try testing.expect(testHashShallow(a) != testHashShallow(b));
    try testing.expect(testHashShallow(a) != testHashShallow(c));
}

test "hash slice deep" {
    // Allocate one array dynamically so that we're assured it is not merged
    // with the other by the optimization passes.
    const array1 = try std.testing.allocator.create([6]u32);
    defer std.testing.allocator.destroy(array1);
    array1.* = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const array2 = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const a = array1[0..];
    const b = array2[0..];
    const c = array1[0..3];
    try testing.expect(testHashDeep(a) == testHashDeep(a));
    try testing.expect(testHashDeep(a) == testHashDeep(array1));
    try testing.expect(testHashDeep(a) == testHashDeep(b));
    try testing.expect(testHashDeep(a) != testHashDeep(c));
}

test "hash struct deep" {
    const Foo = struct {
        a: u32,
        b: u16,
        c: *bool,

        const Self = @This();

        pub fn init(allocator: mem.Allocator, a_: u32, b_: u16, c_: bool) !Self {
            const ptr = try allocator.create(bool);
            ptr.* = c_;
            return Self{ .a = a_, .b = b_, .c = ptr };
        }
    };

    const allocator = std.testing.allocator;
    const foo = try Foo.init(allocator, 123, 10, true);
    const bar = try Foo.init(allocator, 123, 10, true);
    const baz = try Foo.init(allocator, 123, 10, false);
    defer allocator.destroy(foo.c);
    defer allocator.destroy(bar.c);
    defer allocator.destroy(baz.c);

    try testing.expect(testHashDeep(foo) == testHashDeep(bar));
    try testing.expect(testHashDeep(foo) != testHashDeep(baz));
    try testing.expect(testHashDeep(bar) != testHashDeep(baz));

    var hasher = Wyhash.init(0);
    const h = testHashDeep(foo);
    autoHash(&hasher, foo.a);
    autoHash(&hasher, foo.b);
    autoHash(&hasher, foo.c.*);
    try testing.expectEqual(h, hasher.final());

    const h2 = testHashDeepRecursive(&foo);
    try testing.expect(h2 != testHashDeep(&foo));
    try testing.expect(h2 == testHashDeep(foo));
}

test "testHash optional" {
    const a: ?u32 = 123;
    const b: ?u32 = null;
    try testing.expectEqual(testHash(a), testHash(@as(u32, 123)));
    try testing.expect(testHash(a) != testHash(b));
    try testing.expectEqual(testHash(b), 0x409638ee2bde459); // wyhash empty input hash
}

test "testHash array" {
    const a = [_]u32{ 1, 2, 3 };
    const h = testHash(a);
    var hasher = Wyhash.init(0);
    autoHash(&hasher, @as(u32, 1));
    autoHash(&hasher, @as(u32, 2));
    autoHash(&hasher, @as(u32, 3));
    try testing.expectEqual(h, hasher.final());
}

test "testHash multi-dimensional array" {
    const a = [_][]const u32{ &.{ 1, 2, 3 }, &.{ 4, 5 } };
    const b = [_][]const u32{ &.{ 1, 2 }, &.{ 3, 4, 5 } };
    try testing.expect(testHash(a) != testHash(b));
}

test "testHash struct" {
    const Foo = struct {
        a: u32 = 1,
        b: u32 = 2,
        c: u32 = 3,
    };
    const f = Foo{};
    const h = testHash(f);
    var hasher = Wyhash.init(0);
    autoHash(&hasher, @as(u32, 1));
    autoHash(&hasher, @as(u32, 2));
    autoHash(&hasher, @as(u32, 3));
    try testing.expectEqual(h, hasher.final());
}

test "testHash union" {
    const Foo = union(enum) {
        A: u32,
        B: bool,
        C: u32,
        D: void,
    };

    const a = Foo{ .A = 18 };
    var b = Foo{ .B = true };
    const c = Foo{ .C = 18 };
    const d: Foo = .D;
    try testing.expect(testHash(a) == testHash(a));
    try testing.expect(testHash(a) != testHash(b));
    try testing.expect(testHash(a) != testHash(c));
    try testing.expect(testHash(a) != testHash(d));

    b = Foo{ .A = 18 };
    try testing.expect(testHash(a) == testHash(b));

    b = .D;
    try testing.expect(testHash(d) == testHash(b));
}

test "testHash vector" {
    const a: @Vector(4, u32) = [_]u32{ 1, 2, 3, 4 };
    const b: @Vector(4, u32) = [_]u32{ 1, 2, 3, 5 };
    try testing.expect(testHash(a) == testHash(a));
    try testing.expect(testHash(a) != testHash(b));

    const c: @Vector(4, u31) = [_]u31{ 1, 2, 3, 4 };
    const d: @Vector(4, u31) = [_]u31{ 1, 2, 3, 5 };
    try testing.expect(testHash(c) == testHash(c));
    try testing.expect(testHash(c) != testHash(d));
}

test "testHash error union" {
    const Errors = error{Test};
    const Foo = struct {
        a: u32 = 1,
        b: u32 = 2,
        c: u32 = 3,
    };
    const f = Foo{};
    const g: Errors!Foo = Errors.Test;
    try testing.expect(testHash(f) != testHash(g));
    try testing.expect(testHash(f) == testHash(Foo{}));
    try testing.expect(testHash(g) == testHash(Errors.Test));
}
// zig run -O ReleaseFast --zig-lib-dir ../.. benchmark.zig

const std = @import("std");
const builtin = @import("builtin");
const time = std.time;
const Timer = time.Timer;
const hash = std.hash;

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

var prng = std.Random.DefaultPrng.init(0);
const random = prng.random();

const Hash = struct {
    ty: type,
    name: []const u8,
    has_iterative_api: bool = true,
    has_crypto_api: bool = false,
    has_anytype_api: ?[]const comptime_int = null,
    init_u8s: ?[]const u8 = null,
    init_u64: ?u64 = null,
};

const hashes = [_]Hash{
    Hash{
        .ty = hash.XxHash3,
        .name = "xxh3",
        .init_u64 = 0,
        .has_anytype_api = @as([]const comptime_int, &[_]comptime_int{ 8, 16, 32, 48, 64, 80, 96, 112, 128 }),
    },
    Hash{
        .ty = hash.XxHash64,
        .name = "xxhash64",
        .init_u64 = 0,
        .has_anytype_api = @as([]const comptime_int, &[_]comptime_int{ 8, 16, 32, 48, 64, 80, 96, 112, 128 }),
    },
    Hash{
        .ty = hash.XxHash32,
        .name = "xxhash32",
        .init_u64 = 0,
        .has_anytype_api = @as([]const comptime_int, &[_]comptime_int{ 8, 16, 32, 48, 64, 80, 96, 112, 128 }),
    },
    Hash{
        .ty = hash.Wyhash,
        .name = "wyhash",
        .init_u64 = 0,
    },
    Hash{
        .ty = hash.Fnv1a_64,
        .name = "fnv1a",
    },
    Hash{
        .ty = hash.Adler32,
        .name = "adler32",
    },
    Hash{
        .ty = hash.crc.Crc32,
        .name = "crc32",
    },
    Hash{
        .ty = hash.RapidHash,
        .name = "rapidhash",
        .has_iterative_api = false,
        .init_u64 = 0,
    },
    Hash{
        .ty = hash.CityHash32,
        .name = "cityhash-32",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.CityHash64,
        .name = "cityhash-64",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.Murmur2_32,
        .name = "murmur2-32",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.Murmur2_64,
        .name = "murmur2-64",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.Murmur3_32,
        .name = "murmur3-32",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.SipHash64(1, 3),
        .name = "siphash64",
        .has_crypto_api = true,
        .init_u8s = &[_]u8{0} ** 16,
    },
    Hash{
        .ty = hash.SipHash128(1, 3),
        .name = "siphash128",
        .has_crypto_api = true,
        .init_u8s = &[_]u8{0} ** 16,
    },
};

const Result = struct {
    hash: u64,
    throughput: u64,
};

const block_size: usize = 8 * 8192;

pub fn benchmarkHash(comptime H: anytype, bytes: usize, allocator: std.mem.Allocator) !Result {
    var blocks = try allocator.alloc(u8, bytes);
    defer allocator.free(blocks);
    random.bytes(blocks);

    const block_count = bytes / block_size;

    var h = blk: {
        if (H.init_u8s) |init| {
            break :blk H.ty.init(init[0..H.ty.key_length]);
        }
        if (H.init_u64) |init| {
            break :blk H.ty.init(init);
        }
        break :blk H.ty.init();
    };

    var timer = try Timer.start();
    for (0..block_count) |i| {
        h.update(blocks[i * block_size ..][0..block_size]);
    }
    const final = if (H.has_crypto_api) @as(u64, @truncate(h.finalInt())) else h.final();
    std.mem.doNotOptimizeAway(final);

    const elapsed_ns = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const size_float: f64 = @floatFromInt(block_size * block_count);
    const throughput: u64 = @intFromFloat(size_float / elapsed_s);

    return Result{
        .hash = final,
        .throughput = throughput,
    };
}

pub fn benchmarkHashSmallKeys(comptime H: anytype, key_size: usize, bytes: usize, allocator: std.mem.Allocator) !Result {
    var blocks = try allocator.alloc(u8, bytes);
    defer allocator.free(blocks);
    random.bytes(blocks);

    const key_count = bytes / key_size;

    var timer = try Timer.start();

    var sum: u64 = 0;
    for (0..key_count) |i| {
        const small_key = blocks[i * key_size ..][0..key_size];
        const final = blk: {
            if (H.init_u8s) |init| {
                if (H.has_crypto_api) {
                    break :blk @as(u64, @truncate(H.ty.toInt(small_key, init[0..H.ty.key_length])));
                } else {
                    break :blk H.ty.hash(init, small_key);
                }
            }
            if (H.init_u64) |init| {
                break :blk H.ty.hash(init, small_key);
            }
            break :blk H.ty.hash(small_key);
        };
        sum +%= final;
    }
    const elapsed_ns = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const size_float: f64 = @floatFromInt(key_count * key_size);
    const throughput: u64 = @intFromFloat(size_float / elapsed_s);

    std.mem.doNotOptimizeAway(sum);

    return Result{
        .hash = sum,
        .throughput = throughput,
    };
}

// the array and array pointer benchmarks for xxhash are very sensitive to in-lining,
// if you see strange performance changes consider using `.never_inline` or `.always_inline`
// to ensure the changes are not only due to the optimiser inlining the benchmark differently
pub fn benchmarkHashSmallKeysArrayPtr(
    comptime H: anytype,
    comptime key_size: usize,
    bytes: usize,
    allocator: std.mem.Allocator,
) !Result {
    var blocks = try allocator.alloc(u8, bytes);
    defer allocator.free(blocks);
    random.bytes(blocks);

    const key_count = bytes / key_size;

    var timer = try Timer.start();

    var sum: u64 = 0;
    for (0..key_count) |i| {
        const small_key = blocks[i * key_size ..][0..key_size];
        const final: u64 = blk: {
            if (H.init_u8s) |init| {
                if (H.has_crypto_api) {
                    break :blk @truncate(H.ty.toInt(small_key, init[0..H.ty.key_length]));
                } else {
                    break :blk H.ty.hash(init, small_key);
                }
            }
            if (H.init_u64) |init| {
                break :blk H.ty.hash(init, small_key);
            }
            break :blk H.ty.hash(small_key);
        };
        sum +%= final;
    }
    const elapsed_ns = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const throughput: u64 = @intFromFloat(@as(f64, @floatFromInt(bytes)) / elapsed_s);

    std.mem.doNotOptimizeAway(sum);

    return Result{
        .hash = sum,
        .throughput = throughput,
    };
}

// the array and array pointer benchmarks for xxhash are very sensitive to in-lining,
// if you see strange performance changes consider using `.never_inline` or `.always_inline`
// to ensure the changes are not only due to the optimiser inlining the benchmark differently
pub fn benchmarkHashSmallKeysArray(
    comptime H: anytype,
    comptime key_size: usize,
    bytes: usize,
    allocator: std.mem.Allocator,
) !Result {
    var blocks = try allocator.alloc(u8, bytes);
    defer allocator.free(blocks);
    random.bytes(blocks);

    const key_count = bytes / key_size;

    var i: usize = 0;
    var timer = try Timer.start();

    var sum: u64 = 0;
    while (i < key_count) : (i += 1) {
        const small_key = blocks[i * key_size ..][0..key_size];
        const final: u64 = blk: {
            if (H.init_u8s) |init| {
                if (H.has_crypto_api) {
                    break :blk @truncate(H.ty.toInt(small_key, init[0..H.ty.key_length]));
                } else {
                    break :blk H.ty.hash(init, small_key.*);
                }
            }
            if (H.init_u64) |init| {
                break :blk H.ty.hash(init, small_key.*);
            }
            break :blk H.ty.hash(small_key.*);
        };
        sum +%= final;
    }
    const elapsed_ns = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const throughput: u64 = @intFromFloat(@as(f64, @floatFromInt(bytes)) / elapsed_s);

    std.mem.doNotOptimizeAway(sum);

    return Result{
        .hash = sum,
        .throughput = throughput,
    };
}

pub fn benchmarkHashSmallApi(comptime H: anytype, key_size: usize, bytes: usize, allocator: std.mem.Allocator) !Result {
    var blocks = try allocator.alloc(u8, bytes);
    defer allocator.free(blocks);
    random.bytes(blocks);

    const key_count = bytes / key_size;

    var timer = try Timer.start();

    var sum: u64 = 0;
    for (0..key_count) |i| {
        const small_key = blocks[i * key_size ..][0..key_size];
        const final: u64 = blk: {
            if (H.init_u8s) |init| {
                if (H.has_crypto_api) {
                    break :blk @truncate(H.ty.toInt(small_key, init[0..H.ty.key_length]));
                } else {
                    break :blk H.ty.hashSmall(init, small_key);
                }
            }
            if (H.init_u64) |init| {
                break :blk H.ty.hashSmall(init, small_key);
            }
            break :blk H.ty.hashSmall(small_key);
        };
        sum +%= final;
    }
    const elapsed_ns = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const throughput: u64 = @intFromFloat(@as(f64, @floatFromInt(bytes)) / elapsed_s);

    std.mem.doNotOptimizeAway(sum);

    return Result{
        .throughput = throughput,
        .hash = sum,
    };
}

fn usage() void {
    std.debug.print(
        \\throughput_test [options]
        \\
        \\Options:
        \\  --filter    [test-name]
        \\  --seed      [int]
        \\  --count     [int]
        \\  --key-size  [int]
        \\  --iterative-only
        \\  --small-key-only
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
    var key_size: ?usize = null;
    var seed: u32 = 0;
    var test_small_key_only = false;
    var test_iterative_only = false;
    var test_arrays = false;

    const default_small_key_size = 32;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--mode")) {
            try stdout.print("{}\n", .{builtin.mode});
            return;
        } else if (std.mem.eql(u8, args[i], "--seed")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.process.exit(1);
            }

            seed = try std.fmt.parseUnsigned(u32, args[i], 10);
            // we seed later
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
        } else if (std.mem.eql(u8, args[i], "--key-size")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.process.exit(1);
            }

            key_size = try std.fmt.parseUnsigned(usize, args[i], 10);
            if (key_size.? > block_size) {
                try stdout.print("key_size cannot exceed block size of {}\n", .{block_size});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, args[i], "--iterative-only")) {
            test_iterative_only = true;
        } else if (std.mem.eql(u8, args[i], "--small-key-only")) {
            test_small_key_only = true;
        } else if (std.mem.eql(u8, args[i], "--include-array")) {
            test_arrays = true;
        } else if (std.mem.eql(u8, args[i], "--help")) {
            usage();
            return;
        } else {
            usage();
            std.process.exit(1);
        }
    }

    if (test_iterative_only and test_small_key_only) {
        try stdout.print("Cannot use iterative-only and small-key-only together!\n", .{});
        usage();
        std.process.exit(1);
    }

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    inline for (hashes) |H| {
        if (filter == null or std.mem.indexOf(u8, H.name, filter.?) != null) hash: {
            if (!test_iterative_only or H.has_iterative_api) {
                try stdout.print("{s}\n", .{H.name});

                // Always reseed prior to every call so we are hashing the same buffer contents.
                // This allows easier comparison between different implementations.
                if (H.has_iterative_api and !test_small_key_only) {
                    prng.seed(seed);
                    const result = try benchmarkHash(H, count, allocator);
                    try stdout.print("   iterative: {:5} MiB/s [{x:0<16}]\n", .{ result.throughput / (1 * MiB), result.hash });
                }

                if (!test_iterative_only) {
                    if (key_size) |size| {
                        prng.seed(seed);
                        const result_small = try benchmarkHashSmallKeys(H, size, count, allocator);
                        try stdout.print("  small keys: {:3}B {:5} MiB/s {} Hashes/s [{x:0<16}]\n", .{
                            size,
                            result_small.throughput / (1 * MiB),
                            result_small.throughput / size,
                            result_small.hash,
                        });

                        if (!test_arrays) break :hash;
                        if (H.has_anytype_api) |sizes| {
                            inline for (sizes) |exact_size| {
                                if (size == exact_size) {
                                    prng.seed(seed);
                                    const result_array = try benchmarkHashSmallKeysArray(H, exact_size, count, allocator);
                                    prng.seed(seed);
                                    const result_ptr = try benchmarkHashSmallKeysArrayPtr(H, exact_size, count, allocator);
                                    try stdout.print("       array: {:5} MiB/s [{x:0<16}]\n", .{
                                        result_array.throughput / (1 * MiB),
                                        result_array.hash,
                                    });
                                    try stdout.print("   array ptr: {:5} MiB/s [{x:0<16}]\n", .{
                                        result_ptr.throughput / (1 * MiB),
                                        result_ptr.hash,
                                    });
                                }
                            }
                        }
                    } else {
                        prng.seed(seed);
                        const result_small = try benchmarkHashSmallKeys(H, default_small_key_size, count, allocator);
                        try stdout.print("  small keys: {:3}B {:5} MiB/s {} Hashes/s [{x:0<16}]\n", .{
                            default_small_key_size,
                            result_small.throughput / (1 * MiB),
                            result_small.throughput / default_small_key_size,
                            result_small.hash,
                        });

                        if (!test_arrays) break :hash;
                        if (H.has_anytype_api) |sizes| {
                            try stdout.print("       array:\n", .{});
                            inline for (sizes) |exact_size| {
                                prng.seed(seed);
                                const result = try benchmarkHashSmallKeysArray(H, exact_size, count, allocator);
                                try stdout.print("       {d: >3}B {:5} MiB/s [{x:0<16}]\n", .{
                                    exact_size,
                                    result.throughput / (1 * MiB),
                                    result.hash,
                                });
                            }
                            try stdout.print("   array ptr: \n", .{});
                            inline for (sizes) |exact_size| {
                                prng.seed(seed);
                                const result = try benchmarkHashSmallKeysArrayPtr(H, exact_size, count, allocator);
                                try stdout.print("       {d: >3}B {:5} MiB/s [{x:0<16}]\n", .{
                                    exact_size,
                                    result.throughput / (1 * MiB),
                                    result.hash,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}
const std = @import("std");

inline fn offsetPtr(ptr: [*]const u8, offset: usize) [*]const u8 {
    // ptr + offset doesn't work at comptime so we need this instead.
    return @as([*]const u8, @ptrCast(&ptr[offset]));
}

fn fetch32(ptr: [*]const u8, offset: usize) u32 {
    return std.mem.readInt(u32, offsetPtr(ptr, offset)[0..4], .little);
}

fn fetch64(ptr: [*]const u8, offset: usize) u64 {
    return std.mem.readInt(u64, offsetPtr(ptr, offset)[0..8], .little);
}

pub const CityHash32 = struct {
    const Self = @This();

    // Magic numbers for 32-bit hashing.  Copied from Murmur3.
    const c1: u32 = 0xcc9e2d51;
    const c2: u32 = 0x1b873593;

    // A 32-bit to 32-bit integer hash copied from Murmur3.
    fn fmix(h: u32) u32 {
        var h1: u32 = h;
        h1 ^= h1 >> 16;
        h1 *%= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *%= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }

    // Rotate right helper
    fn rotr32(x: u32, comptime r: u32) u32 {
        return (x >> r) | (x << (32 - r));
    }

    // Helper from Murmur3 for combining two 32-bit values.
    fn mur(a: u32, h: u32) u32 {
        var a1: u32 = a;
        var h1: u32 = h;
        a1 *%= c1;
        a1 = rotr32(a1, 17);
        a1 *%= c2;
        h1 ^= a1;
        h1 = rotr32(h1, 19);
        return h1 *% 5 +% 0xe6546b64;
    }

    fn hash32Len0To4(str: []const u8) u32 {
        const len: u32 = @as(u32, @truncate(str.len));
        var b: u32 = 0;
        var c: u32 = 9;
        for (str) |v| {
            b = b *% c1 +% @as(u32, @bitCast(@as(i32, @intCast(@as(i8, @bitCast(v))))));
            c ^= b;
        }
        return fmix(mur(b, mur(len, c)));
    }

    fn hash32Len5To12(str: []const u8) u32 {
        var a: u32 = @as(u32, @truncate(str.len));
        var b: u32 = a *% 5;
        var c: u32 = 9;
        const d: u32 = b;

        a +%= fetch32(str.ptr, 0);
        b +%= fetch32(str.ptr, str.len - 4);
        c +%= fetch32(str.ptr, (str.len >> 1) & 4);

        return fmix(mur(c, mur(b, mur(a, d))));
    }

    fn hash32Len13To24(str: []const u8) u32 {
        const len: u32 = @as(u32, @truncate(str.len));
        const a: u32 = fetch32(str.ptr, (str.len >> 1) - 4);
        const b: u32 = fetch32(str.ptr, 4);
        const c: u32 = fetch32(str.ptr, str.len - 8);
        const d: u32 = fetch32(str.ptr, str.len >> 1);
        const e: u32 = fetch32(str.ptr, 0);
        const f: u32 = fetch32(str.ptr, str.len - 4);

        return fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, len)))))));
    }

    pub fn hash(str: []const u8) u32 {
        if (str.len <= 24) {
            if (str.len <= 4) {
                return hash32Len0To4(str);
            } else {
                if (str.len <= 12)
                    return hash32Len5To12(str);
                return hash32Len13To24(str);
            }
        }

        const len: u32 = @as(u32, @truncate(str.len));
        var h: u32 = len;
        var g: u32 = c1 *% len;
        var f: u32 = g;

        const a0: u32 = rotr32(fetch32(str.ptr, str.len - 4) *% c1, 17) *% c2;
        const a1: u32 = rotr32(fetch32(str.ptr, str.len - 8) *% c1, 17) *% c2;
        const a2: u32 = rotr32(fetch32(str.ptr, str.len - 16) *% c1, 17) *% c2;
        const a3: u32 = rotr32(fetch32(str.ptr, str.len - 12) *% c1, 17) *% c2;
        const a4: u32 = rotr32(fetch32(str.ptr, str.len - 20) *% c1, 17) *% c2;

        h ^= a0;
        h = rotr32(h, 19);
        h = h *% 5 +% 0xe6546b64;
        h ^= a2;
        h = rotr32(h, 19);
        h = h *% 5 +% 0xe6546b64;
        g ^= a1;
        g = rotr32(g, 19);
        g = g *% 5 +% 0xe6546b64;
        g ^= a3;
        g = rotr32(g, 19);
        g = g *% 5 +% 0xe6546b64;
        f +%= a4;
        f = rotr32(f, 19);
        f = f *% 5 +% 0xe6546b64;
        var iters = (str.len - 1) / 20;
        var ptr = str.ptr;
        while (iters != 0) : (iters -= 1) {
            const b0: u32 = rotr32(fetch32(ptr, 0) *% c1, 17) *% c2;
            const b1: u32 = fetch32(ptr, 4);
            const b2: u32 = rotr32(fetch32(ptr, 8) *% c1, 17) *% c2;
            const b3: u32 = rotr32(fetch32(ptr, 12) *% c1, 17) *% c2;
            const b4: u32 = fetch32(ptr, 16);

            h ^= b0;
            h = rotr32(h, 18);
            h = h *% 5 +% 0xe6546b64;
            f +%= b1;
            f = rotr32(f, 19);
            f = f *% c1;
            g +%= b2;
            g = rotr32(g, 18);
            g = g *% 5 +% 0xe6546b64;
            h ^= b3 +% b1;
            h = rotr32(h, 19);
            h = h *% 5 +% 0xe6546b64;
            g ^= b4;
            g = @byteSwap(g) *% 5;
            h +%= b4 *% 5;
            h = @byteSwap(h);
            f +%= b0;
            const t: u32 = h;
            h = f;
            f = g;
            g = t;
            ptr = offsetPtr(ptr, 20);
        }
        g = rotr32(g, 11) *% c1;
        g = rotr32(g, 17) *% c1;
        f = rotr32(f, 11) *% c1;
        f = rotr32(f, 17) *% c1;
        h = rotr32(h +% g, 19);
        h = h *% 5 +% 0xe6546b64;
        h = rotr32(h, 17) *% c1;
        h = rotr32(h +% f, 19);
        h = h *% 5 +% 0xe6546b64;
        h = rotr32(h, 17) *% c1;
        return h;
    }
};

pub const CityHash64 = struct {
    const Self = @This();

    // Some primes between 2^63 and 2^64 for various uses.
    const k0: u64 = 0xc3a5c85c97cb3127;
    const k1: u64 = 0xb492b66fbe98f273;
    const k2: u64 = 0x9ae16a3b2f90404f;

    // Rotate right helper
    fn rotr64(x: u64, comptime r: u64) u64 {
        return (x >> r) | (x << (64 - r));
    }

    fn shiftmix(v: u64) u64 {
        return v ^ (v >> 47);
    }

    fn hashLen16(u: u64, v: u64) u64 {
        return @call(.always_inline, hash128To64, .{ u, v });
    }

    fn hashLen16Mul(low: u64, high: u64, mul: u64) u64 {
        var a: u64 = (low ^ high) *% mul;
        a ^= (a >> 47);
        var b: u64 = (high ^ a) *% mul;
        b ^= (b >> 47);
        b *%= mul;
        return b;
    }

    fn hash128To64(low: u64, high: u64) u64 {
        return @call(.always_inline, hashLen16Mul, .{ low, high, 0x9ddfea08eb382d69 });
    }

    fn hashLen0To16(str: []const u8) u64 {
        const len: u64 = @as(u64, str.len);
        if (len >= 8) {
            const mul: u64 = k2 +% len *% 2;
            const a: u64 = fetch64(str.ptr, 0) +% k2;
            const b: u64 = fetch64(str.ptr, str.len - 8);
            const c: u64 = rotr64(b, 37) *% mul +% a;
            const d: u64 = (rotr64(a, 25) +% b) *% mul;
            return hashLen16Mul(c, d, mul);
        }
        if (len >= 4) {
            const mul: u64 = k2 +% len *% 2;
            const a: u64 = fetch32(str.ptr, 0);
            return hashLen16Mul(len +% (a << 3), fetch32(str.ptr, str.len - 4), mul);
        }
        if (len > 0) {
            const a: u8 = str[0];
            const b: u8 = str[str.len >> 1];
            const c: u8 = str[str.len - 1];
            const y: u32 = @as(u32, @intCast(a)) +% (@as(u32, @intCast(b)) << 8);
            const z: u32 = @as(u32, @truncate(str.len)) +% (@as(u32, @intCast(c)) << 2);
            return shiftmix(@as(u64, @intCast(y)) *% k2 ^ @as(u64, @intCast(z)) *% k0) *% k2;
        }
        return k2;
    }

    fn hashLen17To32(str: []const u8) u64 {
        const len: u64 = @as(u64, str.len);
        const mul: u64 = k2 +% len *% 2;
        const a: u64 = fetch64(str.ptr, 0) *% k1;
        const b: u64 = fetch64(str.ptr, 8);
        const c: u64 = fetch64(str.ptr, str.len - 8) *% mul;
        const d: u64 = fetch64(str.ptr, str.len - 16) *% k2;

        return hashLen16Mul(rotr64(a +% b, 43) +% rotr64(c, 30) +% d, a +% rotr64(b +% k2, 18) +% c, mul);
    }

    fn hashLen33To64(str: []const u8) u64 {
        const len: u64 = @as(u64, str.len);
        const mul: u64 = k2 +% len *% 2;
        const a: u64 = fetch64(str.ptr, 0) *% k2;
        const b: u64 = fetch64(str.ptr, 8);
        const c: u64 = fetch64(str.ptr, str.len - 24);
        const d: u64 = fetch64(str.ptr, str.len - 32);
        const e: u64 = fetch64(str.ptr, 16) *% k2;
        const f: u64 = fetch64(str.ptr, 24) *% 9;
        const g: u64 = fetch64(str.ptr, str.len - 8);
        const h: u64 = fetch64(str.ptr, str.len - 16) *% mul;

        const u: u64 = rotr64(a +% g, 43) +% (rotr64(b, 30) +% c) *% 9;
        const v: u64 = ((a +% g) ^ d) +% f +% 1;
        const w: u64 = @byteSwap((u +% v) *% mul) +% h;
        const x: u64 = rotr64(e +% f, 42) +% c;
        const y: u64 = (@byteSwap((v +% w) *% mul) +% g) *% mul;
        const z: u64 = e +% f +% c;
        const a1: u64 = @byteSwap((x +% z) *% mul +% y) +% b;
        const b1: u64 = shiftmix((z +% a1) *% mul +% d +% h) *% mul;
        return b1 +% x;
    }

    const WeakPair = struct {
        first: u64,
        second: u64,
    };

    fn weakHashLen32WithSeedsHelper(w: u64, x: u64, y: u64, z: u64, a: u64, b: u64) WeakPair {
        var a1: u64 = a;
        var b1: u64 = b;
        a1 +%= w;
        b1 = rotr64(b1 +% a1 +% z, 21);
        const c: u64 = a1;
        a1 +%= x;
        a1 +%= y;
        b1 +%= rotr64(a1, 44);
        return WeakPair{ .first = a1 +% z, .second = b1 +% c };
    }

    fn weakHashLen32WithSeeds(ptr: [*]const u8, a: u64, b: u64) WeakPair {
        return @call(.always_inline, weakHashLen32WithSeedsHelper, .{
            fetch64(ptr, 0),
            fetch64(ptr, 8),
            fetch64(ptr, 16),
            fetch64(ptr, 24),
            a,
            b,
        });
    }

    pub fn hash(str: []const u8) u64 {
        if (str.len <= 32) {
            if (str.len <= 16) {
                return hashLen0To16(str);
            } else {
                return hashLen17To32(str);
            }
        } else if (str.len <= 64) {
            return hashLen33To64(str);
        }

        var len: u64 = @as(u64, str.len);

        var x: u64 = fetch64(str.ptr, str.len - 40);
        var y: u64 = fetch64(str.ptr, str.len - 16) +% fetch64(str.ptr, str.len - 56);
        var z: u64 = hashLen16(fetch64(str.ptr, str.len - 48) +% len, fetch64(str.ptr, str.len - 24));
        var v: WeakPair = weakHashLen32WithSeeds(offsetPtr(str.ptr, str.len - 64), len, z);
        var w: WeakPair = weakHashLen32WithSeeds(offsetPtr(str.ptr, str.len - 32), y +% k1, x);

        x = x *% k1 +% fetch64(str.ptr, 0);
        len = (len - 1) & ~@as(u64, @intCast(63));

        var ptr: [*]const u8 = str.ptr;
        while (true) {
            x = rotr64(x +% y +% v.first +% fetch64(ptr, 8), 37) *% k1;
            y = rotr64(y +% v.second +% fetch64(ptr, 48), 42) *% k1;
            x ^= w.second;
            y +%= v.first +% fetch64(ptr, 40);
            z = rotr64(z +% w.first, 33) *% k1;
            v = weakHashLen32WithSeeds(ptr, v.second *% k1, x +% w.first);
            w = weakHashLen32WithSeeds(offsetPtr(ptr, 32), z +% w.second, y +% fetch64(ptr, 16));
            const t: u64 = z;
            z = x;
            x = t;

            ptr = offsetPtr(ptr, 64);
            len -= 64;
            if (len == 0)
                break;
        }

        return hashLen16(hashLen16(v.first, w.first) +% shiftmix(y) *% k1 +% z, hashLen16(v.second, w.second) +% x);
    }

    pub fn hashWithSeed(str: []const u8, seed: u64) u64 {
        return @call(.always_inline, Self.hashWithSeeds, .{ str, k2, seed });
    }

    pub fn hashWithSeeds(str: []const u8, seed0: u64, seed1: u64) u64 {
        return hashLen16(hash(str) -% seed0, seed1);
    }
};

fn CityHash32hashIgnoreSeed(str: []const u8, seed: u32) u32 {
    _ = seed;
    return CityHash32.hash(str);
}

const verify = @import("verify.zig");

test "cityhash32" {
    const Test = struct {
        fn do() !void {
            // SMHasher doesn't provide a 32bit version of the algorithm.
            // The implementation was verified against the Google Abseil version.
            try std.testing.expectEqual(verify.smhasher(CityHash32hashIgnoreSeed), 0x68254F81);
        }
    };
    try Test.do();
    @setEvalBranchQuota(75000);
    try comptime Test.do();
}

test "cityhash64" {
    const Test = struct {
        fn do() !void {
            // This is not compliant with the SMHasher implementation of CityHash64!
            // The implementation was verified against the Google Abseil version.
            try std.testing.expectEqual(verify.smhasher(CityHash64.hashWithSeed), 0x5FABC5C5);
        }
    };
    try Test.do();
    @setEvalBranchQuota(75000);
    try comptime Test.do();
}
//! This file is auto-generated by tools/update_crc_catalog.zig.

const impl = @import("crc/impl.zig");

pub const Crc = impl.Crc;
pub const Polynomial = impl.Polynomial;
pub const Crc32WithPoly = impl.Crc32WithPoly;
pub const Crc32SmallWithPoly = impl.Crc32SmallWithPoly;

pub const Crc32 = Crc32IsoHdlc;

test {
    _ = @import("crc/test.zig");
}

pub const Crc3Gsm = Crc(u3, .{
    .polynomial = 0x3,
    .initial = 0x0,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x7,
});

pub const Crc3Rohc = Crc(u3, .{
    .polynomial = 0x3,
    .initial = 0x7,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0,
});

pub const Crc4G704 = Crc(u4, .{
    .polynomial = 0x3,
    .initial = 0x0,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0,
});

pub const Crc4Interlaken = Crc(u4, .{
    .polynomial = 0x3,
    .initial = 0xf,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xf,
});

pub const Crc5EpcC1g2 = Crc(u5, .{
    .polynomial = 0x09,
    .initial = 0x09,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc5G704 = Crc(u5, .{
    .polynomial = 0x15,
    .initial = 0x00,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc5Usb = Crc(u5, .{
    .polynomial = 0x05,
    .initial = 0x1f,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x1f,
});

pub const Crc6Cdma2000A = Crc(u6, .{
    .polynomial = 0x27,
    .initial = 0x3f,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc6Cdma2000B = Crc(u6, .{
    .polynomial = 0x07,
    .initial = 0x3f,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc6Darc = Crc(u6, .{
    .polynomial = 0x19,
    .initial = 0x00,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc6G704 = Crc(u6, .{
    .polynomial = 0x03,
    .initial = 0x00,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc6Gsm = Crc(u6, .{
    .polynomial = 0x2f,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x3f,
});

pub const Crc7Mmc = Crc(u7, .{
    .polynomial = 0x09,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc7Rohc = Crc(u7, .{
    .polynomial = 0x4f,
    .initial = 0x7f,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc7Umts = Crc(u7, .{
    .polynomial = 0x45,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8Autosar = Crc(u8, .{
    .polynomial = 0x2f,
    .initial = 0xff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xff,
});

pub const Crc8Bluetooth = Crc(u8, .{
    .polynomial = 0xa7,
    .initial = 0x00,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc8Cdma2000 = Crc(u8, .{
    .polynomial = 0x9b,
    .initial = 0xff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8Darc = Crc(u8, .{
    .polynomial = 0x39,
    .initial = 0x00,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc8DvbS2 = Crc(u8, .{
    .polynomial = 0xd5,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8GsmA = Crc(u8, .{
    .polynomial = 0x1d,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8GsmB = Crc(u8, .{
    .polynomial = 0x49,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xff,
});

pub const Crc8Hitag = Crc(u8, .{
    .polynomial = 0x1d,
    .initial = 0xff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8I4321 = Crc(u8, .{
    .polynomial = 0x07,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x55,
});

pub const Crc8ICode = Crc(u8, .{
    .polynomial = 0x1d,
    .initial = 0xfd,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8Lte = Crc(u8, .{
    .polynomial = 0x9b,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8MaximDow = Crc(u8, .{
    .polynomial = 0x31,
    .initial = 0x00,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc8MifareMad = Crc(u8, .{
    .polynomial = 0x1d,
    .initial = 0xc7,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8Nrsc5 = Crc(u8, .{
    .polynomial = 0x31,
    .initial = 0xff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8Opensafety = Crc(u8, .{
    .polynomial = 0x2f,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8Rohc = Crc(u8, .{
    .polynomial = 0x07,
    .initial = 0xff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc8SaeJ1850 = Crc(u8, .{
    .polynomial = 0x1d,
    .initial = 0xff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xff,
});

pub const Crc8Smbus = Crc(u8, .{
    .polynomial = 0x07,
    .initial = 0x00,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00,
});

pub const Crc8Tech3250 = Crc(u8, .{
    .polynomial = 0x1d,
    .initial = 0xff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc8Wcdma = Crc(u8, .{
    .polynomial = 0x9b,
    .initial = 0x00,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00,
});

pub const Crc10Atm = Crc(u10, .{
    .polynomial = 0x233,
    .initial = 0x000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000,
});

pub const Crc10Cdma2000 = Crc(u10, .{
    .polynomial = 0x3d9,
    .initial = 0x3ff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000,
});

pub const Crc10Gsm = Crc(u10, .{
    .polynomial = 0x175,
    .initial = 0x000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x3ff,
});

pub const Crc11Flexray = Crc(u11, .{
    .polynomial = 0x385,
    .initial = 0x01a,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000,
});

pub const Crc11Umts = Crc(u11, .{
    .polynomial = 0x307,
    .initial = 0x000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000,
});

pub const Crc12Cdma2000 = Crc(u12, .{
    .polynomial = 0xf13,
    .initial = 0xfff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000,
});

pub const Crc12Dect = Crc(u12, .{
    .polynomial = 0x80f,
    .initial = 0x000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000,
});

pub const Crc12Gsm = Crc(u12, .{
    .polynomial = 0xd31,
    .initial = 0x000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xfff,
});

pub const Crc12Umts = Crc(u12, .{
    .polynomial = 0x80f,
    .initial = 0x000,
    .reflect_input = false,
    .reflect_output = true,
    .xor_output = 0x000,
});

pub const Crc13Bbc = Crc(u13, .{
    .polynomial = 0x1cf5,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc14Darc = Crc(u14, .{
    .polynomial = 0x0805,
    .initial = 0x0000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc14Gsm = Crc(u14, .{
    .polynomial = 0x202d,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x3fff,
});

pub const Crc15Can = Crc(u15, .{
    .polynomial = 0x4599,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc15Mpt1327 = Crc(u15, .{
    .polynomial = 0x6815,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0001,
});

pub const Crc16Arc = Crc(u16, .{
    .polynomial = 0x8005,
    .initial = 0x0000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16Cdma2000 = Crc(u16, .{
    .polynomial = 0xc867,
    .initial = 0xffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16Cms = Crc(u16, .{
    .polynomial = 0x8005,
    .initial = 0xffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16Dds110 = Crc(u16, .{
    .polynomial = 0x8005,
    .initial = 0x800d,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16DectR = Crc(u16, .{
    .polynomial = 0x0589,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0001,
});

pub const Crc16DectX = Crc(u16, .{
    .polynomial = 0x0589,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16Dnp = Crc(u16, .{
    .polynomial = 0x3d65,
    .initial = 0x0000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffff,
});

pub const Crc16En13757 = Crc(u16, .{
    .polynomial = 0x3d65,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffff,
});

pub const Crc16Genibus = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0xffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffff,
});

pub const Crc16Gsm = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffff,
});

pub const Crc16Ibm3740 = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0xffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16IbmSdlc = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0xffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffff,
});

pub const Crc16IsoIec144433A = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0xc6c6,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16Kermit = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0x0000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16Lj1200 = Crc(u16, .{
    .polynomial = 0x6f63,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16M17 = Crc(u16, .{
    .polynomial = 0x5935,
    .initial = 0xffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16MaximDow = Crc(u16, .{
    .polynomial = 0x8005,
    .initial = 0x0000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffff,
});

pub const Crc16Mcrf4xx = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0xffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16Modbus = Crc(u16, .{
    .polynomial = 0x8005,
    .initial = 0xffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16Nrsc5 = Crc(u16, .{
    .polynomial = 0x080b,
    .initial = 0xffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16OpensafetyA = Crc(u16, .{
    .polynomial = 0x5935,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16OpensafetyB = Crc(u16, .{
    .polynomial = 0x755b,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16Profibus = Crc(u16, .{
    .polynomial = 0x1dcf,
    .initial = 0xffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffff,
});

pub const Crc16Riello = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0xb2aa,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16SpiFujitsu = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0x1d0f,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16T10Dif = Crc(u16, .{
    .polynomial = 0x8bb7,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16Teledisk = Crc(u16, .{
    .polynomial = 0xa097,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16Tms37157 = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0x89ec,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000,
});

pub const Crc16Umts = Crc(u16, .{
    .polynomial = 0x8005,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc16Usb = Crc(u16, .{
    .polynomial = 0x8005,
    .initial = 0xffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffff,
});

pub const Crc16Xmodem = Crc(u16, .{
    .polynomial = 0x1021,
    .initial = 0x0000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000,
});

pub const Crc17CanFd = Crc(u17, .{
    .polynomial = 0x1685b,
    .initial = 0x00000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00000,
});

pub const Crc21CanFd = Crc(u21, .{
    .polynomial = 0x102899,
    .initial = 0x000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000000,
});

pub const Crc24Ble = Crc(u24, .{
    .polynomial = 0x00065b,
    .initial = 0x555555,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x000000,
});

pub const Crc24FlexrayA = Crc(u24, .{
    .polynomial = 0x5d6dcb,
    .initial = 0xfedcba,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000000,
});

pub const Crc24FlexrayB = Crc(u24, .{
    .polynomial = 0x5d6dcb,
    .initial = 0xabcdef,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000000,
});

pub const Crc24Interlaken = Crc(u24, .{
    .polynomial = 0x328b63,
    .initial = 0xffffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffffff,
});

pub const Crc24LteA = Crc(u24, .{
    .polynomial = 0x864cfb,
    .initial = 0x000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000000,
});

pub const Crc24LteB = Crc(u24, .{
    .polynomial = 0x800063,
    .initial = 0x000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000000,
});

pub const Crc24Openpgp = Crc(u24, .{
    .polynomial = 0x864cfb,
    .initial = 0xb704ce,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x000000,
});

pub const Crc24Os9 = Crc(u24, .{
    .polynomial = 0x800063,
    .initial = 0xffffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffffff,
});

pub const Crc30Cdma = Crc(u30, .{
    .polynomial = 0x2030b9c7,
    .initial = 0x3fffffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x3fffffff,
});

pub const Crc31Philips = Crc(u31, .{
    .polynomial = 0x04c11db7,
    .initial = 0x7fffffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x7fffffff,
});

pub const Crc32Aixm = Crc(u32, .{
    .polynomial = 0x814141ab,
    .initial = 0x00000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00000000,
});

pub const Crc32Autosar = Crc(u32, .{
    .polynomial = 0xf4acfb13,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffffffff,
});

pub const Crc32Base91D = Crc(u32, .{
    .polynomial = 0xa833982b,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffffffff,
});

pub const Crc32Bzip2 = Crc(u32, .{
    .polynomial = 0x04c11db7,
    .initial = 0xffffffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffffffff,
});

pub const Crc32CdRomEdc = Crc(u32, .{
    .polynomial = 0x8001801b,
    .initial = 0x00000000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00000000,
});

pub const Crc32Cksum = Crc(u32, .{
    .polynomial = 0x04c11db7,
    .initial = 0x00000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffffffff,
});

pub const Crc32Iscsi = Crc(u32, .{
    .polynomial = 0x1edc6f41,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffffffff,
});

pub const Crc32IsoHdlc = Crc(u32, .{
    .polynomial = 0x04c11db7,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffffffff,
});

pub const Crc32Jamcrc = Crc(u32, .{
    .polynomial = 0x04c11db7,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00000000,
});

pub const Crc32Koopman = Crc(u32, .{
    .polynomial = 0x741b8cd7,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffffffff,
});

pub const Crc32Mef = Crc(u32, .{
    .polynomial = 0x741b8cd7,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x00000000,
});

pub const Crc32Mpeg2 = Crc(u32, .{
    .polynomial = 0x04c11db7,
    .initial = 0xffffffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00000000,
});

pub const Crc32Xfer = Crc(u32, .{
    .polynomial = 0x000000af,
    .initial = 0x00000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x00000000,
});

pub const Crc40Gsm = Crc(u40, .{
    .polynomial = 0x0004820009,
    .initial = 0x0000000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffffffffff,
});

pub const Crc64Ecma182 = Crc(u64, .{
    .polynomial = 0x42f0e1eba9ea3693,
    .initial = 0x0000000000000000,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0x0000000000000000,
});

pub const Crc64GoIso = Crc(u64, .{
    .polynomial = 0x000000000000001b,
    .initial = 0xffffffffffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffffffffffffffff,
});

pub const Crc64Ms = Crc(u64, .{
    .polynomial = 0x259c84cba6426349,
    .initial = 0xffffffffffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000000000000000,
});

pub const Crc64Redis = Crc(u64, .{
    .polynomial = 0xad93d23594c935a9,
    .initial = 0x0000000000000000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000000000000000,
});

pub const Crc64We = Crc(u64, .{
    .polynomial = 0x42f0e1eba9ea3693,
    .initial = 0xffffffffffffffff,
    .reflect_input = false,
    .reflect_output = false,
    .xor_output = 0xffffffffffffffff,
});

pub const Crc64Xz = Crc(u64, .{
    .polynomial = 0x42f0e1eba9ea3693,
    .initial = 0xffffffffffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0xffffffffffffffff,
});

pub const Crc82Darc = Crc(u82, .{
    .polynomial = 0x0308c0111011401440411,
    .initial = 0x000000000000000000000,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x000000000000000000000,
});
// There is a generic CRC implementation "Crc()" which can be parameterized via
// the Algorithm struct for a plethora of uses.
//
// The primary interface for all of the standard CRC algorithms is the
// generated file "crc.zig", which uses the implementation code here to define
// many standard CRCs.

const std = @import("std");

pub fn Algorithm(comptime W: type) type {
    return struct {
        polynomial: W,
        initial: W,
        reflect_input: bool,
        reflect_output: bool,
        xor_output: W,
    };
}

pub fn Crc(comptime W: type, comptime algorithm: Algorithm(W)) type {
    return struct {
        const Self = @This();
        const I = if (@bitSizeOf(W) < 8) u8 else W;
        const lookup_table = blk: {
            @setEvalBranchQuota(2500);

            const poly = if (algorithm.reflect_input)
                @bitReverse(@as(I, algorithm.polynomial)) >> (@bitSizeOf(I) - @bitSizeOf(W))
            else
                @as(I, algorithm.polynomial) << (@bitSizeOf(I) - @bitSizeOf(W));

            var table: [256]I = undefined;
            for (&table, 0..) |*e, i| {
                var crc: I = i;
                if (algorithm.reflect_input) {
                    var j: usize = 0;
                    while (j < 8) : (j += 1) {
                        crc = (crc >> 1) ^ ((crc & 1) * poly);
                    }
                } else {
                    crc <<= @bitSizeOf(I) - 8;
                    var j: usize = 0;
                    while (j < 8) : (j += 1) {
                        crc = (crc << 1) ^ (((crc >> (@bitSizeOf(I) - 1)) & 1) * poly);
                    }
                }
                e.* = crc;
            }
            break :blk table;
        };

        crc: I,

        pub fn init() Self {
            const initial = if (algorithm.reflect_input)
                @bitReverse(@as(I, algorithm.initial)) >> (@bitSizeOf(I) - @bitSizeOf(W))
            else
                @as(I, algorithm.initial) << (@bitSizeOf(I) - @bitSizeOf(W));
            return Self{ .crc = initial };
        }

        inline fn tableEntry(index: I) I {
            return lookup_table[@as(u8, @intCast(index & 0xFF))];
        }

        pub fn update(self: *Self, bytes: []const u8) void {
            var i: usize = 0;
            if (@bitSizeOf(I) <= 8) {
                while (i < bytes.len) : (i += 1) {
                    self.crc = tableEntry(self.crc ^ bytes[i]);
                }
            } else if (algorithm.reflect_input) {
                while (i < bytes.len) : (i += 1) {
                    const table_index = self.crc ^ bytes[i];
                    self.crc = tableEntry(table_index) ^ (self.crc >> 8);
                }
            } else {
                while (i < bytes.len) : (i += 1) {
                    const table_index = (self.crc >> (@bitSizeOf(I) - 8)) ^ bytes[i];
                    self.crc = tableEntry(table_index) ^ (self.crc << 8);
                }
            }
        }

        pub fn final(self: Self) W {
            var c = self.crc;
            if (algorithm.reflect_input != algorithm.reflect_output) {
                c = @bitReverse(c);
            }
            if (!algorithm.reflect_output) {
                c >>= @bitSizeOf(I) - @bitSizeOf(W);
            }
            return @as(W, @intCast(c ^ algorithm.xor_output));
        }

        pub fn hash(bytes: []const u8) W {
            var c = Self.init();
            c.update(bytes);
            return c.final();
        }
    };
}

pub const Polynomial = enum(u32) {
    IEEE = @compileError("use Crc with algorithm .Crc32IsoHdlc"),
    Castagnoli = @compileError("use Crc with algorithm .Crc32Iscsi"),
    Koopman = @compileError("use Crc with algorithm .Crc32Koopman"),
    _,
};

pub const Crc32WithPoly = @compileError("use Crc instead");
pub const Crc32SmallWithPoly = @compileError("use Crc instead");
//! This file is auto-generated by tools/update_crc_catalog.zig.

const std = @import("std");
const testing = std.testing;
const verify = @import("../verify.zig");
const crc = @import("../crc.zig");

test "crc32 ieee regression" {
    const crc32 = crc.Crc32IsoHdlc;
    try testing.expectEqual(crc32.hash(""), 0x00000000);
    try testing.expectEqual(crc32.hash("a"), 0xe8b7be43);
    try testing.expectEqual(crc32.hash("abc"), 0x352441c2);
}

test "crc32 castagnoli regression" {
    const crc32 = crc.Crc32Iscsi;
    try testing.expectEqual(crc32.hash(""), 0x00000000);
    try testing.expectEqual(crc32.hash("a"), 0xc1d04330);
    try testing.expectEqual(crc32.hash("abc"), 0x364b3fb7);
}

test "crc32 koopman regression" {
    const crc32 = crc.Crc32Koopman;
    try testing.expectEqual(crc32.hash(""), 0x00000000);
    try testing.expectEqual(crc32.hash("a"), 0x0da2aa8a);
    try testing.expectEqual(crc32.hash("abc"), 0xba2322ac);
}

test "CRC-3/GSM" {
    const Crc3Gsm = crc.Crc3Gsm;

    try testing.expectEqual(@as(u3, 0x4), Crc3Gsm.hash("123456789"));

    var c = Crc3Gsm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u3, 0x4), c.final());
}

test "CRC-3/ROHC" {
    const Crc3Rohc = crc.Crc3Rohc;

    try testing.expectEqual(@as(u3, 0x6), Crc3Rohc.hash("123456789"));

    var c = Crc3Rohc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u3, 0x6), c.final());
}

test "CRC-4/G-704" {
    const Crc4G704 = crc.Crc4G704;

    try testing.expectEqual(@as(u4, 0x7), Crc4G704.hash("123456789"));

    var c = Crc4G704.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u4, 0x7), c.final());
}

test "CRC-4/INTERLAKEN" {
    const Crc4Interlaken = crc.Crc4Interlaken;

    try testing.expectEqual(@as(u4, 0xb), Crc4Interlaken.hash("123456789"));

    var c = Crc4Interlaken.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u4, 0xb), c.final());
}

test "CRC-5/EPC-C1G2" {
    const Crc5EpcC1g2 = crc.Crc5EpcC1g2;

    try testing.expectEqual(@as(u5, 0x00), Crc5EpcC1g2.hash("123456789"));

    var c = Crc5EpcC1g2.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u5, 0x00), c.final());
}

test "CRC-5/G-704" {
    const Crc5G704 = crc.Crc5G704;

    try testing.expectEqual(@as(u5, 0x07), Crc5G704.hash("123456789"));

    var c = Crc5G704.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u5, 0x07), c.final());
}

test "CRC-5/USB" {
    const Crc5Usb = crc.Crc5Usb;

    try testing.expectEqual(@as(u5, 0x19), Crc5Usb.hash("123456789"));

    var c = Crc5Usb.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u5, 0x19), c.final());
}

test "CRC-6/CDMA2000-A" {
    const Crc6Cdma2000A = crc.Crc6Cdma2000A;

    try testing.expectEqual(@as(u6, 0x0d), Crc6Cdma2000A.hash("123456789"));

    var c = Crc6Cdma2000A.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u6, 0x0d), c.final());
}

test "CRC-6/CDMA2000-B" {
    const Crc6Cdma2000B = crc.Crc6Cdma2000B;

    try testing.expectEqual(@as(u6, 0x3b), Crc6Cdma2000B.hash("123456789"));

    var c = Crc6Cdma2000B.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u6, 0x3b), c.final());
}

test "CRC-6/DARC" {
    const Crc6Darc = crc.Crc6Darc;

    try testing.expectEqual(@as(u6, 0x26), Crc6Darc.hash("123456789"));

    var c = Crc6Darc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u6, 0x26), c.final());
}

test "CRC-6/G-704" {
    const Crc6G704 = crc.Crc6G704;

    try testing.expectEqual(@as(u6, 0x06), Crc6G704.hash("123456789"));

    var c = Crc6G704.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u6, 0x06), c.final());
}

test "CRC-6/GSM" {
    const Crc6Gsm = crc.Crc6Gsm;

    try testing.expectEqual(@as(u6, 0x13), Crc6Gsm.hash("123456789"));

    var c = Crc6Gsm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u6, 0x13), c.final());
}

test "CRC-7/MMC" {
    const Crc7Mmc = crc.Crc7Mmc;

    try testing.expectEqual(@as(u7, 0x75), Crc7Mmc.hash("123456789"));

    var c = Crc7Mmc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u7, 0x75), c.final());
}

test "CRC-7/ROHC" {
    const Crc7Rohc = crc.Crc7Rohc;

    try testing.expectEqual(@as(u7, 0x53), Crc7Rohc.hash("123456789"));

    var c = Crc7Rohc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u7, 0x53), c.final());
}

test "CRC-7/UMTS" {
    const Crc7Umts = crc.Crc7Umts;

    try testing.expectEqual(@as(u7, 0x61), Crc7Umts.hash("123456789"));

    var c = Crc7Umts.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u7, 0x61), c.final());
}

test "CRC-8/AUTOSAR" {
    const Crc8Autosar = crc.Crc8Autosar;

    try testing.expectEqual(@as(u8, 0xdf), Crc8Autosar.hash("123456789"));

    var c = Crc8Autosar.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xdf), c.final());
}

test "CRC-8/BLUETOOTH" {
    const Crc8Bluetooth = crc.Crc8Bluetooth;

    try testing.expectEqual(@as(u8, 0x26), Crc8Bluetooth.hash("123456789"));

    var c = Crc8Bluetooth.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x26), c.final());
}

test "CRC-8/CDMA2000" {
    const Crc8Cdma2000 = crc.Crc8Cdma2000;

    try testing.expectEqual(@as(u8, 0xda), Crc8Cdma2000.hash("123456789"));

    var c = Crc8Cdma2000.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xda), c.final());
}

test "CRC-8/DARC" {
    const Crc8Darc = crc.Crc8Darc;

    try testing.expectEqual(@as(u8, 0x15), Crc8Darc.hash("123456789"));

    var c = Crc8Darc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x15), c.final());
}

test "CRC-8/DVB-S2" {
    const Crc8DvbS2 = crc.Crc8DvbS2;

    try testing.expectEqual(@as(u8, 0xbc), Crc8DvbS2.hash("123456789"));

    var c = Crc8DvbS2.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xbc), c.final());
}

test "CRC-8/GSM-A" {
    const Crc8GsmA = crc.Crc8GsmA;

    try testing.expectEqual(@as(u8, 0x37), Crc8GsmA.hash("123456789"));

    var c = Crc8GsmA.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x37), c.final());
}

test "CRC-8/GSM-B" {
    const Crc8GsmB = crc.Crc8GsmB;

    try testing.expectEqual(@as(u8, 0x94), Crc8GsmB.hash("123456789"));

    var c = Crc8GsmB.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x94), c.final());
}

test "CRC-8/HITAG" {
    const Crc8Hitag = crc.Crc8Hitag;

    try testing.expectEqual(@as(u8, 0xb4), Crc8Hitag.hash("123456789"));

    var c = Crc8Hitag.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xb4), c.final());
}

test "CRC-8/I-432-1" {
    const Crc8I4321 = crc.Crc8I4321;

    try testing.expectEqual(@as(u8, 0xa1), Crc8I4321.hash("123456789"));

    var c = Crc8I4321.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xa1), c.final());
}

test "CRC-8/I-CODE" {
    const Crc8ICode = crc.Crc8ICode;

    try testing.expectEqual(@as(u8, 0x7e), Crc8ICode.hash("123456789"));

    var c = Crc8ICode.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x7e), c.final());
}

test "CRC-8/LTE" {
    const Crc8Lte = crc.Crc8Lte;

    try testing.expectEqual(@as(u8, 0xea), Crc8Lte.hash("123456789"));

    var c = Crc8Lte.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xea), c.final());
}

test "CRC-8/MAXIM-DOW" {
    const Crc8MaximDow = crc.Crc8MaximDow;

    try testing.expectEqual(@as(u8, 0xa1), Crc8MaximDow.hash("123456789"));

    var c = Crc8MaximDow.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xa1), c.final());
}

test "CRC-8/MIFARE-MAD" {
    const Crc8MifareMad = crc.Crc8MifareMad;

    try testing.expectEqual(@as(u8, 0x99), Crc8MifareMad.hash("123456789"));

    var c = Crc8MifareMad.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x99), c.final());
}

test "CRC-8/NRSC-5" {
    const Crc8Nrsc5 = crc.Crc8Nrsc5;

    try testing.expectEqual(@as(u8, 0xf7), Crc8Nrsc5.hash("123456789"));

    var c = Crc8Nrsc5.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xf7), c.final());
}

test "CRC-8/OPENSAFETY" {
    const Crc8Opensafety = crc.Crc8Opensafety;

    try testing.expectEqual(@as(u8, 0x3e), Crc8Opensafety.hash("123456789"));

    var c = Crc8Opensafety.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x3e), c.final());
}

test "CRC-8/ROHC" {
    const Crc8Rohc = crc.Crc8Rohc;

    try testing.expectEqual(@as(u8, 0xd0), Crc8Rohc.hash("123456789"));

    var c = Crc8Rohc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xd0), c.final());
}

test "CRC-8/SAE-J1850" {
    const Crc8SaeJ1850 = crc.Crc8SaeJ1850;

    try testing.expectEqual(@as(u8, 0x4b), Crc8SaeJ1850.hash("123456789"));

    var c = Crc8SaeJ1850.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x4b), c.final());
}

test "CRC-8/SMBUS" {
    const Crc8Smbus = crc.Crc8Smbus;

    try testing.expectEqual(@as(u8, 0xf4), Crc8Smbus.hash("123456789"));

    var c = Crc8Smbus.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0xf4), c.final());
}

test "CRC-8/TECH-3250" {
    const Crc8Tech3250 = crc.Crc8Tech3250;

    try testing.expectEqual(@as(u8, 0x97), Crc8Tech3250.hash("123456789"));

    var c = Crc8Tech3250.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x97), c.final());
}

test "CRC-8/WCDMA" {
    const Crc8Wcdma = crc.Crc8Wcdma;

    try testing.expectEqual(@as(u8, 0x25), Crc8Wcdma.hash("123456789"));

    var c = Crc8Wcdma.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u8, 0x25), c.final());
}

test "CRC-10/ATM" {
    const Crc10Atm = crc.Crc10Atm;

    try testing.expectEqual(@as(u10, 0x199), Crc10Atm.hash("123456789"));

    var c = Crc10Atm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u10, 0x199), c.final());
}

test "CRC-10/CDMA2000" {
    const Crc10Cdma2000 = crc.Crc10Cdma2000;

    try testing.expectEqual(@as(u10, 0x233), Crc10Cdma2000.hash("123456789"));

    var c = Crc10Cdma2000.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u10, 0x233), c.final());
}

test "CRC-10/GSM" {
    const Crc10Gsm = crc.Crc10Gsm;

    try testing.expectEqual(@as(u10, 0x12a), Crc10Gsm.hash("123456789"));

    var c = Crc10Gsm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u10, 0x12a), c.final());
}

test "CRC-11/FLEXRAY" {
    const Crc11Flexray = crc.Crc11Flexray;

    try testing.expectEqual(@as(u11, 0x5a3), Crc11Flexray.hash("123456789"));

    var c = Crc11Flexray.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u11, 0x5a3), c.final());
}

test "CRC-11/UMTS" {
    const Crc11Umts = crc.Crc11Umts;

    try testing.expectEqual(@as(u11, 0x061), Crc11Umts.hash("123456789"));

    var c = Crc11Umts.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u11, 0x061), c.final());
}

test "CRC-12/CDMA2000" {
    const Crc12Cdma2000 = crc.Crc12Cdma2000;

    try testing.expectEqual(@as(u12, 0xd4d), Crc12Cdma2000.hash("123456789"));

    var c = Crc12Cdma2000.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u12, 0xd4d), c.final());
}

test "CRC-12/DECT" {
    const Crc12Dect = crc.Crc12Dect;

    try testing.expectEqual(@as(u12, 0xf5b), Crc12Dect.hash("123456789"));

    var c = Crc12Dect.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u12, 0xf5b), c.final());
}

test "CRC-12/GSM" {
    const Crc12Gsm = crc.Crc12Gsm;

    try testing.expectEqual(@as(u12, 0xb34), Crc12Gsm.hash("123456789"));

    var c = Crc12Gsm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u12, 0xb34), c.final());
}

test "CRC-12/UMTS" {
    const Crc12Umts = crc.Crc12Umts;

    try testing.expectEqual(@as(u12, 0xdaf), Crc12Umts.hash("123456789"));

    var c = Crc12Umts.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u12, 0xdaf), c.final());
}

test "CRC-13/BBC" {
    const Crc13Bbc = crc.Crc13Bbc;

    try testing.expectEqual(@as(u13, 0x04fa), Crc13Bbc.hash("123456789"));

    var c = Crc13Bbc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u13, 0x04fa), c.final());
}

test "CRC-14/DARC" {
    const Crc14Darc = crc.Crc14Darc;

    try testing.expectEqual(@as(u14, 0x082d), Crc14Darc.hash("123456789"));

    var c = Crc14Darc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u14, 0x082d), c.final());
}

test "CRC-14/GSM" {
    const Crc14Gsm = crc.Crc14Gsm;

    try testing.expectEqual(@as(u14, 0x30ae), Crc14Gsm.hash("123456789"));

    var c = Crc14Gsm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u14, 0x30ae), c.final());
}

test "CRC-15/CAN" {
    const Crc15Can = crc.Crc15Can;

    try testing.expectEqual(@as(u15, 0x059e), Crc15Can.hash("123456789"));

    var c = Crc15Can.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u15, 0x059e), c.final());
}

test "CRC-15/MPT1327" {
    const Crc15Mpt1327 = crc.Crc15Mpt1327;

    try testing.expectEqual(@as(u15, 0x2566), Crc15Mpt1327.hash("123456789"));

    var c = Crc15Mpt1327.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u15, 0x2566), c.final());
}

test "CRC-16/ARC" {
    const Crc16Arc = crc.Crc16Arc;

    try testing.expectEqual(@as(u16, 0xbb3d), Crc16Arc.hash("123456789"));

    var c = Crc16Arc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xbb3d), c.final());
}

test "CRC-16/CDMA2000" {
    const Crc16Cdma2000 = crc.Crc16Cdma2000;

    try testing.expectEqual(@as(u16, 0x4c06), Crc16Cdma2000.hash("123456789"));

    var c = Crc16Cdma2000.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x4c06), c.final());
}

test "CRC-16/CMS" {
    const Crc16Cms = crc.Crc16Cms;

    try testing.expectEqual(@as(u16, 0xaee7), Crc16Cms.hash("123456789"));

    var c = Crc16Cms.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xaee7), c.final());
}

test "CRC-16/DDS-110" {
    const Crc16Dds110 = crc.Crc16Dds110;

    try testing.expectEqual(@as(u16, 0x9ecf), Crc16Dds110.hash("123456789"));

    var c = Crc16Dds110.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x9ecf), c.final());
}

test "CRC-16/DECT-R" {
    const Crc16DectR = crc.Crc16DectR;

    try testing.expectEqual(@as(u16, 0x007e), Crc16DectR.hash("123456789"));

    var c = Crc16DectR.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x007e), c.final());
}

test "CRC-16/DECT-X" {
    const Crc16DectX = crc.Crc16DectX;

    try testing.expectEqual(@as(u16, 0x007f), Crc16DectX.hash("123456789"));

    var c = Crc16DectX.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x007f), c.final());
}

test "CRC-16/DNP" {
    const Crc16Dnp = crc.Crc16Dnp;

    try testing.expectEqual(@as(u16, 0xea82), Crc16Dnp.hash("123456789"));

    var c = Crc16Dnp.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xea82), c.final());
}

test "CRC-16/EN-13757" {
    const Crc16En13757 = crc.Crc16En13757;

    try testing.expectEqual(@as(u16, 0xc2b7), Crc16En13757.hash("123456789"));

    var c = Crc16En13757.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xc2b7), c.final());
}

test "CRC-16/GENIBUS" {
    const Crc16Genibus = crc.Crc16Genibus;

    try testing.expectEqual(@as(u16, 0xd64e), Crc16Genibus.hash("123456789"));

    var c = Crc16Genibus.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xd64e), c.final());
}

test "CRC-16/GSM" {
    const Crc16Gsm = crc.Crc16Gsm;

    try testing.expectEqual(@as(u16, 0xce3c), Crc16Gsm.hash("123456789"));

    var c = Crc16Gsm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xce3c), c.final());
}

test "CRC-16/IBM-3740" {
    const Crc16Ibm3740 = crc.Crc16Ibm3740;

    try testing.expectEqual(@as(u16, 0x29b1), Crc16Ibm3740.hash("123456789"));

    var c = Crc16Ibm3740.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x29b1), c.final());
}

test "CRC-16/IBM-SDLC" {
    const Crc16IbmSdlc = crc.Crc16IbmSdlc;

    try testing.expectEqual(@as(u16, 0x906e), Crc16IbmSdlc.hash("123456789"));

    var c = Crc16IbmSdlc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x906e), c.final());
}

test "CRC-16/ISO-IEC-14443-3-A" {
    const Crc16IsoIec144433A = crc.Crc16IsoIec144433A;

    try testing.expectEqual(@as(u16, 0xbf05), Crc16IsoIec144433A.hash("123456789"));

    var c = Crc16IsoIec144433A.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xbf05), c.final());
}

test "CRC-16/KERMIT" {
    const Crc16Kermit = crc.Crc16Kermit;

    try testing.expectEqual(@as(u16, 0x2189), Crc16Kermit.hash("123456789"));

    var c = Crc16Kermit.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x2189), c.final());
}

test "CRC-16/LJ1200" {
    const Crc16Lj1200 = crc.Crc16Lj1200;

    try testing.expectEqual(@as(u16, 0xbdf4), Crc16Lj1200.hash("123456789"));

    var c = Crc16Lj1200.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xbdf4), c.final());
}

test "CRC-16/M17" {
    const Crc16M17 = crc.Crc16M17;

    try testing.expectEqual(@as(u16, 0x772b), Crc16M17.hash("123456789"));

    var c = Crc16M17.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x772b), c.final());
}

test "CRC-16/MAXIM-DOW" {
    const Crc16MaximDow = crc.Crc16MaximDow;

    try testing.expectEqual(@as(u16, 0x44c2), Crc16MaximDow.hash("123456789"));

    var c = Crc16MaximDow.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x44c2), c.final());
}

test "CRC-16/MCRF4XX" {
    const Crc16Mcrf4xx = crc.Crc16Mcrf4xx;

    try testing.expectEqual(@as(u16, 0x6f91), Crc16Mcrf4xx.hash("123456789"));

    var c = Crc16Mcrf4xx.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x6f91), c.final());
}

test "CRC-16/MODBUS" {
    const Crc16Modbus = crc.Crc16Modbus;

    try testing.expectEqual(@as(u16, 0x4b37), Crc16Modbus.hash("123456789"));

    var c = Crc16Modbus.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x4b37), c.final());
}

test "CRC-16/NRSC-5" {
    const Crc16Nrsc5 = crc.Crc16Nrsc5;

    try testing.expectEqual(@as(u16, 0xa066), Crc16Nrsc5.hash("123456789"));

    var c = Crc16Nrsc5.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xa066), c.final());
}

test "CRC-16/OPENSAFETY-A" {
    const Crc16OpensafetyA = crc.Crc16OpensafetyA;

    try testing.expectEqual(@as(u16, 0x5d38), Crc16OpensafetyA.hash("123456789"));

    var c = Crc16OpensafetyA.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x5d38), c.final());
}

test "CRC-16/OPENSAFETY-B" {
    const Crc16OpensafetyB = crc.Crc16OpensafetyB;

    try testing.expectEqual(@as(u16, 0x20fe), Crc16OpensafetyB.hash("123456789"));

    var c = Crc16OpensafetyB.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x20fe), c.final());
}

test "CRC-16/PROFIBUS" {
    const Crc16Profibus = crc.Crc16Profibus;

    try testing.expectEqual(@as(u16, 0xa819), Crc16Profibus.hash("123456789"));

    var c = Crc16Profibus.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xa819), c.final());
}

test "CRC-16/RIELLO" {
    const Crc16Riello = crc.Crc16Riello;

    try testing.expectEqual(@as(u16, 0x63d0), Crc16Riello.hash("123456789"));

    var c = Crc16Riello.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x63d0), c.final());
}

test "CRC-16/SPI-FUJITSU" {
    const Crc16SpiFujitsu = crc.Crc16SpiFujitsu;

    try testing.expectEqual(@as(u16, 0xe5cc), Crc16SpiFujitsu.hash("123456789"));

    var c = Crc16SpiFujitsu.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xe5cc), c.final());
}

test "CRC-16/T10-DIF" {
    const Crc16T10Dif = crc.Crc16T10Dif;

    try testing.expectEqual(@as(u16, 0xd0db), Crc16T10Dif.hash("123456789"));

    var c = Crc16T10Dif.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xd0db), c.final());
}

test "CRC-16/TELEDISK" {
    const Crc16Teledisk = crc.Crc16Teledisk;

    try testing.expectEqual(@as(u16, 0x0fb3), Crc16Teledisk.hash("123456789"));

    var c = Crc16Teledisk.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x0fb3), c.final());
}

test "CRC-16/TMS37157" {
    const Crc16Tms37157 = crc.Crc16Tms37157;

    try testing.expectEqual(@as(u16, 0x26b1), Crc16Tms37157.hash("123456789"));

    var c = Crc16Tms37157.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x26b1), c.final());
}

test "CRC-16/UMTS" {
    const Crc16Umts = crc.Crc16Umts;

    try testing.expectEqual(@as(u16, 0xfee8), Crc16Umts.hash("123456789"));

    var c = Crc16Umts.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xfee8), c.final());
}

test "CRC-16/USB" {
    const Crc16Usb = crc.Crc16Usb;

    try testing.expectEqual(@as(u16, 0xb4c8), Crc16Usb.hash("123456789"));

    var c = Crc16Usb.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0xb4c8), c.final());
}

test "CRC-16/XMODEM" {
    const Crc16Xmodem = crc.Crc16Xmodem;

    try testing.expectEqual(@as(u16, 0x31c3), Crc16Xmodem.hash("123456789"));

    var c = Crc16Xmodem.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u16, 0x31c3), c.final());
}

test "CRC-17/CAN-FD" {
    const Crc17CanFd = crc.Crc17CanFd;

    try testing.expectEqual(@as(u17, 0x04f03), Crc17CanFd.hash("123456789"));

    var c = Crc17CanFd.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u17, 0x04f03), c.final());
}

test "CRC-21/CAN-FD" {
    const Crc21CanFd = crc.Crc21CanFd;

    try testing.expectEqual(@as(u21, 0x0ed841), Crc21CanFd.hash("123456789"));

    var c = Crc21CanFd.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u21, 0x0ed841), c.final());
}

test "CRC-24/BLE" {
    const Crc24Ble = crc.Crc24Ble;

    try testing.expectEqual(@as(u24, 0xc25a56), Crc24Ble.hash("123456789"));

    var c = Crc24Ble.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0xc25a56), c.final());
}

test "CRC-24/FLEXRAY-A" {
    const Crc24FlexrayA = crc.Crc24FlexrayA;

    try testing.expectEqual(@as(u24, 0x7979bd), Crc24FlexrayA.hash("123456789"));

    var c = Crc24FlexrayA.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0x7979bd), c.final());
}

test "CRC-24/FLEXRAY-B" {
    const Crc24FlexrayB = crc.Crc24FlexrayB;

    try testing.expectEqual(@as(u24, 0x1f23b8), Crc24FlexrayB.hash("123456789"));

    var c = Crc24FlexrayB.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0x1f23b8), c.final());
}

test "CRC-24/INTERLAKEN" {
    const Crc24Interlaken = crc.Crc24Interlaken;

    try testing.expectEqual(@as(u24, 0xb4f3e6), Crc24Interlaken.hash("123456789"));

    var c = Crc24Interlaken.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0xb4f3e6), c.final());
}

test "CRC-24/LTE-A" {
    const Crc24LteA = crc.Crc24LteA;

    try testing.expectEqual(@as(u24, 0xcde703), Crc24LteA.hash("123456789"));

    var c = Crc24LteA.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0xcde703), c.final());
}

test "CRC-24/LTE-B" {
    const Crc24LteB = crc.Crc24LteB;

    try testing.expectEqual(@as(u24, 0x23ef52), Crc24LteB.hash("123456789"));

    var c = Crc24LteB.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0x23ef52), c.final());
}

test "CRC-24/OPENPGP" {
    const Crc24Openpgp = crc.Crc24Openpgp;

    try testing.expectEqual(@as(u24, 0x21cf02), Crc24Openpgp.hash("123456789"));

    var c = Crc24Openpgp.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0x21cf02), c.final());
}

test "CRC-24/OS-9" {
    const Crc24Os9 = crc.Crc24Os9;

    try testing.expectEqual(@as(u24, 0x200fa5), Crc24Os9.hash("123456789"));

    var c = Crc24Os9.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u24, 0x200fa5), c.final());
}

test "CRC-30/CDMA" {
    const Crc30Cdma = crc.Crc30Cdma;

    try testing.expectEqual(@as(u30, 0x04c34abf), Crc30Cdma.hash("123456789"));

    var c = Crc30Cdma.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u30, 0x04c34abf), c.final());
}

test "CRC-31/PHILIPS" {
    const Crc31Philips = crc.Crc31Philips;

    try testing.expectEqual(@as(u31, 0x0ce9e46c), Crc31Philips.hash("123456789"));

    var c = Crc31Philips.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u31, 0x0ce9e46c), c.final());
}

test "CRC-32/AIXM" {
    const Crc32Aixm = crc.Crc32Aixm;

    try testing.expectEqual(@as(u32, 0x3010bf7f), Crc32Aixm.hash("123456789"));

    var c = Crc32Aixm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x3010bf7f), c.final());
}

test "CRC-32/AUTOSAR" {
    const Crc32Autosar = crc.Crc32Autosar;

    try testing.expectEqual(@as(u32, 0x1697d06a), Crc32Autosar.hash("123456789"));

    var c = Crc32Autosar.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x1697d06a), c.final());
}

test "CRC-32/BASE91-D" {
    const Crc32Base91D = crc.Crc32Base91D;

    try testing.expectEqual(@as(u32, 0x87315576), Crc32Base91D.hash("123456789"));

    var c = Crc32Base91D.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x87315576), c.final());
}

test "CRC-32/BZIP2" {
    const Crc32Bzip2 = crc.Crc32Bzip2;

    try testing.expectEqual(@as(u32, 0xfc891918), Crc32Bzip2.hash("123456789"));

    var c = Crc32Bzip2.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0xfc891918), c.final());
}

test "CRC-32/CD-ROM-EDC" {
    const Crc32CdRomEdc = crc.Crc32CdRomEdc;

    try testing.expectEqual(@as(u32, 0x6ec2edc4), Crc32CdRomEdc.hash("123456789"));

    var c = Crc32CdRomEdc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x6ec2edc4), c.final());
}

test "CRC-32/CKSUM" {
    const Crc32Cksum = crc.Crc32Cksum;

    try testing.expectEqual(@as(u32, 0x765e7680), Crc32Cksum.hash("123456789"));

    var c = Crc32Cksum.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x765e7680), c.final());
}

test "CRC-32/ISCSI" {
    const Crc32Iscsi = crc.Crc32Iscsi;

    try testing.expectEqual(@as(u32, 0xe3069283), Crc32Iscsi.hash("123456789"));

    var c = Crc32Iscsi.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0xe3069283), c.final());
}

test "CRC-32/ISO-HDLC" {
    const Crc32IsoHdlc = crc.Crc32IsoHdlc;

    try testing.expectEqual(@as(u32, 0xcbf43926), Crc32IsoHdlc.hash("123456789"));

    var c = Crc32IsoHdlc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0xcbf43926), c.final());
}

test "CRC-32/JAMCRC" {
    const Crc32Jamcrc = crc.Crc32Jamcrc;

    try testing.expectEqual(@as(u32, 0x340bc6d9), Crc32Jamcrc.hash("123456789"));

    var c = Crc32Jamcrc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x340bc6d9), c.final());
}

test "CRC-32/KOOPMAN" {
    const Crc32Koopman = crc.Crc32Koopman;

    try testing.expectEqual(@as(u32, 0x2d3dd0ae), Crc32Koopman.hash("123456789"));

    var c = Crc32Koopman.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x2d3dd0ae), c.final());
}

test "CRC-32/MEF" {
    const Crc32Mef = crc.Crc32Mef;

    try testing.expectEqual(@as(u32, 0xd2c22f51), Crc32Mef.hash("123456789"));

    var c = Crc32Mef.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0xd2c22f51), c.final());
}

test "CRC-32/MPEG-2" {
    const Crc32Mpeg2 = crc.Crc32Mpeg2;

    try testing.expectEqual(@as(u32, 0x0376e6e7), Crc32Mpeg2.hash("123456789"));

    var c = Crc32Mpeg2.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0x0376e6e7), c.final());
}

test "CRC-32/XFER" {
    const Crc32Xfer = crc.Crc32Xfer;

    try testing.expectEqual(@as(u32, 0xbd0be338), Crc32Xfer.hash("123456789"));

    var c = Crc32Xfer.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u32, 0xbd0be338), c.final());
}

test "CRC-40/GSM" {
    const Crc40Gsm = crc.Crc40Gsm;

    try testing.expectEqual(@as(u40, 0xd4164fc646), Crc40Gsm.hash("123456789"));

    var c = Crc40Gsm.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u40, 0xd4164fc646), c.final());
}

test "CRC-64/ECMA-182" {
    const Crc64Ecma182 = crc.Crc64Ecma182;

    try testing.expectEqual(@as(u64, 0x6c40df5f0b497347), Crc64Ecma182.hash("123456789"));

    var c = Crc64Ecma182.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u64, 0x6c40df5f0b497347), c.final());
}

test "CRC-64/GO-ISO" {
    const Crc64GoIso = crc.Crc64GoIso;

    try testing.expectEqual(@as(u64, 0xb90956c775a41001), Crc64GoIso.hash("123456789"));

    var c = Crc64GoIso.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u64, 0xb90956c775a41001), c.final());
}

test "CRC-64/MS" {
    const Crc64Ms = crc.Crc64Ms;

    try testing.expectEqual(@as(u64, 0x75d4b74f024eceea), Crc64Ms.hash("123456789"));

    var c = Crc64Ms.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u64, 0x75d4b74f024eceea), c.final());
}

test "CRC-64/REDIS" {
    const Crc64Redis = crc.Crc64Redis;

    try testing.expectEqual(@as(u64, 0xe9c6d914c4b8d9ca), Crc64Redis.hash("123456789"));

    var c = Crc64Redis.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u64, 0xe9c6d914c4b8d9ca), c.final());
}

test "CRC-64/WE" {
    const Crc64We = crc.Crc64We;

    try testing.expectEqual(@as(u64, 0x62ec59e3f1a4f00a), Crc64We.hash("123456789"));

    var c = Crc64We.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u64, 0x62ec59e3f1a4f00a), c.final());
}

test "CRC-64/XZ" {
    const Crc64Xz = crc.Crc64Xz;

    try testing.expectEqual(@as(u64, 0x995dc9bbdf1939fa), Crc64Xz.hash("123456789"));

    var c = Crc64Xz.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u64, 0x995dc9bbdf1939fa), c.final());
}

test "CRC-82/DARC" {
    const Crc82Darc = crc.Crc82Darc;

    try testing.expectEqual(@as(u82, 0x09ea83f625023801fd612), Crc82Darc.hash("123456789"));

    var c = Crc82Darc.init();
    c.update("1234");
    c.update("56789");
    try testing.expectEqual(@as(u82, 0x09ea83f625023801fd612), c.final());
}
// FNV1a - Fowler-Noll-Vo hash function
//
// FNV1a is a fast, non-cryptographic hash function with fairly good distribution properties.
//
// https://tools.ietf.org/html/draft-eastlake-fnv-14

const std = @import("std");
const testing = std.testing;

pub const Fnv1a_32 = Fnv1a(u32, 0x01000193, 0x811c9dc5);
pub const Fnv1a_64 = Fnv1a(u64, 0x100000001b3, 0xcbf29ce484222325);
pub const Fnv1a_128 = Fnv1a(u128, 0x1000000000000000000013b, 0x6c62272e07bb014262b821756295c58d);

fn Fnv1a(comptime T: type, comptime prime: T, comptime offset: T) type {
    return struct {
        const Self = @This();

        value: T,

        pub fn init() Self {
            return Self{ .value = offset };
        }

        pub fn update(self: *Self, input: []const u8) void {
            for (input) |b| {
                self.value ^= b;
                self.value *%= prime;
            }
        }

        pub fn final(self: *Self) T {
            return self.value;
        }

        pub fn hash(input: []const u8) T {
            var c = Self.init();
            c.update(input);
            return c.final();
        }
    };
}

const verify = @import("verify.zig");

test "fnv1a-32" {
    try testing.expect(Fnv1a_32.hash("") == 0x811c9dc5);
    try testing.expect(Fnv1a_32.hash("a") == 0xe40c292c);
    try testing.expect(Fnv1a_32.hash("foobar") == 0xbf9cf968);
    try verify.iterativeApi(Fnv1a_32);
}

test "fnv1a-64" {
    try testing.expect(Fnv1a_64.hash("") == 0xcbf29ce484222325);
    try testing.expect(Fnv1a_64.hash("a") == 0xaf63dc4c8601ec8c);
    try testing.expect(Fnv1a_64.hash("foobar") == 0x85944171f73967e8);
    try verify.iterativeApi(Fnv1a_64);
}

test "fnv1a-128" {
    try testing.expect(Fnv1a_128.hash("") == 0x6c62272e07bb014262b821756295c58d);
    try testing.expect(Fnv1a_128.hash("a") == 0xd228cb696f1a8caf78912b704e4a8964);
    try verify.iterativeApi(Fnv1a_128);
}
const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const native_endian = builtin.target.cpu.arch.endian();

const default_seed: u32 = 0xc70f6907;

pub const Murmur2_32 = struct {
    const Self = @This();

    pub fn hash(str: []const u8) u32 {
        return @call(.always_inline, Self.hashWithSeed, .{ str, default_seed });
    }

    pub fn hashWithSeed(str: []const u8, seed: u32) u32 {
        const m: u32 = 0x5bd1e995;
        const len: u32 = @truncate(str.len);
        var h1: u32 = seed ^ len;
        for (@as([*]align(1) const u32, @ptrCast(str.ptr))[0..(len >> 2)]) |v| {
            var k1: u32 = v;
            if (native_endian == .big)
                k1 = @byteSwap(k1);
            k1 *%= m;
            k1 ^= k1 >> 24;
            k1 *%= m;
            h1 *%= m;
            h1 ^= k1;
        }
        const offset = len & 0xfffffffc;
        const rest = len & 3;
        if (rest >= 3) {
            h1 ^= @as(u32, @intCast(str[offset + 2])) << 16;
        }
        if (rest >= 2) {
            h1 ^= @as(u32, @intCast(str[offset + 1])) << 8;
        }
        if (rest >= 1) {
            h1 ^= @as(u32, @intCast(str[offset + 0]));
            h1 *%= m;
        }
        h1 ^= h1 >> 13;
        h1 *%= m;
        h1 ^= h1 >> 15;
        return h1;
    }

    pub fn hashUint32(v: u32) u32 {
        return @call(.always_inline, Self.hashUint32WithSeed, .{ v, default_seed });
    }

    pub fn hashUint32WithSeed(v: u32, seed: u32) u32 {
        const m: u32 = 0x5bd1e995;
        const len: u32 = 4;
        var h1: u32 = seed ^ len;
        var k1: u32 = undefined;
        k1 = v *% m;
        k1 ^= k1 >> 24;
        k1 *%= m;
        h1 *%= m;
        h1 ^= k1;
        h1 ^= h1 >> 13;
        h1 *%= m;
        h1 ^= h1 >> 15;
        return h1;
    }

    pub fn hashUint64(v: u64) u32 {
        return @call(.always_inline, Self.hashUint64WithSeed, .{ v, default_seed });
    }

    pub fn hashUint64WithSeed(v: u64, seed: u32) u32 {
        const m: u32 = 0x5bd1e995;
        const len: u32 = 8;
        var h1: u32 = seed ^ len;
        var k1: u32 = undefined;
        k1 = @as(u32, @truncate(v)) *% m;
        k1 ^= k1 >> 24;
        k1 *%= m;
        h1 *%= m;
        h1 ^= k1;
        k1 = @as(u32, @truncate(v >> 32)) *% m;
        k1 ^= k1 >> 24;
        k1 *%= m;
        h1 *%= m;
        h1 ^= k1;
        h1 ^= h1 >> 13;
        h1 *%= m;
        h1 ^= h1 >> 15;
        return h1;
    }
};

pub const Murmur2_64 = struct {
    const Self = @This();

    pub fn hash(str: []const u8) u64 {
        return @call(.always_inline, Self.hashWithSeed, .{ str, default_seed });
    }

    pub fn hashWithSeed(str: []const u8, seed: u64) u64 {
        const m: u64 = 0xc6a4a7935bd1e995;
        var h1: u64 = seed ^ (@as(u64, str.len) *% m);
        for (@as([*]align(1) const u64, @ptrCast(str.ptr))[0 .. str.len / 8]) |v| {
            var k1: u64 = v;
            if (native_endian == .big)
                k1 = @byteSwap(k1);
            k1 *%= m;
            k1 ^= k1 >> 47;
            k1 *%= m;
            h1 ^= k1;
            h1 *%= m;
        }
        const rest = str.len & 7;
        const offset = str.len - rest;
        if (rest > 0) {
            var k1: u64 = 0;
            @memcpy(@as([*]u8, @ptrCast(&k1))[0..rest], str[offset..]);
            if (native_endian == .big)
                k1 = @byteSwap(k1);
            h1 ^= k1;
            h1 *%= m;
        }
        h1 ^= h1 >> 47;
        h1 *%= m;
        h1 ^= h1 >> 47;
        return h1;
    }

    pub fn hashUint32(v: u32) u64 {
        return @call(.always_inline, Self.hashUint32WithSeed, .{ v, default_seed });
    }

    pub fn hashUint32WithSeed(v: u32, seed: u64) u64 {
        const m: u64 = 0xc6a4a7935bd1e995;
        const len: u64 = 4;
        var h1: u64 = seed ^ (len *% m);
        const k1: u64 = v;
        h1 ^= k1;
        h1 *%= m;
        h1 ^= h1 >> 47;
        h1 *%= m;
        h1 ^= h1 >> 47;
        return h1;
    }

    pub fn hashUint64(v: u64) u64 {
        return @call(.always_inline, Self.hashUint64WithSeed, .{ v, default_seed });
    }

    pub fn hashUint64WithSeed(v: u64, seed: u64) u64 {
        const m: u64 = 0xc6a4a7935bd1e995;
        const len: u64 = 8;
        var h1: u64 = seed ^ (len *% m);
        var k1: u64 = undefined;
        k1```
