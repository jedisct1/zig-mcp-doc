```
e-hash the password when it is longer.
    silently_truncate_password: bool,
};

/// Verify that a previously computed hash is valid for a given password.
pub fn strVerify(
    str: []const u8,
    password: []const u8,
    options: VerifyOptions,
) Error!void {
    if (mem.startsWith(u8, str, crypt_format.prefix)) {
        return CryptFormatHasher.verify(str, password, options.silently_truncate_password);
    } else {
        return PhcFormatHasher.verify(str, password, options.silently_truncate_password);
    }
}

test "bcrypt codec" {
    var salt: [salt_length]u8 = undefined;
    crypto.random.bytes(&salt);
    var salt_str: [salt_str_length]u8 = undefined;
    _ = crypt_format.Codec.Encoder.encode(salt_str[0..], salt[0..]);
    var salt2: [salt_length]u8 = undefined;
    try crypt_format.Codec.Decoder.decode(salt2[0..], salt_str[0..]);
    try testing.expectEqualSlices(u8, salt[0..], salt2[0..]);
}

test "bcrypt crypt format" {
    var hash_options = HashOptions{
        .params = .{ .rounds_log = 5, .silently_truncate_password = false },
        .encoding = .crypt,
    };
    var verify_options = VerifyOptions{ .silently_truncate_password = false };

    var buf: [hash_length]u8 = undefined;
    const s = try strHash("password", hash_options, &buf);

    try testing.expect(mem.startsWith(u8, s, crypt_format.prefix));
    try strVerify(s, "password", verify_options);
    try testing.expectError(
        error.PasswordVerificationFailed,
        strVerify(s, "invalid password", verify_options),
    );

    var long_buf: [hash_length]u8 = undefined;
    var long_s = try strHash("password" ** 100, hash_options, &long_buf);

    try testing.expect(mem.startsWith(u8, long_s, crypt_format.prefix));
    try strVerify(long_s, "password" ** 100, verify_options);
    try testing.expectError(
        error.PasswordVerificationFailed,
        strVerify(long_s, "password" ** 101, verify_options),
    );

    hash_options.params.silently_truncate_password = true;
    verify_options.silently_truncate_password = true;
    long_s = try strHash("password" ** 100, hash_options, &long_buf);
    try strVerify(long_s, "password" ** 101, verify_options);

    try strVerify(
        "$2b$08$WUQKyBCaKpziCwUXHiMVvu40dYVjkTxtWJlftl0PpjY2BxWSvFIEe",
        "The devil himself",
        verify_options,
    );
}

test "bcrypt phc format" {
    var hash_options = HashOptions{
        .params = .{ .rounds_log = 5, .silently_truncate_password = false },
        .encoding = .phc,
    };
    var verify_options = VerifyOptions{ .silently_truncate_password = false };
    const prefix = "$bcrypt$";

    var buf: [hash_length * 2]u8 = undefined;
    const s = try strHash("password", hash_options, &buf);

    try testing.expect(mem.startsWith(u8, s, prefix));
    try strVerify(s, "password", verify_options);
    try testing.expectError(
        error.PasswordVerificationFailed,
        strVerify(s, "invalid password", verify_options),
    );

    var long_buf: [hash_length * 2]u8 = undefined;
    var long_s = try strHash("password" ** 100, hash_options, &long_buf);

    try testing.expect(mem.startsWith(u8, long_s, prefix));
    try strVerify(long_s, "password" ** 100, verify_options);
    try testing.expectError(
        error.PasswordVerificationFailed,
        strVerify(long_s, "password" ** 101, verify_options),
    );

    hash_options.params.silently_truncate_password = true;
    verify_options.silently_truncate_password = true;
    long_s = try strHash("password" ** 100, hash_options, &long_buf);
    try strVerify(long_s, "password" ** 101, verify_options);

    try strVerify(
        "$bcrypt$r=5$2NopntlgE2lX3cTwr4qz8A$r3T7iKYQNnY4hAhGjk9RmuyvgrYJZwc",
        "The devil himself",
        verify_options,
    );
}

test "openssh kdf" {
    var key: [100]u8 = undefined;
    const pass = "password";
    const salt = "salt";
    const rounds = 5;
    try opensshKdf(pass, salt, &key, rounds);
    const expected = [_]u8{ 65, 207, 68, 58, 55, 252, 114, 141, 255, 65, 216, 175, 5, 92, 235, 68, 220, 92, 118, 161, 40, 13, 241, 190, 56, 152, 69, 136, 41, 214, 51, 205, 37, 221, 101, 59, 105, 73, 133, 36, 14, 59, 94, 212, 111, 107, 109, 237, 213, 235, 246, 119, 59, 76, 45, 130, 142, 81, 178, 231, 161, 158, 138, 108, 18, 162, 26, 50, 218, 251, 23, 66, 2, 232, 20, 202, 216, 46, 12, 250, 247, 246, 252, 23, 155, 74, 77, 195, 120, 113, 57, 88, 126, 81, 9, 249, 72, 18, 208, 160 };
    try testing.expectEqualSlices(u8, &key, &expected);
}
// zig run -O ReleaseFast --zig-lib-dir ../.. benchmark.zig

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const time = std.time;
const Timer = time.Timer;
const crypto = std.crypto;

const KiB = 1024;
const MiB = 1024 * KiB;

var prng = std.Random.DefaultPrng.init(0);
const random = prng.random();

const Crypto = struct {
    ty: type,
    name: []const u8,
};

const hashes = [_]Crypto{
    Crypto{ .ty = crypto.hash.Md5, .name = "md5" },
    Crypto{ .ty = crypto.hash.Sha1, .name = "sha1" },
    Crypto{ .ty = crypto.hash.sha2.Sha256, .name = "sha256" },
    Crypto{ .ty = crypto.hash.sha2.Sha512, .name = "sha512" },
    Crypto{ .ty = crypto.hash.sha3.Sha3_256, .name = "sha3-256" },
    Crypto{ .ty = crypto.hash.sha3.Sha3_512, .name = "sha3-512" },
    Crypto{ .ty = crypto.hash.sha3.Shake128, .name = "shake-128" },
    Crypto{ .ty = crypto.hash.sha3.Shake256, .name = "shake-256" },
    Crypto{ .ty = crypto.hash.sha3.TurboShake128(null), .name = "turboshake-128" },
    Crypto{ .ty = crypto.hash.sha3.TurboShake256(null), .name = "turboshake-256" },
    Crypto{ .ty = crypto.hash.blake2.Blake2s256, .name = "blake2s" },
    Crypto{ .ty = crypto.hash.blake2.Blake2b512, .name = "blake2b" },
    Crypto{ .ty = crypto.hash.Blake3, .name = "blake3" },
};

const block_size: usize = 8 * 8192;

pub fn benchmarkHash(comptime Hash: anytype, comptime bytes: comptime_int) !u64 {
    const blocks_count = bytes / block_size;
    var block: [block_size]u8 = undefined;
    random.bytes(&block);

    var h = Hash.init(.{});

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..blocks_count) |_| {
        h.update(&block);
    }
    var final: [Hash.digest_length]u8 = undefined;
    h.final(&final);
    std.mem.doNotOptimizeAway(final);

    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(bytes / elapsed_s));

    return throughput;
}

const macs = [_]Crypto{
    Crypto{ .ty = crypto.onetimeauth.Ghash, .name = "ghash" },
    Crypto{ .ty = crypto.onetimeauth.Polyval, .name = "polyval" },
    Crypto{ .ty = crypto.onetimeauth.Poly1305, .name = "poly1305" },
    Crypto{ .ty = crypto.auth.hmac.HmacMd5, .name = "hmac-md5" },
    Crypto{ .ty = crypto.auth.hmac.HmacSha1, .name = "hmac-sha1" },
    Crypto{ .ty = crypto.auth.hmac.sha2.HmacSha256, .name = "hmac-sha256" },
    Crypto{ .ty = crypto.auth.hmac.sha2.HmacSha512, .name = "hmac-sha512" },
    Crypto{ .ty = crypto.auth.siphash.SipHash64(2, 4), .name = "siphash-2-4" },
    Crypto{ .ty = crypto.auth.siphash.SipHash64(1, 3), .name = "siphash-1-3" },
    Crypto{ .ty = crypto.auth.siphash.SipHash128(2, 4), .name = "siphash128-2-4" },
    Crypto{ .ty = crypto.auth.siphash.SipHash128(1, 3), .name = "siphash128-1-3" },
    Crypto{ .ty = crypto.auth.aegis.Aegis128X4Mac, .name = "aegis-128x4 mac" },
    Crypto{ .ty = crypto.auth.aegis.Aegis256X4Mac, .name = "aegis-256x4 mac" },
    Crypto{ .ty = crypto.auth.aegis.Aegis128X2Mac, .name = "aegis-128x2 mac" },
    Crypto{ .ty = crypto.auth.aegis.Aegis256X2Mac, .name = "aegis-256x2 mac" },
    Crypto{ .ty = crypto.auth.aegis.Aegis128LMac, .name = "aegis-128l mac" },
    Crypto{ .ty = crypto.auth.aegis.Aegis256Mac, .name = "aegis-256 mac" },
    Crypto{ .ty = crypto.auth.cmac.CmacAes128, .name = "aes-cmac" },
};

pub fn benchmarkMac(comptime Mac: anytype, comptime bytes: comptime_int) !u64 {
    var in: [512 * KiB]u8 = undefined;
    random.bytes(in[0..]);

    const key_length = if (Mac.key_length == 0) 32 else Mac.key_length;
    var key: [key_length]u8 = undefined;
    random.bytes(key[0..]);

    var mac: [Mac.mac_length]u8 = undefined;
    var offset: usize = 0;
    var timer = try Timer.start();
    const start = timer.lap();
    while (offset < bytes) : (offset += in.len) {
        Mac.create(mac[0..], in[0..], key[0..]);
        mem.doNotOptimizeAway(&mac);
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(bytes / elapsed_s));

    return throughput;
}

const exchanges = [_]Crypto{Crypto{ .ty = crypto.dh.X25519, .name = "x25519" }};

pub fn benchmarkKeyExchange(comptime DhKeyExchange: anytype, comptime exchange_count: comptime_int) !u64 {
    std.debug.assert(DhKeyExchange.shared_length >= DhKeyExchange.secret_length);

    var secret: [DhKeyExchange.shared_length]u8 = undefined;
    random.bytes(secret[0..]);

    var public: [DhKeyExchange.shared_length]u8 = undefined;
    random.bytes(public[0..]);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < exchange_count) : (i += 1) {
            const out = try DhKeyExchange.scalarmult(secret, public);
            secret[0..16].* = out[0..16].*;
            public[0..16].* = out[16..32].*;
            mem.doNotOptimizeAway(&out);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(exchange_count / elapsed_s));

    return throughput;
}

const signatures = [_]Crypto{
    Crypto{ .ty = crypto.sign.Ed25519, .name = "ed25519" },
    Crypto{ .ty = crypto.sign.ecdsa.EcdsaP256Sha256, .name = "ecdsa-p256" },
    Crypto{ .ty = crypto.sign.ecdsa.EcdsaP384Sha384, .name = "ecdsa-p384" },
    Crypto{ .ty = crypto.sign.ecdsa.EcdsaSecp256k1Sha256, .name = "ecdsa-secp256k1" },
};

pub fn benchmarkSignature(comptime Signature: anytype, comptime signatures_count: comptime_int) !u64 {
    const msg = [_]u8{0} ** 64;
    const key_pair = Signature.KeyPair.generate();

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < signatures_count) : (i += 1) {
            const sig = try key_pair.sign(&msg, null);
            mem.doNotOptimizeAway(&sig);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(signatures_count / elapsed_s));

    return throughput;
}

const signature_verifications = [_]Crypto{Crypto{ .ty = crypto.sign.Ed25519, .name = "ed25519" }};

pub fn benchmarkSignatureVerification(comptime Signature: anytype, comptime signatures_count: comptime_int) !u64 {
    const msg = [_]u8{0} ** 64;
    const key_pair = Signature.KeyPair.generate();
    const sig = try key_pair.sign(&msg, null);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < signatures_count) : (i += 1) {
            try sig.verify(&msg, key_pair.public_key);
            mem.doNotOptimizeAway(&sig);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(signatures_count / elapsed_s));

    return throughput;
}

const batch_signature_verifications = [_]Crypto{Crypto{ .ty = crypto.sign.Ed25519, .name = "ed25519" }};

pub fn benchmarkBatchSignatureVerification(comptime Signature: anytype, comptime signatures_count: comptime_int) !u64 {
    const msg = [_]u8{0} ** 64;
    const key_pair = Signature.KeyPair.generate();
    const sig = try key_pair.sign(&msg, null);

    var batch: [64]Signature.BatchElement = undefined;
    for (&batch) |*element| {
        element.* = Signature.BatchElement{ .sig = sig, .msg = &msg, .public_key = key_pair.public_key };
    }

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < signatures_count) : (i += 1) {
            try Signature.verifyBatch(batch.len, batch);
            mem.doNotOptimizeAway(&sig);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = batch.len * @as(u64, @intFromFloat(signatures_count / elapsed_s));

    return throughput;
}

const kems = [_]Crypto{
    Crypto{ .ty = crypto.kem.kyber_d00.Kyber512, .name = "kyber512d00" },
    Crypto{ .ty = crypto.kem.kyber_d00.Kyber768, .name = "kyber768d00" },
    Crypto{ .ty = crypto.kem.kyber_d00.Kyber1024, .name = "kyber1024d00" },
};

pub fn benchmarkKem(comptime Kem: anytype, comptime kems_count: comptime_int) !u64 {
    const key_pair = Kem.KeyPair.generate();

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < kems_count) : (i += 1) {
            const e = key_pair.public_key.encaps(null);
            mem.doNotOptimizeAway(&e);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(kems_count / elapsed_s));

    return throughput;
}

pub fn benchmarkKemDecaps(comptime Kem: anytype, comptime kems_count: comptime_int) !u64 {
    const key_pair = Kem.KeyPair.generate();

    const e = key_pair.public_key.encaps(null);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < kems_count) : (i += 1) {
            const ss2 = try key_pair.secret_key.decaps(&e.ciphertext);
            mem.doNotOptimizeAway(&ss2);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(kems_count / elapsed_s));

    return throughput;
}

pub fn benchmarkKemKeyGen(comptime Kem: anytype, comptime kems_count: comptime_int) !u64 {
    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < kems_count) : (i += 1) {
            const key_pair = Kem.KeyPair.generate();
            mem.doNotOptimizeAway(&key_pair);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(kems_count / elapsed_s));

    return throughput;
}

const aeads = [_]Crypto{
    Crypto{ .ty = crypto.aead.chacha_poly.ChaCha20Poly1305, .name = "chacha20Poly1305" },
    Crypto{ .ty = crypto.aead.chacha_poly.XChaCha20Poly1305, .name = "xchacha20Poly1305" },
    Crypto{ .ty = crypto.aead.chacha_poly.XChaCha8Poly1305, .name = "xchacha8Poly1305" },
    Crypto{ .ty = crypto.aead.salsa_poly.XSalsa20Poly1305, .name = "xsalsa20Poly1305" },
    Crypto{ .ty = crypto.aead.aegis.Aegis128X4, .name = "aegis-128x4" },
    Crypto{ .ty = crypto.aead.aegis.Aegis128X2, .name = "aegis-128x2" },
    Crypto{ .ty = crypto.aead.aegis.Aegis128L, .name = "aegis-128l" },
    Crypto{ .ty = crypto.aead.aegis.Aegis256X4, .name = "aegis-256x4" },
    Crypto{ .ty = crypto.aead.aegis.Aegis256X2, .name = "aegis-256x2" },
    Crypto{ .ty = crypto.aead.aegis.Aegis256, .name = "aegis-256" },
    Crypto{ .ty = crypto.aead.aes_gcm.Aes128Gcm, .name = "aes128-gcm" },
    Crypto{ .ty = crypto.aead.aes_gcm.Aes256Gcm, .name = "aes256-gcm" },
    Crypto{ .ty = crypto.aead.aes_ocb.Aes128Ocb, .name = "aes128-ocb" },
    Crypto{ .ty = crypto.aead.aes_ocb.Aes256Ocb, .name = "aes256-ocb" },
    Crypto{ .ty = crypto.aead.isap.IsapA128A, .name = "isapa128a" },
};

pub fn benchmarkAead(comptime Aead: anytype, comptime bytes: comptime_int) !u64 {
    var in: [512 * KiB]u8 = undefined;
    random.bytes(in[0..]);

    var tag: [Aead.tag_length]u8 = undefined;

    var key: [Aead.key_length]u8 = undefined;
    random.bytes(key[0..]);

    var nonce: [Aead.nonce_length]u8 = undefined;
    random.bytes(nonce[0..]);

    var offset: usize = 0;
    var timer = try Timer.start();
    const start = timer.lap();
    while (offset < bytes) : (offset += in.len) {
        Aead.encrypt(in[0..], tag[0..], in[0..], &[_]u8{}, nonce, key);
        try Aead.decrypt(in[0..], in[0..], tag, &[_]u8{}, nonce, key);
    }
    mem.doNotOptimizeAway(&in);
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(2 * bytes / elapsed_s));

    return throughput;
}

const aes = [_]Crypto{
    Crypto{ .ty = crypto.core.aes.Aes128, .name = "aes128-single" },
    Crypto{ .ty = crypto.core.aes.Aes256, .name = "aes256-single" },
};

pub fn benchmarkAes(comptime Aes: anytype, comptime count: comptime_int) !u64 {
    var key: [Aes.key_bits / 8]u8 = undefined;
    random.bytes(key[0..]);
    const ctx = Aes.initEnc(key);

    var in = [_]u8{0} ** 16;

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            ctx.encrypt(&in, &in);
        }
    }
    mem.doNotOptimizeAway(&in);
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(count / elapsed_s));

    return throughput;
}

const aes8 = [_]Crypto{
    Crypto{ .ty = crypto.core.aes.Aes128, .name = "aes128-8" },
    Crypto{ .ty = crypto.core.aes.Aes256, .name = "aes256-8" },
};

pub fn benchmarkAes8(comptime Aes: anytype, comptime count: comptime_int) !u64 {
    var key: [Aes.key_bits / 8]u8 = undefined;
    random.bytes(key[0..]);
    const ctx = Aes.initEnc(key);

    var in = [_]u8{0} ** (8 * 16);

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            ctx.encryptWide(8, &in, &in);
        }
    }
    mem.doNotOptimizeAway(&in);
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(8 * count / elapsed_s));

    return throughput;
}

const CryptoPwhash = struct {
    ty: type,
    params: *const anyopaque,
    name: []const u8,
};
const bcrypt_params = crypto.pwhash.bcrypt.Params{ .rounds_log = 8, .silently_truncate_password = true };
const pwhashes = [_]CryptoPwhash{
    .{
        .ty = crypto.pwhash.bcrypt,
        .params = &bcrypt_params,
        .name = "bcrypt",
    },
    .{
        .ty = crypto.pwhash.scrypt,
        .params = &crypto.pwhash.scrypt.Params.interactive,
        .name = "scrypt",
    },
    .{
        .ty = crypto.pwhash.argon2,
        .params = &crypto.pwhash.argon2.Params.interactive_2id,
        .name = "argon2",
    },
};

fn benchmarkPwhash(
    allocator: mem.Allocator,
    comptime ty: anytype,
    comptime params: *const anyopaque,
    comptime count: comptime_int,
) !f64 {
    const password = "testpass" ** 2;
    const opts = ty.HashOptions{
        .allocator = allocator,
        .params = @as(*const ty.Params, @ptrCast(@alignCast(params))).*,
        .encoding = .phc,
    };
    var buf: [256]u8 = undefined;

    var timer = try Timer.start();
    const start = timer.lap();
    {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            _ = try ty.strHash(password, opts, &buf);
            mem.doNotOptimizeAway(&buf);
        }
    }
    const end = timer.read();

    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = elapsed_s / count;

    return throughput;
}

fn usage() void {
    std.debug.print(
        \\throughput_test [options]
        \\
        \\Options:
        \\  --filter [test-name]
        \\  --seed   [int]
        \\  --help
        \\
    , .{});
}

fn mode(comptime x: comptime_int) comptime_int {
    return if (builtin.mode == .Debug) x / 64 else x;
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();
    const args = try std.process.argsAlloc(arena_allocator);

    var filter: ?[]u8 = "";

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

            const seed = try std.fmt.parseUnsigned(u32, args[i], 10);
            prng.seed(seed);
        } else if (std.mem.eql(u8, args[i], "--filter")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.process.exit(1);
            }

            filter = args[i];
        } else if (std.mem.eql(u8, args[i], "--help")) {
            usage();
            return;
        } else {
            usage();
            std.process.exit(1);
        }
    }

    inline for (hashes) |H| {
        if (filter == null or std.mem.indexOf(u8, H.name, filter.?) != null) {
            const throughput = try benchmarkHash(H.ty, mode(128 * MiB));
            try stdout.print("{s:>17}: {:10} MiB/s\n", .{ H.name, throughput / (1 * MiB) });
        }
    }

    inline for (macs) |M| {
        if (filter == null or std.mem.indexOf(u8, M.name, filter.?) != null) {
            const throughput = try benchmarkMac(M.ty, mode(128 * MiB));
            try stdout.print("{s:>17}: {:10} MiB/s\n", .{ M.name, throughput / (1 * MiB) });
        }
    }

    inline for (exchanges) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkKeyExchange(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} exchanges/s\n", .{ E.name, throughput });
        }
    }

    inline for (signatures) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkSignature(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} signatures/s\n", .{ E.name, throughput });
        }
    }

    inline for (signature_verifications) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkSignatureVerification(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} verifications/s\n", .{ E.name, throughput });
        }
    }

    inline for (batch_signature_verifications) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkBatchSignatureVerification(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} verifications/s (batch)\n", .{ E.name, throughput });
        }
    }

    inline for (aeads) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkAead(E.ty, mode(128 * MiB));
            try stdout.print("{s:>17}: {:10} MiB/s\n", .{ E.name, throughput / (1 * MiB) });
        }
    }

    inline for (aes) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkAes(E.ty, mode(100000000));
            try stdout.print("{s:>17}: {:10} ops/s\n", .{ E.name, throughput });
        }
    }

    inline for (aes8) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkAes8(E.ty, mode(10000000));
            try stdout.print("{s:>17}: {:10} ops/s\n", .{ E.name, throughput });
        }
    }

    inline for (pwhashes) |H| {
        if (filter == null or std.mem.indexOf(u8, H.name, filter.?) != null) {
            const throughput = try benchmarkPwhash(arena_allocator, H.ty, H.params, mode(64));
            try stdout.print("{s:>17}: {d:10.3} s/ops\n", .{ H.name, throughput });
        }
    }

    inline for (kems) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkKem(E.ty, mode(1000));
            try stdout.print("{s:>17}: {:10} encaps/s\n", .{ E.name, throughput });
        }
    }

    inline for (kems) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkKemDecaps(E.ty, mode(25000));
            try stdout.print("{s:>17}: {:10} decaps/s\n", .{ E.name, throughput });
        }
    }

    inline for (kems) |E| {
        if (filter == null or std.mem.indexOf(u8, E.name, filter.?) != null) {
            const throughput = try benchmarkKemKeyGen(E.ty, mode(25000));
            try stdout.print("{s:>17}: {:10} keygen/s\n", .{ E.name, throughput });
        }
    }
}
const std = @import("../std.zig");
const mem = std.mem;
const math = std.math;
const debug = std.debug;
const htest = @import("test.zig");

const RoundParam = struct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: usize,
    y: usize,
};

fn roundParam(a: usize, b: usize, c: usize, d: usize, x: usize, y: usize) RoundParam {
    return RoundParam{
        .a = a,
        .b = b,
        .c = c,
        .d = d,
        .x = x,
        .y = y,
    };
}

/////////////////////
// Blake2s

pub const Blake2s128 = Blake2s(128);
pub const Blake2s160 = Blake2s(160);
pub const Blake2s224 = Blake2s(224);
pub const Blake2s256 = Blake2s(256);

pub fn Blake2s(comptime out_bits: usize) type {
    return struct {
        const Self = @This();
        pub const block_length = 64;
        pub const digest_length = out_bits / 8;
        pub const key_length_min = 0;
        pub const key_length_max = 32;
        pub const key_length = 32; // recommended key length
        pub const Options = struct { key: ?[]const u8 = null, salt: ?[8]u8 = null, context: ?[8]u8 = null, expected_out_bits: usize = out_bits };

        const iv = [8]u32{
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        };

        const sigma = [10][16]u8{
            [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            [_]u8{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            [_]u8{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            [_]u8{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            [_]u8{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            [_]u8{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            [_]u8{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            [_]u8{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            [_]u8{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            [_]u8{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        };

        h: [8]u32,
        t: u64,
        // Streaming cache
        buf: [64]u8,
        buf_len: u8,

        pub fn init(options: Options) Self {
            comptime debug.assert(8 <= out_bits and out_bits <= 256);

            var d: Self = undefined;
            d.h = iv;

            const key_len = if (options.key) |key| key.len else 0;
            // default parameters
            d.h[0] ^= 0x01010000 ^ @as(u32, @truncate(key_len << 8)) ^ @as(u32, @intCast(options.expected_out_bits >> 3));
            d.t = 0;
            d.buf_len = 0;

            if (options.salt) |salt| {
                d.h[4] ^= mem.readInt(u32, salt[0..4], .little);
                d.h[5] ^= mem.readInt(u32, salt[4..8], .little);
            }
            if (options.context) |context| {
                d.h[6] ^= mem.readInt(u32, context[0..4], .little);
                d.h[7] ^= mem.readInt(u32, context[4..8], .little);
            }
            if (key_len > 0) {
                @memset(d.buf[key_len..], 0);
                d.update(options.key.?);
                d.buf_len = 64;
            }
            return d;
        }

        pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
            var d = Self.init(options);
            d.update(b);
            d.final(out);
        }

        pub fn update(d: *Self, b: []const u8) void {
            var off: usize = 0;

            // Partial buffer exists from previous update. Copy into buffer then hash.
            if (d.buf_len != 0 and d.buf_len + b.len > 64) {
                off += 64 - d.buf_len;
                @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);
                d.t += 64;
                d.round(d.buf[0..], false);
                d.buf_len = 0;
            }

            // Full middle blocks.
            while (off + 64 < b.len) : (off += 64) {
                d.t += 64;
                d.round(b[off..][0..64], false);
            }

            // Copy any remainder for next pass.
            const b_slice = b[off..];
            @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
            d.buf_len += @as(u8, @intCast(b_slice.len));
        }

        pub fn final(d: *Self, out: *[digest_length]u8) void {
            @memset(d.buf[d.buf_len..], 0);
            d.t += d.buf_len;
            d.round(d.buf[0..], true);
            for (&d.h) |*x| x.* = mem.nativeToLittle(u32, x.*);
            out.* = @as(*[digest_length]u8, @ptrCast(&d.h)).*;
        }

        fn round(d: *Self, b: *const [64]u8, last: bool) void {
            var m: [16]u32 = undefined;
            var v: [16]u32 = undefined;

            for (&m, 0..) |*r, i| {
                r.* = mem.readInt(u32, b[4 * i ..][0..4], .little);
            }

            var k: usize = 0;
            while (k < 8) : (k += 1) {
                v[k] = d.h[k];
                v[k + 8] = iv[k];
            }

            v[12] ^= @as(u32, @truncate(d.t));
            v[13] ^= @as(u32, @intCast(d.t >> 32));
            if (last) v[14] = ~v[14];

            const rounds = comptime [_]RoundParam{
                roundParam(0, 4, 8, 12, 0, 1),
                roundParam(1, 5, 9, 13, 2, 3),
                roundParam(2, 6, 10, 14, 4, 5),
                roundParam(3, 7, 11, 15, 6, 7),
                roundParam(0, 5, 10, 15, 8, 9),
                roundParam(1, 6, 11, 12, 10, 11),
                roundParam(2, 7, 8, 13, 12, 13),
                roundParam(3, 4, 9, 14, 14, 15),
            };

            comptime var j: usize = 0;
            inline while (j < 10) : (j += 1) {
                inline for (rounds) |r| {
                    v[r.a] = v[r.a] +% v[r.b] +% m[sigma[j][r.x]];
                    v[r.d] = math.rotr(u32, v[r.d] ^ v[r.a], @as(usize, 16));
                    v[r.c] = v[r.c] +% v[r.d];
                    v[r.b] = math.rotr(u32, v[r.b] ^ v[r.c], @as(usize, 12));
                    v[r.a] = v[r.a] +% v[r.b] +% m[sigma[j][r.y]];
                    v[r.d] = math.rotr(u32, v[r.d] ^ v[r.a], @as(usize, 8));
                    v[r.c] = v[r.c] +% v[r.d];
                    v[r.b] = math.rotr(u32, v[r.b] ^ v[r.c], @as(usize, 7));
                }
            }

            for (&d.h, 0..) |*r, i| {
                r.* ^= v[i] ^ v[i + 8];
            }
        }

        pub const Error = error{};
        pub const Writer = std.io.Writer(*Self, Error, write);

        fn write(self: *Self, bytes: []const u8) Error!usize {
            self.update(bytes);
            return bytes.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

test "blake2s160 single" {
    const h1 = "354c9c33f735962418bdacb9479873429c34916f";
    try htest.assertEqualHash(Blake2s160, h1, "");

    const h2 = "5ae3b99be29b01834c3b508521ede60438f8de17";
    try htest.assertEqualHash(Blake2s160, h2, "abc");

    const h3 = "5a604fec9713c369e84b0ed68daed7d7504ef240";
    try htest.assertEqualHash(Blake2s160, h3, "The quick brown fox jumps over the lazy dog");

    const h4 = "b60c4dc60e2681e58fbc24e77f07e02c69e72ed0";
    try htest.assertEqualHash(Blake2s160, h4, "a" ** 32 ++ "b" ** 32);
}

test "blake2s160 streaming" {
    var h = Blake2s160.init(.{});
    var out: [20]u8 = undefined;

    const h1 = "354c9c33f735962418bdacb9479873429c34916f";

    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "5ae3b99be29b01834c3b508521ede60438f8de17";

    h = Blake2s160.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Blake2s160.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    const h3 = "b60c4dc60e2681e58fbc24e77f07e02c69e72ed0";

    h = Blake2s160.init(.{});
    h.update("a" ** 32);
    h.update("b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2s160.init(.{});
    h.update("a" ** 32 ++ "b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    const h4 = "4667fd60791a7fe41f939bca646b4529e296bd68";

    h = Blake2s160.init(.{ .context = [_]u8{0x69} ** 8, .salt = [_]u8{0x42} ** 8 });
    h.update("a" ** 32);
    h.update("b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);

    h = Blake2s160.init(.{ .context = [_]u8{0x69} ** 8, .salt = [_]u8{0x42} ** 8 });
    h.update("a" ** 32 ++ "b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);
}

test "comptime blake2s160" {
    //comptime
    {
        @setEvalBranchQuota(10000);
        var block = [_]u8{0} ** Blake2s160.block_length;
        var out: [Blake2s160.digest_length]u8 = undefined;

        const h1 = "2c56ad9d0b2c8b474aafa93ab307db2f0940105f";

        try htest.assertEqualHash(Blake2s160, h1, block[0..]);

        var h = Blake2s160.init(.{});
        h.update(&block);
        h.final(out[0..]);

        try htest.assertEqual(h1, out[0..]);
    }
}

test "blake2s224 single" {
    const h1 = "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4";
    try htest.assertEqualHash(Blake2s224, h1, "");

    const h2 = "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55";
    try htest.assertEqualHash(Blake2s224, h2, "abc");

    const h3 = "e4e5cb6c7cae41982b397bf7b7d2d9d1949823ae78435326e8db4912";
    try htest.assertEqualHash(Blake2s224, h3, "The quick brown fox jumps over the lazy dog");

    const h4 = "557381a78facd2b298640f4e32113e58967d61420af1aa939d0cfe01";
    try htest.assertEqualHash(Blake2s224, h4, "a" ** 32 ++ "b" ** 32);
}

test "blake2s224 streaming" {
    var h = Blake2s224.init(.{});
    var out: [28]u8 = undefined;

    const h1 = "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4";

    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55";

    h = Blake2s224.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Blake2s224.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    const h3 = "557381a78facd2b298640f4e32113e58967d61420af1aa939d0cfe01";

    h = Blake2s224.init(.{});
    h.update("a" ** 32);
    h.update("b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2s224.init(.{});
    h.update("a" ** 32 ++ "b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    const h4 = "a4d6a9d253441b80e5dfd60a04db169ffab77aec56a2855c402828c3";

    h = Blake2s224.init(.{ .context = [_]u8{0x69} ** 8, .salt = [_]u8{0x42} ** 8 });
    h.update("a" ** 32);
    h.update("b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);

    h = Blake2s224.init(.{ .context = [_]u8{0x69} ** 8, .salt = [_]u8{0x42} ** 8 });
    h.update("a" ** 32 ++ "b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);
}

test "comptime blake2s224" {
    comptime {
        @setEvalBranchQuota(10000);
        var block = [_]u8{0} ** Blake2s224.block_length;
        var out: [Blake2s224.digest_length]u8 = undefined;

        const h1 = "86b7611563293f8c73627df7a6d6ba25ca0548c2a6481f7d116ee576";

        try htest.assertEqualHash(Blake2s224, h1, block[0..]);

        var h = Blake2s224.init(.{});
        h.update(&block);
        h.final(out[0..]);

        try htest.assertEqual(h1, out[0..]);
    }
}

test "blake2s256 single" {
    const h1 = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
    try htest.assertEqualHash(Blake2s256, h1, "");

    const h2 = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
    try htest.assertEqualHash(Blake2s256, h2, "abc");

    const h3 = "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812";
    try htest.assertEqualHash(Blake2s256, h3, "The quick brown fox jumps over the lazy dog");

    const h4 = "8d8711dade07a6b92b9a3ea1f40bee9b2c53ff3edd2a273dec170b0163568977";
    try htest.assertEqualHash(Blake2s256, h4, "a" ** 32 ++ "b" ** 32);
}

test "blake2s256 streaming" {
    var h = Blake2s256.init(.{});
    var out: [32]u8 = undefined;

    const h1 = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";

    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";

    h = Blake2s256.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Blake2s256.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    const h3 = "8d8711dade07a6b92b9a3ea1f40bee9b2c53ff3edd2a273dec170b0163568977";

    h = Blake2s256.init(.{});
    h.update("a" ** 32);
    h.update("b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2s256.init(.{});
    h.update("a" ** 32 ++ "b" ** 32);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);
}

test "blake2s256 keyed" {
    var out: [32]u8 = undefined;

    const h1 = "10f918da4d74fab3302e48a5d67d03804b1ec95372a62a0f33b7c9fa28ba1ae6";
    const key = "secret_key";

    Blake2s256.hash("a" ** 64 ++ "b" ** 64, &out, .{ .key = key });
    try htest.assertEqual(h1, out[0..]);

    var h = Blake2s256.init(.{ .key = key });
    h.update("a" ** 64 ++ "b" ** 64);
    h.final(out[0..]);

    try htest.assertEqual(h1, out[0..]);

    h = Blake2s256.init(.{ .key = key });
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);

    try htest.assertEqual(h1, out[0..]);
}

test "comptime blake2s256" {
    comptime {
        @setEvalBranchQuota(10000);
        var block = [_]u8{0} ** Blake2s256.block_length;
        var out: [Blake2s256.digest_length]u8 = undefined;

        const h1 = "ae09db7cd54f42b490ef09b6bc541af688e4959bb8c53f359a6f56e38ab454a3";

        try htest.assertEqualHash(Blake2s256, h1, block[0..]);

        var h = Blake2s256.init(.{});
        h.update(&block);
        h.final(out[0..]);

        try htest.assertEqual(h1, out[0..]);
    }
}

/////////////////////
// Blake2b

pub const Blake2b128 = Blake2b(128);
pub const Blake2b160 = Blake2b(160);
pub const Blake2b256 = Blake2b(256);
pub const Blake2b384 = Blake2b(384);
pub const Blake2b512 = Blake2b(512);

pub fn Blake2b(comptime out_bits: usize) type {
    return struct {
        const Self = @This();
        pub const block_length = 128;
        pub const digest_length = out_bits / 8;
        pub const key_length_min = 0;
        pub const key_length_max = 64;
        pub const key_length = 32; // recommended key length
        pub const Options = struct { key: ?[]const u8 = null, salt: ?[16]u8 = null, context: ?[16]u8 = null, expected_out_bits: usize = out_bits };

        const iv = [8]u64{
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        };

        const sigma = [12][16]u8{
            [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            [_]u8{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            [_]u8{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            [_]u8{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            [_]u8{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            [_]u8{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            [_]u8{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            [_]u8{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            [_]u8{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            [_]u8{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            [_]u8{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        };

        h: [8]u64,
        t: u128,
        // Streaming cache
        buf: [128]u8,
        buf_len: u8,

        pub fn init(options: Options) Self {
            comptime debug.assert(8 <= out_bits and out_bits <= 512);

            var d: Self = undefined;
            d.h = iv;

            const key_len = if (options.key) |key| key.len else 0;
            // default parameters
            d.h[0] ^= 0x01010000 ^ (key_len << 8) ^ (options.expected_out_bits >> 3);
            d.t = 0;
            d.buf_len = 0;

            if (options.salt) |salt| {
                d.h[4] ^= mem.readInt(u64, salt[0..8], .little);
                d.h[5] ^= mem.readInt(u64, salt[8..16], .little);
            }
            if (options.context) |context| {
                d.h[6] ^= mem.readInt(u64, context[0..8], .little);
                d.h[7] ^= mem.readInt(u64, context[8..16], .little);
            }
            if (key_len > 0) {
                @memset(d.buf[key_len..], 0);
                d.update(options.key.?);
                d.buf_len = 128;
            }
            return d;
        }

        pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
            var d = Self.init(options);
            d.update(b);
            d.final(out);
        }

        pub fn update(d: *Self, b: []const u8) void {
            var off: usize = 0;

            // Partial buffer exists from previous update. Copy into buffer then hash.
            if (d.buf_len != 0 and d.buf_len + b.len > 128) {
                off += 128 - d.buf_len;
                @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);
                d.t += 128;
                d.round(d.buf[0..], false);
                d.buf_len = 0;
            }

            // Full middle blocks.
            while (off + 128 < b.len) : (off += 128) {
                d.t += 128;
                d.round(b[off..][0..128], false);
            }

            // Copy any remainder for next pass.
            const b_slice = b[off..];
            @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
            d.buf_len += @as(u8, @intCast(b_slice.len));
        }

        pub fn final(d: *Self, out: *[digest_length]u8) void {
            @memset(d.buf[d.buf_len..], 0);
            d.t += d.buf_len;
            d.round(d.buf[0..], true);
            for (&d.h) |*x| x.* = mem.nativeToLittle(u64, x.*);
            out.* = @as(*[digest_length]u8, @ptrCast(&d.h)).*;
        }

        fn round(d: *Self, b: *const [128]u8, last: bool) void {
            var m: [16]u64 = undefined;
            var v: [16]u64 = undefined;

            for (&m, 0..) |*r, i| {
                r.* = mem.readInt(u64, b[8 * i ..][0..8], .little);
            }

            var k: usize = 0;
            while (k < 8) : (k += 1) {
                v[k] = d.h[k];
                v[k + 8] = iv[k];
            }

            v[12] ^= @as(u64, @truncate(d.t));
            v[13] ^= @as(u64, @intCast(d.t >> 64));
            if (last) v[14] = ~v[14];

            const rounds = comptime [_]RoundParam{
                roundParam(0, 4, 8, 12, 0, 1),
                roundParam(1, 5, 9, 13, 2, 3),
                roundParam(2, 6, 10, 14, 4, 5),
                roundParam(3, 7, 11, 15, 6, 7),
                roundParam(0, 5, 10, 15, 8, 9),
                roundParam(1, 6, 11, 12, 10, 11),
                roundParam(2, 7, 8, 13, 12, 13),
                roundParam(3, 4, 9, 14, 14, 15),
            };

            comptime var j: usize = 0;
            inline while (j < 12) : (j += 1) {
                inline for (rounds) |r| {
                    v[r.a] = v[r.a] +% v[r.b] +% m[sigma[j][r.x]];
                    v[r.d] = math.rotr(u64, v[r.d] ^ v[r.a], @as(usize, 32));
                    v[r.c] = v[r.c] +% v[r.d];
                    v[r.b] = math.rotr(u64, v[r.b] ^ v[r.c], @as(usize, 24));
                    v[r.a] = v[r.a] +% v[r.b] +% m[sigma[j][r.y]];
                    v[r.d] = math.rotr(u64, v[r.d] ^ v[r.a], @as(usize, 16));
                    v[r.c] = v[r.c] +% v[r.d];
                    v[r.b] = math.rotr(u64, v[r.b] ^ v[r.c], @as(usize, 63));
                }
            }

            for (&d.h, 0..) |*r, i| {
                r.* ^= v[i] ^ v[i + 8];
            }
        }
    };
}

test "blake2b160 single" {
    const h1 = "3345524abf6bbe1809449224b5972c41790b6cf2";
    try htest.assertEqualHash(Blake2b160, h1, "");

    const h2 = "384264f676f39536840523f284921cdc68b6846b";
    try htest.assertEqualHash(Blake2b160, h2, "abc");

    const h3 = "3c523ed102ab45a37d54f5610d5a983162fde84f";
    try htest.assertEqualHash(Blake2b160, h3, "The quick brown fox jumps over the lazy dog");

    const h4 = "43758f5de1740f651f1ae39de92260fe8bd5a11f";
    try htest.assertEqualHash(Blake2b160, h4, "a" ** 64 ++ "b" ** 64);
}

test "blake2b160 streaming" {
    var h = Blake2b160.init(.{});
    var out: [20]u8 = undefined;

    const h1 = "3345524abf6bbe1809449224b5972c41790b6cf2";

    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "384264f676f39536840523f284921cdc68b6846b";

    h = Blake2b160.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Blake2b160.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    const h3 = "43758f5de1740f651f1ae39de92260fe8bd5a11f";

    h = Blake2b160.init(.{});
    h.update("a" ** 64 ++ "b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2b160.init(.{});
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2b160.init(.{});
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    const h4 = "72328f8a8200663752fc302d372b5dd9b49dd8dc";

    h = Blake2b160.init(.{ .context = [_]u8{0x69} ** 16, .salt = [_]u8{0x42} ** 16 });
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);

    h = Blake2b160.init(.{ .context = [_]u8{0x69} ** 16, .salt = [_]u8{0x42} ** 16 });
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);
}

test "comptime blake2b160" {
    comptime {
        @setEvalBranchQuota(10000);
        var block = [_]u8{0} ** Blake2b160.block_length;
        var out: [Blake2b160.digest_length]u8 = undefined;

        const h1 = "8d26f158f564e3293b42f5e3d34263cb173aa9c9";

        try htest.assertEqualHash(Blake2b160, h1, block[0..]);

        var h = Blake2b160.init(.{});
        h.update(&block);
        h.final(out[0..]);

        try htest.assertEqual(h1, out[0..]);
    }
}

test "blake2b384 single" {
    const h1 = "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100";
    try htest.assertEqualHash(Blake2b384, h1, "");

    const h2 = "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4";
    try htest.assertEqualHash(Blake2b384, h2, "abc");

    const h3 = "b7c81b228b6bd912930e8f0b5387989691c1cee1e65aade4da3b86a3c9f678fc8018f6ed9e2906720c8d2a3aeda9c03d";
    try htest.assertEqualHash(Blake2b384, h3, "The quick brown fox jumps over the lazy dog");

    const h4 = "b7283f0172fecbbd7eca32ce10d8a6c06b453cb3cf675b33eb4246f0da2bb94a6c0bdd6eec0b5fd71ec4fd51be80bf4c";
    try htest.assertEqualHash(Blake2b384, h4, "a" ** 64 ++ "b" ** 64);
}

test "blake2b384 streaming" {
    var h = Blake2b384.init(.{});
    var out: [48]u8 = undefined;

    const h1 = "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100";

    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4";

    h = Blake2b384.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Blake2b384.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    const h3 = "b7283f0172fecbbd7eca32ce10d8a6c06b453cb3cf675b33eb4246f0da2bb94a6c0bdd6eec0b5fd71ec4fd51be80bf4c";

    h = Blake2b384.init(.{});
    h.update("a" ** 64 ++ "b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2b384.init(.{});
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2b384.init(.{});
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    const h4 = "934c48fcb197031c71f583d92f98703510805e72142e0b46f5752d1e971bc86c355d556035613ff7a4154b4de09dac5c";

    h = Blake2b384.init(.{ .context = [_]u8{0x69} ** 16, .salt = [_]u8{0x42} ** 16 });
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);

    h = Blake2b384.init(.{ .context = [_]u8{0x69} ** 16, .salt = [_]u8{0x42} ** 16 });
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h4, out[0..]);
}

test "comptime blake2b384" {
    comptime {
        @setEvalBranchQuota(20000);
        var block = [_]u8{0} ** Blake2b384.block_length;
        var out: [Blake2b384.digest_length]u8 = undefined;

        const h1 = "e8aa1931ea0422e4446fecdd25c16cf35c240b10cb4659dd5c776eddcaa4d922397a589404b46eb2e53d78132d05fd7d";

        try htest.assertEqualHash(Blake2b384, h1, block[0..]);

        var h = Blake2b384.init(.{});
        h.update(&block);
        h.final(out[0..]);

        try htest.assertEqual(h1, out[0..]);
    }
}

test "blake2b512 single" {
    const h1 = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
    try htest.assertEqualHash(Blake2b512, h1, "");

    const h2 = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
    try htest.assertEqualHash(Blake2b512, h2, "abc");

    const h3 = "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918";
    try htest.assertEqualHash(Blake2b512, h3, "The quick brown fox jumps over the lazy dog");

    const h4 = "049980af04d6a2cf16b4b49793c3ed7e40732073788806f2c989ebe9547bda0541d63abe298ec8955d08af48ae731f2e8a0bd6d201655a5473b4aa79d211b920";
    try htest.assertEqualHash(Blake2b512, h4, "a" ** 64 ++ "b" ** 64);
}

test "blake2b512 streaming" {
    var h = Blake2b512.init(.{});
    var out: [64]u8 = undefined;

    const h1 = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";

    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";

    h = Blake2b512.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Blake2b512.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    const h3 = "049980af04d6a2cf16b4b49793c3ed7e40732073788806f2c989ebe9547bda0541d63abe298ec8955d08af48ae731f2e8a0bd6d201655a5473b4aa79d211b920";

    h = Blake2b512.init(.{});
    h.update("a" ** 64 ++ "b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);

    h = Blake2b512.init(.{});
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);
    try htest.assertEqual(h3, out[0..]);
}

test "blake2b512 keyed" {
    var out: [64]u8 = undefined;

    const h1 = "8a978060ccaf582f388f37454363071ac9a67e3a704585fd879fb8a419a447e389c7c6de790faa20a7a7dccf197de736bc5b40b98a930b36df5bee7555750c4d";
    const key = "secret_key";

    Blake2b512.hash("a" ** 64 ++ "b" ** 64, &out, .{ .key = key });
    try htest.assertEqual(h1, out[0..]);

    var h = Blake2b512.init(.{ .key = key });
    h.update("a" ** 64 ++ "b" ** 64);
    h.final(out[0..]);

    try htest.assertEqual(h1, out[0..]);

    h = Blake2b512.init(.{ .key = key });
    h.update("a" ** 64);
    h.update("b" ** 64);
    h.final(out[0..]);

    try htest.assertEqual(h1, out[0..]);
}

test "comptime blake2b512" {
    comptime {
        @setEvalBranchQuota(12000);
        var block = [_]u8{0} ** Blake2b512.block_length;
        var out: [Blake2b512.digest_length]u8 = undefined;

        const h1 = "865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf798e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41";

        try htest.assertEqualHash(Blake2b512, h1, block[0..]);

        var h = Blake2b512.init(.{});
        h.update(&block);
        h.final(out[0..]);

        try htest.assertEqual(h1, out[0..]);
    }
}
// Translated from BLAKE3 reference implementation.
// Source: https://github.com/BLAKE3-team/BLAKE3

const std = @import("../std.zig");
const builtin = @import("builtin");
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;
const testing = std.testing;

const ChunkIterator = struct {
    slice: []u8,
    chunk_len: usize,

    fn init(slice: []u8, chunk_len: usize) ChunkIterator {
        return ChunkIterator{
            .slice = slice,
            .chunk_len = chunk_len,
        };
    }

    fn next(self: *ChunkIterator) ?[]u8 {
        const next_chunk = self.slice[0..@min(self.chunk_len, self.slice.len)];
        self.slice = self.slice[next_chunk.len..];
        return if (next_chunk.len > 0) next_chunk else null;
    }
};

const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const IV = [8]u32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const MSG_SCHEDULE = [7][16]u8{
    [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    [_]u8{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
    [_]u8{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
    [_]u8{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
    [_]u8{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
    [_]u8{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
    [_]u8{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
};

// These are the internal flags that we use to domain separate root/non-root,
// chunk/parent, and chunk beginning/middle/end. These get set at the high end
// of the block flags word in the compression function, so their values start
// high and go down.
const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const KEYED_HASH: u8 = 1 << 4;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

const CompressVectorized = struct {
    const Lane = @Vector(4, u32);
    const Rows = [4]Lane;

    inline fn g(comptime even: bool, rows: *Rows, m: Lane) void {
        rows[0] +%= rows[1] +% m;
        rows[3] ^= rows[0];
        rows[3] = math.rotr(Lane, rows[3], if (even) 8 else 16);
        rows[2] +%= rows[3];
        rows[1] ^= rows[2];
        rows[1] = math.rotr(Lane, rows[1], if (even) 7 else 12);
    }

    inline fn diagonalize(rows: *Rows) void {
        rows[0] = @shuffle(u32, rows[0], undefined, [_]i32{ 3, 0, 1, 2 });
        rows[3] = @shuffle(u32, rows[3], undefined, [_]i32{ 2, 3, 0, 1 });
        rows[2] = @shuffle(u32, rows[2], undefined, [_]i32{ 1, 2, 3, 0 });
    }

    inline fn undiagonalize(rows: *Rows) void {
        rows[0] = @shuffle(u32, rows[0], undefined, [_]i32{ 1, 2, 3, 0 });
        rows[3] = @shuffle(u32, rows[3], undefined, [_]i32{ 2, 3, 0, 1 });
        rows[2] = @shuffle(u32, rows[2], undefined, [_]i32{ 3, 0, 1, 2 });
    }

    fn compress(
        chaining_value: [8]u32,
        block_words: [16]u32,
        block_len: u32,
        counter: u64,
        flags: u8,
    ) [16]u32 {
        const md = Lane{ @as(u32, @truncate(counter)), @as(u32, @truncate(counter >> 32)), block_len, @as(u32, flags) };
        var rows = Rows{ chaining_value[0..4].*, chaining_value[4..8].*, IV[0..4].*, md };

        var m = Rows{ block_words[0..4].*, block_words[4..8].*, block_words[8..12].*, block_words[12..16].* };
        var t0 = @shuffle(u32, m[0], m[1], [_]i32{ 0, 2, (-1 - 0), (-1 - 2) });
        g(false, &rows, t0);
        var t1 = @shuffle(u32, m[0], m[1], [_]i32{ 1, 3, (-1 - 1), (-1 - 3) });
        g(true, &rows, t1);
        diagonalize(&rows);
        var t2 = @shuffle(u32, m[2], m[3], [_]i32{ 0, 2, (-1 - 0), (-1 - 2) });
        t2 = @shuffle(u32, t2, undefined, [_]i32{ 3, 0, 1, 2 });
        g(false, &rows, t2);
        var t3 = @shuffle(u32, m[2], m[3], [_]i32{ 1, 3, (-1 - 1), (-1 - 3) });
        t3 = @shuffle(u32, t3, undefined, [_]i32{ 3, 0, 1, 2 });
        g(true, &rows, t3);
        undiagonalize(&rows);
        m = Rows{ t0, t1, t2, t3 };

        var i: usize = 0;
        while (i < 6) : (i += 1) {
            t0 = @shuffle(u32, m[0], m[1], [_]i32{ 2, 1, (-1 - 1), (-1 - 3) });
            t0 = @shuffle(u32, t0, undefined, [_]i32{ 1, 2, 3, 0 });
            g(false, &rows, t0);
            t1 = @shuffle(u32, m[2], m[3], [_]i32{ 2, 2, (-1 - 3), (-1 - 3) });
            var tt = @shuffle(u32, m[0], undefined, [_]i32{ 3, 3, 0, 0 });
            t1 = @shuffle(u32, tt, t1, [_]i32{ 0, (-1 - 1), 2, (-1 - 3) });
            g(true, &rows, t1);
            diagonalize(&rows);
            t2 = @shuffle(u32, m[3], m[1], [_]i32{ 0, 1, (-1 - 0), (-1 - 1) });
            tt = @shuffle(u32, t2, m[2], [_]i32{ 0, 1, 2, (-1 - 3) });
            t2 = @shuffle(u32, tt, undefined, [_]i32{ 0, 2, 3, 1 });
            g(false, &rows, t2);
            t3 = @shuffle(u32, m[1], m[3], [_]i32{ 2, (-1 - 2), 3, (-1 - 3) });
            tt = @shuffle(u32, m[2], t3, [_]i32{ 0, (-1 - 0), 1, (-1 - 1) });
            t3 = @shuffle(u32, tt, undefined, [_]i32{ 2, 3, 1, 0 });
            g(true, &rows, t3);
            undiagonalize(&rows);
            m = Rows{ t0, t1, t2, t3 };
        }

        rows[0] ^= rows[2];
        rows[1] ^= rows[3];
        rows[2] ^= @Vector(4, u32){ chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3] };
        rows[3] ^= @Vector(4, u32){ chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7] };

        return @as([16]u32, @bitCast(rows));
    }
};

const CompressGeneric = struct {
    fn g(state: *[16]u32, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize, mx: u32, my: u32) void {
        state[a] +%= state[b] +% mx;
        state[d] = math.rotr(u32, state[d] ^ state[a], 16);
        state[c] +%= state[d];
        state[b] = math.rotr(u32, state[b] ^ state[c], 12);
        state[a] +%= state[b] +% my;
        state[d] = math.rotr(u32, state[d] ^ state[a], 8);
        state[c] +%= state[d];
        state[b] = math.rotr(u32, state[b] ^ state[c], 7);
    }

    fn round(state: *[16]u32, msg: [16]u32, schedule: [16]u8) void {
        // Mix the columns.
        g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
        g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
        g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
        g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

        // Mix the diagonals.
        g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
        g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
        g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
        g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
    }

    fn compress(
        chaining_value: [8]u32,
        block_words: [16]u32,
        block_len: u32,
        counter: u64,
        flags: u8,
    ) [16]u32 {
        var state = [16]u32{
            chaining_value[0],
            chaining_value[1],
            chaining_value[2],
            chaining_value[3],
            chaining_value[4],
            chaining_value[5],
            chaining_value[6],
            chaining_value[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            @as(u32, @truncate(counter)),
            @as(u32, @truncate(counter >> 32)),
            block_len,
            flags,
        };
        for (MSG_SCHEDULE) |schedule| {
            round(&state, block_words, schedule);
        }
        for (chaining_value, 0..) |_, i| {
            state[i] ^= state[i + 8];
            state[i + 8] ^= chaining_value[i];
        }
        return state;
    }
};

const compress = if (builtin.cpu.arch == .x86_64)
    CompressVectorized.compress
else
    CompressGeneric.compress;

fn first8Words(words: [16]u32) [8]u32 {
    return @as(*const [8]u32, @ptrCast(&words)).*;
}

fn wordsFromLittleEndianBytes(comptime count: usize, bytes: [count * 4]u8) [count]u32 {
    var words: [count]u32 = undefined;
    for (&words, 0..) |*word, i| {
        word.* = mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    }
    return words;
}

// Each chunk or parent node can produce either an 8-word chaining value or, by
// setting the ROOT flag, any number of final output bytes. The Output struct
// captures the state just prior to choosing between those two possibilities.
const Output = struct {
    input_chaining_value: [8]u32 align(16),
    block_words: [16]u32 align(16),
    block_len: u32,
    counter: u64,
    flags: u8,

    fn chainingValue(self: *const Output) [8]u32 {
        return first8Words(compress(
            self.input_chaining_value,
            self.block_words,
            self.block_len,
            self.counter,
            self.flags,
        ));
    }

    fn rootOutputBytes(self: *const Output, output: []u8) void {
        var out_block_it = ChunkIterator.init(output, 2 * OUT_LEN);
        var output_block_counter: usize = 0;
        while (out_block_it.next()) |out_block| {
            const words = compress(
                self.input_chaining_value,
                self.block_words,
                self.block_len,
                output_block_counter,
                self.flags | ROOT,
            );
            var out_word_it = ChunkIterator.init(out_block, 4);
            var word_counter: usize = 0;
            while (out_word_it.next()) |out_word| {
                var word_bytes: [4]u8 = undefined;
                mem.writeInt(u32, &word_bytes, words[word_counter], .little);
                @memcpy(out_word, word_bytes[0..out_word.len]);
                word_counter += 1;
            }
            output_block_counter += 1;
        }
    }
};

const ChunkState = struct {
    chaining_value: [8]u32 align(16),
    chunk_counter: u64,
    block: [BLOCK_LEN]u8 align(16) = [_]u8{0} ** BLOCK_LEN,
    block_len: u8 = 0,
    blocks_compressed: u8 = 0,
    flags: u8,

    fn init(key: [8]u32, chunk_counter: u64, flags: u8) ChunkState {
        return ChunkState{
            .chaining_value = key,
            .chunk_counter = chunk_counter,
            .flags = flags,
        };
    }

    fn len(self: *const ChunkState) usize {
        return BLOCK_LEN * @as(usize, self.blocks_compressed) + @as(usize, self.block_len);
    }

    fn fillBlockBuf(self: *ChunkState, input: []const u8) []const u8 {
        const want = BLOCK_LEN - self.block_len;
        const take = @min(want, input.len);
        @memcpy(self.block[self.block_len..][0..take], input[0..take]);
        self.block_len += @as(u8, @truncate(take));
        return input[take..];
    }

    fn startFlag(self: *const ChunkState) u8 {
        return if (self.blocks_compressed == 0) CHUNK_START else 0;
    }

    fn update(self: *ChunkState, input_slice: []const u8) void {
        var input = input_slice;
        while (input.len > 0) {
            // If the block buffer is full, compress it and clear it. More
            // input is coming, so this compression is not CHUNK_END.
            if (self.block_len == BLOCK_LEN) {
                const block_words = wordsFromLittleEndianBytes(16, self.block);
                self.chaining_value = first8Words(compress(
                    self.chaining_value,
                    block_words,
                    BLOCK_LEN,
                    self.chunk_counter,
                    self.flags | self.startFlag(),
                ));
                self.blocks_compressed += 1;
                self.block = [_]u8{0} ** BLOCK_LEN;
                self.block_len = 0;
            }

            // Copy input bytes into the block buffer.
            input = self.fillBlockBuf(input);
        }
    }

    fn output(self: *const ChunkState) Output {
        const block_words = wordsFromLittleEndianBytes(16, self.block);
        return Output{
            .input_chaining_value = self.chaining_value,
            .block_words = block_words,
            .block_len = self.block_len,
            .counter = self.chunk_counter,
            .flags = self.flags | self.startFlag() | CHUNK_END,
        };
    }
};

fn parentOutput(
    left_child_cv: [8]u32,
    right_child_cv: [8]u32,
    key: [8]u32,
    flags: u8,
) Output {
    var block_words: [16]u32 align(16) = undefined;
    block_words[0..8].* = left_child_cv;
    block_words[8..].* = right_child_cv;
    return Output{
        .input_chaining_value = key,
        .block_words = block_words,
        .block_len = BLOCK_LEN, // Always BLOCK_LEN (64) for parent nodes.
        .counter = 0, // Always 0 for parent nodes.
        .flags = PARENT | flags,
    };
}

fn parentCv(
    left_child_cv: [8]u32,
    right_child_cv: [8]u32,
    key: [8]u32,
    flags: u8,
) [8]u32 {
    return parentOutput(left_child_cv, right_child_cv, key, flags).chainingValue();
}

/// An incremental hasher that can accept any number of writes.
pub const Blake3 = struct {
    pub const Options = struct { key: ?[digest_length]u8 = null };
    pub const KdfOptions = struct {};

    chunk_state: ChunkState,
    key: [8]u32,
    cv_stack: [54][8]u32 = undefined, // Space for 54 subtree chaining values:
    cv_stack_len: u8 = 0, // 2^54 * CHUNK_LEN = 2^64
    flags: u8,

    pub const block_length = BLOCK_LEN;
    pub const digest_length = OUT_LEN;
    pub const key_length = KEY_LEN;

    fn init_internal(key: [8]u32, flags: u8) Blake3 {
        return Blake3{
            .chunk_state = ChunkState.init(key, 0, flags),
            .key = key,
            .flags = flags,
        };
    }

    /// Construct a new `Blake3` for the hash function, with an optional key
    pub fn init(options: Options) Blake3 {
        if (options.key) |key| {
            const key_words = wordsFromLittleEndianBytes(8, key);
            return Blake3.init_internal(key_words, KEYED_HASH);
        } else {
            return Blake3.init_internal(IV, 0);
        }
    }

    /// Construct a new `Blake3` for the key derivation function. The context
    /// string should be hardcoded, globally unique, and application-specific.
    pub fn initKdf(context: []const u8, options: KdfOptions) Blake3 {
        _ = options;
        var context_hasher = Blake3.init_internal(IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context);
        var context_key: [KEY_LEN]u8 = undefined;
        context_hasher.final(context_key[0..]);
        const context_key_words = wordsFromLittleEndianBytes(8, context_key);
        return Blake3.init_internal(context_key_words, DERIVE_KEY_MATERIAL);
    }

    pub fn hash(b: []const u8, out: []u8, options: Options) void {
        var d = Blake3.init(options);
        d.update(b);
        d.final(out);
    }

    fn pushCv(self: *Blake3, cv: [8]u32) void {
        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    fn popCv(self: *Blake3) [8]u32 {
        self.cv_stack_len -= 1;
        return self.cv_stack[self.cv_stack_len];
    }

    // Section 5.1.2 of the BLAKE3 spec explains this algorithm in more detail.
    fn addChunkChainingValue(self: *Blake3, first_cv: [8]u32, total_chunks: u64) void {
        // This chunk might complete some subtrees. For each completed subtree,
        // its left child will be the current top entry in the CV stack, and
        // its right child will be the current value of `new_cv`. Pop each left
        // child off the stack, merge it with `new_cv`, and overwrite `new_cv`
        // with the result. After all these merges, push the final value of
        // `new_cv` onto the stack. The number of completed subtrees is given
        // by the number of trailing 0-bits in the new total number of chunks.
        var new_cv = first_cv;
        var chunk_counter = total_chunks;
        while (chunk_counter & 1 == 0) {
            new_cv = parentCv(self.popCv(), new_cv, self.key, self.flags);
            chunk_counter >>= 1;
        }
        self.pushCv(new_cv);
    }

    /// Add input to the hash state. This can be called any number of times.
    pub fn update(self: *Blake3, input_slice: []const u8) void {
        var input = input_slice;
        while (input.len > 0) {
            // If the current chunk is complete, finalize it and reset the
            // chunk state. More input is coming, so this chunk is not ROOT.
            if (self.chunk_state.len() == CHUNK_LEN) {
                const chunk_cv = self.chunk_state.output().chainingValue();
                const total_chunks = self.chunk_state.chunk_counter + 1;
                self.addChunkChainingValue(chunk_cv, total_chunks);
                self.chunk_state = ChunkState.init(self.key, total_chunks, self.flags);
            }

            // Compress input bytes into the current chunk state.
            const want = CHUNK_LEN - self.chunk_state.len();
            const take = @min(want, input.len);
            self.chunk_state.update(input[0..take]);
            input = input[take..];
        }
    }

    /// Finalize the hash and write any number of output bytes.
    pub fn final(self: *const Blake3, out_slice: []u8) void {
        // Starting with the Output from the current chunk, compute all the
        // parent chaining values along the right edge of the tree, until we
        // have the root Output.
        var output = self.chunk_state.output();
        var parent_nodes_remaining: usize = self.cv_stack_len;
        while (parent_nodes_remaining > 0) {
            parent_nodes_remaining -= 1;
            output = parentOutput(
                self.cv_stack[parent_nodes_remaining],
                output.chainingValue(),
                self.key,
                self.flags,
            );
        }
        output.rootOutputBytes(out_slice);
    }

    pub const Error = error{};
    pub const Writer = std.io.Writer(*Blake3, Error, write);

    fn write(self: *Blake3, bytes: []const u8) Error!usize {
        self.update(bytes);
        return bytes.len;
    }

    pub fn writer(self: *Blake3) Writer {
        return .{ .context = self };
    }
};

// Use named type declarations to workaround crash with anonymous structs (issue #4373).
const ReferenceTest = struct {
    key: *const [KEY_LEN]u8,
    context_string: []const u8,
    cases: []const ReferenceTestCase,
};

const ReferenceTestCase = struct {
    input_len: usize,
    hash: *const [262]u8,
    keyed_hash: *const [262]u8,
    derive_key: *const [262]u8,
};

// Each test is an input length and three outputs, one for each of the `hash`, `keyed_hash`, and
// `derive_key` modes. The input in each case is filled with a 251-byte-long repeating pattern:
// 0, 1, 2, ..., 249, 250, 0, 1, ... The key used with `keyed_hash` is the 32-byte ASCII string
// given in the `key` field below. For `derive_key`, the test input is used as the input key, and
// the context string is 'BLAKE3 2019-12-27 16:29:52 test vectors context'. (As good practice for
// following the security requirements of `derive_key`, test runners should make that context
// string a hardcoded constant, and we do not provided it in machine-readable form.) Outputs are
// encoded as hexadecimal. Each case is an extended output, and implementations should also check
// that the first 32 bytes match their default-length output.
//
// Source: https://github.com/BLAKE3-team/BLAKE3/blob/92d421dea1a89e2f079f4dbd93b0dab41234b279/test_vectors/test_vectors.json
const reference_test = ReferenceTest{
    .key = "whats the Elvish word for friend",
    .context_string = "BLAKE3 2019-12-27 16:29:52 test vectors context",
    .cases = &[_]ReferenceTestCase{
        .{
            .input_len = 0,
            .hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
            .keyed_hash = "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f",
            .derive_key = "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0",
        },
        .{
            .input_len = 1,
            .hash = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5",
            .keyed_hash = "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b6568c0490609413006fbd428eb3fd14e7756d90f73a4725fad147f7bf70fd61c4e0cf7074885e92b0e3f125978b4154986d4fb202a3f331a3fb6cf349a3a70e49990f98fe4289761c8602c4e6ab1138d31d3b62218078b2f3ba9a88e1d08d0dd4cea11",
            .derive_key = "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c5827b91bf889b6b97c5477f535361caefca0b5d8c4746441c57617111933158950670f9aa8a05d791daae10ac683cbef8faf897c84e6114a59d2173c3f417023a35d6983f2c7dfa57e7fc559ad751dbfb9ffab39c2ef8c4aafebc9ae973a64f0c76551",
        },
        .{
            .input_len = 1023,
            .hash = "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b05592b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad3339c56778957d870eb9717b57ea3d9fb68d1b55127bba6a906a4a24bbd5acb2d123a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09b6522d9c8d822f2f28f485",
            .keyed_hash = "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e890316d2e6d8b8c25b0a5b2180f94fb1a158ef508c3cde45e2966bd796a696d3e13efd86259d756387d9becf5c8bf1ce2192b87025152907b6d8cc33d17826d8b7b9bc97e38c3c85108ef09f013e01c229c20a83d9e8efac5b37470da28575fd755a10",
            .derive_key = "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea59c413264404661e9e4d955409dfe4ad3aa487871bcd454ed12abfe2c2b1eb7757588cf6cb18d2eccad49e018c0d0fec323bec82bf1644c6325717d13ea712e6840d3e6e730d35553f59eff5377a9c350bcc1556694b924b858f329c44ee64b884ef00d",
        },
        .{
            .input_len = 1024,
            .hash = "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e",
            .keyed_hash = "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4a78bc838c72852d4f49c864acb7adafe2478e824afe51c8919d06168414c265f298a8094b1ad813a9b8614acabac321f24ce61c5a5346eb519520d38ecc43e89b5000236df0597243e4d2493fd626730e2ba17ac4d8824d09d1a4a8f57b8227778e2de",
            .derive_key = "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a6896843027066c23b601d3ddfb391e90d5c8eccdef4ae2a264bce9e612ba15e2bc9d654af1481b2e75dbabe615974f1070bba84d56853265a34330b4766f8e75edd1f4a1650476c10802f22b64bd3919d246ba20a17558bc51c199efdec67e80a227251808d8ce5bad",
        },
        .{
            .input_len = 1025,
            .hash = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a",
            .keyed_hash = "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d54085d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf82636cff4542540a7738d5b930",
            .derive_key = "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb5d31013a167509e9066273ab6e2123bc835b408b067d88f96addb550d96b6852dad38e320b9d940f86db74d398c770f462118b35d2724efa13da97194491d96dd37c3c09cbef665953f2ee85ec83d88b88d11547a6f911c8217cca46defa2751e7f3ad",
        },
        .{
            .input_len = 2048,
            .hash = "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf618ad094266d4fc3c968c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f53a8863ac75655461cea8f9",
            .keyed_hash = "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd10173b961cd574288194b23ece278c330fbb8585485e74967f31352a8183aa782b2b22f26cdcadb61eed1a5bc144b8198fbb0c13abbf8e3192c145d0a5c21633b0ef86054f42809df823389ee40811a5910dcbd1018af31c3b43aa55201ed4edaac74fe",
            .derive_key = "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23e2c11a1ebffcea4d80447867b61badb1383d842d4e79645d48dd82ccba290769caa7af8eaa1bd78a2a5e6e94fbdab78d9c7b74e894879f6a515257ccf6f95056f4e25390f24f6b35ffbb74b766202569b1d797f2d4bd9d17524c720107f985f4ddc583",
        },
        .{
            .input_len = 2049,
            .hash = "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d74103403822a2e0bc1eb193e7aecc9643a76b7bbc0c9f9c52e8783aae98764ca468962b5c2ec92f0c74eb5448d519713e09413719431c802f948dd5d90425a4ecdadece9eb178d80f26efccae630734dff63340285adec2aed3b51073ad3",
            .keyed_hash = "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5f9a88abfefdfa1e00b418971f2b39c64ca621e8eb37fceac57fd0c8fc8e117d43b81447be22d5d8186f8f5919ba6bcc6846bd7d50726c06d245672c2ad4f61702c646499ee1173daa061ffe15bf45a631e2946d616a4c345822f1151284712f76b2b0e",
            .derive_key = "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf27316d8e9e79081a80b046b60f6a263616f33ca464bd78d79fa18200d06c7fc9bffd808cc4755277a7d5e09da0f29ed150f6537ea9bed946227ff184cc66a72a5f8c1e4bd8b04e81cf40fe6dc4427ad5678311a61f4ffc39d195589bdbc670f63ae70f4b6",
        },
        .{
            .input_len = 3072,
            .hash = "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd29a3f6b0b978d6608335c09dc94ccf682f9951cdfc501bfe47b9c9189a6fc7b404d120258506341a6d802857322fbd20d3e5dae05b95c88793fa83db1cb08e7d8008d1599b6209d78336e24839724c191b2a52a80448306e0daa84a3fdb566661a37e11",
            .keyed_hash = "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df19177022f302d0529e4174cc507c463671217975e81dab02b8fdeb0d7ccc7568dd22574c783a76be215441b32e91b9a904be8ea81f7a0afd14bad8ee7c8efc305ace5d3dd61b996febe8da4f56ca0919359a7533216e2999fc87ff7d8f176fbecb3d6f34278b",
            .derive_key = "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b3604131bbd6e3ba573b6dd682fa0a63e5b165d39fc43a625d00207607a2bfeb65ff1d29292152e26b298868e3b87be95d6458f6f2ce6118437b632415abe6ad522874bcd79e4030a5e7bad2efa90a7a7c67e93f0a18fb28369d0a9329ab5c24134ccb0",
        },
        .{
            .input_len = 3073,
            .hash = "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd39a27ae3b79d68d89da9bf25bc27139ae65a324918a5f9b7828181e52cf373c84f35b639b7fccbb985b6f2fa56aea0c18f531203497b8bbd3a07ceb5926f1cab74d14bd66486d9a91eba99059a98bd1cd25876b2af5a76c3e9eed554ed72ea952b603bf",
            .keyed_hash = "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a96d6da3fe985054d3478865be9a092250839a697bbda74e279e8a9e69f0025e4cfddd6cfb434b1cd9543aaf97c635d1b451a4386041e4bb100f5e45407cbbc24fa53ea2de3536ccb329e4eb9466ec37093a42cf62b82903c696a93a50b702c80f3c3c5",
            .derive_key = "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081576288e552647a9d86481c2cae75c2dd4e7c5195fb9ada1ef50e9c5098c249d743929191441301c69e1f48505a4305ec1778450ee48b8e69dc23a25960fe33070ea549119599760a8a2d28aeca06b8c5e9ba58bc19e11fe57b6ee98aa44b2a8e6b14a5",
        },
        .{
            .input_len = 4096,
            .hash = "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e9690289e9409ddb1b99768eafe1623da896faf7e1114bebeadc1be30829b6f8af707d85c298f4f0ff4d9438aef948335612ae921e76d411c3a9111df62d27eaf871959ae0062b5492a0feb98ef3ed4af277f5395172dbe5c311918ea0074ce0036454f620",
            .keyed_hash = "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0bbb64a36edb564e01e4b4aaf3b060092a6b838bea44afebd2deb8298fa562b7b597c757b9df4c911c3ca462e2ac89e9a787357aaf74c3b56d5c07bc93ce899568a3eb17d9250c20f6c5f6c1e792ec9a2dcb715398d5a6ec6d5c54f586a00403a1af1de",
            .derive_key = "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9d78038f7b198596c6cc4a9ccf93223c08722d684f240ff6569075ed81591fd93f9fff1110b3a75bc67e426012e5588959cc5a4c192173a03c00731cf84544f65a2fb9378989f72e9694a6a394a8a30997c2e67f95a504e631cd2c5f55246024761b245",
        },
        .{
            .input_len = 4097,
            .hash = "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb99505f91b0b5600a11251652eacfa9497b31cd3c409ce2e45cfe6c0a016967316c426bd26f619eab5d70af9a418b845c608840390f361630bd497b1ab44019316357c61dbe091ce72fc16dc340ac3d6e009e050b3adac4b5b2c92e722cffdc46501531956",
            .keyed_hash = "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc606db4976cfdd266ae0abf667d9481831ff12e0caa268e7d3e57260c0824115a54ce595ccc897786d9dcbf495599cfd90157186a46ec800a6763f1c59e36197e9939e900809f7077c102f888caaf864b253bc41eea812656d46742e4ea42769f89b83f",
            .derive_key = "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8a897f66a400fed9198fd61dd2d58d382458e64e100128075fc54b860934e8de2e84170734b06e1d212a117100820dbc48292d148afa50567b8b84b1ec336ae10d40c8c975a624996e12de31abbe135d9d159375739c333798a80c64ae895e51e22f3ad",
        },
        .{
            .input_len = 5120,
            .hash = "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833acc61c8fdc114a2010ce8038c853e121e1544985133fccdd0a2d507e8e615e611e9a0ba4f47915f49e53d721816a9198e8b30f12d20ec3689989175f1bf7a300eee0d9321fad8da232ece6efb8e9fd81b42ad161f6b9550a069e66b11b40487a5f5059",
            .keyed_hash = "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e209b4dc9209cd80ce7c1f7c9a744658e7e288465717ae6e56d5463d4f80cdb2ef56495f6a4f5487f69749af0c34c2cdfa857f3056bf8d807336a14d7b89bf62bef2fb54f9af6a546f818dc1e98b9e07f8a5834da50fa28fb5874af91bf06020d1bf0120e",
            .derive_key = "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f6055d0cefd84d9d57fe792d65a278fd20384ac6c30fdb340092f1a74a92ace99c482b28f0fc0ef3b923e56ade20c6dba47e49227166251337d80a037e987ad3a7f728b5ab6dfafd6e2ab1bd583a95d9c895ba9c2422c24ea0f62961f0dca45cad47bfa0d",
        },
        .{
            .input_len = 5121,
            .hash = "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff96adaab0613a6146cdaabe498c3a94e529d3fc1da2bd08edf54ed64d40dcd6777647eac51d8277d70219a9694334a68bc8f0f23e20b0ff70ada6f844542dfa32cd4204ca1846ef76d811cdb296f65e260227f477aa7aa008bac878f72257484f2b6c95",
            .keyed_hash = "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d0240d07e63f13667a8d1490e5e04f13eb617aea16a8c8a5aaed1ef6fbde1b0515e3c81050b361af6ead126032998290b563e3caddeaebfab592e155f2e161fb7cba939092133f23f9e65245e58ec23457b78a2e8a125588aad6e07d7f11a85b88d375b72d",
            .derive_key = "b07f01e518e702f7ccb44a267e9e112d403a7b3f4883a47ffbed4b48339b3c341a0add0ac032ab5aaea1e4e5b004707ec5681ae0fcbe3796974c0b1cf31a194740c14519273eedaabec832e8a784b6e7cfc2c5952677e6c3f2c3914454082d7eb1ce1766ac7d75a4d3001fc89544dd46b5147382240d689bbbaefc359fb6ae30263165",
        },
        .{
            .input_len = 6144,
            .hash = "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca2054d742022da6fdda444ebc384b04a54c3ac5839b49da7d39f6d8a9db03deab32aade156c1c0311e9b3435cde0ddba0dce7b26a376cad121294b689193508dd63151603c6ddb866ad16c2ee41585d1633a2cea093bea714f4c5d6b903522045b20395c83",
            .keyed_hash = "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1dc35754060091dc5caf3efabe0603c60f45e415bb3407db67e6beb3d11cf8e4f7907561f05dace0c15807f4b5f389c841eb114d81a82c02a00b57206b1d11fa6e803486b048a5ce87105a686dee041207e095323dfe172df73deb8c9532066d88f9da7e",
            .derive_key = "2a95beae63ddce523762355cf4b9c1d8f131465780a391286a5d01abb5683a1597099e3c6488aab6c48f3c15dbe1942d21dbcdc12115d19a8b8465fb54e9053323a9178e4275647f1a9927f6439e52b7031a0b465c861a3fc531527f7758b2b888cf2f20582e9e2c593709c0a44f9c6e0f8b963994882ea4168827823eef1f64169fef",
        },
        .{
            .input_len = 6145,
            .hash = "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f18a2cfdd73c6e39dd75ce7c1c6e3ef238fd54465f053b25d21044ccb2093beb015015532b108313b5829c3621ce324b8e14229091b7c93f32db2e4e63126a377d2a63a3597997d4f1cba59309cb4af240ba70cebff9a23d5e3ff0cdae2cfd54e070022",
            .keyed_hash = "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539f3c184ca2f59780e27a576c1d1fb9772e99fd17881d02ac7dfd39675aca918453283ed8c3169085ef4a466b91c1649cc341dfdee60e32231fc34c9c4e0b9a2ba87ca8f372589c744c15fd6f985eec15e98136f25beeb4b13c4e43dc84abcc79cd4646c",
            .derive_key = "379bcc61d0051dd489f686c13de00d5b14c505245103dc040d9e4dd1facab8e5114493d029bdbd295aaa744a59e31f35c7f52dba9c3642f773dd0b4262a9980a2aef811697e1305d37ba9d8b6d850ef07fe41108993180cf779aeece363704c76483458603bbeeb693cffbbe5588d1f3535dcad888893e53d977424bb707201569a8d2",
        },
        .{
            .input_len = 7168,
            .hash = "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a5707c321c83361793b9af62a40f43b523df1c8633cecb4cd14d00bdc79c78fca5165b863893f6d38b02ff7236c5a9a8ad2dba87d24c547cab046c29fc5bc1ed142e1de4763613bb162a5a538e6ef05ed05199d751f9eb58d332791b8d73fb74e4fce95",
            .keyed_hash = "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fca2f01d5277d69bb681c70fa8d36094f73ec06e452c80d2ff2257ed82e7ba348400989a65ee8daa7094ae0933e3d2210ac6395c4af24f91c2b590ef87d7788d7066ea3eaebca4c08a4f14b9a27644f99084c3543711b64a070b94f2c9d1d8a90d035d52",
            .derive_key = "11c37a112765370c94a51415d0d651190c288566e295d505defdad895dae223730d5a5175a38841693020669c7638f40b9bc1f9f39cf98bda7a5b54ae24218a800a2116b34665aa95d846d97ea988bfcb53dd9c055d588fa21ba78996776ea6c40bc428b53c62b5f3ccf200f647a5aae8067f0ea1976391fcc72af1945100e2a6dcb88",
        },
        .{
            .input_len = 7169,
            .hash = "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e781798a8b20534be1ca9eb2ae2df3fae2ea60e48c6fb0b850b1385b5de0fe460dbe9d9f9b0d8db4435da75c601156df9d047f4ede008732eb17adc05d96180f8a73548522840779e6062d643b79478a6e8dbce68927f36ebf676ffa7d72d5f68f050b119c8",
            .keyed_hash = "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa5113c9e28d72fcbfc020814ce3f5d4fc867f01c8f5b6caf305b3ea8a8ba2da3ab69fabcb438f19ff11f5378ad4484d75c478de425fb8e6ee809b54eec9bdb184315dc856617c09f5340451bf42fd3270a7b0b6566169f242e533777604c118a6358250f54",
            .derive_key = "554b0a5efea9ef183f2f9b931b7497995d9eb26f5c5c6dad2b97d62fc5ac31d99b20652c016d88ba2a611bbd761668d5eda3e568e940faae24b0d9991c3bd25a65f770b89fdcadabcb3d1a9c1cb63e69721cacf1ae69fefdcef1e3ef41bc5312ccc17222199e47a26552c6adc460cf47a72319cb5039369d0060eaea59d6c65130f1dd",
        },
        .{
            .input_len = 8192,
            .hash = "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a635fe51a27db045a567c1ad51be5aa34c01c6651c4d9b5b5ac5d0fd58cf18dd61a47778566b797a8c67df7b1d60b97b19288d2d877bb2df417ace009dcb0241ca1257d62712b6a4043b4ff33f690d849da91ea3bf711ed583cb7b7a7da2839ba71309bbf",
            .keyed_hash = "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a4834464159dcbc12a0ba0c6d6eb41bac0ed6585cabfe0aca36a375e6c5480c22afdc40785c170f5a6b8a1107dbee282318d00d915ac9ed1143ad40765ec120042ee121cd2baa36250c618adaf9e27260fda2f94dea8fb6f08c04f8f10c78292aa46102",
            .derive_key = "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d4c9e58958553513b67f84f8eac653aeeb02ae1d5672dcecf91cd9985a0e67f4501910ecba25555395427ccc7241d70dc21c190e2aadee875e5aae6bf1912837e53411dabf7a56cbf8e4fb780432b0d7fe6cec45024a0788cf5874616407757e9e6bef7",
        },
        .{
            .input_len = 8193,
            .hash = "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3bb2282aa69be089359ea1154b9a9286c4a56af4de975a9aa4a5c497654914d279bea60bb6d2cf7225a2fa0ff5ef56bbe4b149f3ed15860f78b4e2ad04e158e375c1e0c0b551cd7dfc82f1b155c11b6b3ed51ec9edb30d133653bb5709d1dbd55f4e1ff6",
            .keyed_hash = "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5f03228648fd983aef045c2fa8290934b0866b615f585149587dda2299039965328835a2b18f1d63b7e300fc76ff260b571839fe44876a4eae66cbac8c67694411ed7e09df51068a22c6e67d6d3dd2cca8ff12e3275384006c80f4db68023f24eebba57",
            .derive_key = "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f12f20a01d6d622edf3de026a4db4e4526225debb93c1237934d71c7340bb5916158cbdafe9ac3225476b6ab57a12357db3abbad7a26c6e66290e44034fb08a20a8d0ec264f309994d2810c49cfba6989d7abb095897459f5425adb48aba07c5fb3c83c0",
        },
        .{
            .input_len = 16384,
            .hash = "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde49d764c270176e53e97bdffa58d549073f2c660be0e81293767ed4e4929f9ad34bbb39a529334c57c4a381ffd2a6d4bfdbf1482651b172aa883cc13408fa67758a3e47503f93f87720a3177325f7823251b85275f64636a8f1d599c2e49722f42e93893",
            .keyed_hash = "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0df9e601b101e4cf63a404dfe50f2e1865bb12edc8fca166579ce0c70dba5a5c0fc960ad6f3772183416a00bd29d4c6e651ea7620bb100c9449858bf14e1ddc9ecd35725581ca5b9160de04060045993d972571c3e8f71e9d0496bfa744656861b169d65",
            .derive_key = "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e160dc0b1f09caa35f2f417b9ef309dfe5ebd67f4c9507995a531374d099cf8ae317542e885ec6f589378864d3ea98716b3bbb65ef4ab5e0ab5bb298a501f19a41ec19af84a5e6b428ecd813b1a47ed91c9657c3fba11c406bc316768b58f6802c9e9b57",
        },
        .{
            .input_len = 31744,
            .hash = "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7b77304bd55fe73af663c02d3f52ea053ba43431ca5bab7bfea2f5e9d7121770d88f70ae9649ea713087d1914f7f312147e247f87eb2d4ffef0ac978bf7b6579d57d533355aa20b8b77b13fd09748728a5cc327a8ec470f4013226f",
            .keyed_hash = "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a4193a7258db2d9cd32a7a3ecfce46144114b15c2fcb68a618a976bd74515d47be08b628be420b5e830fade7c080e351a076fbc38641ad80c736c8a18fe3c66ce12f95c61c2462a9770d60d0f77115bbcd3782b593016a4e728d4c06cee4505cb0c08a42ec",
            .derive_key = "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e9759adeb797a3fbf771b1bcea30150a020e317982bf0d6e7d14dd9f064bc11025c25f31e81bd78a921db0174f03dd481d30e93fd8e90f8b2fee209f849f2d2a52f31719a490fb0ba7aea1e09814ee912eba111a9fde9d5c274185f7bae8ba85d300a2b",
        },
        .{
            .input_len = 102400,
            .hash = "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e",
            .keyed_hash = "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7f9dbdd3e1d81dcbca3ba241bb18760f207710b751846faaeb9dff8262710999a59b2aa1aca298a032d94eacfadf1aa192418eb54808db23b56e34213266aa08499a16b354f018fc4967d05f8b9d2ad87a7278337be9693fc638a3bfdbe314574ee6fc4",
            .derive_key = "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6d83a3e041bc3a48df2879f4a0a3ed40e7c961c73eff740f3117a0504c2dff4786d44fb17f1549eb0ba585e40ec29bf7732f0b7e286ff8acddc4cb1e23b87ff5d824a986458dcc6a04ac83969b80637562953df51ed1a7e90a7926924d2763778be8560",
        },
    },
};

fn testBlake3(hasher: *Blake3, input_len: usize, expected_hex: [262]u8) !void {
    // Save initial state
    const initial_state = hasher.*;

    // Setup input pattern
    var input_pattern: [251]u8 = undefined;
    for (&input_pattern, 0..) |*e, i| e.* = @as(u8, @truncate(i));

    // Write repeating input pattern to hasher
    var input_counter = input_len;
    while (input_counter > 0) {
        const update_len = @min(input_counter, input_pattern.len);
        hasher.update(input_pattern[0..update_len]);
        input_counter -= update_len;
    }

    // Read final hash value
    var actual_bytes: [expected_hex.len / 2]u8 = undefined;
    hasher.final(actual_bytes[0..]);

    // Compare to expected value
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    _ = fmt.hexToBytes(expected_bytes[0..], expected_hex[0..]) catch unreachable;
    try testing.expectEqual(actual_bytes, expected_bytes);

    // Restore initial state
    hasher.* = initial_state;
}

test "BLAKE3 reference test cases" {
    var hash_state = Blake3.init(.{});
    const hash = &hash_state;
    var keyed_hash_state = Blake3.init(.{ .key = reference_test.key.* });
    const keyed_hash = &keyed_hash_state;
    var derive_key_state = Blake3.initKdf(reference_test.context_string, .{});
    const derive_key = &derive_key_state;

    for (reference_test.cases) |t| {
        try testBlake3(hash, t.input_len, t.hash.*);
        try testBlake3(keyed_hash, t.input_len, t.keyed_hash.*);
        try testBlake3(derive_key, t.input_len, t.derive_key.*);
    }
}
buffer: []const u8,
index: u32,

pub const Bundle = @import("Certificate/Bundle.zig");

pub const Version = enum { v1, v2, v3 };

pub const Algorithm = enum {
    sha1WithRSAEncryption,
    sha224WithRSAEncryption,
    sha256WithRSAEncryption,
    sha384WithRSAEncryption,
    sha512WithRSAEncryption,
    ecdsa_with_SHA224,
    ecdsa_with_SHA256,
    ecdsa_with_SHA384,
    ecdsa_with_SHA512,
    md2WithRSAEncryption,
    md5WithRSAEncryption,
    curveEd25519,

    pub const map = std.StaticStringMap(Algorithm).initComptime(.{
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 }, .sha1WithRSAEncryption },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B }, .sha256WithRSAEncryption },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C }, .sha384WithRSAEncryption },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D }, .sha512WithRSAEncryption },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E }, .sha224WithRSAEncryption },
        .{ &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01 }, .ecdsa_with_SHA224 },
        .{ &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 }, .ecdsa_with_SHA256 },
        .{ &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 }, .ecdsa_with_SHA384 },
        .{ &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04 }, .ecdsa_with_SHA512 },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02 }, .md2WithRSAEncryption },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 }, .md5WithRSAEncryption },
        .{ &.{ 0x2B, 0x65, 0x70 }, .curveEd25519 },
    });

    pub fn Hash(comptime algorithm: Algorithm) type {
        return switch (algorithm) {
            .sha1WithRSAEncryption => crypto.hash.Sha1,
            .ecdsa_with_SHA224, .sha224WithRSAEncryption => crypto.hash.sha2.Sha224,
            .ecdsa_with_SHA256, .sha256WithRSAEncryption => crypto.hash.sha2.Sha256,
            .ecdsa_with_SHA384, .sha384WithRSAEncryption => crypto.hash.sha2.Sha384,
            .ecdsa_with_SHA512, .sha512WithRSAEncryption, .curveEd25519 => crypto.hash.sha2.Sha512,
            .md2WithRSAEncryption => @compileError("unimplemented"),
            .md5WithRSAEncryption => crypto.hash.Md5,
        };
    }
};

pub const AlgorithmCategory = enum {
    rsaEncryption,
    rsassa_pss,
    X9_62_id_ecPublicKey,
    curveEd25519,

    pub const map = std.StaticStringMap(AlgorithmCategory).initComptime(.{
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }, .rsaEncryption },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A }, .rsassa_pss },
        .{ &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 }, .X9_62_id_ecPublicKey },
        .{ &.{ 0x2B, 0x65, 0x70 }, .curveEd25519 },
    });
};

pub const Attribute = enum {
    commonName,
    serialNumber,
    countryName,
    localityName,
    stateOrProvinceName,
    streetAddress,
    organizationName,
    organizationalUnitName,
    postalCode,
    organizationIdentifier,
    pkcs9_emailAddress,
    domainComponent,

    pub const map = std.StaticStringMap(Attribute).initComptime(.{
        .{ &.{ 0x55, 0x04, 0x03 }, .commonName },
        .{ &.{ 0x55, 0x04, 0x05 }, .serialNumber },
        .{ &.{ 0x55, 0x04, 0x06 }, .countryName },
        .{ &.{ 0x55, 0x04, 0x07 }, .localityName },
        .{ &.{ 0x55, 0x04, 0x08 }, .stateOrProvinceName },
        .{ &.{ 0x55, 0x04, 0x09 }, .streetAddress },
        .{ &.{ 0x55, 0x04, 0x0A }, .organizationName },
        .{ &.{ 0x55, 0x04, 0x0B }, .organizationalUnitName },
        .{ &.{ 0x55, 0x04, 0x11 }, .postalCode },
        .{ &.{ 0x55, 0x04, 0x61 }, .organizationIdentifier },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 }, .pkcs9_emailAddress },
        .{ &.{ 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 }, .domainComponent },
    });
};

pub const NamedCurve = enum {
    secp384r1,
    secp521r1,
    X9_62_prime256v1,

    pub const map = std.StaticStringMap(NamedCurve).initComptime(.{
        .{ &.{ 0x2B, 0x81, 0x04, 0x00, 0x22 }, .secp384r1 },
        .{ &.{ 0x2B, 0x81, 0x04, 0x00, 0x23 }, .secp521r1 },
        .{ &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x```
