```
14, 13, 18),
    };
    var x = b.*;
    var j: usize = 0;
    while (j < 8) : (j += 2) {
        inline for (arx_steps) |r| {
            x[r.a] ^= math.rotl(u32, x[r.b] +% x[r.c], r.d);
        }
    }
    j = 0;
    while (j < 16) : (j += 1) {
        b[j] +%= x[j];
    }
}

fn salsaXor(tmp: *align(16) [16]u32, in: []align(16) const u32, out: []align(16) u32) void {
    blockXor(tmp, in, 1);
    salsa8core(tmp);
    blockCopy(out, tmp, 1);
}

fn blockMix(tmp: *align(16) [16]u32, in: []align(16) const u32, out: []align(16) u32, r: u30) void {
    blockCopy(tmp, @alignCast(in[(2 * r - 1) * 16 ..]), 1);
    var i: usize = 0;
    while (i < 2 * r) : (i += 2) {
        salsaXor(tmp, @alignCast(in[i * 16 ..]), @alignCast(out[i * 8 ..]));
        salsaXor(tmp, @alignCast(in[i * 16 + 16 ..]), @alignCast(out[i * 8 + r * 16 ..]));
    }
}

fn integerify(b: []align(16) const u32, r: u30) u64 {
    const j = (2 * r - 1) * 16;
    return @as(u64, b[j]) | @as(u64, b[j + 1]) << 32;
}

fn smix(b: []align(16) u8, r: u30, n: usize, v: []align(16) u32, xy: []align(16) u32) void {
    const x: []align(16) u32 = @alignCast(xy[0 .. 32 * r]);
    const y: []align(16) u32 = @alignCast(xy[32 * r ..]);

    for (x, 0..) |*v1, j| {
        v1.* = mem.readInt(u32, b[4 * j ..][0..4], .little);
    }

    var tmp: [16]u32 align(16) = undefined;
    var i: usize = 0;
    while (i < n) : (i += 2) {
        blockCopy(@alignCast(v[i * (32 * r) ..]), x, 2 * r);
        blockMix(&tmp, x, y, r);

        blockCopy(@alignCast(v[(i + 1) * (32 * r) ..]), y, 2 * r);
        blockMix(&tmp, y, x, r);
    }

    i = 0;
    while (i < n) : (i += 2) {
        var j = @as(usize, @intCast(integerify(x, r) & (n - 1)));
        blockXor(x, @alignCast(v[j * (32 * r) ..]), 2 * r);
        blockMix(&tmp, x, y, r);

        j = @as(usize, @intCast(integerify(y, r) & (n - 1)));
        blockXor(y, @alignCast(v[j * (32 * r) ..]), 2 * r);
        blockMix(&tmp, y, x, r);
    }

    for (x, 0..) |v1, j| {
        mem.writeInt(u32, b[4 * j ..][0..4], v1, .little);
    }
}

/// Scrypt parameters
pub const Params = struct {
    const Self = @This();

    /// The CPU/Memory cost parameter [ln] is log2(N).
    ln: u6,

    /// The [r]esource usage parameter specifies the block size.
    r: u30,

    /// The [p]arallelization parameter.
    /// A large value of [p] can be used to increase the computational cost of scrypt without
    /// increasing the memory usage.
    p: u30,

    /// Baseline parameters for interactive logins
    pub const interactive = Self.fromLimits(524288, 16777216);

    /// Baseline parameters for offline usage
    pub const sensitive = Self.fromLimits(33554432, 1073741824);

    /// Recommended parameters according to the
    /// [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
    pub const owasp = Self{ .ln = 17, .r = 8, .p = 1 };

    /// Create parameters from ops and mem limits, where mem_limit given in bytes
    pub fn fromLimits(ops_limit: u64, mem_limit: usize) Self {
        const ops = @max(32768, ops_limit);
        const r: u30 = 8;
        if (ops < mem_limit / 32) {
            const max_n = ops / (r * 4);
            return Self{ .r = r, .p = 1, .ln = @as(u6, @intCast(math.log2(max_n))) };
        } else {
            const max_n = mem_limit / (@as(usize, @intCast(r)) * 128);
            const ln = @as(u6, @intCast(math.log2(max_n)));
            const max_rp = @min(0x3fffffff, (ops / 4) / (@as(u64, 1) << ln));
            return Self{ .r = r, .p = @as(u30, @intCast(max_rp / @as(u64, r))), .ln = ln };
        }
    }
};

/// Apply scrypt to generate a key from a password.
///
/// scrypt is defined in RFC 7914.
///
/// allocator: mem.Allocator.
///
/// derived_key: Slice of appropriate size for generated key. Generally 16 or 32 bytes in length.
///              May be uninitialized. All bytes will be overwritten.
///              Maximum size is `derived_key.len / 32 == 0xffff_ffff`.
///
/// password: Arbitrary sequence of bytes of any length.
///
/// salt: Arbitrary sequence of bytes of any length.
///
/// params: Params.
pub fn kdf(
    allocator: mem.Allocator,
    derived_key: []u8,
    password: []const u8,
    salt: []const u8,
    params: Params,
) KdfError!void {
    if (derived_key.len == 0) return KdfError.WeakParameters;
    if (derived_key.len / 32 > 0xffff_ffff) return KdfError.OutputTooLong;
    if (params.ln == 0 or params.r == 0 or params.p == 0) return KdfError.WeakParameters;

    const n64 = @as(u64, 1) << params.ln;
    if (n64 > max_size) return KdfError.WeakParameters;
    const n = @as(usize, @intCast(n64));
    if (@as(u64, params.r) * @as(u64, params.p) >= 1 << 30 or
        params.r > max_int / 128 / @as(u64, params.p) or
        params.r > max_int / 256 or
        n > max_int / 128 / @as(u64, params.r)) return KdfError.WeakParameters;

    const xy = try allocator.alignedAlloc(u32, .@"16", 64 * params.r);
    defer allocator.free(xy);
    const v = try allocator.alignedAlloc(u32, .@"16", 32 * n * params.r);
    defer allocator.free(v);
    var dk = try allocator.alignedAlloc(u8, .@"16", params.p * 128 * params.r);
    defer allocator.free(dk);

    try pwhash.pbkdf2(dk, password, salt, 1, HmacSha256);
    var i: u32 = 0;
    while (i < params.p) : (i += 1) {
        smix(@alignCast(dk[i * 128 * params.r ..]), params.r, n, v, xy);
    }
    try pwhash.pbkdf2(derived_key, password, dk, 1, HmacSha256);
}

const crypt_format = struct {
    /// String prefix for scrypt
    pub const prefix = "$7$";

    /// Standard type for a set of scrypt parameters, with the salt and hash.
    pub fn HashResult(comptime crypt_max_hash_len: usize) type {
        return struct {
            ln: u6,
            r: u30,
            p: u30,
            salt: []const u8,
            hash: BinValue(crypt_max_hash_len),
        };
    }

    const Codec = CustomB64Codec("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".*);

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
            const max_encoded_length = Codec.encodedLen(max_len);

            buf: [max_len]u8 = undefined,
            len: usize = 0,

            /// Wrap an existing byte slice
            pub fn fromSlice(slice: []const u8) EncodingError!Self {
                if (slice.len > capacity) return EncodingError.NoSpaceLeft;
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
                const len = Codec.decodedLen(str.len);
                if (len > self.buf.len) return EncodingError.NoSpaceLeft;
                try Codec.decode(self.buf[0..len], str);
                self.len = len;
            }

            fn toB64(self: *const Self, buf: []u8) ![]const u8 {
                const value = self.constSlice();
                const len = Codec.encodedLen(value.len);
                if (len > buf.len) return EncodingError.NoSpaceLeft;
                const encoded = buf[0..len];
                Codec.encode(encoded, value);
                return encoded;
            }
        };
    }

    /// Expand binary data into a salt for the modular crypt format.
    pub fn saltFromBin(comptime len: usize, salt: [len]u8) [Codec.encodedLen(len)]u8 {
        var buf: [Codec.encodedLen(len)]u8 = undefined;
        Codec.encode(&buf, &salt);
        return buf;
    }

    /// Deserialize a string into a structure `T` (matching `HashResult`).
    pub fn deserialize(comptime T: type, str: []const u8) EncodingError!T {
        var out: T = undefined;

        if (str.len < 16) return EncodingError.InvalidEncoding;
        if (!mem.eql(u8, prefix, str[0..3])) return EncodingError.InvalidEncoding;
        out.ln = try Codec.intDecode(u6, str[3..4]);
        out.r = try Codec.intDecode(u30, str[4..9]);
        out.p = try Codec.intDecode(u30, str[9..14]);

        var it = mem.splitScalar(u8, str[14..], '$');

        const salt = it.first();
        if (@hasField(T, "salt")) out.salt = salt;

        const hash_str = it.next() orelse return EncodingError.InvalidEncoding;
        if (@hasField(T, "hash")) try out.hash.fromB64(hash_str);

        return out;
    }

    /// Serialize parameters into a string in modular crypt format.
    pub fn serialize(params: anytype, str: []u8) EncodingError![]const u8 {
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
        var header: [14]u8 = undefined;
        header[0..3].* = prefix.*;
        Codec.intEncode(header[3..4], params.ln);
        Codec.intEncode(header[4..9], params.r);
        Codec.intEncode(header[9..14], params.p);
        try out.writeAll(&header);
        try out.writeAll(params.salt);
        try out.writeAll("$");
        var buf: [@TypeOf(params.hash).max_encoded_length]u8 = undefined;
        const hash_str = try params.hash.toB64(&buf);
        try out.writeAll(hash_str);
    }

    /// Custom codec that maps 6 bits into 8 like regular Base64, but uses its own alphabet,
    /// encodes bits in little-endian, and can also encode integers.
    fn CustomB64Codec(comptime map: [64]u8) type {
        return struct {
            const map64 = map;

            fn encodedLen(len: usize) usize {
                return (len * 4 + 2) / 3;
            }

            fn decodedLen(len: usize) usize {
                return len / 4 * 3 + (len % 4) * 3 / 4;
            }

            fn intEncode(dst: []u8, src: anytype) void {
                var n = src;
                for (dst) |*x| {
                    x.* = map64[@as(u6, @truncate(n))];
                    n = math.shr(@TypeOf(src), n, 6);
                }
            }

            fn intDecode(comptime T: type, src: *const [(@bitSizeOf(T) + 5) / 6]u8) !T {
                var v: T = 0;
                for (src, 0..) |x, i| {
                    const vi = mem.indexOfScalar(u8, &map64, x) orelse return EncodingError.InvalidEncoding;
                    v |= @as(T, @intCast(vi)) << @as(math.Log2Int(T), @intCast(i * 6));
                }
                return v;
            }

            fn decode(dst: []u8, src: []const u8) !void {
                std.debug.assert(dst.len == decodedLen(src.len));
                var i: usize = 0;
                while (i < src.len / 4) : (i += 1) {
                    mem.writeInt(u24, dst[i * 3 ..][0..3], try intDecode(u24, src[i * 4 ..][0..4]), .little);
                }
                const leftover = src[i * 4 ..];
                var v: u24 = 0;
                for (leftover, 0..) |_, j| {
                    v |= @as(u24, try intDecode(u6, leftover[j..][0..1])) << @as(u5, @intCast(j * 6));
                }
                for (dst[i * 3 ..], 0..) |*x, j| {
                    x.* = @as(u8, @truncate(v >> @as(u5, @intCast(j * 8))));
                }
            }

            fn encode(dst: []u8, src: []const u8) void {
                std.debug.assert(dst.len == encodedLen(src.len));
                var i: usize = 0;
                while (i < src.len / 3) : (i += 1) {
                    intEncode(dst[i * 4 ..][0..4], mem.readInt(u24, src[i * 3 ..][0..3], .little));
                }
                const leftover = src[i * 3 ..];
                var v: u24 = 0;
                for (leftover, 0..) |x, j| {
                    v |= @as(u24, x) << @as(u5, @intCast(j * 8));
                }
                intEncode(dst[i * 4 ..], v);
            }
        };
    }
};

/// Hash and verify passwords using the PHC format.
const PhcFormatHasher = struct {
    const alg_id = "scrypt";
    const BinValue = phc_format.BinValue;

    const HashResult = struct {
        alg_id: []const u8,
        ln: u6,
        r: u30,
        p: u30,
        salt: BinValue(max_salt_len),
        hash: BinValue(max_hash_len),
    };

    /// Return a non-deterministic hash of the password encoded as a PHC-format string
    pub fn create(
        allocator: mem.Allocator,
        password: []const u8,
        params: Params,
        buf: []u8,
    ) HasherError![]const u8 {
        var salt: [default_salt_len]u8 = undefined;
        crypto.random.bytes(&salt);

        var hash: [default_hash_len]u8 = undefined;
        try kdf(allocator, &hash, password, &salt, params);

        return phc_format.serialize(HashResult{
            .alg_id = alg_id,
            .ln = params.ln,
            .r = params.r,
            .p = params.p,
            .salt = try BinValue(max_salt_len).fromSlice(&salt),
            .hash = try BinValue(max_hash_len).fromSlice(&hash),
        }, buf);
    }

    /// Verify a password against a PHC-format encoded string
    pub fn verify(
        allocator: mem.Allocator,
        str: []const u8,
        password: []const u8,
    ) HasherError!void {
        const hash_result = try phc_format.deserialize(HashResult, str);
        if (!mem.eql(u8, hash_result.alg_id, alg_id)) return HasherError.PasswordVerificationFailed;
        const params = Params{ .ln = hash_result.ln, .r = hash_result.r, .p = hash_result.p };
        const expected_hash = hash_result.hash.constSlice();
        var hash_buf: [max_hash_len]u8 = undefined;
        if (expected_hash.len > hash_buf.len) return HasherError.InvalidEncoding;
        const hash = hash_buf[0..expected_hash.len];
        try kdf(allocator, hash, password, hash_result.salt.constSlice(), params);
        if (!mem.eql(u8, hash, expected_hash)) return HasherError.PasswordVerificationFailed;
    }
};

/// Hash and verify passwords using the modular crypt format.
const CryptFormatHasher = struct {
    const BinValue = crypt_format.BinValue;
    const HashResult = crypt_format.HashResult(max_hash_len);

    /// Length of a string returned by the create() function
    pub const pwhash_str_length: usize = 101;

    /// Return a non-deterministic hash of the password encoded into the modular crypt format
    pub fn create(
        allocator: mem.Allocator,
        password: []const u8,
        params: Params,
        buf: []u8,
    ) HasherError![]const u8 {
        var salt_bin: [default_salt_len]u8 = undefined;
        crypto.random.bytes(&salt_bin);
        const salt = crypt_format.saltFromBin(salt_bin.len, salt_bin);

        var hash: [default_hash_len]u8 = undefined;
        try kdf(allocator, &hash, password, &salt, params);

        return crypt_format.serialize(HashResult{
            .ln = params.ln,
            .r = params.r,
            .p = params.p,
            .salt = &salt,
            .hash = try BinValue(max_hash_len).fromSlice(&hash),
        }, buf);
    }

    /// Verify a password against a string in modular crypt format
    pub fn verify(
        allocator: mem.Allocator,
        str: []const u8,
        password: []const u8,
    ) HasherError!void {
        const hash_result = try crypt_format.deserialize(HashResult, str);
        const params = Params{ .ln = hash_result.ln, .r = hash_result.r, .p = hash_result.p };
        const expected_hash = hash_result.hash.constSlice();
        var hash_buf: [max_hash_len]u8 = undefined;
        if (expected_hash.len > hash_buf.len) return HasherError.InvalidEncoding;
        const hash = hash_buf[0..expected_hash.len];
        try kdf(allocator, hash, password, hash_result.salt, params);
        if (!mem.eql(u8, hash, expected_hash)) return HasherError.PasswordVerificationFailed;
    }
};

/// Options for hashing a password.
///
/// Allocator is required for scrypt.
pub const HashOptions = struct {
    allocator: ?mem.Allocator,
    params: Params,
    encoding: pwhash.Encoding,
};

/// Compute a hash of a password using the scrypt key derivation function.
/// The function returns a string that includes all the parameters required for verification.
pub fn strHash(
    password: []const u8,
    options: HashOptions,
    out: []u8,
) Error![]const u8 {
    const allocator = options.allocator orelse return Error.AllocatorRequired;
    switch (options.encoding) {
        .phc => return PhcFormatHasher.create(allocator, password, options.params, out),
        .crypt => return CryptFormatHasher.create(allocator, password, options.params, out),
    }
}

/// Options for hash verification.
///
/// Allocator is required for scrypt.
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
    if (mem.startsWith(u8, str, crypt_format.prefix)) {
        return CryptFormatHasher.verify(allocator, str, password);
    } else {
        return PhcFormatHasher.verify(allocator, str, password);
    }
}

// These tests take way too long to run, so I have disabled them.
const run_long_tests = false;

test "kdf" {
    if (!run_long_tests) return error.SkipZigTest;

    const password = "testpass";
    const salt = "saltsalt";

    var dk: [32]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 15, .r = 8, .p = 1 });

    const hex = "1e0f97c3f6609024022fbe698da29c2fe53ef1087a8e396dc6d5d2a041e886de";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    try std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 1" {
    if (!run_long_tests) return error.SkipZigTest;

    const password = "";
    const salt = "";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 4, .r = 1, .p = 1 });

    const hex = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    try std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 2" {
    if (!run_long_tests) return error.SkipZigTest;

    const password = "password";
    const salt = "NaCl";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 10, .r = 8, .p = 16 });

    const hex = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    try std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 3" {
    if (!run_long_tests) return error.SkipZigTest;

    const password = "pleaseletmein";
    const salt = "SodiumChloride";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 14, .r = 8, .p = 1 });

    const hex = "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    try std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 4" {
    if (!run_long_tests) return error.SkipZigTest;

    const password = "pleaseletmein";
    const salt = "SodiumChloride";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 20, .r = 8, .p = 1 });

    const hex = "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    try std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "password hashing (crypt format)" {
    if (!run_long_tests) return error.SkipZigTest;

    const alloc = std.testing.allocator;

    const str = "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5";
    const password = "Y0!?iQa9M%5ekffW(`";
    try CryptFormatHasher.verify(alloc, str, password);

    const params = Params.interactive;
    var buf: [CryptFormatHasher.pwhash_str_length]u8 = undefined;
    const str2 = try CryptFormatHasher.create(alloc, password, params, &buf);
    try CryptFormatHasher.verify(alloc, str2, password);
}

test "strHash and strVerify" {
    if (!run_long_tests) return error.SkipZigTest;

    const alloc = std.testing.allocator;

    const password = "testpass";
    const params = Params.interactive;
    const verify_options = VerifyOptions{ .allocator = alloc };
    var buf: [128]u8 = undefined;

    {
        const str = try strHash(
            password,
            .{ .allocator = alloc, .params = params, .encoding = .crypt },
            &buf,
        );
        try strVerify(str, password, verify_options);
    }
    {
        const str = try strHash(
            password,
            .{ .allocator = alloc, .params = params, .encoding = .phc },
            &buf,
        );
        try strVerify(str, password, verify_options);
    }
}

test "unix-scrypt" {
    if (!run_long_tests) return error.SkipZigTest;

    const alloc = std.testing.allocator;

    // https://gitlab.com/jas/scrypt-unix-crypt/blob/master/unix-scrypt.txt
    {
        const str = "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D";
        const password = "pleaseletmein";
        try strVerify(str, password, .{ .allocator = alloc });
    }
    // one of the libsodium test vectors
    {
        const str = "$7$B6....1....75gBMAGwfFWZqBdyF3WdTQnWdUsuTiWjG1fF9c1jiSD$tc8RoB3.Em3/zNgMLWo2u00oGIoTyJv4fl3Fl8Tix72";
        const password = "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg nrDFal+Jxl3,2`#^tFSu%v_+7iYse8-cCkNf!tD=KrW)";
        try strVerify(str, password, .{ .allocator = alloc });
    }
}

test "crypt format" {
    const str = "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D";
    const params = try crypt_format.deserialize(crypt_format.HashResult(32), str);
    var buf: [str.len]u8 = undefined;
    const s1 = try crypt_format.serialize(params, &buf);
    try std.testing.expectEqualStrings(s1, str);
}

test "kdf fast" {
    const TestVector = struct {
        password: []const u8,
        salt: []const u8,
        params: Params,
        want: []const u8,
    };
    const test_vectors = [_]TestVector{
        .{
            .password = "p",
            .salt = "s",
            .params = .{ .ln = 1, .r = 1, .p = 1 },
            .want = &([_]u8{
                0x48, 0xb0, 0xd2, 0xa8, 0xa3, 0x27, 0x26, 0x11,
                0x98, 0x4c, 0x50, 0xeb, 0xd6, 0x30, 0xaf, 0x52,
            }),
        },
    };
    inline for (test_vectors) |v| {
        var dk: [v.want.len]u8 = undefined;
        try kdf(std.testing.allocator, &dk, v.password, v.salt, v.params);
        try std.testing.expectEqualSlices(u8, &dk, v.want);
    }
}
const std = @import("../std.zig");
const mem = std.mem;
const math = std.math;

const RoundParam = struct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    i: u32,
};

fn roundParam(a: usize, b: usize, c: usize, d: usize, e: usize, i: u32) RoundParam {
    return RoundParam{
        .a = a,
        .b = b,
        .c = c,
        .d = d,
        .e = e,
        .i = i,
    };
}

/// The SHA-1 function is now considered cryptographically broken.
/// Namely, it is feasible to find multiple inputs producing the same hash.
/// For a fast-performing, cryptographically secure hash function, see SHA512/256, BLAKE2 or BLAKE3.
pub const Sha1 = struct {
    const Self = @This();
    pub const block_length = 64;
    pub const digest_length = 20;
    pub const Options = struct {};

    s: [5]u32,
    // Streaming Cache
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init(options: Options) Self {
        _ = options;
        return Self{
            .s = [_]u32{
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            },
        };
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Sha1.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

            d.round(d.buf[0..]);
            d.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= b.len) : (off += 64) {
            d.round(b[off..][0..64]);
        }

        // Copy any remainder for next pass.
        @memcpy(d.buf[d.buf_len..][0 .. b.len - off], b[off..]);
        d.buf_len += @as(u8, @intCast(b[off..].len));

        d.total_len += b.len;
    }

    pub fn peek(d: Self) [digest_length]u8 {
        var copy = d;
        return copy.finalResult();
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        @memset(d.buf[d.buf_len..], 0);

        // Append padding bits.
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        // > 448 mod 512 so need to add an extra round to wrap around.
        if (64 - d.buf_len < 8) {
            d.round(d.buf[0..]);
            @memset(d.buf[0..], 0);
        }

        // Append message length.
        var i: usize = 1;
        var len = d.total_len >> 5;
        d.buf[63] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
        while (i < 8) : (i += 1) {
            d.buf[63 - i] = @as(u8, @intCast(len & 0xff));
            len >>= 8;
        }

        d.round(d.buf[0..]);

        for (d.s, 0..) |s, j| {
            mem.writeInt(u32, out[4 * j ..][0..4], s, .big);
        }
    }

    pub fn finalResult(d: *Self) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        d.final(&result);
        return result;
    }

    fn round(d: *Self, b: *const [64]u8) void {
        var s: [16]u32 = undefined;

        var v: [5]u32 = [_]u32{
            d.s[0],
            d.s[1],
            d.s[2],
            d.s[3],
            d.s[4],
        };

        const round0a = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 4, 0),
            roundParam(4, 0, 1, 2, 3, 1),
            roundParam(3, 4, 0, 1, 2, 2),
            roundParam(2, 3, 4, 0, 1, 3),
            roundParam(1, 2, 3, 4, 0, 4),
            roundParam(0, 1, 2, 3, 4, 5),
            roundParam(4, 0, 1, 2, 3, 6),
            roundParam(3, 4, 0, 1, 2, 7),
            roundParam(2, 3, 4, 0, 1, 8),
            roundParam(1, 2, 3, 4, 0, 9),
            roundParam(0, 1, 2, 3, 4, 10),
            roundParam(4, 0, 1, 2, 3, 11),
            roundParam(3, 4, 0, 1, 2, 12),
            roundParam(2, 3, 4, 0, 1, 13),
            roundParam(1, 2, 3, 4, 0, 14),
            roundParam(0, 1, 2, 3, 4, 15),
        };
        inline for (round0a) |r| {
            s[r.i] = mem.readInt(u32, b[r.i * 4 ..][0..4], .big);

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x5A827999 +% s[r.i & 0xf] +% ((v[r.b] & v[r.c]) | (~v[r.b] & v[r.d]));
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round0b = comptime [_]RoundParam{
            roundParam(4, 0, 1, 2, 3, 16),
            roundParam(3, 4, 0, 1, 2, 17),
            roundParam(2, 3, 4, 0, 1, 18),
            roundParam(1, 2, 3, 4, 0, 19),
        };
        inline for (round0b) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x5A827999 +% s[r.i & 0xf] +% ((v[r.b] & v[r.c]) | (~v[r.b] & v[r.d]));
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round1 = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 4, 20),
            roundParam(4, 0, 1, 2, 3, 21),
            roundParam(3, 4, 0, 1, 2, 22),
            roundParam(2, 3, 4, 0, 1, 23),
            roundParam(1, 2, 3, 4, 0, 24),
            roundParam(0, 1, 2, 3, 4, 25),
            roundParam(4, 0, 1, 2, 3, 26),
            roundParam(3, 4, 0, 1, 2, 27),
            roundParam(2, 3, 4, 0, 1, 28),
            roundParam(1, 2, 3, 4, 0, 29),
            roundParam(0, 1, 2, 3, 4, 30),
            roundParam(4, 0, 1, 2, 3, 31),
            roundParam(3, 4, 0, 1, 2, 32),
            roundParam(2, 3, 4, 0, 1, 33),
            roundParam(1, 2, 3, 4, 0, 34),
            roundParam(0, 1, 2, 3, 4, 35),
            roundParam(4, 0, 1, 2, 3, 36),
            roundParam(3, 4, 0, 1, 2, 37),
            roundParam(2, 3, 4, 0, 1, 38),
            roundParam(1, 2, 3, 4, 0, 39),
        };
        inline for (round1) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x6ED9EBA1 +% s[r.i & 0xf] +% (v[r.b] ^ v[r.c] ^ v[r.d]);
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round2 = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 4, 40),
            roundParam(4, 0, 1, 2, 3, 41),
            roundParam(3, 4, 0, 1, 2, 42),
            roundParam(2, 3, 4, 0, 1, 43),
            roundParam(1, 2, 3, 4, 0, 44),
            roundParam(0, 1, 2, 3, 4, 45),
            roundParam(4, 0, 1, 2, 3, 46),
            roundParam(3, 4, 0, 1, 2, 47),
            roundParam(2, 3, 4, 0, 1, 48),
            roundParam(1, 2, 3, 4, 0, 49),
            roundParam(0, 1, 2, 3, 4, 50),
            roundParam(4, 0, 1, 2, 3, 51),
            roundParam(3, 4, 0, 1, 2, 52),
            roundParam(2, 3, 4, 0, 1, 53),
            roundParam(1, 2, 3, 4, 0, 54),
            roundParam(0, 1, 2, 3, 4, 55),
            roundParam(4, 0, 1, 2, 3, 56),
            roundParam(3, 4, 0, 1, 2, 57),
            roundParam(2, 3, 4, 0, 1, 58),
            roundParam(1, 2, 3, 4, 0, 59),
        };
        inline for (round2) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x8F1BBCDC +% s[r.i & 0xf] +% ((v[r.b] & v[r.c]) ^ (v[r.b] & v[r.d]) ^ (v[r.c] & v[r.d]));
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round3 = comptime [_]RoundParam{
            roundParam(0, 1, 2, 3, 4, 60),
            roundParam(4, 0, 1, 2, 3, 61),
            roundParam(3, 4, 0, 1, 2, 62),
            roundParam(2, 3, 4, 0, 1, 63),
            roundParam(1, 2, 3, 4, 0, 64),
            roundParam(0, 1, 2, 3, 4, 65),
            roundParam(4, 0, 1, 2, 3, 66),
            roundParam(3, 4, 0, 1, 2, 67),
            roundParam(2, 3, 4, 0, 1, 68),
            roundParam(1, 2, 3, 4, 0, 69),
            roundParam(0, 1, 2, 3, 4, 70),
            roundParam(4, 0, 1, 2, 3, 71),
            roundParam(3, 4, 0, 1, 2, 72),
            roundParam(2, 3, 4, 0, 1, 73),
            roundParam(1, 2, 3, 4, 0, 74),
            roundParam(0, 1, 2, 3, 4, 75),
            roundParam(4, 0, 1, 2, 3, 76),
            roundParam(3, 4, 0, 1, 2, 77),
            roundParam(2, 3, 4, 0, 1, 78),
            roundParam(1, 2, 3, 4, 0, 79),
        };
        inline for (round3) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0xCA62C1D6 +% s[r.i & 0xf] +% (v[r.b] ^ v[r.c] ^ v[r.d]);
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        d.s[0] +%= v[0];
        d.s[1] +%= v[1];
        d.s[2] +%= v[2];
        d.s[3] +%= v[3];
        d.s[4] +%= v[4];
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

const htest = @import("test.zig");

test "sha1 single" {
    try htest.assertEqualHash(Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "");
    try htest.assertEqualHash(Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d", "abc");
    try htest.assertEqualHash(Sha1, "a49b2446a02c645bf419f995b67091253a04a259", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha1 streaming" {
    var h = Sha1.init(.{});
    var out: [20]u8 = undefined;

    h.final(&out);
    try htest.assertEqual("da39a3ee5e6b4b0d3255bfef95601890afd80709", out[0..]);

    h = Sha1.init(.{});
    h.update("abc");
    h.final(&out);
    try htest.assertEqual("a9993e364706816aba3e25717850c26c9cd0d89d", out[0..]);

    h = Sha1.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(&out);
    try htest.assertEqual("a9993e364706816aba3e25717850c26c9cd0d89d", out[0..]);
}

test "sha1 aligned final" {
    var block = [_]u8{0} ** Sha1.block_length;
    var out: [Sha1.digest_length]u8 = undefined;

    var h = Sha1.init(.{});
    h.update(&block);
    h.final(out[0..]);
}
//! Secure Hashing Algorithm 2 (SHA2)
//!
//! Published by the National Institute of Standards and Technology (NIST) [1] [2].
//!
//! Truncation mitigates length-extension attacks but increases vulnerability to collision
//! attacks. Collision attacks remain impractical for all types defined here.
//!
//! T: original hash function, whose output is simply truncated.
//!    A truncated output is just the first bytes of a longer output.
//! _: hash function with context separation.
//!    Different lengths produce completely different outputs.
//!
//! [1] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//! [2] https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf

const std = @import("../std.zig");
const builtin = @import("builtin");
const mem = std.mem;
const math = std.math;
const htest = @import("test.zig");

pub const Sha224 = Sha2x32(iv224, 224);
pub const Sha256 = Sha2x32(iv256, 256);
pub const Sha384 = Sha2x64(iv384, 384);
pub const Sha512 = Sha2x64(iv512, 512);

/// SHA-256 truncated to leftmost 192 bits.
pub const Sha256T192 = Sha2x32(iv256, 192);

/// SHA-512 truncated to leftmost 224 bits.
pub const Sha512T224 = Sha2x64(iv512, 224);
/// SHA-512 truncated to leftmost 256 bits.
pub const Sha512T256 = Sha2x64(iv512, 256);

/// SHA-512 with a different initialization vector truncated to leftmost 224 bits.
pub const Sha512_224 = Sha2x64(truncatedSha512Iv(224), 224);
/// SHA-512 with a different initialization vector truncated to leftmost 256 bits.
pub const Sha512_256 = Sha2x64(truncatedSha512Iv(256), 256);

/// Low 32 bits of iv384.
const iv224 = Iv32{
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
};
/// First thirty-two bits of the fractional parts of the square
/// roots of the first eight prime numbers.
const iv256 = Iv32{
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
};

/// First sixty-four bits of the fractional parts of the square
/// roots of the ninth through sixteenth prime numbers.
const iv384 = Iv64{
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
};
/// First sixty-four bits of the fractional parts of the square
/// roots of the first eight prime numbers.
const iv512 = Iv64{
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
};

const Iv32 = [8]u32;
fn Sha2x32(comptime iv: Iv32, digest_bits: comptime_int) type {
    return struct {
        const Self = @This();
        pub const block_length = 64;
        pub const digest_length = digest_bits / 8;
        pub const Options = struct {};

        s: [8]u32 align(16),
        // Streaming Cache
        buf: [64]u8 = undefined,
        buf_len: u8 = 0,
        total_len: u64 = 0,

        pub fn init(options: Options) Self {
            _ = options;
            return Self{ .s = iv };
        }

        pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
            var d = Self.init(options);
            d.update(b);
            d.final(out);
        }

        pub fn update(d: *Self, b: []const u8) void {
            var off: usize = 0;

            // Partial buffer exists from previous update. Copy into buffer then hash.
            if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
                off += 64 - d.buf_len;
                @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

                d.round(&d.buf);
                d.buf_len = 0;
            }

            // Full middle blocks.
            while (off + 64 <= b.len) : (off += 64) {
                d.round(b[off..][0..64]);
            }

            // Copy any remainder for next pass.
            const b_slice = b[off..];
            @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
            d.buf_len += @as(u8, @intCast(b[off..].len));

            d.total_len += b.len;
        }

        pub fn peek(d: Self) [digest_length]u8 {
            var copy = d;
            return copy.finalResult();
        }

        pub fn final(d: *Self, out: *[digest_length]u8) void {
            // The buffer here will never be completely full.
            @memset(d.buf[d.buf_len..], 0);

            // Append padding bits.
            d.buf[d.buf_len] = 0x80;
            d.buf_len += 1;

            // > 448 mod 512 so need to add an extra round to wrap around.
            if (64 - d.buf_len < 8) {
                d.round(&d.buf);
                @memset(d.buf[0..], 0);
            }

            // Append message length.
            var i: usize = 1;
            var len = d.total_len >> 5;
            d.buf[63] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
            while (i < 8) : (i += 1) {
                d.buf[63 - i] = @as(u8, @intCast(len & 0xff));
                len >>= 8;
            }

            d.round(&d.buf);

            // May truncate for possible 224 or 192 output
            const rr = d.s[0 .. digest_length / 4];

            for (rr, 0..) |s, j| {
                mem.writeInt(u32, out[4 * j ..][0..4], s, .big);
            }
        }

        pub fn finalResult(d: *Self) [digest_length]u8 {
            var result: [digest_length]u8 = undefined;
            d.final(&result);
            return result;
        }

        const W = [64]u32{
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
        };

        fn round(d: *Self, b: *const [64]u8) void {
            var s: [64]u32 align(16) = undefined;
            for (@as(*align(1) const [16]u32, @ptrCast(b)), 0..) |*elem, i| {
                s[i] = mem.readInt(u32, mem.asBytes(elem), .big);
            }

            if (!@inComptime()) {
                const V4u32 = @Vector(4, u32);
                switch (builtin.cpu.arch) {
                    .aarch64 => if (builtin.zig_backend != .stage2_c and comptime std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha2)) {
                        var x: V4u32 = d.s[0..4].*;
                        var y: V4u32 = d.s[4..8].*;
                        const s_v = @as(*[16]V4u32, @ptrCast(&s));

                        comptime var k: u8 = 0;
                        inline while (k < 16) : (k += 1) {
                            if (k > 3) {
                                s_v[k] = asm (
                                    \\sha256su0.4s %[w0_3], %[w4_7]
                                    \\sha256su1.4s %[w0_3], %[w8_11], %[w12_15]
                                    : [w0_3] "=w" (-> V4u32),
                                    : [_] "0" (s_v[k - 4]),
                                      [w4_7] "w" (s_v[k - 3]),
                                      [w8_11] "w" (s_v[k - 2]),
                                      [w12_15] "w" (s_v[k - 1]),
                                );
                            }

                            const w: V4u32 = s_v[k] +% @as(V4u32, W[4 * k ..][0..4].*);
                            asm volatile (
                                \\mov.4s v0, %[x]
                                \\sha256h.4s %[x], %[y], %[w]
                                \\sha256h2.4s %[y], v0, %[w]
                                : [x] "=w" (x),
                                  [y] "=w" (y),
                                : [_] "0" (x),
                                  [_] "1" (y),
                                  [w] "w" (w),
                                : "v0"
                            );
                        }

                        d.s[0..4].* = x +% @as(V4u32, d.s[0..4].*);
                        d.s[4..8].* = y +% @as(V4u32, d.s[4..8].*);
                        return;
                    },
                    // C backend doesn't currently support passing vectors to inline asm.
                    .x86_64 => if (builtin.zig_backend != .stage2_c and comptime std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .sha, .avx2 })) {
                        var x: V4u32 = [_]u32{ d.s[5], d.s[4], d.s[1], d.s[0] };
                        var y: V4u32 = [_]u32{ d.s[7], d.s[6], d.s[3], d.s[2] };
                        const s_v = @as(*[16]V4u32, @ptrCast(&s));

                        comptime var k: u8 = 0;
                        inline while (k < 16) : (k += 1) {
                            if (k < 12) {
                                var tmp = s_v[k];
                                s_v[k + 4] = asm (
                                    \\ sha256msg1 %[w4_7], %[tmp]
                                    \\ vpalignr $0x4, %[w8_11], %[w12_15], %[result]
                                    \\ paddd %[tmp], %[result]
                                    \\ sha256msg2 %[w12_15], %[result]
                                    : [tmp] "=&x" (tmp),
                                      [result] "=&x" (-> V4u32),
                                    : [_] "0" (tmp),
                                      [w4_7] "x" (s_v[k + 1]),
                                      [w8_11] "x" (s_v[k + 2]),
                                      [w12_15] "x" (s_v[k + 3]),
                                );
                            }

                            const w: V4u32 = s_v[k] +% @as(V4u32, W[4 * k ..][0..4].*);
                            y = asm ("sha256rnds2 %[x], %[y]"
                                : [y] "=x" (-> V4u32),
                                : [_] "0" (y),
                                  [x] "x" (x),
                                  [_] "{xmm0}" (w),
                            );

                            x = asm ("sha256rnds2 %[y], %[x]"
                                : [x] "=x" (-> V4u32),
                                : [_] "0" (x),
                                  [y] "x" (y),
                                  [_] "{xmm0}" (@as(V4u32, @bitCast(@as(u128, @bitCast(w)) >> 64))),
                            );
                        }

                        d.s[0] +%= x[3];
                        d.s[1] +%= x[2];
                        d.s[4] +%= x[1];
                        d.s[5] +%= x[0];
                        d.s[2] +%= y[3];
                        d.s[3] +%= y[2];
                        d.s[6] +%= y[1];
                        d.s[7] +%= y[0];
                        return;
                    },
                    else => {},
                }
            }

            var i: usize = 16;
            while (i < 64) : (i += 1) {
                s[i] = s[i - 16] +% s[i - 7] +% (math.rotr(u32, s[i - 15], @as(u32, 7)) ^ math.rotr(u32, s[i - 15], @as(u32, 18)) ^ (s[i - 15] >> 3)) +% (math.rotr(u32, s[i - 2], @as(u32, 17)) ^ math.rotr(u32, s[i - 2], @as(u32, 19)) ^ (s[i - 2] >> 10));
            }

            var v: [8]u32 = d.s;

            const round0 = comptime [_]RoundParam256{
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 0),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 1),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 2),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 3),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 4),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 5),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 6),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 7),
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 8),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 9),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 10),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 11),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 12),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 13),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 14),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 15),
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 16),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 17),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 18),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 19),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 20),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 21),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 22),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 23),
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 24),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 25),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 26),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 27),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 28),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 29),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 30),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 31),
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 32),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 33),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 34),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 35),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 36),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 37),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 38),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 39),
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 40),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 41),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 42),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 43),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 44),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 45),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 46),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 47),
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 48),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 49),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 50),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 51),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 52),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 53),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 54),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 55),
                roundParam256(0, 1, 2, 3, 4, 5, 6, 7, 56),
                roundParam256(7, 0, 1, 2, 3, 4, 5, 6, 57),
                roundParam256(6, 7, 0, 1, 2, 3, 4, 5, 58),
                roundParam256(5, 6, 7, 0, 1, 2, 3, 4, 59),
                roundParam256(4, 5, 6, 7, 0, 1, 2, 3, 60),
                roundParam256(3, 4, 5, 6, 7, 0, 1, 2, 61),
                roundParam256(2, 3, 4, 5, 6, 7, 0, 1, 62),
                roundParam256(1, 2, 3, 4, 5, 6, 7, 0, 63),
            };
            inline for (round0) |r| {
                v[r.h] = v[r.h] +% (math.rotr(u32, v[r.e], @as(u32, 6)) ^ math.rotr(u32, v[r.e], @as(u32, 11)) ^ math.rotr(u32, v[r.e], @as(u32, 25))) +% (v[r.g] ^ (v[r.e] & (v[r.f] ^ v[r.g]))) +% W[r.i] +% s[r.i];

                v[r.d] = v[r.d] +% v[r.h];

                v[r.h] = v[r.h] +% (math.rotr(u32, v[r.a], @as(u32, 2)) ^ math.rotr(u32, v[r.a], @as(u32, 13)) ^ math.rotr(u32, v[r.a], @as(u32, 22))) +% ((v[r.a] & (v[r.b] | v[r.c])) | (v[r.b] & v[r.c]));
            }

            for (&d.s, v) |*dv, vv| dv.* +%= vv;
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

const RoundParam256 = struct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    g: usize,
    h: usize,
    i: usize,
};

fn roundParam256(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize, g: usize, h: usize, i: usize) RoundParam256 {
    return RoundParam256{
        .a = a,
        .b = b,
        .c = c,
        .d = d,
        .e = e,
        .f = f,
        .g = g,
        .h = h,
        .i = i,
    };
}

test Sha224 {
    try htest.assertEqualHash(Sha224, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "");
    try htest.assertEqualHash(Sha224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "abc");
    try htest.assertEqualHash(Sha224, "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha224 streaming" {
    var h = Sha224.init(.{});
    var out: [28]u8 = undefined;

    h.final(out[0..]);
    try htest.assertEqual("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", out[0..]);

    h = Sha224.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", out[0..]);

    h = Sha224.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", out[0..]);
}

test Sha256 {
    try htest.assertEqualHash(Sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
    try htest.assertEqualHash(Sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
    try htest.assertEqualHash(Sha256, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test Sha256T192 {
    try htest.assertEqualHash(Sha256T192, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934c", "");
    try htest.assertEqualHash(Sha256T192, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9c", "abc");
    try htest.assertEqualHash(Sha256T192, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha256 streaming" {
    var h = Sha256.init(.{});
    var out: [32]u8 = undefined;

    h.final(out[0..]);
    try htest.assertEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", out[0..]);

    h = Sha256.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out[0..]);

    h = Sha256.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out[0..]);
}

test "sha256 aligned final" {
    var block = [_]u8{0} ** Sha256.block_length;
    var out: [Sha256.digest_length]u8 = undefined;

    var h = Sha256.init(.{});
    h.update(&block);
    h.final(out[0..]);
}

const Iv64 = [8]u64;
fn Sha2x64(comptime iv: Iv64, digest_bits: comptime_int) type {
    return struct {
        const Self = @This();
        pub const block_length = 128;
        pub const digest_length = std.math.divCeil(comptime_int, digest_bits, 8) catch unreachable;
        pub const Options = struct {};

        s: Iv64,
        // Streaming Cache
        buf: [128]u8 = undefined,
        buf_len: u8 = 0,
        total_len: u128 = 0,

        pub fn init(options: Options) Self {
            _ = options;
            return Self{ .s = iv };
        }

        pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
            var d = Self.init(options);
            d.update(b);
            d.final(out);
        }

        pub fn update(d: *Self, b: []const u8) void {
            var off: usize = 0;

            // Partial buffer exists from previous update. Copy into buffer then hash.
            if (d.buf_len != 0 and d.buf_len + b.len >= 128) {
                off += 128 - d.buf_len;
                @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

                d.round(&d.buf);
                d.buf_len = 0;
            }

            // Full middle blocks.
            while (off + 128 <= b.len) : (off += 128) {
                d.round(b[off..][0..128]);
            }

            // Copy any remainder for next pass.
            const b_slice = b[off..];
            @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
            d.buf_len += @as(u8, @intCast(b[off..].len));

            d.total_len += b.len;
        }

        pub fn peek(d: Self) [digest_length]u8 {
            var copy = d;
            return copy.finalResult();
        }

        pub fn final(d: *Self, out: *[digest_length]u8) void {
            // The buffer here will never be completely full.
            @memset(d.buf[d.buf_len..], 0);

            // Append padding bits.
            d.buf[d.buf_len] = 0x80;
            d.buf_len += 1;

            // > 896 mod 1024 so need to add an extra round to wrap around.
            if (128 - d.buf_len < 16) {
                d.round(d.buf[0..]);
                @memset(d.buf[0..], 0);
            }

            // Append message length.
            var i: usize = 1;
            var len = d.total_len >> 5;
            d.buf[127] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
            while (i < 16) : (i += 1) {
                d.buf[127 - i] = @as(u8, @intCast(len & 0xff));
                len >>= 8;
            }

            d.round(d.buf[0..]);

            // May truncate for possible 384 output
            const rr = d.s[0 .. digest_length / 8];

            for (rr, 0..) |s, j| {
                mem.writeInt(u64, out[8 * j ..][0..8], s, .big);
            }

            if (digest_bits % 8 != 0) @compileError("impl doesn't support non-byte digest_len");
            const bytes_left = digest_bits / 8 % 8;
            if (bytes_left > 0) {
                const rest = d.s[(digest_bits / 64)];
                var buf: [8]u8 = undefined;
                std.mem.writeInt(u64, &buf, rest, .big);
                @memcpy(out[digest_bits / 64 * 8 ..], buf[0..bytes_left]);
            }
        }

        pub fn finalResult(d: *Self) [digest_length]u8 {
            var result: [digest_length]u8 = undefined;
            d.final(&result);
            return result;
        }

        fn round(d: *Self, b: *const [128]u8) void {
            var s: [80]u64 = undefined;

            var i: usize = 0;
            while (i < 16) : (i += 1) {
                s[i] = mem.readInt(u64, b[i * 8 ..][0..8], .big);
            }
            while (i < 80) : (i += 1) {
                s[i] = s[i - 16] +% s[i - 7] +%
                    (math.rotr(u64, s[i - 15], @as(u64, 1)) ^ math.rotr(u64, s[i - 15], @as(u64, 8)) ^ (s[i - 15] >> 7)) +%
                    (math.rotr(u64, s[i - 2], @as(u64, 19)) ^ math.rotr(u64, s[i - 2], @as(u64, 61)) ^ (s[i - 2] >> 6));
            }

            var v: [8]u64 = d.s;

            const round0 = comptime [_]RoundParam512{
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 0, 0x428A2F98D728AE22),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 1, 0x7137449123EF65CD),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 2, 0xB5C0FBCFEC4D3B2F),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 3, 0xE9B5DBA58189DBBC),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 4, 0x3956C25BF348B538),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 5, 0x59F111F1B605D019),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 6, 0x923F82A4AF194F9B),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 7, 0xAB1C5ED5DA6D8118),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 8, 0xD807AA98A3030242),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 9, 0x12835B0145706FBE),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 10, 0x243185BE4EE4B28C),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 11, 0x550C7DC3D5FFB4E2),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 12, 0x72BE5D74F27B896F),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 13, 0x80DEB1FE3B1696B1),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 14, 0x9BDC06A725C71235),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 15, 0xC19BF174CF692694),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 16, 0xE49B69C19EF14AD2),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 17, 0xEFBE4786384F25E3),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 18, 0x0FC19DC68B8CD5B5),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 19, 0x240CA1CC77AC9C65),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 20, 0x2DE92C6F592B0275),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 21, 0x4A7484AA6EA6E483),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 22, 0x5CB0A9DCBD41FBD4),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 23, 0x76F988DA831153B5),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 24, 0x983E5152EE66DFAB),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 25, 0xA831C66D2DB43210),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 26, 0xB00327C898FB213F),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 27, 0xBF597FC7BEEF0EE4),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 28, 0xC6E00BF33DA88FC2),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 29, 0xD5A79147930AA725),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 30, 0x06CA6351E003826F),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 31, 0x142929670A0E6E70),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 32, 0x27B70A8546D22FFC),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 33, 0x2E1B21385C26C926),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 34, 0x4D2C6DFC5AC42AED),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 35, 0x53380D139D95B3DF),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 36, 0x650A73548BAF63DE),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 37, 0x766A0ABB3C77B2A8),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 38, 0x81C2C92E47EDAEE6),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 39, 0x92722C851482353B),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 40, 0xA2BFE8A14CF10364),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 41, 0xA81A664BBC423001),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 42, 0xC24B8B70D0F89791),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 43, 0xC76C51A30654BE30),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 44, 0xD192E819D6EF5218),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 45, 0xD69906245565A910),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 46, 0xF40E35855771202A),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 47, 0x106AA07032BBD1B8),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 48, 0x19A4C116B8D2D0C8),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 49, 0x1E376C085141AB53),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 50, 0x2748774CDF8EEB99),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 51, 0x34B0BCB5E19B48A8),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 52, 0x391C0CB3C5C95A63),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 53, 0x4ED8AA4AE3418ACB),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 54, 0x5B9CCA4F7763E373),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 55, 0x682E6FF3D6B2B8A3),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 56, 0x748F82EE5DEFB2FC),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 57, 0x78A5636F43172F60),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 58, 0x84C87814A1F0AB72),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 59, 0x8CC702081A6439EC),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 60, 0x90BEFFFA23631E28),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 61, 0xA4506CEBDE82BDE9),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 62, 0xBEF9A3F7B2C67915),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 63, 0xC67178F2E372532B),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 64, 0xCA273ECEEA26619C),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 65, 0xD186B8C721C0C207),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 66, 0xEADA7DD6CDE0EB1E),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 67, 0xF57D4F7FEE6ED178),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 68, 0x06F067AA72176FBA),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 69, 0x0A637DC5A2C898A6),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 70, 0x113F9804BEF90DAE),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 71, 0x1B710B35131C471B),
                roundParam512(0, 1, 2, 3, 4, 5, 6, 7, 72, 0x28DB77F523047D84),
                roundParam512(7, 0, 1, 2, 3, 4, 5, 6, 73, 0x32CAAB7B40C72493),
                roundParam512(6, 7, 0, 1, 2, 3, 4, 5, 74, 0x3C9EBE0A15C9BEBC),
                roundParam512(5, 6, 7, 0, 1, 2, 3, 4, 75, 0x431D67C49C100D4C),
                roundParam512(4, 5, 6, 7, 0, 1, 2, 3, 76, 0x4CC5D4BECB3E42B6),
                roundParam512(3, 4, 5, 6, 7, 0, 1, 2, 77, 0x597F299CFC657E2A),
                roundParam512(2, 3, 4, 5, 6, 7, 0, 1, 78, 0x5FCB6FAB3AD6FAEC),
                roundParam512(1, 2, 3, 4, 5, 6, 7, 0, 79, 0x6C44198C4A475817),
            };
            inline for (round0) |r| {
                v[r.h] = v[r.h] +% (math.rotr(u64, v[r.e], @as(u64, 14)) ^ math.rotr(u64, v[r.e], @as(u64, 18)) ^ math.rotr(u64, v[r.e], @as(u64, 41))) +% (v[r.g] ^ (v[r.e] & (v[r.f] ^ v[r.g]))) +% r.k +% s[r.i];

                v[r.d] = v[r.d] +% v[r.h];

                v[r.h] = v[r.h] +% (math.rotr(u64, v[r.a], @as(u64, 28)) ^ math.rotr(u64, v[r.a], @as(u64, 34)) ^ math.rotr(u64, v[r.a], @as(u64, 39))) +% ((v[r.a] & (v[r.b] | v[r.c])) | (v[r.b] & v[r.c]));
            }

            for (&d.s, v) |*dv, vv| dv.* +%= vv;
        }
    };
}

const RoundParam512 = struct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    g: usize,
    h: usize,
    i: usize,
    k: u64,
};

fn roundParam512(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize, g: usize, h: usize, i: usize, k: u64) RoundParam512 {
    return RoundParam512{
        .a = a,
        .b = b,
        .c = c,
        .d = d,
        .e = e,
        .f = f,
        .g = g,
        .h = h,
        .i = i,
        .k = k,
    };
}

/// Compute the IV for a truncated version of SHA512 per FIPS 180 Section 5.3.6
fn truncatedSha512Iv(digest_len: comptime_int) Iv64 {
    const assert = std.debug.assert;
    comptime assert(digest_len > 1);
    comptime assert(digest_len <= 512);
    comptime assert(digest_len != 384); // NIST specially defines this (see `iv384`)

    comptime var gen_params = iv512;
    inline for (&gen_params) |*iv| {
        iv.* ^= 0xa5a5a5a5a5a5a5a5;
    }
    const GenHash = Sha2x64(gen_params, 512);

    var params: [@sizeOf(Iv64)]u8 = undefined;
    const algo_str = std.fmt.comptimePrint("SHA-512/{d}", .{digest_len});
    GenHash.hash(algo_str, &params, .{});

    return Iv64{
        std.mem.readInt(u64, params[0..8], .big),
        std.mem.readInt(u64, params[8..16], .big),
        std.mem.readInt(u64, params[16..24], .big),
        std.mem.readInt(u64, params[24..32], .big),
        std.mem.readInt(u64, params[32..40], .big),
        std.mem.readInt(u64, params[40..48], .big),
        std.mem.readInt(u64, params[48..56], .big),
        std.mem.readInt(u64, params[56..64], .big),
    };
}

test truncatedSha512Iv {
    // Section 5.3.6.1
    try std.testing.expectEqual(Iv64{
        0x8C3D37C819544DA2,
        0x73E1996689DCD4D6,
        0x1DFAB7AE32FF9C82,
        0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8,
        0x77E36F7304C48942,
        0x3F9D85A86A1D36C8,
        0x1112E6AD91D692A1,
    }, truncatedSha512Iv(224));
    // Section 5.3.6.2
    try std.testing.expectEqual(Iv64{
        0x22312194FC2BF72C,
        0x9F555FA3C84C64C2,
        0x2393B86B6F53B151,
        0x963877195940EABD,
        0x96283EE2A88EFFE3,
        0xBE5E1E2553863992,
        0x2B0199FC2C85B8AA,
        0x0EB72DDC81C52CA2,
    }, truncatedSha512Iv(256));
}

test Sha384 {
    const h1 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    try htest.assertEqualHash(Sha384, h1, "");

    const h2 = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    try htest.assertEqualHash(Sha384, h2, "abc");

    const h3 = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039";
    try htest.assertEqualHash(Sha384, h3, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha384 streaming" {
    var h = Sha384.init(.{});
    var out: [48]u8 = undefined;

    const h1 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";

    h = Sha384.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Sha384.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);
}

test Sha512 {
    const h1 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    try htest.assertEqualHash(Sha512, h1, "");

    const h2 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    try htest.assertEqualHash(Sha512, h2, "abc");

    const h3 = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
    try htest.assertEqualHash(Sha512, h3, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha512 streaming" {
    var h = Sha512.init(.{});
    var out: [64]u8 = undefined;

    const h1 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    h = Sha512.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Sha512.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);
}

test "sha512 aligned final" {
    var block = [_]u8{0} ** Sha512.block_length;
    var out: [Sha512.digest_length]u8 = undefined;

    var h = Sha512.init(.{});
    h.update(&block);
    h.final(out[0..]);
}

test Sha512_224 {
    const h1 = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4";
    try htest.assertEqualHash(Sha512_224, h1, "");

    const h2 = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa";
    try htest.assertEqualHash(Sha512_224, h2, "abc");

    const h3 = "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9";
    try htest.assertEqualHash(Sha512_224, h3, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test Sha512_256 {
    const h1 = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a";
    try htest.assertEqualHash(Sha512_256, h1, "");

    const h2 = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23";
    try htest.assertEqualHash(Sha512_256, h2, "abc");

    const h3 = "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a";
    try htest.assertEqualHash(Sha512_256, h3, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}
const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

const KeccakState = std.crypto.core.keccak.State;

pub const Sha3_224 = Keccak(1600, 224, 0x06, 24);
pub const Sha3_256 = Keccak(1600, 256, 0x06, 24);
pub const Sha3_384 = Keccak(1600, 384, 0x06, 24);
pub const Sha3_512 = Keccak(1600, 512, 0x06, 24);

pub const Keccak256 = Keccak(1600, 256, 0x01, 24);
pub const Keccak512 = Keccak(1600, 512, 0x01, 24);

pub const Shake128 = Shake(128);
pub const Shake256 = Shake(256);

pub const CShake128 = CShake(128, null);
pub const CShake256 = CShake(256, null);

pub const KMac128 = KMac(128);
pub const KMac256 = KMac(256);

pub const TupleHash128 = TupleHash(128);
pub const TupleHash256 = TupleHash(256);

/// TurboSHAKE128 is a XOF (a secure hash function with a variable output length), with a 128 bit security level.
/// It is based on the same permutation as SHA3 and SHAKE128, but which much higher performance.
/// The delimiter is 0x1f by default, but can be changed for context-separation.
/// For a protocol that uses both KangarooTwelve and TurboSHAKE128, it is recommended to avoid using 0x06, 0x07 or 0x0b for the delimiter.
pub fn TurboShake128(delim: ?u7) type {
    return TurboShake(128, delim);
}

/// TurboSHAKE256 is a XOF (a secure hash function with a variable output length), with a 256 bit security level.
/// It is based on the same permutation as SHA3 and SHAKE256, but which much higher performance.
/// The delimiter is 0x1f by default, but can be changed for context-separation.
pub fn TurboShake256(comptime delim: ?u7) type {
    return TurboShake(256, delim);
}

/// A generic Keccak hash function.
pub fn Keccak(comptime f: u11, comptime output_bits: u11, comptime default_delim: u8, comptime rounds: u5) type {
    comptime assert(output_bits > 0 and output_bits * 2 < f and output_bits % 8 == 0); // invalid output length

    const State = KeccakState(f, output_bits * 2, rounds);

    return struct {
        const Self = @This();

        st: State,

        /// The output length, in bytes.
        pub const digest_length = std.math.divCeil(comptime_int, output_bits, 8) catch unreachable;
        /// The block length, or rate, in bytes.
        pub const block_length = State.rate;
        /// The delimiter can be overwritten in the options.
        pub const Options = struct { delim: u8 = default_delim };

        /// Initialize a Keccak hash function.
        pub fn init(options: Options) Self {
            return Self{ .st = .{ .delim = options.delim } };
        }

        /// Hash a slice of bytes.
        pub fn hash(bytes: []const u8, out: *[digest_length]u8, options: Options) void {
            var st = Self.init(options);
            st.update(bytes);
            st.final(out);
        }

        /// Absorb a slice of bytes into the state.
        pub fn update(self: *Self, bytes: []const u8) void {
            self.st.absorb(bytes);
        }

        /// Return the hash of the absorbed bytes.
        pub fn final(self: *Self, out: *[digest_length]u8) void {
            self.st.pad();
            self.st.squeeze(out[0..]);
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

/// The SHAKE extendable output hash function.
pub fn Shake(comptime security_level: u11) type {
    return ShakeLike(security_level, 0x1f, 24);
}

/// The TurboSHAKE extendable output hash function.
/// It is based on the same permutation as SHA3 and SHAKE, but which much higher performance.
/// The delimiter is 0x1f by default, but can be changed for context-separation.
/// https://eprint.iacr.org/2023/342
pub fn TurboShake(comptime security_level: u11, comptime delim: ?u7) type {
    comptime assert(security_level <= 256);
    const d = delim orelse 0x1f;
    comptime assert(d >= 0x01); // delimiter must be >= 1
    return ShakeLike(security_level, d, 12);
}

fn ShakeLike(comptime security_level: u11, comptime default_delim: u8, comptime rounds: u5) type {
    const f = 1600;
    const State = KeccakState(f, security_level * 2, rounds);

    return struct {
        const Self = @This();

        st: State,
        buf: [State.rate]u8 = undefined,
        offset: usize = 0,
        padded: bool = false,

        /// The recommended output length, in bytes.
        pub const digest_length = security_level / 8 * 2;
        /// The block length, or rate, in bytes.
        pub const block_length = State.rate;
        /// The delimiter can be overwritten in the options.
        pub const Options = struct { delim: u8 = default_delim };

        /// Initialize a SHAKE extensible hash function.
        pub fn init(options: Options) Self {
            return Self{ .st = .{ .delim = options.delim } };
        }

        /// Hash a slice of bytes.
        /// `out` can be any length.
        pub fn hash(bytes: []const u8, out: []u8, options: Options) void {
            var st = Self.init(options);
            st.update(bytes);
            st.squeeze(out);
        }

        /// Absorb a slice of bytes into the state.
        pub fn update(self: *Self, bytes: []const u8) void {
            self.st.absorb(bytes);
        }

        /// Squeeze a slice of bytes from the state.
        /// `out` can be any length, and the function can be called multiple times.
        pub fn squeeze(self: *Self, out_: []u8) void {
            if (!self.padded) {
                self.st.pad();
                self.padded = true;
            }
            var out = out_;
            if (self.offset > 0) {
                const left = self.buf.len - self.offset;
                if (left > 0) {
                    const n = @min(left, out.len);
                    @memcpy(out[0..n], self.buf[self.offset..][0..n]);
                    out = out[n..];
                    self.offset += n;
                    if (out.len == 0) {
                        return;
                    }
                }
            }
            const full_blocks = out[0 .. out.len - out.len % State.rate];
            if (full_blocks.len > 0) {
                self.st.squeeze(full_blocks);
                out = out[full_blocks.len..];
            }
            if (out.len > 0) {
                self.st.squeeze(self.buf[0..]);
                @memcpy(out[0..], self.buf[0..out.len]);
                self.offset = out.len;
            }
        }

        /// Return the hash of the absorbed bytes.
        /// `out` can be of any length, but the function must not be called multiple times (use `squeeze` for that purpose instead).
        pub fn final(self: *Self, out: []u8) void {
            self.squeeze(out);
            self.st.st.clear(0, State.rate);
        }

        /// Align the input to a block boundary.
        pub fn fillBlock(self: *Self) void {
            self.st.fillBlock();
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

/// The cSHAKE extendable output hash function.
/// cSHAKE is similar to SHAKE, but in addition to the input message, it also takes an optional context (aka customization string).
pub fn CShake(comptime security_level: u11, comptime fname: ?[]const u8) type {
    return CShakeLike(security_level, 0x04, 24, fname);
}

fn CShakeLike(comptime security_level: u11, comptime default_delim: u8, comptime rounds: u5, comptime fname: ?[]const u8) type {
    return struct {
        const Shaker = ShakeLike(security_level, default_delim, rounds);
        shaker: Shaker,

        /// The recommended output length, in bytes.
        pub const digest_length = Shaker.digest_length;
        /// The block length, or rate, in bytes.
        pub const block_length = Shaker.block_length;

        /// cSHAKE options can include a context string.
        pub const Options = struct { context: ?[]const u8 = null };

        const Self = @This();

        /// Initialize a SHAKE extensible hash function.
        pub fn init(options: Options) Self {
            if (fname == null and options.context == null) {
                return Self{ .shaker = Shaker.init(.{ .delim = 0x1f }) };
            }
            var shaker = Shaker.init(.{});
            comptime assert(Shaker.block_length % 8 == 0);
            const encoded_rate_len = NistLengthEncoding.encode(.left, block_length / 8);
            shaker.update(encoded_rate_len.slice());
            const encoded_zero = comptime NistLengthEncoding.encode(.left, 0);
            if (fname) |name| {
                const encoded_fname_len = comptime NistLengthEncoding.encode(.left, name.len);
                const encoded_fname = comptime encoded_fname_len.slice() ++ name;
                shaker.update(encoded_fname);
            } else {
                shaker.update(encoded_zero.slice());
            }
            if (options.context) |context| {
                const encoded_context_len = NistLengthEncoding.encode(.left, context.len);
                shaker.update(encoded_context_len.slice());
                shaker.update(context);
            } else {
                shaker.update(encoded_zero.slice());
            }
            shaker.st.fillBlock();
            return Self{ .shaker = shaker };
        }

        /// Hash a slice of bytes.
        /// `out` can be any length.
        pub fn hash(bytes: []const u8, out: []u8, options: Options) void {
            var st = Self.init(options);
            st.update(bytes);
            st.squeeze(out);
        }

        /// Absorb a slice of bytes into the state.
        pub fn update(self: *Self, bytes: []const u8) void {
            self.shaker.update(bytes);
        }

        /// Squeeze a slice of bytes from the state.
        /// `out` can be any length, and the function can be called multiple times.
        pub fn squeeze(self: *Self, out: []u8) void {
            self.shaker.squeeze(out);
        }

        /// Return the hash of the absorbed bytes.
        /// `out` can be of any length, but the function must not be called multiple times (use `squeeze` for that purpose instead).
        pub fn final(self: *Self, out: []u8) void {
            self.shaker.final(out);
        }

        /// Align the input to a block boundary.
        pub fn fillBlock(self: *Self) void {
            self.shaker.fillBlock();
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

/// The KMAC extendable output authentication function.
/// KMAC is a keyed version of the cSHAKE function, with an optional context.
/// It can be used as an SHA-3 based alternative to HMAC, as well as a generic keyed XoF (extendable output function).
pub fn KMac(comptime security_level: u11) type {
    return KMacLike(security_level, 0x04, 24);
}

fn KMacLike(comptime security_level: u11, comptime default_delim: u8, comptime rounds: u5) type {
    const CShaker = CShakeLike(security_level, default_delim, rounds, "KMAC");

    return struct {
        const Self = @This();

        /// The recommended output length, in bytes.
        pub const mac_length = CShaker.digest_length;
        /// The minimum output length, in bytes.
        pub const mac_length_min = 4;
        /// The recommended key length, in bytes.
        pub const key_length = security_level / 8;
        /// The minimum key length, in bytes.
        pub const key_length_min = 0;
        /// The block length, or rate, in bytes.
        pub const block_length = CShaker.block_length;

        cshaker: CShaker,
        xof_mode: bool = false,

        /// KMAC options can include a context string.
        pub const Options = struct {
            context: ?[]const u8 = null,
        };

        /// Initialize a state for the KMAC function, with an optional context and an arbitrary-long key.
        /// If the context and key are going to be reused, the structure can be initialized once, and cloned for each message.
        /// This is more efficient than reinitializing the state for each message at the cost of a small amount of memory.
        pub fn initWithOptions(key: []const u8, options: Options) Self {
            var cshaker = CShaker.init(.{ .context = options.context });
            const encoded_rate_len = NistLengthEncoding.encode(.left, block_length / 8);
            cshaker.update(encoded_rate_len.slice());
            const encoded_key_len = NistLengthEncoding.encode(.left, key.len);
            cshaker.update(encoded_key_len.slice());
            cshaker.update(key);
            cshaker.fillBlock();
            return Self{
                .cshaker = cshaker,
            };
        }

        /// Initialize a state for the KMAC function.
        /// If the context and key are going to be reused, the structure can be initialized once, and cloned for each message.
        /// This is more efficient than reinitializing the state for each message at the cost of a small amount of memory.
        pub fn init(key: []const u8) Self {
            return initWithOptions(key, .{});
        }

        /// Add data to the state.
        pub fn update(self: *Self, b: []const u8) void {
            self.cshaker.update(b);
        }

        /// Return an authentication tag for the current state.
        pub fn final(self: *Self, out: []u8) void {
            const encoded_out_len = NistLengthEncoding.encode(.right, out.len);
            self.update(encoded_out_len.slice());
            self.cshaker.final(out);
        }

        /// Squeeze a slice of bytes from the state.
        /// `out` can be any length, and the function can be called multiple times.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (!self.xof_mode) {
                const encoded_out_len = comptime NistLengthEncoding.encode(.right, 0);
                self.update(encoded_out_len.slice());
                self.xof_mode = true;
            }
            self.cshaker.squeeze(out);
        }

        /// Return an authentication tag for a message and a key, with an optional context.
        pub fn createWithOptions(out: []u8, msg: []const u8, key: []const u8, options: Options) void {
            var ctx = Self.initWithOptions(key, options);
            ctx.update(msg);
            ctx.final(out);
        }

        /// Return an authentication tag for a message and a key.
        pub fn create(out: []u8, msg: []const u8, key: []const u8) void {
            var ctx = Self.init(key);
            ctx.update(msg);
            ctx.final(out);
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

/// The TupleHash extendable output hash function, with domain-separated inputs.
/// TupleHash is a secure hash function with a variable output length, based on the cSHAKE function.
/// It is designed for unambiguously hashing tuples of data.
///
/// With most hash functions, calling `update("A")` followed by `update("B")`is identical to `update("AB")`.
/// With TupleHash, this is not the case: `update("A"); update("B")` is different from `update("AB")`.
///
/// Any number of inputs can be hashed, and the output depends on individual inputs and their order.
pub fn TupleHash(comptime security_level: u11) type {
    return TupleHashLike(security_level, 0x04, 24);
}

fn TupleHashLike(comptime security_level: u11, comptime default_delim: u8, comptime rounds: u5) type {
    const CShaker = CShakeLike(security_level, default_delim, rounds, "TupleHash");

    return struct {
        const Self = @This();

        /// The output length, in bytes.
        pub const digest_length = CShaker.digest_length;
        /// The block length, or rate, in bytes.
        pub const block_length = CShaker.block_length;

        cshaker: CShaker,
        xof_mode: bool = false,

        /// TupleHash options can include a context string.
        pub const Options = struct {
            context: ?[]const u8 = null,
        };

        /// Initialize a state for the TupleHash function, with an optional context.
        /// If the context is going to be reused, the structure can be initialized once, and cloned for each message.
        /// This is more efficient than reinitializing the state for each message at the cost of a small amount of memory.
        ///
        /// A key can be optionally added to the context to create a keyed TupleHash function, similar to KMAC.
        pub fn initWithOptions(options: Options) Self {
            const cshaker = CShaker.init(.{ .context = options.context });
            return Self{
                .cshaker = cshaker,
            };
        }

        /// Initialize a state for the MAC function.
        pub fn init() Self {
            return initWithOptions(.{});
        }

        /// Add data to the state, separated from previous updates.
        pub fn update(self: *Self, b: []const u8) void {
            const encoded_b_len = NistLengthEncoding.encode(.left, b.len);
            self.cshaker.update(encoded_b_len.slice());
            self.cshaker.update(b);
        }

        /// Return an authentication tag for the current state.
        pub fn final(self: *Self, out: []u8) void {
            const encoded_out_len = NistLengthEncoding.encode(.right, out.len);
            self.cshaker.update(encoded_out_len.slice());
            self.cshaker.final(out);
        }

        /// Align the input to a block boundary.
        pub fn fillBlock(self: *Self) void {
            self.cshaker.fillBlock();
        }

        /// Squeeze a slice of bytes from the state.
        /// `out` can be any length, and the function can be called multiple times.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (!self.xof_mode) {
                const encoded_out_len = comptime NistLengthEncoding.encode(.right, 0);
                self.update(encoded_out_len.slice());
                self.xof_mode = true;
            }
            self.cshaker.squeeze(out);
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

/// The NIST SP 800-185 encoded length format.
pub const NistLengthEncoding = enum {
    left,
    right,

    /// A length encoded according to NIST SP 800-185.
    pub const Length = struct {
        /// The size of the encoded value, in bytes.
        len: usize = 0,
        /// A buffer to store the encoded length.
        buf: [@sizeOf(usize) + 1]u8 = undefined,

        /// Return the encoded length as a slice.
        pub fn slice(self: *const Length) []const u8 {
            return self.buf[0..self.len];
        }
    };

    /// Encode a length according to NIST SP 800-185.
    pub fn encode(comptime encoding: NistLengthEncoding, len: usize) Length {
        const len_bits = @bitSizeOf(@TypeOf(len)) - @clz(len) + 3;
        const len_bytes = std.math.divCeil(usize, len_bits, 8) catch unreachable;

        var res = Length{ .len = len_bytes + 1 };
        if (encoding == .right) {
            res.buf[len_bytes] = @intCast(len_bytes);
        }
        const end = if (encoding == .right) len_bytes - 1 else len_bytes;
        res.buf[end] = @truncate(len << 3);
        var len_ = len >> 5;
        for (1..len_bytes) |i| {
            res.buf[end - i] = @truncate(len_);
            len_ >>= 8;
        }
        if (encoding == .left) {
            res.buf[0] = @intCast(len_bytes);
        }
        return res;
    }
};

const htest = @import("test.zig");

test "sha3-224 single" {
    try htest.assertEqualHash(Sha3_224, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "");
    try htest.assertEqualHash(Sha3_224, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", "abc");
    try htest.assertEqualHash(Sha3_224, "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha3-224 streaming" {
    var h = Sha3_224.init(.{});
    var out: [28]u8 = undefined;

    h.final(out[0..]);
    try htest.assertEqual("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", out[0..]);

    h = Sha3_224.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", out[0..]);

    h = Sha3_224.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", out[0..]);
}

test "sha3-256 single" {
    try htest.assertEqualHash(Sha3_256, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "");
    try htest.assertEqualHash(Sha3_256, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "abc");
    try htest.assertEqualHash(Sha3_256, "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha3-256 streaming" {
    var h = Sha3_256.init(.{});
    var out: [32]u8 = undefined;

    h.final(out[0..]);
    try htest.assertEqual("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", out[0..]);

    h = Sha3_256.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", out[0..]);

    h = Sha3_256.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", out[0..]);
}

test "sha3-256 aligned final" {
    var block = [_]u8{0} ** Sha3_256.block_length;
    var out: [Sha3_256.digest_length]u8 = undefined;

    var h = Sha3_256.init(.{});
    h.update(&block);
    h.final(out[0..]);
}

test "sha3-384 single" {
    const h1 = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    try htest.assertEqualHash(Sha3_384, h1, "");
    const h2 = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25";
    try htest.assertEqualHash(Sha3_384, h2, "abc");
    const h3 = "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7";
    try htest.assertEqualHash(Sha3_384, h3, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha3-384 streaming" {
    var h = Sha3_384.init(.{});
    var out: [48]u8 = undefined;

    const h1 = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25";
    h = Sha3_384.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Sha3_384.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);
}

test "sha3-512 single" {
    const h1 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    try htest.assertEqualHash(Sha3_512, h1, "");
    const h2 = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
    try htest.assertEqualHash(Sha3_512, h2, "abc");
    const h3 = "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185";
    try htest.assertEqualHash(Sha3_512, h3, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha3-512 streaming" {
    var h = Sha3_512.init(.{});
    var out: [64]u8 = undefined;

    const h1 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    h.final(out[0..]);
    try htest.assertEqual(h1, out[0..]);

    const h2 = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
    h = Sha3_512.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);

    h = Sha3_512.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual(h2, out[0..]);
}

test "sha3-512 aligned final" {
    var block = [_]u8{0} ** Sha3_512.block_length;
    var out: [Sha3_512.digest_length]u8 = undefined;

    var h = Sha3_512.init(.{});
    h.update(&block);
    h.final(out[0..]);
}

test "keccak-256 single" {
    try htest.assertEqualHash(Keccak256, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "");
    try htest.assertEqualHash(Keccak256, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "abc");
    try htest.assertEqualHash(Keccak256, "f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "keccak-512 single" {
    try htest.assertEqualHash(Keccak512, "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", "");
    try htest.assertEqualHash(Keccak512, "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96", "abc");
    try htest.assertEqualHash(Keccak512, "ac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f3f1db7a983dad13d53439ccac0b37e24037e7b95f80f59f37a2f683c4ba4682", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "SHAKE-128 single" {
    var out: [10]u8 = undefined;
    Shake128.hash("hello123", &out, .{});
    try htest.assertEqual("1b85861510bc4d8e467d", &out);
}

test "SHAKE-128 multisqueeze" {
    var out: [10]u8 = undefined;
    var h = Shake128.init(.{});
    h.update("hello123");
    h.squeeze(out[0..4]);
    h.squeeze(out[4..]);
    try htest.assertEqual("1b85861510bc4d8e467d", &out);
}

test "SHAKE-128 multisqueeze with multiple blocks" {
    var out: [100]u8 = undefined;
    var out2: [100]u8 = undefined;

    var h = Shake128.init(.{});
    h.update("hello123");
    h.squeeze(out[0..50]);
    h.squeeze(out[50..]);

    var h2 = Shake128.init(.{});
    h2.update("hello123");
    h2.squeeze(&out2);
    try std.testing.expectEqualSlices(u8, &out, &out2);
}

test "SHAKE-256 single" {
    var out: [10]u8 = undefined;
    Shake256.hash("hello123", &out, .{});
    try htest.assertEqual("ade612ba265f92de4a37", &out);
}

test "TurboSHAKE-128" {
    var out: [32]u8 = undefined;
    TurboShake(128, 0x06).hash("\xff", &out, .{});
    try htest.assertEqual("8ec9c66465ed0d4a6c35d13506718d687a25cb05c74cca1e42501abd83874a67", &out);
}

test "SHA-3 with streaming" {
    var msg: [613]u8 = [613]u8{ 0x97, 0xd1, 0x2d, 0x1a, 0x16, 0x2d, 0x36, 0x4d, 0x20, 0x62, 0x19, 0x0b, 0x14, 0x93, 0xbb, 0xf8, 0x5b, 0xea, 0x04, 0xc2, 0x61, 0x8e, 0xd6, 0x08, 0x81, 0xa1, 0x1d, 0x73, 0x27, 0x48, 0xbf, 0xa4, 0xba, 0xb1, 0x9a, 0x48, 0x```
