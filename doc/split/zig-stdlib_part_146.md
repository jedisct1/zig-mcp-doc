```
umber_literal});
    try testTokenize("0xF.Fp0", &.{.number_literal});
    try testTokenize("0xF.FP0", &.{.number_literal});
    try testTokenize("0x1p0", &.{.number_literal});
    try testTokenize("0xfp0", &.{.number_literal});
    try testTokenize("0x1.0+0xF.0", &.{ .number_literal, .plus, .number_literal });

    try testTokenize("0x1.", &.{ .number_literal, .period });
    try testTokenize("0xF.", &.{ .number_literal, .period });
    try testTokenize("0x1.+0xF.", &.{ .number_literal, .period, .plus, .number_literal, .period });
    try testTokenize("0xff.p10", &.{.number_literal});

    try testTokenize("0x0123456.789ABCDEF", &.{.number_literal});
    try testTokenize("0x0_123_456.789_ABC_DEF", &.{.number_literal});
    try testTokenize("0x0_1_2_3_4_5_6.7_8_9_A_B_C_D_E_F", &.{.number_literal});
    try testTokenize("0x0p0", &.{.number_literal});
    try testTokenize("0x0.0p0", &.{.number_literal});
    try testTokenize("0xff.ffp10", &.{.number_literal});
    try testTokenize("0xff.ffP10", &.{.number_literal});
    try testTokenize("0xffp10", &.{.number_literal});
    try testTokenize("0xff_ff.ff_ffp1_0_0_0", &.{.number_literal});
    try testTokenize("0xf_f_f_f.f_f_f_fp+1_000", &.{.number_literal});
    try testTokenize("0xf_f_f_f.f_f_f_fp-1_00_0", &.{.number_literal});

    try testTokenize("0x1e", &.{.number_literal});
    try testTokenize("0x1e0", &.{.number_literal});
    try testTokenize("0x1p", &.{.number_literal});
    try testTokenize("0xfp0z1", &.{.number_literal});
    try testTokenize("0xff.ffpff", &.{.number_literal});
    try testTokenize("0x0.p", &.{.number_literal});
    try testTokenize("0x0.z", &.{.number_literal});
    try testTokenize("0x0._", &.{.number_literal});
    try testTokenize("0x0_.0", &.{.number_literal});
    try testTokenize("0x0_.0.0", &.{ .number_literal, .period, .number_literal });
    try testTokenize("0x0._0", &.{.number_literal});
    try testTokenize("0x0.0_", &.{.number_literal});
    try testTokenize("0x0_p0", &.{.number_literal});
    try testTokenize("0x0_.p0", &.{.number_literal});
    try testTokenize("0x0._p0", &.{.number_literal});
    try testTokenize("0x0.0_p0", &.{.number_literal});
    try testTokenize("0x0._0p0", &.{.number_literal});
    try testTokenize("0x0.0p_0", &.{.number_literal});
    try testTokenize("0x0.0p+_0", &.{.number_literal});
    try testTokenize("0x0.0p-_0", &.{.number_literal});
    try testTokenize("0x0.0p0_", &.{.number_literal});
}

test "multi line string literal with only 1 backslash" {
    try testTokenize("x \\\n;", &.{ .identifier, .invalid, .semicolon });
}

test "invalid builtin identifiers" {
    try testTokenize("@()", &.{.invalid});
    try testTokenize("@0()", &.{.invalid});
}

test "invalid token with unfinished escape right before eof" {
    try testTokenize("\"\\", &.{.invalid});
    try testTokenize("'\\", &.{.invalid});
    try testTokenize("'\\u", &.{.invalid});
}

test "saturating operators" {
    try testTokenize("<<", &.{.angle_bracket_angle_bracket_left});
    try testTokenize("<<|", &.{.angle_bracket_angle_bracket_left_pipe});
    try testTokenize("<<|=", &.{.angle_bracket_angle_bracket_left_pipe_equal});

    try testTokenize("*", &.{.asterisk});
    try testTokenize("*|", &.{.asterisk_pipe});
    try testTokenize("*|=", &.{.asterisk_pipe_equal});

    try testTokenize("+", &.{.plus});
    try testTokenize("+|", &.{.plus_pipe});
    try testTokenize("+|=", &.{.plus_pipe_equal});

    try testTokenize("-", &.{.minus});
    try testTokenize("-|", &.{.minus_pipe});
    try testTokenize("-|=", &.{.minus_pipe_equal});
}

test "null byte before eof" {
    try testTokenize("123 \x00 456", &.{ .number_literal, .invalid });
    try testTokenize("//\x00", &.{.invalid});
    try testTokenize("\\\\\x00", &.{.invalid});
    try testTokenize("\x00", &.{.invalid});
    try testTokenize("// NUL\x00\n", &.{.invalid});
    try testTokenize("///\x00\n", &.{ .doc_comment, .invalid });
    try testTokenize("/// NUL\x00\n", &.{ .doc_comment, .invalid });
}

test "invalid tabs and carriage returns" {
    // "Inside Line Comments and Documentation Comments, Any TAB is rejected by
    // the grammar since it is ambiguous how it should be rendered."
    // https://github.com/ziglang/zig-spec/issues/38
    try testTokenize("//\t", &.{.invalid});
    try testTokenize("// \t", &.{.invalid});
    try testTokenize("///\t", &.{.invalid});
    try testTokenize("/// \t", &.{.invalid});
    try testTokenize("//!\t", &.{.invalid});
    try testTokenize("//! \t", &.{.invalid});

    // "Inside Line Comments and Documentation Comments, CR directly preceding
    // NL is unambiguously part of the newline sequence. It is accepted by the
    // grammar and removed by zig fmt, leaving only NL. CR anywhere else is
    // rejected by the grammar."
    // https://github.com/ziglang/zig-spec/issues/38
    try testTokenize("//\r", &.{.invalid});
    try testTokenize("// \r", &.{.invalid});
    try testTokenize("///\r", &.{.invalid});
    try testTokenize("/// \r", &.{.invalid});
    try testTokenize("//\r ", &.{.invalid});
    try testTokenize("// \r ", &.{.invalid});
    try testTokenize("///\r ", &.{.invalid});
    try testTokenize("/// \r ", &.{.invalid});
    try testTokenize("//\r\n", &.{});
    try testTokenize("// \r\n", &.{});
    try testTokenize("///\r\n", &.{.doc_comment});
    try testTokenize("/// \r\n", &.{.doc_comment});
    try testTokenize("//!\r", &.{.invalid});
    try testTokenize("//! \r", &.{.invalid});
    try testTokenize("//!\r ", &.{.invalid});
    try testTokenize("//! \r ", &.{.invalid});
    try testTokenize("//!\r\n", &.{.container_doc_comment});
    try testTokenize("//! \r\n", &.{.container_doc_comment});

    // The control characters TAB and CR are rejected by the grammar inside multi-line string literals,
    // except if CR is directly before NL.
    // https://github.com/ziglang/zig-spec/issues/38
    try testTokenize("\\\\\r", &.{.invalid});
    try testTokenize("\\\\\r ", &.{.invalid});
    try testTokenize("\\\\ \r", &.{.invalid});
    try testTokenize("\\\\\t", &.{.invalid});
    try testTokenize("\\\\\t ", &.{.invalid});
    try testTokenize("\\\\ \t", &.{.invalid});
    try testTokenize("\\\\\r\n", &.{.multiline_string_literal_line});

    // "TAB used as whitespace is...accepted by the grammar. CR used as
    // whitespace, whether directly preceding NL or stray, is...accepted by the
    // grammar."
    // https://github.com/ziglang/zig-spec/issues/38
    try testTokenize("\tpub\tswitch\t", &.{ .keyword_pub, .keyword_switch });
    try testTokenize("\rpub\rswitch\r", &.{ .keyword_pub, .keyword_switch });
}

test "fuzzable properties upheld" {
    return std.testing.fuzz({}, testPropertiesUpheld, .{});
}

fn testTokenize(source: [:0]const u8, expected_token_tags: []const Token.Tag) !void {
    var tokenizer = Tokenizer.init(source);
    for (expected_token_tags) |expected_token_tag| {
        const token = tokenizer.next();
        try std.testing.expectEqual(expected_token_tag, token.tag);
    }
    // Last token should always be eof, even when the last token was invalid,
    // in which case the tokenizer is in an invalid state, which can only be
    // recovered by opinionated means outside the scope of this implementation.
    const last_token = tokenizer.next();
    try std.testing.expectEqual(Token.Tag.eof, last_token.tag);
    try std.testing.expectEqual(source.len, last_token.loc.start);
    try std.testing.expectEqual(source.len, last_token.loc.end);
}

fn testPropertiesUpheld(context: void, source: []const u8) anyerror!void {
    _ = context;
    const source0 = try std.testing.allocator.dupeZ(u8, source);
    defer std.testing.allocator.free(source0);
    var tokenizer = Tokenizer.init(source0);
    var tokenization_failed = false;
    while (true) {
        const token = tokenizer.next();

        // Property: token end location after start location (or equal)
        try std.testing.expect(token.loc.end >= token.loc.start);

        switch (token.tag) {
            .invalid => {
                tokenization_failed = true;

                // Property: invalid token always ends at newline or eof
                try std.testing.expect(source0[token.loc.end] == '\n' or source0[token.loc.end] == 0);
            },
            .eof => {
                // Property: EOF token is always 0-length at end of source.
                try std.testing.expectEqual(source0.len, token.loc.start);
                try std.testing.expectEqual(source0.len, token.loc.end);
                break;
            },
            else => continue,
        }
    }

    if (source0.len > 0) for (source0, source0[1..][0..source0.len]) |cur, next| {
        // Property: No null byte allowed except at end.
        if (cur == 0) {
            try std.testing.expect(tokenization_failed);
        }
        // Property: No ASCII control characters other than \n and \t are allowed.
        if (std.ascii.isControl(cur) and cur != '\n' and cur != '\t') {
            try std.testing.expect(tokenization_failed);
        }
        // Property: All '\r' must be followed by '\n'.
        if (cur == '\r' and next != '\n') {
            try std.testing.expect(tokenization_failed);
        }
    };
}
windows10sdk: ?Installation,
windows81sdk: ?Installation,
msvc_lib_dir: ?[]const u8,

const WindowsSdk = @This();
const std = @import("std");
const builtin = @import("builtin");

const windows = std.os.windows;
const RRF = windows.advapi32.RRF;

const windows_kits_reg_key = "SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots";

// https://learn.microsoft.com/en-us/windows/win32/msi/productversion
const version_major_minor_max_length = "255.255".len;
// note(bratishkaerik): i think ProductVersion in registry (created by Visual Studio installer) also follows this rule
const product_version_max_length = version_major_minor_max_length + ".65535".len;

/// Find path and version of Windows 10 SDK and Windows 8.1 SDK, and find path to MSVC's `lib/` directory.
/// Caller owns the result's fields.
/// After finishing work, call `free(allocator)`.
pub fn find(allocator: std.mem.Allocator, arch: std.Target.Cpu.Arch) error{ OutOfMemory, NotFound, PathTooLong }!WindowsSdk {
    if (builtin.os.tag != .windows) return error.NotFound;

    //note(dimenus): If this key doesn't exist, neither the Win 8 SDK nor the Win 10 SDK is installed
    const roots_key = RegistryWtf8.openKey(windows.HKEY_LOCAL_MACHINE, windows_kits_reg_key, .{ .wow64_32 = true }) catch |err| switch (err) {
        error.KeyNotFound => return error.NotFound,
    };
    defer roots_key.closeKey();

    const windows10sdk = Installation.find(allocator, roots_key, "KitsRoot10", "", "v10.0") catch |err| switch (err) {
        error.InstallationNotFound => null,
        error.PathTooLong => null,
        error.VersionTooLong => null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer if (windows10sdk) |*w| w.free(allocator);

    const windows81sdk = Installation.find(allocator, roots_key, "KitsRoot81", "winver", "v8.1") catch |err| switch (err) {
        error.InstallationNotFound => null,
        error.PathTooLong => null,
        error.VersionTooLong => null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer if (windows81sdk) |*w| w.free(allocator);

    const msvc_lib_dir: ?[]const u8 = MsvcLibDir.find(allocator, arch) catch |err| switch (err) {
        error.MsvcLibDirNotFound => null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer allocator.free(msvc_lib_dir);

    return .{
        .windows10sdk = windows10sdk,
        .windows81sdk = windows81sdk,
        .msvc_lib_dir = msvc_lib_dir,
    };
}

pub fn free(sdk: WindowsSdk, allocator: std.mem.Allocator) void {
    if (sdk.windows10sdk) |*w10sdk| {
        w10sdk.free(allocator);
    }
    if (sdk.windows81sdk) |*w81sdk| {
        w81sdk.free(allocator);
    }
    if (sdk.msvc_lib_dir) |msvc_lib_dir| {
        allocator.free(msvc_lib_dir);
    }
}

/// Iterates via `iterator` and collects all folders with names starting with `strip_prefix`
/// and a version. Returns slice of version strings sorted in descending order.
/// Caller owns result.
fn iterateAndFilterByVersion(
    iterator: *std.fs.Dir.Iterator,
    allocator: std.mem.Allocator,
    prefix: []const u8,
) error{OutOfMemory}![][]const u8 {
    const Version = struct {
        nums: [4]u32,
        build: []const u8,

        fn parseNum(num: []const u8) ?u32 {
            if (num[0] == '0' and num.len > 1) return null;
            return std.fmt.parseInt(u32, num, 10) catch null;
        }

        fn order(lhs: @This(), rhs: @This()) std.math.Order {
            return std.mem.order(u32, &lhs.nums, &rhs.nums).differ() orelse
                std.mem.order(u8, lhs.build, rhs.build);
        }
    };
    var versions = std.ArrayList(Version).init(allocator);
    var dirs = std.ArrayList([]const u8).init(allocator);
    defer {
        versions.deinit();
        for (dirs.items) |filtered_dir| allocator.free(filtered_dir);
        dirs.deinit();
    }

    iterate: while (iterator.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.startsWith(u8, entry.name, prefix)) continue;

        var version: Version = .{
            .nums = .{0} ** 4,
            .build = "",
        };
        const suffix = entry.name[prefix.len..];
        const underscore = std.mem.indexOfScalar(u8, entry.name, '_');
        var num_it = std.mem.splitScalar(u8, suffix[0 .. underscore orelse suffix.len], '.');
        version.nums[0] = Version.parseNum(num_it.first()) orelse continue;
        for (version.nums[1..]) |*num|
            num.* = Version.parseNum(num_it.next() orelse break) orelse continue :iterate
        else if (num_it.next()) |_| continue;

        const name = try allocator.dupe(u8, suffix);
        errdefer allocator.free(name);
        if (underscore) |pos| version.build = name[pos + 1 ..];

        try versions.append(version);
        try dirs.append(name);
    }

    std.mem.sortUnstableContext(0, dirs.items.len, struct {
        versions: []Version,
        dirs: [][]const u8,
        pub fn lessThan(context: @This(), lhs: usize, rhs: usize) bool {
            return context.versions[lhs].order(context.versions[rhs]).compare(.gt);
        }
        pub fn swap(context: @This(), lhs: usize, rhs: usize) void {
            std.mem.swap(Version, &context.versions[lhs], &context.versions[rhs]);
            std.mem.swap([]const u8, &context.dirs[lhs], &context.dirs[rhs]);
        }
    }{ .versions = versions.items, .dirs = dirs.items });
    return dirs.toOwnedSlice();
}

const OpenOptions = struct {
    /// Sets the KEY_WOW64_32KEY access flag.
    /// https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view
    wow64_32: bool = false,
};

const RegistryWtf8 = struct {
    key: windows.HKEY,

    /// Assert that `key` is valid WTF-8 string
    pub fn openKey(hkey: windows.HKEY, key: []const u8, options: OpenOptions) error{KeyNotFound}!RegistryWtf8 {
        const key_wtf16le: [:0]const u16 = key_wtf16le: {
            var key_wtf16le_buf: [RegistryWtf16Le.key_name_max_len]u16 = undefined;
            const key_wtf16le_len: usize = std.unicode.wtf8ToWtf16Le(key_wtf16le_buf[0..], key) catch |err| switch (err) {
                error.InvalidWtf8 => unreachable,
            };
            key_wtf16le_buf[key_wtf16le_len] = 0;
            break :key_wtf16le key_wtf16le_buf[0..key_wtf16le_len :0];
        };

        const registry_wtf16le = try RegistryWtf16Le.openKey(hkey, key_wtf16le, options);
        return .{ .key = registry_wtf16le.key };
    }

    /// Closes key, after that usage is invalid
    pub fn closeKey(reg: RegistryWtf8) void {
        const return_code_int: windows.HRESULT = windows.advapi32.RegCloseKey(reg.key);
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            else => {},
        }
    }

    /// Get string from registry.
    /// Caller owns result.
    pub fn getString(reg: RegistryWtf8, allocator: std.mem.Allocator, subkey: []const u8, value_name: []const u8) error{ OutOfMemory, ValueNameNotFound, NotAString, StringNotFound }![]u8 {
        const subkey_wtf16le: [:0]const u16 = subkey_wtf16le: {
            var subkey_wtf16le_buf: [RegistryWtf16Le.key_name_max_len]u16 = undefined;
            const subkey_wtf16le_len: usize = std.unicode.wtf8ToWtf16Le(subkey_wtf16le_buf[0..], subkey) catch unreachable;
            subkey_wtf16le_buf[subkey_wtf16le_len] = 0;
            break :subkey_wtf16le subkey_wtf16le_buf[0..subkey_wtf16le_len :0];
        };

        const value_name_wtf16le: [:0]const u16 = value_name_wtf16le: {
            var value_name_wtf16le_buf: [RegistryWtf16Le.value_name_max_len]u16 = undefined;
            const value_name_wtf16le_len: usize = std.unicode.wtf8ToWtf16Le(value_name_wtf16le_buf[0..], value_name) catch unreachable;
            value_name_wtf16le_buf[value_name_wtf16le_len] = 0;
            break :value_name_wtf16le value_name_wtf16le_buf[0..value_name_wtf16le_len :0];
        };

        const registry_wtf16le: RegistryWtf16Le = .{ .key = reg.key };
        const value_wtf16le = try registry_wtf16le.getString(allocator, subkey_wtf16le, value_name_wtf16le);
        defer allocator.free(value_wtf16le);

        const value_wtf8: []u8 = try std.unicode.wtf16LeToWtf8Alloc(allocator, value_wtf16le);
        errdefer allocator.free(value_wtf8);

        return value_wtf8;
    }

    /// Get DWORD (u32) from registry.
    pub fn getDword(reg: RegistryWtf8, subkey: []const u8, value_name: []const u8) error{ ValueNameNotFound, NotADword, DwordTooLong, DwordNotFound }!u32 {
        const subkey_wtf16le: [:0]const u16 = subkey_wtf16le: {
            var subkey_wtf16le_buf: [RegistryWtf16Le.key_name_max_len]u16 = undefined;
            const subkey_wtf16le_len: usize = std.unicode.wtf8ToWtf16Le(subkey_wtf16le_buf[0..], subkey) catch unreachable;
            subkey_wtf16le_buf[subkey_wtf16le_len] = 0;
            break :subkey_wtf16le subkey_wtf16le_buf[0..subkey_wtf16le_len :0];
        };

        const value_name_wtf16le: [:0]const u16 = value_name_wtf16le: {
            var value_name_wtf16le_buf: [RegistryWtf16Le.value_name_max_len]u16 = undefined;
            const value_name_wtf16le_len: usize = std.unicode.wtf8ToWtf16Le(value_name_wtf16le_buf[0..], value_name) catch unreachable;
            value_name_wtf16le_buf[value_name_wtf16le_len] = 0;
            break :value_name_wtf16le value_name_wtf16le_buf[0..value_name_wtf16le_len :0];
        };

        const registry_wtf16le: RegistryWtf16Le = .{ .key = reg.key };
        return registry_wtf16le.getDword(subkey_wtf16le, value_name_wtf16le);
    }

    /// Under private space with flags:
    /// KEY_QUERY_VALUE and KEY_ENUMERATE_SUB_KEYS.
    /// After finishing work, call `closeKey`.
    pub fn loadFromPath(absolute_path: []const u8) error{KeyNotFound}!RegistryWtf8 {
        const absolute_path_wtf16le: [:0]const u16 = absolute_path_wtf16le: {
            var absolute_path_wtf16le_buf: [RegistryWtf16Le.value_name_max_len]u16 = undefined;
            const absolute_path_wtf16le_len: usize = std.unicode.wtf8ToWtf16Le(absolute_path_wtf16le_buf[0..], absolute_path) catch unreachable;
            absolute_path_wtf16le_buf[absolute_path_wtf16le_len] = 0;
            break :absolute_path_wtf16le absolute_path_wtf16le_buf[0..absolute_path_wtf16le_len :0];
        };

        const registry_wtf16le = try RegistryWtf16Le.loadFromPath(absolute_path_wtf16le);
        return .{ .key = registry_wtf16le.key };
    }
};

const RegistryWtf16Le = struct {
    key: windows.HKEY,

    /// Includes root key (f.e. HKEY_LOCAL_MACHINE).
    /// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
    pub const key_name_max_len = 255;
    /// In Unicode characters.
    /// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
    pub const value_name_max_len = 16_383;

    /// Under HKEY_LOCAL_MACHINE with flags:
    /// KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, optionally KEY_WOW64_32KEY.
    /// After finishing work, call `closeKey`.
    fn openKey(hkey: windows.HKEY, key_wtf16le: [:0]const u16, options: OpenOptions) error{KeyNotFound}!RegistryWtf16Le {
        var key: windows.HKEY = undefined;
        var access: windows.REGSAM = windows.KEY_QUERY_VALUE | windows.KEY_ENUMERATE_SUB_KEYS;
        if (options.wow64_32) access |= windows.KEY_WOW64_32KEY;
        const return_code_int: windows.HRESULT = windows.advapi32.RegOpenKeyExW(
            hkey,
            key_wtf16le,
            0,
            access,
            &key,
        );
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            .FILE_NOT_FOUND => return error.KeyNotFound,

            else => return error.KeyNotFound,
        }
        return .{ .key = key };
    }

    /// Closes key, after that usage is invalid
    fn closeKey(reg: RegistryWtf16Le) void {
        const return_code_int: windows.HRESULT = windows.advapi32.RegCloseKey(reg.key);
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            else => {},
        }
    }

    /// Get string ([:0]const u16) from registry.
    fn getString(reg: RegistryWtf16Le, allocator: std.mem.Allocator, subkey_wtf16le: [:0]const u16, value_name_wtf16le: [:0]const u16) error{ OutOfMemory, ValueNameNotFound, NotAString, StringNotFound }![]const u16 {
        var actual_type: windows.ULONG = undefined;

        // Calculating length to allocate
        var value_wtf16le_buf_size: u32 = 0; // in bytes, including any terminating NUL character or characters.
        var return_code_int: windows.HRESULT = windows.advapi32.RegGetValueW(
            reg.key,
            subkey_wtf16le,
            value_name_wtf16le,
            RRF.RT_REG_SZ,
            &actual_type,
            null,
            &value_wtf16le_buf_size,
        );

        // Check returned code and type
        var return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => std.debug.assert(value_wtf16le_buf_size != 0),
            .MORE_DATA => unreachable, // We are only reading length
            .FILE_NOT_FOUND => return error.ValueNameNotFound,
            .INVALID_PARAMETER => unreachable, // We didn't combine RRF.SUBKEY_WOW6464KEY and RRF.SUBKEY_WOW6432KEY
            else => return error.StringNotFound,
        }
        switch (actual_type) {
            windows.REG.SZ => {},
            else => return error.NotAString,
        }

        const value_wtf16le_buf: []u16 = try allocator.alloc(u16, std.math.divCeil(u32, value_wtf16le_buf_size, 2) catch unreachable);
        errdefer allocator.free(value_wtf16le_buf);

        return_code_int = windows.advapi32.RegGetValueW(
            reg.key,
            subkey_wtf16le,
            value_name_wtf16le,
            RRF.RT_REG_SZ,
            &actual_type,
            value_wtf16le_buf.ptr,
            &value_wtf16le_buf_size,
        );

        // Check returned code and (just in case) type again.
        return_code = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            .MORE_DATA => unreachable, // Calculated first time length should be enough, even overestimated
            .FILE_NOT_FOUND => return error.ValueNameNotFound,
            .INVALID_PARAMETER => unreachable, // We didn't combine RRF.SUBKEY_WOW6464KEY and RRF.SUBKEY_WOW6432KEY
            else => return error.StringNotFound,
        }
        switch (actual_type) {
            windows.REG.SZ => {},
            else => return error.NotAString,
        }

        const value_wtf16le: []const u16 = value_wtf16le: {
            // note(bratishkaerik): somehow returned value in `buf_len` is overestimated by Windows and contains extra space
            // we will just search for zero termination and forget length
            // Windows sure is strange
            const value_wtf16le_overestimated: [*:0]const u16 = @ptrCast(value_wtf16le_buf.ptr);
            break :value_wtf16le std.mem.span(value_wtf16le_overestimated);
        };

        _ = allocator.resize(value_wtf16le_buf, value_wtf16le.len);
        return value_wtf16le;
    }

    /// Get DWORD (u32) from registry.
    fn getDword(reg: RegistryWtf16Le, subkey_wtf16le: [:0]const u16, value_name_wtf16le: [:0]const u16) error{ ValueNameNotFound, NotADword, DwordTooLong, DwordNotFound }!u32 {
        var actual_type: windows.ULONG = undefined;
        var reg_size: u32 = @sizeOf(u32);
        var reg_value: u32 = 0;

        const return_code_int: windows.HRESULT = windows.advapi32.RegGetValueW(
            reg.key,
            subkey_wtf16le,
            value_name_wtf16le,
            RRF.RT_REG_DWORD,
            &actual_type,
            &reg_value,
            &reg_size,
        );
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            .MORE_DATA => return error.DwordTooLong,
            .FILE_NOT_FOUND => return error.ValueNameNotFound,
            .INVALID_PARAMETER => unreachable, // We didn't combine RRF.SUBKEY_WOW6464KEY and RRF.SUBKEY_WOW6432KEY
            else => return error.DwordNotFound,
        }

        switch (actual_type) {
            windows.REG.DWORD => {},
            else => return error.NotADword,
        }

        return reg_value;
    }

    /// Under private space with flags:
    /// KEY_QUERY_VALUE and KEY_ENUMERATE_SUB_KEYS.
    /// After finishing work, call `closeKey`.
    fn loadFromPath(absolute_path_as_wtf16le: [:0]const u16) error{KeyNotFound}!RegistryWtf16Le {
        var key: windows.HKEY = undefined;

        const return_code_int: windows.HRESULT = std.os.windows.advapi32.RegLoadAppKeyW(
            absolute_path_as_wtf16le,
            &key,
            windows.KEY_QUERY_VALUE | windows.KEY_ENUMERATE_SUB_KEYS,
            0,
            0,
        );
        const return_code: windows.Win32Error = @enumFromInt(return_code_int);
        switch (return_code) {
            .SUCCESS => {},
            else => return error.KeyNotFound,
        }

        return .{ .key = key };
    }
};

pub const Installation = struct {
    path: []const u8,
    version: []const u8,

    /// Find path and version of Windows SDK.
    /// Caller owns the result's fields.
    /// After finishing work, call `free(allocator)`.
    fn find(
        allocator: std.mem.Allocator,
        roots_key: RegistryWtf8,
        roots_subkey: []const u8,
        prefix: []const u8,
        version_key_name: []const u8,
    ) error{ OutOfMemory, InstallationNotFound, PathTooLong, VersionTooLong }!Installation {
        roots: {
            const installation = findFromRoot(allocator, roots_key, roots_subkey, prefix) catch
                break :roots;
            if (installation.isValidVersion()) return installation;
            installation.free(allocator);
        }
        {
            const installation = try findFromInstallationFolder(allocator, version_key_name);
            if (installation.isValidVersion()) return installation;
            installation.free(allocator);
        }
        return error.InstallationNotFound;
    }

    fn findFromRoot(
        allocator: std.mem.Allocator,
        roots_key: RegistryWtf8,
        roots_subkey: []const u8,
        prefix: []const u8,
    ) error{ OutOfMemory, InstallationNotFound, PathTooLong, VersionTooLong }!Installation {
        const path = path: {
            const path_maybe_with_trailing_slash = roots_key.getString(allocator, "", roots_subkey) catch |err| switch (err) {
                error.NotAString => return error.InstallationNotFound,
                error.ValueNameNotFound => return error.InstallationNotFound,
                error.StringNotFound => return error.InstallationNotFound,

                error.OutOfMemory => return error.OutOfMemory,
            };
            if (path_maybe_with_trailing_slash.len > std.fs.max_path_bytes or !std.fs.path.isAbsolute(path_maybe_with_trailing_slash)) {
                allocator.free(path_maybe_with_trailing_slash);
                return error.PathTooLong;
            }

            var path = std.ArrayList(u8).fromOwnedSlice(allocator, path_maybe_with_trailing_slash);
            errdefer path.deinit();

            // String might contain trailing slash, so trim it here
            if (path.items.len > "C:\\".len and path.getLast() == '\\') _ = path.pop();
            break :path try path.toOwnedSlice();
        };
        errdefer allocator.free(path);

        const version = version: {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const sdk_lib_dir_path = std.fmt.bufPrint(buf[0..], "{s}\\Lib\\", .{path}) catch |err| switch (err) {
                error.NoSpaceLeft => return error.PathTooLong,
            };
            if (!std.fs.path.isAbsolute(sdk_lib_dir_path)) return error.InstallationNotFound;

            // enumerate files in sdk path looking for latest version
            var sdk_lib_dir = std.fs.openDirAbsolute(sdk_lib_dir_path, .{
                .iterate = true,
            }) catch |err| switch (err) {
                error.NameTooLong => return error.PathTooLong,
                else => return error.InstallationNotFound,
            };
            defer sdk_lib_dir.close();

            var iterator = sdk_lib_dir.iterate();
            const versions = try iterateAndFilterByVersion(&iterator, allocator, prefix);
            if (versions.len == 0) return error.InstallationNotFound;
            defer {
                for (versions[1..]) |version| allocator.free(version);
                allocator.free(versions);
            }
            break :version versions[0];
        };
        errdefer allocator.free(version);

        return .{ .path = path, .version = version };
    }

    fn findFromInstallationFolder(
        allocator: std.mem.Allocator,
        version_key_name: []const u8,
    ) error{ OutOfMemory, InstallationNotFound, PathTooLong, VersionTooLong }!Installation {
        var key_name_buf: [RegistryWtf16Le.key_name_max_len]u8 = undefined;
        const key_name = std.fmt.bufPrint(
            &key_name_buf,
            "SOFTWARE\\Microsoft\\Microsoft SDKs\\Windows\\{s}",
            .{version_key_name},
        ) catch unreachable;
        const key = key: for ([_]bool{ true, false }) |wow6432node| {
            for ([_]windows.HKEY{ windows.HKEY_LOCAL_MACHINE, windows.HKEY_CURRENT_USER }) |hkey| {
                break :key RegistryWtf8.openKey(hkey, key_name, .{ .wow64_32 = wow6432node }) catch |err| switch (err) {
                    error.KeyNotFound => return error.InstallationNotFound,
                };
            }
        } else return error.InstallationNotFound;
        defer key.closeKey();

        const path: []const u8 = path: {
            const path_maybe_with_trailing_slash = key.getString(allocator, "", "InstallationFolder") catch |err| switch (err) {
                error.NotAString => return error.InstallationNotFound,
                error.ValueNameNotFound => return error.InstallationNotFound,
                error.StringNotFound => return error.InstallationNotFound,

                error.OutOfMemory => return error.OutOfMemory,
            };

            if (path_maybe_with_trailing_slash.len > std.fs.max_path_bytes or !std.fs.path.isAbsolute(path_maybe_with_trailing_slash)) {
                allocator.free(path_maybe_with_trailing_slash);
                return error.PathTooLong;
            }

            var path = std.ArrayList(u8).fromOwnedSlice(allocator, path_maybe_with_trailing_slash);
            errdefer path.deinit();

            // String might contain trailing slash, so trim it here
            if (path.items.len > "C:\\".len and path.getLast() == '\\') _ = path.pop();

            const path_without_trailing_slash = try path.toOwnedSlice();
            break :path path_without_trailing_slash;
        };
        errdefer allocator.free(path);

        const version: []const u8 = version: {

            // note(dimenus): Microsoft doesn't include the .0 in the ProductVersion key....
            const version_without_0 = key.getString(allocator, "", "ProductVersion") catch |err| switch (err) {
                error.NotAString => return error.InstallationNotFound,
                error.ValueNameNotFound => return error.InstallationNotFound,
                error.StringNotFound => return error.InstallationNotFound,

                error.OutOfMemory => return error.OutOfMemory,
            };
            if (version_without_0.len + ".0".len > product_version_max_length) {
                allocator.free(version_without_0);
                return error.VersionTooLong;
            }

            var version = std.ArrayList(u8).fromOwnedSlice(allocator, version_without_0);
            errdefer version.deinit();

            try version.appendSlice(".0");

            const version_with_0 = try version.toOwnedSlice();
            break :version version_with_0;
        };
        errdefer allocator.free(version);

        return .{ .path = path, .version = version };
    }

    /// Check whether this version is enumerated in registry.
    fn isValidVersion(installation: Installation) bool {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const reg_query_as_wtf8 = std.fmt.bufPrint(buf[0..], "{s}\\{s}\\Installed Options", .{
            windows_kits_reg_key,
            installation.version,
        }) catch |err| switch (err) {
            error.NoSpaceLeft => return false,
        };

        const options_key = RegistryWtf8.openKey(
            windows.HKEY_LOCAL_MACHINE,
            reg_query_as_wtf8,
            .{ .wow64_32 = true },
        ) catch |err| switch (err) {
            error.KeyNotFound => return false,
        };
        defer options_key.closeKey();

        const option_name = comptime switch (builtin.target.cpu.arch) {
            .thumb => "OptionId.DesktopCPParm",
            .aarch64 => "OptionId.DesktopCPParm64",
            .x86 => "OptionId.DesktopCPPx86",
            .x86_64 => "OptionId.DesktopCPPx64",
            else => |tag| @compileError("Windows SDK cannot be detected on architecture " ++ tag),
        };

        const reg_value = options_key.getDword("", option_name) catch return false;
        return (reg_value == 1);
    }

    fn free(install: Installation, allocator: std.mem.Allocator) void {
        allocator.free(install.path);
        allocator.free(install.version);
    }
};

const MsvcLibDir = struct {
    fn findInstancesDirViaSetup(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }!std.fs.Dir {
        const vs_setup_key_path = "SOFTWARE\\Microsoft\\VisualStudio\\Setup";
        const vs_setup_key = RegistryWtf8.openKey(windows.HKEY_LOCAL_MACHINE, vs_setup_key_path, .{}) catch |err| switch (err) {
            error.KeyNotFound => return error.PathNotFound,
        };
        defer vs_setup_key.closeKey();

        const packages_path = vs_setup_key.getString(allocator, "", "CachePath") catch |err| switch (err) {
            error.NotAString,
            error.ValueNameNotFound,
            error.StringNotFound,
            => return error.PathNotFound,

            error.OutOfMemory => return error.OutOfMemory,
        };
        defer allocator.free(packages_path);

        if (!std.fs.path.isAbsolute(packages_path)) return error.PathNotFound;

        const instances_path = try std.fs.path.join(allocator, &.{ packages_path, "_Instances" });
        defer allocator.free(instances_path);

        return std.fs.openDirAbsolute(instances_path, .{ .iterate = true }) catch return error.PathNotFound;
    }

    fn findInstancesDirViaCLSID(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }!std.fs.Dir {
        const setup_configuration_clsid = "{177f0c4a-1cd3-4de7-a32c-71dbbb9fa36d}";
        const setup_config_key = RegistryWtf8.openKey(windows.HKEY_CLASSES_ROOT, "CLSID\\" ++ setup_configuration_clsid, .{}) catch |err| switch (err) {
            error.KeyNotFound => return error.PathNotFound,
        };
        defer setup_config_key.closeKey();

        const dll_path = setup_config_key.getString(allocator, "InprocServer32", "") catch |err| switch (err) {
            error.NotAString,
            error.ValueNameNotFound,
            error.StringNotFound,
            => return error.PathNotFound,

            error.OutOfMemory => return error.OutOfMemory,
        };
        defer allocator.free(dll_path);

        if (!std.fs.path.isAbsolute(dll_path)) return error.PathNotFound;

        var path_it = std.fs.path.componentIterator(dll_path) catch return error.PathNotFound;
        // the .dll filename
        _ = path_it.last();
        const root_path = while (path_it.previous()) |dir_component| {
            if (std.ascii.eqlIgnoreCase(dir_component.name, "VisualStudio")) {
                break dir_component.path;
            }
        } else {
            return error.PathNotFound;
        };

        const instances_path = try std.fs.path.join(allocator, &.{ root_path, "Packages", "_Instances" });
        defer allocator.free(instances_path);

        return std.fs.openDirAbsolute(instances_path, .{ .iterate = true }) catch return error.PathNotFound;
    }

    fn findInstancesDir(allocator: std.mem.Allocator) error{ OutOfMemory, PathNotFound }!std.fs.Dir {
        // First, try getting the packages cache path from the registry.
        // This only seems to exist when the path is different from the default.
        method1: {
            return findInstancesDirViaSetup(allocator) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.PathNotFound => break :method1,
            };
        }
        // Otherwise, try to get the path from the .dll that would have been
        // loaded via COM for SetupConfiguration.
        method2: {
            return findInstancesDirViaCLSID(allocator) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.PathNotFound => break :method2,
            };
        }
        // If that can't be found, fall back to manually appending
        // `Microsoft\VisualStudio\Packages\_Instances` to %PROGRAMDATA%
        method3: {
            const program_data = std.process.getEnvVarOwned(allocator, "PROGRAMDATA") catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.InvalidWtf8 => unreachable,
                error.EnvironmentVariableNotFound => break :method3,
            };
            defer allocator.free(program_data);

            if (!std.fs.path.isAbsolute(program_data)) break :method3;

            const instances_path = try std.fs.path.join(allocator, &.{ program_data, "Microsoft", "VisualStudio", "Packages", "_Instances" });
            defer allocator.free(instances_path);

            return std.fs.openDirAbsolute(instances_path, .{ .iterate = true }) catch break :method3;
        }
        return error.PathNotFound;
    }

    /// Intended to be equivalent to `ISetupHelper.ParseVersion`
    /// Example: 17.4.33205.214 -> 0x0011000481b500d6
    fn parseVersionQuad(version: []const u8) error{InvalidVersion}!u64 {
        var it = std.mem.splitScalar(u8, version, '.');
        const a = it.first();
        const b = it.next() orelse return error.InvalidVersion;
        const c = it.next() orelse return error.InvalidVersion;
        const d = it.next() orelse return error.InvalidVersion;
        if (it.next()) |_| return error.InvalidVersion;
        var result: u64 = undefined;
        var result_bytes = std.mem.asBytes(&result);

        std.mem.writeInt(
            u16,
            result_bytes[0..2],
            std.fmt.parseUnsigned(u16, d, 10) catch return error.InvalidVersion,
            .little,
        );
        std.mem.writeInt(
            u16,
            result_bytes[2..4],
            std.fmt.parseUnsigned(u16, c, 10) catch return error.InvalidVersion,
            .little,
        );
        std.mem.writeInt(
            u16,
            result_bytes[4..6],
            std.fmt.parseUnsigned(u16, b, 10) catch return error.InvalidVersion,
            .little,
        );
        std.mem.writeInt(
            u16,
            result_bytes[6..8],
            std.fmt.parseUnsigned(u16, a, 10) catch return error.InvalidVersion,
            .little,
        );

        return result;
    }

    /// Intended to be equivalent to ISetupConfiguration.EnumInstances:
    /// https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.setup.configuration
    /// but without the use of COM in order to avoid a dependency on ole32.dll
    ///
    /// The logic in this function is intended to match what ISetupConfiguration does
    /// under-the-hood, as verified using Procmon.
    fn findViaCOM(allocator: std.mem.Allocator, arch: std.Target.Cpu.Arch) error{ OutOfMemory, PathNotFound }![]const u8 {
        // Typically `%PROGRAMDATA%\Microsoft\VisualStudio\Packages\_Instances`
        // This will contain directories with names of instance IDs like 80a758ca,
        // which will contain `state.json` files that have the version and
        // installation directory.
        var instances_dir = try findInstancesDir(allocator);
        defer instances_dir.close();

        var state_subpath_buf: [std.fs.max_name_bytes + 32]u8 = undefined;
        var latest_version_lib_dir: std.ArrayListUnmanaged(u8) = .empty;
        errdefer latest_version_lib_dir.deinit(allocator);

        var latest_version: u64 = 0;
        var instances_dir_it = instances_dir.iterateAssumeFirstIteration();
        while (instances_dir_it.next() catch return error.PathNotFound) |entry| {
            if (entry.kind != .directory) continue;

            var fbs = std.io.fixedBufferStream(&state_subpath_buf);
            const writer = fbs.writer();

            writer.writeAll(entry.name) catch unreachable;
            writer.writeByte(std.fs.path.sep) catch unreachable;
            writer.writeAll("state.json") catch unreachable;

            const json_contents = instances_dir.readFileAlloc(allocator, fbs.getWritten(), std.math.maxInt(usize)) catch continue;
            defer allocator.free(json_contents);

            var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_contents, .{}) catch continue;
            defer parsed.deinit();

            if (parsed.value != .object) continue;
            const catalog_info = parsed.value.object.get("catalogInfo") orelse continue;
            if (catalog_info != .object) continue;
            const product_version_value = catalog_info.object.get("buildVersion") orelse continue;
            if (product_version_value != .string) continue;
            const product_version_text = product_version_value.string;
            const parsed_version = parseVersionQuad(product_version_text) catch continue;

            // We want to end up with the most recent version installed
            if (parsed_version <= latest_version) continue;

            const installation_path = parsed.value.object.get("installationPath") orelse continue;
            if (installation_path != .string) continue;

            const lib_dir_path = libDirFromInstallationPath(allocator, installation_path.string, arch) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.PathNotFound => continue,
            };
            defer allocator.free(lib_dir_path);

            latest_version_lib_dir.clearRetainingCapacity();
            try latest_version_lib_dir.appendSlice(allocator, lib_dir_path);
            latest_version = parsed_version;
        }

        if (latest_version_lib_dir.items.len == 0) return error.PathNotFound;
        return latest_version_lib_dir.toOwnedSlice(allocator);
    }

    fn libDirFromInstallationPath(allocator: std.mem.Allocator, installation_path: []const u8, arch: std.Target.Cpu.Arch) error{ OutOfMemory, PathNotFound }![]const u8 {
        var lib_dir_buf = try std.ArrayList(u8).initCapacity(allocator, installation_path.len + 64);
        errdefer lib_dir_buf.deinit();

        lib_dir_buf.appendSliceAssumeCapacity(installation_path);

        if (!std.fs.path.isSep(lib_dir_buf.getLast())) {
            try lib_dir_buf.append('\\');
        }
        const installation_path_with_trailing_sep_len = lib_dir_buf.items.len;

        try lib_dir_buf.appendSlice("VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt");
        var default_tools_version_buf: [512]u8 = undefined;
        const default_tools_version_contents = std.fs.cwd().readFile(lib_dir_buf.items, &default_tools_version_buf) catch {
            return error.PathNotFound;
        };
        var tokenizer = std.mem.tokenizeAny(u8, default_tools_version_contents, " \r\n");
        const default_tools_version = tokenizer.next() orelse return error.PathNotFound;

        lib_dir_buf.shrinkRetainingCapacity(installation_path_with_trailing_sep_len);
        try lib_dir_buf.appendSlice("VC\\Tools\\MSVC\\");
        try lib_dir_buf.appendSlice(default_tools_version);
        try lib_dir_buf.appendSlice("\\Lib\\");
        try lib_dir_buf.appendSlice(switch (arch) {
            .thumb => "arm",
            .aarch64 => "arm64",
            .x86 => "x86",
            .x86_64 => "x64",
            else => unreachable,
        });

        if (!verifyLibDir(lib_dir_buf.items)) {
            return error.PathNotFound;
        }

        return lib_dir_buf.toOwnedSlice();
    }

    // https://learn.microsoft.com/en-us/visualstudio/install/tools-for-managing-visual-studio-instances?view=vs-2022#editing-the-registry-for-a-visual-studio-instance
    fn findViaRegistry(allocator: std.mem.Allocator, arch: std.Target.Cpu.Arch) error{ OutOfMemory, PathNotFound }![]const u8 {

        // %localappdata%\Microsoft\VisualStudio\
        // %appdata%\Local\Microsoft\VisualStudio\
        const visualstudio_folder_path = std.fs.getAppDataDir(allocator, "Microsoft\\VisualStudio\\") catch return error.PathNotFound;
        defer allocator.free(visualstudio_folder_path);

        const vs_versions: []const []const u8 = vs_versions: {
            if (!std.fs.path.isAbsolute(visualstudio_folder_path)) return error.PathNotFound;
            // enumerate folders that contain `privateregistry.bin`, looking for all versions
            // f.i. %localappdata%\Microsoft\VisualStudio\17.0_9e9cbb98\
            var visualstudio_folder = std.fs.openDirAbsolute(visualstudio_folder_path, .{
                .iterate = true,
            }) catch return error.PathNotFound;
            defer visualstudio_folder.close();

            var iterator = visualstudio_folder.iterate();
            break :vs_versions try iterateAndFilterByVersion(&iterator, allocator, "");
        };
        defer {
            for (vs_versions) |vs_version| allocator.free(vs_version);
            allocator.free(vs_versions);
        }
        var config_subkey_buf: [RegistryWtf16Le.key_name_max_len * 2]u8 = undefined;
        const source_directories: []const u8 = source_directories: for (vs_versions) |vs_version| {
            const privateregistry_absolute_path = std.fs.path.join(allocator, &.{ visualstudio_folder_path, vs_version, "privateregistry.bin" }) catch continue;
            defer allocator.free(privateregistry_absolute_path);
            if (!std.fs.path.isAbsolute(privateregistry_absolute_path)) continue;

            const visualstudio_registry = RegistryWtf8.loadFromPath(privateregistry_absolute_path) catch continue;
            defer visualstudio_registry.closeKey();

            const config_subkey = std.fmt.bufPrint(config_subkey_buf[0..], "Software\\Microsoft\\VisualStudio\\{s}_Config", .{vs_version}) catch unreachable;

            const source_directories_value = visualstudio_registry.getString(allocator, config_subkey, "Source Directories") catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
            if (source_directories_value.len > (std.fs.max_path_bytes * 30)) { // note(bratishkaerik): guessing from the fact that on my computer it has 15 paths and at least some of them are not of max length
                allocator.free(source_directories_value);
                continue;
            }

            break :source_directories source_directories_value;
        } else return error.PathNotFound;
        defer allocator.free(source_directories);

        var source_directories_split = std.mem.splitScalar(u8, source_directories, ';');

        const msvc_dir: []const u8 = msvc_dir: {
            const msvc_include_dir_maybe_with_trailing_slash = try allocator.dupe(u8, source_directories_split.first());

            if (msvc_include_dir_maybe_with_trailing_slash.len > std.fs.max_path_bytes or !std.fs.path.isAbsolute(msvc_include_dir_maybe_with_trailing_slash)) {
                allocator.free(msvc_include_dir_maybe_with_trailing_slash);
                return error.PathNotFound;
            }

            var msvc_dir = std.ArrayList(u8).fromOwnedSlice(allocator, msvc_include_dir_maybe_with_trailing_slash);
            errdefer msvc_dir.deinit();

            // String might contain trailing slash, so trim it here
            if (msvc_dir.items.len > "C:\\".len and msvc_dir.getLast() == '\\') _ = msvc_dir.pop();

            // Remove `\include` at the end of path
            if (std.mem.endsWith(u8, msvc_dir.items, "\\include")) {
                msvc_dir.shrinkRetainingCapacity(msvc_dir.items.len - "\\include".len);
            }

            try msvc_dir.appendSlice("\\Lib\\");
            try msvc_dir.appendSlice(switch (arch) {
                .thumb => "arm",
                .aarch64 => "arm64",
                .x86 => "x86",
                .x86_64 => "x64",
                else => unreachable,
            });
            const msvc_dir_with_arch = try msvc_dir.toOwnedSlice();
            break :msvc_dir msvc_dir_with_arch;
        };
        errdefer allocator.free(msvc_dir);

        if (!verifyLibDir(msvc_dir)) {
            return error.PathNotFound;
        }

        return msvc_dir;
    }

    fn findViaVs7Key(allocator: std.mem.Allocator, arch: std.Target.Cpu.Arch) error{ OutOfMemory, PathNotFound }![]const u8 {
        var base_path: std.ArrayList(u8) = base_path: {
            try_env: {
                var env_map = std.process.getEnvMap(allocator) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => break :try_env,
                };
                defer env_map.deinit();

                if (env_map.get("VS140COMNTOOLS")) |VS140COMNTOOLS| {
                    if (VS140COMNTOOLS.len < "C:\\Common7\\Tools".len) break :try_env;
                    if (!std.fs.path.isAbsolute(VS140COMNTOOLS)) break :try_env;
                    var list = std.ArrayList(u8).init(allocator);
                    errdefer list.deinit();

                    try list.appendSlice(VS140COMNTOOLS); // C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools
                    // String might contain trailing slash, so trim it here
                    if (list.items.len > "C:\\".len and list.getLast() == '\\') _ = list.pop();
                    list.shrinkRetainingCapacity(list.items.len - "\\Common7\\Tools".len); // C:\Program Files (x86)\Microsoft Visual Studio 14.0
                    break :base_path list;
                }
            }

            const vs7_key = RegistryWtf8.openKey(windows.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7", .{ .wow64_32 = true }) catch return error.PathNotFound;
            defer vs7_key.closeKey();
            try_vs7_key: {
                const path_maybe_with_trailing_slash = vs7_key.getString(allocator, "", "14.0") catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => break :try_vs7_key,
                };

                if (path_maybe_with_trailing_slash.len > std.fs.max_path_bytes or !std.fs.path.isAbsolute(path_maybe_with_trailing_slash)) {
                    allocator.free(path_maybe_with_trailing_slash);
                    break :try_vs7_key;
                }

                var path = std.ArrayList(u8).fromOwnedSlice(allocator, path_maybe_with_trailing_slash);
                errdefer path.deinit();

                // String might contain trailing slash, so trim it here
                if (path.items.len > "C:\\".len and path.getLast() == '\\') _ = path.pop();
                break :base_path path;
            }
            return error.PathNotFound;
        };
        errdefer base_path.deinit();

        try base_path.appendSlice("\\VC\\lib\\");
        try base_path.appendSlice(switch (arch) {
            .thumb => "arm",
            .aarch64 => "arm64",
            .x86 => "", //x86 is in the root of the Lib folder
            .x86_64 => "amd64",
            else => unreachable,
        });

        if (!verifyLibDir(base_path.items)) {
            return error.PathNotFound;
        }

        const full_path = try base_path.toOwnedSlice();
        return full_path;
    }

    fn verifyLibDir(lib_dir_path: []const u8) bool {
        std.debug.assert(std.fs.path.isAbsolute(lib_dir_path)); // should be already handled in `findVia*`

        var dir = std.fs.openDirAbsolute(lib_dir_path, .{}) catch return false;
        defer dir.close();

        const stat = dir.statFile("vcruntime.lib") catch return false;
        if (stat.kind != .file)
            return false;

        return true;
    }

    /// Find path to MSVC's `lib/` directory.
    /// Caller owns the result.
    pub fn find(allocator: std.mem.Allocator, arch: std.Target.Cpu.Arch) error{ OutOfMemory, MsvcLibDirNotFound }![]const u8 {
        const full_path = MsvcLibDir.findViaCOM(allocator, arch) catch |err1| switch (err1) {
            error.OutOfMemory => return error.OutOfMemory,
            error.PathNotFound => MsvcLibDir.findViaRegistry(allocator, arch) catch |err2| switch (err2) {
                error.OutOfMemory => return error.OutOfMemory,
                error.PathNotFound => MsvcLibDir.findViaVs7Key(allocator, arch) catch |err3| switch (err3) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.PathNotFound => return error.MsvcLibDirNotFound,
                },
            },
        };
        errdefer allocator.free(full_path);

        return full_path;
    }
};
//! Zig Intermediate Representation.
//!
//! Astgen.zig converts AST nodes to these untyped IR instructions. Next,
//! Sema.zig processes these into AIR.
//! The minimum amount of information needed to represent a list of ZIR instructions.
//! Once this structure is completed, it can be used to generate AIR, followed by
//! machine code, without any memory access into the AST tree token list, node list,
//! or source bytes. Exceptions include:
//!  * Compile errors, which may need to reach into these data structures to
//!    create a useful report.
//!  * In the future, possibly inline assembly, which needs to get parsed and
//!    handled by the codegen backend, and errors reported there. However for now,
//!    inline assembly is not an exception.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const BigIntConst = std.math.big.int.Const;
const BigIntMutable = std.math.big.int.Mutable;
const Ast = std.zig.Ast;

const Zir = @This();

instructions: std.MultiArrayList(Inst).Slice,
/// In order to store references to strings in fewer bytes, we copy all
/// string bytes into here. String bytes can be null. It is up to whomever
/// is referencing the data here whether they want to store both index and length,
/// thus allowing null bytes, or store only index, and use null-termination. The
/// `string_bytes` array is agnostic to either usage.
/// Index 0 is reserved for special cases.
string_bytes: []u8,
/// The meaning of this data is determined by `Inst.Tag` value.
/// The first few indexes are reserved. See `ExtraIndex` for the values.
extra: []u32,

/// The data stored at byte offset 0 when ZIR is stored in a file.
pub const Header = extern struct {
    instructions_len: u32,
    string_bytes_len: u32,
    extra_len: u32,
    /// We could leave this as padding, however it triggers a Valgrind warning because
    /// we read and write undefined bytes to the file system. This is harmless, but
    /// it's essentially free to have a zero field here and makes the warning go away,
    /// making it more likely that following Valgrind warnings will be taken seriously.
    unused: u32 = 0,
    stat_inode: std.fs.File.INode,
    stat_size: u64,
    stat_mtime: i128,
};

pub const ExtraIndex = enum(u32) {
    /// If this is 0, no compile errors. Otherwise there is a `CompileErrors`
    /// payload at this index.
    compile_errors,
    /// If this is 0, this file contains no imports. Otherwise there is a `Imports`
    /// payload at this index.
    imports,

    _,
};

fn ExtraData(comptime T: type) type {
    return struct { data: T, end: usize };
}

/// Returns the requested data, as well as the new index which is at the start of the
/// trailers for the object.
pub fn extraData(code: Zir, comptime T: type, index: usize) ExtraData(T) {
    const fields = @typeInfo(T).@"struct".fields;
    var i: usize = index;
    var result: T = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => code.extra[i],

            Inst.Ref,
            Inst.Index,
            Inst.Declaration.Name,
            std.zig.SimpleComptimeReason,
            NullTerminatedString,
            // Ast.TokenIndex is missing because it is a u32.
            Ast.OptionalTokenIndex,
            Ast.Node.Index,
            Ast.Node.OptionalIndex,
            => @enumFromInt(code.extra[i]),

            Ast.TokenOffset,
            Ast.OptionalTokenOffset,
            Ast.Node.Offset,
            Ast.Node.OptionalOffset,
            => @enumFromInt(@as(i32, @bitCast(code.extra[i]))),

            Inst.Call.Flags,
            Inst.BuiltinCall.Flags,
            Inst.SwitchBlock.Bits,
            Inst.SwitchBlockErrUnion.Bits,
            Inst.FuncFancy.Bits,
            Inst.Declaration.Flags,
            Inst.Param.Type,
            Inst.Func.RetTy,
            => @bitCast(code.extra[i]),

            else => @compileError("bad field type"),
        };
        i += 1;
    }
    return .{
        .data = result,
        .end = i,
    };
}

pub const NullTerminatedString = enum(u32) {
    empty = 0,
    _,
};

/// Given an index into `string_bytes` returns the null-terminated string found there.
pub fn nullTerminatedString(code: Zir, index: NullTerminatedString) [:0]const u8 {
    const slice = code.string_bytes[@intFromEnum(index)..];
    return slice[0..std.mem.indexOfScalar(u8, slice, 0).? :0];
}

pub fn refSlice(code: Zir, start: usize, len: usize) []Inst.Ref {
    return @ptrCast(code.extra[start..][0..len]);
}

pub fn bodySlice(zir: Zir, start: usize, len: usize) []Inst.Index {
    return @ptrCast(zir.extra[start..][0..len]);
}

pub fn hasCompileErrors(code: Zir) bool {
    if (code.extra[@intFromEnum(ExtraIndex.compile_errors)] != 0) {
        return true;
    } else {
        assert(code.instructions.len != 0); // i.e. lowering did not fail
        return false;
    }
}

pub fn loweringFailed(code: Zir) bool {
    if (code.instructions.len == 0) {
        assert(code.hasCompileErrors());
        return true;
    } else {
        return false;
    }
}

pub fn deinit(code: *Zir, gpa: Allocator) void {
    code.instructions.deinit(gpa);
    gpa.free(code.string_bytes);
    gpa.free(code.extra);
    code.* = undefined;
}

/// These are untyped instructions generated from an Abstract Syntax Tree.
/// The data here is immutable because it is possible to have multiple
/// analyses on the same ZIR happening at the same time.
pub const Inst = struct {
    tag: Tag,
    data: Data,

    /// These names are used directly as the instruction names in the text format.
    /// See `data_field_map` for a list of which `Data` fields are used by each `Tag`.
    pub const Tag = enum(u8) {
        /// Arithmetic addition, asserts no integer overflow.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        add,
        /// Twos complement wrapping integer addition.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        addwrap,
        /// Saturating addition.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        add_sat,
        /// The same as `add` except no safety check.
        add_unsafe,
        /// Arithmetic subtraction. Asserts no integer overflow.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        sub,
        /// Twos complement wrapping integer subtraction.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        subwrap,
        /// Saturating subtraction.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        sub_sat,
        /// Arithmetic multiplication. Asserts no integer overflow.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        mul,
        /// Twos complement wrapping integer multiplication.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        mulwrap,
        /// Saturating multiplication.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        mul_sat,
        /// Implements the `@divExact` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        div_exact,
        /// Implements the `@divFloor` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        div_floor,
        /// Implements the `@divTrunc` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        div_trunc,
        /// Implements the `@mod` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        mod,
        /// Implements the `@rem` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        rem,
        /// Ambiguously remainder division or modulus. If the computation would possibly have
        /// a different value depending on whether the operation is remainder division or modulus,
        /// a compile error is emitted. Otherwise the computation is performed.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        mod_rem,
        /// Integer shift-left. Zeroes are shifted in from the right hand side.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        shl,
        /// Implements the `@shlExact` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        shl_exact,
        /// Saturating shift-left.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        shl_sat,
        /// Integer shift-right. Arithmetic or logical depending on the signedness of
        /// the integer type.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        shr,
        /// Implements the `@shrExact` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        shr_exact,

        /// Declares a parameter of the current function. Used for:
        /// * debug info
        /// * checking shadowing against declarations in the current namespace
        /// * parameter type expressions referencing other parameters
        /// These occur in the block outside a function body (the same block as
        /// contains the func instruction).
        /// Uses the `pl_tok` field. Token is the parameter name, payload is a `Param`.
        param,
        /// Same as `param` except the parameter is marked comptime.
        param_comptime,
        /// Same as `param` except the parameter is marked anytype.
        /// Uses the `str_tok` field. Token is the parameter name. String is the parameter name.
        param_anytype,
        /// Same as `param` except the parameter is marked both comptime and anytype.
        /// Uses the `str_tok` field. Token is the parameter name. String is the parameter name.
        param_anytype_comptime,
        /// Array concatenation. `a ++ b`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        array_cat,
        /// Array multiplication `a ** b`
        /// Uses the `pl_node` union field. Payload is `ArrayMul`.
        array_mul,
        /// `[N]T` syntax. No source location provided.
        /// Uses the `pl_node` union field. Payload is `Bin`. lhs is length, rhs is element type.
        array_type,
        /// `[N:S]T` syntax. Source location is the array type expression node.
        /// Uses the `pl_node` union field. Payload is `ArrayTypeSentinel`.
        array_type_sentinel,
        /// `@Vector` builtin.
        /// Uses the `pl_node` union field with `Bin` payload.
        /// lhs is length, rhs is element type.
        vector_type,
        /// Given a pointer type, returns its element type. Reaches through any optional or error
        /// union types wrapping the pointer. Asserts that the underlying type is a pointer type.
        /// Returns generic poison if the element type is `anyopaque`.
        /// Uses the `un_node` field.
        elem_type,
        /// Given an indexable pointer (slice, many-ptr, single-ptr-to-array), returns its
        /// element type. Emits a compile error if the type is not an indexable pointer.
        /// Uses the `un_node` field.
        indexable_ptr_elem_type,
        /// Given a vector or array type, returns its element type.
        /// Uses the `un_node` field.
        vec_arr_elem_type,
        /// Given a pointer to an indexable object, returns the len property. This is
        /// used by for loops. This instruction also emits a for-loop specific compile
        /// error if the indexable object is not indexable.
        /// Uses the `un_node` field. The AST node is the for loop node.
        indexable_ptr_len,
        /// Create a `anyframe->T` type.
        /// Uses the `un_node` field.
        anyframe_type,
        /// Type coercion to the function's return type.
        /// Uses the `pl_node` field. Payload is `As`. AST node could be many things.
        as_node,
        /// Same as `as_node` but ignores runtime to comptime int error.
        as_shift_operand,
        /// Bitwise AND. `&`
        bit_and,
        /// Reinterpret the memory representation of a value as a different type.
        /// Uses the pl_node field with payload `Bin`.
        bitcast,
        /// Bitwise NOT. `~`
        /// Uses `un_node`.
        bit_not,
        /// Bitwise OR. `|`
        bit_or,
        /// A labeled block of code, which can return a value.
        /// Uses the `pl_node` union field. Payload is `Block`.
        block,
        /// Like `block`, but forces full evaluation of its contents at compile-time.
        /// Exited with `break_inline`.
        /// Uses the `pl_node` union field. Payload is `BlockComptime`.
        block_comptime,
        /// A list of instructions which are analyzed in the parent context, without
        /// generating a runtime block. Must terminate with an "inline" variant of
        /// a noreturn instruction.
        /// Uses the `pl_node` union field. Payload is `Block`.
        block_inline,
        /// This instruction may only ever appear in the list of declarations for a
        /// namespace type, e.g. within a `struct_decl` instruction. It represents a
        /// single source declaration (`const`/`var`/`fn`), containing the name,
        /// attributes, type, and value of the declaration.
        /// Uses the `declaration` union field. Payload is `Declaration`.
        declaration,
        /// Implements `suspend {...}`.
        /// Uses the `pl_node` union field. Payload is `Block`.
        suspend_block,
        /// Boolean NOT. See also `bit_not`.
        /// Uses the `un_node` field.
        bool_not,
        /// Short-circuiting boolean `and`. `lhs` is a boolean `Ref` and the other operand
        /// is a block, which is evaluated if `lhs` is `true`.
        /// Uses the `pl_node` union field. Payload is `BoolBr`.
        bool_br_and,
        /// Short-circuiting boolean `or`. `lhs` is a boolean `Ref` and the other operand
        /// is a block, which is evaluated if `lhs` is `false`.
        /// Uses the `pl_node` union field. Payload is `BoolBr`.
        bool_br_or,
        /// Return a value from a block.
        /// Uses the `break` union field.
        /// Uses the source information from previous instruction.
        @"break",
        /// Return a value from a block. This instruction is used as the terminator
        /// of a `block_inline`. It allows using the return value from `Sema.analyzeBody`.
        /// This instruction may also be used when it is known that there is only one
        /// break instruction in a block, and the target block is the parent.
        /// Uses the `break` union field.
        break_inline,
        /// Branch from within a switch case to the case specified by the operand.
        /// Uses the `break` union field. `block_inst` refers to a `switch_block` or `switch_block_ref`.
        switch_continue,
        /// Checks that comptime control flow does not happen inside a runtime block.
        /// Uses the `un_node` union field.
        check_comptime_control_flow,
        /// Function call.
        /// Uses the `pl_node` union field with payload `Call`.
        /// AST node is the function call.
        call,
        /// Function call using `a.b()` syntax.
        /// Uses the named field as the callee. If there is no such field, searches in the type for
        /// a decl matching the field name. The decl is resolved and we ensure that it's a function
        /// which can accept the object as the first parameter, with one pointer fixup. This
        /// function is then used as the callee, with the object as an implicit first parameter.
        /// Uses the `pl_node` union field with payload `FieldCall`.
        /// AST node is the function call.
        field_call,
        /// Implements the `@call` builtin.
        /// Uses the `pl_node` union field with payload `BuiltinCall`.
        /// AST node is the builtin call.
        builtin_call,
        /// `<`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        cmp_lt,
        /// `<=`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        cmp_lte,
        /// `==`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        cmp_eq,
        /// `>=`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        cmp_gte,
        /// `>`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        cmp_gt,
        /// `!=`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        cmp_neq,
        /// Conditional branch. Splits control flow based on a boolean condition value.
        /// Uses the `pl_node` union field. AST node is an if, while, for, etc.
        /// Payload is `CondBr`.
        condbr,
        /// Same as `condbr`, except the condition is coerced to a comptime value, and
        /// only the taken branch is analyzed. The then block and else block must
        /// terminate with an "inline" variant of a noreturn instruction.
        condbr_inline,
        /// Given an operand which is an error union, splits control flow. In
        /// case of error, control flow goes into the block that is part of this
        /// instruction, which is guaranteed to end with a return instruction
        /// and never breaks out of the block.
        /// In the case of non-error, control flow proceeds to the next instruction
        /// after the `try`, with the result of this instruction being the unwrapped
        /// payload value, as if `err_union_payload_unsafe` was executed on the operand.
        /// Uses the `pl_node` union field. Payload is `Try`.
        @"try",
        /// Same as `try` except the operand is a pointer and the result is a pointer.
        try_ptr,
        /// An error set type definition. Contains a list of field names.
        /// Uses the `pl_node` union field. Payload is `ErrorSetDecl`.
        error_set_decl,
        /// Declares the beginning of a statement. Used for debug info.
        /// Uses the `dbg_stmt` union field. The line and column are offset
        /// from the parent declaration.
        dbg_stmt,
        /// Marks a variable declaration. Used for debug info.
        /// Uses the `str_op` union field. The string is the local variable name,
        /// and the operand is the pointer to the variable's location. The local
        /// may be a const or a var.
        dbg_var_ptr,
        /// Same as `dbg_var_ptr` but the local is always a const and the operand
        /// is the local's value.
        dbg_var_val,
        /// Uses a name to identify a Decl and takes a pointer to it.
        /// Uses the `str_tok` union field.
        decl_ref,
        /// Uses a name to identify a Decl and uses it as a value.
        /// Uses the `str_tok` union field.
        decl_val,
        /// Load the value from a pointer. Assumes `x.*` syntax.
        /// Uses `un_node` field. AST node is the `x.*` syntax.
        load,
        /// Arithmetic division. Asserts no integer overflow.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        div,
        /// Given a pointer to an array, slice, or pointer, returns a pointer to the element at
        /// the provided index.
        /// Uses the `pl_node` union field. AST node is a[b] syntax. Payload is `Bin`.
        elem_ptr_node,
        /// Same as `elem_ptr_node` but used only for for loop.
        /// Uses the `pl_node` union field. AST node is the condition of a for loop.
        /// Payload is `Bin`.
        /// No OOB safety check is emitted.
        elem_ptr,
        /// Given an array, slice, or pointer, returns the element at the provided index.
        /// Uses the `pl_node` union field. AST node is a[b] syntax. Payload is `Bin`.
        elem_val_node,
        /// Same as `elem_val_node` but used only for for loop.
        /// Uses the `pl_node` union field. AST node is the condition of a for loop.
        /// Payload is `Bin`.
        /// No OOB safety check is emitted.
        elem_val,
        /// Same as `elem_val` but takes the index as an immediate value.
        /// No OOB safety check is emitted. A prior instruction must validate this operation.
        /// Uses the `elem_val_imm` union field.
        elem_val_imm,
        /// Emits a compile error if the operand is not `void`.
        /// Uses the `un_node` field.
        ensure_result_used,
        /// Emits a compile error if an error is ignored.
        /// Uses the `un_node` field.
        ensure_result_non_error,
        /// Emits a compile error error union payload is not void.
        ensure_err_union_payload_void,
        /// Create a `E!T` type.
        /// Uses the `pl_node` field with `Bin` payload.
        error_union_type,
        /// `error.Foo` syntax. Uses the `str_tok` field of the Data union.
        error_value,
        /// Implements the `@export` builtin function.
        /// Uses the `pl_node` union field. Payload is `Export`.
        @"export",
        /// Given a pointer to a struct or object that contains virtual fields, returns a pointer
        /// to the named field. The field name is stored in string_bytes. Used by a.b syntax.
        /// Uses `pl_node` field. The AST node is the a.b syntax. Payload is Field.
        field_ptr,
        /// Given a struct or object that contains virtual fields, returns the named field.
        /// The field name is stored in string_bytes. Used by a.b syntax.
        /// This instruction also accepts a pointer.
        /// Uses `pl_node` field. The AST node is the a.b syntax. Payload is Field.
        field_val,
        /// Given a pointer to a struct or object that contains virtual fields, returns a pointer
        /// to the named field. The field name is a comptime instruction. Used by @field.
        /// Uses `pl_node` field. The AST node is the builtin call. Payload is FieldNamed.
        field_ptr_named,
        /// Given a struct or object that contains virtual fields, returns the named field.
        /// The field name is a comptime instruction. Used by @field.
        /// Uses `pl_node` field. The AST node is the builtin call. Payload is FieldNamed.
        field_val_named,
        /// Returns a function type, or a function instance, depending on whether
        /// the body_len is 0. Calling convention is auto.
        /// Uses the `pl_node` union field. `payload_index` points to a `Func`.
        func,
        /// Same as `func` but has an inferred error set.
        func_inferred,
        /// Represents a function declaration or function prototype, depending on
        /// whether body_len is 0.
        /// Uses the `pl_node` union field. `payload_index` points to a `FuncFancy`.
        func_fancy,
        /// Implements the `@import` builtin.
        /// Uses the `pl_tok` field.
        import,
        /// Integer literal that fits in a u64. Uses the `int` union field.
        int,
        /// Arbitrary sized integer literal. Uses the `str` union field.
        int_big,
        /// A float literal that fits in a f64. Uses the float union value.
        float,
        /// A float literal that fits in a f128. Uses the `pl_node` union value.
        /// Payload is `Float128`.
        float128,
        /// Make an integer type out of signedness and bit count.
        /// Payload is `int_type`
        int_type,
        /// Return a boolean false if an optional is null. `x != null`
        /// Uses the `un_node` field.
        is_non_null,
        /// Return a boolean false if an optional is null. `x.* != null`
        /// Uses the `un_node` field.
        is_non_null_ptr,
        /// Return a boolean false if value is an error
        /// Uses the `un_node` field.
        is_non_err,
        /// Return a boolean false if dereferenced pointer is an error
        /// Uses the `un_node` field.
        is_non_err_ptr,
        /// Same as `is_non_er` but doesn't validate that the type can be an error.
        /// Uses the `un_node` field.
        ret_is_non_err,
        /// A labeled block of code that loops forever. At the end of the body will have either
        /// a `repeat` instruction or a `repeat_inline` instruction.
        /// Uses the `pl_node` field. The AST node is either a for loop or while loop.
        /// This ZIR instruction is needed because AIR does not (yet?) match ZIR, and Sema
        /// needs to emit more than 1 AIR block for this instruction.
        /// The payload is `Block`.
        loop,
        /// Sends runtime control flow back to the beginning of the current block.
        /// Uses the `node` field.
        repeat,
        /// Sends comptime control flow back to the beginning of the current block.
        /// Uses the `node` field.
        repeat_inline,
        /// Asserts that all the lengths provided match. Used to build a for loop.
        /// Return value is the length as a usize.
        /// Uses the `pl_node` field with payload `MultiOp`.
        /// There are two items for each AST node inside the for loop condition.
        /// If both items in a pair are `.none`, then this node is an unbounded range.
        /// If only the second item in a pair is `.none`, then the first is an indexable.
        /// Otherwise, the node is a bounded range `a..b`, with the items being `a` and `b`.
        /// Illegal behaviors:
        ///  * If all lengths are unbounded ranges (always a compile error).
        ///  * If any two lengths do not match each other.
        for_len,
        /// Merge two error sets into one, `E1 || E2`.
        /// Uses the `pl_node` field with payload `Bin`.
        merge_error_sets,
        /// Turns an R-Value into a const L-Value. In other words, it takes a value,
        /// stores it in a memory location, and returns a const pointer to it. If the value
        /// is `comptime`, the memory location is global static constant data. Otherwise,
        /// the memory location is in the stack frame, local to the scope containing the
        /// instruction.
        /// Uses the `un_tok` union field.
        ref,
        /// Sends control flow back to the function's callee.
        /// Includes an operand as the return value.
        /// Includes an AST node source location.
        /// Uses the `un_node` union field.
        ret_node,
        /// Sends control flow back to the function's callee.
        /// The operand is a `ret_ptr` instruction, where the return value can be found.
        /// Includes an AST node source location.
        /// Uses the `un_node` union field.
        ret_load,
        /// Sends control flow back to the function's callee.
        /// Includes an operand as the return value.
        /// Includes a token source location.
        /// Uses the `un_tok` union field.
        ret_implicit,
        /// Sends control flow back to the function's callee.
        /// The return operand is `error.foo` where `foo` is given by the string.
        /// If the current function has an inferred error set, the error given by the
        /// name is added to it.
        /// Uses the `str_tok` union field.
        ret_err_value,
        /// A string name is provided which is an anonymous error set value.
        /// If the current function has an inferred error set, the error given by the
        /// name is added to it.
        /// Results in the error code. Note that control flow is not diverted with
        /// this instruction; a following 'ret' instruction will do the diversion.
        /// Uses the `str_tok` union field.
        ret_err_value_code,
        /// Obtains a pointer to the return value.
        /// Uses the `node` union field.
        ret_ptr,
        /// Obtains the return type of the in-scope function.
        /// Uses the `node` union field.
        ret_type,
        /// Create a pointer type which can have a sentinel, alignment, address space, and/or bit range.
        /// Uses the `ptr_type` union field.
        ptr_type,
        /// Slice operation `lhs[rhs..]`. No sentinel and no end offset.
        /// Returns a pointer to the subslice.
        /// Uses the `pl_node` field. AST node is the slice syntax. Payload is `SliceStart`.
        slice_start,
        /// Slice operation `array_ptr[start..end]`. No sentinel.
        /// Returns a pointer to the subslice.
        /// Uses the `pl_node` field. AST node is the slice syntax. Payload is `SliceEnd`.
        slice_end,
        /// Slice operation `array_ptr[start..end:sentinel]`.
        /// Returns a pointer to the subslice.
        /// Uses the `pl_node` field. AST node is the slice syntax. Payload is `SliceSentinel`.
        slice_sentinel,
        /// Slice operation `array_ptr[start..][0..len]`. Optional sentinel.
        /// Returns a pointer to the subslice.
        /// Uses the `pl_node` field. AST node is the slice syntax. Payload is `SliceLength`.
        slice_length,
        /// Given a value which is a pointer to the LHS of a slice operation, return the sentinel
        /// type, used as the result type of the slice sentinel (i.e. `s` in `lhs[a..b :s]`).
        /// Uses the `un_node` field. AST node is the slice syntax. Operand is `lhs`.
        slice_sentinel_ty,
        /// Same as `store` except provides a source location.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        store_node,
        /// Same as `store_node` but the type of the value being stored will be
        /// used to infer the pointer type of an `alloc_inferred`.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        store_to_inferred_ptr,
        /// String Literal. Makes an anonymous Decl and then takes a pointer to it.
        /// Uses the `str` union field.
        str,
        /// Arithmetic negation. Asserts no integer overflow.
        /// Same as sub with a lhs of 0, split into a separate instruction to save memory.
        /// Uses `un_node`.
        negate,
        /// Twos complement wrapping integer negation.
        /// Same as subwrap with a lhs of 0, split into a separate instruction to save memory.
        /// Uses `un_node`.
        negate_wrap,
        /// Returns the type of a value.
        /// Uses the `un_node` field.
        typeof,
        /// Implements `@TypeOf` for one operand.
        /// Uses the `pl_node` field. Payload is `Block`.
        typeof_builtin,
        /// Given a value, look at the type of it, which must be an integer type.
        /// Returns the integer type for the RHS of a shift operation.
        /// Uses the `un_node` field.
        typeof_log2_int_type,
        /// Asserts control-flow will not reach this instruction (`unreachable`).
        /// Uses the `@"unreachable"` union field.
        @"unreachable",
        /// Bitwise XOR. `^`
        /// Uses the `pl_node` union field. Payload is `Bin`.
        xor,
        /// Create an optional type '?T'
        /// Uses the `un_node` field.
        optional_type,
        /// ?T => T with safety.
        /// Given an optional value, returns the payload value, with a safety check that
        /// the value is non-null. Used for `orelse`, `if` and `while`.
        /// Uses the `un_node` field.
        optional_payload_safe,
        /// ?T => T without safety.
        /// Given an optional value, returns the payload value. No safety checks.
        /// Uses the `un_node` field.
        optional_payload_unsafe,
        /// *?T => *T with safety.
        /// Given a pointer to an optional value, returns a pointer to the payload value,
        /// with a safety check that the value is non-null. Used for `orelse`, `if` and `while`.
        /// Uses the `un_node` field.
        optional_payload_safe_ptr,
        /// *?T => *T without safety.
        /// Given a pointer to an optional value, returns a pointer to the payload value.
        /// No safety checks.
        /// Uses the `un_node` field.
        optional_payload_unsafe_ptr,
        /// E!T => T without safety.
        /// Given an error union value, returns the payload value. No safety checks.
        /// Uses the `un_node` field.
        err_union_payload_unsafe,
        /// *E!T => *T without safety.
        /// Given a pointer to a error union value, returns a pointer to the payload value.
        /// No safety checks.
        /// Uses the `un_node` field.
        err_union_payload_unsafe_ptr,
        /// E!T => E without safety.
        /// Given an error union value, returns the error code. No safety checks.
        /// Uses the `un_node` field.
        err_union_code,
        /// *E!T => E without safety.
        /// Given a pointer to an error union value, returns the error code. No safety checks.
        /// Uses the `un_node` field.
        err_union_code_ptr,
        /// An enum literal. Uses the `str_tok` union field.
        enum_literal,
        /// A decl literal. This is similar to `field`, but unwraps error unions and optionals,
        /// and coerces the result to the given type.
        /// Uses the `pl_node` union field. Payload is `Field`.
        decl_literal,
        /// The same as `decl_literal`, but the coercion is omitted. This is used for decl literal
        /// function call syntax, i.e. `.foo()`.
        /// Uses the `pl_node` union field. Payload is `Field`.
        decl_literal_no_coerce,
        /// A switch expression. Uses the `pl_node` union field.
        /// AST node is the switch, payload is `SwitchBlock`.
        switch_block,
        /// A switch expression. Uses the `pl_node` union field.
        /// AST node is the switch, payload is `SwitchBlock`. Operand is a pointer.
        switch_block_ref,
        /// A switch on an error union `a catch |err| switch (err) {...}`.
        /// Uses the `pl_node` union field. AST node is the `catch`, payload is `SwitchBlockErrUnion`.
        switch_block_err_union,
        /// Check that operand type supports the dereference operand (.*).
        /// Uses the `un_node` field.
        validate_deref,
        /// Check that the operand's type is an array or tuple with the given number of elements.
        /// Uses the `pl_node` field. Payload is `ValidateDestructure`.
        validate_destructure,
        /// Given a struct or union, and a field name as a Ref,
        /// returns the field type. Uses the `pl_node` field. Payload is `FieldTypeRef`.
        field_type_ref,
        /// Given a pointer, initializes all error unions and optionals in the pointee to payloads,
        /// returning the base payload pointer. For instance, converts *E!?T into a valid *T
        /// (clobbering any existing error or null value).
        /// Uses the `un_node` field.
        opt_eu_base_ptr_init,
        /// Coerce a given value such that when a reference is taken, the resulting pointer will be
        /// coercible to the given type. For instance, given a value of type 'u32' and the pointer
        /// type '*u64', coerces the value to a 'u64'. Asserts that the type is a pointer type.
        /// Uses the `pl_node` field. Payload is `Bin`.
        /// LHS is the pointer type, RHS is the value.
        coerce_ptr_elem_ty,
        /// Given a type, validate that it is a pointer type suitable for return from the address-of
        /// operator. Emit a compile error if not.
        /// Uses the `un_tok` union field. Token is the `&` operator. Operand is the type.
        validate_ref_ty,
        /// Given a value, check whether it is a valid local constant in this scope.
        /// In a runtime scope, this is always a nop.
        /// In a comptime scope, raises a compile error if the value is runtime-known.
        /// Result is always void.
        /// Uses the `un_node` union field. Node is the initializer. Operand is the initializer value.
        validate_const,

        // The following tags all relate to struct initialization expressions.

        /// A struct literal with a specified explicit type, with no fields.
        /// Uses the `un_node` field.
        struct_init_empty,
        /// An anonymous struct literal with a known result type, with no fields.
        /// Uses the `un_node` field.
        struct_init_empty_result,
        /// An anonymous struct literal with no fields, returned by reference, with a known result
        /// type for the pointer. Asserts that the type is a pointer.
        /// Uses the `un_node` field.
        struct_init_empty_ref_result,
        /// Struct initialization without a type. Creates a value of an anonymous struct type.
        /// Uses the `pl_node` field. Payload is `StructInitAnon`.
        struct_init_anon,
        /// Finalizes a typed struct or union initialization, performs validation, and returns the
        /// struct or union value. The given type must be validated prior to this instruction, using
        /// `validate_struct_init_ty` or `validate_struct_init_result_ty`. If the given type is
        /// generic poison, this is downgraded to an anonymous initialization.
        /// Uses the `pl_node` field. Payload is `StructInit`.
        struct_init,
        /// Struct initialization syntax, make the result a pointer. Equivalent to `struct_init`
        /// followed by `ref` - this ZIR tag exists as an optimization for a common pattern.
        /// Uses the `pl_node` field. Payload is `StructInit`.
        struct_init_ref,
        /// Checks that the type supports struct init syntax. Always returns void.
        /// Uses the `un_node` field.
        validate_struct_init_ty,
        /// Like `validate_struct_init_ty`, but additionally accepts types which structs coerce to.
        /// Used on the known result type of a struct init expression. Always returns void.
        /// Uses the `un_node` field.
        validate_struct_init_result_ty,
        /// Given a set of `struct_init_field_ptr` instructions, assumes they are all part of a
        /// struct initialization expression, and emits compile errors for duplicate fields as well
        /// as missing fields, if applicable.
        /// This instruction asserts that there is at least one struct_init_field_ptr instruction,
        /// because it must use one of them to find out the struct type.
        /// Uses the `pl_node` field. Payload is `Block`.
        validate_ptr_struct_init,
        /// Given a type being used for a struct initialization expression, returns the type of the
        /// field with the given name.
        /// Uses the `pl_node` field. Payload is `FieldType`.
        struct_init_field_type,
        /// Given a pointer being used as the result pointer of a struct initialization expression,
        /// return a pointer to the field of the given name.
        /// Uses the `pl_node` field. The AST node is the field initializer. Payload is Field.
        struct_init_field_ptr,

        // The following tags all relate to array initialization expressions.

        /// Array initialization without a type. Creates a value of a tuple type.
        /// Uses the `pl_node` field. Payload is `MultiOp`.
        array_init_anon,
        /// Array initialization syntax with a known type. The given type must be validated prior to
        /// this instruction, using some `validate_array_init_*_ty` instruction.
        /// Uses the `pl_node` field. Payload is `MultiOp`, where the first operand is the type.
        array_init,
        /// Array initialization syntax, make the result a pointer. Equivalent to `array_init`
        /// followed by `ref`- this ZIR tag exists as an optimization for a common pattern.
        /// Uses the `pl_node` field. Payload is `MultiOp`, where the first operand is the type.
        array_init_ref,
        /// Checks that the type supports array init syntax. Always returns void.
        /// Uses the `pl_node` field. Payload is `ArrayInit`.
        validate_array_init_ty,
        /// Like `validate_array_init_ty`, but additionally accepts types which arrays coerce to.
        /// Used on the known result type of an array init expression. Always returns void.
        /// Uses the `pl_node` field. Payload is `ArrayInit`.
        validate_array_init_result_ty,
        /// Given a pointer or slice type and an element count, return the expected type of an array
        /// initializer such that a pointer to the initializer has the given pointer type, checking
        /// that this type supports array init syntax and emitting a compile error if not. Preserves
        /// error union and optional wrappers on the array type, if any.
        /// Asserts that the given type is a pointer or slice type.
        /// Uses the `pl_node` field. Payload is `ArrayInitRefTy`.
        validate_array_init_ref_ty,
        /// Given a set of `array_init_elem_ptr` instructions, assumes they are all part of an array
        /// initialization expression, and emits a compile error if the number of elements does not
        /// match the array type.
        /// This instruction asserts that there is at least one `array_init_elem_ptr` instruction,
        /// because it must use one of them to find out the array type.
        /// Uses the `pl_node` field. Payload is `Block`.
        validate_ptr_array_init,
        /// Given a type being used for an array initialization expression, returns the type of the
        /// element at the given index.
        /// Uses the `bin` union field. lhs is the indexable type, rhs is the index.
        array_init_elem_type,
        /// Given a pointer being used as the result pointer of an array initialization expression,
        /// return a pointer to the element at the given index.
        /// Uses the `pl_node` union field. AST node is an element inside array initialization
        /// syntax. Payload is `ElemPtrImm`.
        array_init_elem_ptr,

        /// Implements the `@unionInit` builtin.
        /// Uses the `pl_node` field. Payload is `UnionInit`.
        union_init,
        /// Implements the `@typeInfo` builtin. Uses `un_node`.
        type_info,
        /// Implements the `@sizeOf` builtin. Uses `un_node`.
        size_of,
        /// Implements the `@bitSizeOf` builtin. Uses `un_node`.
        bit_size_of,

        /// Implement builtin `@intFromPtr`. Uses `un_node`.
        /// Convert a pointer to a `usize` integer.
        int_from_ptr,
        /// Emit an error message and fail compilation.
        /// Uses the `un_node` field.
        compile_error,
        /// Changes the maximum number of backwards branches that compile-time
        /// code execution can use before giving up and making a compile error.
        /// Uses the `un_node` union field.
        set_eval_branch_quota,
        /// Converts an enum value into an integer. Resulting type will be the tag type
        /// of the enum. Uses `un_node`.
        int_from_enum,
        /// Implement builtin `@alignOf`. Uses `un_node`.
        align_of,
        /// Implement builtin `@intFromBool`. Uses `un_node`.
        int_from_bool,
        /// Implement builtin `@embedFile`. Uses `un_node`.
        embed_file,
        /// Implement builtin `@errorName`. Uses `un_node`.
        error_name,
        /// Implement builtin `@panic`. Uses `un_node`.
        panic,
        /// Implements `@trap`.
        /// Uses the `node` field.
        trap,
        /// Implement builtin `@setRuntimeSafety`. Uses `un_node`.
        set_runtime_safety,
        /// Implement builtin `@sqrt`. Uses `un_node`.
        sqrt,
        /// Implement builtin `@sin`. Uses `un_node`.
        sin,
        /// Implement builtin `@cos`. Uses `un_node`.
        cos,
        /// Implement builtin `@tan`. Uses `un_node`.
        tan,
        /// Implement builtin `@exp`. Uses `un_node`.
        exp,
        /// Implement builtin `@exp2`. Uses `un_node`.
        exp2,
        /// Implement builtin `@log`. Uses `un_node`.
        log,
        /// Implement builtin `@log2`. Uses `un_node`.
        log2,
        /// Implement builtin `@log10`. Uses `un_node`.
        log10,
        /// Implement builtin `@abs`. Uses `un_node`.
        abs,
        /// Implement builtin `@floor`. Uses `un_node`.
        floor,
        /// Implement builtin `@ceil`. Uses `un_node`.
        ceil,
        /// Implement builtin `@trunc`. Uses `un_node`.
        trunc,
        /// Implement builtin `@round`. Uses `un_node`.
        round,
        /// Implement builtin `@tagName`. Uses `un_node`.
        tag_name,
        /// Implement builtin `@typeName`. Uses `un_node`.
        type_name,
        /// Implement builtin `@Frame`. Uses `un_node`.
        frame_type,
        /// Implement builtin `@frameSize`. Uses `un_node`.
        frame_size,

        /// Implements the `@intFromFloat` builtin.
        /// Uses `pl_node` with payload `Bin`. `lhs` is dest type, `rhs` is operand.
        int_from_float,
        /// Implements the `@floatFromInt` builtin.
        /// Uses `pl_node` with payload `Bin`. `lhs` is dest type, `rhs` is operand.
        float_from_int,
        /// Implements the `@ptrFromInt` builtin.
        /// Uses `pl_node` with payload `Bin`. `lhs` is dest type, `rhs` is operand.
        ptr_from_int,
        /// Converts an integer into an enum value.
        /// Uses `pl_node` with payload `Bin`. `lhs` is dest type, `rhs` is operand.
        enum_from_int```
