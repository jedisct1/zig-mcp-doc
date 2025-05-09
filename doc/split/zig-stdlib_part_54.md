```
std.mem.readInt(u64, self.slice[self.offset..][0..8], .little);
}

pub fn readU64(self: FloatStream) ?u64 {
    if (self.hasLen(8)) {
        return self.readU64Unchecked();
    }
    return null;
}

pub fn atUnchecked(self: *FloatStream, i: usize) u8 {
    return self.slice[self.offset + i];
}

pub fn scanDigit(self: *FloatStream, comptime base: u8) ?u8 {
    comptime std.debug.assert(base == 10 or base == 16);

    retry: while (true) {
        if (self.first()) |ok| {
            if ('0' <= ok and ok <= '9') {
                self.advance(1);
                return ok - '0';
            } else if (base == 16 and 'a' <= ok and ok <= 'f') {
                self.advance(1);
                return ok - 'a' + 10;
            } else if (base == 16 and 'A' <= ok and ok <= 'F') {
                self.advance(1);
                return ok - 'A' + 10;
            } else if (ok == '_') {
                self.advance(1);
                self.underscore_count += 1;
                continue :retry;
            }
        }
        return null;
    }
}
const std = @import("std");
const common = @import("common.zig");
const FloatStream = @import("FloatStream.zig");
const isEightDigits = common.isEightDigits;
const Number = common.Number;

/// Parse 8 digits, loaded as bytes in little-endian order.
///
/// This uses the trick where every digit is in [0x030, 0x39],
/// and therefore can be parsed in 3 multiplications, much
/// faster than the normal 8.
///
/// This is based off the algorithm described in "Fast numeric string to
/// int", available here: <https://johnnylee-sde.github.io/Fast-numeric-string-to-int/>.
fn parse8Digits(v_: u64) u64 {
    var v = v_;
    const mask = 0x0000_00ff_0000_00ff;
    const mul1 = 0x000f_4240_0000_0064;
    const mul2 = 0x0000_2710_0000_0001;
    v -= 0x3030_3030_3030_3030;
    v = (v * 10) + (v >> 8); // will not overflow, fits in 63 bits
    const v1 = (v & mask) *% mul1;
    const v2 = ((v >> 16) & mask) *% mul2;
    return @as(u64, @as(u32, @truncate((v1 +% v2) >> 32)));
}

/// Parse digits until a non-digit character is found.
fn tryParseDigits(comptime T: type, stream: *FloatStream, x: *T, comptime base: u8) void {
    // Try to parse 8 digits at a time, using an optimized algorithm.
    // This only supports decimal digits.
    if (base == 10) {
        while (stream.hasLen(8)) {
            const v = stream.readU64Unchecked();
            if (!isEightDigits(v)) {
                break;
            }

            x.* = x.* *% 1_0000_0000 +% parse8Digits(v);
            stream.advance(8);
        }
    }

    while (stream.scanDigit(base)) |digit| {
        x.* *%= base;
        x.* +%= digit;
    }
}

fn min_n_digit_int(comptime T: type, digit_count: usize) T {
    var n: T = 1;
    var i: usize = 1;
    while (i < digit_count) : (i += 1) n *= 10;
    return n;
}

/// Parse up to N digits
fn tryParseNDigits(comptime T: type, stream: *FloatStream, x: *T, comptime base: u8, comptime n: usize) void {
    while (x.* < min_n_digit_int(T, n)) {
        if (stream.scanDigit(base)) |digit| {
            x.* *%= base;
            x.* +%= digit;
        } else {
            break;
        }
    }
}

/// Parse the scientific notation component of a float.
fn parseScientific(stream: *FloatStream) ?i64 {
    var exponent: i64 = 0;
    var negative = false;

    if (stream.first()) |c| {
        negative = c == '-';
        if (c == '-' or c == '+') {
            stream.advance(1);
        }
    }
    if (stream.firstIsDigit(10)) {
        while (stream.scanDigit(10)) |digit| {
            // no overflows here, saturate well before overflow
            if (exponent < 0x1000_0000) {
                exponent = 10 * exponent + digit;
            }
        }

        return if (negative) -exponent else exponent;
    }

    return null;
}

const ParseInfo = struct {
    // 10 or 16
    base: u8,
    // 10^19 fits in u64, 16^16 fits in u64
    max_mantissa_digits: usize,
    // e.g. e or p (E and P also checked)
    exp_char_lower: u8,
};

fn parsePartialNumberBase(comptime T: type, stream: *FloatStream, negative: bool, n: *usize, comptime info: ParseInfo) ?Number(T) {
    std.debug.assert(info.base == 10 or info.base == 16);
    const MantissaT = common.mantissaType(T);

    // parse initial digits before dot
    var mantissa: MantissaT = 0;
    tryParseDigits(MantissaT, stream, &mantissa, info.base);
    const int_end = stream.offsetTrue();
    var n_digits = @as(isize, @intCast(stream.offsetTrue()));

    // handle dot with the following digits
    var exponent: i64 = 0;
    if (stream.firstIs(".")) {
        stream.advance(1);
        const marker = stream.offsetTrue();
        tryParseDigits(MantissaT, stream, &mantissa, info.base);
        const n_after_dot = stream.offsetTrue() - marker;
        exponent = -@as(i64, @intCast(n_after_dot));
        n_digits += @as(isize, @intCast(n_after_dot));
    }

    // adjust required shift to offset mantissa for base-16 (2^4)
    if (info.base == 16) {
        exponent *= 4;
    }

    if (n_digits == 0) {
        return null;
    }

    // handle scientific format
    var exp_number: i64 = 0;
    if (stream.firstIsLower(&.{info.exp_char_lower})) {
        stream.advance(1);
        exp_number = parseScientific(stream) orelse return null;
        exponent += exp_number;
    }

    const len = stream.offset; // length must be complete parsed length
    n.* += len;

    if (stream.underscore_count > 0 and !validUnderscores(stream.slice, info.base)) {
        return null;
    }

    // common case with not many digits
    if (n_digits <= info.max_mantissa_digits) {
        return Number(T){
            .exponent = exponent,
            .mantissa = mantissa,
            .negative = negative,
            .many_digits = false,
            .hex = info.base == 16,
        };
    }

    n_digits -= info.max_mantissa_digits;
    var many_digits = false;
    stream.reset(); // re-parse from beginning
    while (stream.firstIs("0._")) {
        // '0' = '.' + 2
        const next = stream.firstUnchecked();
        if (next != '_') {
            n_digits -= @as(isize, @intCast(next -| ('0' - 1)));
        } else {
            stream.underscore_count += 1;
        }
        stream.advance(1);
    }
    if (n_digits > 0) {
        // at this point we have more than max_mantissa_digits significant digits, let's try again
        many_digits = true;
        mantissa = 0;
        stream.reset();
        tryParseNDigits(MantissaT, stream, &mantissa, info.base, info.max_mantissa_digits);

        exponent = blk: {
            if (mantissa >= min_n_digit_int(MantissaT, info.max_mantissa_digits)) {
                // big int
                break :blk @as(i64, @intCast(int_end)) - @as(i64, @intCast(stream.offsetTrue()));
            } else {
                // the next byte must be present and be '.'
                // We know this is true because we had more than 19
                // digits previously, so we overflowed a 64-bit integer,
                // but parsing only the integral digits produced less
                // than 19 digits. That means we must have a decimal
                // point, and at least 1 fractional digit.
                stream.advance(1);
                const marker = stream.offsetTrue();
                tryParseNDigits(MantissaT, stream, &mantissa, info.base, info.max_mantissa_digits);
                break :blk @as(i64, @intCast(marker)) - @as(i64, @intCast(stream.offsetTrue()));
            }
        };
        if (info.base == 16) {
            exponent *= 4;
        }
        // add back the explicit part
        exponent += exp_number;
    }

    return Number(T){
        .exponent = exponent,
        .mantissa = mantissa,
        .negative = negative,
        .many_digits = many_digits,
        .hex = info.base == 16,
    };
}

/// Parse a partial, non-special floating point number.
///
/// This creates a representation of the float as the
/// significant digits and the decimal exponent.
fn parsePartialNumber(comptime T: type, s: []const u8, negative: bool, n: *usize) ?Number(T) {
    std.debug.assert(s.len != 0);
    const MantissaT = common.mantissaType(T);
    n.* = 0;

    if (s.len >= 2 and s[0] == '0' and std.ascii.toLower(s[1]) == 'x') {
        var stream = FloatStream.init(s[2..]);
        n.* += 2;
        return parsePartialNumberBase(T, &stream, negative, n, .{
            .base = 16,
            .max_mantissa_digits = if (MantissaT == u64) 16 else 32,
            .exp_char_lower = 'p',
        });
    } else {
        var stream = FloatStream.init(s);
        return parsePartialNumberBase(T, &stream, negative, n, .{
            .base = 10,
            .max_mantissa_digits = if (MantissaT == u64) 19 else 38,
            .exp_char_lower = 'e',
        });
    }
}

pub fn parseNumber(comptime T: type, s: []const u8, negative: bool) ?Number(T) {
    var consumed: usize = 0;
    if (parsePartialNumber(T, s, negative, &consumed)) |number| {
        // must consume entire float (no trailing data)
        if (s.len == consumed) {
            return number;
        }
    }
    return null;
}

fn parsePartialInfOrNan(comptime T: type, s: []const u8, negative: bool, n: *usize) ?T {
    // inf/infinity; infxxx should only consume inf.
    if (std.ascii.startsWithIgnoreCase(s, "inf")) {
        n.* = 3;
        if (std.ascii.startsWithIgnoreCase(s[3..], "inity")) {
            n.* = 8;
        }

        return if (!negative) std.math.inf(T) else -std.math.inf(T);
    }

    if (std.ascii.startsWithIgnoreCase(s, "nan")) {
        n.* = 3;
        return std.math.nan(T);
    }

    return null;
}

pub fn parseInfOrNan(comptime T: type, s: []const u8, negative: bool) ?T {
    var consumed: usize = 0;
    if (parsePartialInfOrNan(T, s, negative, &consumed)) |special| {
        if (s.len == consumed) {
            return special;
        }
    }
    return null;
}

pub fn validUnderscores(s: []const u8, comptime base: u8) bool {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '_') {
            // underscore at start of end
            if (i == 0 or i + 1 == s.len) {
                return false;
            }
            // consecutive underscores
            if (!common.isDigit(s[i - 1], base) or !common.isDigit(s[i + 1], base)) {
                return false;
            }

            // next is guaranteed a digit, skip an extra
            i += 1;
        }
    }

    return true;
}
//! File System.

const std = @import("std.zig");
const builtin = @import("builtin");
const root = @import("root");
const mem = std.mem;
const base64 = std.base64;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const native_os = builtin.os.tag;
const posix = std.posix;
const windows = std.os.windows;

const is_darwin = native_os.isDarwin();

pub const AtomicFile = @import("fs/AtomicFile.zig");
pub const Dir = @import("fs/Dir.zig");
pub const File = @import("fs/File.zig");
pub const path = @import("fs/path.zig");

pub const has_executable_bit = switch (native_os) {
    .windows, .wasi => false,
    else => true,
};

pub const wasi = @import("fs/wasi.zig");

// TODO audit these APIs with respect to Dir and absolute paths

pub const realpath = posix.realpath;
pub const realpathZ = posix.realpathZ;
pub const realpathW = posix.realpathW;

pub const getAppDataDir = @import("fs/get_app_data_dir.zig").getAppDataDir;
pub const GetAppDataDirError = @import("fs/get_app_data_dir.zig").GetAppDataDirError;

pub const MAX_PATH_BYTES = @compileError("deprecated; renamed to max_path_bytes");

/// The maximum length of a file path that the operating system will accept.
///
/// Paths, including those returned from file system operations, may be longer
/// than this length, but such paths cannot be successfully passed back in
/// other file system operations. However, all path components returned by file
/// system operations are assumed to fit into a `u8` array of this length.
///
/// The byte count includes room for a null sentinel byte.
///
/// * On Windows, `[]u8` file paths are encoded as
///   [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On WASI, `[]u8` file paths are encoded as valid UTF-8.
/// * On other platforms, `[]u8` file paths are opaque sequences of bytes with
///   no particular encoding.
pub const max_path_bytes = switch (native_os) {
    .linux, .macos, .ios, .freebsd, .openbsd, .netbsd, .dragonfly, .haiku, .solaris, .illumos, .plan9, .emscripten, .wasi, .serenity => posix.PATH_MAX,
    // Each WTF-16LE code unit may be expanded to 3 WTF-8 bytes.
    // If it would require 4 WTF-8 bytes, then there would be a surrogate
    // pair in the WTF-16LE, and we (over)account 3 bytes for it that way.
    // +1 for the null byte at the end, which can be encoded in 1 byte.
    .windows => windows.PATH_MAX_WIDE * 3 + 1,
    else => if (@hasDecl(root, "os") and @hasDecl(root.os, "PATH_MAX"))
        root.os.PATH_MAX
    else
        @compileError("PATH_MAX not implemented for " ++ @tagName(native_os)),
};

/// This represents the maximum size of a `[]u8` file name component that
/// the platform's common file systems support. File name components returned by file system
/// operations are likely to fit into a `u8` array of this length, but
/// (depending on the platform) this assumption may not hold for every configuration.
/// The byte count does not include a null sentinel byte.
/// On Windows, `[]u8` file name components are encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, file name components are encoded as valid UTF-8.
/// On other platforms, `[]u8` components are an opaque sequence of bytes with no particular encoding.
pub const max_name_bytes = switch (native_os) {
    .linux, .macos, .ios, .freebsd, .openbsd, .netbsd, .dragonfly, .solaris, .illumos, .serenity => posix.NAME_MAX,
    // Haiku's NAME_MAX includes the null terminator, so subtract one.
    .haiku => posix.NAME_MAX - 1,
    // Each WTF-16LE character may be expanded to 3 WTF-8 bytes.
    // If it would require 4 WTF-8 bytes, then there would be a surrogate
    // pair in the WTF-16LE, and we (over)account 3 bytes for it that way.
    .windows => windows.NAME_MAX * 3,
    // For WASI, the MAX_NAME will depend on the host OS, so it needs to be
    // as large as the largest max_name_bytes (Windows) in order to work on any host OS.
    // TODO determine if this is a reasonable approach
    .wasi => windows.NAME_MAX * 3,
    else => if (@hasDecl(root, "os") and @hasDecl(root.os, "NAME_MAX"))
        root.os.NAME_MAX
    else
        @compileError("NAME_MAX not implemented for " ++ @tagName(native_os)),
};

/// Deprecated: use `max_name_bytes`
pub const MAX_NAME_BYTES = max_name_bytes;

pub const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".*;

/// Base64 encoder, replacing the standard `+/` with `-_` so that it can be used in a file name on any filesystem.
pub const base64_encoder = base64.Base64Encoder.init(base64_alphabet, null);

/// Base64 decoder, replacing the standard `+/` with `-_` so that it can be used in a file name on any filesystem.
pub const base64_decoder = base64.Base64Decoder.init(base64_alphabet, null);

/// Deprecated. Use `cwd().atomicSymLink()` instead.
pub fn atomicSymLink(_: Allocator, existing_path: []const u8, new_path: []const u8) !void {
    try cwd().atomicSymLink(existing_path, new_path, .{});
}

/// Same as `Dir.updateFile`, except asserts that both `source_path` and `dest_path`
/// are absolute. See `Dir.updateFile` for a function that operates on both
/// absolute and relative paths.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn updateFileAbsolute(
    source_path: []const u8,
    dest_path: []const u8,
    args: Dir.CopyFileOptions,
) !Dir.PrevStatus {
    assert(path.isAbsolute(source_path));
    assert(path.isAbsolute(dest_path));
    const my_cwd = cwd();
    return Dir.updateFile(my_cwd, source_path, my_cwd, dest_path, args);
}

/// Same as `Dir.copyFile`, except asserts that both `source_path` and `dest_path`
/// are absolute. See `Dir.copyFile` for a function that operates on both
/// absolute and relative paths.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn copyFileAbsolute(
    source_path: []const u8,
    dest_path: []const u8,
    args: Dir.CopyFileOptions,
) !void {
    assert(path.isAbsolute(source_path));
    assert(path.isAbsolute(dest_path));
    const my_cwd = cwd();
    return Dir.copyFile(my_cwd, source_path, my_cwd, dest_path, args);
}

/// Create a new directory, based on an absolute path.
/// Asserts that the path is absolute. See `Dir.makeDir` for a function that operates
/// on both absolute and relative paths.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn makeDirAbsolute(absolute_path: []const u8) !void {
    assert(path.isAbsolute(absolute_path));
    return posix.mkdir(absolute_path, Dir.default_mode);
}

/// Same as `makeDirAbsolute` except the parameter is null-terminated.
pub fn makeDirAbsoluteZ(absolute_path_z: [*:0]const u8) !void {
    assert(path.isAbsoluteZ(absolute_path_z));
    return posix.mkdirZ(absolute_path_z, Dir.default_mode);
}

/// Same as `makeDirAbsolute` except the parameter is a null-terminated WTF-16 LE-encoded string.
pub fn makeDirAbsoluteW(absolute_path_w: [*:0]const u16) !void {
    assert(path.isAbsoluteWindowsW(absolute_path_w));
    return posix.mkdirW(mem.span(absolute_path_w), Dir.default_mode);
}

/// Same as `Dir.deleteDir` except the path is absolute.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteDirAbsolute(dir_path: []const u8) !void {
    assert(path.isAbsolute(dir_path));
    return posix.rmdir(dir_path);
}

/// Same as `deleteDirAbsolute` except the path parameter is null-terminated.
pub fn deleteDirAbsoluteZ(dir_path: [*:0]const u8) !void {
    assert(path.isAbsoluteZ(dir_path));
    return posix.rmdirZ(dir_path);
}

/// Same as `deleteDirAbsolute` except the path parameter is WTF-16 and target OS is assumed Windows.
pub fn deleteDirAbsoluteW(dir_path: [*:0]const u16) !void {
    assert(path.isAbsoluteWindowsW(dir_path));
    return posix.rmdirW(mem.span(dir_path));
}

/// Same as `Dir.rename` except the paths are absolute.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn renameAbsolute(old_path: []const u8, new_path: []const u8) !void {
    assert(path.isAbsolute(old_path));
    assert(path.isAbsolute(new_path));
    return posix.rename(old_path, new_path);
}

/// Same as `renameAbsolute` except the path parameters are null-terminated.
pub fn renameAbsoluteZ(old_path: [*:0]const u8, new_path: [*:0]const u8) !void {
    assert(path.isAbsoluteZ(old_path));
    assert(path.isAbsoluteZ(new_path));
    return posix.renameZ(old_path, new_path);
}

/// Same as `renameAbsolute` except the path parameters are WTF-16 and target OS is assumed Windows.
pub fn renameAbsoluteW(old_path: [*:0]const u16, new_path: [*:0]const u16) !void {
    assert(path.isAbsoluteWindowsW(old_path));
    assert(path.isAbsoluteWindowsW(new_path));
    return posix.renameW(old_path, new_path);
}

/// Same as `Dir.rename`, except `new_sub_path` is relative to `new_dir`
pub fn rename(old_dir: Dir, old_sub_path: []const u8, new_dir: Dir, new_sub_path: []const u8) !void {
    return posix.renameat(old_dir.fd, old_sub_path, new_dir.fd, new_sub_path);
}

/// Same as `rename` except the parameters are null-terminated.
pub fn renameZ(old_dir: Dir, old_sub_path_z: [*:0]const u8, new_dir: Dir, new_sub_path_z: [*:0]const u8) !void {
    return posix.renameatZ(old_dir.fd, old_sub_path_z, new_dir.fd, new_sub_path_z);
}

/// Same as `rename` except the parameters are WTF16LE, NT prefixed.
/// This function is Windows-only.
pub fn renameW(old_dir: Dir, old_sub_path_w: []const u16, new_dir: Dir, new_sub_path_w: []const u16) !void {
    return posix.renameatW(old_dir.fd, old_sub_path_w, new_dir.fd, new_sub_path_w, windows.TRUE);
}

/// Returns a handle to the current working directory. It is not opened with iteration capability.
/// Closing the returned `Dir` is checked illegal behavior. Iterating over the result is illegal behavior.
/// On POSIX targets, this function is comptime-callable.
pub fn cwd() Dir {
    if (native_os == .windows) {
        return .{ .fd = windows.peb().ProcessParameters.CurrentDirectory.Handle };
    } else if (native_os == .wasi) {
        return .{ .fd = std.options.wasiCwd() };
    } else {
        return .{ .fd = posix.AT.FDCWD };
    }
}

pub fn defaultWasiCwd() std.os.wasi.fd_t {
    // Expect the first preopen to be current working directory.
    return 3;
}

/// Opens a directory at the given path. The directory is a system resource that remains
/// open until `close` is called on the result.
/// See `openDirAbsoluteZ` for a function that accepts a null-terminated path.
///
/// Asserts that the path parameter has no null bytes.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn openDirAbsolute(absolute_path: []const u8, flags: Dir.OpenOptions) File.OpenError!Dir {
    assert(path.isAbsolute(absolute_path));
    return cwd().openDir(absolute_path, flags);
}

/// Same as `openDirAbsolute` but the path parameter is null-terminated.
pub fn openDirAbsoluteZ(absolute_path_c: [*:0]const u8, flags: Dir.OpenOptions) File.OpenError!Dir {
    assert(path.isAbsoluteZ(absolute_path_c));
    return cwd().openDirZ(absolute_path_c, flags);
}
/// Same as `openDirAbsolute` but the path parameter is null-terminated.
pub fn openDirAbsoluteW(absolute_path_c: [*:0]const u16, flags: Dir.OpenOptions) File.OpenError!Dir {
    assert(path.isAbsoluteWindowsW(absolute_path_c));
    return cwd().openDirW(absolute_path_c, flags);
}

/// Opens a file for reading or writing, without attempting to create a new file, based on an absolute path.
/// Call `File.close` to release the resource.
/// Asserts that the path is absolute. See `Dir.openFile` for a function that
/// operates on both absolute and relative paths.
/// Asserts that the path parameter has no null bytes. See `openFileAbsoluteZ` for a function
/// that accepts a null-terminated path.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn openFileAbsolute(absolute_path: []const u8, flags: File.OpenFlags) File.OpenError!File {
    assert(path.isAbsolute(absolute_path));
    return cwd().openFile(absolute_path, flags);
}

/// Same as `openFileAbsolute` but the path parameter is null-terminated.
pub fn openFileAbsoluteZ(absolute_path_c: [*:0]const u8, flags: File.OpenFlags) File.OpenError!File {
    assert(path.isAbsoluteZ(absolute_path_c));
    return cwd().openFileZ(absolute_path_c, flags);
}

/// Same as `openFileAbsolute` but the path parameter is WTF-16-encoded.
pub fn openFileAbsoluteW(absolute_path_w: []const u16, flags: File.OpenFlags) File.OpenError!File {
    assert(path.isAbsoluteWindowsWTF16(absolute_path_w));
    return cwd().openFileW(absolute_path_w, flags);
}

/// Test accessing `path`.
/// Be careful of Time-Of-Check-Time-Of-Use race conditions when using this function.
/// For example, instead of testing if a file exists and then opening it, just
/// open it and handle the error for file not found.
/// See `accessAbsoluteZ` for a function that accepts a null-terminated path.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn accessAbsolute(absolute_path: []const u8, flags: File.OpenFlags) Dir.AccessError!void {
    assert(path.isAbsolute(absolute_path));
    try cwd().access(absolute_path, flags);
}
/// Same as `accessAbsolute` but the path parameter is null-terminated.
pub fn accessAbsoluteZ(absolute_path: [*:0]const u8, flags: File.OpenFlags) Dir.AccessError!void {
    assert(path.isAbsoluteZ(absolute_path));
    try cwd().accessZ(absolute_path, flags);
}
/// Same as `accessAbsolute` but the path parameter is WTF-16 encoded.
pub fn accessAbsoluteW(absolute_path: [*:0]const u16, flags: File.OpenFlags) Dir.AccessError!void {
    assert(path.isAbsoluteWindowsW(absolute_path));
    try cwd().accessW(absolute_path, flags);
}

/// Creates, opens, or overwrites a file with write access, based on an absolute path.
/// Call `File.close` to release the resource.
/// Asserts that the path is absolute. See `Dir.createFile` for a function that
/// operates on both absolute and relative paths.
/// Asserts that the path parameter has no null bytes. See `createFileAbsoluteC` for a function
/// that accepts a null-terminated path.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn createFileAbsolute(absolute_path: []const u8, flags: File.CreateFlags) File.OpenError!File {
    assert(path.isAbsolute(absolute_path));
    return cwd().createFile(absolute_path, flags);
}

/// Same as `createFileAbsolute` but the path parameter is null-terminated.
pub fn createFileAbsoluteZ(absolute_path_c: [*:0]const u8, flags: File.CreateFlags) File.OpenError!File {
    assert(path.isAbsoluteZ(absolute_path_c));
    return cwd().createFileZ(absolute_path_c, flags);
}

/// Same as `createFileAbsolute` but the path parameter is WTF-16 encoded.
pub fn createFileAbsoluteW(absolute_path_w: [*:0]const u16, flags: File.CreateFlags) File.OpenError!File {
    assert(path.isAbsoluteWindowsW(absolute_path_w));
    return cwd().createFileW(mem.span(absolute_path_w), flags);
}

/// Delete a file name and possibly the file it refers to, based on an absolute path.
/// Asserts that the path is absolute. See `Dir.deleteFile` for a function that
/// operates on both absolute and relative paths.
/// Asserts that the path parameter has no null bytes.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteFileAbsolute(absolute_path: []const u8) Dir.DeleteFileError!void {
    assert(path.isAbsolute(absolute_path));
    return cwd().deleteFile(absolute_path);
}

/// Same as `deleteFileAbsolute` except the parameter is null-terminated.
pub fn deleteFileAbsoluteZ(absolute_path_c: [*:0]const u8) Dir.DeleteFileError!void {
    assert(path.isAbsoluteZ(absolute_path_c));
    return cwd().deleteFileZ(absolute_path_c);
}

/// Same as `deleteFileAbsolute` except the parameter is WTF-16 encoded.
pub fn deleteFileAbsoluteW(absolute_path_w: [*:0]const u16) Dir.DeleteFileError!void {
    assert(path.isAbsoluteWindowsW(absolute_path_w));
    return cwd().deleteFileW(mem.span(absolute_path_w));
}

/// Removes a symlink, file, or directory.
/// This is equivalent to `Dir.deleteTree` with the base directory.
/// Asserts that the path is absolute. See `Dir.deleteTree` for a function that
/// operates on both absolute and relative paths.
/// Asserts that the path parameter has no null bytes.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteTreeAbsolute(absolute_path: []const u8) !void {
    assert(path.isAbsolute(absolute_path));
    const dirname = path.dirname(absolute_path) orelse return error{
        /// Attempt to remove the root file system path.
        /// This error is unreachable if `absolute_path` is relative.
        CannotDeleteRootDirectory,
    }.CannotDeleteRootDirectory;

    var dir = try cwd().openDir(dirname, .{});
    defer dir.close();

    return dir.deleteTree(path.basename(absolute_path));
}

/// Same as `Dir.readLink`, except it asserts the path is absolute.
/// On Windows, `pathname` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `pathname` should be encoded as valid UTF-8.
/// On other platforms, `pathname` is an opaque sequence of bytes with no particular encoding.
pub fn readLinkAbsolute(pathname: []const u8, buffer: *[max_path_bytes]u8) ![]u8 {
    assert(path.isAbsolute(pathname));
    return posix.readlink(pathname, buffer);
}

/// Windows-only. Same as `readlinkW`, except the path parameter is null-terminated, WTF16
/// encoded.
pub fn readlinkAbsoluteW(pathname_w: [*:0]const u16, buffer: *[max_path_bytes]u8) ![]u8 {
    assert(path.isAbsoluteWindowsW(pathname_w));
    return posix.readlinkW(mem.span(pathname_w), buffer);
}

/// Same as `readLink`, except the path parameter is null-terminated.
pub fn readLinkAbsoluteZ(pathname_c: [*:0]const u8, buffer: *[max_path_bytes]u8) ![]u8 {
    assert(path.isAbsoluteZ(pathname_c));
    return posix.readlinkZ(pathname_c, buffer);
}

/// Creates a symbolic link named `sym_link_path` which contains the string `target_path`.
/// A symbolic link (also known as a soft link) may point to an existing file or to a nonexistent
/// one; the latter case is known as a dangling link.
/// If `sym_link_path` exists, it will not be overwritten.
/// See also `symLinkAbsoluteZ` and `symLinkAbsoluteW`.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn symLinkAbsolute(
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: Dir.SymLinkFlags,
) !void {
    assert(path.isAbsolute(target_path));
    assert(path.isAbsolute(sym_link_path));
    if (native_os == .windows) {
        const target_path_w = try windows.sliceToPrefixedFileW(null, target_path);
        const sym_link_path_w = try windows.sliceToPrefixedFileW(null, sym_link_path);
        return windows.CreateSymbolicLink(null, sym_link_path_w.span(), target_path_w.span(), flags.is_directory);
    }
    return posix.symlink(target_path, sym_link_path);
}

/// Windows-only. Same as `symLinkAbsolute` except the parameters are null-terminated, WTF16 LE encoded.
/// Note that this function will by default try creating a symbolic link to a file. If you would
/// like to create a symbolic link to a directory, specify this with `SymLinkFlags{ .is_directory = true }`.
/// See also `symLinkAbsolute`, `symLinkAbsoluteZ`.
pub fn symLinkAbsoluteW(
    target_path_w: [*:0]const u16,
    sym_link_path_w: [*:0]const u16,
    flags: Dir.SymLinkFlags,
) !void {
    assert(path.isAbsoluteWindowsW(target_path_w));
    assert(path.isAbsoluteWindowsW(sym_link_path_w));
    return windows.CreateSymbolicLink(null, mem.span(sym_link_path_w), mem.span(target_path_w), flags.is_directory);
}

/// Same as `symLinkAbsolute` except the parameters are null-terminated pointers.
/// See also `symLinkAbsolute`.
pub fn symLinkAbsoluteZ(
    target_path_c: [*:0]const u8,
    sym_link_path_c: [*:0]const u8,
    flags: Dir.SymLinkFlags,
) !void {
    assert(path.isAbsoluteZ(target_path_c));
    assert(path.isAbsoluteZ(sym_link_path_c));
    if (native_os == .windows) {
        const target_path_w = try windows.cStrToPrefixedFileW(null, target_path_c);
        const sym_link_path_w = try windows.cStrToPrefixedFileW(null, sym_link_path_c);
        return windows.CreateSymbolicLink(null, sym_link_path_w.span(), target_path_w.span(), flags.is_directory);
    }
    return posix.symlinkZ(target_path_c, sym_link_path_c);
}

pub const OpenSelfExeError = posix.OpenError || SelfExePathError || posix.FlockError;

pub fn openSelfExe(flags: File.OpenFlags) OpenSelfExeError!File {
    if (native_os == .linux or native_os == .serenity) {
        return openFileAbsoluteZ("/proc/self/exe", flags);
    }
    if (native_os == .windows) {
        // If ImagePathName is a symlink, then it will contain the path of the symlink,
        // not the path that the symlink points to. However, because we are opening
        // the file, we can let the openFileW call follow the symlink for us.
        const image_path_unicode_string = &windows.peb().ProcessParameters.ImagePathName;
        const image_path_name = image_path_unicode_string.Buffer.?[0 .. image_path_unicode_string.Length / 2 :0];
        const prefixed_path_w = try windows.wToPrefixedFileW(null, image_path_name);
        return cwd().openFileW(prefixed_path_w.span(), flags);
    }
    // Use of max_path_bytes here is valid as the resulting path is immediately
    // opened with no modification.
    var buf: [max_path_bytes]u8 = undefined;
    const self_exe_path = try selfExePath(&buf);
    buf[self_exe_path.len] = 0;
    return openFileAbsoluteZ(buf[0..self_exe_path.len :0].ptr, flags);
}

// This is `posix.ReadLinkError || posix.RealPathError` with impossible errors excluded
pub const SelfExePathError = error{
    FileNotFound,
    AccessDenied,
    NameTooLong,
    NotSupported,
    NotDir,
    SymLinkLoop,
    InputOutput,
    FileTooBig,
    IsDir,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    NoDevice,
    SystemResources,
    NoSpaceLeft,
    FileSystem,
    BadPathName,
    DeviceBusy,
    SharingViolation,
    PipeBusy,
    NotLink,
    PathAlreadyExists,

    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    ProcessNotFound,

    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,

    /// On Windows, the volume does not contain a recognized file system. File
    /// system drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
} || posix.SysCtlError;

/// `selfExePath` except allocates the result on the heap.
/// Caller owns returned memory.
pub fn selfExePathAlloc(allocator: Allocator) ![]u8 {
    // Use of max_path_bytes here is justified as, at least on one tested Linux
    // system, readlink will completely fail to return a result larger than
    // PATH_MAX even if given a sufficiently large buffer. This makes it
    // fundamentally impossible to get the selfExePath of a program running in
    // a very deeply nested directory chain in this way.
    // TODO(#4812): Investigate other systems and whether it is possible to get
    // this path by trying larger and larger buffers until one succeeds.
    var buf: [max_path_bytes]u8 = undefined;
    return allocator.dupe(u8, try selfExePath(&buf));
}

/// Get the path to the current executable. Follows symlinks.
/// If you only need the directory, use selfExeDirPath.
/// If you only want an open file handle, use openSelfExe.
/// This function may return an error if the current executable
/// was deleted after spawning.
/// Returned value is a slice of out_buffer.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
///
/// On Linux, depends on procfs being mounted. If the currently executing binary has
/// been deleted, the file path looks something like `/a/b/c/exe (deleted)`.
/// TODO make the return type of this a null terminated pointer
pub fn selfExePath(out_buffer: []u8) SelfExePathError![]u8 {
    if (is_darwin) {
        // Note that _NSGetExecutablePath() will return "a path" to
        // the executable not a "real path" to the executable.
        var symlink_path_buf: [max_path_bytes:0]u8 = undefined;
        var u32_len: u32 = max_path_bytes + 1; // include the sentinel
        const rc = std.c._NSGetExecutablePath(&symlink_path_buf, &u32_len);
        if (rc != 0) return error.NameTooLong;

        var real_path_buf: [max_path_bytes]u8 = undefined;
        const real_path = std.posix.realpathZ(&symlink_path_buf, &real_path_buf) catch |err| switch (err) {
            error.InvalidWtf8 => unreachable, // Windows-only
            error.NetworkNotFound => unreachable, // Windows-only
            else => |e| return e,
        };
        if (real_path.len > out_buffer.len) return error.NameTooLong;
        const result = out_buffer[0..real_path.len];
        @memcpy(result, real_path);
        return result;
    }
    switch (native_os) {
        .linux, .serenity => return posix.readlinkZ("/proc/self/exe", out_buffer) catch |err| switch (err) {
            error.InvalidUtf8 => unreachable, // WASI-only
            error.InvalidWtf8 => unreachable, // Windows-only
            error.UnsupportedReparsePointType => unreachable, // Windows-only
            error.NetworkNotFound => unreachable, // Windows-only
            else => |e| return e,
        },
        .solaris, .illumos => return posix.readlinkZ("/proc/self/path/a.out", out_buffer) catch |err| switch (err) {
            error.InvalidUtf8 => unreachable, // WASI-only
            error.InvalidWtf8 => unreachable, // Windows-only
            error.UnsupportedReparsePointType => unreachable, // Windows-only
            error.NetworkNotFound => unreachable, // Windows-only
            else => |e| return e,
        },
        .freebsd, .dragonfly => {
            var mib = [4]c_int{ posix.CTL.KERN, posix.KERN.PROC, posix.KERN.PROC_PATHNAME, -1 };
            var out_len: usize = out_buffer.len;
            try posix.sysctl(&mib, out_buffer.ptr, &out_len, null, 0);
            // TODO could this slice from 0 to out_len instead?
            return mem.sliceTo(out_buffer, 0);
        },
        .netbsd => {
            var mib = [4]c_int{ posix.CTL.KERN, posix.KERN.PROC_ARGS, -1, posix.KERN.PROC_PATHNAME };
            var out_len: usize = out_buffer.len;
            try posix.sysctl(&mib, out_buffer.ptr, &out_len, null, 0);
            // TODO could this slice from 0 to out_len instead?
            return mem.sliceTo(out_buffer, 0);
        },
        .openbsd, .haiku => {
            // OpenBSD doesn't support getting the path of a running process, so try to guess it
            if (std.os.argv.len == 0)
                return error.FileNotFound;

            const argv0 = mem.span(std.os.argv[0]);
            if (mem.indexOf(u8, argv0, "/") != null) {
                // argv[0] is a path (relative or absolute): use realpath(3) directly
                var real_path_buf: [max_path_bytes]u8 = undefined;
                const real_path = posix.realpathZ(std.os.argv[0], &real_path_buf) catch |err| switch (err) {
                    error.InvalidWtf8 => unreachable, // Windows-only
                    error.NetworkNotFound => unreachable, // Windows-only
                    else => |e| return e,
                };
                if (real_path.len > out_buffer.len)
                    return error.NameTooLong;
                const result = out_buffer[0..real_path.len];
                @memcpy(result, real_path);
                return result;
            } else if (argv0.len != 0) {
                // argv[0] is not empty (and not a path): search it inside PATH
                const PATH = posix.getenvZ("PATH") orelse return error.FileNotFound;
                var path_it = mem.tokenizeScalar(u8, PATH, path.delimiter);
                while (path_it.next()) |a_path| {
                    var resolved_path_buf: [max_path_bytes - 1:0]u8 = undefined;
                    const resolved_path = std.fmt.bufPrintZ(&resolved_path_buf, "{s}/{s}", .{
                        a_path,
                        std.os.argv[0],
                    }) catch continue;

                    var real_path_buf: [max_path_bytes]u8 = undefined;
                    if (posix.realpathZ(resolved_path, &real_path_buf)) |real_path| {
                        // found a file, and hope it is the right file
                        if (real_path.len > out_buffer.len)
                            return error.NameTooLong;
                        const result = out_buffer[0..real_path.len];
                        @memcpy(result, real_path);
                        return result;
                    } else |_| continue;
                }
            }
            return error.FileNotFound;
        },
        .windows => {
            const image_path_unicode_string = &windows.peb().ProcessParameters.ImagePathName;
            const image_path_name = image_path_unicode_string.Buffer.?[0 .. image_path_unicode_string.Length / 2 :0];

            // If ImagePathName is a symlink, then it will contain the path of the
            // symlink, not the path that the symlink points to. We want the path
            // that the symlink points to, though, so we need to get the realpath.
            const pathname_w = try windows.wToPrefixedFileW(null, image_path_name);
            return std.fs.cwd().realpathW(pathname_w.span(), out_buffer) catch |err| switch (err) {
                error.InvalidWtf8 => unreachable,
                else => |e| return e,
            };
        },
        else => @compileError("std.fs.selfExePath not supported for this target"),
    }
}

/// `selfExeDirPath` except allocates the result on the heap.
/// Caller owns returned memory.
pub fn selfExeDirPathAlloc(allocator: Allocator) ![]u8 {
    // Use of max_path_bytes here is justified as, at least on one tested Linux
    // system, readlink will completely fail to return a result larger than
    // PATH_MAX even if given a sufficiently large buffer. This makes it
    // fundamentally impossible to get the selfExeDirPath of a program running
    // in a very deeply nested directory chain in this way.
    // TODO(#4812): Investigate other systems and whether it is possible to get
    // this path by trying larger and larger buffers until one succeeds.
    var buf: [max_path_bytes]u8 = undefined;
    return allocator.dupe(u8, try selfExeDirPath(&buf));
}

/// Get the directory path that contains the current executable.
/// Returned value is a slice of out_buffer.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn selfExeDirPath(out_buffer: []u8) SelfExePathError![]const u8 {
    const self_exe_path = try selfExePath(out_buffer);
    // Assume that the OS APIs return absolute paths, and therefore dirname
    // will not return null.
    return path.dirname(self_exe_path).?;
}

/// `realpath`, except caller must free the returned memory.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
/// See also `Dir.realpath`.
pub fn realpathAlloc(allocator: Allocator, pathname: []const u8) ![]u8 {
    // Use of max_path_bytes here is valid as the realpath function does not
    // have a variant that takes an arbitrary-size buffer.
    // TODO(#4812): Consider reimplementing realpath or using the POSIX.1-2008
    // NULL out parameter (GNU's canonicalize_file_name) to handle overelong
    // paths. musl supports passing NULL but restricts the output to PATH_MAX
    // anyway.
    var buf: [max_path_bytes]u8 = undefined;
    return allocator.dupe(u8, try posix.realpath(pathname, &buf));
}

test {
    if (native_os != .wasi) {
        _ = &makeDirAbsolute;
        _ = &makeDirAbsoluteZ;
        _ = &copyFileAbsolute;
        _ = &updateFileAbsolute;
    }
    _ = &AtomicFile;
    _ = &Dir;
    _ = &File;
    _ = &path;
    _ = @import("fs/test.zig");
    _ = @import("fs/get_app_data_dir.zig");
}
file: File,
// TODO either replace this with rand_buf or use []u16 on Windows
tmp_path_buf: [tmp_path_len:0]u8,
dest_basename: []const u8,
file_open: bool,
file_exists: bool,
close_dir_on_deinit: bool,
dir: Dir,

pub const InitError = File.OpenError;

pub const random_bytes_len = 12;
const tmp_path_len = fs.base64_encoder.calcSize(random_bytes_len);

/// Note that the `Dir.atomicFile` API may be more handy than this lower-level function.
pub fn init(
    dest_basename: []const u8,
    mode: File.Mode,
    dir: Dir,
    close_dir_on_deinit: bool,
) InitError!AtomicFile {
    var rand_buf: [random_bytes_len]u8 = undefined;
    var tmp_path_buf: [tmp_path_len:0]u8 = undefined;

    while (true) {
        std.crypto.random.bytes(rand_buf[0..]);
        const tmp_path = fs.base64_encoder.encode(&tmp_path_buf, &rand_buf);
        tmp_path_buf[tmp_path.len] = 0;

        const file = dir.createFile(
            tmp_path,
            .{ .mode = mode, .exclusive = true },
        ) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => |e| return e,
        };

        return AtomicFile{
            .file = file,
            .tmp_path_buf = tmp_path_buf,
            .dest_basename = dest_basename,
            .file_open = true,
            .file_exists = true,
            .close_dir_on_deinit = close_dir_on_deinit,
            .dir = dir,
        };
    }
}

/// Always call deinit, even after a successful finish().
pub fn deinit(self: *AtomicFile) void {
    if (self.file_open) {
        self.file.close();
        self.file_open = false;
    }
    if (self.file_exists) {
        self.dir.deleteFile(&self.tmp_path_buf) catch {};
        self.file_exists = false;
    }
    if (self.close_dir_on_deinit) {
        self.dir.close();
    }
    self.* = undefined;
}

pub const FinishError = posix.RenameError;

/// On Windows, this function introduces a period of time where some file
/// system operations on the destination file will result in
/// `error.AccessDenied`, including rename operations (such as the one used in
/// this function).
pub fn finish(self: *AtomicFile) FinishError!void {
    assert(self.file_exists);
    if (self.file_open) {
        self.file.close();
        self.file_open = false;
    }
    try posix.renameat(self.dir.fd, self.tmp_path_buf[0..], self.dir.fd, self.dest_basename);
    self.file_exists = false;
}

const AtomicFile = @This();
const std = @import("../std.zig");
const File = std.fs.File;
const Dir = std.fs.Dir;
const fs = std.fs;
const assert = std.debug.assert;
const posix = std.posix;
fd: Handle,

pub const Handle = posix.fd_t;

pub const default_mode = 0o755;

pub const Entry = struct {
    name: []const u8,
    kind: Kind,

    pub const Kind = File.Kind;
};

const IteratorError = error{
    AccessDenied,
    SystemResources,
    /// WASI-only. The path of an entry could not be encoded as valid UTF-8.
    /// WASI is unable to handle paths that cannot be encoded as well-formed UTF-8.
    /// https://github.com/WebAssembly/wasi-filesystem/issues/17#issuecomment-1430639353
    InvalidUtf8,
} || posix.UnexpectedError;

pub const Iterator = switch (native_os) {
    .macos, .ios, .freebsd, .netbsd, .dragonfly, .openbsd, .solaris, .illumos => struct {
        dir: Dir,
        seek: i64,
        buf: [1024]u8, // TODO align(@alignOf(posix.system.dirent)),
        index: usize,
        end_index: usize,
        first_iter: bool,

        const Self = @This();

        pub const Error = IteratorError;

        /// Memory such as file names referenced in this returned entry becomes invalid
        /// with subsequent calls to `next`, as well as when this `Dir` is deinitialized.
        pub fn next(self: *Self) Error!?Entry {
            switch (native_os) {
                .macos, .ios => return self.nextDarwin(),
                .freebsd, .netbsd, .dragonfly, .openbsd => return self.nextBsd(),
                .solaris, .illumos => return self.nextSolaris(),
                else => @compileError("unimplemented"),
            }
        }

        fn nextDarwin(self: *Self) !?Entry {
            start_over: while (true) {
                if (self.index >= self.end_index) {
                    if (self.first_iter) {
                        posix.lseek_SET(self.dir.fd, 0) catch unreachable; // EBADF here likely means that the Dir was not opened with iteration permissions
                        self.first_iter = false;
                    }
                    const rc = posix.system.getdirentries(
                        self.dir.fd,
                        &self.buf,
                        self.buf.len,
                        &self.seek,
                    );
                    if (rc == 0) return null;
                    if (rc < 0) {
                        switch (posix.errno(rc)) {
                            .BADF => unreachable, // Dir is invalid or was opened without iteration ability
                            .FAULT => unreachable,
                            .NOTDIR => unreachable,
                            .INVAL => unreachable,
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    }
                    self.index = 0;
                    self.end_index = @as(usize, @intCast(rc));
                }
                const darwin_entry = @as(*align(1) posix.system.dirent, @ptrCast(&self.buf[self.index]));
                const next_index = self.index + darwin_entry.reclen;
                self.index = next_index;

                const name = @as([*]u8, @ptrCast(&darwin_entry.name))[0..darwin_entry.namlen];

                if (mem.eql(u8, name, ".") or mem.eql(u8, name, "..") or (darwin_entry.ino == 0)) {
                    continue :start_over;
                }

                const entry_kind: Entry.Kind = switch (darwin_entry.type) {
                    posix.DT.BLK => .block_device,
                    posix.DT.CHR => .character_device,
                    posix.DT.DIR => .directory,
                    posix.DT.FIFO => .named_pipe,
                    posix.DT.LNK => .sym_link,
                    posix.DT.REG => .file,
                    posix.DT.SOCK => .unix_domain_socket,
                    posix.DT.WHT => .whiteout,
                    else => .unknown,
                };
                return Entry{
                    .name = name,
                    .kind = entry_kind,
                };
            }
        }

        fn nextSolaris(self: *Self) !?Entry {
            start_over: while (true) {
                if (self.index >= self.end_index) {
                    if (self.first_iter) {
                        posix.lseek_SET(self.dir.fd, 0) catch unreachable; // EBADF here likely means that the Dir was not opened with iteration permissions
                        self.first_iter = false;
                    }
                    const rc = posix.system.getdents(self.dir.fd, &self.buf, self.buf.len);
                    switch (posix.errno(rc)) {
                        .SUCCESS => {},
                        .BADF => unreachable, // Dir is invalid or was opened without iteration ability
                        .FAULT => unreachable,
                        .NOTDIR => unreachable,
                        .INVAL => unreachable,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                    if (rc == 0) return null;
                    self.index = 0;
                    self.end_index = @as(usize, @intCast(rc));
                }
                const entry = @as(*align(1) posix.system.dirent, @ptrCast(&self.buf[self.index]));
                const next_index = self.index + entry.reclen;
                self.index = next_index;

                const name = mem.sliceTo(@as([*:0]u8, @ptrCast(&entry.name)), 0);
                if (mem.eql(u8, name, ".") or mem.eql(u8, name, ".."))
                    continue :start_over;

                // Solaris dirent doesn't expose type, so we have to call stat to get it.
                const stat_info = posix.fstatat(
                    self.dir.fd,
                    name,
                    posix.AT.SYMLINK_NOFOLLOW,
                ) catch |err| switch (err) {
                    error.NameTooLong => unreachable,
                    error.SymLinkLoop => unreachable,
                    error.FileNotFound => unreachable, // lost the race
                    else => |e| return e,
                };
                const entry_kind: Entry.Kind = switch (stat_info.mode & posix.S.IFMT) {
                    posix.S.IFIFO => .named_pipe,
                    posix.S.IFCHR => .character_device,
                    posix.S.IFDIR => .directory,
                    posix.S.IFBLK => .block_device,
                    posix.S.IFREG => .file,
                    posix.S.IFLNK => .sym_link,
                    posix.S.IFSOCK => .unix_domain_socket,
                    posix.S.IFDOOR => .door,
                    posix.S.IFPORT => .event_port,
                    else => .unknown,
                };
                return Entry{
                    .name = name,
                    .kind = entry_kind,
                };
            }
        }

        fn nextBsd(self: *Self) !?Entry {
            start_over: while (true) {
                if (self.index >= self.end_index) {
                    if (self.first_iter) {
                        posix.lseek_SET(self.dir.fd, 0) catch unreachable; // EBADF here likely means that the Dir was not opened with iteration permissions
                        self.first_iter = false;
                    }
                    const rc = posix.system.getdents(self.dir.fd, &self.buf, self.buf.len);
                    switch (posix.errno(rc)) {
                        .SUCCESS => {},
                        .BADF => unreachable, // Dir is invalid or was opened without iteration ability
                        .FAULT => unreachable,
                        .NOTDIR => unreachable,
                        .INVAL => unreachable,
                        // Introduced in freebsd 13.2: directory unlinked but still open.
                        // To be consistent, iteration ends if the directory being iterated is deleted during iteration.
                        .NOENT => return null,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                    if (rc == 0) return null;
                    self.index = 0;
                    self.end_index = @as(usize, @intCast(rc));
                }
                const bsd_entry = @as(*align(1) posix.system.dirent, @ptrCast(&self.buf[self.index]));
                const next_index = self.index +
                    if (@hasField(posix.system.dirent, "reclen")) bsd_entry.reclen else bsd_entry.reclen();
                self.index = next_index;

                const name = @as([*]u8, @ptrCast(&bsd_entry.name))[0..bsd_entry.namlen];

                const skip_zero_fileno = switch (native_os) {
                    // fileno=0 is used to mark invalid entries or deleted files.
                    .openbsd, .netbsd => true,
                    else => false,
                };
                if (mem.eql(u8, name, ".") or mem.eql(u8, name, "..") or
                    (skip_zero_fileno and bsd_entry.fileno == 0))
                {
                    continue :start_over;
                }

                const entry_kind: Entry.Kind = switch (bsd_entry.type) {
                    posix.DT.BLK => .block_device,
                    posix.DT.CHR => .character_device,
                    posix.DT.DIR => .directory,
                    posix.DT.FIFO => .named_pipe,
                    posix.DT.LNK => .sym_link,
                    posix.DT.REG => .file,
                    posix.DT.SOCK => .unix_domain_socket,
                    posix.DT.WHT => .whiteout,
                    else => .unknown,
                };
                return Entry{
                    .name = name,
                    .kind = entry_kind,
                };
            }
        }

        pub fn reset(self: *Self) void {
            self.index = 0;
            self.end_index = 0;
            self.first_iter = true;
        }
    },
    .haiku => struct {
        dir: Dir,
        buf: [@sizeOf(DirEnt) + posix.PATH_MAX]u8 align(@alignOf(DirEnt)),
        offset: usize,
        index: usize,
        end_index: usize,
        first_iter: bool,

        const Self = @This();
        const DirEnt = posix.system.DirEnt;

        pub const Error = IteratorError;

        /// Memory such as file names referenced in this returned entry becomes invalid
        /// with subsequent calls to `next`, as well as when this `Dir` is deinitialized.
        pub fn next(self: *Self) Error!?Entry {
            while (true) {
                if (self.index >= self.end_index) {
                    if (self.first_iter) {
                        switch (@as(posix.E, @enumFromInt(posix.system._kern_rewind_dir(self.dir.fd)))) {
                            .SUCCESS => {},
                            .BADF => unreachable, // Dir is invalid
                            .FAULT => unreachable,
                            .NOTDIR => unreachable,
                            .INVAL => unreachable,
                            .ACCES => return error.AccessDenied,
                            .PERM => return error.PermissionDenied,
                            else => |err| return posix.unexpectedErrno(err),
                        }
                        self.first_iter = false;
                    }
                    const rc = posix.system._kern_read_dir(
                        self.dir.fd,
                        &self.buf,
                        self.buf.len,
                        self.buf.len / @sizeOf(DirEnt),
                    );
                    if (rc == 0) return null;
                    if (rc < 0) {
                        switch (@as(posix.E, @enumFromInt(rc))) {
                            .BADF => unreachable, // Dir is invalid
                            .FAULT => unreachable,
                            .NOTDIR => unreachable,
                            .INVAL => unreachable,
                            .OVERFLOW => unreachable,
                            .ACCES => return error.AccessDenied,
                            .PERM => return error.PermissionDenied,
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    }
                    self.offset = 0;
                    self.index = 0;
                    self.end_index = @intCast(rc);
                }
                const dirent: *DirEnt = @ptrCast(@alignCast(&self.buf[self.offset]));
                self.offset += dirent.reclen;
                self.index += 1;
                const name = mem.span(dirent.getName());
                if (mem.eql(u8, name, ".") or mem.eql(u8, name, "..") or dirent.ino == 0) continue;

                var stat_info: posix.Stat = undefined;
                switch (@as(posix.E, @enumFromInt(posix.system._kern_read_stat(
                    self.dir.fd,
                    name,
                    false,
                    &stat_info,
                    0,
                )))) {
                    .SUCCESS => {},
                    .INVAL => unreachable,
                    .BADF => unreachable, // Dir is invalid
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .FAULT => unreachable,
                    .NAMETOOLONG => unreachable,
                    .LOOP => unreachable,
                    .NOENT => continue,
                    else => |err| return posix.unexpectedErrno(err),
                }
                const statmode = stat_info.mode & posix.S.IFMT;

                const entry_kind: Entry.Kind = switch (statmode) {
                    posix.S.IFDIR => .directory,
                    posix.S.IFBLK => .block_device,
                    posix.S.IFCHR => .character_device,
                    posix.S.IFLNK => .sym_link,
                    posix.S.IFREG => .file,
                    posix.S.IFIFO => .named_pipe,
                    else => .unknown,
                };

                return Entry{
                    .name = name,
                    .kind = entry_kind,
                };
            }
        }

        pub fn reset(self: *Self) void {
            self.index = 0;
            self.end_index = 0;
            self.first_iter = true;
        }
    },
    .linux => struct {
        dir: Dir,
        // The if guard is solely there to prevent compile errors from missing `linux.dirent64`
        // definition when compiling for other OSes. It doesn't do anything when compiling for Linux.
        buf: [1024]u8 align(@alignOf(linux.dirent64)),
        index: usize,
        end_index: usize,
        first_iter: bool,

        const Self = @This();

        pub const Error = IteratorError;

        /// Memory such as file names referenced in this returned entry becomes invalid
        /// with subsequent calls to `next`, as well as when this `Dir` is deinitialized.
        pub fn next(self: *Self) Error!?Entry {
            return self.nextLinux() catch |err| switch (err) {
                // To be consistent across platforms, iteration ends if the directory being iterated is deleted during iteration.
                // This matches the behavior of non-Linux UNIX platforms.
                error.DirNotFound => null,
                else => |e| return e,
            };
        }

        pub const ErrorLinux = error{DirNotFound} || IteratorError;

        /// Implementation of `next` that can return `error.DirNotFound` if the directory being
        /// iterated was deleted during iteration (this error is Linux specific).
        pub fn nextLinux(self: *Self) ErrorLinux!?Entry {
            start_over: while (true) {
                if (self.index >= self.end_index) {
                    if (self.first_iter) {
                        posix.lseek_SET(self.dir.fd, 0) catch unreachable; // EBADF here likely means that the Dir was not opened with iteration permissions
                        self.first_iter = false;
                    }
                    const rc = linux.getdents64(self.dir.fd, &self.buf, self.buf.len);
                    switch (linux.E.init(rc)) {
                        .SUCCESS => {},
                        .BADF => unreachable, // Dir is invalid or was opened without iteration ability
                        .FAULT => unreachable,
                        .NOTDIR => unreachable,
                        .NOENT => return error.DirNotFound, // The directory being iterated was deleted during iteration.
                        .INVAL => return error.Unexpected, // Linux may in some cases return EINVAL when reading /proc/$PID/net.
                        .ACCES => return error.AccessDenied, // Do not have permission to iterate this directory.
                        else => |err| return posix.unexpectedErrno(err),
                    }
                    if (rc == 0) return null;
                    self.index = 0;
                    self.end_index = rc;
                }
                const linux_entry = @as(*align(1) linux.dirent64, @ptrCast(&self.buf[self.index]));
                const next_index = self.index + linux_entry.reclen;
                self.index = next_index;

                const name = mem.sliceTo(@as([*:0]u8, @ptrCast(&linux_entry.name)), 0);

                // skip . and .. entries
                if (mem.eql(u8, name, ".") or mem.eql(u8, name, "..")) {
                    continue :start_over;
                }

                const entry_kind: Entry.Kind = switch (linux_entry.type) {
                    linux.DT.BLK => .block_device,
                    linux.DT.CHR => .character_device,
                    linux.DT.DIR => .directory,
                    linux.DT.FIFO => .named_pipe,
                    linux.DT.LNK => .sym_link,
                    linux.DT.REG => .file,
                    linux.DT.SOCK => .unix_domain_socket,
                    else => .unknown,
                };
                return Entry{
                    .name = name,
                    .kind = entry_kind,
                };
            }
        }

        pub fn reset(self: *Self) void {
            self.index = 0;
            self.end_index = 0;
            self.first_iter = true;
        }
    },
    .windows => struct {
        dir: Dir,
        buf: [1024]u8 align(@alignOf(windows.FILE_BOTH_DIR_INFORMATION)),
        index: usize,
        end_index: usize,
        first_iter: bool,
        name_data: [fs.max_name_bytes]u8,

        const Self = @This();

        pub const Error = IteratorError;

        /// Memory such as file names referenced in this returned entry becomes invalid
        /// with subsequent calls to `next`, as well as when this `Dir` is deinitialized.
        pub fn next(self: *Self) Error!?Entry {
            const w = windows;
            while (true) {
                if (self.index >= self.end_index) {
                    var io: w.IO_STATUS_BLOCK = undefined;
                    const rc = w.ntdll.NtQueryDirectoryFile(
                        self.dir.fd,
                        null,
                        null,
                        null,
                        &io,
                        &self.buf,
                        self.buf.len,
                        .FileBothDirectoryInformation,
                        w.FALSE,
                        null,
                        if (self.first_iter) @as(w.BOOLEAN, w.TRUE) else @as(w.BOOLEAN, w.FALSE),
                    );
                    self.first_iter = false;
                    if (io.Information == 0) return null;
                    self.index = 0;
                    self.end_index = io.Information;
                    switch (rc) {
                        .SUCCESS => {},
                        .ACCESS_DENIED => return error.AccessDenied, // Double-check that the Dir was opened with iteration ability

                        else => return w.unexpectedStatus(rc),
                    }
                }

                // While the official api docs guarantee FILE_BOTH_DIR_INFORMATION to be aligned properly
                // this may not always be the case (e.g. due to faulty VM/Sandboxing tools)
                const dir_info: *align(2) w.FILE_BOTH_DIR_INFORMATION = @ptrCast(@alignCast(&self.buf[self.index]));
                if (dir_info.NextEntryOffset != 0) {
                    self.index += dir_info.NextEntryOffset;
                } else {
                    self.index = self.buf.len;
                }

                const name_wtf16le = @as([*]u16, @ptrCast(&dir_info.FileName))[0 .. dir_info.FileNameLength / 2];

                if (mem.eql(u16, name_wtf16le, &[_]u16{'.'}) or mem.eql(u16, name_wtf16le, &[_]u16{ '.', '.' }))
                    continue;
                const name_wtf8_len = std.unicode.wtf16LeToWtf8(self.name_data[0..], name_wtf16le);
                const name_wtf8 = self.name_data[0..name_wtf8_len];
                const kind: Entry.Kind = blk: {
                    const attrs = dir_info.FileAttributes;
                    if (attrs & w.FILE_ATTRIBUTE_DIRECTORY != 0) break :blk .directory;
                    if (attrs & w.FILE_ATTRIBUTE_REPARSE_POINT != 0) break :blk .sym_link;
                    break :blk .file;
                };
                return Entry{
                    .name = name_wtf8,
                    .kind = kind,
                };
            }
        }

        pub fn reset(self: *Self) void {
            self.index = 0;
            self.end_index = 0;
            self.first_iter = true;
        }
    },
    .wasi => struct {
        dir: Dir,
        buf: [1024]u8, // TODO align(@alignOf(posix.wasi.dirent_t)),
        cookie: u64,
        index: usize,
        end_index: usize,

        const Self = @This();

        pub const Error = IteratorError;

        /// Memory such as file names referenced in this returned entry becomes invalid
        /// with subsequent calls to `next`, as well as when this `Dir` is deinitialized.
        pub fn next(self: *Self) Error!?Entry {
            return self.nextWasi() catch |err| switch (err) {
                // To be consistent across platforms, iteration ends if the directory being iterated is deleted during iteration.
                // This matches the behavior of non-Linux UNIX platforms.
                error.DirNotFound => null,
                else => |e| return e,
            };
        }

        pub const ErrorWasi = error{DirNotFound} || IteratorError;

        /// Implementation of `next` that can return platform-dependent errors depending on the host platform.
        /// When the host platform is Linux, `error.DirNotFound` can be returned if the directory being
        /// iterated was deleted during iteration.
        pub fn nextWasi(self: *Self) ErrorWasi!?Entry {
            // We intentinally use fd_readdir even when linked with libc,
            // since its implementation is exactly the same as below,
            // and we avoid the code complexity here.
            const w = std.os.wasi;
            start_over: while (true) {
                // According to the WASI spec, the last entry might be truncated,
                // so we need to check if the left buffer contains the whole dirent.
                if (self.end_index - self.index < @sizeOf(w.dirent_t)) {
                    var bufused: usize = undefined;
                    switch (w.fd_readdir(self.dir.fd, &self.buf, self.buf.len, self.cookie, &bufused)) {
                        .SUCCESS => {},
                        .BADF => unreachable, // Dir is invalid or was opened without iteration ability
                        .FAULT => unreachable,
                        .NOTDIR => unreachable,
                        .INVAL => unreachable,
                        .NOENT => return error.DirNotFound, // The directory being iterated was deleted during iteration.
                        .NOTCAPABLE => return error.AccessDenied,
                        .ILSEQ => return error.InvalidUtf8, // An entry's name cannot be encoded as UTF-8.
                        else => |err| return posix.unexpectedErrno(err),
                    }
                    if (bufused == 0) return null;
                    self.index = 0;
                    self.end_index = bufused;
                }
                const entry = @as(*align(1) w.dirent_t, @ptrCast(&self.buf[self.index]));
                const entry_size = @sizeOf(w.dirent_t);
                const name_index = self.index + entry_size;
                if (name_index + entry.namlen > self.end_index) {
                    // This case, the name is truncated, so we need to call readdir to store the entire name.
                    self.end_index = self.index; // Force fd_readdir in the next loop.
                    continue :start_over;
                }
                const name = self.buf[name_index .. name_index + entry.namlen];

                const next_index = name_index + entry.namlen;
                self.index = next_index;
                self.cookie = entry.next;

                // skip . and .. entries
                if (mem.eql(u8, name, ".") or mem.eql(u8, name, "..")) {
                    continue :start_over;
                }

                const entry_kind: Entry.Kind = switch (entry.type) {
                    .BLOCK_DEVICE => .block_device,
                    .CHARACTER_DEVICE => .character_device,
                    .DIRECTORY => .directory,
                    .SYMBOLIC_LINK => .sym_link,
                    .REGULAR_FILE => .file,
                    .SOCKET_STREAM, .SOCKET_DGRAM => .unix_domain_socket,
                    else => .unknown,
                };
                return Entry{
                    .name = name,
                    .kind = entry_kind,
                };
            }
        }

        pub fn reset(self: *Self) void {
            self.index = 0;
            self.end_index = 0;
            self.cookie = std.os.wasi.DIRCOOKIE_START;
        }
    },
    else => @compileError("unimplemented"),
};

pub fn iterate(self: Dir) Iterator {
    return self.iterateImpl(true);
}

/// Like `iterate`, but will not reset the directory cursor before the first
/// iteration. This should only be used in cases where it is known that the
/// `Dir` has not had its cursor modified yet (e.g. it was just opened).
pub fn iterateAssumeFirstIteration(self: Dir) Iterator {
    return self.iterateImpl(false);
}

fn iterateImpl(self: Dir, first_iter_start_value: bool) Iterator {
    switch (native_os) {
        .macos,
        .ios,
        .freebsd,
        .netbsd,
        .dragonfly,
        .openbsd,
        .solaris,
        .illumos,
        => return Iterator{
            .dir = self,
            .seek = 0,
            .index = 0,
            .end_index = 0,
            .buf = undefined,
            .first_iter = first_iter_start_value,
        },
        .linux => return Iterator{
            .dir = self,
            .index = 0,
            .end_index = 0,
            .buf = undefined,
            .first_iter = first_iter_start_value,
        },
        .haiku => return Iterator{
            .dir = self,
            .offset = 0,
            .index = 0,
            .end_index = 0,
            .buf = undefined,
            .first_iter = first_iter_start_value,
        },
        .windows => return Iterator{
            .dir = self,
            .index = 0,
            .end_index = 0,
            .first_iter = first_iter_start_value,
            .buf = undefined,
            .name_data = undefined,
        },
        .wasi => return Iterator{
            .dir = self,
            .cookie = std.os.wasi.DIRCOOKIE_START,
            .index = 0,
            .end_index = 0,
            .buf = undefined,
        },
        else => @compileError("unimplemented"),
    }
}

pub const Walker = struct {
    stack: std.ArrayListUnmanaged(StackItem),
    name_buffer: std.ArrayListUnmanaged(u8),
    allocator: Allocator,

    pub const Entry = struct {
        /// The containing directory. This can be used to operate directly on `basename`
        /// rather than `path`, avoiding `error.NameTooLong` for deeply nested paths.
        /// The directory remains open until `next` or `deinit` is called.
        dir: Dir,
        basename: [:0]const u8,
        path: [:0]const u8,
        kind: Dir.Entry.Kind,
    };

    const StackItem = struct {
        iter: Dir.Iterator,
        dirname_len: usize,
    };

    /// After each call to this function, and on deinit(), the memory returned
    /// from this function becomes invalid. A copy must be made in order to keep
    /// a reference to the path.
    pub fn next(self: *Walker) !?Walker.Entry {
        const gpa = self.allocator;
        while (self.stack.items.len != 0) {
            // `top` and `containing` become invalid after appending to `self.stack`
            var top = &self.stack.items[self.stack.items.len - 1];
            var containing = top;
            var dirname_len = top.dirname_len;
            if (top.iter.next() catch |err| {
                // If we get an error, then we want the user to be able to continue
                // walking if they want, which means that we need to pop the directory
                // that errored from the stack. Otherwise, all future `next` calls would
                // likely just fail with the same error.
                var item = self.stack.pop().?;
                if (self.stack.items.len != 0) {
                    item.iter.dir.close();
                }
                return err;
            }) |base| {
                self.name_buffer.shrinkRetainingCapacity(dirname_len);
                if (self.name_buffer.items.len != 0) {
                    try self.name_buffer.append(gpa, fs.path.sep);
                    dirname_len += 1;
                }
                try self.name_buffer.ensureUnusedCapacity(gpa, base.name.len + 1);
                self.name_buffer.appendSliceAssumeCapacity(base.name);
                self.name_buffer.appendAssumeCapacity(0);
                if (base.kind == .directory) {
                    var new_dir = top.iter.dir.openDir(base.name, .{ .iterate = true }) catch |err| switch (err) {
                        error.NameTooLong => unreachable, // no path sep in base.name
                        else => |e| return e,
                    };
                    {
                        errdefer new_dir.close();
                        try self.stack.append(gpa, .{
                            .iter = new_dir.iterateAssumeFirstIteration(),
                            .dirname_len = self.name_buffer.items.len - 1,
                        });
                        top = &self.stack.items[self.stack.items.len - 1];
                        containing = &self.stack.items[self.stack.items.len - 2];
                    }
                }
                return .{
                    .dir = containing.iter.dir,
                    .basename = self.name_buffer.items[dirname_len .. self.name_buffer.items.len - 1 :0],
                    .path = self.name_buffer.items[0 .. self.name_buffer.items.len - 1 :0],
                    .kind = base.kind,
                };
            } else {
                var item = self.stack.pop().?;
                if (self.stack.items.len != 0) {
                    item.iter.dir.close();
                }
            }
        }
        return null;
    }

    pub fn deinit(self: *Walker) void {
        const gpa = self.allocator;
        // Close any remaining directories except the initial one (which is always at index 0)
        if (self.stack.items.len > 1) {
            for (self.stack.items[1..]) |*item| {
                item.iter.dir.close();
            }
        }
        self.stack.deinit(gpa);
        self.name_buffer.deinit(gpa);
    }
};

/// Recursively iterates over a directory.
///
/// `self` must have been opened with `OpenOptions{.iterate = true}`.
///
/// `Walker.deinit` releases allocated memory and directory handles.
///
/// The order of returned file system entries is undefined.
///
/// `self` will not be closed after walking it.
pub fn walk(self: Dir, allocator: Allocator) Allocator.Error!Walker {
    var stack: std.ArrayListUnmanaged(Walker.StackItem) = .empty;

    try stack.append(allocator, .{
        .iter = self.iterate(),
        .dirname_len = 0,
    });

    return .{
        .stack = stack,
        .name_buffer = .{},
        .allocator = allocator,
    };
}

pub const OpenError = error{
    FileNotFound,
    NotDir,
    AccessDenied,
    PermissionDenied,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    NameTooLong,
    SystemFdQuotaExceeded,
    NoDevice,
    SystemResources,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
    BadPathName,
    DeviceBusy,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    ProcessNotFound,
} || posix.UnexpectedError;

pub fn close(self: *Dir) void {
    posix.close(self.fd);
    self.* = undefined;
}

/// Opens a file for reading or writing, without attempting to create a new file.
/// To create a new file, see `createFile`.
/// Call `File.close` to release the resource.
/// Asserts that the path parameter has no null bytes.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn openFile(self: Dir, sub_path: []const u8, flags: File.OpenFlags) File.OpenError!File {
    if (native_os == .windows) {
        const path_w = try windows.sliceToPrefixedFileW(self.fd, sub_path);
        return self.openFileW(path_w.span(), flags);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var base: std.os.wasi.rights_t = .{};
        // POLL_FD_READWRITE only grants extra rights if the corresponding FD_READ and/or FD_WRITE
        // is also set.
        if (flags.isRead()) {
            base.FD_READ = true;
            base.FD_TELL = true;
            base.FD_SEEK = true;
            base.FD_FILESTAT_GET = true;
            base.POLL_FD_READWRITE = true;
        }
        if (flags.isWrite()) {
            base.FD_WRITE = true;
            base.FD_TELL = true;
            base.FD_SEEK = true;
            base.FD_DATASYNC = true;
            base.FD_FDSTAT_SET_FLAGS = true;
            base.FD_SYNC = true;
            base.FD_ALLOCATE = true;
            base.FD_ADVISE = true;
            base.FD_FILESTAT_SET_TIMES = true;
            base.FD_FILESTAT_SET_SIZE = true;
            base.POLL_FD_READWRITE = true;
        }
        const fd = try posix.openatWasi(self.fd, sub_path, .{}, .{}, .{}, base, .{});
        return .{ .handle = fd };
    }
    const path_c = try posix.toPosixPath(sub_path);
    return self.openFileZ(&path_c, flags);
}

/// Same as `openFile` but the path parameter is null-terminated.
pub fn openFileZ(self: Dir, sub_path: [*:0]const u8, flags: File.OpenFlags) File.OpenError!File {
    switch (native_os) {
        .windows => {
            const path_w = try windows.cStrToPrefixedFileW(self.fd, sub_path);
            return self.openFileW(path_w.span(), flags);
        },
        // Use the libc API when libc is linked because it implements things
        // such as opening absolute file paths.
        .wasi => if (!builtin.link_libc) {
            return openFile(self, mem.sliceTo(sub_path, 0), flags);
        },
        else => {},
    }

    var os_flags: posix.O = switch (native_os) {
        .wasi => .{
            .read = flags.mode != .write_only,
            .write = flags.mode != .read_only,
        },
        else => .{
            .ACCMODE = switch (flags.mode) {
                .read_only => .RDONLY,
                .write_only => .WRONLY,
                .read_write => .RDWR,
            },
        },
    };
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;
    if (@hasField(posix.O, "LARGEFILE")) os_flags.LARGEFILE = true;
    if (@hasField(posix.O, "NOCTTY")) os_flags.NOCTTY = !flags.allow_ctty;

    // Use the O locking flags if the os supports them to acquire the lock
    // atomically.
    const has_flock_open_flags = @hasField(posix.O, "EXLOCK");
    if (has_flock_open_flags) {
        // Note that the NONBLOCK flag is removed after the openat() call
        // is successful.
        switch (flags.lock) {
            .none => {},
            .shared => {
                os_flags.SHLOCK = true;
                os_flags.NONBLOCK = flags.lock_nonblocking;
            },
            .exclusive => {
                os_flags.EXLOCK = true;
                os_flags.NONBLOCK = flags.lock_nonblocking;
            },
        }
    }
    const fd = try posix.openatZ(self.fd, sub_path, os_flags, 0);
    errdefer posix.close(fd);

    if (have_flock and !has_flock_open_flags and flags.lock != .none) {
        // TODO: integrate async I/O
        const lock_nonblocking: i32 = if (flags.lock_nonblocking) posix.LOCK.NB else 0;
        try posix.flock(fd, switch (flags.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        });
    }

    if (has_flock_open_flags and flags.lock_nonblocking) {
        var fl_flags = posix.fcntl(fd, posix.F.GETFL, 0) catch |err| switch (err) {
            error.FileBusy => unreachable,
            error.Locked => unreachable,
            error.PermissionDenied => unreachable,
            error.DeadLock => unreachable,
            error.LockedRegionLimitExceeded => unreachable,
            else => |e| return e,
        };
        fl_flags &= ~@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));
        _ = posix.fcntl(fd, posix.F.SETFL, fl_flags) catch |err| switch (err) {
            error.FileBusy => unreachable,
            error.Locked => unreachable,
            error.PermissionDenied => unreachable,
            error.DeadLock => unreachable,
            error.LockedRegionLimitExceeded => unreachable,
            else => |e| return e,
        };
    }

    return .{ .handle = fd };
}

/// Same as `openFile` but Windows-only and the path parameter is
/// [WTF-16](https://simonsapin.github.io/wtf-8/#potentially-ill-formed-utf-16) encoded.
pub fn openFileW(self: Dir, sub_path_w: []const u16, flags: File.OpenFlags) File.OpenError!File {
    const w = windows;
    const file: File = .{
        .handle = try w.OpenFile(sub_path_w, .{
            .dir = self.fd,
            .access_mask = w.SYNCHRONIZE |
                (if (flags.isRead()) @as(u32, w.GENERIC_READ) else 0) |
                (if (flags.isWrite()) @as(u32, w.GENERIC_WRITE) else 0),
            .creation = w.FILE_OPEN,
        }),
    };
    errdefer file.close();
    var io: w.IO_STATUS_BLOCK = undefined;
    const range_off: w.LARGE_INTEGER = 0;
    const range_len: w.LARGE_INTEGER = 1;
    const exclusive = switch (flags.lock) {
        .none => return file,
        .shared => false,
        .exclusive => true,
    };
    try w.LockFile(
        file.handle,
        null,
        null,
        null,
        &io,
        &range_off,
        &range_len,
        null,
        @intFromBool(flags.lock_nonblocking),
        @intFromBool(exclusive),
    );
    return file;
}

/// Creates, opens, or overwrites a file with write access.
/// Call `File.close` on the result when done.
/// Asserts that the path parameter has no null bytes.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn createFile(self: Dir, sub_path: []const u8, flags: File.CreateFlags) File.OpenError!File {
    if (native_os == .windows) {
        const path_w = try windows.sliceToPrefixedFileW(self.fd, sub_path);
        return self.createFileW(path_w.span(), flags);
    }
    if (native_os == .wasi) {
        return .{
            .handle = try posix.openatWasi(self.fd, sub_path, .{}, .{
                .CREAT = true,
                .TRUNC = flags.truncate,
                .EXCL = flags.exclusive,
            }, .{}, .{
                .FD_READ = flags.read,
                .FD_WRITE = true,
                .FD_DATASYNC = true,
                .FD_SEEK = true,
                .FD_TELL = true,
                .FD_FDSTAT_SET_FLAGS = true,
                .FD_SYNC = true,
                .FD_ALLOCATE = true,
                .FD_ADVISE = true,
                .FD_FILESTAT_SET_TIMES = true,
                .FD_FILESTAT_SET_SIZE = true,
                .FD_FILESTAT_GET = true,
                // POLL_FD_READWRITE only grants extra rights if the corresponding FD_READ and/or
                // FD_WRITE is also set.
                .POLL_FD_READWRITE = true,
            }, .{}),
        };
    }
    const path_c = try posix.toPosixPath(sub_path);
    return self.createFileZ(&path_c, flags);
}

/// Same as `createFile` but the path parameter is null-terminated.
pub fn createFileZ(self: Dir, sub_path_c: [*:0]const u8, flags: File.CreateFlags) File.OpenError!File {
    switch (native_os) {
        .windows => {
            const path_w = try windows.cStrToPrefixedFileW(self.fd, sub_path_c);
            return self.createFileW(path_w.span(), flags);
        },
        .wasi => {
            return createFile(self, mem.sliceTo(sub_path_c, 0), flags);
        },
        else => {},
    }

    var os_flags: posix.O = .{
        .ACCMODE = if (flags.read) .RDWR else .WRONLY,
        .CREAT = true,
        .TRUNC = flags.truncate,
        .EXCL = flags.exclusive,
    };
    if (@hasField(posix.O, "LARGEFILE")) os_flags.LARGEFILE = true;
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;

    // Use the O locking flags if the os supports them to acquire the lock
    // atomically. Note that the NONBLOCK flag is removed after the openat()
    // call is successful.
    const has_flock_open_flags = @hasField(posix.O, "EXLOCK");
    if (has_flock_open_flags) switch (flags.lock) {
        .none => {},
        .shared => {
            os_flags.SHLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
        .exclusive => {
            os_flags.EXLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
    };

    const fd = try posix.openatZ(self.fd, sub_path_c, os_flags, flags.mode);
    errdefer posix.close(fd);

    if (have_flock and !has_flock_open_flags and flags.lock != .none) {
        // TODO: integrate async I/O
        const lock_nonblocking: i32 = if (flags.lock_nonblocking) posix.LOCK.NB else 0;
        try posix.flock(fd, switch (flags.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        });
    }

    if (has_flock_open_flags and flags.lock_nonblocking) {
        var fl_flags = posix.fcntl(fd, posix.F.GETFL, 0) catch |err| switch (err) {
            error.FileBusy => unreachable,
            error.Locked => unreachable,
            error.PermissionDenied => unreachable,
            error.DeadLock => unreachable,
            error.LockedRegionLimitExceeded => unreachable,
            else => |e| return e,
        };
        fl_flags &= ~@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));
        _ = posix.fcntl(fd, posix.F.SETFL, fl_flags) catch |err| switch (err) {
            error.FileBusy => unreachable,
            error.Locked => unreachable,
            error.PermissionDenied => unreachable,
            error.DeadLock => unreachable,
            error.LockedRegionLimitExceeded => unreachable,
            else => |e| return e,
        };
    }

    return .{ .handle = fd };
}

/// Same as `createFile` but Windows-only and the path parameter is
/// [WTF-16](https://simonsapin.github.io/wtf-8/#potentially-ill-formed-utf-16) encoded.
pub fn createFileW(self: Dir, sub_path_w: []const u16, flags: File.CreateFlags) File.OpenError!File {
    const w = windows;
    const read_flag = if (flags.read) @as(u32, w.GENERIC_READ) else 0;
    const file: File = .{
        .handle = try w.OpenFile(sub_path_w, .{
            .dir = self.fd,
            .access_mask = w.SYNCHRONIZE | w.GENERIC_WRITE | read_flag,
            .creation = if (flags.exclusive)
                @as(u32, w.FILE_CREATE)
            else if (flags.truncate)
                @as(u32, w.FILE_OVERWRITE_IF)
            else
                @as(u32, w.FILE_OPEN_IF),
        }),
    };
    errdefer file.close();
    var io: w.IO_STATUS_BLOCK = undefined;
    const range_off: w.LARGE_INTEGER = 0;
    const range_len: w.LARGE_INTEGER = 1;
    const exclusive = switch (flags.lock) {
        .none => return file,
        .shared => false,
        .exclusive => true,
    };
    try w.LockFile(
        file.handle,
        null,
        null,
        null,
        &io,
        &range_off,
        &range_len,
        null,
        @intFromBool(flags.lock_nonblocking),
        @intFromBool(exclusive),
    );
    return file;
}

pub const MakeError = posix.MakeDirError;

/// Creates a single directory with a relative or absolute path.
/// To create multiple directories to make an entire path, see `makePath`.
/// To operate on only absolute paths, see `makeDirAbsolute`.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn makeDir(self: Dir, sub_path: []const u8) MakeError!void {
    try posix.mkdirat(self.fd, sub_path, default_mode);
}

/// Same as `makeDir`, but `sub_path` is null-terminated.
/// To create multiple directories to make an entire path, see `makePath`.
/// To operate on only absolute paths, see `makeDirAbsoluteZ`.
pub fn makeDirZ(self: Dir, sub_path: [*:0]const u8) MakeError!void {
    try posix.mkdiratZ(self.fd, sub_path, default_mode);
}

/// Creates a single directory with a relative or absolute null-terminated WTF-16 LE-encoded path.
/// To create multiple directories to make an entire path, see `makePath`.
/// To operate on only absolute paths, see `makeDirAbsoluteW`.
pub fn makeDirW(self: Dir, sub_path: [*:0]const u16) MakeError!void {
    try posix.mkdiratW(self.fd, mem.span(sub_path), default_mode);
}

/// Calls makeDir iteratively to make an entire path
/// (i.e. creating any parent directories that do not exist).
/// Returns success if the path already exists and is a directory.
/// This function is not atomic, and if it returns an error, the file system may
/// have been modified regardless.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
///
/// Paths containing `..` components are handled differently depending on the platform:
/// - On Windows, `..` are resolved before the path is passed to NtCreateFile, meaning
///   a `sub_path` like "first/../second" will resolve to "second" and only a
///   `./second` directory will be created.
/// - On other platforms, `..` are not resolved before the path is passed to `mkdirat`,
///   meaning a `sub_path` like "first/../second" will create both a `./first`
///   and a `./second` directory.
pub fn makePath(self: Dir, sub_path: []const u8) (MakeError || StatFileError)!void {
    var it = try fs.path.componentIterator(sub_path);
    var component = it.last() orelse return;
    while (true) {
        self.makeDir(component.path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                // stat the file and return an error if it's not a directory
                // this is important because otherwise a dangling symlink
                // could cause an infinite loop
                check_dir: {
                    // workaround for windows, see https://github.com/ziglang/zig/issues/16738
                    const fstat = self.statFile(component.path) catch |stat_err| switch (stat_err) {
                        error.IsDir => break :check_dir,
                        else => |e| return e,
                    };
                    if (fstat.kind != .directory) return error.NotDir;
                }
            },
            error.FileNotFound => |e| {
                component = it.previous() orelse return e;
                continue;
            },
            else => |e| return e,
        };
        component = it.next() orelse return;
    }
}

/// Windows only. Calls makeOpenDirAccessMaskW iteratively to make an entire path
/// (i.e. creating any parent directories that do not exist).
/// Opens the dir if the path already exists and is a directory.
/// This function is not atomic, and if it returns an error, the file system may
/// have been modified regardless.
/// `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
fn makeOpenPathAccessMaskW(self: Dir, sub_path: []const u8, access_mask: u32, no_follow: bool) (MakeError || OpenError || StatFileError)!Dir {
    const w = windows;
    var it = try fs.path.componentIterator(sub_path);
    // If there are no components in the path, then create a dummy component with the full path.
    var component = it.last() orelse fs.path.NativeComponentIterator.Component{
        .name = "",
        .path = sub_path,
    };

    while (true) {
        const sub_path_w = try w.sliceToPrefixedFileW(self.fd, component.path);
        const is_last = it.peekNext() == null;
        var result = self.makeOpenDirAccessMaskW(sub_path_w.span().ptr, access_mask, .{
            .no_follow = no_follow,
            .create_disposition = if (is_last) w.FILE_OPEN_IF else w.FILE_CREATE,
        }) catch |err| switch (err) {
            error.FileNotFound => |e| {
                component = it.previous() orelse return e;
                continue;
            },
            error.PathAlreadyExists => result: {
                assert(!is_last);
                // stat the file and return an error if it's not a directory
                // this is important because otherwise a dangling symlink
                // could cause an infinite loop
                check_dir: {
                    // workaround for windows, see https://github.com/ziglang/zig/issues/16738
                    const fstat = self.statFile(component.path) catch |stat_err| switch (stat_err) {
                        error.IsDir => break :check_dir,
                        else => |e| return e,
                    };
                    if (fstat.kind != .directory) return error.NotDir;
                }
                break :result null;
            },
            else => |e| return e,
        };

        component = it.next() orelse return result.?;

        // Don't leak the intermediate file handles
        if (result) |*dir| {
            dir.close();
        }
    }
}

/// This function performs `makePath`, followed by `openDir`.
/// If supported by the OS, this operation is atomic. It is not atomic on
/// all operating systems.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn makeOpenPath(self: Dir, sub_path: []const u8, open_dir_options: OpenOptions) (MakeError || OpenError || StatFileError)!Dir {
    return switch (native_os) {
        .windows => {
            const w = windows;
            const base_flags = w.STANDARD_RIGHTS_READ | w.FILE_READ_ATTRIBUTES | w.FILE_READ_EA |
                w.SYNCHRONIZE | w.FILE_TRAVERSE |
                (if (open_dir_options.iterate) w.FILE_LIST_DIRECTORY else @as(u32, 0));

            return self.makeOpenPathAccessMaskW(sub_path, base_flags, open_dir_options.no_follow);
        },
        else => {
            return self.openDir(s```
