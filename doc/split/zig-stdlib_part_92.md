```
s, size, alloc_type, protect)) {
        .SUCCESS => return,
        .ACCESS_DENIED => NtAllocateVirtualMemoryError.AccessDenied,
        .INVALID_PARAMETER => NtAllocateVirtualMemoryError.InvalidParameter,
        .NO_MEMORY => NtAllocateVirtualMemoryError.NoMemory,
        else => |st| unexpectedStatus(st),
    };
}

pub const NtFreeVirtualMemoryError = error{
    AccessDenied,
    InvalidParameter,
    Unexpected,
};

pub fn NtFreeVirtualMemory(hProcess: HANDLE, addr: ?*PVOID, size: *SIZE_T, free_type: ULONG) NtFreeVirtualMemoryError!void {
    return switch (ntdll.NtFreeVirtualMemory(hProcess, addr, size, free_type)) {
        .SUCCESS => return,
        .ACCESS_DENIED => NtFreeVirtualMemoryError.AccessDenied,
        .INVALID_PARAMETER => NtFreeVirtualMemoryError.InvalidParameter,
        else => NtFreeVirtualMemoryError.Unexpected,
    };
}

pub const VirtualAllocError = error{Unexpected};

pub fn VirtualAlloc(addr: ?LPVOID, size: usize, alloc_type: DWORD, flProtect: DWORD) VirtualAllocError!LPVOID {
    return kernel32.VirtualAlloc(addr, size, alloc_type, flProtect) orelse {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    };
}

pub fn VirtualFree(lpAddress: ?LPVOID, dwSize: usize, dwFreeType: DWORD) void {
    assert(kernel32.VirtualFree(lpAddress, dwSize, dwFreeType) != 0);
}

pub const VirtualProtectError = error{
    InvalidAddress,
    Unexpected,
};

pub fn VirtualProtect(lpAddress: ?LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: *DWORD) VirtualProtectError!void {
    // ntdll takes an extra level of indirection here
    var addr = lpAddress;
    var size = dwSize;
    switch (ntdll.NtProtectVirtualMemory(self_process_handle, &addr, &size, flNewProtect, lpflOldProtect)) {
        .SUCCESS => {},
        .INVALID_ADDRESS => return error.InvalidAddress,
        else => |st| return unexpectedStatus(st),
    }
}

pub fn VirtualProtectEx(handle: HANDLE, addr: ?LPVOID, size: SIZE_T, new_prot: DWORD) VirtualProtectError!DWORD {
    var old_prot: DWORD = undefined;
    var out_addr = addr;
    var out_size = size;
    switch (ntdll.NtProtectVirtualMemory(
        handle,
        &out_addr,
        &out_size,
        new_prot,
        &old_prot,
    )) {
        .SUCCESS => return old_prot,
        .INVALID_ADDRESS => return error.InvalidAddress,
        // TODO: map errors
        else => |rc| return unexpectedStatus(rc),
    }
}

pub const VirtualQueryError = error{Unexpected};

pub fn VirtualQuery(lpAddress: ?LPVOID, lpBuffer: PMEMORY_BASIC_INFORMATION, dwLength: SIZE_T) VirtualQueryError!SIZE_T {
    const rc = kernel32.VirtualQuery(lpAddress, lpBuffer, dwLength);
    if (rc == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }

    return rc;
}

pub const SetConsoleTextAttributeError = error{Unexpected};

pub fn SetConsoleTextAttribute(hConsoleOutput: HANDLE, wAttributes: WORD) SetConsoleTextAttributeError!void {
    if (kernel32.SetConsoleTextAttribute(hConsoleOutput, wAttributes) == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub fn SetConsoleCtrlHandler(handler_routine: ?HANDLER_ROUTINE, add: bool) !void {
    const success = kernel32.SetConsoleCtrlHandler(
        handler_routine,
        if (add) TRUE else FALSE,
    );

    if (success == FALSE) {
        return switch (GetLastError()) {
            else => |err| unexpectedError(err),
        };
    }
}

pub fn SetFileCompletionNotificationModes(handle: HANDLE, flags: UCHAR) !void {
    const success = kernel32.SetFileCompletionNotificationModes(handle, flags);
    if (success == FALSE) {
        return switch (GetLastError()) {
            else => |err| unexpectedError(err),
        };
    }
}

pub const GetEnvironmentStringsError = error{OutOfMemory};

pub fn GetEnvironmentStringsW() GetEnvironmentStringsError![*:0]u16 {
    return kernel32.GetEnvironmentStringsW() orelse return error.OutOfMemory;
}

pub fn FreeEnvironmentStringsW(penv: [*:0]u16) void {
    assert(kernel32.FreeEnvironmentStringsW(penv) != 0);
}

pub const GetEnvironmentVariableError = error{
    EnvironmentVariableNotFound,
    Unexpected,
};

pub fn GetEnvironmentVariableW(lpName: LPWSTR, lpBuffer: [*]u16, nSize: DWORD) GetEnvironmentVariableError!DWORD {
    const rc = kernel32.GetEnvironmentVariableW(lpName, lpBuffer, nSize);
    if (rc == 0) {
        switch (GetLastError()) {
            .ENVVAR_NOT_FOUND => return error.EnvironmentVariableNotFound,
            else => |err| return unexpectedError(err),
        }
    }
    return rc;
}

pub const CreateProcessError = error{
    FileNotFound,
    AccessDenied,
    InvalidName,
    NameTooLong,
    InvalidExe,
    Unexpected,
};

pub const CreateProcessFlags = packed struct(u32) {
    debug_process: bool = false,
    debug_only_this_process: bool = false,
    create_suspended: bool = false,
    detached_process: bool = false,
    create_new_console: bool = false,
    normal_priority_class: bool = false,
    idle_priority_class: bool = false,
    high_priority_class: bool = false,
    realtime_priority_class: bool = false,
    create_new_process_group: bool = false,
    create_unicode_environment: bool = false,
    create_separate_wow_vdm: bool = false,
    create_shared_wow_vdm: bool = false,
    create_forcedos: bool = false,
    below_normal_priority_class: bool = false,
    above_normal_priority_class: bool = false,
    inherit_parent_affinity: bool = false,
    inherit_caller_priority: bool = false,
    create_protected_process: bool = false,
    extended_startupinfo_present: bool = false,
    process_mode_background_begin: bool = false,
    process_mode_background_end: bool = false,
    create_secure_process: bool = false,
    _reserved: bool = false,
    create_breakaway_from_job: bool = false,
    create_preserve_code_authz_level: bool = false,
    create_default_error_mode: bool = false,
    create_no_window: bool = false,
    profile_user: bool = false,
    profile_kernel: bool = false,
    profile_server: bool = false,
    create_ignore_system_default: bool = false,
};

pub fn CreateProcessW(
    lpApplicationName: ?LPCWSTR,
    lpCommandLine: ?LPWSTR,
    lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: CreateProcessFlags,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?LPCWSTR,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) CreateProcessError!void {
    if (kernel32.CreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
    ) == 0) {
        switch (GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .DIRECTORY => return error.FileNotFound,
            .ACCESS_DENIED => return error.AccessDenied,
            .INVALID_PARAMETER => unreachable,
            .INVALID_NAME => return error.InvalidName,
            .FILENAME_EXCED_RANGE => return error.NameTooLong,
            // These are all the system errors that are mapped to ENOEXEC by
            // the undocumented _dosmaperr (old CRT) or __acrt_errno_map_os_error
            // (newer CRT) functions. Their code can be found in crt/src/dosmap.c (old SDK)
            // or urt/misc/errno.cpp (newer SDK) in the Windows SDK.
            .BAD_FORMAT,
            .INVALID_STARTING_CODESEG, // MIN_EXEC_ERROR in errno.cpp
            .INVALID_STACKSEG,
            .INVALID_MODULETYPE,
            .INVALID_EXE_SIGNATURE,
            .EXE_MARKED_INVALID,
            .BAD_EXE_FORMAT,
            .ITERATED_DATA_EXCEEDS_64k,
            .INVALID_MINALLOCSIZE,
            .DYNLINK_FROM_INVALID_RING,
            .IOPL_NOT_ENABLED,
            .INVALID_SEGDPL,
            .AUTODATASEG_EXCEEDS_64k,
            .RING2SEG_MUST_BE_MOVABLE,
            .RELOC_CHAIN_XEEDS_SEGLIM,
            .INFLOOP_IN_RELOC_CHAIN, // MAX_EXEC_ERROR in errno.cpp
            // This one is not mapped to ENOEXEC but it is possible, for example
            // when calling CreateProcessW on a plain text file with a .exe extension
            .EXE_MACHINE_TYPE_MISMATCH,
            => return error.InvalidExe,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const LoadLibraryError = error{
    FileNotFound,
    Unexpected,
};

pub fn LoadLibraryW(lpLibFileName: [*:0]const u16) LoadLibraryError!HMODULE {
    return kernel32.LoadLibraryW(lpLibFileName) orelse {
        switch (GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .MOD_NOT_FOUND => return error.FileNotFound,
            else => |err| return unexpectedError(err),
        }
    };
}

pub const LoadLibraryFlags = enum(DWORD) {
    none = 0,
    dont_resolve_dll_references = 0x00000001,
    load_ignore_code_authz_level = 0x00000010,
    load_library_as_datafile = 0x00000002,
    load_library_as_datafile_exclusive = 0x00000040,
    load_library_as_image_resource = 0x00000020,
    load_library_search_application_dir = 0x00000200,
    load_library_search_default_dirs = 0x00001000,
    load_library_search_dll_load_dir = 0x00000100,
    load_library_search_system32 = 0x00000800,
    load_library_search_user_dirs = 0x00000400,
    load_with_altered_search_path = 0x00000008,
    load_library_require_signed_target = 0x00000080,
    load_library_safe_current_dirs = 0x00002000,
};

pub fn LoadLibraryExW(lpLibFileName: [*:0]const u16, dwFlags: LoadLibraryFlags) LoadLibraryError!HMODULE {
    return kernel32.LoadLibraryExW(lpLibFileName, null, @intFromEnum(dwFlags)) orelse {
        switch (GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .MOD_NOT_FOUND => return error.FileNotFound,
            else => |err| return unexpectedError(err),
        }
    };
}

pub fn FreeLibrary(hModule: HMODULE) void {
    assert(kernel32.FreeLibrary(hModule) != 0);
}

pub fn QueryPerformanceFrequency() u64 {
    // "On systems that run Windows XP or later, the function will always succeed"
    // https://docs.microsoft.com/en-us/windows/desktop/api/profileapi/nf-profileapi-queryperformancefrequency
    var result: LARGE_INTEGER = undefined;
    assert(ntdll.RtlQueryPerformanceFrequency(&result) != 0);
    // The kernel treats this integer as unsigned.
    return @as(u64, @bitCast(result));
}

pub fn QueryPerformanceCounter() u64 {
    // "On systems that run Windows XP or later, the function will always succeed"
    // https://docs.microsoft.com/en-us/windows/desktop/api/profileapi/nf-profileapi-queryperformancecounter
    var result: LARGE_INTEGER = undefined;
    assert(ntdll.RtlQueryPerformanceCounter(&result) != 0);
    // The kernel treats this integer as unsigned.
    return @as(u64, @bitCast(result));
}

pub fn InitOnceExecuteOnce(InitOnce: *INIT_ONCE, InitFn: INIT_ONCE_FN, Parameter: ?*anyopaque, Context: ?*anyopaque) void {
    assert(kernel32.InitOnceExecuteOnce(InitOnce, InitFn, Parameter, Context) != 0);
}

pub const SetFileTimeError = error{Unexpected};

pub fn SetFileTime(
    hFile: HANDLE,
    lpCreationTime: ?*const FILETIME,
    lpLastAccessTime: ?*const FILETIME,
    lpLastWriteTime: ?*const FILETIME,
) SetFileTimeError!void {
    const rc = kernel32.SetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
    if (rc == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const LockFileError = error{
    SystemResources,
    WouldBlock,
} || UnexpectedError;

pub fn LockFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?*IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ByteOffset: *const LARGE_INTEGER,
    Length: *const LARGE_INTEGER,
    Key: ?*ULONG,
    FailImmediately: BOOLEAN,
    ExclusiveLock: BOOLEAN,
) !void {
    const rc = ntdll.NtLockFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        ByteOffset,
        Length,
        Key,
        FailImmediately,
        ExclusiveLock,
    );
    switch (rc) {
        .SUCCESS => return,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .LOCK_NOT_GRANTED => return error.WouldBlock,
        .ACCESS_VIOLATION => unreachable, // bad io_status_block pointer
        else => return unexpectedStatus(rc),
    }
}

pub const UnlockFileError = error{
    RangeNotLocked,
} || UnexpectedError;

pub fn UnlockFile(
    FileHandle: HANDLE,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ByteOffset: *const LARGE_INTEGER,
    Length: *const LARGE_INTEGER,
    Key: ?*ULONG,
) !void {
    const rc = ntdll.NtUnlockFile(FileHandle, IoStatusBlock, ByteOffset, Length, Key);
    switch (rc) {
        .SUCCESS => return,
        .RANGE_NOT_LOCKED => return error.RangeNotLocked,
        .ACCESS_VIOLATION => unreachable, // bad io_status_block pointer
        else => return unexpectedStatus(rc),
    }
}

/// This is a workaround for the C backend until zig has the ability to put
/// C code in inline assembly.
extern fn zig_thumb_windows_teb() callconv(.c) *anyopaque;
extern fn zig_aarch64_windows_teb() callconv(.c) *anyopaque;
extern fn zig_x86_windows_teb() callconv(.c) *anyopaque;
extern fn zig_x86_64_windows_teb() callconv(.c) *anyopaque;

pub fn teb() *TEB {
    return switch (native_arch) {
        .thumb => if (builtin.zig_backend == .stage2_c)
            @ptrCast(@alignCast(zig_thumb_windows_teb()))
        else
            asm (
                \\ mrc p15, 0, %[ptr], c13, c0, 2
                : [ptr] "=r" (-> *TEB),
            ),
        .aarch64 => if (builtin.zig_backend == .stage2_c)
            @ptrCast(@alignCast(zig_aarch64_windows_teb()))
        else
            asm (
                \\ mov %[ptr], x18
                : [ptr] "=r" (-> *TEB),
            ),
        .x86 => if (builtin.zig_backend == .stage2_c)
            @ptrCast(@alignCast(zig_x86_windows_teb()))
        else
            asm (
                \\ movl %%fs:0x18, %[ptr]
                : [ptr] "=r" (-> *TEB),
            ),
        .x86_64 => if (builtin.zig_backend == .stage2_c)
            @ptrCast(@alignCast(zig_x86_64_windows_teb()))
        else
            asm (
                \\ movq %%gs:0x30, %[ptr]
                : [ptr] "=r" (-> *TEB),
            ),
        else => @compileError("unsupported arch"),
    };
}

pub fn peb() *PEB {
    return teb().ProcessEnvironmentBlock;
}

/// A file time is a 64-bit value that represents the number of 100-nanosecond
/// intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated
/// Universal Time (UTC).
/// This function returns the number of nanoseconds since the canonical epoch,
/// which is the POSIX one (Jan 01, 1970 AD).
pub fn fromSysTime(hns: i64) i128 {
    const adjusted_epoch: i128 = hns + std.time.epoch.windows * (std.time.ns_per_s / 100);
    return adjusted_epoch * 100;
}

pub fn toSysTime(ns: i128) i64 {
    const hns = @divFloor(ns, 100);
    return @as(i64, @intCast(hns)) - std.time.epoch.windows * (std.time.ns_per_s / 100);
}

pub fn fileTimeToNanoSeconds(ft: FILETIME) i128 {
    const hns = (@as(i64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return fromSysTime(hns);
}

/// Converts a number of nanoseconds since the POSIX epoch to a Windows FILETIME.
pub fn nanoSecondsToFileTime(ns: i128) FILETIME {
    const adjusted: u64 = @bitCast(toSysTime(ns));
    return FILETIME{
        .dwHighDateTime = @as(u32, @truncate(adjusted >> 32)),
        .dwLowDateTime = @as(u32, @truncate(adjusted)),
    };
}

/// Compares two WTF16 strings using the equivalent functionality of
/// `RtlEqualUnicodeString` (with case insensitive comparison enabled).
/// This function can be called on any target.
pub fn eqlIgnoreCaseWTF16(a: []const u16, b: []const u16) bool {
    if (@inComptime() or builtin.os.tag != .windows) {
        // This function compares the strings code unit by code unit (aka u16-to-u16),
        // so any length difference implies inequality. In other words, there's no possible
        // conversion that changes the number of WTF-16 code units needed for the uppercase/lowercase
        // version in the conversion table since only codepoints <= max(u16) are eligible
        // for conversion at all.
        if (a.len != b.len) return false;

        for (a, b) |a_c, b_c| {
            // The slices are always WTF-16 LE, so need to convert the elements to native
            // endianness for the uppercasing
            const a_c_native = std.mem.littleToNative(u16, a_c);
            const b_c_native = std.mem.littleToNative(u16, b_c);
            if (a_c != b_c and nls.upcaseW(a_c_native) != nls.upcaseW(b_c_native)) {
                return false;
            }
        }
        return true;
    }
    // Use RtlEqualUnicodeString on Windows when not in comptime to avoid including a
    // redundant copy of the uppercase data.
    const a_bytes = @as(u16, @intCast(a.len * 2));
    const a_string = UNICODE_STRING{
        .Length = a_bytes,
        .MaximumLength = a_bytes,
        .Buffer = @constCast(a.ptr),
    };
    const b_bytes = @as(u16, @intCast(b.len * 2));
    const b_string = UNICODE_STRING{
        .Length = b_bytes,
        .MaximumLength = b_bytes,
        .Buffer = @constCast(b.ptr),
    };
    return ntdll.RtlEqualUnicodeString(&a_string, &b_string, TRUE) == TRUE;
}

/// Compares two WTF-8 strings using the equivalent functionality of
/// `RtlEqualUnicodeString` (with case insensitive comparison enabled).
/// This function can be called on any target.
/// Assumes `a` and `b` are valid WTF-8.
pub fn eqlIgnoreCaseWtf8(a: []const u8, b: []const u8) bool {
    // A length equality check is not possible here because there are
    // some codepoints that have a different length uppercase UTF-8 representations
    // than their lowercase counterparts, e.g. U+0250 (2 bytes) <-> U+2C6F (3 bytes).
    // There are 7 such codepoints in the uppercase data used by Windows.

    var a_wtf8_it = std.unicode.Wtf8View.initUnchecked(a).iterator();
    var b_wtf8_it = std.unicode.Wtf8View.initUnchecked(b).iterator();

    // Use RtlUpcaseUnicodeChar on Windows when not in comptime to avoid including a
    // redundant copy of the uppercase data.
    const upcaseImpl = switch (builtin.os.tag) {
        .windows => if (@inComptime()) nls.upcaseW else ntdll.RtlUpcaseUnicodeChar,
        else => nls.upcaseW,
    };

    while (true) {
        const a_cp = a_wtf8_it.nextCodepoint() orelse break;
        const b_cp = b_wtf8_it.nextCodepoint() orelse return false;

        if (a_cp <= std.math.maxInt(u16) and b_cp <= std.math.maxInt(u16)) {
            if (a_cp != b_cp and upcaseImpl(@intCast(a_cp)) != upcaseImpl(@intCast(b_cp))) {
                return false;
            }
        } else if (a_cp != b_cp) {
            return false;
        }
    }
    // Make sure there are no leftover codepoints in b
    if (b_wtf8_it.nextCodepoint() != null) return false;

    return true;
}

fn testEqlIgnoreCase(comptime expect_eql: bool, comptime a: []const u8, comptime b: []const u8) !void {
    try std.testing.expectEqual(expect_eql, eqlIgnoreCaseWtf8(a, b));
    try std.testing.expectEqual(expect_eql, eqlIgnoreCaseWTF16(
        std.unicode.utf8ToUtf16LeStringLiteral(a),
        std.unicode.utf8ToUtf16LeStringLiteral(b),
    ));

    try comptime std.testing.expect(expect_eql == eqlIgnoreCaseWtf8(a, b));
    try comptime std.testing.expect(expect_eql == eqlIgnoreCaseWTF16(
        std.unicode.utf8ToUtf16LeStringLiteral(a),
        std.unicode.utf8ToUtf16LeStringLiteral(b),
    ));
}

test "eqlIgnoreCaseWTF16/Wtf8" {
    try testEqlIgnoreCase(true, "\x01 a B Λ ɐ", "\x01 A b λ Ɐ");
    // does not do case-insensitive comparison for codepoints >= U+10000
    try testEqlIgnoreCase(false, "𐓏", "𐓷");
}

pub const PathSpace = struct {
    data: [PATH_MAX_WIDE:0]u16,
    len: usize,

    pub fn span(self: *const PathSpace) [:0]const u16 {
        return self.data[0..self.len :0];
    }
};

/// The error type for `removeDotDirsSanitized`
pub const RemoveDotDirsError = error{TooManyParentDirs};

/// Removes '.' and '..' path components from a "sanitized relative path".
/// A "sanitized path" is one where:
///    1) all forward slashes have been replaced with back slashes
///    2) all repeating back slashes have been collapsed
///    3) the path is a relative one (does not start with a back slash)
pub fn removeDotDirsSanitized(comptime T: type, path: []T) RemoveDotDirsError!usize {
    std.debug.assert(path.len == 0 or path[0] != '\\');

    var write_idx: usize = 0;
    var read_idx: usize = 0;
    while (read_idx < path.len) {
        if (path[read_idx] == '.') {
            if (read_idx + 1 == path.len)
                return write_idx;

            const after_dot = path[read_idx + 1];
            if (after_dot == '\\') {
                read_idx += 2;
                continue;
            }
            if (after_dot == '.' and (read_idx + 2 == path.len or path[read_idx + 2] == '\\')) {
                if (write_idx == 0) return error.TooManyParentDirs;
                std.debug.assert(write_idx >= 2);
                write_idx -= 1;
                while (true) {
                    write_idx -= 1;
                    if (write_idx == 0) break;
                    if (path[write_idx] == '\\') {
                        write_idx += 1;
                        break;
                    }
                }
                if (read_idx + 2 == path.len)
                    return write_idx;
                read_idx += 3;
                continue;
            }
        }

        // skip to the next path separator
        while (true) : (read_idx += 1) {
            if (read_idx == path.len)
                return write_idx;
            path[write_idx] = path[read_idx];
            write_idx += 1;
            if (path[read_idx] == '\\')
                break;
        }
        read_idx += 1;
    }
    return write_idx;
}

/// Normalizes a Windows path with the following steps:
///     1) convert all forward slashes to back slashes
///     2) collapse duplicate back slashes
///     3) remove '.' and '..' directory parts
/// Returns the length of the new path.
pub fn normalizePath(comptime T: type, path: []T) RemoveDotDirsError!usize {
    mem.replaceScalar(T, path, '/', '\\');
    const new_len = mem.collapseRepeatsLen(T, path, '\\');

    const prefix_len: usize = init: {
        if (new_len >= 1 and path[0] == '\\') break :init 1;
        if (new_len >= 2 and path[1] == ':')
            break :init if (new_len >= 3 and path[2] == '\\') @as(usize, 3) else @as(usize, 2);
        break :init 0;
    };

    return prefix_len + try removeDotDirsSanitized(T, path[prefix_len..new_len]);
}

pub const Wtf8ToPrefixedFileWError = error{InvalidWtf8} || Wtf16ToPrefixedFileWError;

/// Same as `sliceToPrefixedFileW` but accepts a pointer
/// to a null-terminated WTF-8 encoded path.
/// https://simonsapin.github.io/wtf-8/
pub fn cStrToPrefixedFileW(dir: ?HANDLE, s: [*:0]const u8) Wtf8ToPrefixedFileWError!PathSpace {
    return sliceToPrefixedFileW(dir, mem.sliceTo(s, 0));
}

/// Same as `wToPrefixedFileW` but accepts a WTF-8 encoded path.
/// https://simonsapin.github.io/wtf-8/
pub fn sliceToPrefixedFileW(dir: ?HANDLE, path: []const u8) Wtf8ToPrefixedFileWError!PathSpace {
    var temp_path: PathSpace = undefined;
    temp_path.len = try std.unicode.wtf8ToWtf16Le(&temp_path.data, path);
    temp_path.data[temp_path.len] = 0;
    return wToPrefixedFileW(dir, temp_path.span());
}

pub const Wtf16ToPrefixedFileWError = error{
    AccessDenied,
    BadPathName,
    FileNotFound,
    NameTooLong,
    Unexpected,
};

/// Converts the `path` to WTF16, null-terminated. If the path contains any
/// namespace prefix, or is anything but a relative path (rooted, drive relative,
/// etc) the result will have the NT-style prefix `\??\`.
///
/// Similar to RtlDosPathNameToNtPathName_U with a few differences:
/// - Does not allocate on the heap.
/// - Relative paths are kept as relative unless they contain too many ..
///   components, in which case they are resolved against the `dir` if it
///   is non-null, or the CWD if it is null.
/// - Special case device names like COM1, NUL, etc are not handled specially (TODO)
/// - . and space are not stripped from the end of relative paths (potential TODO)
pub fn wToPrefixedFileW(dir: ?HANDLE, path: [:0]const u16) Wtf16ToPrefixedFileWError!PathSpace {
    const nt_prefix = [_]u16{ '\\', '?', '?', '\\' };
    switch (getNamespacePrefix(u16, path)) {
        // TODO: Figure out a way to design an API that can avoid the copy for .nt,
        //       since it is always returned fully unmodified.
        .nt, .verbatim => {
            var path_space: PathSpace = undefined;
            path_space.data[0..nt_prefix.len].* = nt_prefix;
            const len_after_prefix = path.len - nt_prefix.len;
            @memcpy(path_space.data[nt_prefix.len..][0..len_after_prefix], path[nt_prefix.len..]);
            path_space.len = path.len;
            path_space.data[path_space.len] = 0;
            return path_space;
        },
        .local_device, .fake_verbatim => {
            var path_space: PathSpace = undefined;
            const path_byte_len = ntdll.RtlGetFullPathName_U(
                path.ptr,
                path_space.data.len * 2,
                &path_space.data,
                null,
            );
            if (path_byte_len == 0) {
                // TODO: This may not be the right error
                return error.BadPathName;
            } else if (path_byte_len / 2 > path_space.data.len) {
                return error.NameTooLong;
            }
            path_space.len = path_byte_len / 2;
            // Both prefixes will be normalized but retained, so all
            // we need to do now is replace them with the NT prefix
            path_space.data[0..nt_prefix.len].* = nt_prefix;
            return path_space;
        },
        .none => {
            const path_type = getUnprefixedPathType(u16, path);
            var path_space: PathSpace = undefined;
            relative: {
                if (path_type == .relative) {
                    // TODO: Handle special case device names like COM1, AUX, NUL, CONIN$, CONOUT$, etc.
                    //       See https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html

                    // TODO: Potentially strip all trailing . and space characters from the
                    //       end of the path. This is something that both RtlDosPathNameToNtPathName_U
                    //       and RtlGetFullPathName_U do. Technically, trailing . and spaces
                    //       are allowed, but such paths may not interact well with Windows (i.e.
                    //       files with these paths can't be deleted from explorer.exe, etc).
                    //       This could be something that normalizePath may want to do.

                    @memcpy(path_space.data[0..path.len], path);
                    // Try to normalize, but if we get too many parent directories,
                    // then we need to start over and use RtlGetFullPathName_U instead.
                    path_space.len = normalizePath(u16, path_space.data[0..path.len]) catch |err| switch (err) {
                        error.TooManyParentDirs => break :relative,
                    };
                    path_space.data[path_space.len] = 0;
                    return path_space;
                }
            }
            // We now know we are going to return an absolute NT path, so
            // we can unconditionally prefix it with the NT prefix.
            path_space.data[0..nt_prefix.len].* = nt_prefix;
            if (path_type == .root_local_device) {
                // `\\.` and `\\?` always get converted to `\??\` exactly, so
                // we can just stop here
                path_space.len = nt_prefix.len;
                path_space.data[path_space.len] = 0;
                return path_space;
            }
            const path_buf_offset = switch (path_type) {
                // UNC paths will always start with `\\`. However, we want to
                // end up with something like `\??\UNC\server\share`, so to get
                // RtlGetFullPathName to write into the spot we want the `server`
                // part to end up, we need to provide an offset such that
                // the `\\` part gets written where the `C\` of `UNC\` will be
                // in the final NT path.
                .unc_absolute => nt_prefix.len + 2,
                else => nt_prefix.len,
            };
            const buf_len: u32 = @intCast(path_space.data.len - path_buf_offset);
            const path_to_get: [:0]const u16 = path_to_get: {
                // If dir is null, then we don't need to bother with GetFinalPathNameByHandle because
                // RtlGetFullPathName_U will resolve relative paths against the CWD for us.
                if (path_type != .relative or dir == null) {
                    break :path_to_get path;
                }
                // We can also skip GetFinalPathNameByHandle if the handle matches
                // the handle returned by fs.cwd()
                if (dir.? == std.fs.cwd().fd) {
                    break :path_to_get path;
                }
                // At this point, we know we have a relative path that had too many
                // `..` components to be resolved by normalizePath, so we need to
                // convert it into an absolute path and let RtlGetFullPathName_U
                // canonicalize it. We do this by getting the path of the `dir`
                // and appending the relative path to it.
                var dir_path_buf: [PATH_MAX_WIDE:0]u16 = undefined;
                const dir_path = GetFinalPathNameByHandle(dir.?, .{}, &dir_path_buf) catch |err| switch (err) {
                    // This mapping is not correct; it is actually expected
                    // that calling GetFinalPathNameByHandle might return
                    // error.UnrecognizedVolume, and in fact has been observed
                    // in the wild. The problem is that wToPrefixedFileW was
                    // never intended to make *any* OS syscall APIs. It's only
                    // supposed to convert a string to one that is eligible to
                    // be used in the ntdll syscalls.
                    //
                    // To solve this, this function needs to no longer call
                    // GetFinalPathNameByHandle under any conditions, or the
                    // calling function needs to get reworked to not need to
                    // call this function.
                    //
                    // This may involve making breaking API changes.
                    error.UnrecognizedVolume => return error.Unexpected,
                    else => |e| return e,
                };
                if (dir_path.len + 1 + path.len > PATH_MAX_WIDE) {
                    return error.NameTooLong;
                }
                // We don't have to worry about potentially doubling up path separators
                // here since RtlGetFullPathName_U will handle canonicalizing it.
                dir_path_buf[dir_path.len] = '\\';
                @memcpy(dir_path_buf[dir_path.len + 1 ..][0..path.len], path);
                const full_len = dir_path.len + 1 + path.len;
                dir_path_buf[full_len] = 0;
                break :path_to_get dir_path_buf[0..full_len :0];
            };
            const path_byte_len = ntdll.RtlGetFullPathName_U(
                path_to_get.ptr,
                buf_len * 2,
                path_space.data[path_buf_offset..].ptr,
                null,
            );
            if (path_byte_len == 0) {
                // TODO: This may not be the right error
                return error.BadPathName;
            } else if (path_byte_len / 2 > buf_len) {
                return error.NameTooLong;
            }
            path_space.len = path_buf_offset + (path_byte_len / 2);
            if (path_type == .unc_absolute) {
                // Now add in the UNC, the `C` should overwrite the first `\` of the
                // FullPathName, ultimately resulting in `\??\UNC\<the rest of the path>`
                std.debug.assert(path_space.data[path_buf_offset] == '\\');
                std.debug.assert(path_space.data[path_buf_offset + 1] == '\\');
                const unc = [_]u16{ 'U', 'N', 'C' };
                path_space.data[nt_prefix.len..][0..unc.len].* = unc;
            }
            return path_space;
        },
    }
}

pub const NamespacePrefix = enum {
    none,
    /// `\\.\` (path separators can be `\` or `/`)
    local_device,
    /// `\\?\`
    /// When converted to an NT path, everything past the prefix is left
    /// untouched and `\\?\` is replaced by `\??\`.
    verbatim,
    /// `\\?\` without all path separators being `\`.
    /// This seems to be recognized as a prefix, but the 'verbatim' aspect
    /// is not respected (i.e. if `//?/C:/foo` is converted to an NT path,
    /// it will become `\??\C:\foo` [it will be canonicalized and the //?/ won't
    /// be treated as part of the final path])
    fake_verbatim,
    /// `\??\`
    nt,
};

/// If `T` is `u16`, then `path` should be encoded as WTF-16LE.
pub fn getNamespacePrefix(comptime T: type, path: []const T) NamespacePrefix {
    if (path.len < 4) return .none;
    var all_backslash = switch (mem.littleToNative(T, path[0])) {
        '\\' => true,
        '/' => false,
        else => return .none,
    };
    all_backslash = all_backslash and switch (mem.littleToNative(T, path[3])) {
        '\\' => true,
        '/' => false,
        else => return .none,
    };
    switch (mem.littleToNative(T, path[1])) {
        '?' => if (mem.littleToNative(T, path[2]) == '?' and all_backslash) return .nt else return .none,
        '\\' => {},
        '/' => all_backslash = false,
        else => return .none,
    }
    return switch (mem.littleToNative(T, path[2])) {
        '?' => if (all_backslash) .verbatim else .fake_verbatim,
        '.' => .local_device,
        else => .none,
    };
}

test getNamespacePrefix {
    try std.testing.expectEqual(NamespacePrefix.none, getNamespacePrefix(u8, ""));
    try std.testing.expectEqual(NamespacePrefix.nt, getNamespacePrefix(u8, "\\??\\"));
    try std.testing.expectEqual(NamespacePrefix.none, getNamespacePrefix(u8, "/??/"));
    try std.testing.expectEqual(NamespacePrefix.none, getNamespacePrefix(u8, "/??\\"));
    try std.testing.expectEqual(NamespacePrefix.none, getNamespacePrefix(u8, "\\?\\\\"));
    try std.testing.expectEqual(NamespacePrefix.local_device, getNamespacePrefix(u8, "\\\\.\\"));
    try std.testing.expectEqual(NamespacePrefix.local_device, getNamespacePrefix(u8, "\\\\./"));
    try std.testing.expectEqual(NamespacePrefix.local_device, getNamespacePrefix(u8, "/\\./"));
    try std.testing.expectEqual(NamespacePrefix.local_device, getNamespacePrefix(u8, "//./"));
    try std.testing.expectEqual(NamespacePrefix.none, getNamespacePrefix(u8, "/.//"));
    try std.testing.expectEqual(NamespacePrefix.verbatim, getNamespacePrefix(u8, "\\\\?\\"));
    try std.testing.expectEqual(NamespacePrefix.fake_verbatim, getNamespacePrefix(u8, "\\/?\\"));
    try std.testing.expectEqual(NamespacePrefix.fake_verbatim, getNamespacePrefix(u8, "\\/?/"));
    try std.testing.expectEqual(NamespacePrefix.fake_verbatim, getNamespacePrefix(u8, "//?/"));
}

pub const UnprefixedPathType = enum {
    unc_absolute,
    drive_absolute,
    drive_relative,
    rooted,
    relative,
    root_local_device,
};

/// Get the path type of a path that is known to not have any namespace prefixes
/// (`\\?\`, `\\.\`, `\??\`).
/// If `T` is `u16`, then `path` should be encoded as WTF-16LE.
pub fn getUnprefixedPathType(comptime T: type, path: []const T) UnprefixedPathType {
    if (path.len < 1) return .relative;

    if (std.debug.runtime_safety) {
        std.debug.assert(getNamespacePrefix(T, path) == .none);
    }

    const windows_path = std.fs.path.PathType.windows;
    if (windows_path.isSep(T, mem.littleToNative(T, path[0]))) {
        // \x
        if (path.len < 2 or !windows_path.isSep(T, mem.littleToNative(T, path[1]))) return .rooted;
        // exactly \\. or \\? with nothing trailing
        if (path.len == 3 and (mem.littleToNative(T, path[2]) == '.' or mem.littleToNative(T, path[2]) == '?')) return .root_local_device;
        // \\x
        return .unc_absolute;
    } else {
        // x
        if (path.len < 2 or mem.littleToNative(T, path[1]) != ':') return .relative;
        // x:\
        if (path.len > 2 and windows_path.isSep(T, mem.littleToNative(T, path[2]))) return .drive_absolute;
        // x:
        return .drive_relative;
    }
}

test getUnprefixedPathType {
    try std.testing.expectEqual(UnprefixedPathType.relative, getUnprefixedPathType(u8, ""));
    try std.testing.expectEqual(UnprefixedPathType.relative, getUnprefixedPathType(u8, "x"));
    try std.testing.expectEqual(UnprefixedPathType.relative, getUnprefixedPathType(u8, "x\\"));
    try std.testing.expectEqual(UnprefixedPathType.root_local_device, getUnprefixedPathType(u8, "//."));
    try std.testing.expectEqual(UnprefixedPathType.root_local_device, getUnprefixedPathType(u8, "/\\?"));
    try std.testing.expectEqual(UnprefixedPathType.root_local_device, getUnprefixedPathType(u8, "\\\\?"));
    try std.testing.expectEqual(UnprefixedPathType.unc_absolute, getUnprefixedPathType(u8, "\\\\x"));
    try std.testing.expectEqual(UnprefixedPathType.unc_absolute, getUnprefixedPathType(u8, "//x"));
    try std.testing.expectEqual(UnprefixedPathType.rooted, getUnprefixedPathType(u8, "\\x"));
    try std.testing.expectEqual(UnprefixedPathType.rooted, getUnprefixedPathType(u8, "/"));
    try std.testing.expectEqual(UnprefixedPathType.drive_relative, getUnprefixedPathType(u8, "x:"));
    try std.testing.expectEqual(UnprefixedPathType.drive_relative, getUnprefixedPathType(u8, "x:abc"));
    try std.testing.expectEqual(UnprefixedPathType.drive_relative, getUnprefixedPathType(u8, "x:a/b/c"));
    try std.testing.expectEqual(UnprefixedPathType.drive_absolute, getUnprefixedPathType(u8, "x:\\"));
    try std.testing.expectEqual(UnprefixedPathType.drive_absolute, getUnprefixedPathType(u8, "x:\\abc"));
    try std.testing.expectEqual(UnprefixedPathType.drive_absolute, getUnprefixedPathType(u8, "x:/a/b/c"));
}

/// Similar to `RtlNtPathNameToDosPathName` but does not do any heap allocation.
/// The possible transformations are:
///   \??\C:\Some\Path -> C:\Some\Path
///   \??\UNC\server\share\foo -> \\server\share\foo
/// If the path does not have the NT namespace prefix, then `error.NotNtPath` is returned.
///
/// Functionality is based on the ReactOS test cases found here:
/// https://github.com/reactos/reactos/blob/master/modules/rostests/apitests/ntdll/RtlNtPathNameToDosPathName.c
///
/// `path` should be encoded as WTF-16LE.
pub fn ntToWin32Namespace(path: []const u16) !PathSpace {
    if (path.len > PATH_MAX_WIDE) return error.NameTooLong;

    var path_space: PathSpace = undefined;
    const namespace_prefix = getNamespacePrefix(u16, path);
    switch (namespace_prefix) {
        .nt => {
            var dest_index: usize = 0;
            var after_prefix = path[4..]; // after the `\??\`
            // The prefix \??\UNC\ means this is a UNC path, in which case the
            // `\??\UNC\` should be replaced by `\\` (two backslashes)
            // TODO: the "UNC" should technically be matched case-insensitively, but
            //       it's unlikely to matter since most/all paths passed into this
            //       function will have come from the OS meaning it should have
            //       the 'canonical' uppercase UNC.
            const is_unc = after_prefix.len >= 4 and
                std.mem.eql(u16, after_prefix[0..3], std.unicode.utf8ToUtf16LeStringLiteral("UNC")) and
                std.fs.path.PathType.windows.isSep(u16, std.mem.littleToNative(u16, after_prefix[3]));
            if (is_unc) {
                path_space.data[0] = comptime std.mem.nativeToLittle(u16, '\\');
                dest_index += 1;
                // We want to include the last `\` of `\??\UNC\`
                after_prefix = path[7..];
            }
            @memcpy(path_space.data[dest_index..][0..after_prefix.len], after_prefix);
            path_space.len = dest_index + after_prefix.len;
            path_space.data[path_space.len] = 0;
            return path_space;
        },
        else => return error.NotNtPath,
    }
}

test ntToWin32Namespace {
    const L = std.unicode.utf8ToUtf16LeStringLiteral;

    try testNtToWin32Namespace(L("UNC"), L("\\??\\UNC"));
    try testNtToWin32Namespace(L("\\\\"), L("\\??\\UNC\\"));
    try testNtToWin32Namespace(L("\\\\path1"), L("\\??\\UNC\\path1"));
    try testNtToWin32Namespace(L("\\\\path1\\path2"), L("\\??\\UNC\\path1\\path2"));

    try testNtToWin32Namespace(L(""), L("\\??\\"));
    try testNtToWin32Namespace(L("C:"), L("\\??\\C:"));
    try testNtToWin32Namespace(L("C:\\"), L("\\??\\C:\\"));
    try testNtToWin32Namespace(L("C:\\test"), L("\\??\\C:\\test"));
    try testNtToWin32Namespace(L("C:\\test\\"), L("\\??\\C:\\test\\"));

    try std.testing.expectError(error.NotNtPath, ntToWin32Namespace(L("foo")));
    try std.testing.expectError(error.NotNtPath, ntToWin32Namespace(L("C:\\test")));
    try std.testing.expectError(error.NotNtPath, ntToWin32Namespace(L("\\\\.\\test")));
}

fn testNtToWin32Namespace(expected: []const u16, path: []const u16) !void {
    const converted = try ntToWin32Namespace(path);
    try std.testing.expectEqualSlices(u16, expected, converted.span());
}

fn getFullPathNameW(path: [*:0]const u16, out: []u16) !usize {
    const result = kernel32.GetFullPathNameW(path, @as(u32, @intCast(out.len)), out.ptr, null);
    if (result == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return result;
}

inline fn MAKELANGID(p: c_ushort, s: c_ushort) LANGID {
    return (s << 10) | p;
}

/// Loads a Winsock extension function in runtime specified by a GUID.
pub fn loadWinsockExtensionFunction(comptime T: type, sock: ws2_32.SOCKET, guid: GUID) !T {
    var function: T = undefined;
    var num_bytes: DWORD = undefined;

    const rc = ws2_32.WSAIoctl(
        sock,
        ws2_32.SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid,
        @sizeOf(GUID),
        @as(?*anyopaque, @ptrFromInt(@intFromPtr(&function))),
        @sizeOf(T),
        &num_bytes,
        null,
        null,
    );

    if (rc == ws2_32.SOCKET_ERROR) {
        return switch (ws2_32.WSAGetLastError()) {
            .WSAEOPNOTSUPP => error.OperationNotSupported,
            .WSAENOTSOCK => error.FileDescriptorNotASocket,
            else => |err| unexpectedWSAError(err),
        };
    }

    if (num_bytes != @sizeOf(T)) {
        return error.ShortRead;
    }

    return function;
}

/// Call this when you made a windows DLL call or something that does SetLastError
/// and you get an unexpected error.
pub fn unexpectedError(err: Win32Error) UnexpectedError {
    if (std.posix.unexpected_error_tracing) {
        // 614 is the length of the longest windows error description
        var buf_wstr: [614:0]WCHAR = undefined;
        const len = kernel32.FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null,
            err,
            MAKELANGID(LANG.NEUTRAL, SUBLANG.DEFAULT),
            &buf_wstr,
            buf_wstr.len,
            null,
        );
        std.debug.print("error.Unexpected: GetLastError({}): {}\n", .{
            @intFromEnum(err),
            std.unicode.fmtUtf16Le(buf_wstr[0..len]),
        });
        std.debug.dumpCurrentStackTrace(@returnAddress());
    }
    return error.Unexpected;
}

pub fn unexpectedWSAError(err: ws2_32.WinsockError) UnexpectedError {
    return unexpectedError(@as(Win32Error, @enumFromInt(@intFromEnum(err))));
}

/// Call this when you made a windows NtDll call
/// and you get an unexpected status.
pub fn unexpectedStatus(status: NTSTATUS) UnexpectedError {
    if (std.posix.unexpected_error_tracing) {
        std.debug.print("error.Unexpected NTSTATUS=0x{x}\n", .{@intFromEnum(status)});
        std.debug.dumpCurrentStackTrace(@returnAddress());
    }
    return error.Unexpected;
}

pub const Win32Error = @import("windows/win32error.zig").Win32Error;
pub const NTSTATUS = @import("windows/ntstatus.zig").NTSTATUS;
pub const LANG = @import("windows/lang.zig");
pub const SUBLANG = @import("windows/sublang.zig");

/// The standard input device. Initially, this is the console input buffer, CONIN$.
pub const STD_INPUT_HANDLE = maxInt(DWORD) - 10 + 1;

/// The standard output device. Initially, this is the active console screen buffer, CONOUT$.
pub const STD_OUTPUT_HANDLE = maxInt(DWORD) - 11 + 1;

/// The standard error device. Initially, this is the active console screen buffer, CONOUT$.
pub const STD_ERROR_HANDLE = maxInt(DWORD) - 12 + 1;

/// Deprecated; use `std.builtin.CallingConvention.winapi` instead.
pub const WINAPI: std.builtin.CallingConvention = .winapi;

pub const BOOL = c_int;
pub const BOOLEAN = BYTE;
pub const BYTE = u8;
pub const CHAR = u8;
pub const UCHAR = u8;
pub const FLOAT = f32;
pub const HANDLE = *anyopaque;
pub const HCRYPTPROV = ULONG_PTR;
pub const ATOM = u16;
pub const HBRUSH = *opaque {};
pub const HCURSOR = *opaque {};
pub const HICON = *opaque {};
pub const HINSTANCE = *opaque {};
pub const HMENU = *opaque {};
pub const HMODULE = *opaque {};
pub const HWND = *opaque {};
pub const HDC = *opaque {};
pub const HGLRC = *opaque {};
pub const FARPROC = *opaque {};
pub const PROC = *opaque {};
pub const INT = c_int;
pub const LPCSTR = [*:0]const CHAR;
pub const LPCVOID = *const anyopaque;
pub const LPSTR = [*:0]CHAR;
pub const LPVOID = *anyopaque;
pub const LPWSTR = [*:0]WCHAR;
pub const LPCWSTR = [*:0]const WCHAR;
pub const PVOID = *anyopaque;
pub const PWSTR = [*:0]WCHAR;
pub const PCWSTR = [*:0]const WCHAR;
/// Allocated by SysAllocString, freed by SysFreeString
pub const BSTR = [*:0]WCHAR;
pub const SIZE_T = usize;
pub const UINT = c_uint;
pub const ULONG_PTR = usize;
pub const LONG_PTR = isize;
pub const DWORD_PTR = ULONG_PTR;
pub const WCHAR = u16;
pub const WORD = u16;
pub const DWORD = u32;
pub const DWORD64 = u64;
pub const LARGE_INTEGER = i64;
pub const ULARGE_INTEGER = u64;
pub const USHORT = u16;
pub const SHORT = i16;
pub const ULONG = u32;
pub const LONG = i32;
pub const ULONG64 = u64;
pub const ULONGLONG = u64;
pub const LONGLONG = i64;
pub const HLOCAL = HANDLE;
pub const LANGID = c_ushort;

pub const WPARAM = usize;
pub const LPARAM = LONG_PTR;
pub const LRESULT = LONG_PTR;

pub const va_list = *opaque {};

pub const TCHAR = @compileError("Deprecated: choose between `CHAR` or `WCHAR` directly instead.");
pub const LPTSTR = @compileError("Deprecated: choose between `LPSTR` or `LPWSTR` directly instead.");
pub const LPCTSTR = @compileError("Deprecated: choose between `LPCSTR` or `LPCWSTR` directly instead.");
pub const PTSTR = @compileError("Deprecated: choose between `PSTR` or `PWSTR` directly instead.");
pub const PCTSTR = @compileError("Deprecated: choose between `PCSTR` or `PCWSTR` directly instead.");

pub const TRUE = 1;
pub const FALSE = 0;

pub const DEVICE_TYPE = ULONG;
pub const FILE_DEVICE_BEEP: DEVICE_TYPE = 0x0001;
pub const FILE_DEVICE_CD_ROM: DEVICE_TYPE = 0x0002;
pub const FILE_DEVICE_CD_ROM_FILE_SYSTEM: DEVICE_TYPE = 0x0003;
pub const FILE_DEVICE_CONTROLLER: DEVICE_TYPE = 0x0004;
pub const FILE_DEVICE_DATALINK: DEVICE_TYPE = 0x0005;
pub const FILE_DEVICE_DFS: DEVICE_TYPE = 0x0006;
pub const FILE_DEVICE_DISK: DEVICE_TYPE = 0x0007;
pub const FILE_DEVICE_DISK_FILE_SYSTEM: DEVICE_TYPE = 0x0008;
pub const FILE_DEVICE_FILE_SYSTEM: DEVICE_TYPE = 0x0009;
pub const FILE_DEVICE_INPORT_PORT: DEVICE_TYPE = 0x000a;
pub const FILE_DEVICE_KEYBOARD: DEVICE_TYPE = 0x000b;
pub const FILE_DEVICE_MAILSLOT: DEVICE_TYPE = 0x000c;
pub const FILE_DEVICE_MIDI_IN: DEVICE_TYPE = 0x000d;
pub const FILE_DEVICE_MIDI_OUT: DEVICE_TYPE = 0x000e;
pub const FILE_DEVICE_MOUSE: DEVICE_TYPE = 0x000f;
pub const FILE_DEVICE_MULTI_UNC_PROVIDER: DEVICE_TYPE = 0x0010;
pub const FILE_DEVICE_NAMED_PIPE: DEVICE_TYPE = 0x0011;
pub const FILE_DEVICE_NETWORK: DEVICE_TYPE = 0x0012;
pub const FILE_DEVICE_NETWORK_BROWSER: DEVICE_TYPE = 0x0013;
pub const FILE_DEVICE_NETWORK_FILE_SYSTEM: DEVICE_TYPE = 0x0014;
pub const FILE_DEVICE_NULL: DEVICE_TYPE = 0x0015;
pub const FILE_DEVICE_PARALLEL_PORT: DEVICE_TYPE = 0x0016;
pub const FILE_DEVICE_PHYSICAL_NETCARD: DEVICE_TYPE = 0x0017;
pub const FILE_DEVICE_PRINTER: DEVICE_TYPE = 0x0018;
pub const FILE_DEVICE_SCANNER: DEVICE_TYPE = 0x0019;
pub const FILE_DEVICE_SERIAL_MOUSE_PORT: DEVICE_TYPE = 0x001a;
pub const FILE_DEVICE_SERIAL_PORT: DEVICE_TYPE = 0x001b;
pub const FILE_DEVICE_SCREEN: DEVICE_TYPE = 0x001c;
pub const FILE_DEVICE_SOUND: DEVICE_TYPE = 0x001d;
pub const FILE_DEVICE_STREAMS: DEVICE_TYPE = 0x001e;
pub const FILE_DEVICE_TAPE: DEVICE_TYPE = 0x001f;
pub const FILE_DEVICE_TAPE_FILE_SYSTEM: DEVICE_TYPE = 0x0020;
pub const FILE_DEVICE_TRANSPORT: DEVICE_TYPE = 0x0021;
pub const FILE_DEVICE_UNKNOWN: DEVICE_TYPE = 0x0022;
pub const FILE_DEVICE_VIDEO: DEVICE_TYPE = 0x0023;
pub const FILE_DEVICE_VIRTUAL_DISK: DEVICE_TYPE = 0x0024;
pub const FILE_DEVICE_WAVE_IN: DEVICE_TYPE = 0x0025;
pub const FILE_DEVICE_WAVE_OUT: DEVICE_TYPE = 0x0026;
pub const FILE_DEVICE_8042_PORT: DEVICE_TYPE = 0x0027;
pub const FILE_DEVICE_NETWORK_REDIRECTOR: DEVICE_TYPE = 0x0028;
pub const FILE_DEVICE_BATTERY: DEVICE_TYPE = 0x0029;
pub const FILE_DEVICE_BUS_EXTENDER: DEVICE_TYPE = 0x002a;
pub const FILE_DEVICE_MODEM: DEVICE_TYPE = 0x002b;
pub const FILE_DEVICE_VDM: DEVICE_TYPE = 0x002c;
pub const FILE_DEVICE_MASS_STORAGE: DEVICE_TYPE = 0x002d;
pub const FILE_DEVICE_SMB: DEVICE_TYPE = 0x002e;
pub const FILE_DEVICE_KS: DEVICE_TYPE = 0x002f;
pub const FILE_DEVICE_CHANGER: DEVICE_TYPE = 0x0030;
pub const FILE_DEVICE_SMARTCARD: DEVICE_TYPE = 0x0031;
pub const FILE_DEVICE_ACPI: DEVICE_TYPE = 0x0032;
pub const FILE_DEVICE_DVD: DEVICE_TYPE = 0x0033;
pub const FILE_DEVICE_FULLSCREEN_VIDEO: DEVICE_TYPE = 0x0034;
pub const FILE_DEVICE_DFS_FILE_SYSTEM: DEVICE_TYPE = 0x0035;
pub const FILE_DEVICE_DFS_VOLUME: DEVICE_TYPE = 0x0036;
pub const FILE_DEVICE_SERENUM: DEVICE_TYPE = 0x0037;
pub const FILE_DEVICE_TERMSRV: DEVICE_TYPE = 0x0038;
pub const FILE_DEVICE_KSEC: DEVICE_TYPE = 0x0039;
pub const FILE_DEVICE_FIPS: DEVICE_TYPE = 0x003a;
pub const FILE_DEVICE_INFINIBAND: DEVICE_TYPE = 0x003b;
// TODO: missing values?
pub const FILE_DEVICE_VMBUS: DEVICE_TYPE = 0x003e;
pub const FILE_DEVICE_CRYPT_PROVIDER: DEVICE_TYPE = 0x003f;
pub const FILE_DEVICE_WPD: DEVICE_TYPE = 0x0040;
pub const FILE_DEVICE_BLUETOOTH: DEVICE_TYPE = 0x0041;
pub const FILE_DEVICE_MT_COMPOSITE: DEVICE_TYPE = 0x0042;
pub const FILE_DEVICE_MT_TRANSPORT: DEVICE_TYPE = 0x0043;
pub const FILE_DEVICE_BIOMETRIC: DEVICE_TYPE = 0x0044;
pub const FILE_DEVICE_PMI: DEVICE_TYPE = 0x0045;
pub const FILE_DEVICE_EHSTOR: DEVICE_TYPE = 0x0046;
pub const FILE_DEVICE_DEVAPI: DEVICE_TYPE = 0x0047;
pub const FILE_DEVICE_GPIO: DEVICE_TYPE = 0x0048;
pub const FILE_DEVICE_USBEX: DEVICE_TYPE = 0x0049;
pub const FILE_DEVICE_CONSOLE: DEVICE_TYPE = 0x0050;
pub const FILE_DEVICE_NFP: DEVICE_TYPE = 0x0051;
pub const FILE_DEVICE_SYSENV: DEVICE_TYPE = 0x0052;
pub const FILE_DEVICE_VIRTUAL_BLOCK: DEVICE_TYPE = 0x0053;
pub const FILE_DEVICE_POINT_OF_SERVICE: DEVICE_TYPE = 0x0054;
pub const FILE_DEVICE_STORAGE_REPLICATION: DEVICE_TYPE = 0x0055;
pub const FILE_DEVICE_TRUST_ENV: DEVICE_TYPE = 0x0056;
pub const FILE_DEVICE_UCM: DEVICE_TYPE = 0x0057;
pub const FILE_DEVICE_UCMTCPCI: DEVICE_TYPE = 0x0058;
pub const FILE_DEVICE_PERSISTENT_MEMORY: DEVICE_TYPE = 0x0059;
pub const FILE_DEVICE_NVDIMM: DEVICE_TYPE = 0x005a;
pub const FILE_DEVICE_HOLOGRAPHIC: DEVICE_TYPE = 0x005b;
pub const FILE_DEVICE_SDFXHCI: DEVICE_TYPE = 0x005c;

/// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes
pub const TransferType = enum(u2) {
    METHOD_BUFFERED = 0,
    METHOD_IN_DIRECT = 1,
    METHOD_OUT_DIRECT = 2,
    METHOD_NEITHER = 3,
};

pub const FILE_ANY_ACCESS = 0;
pub const FILE_READ_ACCESS = 1;
pub const FILE_WRITE_ACCESS = 2;

/// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
pub fn CTL_CODE(deviceType: u16, function: u12, method: TransferType, access: u2) DWORD {
    return (@as(DWORD, deviceType) << 16) |
        (@as(DWORD, access) << 14) |
        (@as(DWORD, function) << 2) |
        @intFromEnum(method);
}

pub const INVALID_HANDLE_VALUE = @as(HANDLE, @ptrFromInt(maxInt(usize)));

pub const INVALID_FILE_ATTRIBUTES = @as(DWORD, maxInt(DWORD));

pub const FILE_ALL_INFORMATION = extern struct {
    BasicInformation: FILE_BASIC_INFORMATION,
    StandardInformation: FILE_STANDARD_INFORMATION,
    InternalInformation: FILE_INTERNAL_INFORMATION,
    EaInformation: FILE_EA_INFORMATION,
    AccessInformation: FILE_ACCESS_INFORMATION,
    PositionInformation: FILE_POSITION_INFORMATION,
    ModeInformation: FILE_MODE_INFORMATION,
    AlignmentInformation: FILE_ALIGNMENT_INFORMATION,
    NameInformation: FILE_NAME_INFORMATION,
};

pub const FILE_BASIC_INFORMATION = extern struct {
    CreationTime: LARGE_INTEGER,
    LastAccessTime: LARGE_INTEGER,
    LastWriteTime: LARGE_INTEGER,
    ChangeTime: LARGE_INTEGER,
    FileAttributes: ULONG,
};

pub const FILE_STANDARD_INFORMATION = extern struct {
    AllocationSize: LARGE_INTEGER,
    EndOfFile: LARGE_INTEGER,
    NumberOfLinks: ULONG,
    DeletePending: BOOLEAN,
    Directory: BOOLEAN,
};

pub const FILE_INTERNAL_INFORMATION = extern struct {
    IndexNumber: LARGE_INTEGER,
};

pub const FILE_EA_INFORMATION = extern struct {
    EaSize: ULONG,
};

pub const FILE_ACCESS_INFORMATION = extern struct {
    AccessFlags: ACCESS_MASK,
};

pub const FILE_POSITION_INFORMATION = extern struct {
    CurrentByteOffset: LARGE_INTEGER,
};

pub const FILE_END_OF_FILE_INFORMATION = extern struct {
    EndOfFile: LARGE_INTEGER,
};

pub const FILE_MODE_INFORMATION = extern struct {
    Mode: ULONG,
};

pub const FILE_ALIGNMENT_INFORMATION = extern struct {
    AlignmentRequirement: ULONG,
};

pub const FILE_NAME_INFORMATION = extern struct {
    FileNameLength: ULONG,
    FileName: [1]WCHAR,
};

pub const FILE_DISPOSITION_INFORMATION_EX = extern struct {
    /// combination of FILE_DISPOSITION_* flags
    Flags: ULONG,
};

const FILE_DISPOSITION_DO_NOT_DELETE: ULONG = 0x00000000;
const FILE_DISPOSITION_DELETE: ULONG = 0x00000001;
const FILE_DISPOSITION_POSIX_SEMANTICS: ULONG = 0x00000002;
const FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK: ULONG = 0x00000004;
const FILE_DISPOSITION_ON_CLOSE: ULONG = 0x00000008;
const FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE: ULONG = 0x00000010;

// FILE_RENAME_INFORMATION.Flags
pub const FILE_RENAME_REPLACE_IF_EXISTS = 0x00000001;
pub const FILE_RENAME_POSIX_SEMANTICS = 0x00000002;
pub const FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE = 0x00000004;
pub const FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE = 0x00000008;
pub const FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE = 0x00000010;
pub const FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE = 0x00000020;
pub const FILE_RENAME_PRESERVE_AVAILABLE_SPACE = 0x00000030;
pub const FILE_RENAME_IGNORE_READONLY_ATTRIBUTE = 0x00000040;
pub const FILE_RENAME_FORCE_RESIZE_TARGET_SR = 0x00000080;
pub const FILE_RENAME_FORCE_RESIZE_SOURCE_SR = 0x00000100;
pub const FILE_RENAME_FORCE_RESIZE_SR = 0x00000180;

pub const FILE_RENAME_INFORMATION = extern struct {
    Flags: BOOLEAN,
    RootDirectory: ?HANDLE,
    FileNameLength: ULONG,
    FileName: [1]WCHAR,
};

// FileRenameInformationEx (since .win10_rs1)
pub const FILE_RENAME_INFORMATION_EX = extern struct {
    Flags: ULONG,
    RootDirectory: ?HANDLE,
    FileNameLength: ULONG,
    FileName: [1]WCHAR,
};

pub const IO_STATUS_BLOCK = extern struct {
    // "DUMMYUNIONNAME" expands to "u"
    u: extern union {
        Status: NTSTATUS,
        Pointer: ?*anyopaque,
    },
    Information: ULONG_PTR,
};

pub const FILE_INFORMATION_CLASS = enum(c_int) {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileDispositionInformationEx,
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation,
    FileStatInformation,
    FileMemoryPartitionInformation,
    FileStatLxInformation,
    FileCaseSensitiveInformation,
    FileLinkInformationEx,
    FileLinkInformationExBypassAccessCheck,
    FileStorageReserveIdInformation,
    FileCaseSensitiveInformationForceAccessCheck,
    FileMaximumInformation,
};

pub const FILE_ATTRIBUTE_TAG_INFO = extern struct {
    FileAttributes: DWORD,
    ReparseTag: DWORD,
};

/// "If this bit is set, the file or directory represents another named entity in the system."
/// https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags
pub const reparse_tag_name_surrogate_bit = 0x20000000;

pub const FILE_DISPOSITION_INFORMATION = extern struct {
    DeleteFile: BOOLEAN,
};

pub const FILE_FS_DEVICE_INFORMATION = extern struct {
    DeviceType: DEVICE_TYPE,
    Characteristics: ULONG,
};

pub const FILE_FS_VOLUME_INFORMATION = extern struct {
    VolumeCreationTime: LARGE_INTEGER,
    VolumeSerialNumber: ULONG,
    VolumeLabelLength: ULONG,
    SupportsObjects: BOOLEAN,
    // Flexible array member
    VolumeLabel: [1]WCHAR,
};

pub const FS_INFORMATION_CLASS = enum(c_int) {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsSectorSizeInformation,
    FileFsDataCopyInformation,
    FileFsMetadataSizeInformation,
    FileFsFullSizeInformationEx,
    FileFsMaximumInformation,
};

pub const OVERLAPPED = extern struct {
    Internal: ULONG_PTR,
    InternalHigh: ULONG_PTR,
    DUMMYUNIONNAME: extern union {
        DUMMYSTRUCTNAME: extern struct {
            Offset: DWORD,
            OffsetHigh: DWORD,
        },
        Pointer: ?PVOID,
    },
    hEvent: ?HANDLE,
};

pub const OVERLAPPED_ENTRY = extern struct {
    lpCompletionKey: ULONG_PTR,
    lpOverlapped: *OVERLAPPED,
    Internal: ULONG_PTR,
    dwNumberOfBytesTransferred: DWORD,
};

pub const MAX_PATH = 260;

pub const FILE_INFO_BY_HANDLE_CLASS = enum(u32) {
    FileBasicInfo = 0,
    FileStandardInfo = 1,
    FileNameInfo = 2,
    FileRenameInfo = 3,
    FileDispositionInfo = 4,
    FileAllocationInfo = 5,
    FileEndOfFileInfo = 6,
    FileStreamInfo = 7,
    FileCompressionInfo = 8,
    FileAttributeTagInfo = 9,
    FileIdBothDirectoryInfo = 10,
    FileIdBothDirectoryRestartInfo = 11,
    FileIoPriorityHintInfo = 12,
    FileRemoteProtocolInfo = 13,
    FileFullDirectoryInfo = 14,
    FileFullDirectoryRestartInfo = 15,
    FileStorageInfo = 16,
    FileAlignmentInfo = 17,
    FileIdInfo = 18,
    FileIdExtdDirectoryInfo = 19,
    FileIdExtdDirectoryRestartInfo = 20,
};

pub const BY_HANDLE_FILE_INFORMATION = extern struct {
    dwFileAttributes: DWORD,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    dwVolumeSerialNumber: DWORD,
    nFileSizeHigh: DWORD,
    nFileSizeLow: DWORD,
    nNumberOfLinks: DWORD,
    nFileIndexHigh: DWORD,
    nFileIndexLow: DWORD,
};

pub const FILE_NAME_INFO = extern struct {
    FileNameLength: DWORD,
    FileName: [1]WCHAR,
};

/// Return the normalized drive name. This is the default.
pub const FILE_NAME_NORMALIZED = 0x0;

/// Return the opened file name (not normalized).
pub const FILE_NAME_OPENED = 0x8;

/// Return the path with the drive letter. This is the default.
pub const VOLUME_NAME_DOS = 0x0;

/// Return the path with a volume GUID path instead of the drive name.
pub const VOLUME_NAME_GUID = 0x1;

/// Return the path with no drive information.
pub const VOLUME_NAME_NONE = 0x4;

/// Return the path with the volume device path.
pub const VOLUME_NAME_NT = 0x2;

pub const SECURITY_ATTRIBUTES = extern struct {
    nLength: DWORD,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: BOOL,
};

pub const PIPE_ACCESS_INBOUND = 0x00000001;
pub const PIPE_ACCESS_OUTBOUND = 0x00000002;
pub const PIPE_ACCESS_DUPLEX = 0x00000003;

pub const PIPE_TYPE_BYTE = 0x00000000;
pub const PIPE_TYPE_MESSAGE = 0x00000004;

pub const PIPE_READMODE_BYTE = 0x00000000;
pub const PIPE_READMODE_MESSAGE = 0x00000002;

pub const PIPE_WAIT = 0x00000000;
pub const PIPE_NOWAIT = 0x00000001;

pub const GENERIC_READ = 0x80000000;
pub const GENERIC_WRITE = 0x40000000;
pub const GENERIC_EXECUTE = 0x20000000;
pub const GENERIC_ALL = 0x10000000;

pub const FILE_SHARE_DELETE = 0x00000004;
pub const FILE_SHARE_READ = 0x00000001;
pub const FILE_SHARE_WRITE = 0x00000002;

pub const DELETE = 0x00010000;
pub const READ_CONTROL = 0x00020000;
pub const WRITE_DAC = 0x00040000;
pub const WRITE_OWNER = 0x00080000;
pub const SYNCHRONIZE = 0x00100000;
pub const STANDARD_RIGHTS_READ = READ_CONTROL;
pub const STANDARD_RIGHTS_WRITE = READ_CONTROL;
pub const STANDARD_RIGHTS_EXECUTE = READ_CONTROL;
pub const STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER;
pub const MAXIMUM_ALLOWED = 0x02000000;

// disposition for NtCreateFile
pub const FILE_SUPERSEDE = 0;
pub const FILE_OPEN = 1;
pub const FILE_CREATE = 2;
pub const FILE_OPEN_IF = 3;
pub const FILE_OVERWRITE = 4;
pub const FILE_OVERWRITE_IF = 5;
pub const FILE_MAXIMUM_DISPOSITION = 5;

// flags for NtCreateFile and NtOpenFile
pub const FILE_READ_DATA = 0x00000001;
pub const FILE_LIST_DIRECTORY = 0x00000001;
pub const FILE_WRITE_DATA = 0x00000002;
pub const FILE_ADD_FILE = 0x00000002;
pub const FILE_APPEND_DATA = 0x00000004;
pub const FILE_ADD_SUBDIRECTORY = 0x00000004;
pub const FILE_CREATE_PIPE_INSTANCE = 0x00000004;
pub const FILE_READ_EA = 0x00000008;
pub const FILE_WRITE_EA = 0x00000010;
pub const FILE_EXECUTE = 0x00000020;
pub const FILE_TRAVERSE = 0x00000020;
pub const FILE_DELETE_CHILD = 0x00000040;
pub const FILE_READ_ATTRIBUTES = 0x00000080;
pub const FILE_WRITE_ATTRIBUTES = 0x00000100;

pub const FILE_DIRECTORY_FILE = 0x00000001;
pub const FILE_WRITE_THROUGH = 0x00000002;
pub const FILE_SEQUENTIAL_ONLY = 0x00000004;
pub const FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008;
pub const FILE_SYNCHRONOUS_IO_ALERT = 0x00000010;
pub const FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
pub const FILE_NON_DIRECTORY_FILE = 0x00000040;
pub const FILE_CREATE_TREE_CONNECTION = 0x00000080;
pub const FILE_COMPLETE_IF_OPLOCKED = 0x00000100;
pub const FILE_NO_EA_KNOWLEDGE = 0x00000200;
pub const FILE_OPEN_FOR_RECOVERY = 0x00000400;
pub const FILE_RANDOM_ACCESS = 0x00000800;
pub const FILE_DELETE_ON_CLOSE = 0x00001000;
pub const FILE_OPEN_BY_FILE_ID = 0x00002000;
pub const FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000;
pub const FILE_NO_COMPRESSION = 0x00008000;
pub const FILE_RESERVE_OPFILTER = 0x00100000;
pub const FILE_OPEN_REPARSE_POINT = 0x00200000;
pub const FILE_OPEN_OFFLINE_FILE = 0x00400000;
pub const FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000;

pub const CREATE_ALWAYS = 2;
pub const CREATE_NEW = 1;
pub const OPEN_ALWAYS = 4;
pub const OPEN_EXISTING = 3;
pub const TRUNCATE_EXISTING = 5;

pub const FILE_ATTRIBUTE_ARCHIVE = 0x20;
pub const FILE_ATTRIBUTE_COMPRESSED = 0x800;
pub const FILE_ATTRIBUTE_DEVICE = 0x40;
pub const FILE_ATTRIBUTE_DIRECTORY = 0x10;
pub const FILE_ATTRIBUTE_ENCRYPTED = 0x4000;
pub const FILE_ATTRIBUTE_HIDDEN = 0x2;
pub const FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x8000;
pub const FILE_ATTRIBUTE_NORMAL = 0x80;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000;
pub const FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x20000;
pub const FILE_ATTRIBUTE_OFFLINE = 0x1000;
pub const FILE_ATTRIBUTE_READONLY = 0x1;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000;
pub const FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
pub const FILE_ATTRIBUTE_SPARSE_FILE = 0x200;
pub const FILE_ATTRIBUTE_SYSTEM = 0x4;
pub const FILE_ATTRIBUTE_TEMPORARY = 0x100;
pub const FILE_ATTRIBUTE_VIRTUAL = 0x10000;

pub const FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1ff;
pub const FILE_GENERIC_READ = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
pub const FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;
pub const FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;

// Flags for NtCreateNamedPipeFile
// NamedPipeType
pub const FILE_PIPE_BYTE_STREAM_TYPE = 0x0;
pub const FILE_PIPE_MESSAGE_TYPE = 0x1;
pub const FILE_PIPE_ACCEPT_REMOTE_CLIENTS = 0x0;
pub const FILE_PIPE_REJECT_REMOTE_CLIENTS = 0x2;
pub const FILE_PIPE_TYPE_VALID_MASK = 0x3;
// CompletionMode
pub const FILE_PIPE_QUEUE_OPERATION = 0x0;
pub const FILE_PIPE_COMPLETE_OPERATION = 0x1;
// ReadMode
pub const FILE_PIPE_BYTE_STREAM_MODE = 0x0;
pub const FILE_PIPE_MESSAGE_MODE = 0x1;

// flags for CreateEvent
pub const CREATE_EVENT_INITIAL_SET = 0x00000002;
pub const CREATE_EVENT_MANUAL_RESET = 0x00000001;

pub const EVENT_ALL_ACCESS = 0x1F0003;
pub const EVENT_MODIFY_STATE = 0x0002;

// MEMORY_BASIC_INFORMATION.Type flags for VirtualQuery
pub const MEM_IMAGE = 0x1000000;
pub const MEM_MAPPED = 0x40000;
pub const MEM_PRIVATE = 0x20000;

pub const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};

pub const STARTUPINFOW = extern struct {
    cb: DWORD,
    lpReserved: ?LPWSTR,
    lpDesktop: ?LPWSTR,
    lpTitle: ?LPWSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: WORD,
    cbReserved2: WORD,
    lpReserved2: ?*BYTE,
    hStdInput: ?HANDLE,
    hStdOutput: ?HANDLE,
    hStdError: ?HANDLE,
};

pub const STARTF_FORCEONFEEDBACK = 0x00000040;
pub const STARTF_FORCEOFFFEEDBACK = 0x00000080;
pub const STARTF_PREVENTPINNING = 0x00002000;
pub const STARTF_RUNFULLSCREEN = 0x00000020;
pub const STARTF_TITLEISAPPID = 0x00001000;
pub const STARTF_TITLEISLINKNAME = 0x00000800;
pub const STARTF_UNTRUSTEDSOURCE = 0x00008000;
pub const STARTF_USECOUNTCHARS = 0x00000008;
pub const STARTF_USEFILLATTRIBUTE = 0x00000010;
pub const STARTF_USEHOTKEY = 0x00000200;
pub const STARTF_USEPOSITION = 0x00000004;
pub const STARTF_USESHOWWINDOW = 0x00000001;
pub const STARTF_USESIZE = 0x00000002;
pub const STARTF_USESTDHANDLES = 0x00000100;

pub const INFINITE = 4294967295;

pub const MAXIMUM_WAIT_OBJECTS = 64;

pub const WAIT_ABANDONED = 0x00000080;
pub const WAIT_ABANDONED_0 = WAIT_ABANDONED + 0;
pub const WAIT_OBJECT_0 = 0x00000000;
pub const WAIT_TIMEOUT = 0x00000102;
pub const WAIT_FAILED = 0xFFFFFFFF;

pub const HANDLE_FLAG_INHERIT = 0x00000001;
pub const HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;

pub const MOVEFILE_COPY_ALLOWED = 2;
pub const MOVEFILE_CREATE_HARDLINK = 16;
pub const MOVEFILE_DELAY_UNTIL_REBOOT = 4;
pub const MOVEFILE_FAIL_IF_NOT_TRACKABLE = 32;
pub const MOVEFILE_REPLACE_EXISTING = 1;
pub const MOVEFILE_WRITE_THROUGH = 8;

pub const FILE_BEGIN = 0;
pub const FILE_CURRENT = 1;
pub const FILE_END = 2;

pub const HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;
pub const HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;
pub const HEAP_GENERATE_EXCEPTIONS = 0x00000004;
pub const HEAP_NO_SERIALIZE = 0x00000001;

// AllocationType values
pub const MEM_COMMIT = 0x1000;
pub const MEM_RESERVE = 0x2000;
pub const MEM_FREE = 0x10000;
pub const MEM_RESET = 0x80000;
pub const MEM_RESET_UNDO = 0x1000000;
pub const MEM_LARGE_PAGES = 0x20000000;
pub const MEM_PHYSICAL = 0x400000;
pub const MEM_TOP_DOWN = 0x100000;
pub const MEM_WRITE_WATCH = 0x200000;
pub const MEM_RESERVE_PLACEHOLDER = 0x00040000;
pub const MEM_PRESERVE_PLACEHOLDER = 0x00000400;

// Protect values
pub const PAGE_EXECUTE = 0x10;
pub const PAGE_EXECUTE_READ = 0x20;
pub const PAGE_EXECUTE_READWRITE = 0x40;
pub const PAGE_EXECUTE_WRITECOPY = 0x80;
pub const PAGE_NOACCESS = 0x01;
pub const PAGE_READONLY = 0x02;
pub const PAGE_READWRITE = 0x04;
pub const PAGE_WRITECOPY = 0x08;
pub const PAGE_TARGETS_INVALID = 0x40000000;
pub const PAGE_TARGETS_NO_UPDATE = 0x40000000; // Same as PAGE_TARGETS_INVALID
pub const PAGE_GUARD = 0x100;
pub const PAGE_NOCACHE = 0x200;
pub const PAGE_WRITECOMBINE = 0x400;

// FreeType values
pub const MEM_COALESCE_PLACEHOLDERS = 0x1;
pub const MEM_RESERVE_PLACEHOLDERS = 0x2;
pub const MEM_DECOMMIT = 0x4000;
pub const MEM_RELEASE = 0x8000;

pub const PTHREAD_START_ROUTINE = *const fn (LPVOID) callconv(.winapi) DWORD;
pub const LPTHREAD_START_ROUTINE = PTHREAD_START_ROUTINE;

pub const WIN32_FIND_DATAW = extern struct {
    dwFileAttributes: DWORD,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    nFileSizeHigh: DWORD,
    nFileSizeLow: DWORD,
    dwReserved0: DWORD,
    dwReserved1: DWORD,
    cFileName: [260]u16,
    cAlternateFileName: [14]u16,
};

pub const FILETIME = extern struct {
    dwLowDateTime: DWORD,
    dwHighDateTime: DWORD,
};

pub const SYSTEM_INFO = extern struct {
    anon1: extern union {
        dwOemId: DWORD,
        anon2: extern struct {
            wProcessorArchitecture: WORD,
            wReserved: WORD,
        },
    },
    dwPageSize: DWORD,
    lpMinimumApplicationAddress: LPVOID,
    lpMaximumApplicationAddress: LPVOID,
    dwActiveProcessorMask: DWORD_PTR,
    dwNumberOfProcessors: DWORD,
    dwProcessorType: DWORD,
    dwAllocationGranularity: DWORD,
    wProcessorLevel: WORD,
    wProcessorRevision: WORD,
};

pub const HRESULT = c_long;

pub const KNOWNFOLDERID = GUID;
pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,

    const hex_offsets = switch (builtin.target.cpu.arch.endian()) {
        .big => [16]u6{
            0,  2,  4,  6,
            9,  11, 14, 16,
            19, 21, 24, 26,
            28, 30, 32, 34,
        },
        .little => [16]u6{
            6,  4,  2,  0,
            11, 9,  16, 14,
            19, 21, 24, 26,
            28, 30, 32, 34,
        },
    };

    pub fn parse(s: []const u8) GUID {
        assert(s[0] == '{');
        assert(s[37] == '}');
        return parseNoBraces(s[1 .. s.len - 1]) catch @panic("invalid GUID string");
    }

    pub fn parseNoBraces(s: []const u8) !GUID {
        assert(s.len == 36);
        assert(s[8] == '-');
        assert(s[13] == '-');
        assert(s[18] == '-');
        assert(s[23] == '-');
        var bytes: [16]u8 = undefined;
        for (hex_offsets, 0..) |hex_offset, i| {
            bytes[i] = (try std.fmt.charToDigit(s[hex_offset], 16)) << 4 |
                try std.fmt.charToDigit(s[hex_offset + 1], 16);
        }
        return @as(GUID, @bitCast(bytes));
    }
};

test GUID {
    try std.testing.expectEqual(
        GUID{
            .Data1 = 0x01234567,
            .Data2 = 0x89ab,
            .Data3 = 0xef10,
            .Data4 = "\x32\x54\x76\x98\xba\xdc\xfe\x91".*,
        },
        GUID.parse("{01234567-89AB-EF10-3254-7698badcfe91}"),
    );
}

pub const FOLDERID_LocalAppData = GUID.parse("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}");

pub const KF_FLAG_DEFAULT = 0;
pub const KF_FLAG_NO_APPCONTAINER_REDIRECTION = 65536;
pub const KF_FLAG_CREATE = 32768;
pub const KF_FLAG_DONT_VERIFY = 16384;
pub const KF_FLAG_DONT_UNEXPAND = 8192;
pub const KF_FLAG_NO_ALIAS = 4096;
pub const KF_FLAG_INIT = 2048;
pub const KF_FLAG_DEFAULT_PATH = 1024;
pub const KF_FLAG_NOT_PARENT_RELATIVE = 512;
pub const KF_FLAG_SIMPLE_IDLIST = 256;
pub const KF_FLAG_ALIAS_ONLY = -2147483648;

pub const S_OK = 0;
pub const S_FALSE = 0x00000001;
pub const E_NOTIMPL = @as(c_long, @bitCast(@as(c_ulong, 0x80004001)));
pub const E_NOINTERFACE = @as(c_long, @bitCast(@as(c_ulong, 0x80004002)));
pub const E_POINTER = @as(c_long, @bitCast(@as(c_ulong, 0x80004003)));
pub const E_ABORT = @as(c_long, @bitCast(@as(c_ulong, 0x80004004)));
pub const E_FAIL = @as(c_long, @bitCast(@as(c_ulong, 0x80004005)));
pub const E_UNEXPECTED = @as(c_long, @bitCast(@as(c_ulong, 0x8000FFFF)));
pub const E_ACCESSDENIED = @as(c_long, @bitCast(@as(c_ulong, 0x80070005)));
pub const E_HANDLE = @as(c_long, @bitCast(@as(c_ulong, 0x80070006)));
pub const E_OUTOFMEMORY = @as(c_long, @bitCast(@as(c_ulong, 0x8007000E)));
pub const E_INVALIDARG = @as(c_long, @bitCast(@as(c_ulong, 0x80070057)));

pub fn HRESULT_CODE(hr: HRESULT) Win32Error {
    return @enumFromInt(hr & 0xFFFF);
}

pub const FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
pub const FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
pub const FILE_FLAG_NO_BUFFERING = 0x20000000;
pub const FILE_FLAG_OPEN_NO_RECALL = 0x00100000;
pub const FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
pub const FILE_FLAG_OVERLAPPED = 0x40000000;
pub const FILE_FLAG_POSIX_SEMANTICS = 0x0100000;
pub const FILE_FLAG_RANDOM_ACCESS = 0x10000000;
pub const FILE_FLAG_SESSION_AWARE = 0x00800000;
pub const FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
pub const FILE_FLAG_WRITE_THROUGH = 0x80000000;

pub const RECT = extern struct {
    left: LONG,
    top: LONG,
    right: LONG,
    bottom: LONG,
};

pub const SMALL_RECT = extern struct {
    Left: SHORT,
    Top: SHORT,
    Right: SHORT,
    Bottom: SHORT,
};

pub const POINT = extern struct {
    x: LONG,
    y: LONG,
};

pub const COORD = extern struct {
    X: SHORT,
    Y: SHORT,
};

pub const CREATE_UNICODE_ENVIRONMENT = 1024;

pub const TLS_OUT_OF_INDEXES = 4294967295;
pub const IMAGE_TLS_DIRECTORY = extern struct {
    StartAddressOfRawData: usize,
    EndAddressOfRawData: usize,
    AddressOfIndex: usize,
    AddressOfCallBacks: usize,
    SizeOfZeroFill: u32,
    Characteristics: u32,
};
pub const IMAGE_TLS_DIRECTORY64 = IMAGE_TLS_DIRECTORY;
pub const IMAGE_TLS_DIRECTORY32 = IMAGE_TLS_DIRECTORY;

pub const PIMAGE_TLS_CALLBACK = ?*const fn (PVOID, DWORD, PVOID) callconv(.winapi) void;

pub const PROV_RSA_FULL = 1;

pub const REGSAM = ACCESS_MASK;
pub const ACCESS_MASK = DWORD;
pub const LSTATUS = LONG;

pub const SECTION_INHERIT = enum(c_int) {
    ViewShare = 0,
    ViewUnmap = 1,
};

pub const SECTION_QUERY = 0x0001;
pub const SECTION_MAP_WRITE = 0x0002;
pub const SECTION_MAP_READ = 0x0004;
pub const SECTION_MAP_EXECUTE = 0x0008;
pub const SECTION_EXTEND_SIZE = 0x0010;
pub const SECTION_ALL_ACCESS =
    STANDARD_RIGHTS_REQUIRED |
    SECTION_QUERY |
    SECTION_MAP_WRITE |
    SECTION_MAP_READ |
    SECTION_MAP_EXECUTE |
    SECTION_EXTEND_SIZE;

pub const SEC_64K_PAGES = 0x80000;
pub const SEC_FILE = 0x800000;
pub const SEC_IMAGE = 0x1000000;
pub const SEC_PROTECTED_IMAGE = 0x2000000;
pub const SEC_RESERVE = 0x4000000;
pub const SEC_COMMIT = 0x8000000;
pub const SEC_IMAGE_NO_EXECUTE = SEC_IMAGE | SEC_NOCACHE;
pub const SEC_NOCACHE = 0x10000000;
pub const SEC_WRITECOMBINE = 0x40000000;
pub const SEC_LARGE_PAGES = 0x80000000;

pub const HKEY = *opaque {};

pub const HKEY_CLASSES_ROOT: HKEY = @ptrFromInt(0x80000000);
pub const HKEY_CURRENT_USER: HKEY = @ptrFromInt(0x80000001);
pub const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(0x80000002);
pub const HKEY_USERS: HKEY = @ptrFromInt(0x80000003);
pub const HKEY_PERFORMANCE_DATA: HKEY = @ptrFromInt(0x80000004);
pub const HKEY_PERFORMANCE_TEXT: HKEY = @ptrFromInt(0x80000050);
pub const HKEY_PERFORMANCE_NLSTEXT: HKEY = @ptrFromInt(0x80000060);
pub const HKEY_CURRENT_CONFIG: HKEY = @ptrFromInt(0x80000005);
pub const HKEY_DYN_DATA: HKEY = @ptrFromInt(0x80000006);
pub const HKEY_CURRENT_USER_LOCAL_SETTINGS: HKEY = @ptrFromInt(0x80000007);

/// Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY,
/// KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
pub const KEY_ALL_ACCESS = 0xF003F;
/// Reserved for system use.
pub const KEY_CREATE_LINK = 0x0020;
/// Required to create a subkey of a registry key.
pub const KEY_CREATE_SUB_KEY = 0x0004;
/// Required to enumerate the subkeys of a registry key.
pub const KEY_ENUMERATE_SUB_KEYS = 0x0008;
/// Equivalent to KEY_READ.
pub const KEY_EXECUTE = 0x20019;
/// Required to request change notifications for a registry key or for subkeys of a registry key.
pub const KEY_NOTIFY = 0x0010;
/// Required to query the values of a registry key.
pub const KEY_QUERY_VALUE = 0x0001;
/// Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
pub const KEY_READ = 0x20019;
/// Required to create, delete, or set a registry value.
pub const KEY_SET_VALUE = 0x0002;
/// Indicates that an application on 64-bit Windows should operate on the 32-bit registry view.
/// This flag is ignored by 32-bit Windows.
pub const KEY_WOW64_32KEY = 0x0200;
/// Indicates that an application on 64-bit Windows should operate on the 64-bit registry view.
/// This flag is ignored by 32-bit Windows.
pub const KEY_WOW64_64KEY = 0x0100;
/// Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
pub const KEY_WRITE = 0x20006;

/// Open symbolic link.
pub const REG_OPTION_OPEN_LINK: DWORD = 0x8;

pub const RTL_QUERY_REGISTRY_TABLE = extern struct {
    QueryRoutine: RTL_QUERY_REGISTRY_ROUTINE,
    Flags: ULONG,
    Name: ?PWSTR,
    EntryContext: ?*anyopaque,
    DefaultType: ULONG,
    DefaultData: ?*anyopaque,
    DefaultLength: ULONG,
};

pub const RTL_QUERY_REGISTRY_ROUTINE = ?*const fn (
    PWSTR,
    ULONG,
    ?*anyopaque,
    ULONG,
    ?*anyopaque,
    ?*anyopaque,
) callconv(.winapi) NTSTATUS;

/// Path is a full path
pub const RTL_REGISTRY_ABSOLUTE = 0;
/// \Registry\Machine\System\CurrentControlSet\Services
pub const RTL_REGISTRY_SERVICES = 1;
/// \Registry\Machine\System\CurrentControlSet\Control
pub const RTL_REGISTRY_CONTROL = 2;
/// \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
pub const RTL_REGISTRY_WINDOWS_NT = 3;
/// \Registry\Machine\Hardware\DeviceMap
pub const RTL_REGISTRY_DEVICEMAP = 4;
/// \Registry\User\CurrentUser
pub const RTL_REGISTRY_USER = 5;
pub const RTL_REGISTRY_MAXIMUM = 6;

/// Low order bits are registry handle
pub const RTL_REGISTRY_HANDLE = 0x40000000;
/// Indicates the key node is optional
pub const RTL_REGISTRY_OPTIONAL = 0x80000000;

/// Name is a subkey and remainder of table or until next subkey are value
/// names for that subkey to look at.
pub const RTL_QUERY_REGISTRY_SUBKEY = 0x00000001;

/// Reset current key to original key for this and all following table entries.
pub const RTL_QUERY_REGISTRY_TOPKEY = 0x00000002;

/// Fail if no match found for this table entry.
pub const RTL_QUERY_REGISTRY_REQUIRED = 0x00000004;

/// Used to mark a table entry that has no value name, just wants a call out, not
/// an enumeration of all values.
pub const RTL_QUERY_REGISTRY_NOVALUE = 0x00000008;

/// Used to suppress the expansion of REG_MULTI_SZ into multiple callouts or
/// to prevent the expansion of environment variable values in REG_EXPAND_SZ.
pub const RTL_QUERY_REGISTRY_NOEXPAND = 0x00000010;

/// QueryRoutine field ignored.  EntryContext field points to location to store value.
/// For null terminated strings, EntryContext points to UNICODE_STRING structure that
/// that describes maximum size of buffer. If .Buffer field is NULL then a buffer is
/// allocated.
pub const RTL_QUERY_REGISTRY_DIRECT = 0x00000020;

/// Used to delete value keys after they are queried.
pub const RTL_QUERY_REGISTRY_DELETE = 0x00000040;

/// Use this flag with the RTL_QUERY_REGISTRY_DIRECT flag to verify that the REG_XXX type
/// of the stored registry value matches the type expected by the caller.
/// If the types do not match, the call fails.
pub const RTL_QUERY_REGISTRY_TYPECHECK = 0x00000100;

pub const REG = struct {
    /// No value type
    pub const NONE: ULONG = 0;
    /// Unicode nul terminated string
    pub const SZ: ULONG = 1;
    /// Unicode nul terminated string (with environment variable references)
    pub const EXPAND_SZ: ULONG = 2;
    /// Free form binary
    pub const BINARY: ULONG = 3;
    /// 32-bit number
    pub const DWORD: ULONG = 4;
    /// 32-bit number (same as REG_DWORD)
    pub const DWORD_LITTLE_ENDIAN: ULONG = 4;
    /// 32-bit number
    pub const DWORD_BIG_ENDIAN: ULONG = 5;
    /// Symbolic Link (unicode)
    pub const LINK: ULONG = 6;
    /// Multiple Unicode strings
    pub const MULTI_SZ: ULONG = 7;
    /// Resource list in the resource map
    pub const RESOURCE_LIST: ULONG = 8;
    /// Resource list in the hardware description
    pub const FULL_RESOURCE_DESCRIPTOR: ULONG = 9;
    pub const RESOURCE_REQUIREMENTS_LIST: ULONG = 10;
    /// 64-bit number
    pub const QWORD: ULONG = 11;
    /// 64-bit number (same as REG_QWORD)
    pub const QWORD_LITTLE_ENDIAN: ULONG = 11;
};

pub const FILE_NOTIFY_INFORMATION = extern struct {
    NextEntryOffset: DWORD,
    Action: DWORD,
    FileNameLength: DWORD,
    // Flexible array member
    // FileName: [1]WCHAR,
};

pub const FILE_ACTION_ADDED = 0x00000001;
pub const FILE_ACTION_REMOVED = 0x00000002;
pub const FILE_ACTION_MODIFIED = 0x00000003;
pub const FILE_ACTION_RENAMED_OLD_NAME = 0x00000004;
pub const FILE_ACTION_RENAMED_NEW_NAME = 0x00000005;

pub const LPOVERLAPPED_COMPLETION_ROUTINE = ?*const fn (DWORD, DWORD, *OVERLAPPED) callconv(.winapi) void;

pub const FileNotifyChangeFilter = packed struct(DWORD) {
    file_name: bool = false,
    dir_name: bool = false,
    attributes: bool = false,
    size: bool = false,
    last_write: bool = false,
    last_access: bool = false,
    creation: bool = false,
    ea: bool = false,
    security: bool = false,
    stream_name: bool = false,
    stream_size: bool = false,
    stream_write: bool = false,
    _pad: u20 = 0,
};

pub const CONSOLE_SCREEN_BUFFER_INFO = extern struct {
    dwSize: COORD,
    dwCursorPosition: COORD,
    wAttributes: WORD,
    srWindow: SMALL_RECT,
    dwMaximumWindowSize: COORD,
};

pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4;
pub const DISABLE_NEWLINE_AUTO_RETURN = 0x8;

pub const FOREGROUND_BLUE = 1;
pub const FOREGROUND_GREEN = 2;
pub const FOREGROUND_RED = 4;
pub const FOREGROUND_INTENSITY = 8;

pub const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

pub const RTL_CRITICAL_SECTION_DEBUG = extern struct {
    Type: WORD,
    CreatorBackTraceIndex: WORD,
    CriticalSection: *RTL_CRITICAL_SECTION,
    ProcessLocksList: LIST_ENTRY,
    EntryCount: DWORD,
    ContentionCount: DWORD,
    Flags: DWORD,
    CreatorBackTraceIndexHigh: WORD,
    SpareWORD: WORD,
};

pub const RTL_CRITICAL_SECTION = extern struct {
    DebugInfo: *RTL_CRITICAL_SECTION_DEBUG,
    LockCount: LONG,
    RecursionCount: LONG,
    OwningThread: HANDLE,
    LockSemaphore: HANDLE,
    SpinCount: ULONG_PTR,
};

pub const CRITICAL_SECTION = RTL_CRITICAL_SECTION;
pub const INIT_ONCE = RTL_RUN_ONCE;
pub const INIT_ONCE_STATIC_INIT = RTL_RUN_ONCE_INIT;
pub const INIT_ONCE_FN = *const fn (InitOnce: *INIT_ONCE, Parameter: ?*anyopaque, Context: ?*anyopaque) callconv(.winapi) BOOL;

pub const RTL_RUN_ONCE = extern struct {
    Ptr: ?*anyopaque,
};

pub const RTL_RUN_ONCE_INIT = RTL_RUN_ONCE{ .Ptr = null };

pub const COINIT = struct {
    pub const APARTMENTTHREADED = 2;
    pub const MULTITHREADED = 0;
    pub const DISABLE_OLE1DDE = 4;
    pub const SPEED_OVER_MEMORY = 8;
};

pub const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: PVOID,
    AllocationBase: PVOID,
    AllocationProtect: DWORD,
    PartitionId: WORD,
    RegionSize: SIZE_T,
    State: DWORD,
    Protect: DWORD,
    Type: DWORD,
};

pub const PMEMORY_BASIC_INFORMATION = *MEMORY_BASIC_INFORMATION;

/// > The maximum path of 32,767 characters is approximate, because the "\\?\"
/// > prefix may be expanded to a longer string by the system at run time, and
/// > this expansion applies to the total length.
/// from https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#maximum-path-length-limitation
pub const PATH_MAX_WIDE = 32767;

/// > [Each file name component can be] up to the value returned in the
/// > lpMaximumComponentLength parameter of the GetVolumeInformation function
/// > (this value is commonly 255 characters)
/// from https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
///
/// > The value that is stored in the variable that *lpMaximumComponentLength points to is
/// > used to indicate that a specified file system supports long names. For example, for
/// > a FAT file system that supports long names, the function stores the value 255, rather
/// > than the previous 8.3 indicator. Long names can also be supported on systems that use
/// > the NTFS file system.
/// from https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw
///
/// The assumption being made here is that while lpMaximumComponentLength may vary, it will never
/// be larger than 255.
///
/// TODO: More verification of this assumption.
pub const NAME_MAX = 255;

pub const FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
pub const FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000;
pub const FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
pub const FORMAT_MESSAGE_FROM_STRING = 0x00000400;
pub const FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
pub const FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
pub const FORMAT_MESSAGE_MAX_WIDTH_MASK = 0x000000FF;

pub const EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
pub const EXCEPTION_ACCESS_VIOLATION = 0xc0000005;
pub const EXCEPTION_ILLEGAL_INSTRUCTION = 0xc000001d;
pub const EXCEPTION_STACK_OVERFLOW = 0xc00000fd;
pub const EXCEPTION_CONTINUE_SEARCH = 0;

pub const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: *EXCEPTION_RECORD,
    ExceptionAddress: *anyopaque,
    NumberParameters: u32,
    ExceptionInformation: [15]usize,
};

pub const FLOATING_SAVE_AREA = switch (native_arch) {
    .x86 => extern struct {
        ControlWord: DWORD,
        StatusWord: DWORD,
        TagWord: DWORD,
        ErrorOffset: DWORD,
        ErrorSelector: DWORD,
        DataOffset: DWORD,
        DataSelector: DWORD,
        RegisterArea: [80]BYTE,
        Cr0NpxState: DWORD,
    },
    else => @compileError("FLOATING_SAVE_AREA only defined on x86"),
};

pub const M128A = switch (native_arch) {
    .x86_64 => extern struct {
        Low: ULONGLONG,
        High: LONGLONG,
    },
    else => @compileError("M128A only defined on x86_64"),
};

pub const XMM_SAVE_AREA32 = switch (native_arch) {
    .x86_64 => extern struct {
        ControlWord: WORD,
        StatusWord: WORD,
        TagWord: BYTE,
        Reserved1: BYTE,
        ErrorOpcode: WORD,
        ErrorOffset: DWORD,
        ErrorSelector: WORD,
        Reserved2: WORD,
        DataOffset: DWORD,
        DataSelector: WORD,
        Reserved3: WORD,
        MxCsr: DWORD,
        MxCsr_Mask: DWORD,
        FloatRegisters: [8]M128A,
        XmmRegisters: [16]M128A,
        Reserved4: [96]BYTE,
    },
    else => @compileError("XMM_SAVE_AREA32 only defined on x86_64"),
};

pub const NEON128 = switch (native_arch) {
    .thumb => extern struct {
        Low: ULONGLONG,
        High: LONGLONG,
    },
    .aarch64 => extern union {
        DUMMYSTRUCTNAME: extern struct {
            Low: ULONGLONG,
            High: LONGLONG,
        },
        D: [2]f64,
        S: [4]f32,
        H: [8]WORD,
        B: [16]BYTE,
    },
    else => @compileError("NEON128 only defined on aarch64"),
};

pub const CONTEXT = switch (native_arch) {
    .x86 => extern struct {
        ContextFlags: DWORD,
        Dr0: DWORD,
        Dr1: DWORD,
        Dr2: DWORD,
        Dr3: DWORD,
        Dr6: DWORD,
        Dr7: DWORD,
        FloatSave: FLOATING_SAVE_AREA,
        SegGs: DWORD,
        SegFs: DWORD,
        SegEs: DWORD,
        SegDs: DWORD,
        Edi: DWORD,
        Esi: DWORD,
        Ebx: DWORD,
        Edx: DWORD,
        Ecx: DWORD,
        Eax: DWORD,
        Ebp: DWORD,
        Eip: DWORD,
        SegCs: DWORD,
        EFlags: DWORD,
        Esp: DWORD,
        SegSs: DWORD,
        ExtendedRegisters: [512]BYTE,

        pub fn getRegs(ctx: *const CONTEXT) struct { bp: usize, ip: usize } {
            return .{ .bp = ctx.Ebp, .ip = ctx.Eip };
        }
    },
    .x86_64 => extern struct {
        P1Home: DWORD64 align(16),
        P2Home: DWORD64,
        P3Home: DWORD64,
        P4Home: DWORD64,
        P5Home: DWORD64,
        P6Home: DWORD64,
        ContextFlags: DWORD,
        MxCsr: DWORD,
        SegCs: WORD,
        SegDs: WORD,
        SegEs: WORD,
        SegFs: WORD,
        SegGs: WORD,
        SegSs: WORD,
        EFlags: DWORD,
        Dr0: DWORD64,
        Dr1: DWORD64,
        Dr2: DWORD64,
        Dr3: DWORD64,
        Dr6: DWORD64,
        Dr7: DWORD64,
        Rax: DWORD64,
        Rcx: DWORD64,
        Rdx: DWORD64,
        Rbx: DWORD64,
        Rsp: DWORD64,
        Rbp: DWORD64,
        Rsi: DWORD64,
        Rdi: DWORD64,
        R8: DWORD64,
        R9: DWORD64,
        R10: DWORD64,
        R11: DWORD64,
        R12: DWORD64,
        R13: DWORD64,
        R14: DWORD64,
        R15: DWORD64,
        Rip: DWORD64,
        DUMMYUNIONNAME: extern union {
            FltSave: XMM_SAVE_AREA32,
            FloatSave: XMM_SAVE_AREA32,
            DUMMYSTRUCTNAME: extern struct {
                Header: [2]M128A,
                Legacy: [8]M128A,
                Xmm0: M128A,
                Xmm1: M128A,
                Xmm2: M128A,
                Xmm3: M128A,
                Xmm4: M128A,
                Xmm5: M128A,
                Xmm6: M128A,
                Xmm7: M128A,
                Xmm8: M128A,
                Xmm9: M128A,
                Xmm10: M128A,
                Xmm11: M128A,
                Xmm12: M128A,
                Xmm13: M128A,
                Xmm14: M128A,
                Xmm15: M128A,
            },
        },
        VectorRegister: [26]M128A,
        VectorControl: DWORD64,
        DebugControl: DWORD64,
        LastBranchToRip: DWORD64,
        LastBranchFromRip: DWORD64,
        LastExceptionToRip: DWORD64,
        LastExceptionFromRip: DWORD64,

        pub fn getRegs(ctx: *const CONTEXT) struct { bp: usize, ip: usize, sp: usize } {
            return .{ .bp = ctx.Rbp, .ip = ctx.Rip, .sp = ctx.Rsp };
        }

        pub fn setIp(ctx: *CONTEXT, ip: usize) void {
            ctx.Rip = ip;
        }

        pub fn setSp(ctx: *CONTEXT, sp: usize) void {
            ctx.Rsp = sp;
        }
    },
    .thumb => extern struct {
        ContextFlags: ULONG,
        R0: ULONG,
        R1: ULONG,
        R2: ULONG,
        R3: ULONG,
        R4: ULONG,
        R5: ULONG,
        R6: ULONG,
        R7: ULONG,
        R8: ULONG,
        R9: ULONG,
        R10: ULONG,
        R11: ULONG,
        R12: ULONG,
        Sp: ULONG,
        Lr: ULONG,
        Pc: ULONG,
        Cpsr: ULONG,
        Fpcsr: ULONG,
        Padding: ULONG,
        DUMMYUNIONNAME: extern union {
            Q: [16]NEON128,
            D: [32]ULONGLONG,
            S: [32]ULONG,
        },
        Bvr: [8]ULONG,
        Bcr: [8]ULONG,
        Wvr: [1]ULONG,
        Wcr: [1]ULONG,
        Padding2: [2]ULONG,

        pub fn getRegs(ctx: *const CONTEXT) struct { bp: usize, ip: usize, sp: usize } {
            return .{
                .bp = ctx.DUMMYUNIONNAME.S[11],
                .ip = ctx.Pc,
                .sp = ctx.Sp,
            };
        }

        pub fn setIp(ctx: *CONTEXT, ip: usize) void {
            ctx.Pc = ip;
        }

        pub fn setSp(ctx: *CONTEXT, sp: usize) void {
            ctx.Sp = sp;
        }
    },
    .aarch64 => extern struct {
        ContextFlags: ULONG align(16),
        Cpsr: ULONG,
        DUMMYUNIONNAME: extern union {
            DUMMYSTRUCTNAME: extern struct {
                X0: DWORD64,
                X1: DWORD64,
                X2: DWORD64,
                X3: DWORD64,
                X4: DWORD64,
                X5: DWORD64,
                X6: DWORD64,
                X7: DWORD64,
                X8: DWORD64,
                X9: DWORD64,
                X10: DWORD64,
                X11: DWORD64,
                X12: DWORD64,
                X13: DWORD64,
                X14: DWORD64,
                X15: DWORD64,
                X16: DWORD64,
                X17: DWORD64,
                X18: DWORD64,
                X19: DWORD64,
                X20: DWORD64,
                X21: DWORD64,
                X22: DWORD64,
                X23: DWORD64,
                X24: DWORD64,
                X25: DWORD64,
                X26: DWORD64,
                X27: DWORD64,
                X28: DWORD64,
                Fp: DWORD64,
                Lr: DWORD64,
            },
            X: [31]DWORD64,
        },
        Sp: DWORD64,
        Pc: DWORD64,
        V: [32]NEON128,
        Fpcr: DWORD,
        Fpsr: DWORD,
        Bcr: [8]DWORD,
        Bvr: [8]DWORD64,
        Wcr: [2]DWORD,
        Wvr: [2]DWORD64,

        pub fn getRegs(ctx: *const CONTEXT) struct { bp: usize, ip: usize, sp: usize } {
            return .{
                .bp = ctx.DUMMYUNIONNAME.DUMMYSTRUCTNAME.Fp,
                .ip = ctx.Pc,
                .sp = ctx.Sp,
            };
        }

        pub fn setIp(ctx: *CONTEXT, ip: usize) void {
            ctx.Pc = ip;
        }

        pub fn setSp(ctx: *CONTEXT, sp: usize) void {
            ctx.Sp = sp;
        }
    },
    else => @compileError("CONTEXT is not defined for this architecture"),
};

pub const RUNTIME_FUNCTION = switch (native_arch) {
    .x86_64 => extern struct {
        BeginAddress: DWORD,
        EndAddress: DWORD,
        UnwindData: DWORD,
    },
    .thumb => extern struct {
        BeginAddress: DWORD,
        DUMMYUNIONNAME: extern union {
            UnwindData: DWORD,
            DUMMYSTRUCTNAME: packed struct {
                Flag: u2,
                FunctionLength: u11,
                Ret: u2,
                H: u1,
                Reg: u3,
                R: u1,
                L: u1,
                C: u1,
                StackAdjust: u10,
            },
        },
    },
    .aarch64 => extern struct {
        BeginAddress: DWORD,
        DUMMYUNIONNAME: extern union {
            UnwindData: DWORD,
            DUMMYSTRUCTNAME: packed struct {
                Flag: u2,
                FunctionLength: u11,
                RegF: u3,
                RegI: u4,
                H: u1,
                CR: u2,
                FrameSize: u9,
            },
        },
    },
    else => @compileError("RUNTIME_FUNCTION is not defined for this architecture"),
};

pub const KNONVOLATILE_CONTEXT_POINTERS = switch (native_arch) {
    .x86_64 => extern struct {
        FloatingContext: [16]?*M128A,
        IntegerContext: [16]?*ULONG64,
    },
    .thumb => extern struct {
        R4: ?*DWORD,
        R5: ?*DWORD,
        R6: ?*DWORD,
        R7: ?*DWORD,
        R8: ?*DWORD,
        R9: ?*DWORD,
        R10: ?*DWORD,
        R11: ?*DWORD,
        Lr: ?*DWORD,
        D8: ?*ULONGLONG,
        D9: ?*ULONGLONG,
        D10: ?*ULONGLONG,
        D11: ?*ULONGLONG,
        D12: ?*ULONGLONG,
        D13: ?*ULONGLONG,
        D14: ?*ULONGLONG,
        D15: ?*ULONGLONG,
    },
    .aarch64 => extern struct {
        X19: ?*DWORD64,
        X20: ?*DWORD64,
        X21: ?*DWORD64,
        X22: ?*DWORD64,
        X23: ?*DWORD64,
        X24: ?*DWORD64,
        X25: ?*DWORD64,
        X26: ?*DWORD64,
        X27: ?*DWORD64,
        X28: ?*DWORD64,
        Fp: ?*DWORD64,
        Lr: ?*DWORD64,
        D8: ?*DWORD64,
        D9: ?*DWORD64,
        D10: ?*DWORD64,
        D11: ?*DWORD64,
        D12: ?*DWORD64,
        D13: ?*DWORD64,
        D14: ?*DWORD64,
        D15: ?*DWORD64,
    },
    else => @compileError("KNONVOLATILE_CONTEXT_POINTERS is not defined for this architecture"),
};

pub const EXCEPTION_POINTERS = extern struct {
    ExceptionRecord: *EXCEPTION_RECORD,
    ContextRecord: *CONTEXT,
};

pub const VECTORED_EXCEPTION_HANDLER = *const fn (ExceptionInfo: *EXCEPTION_POINTERS) callconv(.winapi) c_long;

pub const EXCEPTION_DISPOSITION = i32;
pub const EXCEPTION_ROUTINE = *const fn (
    ExceptionRecord: ?*EXCEPTION_RECORD,
    EstablisherFrame: PVOID,
    ContextRecord: *(Self.CONTEXT),
    DispatcherContext: PVOID,
) callconv(.winapi) EXCEPTION_DISPOSITION;

pub const UNWIND_HISTORY_TABLE_SIZE = 12;
pub const UNWIND_HISTORY_TABLE_ENTRY = extern struct {
    ImageBase: ULONG64,
    FunctionEntry: *Self.RUNTIME_FUNCTION,
};

pub const UNWIND_HISTORY_TABLE = extern struct {
    Count: ULONG,
    LocalHint: BYTE,
    GlobalHint: BYTE,
    Search: BYTE,
    Once: BYTE,
    LowAddress: ULONG64,
    HighAddress: ULONG64,
    Entry: [UNWIND_HISTORY_TABLE_SIZE]UNWIND_HISTORY_TABLE_ENTRY,
};

pub const UNW_FLAG_NHANDLER = 0x0;
pub const UNW_FLAG_EHANDLER = 0x1;
pub const UNW_FLAG_UHANDLER = 0x2;
pub const UNW_FLAG_CHAININFO = 0x4;

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: ULONG,
    RootDirectory: ?HANDLE,
    ObjectName: *UNICODE_STRING,
    Attributes: ULONG,
    SecurityDescriptor: ?*anyopaque,
    SecurityQualityOfService: ?*anyopaque,
};

pub const OBJ_INHERIT = 0x00000002;
pub const OBJ_PERMANENT = 0x00000010;
pub const OBJ_EXCLUSIVE = 0x00000020;
pub const OBJ_CASE_INSENSITIVE = 0x00000040;
pub const O```
