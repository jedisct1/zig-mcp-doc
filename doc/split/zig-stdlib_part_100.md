```

    switch (errno(system.mkdir(dir_path, mode))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .DQUOT => return error.DiskQuota,
        .EXIST => return error.PathAlreadyExists,
        .FAULT => unreachable,
        .LOOP => return error.SymLinkLoop,
        .MLINK => return error.LinkQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .NOTDIR => return error.NotDir,
        .ROFS => return error.ReadOnlyFileSystem,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Windows-only. Same as `mkdir` but the parameters is WTF16LE encoded.
pub fn mkdirW(dir_path_w: []const u16, mode: mode_t) MakeDirError!void {
    _ = mode;
    const sub_dir_handle = windows.OpenFile(dir_path_w, .{
        .dir = fs.cwd().fd,
        .access_mask = windows.GENERIC_READ | windows.SYNCHRONIZE,
        .creation = windows.FILE_CREATE,
        .filter = .dir_only,
    }) catch |err| switch (err) {
        error.IsDir => return error.Unexpected,
        error.PipeBusy => return error.Unexpected,
        error.NoDevice => return error.Unexpected,
        error.WouldBlock => return error.Unexpected,
        error.AntivirusInterference => return error.Unexpected,
        else => |e| return e,
    };
    windows.CloseHandle(sub_dir_handle);
}

pub const DeleteDirError = error{
    AccessDenied,
    PermissionDenied,
    FileBusy,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotDir,
    DirNotEmpty,
    ReadOnlyFileSystem,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
    BadPathName,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || UnexpectedError;

/// Deletes an empty directory.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn rmdir(dir_path: []const u8) DeleteDirError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        return unlinkat(AT.FDCWD, dir_path, AT.REMOVEDIR) catch |err| switch (err) {
            error.FileSystem => unreachable, // only occurs when targeting files
            error.IsDir => unreachable, // only occurs when targeting files
            else => |e| return e,
        };
    } else if (native_os == .windows) {
        const dir_path_w = try windows.sliceToPrefixedFileW(null, dir_path);
        return rmdirW(dir_path_w.span());
    } else {
        const dir_path_c = try toPosixPath(dir_path);
        return rmdirZ(&dir_path_c);
    }
}

/// Same as `rmdir` except the parameter is null-terminated.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn rmdirZ(dir_path: [*:0]const u8) DeleteDirError!void {
    if (native_os == .windows) {
        const dir_path_w = try windows.cStrToPrefixedFileW(null, dir_path);
        return rmdirW(dir_path_w.span());
    } else if (native_os == .wasi and !builtin.link_libc) {
        return rmdir(mem.sliceTo(dir_path, 0));
    }
    switch (errno(system.rmdir(dir_path))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BUSY => return error.FileBusy,
        .FAULT => unreachable,
        .INVAL => return error.BadPathName,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .EXIST => return error.DirNotEmpty,
        .NOTEMPTY => return error.DirNotEmpty,
        .ROFS => return error.ReadOnlyFileSystem,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Windows-only. Same as `rmdir` except the parameter is WTF-16 LE encoded.
pub fn rmdirW(dir_path_w: []const u16) DeleteDirError!void {
    return windows.DeleteFile(dir_path_w, .{ .dir = fs.cwd().fd, .remove_dir = true }) catch |err| switch (err) {
        error.IsDir => unreachable,
        else => |e| return e,
    };
}

pub const ChangeCurDirError = error{
    AccessDenied,
    FileSystem,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotDir,
    BadPathName,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
} || UnexpectedError;

/// Changes the current working directory of the calling process.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn chdir(dir_path: []const u8) ChangeCurDirError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        @compileError("WASI does not support os.chdir");
    } else if (native_os == .windows) {
        var wtf16_dir_path: [windows.PATH_MAX_WIDE]u16 = undefined;
        if (try std.unicode.checkWtf8ToWtf16LeOverflow(dir_path, &wtf16_dir_path)) {
            return error.NameTooLong;
        }
        const len = try std.unicode.wtf8ToWtf16Le(&wtf16_dir_path, dir_path);
        return chdirW(wtf16_dir_path[0..len]);
    } else {
        const dir_path_c = try toPosixPath(dir_path);
        return chdirZ(&dir_path_c);
    }
}

/// Same as `chdir` except the parameter is null-terminated.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn chdirZ(dir_path: [*:0]const u8) ChangeCurDirError!void {
    if (native_os == .windows) {
        const dir_path_span = mem.span(dir_path);
        var wtf16_dir_path: [windows.PATH_MAX_WIDE]u16 = undefined;
        if (try std.unicode.checkWtf8ToWtf16LeOverflow(dir_path_span, &wtf16_dir_path)) {
            return error.NameTooLong;
        }
        const len = try std.unicode.wtf8ToWtf16Le(&wtf16_dir_path, dir_path_span);
        return chdirW(wtf16_dir_path[0..len]);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return chdir(mem.span(dir_path));
    }
    switch (errno(system.chdir(dir_path))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .FAULT => unreachable,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Windows-only. Same as `chdir` except the parameter is WTF16 LE encoded.
pub fn chdirW(dir_path: []const u16) ChangeCurDirError!void {
    windows.SetCurrentDirectory(dir_path) catch |err| switch (err) {
        error.NoDevice => return error.FileSystem,
        else => |e| return e,
    };
}

pub const FchdirError = error{
    AccessDenied,
    NotDir,
    FileSystem,
} || UnexpectedError;

pub fn fchdir(dirfd: fd_t) FchdirError!void {
    if (dirfd == AT.FDCWD) return;
    while (true) {
        switch (errno(system.fchdir(dirfd))) {
            .SUCCESS => return,
            .ACCES => return error.AccessDenied,
            .BADF => unreachable,
            .NOTDIR => return error.NotDir,
            .INTR => continue,
            .IO => return error.FileSystem,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const ReadLinkError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to read value of a symbolic link relative to it.
    AccessDenied,
    PermissionDenied,
    FileSystem,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotLink,
    NotDir,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
    BadPathName,
    /// Windows-only. This error may occur if the opened reparse point is
    /// of unsupported type.
    UnsupportedReparsePointType,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || UnexpectedError;

/// Read value of a symbolic link.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// The return value is a slice of `out_buffer` from index 0.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, the result is encoded as UTF-8.
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn readlink(file_path: []const u8, out_buffer: []u8) ReadLinkError![]u8 {
    if (native_os == .wasi and !builtin.link_libc) {
        return readlinkat(AT.FDCWD, file_path, out_buffer);
    } else if (native_os == .windows) {
        const file_path_w = try windows.sliceToPrefixedFileW(null, file_path);
        return readlinkW(file_path_w.span(), out_buffer);
    } else {
        const file_path_c = try toPosixPath(file_path);
        return readlinkZ(&file_path_c, out_buffer);
    }
}

/// Windows-only. Same as `readlink` except `file_path` is WTF16 LE encoded.
/// The result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// See also `readlinkZ`.
pub fn readlinkW(file_path: []const u16, out_buffer: []u8) ReadLinkError![]u8 {
    return windows.ReadLink(fs.cwd().fd, file_path, out_buffer);
}

/// Same as `readlink` except `file_path` is null-terminated.
pub fn readlinkZ(file_path: [*:0]const u8, out_buffer: []u8) ReadLinkError![]u8 {
    if (native_os == .windows) {
        const file_path_w = try windows.cStrToPrefixedFileW(null, file_path);
        return readlinkW(file_path_w.span(), out_buffer);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return readlink(mem.sliceTo(file_path, 0), out_buffer);
    }
    const rc = system.readlink(file_path, out_buffer.ptr, out_buffer.len);
    switch (errno(rc)) {
        .SUCCESS => return out_buffer[0..@bitCast(rc)],
        .ACCES => return error.AccessDenied,
        .FAULT => unreachable,
        .INVAL => return error.NotLink,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Similar to `readlink` except reads value of a symbolink link **relative** to `dirfd` directory handle.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// The return value is a slice of `out_buffer` from index 0.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, the result is encoded as UTF-8.
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
/// See also `readlinkatWasi`, `realinkatZ` and `realinkatW`.
pub fn readlinkat(dirfd: fd_t, file_path: []const u8, out_buffer: []u8) ReadLinkError![]u8 {
    if (native_os == .wasi and !builtin.link_libc) {
        return readlinkatWasi(dirfd, file_path, out_buffer);
    }
    if (native_os == .windows) {
        const file_path_w = try windows.sliceToPrefixedFileW(dirfd, file_path);
        return readlinkatW(dirfd, file_path_w.span(), out_buffer);
    }
    const file_path_c = try toPosixPath(file_path);
    return readlinkatZ(dirfd, &file_path_c, out_buffer);
}

/// WASI-only. Same as `readlinkat` but targets WASI.
/// See also `readlinkat`.
pub fn readlinkatWasi(dirfd: fd_t, file_path: []const u8, out_buffer: []u8) ReadLinkError![]u8 {
    var bufused: usize = undefined;
    switch (wasi.path_readlink(dirfd, file_path.ptr, file_path.len, out_buffer.ptr, out_buffer.len, &bufused)) {
        .SUCCESS => return out_buffer[0..bufused],
        .ACCES => return error.AccessDenied,
        .FAULT => unreachable,
        .INVAL => return error.NotLink,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .NOTCAPABLE => return error.AccessDenied,
        .ILSEQ => return error.InvalidUtf8,
        else => |err| return unexpectedErrno(err),
    }
}

/// Windows-only. Same as `readlinkat` except `file_path` is null-terminated, WTF16 LE encoded.
/// The result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// See also `readlinkat`.
pub fn readlinkatW(dirfd: fd_t, file_path: []const u16, out_buffer: []u8) ReadLinkError![]u8 {
    return windows.ReadLink(dirfd, file_path, out_buffer);
}

/// Same as `readlinkat` except `file_path` is null-terminated.
/// See also `readlinkat`.
pub fn readlinkatZ(dirfd: fd_t, file_path: [*:0]const u8, out_buffer: []u8) ReadLinkError![]u8 {
    if (native_os == .windows) {
        const file_path_w = try windows.cStrToPrefixedFileW(dirfd, file_path);
        return readlinkatW(dirfd, file_path_w.span(), out_buffer);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return readlinkat(dirfd, mem.sliceTo(file_path, 0), out_buffer);
    }
    const rc = system.readlinkat(dirfd, file_path, out_buffer.ptr, out_buffer.len);
    switch (errno(rc)) {
        .SUCCESS => return out_buffer[0..@bitCast(rc)],
        .ACCES => return error.AccessDenied,
        .FAULT => unreachable,
        .INVAL => return error.NotLink,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

pub const SetEidError = error{
    InvalidUserId,
    PermissionDenied,
} || UnexpectedError;

pub const SetIdError = error{ResourceLimitReached} || SetEidError;

pub fn setuid(uid: uid_t) SetIdError!void {
    switch (errno(system.setuid(uid))) {
        .SUCCESS => return,
        .AGAIN => return error.ResourceLimitReached,
        .INVAL => return error.InvalidUserId,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn seteuid(uid: uid_t) SetEidError!void {
    switch (errno(system.seteuid(uid))) {
        .SUCCESS => return,
        .INVAL => return error.InvalidUserId,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn setreuid(ruid: uid_t, euid: uid_t) SetIdError!void {
    switch (errno(system.setreuid(ruid, euid))) {
        .SUCCESS => return,
        .AGAIN => return error.ResourceLimitReached,
        .INVAL => return error.InvalidUserId,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn setgid(gid: gid_t) SetIdError!void {
    switch (errno(system.setgid(gid))) {
        .SUCCESS => return,
        .AGAIN => return error.ResourceLimitReached,
        .INVAL => return error.InvalidUserId,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn setegid(uid: uid_t) SetEidError!void {
    switch (errno(system.setegid(uid))) {
        .SUCCESS => return,
        .INVAL => return error.InvalidUserId,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn setregid(rgid: gid_t, egid: gid_t) SetIdError!void {
    switch (errno(system.setregid(rgid, egid))) {
        .SUCCESS => return,
        .AGAIN => return error.ResourceLimitReached,
        .INVAL => return error.InvalidUserId,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub const SetPgidError = error{
    ProcessAlreadyExec,
    InvalidProcessGroupId,
    PermissionDenied,
    ProcessNotFound,
} || UnexpectedError;

pub fn setpgid(pid: pid_t, pgid: pid_t) SetPgidError!void {
    switch (errno(system.setpgid(pid, pgid))) {
        .SUCCESS => return,
        .ACCES => return error.ProcessAlreadyExec,
        .INVAL => return error.InvalidProcessGroupId,
        .PERM => return error.PermissionDenied,
        .SRCH => return error.ProcessNotFound,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn getuid() uid_t {
    return system.getuid();
}

pub fn geteuid() uid_t {
    return system.geteuid();
}

/// Test whether a file descriptor refers to a terminal.
pub fn isatty(handle: fd_t) bool {
    if (native_os == .windows) {
        if (fs.File.isCygwinPty(.{ .handle = handle }))
            return true;

        var out: windows.DWORD = undefined;
        return windows.kernel32.GetConsoleMode(handle, &out) != 0;
    }
    if (builtin.link_libc) {
        return system.isatty(handle) != 0;
    }
    if (native_os == .wasi) {
        var statbuf: wasi.fdstat_t = undefined;
        const err = wasi.fd_fdstat_get(handle, &statbuf);
        if (err != .SUCCESS)
            return false;

        // A tty is a character device that we can't seek or tell on.
        if (statbuf.fs_filetype != .CHARACTER_DEVICE)
            return false;
        if (statbuf.fs_rights_base.FD_SEEK or statbuf.fs_rights_base.FD_TELL)
            return false;

        return true;
    }
    if (native_os == .linux) {
        while (true) {
            var wsz: winsize = undefined;
            const fd: usize = @bitCast(@as(isize, handle));
            const rc = linux.syscall3(.ioctl, fd, linux.T.IOCGWINSZ, @intFromPtr(&wsz));
            switch (linux.E.init(rc)) {
                .SUCCESS => return true,
                .INTR => continue,
                else => return false,
            }
        }
    }
    return system.isatty(handle) != 0;
}

pub const SocketError = error{
    /// Permission to create a socket of the specified type and/or
    /// pro‐tocol is denied.
    AccessDenied,

    /// The implementation does not support the specified address family.
    AddressFamilyNotSupported,

    /// Unknown protocol, or protocol family not available.
    ProtocolFamilyNotAvailable,

    /// The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,

    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,

    /// Insufficient memory is available. The socket cannot be created until sufficient
    /// resources are freed.
    SystemResources,

    /// The protocol type or the specified protocol is not supported within this domain.
    ProtocolNotSupported,

    /// The socket type is not supported by the protocol.
    SocketTypeNotSupported,
} || UnexpectedError;

pub fn socket(domain: u32, socket_type: u32, protocol: u32) SocketError!socket_t {
    if (native_os == .windows) {
        // NOTE: windows translates the SOCK.NONBLOCK/SOCK.CLOEXEC flags into
        // windows-analogous operations
        const filtered_sock_type = socket_type & ~@as(u32, SOCK.NONBLOCK | SOCK.CLOEXEC);
        const flags: u32 = if ((socket_type & SOCK.CLOEXEC) != 0)
            windows.ws2_32.WSA_FLAG_NO_HANDLE_INHERIT
        else
            0;
        const rc = try windows.WSASocketW(
            @bitCast(domain),
            @bitCast(filtered_sock_type),
            @bitCast(protocol),
            null,
            0,
            flags,
        );
        errdefer windows.closesocket(rc) catch unreachable;
        if ((socket_type & SOCK.NONBLOCK) != 0) {
            var mode: c_ulong = 1; // nonblocking
            if (windows.ws2_32.SOCKET_ERROR == windows.ws2_32.ioctlsocket(rc, windows.ws2_32.FIONBIO, &mode)) {
                switch (windows.ws2_32.WSAGetLastError()) {
                    // have not identified any error codes that should be handled yet
                    else => unreachable,
                }
            }
        }
        return rc;
    }

    const have_sock_flags = !builtin.target.os.tag.isDarwin() and native_os != .haiku;
    const filtered_sock_type = if (!have_sock_flags)
        socket_type & ~@as(u32, SOCK.NONBLOCK | SOCK.CLOEXEC)
    else
        socket_type;
    const rc = system.socket(domain, filtered_sock_type, protocol);
    switch (errno(rc)) {
        .SUCCESS => {
            const fd: fd_t = @intCast(rc);
            errdefer close(fd);
            if (!have_sock_flags) {
                try setSockFlags(fd, socket_type);
            }
            return fd;
        },
        .ACCES => return error.AccessDenied,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .INVAL => return error.ProtocolFamilyNotAvailable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolNotSupported,
        .PROTOTYPE => return error.SocketTypeNotSupported,
        else => |err| return unexpectedErrno(err),
    }
}

pub const ShutdownError = error{
    ConnectionAborted,

    /// Connection was reset by peer, application should close socket as it is no longer usable.
    ConnectionResetByPeer,
    BlockingOperationInProgress,

    /// The network subsystem has failed.
    NetworkSubsystemFailed,

    /// The socket is not connected (connection-oriented sockets only).
    SocketNotConnected,
    SystemResources,
} || UnexpectedError;

pub const ShutdownHow = enum { recv, send, both };

/// Shutdown socket send/receive operations
pub fn shutdown(sock: socket_t, how: ShutdownHow) ShutdownError!void {
    if (native_os == .windows) {
        const result = windows.ws2_32.shutdown(sock, switch (how) {
            .recv => windows.ws2_32.SD_RECEIVE,
            .send => windows.ws2_32.SD_SEND,
            .both => windows.ws2_32.SD_BOTH,
        });
        if (0 != result) switch (windows.ws2_32.WSAGetLastError()) {
            .WSAECONNABORTED => return error.ConnectionAborted,
            .WSAECONNRESET => return error.ConnectionResetByPeer,
            .WSAEINPROGRESS => return error.BlockingOperationInProgress,
            .WSAEINVAL => unreachable,
            .WSAENETDOWN => return error.NetworkSubsystemFailed,
            .WSAENOTCONN => return error.SocketNotConnected,
            .WSAENOTSOCK => unreachable,
            .WSANOTINITIALISED => unreachable,
            else => |err| return windows.unexpectedWSAError(err),
        };
    } else {
        const rc = system.shutdown(sock, switch (how) {
            .recv => SHUT.RD,
            .send => SHUT.WR,
            .both => SHUT.RDWR,
        });
        switch (errno(rc)) {
            .SUCCESS => return,
            .BADF => unreachable,
            .INVAL => unreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NOTSOCK => unreachable,
            .NOBUFS => return error.SystemResources,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const BindError = error{
    /// The address is protected, and the user is not the superuser.
    /// For UNIX domain sockets: Search permission is denied on  a  component
    /// of  the  path  prefix.
    AccessDenied,

    /// The given address is already in use, or in the case of Internet domain sockets,
    /// The  port number was specified as zero in the socket
    /// address structure, but, upon attempting to bind to  an  ephemeral  port,  it  was
    /// determined  that  all  port  numbers in the ephemeral port range are currently in
    /// use.  See the discussion of /proc/sys/net/ipv4/ip_local_port_range ip(7).
    AddressInUse,

    /// A nonexistent interface was requested or the requested address was not local.
    AddressNotAvailable,

    /// The address is not valid for the address family of socket.
    AddressFamilyNotSupported,

    /// Too many symbolic links were encountered in resolving addr.
    SymLinkLoop,

    /// addr is too long.
    NameTooLong,

    /// A component in the directory prefix of the socket pathname does not exist.
    FileNotFound,

    /// Insufficient kernel memory was available.
    SystemResources,

    /// A component of the path prefix is not a directory.
    NotDir,

    /// The socket inode would reside on a read-only filesystem.
    ReadOnlyFileSystem,

    /// The network subsystem has failed.
    NetworkSubsystemFailed,

    FileDescriptorNotASocket,

    AlreadyBound,
} || UnexpectedError;

/// addr is `*const T` where T is one of the sockaddr
pub fn bind(sock: socket_t, addr: *const sockaddr, len: socklen_t) BindError!void {
    if (native_os == .windows) {
        const rc = windows.bind(sock, addr, len);
        if (rc == windows.ws2_32.SOCKET_ERROR) {
            switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable, // not initialized WSA
                .WSAEACCES => return error.AccessDenied,
                .WSAEADDRINUSE => return error.AddressInUse,
                .WSAEADDRNOTAVAIL => return error.AddressNotAvailable,
                .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                .WSAEFAULT => unreachable, // invalid pointers
                .WSAEINVAL => return error.AlreadyBound,
                .WSAENOBUFS => return error.SystemResources,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                else => |err| return windows.unexpectedWSAError(err),
            }
            unreachable;
        }
        return;
    } else {
        const rc = system.bind(sock, addr, len);
        switch (errno(rc)) {
            .SUCCESS => return,
            .ACCES, .PERM => return error.AccessDenied,
            .ADDRINUSE => return error.AddressInUse,
            .BADF => unreachable, // always a race condition if this error is returned
            .INVAL => unreachable, // invalid parameters
            .NOTSOCK => unreachable, // invalid `sockfd`
            .AFNOSUPPORT => return error.AddressFamilyNotSupported,
            .ADDRNOTAVAIL => return error.AddressNotAvailable,
            .FAULT => unreachable, // invalid `addr` pointer
            .LOOP => return error.SymLinkLoop,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .NOTDIR => return error.NotDir,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return unexpectedErrno(err),
        }
    }
    unreachable;
}

pub const ListenError = error{
    /// Another socket is already listening on the same port.
    /// For Internet domain sockets, the  socket referred to by sockfd had not previously
    /// been bound to an address and, upon attempting to bind it to an ephemeral port, it
    /// was determined that all port numbers in the ephemeral port range are currently in
    /// use.  See the discussion of /proc/sys/net/ipv4/ip_local_port_range in ip(7).
    AddressInUse,

    /// The file descriptor sockfd does not refer to a socket.
    FileDescriptorNotASocket,

    /// The socket is not of a type that supports the listen() operation.
    OperationNotSupported,

    /// The network subsystem has failed.
    NetworkSubsystemFailed,

    /// Ran out of system resources
    /// On Windows it can either run out of socket descriptors or buffer space
    SystemResources,

    /// Already connected
    AlreadyConnected,

    /// Socket has not been bound yet
    SocketNotBound,
} || UnexpectedError;

pub fn listen(sock: socket_t, backlog: u31) ListenError!void {
    if (native_os == .windows) {
        const rc = windows.listen(sock, backlog);
        if (rc == windows.ws2_32.SOCKET_ERROR) {
            switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable, // not initialized WSA
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAEADDRINUSE => return error.AddressInUse,
                .WSAEISCONN => return error.AlreadyConnected,
                .WSAEINVAL => return error.SocketNotBound,
                .WSAEMFILE, .WSAENOBUFS => return error.SystemResources,
                .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                .WSAEOPNOTSUPP => return error.OperationNotSupported,
                .WSAEINPROGRESS => unreachable,
                else => |err| return windows.unexpectedWSAError(err),
            }
        }
        return;
    } else {
        const rc = system.listen(sock, backlog);
        switch (errno(rc)) {
            .SUCCESS => return,
            .ADDRINUSE => return error.AddressInUse,
            .BADF => unreachable,
            .NOTSOCK => return error.FileDescriptorNotASocket,
            .OPNOTSUPP => return error.OperationNotSupported,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const AcceptError = error{
    ConnectionAborted,

    /// The file descriptor sockfd does not refer to a socket.
    FileDescriptorNotASocket,

    /// The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,

    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,

    /// Not enough free memory.  This often means that the memory allocation  is  limited
    /// by the socket buffer limits, not by the system memory.
    SystemResources,

    /// Socket is not listening for new connections.
    SocketNotListening,

    ProtocolFailure,

    /// Firewall rules forbid connection.
    BlockedByFirewall,

    /// This error occurs when no global event loop is configured,
    /// and accepting from the socket would block.
    WouldBlock,

    /// An incoming connection was indicated, but was subsequently terminated by the
    /// remote peer prior to accepting the call.
    ConnectionResetByPeer,

    /// The network subsystem has failed.
    NetworkSubsystemFailed,

    /// The referenced socket is not a type that supports connection-oriented service.
    OperationNotSupported,
} || UnexpectedError;

/// Accept a connection on a socket.
/// If `sockfd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
pub fn accept(
    /// This argument is a socket that has been created with `socket`, bound to a local address
    /// with `bind`, and is listening for connections after a `listen`.
    sock: socket_t,
    /// This argument is a pointer to a sockaddr structure.  This structure is filled in with  the
    /// address  of  the  peer  socket, as known to the communications layer.  The exact format of the
    /// address returned addr is determined by the socket's address  family  (see  `socket`  and  the
    /// respective  protocol  man  pages).
    addr: ?*sockaddr,
    /// This argument is a value-result argument: the caller must initialize it to contain  the
    /// size (in bytes) of the structure pointed to by addr; on return it will contain the actual size
    /// of the peer address.
    ///
    /// The returned address is truncated if the buffer provided is too small; in this  case,  `addr_size`
    /// will return a value greater than was supplied to the call.
    addr_size: ?*socklen_t,
    /// The following values can be bitwise ORed in flags to obtain different behavior:
    /// * `SOCK.NONBLOCK` - Set the `NONBLOCK` file status flag on the open file description (see `open`)
    ///   referred  to by the new file descriptor.  Using this flag saves extra calls to `fcntl` to achieve
    ///   the same result.
    /// * `SOCK.CLOEXEC`  - Set the close-on-exec (`FD_CLOEXEC`) flag on the new file descriptor.   See  the
    ///   description  of the `CLOEXEC` flag in `open` for reasons why this may be useful.
    flags: u32,
) AcceptError!socket_t {
    const have_accept4 = !(builtin.target.os.tag.isDarwin() or native_os == .windows or native_os == .haiku);
    assert(0 == (flags & ~@as(u32, SOCK.NONBLOCK | SOCK.CLOEXEC))); // Unsupported flag(s)

    const accepted_sock: socket_t = while (true) {
        const rc = if (have_accept4)
            system.accept4(sock, addr, addr_size, flags)
        else if (native_os == .windows)
            windows.accept(sock, addr, addr_size)
        else
            system.accept(sock, addr, addr_size);

        if (native_os == .windows) {
            if (rc == windows.ws2_32.INVALID_SOCKET) {
                switch (windows.ws2_32.WSAGetLastError()) {
                    .WSANOTINITIALISED => unreachable, // not initialized WSA
                    .WSAECONNRESET => return error.ConnectionResetByPeer,
                    .WSAEFAULT => unreachable,
                    .WSAEINVAL => return error.SocketNotListening,
                    .WSAEMFILE => return error.ProcessFdQuotaExceeded,
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAENOBUFS => return error.FileDescriptorNotASocket,
                    .WSAEOPNOTSUPP => return error.OperationNotSupported,
                    .WSAEWOULDBLOCK => return error.WouldBlock,
                    else => |err| return windows.unexpectedWSAError(err),
                }
            } else {
                break rc;
            }
        } else {
            switch (errno(rc)) {
                .SUCCESS => break @intCast(rc),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .BADF => unreachable, // always a race condition
                .CONNABORTED => return error.ConnectionAborted,
                .FAULT => unreachable,
                .INVAL => return error.SocketNotListening,
                .NOTSOCK => unreachable,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NOBUFS => return error.SystemResources,
                .NOMEM => return error.SystemResources,
                .OPNOTSUPP => unreachable,
                .PROTO => return error.ProtocolFailure,
                .PERM => return error.BlockedByFirewall,
                else => |err| return unexpectedErrno(err),
            }
        }
    };

    errdefer switch (native_os) {
        .windows => windows.closesocket(accepted_sock) catch unreachable,
        else => close(accepted_sock),
    };
    if (!have_accept4) {
        try setSockFlags(accepted_sock, flags);
    }
    return accepted_sock;
}

fn setSockFlags(sock: socket_t, flags: u32) !void {
    if ((flags & SOCK.CLOEXEC) != 0) {
        if (native_os == .windows) {
            // TODO: Find out if this is supported for sockets
        } else {
            var fd_flags = fcntl(sock, F.GETFD, 0) catch |err| switch (err) {
                error.FileBusy => unreachable,
                error.Locked => unreachable,
                error.PermissionDenied => unreachable,
                error.DeadLock => unreachable,
                error.LockedRegionLimitExceeded => unreachable,
                else => |e| return e,
            };
            fd_flags |= FD_CLOEXEC;
            _ = fcntl(sock, F.SETFD, fd_flags) catch |err| switch (err) {
                error.FileBusy => unreachable,
                error.Locked => unreachable,
                error.PermissionDenied => unreachable,
                error.DeadLock => unreachable,
                error.LockedRegionLimitExceeded => unreachable,
                else => |e| return e,
            };
        }
    }
    if ((flags & SOCK.NONBLOCK) != 0) {
        if (native_os == .windows) {
            var mode: c_ulong = 1;
            if (windows.ws2_32.ioctlsocket(sock, windows.ws2_32.FIONBIO, &mode) == windows.ws2_32.SOCKET_ERROR) {
                switch (windows.ws2_32.WSAGetLastError()) {
                    .WSANOTINITIALISED => unreachable,
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                    // TODO: handle more errors
                    else => |err| return windows.unexpectedWSAError(err),
                }
            }
        } else {
            var fl_flags = fcntl(sock, F.GETFL, 0) catch |err| switch (err) {
                error.FileBusy => unreachable,
                error.Locked => unreachable,
                error.PermissionDenied => unreachable,
                error.DeadLock => unreachable,
                error.LockedRegionLimitExceeded => unreachable,
                else => |e| return e,
            };
            fl_flags |= 1 << @bitOffsetOf(O, "NONBLOCK");
            _ = fcntl(sock, F.SETFL, fl_flags) catch |err| switch (err) {
                error.FileBusy => unreachable,
                error.Locked => unreachable,
                error.PermissionDenied => unreachable,
                error.DeadLock => unreachable,
                error.LockedRegionLimitExceeded => unreachable,
                else => |e| return e,
            };
        }
    }
}

pub const EpollCreateError = error{
    /// The  per-user   limit   on   the   number   of   epoll   instances   imposed   by
    /// /proc/sys/fs/epoll/max_user_instances  was encountered.  See epoll(7) for further
    /// details.
    /// Or, The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,

    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,

    /// There was insufficient memory to create the kernel object.
    SystemResources,
} || UnexpectedError;

pub fn epoll_create1(flags: u32) EpollCreateError!i32 {
    const rc = system.epoll_create1(flags);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return unexpectedErrno(err),

        .INVAL => unreachable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
    }
}

pub const EpollCtlError = error{
    /// op was EPOLL_CTL_ADD, and the supplied file descriptor fd is  already  registered
    /// with this epoll instance.
    FileDescriptorAlreadyPresentInSet,

    /// fd refers to an epoll instance and this EPOLL_CTL_ADD operation would result in a
    /// circular loop of epoll instances monitoring one another.
    OperationCausesCircularLoop,

    /// op was EPOLL_CTL_MOD or EPOLL_CTL_DEL, and fd is not registered with  this  epoll
    /// instance.
    FileDescriptorNotRegistered,

    /// There was insufficient memory to handle the requested op control operation.
    SystemResources,

    /// The  limit  imposed  by /proc/sys/fs/epoll/max_user_watches was encountered while
    /// trying to register (EPOLL_CTL_ADD) a new file descriptor on  an  epoll  instance.
    /// See epoll(7) for further details.
    UserResourceLimitReached,

    /// The target file fd does not support epoll.  This error can occur if fd refers to,
    /// for example, a regular file or a directory.
    FileDescriptorIncompatibleWithEpoll,
} || UnexpectedError;

pub fn epoll_ctl(epfd: i32, op: u32, fd: i32, event: ?*system.epoll_event) EpollCtlError!void {
    const rc = system.epoll_ctl(epfd, op, fd, event);
    switch (errno(rc)) {
        .SUCCESS => return,
        else => |err| return unexpectedErrno(err),

        .BADF => unreachable, // always a race condition if this happens
        .EXIST => return error.FileDescriptorAlreadyPresentInSet,
        .INVAL => unreachable,
        .LOOP => return error.OperationCausesCircularLoop,
        .NOENT => return error.FileDescriptorNotRegistered,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.UserResourceLimitReached,
        .PERM => return error.FileDescriptorIncompatibleWithEpoll,
    }
}

/// Waits for an I/O event on an epoll file descriptor.
/// Returns the number of file descriptors ready for the requested I/O,
/// or zero if no file descriptor became ready during the requested timeout milliseconds.
pub fn epoll_wait(epfd: i32, events: []system.epoll_event, timeout: i32) usize {
    while (true) {
        // TODO get rid of the @intCast
        const rc = system.epoll_wait(epfd, events.ptr, @intCast(events.len), timeout);
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .BADF => unreachable,
            .FAULT => unreachable,
            .INVAL => unreachable,
            else => unreachable,
        }
    }
}

pub const EventFdError = error{
    SystemResources,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
} || UnexpectedError;

pub fn eventfd(initval: u32, flags: u32) EventFdError!i32 {
    const rc = system.eventfd(initval, flags);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return unexpectedErrno(err),

        .INVAL => unreachable, // invalid parameters
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NODEV => return error.SystemResources,
        .NOMEM => return error.SystemResources,
    }
}

pub const GetSockNameError = error{
    /// Insufficient resources were available in the system to perform the operation.
    SystemResources,

    /// The network subsystem has failed.
    NetworkSubsystemFailed,

    /// Socket hasn't been bound yet
    SocketNotBound,

    FileDescriptorNotASocket,
} || UnexpectedError;

pub fn getsockname(sock: socket_t, addr: *sockaddr, addrlen: *socklen_t) GetSockNameError!void {
    if (native_os == .windows) {
        const rc = windows.getsockname(sock, addr, addrlen);
        if (rc == windows.ws2_32.SOCKET_ERROR) {
            switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAEFAULT => unreachable, // addr or addrlen have invalid pointers or addrlen points to an incorrect value
                .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                .WSAEINVAL => return error.SocketNotBound,
                else => |err| return windows.unexpectedWSAError(err),
            }
        }
        return;
    } else {
        const rc = system.getsockname(sock, addr, addrlen);
        switch (errno(rc)) {
            .SUCCESS => return,
            else => |err| return unexpectedErrno(err),

            .BADF => unreachable, // always a race condition
            .FAULT => unreachable,
            .INVAL => unreachable, // invalid parameters
            .NOTSOCK => return error.FileDescriptorNotASocket,
            .NOBUFS => return error.SystemResources,
        }
    }
}

pub fn getpeername(sock: socket_t, addr: *sockaddr, addrlen: *socklen_t) GetSockNameError!void {
    if (native_os == .windows) {
        const rc = windows.getpeername(sock, addr, addrlen);
        if (rc == windows.ws2_32.SOCKET_ERROR) {
            switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAEFAULT => unreachable, // addr or addrlen have invalid pointers or addrlen points to an incorrect value
                .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                .WSAEINVAL => return error.SocketNotBound,
                else => |err| return windows.unexpectedWSAError(err),
            }
        }
        return;
    } else {
        const rc = system.getpeername(sock, addr, addrlen);
        switch (errno(rc)) {
            .SUCCESS => return,
            else => |err| return unexpectedErrno(err),

            .BADF => unreachable, // always a race condition
            .FAULT => unreachable,
            .INVAL => unreachable, // invalid parameters
            .NOTSOCK => return error.FileDescriptorNotASocket,
            .NOBUFS => return error.SystemResources,
        }
    }
}

pub const ConnectError = error{
    /// For UNIX domain sockets, which are identified by pathname: Write permission is denied on  the  socket
    /// file,  or  search  permission  is  denied  for  one of the directories in the path prefix.
    /// or
    /// The user tried to connect to a broadcast address without having the socket broadcast flag enabled  or
    /// the connection request failed because of a local firewall rule.
    AccessDenied,

    /// See AccessDenied
    PermissionDenied,

    /// Local address is already in use.
    AddressInUse,

    /// (Internet  domain  sockets)  The  socket  referred  to  by sockfd had not previously been bound to an
    /// address and, upon attempting to bind it to an ephemeral port, it was determined that all port numbers
    /// in    the    ephemeral    port    range    are   currently   in   use.    See   the   discussion   of
    /// /proc/sys/net/ipv4/ip_local_port_range in ip(7).
    AddressNotAvailable,

    /// The passed address didn't have the correct address family in its sa_family field.
    AddressFamilyNotSupported,

    /// Insufficient entries in the routing cache.
    SystemResources,

    /// A connect() on a stream socket found no one listening on the remote address.
    ConnectionRefused,

    /// Network is unreachable.
    NetworkUnreachable,

    /// Timeout  while  attempting  connection.   The server may be too busy to accept new connections.  Note
    /// that for IP sockets the timeout may be very long when syncookies are enabled on the server.
    ConnectionTimedOut,

    /// This error occurs when no global event loop is configured,
    /// and connecting to the socket would block.
    WouldBlock,

    /// The given path for the unix socket does not exist.
    FileNotFound,

    /// Connection was reset by peer before connect could complete.
    ConnectionResetByPeer,

    /// Socket is non-blocking and already has a pending connection in progress.
    ConnectionPending,
} || UnexpectedError;

/// Initiate a connection on a socket.
/// If `sockfd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN or EINPROGRESS is received.
pub fn connect(sock: socket_t, sock_addr: *const sockaddr, len: socklen_t) ConnectError!void {
    if (native_os == .windows) {
        const rc = windows.ws2_32.connect(sock, sock_addr, @intCast(len));
        if (rc == 0) return;
        switch (windows.ws2_32.WSAGetLastError()) {
            .WSAEADDRINUSE => return error.AddressInUse,
            .WSAEADDRNOTAVAIL => return error.AddressNotAvailable,
            .WSAECONNREFUSED => return error.ConnectionRefused,
            .WSAECONNRESET => return error.ConnectionResetByPeer,
            .WSAETIMEDOUT => return error.ConnectionTimedOut,
            .WSAEHOSTUNREACH, // TODO: should we return NetworkUnreachable in this case as well?
            .WSAENETUNREACH,
            => return error.NetworkUnreachable,
            .WSAEFAULT => unreachable,
            .WSAEINVAL => unreachable,
            .WSAEISCONN => unreachable,
            .WSAENOTSOCK => unreachable,
            .WSAEWOULDBLOCK => return error.WouldBlock,
            .WSAEACCES => unreachable,
            .WSAENOBUFS => return error.SystemResources,
            .WSAEAFNOSUPPORT => return error.AddressFamilyNotSupported,
            else => |err| return windows.unexpectedWSAError(err),
        }
        return;
    }

    while (true) {
        switch (errno(system.connect(sock, sock_addr, len))) {
            .SUCCESS => return,
            .ACCES => return error.AccessDenied,
            .PERM => return error.PermissionDenied,
            .ADDRINUSE => return error.AddressInUse,
            .ADDRNOTAVAIL => return error.AddressNotAvailable,
            .AFNOSUPPORT => return error.AddressFamilyNotSupported,
            .AGAIN, .INPROGRESS => return error.WouldBlock,
            .ALREADY => return error.ConnectionPending,
            .BADF => unreachable, // sockfd is not a valid open file descriptor.
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            .FAULT => unreachable, // The socket structure address is outside the user's address space.
            .INTR => continue,
            .ISCONN => unreachable, // The socket is already connected.
            .HOSTUNREACH => return error.NetworkUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            .PROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
            .TIMEDOUT => return error.ConnectionTimedOut,
            .NOENT => return error.FileNotFound, // Returned when socket is AF.UNIX and the given path does not exist.
            .CONNABORTED => unreachable, // Tried to reuse socket that previously received error.ConnectionRefused.
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const GetSockOptError = error{
    /// The calling process does not have the appropriate privileges.
    AccessDenied,

    /// The option is not supported by the protocol.
    InvalidProtocolOption,

    /// Insufficient resources are available in the system to complete the call.
    SystemResources,
} || UnexpectedError;

pub fn getsockopt(fd: socket_t, level: i32, optname: u32, opt: []u8) GetSockOptError!void {
    var len: socklen_t = undefined;
    switch (errno(system.getsockopt(fd, level, optname, opt.ptr, &len))) {
        .SUCCESS => {
            std.debug.assert(len == opt.len);
        },
        .BADF => unreachable,
        .NOTSOCK => unreachable,
        .INVAL => unreachable,
        .FAULT => unreachable,
        .NOPROTOOPT => return error.InvalidProtocolOption,
        .NOMEM => return error.SystemResources,
        .NOBUFS => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn getsockoptError(sockfd: fd_t) ConnectError!void {
    var err_code: i32 = undefined;
    var size: u32 = @sizeOf(u32);
    const rc = system.getsockopt(sockfd, SOL.SOCKET, SO.ERROR, @ptrCast(&err_code), &size);
    assert(size == 4);
    switch (errno(rc)) {
        .SUCCESS => switch (@as(E, @enumFromInt(err_code))) {
            .SUCCESS => return,
            .ACCES => return error.AccessDenied,
            .PERM => return error.PermissionDenied,
            .ADDRINUSE => return error.AddressInUse,
            .ADDRNOTAVAIL => return error.AddressNotAvailable,
            .AFNOSUPPORT => return error.AddressFamilyNotSupported,
            .AGAIN => return error.SystemResources,
            .ALREADY => return error.ConnectionPending,
            .BADF => unreachable, // sockfd is not a valid open file descriptor.
            .CONNREFUSED => return error.ConnectionRefused,
            .FAULT => unreachable, // The socket structure address is outside the user's address space.
            .ISCONN => unreachable, // The socket is already connected.
            .HOSTUNREACH => return error.NetworkUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            .PROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
            .TIMEDOUT => return error.ConnectionTimedOut,
            .CONNRESET => return error.ConnectionResetByPeer,
            else => |err| return unexpectedErrno(err),
        },
        .BADF => unreachable, // The argument sockfd is not a valid file descriptor.
        .FAULT => unreachable, // The address pointed to by optval or optlen is not in a valid part of the process address space.
        .INVAL => unreachable,
        .NOPROTOOPT => unreachable, // The option is unknown at the level indicated.
        .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
        else => |err| return unexpectedErrno(err),
    }
}

pub const WaitPidResult = struct {
    pid: pid_t,
    status: u32,
};

/// Use this version of the `waitpid` wrapper if you spawned your child process using explicit
/// `fork` and `execve` method.
pub fn waitpid(pid: pid_t, flags: u32) WaitPidResult {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        const rc = system.waitpid(pid, &status, @intCast(flags));
        switch (errno(rc)) {
            .SUCCESS => return .{
                .pid = @intCast(rc),
                .status = @bitCast(status),
            },
            .INTR => continue,
            .CHILD => unreachable, // The process specified does not exist. It would be a race condition to handle this error.
            .INVAL => unreachable, // Invalid flags.
            else => unreachable,
        }
    }
}

pub fn wait4(pid: pid_t, flags: u32, ru: ?*rusage) WaitPidResult {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        const rc = system.wait4(pid, &status, @intCast(flags), ru);
        switch (errno(rc)) {
            .SUCCESS => return .{
                .pid = @intCast(rc),
                .status = @bitCast(status),
            },
            .INTR => continue,
            .CHILD => unreachable, // The process specified does not exist. It would be a race condition to handle this error.
            .INVAL => unreachable, // Invalid flags.
            else => unreachable,
        }
    }
}

pub const FStatError = error{
    SystemResources,

    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to get its filestat information.
    AccessDenied,
    PermissionDenied,
} || UnexpectedError;

/// Return information about a file descriptor.
pub fn fstat(fd: fd_t) FStatError!Stat {
    if (native_os == .wasi and !builtin.link_libc) {
        return Stat.fromFilestat(try std.os.fstat_wasi(fd));
    }
    if (native_os == .windows) {
        @compileError("fstat is not yet implemented on Windows");
    }

    const fstat_sym = if (lfs64_abi) system.fstat64 else system.fstat;
    var stat = mem.zeroes(Stat);
    switch (errno(fstat_sym(fd, &stat))) {
        .SUCCESS => return stat,
        .INVAL => unreachable,
        .BADF => unreachable, // Always a race condition.
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub const FStatAtError = FStatError || error{
    NameTooLong,
    FileNotFound,
    SymLinkLoop,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
};

/// Similar to `fstat`, but returns stat of a resource pointed to by `pathname`
/// which is relative to `dirfd` handle.
/// On WASI, `pathname` should be encoded as valid UTF-8.
/// On other platforms, `pathname` is an opaque sequence of bytes with no particular encoding.
/// See also `fstatatZ` and `std.os.fstatat_wasi`.
pub fn fstatat(dirfd: fd_t, pathname: []const u8, flags: u32) FStatAtError!Stat {
    if (native_os == .wasi and !builtin.link_libc) {
        const filestat = try std.os.fstatat_wasi(dirfd, pathname, .{
            .SYMLINK_FOLLOW = (flags & AT.SYMLINK_NOFOLLOW) == 0,
        });
        return Stat.fromFilestat(filestat);
    } else if (native_os == .windows) {
        @compileError("fstatat is not yet implemented on Windows");
    } else {
        const pathname_c = try toPosixPath(pathname);
        return fstatatZ(dirfd, &pathname_c, flags);
    }
}

/// Same as `fstatat` but `pathname` is null-terminated.
/// See also `fstatat`.
pub fn fstatatZ(dirfd: fd_t, pathname: [*:0]const u8, flags: u32) FStatAtError!Stat {
    if (native_os == .wasi and !builtin.link_libc) {
        const filestat = try std.os.fstatat_wasi(dirfd, mem.sliceTo(pathname, 0), .{
            .SYMLINK_FOLLOW = (flags & AT.SYMLINK_NOFOLLOW) == 0,
        });
        return Stat.fromFilestat(filestat);
    }

    const fstatat_sym = if (lfs64_abi) system.fstatat64 else system.fstatat;
    var stat = mem.zeroes(Stat);
    switch (errno(fstatat_sym(dirfd, pathname, &stat, flags))) {
        .SUCCESS => return stat,
        .INVAL => unreachable,
        .BADF => unreachable, // Always a race condition.
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .FAULT => unreachable,
        .NAMETOOLONG => return error.NameTooLong,
        .LOOP => return error.SymLinkLoop,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.FileNotFound,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

pub const KQueueError = error{
    /// The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,

    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,
} || UnexpectedError;

pub fn kqueue() KQueueError!i32 {
    const rc = system.kqueue();
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return unexpectedErrno(err),
    }
}

pub const KEventError = error{
    /// The process does not have permission to register a filter.
    AccessDenied,

    /// The event could not be found to be modified or deleted.
    EventNotFound,

    /// No memory was available to register the event.
    SystemResources,

    /// The specified process to attach to does not exist.
    ProcessNotFound,

    /// changelist or eventlist had too many items on it.
    /// TODO remove this possibility
    Overflow,
};

pub fn kevent(
    kq: i32,
    changelist: []const Kevent,
    eventlist: []Kevent,
    timeout: ?*const timespec,
) KEventError!usize {
    while (true) {
        const rc = system.kevent(
            kq,
            changelist.ptr,
            cast(c_int, changelist.len) orelse return error.Overflow,
            eventlist.ptr,
            cast(c_int, eventlist.len) orelse return error.Overflow,
            timeout,
        );
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .ACCES => return error.AccessDenied,
            .FAULT => unreachable,
            .BADF => unreachable, // Always a race condition.
            .INTR => continue,
            .INVAL => unreachable,
            .NOENT => return error.EventNotFound,
            .NOMEM => return error.SystemResources,
            .SRCH => return error.ProcessNotFound,
            else => unreachable,
        }
    }
}

pub const INotifyInitError = error{
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
} || UnexpectedError;

/// initialize an inotify instance
pub fn inotify_init1(flags: u32) INotifyInitError!i32 {
    const rc = system.inotify_init1(flags);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .INVAL => unreachable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        else => |err| return unexpectedErrno(err),
    }
}

pub const INotifyAddWatchError = error{
    AccessDenied,
    NameTooLong,
    FileNotFound,
    SystemResources,
    UserResourceLimitReached,
    NotDir,
    WatchAlreadyExists,
} || UnexpectedError;

/// add a watch to an initialized inotify instance
pub fn inotify_add_watch(inotify_fd: i32, pathname: []const u8, mask: u32) INotifyAddWatchError!i32 {
    const pathname_c = try toPosixPath(pathname);
    return inotify_add_watchZ(inotify_fd, &pathname_c, mask);
}

/// Same as `inotify_add_watch` except pathname is null-terminated.
pub fn inotify_add_watchZ(inotify_fd: i32, pathname: [*:0]const u8, mask: u32) INotifyAddWatchError!i32 {
    const rc = system.inotify_add_watch(inotify_fd, pathname, mask);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .BADF => unreachable,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.UserResourceLimitReached,
        .NOTDIR => return error.NotDir,
        .EXIST => return error.WatchAlreadyExists,
        else => |err| return unexpectedErrno(err),
    }
}

/// remove an existing watch from an inotify instance
pub fn inotify_rm_watch(inotify_fd: i32, wd: i32) void {
    switch (errno(system.inotify_rm_watch(inotify_fd, wd))) {
        .SUCCESS => return,
        .BADF => unreachable,
        .INVAL => unreachable,
        else => unreachable,
    }
}

pub const FanotifyInitError = error{
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    PermissionDenied,
    /// The kernel does not recognize the flags passed, likely because it is an
    /// older version.
    UnsupportedFlags,
} || UnexpectedError;

pub fn fanotify_init(flags: std.os.linux.fanotify.InitFlags, event_f_flags: u32) FanotifyInitError!i32 {
    const rc = system.fanotify_init(flags, event_f_flags);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .INVAL => return error.UnsupportedFlags,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub const FanotifyMarkError = error{
    MarkAlreadyExists,
    IsDir,
    NotAssociatedWithFileSystem,
    FileNotFound,
    SystemResources,
    UserMarkQuotaExceeded,
    NotDir,
    OperationNotSupported,
    PermissionDenied,
    NotSameFileSystem,
    NameTooLong,
} || UnexpectedError;

pub fn fanotify_mark(
    fanotify_fd: fd_t,
    flags: std.os.linux.fanotify.MarkFlags,
    mask: std.os.linux.fanotify.MarkMask,
    dirfd: fd_t,
    pathname: ?[]const u8,
) FanotifyMarkError!void {
    if (pathname) |path| {
        const path_c = try toPosixPath(path);
        return fanotify_markZ(fanotify_fd, flags, mask, dirfd, &path_c);
    } else {
        return fanotify_markZ(fanotify_fd, flags, mask, dirfd, null);
    }
}

pub fn fanotify_markZ(
    fanotify_fd: fd_t,
    flags: std.os.linux.fanotify.MarkFlags,
    mask: std.os.linux.fanotify.MarkMask,
    dirfd: fd_t,
    pathname: ?[*:0]const u8,
) FanotifyMarkError!void {
    const rc = system.fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname);
    switch (errno(rc)) {
        .SUCCESS => return,
        .BADF => unreachable,
        .EXIST => return error.MarkAlreadyExists,
        .INVAL => unreachable,
        .ISDIR => return error.IsDir,
        .NODEV => return error.NotAssociatedWithFileSystem,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.UserMarkQuotaExceeded,
        .NOTDIR => return error.NotDir,
        .OPNOTSUPP => return error.OperationNotSupported,
        .PERM => return error.PermissionDenied,
        .XDEV => return error.NotSameFileSystem,
        else => |err| return unexpectedErrno(err),
    }
}

pub const MProtectError = error{
    /// The memory cannot be given the specified access.  This can happen, for example, if you
    /// mmap(2)  a  file  to  which  you have read-only access, then ask mprotect() to mark it
    /// PROT_WRITE.
    AccessDenied,

    /// Changing  the  protection  of a memory region would result in the total number of map‐
    /// pings with distinct attributes (e.g., read versus read/write protection) exceeding the
    /// allowed maximum.  (For example, making the protection of a range PROT_READ in the mid‐
    /// dle of a region currently protected as PROT_READ|PROT_WRITE would result in three map‐
    /// pings: two read/write mappings at each end and a read-only mapping in the middle.)
    OutOfMemory,
} || UnexpectedError;

pub fn mprotect(memory: []align(page_size_min) u8, protection: u32) MProtectError!void {
    if (native_os == .windows) {
        const win_prot: windows.DWORD = switch (@as(u3, @truncate(protection))) {
            0b000 => windows.PAGE_NOACCESS,
            0b001 => windows.PAGE_READONLY,
            0b010 => unreachable, // +w -r not allowed
            0b011 => windows.PAGE_READWRITE,
            0b100 => windows.PAGE_EXECUTE,
            0b101 => windows.PAGE_EXECUTE_READ,
            0b110 => unreachable, // +w -r not allowed
            0b111 => windows.PAGE_EXECUTE_READWRITE,
        };
        var old: windows.DWORD = undefined;
        windows.VirtualProtect(memory.ptr, memory.len, win_prot, &old) catch |err| switch (err) {
            error.InvalidAddress => return error.AccessDenied,
            error.Unexpected => return error.Unexpected,
        };
    } else {
        switch (errno(system.mprotect(memory.ptr, memory.len, protection))) {
            .SUCCESS => return,
            .INVAL => unreachable,
            .ACCES => return error.AccessDenied,
            .NOMEM => return error.OutOfMemory,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const ForkError = error{SystemResources} || UnexpectedError;

pub fn fork() ForkError!pid_t {
    const rc = system.fork();
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        else => |err| return unexpectedErrno(err),
    }
}

pub const MMapError = error{
    /// The underlying filesystem of the specified file does not support memory mapping.
    MemoryMappingNotSupported,

    /// A file descriptor refers to a non-regular file. Or a file mapping was requested,
    /// but the file descriptor is not open for reading. Or `MAP.SHARED` was requested
    /// and `PROT_WRITE` is set, but the file descriptor is not open in `RDWR` mode.
    /// Or `PROT_WRITE` is set, but the file is append-only.
    AccessDenied,

    /// The `prot` argument asks for `PROT_EXEC` but the mapped area belongs to a file on
    /// a filesystem that was mounted no-exec.
    PermissionDenied,
    LockedMemoryLimitExceeded,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    OutOfMemory,

    /// Using FIXED_NOREPLACE flag and the process has already mapped memory at the given address
    MappingAlreadyExists,
} || UnexpectedError;

/// Map files or devices into memory.
/// `length` does not need to be aligned.
/// Use of a mapped region can result in these signals:
/// * SIGSEGV - Attempted write into a region mapped as read-only.
/// * SIGBUS - Attempted  access to a portion of the buffer that does not correspond to the file
pub fn mmap(
    ptr: ?[*]align(page_size_min) u8,
    length: usize,
    prot: u32,
    flags: system.MAP,
    fd: fd_t,
    offset: u64,
) MMapError![]align(page_size_min) u8 {
    const mmap_sym = if (lfs64_abi) system.mmap64 else system.mmap;
    const rc = mmap_sym(ptr, length, prot, @bitCast(flags), fd, @bitCast(offset));
    const err: E = if (builtin.link_libc) blk: {
        if (rc != std.c.MAP_FAILED) return @as([*]align(page_size_min) u8, @ptrCast(@alignCast(rc)))[0..length];
        break :blk @enumFromInt(system._errno().*);
    } else blk: {
        const err = errno(rc);
        if (err == .SUCCESS) return @as([*]align(page_size_min) u8, @ptrFromInt(rc))[0..length];
        break :blk err;
    };
    switch (err) {
        .SUCCESS => unreachable,
        .TXTBSY => return error.AccessDenied,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .AGAIN => return error.LockedMemoryLimitExceeded,
        .BADF => unreachable, // Always a race condition.
        .OVERFLOW => unreachable, // The number of pages used for length + offset would overflow.
        .NODEV => return error.MemoryMappingNotSupported,
        .INVAL => unreachable, // Invalid parameters to mmap()
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.OutOfMemory,
        .EXIST => return error.MappingAlreadyExists,
        else => return unexpectedErrno(err),
    }
}

/// Deletes the mappings for the specified address range, causing
/// further references to addresses within the range to generate invalid memory references.
/// Note that while POSIX allows unmapping a region in the middle of an existing mapping,
/// Zig's munmap function does not, for two reasons:
/// * It violates the Zig principle that resource deallocation must succeed.
/// * The Windows function, VirtualFree, has this restriction.
pub fn munmap(memory: []align(page_size_min) const u8) void {
    switch (errno(system.munmap(memory.ptr, memory.len))) {
        .SUCCESS => return,
        .INVAL => unreachable, // Invalid parameters.
        .NOMEM => unreachable, // Attempted to unmap a region in the middle of an existing mapping.
        else => unreachable,
    }
}

pub const MRemapError = error{
    LockedMemoryLimitExceeded,
    /// Either a bug in the calling code, or the operating system abused the
    /// EINVAL error code.
    InvalidSyscallParameters,
    OutOfMemory,
} || UnexpectedError;

pub fn mremap(
    old_address: ?[*]align(page_size_min) u8,
    old_len: usize,
    new_len: usize,
    flags: system.MREMAP,
    new_address: ?[*]align(page_size_min) u8,
) MRemapError![]align(page_size_min) u8 {
    const rc = system.mremap(old_address, old_len, new_len, flags, new_address);
    const err: E = if (builtin.link_libc) blk: {
        if (rc != std.c.MAP_FAILED) return @as([*]align(page_size_min) u8, @ptrCast(@alignCast(rc)))[0..new_len];
        break :blk @enumFromInt(system._errno().*);
    } else blk: {
        const err = errno(rc);
        if (err == .SUCCESS) return @as([*]align(page_size_min) u8, @ptrFromInt(rc))[0..new_len];
        break :blk err;
    };
    switch (err) {
        .SUCCESS => unreachable,
        .AGAIN => return error.LockedMemoryLimitExceeded,
        .INVAL => return error.InvalidSyscallParameters,
        .NOMEM => return error.OutOfMemory,
        .FAULT => unreachable,
        else => return unexpectedErrno(err),
    }
}

pub const MSyncError = error{
    UnmappedMemory,
    PermissionDenied,
} || UnexpectedError;

pub fn msync(memory: []align(page_size_min) u8, flags: i32) MSyncError!void {
    switch (errno(system.msync(memory.ptr, memory.len, flags))) {
        .SUCCESS => return,
        .PERM => return error.PermissionDenied,
        .NOMEM => return error.UnmappedMemory, // Unsuccessful, provided pointer does not point mapped memory
        .INVAL => unreachable, // Invalid parameters.
        else => unreachable,
    }
}

pub const AccessError = error{
    AccessDenied,
    PermissionDenied,
    FileNotFound,
    NameTooLong,
    InputOutput,
    SystemResources,
    BadPathName,
    FileBusy,
    SymLinkLoop,
    ReadOnlyFileSystem,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
} || UnexpectedError;

/// check user's permissions for a file
///
/// * On Windows, asserts `path` is valid [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On WASI, invalid UTF-8 passed to `path` causes `error.InvalidUtf8`.
/// * On other platforms, `path` is an opaque sequence of bytes with no particular encoding.
///
/// On Windows, `mode` is ignored. This is a POSIX API that is only partially supported by
/// Windows. See `fs` for the cross-platform file system API.
pub fn access(path: []const u8, mode: u32) AccessError!void {
    if (native_os == .windows) {
        const path_w = try windows.sliceToPrefixedFileW(null, path);
        _ = try windows.GetFileAttributesW(path_w.span().ptr);
        return;
    } else if (native_os == .wasi and !builtin.link_libc) {
        return faccessat(AT.FDCWD, path, mode, 0);
    }
    const path_c = try toPosixPath(path);
    return accessZ(&path_c, mode);
}

/// Same as `access` except `path` is null-terminated.
pub fn accessZ(path: [*:0]const u8, mode: u32) AccessError!void {
    if (native_os == .windows) {
        const path_w = try windows.cStrToPrefixedFileW(null, path);
        _ = try windows.GetFileAttributesW(path_w.span().ptr);
        return;
    } else if (native_os == .wasi and !builtin.link_libc) {
        return access(mem.sliceTo(path, 0), mode);
    }
    switch (errno(system.access(path, mode))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .ROFS => return error.ReadOnlyFileSystem,
        .LOOP => return error.SymLinkLoop,
        .TXTBSY => return error.FileBusy,
        .NOTDIR => return error.FileNotFound,
        .NOENT => return error.FileNotFound,
        .NAMETOOLONG => return error.NameTooLong,
        .INVAL => unreachable,
        .FAULT => unreachable,
        .IO => return error.InputOutput,
        .NOMEM => return error.SystemResources,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Check user's permissions for a file, based on an open directory handle.
///
/// * On Windows, asserts `path` is valid [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On WASI, invalid UTF-8 passed to `path` causes `error.InvalidUtf8`.
/// * On other platforms, `path` is an opaque sequence of bytes with no particular encoding.
///
/// On Windows, `mode` is ignored. This is a POSIX API that is only partially supported by
/// Windows. See `fs` for the cross-platform file system API.
pub fn faccessat(dirfd: fd_t, path: []const u8, mode: u32, flags: u32) AccessError!void {
    if (native_os == .windows) {
        const path_w = try windows.sliceToPrefixedFileW(dirfd, path);
        return faccessatW(dirfd, path_w.span().ptr);
    } else if (native_os == .wasi and !builtin.link_libc) {
        const resolved: RelativePathWasi = .{ .dir_fd = dirfd, .relative_path = path };

        const st = try std.os.fstatat_wasi(dirfd, path, .{
            .SYMLINK_FOLLOW = (flags & AT.SYMLINK_NOFOLLOW) == 0,
        });

        if (mode != F_OK) {
            var directory: wasi.fdstat_t = undefined;
            if (wasi.fd_fdstat_get(resolved.dir_fd, &directory) != .SUCCESS) {
                return error.AccessDenied;
            }

            var rights: wasi.rights_t = .{};
            if (mode & R_OK != 0) {
                if (st.filetype == .DIRECTORY) {
                    rights.FD_READDIR = true;
                } else {
                    rights.FD_READ = true;
                }
            }
            if (mode & W_OK != 0) {
                rights.FD_WRITE = true;
            }
            // No validation for X_OK

            // https://github.com/ziglang/zig/issues/18882
            const rights_int: u64 = @bitCast(rights);
            const inheriting_int: u64 = @bitCast(directory.fs_rights_inheriting);
            if ((rights_int & inheriting_int) != rights_int) {
                return error.AccessDenied;
            }
        }
        return;
    }
    const path_c = try toPosixPath(path);
    return faccessatZ(dirfd, &path_c, mode, flags);
}

/// Same as `faccessat` except the path parameter is null-terminated.
pub fn faccessatZ(dirfd: fd_t, path: [*:0]const u8, mode: u32, flags: u32) AccessError!void {
    if (native_os == .windows) {
        const path_w = try windows.cStrToPrefixedFileW(dirfd, path);
        return faccessatW(dirfd, path_w.span().ptr);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return faccessat(dirfd, mem.sliceTo(path, 0), mode, flags);
    }
    switch (errno(system.faccessat(dirfd, path, mode, flags))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .ROFS => return error.ReadOnlyFileSystem,
        .LOOP => return error.SymLinkLoop,
        .TXTBSY => return error.FileBusy,
        .NOTDIR => return error.FileNotFound,
        .NOENT => return error.FileNotFound,
        .NAMETOOLONG => return error.NameTooLong,
        .INVAL => unreachable,
        .FAULT => unreachable,
        .IO => return error.InputOutput,
        .NOMEM => return error.SystemResources,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Same as `faccessat` except asserts the target is Windows and the path parameter
/// is NtDll-prefixed, null-terminated, WTF-16 encoded.
pub fn faccessatW(dirfd: fd_t, sub_path_w: [*:0]const u16) AccessError!void {
    if (sub_path_w[0] == '.' and sub_path_w[1] == 0) {
        return;
    }
    if (sub_path_w[0] == '.' and sub_path_w[1] == '.' and sub_path_w[2] == 0) {
        return;
    }

    const path_len_bytes = cast(u16, mem.sliceTo(sub_path_w, 0).len * 2) orelse return error.NameTooLong;
    var nt_name = windows.UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(sub_path_w),
    };
    var attr = windows.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(windows.OBJECT_ATTRIBUTES),
        .RootDirectory = if (fs.path.isAbsoluteWindowsW(sub_path_w)) null else dirfd,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var basic_info: windows.FILE_BASIC_INFORMATION = undefined;
    switch (windows.ntdll.NtQueryAttributesFile(&attr, &basic_info)) {
        .SUCCESS => return,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .OBJECT_NAME_INVALID => unreachable,
        .INVALID_PARAMETER => unreachable,
        .ACCESS_DENIED => return error.AccessDenied,
        .OBJECT_PATH_SYNTAX_BAD => unreachable,
        else => |rc| return windows.unexpectedStatus(rc),
    }
}

pub const PipeError = error{
    SystemFdQuotaExceeded,
    ProcessFdQuotaExceeded,
} || UnexpectedError;

/// Creates a unidirectional data channel that can be used for interprocess communication.
pub fn pipe() PipeError![2]fd_t {
    var fds: [2]fd_t = undefined;
    switch (errno(system.pipe(&fds))) {
        .SUCCESS => return fds,
        .INVAL => unreachable, // Invalid parameters to pipe()
        .FAULT => unreachable, // Invalid fds pointer
        .NFILE => return error.SystemFdQuotaExceeded,
        .MFILE => return error.ProcessFdQuotaExceeded,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn pipe2(flags: O) PipeError![2]fd_t {
    if (@TypeOf(system.pipe2) != void) {
        var fds: [2]fd_t = undefined;
        switch (errno(system.pipe2(&fds, flags))) {
            .SUCCESS => return fds,
            .INVAL => unreachable, // Invalid flags
            .FAULT => unreachable, // Invalid fds pointer
            .NFILE => return error.SystemFdQuotaExceeded,
            .MFILE => return error.ProcessFdQuotaExceeded,
            else => |err| return unexpectedErrno(err),
        }
    }

    const fds: [2]fd_t = try pipe();
    errdefer {
        close(fds[0]);
        close(fds[1]);
    }

    // https://github.com/ziglang/zig/issues/18882
    if (@as(u32, @bitCast(flags)) == 0)
        return fds;

    // CLOEXEC is special, it's a file descriptor flag and must be set using
    // F.SETFD.
    if (flags.CLOEXEC) {
        for (fds) |fd| {
            switch (errno(system.fcntl(fd, F.SETFD, @as(u32, FD_CLOEXEC)))) {
                .SUCCESS => {},
                .INVAL => unreachable, // Invalid flags
                .BADF => unreachable, // Always a race condition
                else => |err| return unexpectedErrno(err),
            }
        }
    }

    const new_flags: u32 = f: {
        var new_flags = flags;
        new_flags.CLOEXEC = false;
        break :f @bitCast(new_flags);
    };
    // Set every other flag affecting the file status using F.SETFL.
    if (new_flags != 0) {
        for (fds) |fd| {
            switch (errno(system.fcntl(fd, F.SETFL, new_flags))) {
                .SUCCESS => {},
                .INVAL => unreachable, // Invalid flags
                .BADF => unreachable, // Always a race condition
                else => |err| return unexpectedErrno(err),
            }
        }
    }

    return fds;
}

pub const SysCtlError = error{
    PermissionDenied,
    SystemResources,
    NameTooLong,
    UnknownName,
} || UnexpectedError;

pub fn sysctl(
    name: []const c_int,
    oldp: ?*anyopaque,
    oldlenp: ?*usize,
    newp: ?*anyopaque,
    newlen: usize,
) SysCtlError!void {
    if (native_os == .wasi) {
        @compileError("sysctl not supported on WASI");
    }
    if (native_os == .haiku) {
        @compileError("sysctl not supported on Haiku");
    }

    const name_len = cast(c_uint, name.len) orelse return error.NameTooLong;
    switch (errno(system.sysctl(name.ptr, name_len, oldp, oldlenp, newp, newlen))) {
        .SUCCESS => return,
        .FAULT => unreachable,
        .PERM => return error.PermissionDenied,
        .NOMEM => return error.SystemResources,
        .NOENT => return error.UnknownName,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn sysctlbynameZ(
    name: [*:0]const u8,
    oldp: ?*anyopaque,
    oldlenp: ?*usize,
    newp: ?*anyopaque,
    newlen: usize,
) SysCtlError!void {
    if (native_os == .wasi) {
        @compileError("sysctl not supported on WASI");
    }
    if (native_os == .haiku) {
        @compileError("sysctl not supported on Haiku");
    }

    switch (errno(system.sysctlbyname(name, oldp, oldlenp, newp, newlen))) {
        .SUCCESS => return,
        .FAULT => unreachable,
        .PERM => return error.PermissionDenied,
        .NOMEM => return error.SystemResources,
        .NOENT => return error.UnknownName,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn gettimeofday(tv: ?*timeval, tz: ?*timezone) void {
    switch (errno(system.gettimeofday(tv, tz))) {
        .SUCCESS => return,
        .INVAL => unreachable,
        else => unreachable,
    }
}

pub const SeekError = error{
    Unseekable,

    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to seek on it.
    AccessDenied,
} || UnexpectedError;

/// Repositions read/write file offset relative to the beginning.
pub fn lseek_SET(fd: fd_t, offset: u64) SeekError!void {
    if (native_os == .linux and !builtin.link_libc and @sizeOf(usize) == 4) {
        var result: u64 = undefined;
        switch (errno(system.llseek(fd, offset, &result, SEEK.SET))) {
            .SUCCESS => return,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            else => |err| return unexpectedErrno(err),
        }
    }
    if (native_os == .windows) {
        return windows.SetFilePointerEx_BEGIN(fd, offset);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var new_offset: wasi.filesize_t = undefined;
        switch (wasi.fd_seek(fd, @bitCast(offset), .SET, &new_offset)) {
            .SUCCESS => return,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    const lseek_sym = if (lfs64_abi) system.lseek64 else system.lseek;
    switch (errno(lseek_sym(fd, @bitCast(offset), SEEK.SET))) {
        .SUCCESS => return,
        .BADF => unreachable, // always a race condition
        .INVAL => return error.Unseekable,
        .OVERFLOW => return error.Unseekable,
        .SPIPE => return error.Unseekable,
        .NXIO => return error.Unseekable,
        else => |err| return unexpectedErrno(err),
    }
}

/// Repositions read/write file offset relative to the current offset.
pub fn lseek_CUR(fd: fd_t, offset: i64) SeekError!void {
    if (native_os == .linux and !builtin.link_libc and @sizeOf(usize) == 4) {
        var result: u64 = undefined;
        switch (errno(system.llseek(fd, @bitCast(offset), &result, SEEK.CUR))) {
            .SUCCESS => return,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            else => |err| return unexpectedErrno(err),
        }
    }
    if (native_os == .windows) {
        return windows.SetFilePointerEx_CURRENT(fd, offset);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var new_offset: wasi.filesize_t = undefined;
        switch (wasi.fd_seek(fd, offset, .CUR, &new_offset)) {
            .SUCCESS => return,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }
    const lseek_sym = if (lfs64_abi) system.lseek64 else system.lseek;
    switch (errno(lseek_sym(fd, @bitCast(offset), SEEK.CUR))) {
        .SUCCESS => return,
        .BADF => unreachable, // always a race condition
        .INVAL => return error.Unseekable,
        .OVERFLOW => return error.Unseekable,
        .SPIPE => return error.Unseekable,
        .NXIO => return error.Unseekable,
        else => |err| return unexpectedErrno(err),
    }
}

/// Repositions read/write file offset relative to the end.
pub fn lseek_END(fd: fd_t, offset: i64) SeekError!void {
    if (native_os == .linux and !builtin.link_libc and @sizeOf(usize) == 4) {
        var result: u64 = undefined;
        switch (errno(system.llseek(fd, @bitCast(offset), &result, SEEK.END))) {
            .SUCCESS => return,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            else => |err| return unexpectedErrno(err),
        }
    }
    if (native_os == .windows) {
        return windows.SetFilePointerEx_END(fd, offset);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var new_offset: wasi.filesize_t = undefined;
        switch (wasi.fd_seek(fd, offset, .END, &new_offset)) {
            .SUCCESS => return,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }
    const lseek_sym = if (lfs64_abi) system.lseek64 else system.lseek;
    switch (errno(lseek_sym(fd, @bitCast(offset), SEEK.END))) {
        .SUCCESS => return,
        .BADF => unreachable, // always a race condition
        .INVAL => return error.Unseekable,
        .OVERFLOW => return error.Unseekable,
        .SPIPE => return error.Unseekable,
        .NXIO => return error.Unseekable,
        else => |err| return unexpectedErrno(err),
    }
}

/// Returns the read/write file offset relative to the beginning.
pub fn lseek_CUR_get(fd: fd_t) SeekError!u64 {
    if (native_os == .linux and !builtin.link_libc and @sizeOf(usize) == 4) {
        var result: u64 = undefined;
        switch (errno(system.llseek(fd, 0, &result, SEEK.CUR))) {
            .SUCCESS => return result,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            else => |err| return unexpectedErrno(err),
        }
    }
    if (native_os == .windows) {
        return windows.SetFilePointerEx_CURRENT_get(fd);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var new_offset: wasi.filesize_t = undefined;
        switch (wasi.fd_seek(fd, 0, .CUR, &new_offset)) {
            .SUCCESS => return new_offset,
            .BADF => unreachable, // always a race condition
            .INVAL => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .NXIO => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }
    const lseek_sym = if (lfs64_abi) system.lseek64 else system.lseek;
    const rc = lseek_sym(fd, 0, SEEK.CUR);
    switch (errno(rc)) {
        .SUCCESS => return @bitCast(rc),
        .BADF => unreachable, // always a race condition
        .INVAL => return error.Unseekable,
        .OVERFLOW => return error.Unseekable,
        .SPIPE => return error.Unseekable,
        .NXIO => return error.Unseekable,
        else => |err| return unexpectedErrno(err),
    }
}

pub const FcntlError = error{
    PermissionDenied,
    FileBusy,
    ProcessFdQuotaExceeded,
    Locked,
    DeadLock,
    LockedRegionLimitExceeded,
} || UnexpectedError;

pub fn fcntl(fd: fd_t, cmd: i32, arg: usize) FcntlError!usize {
    while (true) {
        const rc = system.fcntl(fd, cmd, arg);
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN, .ACCES => return error.Locked,
            .BADF => unreachable,
            .BUSY => return error.FileBusy,
            .INVAL => unreachable, // invalid parameters
            .PERM => return error.PermissionDenied,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NOTDIR => unreachable, // invalid parameter
            .DEADLK => return error.DeadLock,
            .NOLCK => return error.LockedRegionLimitExceeded,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const FlockError = error{
    WouldBlock,

    /// The kernel ran out of memory for allocating file locks
    SystemResources,

    /// The underlying filesystem does not support file locks
    FileLocksNotSupported,
} || UnexpectedError;

/// Depending on the operating system `flock` may or may not interact with
/// `fcntl` locks made by other processes.
pub fn flock(fd: fd_t, operation: i32) FlockError!void {
    while (true) {
        const rc = system.flock(fd, operation);
        switch (errno(rc)) {
            .SUCCESS => return,
            .BADF => unreachable,
            .INTR => continue,
            .INVAL => unreachable, // invalid parameters
            .NOLCK => return error.SystemResources,
            .AGAIN => return error.WouldBlock, // TODO: integrate with async instead of just returning an error
            .OPNOTSUPP => return error.FileLocksNotSupported,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const RealPathError = error{
    FileNotFound,
    AccessDenied,
    PermissionDenied,
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
    ProcessNotFound,

    SharingViolation,
    PipeBusy,

    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,

    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,

    PathAlreadyExists,

    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,

    /// On Windows, the volume does not contain a recognized file system. File
    /// system drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
} || UnexpectedError;

/// Return the canonicalized absolute pathname.
///
/// Expands all symbolic links and resolves references to `.`, `..`, and
/// extra `/` characters in `pathname`.
///
/// On Windows, `pathname` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
///
/// On other platforms, `pathname` is an opaque sequence of bytes with no particular encoding.
///
/// The return value is a slice of `out_buffer`, but not necessarily from the beginning.
///
/// See also `realpathZ` and `realpathW`.
///
/// * On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On other platforms, the result is an opaque sequence of bytes with no particular encoding.
///
/// Calling this function is usually a bug.
pub fn realpath(pathname: []const u8, out_buffer: *[max_path_bytes]u8) RealPathError![]u8 {
    if (native_os == .windows) {
        const pathname_w = try windows.sliceToPrefixedFileW(null, pathname);
        return realpathW(pathname_w.span(), out_buffer);
    } else if (native_os == .wasi and !builtin.link_libc) {
        @compileError("WASI does not support os.realpath");
    }
    const pathname_c = try toPosixPath(pathname);
    return realpathZ(&pathname_c, out_buffer);
}

/// Same as `realpath` except `pathname` is null-terminated.
///
/// Calling this function is usually a bug.
pub fn realpathZ(pathname: [*:0]const u8, out_buffer: *[max_path_bytes]u8) RealPathError![]u8 {
    if (native_os == .windows) {
        const pathname_w = try windows.cStrToPrefixedFileW(null, pathname);
        return realpathW(pathname_w.span(), out_buffer);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return realpath(mem.sliceTo(pathname, 0), out_buffer);
    }
    if (!builtin.link_libc) {
        const flags: O = switch (native_os) {
            .linux => .{
                .NONBLOCK = true,
                .CLOEXEC = true,
                .PATH = true,
            },
            else => .{
                .NONBLOCK = true,
                .CLOEXEC = true,
            },
        };
        const fd = openZ(pathname, flags, 0) catch |err| switch (err) {
            error.FileLocksNotSupported => unreachable,
            error.WouldBlock => unreachable,
            error.FileBusy => unreachable, // not asking for write permissions
            error.InvalidUtf8 => unreachable, // WASI-only
            else => |e| return e,
        };
        defer close(fd);

        return std.os.getFdPath(fd, out_buffer);
    }
    const result_path = std.c.realpath(pathname, out_buffer) orelse switch (@as(E, @enumFromInt(std.c._errno().*))) {
        .SUCCESS => unreachable,
        .INVAL => unreachable,
        .BADF => unreachable,
        .FAULT => unreachable,
        .ACCES => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .OPNOTSUPP => return error.NotSupported,
        .NOTDIR => return error.NotDir,
        .NAMETOOLONG => return error.NameTooLong,
        .LOOP => return error.SymLinkLoop,
        .IO => return error.InputOutput,
        else => |err| return unexpectedErrno(err),
    };
    return mem.sliceTo(result_path, 0);
}

/// Same as `realpath` except `pathname` is WTF16LE-encoded.
///
/// The result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
///
/// Calling this function is usually a bug.
pub fn realpathW(pathname: []const u16, out_buffer: *[max_path_bytes]u8) RealPathError![]u8 {
    const w = windows;

    const dir = fs.cwd().fd;
    const access_mask = w.GENERIC_READ | w.SYNCHRONIZE;
    const share_access = w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE;
    const creation = w.FILE_OPEN;
    const h_file = blk: {
        const res = w.OpenFile(pathname, .{
            .dir = dir,
            .access_mask = access_mask,
            .share_access = share_access,
            .creation = creation,
            .filter = .any,
        }) catch |err| switch (err) {
            error.WouldBlock => unreachable,
            else => |e| return e,
        };
        break :blk res;
    };
    defer w.CloseHandle(h_file);

    return std.os.getFdPath(h_file, out_buffer);
}

/// Spurious wakeups are possible and no precision of timing is guaranteed.
pub fn nanosleep(seconds: u64, nanoseconds: u64) void {
    var req = timespec{
        .sec = cast(isize, seconds) orelse maxInt(isize),
        .nsec = cast(isize, nanoseconds) orelse maxInt(isize),
    };
    var rem: timespec = undefined;
    while (true) {
        switch (errno(system.nanosleep(&req, &rem))) {
            .FAULT => unreachable,
   ```
