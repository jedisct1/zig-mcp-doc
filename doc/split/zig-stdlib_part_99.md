```
ort() libc function. Otherwise
/// it raises SIGABRT followed by SIGKILL and finally lo
/// Invokes the current signal handler for SIGABRT, if any.
pub fn abort() noreturn {
    @branchHint(.cold);
    // MSVCRT abort() sometimes opens a popup window which is undesirable, so
    // even when linking libc on Windows we use our own abort implementation.
    // See https://github.com/ziglang/zig/issues/2071 for more details.
    if (native_os == .windows) {
        if (builtin.mode == .Debug) {
            @breakpoint();
        }
        windows.kernel32.ExitProcess(3);
    }
    if (!builtin.link_libc and native_os == .linux) {
        // The Linux man page says that the libc abort() function
        // "first unblocks the SIGABRT signal", but this is a footgun
        // for user-defined signal handlers that want to restore some state in
        // some program sections and crash in others.
        // So, the user-installed SIGABRT handler is run, if present.
        raise(SIG.ABRT) catch {};

        // Disable all signal handlers.
        sigprocmask(SIG.BLOCK, &linux.all_mask, null);

        // Only one thread may proceed to the rest of abort().
        if (!builtin.single_threaded) {
            const global = struct {
                var abort_entered: bool = false;
            };
            while (@cmpxchgWeak(bool, &global.abort_entered, false, true, .seq_cst, .seq_cst)) |_| {}
        }

        // Install default handler so that the tkill below will terminate.
        const sigact = Sigaction{
            .handler = .{ .handler = SIG.DFL },
            .mask = empty_sigset,
            .flags = 0,
        };
        sigaction(SIG.ABRT, &sigact, null);

        _ = linux.tkill(linux.gettid(), SIG.ABRT);

        const sigabrtmask: linux.sigset_t = [_]u32{0} ** 31 ++ [_]u32{1 << (SIG.ABRT - 1)};
        sigprocmask(SIG.UNBLOCK, &sigabrtmask, null);

        // Beyond this point should be unreachable.
        @as(*allowzero volatile u8, @ptrFromInt(0)).* = 0;
        raise(SIG.KILL) catch {};
        exit(127); // Pid 1 might not be signalled in some containers.
    }
    switch (native_os) {
        .uefi, .wasi, .emscripten, .cuda, .amdhsa => @trap(),
        else => system.abort(),
    }
}

pub const RaiseError = UnexpectedError;

pub fn raise(sig: u8) RaiseError!void {
    if (builtin.link_libc) {
        switch (errno(system.raise(sig))) {
            .SUCCESS => return,
            else => |err| return unexpectedErrno(err),
        }
    }

    if (native_os == .linux) {
        // https://git.musl-libc.org/cgit/musl/commit/?id=0bed7e0acfd34e3fb63ca0e4d99b7592571355a9
        //
        // Unlike musl, libc-less Zig std does not have any internal signals for implementation purposes, so we
        // need to block all signals on the assumption that any of them could potentially fork() in a handler.
        var set: sigset_t = undefined;
        sigprocmask(SIG.BLOCK, &linux.all_mask, &set);

        const tid = linux.gettid();
        const rc = linux.tkill(tid, sig);

        // restore signal mask
        sigprocmask(SIG.SETMASK, &set, null);

        switch (errno(rc)) {
            .SUCCESS => return,
            else => |err| return unexpectedErrno(err),
        }
    }

    @compileError("std.posix.raise unimplemented for this target");
}

pub const KillError = error{ ProcessNotFound, PermissionDenied } || UnexpectedError;

pub fn kill(pid: pid_t, sig: u8) KillError!void {
    switch (errno(system.kill(pid, sig))) {
        .SUCCESS => return,
        .INVAL => unreachable, // invalid signal
        .PERM => return error.PermissionDenied,
        .SRCH => return error.ProcessNotFound,
        else => |err| return unexpectedErrno(err),
    }
}

/// Exits all threads of the program with the specified status code.
pub fn exit(status: u8) noreturn {
    if (builtin.link_libc) {
        std.c.exit(status);
    }
    if (native_os == .windows) {
        windows.kernel32.ExitProcess(status);
    }
    if (native_os == .wasi) {
        wasi.proc_exit(status);
    }
    if (native_os == .linux and !builtin.single_threaded) {
        linux.exit_group(status);
    }
    if (native_os == .uefi) {
        const uefi = std.os.uefi;
        // exit() is only available if exitBootServices() has not been called yet.
        // This call to exit should not fail, so we don't care about its return value.
        if (uefi.system_table.boot_services) |bs| {
            _ = bs.exit(uefi.handle, @enumFromInt(status), 0, null);
        }
        // If we can't exit, reboot the system instead.
        uefi.system_table.runtime_services.resetSystem(.reset_cold, @enumFromInt(status), 0, null);
    }
    system.exit(status);
}

pub const ReadError = error{
    InputOutput,
    SystemResources,
    IsDir,
    OperationAborted,
    BrokenPipe,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    NotOpenForReading,
    SocketNotConnected,

    /// This error occurs when no global event loop is configured,
    /// and reading from the file descriptor would block.
    WouldBlock,

    /// reading a timerfd with CANCEL_ON_SET will lead to this error
    /// when the clock goes through a discontinuous change
    Canceled,

    /// In WASI, this error occurs when the file descriptor does
    /// not hold the required rights to read from it.
    AccessDenied,

    /// This error occurs in Linux if the process to be read from
    /// no longer exists.
    ProcessNotFound,

    /// Unable to read file due to lock.
    LockViolation,
} || UnexpectedError;

/// Returns the number of bytes that were read, which can be less than
/// buf.len. If 0 bytes were read, that means EOF.
/// If `fd` is opened in non blocking mode, the function will return error.WouldBlock
/// when EAGAIN is received.
///
/// Linux has a limit on how many bytes may be transferred in one `read` call, which is `0x7ffff000`
/// on both 64-bit and 32-bit systems. This is due to using a signed C int as the return value, as
/// well as stuffing the errno codes into the last `4096` values. This is noted on the `read` man page.
/// The limit on Darwin is `0x7fffffff`, trying to read more than that returns EINVAL.
/// The corresponding POSIX limit is `maxInt(isize)`.
pub fn read(fd: fd_t, buf: []u8) ReadError!usize {
    if (buf.len == 0) return 0;
    if (native_os == .windows) {
        return windows.ReadFile(fd, buf, null);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        const iovs = [1]iovec{iovec{
            .base = buf.ptr,
            .len = buf.len,
        }};

        var nread: usize = undefined;
        switch (wasi.fd_read(fd, &iovs, iovs.len, &nread)) {
            .SUCCESS => return nread,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable,
            .BADF => return error.NotOpenForReading, // Can be a race condition.
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    // Prevents EINVAL.
    const max_count = switch (native_os) {
        .linux => 0x7ffff000,
        .macos, .ios, .watchos, .tvos, .visionos => maxInt(i32),
        else => maxInt(isize),
    };
    while (true) {
        const rc = system.read(fd, buf.ptr, @min(buf.len, max_count));
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .CANCELED => return error.Canceled,
            .BADF => return error.NotOpenForReading, // Can be a race condition.
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            else => |err| return unexpectedErrno(err),
        }
    }
}

/// Number of bytes read is returned. Upon reading end-of-file, zero is returned.
///
/// For POSIX systems, if `fd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
/// On Windows, if the application has a global event loop enabled, I/O Completion Ports are
/// used to perform the I/O. `error.WouldBlock` is not possible on Windows.
///
/// This operation is non-atomic on the following systems:
/// * Windows
/// On these systems, the read races with concurrent writes to the same file descriptor.
///
/// This function assumes that all vectors, including zero-length vectors, have
/// a pointer within the address space of the application.
pub fn readv(fd: fd_t, iov: []const iovec) ReadError!usize {
    if (native_os == .windows) {
        // TODO improve this to use ReadFileScatter
        if (iov.len == 0) return 0;
        const first = iov[0];
        return read(fd, first.base[0..first.len]);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var nread: usize = undefined;
        switch (wasi.fd_read(fd, iov.ptr, iov.len, &nread)) {
            .SUCCESS => return nread,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable, // currently not support in WASI
            .BADF => return error.NotOpenForReading, // can be a race condition
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    while (true) {
        const rc = system.readv(fd, iov.ptr, @min(iov.len, IOV_MAX));
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForReading, // can be a race condition
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const PReadError = ReadError || error{Unseekable};

/// Number of bytes read is returned. Upon reading end-of-file, zero is returned.
///
/// Retries when interrupted by a signal.
///
/// For POSIX systems, if `fd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
/// On Windows, if the application has a global event loop enabled, I/O Completion Ports are
/// used to perform the I/O. `error.WouldBlock` is not possible on Windows.
///
/// Linux has a limit on how many bytes may be transferred in one `pread` call, which is `0x7ffff000`
/// on both 64-bit and 32-bit systems. This is due to using a signed C int as the return value, as
/// well as stuffing the errno codes into the last `4096` values. This is noted on the `read` man page.
/// The limit on Darwin is `0x7fffffff`, trying to read more than that returns EINVAL.
/// The corresponding POSIX limit is `maxInt(isize)`.
pub fn pread(fd: fd_t, buf: []u8, offset: u64) PReadError!usize {
    if (buf.len == 0) return 0;
    if (native_os == .windows) {
        return windows.ReadFile(fd, buf, offset);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        const iovs = [1]iovec{iovec{
            .base = buf.ptr,
            .len = buf.len,
        }};

        var nread: usize = undefined;
        switch (wasi.fd_pread(fd, &iovs, iovs.len, offset, &nread)) {
            .SUCCESS => return nread,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable,
            .BADF => return error.NotOpenForReading, // Can be a race condition.
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    // Prevent EINVAL.
    const max_count = switch (native_os) {
        .linux => 0x7ffff000,
        .macos, .ios, .watchos, .tvos, .visionos => maxInt(i32),
        else => maxInt(isize),
    };

    const pread_sym = if (lfs64_abi) system.pread64 else system.pread;
    while (true) {
        const rc = pread_sym(fd, buf.ptr, @min(buf.len, max_count), @bitCast(offset));
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForReading, // Can be a race condition.
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const TruncateError = error{
    FileTooBig,
    InputOutput,
    FileBusy,
    AccessDenied,
    PermissionDenied,
} || UnexpectedError;

/// Length must be positive when treated as an i64.
pub fn ftruncate(fd: fd_t, length: u64) TruncateError!void {
    const signed_len: i64 = @bitCast(length);
    if (signed_len < 0) return error.FileTooBig; // avoid ambiguous EINVAL errors

    if (native_os == .windows) {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        var eof_info = windows.FILE_END_OF_FILE_INFORMATION{
            .EndOfFile = signed_len,
        };

        const rc = windows.ntdll.NtSetInformationFile(
            fd,
            &io_status_block,
            &eof_info,
            @sizeOf(windows.FILE_END_OF_FILE_INFORMATION),
            .FileEndOfFileInformation,
        );

        switch (rc) {
            .SUCCESS => return,
            .INVALID_HANDLE => unreachable, // Handle not open for writing
            .ACCESS_DENIED => return error.AccessDenied,
            .USER_MAPPED_FILE => return error.AccessDenied,
            .INVALID_PARAMETER => return error.FileTooBig,
            else => return windows.unexpectedStatus(rc),
        }
    }
    if (native_os == .wasi and !builtin.link_libc) {
        switch (wasi.fd_filestat_set_size(fd, length)) {
            .SUCCESS => return,
            .INTR => unreachable,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .PERM => return error.PermissionDenied,
            .TXTBSY => return error.FileBusy,
            .BADF => unreachable, // Handle not open for writing
            .INVAL => unreachable, // Handle not open for writing, negative length, or non-resizable handle
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    const ftruncate_sym = if (lfs64_abi) system.ftruncate64 else system.ftruncate;
    while (true) {
        switch (errno(ftruncate_sym(fd, signed_len))) {
            .SUCCESS => return,
            .INTR => continue,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .PERM => return error.PermissionDenied,
            .TXTBSY => return error.FileBusy,
            .BADF => unreachable, // Handle not open for writing
            .INVAL => unreachable, // Handle not open for writing, negative length, or non-resizable handle
            else => |err| return unexpectedErrno(err),
        }
    }
}

/// Number of bytes read is returned. Upon reading end-of-file, zero is returned.
///
/// Retries when interrupted by a signal.
///
/// For POSIX systems, if `fd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
/// On Windows, if the application has a global event loop enabled, I/O Completion Ports are
/// used to perform the I/O. `error.WouldBlock` is not possible on Windows.
///
/// This operation is non-atomic on the following systems:
/// * Darwin
/// * Windows
/// On these systems, the read races with concurrent writes to the same file descriptor.
pub fn preadv(fd: fd_t, iov: []const iovec, offset: u64) PReadError!usize {
    const have_pread_but_not_preadv = switch (native_os) {
        .windows, .macos, .ios, .watchos, .tvos, .visionos, .haiku => true,
        else => false,
    };
    if (have_pread_but_not_preadv) {
        // We could loop here; but proper usage of `preadv` must handle partial reads anyway.
        // So we simply read into the first vector only.
        if (iov.len == 0) return 0;
        const first = iov[0];
        return pread(fd, first.base[0..first.len], offset);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var nread: usize = undefined;
        switch (wasi.fd_pread(fd, iov.ptr, iov.len, offset, &nread)) {
            .SUCCESS => return nread,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable,
            .BADF => return error.NotOpenForReading, // can be a race condition
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    const preadv_sym = if (lfs64_abi) system.preadv64 else system.preadv;
    while (true) {
        const rc = preadv_sym(fd, iov.ptr, @min(iov.len, IOV_MAX), @bitCast(offset));
        switch (errno(rc)) {
            .SUCCESS => return @bitCast(rc),
            .INTR => continue,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForReading, // can be a race condition
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const WriteError = error{
    DiskQuota,
    FileTooBig,
    InputOutput,
    NoSpaceLeft,
    DeviceBusy,
    InvalidArgument,

    /// File descriptor does not hold the required rights to write to it.
    AccessDenied,
    PermissionDenied,
    BrokenPipe,
    SystemResources,
    OperationAborted,
    NotOpenForWriting,

    /// The process cannot access the file because another process has locked
    /// a portion of the file. Windows-only.
    LockViolation,

    /// This error occurs when no global event loop is configured,
    /// and reading from the file descriptor would block.
    WouldBlock,

    /// Connection reset by peer.
    ConnectionResetByPeer,

    /// This error occurs in Linux if the process being written to
    /// no longer exists.
    ProcessNotFound,
    /// This error occurs when a device gets disconnected before or mid-flush
    /// while it's being written to - errno(6): No such device or address.
    NoDevice,

    /// The socket type requires that message be sent atomically, and the size of the message
    /// to be sent made this impossible. The message is not transmitted.
    MessageTooBig,
} || UnexpectedError;

/// Write to a file descriptor.
/// Retries when interrupted by a signal.
/// Returns the number of bytes written. If nonzero bytes were supplied, this will be nonzero.
///
/// Note that a successful write() may transfer fewer than count bytes.  Such partial  writes  can
/// occur  for  various reasons; for example, because there was insufficient space on the disk
/// device to write all of the requested bytes, or because a blocked write() to a socket,  pipe,  or
/// similar  was  interrupted by a signal handler after it had transferred some, but before it had
/// transferred all of the requested bytes.  In the event of a partial write, the caller can  make
/// another  write() call to transfer the remaining bytes.  The subsequent call will either
/// transfer further bytes or may result in an error (e.g., if the disk is now full).
///
/// For POSIX systems, if `fd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
/// On Windows, if the application has a global event loop enabled, I/O Completion Ports are
/// used to perform the I/O. `error.WouldBlock` is not possible on Windows.
///
/// Linux has a limit on how many bytes may be transferred in one `write` call, which is `0x7ffff000`
/// on both 64-bit and 32-bit systems. This is due to using a signed C int as the return value, as
/// well as stuffing the errno codes into the last `4096` values. This is noted on the `write` man page.
/// The limit on Darwin is `0x7fffffff`, trying to read more than that returns EINVAL.
/// The corresponding POSIX limit is `maxInt(isize)`.
pub fn write(fd: fd_t, bytes: []const u8) WriteError!usize {
    if (bytes.len == 0) return 0;
    if (native_os == .windows) {
        return windows.WriteFile(fd, bytes, null);
    }

    if (native_os == .wasi and !builtin.link_libc) {
        const ciovs = [_]iovec_const{iovec_const{
            .base = bytes.ptr,
            .len = bytes.len,
        }};
        var nwritten: usize = undefined;
        switch (wasi.fd_write(fd, &ciovs, ciovs.len, &nwritten)) {
            .SUCCESS => return nwritten,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable,
            .BADF => return error.NotOpenForWriting, // can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    const max_count = switch (native_os) {
        .linux => 0x7ffff000,
        .macos, .ios, .watchos, .tvos, .visionos => maxInt(i32),
        else => maxInt(isize),
    };
    while (true) {
        const rc = system.write(fd, bytes.ptr, @min(bytes.len, max_count));
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => return error.InvalidArgument,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForWriting, // can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .ACCES => return error.AccessDenied,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .CONNRESET => return error.ConnectionResetByPeer,
            .BUSY => return error.DeviceBusy,
            .NXIO => return error.NoDevice,
            .MSGSIZE => return error.MessageTooBig,
            else => |err| return unexpectedErrno(err),
        }
    }
}

/// Write multiple buffers to a file descriptor.
/// Retries when interrupted by a signal.
/// Returns the number of bytes written. If nonzero bytes were supplied, this will be nonzero.
///
/// Note that a successful write() may transfer fewer bytes than supplied.  Such partial  writes  can
/// occur  for  various reasons; for example, because there was insufficient space on the disk
/// device to write all of the requested bytes, or because a blocked write() to a socket,  pipe,  or
/// similar  was  interrupted by a signal handler after it had transferred some, but before it had
/// transferred all of the requested bytes.  In the event of a partial write, the caller can  make
/// another  write() call to transfer the remaining bytes.  The subsequent call will either
/// transfer further bytes or may result in an error (e.g., if the disk is now full).
///
/// For POSIX systems, if `fd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
/// On Windows, if the application has a global event loop enabled, I/O Completion Ports are
/// used to perform the I/O. `error.WouldBlock` is not possible on Windows.
///
/// If `iov.len` is larger than `IOV_MAX`, a partial write will occur.
///
/// This function assumes that all vectors, including zero-length vectors, have
/// a pointer within the address space of the application.
pub fn writev(fd: fd_t, iov: []const iovec_const) WriteError!usize {
    if (native_os == .windows) {
        // TODO improve this to use WriteFileScatter
        if (iov.len == 0) return 0;
        const first = iov[0];
        return write(fd, first.base[0..first.len]);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var nwritten: usize = undefined;
        switch (wasi.fd_write(fd, iov.ptr, iov.len, &nwritten)) {
            .SUCCESS => return nwritten,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable,
            .BADF => return error.NotOpenForWriting, // can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    while (true) {
        const rc = system.writev(fd, iov.ptr, @min(iov.len, IOV_MAX));
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => return error.InvalidArgument,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForWriting, // Can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .CONNRESET => return error.ConnectionResetByPeer,
            .BUSY => return error.DeviceBusy,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const PWriteError = WriteError || error{Unseekable};

/// Write to a file descriptor, with a position offset.
/// Retries when interrupted by a signal.
/// Returns the number of bytes written. If nonzero bytes were supplied, this will be nonzero.
///
/// Note that a successful write() may transfer fewer bytes than supplied.  Such partial  writes  can
/// occur  for  various reasons; for example, because there was insufficient space on the disk
/// device to write all of the requested bytes, or because a blocked write() to a socket,  pipe,  or
/// similar  was  interrupted by a signal handler after it had transferred some, but before it had
/// transferred all of the requested bytes.  In the event of a partial write, the caller can  make
/// another  write() call to transfer the remaining bytes.  The subsequent call will either
/// transfer further bytes or may result in an error (e.g., if the disk is now full).
///
/// For POSIX systems, if `fd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
/// On Windows, if the application has a global event loop enabled, I/O Completion Ports are
/// used to perform the I/O. `error.WouldBlock` is not possible on Windows.
///
/// Linux has a limit on how many bytes may be transferred in one `pwrite` call, which is `0x7ffff000`
/// on both 64-bit and 32-bit systems. This is due to using a signed C int as the return value, as
/// well as stuffing the errno codes into the last `4096` values. This is noted on the `write` man page.
/// The limit on Darwin is `0x7fffffff`, trying to write more than that returns EINVAL.
/// The corresponding POSIX limit is `maxInt(isize)`.
pub fn pwrite(fd: fd_t, bytes: []const u8, offset: u64) PWriteError!usize {
    if (bytes.len == 0) return 0;
    if (native_os == .windows) {
        return windows.WriteFile(fd, bytes, offset);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        const ciovs = [1]iovec_const{iovec_const{
            .base = bytes.ptr,
            .len = bytes.len,
        }};

        var nwritten: usize = undefined;
        switch (wasi.fd_pwrite(fd, &ciovs, ciovs.len, offset, &nwritten)) {
            .SUCCESS => return nwritten,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable,
            .BADF => return error.NotOpenForWriting, // can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    // Prevent EINVAL.
    const max_count = switch (native_os) {
        .linux => 0x7ffff000,
        .macos, .ios, .watchos, .tvos, .visionos => maxInt(i32),
        else => maxInt(isize),
    };

    const pwrite_sym = if (lfs64_abi) system.pwrite64 else system.pwrite;
    while (true) {
        const rc = pwrite_sym(fd, bytes.ptr, @min(bytes.len, max_count), @bitCast(offset));
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => return error.InvalidArgument,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForWriting, // Can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .BUSY => return error.DeviceBusy,
            else => |err| return unexpectedErrno(err),
        }
    }
}

/// Write multiple buffers to a file descriptor, with a position offset.
/// Retries when interrupted by a signal.
/// Returns the number of bytes written. If nonzero bytes were supplied, this will be nonzero.
///
/// Note that a successful write() may transfer fewer than count bytes.  Such partial  writes  can
/// occur  for  various reasons; for example, because there was insufficient space on the disk
/// device to write all of the requested bytes, or because a blocked write() to a socket,  pipe,  or
/// similar  was  interrupted by a signal handler after it had transferred some, but before it had
/// transferred all of the requested bytes.  In the event of a partial write, the caller can  make
/// another  write() call to transfer the remaining bytes.  The subsequent call will either
/// transfer further bytes or may result in an error (e.g., if the disk is now full).
///
/// If `fd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
///
/// The following systems do not have this syscall, and will return partial writes if more than one
/// vector is provided:
/// * Darwin
/// * Windows
///
/// If `iov.len` is larger than `IOV_MAX`, a partial write will occur.
pub fn pwritev(fd: fd_t, iov: []const iovec_const, offset: u64) PWriteError!usize {
    const have_pwrite_but_not_pwritev = switch (native_os) {
        .windows, .macos, .ios, .watchos, .tvos, .visionos, .haiku => true,
        else => false,
    };

    if (have_pwrite_but_not_pwritev) {
        // We could loop here; but proper usage of `pwritev` must handle partial writes anyway.
        // So we simply write the first vector only.
        if (iov.len == 0) return 0;
        const first = iov[0];
        return pwrite(fd, first.base[0..first.len], offset);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        var nwritten: usize = undefined;
        switch (wasi.fd_pwrite(fd, iov.ptr, iov.len, offset, &nwritten)) {
            .SUCCESS => return nwritten,
            .INTR => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .AGAIN => unreachable,
            .BADF => return error.NotOpenForWriting, // Can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .NOTCAPABLE => return error.AccessDenied,
            else => |err| return unexpectedErrno(err),
        }
    }

    const pwritev_sym = if (lfs64_abi) system.pwritev64 else system.pwritev;
    while (true) {
        const rc = pwritev_sym(fd, iov.ptr, @min(iov.len, IOV_MAX), @bitCast(offset));
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .INVAL => return error.InvalidArgument,
            .FAULT => unreachable,
            .SRCH => return error.ProcessNotFound,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForWriting, // Can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.PermissionDenied,
            .PIPE => return error.BrokenPipe,
            .NXIO => return error.Unseekable,
            .SPIPE => return error.Unseekable,
            .OVERFLOW => return error.Unseekable,
            .BUSY => return error.DeviceBusy,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const OpenError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to open a new resource relative to it.
    AccessDenied,
    PermissionDenied,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    NoDevice,
    /// Either:
    /// * One of the path components does not exist.
    /// * Cwd was used, but cwd has been deleted.
    /// * The path associated with the open directory handle has been deleted.
    /// * On macOS, multiple processes or threads raced to create the same file
    ///   with `O.EXCL` set to `false`.
    FileNotFound,

    /// The path exceeded `max_path_bytes` bytes.
    NameTooLong,

    /// Insufficient kernel memory was available, or
    /// the named file is a FIFO and per-user hard limit on
    /// memory allocation for pipes has been reached.
    SystemResources,

    /// The file is too large to be opened. This error is unreachable
    /// for 64-bit targets, as well as when opening directories.
    FileTooBig,

    /// The path refers to directory but the `DIRECTORY` flag was not provided.
    IsDir,

    /// A new path cannot be created because the device has no room for the new file.
    /// This error is only reachable when the `CREAT` flag is provided.
    NoSpaceLeft,

    /// A component used as a directory in the path was not, in fact, a directory, or
    /// `DIRECTORY` was specified and the path was not a directory.
    NotDir,

    /// The path already exists and the `CREAT` and `EXCL` flags were provided.
    PathAlreadyExists,
    DeviceBusy,

    /// The underlying filesystem does not support file locks
    FileLocksNotSupported,

    /// Path contains characters that are disallowed by the underlying filesystem.
    BadPathName,

    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,

    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,

    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,

    /// This error occurs in Linux if the process to be open was not found.
    ProcessNotFound,

    /// One of these three things:
    /// * pathname  refers to an executable image which is currently being
    ///   executed and write access was requested.
    /// * pathname refers to a file that is currently in  use  as  a  swap
    ///   file, and the O_TRUNC flag was specified.
    /// * pathname  refers  to  a file that is currently being read by the
    ///   kernel (e.g., for module/firmware loading), and write access was
    ///   requested.
    FileBusy,

    WouldBlock,
} || UnexpectedError;

/// Open and possibly create a file. Keeps trying if it gets interrupted.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// See also `openZ`.
pub fn open(file_path: []const u8, flags: O, perm: mode_t) OpenError!fd_t {
    if (native_os == .windows) {
        @compileError("Windows does not support POSIX; use Windows-specific API or cross-platform std.fs API");
    } else if (native_os == .wasi and !builtin.link_libc) {
        return openat(AT.FDCWD, file_path, flags, perm);
    }
    const file_path_c = try toPosixPath(file_path);
    return openZ(&file_path_c, flags, perm);
}

/// Open and possibly create a file. Keeps trying if it gets interrupted.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// See also `open`.
pub fn openZ(file_path: [*:0]const u8, flags: O, perm: mode_t) OpenError!fd_t {
    if (native_os == .windows) {
        @compileError("Windows does not support POSIX; use Windows-specific API or cross-platform std.fs API");
    } else if (native_os == .wasi and !builtin.link_libc) {
        return open(mem.sliceTo(file_path, 0), flags, perm);
    }

    const open_sym = if (lfs64_abi) system.open64 else system.open;
    while (true) {
        const rc = open_sym(file_path, flags, perm);
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,

            .FAULT => unreachable,
            .INVAL => return error.BadPathName,
            .ACCES => return error.AccessDenied,
            .FBIG => return error.FileTooBig,
            .OVERFLOW => return error.FileTooBig,
            .ISDIR => return error.IsDir,
            .LOOP => return error.SymLinkLoop,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NODEV => return error.NoDevice,
            .NOENT => return error.FileNotFound,
            .SRCH => return error.ProcessNotFound,
            .NOMEM => return error.SystemResources,
            .NOSPC => return error.NoSpaceLeft,
            .NOTDIR => return error.NotDir,
            .PERM => return error.PermissionDenied,
            .EXIST => return error.PathAlreadyExists,
            .BUSY => return error.DeviceBusy,
            .ILSEQ => |err| if (native_os == .wasi)
                return error.InvalidUtf8
            else
                return unexpectedErrno(err),
            else => |err| return unexpectedErrno(err),
        }
    }
}

/// Open and possibly create a file. Keeps trying if it gets interrupted.
/// `file_path` is relative to the open directory handle `dir_fd`.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// See also `openatZ`.
pub fn openat(dir_fd: fd_t, file_path: []const u8, flags: O, mode: mode_t) OpenError!fd_t {
    if (native_os == .windows) {
        @compileError("Windows does not support POSIX; use Windows-specific API or cross-platform std.fs API");
    } else if (native_os == .wasi and !builtin.link_libc) {
        // `mode` is ignored on WASI, which does not support unix-style file permissions
        const opts = try openOptionsFromFlagsWasi(flags);
        const fd = try openatWasi(
            dir_fd,
            file_path,
            opts.lookup_flags,
            opts.oflags,
            opts.fs_flags,
            opts.fs_rights_base,
            opts.fs_rights_inheriting,
        );
        errdefer close(fd);

        if (flags.write) {
            const info = try std.os.fstat_wasi(fd);
            if (info.filetype == .DIRECTORY)
                return error.IsDir;
        }

        return fd;
    }
    const file_path_c = try toPosixPath(file_path);
    return openatZ(dir_fd, &file_path_c, flags, mode);
}

/// Open and possibly create a file in WASI.
pub fn openatWasi(
    dir_fd: fd_t,
    file_path: []const u8,
    lookup_flags: wasi.lookupflags_t,
    oflags: wasi.oflags_t,
    fdflags: wasi.fdflags_t,
    base: wasi.rights_t,
    inheriting: wasi.rights_t,
) OpenError!fd_t {
    while (true) {
        var fd: fd_t = undefined;
        switch (wasi.path_open(dir_fd, lookup_flags, file_path.ptr, file_path.len, oflags, base, inheriting, fdflags, &fd)) {
            .SUCCESS => return fd,
            .INTR => continue,

            .FAULT => unreachable,
            // Provides INVAL with a linux host on a bad path name, but NOENT on Windows
            .INVAL => return error.BadPathName,
            .BADF => unreachable,
            .ACCES => return error.AccessDenied,
            .FBIG => return error.FileTooBig,
            .OVERFLOW => return error.FileTooBig,
            .ISDIR => return error.IsDir,
            .LOOP => return error.SymLinkLoop,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NODEV => return error.NoDevice,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .NOSPC => return error.NoSpaceLeft,
            .NOTDIR => return error.NotDir,
            .PERM => return error.PermissionDenied,
            .EXIST => return error.PathAlreadyExists,
            .BUSY => return error.DeviceBusy,
            .NOTCAPABLE => return error.AccessDenied,
            .ILSEQ => return error.InvalidUtf8,
            else => |err| return unexpectedErrno(err),
        }
    }
}

/// A struct to contain all lookup/rights flags accepted by `wasi.path_open`
const WasiOpenOptions = struct {
    oflags: wasi.oflags_t,
    lookup_flags: wasi.lookupflags_t,
    fs_rights_base: wasi.rights_t,
    fs_rights_inheriting: wasi.rights_t,
    fs_flags: wasi.fdflags_t,
};

/// Compute rights + flags corresponding to the provided POSIX access mode.
fn openOptionsFromFlagsWasi(oflag: O) OpenError!WasiOpenOptions {
    const w = std.os.wasi;

    // Next, calculate the read/write rights to request, depending on the
    // provided POSIX access mode
    var rights: w.rights_t = .{};
    if (oflag.read) {
        rights.FD_READ = true;
        rights.FD_READDIR = true;
    }
    if (oflag.write) {
        rights.FD_DATASYNC = true;
        rights.FD_WRITE = true;
        rights.FD_ALLOCATE = true;
        rights.FD_FILESTAT_SET_SIZE = true;
    }

    // https://github.com/ziglang/zig/issues/18882
    const flag_bits: u32 = @bitCast(oflag);
    const oflags_int: u16 = @as(u12, @truncate(flag_bits >> 12));
    const fs_flags_int: u16 = @as(u12, @truncate(flag_bits));

    return .{
        // https://github.com/ziglang/zig/issues/18882
        .oflags = @bitCast(oflags_int),
        .lookup_flags = .{
            .SYMLINK_FOLLOW = !oflag.NOFOLLOW,
        },
        .fs_rights_base = rights,
        .fs_rights_inheriting = rights,
        // https://github.com/ziglang/zig/issues/18882
        .fs_flags = @bitCast(fs_flags_int),
    };
}

/// Open and possibly create a file. Keeps trying if it gets interrupted.
/// `file_path` is relative to the open directory handle `dir_fd`.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// See also `openat`.
pub fn openatZ(dir_fd: fd_t, file_path: [*:0]const u8, flags: O, mode: mode_t) OpenError!fd_t {
    if (native_os == .windows) {
        @compileError("Windows does not support POSIX; use Windows-specific API or cross-platform std.fs API");
    } else if (native_os == .wasi and !builtin.link_libc) {
        return openat(dir_fd, mem.sliceTo(file_path, 0), flags, mode);
    }

    const openat_sym = if (lfs64_abi) system.openat64 else system.openat;
    while (true) {
        const rc = openat_sym(dir_fd, file_path, flags, mode);
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,

            .FAULT => unreachable,
            .INVAL => return error.BadPathName,
            .BADF => unreachable,
            .ACCES => return error.AccessDenied,
            .FBIG => return error.FileTooBig,
            .OVERFLOW => return error.FileTooBig,
            .ISDIR => return error.IsDir,
            .LOOP => return error.SymLinkLoop,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NODEV => return error.NoDevice,
            .NOENT => return error.FileNotFound,
            .SRCH => return error.ProcessNotFound,
            .NOMEM => return error.SystemResources,
            .NOSPC => return error.NoSpaceLeft,
            .NOTDIR => return error.NotDir,
            .PERM => return error.PermissionDenied,
            .EXIST => return error.PathAlreadyExists,
            .BUSY => return error.DeviceBusy,
            .OPNOTSUPP => return error.FileLocksNotSupported,
            .AGAIN => return error.WouldBlock,
            .TXTBSY => return error.FileBusy,
            .NXIO => return error.NoDevice,
            .ILSEQ => |err| if (native_os == .wasi)
                return error.InvalidUtf8
            else
                return unexpectedErrno(err),
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub fn dup(old_fd: fd_t) !fd_t {
    const rc = system.dup(old_fd);
    return switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .MFILE => error.ProcessFdQuotaExceeded,
        .BADF => unreachable, // invalid file descriptor
        else => |err| return unexpectedErrno(err),
    };
}

pub fn dup2(old_fd: fd_t, new_fd: fd_t) !void {
    while (true) {
        switch (errno(system.dup2(old_fd, new_fd))) {
            .SUCCESS => return,
            .BUSY, .INTR => continue,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .INVAL => unreachable, // invalid parameters passed to dup2
            .BADF => unreachable, // invalid file descriptor
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const ExecveError = error{
    SystemResources,
    AccessDenied,
    PermissionDenied,
    InvalidExe,
    FileSystem,
    IsDir,
    FileNotFound,
    NotDir,
    FileBusy,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    NameTooLong,
} || UnexpectedError;

/// This function ignores PATH environment variable. See `execvpeZ` for that.
pub fn execveZ(
    path: [*:0]const u8,
    child_argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) ExecveError {
    switch (errno(system.execve(path, child_argv, envp))) {
        .SUCCESS => unreachable,
        .FAULT => unreachable,
        .@"2BIG" => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .INVAL => return error.InvalidExe,
        .NOEXEC => return error.InvalidExe,
        .IO => return error.FileSystem,
        .LOOP => return error.FileSystem,
        .ISDIR => return error.IsDir,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .TXTBSY => return error.FileBusy,
        else => |err| switch (native_os) {
            .macos, .ios, .tvos, .watchos, .visionos => switch (err) {
                .BADEXEC => return error.InvalidExe,
                .BADARCH => return error.InvalidExe,
                else => return unexpectedErrno(err),
            },
            .linux => switch (err) {
                .LIBBAD => return error.InvalidExe,
                else => return unexpectedErrno(err),
            },
            else => return unexpectedErrno(err),
        },
    }
}

pub const Arg0Expand = enum {
    expand,
    no_expand,
};

/// Like `execvpeZ` except if `arg0_expand` is `.expand`, then `argv` is mutable,
/// and `argv[0]` is expanded to be the same absolute path that is passed to the execve syscall.
/// If this function returns with an error, `argv[0]` will be restored to the value it was when it was passed in.
pub fn execvpeZ_expandArg0(
    comptime arg0_expand: Arg0Expand,
    file: [*:0]const u8,
    child_argv: switch (arg0_expand) {
        .expand => [*:null]?[*:0]const u8,
        .no_expand => [*:null]const ?[*:0]const u8,
    },
    envp: [*:null]const ?[*:0]const u8,
) ExecveError {
    const file_slice = mem.sliceTo(file, 0);
    if (mem.indexOfScalar(u8, file_slice, '/') != null) return execveZ(file, child_argv, envp);

    const PATH = getenvZ("PATH") orelse "/usr/local/bin:/bin/:/usr/bin";
    // Use of PATH_MAX here is valid as the path_buf will be passed
    // directly to the operating system in execveZ.
    var path_buf: [PATH_MAX]u8 = undefined;
    var it = mem.tokenizeScalar(u8, PATH, ':');
    var seen_eacces = false;
    var err: ExecveError = error.FileNotFound;

    // In case of expanding arg0 we must put it back if we return with an error.
    const prev_arg0 = child_argv[0];
    defer switch (arg0_expand) {
        .expand => child_argv[0] = prev_arg0,
        .no_expand => {},
    };

    while (it.next()) |search_path| {
        const path_len = search_path.len + file_slice.len + 1;
        if (path_buf.len < path_len + 1) return error.NameTooLong;
        @memcpy(path_buf[0..search_path.len], search_path);
        path_buf[search_path.len] = '/';
        @memcpy(path_buf[search_path.len + 1 ..][0..file_slice.len], file_slice);
        path_buf[path_len] = 0;
        const full_path = path_buf[0..path_len :0].ptr;
        switch (arg0_expand) {
            .expand => child_argv[0] = full_path,
            .no_expand => {},
        }
        err = execveZ(full_path, child_argv, envp);
        switch (err) {
            error.AccessDenied => seen_eacces = true,
            error.FileNotFound, error.NotDir => {},
            else => |e| return e,
        }
    }
    if (seen_eacces) return error.AccessDenied;
    return err;
}

/// This function also uses the PATH environment variable to get the full path to the executable.
/// If `file` is an absolute path, this is the same as `execveZ`.
pub fn execvpeZ(
    file: [*:0]const u8,
    argv_ptr: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) ExecveError {
    return execvpeZ_expandArg0(.no_expand, file, argv_ptr, envp);
}

/// Get an environment variable.
/// See also `getenvZ`.
pub fn getenv(key: []const u8) ?[:0]const u8 {
    if (native_os == .windows) {
        @compileError("std.posix.getenv is unavailable for Windows because environment strings are in WTF-16 format. See std.process.getEnvVarOwned for a cross-platform API or std.process.getenvW for a Windows-specific API.");
    }
    if (mem.indexOfScalar(u8, key, '=') != null) {
        return null;
    }
    if (builtin.link_libc) {
        var ptr = std.c.environ;
        while (ptr[0]) |line| : (ptr += 1) {
            var line_i: usize = 0;
            while (line[line_i] != 0) : (line_i += 1) {
                if (line_i == key.len) break;
                if (line[line_i] != key[line_i]) break;
            }
            if ((line_i != key.len) or (line[line_i] != '=')) continue;

            return mem.sliceTo(line + line_i + 1, 0);
        }
        return null;
    }
    if (native_os == .wasi) {
        @compileError("std.posix.getenv is unavailable for WASI. See std.process.getEnvMap or std.process.getEnvVarOwned for a cross-platform API.");
    }
    // The simplified start logic doesn't populate environ.
    if (std.start.simplified_logic) return null;
    // TODO see https://github.com/ziglang/zig/issues/4524
    for (std.os.environ) |ptr| {
        var line_i: usize = 0;
        while (ptr[line_i] != 0) : (line_i += 1) {
            if (line_i == key.len) break;
            if (ptr[line_i] != key[line_i]) break;
        }
        if ((line_i != key.len) or (ptr[line_i] != '=')) continue;

        return mem.sliceTo(ptr + line_i + 1, 0);
    }
    return null;
}

/// Get an environment variable with a null-terminated name.
/// See also `getenv`.
pub fn getenvZ(key: [*:0]const u8) ?[:0]const u8 {
    if (builtin.link_libc) {
        const value = system.getenv(key) orelse return null;
        return mem.sliceTo(value, 0);
    }
    if (native_os == .windows) {
        @compileError("std.posix.getenvZ is unavailable for Windows because environment string is in WTF-16 format. See std.process.getEnvVarOwned for cross-platform API or std.process.getenvW for Windows-specific API.");
    }
    return getenv(mem.sliceTo(key, 0));
}

pub const GetCwdError = error{
    NameTooLong,
    CurrentWorkingDirectoryUnlinked,
} || UnexpectedError;

/// The result is a slice of out_buffer, indexed from 0.
pub fn getcwd(out_buffer: []u8) GetCwdError![]u8 {
    if (native_os == .windows) {
        return windows.GetCurrentDirectory(out_buffer);
    } else if (native_os == .wasi and !builtin.link_libc) {
        const path = ".";
        if (out_buffer.len < path.len) return error.NameTooLong;
        const result = out_buffer[0..path.len];
        @memcpy(result, path);
        return result;
    }

    const err: E = if (builtin.link_libc) err: {
        const c_err = if (std.c.getcwd(out_buffer.ptr, out_buffer.len)) |_| 0 else std.c._errno().*;
        break :err @enumFromInt(c_err);
    } else err: {
        break :err errno(system.getcwd(out_buffer.ptr, out_buffer.len));
    };
    switch (err) {
        .SUCCESS => return mem.sliceTo(out_buffer, 0),
        .FAULT => unreachable,
        .INVAL => unreachable,
        .NOENT => return error.CurrentWorkingDirectoryUnlinked,
        .RANGE => return error.NameTooLong,
        else => return unexpectedErrno(err),
    }
}

pub const SymLinkError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to create a new symbolic link relative to it.
    AccessDenied,
    PermissionDenied,
    DiskQuota,
    PathAlreadyExists,
    FileSystem,
    SymLinkLoop,
    FileNotFound,
    SystemResources,
    NoSpaceLeft,
    ReadOnlyFileSystem,
    NotDir,
    NameTooLong,

    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,

    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,

    BadPathName,
} || UnexpectedError;

/// Creates a symbolic link named `sym_link_path` which contains the string `target_path`.
/// A symbolic link (also known as a soft link) may point to an existing file or to a nonexistent
/// one; the latter case is known as a dangling link.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
/// If `sym_link_path` exists, it will not be overwritten.
/// See also `symlinkZ.
pub fn symlink(target_path: []const u8, sym_link_path: []const u8) SymLinkError!void {
    if (native_os == .windows) {
        @compileError("symlink is not supported on Windows; use std.os.windows.CreateSymbolicLink instead");
    } else if (native_os == .wasi and !builtin.link_libc) {
        return symlinkat(target_path, AT.FDCWD, sym_link_path);
    }
    const target_path_c = try toPosixPath(target_path);
    const sym_link_path_c = try toPosixPath(sym_link_path);
    return symlinkZ(&target_path_c, &sym_link_path_c);
}

/// This is the same as `symlink` except the parameters are null-terminated pointers.
/// See also `symlink`.
pub fn symlinkZ(target_path: [*:0]const u8, sym_link_path: [*:0]const u8) SymLinkError!void {
    if (native_os == .windows) {
        @compileError("symlink is not supported on Windows; use std.os.windows.CreateSymbolicLink instead");
    } else if (native_os == .wasi and !builtin.link_libc) {
        return symlinkatZ(target_path, fs.cwd().fd, sym_link_path);
    }
    switch (errno(system.symlink(target_path, sym_link_path))) {
        .SUCCESS => return,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .DQUOT => return error.DiskQuota,
        .EXIST => return error.PathAlreadyExists,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .ROFS => return error.ReadOnlyFileSystem,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Similar to `symlink`, however, creates a symbolic link named `sym_link_path` which contains the string
/// `target_path` **relative** to `newdirfd` directory handle.
/// A symbolic link (also known as a soft link) may point to an existing file or to a nonexistent
/// one; the latter case is known as a dangling link.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
/// If `sym_link_path` exists, it will not be overwritten.
/// See also `symlinkatWasi`, `symlinkatZ` and `symlinkatW`.
pub fn symlinkat(target_path: []const u8, newdirfd: fd_t, sym_link_path: []const u8) SymLinkError!void {
    if (native_os == .windows) {
        @compileError("symlinkat is not supported on Windows; use std.os.windows.CreateSymbolicLink instead");
    } else if (native_os == .wasi and !builtin.link_libc) {
        return symlinkatWasi(target_path, newdirfd, sym_link_path);
    }
    const target_path_c = try toPosixPath(target_path);
    const sym_link_path_c = try toPosixPath(sym_link_path);
    return symlinkatZ(&target_path_c, newdirfd, &sym_link_path_c);
}

/// WASI-only. The same as `symlinkat` but targeting WASI.
/// See also `symlinkat`.
pub fn symlinkatWasi(target_path: []const u8, newdirfd: fd_t, sym_link_path: []const u8) SymLinkError!void {
    switch (wasi.path_symlink(target_path.ptr, target_path.len, newdirfd, sym_link_path.ptr, sym_link_path.len)) {
        .SUCCESS => {},
        .FAULT => unreachable,
        .INVAL => unreachable,
        .BADF => unreachable,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .DQUOT => return error.DiskQuota,
        .EXIST => return error.PathAlreadyExists,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .ROFS => return error.ReadOnlyFileSystem,
        .NOTCAPABLE => return error.AccessDenied,
        .ILSEQ => return error.InvalidUtf8,
        else => |err| return unexpectedErrno(err),
    }
}

/// The same as `symlinkat` except the parameters are null-terminated pointers.
/// See also `symlinkat`.
pub fn symlinkatZ(target_path: [*:0]const u8, newdirfd: fd_t, sym_link_path: [*:0]const u8) SymLinkError!void {
    if (native_os == .windows) {
        @compileError("symlinkat is not supported on Windows; use std.os.windows.CreateSymbolicLink instead");
    } else if (native_os == .wasi and !builtin.link_libc) {
        return symlinkat(mem.sliceTo(target_path, 0), newdirfd, mem.sliceTo(sym_link_path, 0));
    }
    switch (errno(system.symlinkat(target_path, newdirfd, sym_link_path))) {
        .SUCCESS => return,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .DQUOT => return error.DiskQuota,
        .EXIST => return error.PathAlreadyExists,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .ROFS => return error.ReadOnlyFileSystem,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

pub const LinkError = UnexpectedError || error{
    AccessDenied,
    PermissionDenied,
    DiskQuota,
    PathAlreadyExists,
    FileSystem,
    SymLinkLoop,
    LinkQuotaExceeded,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NoSpaceLeft,
    ReadOnlyFileSystem,
    NotSameFileSystem,

    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
};

/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn linkZ(oldpath: [*:0]const u8, newpath: [*:0]const u8) LinkError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        return link(mem.sliceTo(oldpath, 0), mem.sliceTo(newpath, 0));
    }
    switch (errno(system.link(oldpath, newpath))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .DQUOT => return error.DiskQuota,
        .EXIST => return error.PathAlreadyExists,
        .FAULT => unreachable,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .MLINK => return error.LinkQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .PERM => return error.PermissionDenied,
        .ROFS => return error.ReadOnlyFileSystem,
        .XDEV => return error.NotSameFileSystem,
        .INVAL => unreachable,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn link(oldpath: []const u8, newpath: []const u8) LinkError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        return linkat(AT.FDCWD, oldpath, AT.FDCWD, newpath, 0) catch |err| switch (err) {
            error.NotDir => unreachable, // link() does not support directories
            else => |e| return e,
        };
    }
    const old = try toPosixPath(oldpath);
    const new = try toPosixPath(newpath);
    return try linkZ(&old, &new);
}

pub const LinkatError = LinkError || error{NotDir};

/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn linkatZ(
    olddir: fd_t,
    oldpath: [*:0]const u8,
    newdir: fd_t,
    newpath: [*:0]const u8,
    flags: i32,
) LinkatError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        return linkat(olddir, mem.sliceTo(oldpath, 0), newdir, mem.sliceTo(newpath, 0), flags);
    }
    switch (errno(system.linkat(olddir, oldpath, newdir, newpath, flags))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .DQUOT => return error.DiskQuota,
        .EXIST => return error.PathAlreadyExists,
        .FAULT => unreachable,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .MLINK => return error.LinkQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .NOTDIR => return error.NotDir,
        .PERM => return error.PermissionDenied,
        .ROFS => return error.ReadOnlyFileSystem,
        .XDEV => return error.NotSameFileSystem,
        .INVAL => unreachable,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn linkat(
    olddir: fd_t,
    oldpath: []const u8,
    newdir: fd_t,
    newpath: []const u8,
    flags: i32,
) LinkatError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        const old: RelativePathWasi = .{ .dir_fd = olddir, .relative_path = oldpath };
        const new: RelativePathWasi = .{ .dir_fd = newdir, .relative_path = newpath };
        const old_flags: wasi.lookupflags_t = .{
            .SYMLINK_FOLLOW = (flags & AT.SYMLINK_FOLLOW) != 0,
        };
        switch (wasi.path_link(
            old.dir_fd,
            old_flags,
            old.relative_path.ptr,
            old.relative_path.len,
            new.dir_fd,
            new.relative_path.ptr,
            new.relative_path.len,
        )) {
            .SUCCESS => return,
            .ACCES => return error.AccessDenied,
            .DQUOT => return error.DiskQuota,
            .EXIST => return error.PathAlreadyExists,
            .FAULT => unreachable,
            .IO => return error.FileSystem,
            .LOOP => return error.SymLinkLoop,
            .MLINK => return error.LinkQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .NOSPC => return error.NoSpaceLeft,
            .NOTDIR => return error.NotDir,
            .PERM => return error.PermissionDenied,
            .ROFS => return error.ReadOnlyFileSystem,
            .XDEV => return error.NotSameFileSystem,
            .INVAL => unreachable,
            .ILSEQ => return error.InvalidUtf8,
            else => |err| return unexpectedErrno(err),
        }
    }
    const old = try toPosixPath(oldpath);
    const new = try toPosixPath(newpath);
    return try linkatZ(olddir, &old, newdir, &new, flags);
}

pub const UnlinkError = error{
    FileNotFound,

    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to unlink a resource by path relative to it.
    AccessDenied,
    PermissionDenied,
    FileBusy,
    FileSystem,
    IsDir,
    SymLinkLoop,
    NameTooLong,
    NotDir,
    SystemResources,
    ReadOnlyFileSystem,

    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,

    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,

    /// On Windows, file paths cannot contain these characters:
    /// '/', '*', '?', '"', '<', '>', '|'
    BadPathName,

    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || UnexpectedError;

/// Delete a name and possibly the file it refers to.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// See also `unlinkZ`.
pub fn unlink(file_path: []const u8) UnlinkError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        return unlinkat(AT.FDCWD, file_path, 0) catch |err| switch (err) {
            error.DirNotEmpty => unreachable, // only occurs when targeting directories
            else => |e| return e,
        };
    } else if (native_os == .windows) {
        const file_path_w = try windows.sliceToPrefixedFileW(null, file_path);
        return unlinkW(file_path_w.span());
    } else {
        const file_path_c = try toPosixPath(file_path);
        return unlinkZ(&file_path_c);
    }
}

/// Same as `unlink` except the parameter is null terminated.
pub fn unlinkZ(file_path: [*:0]const u8) UnlinkError!void {
    if (native_os == .windows) {
        const file_path_w = try windows.cStrToPrefixedFileW(null, file_path);
        return unlinkW(file_path_w.span());
    } else if (native_os == .wasi and !builtin.link_libc) {
        return unlink(mem.sliceTo(file_path, 0));
    }
    switch (errno(system.unlink(file_path))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BUSY => return error.FileBusy,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .IO => return error.FileSystem,
        .ISDIR => return error.IsDir,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .ROFS => return error.ReadOnlyFileSystem,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Windows-only. Same as `unlink` except the parameter is null-terminated, WTF16 LE encoded.
pub fn unlinkW(file_path_w: []const u16) UnlinkError!void {
    windows.DeleteFile(file_path_w, .{ .dir = fs.cwd().fd }) catch |err| switch (err) {
        error.DirNotEmpty => unreachable, // we're not passing .remove_dir = true
        else => |e| return e,
    };
}

pub const UnlinkatError = UnlinkError || error{
    /// When passing `AT.REMOVEDIR`, this error occurs when the named directory is not empty.
    DirNotEmpty,
};

/// Delete a file name and possibly the file it refers to, based on an open directory handle.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
/// Asserts that the path parameter has no null bytes.
pub fn unlinkat(dirfd: fd_t, file_path: []const u8, flags: u32) UnlinkatError!void {
    if (native_os == .windows) {
        const file_path_w = try windows.sliceToPrefixedFileW(dirfd, file_path);
        return unlinkatW(dirfd, file_path_w.span(), flags);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return unlinkatWasi(dirfd, file_path, flags);
    } else {
        const file_path_c = try toPosixPath(file_path);
        return unlinkatZ(dirfd, &file_path_c, flags);
    }
}

/// WASI-only. Same as `unlinkat` but targeting WASI.
/// See also `unlinkat`.
pub fn unlinkatWasi(dirfd: fd_t, file_path: []const u8, flags: u32) UnlinkatError!void {
    const remove_dir = (flags & AT.REMOVEDIR) != 0;
    const res = if (remove_dir)
        wasi.path_remove_directory(dirfd, file_path.ptr, file_path.len)
    else
        wasi.path_unlink_file(dirfd, file_path.ptr, file_path.len);
    switch (res) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BUSY => return error.FileBusy,
        .FAULT => unreachable,
        .IO => return error.FileSystem,
        .ISDIR => return error.IsDir,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .ROFS => return error.ReadOnlyFileSystem,
        .NOTEMPTY => return error.DirNotEmpty,
        .NOTCAPABLE => return error.AccessDenied,
        .ILSEQ => return error.InvalidUtf8,

        .INVAL => unreachable, // invalid flags, or pathname has . as last component
        .BADF => unreachable, // always a race condition

        else => |err| return unexpectedErrno(err),
    }
}

/// Same as `unlinkat` but `file_path` is a null-terminated string.
pub fn unlinkatZ(dirfd: fd_t, file_path_c: [*:0]const u8, flags: u32) UnlinkatError!void {
    if (native_os == .windows) {
        const file_path_w = try windows.cStrToPrefixedFileW(dirfd, file_path_c);
        return unlinkatW(dirfd, file_path_w.span(), flags);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return unlinkat(dirfd, mem.sliceTo(file_path_c, 0), flags);
    }
    switch (errno(system.unlinkat(dirfd, file_path_c, flags))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BUSY => return error.FileBusy,
        .FAULT => unreachable,
        .IO => return error.FileSystem,
        .ISDIR => return error.IsDir,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .ROFS => return error.ReadOnlyFileSystem,
        .EXIST => return error.DirNotEmpty,
        .NOTEMPTY => return error.DirNotEmpty,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),

        .INVAL => unreachable, // invalid flags, or pathname has . as last component
        .BADF => unreachable, // always a race condition

        else => |err| return unexpectedErrno(err),
    }
}

/// Same as `unlinkat` but `sub_path_w` is WTF16LE, NT prefixed. Windows only.
pub fn unlinkatW(dirfd: fd_t, sub_path_w: []const u16, flags: u32) UnlinkatError!void {
    const remove_dir = (flags & AT.REMOVEDIR) != 0;
    return windows.DeleteFile(sub_path_w, .{ .dir = dirfd, .remove_dir = remove_dir });
}

pub const RenameError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to rename a resource by path relative to it.
    ///
    /// On Windows, this error may be returned instead of PathAlreadyExists when
    /// renaming a directory over an existing directory.
    AccessDenied,
    PermissionDenied,
    FileBusy,
    DiskQuota,
    IsDir,
    SymLinkLoop,
    LinkQuotaExceeded,
    NameTooLong,
    FileNotFound,
    NotDir,
    SystemResources,
    NoSpaceLeft,
    PathAlreadyExists,
    ReadOnlyFileSystem,
    RenameAcrossMountPoints,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
    BadPathName,
    NoDevice,
    SharingViolation,
    PipeBusy,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,
} || UnexpectedError;

/// Change the name or location of a file.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn rename(old_path: []const u8, new_path: []const u8) RenameError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        return renameat(AT.FDCWD, old_path, AT.FDCWD, new_path);
    } else if (native_os == .windows) {
        const old_path_w = try windows.sliceToPrefixedFileW(null, old_path);
        const new_path_w = try windows.sliceToPrefixedFileW(null, new_path);
        return renameW(old_path_w.span().ptr, new_path_w.span().ptr);
    } else {
        const old_path_c = try toPosixPath(old_path);
        const new_path_c = try toPosixPath(new_path);
        return renameZ(&old_path_c, &new_path_c);
    }
}

/// Same as `rename` except the parameters are null-terminated.
pub fn renameZ(old_path: [*:0]const u8, new_path: [*:0]const u8) RenameError!void {
    if (native_os == .windows) {
        const old_path_w = try windows.cStrToPrefixedFileW(null, old_path);
        const new_path_w = try windows.cStrToPrefixedFileW(null, new_path);
        return renameW(old_path_w.span().ptr, new_path_w.span().ptr);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return rename(mem.sliceTo(old_path, 0), mem.sliceTo(new_path, 0));
    }
    switch (errno(system.rename(old_path, new_path))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BUSY => return error.FileBusy,
        .DQUOT => return error.DiskQuota,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .ISDIR => return error.IsDir,
        .LOOP => return error.SymLinkLoop,
        .MLINK => return error.LinkQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .EXIST => return error.PathAlreadyExists,
        .NOTEMPTY => return error.PathAlreadyExists,
        .ROFS => return error.ReadOnlyFileSystem,
        .XDEV => return error.RenameAcrossMountPoints,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Same as `rename` except the parameters are null-terminated and WTF16LE encoded.
/// Assumes target is Windows.
pub fn renameW(old_path: [*:0]const u16, new_path: [*:0]const u16) RenameError!void {
    const flags = windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH;
    return windows.MoveFileExW(old_path, new_path, flags);
}

/// Change the name or location of a file based on an open directory handle.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn renameat(
    old_dir_fd: fd_t,
    old_path: []const u8,
    new_dir_fd: fd_t,
    new_path: []const u8,
) RenameError!void {
    if (native_os == .windows) {
        const old_path_w = try windows.sliceToPrefixedFileW(old_dir_fd, old_path);
        const new_path_w = try windows.sliceToPrefixedFileW(new_dir_fd, new_path);
        return renameatW(old_dir_fd, old_path_w.span(), new_dir_fd, new_path_w.span(), windows.TRUE);
    } else if (native_os == .wasi and !builtin.link_libc) {
        const old: RelativePathWasi = .{ .dir_fd = old_dir_fd, .relative_path = old_path };
        const new: RelativePathWasi = .{ .dir_fd = new_dir_fd, .relative_path = new_path };
        return renameatWasi(old, new);
    } else {
        const old_path_c = try toPosixPath(old_path);
        const new_path_c = try toPosixPath(new_path);
        return renameatZ(old_dir_fd, &old_path_c, new_dir_fd, &new_path_c);
    }
}

/// WASI-only. Same as `renameat` expect targeting WASI.
/// See also `renameat`.
fn renameatWasi(old: RelativePathWasi, new: RelativePathWasi) RenameError!void {
    switch (wasi.path_rename(old.dir_fd, old.relative_path.ptr, old.relative_path.len, new.dir_fd, new.relative_path.ptr, new.relative_path.len)) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BUSY => return error.FileBusy,
        .DQUOT => return error.DiskQuota,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .ISDIR => return error.IsDir,
        .LOOP => return error.SymLinkLoop,
        .MLINK => return error.LinkQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .EXIST => return error.PathAlreadyExists,
        .NOTEMPTY => return error.PathAlreadyExists,
        .ROFS => return error.ReadOnlyFileSystem,
        .XDEV => return error.RenameAcrossMountPoints,
        .NOTCAPABLE => return error.AccessDenied,
        .ILSEQ => return error.InvalidUtf8,
        else => |err| return unexpectedErrno(err),
    }
}

/// An fd-relative file path
///
/// This is currently only used for WASI-specific functionality, but the concept
/// is the same as the dirfd/pathname pairs in the `*at(...)` POSIX functions.
const RelativePathWasi = struct {
    /// Handle to directory
    dir_fd: fd_t,
    /// Path to resource within `dir_fd`.
    relative_path: []const u8,
};

/// Same as `renameat` except the parameters are null-terminated.
pub fn renameatZ(
    old_dir_fd: fd_t,
    old_path: [*:0]const u8,
    new_dir_fd: fd_t,
    new_path: [*:0]const u8,
) RenameError!void {
    if (native_os == .windows) {
        const old_path_w = try windows.cStrToPrefixedFileW(old_dir_fd, old_path);
        const new_path_w = try windows.cStrToPrefixedFileW(new_dir_fd, new_path);
        return renameatW(old_dir_fd, old_path_w.span(), new_dir_fd, new_path_w.span(), windows.TRUE);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return renameat(old_dir_fd, mem.sliceTo(old_path, 0), new_dir_fd, mem.sliceTo(new_path, 0));
    }

    switch (errno(system.renameat(old_dir_fd, old_path, new_dir_fd, new_path))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BUSY => return error.FileBusy,
        .DQUOT => return error.DiskQuota,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .ISDIR => return error.IsDir,
        .LOOP => return error.SymLinkLoop,
        .MLINK => return error.LinkQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .EXIST => return error.PathAlreadyExists,
        .NOTEMPTY => return error.PathAlreadyExists,
        .ROFS => return error.ReadOnlyFileSystem,
        .XDEV => return error.RenameAcrossMountPoints,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Same as `renameat` but Windows-only and the path parameters are
/// [WTF-16](https://simonsapin.github.io/wtf-8/#potentially-ill-formed-utf-16) encoded.
pub fn renameatW(
    old_dir_fd: fd_t,
    old_path_w: []const u16,
    new_dir_fd: fd_t,
    new_path_w: []const u16,
    ReplaceIfExists: windows.BOOLEAN,
) RenameError!void {
    const src_fd = windows.OpenFile(old_path_w, .{
        .dir = old_dir_fd,
        .access_mask = windows.SYNCHRONIZE | windows.GENERIC_WRITE | windows.DELETE,
        .creation = windows.FILE_OPEN,
        .filter = .any, // This function is supposed to rename both files and directories.
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.WouldBlock => unreachable, // Not possible without `.share_access_nonblocking = true`.
        else => |e| return e,
    };
    defer windows.CloseHandle(src_fd);

    var need_fallback = true;
    var rc: windows.NTSTATUS = undefined;
    // FILE_RENAME_INFORMATION_EX and FILE_RENAME_POSIX_SEMANTICS require >= win10_rs1,
    // but FILE_RENAME_IGNORE_READONLY_ATTRIBUTE requires >= win10_rs5. We check >= rs5 here
    // so that we only use POSIX_SEMANTICS when we know IGNORE_READONLY_ATTRIBUTE will also be
    // supported in order to avoid either (1) using a redundant call that we can know in advance will return
    // STATUS_NOT_SUPPORTED or (2) only setting IGNORE_READONLY_ATTRIBUTE when >= rs5
    // and therefore having different behavior when the Windows version is >= rs1 but < rs5.
    if (builtin.target.os.isAtLeast(.windows, .win10_rs5) orelse false) {
        const struct_buf_len = @sizeOf(windows.FILE_RENAME_INFORMATION_EX) + (max_path_bytes - 1);
        var rename_info_buf: [struct_buf_len]u8 align(@alignOf(windows.FILE_RENAME_INFORMATION_EX)) = undefined;
        const struct_len = @sizeOf(windows.FILE_RENAME_INFORMATION_EX) - 1 + new_path_w.len * 2;
        if (struct_len > struct_buf_len) return error.NameTooLong;

        const rename_info: *windows.FILE_RENAME_INFORMATION_EX = @ptrCast(&rename_info_buf);
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;

        var flags: windows.ULONG = windows.FILE_RENAME_POSIX_SEMANTICS | windows.FILE_RENAME_IGNORE_READONLY_ATTRIBUTE;
        if (ReplaceIfExists == windows.TRUE) flags |= windows.FILE_RENAME_REPLACE_IF_EXISTS;
        rename_info.* = .{
            .Flags = flags,
            .RootDirectory = if (fs.path.isAbsoluteWindowsWTF16(new_path_w)) null else new_dir_fd,
            .FileNameLength = @intCast(new_path_w.len * 2), // already checked error.NameTooLong
            .FileName = undefined,
        };
        @memcpy((&rename_info.FileName).ptr, new_path_w);
        rc = windows.ntdll.NtSetInformationFile(
            src_fd,
            &io_status_block,
            rename_info,
            @intCast(struct_len), // already checked for error.NameTooLong
            .FileRenameInformationEx,
        );
        switch (rc) {
            .SUCCESS => return,
            // INVALID_PARAMETER here means that the filesystem does not support FileRenameInformationEx
            .INVALID_PARAMETER => {},
            // For all other statuses, fall down to the switch below to handle them.
            else => need_fallback = false,
        }
    }

    if (need_fallback) {
        const struct_buf_len = @sizeOf(windows.FILE_RENAME_INFORMATION) + (max_path_bytes - 1);
        var rename_info_buf: [struct_buf_len]u8 align(@alignOf(windows.FILE_RENAME_INFORMATION)) = undefined;
        const struct_len = @sizeOf(windows.FILE_RENAME_INFORMATION) - 1 + new_path_w.len * 2;
        if (struct_len > struct_buf_len) return error.NameTooLong;

        const rename_info: *windows.FILE_RENAME_INFORMATION = @ptrCast(&rename_info_buf);
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;

        rename_info.* = .{
            .Flags = ReplaceIfExists,
            .RootDirectory = if (fs.path.isAbsoluteWindowsWTF16(new_path_w)) null else new_dir_fd,
            .FileNameLength = @intCast(new_path_w.len * 2), // already checked error.NameTooLong
            .FileName = undefined,
        };
        @memcpy((&rename_info.FileName).ptr, new_path_w);

        rc =
            windows.ntdll.NtSetInformationFile(
                src_fd,
                &io_status_block,
                rename_info,
                @intCast(struct_len), // already checked for error.NameTooLong
                .FileRenameInformation,
            );
    }

    switch (rc) {
        .SUCCESS => {},
        .INVALID_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        .OBJECT_PATH_SYNTAX_BAD => unreachable,
        .ACCESS_DENIED => return error.AccessDenied,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NOT_SAME_DEVICE => return error.RenameAcrossMountPoints,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .DIRECTORY_NOT_EMPTY => return error.PathAlreadyExists,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        else => return windows.unexpectedStatus(rc),
    }
}

/// On Windows, `sub_dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_dir_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn mkdirat(dir_fd: fd_t, sub_dir_path: []const u8, mode: mode_t) MakeDirError!void {
    if (native_os == .windows) {
        const sub_dir_path_w = try windows.sliceToPrefixedFileW(dir_fd, sub_dir_path);
        return mkdiratW(dir_fd, sub_dir_path_w.span(), mode);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return mkdiratWasi(dir_fd, sub_dir_path, mode);
    } else {
        const sub_dir_path_c = try toPosixPath(sub_dir_path);
        return mkdiratZ(dir_fd, &sub_dir_path_c, mode);
    }
}

pub fn mkdiratWasi(dir_fd: fd_t, sub_dir_path: []const u8, mode: mode_t) MakeDirError!void {
    _ = mode;
    switch (wasi.path_create_directory(dir_fd, sub_dir_path.ptr, sub_dir_path.len)) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .BADF => unreachable,
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
        .NOTCAPABLE => return error.AccessDenied,
        .ILSEQ => return error.InvalidUtf8,
        else => |err| return unexpectedErrno(err),
    }
}

/// Same as `mkdirat` except the parameters are null-terminated.
pub fn mkdiratZ(dir_fd: fd_t, sub_dir_path: [*:0]const u8, mode: mode_t) MakeDirError!void {
    if (native_os == .windows) {
        const sub_dir_path_w = try windows.cStrToPrefixedFileW(dir_fd, sub_dir_path);
        return mkdiratW(dir_fd, sub_dir_path_w.span(), mode);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return mkdirat(dir_fd, mem.sliceTo(sub_dir_path, 0), mode);
    }
    switch (errno(system.mkdirat(dir_fd, sub_dir_path, mode))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .BADF => unreachable,
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
        // dragonfly: when dir_fd is unlinked from filesystem
        .NOTCONN => return error.FileNotFound,
        .ILSEQ => |err| if (native_os == .wasi)
            return error.InvalidUtf8
        else
            return unexpectedErrno(err),
        else => |err| return unexpectedErrno(err),
    }
}

/// Windows-only. Same as `mkdirat` except the parameter WTF16 LE encoded.
pub fn mkdiratW(dir_fd: fd_t, sub_path_w: []const u16, mode: mode_t) MakeDirError!void {
    _ = mode;
    const sub_dir_handle = windows.OpenFile(sub_path_w, .{
        .dir = dir_fd,
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

pub const MakeDirError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to create a new directory relative to it.
    AccessDenied,
    PermissionDenied,
    DiskQuota,
    PathAlreadyExists,
    SymLinkLoop,
    LinkQuotaExceeded,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NoSpaceLeft,
    NotDir,
    ReadOnlyFileSystem,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
    BadPathName,
    NoDevice,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || UnexpectedError;

/// Create a directory.
/// `mode` is ignored on Windows and WASI.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn mkdir(dir_path: []const u8, mode: mode_t) MakeDirError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        return mkdirat(AT.FDCWD, dir_path, mode);
    } else if (native_os == .windows) {
        const dir_path_w = try windows.sliceToPrefixedFileW(null, dir_path);
        return mkdirW(dir_path_w.span(), mode);
    } else {
        const dir_path_c = try toPosixPath(dir_path);
        return mkdirZ(&dir_path_c, mode);
    }
}

/// Same as `mkdir` but the parameter is null-terminated.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn mkdirZ(dir_path: [*:0]const u8, mode: mode_t) MakeDirError!void {
    if (native_os == .windows) {
        const dir_path_w = try windows.cStrToPrefixedFileW(null, dir_path);
        return mkdirW(dir_path_w.span(), mode);
    } else if (native_os == .wasi and !builtin.link_libc) {
        return mkdir(mem.sliceTo(dir_path, 0), mode);
    }```
