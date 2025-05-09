```
         .INVAL => {
                // Sometimes Darwin returns EINVAL for no reason.
                // We treat it as a spurious wakeup.
                return;
            },
            .INTR => {
                req = rem;
                continue;
            },
            // This prong handles success as well as unexpected errors.
            else => return,
        }
    }
}

pub fn dl_iterate_phdr(
    context: anytype,
    comptime Error: type,
    comptime callback: fn (info: *dl_phdr_info, size: usize, context: @TypeOf(context)) Error!void,
) Error!void {
    const Context = @TypeOf(context);
    const elf = std.elf;
    const dl = @import("dynamic_library.zig");

    switch (builtin.object_format) {
        .elf, .c => {},
        else => @compileError("dl_iterate_phdr is not available for this target"),
    }

    if (builtin.link_libc) {
        switch (system.dl_iterate_phdr(struct {
            fn callbackC(info: *dl_phdr_info, size: usize, data: ?*anyopaque) callconv(.c) c_int {
                const context_ptr: *const Context = @ptrCast(@alignCast(data));
                callback(info, size, context_ptr.*) catch |err| return @intFromError(err);
                return 0;
            }
        }.callbackC, @ptrCast(@constCast(&context)))) {
            0 => return,
            else => |err| return @as(Error, @errorCast(@errorFromInt(@as(std.meta.Int(.unsigned, @bitSizeOf(anyerror)), @intCast(err))))),
        }
    }

    const elf_base = std.process.getBaseAddress();
    const ehdr: *elf.Ehdr = @ptrFromInt(elf_base);
    // Make sure the base address points to an ELF image.
    assert(mem.eql(u8, ehdr.e_ident[0..4], elf.MAGIC));
    const n_phdr = ehdr.e_phnum;
    const phdrs = (@as([*]elf.Phdr, @ptrFromInt(elf_base + ehdr.e_phoff)))[0..n_phdr];

    var it = dl.linkmap_iterator(phdrs) catch unreachable;

    // The executable has no dynamic link segment, create a single entry for
    // the whole ELF image.
    if (it.end()) {
        // Find the base address for the ELF image, if this is a PIE the value
        // is non-zero.
        const base_address = for (phdrs) |*phdr| {
            if (phdr.p_type == elf.PT_PHDR) {
                break @intFromPtr(phdrs.ptr) - phdr.p_vaddr;
                // We could try computing the difference between _DYNAMIC and
                // the p_vaddr of the PT_DYNAMIC section, but using the phdr is
                // good enough (Is it?).
            }
        } else unreachable;

        var info = dl_phdr_info{
            .addr = base_address,
            .name = "/proc/self/exe",
            .phdr = phdrs.ptr,
            .phnum = ehdr.e_phnum,
        };

        return callback(&info, @sizeOf(dl_phdr_info), context);
    }

    // Last return value from the callback function.
    while (it.next()) |entry| {
        var phdr: [*]elf.Phdr = undefined;
        var phnum: u16 = undefined;

        if (entry.l_addr != 0) {
            const elf_header: *elf.Ehdr = @ptrFromInt(entry.l_addr);
            phdr = @ptrFromInt(entry.l_addr + elf_header.e_phoff);
            phnum = elf_header.e_phnum;
        } else {
            // This is the running ELF image
            phdr = @ptrFromInt(elf_base + ehdr.e_phoff);
            phnum = ehdr.e_phnum;
        }

        var info = dl_phdr_info{
            .addr = entry.l_addr,
            .name = entry.l_name,
            .phdr = phdr,
            .phnum = phnum,
        };

        try callback(&info, @sizeOf(dl_phdr_info), context);
    }
}

pub const ClockGetTimeError = error{UnsupportedClock} || UnexpectedError;

pub fn clock_gettime(clock_id: clockid_t) ClockGetTimeError!timespec {
    var tp: timespec = undefined;

    if (native_os == .windows) {
        @compileError("Windows does not support POSIX; use Windows-specific API or cross-platform std.time API");
    } else if (native_os == .wasi and !builtin.link_libc) {
        var ts: timestamp_t = undefined;
        switch (system.clock_time_get(clock_id, 1, &ts)) {
            .SUCCESS => {
                tp = .{
                    .sec = @intCast(ts / std.time.ns_per_s),
                    .nsec = @intCast(ts % std.time.ns_per_s),
                };
            },
            .INVAL => return error.UnsupportedClock,
            else => |err| return unexpectedErrno(err),
        }
        return tp;
    }

    switch (errno(system.clock_gettime(clock_id, &tp))) {
        .SUCCESS => return tp,
        .FAULT => unreachable,
        .INVAL => return error.UnsupportedClock,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn clock_getres(clock_id: clockid_t, res: *timespec) ClockGetTimeError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        var ts: timestamp_t = undefined;
        switch (system.clock_res_get(@bitCast(clock_id), &ts)) {
            .SUCCESS => res.* = .{
                .sec = @intCast(ts / std.time.ns_per_s),
                .nsec = @intCast(ts % std.time.ns_per_s),
            },
            .INVAL => return error.UnsupportedClock,
            else => |err| return unexpectedErrno(err),
        }
        return;
    }

    switch (errno(system.clock_getres(clock_id, res))) {
        .SUCCESS => return,
        .FAULT => unreachable,
        .INVAL => return error.UnsupportedClock,
        else => |err| return unexpectedErrno(err),
    }
}

pub const SchedGetAffinityError = error{PermissionDenied} || UnexpectedError;

pub fn sched_getaffinity(pid: pid_t) SchedGetAffinityError!cpu_set_t {
    var set: cpu_set_t = undefined;
    switch (errno(system.sched_getaffinity(pid, @sizeOf(cpu_set_t), &set))) {
        .SUCCESS => return set,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .SRCH => unreachable,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub const SigaltstackError = error{
    /// The supplied stack size was less than MINSIGSTKSZ.
    SizeTooSmall,

    /// Attempted to change the signal stack while it was active.
    PermissionDenied,
} || UnexpectedError;

pub fn sigaltstack(ss: ?*stack_t, old_ss: ?*stack_t) SigaltstackError!void {
    switch (errno(system.sigaltstack(ss, old_ss))) {
        .SUCCESS => return,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .NOMEM => return error.SizeTooSmall,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

/// Examine and change a signal action.
pub fn sigaction(sig: u6, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) void {
    switch (errno(system.sigaction(sig, act, oact))) {
        .SUCCESS => return,
        // EINVAL means the signal is either invalid or some signal that cannot have its action
        // changed. For POSIX, this means SIGKILL/SIGSTOP. For e.g. Solaris, this also includes the
        // non-standard SIGWAITING, SIGCANCEL, and SIGLWP. Either way, programmer error.
        .INVAL => unreachable,
        else => unreachable,
    }
}

/// Sets the thread signal mask.
pub fn sigprocmask(flags: u32, noalias set: ?*const sigset_t, noalias oldset: ?*sigset_t) void {
    switch (errno(system.sigprocmask(@bitCast(flags), set, oldset))) {
        .SUCCESS => return,
        .FAULT => unreachable,
        .INVAL => unreachable,
        else => unreachable,
    }
}

pub const FutimensError = error{
    /// times is NULL, or both nsec values are UTIME_NOW, and either:
    /// *  the effective user ID of the caller does not match the  owner
    ///    of  the  file,  the  caller does not have write access to the
    ///    file, and the caller is not privileged (Linux: does not  have
    ///    either  the  CAP_FOWNER  or the CAP_DAC_OVERRIDE capability);
    ///    or,
    /// *  the file is marked immutable (see chattr(1)).
    AccessDenied,

    /// The caller attempted to change one or both timestamps to a value
    /// other than the current time, or to change one of the  timestamps
    /// to the current time while leaving the other timestamp unchanged,
    /// (i.e., times is not NULL, neither nsec  field  is  UTIME_NOW,
    /// and neither nsec field is UTIME_OMIT) and either:
    /// *  the  caller's  effective  user ID does not match the owner of
    ///    file, and the caller is not privileged (Linux: does not  have
    ///    the CAP_FOWNER capability); or,
    /// *  the file is marked append-only or immutable (see chattr(1)).
    PermissionDenied,

    ReadOnlyFileSystem,
} || UnexpectedError;

pub fn futimens(fd: fd_t, times: ?*const [2]timespec) FutimensError!void {
    if (native_os == .wasi and !builtin.link_libc) {
        // TODO WASI encodes `wasi.fstflags` to signify magic values
        // similar to UTIME_NOW and UTIME_OMIT. Currently, we ignore
        // this here, but we should really handle it somehow.
        const error_code = blk: {
            if (times) |times_arr| {
                const atim = times_arr[0].toTimestamp();
                const mtim = times_arr[1].toTimestamp();
                break :blk wasi.fd_filestat_set_times(fd, atim, mtim, .{
                    .ATIM = true,
                    .MTIM = true,
                });
            }

            break :blk wasi.fd_filestat_set_times(fd, 0, 0, .{
                .ATIM_NOW = true,
                .MTIM_NOW = true,
            });
        };
        switch (error_code) {
            .SUCCESS => return,
            .ACCES => return error.AccessDenied,
            .PERM => return error.PermissionDenied,
            .BADF => unreachable, // always a race condition
            .FAULT => unreachable,
            .INVAL => unreachable,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return unexpectedErrno(err),
        }
    }

    switch (errno(system.futimens(fd, times))) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .BADF => unreachable, // always a race condition
        .FAULT => unreachable,
        .INVAL => unreachable,
        .ROFS => return error.ReadOnlyFileSystem,
        else => |err| return unexpectedErrno(err),
    }
}

pub const GetHostNameError = error{PermissionDenied} || UnexpectedError;

pub fn gethostname(name_buffer: *[HOST_NAME_MAX]u8) GetHostNameError![]u8 {
    if (builtin.link_libc) {
        switch (errno(system.gethostname(name_buffer, name_buffer.len))) {
            .SUCCESS => return mem.sliceTo(name_buffer, 0),
            .FAULT => unreachable,
            .NAMETOOLONG => unreachable, // HOST_NAME_MAX prevents this
            .PERM => return error.PermissionDenied,
            else => |err| return unexpectedErrno(err),
        }
    }
    if (native_os == .linux) {
        const uts = uname();
        const hostname = mem.sliceTo(&uts.nodename, 0);
        const result = name_buffer[0..hostname.len];
        @memcpy(result, hostname);
        return result;
    }

    @compileError("TODO implement gethostname for this OS");
}

pub fn uname() utsname {
    var uts: utsname = undefined;
    switch (errno(system.uname(&uts))) {
        .SUCCESS => return uts,
        .FAULT => unreachable,
        else => unreachable,
    }
}

pub fn res_mkquery(
    op: u4,
    dname: []const u8,
    class: u8,
    ty: u8,
    data: []const u8,
    newrr: ?[*]const u8,
    buf: []u8,
) usize {
    _ = data;
    _ = newrr;
    // This implementation is ported from musl libc.
    // A more idiomatic "ziggy" implementation would be welcome.
    var name = dname;
    if (mem.endsWith(u8, name, ".")) name.len -= 1;
    assert(name.len <= 253);
    const n = 17 + name.len + @intFromBool(name.len != 0);

    // Construct query template - ID will be filled later
    var q: [280]u8 = undefined;
    @memset(q[0..n], 0);
    q[2] = @as(u8, op) * 8 + 1;
    q[5] = 1;
    @memcpy(q[13..][0..name.len], name);
    var i: usize = 13;
    var j: usize = undefined;
    while (q[i] != 0) : (i = j + 1) {
        j = i;
        while (q[j] != 0 and q[j] != '.') : (j += 1) {}
        // TODO determine the circumstances for this and whether or
        // not this should be an error.
        if (j - i - 1 > 62) unreachable;
        q[i - 1] = @intCast(j - i);
    }
    q[i + 1] = ty;
    q[i + 3] = class;

    // Make a reasonably unpredictable id
    const ts = clock_gettime(.REALTIME) catch unreachable;
    const UInt = std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(ts.nsec)));
    const unsec: UInt = @bitCast(ts.nsec);
    const id: u32 = @truncate(unsec + unsec / 65536);
    q[0] = @truncate(id / 256);
    q[1] = @truncate(id);

    @memcpy(buf[0..n], q[0..n]);
    return n;
}

pub const SendError = error{
    /// (For UNIX domain sockets, which are identified by pathname) Write permission is  denied
    /// on  the destination socket file, or search permission is denied for one of the
    /// directories the path prefix.  (See path_resolution(7).)
    /// (For UDP sockets) An attempt was made to send to a network/broadcast address as  though
    /// it was a unicast address.
    AccessDenied,

    /// The socket is marked nonblocking and the requested operation would block, and
    /// there is no global event loop configured.
    /// It's also possible to get this error under the following condition:
    /// (Internet  domain datagram sockets) The socket referred to by sockfd had not previously
    /// been bound to an address and, upon attempting to bind it to an ephemeral port,  it  was
    /// determined that all port numbers in the ephemeral port range are currently in use.  See
    /// the discussion of /proc/sys/net/ipv4/ip_local_port_range in ip(7).
    WouldBlock,

    /// Another Fast Open is already in progress.
    FastOpenAlreadyInProgress,

    /// Connection reset by peer.
    ConnectionResetByPeer,

    /// The  socket  type requires that message be sent atomically, and the size of the message
    /// to be sent made this impossible. The message is not transmitted.
    MessageTooBig,

    /// The output queue for a network interface was full.  This generally indicates  that  the
    /// interface  has  stopped sending, but may be caused by transient congestion.  (Normally,
    /// this does not occur in Linux.  Packets are just silently dropped when  a  device  queue
    /// overflows.)
    /// This is also caused when there is not enough kernel memory available.
    SystemResources,

    /// The  local  end  has been shut down on a connection oriented socket.  In this case, the
    /// process will also receive a SIGPIPE unless MSG.NOSIGNAL is set.
    BrokenPipe,

    FileDescriptorNotASocket,

    /// Network is unreachable.
    NetworkUnreachable,

    /// The local network interface used to reach the destination is down.
    NetworkSubsystemFailed,
} || UnexpectedError;

pub const SendMsgError = SendError || error{
    /// The passed address didn't have the correct address family in its sa_family field.
    AddressFamilyNotSupported,

    /// Returned when socket is AF.UNIX and the given path has a symlink loop.
    SymLinkLoop,

    /// Returned when socket is AF.UNIX and the given path length exceeds `max_path_bytes` bytes.
    NameTooLong,

    /// Returned when socket is AF.UNIX and the given path does not point to an existing file.
    FileNotFound,
    NotDir,

    /// The socket is not connected (connection-oriented sockets only).
    SocketNotConnected,
    AddressNotAvailable,
};

pub fn sendmsg(
    /// The file descriptor of the sending socket.
    sockfd: socket_t,
    /// Message header and iovecs
    msg: *const msghdr_const,
    flags: u32,
) SendMsgError!usize {
    while (true) {
        const rc = system.sendmsg(sockfd, msg, flags);
        if (native_os == .windows) {
            if (rc == windows.ws2_32.SOCKET_ERROR) {
                switch (windows.ws2_32.WSAGetLastError()) {
                    .WSAEACCES => return error.AccessDenied,
                    .WSAEADDRNOTAVAIL => return error.AddressNotAvailable,
                    .WSAECONNRESET => return error.ConnectionResetByPeer,
                    .WSAEMSGSIZE => return error.MessageTooBig,
                    .WSAENOBUFS => return error.SystemResources,
                    .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                    .WSAEAFNOSUPPORT => return error.AddressFamilyNotSupported,
                    .WSAEDESTADDRREQ => unreachable, // A destination address is required.
                    .WSAEFAULT => unreachable, // The lpBuffers, lpTo, lpOverlapped, lpNumberOfBytesSent, or lpCompletionRoutine parameters are not part of the user address space, or the lpTo parameter is too small.
                    .WSAEHOSTUNREACH => return error.NetworkUnreachable,
                    // TODO: WSAEINPROGRESS, WSAEINTR
                    .WSAEINVAL => unreachable,
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAENETRESET => return error.ConnectionResetByPeer,
                    .WSAENETUNREACH => return error.NetworkUnreachable,
                    .WSAENOTCONN => return error.SocketNotConnected,
                    .WSAESHUTDOWN => unreachable, // The socket has been shut down; it is not possible to WSASendTo on a socket after shutdown has been invoked with how set to SD_SEND or SD_BOTH.
                    .WSAEWOULDBLOCK => return error.WouldBlock,
                    .WSANOTINITIALISED => unreachable, // A successful WSAStartup call must occur before using this function.
                    else => |err| return windows.unexpectedWSAError(err),
                }
            } else {
                return @intCast(rc);
            }
        } else {
            switch (errno(rc)) {
                .SUCCESS => return @intCast(rc),

                .ACCES => return error.AccessDenied,
                .AGAIN => return error.WouldBlock,
                .ALREADY => return error.FastOpenAlreadyInProgress,
                .BADF => unreachable, // always a race condition
                .CONNRESET => return error.ConnectionResetByPeer,
                .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
                .FAULT => unreachable, // An invalid user space address was specified for an argument.
                .INTR => continue,
                .INVAL => unreachable, // Invalid argument passed.
                .ISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
                .MSGSIZE => return error.MessageTooBig,
                .NOBUFS => return error.SystemResources,
                .NOMEM => return error.SystemResources,
                .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
                .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
                .PIPE => return error.BrokenPipe,
                .AFNOSUPPORT => return error.AddressFamilyNotSupported,
                .LOOP => return error.SymLinkLoop,
                .NAMETOOLONG => return error.NameTooLong,
                .NOENT => return error.FileNotFound,
                .NOTDIR => return error.NotDir,
                .HOSTUNREACH => return error.NetworkUnreachable,
                .NETUNREACH => return error.NetworkUnreachable,
                .NOTCONN => return error.SocketNotConnected,
                .NETDOWN => return error.NetworkSubsystemFailed,
                else => |err| return unexpectedErrno(err),
            }
        }
    }
}

pub const SendToError = SendMsgError || error{
    /// The destination address is not reachable by the bound address.
    UnreachableAddress,
    /// The destination address is not listening.
    ConnectionRefused,
};

/// Transmit a message to another socket.
///
/// The `sendto` call may be used only when the socket is in a connected state (so that the intended
/// recipient  is  known). The  following call
///
///     send(sockfd, buf, len, flags);
///
/// is equivalent to
///
///     sendto(sockfd, buf, len, flags, NULL, 0);
///
/// If  sendto()  is used on a connection-mode (`SOCK.STREAM`, `SOCK.SEQPACKET`) socket, the arguments
/// `dest_addr` and `addrlen` are asserted to be `null` and `0` respectively, and asserted
/// that the socket was actually connected.
/// Otherwise, the address of the target is given by `dest_addr` with `addrlen` specifying  its  size.
///
/// If the message is too long to pass atomically through the underlying protocol,
/// `SendError.MessageTooBig` is returned, and the message is not transmitted.
///
/// There is no  indication  of  failure  to  deliver.
///
/// When the message does not fit into the send buffer of  the  socket,  `sendto`  normally  blocks,
/// unless  the socket has been placed in nonblocking I/O mode.  In nonblocking mode it would fail
/// with `SendError.WouldBlock`.  The `select` call may be used  to  determine when it is
/// possible to send more data.
pub fn sendto(
    /// The file descriptor of the sending socket.
    sockfd: socket_t,
    /// Message to send.
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const sockaddr,
    addrlen: socklen_t,
) SendToError!usize {
    if (native_os == .windows) {
        switch (windows.sendto(sockfd, buf.ptr, buf.len, flags, dest_addr, addrlen)) {
            windows.ws2_32.SOCKET_ERROR => switch (windows.ws2_32.WSAGetLastError()) {
                .WSAEACCES => return error.AccessDenied,
                .WSAEADDRNOTAVAIL => return error.AddressNotAvailable,
                .WSAECONNRESET => return error.ConnectionResetByPeer,
                .WSAEMSGSIZE => return error.MessageTooBig,
                .WSAENOBUFS => return error.SystemResources,
                .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                .WSAEAFNOSUPPORT => return error.AddressFamilyNotSupported,
                .WSAEDESTADDRREQ => unreachable, // A destination address is required.
                .WSAEFAULT => unreachable, // The lpBuffers, lpTo, lpOverlapped, lpNumberOfBytesSent, or lpCompletionRoutine parameters are not part of the user address space, or the lpTo parameter is too small.
                .WSAEHOSTUNREACH => return error.NetworkUnreachable,
                // TODO: WSAEINPROGRESS, WSAEINTR
                .WSAEINVAL => unreachable,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAENETRESET => return error.ConnectionResetByPeer,
                .WSAENETUNREACH => return error.NetworkUnreachable,
                .WSAENOTCONN => return error.SocketNotConnected,
                .WSAESHUTDOWN => unreachable, // The socket has been shut down; it is not possible to WSASendTo on a socket after shutdown has been invoked with how set to SD_SEND or SD_BOTH.
                .WSAEWOULDBLOCK => return error.WouldBlock,
                .WSANOTINITIALISED => unreachable, // A successful WSAStartup call must occur before using this function.
                else => |err| return windows.unexpectedWSAError(err),
            },
            else => |rc| return @intCast(rc),
        }
    }
    while (true) {
        const rc = system.sendto(sockfd, buf.ptr, buf.len, flags, dest_addr, addrlen);
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),

            .ACCES => return error.AccessDenied,
            .AGAIN => return error.WouldBlock,
            .ALREADY => return error.FastOpenAlreadyInProgress,
            .BADF => unreachable, // always a race condition
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
            .FAULT => unreachable, // An invalid user space address was specified for an argument.
            .INTR => continue,
            .INVAL => return error.UnreachableAddress,
            .ISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
            .MSGSIZE => return error.MessageTooBig,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
            .PIPE => return error.BrokenPipe,
            .AFNOSUPPORT => return error.AddressFamilyNotSupported,
            .LOOP => return error.SymLinkLoop,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .HOSTUNREACH => return error.NetworkUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NETDOWN => return error.NetworkSubsystemFailed,
            else => |err| return unexpectedErrno(err),
        }
    }
}

/// Transmit a message to another socket.
///
/// The `send` call may be used only when the socket is in a connected state (so that the intended
/// recipient  is  known).   The  only  difference  between `send` and `write` is the presence of
/// flags.  With a zero flags argument, `send` is equivalent to  `write`.   Also,  the  following
/// call
///
///     send(sockfd, buf, len, flags);
///
/// is equivalent to
///
///     sendto(sockfd, buf, len, flags, NULL, 0);
///
/// There is no  indication  of  failure  to  deliver.
///
/// When the message does not fit into the send buffer of  the  socket,  `send`  normally  blocks,
/// unless  the socket has been placed in nonblocking I/O mode.  In nonblocking mode it would fail
/// with `SendError.WouldBlock`.  The `select` call may be used  to  determine when it is
/// possible to send more data.
pub fn send(
    /// The file descriptor of the sending socket.
    sockfd: socket_t,
    buf: []const u8,
    flags: u32,
) SendError!usize {
    return sendto(sockfd, buf, flags, null, 0) catch |err| switch (err) {
        error.AddressFamilyNotSupported => unreachable,
        error.SymLinkLoop => unreachable,
        error.NameTooLong => unreachable,
        error.FileNotFound => unreachable,
        error.NotDir => unreachable,
        error.NetworkUnreachable => unreachable,
        error.AddressNotAvailable => unreachable,
        error.SocketNotConnected => unreachable,
        error.UnreachableAddress => unreachable,
        error.ConnectionRefused => unreachable,
        else => |e| return e,
    };
}

pub const SendFileError = PReadError || WriteError || SendError;

/// Transfer data between file descriptors, with optional headers and trailers.
///
/// Returns the number of bytes written, which can be zero.
///
/// The `sendfile` call copies `in_len` bytes from one file descriptor to another. When possible,
/// this is done within the operating system kernel, which can provide better performance
/// characteristics than transferring data from kernel to user space and back, such as with
/// `read` and `write` calls. When `in_len` is `0`, it means to copy until the end of the input file has been
/// reached. Note, however, that partial writes are still possible in this case.
///
/// `in_fd` must be a file descriptor opened for reading, and `out_fd` must be a file descriptor
/// opened for writing. They may be any kind of file descriptor; however, if `in_fd` is not a regular
/// file system file, it may cause this function to fall back to calling `read` and `write`, in which case
/// atomicity guarantees no longer apply.
///
/// Copying begins reading at `in_offset`. The input file descriptor seek position is ignored and not updated.
/// If the output file descriptor has a seek position, it is updated as bytes are written. When
/// `in_offset` is past the end of the input file, it successfully reads 0 bytes.
///
/// `flags` has different meanings per operating system; refer to the respective man pages.
///
/// These systems support atomically sending everything, including headers and trailers:
/// * macOS
/// * FreeBSD
///
/// These systems support in-kernel data copying, but headers and trailers are not sent atomically:
/// * Linux
///
/// Other systems fall back to calling `read` / `write`.
///
/// Linux has a limit on how many bytes may be transferred in one `sendfile` call, which is `0x7ffff000`
/// on both 64-bit and 32-bit systems. This is due to using a signed C int as the return value, as
/// well as stuffing the errno codes into the last `4096` values. This is noted on the `sendfile` man page.
/// The limit on Darwin is `0x7fffffff`, trying to write more than that returns EINVAL.
/// The corresponding POSIX limit on this is `maxInt(isize)`.
pub fn sendfile(
    out_fd: fd_t,
    in_fd: fd_t,
    in_offset: u64,
    in_len: u64,
    headers: []const iovec_const,
    trailers: []const iovec_const,
    flags: u32,
) SendFileError!usize {
    var header_done = false;
    var total_written: usize = 0;

    // Prevents EOVERFLOW.
    const size_t = std.meta.Int(.unsigned, @typeInfo(usize).int.bits - 1);
    const max_count = switch (native_os) {
        .linux => 0x7ffff000,
        .macos, .ios, .watchos, .tvos, .visionos => maxInt(i32),
        else => maxInt(size_t),
    };

    switch (native_os) {
        .linux => sf: {
            if (headers.len != 0) {
                const amt = try writev(out_fd, headers);
                total_written += amt;
                if (amt < count_iovec_bytes(headers)) return total_written;
                header_done = true;
            }

            // Here we match BSD behavior, making a zero count value send as many bytes as possible.
            const adjusted_count = if (in_len == 0) max_count else @min(in_len, max_count);

            const sendfile_sym = if (lfs64_abi) system.sendfile64 else system.sendfile;
            while (true) {
                var offset: off_t = @bitCast(in_offset);
                const rc = sendfile_sym(out_fd, in_fd, &offset, adjusted_count);
                switch (errno(rc)) {
                    .SUCCESS => {
                        const amt: usize = @bitCast(rc);
                        total_written += amt;
                        if (in_len == 0 and amt == 0) {
                            // We have detected EOF from `in_fd`.
                            break;
                        } else if (amt < in_len) {
                            return total_written;
                        } else {
                            break;
                        }
                    },

                    .BADF => unreachable, // Always a race condition.
                    .FAULT => unreachable, // Segmentation fault.
                    .OVERFLOW => unreachable, // We avoid passing too large of a `count`.
                    .NOTCONN => return error.BrokenPipe, // `out_fd` is an unconnected socket

                    .INVAL => {
                        // EINVAL could be any of the following situations:
                        // * Descriptor is not valid or locked
                        // * an mmap(2)-like operation is  not  available  for in_fd
                        // * count is negative
                        // * out_fd has the APPEND flag set
                        // Because of the "mmap(2)-like operation" possibility, we fall back to doing read/write
                        // manually.
                        break :sf;
                    },
                    .AGAIN => return error.WouldBlock,
                    .IO => return error.InputOutput,
                    .PIPE => return error.BrokenPipe,
                    .NOMEM => return error.SystemResources,
                    .NXIO => return error.Unseekable,
                    .SPIPE => return error.Unseekable,
                    else => |err| {
                        unexpectedErrno(err) catch {};
                        break :sf;
                    },
                }
            }

            if (trailers.len != 0) {
                total_written += try writev(out_fd, trailers);
            }

            return total_written;
        },
        .freebsd => sf: {
            var hdtr_data: std.c.sf_hdtr = undefined;
            var hdtr: ?*std.c.sf_hdtr = null;
            if (headers.len != 0 or trailers.len != 0) {
                // Here we carefully avoid `@intCast` by returning partial writes when
                // too many io vectors are provided.
                const hdr_cnt = cast(u31, headers.len) orelse maxInt(u31);
                if (headers.len > hdr_cnt) return writev(out_fd, headers);

                const trl_cnt = cast(u31, trailers.len) orelse maxInt(u31);

                hdtr_data = std.c.sf_hdtr{
                    .headers = headers.ptr,
                    .hdr_cnt = hdr_cnt,
                    .trailers = trailers.ptr,
                    .trl_cnt = trl_cnt,
                };
                hdtr = &hdtr_data;
            }

            while (true) {
                var sbytes: off_t = undefined;
                const err = errno(system.sendfile(in_fd, out_fd, @bitCast(in_offset), @min(in_len, max_count), hdtr, &sbytes, flags));
                const amt: usize = @bitCast(sbytes);
                switch (err) {
                    .SUCCESS => return amt,

                    .BADF => unreachable, // Always a race condition.
                    .FAULT => unreachable, // Segmentation fault.
                    .NOTCONN => return error.BrokenPipe, // `out_fd` is an unconnected socket

                    .INVAL, .OPNOTSUPP, .NOTSOCK, .NOSYS => {
                        // EINVAL could be any of the following situations:
                        // * The fd argument is not a regular file.
                        // * The s argument is not a SOCK.STREAM type socket.
                        // * The offset argument is negative.
                        // Because of some of these possibilities, we fall back to doing read/write
                        // manually, the same as ENOSYS.
                        break :sf;
                    },

                    .INTR => if (amt != 0) return amt else continue,

                    .AGAIN => if (amt != 0) {
                        return amt;
                    } else {
                        return error.WouldBlock;
                    },

                    .BUSY => if (amt != 0) {
                        return amt;
                    } else {
                        return error.WouldBlock;
                    },

                    .IO => return error.InputOutput,
                    .NOBUFS => return error.SystemResources,
                    .PIPE => return error.BrokenPipe,

                    else => {
                        unexpectedErrno(err) catch {};
                        if (amt != 0) {
                            return amt;
                        } else {
                            break :sf;
                        }
                    },
                }
            }
        },
        .macos, .ios, .tvos, .watchos, .visionos => sf: {
            var hdtr_data: std.c.sf_hdtr = undefined;
            var hdtr: ?*std.c.sf_hdtr = null;
            if (headers.len != 0 or trailers.len != 0) {
                // Here we carefully avoid `@intCast` by returning partial writes when
                // too many io vectors are provided.
                const hdr_cnt = cast(u31, headers.len) orelse maxInt(u31);
                if (headers.len > hdr_cnt) return writev(out_fd, headers);

                const trl_cnt = cast(u31, trailers.len) orelse maxInt(u31);

                hdtr_data = std.c.sf_hdtr{
                    .headers = headers.ptr,
                    .hdr_cnt = hdr_cnt,
                    .trailers = trailers.ptr,
                    .trl_cnt = trl_cnt,
                };
                hdtr = &hdtr_data;
            }

            while (true) {
                var sbytes: off_t = @min(in_len, max_count);
                const err = errno(system.sendfile(in_fd, out_fd, @bitCast(in_offset), &sbytes, hdtr, flags));
                const amt: usize = @bitCast(sbytes);
                switch (err) {
                    .SUCCESS => return amt,

                    .BADF => unreachable, // Always a race condition.
                    .FAULT => unreachable, // Segmentation fault.
                    .INVAL => unreachable,
                    .NOTCONN => return error.BrokenPipe, // `out_fd` is an unconnected socket

                    .OPNOTSUPP, .NOTSOCK, .NOSYS => break :sf,

                    .INTR => if (amt != 0) return amt else continue,

                    .AGAIN => if (amt != 0) {
                        return amt;
                    } else {
                        return error.WouldBlock;
                    },

                    .IO => return error.InputOutput,
                    .PIPE => return error.BrokenPipe,

                    else => {
                        unexpectedErrno(err) catch {};
                        if (amt != 0) {
                            return amt;
                        } else {
                            break :sf;
                        }
                    },
                }
            }
        },
        else => {}, // fall back to read/write
    }

    if (headers.len != 0 and !header_done) {
        const amt = try writev(out_fd, headers);
        total_written += amt;
        if (amt < count_iovec_bytes(headers)) return total_written;
    }

    rw: {
        var buf: [8 * 4096]u8 = undefined;
        // Here we match BSD behavior, making a zero count value send as many bytes as possible.
        const adjusted_count = if (in_len == 0) buf.len else @min(buf.len, in_len);
        const amt_read = try pread(in_fd, buf[0..adjusted_count], in_offset);
        if (amt_read == 0) {
            if (in_len == 0) {
                // We have detected EOF from `in_fd`.
                break :rw;
            } else {
                return total_written;
            }
        }
        const amt_written = try write(out_fd, buf[0..amt_read]);
        total_written += amt_written;
        if (amt_written < in_len or in_len == 0) return total_written;
    }

    if (trailers.len != 0) {
        total_written += try writev(out_fd, trailers);
    }

    return total_written;
}

fn count_iovec_bytes(iovs: []const iovec_const) usize {
    var count: usize = 0;
    for (iovs) |iov| {
        count += iov.len;
    }
    return count;
}

pub const CopyFileRangeError = error{
    FileTooBig,
    InputOutput,
    /// `fd_in` is not open for reading; or `fd_out` is not open  for  writing;
    /// or the  `APPEND`  flag  is  set  for `fd_out`.
    FilesOpenedWithWrongFlags,
    IsDir,
    OutOfMemory,
    NoSpaceLeft,
    Unseekable,
    PermissionDenied,
    SwapFile,
    CorruptedData,
} || PReadError || PWriteError || UnexpectedError;

/// Transfer data between file descriptors at specified offsets.
///
/// Returns the number of bytes written, which can less than requested.
///
/// The `copy_file_range` call copies `len` bytes from one file descriptor to another. When possible,
/// this is done within the operating system kernel, which can provide better performance
/// characteristics than transferring data from kernel to user space and back, such as with
/// `pread` and `pwrite` calls.
///
/// `fd_in` must be a file descriptor opened for reading, and `fd_out` must be a file descriptor
/// opened for writing. They may be any kind of file descriptor; however, if `fd_in` is not a regular
/// file system file, it may cause this function to fall back to calling `pread` and `pwrite`, in which case
/// atomicity guarantees no longer apply.
///
/// If `fd_in` and `fd_out` are the same, source and target ranges must not overlap.
/// The file descriptor seek positions are ignored and not updated.
/// When `off_in` is past the end of the input file, it successfully reads 0 bytes.
///
/// `flags` has different meanings per operating system; refer to the respective man pages.
///
/// These systems support in-kernel data copying:
/// * Linux (cross-filesystem from version 5.3)
/// * FreeBSD 13.0
///
/// Other systems fall back to calling `pread` / `pwrite`.
///
/// Maximum offsets on Linux and FreeBSD are `maxInt(i64)`.
pub fn copy_file_range(fd_in: fd_t, off_in: u64, fd_out: fd_t, off_out: u64, len: usize, flags: u32) CopyFileRangeError!usize {
    if (builtin.os.tag == .freebsd or
        (comptime builtin.os.tag == .linux and std.c.versionCheck(.{ .major = 2, .minor = 27, .patch = 0 })))
    {
        var off_in_copy: i64 = @bitCast(off_in);
        var off_out_copy: i64 = @bitCast(off_out);

        while (true) {
            const rc = system.copy_file_range(fd_in, &off_in_copy, fd_out, &off_out_copy, len, flags);
            if (native_os == .freebsd) {
                switch (errno(rc)) {
                    .SUCCESS => return @intCast(rc),
                    .BADF => return error.FilesOpenedWithWrongFlags,
                    .FBIG => return error.FileTooBig,
                    .IO => return error.InputOutput,
                    .ISDIR => return error.IsDir,
                    .NOSPC => return error.NoSpaceLeft,
                    .INVAL => break, // these may not be regular files, try fallback
                    .INTEGRITY => return error.CorruptedData,
                    .INTR => continue,
                    else => |err| return unexpectedErrno(err),
                }
            } else { // assume linux
                switch (errno(rc)) {
                    .SUCCESS => return @intCast(rc),
                    .BADF => return error.FilesOpenedWithWrongFlags,
                    .FBIG => return error.FileTooBig,
                    .IO => return error.InputOutput,
                    .ISDIR => return error.IsDir,
                    .NOSPC => return error.NoSpaceLeft,
                    .INVAL => break, // these may not be regular files, try fallback
                    .NOMEM => return error.OutOfMemory,
                    .OVERFLOW => return error.Unseekable,
                    .PERM => return error.PermissionDenied,
                    .TXTBSY => return error.SwapFile,
                    .XDEV => break, // support for cross-filesystem copy added in Linux 5.3, use fallback
                    else => |err| return unexpectedErrno(err),
                }
            }
        }
    }

    var buf: [8 * 4096]u8 = undefined;
    const amt_read = try pread(fd_in, buf[0..@min(buf.len, len)], off_in);
    if (amt_read == 0) return 0;
    return pwrite(fd_out, buf[0..amt_read], off_out);
}

pub const PollError = error{
    /// The network subsystem has failed.
    NetworkSubsystemFailed,

    /// The kernel had no space to allocate file descriptor tables.
    SystemResources,
} || UnexpectedError;

pub fn poll(fds: []pollfd, timeout: i32) PollError!usize {
    if (native_os == .windows) {
        switch (windows.poll(fds.ptr, @intCast(fds.len), timeout)) {
            windows.ws2_32.SOCKET_ERROR => switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAENOBUFS => return error.SystemResources,
                // TODO: handle more errors
                else => |err| return windows.unexpectedWSAError(err),
            },
            else => |rc| return @intCast(rc),
        }
    }
    while (true) {
        const fds_count = cast(nfds_t, fds.len) orelse return error.SystemResources;
        const rc = system.poll(fds.ptr, fds_count, timeout);
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .FAULT => unreachable,
            .INTR => continue,
            .INVAL => unreachable,
            .NOMEM => return error.SystemResources,
            else => |err| return unexpectedErrno(err),
        }
    }
    unreachable;
}

pub const PPollError = error{
    /// The operation was interrupted by a delivery of a signal before it could complete.
    SignalInterrupt,

    /// The kernel had no space to allocate file descriptor tables.
    SystemResources,
} || UnexpectedError;

pub fn ppoll(fds: []pollfd, timeout: ?*const timespec, mask: ?*const sigset_t) PPollError!usize {
    var ts: timespec = undefined;
    var ts_ptr: ?*timespec = null;
    if (timeout) |timeout_ns| {
        ts_ptr = &ts;
        ts = timeout_ns.*;
    }
    const fds_count = cast(nfds_t, fds.len) orelse return error.SystemResources;
    const rc = system.ppoll(fds.ptr, fds_count, ts_ptr, mask);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .FAULT => unreachable,
        .INTR => return error.SignalInterrupt,
        .INVAL => unreachable,
        .NOMEM => return error.SystemResources,
        else => |err| return unexpectedErrno(err),
    }
}

pub const RecvFromError = error{
    /// The socket is marked nonblocking and the requested operation would block, and
    /// there is no global event loop configured.
    WouldBlock,

    /// A remote host refused to allow the network connection, typically because it is not
    /// running the requested service.
    ConnectionRefused,

    /// Could not allocate kernel memory.
    SystemResources,

    ConnectionResetByPeer,
    ConnectionTimedOut,

    /// The socket has not been bound.
    SocketNotBound,

    /// The UDP message was too big for the buffer and part of it has been discarded
    MessageTooBig,

    /// The network subsystem has failed.
    NetworkSubsystemFailed,

    /// The socket is not connected (connection-oriented sockets only).
    SocketNotConnected,
} || UnexpectedError;

pub fn recv(sock: socket_t, buf: []u8, flags: u32) RecvFromError!usize {
    return recvfrom(sock, buf, flags, null, null);
}

/// If `sockfd` is opened in non blocking mode, the function will
/// return error.WouldBlock when EAGAIN is received.
pub fn recvfrom(
    sockfd: socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*sockaddr,
    addrlen: ?*socklen_t,
) RecvFromError!usize {
    while (true) {
        const rc = system.recvfrom(sockfd, buf.ptr, buf.len, flags, src_addr, addrlen);
        if (native_os == .windows) {
            if (rc == windows.ws2_32.SOCKET_ERROR) {
                switch (windows.ws2_32.WSAGetLastError()) {
                    .WSANOTINITIALISED => unreachable,
                    .WSAECONNRESET => return error.ConnectionResetByPeer,
                    .WSAEINVAL => return error.SocketNotBound,
                    .WSAEMSGSIZE => return error.MessageTooBig,
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAENOTCONN => return error.SocketNotConnected,
                    .WSAEWOULDBLOCK => return error.WouldBlock,
                    .WSAETIMEDOUT => return error.ConnectionTimedOut,
                    // TODO: handle more errors
                    else => |err| return windows.unexpectedWSAError(err),
                }
            } else {
                return @intCast(rc);
            }
        } else {
            switch (errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .BADF => unreachable, // always a race condition
                .FAULT => unreachable,
                .INVAL => unreachable,
                .NOTCONN => return error.SocketNotConnected,
                .NOTSOCK => unreachable,
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .NOMEM => return error.SystemResources,
                .CONNREFUSED => return error.ConnectionRefused,
                .CONNRESET => return error.ConnectionResetByPeer,
                .TIMEDOUT => return error.ConnectionTimedOut,
                else => |err| return unexpectedErrno(err),
            }
        }
    }
}

pub const DnExpandError = error{InvalidDnsPacket};

pub fn dn_expand(
    msg: []const u8,
    comp_dn: []const u8,
    exp_dn: []u8,
) DnExpandError!usize {
    // This implementation is ported from musl libc.
    // A more idiomatic "ziggy" implementation would be welcome.
    var p = comp_dn.ptr;
    var len: usize = maxInt(usize);
    const end = msg.ptr + msg.len;
    if (p == end or exp_dn.len == 0) return error.InvalidDnsPacket;
    var dest = exp_dn.ptr;
    const dend = dest + @min(exp_dn.len, 254);
    // detect reference loop using an iteration counter
    var i: usize = 0;
    while (i < msg.len) : (i += 2) {
        // loop invariants: p<end, dest<dend
        if ((p[0] & 0xc0) != 0) {
            if (p + 1 == end) return error.InvalidDnsPacket;
            const j = @as(usize, p[0] & 0x3f) << 8 | p[1];
            if (len == maxInt(usize)) len = @intFromPtr(p) + 2 - @intFromPtr(comp_dn.ptr);
            if (j >= msg.len) return error.InvalidDnsPacket;
            p = msg.ptr + j;
        } else if (p[0] != 0) {
            if (dest != exp_dn.ptr) {
                dest[0] = '.';
                dest += 1;
            }
            var j = p[0];
            p += 1;
            if (j >= @intFromPtr(end) - @intFromPtr(p) or j >= @intFromPtr(dend) - @intFromPtr(dest)) {
                return error.InvalidDnsPacket;
            }
            while (j != 0) {
                j -= 1;
                dest[0] = p[0];
                dest += 1;
                p += 1;
            }
        } else {
            dest[0] = 0;
            if (len == maxInt(usize)) len = @intFromPtr(p) + 1 - @intFromPtr(comp_dn.ptr);
            return len;
        }
    }
    return error.InvalidDnsPacket;
}

pub const SetSockOptError = error{
    /// The socket is already connected, and a specified option cannot be set while the socket is connected.
    AlreadyConnected,

    /// The option is not supported by the protocol.
    InvalidProtocolOption,

    /// The send and receive timeout values are too big to fit into the timeout fields in the socket structure.
    TimeoutTooBig,

    /// Insufficient resources are available in the system to complete the call.
    SystemResources,

    /// Setting the socket option requires more elevated permissions.
    PermissionDenied,

    OperationNotSupported,
    NetworkSubsystemFailed,
    FileDescriptorNotASocket,
    SocketNotBound,
    NoDevice,
} || UnexpectedError;

/// Set a socket's options.
pub fn setsockopt(fd: socket_t, level: i32, optname: u32, opt: []const u8) SetSockOptError!void {
    if (native_os == .windows) {
        const rc = windows.ws2_32.setsockopt(fd, level, @intCast(optname), opt.ptr, @intCast(opt.len));
        if (rc == windows.ws2_32.SOCKET_ERROR) {
            switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAEFAULT => unreachable,
                .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                .WSAEINVAL => return error.SocketNotBound,
                else => |err| return windows.unexpectedWSAError(err),
            }
        }
        return;
    } else {
        switch (errno(system.setsockopt(fd, level, optname, opt.ptr, @intCast(opt.len)))) {
            .SUCCESS => {},
            .BADF => unreachable, // always a race condition
            .NOTSOCK => unreachable, // always a race condition
            .INVAL => unreachable,
            .FAULT => unreachable,
            .DOM => return error.TimeoutTooBig,
            .ISCONN => return error.AlreadyConnected,
            .NOPROTOOPT => return error.InvalidProtocolOption,
            .NOMEM => return error.SystemResources,
            .NOBUFS => return error.SystemResources,
            .PERM => return error.PermissionDenied,
            .NODEV => return error.NoDevice,
            .OPNOTSUPP => return error.OperationNotSupported,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const MemFdCreateError = error{
    SystemFdQuotaExceeded,
    ProcessFdQuotaExceeded,
    OutOfMemory,
    /// Either the name provided exceeded `NAME_MAX`, or invalid flags were passed.
    NameTooLong,
    SystemOutdated,
} || UnexpectedError;

pub fn memfd_createZ(name: [*:0]const u8, flags: u32) MemFdCreateError!fd_t {
    switch (native_os) {
        .linux => {
            // memfd_create is available only in glibc versions starting with 2.27.
            const use_c = std.c.versionCheck(.{ .major = 2, .minor = 27, .patch = 0 });
            const sys = if (use_c) std.c else linux;
            const rc = sys.memfd_create(name, flags);
            switch (errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .FAULT => unreachable, // name has invalid memory
                .INVAL => return error.NameTooLong, // or, program has a bug and flags are faulty
                .NFILE => return error.SystemFdQuotaExceeded,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NOMEM => return error.OutOfMemory,
                else => |err| return unexpectedErrno(err),
            }
        },
        .freebsd => {
            if (comptime builtin.os.version_range.semver.max.order(.{ .major = 13, .minor = 0, .patch = 0 }) == .lt)
                @compileError("memfd_create is unavailable on FreeBSD < 13.0");
            const rc = system.memfd_create(name, flags);
            switch (errno(rc)) {
                .SUCCESS => return rc,
                .BADF => unreachable, // name argument NULL
                .INVAL => unreachable, // name too long or invalid/unsupported flags.
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NOSYS => return error.SystemOutdated,
                else => |err| return unexpectedErrno(err),
            }
        },
        else => @compileError("target OS does not support memfd_create()"),
    }
}

pub fn memfd_create(name: []const u8, flags: u32) MemFdCreateError!fd_t {
    var buffer: [NAME_MAX - "memfd:".len - 1:0]u8 = undefined;
    if (name.len > buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    return memfd_createZ(&buffer, flags);
}

pub fn getrusage(who: i32) rusage {
    var result: rusage = undefined;
    const rc = system.getrusage(who, &result);
    switch (errno(rc)) {
        .SUCCESS => return result,
        .INVAL => unreachable,
        .FAULT => unreachable,
        else => unreachable,
    }
}

pub const TIOCError = error{NotATerminal};

pub const TermiosGetError = TIOCError || UnexpectedError;

pub fn tcgetattr(handle: fd_t) TermiosGetError!termios {
    while (true) {
        var term: termios = undefined;
        switch (errno(system.tcgetattr(handle, &term))) {
            .SUCCESS => return term,
            .INTR => continue,
            .BADF => unreachable,
            .NOTTY => return error.NotATerminal,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const TermiosSetError = TermiosGetError || error{ProcessOrphaned};

pub fn tcsetattr(handle: fd_t, optional_action: TCSA, termios_p: termios) TermiosSetError!void {
    while (true) {
        switch (errno(system.tcsetattr(handle, optional_action, &termios_p))) {
            .SUCCESS => return,
            .BADF => unreachable,
            .INTR => continue,
            .INVAL => unreachable,
            .NOTTY => return error.NotATerminal,
            .IO => return error.ProcessOrphaned,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const TermioGetPgrpError = TIOCError || UnexpectedError;

/// Returns the process group ID for the TTY associated with the given handle.
pub fn tcgetpgrp(handle: fd_t) TermioGetPgrpError!pid_t {
    while (true) {
        var pgrp: pid_t = undefined;
        switch (errno(system.tcgetpgrp(handle, &pgrp))) {
            .SUCCESS => return pgrp,
            .BADF => unreachable,
            .INVAL => unreachable,
            .INTR => continue,
            .NOTTY => return error.NotATerminal,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const TermioSetPgrpError = TermioGetPgrpError || error{NotAPgrpMember};

/// Sets the controlling process group ID for given TTY.
/// handle must be valid fd_t to a TTY associated with calling process.
/// pgrp must be a valid process group, and the calling process must be a member
/// of that group.
pub fn tcsetpgrp(handle: fd_t, pgrp: pid_t) TermioSetPgrpError!void {
    while (true) {
        switch (errno(system.tcsetpgrp(handle, &pgrp))) {
            .SUCCESS => return,
            .BADF => unreachable,
            .INVAL => unreachable,
            .INTR => continue,
            .NOTTY => return error.NotATerminal,
            .PERM => return TermioSetPgrpError.NotAPgrpMember,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub fn signalfd(fd: fd_t, mask: *const sigset_t, flags: u32) !fd_t {
    const rc = system.signalfd(fd, mask, flags);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .BADF, .INVAL => unreachable,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        .MFILE => return error.ProcessResources,
        .NODEV => return error.InodeMountFail,
        else => |err| return unexpectedErrno(err),
    }
}

pub const SyncError = error{
    InputOutput,
    NoSpaceLeft,
    DiskQuota,
    AccessDenied,
} || UnexpectedError;

/// Write all pending file contents and metadata modifications to all filesystems.
pub fn sync() void {
    system.sync();
}

/// Write all pending file contents and metadata modifications to the filesystem which contains the specified file.
pub fn syncfs(fd: fd_t) SyncError!void {
    const rc = system.syncfs(fd);
    switch (errno(rc)) {
        .SUCCESS => return,
        .BADF, .INVAL, .ROFS => unreachable,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .DQUOT => return error.DiskQuota,
        else => |err| return unexpectedErrno(err),
    }
}

/// Write all pending file contents and metadata modifications for the specified file descriptor to the underlying filesystem.
pub fn fsync(fd: fd_t) SyncError!void {
    if (native_os == .windows) {
        if (windows.kernel32.FlushFileBuffers(fd) != 0)
            return;
        switch (windows.GetLastError()) {
            .SUCCESS => return,
            .INVALID_HANDLE => unreachable,
            .ACCESS_DENIED => return error.AccessDenied, // a sync was performed but the system couldn't update the access time
            .UNEXP_NET_ERR => return error.InputOutput,
            else => return error.InputOutput,
        }
    }
    const rc = system.fsync(fd);
    switch (errno(rc)) {
        .SUCCESS => return,
        .BADF, .INVAL, .ROFS => unreachable,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .DQUOT => return error.DiskQuota,
        else => |err| return unexpectedErrno(err),
    }
}

/// Write all pending file contents for the specified file descriptor to the underlying filesystem, but not necessarily the metadata.
pub fn fdatasync(fd: fd_t) SyncError!void {
    if (native_os == .windows) {
        return fsync(fd) catch |err| switch (err) {
            SyncError.AccessDenied => return, // fdatasync doesn't promise that the access time was synced
            else => return err,
        };
    }
    const rc = system.fdatasync(fd);
    switch (errno(rc)) {
        .SUCCESS => return,
        .BADF, .INVAL, .ROFS => unreachable,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .DQUOT => return error.DiskQuota,
        else => |err| return unexpectedErrno(err),
    }
}

pub const PrctlError = error{
    /// Can only occur with PR_SET_SECCOMP/SECCOMP_MODE_FILTER or
    /// PR_SET_MM/PR_SET_MM_EXE_FILE
    AccessDenied,
    /// Can only occur with PR_SET_MM/PR_SET_MM_EXE_FILE
    InvalidFileDescriptor,
    InvalidAddress,
    /// Can only occur with PR_SET_SPECULATION_CTRL, PR_MPX_ENABLE_MANAGEMENT,
    /// or PR_MPX_DISABLE_MANAGEMENT
    UnsupportedFeature,
    /// Can only occur with PR_SET_FP_MODE
    OperationNotSupported,
    PermissionDenied,
} || UnexpectedError;

pub fn prctl(option: PR, args: anytype) PrctlError!u31 {
    if (@typeInfo(@TypeOf(args)) != .@"struct")
        @compileError("Expected tuple or struct argument, found " ++ @typeName(@TypeOf(args)));
    if (args.len > 4)
        @compileError("prctl takes a maximum of 4 optional arguments");

    var buf: [4]usize = undefined;
    {
        comptime var i = 0;
        inline while (i < args.len) : (i += 1) buf[i] = args[i];
    }

    const rc = system.prctl(@intFromEnum(option), buf[0], buf[1], buf[2], buf[3]);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .BADF => return error.InvalidFileDescriptor,
        .FAULT => return error.InvalidAddress,
        .INVAL => unreachable,
        .NODEV, .NXIO => return error.UnsupportedFeature,
        .OPNOTSUPP => return error.OperationNotSupported,
        .PERM, .BUSY => return error.PermissionDenied,
        .RANGE => unreachable,
        else => |err| return unexpectedErrno(err),
    }
}

pub const GetrlimitError = UnexpectedError;

pub fn getrlimit(resource: rlimit_resource) GetrlimitError!rlimit {
    const getrlimit_sym = if (lfs64_abi) system.getrlimit64 else system.getrlimit;

    var limits: rlimit = undefined;
    switch (errno(getrlimit_sym(resource, &limits))) {
        .SUCCESS => return limits,
        .FAULT => unreachable, // bogus pointer
        .INVAL => unreachable,
        else => |err| return unexpectedErrno(err),
    }
}

pub const SetrlimitError = error{ PermissionDenied, LimitTooBig } || UnexpectedError;

pub fn setrlimit(resource: rlimit_resource, limits: rlimit) SetrlimitError!void {
    const setrlimit_sym = if (lfs64_abi) system.setrlimit64 else system.setrlimit;

    switch (errno(setrlimit_sym(resource, &limits))) {
        .SUCCESS => return,
        .FAULT => unreachable, // bogus pointer
        .INVAL => return error.LimitTooBig, // this could also mean "invalid resource", but that would be unreachable
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub const MincoreError = error{
    /// A kernel resource was temporarily unavailable.
    SystemResources,
    /// vec points to an invalid address.
    InvalidAddress,
    /// addr is not page-aligned.
    InvalidSyscall,
    /// One of the following:
    /// * length is greater than user space TASK_SIZE - addr
    /// * addr + length contains unmapped memory
    OutOfMemory,
    /// The mincore syscall is not available on this version and configuration
    /// of this UNIX-like kernel.
    MincoreUnavailable,
} || UnexpectedError;

/// Determine whether pages are resident in memory.
pub fn mincore(ptr: [*]align(page_size_min) u8, length: usize, vec: [*]u8) MincoreError!void {
    return switch (errno(system.mincore(ptr, length, vec))) {
        .SUCCESS => {},
        .AGAIN => error.SystemResources,
        .FAULT => error.InvalidAddress,
        .INVAL => error.InvalidSyscall,
        .NOMEM => error.OutOfMemory,
        .NOSYS => error.MincoreUnavailable,
        else => |err| unexpectedErrno(err),
    };
}

pub const MadviseError = error{
    /// advice is MADV.REMOVE, but the specified address range is not a shared writable mapping.
    AccessDenied,
    /// advice is MADV.HWPOISON, but the caller does not have the CAP_SYS_ADMIN capability.
    PermissionDenied,
    /// A kernel resource was temporarily unavailable.
    SystemResources,
    /// One of the following:
    /// * addr is not page-aligned or length is negative
    /// * advice is not valid
    /// * advice is MADV.DONTNEED or MADV.REMOVE and the specified address range
    ///   includes locked, Huge TLB pages, or VM_PFNMAP pages.
    /// * advice is MADV.MERGEABLE or MADV.UNMERGEABLE, but the kernel was not
    ///   configured with CONFIG_KSM.
    /// * advice is MADV.FREE or MADV.WIPEONFORK but the specified address range
    ///   includes file, Huge TLB, MAP.SHARED, or VM_PFNMAP ranges.
    InvalidSyscall,
    /// (for MADV.WILLNEED) Paging in this area would exceed the process's
    /// maximum resident set size.
    WouldExceedMaximumResidentSetSize,
    /// One of the following:
    /// * (for MADV.WILLNEED) Not enough memory: paging in failed.
    /// * Addresses in the specified range are not currently mapped, or
    ///   are outside the address space of the process.
    OutOfMemory,
    /// The madvise syscall is not available on this version and configuration
    /// of the Linux kernel.
    MadviseUnavailable,
    /// The operating system returned an undocumented error code.
    Unexpected,
};

/// Give advice about use of memory.
/// This syscall is optional and is sometimes configured to be disabled.
pub fn madvise(ptr: [*]align(page_size_min) u8, length: usize, advice: u32) MadviseError!void {
    switch (errno(system.madvise(ptr, length, advice))) {
        .SUCCESS => return,
        .PERM => return error.PermissionDenied,
        .ACCES => return error.AccessDenied,
        .AGAIN => return error.SystemResources,
        .BADF => unreachable, // The map exists, but the area maps something that isn't a file.
        .INVAL => return error.InvalidSyscall,
        .IO => return error.WouldExceedMaximumResidentSetSize,
        .NOMEM => return error.OutOfMemory,
        .NOSYS => return error.MadviseUnavailable,
        else => |err| return unexpectedErrno(err),
    }
}

pub const PerfEventOpenError = error{
    /// Returned if the perf_event_attr size value is too small (smaller
    /// than PERF_ATTR_SIZE_VER0), too big (larger than the page  size),
    /// or  larger  than the kernel supports and the extra bytes are not
    /// zero.  When E2BIG is returned, the perf_event_attr size field is
    /// overwritten by the kernel to be the size of the structure it was
    /// expecting.
    TooBig,
    /// Returned when the requested event requires CAP_SYS_ADMIN permis‐
    /// sions  (or a more permissive perf_event paranoid setting).  Some
    /// common cases where an unprivileged process  may  encounter  this
    /// error:  attaching  to a process owned by a different user; moni‐
    /// toring all processes on a given CPU (i.e.,  specifying  the  pid
    /// argument  as  -1); and not setting exclude_kernel when the para‐
    /// noid setting requires it.
    /// Also:
    /// Returned on many (but not all) architectures when an unsupported
    /// exclude_hv,  exclude_idle,  exclude_user, or exclude_kernel set‐
    /// ting is specified.
    /// It can also happen, as with EACCES, when the requested event re‐
    /// quires   CAP_SYS_ADMIN   permissions   (or   a  more  permissive
    /// perf_event paranoid setting).  This includes  setting  a  break‐
    /// point on a kernel address, and (since Linux 3.13) setting a ker‐
    /// nel function-trace tracepoint.
    PermissionDenied,
    /// Returned if another event already has exclusive  access  to  the
    /// PMU.
    DeviceBusy,
    /// Each  opened  event uses one file descriptor.  If a large number
    /// of events are opened, the per-process limit  on  the  number  of
    /// open file descriptors will be reached, and no more events can be
    /// created.
    ProcessResources,
    EventRequiresUnsupportedCpuFeature,
    /// Returned if  you  try  to  add  more  breakpoint
    /// events than supported by the hardware.
    TooManyBreakpoints,
    /// Returned  if PERF_SAMPLE_STACK_USER is set in sample_type and it
    /// is not supported by hardware.
    SampleStackNotSupported,
    /// Returned if an event requiring a specific  hardware  feature  is
    /// requested  but  there is no hardware support.  This includes re‐
    /// questing low-skid events if not supported, branch tracing if  it
    /// is not available, sampling if no PMU interrupt is available, and
    /// branch stacks for software events.
    EventNotSupported,
    /// Returned  if  PERF_SAMPLE_CALLCHAIN  is   requested   and   sam‐
    /// ple_max_stack   is   larger   than   the  maximum  specified  in
    /// /proc/sys/kernel/perf_event_max_stack.
    SampleMaxStackOverflow,
    /// Returned if attempting to attach to a process that does not  exist.
    ProcessNotFound,
} || UnexpectedError;

pub fn perf_event_open(
    attr: *system.perf_event_attr,
    pid: pid_t,
    cpu: i32,
    group_fd: fd_t,
    flags: usize,
) PerfEventOpenError!fd_t {
    if (native_os == .linux) {
        // There is no syscall wrapper for this function exposed by libcs
        const rc = linux.perf_event_open(attr, pid, cpu, group_fd, flags);
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .@"2BIG" => return error.TooBig,
            .ACCES => return error.PermissionDenied,
            .BADF => unreachable, // group_fd file descriptor is not valid.
            .BUSY => return error.DeviceBusy,
            .FAULT => unreachable, // Segmentation fault.
            .INVAL => unreachable, // Bad attr settings.
            .INTR => unreachable, // Mixed perf and ftrace handling for a uprobe.
            .MFILE => return error.ProcessResources,
            .NODEV => return error.EventRequiresUnsupportedCpuFeature,
            .NOENT => unreachable, // Invalid type setting.
            .NOSPC => return error.TooManyBreakpoints,
            .NOSYS => return error.SampleStackNotSupported,
            .OPNOTSUPP => return error.EventNotSupported,
            .OVERFLOW => return error.SampleMaxStackOverflow,
            .PERM => return error.PermissionDenied,
            .SRCH => return error.ProcessNotFound,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const TimerFdCreateError = error{
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    NoDevice,
    SystemResources,
} || UnexpectedError;

pub const TimerFdGetError = error{InvalidHandle} || UnexpectedError;
pub const TimerFdSetError = TimerFdGetError || error{Canceled};

pub fn timerfd_create(clock_id: system.timerfd_clockid_t, flags: system.TFD) TimerFdCreateError!fd_t {
    const rc = system.timerfd_create(clock_id, @bitCast(flags));
    return switch (errno(rc)) {
        .SUCCESS => @intCast(rc),
        .INVAL => unreachable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NODEV => return error.NoDevice,
        .NOMEM => return error.SystemResources,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    };
}

pub fn timerfd_settime(
    fd: i32,
    flags: system.TFD.TIMER,
    new_value: *const system.itimerspec,
    old_value: ?*system.itimerspec,
) TimerFdSetError!void {
    const rc = system.timerfd_settime(fd, @bitCast(flags), new_value, old_value);
    return switch (errno(rc)) {
        .SUCCESS => {},
        .BADF => error.InvalidHandle,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .CANCELED => error.Canceled,
        else => |err| return unexpectedErrno(err),
    };
}

pub fn timerfd_gettime(fd: i32) TimerFdGetError!system.itimerspec {
    var curr_value: system.itimerspec = undefined;
    const rc = system.timerfd_gettime(fd, &curr_value);
    return switch (errno(rc)) {
        .SUCCESS => return curr_value,
        .BADF => error.InvalidHandle,
        .FAULT => unreachable,
        .INVAL => unreachable,
        else => |err| return unexpectedErrno(err),
    };
}

pub const PtraceError = error{
    DeviceBusy,
    InputOutput,
    ProcessNotFound,
    PermissionDenied,
} || UnexpectedError;

pub fn ptrace(request: u32, pid: pid_t, addr: usize, signal: usize) PtraceError!void {
    if (native_os == .windows or native_os == .wasi)
        @compileError("Unsupported OS");

    return switch (native_os) {
        .linux => switch (errno(linux.ptrace(request, pid, addr, signal, 0))) {
            .SUCCESS => {},
            .SRCH => error.ProcessNotFound,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .IO => return error.InputOutput,
            .PERM => error.PermissionDenied,
            .BUSY => error.DeviceBusy,
            else => |err| return unexpectedErrno(err),
        },

        .macos, .ios, .tvos, .watchos, .visionos => switch (errno(std.c.ptrace(
            @intCast(request),
            pid,
            @ptrFromInt(addr),
            @intCast(signal),
        ))) {
            .SUCCESS => {},
            .SRCH => error.ProcessNotFound,
            .INVAL => unreachable,
            .PERM => error.PermissionDenied,
            .BUSY => error.DeviceBusy,
            else => |err| return unexpectedErrno(err),
        },

        else => switch (errno(system.ptrace(request, pid, addr, signal))) {
            .SUCCESS => {},
            .SRCH => error.ProcessNotFound,
            .INVAL => unreachable,
            .PERM => error.PermissionDenied,
            .BUSY => error.DeviceBusy,
            else => |err| return unexpectedErrno(err),
        },
    };
}

pub const NameToFileHandleAtError = error{
    FileNotFound,
    NotDir,
    OperationNotSupported,
    NameTooLong,
    Unexpected,
};

pub fn name_to_handle_at(
    dirfd: fd_t,
    pathname: []const u8,
    handle: *std.os.linux.file_handle,
    mount_id: *i32,
    flags: u32,
) NameToFileHandleAtError!void {
    const pathname_c = try toPosixPath(pathname);
    return name_to_handle_atZ(dirfd, &pathname_c, handle, mount_id, flags);
}

pub fn name_to_handle_atZ(
    dirfd: fd_t,
    pathname_z: [*:0]const u8,
    handle: *std.os.linux.file_handle,
    mount_id: *i32,
    flags: u32,
) NameToFileHandleAtError!void {
    switch (errno(system.name_to_handle_at(dirfd, pathname_z, handle, mount_id, flags))) {
        .SUCCESS => {},
        .FAULT => unreachable, // pathname, mount_id, or handle outside accessible address space
        .INVAL => unreachable, // bad flags, or handle_bytes too big
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .OPNOTSUPP => return error.OperationNotSupported,
        .OVERFLOW => return error.NameTooLong,
        else => |err| return unexpectedErrno(err),
    }
}

pub const IoCtl_SIOCGIFINDEX_Error = error{
    FileSystem,
    InterfaceNotFound,
} || UnexpectedError;

pub fn ioctl_SIOCGIFINDEX(fd: fd_t, ifr: *ifreq) IoCtl_SIOCGIFINDEX_Error!void {
    while (true) {
        switch (errno(system.ioctl(fd, SIOCGIFINDEX, @intFromPtr(ifr)))) {
            .SUCCESS => return,
            .INVAL => unreachable, // Bad parameters.
            .NOTTY => unreachable,
            .NXIO => unreachable,
            .BADF => unreachable, // Always a race condition.
            .FAULT => unreachable, // Bad pointer parameter.
            .INTR => continue,
            .IO => return error.FileSystem,
            .NODEV => return error.InterfaceNotFound,
            else => |err| return unexpectedErrno(err),
        }
    }
}

const lfs64_abi = native_os == .linux and builtin.link_libc and (builtin.abi.isGnu() or builtin.abi.isAndroid());

/// Whether or not `error.Unexpected` will print its value and a stack trace.
///
/// If this happens the fix is to add the error code to the corresponding
/// switch expression, possibly introduce a new error in the error set, and
/// send a patch to Zig.
pub const unexpected_error_tracing = builtin.zig_backend == .stage2_llvm and builtin.mode == .Debug;

pub const UnexpectedError = error{
    /// The Operating System returned an undocumented error code.
    ///
    /// This error is in theory not possible, but it would be better
    /// to handle this error than to invoke undefined behavior.
    ///
    /// When this error code is observed, it usually means the Zig Standard
    /// Library needs a small patch to add the error code to the error set for
    /// the respective function.
    Unexpected,
};

/// Call this when you made a syscall or something that sets errno
/// and you get an unexpected error.
pub fn unexpectedErrno(err: E) UnexpectedError {
    if (unexpected_error_tracing) {
        std.debug.print("unexpected errno: {d}\n", .{@intFromEnum(err)});
        std.debug.dumpCurrentStackTrace(null);
    }
    return error.Unexpected;
}

/// Used to convert a slice to a null terminated slice on the stack.
pub fn toPosixPath(file_path: []const u8) error{NameTooLong}![PATH_MAX - 1:0]u8 {
    if (std.debug.runtime_safety) assert(mem.indexOfScalar(u8, file_path, 0) == null);
    var path_with_null: [PATH_MAX - 1:0]u8 = undefined;
    // >= rather than > to make room for the null byte
    if (file_path.len >= PATH_MAX) return error.NameTooLong;
    @memcpy(path_with_null[0..file_path.len], file_path);
    path_with_null[file_path.len] = 0;
    return path_with_null;
}
const std = @import("../std.zig");
const posix = std.posix;
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectError = testing.expectError;
const io = std.io;
const fs = std.fs;
const mem = std.mem;
const elf = std.elf;
const Thread = std.Thread;
const linux = std.os.linux;

const a = std.testing.allocator;

const builtin = @import("builtin");
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const AtomicOrder = std.builtin.AtomicOrder;
const native_os = builtin.target.os.tag;
const tmpDir = std.testing.tmpDir;

// https://github.com/ziglang/zig/issues/20288
test "WTF-8 to WTF-16 conversion buffer overflows" {
    if (native_os != .windows) return error.SkipZigTest;

    const input_wtf8 = "\u{10FFFF}" ** 16385;
    try expectError(error.NameTooLong, posix.chdir(input_wtf8));
    try expectError(error.NameTooLong, posix.chdirZ(input_wtf8));
}

test "check WASI CWD" {
    if (native_os == .wasi) {
        if (std.options.wasiCwd() != 3) {
            @panic("WASI code that uses cwd (like this test) needs a preopen for cwd (add '--dir=.' to wasmtime)");
        }

        if (!builtin.link_libc) {
            // WASI without-libc hardcodes fd 3 as the FDCWD token so it can be passed directly to WASI calls
            try expectEqual(3, posix.AT.FDCWD);
        }
    }
}

test "chdir absolute parent" {
    if (native_os == .wasi) return error.SkipZigTest;

    // Restore default CWD at end of test.
    const orig_cwd = try fs.cwd().openDir(".", .{});
    defer orig_cwd.setAsCwd() catch unreachable;

    // Get current working directory path
    var old_cwd_buf: [fs.max_path_bytes]u8 = undefined;
    const old_cwd = try posix.getcwd(old_cwd_buf[0..]);

    {
        // Firstly, changing to itself should have no effect
        try posix.chdir(old_cwd);
        var new_cwd_buf: [fs.max_path_bytes]u8 = undefined;
        const new_cwd = try posix.getcwd(new_cwd_buf[0..]);
        try expect(mem.eql(u8, old_cwd, new_cwd));
    }

    // Next, change current working directory to one level above
    const parent = fs.path.dirname(old_cwd) orelse unreachable; // old_cwd should be absolute
    try posix.chdir(parent);

    var new_cwd_buf: [fs.max_path_bytes]u8 = undefined;
    const new_cwd = try posix.getcwd(new_cwd_buf[0..]);
    try expect(mem.eql(u8, parent, new_cwd));
}

test "chdir relative" {
    if (native_os == .wasi) return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // Restore default CWD at end of test.
    const orig_cwd = try fs.cwd().openDir(".", .{});
    defer orig_cwd.setAsCwd() catch unreachable;

    // Use the tmpDir parent_dir as the "base" for the test. Then cd into the child
    try tmp.parent_dir.setAsCwd();

    // Capture base working directory path, to build expected full path
    var base_cwd_buf: [fs.max_path_bytes]u8 = undefined;
    const base_cwd = try posix.getcwd(base_cwd_buf[0..]);

    const dir_name = &tmp.sub_path;
    const expected_path = try fs.path.resolve(a, &.{ base_cwd, dir_name });
    defer a.free(expected_path);

    // change current working directory to new directory
    try posix.chdir(dir_name);

    var new_cwd_buf: [fs.max_path_bytes]u8 = undefined;
    const new_cwd = try posix.getcwd(new_cwd_buf[0..]);

    // On Windows, fs.path.resolve returns an uppercase drive letter, but the drive letter returned by getcwd may be lowercase
    const resolved_cwd = try fs.path.resolve(a, &.{new_cwd});
    defer a.free(resolved_cwd);

    try expect(mem.eql(u8, expected_path, resolved_cwd));
}

test "open smoke test" {
    if (native_os == .wasi) return error.SkipZigTest;
    if (native_os == .windows) return error.SkipZigTest;

    // TODO verify file attributes using `fstat`

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const base_path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(base_path);

    const mode: posix.mode_t = if (native_os == .windows) 0 else 0o666;

    {
        // Create some file using `open`.
        const file_path = try fs.path.join(a, &.{ base_path, "some_file" });
        defer a.free(file_path);
        const fd = try posix.open(file_path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true }, mode);
        posix.close(fd);
    }

    {
        // Try this again with the same flags. This op should fail with error.PathAlreadyExists.
        const file_path = try fs.path.join(a, &.{ base_path, "some_file" });
        defer a.free(file_path);
        try expectError(error.PathAlreadyExists, posix.open(file_path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true }, mode));
    }

    {
        // Try opening without `EXCL` flag.
        const file_path = try fs.path.join(a, &.{ base_path, "some_file" });
        defer a.free(file_path);
        const fd = try posix.open(file_path, .{ .ACCMODE = .RDWR, .CREAT = true }, mode);
        posix.close(fd);
    }

    {
        // Try opening as a directory which should fail.
        const file_path = try fs.path.join(a, &.{ base_path, "some_file" });
        defer a.free(file_path);
        try expectError(error.NotDir, posix.open(file_path, .{ .ACCMODE = .RDWR, .DIRECTORY = true }, mode));
    }

    {
        // Create some directory
        const file_path = try fs.path.join(a, &.{ base_path, "some_dir" });
        defer a.free(file_path);
        try posix.mkdir(file_path, mode);
    }

    {
        // Open dir using `open`
        const file_path = try fs.path.join(a, &.{ base_path, "some_dir" });
        defer a.free(file_path);
        const fd = try posix.open(file_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, mode);
        posix.close(fd);
    }

    {
        // Try opening as file which should fail.
        const file_path = try fs.path.join(a, &.{ base_path, "some_dir" });
        defer a.free(file_path);
        try expectError(error.IsDir, posix.open(file_path, .{ .ACCMODE = .RDWR }, mode));
    }
}

test "openat smoke test" {
    if (native_os == .windows) return error.SkipZigTest;

    // TODO verify file attributes using `fstatat`

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var fd: posix.fd_t = undefined;
    const mode: posix.mode_t = if (native_os == .windows) 0 else 0o666;

    // Create some file using `openat`.
    fd = try posix.openat(tmp.dir.fd, "some_file", CommonOpenFlags.lower(.{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .EXCL = true,
    }), mode);
    posix.close(fd);

    // Try this again with the same flags. This op should fail with error.PathAlreadyExists.
    try expectError(error.PathAlreadyExists, posix.openat(tmp.dir.fd, "some_file", CommonOpenFlags.lower(.{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .EXCL = true,
    }), mode));

    // Try opening without `EXCL` flag.
    fd = try posix.openat(tmp.dir.fd, "some_file", CommonOpenFlags.lower(.{
        .ACCMODE = .RDWR,
        .CREAT = true,
    }), mode);
    posix.close(fd);

    // Try opening as a directory which should fail.
    try expectError(error.NotDir, posix.openat(tmp.dir.fd, "some_file", CommonOpenFlags.lower(.{
        .ACCMODE = .RDWR,
        .DIRECTORY = true,
    }), mode));

    // Create some directory
    try posix.mkdirat(tmp.dir.fd, "some_dir", mode);

    // Open dir using `open`
    fd = try posix.openat(tmp.dir.fd, "some_dir", CommonOpenFlags.lower(.{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
    }), mode);
    posix.close(fd);

    // Try opening as file which should fail (skip on wasi+libc due to
    // https://github.com/bytecodealliance/wasmtime/issues/9054)
    if (native_os != .wasi or !builtin.link_libc) {
        try expectError(error.IsDir, posix.openat(tmp.dir.fd, "some_dir", CommonOpenFlags.lower(.{
            .ACCMODE = .RDWR,
        }), mode));
    }
}

test "symlink with relative paths" {
    if (native_os == .wasi) return error.SkipZigTest; // Can symlink, but can't change into tmpDir

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const target_name = "symlink-target";
    const symlink_name = "symlinker";

    // Restore default CWD at end of test.
    const orig_cwd = try fs.cwd().openDir(".", .{});
    defer orig_cwd.setAsCwd() catch unreachable;

    // Create the target file
    try tmp.dir.writeFile(.{ .sub_path = target_name, .data = "nonsense" });

    // Want to test relative paths, so cd into the tmpdir for this test
    try tmp.dir.setAsCwd();

    if (native_os == .windows) {
        const wtarget_name = try std.unicode.wtf8ToWtf16LeAllocZ(a, target_name);
        const wsymlink_name = try std.unicode.wtf8ToWtf16LeAllocZ(a, symlink_name);
        defer a.free(wtarget_name);
        defer a.free(wsymlink_name);

        std.os.windows.CreateSymbolicLink(tmp.dir.fd, wsymlink_name, wtarget_name, false) catch |err| switch (err) {
            // Symlink requires admin privileges on windows, so this test can legitimately fail.
            error.AccessDenied => return error.SkipZigTest,
            else => return err,
        };
    } else {
        try posix.symlink(target_name, symlink_name);
    }

    var buffer: [fs.max_path_bytes]u8 = undefined;
    const given = try posix.readlink(symlink_name, buffer[0..]);
    try expect(mem.eql(u8, target_name, given));
}

test "readlink on Windows" {
    if (native_os != .windows) return error.SkipZigTest;

    try testReadlink("C:\\ProgramData", "C:\\Users\\All Users");
    try testReadlink("C:\\Users\\Default", "C:\\Users\\Default User");
    try testReadlink("C:\\Users", "C:\\Documents and Settings");
}

fn testReadlink(target_path: []const u8, symlink_path: []const u8) !void {
    var buffer: [fs.max_path_bytes]u8 = undefined;
    const given = try posix.readlink(symlink_path, buffer[0..]);
    try expect(mem.eql(u8, target_path, given));
}

test "link with relative paths" {
    if (native_os == .wasi) return error.SkipZigTest; // Can link, but can't change into tmpDir
    if ((builtin.cpu.arch == .riscv32 or builtin.cpu.arch.isLoongArch()) and builtin.os.tag == .linux and !builtin.link_libc) return error.SkipZigTest; // No `fstat()`.
    if (builtin.cpu.arch.isMIPS64()) return error.SkipZigTest; // `nstat.nlink` assertion is failing with LLVM 20+ for unclear reasons.

    switch (native_os) {
        .wasi, .linux, .solaris, .illumos => {},
        else => return error.SkipZigTest,
    }

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // Restore default CWD at end of test.
    const orig_cwd = try fs.cwd().openDir(".", .{});
    defer orig_cwd.setAsCwd() catch unreachable;

    const target_name = "link-target";
    const link_name = "newlink";

    try tmp.dir.writeFile(.{ .sub_path = target_name, .data = "example" });

    // Test 1: create the relative link from inside tmp
    try tmp.dir.setAsCwd();
    try posix.link(target_name, link_name);

    // Verify
    const efd = try tmp.dir.openFile(target_name, .{});
    defer efd.close();

    const nfd = try tmp.dir.openFile(link_name, .{});
    defer nfd.close();

    {
        const estat = try posix.fstat(efd.handle);
        const nstat = try posix.fstat(nfd.handle);
        try testing.expectEqual(estat.ino, nstat.ino);
        try testing.expectEqual(@as(@TypeOf(nstat.nlink), 2), nstat.nlink);
    }

    // Test 2: Remove the link and see the stats update
    try posix.unlink(link_name);

    {
        const estat = try posix.fstat(efd.handle);
        try testing.expectEqual(@as(@TypeOf(estat.nlink), 1), estat.nlink);
    }
}

test "linkat with different directories" {
    if ((builtin.cpu.arch == .riscv32 or builtin.cpu.arch.isLoongArch()) and builtin.os.tag == .linux and !builtin.link_libc) return error.SkipZigTest; // No `fstatat()`.
    if (builtin.cpu.arch.isMIPS64()) return error.SkipZigTest; // `nstat.nlink` assertion is failing with LLVM 20+ for unclear reasons.

    switch (native_os) {
        .wasi, .linux, .solaris, .illumos => {},
        else => return error.SkipZigTest,
    }

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const target_name = "link-target";
    const link_name = "newlink";

    const subdir = try tmp.dir.makeOpenPath("subdir", .{});

    defer tmp.dir.deleteFile(target_name) catch {};
    try tmp.dir.writeFile(.{ .sub_path = target_name, .data = "example" });

    // Test 1: link from file in subdir back up to target in parent directory
    try posix.linkat(tmp.dir.fd, target_name, subdir.fd, link_name, 0);

    const efd = try tmp.dir.openFile(target_name, .{});
    defer efd.close();

    const nfd = try subdir.openFile(link_name, .{});
    defer nfd.close();

    {
        const estat = try posix.fstat(efd.handle);
        const nstat = try posix.fstat(nfd.handle);
        try testing.expectEqual(estat.ino, nstat.ino);
        try testing.expectEqual(@as(@TypeOf(nstat.nlink), 2), nstat.nlink);
    }

    // Test 2: remove link
    try posix.unlinkat(subdir.fd, link_name, 0);

    {
        const estat = try posix.fstat(efd.handle);
        try testing.expectEqual(@as(@TypeOf(estat.nlink), 1), estat.nlink);
    }
}

test "fstatat" {
    if ((builtin.cpu.arch == .riscv32 or builtin.cpu.arch.isLoongArch()) and builtin.os.tag == .linux and !builtin.link_libc) return error.SkipZigTest; // No `fstatat()`.
    // enable when `fstat` and `fstatat` are implemented on Windows
    if (native_os == .windows) return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // create dummy file
    const contents = "nonsense";
    try tmp.dir.writeFile(.{ .sub_path = "file.txt", .data = contents });

    // fetch file's info on the opened fd directly
    const file = try tmp.dir.openFile("file.txt", .{});
    const stat = try posix.fstat(file.handle);
    defer file.close();

    // now repeat but using `fstatat` instead
    const statat = try posix.fstatat(tmp.dir.fd, "file.txt", posix.AT.SYMLINK_NOFOLLOW);

    // s390x-linux does not have nanosecond precision for fstat(), but it does for fstatat(). As a
    // result, comparing the two structures is doomed to fail.
    if (builtin.cpu.arch == .s390x and builtin.os.tag == .linux) return error.SkipZigTest;

    try expectEqual(stat, statat);
}

test "readlinkat" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // create file
    try tmp.dir.writeFile(.{ .sub_path = "file.txt", .data = "nonsense" });

    // create a symbolic link
    if (native_os == .windows) {
        std.os.windows.CreateSymbolicLink(
            tmp.dir.fd,
            &[_]u16{ 'l', 'i', 'n', 'k' },
            &[_:0]u16{ 'f', 'i', 'l', 'e', '.', 't', 'x', 't' },
            false,
        ) catch |err| switch (err) {
            // Symlink requires admin privileges on windows, so this test can legitimately fail.
            error.AccessDenied => return error.SkipZigTest,
            else => return err,
        };
    } else {
        try posix.symlinkat("file.txt", tmp.dir.fd, "link");
    }

    // read the link
    var buffer: [fs.max_path_bytes]u8 = undefined;
    const read_link = try posix.readlinkat(tmp.dir.fd, "link", buffer[0..]);
    try expect(mem.eql(u8, "file.txt", read_link));
}

fn testThreadIdFn(thread_id: *Thread.Id) void {
    thread_id.* = Thread.getCurrentId();
}

test "Thread.getCurrentId" {
    if (builtin.single_threaded) return error.SkipZigTest;

    var thread_current_id: Thread.Id = undefined;
    const thread = try Thread.spawn(.{}, testThreadIdFn, .{&thread_current_id});
    thread.join();
    try expect(Thread.getCurrentId() != thread_current_id);
}

test "spawn threads" {
    if (builtin.single_threaded) return error.SkipZigTest;

    var shared_ctx: i32 = 1;

    const thread1 = try Thread.spawn(.{}, start1, .{});
    const thread2 = try Thread.spawn(.{}, start2, .{&shared_ctx});
    const thread3 = try Thread.spawn(.{}, start2, .{&shared_ctx});
    const thread4 = try Thread.spawn(.{}, start2, .{&shared_ctx});

    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();

    try expect(shared_ctx == 4);
}

fn start1() u8 {
    return 0;
}

fn start2(ctx: *i32) u8 {
    _ = @atomicRmw(i32, ctx, AtomicRmwOp.Add, 1, AtomicOrder.seq_cst);
    return 0;
}

test "cpu count" {
    if (native_os == .wasi) return error.SkipZigTest;

    const cpu_count = try Thread.getCpuCount();
    try expect(cpu_count >= 1);
}

test "thread local storage" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const thread1 = try Thread.spawn(.{}, testTls, .{});
    const thread2 = try Thread.spawn(.{}, testTls, .{});
    try testTls();
    thread1.join();
    thread2.join();
}

threadlocal var x: i32 = 1234;
fn testTls() !void {
    if (x != 1234) return error.TlsBadStartValue;
    x += 1;
    if (x != 1235) return error.TlsBadEndValue;
}

test "getrandom" {
    var buf_a: [50]u8 = undefined;
    var buf_b: [50]u8 = undefined;
    try posix.getrandom(&buf_a);
    try posix.getrandom(&buf_b);
    // If this test fails the chance is significantly higher that there is a bug than
    // that two sets of 50 bytes were equal.
    try expect(!mem.eql(u8, &buf_a, &buf_b));
}

test "getcwd" {
    // at least call it so it gets compiled
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    _ = posix.getcwd(&buf) catch undefined;
}

test "getuid" {
    if (native_os == .windows or native_os == .wasi) return error.SkipZigTest;
    _ = posix.getuid();
    _ = posix.geteuid();
}

test "sigaltstack" {
    if (native_os == .windows or native_os == .wasi) return error.SkipZigTest;

    var st: posix.stack_t = undefined;
    try posix.sigaltstack(null, &st);
    // Setting a stack size less than MINSIGSTKSZ returns ENOMEM
    st.flags = 0;
    st.size = 1;
    try testing.expectError(error.SizeTooSmall, posix.sigaltstack(&st, null));
}

// If the type is not available use void to avoid erroring out when `iter_fn` is
// analyzed
const have_dl_phdr_info = posix.system.dl_phdr_info != void;
const dl_phdr_info = if (have_dl_phdr_info) posix.dl_phdr_info else anyopaque;

const IterFnError = error{
    MissingPtLoadSegment,
    MissingLoad,
    BadElfMagic,
    FailedConsistencyCheck,
};

fn iter_fn(info: *dl_phdr_info, size: usize, counter: *usize) IterFnError!void {
    _ = size;
    // Count how many libraries are loaded
    counter.* += @as(usize, 1);

    // The image should contain at least a PT_LOAD segment
    if (info.phnum < 1) return error.MissingPtLoadSegment;

    // Quick & dirty validation of the phdr pointers, make sure we're not
    // pointing to some random gibberish
    var i: usize = 0;
    var found_load = false;
    while (i < info.phnum) : (i += 1) {
        const phdr = info.phdr[i];

        if (phdr.p_type != elf.PT_LOAD) continue;

        const reloc_addr = info.addr + phdr.p_vaddr;
        // Find the ELF header
        const elf_header = @as(*elf.Ehdr, @ptrFromInt(reloc_addr - phdr.p_offset));
        // Validate the magic
        if (!mem.eql(u8, elf_header.e_ident[0..4], elf.MAGIC)) return error.BadElfMagic;
        // Consistency check
        if (elf_header.e_phnum != info.phnum) return error.FailedConsistencyCheck;

        found_load = true;
        break;
    }

    if (!found_load) return error.MissingLoad;
}

test "dl_iterate_phdr" {
    if (builtin.object_format != .elf) return error.SkipZigTest;

    var counter: usize = 0;
    try posix.dl_iterate_phdr(&counter, IterFnError, iter_fn);
    try expect(counter != 0);
}

test "gethostname" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    var buf: [posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = try posix.gethostname(&buf);
    try expect(hostname.len != 0);
}

test "pipe" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    const fds = try posix.pipe();
    try expect((try posix.write(fds[1], "hello")) == 5);
    var buf: [16]u8 = undefined;
    try expect((try posix.read(fds[0], buf[0..])) == 5);
    try testing.expectEqualSlices(u8, buf[0..5], "hello");
    posix.close(fds[1]);
    posix.close(fds[0]);
}

test "argsAlloc" {
    const args = try std.process.argsAlloc(std.testing.allocator);
    std.process.argsFree(std.testing.allocator, args);
}

test "memfd_create" {
    // memfd_create is only supported by linux and freebsd.
    switch (native_os) {
        .linux => {},
        .freebsd => {
            if (comptime builtin.os.version_range.semver.max.order(.{ .major = 13, .minor = 0, .patch = 0 }) == .lt)
                return error.SkipZigTest;
        },
        else => return error.SkipZigTest,
    }

    const fd = try posix.memfd_create("test", 0);
    defer posix.close(fd);
    try expect((try posix.write(fd, "test")) == 4);
    try posix.lseek_SET(fd, 0);

    var buf: [10]u8 = undefined;
    const bytes_read = try posix.read(fd, &buf);
    try expect(bytes_read == 4);
    try expect(mem.eql(u8, buf[0..4], "test"));
}

test "mmap" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // Simple mmap() call with non page-aligned size
    {
        const data = try posix.mmap(
            null,
            1234,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        defer posix.munmap(data);

        try testing.expectEqual(@as(usize, 1234), data.len);

        // By definition the data returned by mmap is zero-filled
        try testing.expect(mem.eql(u8, data, &[_]u8{0x00} ** 1234));

        // Make sure the memory is writeable as requested
        @memset(data, 0x55);
        try testing.expect(mem.eql(u8, data, &[_]u8{0x55} ** 1234));
    }

    const test_out_file = "os_tmp_test";
    // Must be a multiple of 4096 so that the test works with mmap2
    const alloc_size = 8 * 4096;

    // Create a file used for testing mmap() calls with a file descriptor
    {
        const file = try tmp.dir.createFile(test_out_file, .{});
        defer file.close();

        const stream = file.writer();

        var i: u32 = 0;
        while (i < alloc_size / @sizeOf(u32)) : (i += 1) {
            try stream.writeInt(u32, i, .little);
        }
    }

    // Map the whole file
    {
        const file = try tmp.dir.openFile(test_out_file, .{});
        defer file.close();

        const data = try posix.mmap(
            null,
            alloc_size,
            posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            file.handle,
            0,
        );
        defer posix.munmap(data);

        var mem_stream = io.fixedBufferStream(data);
        const stream = mem_stream.reader();

        var i: u32 = 0;
        while (i < alloc_size / @sizeOf(u32)) : (i += 1) {
            try testing.expectEqual(i, try stream.readInt(u32, .little));
        }
    }

   ```
