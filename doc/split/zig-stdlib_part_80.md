```
 packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u4 = 0,
        CREAT: bool = false,
        EXCL: bool = false,
        NOCTTY: bool = false,
        TRUNC: bool = false,
        APPEND: bool = false,
        NONBLOCK: bool = false,
        DSYNC: bool = false,
        ASYNC: bool = false,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        LARGEFILE: bool = false,
        DIRECT: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        SYNC: bool = false,
        PATH: bool = false,
        TMPFILE: bool = false,
        _23: u9 = 0,
    },
    .hexagon, .s390x => packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u4 = 0,
        CREAT: bool = false,
        EXCL: bool = false,
        NOCTTY: bool = false,
        TRUNC: bool = false,
        APPEND: bool = false,
        NONBLOCK: bool = false,
        DSYNC: bool = false,
        ASYNC: bool = false,
        DIRECT: bool = false,
        LARGEFILE: bool = false,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        _20: u1 = 0,
        PATH: bool = false,
        _22: u10 = 0,

        // #define O_RSYNC    04010000
        // #define O_SYNC     04010000
        // #define O_TMPFILE 020200000
        // #define O_NDELAY O_NONBLOCK
    },
    .m68k => packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u4 = 0,
        CREAT: bool = false,
        EXCL: bool = false,
        NOCTTY: bool = false,
        TRUNC: bool = false,
        APPEND: bool = false,
        NONBLOCK: bool = false,
        DSYNC: bool = false,
        ASYNC: bool = false,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        DIRECT: bool = false,
        LARGEFILE: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        _20: u1 = 0,
        PATH: bool = false,
        _22: u10 = 0,
    },
    else => @compileError("missing std.os.linux.O constants for this architecture"),
};

/// Set by startup code, used by `getauxval`.
pub var elf_aux_maybe: ?[*]std.elf.Auxv = null;

/// Whether an external or internal getauxval implementation is used.
const extern_getauxval = switch (builtin.zig_backend) {
    // Calling extern functions is not yet supported with these backends
    .stage2_aarch64, .stage2_arm, .stage2_riscv64, .stage2_sparc64 => false,
    else => !builtin.link_libc,
};

pub const getauxval = if (extern_getauxval) struct {
    comptime {
        const root = @import("root");
        // Export this only when building an executable, otherwise it is overriding
        // the libc implementation
        if (builtin.output_mode == .Exe or @hasDecl(root, "main")) {
            @export(&getauxvalImpl, .{ .name = "getauxval", .linkage = .weak });
        }
    }
    extern fn getauxval(index: usize) usize;
}.getauxval else getauxvalImpl;

fn getauxvalImpl(index: usize) callconv(.c) usize {
    const auxv = elf_aux_maybe orelse return 0;
    var i: usize = 0;
    while (auxv[i].a_type != std.elf.AT_NULL) : (i += 1) {
        if (auxv[i].a_type == index)
            return auxv[i].a_un.a_val;
    }
    return 0;
}

// Some architectures (and some syscalls) require 64bit parameters to be passed
// in a even-aligned register pair.
const require_aligned_register_pair =
    builtin.cpu.arch.isPowerPC32() or
    builtin.cpu.arch.isMIPS32() or
    builtin.cpu.arch.isArm();

// Split a 64bit value into a {LSB,MSB} pair.
// The LE/BE variants specify the endianness to assume.
fn splitValueLE64(val: i64) [2]u32 {
    const u: u64 = @bitCast(val);
    return [2]u32{
        @as(u32, @truncate(u)),
        @as(u32, @truncate(u >> 32)),
    };
}
fn splitValueBE64(val: i64) [2]u32 {
    const u: u64 = @bitCast(val);
    return [2]u32{
        @as(u32, @truncate(u >> 32)),
        @as(u32, @truncate(u)),
    };
}
fn splitValue64(val: i64) [2]u32 {
    const u: u64 = @bitCast(val);
    switch (native_endian) {
        .little => return [2]u32{
            @as(u32, @truncate(u)),
            @as(u32, @truncate(u >> 32)),
        },
        .big => return [2]u32{
            @as(u32, @truncate(u >> 32)),
            @as(u32, @truncate(u)),
        },
    }
}

/// Get the errno from a syscall return value, or 0 for no error.
/// The public API is exposed via the `E` namespace.
fn errnoFromSyscall(r: usize) E {
    const signed_r: isize = @bitCast(r);
    const int = if (signed_r > -4096 and signed_r < 0) -signed_r else 0;
    return @enumFromInt(int);
}

pub fn dup(old: i32) usize {
    return syscall1(.dup, @as(usize, @bitCast(@as(isize, old))));
}

pub fn dup2(old: i32, new: i32) usize {
    if (@hasField(SYS, "dup2")) {
        return syscall2(.dup2, @as(usize, @bitCast(@as(isize, old))), @as(usize, @bitCast(@as(isize, new))));
    } else {
        if (old == new) {
            if (std.debug.runtime_safety) {
                const rc = fcntl(F.GETFD, @as(fd_t, old), 0);
                if (@as(isize, @bitCast(rc)) < 0) return rc;
            }
            return @as(usize, @intCast(old));
        } else {
            return syscall3(.dup3, @as(usize, @bitCast(@as(isize, old))), @as(usize, @bitCast(@as(isize, new))), 0);
        }
    }
}

pub fn dup3(old: i32, new: i32, flags: u32) usize {
    return syscall3(.dup3, @as(usize, @bitCast(@as(isize, old))), @as(usize, @bitCast(@as(isize, new))), flags);
}

pub fn chdir(path: [*:0]const u8) usize {
    return syscall1(.chdir, @intFromPtr(path));
}

pub fn fchdir(fd: fd_t) usize {
    return syscall1(.fchdir, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn chroot(path: [*:0]const u8) usize {
    return syscall1(.chroot, @intFromPtr(path));
}

pub fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) usize {
    return syscall3(.execve, @intFromPtr(path), @intFromPtr(argv), @intFromPtr(envp));
}

pub fn fork() usize {
    if (comptime native_arch.isSPARC()) {
        return syscall_fork();
    } else if (@hasField(SYS, "fork")) {
        return syscall0(.fork);
    } else {
        return syscall2(.clone, SIG.CHLD, 0);
    }
}

/// This must be inline, and inline call the syscall function, because if the
/// child does a return it will clobber the parent's stack.
/// It is advised to avoid this function and use clone instead, because
/// the compiler is not aware of how vfork affects control flow and you may
/// see different results in optimized builds.
pub inline fn vfork() usize {
    return @call(.always_inline, syscall0, .{.vfork});
}

pub fn futimens(fd: i32, times: ?*const [2]timespec) usize {
    return utimensat(fd, null, times, 0);
}

pub fn utimensat(dirfd: i32, path: ?[*:0]const u8, times: ?*const [2]timespec, flags: u32) usize {
    return syscall4(.utimensat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(times), flags);
}

pub fn fallocate(fd: i32, mode: i32, offset: i64, length: i64) usize {
    if (usize_bits < 64) {
        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(length);
        return syscall6(
            .fallocate,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(@as(isize, mode))),
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
        );
    } else {
        return syscall4(
            .fallocate,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(@as(isize, mode))),
            @as(u64, @bitCast(offset)),
            @as(u64, @bitCast(length)),
        );
    }
}

pub fn futex_wait(uaddr: *const i32, futex_op: u32, val: i32, timeout: ?*const timespec) usize {
    return syscall4(.futex, @intFromPtr(uaddr), futex_op, @as(u32, @bitCast(val)), @intFromPtr(timeout));
}

pub fn futex_wake(uaddr: *const i32, futex_op: u32, val: i32) usize {
    return syscall3(.futex, @intFromPtr(uaddr), futex_op, @as(u32, @bitCast(val)));
}

/// Given an array of `futex_waitv`, wait on each uaddr.
/// The thread wakes if a futex_wake() is performed at any uaddr.
/// The syscall returns immediately if any waiter has *uaddr != val.
/// timeout is an optional timeout value for the operation.
/// Each waiter has individual flags.
/// The `flags` argument for the syscall should be used solely for specifying
/// the timeout as realtime, if needed.
/// Flags for private futexes, sizes, etc. should be used on the
/// individual flags of each waiter.
///
/// Returns the array index of one of the woken futexes.
/// No further information is provided: any number of other futexes may also
/// have been woken by the same event, and if more than one futex was woken,
/// the returned index may refer to any one of them.
/// (It is not necessaryily the futex with the smallest index, nor the one
/// most recently woken, nor...)
pub fn futex2_waitv(
    /// List of futexes to wait on.
    waiters: [*]futex_waitv,
    /// Length of `waiters`.
    nr_futexes: u32,
    /// Flag for timeout (monotonic/realtime).
    flags: u32,
    /// Optional absolute timeout.
    timeout: ?*const timespec,
    /// Clock to be used for the timeout, realtime or monotonic.
    clockid: clockid_t,
) usize {
    return syscall5(
        .futex_waitv,
        @intFromPtr(waiters),
        nr_futexes,
        flags,
        @intFromPtr(timeout),
        @bitCast(@as(isize, @intFromEnum(clockid))),
    );
}

/// Wait on a futex.
/// Identical to the traditional `FUTEX.FUTEX_WAIT_BITSET` op, except it is part of the
/// futex2 familiy of calls.
pub fn futex2_wait(
    /// Address of the futex to wait on.
    uaddr: *const anyopaque,
    /// Value of `uaddr`.
    val: usize,
    /// Bitmask.
    mask: usize,
    /// `FUTEX2` flags.
    flags: u32,
    /// Optional absolute timeout.
    timeout: ?*const timespec,
    /// Clock to be used for the timeout, realtime or monotonic.
    clockid: clockid_t,
) usize {
    return syscall6(
        .futex_wait,
        @intFromPtr(uaddr),
        val,
        mask,
        flags,
        @intFromPtr(timeout),
        @bitCast(@as(isize, @intFromEnum(clockid))),
    );
}

/// Wake a number of futexes.
/// Identical to the traditional `FUTEX.FUTEX_WAIT_BITSET` op, except it is part of the
/// futex2 family of calls.
pub fn futex2_wake(
    /// Address of the futex(es) to wake.
    uaddr: *const anyopaque,
    /// Bitmask
    mask: usize,
    /// Number of the futexes to wake.
    nr: i32,
    /// `FUTEX2` flags.
    flags: u32,
) usize {
    return syscall4(
        .futex_wake,
        @intFromPtr(uaddr),
        mask,
        @bitCast(@as(isize, nr)),
        flags,
    );
}

/// Requeue a waiter from one futex to another.
/// Identical to `FUTEX.CMP_REQUEUE`, except it is part of the futex2 family of calls.
pub fn futex2_requeue(
    /// Array describing the source and destination futex.
    waiters: [*]futex_waitv,
    /// Unused.
    flags: u32,
    /// Number of futexes to wake.
    nr_wake: i32,
    /// Number of futexes to requeue.
    nr_requeue: i32,
) usize {
    return syscall4(
        .futex_requeue,
        @intFromPtr(waiters),
        flags,
        @bitCast(@as(isize, nr_wake)),
        @bitCast(@as(isize, nr_requeue)),
    );
}

pub fn getcwd(buf: [*]u8, size: usize) usize {
    return syscall2(.getcwd, @intFromPtr(buf), size);
}

pub fn getdents(fd: i32, dirp: [*]u8, len: usize) usize {
    return syscall3(
        .getdents,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(dirp),
        @min(len, maxInt(c_int)),
    );
}

pub fn getdents64(fd: i32, dirp: [*]u8, len: usize) usize {
    return syscall3(
        .getdents64,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(dirp),
        @min(len, maxInt(c_int)),
    );
}

pub fn inotify_init1(flags: u32) usize {
    return syscall1(.inotify_init1, flags);
}

pub fn inotify_add_watch(fd: i32, pathname: [*:0]const u8, mask: u32) usize {
    return syscall3(.inotify_add_watch, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(pathname), mask);
}

pub fn inotify_rm_watch(fd: i32, wd: i32) usize {
    return syscall2(.inotify_rm_watch, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, wd))));
}

pub fn fanotify_init(flags: fanotify.InitFlags, event_f_flags: u32) usize {
    return syscall2(.fanotify_init, @as(u32, @bitCast(flags)), event_f_flags);
}

pub fn fanotify_mark(
    fd: fd_t,
    flags: fanotify.MarkFlags,
    mask: fanotify.MarkMask,
    dirfd: fd_t,
    pathname: ?[*:0]const u8,
) usize {
    if (usize_bits < 64) {
        const mask_halves = splitValue64(@bitCast(mask));
        return syscall6(
            .fanotify_mark,
            @bitCast(@as(isize, fd)),
            @as(u32, @bitCast(flags)),
            mask_halves[0],
            mask_halves[1],
            @bitCast(@as(isize, dirfd)),
            @intFromPtr(pathname),
        );
    } else {
        return syscall5(
            .fanotify_mark,
            @bitCast(@as(isize, fd)),
            @as(u32, @bitCast(flags)),
            @bitCast(mask),
            @bitCast(@as(isize, dirfd)),
            @intFromPtr(pathname),
        );
    }
}

pub fn name_to_handle_at(
    dirfd: fd_t,
    pathname: [*:0]const u8,
    handle: *std.os.linux.file_handle,
    mount_id: *i32,
    flags: u32,
) usize {
    return syscall5(
        .name_to_handle_at,
        @as(u32, @bitCast(dirfd)),
        @intFromPtr(pathname),
        @intFromPtr(handle),
        @intFromPtr(mount_id),
        flags,
    );
}

pub fn readlink(noalias path: [*:0]const u8, noalias buf_ptr: [*]u8, buf_len: usize) usize {
    if (@hasField(SYS, "readlink")) {
        return syscall3(.readlink, @intFromPtr(path), @intFromPtr(buf_ptr), buf_len);
    } else {
        return syscall4(.readlinkat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), @intFromPtr(buf_ptr), buf_len);
    }
}

pub fn readlinkat(dirfd: i32, noalias path: [*:0]const u8, noalias buf_ptr: [*]u8, buf_len: usize) usize {
    return syscall4(.readlinkat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(buf_ptr), buf_len);
}

pub fn mkdir(path: [*:0]const u8, mode: mode_t) usize {
    if (@hasField(SYS, "mkdir")) {
        return syscall2(.mkdir, @intFromPtr(path), mode);
    } else {
        return syscall3(.mkdirat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), mode);
    }
}

pub fn mkdirat(dirfd: i32, path: [*:0]const u8, mode: mode_t) usize {
    return syscall3(.mkdirat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), mode);
}

pub fn mknod(path: [*:0]const u8, mode: u32, dev: u32) usize {
    if (@hasField(SYS, "mknod")) {
        return syscall3(.mknod, @intFromPtr(path), mode, dev);
    } else {
        return mknodat(AT.FDCWD, path, mode, dev);
    }
}

pub fn mknodat(dirfd: i32, path: [*:0]const u8, mode: u32, dev: u32) usize {
    return syscall4(.mknodat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), mode, dev);
}

pub fn mount(special: [*:0]const u8, dir: [*:0]const u8, fstype: ?[*:0]const u8, flags: u32, data: usize) usize {
    return syscall5(.mount, @intFromPtr(special), @intFromPtr(dir), @intFromPtr(fstype), flags, data);
}

pub fn umount(special: [*:0]const u8) usize {
    return syscall2(.umount2, @intFromPtr(special), 0);
}

pub fn umount2(special: [*:0]const u8, flags: u32) usize {
    return syscall2(.umount2, @intFromPtr(special), flags);
}

pub fn mmap(address: ?[*]u8, length: usize, prot: usize, flags: MAP, fd: i32, offset: i64) usize {
    if (@hasField(SYS, "mmap2")) {
        return syscall6(
            .mmap2,
            @intFromPtr(address),
            length,
            prot,
            @as(u32, @bitCast(flags)),
            @bitCast(@as(isize, fd)),
            @truncate(@as(u64, @bitCast(offset)) / std.heap.pageSize()),
        );
    } else {
        // The s390x mmap() syscall existed before Linux supported syscalls with 5+ parameters, so
        // it takes a single pointer to an array of arguments instead.
        return if (native_arch == .s390x) syscall1(
            .mmap,
            @intFromPtr(&[_]usize{
                @intFromPtr(address),
                length,
                prot,
                @as(u32, @bitCast(flags)),
                @bitCast(@as(isize, fd)),
                @as(u64, @bitCast(offset)),
            }),
        ) else syscall6(
            .mmap,
            @intFromPtr(address),
            length,
            prot,
            @as(u32, @bitCast(flags)),
            @bitCast(@as(isize, fd)),
            @as(u64, @bitCast(offset)),
        );
    }
}

pub fn mprotect(address: [*]const u8, length: usize, protection: usize) usize {
    return syscall3(.mprotect, @intFromPtr(address), length, protection);
}

pub fn mremap(old_addr: ?[*]const u8, old_len: usize, new_len: usize, flags: MREMAP, new_addr: ?[*]const u8) usize {
    return syscall5(
        .mremap,
        @intFromPtr(old_addr),
        old_len,
        new_len,
        @as(u32, @bitCast(flags)),
        @intFromPtr(new_addr),
    );
}

pub const MSF = struct {
    pub const ASYNC = 1;
    pub const INVALIDATE = 2;
    pub const SYNC = 4;
};

/// Can only be called on 64 bit systems.
pub fn mseal(address: [*]const u8, length: usize, flags: usize) usize {
    return syscall3(.mseal, @intFromPtr(address), length, flags);
}

pub fn msync(address: [*]const u8, length: usize, flags: i32) usize {
    return syscall3(.msync, @intFromPtr(address), length, @as(u32, @bitCast(flags)));
}

pub fn munmap(address: [*]const u8, length: usize) usize {
    return syscall2(.munmap, @intFromPtr(address), length);
}

pub fn poll(fds: [*]pollfd, n: nfds_t, timeout: i32) usize {
    if (@hasField(SYS, "poll")) {
        return syscall3(.poll, @intFromPtr(fds), n, @as(u32, @bitCast(timeout)));
    } else {
        return syscall5(
            .ppoll,
            @intFromPtr(fds),
            n,
            @intFromPtr(if (timeout >= 0)
                &timespec{
                    .sec = @divTrunc(timeout, 1000),
                    .nsec = @rem(timeout, 1000) * 1000000,
                }
            else
                null),
            0,
            NSIG / 8,
        );
    }
}

pub fn ppoll(fds: [*]pollfd, n: nfds_t, timeout: ?*timespec, sigmask: ?*const sigset_t) usize {
    return syscall5(.ppoll, @intFromPtr(fds), n, @intFromPtr(timeout), @intFromPtr(sigmask), NSIG / 8);
}

pub fn read(fd: i32, buf: [*]u8, count: usize) usize {
    return syscall3(.read, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(buf), count);
}

pub fn preadv(fd: i32, iov: [*]const iovec, count: usize, offset: i64) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall5(
        .preadv,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // Kernel expects the offset is split into largest natural word-size.
        // See following link for detail:
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=601cc11d054ae4b5e9b5babec3d8e4667a2cb9b5
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
    );
}

pub fn preadv2(fd: i32, iov: [*]const iovec, count: usize, offset: i64, flags: kernel_rwf) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall6(
        .preadv2,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // See comments in preadv
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
        flags,
    );
}

pub fn readv(fd: i32, iov: [*]const iovec, count: usize) usize {
    return syscall3(.readv, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(iov), count);
}

pub fn writev(fd: i32, iov: [*]const iovec_const, count: usize) usize {
    return syscall3(.writev, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(iov), count);
}

pub fn pwritev(fd: i32, iov: [*]const iovec_const, count: usize, offset: i64) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall5(
        .pwritev,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // See comments in preadv
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
    );
}

pub fn pwritev2(fd: i32, iov: [*]const iovec_const, count: usize, offset: i64, flags: kernel_rwf) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall6(
        .pwritev2,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // See comments in preadv
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
        flags,
    );
}

pub fn rmdir(path: [*:0]const u8) usize {
    if (@hasField(SYS, "rmdir")) {
        return syscall1(.rmdir, @intFromPtr(path));
    } else {
        return syscall3(.unlinkat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), AT.REMOVEDIR);
    }
}

pub fn symlink(existing: [*:0]const u8, new: [*:0]const u8) usize {
    if (@hasField(SYS, "symlink")) {
        return syscall2(.symlink, @intFromPtr(existing), @intFromPtr(new));
    } else {
        return syscall3(.symlinkat, @intFromPtr(existing), @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(new));
    }
}

pub fn symlinkat(existing: [*:0]const u8, newfd: i32, newpath: [*:0]const u8) usize {
    return syscall3(.symlinkat, @intFromPtr(existing), @as(usize, @bitCast(@as(isize, newfd))), @intFromPtr(newpath));
}

pub fn pread(fd: i32, buf: [*]u8, count: usize, offset: i64) usize {
    if (@hasField(SYS, "pread64") and usize_bits < 64) {
        const offset_halves = splitValue64(offset);
        if (require_aligned_register_pair) {
            return syscall6(
                .pread64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                0,
                offset_halves[0],
                offset_halves[1],
            );
        } else {
            return syscall5(
                .pread64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                offset_halves[0],
                offset_halves[1],
            );
        }
    } else {
        // Some architectures (eg. 64bit SPARC) pread is called pread64.
        const syscall_number = if (!@hasField(SYS, "pread") and @hasField(SYS, "pread64"))
            .pread64
        else
            .pread;
        return syscall4(
            syscall_number,
            @as(usize, @bitCast(@as(isize, fd))),
            @intFromPtr(buf),
            count,
            @as(u64, @bitCast(offset)),
        );
    }
}

pub fn access(path: [*:0]const u8, mode: u32) usize {
    if (@hasField(SYS, "access")) {
        return syscall2(.access, @intFromPtr(path), mode);
    } else {
        return syscall4(.faccessat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), mode, 0);
    }
}

pub fn faccessat(dirfd: i32, path: [*:0]const u8, mode: u32, flags: u32) usize {
    return syscall4(.faccessat2, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), mode, flags);
}

pub fn pipe(fd: *[2]i32) usize {
    if (comptime (native_arch.isMIPS() or native_arch.isSPARC())) {
        return syscall_pipe(fd);
    } else if (@hasField(SYS, "pipe")) {
        return syscall1(.pipe, @intFromPtr(fd));
    } else {
        return syscall2(.pipe2, @intFromPtr(fd), 0);
    }
}

pub fn pipe2(fd: *[2]i32, flags: O) usize {
    return syscall2(.pipe2, @intFromPtr(fd), @as(u32, @bitCast(flags)));
}

pub fn write(fd: i32, buf: [*]const u8, count: usize) usize {
    return syscall3(.write, @bitCast(@as(isize, fd)), @intFromPtr(buf), count);
}

pub fn ftruncate(fd: i32, length: i64) usize {
    if (@hasField(SYS, "ftruncate64") and usize_bits < 64) {
        const length_halves = splitValue64(length);
        if (require_aligned_register_pair) {
            return syscall4(
                .ftruncate64,
                @as(usize, @bitCast(@as(isize, fd))),
                0,
                length_halves[0],
                length_halves[1],
            );
        } else {
            return syscall3(
                .ftruncate64,
                @as(usize, @bitCast(@as(isize, fd))),
                length_halves[0],
                length_halves[1],
            );
        }
    } else {
        return syscall2(
            .ftruncate,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(length)),
        );
    }
}

pub fn pwrite(fd: i32, buf: [*]const u8, count: usize, offset: i64) usize {
    if (@hasField(SYS, "pwrite64") and usize_bits < 64) {
        const offset_halves = splitValue64(offset);

        if (require_aligned_register_pair) {
            return syscall6(
                .pwrite64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                0,
                offset_halves[0],
                offset_halves[1],
            );
        } else {
            return syscall5(
                .pwrite64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                offset_halves[0],
                offset_halves[1],
            );
        }
    } else {
        // Some architectures (eg. 64bit SPARC) pwrite is called pwrite64.
        const syscall_number = if (!@hasField(SYS, "pwrite") and @hasField(SYS, "pwrite64"))
            .pwrite64
        else
            .pwrite;
        return syscall4(
            syscall_number,
            @as(usize, @bitCast(@as(isize, fd))),
            @intFromPtr(buf),
            count,
            @as(u64, @bitCast(offset)),
        );
    }
}

pub fn rename(old: [*:0]const u8, new: [*:0]const u8) usize {
    if (@hasField(SYS, "rename")) {
        return syscall2(.rename, @intFromPtr(old), @intFromPtr(new));
    } else if (@hasField(SYS, "renameat")) {
        return syscall4(.renameat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(old), @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(new));
    } else {
        return syscall5(.renameat2, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(old), @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(new), 0);
    }
}

pub fn renameat(oldfd: i32, oldpath: [*:0]const u8, newfd: i32, newpath: [*:0]const u8) usize {
    if (@hasField(SYS, "renameat")) {
        return syscall4(
            .renameat,
            @as(usize, @bitCast(@as(isize, oldfd))),
            @intFromPtr(oldpath),
            @as(usize, @bitCast(@as(isize, newfd))),
            @intFromPtr(newpath),
        );
    } else {
        return syscall5(
            .renameat2,
            @as(usize, @bitCast(@as(isize, oldfd))),
            @intFromPtr(oldpath),
            @as(usize, @bitCast(@as(isize, newfd))),
            @intFromPtr(newpath),
            0,
        );
    }
}

pub fn renameat2(oldfd: i32, oldpath: [*:0]const u8, newfd: i32, newpath: [*:0]const u8, flags: u32) usize {
    return syscall5(
        .renameat2,
        @as(usize, @bitCast(@as(isize, oldfd))),
        @intFromPtr(oldpath),
        @as(usize, @bitCast(@as(isize, newfd))),
        @intFromPtr(newpath),
        flags,
    );
}

pub fn open(path: [*:0]const u8, flags: O, perm: mode_t) usize {
    if (@hasField(SYS, "open")) {
        return syscall3(.open, @intFromPtr(path), @as(u32, @bitCast(flags)), perm);
    } else {
        return syscall4(
            .openat,
            @bitCast(@as(isize, AT.FDCWD)),
            @intFromPtr(path),
            @as(u32, @bitCast(flags)),
            perm,
        );
    }
}

pub fn create(path: [*:0]const u8, perm: mode_t) usize {
    return syscall2(.creat, @intFromPtr(path), perm);
}

pub fn openat(dirfd: i32, path: [*:0]const u8, flags: O, mode: mode_t) usize {
    // dirfd could be negative, for example AT.FDCWD is -100
    return syscall4(.openat, @bitCast(@as(isize, dirfd)), @intFromPtr(path), @as(u32, @bitCast(flags)), mode);
}

/// See also `clone` (from the arch-specific include)
pub fn clone5(flags: usize, child_stack_ptr: usize, parent_tid: *i32, child_tid: *i32, newtls: usize) usize {
    return syscall5(.clone, flags, child_stack_ptr, @intFromPtr(parent_tid), @intFromPtr(child_tid), newtls);
}

/// See also `clone` (from the arch-specific include)
pub fn clone2(flags: u32, child_stack_ptr: usize) usize {
    return syscall2(.clone, flags, child_stack_ptr);
}

pub fn close(fd: i32) usize {
    return syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn fchmod(fd: i32, mode: mode_t) usize {
    return syscall2(.fchmod, @as(usize, @bitCast(@as(isize, fd))), mode);
}

pub fn chmod(path: [*:0]const u8, mode: mode_t) usize {
    if (@hasField(SYS, "chmod")) {
        return syscall2(.chmod, @intFromPtr(path), mode);
    } else {
        return fchmodat(AT.FDCWD, path, mode, 0);
    }
}

pub fn fchown(fd: i32, owner: uid_t, group: gid_t) usize {
    if (@hasField(SYS, "fchown32")) {
        return syscall3(.fchown32, @as(usize, @bitCast(@as(isize, fd))), owner, group);
    } else {
        return syscall3(.fchown, @as(usize, @bitCast(@as(isize, fd))), owner, group);
    }
}

pub fn fchmodat(fd: i32, path: [*:0]const u8, mode: mode_t, _: u32) usize {
    return syscall3(.fchmodat, @bitCast(@as(isize, fd)), @intFromPtr(path), mode);
}

pub fn fchmodat2(fd: i32, path: [*:0]const u8, mode: mode_t, flags: u32) usize {
    return syscall4(.fchmodat2, @bitCast(@as(isize, fd)), @intFromPtr(path), mode, flags);
}

/// Can only be called on 32 bit systems. For 64 bit see `lseek`.
pub fn llseek(fd: i32, offset: u64, result: ?*u64, whence: usize) usize {
    // NOTE: The offset parameter splitting is independent from the target
    // endianness.
    return syscall5(
        .llseek,
        @as(usize, @bitCast(@as(isize, fd))),
        @as(usize, @truncate(offset >> 32)),
        @as(usize, @truncate(offset)),
        @intFromPtr(result),
        whence,
    );
}

/// Can only be called on 64 bit systems. For 32 bit see `llseek`.
pub fn lseek(fd: i32, offset: i64, whence: usize) usize {
    return syscall3(.lseek, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(offset)), whence);
}

pub fn exit(status: i32) noreturn {
    _ = syscall1(.exit, @as(usize, @bitCast(@as(isize, status))));
    unreachable;
}

pub fn exit_group(status: i32) noreturn {
    _ = syscall1(.exit_group, @as(usize, @bitCast(@as(isize, status))));
    unreachable;
}

/// flags for the `reboot' system call.
pub const LINUX_REBOOT = struct {
    /// First magic value required to use _reboot() system call.
    pub const MAGIC1 = enum(u32) {
        MAGIC1 = 0xfee1dead,
        _,
    };

    /// Second magic value required to use _reboot() system call.
    pub const MAGIC2 = enum(u32) {
        MAGIC2 = 672274793,
        MAGIC2A = 85072278,
        MAGIC2B = 369367448,
        MAGIC2C = 537993216,
        _,
    };

    /// Commands accepted by the _reboot() system call.
    pub const CMD = enum(u32) {
        /// Restart system using default command and mode.
        RESTART = 0x01234567,

        /// Stop OS and give system control to ROM monitor, if any.
        HALT = 0xCDEF0123,

        /// Ctrl-Alt-Del sequence causes RESTART command.
        CAD_ON = 0x89ABCDEF,

        /// Ctrl-Alt-Del sequence sends SIGINT to init task.
        CAD_OFF = 0x00000000,

        /// Stop OS and remove all power from system, if possible.
        POWER_OFF = 0x4321FEDC,

        /// Restart system using given command string.
        RESTART2 = 0xA1B2C3D4,

        /// Suspend system using software suspend if compiled in.
        SW_SUSPEND = 0xD000FCE2,

        /// Restart system using a previously loaded Linux kernel
        KEXEC = 0x45584543,

        _,
    };
};

pub fn reboot(magic: LINUX_REBOOT.MAGIC1, magic2: LINUX_REBOOT.MAGIC2, cmd: LINUX_REBOOT.CMD, arg: ?*const anyopaque) usize {
    return std.os.linux.syscall4(
        .reboot,
        @intFromEnum(magic),
        @intFromEnum(magic2),
        @intFromEnum(cmd),
        @intFromPtr(arg),
    );
}

pub fn getrandom(buf: [*]u8, count: usize, flags: u32) usize {
    return syscall3(.getrandom, @intFromPtr(buf), count, flags);
}

pub fn kill(pid: pid_t, sig: i32) usize {
    return syscall2(.kill, @as(usize, @bitCast(@as(isize, pid))), @as(usize, @bitCast(@as(isize, sig))));
}

pub fn tkill(tid: pid_t, sig: i32) usize {
    return syscall2(.tkill, @as(usize, @bitCast(@as(isize, tid))), @as(usize, @bitCast(@as(isize, sig))));
}

pub fn tgkill(tgid: pid_t, tid: pid_t, sig: i32) usize {
    return syscall3(.tgkill, @as(usize, @bitCast(@as(isize, tgid))), @as(usize, @bitCast(@as(isize, tid))), @as(usize, @bitCast(@as(isize, sig))));
}

pub fn link(oldpath: [*:0]const u8, newpath: [*:0]const u8) usize {
    if (@hasField(SYS, "link")) {
        return syscall2(
            .link,
            @intFromPtr(oldpath),
            @intFromPtr(newpath),
        );
    } else {
        return syscall5(
            .linkat,
            @as(usize, @bitCast(@as(isize, AT.FDCWD))),
            @intFromPtr(oldpath),
            @as(usize, @bitCast(@as(isize, AT.FDCWD))),
            @intFromPtr(newpath),
            0,
        );
    }
}

pub fn linkat(oldfd: fd_t, oldpath: [*:0]const u8, newfd: fd_t, newpath: [*:0]const u8, flags: i32) usize {
    return syscall5(
        .linkat,
        @as(usize, @bitCast(@as(isize, oldfd))),
        @intFromPtr(oldpath),
        @as(usize, @bitCast(@as(isize, newfd))),
        @intFromPtr(newpath),
        @as(usize, @bitCast(@as(isize, flags))),
    );
}

pub fn unlink(path: [*:0]const u8) usize {
    if (@hasField(SYS, "unlink")) {
        return syscall1(.unlink, @intFromPtr(path));
    } else {
        return syscall3(.unlinkat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), 0);
    }
}

pub fn unlinkat(dirfd: i32, path: [*:0]const u8, flags: u32) usize {
    return syscall3(.unlinkat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), flags);
}

pub fn waitpid(pid: pid_t, status: *u32, flags: u32) usize {
    return syscall4(.wait4, @as(usize, @bitCast(@as(isize, pid))), @intFromPtr(status), flags, 0);
}

pub fn wait4(pid: pid_t, status: *u32, flags: u32, usage: ?*rusage) usize {
    return syscall4(
        .wait4,
        @as(usize, @bitCast(@as(isize, pid))),
        @intFromPtr(status),
        flags,
        @intFromPtr(usage),
    );
}

pub fn waitid(id_type: P, id: i32, infop: *siginfo_t, flags: u32) usize {
    return syscall5(.waitid, @intFromEnum(id_type), @as(usize, @bitCast(@as(isize, id))), @intFromPtr(infop), flags, 0);
}

pub fn fcntl(fd: fd_t, cmd: i32, arg: usize) usize {
    if (@hasField(SYS, "fcntl64")) {
        return syscall3(.fcntl64, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, cmd))), arg);
    } else {
        return syscall3(.fcntl, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, cmd))), arg);
    }
}

pub fn flock(fd: fd_t, operation: i32) usize {
    return syscall2(.flock, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, operation))));
}

// We must follow the C calling convention when we call into the VDSO
const VdsoClockGettime = *align(1) const fn (clockid_t, *timespec) callconv(.c) usize;
var vdso_clock_gettime: ?VdsoClockGettime = &init_vdso_clock_gettime;

pub fn clock_gettime(clk_id: clockid_t, tp: *timespec) usize {
    if (VDSO != void) {
        const ptr = @atomicLoad(?VdsoClockGettime, &vdso_clock_gettime, .unordered);
        if (ptr) |f| {
            const rc = f(clk_id, tp);
            switch (rc) {
                0, @as(usize, @bitCast(-@as(isize, @intFromEnum(E.INVAL)))) => return rc,
                else => {},
            }
        }
    }
    return syscall2(.clock_gettime, @intFromEnum(clk_id), @intFromPtr(tp));
}

fn init_vdso_clock_gettime(clk: clockid_t, ts: *timespec) callconv(.c) usize {
    const ptr: ?VdsoClockGettime = @ptrFromInt(vdso.lookup(VDSO.CGT_VER, VDSO.CGT_SYM));
    // Note that we may not have a VDSO at all, update the stub address anyway
    // so that clock_gettime will fall back on the good old (and slow) syscall
    @atomicStore(?VdsoClockGettime, &vdso_clock_gettime, ptr, .monotonic);
    // Call into the VDSO if available
    if (ptr) |f| return f(clk, ts);
    return @as(usize, @bitCast(-@as(isize, @intFromEnum(E.NOSYS))));
}

pub fn clock_getres(clk_id: i32, tp: *timespec) usize {
    return syscall2(.clock_getres, @as(usize, @bitCast(@as(isize, clk_id))), @intFromPtr(tp));
}

pub fn clock_settime(clk_id: i32, tp: *const timespec) usize {
    return syscall2(.clock_settime, @as(usize, @bitCast(@as(isize, clk_id))), @intFromPtr(tp));
}

pub fn clock_nanosleep(clockid: clockid_t, flags: TIMER, request: *const timespec, remain: ?*timespec) usize {
    return syscall4(
        .clock_nanosleep,
        @intFromEnum(clockid),
        @as(u32, @bitCast(flags)),
        @intFromPtr(request),
        @intFromPtr(remain),
    );
}

pub fn gettimeofday(tv: ?*timeval, tz: ?*timezone) usize {
    return syscall2(.gettimeofday, @intFromPtr(tv), @intFromPtr(tz));
}

pub fn settimeofday(tv: *const timeval, tz: *const timezone) usize {
    return syscall2(.settimeofday, @intFromPtr(tv), @intFromPtr(tz));
}

pub fn nanosleep(req: *const timespec, rem: ?*timespec) usize {
    if (native_arch == .riscv32) {
        @compileError("No nanosleep syscall on this architecture.");
    } else return syscall2(.nanosleep, @intFromPtr(req), @intFromPtr(rem));
}

pub fn pause() usize {
    if (@hasField(SYS, "pause")) {
        return syscall0(.pause);
    } else {
        return syscall4(.ppoll, 0, 0, 0, 0);
    }
}

pub fn setuid(uid: uid_t) usize {
    if (@hasField(SYS, "setuid32")) {
        return syscall1(.setuid32, uid);
    } else {
        return syscall1(.setuid, uid);
    }
}

pub fn setgid(gid: gid_t) usize {
    if (@hasField(SYS, "setgid32")) {
        return syscall1(.setgid32, gid);
    } else {
        return syscall1(.setgid, gid);
    }
}

pub fn setreuid(ruid: uid_t, euid: uid_t) usize {
    if (@hasField(SYS, "setreuid32")) {
        return syscall2(.setreuid32, ruid, euid);
    } else {
        return syscall2(.setreuid, ruid, euid);
    }
}

pub fn setregid(rgid: gid_t, egid: gid_t) usize {
    if (@hasField(SYS, "setregid32")) {
        return syscall2(.setregid32, rgid, egid);
    } else {
        return syscall2(.setregid, rgid, egid);
    }
}

pub fn getuid() uid_t {
    if (@hasField(SYS, "getuid32")) {
        return @as(uid_t, @intCast(syscall0(.getuid32)));
    } else {
        return @as(uid_t, @intCast(syscall0(.getuid)));
    }
}

pub fn getgid() gid_t {
    if (@hasField(SYS, "getgid32")) {
        return @as(gid_t, @intCast(syscall0(.getgid32)));
    } else {
        return @as(gid_t, @intCast(syscall0(.getgid)));
    }
}

pub fn geteuid() uid_t {
    if (@hasField(SYS, "geteuid32")) {
        return @as(uid_t, @intCast(syscall0(.geteuid32)));
    } else {
        return @as(uid_t, @intCast(syscall0(.geteuid)));
    }
}

pub fn getegid() gid_t {
    if (@hasField(SYS, "getegid32")) {
        return @as(gid_t, @intCast(syscall0(.getegid32)));
    } else {
        return @as(gid_t, @intCast(syscall0(.getegid)));
    }
}

pub fn seteuid(euid: uid_t) usize {
    // We use setresuid here instead of setreuid to ensure that the saved uid
    // is not changed. This is what musl and recent glibc versions do as well.
    //
    // The setresuid(2) man page says that if -1 is passed the corresponding
    // id will not be changed. Since uid_t is unsigned, this wraps around to the
    // max value in C.
    comptime assert(@typeInfo(uid_t) == .int and @typeInfo(uid_t).int.signedness == .unsigned);
    return setresuid(std.math.maxInt(uid_t), euid, std.math.maxInt(uid_t));
}

pub fn setegid(egid: gid_t) usize {
    // We use setresgid here instead of setregid to ensure that the saved uid
    // is not changed. This is what musl and recent glibc versions do as well.
    //
    // The setresgid(2) man page says that if -1 is passed the corresponding
    // id will not be changed. Since gid_t is unsigned, this wraps around to the
    // max value in C.
    comptime assert(@typeInfo(uid_t) == .int and @typeInfo(uid_t).int.signedness == .unsigned);
    return setresgid(std.math.maxInt(gid_t), egid, std.math.maxInt(gid_t));
}

pub fn getresuid(ruid: *uid_t, euid: *uid_t, suid: *uid_t) usize {
    if (@hasField(SYS, "getresuid32")) {
        return syscall3(.getresuid32, @intFromPtr(ruid), @intFromPtr(euid), @intFromPtr(suid));
    } else {
        return syscall3(.getresuid, @intFromPtr(ruid), @intFromPtr(euid), @intFromPtr(suid));
    }
}

pub fn getresgid(rgid: *gid_t, egid: *gid_t, sgid: *gid_t) usize {
    if (@hasField(SYS, "getresgid32")) {
        return syscall3(.getresgid32, @intFromPtr(rgid), @intFromPtr(egid), @intFromPtr(sgid));
    } else {
        return syscall3(.getresgid, @intFromPtr(rgid), @intFromPtr(egid), @intFromPtr(sgid));
    }
}

pub fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) usize {
    if (@hasField(SYS, "setresuid32")) {
        return syscall3(.setresuid32, ruid, euid, suid);
    } else {
        return syscall3(.setresuid, ruid, euid, suid);
    }
}

pub fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) usize {
    if (@hasField(SYS, "setresgid32")) {
        return syscall3(.setresgid32, rgid, egid, sgid);
    } else {
        return syscall3(.setresgid, rgid, egid, sgid);
    }
}

pub fn setpgid(pid: pid_t, pgid: pid_t) usize {
    return syscall2(.setpgid, @intCast(pid), @intCast(pgid));
}

pub fn getgroups(size: usize, list: ?*gid_t) usize {
    if (@hasField(SYS, "getgroups32")) {
        return syscall2(.getgroups32, size, @intFromPtr(list));
    } else {
        return syscall2(.getgroups, size, @intFromPtr(list));
    }
}

pub fn setgroups(size: usize, list: [*]const gid_t) usize {
    if (@hasField(SYS, "setgroups32")) {
        return syscall2(.setgroups32, size, @intFromPtr(list));
    } else {
        return syscall2(.setgroups, size, @intFromPtr(list));
    }
}

pub fn setsid() pid_t {
    return @bitCast(@as(u32, @truncate(syscall0(.setsid))));
}

pub fn getpid() pid_t {
    return @bitCast(@as(u32, @truncate(syscall0(.getpid))));
}

pub fn getppid() pid_t {
    return @bitCast(@as(u32, @truncate(syscall0(.getppid))));
}

pub fn gettid() pid_t {
    return @bitCast(@as(u32, @truncate(syscall0(.gettid))));
}

pub fn sigprocmask(flags: u32, noalias set: ?*const sigset_t, noalias oldset: ?*sigset_t) usize {
    return syscall4(.rt_sigprocmask, flags, @intFromPtr(set), @intFromPtr(oldset), NSIG / 8);
}

pub fn sigaction(sig: u6, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) usize {
    assert(sig >= 1);
    assert(sig != SIG.KILL);
    assert(sig != SIG.STOP);

    var ksa: k_sigaction = undefined;
    var oldksa: k_sigaction = undefined;
    const mask_size = @sizeOf(@TypeOf(ksa.mask));

    if (act) |new| {
        const restorer_fn = if ((new.flags & SA.SIGINFO) != 0) &restore_rt else &restore;
        ksa = k_sigaction{
            .handler = new.handler.handler,
            .flags = new.flags | SA.RESTORER,
            .mask = undefined,
            .restorer = @ptrCast(restorer_fn),
        };
        @memcpy(@as([*]u8, @ptrCast(&ksa.mask))[0..mask_size], @as([*]const u8, @ptrCast(&new.mask)));
    }

    const ksa_arg = if (act != null) @intFromPtr(&ksa) else 0;
    const oldksa_arg = if (oact != null) @intFromPtr(&oldksa) else 0;

    const result = switch (native_arch) {
        // The sparc version of rt_sigaction needs the restorer function to be passed as an argument too.
        .sparc, .sparc64 => syscall5(.rt_sigaction, sig, ksa_arg, oldksa_arg, @intFromPtr(ksa.restorer), mask_size),
        else => syscall4(.rt_sigaction, sig, ksa_arg, oldksa_arg, mask_size),
    };
    if (E.init(result) != .SUCCESS) return result;

    if (oact) |old| {
        old.handler.handler = oldksa.handler;
        old.flags = @as(c_uint, @truncate(oldksa.flags));
        @memcpy(@as([*]u8, @ptrCast(&old.mask))[0..mask_size], @as([*]const u8, @ptrCast(&oldksa.mask)));
    }

    return 0;
}

const usize_bits = @typeInfo(usize).int.bits;

pub const sigset_t = [1024 / 32]u32;

const sigset_len = @typeInfo(sigset_t).array.len;

/// Empty set to initialize sigset_t instances from.
pub const empty_sigset: sigset_t = [_]u32{0} ** sigset_len;

pub const filled_sigset: sigset_t = [_]u32{0x7fff_ffff} ++ [_]u32{0} ** (sigset_len - 1);

pub const all_mask: sigset_t = [_]u32{0xffff_ffff} ** sigset_len;

fn sigset_bit_index(sig: usize) struct { word: usize, mask: u32 } {
    assert(sig > 0);
    assert(sig < NSIG);
    const bit = sig - 1;
    const shift = @as(u5, @truncate(bit % 32));
    return .{
        .word = bit / 32,
        .mask = @as(u32, 1) << shift,
    };
}

pub fn sigaddset(set: *sigset_t, sig: usize) void {
    const index = sigset_bit_index(sig);
    (set.*)[index.word] |= index.mask;
}

pub fn sigdelset(set: *sigset_t, sig: usize) void {
    const index = sigset_bit_index(sig);
    (set.*)[index.word] ^= index.mask;
}

pub fn sigismember(set: *const sigset_t, sig: usize) bool {
    const index = sigset_bit_index(sig);
    return ((set.*)[index.word] & index.mask) != 0;
}

pub fn getsockname(fd: i32, noalias addr: *sockaddr, noalias len: *socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.getsockname, &[3]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len) });
    }
    return syscall3(.getsockname, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len));
}

pub fn getpeername(fd: i32, noalias addr: *sockaddr, noalias len: *socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.getpeername, &[3]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len) });
    }
    return syscall3(.getpeername, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len));
}

pub fn socket(domain: u32, socket_type: u32, protocol: u32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.socket, &[3]usize{ domain, socket_type, protocol });
    }
    return syscall3(.socket, domain, socket_type, protocol);
}

pub fn setsockopt(fd: i32, level: i32, optname: u32, optval: [*]const u8, optlen: socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.setsockopt, &[5]usize{ @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, level))), optname, @intFromPtr(optval), @as(usize, @intCast(optlen)) });
    }
    return syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, level))), optname, @intFromPtr(optval), @as(usize, @intCast(optlen)));
}

pub fn getsockopt(fd: i32, level: i32, optname: u32, noalias optval: [*]u8, noalias optlen: *socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.getsockopt, &[5]usize{ @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, level))), optname, @intFromPtr(optval), @intFromPtr(optlen) });
    }
    return syscall5(.getsockopt, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, level))), optname, @intFromPtr(optval), @intFromPtr(optlen));
}

pub fn sendmsg(fd: i32, msg: *const msghdr_const, flags: u32) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const msg_usize = @intFromPtr(msg);
    if (native_arch == .x86) {
        return socketcall(SC.sendmsg, &[3]usize{ fd_usize, msg_usize, flags });
    } else {
        return syscall3(.sendmsg, fd_usize, msg_usize, flags);
    }
}

pub fn sendmmsg(fd: i32, msgvec: [*]mmsghdr_const, vlen: u32, flags: u32) usize {
    if (@typeInfo(usize).int.bits > @typeInfo(@typeInfo(mmsghdr).@"struct".fields[1].type).int.bits) {
        // workaround kernel brokenness:
        // if adding up all iov_len overflows a i32 then split into multiple calls
        // see https://www.openwall.com/lists/musl/2014/06/07/5
        const kvlen = if (vlen > IOV_MAX) IOV_MAX else vlen; // matches kernel
        var next_unsent: usize = 0;
        for (msgvec[0..kvlen], 0..) |*msg, i| {
            var size: i32 = 0;
            const msg_iovlen = @as(usize, @intCast(msg.hdr.iovlen)); // kernel side this is treated as unsigned
            for (msg.hdr.iov[0..msg_iovlen]) |iov| {
                if (iov.len > std.math.maxInt(i32) or @addWithOverflow(size, @as(i32, @intCast(iov.len)))[1] != 0) {
                    // batch-send all messages up to the current message
                    if (next_unsent < i) {
                        const batch_size = i - next_unsent;
                        const r = syscall4(.sendmmsg, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&msgvec[next_unsent]), batch_size, flags);
                        if (E.init(r) != .SUCCESS) return next_unsent;
                        if (r < batch_size) return next_unsent + r;
                    }
                    // send current message as own packet
                    const r = sendmsg(fd, &msg.hdr, flags);
                    if (E.init(r) != .SUCCESS) return r;
                    // Linux limits the total bytes sent by sendmsg to INT_MAX, so this cast is safe.
                    msg.len = @as(u32, @intCast(r));
                    next_unsent = i + 1;
                    break;
                }
                size += @intCast(iov.len);
            }
        }
        if (next_unsent < kvlen or next_unsent == 0) { // want to make sure at least one syscall occurs (e.g. to trigger MSG.EOR)
            const batch_size = kvlen - next_unsent;
            const r = syscall4(.sendmmsg, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&msgvec[next_unsent]), batch_size, flags);
            if (E.init(r) != .SUCCESS) return r;
            return next_unsent + r;
        }
        return kvlen;
    }
    return syscall4(.sendmmsg, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(msgvec), vlen, flags);
}

pub fn connect(fd: i32, addr: *const anyopaque, len: socklen_t) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const addr_usize = @intFromPtr(addr);
    if (native_arch == .x86) {
        return socketcall(SC.connect, &[3]usize{ fd_usize, addr_usize, len });
    } else {
        return syscall3(.connect, fd_usize, addr_usize, len);
    }
}

pub fn recvmsg(fd: i32, msg: *msghdr, flags: u32) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const msg_usize = @intFromPtr(msg);
    if (native_arch == .x86) {
        return socketcall(SC.recvmsg, &[3]usize{ fd_usize, msg_usize, flags });
    } else {
        return syscall3(.recvmsg, fd_usize, msg_usize, flags);
    }
}

pub fn recvmmsg(fd: i32, msgvec: ?[*]mmsghdr, vlen: u32, flags: u32, timeout: ?*timespec) usize {
    return syscall5(
        .recvmmsg,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(msgvec),
        vlen,
        flags,
        @intFromPtr(timeout),
    );
}

pub fn recvfrom(
    fd: i32,
    noalias buf: [*]u8,
    len: usize,
    flags: u32,
    noalias addr: ?*sockaddr,
    noalias alen: ?*socklen_t,
) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const buf_usize = @intFromPtr(buf);
    const addr_usize = @intFromPtr(addr);
    const alen_usize = @intFromPtr(alen);
    if (native_arch == .x86) {
        return socketcall(SC.recvfrom, &[6]usize{ fd_usize, buf_usize, len, flags, addr_usize, alen_usize });
    } else {
        return syscall6(.recvfrom, fd_usize, buf_usize, len, flags, addr_usize, alen_usize);
    }
}

pub fn shutdown(fd: i32, how: i32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.shutdown, &[2]usize{ @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, how))) });
    }
    return syscall2(.shutdown, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, how))));
}

pub fn bind(fd: i32, addr: *const sockaddr, len: socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.bind, &[3]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @as(usize, @intCast(len)) });
    }
    return syscall3(.bind, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @as(usize, @intCast(len)));
}

pub fn listen(fd: i32, backlog: u32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.listen, &[2]usize{ @as(usize, @bitCast(@as(isize, fd))), backlog });
    }
    return syscall2(.listen, @as(usize, @bitCast(@as(isize, fd))), backlog);
}

pub fn sendto(fd: i32, buf: [*]const u8, len: usize, flags: u32, addr: ?*const sockaddr, alen: socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.sendto, &[6]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(buf), len, flags, @intFromPtr(addr), @as(usize, @intCast(alen)) });
    }
    return syscall6(.sendto, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(buf), len, flags, @intFromPtr(addr), @as(usize, @intCast(alen)));
}

pub fn sendfile(outfd: i32, infd: i32, offset: ?*i64, count: usize) usize {
    if (@hasField(SYS, "sendfile64")) {
        return syscall4(
            .sendfile64,
            @as(usize, @bitCast(@as(isize, outfd))),
            @as(usize, @bitCast(@as(isize, infd))),
            @intFromPtr(offset),
            count,
        );
    } else {
        return syscall4(
            .sendfile,
            @as(usize, @bitCast(@as(isize, outfd))),
            @as(usize, @bitCast(@as(isize, infd))),
            @intFromPtr(offset),
            count,
        );
    }
}

pub fn socketpair(domain: i32, socket_type: i32, protocol: i32, fd: *[2]i32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.socketpair, &[4]usize{ @as(usize, @intCast(domain)), @as(usize, @intCast(socket_type)), @as(usize, @intCast(protocol)), @intFromPtr(fd) });
    }
    return syscall4(.socketpair, @as(usize, @intCast(domain)), @as(usize, @intCast(socket_type)), @as(usize, @intCast(protocol)), @intFromPtr(fd));
}

pub fn accept(fd: i32, noalias addr: ?*sockaddr, noalias len: ?*socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.accept, &[4]usize{ fd, addr, len, 0 });
    }
    return accept4(fd, addr, len, 0);
}

pub fn accept4(fd: i32, noalias addr: ?*sockaddr, noalias len: ?*socklen_t, flags: u32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.accept4, &[4]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len), flags });
    }
    return syscall4(.accept4, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len), flags);
}

pub fn fstat(fd: i32, stat_buf: *Stat) usize {
    if (native_arch == .riscv32 or native_arch.isLoongArch()) {
        // riscv32 and loongarch have made the interesting decision to not implement some of
        // the older stat syscalls, including this one.
        @compileError("No fstat syscall on this architecture.");
    } else if (@hasField(SYS, "fstat64")) {
        return syscall2(.fstat64, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(stat_buf));
    } else {
        return syscall2(.fstat, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(stat_buf));
    }
}

pub fn stat(pathname: [*:0]const u8, statbuf: *Stat) usize {
    if (native_arch == .riscv32 or native_arch.isLoongArch()) {
        // riscv32 and loongarch have made the interesting decision to not implement some of
        // the older stat syscalls, including this one.
        @compileError("No stat syscall on this architecture.");
    } else if (@hasField(SYS, "stat64")) {
        return syscall2(.stat64, @intFromPtr(pathname), @intFromPtr(statbuf));
    } else {
        return syscall2(.stat, @intFromPtr(pathname), @intFromPtr(statbuf));
    }
}

pub fn lstat(pathname: [*:0]const u8, statbuf: *Stat) usize {
    if (native_arch == .riscv32 or native_arch.isLoongArch()) {
        // riscv32 and loongarch have made the interesting decision to not implement some of
        // the older stat syscalls, including this one.
        @compileError("No lstat syscall on this architecture.");
    } else if (@hasField(SYS, "lstat64")) {
        return syscall2(.lstat64, @intFromPtr(pathname), @intFromPtr(statbuf));
    } else {
        return syscall2(.lstat, @intFromPtr(pathname), @intFromPtr(statbuf));
    }
}

pub fn fstatat(dirfd: i32, path: [*:0]const u8, stat_buf: *Stat, flags: u32) usize {
    if (native_arch == .riscv32 or native_arch.isLoongArch()) {
        // riscv32 and loongarch have made the interesting decision to not implement some of
        // the older stat syscalls, including this one.
        @compileError("No fstatat syscall on this architecture.");
    } else if (@hasField(SYS, "fstatat64")) {
        return syscall4(.fstatat64, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(stat_buf), flags);
    } else {
        return syscall4(.fstatat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(stat_buf), flags);
    }
}

pub fn statx(dirfd: i32, path: [*:0]const u8, flags: u32, mask: u32, statx_buf: *Statx) usize {
    return syscall5(
        .statx,
        @as(usize, @bitCast(@as(isize, dirfd))),
        @intFromPtr(path),
        flags,
        mask,
        @intFromPtr(statx_buf),
    );
}

pub fn listxattr(path: [*:0]const u8, list: [*]u8, size: usize) usize {
    return syscall3(.listxattr, @intFromPtr(path), @intFromPtr(list), size);
}

pub fn llistxattr(path: [*:0]const u8, list: [*]u8, size: usize) usize {
    return syscall3(.llistxattr, @intFromPtr(path), @intFromPtr(list), size);
}

pub fn flistxattr(fd: fd_t, list: [*]u8, size: usize) usize {
    return syscall3(.flistxattr, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(list), size);
}

pub fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]u8, size: usize) usize {
    return syscall4(.getxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size);
}

pub fn lgetxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]u8, size: usize) usize {
    return syscall4(.lgetxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size);
}

pub fn fgetxattr(fd: fd_t, name: [*:0]const u8, value: [*]u8, size: usize) usize {
    return syscall4(.fgetxattr, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(name), @intFromPtr(value), size);
}

pub fn setxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]const u8, size: usize, flags: usize) usize {
    return syscall5(.setxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size, flags);
}

pub fn lsetxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]const u8, size: usize, flags: usize) usize {
    return syscall5(.lsetxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size, flags);
}

pub fn fsetxattr(fd: fd_t, name: [*:0]const u8, value: [*]const u8, size: usize, flags: usize) usize {
    return syscall5(.fsetxattr, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(name), @intFromPtr(value), size, flags);
}

pub fn removexattr(path: [*:0]const u8, name: [*:0]const u8) usize {
    return syscall2(.removexattr, @intFromPtr(path), @intFromPtr(name));
}

pub fn lremovexattr(path: [*:0]const u8, name: [*:0]const u8) usize {
    return syscall2(.lremovexattr, @intFromPtr(path), @intFromPtr(name));
}

pub fn fremovexattr(fd: usize, name: [*:0]const u8) usize {
    return syscall2(.fremovexattr, fd, @intFromPtr(name));
}

pub const sched_param = extern struct {
    priority: i32,
};

pub const SCHED = packed struct(i32) {
    pub const Mode = enum(u3) {
        /// normal multi-user scheduling
        NORMAL = 0,
        /// FIFO realtime scheduling
        FIFO = 1,
        /// Round-robin realtime scheduling
        RR = 2,
        /// For "batch" style execution of processes
        BATCH = 3,
        /// Low latency scheduling
        IDLE = 5,
        /// Sporadic task model deadline scheduling
        DEADLINE = 6,
    };
    mode: Mode, //bits [0, 2]
    _3: u27 = 0, //bits [3, 29]
    /// set to true to stop children from inheriting policies
    RESET_ON_FORK: bool = false, //bit 30
    _31: u1 = 0, //bit 31
};

pub fn sched_setparam(pid: pid_t, param: *const sched_param) usize {
    return syscall2(.sched_setparam, @as(usize, @bitCast(@as(isize, pid))), @intFromPtr(param));
}

pub fn sched_getparam(pid: pid_t, param: *sched_param) usize {
    return syscall2(.sched_getparam, @as(usize, @bitCast(@as(isize, pid))), @intFromPtr(param));
}

pub fn sched_setscheduler(pid: pid_t, policy: SCHED, param: *const sched_param) usize {
    return syscall3(.sched_setscheduler, @as(usize, @bitCast(@as(isize, pid))), @intCast(@as(u32, @bitCast(policy))), @intFromPtr(param));
}

pub fn sched_getscheduler(pid: pid_t) usize {
    return syscall1(.sched_getscheduler, @as(usize, @bitCast(@as(isize, pid))));
}

pub fn sched_get_priority_max(policy: SCHED) usize {
    return syscall1(.sched_get_priority_max, @intCast(@as(u32, @bitCast(policy))));
}

pub fn sched_get_priority_min(policy: SCHED) usize {
    return syscall1(.sched_get_priority_min, @intCast(@as(u32, @bitCast(policy))));
}

pub fn getcpu(cpu: ?*usize, node: ?*usize) usize {
    return syscall2(.getcpu, @intFromPtr(cpu), @intFromPtr(node));
}

pub const sched_attr = extern struct {
    size: u32 = 48, // Size of this structure
    policy: u32 = 0, // Policy (SCHED_*)
    flags: u64 = 0, // Flags
    nice: u32 = 0, // Nice value (SCHED_OTHER, SCHED_BATCH)
    priority: u32 = 0, // Static priority (SCHED_FIFO, SCHED_RR)
    // Remaining fields are for SCHED_DEADLINE
    runtime: u64 = 0,
    deadline: u64 = 0,
    period: u64 = 0,
};

pub fn sched_setattr(pid: pid_t, attr: *const sched_attr, flags: usize) usize {
    return syscall3(.sched_setattr, @as(usize, @bitCast(@as(isize, pid))), @intFromPtr(attr), flags);
}

pub fn sched_getattr(pid: pid_t, attr: *sched_attr, size: usize, flags: usize) usize {
    return syscall4(.sched_getattr, @as(usize, @bitCast(@as(isize, pid))), @intFromPtr(attr), size, flags);
}

pub fn sched_rr_get_interval(pid: pid_t, tp: *timespec) usize {
    return syscall2(.sched_rr_get_interval, @as(usize, @bitCast(@as(isize, pid))), @intFromPtr(tp));
}

pub fn sched_yield() usize {
    return syscall0(.sched_yield);
}

pub fn sched_getaffinity(pid: pid_t, size: usize, set: *cpu_set_t) usize {
    const rc = syscall3(.sched_getaffinity, @as(usize, @bitCast(@as(isize, pid))), size, @intFromPtr(set));
    if (@as(isize, @bitCast(rc)) < 0) return rc;
    if (rc < size) @memset(@as([*]u8, @ptrCast(set))[rc..size], 0);
    return 0;
}

pub fn sched_setaffinity(pid: pid_t, set: *const cpu_set_t) !void {
    const size = @sizeOf(cpu_set_t);
    const rc = syscall3(.sched_setaffinity, @as(usize, @bitCast(@as(isize, pid))), size, @intFromPtr(set));

    switch (E.init(rc)) {
        .SUCCESS => return,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn epoll_create() usize {
    return epoll_create1(0);
}

pub fn epoll_create1(flags: usize) usize {
    return syscall1(.epoll_create1, flags);
}

pub fn epoll_ctl(epoll_fd: i32, op: u32, fd: i32, ev: ?*epoll_event) usize {
    return syscall4(.epoll_ctl, @as(usize, @bitCast(@as(isize, epoll_fd))), @as(usize, @intCast(op)), @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(ev));
}

pub fn epoll_wait(epoll_fd: i32, events: [*]epoll_event, maxevents: u32, timeout: i32) usize {
    return epoll_pwait(epoll_fd, events, maxevents, timeout, null);
}

pub fn epoll_pwait(epoll_fd: i32, events: [*]epoll_event, maxevents: u32, timeout: i32, sigmask: ?*const sigset_t) usize {
    return syscall6(
        .epoll_pwait,
        @as(usize, @bitCast(@as(isize, epoll_fd))),
        @intFromPtr(events),
        @as(usize, @intCast(maxevents)),
        @as(usize, @bitCast(@as(isize, timeout))),
        @intFromPtr(sigmask),
        NSIG / 8,
    );
}

pub fn eventfd(count: u32, flags: u32) usize {
    return syscall2(.eventfd2, count, flags);
}

pub fn timerfd_create(clockid: timerfd_clockid_t, flags: TFD) usize {
    return syscall2(
        .timerfd_create,
        @intFromEnum(clockid),
        @as(u32, @bitCast(flags)),
    );
}

pub const itimerspec = extern struct {
    it_interval: timespec,
    it_value: timespec,
};

pub fn timerfd_gettime(fd: i32, curr_value: *itimerspec) usize {
    return syscall2(.timerfd_gettime, @bitCast(@as(isize, fd)), @intFromPtr(curr_value));
}

pub fn timerfd_settime(fd: i32, flags: TFD.TIMER, new_value: *const itimerspec, old_value: ?*itimerspec) usize {
    return syscall4(.timerfd_settime, @bitCast(@as(isize, fd)), @as(u32, @bitCast(flags)), @intFromPtr(new_value), @intFromPtr(old_value));
}

// Flags for the 'setitimer' system call
pub const ITIMER = enum(i32) {
    REAL = 0,
    VIRTUAL = 1,
    PROF = 2,
};

pub fn getitimer(which: i32, curr_value: *itimerspec) usize {
    return syscall2(.getitimer, @as(usize, @bitCast(@as(isize, which))), @intFromPtr(curr_value));
}

pub fn setitimer(which: i32, new_value: *const itimerspec, old_value: ?*itimerspec) usize {
    return syscall3(.setitimer, @as(usize, @bitCast(@as(isize, which))), @intFromPtr(new_value), @intFromPtr(old_value));
}

pub fn unshare(flags: usize) usize {
    return syscall1(.unshare, flags);
}

pub fn capget(hdrp: *cap_user_header_t, datap: *cap_user_data_t) usize {
    return syscall2(.capget, @intFromPtr(hdrp), @intFromPtr(datap));
}

pub fn capset(hdrp: *cap_user_header_t, datap: *const cap_user_data_t) usize {
    return syscall2(.capset, @intFromPtr(hdrp), @intFromPtr(datap));
}

pub fn sigaltstack(ss: ?*stack_t, old_ss: ?*stack_t) usize {
    return syscall2(.sigaltstack, @intFromPtr(ss), @intFromPtr(old_ss));
}

pub fn uname(uts: *utsname) usize {
    return syscall1(.uname, @intFromPtr(uts));
}

pub fn io_uring_setup(entries: u32, p: *io_uring_params) usize {
    return syscall2(.io_uring_setup, entries, @intFromPtr(p));
}

pub fn io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32, sig: ?*sigset_t) usize {
    return syscall6(.io_uring_enter, @as(usize, @bitCast(@as(isize, fd))), to_submit, min_complete, flags, @intFromPtr(sig), NSIG / 8);
}

pub fn io_uring_register(fd: i32, opcode: IORING_REGISTER, arg: ?*const anyopaque, nr_args: u32) usize {
    return syscall4(.io_uring_register, @as(usize, @bitCast(@as(isize, fd))), @intFromEnum(opcode), @intFromPtr(arg), nr_args);
}

pub fn memfd_create(name: [*:0]const u8, flags: u32) usize {
    return syscall2(.memfd_create, @intFromPtr(name), flags);
}

pub fn getrusage(who: i32, usage: *rusage) usize {
    return syscall2(.getrusage, @as(usize, @bitCast(@as(isize, who))), @intFromPtr(usage));
}

pub fn tcgetattr(fd: fd_t, termios_p: *termios) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.CGETS, @intFromPtr(termios_p));
}

pub fn tcsetattr(fd: fd_t, optional_action: TCSA, termios_p: *const termios) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.CSETS + @intFromEnum(optional_action), @intFromPtr(termios_p));
}

pub fn tcgetpgrp(fd: fd_t, pgrp: *pid_t) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.IOCGPGRP, @intFromPtr(pgrp));
}

pub fn tcsetpgrp(fd: fd_t, pgrp: *const pid_t) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.IOCSPGRP, @intFromPtr(pgrp));
}

pub fn tcdrain(fd: fd_t) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.CSBRK, 1);
}

pub fn ioctl(fd: fd_t, request: u32, arg: usize) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), request, arg);
}

pub fn signalfd(fd: fd_t, mask: *const sigset_t, flags: u32) usize {
    return syscall4(.signalfd4, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(mask), NSIG / 8, flags);
}

pub fn copy_file_range(fd_in: fd_t, off_in: ?*i64, fd_out: fd_t, off_out: ?*i64, len: usize, flags: u32) usize {
    return syscall6(
        .copy_file_range,
        @as(usize, @bitCast(@as(isize, fd_in))),
        @intFromPtr(off_in),
        @as(usize, @bitCast(@as(isize, fd_out))),
        @intFromPtr(off_out),
        len,
        flags,
    );
}

pub fn bpf(cmd: BPF.Cmd, attr: *BPF.Attr, size: u32) usize {
    return syscall3(.bpf, @intFromEnum(cmd), @intFromPtr(attr), size);
}

pub fn sync() void {
    _ = syscall0(.sync);
}

pub fn syncfs(fd: fd_t) usize {
    return syscall1(.syncfs, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn fsync(fd: fd_t) usize {
    return syscall1(.fsync, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn fdatasync(fd: fd_t) usize {
    return syscall1(.fdatasync, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return syscall5(.prctl, @as(usize, @bitCast(@as(isize, option))), arg2, arg3, arg4, arg5);
}

pub fn getrlimit(resource: rlimit_resource, rlim: *rlimit) usize {
    // use prlimit64 to have 64 bit limits on 32 bit platforms
    return prlimit(0, resource, null, rlim);
}

pub fn setrlimit(resource: rlimit_resource, rlim: *const rlimit) usize {
    // use prlimit64 to have 64 bit limits on 32 bit platforms
    return prlimit(0, resource, rlim, null);
}

pub fn prlimit(pid: pid_t, resource: rlimit_resource, new_limit: ?*const rlimit, old_limit: ?*rlimit) usize {
    return syscall4(
        .prlimit64,
        @as(usize, @bitCast(@as(isize, pid))),
        @as(usize, @bitCast(@as(isize, @intFromEnum(resource)))),
        @intFromPtr(new_limit),
        @intFromPtr(old_limit),
    );
}

pub fn mincore(address: [*]u8, len: usize, vec: [*]u8) usize {
    return syscall3(.mincore, @intFromPtr(address), len, @intFromPtr(vec));
}

pub fn madvise(address: [*]u8, len: usize, advice: u32) usize {
    return syscall3(.madvise, @intFromPtr(address), len, advice);
}

pub fn pidfd_open(pid: pid_t, flags: u32) usize {
    return syscall2(.pidfd_open, @as(usize, @bitCast(@as(isize, pid))), flags);
}

pub fn pidfd_getfd(pidfd: fd_t, targetfd: fd_t, flags: u32) usize {
    return syscall3(
        .pidfd_getfd,
        @as(usize, @bitCast(@as(isize, pidfd))),
        @as(usize, @bitCast(@as(isize, targetfd))),
        flags,
    );
}

pub fn pidfd_send_signal(pidfd: fd_t, sig: i32, info: ?*siginfo_t, flags: u32) usize {
    return syscall4(
        .pidfd_send_signal,
        @as(usize, @bitCast(@as(isize, pidfd))),
        @as(usize, @bitCast(@as(isize, sig))),
        @intFromPtr(info),
        flags,
    );
}

pub fn process_vm_readv(pid: pid_t, local: []const iovec, remote: []const iovec_const, flags: usize) usize {
    return syscall6(
        .process_vm_readv,
        @as(usize, @bitCast(@as(isize, pid))),
        @intFromPtr(local.ptr),
        local.len,
        @intFromPtr(remote.ptr),
        remote.len,
        flags,
    );
}

pub fn process_vm_writev(pid: pid_t, local: []const iovec_const, remote: []const iovec_const, flags: usize) usize {
    return syscall6(
        .process_vm_writev,
        @as(usize, @bitCast(@as(isize, pid))),
        @intFromPtr(local.ptr),
        local.len,
        @intFromPtr(remote.ptr),
        remote.len,
        flags,
    );
}

pub fn fadvise(fd: fd_t, offset: i64, len: i64, advice: usize) usize {
    if (comptime native_arch.isArm() or native_arch.isPowerPC32()) {
        // These architectures reorder the arguments so that a register is not skipped to align the
        // register number that `offset` is passed in.

        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(len);

        return syscall6(
            .fadvise64_64,
            @as(usize, @bitCast(@as(isize, fd))),
            advice,
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
        );
    } else if (native_arch.isMIPS32()) {
        // MIPS O32 does not deal with the register alignment issue, so pass a dummy value.

        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(len);

        return syscall7(
            .fadvise64,
            @as(usize, @bitCast(@as(isize, fd))),
            0,
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
            advice,
        );
    } else if (comptime usize_bits < 64) {
        // Other 32-bit architectures do not require register alignment.

        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(len);

        return syscall6(
            switch (builtin.abi) {
                .gnuabin32, .gnux32, .muslabin32, .muslx32 => .fadvise64,
                else => .fadvise64_64,
            },
            @as(usize, @bitCast(@as(isize, fd))),
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
            advice,
        );
    } else {
        // On 64-bit architectures, fadvise64_64 and fadvise64 are the same. Generally, older ports
        // call it fadvise64 (x86, PowerPC, etc), while newer ports call it fadvise64_64 (RISC-V,
        // LoongArch, etc). SPARC is the odd one out because it has both.
        return syscall4(
            if (@hasField(SYS, "fadvise64_64")) .fadvise64_64 else .fadvise64,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(offset)),
            @as(usize, @bitCast(len)),
            advice,
        );
    }
}

pub fn perf_event_open(
    attr: *perf_event_attr,
    pid: pid_t,
    cpu: i32,
    group_fd: fd_t,
    flags: usize,
) usize {
    return syscall5(
        .perf_event_open,
        @intFromPtr(attr),
        @as(usize, @bitCast(@as(isize, pid))),
        @as(usize, @bitCast(@as(isize, cpu))),
        @as(usize, @bitCast(@as(isize, group_fd))),
        flags,
    );
}

pub fn seccomp(operation: u32, flags: u32, args: ?*const anyopaque) usize {
    return syscall3(.seccomp, operation, flags, @intFromPtr(args));
}

pub fn ptrace(
    req: u32,
    pid: pid_t,
    addr: usize,
    data: usize,
    addr2: usize,
) usize {
    return syscall5(
        .ptrace,
        req,
        @as(usize, @bitCast(@as(isize, pid))),
        addr,
        data,
        addr2,
    );
}

/// Query the page cache statistics of a file.
pub fn cachestat(
    /// The open file descriptor to retrieve statistics from.
    fd: fd_t,
    /// The byte range in `fd` to query.
    /// When `len > 0`, the range is `[off..off + len]`.
    /// When `len` == 0, the range is from `off` to the end of `fd`.
    cstat_range: *const cache_stat_range,
    /// The structure where page cache statistics are stored.
    cstat: *cache_stat,
    /// Currently unused, and must be set to `0`.
    flags: u32,
) usize {
    return syscall4(
        .cachestat,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(cstat_range),
        @intFromPtr(cstat),
        flags,
    );
}

pub fn map_shadow_stack(addr: u64, size: u64, flags: u32) usize {
    return syscall3(.map_shadow_stack, addr, size, flags);
}

pub const Sysinfo = switch (native_abi) {
    .gnux32, .muslx32 => extern struct {
        /// Seconds since boot
        uptime: i64,
        /// 1, 5, and 15 minute load averages
        loads: [3]u64,
        /// Total usable main memory size
        totalram: u64,
        /// Available memory size
        freeram: u64,
        /// Amount of shared memory
        sharedram: u64,
        /// Memory used by buffers
        bufferram: u64,
        /// Total swap space size
        totalswap: u64,
        /// swap space still available
        freeswap: u64,
        /// Number of current processes
        procs: u16,
        /// Explicit padding for m68k
        pad: u16,
        /// Total high memory size
        totalhigh: u64,
        /// Available high memory size
        freehigh: u64,
        /// Memory unit size in bytes
        mem_unit: u32,
    },
    else => extern struct {
        /// Seconds since boot
        uptime: isize,
        /// 1, 5, and 15 minute load averages
        loads: [3]usize,
        /// Total usable main memory size
        totalram: usize,
        /// Available memory size
        freeram: usize,
        /// Amount of shared memory
        sharedram: usize,
        /// Memory used by buffers
        bufferram: usize,
        /// Total swap space size
        totalswap: usize,
        /// swap space still available
        freeswap: usize,
        /// Number of current processes
        procs: u16,
        /// Explicit padding for m68k
        pad: u16,
        /// Total high memory size
        totalhigh: usize,
        /// Available high memory size
        freehigh: usize,
        /// Memory unit size in bytes
        mem_unit: u32,
        /// Pad
        _f: [20 - 2 * @sizeOf(usize) - @sizeOf(u32)]u8,
    },
};

pub fn sysinfo(info: *Sysinfo) usize {
    return syscall1(.sysinfo, @intFromPtr(info));
}

pub const E = switch (native_arch) {
    .mips, .mipsel, .mips64, .mips64el => enum(u16) {
        /// No error occurred.
        SUCCESS = 0,

        PERM = 1,
        NOENT = 2,
        SRCH = 3,
        INTR = 4,
        IO = 5,
        NXIO = 6,
        @"2BIG" = 7,
        NOEXEC = 8,
        BADF = 9,
        CHILD = 10,
        /// Also used for WOULDBLOCK.
        AGAIN = 11,
        NOMEM = 12,
        ACCES = 13,
        FAULT = 14,
        NOTBLK = 15,
        BUSY = 16,
        EXIST = 17,
        XDEV = 18,
        NODEV = 19,
        NOTDIR = 20,
        ISDIR = 21,
        INVAL = 22,
        NFILE = 23,
        MFILE = 24,
        NOTTY = 25,
        TXTBSY = 26,
        FBIG = 27,
        NOSPC = 28,
        SPIPE = 29,
        ROFS = 30,
        MLINK = 31,
        PIPE = 32,
        DOM = 33,
        RANGE = 34,

        NOMSG = 35,
        IDRM = 36,
        CHRNG = 37,
        L2NSYNC = 38,
        L3HLT = 39,
        L3RST = 40,
        LNRNG = 41,
        UNATCH = 42,
        NOCSI = 43,
        L2HLT = 44,
        DEADLK = 45,
        NOLCK = 46,
        BADE = 50,
        BADR = 51,
        XFULL = 52,
        NOANO = 53,
        BADRQC = 54,
        BADSLT = 55,
        DEADLOCK = 56,
        BFONT = 59,
        NOSTR = 60,
        NODATA = 61,
        TIME = 62,
        NOSR = 63,
        NONET = 64,
        NOPKG = 65,
        REMOTE = 66,
        NOLINK = 67,
        ADV = 68,
        SRMNT = 69,
        COMM = 70,
        PROTO = 71,
        DOTDOT = 73,
        MULTIHOP = 74,
        BADMSG = 77,
        NAMETOOLONG = 78,
        OVERFLOW = 79,
        NOTUNIQ = 80,
        BADFD = 81,
        REMCHG = 82,
        LIBACC = 83,
        LIBBAD = 84,
        LIBSCN = 85,
        LIBMAX = 86,
        LIBEXEC = 87,
        ILSEQ = 88,
        NOSYS = 89,
        LOOP = 90,
        RESTART = 91,
        STRPIPE = 92,
        NOTEMPTY = 93,
        USERS = 94,
        NOTSOCK = 95,
        DESTADDRREQ = 96,
        MSGSIZE = 97,
        PROTOTYPE = 98,
        NOPROTOOPT = 99,
        PROTONOSUPPORT = 120,
        SOCKTNOSUPPORT = 121,
        OPNOTSUPP = 122,
        PFNOSUPPORT = 123,
        AFNOSUPPORT = 124,
        ADDRINUSE = 125,
        ADDRNOTAVAIL = 126,
        NETDOWN = 127,
        NETUNREACH = 128,
        NETRESET = 129,
        CONNABORTED = 130,
        CONNRESET = 131,
        NOBUFS = 132,
        ISCONN = 133,
        NOTCONN = 134,
        UCLEAN = 135,
        NOTNAM = 137,
        NAVAIL = 138,
        ISNAM = 139,
        REMOTEIO = 140,
        SHUTDOWN = 143,
        TOOMANYREFS = 144,
        TIMEDOUT = 145,
        CONNREFUSED = 146,
        HOSTDOWN = 147,
        HOSTUNREACH = 148,
        ALREADY = 149,
        INPROGRESS = 150,
        STALE = 151,
        CANCELED = 158,
        NOMEDIUM = 159,
        MEDIUMTYPE = 160,
        NOKEY = 161,
        KEYEXPIRED = 162,
        KEYREVOKED = 163,
        KEYREJECTED = 164,
        OWNERDEAD = 165,
        NOTRECOVERABLE = 166,
        RFKILL = 167,
        HWPOISON = 168,
        DQUOT = 1133,
        _,

        pub const init = errnoFromSyscall;
    },
    .sparc, .sparc64 => enum(u16) {
        /// No error occurred.
        SUCCESS = 0,

        PERM = 1,
        NOENT = 2,
        SRCH = 3,
        INTR = 4,
        IO = 5,
        NXIO = 6,
        @"2BIG" = 7,
        NOEXEC = 8,
        BADF = 9,
        CHILD = 10,
        /// Also used for WOULDBLOCK
        AGAIN = 11,
        NOMEM = 12,
        ACCES = 13,
        FAULT = 14,
        NOTBLK = 15,
        BUSY = 16,
        EXIST = 17,
        XDEV = 18,
        NODEV = 19,
        NOTDIR = 20,
        ISDIR = 21,
        INVAL = 22,
        NFILE = 23,
        MFILE = 24,
        NOTTY = 25,
        TXTBSY = 26,
        FBIG = 27,
        NOSPC = 28,
        SPIPE = 29,
        ROFS = 30,
        MLINK = 31,
        PIPE = 32,
        DOM = 33,
        RANGE = 34,

        INPROGRESS = 36,
        ALREADY = 37,
        NOTSOCK = 38,
        DESTADDRREQ = 39,
        MSGSIZE = 40,
        PROTOTYPE = 41,
        NOPROTOOPT = 42,
        PROTONOSUPPORT = 43,
        SOCKTNOSUPPORT = 44,
        /// Also used for NOTSUP
        OPNOTSUPP = 45,
        PFNOSUPPORT = 46,
        AFNOSUPPORT = 47,
        ADDRINUSE = 48,
        ADDRNOTAVAIL = 49,
        NETDOWN = 50,
        NETUNREACH = 51,
        NETRESET = 52,
        CONNABORTED = 53,
        CONNRESET = 54,
        NOBUFS = 55,
        ISCONN = 56,
        NOTCONN = 57,
        SHUTDOWN = 58,
        TOOMANYREFS = 59,
        TIMEDOUT = 60,
        CONNREFUSED = 61,
        LOOP = 62,
        NAMETOOLONG = 63,
        HOSTDOWN = 64,
        HOSTUNREACH = 65,
        NOTEMPTY = 66,
        PROCLIM = 67,
        USERS = 68,
        DQUOT = 69,
        STALE = 70,
        REMOTE = 71,
        NOSTR = 72,
        TIME = 73,
        NOSR = 74,
        NOMSG = 75,
        BADMSG = 76,
        IDRM = 77,
        DEADLK = 78,
        NOLCK = 79,
        NONET = 80,
        RREMOTE = 81,
        NOLINK = 82,
        ADV = 83,
        SRMNT = 84,
        COMM = 85,
        PROTO = 86,
        MULTIHOP = 87,
        DOTDOT = 88,
        REMCHG = 89,
        NOSYS = 90,
        STRPIPE = 91,
        OVERFLOW = 92,
        BADFD = 93,
        CHRNG = 94,
        L2NSYNC = 95,
        L3HLT = 96,
        L3RST = 97,
        LNRNG = 98,
        UNATCH = 99,
        NOCSI = 100,
        L2HLT = 101,
        BADE = 102,
        BADR = 103,
        XFULL = 104,
        NOANO = 105,
        BADRQC = 106,
        BADSLT = 107,
        DEADLOCK = 108,
        BFONT = 109,
        LIBEXEC = 110,
        NODATA = 111,
        LIBBAD = 112,
        NOPKG = 113,
        LIBACC = 114,
        NOTUNIQ = 115,
        RESTART = 116,
        UCLEAN = 117,
        NOTNAM = 118,
        NAVAIL = 119,
        ISNAM = 120,
        REMOTEIO = 121,
        ILSEQ = 122,
        LIBMAX = 123,
        LIBSCN = 124,
        NOMEDIUM = 125,
        MEDIUMTYPE = 126,
        CANCELED = 127,
        NOKEY = 128,
        KEYEXPIRED = 129,
        KEYREVOKED = 130,
        KEYREJECTED = 131,
        OWNERDEAD = 132,
        NOTRECOVERABLE = 133,
        RFKILL = 134,
        HWPOISON = 135,
        _,

        pub const init = errnoFromSyscall;
    },
    else => enum(u16) {
        /// No error occurred.
        /// Same code used for `NSROK`.
        SUCCESS = 0,
        /// Operation not permitted
        PERM = 1,
        /// No such file or directory
        NOENT = 2,
        /// No such process
        SRCH = 3,
        /// Interrupted system call
        INTR = 4,
        /// I/O error
        IO = 5,
        /// No such device or address
        NXIO = 6,
        /// Arg list too long
        @"2BIG" = 7,
        /// Exec format error
        NOEXEC = 8,
        /// Bad file number
        BADF = 9,
        /// No child processes
        CHILD = 10,
        /// Try again
        /// Also means: WOULDBLOCK: operation would block
        AGAIN = 11,
        /// Out of memory
        NOMEM = 12,
        /// Permission denied
        ACCES = 13,
        /// Bad address
        FAULT = 14,
        /// Block device required
        NOTBLK = 15,
        /// Device or resource busy
        BUSY = 16,
        /// File exists
        EXIST = 17,
        /// Cross-device link
        XDEV = 18,
        /// No such device
        NODEV = 19,
        /// Not a directory
        NOTDIR = 20,
        /// Is a directory
        ISDIR = 21,
        /// Invalid argument
        INVAL = 22,
        /// File table overflow
        NFILE = 23,
        /// Too many open files
        MFILE = 24,
        /// Not a typewriter
        NOTTY = 25,
        /// Text file busy
        TXTBSY = 26,
        /// File too large
        FBIG = 27,
        /// No space left on device
        NOSPC = 28,
        /// Illegal seek
        SPIPE = 29,
        /// Read-only file system
        ROFS = 30,
        /// Too many links
        MLINK = 31,
        /// Broken pipe
        PIPE = 32,
        /// Math argument out of domain of func
        DOM = 33,
        /// Math result not representable
        RANGE = 34,
        /// Resource deadlock would occur
        DEADLK = 35,
        /// File name too long
        NAMETOOLONG = 36,
        /// No record locks available
        NOLCK = 37,
        /// Function not implemented
        NOSYS = 38,
        /// Directory not empty
        NOTEMPTY = 39,
        /// Too many symbolic links encountered
        LOOP = 40,
        /// No message of desired type
        NOMSG = 42,
        /// Identifier removed
        IDRM = 43,
        /// Channel number out of range
        CHRNG = 44,
        /// Level 2 not synchronized
        L2NSYNC = 45,
        /// Level 3 halted
        L3HLT = 46,
        /// Level 3 reset
        L3RST = 47,
        /// Link number out of range
        LNRNG = 48,
        /// Protocol driver not attached
        UNATCH = 49,
        /// No CSI structure available
        NOCSI = 50,
        /// Level 2 halted
        L2HLT = 51,
        /// Invalid exchange
        BADE = 52,
        /// Invalid request descriptor
        BADR = 53,
        /// Exchange full
        XFULL = 54,
        /// No anode
        NOANO = 55,
        /// Invalid request code
        BADRQC = 56,
        /// Invalid slot
        BADSLT = 57,
        /// Bad font file format
        BFONT = 59,
        /// Device not a stream
        NOSTR = 60,
        /// No data available
        NODATA = 61,
        /// Timer expired
        TIME = 62,
        /// Out of streams resources
        NOSR = 63,
        /// Machine is not on the network
        NONET = 64,
        /// Package not installed
        NOPKG = 65,
        /// Object is remote
        REMOTE = 66,
        /// Link has been severed
        NOLINK = 67,
        /// Advertise error
        ADV = 68,
        /// Srmount error
        SRMNT = 69,
        /// Communication error on send
        COMM = 70,
        /// Protocol error
        PROTO = 71,
        /// Multihop attempted
        MULTIHOP = 72,
        /// RFS specific error
        DOTDOT = 73,
        /// Not a data message
        BADMSG = 74,
        /// Value too large for defined data type
        OVERFLOW = 75,
        /// Name not unique on network
        NOTUNIQ = 76,
        /// File descriptor in bad state
        BADFD = 77,
        /// Remote address changed
        REMCHG = 78,
        /// Can not access a needed shared library
        LIBACC = 79,
        /// Accessing a corrupted shared library
        LIBBAD = 80,
        /// .lib section in a.out corrupted
        LIBSCN = 81,
        /// Attempting to link in too many shared libraries
        LIBMAX = 82,
        /// Cannot exec a shared library directly
        LIBEXEC = 83,
        /// Illegal byte sequence
        ILSEQ = 84,
        /// Interrupted system call should be restarted
        RESTART = 85,
        /// Streams pipe error
        STRPIPE = 86,
        /// Too many users
        USERS = 87,
        /// Socket operation on non-socket
        NOTSOCK = 88,
        /// Destination address required
        DESTADDRREQ = 89,
        /// Message too long
        MSGSIZE = 90,
        /// Protocol wrong type for socket
        PROTOTYPE = 91,
        /// Protocol not available
        NOPROTOOPT = 92,
        /// Protocol not supported
        PROTONOSUPPORT = 93,
        /// Socket type not supported
        SOCKTNOSUPPORT = 94,
        /// Operation not supported on transport endpoint
        /// This code also means `NOTSUP`.
        OPNOTSUPP = 95,
        /// Protocol family not supported
        PFNOSUPPORT = 96,
        /// Address family not supported by protocol
        AFNOSUPPORT = 97,
        /// Address already in use
        ADDRINUSE = 98,
        /// Cannot assign requested address
        ADDRNOTAVAIL = 99,
        /// Network is down
        NETDOWN = 100,
        /// Network is unreachable
        NETUNREACH = 101,
        /// Network dropped connection because of reset
        NETRESET = 102,
        /// Software caused connection abort
        CONNABORTED = 103,
        /// Connection reset by peer
        CONNRESET = 104,
        /// No buffer space available
        NOBUFS = 105,
        /// Transport endpoint is already connected
        ISCONN = 106,
        /// Transport endpoint is not connected
        NOTCONN = 107,
        /// Cannot send after transport endpoint shutdown
        SHUTDOWN = 108,
        /// Too many references: cannot splice
        TOOMANYREFS = 109,
        /// Connection timed out
        TIMEDOUT = 110,
        /// Connection refused
        CONNREFUSED = 111,
        /// Host is down
        HOSTDOWN = 112,
        /// No route to host
        HOSTUNREACH = 113,
        /// Operation already in progress
        ALREADY = 114,
        /// Operation now in progress
        INPROGRESS = 115,
        /// Stale NFS file handle
        STALE = 116,
        /// Structure needs cleaning
        UCLEAN = 117,
        /// Not a XENIX named type file
        NOTNAM = 118,
        /// No XENIX semaphores available
        NAVAIL = 119,
        /// Is a named type file
        ISNAM = 120,
        /// Remote I/O error
        REMOTEIO = 121,
        /// Quota exceeded
        DQUOT = 122,
        /// No medium found
        NOMEDIUM = 123,
        /// Wrong medium type
        MEDIUMTYPE = 124,
        /// Operation canceled
        CANCELED = 125,
        /// Required key not available
        NOKEY = 126,
        /// Key has expired
        KEYEXPIRED = 127,
        /// Key has been revoked
        KEYREVOKED = 128,
        /// Key was rejected by service
        KEYREJECTED = 129,
        // for robust mutexes
        /// Owner died
        OWNERDEAD = 130,
        /// State not recoverable
        NOTRECOVERABLE = 131,
        /// Operation not possible due to RF-kill
        RFKILL = 132,
        /// Memory page has hardware error
        HWPOISON = 133,
        // nameserver query return codes
        /// DNS server returned answer with no data
        NSRNODATA = 160,
        /// DNS server claims query was misformatted
        NSRFORMERR = 161,
        /// DNS server returned general failure
        NSRSERVFAIL = 162,
        /// Domain name not found
        NSRNOTFOUND = 163,
        /// DNS server does not implement requested operation
        NSRNOTIMP = 164,
        /// DNS server refused query
        NSRREFUSED = 165,
        /// Misformatted DNS query
        NSRBADQUERY = 166,
        /// Misformatted domain name
        NSRBADNAME = 167,
        /// Unsupported address family
        NSRBADFAMILY = 168,
        /// Misformatted DNS reply
        NSRBADRESP = 169,
        /// Could not contact DNS servers
        NSRCONNREFUSED = 170,
        /// Timeout while contacting DNS servers
        NSRTIMEOUT = 171,
        /// End of file
        NSROF = 172,
        /// Error reading file
        NSRFILE = 173,
        /// Out of memory
        NSRNOMEM = 174,
        /// Application terminated lookup
        NSRDESTRUCTION = 175,
        /// Domain name is too long
        NSRQUERYDOMAINTOOLONG = 176,
        /// Domain name is too long
        NSRCNAMELOOP = 177,

        _,

        pub const init = errnoFromSyscall;
    },
};

pub const pid_t = i32;
pub const fd_t = i32;
pub const socket_t = i32;
pub const uid_t = u32;
pub const gid_t = u32;
pub const clock_t = isize;

pub const NAME_MAX = 255;
pub const PATH_MAX = 4096;
pub const IOV_MAX = 1024;

/// Largest hardware address length
/// e.g. a mac address is a type of hardware address
pub const MAX_ADDR_LEN = 32;

pub const STDIN_FILENO = 0;
pub const STDOUT_FILENO = 1;
pub const STDERR_FILENO = 2;

pub const AT = struct {
    /// Special value used to indicate openat should use the current working directory
    pub const FDCWD = -100;

    /// Do not follow symbolic links
    pub const SYMLINK_NOFOLLOW = 0x100;

    /// Remove directory instead of unlinking file
    pub const REMOVEDIR = 0x200;

    /// Follow symbolic links.
    pub const SYMLINK_FOLLOW = 0x400;

    /// Suppress terminal automount traversal
    pub const NO_AUTOMOUNT = 0x800;

    /// Allow empty relative pathname
    pub const EMPTY_PATH = 0x1000;

    /// Type of synchronisation required from statx()
    pub const STATX_SYNC_TYPE = 0x6000;

    /// - Do whatever stat() does
    pub const STATX_SYNC_AS_STAT = 0x0000;

    /// - Force the attributes to be sync'd with the server
    pub const STATX_FORCE_SYNC = 0x2000;

    /// - Don't sync attributes with the server
    pub const STATX_DONT_SYNC = 0x4000;

    /// Apply to the entire subtree
    pub const RECURSIVE = 0x8000;

    pub const HANDLE_FID = REMOVEDIR;
};

pub const FALLOC = struct {
    /// Default is extend size
    pub const FL_KEEP_SIZE = 0x01;

    /// De-allocates range
    pub const FL_PUNCH_HOLE = 0x02;

    /// Reserved codepoint
    pub const FL_NO_HIDE_STALE = 0x04;

    /// Removes a range of a file without leaving a hole in the file
    pub const FL_COLLAPSE_RANGE = 0x08;

    /// Converts a range of file to zeros preferably without issuing data IO
    pub const FL_ZERO_RANGE = 0x10;

    /// Inserts space within the file size without overwriting any existing data
    pub const FL_INSERT_RANGE = 0x20;

    /// Unshares shared blocks within the file size without overwriting any existing data
    pub const FL_UNSHARE_RANGE = 0x40;
};

pub const FUTEX = struct {
    pub const WAIT = 0;
    pub const WAKE = 1;
    pub const FD = 2;
    pub const REQUEUE = 3;
    pub const CMP_REQUEUE = 4;
    pub const WAKE_OP = 5;
    pub const LOCK_PI = 6;
    pub const UNLOCK_PI = 7;
    pub const TRYLOCK_PI = 8;
    pub const WAIT_BITSET = 9;
    pub const WAKE_BITSET = 10;
    pub const WAIT_REQUEUE_PI = 11;
    pub const CMP_REQUEUE_PI = 12;

    pub const PRIVATE_FLAG = 128;

    pub const CLOCK_REALTIME = 256;

    /// Max numbers of elements in a `futex_waitv` array.
    pub const WAITV_MAX = 128;
};

pub const FUTEX2 = struct {
    pub const SIZE_U8 = 0x00;
    pub const SIZE_U16 = 0x01;
    pub const SIZE_U32 = 0x02;
    pub const SIZE_U64 = 0x03;
    pub const NUMA = 0x04;

    pub const PRIVATE = FUTEX.PRIVATE_FLAG;
};

pub const PROT = struct {
    /// page can not be accessed
    pub const NONE = 0x0;
    /// page can be read
    pub const READ = 0x1;
    /// page can be written
    pub const WRITE = 0x2;
    /// page can be executed
    pub const EXEC = 0x4;
    /// page may be used for atomic ops
    pub const SEM = switch (native_arch) {
        // TODO: also xtensa
        .mips, .mipsel, .mips64, .mips64el => 0x10,
        else => 0x8,
    };
    /// mprotect flag: extend change to start of growsdown vma
    pub const GROWSDOWN = 0x01000000;
    /// mprotect flag: extend change to end of growsup vma
    pub const GROWSUP = 0x02000000;
};

pub const FD_CLOEXEC = 1;

pub const F_OK = 0;
pub const X_OK = 1;
pub const W_OK = 2;
pub const R_OK = 4;

pub const W = struct {
    pub const NOHANG = 1;
    pub const UNTRACED = 2;
    pub const STOPPED = 2;
    pub const EXITED = 4;
    pub const CONTINUED = 8;
    pub const NOWAIT = 0x1000000;

    pub fn EXITSTATUS(s: u32) u8 {
        return @as(u8, @intCast((s & 0xff00) >> 8));
    }
    pub fn TERMSIG(s: u32) u32 {
        return s & 0x7f;
    }
    pub fn STOPSIG(s: u32) u32 {
        return EXITSTATUS(s);
    }
    pub fn IFEXITED(s: u32) bool {
        return TERMSIG(s) == 0;
    }
    pub fn IFSTOPPED(s: u32) bool {
        return @as(u16, @truncate(((s & 0xffff) *% 0x10001) >> 8)) > 0x7f00;
    }
    pub fn IFSIGNALED(s: u32) bool {
        return (s & 0xffff) -% 1 < 0xff;
    }
};

// waitid id types
pub const P = enum(c_uint) {
    ALL = 0,
    PID = 1,
    PGID = 2,
    PIDFD = 3,
    _,
};

pub const SA = if (is_mips) struct {
    pub const NOCLDSTOP = 1;
    pub const NOCLDWAIT = 0x10000;
    pub const SIGINFO = 8;
    pub const RESTART = 0x10000000;
    pub const RESETHAND = 0x80000000;
    pub const ONSTACK = 0x08000000;
    pub const NODEFER = 0x40000000;
    pub const RESTORER = 0x04000000;
} else if (is_sparc) struct {
    pub const NOCLDSTOP = 0x8;
    pub const NOCLDWAIT = 0x100;
    pub const SIGINFO = 0x200;
    pub const RESTART = 0x2;
    pub const RESETHAND = 0x4;
    pub const ONSTACK = 0x1;
    pub const NODEFER = 0x20;
    pub const RESTORER = 0x04000000;
} else struct {
    pub const NOCLDSTOP = 1;
    pub const NOCLDWAIT = 2;
    pub const SIGINFO = 4;
    pub const RESTART = 0x10000000;
    pub const RESETHAND = 0x80000000;
    pub const ONSTACK = 0x08000000;
    pub const NODEFER = 0x40000000;
    pub const RESTORER = 0x04000000;
};

pub const SIG = if (is_mips) struct {
    pub const BLOCK = 1;
    pub const UNBLOCK = 2;
    pub const SETMASK = 3;

    pub const HUP = 1;
    pub const INT = 2;
    pub const QUIT = 3;
    pub const ILL = 4;
    pub const TRAP = 5;
    pub const ABRT = 6;
    pub const IOT = ABRT;
    pub const BUS = 7;
    pub const FPE = 8;
    pub const KILL = 9;
    pub const USR1 = 10;
    pub const SEGV = 11;
    pub const USR2 = 12;
    pub const PIPE = 13;
    pub const ALRM = 14;
    pub const TERM = 15;
    pub const STKFLT = 16;
    pub const CHLD = 17;
    pub const CONT = 18;
    pub const STOP = 19;
    pub const TSTP = 20;
    pub const TTIN = 21;
    pub const TTOU = 22;
    pub const URG = 23;
    pub const XCPU = 24;
    pub const XFSZ = 25;
    pub const VTALRM = 26;
    pub const PROF = 27;
    pub const WINCH = 28;
    pub const IO = 29;
    pub const POLL = 29;
    pub const PWR = 30;
    pub const SYS = 31;
    pub const UNUSED = SIG.SYS;

    pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));
    pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
    pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
} else if (is_sparc) struct {
    pub const BLOCK = 1;
    pub const UNBLOCK = 2;
    pub const SETMASK = 4;

    pub const HUP = 1;
    pub const INT = 2;
    pub const QUIT = 3;
    pub const ILL = 4;
    pub const TRAP = 5;
    pub const ABRT = 6;
    pub const EMT = 7;
    pub const FPE = 8;
    pub const KILL = 9;
    pub const BUS = 10;
    pub const SEGV = 11;
    pub const SYS = 12;
    pub const PIPE = 13;
    pub const ALRM = 14;
    pub const TERM = 15;
    pub const URG = 16;
    pub const STOP = 17;
    pub const TSTP = 18;
    pub const CONT = 19;
    pub const CHLD = 20;
    pub const TTIN = 21;
    pub const TTOU = 22;
    pub const POLL = 23;
    pub const XCPU = 24;
    pub const XFSZ = 25;
    pub const VTALRM = 26;
    pub const PROF = 27;
    pub const WINCH = 28;
    pub const LOST = 29;
    pub const USR1 = 30;
    pub const USR2 = 31;
    pub const IOT = ABRT;
    pub const CLD = CHLD;
    pub const PWR = LOST;
    pub const IO = SIG.POLL;

    pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));
    pub const DFL: ?Sigaction.handler_fn = @ptrFrom```
