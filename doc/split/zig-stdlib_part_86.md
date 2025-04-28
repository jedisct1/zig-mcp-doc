```
: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
          [arg4] "{r6}" (arg4),
          [arg5] "{r7}" (arg5),
          [arg6] "{r8}" (arg6),
        : "memory", "cr0", "r9", "r10", "r11", "r12"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         3,    4,     5,     6,   7,    8,   9
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         0          3,     4,     5,    6,   7
    asm volatile (
        \\  # create initial stack frame for new thread
        \\  clrrdi 4, 4, 4
        \\  li     0, 0
        \\  stdu   0,-32(4)
        \\
        \\  # save fn and arg to child stack
        \\  std    3,  8(4)
        \\  std    6, 16(4)
        \\
        \\  # shuffle args into correct registers and call SYS_clone
        \\  mr    3, 5
        \\  #mr   4, 4
        \\  mr    5, 7
        \\  mr    6, 8
        \\  mr    7, 9
        \\  li    0, 120  # SYS_clone = 120
        \\  sc
        \\
        \\  # if error, negate return (errno)
        \\  bns+  1f
        \\  neg   3, 3
        \\
        \\1:
        \\  # if we're the parent, return
        \\  cmpwi cr7, 3, 0
        \\  bnelr cr7
        \\
        \\  # we're the child
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\  .cfi_undefined lr
    );
    asm volatile (
        \\  li    31, 0
        \\  mtlr   0
        \\
        \\  # call fn(arg)
        \\  ld     3, 16(1)
        \\  ld    12,  8(1)
        \\  mtctr 12
        \\  bctrl
        \\
        \\  # call SYS_exit. exit code is already in r3 from fn return value
        \\  li    0, 1    # SYS_exit = 1
        \\  sc
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ sc
        :
        : [number] "{r0}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const GETLK = 5;
    pub const SETLK = 6;
    pub const SETLKW = 7;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__kernel_clock_gettime";
    pub const CGT_VER = "LINUX_2.6.15";
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
    __unused: [4]u8,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: usize,
    control: ?*anyopaque,
    controllen: usize,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: usize,
    control: ?*const anyopaque,
    controllen: usize,
    flags: i32,
};

pub const blksize_t = i64;
pub const nlink_t = u64;
pub const time_t = i64;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    nlink: nlink_t,
    mode: mode_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    size: off_t,
    blksize: blksize_t,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [3]u64,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const timeval = extern struct {
    sec: isize,
    usec: isize,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

pub const greg_t = u64;
pub const gregset_t = [48]greg_t;
pub const fpregset_t = [33]f64;

/// The position of the vscr register depends on endianness.
/// On C, macros are used to change vscr_word's offset to
/// account for this. Here we'll just define vscr_word_le
/// and vscr_word_be. Code must take care to use the correct one.
pub const vrregset = extern struct {
    vrregs: [32][4]u32 align(16),
    vscr_word_le: u32,
    _pad1: [2]u32,
    vscr_word_be: u32,
    vrsave: u32,
    _pad2: [3]u32,
};
pub const vrregset_t = vrregset;

pub const mcontext_t = extern struct {
    __unused: [4]u64,
    signal: i32,
    _pad0: i32,
    handler: u64,
    oldmask: u64,
    regs: ?*anyopaque,
    gp_regs: gregset_t,
    fp_regs: fpregset_t,
    v_regs: *vrregset_t,
    vmx_reserve: [34 + 34 + 32 + 1]i64,
};

pub const ucontext_t = extern struct {
    flags: u32,
    link: ?*ucontext_t,
    stack: stack_t,
    sigmask: sigset_t,
    mcontext: mcontext_t,
};

pub const Elf_Symndx = u32;

/// TODO
pub const getcontext = {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const linux = std.os.linux;
const SYS = linux.SYS;
const uid_t = std.os.linux.uid_t;
const gid_t = std.os.linux.gid_t;
const pid_t = std.os.linux.pid_t;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const timespec = std.os.linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
          [arg4] "{x13}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
          [arg4] "{x13}" (arg4),
          [arg5] "{x14}" (arg5),
        : "memory"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
          [arg4] "{x13}" (arg4),
          [arg5] "{x14}" (arg5),
          [arg6] "{x15}" (arg6),
        : "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         a0,   a1,    a2,    a3,  a4,   a5,  a6
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         a7         a0,    a1,    a2,   a3,  a4
    asm volatile (
        \\    # Save func and arg to stack
        \\    addi a1, a1, -8
        \\    sw a0, 0(a1)
        \\    sw a3, 4(a1)
        \\
        \\    # Call SYS_clone
        \\    mv a0, a2
        \\    mv a2, a4
        \\    mv a3, a5
        \\    mv a4, a6
        \\    li a7, 220 # SYS_clone
        \\    ecall
        \\
        \\    beqz a0, 1f
        \\    # Parent
        \\    ret
        \\
        \\    # Child
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\    .cfi_undefined ra
    );
    asm volatile (
        \\    mv fp, zero
        \\    mv ra, zero
        \\
        \\    lw a1, 0(sp)
        \\    lw a0, 4(sp)
        \\    jalr a1
        \\
        \\    # Exit
        \\    li a7, 93 # SYS_exit
        \\    ecall
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ ecall
        :
        : [number] "{x17}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;
    pub const GETLK = 5;
    pub const SETLK = 6;
    pub const SETLKW = 7;
    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = i64;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

pub const timeval = extern struct {
    sec: time_t,
    usec: i64,
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
    __unused: [4]u8,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*const anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __pad: usize,
    size: off_t,
    blksize: blksize_t,
    __pad2: i32,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [2]u32,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const Elf_Symndx = u32;

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_4.15";
};

/// TODO
pub const ucontext_t = void;

/// TODO
pub const getcontext = {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const linux = std.os.linux;
const SYS = linux.SYS;
const uid_t = std.os.linux.uid_t;
const gid_t = std.os.linux.gid_t;
const pid_t = std.os.linux.pid_t;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const timespec = std.os.linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
          [arg4] "{x13}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
          [arg4] "{x13}" (arg4),
          [arg5] "{x14}" (arg5),
        : "memory"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile ("ecall"
        : [ret] "={x10}" (-> usize),
        : [number] "{x17}" (@intFromEnum(number)),
          [arg1] "{x10}" (arg1),
          [arg2] "{x11}" (arg2),
          [arg3] "{x12}" (arg3),
          [arg4] "{x13}" (arg4),
          [arg5] "{x14}" (arg5),
          [arg6] "{x15}" (arg6),
        : "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         a0,   a1,    a2,    a3,  a4,   a5,  a6
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         a7         a0,    a1,    a2,   a3,  a4
    asm volatile (
        \\    # Save func and arg to stack
        \\    addi a1, a1, -16
        \\    sd a0, 0(a1)
        \\    sd a3, 8(a1)
        \\
        \\    # Call SYS_clone
        \\    mv a0, a2
        \\    mv a2, a4
        \\    mv a3, a5
        \\    mv a4, a6
        \\    li a7, 220 # SYS_clone
        \\    ecall
        \\
        \\    beqz a0, 1f
        \\    # Parent
        \\    ret
        \\
        \\    # Child
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\    .cfi_undefined ra
    );
    asm volatile (
        \\    mv fp, zero
        \\    mv ra, zero
        \\
        \\    ld a1, 0(sp)
        \\    ld a0, 8(sp)
        \\    jalr a1
        \\
        \\    # Exit
        \\    li a7, 93 # SYS_exit
        \\    ecall
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ ecall
        :
        : [number] "{x17}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;
    pub const GETLK = 5;
    pub const SETLK = 6;
    pub const SETLKW = 7;
    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = i64;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

pub const timeval = extern struct {
    sec: time_t,
    usec: i64,
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
    __unused: [4]u8,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*const anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __pad: usize,
    size: off_t,
    blksize: blksize_t,
    __pad2: i32,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [2]u32,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const Elf_Symndx = u32;

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_4.15";
};

/// TODO
pub const ucontext_t = void;

/// TODO
pub const getcontext = {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const linux = std.os.linux;
const SYS = linux.SYS;
const uid_t = std.os.linux.uid_t;
const gid_t = std.os.linux.gid_t;
const pid_t = std.os.linux.pid_t;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const timespec = std.os.linux.timespec;
const stack_t = std.os.linux.stack_t;
const sigset_t = std.os.linux.sigset_t;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("svc 0"
        : [ret] "={r2}" (-> usize),
        : [number] "{r1}" (@intFromEnum(number)),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("svc 0"
        : [ret] "={r2}" (-> usize),
        : [number] "{r1}" (@intFromEnum(number)),
          [arg1] "{r2}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("svc 0"
        : [ret] "={r2}" (-> usize),
        : [number] "{r1}" (@intFromEnum(number)),
          [arg1] "{r2}" (arg1),
          [arg2] "{r3}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("svc 0"
        : [ret] "={r2}" (-> usize),
        : [number] "{r1}" (@intFromEnum(number)),
          [arg1] "{r2}" (arg1),
          [arg2] "{r3}" (arg2),
          [arg3] "{r4}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("svc 0"
        : [ret] "={r2}" (-> usize),
        : [number] "{r1}" (@intFromEnum(number)),
          [arg1] "{r2}" (arg1),
          [arg2] "{r3}" (arg2),
          [arg3] "{r4}" (arg3),
          [arg4] "{r5}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("svc 0"
        : [ret] "={r2}" (-> usize),
        : [number] "{r1}" (@intFromEnum(number)),
          [arg1] "{r2}" (arg1),
          [arg2] "{r3}" (arg2),
          [arg3] "{r4}" (arg3),
          [arg4] "{r5}" (arg4),
          [arg5] "{r6}" (arg5),
        : "memory"
    );
}

pub fn syscall6(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) usize {
    return asm volatile ("svc 0"
        : [ret] "={r2}" (-> usize),
        : [number] "{r1}" (@intFromEnum(number)),
          [arg1] "{r2}" (arg1),
          [arg2] "{r3}" (arg2),
          [arg3] "{r4}" (arg3),
          [arg4] "{r5}" (arg4),
          [arg5] "{r6}" (arg5),
          [arg6] "{r7}" (arg6),
        : "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    asm volatile (
        \\# int clone(
        \\#    fn,      a = r2
        \\#    stack,   b = r3
        \\#    flags,   c = r4
        \\#    arg,     d = r5
        \\#    ptid,    e = r6
        \\#    tls,     f = *(r15+160)
        \\#    ctid)    g = *(r15+168)
        \\#
        \\# pseudo C code:
        \\# tid = syscall(SYS_clone,b,c,e,g,f);
        \\# if (!tid) syscall(SYS_exit, a(d));
        \\# return tid;
        \\
        \\# preserve call-saved register used as syscall arg
        \\stg  %%r6, 48(%%r15)
        \\
        \\# create initial stack frame for new thread
        \\nill %%r3, 0xfff8
        \\aghi %%r3, -160
        \\lghi %%r0, 0
        \\stg  %%r0, 0(%%r3)
        \\
        \\# save fn and arg to child stack
        \\stg  %%r2,  8(%%r3)
        \\stg  %%r5, 16(%%r3)
        \\
        \\# shuffle args into correct registers and call SYS_clone
        \\lgr  %%r2, %%r3
        \\lgr  %%r3, %%r4
        \\lgr  %%r4, %%r6
        \\lg   %%r5, 168(%%r15)
        \\lg   %%r6, 160(%%r15)
        \\svc  120
        \\
        \\# restore call-saved register
        \\lg   %%r6, 48(%%r15)
        \\
        \\# if error or if we're the parent, return
        \\ltgr %%r2, %%r2
        \\bnzr %%r14
        \\
        \\# we're the child
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\.cfi_undefined %%r14
    );
    asm volatile (
        \\lghi %%r11, 0
        \\lghi %%r14, 0
        \\
        \\# call fn(arg)
        \\lg   %%r1,  8(%%r15)
        \\lg   %%r2, 16(%%r15)
        \\basr %%r14, %%r1
        \\
        \\# call SYS_exit. exit code is already in r2 from fn return value
        \\svc  1
        \\
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\svc 0
        :
        : [number] "{r1}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;
    pub const GETLK = 5;
    pub const SETLK = 6;
    pub const SETLKW = 7;
    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const blksize_t = i64;
pub const nlink_t = u64;
pub const time_t = i64;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

pub const timeval = extern struct {
    sec: time_t,
    usec: i64,
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    __pad1: i32 = 0,
    iovlen: i32,
    control: ?*anyopaque,
    __pad2: i32 = 0,
    controllen: socklen_t,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    __pad1: i32 = 0,
    iovlen: i32,
    control: ?*const anyopaque,
    __pad2: i32 = 0,
    controllen: socklen_t,
    flags: i32,
};

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    nlink: nlink_t,
    mode: mode_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    size: off_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    blksize: blksize_t,
    blocks: blkcnt_t,
    __unused: [3]c_ulong,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const Elf_Symndx = u64;

pub const VDSO = struct {
    pub const CGT_SYM = "__kernel_clock_gettime";
    pub const CGT_VER = "LINUX_2.6.29";
};

pub const ucontext_t = extern struct {
    flags: u64,
    link: ?*ucontext_t,
    stack: stack_t,
    mcontext: mcontext_t,
    sigmask: sigset_t,
};

pub const mcontext_t = extern struct {
    __regs1: [18]u64,
    __regs2: [18]u32,
    __regs3: [16]f64,
};

/// TODO
pub const getcontext = {};
//! API bits for the Secure Computing facility in the Linux kernel, which allows
//! processes to restrict access to the system call API.
//!
//! Seccomp started life with a single "strict" mode, which only allowed calls
//! to read(2), write(2), _exit(2) and sigreturn(2). It turns out that this
//! isn't that useful for general-purpose applications, and so a mode that
//! utilizes user-supplied filters mode was added.
//!
//! Seccomp filters are classic BPF programs. Conceptually, a seccomp program
//! is attached to the kernel and is executed on each syscall. The "packet"
//! being validated is the `data` structure, and the verdict is an action that
//! the kernel performs on the calling process. The actions are variations on a
//! "pass" or "fail" result, where a pass allows the syscall to continue and a
//! fail blocks the syscall and returns some sort of error value. See the full
//! list of actions under ::RET for more information. Finally, only word-sized,
//! absolute loads (`ld [k]`) are supported to read from the `data` structure.
//!
//! There are some issues with the filter API that have traditionally made
//! writing them a pain:
//!
//! 1. Each CPU architecture supported by Linux has its own unique ABI and
//!    syscall API. It is not guaranteed that the syscall numbers and arguments
//!    are the same across architectures, or that they're even implemented. Thus,
//!    filters cannot be assumed to be portable without consulting documentation
//!    like syscalls(2) and testing on target hardware. This also requires
//!    checking the value of `data.arch` to make sure that a filter was compiled
//!    for the correct architecture.
//! 2. Many syscalls take an `unsigned long` or `size_t` argument, the size of
//!    which is dependant on the ABI. Since BPF programs execute in a 32-bit
//!    machine, validation of 64-bit arguments necessitates two load-and-compare
//!    instructions for the upper and lower words.
//! 3. A further wrinkle to the above is endianness. Unlike network packets,
//!    syscall data shares the endianness of the target machine. A filter
//!    compiled on a little-endian machine will not work on a big-endian one,
//!    and vice-versa. For example: Checking the upper 32-bits of `data.arg1`
//!    requires a load at `@offsetOf(data, "arg1") + 4` on big-endian systems
//!    and `@offsetOf(data, "arg1")` on little-endian systems. Endian-portable
//!    filters require adjusting these offsets at compile time, similar to how
//!    e.g. OpenSSH does[1].
//! 4. Syscalls with userspace implementations via the vDSO cannot be traced or
//!    filtered. The vDSO can be disabled or just ignored, which must be taken
//!    into account when writing filters.
//! 5. Software libraries -  especially dynamically loaded ones - tend to use
//!    more of the syscall API over time, thus filters must evolve with them.
//!    Static filters can result in reduced or even broken functionality when
//!    calling newer code from these libraries. This is known to happen with
//!    critical libraries like glibc[2].
//!
//! Some of these issues can be mitigated with help from Zig and the standard
//! library. Since the target CPU is known at compile time, the proper syscall
//! numbers are mixed into the `os` namespace under `std.os.SYS (see the code
//! for `arch_bits` in `os/linux.zig`). Referencing an unimplemented syscall
//! would be a compile error. Endian offsets can also be defined in a similar
//! manner to the OpenSSH example:
//!
//! ```zig
//! const offset = if (native_endian == .little) struct {
//!     pub const low = 0;
//!     pub const high = @sizeOf(u32);
//! } else struct {
//!     pub const low = @sizeOf(u32);
//!     pub const high = 0;
//! };
//! ```
//!
//! Unfortunately, there is no easy solution for issue 5. The most reliable
//! strategy is to keep testing; test newer Zig versions, different libcs,
//! different distros, and design your filter to accommodate all of them.
//! Alternatively, you could inject a filter at runtime. Since filters are
//! preserved across execve(2), a filter could be setup before executing your
//! program, without your program having any knowledge of this happening. This
//! is the method used by systemd[3] and Cloudflare's sandbox library[4].
//!
//! [1]: https://github.com/openssh/openssh-portable/blob/master/sandbox-seccomp-filter.c#L81
//! [2]: https://sourceware.org/legacy-ml/libc-alpha/2017-11/msg00246.html
//! [3]: https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=
//! [4]: https://github.com/cloudflare/sandbox
//!
//! See Also
//! - seccomp(2), seccomp_unotify(2)
//! - https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
const IOCTL = @import("ioctl.zig");

// Modes for the prctl(2) form `prctl(PR_SET_SECCOMP, mode)`
pub const MODE = struct {
    /// Seccomp not in use.
    pub const DISABLED = 0;
    /// Uses a hard-coded filter.
    pub const STRICT = 1;
    /// Uses a user-supplied filter.
    pub const FILTER = 2;
};

// Operations for the seccomp(2) form `seccomp(operation, flags, args)`
pub const SET_MODE_STRICT = 0;
pub const SET_MODE_FILTER = 1;
pub const GET_ACTION_AVAIL = 2;
pub const GET_NOTIF_SIZES = 3;

/// Bitflags for the SET_MODE_FILTER operation.
pub const FILTER_FLAG = struct {
    pub const TSYNC = 1 << 0;
    pub const LOG = 1 << 1;
    pub const SPEC_ALLOW = 1 << 2;
    pub const NEW_LISTENER = 1 << 3;
    pub const TSYNC_ESRCH = 1 << 4;
};

/// Action values for seccomp BPF programs.
/// The lower 16-bits are for optional return data.
/// The upper 16-bits are ordered from least permissive values to most.
pub const RET = struct {
    /// Kill the process.
    pub const KILL_PROCESS = 0x80000000;
    /// Kill the thread.
    pub const KILL_THREAD = 0x00000000;
    pub const KILL = KILL_THREAD;
    /// Disallow and force a SIGSYS.
    pub const TRAP = 0x00030000;
    /// Return an errno.
    pub const ERRNO = 0x00050000;
    /// Forward the syscall to a userspace supervisor to make a decision.
    pub const USER_NOTIF = 0x7fc00000;
    /// Pass to a tracer or disallow.
    pub const TRACE = 0x7ff00000;
    /// Allow after logging.
    pub const LOG = 0x7ffc0000;
    /// Allow.
    pub const ALLOW = 0x7fff0000;

    // Masks for the return value sections.
    pub const ACTION_FULL = 0xffff0000;
    pub const ACTION = 0x7fff0000;
    pub const DATA = 0x0000ffff;
};

pub const IOCTL_NOTIF = struct {
    pub const RECV = IOCTL.IOWR('!', 0, notif);
    pub const SEND = IOCTL.IOWR('!', 1, notif_resp);
    pub const ID_VALID = IOCTL.IOW('!', 2, u64);
    pub const ADDFD = IOCTL.IOW('!', 3, notif_addfd);
};

/// Tells the kernel that the supervisor allows the syscall to continue.
pub const USER_NOTIF_FLAG_CONTINUE = 1 << 0;

/// See seccomp_unotify(2).
pub const ADDFD_FLAG = struct {
    pub const SETFD = 1 << 0;
    pub const SEND = 1 << 1;
};

pub const data = extern struct {
    /// The system call number.
    nr: c_int,
    /// The CPU architecture/system call convention.
    /// One of the values defined in `std.os.linux.AUDIT`.
    arch: u32,
    instruction_pointer: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
};

/// Used with the ::GET_NOTIF_SIZES command to check if the kernel structures
/// have changed.
pub const notif_sizes = extern struct {
    /// Size of ::notif.
    notif: u16,
    /// Size of ::resp.
    notif_resp: u16,
    /// Size of ::data.
    data: u16,
};

pub const notif = extern struct {
    /// Unique notification cookie for each filter.
    id: u64,
    /// ID of the thread that triggered the notification.
    pid: u32,
    /// Bitmask for event information. Currently set to zero.
    flags: u32,
    /// The current system call data.
    data: data,
};

/// The decision payload the supervisor process sends to the kernel.
pub const notif_resp = extern struct {
    /// The filter cookie.
    id: u64,
    /// The return value for a spoofed syscall.
    val: i64,
    /// Set to zero for a spoofed success or a negative error number for a
    /// failure.
    @"error": i32,
    /// Bitmask containing the decision. Either USER_NOTIF_FLAG_CONTINUE to
    /// allow the syscall or zero to spoof the return values.
    flags: u32,
};

pub const notif_addfd = extern struct {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const pid_t = linux.pid_t;
const uid_t = linux.uid_t;
const clock_t = linux.clock_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;

const linux = std.os.linux;
const SYS = linux.SYS;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const timespec = linux.timespec;

pub fn syscall_pipe(fd: *[2]i32) usize {
    return asm volatile (
        \\ mov %[arg], %%g3
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ # Return the error code
        \\ ba 2f
        \\ neg %%o0
        \\1:
        \\ st %%o0, [%%g3+0]
        \\ st %%o1, [%%g3+4]
        \\ clr %%o0
        \\2:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(SYS.pipe)),
          [arg] "r" (fd),
        : "memory", "g3"
    );
}

pub fn syscall_fork() usize {
    // Linux/sparc64 fork() returns two values in %o0 and %o1:
    // - On the parent's side, %o0 is the child's PID and %o1 is 0.
    // - On the child's side, %o0 is the parent's PID and %o1 is 1.
    // We need to clear the child's %o0 so that the return values
    // conform to the libc convention.
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ ba 2f
        \\ neg %%o0
        \\ 1:
        \\ # Clear the child's %%o0
        \\ dec %%o1
        \\ and %%o1, %%o0, %%o0
        \\ 2:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(SYS.fork)),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn syscall0(number: SYS) usize {
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ neg %%o0
        \\ 1:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(number)),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ neg %%o0
        \\ 1:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(number)),
          [arg1] "{o0}" (arg1),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ neg %%o0
        \\ 1:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(number)),
          [arg1] "{o0}" (arg1),
          [arg2] "{o1}" (arg2),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ neg %%o0
        \\ 1:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(number)),
          [arg1] "{o0}" (arg1),
          [arg2] "{o1}" (arg2),
          [arg3] "{o2}" (arg3),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ neg %%o0
        \\ 1:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(number)),
          [arg1] "{o0}" (arg1),
          [arg2] "{o1}" (arg2),
          [arg3] "{o2}" (arg3),
          [arg4] "{o3}" (arg4),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ neg %%o0
        \\ 1:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(number)),
          [arg1] "{o0}" (arg1),
          [arg2] "{o1}" (arg2),
          [arg3] "{o2}" (arg3),
          [arg4] "{o3}" (arg4),
          [arg5] "{o4}" (arg5),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile (
        \\ t 0x6d
        \\ bcc,pt %%xcc, 1f
        \\ nop
        \\ neg %%o0
        \\ 1:
        : [ret] "={o0}" (-> usize),
        : [number] "{g1}" (@intFromEnum(number)),
          [arg1] "{o0}" (arg1),
          [arg2] "{o1}" (arg2),
          [arg3] "{o2}" (arg3),
          [arg4] "{o3}" (arg4),
          [arg5] "{o4}" (arg5),
          [arg6] "{o5}" (arg6),
        : "memory", "xcc", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         i0,   i1,    i2,    i3,  i4,   i5,  sp
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         g1         o0,    o1,    o2,   o3,  o4
    asm volatile (
        \\ save %%sp, -192, %%sp
        \\ # Save the func pointer and the arg pointer
        \\ mov %%i0, %%g2
        \\ mov %%i3, %%g3
        \\ # Shuffle the arguments
        \\ mov 217, %%g1 // SYS_clone
        \\ mov %%i2, %%o0
        \\ # Add some extra space for the initial frame
        \\ sub %%i1, 176 + 2047, %%o1
        \\ mov %%i4, %%o2
        \\ mov %%i5, %%o3
        \\ ldx [%%fp + 0x8af], %%o4
        \\ t 0x6d
        \\ bcs,pn %%xcc, 1f
        \\ nop
        \\ # The child pid is returned in o0 while o1 tells if this
        \\ # process is # the child (=1) or the parent (=0).
        \\ brnz %%o1, 2f
        \\ nop
        \\ # Parent process, return the child pid
        \\ mov %%o0, %%i0
        \\ ret
        \\ restore
        \\1:
        \\ # The syscall failed
        \\ sub %%g0, %%o0, %%i0
        \\ ret
        \\ restore
        \\2:
        \\ # Child process
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\ .cfi_undefined %%i7
    );
    asm volatile (
        \\ mov %%g0, %%fp
        \\ mov %%g0, %%i7
        \\
        \\ # call func(arg)
        \\ mov %%g0, %%fp
        \\ call %%g2
        \\ mov %%g3, %%o0
        \\ # Exit
        \\ mov 1, %%g1 // SYS_exit
        \\ t 0x6d
    );
}

pub const restore = restore_rt;

// Need to use C ABI here instead of naked
// to prevent an infinite loop when calling rt_sigreturn.
pub fn restore_rt() callconv(.c) void {
    return asm volatile ("t 0x6d"
        :
        : [number] "{g1}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory", "xcc", "o0", "o1", "o2", "o3", "o4", "o5", "o7"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 5;
    pub const GETOWN = 6;
    pub const GETLK = 7;
    pub const SETLK = 8;
    pub const SETLKW = 9;

    pub const RDLCK = 1;
    pub const WRLCK = 2;
    pub const UNLCK = 3;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_2.6";
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: u64,
    control: ?*anyopaque,
    controllen: u64,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: u64,
    control: ?*const anyopaque,
    controllen: u64,
    flags: i32,
};

pub const off_t = i64;
pub const ino_t = u64;
pub const mode_t = u32;
pub const dev_t = usize;
pub const nlink_t = u32;
pub const blksize_t = isize;
pub const blkcnt_t = isize;

// The `stat64` definition used by the kernel.
pub const Stat = extern struct {
    dev: u64,
    ino: u64,
    nlink: u64,

    mode: u32,
    uid: u32,
    gid: u32,
    __pad0: u32,

    rdev: u64,
    size: i64,
    blksize: i64,
    blocks: i64,

    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [3]u64,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const timeval = extern struct {
    sec: isize,
    usec: i32,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

// TODO I'm not sure if the code below is correct, need someone with more
// knowledge about sparc64 linux internals to look into.

pub const Elf_Symndx = u32;

pub const fpstate = extern struct {
    regs: [32]u64,
    fsr: u64,
    gsr: u64,
    fprs: u64,
};

pub const __fpq = extern struct {
    fpq_addr: *u32,
    fpq_instr: u32,
};

pub const __fq = extern struct {
    FQu: extern union {
        whole: f64,
        fpq: __fpq,
    },
};

pub const fpregset_t = extern struct {
    fpu_fr: extern union {
        fpu_regs: [32]u32,
        fpu_dregs: [32]f64,
        fpu_qregs: [16]c_longdouble,
    },
    fpu_q: *__fq,
    fpu_fsr: u64,
    fpu_qcnt: u8,
    fpu_q_entrysize: u8,
    fpu_en: u8,
};

pub const siginfo_fpu_t = extern struct {
    float_regs: [64]u32,
    fsr: u64,
    gsr: u64,
    fprs: u64,
};

pub const sigcontext = extern struct {
    info: [128]i8,
    regs: extern struct {
        u_regs: [16]u64,
        tstate: u64,
        tpc: u64,
        tnpc: u64,
        y: u64,
        fprs: u64,
    },
    fpu_save: *siginfo_fpu_t,
    stack: extern struct {
        sp: usize,
        flags: i32,
        size: u64,
    },
    mask: u64,
};

pub const greg_t = u64;
pub const gregset_t = [19]greg_t;

pub const fq = extern struct {
    addr: *u64,
    insn: u32,
};

pub const fpu_t = extern struct {
    fregs: extern union {
        sregs: [32]u32,
        dregs: [32]u64,
        qregs: [16]c_longdouble,
    },
    fsr: u64,
    fprs: u64,
    gsr: u64,
    fq: *fq,
    qcnt: u8,
    qentsz: u8,
    enab: u8,
};

pub const mcontext_t = extern struct {
    gregs: gregset_t,
    fp: greg_t,
    i7: greg_t,
    fpregs: fpu_t,
};

pub const ucontext_t = extern struct {
    link: ?*ucontext_t,
    flags: u64,
    sigmask: u64,
    mcontext: mcontext_t,
    stack: stack_t,
    sigset: sigset_t,
};

/// TODO
pub const getcontext = {};
// This file is automatically generated.
// See tools/generate_linux_syscalls.zig for more info.

pub const X86 = enum(usize) {
    restart_syscall = 0,
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    waitpid = 7,
    creat = 8,
    link = 9,
    unlink = 10,
    execve = 11,
    chdir = 12,
    time = 13,
    mknod = 14,
    chmod = 15,
    lchown = 16,
    @"break" = 17,
    oldstat = 18,
    lseek = 19,
    getpid = 20,
    mount = 21,
    umount = 22,
    setuid = 23,
    getuid = 24,
    stime = 25,
    ptrace = 26,
    alarm = 27,
    oldfstat = 28,
    pause = 29,
    utime = 30,
    stty = 31,
    gtty = 32,
    access = 33,
    nice = 34,
    ftime = 35,
    sync = 36,
    kill = 37,
    rename = 38,
    mkdir = 39,
    rmdir = 40,
    dup = 41,
    pipe = 42,
    times = 43,
    prof = 44,
    brk = 45,
    setgid = 46,
    getgid = 47,
    signal = 48,
    geteuid = 49,
    getegid = 50,
    acct = 51,
    umount2 = 52,
    lock = 53,
    ioctl = 54,
    fcntl = 55,
    mpx = 56,
    setpgid = 57,
    ulimit = 58,
    oldolduname = 59,
    umask = 60,
    chroot = 61,
    ustat = 62,
    dup2 = 63,
    getppid = 64,
    getpgrp = 65,
    setsid = 66,
    sigaction = 67,
    sgetmask = 68,
    ssetmask = 69,
    setreuid = 70,
    setregid = 71,
    sigsuspend = 72,
    sigpending = 73,
    sethostname = 74,
    setrlimit = 75,
    getrlimit = 76,
    getrusage = 77,
    gettimeofday = 78,
    settimeofday = 79,
    getgroups = 80,
    setgroups = 81,
    select = 82,
    symlink = 83,
    oldlstat = 84,
    readlink = 85,
    uselib = 86,
    swapon = 87,
    reboot = 88,
    readdir = 89,
    mmap = 90,
    munmap = 91,
    truncate = 92,
    ftruncate = 93,
    fchmod = 94,
    fchown = 95,
    getpriority = 96,
    setpriority = 97,
    profil = 98,
    statfs = 99,
    fstatfs = 100,
    ioperm = 101,
    socketcall = 102,
    syslog = 103,
    setitimer = 104,
    getitimer = 105,
    stat = 106,
    lstat = 107,
    fstat = 108,
    olduname = 109,
    iopl = 110,
    vhangup = 111,
    idle = 112,
    vm86old = 113,
    wait4 = 114,
    swapoff = 115,
    sysinfo = 116,
    ipc = 117,
    fsync = 118,
    sigreturn = 119,
    clone = 120,
    setdomainname = 121,
    uname = 122,
    modify_ldt = 123,
    adjtimex = 124,
    mprotect = 125,
    sigprocmask = 126,
    create_module = 127,
    init_module = 128,
    delete_module = 129,
    get_kernel_syms = 130,
    quotactl = 131,
    getpgid = 132,
    fchdir = 133,
    bdflush = 134,
    sysfs = 135,
    personality = 136,
    afs_syscall = 137,
    setfsuid = 138,
    setfsgid = 139,
    llseek = 140,
    getdents = 141,
    newselect = 142,
    flock = 143,
    msync = 144,
    readv = 145,
    writev = 146,
    getsid = 147,
    fdatasync = 148,
    sysctl = 149,
    mlock = 150,
    munlock = 151,
    mlockall = 152,
    munlockall = 153,
    sched_setparam = 154,
    sched_getparam = 155,
    sched_setscheduler = 156,
    sched_getscheduler = 157,
    sched_yield = 158,
    sched_get_priority_max = 159,
    sched_get_priority_min = 160,
    sched_rr_get_interval = 161,
    nanosleep = 162,
    mremap = 163,
    setresuid = 164,
    getresuid = 165,
    vm86 = 166,
    query_module = 167,
    poll = 168,
    nfsservctl = 169,
    setresgid = 170,
    getresgid = 171,
    prctl = 172,
    rt_sigreturn = 173,
    rt_sigaction = 174,
    rt_sigprocmask = 175,
    rt_sigpending = 176,
    rt_sigtimedwait = 177,
    rt_sigqueueinfo = 178,
    rt_sigsuspend = 179,
    pread64 = 180,
    pwrite64 = 181,
    chown = 182,
    getcwd = 183,
    capget = 184,
    capset = 185,
    sigaltstack = 186,
    sendfile = 187,
    getpmsg = 188,
    putpmsg = 189,
    vfork = 190,
    ugetrlimit = 191,
    mmap2 = 192,
    truncate64 = 193,
    ftruncate64 = 194,
    stat64 = 195,
    lstat64 = 196,
    fstat64 = 197,
    lchown32 = 198,
    getuid32 = 199,
    getgid32 = 200,
    geteuid32 = 201,
    getegid32 = 202,
    setreuid32 = 203,
    setregid32 = 204,
    getgroups32 = 205,
    setgroups32 = 206,
    fchown32 = 207,
    setresuid32 = 208,
    getresuid32 = 209,
    setresgid32 = 210,
    getresgid32 = 211,
    chown32 = 212,
    setuid32 = 213,
    setgid32 = 214,
    setfsuid32 = 215,
    setfsgid32 = 216,
    pivot_root = 217,
    mincore = 218,
    madvise = 219,
    getdents64 = 220,
    fcntl64 = 221,
    gettid = 224,
    readahead = 225,
    setxattr = 226,
    lsetxattr = 227,
    fsetxattr = 228,
    getxattr = 229,
    lgetxattr = 230,
    fgetxattr = 231,
    listxattr = 232,
    llistxattr = 233,
    flistxattr = 234,
    removexattr = 235,
    lremovexattr = 236,
    fremovexattr = 237,
    tkill = 238,
    sendfile64 = 239,
    futex = 240,
    sched_setaffinity = 241,
    sched_getaffinity = 242,
    set_thread_area = 243,
    get_thread_area = 244,
    io_setup = 245,
    io_destroy = 246,
    io_getevents = 247,
    io_submit = 248,
    io_cancel = 249,
    fadvise64 = 250,
    exit_group = 252,
    lookup_dcookie = 253,
    epoll_create = 254,
    epoll_ctl = 255,
    epoll_wait = 256,
    remap_file_pages = 257,
    set_tid_address = 258,
    timer_create = 259,
    timer_settime = 260,
    timer_gettime = 261,
    timer_getoverrun = 262,
    timer_delete = 263,
    clock_settime = 264,
    clock_gettime = 265,
    clock_getres = 266,
    clock_nanosleep = 267,
    statfs64 = 268,
    fstatfs64 = 269,
    tgkill = 270,
    utimes = 271,
    fadvise64_64 = 272,
    vserver = 273,
    mbind = 274,
    get_mempolicy = 275,
    set_mempolicy = 276,
    mq_open = 277,
    mq_unlink = 278,
    mq_timedsend = 279,
    mq_timedreceive = 280,
    mq_notify = 281,
    mq_getsetattr = 282,
    kexec_load = 283,
    waitid = 284,
    add_key = 286,
    request_key = 287,
    keyctl = 288,
    ioprio_set = 289,
    ioprio_get = 290,
    inotify_init = 291,
    inotify_add_watch = 292,
    inotify_rm_watch = 293,
    migrate_pages = 294,
    openat = 295,
    mkdirat = 296,
    mknodat = 297,
    fchownat = 298,
    futimesat = 299,
    fstatat64 = 300,
    unlinkat = 301,
    renameat = 302,
    linkat = 303,
    symlinkat = 304,
    readlinkat = 305,
    fchmodat = 306,
    faccessat = 307,
    pselect6 = 308,
    ppoll = 309,
    unshare = 310,
    set_robust_list = 311,
    get_robust_list = 312,
    splice = 313,
    sync_file_range = 314,
    tee = 315,
    vmsplice = 316,
    move_pages = 317,
    getcpu = 318,
    epoll_pwait = 319,
    utimensat = 320,
    signalfd = 321,
    timerfd_create = 322,
    eventfd = 323,
    fallocate = 324,
    timerfd_settime = 325,
    timerfd_gettime = 326,
    signalfd4 = 327,
    eventfd2 = 328,
    epoll_create1 = 329,
    dup3 = 330,
    pipe2 = 331,
    inotify_init1 = 332,
    preadv = 333,
    pwritev = 334,
    rt_tgsigqueueinfo = 335,
    perf_event_open = 336,
    recvmmsg = 337,
    fanotify_init = 338,
    fanotify_mark = 339,
    prlimit64 = 340,
    name_to_handle_at = 341,
    open_by_handle_at = 342,
    clock_adjtime = 343,
    syncfs = 344,
    sendmmsg = 345,
    setns = 346,
    process_vm_readv = 347,
    process_vm_writev = 348,
    kcmp = 349,
    finit_module = 350,
    sched_setattr = 351,
    sched_getattr = 352,
    renameat2 = 353,
    seccomp = 354,
    getrandom = 355,
    memfd_create = 356,
    bpf = 357,
    execveat = 358,
    socket = 359,
    socketpair = 360,
    bind = 361,
    connect = 362,
    listen = 363,
    accept4 = 364,
    getsockopt = 365,
    setsockopt = 366,
    getsockname = 367,
    getpeername = 368,
    sendto = 369,
    sendmsg = 370,
    recvfrom = 371,
    recvmsg = 372,
    shutdown = 373,
    userfaultfd = 374,
    membarrier = 375,
    mlock2 = 376,
    copy_file_range = 377,
    preadv2 = 378,
    pwritev2 = 379,
    pkey_mprotect = 380,
    pkey_alloc = 381,
    pkey_free = 382,
    statx = 383,
    arch_prctl = 384,
    io_pgetevents = 385,
    rseq = 386,
    semget = 393,
    semctl = 394,
    shmget = 395,
    shmctl = 396,
    shmat = 397,
    shmdt = 398,
    msgget = 399,
    msgsnd = 400,
    msgrcv = 401,
    msgctl = 402,
    clock_gettime64 = 403,
    clock_settime64 = 404,
    clock_adjtime64 = 405,
    clock_getres_time64 = 406,
    clock_nanosleep_time64 = 407,
    timer_gettime64 = 408,
    timer_settime64 = 409,
    timerfd_gettime64 = 410,
    timerfd_settime64 = 411,
    utimensat_time64 = 412,
    pselect6_time64 = 413,
    ppoll_time64 = 414,
    io_pgetevents_time64 = 416,
    recvmmsg_time64 = 417,
    mq_timedsend_time64 = 418,
    mq_timedreceive_time64 = 419,
    semtimedop_time64 = 420,
    rt_sigtimedwait_time64 = 421,
    futex_time64 = 422,
    sched_rr_get_interval_time64 = 423,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    memfd_secret = 447,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
};

pub const X64 = enum(usize) {
    read = 0,
    write = 1,
    open = 2,
    close = 3,
    stat = 4,
    fstat = 5,
    lstat = 6,
    poll = 7,
    lseek = 8,
    mmap = 9,
    mprotect = 10,
    munmap = 11,
    brk = 12,
    rt_sigaction = 13,
    rt_sigprocmask = 14,
    rt_sigreturn = 15,
    ioctl = 16,
    pread64 = 17,
    pwrite64 = 18,
    readv = 19,
    writev = 20,
    access = 21,
    pipe = 22,
    select = 23,
    sched_yield = 24,
    mremap = 25,
    msync = 26,
    mincore = 27,
    madvise = 28,
    shmget = 29,
    shmat = 30,
    shmctl = 31,
    dup = 32,
    dup2 = 33,
    pause = 34,
    nanosleep = 35,
    getitimer = 36,
    alarm = 37,
    setitimer = 38,
    getpid = 39,
    sendfile = 40,
    socket = 41,
    connect = 42,
    accept = 43,
    sendto = 44,
    recvfrom = 45,
    sendmsg = 46,
    recvmsg = 47,
    shutdown = 48,
    bind = 49,
    listen = 50,
    getsockname = 51,
    getpeername = 52,
    socketpair = 53,
    setsockopt = 54,
    getsockopt = 55,
    clone = 56,
    fork = 57,
    vfork = 58,
    execve = 59,
    exit = 60,
    wait4 = 61,
    kill = 62,
    uname = 63,
    semget = 64,
    semop = 65,
    semctl = 66,
    shmdt = 67,
    msgget = 68,
    msgsnd = 69,
    msgrcv = 70,
    msgctl = 71,
    fcntl = 72,
    flock = 73,
    fsync = 74,
    fdatasync = 75,
    truncate = 76,
    ftruncate = 77,
    getdents = 78,
    getcwd = 79,
    chdir = 80,
    fchdir = 81,
    rename = 82,
    mkdir = 83,
    rmdir = 84,
    creat = 85,
    link = 86,
    unlink = 87,
    symlink = 88,
    readlink = 89,
    chmod = 90,
    fchmod = 91,
    chown = 92,
    fchown = 93,
    lchown = 94,
    umask = 95,
    gettimeofday = 96,
    getrlimit = 97,
    getrusage = 98,
    sysinfo = 99,
    times = 100,
    ptrace = 101,
    getuid = 102,
    syslog = 103,
    getgid = 104,
    setuid = 105,
    setgid = 106,
    geteuid = 107,
    getegid = 108,
    setpgid = 109,
    getppid = 110,
    getpgrp = 111,
    setsid = 112,
    setreuid = 113,
    setregid = 114,
    getgroups = 115,
    setgroups = 116,
    setresuid = 117,
    getresuid = 118,
    setresgid = 119,
    getresgid = 120,
    getpgid = 121,
    setfsuid = 122,
    setfsgid = 123,
    getsid = 124,
    capget = 125,
    capset = 126,
    rt_sigpending = 127,
    rt_sigtimedwait = 128,
    rt_sigqueueinfo = 129,
    rt_sigsuspend = 130,
    sigaltstack = 131,
    utime = 132,
    mknod = 133,
    uselib = 134,
    personality = 135,
    ustat = 136,
    statfs = 137,
    fstatfs = 138,
    sysfs = 139,
    getpriority = 140,
    setpriority = 141,
    sched_setparam = 142,
    sched_getparam = 143,
    sched_setscheduler = 144,
    sched_getscheduler = 145,
    sched_get_priority_max = 146,
    sched_get_priority_min = 147,
    sched_rr_get_interval = 148,
    mlock = 149,
    munlock = 150,
    mlockall = 151,
    munlockall = 152,
    vhangup = 153,
    modify_ldt = 154,
    pivot_root = 155,
    sysctl = 156,
    prctl = 157,
    arch_prctl = 158,
    adjtimex = 159,
    setrlimit = 160,
    chroot = 161,
    sync = 162,
    acct = 163,
    settimeofday = 164,
    mount = 165,
    umount2 = 166,
    swapon = 167,
    swapoff = 168,
    reboot = 169,
    sethostname = 170,
    setdomainname = 171,
    iopl = 172,
    ioperm = 173,
    create_module = 174,
    init_module = 175,
    delete_module = 176,
    get_kernel_syms = 177,
    query_module = 178,
    quotactl = 179,
    nfsservctl = 180,
    getpmsg = 181,
    putpmsg = 182,
    afs_syscall = 183,
    tuxcall = 184,
    security = 185,
    gettid = 186,
    readahead = 187,
    setxattr = 188,
    lsetxattr = 189,
    fsetxattr = 190,
    getxattr = 191,
    lgetxattr = 192,
    fgetxattr = 193,
    listxattr = 194,
    llistxattr = 195,
    flistxattr = 196,
    removexattr = 197,
    lremovexattr = 198,
    fremovexattr = 199,
    tkill = 200,
    time = 201,
    futex = 202,
    sched_setaffinity = 203,
    sched_getaffinity = 204,
    set_thread_area = 205,
    io_setup = 206,
    io_destroy = 207,
    io_getevents = 208,
    io_submit = 209,
    io_cancel = 210,
    get_thread_area = 211,
    lookup_dcookie = 212,
    epoll_create = 213,
    epoll_ctl_old = 214,
    epoll_wait_old = 215,
    remap_file_pages = 216,
    getdents64 = 217,
    set_tid_address = 218,
    restart_syscall = 219,
    semtimedop = 220,
    fadvise64 = 221,
    timer_create = 222,
    timer_settime = 223,
    timer_gettime = 224,
    timer_getoverrun = 225,
    timer_delete = 226,
    clock_settime = 227,
    clock_gettime = 228,
    clock_getres = 229,
    clock_nanosleep = 230,
    exit_group = 231,
    epoll_wait = 232,
    epoll_ctl = 233,
    tgkill = 234,
    utimes = 235,
    vserver = 236,
    mbind = 237,
    set_mempolicy = 238,
    get_mempolicy = 239,
    mq_open = 240,
    mq_unlink = 241,
    mq_timedsend = 242,
    mq_timedreceive = 243,
    mq_notify = 244,
    mq_getsetattr = 245,
    kexec_load = 246,
    waitid = 247,
    add_key = 248,
    request_key = 249,
    keyctl = 250,
    ioprio_set = 251,
    ioprio_get = 252,
    inotify_init = 253,
    inotify_add_watch = 254,
    inotify_rm_watch = 255,
    migrate_pages = 256,
    openat = 257,
    mkdirat = 258,
    mknodat = 259,
    fchownat = 260,
    futimesat = 261,
    fstatat64 = 262,
    unlinkat = 263,
    renameat = 264,
    linkat = 265,
    symlinkat = 266,
    readlinkat = 267,
    fchmodat = 268,
    faccessat = 269,
    pselect6 = 270,
    ppoll = 271,
    unshare = 272,
    set_robust_list = 273,
    get_robust_list = 274,
    splice = 275,
    tee = 276,
    sync_file_range = 277,
    vmsplice = 278,
    move_pages = 279,
    utimensat = 280,
    epoll_pwait = 281,
    signalfd = 282,
    timerfd_create = 283,
    eventfd = 284,
    fallocate = 285,
    timerfd_settime = 286,
    timerfd_gettime = 287,
    accept4 = 288,
    signalfd4 = 289,
    eventfd2 = 290,
    epoll_create1 = 291,
    dup3 = 292,
    pipe2 = 293,
    inotify_init1 = 294,
    preadv = 295,
    pwritev = 296,
    rt_tgsigqueueinfo = 297,
    perf_event_open = 298,
    recvmmsg = 299,
    fanotify_init = 300,
    fanotify_mark = 301,
    prlimit64 = 302,
    name_to_handle_at = 303,
    open_by_handle_at = 304,
    clock_adjtime = 305,
    syncfs = 306,
    sendmmsg = 307,
    setns = 308,
    getcpu = 309,
    process_vm_readv = 310,
    process_vm_writev = 311,
    kcmp = 312,
    finit_module = 313,
    sched_setattr = 314,
    sched_getattr = 315,
    renameat2 = 316,
    seccomp = 317,
    getrandom = 318,
    memfd_create = 319,
    kexec_file_load = 320,
    bpf = 321,
    execveat = 322,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
    copy_file_range = 326,
    preadv2 = 327,
    pwritev2 = 328,
    pkey_mprotect = 329,
    pkey_alloc = 330,
    pkey_free = 331,
    statx = 332,
    io_pgetevents = 333,
    rseq = 334,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    memfd_secret = 447,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
};

pub const X32 = enum(usize) {
    read = 0,
    write = 1,
    open = 2,
    close = 3,
    stat = 4,
    fstat = 5,
    lstat = 6,
    poll = 7,
    lseek = 8,
    mmap = 9,
    mprotect = 10,
    munmap = 11,
    brk = 12,
    rt_sigprocmask = 14,
    pread64 = 17,
    pwrite64 = 18,
    access = 21,
    pipe = 22,
    select = 23,
    sched_yield = 24,
    mremap = 25,
    msync = 26,
    mincore = 27,
    madvise = 28,
    shmget = 29,
    shmat = 30,
    shmctl = 31,
    dup = 32,
    dup2 = 33,
    pause = 34,
    nanosleep = 35,
    getitimer = 36,
    alarm = 37,
    setitimer = 38,
    getpid = 39,
    sendfile = 40,
    socket = 41,
    connect = 42,
    accept = 43,
    sendto = 44,
    shutdown = 48,
    bind = 49,
    listen = 50,
    getsockname = 51,
    getpeername = 52,
    socketpair = 53,
    clone = 56,
    fork = 57,
    vfork = 58,
    exit = 60,
    wait4 = 61,
    kill = 62,
    uname = 63,
    semget = 64,
    semop = 65,
    semctl = 66,
    shmdt = 67,
    msgget = 68,
    msgsnd = 69,
    msgrcv = 70,
    msgctl = 71,
    fcntl = 72,
    flock = 73,
    fsync = 74,
    fdatasync = 75,
    truncate = 76,
    ftruncate = 77,
    getdents = 78,
    getcwd = 79,
    chdir = 80,
    fchdir = 81,
    rename = 82,
    mkdir = 83,
    rmdir = 84,
    creat = 85,
    link = 86,
    unlink = 87,
    symlink = 88,
    readlink = 89,
    chmod = 90,
    fchmod = 91,
    chown = 92,
    fchown = 93,
    lchown = 94,
    umask = 95,
    gettimeofday = 96,
    getrlimit = 97,
    getrusage = 98,
    sysinfo = 99,
    times = 100,
    getuid = 102,
    syslog = 103,
    getgid = 104,
    setuid = 105,
    setgid = 106,
    geteuid = 107,
    getegid = 108,
    setpgid = 109,
    getppid = 110,
    getpgrp = 111,
    setsid = 112,
    setreuid = 113,
    setregid = 114,
    getgroups = 115,
    setgroups = 116,
    setresuid = 117,
    getresuid = 118,
    setresgid = 119,
    getresgid = 120,
    getpgid = 121,
    setfsuid = 122,
    setfsgid = 123,
    getsid = 124,
    capget = 125,
    capset = 126,
    rt_sigsuspend = 130,
    utime = 132,
    mknod = 133,
    personality = 135,
    ustat = 136,
    statfs = 137,
    fstatfs = 138,
    sysfs = 139,
    getpriority = 140,
    setpriority = 141,
    sched_setparam = 142,
    sched_getparam = 143,
    sched_setscheduler = 144,
    sched_getscheduler = 145,
    sched_get_priority_max = 146,
    sched_get_priority_min = 147,
    sched_rr_get_interval = 148,
    mlock = 149,
    munlock = 150,
    mlockall = 151,
    munlockall = 152,
    vhangup = 153,
    modify_ldt = 154,
    pivot_root = 155,
    prctl = 157,
    arch_prctl = 158,
    adjtimex = 159,
    setrlimit = 160,
    chroot = 161,
    sync = 162,
    acct = 163,
    settimeofday = 164,
    mount = 165,
    umount2 = 166,
    swapon = 167,
    swapoff = 168,
    reboot = 169,
    sethostname = 170,
    setdomainname = 171,
    iopl = 172,
    ioperm = 173,
    init_module = 175,
    delete_module = 176,
    quotactl = 179,
    getpmsg = 181,
    putpmsg = 182,
    afs_syscall = 183,
    tuxcall = 184,
    security = 185,
    gettid = 186,
    readahead = 187,
    setxattr = 188,
    lsetxattr = 189,
    fsetxattr = 190,
    getxattr = 191,
    lgetxattr = 192,
    fgetxattr = 193,
    listxattr = 194,
    llistxattr = 195,
    flistxattr = 196,
    removexattr = 197,
    lremovexattr = 198,
    fremovexattr = 199,
    tkill = 200,
    time = 201,
    futex = 202,
    sched_setaffinity = 203,
    sched_getaffinity = 204,
    io_destroy = 207,
    io_getevents = 208,
    io_cancel = 210,
    lookup_dcookie = 212,
    epoll_create = 213,
    remap_file_pages = 216,
    getdents64 = 217,
    set_tid_address = 218,
    restart_syscall = 219,
    semtimedop = 220,
    fadvise64 = 221,
    timer_settime = 223,
    timer_gettime = 224,
    timer_getoverrun = 225,
    timer_delete = 226,
    clock_settime = 227,
    clock_gettime = 228,
    clock_getres = 229,
    clock_nanosleep = 230,
    exit_group = 231,
    epoll_wait = 232,
    epoll_ctl = 233,
    tgkill = 234,
    utimes = 235,
    mbind = 237,
    set_mempolicy = 238,
    get_mempolicy = 239,
    mq_open = 240,
    mq_unlink = 241,
    mq_timedsend = 242,
    mq_timedreceive = 243,
    mq_getsetattr = 245,
    add_key = 248,
    request_key = 249,
    keyctl = 250,
    ioprio_set = 251,
    ioprio_get = 252,
    inotify_init = 253,
    inotify_add_watch = 254,
    inotify_rm_watch = 255,
    migrate_pages = 256,
    openat = 257,
    mkdirat = 258,
    mknodat = 259,
    fchownat = 260,
    futimesat = 261,
    fstatat64 = 262,
    unlinkat = 263,
    renameat = 264,
    linkat = 265,
    symlinkat = 266,
    readlinkat = 267,
    fchmodat = 268,
    faccessat = 269,
    pselect6 = 270,
    ppoll = 271,
    unshare = 272,
    splice = 275,
    tee = 276,
    sync_file_range = 277,
    utimensat = 280,
    epoll_pwait = 281,
    signalfd = 282,
    timerfd_create = 283,
    eventfd = 284,
    fallocate = 285,
    timerfd_settime = 286,
    timerfd_gettime = 287,
    accept4 = 288,
    signalfd4 = 289,
    eventfd2 = 290,
    epoll_create1 = 291,
    dup3 = 292,
    pipe2 = 293,
    inotify_init1 = 294,
    perf_event_open = 298,
    fanotify_init = 300,
    fanotify_mark = 301,
    prlimit64 = 302,
    name_to_handle_at = 303,
    open_by_handle_at = 304,
    clock_adjtime = 305,
    syncfs = 306,
    setns = 308,
    getcpu = 309,
    kcmp = 312,
    finit_module = 313,
    sched_setattr = 314,
    sched_getattr = 315,
    renameat2 = 316,
    seccomp = 317,
    getrandom = 318,
    memfd_create = 319,
    kexec_file_load = 320,
    bpf = 321,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
    copy_file_range = 326,
    pkey_mprotect = 329,
    pkey_alloc = 330,
    pkey_free = 331,
    statx = 332,
    io_pgetevents = 333,
    rseq = 334,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    memfd_secret = 447,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
    rt_sigaction = 512,
    rt_sigreturn = 513,
    ioctl = 514,
    readv = 515,
    writev = 516,
    recvfrom = 517,
    sendmsg = 518,
    recvmsg = 519,
    execve = 520,
    ptrace = 521,
    rt_sigpending = 522,
    rt_sigtimedwait = 523,
    rt_sigqueueinfo = 524,
    sigaltstack = 525,
    timer_create = 526,
    mq_notify = 527,
    kexec_load = 528,
    waitid = 529,
    set_robust_list = 530,
    get_robust_list = 531,
    vmsplice = 532,
    move_pages = 533,
    preadv = 534,
    pwritev = 535,
    rt_tgsigqueueinfo = 536,
    recvmmsg = 537,
    sendmmsg = 538,
    process_vm_readv = 539,
    process_vm_writev = 540,
    setsockopt = 541,
    getsockopt = 542,
    io_setup = 543,
    io_submit = 544,
    execveat = 545,
    preadv2 = 546,
    pwritev2 = 547,
};

pub const Arm = enum(usize) {
    const arm_base = 0x0f0000;

    restart_syscall = 0,
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    creat = 8,
    link = 9,
    unlink = 10,
    execve = 11,
    chdir = 12,
    mknod = 14,
    chmod = 15,
    lchown = 16,
    lseek = 19,
    getpid = 20,
    mount = 21,
    setuid = 23,
    getuid = 24,
    ptrace = 26,
    pause = 29,
    access = 33,
    nice = 34,
    sync = 36,
    kill = 37,
    rename = 38,
    mkdir = 39,
    rmdir = 40,
    dup = 41,
    pipe = 42,
    times = 43,
    brk = 45,
    setgid = 46,
    getgid = 47,
    geteuid = 49,
    getegid = 50,
    acct = 51,
    umount2 = 52,
    ioctl = 54,
    fcntl = 55,
    setpgid = 57,
    umask = 60,
    chroot = 61,
    ustat = 62,
    dup2 = 63,
    getppid = 64,
    getpgrp = 65,
    setsid = 66,
    sigaction = 67,
    setreuid = 70,
    setregid = 71,
    sigsuspend = 72,
    sigpending = 73,
    sethostname = 74,
    setrlimit = 75,
    getrusage = 77,
    gettimeofday = 78,
    settimeofday = 79,
    getgroups = 80,
    setgroups = 81,
    symlink = 83,
    readlink = 85,
    uselib = 86,
    swapon = 87,
    reboot = 88,
    munmap = 91,
    truncate = 92,
    ftruncate = 93,
    fchmod = 94,
    fchown = 95,
    getpriority = 96,
    setpriority = 97,
    statfs = 99,
    fstatfs = 100,
    syslog = 103,
    setitimer = 104,
    getitimer = 105,
    stat = 106,
    lstat = 107,
    fstat = 108,
    vhangup = 111,
    wait4 = 114,
    swapoff = 115,
    sysinfo = 116,
    fsync = 118,
    sigreturn = 119,
    clone = 120,
    setdomainname = 121,
    uname = 122,
    adjtimex = 124,
    mprotect = 125,
    sigprocmask = 126,
    init_module = 128,
    delete_module = 129,
    quotactl = 131,
    getpgid = 132,
    fchdir = 133,
    bdflush = 134,
    sysfs = 135,
    personality = 136,
    setfsuid = 138,
    setfsgid = 139,
    llseek = 140,
    getdents = 141,
    newselect = 142,
    flock = 143,
    msync = 144,
    readv = 145,
    writev = 146,
    getsid = 147,
    fdatasync = 148,
    sysctl = 149,
    mlock = 150,
    munlock = 151,
    mlockall = 152,
    munlockall = 153,
    sched_setparam = 154,
    sched_getparam = 155,
    sched_setscheduler = 156,
    sched_getscheduler = 157,
    sched_yield = 158,
    sched_get_priority_max = 159,
    sched_get_priority_min = 160,
    sched_rr_get_interval = 161,
    nanosleep = 162,
    mremap = 163,
    setresuid = 164,
    getresuid = 165,
    poll = 168,
    nfsservctl = 169,
    setresgid = 170,
    getresgid = 171,
    prctl = 172,
    rt_sigreturn = 173,
    rt_sigaction = 174,
    rt_sigprocmask = 175,
    rt_sigpending = 176,
    rt_sigtimedwait = 177,
    rt_sigqueueinfo = 178,
    rt_sigsuspend = 179,
    pread64 = 180,
    pwrite64 = 181,
    chown = 182,
    getcwd = 183,
    capget = 184,
    capset = 185,
    sigaltstack = 186,
    sendfile = 187,
    vfork = 190,
    ugetrlimit = 191,
    mmap2 = 192,
    truncate64 = 193,
    ftruncate64 = 194,
    stat64 = 195,
    lstat64 = 196,
    fstat64 = 197,
    lchown32 = 198,
    getuid32 = 199,
    getgid32 = 200,
    geteuid32 = 201,
    getegid32 = 202,
    setreuid32 = 203,
    setregid32 = 204,
    getgroups32 = 205,
    setgroups32 = 206,
    fchown32 = 207,
    setresuid32 = 208,
    getresuid32 = 209,
    setresgid32 = 210,
    getresgid32 = 211,
    chown32 = 212,
    setuid32 = 213,
    setgid32 = 214,
    setfsuid32 = 215,
    setfsgid32 = 216,
    getdents64 = 217,
    pivot_root = 218,
    mincore = 219,
    madvise = 220,
    fcntl64 = 221,
    gettid = 224,
    readahead = 225,
    setxattr = 226,
    lsetxattr = 227,
    fsetxattr = 228,
    getxattr = 229,
    lgetxattr = 230,
    fgetxattr = 231,
    listxattr = 232,
    llistxattr = 233,
    flistxattr = 234,
    removexattr = 235,
    lremovexattr = 236,
    fremovexattr = 237,
    tkill = 238,
    sendfile64 = 239,
    futex = 240,
    sched_setaffinity = 241,
    sched_getaffinity = 242,
    io_setup = 243,
    io_destroy = 244,
    io_getevents = 245,
    io_submit = 246,
    io_cancel = 247,
    exit_group = 248,
    lookup_dcookie = 249,
    epoll_create = 250,
    epoll_ctl = 251,
    epoll_wait = 252,
    remap_file_pages = 253,
    set_tid_address = 256,
    timer_create = 257,
    timer_settime = 258,
    timer_gettime = 259,
    timer_getoverrun = 260,
    timer_delete = 261,
    clock_settime = 262,
    clock_gettime = 263,
    clock_getres = 264,
    clock_nanosleep = 265,
    statfs64 = 266,
    fstatfs64 = 267,
    tgkill = 268,
    utimes = 269,
    fadvise64_64 = 270,
    pciconfig_iobase = 271,
    pciconfig_read = 272,
    pciconfig_write = 273,
    mq_open = 274,
    mq_unlink = 275,
    mq_timedsend = 276,
    mq_timedreceive = 277,
    mq_notify = 278,
    mq_getsetattr = 279,
    waitid = 280,
    socket = 281,
    bind = 282,
    connect = 283,
    listen = 284,
    accept = 285,
    getsockname = 286,
    getpeername = 287,
    socketpair = 288,
    send = 289,
    sendto = 290,
    recv = 291,
    recvfrom = 292,
    shutdown = 293,
    setsockopt = 294,
    getsockopt = 295,
    sendmsg = 296,
    recvmsg = 297,
    semop = 298,
    semget = 299,
    semctl = 300,
    msgsnd = 301,
    msgrcv = 302,
    msgget = 303,
    msgctl = 304,
    shmat = 305,
    shmdt = 306,
    shmget = 307,
    shmctl = 308,
    add_key = 309,
    request_key = 310,
    keyctl = 311,
    semtimedop = 312,
    vserver = 313,
    ioprio_set = 314,
    ioprio_get = 315,
    inotify_init = 316,
    inotify_add_watch = 317,
    inotify_rm_watch = 318,
    mbind = 319,
    get_mempolicy = 320,
    set_mempolicy = 321,
    openat = 322,
    mkdirat = 323,
    mknodat = 324,
    fchownat = 325,
    futimesat = 326,
    fstatat64 = 327,
    unlinkat = 328,
    renameat = 329,
    linkat = 330,
    symlinkat = 331,
    readlinkat = 332,
    fchmodat = 333,
    faccessat = 334,
    pselect6 = 335,
    ppoll = 336,
    unshare = 337,
    set_robust_list = 338,
    get_robust_list = 339,
    splice = 340,
    sync_file_range = 341,
    tee = 342,
    vmsplice = 343,
    move_pages = 344,
    getcpu = 345,
    epoll_pwait = 346,
    kexec_load = 347,
    utimensat = 348,
    signalfd = 349,
    timerfd_create = 350,
    eventfd = 351,
    fallocate = 352,
    timerfd_settime = 353,
    timerfd_gettime = 354,
    signalfd4 = 355,
    eventfd2 = 356,
    epoll_create1 = 357,
    dup3 = 358,
    pipe2 = 359,
    inotify_init1 = 360,
    preadv = 361,
    pwritev = 362,
    rt_tgsigqueueinfo = 363,
    perf_event_open = 364,
    recvmmsg = 365,
    accept4 = 366,
    fanotify_init = 367,
    fanotify_mark = 368,
    prlimit64 = 369,
    name_to_handle_at = 370,
    open_by_handle_at = 371,
    clock_adjtime = 372,
    syncfs = 373,
    sendmmsg = 374,
    setns = 375,
    process_vm_readv = 376,
    process_vm_writev = 377,
    kcmp = 378,
    finit_module = 379,
    sched_setattr = 380,
    sched_getattr = 381,
    renameat2 = 382,
    seccomp = 383,
    getrandom = 384,
    memfd_create = 385,
    bpf = 386,
    execveat = 387,
    userfaultfd = 388,
    membarrier = 389,
    mlock2 = 390,
    copy_file_range = 391,
    preadv2 = 392,
    pwritev2 = 393,
    pkey_mprotect = 394,
    pkey_alloc = 395,
    pkey_free = 396,
    statx = 397,
    rseq = 398,
    io_pgetevents = 399,
    migrate_pages = 400,
    kexec_file_load = 401,
    clock_gettime64 = 403,
    clock_settime64 = 404,
    clock_adjtime64 = 405,
    clock_getres_time64 = 406,
    clock_nanosleep_time64 = 407,
    timer_gettime64 = 408,
    timer_settime64 = 409,
    timerfd_gettime64 = 410,
    timerfd_settime64 = 411,
    utimensat_time64 = 412,
    pselect6_time64 = 413,
    ppoll_time64 = 414,
    io_pgetevents_time64 = 416,
    recvmmsg_time64 = 417,
    mq_timedsend_time64 = 418,
    mq_timedreceive_time64 = 419,
    semtimedop_time64 = 420,
    rt_sigtimedwait_time64 = 421,
    futex_time64 = 422,
    sched_rr_get_interval_time64 = 423,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,

    breakpoint = arm_base + 1,
    cacheflush = arm_base + 2,
    usr26 = arm_base + 3,
    usr32 = arm_base + 4,
    set_tls = arm_base + 5,
    get_tls = arm_base + 6,
};

pub const Sparc = enum(usize) {
    restart_syscall = 0,
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    wait4 = 7,
    creat = 8,
    link = 9,
    unlink = 10,
    execv = 11,
    chdir = 12,
    chown = 13,
    mknod = 14,
    chmod = 15,
    lchown = 16,
    brk = 17,
    perfctr = 18,
    lseek = 19,
    getpid = 20,
    capget = 21,
    capset = 22,
    setuid = 23,
    getuid = 24,
    vmsplice = 25,
    ptrace = 26,
    alarm = 27,
    sigaltstack = 28,
    pause = 29,
    utime = 30,
    lchown32 = 31,
    fchown32 = 32,
    access = 33,
    nice = 34,
    chown32 = 35,
    sync = 36,
    kill = 37,
    stat = 38,
    sendfile = 39,
    lstat = 40,
    dup = 41,
    pipe = 42,
    times = 43,
    getuid32 = 44,
    umount2 = 45,
    setgid = 46,
    getgid = 47,
    signal = 48,
    geteuid = 49,
    getegid = 50,
    acct = 51,
    getgid32 = 53,
    ioctl = 54,
    reboot = 55,
    mmap2 = 56,
    symlink = 57,
    readlink = 58,
    execve = 59,
    umask = 60,
    chroot = 61,
    fstat = 62,
    fstat64 = 63,
    getpagesize = 64,
    msync = 65,
    vfork = 66,
    pread64 = 67,
    pwrite64 = 68,
    geteuid32 = 69,
    getegid32 = 70,
    mmap = 71,
    setreuid32 = 72,
    munmap = 73,
    mprotect = 74,
    madvise = 75,
    vhangup = 76,
    truncate64 = 77,
    mincore = 78,
    getgroups = 79,
    setgroups = 80,
    getpgrp = 81,
    setgroups32 = 82,
    setitimer = 83,
    ftruncate64 = 84,
    swapon = 85,
    getitimer = 86,
    setuid32 = 87,
    sethostname = 88,
    setgid32 = 89,
    dup2 = 90,
    setfsuid32 = 91,
    fcntl = 92,
    select = 93,
    setfsgid32 = 94,
    fsync = 95,
    setpriority = 96,
    socket = 97,
    connect = 98,
    accept = 99,
    getpriority = 100,
    rt_sigreturn = 101,
    rt_sigaction = 102,
    rt_sigprocmask = 103,
    rt_sigpending = 104,
    rt_sigtimedwait = 105,
    rt_sigqueueinfo = 106,
    rt_sigsuspend = 107,
    setresuid32 = 108,
    getresuid32 = 109,
    setresgid32 = 110,
    getresgid32 = 111,
    setregid32 = 112,
    recvmsg = 113,
    sendmsg = 114,
    getgroups32 = 115,
    gettimeofday = 116,
    getrusage = 117,
    getsockopt = 118,
    getcwd = 119,
    readv = 120,
    writev = 121,
    settimeofday = 122,
    fchown = 123,
    fchmod = 124,
    recvfrom = 125,
    setreuid = 126,
    setregid = 127,
    rename = 128,
    truncate = 129,
    ftruncate = 130,
    flock = 131,
    lstat64 = 132,
    sendto = 133,
    shutdown = 134,
    socketpair = 135,
    mkdir = 136,
    rmdir = 137,
    utimes = 138,
    stat64 = 139,
    sendfile64 = 140,
    getpeername = 141,
    futex = 142,
    gettid = 143,
    getrlimit = 144,
    setrlimit = 145,
    pivot_root = 146,
    prctl = 147,
    pciconfig_read = 148,
    pciconfig_write = 149,
    getsockname = 150,
    inotify_init = 151,
    inotify_add_watch = 152,
    poll = 153,
    getdents64 = 154,
    fcntl64 = 155,
    inotify_rm_watch = 156,
    statfs = 157,
    fstatfs = 158,
    umount = 159,
    sched_set_affinity = 160,
    sched_get_affinity = 161,
    getdomainname = 162,
    setdomainname = 163,
    quotactl = 165,
    set_tid_address = 166,
    mount = 167,
    ustat = 168,
    setxattr = 169,
    lsetxattr = 170,
    fsetxattr = 171,
    getxattr = 172,
    lgetxattr = 173,
    getdents = 174,
    setsid = 175,
    fchdir = 176,
    fgetxattr = 177,
    listxattr = 178,
    llistxattr = 179,
    flistxattr = 180,
    removexattr = 181,
    lremovexattr = 182,
    sigpending = 183,
    query_module = 184,
    setpgid = 185,
    fremovexattr = 186,
    tkill = 187,
    exit_group = 188,
    uname = 189,
    init_module = 190,
    personality = 191,
    remap_file_pages = 192,
    epoll_create = 193,
    epoll_ctl = 194,
    epoll_wait = 195,
    ioprio_set = 196,
    getppid = 197,
    sigaction = 198,
    sgetmask = 199,
    ssetmask = 200,
    sigsuspend = 201,
    oldlstat = 202,
    uselib = 203,
    readdir = 204,
    readahead = 205,
    socketcall = 206,
    syslog = 207,
    lookup_dcookie = 208,
    fadvise64 = 209,
    fadvise64_64 = 210,
    tgkill = 211,
    waitpid = 212,
    swapoff = 213,
    sysinfo = 214,
    ipc = 215,
    sigreturn = 216,
    clone = 217,
    ioprio_get = 218,
    adjtimex = 219,
    sigprocmask = 220,
    create_module = 221,
    delete_module = 222,
    get_kernel_syms = 223,
    getpgid = 224,
    bdflush = 225,
    sysfs = 226,
    afs_syscall = 227,
    setfsuid = 228,
    setfsgid = 229,
    newselect = 230,
    time = 231,
    splice = 232,
    stime = 233,
    statfs64 = 234,
    fstatfs64 = 235,
    llseek = 236,
    mlock = 237,
    munlock = 238,
    mlockall = 239,
    munlockall = 240,
    sched_setparam = 241,
    sched_getparam = 242,
    sched_setscheduler = 243,
    sched_getscheduler = 244,
    sched_yield = 245,
    sched_get_priority_max = 246,
    sched_get_priority_min = 247,
    sched_rr_get_interval = 248,
    nanosleep = 249,
    mremap = 250,
    sysctl = 251,
    getsid = 252,
    fdatasync = 253,
    nfsservctl = 254,
    sync_file_range = 255,
    clock_settime = 256,
    clock_gettime = 257,
    clock_getres = 258,
    clock_nanosleep = 259,
    sched_getaffinity = 260,
    sched_setaffinity = 261,
    timer_settime = 262,
    timer_gettime = 263,
    timer_getoverrun = 264,
    timer_delete = 265,
    timer_create = 266,
    vserver = 267,
    io_setup = 268,
    io_destroy = 269,
    io_submit = 270,
    io_cancel = 271,
    io_getevents = 272,
    mq_open = 273,
    mq_unlink = 274,
    mq_timedsend = 275,
    mq_timedreceive = 276,
    mq_notify = 277,
    mq_getsetattr = 278,
    waitid = 279,
    tee = 280,
    add_key = 281,
    request_key = 282,
    keyctl = 283,
    openat = 284,
    mkdirat = 285,
    mknodat = 286,
    fchownat = 287,
    futimesat = 288,
    fstatat64 = 289,
    unlinkat = 290,
    renameat = 291,
    linkat = 292,
    symlinkat = 293,
    readlinkat = 294,
    fchmodat = 295,
    faccessat = 296,
    pselect6 = 297,
    ppoll = 298,
    unshare = 299,
    set_robust_list = 300,
    get_robust_list = 301,
    migrate_pages = 302,
    mbind = 303,
    get_mempolicy = 304,
    set_mempolicy = 305,
    kexec_load = 306,
    move_pages = 307,
    getcpu = 308,
    epoll_pwait = 309,
    utimensat = 310,
    signalfd = 311,
    timerfd_create = 312,
    eventfd = 313,
    fallocate = 314,
    timerfd_settime = 315,
    timerfd_gettime = 316,
    signalfd4 = 317,
    eventfd2 = 318,
    epoll_create1 = 319,
    dup3 = 320,
    pipe2 = 321,
    inotify_init1 = 322,
    accept4 = 323,
    preadv = 324,
    pwritev = 325,
    rt_tgsigqueueinfo = 326,
    perf_event_open = 327,
    recvmmsg = 328,
    fanotify_init = 329,
    fanotify_mark = 330,
    prlimit64 = 331,
    name_to_handle_at = 332,
    open_by_handle_at = 333,
    clock_adjtime = 334,
    syncfs = 335,
    sendmmsg = 336,
    setns = 337,
    process_vm_readv = 338,
    process_vm_writev = 339,
    kern_features = 340,
    kcmp = 341,
    finit_module = 342,
    sched_setattr = 343,
    sched_getattr = 344,
    renameat2 = 345,
    seccomp = 346,
    getrandom = 347,
    memfd_create = 348,
    bpf = 349,
    execveat = 350,
    membarrier = 351,
    userfaultfd = 352,
    bind = 353,
    listen = 354,
    setsockopt = 355,
    mlock2 = 356,
    copy_file_range = 357,
    preadv2 = 358,
    pwritev2 = 359,
    statx = 360,
    io_pgetevents = 361,
    pkey_mprotect = 362,
    pkey_alloc = 363,
    pkey_free = 364,
    rseq = 365,
    semget = 393,
    semctl = 394,
    shmget = 395,
    shmctl = 396,
    shmat = 397,
    shmdt = 398,
    msgget = 399,
    msgsnd = 400,
    msgrcv = 401,
    msgctl = 402,
    clock_gettime64 = 403,
    clock_settime64 = 404,
    clock_adjtime64 = 405,
    clock_getres_time64 = 406,
    clock_nanosleep_time64 = 407,
    timer_gettime64 = 408,
    timer_settime64 = 409,
    timerfd_gettime64 = 410,
    timerfd_settime64 = 411,
    utimensat_time64 = 412,
    pselect6_time64 = 413,
    ppoll_time64 = 414,
    io_pgetevents_time64 = 416,
    recvmmsg_time64 = 417,
    mq_timedsend_time64 = 418,
    mq_timedreceive_time64 = 419,
    semtimedop_time64 = 420,
    rt_sigtimedwait_time64 = 421,
    futex_time64 = 422,
    sched_rr_get_interval_time64 = 423,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
};

pub const Sparc64 = enum(usize) {
    restart_syscall = 0,
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    wait4 = 7,
    creat = 8,
    link = 9,
    unlink = 10,
    execv = 11,
    chdir = 12,
    chown = 13,
    mknod = 14,
    chmod = 15,
    lchown = 16,
    brk = 17,
    perfctr = 18,
    lseek = 19,
    getpid = 20,
    capget = 21,
    capset = 22,
    setuid = 23,
    getuid = 24,
    vmsplice = 25,
    ptrace = 26,
    alarm = 27,
    sigaltstack = 28,
    pause = 29,
    utime = 30,
    access = 33,
    nice = 34,
    sync = 36,
    kill = 37,
    stat = 38,
    sendfile = 39,
    lstat = 40,
    dup = 41,
    pipe = 42,
    times = 43,
    umount2 = 45,
    setgid = 46,
    getgid = 47,
    signal = 48,
    geteuid = 49,
    getegid = 50,
    acct = 51,
    memory_ordering = 52,
    ioctl = 54,
    reboot = 55,
    symlink = 57,
    readlink = 58,
    execve = 59,
    umask = 60,
    chroot = 61,
    fstat = 62,
    fstat64 = 63,
    getpagesize = 64,
    msync = 65,
    vfork = 66,
    pread64 = 67,
    pwrite64 = 68,
    mmap = 71,
    munmap = 73,
    mprotect = 74,
    madvise = 75,
    vhangup = 76,
    mincore = 78,
    getgroups = 79,
    setgroups = 80,
    getpgrp = 81,
    setitimer = 83,
    swapon = 85,
    getitimer = 86,
    sethostname = 88,
    dup2 = 90,
    fcntl = 92,
    select = 93,
    fsync = 95,
    setpriority = 96,
    socket = 97,
    connect = 98,
    accept = 99,
    getpriority = 100,
    rt_sigreturn = 101,
    rt_sigaction = 102,
    rt_sigprocmask = 103,
    rt_sigpending = 104,
    rt_sigtimedwait = 105,
    rt_sigqueueinfo = 106,
    rt_sigsuspend = 107,
    setresuid = 108,
    getresuid = 109,
    setresgid = 110,
    getresgid = 111,
    recvmsg = 113,
    sendmsg = 114,
    gettimeofday = 116,
    getrusage = 117,
    getsockopt = 118,
    getcwd = 119,
    readv = 120,
    writev = 121,
    settimeofday = 122,
    fchown = 123,
    fchmod = 124,
    recvfrom = 125,
    setreuid = 126,
    setregid = 127,
    rename = 128,
    truncate = 129,
    ftruncate = 130,
    flock = 131,
    lstat64 = 132,
    sendto = 133,
    shutdown = 134,
    socketpair = 135,
    mkdir = 136,
    rmdir = 137,
    utimes = 138,
    stat64 = 139,
    sendfile64 = 140,
    getpeername = 141,
    futex = 142,
    gettid = 143,
    getrlimit = 144,
    setrlimit = 145,
    pivot_root = 146,
    prctl = 147,
    pciconfig_read = 148,
    pciconfig_write = 149,
    getsockname = 150,
    inotify_init = 151,
    inotify_add_watch = 152,
    poll = 153,
    getdents64 = 154,
    inotify_rm_watch = 156,
    statfs = 157,
    fstatfs = 158,
    umount = 159,
    sched_set_affinity = 160,
    sched_get_affinity = 161,
    getdomainname = 162,
    setdomainname = 163,
    utrap_install = 164,
    quotactl = 165,
    set_tid_address = 166,
    mount = 167,
    ustat = 168,
    setxattr = 169,
    lsetxattr = 170,
    fsetxattr = 171,
    getxattr = 172,
    lgetxattr = 173,
    getdents = 174,
    setsid = 175,
    fchdir = 176,
    fgetxattr = 177,
    listxattr = 178,
    llistxattr = 179,
    flistxattr = 180,
    removexattr = 181,
    lremovexattr = 182,
    sigpending = 183,
    query_module = 184,
    setpgid = 185,
    fremovexattr = 186,
    tkill = 187,
    exit_group = 188,
    uname = 189,
    init_module = 190,
    personality = 191,
    remap_file_pages = 192,
    epoll_create = 193,
    epoll_ctl = 194,
    epoll_wait = 195,
    ioprio_set = 196,
    getppid = 197,
    sigaction = 198,
    sgetmask = 199,
    ssetmask = 200,
    sigsuspend = 201,
    oldlstat = 202,
    uselib = 203,
    readdir = 204,
    readahead = 205,
    socketcall = 206,
    syslog = 207,
    lookup_dcookie = 208,
    fadvise64 = 209,
    fadvise64_64 = 210,
    tgkill = 211,
    waitpid = 212,
    swapoff = 213,
    sysinfo = 214,
    ipc = 215,
    sigreturn = 216,
    clone = 217,
    ioprio_get = 218,
    adjtimex = 219,
    sigprocmask = 220,
    create_module = 221,
    delete_module = 222,
    get_kernel_syms = 223,
    getpgid = 224,
    bdflush = 225,
    sysfs = 226,
    afs_syscall = 227,
    setfsuid = 228,
    setfsgid = 229,
    newselect = 230,
    splice = 232,
    stime = 233,
    statfs64 = 234,
    fstatfs64 = 235,
    llseek = 236,
    mlock = 237,
    munlock = 238,
    mlockall = 239,
    munlockall = 240,
    sched_setparam = 241,
    sched_getparam = 242,
    sched_setscheduler = 243,
    sched_getscheduler = 244,
    sched_yield = 245,
    sched_get_priority_max = 246,
    sched_get_priority_min = 247,
    sched_rr_get_interval = 248,
    nanosleep = 249,
    mremap = 250,
    sysctl = 251,
    getsid = 252,
    fdatasync = 253,
    nfsservctl = 254,
    sync_file_range = 255,
    clock_settime = 256,
    clock_gettime = 257,
    clock_getres = 258,
    clock_nanosleep = 259,
    sched_getaffinity = 260,
    sched_setaffinity = 261,
    timer_settime = 262,
    timer_gettime = 263,
    timer_getoverrun = 264,
    timer_delete = 265,
    timer_create = 266,
    vserver = 267,
    io_setup = 268,
    io_destroy = 269,
    io_submit = 270,
    io_cancel = 271,
    io_getevents = 272,
    mq_open = 273,
    mq_unlink = 274,
    mq_timedsend = 275,
    mq_timedreceive = 276,
    mq_notify = 277,
    mq_getsetattr = 278,
    waitid = 279,
    tee = 280,
    add_key = 281,
    request_key = 282,
    keyctl = 283,
    openat = 284,
    mkdirat = 285,
    mknodat = 286,
    fchownat = 287,
    futimesat = 288,
    fstatat64 = 289,
    unlinkat = 290,
    renameat = 291,
    linkat = 292,
    symlinkat = 293,
    readlinkat = 294,
    fchmodat = 295,
    faccessat = 296,
    pselect6 = 297,
    ppoll = 298,
    unshare = 299,
    set_robust_list = 300,
    get_robust_list = 301,
    migrate_pages = 302,
    mbind = 303,
    get_mempolicy = 304,
    set_mempolicy = 305,
    kexec_load = 306,
    move_pages = 307,
    getcpu = 308,
    epoll_pwait = 309,
    utimensat = 310,
    signalfd = 311,
    timerfd_create = 312,
    eventfd = 313,
    fallocate = 314,
    timerfd_settime = 315,
    timerfd_gettime = 316,
    signalfd4 = 317,
    eventfd2 = 318,
    epoll_create1 = 319,
    dup3 = 320,
    pipe2 = 321,
    inotify_init1 = 322,
    accept4 = 323,
    preadv = 324,
    pwritev = 325,
    rt_tgsigqueueinfo = 326,
    perf_event_open = 327,
    recvmmsg = 328,
    fanotify_init = 329,
    fanotify_mark = 330,
    prlimit64 = 331,
    name_to_handle_at = 332,
    open_by_handle_at = 333,
    clock_adjtime = 334,
    syncfs = 335,
    sendmmsg = 336,
    setns = 337,
    process_vm_readv = 338,
    process_vm_writev = 339,
    kern_features = 340,
    kcmp = 341,
    finit_module = 342,
    sched_setattr = 343,
    sched_getattr = 344,
    renameat2 = 345,
    seccomp = 346,
    getrandom = 347,
    memfd_create = 348,
    bpf = 349,
    execveat = 350,
    membarrier = 351,
    userfaultfd = 352,
    bind = 353,
    listen = 354,
    setsockopt = 355,
    mlock2 = 356,
    copy_file_range = 357,
    preadv2 = 358,
    pwritev2 = 359,
    statx = 360,
    io_pgetevents = 361,
    pkey_mprotect = 362,
    pkey_alloc = 363,
    pkey_free = 364,
    rseq = 365,
    semtimedop = 392,
    semget = 393,
    semctl = 394,
    shmget = 395,
    shmctl = 396,
    shmat = 397,
    shmdt = 398,
    msgget = 399,
    msgsnd = 400,
    msgrcv = 401,
    msgctl = 402,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
};

pub const M68k = enum(usize) {
    restart_syscall = 0,
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    waitpid = 7,
    creat = 8,
    link = 9,
    unlink = 10,
    execve = 11,
    chdir = 12,
    time = 13,
    mknod = 14,
    chmod = 15,
    chown = 16,
    oldstat = 18,
    lseek = 19,
    getpid = 20,
    mount = 21,
    umount = 22,
    setuid = 23,
    getuid = 24,
    stime = 25,
    ptrace = 26,
    alarm = 27,
    oldfstat = 28,
    pause = 29,
    utime = 30,
    access = 33,
    nice = 34,
    sync = 36,
    kill = 37,
    rename = 38,
    mkdir = 39,
    rmdir = 40,
    dup = 41,
    pipe = 42,
    times = 43,
    brk = 45,
    setgid = 46,
    getgid = 47,
    signal = 48,
    geteuid = 49,
    getegid = 50,
    acct = 51,
    umount2 = 52,
    ioctl = 54,
    fcntl = 55,
    setpgid = 57,
    umask = 60,
    chroot = 61,
    ustat = 62,
    dup2 = 63,
    getppid = 64,
    getpgrp = 65,
    setsid = 66,
    sigaction = 67,
    sgetmask = 68,
    ssetmask = 69,
    setreuid = 70,
    setregid = 71,
    sigsuspend = 72,
    sigpending = 73,
    sethostname = 74,
    setrlimit = 75,
    getrlimit = 76,
    getrusage = 77,
    gettimeofday = 78,
    settimeofday = 79,
    getgroups = 80,
    setgroups = 81,
    select = 82,
    symlink = 83,
    oldlstat = 84,
    readlink = 85,
    uselib = 86,
    swapon = 87,
    reboot = 88,
    readdir = 89,
    mmap = 90,
    munmap = 91,
    truncate = 92,
    ftruncate = 93,
    fchmod = 94,
    fchown = 95,
    getpriority = 96,
    setpriority = 97,
    statfs = 99,
    fstatfs = 100,
    socketcall = 102,
    syslog = 103,
    setitimer = 104,
    getitimer = 105,
    stat = 106,
    lstat = 107,
    fstat = 108,
    vhangup = 111,
    wait4 = 114,
    swapoff = 115,
    sysinfo = 116,
    ipc = 117,
    fsync = 118,
    sigreturn = 119,
    clone = 120,
    setdomainname = 121,
    uname = 122,
    cacheflush = 123,
    adjtimex = 124,
    mprotect = 125,
    sigprocmask = 126,
    create_module = 127,
    init_module = 128,
    delete_module = 129,
    get_kernel_syms = 130,
    quotactl = 131,
    getpgid = 132,
    fchdir = 133,
    bdflush = 134,
    sysfs = 135,
    personality = 136,
    setfsuid = 138,
    setfsgid = 139,
    llseek = 140,
    getdents = 141,
    newselect = 142,
    flock = 143,
    msync = 144,
    readv = 145,
    writev = 146,
    getsid = 147,
    fdatasync = 148,
    sysctl = 149,
    mlock = 150,
    munlock = 151,
    mlockall = 152,
    munlockall = 153,
    sched_setparam = 154,
    sched_getparam = 155,
    sched_setscheduler = 156,
    sched_getscheduler = 157,
    sched_yield = 158,
    sched_get_priority_max = 159,
    sched_get_priority_min = 160,
    sched_rr_get_interval = 161,
    nanosleep = 162,
    mremap = 163,
    setresuid = 164,
    getresuid = 165,
    getpagesize = 166,
    query_module = 167,
    poll = 168,
    nfsservctl = 169,
    setresgid = 170,
    getresgid = 171,
    prctl = 172,
    rt_sigreturn = 173,
    rt_sigaction = 174,
    rt_sigprocmask = 175,
    rt_sigpending = 176,
    rt_sigtimedwait = 177,
    rt_sigqueueinfo = 178,
    rt_sigsuspend = 179,
    pread64 = 180,
    pwrite64 = 181,
    lchown = 182,
    getcwd = 183,
    capget = 184,
    capset = 185,
    sigaltstack = 186,
    sendfile = 187,
    getpmsg = 188,
    putpmsg = 189,
    vfork = 190,
    ugetrlimit = 191,
    mmap2 = 192,
    truncate64 = 193,
    ftruncate64 = 194,
    stat64 = 195,
    lstat64 = 196,
    fstat64 = 197,
    chown32 = 198,
    getuid32 = 199,
    getgid32 = 200,
    geteuid32 = 201,
    getegid32 = 202,
    setreuid32 = 203,
    setregid32 = 204,
    getgroups32 = 205,
    setgroups32 = 206,
    fchown32 = 207,
    setresuid32 = 208,
    getresuid32 = 209,
    setresgid32 = 210,
    getresgid32 = 211,
    lchown32 = 212,
    setuid32 = 213,
    setgid32 = 214,
    setfsuid32 = 215,
    setfsgid32 = 216,
    pivot_root = 217,
    getdents64 = 220,
    gettid = 221,
    tkill = 222,
    setxattr = 223,
    lsetxattr = 224,
    fsetxattr = 225,
    getxattr = 226,
    lgetxattr = 227,
    fgetxattr = 228,
    listxattr = 229,
    llistxattr = 230,
    flistxattr = 231,
    removexattr = 2```
