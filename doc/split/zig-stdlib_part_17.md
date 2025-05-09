```
p(pw: *const passwd) ?*passwd;

pub const auth_item_t = enum(c_int) {
    ALL = 0,
    CHALLENGE = 1,
    CLASS = 2,
    NAME = 3,
    SERVICE = 4,
    STYLE = 5,
    INTERACTIVE = 6,
};

pub const BI = struct {
    pub const AUTH = "authorize"; // Accepted authentication
    pub const REJECT = "reject"; // Rejected authentication
    pub const CHALLENGE = "reject challenge"; // Reject with a challenge
    pub const SILENT = "reject silent"; // Reject silently
    pub const REMOVE = "remove"; // remove file on error
    pub const ROOTOKAY = "authorize root"; // root authenticated
    pub const SECURE = "authorize secure"; // okay on non-secure line
    pub const SETENV = "setenv"; // set environment variable
    pub const UNSETENV = "unsetenv"; // unset environment variable
    pub const VALUE = "value"; // set local variable
    pub const EXPIRED = "reject expired"; // account expired
    pub const PWEXPIRED = "reject pwexpired"; // password expired
    pub const FDPASS = "fd"; // child is passing an fd
};

pub const AUTH = struct {
    pub const OKAY: c_int = 0x01; // user authenticated
    pub const ROOTOKAY: c_int = 0x02; // authenticated as root
    pub const SECURE: c_int = 0x04; // secure login
    pub const SILENT: c_int = 0x08; // silent rejection
    pub const CHALLENGE: c_int = 0x10; // a challenge was given
    pub const EXPIRED: c_int = 0x20; // account expired
    pub const PWEXPIRED: c_int = 0x40; // password expired
    pub const ALLOW: c_int = (OKAY | ROOTOKAY | SECURE);
};

pub const TCFLUSH = enum(u32) {
    none = 0,
    I = 1,
    O = 2,
    IO = 3,
};

pub const TCIO = enum(u32) {
    OOFF = 1,
    OON = 2,
    IOFF = 3,
    ION = 4,
};

pub const ucontext_t = switch (builtin.cpu.arch) {
    .x86_64 => extern struct {
        sc_rdi: c_long,
        sc_rsi: c_long,
        sc_rdx: c_long,
        sc_rcx: c_long,
        sc_r8: c_long,
        sc_r9: c_long,
        sc_r10: c_long,
        sc_r11: c_long,
        sc_r12: c_long,
        sc_r13: c_long,
        sc_r14: c_long,
        sc_r15: c_long,
        sc_rbp: c_long,
        sc_rbx: c_long,
        sc_rax: c_long,
        sc_gs: c_long,
        sc_fs: c_long,
        sc_es: c_long,
        sc_ds: c_long,
        sc_trapno: c_long,
        sc_err: c_long,
        sc_rip: c_long,
        sc_cs: c_long,
        sc_rflags: c_long,
        sc_rsp: c_long,
        sc_ss: c_long,

        sc_fpstate: *anyopaque, // struct fxsave64 *
        __sc_unused: c_int,
        sc_mask: c_int,
        sc_cookie: c_long,
    },
    .aarch64 => extern struct {
        __sc_unused: c_int,
        sc_mask: c_int,
        sc_sp: c_ulong,
        sc_lr: c_ulong,
        sc_elr: c_ulong,
        sc_spsr: c_ulong,
        sc_x: [30]c_ulong,
        sc_cookie: c_long,
    },
    else => @compileError("missing ucontext_t type definition"),
};

pub const E = enum(u16) {
    /// No error occurred.
    SUCCESS = 0,
    PERM = 1, // Operation not permitted
    NOENT = 2, // No such file or directory
    SRCH = 3, // No such process
    INTR = 4, // Interrupted system call
    IO = 5, // Input/output error
    NXIO = 6, // Device not configured
    @"2BIG" = 7, // Argument list too long
    NOEXEC = 8, // Exec format error
    BADF = 9, // Bad file descriptor
    CHILD = 10, // No child processes
    DEADLK = 11, // Resource deadlock avoided
    // 11 was AGAIN
    NOMEM = 12, // Cannot allocate memory
    ACCES = 13, // Permission denied
    FAULT = 14, // Bad address
    NOTBLK = 15, // Block device required
    BUSY = 16, // Device busy
    EXIST = 17, // File exists
    XDEV = 18, // Cross-device link
    NODEV = 19, // Operation not supported by device
    NOTDIR = 20, // Not a directory
    ISDIR = 21, // Is a directory
    INVAL = 22, // Invalid argument
    NFILE = 23, // Too many open files in system
    MFILE = 24, // Too many open files
    NOTTY = 25, // Inappropriate ioctl for device
    TXTBSY = 26, // Text file busy
    FBIG = 27, // File too large
    NOSPC = 28, // No space left on device
    SPIPE = 29, // Illegal seek
    ROFS = 30, // Read-only file system
    MLINK = 31, // Too many links
    PIPE = 32, // Broken pipe

    // math software
    DOM = 33, // Numerical argument out of domain
    RANGE = 34, // Result too large or too small

    // non-blocking and interrupt i/o
    // also: WOULDBLOCK: operation would block
    AGAIN = 35, // Resource temporarily unavailable
    INPROGRESS = 36, // Operation now in progress
    ALREADY = 37, // Operation already in progress

    // ipc/network software -- argument errors
    NOTSOCK = 38, // Socket operation on non-socket
    DESTADDRREQ = 39, // Destination address required
    MSGSIZE = 40, // Message too long
    PROTOTYPE = 41, // Protocol wrong type for socket
    NOPROTOOPT = 42, // Protocol option not available
    PROTONOSUPPORT = 43, // Protocol not supported
    SOCKTNOSUPPORT = 44, // Socket type not supported
    OPNOTSUPP = 45, // Operation not supported
    PFNOSUPPORT = 46, // Protocol family not supported
    AFNOSUPPORT = 47, // Address family not supported by protocol family
    ADDRINUSE = 48, // Address already in use
    ADDRNOTAVAIL = 49, // Can't assign requested address

    // ipc/network software -- operational errors
    NETDOWN = 50, // Network is down
    NETUNREACH = 51, // Network is unreachable
    NETRESET = 52, // Network dropped connection on reset
    CONNABORTED = 53, // Software caused connection abort
    CONNRESET = 54, // Connection reset by peer
    NOBUFS = 55, // No buffer space available
    ISCONN = 56, // Socket is already connected
    NOTCONN = 57, // Socket is not connected
    SHUTDOWN = 58, // Can't send after socket shutdown
    TOOMANYREFS = 59, // Too many references: can't splice
    TIMEDOUT = 60, // Operation timed out
    CONNREFUSED = 61, // Connection refused

    LOOP = 62, // Too many levels of symbolic links
    NAMETOOLONG = 63, // File name too long

    // should be rearranged
    HOSTDOWN = 64, // Host is down
    HOSTUNREACH = 65, // No route to host
    NOTEMPTY = 66, // Directory not empty

    // quotas & mush
    PROCLIM = 67, // Too many processes
    USERS = 68, // Too many users
    DQUOT = 69, // Disc quota exceeded

    // Network File System
    STALE = 70, // Stale NFS file handle
    REMOTE = 71, // Too many levels of remote in path
    BADRPC = 72, // RPC struct is bad
    RPCMISMATCH = 73, // RPC version wrong
    PROGUNAVAIL = 74, // RPC prog. not avail
    PROGMISMATCH = 75, // Program version wrong
    PROCUNAVAIL = 76, // Bad procedure for program

    NOLCK = 77, // No locks available
    NOSYS = 78, // Function not implemented

    FTYPE = 79, // Inappropriate file type or format
    AUTH = 80, // Authentication error
    NEEDAUTH = 81, // Need authenticator
    IPSEC = 82, // IPsec processing failure
    NOATTR = 83, // Attribute not found

    // Wide/multibyte-character handling, ISO/IEC 9899/AMD1:1995
    ILSEQ = 84, // Illegal byte sequence

    NOMEDIUM = 85, // No medium found
    MEDIUMTYPE = 86, // Wrong medium type
    OVERFLOW = 87, // Value too large to be stored in data type
    CANCELED = 88, // Operation canceled
    IDRM = 89, // Identifier removed
    NOMSG = 90, // No message of desired type
    NOTSUP = 91, // Not supported
    BADMSG = 92, // Bad or Corrupt message
    NOTRECOVERABLE = 93, // State not recoverable
    OWNERDEAD = 94, // Previous owner died
    PROTO = 95, // Protocol error

    _,
};

pub const MAX_PAGE_SHIFT = switch (builtin.cpu.arch) {
    .x86 => 12,
    .sparc64 => 13,
};

pub const HW = struct {
    pub const MACHINE = 1;
    pub const MODEL = 2;
    pub const NCPU = 3;
    pub const BYTEORDER = 4;
    pub const PHYSMEM = 5;
    pub const USERMEM = 6;
    pub const PAGESIZE = 7;
    pub const DISKNAMES = 8;
    pub const DISKSTATS = 9;
    pub const DISKCOUNT = 10;
    pub const SENSORS = 11;
    pub const CPUSPEED = 12;
    pub const SETPERF = 13;
    pub const VENDOR = 14;
    pub const PRODUCT = 15;
    pub const VERSION = 16;
    pub const SERIALNO = 17;
    pub const UUID = 18;
    pub const PHYSMEM64 = 19;
    pub const USERMEM64 = 20;
    pub const NCPUFOUND = 21;
    pub const ALLOWPOWERDOWN = 22;
    pub const PERFPOLICY = 23;
    pub const SMT = 24;
    pub const NCPUONLINE = 25;
    pub const POWER = 26;
};

pub const PTHREAD_STACK_MIN = switch (builtin.cpu.arch) {
    .sparc64 => 1 << 13,
    .mips64 => 1 << 14,
    else => 1 << 12,
};
const std = @import("../std.zig");
const assert = std.debug.assert;
const builtin = @import("builtin");
const O = std.c.O;
const clockid_t = std.c.clockid_t;
const pid_t = std.c.pid_t;
const timespec = std.c.timespec;

comptime {
    assert(builtin.os.tag == .serenity); // Prevent access of std.c symbols on wrong OS.
}

// https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/futex.h#L46-L53
pub const FUTEX = struct {
    pub const WAIT = 1;
    pub const WAKE = 2;
    pub const REQUEUE = 3;
    pub const CMP_REQUEUE = 4;
    pub const WAKE_OP = 5;
    pub const WAIT_BITSET = 9;
    pub const WAKE_BITSET = 10;

    pub const CLOCK_REALTIME = 1 << 8;
    pub const PRIVATE_FLAG = 1 << 9;
};

// https://github.com/SerenityOS/serenity/blob/54e79aa1d90bbcb69014255a59afb085802719d3/Kernel/API/POSIX/serenity.h#L18-L36
pub const PERF_EVENT = packed struct(c_int) {
    SAMPLE: bool = false,
    MALLOC: bool = false,
    FREE: bool = false,
    MMAP: bool = false,
    MUNMAP: bool = false,
    PROCESS_CREATE: bool = false,
    PROCESS_EXEC: bool = false,
    PROCESS_EXIT: bool = false,
    THREAD_CREATE: bool = false,
    THREAD_EXIT: bool = false,
    CONTEXT_SWITCH: bool = false,
    KMALLOC: bool = false,
    KFREE: bool = false,
    PAGE_FAULT: bool = false,
    SYSCALL: bool = false,
    SIGNPOST: bool = false,
    FILESYSTEM: bool = false,
};

// https://github.com/SerenityOS/serenity/blob/abc150085f532f123b598949218893cb272ccc4c/Userland/Libraries/LibC/serenity.h

pub extern "c" fn disown(pid: pid_t) c_int;

pub extern "c" fn profiling_enable(pid: pid_t, event_mask: PERF_EVENT) c_int;
pub extern "c" fn profiling_disable(pid: pid_t) c_int;
pub extern "c" fn profiling_free_buffer(pid: pid_t) c_int;

pub extern "c" fn futex(userspace_address: *u32, futex_op: c_int, value: u32, timeout: *const timespec, userspace_address2: *u32, value3: u32) c_int;
pub extern "c" fn futex_wait(userspace_address: *u32, value: u32, abstime: *const timespec, clockid: clockid_t, process_shared: c_int) c_int;
pub extern "c" fn futex_wake(userspace_address: *u32, count: u32, process_shared: c_int) c_int;

pub extern "c" fn purge(mode: c_int) c_int;

pub extern "c" fn perf_event(type: PERF_EVENT, arg1: usize, arg2: usize) c_int;
pub extern "c" fn perf_register_string(string: [*]const u8, string_length: usize) c_int;

pub extern "c" fn get_stack_bounds(user_stack_base: *usize, user_stack_size: *usize) c_int;

pub extern "c" fn anon_create(size: usize, options: O) c_int;

pub extern "c" fn serenity_readlink(path: [*]const u8, path_length: usize, buffer: [*]u8, buffer_size: usize) c_int;
pub extern "c" fn serenity_open(path: [*]const u8, path_length: usize, options: c_int, ...) c_int;

pub extern "c" fn getkeymap(name_buffer: [*]u8, name_buffer_size: usize, map: [*]u32, shift_map: [*]u32, alt_map: [*]u32, altgr_map: [*]u32, shift_altgr_map: [*]u32) c_int;
pub extern "c" fn setkeymap(name: [*]const u8, map: [*]const u32, shift_map: [*]const u32, alt_map: [*]const u32, altgr_map: [*]const u32, shift_altgr_map: [*]const u32) c_int;

pub extern "c" fn internet_checksum(ptr: *const anyopaque, count: usize) u16;
const builtin = @import("builtin");
const std = @import("../std.zig");
const assert = std.debug.assert;
const SO = std.c.SO;
const fd_t = std.c.fd_t;
const gid_t = std.c.gid_t;
const ino_t = std.c.ino_t;
const mode_t = std.c.mode_t;
const off_t = std.c.off_t;
const pid_t = std.c.pid_t;
const pthread_t = std.c.pthread_t;
const sockaddr = std.c.sockaddr;
const socklen_t = std.c.socklen_t;
const timespec = std.c.timespec;
const uid_t = std.c.uid_t;
const IFNAMESIZE = std.c.IFNAMESIZE;

comptime {
    assert(builtin.os.tag == .solaris or builtin.os.tag == .illumos); // Prevent access of std.c symbols on wrong OS.
}

pub extern "c" fn pthread_setname_np(thread: pthread_t, name: [*:0]const u8, arg: ?*anyopaque) c_int;
pub extern "c" fn sysconf(sc: c_int) i64;

pub const major_t = u32;
pub const minor_t = u32;
pub const id_t = i32;
pub const taskid_t = id_t;
pub const projid_t = id_t;
pub const poolid_t = id_t;
pub const zoneid_t = id_t;
pub const ctid_t = id_t;

pub const cmsghdr = extern struct {
    len: socklen_t,
    level: i32,
    type: i32,
};

pub const SCM = struct {
    pub const UCRED = 0x1012;
    pub const RIGHTS = 0x1010;
    pub const TIMESTAMP = SO.TIMESTAMP;
};

pub const fpregset_t = extern union {
    regs: [130]u32,
    chip_state: extern struct {
        cw: u16,
        sw: u16,
        fctw: u8,
        __fx_rsvd: u8,
        fop: u16,
        rip: u64,
        rdp: u64,
        mxcsr: u32,
        mxcsr_mask: u32,
        st: [8]extern union {
            fpr_16: [5]u16,
            __fpr_pad: u128,
        },
        xmm: [16]u128,
        __fx_ign2: [6]u128,
        status: u32,
        xstatus: u32,
    },
};

pub const GETCONTEXT = 0;
pub const SETCONTEXT = 1;
pub const GETUSTACK = 2;
pub const SETUSTACK = 3;

pub const POSIX_FADV = struct {
    pub const NORMAL = 0;
    pub const RANDOM = 1;
    pub const SEQUENTIAL = 2;
    pub const WILLNEED = 3;
    pub const DONTNEED = 4;
    pub const NOREUSE = 5;
};

pub const priority = enum(c_int) {
    PROCESS = 0,
    PGRP = 1,
    USER = 2,
    GROUP = 3,
    SESSION = 4,
    LWP = 5,
    TASK = 6,
    PROJECT = 7,
    ZONE = 8,
    CONTRACT = 9,
};

/// Extensions to the ELF auxiliary vector.
pub const AT_SUN = struct {
    /// effective user id
    pub const UID = 2000;
    /// real user id
    pub const RUID = 2001;
    /// effective group id
    pub const GID = 2002;
    /// real group id
    pub const RGID = 2003;
    /// dynamic linker's ELF header
    pub const LDELF = 2004;
    /// dynamic linker's section headers
    pub const LDSHDR = 2005;
    /// name of dynamic linker
    pub const LDNAME = 2006;
    /// large pagesize
    pub const LPAGESZ = 2007;
    /// platform name
    pub const PLATFORM = 2008;
    /// hints about hardware capabilities.
    pub const HWCAP = 2009;
    pub const HWCAP2 = 2023;
    /// flush icache?
    pub const IFLUSH = 2010;
    /// cpu name
    pub const CPU = 2011;
    /// exec() path name in the auxv, null terminated.
    pub const EXECNAME = 2014;
    /// mmu module name
    pub const MMU = 2015;
    /// dynamic linkers data segment
    pub const LDDATA = 2016;
    /// AF_SUN_ flags passed from the kernel
    pub const AUXFLAGS = 2017;
    /// name of the emulation binary for the linker
    pub const EMULATOR = 2018;
    /// name of the brand library for the linker
    pub const BRANDNAME = 2019;
    /// vectors for brand modules.
    pub const BRAND_AUX1 = 2020;
    pub const BRAND_AUX2 = 2021;
    pub const BRAND_AUX3 = 2022;
    pub const BRAND_AUX4 = 2025;
    pub const BRAND_NROOT = 2024;
    /// vector for comm page.
    pub const COMMPAGE = 2026;
    /// information about the x86 FPU.
    pub const FPTYPE = 2027;
    pub const FPSIZE = 2028;
};

/// ELF auxiliary vector flags.
pub const AF_SUN = struct {
    /// tell ld.so.1 to run "secure" and ignore the environment.
    pub const SETUGID = 0x00000001;
    /// hardware capabilities can be verified against AT_SUN_HWCAP
    pub const HWCAPVERIFY = 0x00000002;
    pub const NOPLM = 0x00000004;
};

pub const procfs = struct {
    pub const misc_header = extern struct {
        size: u32,
        type: enum(u32) {
            Pathname,
            Socketname,
            Peersockname,
            SockoptsBoolOpts,
            SockoptLinger,
            SockoptSndbuf,
            SockoptRcvbuf,
            SockoptIpNexthop,
            SockoptIpv6Nexthop,
            SockoptType,
            SockoptTcpCongestion,
            SockfiltersPriv = 14,
        },
    };

    pub const fdinfo = extern struct {
        fd: fd_t,
        mode: mode_t,
        ino: ino_t,
        size: off_t,
        offset: off_t,
        uid: uid_t,
        gid: gid_t,
        dev_major: major_t,
        dev_minor: minor_t,
        special_major: major_t,
        special_minor: minor_t,
        fileflags: i32,
        fdflags: i32,
        locktype: i16,
        lockpid: pid_t,
        locksysid: i32,
        peerpid: pid_t,
        __filler: [25]c_int,
        peername: [15:0]u8,
        misc: [1]u8,
    };
};

pub const SFD = struct {
    pub const CLOEXEC = 0o2000000;
    pub const NONBLOCK = 0o4000;
};

pub const signalfd_siginfo = extern struct {
    signo: u32,
    errno: i32,
    code: i32,
    pid: u32,
    uid: uid_t,
    fd: i32,
    tid: u32, // unused
    band: u32,
    overrun: u32, // unused
    trapno: u32,
    status: i32,
    int: i32, // unused
    ptr: u64, // unused
    utime: u64,
    stime: u64,
    addr: u64,
    __pad: [48]u8,
};

pub const PORT_SOURCE = struct {
    pub const AIO = 1;
    pub const TIMER = 2;
    pub const USER = 3;
    pub const FD = 4;
    pub const ALERT = 5;
    pub const MQ = 6;
    pub const FILE = 7;
};

pub const PORT_ALERT = struct {
    pub const SET = 0x01;
    pub const UPDATE = 0x02;
};

/// User watchable file events.
pub const FILE_EVENT = struct {
    pub const ACCESS = 0x00000001;
    pub const MODIFIED = 0x00000002;
    pub const ATTRIB = 0x00000004;
    pub const DELETE = 0x00000010;
    pub const RENAME_TO = 0x00000020;
    pub const RENAME_FROM = 0x00000040;
    pub const TRUNC = 0x00100000;
    pub const NOFOLLOW = 0x10000000;
    /// The filesystem holding the watched file was unmounted.
    pub const UNMOUNTED = 0x20000000;
    /// Some other file/filesystem got mounted over the watched file/directory.
    pub const MOUNTEDOVER = 0x40000000;

    pub fn isException(event: u32) bool {
        return event & (UNMOUNTED | DELETE | RENAME_TO | RENAME_FROM | MOUNTEDOVER) > 0;
    }
};

pub const port_notify = extern struct {
    /// Bind request(s) to port.
    port: u32,
    /// User defined variable.
    user: ?*void,
};

pub const file_obj = extern struct {
    /// Access time.
    atim: timespec,
    /// Modification time
    mtim: timespec,
    /// Change time
    ctim: timespec,
    __pad: [3]usize,
    name: [*:0]u8,
};

// struct ifreq is marked obsolete, with struct lifreq preferred for interface requests.
// Here we alias lifreq to ifreq to avoid chainging existing code in os and x.os.IPv6.
pub const SIOCGLIFINDEX = IOWR('i', 133, lifreq);

pub const lif_nd_req = extern struct {
    addr: sockaddr.storage,
    state_create: u8,
    state_same_lla: u8,
    state_diff_lla: u8,
    hdw_len: i32,
    flags: i32,
    __pad: i32,
    hdw_addr: [64]u8,
};

pub const lif_ifinfo_req = extern struct {
    maxhops: u8,
    reachtime: u32,
    reachretrans: u32,
    maxmtu: u32,
};

/// IP interface request. See if_tcp(7p) for more info.
pub const lifreq = extern struct {
    // Not actually in a union, but the stdlib expects one for ifreq
    ifrn: extern union {
        /// Interface name, e.g. "lo0", "en0".
        name: [IFNAMESIZE]u8,
    },
    ru1: extern union {
        /// For subnet/token etc.
        addrlen: i32,
        /// Driver's PPA (physical point of attachment).
        ppa: u32,
    },
    /// One of the IFT types, e.g. IFT_ETHER.
    type: u32,
    ifru: extern union {
        /// Address.
        addr: sockaddr.storage,
        /// Other end of a peer-to-peer link.
        dstaddr: sockaddr.storage,
        /// Broadcast address.
        broadaddr: sockaddr.storage,
        /// Address token.
        token: sockaddr.storage,
        /// Subnet prefix.
        subnet: sockaddr.storage,
        /// Interface index.
        ivalue: i32,
        /// Flags for SIOC?LIFFLAGS.
        flags: u64,
        /// Hop count metric
        metric: i32,
        /// Maximum transmission unit
        mtu: u32,
        // Technically [2]i32
        muxid: packed struct { ip: i32, arp: i32 },
        /// Neighbor reachability determination entries
        nd_req: lif_nd_req,
        /// Link info
        ifinfo_req: lif_ifinfo_req,
        /// Name of the multipath interface group
        groupname: [IFNAMESIZE]u8,
        binding: [IFNAMESIZE]u8,
        /// Zone id associated with this interface.
        zoneid: zoneid_t,
        /// Duplicate address detection state. Either in progress or completed.
        dadstate: u32,
    },
};

const IoCtlCommand = enum(u32) {
    none = 0x20000000, // no parameters
    write = 0x40000000, // copy out parameters
    read = 0x80000000, // copy in parameters
    read_write = 0xc0000000,
};

fn ioImpl(cmd: IoCtlCommand, io_type: u8, nr: u8, comptime IOT: type) i32 {
    const size = @as(u32, @intCast(@as(u8, @truncate(@sizeOf(IOT))))) << 16;
    const t = @as(u32, @intCast(io_type)) << 8;
    return @as(i32, @bitCast(@intFromEnum(cmd) | size | t | nr));
}

pub fn IO(io_type: u8, nr: u8) i32 {
    return ioImpl(.none, io_type, nr, void);
}

pub fn IOR(io_type: u8, nr: u8, comptime IOT: type) i32 {
    return ioImpl(.write, io_type, nr, IOT);
}

pub fn IOW(io_type: u8, nr: u8, comptime IOT: type) i32 {
    return ioImpl(.read, io_type, nr, IOT);
}

pub fn IOWR(io_type: u8, nr: u8, comptime IOT: type) i32 {
    return ioImpl(.read_write, io_type, nr, IOT);
}
const std = @import("std.zig");
const assert = std.debug.assert;
const mem = std.mem;

pub const CoffHeaderFlags = packed struct {
    /// Image only, Windows CE, and Microsoft Windows NT and later.
    /// This indicates that the file does not contain base relocations
    /// and must therefore be loaded at its preferred base address.
    /// If the base address is not available, the loader reports an error.
    /// The default behavior of the linker is to strip base relocations
    /// from executable (EXE) files.
    RELOCS_STRIPPED: u1 = 0,

    /// Image only. This indicates that the image file is valid and can be run.
    /// If this flag is not set, it indicates a linker error.
    EXECUTABLE_IMAGE: u1 = 0,

    /// COFF line numbers have been removed. This flag is deprecated and should be zero.
    LINE_NUMS_STRIPPED: u1 = 0,

    /// COFF symbol table entries for local symbols have been removed.
    /// This flag is deprecated and should be zero.
    LOCAL_SYMS_STRIPPED: u1 = 0,

    /// Obsolete. Aggressively trim working set.
    /// This flag is deprecated for Windows 2000 and later and must be zero.
    AGGRESSIVE_WS_TRIM: u1 = 0,

    /// Application can handle > 2-GB addresses.
    LARGE_ADDRESS_AWARE: u1 = 0,

    /// This flag is reserved for future use.
    RESERVED: u1 = 0,

    /// Little endian: the least significant bit (LSB) precedes the
    /// most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    BYTES_REVERSED_LO: u1 = 0,

    /// Machine is based on a 32-bit-word architecture.
    @"32BIT_MACHINE": u1 = 0,

    /// Debugging information is removed from the image file.
    DEBUG_STRIPPED: u1 = 0,

    /// If the image is on removable media, fully load it and copy it to the swap file.
    REMOVABLE_RUN_FROM_SWAP: u1 = 0,

    /// If the image is on network media, fully load it and copy it to the swap file.
    NET_RUN_FROM_SWAP: u1 = 0,

    /// The image file is a system file, not a user program.
    SYSTEM: u1 = 0,

    /// The image file is a dynamic-link library (DLL).
    /// Such files are considered executable files for almost all purposes,
    /// although they cannot be directly run.
    DLL: u1 = 0,

    /// The file should be run only on a uniprocessor machine.
    UP_SYSTEM_ONLY: u1 = 0,

    /// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    BYTES_REVERSED_HI: u1 = 0,
};

pub const CoffHeader = extern struct {
    /// The number that identifies the type of target machine.
    machine: MachineType,

    /// The number of sections. This indicates the size of the section table, which immediately follows the headers.
    number_of_sections: u16,

    /// The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value),
    /// which indicates when the file was created.
    time_date_stamp: u32,

    /// The file offset of the COFF symbol table, or zero if no COFF symbol table is present.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pointer_to_symbol_table: u32,

    /// The number of entries in the symbol table.
    /// This data can be used to locate the string table, which immediately follows the symbol table.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    number_of_symbols: u32,

    /// The size of the optional header, which is required for executable files but not for object files.
    /// This value should be zero for an object file. For a description of the header format, see Optional Header (Image Only).
    size_of_optional_header: u16,

    /// The flags that indicate the attributes of the file.
    flags: CoffHeaderFlags,
};

// OptionalHeader.magic values
// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

pub const DllFlags = packed struct {
    _reserved_0: u5 = 0,

    /// Image can handle a high entropy 64-bit virtual address space.
    HIGH_ENTROPY_VA: u1 = 0,

    /// DLL can be relocated at load time.
    DYNAMIC_BASE: u1 = 0,

    /// Code Integrity checks are enforced.
    FORCE_INTEGRITY: u1 = 0,

    /// Image is NX compatible.
    NX_COMPAT: u1 = 0,

    /// Isolation aware, but do not isolate the image.
    NO_ISOLATION: u1 = 0,

    /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
    NO_SEH: u1 = 0,

    /// Do not bind the image.
    NO_BIND: u1 = 0,

    /// Image must execute in an AppContainer.
    APPCONTAINER: u1 = 0,

    /// A WDM driver.
    WDM_DRIVER: u1 = 0,

    /// Image supports Control Flow Guard.
    GUARD_CF: u1 = 0,

    /// Terminal Server aware.
    TERMINAL_SERVER_AWARE: u1 = 0,
};

pub const Subsystem = enum(u16) {
    /// An unknown subsystem
    UNKNOWN = 0,

    /// Device drivers and native Windows processes
    NATIVE = 1,

    /// The Windows graphical user interface (GUI) subsystem
    WINDOWS_GUI = 2,

    /// The Windows character subsystem
    WINDOWS_CUI = 3,

    /// The OS/2 character subsystem
    OS2_CUI = 5,

    /// The Posix character subsystem
    POSIX_CUI = 7,

    /// Native Win9x driver
    NATIVE_WINDOWS = 8,

    /// Windows CE
    WINDOWS_CE_GUI = 9,

    /// An Extensible Firmware Interface (EFI) application
    EFI_APPLICATION = 10,

    /// An EFI driver with boot services
    EFI_BOOT_SERVICE_DRIVER = 11,

    /// An EFI driver with run-time services
    EFI_RUNTIME_DRIVER = 12,

    /// An EFI ROM image
    EFI_ROM = 13,

    /// XBOX
    XBOX = 14,

    /// Windows boot application
    WINDOWS_BOOT_APPLICATION = 16,

    _,
};

pub const OptionalHeader = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
};

pub const OptionalHeaderPE32 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_flags: DllFlags,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

pub const OptionalHeaderPE64 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_flags: DllFlags,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

pub const DirectoryEntry = enum(u16) {
    /// Export Directory
    EXPORT = 0,

    /// Import Directory
    IMPORT = 1,

    /// Resource Directory
    RESOURCE = 2,

    /// Exception Directory
    EXCEPTION = 3,

    /// Security Directory
    SECURITY = 4,

    /// Base Relocation Table
    BASERELOC = 5,

    /// Debug Directory
    DEBUG = 6,

    /// Architecture Specific Data
    ARCHITECTURE = 7,

    /// RVA of GP
    GLOBALPTR = 8,

    /// TLS Directory
    TLS = 9,

    /// Load Configuration Directory
    LOAD_CONFIG = 10,

    /// Bound Import Directory in headers
    BOUND_IMPORT = 11,

    /// Import Address Table
    IAT = 12,

    /// Delay Load Import Descriptors
    DELAY_IMPORT = 13,

    /// COM Runtime descriptor
    COM_DESCRIPTOR = 14,

    _,
};

pub const ImageDataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
};

pub const BaseRelocationDirectoryEntry = extern struct {
    /// The image base plus the page RVA is added to each offset to create the VA where the base relocation must be applied.
    page_rva: u32,

    /// The total number of bytes in the base relocation block, including the Page RVA and Block Size fields and the Type/Offset fields that follow.
    block_size: u32,
};

pub const BaseRelocation = packed struct {
    /// Stored in the remaining 12 bits of the WORD, an offset from the starting address that was specified in the Page RVA field for the block.
    /// This offset specifies where the base relocation is to be applied.
    offset: u12,

    /// Stored in the high 4 bits of the WORD, a value that indicates the type of base relocation to be applied.
    type: BaseRelocationType,
};

pub const BaseRelocationType = enum(u4) {
    /// The base relocation is skipped. This type can be used to pad a block.
    ABSOLUTE = 0,

    /// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
    HIGH = 1,

    /// The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
    LOW = 2,

    /// The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
    HIGHLOW = 3,

    /// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
    /// The 16-bit field represents the high value of a 32-bit word.
    /// The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
    /// This means that this base relocation occupies two slots.
    HIGHADJ = 4,

    /// When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
    MIPS_JMPADDR = 5,

    /// This relocation is meaningful only when the machine type is ARM or Thumb.
    /// The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
    // ARM_MOV32 = 5,

    /// This relocation is only meaningful when the machine type is RISC-V.
    /// The base relocation applies to the high 20 bits of a 32-bit absolute address.
    // RISCV_HIGH20 = 5,

    /// Reserved, must be zero.
    RESERVED = 6,

    /// This relocation is meaningful only when the machine type is Thumb.
    /// The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
    THUMB_MOV32 = 7,

    /// This relocation is only meaningful when the machine type is RISC-V.
    /// The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
    // RISCV_LOW12I = 7,

    /// This relocation is only meaningful when the machine type is RISC-V.
    /// The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format.
    RISCV_LOW12S = 8,

    /// This relocation is only meaningful when the machine type is LoongArch 32-bit.
    /// The base relocation applies to a 32-bit absolute address formed in two consecutive instructions.
    // LOONGARCH32_MARK_LA = 8,

    /// This relocation is only meaningful when the machine type is LoongArch 64-bit.
    /// The base relocation applies to a 64-bit absolute address formed in four consecutive instructions.
    // LOONGARCH64_MARK_LA = 8,

    /// The relocation is only meaningful when the machine type is MIPS.
    /// The base relocation applies to a MIPS16 jump instruction.
    MIPS_JMPADDR16 = 9,

    /// The base relocation applies the difference to the 64-bit field at offset.
    DIR64 = 10,

    _,
};

pub const DebugDirectoryEntry = extern struct {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    type: DebugType,
    size_of_data: u32,
    address_of_raw_data: u32,
    pointer_to_raw_data: u32,
};

pub const DebugType = enum(u32) {
    UNKNOWN = 0,
    COFF = 1,
    CODEVIEW = 2,
    FPO = 3,
    MISC = 4,
    EXCEPTION = 5,
    FIXUP = 6,
    OMAP_TO_SRC = 7,
    OMAP_FROM_SRC = 8,
    BORLAND = 9,
    RESERVED10 = 10,
    VC_FEATURE = 12,
    POGO = 13,
    ILTCG = 14,
    MPX = 15,
    REPRO = 16,
    EX_DLLCHARACTERISTICS = 20,

    _,
};

pub const ImportDirectoryEntry = extern struct {
    /// The RVA of the import lookup table.
    /// This table contains a name or ordinal for each import.
    /// (The name "Characteristics" is used in Winnt.h, but no longer describes this field.)
    import_lookup_table_rva: u32,

    /// The stamp that is set to zero until the image is bound.
    /// After the image is bound, this field is set to the time/data stamp of the DLL.
    time_date_stamp: u32,

    /// The index of the first forwarder reference.
    forwarder_chain: u32,

    /// The address of an ASCII string that contains the name of the DLL.
    /// This address is relative to the image base.
    name_rva: u32,

    /// The RVA of the import address table.
    /// The contents of this table are identical to the contents of the import lookup table until the image is bound.
    import_address_table_rva: u32,
};

pub const ImportLookupEntry32 = struct {
    pub const ByName = packed struct {
        name_table_rva: u31,
        flag: u1 = 0,
    };

    pub const ByOrdinal = packed struct {
        ordinal_number: u16,
        unused: u15 = 0,
        flag: u1 = 1,
    };

    const mask = 0x80000000;

    pub fn getImportByName(raw: u32) ?ByName {
        if (mask & raw != 0) return null;
        return @as(ByName, @bitCast(raw));
    }

    pub fn getImportByOrdinal(raw: u32) ?ByOrdinal {
        if (mask & raw == 0) return null;
        return @as(ByOrdinal, @bitCast(raw));
    }
};

pub const ImportLookupEntry64 = struct {
    pub const ByName = packed struct {
        name_table_rva: u31,
        unused: u32 = 0,
        flag: u1 = 0,
    };

    pub const ByOrdinal = packed struct {
        ordinal_number: u16,
        unused: u47 = 0,
        flag: u1 = 1,
    };

    const mask = 0x8000000000000000;

    pub fn getImportByName(raw: u64) ?ByName {
        if (mask & raw != 0) return null;
        return @as(ByName, @bitCast(raw));
    }

    pub fn getImportByOrdinal(raw: u64) ?ByOrdinal {
        if (mask & raw == 0) return null;
        return @as(ByOrdinal, @bitCast(raw));
    }
};

/// Every name ends with a NULL byte. IF the NULL byte does not fall on
/// 2byte boundary, the entry structure is padded to ensure 2byte alignment.
pub const ImportHintNameEntry = extern struct {
    /// An index into the export name pointer table.
    /// A match is attempted first with this value. If it fails, a binary search is performed on the DLL's export name pointer table.
    hint: u16,

    /// Pointer to NULL terminated ASCII name.
    /// Variable length...
    name: [1]u8,
};

pub const SectionHeader = extern struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    flags: SectionHeaderFlags,

    pub fn getName(self: *align(1) const SectionHeader) ?[]const u8 {
        if (self.name[0] == '/') return null;
        const len = std.mem.indexOfScalar(u8, &self.name, @as(u8, 0)) orelse self.name.len;
        return self.name[0..len];
    }

    pub fn getNameOffset(self: SectionHeader) ?u32 {
        if (self.name[0] != '/') return null;
        const len = std.mem.indexOfScalar(u8, &self.name, @as(u8, 0)) orelse self.name.len;
        const offset = std.fmt.parseInt(u32, self.name[1..len], 10) catch unreachable;
        return offset;
    }

    /// Applicable only to section headers in COFF objects.
    pub fn getAlignment(self: SectionHeader) ?u16 {
        if (self.flags.ALIGN == 0) return null;
        return std.math.powi(u16, 2, self.flags.ALIGN - 1) catch unreachable;
    }

    pub fn setAlignment(self: *SectionHeader, new_alignment: u16) void {
        assert(new_alignment > 0 and new_alignment <= 8192);
        self.flags.ALIGN = @intCast(std.math.log2(new_alignment));
    }

    pub fn isCode(self: SectionHeader) bool {
        return self.flags.CNT_CODE == 0b1;
    }

    pub fn isComdat(self: SectionHeader) bool {
        return self.flags.LNK_COMDAT == 0b1;
    }
};

pub const SectionHeaderFlags = packed struct {
    _reserved_0: u3 = 0,

    /// The section should not be padded to the next boundary.
    /// This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.
    /// This is valid only for object files.
    TYPE_NO_PAD: u1 = 0,

    _reserved_1: u1 = 0,

    /// The section contains executable code.
    CNT_CODE: u1 = 0,

    /// The section contains initialized data.
    CNT_INITIALIZED_DATA: u1 = 0,

    /// The section contains uninitialized data.
    CNT_UNINITIALIZED_DATA: u1 = 0,

    /// Reserved for future use.
    LNK_OTHER: u1 = 0,

    /// The section contains comments or other information.
    /// The .drectve section has this type.
    /// This is valid for object files only.
    LNK_INFO: u1 = 0,

    _reserved_2: u1 = 0,

    /// The section will not become part of the image.
    /// This is valid only for object files.
    LNK_REMOVE: u1 = 0,

    /// The section contains COMDAT data.
    /// For more information, see COMDAT Sections (Object Only).
    /// This is valid only for object files.
    LNK_COMDAT: u1 = 0,

    _reserved_3: u2 = 0,

    /// The section contains data referenced through the global pointer (GP).
    GPREL: u1 = 0,

    /// Reserved for future use.
    MEM_PURGEABLE: u1 = 0,

    /// Reserved for future use.
    MEM_16BIT: u1 = 0,

    /// Reserved for future use.
    MEM_LOCKED: u1 = 0,

    /// Reserved for future use.
    MEM_PRELOAD: u1 = 0,

    /// Takes on multiple values according to flags:
    /// pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x100000;
    /// pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x200000;
    /// pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x300000;
    /// pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x400000;
    /// pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x500000;
    /// pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x600000;
    /// pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x700000;
    /// pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x800000;
    /// pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x900000;
    /// pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0xA00000;
    /// pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0xB00000;
    /// pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0xC00000;
    /// pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0xD00000;
    /// pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0xE00000;
    ALIGN: u4 = 0,

    /// The section contains extended relocations.
    LNK_NRELOC_OVFL: u1 = 0,

    /// The section can be discarded as needed.
    MEM_DISCARDABLE: u1 = 0,

    /// The section cannot be cached.
    MEM_NOT_CACHED: u1 = 0,

    /// The section is not pageable.
    MEM_NOT_PAGED: u1 = 0,

    /// The section can be shared in memory.
    MEM_SHARED: u1 = 0,

    /// The section can be executed as code.
    MEM_EXECUTE: u1 = 0,

    /// The section can be read.
    MEM_READ: u1 = 0,

    /// The section can be written to.
    MEM_WRITE: u1 = 0,
};

pub const Symbol = struct {
    name: [8]u8,
    value: u32,
    section_number: SectionNumber,
    type: SymType,
    storage_class: StorageClass,
    number_of_aux_symbols: u8,

    pub fn sizeOf() usize {
        return 18;
    }

    pub fn getName(self: *const Symbol) ?[]const u8 {
        if (std.mem.eql(u8, self.name[0..4], "\x00\x00\x00\x00")) return null;
        const len = std.mem.indexOfScalar(u8, &self.name, @as(u8, 0)) orelse self.name.len;
        return self.name[0..len];
    }

    pub fn getNameOffset(self: Symbol) ?u32 {
        if (!std.mem.eql(u8, self.name[0..4], "\x00\x00\x00\x00")) return null;
        const offset = std.mem.readInt(u32, self.name[4..8], .little);
        return offset;
    }
};

pub const SectionNumber = enum(u16) {
    /// The symbol record is not yet assigned a section.
    /// A value of zero indicates that a reference to an external symbol is defined elsewhere.
    /// A value of non-zero is a common symbol with a size that is specified by the value.
    UNDEFINED = 0,

    /// The symbol has an absolute (non-relocatable) value and is not an address.
    ABSOLUTE = 0xffff,

    /// The symbol provides general type or debugging information but does not correspond to a section.
    /// Microsoft tools use this setting along with .file records (storage class FILE).
    DEBUG = 0xfffe,
    _,
};

pub const SymType = packed struct {
    complex_type: ComplexType,
    base_type: BaseType,
};

pub const BaseType = enum(u8) {
    /// No type information or unknown base type. Microsoft tools use this setting
    NULL = 0,

    /// No valid type; used with void pointers and functions
    VOID = 1,

    /// A character (signed byte)
    CHAR = 2,

    /// A 2-byte signed integer
    SHORT = 3,

    /// A natural integer type (normally 4 bytes in Windows)
    INT = 4,

    /// A 4-byte signed integer
    LONG = 5,

    /// A 4-byte floating-point number
    FLOAT = 6,

    /// An 8-byte floating-point number
    DOUBLE = 7,

    /// A structure
    STRUCT = 8,

    /// A union
    UNION = 9,

    /// An enumerated type
    ENUM = 10,

    /// A member of enumeration (a specified value)
    MOE = 11,

    /// A byte; unsigned 1-byte integer
    BYTE = 12,

    /// A word; unsigned 2-byte integer
    WORD = 13,

    /// An unsigned integer of natural size (normally, 4 bytes)
    UINT = 14,

    /// An unsigned 4-byte integer
    DWORD = 15,

    _,
};

pub const ComplexType = enum(u8) {
    /// No derived type; the symbol is a simple scalar variable.
    NULL = 0,

    /// The symbol is a pointer to base type.
    POINTER = 16,

    /// The symbol is a function that returns a base type.
    FUNCTION = 32,

    /// The symbol is an array of base type.
    ARRAY = 48,

    _,
};

pub const StorageClass = enum(u8) {
    /// A special symbol that represents the end of function, for debugging purposes.
    END_OF_FUNCTION = 0xff,

    /// No assigned storage class.
    NULL = 0,

    /// The automatic (stack) variable. The Value field specifies the stack frame offset.
    AUTOMATIC = 1,

    /// A value that Microsoft tools use for external symbols.
    /// The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0).
    /// If the section number is not zero, then the Value field specifies the offset within the section.
    EXTERNAL = 2,

    /// The offset of the symbol within the section.
    /// If the Value field is zero, then the symbol represents a section name.
    STATIC = 3,

    /// A register variable.
    /// The Value field specifies the register number.
    REGISTER = 4,

    /// A symbol that is defined externally.
    EXTERNAL_DEF = 5,

    /// A code label that is defined within the module.
    /// The Value field specifies the offset of the symbol within the section.
    LABEL = 6,

    /// A reference to a code label that is not defined.
    UNDEFINED_LABEL = 7,

    /// The structure member. The Value field specifies the n th member.
    MEMBER_OF_STRUCT = 8,

    /// A formal argument (parameter) of a function. The Value field specifies the n th argument.
    ARGUMENT = 9,

    /// The structure tag-name entry.
    STRUCT_TAG = 10,

    /// A union member. The Value field specifies the n th member.
    MEMBER_OF_UNION = 11,

    /// The Union tag-name entry.
    UNION_TAG = 12,

    /// A Typedef entry.
    TYPE_DEFINITION = 13,

    /// A static data declaration.
    UNDEFINED_STATIC = 14,

    /// An enumerated type tagname entry.
    ENUM_TAG = 15,

    /// A member of an enumeration. The Value field specifies the n th member.
    MEMBER_OF_ENUM = 16,

    /// A register parameter.
    REGISTER_PARAM = 17,

    /// A bit-field reference. The Value field specifies the n th bit in the bit field.
    BIT_FIELD = 18,

    /// A .bb (beginning of block) or .eb (end of block) record.
    /// The Value field is the relocatable address of the code location.
    BLOCK = 100,

    /// A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf ), end function ( .ef ), and lines in function ( .lf ).
    /// For .lf records, the Value field gives the number of source lines in the function.
    /// For .ef records, the Value field gives the size of the function code.
    FUNCTION = 101,

    /// An end-of-structure entry.
    END_OF_STRUCT = 102,

    /// A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record.
    /// The symbol is followed by auxiliary records that name the file.
    FILE = 103,

    /// A definition of a section (Microsoft tools use STATIC storage class instead).
    SECTION = 104,

    /// A weak external. For more information, see Auxiliary Format 3: Weak Externals.
    WEAK_EXTERNAL = 105,

    /// A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token.
    /// For more information, see CLR Token Definition (Object Only).
    CLR_TOKEN = 107,

    _,
};

pub const FunctionDefinition = struct {
    /// The symbol-table index of the corresponding .bf (begin function) symbol record.
    tag_index: u32,

    /// The size of the executable code for the function itself.
    /// If the function is in its own section, the SizeOfRawData in the section header is greater or equal to this field,
    /// depending on alignment considerations.
    total_size: u32,

    /// The file offset of the first COFF line-number entry for the function, or zero if none exists.
    pointer_to_linenumber: u32,

    /// The symbol-table index of the record for the next function.
    /// If the function is the last in the symbol table, this field is set to zero.
    pointer_to_next_function: u32,

    unused: [2]u8,
};

pub const SectionDefinition = struct {
    /// The size of section data; the same as SizeOfRawData in the section header.
    length: u32,

    /// The number of relocation entries for the section.
    number_of_relocations: u16,

    /// The number of line-number entries for the section.
    number_of_linenumbers: u16,

    /// The checksum for communal data. It is applicable if the IMAGE_SCN_LNK_COMDAT flag is set in the section header.
    checksum: u32,

    /// One-based index into the section table for the associated section. This is used when the COMDAT selection setting is 5.
    number: u16,

    /// The COMDAT selection number. This is applicable if the section is a COMDAT section.
    selection: ComdatSelection,

    unused: [3]u8,
};

pub const FileDefinition = struct {
    /// An ANSI string that gives the name of the source file.
    /// This is padded with nulls if it is less than the maximum length.
    file_name: [18]u8,

    pub fn getFileName(self: *const FileDefinition) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.file_name, @as(u8, 0)) orelse self.file_name.len;
        return self.file_name[0..len];
    }
};

pub const WeakExternalDefinition = struct {
    /// The symbol-table index of sym2, the symbol to be linked if sym1 is not found.
    tag_index: u32,

    /// A value of IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY indicates that no library search for sym1 should be performed.
    /// A value of IMAGE_WEAK_EXTERN_SEARCH_LIBRARY indicates that a library search for sym1 should be performed.
    /// A value of IMAGE_WEAK_EXTERN_SEARCH_ALIAS indicates that sym1 is an alias for sym2.
    flag: WeakExternalFlag,

    unused: [10]u8,
};

// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/km/ntimage.h
pub const WeakExternalFlag = enum(u32) {
    SEARCH_NOLIBRARY = 1,
    SEARCH_LIBRARY = 2,
    SEARCH_ALIAS = 3,
    ANTI_DEPENDENCY = 4,
    _,
};

pub const ComdatSelection = enum(u8) {
    /// Not a COMDAT section.
    NONE = 0,

    /// If this symbol is already defined, the linker issues a "multiply defined symbol" error.
    NODUPLICATES = 1,

    /// Any section that defines the same COMDAT symbol can be linked; the rest are removed.
    ANY = 2,

    /// The linker chooses an arbitrary section among the definitions for this symbol.
    /// If all definitions are not the same size, a "multiply defined symbol" error is issued.
    SAME_SIZE = 3,

    /// The linker chooses an arbitrary section among the definitions for this symbol.
    /// If all definitions do not match exactly, a "multiply defined symbol" error is issued.
    EXACT_MATCH = 4,

    /// The section is linked if a certain other COMDAT section is linked.
    /// This other section is indicated by the Number field of the auxiliary symbol record for the section definition.
    /// This setting is useful for definitions that have components in multiple sections
    /// (for example, code in one and data in another), but where all must be linked or discarded as a set.
    /// The other section this section is associated with must be a COMDAT section, which can be another
    /// associative COMDAT section. An associative COMDAT section's section association chain can't form a loop.
    /// The section association chain must eventually come to a COMDAT section that doesn't have IMAGE_COMDAT_SELECT_ASSOCIATIVE set.
    ASSOCIATIVE = 5,

    /// The linker chooses the largest definition from among all of the definitions for this symbol.
    /// If multiple definitions have this size, the choice between them is arbitrary.
    LARGEST = 6,

    _,
};

pub const DebugInfoDefinition = struct {
    unused_1: [4]u8,

    /// The actual ordinal line number (1, 2, 3, and so on) within the source file, corresponding to the .bf or .ef record.
    linenumber: u16,

    unused_2: [6]u8,

    /// The symbol-table index of the next .bf symbol record.
    /// If the function is the last in the symbol table, this field is set to zero.
    /// It is not used for .ef records.
    pointer_to_next_function: u32,

    unused_3: [2]u8,
};

pub const MachineType = enum(u16) {
    UNKNOWN = 0x0,
    /// Alpha AXP, 32-bit address space
    ALPHA = 0x184,
    /// Alpha 64, 64-bit address space
    ALPHA64 = 0x284,
    /// Matsushita AM33
    AM33 = 0x1d3,
    /// x64
    X64 = 0x8664,
    /// ARM little endian
    ARM = 0x1c0,
    /// ARM64 little endian
    ARM64 = 0xaa64,
    /// ARM64EC
    ARM64EC = 0xa641,
    /// ARM64X
    ARM64X = 0xa64e,
    /// ARM Thumb-2 little endian
    ARMNT = 0x1c4,
    /// CEE
    CEE = 0xc0ee,
    /// CEF
    CEF = 0xcef,
    /// Hybrid PE
    CHPE_X86 = 0x3a64,
    /// EFI byte code
    EBC = 0xebc,
    /// Intel 386 or later processors and compatible processors
    I386 = 0x14c,
    /// Intel Itanium processor family
    IA64 = 0x200,
    /// LoongArch32
    LOONGARCH32 = 0x6232,
    /// LoongArch64
    LOONGARCH64 = 0x6264,
    /// Mitsubishi M32R little endian
    M32R = 0x9041,
    /// MIPS16
    MIPS16 = 0x266,
    /// MIPS with FPU
    MIPSFPU = 0x366,
    /// MIPS16 with FPU
    MIPSFPU16 = 0x466,
    /// Power PC little endian
    POWERPC = 0x1f0,
    /// Power PC with floating point support
    POWERPCFP = 0x1f1,
    /// MIPS little endian
    R3000 = 0x162,
    /// MIPS little endian
    R4000 = 0x166,
    /// MIPS little endian
    R10000 = 0x168,
    /// RISC-V 32-bit address space
    RISCV32 = 0x5032,
    /// RISC-V 64-bit address space
    RISCV64 = 0x5064,
    /// RISC-V 128-bit address space
    RISCV128 = 0x5128,
    /// Hitachi SH3
    SH3 = 0x1a2,
    /// Hitachi SH3 DSP
    SH3DSP = 0x1a3,
    /// SH3E little-endian
    SH3E = 0x1a4,
    /// Hitachi SH4
    SH4 = 0x1a6,
    /// Hitachi SH5
    SH5 = 0x1a8,
    /// Thumb
    THUMB = 0x1c2,
    /// Infineon
    TRICORE = 0x520,
    /// MIPS little-endian WCE v2
    WCEMIPSV2 = 0x169,

    _,
};

pub const CoffError = error{
    InvalidPEMagic,
    InvalidPEHeader,
    InvalidMachine,
    MissingPEHeader,
    MissingCoffSection,
    MissingStringTable,
};

// Official documentation of the format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
pub const Coff = struct {
    data: []const u8,
    // Set if `data` is backed by the image as loaded by the loader
    is_loaded: bool,
    is_image: bool,
    coff_header_offset: usize,

    guid: [16]u8 = undefined,
    age: u32 = undefined,

    // The lifetime of `data` must be longer than the lifetime of the returned Coff
    pub fn init(data: []const u8, is_loaded: bool) !Coff {
        const pe_pointer_offset = 0x3C;
        const pe_magic = "PE\x00\x00";

        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();
        try stream.seekTo(pe_pointer_offset);
        const coff_header_offset = try reader.readInt(u32, .little);
        try stream.seekTo(coff_header_offset);
        var buf: [4]u8 = undefined;
        try reader.readNoEof(&buf);
        const is_image = mem.eql(u8, pe_magic, &buf);

        var coff = @This(){
            .data = data,
            .is_image = is_image,
            .is_loaded = is_loaded,
            .coff_header_offset = coff_header_offset,
        };

        // Do some basic validation upfront
        if (is_image) {
            coff.coff_header_offset = coff.coff_header_offset + 4;
            const coff_header = coff.getCoffHeader();
            if (coff_header.size_of_optional_header == 0) return error.MissingPEHeader;
        }

        // JK: we used to check for architecture here and throw an error if not x86 or derivative.
        // However I am willing to take a leap of faith and let aarch64 have a shot also.

        return coff;
    }

    pub fn getPdbPath(self: *Coff) !?[]const u8 {
        assert(self.is_image);

        const data_dirs = self.getDataDirectories();
        if (@intFromEnum(DirectoryEntry.DEBUG) >= data_dirs.len) return null;

        const debug_dir = data_dirs[@intFromEnum(DirectoryEntry.DEBUG)];
        var stream = std.io.fixedBufferStream(self.data);
        const reader = stream.reader();

        if (self.is_loaded) {
            try stream.seekTo(debug_dir.virtual_address);
        } else {
            // Find what section the debug_dir is in, in order to convert the RVA to a file offset
            for (self.getSectionHeaders()) |*sect| {
                if (debug_dir.virtual_address >= sect.virtual_address and debug_dir.virtual_address < sect.virtual_address + sect.virtual_size) {
                    try stream.seekTo(sect.pointer_to_raw_data + (debug_dir.virtual_address - sect.virtual_address));
                    break;
                }
            } else return error.InvalidDebugDirectory;
        }

        // Find the correct DebugDirectoryEntry, and where its data is stored.
        // It can be in any section.
        const debug_dir_entry_count = debug_dir.size / @sizeOf(DebugDirectoryEntry);
        var i: u32 = 0;
        while (i < debug_dir_entry_count) : (i += 1) {
            const debug_dir_entry = try reader.readStruct(DebugDirectoryEntry);
            if (debug_dir_entry.type == .CODEVIEW) {
                const dir_offset = if (self.is_loaded) debug_dir_entry.address_of_raw_data else debug_dir_entry.pointer_to_raw_data;
                try stream.seekTo(dir_offset);
                break;
            }
        } else return null;

        var cv_signature: [4]u8 = undefined; // CodeView signature
        try reader.readNoEof(cv_signature[0..]);
        // 'RSDS' indicates PDB70 format, used by lld.
        if (!mem.eql(u8, &cv_signature, "RSDS"))
            return error.InvalidPEMagic;
        try reader.readNoEof(self.guid[0..]);
        self.age = try reader.readInt(u32, .little);

        // Finally read the null-terminated string.
        const start = reader.context.pos;
        const len = std.mem.indexOfScalar(u8, self.data[start..], 0) orelse return null;
        return self.data[start .. start + len];
    }

    pub fn getCoffHeader(self: Coff) CoffHeader {
        return @as(*align(1) const CoffHeader, @ptrCast(self.data[self.coff_header_offset..][0..@sizeOf(CoffHeader)])).*;
    }

    pub fn getOptionalHeader(self: Coff) OptionalHeader {
        assert(self.is_image);
        const offset = self.coff_header_offset + @sizeOf(CoffHeader);
        return @as(*align(1) const OptionalHeader, @ptrCast(self.data[offset..][0..@sizeOf(OptionalHeader)])).*;
    }

    pub fn getOptionalHeader32(self: Coff) OptionalHeaderPE32 {
        assert(self.is_image);
        const offset = self.coff_header_offset + @sizeOf(CoffHeader);
        return @as(*align(1) const OptionalHeaderPE32, @ptrCast(self.data[offset..][0..@sizeOf(OptionalHeaderPE32)])).*;
    }

    pub fn getOptionalHeader64(self: Coff) OptionalHeaderPE64 {
        assert(self.is_image);
        const offset = self.coff_header_offset + @sizeOf(CoffHeader);
        return @as(*align(1) const OptionalHeaderPE64, @ptrCast(self.data[offset..][0..@sizeOf(OptionalHeaderPE64)])).*;
    }

    pub fn getImageBase(self: Coff) u64 {
        const hdr = self.getOptionalHeader();
        return switch (hdr.magic) {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.getOptionalHeader32().image_base,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.getOptionalHeader64().image_base,
            else => unreachable, // We assume we have validated the header already
        };
    }

    pub fn getNumberOfDataDirectories(self: Coff) u32 {
        const hdr = self.getOptionalHeader();
        return switch (hdr.magic) {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.getOptionalHeader32().number_of_rva_and_sizes,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.getOptionalHeader64().number_of_rva_and_sizes,
            else => unreachable, // We assume we have validated the header already
        };
    }

    pub fn getDataDirectories(self: *const Coff) []align(1) const ImageDataDirectory {
        const hdr = self.getOptionalHeader();
        const size: usize = switch (hdr.magic) {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => @sizeOf(OptionalHeaderPE32),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => @sizeOf(OptionalHeaderPE64),
            else => unreachable, // We assume we have validated the header already
        };
        const offset = self.coff_header_offset + @sizeOf(CoffHeader) + size;
        return @as([*]align(1) const ImageDataDirectory, @ptrCast(self.data[offset..]))[0..self.getNumberOfDataDirectories()];
    }

    pub fn getSymtab(self: *const Coff) ?Symtab {
        const coff_header = self.getCoffHeader();
        if (coff_header.pointer_to_symbol_table == 0) return null;

        const offset = coff_header.pointer_to_symbol_table;
        const size = coff_header.number_of_symbols * Symbol.sizeOf();
        return .{ .buffer = self.data[offset..][0..size] };
    }

    pub fn getStrtab(self: *const Coff) error{InvalidStrtabSize}!?Strtab {
        const coff_header = self.getCoffHeader();
        if (coff_header.pointer_to_symbol_table == 0) return null;

        const offset = coff_header.pointer_to_symbol_table + Symbol.sizeOf() * coff_header.number_of_symbols;
        const size = mem.readInt(u32, self.data[offset..][0..4], .little);
        if ((offset + size) > self.data.len) return error.InvalidStrtabSize;

        return Strtab{ .buffer = self.data[offset..][0..size] };
    }

    pub fn strtabRequired(self: *const Coff) bool {
        for (self.getSectionHeaders()) |*sect_hdr| if (sect_hdr.getName() == null) return true;
        return false;
    }

    pub fn getSectionHeaders(self: *const Coff) []align(1) const SectionHeader {
        const coff_header = self.getCoffHeader();
        const offset = self.coff_header_offset + @sizeOf(CoffHeader) + coff_header.size_of_optional_header;
        return @as([*]align(1) const SectionHeader, @ptrCast(self.data.ptr + offset))[0..coff_header.number_of_sections];
    }

    pub fn getSectionHeadersAlloc(self: *const Coff, allocator: mem.Allocator) ![]SectionHeader {
        const section_headers = self.getSectionHeaders();
        const out_buff = try allocator.alloc(SectionHeader, section_headers.len);
        for (out_buff, 0..) |*section_header, i| {
            section_header.* = section_headers[i];
        }

        return out_buff;
    }

    pub fn getSectionName(self: *const Coff, sect_hdr: *align(1) const SectionHeader) error{InvalidStrtabSize}![]const u8 {
        const name = sect_hdr.getName() orelse blk: {
            const strtab = (try self.getStrtab()).?;
            const name_offset = sect_hdr.getNameOffset().?;
            break :blk strtab.get(name_offset);
        };
        return name;
    }

    pub fn getSectionByName(self: *const Coff, comptime name: []const u8) ?*align(1) const SectionHeader {
        for (self.getSectionHeaders()) |*sect| {
            const section_name = self.getSectionName(sect) catch |e| switch (e) {
                error.InvalidStrtabSize => continue, //ignore invalid(?) strtab entries - see also GitHub issue #15238
            };
            if (mem.eql(u8, section_name, name)) {
                return sect;
            }
        }
        return null;
    }

    pub fn getSectionData(self: *const Coff, sec: *align(1) const SectionHeader) []const u8 {
        const offset = if (self.is_loaded) sec.virtual_address else sec.pointer_to_raw_data;
        return self.data[offset..][0..sec.virtual_size];
    }

    pub fn getSectionDataAlloc(self: *const Coff, sec: *align(1) const SectionHeader, allocator: mem.Allocator) ![]u8 {
        const section_data = self.getSectionData(sec);
        return allocator.dupe(u8, section_data);
    }
};

pub const Symtab = struct {
    buffer: []const u8,

    pub fn len(self: Symtab) usize {
        return @divExact(self.buffer.len, Symbol.sizeOf());
    }

    pub const Tag = enum {
        symbol,
        debug_info,
        func_def,
        weak_ext,
        file_def,
        sect_def,
    };

    pub const Record = union(Tag) {
        symbol: Symbol,
        debug_info: DebugInfoDefinition,
        func_def: FunctionDefinition,
        weak_ext: WeakExternalDefinition,
        file_def: FileDefinition,
        sect_def: SectionDefinition,
    };

    /// Lives as long as Symtab instance.
    pub fn at(self: Symtab, index: usize, tag: Tag) Record {
        const offset = index * Symbol.sizeOf();
        const raw = self.buffer[offset..][0..Symbol.sizeOf()];
        return switch (tag) {
            .symbol => .{ .symbol = asSymbol(raw) },
            .debug_info => .{ .debug_info = asDebugInfo(raw) },
            .func_def => .{ .func_def = asFuncDef(raw) },
            .weak_ext => .{ .weak_ext = asWeakExtDef(raw) },
            .file_def => .{ .file_def = asFileDef(raw) },
            .sect_def => .{ .sect_def = asSectDef(raw) },
        };
    }

    fn asSymbol(raw: []const u8) Symbol {
        return .{
            .name = raw[0..8].*,
            .value = mem.readInt(u32, raw[8..12], .little),
            .section_number = @as(SectionNumber, @enumFromInt(mem.readInt(u16, raw[12..14], .little))),
            .type = @as(SymType, @bitCast(mem.readInt(u16, raw[14..16], .little))),
            .storage_class = @as(StorageClass, @enumFromInt(raw[16])),
            .number_of_aux_symbols = raw[17],
        };
    }

    fn asDebugInfo(raw: []const u8) DebugInfoDefinition {
        return .{
            .unused_1 = raw[0..4].*,
            .linenumber = mem.readInt(u16, raw[4..6], .little),
            .unused_2 = raw[6..12].*,
            .pointer_to_next_function = mem.readInt(u32, raw[12..16], .little),
            .unused_3 = raw[16..18].*,
        };
    }

    fn asFuncDef(raw: []const u8) FunctionDefinition {
        return .{
            .tag_index = mem.readInt(u32, raw[0..4], .little),
            .total_size = mem.readInt(u32, raw[4..8], .little),
            .pointer_to_linenumber = mem.readInt(u32, raw[8..12], .little),
            .pointer_to_next_function = mem.readInt(u32, raw[12..16], .little),
            .unused = raw[16..18].*,
        };
    }

    fn asWeakExtDef(raw: []const u8) WeakExternalDefinition {
        return .{
            .tag_index = mem.readInt(u32, raw[0..4], .little),
            .flag = @as(WeakExternalFlag, @enumFromInt(mem.readInt(u32, raw[4..8], .little))),
            .unused = raw[8..18].*,
        };
    }

    fn asFileDef(raw: []const u8) FileDefinition {
        return .{
            .file_name = raw[0..18].*,
        };
    }

    fn asSectDef(raw: []const u8) SectionDefinition {
        return .{
            .length = mem.readInt(u32, raw[0..4], .little),
            .number_of_relocations = mem.readInt(u16, raw[4..6], .little),
            .number_of_linenumbers = mem.readInt(u16, raw[6..8], .little),
            .checksum = mem.readInt(u32, raw[8..12], .little),
            .number = mem.readInt(u16, raw[12..14], .little),
            .selection = @as(ComdatSelection, @enumFromInt(raw[14])),
            .unused = raw[15..18].*,
        };
    }

    pub const Slice = struct {
        buffer: []const u8,
        num: usize,
        count: usize = 0,

        /// Lives as long as Symtab instance.
        pub fn next(self: *Slice) ?Symbol {
            if (self.count >= self.num) return null;
            const sym = asSymbol(self.buffer[0..Symbol.sizeOf()]);
            self.count += 1;
            self.buffer = self.buffer[Symbol.sizeOf()..];
            return sym;
        }
    };

    pub fn slice(self: Symtab, start: usize, end: ?usize) Slice {
        const offset = start * Symbol.sizeOf();
        const llen = if (end) |e| e * Symbol.sizeOf() else self.buffer.len;
        const num = @divExact(llen - offset, Symbol.sizeOf());
        return Slice{ .buffer = self.buffer[offset..][0..llen], .num = num };
    }
};

pub const Strtab = struct {
    buffer: []const u8,

    pub fn get(self: Strtab, off: u32) []const u8 {
        assert(off < self.buffer.len);
        return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.buffer.ptr + off)), 0);
    }
};

pub const ImportHeader = extern struct {
    sig1: MachineType,
    sig2: u16,
    version: u16,
    machine: MachineType,
    time_date_stamp: u32,
    size_of_data: u32,
    hint: u16,
    types: packed struct {
        type: ImportType,
        name_type: ImportNameType,
        reserved: u11,
    },
};

pub const ImportType = enum(u2) {
    /// Executable code.
    CODE = 0,
    /// Data.
    DATA = 1,
    /// Specified as CONST in .def file.
    CONST = 2,
    _,
};

pub const ImportNameType = enum(u3) {
    /// The import is by ordinal. This indicates that the value in the Ordinal/Hint
    /// field of the import header is the import's ordinal. If this constant is not
    /// specified, then the Ordinal/Hint field should always be interpreted as the import's hint.
    ORDINAL = 0,
    /// The import name is identical to the public symbol name.
    NAME = 1,
    /// The import name is the public symbol name, but skipping the leading ?, @, or optionally _.
    NAME_NOPREFIX = 2,
    /// The import name is the public symbol name, but skipping the leading ?, @, or optionally _,
    /// and truncating at the first @.
    NAME_UNDECORATE = 3,
    /// https://github.com/llvm/llvm-project/pull/83211
    NAME_EXPORTAS = 4,
    _,
};

pub const Relocation = extern struct {
    virtual_address: u32,
    symbol_table_index: u32,
    type: u16,
};

pub const ImageRelAmd64 = enum(u16) {
    /// The relocation is ignored.
    absolute = 0,

    /// The 64-bit VA of the relocation target.
    addr64 = 1,

    /// The 32-bit VA of the relocation target.
    addr32 = 2,

    /// The 32-bit address without an image base.
    addr32nb = 3,

    /// The 32-bit relative address from the byte following the relocation.
    rel32 = 4,

    /// The 32-bit address relative to byte distance 1 from the relocation.
    rel32_1 = 5,

    /// The 32-bit address relative to byte distance 2 from the relocation.
    rel32_2 = 6,

    /// The 32-bit address relative to byte distance 3 from the relocation.
    rel32_3 = 7,

    /// The 32-bit address relative to byte distance 4 from the relocation.
    rel32_4 = 8,

    /// The 32-bit address relative to byte distance 5 from the relocation.
    rel32_5 = 9,

    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    section = 10,

    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    secrel = 11,

    /// A 7-bit unsigned offset from the base of the section that contains the target.
    secrel7 = 12,

    /// CLR tokens.
    token = 13,

    /// A 32-bit signed span-dependent value emitted into the object.
    srel32 = 14,

    /// A pair that must immediately follow every span-dependent value.
    pair = 15,

    /// A 32-bit signed span-dependent value that is applied at link time.
    sspan32 = 16,

    _,
};

pub const ImageRelArm64 = enum(u16) {
    /// The relocation is ignored.
    absolute = 0,

    /// The 32-bit VA of the target.
    addr32 = 1,

    /// The 32-bit RVA of the target.
    addr32nb = 2,

    /// The 26-bit relative displacement to the target, for B and BL instructions.
    branch26 = 3,

    /// The page base of the target, for ADRP instruction.
    pagebase_rel21 = 4,

    /// The 21-bit relative displacement to the target, for instruction ADR.
    rel21 = 5,

    /// The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    pageoffset_12a = 6,

    /// The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
    pageoffset_12l = 7,

    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    secrel = 8,

    /// Bit 0:11 of section offset of the target for instructions ADD/ADDS (immediate) with zero shift.
    low12a = 9,

    /// Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    high12a = 10,

    /// Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
    low12l = 11,

    /// CLR token.
    token = 12,

    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    section = 13,

    /// The 64-bit VA of the relocation target.
    addr64 = 14,

    /// The 19-bit offset to the relocation target, for conditional B instruction.
    branch19 = 15,

    /// The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
    branch14 = 16,

    /// The 32-bit relative address from the byte following the relocation.
    rel32 = 17,

    _,
};
//! Compression algorithms.

const std = @import("std.zig");

pub const flate = @import("compress/flate.zig");
pub const gzip = @import("compress/gzip.zig");
pub const zlib = @import("compress/zlib.zig");
pub const lzma = @import("compress/lzma.zig");
pub const lzma2 = @import("compress/lzma2.zig");
pub const xz = @import("compress/xz.zig");
pub const zstd = @import("compress/zstandard.zig");

pub fn HashedReader(ReaderType: type, HasherType: type) type {
    return struct {
        child_reader: ReaderType,
        hasher: HasherType,

        pub const Error = ReaderType.Error;
        pub const Reader = std.io.Reader(*@This(), Error, read);

        pub fn read(self: *@This(), buf: []u8) Error!usize {
            const amt = try self.child_reader.read(buf);
            self.hasher.update(buf[0..amt]);
            return amt;
        }

        pub fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }
    };
}

pub fn hashedReader(
    reader: anytype,
    hasher: anytype,
) HashedReader(@TypeOf(reader), @TypeOf(hasher)) {
    return .{ .child_reader = reader, .hasher = hasher };
}

pub fn HashedWriter(WriterType: type, HasherType: type) type {
    return struct {
        child_writer: WriterType,
        hasher: HasherType,

        pub const Error = WriterType.Error;
        pub const Writer = std.io.Writer(*@This(), Error, write);

        pub fn write(self: *@This(), buf: []const u8) Error!usize {
            const amt = try self.child_writer.write(buf);
            self.hasher.update(buf[0..amt]);
            return amt;
        }

        pub fn writer(self: *@This()) Writer {
            return .{ .context = self };
        }
    };
}

pub fn hashedWriter(
    writer: anytype,
    hasher: anytype,
) HashedWriter(@TypeOf(writer), @TypeOf(hasher)) {
    return .{ .child_writer = writer, .hasher = hasher };
}

test {
    _ = lzma;
    _ = lzma2;
    _ = xz;
    _ = zstd;
    _ = flate;
    _ = gzip;
    _ = zlib;
}
/// Deflate is a lossless data compression file format that uses a combination
/// of LZ77 and Huffman coding.
pub const deflate = @import("flate/deflate.zig");

/// Inflate is the decoding process that takes a Deflate bitstream for
/// decompression and correctly produces the original full-size data or file.
pub const inflate = @import("flate/inflate.zig");

/// Decompress compressed data from reader and write plain data to the writer.
pub fn decompress(reader: anytype, writer: anytype) !void {
    try inflate.decompress(.raw, reader, writer);
}

/// Decompressor type
pub fn Decompressor(comptime ReaderType: type) type {
    return inflate.Decompressor(.raw, ReaderType);
}

/// Create Decompressor which will read compressed data from reader.
pub fn decompressor(reader: anytype) Decompressor(@TypeOf(reader)) {
    return inflate.decompressor(.raw, reader);
}

/// Compression level, trades between speed and compression size.
pub const Options = deflate.Options;

/// Compress plain data from reader and write compressed data to the writer.
pub fn compress(reader: anytype, writer: anytype, options: Options) !void {
    try deflate.compress(.raw, reader, writer, options);
}

/// Compressor type
pub fn Compressor(comptime WriterType: type) type {
    return deflate.Compressor(.raw, WriterType);
}

/// Create Compressor which outputs compressed data to the writer.
pub fn compressor(writer: anytype, options: Options) !Compressor(@TypeOf(writer)) {
    return try deflate.compressor(.raw, writer, options);
}

/// Huffman only compression. Without Lempel-Ziv match searching. Faster
/// compression, less memory requirements but bigger compressed sizes.
pub const huffman = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.huffman.compress(.raw, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.huffman.Compressor(.raw, WriterType);
    }

    pub fn compressor(writer: anytype) !huffman.Compressor(@TypeOf(writer)) {
        return deflate.huffman.compressor(.raw, writer);
    }
};

// No compression store only. Compressed size is slightly bigger than plain.
pub const store = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.store.compress(.raw, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.store.Compressor(.raw, WriterType);
    }

    pub fn compressor(writer: anytype) !store.Compressor(@TypeOf(writer)) {
        return deflate.store.compressor(.raw, writer);
    }
};

/// Container defines header/footer around deflate bit stream. Gzip and zlib
/// compression algorithms are containers around deflate bit stream body.
const Container = @import("flate/container.zig").Container;
const std = @import("std");
const testing = std.testing;
const fixedBufferStream = std.io.fixedBufferStream;
const print = std.debug.print;
const builtin = @import("builtin");

test {
    _ = deflate;
    _ = inflate;
}

test "compress/decompress" {
    var cmp_buf: [64 * 1024]u8 = undefined; // compressed data buffer
    var dcm_buf: [64 * 1024]u8 = undefined; // decompressed data buffer

    const levels = [_]deflate.Level{ .level_4, .level_5, .level_6, .level_7, .level_8, .level_9 };
    const cases = [_]struct {
        data: []const u8, // uncompressed content
        // compressed data sizes per level 4-9
        gzip_sizes: [levels.len]usize = [_]usize{0} ** levels.len,
        huffman_only_size: usize = 0,
        store_size: usize = 0,
    }{
        .{
            .data = @embedFile("flate/testdata/rfc1951.txt"),
            .gzip_sizes = [_]usize{ 11513, 11217, 11139, 11126, 11122, 11119 },
            .huffman_only_size = 20287,
            .store_size = 36967,
        },
        .{
            .data = @embedFile("flate/testdata/fuzz/roundtrip1.input"),
            .gzip_sizes = [_]usize{ 373, 370, 370, 370, 370, 370 },
            .huffman_only_size = 393,
            .store_size = 393,
        },
        .{
            .data = @embedFile("flate/testdata/fuzz/roundtrip2.input"),
            .gzip_sizes = [_]usize{ 373, 373, 373, 373, 373, 373 },
            .huffman_only_size = 394,
            .store_size = 394,
        },
        .{
            .data = @embedFile("flate/testdata/fuzz/deflate-stream.expect"),
            .gzip_sizes = [_]usize{ 351, 347, 347, 347, 347, 347 },
            .huffman_only_size = 498,
            .store_size = 747,
        },
    };

    for (cases, 0..) |case, case_no| { // for each case
        const data = case.data;

        for (levels, 0..) |level, i| { // for each compression level

            inline for (Container.list) |container| { // for each wrapping
                var compressed_size: usize = if (case.gzip_sizes[i] > 0)
                    case.gzip_sizes[i] - Container.gzip.size() + container.size()
                else
                    0;

                // compress original stream to compressed stream
                {
                    var original = fixedBufferStream(data);
                    var compressed = fixedBufferStream(&cmp_buf);
                    try deflate.compress(container, original.reader(), compressed.writer(), .{ .level = level });
                    if (compressed_size == 0) {
                        if (container == .gzip)
                            print("case {d} gzip level {} compressed size: {d}\n", .{ case_no, level, compressed.pos });
                        compressed_size = compressed.pos;
                    }
                    try testing.expectEqual(compressed_size, compressed.pos);
                }
                // decompress compressed stream to decompressed stream
                {
                    var compressed = fixedBufferStream(cmp_buf[0..compressed_size]);
                    var decompressed = fixedBufferStream(&dcm_buf);
                    try inflate.decompress(container, compressed.reader(), decompressed.writer());
                    try testing.expectEqualSlices(u8, data, decompressed.getWritten());
                }

                // compressor writer interface
                {
                    var compressed = fixedBufferStream(&cmp_buf);
                    var cmp = try deflate.compressor(container, compressed.writer(), .{ .level = level });
                    var cmp_wrt = cmp.writer();
                    try cmp_wrt.writeAll(data);
                    try cmp.finish();

                    try testing.expectEqual(compressed_size, compressed.pos);
                }
                // decompressor reader interface
                {
                    var compressed = fixedBufferStream(cmp_buf[0..compressed_size]);
                    var dcm = inflate.decompressor(container, compressed.reader());
                    var dcm_rdr = dcm.reader();
                    const n = try dcm_rdr.readAll(&dcm_buf);
                    try testing.expectEqual(data.len, n);
                    try testing.expectEqualSlices(u8, data, dcm_buf[0..n]);
                }
            }
        }
        // huffman only compression
        {
            inline for (Container.list) |container| { // for each wrapping
                var compressed_size: usize = if (case.huffman_only_size > 0)
                    case.huffman_only_size - Container.gzip.size() + container.size()
                else
                    0;

                // compress original stream to compressed stream
                {
                    var original = fixedBufferStream(data);
                    var compressed = fixedBufferStream(&cmp_buf);
                    var cmp = try deflate.huffman.compressor(container, compressed.writer());
                    try cmp.compress(original.reader());
                    try cmp.finish();
                    if (compressed_size == 0) {
                        if (container == .gzip)
                            print("case {d} huffman only compressed size: {d}\n", .{ case_no, compressed.pos });
                        compressed_size = compressed.pos;
                    }
                    try testing.expectEqual(compressed_size, compressed.pos);
                }
                // decompress compressed stream to decompressed stream
                {
                    var compressed = fixedBufferStream(cmp_buf[0..compressed_size]);
                    var decompressed = fixedBufferStream(&dcm_buf);
                    try inflate.decompress(container, compressed.reader(), decompressed.writer());
                    try testing.expectEqualSlices(u8, data, decompressed.getWritten());
                }
            }
        }

        // store only
        {
            inline for (Container.list) |container| { // for each wrapping
                var compressed_size: usize = if (case.store_size > 0)
                    case.store_size - Container.gzip.size() + container.size()
                else
                    0;

                // compress original stream to compressed stream
                {
                    var original = fixedBufferStream(data);
                    var compressed = fixedBufferStream(&cmp_buf);
                    var cmp = try deflate.store.compressor(container, compressed.writer());
                    try cmp.compress(original.reader());
                    try cmp.finish();
                    if (compressed_size == 0) {
                        if (container == .gzip)
                            print("case {d} store only compressed size: {d}\n", .{ case_no, compressed.pos });
                        compressed_size = compressed.pos;
                    }

                    try testing.expectEqual(compressed_size, compressed.pos);
                }
                // decompress compressed stream to decompressed stream
                {
                    var compressed = fixedBufferStream(cmp_buf[0..compressed_size]);
                    var decompressed = fixedBufferStream(&dcm_buf);
                    try inflate.decompress(container, compressed.reader(), decompressed.writer());
                    try testing.expectEqualSlices(u8, data, decompressed.getWritten());
                }
            }
        }
    }
}

fn testDecompress(comptime container: Container, compressed: []const u8, expected_plain: []const u8) !void {
    var in = fixedBufferStream(compressed);
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();

    try inflate.decompress(container, in.reader(), out.writer());
    try testing.expectEqualSlices(u8, expected_plain, out.items);
}

test "don't read past deflate stream's end" {
    try testDecompress(.zlib, &[_]u8{
        0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0xc0, 0x00, 0xc1, 0xff,
        0xff, 0x43, 0x30, 0x03, 0x03, 0xc3, 0xff, 0xff, 0xff, 0x01,
        0x83, 0x95, 0x0b, 0xf5,
    }, &[_]u8{
        0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff,
        0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff,
    });
}

test "zlib header" {
    // Truncated header
    try testing.expectError(
        error.EndOfStream,
        testDecompress(.zlib, &[_]u8{0x78}, ""),
    );
    // Wrong CM
    try testing.expectError(
        error.BadZlibHeader,
        testDecompress(.zlib, &[_]u8{ 0x79, 0x94 }, ""),
    );
    // Wrong CINFO
    try testing.expectError(
        error.BadZlibHeader,
        testDecompress(.zlib, &[_]u8{ 0x88, 0x98 }, ""),
    );
    // Wrong checksum
    try testing.expectError(
        error.WrongZlibChecksum,
        testDecompress(.zlib, &[_]u8{ 0x78, 0xda, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 }, ""),
    );
    // Truncated checksum
    try testing.expectError(
        error.EndOfStream,
        testDecompress(.zlib, &[_]u8{ 0x78, 0xda, 0x03, 0x00, 0x00 }, ""),
    );
}

test "gzip header" {
    // Truncated header
    try testing.expectError(
        error.EndOfStream,
        testDecompress(.gzip, &[_]u8{ 0x1f, 0x8B }, undefined),
    );
    // Wrong CM
    try testing.expectError(
        error.BadGzipHeader,
        testDecompress(.gzip, &[_]u8{
            0x1f, 0x8b, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        }, undefined),
    );

    // Wrong checksum
    try testing.expectError(
        error.WrongGzipChecksum,
        testDecompress(.gzip, &[_]u8{
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        }, undefined),
    );
    // Truncated checksum
    try testing.expectError(
        error.EndOfStream,
        testDecompress(.gzip, &[_]u8{
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00,
        }, undefined),
    );
    // Wrong initial size
    try testing.expectError(
        error.WrongGzipSize,
        testDecompress(.gzip, &[_]u8{
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        }, undefined),
    );
    // Truncated initial size field
    try testing.expectError(
        error.EndOfStream,
        testDecompress(.gzip, &[_]u8{
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        }, undefined),
    );

    try testDecompress(.gzip, &[_]u8{
        // GZIP header
        0x1f, 0x8b, 0x08, 0x12, 0x00, 0x09, 0x6e, 0x88, 0x00, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00,
        // header.FHCRC (should cover entire header)
        0x99, 0xd6,
        // GZIP data
        0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, "");
}

test "public interface" {
    const plain_data = [_]u8{ 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0x0a };

    // deflate final stored block, header + plain (stored) data
    const deflate_block = [_]u8{
        0b0000_0001, 0b0000_1100, 0x00, 0b1111_0011, 0xff, // deflate fixed buffer header len, nlen
    } ++ plain_data;

    // gzip header/footer + deflate block
    const gzip_data =
        [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 } ++ // gzip header (10 bytes)
        deflate_block ++
        [_]u8{ 0xd5, 0xe0, 0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00 }; // gzip footer checksum (4 byte), size (4 bytes)

    // zlib header/footer + deflate block
    const zlib_data = [_]u8{ 0x78, 0b10_0_11100 } ++ // zlib header (2 bytes)}
        deflate_block ++
        [_]u8{ 0x1c, 0xf2, 0x04, 0x47 }; // zlib footer: checksum

    const gzip = @import("gzip.zig");
    const zlib = @import("zlib.zig");
    const flate = @This();

    try testInterface(gzip, &gzip_data, &plain_data);
    try testInterface(zlib, &zlib_data, &plain_data);
    try testInterface(flate, &deflate_block, &plain_data);
}

fn testInterface(comptime pkg: type, gzip_data: []const u8, plain_data: []const u8) !void {
    var buffer1: [64]u8 = undefined;
    var buffer2: [64]u8 = undefined;

    var compressed = fixedBufferStream(&buffer1);
    var plain = fixedBufferStream(&buffer2);

    // decompress
    {
        var in = fixedBufferStream(gzip_data);
        try pkg.decompress(in.reader(), plain.writer());
        try testing.expectEqualSlices(u8, plain_data, plain.getWritten());
    }
    plain.reset();
    compressed.reset();

    // compress/decompress
    {
        var in = fixedBufferStream(plain_data);
        try pkg.compress(in.reader(), compressed.writer(), .{});
        compressed.reset();
        try pkg.decompress(compressed.reader(), plain.writer());
        try testing.expectEqualSlices(u8, plain_data, plain.getWritten());
    }
    plain.reset();
    compressed.reset();

    // compressor/decompressor
    {
        var in = fixedBufferStream(plain_data);
        var cmp = try pkg.compressor(compressed.writer(), .{});
        try cmp.compress(in.reader());
        try cmp.finish();

        compressed.reset();
        var dcp = pkg.decompressor(compressed.reader());
        try dcp.decompress(plain.writer());
        try testing.expectEqualSlices(u8, plain_data, plain.getWritten());
    }
    plain.reset();
    compressed.reset();

    // huffman
    {
        // huffman compress/decompress
        {
            var in = fixedBufferStream(plain_data);
            try pkg.huffman.compress(in.reader(), compressed.writer());
            compressed.reset();
            try pkg.decompress(compressed.reader(), plain.writer());
            try testing.expectEqualSlices(u8, plain_data, plain.getWritten());
        }
        plain.reset();
        compressed.reset();

        // huffman compressor/decompressor
        {
            var in = fixedBufferStream(plain_data);
            var cmp = try pkg.huffman.compressor(compressed.writer());
            try cmp.compress(in.reader());
            try cmp.finish();

            compressed.reset();
            try pkg.decompress(compressed.reader(), plain.writer());
            try testing.expectEqualSlices(u8, plain_data, plain.getWritten());
        }
    }
    plain.reset();
    compressed.reset();

    // store
    {
        // store compress/decompress
        {
            var in = fixedBufferStream(plain_data);
            try pkg.store.compress(in.reader(), compressed.writer());
            compressed.reset();
            try pkg.decompress(compressed.reader(), plain.writer());
            try testing.expectEqualSlices(u8, plain_data, plain.getWritten());
        }
        plain.reset();
        compressed.reset();

        // store compressor/decompressor
        {
            var in = fixedBufferStream(plain_data);
            var cmp = try pkg.store.compressor(compressed.writer());
            try cmp.compress(in.reader());
            try cmp.finish();

            compressed.reset();
            try pkg.decompress(compressed.reader(), plain.writer());
            try testing.expectEqualSlices(u8, plain_data, plain.getWritten());
        }
    }
}
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub fn bitReader(comptime T: type, reader: anytype) BitReader(T, @TypeOf(reader)) {
    return BitReader(T, @TypeOf(reader)).init(reader);
}

pub fn BitReader64(comptime ReaderType: type) type {
    return BitReader(u64, ReaderType);
}

pub fn BitReader32(comptime ReaderType: type) type {
    return BitReader(u32, ReaderType);
}

/// Bit reader used during inflate (decompression). Has internal buffer of 64
/// bits which shifts right after bits are consumed. Uses forward_reader to fill
/// that internal buffer when needed.
///
/// readF is the core function. Supports few different ways of getting bits
/// controlled by flags. In hot path we try to avoid checking whether we need to
/// fill buffer from forward_reader by calling fill in advance and readF with
/// buffered flag set.
///
pub fn BitReader(comptime T: type, comptime ReaderType: type) type {
    assert(T == u32 or T == u64);
    const t_bytes: usize = @sizeOf(T);
    const Tshift = if (T == u64) u6 else u5;

    return struct {
        // Underlying reader used for filling internal bits buffer
        forward_reader: ReaderType = undefined,
        // Internal buffer of 64 bits
        bits: T = 0,
        // Number of bits in the buffer
        nbits: u32 = 0,

        const Self = @This();

        pub const Error = ReaderType.Error || error{EndOfStream};

        pub fn init(rdr: ReaderType) Self {
            var self = Self{ .forward_reader = rdr };
            self.fill(1) catch {};
            return self;
        }

        /// Try to have `nice` bits are available in buffer. Reads from
        /// forward reader if there is no `nice` bits in buffer. Returns error
        /// if end of forward stream is reached and internal buffer is empty.
        /// It will not error if less than `nice` bits are in buffer, only when
        /// all bits are exhausted. During inflate we usually know what is the
        /// maximum bits for the next step but usually that step will need less
        /// bits to decode. So `nice` is not hard limit, it will just try to have
        /// that number of bits available. If end of forward stream is reached
        /// it may be some extra zero bits in buffer.
        pub inline fn fill(self: *Self, nice: u6) !void {
            if (self.nbits >= nice and nice != 0) {
                return; // We have enough bits
            }
            // Read more bits from forward reader

            // Number of empty bytes in bits, round nbits to whole bytes.
            const empty_bytes =
                @as(u8, if (self.nbits & 0x7 == 0) t_bytes else t_bytes - 1) - // 8 for 8, 16, 24..., 7 otherwise
                (self.nbits >> 3); // 0 for 0-7, 1 for 8-16, ... same as / 8

            var buf: [t_bytes]u8 = [_]u8{0} ** t_bytes;
            const bytes_read = self.forward_reader.readAll(buf[0..empty_bytes]) catch 0;
            if (bytes_read > 0) {
                const u: T = std.mem.readInt(T, buf[0..t_bytes], .little);
                self.bits |= u << @as(Tshift, @intCast(self.nbits));
                self.nbits += 8 * @as(u8, @intCast(bytes_read));
                return;
            }

            if (self.nbits == 0)
                return error.EndOfStream;
        }

        /// Read exactly buf.len bytes into buf.
        pub fn readAll(self: *Self, buf: []u8) !void {
            assert(self.alignBits() == 0); // internal bits must be at byte boundary

            // First read from internal bits buffer.
            var n: usize = 0;
            while (self.nbits > 0 and n < buf.len) {
                buf[n] = try self.readF(u8, flag.buffered);
                n += 1;
            }
            // Then use forward reader for all other bytes.
            try self.forward_reader.readNoEof(buf[n..]);
        }

        pub const flag = struct {
            pub const peek: u3 = 0b001; // dont advance internal buffer, just get bits, leave them in buffer
            pub const buffered: u3 = 0b010; // assume that there is no need to fill, fill should be called before
            pub const reverse: u3 = 0b100; // bit reverse read bits
        };

        /// Alias for readF(U, 0).
        pub fn read(self: *Self, comptime U: type) !U {
            return self.readF(U, 0);
        }

        /// Alias for readF with flag.peak set.
        pub inline fn peekF(self: *Self, comptime U: type, comptime how: u3) !U {
            return self.readF(U, how | flag.peek);
        }

        /// Read with flags provided.
        pub fn readF(self: *Self, comptime U: type, comptime how: u3) !U {
            if (U == T) {
                assert(how == 0);
                assert(self.alignBits() == 0);
                try self.fill(@bitSizeOf(T));
                if (self.nbits != @bitSizeOf(T)) return error.EndOfStream;
                const v = self.bits;
                self.nbits = 0;
                self.bits = 0;
                return v;
            }
            const n: Tshift = @bitSizeOf(U);
            switch (how) {
                0 => { // `normal` read
                    try self.fill(n); // ensure that there are n bits in the buffer
                    const u: U = @truncate(self.bits); // get n bits
                    try self.shift(n); // advance buffer for n
                    return u;
                },
                (flag.peek) => { // no shift, leave bits in the buffer
                    try self.fill(n);
                    return @truncate(self.bits);
                },
                flag.buffered => { // no fill, assume that buffer has enough bits
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return u;
                },
                (flag.reverse) => { // same as 0 with bit reverse
                    try self.fill(n);
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return @bitReverse(u);
                },
                (flag.peek | flag.reverse) => {
                    try self.fill(n);
                    return @bitReverse(@as(U, @truncate(self.bits)));
                },
                (flag.buffered | flag.reverse) => {
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return @bitReverse(u);
                },
                (flag.peek | flag.buffered) => {
                    return @truncate(self.bits);
                },
                (flag.peek | flag.buffered | flag.reverse) => {
                    return @bitReverse(@as(U, @truncate(self.b```
