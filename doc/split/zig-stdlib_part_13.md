```
const PROC_UID = 5;
        pub const PROC_RUID = 6;
        pub const PROC_KTHREAD = 7;
        pub const PROC_SHOW_THREADS = 0x40000000;

        pub const PROC_ARGV = 1;
        pub const PROC_NARGV = 2;
        pub const PROC_ENV = 3;
        pub const PROC_NENV = 4;
    },
    else => void,
};
pub const MADV = switch (native_os) {
    .linux => linux.MADV,
    .emscripten => emscripten.MADV,
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        pub const NORMAL = 0;
        pub const RANDOM = 1;
        pub const SEQUENTIAL = 2;
        pub const WILLNEED = 3;
        pub const DONTNEED = 4;
        pub const FREE = 5;
        pub const ZERO_WIRED_PAGES = 6;
        pub const FREE_REUSABLE = 7;
        pub const FREE_REUSE = 8;
        pub const CAN_REUSE = 9;
        pub const PAGEOUT = 10;
        pub const ZERO = 11;
    },
    .freebsd => struct {
        pub const NORMAL = 0;
        pub const RANDOM = 1;
        pub const SEQUENTIAL = 2;
        pub const WILLNEED = 3;
        pub const DONTNEED = 4;
        pub const FREE = 5;
        pub const NOSYNC = 6;
        pub const AUTOSYNC = 7;
        pub const NOCORE = 8;
        pub const CORE = 9;
        pub const PROTECT = 10;
    },
    .solaris, .illumos => struct {
        /// no further special treatment
        pub const NORMAL = 0;
        /// expect random page references
        pub const RANDOM = 1;
        /// expect sequential page references
        pub const SEQUENTIAL = 2;
        /// will need these pages
        pub const WILLNEED = 3;
        /// don't need these pages
        pub const DONTNEED = 4;
        /// contents can be freed
        pub const FREE = 5;
        /// default access
        pub const ACCESS_DEFAULT = 6;
        /// next LWP to access heavily
        pub const ACCESS_LWP = 7;
        /// many processes to access heavily
        pub const ACCESS_MANY = 8;
        /// contents will be purged
        pub const PURGE = 9;
    },
    .dragonfly => struct {
        pub const SEQUENTIAL = 2;
        pub const CONTROL_END = SETMAP;
        pub const DONTNEED = 4;
        pub const RANDOM = 1;
        pub const WILLNEED = 3;
        pub const NORMAL = 0;
        pub const CONTROL_START = INVAL;
        pub const FREE = 5;
        pub const NOSYNC = 6;
        pub const AUTOSYNC = 7;
        pub const NOCORE = 8;
        pub const CORE = 9;
        pub const INVAL = 10;
        pub const SETMAP = 11;
    },
    // https://github.com/SerenityOS/serenity/blob/6d59d4d3d9e76e39112842ec487840828f1c9bfe/Kernel/API/POSIX/sys/mman.h#L35-L41
    .serenity => struct {
        pub const NORMAL = 0x0;
        pub const SET_VOLATILE = 0x1;
        pub const SET_NONVOLATILE = 0x2;
        pub const DONTNEED = 0x3;
        pub const WILLNEED = 0x4;
        pub const SEQUENTIAL = 0x5;
        pub const RANDOM = 0x6;
    },
    else => void,
};
pub const MSF = switch (native_os) {
    .linux => linux.MSF,
    .emscripten => emscripten.MSF,
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        pub const ASYNC = 0x1;
        pub const INVALIDATE = 0x2;
        /// invalidate, leave mapped
        pub const KILLPAGES = 0x4;
        /// deactivate, leave mapped
        pub const DEACTIVATE = 0x8;
        pub const SYNC = 0x10;
    },
    .openbsd, .haiku, .dragonfly, .netbsd, .solaris, .illumos, .freebsd => struct {
        pub const ASYNC = 1;
        pub const INVALIDATE = 2;
        pub const SYNC = 4;
    },
    // https://github.com/SerenityOS/serenity/blob/6d59d4d3d9e76e39112842ec487840828f1c9bfe/Kernel/API/POSIX/sys/mman.h#L50-L52
    .serenity => struct {
        pub const SYNC = 1;
        pub const ASYNC = 2;
        pub const INVALIDATE = 4;
    },
    else => void,
};
pub const NAME_MAX = switch (native_os) {
    .linux => linux.NAME_MAX,
    .emscripten => emscripten.NAME_MAX,
    // Haiku's headers make this 256, to contain room for the terminating null
    // character, but POSIX definition says that NAME_MAX does not include the
    // terminating null.
    // https://github.com/SerenityOS/serenity/blob/c87557e9c1865fa1a6440de34ff6ce6fc858a2b7/Kernel/API/POSIX/sys/limits.h#L20
    .haiku, .openbsd, .dragonfly, .netbsd, .solaris, .illumos, .freebsd, .macos, .ios, .tvos, .watchos, .visionos, .serenity => 255,
    else => {},
};
pub const PATH_MAX = switch (native_os) {
    .linux => linux.PATH_MAX,
    .emscripten => emscripten.PATH_MAX,
    .wasi => 4096,
    .windows => 260,
    .openbsd, .haiku, .dragonfly, .netbsd, .solaris, .illumos, .freebsd, .macos, .ios, .tvos, .watchos, .visionos, .serenity => 1024,
    else => {},
};

pub const POLL = switch (native_os) {
    .linux => linux.POLL,
    .emscripten => emscripten.POLL,
    .wasi => struct {
        pub const RDNORM = 0x1;
        pub const WRNORM = 0x2;
        pub const IN = RDNORM;
        pub const OUT = WRNORM;
        pub const ERR = 0x1000;
        pub const HUP = 0x2000;
        pub const NVAL = 0x4000;
    },
    .windows => ws2_32.POLL,
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        pub const IN = 0x001;
        pub const PRI = 0x002;
        pub const OUT = 0x004;
        pub const RDNORM = 0x040;
        pub const WRNORM = OUT;
        pub const RDBAND = 0x080;
        pub const WRBAND = 0x100;

        pub const EXTEND = 0x0200;
        pub const ATTRIB = 0x0400;
        pub const NLINK = 0x0800;
        pub const WRITE = 0x1000;

        pub const ERR = 0x008;
        pub const HUP = 0x010;
        pub const NVAL = 0x020;

        pub const STANDARD = IN | PRI | OUT | RDNORM | RDBAND | WRBAND | ERR | HUP | NVAL;
    },
    .freebsd => struct {
        /// any readable data available.
        pub const IN = 0x0001;
        /// OOB/Urgent readable data.
        pub const PRI = 0x0002;
        /// file descriptor is writeable.
        pub const OUT = 0x0004;
        /// non-OOB/URG data available.
        pub const RDNORM = 0x0040;
        /// no write type differentiation.
        pub const WRNORM = OUT;
        /// OOB/Urgent readable data.
        pub const RDBAND = 0x0080;
        /// OOB/Urgent data can be written.
        pub const WRBAND = 0x0100;
        /// like IN, except ignore EOF.
        pub const INIGNEOF = 0x2000;
        /// some poll error occurred.
        pub const ERR = 0x0008;
        /// file descriptor was "hung up".
        pub const HUP = 0x0010;
        /// requested events "invalid".
        pub const NVAL = 0x0020;

        pub const STANDARD = IN | PRI | OUT | RDNORM | RDBAND | WRBAND | ERR | HUP | NVAL;
    },
    .solaris, .illumos => struct {
        pub const IN = 0x0001;
        pub const PRI = 0x0002;
        pub const OUT = 0x0004;
        pub const RDNORM = 0x0040;
        pub const WRNORM = .OUT;
        pub const RDBAND = 0x0080;
        pub const WRBAND = 0x0100;
        /// Read-side hangup.
        pub const RDHUP = 0x4000;

        /// Non-testable events (may not be specified in events).
        pub const ERR = 0x0008;
        pub const HUP = 0x0010;
        pub const NVAL = 0x0020;

        /// Events to control `/dev/poll` (not specified in revents)
        pub const REMOVE = 0x0800;
        pub const ONESHOT = 0x1000;
        pub const ET = 0x2000;
    },
    .dragonfly, .netbsd => struct {
        /// Testable events (may be specified in events field).
        pub const IN = 0x0001;
        pub const PRI = 0x0002;
        pub const OUT = 0x0004;
        pub const RDNORM = 0x0040;
        pub const WRNORM = OUT;
        pub const RDBAND = 0x0080;
        pub const WRBAND = 0x0100;

        /// Non-testable events (may not be specified in events field).
        pub const ERR = 0x0008;
        pub const HUP = 0x0010;
        pub const NVAL = 0x0020;
    },
    .haiku => struct {
        /// any readable data available
        pub const IN = 0x0001;
        /// file descriptor is writeable
        pub const OUT = 0x0002;
        pub const RDNORM = IN;
        pub const WRNORM = OUT;
        /// priority readable data
        pub const RDBAND = 0x0008;
        /// priority data can be written
        pub const WRBAND = 0x0010;
        /// high priority readable data
        pub const PRI = 0x0020;

        /// errors pending
        pub const ERR = 0x0004;
        /// disconnected
        pub const HUP = 0x0080;
        /// invalid file descriptor
        pub const NVAL = 0x1000;
    },
    .openbsd => struct {
        pub const IN = 0x0001;
        pub const PRI = 0x0002;
        pub const OUT = 0x0004;
        pub const ERR = 0x0008;
        pub const HUP = 0x0010;
        pub const NVAL = 0x0020;
        pub const RDNORM = 0x0040;
        pub const NORM = RDNORM;
        pub const WRNORM = OUT;
        pub const RDBAND = 0x0080;
        pub const WRBAND = 0x0100;
    },
    // https://github.com/SerenityOS/serenity/blob/265764ff2fec038855193296588a887fc322d76a/Kernel/API/POSIX/poll.h#L15-L24
    .serenity => struct {
        pub const IN = 0x0001;
        pub const PRI = 0x0002;
        pub const OUT = 0x0004;
        pub const ERR = 0x0008;
        pub const HUP = 0x0010;
        pub const NVAL = 0x0020;
        pub const RDNORM = IN;
        pub const WRNORM = OUT;
        pub const WRBAND = 0x1000;
        pub const RDHUP = 0x2000;
    },
    else => void,
};

/// Basic memory protection flags
pub const PROT = switch (native_os) {
    .linux => linux.PROT,
    .emscripten => emscripten.PROT,
    // https://github.com/SerenityOS/serenity/blob/6d59d4d3d9e76e39112842ec487840828f1c9bfe/Kernel/API/POSIX/sys/mman.h#L28-L31
    .openbsd, .haiku, .dragonfly, .netbsd, .solaris, .illumos, .freebsd, .windows, .serenity => struct {
        /// page can not be accessed
        pub const NONE = 0x0;
        /// page can be read
        pub const READ = 0x1;
        /// page can be written
        pub const WRITE = 0x2;
        /// page can be executed
        pub const EXEC = 0x4;
    },
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        /// [MC2] no permissions
        pub const NONE: vm_prot_t = 0x00;
        /// [MC2] pages can be read
        pub const READ: vm_prot_t = 0x01;
        /// [MC2] pages can be written
        pub const WRITE: vm_prot_t = 0x02;
        /// [MC2] pages can be executed
        pub const EXEC: vm_prot_t = 0x04;
        /// When a caller finds that they cannot obtain write permission on a
        /// mapped entry, the following flag can be used. The entry will be
        /// made "needs copy" effectively copying the object (using COW),
        /// and write permission will be added to the maximum protections for
        /// the associated entry.
        pub const COPY: vm_prot_t = 0x10;
    },
    else => void,
};

pub const REG = switch (native_os) {
    .linux => linux.REG,
    .emscripten => emscripten.REG,
    .freebsd => switch (builtin.cpu.arch) {
        .aarch64 => struct {
            pub const FP = 29;
            pub const SP = 31;
            pub const PC = 32;
        },
        .arm => struct {
            pub const FP = 11;
            pub const SP = 13;
            pub const PC = 15;
        },
        .x86_64 => struct {
            pub const RBP = 12;
            pub const RIP = 21;
            pub const RSP = 24;
        },
        else => struct {},
    },
    .solaris, .illumos => struct {
        pub const R15 = 0;
        pub const R14 = 1;
        pub const R13 = 2;
        pub const R12 = 3;
        pub const R11 = 4;
        pub const R10 = 5;
        pub const R9 = 6;
        pub const R8 = 7;
        pub const RDI = 8;
        pub const RSI = 9;
        pub const RBP = 10;
        pub const RBX = 11;
        pub const RDX = 12;
        pub const RCX = 13;
        pub const RAX = 14;
        pub const RIP = 17;
        pub const RSP = 20;
    },
    .netbsd => switch (builtin.cpu.arch) {
        .aarch64 => struct {
            pub const FP = 29;
            pub const SP = 31;
            pub const PC = 32;
        },
        .arm => struct {
            pub const FP = 11;
            pub const SP = 13;
            pub const PC = 15;
        },
        .x86_64 => struct {
            pub const RDI = 0;
            pub const RSI = 1;
            pub const RDX = 2;
            pub const RCX = 3;
            pub const R8 = 4;
            pub const R9 = 5;
            pub const R10 = 6;
            pub const R11 = 7;
            pub const R12 = 8;
            pub const R13 = 9;
            pub const R14 = 10;
            pub const R15 = 11;
            pub const RBP = 12;
            pub const RBX = 13;
            pub const RAX = 14;
            pub const GS = 15;
            pub const FS = 16;
            pub const ES = 17;
            pub const DS = 18;
            pub const TRAPNO = 19;
            pub const ERR = 20;
            pub const RIP = 21;
            pub const CS = 22;
            pub const RFLAGS = 23;
            pub const RSP = 24;
            pub const SS = 25;
        },
        else => struct {},
    },
    else => struct {},
};
pub const RLIM = switch (native_os) {
    .linux => linux.RLIM,
    .emscripten => emscripten.RLIM,
    // https://github.com/SerenityOS/serenity/blob/aae106e37b48f2158e68902293df1e4bf7b80c0f/Userland/Libraries/LibC/sys/resource.h#L52
    .openbsd, .haiku, .dragonfly, .netbsd, .freebsd, .macos, .ios, .tvos, .watchos, .visionos, .serenity => struct {
        /// No limit
        pub const INFINITY: rlim_t = (1 << 63) - 1;

        pub const SAVED_MAX = INFINITY;
        pub const SAVED_CUR = INFINITY;
    },
    .solaris, .illumos => struct {
        /// No limit
        pub const INFINITY: rlim_t = (1 << 63) - 3;
        pub const SAVED_MAX: rlim_t = (1 << 63) - 2;
        pub const SAVED_CUR: rlim_t = (1 << 63) - 1;
    },
    else => void,
};
pub const S = switch (native_os) {
    .linux => linux.S,
    .emscripten => emscripten.S,
    .wasi => struct {
        // Match `S_*` constants from lib/libc/include/wasm-wasi-musl/__mode_t.h
        pub const IFBLK = 0x6000;
        pub const IFCHR = 0x2000;
        pub const IFDIR = 0x4000;
        pub const IFIFO = 0x1000;
        pub const IFLNK = 0xa000;
        pub const IFMT = IFBLK | IFCHR | IFDIR | IFIFO | IFLNK | IFREG | IFSOCK;
        pub const IFREG = 0x8000;
        pub const IFSOCK = 0xc000;

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }
    },
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        pub const IFMT = 0o170000;

        pub const IFIFO = 0o010000;
        pub const IFCHR = 0o020000;
        pub const IFDIR = 0o040000;
        pub const IFBLK = 0o060000;
        pub const IFREG = 0o100000;
        pub const IFLNK = 0o120000;
        pub const IFSOCK = 0o140000;
        pub const IFWHT = 0o160000;

        pub const ISUID = 0o4000;
        pub const ISGID = 0o2000;
        pub const ISVTX = 0o1000;
        pub const IRWXU = 0o700;
        pub const IRUSR = 0o400;
        pub const IWUSR = 0o200;
        pub const IXUSR = 0o100;
        pub const IRWXG = 0o070;
        pub const IRGRP = 0o040;
        pub const IWGRP = 0o020;
        pub const IXGRP = 0o010;
        pub const IRWXO = 0o007;
        pub const IROTH = 0o004;
        pub const IWOTH = 0o002;
        pub const IXOTH = 0o001;

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }

        pub fn IWHT(m: u32) bool {
            return m & IFMT == IFWHT;
        }
    },
    .freebsd => struct {
        pub const IFMT = 0o170000;

        pub const IFIFO = 0o010000;
        pub const IFCHR = 0o020000;
        pub const IFDIR = 0o040000;
        pub const IFBLK = 0o060000;
        pub const IFREG = 0o100000;
        pub const IFLNK = 0o120000;
        pub const IFSOCK = 0o140000;
        pub const IFWHT = 0o160000;

        pub const ISUID = 0o4000;
        pub const ISGID = 0o2000;
        pub const ISVTX = 0o1000;
        pub const IRWXU = 0o700;
        pub const IRUSR = 0o400;
        pub const IWUSR = 0o200;
        pub const IXUSR = 0o100;
        pub const IRWXG = 0o070;
        pub const IRGRP = 0o040;
        pub const IWGRP = 0o020;
        pub const IXGRP = 0o010;
        pub const IRWXO = 0o007;
        pub const IROTH = 0o004;
        pub const IWOTH = 0o002;
        pub const IXOTH = 0o001;

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }

        pub fn IWHT(m: u32) bool {
            return m & IFMT == IFWHT;
        }
    },
    .solaris, .illumos => struct {
        pub const IFMT = 0o170000;

        pub const IFIFO = 0o010000;
        pub const IFCHR = 0o020000;
        pub const IFDIR = 0o040000;
        pub const IFBLK = 0o060000;
        pub const IFREG = 0o100000;
        pub const IFLNK = 0o120000;
        pub const IFSOCK = 0o140000;
        /// SunOS 2.6 Door
        pub const IFDOOR = 0o150000;
        /// Solaris 10 Event Port
        pub const IFPORT = 0o160000;

        pub const ISUID = 0o4000;
        pub const ISGID = 0o2000;
        pub const ISVTX = 0o1000;
        pub const IRWXU = 0o700;
        pub const IRUSR = 0o400;
        pub const IWUSR = 0o200;
        pub const IXUSR = 0o100;
        pub const IRWXG = 0o070;
        pub const IRGRP = 0o040;
        pub const IWGRP = 0o020;
        pub const IXGRP = 0o010;
        pub const IRWXO = 0o007;
        pub const IROTH = 0o004;
        pub const IWOTH = 0o002;
        pub const IXOTH = 0o001;

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }

        pub fn ISDOOR(m: u32) bool {
            return m & IFMT == IFDOOR;
        }

        pub fn ISPORT(m: u32) bool {
            return m & IFMT == IFPORT;
        }
    },
    .netbsd => struct {
        pub const IFMT = 0o170000;

        pub const IFIFO = 0o010000;
        pub const IFCHR = 0o020000;
        pub const IFDIR = 0o040000;
        pub const IFBLK = 0o060000;
        pub const IFREG = 0o100000;
        pub const IFLNK = 0o120000;
        pub const IFSOCK = 0o140000;
        pub const IFWHT = 0o160000;

        pub const ISUID = 0o4000;
        pub const ISGID = 0o2000;
        pub const ISVTX = 0o1000;
        pub const IRWXU = 0o700;
        pub const IRUSR = 0o400;
        pub const IWUSR = 0o200;
        pub const IXUSR = 0o100;
        pub const IRWXG = 0o070;
        pub const IRGRP = 0o040;
        pub const IWGRP = 0o020;
        pub const IXGRP = 0o010;
        pub const IRWXO = 0o007;
        pub const IROTH = 0o004;
        pub const IWOTH = 0o002;
        pub const IXOTH = 0o001;

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }

        pub fn IWHT(m: u32) bool {
            return m & IFMT == IFWHT;
        }
    },
    .dragonfly => struct {
        pub const IREAD = IRUSR;
        pub const IEXEC = IXUSR;
        pub const IWRITE = IWUSR;
        pub const IXOTH = 1;
        pub const IWOTH = 2;
        pub const IROTH = 4;
        pub const IRWXO = 7;
        pub const IXGRP = 8;
        pub const IWGRP = 16;
        pub const IRGRP = 32;
        pub const IRWXG = 56;
        pub const IXUSR = 64;
        pub const IWUSR = 128;
        pub const IRUSR = 256;
        pub const IRWXU = 448;
        pub const ISTXT = 512;
        pub const BLKSIZE = 512;
        pub const ISVTX = 512;
        pub const ISGID = 1024;
        pub const ISUID = 2048;
        pub const IFIFO = 4096;
        pub const IFCHR = 8192;
        pub const IFDIR = 16384;
        pub const IFBLK = 24576;
        pub const IFREG = 32768;
        pub const IFDB = 36864;
        pub const IFLNK = 40960;
        pub const IFSOCK = 49152;
        pub const IFWHT = 57344;
        pub const IFMT = 61440;

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }
    },
    .haiku => struct {
        pub const IFMT = 0o170000;
        pub const IFSOCK = 0o140000;
        pub const IFLNK = 0o120000;
        pub const IFREG = 0o100000;
        pub const IFBLK = 0o060000;
        pub const IFDIR = 0o040000;
        pub const IFCHR = 0o020000;
        pub const IFIFO = 0o010000;
        pub const INDEX_DIR = 0o4000000000;

        pub const IUMSK = 0o7777;
        pub const ISUID = 0o4000;
        pub const ISGID = 0o2000;
        pub const ISVTX = 0o1000;
        pub const IRWXU = 0o700;
        pub const IRUSR = 0o400;
        pub const IWUSR = 0o200;
        pub const IXUSR = 0o100;
        pub const IRWXG = 0o070;
        pub const IRGRP = 0o040;
        pub const IWGRP = 0o020;
        pub const IXGRP = 0o010;
        pub const IRWXO = 0o007;
        pub const IROTH = 0o004;
        pub const IWOTH = 0o002;
        pub const IXOTH = 0o001;

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }

        pub fn ISINDEX(m: u32) bool {
            return m & INDEX_DIR == INDEX_DIR;
        }
    },
    .openbsd => struct {
        pub const IFMT = 0o170000;

        pub const IFIFO = 0o010000;
        pub const IFCHR = 0o020000;
        pub const IFDIR = 0o040000;
        pub const IFBLK = 0o060000;
        pub const IFREG = 0o100000;
        pub const IFLNK = 0o120000;
        pub const IFSOCK = 0o140000;

        pub const ISUID = 0o4000;
        pub const ISGID = 0o2000;
        pub const ISVTX = 0o1000;
        pub const IRWXU = 0o700;
        pub const IRUSR = 0o400;
        pub const IWUSR = 0o200;
        pub const IXUSR = 0o100;
        pub const IRWXG = 0o070;
        pub const IRGRP = 0o040;
        pub const IWGRP = 0o020;
        pub const IXGRP = 0o010;
        pub const IRWXO = 0o007;
        pub const IROTH = 0o004;
        pub const IWOTH = 0o002;
        pub const IXOTH = 0o001;

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }
    },
    // https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/sys/stat.h#L16-L51
    .serenity => struct {
        pub const IFMT = 0o170000;
        pub const IFDIR = 0o040000;
        pub const IFCHR = 0o020000;
        pub const IFBLK = 0o060000;
        pub const IFREG = 0o100000;
        pub const IFIFO = 0o010000;
        pub const IFLNK = 0o120000;
        pub const IFSOCK = 0o140000;

        pub const ISUID = 0o4000;
        pub const ISGID = 0o2000;
        pub const ISVTX = 0o1000;
        pub const IRUSR = 0o400;
        pub const IWUSR = 0o200;
        pub const IXUSR = 0o100;
        pub const IREAD = IRUSR;
        pub const IWRITE = IWUSR;
        pub const IEXEC = IXUSR;
        pub const IRGRP = 0o040;
        pub const IWGRP = 0o020;
        pub const IXGRP = 0o010;
        pub const IROTH = 0o004;
        pub const IWOTH = 0o002;
        pub const IXOTH = 0o001;

        pub const IRWXU = IRUSR | IWUSR | IXUSR;

        pub const IRWXG = IRWXU >> 3;
        pub const IRWXO = IRWXG >> 3;

        pub fn ISDIR(m: u32) bool {
            return m & IFMT == IFDIR;
        }

        pub fn ISCHR(m: u32) bool {
            return m & IFMT == IFCHR;
        }

        pub fn ISBLK(m: u32) bool {
            return m & IFMT == IFBLK;
        }

        pub fn ISREG(m: u32) bool {
            return m & IFMT == IFREG;
        }

        pub fn ISFIFO(m: u32) bool {
            return m & IFMT == IFIFO;
        }

        pub fn ISLNK(m: u32) bool {
            return m & IFMT == IFLNK;
        }

        pub fn ISSOCK(m: u32) bool {
            return m & IFMT == IFSOCK;
        }
    },
    else => void,
};
pub const SA = switch (native_os) {
    .linux => linux.SA,
    .emscripten => emscripten.SA,
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        /// take signal on signal stack
        pub const ONSTACK = 0x0001;
        /// restart system on signal return
        pub const RESTART = 0x0002;
        /// reset to SIG.DFL when taking signal
        pub const RESETHAND = 0x0004;
        /// do not generate SIG.CHLD on child stop
        pub const NOCLDSTOP = 0x0008;
        /// don't mask the signal we're delivering
        pub const NODEFER = 0x0010;
        /// don't keep zombies around
        pub const NOCLDWAIT = 0x0020;
        /// signal handler with SIGINFO args
        pub const SIGINFO = 0x0040;
        /// do not bounce off kernel's sigtramp
        pub const USERTRAMP = 0x0100;
        /// signal handler with SIGINFO args with 64bit regs information
        pub const @"64REGSET" = 0x0200;
    },
    .freebsd => struct {
        pub const ONSTACK = 0x0001;
        pub const RESTART = 0x0002;
        pub const RESETHAND = 0x0004;
        pub const NOCLDSTOP = 0x0008;
        pub const NODEFER = 0x0010;
        pub const NOCLDWAIT = 0x0020;
        pub const SIGINFO = 0x0040;
    },
    .solaris, .illumos => struct {
        pub const ONSTACK = 0x00000001;
        pub const RESETHAND = 0x00000002;
        pub const RESTART = 0x00000004;
        pub const SIGINFO = 0x00000008;
        pub const NODEFER = 0x00000010;
        pub const NOCLDWAIT = 0x00010000;
    },
    .netbsd => struct {
        pub const ONSTACK = 0x0001;
        pub const RESTART = 0x0002;
        pub const RESETHAND = 0x0004;
        pub const NOCLDSTOP = 0x0008;
        pub const NODEFER = 0x0010;
        pub const NOCLDWAIT = 0x0020;
        pub const SIGINFO = 0x0040;
    },
    .dragonfly => struct {
        pub const ONSTACK = 0x0001;
        pub const RESTART = 0x0002;
        pub const RESETHAND = 0x0004;
        pub const NODEFER = 0x0010;
        pub const NOCLDWAIT = 0x0020;
        pub const SIGINFO = 0x0040;
    },
    .haiku => struct {
        pub const NOCLDSTOP = 0x01;
        pub const NOCLDWAIT = 0x02;
        pub const RESETHAND = 0x04;
        pub const NODEFER = 0x08;
        pub const RESTART = 0x10;
        pub const ONSTACK = 0x20;
        pub const SIGINFO = 0x40;
        pub const NOMASK = NODEFER;
        pub const STACK = ONSTACK;
        pub const ONESHOT = RESETHAND;
    },
    .openbsd => struct {
        pub const ONSTACK = 0x0001;
        pub const RESTART = 0x0002;
        pub const RESETHAND = 0x0004;
        pub const NOCLDSTOP = 0x0008;
        pub const NODEFER = 0x0010;
        pub const NOCLDWAIT = 0x0020;
        pub const SIGINFO = 0x0040;
    },
    // https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/signal.h#L65-L71
    .serenity => struct {
        pub const NOCLDSTOP = 1;
        pub const NOCLDWAIT = 2;
        pub const SIGINFO = 4;
        pub const ONSTACK = 0x08000000;
        pub const RESTART = 0x10000000;
        pub const NODEFER = 0x40000000;
        pub const RESETHAND = 0x80000000;
        pub const NOMASK = NODEFER;
        pub const ONESHOT = RESETHAND;
    },
    else => void,
};
pub const sigval_t = switch (native_os) {
    .netbsd, .solaris, .illumos => extern union {
        int: i32,
        ptr: ?*anyopaque,
    },
    else => void,
};

pub const SC = switch (native_os) {
    .linux => linux.SC,
    else => void,
};

pub const _SC = if (builtin.abi.isAndroid()) enum(c_int) {
    PAGESIZE = 39,
    NPROCESSORS_ONLN = 97,
} else switch (native_os) {
    .driverkit, .ios, .macos, .tvos, .visionos, .watchos => enum(c_int) {
        PAGESIZE = 29,
    },
    .dragonfly => enum(c_int) {
        PAGESIZE = 47,
    },
    .freebsd => enum(c_int) {
        PAGESIZE = 47,
    },
    .fuchsia => enum(c_int) {
        PAGESIZE = 30,
    },
    .haiku => enum(c_int) {
        PAGESIZE = 27,
    },
    .linux => enum(c_int) {
        PAGESIZE = 30,
    },
    .netbsd => enum(c_int) {
        PAGESIZE = 28,
    },
    .openbsd => enum(c_int) {
        PAGESIZE = 28,
    },
    .solaris, .illumos => enum(c_int) {
        PAGESIZE = 11,
        NPROCESSORS_ONLN = 15,
    },
    // https://github.com/SerenityOS/serenity/blob/1dfc9e2df39dd23f1de92530677c845aae4345f2/Kernel/API/POSIX/unistd.h#L36-L52
    .serenity => enum(c_int) {
        MONOTONIC_CLOCK = 0,
        NPROCESSORS_CONF = 1,
        NPROCESSORS_ONLN = 2,
        OPEN_MAX = 3,
        HOST_NAME_MAX = 4,
        TTY_NAME_MAX = 5,
        PAGESIZE = 6,
        GETPW_R_SIZE_MAX = 7,
        GETGR_R_SIZE_MAX = 8,
        CLK_TCK = 9,
        SYMLOOP_MAX = 10,
        MAPPED_FILES = 11,
        ARG_MAX = 12,
        IOV_MAX = 13,
        PHYS_PAGES = 14,
    },
    else => void,
};

pub const SEEK = switch (native_os) {
    .linux => linux.SEEK,
    .emscripten => emscripten.SEEK,
    .wasi => struct {
        pub const SET: wasi.whence_t = .SET;
        pub const CUR: wasi.whence_t = .CUR;
        pub const END: wasi.whence_t = .END;
    },
    // https://github.com/SerenityOS/serenity/blob/808ce594db1f2190e5212a250e900bde2ffe710b/Kernel/API/POSIX/stdio.h#L15-L17
    .openbsd, .haiku, .netbsd, .freebsd, .macos, .ios, .tvos, .watchos, .visionos, .windows, .serenity => struct {
        pub const SET = 0;
        pub const CUR = 1;
        pub const END = 2;
    },
    .dragonfly, .solaris, .illumos => struct {
        pub const SET = 0;
        pub const CUR = 1;
        pub const END = 2;
        pub const DATA = 3;
        pub const HOLE = 4;
    },
    else => void,
};
pub const SHUT = switch (native_os) {
    .linux => linux.SHUT,
    .emscripten => emscripten.SHUT,
    // https://github.com/SerenityOS/serenity/blob/ac44ec5ebc707f9dd0c3d4759a1e17e91db5d74f/Kernel/API/POSIX/sys/socket.h#L40-L42
    else => struct {
        pub const RD = 0;
        pub const WR = 1;
        pub const RDWR = 2;
    },
};

/// Signal types
pub const SIG = switch (native_os) {
    .linux => linux.SIG,
    .emscripten => emscripten.SIG,
    .windows => struct {
        /// interrupt
        pub const INT = 2;
        /// illegal instruction - invalid function image
        pub const ILL = 4;
        /// floating point exception
        pub const FPE = 8;
        /// segment violation
        pub const SEGV = 11;
        /// Software termination signal from kill
        pub const TERM = 15;
        /// Ctrl-Break sequence
        pub const BREAK = 21;
        /// abnormal termination triggered by abort call
        pub const ABRT = 22;
        /// SIGABRT compatible with other platforms, same as SIGABRT
        pub const ABRT_COMPAT = 6;

        // Signal action codes
        /// default signal action
        pub const DFL = 0;
        /// ignore signal
        pub const IGN = 1;
        /// return current value
        pub const GET = 2;
        /// signal gets error
        pub const SGE = 3;
        /// acknowledge
        pub const ACK = 4;
        /// Signal error value (returned by signal call on error)
        pub const ERR = -1;
    },
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));
        pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
        pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
        pub const HOLD: ?Sigaction.handler_fn = @ptrFromInt(5);

        /// block specified signal set
        pub const BLOCK = 1;
        /// unblock specified signal set
        pub const UNBLOCK = 2;
        /// set specified signal set
        pub const SETMASK = 3;
        /// hangup
        pub const HUP = 1;
        /// interrupt
        pub const INT = 2;
        /// quit
        pub const QUIT = 3;
        /// illegal instruction (not reset when caught)
        pub const ILL = 4;
        /// trace trap (not reset when caught)
        pub const TRAP = 5;
        /// abort()
        pub const ABRT = 6;
        /// pollable event ([XSR] generated, not supported)
        pub const POLL = 7;
        /// compatibility
        pub const IOT = ABRT;
        /// EMT instruction
        pub const EMT = 7;
        /// floating point exception
        pub const FPE = 8;
        /// kill (cannot be caught or ignored)
        pub const KILL = 9;
        /// bus error
        pub const BUS = 10;
        /// segmentation violation
        pub const SEGV = 11;
        /// bad argument to system call
        pub const SYS = 12;
        /// write on a pipe with no one to read it
        pub const PIPE = 13;
        /// alarm clock
        pub const ALRM = 14;
        /// software termination signal from kill
        pub const TERM = 15;
        /// urgent condition on IO channel
        pub const URG = 16;
        /// sendable stop signal not from tty
        pub const STOP = 17;
        /// stop signal from tty
        pub const TSTP = 18;
        /// continue a stopped process
        pub const CONT = 19;
        /// to parent on child stop or exit
        pub const CHLD = 20;
        /// to readers pgrp upon background tty read
        pub const TTIN = 21;
        /// like TTIN for output if (tp->t_local&LTOSTOP)
        pub const TTOU = 22;
        /// input/output possible signal
        pub const IO = 23;
        /// exceeded CPU time limit
        pub const XCPU = 24;
        /// exceeded file size limit
        pub const XFSZ = 25;
        /// virtual time alarm
        pub const VTALRM = 26;
        /// profiling time alarm
        pub const PROF = 27;
        /// window size changes
        pub const WINCH = 28;
        /// information request
        pub const INFO = 29;
        /// user defined signal 1
        pub const USR1 = 30;
        /// user defined signal 2
        pub const USR2 = 31;
    },
    .freebsd => struct {
        pub const HUP = 1;
        pub const INT = 2;
        pub const QUIT = 3;
        pub const ILL = 4;
        pub const TRAP = 5;
        pub const ABRT = 6;
        pub const IOT = ABRT;
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
        pub const IO = 23;
        pub const XCPU = 24;
        pub const XFSZ = 25;
        pub const VTALRM = 26;
        pub const PROF = 27;
        pub const WINCH = 28;
        pub const INFO = 29;
        pub const USR1 = 30;
        pub const USR2 = 31;
        pub const THR = 32;
        pub const LWP = THR;
        pub const LIBRT = 33;

        pub const RTMIN = 65;
        pub const RTMAX = 126;

        pub const BLOCK = 1;
        pub const UNBLOCK = 2;
        pub const SETMASK = 3;

        pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
        pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
        pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));

        pub const WORDS = 4;
        pub const MAXSIG = 128;

        pub inline fn IDX(sig: usize) usize {
            return sig - 1;
        }
        pub inline fn WORD(sig: usize) usize {
            return IDX(sig) >> 5;
        }
        pub inline fn BIT(sig: usize) usize {
            return 1 << (IDX(sig) & 31);
        }
        pub inline fn VALID(sig: usize) usize {
            return sig <= MAXSIG and sig > 0;
        }
    },
    .solaris, .illumos => struct {
        pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
        pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));
        pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
        pub const HOLD: ?Sigaction.handler_fn = @ptrFromInt(2);

        pub const WORDS = 4;
        pub const MAXSIG = 75;

        pub const SIG_BLOCK = 1;
        pub const SIG_UNBLOCK = 2;
        pub const SIG_SETMASK = 3;

        pub const HUP = 1;
        pub const INT = 2;
        pub const QUIT = 3;
        pub const ILL = 4;
        pub const TRAP = 5;
        pub const IOT = 6;
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
        pub const USR1 = 16;
        pub const USR2 = 17;
        pub const CLD = 18;
        pub const CHLD = 18;
        pub const PWR = 19;
        pub const WINCH = 20;
        pub const URG = 21;
        pub const POLL = 22;
        pub const IO = .POLL;
        pub const STOP = 23;
        pub const TSTP = 24;
        pub const CONT = 25;
        pub const TTIN = 26;
        pub const TTOU = 27;
        pub const VTALRM = 28;
        pub const PROF = 29;
        pub const XCPU = 30;
        pub const XFSZ = 31;
        pub const WAITING = 32;
        pub const LWP = 33;
        pub const FREEZE = 34;
        pub const THAW = 35;
        pub const CANCEL = 36;
        pub const LOST = 37;
        pub const XRES = 38;
        pub const JVM1 = 39;
        pub const JVM2 = 40;
        pub const INFO = 41;

        pub const RTMIN = 42;
        pub const RTMAX = 74;

        pub inline fn IDX(sig: usize) usize {
            return sig - 1;
        }
        pub inline fn WORD(sig: usize) usize {
            return IDX(sig) >> 5;
        }
        pub inline fn BIT(sig: usize) usize {
            return 1 << (IDX(sig) & 31);
        }
        pub inline fn VALID(sig: usize) usize {
            return sig <= MAXSIG and sig > 0;
        }
    },
    .netbsd => struct {
        pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
        pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
        pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));

        pub const WORDS = 4;
        pub const MAXSIG = 128;

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
        pub const IO = 23;
        pub const XCPU = 24;
        pub const XFSZ = 25;
        pub const VTALRM = 26;
        pub const PROF = 27;
        pub const WINCH = 28;
        pub const INFO = 29;
        pub const USR1 = 30;
        pub const USR2 = 31;
        pub const PWR = 32;

        pub const RTMIN = 33;
        pub const RTMAX = 63;

        pub inline fn IDX(sig: usize) usize {
            return sig - 1;
        }
        pub inline fn WORD(sig: usize) usize {
            return IDX(sig) >> 5;
        }
        pub inline fn BIT(sig: usize) usize {
            return 1 << (IDX(sig) & 31);
        }
        pub inline fn VALID(sig: usize) usize {
            return sig <= MAXSIG and sig > 0;
        }
    },
    .dragonfly => struct {
        pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
        pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
        pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));

        pub const BLOCK = 1;
        pub const UNBLOCK = 2;
        pub const SETMASK = 3;

        pub const IOT = ABRT;
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
        pub const IO = 23;
        pub const XCPU = 24;
        pub const XFSZ = 25;
        pub const VTALRM = 26;
        pub const PROF = 27;
        pub const WINCH = 28;
        pub const INFO = 29;
        pub const USR1 = 30;
        pub const USR2 = 31;
        pub const THR = 32;
        pub const CKPT = 33;
        pub const CKPTEXIT = 34;

        pub const WORDS = 4;
    },
    .haiku => struct {
        pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
        pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
        pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));

        pub const HOLD: ?Sigaction.handler_fn = @ptrFromInt(3);

        pub const HUP = 1;
        pub const INT = 2;
        pub const QUIT = 3;
        pub const ILL = 4;
        pub const CHLD = 5;
        pub const ABRT = 6;
        pub const IOT = ABRT;
        pub const PIPE = 7;
        pub const FPE = 8;
        pub const KILL = 9;
        pub const STOP = 10;
        pub const SEGV = 11;
        pub const CONT = 12;
        pub const TSTP = 13;
        pub const ALRM = 14;
        pub const TERM = 15;
        pub const TTIN = 16;
        pub const TTOU = 17;
        pub const USR1 = 18;
        pub const USR2 = 19;
        pub const WINCH = 20;
        pub const KILLTHR = 21;
        pub const TRAP = 22;
        pub const POLL = 23;
        pub const PROF = 24;
        pub const SYS = 25;
        pub const URG = 26;
        pub const VTALRM = 27;
        pub const XCPU = 28;
        pub const XFSZ = 29;
        pub const BUS = 30;
        pub const RESERVED1 = 31;
        pub const RESERVED2 = 32;

        pub const BLOCK = 1;
        pub const UNBLOCK = 2;
        pub const SETMASK = 3;
    },
    .openbsd => struct {
        pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
        pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
        pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));
        pub const CATCH: ?Sigaction.handler_fn = @ptrFromInt(2);
        pub const HOLD: ?Sigaction.handler_fn = @ptrFromInt(3);

        pub const HUP = 1;
        pub const INT = 2;
        pub const QUIT = 3;
        pub const ILL = 4;
        pub const TRAP = 5;
        pub const ABRT = 6;
        pub const IOT = ABRT;
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
        pub const IO = 23;
        pub const XCPU = 24;
        pub const XFSZ = 25;
        pub const VTALRM = 26;
        pub const PROF = 27;
        pub const WINCH = 28;
        pub const INFO = 29;
        pub const USR1 = 30;
        pub const USR2 = 31;
        pub const PWR = 32;

        pub const BLOCK = 1;
        pub const UNBLOCK = 2;
        pub const SETMASK = 3;
    },
    // https://github.com/SerenityOS/serenity/blob/046c23f567a17758d762a33bdf04bacbfd088f9f/Kernel/API/POSIX/signal_numbers.h
    .serenity => struct {
        pub const INVAL = 0;
        pub const HUP = 1;
        pub const INT = 2;
        pub const QUIT = 3;
        pub const ILL = 4;
        pub const TRAP = 5;
        pub const ABRT = 6;
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
        pub const INFO = 30;
        pub const SYS = 31;
        pub const CANCEL = 32;
    },
    else => void,
};

pub const SIOCGIFINDEX = switch (native_os) {
    .linux => linux.SIOCGIFINDEX,
    .emscripten => emscripten.SIOCGIFINDEX,
    .solaris, .illumos => solaris.SIOCGLIFINDEX,
    // https://github.com/SerenityOS/serenity/blob/cb10f70394fb7e9cfc77f827adb2e46d199bc3a5/Kernel/API/Ioctl.h#L118
    .serenity => 34,
    else => void,
};

pub const STDIN_FILENO = switch (native_os) {
    .linux => linux.STDIN_FILENO,
    .emscripten => emscripten.STDIN_FILENO,
    else => 0,
};
pub const STDOUT_FILENO = switch (native_os) {
    .linux => linux.STDOUT_FILENO,
    .emscripten => emscripten.STDOUT_FILENO,
    else => 1,
};
pub const STDERR_FILENO = switch (native_os) {
    .linux => linux.STDERR_FILENO,
    .emscripten => emscripten.STDERR_FILENO,
    else => 2,
};

pub const SYS = switch (native_os) {
    .linux => linux.SYS,
    else => void,
};
/// Renamed from `sigaction` to `Sigaction` to avoid conflict with function name.
pub const Sigaction = switch (native_os) {
    .linux => switch (native_arch) {
        .mips,
        .mipsel,
        .mips64,
        .mips64el,
        => if (builtin.target.abi.isMusl())
            linux.Sigaction
        else if (builtin.target.ptrBitWidth() == 64) extern struct {
            pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
            pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

            flags: c_uint,
            handler: extern union {
                handler: ?handler_fn,
                sigaction: ?sigaction_fn,
            },
            mask: sigset_t,
            restorer: ?*const fn () callconv(.c) void = null,
        } else extern struct {
            pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
            pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

            flags: c_uint,
            handler: extern union {
                handler: ?handler_fn,
                sigaction: ?sigaction_fn,
            },
            mask: sigset_t,
            restorer: ?*const fn () callconv(.c) void = null,
            __resv: [1]c_int = .{0},
        },
        .s390x => if (builtin.abi == .gnu) extern struct {
            pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
            pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

            handler: extern union {
                handler: ?handler_fn,
                sigaction: ?sigaction_fn,
            },
            __glibc_reserved0: c_int = 0,
            flags: c_uint,
            restorer: ?*const fn () callconv(.c) void = null,
            mask: sigset_t,
        } else linux.Sigaction,
        else => linux.Sigaction,
    },
    .emscripten => emscripten.Sigaction,
    .netbsd, .macos, .ios, .tvos, .watchos, .visionos => extern struct {
        pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
        pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

        handler: extern union {
            handler: ?handler_fn,
            sigaction: ?sigaction_fn,
        },
        mask: sigset_t,
        flags: c_uint,
    },
    .dragonfly, .freebsd => extern struct {
        pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
        pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

        /// signal handler
        handler: extern union {
            handler: ?handler_fn,
            sigaction: ?sigaction_fn,
        },
        /// see signal options
        flags: c_uint,
        /// signal mask to apply
        mask: sigset_t,
    },
    .solaris, .illumos => extern struct {
        pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
        pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

        /// signal options
        flags: c_uint,
        /// signal handler
        handler: extern union {
            handler: ?handler_fn,
            sigaction: ?sigaction_fn,
        },
        /// signal mask to apply
        mask: sigset_t,
    },
    .haiku => extern struct {
        pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
        pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

        /// signal handler
        handler: extern union {
            handler: handler_fn,
            sigaction: sigaction_fn,
        },

        /// signal mask to apply
        mask: sigset_t,

        /// see signal options
        flags: i32,

        /// will be passed to the signal handler, BeOS extension
        userdata: *allowzero anyopaque = undefined,
    },
    .openbsd => extern struct {
        pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
        pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

        /// signal handler
        handler: extern union {
            handler: ?handler_fn,
            sigaction: ?sigaction_fn,
        },
        /// signal mask to apply
        mask: sigset_t,
        /// signal options
        flags: c_uint,
    },
    // https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/signal.h#L39-L46
    .serenity => extern struct {
        pub const handler_fn = *align(1) const fn (c_int) callconv(.c) void;
        pub const sigaction_fn = *const fn (c_int, *const siginfo_t, ?*anyopaque) callconv(.c) void;

        handler: extern union {
            handler: ?handler_fn,
            sigaction: ?sigaction_fn,
        },
        mask: sigset_t,
        flags: c_int,
    },
    else => void,
};
pub const T = switch (native_os) {
    .linux => linux.T,
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        pub const IOCGWINSZ = ior(0x40000000, 't', 104, @sizeOf(winsize));

        fn ior(inout: u32, group: usize, num: usize, len: usize) usize {
            return (inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num));
        }
    },
    .freebsd => struct {
        pub const IOCEXCL = 0x2000740d;
        pub const IOCNXCL = 0x2000740e;
        pub const IOCSCTTY = 0x20007461;
        pub const IOCGPGRP = 0x40047477;
        pub const IOCSPGRP = 0x80047476;
        pub const IOCOUTQ = 0x40047473;
        pub const IOCSTI = 0x80017472;
        pub const IOCGWINSZ = 0x40087468;
        pub const IOCSWINSZ = 0x80087467;
        pub const IOCMGET = 0x4004746a;
        pub const IOCMBIS = 0x8004746c;
        pub const IOCMBIC = 0x8004746b;
        pub const IOCMSET = 0x8004746d;
        pub const FIONREAD = 0x4004667f;
        pub const IOCCONS = 0x80047462;
        pub const IOCPKT = 0x80047470;
        pub const FIONBIO = 0x8004667e;
        pub const IOCNOTTY = 0x20007471;
        pub const IOCSETD = 0x8004741b;
        pub const IOCGETD = 0x4004741a;
        pub const IOCSBRK = 0x2000747b;
        pub const IOCCBRK = 0x2000747a;
        pub const IOCGSID = 0x40047463;
        pub const IOCGPTN = 0x4004740f;
        pub const IOCSIG = 0x2004745f;
    },
    .solaris, .illumos => struct {
        pub const CGETA = tioc('T', 1);
        pub const CSETA = tioc('T', 2);
        pub const CSETAW = tioc('T', 3);
        pub const CSETAF = tioc('T', 4);
        pub const CSBRK = tioc('T', 5);
        pub const CXONC = tioc('T', 6);
        pub const CFLSH = tioc('T', 7);
        pub const IOCGWINSZ = tioc('T', 104);
        pub const IOCSWINSZ = tioc('T', 103);
        // Softcarrier ioctls
        pub const IOCGSOFTCAR = tioc('T', 105);
        pub const IOCSSOFTCAR = tioc('T', 106);
        // termios ioctls
        pub const CGETS = tioc('T', 13);
        pub const CSETS = tioc('T', 14);
        pub const CSANOW = tioc('T', 14);
        pub const CSETSW = tioc('T', 15);
        pub const CSADRAIN = tioc('T', 15);
        pub const CSETSF = tioc('T', 16);
        pub const IOCSETLD = tioc('T', 123);
        pub const IOCGETLD = tioc('T', 124);
        // NTP PPS ioctls
        pub const IOCGPPS = tioc('T', 125);
        pub const IOCSPPS = tioc('T', 126);
        pub const IOCGPPSEV = tioc('T', 127);

        pub const IOCGETD = tioc('t', 0);
        pub const IOCSETD = tioc('t', 1);
        pub const IOCHPCL = tioc('t', 2);
        pub const IOCGETP = tioc('t', 8);
        pub const IOCSETP = tioc('t', 9);
        pub const IOCSETN = tioc('t', 10);
        pub const IOCEXCL = tioc('t', 13);
        pub const IOCNXCL = tioc('t', 14);
        pub const IOCFLUSH = tioc('t', 16);
        pub const IOCSETC = tioc('t', 17);
        pub const IOCGETC = tioc('t', 18);
        /// bis local mode bits
        pub const IOCLBIS = tioc('t', 127);
        /// bic local mode bits
        pub const IOCLBIC = tioc('t', 126);
        /// set entire local mode word
        pub const IOCLSET = tioc('t', 125);
        /// get local modes
        pub const IOCLGET = tioc('t', 124);
        /// set break bit
        pub const IOCSBRK = tioc('t', 123);
        /// clear break bit
        pub const IOCCBRK = tioc('t', 122);
        /// set data terminal ready
        pub const IOCSDTR = tioc('t', 121);
        /// clear data terminal ready
        pub const IOCCDTR = tioc('t', 120);
        /// set local special chars
        pub const IOCSLTC = tioc('t', 117);
        /// get local special chars
        pub const IOCGLTC = tioc('t', 116);
        /// driver output queue size
        pub const IOCOUTQ = tioc('t', 115);
        /// void tty association
        pub const IOCNOTTY = tioc('t', 113);
        /// get a ctty
        pub const IOCSCTTY = tioc('t', 132);
        /// stop output, like ^S
        pub const IOCSTOP = tioc('t', 111);
        /// start output, like ^Q
        pub const IOCSTART = tioc('t', 110);
        /// get pgrp of tty
        pub const IOCGPGRP = tioc('t', 20);
        /// set pgrp of tty
        pub const IOCSPGRP = tioc('t', 21);
        /// get session id on ctty
        pub const IOCGSID = tioc('t', 22);
        /// simulate terminal input
        pub const IOCSTI = tioc('t', 23);
        /// set all modem bits
        pub const IOCMSET = tioc('t', 26);
        /// bis modem bits
        pub const IOCMBIS = tioc('t', 27);
        /// bic modem bits
        pub const IOCMBIC = tioc('t', 28);
        /// get all modem bits
        pub const IOCMGET = tioc('t', 29);

        fn tioc(t: u16, num: u8) u16 {
            return (t << 8) | num;
        }
    },
    .netbsd => struct {
        pub const IOCCBRK = 0x2000747a;
        pub const IOCCDTR = 0x20007478;
        pub const IOCCONS = 0x80047462;
        pub const IOCDCDTIMESTAMP = 0x40107458;
        pub const IOCDRAIN = 0x2000745e;
        pub const IOCEXCL = 0x2000740d;
        pub const IOCEXT = 0x80047460;
        pub const IOCFLAG_CDTRCTS = 0x10;
        pub const IOCFLAG_CLOCAL = 0x2;
        pub const IOCFLAG_CRTSCTS = 0x4;
        pub const IOCFLAG_MDMBUF = 0x8;
        pub const IOCFLAG_SOFTCAR = 0x1;
        pub const IOCFLUSH = 0x80047410;
        pub const IOCGETA = 0x402c7413;
        pub const IOCGETD = 0x4004741a;
        pub const IOCGFLAGS = 0x4004745d;
        pub const IOCGLINED = 0x40207442;
        pub const IOCGPGRP = 0x40047477;
        pub const IOCGQSIZE = 0x40047481;
        pub const IOCGRANTPT = 0x20007447;
        pub const IOCGSID = 0x40047463;
        pub const IOCGSIZE = 0x40087468;
        pub const IOCGWINSZ = 0x40087468;
        pub const IOCMBIC = 0x8004746b;
        pub const IOCMBIS = 0x8004746c;
        pub const IOCMGET = 0x4004746a;
        pub const IOCMSET = 0x8004746d;
        pub const IOCM_CAR = 0x40;
        pub const IOCM_CD = 0x40;
        pub const IOCM_CTS = 0x20;
        pub const IOCM_DSR = 0x100;
        pub const IOCM_DTR = 0x2;
        pub const IOCM_LE = 0x1;
        pub const IOCM_RI = 0x80;
        pub const IOCM_RNG = 0x80;
        pub const IOCM_RTS = 0x4;
        pub const IOCM_SR = 0x10;
        pub const IOCM_ST = 0x8;
        pub const IOCNOTTY = 0x20007471;
        pub const IOCNXCL = 0x2000740e;
        pub const IOCOUTQ = 0x40047473;
        pub const IOCPKT = 0x80047470;
        pub const IOCPKT_DATA = 0x0;
        pub const IOCPKT_DOSTOP = 0x20;
        pub const IOCPKT_FLUSHREAD = 0x1;
        pub const IOCPKT_FLUSHWRITE = 0x2;
        pub const IOCPKT_IOCTL = 0x40;
        pub const IOCPKT_NOSTOP = 0x10;
        pub const IOCPKT_START = 0x8;
        pub const IOCPKT_STOP = 0x4;
        pub const IOCPTMGET = 0x40287446;
        pub const IOCPTSNAME = 0x40287448;
        pub const IOCRCVFRAME = 0x80087445;
        pub const IOCREMOTE = 0x80047469;
        pub const IOCSBRK = 0x2000747b;
        pub const IOCSCTTY = 0x20007461;
        pub const IOCSDTR = 0x20007479;
        pub const IOCSETA = 0x802c7414;
        pub const IOCSETAF = 0x802c7416;
        pub const IOCSETAW = 0x802c7415;
        pub const IOCSETD = 0x8004741b;
        pub const IOCSFLAGS = 0x8004745c;
        pub const IOCSIG = 0x2000745f;
        pub const IOCSLINED = 0x80207443;
        pub const IOCSPGRP = 0x80047476;
        pub const IOCSQSIZE = 0x80047480;
        pub const IOCSSIZE = 0x80087467;
        pub const IOCSTART = 0x2000746e;
        pub const IOCSTAT = 0x80047465;
        pub const IOCSTI = 0x80017472;
        pub const IOCSTOP = 0x2000746f;
        pub const IOCSWINSZ = 0x80087467;
        pub const IOCUCNTL = 0x80047466;
        pub const IOCXMTFRAME = 0x80087444;
    },
    .haiku => struct {
        pub const CGETA = 0x8000;
        pub const CSETA = 0x8001;
        pub const CSETAF = 0x8002;
        pub const CSETAW = 0x8003;
        pub const CWAITEVENT = 0x8004;
        pub const CSBRK = 0x8005;
        pub const CFLSH = 0x8006;
        pub const CXONC = 0x8007;
        pub const CQUERYCONNECTED = 0x8008;
        pub const CGETBITS = 0x8009;
        pub const CSETDTR = 0x8010;
        pub const CSETRTS = 0x8011;
        pub const IOCGWINSZ = 0x8012;
        pub const IOCSWINSZ = 0x8013;
        pub const CVTIME = 0x8014;
        pub const IOCGPGRP = 0x8015;
        pub const IOCSPGRP = 0x8016;
        pub const IOCSCTTY = 0x8017;
        pub const IOCMGET = 0x8018;
        pub const IOCMSET = 0x8019;
        pub const IOCSBRK = 0x8020;
        pub const IOCCBRK = 0x8021;
        pub const IOCMBIS = 0x8022;
        pub const IOCMBIC = 0x8023;
        pub const IOCGSID = 0x8024;

        pub const FIONREAD = 0xbe000001;
        pub const FIONBIO = 0xbe000000;
    },
    .openbsd => struct {
        pub const IOCCBRK = 0x2000747a;
        pub const IOCCDTR = 0x20007478;
        pub const IOCCONS = 0x80047462;
        pub const IOCDCDTIMESTAMP = 0x40107458;
        pub const IOCDRAIN = 0x2000745e;
        pub const IOCEXCL = 0x2000740d;
        pub const IOCEXT = 0x80047460;
        pub const IOCFLAG_CDTRCTS = 0x10;
        pub const IOCFLAG_CLOCAL = 0x2;
        pub const IOCFLAG_CRTSCTS = 0x4;
        pub const IOCFLAG_MDMBUF = 0x8;
        pub const IOCFLAG_SOFTCAR = 0x1;
        pub const IOCFLUSH = 0x80047410;
        pub const IOCGETA = 0x402c7413;
        pub const IOCGETD = 0x4004741a;
        pub const IOCGFLAGS = 0x4004745d;
        pub const IOCGLINED = 0x40207442;
        pub const IOCGPGRP = 0x40047477;
        pub const IOCGQSIZE = 0x40047481;
        pub const IOCGRANTPT = 0x20007447;
        pub const IOCGSID = 0x40047463;
        pub const IOCGSIZE = 0x40087468;
        pub const IOCGWINSZ = 0x40087468;
        pub const IOCMBIC = 0x8004746b;
        pub const IOCMBIS = 0x8004746c;
        pub const IOCMGET = 0x4004746a;
        pub const IOCMSET = 0x8004746d;
        pub const IOCM_CAR = 0x40;
        pub const IOCM_CD = 0x40;
        pub const IOCM_CTS = 0x20;
        pub const IOCM_DSR = 0x100;
        pub const IOCM_DTR = 0x2;
        pub const IOCM_LE = 0x1;
        pub const IOCM_RI = 0x80;
        pub const IOCM_RNG = 0x80;
        pub const IOCM_RTS = 0x4;
        pub const IOCM_SR = 0x10;
        pub const IOCM_ST = 0x8;
        pub const IOCNOTTY = 0x20007471;
        pub const IOCNXCL = 0x2000740e;
        pub const IOCOUTQ = 0x40047473;
        pub const IOCPKT = 0x80047470;
        pub const IOCPKT_DATA = 0x0;
        pub const IOCPKT_DOSTOP = 0x20;
        pub const IOCPKT_FLUSHREAD = 0x1;
        pub const IOCPKT_FLUSHWRITE = 0x2;
        pub const IOCPKT_IOCTL = 0x40;
        pub const IOCPKT_NOSTOP = 0x10;
        pub const IOCPKT_START = 0x8;
        pub const IOCPKT_STOP = 0x4;
        pub const IOCPTMGET = 0x40287446;
        pub const IOCPTSNAME = 0x40287448;
        pub const IOCRCVFRAME = 0x80087445;
        pub const IOCREMOTE = 0x80047469;
        pub const IOCSBRK = 0x2000747b;
        pub const IOCSCTTY = 0x20007461;
        pub const IOCSDTR = 0x20007479;
        pub const IOCSETA = 0x802c7414;
        pub const IOCSETAF = 0x802c7416;
        pub const IOCSETAW = 0x802c7415;
        pub const IOCSETD = 0x8004741b;
        pub const IOCSFLAGS = 0x8004745c;
        pub const IOCSIG = 0x2000745f;
        pub const IOCSLINED = 0x80207443;
        pub const IOCSPGRP = 0x80047476;
        pub const IOCSQSIZE = 0x80047480;
        pub const IOCSSIZE = 0x80087467;
        pub const IOCSTART = 0x2000746e;
        pub const IOCSTAT = 0x80047465;
        pub const IOCSTI = 0x80017472;
        pub const IOCSTOP = 0x2000746f;
        pub const IOCSWINSZ = 0x80087467;
        pub const IOCUCNTL = 0x80047466;
        pub const IOCXMTFRAME = 0x80087444;
    },
    .dragonfly => struct {
        pub const IOCMODG = 0x40047403;
        pub const IOCMODS = 0x80047404;
        pub const IOCM_LE = 0x00000001;
        pub const IOCM_DTR = 0x00000002;
        pub const IOCM_RTS = 0x00000004;
        pub const IOCM_ST = 0x00000008;
        pub const IOCM_SR = 0x00000010;
        pub const IOCM_CTS = 0x00000020;
        pub const IOCM_CAR = 0x00000040;
        pub const IOCM_CD = 0x00000040;
        pub const IOCM_RNG = 0x00000080;
        pub const IOCM_RI = 0x00000080;
        pub const IOCM_DSR = 0x00000100;
        pub const IOCEXCL = 0x2000740d;
        pub const IOCNXCL = 0x2000740e;
        pub const IOCFLUSH = 0x80047410;
        pub const IOCGETA = 0x402c7413;
        pub const IOCSETA = 0x802c7414;
        pub const IOCSETAW = 0x802c7415;
        pub const IOCSETAF = 0x802c7416;
        pub const IOCGETD = 0x4004741a;
        pub const IOCSETD = 0x8004741b;
        pub const IOCSBRK = 0x2000747b;
        pub const IOCCBRK = 0x2000747a;
        pub const IOCSDTR = 0x20007479;
        pub const IOCCDTR = 0x20007478;
        pub const IOCGPGRP = 0x40047477;
        pub const IOCSPGRP = 0x80047476;
        pub const IOCOUTQ = 0x40047473;
        pub const IOCSTI = 0x80017472;
        pub const IOCNOTTY = 0x20007471;
        pub const IOCPKT = 0x80047470;
        pub const IOCPKT_DATA = 0x00000000;
        pub const IOCPKT_FLUSHREAD = 0x00000001;
        pub const IOCPKT_FLUSHWRITE = 0x00000002;
        pub const IOCPKT_STOP = 0x00000004;
        pub const IOCPKT_START = 0x00000008;
        pub const IOCPKT_NOSTOP = 0x00000010;
        pub const IOCPKT_DOSTOP = 0x00000020;
        pub const IOCPKT_IOCTL = 0x00000040;
        pub const IOCSTOP = 0x2000746f;
        pub const IOCSTART = 0x2000746e;
        pub const IOCMSET = 0x8004746d;
        pub const IOCMBIS = 0x8004746c;
        pub const IOCMBIC = 0x8004746b;
        pub const IOCMGET = 0x4004746a;
        pub const IOCREMOTE = 0x80047469;
        pub const IOCGWINSZ = 0x40087468;
        pub const IOCSWINSZ = 0x80087467;
        pub const IOCUCNTL = 0x80047466;
        pub const IOCSTAT = 0x20007465;
        pub const IOCGSID = 0x40047463;
        pub const IOCCONS = 0x80047462;
        pub const IOCSCTTY = 0x20007461;
        pub const IOCEXT = 0x80047460;
        pub const IOCSIG = 0x2000745f;
        pub const IOCDRAIN = 0x2000745e;
        pub const IOCMSDTRWAIT = 0x8004745b;
        pub const IOCMGDTRWAIT = 0x4004745a;
        pub const IOCTIMESTAMP = 0x40107459;
        pub const IOCDCDTIMESTAMP = 0x40107458;
        pub const IOCSDRAINWAIT = 0x80047457;
        pub const IOCGDRAINWAIT = 0x40047456;
        pub const IOCISPTMASTER = 0x20007455;
    },
    // https://github.com/SerenityOS/serenity/blob/cb10f70394fb7e9cfc77f827adb2e46d199bc3a5/Kernel/API/Ioctl.h#L84-L96
    .serenity => struct {
        pub const IOCGPGRP = 0;
        pub const IOCSPGRP = 1;
        pub const CGETS = 2;
        pub const CSETS = 3;
        pub const CSETSW = 4;
        pub const CSETSF = 5;
        pub const CFLSH = 6;
        pub const IOCGWINSZ = 7;
        pub const IOCSCTTY = 8;
        pub const IOCSTI = 9;
        pub const IOCNOTTY = 10;
        pub const IOCSWINSZ = 11;
        pub const IOCGPTN = 12;
    },
    else => void,
};
pub const IOCPARM_MASK = switch (native_os) {
    .windows => ws2_32.IOCPARM_MASK,
    .macos, .ios, .tvos, .watchos, .visionos => 0x1fff,
    else => void,
};
pub const TCSA = std.posix.TCSA;
pub const TFD = switch (native_os) {
    .linux => linux.TFD,
    else => void,
};
pub const VDSO = switch (native_os) {
    .linux => linux.VDSO,
    else => void,
};
pub const W = switch (native_os) {
    .linux => linux.W,
    .emscripten => emscripten.W,
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        /// [XSI] no hang in wait/no child to reap
        pub const NOHANG = 0x00000001;
        /// [XSI] notify on stop, untraced child
        pub const UNTRACED = 0x00000002;

        pub fn EXITSTATUS(x: u32) u8 {
            return @as(u8, @intCast(x >> 8));
        }
        pub fn TERMSIG(x: u32) u32 {
            return status(x);
        }
        pub fn STOPSIG(x: u32) u32 {
            return x >> 8;
        }
        pub fn IFEXITED(x: u32) bool {
            return status(x) == 0;
        }
        pub fn IFSTOPPED(x: u32) bool {
            return status(x) == stopped and STOPSIG(x) != 0x13;
        }
        pub fn IFSIGNALED(x: u32) bool {
            return status(x) != stopped and status(x) != 0;
        }

        fn status(x: u32) u32 {
            return x & 0o177;
        }
        const stopped = 0o177;
    },
    .freebsd => struct {
        pub const NOHANG = 1;
        pub const UNTRACED = 2;
        pub const STOPPED = UNTRACED;
        pub const CONTINUED = 4;
        pub const NOWAIT = 8;
        pub const EXITED = 16;
        pub const TRAPPED = 32;

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
            return @as(u16, @truncate((((s & 0xffff) *% 0x10001) >> 8))) > 0x7f00;
        }
        pub fn IFSIGNALED(s: u32) bool {
            return (s & 0xffff) -% 1 < 0xff;
        }
    },
    .solaris, .illumos => struct {
        pub const EXITED = 0o001;
        pub const TRAPPED = 0o002;
        pub const UNTRACED = 0o004;
        pub const STOPPED = UNTRACED;
        pub const CONTINUED = 0o010;
        pub const NOHANG = 0o100;
        pub const NOWAIT = 0o200;

        pub fn EXITSTATUS(s: u32) u8 {
            return @as(u8, @intCast((s >> 8) & 0xff));
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

        pub fn IFCONTINUED(s: u32) bool {
            return ((s & 0o177777) == 0o177777);
        }

        pub fn IFSTOPPED(s: u32) bool {
            return (s & 0x00ff != 0o177) and !(s & 0xff00 != 0);
        }

        pub fn IFSIGNALED(s: u32) bool {
            return s & 0x00ff > 0 and s & 0xff00 == 0;
        }
    },
    .netbsd => struct {
        pub const NOHANG = 0x00000001;
        pub const UNTRACED = 0x00000002;
        pub const STOPPED = UNTRACED;
        pub const CONTINUED = 0x00000010;
        pub const NOWAIT = 0x00010000;
        pub const EXITED = 0x00000020;
        pub const TRAPPED = 0x00000040;

        pub fn EXITSTATUS(s: u32) u8 {
            return @as(u8, @intCast((s >> 8) & 0xff));
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

        pub fn IFCONTINUED(s: u32) bool {
            return ((s & 0x7f) == 0xffff);
        }

        pub fn IFSTOPPED(s: u32) bool {
            return ((s & 0x7f != 0x7f) and !IFCONTINUED(s));
        }

        pub fn IFSIGNALED(s: u32) bool {
            return !IFSTOPPED(s) and !IFCONTINUED(s) and !IFEXITED(s);
        }
    },
    .dragonfly => struct {
        pub const NOHANG = 0x0001;
        pub const UNTRACED = 0x0002;
        pub const CONTINUED = 0x0004;
        pub const STOPPED = UNTRACED;
        pub const NOWAIT = 0x0008;
        pub const EXITED = 0x0010;
        pub const TRAPPED = 0x0020;

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
            return @as(u16, @truncate((((s & 0xffff) *% 0x10001) >> 8))) > 0x7f00;
        }
        pub fn IFSIGNALED(s: u32) bool {
            return (s & 0xffff) -% 1 < 0xff;
        }
    },
    .haiku => struct {
        pub const NOHANG = 0x1;
        pub const UNTRACED = 0x2;
        pub const CONTINUED = 0x4;
        pub const EXITED = 0x08;
        pub const STOPPED = 0x10;
        pub const NOWAIT = 0x20;

        pub fn EXITSTATUS(s: u32) u8 {
            return @as(u8, @intCast(s & 0xff));
        }

        pub fn TERMSIG(s: u32) u32 {
            return (s >> 8) & 0xff;
        }

        pub fn STOPSIG(s: u32) u32 {
            return (s >> 16) & 0xff;
        }

        pub fn IFEXITED(s: u32) bool {
            return (s & ~@as(u32, 0xff)) == 0;
        }

        pub fn IFSTOPPED(s: u32) bool {
            return ((s >> 16) & 0xff) != 0;
        }

        pub fn IFSIGNALED(s: u32) bool {
            return ((s >> 8) & 0xff) != 0;
        }
    },
    .openbsd => struct {
        pub const NOHANG = 1;
        pub const UNTRACED = 2;
        pub const CONTINUED = 8;

        pub fn EXITSTATUS(s: u32) u8 {
            return @as(u8, @intCast((s >> 8) & 0xff));
        }
        pub fn TERMSIG(s: u32) u32 {
            return (s & 0x7f);
        }
        pub fn STOPSIG(s: u32) u32 {
            return EXITSTATUS(s);
        }
        pub fn IFEXITED(s: u32) bool {
            return TERMSIG(s) == 0;
        }

        pub fn IFCONTINUED(s: u32) bool {
            return ((s & 0o177777) == 0o177777);
        }

        pub fn IFSTOPPED(s: u32) bool {
            return (s & 0xff == 0o177);
        }

        pub fn IFSIGNALED(s: u32) bool {
            return (((s) & 0o177) != 0o177) and (((s) & 0o177) != 0);
        }
    },
    // https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/sys/wait.h
    .serenity => struct {
        pub const NOHANG = 1;
        pub const UNTRACED = 2;
        pub const STOPPED = UNTRACED;
        pub const EXITED = 4;
        pub const CONTINUED = 8;
        pub const NOWAIT = 0x1000000;

        pub fn EXITSTATUS(s: u32) u8 {
            return @intCast((s & 0xff00) >> 8);
        }

        pub fn STOPSIG(s: u32) u32 {
            return EXITSTATUS(s);
        }

        pub fn TERMSIG(s: u32) u32 {
            return s & 0x7f;
        }

        pub fn IFEXITED(s: u32) bool {
            return TERMSIG(s) == 0;
        }

        pub fn IFSTOPPED(s: u32) bool {
            return (s & 0xff) == 0x7f;
        }

        pub fn IFSIGNALED(s: u32) bool {
            return (((s & 0x7f) + 1) >> 1) > 0;
        }

        pub fn IFCONTINUED(s: u32) bool {
            return s == 0xffff;
        }
    },
    else => void,
};
pub const clock_t = switch (native_os) {
    .linux => linux.clock_t,
    .emscripten => emscripten.clock_t,
    .macos, .ios, .tvos, .watchos, .visionos => c_ulong,
    .freebsd => isize,
    .openbsd, .solaris, .illumos => i64,
    .netbsd => u32,
    .haiku => i32,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L50
    .serenity => u64,
    else => void,
};
pub const cpu_set_t = switch (native_os) {
    .linux => linux.cpu_set_t,
    .emscripten => emscripten.cpu_set_t,
    else => void,
};
pub const dl_phdr_info = switch (native_os) {
    .linux => linux.dl_phdr_info,
    .emscripten => emscripten.dl_phdr_info,
    .freebsd => extern struct {
        /// Module relocation base.
        addr: std.elf.Addr,
        /// Module name.
        name: ?[*:0]const u8,
        /// Pointer to module's phdr.
        phdr: [*]std.elf.Phdr,
        /// Number of entries in phdr.
        phnum: u16,
        /// Total number of loads.
        adds: u64,
        /// Total number of unloads.
        subs: u64,
        tls_modid: usize,
        tls_data: ?*anyopaque,
    },
    .solaris, .illumos => extern struct {
        addr: std.elf.Addr,
        name: ?[*:0]const u8,
        phdr: [*]std.elf.Phdr,
        phnum: std.elf.Half,
        /// Incremented when a new object is mapped into the process.
        adds: u64,
        /// Incremented when an object is unmapped from the process.
        subs: u64,
    },
    // https://github.com/SerenityOS/serenity/blob/45d81dceed81df0c8ef75b440b20cc0938195faa/Userland/Libraries/LibC/link.h#L15-L20
    .openbsd, .haiku, .dragonfly, .netbsd, .serenity => extern struct {
        addr: usize,
        name: ?[*:0]const u8,
        phdr: [*]std.elf.Phdr,
        phnum: std.elf.Half,
    },
    else => void,
};
pub const epoll_event = switch (native_os) {
    .linux => linux.epoll_event,
    else => void,
};
pub const ifreq = switch (native_os) {
    .linux => linux.ifreq,
    .emscripten => emscripten.ifreq,
    .solaris, .illumos => lifreq,
    // https://github.com/SerenityOS/serenity/blob/9882848e0bf783dfc8e8a6d887a848d70d9c58f4/Kernel/API/POSIX/net/if.h#L49-L82
    .serenity => extern struct {
        // Not actually in a union, but the stdlib expects one for ifreq
        ifrn: extern union {
            name: [IFNAMESIZE]u8,
        },
        ifru: extern union {
            addr: sockaddr,
            dstaddr: sockaddr,
            broadaddr: sockaddr,
            netmask: sockaddr,
            hwaddr: sockaddr,
            flags: c_short,
            metric: c_int,
            vnetid: i64,
            media: u64,
            data: ?*anyopaque,
            index: c_uint,
        },
    },
    else => void,
};
pub const itimerspec = switch (native_os) {
    .linux => linux.itimerspec,
    .haiku => extern struct {
        interval: timespec,
        value: timespec,
    },
    else => void,
};
pub const msghdr = switch (native_os) {
    .linux => linux.msghdr,
    .openbsd,
    .emscripten,
    .dragonfly,
    .freebsd,
    .netbsd,
    .haiku,
    .solaris,
    .illumos,
    .macos,
    .driverkit,
    .ios,
    .tvos,
    .visionos,
    .watchos,
    => extern struct {
        /// optional address
        name: ?*sockaddr,
        /// size of address
        namelen: socklen_t,
        /// scatter/gather array
        iov: [*]iovec,
        /// # elements in iov
        iovlen: i32,
        /// ancillary data
        control: ?*anyopaque,
        /// ancillary data buffer len
        controllen: socklen_t,
        /// flags on received message
        flags: i32,
    },
    // https://github.com/SerenityOS/serenity/blob/ac44ec5ebc707f9dd0c3d4759a1e17e91db5d74f/Kernel/API/POSIX/sys/socket.h#L74-L82
    .serenity => extern struct {
        name: ?*anyopaque,
        namelen: socklen_t,
        iov: [*]iovec,
        iovlen: c_int,
        control: ?*anyopaque,
        controllen: socklen_t,
        flags: c_int,
    },
    else => void,
};
pub const msghdr_const = switch (native_os) {
    .linux => linux.msghdr_const,
    .openbsd,
    .emscripten,
    .dragonfly,
    .freebsd,
    .netbsd,
    .haiku,
    .solaris,
    .illumos,
    .macos,
    .driverkit,
    .ios,
    .tvos,
    .visionos,
    .watchos,
    => extern struct {
        /// optional address
        name: ?*const sockaddr,
        /// size of address
        namelen: socklen_t,
        /// scatter/gather array
        iov: [*]const iovec_const,
        /// # elements in iov
        iovlen: i32,
        /// ancillary data
        control: ?*const anyopaque,
        /// ancillary data buffer len
        controllen: socklen_t,
        /// flags on received message
        flags: i32,
    },
    .serenity => extern struct {
        name: ?*const anyopaque,
        namelen: socklen_t,
        iov: [*]const iovec,
        iovlen: c_int,
        control: ?*const anyopaque,
        controllen: socklen_t,
        flags: c_int,
    },
    else => void,
};
pub const nfds_t = switch (native_os) {
    .linux => linux.nfds_t,
    .emscripten => emscripten.nfds_t,
    .haiku, .solaris, .illumos, .wasi => usize,
    .windows => c_ulong,
    .openbsd, .dragonfly, .netbsd, .freebsd, .macos, .ios, .tvos, .watchos, .visionos => u32,
    // https://github.com/SerenityOS/serenity/blob/265764ff2fec038855193296588a887fc322d76a/Kernel/API/POSIX/poll.h#L32
    .serenity => c_uint,
    else => void,
};
pub const perf_event_attr = switch (native_os) {
    .linux => linux.perf_event_attr,
    else => void,
};
pub const pid_t = switch (native_os) {
    .linux => linux.pid_t,
    .emscripten => emscripten.pid_t,
    .windows => windows.HANDLE,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L31-L32
    .serenity => c_int,
    else => i32,
};
pub const pollfd = switch (native_os) {
    .linux => linux.pollfd,
    .emscripten => emscripten.pollfd,
    .windows => ws2_32.pollfd,
    // https://github.com/SerenityOS/serenity/blob/265764ff2fec038855193296588a887fc322d76a/Kernel/API/POSIX/poll.h#L26-L30
    .serenity => extern struct {
        fd: fd_t,
        events: c_short,
        revents: c_short,
    },
    else => extern struct {
        fd: fd_t,
        events: i16,
        revents: i16,
    },
};
pub const rlim_t = switch (native_os) {
    .linux => linux.rlim_t,
    .emscripten => emscripten.rlim_t,
    .openbsd, .netbsd, .solaris, .illumos, .macos, .ios, .tvos, .watchos, .visionos => u64,
    .haiku, .dragonfly, .freebsd => i64,
    // https://github.com/SerenityOS/serenity/blob/aae106e37b48f2158e68902293df1e4bf7b80c0f/Userland/Libraries/LibC/sys/resource.h#L54
    .serenity => usize,
    else => void,
};
pub const rlimit = switch (native_os) {
    .linux, .emscripten => linux.rlimit,
    .windows => void,
    // https://github.com/SerenityOS/serenity/blob/aae106e37b48f2158e68902293df1e4bf7b80c0f/Userland/Libraries/LibC/sys/resource.h#L56-L59
    else => extern struct {
        /// Soft limit
        cur: rlim_t,
        /// Hard limit
        max: rlim_t,
    },
};
pub const rlimit_resource = switch (native_os) {
    .linux => linux.rlimit_resource,
    .emscripten => emscripten.rlimit_resource,
    .openbsd, .macos, .ios, .tvos, .watchos, .visionos => enum(c_int) {
        CPU = 0,
        FSIZE = 1,
        DATA = 2,
        STACK = 3,
        CORE = 4,
        RSS = 5,
        MEMLOCK = 6,
        NPROC = 7,
        NOFILE = 8,
        _,

        pub const AS: rlimit_resource = .RSS;
    },
    .freebsd => enum(c_int) {
        CPU = 0,
        FSIZE = 1,
        DATA = 2,
        STACK = 3,
        CORE = 4,
        RSS = 5,
        MEMLOCK = 6,
        NPROC = 7,
        NOFILE = 8,
        SBSIZE = 9,
        VMEM = 10,
        NPTS = 11,
        SWAP = 12,
        KQUEUES = 13,
        UMTXP = 14,
        _,

        pub const AS: rlimit_resource = .VMEM;
    },
    .solaris, .illumos => enum(c_int) {
        CPU = 0,
        FSIZE = 1,
        DATA = 2,
        STACK = 3,
        CORE = 4,
        NOFILE = 5,
        VMEM = 6,
        _,

        pub const AS: rlimit_resource = .VMEM;
    },
    .netbsd => enum(c_int) {
        CPU = 0,
        FSIZE = 1,
        DATA = 2,
        STACK = 3,
        CORE = 4,
        RSS = 5,
        MEMLOCK = 6,
        NPROC = 7,
        NOFILE = 8,
        SBSIZE = 9,
        VMEM = 10,
        NTHR = 11,
        _,

        pub const AS: rlimit_resource = .VMEM;
    },
    .dragonfly => enum(c_int) {
        CPU = 0,
        FSIZE = 1,
        DATA = 2,
        STACK = 3,
        CORE = 4,
        RSS = 5,
        MEMLOCK = 6,
        NPROC = 7,
        NOFILE = 8,
        SBSIZE = 9,
        VMEM = 10,
        POSIXLOCKS = 11,
        _,

        pub const AS: rlimit_resource = .VMEM;
    },
    .haiku => enum(i32) {
        CORE = 0,
        CPU = 1,
        DATA = 2,
        FSIZE = 3,
        NOFILE = 4,
        STACK = 5,
        AS = 6,
        NOVMON = 7,
        _,
    },
    // https://github.com/SerenityOS/serenity/blob/aae106e37b48f2158e68902293df1e4bf7b80c0f/Userland/Libraries/LibC/sys/resource.h#L42-L48
    .serenity => enum(c_int) {
        CORE = 1,
        CPU = 2,
        DATA = 3,
        FSIZE = 4,
        NOFILE = 5,
        STACK = 6,
        AS = 7,
        _,
    },
    else => void,
};
pub const rusage = switch (native_os) {
    .linux => linux.rusage,
    .emscripten => emscripten.rusage,
    .macos, .ios, .tvos, .watchos, .visionos => extern struct {
        utime: timeval,
        stime: timeval,
        maxrss: isize,
        ixrss: isize,
        idrss: isize,
        isrss: isize,
        minflt: isize,
        majflt: isize,
        nswap: isize,
        inblock: isize,
        oublock: isize,
        msgsnd: isize,
        msgrcv: isize,
        nsignals: isize,
        nvcsw: isize,
        nivcsw: isize,

        pub const SELF = 0;
        pub const CHILDREN = -1;
    },
    .solaris, .illumos => extern struct {
        utime: timeval,
        stime: timeval,
        maxrss: isize,
        ixrss: isize,
        idrss: isize,
        isrss: isize,
        minflt: isize,
        majflt: isize,
        nswap: isize,
        inblock: isize,
        oublock: isize,
        msgsnd: isize,
        msgrcv: isize,
        nsignals: isize,
        nvcsw: isize,
        nivcsw: isize,

        pub const SELF = 0;
        pub const CHILDREN = -1;
        pub const THREAD = 1;
    },
    // https://github.com/SerenityOS/serenity/blob/aae106e37b48f2158e68902293df1e4bf7b80c0f/Userland/Libraries/LibC/sys/resource.h#L18-L38
    .serenity => extern struct {
        utime: timeval,
        stime: timeval,
        maxrss: c_long,
        ixrss: c_long,
        idrss: c_long,
        isrss: c_long,
        minflt: c_long,
        majflt: c_long,
        nswap: c_long,
        inblock: c_long,
        oublock: c_long,
        msgsnd: c_long,
        msgrcv: c_long,
        nsignals: c_long,
        nvcsw: c_long,
        nivcsw: c_long,

        pub const SELF = 1;
        pub const CHILDREN = 2;
    },
    else => void,
};

pub const siginfo_t = switch (native_os) {
    .linux => linux.siginfo_t,
    .emscripten => emscripten.siginfo_t,
    .macos, .ios, .tvos, .watchos, .visionos => extern struct {
        signo: c_int,
        errno: c_int,
        code: c_int,
        pid: pid_t,
        uid: uid_t,
        status: c_int,
        addr: *allowzero anyopaque,
        value: extern union {
            int: c_int,
            ptr: *anyopaque,
        },
        si_band: c_long,
        _pad: [7]c_ulong,
    },
    .freebsd => extern struct {
        // Signal number.
        signo: c_int,
        // Errno association.
        errno: c_int,
        /// Signal code.
        ///
        /// Cause of signal, one of the SI_ macros or signal-specific values, i.e.
        /// one of the FPE_... values for SIGFPE.
        /// This value is equivalent to the second argument to an old-style FreeBSD
        /// signal handler.
        code: c_int,
        /// Sending process.
        pid: pid_t,
        /// Sender's ruid.
        uid: uid_t,
        /// Exit value.
        status: c_int,
        /// Faulting instruction.
        addr: *allowzero anyopaque,
        /// Signal value.
        value: sigval,
        reason: extern union {
            fault: extern struct {
                /// Machine specific trap code.
                trapno: c_int,
            },
            timer: extern struct {
                timerid: c_int,
                overrun: c_int,
            },
            mesgq: extern struct {
                mqd: c_int,
            },
            poll: extern struct {
                /// Band event for SIGPOLL. UNUSED.
                band: c_long,
            },
            spare: extern struct {
                spare1: c_long,
                spare2: [7]c_int,
            },
        },
    },
    .solaris, .illumos => extern struct {
        signo: c_int,
        code: c_int,
        errno: c_int,
        // 64bit architectures insert 4bytes of padding here, this is done by
        // correctly aligning the reason field
        reason: extern union {
            proc: extern struct {
                pid: pid_t,
                pdata: extern union {
                    kill: extern struct {
                        uid: uid_t,
                        value: sigval_t,
                    },
                    cld: extern struct {
                        utime: clock_t,
                        status: c_int,
                        stime: clock_t,
                    },
                },
                contract: solaris.ctid_t,
                zone: solaris.zoneid_t,
            },
            fault: extern struct {
                addr: *allowzero anyopaque,
                trapno: c_int,
                pc: ?*anyopaque,
            },
            file: extern struct {
                // fd not currently available for SIGPOLL.
                fd: c_int,
                band: c_long,
            },
            prof: extern struct {
                addr: ?*anyopaque,
                timestamp: timespec,
                syscall: c_short,
                sysarg: u8,
                fault: u8,
                args: [8]c_long,
                state: [10]c_int,
            },
            rctl: extern struct {
                entity: i32,
            },
            __pad: [256 - 4 * @sizeOf(c_int)]u8,
        } align(@sizeOf(usize)),

        comptime {
            assert(@sizeOf(@This()) == 256);
            assert(@alignOf(@This()) == @sizeOf(usize));
        }
    },
    .netbsd => extern union {
        pad: [128]u8,
        info: netbsd._ksiginfo,
    },
    .dragonfly => extern struct {
        signo: c_int,
        errno: c_int,
        code: c_int,
        pid: c_int,
        uid: uid_t,
        status: c_int,
        addr: *allowzero anyopaque,
        value: sigval,
        band: c_long,
        __spare__: [7]c_int,
    },
    .haiku => extern struct {
        signo: i32,
        code: i32,
        errno: i32,

        pid: pid_t,
        uid: uid_t,
        addr: *allowzero anyopaque,
    },
    .openbsd => extern struct {
        signo: c_int,
        code: c_int,
        errno: c_int,
        data: extern union {
            proc: extern struct {
                pid: pid_t,
                pdata: extern union {
                    kill: extern struct {
                        uid: uid_t,
                        value: sigval,
                    },
                    cld: extern struct {
                        utime: clock_t,
                        stime: clock_t,
                        status: c_int,
                    },
                },
            },
            fault: extern struct {
                addr: *allowzero anyopaque,
                trapno: c_int,
            },
            __pad: [128 - 3 * @sizeOf(c_int)]u8,
        },

        comptime {
            if (@sizeOf(usize) == 4)
                assert(@sizeOf(@This()) == 128)
            else
                // Take into account the padding between errno and data fields.
                assert(@sizeOf(@This()) == 136);
        }
    },
    // https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/signal.h#L27-L37
    .serenity => extern struct {
        signo: c_int,
        code: c_int,
        errno: c_int,
        pid: pid_t,
        uid: uid_t,
        addr: ?*anyopaque,
        status: c_int,
        band: c_int,
        value: sigval,
    },
    else => void,
};
pub const sigset_t = switch (native_os) {
    .linux => linux.sigset_t,
    .emscripten => emscripten.sigset_t,
    // https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/signal.h#L19
    .openbsd, .macos, .ios, .tvos, .watchos, .visionos, .serenity => u32,
    .dragonfly, .netbsd, .solaris, .illumos, .freebsd => extern struct {
        __bits: [SIG.WORDS]u32,
    },
    .haiku => u64,
    else => u0,
};
pub const empty_sigset: sigset_t = switch (native_os) {
    .linux => linux.empty_sigset,
    .emscripten => emscripten.empty_sigset,
    .dragonfly, .netbsd, .solaris, .illumos, .freebsd => .{ .__bits = [_]u32{0} ** SIG.WORDS },
    else => 0,
};
pub const filled_sigset = switch (native_os) {
    .linux => linux.filled_sigset,
    .haiku => ~@as(sigset_t, 0),
    else => 0,
};
pub const sigval = switch (native_os) {
    .linux => linux.sigval,
    // https://github.com/SerenityOS/serenity/blob/ec492a1a0819e6239ea44156825c4ee7234ca3db/Kernel/API/POSIX/signal.h#L22-L25
    .openbsd, .dragonfly, .freebsd, .serenity => extern union {
        int: c_int,
        ptr: ?*anyopaque,
    },
    else => void,
};

pub const addrinfo = if (builtin.abi.isAndroid()) extern struct {
    flags: AI,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: socklen_t,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,
} else switch (native_os) {
    .linux, .emscripten => linux.addrinfo,
    .windows => ws2_32.addrinfo,
    .freebsd, .macos, .ios, .tvos, .watchos, .visionos => extern struct {
        flags: AI,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: socklen_t,
        canonname: ?[*:0]u8,
        addr: ?*sockaddr,
        next: ?*addrinfo,
    },
    .solaris, .illumos => extern struct {
        flags: AI,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: socklen_t,
        canonname: ?[*:0]u8,
        addr: ?*sockaddr,
        next: ?*addrinfo,
    },
    .netbsd => extern struct {
        flags: AI,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: socklen_t,
        canonname: ?[*:0]u8,
        addr: ?*sockaddr,
        next: ?*addrinfo,
    },
    .dragonfly => extern struct {
        flags: AI,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: socklen_t,
        canonname: ?[*:0]u8,
        addr: ?*sockaddr,
        next: ?*addrinfo,
    },
    .haiku => extern struct {
        flags: AI,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: socklen_t,
        canonname: ?[*:0]u8,
        addr: ?*sockaddr,
        next: ?*addrinfo,
    },
    // https://github.com/SerenityOS/serenity/blob/d510d2aeb2facbd8f6c383d70fd1b033e1fee5dd/Userland/Libraries/LibC/netdb.h#L66-L75
    .openbsd, .serenity => extern struct {
        flags: AI,
        family: c_int,
        socktype: c_int,
        protocol: c_int,
        addrlen: socklen_t,
        addr: ?*sockaddr,
        canonname: ?[*:0]u8,
        next: ?*addrinfo,
    },
    else => void,
};
pub const sockaddr = switch (native_os) {
    .linux, .emscripten => linux.sockaddr,
    .windows => ws2_32.sockaddr,
    .macos, .ios, .tvos, .watchos, .visionos => extern struct {
        len: u8,
        family: sa_family_t,
        data: [14]u8,

        pub const SS_MAXSIZE = 128;
        pub const storage = extern struct {
            len: u8 align(8),
            family: sa_family_t,
            padding: [126]u8 = undefined,

            comptime {
                assert(@sizeOf(storage) == SS_MAXSIZE);
                assert(@alignOf(storage) == 8);
            }
        };
        pub const in = extern struct {
            len: u8 = @sizeOf(in),
            family: sa_family_t = AF.INET,
            port: in_port_t,
            addr: u32,
            zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        pub const in6 = extern struct {
            len: u8 = @sizeOf(in6),
            family: sa_family_t = AF.INET6,
            port: in_port_t,
            flowinfo: u32,
            addr: [16]u8,
            scope_id: u32,
        };

        /// UNIX domain socket
        pub const un = extern struct {
            len: u8 = @sizeOf(un),
            family: sa_family_t = AF.UNIX,
            path: [104]u8,
        };
    },
    .freebsd => extern struct {
        /// total length
        len: u8,
        /// address family
        family: sa_family_t,
        /// actually longer; address value
        data: [14]u8,

        pub const SS_MAXSIZE = 128;
        pub const storage = extern struct {
            len: u8 align(8),
            family: sa_family_t,
            padding: [126]u8 = undefined,

            comptime {
                assert(@sizeOf(storage) == SS_MAXSIZE);
                assert(@alignOf(storage) == 8);
            }
        };

        pub const in = extern struct {
            len: u8 = @sizeOf(in),
            family: sa_family_t = AF.INET,
            port: in_port_t,
            addr: u32,
            zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };

        pub const in6 = extern struct {
            len: u8 = @sizeOf(in6),
            family: sa_family_t = AF.INET6,
            port: in_port_t,
            flowinfo: u32,
            addr: [16]u8,
            scope_id: u32,
        };

        pub const un = extern struct {
            len: u8 = @sizeOf(un),
            family: sa_family_t = AF.UNIX,
            path: [104]u8,
        };
    },
    .solaris, .illumos => extern struct {
        /// address family
        family: sa_family_t,

        /// actually longer; address value
        data: [14]u8,

        pub const SS_MAXSIZE = 256;
        pub const storage = extern struct {
            family: sa_family_t align(8),
            padding: [254]u8 = undefined,

            comptime {
                assert(@sizeOf(storage) == SS_MAXSIZE);
                assert(@alignOf(storage) == 8);
            }
        };

        pub const in = extern struct {
            family: sa_family_t = AF.INET,
            port: in_port_t,
            addr: u32,
            zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };

        pub const in6 = extern struct {
            family: sa_family_t = AF.INET6,
            port: in_port_t,
            flowinfo: u32,
            addr: [16]u8,
            scope_id: u32,
            __src_id: u32 = 0,
        };

        /// Definitions for UNIX IPC domain.
        pub const un = extern struct {
            family: sa_family_t = AF.UNIX,
            path: [108]u8,
        };
    },
    .netbsd => extern struct {
        /// total length
        len: u8,
        /// address family
        family: sa_family_t,
        /// actually longer; address value
        data: [14]u8,

        pub const SS_MAXSIZE = 128;
        pub const storage = extern struct {
            len: u8 align(8),
            family: sa_family_t,
            padding: [126]u8 = undefined,

            comptime {
                assert(@sizeOf(storage) == SS_MAXSIZE);
                assert(@alignOf(storage) == 8);
            }
        };

        pub const in = extern struct {
         ```
