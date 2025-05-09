```
ion_info_t = darwin.vm_region_info_t;
pub const vm_region_recurse_info_t = darwin.vm_region_recurse_info_t;
pub const vm_region_submap_info_64 = darwin.vm_region_submap_info_64;
pub const vm_region_submap_short_info_64 = darwin.vm_region_submap_short_info_64;
pub const vm_region_top_info = darwin.vm_region_top_info;

pub const caddr_t = darwin.caddr_t;
pub const exception_behavior_array_t = darwin.exception_behavior_array_t;
pub const exception_behavior_t = darwin.exception_behavior_t;
pub const exception_data_t = darwin.exception_data_t;
pub const exception_data_type_t = darwin.exception_data_type_t;
pub const exception_flavor_array_t = darwin.exception_flavor_array_t;
pub const exception_handler_array_t = darwin.exception_handler_array_t;
pub const exception_handler_t = darwin.exception_handler_t;
pub const exception_mask_array_t = darwin.exception_mask_array_t;
pub const exception_mask_t = darwin.exception_mask_t;
pub const exception_port_array_t = darwin.exception_port_array_t;
pub const exception_port_t = darwin.exception_port_t;
pub const mach_exception_data_t = darwin.mach_exception_data_t;
pub const mach_exception_data_type_t = darwin.mach_exception_data_type_t;
pub const mach_msg_bits_t = darwin.mach_msg_bits_t;
pub const mach_msg_id_t = darwin.mach_msg_id_t;
pub const mach_msg_option_t = darwin.mach_msg_option_t;
pub const mach_msg_size_t = darwin.mach_msg_size_t;
pub const mach_msg_timeout_t = darwin.mach_msg_timeout_t;
pub const mach_msg_type_name_t = darwin.mach_msg_type_name_t;
pub const mach_port_right_t = darwin.mach_port_right_t;
pub const memory_object_offset_t = darwin.memory_object_offset_t;
pub const policy_t = darwin.policy_t;
pub const task_policy_flavor_t = darwin.task_policy_flavor_t;
pub const task_policy_t = darwin.task_policy_t;
pub const task_t = darwin.task_t;
pub const thread_act_t = darwin.thread_act_t;
pub const thread_flavor_t = darwin.thread_flavor_t;
pub const thread_port_t = darwin.thread_port_t;
pub const thread_state_flavor_t = darwin.thread_state_flavor_t;
pub const thread_state_t = darwin.thread_state_t;
pub const thread_t = darwin.thread_t;
pub const time_value_t = darwin.time_value_t;
pub const vm32_object_id_t = darwin.vm32_object_id_t;
pub const vm_behavior_t = darwin.vm_behavior_t;
pub const vm_inherit_t = darwin.vm_inherit_t;
pub const vm_map_read_t = darwin.vm_map_read_t;
pub const vm_object_id_t = darwin.vm_object_id_t;
pub const vm_region_flavor_t = darwin.vm_region_flavor_t;

pub const _ksiginfo = netbsd._ksiginfo;
pub const _lwp_self = netbsd._lwp_self;
pub const lwpid_t = netbsd.lwpid_t;

pub const lwp_gettid = dragonfly.lwp_gettid;
pub const umtx_sleep = dragonfly.umtx_sleep;
pub const umtx_wakeup = dragonfly.umtx_wakeup;

pub const PERF_EVENT = serenity.PERF_EVENT;
pub const disown = serenity.disown;
pub const profiling_enable = serenity.profiling_enable;
pub const profiling_disable = serenity.profiling_disable;
pub const profiling_free_buffer = serenity.profiling_free_buffer;
pub const futex_wait = serenity.futex_wait;
pub const futex_wake = serenity.futex_wake;
pub const purge = serenity.purge;
pub const perf_event = serenity.perf_event;
pub const perf_register_string = serenity.perf_register_string;
pub const get_stack_bounds = serenity.get_stack_bounds;
pub const anon_create = serenity.anon_create;
pub const serenity_readlink = serenity.serenity_readlink;
pub const serenity_open = serenity.serenity_open;
pub const getkeymap = serenity.getkeymap;
pub const setkeymap = serenity.setkeymap;
pub const internet_checksum = serenity.internet_checksum;

/// External definitions shared by two or more operating systems.
const private = struct {
    extern "c" fn close(fd: fd_t) c_int;
    extern "c" fn clock_getres(clk_id: clockid_t, tp: *timespec) c_int;
    extern "c" fn clock_gettime(clk_id: clockid_t, tp: *timespec) c_int;
    extern "c" fn copy_file_range(fd_in: fd_t, off_in: ?*i64, fd_out: fd_t, off_out: ?*i64, len: usize, flags: c_uint) isize;
    extern "c" fn flock(fd: fd_t, operation: c_int) c_int;
    extern "c" fn fork() c_int;
    extern "c" fn fstat(fd: fd_t, buf: *Stat) c_int;
    extern "c" fn fstatat(dirfd: fd_t, path: [*:0]const u8, buf: *Stat, flag: u32) c_int;
    extern "c" fn getdirentries(fd: fd_t, buf_ptr: [*]u8, nbytes: usize, basep: *i64) isize;
    extern "c" fn getdents(fd: c_int, buf_ptr: [*]u8, nbytes: usize) switch (native_os) {
        .freebsd => isize,
        .solaris, .illumos => usize,
        else => c_int,
    };
    extern "c" fn getrusage(who: c_int, usage: *rusage) c_int;
    extern "c" fn gettimeofday(noalias tv: ?*timeval, noalias tz: ?*timezone) c_int;
    extern "c" fn msync(addr: *align(page_size) const anyopaque, len: usize, flags: c_int) c_int;
    extern "c" fn nanosleep(rqtp: *const timespec, rmtp: ?*timespec) c_int;
    extern "c" fn pipe2(fds: *[2]fd_t, flags: O) c_int;
    extern "c" fn readdir(dir: *DIR) ?*dirent;
    extern "c" fn realpath(noalias file_name: [*:0]const u8, noalias resolved_name: [*]u8) ?[*:0]u8;
    extern "c" fn sched_yield() c_int;
    extern "c" fn sendfile(out_fd: fd_t, in_fd: fd_t, offset: ?*off_t, count: usize) isize;
    extern "c" fn sigaction(sig: c_int, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) c_int;
    extern "c" fn sigfillset(set: ?*sigset_t) void;
    extern "c" fn sigprocmask(how: c_int, noalias set: ?*const sigset_t, noalias oset: ?*sigset_t) c_int;
    extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
    extern "c" fn stat(noalias path: [*:0]const u8, noalias buf: *Stat) c_int;
    extern "c" fn sigaltstack(ss: ?*stack_t, old_ss: ?*stack_t) c_int;
    extern "c" fn sysconf(sc: c_int) c_long;

    extern "c" fn pthread_setname_np(thread: pthread_t, name: [*:0]const u8) c_int;
    extern "c" fn getcontext(ucp: *ucontext_t) c_int;

    extern "c" fn getrandom(buf_ptr: [*]u8, buf_len: usize, flags: c_uint) isize;
    extern "c" fn getentropy(buffer: [*]u8, size: usize) c_int;
    extern "c" fn arc4random_buf(buf: [*]u8, len: usize) void;

    extern "c" fn _msize(memblock: ?*anyopaque) usize;
    extern "c" fn malloc_size(?*const anyopaque) usize;
    extern "c" fn malloc_usable_size(?*const anyopaque) usize;
    extern "c" fn posix_memalign(memptr: *?*anyopaque, alignment: usize, size: usize) c_int;

    /// macos modernized symbols.
    /// x86_64 links to $INODE64 suffix for 64-bit support.
    /// Note these are not necessary on aarch64.
    extern "c" fn @"fstat$INODE64"(fd: fd_t, buf: *Stat) c_int;
    extern "c" fn @"fstatat$INODE64"(dirfd: fd_t, path: [*:0]const u8, buf: *Stat, flag: u32) c_int;
    extern "c" fn @"readdir$INODE64"(dir: *DIR) ?*dirent;
    extern "c" fn @"stat$INODE64"(noalias path: [*:0]const u8, noalias buf: *Stat) c_int;

    /// macos modernized symbols.
    extern "c" fn @"realpath$DARWIN_EXTSN"(noalias file_name: [*:0]const u8, noalias resolved_name: [*]u8) ?[*:0]u8;
    extern "c" fn __getdirentries64(fd: fd_t, buf_ptr: [*]u8, buf_len: usize, basep: *i64) isize;

    extern "c" fn pthread_threadid_np(thread: ?pthread_t, thread_id: *u64) c_int;

    /// netbsd modernized symbols.
    extern "c" fn __clock_getres50(clk_id: clockid_t, tp: *timespec) c_int;
    extern "c" fn __clock_gettime50(clk_id: clockid_t, tp: *timespec) c_int;
    extern "c" fn __fstat50(fd: fd_t, buf: *Stat) c_int;
    extern "c" fn __getrusage50(who: c_int, usage: *rusage) c_int;
    extern "c" fn __gettimeofday50(noalias tv: ?*timeval, noalias tz: ?*timezone) c_int;
    extern "c" fn __libc_thr_yield() c_int;
    extern "c" fn __msync13(addr: *align(page_size) const anyopaque, len: usize, flags: c_int) c_int;
    extern "c" fn __nanosleep50(rqtp: *const timespec, rmtp: ?*timespec) c_int;
    extern "c" fn __sigaction14(sig: c_int, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) c_int;
    extern "c" fn __sigfillset14(set: ?*sigset_t) void;
    extern "c" fn __sigprocmask14(how: c_int, noalias set: ?*const sigset_t, noalias oset: ?*sigset_t) c_int;
    extern "c" fn __socket30(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
    extern "c" fn __stat50(path: [*:0]const u8, buf: *Stat) c_int;
    extern "c" fn __getdents30(fd: c_int, buf_ptr: [*]u8, nbytes: usize) c_int;
    extern "c" fn __sigaltstack14(ss: ?*stack_t, old_ss: ?*stack_t) c_int;

    // Don't forget to add another clown when an OS picks yet another unique
    // symbol name for errno location!
    // 🤡🤡🤡🤡🤡🤡

    extern "c" fn ___errno() *c_int;
    extern "c" fn __errno() *c_int;
    extern "c" fn __errno_location() *c_int;
    extern "c" fn __error() *c_int;
    extern "c" fn _errno() *c_int;

    extern threadlocal var errno: c_int;

    fn errnoFromThreadLocal() *c_int {
        return &errno;
    }
};
const std = @import("std");
const builtin = @import("builtin");
const native_arch = builtin.target.cpu.arch;
const assert = std.debug.assert;
const AF = std.c.AF;
const PROT = std.c.PROT;
const fd_t = std.c.fd_t;
const iovec_const = std.posix.iovec_const;
const mode_t = std.c.mode_t;
const off_t = std.c.off_t;
const pid_t = std.c.pid_t;
const pthread_attr_t = std.c.pthread_attr_t;
const sigset_t = std.c.sigset_t;
const timespec = std.c.timespec;
const sf_hdtr = std.c.sf_hdtr;

comptime {
    assert(builtin.os.tag.isDarwin()); // Prevent access of std.c symbols on wrong OS.
}

pub const mach_port_t = c_uint;

pub const THREAD_STATE_NONE = switch (native_arch) {
    .aarch64 => 5,
    .x86_64 => 13,
    else => @compileError("unsupported arch"),
};

pub const EXC = enum(exception_type_t) {
    NULL = 0,
    /// Could not access memory
    BAD_ACCESS = 1,
    /// Instruction failed
    BAD_INSTRUCTION = 2,
    /// Arithmetic exception
    ARITHMETIC = 3,
    /// Emulation instruction
    EMULATION = 4,
    /// Software generated exception
    SOFTWARE = 5,
    /// Trace, breakpoint, etc.
    BREAKPOINT = 6,
    /// System calls.
    SYSCALL = 7,
    /// Mach system calls.
    MACH_SYSCALL = 8,
    /// RPC alert
    RPC_ALERT = 9,
    /// Abnormal process exit
    CRASH = 10,
    /// Hit resource consumption limit
    RESOURCE = 11,
    /// Violated guarded resource protections
    GUARD = 12,
    /// Abnormal process exited to corpse state
    CORPSE_NOTIFY = 13,

    pub const TYPES_COUNT = @typeInfo(EXC).@"enum".fields.len;
    pub const SOFT_SIGNAL = 0x10003;

    pub const MASK = packed struct(u32) {
        _0: u1 = 0,
        BAD_ACCESS: bool = false,
        BAD_INSTRUCTION: bool = false,
        ARITHMETIC: bool = false,
        EMULATION: bool = false,
        SOFTWARE: bool = false,
        BREAKPOINT: bool = false,
        SYSCALL: bool = false,
        MACH_SYSCALL: bool = false,
        RPC_ALERT: bool = false,
        CRASH: bool = false,
        RESOURCE: bool = false,
        GUARD: bool = false,
        CORPSE_NOTIFY: bool = false,
        _14: u18 = 0,

        pub const MACHINE: MASK = @bitCast(@as(u32, 0));

        pub const ALL: MASK = .{
            .BAD_ACCESS = true,
            .BAD_INSTRUCTION = true,
            .ARITHMETIC = true,
            .EMULATION = true,
            .SOFTWARE = true,
            .BREAKPOINT = true,
            .SYSCALL = true,
            .MACH_SYSCALL = true,
            .RPC_ALERT = true,
            .CRASH = true,
            .RESOURCE = true,
            .GUARD = true,
            .CORPSE_NOTIFY = true,
        };
    };
};

pub const EXCEPTION = enum(u32) {
    /// Send a catch_exception_raise message including the identity.
    DEFAULT = 1,
    /// Send a catch_exception_raise_state message including the
    /// thread state.
    STATE = 2,
    /// Send a catch_exception_raise_state_identity message including
    /// the thread identity and state.
    STATE_IDENTITY = 3,
    /// Send a catch_exception_raise_identity_protected message including protected task
    /// and thread identity.
    IDENTITY_PROTECTED = 4,

    _,
};

/// Prefer sending a catch_exception_raice_backtrace message, if applicable.
pub const MACH_EXCEPTION_BACKTRACE_PREFERRED = 0x20000000;
/// include additional exception specific errors, not used yet.
pub const MACH_EXCEPTION_ERRORS = 0x40000000;
/// Send 64-bit code and subcode in the exception header */
pub const MACH_EXCEPTION_CODES = 0x80000000;

pub const MACH_EXCEPTION_MASK = MACH_EXCEPTION_CODES |
    MACH_EXCEPTION_ERRORS |
    MACH_EXCEPTION_BACKTRACE_PREFERRED;

pub const TASK_NULL: task_t = 0;
pub const THREAD_NULL: thread_t = 0;
pub const MACH_PORT_NULL: mach_port_t = 0;
pub const MACH_MSG_TIMEOUT_NONE: mach_msg_timeout_t = 0;

pub const MACH_MSG_OPTION_NONE = 0x00000000;

pub const MACH_SEND_MSG = 0x00000001;
pub const MACH_RCV_MSG = 0x00000002;

pub const MACH_RCV_LARGE = 0x00000004;
pub const MACH_RCV_LARGE_IDENTITY = 0x00000008;

pub const MACH_SEND_TIMEOUT = 0x00000010;
pub const MACH_SEND_OVERRIDE = 0x00000020;
pub const MACH_SEND_INTERRUPT = 0x00000040;
pub const MACH_SEND_NOTIFY = 0x00000080;
pub const MACH_SEND_ALWAYS = 0x00010000;
pub const MACH_SEND_FILTER_NONFATAL = 0x00010000;
pub const MACH_SEND_TRAILER = 0x00020000;
pub const MACH_SEND_NOIMPORTANCE = 0x00040000;
pub const MACH_SEND_NODENAP = MACH_SEND_NOIMPORTANCE;
pub const MACH_SEND_IMPORTANCE = 0x00080000;
pub const MACH_SEND_SYNC_OVERRIDE = 0x00100000;
pub const MACH_SEND_PROPAGATE_QOS = 0x00200000;
pub const MACH_SEND_SYNC_USE_THRPRI = MACH_SEND_PROPAGATE_QOS;
pub const MACH_SEND_KERNEL = 0x00400000;
pub const MACH_SEND_SYNC_BOOTSTRAP_CHECKIN = 0x00800000;

pub const MACH_RCV_TIMEOUT = 0x00000100;
pub const MACH_RCV_NOTIFY = 0x00000000;
pub const MACH_RCV_INTERRUPT = 0x00000400;
pub const MACH_RCV_VOUCHER = 0x00000800;
pub const MACH_RCV_OVERWRITE = 0x00000000;
pub const MACH_RCV_GUARDED_DESC = 0x00001000;
pub const MACH_RCV_SYNC_WAIT = 0x00004000;
pub const MACH_RCV_SYNC_PEEK = 0x00008000;

pub const MACH_MSG_STRICT_REPLY = 0x00000200;

pub const exception_type_t = c_int;

pub const mcontext_t = switch (native_arch) {
    .aarch64 => extern struct {
        es: exception_state,
        ss: thread_state,
        ns: neon_state,
    },
    .x86_64 => extern struct {
        es: exception_state,
        ss: thread_state,
        fs: float_state,
    },
    else => @compileError("unsupported arch"),
};

pub const exception_state = switch (native_arch) {
    .aarch64 => extern struct {
        far: u64, // Virtual Fault Address
        esr: u32, // Exception syndrome
        exception: u32, // Number of arm exception taken
    },
    .x86_64 => extern struct {
        trapno: u16,
        cpu: u16,
        err: u32,
        faultvaddr: u64,
    },
    else => @compileError("unsupported arch"),
};

pub const thread_state = switch (native_arch) {
    .aarch64 => extern struct {
        /// General purpose registers
        regs: [29]u64,
        /// Frame pointer x29
        fp: u64,
        /// Link register x30
        lr: u64,
        /// Stack pointer x31
        sp: u64,
        /// Program counter
        pc: u64,
        /// Current program status register
        cpsr: u32,
        __pad: u32,
    },
    .x86_64 => extern struct {
        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rdi: u64,
        rsi: u64,
        rbp: u64,
        rsp: u64,
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rip: u64,
        rflags: u64,
        cs: u64,
        fs: u64,
        gs: u64,
    },
    else => @compileError("unsupported arch"),
};

pub const neon_state = extern struct {
    q: [32]u128,
    fpsr: u32,
    fpcr: u32,
};

pub const float_state = extern struct {
    reserved: [2]c_int,
    fcw: u16,
    fsw: u16,
    ftw: u8,
    rsrv1: u8,
    fop: u16,
    ip: u32,
    cs: u16,
    rsrv2: u16,
    dp: u32,
    ds: u16,
    rsrv3: u16,
    mxcsr: u32,
    mxcsrmask: u32,
    stmm: [8]stmm_reg,
    xmm: [16]xmm_reg,
    rsrv4: [96]u8,
    reserved1: c_int,
};

pub const stmm_reg = [16]u8;
pub const xmm_reg = [16]u8;

pub extern "c" fn NSVersionOfRunTimeLibrary(library_name: [*:0]const u8) u32;
pub extern "c" fn _NSGetExecutablePath(buf: [*:0]u8, bufsize: *u32) c_int;
pub extern "c" fn _dyld_image_count() u32;
pub extern "c" fn _dyld_get_image_header(image_index: u32) ?*mach_header;
pub extern "c" fn _dyld_get_image_vmaddr_slide(image_index: u32) usize;
pub extern "c" fn _dyld_get_image_name(image_index: u32) [*:0]const u8;

pub const COPYFILE = packed struct(u32) {
    ACL: bool = false,
    STAT: bool = false,
    XATTR: bool = false,
    DATA: bool = false,
    _: u28 = 0,
};

pub const copyfile_state_t = *opaque {};
pub extern "c" fn fcopyfile(from: fd_t, to: fd_t, state: ?copyfile_state_t, flags: COPYFILE) c_int;
pub extern "c" fn __getdirentries64(fd: c_int, buf_ptr: [*]u8, buf_len: usize, basep: *i64) isize;

pub extern "c" fn mach_absolute_time() u64;
pub extern "c" fn mach_continuous_time() u64;
pub extern "c" fn mach_timebase_info(tinfo: ?*mach_timebase_info_data) kern_return_t;

pub extern "c" fn kevent64(
    kq: c_int,
    changelist: [*]const kevent64_s,
    nchanges: c_int,
    eventlist: [*]kevent64_s,
    nevents: c_int,
    flags: c_uint,
    timeout: ?*const timespec,
) c_int;

pub const mach_hdr = if (@sizeOf(usize) == 8) mach_header_64 else mach_header;

pub const mach_header_64 = std.macho.mach_header_64;
pub const mach_header = std.macho.mach_header;

pub extern "c" fn @"close$NOCANCEL"(fd: fd_t) c_int;
pub extern "c" fn mach_host_self() mach_port_t;
pub extern "c" fn clock_get_time(clock_serv: clock_serv_t, cur_time: *mach_timespec_t) kern_return_t;

pub const exception_data_type_t = integer_t;
pub const exception_data_t = ?*mach_exception_data_type_t;
pub const mach_exception_data_type_t = i64;
pub const mach_exception_data_t = ?*mach_exception_data_type_t;
pub const vm_map_t = mach_port_t;
pub const vm_map_read_t = mach_port_t;
pub const vm_region_flavor_t = c_int;
pub const vm_region_info_t = *c_int;
pub const vm_region_recurse_info_t = *c_int;
pub const mach_vm_address_t = usize;
pub const vm_offset_t = usize;
pub const mach_vm_size_t = u64;
pub const mach_msg_bits_t = c_uint;
pub const mach_msg_id_t = integer_t;
pub const mach_msg_type_number_t = natural_t;
pub const mach_msg_type_name_t = c_uint;
pub const mach_msg_option_t = integer_t;
pub const mach_msg_size_t = natural_t;
pub const mach_msg_timeout_t = natural_t;
pub const mach_port_right_t = natural_t;
pub const task_t = mach_port_t;
pub const thread_port_t = task_t;
pub const thread_t = thread_port_t;
pub const exception_mask_t = c_uint;
pub const exception_mask_array_t = [*]exception_mask_t;
pub const exception_handler_t = mach_port_t;
pub const exception_handler_array_t = [*]exception_handler_t;
pub const exception_port_t = exception_handler_t;
pub const exception_port_array_t = exception_handler_array_t;
pub const exception_flavor_array_t = [*]thread_state_flavor_t;
pub const exception_behavior_t = c_uint;
pub const exception_behavior_array_t = [*]exception_behavior_t;
pub const thread_state_flavor_t = c_int;
pub const ipc_space_t = mach_port_t;
pub const ipc_space_port_t = ipc_space_t;

pub const MACH_PORT_RIGHT = enum(mach_port_right_t) {
    SEND = 0,
    RECEIVE = 1,
    SEND_ONCE = 2,
    PORT_SET = 3,
    DEAD_NAME = 4,
    /// Obsolete right
    LABELH = 5,
    /// Right not implemented
    NUMBER = 6,
};

pub const MACH_MSG_TYPE = enum(mach_msg_type_name_t) {
    /// Must hold receive right
    MOVE_RECEIVE = 16,
    /// Must hold send right(s)
    MOVE_SEND = 17,
    /// Must hold sendonce right
    MOVE_SEND_ONCE = 18,
    /// Must hold send right(s)
    COPY_SEND = 19,
    /// Must hold receive right
    MAKE_SEND = 20,
    /// Must hold receive right
    MAKE_SEND_ONCE = 21,
    /// NOT VALID
    COPY_RECEIVE = 22,
    /// Must hold receive right
    DISPOSE_RECEIVE = 24,
    /// Must hold send right(s)
    DISPOSE_SEND = 25,
    /// Must hold sendonce right
    DISPOSE_SEND_ONCE = 26,
};

extern "c" var mach_task_self_: mach_port_t;
pub fn mach_task_self() callconv(.c) mach_port_t {
    return mach_task_self_;
}

pub extern "c" fn mach_msg(
    msg: ?*mach_msg_header_t,
    option: mach_msg_option_t,
    send_size: mach_msg_size_t,
    rcv_size: mach_msg_size_t,
    rcv_name: mach_port_name_t,
    timeout: mach_msg_timeout_t,
    notify: mach_port_name_t,
) kern_return_t;

pub const mach_msg_header_t = extern struct {
    msgh_bits: mach_msg_bits_t,
    msgh_size: mach_msg_size_t,
    msgh_remote_port: mach_port_t,
    msgh_local_port: mach_port_t,
    msgh_voucher_port: mach_port_name_t,
    msgh_id: mach_msg_id_t,
};

pub extern "c" fn task_get_exception_ports(
    task: task_t,
    exception_mask: exception_mask_t,
    masks: exception_mask_array_t,
    masks_cnt: *mach_msg_type_number_t,
    old_handlers: exception_handler_array_t,
    old_behaviors: exception_behavior_array_t,
    old_flavors: exception_flavor_array_t,
) kern_return_t;
pub extern "c" fn task_set_exception_ports(
    task: task_t,
    exception_mask: exception_mask_t,
    new_port: mach_port_t,
    behavior: exception_behavior_t,
    new_flavor: thread_state_flavor_t,
) kern_return_t;

pub const task_read_t = mach_port_t;

pub extern "c" fn task_resume(target_task: task_read_t) kern_return_t;
pub extern "c" fn task_suspend(target_task: task_read_t) kern_return_t;

pub extern "c" fn task_for_pid(target_tport: mach_port_name_t, pid: pid_t, t: *mach_port_name_t) kern_return_t;
pub extern "c" fn pid_for_task(target_tport: mach_port_name_t, pid: *pid_t) kern_return_t;
pub extern "c" fn mach_vm_read(
    target_task: vm_map_read_t,
    address: mach_vm_address_t,
    size: mach_vm_size_t,
    data: *vm_offset_t,
    data_cnt: *mach_msg_type_number_t,
) kern_return_t;
pub extern "c" fn mach_vm_write(
    target_task: vm_map_t,
    address: mach_vm_address_t,
    data: vm_offset_t,
    data_cnt: mach_msg_type_number_t,
) kern_return_t;
pub extern "c" fn mach_vm_region(
    target_task: vm_map_t,
    address: *mach_vm_address_t,
    size: *mach_vm_size_t,
    flavor: vm_region_flavor_t,
    info: vm_region_info_t,
    info_cnt: *mach_msg_type_number_t,
    object_name: *mach_port_t,
) kern_return_t;
pub extern "c" fn mach_vm_region_recurse(
    target_task: vm_map_t,
    address: *mach_vm_address_t,
    size: *mach_vm_size_t,
    nesting_depth: *natural_t,
    info: vm_region_recurse_info_t,
    info_cnt: *mach_msg_type_number_t,
) kern_return_t;

pub const vm_inherit_t = u32;
pub const memory_object_offset_t = u64;
pub const vm_behavior_t = i32;
pub const vm32_object_id_t = u32;
pub const vm_object_id_t = u64;

pub const VM = struct {
    pub const INHERIT = struct {
        pub const SHARE: vm_inherit_t = 0;
        pub const COPY: vm_inherit_t = 1;
        pub const NONE: vm_inherit_t = 2;
        pub const DONATE_COPY: vm_inherit_t = 3;
        pub const DEFAULT = COPY;
    };

    pub const BEHAVIOR = struct {
        pub const DEFAULT: vm_behavior_t = 0;
        pub const RANDOM: vm_behavior_t = 1;
        pub const SEQUENTIAL: vm_behavior_t = 2;
        pub const RSEQNTL: vm_behavior_t = 3;
        pub const WILLNEED: vm_behavior_t = 4;
        pub const DONTNEED: vm_behavior_t = 5;
        pub const FREE: vm_behavior_t = 6;
        pub const ZERO_WIRED_PAGES: vm_behavior_t = 7;
        pub const REUSABLE: vm_behavior_t = 8;
        pub const REUSE: vm_behavior_t = 9;
        pub const CAN_REUSE: vm_behavior_t = 10;
        pub const PAGEOUT: vm_behavior_t = 11;
    };

    pub const REGION = struct {
        pub const BASIC_INFO_64 = 9;
        pub const EXTENDED_INFO = 13;
        pub const TOP_INFO = 12;
        pub const SUBMAP_INFO_COUNT_64: mach_msg_type_number_t = @sizeOf(vm_region_submap_info_64) / @sizeOf(natural_t);
        pub const SUBMAP_SHORT_INFO_COUNT_64: mach_msg_type_number_t = @sizeOf(vm_region_submap_short_info_64) / @sizeOf(natural_t);
        pub const BASIC_INFO_COUNT: mach_msg_type_number_t = @sizeOf(vm_region_basic_info_64) / @sizeOf(c_int);
        pub const EXTENDED_INFO_COUNT: mach_msg_type_number_t = @sizeOf(vm_region_extended_info) / @sizeOf(natural_t);
        pub const TOP_INFO_COUNT: mach_msg_type_number_t = @sizeOf(vm_region_top_info) / @sizeOf(natural_t);
    };

    pub fn MAKE_TAG(tag: u8) u32 {
        return @as(u32, tag) << 24;
    }
};

pub const vm_region_basic_info_64 = extern struct {
    protection: vm_prot_t,
    max_protection: vm_prot_t,
    inheritance: vm_inherit_t,
    shared: boolean_t,
    reserved: boolean_t,
    offset: memory_object_offset_t,
    behavior: vm_behavior_t,
    user_wired_count: u16,
};

pub const vm_region_extended_info = extern struct {
    protection: vm_prot_t,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u16,
    external_pager: u8,
    share_mode: u8,
    pages_reusable: u32,
};

pub const vm_region_top_info = extern struct {
    obj_id: u32,
    ref_count: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    share_mode: u8,
};

pub const vm_region_submap_info_64 = extern struct {
    // present across protection
    protection: vm_prot_t,
    // max avail through vm_prot
    max_protection: vm_prot_t,
    // behavior of map/obj on fork
    inheritance: vm_inherit_t,
    // offset into object/map
    offset: memory_object_offset_t,
    // user tag on map entry
    user_tag: u32,
    // only valid for objects
    pages_resident: u32,
    // only for objects
    pages_shared_now_private: u32,
    // only for objects
    pages_swapped_out: u32,
    // only for objects
    pages_dirtied: u32,
    // obj/map mappers, etc.
    ref_count: u32,
    // only for obj
    shadow_depth: u16,
    // only for obj
    external_pager: u8,
    // see enumeration
    share_mode: u8,
    // submap vs obj
    is_submap: boolean_t,
    // access behavior hint
    behavior: vm_behavior_t,
    // obj/map name, not a handle
    object_id: vm32_object_id_t,
    user_wired_count: u16,
    pages_reusable: u32,
    object_id_full: vm_object_id_t,
};

pub const vm_region_submap_short_info_64 = extern struct {
    // present access protection
    protection: vm_prot_t,
    // max avail through vm_prot
    max_protection: vm_prot_t,
    // behavior of map/obj on fork
    inheritance: vm_inherit_t,
    // offset into object/map
    offset: memory_object_offset_t,
    // user tag on map entry
    user_tag: u32,
    // obj/map mappers, etc
    ref_count: u32,
    // only for obj
    shadow_depth: u16,
    // only for obj
    external_pager: u8,
    // see enumeration
    share_mode: u8,
    //  submap vs obj
    is_submap: boolean_t,
    // access behavior hint
    behavior: vm_behavior_t,
    // obj/map name, not a handle
    object_id: vm32_object_id_t,
    user_wired_count: u16,
};

pub const thread_act_t = mach_port_t;
pub const thread_state_t = *natural_t;
pub const mach_port_array_t = [*]mach_port_t;

pub extern "c" fn task_threads(
    target_task: mach_port_t,
    init_port_set: *mach_port_array_t,
    init_port_count: *mach_msg_type_number_t,
) kern_return_t;
pub extern "c" fn thread_get_state(
    thread: thread_act_t,
    flavor: thread_flavor_t,
    state: thread_state_t,
    count: *mach_msg_type_number_t,
) kern_return_t;
pub extern "c" fn thread_set_state(
    thread: thread_act_t,
    flavor: thread_flavor_t,
    new_state: thread_state_t,
    count: mach_msg_type_number_t,
) kern_return_t;
pub extern "c" fn thread_info(
    thread: thread_act_t,
    flavor: thread_flavor_t,
    info: thread_info_t,
    count: *mach_msg_type_number_t,
) kern_return_t;
pub extern "c" fn thread_resume(thread: thread_act_t) kern_return_t;

pub const THREAD_BASIC_INFO = 3;
pub const THREAD_BASIC_INFO_COUNT: mach_msg_type_number_t = @sizeOf(thread_basic_info) / @sizeOf(natural_t);

pub const THREAD_IDENTIFIER_INFO = 4;
pub const THREAD_IDENTIFIER_INFO_COUNT: mach_msg_type_number_t = @sizeOf(thread_identifier_info) / @sizeOf(natural_t);

pub const thread_flavor_t = natural_t;
pub const thread_info_t = *integer_t;
pub const time_value_t = time_value;
pub const task_policy_flavor_t = natural_t;
pub const task_policy_t = *integer_t;
pub const policy_t = c_int;

pub const time_value = extern struct {
    seconds: integer_t,
    microseconds: integer_t,
};

pub const thread_basic_info = extern struct {
    // user run time
    user_time: time_value_t,
    // system run time
    system_time: time_value_t,
    // scaled cpu usage percentage
    cpu_usage: integer_t,
    // scheduling policy in effect
    policy: policy_t,
    // run state
    run_state: integer_t,
    // various flags
    flags: integer_t,
    // suspend count for thread
    suspend_count: integer_t,
    // number of seconds that thread has been sleeping
    sleep_time: integer_t,
};

pub const thread_identifier_info = extern struct {
    /// System-wide unique 64-bit thread id
    thread_id: u64,

    /// Handle to be used by libproc
    thread_handle: u64,

    /// libdispatch queue address
    dispatch_qaddr: u64,
};

pub const MATTR = struct {
    /// Cachability
    pub const CACHE = 1;
    /// Migrability
    pub const MIGRATE = 2;
    /// Replicability
    pub const REPLICATE = 4;
    /// (Generic) turn attribute off
    pub const VAL_OFF = 0;
    /// (Generic) turn attribute on
    pub const VAL_ON = 1;
    /// (Generic) return current value
    pub const VAL_GET = 2;
    /// Flush from all caches
    pub const VAL_CACHE_FLUSH = 6;
    /// Flush from data caches
    pub const VAL_DCACHE_FLUSH = 7;
    /// Flush from instruction caches
    pub const VAL_ICACHE_FLUSH = 8;
    /// Sync I+D caches
    pub const VAL_CACHE_SYNC = 9;
    /// Get page info (stats)
    pub const VAL_GET_INFO = 10;
};

pub const TASK_VM_INFO = 22;
pub const TASK_VM_INFO_COUNT: mach_msg_type_number_t = @sizeOf(task_vm_info_data_t) / @sizeOf(natural_t);

pub const task_vm_info = extern struct {
    // virtual memory size (bytes)
    virtual_size: mach_vm_size_t,
    // number of memory regions
    region_count: integer_t,
    page_size: integer_t,
    // resident memory size (bytes)
    resident_size: mach_vm_size_t,
    // peak resident size (bytes)
    resident_size_peak: mach_vm_size_t,

    device: mach_vm_size_t,
    device_peak: mach_vm_size_t,
    internal: mach_vm_size_t,
    internal_peak: mach_vm_size_t,
    external: mach_vm_size_t,
    external_peak: mach_vm_size_t,
    reusable: mach_vm_size_t,
    reusable_peak: mach_vm_size_t,
    purgeable_volatile_pmap: mach_vm_size_t,
    purgeable_volatile_resident: mach_vm_size_t,
    purgeable_volatile_virtual: mach_vm_size_t,
    compressed: mach_vm_size_t,
    compressed_peak: mach_vm_size_t,
    compressed_lifetime: mach_vm_size_t,

    // added for rev1
    phys_footprint: mach_vm_size_t,

    // added for rev2
    min_address: mach_vm_address_t,
    max_address: mach_vm_address_t,

    // added for rev3
    ledger_phys_footprint_peak: i64,
    ledger_purgeable_nonvolatile: i64,
    ledger_purgeable_novolatile_compressed: i64,
    ledger_purgeable_volatile: i64,
    ledger_purgeable_volatile_compressed: i64,
    ledger_tag_network_nonvolatile: i64,
    ledger_tag_network_nonvolatile_compressed: i64,
    ledger_tag_network_volatile: i64,
    ledger_tag_network_volatile_compressed: i64,
    ledger_tag_media_footprint: i64,
    ledger_tag_media_footprint_compressed: i64,
    ledger_tag_media_nofootprint: i64,
    ledger_tag_media_nofootprint_compressed: i64,
    ledger_tag_graphics_footprint: i64,
    ledger_tag_graphics_footprint_compressed: i64,
    ledger_tag_graphics_nofootprint: i64,
    ledger_tag_graphics_nofootprint_compressed: i64,
    ledger_tag_neural_footprint: i64,
    ledger_tag_neural_footprint_compressed: i64,
    ledger_tag_neural_nofootprint: i64,
    ledger_tag_neural_nofootprint_compressed: i64,

    // added for rev4
    limit_bytes_remaining: u64,

    // added for rev5
    decompressions: integer_t,
};

pub const task_vm_info_data_t = task_vm_info;

pub const vm_prot_t = c_int;
pub const boolean_t = c_int;

pub extern "c" fn mach_vm_protect(
    target_task: vm_map_t,
    address: mach_vm_address_t,
    size: mach_vm_size_t,
    set_maximum: boolean_t,
    new_protection: vm_prot_t,
) kern_return_t;

pub extern "c" fn mach_port_allocate(
    task: ipc_space_t,
    right: mach_port_right_t,
    name: *mach_port_name_t,
) kern_return_t;
pub extern "c" fn mach_port_deallocate(task: ipc_space_t, name: mach_port_name_t) kern_return_t;
pub extern "c" fn mach_port_insert_right(
    task: ipc_space_t,
    name: mach_port_name_t,
    poly: mach_port_t,
    poly_poly: mach_msg_type_name_t,
) kern_return_t;

pub extern "c" fn task_info(
    target_task: task_name_t,
    flavor: task_flavor_t,
    task_info_out: task_info_t,
    task_info_outCnt: *mach_msg_type_number_t,
) kern_return_t;

pub const mach_task_basic_info = extern struct {
    /// Virtual memory size (bytes)
    virtual_size: mach_vm_size_t,
    /// Resident memory size (bytes)
    resident_size: mach_vm_size_t,
    /// Total user run time for terminated threads
    user_time: time_value_t,
    /// Total system run time for terminated threads
    system_time: time_value_t,
    /// Default policy for new threads
    policy: policy_t,
    /// Suspend count for task
    suspend_count: mach_vm_size_t,
};

pub const MACH_TASK_BASIC_INFO = 20;
pub const MACH_TASK_BASIC_INFO_COUNT: mach_msg_type_number_t = @sizeOf(mach_task_basic_info) / @sizeOf(natural_t);

pub extern "c" fn _host_page_size(task: mach_port_t, size: *vm_size_t) kern_return_t;
pub extern "c" fn vm_deallocate(target_task: vm_map_t, address: vm_address_t, size: vm_size_t) kern_return_t;
pub extern "c" fn vm_machine_attribute(
    target_task: vm_map_t,
    address: vm_address_t,
    size: vm_size_t,
    attribute: vm_machine_attribute_t,
    value: *vm_machine_attribute_val_t,
) kern_return_t;

pub extern "c" fn sendfile(
    in_fd: fd_t,
    out_fd: fd_t,
    offset: off_t,
    len: *off_t,
    sf_hdtr: ?*sf_hdtr,
    flags: u32,
) c_int;

pub fn sigaddset(set: *sigset_t, signo: u5) void {
    set.* |= @as(u32, 1) << (signo - 1);
}

pub const qos_class_t = enum(c_uint) {
    /// highest priority QOS class for critical tasks
    QOS_CLASS_USER_INTERACTIVE = 0x21,
    /// slightly more moderate priority QOS class
    QOS_CLASS_USER_INITIATED = 0x19,
    /// default QOS class when none is set
    QOS_CLASS_DEFAULT = 0x15,
    /// more energy efficient QOS class than default
    QOS_CLASS_UTILITY = 0x11,
    /// QOS class more appropriate for background tasks
    QOS_CLASS_BACKGROUND = 0x09,
    /// QOS class as a return value
    QOS_CLASS_UNSPECIFIED = 0x00,
};

// Grand Central Dispatch is exposed by libSystem.
pub extern "c" fn dispatch_release(object: *anyopaque) void;

pub const dispatch_semaphore_t = *opaque {};
pub extern "c" fn dispatch_semaphore_create(value: isize) ?dispatch_semaphore_t;
pub extern "c" fn dispatch_semaphore_wait(dsema: dispatch_semaphore_t, timeout: dispatch_time_t) isize;
pub extern "c" fn dispatch_semaphore_signal(dsema: dispatch_semaphore_t) isize;

pub const dispatch_time_t = u64;
pub const DISPATCH_TIME_NOW = @as(dispatch_time_t, 0);
pub const DISPATCH_TIME_FOREVER = ~@as(dispatch_time_t, 0);
pub extern "c" fn dispatch_time(when: dispatch_time_t, delta: i64) dispatch_time_t;

const dispatch_once_t = usize;
const dispatch_function_t = fn (?*anyopaque) callconv(.c) void;
pub extern fn dispatch_once_f(
    predicate: *dispatch_once_t,
    context: ?*anyopaque,
    function: dispatch_function_t,
) void;

/// Undocumented futex-like API available on darwin 16+
/// (macOS 10.12+, iOS 10.0+, tvOS 10.0+, watchOS 3.0+, catalyst 13.0+).
///
/// [ulock.h]: https://github.com/apple/darwin-xnu/blob/master/bsd/sys/ulock.h
/// [sys_ulock.c]: https://github.com/apple/darwin-xnu/blob/master/bsd/kern/sys_ulock.c
pub const UL = packed struct(u32) {
    op: Op,
    WAKE_ALL: bool = false,
    WAKE_THREAD: bool = false,
    _10: u6 = 0,
    WAIT_WORKQ_DATA_CONTENTION: bool = false,
    WAIT_CANCEL_POINT: bool = false,
    WAIT_ADAPTIVE_SPIN: bool = false,
    _19: u5 = 0,
    NO_ERRNO: bool = false,
    _: u7 = 0,

    pub const Op = enum(u8) {
        COMPARE_AND_WAIT = 1,
        UNFAIR_LOCK = 2,
        COMPARE_AND_WAIT_SHARED = 3,
        UNFAIR_LOCK64_SHARED = 4,
        COMPARE_AND_WAIT64 = 5,
        COMPARE_AND_WAIT64_SHARED = 6,
    };
};

pub extern "c" fn __ulock_wait2(op: UL, addr: ?*const anyopaque, val: u64, timeout_ns: u64, val2: u64) c_int;
pub extern "c" fn __ulock_wait(op: UL, addr: ?*const anyopaque, val: u64, timeout_us: u32) c_int;
pub extern "c" fn __ulock_wake(op: UL, addr: ?*const anyopaque, val: u64) c_int;

pub const os_unfair_lock_t = *os_unfair_lock;
pub const os_unfair_lock = extern struct {
    _os_unfair_lock_opaque: u32 = 0,
};

pub extern "c" fn os_unfair_lock_lock(o: os_unfair_lock_t) void;
pub extern "c" fn os_unfair_lock_unlock(o: os_unfair_lock_t) void;
pub extern "c" fn os_unfair_lock_trylock(o: os_unfair_lock_t) bool;
pub extern "c" fn os_unfair_lock_assert_owner(o: os_unfair_lock_t) void;
pub extern "c" fn os_unfair_lock_assert_not_owner(o: os_unfair_lock_t) void;

pub const os_signpost_id_t = u64;

pub const OS_SIGNPOST_ID_NULL: os_signpost_id_t = 0;
pub const OS_SIGNPOST_ID_INVALID: os_signpost_id_t = !0;
pub const OS_SIGNPOST_ID_EXCLUSIVE: os_signpost_id_t = 0xeeeeb0b5b2b2eeee;

pub const os_log_t = *opaque {};
pub const os_log_type_t = enum(u8) {
    /// default messages always captures
    OS_LOG_TYPE_DEFAULT = 0x00,
    /// messages with additional infos
    OS_LOG_TYPE_INFO = 0x01,
    /// debug messages
    OS_LOG_TYPE_DEBUG = 0x02,
    /// error messages
    OS_LOG_TYPE_ERROR = 0x10,
    /// unexpected conditions messages
    OS_LOG_TYPE_FAULT = 0x11,
};

pub const OS_LOG_CATEGORY_POINTS_OF_INTEREST: *const u8 = "PointsOfInterest";
pub const OS_LOG_CATEGORY_DYNAMIC_TRACING: *const u8 = "DynamicTracing";
pub const OS_LOG_CATEGORY_DYNAMIC_STACK_TRACING: *const u8 = "DynamicStackTracing";

pub extern "c" fn os_log_create(subsystem: [*]const u8, category: [*]const u8) os_log_t;
pub extern "c" fn os_log_type_enabled(log: os_log_t, tpe: os_log_type_t) bool;
pub extern "c" fn os_signpost_id_generate(log: os_log_t) os_signpost_id_t;
pub extern "c" fn os_signpost_interval_begin(log: os_log_t, signpos: os_signpost_id_t, func: [*]const u8, ...) void;
pub extern "c" fn os_signpost_interval_end(log: os_log_t, signpos: os_signpost_id_t, func: [*]const u8, ...) void;
pub extern "c" fn os_signpost_id_make_with_pointer(log: os_log_t, ptr: ?*anyopaque) os_signpost_id_t;
pub extern "c" fn os_signpost_enabled(log: os_log_t) bool;

pub extern "c" fn pthread_setname_np(name: [*:0]const u8) c_int;
pub extern "c" fn pthread_attr_set_qos_class_np(attr: *pthread_attr_t, qos_class: qos_class_t, relative_priority: c_int) c_int;
pub extern "c" fn pthread_attr_get_qos_class_np(attr: *pthread_attr_t, qos_class: *qos_class_t, relative_priority: *c_int) c_int;
pub extern "c" fn pthread_set_qos_class_self_np(qos_class: qos_class_t, relative_priority: c_int) c_int;
pub extern "c" fn pthread_get_qos_class_np(pthread: std.c.pthread_t, qos_class: *qos_class_t, relative_priority: *c_int) c_int;

pub const mach_timebase_info_data = extern struct {
    numer: u32,
    denom: u32,
};

pub const kevent64_s = extern struct {
    ident: u64,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: i64,
    udata: u64,
    ext: [2]u64,
};

// sys/types.h on macos uses #pragma pack() so these checks are
// to make sure the struct is laid out the same. These values were
// produced from C code using the offsetof macro.
comptime {
    if (builtin.target.os.tag.isDarwin()) {
        assert(@offsetOf(kevent64_s, "ident") == 0);
        assert(@offsetOf(kevent64_s, "filter") == 8);
        assert(@offsetOf(kevent64_s, "flags") == 10);
        assert(@offsetOf(kevent64_s, "fflags") == 12);
        assert(@offsetOf(kevent64_s, "data") == 16);
        assert(@offsetOf(kevent64_s, "udata") == 24);
        assert(@offsetOf(kevent64_s, "ext") == 32);
    }
}

pub const clock_serv_t = mach_port_t;
pub const clock_res_t = c_int;
pub const mach_port_name_t = natural_t;
pub const natural_t = c_uint;
pub const mach_timespec_t = extern struct {
    sec: c_uint,
    nsec: clock_res_t,
};
pub const kern_return_t = c_int;
pub const host_t = mach_port_t;
pub const integer_t = c_int;
pub const task_flavor_t = natural_t;
pub const task_info_t = *integer_t;
pub const task_name_t = mach_port_name_t;
pub const vm_address_t = vm_offset_t;
pub const vm_size_t = mach_vm_size_t;
pub const vm_machine_attribute_t = usize;
pub const vm_machine_attribute_val_t = isize;

pub const CALENDAR_CLOCK = 1;

/// no flag value
pub const KEVENT_FLAG_NONE = 0x000;
/// immediate timeout
pub const KEVENT_FLAG_IMMEDIATE = 0x001;
/// output events only include change
pub const KEVENT_FLAG_ERROR_EVENTS = 0x002;

pub const SYSPROTO_EVENT = 1;
pub const SYSPROTO_CONTROL = 2;

pub const mach_msg_return_t = kern_return_t;

pub fn getMachMsgError(err: mach_msg_return_t) MachMsgE {
    return @as(MachMsgE, @enumFromInt(@as(u32, @truncate(@as(usize, @intCast(err))))));
}

/// All special error code bits defined below.
pub const MACH_MSG_MASK: u32 = 0x3e00;
/// No room in IPC name space for another capability name.
pub const MACH_MSG_IPC_SPACE: u32 = 0x2000;
/// No room in VM address space for out-of-line memory.
pub const MACH_MSG_VM_SPACE: u32 = 0x1000;
/// Kernel resource shortage handling out-of-line memory.
pub const MACH_MSG_IPC_KERNEL: u32 = 0x800;
/// Kernel resource shortage handling an IPC capability.
pub const MACH_MSG_VM_KERNEL: u32 = 0x400;

/// Mach msg return values
pub const MachMsgE = enum(u32) {
    SUCCESS = 0x00000000,

    /// Thread is waiting to send.  (Internal use only.)
    SEND_IN_PROGRESS = 0x10000001,
    /// Bogus in-line data.
    SEND_INVALID_DATA = 0x10000002,
    /// Bogus destination port.
    SEND_INVALID_DEST = 0x10000003,
    ///  Message not sent before timeout expired.
    SEND_TIMED_OUT = 0x10000004,
    ///  Bogus voucher port.
    SEND_INVALID_VOUCHER = 0x10000005,
    ///  Software interrupt.
    SEND_INTERRUPTED = 0x10000007,
    ///  Data doesn't contain a complete message.
    SEND_MSG_TOO_SMALL = 0x10000008,
    ///  Bogus reply port.
    SEND_INVALID_REPLY = 0x10000009,
    ///  Bogus port rights in the message body.
    SEND_INVALID_RIGHT = 0x1000000a,
    ///  Bogus notify port argument.
    SEND_INVALID_NOTIFY = 0x1000000b,
    ///  Invalid out-of-line memory pointer.
    SEND_INVALID_MEMORY = 0x1000000c,
    ///  No message buffer is available.
    SEND_NO_BUFFER = 0x1000000d,
    ///  Send is too large for port
    SEND_TOO_LARGE = 0x1000000e,
    ///  Invalid msg-type specification.
    SEND_INVALID_TYPE = 0x1000000f,
    ///  A field in the header had a bad value.
    SEND_INVALID_HEADER = 0x10000010,
    ///  The trailer to be sent does not match kernel format.
    SEND_INVALID_TRAILER = 0x10000011,
    ///  The sending thread context did not match the context on the dest port
    SEND_INVALID_CONTEXT = 0x10000012,
    ///  compatibility: no longer a returned error
    SEND_INVALID_RT_OOL_SIZE = 0x10000015,
    ///  The destination port doesn't accept ports in body
    SEND_NO_GRANT_DEST = 0x10000016,
    ///  Message send was rejected by message filter
    SEND_MSG_FILTERED = 0x10000017,

    ///  Thread is waiting for receive.  (Internal use only.)
    RCV_IN_PROGRESS = 0x10004001,
    ///  Bogus name for receive port/port-set.
    RCV_INVALID_NAME = 0x10004002,
    ///  Didn't get a message within the timeout value.
    RCV_TIMED_OUT = 0x10004003,
    ///  Message buffer is not large enough for inline data.
    RCV_TOO_LARGE = 0x10004004,
    ///  Software interrupt.
    RCV_INTERRUPTED = 0x10004005,
    ///  compatibility: no longer a returned error
    RCV_PORT_CHANGED = 0x10004006,
    ///  Bogus notify port argument.
    RCV_INVALID_NOTIFY = 0x10004007,
    ///  Bogus message buffer for inline data.
    RCV_INVALID_DATA = 0x10004008,
    ///  Port/set was sent away/died during receive.
    RCV_PORT_DIED = 0x10004009,
    ///  compatibility: no longer a returned error
    RCV_IN_SET = 0x1000400a,
    ///  Error receiving message header.  See special bits.
    RCV_HEADER_ERROR = 0x1000400b,
    ///  Error receiving message body.  See special bits.
    RCV_BODY_ERROR = 0x1000400c,
    ///  Invalid msg-type specification in scatter list.
    RCV_INVALID_TYPE = 0x1000400d,
    ///  Out-of-line overwrite region is not large enough
    RCV_SCATTER_SMALL = 0x1000400e,
    ///  trailer type or number of trailer elements not supported
    RCV_INVALID_TRAILER = 0x1000400f,
    ///  Waiting for receive with timeout. (Internal use only.)
    RCV_IN_PROGRESS_TIMED = 0x10004011,
    ///  invalid reply port used in a STRICT_REPLY message
    RCV_INVALID_REPLY = 0x10004012,
};

pub const FCNTL_FS_SPECIFIC_BASE = 0x00010000;

/// Max open files per process
/// https://opensource.apple.com/source/xnu/xnu-4903.221.2/bsd/sys/syslimits.h.auto.html
pub const OPEN_MAX = 10240;

// CPU families mapping
pub const CPUFAMILY = enum(u32) {
    UNKNOWN = 0,
    POWERPC_G3 = 0xcee41549,
    POWERPC_G4 = 0x77c184ae,
    POWERPC_G5 = 0xed76d8aa,
    INTEL_6_13 = 0xaa33392b,
    INTEL_PENRYN = 0x78ea4fbc,
    INTEL_NEHALEM = 0x6b5a4cd2,
    INTEL_WESTMERE = 0x573b5eec,
    INTEL_SANDYBRIDGE = 0x5490b78c,
    INTEL_IVYBRIDGE = 0x1f65e835,
    INTEL_HASWELL = 0x10b282dc,
    INTEL_BROADWELL = 0x582ed09c,
    INTEL_SKYLAKE = 0x37fc219f,
    INTEL_KABYLAKE = 0x0f817246,
    ARM_9 = 0xe73283ae,
    ARM_11 = 0x8ff620d8,
    ARM_XSCALE = 0x53b005f5,
    ARM_12 = 0xbd1b0ae9,
    ARM_13 = 0x0cc90e64,
    ARM_14 = 0x96077ef1,
    ARM_15 = 0xa8511bca,
    ARM_SWIFT = 0x1e2d6381,
    ARM_CYCLONE = 0x37a09642,
    ARM_TYPHOON = 0x2c91a47e,
    ARM_TWISTER = 0x92fb37c8,
    ARM_HURRICANE = 0x67ceee93,
    ARM_MONSOON_MISTRAL = 0xe81e7ef6,
    ARM_VORTEX_TEMPEST = 0x07d34b9f,
    ARM_LIGHTNING_THUNDER = 0x462504d2,
    ARM_FIRESTORM_ICESTORM = 0x1b588bb3,
    ARM_BLIZZARD_AVALANCHE = 0xda33d83d,
    ARM_EVEREST_SAWTOOTH = 0x8765edea,
    ARM_COLL = 0x2876f5b5,
    ARM_IBIZA = 0xfa33415e,
    ARM_LOBOS = 0x5f4dea93,
    ARM_PALMA = 0x72015832,
    ARM_DONAN = 0x6f5129ac,
    ARM_BRAVA = 0x17d5b93a,
    ARM_TAHITI = 0x75d4acb9,
    ARM_TUPAI = 0x204526d0,
    _,
};

pub const PT = struct {
    pub const TRACE_ME = 0;
    pub const READ_I = 1;
    pub const READ_D = 2;
    pub const READ_U = 3;
    pub const WRITE_I = 4;
    pub const WRITE_D = 5;
    pub const WRITE_U = 6;
    pub const CONTINUE = 7;
    pub const KILL = 8;
    pub const STEP = 9;
    pub const DETACH = 11;
    pub const SIGEXC = 12;
    pub const THUPDATE = 13;
    pub const ATTACHEXC = 14;
    pub const FORCEQUOTA = 30;
    pub const DENY_ATTACH = 31;
};

pub const caddr_t = ?[*]u8;

pub extern "c" fn ptrace(request: c_int, pid: pid_t, addr: caddr_t, data: c_int) c_int;

pub const POSIX_SPAWN = struct {
    pub const RESETIDS = 0x0001;
    pub const SETPGROUP = 0x0002;
    pub const SETSIGDEF = 0x0004;
    pub const SETSIGMASK = 0x0008;
    pub const SETEXEC = 0x0040;
    pub const START_SUSPENDED = 0x0080;
    pub const DISABLE_ASLR = 0x0100;
    pub const SETSID = 0x0400;
    pub const RESLIDE = 0x0800;
    pub const CLOEXEC_DEFAULT = 0x4000;
};

pub const posix_spawnattr_t = *opaque {};
pub const posix_spawn_file_actions_t = *opaque {};
pub extern "c" fn posix_spawnattr_init(attr: *posix_spawnattr_t) c_int;
pub extern "c" fn posix_spawnattr_destroy(attr: *posix_spawnattr_t) c_int;
pub extern "c" fn posix_spawnattr_setflags(attr: *posix_spawnattr_t, flags: c_short) c_int;
pub extern "c" fn posix_spawnattr_getflags(attr: *const posix_spawnattr_t, flags: *c_short) c_int;
pub extern "c" fn posix_spawn_file_actions_init(actions: *posix_spawn_file_actions_t) c_int;
pub extern "c" fn posix_spawn_file_actions_destroy(actions: *posix_spawn_file_actions_t) c_int;
pub extern "c" fn posix_spawn_file_actions_addclose(actions: *posix_spawn_file_actions_t, filedes: fd_t) c_int;
pub extern "c" fn posix_spawn_file_actions_addopen(
    actions: *posix_spawn_file_actions_t,
    filedes: fd_t,
    path: [*:0]const u8,
    oflag: c_int,
    mode: mode_t,
) c_int;
pub extern "c" fn posix_spawn_file_actions_adddup2(
    actions: *posix_spawn_file_actions_t,
    filedes: fd_t,
    newfiledes: fd_t,
) c_int;
pub extern "c" fn posix_spawn_file_actions_addinherit_np(actions: *posix_spawn_file_actions_t, filedes: fd_t) c_int;
pub extern "c" fn posix_spawn_file_actions_addchdir_np(actions: *posix_spawn_file_actions_t, path: [*:0]const u8) c_int;
pub extern "c" fn posix_spawn_file_actions_addfchdir_np(actions: *posix_spawn_file_actions_t, filedes: fd_t) c_int;
pub extern "c" fn posix_spawn(
    pid: *pid_t,
    path: [*:0]const u8,
    actions: ?*const posix_spawn_file_actions_t,
    attr: ?*const posix_spawnattr_t,
    argv: [*:null]const ?[*:0]const u8,
    env: [*:null]const ?[*:0]const u8,
) c_int;
pub extern "c" fn posix_spawnp(
    pid: *pid_t,
    path: [*:0]const u8,
    actions: ?*const posix_spawn_file_actions_t,
    attr: ?*const posix_spawnattr_t,
    argv: [*:null]const ?[*:0]const u8,
    env: [*:null]const ?[*:0]const u8,
) c_int;

pub const E = enum(u16) {
    /// No error occurred.
    SUCCESS = 0,
    /// Operation not permitted
    PERM = 1,
    /// No such file or directory
    NOENT = 2,
    /// No such process
    SRCH = 3,
    /// Interrupted system call
    INTR = 4,
    /// Input/output error
    IO = 5,
    /// Device not configured
    NXIO = 6,
    /// Argument list too long
    @"2BIG" = 7,
    /// Exec format error
    NOEXEC = 8,
    /// Bad file descriptor
    BADF = 9,
    /// No child processes
    CHILD = 10,
    /// Resource deadlock avoided
    DEADLK = 11,
    /// Cannot allocate memory
    NOMEM = 12,
    /// Permission denied
    ACCES = 13,
    /// Bad address
    FAULT = 14,
    /// Block device required
    NOTBLK = 15,
    /// Device / Resource busy
    BUSY = 16,
    /// File exists
    EXIST = 17,
    /// Cross-device link
    XDEV = 18,
    /// Operation not supported by device
    NODEV = 19,
    /// Not a directory
    NOTDIR = 20,
    /// Is a directory
    ISDIR = 21,
    /// Invalid argument
    INVAL = 22,
    /// Too many open files in system
    NFILE = 23,
    /// Too many open files
    MFILE = 24,
    /// Inappropriate ioctl for device
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
    // math software
    /// Numerical argument out of domain
    DOM = 33,
    /// Result too large
    RANGE = 34,
    // non-blocking and interrupt i/o
    /// Resource temporarily unavailable
    /// This is the same code used for `WOULDBLOCK`.
    AGAIN = 35,
    /// Operation now in progress
    INPROGRESS = 36,
    /// Operation already in progress
    ALREADY = 37,
    // ipc/network software -- argument errors
    /// Socket operation on non-socket
    NOTSOCK = 38,
    /// Destination address required
    DESTADDRREQ = 39,
    /// Message too long
    MSGSIZE = 40,
    /// Protocol wrong type for socket
    PROTOTYPE = 41,
    /// Protocol not available
    NOPROTOOPT = 42,
    /// Protocol not supported
    PROTONOSUPPORT = 43,
    /// Socket type not supported
    SOCKTNOSUPPORT = 44,
    /// Operation not supported
    /// The same code is used for `NOTSUP`.
    OPNOTSUPP = 45,
    /// Protocol family not supported
    PFNOSUPPORT = 46,
    /// Address family not supported by protocol family
    AFNOSUPPORT = 47,
    /// Address already in use
    ADDRINUSE = 48,
    /// Can't assign requested address
    // ipc/network software -- operational errors
    ADDRNOTAVAIL = 49,
    /// Network is down
    NETDOWN = 50,
    /// Network is unreachable
    NETUNREACH = 51,
    /// Network dropped connection on reset
    NETRESET = 52,
    /// Software caused connection abort
    CONNABORTED = 53,
    /// Connection reset by peer
    CONNRESET = 54,
    /// No buffer space available
    NOBUFS = 55,
    /// Socket is already connected
    ISCONN = 56,
    /// Socket is not connected
    NOTCONN = 57,
    /// Can't send after socket shutdown
    SHUTDOWN = 58,
    /// Too many references: can't splice
    TOOMANYREFS = 59,
    /// Operation timed out
    TIMEDOUT = 60,
    /// Connection refused
    CONNREFUSED = 61,
    /// Too many levels of symbolic links
    LOOP = 62,
    /// File name too long
    NAMETOOLONG = 63,
    /// Host is down
    HOSTDOWN = 64,
    /// No route to host
    HOSTUNREACH = 65,
    /// Directory not empty
    // quotas & mush
    NOTEMPTY = 66,
    /// Too many processes
    PROCLIM = 67,
    /// Too many users
    USERS = 68,
    /// Disc quota exceeded
    // Network File System
    DQUOT = 69,
    /// Stale NFS file handle
    STALE = 70,
    /// Too many levels of remote in path
    REMOTE = 71,
    /// RPC struct is bad
    BADRPC = 72,
    /// RPC version wrong
    RPCMISMATCH = 73,
    /// RPC prog. not avail
    PROGUNAVAIL = 74,
    /// Program version wrong
    PROGMISMATCH = 75,
    /// Bad procedure for program
    PROCUNAVAIL = 76,
    /// No locks available
    NOLCK = 77,
    /// Function not implemented
    NOSYS = 78,
    /// Inappropriate file type or format
    FTYPE = 79,
    /// Authentication error
    AUTH = 80,
    /// Need authenticator
    NEEDAUTH = 81,
    // Intelligent device errors
    /// Device power is off
    PWROFF = 82,
    /// Device error, e.g. paper out
    DEVERR = 83,
    /// Value too large to be stored in data type
    OVERFLOW = 84,
    // Program loading errors
    /// Bad executable
    BADEXEC = 85,
    /// Bad CPU type in executable
    BADARCH = 86,
    /// Shared library version mismatch
    SHLIBVERS = 87,
    /// Malformed Macho file
    BADMACHO = 88,
    /// Operation canceled
    CANCELED = 89,
    /// Identifier removed
    IDRM = 90,
    /// No message of desired type
    NOMSG = 91,
    /// Illegal byte sequence
    ILSEQ = 92,
    /// Attribute not found
    NOATTR = 93,
    /// Bad message
    BADMSG = 94,
    /// Reserved
    MULTIHOP = 95,
    /// No message available on STREAM
    NODATA = 96,
    /// Reserved
    NOLINK = 97,
    /// No STREAM resources
    NOSR = 98,
    /// Not a STREAM
    NOSTR = 99,
    /// Protocol error
    PROTO = 100,
    /// STREAM ioctl timeout
    TIME = 101,
    /// No such policy registered
    NOPOLICY = 103,
    /// State not recoverable
    NOTRECOVERABLE = 104,
    /// Previous owner died
    OWNERDEAD = 105,
    /// Interface output queue is full
    QFULL = 106,
    _,
};

/// From Common Security Services Manager
/// Security.framework/Headers/cssm*.h
pub const DB_RECORDTYPE = enum(u32) {
    // Record Types defined in the Schema Management Name Space
    SCHEMA_INFO = SCHEMA_START + 0,
    SCHEMA_INDEXES = SCHEMA_START + 1,
    SCHEMA_ATTRIBUTES = SCHEMA_START + 2,
    SCHEMA_PARSING_MODULE = SCHEMA_START + 3,

    // Record Types defined in the Open Group Application Name Space
    ANY = OPEN_GROUP_START + 0,
    CERT = OPEN_GROUP_START + 1,
    CRL = OPEN_GROUP_START + 2,
    POLICY = OPEN_GROUP_START + 3,
    GENERIC = OPEN_GROUP_START + 4,
    PUBLIC_KEY = OPEN_GROUP_START + 5,
    PRIVATE_KEY = OPEN_GROUP_START + 6,
    SYMMETRIC_KEY = OPEN_GROUP_START + 7,
    ALL_KEYS = OPEN_GROUP_START + 8,

    // AppleFileDL record types
    GENERIC_PASSWORD = APP_DEFINED_START + 0,
    INTERNET_PASSWORD = APP_DEFINED_START + 1,
    APPLESHARE_PASSWORD = APP_DEFINED_START + 2,

    X509_CERTIFICATE = APP_DEFINED_START + 0x1000,
    USER_TRUST,
    X509_CRL,
    UNLOCK_REFERRAL,
    EXTENDED_ATTRIBUTE,
    METADATA = APP_DEFINED_START + 0x8000,

    _,

    // Schema Management Name Space Range Definition
    pub const SCHEMA_START = 0x00000000;
    pub const SCHEMA_END = SCHEMA_START + 4;

    // Open Group Application Name Space Range Definition
    pub const OPEN_GROUP_START = 0x0000000A;
    pub const OPEN_GROUP_END = OPEN_GROUP_START + 8;

    // Industry At Large Application Name Space Range Definition
    pub const APP_DEFINED_START = 0x80000000;
    pub const APP_DEFINED_END = 0xffffffff;
};

pub const TCP = struct {
    /// Turn off Nagle's algorithm
    pub const NODELAY = 0x01;
    /// Limit MSS
    pub const MAXSEG = 0x02;
    /// Don't push last block of write
    pub const NOPUSH = 0x04;
    /// Don't use TCP options
    pub const NOOPT = 0x08;
    /// Idle time used when SO_KEEPALIVE is enabled
    pub const KEEPALIVE = 0x10;
    /// Connection timeout
    pub const CONNECTIONTIMEOUT = 0x20;
    /// Time after which a conection in persist timeout will terminate.
    pub const PERSIST_TIMEOUT = 0x40;
    /// Time after which TCP retransmissions will be stopped and the connection will be dropped.
    pub const RXT_CONNDROPTIME = 0x80;
    /// Drop a connection after retransmitting the FIN 3 times.
    pub const RXT_FINDROP = 0x100;
    /// Interval between keepalives
    pub const KEEPINTVL = 0x101;
    /// Number of keepalives before clsoe
    pub const KEEPCNT = 0x102;
    /// Always ack every other packet
    pub const SENDMOREACKS = 0x103;
    /// Enable ECN on a connection
    pub const ENABLE_ECN = 0x104;
    /// Enable/Disable TCP Fastopen on this socket
    pub const FASTOPEN = 0x105;
    /// State of the TCP connection
    pub const CONNECTION_INFO = 0x106;
};
const std = @import("../std.zig");

const SIG = std.c.SIG;
const gid_t = std.c.gid_t;
const iovec = std.c.iovec;
const pid_t = std.c.pid_t;
const socklen_t = std.c.socklen_t;
const uid_t = std.c.uid_t;

pub extern "c" fn lwp_gettid() c_int;
pub extern "c" fn umtx_sleep(ptr: *const volatile c_int, value: c_int, timeout: c_int) c_int;
pub extern "c" fn umtx_wakeup(ptr: *const volatile c_int, count: c_int) c_int;

pub const mcontext_t = extern struct {
    onstack: register_t, // XXX - sigcontext compat.
    rdi: register_t,
    rsi: register_t,
    rdx: register_t,
    rcx: register_t,
    r8: register_t,
    r9: register_t,
    rax: register_t,
    rbx: register_t,
    rbp: register_t,
    r10: register_t,
    r11: register_t,
    r12: register_t,
    r13: register_t,
    r14: register_t,
    r15: register_t,
    xflags: register_t,
    trapno: register_t,
    addr: register_t,
    flags: register_t,
    err: register_t,
    rip: register_t,
    cs: register_t,
    rflags: register_t,
    rsp: register_t, // machine state
    ss: register_t,

    len: c_uint, // sizeof(mcontext_t)
    fpformat: c_uint,
    ownedfp: c_uint,
    reserved: c_uint,
    unused: [8]c_uint,

    // NOTE! 64-byte aligned as of here. Also must match savefpu structure.
    fpregs: [256]c_int align(64),
};

pub const register_t = isize;

pub const E = enum(u16) {
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
    DEADLK = 11,
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
    /// This code is also used for `WOULDBLOCK`.
    AGAIN = 35,
    INPROGRESS = 36,
    ALREADY = 37,
    NOTSOCK = 38,
    DESTADDRREQ = 39,
    MSGSIZE = 40,
    PROTOTYPE = 41,
    NOPROTOOPT = 42,
    PROTONOSUPPORT = 43,
    SOCKTNOSUPPORT = 44,
    /// This code is also used for `NOTSUP`.
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
    BADRPC = 72,
    RPCMISMATCH = 73,
    PROGUNAVAIL = 74,
    PROGMISMATCH = 75,
    PROCUNAVAIL = 76,
    NOLCK = 77,
    NOSYS = 78,
    FTYPE = 79,
    AUTH = 80,
    NEEDAUTH = 81,
    IDRM = 82,
    NOMSG = 83,
    OVERFLOW = 84,
    CANCELED = 85,
    ILSEQ = 86,
    NOATTR = 87,
    DOOFUS = 88,
    BADMSG = 89,
    MULTIHOP = 90,
    NOLINK = 91,
    PROTO = 92,
    NOMEDIUM = 93,
    ASYNC = 99,
    _,
};

pub const BADSIG = SIG.ERR;

pub const sig_t = *const fn (i32) callconv(.c) void;

pub const cmsghdr = extern struct {
    len: socklen_t,
    level: c_int,
    type: c_int,
};

pub const cmsgcred = extern struct {
    pid: pid_t,
    uid: uid_t,
    euid: uid_t,
    gid: gid_t,
    ngroups: c_short,
    groups: [16]gid_t,
};
pub const sf_hdtr = extern struct {
    headers: [*]iovec,
    hdr_cnt: c_int,
    trailers: [*]iovec,
    trl_cnt: c_int,
};

pub const MS_SYNC = 0;
pub const MS_ASYNC = 1;
pub const MS_INVALIDATE = 2;

pub const POSIX_MADV_SEQUENTIAL = 2;
pub const POSIX_MADV_RANDOM = 1;
pub const POSIX_MADV_DONTNEED = 4;
pub const POSIX_MADV_NORMAL = 0;
pub const POSIX_MADV_WILLNEED = 3;
const builtin = @import("builtin");
const std = @import("../std.zig");
const assert = std.debug.assert;

const PATH_MAX = std.c.PATH_MAX;
const blkcnt_t = std.c.blkcnt_t;
const blksize_t = std.c.blksize_t;
const dev_t = std.c.dev_t;
const fd_t = std.c.fd_t;
const gid_t = std.c.gid_t;
const ino_t = std.c.ino_t;
const iovec_const = std.posix.iovec_const;
const mode_t = std.c.mode_t;
const nlink_t = std.c.nlink_t;
const off_t = std.c.off_t;
const pid_t = std.c.pid_t;
const sockaddr = std.c.sockaddr;
const time_t = std.c.time_t;
const timespec = std.c.timespec;
const uid_t = std.c.uid_t;
const sf_hdtr = std.c.sf_hdtr;
const clockid_t = std.c.clockid_t;

comptime {
    assert(builtin.os.tag == .freebsd); // Prevent access of std.c symbols on wrong OS.
}

pub extern "c" fn kinfo_getfile(pid: pid_t, cntp: *c_int) ?[*]kinfo_file;
pub extern "c" fn copy_file_range(fd_in: fd_t, off_in: ?*off_t, fd_out: fd_t, off_out: ?*off_t, len: usize, flags: u32) usize;

pub extern "c" fn sendfile(
    in_fd: fd_t,
    out_fd: fd_t,
    offset: off_t,
    nbytes: usize,
    sf_hdtr: ?*sf_hdtr,
    sbytes: ?*off_t,
    flags: u32,
) c_int;

pub const UMTX_OP = enum(c_int) {
    LOCK = 0,
    UNLOCK = 1,
    WAIT = 2,
    WAKE = 3,
    MUTEX_TRYLOCK = 4,
    MUTEX_LOCK = 5,
    MUTEX_UNLOCK = 6,
    SET_CEILING = 7,
    CV_WAIT = 8,
    CV_SIGNAL = 9,
    CV_BROADCAST = 10,
    WAIT_UINT = 11,
    RW_RDLOCK = 12,
    RW_WRLOCK = 13,
    RW_UNLOCK = 14,
    WAIT_UINT_PRIVATE = 15,
    WAKE_PRIVATE = 16,
    MUTEX_WAIT = 17,
    MUTEX_WAKE = 18, // deprecated
    SEM_WAIT = 19, // deprecated
    SEM_WAKE = 20, // deprecated
    NWAKE_PRIVATE = 31,
    MUTEX_WAKE2 = 22,
    SEM2_WAIT = 23,
    SEM2_WAKE = 24,
    SHM = 25,
    ROBUST_LISTS = 26,
};

pub const UMTX_ABSTIME = 0x01;
pub const _umtx_time = extern struct {
    timeout: timespec,
    flags: u32,
    clockid: clockid_t,
};

pub extern "c" fn _umtx_op(obj: usize, op: c_int, val: c_ulong, uaddr: usize, uaddr2: usize) c_int;

pub const fflags_t = u32;

pub const Stat = extern struct {
    /// The inode's device.
    dev: dev_t,
    /// The inode's number.
    ino: ino_t,
    /// Number of hard links.
    nlink: nlink_t,
    /// Inode protection mode.
    mode: mode_t,
    __pad0: i16,
    /// User ID of the file's owner.
    uid: uid_t,
    /// Group ID of the file's group.
    gid: gid_t,
    __pad1: i32,
    /// Device type.
    rdev: dev_t,
    /// Time of last access.
    atim: timespec,
    /// Time of last data modification.
    mtim: timespec,
    /// Time of last file status change.
    ctim: timespec,
    /// Time of file creation.
    birthtim: timespec,
    /// File size, in bytes.
    size: off_t,
    /// Blocks allocated for file.
    blocks: blkcnt_t,
    /// Optimal blocksize for I/O.
    blksize: blksize_t,
    /// User defined flags for file.
    flags: fflags_t,
    /// File generation number.
    gen: u64,
    __spare: [10]u64,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }

    pub fn birthtime(self: @This()) timespec {
        return self.birthtim;
    }
};

pub const fsblkcnt_t = u64;
pub const fsfilcnt_t = u64;

pub const CAP_RIGHTS_VERSION = 0;

pub const cap_rights = extern struct {
    rights: [CAP_RIGHTS_VERSION + 2]u64,
};

pub const kinfo_file = extern struct {
    /// Size of this record.
    /// A zero value is for the sentinel record at the end of an array.
    structsize: c_int,
    /// Descriptor type.
    type: c_int,
    /// Array index.
    fd: fd_t,
    /// Reference count.
    ref_count: c_int,
    /// Flags.
    flags: c_int,
    // 64bit padding.
    _pad0: c_int,
    /// Seek location.
    offset: i64,
    un: extern union {
        socket: extern struct {
            /// Sendq size.
            sendq: u32,
            /// Socket domain.
            domain: c_int,
            /// Socket type.
            type: c_int,
            /// Socket protocol.
            protocol: c_int,
            /// Socket address.
            address: sockaddr.storage,
            /// Peer address.
            peer: sockaddr.storage,
            /// Address of so_pcb.
            pcb: u64,
            /// Address of inp_ppcb.
            inpcb: u64,
            /// Address of unp_conn.
            unpconn: u64,
            /// Send buffer state.
            snd_sb_state: u16,
            /// Receive buffer state.
            rcv_sb_state: u16,
            /// Recvq size.
            recvq: u32,
        },
        file: extern struct {
            /// Vnode type.
            type: i32,
            // Reserved for future use
            _spare1: [3]i32,
            _spare2: [30]u64,
            /// Vnode filesystem id.
            fsid: u64,
            /// File device.
            rdev: u64,
            /// Global file id.
            fileid: u64,
            /// File size.
            size: u64,
            /// fsid compat for FreeBSD 11.
            fsid_freebsd11: u32,
            /// rdev compat for FreeBSD 11.
            rdev_freebsd11: u32,
            /// File mode.
            mode: u16,
            // 64bit padding.
            _pad0: u16,
            _pad1: u32,
        },
        sem: extern struct {
            _spare0: [4]u32,
            _spare1: [32]u64,
            /// Semaphore value.
            value: u32,
            /// Semaphore mode.
            mode: u16,
        },
        pipe: extern struct {
            _spare1: [4]u32,
            _spare2: [32]u64,
            addr: u64,
            peer: u64,
            buffer_cnt: u32,
            // 64bit padding.
            kf_pipe_pad0: [3]u32,
        },
        proc: extern struct {
            _spare1: [4]u32,
            _spare2: [32]u64,
            pid: pid_t,
        },
        eventfd: extern struct {
            value: u64,
            flags: u32,
        },
    },
    /// Status flags.
    status: u16,
    // 32-bit alignment padding.
    _pad1: u16,
    // Reserved for future use.
    _spare: c_int,
    /// Capability rights.
    cap_rights: cap_rights,
    /// Reserved for future cap_rights
    _cap_spare: u64,
    /// Path to file, if any.
    path: [PATH_MAX - 1:0]u8,

    comptime {
        assert(@sizeOf(@This()) == KINFO_FILE_SIZE);
        assert(@alignOf(@This()) == @sizeOf(u64));
    }
};

pub const KINFO_FILE_SIZE = 1392;

pub const MFD = struct {
    pub const CLOEXEC = 0x0001;
    pub const ALLOW_SEALING = 0x0002;
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
    ROFS = 30, // Read-only filesystem
    MLINK = 31, // Too many links
    PIPE = 32, // Broken pipe

    // math software
    DOM = 33, // Numerical argument out of domain
    RANGE = 34, // Result too large

    // non-blocking and interrupt i/o

    /// Resource temporarily unavailable
    /// This code is also used for `WOULDBLOCK`: operation would block.
    AGAIN = 35,
    INPROGRESS = 36, // Operation now in progress
    ALREADY = 37, // Operation already in progress

    // ipc/network software -- argument errors
    NOTSOCK = 38, // Socket operation on non-socket
    DESTADDRREQ = 39, // Destination address required
    MSGSIZE = 40, // Message too long
    PROTOTYPE = 41, // Protocol wrong type for socket
    NOPROTOOPT = 42, // Protocol not available
    PROTONOSUPPORT = 43, // Protocol not supported
    SOCKTNOSUPPORT = 44, // Socket type not supported
    /// Operation not supported
    /// This code is also used for `NOTSUP`.
    OPNOTSUPP = 45,
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
    IDRM = 82, // Identifier removed
    NOMSG = 83, // No message of desired type
    OVERFLOW = 84, // Value too large to be stored in data type
    CANCELED = 85, // Operation canceled
    ILSEQ = 86, // Illegal byte sequence
    NOATTR = 87, // Attribute not found

    DOOFUS = 88, // Programming error

    BADMSG = 89, // Bad message
    MULTIHOP = 90, // Multihop attempted
    NOLINK = 91, // Link has been severed
    PROTO = 92, // Protocol error

    NOTCAPABLE = 93, // Capabilities insufficient
    CAPMODE = 94, // Not permitted in capability mode
    NOTRECOVERABLE = 95, // State not recoverable
    OWNERDEAD = 96, // Previous owner died
    INTEGRITY = 97, // Integrity check failed
    _,
};
const std = @import("../std.zig");
const assert = std.debug.assert;
const builtin = @import("builtin");
const maxInt = std.math.maxInt;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const socklen_t = std.c.socklen_t;
const fd_t = std.c.fd_t;
const PATH_MAX = std.c.PATH_MAX;
const uid_t = std.c.uid_t;
const gid_t = std.c.gid_t;
const dev_t = std.c.dev_t;
const ino_t = std.c.ino_t;

comptime {
    assert(builtin.os.tag == .haiku); // Prevent access of std.c symbols on wrong OS.
}

pub extern "root" fn _errnop() *i32;
pub extern "root" fn find_directory(which: directory_which, volume: i32, createIt: bool, path_ptr: [*]u8, length: i32) u64;
pub extern "root" fn find_thread(thread_name: ?*anyopaque) i32;
pub extern "root" fn get_system_info(system_info: *system_info) usize;
pub extern "root" fn _get_team_info(team: i32, team_info: *team_info, size: usize) i32;
pub extern "root" fn _get_next_area_info(team: i32, cookie: *i64, area_info: *area_info, size: usize) i32;
pub extern "root" fn _get_next_image_info(team: i32, cookie: *i32, image_info: *image_info, size: usize) i32;

pub const area_info = extern struct {
    area: u32,
    name: [32]u8,
    size: usize,
    lock: u32,
    protection: u32,
    team_id: i32,
    ram_size: u32,
    copy_count: u32,
    in_count: u32,
    out_count: u32,
    address: *anyopaque,
};

pub const image_info = extern struct {
    id: u32,
    image_type: u32,
    sequence: i32,
    init_order: i32,
    init_routine: *anyopaque,
    term_routine: *anyopaque,
    device: i32,
    node: i64,
    name: [PATH_MAX]u8,
    text: *anyopaque,
    data: *anyopaque,
    text_size: i32,
    data_size: i32,
    api_version: i32,
    abi: i32,
};

pub const system_info = extern struct {
    boot_time: i64,
    cpu_count: u32,
    max_pages: u64,
    used_pages: u64,
    cached_pages: u64,
    block_cache_pages: u64,
    ignored_pages: u64,
    needed_memory: u64,
    free_memory: u64,
    max_swap_pages: u64,
    free_swap_pages: u64,
    page_faults: u32,
    max_sems: u32,
    used_sems: u32,
    max_ports: u32,
    used_ports: u32,
    max_threads: u32,
    used_threads: u32,
    max_teams: u32,
    used_teams: u32,
    kernel_name: [256]u8,
    kernel_build_date: [32]u8,
    kernel_build_time: [32]u8,
    kernel_version: i64,
    abi: u32,
};

pub const team_info = extern struct {
    team_id: i32,
    thread_count: i32,
    image_count: i32,
    area_count: i32,
    debugger_nub_thread: i32,
    debugger_nub_port: i32,
    argc: i32,
    args: [64]u8,
    uid: uid_t,
    gid: gid_t,
};

pub const directory_which = enum(i32) {
    B_USER_SETTINGS_DIRECTORY = 0xbbe,

    _,
};

pub const area_id = i32;
pub const port_id = i32;
pub const sem_id = i32;
pub const team_id = i32;
pub const thread_id = i32;

pub const E = enum(i32) {
    pub const B_GENERAL_ERROR_BASE: i32 = std.math.minInt(i32);
    pub const B_OS_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x1000;
    pub const B_APP_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x2000;
    pub const B_INTERFACE_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x3000;
    pub const B_MEDIA_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x4000;
    pub const B_TRANSLATION_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x4800;
    pub const B_MIDI_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x5000;
    pub const B_STORAGE_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x6000;
    pub const B_POSIX_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x7000;
    pub const B_MAIL_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x8000;
    pub const B_PRINT_ERROR_BASE = B_GENERAL_ERROR_BASE + 0x9000;
    pub const B_DEVICE_ERROR_BASE = B_GENERAL_ERROR_BASE + 0xa000;

    pub const B_ERRORS_END = B_GENERAL_ERROR_BASE + 0xffff;

    pub const B_NO_MEMORY = B_GENERAL_ERROR_BASE + 0;
    pub const B_IO_ERROR = B_GENERAL_ERROR_BASE + 1;
    pub const B_PERMISSION_DENIED = B_GENERAL_ERROR_BASE + 2;
    pub const B_BAD_INDEX = B_GENERAL_ERROR_BASE + 3;
    pub const B_BAD_TYPE = B_GENERAL_ERROR_BASE + 4;
    pub const B_BAD_VALUE = B_GENERAL_ERROR_BASE + 5;
    pub const B_MISMATCHED_VALUES = B_GENERAL_ERROR_BASE + 6;
    pub const B_NAME_NOT_FOUND = B_GENERAL_ERROR_BASE + 7;
    pub const B_NAME_IN_USE = B_GENERAL_ERROR_BASE + 8;
    pub const B_TIMED_OUT = B_GENERAL_ERROR_BASE + 9;
    pub const B_INTERRUPTED = B_GENERAL_ERROR_BASE + 10;
    pub const B_WOULD_BLOCK = B_GENERAL_ERROR_BASE + 11;
    pub const B_CANCELED = B_GENERAL_ERROR_BASE + 12;
    pub const B_NO_INIT = B_GENERAL_ERROR_BASE + 13;
    pub const B_NOT_INITIALIZED = B_GENERAL_ERROR_BASE + 13;
    pub const B_BUSY = B_GENERAL_ERROR_BASE + 14;
    pub const B_NOT_ALLOWED = B_GENERAL_ERROR_BASE + 15;
    pub const B_BAD_DATA = B_GENERAL_ERROR_BASE + 16;
    pub const B_DONT_DO_THAT = B_GENERAL_ERROR_BASE + 17;

    pub const B_BAD_IMAGE_ID = B_OS_ERROR_BASE + 0x300;
    pub const B_BAD_ADDRESS = B_OS_ERROR_BASE + 0x301;
    pub const B_NOT_AN_EXECUTABLE = B_OS_ERROR_BASE + 0x302;
    pub const B_MISSING_LIBRARY = B_OS_ERROR_BASE + 0x303;
    pub const B_MISSING_SYMBOL = B_OS_ERROR_BASE + 0x304;
    pub const B_UNKNOWN_EXECUTABLE = B_OS_ERROR_BASE + 0x305;
    pub const B_LEGACY_EXECUTABLE = B_OS_ERROR_BASE + 0x306;

    pub const B_FILE_ERROR = B_STORAGE_ERROR_BASE + 0;
    pub const B_FILE_EXISTS = B_STORAGE_ERROR_BASE + 2;
    pub const B_ENTRY_NOT_FOUND = B_STORAGE_ERROR_BASE + 3;
    pub const B_NAME_TOO_LONG = B_STORAGE_ERROR_BASE + 4;
    pub const B_NOT_A_DIRECTORY = B_STORAGE_ERROR_BASE + 5;
    pub const B_DIRECTORY_NOT_EMPTY = B_STORAGE_ERROR_BASE + 6;
    pub const B_DEVICE_FULL = B_STORAGE_ERROR_BASE + 7;
    pub const B_READ_ONLY_DEVICE = B_STORAGE_ERROR_BASE + 8;
    pub const B_IS_A_DIRECTORY = B_STORAGE_ERROR_BASE + 9;
    pub const B_NO_MORE_FDS = B_STORAGE_ERROR_BASE + 10;
    pub const B_CROSS_DEVICE_LINK = B_STORAGE_ERROR_BASE + 11;
    pub const B_LINK_LIMIT = B_STORAGE_ERROR_BASE + 12;
    pub const B_BUSTED_PIPE = B_STORAGE_ERROR_BASE + 13;
    pub const B_UNSUPPORTED = B_STORAGE_ERROR_BASE + 14;
    pub const B_PARTITION_TOO_SMALL = B_STORAGE_ERROR_BASE + 15;
    pub const B_PARTIAL_READ = B_STORAGE_ERROR_BASE + 16;
    pub const B_PARTIAL_WRITE = B_STORAGE_ERROR_BASE + 17;

    SUCCESS = 0,

    @"2BIG" = B_POSIX_ERROR_BASE + 1,
    CHILD = B_POSIX_ERROR_BASE + 2,
    DEADLK = B_POSIX_ERROR_BASE + 3,
    FBIG = B_POSIX_ERROR_BASE + 4,
    MLINK = B_POSIX_ERROR_BASE + 5,
    NFILE = B_POSIX_ERROR_BASE + 6,
    NODEV = B_POSIX_ERROR_BASE + 7,
    NOLCK = B_POSIX_ERROR_BASE + 8,
    NOSYS = B_POSIX_ERROR_BASE + 9,
    NOTTY = B_POSIX_ERROR_BASE + 10,
    NXIO = B_POSIX_ERROR_BASE + 11,
    SPIPE = B_POSIX_ERROR_BASE + 12,
    SRCH = B_POSIX_ERROR_BASE + 13,
    FPOS = B_POSIX_ERROR_BASE + 14,
    SIGPARM = B_POSIX_ERROR_BASE + 15,
    DOM = B_POSIX_ERROR_BASE + 16,
    RANGE = B_POSIX_ERROR_BASE + 17,
    PROTOTYPE = B_POSIX_ERROR_BASE + 18,
    PROTONOSUPPORT = B_POSIX_ERROR_BASE + 19,
    PFNOSUPPORT = B_POSIX_ERROR_BASE + 20,
    AFNOSUPPORT = B_POSIX_ERROR_BASE + 21,
    ADDRINUSE = B_POSIX_ERROR_BASE + 22,
    ADDRNOTAVAIL = B_POSIX_ERROR_BASE + 23,
    NETDOWN = B_POSIX_ERROR_BASE + 24,
    NETUNREACH = B_POSIX_ERROR_BASE + 25,
    NETRESET = B_POSIX_ERROR_BASE + 26,
    CONNABORTED = B_POSIX_ERROR_BASE + 27,
    CONNRESET = B_POSIX_ERROR_BASE + 28,
    ISCONN = B_POSIX_ERROR_BASE + 29,
    NOTCONN = B_POSIX_ERROR_BASE + 30,
    SHUTDOWN = B_POSIX_ERROR_BASE + 31,
    CONNREFUSED = B_POSIX_ERROR_BASE + 32,
    HOSTUNREACH = B_POSIX_ERROR_BASE + 33,
    NOPROTOOPT = B_POSIX_ERROR_BASE + 34,
    NOBUFS = B_POSIX_ERROR_BASE + 35,
    INPROGRESS = B_POSIX_ERROR_BASE + 36,
    ALREADY = B_POSIX_ERROR_BASE + 37,
    ILSEQ = B_POSIX_ERROR_BASE + 38,
    NOMSG = B_POSIX_ERROR_BASE + 39,
    STALE = B_POSIX_ERROR_BASE + 40,
    OVERFLOW = B_POSIX_ERROR_BASE + 41,
    MSGSIZE = B_POSIX_ERROR_BASE + 42,
    OPNOTSUPP = B_POSIX_ERROR_BASE + 43,
    NOTSOCK = B_POSIX_ERROR_BASE + 44,
    HOSTDOWN = B_POSIX_ERROR_BASE + 45,
    BADMSG = B_POSIX_ERROR_BASE + 46,
    CANCELED = B_POSIX_ERROR_BASE + 47,
    DESTADDRREQ = B_POSIX_ERROR_BASE + 48,
    DQUOT = B_POSIX_ERROR_BASE + 49,
    IDRM = B_POSIX_ERROR_BASE + 50,
    MULTIHOP = B_POSIX_ERROR_BASE + 51,
    NODATA = B_POSIX_ERROR_BASE + 52,
    NOLINK = B_POSIX_ERROR_BASE + 53,
    NOSR = B_POSIX_ERROR_BASE + 54,
    NOSTR = B_POSIX_ERROR_BASE + 55,
    NOTSUP = B_POSIX_ERROR_BASE + 56,
    PROTO = B_POSIX_ERROR_BASE + 57,
    TIME = B_POSIX_ERROR_BASE + 58,
    TXTBSY = B_POSIX_ERROR_BASE + 59,
    NOATTR = B_POSIX_ERROR_BASE + 60,
    NOTRECOVERABLE = B_POSIX_ERROR_BASE + 61,
    OWNERDEAD = B_POSIX_ERROR_BASE + 62,

    NOMEM = B_NO_MEMORY,

    ACCES = B_PERMISSION_DENIED,
    INTR = B_INTERRUPTED,
    IO = B_IO_ERROR,
    BUSY = B_BUSY,
    FAULT = B_BAD_ADDRESS,
    TIMEDOUT = B_TIMED_OUT,
    /// Also used for WOULDBLOCK
    AGAIN = B_WOULD_BLOCK,
    BADF = B_FILE_ERROR,
    EXIST = B_FILE_EXISTS,
    INVAL = B_BAD_VALUE,
    NAMETOOLONG = B_NAME_TOO_LONG,
    NOENT = B_ENTRY_NOT_FOUND,
    PERM = B_NOT_ALLOWED,
    NOTDIR = B_NOT_A_DIRECTORY,
    ISDIR = B_IS_A_DIRECTORY,
    NOTEMPTY = B_DIRECTORY_NOT_EMPTY,
    NOSPC = B_DEVICE_FULL,
    ROFS = B_READ_ONLY_DEVICE,
    MFILE = B_NO_MORE_FDS,
    XDEV = B_CROSS_DEVICE_LINK,
    LOOP = B_LINK_LIMIT,
    NOEXEC = B_NOT_AN_EXECUTABLE,
    PIPE = B_BUSTED_PIPE,

    _,
};

pub const status_t = i32;

pub const mcontext_t = switch (builtin.cpu.arch) {
    .arm, .thumb => extern struct {
        r0: u32,
        r1: u32,
        r2: u32,
        r3: u32,
        r4: u32,
        r5: u32,
        r6: u32,
        r7: u32,
        r8: u32,
        r9: u32,
        r10: u32,
        r11: u32,
        r12: u32,
        r13: u32,
        r14: u32,
        r15: u32,
        cpsr: u32,
    },
    .aarch64 => extern struct {
        x: [10]u64,
        lr: u64,
        sp: u64,
        elr: u64,
        spsr: u64,
        fp_q: [32]u128,
        fpsr: u32,
        fpcr: u32,
    },
    .m68k => extern struct {
        pc: u32,
        d0: u32,
        d1: u32,
        d2: u32,
        d3: u32,
        d4: u32,
        d5: u32,
        d6: u32,
        d7: u32,
        a0: u32,
        a1: u32,
        a2: u32,
        a3: u32,
        a4: u32,
        a5: u32,
        a6: u32,
        a7: u32,
        ccr: u8,
        f0: f64,
        f1: f64,
        f2: f64,
        f3: f64,
        f4: f64,
        f5: f64,
        f6: f64,
        f7: f64,
        f8: f64,
        f9: f64,
        f10: f64,
        f11: f64,
        f12: f64,
        f13: f64,
    },
    .mipsel => extern struct {
        r0: u32,
    },
    .powerpc => extern struct {
        pc: u32,
        r0: u32,
        r1: u32,
        r2: u32,
        r3: u32,
        r4: u32,
        r5: u32,
        r6: u32,
        r7: u32,
        r8: u32,
        r9: u32,
        r10: u32,
        r11: u32,
        r12: u32,
        f0: f64,
        f1: f64,
        f2: f64,
        f3: f64,
        f4: f64,
        f5: f64,
        f6: f64,
        f7: f64,
        f8: f64,
        f9: f64,
        f10: f64,
        f11: f64,
        f12: f64,
        f13: f64,
        reserved: u32,
        fpscr: u32,
        ctr: u32,
        xer: u32,
        cr: u32,
        msr: u32,
        lr: u32,
    },
    .riscv64 => extern struct {
        x: [31]u64,
        pc: u64,
        f: [32]f64,
        fcsr: u64,
    },
    .sparc64 => extern struct {
        g1: u64,
        g2: u64,
        g3: u64,
        g4: u64,
        g5: u64,
        g6: u64,
        g7: u64,
        o0: u64,
        o1: u64,
        o2: u64,
        o3: u64,
        o4: u64,
        o5: u64,
        sp: u64,
        o7: u64,
        l0: u64,
        l1: u64,
        l2: u64,
        l3: u64,
        l4: u64,
        l5: u64,
        l6: u64,
        l7: u64,
        i0: u64,
        i1: u64,
        i2: u64,
        i3: u64,
        i4: u64,
        i5: u64,
        fp: u64,
        i7: u64,
    },
    .x86 => extern struct {
        pub const old_extended_regs = extern struct {
            control: u16,
            reserved1: u16,
            status: u16,
            reserved2: u16,
            tag: u16,
            reserved3: u16,
            eip: u32,
            cs: u16,
            opcode: u16,
            datap: u32,
            ds: u16,
            reserved4: u16,
            fp_mmx: [8][10]u8,
        };

        pub const fp_register = extern struct { value: [10]u8, reserved: [6]u8 };

        pub const xmm_register = extern struct { value: [16]u8 };

        pub const new_extended_regs = extern struct {
            control: u16,
            status: u16,
            tag: u16,
            opcode: u16,
            eip: u32,
            cs: u16,
            reserved1: u16,
            datap: u32,
            ds: u16,
            reserved2: u16,
            mxcsr: u32,
            reserved3: u32,
            fp_mmx: [8]fp_register,
            xmmx: [8]xmm_register,
            reserved4: [224]u8,
        };

        pub const extended_regs = extern struct {
            state: extern union {
                old_format: old_extended_regs,
                new_format: new_extended_regs,
            },
            format: u32,
        };

        eip: u32,
        eflags: u32,
        eax: u32,
        ecx: u32,
        edx: u32,
        esp: u32,
        ebp: u32,
        reserved: u32,
        xregs: extended_regs,
        edi: u32,
        esi: u32,
        ebx: u32,
    },
    .x86_64 => extern struct {
        pub const fp_register = extern struct {
            value: [10]u8,
            reserved: [6]u8,
        };

        pub const xmm_register = extern struct {
            value: [16]u8,
        };

        pub const fpu_state = extern struct {
            control: u16,
            status: u16,
            tag: u16,
            opcode: u16,
            rip: u64,
            rdp: u64,
            mxcsr: u32,
            mscsr_mask: u32,

            fp_mmx: [8]fp_register,
            xmm: [16]xmm_register,
            reserved: [96]u8,
        };

        pub const xstate_hdr = extern struct {
            bv: u64,
            xcomp_bv: u64,
            reserved: [48]u8,
        };

        pub const savefpu = extern struct {
            fxsave: fpu_state,
            xstate: xstate_hdr,
            ymm: [16]xmm_register,
        };

        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rdi: u64,
        rsi: u64,
        rbp: u64,
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rsp: u64,
        rip: u64,
        rflags: u64,
        fpu: savefpu,
    },
    else => void,
};

pub const DirEnt = extern struct {
    /// device
    dev: dev_t,
    /// parent device (only for queries)
    pdev: dev_t,
    /// inode number
    ino: ino_t,
    /// parent inode (only for queries)
    pino: ino_t,
    /// length of this record, not the name
    reclen: u16,
    /// name of the entry (null byte terminated)
    name: [0]u8,
    pub fn getName(dirent: *const DirEnt) [*:0]const u8 {
        return @ptrCast(&dirent.name);
    }
};
const std = @import("../std.zig");
const clock_t = std.c.clock_t;
const pid_t = std.c.pid_t;
const pthread_t = std.c.pthread_t;
const sigval_t = std.c.sigval_t;
const uid_t = std.c.uid_t;

pub const lwpid_t = i32;

pub extern "c" fn _lwp_self() lwpid_t;
pub extern "c" fn pthread_setname_np(thread: pthread_t, name: [*:0]const u8, arg: ?*anyopaque) c_int;

pub const TCIFLUSH = 1;
pub const TCOFLUSH = 2;
pub const TCIOFLUSH = 3;
pub const TCOOFF = 1;
pub const TCOON = 2;
pub const TCIOFF = 3;
pub const TCION = 4;

pub const _ksiginfo = extern struct {
    signo: i32,
    code: i32,
    errno: i32,
    // 64bit architectures insert 4bytes of padding here, this is done by
    // correctly aligning the reason field
    reason: extern union {
        rt: extern struct {
            pid: pid_t,
            uid: uid_t,
            value: sigval_t,
        },
        child: extern struct {
            pid: pid_t,
            uid: uid_t,
            status: i32,
            utime: clock_t,
            stime: clock_t,
        },
        fault: extern struct {
            addr: *allowzero anyopaque,
            trap: i32,
            trap2: i32,
            trap3: i32,
        },
        poll: extern struct {
            band: i32,
            fd: i32,
        },
        syscall: extern struct {
            sysnum: i32,
            retval: [2]i32,
            @"error": i32,
            args: [8]u64,
        },
        ptrace_state: extern struct {
            pe_report_event: i32,
            option: extern union {
                pe_other_pid: pid_t,
                pe_lwp: lwpid_t,
            },
        },
    } align(@sizeOf(usize)),
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

    // SystemV IPC
    IDRM = 82, // Identifier removed
    NOMSG = 83, // No message of desired type
    OVERFLOW = 84, // Value too large to be stored in data type

    // Wide/multibyte-character handling, ISO/IEC 9899/AMD1:1995
    ILSEQ = 85, // Illegal byte sequence

    // From IEEE Std 1003.1-2001
    // Base, Realtime, Threads or Thread Priority Scheduling option errors
    NOTSUP = 86, // Not supported

    // Realtime option errors
    CANCELED = 87, // Operation canceled

    // Realtime, XSI STREAMS option errors
    BADMSG = 88, // Bad or Corrupt message

    // XSI STREAMS option errors
    NODATA = 89, // No message available
    NOSR = 90, // No STREAM resources
    NOSTR = 91, // Not a STREAM
    TIME = 92, // STREAM ioctl timeout

    // File system extended attribute errors
    NOATTR = 93, // Attribute not found

    // Realtime, XSI STREAMS option errors
    MULTIHOP = 94, // Multihop attempted
    NOLINK = 95, // Link has been severed
    PROTO = 96, // Protocol error

    _,
};
const std = @import("../std.zig");
const assert = std.debug.assert;
const maxInt = std.math.maxInt;
const builtin = @import("builtin");
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const passwd = std.c.passwd;
const timespec = std.c.timespec;
const uid_t = std.c.uid_t;
const pid_t = std.c.pid_t;

comptime {
    assert(builtin.os.tag == .openbsd); // Prevent access of std.c symbols on wrong OS.
}

pub const pthread_spinlock_t = extern struct {
    inner: ?*anyopaque = null,
};

pub extern "c" fn pledge(promises: ?[*:0]const u8, execpromises: ?[*:0]const u8) c_int;
pub extern "c" fn unveil(path: ?[*:0]const u8, permissions: ?[*:0]const u8) c_int;
pub extern "c" fn getthrid() pid_t;

pub const FUTEX = struct {
    pub const WAIT = 1;
    pub const WAKE = 2;
    pub const REQUEUE = 3;
    pub const PRIVATE_FLAG = 128;
};
pub extern "c" fn futex(uaddr: ?*const volatile u32, op: c_int, val: c_int, timeout: ?*const timespec, uaddr2: ?*const volatile u32) c_int;

pub const login_cap_t = extern struct {
    class: ?[*:0]const u8,
    cap: ?[*:0]const u8,
    style: ?[*:0]const u8,
};

pub extern "c" fn login_getclass(class: ?[*:0]const u8) ?*login_cap_t;
pub extern "c" fn login_getstyle(lc: *login_cap_t, style: ?[*:0]const u8, atype: ?[*:0]const u8) ?[*:0]const u8;
pub extern "c" fn login_getcapbool(lc: *login_cap_t, cap: [*:0]const u8, def: c_int) c_int;
pub extern "c" fn login_getcapnum(lc: *login_cap_t, cap: [*:0]const u8, def: i64, err: i64) i64;
pub extern "c" fn login_getcapsize(lc: *login_cap_t, cap: [*:0]const u8, def: i64, err: i64) i64;
pub extern "c" fn login_getcapstr(lc: *login_cap_t, cap: [*:0]const u8, def: [*:0]const u8, err: [*:0]const u8) [*:0]const u8;
pub extern "c" fn login_getcaptime(lc: *login_cap_t, cap: [*:0]const u8, def: i64, err: i64) i64;
pub extern "c" fn login_close(lc: *login_cap_t) void;
pub extern "c" fn setclasscontext(class: [*:0]const u8, flags: c_uint) c_int;
pub extern "c" fn setusercontext(lc: *login_cap_t, pwd: *passwd, uid: uid_t, flags: c_uint) c_int;

pub const auth_session_t = opaque {};

pub extern "c" fn auth_userokay(name: [*:0]const u8, style: ?[*:0]const u8, arg_type: ?[*:0]const u8, password: ?[*:0]const u8) c_int;
pub extern "c" fn auth_approval(as: ?*auth_session_t, ?*login_cap_t, name: ?[*:0]const u8, type: ?[*:0]const u8) c_int;
pub extern "c" fn auth_userchallenge(name: [*:0]const u8, style: ?[*:0]const u8, arg_type: ?[*:0]const u8, chappengep: *?[*:0]const u8) ?*auth_session_t;
pub extern "c" fn auth_userresponse(as: *auth_session_t, response: [*:0]const u8, more: c_int) c_int;
pub extern "c" fn auth_usercheck(name: [*:0]const u8, style: ?[*:0]const u8, arg_type: ?[*:0]const u8, password: ?[*:0]const u8) ?*auth_session_t;
pub extern "c" fn auth_open() ?*auth_session_t;
pub extern "c" fn auth_close(as: *auth_session_t) c_int;
pub extern "c" fn auth_setdata(as: *auth_session_t, ptr: *anyopaque, len: usize) c_int;
pub extern "c" fn auth_setitem(as: *auth_session_t, item: auth_item_t, value: [*:0]const u8) c_int;
pub extern "c" fn auth_getitem(as: *auth_session_t, item: auth_item_t) ?[*:0]const u8;
pub extern "c" fn auth_setoption(as: *auth_session_t, n: [*:0]const u8, v: [*:0]const u8) c_int;
pub extern "c" fn auth_setstate(as: *auth_session_t, s: c_int) void;
pub extern "c" fn auth_getstate(as: *auth_session_t) c_int;
pub extern "c" fn auth_clean(as: *auth_session_t) void;
pub extern "c" fn auth_clrenv(as: *auth_session_t) void;
pub extern "c" fn auth_clroption(as: *auth_session_t, option: [*:0]const u8) void;
pub extern "c" fn auth_clroptions(as: *auth_session_t) void;
pub extern "c" fn auth_setenv(as: *auth_session_t) void;
pub extern "c" fn auth_getvalue(as: *auth_session_t, what: [*:0]const u8) ?[*:0]const u8;
pub extern "c" fn auth_verify(as: ?*auth_session_t, style: ?[*:0]const u8, name: ?[*:0]const u8, ...) ?*auth_session_t;
pub extern "c" fn auth_call(as: *auth_session_t, path: [*:0]const u8, ...) c_int;
pub extern "c" fn auth_challenge(as: *auth_session_t) [*:0]const u8;
pub extern "c" fn auth_check_expire(as: *auth_session_t) i64;
pub extern "c" fn auth_check_change(as: *auth_session_t) i64;
pub extern "c" fn auth_getpwd(as: *auth_session_t) ?*passwd;
pub extern "c" fn auth_setpwd(as: *auth_session_t, pwd: *passwd) c_int;
pub extern "c" fn auth_mkvalue(value: [*:0]const u8) ?[*:0]const u8;
pub extern "c" fn auth_cat(file: [*:0]const u8) c_int;
pub extern "c" fn auth_checknologin(lc: *login_cap_t) void;
// TODO: auth_set_va_list requires zig support for va_list type (#515)

pub extern "c" fn getpwuid_shadow(uid: uid_t) ?*passwd;
pub extern "c" fn getpwnam_shadow(name: [*:0]const u8) ?*passwd;
pub extern "c" fn getpwnam_r(name: [*:0]const u8, pw: *passwd, buf: [*]u8, buflen: usize, pwretp: *?*passwd) c_int;
pub extern "c" fn getpwuid_r(uid: uid_t, pw: *passwd, buf: [*]u8, buflen: usize, pwretp: *?*passwd) c_int;
pub extern "c" fn getpwent() ?*passwd;
pub extern "c" fn setpwent() void;
pub extern "c" fn endpwent() void;
pub extern "c" fn setpassent(stayopen: c_int) c_int;
pub extern "c" fn uid_from_user(name: [*:0]const u8, uid: *uid_t) c_int;
pub extern "c" fn user_from_uid(uid: uid_t, noname: c_int) ?[*:0]const u8;
pub extern "c" fn bcrypt_gensalt(log_rounds: u8) [*:0]const u8;
pub extern "c" fn bcrypt(pass: [*:0]const u8, salt: [*:0]const u8) ?[*:0]const u8;
pub extern "c" fn bcrypt_newhash(pass: [*:0]const u8, log_rounds: c_int, hash: [*]u8, hashlen: usize) c_int;
pub extern "c" fn bcrypt_checkpass(pass: [*:0]const u8, goodhash: [*:0]const u8) c_int;
pub extern "c" fn pw_du```
