```
size, *u32) callconv(cc) Status,

    /// Copies the contents of one buffer to another buffer
    copyMem: *const fn (dest: [*]u8, src: [*]const u8, len: usize) callconv(cc) void,

    /// Fills a buffer with a specified value
    setMem: *const fn (buffer: [*]u8, size: usize, value: u8) callconv(cc) void,

    /// Creates an event in a group.
    createEventEx: *const fn (type: u32, notify_tpl: usize, notify_func: EventNotify, notify_ctx: *const anyopaque, event_group: *align(8) const Guid, event: *Event) callconv(cc) Status,

    /// Opens a protocol with a structure as the loaded image for a UEFI application
    pub fn openProtocolSt(self: *BootServices, comptime protocol: type, handle: Handle) !*protocol {
        if (!@hasDecl(protocol, "guid"))
            @compileError("Protocol is missing guid!");

        var ptr: ?*protocol = undefined;

        try self.openProtocol(
            handle,
            &protocol.guid,
            @as(*?*anyopaque, @ptrCast(&ptr)),
            // Invoking handle (loaded image)
            uefi.handle,
            // Control handle (null as not a driver)
            null,
            uefi.tables.OpenProtocolAttributes{ .by_handle_protocol = true },
        ).err();

        return ptr.?;
    }

    pub const signature: u64 = 0x56524553544f4f42;

    pub const event_timer: u32 = 0x80000000;
    pub const event_runtime: u32 = 0x40000000;
    pub const event_notify_wait: u32 = 0x00000100;
    pub const event_notify_signal: u32 = 0x00000200;
    pub const event_signal_exit_boot_services: u32 = 0x00000201;
    pub const event_signal_virtual_address_change: u32 = 0x00000202;

    pub const tpl_application: usize = 4;
    pub const tpl_callback: usize = 8;
    pub const tpl_notify: usize = 16;
    pub const tpl_high_level: usize = 31;
};
const uefi = @import("std").os.uefi;
const Guid = uefi.Guid;

pub const ConfigurationTable = extern struct {
    vendor_guid: Guid,
    vendor_table: *anyopaque,

    pub const acpi_20_table_guid align(8) = Guid{
        .time_low = 0x8868e871,
        .time_mid = 0xe4f1,
        .time_high_and_version = 0x11d3,
        .clock_seq_high_and_reserved = 0xbc,
        .clock_seq_low = 0x22,
        .node = [_]u8{ 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 },
    };
    pub const acpi_10_table_guid align(8) = Guid{
        .time_low = 0xeb9d2d30,
        .time_mid = 0x2d88,
        .time_high_and_version = 0x11d3,
        .clock_seq_high_and_reserved = 0x9a,
        .clock_seq_low = 0x16,
        .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
    };
    pub const sal_system_table_guid align(8) = Guid{
        .time_low = 0xeb9d2d32,
        .time_mid = 0x2d88,
        .time_high_and_version = 0x113d,
        .clock_seq_high_and_reserved = 0x9a,
        .clock_seq_low = 0x16,
        .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
    };
    pub const smbios_table_guid align(8) = Guid{
        .time_low = 0xeb9d2d31,
        .time_mid = 0x2d88,
        .time_high_and_version = 0x11d3,
        .clock_seq_high_and_reserved = 0x9a,
        .clock_seq_low = 0x16,
        .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
    };
    pub const smbios3_table_guid align(8) = Guid{
        .time_low = 0xf2fd1544,
        .time_mid = 0x9794,
        .time_high_and_version = 0x4a2c,
        .clock_seq_high_and_reserved = 0x99,
        .clock_seq_low = 0x2e,
        .node = [_]u8{ 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94 },
    };
    pub const mps_table_guid align(8) = Guid{
        .time_low = 0xeb9d2d2f,
        .time_mid = 0x2d88,
        .time_high_and_version = 0x11d3,
        .clock_seq_high_and_reserved = 0x9a,
        .clock_seq_low = 0x16,
        .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
    };
    pub const json_config_data_table_guid align(8) = Guid{
        .time_low = 0x87367f87,
        .time_mid = 0x1119,
        .time_high_and_version = 0x41ce,
        .clock_seq_high_and_reserved = 0xaa,
        .clock_seq_low = 0xec,
        .node = [_]u8{ 0x8b, 0xe0, 0x11, 0x1f, 0x55, 0x8a },
    };
    pub const json_capsule_data_table_guid align(8) = Guid{
        .time_low = 0x35e7a725,
        .time_mid = 0x8dd2,
        .time_high_and_version = 0x4cac,
        .clock_seq_high_and_reserved = 0x80,
        .clock_seq_low = 0x11,
        .node = [_]u8{ 0x33, 0xcd, 0xa8, 0x10, 0x90, 0x56 },
    };
    pub const json_capsule_result_table_guid align(8) = Guid{
        .time_low = 0xdbc461c3,
        .time_mid = 0xb3de,
        .time_high_and_version = 0x422a,
        .clock_seq_high_and_reserved = 0xb9,
        .clock_seq_low = 0xb4,
        .node = [_]u8{ 0x98, 0x86, 0xfd, 0x49, 0xa1, 0xe5 },
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const TableHeader = uefi.tables.TableHeader;
const Time = uefi.Time;
const TimeCapabilities = uefi.TimeCapabilities;
const Status = uefi.Status;
const MemoryDescriptor = uefi.tables.MemoryDescriptor;
const ResetType = uefi.tables.ResetType;
const CapsuleHeader = uefi.tables.CapsuleHeader;
const PhysicalAddress = uefi.tables.PhysicalAddress;
const cc = uefi.cc;

/// Runtime services are provided by the firmware before and after exitBootServices has been called.
///
/// As the runtime_services table may grow with new UEFI versions, it is important to check hdr.header_size.
///
/// Some functions may not be supported. Check the RuntimeServicesSupported variable using getVariable.
/// getVariable is one of the functions that may not be supported.
///
/// Some functions may not be called while other functions are running.
pub const RuntimeServices = extern struct {
    hdr: TableHeader,

    /// Returns the current time and date information, and the time-keeping capabilities of the hardware platform.
    getTime: *const fn (time: *uefi.Time, capabilities: ?*TimeCapabilities) callconv(cc) Status,

    /// Sets the current local time and date information
    setTime: *const fn (time: *uefi.Time) callconv(cc) Status,

    /// Returns the current wakeup alarm clock setting
    getWakeupTime: *const fn (enabled: *bool, pending: *bool, time: *uefi.Time) callconv(cc) Status,

    /// Sets the system wakeup alarm clock time
    setWakeupTime: *const fn (enable: *bool, time: ?*uefi.Time) callconv(cc) Status,

    /// Changes the runtime addressing mode of EFI firmware from physical to virtual.
    setVirtualAddressMap: *const fn (mmap_size: usize, descriptor_size: usize, descriptor_version: u32, virtual_map: [*]MemoryDescriptor) callconv(cc) Status,

    /// Determines the new virtual address that is to be used on subsequent memory accesses.
    convertPointer: *const fn (debug_disposition: usize, address: **anyopaque) callconv(cc) Status,

    /// Returns the value of a variable.
    getVariable: *const fn (var_name: [*:0]const u16, vendor_guid: *align(8) const Guid, attributes: ?*u32, data_size: *usize, data: ?*anyopaque) callconv(cc) Status,

    /// Enumerates the current variable names.
    getNextVariableName: *const fn (var_name_size: *usize, var_name: [*:0]u16, vendor_guid: *align(8) Guid) callconv(cc) Status,

    /// Sets the value of a variable.
    setVariable: *const fn (var_name: [*:0]const u16, vendor_guid: *align(8) const Guid, attributes: u32, data_size: usize, data: *anyopaque) callconv(cc) Status,

    /// Return the next high 32 bits of the platform's monotonic counter
    getNextHighMonotonicCount: *const fn (high_count: *u32) callconv(cc) Status,

    /// Resets the entire platform.
    resetSystem: *const fn (reset_type: ResetType, reset_status: Status, data_size: usize, reset_data: ?*const anyopaque) callconv(cc) noreturn,

    /// Passes capsules to the firmware with both virtual and physical mapping.
    /// Depending on the intended consumption, the firmware may process the capsule immediately.
    /// If the payload should persist across a system reset, the reset value returned from
    /// `queryCapsuleCapabilities` must be passed into resetSystem and will cause the capsule
    /// to be processed by the firmware as part of the reset process.
    updateCapsule: *const fn (capsule_header_array: **CapsuleHeader, capsule_count: usize, scatter_gather_list: PhysicalAddress) callconv(cc) Status,

    /// Returns if the capsule can be supported via `updateCapsule`
    queryCapsuleCapabilities: *const fn (capsule_header_array: **CapsuleHeader, capsule_count: usize, maximum_capsule_size: *usize, reset_type: ResetType) callconv(cc) Status,

    /// Returns information about the EFI variables
    queryVariableInfo: *const fn (attributes: *u32, maximum_variable_storage_size: *u64, remaining_variable_storage_size: *u64, maximum_variable_size: *u64) callconv(cc) Status,

    pub const signature: u64 = 0x56524553544e5552;
};
const uefi = @import("std").os.uefi;
const BootServices = uefi.tables.BootServices;
const ConfigurationTable = uefi.tables.ConfigurationTable;
const Handle = uefi.Handle;
const RuntimeServices = uefi.tables.RuntimeServices;
const SimpleTextInputProtocol = uefi.protocol.SimpleTextInput;
const SimpleTextOutputProtocol = uefi.protocol.SimpleTextOutput;
const TableHeader = uefi.tables.TableHeader;

/// The EFI System Table contains pointers to the runtime and boot services tables.
///
/// As the system_table may grow with new UEFI versions, it is important to check hdr.header_size.
///
/// After successfully calling boot_services.exitBootServices, console_in_handle,
/// con_in, console_out_handle, con_out, standard_error_handle, std_err, and
/// boot_services should be set to null. After setting these attributes to null,
/// hdr.crc32 must be recomputed.
pub const SystemTable = extern struct {
    hdr: TableHeader,

    /// A null-terminated string that identifies the vendor that produces the system firmware of the platform.
    firmware_vendor: [*:0]u16,
    firmware_revision: u32,
    console_in_handle: ?Handle,
    con_in: ?*SimpleTextInputProtocol,
    console_out_handle: ?Handle,
    con_out: ?*SimpleTextOutputProtocol,
    standard_error_handle: ?Handle,
    std_err: ?*SimpleTextOutputProtocol,
    runtime_services: *RuntimeServices,
    boot_services: ?*BootServices,
    number_of_table_entries: usize,
    configuration_table: [*]ConfigurationTable,

    pub const signature: u64 = 0x5453595320494249;
    pub const revision_1_02: u32 = (1 << 16) | 2;
    pub const revision_1_10: u32 = (1 << 16) | 10;
    pub const revision_2_00: u32 = (2 << 16);
    pub const revision_2_10: u32 = (2 << 16) | 10;
    pub const revision_2_20: u32 = (2 << 16) | 20;
    pub const revision_2_30: u32 = (2 << 16) | 30;
    pub const revision_2_31: u32 = (2 << 16) | 31;
    pub const revision_2_40: u32 = (2 << 16) | 40;
    pub const revision_2_50: u32 = (2 << 16) | 50;
    pub const revision_2_60: u32 = (2 << 16) | 60;
    pub const revision_2_70: u32 = (2 << 16) | 70;
    pub const revision_2_80: u32 = (2 << 16) | 80;
    pub const revision_2_90: u32 = (2 << 16) | 90;
    pub const revision_2_100: u32 = (2 << 16) | 100;
    pub const revision_2_110: u32 = (2 << 16) | 110;
};
pub const TableHeader = extern struct {
    signature: u64,
    revision: u32,

    /// The size, in bytes, of the entire table including the TableHeader
    header_size: u32,
    crc32: u32,
    reserved: u32,
};
//! wasi_snapshot_preview1 spec available (in witx format) here:
//! * typenames -- https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/witx/typenames.witx
//! * module -- https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/witx/wasi_snapshot_preview1.witx
//! Note that libc API does *not* go in this file. wasi libc API goes into std/c.zig instead.
const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;

comptime {
    if (builtin.os.tag == .wasi) {
        assert(@alignOf(i8) == 1);
        assert(@alignOf(u8) == 1);
        assert(@alignOf(i16) == 2);
        assert(@alignOf(u16) == 2);
        assert(@alignOf(i32) == 4);
        assert(@alignOf(u32) == 4);
        assert(@alignOf(i64) == 8);
        assert(@alignOf(u64) == 8);
    }
}

pub const iovec_t = std.posix.iovec;
pub const ciovec_t = std.posix.iovec_const;

pub extern "wasi_snapshot_preview1" fn args_get(argv: [*][*:0]u8, argv_buf: [*]u8) errno_t;
pub extern "wasi_snapshot_preview1" fn args_sizes_get(argc: *usize, argv_buf_size: *usize) errno_t;

pub extern "wasi_snapshot_preview1" fn clock_res_get(clock_id: clockid_t, resolution: *timestamp_t) errno_t;
pub extern "wasi_snapshot_preview1" fn clock_time_get(clock_id: clockid_t, precision: timestamp_t, timestamp: *timestamp_t) errno_t;

pub extern "wasi_snapshot_preview1" fn environ_get(environ: [*][*:0]u8, environ_buf: [*]u8) errno_t;
pub extern "wasi_snapshot_preview1" fn environ_sizes_get(environ_count: *usize, environ_buf_size: *usize) errno_t;

pub extern "wasi_snapshot_preview1" fn fd_advise(fd: fd_t, offset: filesize_t, len: filesize_t, advice: advice_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_allocate(fd: fd_t, offset: filesize_t, len: filesize_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_close(fd: fd_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_datasync(fd: fd_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_pread(fd: fd_t, iovs: [*]const iovec_t, iovs_len: usize, offset: filesize_t, nread: *usize) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_pwrite(fd: fd_t, iovs: [*]const ciovec_t, iovs_len: usize, offset: filesize_t, nwritten: *usize) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_read(fd: fd_t, iovs: [*]const iovec_t, iovs_len: usize, nread: *usize) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_readdir(fd: fd_t, buf: [*]u8, buf_len: usize, cookie: dircookie_t, bufused: *usize) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_renumber(from: fd_t, to: fd_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_seek(fd: fd_t, offset: filedelta_t, whence: whence_t, newoffset: *filesize_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_sync(fd: fd_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_tell(fd: fd_t, newoffset: *filesize_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_write(fd: fd_t, iovs: [*]const ciovec_t, iovs_len: usize, nwritten: *usize) errno_t;

pub extern "wasi_snapshot_preview1" fn fd_fdstat_get(fd: fd_t, buf: *fdstat_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_fdstat_set_flags(fd: fd_t, flags: fdflags_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_fdstat_set_rights(fd: fd_t, fs_rights_base: rights_t, fs_rights_inheriting: rights_t) errno_t;

pub extern "wasi_snapshot_preview1" fn fd_filestat_get(fd: fd_t, buf: *filestat_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_filestat_set_size(fd: fd_t, st_size: filesize_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_filestat_set_times(fd: fd_t, st_atim: timestamp_t, st_mtim: timestamp_t, fstflags: fstflags_t) errno_t;

pub extern "wasi_snapshot_preview1" fn fd_prestat_get(fd: fd_t, buf: *prestat_t) errno_t;
pub extern "wasi_snapshot_preview1" fn fd_prestat_dir_name(fd: fd_t, path: [*]u8, path_len: usize) errno_t;

pub extern "wasi_snapshot_preview1" fn path_create_directory(fd: fd_t, path: [*]const u8, path_len: usize) errno_t;
pub extern "wasi_snapshot_preview1" fn path_filestat_get(fd: fd_t, flags: lookupflags_t, path: [*]const u8, path_len: usize, buf: *filestat_t) errno_t;
pub extern "wasi_snapshot_preview1" fn path_filestat_set_times(fd: fd_t, flags: lookupflags_t, path: [*]const u8, path_len: usize, st_atim: timestamp_t, st_mtim: timestamp_t, fstflags: fstflags_t) errno_t;
pub extern "wasi_snapshot_preview1" fn path_link(old_fd: fd_t, old_flags: lookupflags_t, old_path: [*]const u8, old_path_len: usize, new_fd: fd_t, new_path: [*]const u8, new_path_len: usize) errno_t;
pub extern "wasi_snapshot_preview1" fn path_open(dirfd: fd_t, dirflags: lookupflags_t, path: [*]const u8, path_len: usize, oflags: oflags_t, fs_rights_base: rights_t, fs_rights_inheriting: rights_t, fs_flags: fdflags_t, fd: *fd_t) errno_t;
pub extern "wasi_snapshot_preview1" fn path_readlink(fd: fd_t, path: [*]const u8, path_len: usize, buf: [*]u8, buf_len: usize, bufused: *usize) errno_t;
pub extern "wasi_snapshot_preview1" fn path_remove_directory(fd: fd_t, path: [*]const u8, path_len: usize) errno_t;
pub extern "wasi_snapshot_preview1" fn path_rename(old_fd: fd_t, old_path: [*]const u8, old_path_len: usize, new_fd: fd_t, new_path: [*]const u8, new_path_len: usize) errno_t;
pub extern "wasi_snapshot_preview1" fn path_symlink(old_path: [*]const u8, old_path_len: usize, fd: fd_t, new_path: [*]const u8, new_path_len: usize) errno_t;
pub extern "wasi_snapshot_preview1" fn path_unlink_file(fd: fd_t, path: [*]const u8, path_len: usize) errno_t;

pub extern "wasi_snapshot_preview1" fn poll_oneoff(in: *const subscription_t, out: *event_t, nsubscriptions: usize, nevents: *usize) errno_t;

pub extern "wasi_snapshot_preview1" fn proc_exit(rval: exitcode_t) noreturn;

pub extern "wasi_snapshot_preview1" fn random_get(buf: [*]u8, buf_len: usize) errno_t;

pub extern "wasi_snapshot_preview1" fn sched_yield() errno_t;

pub extern "wasi_snapshot_preview1" fn sock_accept(sock: fd_t, flags: fdflags_t, result_fd: *fd_t) errno_t;
pub extern "wasi_snapshot_preview1" fn sock_recv(sock: fd_t, ri_data: [*]iovec_t, ri_data_len: usize, ri_flags: riflags_t, ro_datalen: *usize, ro_flags: *roflags_t) errno_t;
pub extern "wasi_snapshot_preview1" fn sock_send(sock: fd_t, si_data: [*]const ciovec_t, si_data_len: usize, si_flags: siflags_t, so_datalen: *usize) errno_t;
pub extern "wasi_snapshot_preview1" fn sock_shutdown(sock: fd_t, how: sdflags_t) errno_t;

// As defined in the wasi_snapshot_preview1 spec file:
// https://github.com/WebAssembly/WASI/blob/master/phases/snapshot/witx/typenames.witx
pub const advice_t = enum(u8) {
    NORMAL = 0,
    SEQUENTIAL = 1,
    RANDOM = 2,
    WILLNEED = 3,
    DONTNEED = 4,
    NOREUSE = 5,
};

pub const clockid_t = enum(u32) {
    REALTIME = 0,
    MONOTONIC = 1,
    PROCESS_CPUTIME_ID = 2,
    THREAD_CPUTIME_ID = 3,
};

pub const device_t = u64;

pub const dircookie_t = u64;
pub const DIRCOOKIE_START: dircookie_t = 0;

pub const dirnamlen_t = u32;

pub const dirent_t = extern struct {
    next: dircookie_t,
    ino: inode_t,
    namlen: dirnamlen_t,
    type: filetype_t,
};

pub const errno_t = enum(u16) {
    SUCCESS = 0,
    @"2BIG" = 1,
    ACCES = 2,
    ADDRINUSE = 3,
    ADDRNOTAVAIL = 4,
    AFNOSUPPORT = 5,
    /// This is also the error code used for `WOULDBLOCK`.
    AGAIN = 6,
    ALREADY = 7,
    BADF = 8,
    BADMSG = 9,
    BUSY = 10,
    CANCELED = 11,
    CHILD = 12,
    CONNABORTED = 13,
    CONNREFUSED = 14,
    CONNRESET = 15,
    DEADLK = 16,
    DESTADDRREQ = 17,
    DOM = 18,
    DQUOT = 19,
    EXIST = 20,
    FAULT = 21,
    FBIG = 22,
    HOSTUNREACH = 23,
    IDRM = 24,
    ILSEQ = 25,
    INPROGRESS = 26,
    INTR = 27,
    INVAL = 28,
    IO = 29,
    ISCONN = 30,
    ISDIR = 31,
    LOOP = 32,
    MFILE = 33,
    MLINK = 34,
    MSGSIZE = 35,
    MULTIHOP = 36,
    NAMETOOLONG = 37,
    NETDOWN = 38,
    NETRESET = 39,
    NETUNREACH = 40,
    NFILE = 41,
    NOBUFS = 42,
    NODEV = 43,
    NOENT = 44,
    NOEXEC = 45,
    NOLCK = 46,
    NOLINK = 47,
    NOMEM = 48,
    NOMSG = 49,
    NOPROTOOPT = 50,
    NOSPC = 51,
    NOSYS = 52,
    NOTCONN = 53,
    NOTDIR = 54,
    NOTEMPTY = 55,
    NOTRECOVERABLE = 56,
    NOTSOCK = 57,
    /// This is also the code used for `NOTSUP`.
    OPNOTSUPP = 58,
    NOTTY = 59,
    NXIO = 60,
    OVERFLOW = 61,
    OWNERDEAD = 62,
    PERM = 63,
    PIPE = 64,
    PROTO = 65,
    PROTONOSUPPORT = 66,
    PROTOTYPE = 67,
    RANGE = 68,
    ROFS = 69,
    SPIPE = 70,
    SRCH = 71,
    STALE = 72,
    TIMEDOUT = 73,
    TXTBSY = 74,
    XDEV = 75,
    NOTCAPABLE = 76,
    _,
};

pub const event_t = extern struct {
    userdata: userdata_t,
    @"error": errno_t,
    type: eventtype_t,
    fd_readwrite: eventfdreadwrite_t,
};

pub const eventfdreadwrite_t = extern struct {
    nbytes: filesize_t,
    flags: eventrwflags_t,
};

pub const eventrwflags_t = u16;
pub const EVENT_FD_READWRITE_HANGUP: eventrwflags_t = 0x0001;

pub const eventtype_t = enum(u8) {
    CLOCK = 0,
    FD_READ = 1,
    FD_WRITE = 2,
};

pub const exitcode_t = u32;

pub const fd_t = i32;

pub const fdflags_t = packed struct(u16) {
    APPEND: bool = false,
    DSYNC: bool = false,
    NONBLOCK: bool = false,
    RSYNC: bool = false,
    SYNC: bool = false,
    _: u11 = 0,
};

pub const fdstat_t = extern struct {
    fs_filetype: filetype_t,
    fs_flags: fdflags_t,
    fs_rights_base: rights_t,
    fs_rights_inheriting: rights_t,
};

pub const filedelta_t = i64;

pub const filesize_t = u64;

pub const filestat_t = extern struct {
    dev: device_t,
    ino: inode_t,
    filetype: filetype_t,
    nlink: linkcount_t,
    size: filesize_t,
    atim: timestamp_t,
    mtim: timestamp_t,
    ctim: timestamp_t,
};

pub const filetype_t = enum(u8) {
    UNKNOWN,
    BLOCK_DEVICE,
    CHARACTER_DEVICE,
    DIRECTORY,
    REGULAR_FILE,
    SOCKET_DGRAM,
    SOCKET_STREAM,
    SYMBOLIC_LINK,
    _,
};

pub const fstflags_t = packed struct(u16) {
    ATIM: bool = false,
    ATIM_NOW: bool = false,
    MTIM: bool = false,
    MTIM_NOW: bool = false,
    _: u12 = 0,
};

pub const inode_t = u64;

pub const linkcount_t = u64;

pub const lookupflags_t = packed struct(u32) {
    SYMLINK_FOLLOW: bool = false,
    _: u31 = 0,
};

pub const oflags_t = packed struct(u16) {
    CREAT: bool = false,
    DIRECTORY: bool = false,
    EXCL: bool = false,
    TRUNC: bool = false,
    _: u12 = 0,
};

pub const preopentype_t = u8;
pub const PREOPENTYPE_DIR: preopentype_t = 0;

pub const prestat_t = extern struct {
    pr_type: preopentype_t,
    u: prestat_u_t,
};

pub const prestat_dir_t = extern struct {
    pr_name_len: usize,
};

pub const prestat_u_t = extern union {
    dir: prestat_dir_t,
};

pub const riflags_t = u16;
pub const roflags_t = u16;

pub const SOCK = struct {
    pub const RECV_PEEK: riflags_t = 0x0001;
    pub const RECV_WAITALL: riflags_t = 0x0002;

    pub const RECV_DATA_TRUNCATED: roflags_t = 0x0001;
};

pub const rights_t = packed struct(u64) {
    /// The right to invoke fd_datasync. If PATH_OPEN is set, includes the right to invoke
    /// path_open with fdflags_t.dsync.
    FD_DATASYNC: bool = false,
    /// The right to invoke fd_read and sock_recv. If FD_SEEK is set, includes the right to invoke
    /// fd_pread.
    FD_READ: bool = false,
    /// The right to invoke fd_seek. This flag implies FD_TELL.
    FD_SEEK: bool = false,
    /// The right to invoke fd_fdstat_set_flags.
    FD_FDSTAT_SET_FLAGS: bool = false,
    /// The right to invoke fd_sync. If PATH_OPEN is set, includes the right to invoke path_open
    /// with fdflags_t.RSYNC and fdflags_t.DSYNC.
    FD_SYNC: bool = false,
    /// The right to invoke fd_seek in such a way that the file offset remains unaltered (i.e.
    /// whence_t.CUR with offset zero), or to invoke fd_tell.
    FD_TELL: bool = false,
    /// The right to invoke fd_write and sock_send. If FD_SEEK is set, includes the right to invoke
    /// fd_pwrite.
    FD_WRITE: bool = false,
    /// The right to invoke fd_advise.
    FD_ADVISE: bool = false,
    /// The right to invoke fd_allocate.
    FD_ALLOCATE: bool = false,
    /// The right to invoke path_create_directory.
    PATH_CREATE_DIRECTORY: bool = false,
    /// If PATH_OPEN is set, the right to invoke path_open with oflags_t.CREAT.
    PATH_CREATE_FILE: bool = false,
    /// The right to invoke path_link with the file descriptor as the source directory.
    PATH_LINK_SOURCE: bool = false,
    /// The right to invoke path_link with the file descriptor as the target directory.
    PATH_LINK_TARGET: bool = false,
    /// The right to invoke path_open.
    PATH_OPEN: bool = false,
    /// The right to invoke fd_readdir.
    FD_READDIR: bool = false,
    /// The right to invoke path_readlink.
    PATH_READLINK: bool = false,
    /// The right to invoke path_rename with the file descriptor as the source directory.
    PATH_RENAME_SOURCE: bool = false,
    /// The right to invoke path_rename with the file descriptor as the target directory.
    PATH_RENAME_TARGET: bool = false,
    /// The right to invoke path_filestat_get.
    PATH_FILESTAT_GET: bool = false,
    /// The right to change a file's size. If PATH_OPEN is set, includes the right to invoke
    /// path_open with oflags_t.TRUNC. Note: there is no function named path_filestat_set_size.
    /// This follows POSIX design, which only has ftruncate and does not provide ftruncateat. While
    /// such function would be desirable from the API design perspective, there are virtually no
    /// use cases for it since no code written for POSIX systems would use it. Moreover,
    /// implementing it would require multiple syscalls, leading to inferior performance.
    PATH_FILESTAT_SET_SIZE: bool = false,
    /// The right to invoke path_filestat_set_times.
    PATH_FILESTAT_SET_TIMES: bool = false,
    /// The right to invoke fd_filestat_get.
    FD_FILESTAT_GET: bool = false,
    /// The right to invoke fd_filestat_set_size.
    FD_FILESTAT_SET_SIZE: bool = false,
    /// The right to invoke fd_filestat_set_times.
    FD_FILESTAT_SET_TIMES: bool = false,
    /// The right to invoke path_symlink.
    PATH_SYMLINK: bool = false,
    /// The right to invoke path_remove_directory.
    PATH_REMOVE_DIRECTORY: bool = false,
    /// The right to invoke path_unlink_file.
    PATH_UNLINK_FILE: bool = false,
    /// If FD_READ is set, includes the right to invoke poll_oneoff to subscribe to
    /// eventtype_t.FD_READ. If FD_WRITE is set, includes the right to invoke poll_oneoff to
    /// subscribe to eventtype_t.FD_WRITE.
    POLL_FD_READWRITE: bool = false,
    /// The right to invoke sock_shutdown.
    SOCK_SHUTDOWN: bool = false,
    /// The right to invoke sock_accept.
    SOCK_ACCEPT: bool = false,
    _: u34 = 0,
};

pub const sdflags_t = packed struct(u8) {
    RD: bool = false,
    WR: bool = false,
    _: u6 = 0,
};

pub const siflags_t = u16;

pub const signal_t = enum(u8) {
    NONE = 0,
    HUP = 1,
    INT = 2,
    QUIT = 3,
    ILL = 4,
    TRAP = 5,
    ABRT = 6,
    BUS = 7,
    FPE = 8,
    KILL = 9,
    USR1 = 10,
    SEGV = 11,
    USR2 = 12,
    PIPE = 13,
    ALRM = 14,
    TERM = 15,
    CHLD = 16,
    CONT = 17,
    STOP = 18,
    TSTP = 19,
    TTIN = 20,
    TTOU = 21,
    URG = 22,
    XCPU = 23,
    XFSZ = 24,
    VTALRM = 25,
    PROF = 26,
    WINCH = 27,
    POLL = 28,
    PWR = 29,
    SYS = 30,
};

pub const subclockflags_t = u16;
pub const SUBSCRIPTION_CLOCK_ABSTIME: subclockflags_t = 0x0001;

pub const subscription_t = extern struct {
    userdata: userdata_t,
    u: subscription_u_t,
};

pub const subscription_clock_t = extern struct {
    id: clockid_t,
    timeout: timestamp_t,
    precision: timestamp_t,
    flags: subclockflags_t,
};

pub const subscription_fd_readwrite_t = extern struct {
    fd: fd_t,
};

pub const subscription_u_t = extern struct {
    tag: eventtype_t,
    u: subscription_u_u_t,
};

pub const subscription_u_u_t = extern union {
    clock: subscription_clock_t,
    fd_read: subscription_fd_readwrite_t,
    fd_write: subscription_fd_readwrite_t,
};

/// Nanoseconds.
pub const timestamp_t = u64;

pub const userdata_t = u64;

pub const whence_t = enum(u8) { SET, CUR, END };
//! This file contains thin wrappers around Windows-specific APIs, with these
//! specific goals in mind:
//! * Convert "errno"-style error codes into Zig errors.
//! * When null-terminated or WTF16LE byte buffers are required, provide APIs which accept
//!   slices as well as APIs which accept null-terminated WTF16LE byte buffers.

const builtin = @import("builtin");
const std = @import("../std.zig");
const mem = std.mem;
const assert = std.debug.assert;
const math = std.math;
const maxInt = std.math.maxInt;
const native_arch = builtin.cpu.arch;
const UnexpectedError = std.posix.UnexpectedError;

test {
    if (builtin.os.tag == .windows) {
        _ = @import("windows/test.zig");
    }
}

pub const advapi32 = @import("windows/advapi32.zig");
pub const kernel32 = @import("windows/kernel32.zig");
pub const ntdll = @import("windows/ntdll.zig");
pub const ws2_32 = @import("windows/ws2_32.zig");
pub const crypt32 = @import("windows/crypt32.zig");
pub const nls = @import("windows/nls.zig");

pub const self_process_handle = @as(HANDLE, @ptrFromInt(maxInt(usize)));

const Self = @This();

pub const OpenError = error{
    IsDir,
    NotDir,
    FileNotFound,
    NoDevice,
    AccessDenied,
    PipeBusy,
    PathAlreadyExists,
    Unexpected,
    NameTooLong,
    WouldBlock,
    NetworkNotFound,
    AntivirusInterference,
    BadPathName,
};

pub const OpenFileOptions = struct {
    access_mask: ACCESS_MASK,
    dir: ?HANDLE = null,
    sa: ?*SECURITY_ATTRIBUTES = null,
    share_access: ULONG = FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
    creation: ULONG,
    /// If true, tries to open path as a directory.
    /// Defaults to false.
    filter: Filter = .file_only,
    /// If false, tries to open path as a reparse point without dereferencing it.
    /// Defaults to true.
    follow_symlinks: bool = true,

    pub const Filter = enum {
        /// Causes `OpenFile` to return `error.IsDir` if the opened handle would be a directory.
        file_only,
        /// Causes `OpenFile` to return `error.NotDir` if the opened handle would be a file.
        dir_only,
        /// `OpenFile` does not discriminate between opening files and directories.
        any,
    };
};

pub fn OpenFile(sub_path_w: []const u16, options: OpenFileOptions) OpenError!HANDLE {
    if (mem.eql(u16, sub_path_w, &[_]u16{'.'}) and options.filter == .file_only) {
        return error.IsDir;
    }
    if (mem.eql(u16, sub_path_w, &[_]u16{ '.', '.' }) and options.filter == .file_only) {
        return error.IsDir;
    }

    var result: HANDLE = undefined;

    const path_len_bytes = math.cast(u16, sub_path_w.len * 2) orelse return error.NameTooLong;
    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(sub_path_w.ptr),
    };
    var attr = OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = if (std.fs.path.isAbsoluteWindowsWTF16(sub_path_w)) null else options.dir,
        .Attributes = if (options.sa) |ptr| blk: { // Note we do not use OBJ_CASE_INSENSITIVE here.
            const inherit: ULONG = if (ptr.bInheritHandle == TRUE) OBJ_INHERIT else 0;
            break :blk inherit;
        } else 0,
        .ObjectName = &nt_name,
        .SecurityDescriptor = if (options.sa) |ptr| ptr.lpSecurityDescriptor else null,
        .SecurityQualityOfService = null,
    };
    var io: IO_STATUS_BLOCK = undefined;
    const blocking_flag: ULONG = FILE_SYNCHRONOUS_IO_NONALERT;
    const file_or_dir_flag: ULONG = switch (options.filter) {
        .file_only => FILE_NON_DIRECTORY_FILE,
        .dir_only => FILE_DIRECTORY_FILE,
        .any => 0,
    };
    // If we're not following symlinks, we need to ensure we don't pass in any synchronization flags such as FILE_SYNCHRONOUS_IO_NONALERT.
    const flags: ULONG = if (options.follow_symlinks) file_or_dir_flag | blocking_flag else file_or_dir_flag | FILE_OPEN_REPARSE_POINT;

    while (true) {
        const rc = ntdll.NtCreateFile(
            &result,
            options.access_mask,
            &attr,
            &io,
            null,
            FILE_ATTRIBUTE_NORMAL,
            options.share_access,
            options.creation,
            flags,
            null,
            0,
        );
        switch (rc) {
            .SUCCESS => return result,
            .OBJECT_NAME_INVALID => return error.BadPathName,
            .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
            .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
            .BAD_NETWORK_PATH => return error.NetworkNotFound, // \\server was not found
            .BAD_NETWORK_NAME => return error.NetworkNotFound, // \\server was found but \\server\share wasn't
            .NO_MEDIA_IN_DEVICE => return error.NoDevice,
            .INVALID_PARAMETER => unreachable,
            .SHARING_VIOLATION => return error.AccessDenied,
            .ACCESS_DENIED => return error.AccessDenied,
            .PIPE_BUSY => return error.PipeBusy,
            .PIPE_NOT_AVAILABLE => return error.NoDevice,
            .OBJECT_PATH_SYNTAX_BAD => unreachable,
            .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
            .FILE_IS_A_DIRECTORY => return error.IsDir,
            .NOT_A_DIRECTORY => return error.NotDir,
            .USER_MAPPED_FILE => return error.AccessDenied,
            .INVALID_HANDLE => unreachable,
            .DELETE_PENDING => {
                // This error means that there *was* a file in this location on
                // the file system, but it was deleted. However, the OS is not
                // finished with the deletion operation, and so this CreateFile
                // call has failed. There is not really a sane way to handle
                // this other than retrying the creation after the OS finishes
                // the deletion.
                std.time.sleep(std.time.ns_per_ms);
                continue;
            },
            .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
            else => return unexpectedStatus(rc),
        }
    }
}

pub fn GetCurrentProcess() HANDLE {
    const process_pseudo_handle: usize = @bitCast(@as(isize, -1));
    return @ptrFromInt(process_pseudo_handle);
}

pub fn GetCurrentProcessId() DWORD {
    return @truncate(@intFromPtr(teb().ClientId.UniqueProcess));
}

pub fn GetCurrentThread() HANDLE {
    const thread_pseudo_handle: usize = @bitCast(@as(isize, -2));
    return @ptrFromInt(thread_pseudo_handle);
}

pub fn GetCurrentThreadId() DWORD {
    return @truncate(@intFromPtr(teb().ClientId.UniqueThread));
}

pub fn GetLastError() Win32Error {
    return @enumFromInt(teb().LastErrorValue);
}

pub const CreatePipeError = error{ Unexpected, SystemResources };

var npfs: ?HANDLE = null;

/// A Zig wrapper around `NtCreateNamedPipeFile` and `NtCreateFile` syscalls.
/// It implements similar behavior to `CreatePipe` and is meant to serve
/// as a direct substitute for that call.
pub fn CreatePipe(rd: *HANDLE, wr: *HANDLE, sattr: *const SECURITY_ATTRIBUTES) CreatePipeError!void {
    // Up to NT 5.2 (Windows XP/Server 2003), `CreatePipe` would generate a pipe similar to:
    //
    //      \??\pipe\Win32Pipes.{pid}.{count}
    //
    // where `pid` is the process id and count is a incrementing counter.
    // The implementation was changed after NT 6.0 (Vista) to open a handle to the Named Pipe File System
    // and use that as the root directory for `NtCreateNamedPipeFile`.
    // This object is visible under the NPFS but has no filename attached to it.
    //
    // This implementation replicates how `CreatePipe` works in modern Windows versions.
    const opt_dev_handle = @atomicLoad(?HANDLE, &npfs, .seq_cst);
    const dev_handle = opt_dev_handle orelse blk: {
        const str = std.unicode.utf8ToUtf16LeStringLiteral("\\Device\\NamedPipe\\");
        const len: u16 = @truncate(str.len * @sizeOf(u16));
        const name = UNICODE_STRING{
            .Length = len,
            .MaximumLength = len,
            .Buffer = @constCast(@ptrCast(str)),
        };
        const attrs = OBJECT_ATTRIBUTES{
            .ObjectName = @constCast(&name),
            .Length = @sizeOf(OBJECT_ATTRIBUTES),
            .RootDirectory = null,
            .Attributes = 0,
            .SecurityDescriptor = null,
            .SecurityQualityOfService = null,
        };

        var iosb: IO_STATUS_BLOCK = undefined;
        var handle: HANDLE = undefined;
        switch (ntdll.NtCreateFile(
            &handle,
            GENERIC_READ | SYNCHRONIZE,
            @constCast(&attrs),
            &iosb,
            null,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            null,
            0,
        )) {
            .SUCCESS => {},
            // Judging from the ReactOS sources this is technically possible.
            .INSUFFICIENT_RESOURCES => return error.SystemResources,
            .INVALID_PARAMETER => unreachable,
            else => |e| return unexpectedStatus(e),
        }
        if (@cmpxchgStrong(?HANDLE, &npfs, null, handle, .seq_cst, .seq_cst)) |xchg| {
            CloseHandle(handle);
            break :blk xchg.?;
        } else break :blk handle;
    };

    const name = UNICODE_STRING{ .Buffer = null, .Length = 0, .MaximumLength = 0 };
    var attrs = OBJECT_ATTRIBUTES{
        .ObjectName = @constCast(&name),
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = dev_handle,
        .Attributes = OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = sattr.lpSecurityDescriptor,
        .SecurityQualityOfService = null,
    };
    if (sattr.bInheritHandle != 0) attrs.Attributes |= OBJ_INHERIT;

    // 120 second relative timeout in 100ns units.
    const default_timeout: LARGE_INTEGER = (-120 * std.time.ns_per_s) / 100;
    var iosb: IO_STATUS_BLOCK = undefined;
    var read: HANDLE = undefined;
    switch (ntdll.NtCreateNamedPipeFile(
        &read,
        GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        &attrs,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_PIPE_BYTE_STREAM_TYPE,
        FILE_PIPE_BYTE_STREAM_MODE,
        FILE_PIPE_QUEUE_OPERATION,
        1,
        4096,
        4096,
        @constCast(&default_timeout),
    )) {
        .SUCCESS => {},
        .INVALID_PARAMETER => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |e| return unexpectedStatus(e),
    }
    errdefer CloseHandle(read);

    attrs.RootDirectory = read;

    var write: HANDLE = undefined;
    switch (ntdll.NtCreateFile(
        &write,
        GENERIC_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        &attrs,
        &iosb,
        null,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        null,
        0,
    )) {
        .SUCCESS => {},
        .INVALID_PARAMETER => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |e| return unexpectedStatus(e),
    }

    rd.* = read;
    wr.* = write;
}

pub fn CreateEventEx(attributes: ?*SECURITY_ATTRIBUTES, name: []const u8, flags: DWORD, desired_access: DWORD) !HANDLE {
    const nameW = try sliceToPrefixedFileW(null, name);
    return CreateEventExW(attributes, nameW.span().ptr, flags, desired_access);
}

pub fn CreateEventExW(attributes: ?*SECURITY_ATTRIBUTES, nameW: ?LPCWSTR, flags: DWORD, desired_access: DWORD) !HANDLE {
    const handle = kernel32.CreateEventExW(attributes, nameW, flags, desired_access);
    if (handle) |h| {
        return h;
    } else {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const DeviceIoControlError = error{
    AccessDenied,
    /// The volume does not contain a recognized file system. File system
    /// drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
    Unexpected,
};

/// A Zig wrapper around `NtDeviceIoControlFile` and `NtFsControlFile` syscalls.
/// It implements similar behavior to `DeviceIoControl` and is meant to serve
/// as a direct substitute for that call.
/// TODO work out if we need to expose other arguments to the underlying syscalls.
pub fn DeviceIoControl(
    h: HANDLE,
    ioControlCode: ULONG,
    in: ?[]const u8,
    out: ?[]u8,
) DeviceIoControlError!void {
    // Logic from: https://doxygen.reactos.org/d3/d74/deviceio_8c.html
    const is_fsctl = (ioControlCode >> 16) == FILE_DEVICE_FILE_SYSTEM;

    var io: IO_STATUS_BLOCK = undefined;
    const in_ptr = if (in) |i| i.ptr else null;
    const in_len = if (in) |i| @as(ULONG, @intCast(i.len)) else 0;
    const out_ptr = if (out) |o| o.ptr else null;
    const out_len = if (out) |o| @as(ULONG, @intCast(o.len)) else 0;

    const rc = blk: {
        if (is_fsctl) {
            break :blk ntdll.NtFsControlFile(
                h,
                null,
                null,
                null,
                &io,
                ioControlCode,
                in_ptr,
                in_len,
                out_ptr,
                out_len,
            );
        } else {
            break :blk ntdll.NtDeviceIoControlFile(
                h,
                null,
                null,
                null,
                &io,
                ioControlCode,
                in_ptr,
                in_len,
                out_ptr,
                out_len,
            );
        }
    };
    switch (rc) {
        .SUCCESS => {},
        .PRIVILEGE_NOT_HELD => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_DEVICE_REQUEST => return error.AccessDenied, // Not supported by the underlying filesystem
        .INVALID_PARAMETER => unreachable,
        .UNRECOGNIZED_VOLUME => return error.UnrecognizedVolume,
        else => return unexpectedStatus(rc),
    }
}

pub fn GetOverlappedResult(h: HANDLE, overlapped: *OVERLAPPED, wait: bool) !DWORD {
    var bytes: DWORD = undefined;
    if (kernel32.GetOverlappedResult(h, overlapped, &bytes, @intFromBool(wait)) == 0) {
        switch (GetLastError()) {
            .IO_INCOMPLETE => if (!wait) return error.WouldBlock else unreachable,
            else => |err| return unexpectedError(err),
        }
    }
    return bytes;
}

pub const SetHandleInformationError = error{Unexpected};

pub fn SetHandleInformation(h: HANDLE, mask: DWORD, flags: DWORD) SetHandleInformationError!void {
    if (kernel32.SetHandleInformation(h, mask, flags) == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const RtlGenRandomError = error{Unexpected};

/// Call RtlGenRandom() instead of CryptGetRandom() on Windows
/// https://github.com/rust-lang-nursery/rand/issues/111
/// https://bugzilla.mozilla.org/show_bug.cgi?id=504270
pub fn RtlGenRandom(output: []u8) RtlGenRandomError!void {
    var total_read: usize = 0;
    var buff: []u8 = output[0..];
    const max_read_size: ULONG = maxInt(ULONG);

    while (total_read < output.len) {
        const to_read: ULONG = @min(buff.len, max_read_size);

        if (advapi32.RtlGenRandom(buff.ptr, to_read) == 0) {
            return unexpectedError(GetLastError());
        }

        total_read += to_read;
        buff = buff[to_read..];
    }
}

pub const WaitForSingleObjectError = error{
    WaitAbandoned,
    WaitTimeOut,
    Unexpected,
};

pub fn WaitForSingleObject(handle: HANDLE, milliseconds: DWORD) WaitForSingleObjectError!void {
    return WaitForSingleObjectEx(handle, milliseconds, false);
}

pub fn WaitForSingleObjectEx(handle: HANDLE, milliseconds: DWORD, alertable: bool) WaitForSingleObjectError!void {
    switch (kernel32.WaitForSingleObjectEx(handle, milliseconds, @intFromBool(alertable))) {
        WAIT_ABANDONED => return error.WaitAbandoned,
        WAIT_OBJECT_0 => return,
        WAIT_TIMEOUT => return error.WaitTimeOut,
        WAIT_FAILED => switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        },
        else => return error.Unexpected,
    }
}

pub fn WaitForMultipleObjectsEx(handles: []const HANDLE, waitAll: bool, milliseconds: DWORD, alertable: bool) !u32 {
    assert(handles.len > 0 and handles.len <= MAXIMUM_WAIT_OBJECTS);
    const nCount: DWORD = @as(DWORD, @intCast(handles.len));
    switch (kernel32.WaitForMultipleObjectsEx(
        nCount,
        handles.ptr,
        @intFromBool(waitAll),
        milliseconds,
        @intFromBool(alertable),
    )) {
        WAIT_OBJECT_0...WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS => |n| {
            const handle_index = n - WAIT_OBJECT_0;
            assert(handle_index < nCount);
            return handle_index;
        },
        WAIT_ABANDONED_0...WAIT_ABANDONED_0 + MAXIMUM_WAIT_OBJECTS => |n| {
            const handle_index = n - WAIT_ABANDONED_0;
            assert(handle_index < nCount);
            return error.WaitAbandoned;
        },
        WAIT_TIMEOUT => return error.WaitTimeOut,
        WAIT_FAILED => switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        },
        else => return error.Unexpected,
    }
}

pub const CreateIoCompletionPortError = error{Unexpected};

pub fn CreateIoCompletionPort(
    file_handle: HANDLE,
    existing_completion_port: ?HANDLE,
    completion_key: usize,
    concurrent_thread_count: DWORD,
) CreateIoCompletionPortError!HANDLE {
    const handle = kernel32.CreateIoCompletionPort(file_handle, existing_completion_port, completion_key, concurrent_thread_count) orelse {
        switch (GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            else => |err| return unexpectedError(err),
        }
    };
    return handle;
}

pub const PostQueuedCompletionStatusError = error{Unexpected};

pub fn PostQueuedCompletionStatus(
    completion_port: HANDLE,
    bytes_transferred_count: DWORD,
    completion_key: usize,
    lpOverlapped: ?*OVERLAPPED,
) PostQueuedCompletionStatusError!void {
    if (kernel32.PostQueuedCompletionStatus(completion_port, bytes_transferred_count, completion_key, lpOverlapped) == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const GetQueuedCompletionStatusResult = enum {
    Normal,
    Aborted,
    Cancelled,
    EOF,
    Timeout,
};

pub fn GetQueuedCompletionStatus(
    completion_port: HANDLE,
    bytes_transferred_count: *DWORD,
    lpCompletionKey: *usize,
    lpOverlapped: *?*OVERLAPPED,
    dwMilliseconds: DWORD,
) GetQueuedCompletionStatusResult {
    if (kernel32.GetQueuedCompletionStatus(
        completion_port,
        bytes_transferred_count,
        lpCompletionKey,
        lpOverlapped,
        dwMilliseconds,
    ) == FALSE) {
        switch (GetLastError()) {
            .ABANDONED_WAIT_0 => return GetQueuedCompletionStatusResult.Aborted,
            .OPERATION_ABORTED => return GetQueuedCompletionStatusResult.Cancelled,
            .HANDLE_EOF => return GetQueuedCompletionStatusResult.EOF,
            .WAIT_TIMEOUT => return GetQueuedCompletionStatusResult.Timeout,
            else => |err| {
                if (std.debug.runtime_safety) {
                    @setEvalBranchQuota(2500);
                    std.debug.panic("unexpected error: {}\n", .{err});
                }
            },
        }
    }
    return GetQueuedCompletionStatusResult.Normal;
}

pub const GetQueuedCompletionStatusError = error{
    Aborted,
    Cancelled,
    EOF,
    Timeout,
} || UnexpectedError;

pub fn GetQueuedCompletionStatusEx(
    completion_port: HANDLE,
    completion_port_entries: []OVERLAPPED_ENTRY,
    timeout_ms: ?DWORD,
    alertable: bool,
) GetQueuedCompletionStatusError!u32 {
    var num_entries_removed: u32 = 0;

    const success = kernel32.GetQueuedCompletionStatusEx(
        completion_port,
        completion_port_entries.ptr,
        @as(ULONG, @intCast(completion_port_entries.len)),
        &num_entries_removed,
        timeout_ms orelse INFINITE,
        @intFromBool(alertable),
    );

    if (success == FALSE) {
        return switch (GetLastError()) {
            .ABANDONED_WAIT_0 => error.Aborted,
            .OPERATION_ABORTED => error.Cancelled,
            .HANDLE_EOF => error.EOF,
            .WAIT_TIMEOUT => error.Timeout,
            else => |err| unexpectedError(err),
        };
    }

    return num_entries_removed;
}

pub fn CloseHandle(hObject: HANDLE) void {
    assert(ntdll.NtClose(hObject) == .SUCCESS);
}

pub fn FindClose(hFindFile: HANDLE) void {
    assert(kernel32.FindClose(hFindFile) != 0);
}

pub const ReadFileError = error{
    BrokenPipe,
    /// The specified network name is no longer available.
    ConnectionResetByPeer,
    OperationAborted,
    /// Unable to read file due to lock.
    LockViolation,
    /// Known to be possible when:
    /// - Unable to read from disconnected virtual com port (Windows)
    AccessDenied,
    Unexpected,
};

/// If buffer's length exceeds what a Windows DWORD integer can hold, it will be broken into
/// multiple non-atomic reads.
pub fn ReadFile(in_hFile: HANDLE, buffer: []u8, offset: ?u64) ReadFileError!usize {
    while (true) {
        const want_read_count: DWORD = @min(@as(DWORD, maxInt(DWORD)), buffer.len);
        var amt_read: DWORD = undefined;
        var overlapped_data: OVERLAPPED = undefined;
        const overlapped: ?*OVERLAPPED = if (offset) |off| blk: {
            overlapped_data = .{
                .Internal = 0,
                .InternalHigh = 0,
                .DUMMYUNIONNAME = .{
                    .DUMMYSTRUCTNAME = .{
                        .Offset = @as(u32, @truncate(off)),
                        .OffsetHigh = @as(u32, @truncate(off >> 32)),
                    },
                },
                .hEvent = null,
            };
            break :blk &overlapped_data;
        } else null;
        if (kernel32.ReadFile(in_hFile, buffer.ptr, want_read_count, &amt_read, overlapped) == 0) {
            switch (GetLastError()) {
                .IO_PENDING => unreachable,
                .OPERATION_ABORTED => continue,
                .BROKEN_PIPE => return 0,
                .HANDLE_EOF => return 0,
                .NETNAME_DELETED => return error.ConnectionResetByPeer,
                .LOCK_VIOLATION => return error.LockViolation,
                .ACCESS_DENIED => return error.AccessDenied,
                else => |err| return unexpectedError(err),
            }
        }
        return amt_read;
    }
}

pub const WriteFileError = error{
    SystemResources,
    OperationAborted,
    BrokenPipe,
    NotOpenForWriting,
    /// The process cannot access the file because another process has locked
    /// a portion of the file.
    LockViolation,
    /// The specified network name is no longer available.
    ConnectionResetByPeer,
    /// Known to be possible when:
    /// - Unable to write to disconnected virtual com port (Windows)
    AccessDenied,
    Unexpected,
};

pub fn WriteFile(
    handle: HANDLE,
    bytes: []const u8,
    offset: ?u64,
) WriteFileError!usize {
    var bytes_written: DWORD = undefined;
    var overlapped_data: OVERLAPPED = undefined;
    const overlapped: ?*OVERLAPPED = if (offset) |off| blk: {
        overlapped_data = .{
            .Internal = 0,
            .InternalHigh = 0,
            .DUMMYUNIONNAME = .{
                .DUMMYSTRUCTNAME = .{
                    .Offset = @truncate(off),
                    .OffsetHigh = @truncate(off >> 32),
                },
            },
            .hEvent = null,
        };
        break :blk &overlapped_data;
    } else null;
    const adjusted_len = math.cast(u32, bytes.len) orelse maxInt(u32);
    if (kernel32.WriteFile(handle, bytes.ptr, adjusted_len, &bytes_written, overlapped) == 0) {
        switch (GetLastError()) {
            .INVALID_USER_BUFFER => return error.SystemResources,
            .NOT_ENOUGH_MEMORY => return error.SystemResources,
            .OPERATION_ABORTED => return error.OperationAborted,
            .NOT_ENOUGH_QUOTA => return error.SystemResources,
            .IO_PENDING => unreachable,
            .NO_DATA => return error.BrokenPipe,
            .INVALID_HANDLE => return error.NotOpenForWriting,
            .LOCK_VIOLATION => return error.LockViolation,
            .NETNAME_DELETED => return error.ConnectionResetByPeer,
            .ACCESS_DENIED => return error.AccessDenied,
            else => |err| return unexpectedError(err),
        }
    }
    return bytes_written;
}

pub const SetCurrentDirectoryError = error{
    NameTooLong,
    FileNotFound,
    NotDir,
    AccessDenied,
    NoDevice,
    BadPathName,
    Unexpected,
};

pub fn SetCurrentDirectory(path_name: []const u16) SetCurrentDirectoryError!void {
    const path_len_bytes = math.cast(u16, path_name.len * 2) orelse return error.NameTooLong;

    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(path_name.ptr),
    };

    const rc = ntdll.RtlSetCurrentDirectory_U(&nt_name);
    switch (rc) {
        .SUCCESS => {},
        .OBJECT_NAME_INVALID => return error.BadPathName,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NO_MEDIA_IN_DEVICE => return error.NoDevice,
        .INVALID_PARAMETER => unreachable,
        .ACCESS_DENIED => return error.AccessDenied,
        .OBJECT_PATH_SYNTAX_BAD => unreachable,
        .NOT_A_DIRECTORY => return error.NotDir,
        else => return unexpectedStatus(rc),
    }
}

pub const GetCurrentDirectoryError = error{
    NameTooLong,
    Unexpected,
};

/// The result is a slice of `buffer`, indexed from 0.
/// The result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
pub fn GetCurrentDirectory(buffer: []u8) GetCurrentDirectoryError![]u8 {
    var wtf16le_buf: [PATH_MAX_WIDE:0]u16 = undefined;
    const result = kernel32.GetCurrentDirectoryW(wtf16le_buf.len + 1, &wtf16le_buf);
    if (result == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    assert(result <= wtf16le_buf.len);
    const wtf16le_slice = wtf16le_buf[0..result];
    var end_index: usize = 0;
    var it = std.unicode.Wtf16LeIterator.init(wtf16le_slice);
    while (it.nextCodepoint()) |codepoint| {
        const seq_len = std.unicode.utf8CodepointSequenceLength(codepoint) catch unreachable;
        if (end_index + seq_len >= buffer.len)
            return error.NameTooLong;
        end_index += std.unicode.wtf8Encode(codepoint, buffer[end_index..]) catch unreachable;
    }
    return buffer[0..end_index];
}

pub const CreateSymbolicLinkError = error{
    AccessDenied,
    PathAlreadyExists,
    FileNotFound,
    NameTooLong,
    NoDevice,
    NetworkNotFound,
    BadPathName,
    /// The volume does not contain a recognized file system. File system
    /// drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
    Unexpected,
};

/// Needs either:
/// - `SeCreateSymbolicLinkPrivilege` privilege
/// or
/// - Developer mode on Windows 10
/// otherwise fails with `error.AccessDenied`. In which case `sym_link_path` may still
/// be created on the file system but will lack reparse processing data applied to it.
pub fn CreateSymbolicLink(
    dir: ?HANDLE,
    sym_link_path: []const u16,
    target_path: [:0]const u16,
    is_directory: bool,
) CreateSymbolicLinkError!void {
    const SYMLINK_DATA = extern struct {
        ReparseTag: ULONG,
        ReparseDataLength: USHORT,
        Reserved: USHORT,
        SubstituteNameOffset: USHORT,
        SubstituteNameLength: USHORT,
        PrintNameOffset: USHORT,
        PrintNameLength: USHORT,
        Flags: ULONG,
    };

    const symlink_handle = OpenFile(sym_link_path, .{
        .access_mask = SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        .dir = dir,
        .creation = FILE_CREATE,
        .filter = if (is_directory) .dir_only else .file_only,
    }) catch |err| switch (err) {
        error.IsDir => return error.PathAlreadyExists,
        error.NotDir => return error.Unexpected,
        error.WouldBlock => return error.Unexpected,
        error.PipeBusy => return error.Unexpected,
        error.NoDevice => return error.Unexpected,
        error.AntivirusInterference => return error.Unexpected,
        else => |e| return e,
    };
    defer CloseHandle(symlink_handle);

    // Relevant portions of the documentation:
    // > Relative links are specified using the following conventions:
    // > - Root relative—for example, "\Windows\System32" resolves to "current drive:\Windows\System32".
    // > - Current working directory–relative—for example, if the current working directory is
    // >   C:\Windows\System32, "C:File.txt" resolves to "C:\Windows\System32\File.txt".
    // > Note: If you specify a current working directory–relative link, it is created as an absolute
    // > link, due to the way the current working directory is processed based on the user and the thread.
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsymboliclinkw
    var is_target_absolute = false;
    const final_target_path = target_path: {
        switch (getNamespacePrefix(u16, target_path)) {
            .none => switch (getUnprefixedPathType(u16, target_path)) {
                // Rooted paths need to avoid getting put through wToPrefixedFileW
                // (and they are treated as relative in this context)
                // Note: It seems that rooted paths in symbolic links are relative to
                //       the drive that the symbolic exists on, not to the CWD's drive.
                //       So, if the symlink is on C:\ and the CWD is on D:\,
                //       it will still resolve the path relative to the root of
                //       the C:\ drive.
                .rooted => break :target_path target_path,
                // Keep relative paths relative, but anything else needs to get NT-prefixed.
                else => if (!std.fs.path.isAbsoluteWindowsWTF16(target_path))
                    break :target_path target_path,
            },
            // Already an NT path, no need to do anything to it
            .nt => break :target_path target_path,
            else => {},
        }
        var prefixed_target_path = try wToPrefixedFileW(dir, target_path);
        // We do this after prefixing to ensure that drive-relative paths are treated as absolute
        is_target_absolute = std.fs.path.isAbsoluteWindowsWTF16(prefixed_target_path.span());
        break :target_path prefixed_target_path.span();
    };

    // prepare reparse data buffer
    var buffer: [MAXIMUM_REPARSE_DATA_BUFFER_SIZE]u8 = undefined;
    const buf_len = @sizeOf(SYMLINK_DATA) + final_target_path.len * 4;
    const header_len = @sizeOf(ULONG) + @sizeOf(USHORT) * 2;
    const target_is_absolute = std.fs.path.isAbsoluteWindowsWTF16(final_target_path);
    const symlink_data = SYMLINK_DATA{
        .ReparseTag = IO_REPARSE_TAG_SYMLINK,
        .ReparseDataLength = @intCast(buf_len - header_len),
        .Reserved = 0,
        .SubstituteNameOffset = @intCast(final_target_path.len * 2),
        .SubstituteNameLength = @intCast(final_target_path.len * 2),
        .PrintNameOffset = 0,
        .PrintNameLength = @intCast(final_target_path.len * 2),
        .Flags = if (!target_is_absolute) SYMLINK_FLAG_RELATIVE else 0,
    };

    @memcpy(buffer[0..@sizeOf(SYMLINK_DATA)], std.mem.asBytes(&symlink_data));
    @memcpy(buffer[@sizeOf(SYMLINK_DATA)..][0 .. final_target_path.len * 2], @as([*]const u8, @ptrCast(final_target_path)));
    const paths_start = @sizeOf(SYMLINK_DATA) + final_target_path.len * 2;
    @memcpy(buffer[paths_start..][0 .. final_target_path.len * 2], @as([*]const u8, @ptrCast(final_target_path)));
    _ = try DeviceIoControl(symlink_handle, FSCTL_SET_REPARSE_POINT, buffer[0..buf_len], null);
}

pub const ReadLinkError = error{
    FileNotFound,
    NetworkNotFound,
    AccessDenied,
    Unexpected,
    NameTooLong,
    UnsupportedReparsePointType,
};

pub fn ReadLink(dir: ?HANDLE, sub_path_w: []const u16, out_buffer: []u8) ReadLinkError![]u8 {
    // Here, we use `NtCreateFile` to shave off one syscall if we were to use `OpenFile` wrapper.
    // With the latter, we'd need to call `NtCreateFile` twice, once for file symlink, and if that
    // failed, again for dir symlink. Omitting any mention of file/dir flags makes it possible
    // to open the symlink there and then.
    const path_len_bytes = math.cast(u16, sub_path_w.len * 2) orelse return error.NameTooLong;
    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(sub_path_w.ptr),
    };
    var attr = OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = if (std.fs.path.isAbsoluteWindowsWTF16(sub_path_w)) null else dir,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var result_handle: HANDLE = undefined;
    var io: IO_STATUS_BLOCK = undefined;

    const rc = ntdll.NtCreateFile(
        &result_handle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attr,
        &io,
        null,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        null,
        0,
    );
    switch (rc) {
        .SUCCESS => {},
        .OBJECT_NAME_INVALID => unreachable,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NO_MEDIA_IN_DEVICE => return error.FileNotFound,
        .BAD_NETWORK_PATH => return error.NetworkNotFound, // \\server was not found
        .BAD_NETWORK_NAME => return error.NetworkNotFound, // \\server was found but \\server\share wasn't
        .INVALID_PARAMETER => unreachable,
        .SHARING_VIOLATION => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        .PIPE_BUSY => return error.AccessDenied,
        .OBJECT_PATH_SYNTAX_BAD => unreachable,
        .OBJECT_NAME_COLLISION => unreachable,
        .FILE_IS_A_DIRECTORY => unreachable,
        else => return unexpectedStatus(rc),
    }
    defer CloseHandle(result_handle);

    var reparse_buf: [MAXIMUM_REPARSE_DATA_BUFFER_SIZE]u8 align(@alignOf(REPARSE_DATA_BUFFER)) = undefined;
    _ = DeviceIoControl(result_handle, FSCTL_GET_REPARSE_POINT, null, reparse_buf[0..]) catch |err| switch (err) {
        error.AccessDenied => return error.Unexpected,
        error.UnrecognizedVolume => return error.Unexpected,
        else => |e| return e,
    };

    const reparse_struct: *const REPARSE_DATA_BUFFER = @ptrCast(@alignCast(&reparse_buf[0]));
    switch (reparse_struct.ReparseTag) {
        IO_REPARSE_TAG_SYMLINK => {
            const buf: *const SYMBOLIC_LINK_REPARSE_BUFFER = @ptrCast(@alignCast(&reparse_struct.DataBuffer[0]));
            const offset = buf.SubstituteNameOffset >> 1;
            const len = buf.SubstituteNameLength >> 1;
            const path_buf = @as([*]const u16, &buf.PathBuffer);
            const is_relative = buf.Flags & SYMLINK_FLAG_RELATIVE != 0;
            return parseReadlinkPath(path_buf[offset..][0..len], is_relative, out_buffer);
        },
        IO_REPARSE_TAG_MOUNT_POINT => {
            const buf: *const MOUNT_POINT_REPARSE_BUFFER = @ptrCast(@alignCast(&reparse_struct.DataBuffer[0]));
            const offset = buf.SubstituteNameOffset >> 1;
            const len = buf.SubstituteNameLength >> 1;
            const path_buf = @as([*]const u16, &buf.PathBuffer);
            return parseReadlinkPath(path_buf[offset..][0..len], false, out_buffer);
        },
        else => |value| {
            std.debug.print("unsupported symlink type: {}", .{value});
            return error.UnsupportedReparsePointType;
        },
    }
}

/// Asserts that there is enough space is `out_buffer`.
/// The result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
fn parseReadlinkPath(path: []const u16, is_relative: bool, out_buffer: []u8) []u8 {
    const win32_namespace_path = path: {
        if (is_relative) break :path path;
        const win32_path = ntToWin32Namespace(path) catch |err| switch (err) {
            error.NameTooLong => unreachable,
            error.NotNtPath => break :path path,
        };
        break :path win32_path.span();
    };
    const out_len = std.unicode.wtf16LeToWtf8(out_buffer, win32_namespace_path);
    return out_buffer[0..out_len];
}

pub const DeleteFileError = error{
    FileNotFound,
    AccessDenied,
    NameTooLong,
    /// Also known as sharing violation.
    FileBusy,
    Unexpected,
    NotDir,
    IsDir,
    DirNotEmpty,
    NetworkNotFound,
};

pub const DeleteFileOptions = struct {
    dir: ?HANDLE,
    remove_dir: bool = false,
};

pub fn DeleteFile(sub_path_w: []const u16, options: DeleteFileOptions) DeleteFileError!void {
    const create_options_flags: ULONG = if (options.remove_dir)
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
    else
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT; // would we ever want to delete the target instead?

    const path_len_bytes = @as(u16, @intCast(sub_path_w.len * 2));
    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        // The Windows API makes this mutable, but it will not mutate here.
        .Buffer = @constCast(sub_path_w.ptr),
    };

    if (sub_path_w[0] == '.' and sub_path_w[1] == 0) {
        // Windows does not recognize this, but it does work with empty string.
        nt_name.Length = 0;
    }
    if (sub_path_w[0] == '.' and sub_path_w[1] == '.' and sub_path_w[2] == 0) {
        // Can't remove the parent directory with an open handle.
        return error.FileBusy;
    }

    var attr = OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = if (std.fs.path.isAbsoluteWindowsWTF16(sub_path_w)) null else options.dir,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var io: IO_STATUS_BLOCK = undefined;
    var tmp_handle: HANDLE = undefined;
    var rc = ntdll.NtCreateFile(
        &tmp_handle,
        SYNCHRONIZE | DELETE,
        &attr,
        &io,
        null,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        create_options_flags,
        null,
        0,
    );
    switch (rc) {
        .SUCCESS => {},
        .OBJECT_NAME_INVALID => unreachable,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .BAD_NETWORK_PATH => return error.NetworkNotFound, // \\server was not found
        .BAD_NETWORK_NAME => return error.NetworkNotFound, // \\server was found but \\server\share wasn't
        .INVALID_PARAMETER => unreachable,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        .SHARING_VIOLATION => return error.FileBusy,
        .ACCESS_DENIED => return error.AccessDenied,
        .DELETE_PENDING => return,
        else => return unexpectedStatus(rc),
    }
    defer CloseHandle(tmp_handle);

    // FileDispositionInformationEx (and therefore FILE_DISPOSITION_POSIX_SEMANTICS and FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
    // are only supported on NTFS filesystems, so the version check on its own is only a partial solution. To support non-NTFS filesystems
    // like FAT32, we need to fallback to FileDispositionInformation if the usage of FileDispositionInformationEx gives
    // us INVALID_PARAMETER.
    // The same reasoning for win10_rs5 as in os.renameatW() applies (FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE requires >= win10_rs5).
    var need_fallback = true;
    if (comptime builtin.target.os.version_range.windows.min.isAtLeast(.win10_rs5)) {
        // Deletion with posix semantics if the filesystem supports it.
        var info = FILE_DISPOSITION_INFORMATION_EX{
            .Flags = FILE_DISPOSITION_DELETE |
                FILE_DISPOSITION_POSIX_SEMANTICS |
                FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
        };

        rc = ntdll.NtSetInformationFile(
            tmp_handle,
            &io,
            &info,
            @sizeOf(FILE_DISPOSITION_INFORMATION_EX),
            .FileDispositionInformationEx,
        );
        switch (rc) {
            .SUCCESS => return,
            // INVALID_PARAMETER here means that the filesystem does not support FileDispositionInformationEx
            .INVALID_PARAMETER => {},
            // For all other statuses, fall down to the switch below to handle them.
            else => need_fallback = false,
        }
    }
    if (need_fallback) {
        // Deletion with file pending semantics, which requires waiting or moving
        // files to get them removed (from here).
        var file_dispo = FILE_DISPOSITION_INFORMATION{
            .DeleteFile = TRUE,
        };

        rc = ntdll.NtSetInformationFile(
            tmp_handle,
            &io,
            &file_dispo,
            @sizeOf(FILE_DISPOSITION_INFORMATION),
            .FileDispositionInformation,
        );
    }
    switch (rc) {
        .SUCCESS => {},
        .DIRECTORY_NOT_EMPTY => return error.DirNotEmpty,
        .INVALID_PARAMETER => unreachable,
        .CANNOT_DELETE => return error.AccessDenied,
        .MEDIA_WRITE_PROTECTED => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        else => return unexpectedStatus(rc),
    }
}

pub const MoveFileError = error{ FileNotFound, AccessDenied, Unexpected };

pub fn MoveFileEx(old_path: []const u8, new_path: []const u8, flags: DWORD) (MoveFileError || Wtf8ToPrefixedFileWError)!void {
    const old_path_w = try sliceToPrefixedFileW(null, old_path);
    const new_path_w = try sliceToPrefixedFileW(null, new_path);
    return MoveFileExW(old_path_w.span().ptr, new_path_w.span().ptr, flags);
}

pub fn MoveFileExW(old_path: [*:0]const u16, new_path: [*:0]const u16, flags: DWORD) MoveFileError!void {
    if (kernel32.MoveFileExW(old_path, new_path, flags) == 0) {
        switch (GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .ACCESS_DENIED => return error.AccessDenied,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const GetStdHandleError = error{
    NoStandardHandleAttached,
    Unexpected,
};

pub fn GetStdHandle(handle_id: DWORD) GetStdHandleError!HANDLE {
    const handle = kernel32.GetStdHandle(handle_id) orelse return error.NoStandardHandleAttached;
    if (handle == INVALID_HANDLE_VALUE) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return handle;
}

pub const SetFilePointerError = error{Unexpected};

/// The SetFilePointerEx function with the `dwMoveMethod` parameter set to `FILE_BEGIN`.
pub fn SetFilePointerEx_BEGIN(handle: HANDLE, offset: u64) SetFilePointerError!void {
    // "The starting point is zero or the beginning of the file. If [FILE_BEGIN]
    // is specified, then the liDistanceToMove parameter is interpreted as an unsigned value."
    // https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-setfilepointerex
    const ipos = @as(LARGE_INTEGER, @bitCast(offset));
    if (kernel32.SetFilePointerEx(handle, ipos, null, FILE_BEGIN) == 0) {
        switch (GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
}

/// The SetFilePointerEx function with the `dwMoveMethod` parameter set to `FILE_CURRENT`.
pub fn SetFilePointerEx_CURRENT(handle: HANDLE, offset: i64) SetFilePointerError!void {
    if (kernel32.SetFilePointerEx(handle, offset, null, FILE_CURRENT) == 0) {
        switch (GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
}

/// The SetFilePointerEx function with the `dwMoveMethod` parameter set to `FILE_END`.
pub fn SetFilePointerEx_END(handle: HANDLE, offset: i64) SetFilePointerError!void {
    if (kernel32.SetFilePointerEx(handle, offset, null, FILE_END) == 0) {
        switch (GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
}

/// The SetFilePointerEx function with parameters to get the current offset.
pub fn SetFilePointerEx_CURRENT_get(handle: HANDLE) SetFilePointerError!u64 {
    var result: LARGE_INTEGER = undefined;
    if (kernel32.SetFilePointerEx(handle, 0, &result, FILE_CURRENT) == 0) {
        switch (GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
    // Based on the docs for FILE_BEGIN, it seems that the returned signed integer
    // should be interpreted as an unsigned integer.
    return @as(u64, @bitCast(result));
}

pub const QueryObjectNameError = error{
    AccessDenied,
    InvalidHandle,
    NameTooLong,
    Unexpected,
};

pub fn QueryObjectName(handle: HANDLE, out_buffer: []u16) QueryObjectNameError![]u16 {
    const out_buffer_aligned = mem.alignInSlice(out_buffer, @alignOf(OBJECT_NAME_INFORMATION)) orelse return error.NameTooLong;

    const info = @as(*OBJECT_NAME_INFORMATION, @ptrCast(out_buffer_aligned));
    // buffer size is specified in bytes
    const out_buffer_len = std.math.cast(ULONG, out_buffer_aligned.len * 2) orelse std.math.maxInt(ULONG);
    // last argument would return the length required for full_buffer, not exposed here
    return switch (ntdll.NtQueryObject(handle, .ObjectNameInformation, info, out_buffer_len, null)) {
        .SUCCESS => blk: {
            // info.Name.Buffer from ObQueryNameString is documented to be null (and MaximumLength == 0)
            // if the object was "unnamed", not sure if this can happen for file handles
            if (info.Name.MaximumLength == 0) break :blk error.Unexpected;
            // resulting string length is specified in bytes
            const path_length_unterminated = @divExact(info.Name.Length, 2);
            break :blk info.Name.Buffer.?[0..path_length_unterminated];
        },
        .ACCESS_DENIED => error.AccessDenied,
        .INVALID_HANDLE => error.InvalidHandle,
        // triggered when the buffer is too small for the OBJECT_NAME_INFORMATION object (.INFO_LENGTH_MISMATCH),
        // or if the buffer is too small for the file path returned (.BUFFER_OVERFLOW, .BUFFER_TOO_SMALL)
        .INFO_LENGTH_MISMATCH, .BUFFER_OVERFLOW, .BUFFER_TOO_SMALL => error.NameTooLong,
        else => |e| unexpectedStatus(e),
    };
}

test QueryObjectName {
    if (builtin.os.tag != .windows)
        return;

    //any file will do; canonicalization works on NTFS junctions and symlinks, hardlinks remain separate paths.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const handle = tmp.dir.fd;
    var out_buffer: [PATH_MAX_WIDE]u16 = undefined;

    const result_path = try QueryObjectName(handle, &out_buffer);
    const required_len_in_u16 = result_path.len + @divExact(@intFromPtr(result_path.ptr) - @intFromPtr(&out_buffer), 2) + 1;
    //insufficient size
    try std.testing.expectError(error.NameTooLong, QueryObjectName(handle, out_buffer[0 .. required_len_in_u16 - 1]));
    //exactly-sufficient size
    _ = try QueryObjectName(handle, out_buffer[0..required_len_in_u16]);
}

pub const GetFinalPathNameByHandleError = error{
    AccessDenied,
    BadPathName,
    FileNotFound,
    NameTooLong,
    /// The volume does not contain a recognized file system. File system
    /// drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
    Unexpected,
};

/// Specifies how to format volume path in the result of `GetFinalPathNameByHandle`.
/// Defaults to DOS volume names.
pub const GetFinalPathNameByHandleFormat = struct {
    volume_name: enum {
        /// Format as DOS volume name
        Dos,
        /// Format as NT volume name
        Nt,
    } = .Dos,
};

/// Returns canonical (normalized) path of handle.
/// Use `GetFinalPathNameByHandleFormat` to specify whether the path is meant to include
/// NT or DOS volume name (e.g., `\Device\HarddiskVolume0\foo.txt` versus `C:\foo.txt`).
/// If DOS volume name format is selected, note that this function does *not* prepend
/// `\\?\` prefix to the resultant path.
pub fn GetFinalPathNameByHandle(
    hFile: HANDLE,
    fmt: GetFinalPathNameByHandleFormat,
    out_buffer: []u16,
) GetFinalPathNameByHandleError![]u16 {
    const final_path = QueryObjectName(hFile, out_buffer) catch |err| switch (err) {
        // we assume InvalidHandle is close enough to FileNotFound in semantics
        // to not further complicate the error set
        error.InvalidHandle => return error.FileNotFound,
        else => |e| return e,
    };

    switch (fmt.volume_name) {
        .Nt => {
            // the returned path is already in .Nt format
            return final_path;
        },
        .Dos => {
            // parse the string to separate volume path from file path
            const expected_prefix = std.unicode.utf8ToUtf16LeStringLiteral("\\Device\\");

            // TODO find out if a path can start with something besides `\Device\<volume name>`,
            // and if we need to handle it differently
            // (i.e. how to determine the start and end of the volume name in that case)
            if (!mem.eql(u16, expected_prefix, final_path[0..expected_prefix.len])) return error.Unexpected;

            const file_path_begin_index = mem.indexOfPos(u16, final_path, expected_prefix.len, &[_]u16{'\\'}) orelse unreachable;
            const volume_name_u16 = final_path[0..file_path_begin_index];
            const device_name_u16 = volume_name_u16[expected_prefix.len..];
            const file_name_u16 = final_path[file_path_begin_index..];

            // MUP is Multiple UNC Provider, and indicates that the path is a UNC
            // path. In this case, the canonical UNC path can be gotten by just
            // dropping the \Device\Mup\ and making sure the path begins with \\
            if (mem.eql(u16, device_name_u16, std.unicode.utf8ToUtf16LeStringLiteral("Mup"))) {
                out_buffer[0] = '\\';
                mem.copyForwards(u16, out_buffer[1..][0..file_name_u16.len], file_name_u16);
                return out_buffer[0 .. 1 + file_name_u16.len];
            }

            // Get DOS volume name. DOS volume names are actually symbolic link objects to the
            // actual NT volume. For example:
            // (NT) \Device\HarddiskVolume4 => (DOS) \DosDevices\C: == (DOS) C:
            const MIN_SIZE = @sizeOf(MOUNTMGR_MOUNT_POINT) + MAX_PATH;
            // We initialize the input buffer to all zeros for convenience since
            // `DeviceIoControl` with `IOCTL_MOUNTMGR_QUERY_POINTS` expects this.
            var input_buf: [MIN_SIZE]u8 align(@alignOf(MOUNTMGR_MOUNT_POINT)) = [_]u8{0} ** MIN_SIZE;
            var output_buf: [MIN_SIZE * 4]u8 align(@alignOf(MOUNTMGR_MOUNT_POINTS)) = undefined;

            // This surprising path is a filesystem path to the mount manager on Windows.
            // Source: https://stackoverflow.com/questions/3012828/using-ioctl-mountmgr-query-points
            // This is the NT namespaced version of \\.\MountPointManager
            const mgmt_path_u16 = std.unicode.utf8ToUtf16LeStringLiteral("\\??\\MountPointManager");
            const mgmt_handle = OpenFile(mgmt_path_u16, .{
                .access_mask = SYNCHRONIZE,
                .share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                .creation = FILE_OPEN,
            }) catch |err| switch (err) {
                error.IsDir => return error.Unexpected,
                error.NotDir => return error.Unexpected,
                error.NoDevice => return error.Unexpected,
                error.AccessDenied => return error.Unexpected,
                error.PipeBusy => return error.Unexpected,
                error.PathAlreadyExists => return error.Unexpected,
                error.WouldBlock => return error.Unexpected,
                error.NetworkNotFound => return error.Unexpected,
                error.AntivirusInterference => return error.Unexpected,
                else => |e| return e,
            };
            defer CloseHandle(mgmt_handle);

            var input_struct: *MOUNTMGR_MOUNT_POINT = @ptrCast(&input_buf[0]);
            input_struct.DeviceNameOffset = @sizeOf(MOUNTMGR_MOUNT_POINT);
            input_struct.DeviceNameLength = @intCast(volume_name_u16.len * 2);
            @memcpy(input_buf[@sizeOf(MOUNTMGR_MOUNT_POINT)..][0 .. volume_name_u16.len * 2], @as([*]const u8, @ptrCast(volume_name_u16.ptr)));

            DeviceIoControl(mgmt_handle, IOCTL_MOUNTMGR_QUERY_POINTS, &input_buf, &output_buf) catch |err| switch (err) {
                error.AccessDenied => return error.Unexpected,
                else => |e| return e,
            };
            const mount_points_struct: *const MOUNTMGR_MOUNT_POINTS = @ptrCast(&output_buf[0]);

            const mount_points = @as(
                [*]const MOUNTMGR_MOUNT_POINT,
                @ptrCast(&mount_points_struct.MountPoints[0]),
            )[0..mount_points_struct.NumberOfMountPoints];

            for (mount_points) |mount_point| {
                const symlink = @as(
                    [*]const u16,
                    @ptrCast(@alignCast(&output_buf[mount_point.SymbolicLinkNameOffset])),
                )[0 .. mount_point.SymbolicLinkNameLength / 2];

                // Look for `\DosDevices\` prefix. We don't really care if there are more than one symlinks
                // with traditional DOS drive letters, so pick the first one available.
                var prefix_buf = std.unicode.utf8ToUtf16LeStringLiteral("\\DosDevices\\");
                const prefix = prefix_buf[0..prefix_buf.len];

                if (mem.startsWith(u16, symlink, prefix)) {
                    const drive_letter = symlink[prefix.len..];

                    if (out_buffer.len < drive_letter.len + file_name_u16.len) return error.NameTooLong;

                    @memcpy(out_buffer[0..drive_letter.len], drive_letter);
                    mem.copyForwards(u16, out_buffer[drive_letter.len..][0..file_name_u16.len], file_name_u16);
                    const total_len = drive_letter.len + file_name_u16.len;

                    // Validate that DOS does not contain any spurious nul bytes.
                    if (mem.indexOfScalar(u16, out_buffer[0..total_len], 0)) |_| {
                        return error.BadPathName;
                    }

                    return out_buffer[0..total_len];
                } else if (mountmgrIsVolumeName(symlink)) {
                    // If the symlink is a volume GUID like \??\Volume{383da0b0-717f-41b6-8c36-00500992b58d},
                    // then it is a volume mounted as a path rather than a drive letter. We need to
                    // query the mount manager again to get the DOS path for the volume.

                    // 49 is the maximum length accepted by mountmgrIsVolumeName
                    const vol_input_size = @sizeOf(MOUNTMGR_TARGET_NAME) + (49 * 2);
                    var vol_input_buf: [vol_input_size]u8 align(@alignOf(MOUNTMGR_TARGET_NAME)) = [_]u8{0} ** vol_input_size;
                    // Note: If the path exceeds MAX_PATH, the Disk Management GUI doesn't accept the full path,
                    // and instead if must be specified using a shortened form (e.g. C:\FOO~1\BAR~1\<...>).
                    // However, just to be sure we can handle any path length, we use PATH_MAX_WIDE here.
                    const min_output_size = @sizeOf(MOUNTMGR_VOLUME_PATHS) + (PATH_MAX_WIDE * 2);
                    var vol_output_buf: [min_output_size]u8 align(@alignOf(MOUNTMGR_VOLUME_PATHS)) = undefined;

                    var vol_input_struct: *MOUNTMGR_TARGET_NAME = @ptrCast(&vol_input_buf[0]);
                    vol_input_struct.DeviceNameLength = @intCast(symlink.len * 2);
                    @memcpy(@as([*]WCHAR, &vol_input_struct.DeviceName)[0..symlink.len], symlink);

                    DeviceIoControl(mgmt_handle, IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH, &vol_input_buf, &vol_output_buf) catch |err| switch (err) {
                        error.AccessDenied => return error.Unexpected,
                        else => |e| return e,
                    };
                    const volume_paths_struct: *const MOUNTMGR_VOLUME_PATHS = @ptrCast(&vol_output_buf[0]);
                    const volume_path = std.mem.sliceTo(@as(
                        [*]const u16,
                        &volume_paths_struct.MultiSz,
                    )[0 .. volume_paths_struct.MultiSzLength / 2], 0);

                    if (out_buffer.len < volume_path.len + file_name_u16.len) return error.NameTooLong;

                    // `out_buffer` currently contains the memory of `file_name_u16`, so it can overlap with where
                    // we want to place the filename before returning. Here are the possible overlapping cases:
                    //
                    // out_buffer:       [filename]
                    //       dest: [___(a)___] [___(b)___]
                    //
                    // In the case of (a), we need to copy forwards, and in the case of (b) we need
                    // to copy backwards. We also need to do this before copying the volume path because
                    // it could overwrite the file_name_u16 memory.
                    const file_name_dest = out_buffer[volume_path.len..][0..file_name_u16.len];
                    const file_name_byte_offset = @intFromPtr(file_name_u16.ptr) - @intFromPtr(out_buffer.ptr);
                    const file_name_index = file_name_byte_offset / @sizeOf(u16);
                    if (volume_path.len > file_name_index)
                        mem.copyBackwards(u16, file_name_dest, file_name_u16)
                    else
                        mem.copyForwards(u16, file_name_dest, file_name_u16);
                    @memcpy(out_buffer[0..volume_path.len], volume_path);
                    const total_len = volume_path.len + file_name_u16.len;

                    // Validate that DOS does not contain any spurious nul bytes.
                    if (mem.indexOfScalar(u16, out_buffer[0..total_len], 0)) |_| {
                        return error.BadPathName;
                    }

                    return out_buffer[0..total_len];
                }
            }

            // If we've ended up here, then something went wrong/is corrupted in the OS,
            // so error out!
            return error.FileNotFound;
        },
    }
}

/// Equivalent to the MOUNTMGR_IS_VOLUME_NAME macro in mountmgr.h
fn mountmgrIsVolumeName(name: []const u16) bool {
    return (name.len == 48 or (name.len == 49 and name[48] == mem.nativeToLittle(u16, '\\'))) and
        name[0] == mem.nativeToLittle(u16, '\\') and
        (name[1] == mem.nativeToLittle(u16, '?') or name[1] == mem.nativeToLittle(u16, '\\')) and
        name[2] == mem.nativeToLittle(u16, '?') and
        name[3] == mem.nativeToLittle(u16, '\\') and
        mem.startsWith(u16, name[4..], std.unicode.utf8ToUtf16LeStringLiteral("Volume{")) and
        name[19] == mem.nativeToLittle(u16, '-') and
        name[24] == mem.nativeToLittle(u16, '-') and
        name[29] == mem.nativeToLittle(u16, '-') and
        name[34] == mem.nativeToLittle(u16, '-') and
        name[47] == mem.nativeToLittle(u16, '}');
}

test mountmgrIsVolumeName {
    @setEvalBranchQuota(2000);
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    try std.testing.expect(mountmgrIsVolumeName(L("\\\\?\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}")));
    try std.testing.expect(mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}")));
    try std.testing.expect(mountmgrIsVolumeName(L("\\\\?\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}\\")));
    try std.testing.expect(mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}\\")));
    try std.testing.expect(!mountmgrIsVolumeName(L("\\\\.\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}")));
    try std.testing.expect(!mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}\\foo")));
    try std.testing.expect(!mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58}")));
}

test GetFinalPathNameByHandle {
    if (builtin.os.tag != .windows)
        return;

    //any file will do
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const handle = tmp.dir.fd;
    var buffer: [PATH_MAX_WIDE]u16 = undefined;

    //check with sufficient size
    const nt_path = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, &buffer);
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, &buffer);

    const required_len_in_u16 = nt_path.len + @divExact(@intFromPtr(nt_path.ptr) - @intFromPtr(&buffer), 2) + 1;
    //check with insufficient size
    try std.testing.expectError(error.NameTooLong, GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, buffer[0 .. required_len_in_u16 - 1]));
    try std.testing.expectError(error.NameTooLong, GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, buffer[0 .. required_len_in_u16 - 1]));

    //check with exactly-sufficient size
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, buffer[0..required_len_in_u16]);
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, buffer[0..required_len_in_u16]);
}

pub const GetFileSizeError = error{Unexpected};

pub fn GetFileSizeEx(hFile: HANDLE) GetFileSizeError!u64 {
    var file_size: LARGE_INTEGER = undefined;
    if (kernel32.GetFileSizeEx(hFile, &file_size) == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return @as(u64, @bitCast(file_size));
}

pub const GetFileAttributesError = error{
    FileNotFound,
    AccessDenied,
    Unexpected,
};

pub fn GetFileAttributes(filename: []const u8) (GetFileAttributesError || Wtf8ToPrefixedFileWError)!DWORD {
    const filename_w = try sliceToPrefixedFileW(null, filename);
    return GetFileAttributesW(filename_w.span().ptr);
}

pub fn GetFileAttributesW(lpFileName: [*:0]const u16) GetFileAttributesError!DWORD {
    const rc = kernel32.GetFileAttributesW(lpFileName);
    if (rc == INVALID_FILE_ATTRIBUTES) {
        switch (GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .ACCESS_DENIED => return error.AccessDenied,
            else => |err| return unexpectedError(err),
        }
    }
    return rc;
}

pub fn WSAStartup(majorVersion: u8, minorVersion: u8) !ws2_32.WSADATA {
    var wsadata: ws2_32.WSADATA = undefined;
    return switch (ws2_32.WSAStartup((@as(WORD, minorVersion) << 8) | majorVersion, &wsadata)) {
        0 => wsadata,
        else => |err_int| switch (@as(ws2_32.WinsockError, @enumFromInt(@as(u16, @intCast(err_int))))) {
            .WSASYSNOTREADY => return error.SystemNotAvailable,
            .WSAVERNOTSUPPORTED => return error.VersionNotSupported,
            .WSAEINPROGRESS => return error.BlockingOperationInProgress,
            .WSAEPROCLIM => return error.ProcessFdQuotaExceeded,
            else => |err| return unexpectedWSAError(err),
        },
    };
}

pub fn WSACleanup() !void {
    return switch (ws2_32.WSACleanup()) {
        0 => {},
        ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
            .WSANOTINITIALISED => return error.NotInitialized,
            .WSAENETDOWN => return error.NetworkNotAvailable,
            .WSAEINPROGRESS => return error.BlockingOperationInProgress,
            else => |err| return unexpectedWSAError(err),
        },
        else => unreachable,
    };
}

var wsa_startup_mutex: std.Thread.Mutex = .{};

pub fn callWSAStartup() !void {
    wsa_startup_mutex.lock();
    defer wsa_startup_mutex.unlock();

    // Here we could use a flag to prevent multiple threads to prevent
    // multiple calls to WSAStartup, but it doesn't matter. We're globally
    // leaking the resource intentionally, and the mutex already prevents
    // data races within the WSAStartup function.
    _ = WSAStartup(2, 2) catch |err| switch (err) {
        error.SystemNotAvailable => return error.SystemResources,
        error.VersionNotSupported => return error.Unexpected,
        error.BlockingOperationInProgress => return error.Unexpected,
        error.ProcessFdQuotaExceeded => return error.ProcessFdQuotaExceeded,
        error.Unexpected => return error.Unexpected,
    };
}

/// Microsoft requires WSAStartup to be called to initialize, or else
/// WSASocketW will return WSANOTINITIALISED.
/// Since this is a standard library, we do not have the luxury of
/// putting initialization code anywhere, because we would not want
/// to pay the cost of calling WSAStartup if there ended up being no
/// networking. Also, if Zig code is used as a library, Zig is not in
/// charge of the start code, and we couldn't put in any initialization
/// code even if we wanted to.
/// The documentation for WSAStartup mentions that there must be a
/// matching WSACleanup call. It is not possible for the Zig Standard
/// Library to honor this for the same reason - there is nowhere to put
/// deinitialization code.
/// So, API users of the zig std lib have two options:
///  * (recommended) The simple, cross-platform way: just call `WSASocketW`
///    and don't worry about it. Zig will call WSAStartup() in a thread-safe
///    manner and never deinitialize networking. This is ideal for an
///    application which has the capability to do networking.
///  * The getting-your-hands-dirty way: call `WSAStartup()` before doing
///    networking, so that the error handling code for WSANOTINITIALISED never
///    gets run, which then allows the application or library to call `WSACleanup()`.
///    This could make sense for a library, which has init and deinit
///    functions for the whole library's lifetime.
pub fn WSASocketW(
    af: i32,
    socket_type: i32,
    protocol: i32,
    protocolInfo: ?*ws2_32.WSAPROTOCOL_INFOW,
    g: ws2_32.GROUP,
    dwFlags: DWORD,
) !ws2_32.SOCKET {
    var first = true;
    while (true) {
        const rc = ws2_32.WSASocketW(af, socket_type, protocol, protocolInfo, g, dwFlags);
        if (rc == ws2_32.INVALID_SOCKET) {
            switch (ws2_32.WSAGetLastError()) {
                .WSAEAFNOSUPPORT => return error.AddressFamilyNotSupported,
                .WSAEMFILE => return error.ProcessFdQuotaExceeded,
                .WSAENOBUFS => return error.SystemResources,
                .WSAEPROTONOSUPPORT => return error.ProtocolNotSupported,
                .WSANOTINITIALISED => {
                    if (!first) return error.Unexpected;
                    first = false;
                    try callWSAStartup();
                    continue;
                },
                else => |err| return unexpectedWSAError(err),
            }
        }
        return rc;
    }
}

pub fn bind(s: ws2_32.SOCKET, name: *const ws2_32.sockaddr, namelen: ws2_32.socklen_t) i32 {
    return ws2_32.bind(s, name, @as(i32, @intCast(namelen)));
}

pub fn listen(s: ws2_32.SOCKET, backlog: u31) i32 {
    return ws2_32.listen(s, backlog);
}

pub fn closesocket(s: ws2_32.SOCKET) !void {
    switch (ws2_32.closesocket(s)) {
        0 => {},
        ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
            else => |err| return unexpectedWSAError(err),
        },
        else => unreachable,
    }
}

pub fn accept(s: ws2_32.SOCKET, name: ?*ws2_32.sockaddr, namelen: ?*ws2_32.socklen_t) ws2_32.SOCKET {
    assert((name == null) == (namelen == null));
    return ws2_32.accept(s, name, @as(?*i32, @ptrCast(namelen)));
}

pub fn getsockname(s: ws2_32.SOCKET, name: *ws2_32.sockaddr, namelen: *ws2_32.socklen_t) i32 {
    return ws2_32.getsockname(s, name, @as(*i32, @ptrCast(namelen)));
}

pub fn getpeername(s: ws2_32.SOCKET, name: *ws2_32.sockaddr, namelen: *ws2_32.socklen_t) i32 {
    return ws2_32.getpeername(s, name, @as(*i32, @ptrCast(namelen)));
}

pub fn sendmsg(
    s: ws2_32.SOCKET,
    msg: *ws2_32.WSAMSG_const,
    flags: u32,
) i32 {
    var bytes_send: DWORD = undefined;
    if (ws2_32.WSASendMsg(s, msg, flags, &bytes_send, null, null) == ws2_32.SOCKET_ERROR) {
        return ws2_32.SOCKET_ERROR;
    } else {
        return @as(i32, @as(u31, @intCast(bytes_send)));
    }
}

pub fn sendto(s: ws2_32.SOCKET, buf: [*]const u8, len: usize, flags: u32, to: ?*const ws2_32.sockaddr, to_len: ws2_32.socklen_t) i32 {
    var buffer = ws2_32.WSABUF{ .len = @as(u31, @truncate(len)), .buf = @constCast(buf) };
    var bytes_send: DWORD = undefined;
    if (ws2_32.WSASendTo(s, @as([*]ws2_32.WSABUF, @ptrCast(&buffer)), 1, &bytes_send, flags, to, @as(i32, @intCast(to_len)), null, null) == ws2_32.SOCKET_ERROR) {
        return ws2_32.SOCKET_ERROR;
    } else {
        return @as(i32, @as(u31, @intCast(bytes_send)));
    }
}

pub fn recvfrom(s: ws2_32.SOCKET, buf: [*]u8, len: usize, flags: u32, from: ?*ws2_32.sockaddr, from_len: ?*ws2_32.socklen_t) i32 {
    var buffer = ws2_32.WSABUF{ .len = @as(u31, @truncate(len)), .buf = buf };
    var bytes_received: DWORD = undefined;
    var flags_inout = flags;
    if (ws2_32.WSARecvFrom(s, @as([*]ws2_32.WSABUF, @ptrCast(&buffer)), 1, &bytes_received, &flags_inout, from, @as(?*i32, @ptrCast(from_len)), null, null) == ws2_32.SOCKET_ERROR) {
        return ws2_32.SOCKET_ERROR;
    } else {
        return @as(i32, @as(u31, @intCast(bytes_received)));
    }
}

pub fn poll(fds: [*]ws2_32.pollfd, n: c_ulong, timeout: i32) i32 {
    return ws2_32.WSAPoll(fds, n, timeout);
}

pub fn WSAIoctl(
    s: ws2_32.SOCKET,
    dwIoControlCode: DWORD,
    inBuffer: ?[]const u8,
    outBuffer: []u8,
    overlapped: ?*OVERLAPPED,
    completionRoutine: ?ws2_32.LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) !DWORD {
    var bytes: DWORD = undefined;
    switch (ws2_32.WSAIoctl(
        s,
        dwIoControlCode,
        if (inBuffer) |i| i.ptr else null,
        if (inBuffer) |i| @as(DWORD, @intCast(i.len)) else 0,
        outBuffer.ptr,
        @as(DWORD, @intCast(outBuffer.len)),
        &bytes,
        overlapped,
        completionRoutine,
    )) {
        0 => {},
        ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
            else => |err| return unexpectedWSAError(err),
        },
        else => unreachable,
    }
    return bytes;
}

const GetModuleFileNameError = error{Unexpected};

pub fn GetModuleFileNameW(hModule: ?HMODULE, buf_ptr: [*]u16, buf_len: DWORD) GetModuleFileNameError![:0]u16 {
    const rc = kernel32.GetModuleFileNameW(hModule, buf_ptr, buf_len);
    if (rc == 0) {
        switch (GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return buf_ptr[0..rc :0];
}

pub const TerminateProcessError = error{ AccessDenied, Unexpected };

pub fn TerminateProcess(hProcess: HANDLE, uExitCode: UINT) TerminateProcessError!void {
    if (kernel32.TerminateProcess(hProcess, uExitCode) == 0) {
        switch (GetLastError()) {
            Win32Error.ACCESS_DENIED => return error.AccessDenied,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const NtAllocateVirtualMemoryError = error{
    AccessDenied,
    InvalidParameter,
    NoMemory,
    Unexpected,
};

pub fn NtAllocateVirtualMemory(hProcess: HANDLE, addr: ?*PVOID, zero_bits: ULONG_PTR, size: ?*SIZE_T, alloc_type: ULONG, protect: ULONG) NtAllocateVirtualMemoryError!void {
    return switch (ntdll.NtAllocateVirtualMemory(hProcess, addr, zero_bit```
