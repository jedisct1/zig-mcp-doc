```
BJ_OPENIF = 0x00000080;
pub const OBJ_OPENLINK = 0x00000100;
pub const OBJ_KERNEL_HANDLE = 0x00000200;
pub const OBJ_VALID_ATTRIBUTES = 0x000003F2;

pub const UNICODE_STRING = extern struct {
    Length: c_ushort,
    MaximumLength: c_ushort,
    Buffer: ?[*]WCHAR,
};

pub const ACTIVATION_CONTEXT_DATA = opaque {};
pub const ASSEMBLY_STORAGE_MAP = opaque {};
pub const FLS_CALLBACK_INFO = opaque {};
pub const RTL_BITMAP = opaque {};
pub const KAFFINITY = usize;
pub const KPRIORITY = i32;

pub const CLIENT_ID = extern struct {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
};

pub const THREAD_BASIC_INFORMATION = extern struct {
    ExitStatus: NTSTATUS,
    TebBaseAddress: PVOID,
    ClientId: CLIENT_ID,
    AffinityMask: KAFFINITY,
    Priority: KPRIORITY,
    BasePriority: KPRIORITY,
};

pub const TEB = extern struct {
    NtTib: NT_TIB,
    EnvironmentPointer: PVOID,
    ClientId: CLIENT_ID,
    ActiveRpcHandle: PVOID,
    ThreadLocalStoragePointer: PVOID,
    ProcessEnvironmentBlock: *PEB,
    LastErrorValue: ULONG,
    Reserved2: [399 * @sizeOf(PVOID) - @sizeOf(ULONG)]u8,
    Reserved3: [1952]u8,
    TlsSlots: [64]PVOID,
    Reserved4: [8]u8,
    Reserved5: [26]PVOID,
    ReservedForOle: PVOID,
    Reserved6: [4]PVOID,
    TlsExpansionSlots: PVOID,
};

comptime {
    // Offsets taken from WinDbg info and Geoff Chappell[1] (RIP)
    // [1]: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm
    assert(@offsetOf(TEB, "NtTib") == 0x00);
    if (@sizeOf(usize) == 4) {
        assert(@offsetOf(TEB, "EnvironmentPointer") == 0x1C);
        assert(@offsetOf(TEB, "ClientId") == 0x20);
        assert(@offsetOf(TEB, "ActiveRpcHandle") == 0x28);
        assert(@offsetOf(TEB, "ThreadLocalStoragePointer") == 0x2C);
        assert(@offsetOf(TEB, "ProcessEnvironmentBlock") == 0x30);
        assert(@offsetOf(TEB, "LastErrorValue") == 0x34);
        assert(@offsetOf(TEB, "TlsSlots") == 0xe10);
    } else if (@sizeOf(usize) == 8) {
        assert(@offsetOf(TEB, "EnvironmentPointer") == 0x38);
        assert(@offsetOf(TEB, "ClientId") == 0x40);
        assert(@offsetOf(TEB, "ActiveRpcHandle") == 0x50);
        assert(@offsetOf(TEB, "ThreadLocalStoragePointer") == 0x58);
        assert(@offsetOf(TEB, "ProcessEnvironmentBlock") == 0x60);
        assert(@offsetOf(TEB, "LastErrorValue") == 0x68);
        assert(@offsetOf(TEB, "TlsSlots") == 0x1480);
    }
}

pub const EXCEPTION_REGISTRATION_RECORD = extern struct {
    Next: ?*EXCEPTION_REGISTRATION_RECORD,
    Handler: ?*EXCEPTION_DISPOSITION,
};

pub const NT_TIB = extern struct {
    ExceptionList: ?*EXCEPTION_REGISTRATION_RECORD,
    StackBase: PVOID,
    StackLimit: PVOID,
    SubSystemTib: PVOID,
    DUMMYUNIONNAME: extern union { FiberData: PVOID, Version: DWORD },
    ArbitraryUserPointer: PVOID,
    Self: ?*@This(),
};

/// Process Environment Block
/// Microsoft documentation of this is incomplete, the fields here are taken from various resources including:
///  - https://github.com/wine-mirror/wine/blob/1aff1e6a370ee8c0213a0fd4b220d121da8527aa/include/winternl.h#L269
///  - https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm
pub const PEB = extern struct {
    // Versions: All
    InheritedAddressSpace: BOOLEAN,

    // Versions: 3.51+
    ReadImageFileExecOptions: BOOLEAN,
    BeingDebugged: BOOLEAN,

    // Versions: 5.2+ (previously was padding)
    BitField: UCHAR,

    // Versions: all
    Mutant: HANDLE,
    ImageBaseAddress: HMODULE,
    Ldr: *PEB_LDR_DATA,
    ProcessParameters: *RTL_USER_PROCESS_PARAMETERS,
    SubSystemData: PVOID,
    ProcessHeap: HANDLE,

    // Versions: 5.1+
    FastPebLock: *RTL_CRITICAL_SECTION,

    // Versions: 5.2+
    AtlThunkSListPtr: PVOID,
    IFEOKey: PVOID,

    // Versions: 6.0+

    /// https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/crossprocessflags.htm
    CrossProcessFlags: ULONG,

    // Versions: 6.0+
    union1: extern union {
        KernelCallbackTable: PVOID,
        UserSharedInfoPtr: PVOID,
    },

    // Versions: 5.1+
    SystemReserved: ULONG,

    // Versions: 5.1, (not 5.2, not 6.0), 6.1+
    AtlThunkSListPtr32: ULONG,

    // Versions: 6.1+
    ApiSetMap: PVOID,

    // Versions: all
    TlsExpansionCounter: ULONG,
    // note: there is padding here on 64 bit
    TlsBitmap: *RTL_BITMAP,
    TlsBitmapBits: [2]ULONG,
    ReadOnlySharedMemoryBase: PVOID,

    // Versions: 1703+
    SharedData: PVOID,

    // Versions: all
    ReadOnlyStaticServerData: *PVOID,
    AnsiCodePageData: PVOID,
    OemCodePageData: PVOID,
    UnicodeCaseTableData: PVOID,

    // Versions: 3.51+
    NumberOfProcessors: ULONG,
    NtGlobalFlag: ULONG,

    // Versions: all
    CriticalSectionTimeout: LARGE_INTEGER,

    // End of Original PEB size

    // Fields appended in 3.51:
    HeapSegmentReserve: ULONG_PTR,
    HeapSegmentCommit: ULONG_PTR,
    HeapDeCommitTotalFreeThreshold: ULONG_PTR,
    HeapDeCommitFreeBlockThreshold: ULONG_PTR,
    NumberOfHeaps: ULONG,
    MaximumNumberOfHeaps: ULONG,
    ProcessHeaps: *PVOID,

    // Fields appended in 4.0:
    GdiSharedHandleTable: PVOID,
    ProcessStarterHelper: PVOID,
    GdiDCAttributeList: ULONG,
    // note: there is padding here on 64 bit
    LoaderLock: *RTL_CRITICAL_SECTION,
    OSMajorVersion: ULONG,
    OSMinorVersion: ULONG,
    OSBuildNumber: USHORT,
    OSCSDVersion: USHORT,
    OSPlatformId: ULONG,
    ImageSubSystem: ULONG,
    ImageSubSystemMajorVersion: ULONG,
    ImageSubSystemMinorVersion: ULONG,
    // note: there is padding here on 64 bit
    ActiveProcessAffinityMask: KAFFINITY,
    GdiHandleBuffer: [
        switch (@sizeOf(usize)) {
            4 => 0x22,
            8 => 0x3C,
            else => unreachable,
        }
    ]ULONG,

    // Fields appended in 5.0 (Windows 2000):
    PostProcessInitRoutine: PVOID,
    TlsExpansionBitmap: *RTL_BITMAP,
    TlsExpansionBitmapBits: [32]ULONG,
    SessionId: ULONG,
    // note: there is padding here on 64 bit
    // Versions: 5.1+
    AppCompatFlags: ULARGE_INTEGER,
    AppCompatFlagsUser: ULARGE_INTEGER,
    ShimData: PVOID,
    // Versions: 5.0+
    AppCompatInfo: PVOID,
    CSDVersion: UNICODE_STRING,

    // Fields appended in 5.1 (Windows XP):
    ActivationContextData: *const ACTIVATION_CONTEXT_DATA,
    ProcessAssemblyStorageMap: *ASSEMBLY_STORAGE_MAP,
    SystemDefaultActivationData: *const ACTIVATION_CONTEXT_DATA,
    SystemAssemblyStorageMap: *ASSEMBLY_STORAGE_MAP,
    MinimumStackCommit: ULONG_PTR,

    // Fields appended in 5.2 (Windows Server 2003):
    FlsCallback: *FLS_CALLBACK_INFO,
    FlsListHead: LIST_ENTRY,
    FlsBitmap: *RTL_BITMAP,
    FlsBitmapBits: [4]ULONG,
    FlsHighIndex: ULONG,

    // Fields appended in 6.0 (Windows Vista):
    WerRegistrationData: PVOID,
    WerShipAssertPtr: PVOID,

    // Fields appended in 6.1 (Windows 7):
    pUnused: PVOID, // previously pContextData
    pImageHeaderHash: PVOID,

    /// TODO: https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/tracingflags.htm
    TracingFlags: ULONG,

    // Fields appended in 6.2 (Windows 8):
    CsrServerReadOnlySharedMemoryBase: ULONGLONG,

    // Fields appended in 1511:
    TppWorkerpListLock: ULONG,
    TppWorkerpList: LIST_ENTRY,
    WaitOnAddressHashTable: [0x80]PVOID,

    // Fields appended in 1709:
    TelemetryCoverageHeader: PVOID,
    CloudFileFlags: ULONG,
};

/// The `PEB_LDR_DATA` structure is the main record of what modules are loaded in a process.
/// It is essentially the head of three double-linked lists of `LDR_DATA_TABLE_ENTRY` structures which each represent one loaded module.
///
/// Microsoft documentation of this is incomplete, the fields here are taken from various resources including:
///  - https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb_ldr_data.htm
pub const PEB_LDR_DATA = extern struct {
    // Versions: 3.51 and higher
    /// The size in bytes of the structure
    Length: ULONG,

    /// TRUE if the structure is prepared.
    Initialized: BOOLEAN,

    SsHandle: PVOID,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,

    // Versions: 5.1 and higher

    /// No known use of this field is known in Windows 8 and higher.
    EntryInProgress: PVOID,

    // Versions: 6.0 from Windows Vista SP1, and higher
    ShutdownInProgress: BOOLEAN,

    /// Though ShutdownThreadId is declared as a HANDLE,
    /// it is indeed the thread ID as suggested by its name.
    /// It is picked up from the UniqueThread member of the CLIENT_ID in the
    /// TEB of the thread that asks to terminate the process.
    ShutdownThreadId: HANDLE,
};

/// Microsoft documentation of this is incomplete, the fields here are taken from various resources including:
///  - https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
///  - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Reserved5: [3]PVOID,
    DUMMYUNIONNAME: extern union {
        CheckSum: ULONG,
        Reserved6: PVOID,
    },
    TimeDateStamp: ULONG,
};

pub const RTL_USER_PROCESS_PARAMETERS = extern struct {
    AllocationSize: ULONG,
    Size: ULONG,
    Flags: ULONG,
    DebugFlags: ULONG,
    ConsoleHandle: HANDLE,
    ConsoleFlags: ULONG,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
    CurrentDirectory: CURDIR,
    DllPath: UNICODE_STRING,
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
    /// Points to a NUL-terminated sequence of NUL-terminated
    /// WTF-16 LE encoded `name=value` sequences.
    /// Example using string literal syntax:
    /// `"NAME=value\x00foo=bar\x00\x00"`
    Environment: [*:0]WCHAR,
    dwX: ULONG,
    dwY: ULONG,
    dwXSize: ULONG,
    dwYSize: ULONG,
    dwXCountChars: ULONG,
    dwYCountChars: ULONG,
    dwFillAttribute: ULONG,
    dwFlags: ULONG,
    dwShowWindow: ULONG,
    WindowTitle: UNICODE_STRING,
    Desktop: UNICODE_STRING,
    ShellInfo: UNICODE_STRING,
    RuntimeInfo: UNICODE_STRING,
    DLCurrentDirectory: [0x20]RTL_DRIVE_LETTER_CURDIR,
};

pub const RTL_DRIVE_LETTER_CURDIR = extern struct {
    Flags: c_ushort,
    Length: c_ushort,
    TimeStamp: ULONG,
    DosPath: UNICODE_STRING,
};

pub const PPS_POST_PROCESS_INIT_ROUTINE = ?*const fn () callconv(.winapi) void;

pub const FILE_DIRECTORY_INFORMATION = extern struct {
    NextEntryOffset: ULONG,
    FileIndex: ULONG,
    CreationTime: LARGE_INTEGER,
    LastAccessTime: LARGE_INTEGER,
    LastWriteTime: LARGE_INTEGER,
    ChangeTime: LARGE_INTEGER,
    EndOfFile: LARGE_INTEGER,
    AllocationSize: LARGE_INTEGER,
    FileAttributes: ULONG,
    FileNameLength: ULONG,
    FileName: [1]WCHAR,
};

pub const FILE_BOTH_DIR_INFORMATION = extern struct {
    NextEntryOffset: ULONG,
    FileIndex: ULONG,
    CreationTime: LARGE_INTEGER,
    LastAccessTime: LARGE_INTEGER,
    LastWriteTime: LARGE_INTEGER,
    ChangeTime: LARGE_INTEGER,
    EndOfFile: LARGE_INTEGER,
    AllocationSize: LARGE_INTEGER,
    FileAttributes: ULONG,
    FileNameLength: ULONG,
    EaSize: ULONG,
    ShortNameLength: CHAR,
    ShortName: [12]WCHAR,
    FileName: [1]WCHAR,
};
pub const FILE_BOTH_DIRECTORY_INFORMATION = FILE_BOTH_DIR_INFORMATION;

/// Helper for iterating a byte buffer of FILE_*_INFORMATION structures (from
/// things like NtQueryDirectoryFile calls).
pub fn FileInformationIterator(comptime FileInformationType: type) type {
    return struct {
        byte_offset: usize = 0,
        buf: []u8 align(@alignOf(FileInformationType)),

        pub fn next(self: *@This()) ?*FileInformationType {
            if (self.byte_offset >= self.buf.len) return null;
            const cur: *FileInformationType = @ptrCast(@alignCast(&self.buf[self.byte_offset]));
            if (cur.NextEntryOffset == 0) {
                self.byte_offset = self.buf.len;
            } else {
                self.byte_offset += cur.NextEntryOffset;
            }
            return cur;
        }
    };
}

pub const IO_APC_ROUTINE = *const fn (PVOID, *IO_STATUS_BLOCK, ULONG) callconv(.winapi) void;

pub const CURDIR = extern struct {
    DosPath: UNICODE_STRING,
    Handle: HANDLE,
};

pub const DUPLICATE_SAME_ACCESS = 2;

pub const MODULEINFO = extern struct {
    lpBaseOfDll: LPVOID,
    SizeOfImage: DWORD,
    EntryPoint: LPVOID,
};

pub const PSAPI_WS_WATCH_INFORMATION = extern struct {
    FaultingPc: LPVOID,
    FaultingVa: LPVOID,
};

pub const VM_COUNTERS = extern struct {
    PeakVirtualSize: SIZE_T,
    VirtualSize: SIZE_T,
    PageFaultCount: ULONG,
    PeakWorkingSetSize: SIZE_T,
    WorkingSetSize: SIZE_T,
    QuotaPeakPagedPoolUsage: SIZE_T,
    QuotaPagedPoolUsage: SIZE_T,
    QuotaPeakNonPagedPoolUsage: SIZE_T,
    QuotaNonPagedPoolUsage: SIZE_T,
    PagefileUsage: SIZE_T,
    PeakPagefileUsage: SIZE_T,
};

pub const PROCESS_MEMORY_COUNTERS = extern struct {
    cb: DWORD,
    PageFaultCount: DWORD,
    PeakWorkingSetSize: SIZE_T,
    WorkingSetSize: SIZE_T,
    QuotaPeakPagedPoolUsage: SIZE_T,
    QuotaPagedPoolUsage: SIZE_T,
    QuotaPeakNonPagedPoolUsage: SIZE_T,
    QuotaNonPagedPoolUsage: SIZE_T,
    PagefileUsage: SIZE_T,
    PeakPagefileUsage: SIZE_T,
};

pub const PROCESS_MEMORY_COUNTERS_EX = extern struct {
    cb: DWORD,
    PageFaultCount: DWORD,
    PeakWorkingSetSize: SIZE_T,
    WorkingSetSize: SIZE_T,
    QuotaPeakPagedPoolUsage: SIZE_T,
    QuotaPagedPoolUsage: SIZE_T,
    QuotaPeakNonPagedPoolUsage: SIZE_T,
    QuotaNonPagedPoolUsage: SIZE_T,
    PagefileUsage: SIZE_T,
    PeakPagefileUsage: SIZE_T,
    PrivateUsage: SIZE_T,
};

pub const GetProcessMemoryInfoError = error{
    AccessDenied,
    InvalidHandle,
    Unexpected,
};

pub fn GetProcessMemoryInfo(hProcess: HANDLE) GetProcessMemoryInfoError!VM_COUNTERS {
    var vmc: VM_COUNTERS = undefined;
    const rc = ntdll.NtQueryInformationProcess(hProcess, .ProcessVmCounters, &vmc, @sizeOf(VM_COUNTERS), null);
    switch (rc) {
        .SUCCESS => return vmc,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_HANDLE => return error.InvalidHandle,
        .INVALID_PARAMETER => unreachable,
        else => return unexpectedStatus(rc),
    }
}

pub const PERFORMANCE_INFORMATION = extern struct {
    cb: DWORD,
    CommitTotal: SIZE_T,
    CommitLimit: SIZE_T,
    CommitPeak: SIZE_T,
    PhysicalTotal: SIZE_T,
    PhysicalAvailable: SIZE_T,
    SystemCache: SIZE_T,
    KernelTotal: SIZE_T,
    KernelPaged: SIZE_T,
    KernelNonpaged: SIZE_T,
    PageSize: SIZE_T,
    HandleCount: DWORD,
    ProcessCount: DWORD,
    ThreadCount: DWORD,
};

pub const ENUM_PAGE_FILE_INFORMATION = extern struct {
    cb: DWORD,
    Reserved: DWORD,
    TotalSize: SIZE_T,
    TotalInUse: SIZE_T,
    PeakUsage: SIZE_T,
};

pub const PENUM_PAGE_FILE_CALLBACKW = ?*const fn (?LPVOID, *ENUM_PAGE_FILE_INFORMATION, LPCWSTR) callconv(.winapi) BOOL;
pub const PENUM_PAGE_FILE_CALLBACKA = ?*const fn (?LPVOID, *ENUM_PAGE_FILE_INFORMATION, LPCSTR) callconv(.winapi) BOOL;

pub const PSAPI_WS_WATCH_INFORMATION_EX = extern struct {
    BasicInfo: PSAPI_WS_WATCH_INFORMATION,
    FaultingThreadId: ULONG_PTR,
    Flags: ULONG_PTR,
};

pub const OSVERSIONINFOW = extern struct {
    dwOSVersionInfoSize: ULONG,
    dwMajorVersion: ULONG,
    dwMinorVersion: ULONG,
    dwBuildNumber: ULONG,
    dwPlatformId: ULONG,
    szCSDVersion: [128]WCHAR,
};
pub const RTL_OSVERSIONINFOW = OSVERSIONINFOW;

pub const REPARSE_DATA_BUFFER = extern struct {
    ReparseTag: ULONG,
    ReparseDataLength: USHORT,
    Reserved: USHORT,
    DataBuffer: [1]UCHAR,
};
pub const SYMBOLIC_LINK_REPARSE_BUFFER = extern struct {
    SubstituteNameOffset: USHORT,
    SubstituteNameLength: USHORT,
    PrintNameOffset: USHORT,
    PrintNameLength: USHORT,
    Flags: ULONG,
    PathBuffer: [1]WCHAR,
};
pub const MOUNT_POINT_REPARSE_BUFFER = extern struct {
    SubstituteNameOffset: USHORT,
    SubstituteNameLength: USHORT,
    PrintNameOffset: USHORT,
    PrintNameLength: USHORT,
    PathBuffer: [1]WCHAR,
};
pub const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: ULONG = 16 * 1024;
pub const FSCTL_SET_REPARSE_POINT: DWORD = 0x900a4;
pub const FSCTL_GET_REPARSE_POINT: DWORD = 0x900a8;
pub const IO_REPARSE_TAG_SYMLINK: ULONG = 0xa000000c;
pub const IO_REPARSE_TAG_MOUNT_POINT: ULONG = 0xa0000003;
pub const SYMLINK_FLAG_RELATIVE: ULONG = 0x1;

pub const SYMBOLIC_LINK_FLAG_DIRECTORY: DWORD = 0x1;
pub const SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE: DWORD = 0x2;

pub const MOUNTMGRCONTROLTYPE = 0x0000006D;

pub const MOUNTMGR_MOUNT_POINT = extern struct {
    SymbolicLinkNameOffset: ULONG,
    SymbolicLinkNameLength: USHORT,
    Reserved1: USHORT,
    UniqueIdOffset: ULONG,
    UniqueIdLength: USHORT,
    Reserved2: USHORT,
    DeviceNameOffset: ULONG,
    DeviceNameLength: USHORT,
    Reserved3: USHORT,
};
pub const MOUNTMGR_MOUNT_POINTS = extern struct {
    Size: ULONG,
    NumberOfMountPoints: ULONG,
    MountPoints: [1]MOUNTMGR_MOUNT_POINT,
};
pub const IOCTL_MOUNTMGR_QUERY_POINTS = CTL_CODE(MOUNTMGRCONTROLTYPE, 2, .METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const MOUNTMGR_TARGET_NAME = extern struct {
    DeviceNameLength: USHORT,
    DeviceName: [1]WCHAR,
};
pub const MOUNTMGR_VOLUME_PATHS = extern struct {
    MultiSzLength: ULONG,
    MultiSz: [1]WCHAR,
};
pub const IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH = CTL_CODE(MOUNTMGRCONTROLTYPE, 12, .METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const OBJECT_INFORMATION_CLASS = enum(c_int) {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectTypesInformation = 3,
    ObjectHandleFlagInformation = 4,
    ObjectSessionInformation = 5,
    MaxObjectInfoClass,
};

pub const OBJECT_NAME_INFORMATION = extern struct {
    Name: UNICODE_STRING,
};

pub const SRWLOCK_INIT = SRWLOCK{};
pub const SRWLOCK = extern struct {
    Ptr: ?PVOID = null,
};

pub const CONDITION_VARIABLE_INIT = CONDITION_VARIABLE{};
pub const CONDITION_VARIABLE = extern struct {
    Ptr: ?PVOID = null,
};

pub const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS = 0x1;
pub const FILE_SKIP_SET_EVENT_ON_HANDLE = 0x2;

pub const CTRL_C_EVENT: DWORD = 0;
pub const CTRL_BREAK_EVENT: DWORD = 1;
pub const CTRL_CLOSE_EVENT: DWORD = 2;
pub const CTRL_LOGOFF_EVENT: DWORD = 5;
pub const CTRL_SHUTDOWN_EVENT: DWORD = 6;

pub const HANDLER_ROUTINE = *const fn (dwCtrlType: DWORD) callconv(.winapi) BOOL;

/// Processor feature enumeration.
pub const PF = enum(DWORD) {
    /// On a Pentium, a floating-point precision error can occur in rare circumstances.
    FLOATING_POINT_PRECISION_ERRATA = 0,

    /// Floating-point operations are emulated using software emulator.
    /// This function returns a nonzero value if floating-point operations are emulated; otherwise, it returns zero.
    FLOATING_POINT_EMULATED = 1,

    /// The atomic compare and exchange operation (cmpxchg) is available.
    COMPARE_EXCHANGE_DOUBLE = 2,

    /// The MMX instruction set is available.
    MMX_INSTRUCTIONS_AVAILABLE = 3,

    PPC_MOVEMEM_64BIT_OK = 4,
    ALPHA_BYTE_INSTRUCTIONS = 5,

    /// The SSE instruction set is available.
    XMMI_INSTRUCTIONS_AVAILABLE = 6,

    /// The 3D-Now instruction is available.
    @"3DNOW_INSTRUCTIONS_AVAILABLE" = 7,

    /// The RDTSC instruction is available.
    RDTSC_INSTRUCTION_AVAILABLE = 8,

    /// The processor is PAE-enabled.
    PAE_ENABLED = 9,

    /// The SSE2 instruction set is available.
    XMMI64_INSTRUCTIONS_AVAILABLE = 10,

    SSE_DAZ_MODE_AVAILABLE = 11,

    /// Data execution prevention is enabled.
    NX_ENABLED = 12,

    /// The SSE3 instruction set is available.
    SSE3_INSTRUCTIONS_AVAILABLE = 13,

    /// The atomic compare and exchange 128-bit operation (cmpxchg16b) is available.
    COMPARE_EXCHANGE128 = 14,

    /// The atomic compare 64 and exchange 128-bit operation (cmp8xchg16) is available.
    COMPARE64_EXCHANGE128 = 15,

    /// The processor channels are enabled.
    CHANNELS_ENABLED = 16,

    /// The processor implements the XSAVI and XRSTOR instructions.
    XSAVE_ENABLED = 17,

    /// The VFP/Neon: 32 x 64bit register bank is present.
    /// This flag has the same meaning as PF_ARM_VFP_EXTENDED_REGISTERS.
    ARM_VFP_32_REGISTERS_AVAILABLE = 18,

    /// This ARM processor implements the ARM v8 NEON instruction set.
    ARM_NEON_INSTRUCTIONS_AVAILABLE = 19,

    /// Second Level Address Translation is supported by the hardware.
    SECOND_LEVEL_ADDRESS_TRANSLATION = 20,

    /// Virtualization is enabled in the firmware and made available by the operating system.
    VIRT_FIRMWARE_ENABLED = 21,

    /// RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE instructions are available.
    RDWRFSGBASE_AVAILABLE = 22,

    /// _fastfail() is available.
    FASTFAIL_AVAILABLE = 23,

    /// The divide instruction_available.
    ARM_DIVIDE_INSTRUCTION_AVAILABLE = 24,

    /// The 64-bit load/store atomic instructions are available.
    ARM_64BIT_LOADSTORE_ATOMIC = 25,

    /// The external cache is available.
    ARM_EXTERNAL_CACHE_AVAILABLE = 26,

    /// The floating-point multiply-accumulate instruction is available.
    ARM_FMAC_INSTRUCTIONS_AVAILABLE = 27,

    RDRAND_INSTRUCTION_AVAILABLE = 28,

    /// This ARM processor implements the ARM v8 instructions set.
    ARM_V8_INSTRUCTIONS_AVAILABLE = 29,

    /// This ARM processor implements the ARM v8 extra cryptographic instructions (i.e., AES, SHA1 and SHA2).
    ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE = 30,

    /// This ARM processor implements the ARM v8 extra CRC32 instructions.
    ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE = 31,

    RDTSCP_INSTRUCTION_AVAILABLE = 32,
    RDPID_INSTRUCTION_AVAILABLE = 33,

    /// This ARM processor implements the ARM v8.1 atomic instructions (e.g., CAS, SWP).
    ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE = 34,

    MONITORX_INSTRUCTION_AVAILABLE = 35,

    /// The SSSE3 instruction set is available.
    SSSE3_INSTRUCTIONS_AVAILABLE = 36,

    /// The SSE4_1 instruction set is available.
    SSE4_1_INSTRUCTIONS_AVAILABLE = 37,

    /// The SSE4_2 instruction set is available.
    SSE4_2_INSTRUCTIONS_AVAILABLE = 38,

    /// The AVX instruction set is available.
    AVX_INSTRUCTIONS_AVAILABLE = 39,

    /// The AVX2 instruction set is available.
    AVX2_INSTRUCTIONS_AVAILABLE = 40,

    /// The AVX512F instruction set is available.
    AVX512F_INSTRUCTIONS_AVAILABLE = 41,

    ERMS_AVAILABLE = 42,

    /// This ARM processor implements the ARM v8.2 Dot Product (DP) instructions.
    ARM_V82_DP_INSTRUCTIONS_AVAILABLE = 43,

    /// This ARM processor implements the ARM v8.3 JavaScript conversion (JSCVT) instructions.
    ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE = 44,

    /// This Arm processor implements the Arm v8.3 LRCPC instructions (for example, LDAPR). Note that certain Arm v8.2 CPUs may optionally support the LRCPC instructions.
    ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE,
};

pub const MAX_WOW64_SHARED_ENTRIES = 16;
pub const PROCESSOR_FEATURE_MAX = 64;
pub const MAXIMUM_XSTATE_FEATURES = 64;

pub const KSYSTEM_TIME = extern struct {
    LowPart: ULONG,
    High1Time: LONG,
    High2Time: LONG,
};

pub const NT_PRODUCT_TYPE = enum(INT) {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer,
};

pub const ALTERNATIVE_ARCHITECTURE_TYPE = enum(INT) {
    StandardDesign,
    NEC98x86,
    EndAlternatives,
};

pub const XSTATE_FEATURE = extern struct {
    Offset: ULONG,
    Size: ULONG,
};

pub const XSTATE_CONFIGURATION = extern struct {
    EnabledFeatures: ULONG64,
    Size: ULONG,
    OptimizedSave: ULONG,
    Features: [MAXIMUM_XSTATE_FEATURES]XSTATE_FEATURE,
};

/// Shared Kernel User Data
pub const KUSER_SHARED_DATA = extern struct {
    TickCountLowDeprecated: ULONG,
    TickCountMultiplier: ULONG,
    InterruptTime: KSYSTEM_TIME,
    SystemTime: KSYSTEM_TIME,
    TimeZoneBias: KSYSTEM_TIME,
    ImageNumberLow: USHORT,
    ImageNumberHigh: USHORT,
    NtSystemRoot: [260]WCHAR,
    MaxStackTraceDepth: ULONG,
    CryptoExponent: ULONG,
    TimeZoneId: ULONG,
    LargePageMinimum: ULONG,
    AitSamplingValue: ULONG,
    AppCompatFlag: ULONG,
    RNGSeedVersion: ULONGLONG,
    GlobalValidationRunlevel: ULONG,
    TimeZoneBiasStamp: LONG,
    NtBuildNumber: ULONG,
    NtProductType: NT_PRODUCT_TYPE,
    ProductTypeIsValid: BOOLEAN,
    Reserved0: [1]BOOLEAN,
    NativeProcessorArchitecture: USHORT,
    NtMajorVersion: ULONG,
    NtMinorVersion: ULONG,
    ProcessorFeatures: [PROCESSOR_FEATURE_MAX]BOOLEAN,
    Reserved1: ULONG,
    Reserved3: ULONG,
    TimeSlip: ULONG,
    AlternativeArchitecture: ALTERNATIVE_ARCHITECTURE_TYPE,
    BootId: ULONG,
    SystemExpirationDate: LARGE_INTEGER,
    SuiteMaskY: ULONG,
    KdDebuggerEnabled: BOOLEAN,
    DummyUnion1: extern union {
        MitigationPolicies: UCHAR,
        Alt: packed struct {
            NXSupportPolicy: u2,
            SEHValidationPolicy: u2,
            CurDirDevicesSkippedForDlls: u2,
            Reserved: u2,
        },
    },
    CyclesPerYield: USHORT,
    ActiveConsoleId: ULONG,
    DismountCount: ULONG,
    ComPlusPackage: ULONG,
    LastSystemRITEventTickCount: ULONG,
    NumberOfPhysicalPages: ULONG,
    SafeBootMode: BOOLEAN,
    DummyUnion2: extern union {
        VirtualizationFlags: UCHAR,
        Alt: packed struct {
            ArchStartedInEl2: u1,
            QcSlIsSupported: u1,
            SpareBits: u6,
        },
    },
    Reserved12: [2]UCHAR,
    DummyUnion3: extern union {
        SharedDataFlags: ULONG,
        Alt: packed struct {
            DbgErrorPortPresent: u1,
            DbgElevationEnabled: u1,
            DbgVirtEnabled: u1,
            DbgInstallerDetectEnabled: u1,
            DbgLkgEnabled: u1,
            DbgDynProcessorEnabled: u1,
            DbgConsoleBrokerEnabled: u1,
            DbgSecureBootEnabled: u1,
            DbgMultiSessionSku: u1,
            DbgMultiUsersInSessionSku: u1,
            DbgStateSeparationEnabled: u1,
            SpareBits: u21,
        },
    },
    DataFlagsPad: [1]ULONG,
    TestRetInstruction: ULONGLONG,
    QpcFrequency: LONGLONG,
    SystemCall: ULONG,
    Reserved2: ULONG,
    SystemCallPad: [2]ULONGLONG,
    DummyUnion4: extern union {
        TickCount: KSYSTEM_TIME,
        TickCountQuad: ULONG64,
        Alt: extern struct {
            ReservedTickCountOverlay: [3]ULONG,
            TickCountPad: [1]ULONG,
        },
    },
    Cookie: ULONG,
    CookiePad: [1]ULONG,
    ConsoleSessionForegroundProcessId: LONGLONG,
    TimeUpdateLock: ULONGLONG,
    BaselineSystemTimeQpc: ULONGLONG,
    BaselineInterruptTimeQpc: ULONGLONG,
    QpcSystemTimeIncrement: ULONGLONG,
    QpcInterruptTimeIncrement: ULONGLONG,
    QpcSystemTimeIncrementShift: UCHAR,
    QpcInterruptTimeIncrementShift: UCHAR,
    UnparkedProcessorCount: USHORT,
    EnclaveFeatureMask: [4]ULONG,
    TelemetryCoverageRound: ULONG,
    UserModeGlobalLogger: [16]USHORT,
    ImageFileExecutionOptions: ULONG,
    LangGenerationCount: ULONG,
    Reserved4: ULONGLONG,
    InterruptTimeBias: ULONGLONG,
    QpcBias: ULONGLONG,
    ActiveProcessorCount: ULONG,
    ActiveGroupCount: UCHAR,
    Reserved9: UCHAR,
    DummyUnion5: extern union {
        QpcData: USHORT,
        Alt: extern struct {
            QpcBypassEnabled: UCHAR,
            QpcShift: UCHAR,
        },
    },
    TimeZoneBiasEffectiveStart: LARGE_INTEGER,
    TimeZoneBiasEffectiveEnd: LARGE_INTEGER,
    XState: XSTATE_CONFIGURATION,
    FeatureConfigurationChangeStamp: KSYSTEM_TIME,
    Spare: ULONG,
    UserPointerAuthMask: ULONG64,
};

/// Read-only user-mode address for the shared data.
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
/// https://msrc-blog.microsoft.com/2022/04/05/randomizing-the-kuser_shared_data-structure-on-windows/
pub const SharedUserData: *const KUSER_SHARED_DATA = @as(*const KUSER_SHARED_DATA, @ptrFromInt(0x7FFE0000));

pub fn IsProcessorFeaturePresent(feature: PF) bool {
    if (@intFromEnum(feature) >= PROCESSOR_FEATURE_MAX) return false;
    return SharedUserData.ProcessorFeatures[@intFromEnum(feature)] == 1;
}

pub const TH32CS_SNAPHEAPLIST = 0x00000001;
pub const TH32CS_SNAPPROCESS = 0x00000002;
pub const TH32CS_SNAPTHREAD = 0x00000004;
pub const TH32CS_SNAPMODULE = 0x00000008;
pub const TH32CS_SNAPMODULE32 = 0x00000010;
pub const TH32CS_SNAPALL = TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE;
pub const TH32CS_INHERIT = 0x80000000;

pub const MAX_MODULE_NAME32 = 255;
pub const MODULEENTRY32 = extern struct {
    dwSize: DWORD,
    th32ModuleID: DWORD,
    th32ProcessID: DWORD,
    GlblcntUsage: DWORD,
    ProccntUsage: DWORD,
    modBaseAddr: *BYTE,
    modBaseSize: DWORD,
    hModule: HMODULE,
    szModule: [MAX_MODULE_NAME32 + 1]CHAR,
    szExePath: [MAX_PATH]CHAR,
};

pub const SYSTEM_INFORMATION_CLASS = enum(c_int) {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
};

pub const SYSTEM_BASIC_INFORMATION = extern struct {
    Reserved: ULONG,
    TimerResolution: ULONG,
    PageSize: ULONG,
    NumberOfPhysicalPages: ULONG,
    LowestPhysicalPageNumber: ULONG,
    HighestPhysicalPageNumber: ULONG,
    AllocationGranularity: ULONG,
    MinimumUserModeAddress: ULONG_PTR,
    MaximumUserModeAddress: ULONG_PTR,
    ActiveProcessorsAffinityMask: KAFFINITY,
    NumberOfProcessors: UCHAR,
};

pub const THREADINFOCLASS = enum(c_int) {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    // Windows 2000+ from here
    ThreadHideFromDebugger,
    // Windows XP+ from here
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    // Windows Vista+ from here
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    // Windows 7+ from here
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    // Windows 8+ from here
    ThreadCpuAccountingInformation,
    // Windows 8.1+ from here
    ThreadSuspendCount,
    // Windows 10+ from here
    ThreadHeterogeneousCpuPolicy,
    ThreadContainerId,
    ThreadNameInformation,
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation,
    ThreadActualGroupAffinity,
};

pub const PROCESSINFOCLASS = enum(c_int) {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass,
};

pub const PROCESS_BASIC_INFORMATION = extern struct {
    ExitStatus: NTSTATUS,
    PebBaseAddress: *PEB,
    AffinityMask: ULONG_PTR,
    BasePriority: KPRIORITY,
    UniqueProcessId: ULONG_PTR,
    InheritedFromUniqueProcessId: ULONG_PTR,
};

pub const ReadMemoryError = error{
    Unexpected,
};

pub fn ReadProcessMemory(handle: HANDLE, addr: ?LPVOID, buffer: []u8) ReadMemoryError![]u8 {
    var nread: usize = 0;
    switch (ntdll.NtReadVirtualMemory(
        handle,
        addr,
        buffer.ptr,
        buffer.len,
        &nread,
    )) {
        .SUCCESS => return buffer[0..nread],
        // TODO: map errors
        else => |rc| return unexpectedStatus(rc),
    }
}

pub const WriteMemoryError = error{
    Unexpected,
};

pub fn WriteProcessMemory(handle: HANDLE, addr: ?LPVOID, buffer: []const u8) WriteMemoryError!usize {
    var nwritten: usize = 0;
    switch (ntdll.NtWriteVirtualMemory(
        handle,
        addr,
        buffer.ptr,
        buffer.len,
        &nwritten,
    )) {
        .SUCCESS => return nwritten,
        // TODO: map errors
        else => |rc| return unexpectedStatus(rc),
    }
}

pub const ProcessBaseAddressError = GetProcessMemoryInfoError || ReadMemoryError;

/// Returns the base address of the process loaded into memory.
pub fn ProcessBaseAddress(handle: HANDLE) ProcessBaseAddressError!HMODULE {
    var info: PROCESS_BASIC_INFORMATION = undefined;
    var nread: DWORD = 0;
    const rc = ntdll.NtQueryInformationProcess(
        handle,
        .ProcessBasicInformation,
        &info,
        @sizeOf(PROCESS_BASIC_INFORMATION),
        &nread,
    );
    switch (rc) {
        .SUCCESS => {},
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_HANDLE => return error.InvalidHandle,
        .INVALID_PARAMETER => unreachable,
        else => return unexpectedStatus(rc),
    }

    var peb_buf: [@sizeOf(PEB)]u8 align(@alignOf(PEB)) = undefined;
    const peb_out = try ReadProcessMemory(handle, info.PebBaseAddress, &peb_buf);
    const ppeb: *const PEB = @ptrCast(@alignCast(peb_out.ptr));
    return ppeb.ImageBaseAddress;
}
const std = @import("../../std.zig");
const windows = std.os.windows;
const BOOL = windows.BOOL;
const DWORD = windows.DWORD;
const HKEY = windows.HKEY;
const BYTE = windows.BYTE;
const LPCWSTR = windows.LPCWSTR;
const LSTATUS = windows.LSTATUS;
const REGSAM = windows.REGSAM;
const ULONG = windows.ULONG;

pub extern "advapi32" fn RegOpenKeyExW(
    hKey: HKEY,
    lpSubKey: LPCWSTR,
    ulOptions: DWORD,
    samDesired: REGSAM,
    phkResult: *HKEY,
) callconv(.winapi) LSTATUS;

pub extern "advapi32" fn RegQueryValueExW(
    hKey: HKEY,
    lpValueName: LPCWSTR,
    lpReserved: ?*DWORD,
    lpType: ?*DWORD,
    lpData: ?*BYTE,
    lpcbData: ?*DWORD,
) callconv(.winapi) LSTATUS;

pub extern "advapi32" fn RegCloseKey(hKey: HKEY) callconv(.winapi) LSTATUS;

// RtlGenRandom is known as SystemFunction036 under advapi32
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa387694.aspx */
pub extern "advapi32" fn SystemFunction036(output: [*]u8, length: ULONG) callconv(.winapi) BOOL;
pub const RtlGenRandom = SystemFunction036;

pub const RRF = struct {
    pub const RT_ANY: DWORD = 0x0000ffff;

    pub const RT_DWORD: DWORD = 0x00000018;
    pub const RT_QWORD: DWORD = 0x00000048;

    pub const RT_REG_BINARY: DWORD = 0x00000008;
    pub const RT_REG_DWORD: DWORD = 0x00000010;
    pub const RT_REG_EXPAND_SZ: DWORD = 0x00000004;
    pub const RT_REG_MULTI_SZ: DWORD = 0x00000020;
    pub const RT_REG_NONE: DWORD = 0x00000001;
    pub const RT_REG_QWORD: DWORD = 0x00000040;
    pub const RT_REG_SZ: DWORD = 0x00000002;

    pub const NOEXPAND: DWORD = 0x10000000;
    pub const ZEROONFAILURE: DWORD = 0x20000000;
    pub const SUBKEY_WOW6464KEY: DWORD = 0x00010000;
    pub const SUBKEY_WOW6432KEY: DWORD = 0x00020000;
};

pub extern "advapi32" fn RegGetValueW(
    hkey: HKEY,
    lpSubKey: LPCWSTR,
    lpValue: LPCWSTR,
    dwFlags: DWORD,
    pdwType: ?*DWORD,
    pvData: ?*anyopaque,
    pcbData: ?*DWORD,
) callconv(.winapi) LSTATUS;

pub extern "advapi32" fn RegLoadAppKeyW(
    lpFile: LPCWSTR,
    phkResult: *HKEY,
    samDesired: REGSAM,
    dwOptions: DWORD,
    reserved: DWORD,
) callconv(.winapi) LSTATUS;
const std = @import("../../std.zig");
const windows = std.os.windows;
const BOOL = windows.BOOL;
const DWORD = windows.DWORD;
const BYTE = windows.BYTE;
const LPCWSTR = windows.LPCWSTR;

pub const CERT_INFO = *opaque {};
pub const HCERTSTORE = *opaque {};
pub const CERT_CONTEXT = extern struct {
    dwCertEncodingType: DWORD,
    pbCertEncoded: [*]BYTE,
    cbCertEncoded: DWORD,
    pCertInfo: CERT_INFO,
    hCertStore: HCERTSTORE,
};

pub extern "crypt32" fn CertOpenSystemStoreW(
    _: ?*const anyopaque,
    szSubsystemProtocol: LPCWSTR,
) callconv(.winapi) ?HCERTSTORE;

pub extern "crypt32" fn CertCloseStore(
    hCertStore: HCERTSTORE,
    dwFlags: DWORD,
) callconv(.winapi) BOOL;

pub extern "crypt32" fn CertEnumCertificatesInStore(
    hCertStore: HCERTSTORE,
    pPrevCertContext: ?*CERT_CONTEXT,
) callconv(.winapi) ?*CERT_CONTEXT;
const std = @import("../../std.zig");
const windows = std.os.windows;

const BOOL = windows.BOOL;
const BOOLEAN = windows.BOOLEAN;
const CONDITION_VARIABLE = windows.CONDITION_VARIABLE;
const CONSOLE_SCREEN_BUFFER_INFO = windows.CONSOLE_SCREEN_BUFFER_INFO;
const COORD = windows.COORD;
const CRITICAL_SECTION = windows.CRITICAL_SECTION;
const DWORD = windows.DWORD;
const FARPROC = windows.FARPROC;
const FILETIME = windows.FILETIME;
const HANDLE = windows.HANDLE;
const HANDLER_ROUTINE = windows.HANDLER_ROUTINE;
const HLOCAL = windows.HLOCAL;
const HMODULE = windows.HMODULE;
const INIT_ONCE = windows.INIT_ONCE;
const INIT_ONCE_FN = windows.INIT_ONCE_FN;
const LARGE_INTEGER = windows.LARGE_INTEGER;
const LPCSTR = windows.LPCSTR;
const LPCVOID = windows.LPCVOID;
const LPCWSTR = windows.LPCWSTR;
const LPTHREAD_START_ROUTINE = windows.LPTHREAD_START_ROUTINE;
const LPVOID = windows.LPVOID;
const LPWSTR = windows.LPWSTR;
const MODULEENTRY32 = windows.MODULEENTRY32;
const OVERLAPPED = windows.OVERLAPPED;
const OVERLAPPED_ENTRY = windows.OVERLAPPED_ENTRY;
const PMEMORY_BASIC_INFORMATION = windows.PMEMORY_BASIC_INFORMATION;
const PROCESS_INFORMATION = windows.PROCESS_INFORMATION;
const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
const SIZE_T = windows.SIZE_T;
const SRWLOCK = windows.SRWLOCK;
const STARTUPINFOW = windows.STARTUPINFOW;
const UCHAR = windows.UCHAR;
const UINT = windows.UINT;
const ULONG = windows.ULONG;
const ULONG_PTR = windows.ULONG_PTR;
const va_list = windows.va_list;
const VECTORED_EXCEPTION_HANDLER = windows.VECTORED_EXCEPTION_HANDLER;
const WCHAR = windows.WCHAR;
const WIN32_FIND_DATAW = windows.WIN32_FIND_DATAW;
const Win32Error = windows.Win32Error;
const WORD = windows.WORD;
const SYSTEM_INFO = windows.SYSTEM_INFO;

// I/O - Filesystem

pub extern "kernel32" fn ReadDirectoryChangesW(
    hDirectory: windows.HANDLE,
    lpBuffer: [*]align(@alignOf(windows.FILE_NOTIFY_INFORMATION)) u8,
    nBufferLength: windows.DWORD,
    bWatchSubtree: windows.BOOL,
    dwNotifyFilter: windows.FileNotifyChangeFilter,
    lpBytesReturned: ?*windows.DWORD,
    lpOverlapped: ?*windows.OVERLAPPED,
    lpCompletionRoutine: windows.LPOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) windows.BOOL;

// TODO: Wrapper around NtCancelIoFile.
pub extern "kernel32" fn CancelIo(
    hFile: HANDLE,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtCancelIoFileEx.
pub extern "kernel32" fn CancelIoEx(
    hFile: HANDLE,
    lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateFileW(
    lpFileName: LPCWSTR,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: ?*SECURITY_ATTRIBUTES,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: ?HANDLE,
) callconv(.winapi) HANDLE;

// TODO A bunch of logic around NtCreateNamedPipe
pub extern "kernel32" fn CreateNamedPipeW(
    lpName: LPCWSTR,
    dwOpenMode: DWORD,
    dwPipeMode: DWORD,
    nMaxInstances: DWORD,
    nOutBufferSize: DWORD,
    nInBufferSize: DWORD,
    nDefaultTimeOut: DWORD,
    lpSecurityAttributes: ?*const SECURITY_ATTRIBUTES,
) callconv(.winapi) HANDLE;

pub extern "kernel32" fn FindFirstFileW(
    lpFileName: LPCWSTR,
    lpFindFileData: *WIN32_FIND_DATAW,
) callconv(.winapi) HANDLE;

pub extern "kernel32" fn FindClose(
    hFindFile: HANDLE,
) callconv(.winapi) BOOL;

// TODO: Wrapper around RtlGetFullPathName_UEx
pub extern "kernel32" fn GetFullPathNameW(
    lpFileName: LPCWSTR,
    nBufferLength: DWORD,
    lpBuffer: LPWSTR,
    lpFilePart: ?*?LPWSTR,
) callconv(.winapi) DWORD;

// TODO: Matches `STD_*_HANDLE` to peb().ProcessParameters.Standard*
pub extern "kernel32" fn GetStdHandle(
    nStdHandle: DWORD,
) callconv(.winapi) ?HANDLE;

pub extern "kernel32" fn MoveFileExW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    dwFlags: DWORD,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtSetInformationFile + `FILE_POSITION_INFORMATION`.
//  `FILE_STANDARD_INFORMATION` is also used if dwMoveMethod is `FILE_END`
pub extern "kernel32" fn SetFilePointerEx(
    hFile: HANDLE,
    liDistanceToMove: LARGE_INTEGER,
    lpNewFilePointer: ?*LARGE_INTEGER,
    dwMoveMethod: DWORD,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtSetInformationFile + `FILE_BASIC_INFORMATION`
pub extern "kernel32" fn SetFileTime(
    hFile: HANDLE,
    lpCreationTime: ?*const FILETIME,
    lpLastAccessTime: ?*const FILETIME,
    lpLastWriteTime: ?*const FILETIME,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn WriteFile(
    in_hFile: HANDLE,
    in_lpBuffer: [*]const u8,
    in_nNumberOfBytesToWrite: DWORD,
    out_lpNumberOfBytesWritten: ?*DWORD,
    in_out_lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;

// TODO: wrapper for NtQueryInformationFile + `FILE_STANDARD_INFORMATION`
pub extern "kernel32" fn GetFileSizeEx(
    hFile: HANDLE,
    lpFileSize: *LARGE_INTEGER,
) callconv(.winapi) BOOL;

// TODO: Wrapper around GetStdHandle + NtFlushBuffersFile.
pub extern "kernel32" fn FlushFileBuffers(
    hFile: HANDLE,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtSetInformationFile + `FILE_IO_COMPLETION_NOTIFICATION_INFORMATION`.
pub extern "kernel32" fn SetFileCompletionNotificationModes(
    FileHandle: HANDLE,
    Flags: UCHAR,
) callconv(.winapi) BOOL;

// TODO: `RtlGetCurrentDirectory_U(nBufferLength * 2, lpBuffer)`
pub extern "kernel32" fn GetCurrentDirectoryW(
    nBufferLength: DWORD,
    lpBuffer: ?[*]WCHAR,
) callconv(.winapi) DWORD;

// TODO: RtlDosPathNameToNtPathNameU_WithStatus + NtQueryAttributesFile.
pub extern "kernel32" fn GetFileAttributesW(
    lpFileName: LPCWSTR,
) callconv(.winapi) DWORD;

pub extern "kernel32" fn ReadFile(
    hFile: HANDLE,
    lpBuffer: LPVOID,
    nNumberOfBytesToRead: DWORD,
    lpNumberOfBytesRead: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn GetSystemDirectoryW(
    lpBuffer: LPWSTR,
    uSize: UINT,
) callconv(.winapi) UINT;

// I/O - Kernel Objects

// TODO: Wrapper around NtCreateEvent.
pub extern "kernel32" fn CreateEventExW(
    lpEventAttributes: ?*SECURITY_ATTRIBUTES,
    lpName: ?LPCWSTR,
    dwFlags: DWORD,
    dwDesiredAccess: DWORD,
) callconv(.winapi) ?HANDLE;

// TODO: Wrapper around GetStdHandle + NtDuplicateObject.
pub extern "kernel32" fn DuplicateHandle(
    hSourceProcessHandle: HANDLE,
    hSourceHandle: HANDLE,
    hTargetProcessHandle: HANDLE,
    lpTargetHandle: *HANDLE,
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwOptions: DWORD,
) callconv(.winapi) BOOL;

// TODO: Wrapper around GetStdHandle + NtQueryObject + NtSetInformationObject with .ObjectHandleFlagInformation.
pub extern "kernel32" fn SetHandleInformation(
    hObject: HANDLE,
    dwMask: DWORD,
    dwFlags: DWORD,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtRemoveIoCompletion.
pub extern "kernel32" fn GetQueuedCompletionStatus(
    CompletionPort: HANDLE,
    lpNumberOfBytesTransferred: *DWORD,
    lpCompletionKey: *ULONG_PTR,
    lpOverlapped: *?*OVERLAPPED,
    dwMilliseconds: DWORD,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtRemoveIoCompletionEx.
pub extern "kernel32" fn GetQueuedCompletionStatusEx(
    CompletionPort: HANDLE,
    lpCompletionPortEntries: [*]OVERLAPPED_ENTRY,
    ulCount: ULONG,
    ulNumEntriesRemoved: *ULONG,
    dwMilliseconds: DWORD,
    fAlertable: BOOL,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtSetIoCompletion with `IoStatus = .SUCCESS`.
pub extern "kernel32" fn PostQueuedCompletionStatus(
    CompletionPort: HANDLE,
    dwNumberOfBytesTransferred: DWORD,
    dwCompletionKey: ULONG_PTR,
    lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;

// TODO:
// GetOverlappedResultEx with bAlertable=false, which calls: GetStdHandle + WaitForSingleObjectEx.
// Uses the SwitchBack system to run implementations for older programs; Do we care about this?
pub extern "kernel32" fn GetOverlappedResult(
    hFile: HANDLE,
    lpOverlapped: *OVERLAPPED,
    lpNumberOfBytesTransferred: *DWORD,
    bWait: BOOL,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtCreateIoCompletion + NtSetInformationFile with FILE_COMPLETION_INFORMATION.
// This would be better splitting into two functions.
pub extern "kernel32" fn CreateIoCompletionPort(
    FileHandle: HANDLE,
    ExistingCompletionPort: ?HANDLE,
    CompletionKey: ULONG_PTR,
    NumberOfConcurrentThreads: DWORD,
) callconv(.winapi) ?HANDLE;

// TODO: Forwarder to NtAddVectoredExceptionHandler.
pub extern "kernel32" fn AddVectoredExceptionHandler(
    First: ULONG,
    Handler: ?VECTORED_EXCEPTION_HANDLER,
) callconv(.winapi) ?LPVOID;

// TODO: Forwarder to NtRemoveVectoredExceptionHandler.
pub extern "kernel32" fn RemoveVectoredExceptionHandler(
    Handle: HANDLE,
) callconv(.winapi) ULONG;

// TODO: Wrapper around RtlReportSilentProcessExit + NtTerminateProcess.
pub extern "kernel32" fn TerminateProcess(
    hProcess: HANDLE,
    uExitCode: UINT,
) callconv(.winapi) BOOL;

// TODO: WaitForSingleObjectEx with bAlertable=false.
pub extern "kernel32" fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
) callconv(.winapi) DWORD;

// TODO: Wrapper for GetStdHandle + NtWaitForSingleObject.
// Sets up an activation context before calling NtWaitForSingleObject.
pub extern "kernel32" fn WaitForSingleObjectEx(
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
    bAlertable: BOOL,
) callconv(.winapi) DWORD;

// TODO: WaitForMultipleObjectsEx with alertable=false
pub extern "kernel32" fn WaitForMultipleObjects(
    nCount: DWORD,
    lpHandle: [*]const HANDLE,
    bWaitAll: BOOL,
    dwMilliseconds: DWORD,
) callconv(.winapi) DWORD;

// TODO: Wrapper around NtWaitForMultipleObjects.
pub extern "kernel32" fn WaitForMultipleObjectsEx(
    nCount: DWORD,
    lpHandle: [*]const HANDLE,
    bWaitAll: BOOL,
    dwMilliseconds: DWORD,
    bAlertable: BOOL,
) callconv(.winapi) DWORD;

// Process Management

pub extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?LPCWSTR,
    lpCommandLine: ?LPWSTR,
    lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: windows.CreateProcessFlags,
    lpEnvironment: ?LPVOID,
    lpCurrentDirectory: ?LPCWSTR,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(.winapi) BOOL;

// TODO: Fowarder to RtlExitUserProcess.
pub extern "kernel32" fn ExitProcess(
    exit_code: UINT,
) callconv(.winapi) noreturn;

// TODO: SleepEx with bAlertable=false.
pub extern "kernel32" fn Sleep(
    dwMilliseconds: DWORD,
) callconv(.winapi) void;

// TODO: Wrapper around NtQueryInformationProcess with `PROCESS_BASIC_INFORMATION`.
pub extern "kernel32" fn GetExitCodeProcess(
    hProcess: HANDLE,
    lpExitCode: *DWORD,
) callconv(.winapi) BOOL;

// TODO: Already a wrapper for this, see `windows.GetCurrentProcess`.
pub extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;

// TODO: memcpy peb().ProcessParameters.Environment, mem.span(0). Requires locking the PEB.
pub extern "kernel32" fn GetEnvironmentStringsW() callconv(.winapi) ?LPWSTR;

// TODO: RtlFreeHeap on the output of GetEnvironmentStringsW.
pub extern "kernel32" fn FreeEnvironmentStringsW(
    penv: LPWSTR,
) callconv(.winapi) BOOL;

// TODO: Wrapper around RtlQueryEnvironmentVariable.
pub extern "kernel32" fn GetEnvironmentVariableW(
    lpName: ?LPCWSTR,
    lpBuffer: ?[*]WCHAR,
    nSize: DWORD,
) callconv(.winapi) DWORD;

// TODO: Wrapper around RtlSetEnvironmentVar.
pub extern "kernel32" fn SetEnvironmentVariableW(
    lpName: LPCWSTR,
    lpValue: ?LPCWSTR,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateToolhelp32Snapshot(
    dwFlags: DWORD,
    th32ProcessID: DWORD,
) callconv(.winapi) HANDLE;

// Threading

// TODO: Already a wrapper for this, see `windows.GetCurrentThreadId`.
pub extern "kernel32" fn GetCurrentThreadId() callconv(.winapi) DWORD;

// TODO: CreateRemoteThread with hProcess=NtCurrentProcess().
pub extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) callconv(.winapi) ?HANDLE;

// TODO: Wrapper around RtlDelayExecution.
pub extern "kernel32" fn SwitchToThread() callconv(.winapi) BOOL;

// Locks, critical sections, initializers

// TODO: Forwarder to RtlInitializeCriticalSection
pub extern "kernel32" fn InitializeCriticalSection(
    lpCriticalSection: *CRITICAL_SECTION,
) callconv(.winapi) void;

// TODO: Forwarder to RtlEnterCriticalSection
pub extern "kernel32" fn EnterCriticalSection(
    lpCriticalSection: *CRITICAL_SECTION,
) callconv(.winapi) void;

// TODO: Forwarder to RtlLeaveCriticalSection
pub extern "kernel32" fn LeaveCriticalSection(
    lpCriticalSection: *CRITICAL_SECTION,
) callconv(.winapi) void;

// TODO: Forwarder to RtlDeleteCriticalSection
pub extern "kernel32" fn DeleteCriticalSection(
    lpCriticalSection: *CRITICAL_SECTION,
) callconv(.winapi) void;

// TODO: Forwarder to RtlTryAcquireSRWLockExclusive
pub extern "kernel32" fn TryAcquireSRWLockExclusive(
    SRWLock: *SRWLOCK,
) callconv(.winapi) BOOLEAN;

// TODO: Forwarder to RtlAcquireSRWLockExclusive
pub extern "kernel32" fn AcquireSRWLockExclusive(
    SRWLock: *SRWLOCK,
) callconv(.winapi) void;

// TODO: Forwarder to RtlReleaseSRWLockExclusive
pub extern "kernel32" fn ReleaseSRWLockExclusive(
    SRWLock: *SRWLOCK,
) callconv(.winapi) void;

pub extern "kernel32" fn InitOnceExecuteOnce(
    InitOnce: *INIT_ONCE,
    InitFn: INIT_ONCE_FN,
    Parameter: ?*anyopaque,
    Context: ?*anyopaque,
) callconv(.winapi) BOOL;

// TODO: Forwarder to RtlWakeConditionVariable
pub extern "kernel32" fn WakeConditionVariable(
    ConditionVariable: *CONDITION_VARIABLE,
) callconv(.winapi) void;

// TODO: Forwarder to RtlWakeAllConditionVariable
pub extern "kernel32" fn WakeAllConditionVariable(
    ConditionVariable: *CONDITION_VARIABLE,
) callconv(.winapi) void;

// TODO:
//  - dwMilliseconds -> LARGE_INTEGER.
//  - RtlSleepConditionVariableSRW
//  - return rc != .TIMEOUT
pub extern "kernel32" fn SleepConditionVariableSRW(
    ConditionVariable: *CONDITION_VARIABLE,
    SRWLock: *SRWLOCK,
    dwMilliseconds: DWORD,
    Flags: ULONG,
) callconv(.winapi) BOOL;

// Console management

pub extern "kernel32" fn GetConsoleMode(
    hConsoleHandle: HANDLE,
    lpMode: *DWORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn SetConsoleMode(
    hConsoleHandle: HANDLE,
    dwMode: DWORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn GetConsoleScreenBufferInfo(
    hConsoleOutput: HANDLE,
    lpConsoleScreenBufferInfo: *CONSOLE_SCREEN_BUFFER_INFO,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn SetConsoleTextAttribute(
    hConsoleOutput: HANDLE,
    wAttributes: WORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn SetConsoleCtrlHandler(
    HandlerRoutine: ?HANDLER_ROUTINE,
    Add: BOOL,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn SetConsoleOutputCP(
    wCodePageID: UINT,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn GetConsoleOutputCP() callconv(.winapi) UINT;

pub extern "kernel32" fn FillConsoleOutputAttribute(
    hConsoleOutput: HANDLE,
    wAttribute: WORD,
    nLength: DWORD,
    dwWriteCoord: COORD,
    lpNumberOfAttrsWritten: *DWORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn FillConsoleOutputCharacterW(
    hConsoleOutput: HANDLE,
    cCharacter: WCHAR,
    nLength: DWORD,
    dwWriteCoord: COORD,
    lpNumberOfCharsWritten: *DWORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn SetConsoleCursorPosition(
    hConsoleOutput: HANDLE,
    dwCursorPosition: COORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn WriteConsoleW(
    hConsoleOutput: HANDLE,
    lpBuffer: [*]const u16,
    nNumberOfCharsToWrite: DWORD,
    lpNumberOfCharsWritten: ?*DWORD,
    lpReserved: ?LPVOID,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn ReadConsoleOutputCharacterW(
    hConsoleOutput: HANDLE,
    lpCharacter: [*]u16,
    nLength: DWORD,
    dwReadCoord: COORD,
    lpNumberOfCharsRead: *DWORD,
) callconv(.winapi) BOOL;

// Memory Mapping/Allocation

// TODO: Wrapper around RtlCreateHeap.
pub extern "kernel32" fn HeapCreate(
    flOptions: DWORD,
    dwInitialSize: SIZE_T,
    dwMaximumSize: SIZE_T,
) callconv(.winapi) ?HANDLE;

// TODO: Forwarder to RtlReAllocateHeap.
pub extern "kernel32" fn HeapReAlloc(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpMem: *anyopaque,
    dwBytes: SIZE_T,
) callconv(.winapi) ?*anyopaque;

// TODO: Fowrarder to RtlAllocateHeap.
pub extern "kernel32" fn HeapAlloc(
    hHeap: HANDLE,
    dwFlags: DWORD,
    dwBytes: SIZE_T,
) callconv(.winapi) ?*anyopaque;

// TODO: Fowrarder to RtlFreeHeap.
pub extern "kernel32" fn HeapFree(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpMem: LPVOID,
) callconv(.winapi) BOOL;

// TODO: Wrapper around RtlValidateHeap (BOOLEAN -> BOOL)
pub extern "kernel32" fn HeapValidate(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpMem: ?*const anyopaque,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtAllocateVirtualMemory.
pub extern "kernel32" fn VirtualAlloc(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) callconv(.winapi) ?LPVOID;

// TODO: Wrapper around NtFreeVirtualMemory.
// If the return value is .INVALID_PAGE_PROTECTION, calls RtlFlushSecureMemoryCache and try again.
pub extern "kernel32" fn VirtualFree(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) callconv(.winapi) BOOL;

// TODO: Wrapper around NtQueryVirtualMemory.
pub extern "kernel32" fn VirtualQuery(
    lpAddress: ?LPVOID,
    lpBuffer: PMEMORY_BASIC_INFORMATION,
    dwLength: SIZE_T,
) callconv(.winapi) SIZE_T;

// TODO: Getter for peb.ProcessHeap
pub extern "kernel32" fn GetProcessHeap() callconv(.winapi) ?HANDLE;

// Code Libraries/Modules

// TODO: Wrapper around LdrGetDllFullName.
pub extern "kernel32" fn GetModuleFileNameW(
    hModule: ?HMODULE,
    lpFilename: [*]WCHAR,
    nSize: DWORD,
) callconv(.winapi) DWORD;

extern "kernel32" fn K32GetModuleFileNameExW(
    hProcess: HANDLE,
    hModule: ?HMODULE,
    lpFilename: LPWSTR,
    nSize: DWORD,
) callconv(.winapi) DWORD;
pub const GetModuleFileNameExW = K32GetModuleFileNameExW;

// TODO: Wrapper around ntdll.LdrGetDllHandle, which is a wrapper around LdrGetDllHandleEx
pub extern "kernel32" fn GetModuleHandleW(
    lpModuleName: ?LPCWSTR,
) callconv(.winapi) ?HMODULE;

pub extern "kernel32" fn Module32First(
    hSnapshot: HANDLE,
    lpme: *MODULEENTRY32,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn Module32Next(
    hSnapshot: HANDLE,
    lpme: *MODULEENTRY32,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn LoadLibraryW(
    lpLibFileName: LPCWSTR,
) callconv(.winapi) ?HMODULE;

pub extern "kernel32" fn LoadLibraryExW(
    lpLibFileName: LPCWSTR,
    hFile: ?HANDLE,
    dwFlags: DWORD,
) callconv(.winapi) ?HMODULE;

pub extern "kernel32" fn GetProcAddress(
    hModule: HMODULE,
    lpProcName: LPCSTR,
) callconv(.winapi) ?FARPROC;

pub extern "kernel32" fn FreeLibrary(
    hModule: HMODULE,
) callconv(.winapi) BOOL;

// Error Management

pub extern "kernel32" fn FormatMessageW(
    dwFlags: DWORD,
    lpSource: ?LPCVOID,
    dwMessageId: Win32Error,
    dwLanguageId: DWORD,
    lpBuffer: LPWSTR,
    nSize: DWORD,
    Arguments: ?*va_list,
) callconv(.winapi) DWORD;

// TODO: Getter for teb().LastErrorValue.
pub extern "kernel32" fn GetLastError() callconv(.winapi) Win32Error;

// TODO: Wrapper around RtlSetLastWin32Error.
pub extern "kernel32" fn SetLastError(
    dwErrCode: Win32Error,
) callconv(.winapi) void;

// Everything Else

pub extern "kernel32" fn GetSystemInfo(lpSystemInfo: *SYSTEM_INFO) callconv(.winapi) void;
pub const NEUTRAL = 0x00;
pub const INVARIANT = 0x7f;
pub const AFRIKAANS = 0x36;
pub const ALBANIAN = 0x1c;
pub const ALSATIAN = 0x84;
pub const AMHARIC = 0x5e;
pub const ARABIC = 0x01;
pub const ARMENIAN = 0x2b;
pub const ASSAMESE = 0x4d;
pub const AZERI = 0x2c;
pub const AZERBAIJANI = 0x2c;
pub const BANGLA = 0x45;
pub const BASHKIR = 0x6d;
pub const BASQUE = 0x2d;
pub const BELARUSIAN = 0x23;
pub const BENGALI = 0x45;
pub const BRETON = 0x7e;
pub const BOSNIAN = 0x1a;
pub const BOSNIAN_NEUTRAL = 0x781a;
pub const BULGARIAN = 0x02;
pub const CATALAN = 0x03;
pub const CENTRAL_KURDISH = 0x92;
pub const CHEROKEE = 0x5c;
pub const CHINESE = 0x04;
pub const CHINESE_SIMPLIFIED = 0x04;
pub const CHINESE_TRADITIONAL = 0x7c04;
pub const CORSICAN = 0x83;
pub const CROATIAN = 0x1a;
pub const CZECH = 0x05;
pub const DANISH = 0x06;
pub const DARI = 0x8c;
pub const DIVEHI = 0x65;
pub const DUTCH = 0x13;
pub const ENGLISH = 0x09;
pub const ESTONIAN = 0x25;
pub const FAEROESE = 0x38;
pub const FARSI = 0x29;
pub const FILIPINO = 0x64;
pub const FINNISH = 0x0b;
pub const FRENCH = 0x0c;
pub const FRISIAN = 0x62;
pub const FULAH = 0x67;
pub const GALICIAN = 0x56;
pub const GEORGIAN = 0x37;
pub const GERMAN = 0x07;
pub const GREEK = 0x08;
pub const GREENLANDIC = 0x6f;
pub const GUJARATI = 0x47;
pub const HAUSA = 0x68;
pub const HAWAIIAN = 0x75;
pub const HEBREW = 0x0d;
pub const HINDI = 0x39;
pub const HUNGARIAN = 0x0e;
pub const ICELANDIC = 0x0f;
pub const IGBO = 0x70;
pub const INDONESIAN = 0x21;
pub const INUKTITUT = 0x5d;
pub const IRISH = 0x3c;
pub const ITALIAN = 0x10;
pub const JAPANESE = 0x11;
pub const KANNADA = 0x4b;
pub const KASHMIRI = 0x60;
pub const KAZAK = 0x3f;
pub const KHMER = 0x53;
pub const KICHE = 0x86;
pub const KINYARWANDA = 0x87;
pub const KONKANI = 0x57;
pub const KOREAN = 0x12;
pub const KYRGYZ = 0x40;
pub const LAO = 0x54;
pub const LATVIAN = 0x26;
pub const LITHUANIAN = 0x27;
pub const LOWER_SORBIAN = 0x2e;
pub const LUXEMBOURGISH = 0x6e;
pub const MACEDONIAN = 0x2f;
pub const MALAY = 0x3e;
pub const MALAYALAM = 0x4c;
pub const MALTESE = 0x3a;
pub const MANIPURI = 0x58;
pub const MAORI = 0x81;
pub const MAPUDUNGUN = 0x7a;
pub const MARATHI = 0x4e;
pub const MOHAWK = 0x7c;
pub const MONGOLIAN = 0x50;
pub const NEPALI = 0x61;
pub const NORWEGIAN = 0x14;
pub const OCCITAN = 0x82;
pub const ODIA = 0x48;
pub const ORIYA = 0x48;
pub const PASHTO = 0x63;
pub const PERSIAN = 0x29;
pub const POLISH = 0x15;
pub const PORTUGUESE = 0x16;
pub const PULAR = 0x67;
pub const PUNJABI = 0x46;
pub const QUECHUA = 0x6b;
pub const ROMANIAN = 0x18;
pub const ROMANSH = 0x17;
pub const RUSSIAN = 0x19;
pub const SAKHA = 0x85;
pub const SAMI = 0x3b;
pub const SANSKRIT = 0x4f;
pub const SCOTTISH_GAELIC = 0x91;
pub const SERBIAN = 0x1a;
pub const SERBIAN_NEUTRAL = 0x7c1a;
pub const SINDHI = 0x59;
pub const SINHALESE = 0x5b;
pub const SLOVAK = 0x1b;
pub const SLOVENIAN = 0x24;
pub const SOTHO = 0x6c;
pub const SPANISH = 0x0a;
pub const SWAHILI = 0x41;
pub const SWEDISH = 0x1d;
pub const SYRIAC = 0x5a;
pub const TAJIK = 0x28;
pub const TAMAZIGHT = 0x5f;
pub const TAMIL = 0x49;
pub const TATAR = 0x44;
pub const TELUGU = 0x4a;
pub const THAI = 0x1e;
pub const TIBETAN = 0x51;
pub const TIGRIGNA = 0x73;
pub const TIGRINYA = 0x73;
pub const TSWANA = 0x32;
pub const TURKISH = 0x1f;
pub const TURKMEN = 0x42;
pub const UIGHUR = 0x80;
pub const UKRAINIAN = 0x22;
pub const UPPER_SORBIAN = 0x2e;
pub const URDU = 0x20;
pub const UZBEK = 0x43;
pub const VALENCIAN = 0x03;
pub const VIETNAMESE = 0x2a;
pub const WELSH = 0x52;
pub const WOLOF = 0x88;
pub const XHOSA = 0x34;
pub const YAKUT = 0x85;
pub const YI = 0x78;
pub const YORUBA = 0x6a;
pub const ZULU = 0x35;
//! Implementations of functionality related to National Language Support
//! on Windows.

const builtin = @import("builtin");
const std = @import("../../std.zig");

/// This corresponds to the uppercase table within the locale-independent
/// l_intl.nls data (found at system32\l_intl.nls).
/// - In l_intl.nls, this data starts at offset 0x04.
/// - In the PEB, this data starts at index [2] of peb.UnicodeCaseTableData when
///   it is casted to `[*]u16`.
///
/// Note: This data has not changed since Windows 8.1, and has become out-of-sync with
///       the Unicode standard.
const uppercase_table = [2544]u16{
    272,   288,   304,   320,   336,   352,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   368,   384,   400,   256,   416,   256,   256,   432,   256,   256,   256,   256,   256,   256,   256,   448,   464,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   480,   496,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,
    256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   256,   512,   528,   528,   528,   528,   528,   528,   528,   528,
    528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   544,   560,   528,   528,   528,   576,   528,   528,   592,   608,
    624,   640,   656,   672,   688,   704,   720,   736,   752,   768,   784,   800,   816,   832,   848,   864,   880,   896,   912,   928,   944,   960,   976,   992,
    1008,  1024,  528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   1040,  528,   528,   1056,  528,   528,   1072,  1088,  1104,  1120,  1136,  1152,
    528,   528,   528,   1168,  1184,  1200,  1216,  1232,  1248,  1264,  1280,  1296,  1312,  1328,  1344,  1360,  1376,  1392,  1408,  528,   528,   528,   1424,  1440,
    1456,  528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   1472,  528,   528,   528,   528,   528,   528,   528,   528,
    1488,  1504,  1520,  1536,  1552,  1568,  1584,  1600,  1616,  1632,  1648,  1664,  1680,  1696,  1712,  1728,  1744,  1760,  1776,  1792,  1808,  1824,  1840,  1856,
    1872,  1888,  1904,  1920,  1936,  1952,  1968,  1984,  528,   528,   528,   528,   2000,  528,   528,   2016,  2032,  528,   528,   528,   528,   528,   528,   528,
    528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   2048,  2064,  528,   528,   528,   528,   2080,  2096,  2112,  2128,  2144,
    2160,  2176,  2192,  2208,  2224,  2240,  2256,  528,   2272,  2288,  2304,  528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,
    528,   528,   528,   528,   2320,  2336,  2352,  528,   2368,  2384,  528,   528,   528,   528,   528,   528,   528,   528,   2400,  2416,  2432,  2448,  2464,  2480,
    2496,  528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   528,   2512,  2528,  528,   528,   528,   528,   528,   528,   528,   528,   528,   528,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     65504, 65504, 65504, 65504, 65504, 65504, 65504,
    65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504,
    65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 0,     65504, 65504, 65504, 65504, 65504, 65504, 65504, 121,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,
    65535, 0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     0,     65535, 0,     65535, 0,     65535, 0,     195,   0,     0,     65535, 0,     65535, 0,     0,     65535, 0,     0,     0,     65535, 0,     0,     0,
    0,     0,     65535, 0,     0,     97,    0,     0,     0,     65535, 163,   0,     0,     0,     130,   0,     0,     65535, 0,     65535, 0,     65535, 0,     0,
    65535, 0,     0,     0,     0,     65535, 0,     0,     65535, 0,     0,     0,     65535, 0,     65535, 0,     0,     65535, 0,     0,     0,     65535, 0,     56,
    0,     0,     0,     0,     0,     0,     65534, 0,     0,     65534, 0,     0,     65534, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,
    65535, 0,     65535, 0,     65535, 65457, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     0,     0,     65534, 0,     65535, 0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     0,
    0,     0,     0,     0,     65535, 0,     0,     0,     0,     0,     65535, 0,     0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    10783, 10780, 0,     65326, 65330, 0,     65331, 65331, 0,     65334, 0,     65333, 0,     0,     0,     0,     65331, 0,     0,     65329, 0,     0,     0,     0,
    65327, 65325, 0,     10743, 0,     0,     0,     65325, 0,     10749, 65323, 0,     0,     65322, 0,     0,     0,     0,     0,     0,     0,     10727, 0,     0,
    65318, 0,     0,     65318, 0,     0,     0,     0,     65318, 65467, 65319, 65319, 65465, 0,     0,     0,     0,     0,     65317, 0,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     65535, 0,     65535, 0,     0,     0,     65535, 0,     0,     0,     130,   130,   130,   0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     0,     65498, 65499, 65499, 65499, 0,     65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504,
    65504, 65504, 0,     65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65472, 65473, 65473, 0,     0,     0,     0,     0,     0,     0,     0,     65528,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     0,     7,     0,     0,     0,     0,     0,     65535, 0,     0,     65535, 0,     0,     0,     0,     65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504,
    65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504,
    65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 65456, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     0,     0,     0,     0,     0,     0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     65535, 0,     65535, 0,     65535, 0,
    65535, 0,     65535, 0,     65535, 0,     65535, 65521, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488,
    65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     35332, 0,     0,     0,     3814,  0,     0,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 8,     8,     8,     8,     8,     8,     8,     8,
    0,     0,     0,     0,     0,     0,     0,     0,     8,     8,     8,     8,     8,     8,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    8,     8,     8,     8,     8,     8,     8,     8,     0,     0,     0,     0,     0,     0,     0,     0,     8,     8,     8,     8,     8,     8,     8,     8,
    0,     0,     0,     0,     0,     0,     0,     0,     8,     8,     8,     8,     8,     8,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     8,     0,     8,     0,     8,     0,     8,     0,     0,     0,     0,     0,     0,     0,     0,     8,     8,     8,     8,     8,     8,     8,     8,
    0,     0,     0,     0,     0,     0,     0,     0,     74,    74,    86,    86,    86,    86,    100,   100,   128,   128,   112,   112,   126,   126,   0,     0,
    8,     8,     8,     8,     8,     8,     8,     8,     0,     0,     0,     0,     0,     0,     0,     0,     8,     8,     8,     8,     8,     8,     8,     8,
    0,     0,     0,     0,     0,     0,     0,     0,     8,     8,     8,     8,     8,     8,     8,     8,     0,     0,     0,     0,     0,     0,     0,     0,
    8,     8,     0,     9,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     9,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     8,     8,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    8,     8,     0,     0,     0,     7,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     9,     0,     0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     65508, 0,
    65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 65520, 0,     0,     0,     0,     65535, 0,     0,     0,
    0,     0,     0,     0,     0,     0,     0,     0,     65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510,
    65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 65510, 0,     0,     0,     0,     0,     0,     65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488,
    65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488,
    65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 65488, 0,     0,     65535, 0,     0,     0,     54741, 54744, 0,
    65535, 0,     65535, 0,     65535, 0,     0,     0,     0,     0,     0,     65535, 0,     0,     65535, 0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272,
    58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272, 58272,
    58272, 58272, 58272, 58272, 58272, 58272, 0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,     0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     65535, 0,     65535, 0,     0,     65535,
    0,     65535, 0,     65535, 0,     65535, 0,     65535, 0,     0,     0,     0,     65535, 0,     0,     0,     0,     65504, 65504, 65504, 65504, 65504, 65504, 65504,
    65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 65504, 0,     0,     0,     0,     0,
};

/// Cross-platform implementation of `ntdll.RtlUpcaseUnicodeChar`.
/// Transforms the UTF-16 code unit in `c` to its uppercased version
/// if there is one. Otherwise, returns `c` unmodified.
///
/// Note: When this function is referenced, it will need to include
///       `uppercase_table.len * 2` bytes of data in the resulting binary
///       since it depends on the `uppercase_table` data. When
///       targeting Windows, `ntdll.RtlUpcaseUnicodeChar` can be
///       used instead to avoid having to include a copy of this data.
pub fn upcaseW(c: u16) u16 {
    if (c < 'a') {
        return c;
    }
    if (c <= 'z') {
        return c - ('a' - 'A');
    }
    if (c >= 0xC0) {
        var offset: u16 = 0;

        offset += @as(u8, @truncate(c >> 8));
        offset = uppercase_table[offset];
        offset += @as(u4, @truncate(c >> 4));
        offset = uppercase_table[offset];
        offset += @as(u4, @truncate(c));
        offset = uppercase_table[offset];

        return c +% offset;
    }
    return c;
}

test "upcaseW matches RtlUpcaseUnicodeChar" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    var c: u16 = 0;
    while (true) : (c += 1) {
        std.testing.expectEqual(std.os.windows.ntdll.RtlUpcaseUnicodeChar(c), upcaseW(c)) catch |err| {
            std.debug.print("mismatch for codepoint U+{X}\n", .{c});
            return err;
        };
        if (c == 0xFFFF) break;
    }
}
const std = @import("../../std.zig");
const windows = std.os.windows;

const BOOL = windows.BOOL;
const DWORD = windows.DWORD;
const DWORD64 = windows.DWORD64;
const ULONG = windows.ULONG;
const ULONG_PTR = windows.ULONG_PTR;
const NTSTATUS = windows.NTSTATUS;
const WORD = windows.WORD;
const HANDLE = windows.HANDLE;
const ACCESS_MASK = windows.ACCESS_MASK;
const IO_APC_ROUTINE = windows.IO_APC_ROUTINE;
const BOOLEAN = windows.BOOLEAN;
const OBJECT_ATTRIBUTES = windows.OBJECT_ATTRIBUTES;
const PVOID = windows.PVOID;
const IO_STATUS_BLOCK = windows.IO_STATUS_BLOCK;
const LARGE_INTEGER = windows.LARGE_INTEGER;
const OBJECT_INFORMATION_CLASS = windows.OBJECT_INFORMATION_CLASS;
const FILE_INFORMATION_CLASS = windows.FILE_INFORMATION_CLASS;
const FS_INFORMATION_CLASS = windows.FS_INFORMATION_CLASS;
const UNICODE_STRING = windows.UNICODE_STRING;
const RTL_OSVERSIONINFOW = windows.RTL_OSVERSIONINFOW;
const FILE_BASIC_INFORMATION = windows.FILE_BASIC_INFORMATION;
const SIZE_T = windows.SIZE_T;
const CURDIR = windows.CURDIR;
const PCWSTR = windows.PCWSTR;
const RTL_QUERY_REGISTRY_TABLE = windows.RTL_QUERY_REGISTRY_TABLE;
const CONTEXT = windows.CONTEXT;
const UNWIND_HISTORY_TABLE = windows.UNWIND_HISTORY_TABLE;
const RUNTIME_FUNCTION = windows.RUNTIME_FUNCTION;
const KNONVOLATILE_CONTEXT_POINTERS = windows.KNONVOLATILE_CONTEXT_POINTERS;
const EXCEPTION_ROUTINE = windows.EXCEPTION_ROUTINE;
const SYSTEM_INFORMATION_CLASS = windows.SYSTEM_INFORMATION_CLASS;
const THREADINFOCLASS = windows.THREADINFOCLASS;
const PROCESSINFOCLASS = windows.PROCESSINFOCLASS;
const LPVOID = windows.LPVOID;
const LPCVOID = windows.LPCVOID;
const SECTION_INHERIT = windows.SECTION_INHERIT;

pub extern "ntdll" fn NtQueryInformationProcess(
    ProcessHandle: HANDLE,
    ProcessInformationClass: PROCESSINFOCLASS,
    ProcessInformation: *anyopaque,
    ProcessInformationLength: ULONG,
    ReturnLength: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtQueryInformationThread(
    ThreadHandle: HANDLE,
    ThreadInformationClass: THREADINFOCLASS,
    ThreadInformation: *anyopaque,
    ThreadInformationLength: ULONG,
    ReturnLength: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtQuerySystemInformation(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: PVOID,
    SystemInformationLength: ULONG,
    ReturnLength: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtSetInformationThread(
    ThreadHandle: HANDLE,
    ThreadInformationClass: THREADINFOCLASS,
    ThreadInformation: *const anyopaque,
    ThreadInformationLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn RtlGetVersion(
    lpVersionInformation: *RTL_OSVERSIONINFOW,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn RtlCaptureStackBackTrace(
    FramesToSkip: DWORD,
    FramesToCapture: DWORD,
    BackTrace: **anyopaque,
    BackTraceHash: ?*DWORD,
) callconv(.winapi) WORD;
pub extern "ntdll" fn RtlCaptureContext(ContextRecord: *CONTEXT) callconv(.winapi) void;
pub extern "ntdll" fn RtlLookupFunctionEntry(
    ControlPc: DWORD64,
    ImageBase: *DWORD64,
    HistoryTable: *UNWIND_HISTORY_TABLE,
) callconv(.winapi) ?*RUNTIME_FUNCTION;
pub extern "ntdll" fn RtlVirtualUnwind(
    HandlerType: DWORD,
    ImageBase: DWORD64,
    ControlPc: DWORD64,
    FunctionEntry: *RUNTIME_FUNCTION,
    ContextRecord: *CONTEXT,
    HandlerData: *?PVOID,
    EstablisherFrame: *DWORD64,
    ContextPointers: ?*KNONVOLATILE_CONTEXT_POINTERS,
) callconv(.winapi) *EXCEPTION_ROUTINE;
pub extern "ntdll" fn RtlGetSystemTimePrecise() callconv(.winapi) LARGE_INTEGER;
pub extern "ntdll" fn NtQueryInformationFile(
    FileHandle: HANDLE,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FileInformation: *anyopaque,
    Length: ULONG,
    FileInformationClass: FILE_INFORMATION_CLASS,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn NtSetInformationFile(
    FileHandle: HANDLE,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FileInformation: PVOID,
    Length: ULONG,
    FileInformationClass: FILE_INFORMATION_CLASS,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtQueryAttributesFile(
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    FileAttributes: *FILE_BASIC_INFORMATION,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn RtlQueryPerformanceCounter(PerformanceCounter: *LARGE_INTEGER) callconv(.winapi) BOOL;
pub extern "ntdll" fn RtlQueryPerformanceFrequency(PerformanceFrequency: *LARGE_INTEGER) callconv(.winapi) BOOL;
pub extern "ntdll" fn NtQueryPerformanceCounter(
    PerformanceCounter: *LARGE_INTEGER,
    PerformanceFrequency: ?*LARGE_INTEGER,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtCreateFile(
    FileHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    IoStatusBlock: *IO_STATUS_BLOCK,
    AllocationSize: ?*LARGE_INTEGER,
    FileAttributes: ULONG,
    ShareAccess: ULONG,
    CreateDisposition: ULONG,
    CreateOptions: ULONG,
    EaBuffer: ?*anyopaque,
    EaLength: ULONG,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn NtCreateSection(
    SectionHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: ?*OBJECT_ATTRIBUTES,
    MaximumSize: ?*LARGE_INTEGER,
    SectionPageProtection: ULONG,
    AllocationAttributes: ULONG,
    FileHandle: ?HANDLE,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn NtMapViewOfSection(
    SectionHandle: HANDLE,
    ProcessHandle: HANDLE,
    BaseAddress: *PVOID,
    ZeroBits: ?*ULONG,
    CommitSize: SIZE_T,
    SectionOffset: ?*LARGE_INTEGER,
    ViewSize: *SIZE_T,
    InheritDispostion: SECTION_INHERIT,
    AllocationType: ULONG,
    Win32Protect: ULONG,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn NtUnmapViewOfSection(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn NtDeviceIoControlFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    IoControlCode: ULONG,
    InputBuffer: ?*const anyopaque,
    InputBufferLength: ULONG,
    OutputBuffer: ?PVOID,
    OutputBufferLength: ULONG,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn NtFsControlFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FsControlCode: ULONG,
    InputBuffer: ?*const anyopaque,
    InputBufferLength: ULONG,
    OutputBuffer: ?PVOID,
    OutputBufferLength: ULONG,
) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn NtClose(Handle: HANDLE) callconv(.winapi) NTSTATUS;
pub extern "ntdll" fn RtlDosPathNameToNtPathName_U(
    DosPathName: [*:0]const u16,
    NtPathName: *UNICODE_STRING,
    NtFileNamePart: ?*?[*:0]const u16,
    DirectoryInfo: ?*CURDIR,
) callconv(.winapi) BOOL;
pub extern "ntdll" fn RtlFreeUnicodeString(UnicodeString: *UNICODE_STRING) callconv(.winapi) void;

/// Returns the number of bytes written to `Buffer`.
/// If the returned count is larger than `BufferByteLength`, the buffer was too small.
/// If the returned count is zero, an error occurred.
pub extern "ntdll" fn RtlGetFullPathName_U(
    FileName: [*:0]const u16,
    BufferByteLength: ULONG,
    Buffer: [*]u16,
    ShortName: ?*[*:0]const u16,
) callconv(.winapi) windows.ULONG;

pub extern "ntdll" fn NtQueryDirectoryFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FileInformation: *anyopaque,
    Length: ULONG,
    FileInformationClass: FILE_INFORMATION_CLASS,
    ReturnSingleEntry: BOOLEAN,
    FileName: ?*UNICODE_STRING,
    RestartScan: BOOLEAN,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtCreateKeyedEvent(
    KeyedEventHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: ?PVOID,
    Flags: ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtReleaseKeyedEvent(
    EventHandle: ?HANDLE,
    Key: ?*const anyopaque,
    Alertable: BOOLEAN,
    Timeout: ?*const LARGE_INTEGER,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtWaitForKeyedEvent(
    EventHandle: ?HANDLE,
    Key: ?*const anyopaque,
    Alertable: BOOLEAN,
    Timeout: ?*const LARGE_INTEGER,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn RtlSetCurrentDirectory_U(PathName: *UNICODE_STRING) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtQueryObject(
    Handle: HANDLE,
    ObjectInformationClass: OBJECT_INFORMATION_CLASS,
    ObjectInformation: PVOID,
    ObjectInformationLength: ULONG,
    ReturnLength: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtQueryVolumeInformationFile(
    FileHandle: HANDLE,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FsInformation: *anyopaque,
    Length: ULONG,
    FsInformationClass: FS_INFORMATION_CLASS,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn RtlWakeAddressAll(
    Address: ?*const anyopaque,
) callconv(.winapi) void;

pub extern "ntdll" fn RtlWakeAddressSingle(
    Address: ?*const anyopaque,
) callconv(.winapi) void;

pub extern "ntdll" fn RtlWaitOnAddress(
    Address: ?*const anyopaque,
    CompareAddress: ?*const anyopaque,
    AddressSize: SIZE_T,
    Timeout: ?*const LARGE_INTEGER,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn RtlEqualUnicodeString(
    String1: *const UNICODE_STRING,
    String2: *const UNICODE_STRING,
    CaseInSensitive: BOOLEAN,
) callconv(.winapi) BOOLEAN;

pub extern "ntdll" fn RtlUpcaseUnicodeChar(
    SourceCharacter: u16,
) callconv(.winapi) u16;

pub extern "ntdll" fn NtLockFile(
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
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtUnlockFile(
    FileHandle: HANDLE,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ByteOffset: *const LARGE_INTEGER,
    Length: *const LARGE_INTEGER,
    Key: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtOpenKey(
    KeyHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: OBJECT_ATTRIBUTES,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn RtlQueryRegistryValues(
    RelativeTo: ULONG,
    Path: PCWSTR,
    QueryTable: [*]RTL_QUERY_REGISTRY_TABLE,
    Context: ?*anyopaque,
    Environment: ?*anyopaque,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtReadVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: ?PVOID,
    Buffer: LPVOID,
    NumberOfBytesToRead: SIZE_T,
    NumberOfBytesRead: ?*SIZE_T,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtWriteVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: ?PVOID,
    Buffer: LPCVOID,
    NumberOfBytesToWrite: SIZE_T,
    NumberOfBytesWritten: ?*SIZE_T,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtProtectVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: *?PVOID,
    NumberOfBytesToProtect: *SIZE_T,
    NewAccessProtection: ULONG,
    OldAccessProtection: *ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn RtlExitUserProcess(
    ExitStatus: u32,
) callconv(.winapi) noreturn;

pub extern "ntdll" fn NtCreateNamedPipeFile(
    FileHandle: *HANDLE,
    DesiredAccess: ULONG,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ShareAccess: ULONG,
    CreateDisposition: ULONG,
    CreateOptions: ULONG,
    NamedPipeType: ULONG,
    ReadMode: ULONG,
    CompletionMode: ULONG,
    MaximumInstances: ULONG,
    InboundQuota: ULONG,
    OutboundQuota: ULONG,
    DefaultTimeout: *LARGE_INTEGER,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtAllocateVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: ?*PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: ?*SIZE_T,
    AllocationType: ULONG,
    PageProtection: ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtFreeVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: ?*PVOID,
    RegionSize: *SIZE_T,
    FreeType: ULONG,
) callconv(.winapi) NTSTATUS;
/// NTSTATUS codes from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55?
pub const NTSTATUS = enum(u32) {
    /// The caller specified WaitAny for WaitType and one of the dispatcher
    /// objects in the Object array has been set to the signaled state.
    pub const WAIT_0: NTSTATUS = .SUCCESS;
    /// The caller attempted to wait for a mutex that has been abandoned.
    pub const ABANDONED_WAIT_0: NTSTATUS = .ABANDONED;
    /// The maximum number of boot-time filters has been reached.
    pub const FWP_TOO_MANY_BOOTTIME_FILTERS: NTSTATUS = .FWP_TOO_MANY_CALLOUTS;

    /// The operation completed successfully.
    SUCCESS = 0x00000000,
    /// The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.
    WAIT_1 = 0x00000001,
    /// The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.
    WAIT_2 = 0x00000002,
    /// The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.
    WAIT_3 = 0x00000003,
    /// The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.
    WAIT_63 = 0x0000003F,
    /// The caller attempted to wait for a mutex that has been abandoned.
    ABANDONED = 0x00000080,
    /// The caller attempted to wait for a mutex that has been abandoned.
    ABANDONED_WAIT_63 = 0x000000BF,
    /// A user-mode APC was delivered before the given Interval expired.
    USER_APC = 0x000000C0,
    /// The delay completed because the thread was alerted.
    ALERTED = 0x00000101,
    /// The given Timeout interval expired.
    TIMEOUT = 0x00000102,
    /// The operation that was requested is pending completion.
    PENDING = 0x00000103,
    /// A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.
    REPARSE = 0x00000104,
    /// Returned by enumeration APIs to indicate more information is available to successive calls.
    MORE_ENTRIES = 0x00000105,
    /// Indicates not all privileges or groups that are referenced are assigned to the caller.
    /// This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned.
    NOT_ALL_ASSIGNED = 0x00000106,
    /// Some of the information to be translated has not been translated.
    SOME_NOT_MAPPED = 0x00000107,
    /// An open/create operation completed while an opportunistic lock (oplock) break is underway.
    OPLOCK_BREAK_IN_PROGRESS = 0x00000108,
    /// A new volume has been mounted by a file system.
    VOLUME_MOUNTED = 0x00000109,
    /// This success level status indicates that the transaction state already exists for the registry subtree but that a transaction commit was previously aborted. The commit has now been completed.
    RXACT_COMMITTED = 0x0000010A,
    /// Indicates that a notify change request has been completed due to closing the handle that made the notify change request.
    NOTIFY_CLEANUP = 0x0000010B,
    /// Indicates that a notify change request is being completed and that the information is not being returned in the caller's buffer.
    /// The caller now needs to enumerate the files to find the changes.
    NOTIFY_ENUM_DIR = 0x0000010C,
    /// {No Quotas} No system quota limits are specifically set for this account.
    NO_QUOTAS_FOR_ACCOUNT = 0x0000010D,
    /// {Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed.
    /// The computer WAS able to connect on a secondary transport.
    PRIMARY_TRANSPORT_CONNECT_FAILED = 0x0000010E,
    /// The page fault was a transition fault.
    PAGE_FAULT_TRANSITION = 0x00000110,
    /// The page fault was a demand zero fault.
    PAGE_FAULT_DEMAND_ZERO = 0x00000111,
    /// The page fault was a demand zero fault.
    PAGE_FAULT_COPY_ON_WRITE = 0x00000112,
    /// The page fault was a demand zero fault.
    PAGE_FAULT_GUARD_PAGE = 0x00000113,
    /// The page fault was satisfied by reading from a secondary storage device.
    PAGE_FAULT_PAGING_FILE = 0x00000114,
    /// The cached page was locked during operation.
    CACHE_PAGE_LOCKED = 0x00000115,
    /// The crash dump exists in a paging file.
    CRASH_DUMP = 0x00000116,
    /// The specified buffer contains all zeros.
    BUFFER_ALL_ZEROS = 0x00000117,
    /// A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.
    REPARSE_OBJECT = 0x00000118,
    /// The device has succeeded a query-stop and its resource requirements have changed.
    RESOURCE_REQUIREMENTS_CHANGED = 0x00000119,
    /// The translator has translated these resources into the global space and no additional translations should be performed.
    TRANSLATION_COMPLETE = 0x00000120,
    /// The directory service evaluated group memberships locally, because it was unable to contact a global catalog server.
    DS_MEMBERSHIP_EVALUATED_LOCALLY = 0x00000121,
    /// A process being terminated has no threads to terminate.
    NOTHING_TO_TERMINATE = 0x00000122,
    /// The specified process is not part of a job.
    PROCESS_NOT_IN_JOB = 0x00000123,
    /// The specified process is part of a job.
    PROCESS_IN_JOB = 0x00000124,
    /// {Volume Shadow Copy Service} The system is now ready for hibernation.
    VOLSNAP_HIBERNATE_READY = 0x00000125,
    /// A file system or file system filter driver has successfully completed an FsFilter operation.
    FSFILTER_OP_COMPLETED_SUCCESSFULLY = 0x00000126,
    /// The specified interrupt vector was already connected.
    INTERRUPT_VECTOR_ALREADY_CONNECTED = 0x00000127,
    /// The specified interrupt vector is still connected.
    INTERRUPT_STILL_CONNECTED = 0x00000128,
    /// The current process is a cloned process.
    PROCESS_CLONED = 0x00000129,
    /// The file was locked and all users of the file can only read.
    FILE_LOCKED_WITH_ONLY_READERS = 0x0000012A,
    /// The file was locked and at least one user of the file can write.
    FILE_LOCKED_WITH_WRITERS = 0x0000012B,
    /// ```
