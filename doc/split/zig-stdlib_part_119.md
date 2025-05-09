```
= nanoseconds / std.time.ns_per_us;
        const us = math.cast(usize, us_from_ns) orelse math.maxInt(usize);
        _ = boot_services.stall(us);
        return;
    }

    const s = nanoseconds / std.time.ns_per_s;
    const ns = nanoseconds % std.time.ns_per_s;

    // Newer kernel ports don't have old `nanosleep()` and `clock_nanosleep()` has been around
    // since Linux 2.6 and glibc 2.1 anyway.
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;

        var req: linux.timespec = .{
            .sec = std.math.cast(linux.time_t, s) orelse std.math.maxInt(linux.time_t),
            .nsec = std.math.cast(linux.time_t, ns) orelse std.math.maxInt(linux.time_t),
        };
        var rem: linux.timespec = undefined;

        while (true) {
            switch (linux.E.init(linux.clock_nanosleep(.MONOTONIC, .{ .ABSTIME = false }, &req, &rem))) {
                .SUCCESS => return,
                .INTR => {
                    req = rem;
                    continue;
                },
                .FAULT,
                .INVAL,
                .OPNOTSUPP,
                => unreachable,
                else => return,
            }
        }
    }

    posix.nanosleep(s, ns);
}

test sleep {
    sleep(1);
}

const Thread = @This();
const Impl = if (native_os == .windows)
    WindowsThreadImpl
else if (use_pthreads)
    PosixThreadImpl
else if (native_os == .linux)
    LinuxThreadImpl
else if (native_os == .wasi)
    WasiThreadImpl
else
    UnsupportedImpl;

impl: Impl,

pub const max_name_len = switch (native_os) {
    .linux => 15,
    .windows => 31,
    .macos, .ios, .watchos, .tvos, .visionos => 63,
    .netbsd => 31,
    .freebsd => 15,
    .openbsd => 23,
    .dragonfly => 1023,
    .solaris, .illumos => 31,
    // https://github.com/SerenityOS/serenity/blob/6b4c300353da49d3508b5442cf61da70bd04d757/Kernel/Tasks/Thread.h#L102
    .serenity => 63,
    else => 0,
};

pub const SetNameError = error{
    NameTooLong,
    Unsupported,
    Unexpected,
} || posix.PrctlError || posix.WriteError || std.fs.File.OpenError || std.fmt.BufPrintError;

pub fn setName(self: Thread, name: []const u8) SetNameError!void {
    if (name.len > max_name_len) return error.NameTooLong;

    const name_with_terminator = blk: {
        var name_buf: [max_name_len:0]u8 = undefined;
        @memcpy(name_buf[0..name.len], name);
        name_buf[name.len] = 0;
        break :blk name_buf[0..name.len :0];
    };

    switch (native_os) {
        .linux => if (use_pthreads) {
            if (self.getHandle() == std.c.pthread_self()) {
                // Set the name of the calling thread (no thread id required).
                const err = try posix.prctl(.SET_NAME, .{@intFromPtr(name_with_terminator.ptr)});
                switch (@as(posix.E, @enumFromInt(err))) {
                    .SUCCESS => return,
                    else => |e| return posix.unexpectedErrno(e),
                }
            } else {
                const err = std.c.pthread_setname_np(self.getHandle(), name_with_terminator.ptr);
                switch (@as(posix.E, @enumFromInt(err))) {
                    .SUCCESS => return,
                    .RANGE => unreachable,
                    else => |e| return posix.unexpectedErrno(e),
                }
            }
        } else {
            var buf: [32]u8 = undefined;
            const path = try std.fmt.bufPrint(&buf, "/proc/self/task/{d}/comm", .{self.getHandle()});

            const file = try std.fs.cwd().openFile(path, .{ .mode = .write_only });
            defer file.close();

            try file.writer().writeAll(name);
            return;
        },
        .windows => {
            var buf: [max_name_len]u16 = undefined;
            const len = try std.unicode.wtf8ToWtf16Le(&buf, name);
            const byte_len = math.cast(c_ushort, len * 2) orelse return error.NameTooLong;

            // Note: NT allocates its own copy, no use-after-free here.
            const unicode_string = windows.UNICODE_STRING{
                .Length = byte_len,
                .MaximumLength = byte_len,
                .Buffer = &buf,
            };

            switch (windows.ntdll.NtSetInformationThread(
                self.getHandle(),
                .ThreadNameInformation,
                &unicode_string,
                @sizeOf(windows.UNICODE_STRING),
            )) {
                .SUCCESS => return,
                .NOT_IMPLEMENTED => return error.Unsupported,
                else => |err| return windows.unexpectedStatus(err),
            }
        },
        .macos, .ios, .watchos, .tvos, .visionos => if (use_pthreads) {
            // There doesn't seem to be a way to set the name for an arbitrary thread, only the current one.
            if (self.getHandle() != std.c.pthread_self()) return error.Unsupported;

            const err = std.c.pthread_setname_np(name_with_terminator.ptr);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        .serenity => if (use_pthreads) {
            const err = std.c.pthread_setname_np(self.getHandle(), name_with_terminator.ptr);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return,
                .NAMETOOLONG => unreachable,
                .SRCH => unreachable,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        .netbsd, .solaris, .illumos => if (use_pthreads) {
            const err = std.c.pthread_setname_np(self.getHandle(), name_with_terminator.ptr, null);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return,
                .INVAL => unreachable,
                .SRCH => unreachable,
                .NOMEM => unreachable,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        .freebsd, .openbsd => if (use_pthreads) {
            // Use pthread_set_name_np for FreeBSD because pthread_setname_np is FreeBSD 12.2+ only.
            // TODO maybe revisit this if depending on FreeBSD 12.2+ is acceptable because
            // pthread_setname_np can return an error.

            std.c.pthread_set_name_np(self.getHandle(), name_with_terminator.ptr);
            return;
        },
        .dragonfly => if (use_pthreads) {
            const err = std.c.pthread_setname_np(self.getHandle(), name_with_terminator.ptr);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return,
                .INVAL => unreachable,
                .FAULT => unreachable,
                .NAMETOOLONG => unreachable, // already checked
                .SRCH => unreachable,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        else => {},
    }
    return error.Unsupported;
}

pub const GetNameError = error{
    Unsupported,
    Unexpected,
} || posix.PrctlError || posix.ReadError || std.fs.File.OpenError || std.fmt.BufPrintError;

/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn getName(self: Thread, buffer_ptr: *[max_name_len:0]u8) GetNameError!?[]const u8 {
    buffer_ptr[max_name_len] = 0;
    var buffer: [:0]u8 = buffer_ptr;

    switch (native_os) {
        .linux => if (use_pthreads) {
            if (self.getHandle() == std.c.pthread_self()) {
                // Get the name of the calling thread (no thread id required).
                const err = try posix.prctl(.GET_NAME, .{@intFromPtr(buffer.ptr)});
                switch (@as(posix.E, @enumFromInt(err))) {
                    .SUCCESS => return std.mem.sliceTo(buffer, 0),
                    else => |e| return posix.unexpectedErrno(e),
                }
            } else {
                const err = std.c.pthread_getname_np(self.getHandle(), buffer.ptr, max_name_len + 1);
                switch (@as(posix.E, @enumFromInt(err))) {
                    .SUCCESS => return std.mem.sliceTo(buffer, 0),
                    .RANGE => unreachable,
                    else => |e| return posix.unexpectedErrno(e),
                }
            }
        } else {
            var buf: [32]u8 = undefined;
            const path = try std.fmt.bufPrint(&buf, "/proc/self/task/{d}/comm", .{self.getHandle()});

            const file = try std.fs.cwd().openFile(path, .{});
            defer file.close();

            const data_len = try file.reader().readAll(buffer_ptr[0 .. max_name_len + 1]);

            return if (data_len >= 1) buffer[0 .. data_len - 1] else null;
        },
        .windows => {
            const buf_capacity = @sizeOf(windows.UNICODE_STRING) + (@sizeOf(u16) * max_name_len);
            var buf: [buf_capacity]u8 align(@alignOf(windows.UNICODE_STRING)) = undefined;

            switch (windows.ntdll.NtQueryInformationThread(
                self.getHandle(),
                .ThreadNameInformation,
                &buf,
                buf_capacity,
                null,
            )) {
                .SUCCESS => {
                    const string = @as(*const windows.UNICODE_STRING, @ptrCast(&buf));
                    const len = std.unicode.wtf16LeToWtf8(buffer, string.Buffer.?[0 .. string.Length / 2]);
                    return if (len > 0) buffer[0..len] else null;
                },
                .NOT_IMPLEMENTED => return error.Unsupported,
                else => |err| return windows.unexpectedStatus(err),
            }
        },
        .macos, .ios, .watchos, .tvos, .visionos => if (use_pthreads) {
            const err = std.c.pthread_getname_np(self.getHandle(), buffer.ptr, max_name_len + 1);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return std.mem.sliceTo(buffer, 0),
                .SRCH => unreachable,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        .serenity => if (use_pthreads) {
            const err = std.c.pthread_getname_np(self.getHandle(), buffer.ptr, max_name_len + 1);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return,
                .NAMETOOLONG => unreachable,
                .SRCH => unreachable,
                .FAULT => unreachable,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        .netbsd, .solaris, .illumos => if (use_pthreads) {
            const err = std.c.pthread_getname_np(self.getHandle(), buffer.ptr, max_name_len + 1);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return std.mem.sliceTo(buffer, 0),
                .INVAL => unreachable,
                .SRCH => unreachable,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        .freebsd, .openbsd => if (use_pthreads) {
            // Use pthread_get_name_np for FreeBSD because pthread_getname_np is FreeBSD 12.2+ only.
            // TODO maybe revisit this if depending on FreeBSD 12.2+ is acceptable because pthread_getname_np can return an error.

            std.c.pthread_get_name_np(self.getHandle(), buffer.ptr, max_name_len + 1);
            return std.mem.sliceTo(buffer, 0);
        },
        .dragonfly => if (use_pthreads) {
            const err = std.c.pthread_getname_np(self.getHandle(), buffer.ptr, max_name_len + 1);
            switch (@as(posix.E, @enumFromInt(err))) {
                .SUCCESS => return std.mem.sliceTo(buffer, 0),
                .INVAL => unreachable,
                .FAULT => unreachable,
                .SRCH => unreachable,
                else => |e| return posix.unexpectedErrno(e),
            }
        },
        else => {},
    }
    return error.Unsupported;
}

/// Represents an ID per thread guaranteed to be unique only within a process.
pub const Id = switch (native_os) {
    .linux,
    .dragonfly,
    .netbsd,
    .freebsd,
    .openbsd,
    .haiku,
    .wasi,
    .serenity,
    => u32,
    .macos, .ios, .watchos, .tvos, .visionos => u64,
    .windows => windows.DWORD,
    else => usize,
};

/// Returns the platform ID of the callers thread.
/// Attempts to use thread locals and avoid syscalls when possible.
pub fn getCurrentId() Id {
    return Impl.getCurrentId();
}

pub const CpuCountError = error{
    PermissionDenied,
    SystemResources,
    Unsupported,
    Unexpected,
};

/// Returns the platforms view on the number of logical CPU cores available.
pub fn getCpuCount() CpuCountError!usize {
    return try Impl.getCpuCount();
}

/// Configuration options for hints on how to spawn threads.
pub const SpawnConfig = struct {
    // TODO compile-time call graph analysis to determine stack upper bound
    // https://github.com/ziglang/zig/issues/157

    /// Size in bytes of the Thread's stack
    stack_size: usize = default_stack_size,
    /// The allocator to be used to allocate memory for the to-be-spawned thread
    allocator: ?std.mem.Allocator = null,

    pub const default_stack_size = 16 * 1024 * 1024;
};

pub const SpawnError = error{
    /// A system-imposed limit on the number of threads was encountered.
    /// There are a number of limits that may trigger this error:
    /// *  the  RLIMIT_NPROC soft resource limit (set via setrlimit(2)),
    ///    which limits the number of processes and threads for  a  real
    ///    user ID, was reached;
    /// *  the kernel's system-wide limit on the number of processes and
    ///    threads,  /proc/sys/kernel/threads-max,  was   reached   (see
    ///    proc(5));
    /// *  the  maximum  number  of  PIDs, /proc/sys/kernel/pid_max, was
    ///    reached (see proc(5)); or
    /// *  the PID limit (pids.max) imposed by the cgroup "process  num‐
    ///    ber" (PIDs) controller was reached.
    ThreadQuotaExceeded,

    /// The kernel cannot allocate sufficient memory to allocate a task structure
    /// for the child, or to copy those parts of the caller's context that need to
    /// be copied.
    SystemResources,

    /// Not enough userland memory to spawn the thread.
    OutOfMemory,

    /// `mlockall` is enabled, and the memory needed to spawn the thread
    /// would exceed the limit.
    LockedMemoryLimitExceeded,

    Unexpected,
};

/// Spawns a new thread which executes `function` using `args` and returns a handle to the spawned thread.
/// `config` can be used as hints to the platform for how to spawn and execute the `function`.
/// The caller must eventually either call `join()` to wait for the thread to finish and free its resources
/// or call `detach()` to excuse the caller from calling `join()` and have the thread clean up its resources on completion.
pub fn spawn(config: SpawnConfig, comptime function: anytype, args: anytype) SpawnError!Thread {
    if (builtin.single_threaded) {
        @compileError("Cannot spawn thread when building in single-threaded mode");
    }

    const impl = try Impl.spawn(config, function, args);
    return Thread{ .impl = impl };
}

/// Represents a kernel thread handle.
/// May be an integer or a pointer depending on the platform.
pub const Handle = Impl.ThreadHandle;

/// Returns the handle of this thread
pub fn getHandle(self: Thread) Handle {
    return self.impl.getHandle();
}

/// Release the obligation of the caller to call `join()` and have the thread clean up its own resources on completion.
/// Once called, this consumes the Thread object and invoking any other functions on it is considered undefined behavior.
pub fn detach(self: Thread) void {
    return self.impl.detach();
}

/// Waits for the thread to complete, then deallocates any resources created on `spawn()`.
/// Once called, this consumes the Thread object and invoking any other functions on it is considered undefined behavior.
pub fn join(self: Thread) void {
    return self.impl.join();
}

pub const YieldError = error{
    /// The system is not configured to allow yielding
    SystemCannotYield,
};

/// Yields the current thread potentially allowing other threads to run.
pub fn yield() YieldError!void {
    if (native_os == .windows) {
        // The return value has to do with how many other threads there are; it is not
        // an error condition on Windows.
        _ = windows.kernel32.SwitchToThread();
        return;
    }
    switch (posix.errno(posix.system.sched_yield())) {
        .SUCCESS => return,
        .NOSYS => return error.SystemCannotYield,
        else => return error.SystemCannotYield,
    }
}

/// State to synchronize detachment of spawner thread to spawned thread
const Completion = std.atomic.Value(enum(if (builtin.zig_backend == .stage2_riscv64) u32 else u8) {
    running,
    detached,
    completed,
});

/// Used by the Thread implementations to call the spawned function with the arguments.
fn callFn(comptime f: anytype, args: anytype) switch (Impl) {
    WindowsThreadImpl => windows.DWORD,
    LinuxThreadImpl => u8,
    PosixThreadImpl => ?*anyopaque,
    else => unreachable,
} {
    const default_value = if (Impl == PosixThreadImpl) null else 0;
    const bad_fn_ret = "expected return type of startFn to be 'u8', 'noreturn', '!noreturn', 'void', or '!void'";

    switch (@typeInfo(@typeInfo(@TypeOf(f)).@"fn".return_type.?)) {
        .noreturn => {
            @call(.auto, f, args);
        },
        .void => {
            @call(.auto, f, args);
            return default_value;
        },
        .int => |info| {
            if (info.bits != 8) {
                @compileError(bad_fn_ret);
            }

            const status = @call(.auto, f, args);
            if (Impl != PosixThreadImpl) {
                return status;
            }

            // pthreads don't support exit status, ignore value
            return default_value;
        },
        .error_union => |info| {
            switch (info.payload) {
                void, noreturn => {
                    @call(.auto, f, args) catch |err| {
                        std.debug.print("error: {s}\n", .{@errorName(err)});
                        if (@errorReturnTrace()) |trace| {
                            std.debug.dumpStackTrace(trace.*);
                        }
                    };

                    return default_value;
                },
                else => {
                    @compileError(bad_fn_ret);
                },
            }
        },
        else => {
            @compileError(bad_fn_ret);
        },
    }
}

/// We can't compile error in the `Impl` switch statement as its eagerly evaluated.
/// So instead, we compile-error on the methods themselves for platforms which don't support threads.
const UnsupportedImpl = struct {
    pub const ThreadHandle = void;

    fn getCurrentId() usize {
        return unsupported({});
    }

    fn getCpuCount() !usize {
        return unsupported({});
    }

    fn spawn(config: SpawnConfig, comptime f: anytype, args: anytype) !Impl {
        return unsupported(.{ config, f, args });
    }

    fn getHandle(self: Impl) ThreadHandle {
        return unsupported(self);
    }

    fn detach(self: Impl) void {
        return unsupported(self);
    }

    fn join(self: Impl) void {
        return unsupported(self);
    }

    fn unsupported(unused: anytype) noreturn {
        _ = unused;
        @compileError("Unsupported operating system " ++ @tagName(native_os));
    }
};

const WindowsThreadImpl = struct {
    pub const ThreadHandle = windows.HANDLE;

    fn getCurrentId() windows.DWORD {
        return windows.GetCurrentThreadId();
    }

    fn getCpuCount() !usize {
        // Faster than calling into GetSystemInfo(), even if amortized.
        return windows.peb().NumberOfProcessors;
    }

    thread: *ThreadCompletion,

    const ThreadCompletion = struct {
        completion: Completion,
        heap_ptr: windows.PVOID,
        heap_handle: windows.HANDLE,
        thread_handle: windows.HANDLE = undefined,

        fn free(self: ThreadCompletion) void {
            const status = windows.kernel32.HeapFree(self.heap_handle, 0, self.heap_ptr);
            assert(status != 0);
        }
    };

    fn spawn(config: SpawnConfig, comptime f: anytype, args: anytype) !Impl {
        const Args = @TypeOf(args);
        const Instance = struct {
            fn_args: Args,
            thread: ThreadCompletion,

            fn entryFn(raw_ptr: windows.PVOID) callconv(.winapi) windows.DWORD {
                const self: *@This() = @ptrCast(@alignCast(raw_ptr));
                defer switch (self.thread.completion.swap(.completed, .seq_cst)) {
                    .running => {},
                    .completed => unreachable,
                    .detached => self.thread.free(),
                };
                return callFn(f, self.fn_args);
            }
        };

        const heap_handle = windows.kernel32.GetProcessHeap() orelse return error.OutOfMemory;
        const alloc_bytes = @alignOf(Instance) + @sizeOf(Instance);
        const alloc_ptr = windows.kernel32.HeapAlloc(heap_handle, 0, alloc_bytes) orelse return error.OutOfMemory;
        errdefer assert(windows.kernel32.HeapFree(heap_handle, 0, alloc_ptr) != 0);

        const instance_bytes = @as([*]u8, @ptrCast(alloc_ptr))[0..alloc_bytes];
        var fba = std.heap.FixedBufferAllocator.init(instance_bytes);
        const instance = fba.allocator().create(Instance) catch unreachable;
        instance.* = .{
            .fn_args = args,
            .thread = .{
                .completion = Completion.init(.running),
                .heap_ptr = alloc_ptr,
                .heap_handle = heap_handle,
            },
        };

        // Windows appears to only support SYSTEM_INFO.dwAllocationGranularity minimum stack size.
        // Going lower makes it default to that specified in the executable (~1mb).
        // Its also fine if the limit here is incorrect as stack size is only a hint.
        var stack_size = std.math.cast(u32, config.stack_size) orelse std.math.maxInt(u32);
        stack_size = @max(64 * 1024, stack_size);

        instance.thread.thread_handle = windows.kernel32.CreateThread(
            null,
            stack_size,
            Instance.entryFn,
            instance,
            0,
            null,
        ) orelse {
            const errno = windows.GetLastError();
            return windows.unexpectedError(errno);
        };

        return Impl{ .thread = &instance.thread };
    }

    fn getHandle(self: Impl) ThreadHandle {
        return self.thread.thread_handle;
    }

    fn detach(self: Impl) void {
        windows.CloseHandle(self.thread.thread_handle);
        switch (self.thread.completion.swap(.detached, .seq_cst)) {
            .running => {},
            .completed => self.thread.free(),
            .detached => unreachable,
        }
    }

    fn join(self: Impl) void {
        windows.WaitForSingleObjectEx(self.thread.thread_handle, windows.INFINITE, false) catch unreachable;
        windows.CloseHandle(self.thread.thread_handle);
        assert(self.thread.completion.load(.seq_cst) == .completed);
        self.thread.free();
    }
};

const PosixThreadImpl = struct {
    const c = std.c;

    pub const ThreadHandle = c.pthread_t;

    fn getCurrentId() Id {
        switch (native_os) {
            .linux => {
                return LinuxThreadImpl.getCurrentId();
            },
            .macos, .ios, .watchos, .tvos, .visionos => {
                var thread_id: u64 = undefined;
                // Pass thread=null to get the current thread ID.
                assert(c.pthread_threadid_np(null, &thread_id) == 0);
                return thread_id;
            },
            .dragonfly => {
                return @as(u32, @bitCast(c.lwp_gettid()));
            },
            .netbsd => {
                return @as(u32, @bitCast(c._lwp_self()));
            },
            .freebsd => {
                return @as(u32, @bitCast(c.pthread_getthreadid_np()));
            },
            .openbsd => {
                return @as(u32, @bitCast(c.getthrid()));
            },
            .haiku => {
                return @as(u32, @bitCast(c.find_thread(null)));
            },
            .serenity => {
                return @as(u32, @bitCast(c.pthread_self()));
            },
            else => {
                return @intFromPtr(c.pthread_self());
            },
        }
    }

    fn getCpuCount() !usize {
        switch (native_os) {
            .linux => {
                return LinuxThreadImpl.getCpuCount();
            },
            .openbsd => {
                var count: c_int = undefined;
                var count_size: usize = @sizeOf(c_int);
                const mib = [_]c_int{ std.c.CTL.HW, std.c.HW.NCPUONLINE };
                posix.sysctl(&mib, &count, &count_size, null, 0) catch |err| switch (err) {
                    error.NameTooLong, error.UnknownName => unreachable,
                    else => |e| return e,
                };
                return @as(usize, @intCast(count));
            },
            .solaris, .illumos, .serenity => {
                // The "proper" way to get the cpu count would be to query
                // /dev/kstat via ioctls, and traverse a linked list for each
                // cpu. (solaris, illumos)
                const rc = c.sysconf(@intFromEnum(std.c._SC.NPROCESSORS_ONLN));
                return switch (posix.errno(rc)) {
                    .SUCCESS => @as(usize, @intCast(rc)),
                    else => |err| posix.unexpectedErrno(err),
                };
            },
            .haiku => {
                var system_info: std.c.system_info = undefined;
                const rc = std.c.get_system_info(&system_info); // always returns B_OK
                return switch (posix.errno(rc)) {
                    .SUCCESS => @as(usize, @intCast(system_info.cpu_count)),
                    else => |err| posix.unexpectedErrno(err),
                };
            },
            else => {
                var count: c_int = undefined;
                var count_len: usize = @sizeOf(c_int);
                const name = if (comptime target.os.tag.isDarwin()) "hw.logicalcpu" else "hw.ncpu";
                posix.sysctlbynameZ(name, &count, &count_len, null, 0) catch |err| switch (err) {
                    error.NameTooLong, error.UnknownName => unreachable,
                    else => |e| return e,
                };
                return @as(usize, @intCast(count));
            },
        }
    }

    handle: ThreadHandle,

    fn spawn(config: SpawnConfig, comptime f: anytype, args: anytype) !Impl {
        const Args = @TypeOf(args);
        const allocator = std.heap.c_allocator;

        const Instance = struct {
            fn entryFn(raw_arg: ?*anyopaque) callconv(.c) ?*anyopaque {
                const args_ptr: *Args = @ptrCast(@alignCast(raw_arg));
                defer allocator.destroy(args_ptr);
                return callFn(f, args_ptr.*);
            }
        };

        const args_ptr = try allocator.create(Args);
        args_ptr.* = args;
        errdefer allocator.destroy(args_ptr);

        var attr: c.pthread_attr_t = undefined;
        if (c.pthread_attr_init(&attr) != .SUCCESS) return error.SystemResources;
        defer assert(c.pthread_attr_destroy(&attr) == .SUCCESS);

        // Use the same set of parameters used by the libc-less impl.
        const stack_size = @max(config.stack_size, 16 * 1024);
        assert(c.pthread_attr_setstacksize(&attr, stack_size) == .SUCCESS);
        assert(c.pthread_attr_setguardsize(&attr, std.heap.pageSize()) == .SUCCESS);

        var handle: c.pthread_t = undefined;
        switch (c.pthread_create(
            &handle,
            &attr,
            Instance.entryFn,
            @ptrCast(args_ptr),
        )) {
            .SUCCESS => return Impl{ .handle = handle },
            .AGAIN => return error.SystemResources,
            .PERM => unreachable,
            .INVAL => unreachable,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn getHandle(self: Impl) ThreadHandle {
        return self.handle;
    }

    fn detach(self: Impl) void {
        switch (c.pthread_detach(self.handle)) {
            .SUCCESS => {},
            .INVAL => unreachable, // thread handle is not joinable
            .SRCH => unreachable, // thread handle is invalid
            else => unreachable,
        }
    }

    fn join(self: Impl) void {
        switch (c.pthread_join(self.handle, null)) {
            .SUCCESS => {},
            .INVAL => unreachable, // thread handle is not joinable (or another thread is already joining in)
            .SRCH => unreachable, // thread handle is invalid
            .DEADLK => unreachable, // two threads tried to join each other
            else => unreachable,
        }
    }
};

const WasiThreadImpl = struct {
    thread: *WasiThread,

    pub const ThreadHandle = i32;
    threadlocal var tls_thread_id: Id = 0;

    const WasiThread = struct {
        /// Thread ID
        tid: std.atomic.Value(i32) = std.atomic.Value(i32).init(0),
        /// Contains all memory which was allocated to bootstrap this thread, including:
        /// - Guard page
        /// - Stack
        /// - TLS segment
        /// - `Instance`
        /// All memory is freed upon call to `join`
        memory: []u8,
        /// The allocator used to allocate the thread's memory,
        /// which is also used during `join` to ensure clean-up.
        allocator: std.mem.Allocator,
        /// The current state of the thread.
        state: State = State.init(.running),
    };

    /// A meta-data structure used to bootstrap a thread
    const Instance = struct {
        thread: WasiThread,
        /// Contains the offset to the new __tls_base.
        /// The offset starting from the memory's base.
        tls_offset: usize,
        /// Contains the offset to the stack for the newly spawned thread.
        /// The offset is calculated starting from the memory's base.
        stack_offset: usize,
        /// Contains the raw pointer value to the wrapper which holds all arguments
        /// for the callback.
        raw_ptr: usize,
        /// Function pointer to a wrapping function which will call the user's
        /// function upon thread spawn. The above mentioned pointer will be passed
        /// to this function pointer as its argument.
        call_back: *const fn (usize) void,
        /// When a thread is in `detached` state, we must free all of its memory
        /// upon thread completion. However, as this is done while still within
        /// the thread, we must first jump back to the main thread's stack or else
        /// we end up freeing the stack that we're currently using.
        original_stack_pointer: [*]u8,
    };

    const State = std.atomic.Value(enum(u8) { running, completed, detached });

    fn getCurrentId() Id {
        return tls_thread_id;
    }

    fn getCpuCount() error{Unsupported}!noreturn {
        return error.Unsupported;
    }

    fn getHandle(self: Impl) ThreadHandle {
        return self.thread.tid.load(.seq_cst);
    }

    fn detach(self: Impl) void {
        switch (self.thread.state.swap(.detached, .seq_cst)) {
            .running => {},
            .completed => self.join(),
            .detached => unreachable,
        }
    }

    fn join(self: Impl) void {
        defer {
            // Create a copy of the allocator so we do not free the reference to the
            // original allocator while freeing the memory.
            var allocator = self.thread.allocator;
            allocator.free(self.thread.memory);
        }

        var spin: u8 = 10;
        while (true) {
            const tid = self.thread.tid.load(.seq_cst);
            if (tid == 0) {
                break;
            }

            if (spin > 0) {
                spin -= 1;
                std.atomic.spinLoopHint();
                continue;
            }

            const result = asm (
                \\ local.get %[ptr]
                \\ local.get %[expected]
                \\ i64.const -1 # infinite
                \\ memory.atomic.wait32 0
                \\ local.set %[ret]
                : [ret] "=r" (-> u32),
                : [ptr] "r" (&self.thread.tid.raw),
                  [expected] "r" (tid),
            );
            switch (result) {
                0 => continue, // ok
                1 => continue, // expected =! loaded
                2 => unreachable, // timeout (infinite)
                else => unreachable,
            }
        }
    }

    fn spawn(config: std.Thread.SpawnConfig, comptime f: anytype, args: anytype) SpawnError!WasiThreadImpl {
        if (config.allocator == null) {
            @panic("an allocator is required to spawn a WASI thread");
        }

        // Wrapping struct required to hold the user-provided function arguments.
        const Wrapper = struct {
            args: @TypeOf(args),
            fn entry(ptr: usize) void {
                const w: *@This() = @ptrFromInt(ptr);
                const bad_fn_ret = "expected return type of startFn to be 'u8', 'noreturn', 'void', or '!void'";
                switch (@typeInfo(@typeInfo(@TypeOf(f)).@"fn".return_type.?)) {
                    .noreturn, .void => {
                        @call(.auto, f, w.args);
                    },
                    .int => |info| {
                        if (info.bits != 8) {
                            @compileError(bad_fn_ret);
                        }
                        _ = @call(.auto, f, w.args); // WASI threads don't support exit status, ignore value
                    },
                    .error_union => |info| {
                        if (info.payload != void) {
                            @compileError(bad_fn_ret);
                        }
                        @call(.auto, f, w.args) catch |err| {
                            std.debug.print("error: {s}\n", .{@errorName(err)});
                            if (@errorReturnTrace()) |trace| {
                                std.debug.dumpStackTrace(trace.*);
                            }
                        };
                    },
                    else => {
                        @compileError(bad_fn_ret);
                    },
                }
            }
        };

        var stack_offset: usize = undefined;
        var tls_offset: usize = undefined;
        var wrapper_offset: usize = undefined;
        var instance_offset: usize = undefined;

        // Calculate the bytes we have to allocate to store all thread information, including:
        // - The actual stack for the thread
        // - The TLS segment
        // - `Instance` - containing information about how to call the user's function.
        const map_bytes = blk: {
            // start with atleast a single page, which is used as a guard to prevent
            // other threads clobbering our new thread.
            // Unfortunately, WebAssembly has no notion of read-only segments, so this
            // is only a best effort.
            var bytes: usize = std.wasm.page_size;

            bytes = std.mem.alignForward(usize, bytes, 16); // align stack to 16 bytes
            stack_offset = bytes;
            bytes += @max(std.wasm.page_size, config.stack_size);

            bytes = std.mem.alignForward(usize, bytes, __tls_align());
            tls_offset = bytes;
            bytes += __tls_size();

            bytes = std.mem.alignForward(usize, bytes, @alignOf(Wrapper));
            wrapper_offset = bytes;
            bytes += @sizeOf(Wrapper);

            bytes = std.mem.alignForward(usize, bytes, @alignOf(Instance));
            instance_offset = bytes;
            bytes += @sizeOf(Instance);

            bytes = std.mem.alignForward(usize, bytes, std.wasm.page_size);
            break :blk bytes;
        };

        // Allocate the amount of memory required for all meta data.
        const allocated_memory = try config.allocator.?.alloc(u8, map_bytes);

        const wrapper: *Wrapper = @ptrCast(@alignCast(&allocated_memory[wrapper_offset]));
        wrapper.* = .{ .args = args };

        const instance: *Instance = @ptrCast(@alignCast(&allocated_memory[instance_offset]));
        instance.* = .{
            .thread = .{ .memory = allocated_memory, .allocator = config.allocator.? },
            .tls_offset = tls_offset,
            .stack_offset = stack_offset,
            .raw_ptr = @intFromPtr(wrapper),
            .call_back = &Wrapper.entry,
            .original_stack_pointer = __get_stack_pointer(),
        };

        const tid = spawnWasiThread(instance);
        // The specification says any value lower than 0 indicates an error.
        // The values of such error are unspecified. WASI-Libc treats it as EAGAIN.
        if (tid < 0) {
            return error.SystemResources;
        }
        instance.thread.tid.store(tid, .seq_cst);

        return .{ .thread = &instance.thread };
    }

    comptime {
        if (!builtin.single_threaded) {
            @export(&wasi_thread_start, .{ .name = "wasi_thread_start" });
        }
    }

    /// Called by the host environment after thread creation.
    fn wasi_thread_start(tid: i32, arg: *Instance) callconv(.c) void {
        comptime assert(!builtin.single_threaded);
        __set_stack_pointer(arg.thread.memory.ptr + arg.stack_offset);
        __wasm_init_tls(arg.thread.memory.ptr + arg.tls_offset);
        @atomicStore(u32, &WasiThreadImpl.tls_thread_id, @intCast(tid), .seq_cst);

        // Finished bootstrapping, call user's procedure.
        arg.call_back(arg.raw_ptr);

        switch (arg.thread.state.swap(.completed, .seq_cst)) {
            .running => {
                // reset the Thread ID
                asm volatile (
                    \\ local.get %[ptr]
                    \\ i32.const 0
                    \\ i32.atomic.store 0
                    :
                    : [ptr] "r" (&arg.thread.tid.raw),
                );

                // Wake the main thread listening to this thread
                asm volatile (
                    \\ local.get %[ptr]
                    \\ i32.const 1 # waiters
                    \\ memory.atomic.notify 0
                    \\ drop # no need to know the waiters
                    :
                    : [ptr] "r" (&arg.thread.tid.raw),
                );
            },
            .completed => unreachable,
            .detached => {
                // restore the original stack pointer so we can free the memory
                // without having to worry about freeing the stack
                __set_stack_pointer(arg.original_stack_pointer);
                // Ensure a copy so we don't free the allocator reference itself
                var allocator = arg.thread.allocator;
                allocator.free(arg.thread.memory);
            },
        }
    }

    /// Asks the host to create a new thread for us.
    /// Newly created thread will call `wasi_tread_start` with the thread ID as well
    /// as the input `arg` that was provided to `spawnWasiThread`
    const spawnWasiThread = @"thread-spawn";
    extern "wasi" fn @"thread-spawn"(arg: *Instance) i32;

    /// Initializes the TLS data segment starting at `memory`.
    /// This is a synthetic function, generated by the linker.
    extern fn __wasm_init_tls(memory: [*]u8) void;

    /// Returns a pointer to the base of the TLS data segment for the current thread
    inline fn __tls_base() [*]u8 {
        return asm (
            \\ .globaltype __tls_base, i32
            \\ global.get __tls_base
            \\ local.set %[ret]
            : [ret] "=r" (-> [*]u8),
        );
    }

    /// Returns the size of the TLS segment
    inline fn __tls_size() u32 {
        return asm volatile (
            \\ .globaltype __tls_size, i32, immutable
            \\ global.get __tls_size
            \\ local.set %[ret]
            : [ret] "=r" (-> u32),
        );
    }

    /// Returns the alignment of the TLS segment
    inline fn __tls_align() u32 {
        return asm (
            \\ .globaltype __tls_align, i32, immutable
            \\ global.get __tls_align
            \\ local.set %[ret]
            : [ret] "=r" (-> u32),
        );
    }

    /// Allows for setting the stack pointer in the WebAssembly module.
    inline fn __set_stack_pointer(addr: [*]u8) void {
        asm volatile (
            \\ local.get %[ptr]
            \\ global.set __stack_pointer
            :
            : [ptr] "r" (addr),
        );
    }

    /// Returns the current value of the stack pointer
    inline fn __get_stack_pointer() [*]u8 {
        return asm (
            \\ global.get __stack_pointer
            \\ local.set %[stack_ptr]
            : [stack_ptr] "=r" (-> [*]u8),
        );
    }
};

const LinuxThreadImpl = struct {
    const linux = std.os.linux;

    pub const ThreadHandle = i32;

    threadlocal var tls_thread_id: ?Id = null;

    fn getCurrentId() Id {
        return tls_thread_id orelse {
            const tid = @as(u32, @bitCast(linux.gettid()));
            tls_thread_id = tid;
            return tid;
        };
    }

    fn getCpuCount() !usize {
        const cpu_set = try posix.sched_getaffinity(0);
        return posix.CPU_COUNT(cpu_set);
    }

    thread: *ThreadCompletion,

    const ThreadCompletion = struct {
        completion: Completion = Completion.init(.running),
        child_tid: std.atomic.Value(i32) = std.atomic.Value(i32).init(1),
        parent_tid: i32 = undefined,
        mapped: []align(std.heap.page_size_min) u8,

        /// Calls `munmap(mapped.ptr, mapped.len)` then `exit(1)` without touching the stack (which lives in `mapped.ptr`).
        /// Ported over from musl libc's pthread detached implementation:
        /// https://github.com/ifduyue/musl/search?q=__unmapself
        fn freeAndExit(self: *ThreadCompletion) noreturn {
            switch (target.cpu.arch) {
                .x86 => asm volatile (
                    \\  movl $91, %%eax # SYS_munmap
                    \\  movl %[ptr], %%ebx
                    \\  movl %[len], %%ecx
                    \\  int $128
                    \\  movl $1, %%eax # SYS_exit
                    \\  movl $0, %%ebx
                    \\  int $128
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .x86_64 => asm volatile (
                    \\  movq $11, %%rax # SYS_munmap
                    \\  syscall
                    \\  movq $60, %%rax # SYS_exit
                    \\  movq $1, %%rdi
                    \\  syscall
                    :
                    : [ptr] "{rdi}" (@intFromPtr(self.mapped.ptr)),
                      [len] "{rsi}" (self.mapped.len),
                ),
                .arm, .armeb, .thumb, .thumbeb => asm volatile (
                    \\  mov r7, #91 // SYS_munmap
                    \\  mov r0, %[ptr]
                    \\  mov r1, %[len]
                    \\  svc 0
                    \\  mov r7, #1 // SYS_exit
                    \\  mov r0, #0
                    \\  svc 0
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .aarch64, .aarch64_be => asm volatile (
                    \\  mov x8, #215 // SYS_munmap
                    \\  mov x0, %[ptr]
                    \\  mov x1, %[len]
                    \\  svc 0
                    \\  mov x8, #93 // SYS_exit
                    \\  mov x0, #0
                    \\  svc 0
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .hexagon => asm volatile (
                    \\  r6 = #215 // SYS_munmap
                    \\  r0 = %[ptr]
                    \\  r1 = %[len]
                    \\  trap0(#1)
                    \\  r6 = #93 // SYS_exit
                    \\  r0 = #0
                    \\  trap0(#1)
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                // We set `sp` to the address of the current function as a workaround for a Linux
                // kernel bug that caused syscalls to return EFAULT if the stack pointer is invalid.
                // The bug was introduced in 46e12c07b3b9603c60fc1d421ff18618241cb081 and fixed in
                // 7928eb0370d1133d0d8cd2f5ddfca19c309079d5.
                .mips, .mipsel => asm volatile (
                    \\  move $sp, $25
                    \\  li $2, 4091 # SYS_munmap
                    \\  move $4, %[ptr]
                    \\  move $5, %[len]
                    \\  syscall
                    \\  li $2, 4001 # SYS_exit
                    \\  li $4, 0
                    \\  syscall
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .mips64, .mips64el => asm volatile (
                    \\  li $2, 5011 # SYS_munmap
                    \\  move $4, %[ptr]
                    \\  move $5, %[len]
                    \\  syscall
                    \\  li $2, 5058 # SYS_exit
                    \\  li $4, 0
                    \\  syscall
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .powerpc, .powerpcle, .powerpc64, .powerpc64le => asm volatile (
                    \\  li 0, 91 # SYS_munmap
                    \\  mr 3, %[ptr]
                    \\  mr 4, %[len]
                    \\  sc
                    \\  li 0, 1 # SYS_exit
                    \\  li 3, 0
                    \\  sc
                    \\  blr
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .riscv32, .riscv64 => asm volatile (
                    \\  li a7, 215 # SYS_munmap
                    \\  mv a0, %[ptr]
                    \\  mv a1, %[len]
                    \\  ecall
                    \\  li a7, 93 # SYS_exit
                    \\  mv a0, zero
                    \\  ecall
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .s390x => asm volatile (
                    \\  lgr %%r2, %[ptr]
                    \\  lgr %%r3, %[len]
                    \\  svc 91 # SYS_munmap
                    \\  lghi %%r2, 0
                    \\  svc 1 # SYS_exit
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .sparc => asm volatile (
                    \\ # See sparc64 comments below.
                    \\ 1:
                    \\  cmp %%fp, 0
                    \\  beq 2f
                    \\  nop
                    \\  ba 1b
                    \\  restore
                    \\ 2:
                    \\  mov 73, %%g1 // SYS_munmap
                    \\  mov %[ptr], %%o0
                    \\  mov %[len], %%o1
                    \\  t 0x3 # ST_FLUSH_WINDOWS
                    \\  t 0x10
                    \\  mov 1, %%g1 // SYS_exit
                    \\  mov 0, %%o0
                    \\  t 0x10
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .sparc64 => asm volatile (
                    \\ # SPARCs really don't like it when active stack frames
                    \\ # is unmapped (it will result in a segfault), so we
                    \\ # force-deactivate it by running `restore` until
                    \\ # all frames are cleared.
                    \\ 1:
                    \\  cmp %%fp, 0
                    \\  beq 2f
                    \\  nop
                    \\  ba 1b
                    \\  restore
                    \\ 2:
                    \\  mov 73, %%g1 // SYS_munmap
                    \\  mov %[ptr], %%o0
                    \\  mov %[len], %%o1
                    \\  # Flush register window contents to prevent background
                    \\  # memory access before unmapping the stack.
                    \\  flushw
                    \\  t 0x6d
                    \\  mov 1, %%g1 // SYS_exit
                    \\  mov 0, %%o0
                    \\  t 0x6d
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                .loongarch32, .loongarch64 => asm volatile (
                    \\ or      $a0, $zero, %[ptr]
                    \\ or      $a1, $zero, %[len]
                    \\ ori     $a7, $zero, 215     # SYS_munmap
                    \\ syscall 0                   # call munmap
                    \\ ori     $a0, $zero, 0
                    \\ ori     $a7, $zero, 93      # SYS_exit
                    \\ syscall 0                   # call exit
                    :
                    : [ptr] "r" (@intFromPtr(self.mapped.ptr)),
                      [len] "r" (self.mapped.len),
                    : "memory"
                ),
                else => |cpu_arch| @compileError("Unsupported linux arch: " ++ @tagName(cpu_arch)),
            }
            unreachable;
        }
    };

    fn spawn(config: SpawnConfig, comptime f: anytype, args: anytype) !Impl {
        const page_size = std.heap.pageSize();
        const Args = @TypeOf(args);
        const Instance = struct {
            fn_args: Args,
            thread: ThreadCompletion,

            fn entryFn(raw_arg: usize) callconv(.c) u8 {
                const self = @as(*@This(), @ptrFromInt(raw_arg));
                defer switch (self.thread.completion.swap(.completed, .seq_cst)) {
                    .running => {},
                    .completed => unreachable,
                    .detached => self.thread.freeAndExit(),
                };
                return callFn(f, self.fn_args);
            }
        };

        var guard_offset: usize = undefined;
        var stack_offset: usize = undefined;
        var tls_offset: usize = undefined;
        var instance_offset: usize = undefined;

        const map_bytes = blk: {
            var bytes: usize = page_size;
            guard_offset = bytes;

            bytes += @max(page_size, config.stack_size);
            bytes = std.mem.alignForward(usize, bytes, page_size);
            stack_offset = bytes;

            bytes = std.mem.alignForward(usize, bytes, linux.tls.area_desc.alignment);
            tls_offset = bytes;
            bytes += linux.tls.area_desc.size;

            bytes = std.mem.alignForward(usize, bytes, @alignOf(Instance));
            instance_offset = bytes;
            bytes += @sizeOf(Instance);

            bytes = std.mem.alignForward(usize, bytes, page_size);
            break :blk bytes;
        };

        // map all memory needed without read/write permissions
        // to avoid committing the whole region right away
        // anonymous mapping ensures file descriptor limits are not exceeded
        const mapped = posix.mmap(
            null,
            map_bytes,
            posix.PROT.NONE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        ) catch |err| switch (err) {
            error.MemoryMappingNotSupported => unreachable,
            error.AccessDenied => unreachable,
            error.PermissionDenied => unreachable,
            error.ProcessFdQuotaExceeded => unreachable,
            error.SystemFdQuotaExceeded => unreachable,
            error.MappingAlreadyExists => unreachable,
            else => |e| return e,
        };
        assert(mapped.len >= map_bytes);
        errdefer posix.munmap(mapped);

        // map everything but the guard page as read/write
        posix.mprotect(
            @alignCast(mapped[guard_offset..]),
            posix.PROT.READ | posix.PROT.WRITE,
        ) catch |err| switch (err) {
            error.AccessDenied => unreachable,
            else => |e| return e,
        };

        // Prepare the TLS segment and prepare a user_desc struct when needed on x86
        var tls_ptr = linux.tls.prepareArea(mapped[tls_offset..]);
        var user_desc: if (target.cpu.arch == .x86) linux.user_desc else void = undefined;
        if (target.cpu.arch == .x86) {
            defer tls_ptr = @intFromPtr(&user_desc);
            user_desc = .{
                .entry_number = linux.tls.area_desc.gdt_entry_number,
                .base_addr = tls_ptr,
                .limit = 0xfffff,
                .flags = .{
                    .seg_32bit = 1,
                    .contents = 0, // Data
                    .read_exec_only = 0,
                    .limit_in_pages = 1,
                    .seg_not_present = 0,
                    .useable = 1,
                },
            };
        }

        const instance: *Instance = @ptrCast(@alignCast(&mapped[instance_offset]));
        instance.* = .{
            .fn_args = args,
            .thread = .{ .mapped = mapped },
        };

        const flags: u32 = linux.CLONE.THREAD | linux.CLONE.DETACHED |
            linux.CLONE.VM | linux.CLONE.FS | linux.CLONE.FILES |
            linux.CLONE.PARENT_SETTID | linux.CLONE.CHILD_CLEARTID |
            linux.CLONE.SIGHAND | linux.CLONE.SYSVSEM | linux.CLONE.SETTLS;

        switch (linux.E.init(linux.clone(
            Instance.entryFn,
            @intFromPtr(&mapped[stack_offset]),
            flags,
            @intFromPtr(instance),
            &instance.thread.parent_tid,
            tls_ptr,
            &instance.thread.child_tid.raw,
        ))) {
            .SUCCESS => return Impl{ .thread = &instance.thread },
            .AGAIN => return error.ThreadQuotaExceeded,
            .INVAL => unreachable,
            .NOMEM => return error.SystemResources,
            .NOSPC => unreachable,
            .PERM => unreachable,
            .USERS => unreachable,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn getHandle(self: Impl) ThreadHandle {
        return self.thread.parent_tid;
    }

    fn detach(self: Impl) void {
        switch (self.thread.completion.swap(.detached, .seq_cst)) {
            .running => {},
            .completed => self.join(),
            .detached => unreachable,
        }
    }

    fn join(self: Impl) void {
        defer posix.munmap(self.thread.mapped);

        var spin: u8 = 10;
        while (true) {
            const tid = self.thread.child_tid.load(.seq_cst);
            if (tid == 0) {
                break;
            }

            if (spin > 0) {
                spin -= 1;
                std.atomic.spinLoopHint();
                continue;
            }

            switch (linux.E.init(linux.futex_wait(
                &self.thread.child_tid.raw,
                linux.FUTEX.WAIT,
                tid,
                null,
            ))) {
                .SUCCESS => continue,
                .INTR => continue,
                .AGAIN => continue,
                else => unreachable,
            }
        }
    }
};

fn testThreadName(thread: *Thread) !void {
    const testCases = &[_][]const u8{
        "mythread",
        "b" ** max_name_len,
    };

    inline for (testCases) |tc| {
        try thread.setName(tc);

        var name_buffer: [max_name_len:0]u8 = undefined;

        const name = try thread.getName(&name_buffer);
        if (name) |value| {
            try std.testing.expectEqual(tc.len, value.len);
            try std.testing.expectEqualStrings(tc, value);
        }
    }
}

test "setName, getName" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const Context = struct {
        start_wait_event: ResetEvent = .{},
        test_done_event: ResetEvent = .{},
        thread_done_event: ResetEvent = .{},

        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: Thread = undefined,

        pub fn run(ctx: *@This()) !void {
            // Wait for the main thread to have set the thread field in the context.
            ctx.start_wait_event.wait();

            switch (native_os) {
                .windows => testThreadName(&ctx.thread) catch |err| switch (err) {
                    error.Unsupported => return error.SkipZigTest,
                    else => return err,
                },
                else => try testThreadName(&ctx.thread),
            }

            // Signal our test is done
            ctx.test_done_event.set();

            // wait for the thread to property exit
            ctx.thread_done_event.wait();
        }
    };

    var context = Context{};
    var thread = try spawn(.{}, Context.run, .{&context});

    context.thread = thread;
    context.start_wait_event.set();
    context.test_done_event.wait();

    switch (native_os) {
        .macos, .ios, .watchos, .tvos, .visionos => {
            const res = thread.setName("foobar");
            try std.testing.expectError(error.Unsupported, res);
        },
        .windows => testThreadName(&thread) catch |err| switch (err) {
            error.Unsupported => return error.SkipZigTest,
            else => return err,
        },
        else => try testThreadName(&thread),
    }

    context.thread_done_event.set();
    thread.join();
}

test {
    // Doesn't use testing.refAllDecls() since that would pull in the compileError spinLoopHint.
    _ = Futex;
    _ = ResetEvent;
    _ = Mutex;
    _ = Semaphore;
    _ = Condition;
    _ = RwLock;
    _ = Pool;
}

fn testIncrementNotify(value: *usize, event: *ResetEvent) void {
    value.* += 1;
    event.set();
}

test join {
    if (builtin.single_threaded) return error.SkipZigTest;

    var value: usize = 0;
    var event = ResetEvent{};

    const thread = try Thread.spawn(.{}, testIncrementNotify, .{ &value, &event });
    thread.join();

    try std.testing.expectEqual(value, 1);
}

test detach {
    if (builtin.single_threaded) return error.SkipZigTest;

    var value: usize = 0;
    var event = ResetEvent{};

    const thread = try Thread.spawn(.{}, testIncrementNotify, .{ &value, &event });
    thread.detach();

    event.wait();
    try std.testing.expectEqual(value, 1);
}
//! Condition variables are used with a Mutex to efficiently wait for an arbitrary condition to occur.
//! It does this by atomically unlocking the mutex, blocking the thread until notified, and finally re-locking the mutex.
//! Condition can be statically initialized and is at most `@sizeOf(u64)` large.
//!
//! Example:
//! ```
//! var m = Mutex{};
//! var c = Condition{};
//! var predicate = false;
//!
//! fn consumer() void {
//!     m.lock();
//!     defer m.unlock();
//!
//!     while (!predicate) {
//!         c.wait(&m);
//!     }
//! }
//!
//! fn producer() void {
//!     {
//!         m.lock();
//!         defer m.unlock();
//!         predicate = true;
//!     }
//!     c.signal();
//! }
//!
//! const thread = try std.Thread.spawn(.{}, producer, .{});
//! consumer();
//! thread.join();
//! ```
//!
//! Note that condition variables can only reliably unblock threads that are sequenced before them using the same Mutex.
//! This means that the following is allowed to deadlock:
//! ```
//! thread-1: mutex.lock()
//! thread-1: condition.wait(&mutex)
//!
//! thread-2: // mutex.lock() (without this, the following signal may not see the waiting thread-1)
//! thread-2: // mutex.unlock() (this is optional for correctness once locked above, as signal can be called while holding the mutex)
//! thread-2: condition.signal()
//! ```

const std = @import("../std.zig");
const builtin = @import("builtin");
const Condition = @This();
const Mutex = std.Thread.Mutex;

const os = std.os;
const assert = std.debug.assert;
const testing = std.testing;
const Futex = std.Thread.Futex;

impl: Impl = .{},

/// Atomically releases the Mutex, blocks the caller thread, then re-acquires the Mutex on return.
/// "Atomically" here refers to accesses done on the Condition after acquiring the Mutex.
///
/// The Mutex must be locked by the caller's thread when this function is called.
/// A Mutex can have multiple Conditions waiting with it concurrently, but not the opposite.
/// It is undefined behavior for multiple threads to wait ith different mutexes using the same Condition concurrently.
/// Once threads have finished waiting with one Mutex, the Condition can be used to wait with another Mutex.
///
/// A blocking call to wait() is unblocked from one of the following conditions:
/// - a spurious ("at random") wake up occurs
/// - a future call to `signal()` or `broadcast()` which has acquired the Mutex and is sequenced after this `wait()`.
///
/// Given wait() can be interrupted spuriously, the blocking condition should be checked continuously
/// irrespective of any notifications from `signal()` or `broadcast()`.
pub fn wait(self: *Condition, mutex: *Mutex) void {
    self.impl.wait(mutex, null) catch |err| switch (err) {
        error.Timeout => unreachable, // no timeout provided so we shouldn't have timed-out
    };
}

/// Atomically releases the Mutex, blocks the caller thread, then re-acquires the Mutex on return.
/// "Atomically" here refers to accesses done on the Condition after acquiring the Mutex.
///
/// The Mutex must be locked by the caller's thread when this function is called.
/// A Mutex can have multiple Conditions waiting with it concurrently, but not the opposite.
/// It is undefined behavior for multiple threads to wait ith different mutexes using the same Condition concurrently.
/// Once threads have finished waiting with one Mutex, the Condition can be used to wait with another Mutex.
///
/// A blocking call to `timedWait()` is unblocked from one of the following conditions:
/// - a spurious ("at random") wake occurs
/// - the caller was blocked for around `timeout_ns` nanoseconds, in which `error.Timeout` is returned.
/// - a future call to `signal()` or `broadcast()` which has acquired the Mutex and is sequenced after this `timedWait()`.
///
/// Given `timedWait()` can be interrupted spuriously, the blocking condition should be checked continuously
/// irrespective of any notifications from `signal()` or `broadcast()`.
pub fn timedWait(self: *Condition, mutex: *Mutex, timeout_ns: u64) error{Timeout}!void {
    return self.impl.wait(mutex, timeout_ns);
}

/// Unblocks at least one thread blocked in a call to `wait()` or `timedWait()` with a given Mutex.
/// The blocked thread must be sequenced before this call with respect to acquiring the same Mutex in order to be observable for unblocking.
/// `signal()` can be called with or without the relevant Mutex being acquired and have no "effect" if there's no observable blocked threads.
pub fn signal(self: *Condition) void {
    self.impl.wake(.one);
}

/// Unblocks all threads currently blocked in a call to `wait()` or `timedWait()` with a given Mutex.
/// The blocked threads must be sequenced before this call with respect to acquiring the same Mutex in order to be observable for unblocking.
/// `broadcast()` can be called with or without the relevant Mutex being acquired and have no "effect" if there's no observable blocked threads.
pub fn broadcast(self: *Condition) void {
    self.impl.wake(.all);
}

const Impl = if (builtin.single_threaded)
    SingleThreadedImpl
else if (builtin.os.tag == .windows)
    WindowsImpl
else
    FutexImpl;

const Notify = enum {
    one, // wake up only one thread
    all, // wake up all threads
};

const SingleThreadedImpl = struct {
    fn wait(self: *Impl, mutex: *Mutex, timeout: ?u64) error{Timeout}!void {
        _ = self;
        _ = mutex;

        // There are no other threads to wake us up.
        // So if we wait without a timeout we would never wake up.
        const timeout_ns = timeout orelse {
            unreachable; // deadlock detected
        };

        std.time.sleep(timeout_ns);
        return error.Timeout;
    }

    fn wake(self: *Impl, comptime notify: Notify) void {
        // There are no other threads to wake up.
        _ = self;
        _ = notify;
    }
};

const WindowsImpl = struct {
    condition: os.windows.CONDITION_VARIABLE = .{},

    fn wait(self: *Impl, mutex: *Mutex, timeout: ?u64) error{Timeout}!void {
        var timeout_overflowed = false;
        var timeout_ms: os.windows.DWORD = os.windows.INFINITE;

        if (timeout) |timeout_ns| {
            // Round the nanoseconds to the nearest millisecond,
            // then saturating cast it to windows DWORD for use in kernel32 call.
            const ms = (timeout_ns +| (std.time.ns_per_ms / 2)) / std.time.ns_per_ms;
            timeout_ms = std.math.cast(os.windows.DWORD, ms) orelse std.math.maxInt(os.windows.DWORD);

            // Track if the timeout overflowed into INFINITE and make sure not to wait forever.
            if (timeout_ms == os.windows.INFINITE) {
                timeout_overflowed = true;
                timeout_ms -= 1;
            }
        }

        if (builtin.mode == .Debug) {
            // The internal state of the DebugMutex needs to be handled here as well.
            mutex.impl.locking_thread.store(0, .unordered);
        }
        const rc = os.windows.kernel32.SleepConditionVariableSRW(
            &self.condition,
            if (builtin.mode == .Debug) &mutex.impl.impl.srwlock else &mutex.impl.srwlock,
            timeout_ms,
            0, // the srwlock was assumed to acquired in exclusive mode not shared
        );
        if (builtin.mode == .Debug) {
            // The internal state of the DebugMutex needs to be handled here as well.
            mutex.impl.locking_thread.store(std.Thread.getCurrentId(), .unordered);
        }

        // Return error.Timeout if we know the timeout elapsed correctly.
        if (rc == os.windows.FALSE) {
            assert(os.windows.GetLastError() == .TIMEOUT);
            if (!timeout_overflowed) return error.Timeout;
        }
    }

    fn wake(self: *Impl, comptime notify: Notify) void {
        switch (notify) {
            .one => os.windows.kernel32.WakeConditionVariable(&self.condition),
            .all => os.windows.kernel32.WakeAllConditionVariable(&self.condition),
        }
    }
};

const FutexImpl = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    epoch: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    const one_waiter = 1;
    const waiter_mask = 0xffff;

    const one_signal = 1 << 16;
    const signal_mask = 0xffff << 16;

    fn wait(self: *Impl, mutex: *Mutex, timeout: ?u64) error{Timeout}!void {
        // Observe the epoch, then check the state again to see if we should wake up.
        // The epoch must be observed before we check the state or we could potentially miss a wake() and deadlock:
        //
        // - T1: s = LOAD(&state)
        // - T2: UPDATE(&s, signal)
        // - T2: UPDATE(&epoch, 1) + FUTEX_WAKE(&epoch)
        // - T1: e = LOAD(&epoch) (was reordered after the state load)
        // - T1: s & signals == 0 -> FUTEX_WAIT(&epoch, e) (missed the state update + the epoch change)
        //
        // Acquire barrier to ensure the epoch load happens before the state load.
        var epoch = self.epoch.load(.acquire);
        var state = self.state.fetchAdd(one_waiter, .monotonic);
        assert(state & waiter_mask != waiter_mask);
        state += one_waiter;

        mutex.unlock();
        defer mutex.lock();

        var futex_deadline = Futex.Deadline.init(timeout);

        while (true) {
            futex_deadline.wait(&self.epoch, epoch) catch |err| switch (err) {
                // On timeout, we must decrement the waiter we added above.
                error.Timeout => {
                    while (true) {
                        // If there's a signal when we're timing out, consume it and report being woken up instead.
                        // Acquire barrier ensures code before the wake() which added the signal happens before we decrement it and return.
                        while (state & signal_mask != 0) {
                            const new_state = state - one_waiter - one_signal;
                            state = self.state.cmpxchgWeak(state, new_state, .acquire, .monotonic) orelse return;
                        }

                        // Remove the waiter we added and officially return timed out.
                        const new_state = state - one_waiter;
                        state = self.state.cmpxchgWeak(state, new_state, .monotonic, .monotonic) orelse return err;
                    }
                },
            };

            epoch = self.epoch.load(.acquire);
            state = self.state.load(.monotonic);

            // Try to wake up by consuming a signal and decremented the waiter we added previously.
            // Acquire barrier ensures code before the wake() which added the signal happens before we decrement it and return.
            while (state & signal_mask != 0) {
                const new_state = state - one_waiter - one_signal;
                state = self.state.cmpxchgWeak(state, new_state, .acquire, .monotonic) orelse return;
            }
        }
    }

    fn wake(self: *Impl, comptime notify: Notify) void {
        var state = self.state.load(.monotonic);
        while (true) {
            const waiters = (state & waiter_mask) / one_waiter;
            const signals = (state & signal_mask) / one_signal;

            // Reserves which waiters to wake up by incrementing the signals count.
            // Therefore, the signals count is always less than or equal to the waiters count.
            // We don't need to Futex.wake if there's nothing to wake up or if other wake() threads have reserved to wake up the current waiters.
            const wakeable = waiters - signals;
            if (wakeable == 0) {
                return;
            }

            const to_wake = switch (notify) {
                .one => 1,
                .all => wakeable,
            };

            // Reserve the amount of waiters to wake by incrementing the signals count.
            // Release barrier ensures code before the wake() happens before the signal it posted and consumed by the wait() threads.
            const new_state = state + (one_signal * to_wake);
            state = self.state.cmpxchgWeak(state, new_state, .release, .monotonic) orelse {
                // Wake up the waiting threads we reserved above by changing the epoch value.
                // NOTE: a waiting thread could miss a wake up if *exactly* ((1<<32)-1) wake()s happen between it observing the epoch and sleeping on it.
                // This is very unlikely due to how many precise amount of Futex.wake() calls that would be between the waiting thread's potential preemption.
                //
                // Release barrier ensures the signal being added to the state happens before the epoch is changed.
                // If not, the waiting thread could potentially deadlock from missing both the state and epoch change:
                //
                // - T2: UPDATE(&epoch, 1) (reordered before the state change)
                // - T1: e = LOAD(&epoch)
                // - T1: s = LOAD(&state)
                // - T2: UPDATE(&state, signal) + FUTEX_WAKE(&epoch)
                // - T1: s & signals == 0 -> FUTEX_WAIT(&epoch, e) (missed both epoch change and state change)
                _ = self.epoch.fetchAdd(1, .release);
                Futex.wake(&self.epoch, to_wake);
                return;
            };
        }
    }
};

test "smoke test" {
    var mutex = Mutex{};
    var cond = Condition{};

    // Try to wake outside the mutex
    defer cond.signal();
    defer cond.broadcast();

    mutex.lock();
    defer mutex.unlock();

    // Try to wait with a timeout (should not deadlock)
    try testing.expectError(error.Timeout, cond.timedWait(&mutex, 0));
    try testing.expectError(error.Timeout, cond.timedWait(&mutex, std.time.ns_per_ms));

    // Try to wake inside the mutex.
    cond.signal();
    cond.broadcast();
}

// Inspired from: https://github.com/Amanieu/parking_lot/pull/129
test "wait and signal" {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 4;

    const MultiWait = struct {
        mutex: Mutex = .{},
        cond: Condition = .{},
        threads: [num_threads]std.Thread = undefined,
        spawn_count: std.math.IntFittingRange(0, num_threads) = 0,

        fn run(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.spawn_count += 1;

            self.cond.wait(&self.mutex);
            self.cond.timedWait(&self.mutex, std.time.ns_per_ms) catch {};
            self.cond.signal();
        }
    };

    var multi_wait = MultiWait{};
    for (&multi_wait.threads) |*t| {
        t.* = try std.Thread.spawn(.{}, MultiWait.run, .{&multi_wait});
    }

    while (true) {
        std.time.sleep(100 * std.time.ns_per_ms);

        multi_wait.mutex.lock();
        defer multi_wait.mutex.unlock();
        // Make sure all of the threads have finished spawning to avoid a deadlock.
        if (multi_wait.spawn_count == num_threads) break;
    }

    multi_wait.cond.signal();
    for (multi_wait.threads) |t| {
        t.join();
    }
}

test signal {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 4;

    const SignalTest = struct {
        mutex: Mutex = .{},
        cond: Condition = .{},
        notified: bool = false,
        threads: [num_threads]std.Thread = undefined,
        spawn_count: std.math.IntFittingRange(0, num_threads) = 0,

        fn run(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.spawn_count += 1;

            // Use timedWait() a few times before using wait()
            // to test multiple threads timing out frequently.
            var i: usize = 0;
            while (!self.notified) : (i +%= 1) {
                if (i < 5) {
                    self.cond.timedWait(&self.mutex, 1) catch {};
                } else {
                    self.cond.wait(&self.mutex);
                }
            }

            // Once we received the signal, notify another thread (inside the lock).
            assert(self.notified);
            self.cond.signal();
        }
    };

    var signal_test = SignalTest{};
    for (&signal_test.threads) |*t| {
        t.* = try std.Thread.spawn(.{}, SignalTest.run, .{&signal_test});
    }

    while (true) {
        std.time.sleep(10 * std.time.ns_per_ms);

        signal_test.mutex.lock();
        defer signal_test.mutex.unlock();
        // Make sure at least one thread has finished spawning to avoid testing nothing.
        if (signal_test.spawn_count > 0) break;
    }

    {
        // Wake up one of them (outside the lock) after setting notified=true.
        defer signal_test.cond.signal();

        signal_test.mutex.lock();
        defer signal_test.mutex.unlock();

        try testing.expect(!signal_test.notified);
        signal_test.notified = true;
    }

    for (signal_test.threads) |t| {
        t.join();
    }
}

test "multi signal" {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 4;
    const num_iterations = 4;

    const Paddle = struct {
        mutex: Mutex = .{},
        cond: Condition = .{},
        value: u32 = 0,

        fn hit(self: *@This()) void {
            defer self.cond.signal();

            self.mutex.lock();
            defer self.mutex.unlock();

            self.value += 1;
        }

        fn run(self: *@This(), hit_to: *@This()) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            var current: u32 = 0;
            while (current < num_iterations) : (current += 1) {
                // Wait for the value to change from hit()
                while (self.value == current) {
                    self.cond.wait(&self.mutex);
                }

                // hit the next paddle
                try testing.expectEqual(self.value, current + 1);
                hit_to.hit();
            }
        }
    };

    var paddles = [_]Paddle{.{}} ** num_threads;
    var threads = [_]std.Thread{undefined} ** num_threads;

    // Create a circle of paddles which hit each other
    for (&threads, 0..) |*t, i| {
        const paddle = &paddles[i];
        const hit_to = &paddles[(i + 1) % paddles.len];
        t.* = try std.Thread.spawn(.{}, Paddle.run, .{ paddle, hit_to });
    }

    // Hit the first paddle and wait for them all to complete by hitting each other for num_iterations.
    paddles[0].hit();
    for (threads) |t| t.join();

    // The first paddle will be hit one last time by the last paddle.
    for (paddles, 0..) |p, i| {
        const expected = @as(u32, num_iterations) + @intFromBool(i == 0);
        try testing.expectEqual(p.value, expected);
    }
}

test broadcast {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 10;

    const BroadcastTest = struct {
        mutex: Mutex = .{},
        cond: Condition = .{},
        completed: Condition = .{},
        count: usize = 0,
        threads: [num_threads]std.Thread = undefined,

        fn run(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // The last broadcast thread to start tells the main test thread it's completed.
            self.count += 1;
            if (self.count == num_threads) {
                self.completed.signal();
            }

            // Waits for the count to reach zero after the main test thread observes it at num_threads.
            // Tries to use timedWait() a bit before falling back to wait() to test multiple threads timing out.
            var i: usize = 0;
            while (self.count != 0) : (i +%= 1) {
                if (i < 10) {
                    self.cond.timedWait(&self.mutex, 1) catch {};
                } else {
                    self.cond.wait(&self.mutex);
                }
            }
        }
    };

    var broadcast_test = BroadcastTest{};
    for (&broadcast_test.threads) |*t| {
        t.* = try std.Thread.spawn(.{}, BroadcastTest.run, .{&broadcast_test});
    }

    {
        broadcast_test.mutex.lock();
        defer broadcast_test.mutex.unlock();

        // Wait for all the broadcast threads to spawn.
        // timedWait() to detect any potential deadlocks.
        while (broadcast_test.count != num_threads) {
            broadcast_test.completed.timedWait(
                &broadcast_test.mutex,
                1 * std.time.ns_per_s,
            ) catch {};
        }

        // Reset the counter and wake all the threads to exit.
        broadcast_test.count = 0;
        broadcast_test.cond.broadcast();
    }

    for (broadcast_test.threads) |t| {
        t.join();
    }
}

test "broadcasting - wake all threads" {
    // Tests issue #12877
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    var num_runs: usize = 1;
    const num_threads = 10;

    while (num_runs > 0) : (num_runs -= 1) {
        const BroadcastTest = struct {
            mutex: Mutex = .{},
            cond: Condition = .{},
            completed: Condition = .{},
            count: usize = 0,
            thread_id_to_wake: usize = 0,
            threads: [num_threads]std.Thread = undefined,
            wakeups: usize = 0,

            fn run(self: *@This(), thread_id: usize) void {
                self.mutex.lock();
                defer self.mutex.unlock();

                // The last broadcast thread to start tells the main test thread it's completed.
                self.count += 1;
                if (self.count == num_threads) {
                    self.completed.signal();
                }

                while (self.thread_id_to_wake != thread_id) {
                    self.cond.timedWait(&self.mutex, 1 * std.time.ns_per_s) catch {};
                    self.wakeups += 1;
                }
                if (self.thread_id_to_wake <= num_threads) {
                    // Signal next thread to wake up.
                    self.thread_id_to_wake += 1;
                    self.cond.broadcast();
                }
            }
        };

        var broadcast_test = BroadcastTest{};
        var thread_id: usize = 1;
        for (&broadcast_test.threads) |*t| {
            t.* = try std.Thread.spawn(.{}, BroadcastTest.run, .{ &broadcast_test, thread_id });
            thread_id += 1;
        }

        {
            broadcast_test.mutex.lock();
            defer broadcast_test.mutex.unlock();

            // Wait for all the broadcast threads to spawn.
            // timedWait() to detect any potential deadlocks.
            while (broadcast_test.count != num_threads) {
                broadcast_test.completed.timedWait(
                    &broadcast_test.mutex,
                    1 * std.time.ns_per_s,
                ) catch {};
            }

            // Signal thread 1 to wake up
            broadcast_test.thread_id_to_wake = 1;
            broadcast_test.cond.broadcast();
        }

        for (broadcast_test.threads) |t| {
            t.join();
        }
    }
}
//! A mechanism used to block (`wait`) and unblock (`wake`) threads using a
//! 32bit memory address as hints.
//!
//! Blocking a thread is acknowledged only if the 32bit memory address is equal
//! to a given value. This check helps avoid block/unblock deadlocks which
//! occur if a `wake()` happens before a `wait()`.
//!
//! Using Futex, other Thread synchronization primitives can be built which
//! efficiently wait for cross-thread events or signals.

const std = @import("../std.zig");
const builtin = @import("builtin");
const Futex = @This();
const windows = std.os.windows;
const linux = std.os.linux;
const c = std.c;

const assert = std.debug.assert;
const testing = std.testing;
const atomic = std.atomic;

/// Checks if `ptr` still contains the value `expect` and, if so, blocks the caller until either:
/// - The value at `ptr` is no longer equal to `expect`.
/// - The caller is unblocked by a matching `wake()`.
/// - The caller is unblocked spuriously ("at random").
///
/// The checking of `ptr` and `expect`, along with blocking the caller, is done atomically
/// and totally ordered (sequentially consistent) with respect to other wait()/wake() calls on the same `ptr`.
pub fn wait(ptr: *const atomic.Value(u32), expect: u32) void {
    @branchHint(.cold);

    Impl.wait(ptr, expect, null) catch |err| switch (err) {
        error.Timeout => unreachable, // null timeout meant to wait forever
    };
}

/// Checks if `ptr` still contains the value `expect` and, if so, blocks the caller until either:
/// - The value at `ptr` is no longer equal to `expect`.
/// - The caller is unblocked by a matching `wake()`.
/// - The caller is unblocked spuriously ("at random").
/// - The caller blocks for longer than the given timeout. In which case, `error.Timeout` is returned.
///
/// The checking of `ptr` and `expect`, along with blocking the caller, is done atomically
/// and totally ordered (sequentially consistent) with respect to other wait()/wake() calls on the same `ptr`.
pub fn timedWait(ptr: *const atomic.Value(u32), expect: u32, timeout_ns: u64) error{Timeout}!void {
    @branchHint(.cold);

    // Avoid calling into the OS for no-op timeouts.
    if (timeout_ns == 0) {
        if (ptr.load(.seq_cst) != expect) return;
        return error.Timeout;
    }

    return Impl.wait(ptr, expect, timeout_ns);
}

/// Unblocks at most `max_waiters` callers blocked in a `wait()` call on `ptr`.
pub fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
    @branchHint(.cold);

    // Avoid calling into the OS if there's nothing to wake up.
    if (max_waiters == 0) {
        return;
    }

    Impl.wake(ptr, max_waiters);
}

const Impl = if (builtin.single_threaded)
    SingleThreadedImpl
else if (builtin.os.tag == .windows)
    WindowsImpl
else if (builtin.os.tag.isDarwin())
    DarwinImpl
else if (builtin.os.tag == .linux)
    LinuxImpl
else if (builtin.os.tag == .freebsd)
    FreebsdImpl
else if (builtin.os.tag == .openbsd)
    OpenbsdImpl
else if (builtin.os.tag == .dragonfly)
    DragonflyImpl
else if (builtin.target.cpu.arch.isWasm())
    WasmImpl
else if (std.Thread.use_pthreads)
    PosixImpl
else
    UnsupportedImpl;

/// We can't do @compileError() in the `Impl` switch statement above as its eagerly evaluated.
/// So instead, we @compileError() on the methods themselves for platforms which don't support futex.
const UnsupportedImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        return unsupported(.{ ptr, expect, timeout });
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        return unsupported(.{ ptr, max_waiters });
    }

    fn unsupported(unused: anytype) noreturn {
        _ = unused;
        @compileError("Unsupported operating system " ++ @tagName(builtin.target.os.tag));
    }
};

const SingleThreadedImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        if (ptr.raw != expect) {
            return;
        }

        // There are no threads to wake us up.
        // So if we wait without a timeout we would never wake up.
        const delay = timeout orelse {
            unreachable; // deadlock detected
        };

        std.time.sleep(delay);
        return error.Timeout;
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        // There are no other threads to possibly wake up
        _ = ptr;
        _ = max_waiters;
    }
};

// We use WaitOnAddress through NtDll instead of API-MS-Win-Core-Synch-l1-2-0.dll
// as it's generally already a linked target and is autoloaded into all processes anyway.
const WindowsImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        var timeout_value: windows.LARGE_INTEGER = undefined;
        var timeout_ptr: ?*const windows.LARGE_INTEGER = null;

        // NTDLL functions work with time in units of 100 nanoseconds.
        // Positive values are absolute deadlines while negative values are relative durations.
        if (timeout) |delay| {
            timeout_value = @as(windows.LARGE_INTEGER, @intCast(delay / 100));
            timeout_value = -timeout_value;
            timeout_ptr = &timeout_value;
        }

        const rc = windows.ntdll.RtlWaitOnAddress(
            ptr,
            &expect,
            @sizeOf(@TypeOf(expect)),
            timeout_ptr,
        );

        switch (rc) {
            .SUCCESS => {},
            .TIMEOUT => {
                assert(timeout != null);
                return error.Timeout;
            },
            else => unreachable,
        }
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        const address: ?*const anyopaque = ptr;
        assert(max_waiters != 0);

        switch (max_waiters) {
            1 => windows.ntdll.RtlWakeAddressSingle(address),
            else => windows.ntdll.RtlWakeAddressAll(address),
        }
    }
};

const DarwinImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        // Darwin XNU 7195.50.7.100.1 introduced __ulock_wait2 and migrated code paths (notably pthread_cond_t) towards it:
        // https://github.com/apple/darwin-xnu/commit/d4061fb0260b3ed486147341b72468f836ed6c8f#diff-08f993cc40af475663274687b7c326cc6c3031e0db3ac8de7b24624610616be6
        //
        // This XNU version appears to correspond to 11.0.1:
        // https://kernelshaman.blogspot.com/2021/01/building-xnu-for-macos-big-sur-1101.html
        //
        // ulock_wait() uses 32-bit micro-second timeouts where 0 = INFINITE or no-timeout
        // ulock_wait2() uses 64-bit nano-second timeouts (with the same convention)
        const supports_ulock_wait2 = builtin.target.os.version_range.semver.min.major >= 11;

        var timeout_ns: u64 = 0;
        if (timeout) |delay| {
            assert(delay != 0); // handled by timedWait()
            timeout_ns = delay;
        }

        // If we're using `__ulock_wait` and `timeout` is too big to fit inside a `u32` count of
        // micro-seconds (around 70min), we'll request a shorter timeout. This is fine (users
        // should handle spurious wakeups), but we need to remember that we did so, so that
        // we don't return `Timeout` incorrectly. If that happens, we set this variable to
        // true so that we we know to ignore the ETIMEDOUT result.
        var timeout_overflowed = false;

        const addr: *const anyopaque = ptr;
        const flags: c.UL = .{
            .op = .COMPARE_AND_WAIT,
            .NO_ERRNO = true,
        };
        const status = blk: {
            if (supports_ulock_wait2) {
                break :blk c.__ulock_wait2(flags, addr, expect, timeout_ns, 0);
            }

            const timeout_us = std.math.cast(u32, timeout_ns / std.time.ns_per_us) orelse overflow: {
                timeout_overflowed = true;
                break :overflow std.math.maxInt(u32);
            };

            break :blk c.__ulock_wait(flags, addr, expect, timeout_us);
        };

        if (status >= 0) return;
        switch (@as(c.E, @enumFromInt(-status))) {
            // Wait was interrupted by the OS or other spurious signalling.
            .INTR => {},
            // Address of the futex was paged out. This is unlikely, but possible in theory, and
            // pthread/libdispatch on darwin bother to handle it. In this case we'll return
            // without waiting, but the caller should retry anyway.
            .FAULT => {},
            // Only report Timeout if we didn't have to cap the timeout
            .TIMEDOUT => {
                assert(timeout != null);
                if (!timeout_overflowed) return error.Timeout;
            },
            else => unreachable,
        }
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        const flags: c.UL = .{
            .op = .COMPARE_AND_WAIT,
            .NO_ERRNO = true,
            .WAKE_ALL = max_waiters > 1,
        };

        while (true) {
            const addr: *const anyopaque = ptr;
            const status = c.__ulock_wake(flags, addr, 0);

            if (status >= 0) return;
            switch (@as(c.E, @enumFromInt(-status))) {
                .INTR => continue, // spurious wake()
                .FAULT => unreachable, // __ulock_wake doesn't generate EFAULT according to darwin pthread_cond_t
                .NOENT => return, // nothing was woken up
                .ALREADY => unreachable, // only for UL.Op.WAKE_THREAD
                else => unreachable,
            }
        }
    }
};

// https://man7.org/linux/man-pages/man2/futex.2.html
const LinuxImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        var ts: linux.timespec = undefined;
        if (timeout) |timeout_ns| {
            ts.sec = @as(@TypeOf(ts.sec), @intCast(timeout_ns / std.time.ns_per_s));
            ts.nsec = @as(@TypeOf(ts.nsec), @intCast(timeout_ns % std.time.ns_per_s));
        }

        const rc = linux.futex_wait(
            @as(*const i32, @ptrCast(&ptr.raw)),
            linux.FUTEX.PRIVATE_FLAG | linux.FUTEX.WAIT,
            @as(i32, @bitCast(expect)),
            if (timeout != null) &ts else null,
        );

        switch (linux.E.init(rc)) {
            .SUCCESS => {}, // notified by `wake()`
            .INTR => {}, // spurious wakeup
            .AGAIN => {}, // ptr.* != expect
            .TIMEDOUT => {
                assert(timeout != null);
                return error.Timeout;
            },
            .INVAL => {}, // possibly timeout overflow
            .FAULT => unreachable, // ptr was invalid
            else => unreachable,
        }
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        const rc = linux.futex_wake(
            @as(*const i32, @ptrCast(&ptr.raw)),
            linux.FUTEX.PRIVATE_FLAG | linux.FUTEX.WAKE,
            std.math.cast(i32, max_waiters) orelse std.math.maxInt(i32),
        );

        switch (linux.E.init(rc)) {
            .SUCCESS => {}, // successful wake up
            .INVAL => {}, // invalid futex_wait() on ptr done elsewhere
            .FAULT => {}, // pointer became invalid while doing the wake
            else => unreachable,
        }
    }
};

// https://www.freebsd.org/cgi/man.cgi?query=_umtx_op&sektion=2&n=1
const FreebsdImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        var tm_size: usize = 0;
        var tm: c._umtx_time = undefined;
        var tm_ptr: ?*const c._umtx_time = null;

        if (timeout) |timeout_ns| {
            tm_ptr = &tm;
            tm_size = @sizeOf(@TypeOf(tm));

            tm.flags = 0; // use relative time not UMTX_ABSTIME
            tm.clockid = .MONOTONIC;
            tm.timeout.sec = @as(@TypeOf(tm.timeout.sec), @intCast(timeout_ns / std.time.ns_per_s));
            tm.timeout.nsec = @as(@TypeOf(tm.timeout.nsec), @intCast(timeout_ns % std.time.ns_per_s));
        }

        const rc = c._umtx_op(
            @intFromPtr(&ptr.raw),
            @intFromEnum(c.UMTX_OP.WAIT_UINT_PRIVATE),
            @as(c_ulong, expect),
            tm_size,
            @intFromPtr(tm_ptr),
        );

        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .FAULT => unreachable, // one of the args points to invalid memory
            .INVAL => unreachable, // arguments should be correct
            .TIMEDOUT => {
                assert(timeout != null);
                return error.Timeout;
            },
            .INTR => {}, // spurious wake
            else => unreachable,
        }
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        const rc = c._umtx_op(
            @intFromPtr(&ptr.raw),
            @intFromEnum(c.UMTX_OP.WAKE_PRIVATE),
            @as(c_ulong, max_waiters),
            0, // there is no timeout struct
            0, // there is no timeout struct pointer
        );

        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .FAULT => {}, // it's ok if the ptr doesn't point to valid memory
            .INVAL => unreachable, // arguments should be correct
            else => unreachable,
        }
    }
};

// https://man.openbsd.org/futex.2
const OpenbsdImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        var ts: c.timespec = undefined;
        if (timeout) |timeout_ns| {
            ts.sec = @as(@TypeOf(ts.sec), @intCast(timeout_ns / std.time.ns_per_s));
            ts.nsec = @as(@TypeOf(ts.nsec), @intCast(timeout_ns % std.time.ns_per_s));
        }

        const rc = c.futex(
            @as(*const volatile u32, @ptrCast(&ptr.raw)),
            c.FUTEX.WAIT | c.FUTEX.PRIVATE_FLAG,
            @as(c_int, @bitCast(expect)),
            if (timeout != null) &ts else null,
            null, // FUTEX.WAIT takes no requeue address
        );

        switch (std.posix.errno(rc)) {
            .SUCCESS => {}, // woken up by wake
            .NOSYS => unreachable, // the futex operation shouldn't be invalid
            .FAULT => unreachable, // ptr was invalid
            .AGAIN => {}, // ptr != expect
            .INVAL => unreachable, // invalid timeout
            .TIMEDOUT => {
                assert(timeout != null);
                return error.Timeout;
            },
            .INTR => {}, // spurious wake from signal
            .CANCELED => {}, // spurious wake from signal with SA_RESTART
            else => unreachable,
        }
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        const rc = c.futex(
            @as(*const volatile u32, @ptrCast(&ptr.raw)),
            c.FUTEX.WAKE | c.FUTEX.PRIVATE_FLAG,
            std.math.cast(c_int, max_waiters) orelse std.math.maxInt(c_int),
            null, // FUTEX.WAKE takes no timeout ptr
            null, // FUTEX.WAKE takes no requeue address
        );

        // returns number of threads woken up.
        assert(rc >= 0);
    }
};

// https://man.dragonflybsd.org/?command=umtx&section=2
const DragonflyImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        // Dragonfly uses a scheme where 0 timeout means wait until signaled or spurious wake.
        // It's reporting of timeout's is also unrealiable so we use an external timing source (Timer) instead.
        var timeout_us: c_int = 0;
        var timeout_overflowed = false;
        var sleep_timer: std.time.Timer = undefined;

        if (timeout) |delay| {
            assert(delay != 0); // handled by timedWait().
            timeout_us = std.math.cast(c_int, delay / std.time.ns_per_us) orelse blk: {
                timeout_overflowed = true;
                break :blk std.math.maxInt(c_int);
            };

            // Only need to record the start time if we can provide somewhat accurate error.Timeout's
            if (!timeout_overflowed) {
                sleep_timer = std.time.Timer.start() catch unreachable;
            }
        }

        const value = @as(c_int, @bitCast(expect));
        const addr = @as(*const volatile c_int, @ptrCast(&ptr.raw));
        const rc = c.umtx_sleep(addr, value, timeout_us);

        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .BUSY => {}, // ptr != expect
            .AGAIN => { // maybe timed out, or paged out, or hit 2s kernel refresh
                if (timeout) |timeout_ns| {
                    // Report error.Timeout only if we know the timeout duration has passed.
                    // If not, there's not much choice other than treating it as a spurious wake.
                    if (!timeout_overflowed and sleep_timer.read() >= timeout_ns) {
                        return error.Timeout;
                    }
                }
            },
            .INTR => {}, // spurious wake
            .INVAL => unreachable, // invalid timeout
            else => unreachable,
        }
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        // A count of zero means wake all waiters.
        assert(max_waiters != 0);
        const to_wake = std.math.cast(c_int, max_waiters) orelse 0;

        // https://man.dragonflybsd.org/?command=umtx&section=2
        // > umtx_wakeup() will generally return 0 unless the address is bad.
        // We are fine with the address ```
