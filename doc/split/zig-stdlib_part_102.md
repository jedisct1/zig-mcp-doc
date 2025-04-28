```
 // Map the upper half of the file
    {
        const file = try tmp.dir.openFile(test_out_file, .{});
        defer file.close();

        const data = try posix.mmap(
            null,
            alloc_size / 2,
            posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            file.handle,
            alloc_size / 2,
        );
        defer posix.munmap(data);

        var mem_stream = io.fixedBufferStream(data);
        const stream = mem_stream.reader();

        var i: u32 = alloc_size / 2 / @sizeOf(u32);
        while (i < alloc_size / @sizeOf(u32)) : (i += 1) {
            try testing.expectEqual(i, try stream.readInt(u32, .little));
        }
    }
}

test "getenv" {
    if (native_os == .wasi and !builtin.link_libc) {
        // std.posix.getenv is not supported on WASI due to the need of allocation
        return error.SkipZigTest;
    }

    if (native_os == .windows) {
        try expect(std.process.getenvW(&[_:0]u16{ 'B', 'O', 'G', 'U', 'S', 0x11, 0x22, 0x33, 0x44, 0x55 }) == null);
    } else {
        try expect(posix.getenv("") == null);
        try expect(posix.getenv("BOGUSDOESNOTEXISTENVVAR") == null);
        if (builtin.link_libc) {
            try testing.expectEqualStrings(posix.getenv("USER") orelse "", mem.span(std.c.getenv("USER") orelse ""));
        }
        try expect(posix.getenvZ("BOGUSDOESNOTEXISTENVVAR") == null);
    }
}

test "fcntl" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const test_out_file = "os_tmp_test";

    const file = try tmp.dir.createFile(test_out_file, .{});
    defer file.close();

    // Note: The test assumes createFile opens the file with CLOEXEC
    {
        const flags = try posix.fcntl(file.handle, posix.F.GETFD, 0);
        try expect((flags & posix.FD_CLOEXEC) != 0);
    }
    {
        _ = try posix.fcntl(file.handle, posix.F.SETFD, 0);
        const flags = try posix.fcntl(file.handle, posix.F.GETFD, 0);
        try expect((flags & posix.FD_CLOEXEC) == 0);
    }
    {
        _ = try posix.fcntl(file.handle, posix.F.SETFD, posix.FD_CLOEXEC);
        const flags = try posix.fcntl(file.handle, posix.F.GETFD, 0);
        try expect((flags & posix.FD_CLOEXEC) != 0);
    }
}

test "signalfd" {
    switch (native_os) {
        .linux, .solaris, .illumos => {},
        else => return error.SkipZigTest,
    }
    _ = &posix.signalfd;
}

test "sync" {
    if (native_os != .linux)
        return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const test_out_file = "os_tmp_test";
    const file = try tmp.dir.createFile(test_out_file, .{});
    defer file.close();

    posix.sync();
    try posix.syncfs(file.handle);
}

test "fsync" {
    switch (native_os) {
        .linux, .windows, .solaris, .illumos => {},
        else => return error.SkipZigTest,
    }

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const test_out_file = "os_tmp_test";
    const file = try tmp.dir.createFile(test_out_file, .{});
    defer file.close();

    try posix.fsync(file.handle);
    try posix.fdatasync(file.handle);
}

test "getrlimit and setrlimit" {
    if (posix.system.rlimit_resource == void) return error.SkipZigTest;

    inline for (@typeInfo(posix.rlimit_resource).@"enum".fields) |field| {
        const resource: posix.rlimit_resource = @enumFromInt(field.value);
        const limit = try posix.getrlimit(resource);

        // XNU kernel does not support RLIMIT_STACK if a custom stack is active,
        // which looks to always be the case. EINVAL is returned.
        // See https://github.com/apple-oss-distributions/xnu/blob/5e3eaea39dcf651e66cb99ba7d70e32cc4a99587/bsd/kern/kern_resource.c#L1173
        if (native_os.isDarwin() and resource == .STACK) {
            continue;
        }

        // On 32 bit MIPS musl includes a fix which changes limits greater than -1UL/2 to RLIM_INFINITY.
        // See http://git.musl-libc.org/cgit/musl/commit/src/misc/getrlimit.c?id=8258014fd1e34e942a549c88c7e022a00445c352
        //
        // This happens for example if RLIMIT_MEMLOCK is bigger than ~2GiB.
        // In that case the following the limit would be RLIM_INFINITY and the following setrlimit fails with EPERM.
        if (builtin.cpu.arch.isMIPS() and builtin.link_libc) {
            if (limit.cur != linux.RLIM.INFINITY) {
                try posix.setrlimit(resource, limit);
            }
        } else {
            try posix.setrlimit(resource, limit);
        }
    }
}

test "shutdown socket" {
    if (native_os == .wasi)
        return error.SkipZigTest;
    if (native_os == .windows) {
        _ = try std.os.windows.WSAStartup(2, 2);
    }
    defer {
        if (native_os == .windows) {
            std.os.windows.WSACleanup() catch unreachable;
        }
    }
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    posix.shutdown(sock, .both) catch |err| switch (err) {
        error.SocketNotConnected => {},
        else => |e| return e,
    };
    std.net.Stream.close(.{ .handle = sock });
}

test "sigaction" {
    if (native_os == .wasi or native_os == .windows)
        return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/7427
    if (native_os == .linux and builtin.target.cpu.arch == .x86)
        return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/15381
    if (native_os == .macos and builtin.target.cpu.arch == .x86_64) {
        return error.SkipZigTest;
    }

    const S = struct {
        var handler_called_count: u32 = 0;

        fn handler(sig: i32, info: *const posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
            _ = ctx_ptr;
            // Check that we received the correct signal.
            switch (native_os) {
                .netbsd => {
                    if (sig == posix.SIG.USR1 and sig == info.info.signo)
                        handler_called_count += 1;
                },
                else => {
                    if (sig == posix.SIG.USR1 and sig == info.signo)
                        handler_called_count += 1;
                },
            }
        }
    };

    var sa: posix.Sigaction = .{
        .handler = .{ .sigaction = &S.handler },
        .mask = posix.empty_sigset,
        .flags = posix.SA.SIGINFO | posix.SA.RESETHAND,
    };
    var old_sa: posix.Sigaction = undefined;

    // Install the new signal handler.
    posix.sigaction(posix.SIG.USR1, &sa, null);

    // Check that we can read it back correctly.
    posix.sigaction(posix.SIG.USR1, null, &old_sa);
    try testing.expectEqual(&S.handler, old_sa.handler.sigaction.?);
    try testing.expect((old_sa.flags & posix.SA.SIGINFO) != 0);

    // Invoke the handler.
    try posix.raise(posix.SIG.USR1);
    try testing.expect(S.handler_called_count == 1);

    // Check if passing RESETHAND correctly reset the handler to SIG_DFL
    posix.sigaction(posix.SIG.USR1, null, &old_sa);
    try testing.expectEqual(posix.SIG.DFL, old_sa.handler.handler);

    // Reinstall the signal w/o RESETHAND and re-raise
    sa.flags = posix.SA.SIGINFO;
    posix.sigaction(posix.SIG.USR1, &sa, null);
    try posix.raise(posix.SIG.USR1);
    try testing.expect(S.handler_called_count == 2);

    // Now set the signal to ignored
    sa.handler = .{ .handler = posix.SIG.IGN };
    sa.flags = 0;
    posix.sigaction(posix.SIG.USR1, &sa, null);

    // Re-raise to ensure handler is actually ignored
    try posix.raise(posix.SIG.USR1);
    try testing.expect(S.handler_called_count == 2);

    // Ensure that ignored state is returned when querying
    posix.sigaction(posix.SIG.USR1, null, &old_sa);
    try testing.expectEqual(posix.SIG.IGN, old_sa.handler.handler.?);
}

test "dup & dup2" {
    switch (native_os) {
        .linux, .solaris, .illumos => {},
        else => return error.SkipZigTest,
    }

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    {
        var file = try tmp.dir.createFile("os_dup_test", .{});
        defer file.close();

        var duped = std.fs.File{ .handle = try posix.dup(file.handle) };
        defer duped.close();
        try duped.writeAll("dup");

        // Tests aren't run in parallel so using the next fd shouldn't be an issue.
        const new_fd = duped.handle + 1;
        try posix.dup2(file.handle, new_fd);
        var dup2ed = std.fs.File{ .handle = new_fd };
        defer dup2ed.close();
        try dup2ed.writeAll("dup2");
    }

    var file = try tmp.dir.openFile("os_dup_test", .{});
    defer file.close();

    var buf: [7]u8 = undefined;
    try testing.expectEqualStrings("dupdup2", buf[0..try file.readAll(&buf)]);
}

test "writev longer than IOV_MAX" {
    if (native_os == .windows or native_os == .wasi) return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("pwritev", .{});
    defer file.close();

    const iovecs = [_]posix.iovec_const{.{ .base = "a", .len = 1 }} ** (posix.IOV_MAX + 1);
    const amt = try file.writev(&iovecs);
    try testing.expectEqual(@as(usize, posix.IOV_MAX), amt);
}

test "POSIX file locking with fcntl" {
    if (native_os == .windows or native_os == .wasi) {
        // Not POSIX.
        return error.SkipZigTest;
    }

    if (true) {
        // https://github.com/ziglang/zig/issues/11074
        return error.SkipZigTest;
    }

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // Create a temporary lock file
    var file = try tmp.dir.createFile("lock", .{ .read = true });
    defer file.close();
    try file.setEndPos(2);
    const fd = file.handle;

    // Place an exclusive lock on the first byte, and a shared lock on the second byte:
    var struct_flock = std.mem.zeroInit(posix.Flock, .{ .type = posix.F.WRLCK });
    _ = try posix.fcntl(fd, posix.F.SETLK, @intFromPtr(&struct_flock));
    struct_flock.start = 1;
    struct_flock.type = posix.F.RDLCK;
    _ = try posix.fcntl(fd, posix.F.SETLK, @intFromPtr(&struct_flock));

    // Check the locks in a child process:
    const pid = try posix.fork();
    if (pid == 0) {
        // child expects be denied the exclusive lock:
        struct_flock.start = 0;
        struct_flock.type = posix.F.WRLCK;
        try expectError(error.Locked, posix.fcntl(fd, posix.F.SETLK, @intFromPtr(&struct_flock)));
        // child expects to get the shared lock:
        struct_flock.start = 1;
        struct_flock.type = posix.F.RDLCK;
        _ = try posix.fcntl(fd, posix.F.SETLK, @intFromPtr(&struct_flock));
        // child waits for the exclusive lock in order to test deadlock:
        struct_flock.start = 0;
        struct_flock.type = posix.F.WRLCK;
        _ = try posix.fcntl(fd, posix.F.SETLKW, @intFromPtr(&struct_flock));
        // child exits without continuing:
        posix.exit(0);
    } else {
        // parent waits for child to get shared lock:
        std.time.sleep(1 * std.time.ns_per_ms);
        // parent expects deadlock when attempting to upgrade the shared lock to exclusive:
        struct_flock.start = 1;
        struct_flock.type = posix.F.WRLCK;
        try expectError(error.DeadLock, posix.fcntl(fd, posix.F.SETLKW, @intFromPtr(&struct_flock)));
        // parent releases exclusive lock:
        struct_flock.start = 0;
        struct_flock.type = posix.F.UNLCK;
        _ = try posix.fcntl(fd, posix.F.SETLK, @intFromPtr(&struct_flock));
        // parent releases shared lock:
        struct_flock.start = 1;
        struct_flock.type = posix.F.UNLCK;
        _ = try posix.fcntl(fd, posix.F.SETLK, @intFromPtr(&struct_flock));
        // parent waits for child:
        const result = posix.waitpid(pid, 0);
        try expect(result.status == 0 * 256);
    }
}

test "rename smoke test" {
    if (native_os == .wasi) return error.SkipZigTest;
    if (native_os == .windows) return error.SkipZigTest;

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

        // Rename the file
        const new_file_path = try fs.path.join(a, &.{ base_path, "some_other_file" });
        defer a.free(new_file_path);
        try posix.rename(file_path, new_file_path);
    }

    {
        // Try opening renamed file
        const file_path = try fs.path.join(a, &.{ base_path, "some_other_file" });
        defer a.free(file_path);
        const fd = try posix.open(file_path, .{ .ACCMODE = .RDWR }, mode);
        posix.close(fd);
    }

    {
        // Try opening original file - should fail with error.FileNotFound
        const file_path = try fs.path.join(a, &.{ base_path, "some_file" });
        defer a.free(file_path);
        try expectError(error.FileNotFound, posix.open(file_path, .{ .ACCMODE = .RDWR }, mode));
    }

    {
        // Create some directory
        const file_path = try fs.path.join(a, &.{ base_path, "some_dir" });
        defer a.free(file_path);
        try posix.mkdir(file_path, mode);

        // Rename the directory
        const new_file_path = try fs.path.join(a, &.{ base_path, "some_other_dir" });
        defer a.free(new_file_path);
        try posix.rename(file_path, new_file_path);
    }

    {
        // Try opening renamed directory
        const file_path = try fs.path.join(a, &.{ base_path, "some_other_dir" });
        defer a.free(file_path);
        const fd = try posix.open(file_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, mode);
        posix.close(fd);
    }

    {
        // Try opening original directory - should fail with error.FileNotFound
        const file_path = try fs.path.join(a, &.{ base_path, "some_dir" });
        defer a.free(file_path);
        try expectError(error.FileNotFound, posix.open(file_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, mode));
    }
}

test "access smoke test" {
    if (native_os == .wasi) return error.SkipZigTest;
    if (native_os == .windows) return error.SkipZigTest;

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
        // Try to access() the file
        const file_path = try fs.path.join(a, &.{ base_path, "some_file" });
        defer a.free(file_path);
        if (native_os == .windows) {
            try posix.access(file_path, posix.F_OK);
        } else {
            try posix.access(file_path, posix.F_OK | posix.W_OK | posix.R_OK);
        }
    }

    {
        // Try to access() a non-existent file - should fail with error.FileNotFound
        const file_path = try fs.path.join(a, &.{ base_path, "some_other_file" });
        defer a.free(file_path);
        try expectError(error.FileNotFound, posix.access(file_path, posix.F_OK));
    }

    {
        // Create some directory
        const file_path = try fs.path.join(a, &.{ base_path, "some_dir" });
        defer a.free(file_path);
        try posix.mkdir(file_path, mode);
    }

    {
        // Try to access() the directory
        const file_path = try fs.path.join(a, &.{ base_path, "some_dir" });
        defer a.free(file_path);

        try posix.access(file_path, posix.F_OK);
    }
}

test "timerfd" {
    if (native_os != .linux) return error.SkipZigTest;

    const tfd = try posix.timerfd_create(.MONOTONIC, .{ .CLOEXEC = true });
    defer posix.close(tfd);

    // Fire event 10_000_000ns = 10ms after the posix.timerfd_settime call.
    var sit: linux.itimerspec = .{ .it_interval = .{ .sec = 0, .nsec = 0 }, .it_value = .{ .sec = 0, .nsec = 10 * (1000 * 1000) } };
    try posix.timerfd_settime(tfd, .{}, &sit, null);

    var fds: [1]posix.pollfd = .{.{ .fd = tfd, .events = linux.POLL.IN, .revents = 0 }};
    try expectEqual(@as(usize, 1), try posix.poll(&fds, -1)); // -1 => infinite waiting

    const git = try posix.timerfd_gettime(tfd);
    const expect_disarmed_timer: linux.itimerspec = .{ .it_interval = .{ .sec = 0, .nsec = 0 }, .it_value = .{ .sec = 0, .nsec = 0 } };
    try expectEqual(expect_disarmed_timer, git);
}

test "isatty" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("foo", .{});
    defer file.close();

    try expectEqual(posix.isatty(file.handle), false);
}

test "read with empty buffer" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("read_empty", .{ .read = true });
    defer file.close();

    const bytes = try a.alloc(u8, 0);
    defer a.free(bytes);

    const rc = try posix.read(file.handle, bytes);
    try expectEqual(rc, 0);
}

test "pread with empty buffer" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("pread_empty", .{ .read = true });
    defer file.close();

    const bytes = try a.alloc(u8, 0);
    defer a.free(bytes);

    const rc = try posix.pread(file.handle, bytes, 0);
    try expectEqual(rc, 0);
}

test "write with empty buffer" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("write_empty", .{});
    defer file.close();

    const bytes = try a.alloc(u8, 0);
    defer a.free(bytes);

    const rc = try posix.write(file.handle, bytes);
    try expectEqual(rc, 0);
}

test "pwrite with empty buffer" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("pwrite_empty", .{});
    defer file.close();

    const bytes = try a.alloc(u8, 0);
    defer a.free(bytes);

    const rc = try posix.pwrite(file.handle, bytes, 0);
    try expectEqual(rc, 0);
}

fn expectMode(dir: posix.fd_t, file: []const u8, mode: posix.mode_t) !void {
    const st = try posix.fstatat(dir, file, posix.AT.SYMLINK_NOFOLLOW);
    try expectEqual(mode, st.mode & 0b111_111_111);
}

test "fchmodat smoke test" {
    if (!std.fs.has_executable_bit) return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    try expectError(error.FileNotFound, posix.fchmodat(tmp.dir.fd, "regfile", 0o666, 0));
    const fd = try posix.openat(
        tmp.dir.fd,
        "regfile",
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .TRUNC = true },
        0o644,
    );
    posix.close(fd);

    if ((builtin.cpu.arch == .riscv32 or builtin.cpu.arch.isLoongArch()) and builtin.os.tag == .linux and !builtin.link_libc) return error.SkipZigTest; // No `fstatat()`.

    try posix.symlinkat("regfile", tmp.dir.fd, "symlink");
    const sym_mode = blk: {
        const st = try posix.fstatat(tmp.dir.fd, "symlink", posix.AT.SYMLINK_NOFOLLOW);
        break :blk st.mode & 0b111_111_111;
    };

    try posix.fchmodat(tmp.dir.fd, "regfile", 0o640, 0);
    try expectMode(tmp.dir.fd, "regfile", 0o640);
    try posix.fchmodat(tmp.dir.fd, "regfile", 0o600, posix.AT.SYMLINK_NOFOLLOW);
    try expectMode(tmp.dir.fd, "regfile", 0o600);

    try posix.fchmodat(tmp.dir.fd, "symlink", 0o640, 0);
    try expectMode(tmp.dir.fd, "regfile", 0o640);
    try expectMode(tmp.dir.fd, "symlink", sym_mode);

    var test_link = true;
    posix.fchmodat(tmp.dir.fd, "symlink", 0o600, posix.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
        error.OperationNotSupported => test_link = false,
        else => |e| return e,
    };
    if (test_link)
        try expectMode(tmp.dir.fd, "symlink", 0o600);
    try expectMode(tmp.dir.fd, "regfile", 0o640);
}

const CommonOpenFlags = packed struct {
    ACCMODE: posix.ACCMODE = .RDONLY,
    CREAT: bool = false,
    EXCL: bool = false,
    LARGEFILE: bool = false,
    DIRECTORY: bool = false,
    CLOEXEC: bool = false,
    NONBLOCK: bool = false,

    pub fn lower(cof: CommonOpenFlags) posix.O {
        var result: posix.O = if (native_os == .wasi) .{
            .read = cof.ACCMODE != .WRONLY,
            .write = cof.ACCMODE != .RDONLY,
        } else .{
            .ACCMODE = cof.ACCMODE,
        };
        result.CREAT = cof.CREAT;
        result.EXCL = cof.EXCL;
        result.DIRECTORY = cof.DIRECTORY;
        result.NONBLOCK = cof.NONBLOCK;
        if (@hasField(posix.O, "CLOEXEC")) result.CLOEXEC = cof.CLOEXEC;
        if (@hasField(posix.O, "LARGEFILE")) result.LARGEFILE = cof.LARGEFILE;
        return result;
    }
};
const std = @import("std.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Order = std.math.Order;
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectError = testing.expectError;

/// Priority Dequeue for storing generic data. Initialize with `init`.
/// Provide `compareFn` that returns `Order.lt` when its second
/// argument should get min-popped before its third argument,
/// `Order.eq` if the arguments are of equal priority, or `Order.gt`
/// if the third argument should be min-popped second.
/// Popping the max element works in reverse. For example,
/// to make `popMin` return the smallest number, provide
/// `fn lessThan(context: void, a: T, b: T) Order { _ = context; return std.math.order(a, b); }`
pub fn PriorityDequeue(comptime T: type, comptime Context: type, comptime compareFn: fn (context: Context, a: T, b: T) Order) type {
    return struct {
        const Self = @This();

        items: []T,
        len: usize,
        allocator: Allocator,
        context: Context,

        /// Initialize and return a new priority dequeue.
        pub fn init(allocator: Allocator, context: Context) Self {
            return Self{
                .items = &[_]T{},
                .len = 0,
                .allocator = allocator,
                .context = context,
            };
        }

        /// Free memory used by the dequeue.
        pub fn deinit(self: Self) void {
            self.allocator.free(self.items);
        }

        /// Insert a new element, maintaining priority.
        pub fn add(self: *Self, elem: T) !void {
            try self.ensureUnusedCapacity(1);
            addUnchecked(self, elem);
        }

        /// Add each element in `items` to the dequeue.
        pub fn addSlice(self: *Self, items: []const T) !void {
            try self.ensureUnusedCapacity(items.len);
            for (items) |e| {
                self.addUnchecked(e);
            }
        }

        fn addUnchecked(self: *Self, elem: T) void {
            self.items[self.len] = elem;

            if (self.len > 0) {
                const start = self.getStartForSiftUp(elem, self.len);
                self.siftUp(start);
            }

            self.len += 1;
        }

        fn isMinLayer(index: usize) bool {
            // In the min-max heap structure:
            // The first element is on a min layer;
            // next two are on a max layer;
            // next four are on a min layer, and so on.
            return 1 == @clz(index +% 1) & 1;
        }

        fn nextIsMinLayer(self: Self) bool {
            return isMinLayer(self.len);
        }

        const StartIndexAndLayer = struct {
            index: usize,
            min_layer: bool,
        };

        fn getStartForSiftUp(self: Self, child: T, index: usize) StartIndexAndLayer {
            const child_index = index;
            const parent_index = parentIndex(child_index);
            const parent = self.items[parent_index];

            const min_layer = self.nextIsMinLayer();
            const order = compareFn(self.context, child, parent);
            if ((min_layer and order == .gt) or (!min_layer and order == .lt)) {
                // We must swap the item with it's parent if it is on the "wrong" layer
                self.items[parent_index] = child;
                self.items[child_index] = parent;
                return .{
                    .index = parent_index,
                    .min_layer = !min_layer,
                };
            } else {
                return .{
                    .index = child_index,
                    .min_layer = min_layer,
                };
            }
        }

        fn siftUp(self: *Self, start: StartIndexAndLayer) void {
            if (start.min_layer) {
                doSiftUp(self, start.index, .lt);
            } else {
                doSiftUp(self, start.index, .gt);
            }
        }

        fn doSiftUp(self: *Self, start_index: usize, target_order: Order) void {
            var child_index = start_index;
            while (child_index > 2) {
                const grandparent_index = grandparentIndex(child_index);
                const child = self.items[child_index];
                const grandparent = self.items[grandparent_index];

                // If the grandparent is already better or equal, we have gone as far as we need to
                if (compareFn(self.context, child, grandparent) != target_order) break;

                // Otherwise swap the item with it's grandparent
                self.items[grandparent_index] = child;
                self.items[child_index] = grandparent;
                child_index = grandparent_index;
            }
        }

        /// Look at the smallest element in the dequeue. Returns
        /// `null` if empty.
        pub fn peekMin(self: *Self) ?T {
            return if (self.len > 0) self.items[0] else null;
        }

        /// Look at the largest element in the dequeue. Returns
        /// `null` if empty.
        pub fn peekMax(self: *Self) ?T {
            if (self.len == 0) return null;
            if (self.len == 1) return self.items[0];
            if (self.len == 2) return self.items[1];
            return self.bestItemAtIndices(1, 2, .gt).item;
        }

        fn maxIndex(self: Self) ?usize {
            if (self.len == 0) return null;
            if (self.len == 1) return 0;
            if (self.len == 2) return 1;
            return self.bestItemAtIndices(1, 2, .gt).index;
        }

        /// Pop the smallest element from the dequeue. Returns
        /// `null` if empty.
        pub fn removeMinOrNull(self: *Self) ?T {
            return if (self.len > 0) self.removeMin() else null;
        }

        /// Remove and return the smallest element from the
        /// dequeue.
        pub fn removeMin(self: *Self) T {
            return self.removeIndex(0);
        }

        /// Pop the largest element from the dequeue. Returns
        /// `null` if empty.
        pub fn removeMaxOrNull(self: *Self) ?T {
            return if (self.len > 0) self.removeMax() else null;
        }

        /// Remove and return the largest element from the
        /// dequeue.
        pub fn removeMax(self: *Self) T {
            return self.removeIndex(self.maxIndex().?);
        }

        /// Remove and return element at index. Indices are in the
        /// same order as iterator, which is not necessarily priority
        /// order.
        pub fn removeIndex(self: *Self, index: usize) T {
            assert(self.len > index);
            const item = self.items[index];
            const last = self.items[self.len - 1];

            self.items[index] = last;
            self.len -= 1;
            siftDown(self, index);

            return item;
        }

        fn siftDown(self: *Self, index: usize) void {
            if (isMinLayer(index)) {
                self.doSiftDown(index, .lt);
            } else {
                self.doSiftDown(index, .gt);
            }
        }

        fn doSiftDown(self: *Self, start_index: usize, target_order: Order) void {
            var index = start_index;
            const half = self.len >> 1;
            while (true) {
                const first_grandchild_index = firstGrandchildIndex(index);
                const last_grandchild_index = first_grandchild_index + 3;

                const elem = self.items[index];

                if (last_grandchild_index < self.len) {
                    // All four grandchildren exist
                    const index2 = first_grandchild_index + 1;
                    const index3 = index2 + 1;

                    // Find the best grandchild
                    const best_left = self.bestItemAtIndices(first_grandchild_index, index2, target_order);
                    const best_right = self.bestItemAtIndices(index3, last_grandchild_index, target_order);
                    const best_grandchild = self.bestItem(best_left, best_right, target_order);

                    // If the item is better than or equal to its best grandchild, we are done
                    if (compareFn(self.context, best_grandchild.item, elem) != target_order) return;

                    // Otherwise, swap them
                    self.items[best_grandchild.index] = elem;
                    self.items[index] = best_grandchild.item;
                    index = best_grandchild.index;

                    // We might need to swap the element with it's parent
                    self.swapIfParentIsBetter(elem, index, target_order);
                } else {
                    // The children or grandchildren are the last layer
                    const first_child_index = firstChildIndex(index);
                    if (first_child_index >= self.len) return;

                    const best_descendent = self.bestDescendent(first_child_index, first_grandchild_index, target_order);

                    // If the item is better than or equal to its best descendant, we are done
                    if (compareFn(self.context, best_descendent.item, elem) != target_order) return;

                    // Otherwise swap them
                    self.items[best_descendent.index] = elem;
                    self.items[index] = best_descendent.item;
                    index = best_descendent.index;

                    // If we didn't swap a grandchild, we are done
                    if (index < first_grandchild_index) return;

                    // We might need to swap the element with it's parent
                    self.swapIfParentIsBetter(elem, index, target_order);
                    return;
                }

                // If we are now in the last layer, we are done
                if (index >= half) return;
            }
        }

        fn swapIfParentIsBetter(self: *Self, child: T, child_index: usize, target_order: Order) void {
            const parent_index = parentIndex(child_index);
            const parent = self.items[parent_index];

            if (compareFn(self.context, parent, child) == target_order) {
                self.items[parent_index] = child;
                self.items[child_index] = parent;
            }
        }

        const ItemAndIndex = struct {
            item: T,
            index: usize,
        };

        fn getItem(self: Self, index: usize) ItemAndIndex {
            return .{
                .item = self.items[index],
                .index = index,
            };
        }

        fn bestItem(self: Self, item1: ItemAndIndex, item2: ItemAndIndex, target_order: Order) ItemAndIndex {
            if (compareFn(self.context, item1.item, item2.item) == target_order) {
                return item1;
            } else {
                return item2;
            }
        }

        fn bestItemAtIndices(self: Self, index1: usize, index2: usize, target_order: Order) ItemAndIndex {
            const item1 = self.getItem(index1);
            const item2 = self.getItem(index2);
            return self.bestItem(item1, item2, target_order);
        }

        fn bestDescendent(self: Self, first_child_index: usize, first_grandchild_index: usize, target_order: Order) ItemAndIndex {
            const second_child_index = first_child_index + 1;
            if (first_grandchild_index >= self.len) {
                // No grandchildren, find the best child (second may not exist)
                if (second_child_index >= self.len) {
                    return .{
                        .item = self.items[first_child_index],
                        .index = first_child_index,
                    };
                } else {
                    return self.bestItemAtIndices(first_child_index, second_child_index, target_order);
                }
            }

            const second_grandchild_index = first_grandchild_index + 1;
            if (second_grandchild_index >= self.len) {
                // One grandchild, so we know there is a second child. Compare first grandchild and second child
                return self.bestItemAtIndices(first_grandchild_index, second_child_index, target_order);
            }

            const best_left_grandchild_index = self.bestItemAtIndices(first_grandchild_index, second_grandchild_index, target_order).index;
            const third_grandchild_index = second_grandchild_index + 1;
            if (third_grandchild_index >= self.len) {
                // Two grandchildren, and we know the best. Compare this to second child.
                return self.bestItemAtIndices(best_left_grandchild_index, second_child_index, target_order);
            } else {
                // Three grandchildren, compare the min of the first two with the third
                return self.bestItemAtIndices(best_left_grandchild_index, third_grandchild_index, target_order);
            }
        }

        /// Return the number of elements remaining in the dequeue
        pub fn count(self: Self) usize {
            return self.len;
        }

        /// Return the number of elements that can be added to the
        /// dequeue before more memory is allocated.
        pub fn capacity(self: Self) usize {
            return self.items.len;
        }

        /// Dequeue takes ownership of the passed in slice. The slice must have been
        /// allocated with `allocator`.
        /// De-initialize with `deinit`.
        pub fn fromOwnedSlice(allocator: Allocator, items: []T, context: Context) Self {
            var queue = Self{
                .items = items,
                .len = items.len,
                .allocator = allocator,
                .context = context,
            };

            if (queue.len <= 1) return queue;

            const half = (queue.len >> 1) - 1;
            var i: usize = 0;
            while (i <= half) : (i += 1) {
                const index = half - i;
                queue.siftDown(index);
            }
            return queue;
        }

        /// Ensure that the dequeue can fit at least `new_capacity` items.
        pub fn ensureTotalCapacity(self: *Self, new_capacity: usize) !void {
            var better_capacity = self.capacity();
            if (better_capacity >= new_capacity) return;
            while (true) {
                better_capacity += better_capacity / 2 + 8;
                if (better_capacity >= new_capacity) break;
            }
            self.items = try self.allocator.realloc(self.items, better_capacity);
        }

        /// Ensure that the dequeue can fit at least `additional_count` **more** items.
        pub fn ensureUnusedCapacity(self: *Self, additional_count: usize) !void {
            return self.ensureTotalCapacity(self.len + additional_count);
        }

        /// Reduce allocated capacity to `new_len`.
        pub fn shrinkAndFree(self: *Self, new_len: usize) void {
            assert(new_len <= self.items.len);

            // Cannot shrink to smaller than the current queue size without invalidating the heap property
            assert(new_len >= self.len);

            self.items = self.allocator.realloc(self.items[0..], new_len) catch |e| switch (e) {
                error.OutOfMemory => { // no problem, capacity is still correct then.
                    self.items.len = new_len;
                    return;
                },
            };
        }

        pub fn update(self: *Self, elem: T, new_elem: T) !void {
            const old_index = blk: {
                var idx: usize = 0;
                while (idx < self.len) : (idx += 1) {
                    const item = self.items[idx];
                    if (compareFn(self.context, item, elem) == .eq) break :blk idx;
                }
                return error.ElementNotFound;
            };
            _ = self.removeIndex(old_index);
            self.addUnchecked(new_elem);
        }

        pub const Iterator = struct {
            queue: *PriorityDequeue(T, Context, compareFn),
            count: usize,

            pub fn next(it: *Iterator) ?T {
                if (it.count >= it.queue.len) return null;
                const out = it.count;
                it.count += 1;
                return it.queue.items[out];
            }

            pub fn reset(it: *Iterator) void {
                it.count = 0;
            }
        };

        /// Return an iterator that walks the queue without consuming
        /// it. The iteration order may differ from the priority order.
        /// Invalidated if the queue is modified.
        pub fn iterator(self: *Self) Iterator {
            return Iterator{
                .queue = self,
                .count = 0,
            };
        }

        fn dump(self: *Self) void {
            const print = std.debug.print;
            print("{{ ", .{});
            print("items: ", .{});
            for (self.items, 0..) |e, i| {
                if (i >= self.len) break;
                print("{}, ", .{e});
            }
            print("array: ", .{});
            for (self.items) |e| {
                print("{}, ", .{e});
            }
            print("len: {} ", .{self.len});
            print("capacity: {}", .{self.capacity()});
            print(" }}\n", .{});
        }

        fn parentIndex(index: usize) usize {
            return (index - 1) >> 1;
        }

        fn grandparentIndex(index: usize) usize {
            return parentIndex(parentIndex(index));
        }

        fn firstChildIndex(index: usize) usize {
            return (index << 1) + 1;
        }

        fn firstGrandchildIndex(index: usize) usize {
            return firstChildIndex(firstChildIndex(index));
        }
    };
}

fn lessThanComparison(context: void, a: u32, b: u32) Order {
    _ = context;
    return std.math.order(a, b);
}

const PDQ = PriorityDequeue(u32, void, lessThanComparison);

test "add and remove min" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(54);
    try queue.add(12);
    try queue.add(7);
    try queue.add(23);
    try queue.add(25);
    try queue.add(13);

    try expectEqual(@as(u32, 7), queue.removeMin());
    try expectEqual(@as(u32, 12), queue.removeMin());
    try expectEqual(@as(u32, 13), queue.removeMin());
    try expectEqual(@as(u32, 23), queue.removeMin());
    try expectEqual(@as(u32, 25), queue.removeMin());
    try expectEqual(@as(u32, 54), queue.removeMin());
}

test "add and remove min structs" {
    const S = struct {
        size: u32,
    };
    var queue = PriorityDequeue(S, void, struct {
        fn order(context: void, a: S, b: S) Order {
            _ = context;
            return std.math.order(a.size, b.size);
        }
    }.order).init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(.{ .size = 54 });
    try queue.add(.{ .size = 12 });
    try queue.add(.{ .size = 7 });
    try queue.add(.{ .size = 23 });
    try queue.add(.{ .size = 25 });
    try queue.add(.{ .size = 13 });

    try expectEqual(@as(u32, 7), queue.removeMin().size);
    try expectEqual(@as(u32, 12), queue.removeMin().size);
    try expectEqual(@as(u32, 13), queue.removeMin().size);
    try expectEqual(@as(u32, 23), queue.removeMin().size);
    try expectEqual(@as(u32, 25), queue.removeMin().size);
    try expectEqual(@as(u32, 54), queue.removeMin().size);
}

test "add and remove max" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(54);
    try queue.add(12);
    try queue.add(7);
    try queue.add(23);
    try queue.add(25);
    try queue.add(13);

    try expectEqual(@as(u32, 54), queue.removeMax());
    try expectEqual(@as(u32, 25), queue.removeMax());
    try expectEqual(@as(u32, 23), queue.removeMax());
    try expectEqual(@as(u32, 13), queue.removeMax());
    try expectEqual(@as(u32, 12), queue.removeMax());
    try expectEqual(@as(u32, 7), queue.removeMax());
}

test "add and remove same min" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.add(1);
    try queue.add(1);

    try expectEqual(@as(u32, 1), queue.removeMin());
    try expectEqual(@as(u32, 1), queue.removeMin());
    try expectEqual(@as(u32, 1), queue.removeMin());
    try expectEqual(@as(u32, 1), queue.removeMin());
    try expectEqual(@as(u32, 2), queue.removeMin());
    try expectEqual(@as(u32, 2), queue.removeMin());
}

test "add and remove same max" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.add(1);
    try queue.add(1);

    try expectEqual(@as(u32, 2), queue.removeMax());
    try expectEqual(@as(u32, 2), queue.removeMax());
    try expectEqual(@as(u32, 1), queue.removeMax());
    try expectEqual(@as(u32, 1), queue.removeMax());
    try expectEqual(@as(u32, 1), queue.removeMax());
    try expectEqual(@as(u32, 1), queue.removeMax());
}

test "removeOrNull empty" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try expect(queue.removeMinOrNull() == null);
    try expect(queue.removeMaxOrNull() == null);
}

test "edge case 3 elements" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(9);
    try queue.add(3);
    try queue.add(2);

    try expectEqual(@as(u32, 2), queue.removeMin());
    try expectEqual(@as(u32, 3), queue.removeMin());
    try expectEqual(@as(u32, 9), queue.removeMin());
}

test "edge case 3 elements max" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(9);
    try queue.add(3);
    try queue.add(2);

    try expectEqual(@as(u32, 9), queue.removeMax());
    try expectEqual(@as(u32, 3), queue.removeMax());
    try expectEqual(@as(u32, 2), queue.removeMax());
}

test "peekMin" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try expect(queue.peekMin() == null);

    try queue.add(9);
    try queue.add(3);
    try queue.add(2);

    try expect(queue.peekMin().? == 2);
    try expect(queue.peekMin().? == 2);
}

test "peekMax" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try expect(queue.peekMin() == null);

    try queue.add(9);
    try queue.add(3);
    try queue.add(2);

    try expect(queue.peekMax().? == 9);
    try expect(queue.peekMax().? == 9);
}

test "sift up with odd indices, removeMin" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    for (items) |e| {
        try queue.add(e);
    }

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.removeMin());
    }
}

test "sift up with odd indices, removeMax" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    for (items) |e| {
        try queue.add(e);
    }

    const sorted_items = [_]u32{ 25, 24, 24, 22, 21, 16, 15, 15, 14, 13, 12, 11, 7, 7, 6, 5, 2, 1 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.removeMax());
    }
}

test "addSlice min" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    try queue.addSlice(items[0..]);

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.removeMin());
    }
}

test "addSlice max" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    try queue.addSlice(items[0..]);

    const sorted_items = [_]u32{ 25, 24, 24, 22, 21, 16, 15, 15, 14, 13, 12, 11, 7, 7, 6, 5, 2, 1 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.removeMax());
    }
}

test "fromOwnedSlice trivial case 0" {
    const items = [0]u32{};
    const queue_items = try testing.allocator.dupe(u32, &items);
    var queue = PDQ.fromOwnedSlice(testing.allocator, queue_items[0..], {});
    defer queue.deinit();
    try expectEqual(@as(usize, 0), queue.len);
    try expect(queue.removeMinOrNull() == null);
}

test "fromOwnedSlice trivial case 1" {
    const items = [1]u32{1};
    const queue_items = try testing.allocator.dupe(u32, &items);
    var queue = PDQ.fromOwnedSlice(testing.allocator, queue_items[0..], {});
    defer queue.deinit();

    try expectEqual(@as(usize, 1), queue.len);
    try expectEqual(items[0], queue.removeMin());
    try expect(queue.removeMinOrNull() == null);
}

test "fromOwnedSlice" {
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    const queue_items = try testing.allocator.dupe(u32, items[0..]);
    var queue = PDQ.fromOwnedSlice(testing.allocator, queue_items[0..], {});
    defer queue.deinit();

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.removeMin());
    }
}

test "update min queue" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(55);
    try queue.add(44);
    try queue.add(11);
    try queue.update(55, 5);
    try queue.update(44, 4);
    try queue.update(11, 1);
    try expectEqual(@as(u32, 1), queue.removeMin());
    try expectEqual(@as(u32, 4), queue.removeMin());
    try expectEqual(@as(u32, 5), queue.removeMin());
}

test "update same min queue" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.update(1, 5);
    try queue.update(2, 4);
    try expectEqual(@as(u32, 1), queue.removeMin());
    try expectEqual(@as(u32, 2), queue.removeMin());
    try expectEqual(@as(u32, 4), queue.removeMin());
    try expectEqual(@as(u32, 5), queue.removeMin());
}

test "update max queue" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(55);
    try queue.add(44);
    try queue.add(11);
    try queue.update(55, 5);
    try queue.update(44, 1);
    try queue.update(11, 4);

    try expectEqual(@as(u32, 5), queue.removeMax());
    try expectEqual(@as(u32, 4), queue.removeMax());
    try expectEqual(@as(u32, 1), queue.removeMax());
}

test "update same max queue" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.update(1, 5);
    try queue.update(2, 4);
    try expectEqual(@as(u32, 5), queue.removeMax());
    try expectEqual(@as(u32, 4), queue.removeMax());
    try expectEqual(@as(u32, 2), queue.removeMax());
    try expectEqual(@as(u32, 1), queue.removeMax());
}

test "update after remove" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try expectEqual(@as(u32, 1), queue.removeMin());
    try expectError(error.ElementNotFound, queue.update(1, 1));
}

test "iterator" {
    var queue = PDQ.init(testing.allocator, {});
    var map = std.AutoHashMap(u32, void).init(testing.allocator);
    defer {
        queue.deinit();
        map.deinit();
    }

    const items = [_]u32{ 54, 12, 7, 23, 25, 13 };
    for (items) |e| {
        _ = try queue.add(e);
        _ = try map.put(e, {});
    }

    var it = queue.iterator();
    while (it.next()) |e| {
        _ = map.remove(e);
    }

    try expectEqual(@as(usize, 0), map.count());
}

test "remove at index" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(3);
    try queue.add(2);
    try queue.add(1);

    var it = queue.iterator();
    var elem = it.next();
    var idx: usize = 0;
    const two_idx = while (elem != null) : (elem = it.next()) {
        if (elem.? == 2)
            break idx;
        idx += 1;
    } else unreachable;

    try expectEqual(queue.removeIndex(two_idx), 2);
    try expectEqual(queue.removeMin(), 1);
    try expectEqual(queue.removeMin(), 3);
    try expectEqual(queue.removeMinOrNull(), null);
}

test "iterator while empty" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    var it = queue.iterator();

    try expectEqual(it.next(), null);
}

test "shrinkAndFree" {
    var queue = PDQ.init(testing.allocator, {});
    defer queue.deinit();

    try queue.ensureTotalCapacity(4);
    try expect(queue.capacity() >= 4);

    try queue.add(1);
    try queue.add(2);
    try queue.add(3);
    try expect(queue.capacity() >= 4);
    try expectEqual(@as(usize, 3), queue.len);

    queue.shrinkAndFree(3);
    try expectEqual(@as(usize, 3), queue.capacity());
    try expectEqual(@as(usize, 3), queue.len);

    try expectEqual(@as(u32, 3), queue.removeMax());
    try expectEqual(@as(u32, 2), queue.removeMax());
    try expectEqual(@as(u32, 1), queue.removeMax());
    try expect(queue.removeMaxOrNull() == null);
}

test "fuzz testing min" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const test_case_count = 100;
    const queue_size = 1_000;

    var i: usize = 0;
    while (i < test_case_count) : (i += 1) {
        try fuzzTestMin(random, queue_size);
    }
}

fn fuzzTestMin(rng: std.Random, comptime queue_size: usize) !void {
    const allocator = testing.allocator;
    const items = try generateRandomSlice(allocator, rng, queue_size);

    var queue = PDQ.fromOwnedSlice(allocator, items, {});
    defer queue.deinit();

    var last_removed: ?u32 = null;
    while (queue.removeMinOrNull()) |next| {
        if (last_removed) |last| {
            try expect(last <= next);
        }
        last_removed = next;
    }
}

test "fuzz testing max" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const test_case_count = 100;
    const queue_size = 1_000;

    var i: usize = 0;
    while (i < test_case_count) : (i += 1) {
        try fuzzTestMax(random, queue_size);
    }
}

fn fuzzTestMax(rng: std.Random, queue_size: usize) !void {
    const allocator = testing.allocator;
    const items = try generateRandomSlice(allocator, rng, queue_size);

    var queue = PDQ.fromOwnedSlice(testing.allocator, items, {});
    defer queue.deinit();

    var last_removed: ?u32 = null;
    while (queue.removeMaxOrNull()) |next| {
        if (last_removed) |last| {
            try expect(last >= next);
        }
        last_removed = next;
    }
}

test "fuzz testing min and max" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const test_case_count = 100;
    const queue_size = 1_000;

    var i: usize = 0;
    while (i < test_case_count) : (i += 1) {
        try fuzzTestMinMax(random, queue_size);
    }
}

fn fuzzTestMinMax(rng: std.Random, queue_size: usize) !void {
    const allocator = testing.allocator;
    const items = try generateRandomSlice(allocator, rng, queue_size);

    var queue = PDQ.fromOwnedSlice(allocator, items, {});
    defer queue.deinit();

    var last_min: ?u32 = null;
    var last_max: ?u32 = null;
    var i: usize = 0;
    while (i < queue_size) : (i += 1) {
        if (i % 2 == 0) {
            const next = queue.removeMin();
            if (last_min) |last| {
                try expect(last <= next);
            }
            last_min = next;
        } else {
            const next = queue.removeMax();
            if (last_max) |last| {
                try expect(last >= next);
            }
            last_max = next;
        }
    }
}

fn generateRandomSlice(allocator: std.mem.Allocator, rng: std.Random, size: usize) ![]u32 {
    var array = std.ArrayList(u32).init(allocator);
    try array.ensureTotalCapacity(size);

    var i: usize = 0;
    while (i < size) : (i += 1) {
        const elem = rng.int(u32);
        try array.append(elem);
    }

    return array.toOwnedSlice();
}

fn contextLessThanComparison(context: []const u32, a: usize, b: usize) Order {
    return std.math.order(context[a], context[b]);
}

const CPDQ = PriorityDequeue(usize, []const u32, contextLessThanComparison);

test "add and remove" {
    const context = [_]u32{ 5, 3, 4, 2, 2, 8, 0 };

    var queue = CPDQ.init(testing.allocator, context[0..]);
    defer queue.deinit();

    try queue.add(0);
    try queue.add(1);
    try queue.add(2);
    try queue.add(3);
    try queue.add(4);
    try queue.add(5);
    try queue.add(6);
    try expectEqual(@as(usize, 6), queue.removeMin());
    try expectEqual(@as(usize, 5), queue.removeMax());
    try expectEqual(@as(usize, 3), queue.removeMin());
    try expectEqual(@as(usize, 0), queue.removeMax());
    try expectEqual(@as(usize, 4), queue.removeMin());
    try expectEqual(@as(usize, 2), queue.removeMax());
    try expectEqual(@as(usize, 1), queue.removeMin());
}

var all_cmps_unique = true;

test "don't compare a value to a copy of itself" {
    var depq = PriorityDequeue(u32, void, struct {
        fn uniqueLessThan(_: void, a: u32, b: u32) Order {
            all_cmps_unique = all_cmps_unique and (a != b);
            return std.math.order(a, b);
        }
    }.uniqueLessThan).init(testing.allocator, {});
    defer depq.deinit();

    try depq.add(1);
    try depq.add(2);
    try depq.add(3);
    try depq.add(4);
    try depq.add(5);
    try depq.add(6);

    _ = depq.removeIndex(2);
    try expectEqual(all_cmps_unique, true);
}
const std = @import("std.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Order = std.math.Order;
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectError = testing.expectError;

/// Priority queue for storing generic data. Initialize with `init`.
/// Provide `compareFn` that returns `Order.lt` when its second
/// argument should get popped before its third argument,
/// `Order.eq` if the arguments are of equal priority, or `Order.gt`
/// if the third argument should be popped first.
/// For example, to make `pop` return the smallest number, provide
/// `fn lessThan(context: void, a: T, b: T) Order { _ = context; return std.math.order(a, b); }`
pub fn PriorityQueue(comptime T: type, comptime Context: type, comptime compareFn: fn (context: Context, a: T, b: T) Order) type {
    return struct {
        const Self = @This();

        items: []T,
        cap: usize,
        allocator: Allocator,
        context: Context,

        /// Initialize and return a priority queue.
        pub fn init(allocator: Allocator, context: Context) Self {
            return Self{
                .items = &[_]T{},
                .cap = 0,
                .allocator = allocator,
                .context = context,
            };
        }

        /// Free memory used by the queue.
        pub fn deinit(self: Self) void {
            self.allocator.free(self.allocatedSlice());
        }

        /// Insert a new element, maintaining priority.
        pub fn add(self: *Self, elem: T) !void {
            try self.ensureUnusedCapacity(1);
            addUnchecked(self, elem);
        }

        fn addUnchecked(self: *Self, elem: T) void {
            self.items.len += 1;
            self.items[self.items.len - 1] = elem;
            siftUp(self, self.items.len - 1);
        }

        fn siftUp(self: *Self, start_index: usize) void {
            const child = self.items[start_index];
            var child_index = start_index;
            while (child_index > 0) {
                const parent_index = ((child_index - 1) >> 1);
                const parent = self.items[parent_index];
                if (compareFn(self.context, child, parent) != .lt) break;
                self.items[child_index] = parent;
                child_index = parent_index;
            }
            self.items[child_index] = child;
        }

        /// Add each element in `items` to the queue.
        pub fn addSlice(self: *Self, items: []const T) !void {
            try self.ensureUnusedCapacity(items.len);
            for (items) |e| {
                self.addUnchecked(e);
            }
        }

        /// Look at the highest priority element in the queue. Returns
        /// `null` if empty.
        pub fn peek(self: *Self) ?T {
            return if (self.items.len > 0) self.items[0] else null;
        }

        /// Pop the highest priority element from the queue. Returns
        /// `null` if empty.
        pub fn removeOrNull(self: *Self) ?T {
            return if (self.items.len > 0) self.remove() else null;
        }

        /// Remove and return the highest priority element from the
        /// queue.
        pub fn remove(self: *Self) T {
            return self.removeIndex(0);
        }

        /// Remove and return element at index. Indices are in the
        /// same order as iterator, which is not necessarily priority
        /// order.
        pub fn removeIndex(self: *Self, index: usize) T {
            assert(self.items.len > index);
            const last = self.items[self.items.len - 1];
            const item = self.items[index];
            self.items[index] = last;
            self.items.len -= 1;

            if (index == self.items.len) {
                // Last element removed, nothing more to do.
            } else if (index == 0) {
                siftDown(self, index);
            } else {
                const parent_index = ((index - 1) >> 1);
                const parent = self.items[parent_index];
                if (compareFn(self.context, last, parent) == .gt) {
                    siftDown(self, index);
                } else {
                    siftUp(self, index);
                }
            }

            return item;
        }

        /// Return the number of elements remaining in the priority
        /// queue.
        pub fn count(self: Self) usize {
            return self.items.len;
        }

        /// Return the number of elements that can be added to the
        /// queue before more memory is allocated.
        pub fn capacity(self: Self) usize {
            return self.cap;
        }

        /// Returns a slice of all the items plus the extra capacity, whose memory
        /// contents are `undefined`.
        fn allocatedSlice(self: Self) []T {
            // `items.len` is the length, not the capacity.
            return self.items.ptr[0..self.cap];
        }

        fn siftDown(self: *Self, target_index: usize) void {
            const target_element = self.items[target_index];
            var index = target_index;
            while (true) {
                var lesser_child_i = (std.math.mul(usize, index, 2) catch break) | 1;
                if (!(lesser_child_i < self.items.len)) break;

                const next_child_i = lesser_child_i + 1;
                if (next_child_i < self.items.len and compareFn(self.context, self.items[next_child_i], self.items[lesser_child_i]) == .lt) {
                    lesser_child_i = next_child_i;
                }

                if (compareFn(self.context, target_element, self.items[lesser_child_i]) == .lt) break;

                self.items[index] = self.items[lesser_child_i];
                index = lesser_child_i;
            }
            self.items[index] = target_element;
        }

        /// PriorityQueue takes ownership of the passed in slice. The slice must have been
        /// allocated with `allocator`.
        /// Deinitialize with `deinit`.
        pub fn fromOwnedSlice(allocator: Allocator, items: []T, context: Context) Self {
            var self = Self{
                .items = items,
                .cap = items.len,
                .allocator = allocator,
                .context = context,
            };

            var i = self.items.len >> 1;
            while (i > 0) {
                i -= 1;
                self.siftDown(i);
            }
            return self;
        }

        /// Ensure that the queue can fit at least `new_capacity` items.
        pub fn ensureTotalCapacity(self: *Self, new_capacity: usize) !void {
            var better_capacity = self.cap;
            if (better_capacity >= new_capacity) return;
            while (true) {
                better_capacity += better_capacity / 2 + 8;
                if (better_capacity >= new_capacity) break;
            }
            try self.ensureTotalCapacityPrecise(better_capacity);
        }

        pub fn ensureTotalCapacityPrecise(self: *Self, new_capacity: usize) !void {
            if (self.capacity() >= new_capacity) return;

            const old_memory = self.allocatedSlice();
            const new_memory = try self.allocator.realloc(old_memory, new_capacity);
            self.items.ptr = new_memory.ptr;
            self.cap = new_memory.len;
        }

        /// Ensure that the queue can fit at least `additional_count` **more** item.
        pub fn ensureUnusedCapacity(self: *Self, additional_count: usize) !void {
            return self.ensureTotalCapacity(self.items.len + additional_count);
        }

        /// Reduce allocated capacity to `new_capacity`.
        pub fn shrinkAndFree(self: *Self, new_capacity: usize) void {
            assert(new_capacity <= self.cap);

            // Cannot shrink to smaller than the current queue size without invalidating the heap property
            assert(new_capacity >= self.items.len);

            const old_memory = self.allocatedSlice();
            const new_memory = self.allocator.realloc(old_memory, new_capacity) catch |e| switch (e) {
                error.OutOfMemory => { // no problem, capacity is still correct then.
                    return;
                },
            };

            self.items.ptr = new_memory.ptr;
            self.cap = new_memory.len;
        }

        pub fn clearRetainingCapacity(self: *Self) void {
            self.items.len = 0;
        }

        pub fn clearAndFree(self: *Self) void {
            self.allocator.free(self.allocatedSlice());
            self.items.len = 0;
            self.cap = 0;
        }

        pub fn update(self: *Self, elem: T, new_elem: T) !void {
            const update_index = blk: {
                var idx: usize = 0;
                while (idx < self.items.len) : (idx += 1) {
                    const item = self.items[idx];
                    if (compareFn(self.context, item, elem) == .eq) break :blk idx;
                }
                return error.ElementNotFound;
            };
            const old_elem: T = self.items[update_index];
            self.items[update_index] = new_elem;
            switch (compareFn(self.context, new_elem, old_elem)) {
                .lt => siftUp(self, update_index),
                .gt => siftDown(self, update_index),
                .eq => {}, // Nothing to do as the items have equal priority
            }
        }

        pub const Iterator = struct {
            queue: *PriorityQueue(T, Context, compareFn),
            count: usize,

            pub fn next(it: *Iterator) ?T {
                if (it.count >= it.queue.items.len) return null;
                const out = it.count;
                it.count += 1;
                return it.queue.items[out];
            }

            pub fn reset(it: *Iterator) void {
                it.count = 0;
            }
        };

        /// Return an iterator that walks the queue without consuming
        /// it. The iteration order may differ from the priority order.
        /// Invalidated if the heap is modified.
        pub fn iterator(self: *Self) Iterator {
            return Iterator{
                .queue = self,
                .count = 0,
            };
        }

        fn dump(self: *Self) void {
            const print = std.debug.print;
            print("{{ ", .{});
            print("items: ", .{});
            for (self.items) |e| {
                print("{}, ", .{e});
            }
            print("array: ", .{});
            for (self.items) |e| {
                print("{}, ", .{e});
            }
            print("len: {} ", .{self.items.len});
            print("capacity: {}", .{self.cap});
            print(" }}\n", .{});
        }
    };
}

fn lessThan(context: void, a: u32, b: u32) Order {
    _ = context;
    return std.math.order(a, b);
}

fn greaterThan(context: void, a: u32, b: u32) Order {
    return lessThan(context, a, b).invert();
}

const PQlt = PriorityQueue(u32, void, lessThan);
const PQgt = PriorityQueue(u32, void, greaterThan);

test "add and remove min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(54);
    try queue.add(12);
    try queue.add(7);
    try queue.add(23);
    try queue.add(25);
    try queue.add(13);
    try expectEqual(@as(u32, 7), queue.remove());
    try expectEqual(@as(u32, 12), queue.remove());
    try expectEqual(@as(u32, 13), queue.remove());
    try expectEqual(@as(u32, 23), queue.remove());
    try expectEqual(@as(u32, 25), queue.remove());
    try expectEqual(@as(u32, 54), queue.remove());
}

test "add and remove same min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.add(1);
    try queue.add(1);
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 2), queue.remove());
    try expectEqual(@as(u32, 2), queue.remove());
}

test "removeOrNull on empty" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try expect(queue.removeOrNull() == null);
}

test "edge case 3 elements" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(9);
    try queue.add(3);
    try queue.add(2);
    try expectEqual(@as(u32, 2), queue.remove());
    try expectEqual(@as(u32, 3), queue.remove());
    try expectEqual(@as(u32, 9), queue.remove());
}

test "peek" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try expect(queue.peek() == null);
    try queue.add(9);
    try queue.add(3);
    try queue.add(2);
    try expectEqual(@as(u32, 2), queue.peek().?);
    try expectEqual(@as(u32, 2), queue.peek().?);
}

test "sift up with odd indices" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    for (items) |e| {
        try queue.add(e);
    }

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.remove());
    }
}

test "addSlice" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    try queue.addSlice(items[0..]);

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.remove());
    }
}

test "fromOwnedSlice trivial case 0" {
    const items = [0]u32{};
    const queue_items = try testing.allocator.dupe(u32, &items);
    var queue = PQlt.fromOwnedSlice(testing.allocator, queue_items[0..], {});
    defer queue.deinit();
    try expectEqual(@as(usize, 0), queue.count());
    try expect(queue.removeOrNull() == null);
}

test "fromOwnedSlice trivial case 1" {
    const items = [1]u32{1};
    const queue_items = try testing.allocator.dupe(u32, &items);
    var queue = PQlt.fromOwnedSlice(testing.allocator, queue_items[0..], {});
    defer queue.deinit();

    try expectEqual(@as(usize, 1), queue.count());
    try expectEqual(items[0], queue.remove());
    try expect(queue.removeOrNull() == null);
}

test "fromOwnedSlice" {
    const items = [_]u32{ 15, 7, 21, 14, 13, 22, 12, 6, 7, 25, 5, 24, 11, 16, 15, 24, 2, 1 };
    const heap_items = try testing.allocator.dupe(u32, items[0..]);
    var queue = PQlt.fromOwnedSlice(testing.allocator, heap_items[0..], {});
    defer queue.deinit();

    const sorted_items = [_]u32{ 1, 2, 5, 6, 7, 7, 11, 12, 13, 14, 15, 15, 16, 21, 22, 24, 24, 25 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.remove());
    }
}

test "add and remove max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(54);
    try queue.add(12);
    try queue.add(7);
    try queue.add(23);
    try queue.add(25);
    try queue.add(13);
    try expectEqual(@as(u32, 54), queue.remove());
    try expectEqual(@as(u32, 25), queue.remove());
    try expectEqual(@as(u32, 23), queue.remove());
    try expectEqual(@as(u32, 13), queue.remove());
    try expectEqual(@as(u32, 12), queue.remove());
    try expectEqual(@as(u32, 7), queue.remove());
}

test "add and remove same max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.add(1);
    try queue.add(1);
    try expectEqual(@as(u32, 2), queue.remove());
    try expectEqual(@as(u32, 2), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
}

test "iterator" {
    var queue = PQlt.init(testing.allocator, {});
    var map = std.AutoHashMap(u32, void).init(testing.allocator);
    defer {
        queue.deinit();
        map.deinit();
    }

    const items = [_]u32{ 54, 12, 7, 23, 25, 13 };
    for (items) |e| {
        _ = try queue.add(e);
        try map.put(e, {});
    }

    var it = queue.iterator();
    while (it.next()) |e| {
        _ = map.remove(e);
    }

    try expectEqual(@as(usize, 0), map.count());
}

test "remove at index" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    const items = [_]u32{ 2, 1, 8, 9, 3, 4, 5 };
    for (items) |e| {
        _ = try queue.add(e);
    }

    var it = queue.iterator();
    var idx: usize = 0;
    const two_idx = while (it.next()) |elem| {
        if (elem == 2)
            break idx;
        idx += 1;
    } else unreachable;
    const sorted_items = [_]u32{ 1, 3, 4, 5, 8, 9 };
    try expectEqual(queue.removeIndex(two_idx), 2);

    var i: usize = 0;
    while (queue.removeOrNull()) |n| : (i += 1) {
        try expectEqual(n, sorted_items[i]);
    }
    try expectEqual(queue.removeOrNull(), null);
}

test "iterator while empty" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    var it = queue.iterator();

    try expectEqual(it.next(), null);
}

test "shrinkAndFree" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.ensureTotalCapacity(4);
    try expect(queue.capacity() >= 4);

    try queue.add(1);
    try queue.add(2);
    try queue.add(3);
    try expect(queue.capacity() >= 4);
    try expectEqual(@as(usize, 3), queue.count());

    queue.shrinkAndFree(3);
    try expectEqual(@as(usize, 3), queue.capacity());
    try expectEqual(@as(usize, 3), queue.count());

    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 2), queue.remove());
    try expectEqual(@as(u32, 3), queue.remove());
    try expect(queue.removeOrNull() == null);
}

test "update min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(55);
    try queue.add(44);
    try queue.add(11);
    try queue.update(55, 5);
    try queue.update(44, 4);
    try queue.update(11, 1);
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 4), queue.remove());
    try expectEqual(@as(u32, 5), queue.remove());
}

test "update same min heap" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.update(1, 5);
    try queue.update(2, 4);
    try expectEqual(@as(u32, 1), queue.remove());
    try expectEqual(@as(u32, 2), queue.remove());
    try expectEqual(@as(u32, 4), queue.remove());
    try expectEqual(@as(u32, 5), queue.remove());
}

test "update max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(55);
    try queue.add(44);
    try queue.add(11);
    try queue.update(55, 5);
    try queue.update(44, 1);
    try queue.update(11, 4);
    try expectEqual(@as(u32, 5), queue.remove());
    try expectEqual(@as(u32, 4), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
}

test "update same max heap" {
    var queue = PQgt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try queue.add(1);
    try queue.add(2);
    try queue.add(2);
    try queue.update(1, 5);
    try queue.update(2, 4);
    try expectEqual(@as(u32, 5), queue.remove());
    try expectEqual(@as(u32, 4), queue.remove());
    try expectEqual(@as(u32, 2), queue.remove());
    try expectEqual(@as(u32, 1), queue.remove());
}

test "update after remove" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.add(1);
    try expectEqual(@as(u32, 1), queue.remove());
    try expectError(error.ElementNotFound, queue.update(1, 1));
}

test "siftUp in remove" {
    var queue = PQlt.init(testing.allocator, {});
    defer queue.deinit();

    try queue.addSlice(&.{ 0, 1, 100, 2, 3, 101, 102, 4, 5, 6, 7, 103, 104, 105, 106, 8 });

    _ = queue.removeIndex(std.mem.indexOfScalar(u32, queue.items[0..queue.count()], 102).?);

    const sorted_items = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 100, 101, 103, 104, 105, 106 };
    for (sorted_items) |e| {
        try expectEqual(e, queue.remove());
    }
}

fn contextLessThan(context: []const u32, a: usize, b: usize) Order {
    return std.math.order(context[a], context[b]);
}

const CPQlt = PriorityQueue(usize, []const u32, contextLessThan);

test "add and remove min heap with context comparator" {
    const context = [_]u32{ 5, 3, 4, 2, 2, 8, 0 };

    var queue = CPQlt.init(testing.allocator, context[0..]);
    defer queue.deinit();

    try queue.add(0);
    try queue.add(1);
    try queue.add(2);
    try queue.add(3);
    try queue.add(4);
    try queue.add(5);
    try queue.add(6);
    try expectEqual(@as(usize, 6), queue.remove());
    try expectEqual(@as(usize, 4), queue.remove());
    try expectEqual(@as(usize, 3), queue.remove());
    try expectEqual(@as(usize, 1), queue.remove());
    try expectEqual(@as(usize, 2), queue.remove());
    try expectEqual(@as(usize, 0), queue.remove());
    try expectEqual(@as(usize, 5), queue.remove());
}
const std = @import("std.zig");
const builtin = @import("builtin");
const fs = std.fs;
const mem = std.mem;
const math = std.math;
const Allocator = mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;
const native_os = builtin.os.tag;
const posix = std.posix;
const windows = std.os.windows;
const unicode = std.unicode;

pub const Child = @import("process/Child.zig");
pub const abort = posix.abort;
pub const exit = posix.exit;
pub const changeCurDir = posix.chdir;
pub const changeCurDirZ = posix.chdirZ;

pub const GetCwdError = posix.GetCwdError;

/// The result is a slice of `out_buffer`, from index `0`.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn getCwd(out_buffer: []u8) ![]u8 {
    return posix.getcwd(out_buffer);
}

pub const GetCwdAllocError = Allocator.Error || posix.GetCwdError;

/// Caller must free the returned memory.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn getCwdAlloc(allocator: Allocator) ![]u8 {
    // The use of max_path_bytes here is just a heuristic: most paths will fit
    // in stack_buf, avoiding an extra allocation in the common case.
    var stack_buf: [fs.max_path_bytes]u8 = undefined;
    var heap_buf: ?[]u8 = null;
    defer if (heap_buf) |buf| allocator.free(buf);

    var current_buf: []u8 = &stack_buf;
    while (true) {
        if (posix.getcwd(current_buf)) |slice| {
            return allocator.dupe(u8, slice);
        } else |err| switch (err) {
            error.NameTooLong => {
                // The path is too long to fit in stack_buf. Allocate geometrically
                // increasing buffers until we find one that works
                const new_capacity = current_buf.len * 2;
                if (heap_buf) |buf| allocator.free(buf);
                current_buf = try allocator.alloc(u8, new_capacity);
                heap_buf = current_buf;
            },
            else => |e| return e,
        }
    }
}

test getCwdAlloc {
    if (native_os == .wasi) return error.SkipZigTest;

    const cwd = try getCwdAlloc(testing.allocator);
    testing.allocator.free(cwd);
}

pub const EnvMap = struct {
    hash_map: HashMap,

    const HashMap = std.HashMap(
        []const u8,
        []const u8,
        EnvNameHashContext,
        std.hash_map.default_max_load_percentage,
    );

    pub const Size = HashMap.Size;

    pub const EnvNameHashContext = struct {
        fn upcase(c: u21) u21 {
            if (c <= std.math.maxInt(u16))
                return windows.ntdll.RtlUpcaseUnicodeChar(@as(u16, @intCast(c)));
            return c;
        }

        pub fn hash(self: @This(), s: []const u8) u64 {
            _ = self;
            if (native_os == .windows) {
                var h = std.hash.Wyhash.init(0);
                var it = unicode.Wtf8View.initUnchecked(s).iterator();
                while (it.nextCodepoint()) |cp| {
                    const cp_upper = upcase(cp);
                    h.update(&[_]u8{
                        @as(u8, @intCast((cp_upper >> 16) & 0xff)),
                        @as(u8, @intCast((cp_upper >> 8) & 0xff)),
                        @as(u8, @intCast((cp_upper >> 0) & 0xff)),
                    });
                }
                return h.final();
            }
            return std.hash_map.hashString(s);
        }

        pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
            _ = self;
            if (native_os == .windows) {
                var it_a = unicode.Wtf8View.initUnchecked(a).iterator();
                var it_b = unicode.Wtf8View.initUnchecked(b).iterator();
                while (true) {
                    const c_a = it_a.nextCodepoint() orelse break;
                    const c_b = it_b.nextCodepoint() orelse return false;
                    if (upcase(c_a) != upcase(c_b))
                        return false;
                }
                return if (it_b.nextCodepoint()) |_| false else true;
            }
            return std.hash_map.eqlString(a, b);
        }
    };

    /// Create a EnvMap backed by a specific allocator.
    /// That allocator will be used for both backing allocations
    /// and string deduplication.
    pub fn init(allocator: Allocator) EnvMap {
        return EnvMap{ .hash_map = HashMap.init(allocator) };
    }

    /// Free the backing storage of the map, as well as all
    /// of the stored keys and values.
    pub fn deinit(self: *EnvMap) void {
        var it = self.hash_map.iterator();
        while (it.next()) |entry| {
            self.free(entry.key_ptr.*);
            self.free(entry.value_ptr.*);
        }

        self.hash_map.deinit();
    }

    /// Same as `put` but the key and value become owned by the EnvMap rather
    /// than being copied.
    /// If `putMove` fails, the ownership of key and value does not transfer.
    /// On Windows `key` must be a valid [WTF-8](https://simonsapin.github.io/wtf-8/) string.
    pub fn putMove(self: *EnvMap, key: []u8, value: []u8) !void {
        assert(unicode.wtf8ValidateSlice(key));
        const get_or_put = try self.hash_map.getOrPut(key);
        if (get_or_put.found_existing) {
            self.free(get_or_put.key_ptr.*);
            self.free(get_or_put.value_ptr.*);
            get_or_put.key_ptr.* = key;
        }
        get_or_put.value_ptr.* = value;
    }

    /// `key` and `value` are copied into the EnvMap.
    /// On Windows `key` must be a valid [WTF-8](https://simonsapin.github.io/wtf-8/) string.
    pub fn put(self: *EnvMap, key: []const u8, value: []const u8) !void {
        assert(unicode.wtf8ValidateSlice(key));
        const value_copy = try self.copy(value);
        errdefer self.free(value_copy);
        const get_or_put = try self.hash_map.getOrPut(key);
        if (get_or_put.found_existing) {
            self.free(get_or_put.value_ptr.*);
        } else {
            get_or_put.key_ptr.* = self.copy(key) catch |err| {
                _ = self.hash_map.remove(key);
                return err;
            };
        }
        get_or_put.value_ptr.* = value_copy;
    }

    /// Find the address of the value associated with a key.
    /// The returned pointer is invalidated if the map resizes.
    /// On Windows `key` must be a valid [WTF-8](https://simonsapin.github.io/wtf-8/) string.
    pub fn getPtr(self: EnvMap, key: []const u8) ?*[]const u8 {
        assert(unicode.wtf8ValidateSlice(key));
        return self.hash_map.getPtr(key);
    }

    /// Return the map's copy of the value associated with
    /// a key.  The returned string is invalidated if this
    /// key is removed from the map.
    /// On Windows `key` must be a valid [WTF-8](https://simonsapin.github.io/wtf-8/) string.
    pub fn get(self: EnvMap, key: []const u8) ?[]const u8 {
        assert(unicode.wtf8ValidateSlice(key));
        return self.hash_map.get(key);
    }

    /// Removes the item from the map and frees its value.
    /// This invalidates the value returned by get() for this key.
    /// On Windows `key` must be a valid [WTF-8](https://simonsapin.github.io/wtf-8/) string.
    pub fn remove(self: *EnvMap, key: []const u8) void {
        assert(unicode.wtf8ValidateSlice(key));
        const kv = self.hash_map.fetchRemove(key) orelse return;
        self.free(kv.key);
        self.free(kv.value);
    }

    /// Returns the number of KV pairs stored in the map.
    pub fn count(self: EnvMap) HashMap.Size {
        return self.hash_map.count();
    }

    /// Returns an iterator over entries in the map.
    pub fn iterator(self: *const EnvMap) HashMap.Iterator {
        return self.hash_map.iterator();
    }

    fn free(self: EnvMap, value: []const u8) void {
        self.hash_map.allocator.free(value);
    }

    fn copy(self: EnvMap, value: []const u8) ![]u8 {
        return self.hash_map.allocator.dupe(u8, value);
    }
};

test EnvMap {
    var env = EnvMap.init(testing.allocator);
    defer env.deinit();

    try env.put("SOMETHING_NEW", "hello");
    try testing.expectEqualStrings("hello", env.get("SOMETHING_NEW").?);
    try testing.expectEqual(@as(EnvMap.Size, 1), env.count());

    // overwrite
    try env.put("SOMETHING_NEW", "something");
    try testing.expectEqualStrings("something", env.get("SOMETHING_NEW").?);
    try testing.expectEqual(@as(EnvMap.Size, 1), env.count());

    // a new longer name to test the Windows-specific conversion buffer
    try env.put("SOMETHING_NEW_AND_LONGER", "1");
    try testing.expectEqualStrings("1", env.get("SOMETHING_NEW_AND_LONGER").?);
    try testing.expectEqual(@as(EnvMap.Size, 2), env.count());

    // case insensitivity on Windows only
    if (native_os == .windows) {
        try testing.expectEqualStrings("1", env.get("something_New_aNd_LONGER").?);
    } else {
        try testing.expect(null == env.get("something_New_aNd_LONGER"));
    }

    var it = env.iterator();
    var count: EnvMap.Size = 0;
    while (it.next()) |entry| {
        const is_an_expected_name = std.mem.eql(u8, "SOMETHING_NEW", entry.key_ptr.*) or std.mem.eql(u8, "SOMETHING_NEW_AND_LONGER", entry.key_ptr.*);
        try testing.expect(is_an_expected_name);
        count += 1;
    }
    try testing.expectEqual(@as(EnvMap.Size, 2), count);

    env.remove("SOMETHING_NEW");
    try testing.expect(env.get("SOMETHING_NEW") == null);

    try testing.expectEqual(@as(EnvMap.Size, 1), env.count());

    if (native_os == .windows) {
        // test Unicode case-insensitivity on Windows
        try env.put("КИРиллИЦА", "something else");
        try testing.expectEqualStrings("something else", env.get("кириллица").?);

        // and WTF-8 that's not valid UTF-8
        const wtf8_with_surrogate_pair = try unicode.wtf16LeToWtf8Alloc(testing.allocator, &[_]u16{
            std.mem.nativeToLittle(u16, 0xD83D), // unpaired high surrogate
        });
        defer testing.allocator.free(wtf8_with_surrogate_pair);

        try env.put(wtf8_with_surrogate_pair, wtf8_with_surrogate_pair);
        try testing.expectEqualSlices(u8, wtf8_with_surrogate_pair, env.get(wtf8_with_surrogate_pair).?);
    }
}

pub const GetEnvMapError = error{
    OutOfMemory,
    /// WASI-only. `environ_sizes_get` or `environ_get`
    /// failed for an unexpected reason.
    Unexpected,
};

/// Returns a snapshot of the environment variables of the current process.
/// Any modifications to the resulting EnvMap will not be reflected in the environment, and
/// likewise, any future modifications to the environment will not be reflected in the EnvMap.
/// Caller owns resulting `EnvMap` and should call its `deinit` fn when done.
pub fn getEnvMap(allocator: Allocator) GetEnvMapError!EnvMap {
    var result = EnvMap.init(allocator);
    errdefer result.deinit();

    if (native_os == .windows) {
        const ptr = windows.peb().ProcessParameters.Environment;

        var i: usize = 0;
        while (ptr[i] != 0) {
            const key_start = i;

            // There are some special environment variables that start with =,
            // so we need a special case to not treat = as a key/value separator
            // if it's the first character.
            // https://devblogs.microsoft.com/oldnewthing/20100506-00/?p=14133
            if (ptr[key_start] == '=') i += 1;

            while (ptr[i] != 0 and ptr[i] != '=') : (i += 1) {}
            const key_w = ptr[key_start..i];
            const key = try unicode.wtf16LeToWtf8Alloc(allocator, key_w);
            errdefer allocator.free(key);

            if (ptr[i] == '=') i += 1;

            const value_start = i;
            while (ptr[i] != 0) : (i += 1) {}
            const value_w = ptr[value_start..i];
            const value = try unicode.wtf16LeToWtf8Alloc(allocator, value_w);
            errdefer allocator.free(value);

            i += 1; // skip over null byte

            try result.putMove(key, value);
        }
        return result;
    } else if (native_os == .wasi and !builtin.link_libc) {
        var environ_count: usize = undefined;
        var environ_buf_size: usize = undefined;

        const environ_sizes_get_ret = std.os.wasi.environ_sizes_get(&environ_count, &environ_buf_size);
        if (environ_sizes_get_ret != .SUCCESS) {
            return posix.unexpectedErrno(environ_sizes_get_ret);
        }

        if (environ_count == 0) {
            return result;
        }

        const environ = try allocator.alloc([*:0]u8, environ_count);
        defer allocator.free(environ);
        const environ_buf = try allocator.alloc(u8, environ_buf_size);
        defer allocator.free(environ_buf);

        const environ_get_ret = std.os.wasi.environ_get(environ.ptr, environ_buf.ptr);
        if (environ_get_ret != .SUCCESS) {
            return posix.unexpectedErrno(environ_get_ret);
        }

        for (environ) |env| {
            const pair = mem.sliceTo(env, 0);
            var parts = mem.splitScalar(u8, pair, '=');
            const key = parts.first();
            const value = parts.rest();
            try result.put(key, value);
        }
        return result;
    } else if (builtin.link_libc) {
        var ptr = std.c.environ;
        while (ptr[0]) |line| : (ptr += 1) {
            var line_i: usize = 0;
            while (line[line_i] != 0 and line[line_i] != '=') : (line_i += 1) {}
            const key = line[0..line_i];

            var end_i: usize = line_i;
            while (line[end_i] != 0) : (end_i += 1) {}
            const value = line[line_i + 1 .. end_i];

            try result.put(key, value);
        }
        return result;
    } else {
        for (std.os.environ) |line| {
            var line_i: usize = 0;
            while (line[line_i] != 0 and line[line_i] != '=') : (line_i += 1) {}
            const key = line[0..line_i];

            var end_i: usize = line_i;
            while (line[end_i] != 0) : (end_i += 1) {}
            const value = line[line_i + 1 .. end_i];

            try result.put(key, value);
        }
        return result;
    }
}

test getEnvMap {
    var env = try getEnvMap(testing.allocator);
    defer env.deinit();
}

pub const GetEnvVarOwnedError = error{
    OutOfMemory,
    EnvironmentVariableNotFound,

    /// On Windows, environment variable keys provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
};

/// Caller must free returned memory.
/// On Windows, if `key` is not valid [WTF-8](https://simonsapin.github.io/wtf-8/),
/// then `error.InvalidWtf8` is returned.
/// On Windows, the value is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the value is an opaque sequence of bytes with no particular encoding.
pub fn getEnvVarOwned(allocator: Allocator, key: []const u8) GetEnvVarOwnedError![]u8 {
    if (native_os == .windows) {
        const result_w = blk: {
            var stack_alloc = std.heap.stackFallback(256 * @sizeOf(u16), allocator);
            const stack_allocator = stack_alloc.get();
            const key_w = try unicode.wtf8ToWtf16LeAllocZ(stack_allocator, key);
            defer stack_allocator.free(key_w);

            break :blk getenvW(key_w) orelse return error.EnvironmentVariableNotFound;
        };
        // wtf16LeToWtf8Alloc can only fail with OutOfMemory
        return unicode.wtf16LeToWtf8Alloc(allocator, result_w);
    } else if (native_os == .wasi and !builtin.link_libc) {
        var envmap = getEnvMap(allocator) catch return error.OutOfMemory;
        defer envmap.deinit();
        const val = envmap.get(key) orelse return error.EnvironmentVariableNotFound;
        return allocator.dupe(u8, val);
    } else {
        const result = posix.getenv(key) orelse return error.EnvironmentVariableNotFound;
        return allocator.dupe(u8, result);
    }
}

/// On Windows, `key` must be valid WTF-8.
pub fn hasEnvVarConstant(comptime key: []const u8) bool {
    if (native_os == .windows) {
        const key_w = comptime unicode.wtf8ToWtf16LeStringLiteral(key);
        return getenvW(key_w) != null;
    } else if (native_os == .wasi and !builtin.link_libc) {
        @compileError("hasEnvVarConstant is not supported for WASI without libc");
    } else {
        return posix.getenv(key) != null;
    }
}

/// On Windows, `key` must be valid WTF-8.
pub fn hasNonEmptyEnvVarConstant(comptime key: []const u8) bool {
    if (native_os == .windows) {
        const key_w = comptime unicode.wtf8ToWtf16LeStringLiteral(key);
        const value = getenvW(key_w) orelse return false;
        return value.len != 0;
    } else if (native_os == .wasi and !builtin.link_libc) {
        @compileError("hasNonEmptyEnvVarConstant is not supported for WASI without libc");
    } else {
        const value = posix.getenv(key) orelse return false;
        return value.len != 0;
    }
}

pub const ParseEnvVarIntError = std.fmt.ParseIntError || error{EnvironmentVariableNotFound};

/// Parses an environment variable as an integer.
///
/// Since the key is comptime-known, no allocation is needed.
///
/// On Windows, `key` must be valid WTF-8.
pub fn parseEnvVarInt(comptime key: []const u8, comptime I: type, base: u8) ParseEnvVarIntError!I {
    if (native_os == .windows) {
        const key_w = comptime std.unicode.wtf8ToWtf16LeStringLiteral(key);
        const text = getenvW(key_w) orelse return error.EnvironmentVariableNotFound;
        return std.fmt.parseIntWithGenericCharacter(I, u16, text, base);
    } else if (native_os == .wasi and !builtin.link_libc) {
        @compileError("parseEnvVarInt is not supported for WASI without libc");
    } else {
        const text = posix.getenv(key) orelse return error.EnvironmentVariableNotFound;
        return std.fmt.parseInt(I, text, base);
    }
}

pub const HasEnvVarError = error{
    OutOfMemory,

    /// On Windows, environment variable keys provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
};

/// On Windows, if `key` is not valid [WTF-8](https://simonsapin.github.io/wtf-8/),
/// then `error.InvalidWtf8` is returned.
pub fn hasEnvVar(allocator: Allocator, key: []const u8) HasEnvVarError!bool {
    if (native_os == .windows) {
        var stack_alloc = std.heap.stackFallback(256 * @sizeOf(u16), allocator);
        const stack_allocator = stack_alloc.get();
        const key_w = try unicode.wtf8ToWtf16LeAllocZ(stack_allocator, key);
        defer stack_allocator.free(key_w);
        return getenvW(key_w) != null;
    } else if (native_os == .wasi and !builtin.link_libc) {
        var envmap = getEnvMap(allocator) catch return error.OutOfMemory;
        defer envmap.deinit();
        return envmap.getPtr(key) != null;
    } else {
        return posix.getenv(key) != null;
    }
}

/// On Windows, if `key` is not valid [WTF-8](https://simonsapin.github.io/wtf-8/),
/// then `error.InvalidWtf8` is returned.
pub fn hasNonEmptyEnvVar(allocator: Allocator, key: []const u8) HasEnvVarError!bool {
    if (native_os == .windows) {
        var stack_alloc = std.heap.stackFallback(256 * @sizeOf(u16), allocator);
        const stack_allocator = stack_alloc.get();
        const key_w = try unicode.wtf8ToWtf16LeAllocZ(stack_allocator, key);
        defer stack_allocator.free(key_w);
        const value = getenvW(key_w) orelse return false;
        return value.len != 0;
    } else if (native_os == .wasi and !builtin.link_libc) {
        var envmap = getEnvMap(allocator) catch return error.OutOfMemory;
        defer envmap.deinit();
        const value = envmap.getPtr(key) orelse return false;
        return value.len != 0;
    } else {
        const value = posix.getenv(key) orelse return false;
        return value.len != 0;
    }
}

/// Windows-only. Get an environment variable with a null-terminated, WTF-16 encoded name.
///
/// This function performs a Unicode-aware case-insensitive lookup using RtlEqualUnicodeString.
///
/// See also:
/// * `std.posix.getenv`
/// * `getEnvMap`
/// * `getEnvVarOwned`
/// * `hasEnvVarConstant`
/// * `hasEnvVar`
pub fn getenvW(key: [*:0]const u16) ?[:0]const u16 {
    if (native_os != .windows) {
        @compileError("Windows-only");
    }
    const key_slice = mem.sliceTo(key, 0);
    // '=' anywhere but the start makes this an invalid environment variable name
    if (key_slice.len > 0 and std.mem.indexOfScalar(u16, key_slice[1..], '=') != null) {
        return null;
    }
    const ptr = windows.peb().ProcessParameters.Environment;
    var i: usize = 0;
    while (ptr[i] != 0) {
        const key_value = mem.sliceTo(ptr[i..], 0);

        // There are some special environment variables that start with =,
        // so we need a special case to not treat = as a key/value separator
        // if it's the first character.
        // https://devblogs.microsoft.com/oldnewthing/20100506-00/?p=14133
        const equal_search_start: usize = if (key_value[0] == '=') 1 else 0;
        const equal_index = std.mem.indexOfScalarPos(u16, key_value, equal_search_start, '=') orelse {
            // This is enforced by CreateProcess.
            // If violated, CreateProcess will fail with INVALID_PARAMETER.
            unreachable; // must contain a =
        };

        const this_key = key_value[0..equal_index];
        if (windows.eqlIgnoreCaseWTF16(key_slice, this_key)) {
            return key_value[equal_index + 1 ..];
        }

        // skip past the NUL terminator
        i += key_value.len + 1;
    }
    return null;
}

test getEnvVarOwned {
    try testing.expectError(
        error.EnvironmentVariableNotFound,
        getEnvVarOwned(std.testing.allocator, "BADENV"),
    );
}

test hasEnvVarConstant {
    if (native_os == .wasi and !builtin.link_libc) return error.SkipZigTest;

    try testing.expect(!hasEnvVarConstant("BADENV"));
}

test hasEnvVar {
    const has_env = try hasEnvVar(std.testing.allocator, "BADENV");
    try testing.expect(!has_env);
}

pub const ArgIteratorPosix = struct {
    index: usize,
    count: usize,

    pub const InitError = error{};

    pub fn init() ArgIteratorPosix {
        return ArgIteratorPosix{
            .index = 0,
            .count = std.os.argv.len,
        };
    }

    pub fn next(self: *ArgIteratorPosix) ?[:0]const u8 {
        if (self.index == self.count) return null;

        const s = std.os.argv[self.index];
        self.index += 1;
        return mem.sliceTo(s, 0);
    }

    pub fn skip(self: *ArgIteratorPosix) bool {
        if (self.index == self.count) return false;

        self.index += 1;
        return true;
    }
};

pub const ArgIteratorWasi = struct {
    allocator: Allocator,
    index: usize,
    args: [][:0]u8,

    pub const InitError = error{OutOfMemory} || posix.UnexpectedError;

    /// You must call deinit to free the internal buffer of the
    /// iterator after you are done.
    pub fn init(allocator: Allocator) InitError!ArgIteratorWasi {
        const fetched_args = try ArgIteratorWasi.internalInit(allocator);
        return ArgIteratorWasi{
            .allocator = allocator,
            .index = 0,
            .args = fetched_args,
        };
    }

    fn internalInit(allocator: Allocator) InitError![][:0]u8 {
        var count: usize = undefined;
        var buf_size: usize = undefined;

        switch (std.os.wasi.args_sizes_get(&count, &buf_size)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }

        if (count == 0) {
            return &[_][:0]u8{};
        }

        const argv = try allocator.alloc([*:0]u8, count);
        defer allocator.free(argv);

        const argv_buf = try allocator.alloc(u8, buf_size);

        switch (std.os.wasi.args_get(arg```
