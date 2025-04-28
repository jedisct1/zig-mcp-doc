```
ch every other architecture it points to the stack
        // slot where the previous frame pointer is saved.
        2 * @sizeOf(usize)
    else if (native_arch.isSPARC())
        // On SPARC the previous frame pointer is stored at 14 slots past %fp+BIAS.
        14 * @sizeOf(usize)
    else
        0;

    const fp_bias = if (native_arch.isSPARC())
        // On SPARC frame pointers are biased by a constant.
        2047
    else
        0;

    // Positive offset of the saved PC wrt the frame pointer.
    const pc_offset = if (native_arch == .powerpc64le)
        2 * @sizeOf(usize)
    else
        @sizeOf(usize);

    pub fn next(it: *StackIterator) ?usize {
        var address = it.next_internal() orelse return null;

        if (it.first_address) |first_address| {
            while (address != first_address) {
                address = it.next_internal() orelse return null;
            }
            it.first_address = null;
        }

        return address;
    }

    fn next_unwind(it: *StackIterator) !usize {
        const unwind_state = &it.unwind_state.?;
        const module = try unwind_state.debug_info.getModuleForAddress(unwind_state.dwarf_context.pc);
        switch (native_os) {
            .macos, .ios, .watchos, .tvos, .visionos => {
                // __unwind_info is a requirement for unwinding on Darwin. It may fall back to DWARF, but unwinding
                // via DWARF before attempting to use the compact unwind info will produce incorrect results.
                if (module.unwind_info) |unwind_info| {
                    if (SelfInfo.unwindFrameMachO(
                        unwind_state.debug_info.allocator,
                        module.base_address,
                        &unwind_state.dwarf_context,
                        &it.ma,
                        unwind_info,
                        module.eh_frame,
                    )) |return_address| {
                        return return_address;
                    } else |err| {
                        if (err != error.RequiresDWARFUnwind) return err;
                    }
                } else return error.MissingUnwindInfo;
            },
            else => {},
        }

        if (try module.getDwarfInfoForAddress(unwind_state.debug_info.allocator, unwind_state.dwarf_context.pc)) |di| {
            return SelfInfo.unwindFrameDwarf(
                unwind_state.debug_info.allocator,
                di,
                module.base_address,
                &unwind_state.dwarf_context,
                &it.ma,
                null,
            );
        } else return error.MissingDebugInfo;
    }

    fn next_internal(it: *StackIterator) ?usize {
        if (have_ucontext) {
            if (it.unwind_state) |*unwind_state| {
                if (!unwind_state.failed) {
                    if (unwind_state.dwarf_context.pc == 0) return null;
                    defer it.fp = unwind_state.dwarf_context.getFp() catch 0;
                    if (it.next_unwind()) |return_address| {
                        return return_address;
                    } else |err| {
                        unwind_state.last_error = err;
                        unwind_state.failed = true;

                        // Fall back to fp-based unwinding on the first failure.
                        // We can't attempt it again for other modules higher in the
                        // stack because the full register state won't have been unwound.
                    }
                }
            }
        }

        const fp = if (comptime native_arch.isSPARC())
            // On SPARC the offset is positive. (!)
            math.add(usize, it.fp, fp_offset) catch return null
        else
            math.sub(usize, it.fp, fp_offset) catch return null;

        // Sanity check.
        if (fp == 0 or !mem.isAligned(fp, @alignOf(usize))) return null;
        const new_fp = math.add(usize, it.ma.load(usize, fp) orelse return null, fp_bias) catch
            return null;

        // Sanity check: the stack grows down thus all the parent frames must be
        // be at addresses that are greater (or equal) than the previous one.
        // A zero frame pointer often signals this is the last frame, that case
        // is gracefully handled by the next call to next_internal.
        if (new_fp != 0 and new_fp < it.fp) return null;
        const new_pc = it.ma.load(usize, math.add(usize, fp, pc_offset) catch return null) orelse
            return null;

        it.fp = new_fp;

        return new_pc;
    }
};

pub fn writeCurrentStackTrace(
    out_stream: anytype,
    debug_info: *SelfInfo,
    tty_config: io.tty.Config,
    start_addr: ?usize,
) !void {
    if (native_os == .windows) {
        var context: ThreadContext = undefined;
        assert(getContext(&context));
        return writeStackTraceWindows(out_stream, debug_info, tty_config, &context, start_addr);
    }
    var context: ThreadContext = undefined;
    const has_context = getContext(&context);

    var it = (if (has_context) blk: {
        break :blk StackIterator.initWithContext(start_addr, debug_info, &context) catch null;
    } else null) orelse StackIterator.init(start_addr, null);
    defer it.deinit();

    while (it.next()) |return_address| {
        printLastUnwindError(&it, debug_info, out_stream, tty_config);

        // On arm64 macOS, the address of the last frame is 0x0 rather than 0x1 as on x86_64 macOS,
        // therefore, we do a check for `return_address == 0` before subtracting 1 from it to avoid
        // an overflow. We do not need to signal `StackIterator` as it will correctly detect this
        // condition on the subsequent iteration and return `null` thus terminating the loop.
        // same behaviour for x86-windows-msvc
        const address = return_address -| 1;
        try printSourceAtAddress(debug_info, out_stream, address, tty_config);
    } else printLastUnwindError(&it, debug_info, out_stream, tty_config);
}

pub noinline fn walkStackWindows(addresses: []usize, existing_context: ?*const windows.CONTEXT) usize {
    if (builtin.cpu.arch == .x86) {
        // RtlVirtualUnwind doesn't exist on x86
        return windows.ntdll.RtlCaptureStackBackTrace(0, addresses.len, @as(**anyopaque, @ptrCast(addresses.ptr)), null);
    }

    const tib = &windows.teb().NtTib;

    var context: windows.CONTEXT = undefined;
    if (existing_context) |context_ptr| {
        context = context_ptr.*;
    } else {
        context = std.mem.zeroes(windows.CONTEXT);
        windows.ntdll.RtlCaptureContext(&context);
    }

    var i: usize = 0;
    var image_base: windows.DWORD64 = undefined;
    var history_table: windows.UNWIND_HISTORY_TABLE = std.mem.zeroes(windows.UNWIND_HISTORY_TABLE);

    while (i < addresses.len) : (i += 1) {
        const current_regs = context.getRegs();
        if (windows.ntdll.RtlLookupFunctionEntry(current_regs.ip, &image_base, &history_table)) |runtime_function| {
            var handler_data: ?*anyopaque = null;
            var establisher_frame: u64 = undefined;
            _ = windows.ntdll.RtlVirtualUnwind(
                windows.UNW_FLAG_NHANDLER,
                image_base,
                current_regs.ip,
                runtime_function,
                &context,
                &handler_data,
                &establisher_frame,
                null,
            );
        } else {
            // leaf function
            context.setIp(@as(*usize, @ptrFromInt(current_regs.sp)).*);
            context.setSp(current_regs.sp + @sizeOf(usize));
        }

        const next_regs = context.getRegs();
        if (next_regs.sp < @intFromPtr(tib.StackLimit) or next_regs.sp > @intFromPtr(tib.StackBase)) {
            break;
        }

        if (next_regs.ip == 0) {
            break;
        }

        addresses[i] = next_regs.ip;
    }

    return i;
}

pub fn writeStackTraceWindows(
    out_stream: anytype,
    debug_info: *SelfInfo,
    tty_config: io.tty.Config,
    context: *const windows.CONTEXT,
    start_addr: ?usize,
) !void {
    var addr_buf: [1024]usize = undefined;
    const n = walkStackWindows(addr_buf[0..], context);
    const addrs = addr_buf[0..n];
    const start_i: usize = if (start_addr) |saddr| blk: {
        for (addrs, 0..) |addr, i| {
            if (addr == saddr) break :blk i;
        }
        return;
    } else 0;
    for (addrs[start_i..]) |addr| {
        try printSourceAtAddress(debug_info, out_stream, addr - 1, tty_config);
    }
}

fn printUnknownSource(debug_info: *SelfInfo, out_stream: anytype, address: usize, tty_config: io.tty.Config) !void {
    const module_name = debug_info.getModuleNameForAddress(address);
    return printLineInfo(
        out_stream,
        null,
        address,
        "???",
        module_name orelse "???",
        tty_config,
        printLineFromFileAnyOs,
    );
}

fn printLastUnwindError(it: *StackIterator, debug_info: *SelfInfo, out_stream: anytype, tty_config: io.tty.Config) void {
    if (!have_ucontext) return;
    if (it.getLastError()) |unwind_error| {
        printUnwindError(debug_info, out_stream, unwind_error.address, unwind_error.err, tty_config) catch {};
    }
}

fn printUnwindError(debug_info: *SelfInfo, out_stream: anytype, address: usize, err: UnwindError, tty_config: io.tty.Config) !void {
    const module_name = debug_info.getModuleNameForAddress(address) orelse "???";
    try tty_config.setColor(out_stream, .dim);
    if (err == error.MissingDebugInfo) {
        try out_stream.print("Unwind information for `{s}:0x{x}` was not available, trace may be incomplete\n\n", .{ module_name, address });
    } else {
        try out_stream.print("Unwind error at address `{s}:0x{x}` ({}), trace may be incomplete\n\n", .{ module_name, address, err });
    }
    try tty_config.setColor(out_stream, .reset);
}

pub fn printSourceAtAddress(debug_info: *SelfInfo, out_stream: anytype, address: usize, tty_config: io.tty.Config) !void {
    const module = debug_info.getModuleForAddress(address) catch |err| switch (err) {
        error.MissingDebugInfo, error.InvalidDebugInfo => return printUnknownSource(debug_info, out_stream, address, tty_config),
        else => return err,
    };

    const symbol_info = module.getSymbolAtAddress(debug_info.allocator, address) catch |err| switch (err) {
        error.MissingDebugInfo, error.InvalidDebugInfo => return printUnknownSource(debug_info, out_stream, address, tty_config),
        else => return err,
    };
    defer if (symbol_info.source_location) |sl| debug_info.allocator.free(sl.file_name);

    return printLineInfo(
        out_stream,
        symbol_info.source_location,
        address,
        symbol_info.name,
        symbol_info.compile_unit_name,
        tty_config,
        printLineFromFileAnyOs,
    );
}

fn printLineInfo(
    out_stream: anytype,
    source_location: ?SourceLocation,
    address: usize,
    symbol_name: []const u8,
    compile_unit_name: []const u8,
    tty_config: io.tty.Config,
    comptime printLineFromFile: anytype,
) !void {
    nosuspend {
        try tty_config.setColor(out_stream, .bold);

        if (source_location) |*sl| {
            try out_stream.print("{s}:{d}:{d}", .{ sl.file_name, sl.line, sl.column });
        } else {
            try out_stream.writeAll("???:?:?");
        }

        try tty_config.setColor(out_stream, .reset);
        try out_stream.writeAll(": ");
        try tty_config.setColor(out_stream, .dim);
        try out_stream.print("0x{x} in {s} ({s})", .{ address, symbol_name, compile_unit_name });
        try tty_config.setColor(out_stream, .reset);
        try out_stream.writeAll("\n");

        // Show the matching source code line if possible
        if (source_location) |sl| {
            if (printLineFromFile(out_stream, sl)) {
                if (sl.column > 0) {
                    // The caret already takes one char
                    const space_needed = @as(usize, @intCast(sl.column - 1));

                    try out_stream.writeByteNTimes(' ', space_needed);
                    try tty_config.setColor(out_stream, .green);
                    try out_stream.writeAll("^");
                    try tty_config.setColor(out_stream, .reset);
                }
                try out_stream.writeAll("\n");
            } else |err| switch (err) {
                error.EndOfFile, error.FileNotFound => {},
                error.BadPathName => {},
                error.AccessDenied => {},
                else => return err,
            }
        }
    }
}

fn printLineFromFileAnyOs(out_stream: anytype, source_location: SourceLocation) !void {
    // Need this to always block even in async I/O mode, because this could potentially
    // be called from e.g. the event loop code crashing.
    var f = try fs.cwd().openFile(source_location.file_name, .{});
    defer f.close();
    // TODO fstat and make sure that the file has the correct size

    var buf: [4096]u8 = undefined;
    var amt_read = try f.read(buf[0..]);
    const line_start = seek: {
        var current_line_start: usize = 0;
        var next_line: usize = 1;
        while (next_line != source_location.line) {
            const slice = buf[current_line_start..amt_read];
            if (mem.indexOfScalar(u8, slice, '\n')) |pos| {
                next_line += 1;
                if (pos == slice.len - 1) {
                    amt_read = try f.read(buf[0..]);
                    current_line_start = 0;
                } else current_line_start += pos + 1;
            } else if (amt_read < buf.len) {
                return error.EndOfFile;
            } else {
                amt_read = try f.read(buf[0..]);
                current_line_start = 0;
            }
        }
        break :seek current_line_start;
    };
    const slice = buf[line_start..amt_read];
    if (mem.indexOfScalar(u8, slice, '\n')) |pos| {
        const line = slice[0 .. pos + 1];
        mem.replaceScalar(u8, line, '\t', ' ');
        return out_stream.writeAll(line);
    } else { // Line is the last inside the buffer, and requires another read to find delimiter. Alternatively the file ends.
        mem.replaceScalar(u8, slice, '\t', ' ');
        try out_stream.writeAll(slice);
        while (amt_read == buf.len) {
            amt_read = try f.read(buf[0..]);
            if (mem.indexOfScalar(u8, buf[0..amt_read], '\n')) |pos| {
                const line = buf[0 .. pos + 1];
                mem.replaceScalar(u8, line, '\t', ' ');
                return out_stream.writeAll(line);
            } else {
                const line = buf[0..amt_read];
                mem.replaceScalar(u8, line, '\t', ' ');
                try out_stream.writeAll(line);
            }
        }
        // Make sure printing last line of file inserts extra newline
        try out_stream.writeByte('\n');
    }
}

test printLineFromFileAnyOs {
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    const output_stream = output.writer();

    const allocator = std.testing.allocator;
    const join = std.fs.path.join;
    const expectError = std.testing.expectError;
    const expectEqualStrings = std.testing.expectEqualStrings;

    var test_dir = std.testing.tmpDir(.{});
    defer test_dir.cleanup();
    // Relies on testing.tmpDir internals which is not ideal, but SourceLocation requires paths.
    const test_dir_path = try join(allocator, &.{ ".zig-cache", "tmp", test_dir.sub_path[0..] });
    defer allocator.free(test_dir_path);

    // Cases
    {
        const path = try join(allocator, &.{ test_dir_path, "one_line.zig" });
        defer allocator.free(path);
        try test_dir.dir.writeFile(.{ .sub_path = "one_line.zig", .data = "no new lines in this file, but one is printed anyway" });

        try expectError(error.EndOfFile, printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 2, .column = 0 }));

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expectEqualStrings("no new lines in this file, but one is printed anyway\n", output.items);
        output.clearRetainingCapacity();
    }
    {
        const path = try fs.path.join(allocator, &.{ test_dir_path, "three_lines.zig" });
        defer allocator.free(path);
        try test_dir.dir.writeFile(.{
            .sub_path = "three_lines.zig",
            .data =
            \\1
            \\2
            \\3
            ,
        });

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expectEqualStrings("1\n", output.items);
        output.clearRetainingCapacity();

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 3, .column = 0 });
        try expectEqualStrings("3\n", output.items);
        output.clearRetainingCapacity();
    }
    {
        const file = try test_dir.dir.createFile("line_overlaps_page_boundary.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "line_overlaps_page_boundary.zig" });
        defer allocator.free(path);

        const overlap = 10;
        var writer = file.writer();
        try writer.writeByteNTimes('a', std.heap.page_size_min - overlap);
        try writer.writeByte('\n');
        try writer.writeByteNTimes('a', overlap);

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 2, .column = 0 });
        try expectEqualStrings(("a" ** overlap) ++ "\n", output.items);
        output.clearRetainingCapacity();
    }
    {
        const file = try test_dir.dir.createFile("file_ends_on_page_boundary.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "file_ends_on_page_boundary.zig" });
        defer allocator.free(path);

        var writer = file.writer();
        try writer.writeByteNTimes('a', std.heap.page_size_max);

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expectEqualStrings(("a" ** std.heap.page_size_max) ++ "\n", output.items);
        output.clearRetainingCapacity();
    }
    {
        const file = try test_dir.dir.createFile("very_long_first_line_spanning_multiple_pages.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "very_long_first_line_spanning_multiple_pages.zig" });
        defer allocator.free(path);

        var writer = file.writer();
        try writer.writeByteNTimes('a', 3 * std.heap.page_size_max);

        try expectError(error.EndOfFile, printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 2, .column = 0 }));

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expectEqualStrings(("a" ** (3 * std.heap.page_size_max)) ++ "\n", output.items);
        output.clearRetainingCapacity();

        try writer.writeAll("a\na");

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 1, .column = 0 });
        try expectEqualStrings(("a" ** (3 * std.heap.page_size_max)) ++ "a\n", output.items);
        output.clearRetainingCapacity();

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = 2, .column = 0 });
        try expectEqualStrings("a\n", output.items);
        output.clearRetainingCapacity();
    }
    {
        const file = try test_dir.dir.createFile("file_of_newlines.zig", .{});
        defer file.close();
        const path = try fs.path.join(allocator, &.{ test_dir_path, "file_of_newlines.zig" });
        defer allocator.free(path);

        var writer = file.writer();
        const real_file_start = 3 * std.heap.page_size_min;
        try writer.writeByteNTimes('\n', real_file_start);
        try writer.writeAll("abc\ndef");

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = real_file_start + 1, .column = 0 });
        try expectEqualStrings("abc\n", output.items);
        output.clearRetainingCapacity();

        try printLineFromFileAnyOs(output_stream, .{ .file_name = path, .line = real_file_start + 2, .column = 0 });
        try expectEqualStrings("def\n", output.items);
        output.clearRetainingCapacity();
    }
}

/// TODO multithreaded awareness
var debug_info_allocator: ?mem.Allocator = null;
var debug_info_arena_allocator: std.heap.ArenaAllocator = undefined;
fn getDebugInfoAllocator() mem.Allocator {
    if (debug_info_allocator) |a| return a;

    debug_info_arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = debug_info_arena_allocator.allocator();
    debug_info_allocator = allocator;
    return allocator;
}

/// Whether or not the current target can print useful debug information when a segfault occurs.
pub const have_segfault_handling_support = switch (native_os) {
    .linux,
    .macos,
    .netbsd,
    .solaris,
    .illumos,
    .windows,
    => true,

    .freebsd, .openbsd => have_ucontext,
    else => false,
};

const enable_segfault_handler = std.options.enable_segfault_handler;
pub const default_enable_segfault_handler = runtime_safety and have_segfault_handling_support;

pub fn maybeEnableSegfaultHandler() void {
    if (enable_segfault_handler) {
        attachSegfaultHandler();
    }
}

var windows_segfault_handle: ?windows.HANDLE = null;

pub fn updateSegfaultHandler(act: ?*const posix.Sigaction) void {
    posix.sigaction(posix.SIG.SEGV, act, null);
    posix.sigaction(posix.SIG.ILL, act, null);
    posix.sigaction(posix.SIG.BUS, act, null);
    posix.sigaction(posix.SIG.FPE, act, null);
}

/// Attaches a global SIGSEGV handler which calls `@panic("segmentation fault");`
pub fn attachSegfaultHandler() void {
    if (!have_segfault_handling_support) {
        @compileError("segfault handler not supported for this target");
    }
    if (native_os == .windows) {
        windows_segfault_handle = windows.kernel32.AddVectoredExceptionHandler(0, handleSegfaultWindows);
        return;
    }
    var act = posix.Sigaction{
        .handler = .{ .sigaction = handleSegfaultPosix },
        .mask = posix.empty_sigset,
        .flags = (posix.SA.SIGINFO | posix.SA.RESTART | posix.SA.RESETHAND),
    };

    updateSegfaultHandler(&act);
}

fn resetSegfaultHandler() void {
    if (native_os == .windows) {
        if (windows_segfault_handle) |handle| {
            assert(windows.kernel32.RemoveVectoredExceptionHandler(handle) != 0);
            windows_segfault_handle = null;
        }
        return;
    }
    var act = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.DFL },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    updateSegfaultHandler(&act);
}

fn handleSegfaultPosix(sig: i32, info: *const posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) noreturn {
    // Reset to the default handler so that if a segfault happens in this handler it will crash
    // the process. Also when this handler returns, the original instruction will be repeated
    // and the resulting segfault will crash the process rather than continually dump stack traces.
    resetSegfaultHandler();

    const addr = switch (native_os) {
        .linux => @intFromPtr(info.fields.sigfault.addr),
        .freebsd, .macos => @intFromPtr(info.addr),
        .netbsd => @intFromPtr(info.info.reason.fault.addr),
        .openbsd => @intFromPtr(info.data.fault.addr),
        .solaris, .illumos => @intFromPtr(info.reason.fault.addr),
        else => unreachable,
    };

    const code = if (native_os == .netbsd) info.info.code else info.code;
    nosuspend switch (panic_stage) {
        0 => {
            panic_stage = 1;
            _ = panicking.fetchAdd(1, .seq_cst);

            {
                lockStdErr();
                defer unlockStdErr();

                dumpSegfaultInfoPosix(sig, code, addr, ctx_ptr);
            }

            waitForOtherThreadToFinishPanicking();
        },
        else => {
            // panic mutex already locked
            dumpSegfaultInfoPosix(sig, code, addr, ctx_ptr);
        },
    };

    // We cannot allow the signal handler to return because when it runs the original instruction
    // again, the memory may be mapped and undefined behavior would occur rather than repeating
    // the segfault. So we simply abort here.
    posix.abort();
}

fn dumpSegfaultInfoPosix(sig: i32, code: i32, addr: usize, ctx_ptr: ?*anyopaque) void {
    const stderr = io.getStdErr().writer();
    _ = switch (sig) {
        posix.SIG.SEGV => if (native_arch == .x86_64 and native_os == .linux and code == 128) // SI_KERNEL
            // x86_64 doesn't have a full 64-bit virtual address space.
            // Addresses outside of that address space are non-canonical
            // and the CPU won't provide the faulting address to us.
            // This happens when accessing memory addresses such as 0xaaaaaaaaaaaaaaaa
            // but can also happen when no addressable memory is involved;
            // for example when reading/writing model-specific registers
            // by executing `rdmsr` or `wrmsr` in user-space (unprivileged mode).
            stderr.print("General protection exception (no address available)\n", .{})
        else
            stderr.print("Segmentation fault at address 0x{x}\n", .{addr}),
        posix.SIG.ILL => stderr.print("Illegal instruction at address 0x{x}\n", .{addr}),
        posix.SIG.BUS => stderr.print("Bus error at address 0x{x}\n", .{addr}),
        posix.SIG.FPE => stderr.print("Arithmetic exception at address 0x{x}\n", .{addr}),
        else => unreachable,
    } catch posix.abort();

    switch (native_arch) {
        .x86,
        .x86_64,
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        .aarch64,
        .aarch64_be,
        => {
            const ctx: *posix.ucontext_t = @ptrCast(@alignCast(ctx_ptr));
            dumpStackTraceFromBase(ctx);
        },
        else => {},
    }
}

fn handleSegfaultWindows(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
    switch (info.ExceptionRecord.ExceptionCode) {
        windows.EXCEPTION_DATATYPE_MISALIGNMENT => handleSegfaultWindowsExtra(info, 0, "Unaligned Memory Access"),
        windows.EXCEPTION_ACCESS_VIOLATION => handleSegfaultWindowsExtra(info, 1, null),
        windows.EXCEPTION_ILLEGAL_INSTRUCTION => handleSegfaultWindowsExtra(info, 2, null),
        windows.EXCEPTION_STACK_OVERFLOW => handleSegfaultWindowsExtra(info, 0, "Stack Overflow"),
        else => return windows.EXCEPTION_CONTINUE_SEARCH,
    }
}

fn handleSegfaultWindowsExtra(info: *windows.EXCEPTION_POINTERS, msg: u8, label: ?[]const u8) noreturn {
    comptime assert(windows.CONTEXT != void);
    nosuspend switch (panic_stage) {
        0 => {
            panic_stage = 1;
            _ = panicking.fetchAdd(1, .seq_cst);

            {
                lockStdErr();
                defer unlockStdErr();

                dumpSegfaultInfoWindows(info, msg, label);
            }

            waitForOtherThreadToFinishPanicking();
        },
        1 => {
            panic_stage = 2;
            io.getStdErr().writeAll("aborting due to recursive panic\n") catch {};
        },
        else => {},
    };
    posix.abort();
}

fn dumpSegfaultInfoWindows(info: *windows.EXCEPTION_POINTERS, msg: u8, label: ?[]const u8) void {
    const stderr = io.getStdErr().writer();
    _ = switch (msg) {
        0 => stderr.print("{s}\n", .{label.?}),
        1 => stderr.print("Segmentation fault at address 0x{x}\n", .{info.ExceptionRecord.ExceptionInformation[1]}),
        2 => stderr.print("Illegal instruction at address 0x{x}\n", .{info.ContextRecord.getRegs().ip}),
        else => unreachable,
    } catch posix.abort();

    dumpStackTraceFromBase(info.ContextRecord);
}

pub fn dumpStackPointerAddr(prefix: []const u8) void {
    const sp = asm (""
        : [argc] "={rsp}" (-> usize),
    );
    print("{s} sp = 0x{x}\n", .{ prefix, sp });
}

test "manage resources correctly" {
    if (builtin.strip_debug_info) return error.SkipZigTest;

    if (native_os == .wasi) return error.SkipZigTest;

    if (native_os == .windows) {
        // https://github.com/ziglang/zig/issues/13963
        return error.SkipZigTest;
    }

    // self-hosted debug info is still too buggy
    if (builtin.zig_backend != .stage2_llvm) return error.SkipZigTest;

    const writer = std.io.null_writer;
    var di = try SelfInfo.open(testing.allocator);
    defer di.deinit();
    try printSourceAtAddress(&di, writer, showMyTrace(), io.tty.detectConfig(std.io.getStdErr()));
}

noinline fn showMyTrace() usize {
    return @returnAddress();
}

/// This API helps you track where a value originated and where it was mutated,
/// or any other points of interest.
/// In debug mode, it adds a small size penalty (104 bytes on 64-bit architectures)
/// to the aggregate that you add it to.
/// In release mode, it is size 0 and all methods are no-ops.
/// This is a pre-made type with default settings.
/// For more advanced usage, see `ConfigurableTrace`.
pub const Trace = ConfigurableTrace(2, 4, builtin.mode == .Debug);

pub fn ConfigurableTrace(comptime size: usize, comptime stack_frame_count: usize, comptime is_enabled: bool) type {
    return struct {
        addrs: [actual_size][stack_frame_count]usize,
        notes: [actual_size][]const u8,
        index: Index,

        const actual_size = if (enabled) size else 0;
        const Index = if (enabled) usize else u0;

        pub const init: @This() = .{
            .addrs = undefined,
            .notes = undefined,
            .index = 0,
        };

        pub const enabled = is_enabled;

        pub const add = if (enabled) addNoInline else addNoOp;

        pub noinline fn addNoInline(t: *@This(), note: []const u8) void {
            comptime assert(enabled);
            return addAddr(t, @returnAddress(), note);
        }

        pub inline fn addNoOp(t: *@This(), note: []const u8) void {
            _ = t;
            _ = note;
            comptime assert(!enabled);
        }

        pub fn addAddr(t: *@This(), addr: usize, note: []const u8) void {
            if (!enabled) return;

            if (t.index < size) {
                t.notes[t.index] = note;
                t.addrs[t.index] = [1]usize{0} ** stack_frame_count;
                var stack_trace: std.builtin.StackTrace = .{
                    .index = 0,
                    .instruction_addresses = &t.addrs[t.index],
                };
                captureStackTrace(addr, &stack_trace);
            }
            // Keep counting even if the end is reached so that the
            // user can find out how much more size they need.
            t.index += 1;
        }

        pub fn dump(t: @This()) void {
            if (!enabled) return;

            const tty_config = io.tty.detectConfig(std.io.getStdErr());
            const stderr = io.getStdErr().writer();
            const end = @min(t.index, size);
            const debug_info = getSelfDebugInfo() catch |err| {
                stderr.print(
                    "Unable to dump stack trace: Unable to open debug info: {s}\n",
                    .{@errorName(err)},
                ) catch return;
                return;
            };
            for (t.addrs[0..end], 0..) |frames_array, i| {
                stderr.print("{s}:\n", .{t.notes[i]}) catch return;
                var frames_array_mutable = frames_array;
                const frames = mem.sliceTo(frames_array_mutable[0..], 0);
                const stack_trace: std.builtin.StackTrace = .{
                    .index = frames.len,
                    .instruction_addresses = frames,
                };
                writeStackTrace(stack_trace, stderr, debug_info, tty_config) catch continue;
            }
            if (t.index > end) {
                stderr.print("{d} more traces not shown; consider increasing trace size\n", .{
                    t.index - end,
                }) catch return;
            }
        }

        pub fn format(
            t: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, t);
            _ = options;
            if (enabled) {
                try writer.writeAll("\n");
                t.dump();
                try writer.writeAll("\n");
            } else {
                return writer.writeAll("(value tracing disabled)");
            }
        }
    };
}

pub const SafetyLock = struct {
    state: State = if (runtime_safety) .unlocked else .unknown,

    pub const State = if (runtime_safety) enum { unlocked, locked } else enum { unknown };

    pub fn lock(l: *SafetyLock) void {
        if (!runtime_safety) return;
        assert(l.state == .unlocked);
        l.state = .locked;
    }

    pub fn unlock(l: *SafetyLock) void {
        if (!runtime_safety) return;
        assert(l.state == .locked);
        l.state = .unlocked;
    }

    pub fn assertUnlocked(l: SafetyLock) void {
        if (!runtime_safety) return;
        assert(l.state == .unlocked);
    }

    pub fn assertLocked(l: SafetyLock) void {
        if (!runtime_safety) return;
        assert(l.state == .locked);
    }
};

test SafetyLock {
    var safety_lock: SafetyLock = .{};
    safety_lock.assertUnlocked();
    safety_lock.lock();
    safety_lock.assertLocked();
    safety_lock.unlock();
    safety_lock.assertUnlocked();
}

/// Detect whether the program is being executed in the Valgrind virtual machine.
///
/// When Valgrind integrations are disabled, this returns comptime-known false.
/// Otherwise, the result is runtime-known.
pub inline fn inValgrind() bool {
    if (@inComptime()) return false;
    if (!builtin.valgrind_support) return false;
    return std.valgrind.runningOnValgrind() > 0;
}

test {
    _ = &Dwarf;
    _ = &MemoryAccessor;
    _ = &FixedBufferReader;
    _ = &Pdb;
    _ = &SelfInfo;
    _ = &dumpHex;
}
const std = @import("../std.zig");
const Allocator = std.mem.Allocator;
const Hash = std.hash.Wyhash;
const Dwarf = std.debug.Dwarf;
const assert = std.debug.assert;

const Coverage = @This();

/// Provides a globally-scoped integer index for directories.
///
/// As opposed to, for example, a directory index that is compilation-unit
/// scoped inside a single ELF module.
///
/// String memory references the memory-mapped debug information.
///
/// Protected by `mutex`.
directories: std.ArrayHashMapUnmanaged(String, void, String.MapContext, false),
/// Provides a globally-scoped integer index for files.
///
/// String memory references the memory-mapped debug information.
///
/// Protected by `mutex`.
files: std.ArrayHashMapUnmanaged(File, void, File.MapContext, false),
string_bytes: std.ArrayListUnmanaged(u8),
/// Protects the other fields.
mutex: std.Thread.Mutex,

pub const init: Coverage = .{
    .directories = .{},
    .files = .{},
    .mutex = .{},
    .string_bytes = .{},
};

pub const String = enum(u32) {
    _,

    pub const MapContext = struct {
        string_bytes: []const u8,

        pub fn eql(self: @This(), a: String, b: String, b_index: usize) bool {
            _ = b_index;
            const a_slice = span(self.string_bytes[@intFromEnum(a)..]);
            const b_slice = span(self.string_bytes[@intFromEnum(b)..]);
            return std.mem.eql(u8, a_slice, b_slice);
        }

        pub fn hash(self: @This(), a: String) u32 {
            return @truncate(Hash.hash(0, span(self.string_bytes[@intFromEnum(a)..])));
        }
    };

    pub const SliceAdapter = struct {
        string_bytes: []const u8,

        pub fn eql(self: @This(), a_slice: []const u8, b: String, b_index: usize) bool {
            _ = b_index;
            const b_slice = span(self.string_bytes[@intFromEnum(b)..]);
            return std.mem.eql(u8, a_slice, b_slice);
        }
        pub fn hash(self: @This(), a: []const u8) u32 {
            _ = self;
            return @truncate(Hash.hash(0, a));
        }
    };
};

pub const SourceLocation = extern struct {
    file: File.Index,
    line: u32,
    column: u32,

    pub const invalid: SourceLocation = .{
        .file = .invalid,
        .line = 0,
        .column = 0,
    };
};

pub const File = extern struct {
    directory_index: u32,
    basename: String,

    pub const Index = enum(u32) {
        invalid = std.math.maxInt(u32),
        _,
    };

    pub const MapContext = struct {
        string_bytes: []const u8,

        pub fn hash(self: MapContext, a: File) u32 {
            const a_basename = span(self.string_bytes[@intFromEnum(a.basename)..]);
            return @truncate(Hash.hash(a.directory_index, a_basename));
        }

        pub fn eql(self: MapContext, a: File, b: File, b_index: usize) bool {
            _ = b_index;
            if (a.directory_index != b.directory_index) return false;
            const a_basename = span(self.string_bytes[@intFromEnum(a.basename)..]);
            const b_basename = span(self.string_bytes[@intFromEnum(b.basename)..]);
            return std.mem.eql(u8, a_basename, b_basename);
        }
    };

    pub const SliceAdapter = struct {
        string_bytes: []const u8,

        pub const Entry = struct {
            directory_index: u32,
            basename: []const u8,
        };

        pub fn hash(self: @This(), a: Entry) u32 {
            _ = self;
            return @truncate(Hash.hash(a.directory_index, a.basename));
        }

        pub fn eql(self: @This(), a: Entry, b: File, b_index: usize) bool {
            _ = b_index;
            if (a.directory_index != b.directory_index) return false;
            const b_basename = span(self.string_bytes[@intFromEnum(b.basename)..]);
            return std.mem.eql(u8, a.basename, b_basename);
        }
    };
};

pub fn deinit(cov: *Coverage, gpa: Allocator) void {
    cov.directories.deinit(gpa);
    cov.files.deinit(gpa);
    cov.string_bytes.deinit(gpa);
    cov.* = undefined;
}

pub fn fileAt(cov: *Coverage, index: File.Index) *File {
    return &cov.files.keys()[@intFromEnum(index)];
}

pub fn stringAt(cov: *Coverage, index: String) [:0]const u8 {
    return span(cov.string_bytes.items[@intFromEnum(index)..]);
}

pub const ResolveAddressesDwarfError = Dwarf.ScanError;

pub fn resolveAddressesDwarf(
    cov: *Coverage,
    gpa: Allocator,
    /// Asserts the addresses are in ascending order.
    sorted_pc_addrs: []const u64,
    /// Asserts its length equals length of `sorted_pc_addrs`.
    output: []SourceLocation,
    d: *Dwarf,
) ResolveAddressesDwarfError!void {
    assert(sorted_pc_addrs.len == output.len);
    assert(d.ranges.items.len != 0); // call `populateRanges` first.

    var range_i: usize = 0;
    var range: *std.debug.Dwarf.Range = &d.ranges.items[0];
    var line_table_i: usize = undefined;
    var prev_pc: u64 = 0;
    var prev_cu: ?*std.debug.Dwarf.CompileUnit = null;
    // Protects directories and files tables from other threads.
    cov.mutex.lock();
    defer cov.mutex.unlock();
    next_pc: for (sorted_pc_addrs, output) |pc, *out| {
        assert(pc >= prev_pc);
        prev_pc = pc;

        while (pc >= range.end) {
            range_i += 1;
            if (range_i >= d.ranges.items.len) {
                out.* = SourceLocation.invalid;
                continue :next_pc;
            }
            range = &d.ranges.items[range_i];
        }
        if (pc < range.start) {
            out.* = SourceLocation.invalid;
            continue :next_pc;
        }
        const cu = &d.compile_unit_list.items[range.compile_unit_index];
        if (cu != prev_cu) {
            prev_cu = cu;
            if (cu.src_loc_cache == null) {
                cov.mutex.unlock();
                defer cov.mutex.lock();
                d.populateSrcLocCache(gpa, cu) catch |err| switch (err) {
                    error.MissingDebugInfo, error.InvalidDebugInfo => {
                        out.* = SourceLocation.invalid;
                        continue :next_pc;
                    },
                    else => |e| return e,
                };
            }
            const slc = &cu.src_loc_cache.?;
            const table_addrs = slc.line_table.keys();
            line_table_i = std.sort.upperBound(u64, table_addrs, pc, struct {
                fn order(context: u64, item: u64) std.math.Order {
                    return std.math.order(context, item);
                }
            }.order);
        }
        const slc = &cu.src_loc_cache.?;
        const table_addrs = slc.line_table.keys();
        while (line_table_i < table_addrs.len and table_addrs[line_table_i] <= pc) line_table_i += 1;

        const entry = slc.line_table.values()[line_table_i - 1];
        const corrected_file_index = entry.file - @intFromBool(slc.version < 5);
        const file_entry = slc.files[corrected_file_index];
        const dir_path = slc.directories[file_entry.dir_index].path;
        try cov.string_bytes.ensureUnusedCapacity(gpa, dir_path.len + file_entry.path.len + 2);
        const dir_gop = try cov.directories.getOrPutContextAdapted(gpa, dir_path, String.SliceAdapter{
            .string_bytes = cov.string_bytes.items,
        }, String.MapContext{
            .string_bytes = cov.string_bytes.items,
        });
        if (!dir_gop.found_existing)
            dir_gop.key_ptr.* = addStringAssumeCapacity(cov, dir_path);
        const file_gop = try cov.files.getOrPutContextAdapted(gpa, File.SliceAdapter.Entry{
            .directory_index = @intCast(dir_gop.index),
            .basename = file_entry.path,
        }, File.SliceAdapter{
            .string_bytes = cov.string_bytes.items,
        }, File.MapContext{
            .string_bytes = cov.string_bytes.items,
        });
        if (!file_gop.found_existing) file_gop.key_ptr.* = .{
            .directory_index = @intCast(dir_gop.index),
            .basename = addStringAssumeCapacity(cov, file_entry.path),
        };
        out.* = .{
            .file = @enumFromInt(file_gop.index),
            .line = entry.line,
            .column = entry.column,
        };
    }
}

pub fn addStringAssumeCapacity(cov: *Coverage, s: []const u8) String {
    const result: String = @enumFromInt(cov.string_bytes.items.len);
    cov.string_bytes.appendSliceAssumeCapacity(s);
    cov.string_bytes.appendAssumeCapacity(0);
    return result;
}

fn span(s: []const u8) [:0]const u8 {
    return std.mem.sliceTo(@as([:0]const u8, @ptrCast(s)), 0);
}
//! Implements parsing, decoding, and caching of DWARF information.
//!
//! This API does not assume the current executable is itself the thing being
//! debugged, however, it does assume the debug info has the same CPU
//! architecture and OS as the current executable. It is planned to remove this
//! limitation.
//!
//! For unopinionated types and bits, see `std.dwarf`.

const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const std = @import("../std.zig");
const Allocator = std.mem.Allocator;
const elf = std.elf;
const mem = std.mem;
const DW = std.dwarf;
const AT = DW.AT;
const EH = DW.EH;
const FORM = DW.FORM;
const Format = DW.Format;
const RLE = DW.RLE;
const UT = DW.UT;
const assert = std.debug.assert;
const cast = std.math.cast;
const maxInt = std.math.maxInt;
const MemoryAccessor = std.debug.MemoryAccessor;
const Path = std.Build.Cache.Path;
const FixedBufferReader = std.debug.FixedBufferReader;

const Dwarf = @This();

pub const expression = @import("Dwarf/expression.zig");
pub const abi = @import("Dwarf/abi.zig");
pub const call_frame = @import("Dwarf/call_frame.zig");

/// Useful to temporarily enable while working on this file.
const debug_debug_mode = false;

endian: std.builtin.Endian,
sections: SectionArray = null_section_array,
is_macho: bool,

/// Filled later by the initializer
abbrev_table_list: std.ArrayListUnmanaged(Abbrev.Table) = .empty,
/// Filled later by the initializer
compile_unit_list: std.ArrayListUnmanaged(CompileUnit) = .empty,
/// Filled later by the initializer
func_list: std.ArrayListUnmanaged(Func) = .empty,

/// Starts out non-`null` if the `.eh_frame_hdr` section is present. May become `null` later if we
/// find that `.eh_frame_hdr` is incomplete.
eh_frame_hdr: ?ExceptionFrameHeader = null,
/// These lookup tables are only used if `eh_frame_hdr` is null
cie_map: std.AutoArrayHashMapUnmanaged(u64, CommonInformationEntry) = .empty,
/// Sorted by start_pc
fde_list: std.ArrayListUnmanaged(FrameDescriptionEntry) = .empty,

/// Populated by `populateRanges`.
ranges: std.ArrayListUnmanaged(Range) = .empty,

pub const Range = struct {
    start: u64,
    end: u64,
    /// Index into `compile_unit_list`.
    compile_unit_index: usize,
};

pub const Section = struct {
    data: []const u8,
    // Module-relative virtual address.
    // Only set if the section data was loaded from disk.
    virtual_address: ?usize = null,
    // If `data` is owned by this Dwarf.
    owned: bool,

    pub const Id = enum {
        debug_info,
        debug_abbrev,
        debug_str,
        debug_str_offsets,
        debug_line,
        debug_line_str,
        debug_ranges,
        debug_loclists,
        debug_rnglists,
        debug_addr,
        debug_names,
        debug_frame,
        eh_frame,
        eh_frame_hdr,
    };

    // For sections that are not memory mapped by the loader, this is an offset
    // from `data.ptr` to where the section would have been mapped. Otherwise,
    // `data` is directly backed by the section and the offset is zero.
    pub fn virtualOffset(self: Section, base_address: usize) i64 {
        return if (self.virtual_address) |va|
            @as(i64, @intCast(base_address + va)) -
                @as(i64, @intCast(@intFromPtr(self.data.ptr)))
        else
            0;
    }
};

pub const Abbrev = struct {
    code: u64,
    tag_id: u64,
    has_children: bool,
    attrs: []Attr,

    fn deinit(abbrev: *Abbrev, allocator: Allocator) void {
        allocator.free(abbrev.attrs);
        abbrev.* = undefined;
    }

    const Attr = struct {
        id: u64,
        form_id: u64,
        /// Only valid if form_id is .implicit_const
        payload: i64,
    };

    const Table = struct {
        // offset from .debug_abbrev
        offset: u64,
        abbrevs: []Abbrev,

        fn deinit(table: *Table, allocator: Allocator) void {
            for (table.abbrevs) |*abbrev| {
                abbrev.deinit(allocator);
            }
            allocator.free(table.abbrevs);
            table.* = undefined;
        }

        fn get(table: *const Table, abbrev_code: u64) ?*const Abbrev {
            return for (table.abbrevs) |*abbrev| {
                if (abbrev.code == abbrev_code) break abbrev;
            } else null;
        }
    };
};

pub const CompileUnit = struct {
    version: u16,
    format: Format,
    die: Die,
    pc_range: ?PcRange,

    str_offsets_base: usize,
    addr_base: usize,
    rnglists_base: usize,
    loclists_base: usize,
    frame_base: ?*const FormValue,

    src_loc_cache: ?SrcLocCache,

    pub const SrcLocCache = struct {
        line_table: LineTable,
        directories: []const FileEntry,
        files: []FileEntry,
        version: u16,

        pub const LineTable = std.AutoArrayHashMapUnmanaged(u64, LineEntry);

        pub const LineEntry = struct {
            line: u32,
            column: u32,
            /// Offset by 1 depending on whether Dwarf version is >= 5.
            file: u32,

            pub const invalid: LineEntry = .{
                .line = undefined,
                .column = undefined,
                .file = std.math.maxInt(u32),
            };

            pub fn isInvalid(le: LineEntry) bool {
                return le.file == invalid.file;
            }
        };

        pub fn findSource(slc: *const SrcLocCache, address: u64) !LineEntry {
            const index = std.sort.upperBound(u64, slc.line_table.keys(), address, struct {
                fn order(context: u64, item: u64) std.math.Order {
                    return std.math.order(context, item);
                }
            }.order);
            if (index == 0) return missing();
            return slc.line_table.values()[index - 1];
        }
    };
};

pub const FormValue = union(enum) {
    addr: u64,
    addrx: usize,
    block: []const u8,
    udata: u64,
    data16: *const [16]u8,
    sdata: i64,
    exprloc: []const u8,
    flag: bool,
    sec_offset: u64,
    ref: u64,
    ref_addr: u64,
    string: [:0]const u8,
    strp: u64,
    strx: usize,
    line_strp: u64,
    loclistx: u64,
    rnglistx: u64,

    fn getString(fv: FormValue, di: Dwarf) ![:0]const u8 {
        switch (fv) {
            .string => |s| return s,
            .strp => |off| return di.getString(off),
            .line_strp => |off| return di.getLineString(off),
            else => return bad(),
        }
    }

    fn getUInt(fv: FormValue, comptime U: type) !U {
        return switch (fv) {
            inline .udata,
            .sdata,
            .sec_offset,
            => |c| cast(U, c) orelse bad(),
            else => bad(),
        };
    }
};

pub const Die = struct {
    tag_id: u64,
    has_children: bool,
    attrs: []Attr,

    const Attr = struct {
        id: u64,
        value: FormValue,
    };

    fn deinit(self: *Die, allocator: Allocator) void {
        allocator.free(self.attrs);
        self.* = undefined;
    }

    fn getAttr(self: *const Die, id: u64) ?*const FormValue {
        for (self.attrs) |*attr| {
            if (attr.id == id) return &attr.value;
        }
        return null;
    }

    fn getAttrAddr(
        self: *const Die,
        di: *const Dwarf,
        id: u64,
        compile_unit: CompileUnit,
    ) error{ InvalidDebugInfo, MissingDebugInfo }!u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            .addr => |value| value,
            .addrx => |index| di.readDebugAddr(compile_unit, index),
            else => bad(),
        };
    }

    fn getAttrSecOffset(self: *const Die, id: u64) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return form_value.getUInt(u64);
    }

    fn getAttrUnsignedLe(self: *const Die, id: u64) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            .Const => |value| value.asUnsignedLe(),
            else => bad(),
        };
    }

    fn getAttrRef(self: *const Die, id: u64, unit_offset: u64, unit_len: u64) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            .ref => |offset| if (offset < unit_len) unit_offset + offset else bad(),
            .ref_addr => |addr| addr,
            else => bad(),
        };
    }

    pub fn getAttrString(
        self: *const Die,
        di: *Dwarf,
        id: u64,
        opt_str: ?[]const u8,
        compile_unit: CompileUnit,
    ) error{ InvalidDebugInfo, MissingDebugInfo }![]const u8 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        switch (form_value.*) {
            .string => |value| return value,
            .strp => |offset| return di.getString(offset),
            .strx => |index| {
                const debug_str_offsets = di.section(.debug_str_offsets) orelse return bad();
                if (compile_unit.str_offsets_base == 0) return bad();
                switch (compile_unit.format) {
                    .@"32" => {
                        const byte_offset = compile_unit.str_offsets_base + 4 * index;
                        if (byte_offset + 4 > debug_str_offsets.len) return bad();
                        const offset = mem.readInt(u32, debug_str_offsets[byte_offset..][0..4], di.endian);
                        return getStringGeneric(opt_str, offset);
                    },
                    .@"64" => {
                        const byte_offset = compile_unit.str_offsets_base + 8 * index;
                        if (byte_offset + 8 > debug_str_offsets.len) return bad();
                        const offset = mem.readInt(u64, debug_str_offsets[byte_offset..][0..8], di.endian);
                        return getStringGeneric(opt_str, offset);
                    },
                }
            },
            .line_strp => |offset| return di.getLineString(offset),
            else => return bad(),
        }
    }
};

/// This represents the decoded .eh_frame_hdr header
pub const ExceptionFrameHeader = struct {
    eh_frame_ptr: usize,
    table_enc: u8,
    fde_count: usize,
    entries: []const u8,

    pub fn entrySize(table_enc: u8) !u8 {
        return switch (table_enc & EH.PE.type_mask) {
            EH.PE.udata2,
            EH.PE.sdata2,
            => 4,
            EH.PE.udata4,
            EH.PE.sdata4,
            => 8,
            EH.PE.udata8,
            EH.PE.sdata8,
            => 16,
            // This is a binary search table, so all entries must be the same length
            else => return bad(),
        };
    }

    fn isValidPtr(
        self: ExceptionFrameHeader,
        comptime T: type,
        ptr: usize,
        ma: *MemoryAccessor,
        eh_frame_len: ?usize,
    ) bool {
        if (eh_frame_len) |len| {
            return ptr >= self.eh_frame_ptr and ptr <= self.eh_frame_ptr + len - @sizeOf(T);
        } else {
            return ma.load(T, ptr) != null;
        }
    }

    /// Find an entry by binary searching the eh_frame_hdr section.
    ///
    /// Since the length of the eh_frame section (`eh_frame_len`) may not be known by the caller,
    /// MemoryAccessor will be used to verify readability of the header entries.
    /// If `eh_frame_len` is provided, then these checks can be skipped.
    pub fn findEntry(
        self: ExceptionFrameHeader,
        ma: *MemoryAccessor,
        eh_frame_len: ?usize,
        eh_frame_hdr_ptr: usize,
        pc: usize,
        cie: *CommonInformationEntry,
        fde: *FrameDescriptionEntry,
    ) !void {
        const entry_size = try entrySize(self.table_enc);

        var left: usize = 0;
        var len: usize = self.fde_count;

        var fbr: FixedBufferReader = .{ .buf = self.entries, .endian = native_endian };

        while (len > 1) {
            const mid = left + len / 2;

            fbr.pos = mid * entry_size;
            const pc_begin = try readEhPointer(&fbr, self.table_enc, @sizeOf(usize), .{
                .pc_rel_base = @intFromPtr(&self.entries[fbr.pos]),
                .follow_indirect = true,
                .data_rel_base = eh_frame_hdr_ptr,
            }) orelse return bad();

            if (pc < pc_begin) {
                len /= 2;
            } else {
                left = mid;
                if (pc == pc_begin) break;
                len -= len / 2;
            }
        }

        if (len == 0) return bad();
        fbr.pos = left * entry_size;

        // Read past the pc_begin field of the entry
        _ = try readEhPointer(&fbr, self.table_enc, @sizeOf(usize), .{
            .pc_rel_base = @intFromPtr(&self.entries[fbr.pos]),
            .follow_indirect = true,
            .data_rel_base = eh_frame_hdr_ptr,
        }) orelse return bad();

        const fde_ptr = cast(usize, try readEhPointer(&fbr, self.table_enc, @sizeOf(usize), .{
            .pc_rel_base = @intFromPtr(&self.entries[fbr.pos]),
            .follow_indirect = true,
            .data_rel_base = eh_frame_hdr_ptr,
        }) orelse return bad()) orelse return bad();

        if (fde_ptr < self.eh_frame_ptr) return bad();

        // Even if eh_frame_len is not specified, all ranges accssed are checked via MemoryAccessor
        const eh_frame = @as([*]const u8, @ptrFromInt(self.eh_frame_ptr))[0 .. eh_frame_len orelse maxInt(u32)];

        const fde_offset = fde_ptr - self.eh_frame_ptr;
        var eh_frame_fbr: FixedBufferReader = .{
            .buf = eh_frame,
            .pos = fde_offset,
            .endian = native_endian,
        };

        const fde_entry_header = try EntryHeader.read(&eh_frame_fbr, if (eh_frame_len == null) ma else null, .eh_frame);
        if (fde_entry_header.entry_bytes.len > 0 and !self.isValidPtr(u8, @intFromPtr(&fde_entry_header.entry_bytes[fde_entry_header.entry_bytes.len - 1]), ma, eh_frame_len)) return bad();
        if (fde_entry_header.type != .fde) return bad();

        // CIEs always come before FDEs (the offset is a subtraction), so we can assume this memory is readable
        const cie_offset = fde_entry_header.type.fde;
        try eh_frame_fbr.seekTo(cie_offset);
        const cie_entry_header = try EntryHeader.read(&eh_frame_fbr, if (eh_frame_len == null) ma else null, .eh_frame);
        if (cie_entry_header.entry_bytes.len > 0 and !self.isValidPtr(u8, @intFromPtr(&cie_entry_header.entry_bytes[cie_entry_header.entry_bytes.len - 1]), ma, eh_frame_len)) return bad();
        if (cie_entry_header.type != .cie) return bad();

        cie.* = try CommonInformationEntry.parse(
            cie_entry_header.entry_bytes,
            0,
            true,
            cie_entry_header.format,
            .eh_frame,
            cie_entry_header.length_offset,
            @sizeOf(usize),
            native_endian,
        );

        fde.* = try FrameDescriptionEntry.parse(
            fde_entry_header.entry_bytes,
            0,
            true,
            cie.*,
            @sizeOf(usize),
            native_endian,
        );
    }
};

pub const EntryHeader = struct {
    /// Offset of the length field in the backing buffer
    length_offset: usize,
    format: Format,
    type: union(enum) {
        cie,
        /// Value is the offset of the corresponding CIE
        fde: u64,
        terminator,
    },
    /// The entry's contents, not including the ID field
    entry_bytes: []const u8,

    /// The length of the entry including the ID field, but not the length field itself
    pub fn entryLength(self: EntryHeader) usize {
        return self.entry_bytes.len + @as(u8, if (self.format == .@"64") 8 else 4);
    }

    /// Reads a header for either an FDE or a CIE, then advances the fbr to the position after the trailing structure.
    /// `fbr` must be a FixedBufferReader backed by either the .eh_frame or .debug_frame sections.
    pub fn read(
        fbr: *FixedBufferReader,
        opt_ma: ?*MemoryAccessor,
        dwarf_section: Section.Id,
    ) !EntryHeader {
        assert(dwarf_section == .eh_frame or dwarf_section == .debug_frame);

        const length_offset = fbr.pos;
        const unit_header = try readUnitHeader(fbr, opt_ma);
        const unit_length = cast(usize, unit_header.unit_length) orelse return bad();
        if (unit_length == 0) return .{
            .length_offset = length_offset,
            .format = unit_header.format,
            .type = .terminator,
            .entry_bytes = &.{},
        };
        const start_offset = fbr.pos;
        const end_offset = start_offset + unit_length;
        defer fbr.pos = end_offset;

        const id = try if (opt_ma) |ma|
            fbr.readAddressChecked(unit_header.format, ma)
        else
            fbr.readAddress(unit_header.format);
        const entry_bytes = fbr.buf[fbr.pos..end_offset];
        const cie_id: u64 = switch (dwarf_section) {
            .eh_frame => CommonInformationEntry.eh_id,
            .debug_frame => switch (unit_header.format) {
                .@"32" => CommonInformationEntry.dwarf32_id,
                .@"64" => CommonInformationEntry.dwarf64_id,
            },
            else => unreachable,
        };

        return .{
            .length_offset = length_offset,
            .format = unit_header.format,
            .type = if (id == cie_id) .cie else .{ .fde = switch (dwarf_section) {
                .eh_frame => try std.math.sub(u64, start_offset, id),
                .debug_frame => id,
                else => unreachable,
            } },
            .entry_bytes = entry_bytes,
        };
    }
};

pub const CommonInformationEntry = struct {
    // Used in .eh_frame
    pub const eh_id = 0;

    // Used in .debug_frame (DWARF32)
    pub const dwarf32_id = maxInt(u32);

    // Used in .debug_frame (DWARF64)
    pub const dwarf64_id = maxInt(u64);

    // Offset of the length field of this entry in the eh_frame section.
    // This is the key that FDEs use to reference CIEs.
    length_offset: u64,
    version: u8,
    address_size: u8,
    format: Format,

    // Only present in version 4
    segment_selector_size: ?u8,

    code_alignment_factor: u32,
    data_alignment_factor: i32,
    return_address_register: u8,

    aug_str: []const u8,
    aug_data: []const u8,
    lsda_pointer_enc: u8,
    personality_enc: ?u8,
    personality_routine_pointer: ?u64,
    fde_pointer_enc: u8,
    initial_instructions: []const u8,

    pub fn isSignalFrame(self: CommonInformationEntry) bool {
        for (self.aug_str) |c| if (c == 'S') return true;
        return false;
    }

    pub fn addressesSignedWithBKey(self: CommonInformationEntry) bool {
        for (self.aug_str) |c| if (c == 'B') return true;
        return false;
    }

    pub fn mteTaggedFrame(self: CommonInformationEntry) bool {
        for (self.aug_str) |c| if (c == 'G') return true;
        return false;
    }

    /// This function expects to read the CIE starting with the version field.
    /// The returned struct references memory backed by cie_bytes.
    ///
    /// See the FrameDescriptionEntry.parse documentation for the description
    /// of `pc_rel_offset` and `is_runtime`.
    ///
    /// `length_offset` specifies the offset of this CIE's length field in the
    /// .eh_frame / .debug_frame section.
    pub fn parse(
        cie_bytes: []const u8,
        pc_rel_offset: i64,
        is_runtime: bool,
        format: Format,
        dwarf_section: Section.Id,
        length_offset: u64,
        addr_size_bytes: u8,
        endian: std.builtin.Endian,
    ) !CommonInformationEntry {
        if (addr_size_bytes > 8) return error.UnsupportedAddrSize;

        var fbr: FixedBufferReader = .{ .buf = cie_bytes, .endian = endian };

        const version = try fbr.readByte();
        switch (dwarf_section) {
            .eh_frame => if (version != 1 and version != 3) return error.UnsupportedDwarfVersion,
            .debug_frame => if (version != 4) return error.UnsupportedDwarfVersion,
            else => return error.UnsupportedDwarfSection,
        }

        var has_eh_data = false;
        var has_aug_data = false;

        var aug_str_len: usize = 0;
        const aug_str_start = fbr.pos;
        var aug_byte = try fbr.readByte();
        while (aug_byte != 0) : (aug_byte = try fbr.readByte()) {
            switch (aug_byte) {
                'z' => {
                    if (aug_str_len != 0) return bad();
                    has_aug_data = true;
                },
                'e' => {
                    if (has_aug_data or aug_str_len != 0) return bad();
                    if (try fbr.readByte() != 'h') return bad();
                    has_eh_data = true;
                },
                else => if (has_eh_data) return bad(),
            }

            aug_str_len += 1;
        }

        if (has_eh_data) {
            // legacy data created by older versions of gcc - unsupported here
            for (0..addr_size_bytes) |_| _ = try fbr.readByte();
        }

        const address_size = if (version == 4) try fbr.readByte() else addr_size_bytes;
        const segment_selector_size = if (version == 4) try fbr.readByte() else null;

        const code_alignment_factor = try fbr.readUleb128(u32);
        const data_alignment_factor = try fbr.readIleb128(i32);
        const return_address_register = if (version == 1) try fbr.readByte() else try fbr.readUleb128(u8);

        var lsda_pointer_enc: u8 = EH.PE.omit;
        var personality_enc: ?u8 = null;
        var personality_routine_pointer: ?u64 = null;
        var fde_pointer_enc: u8 = EH.PE.absptr;

        var aug_data: []const u8 = &[_]u8{};
        const aug_str = if (has_aug_data) blk: {
            const aug_data_len = try fbr.readUleb128(usize);
            const aug_data_start = fbr.pos;
            aug_data = cie_bytes[aug_data_start..][0..aug_data_len];

            const aug_str = cie_bytes[aug_str_start..][0..aug_str_len];
            for (aug_str[1..]) |byte| {
                switch (byte) {
                    'L' => {
                        lsda_pointer_enc = try fbr.readByte();
                    },
                    'P' => {
                        personality_enc = try fbr.readByte();
                        personality_routine_pointer = try readEhPointer(&fbr, personality_enc.?, addr_size_bytes, .{
                            .pc_rel_base = try pcRelBase(@intFromPtr(&cie_bytes[fbr.pos]), pc_rel_offset),
                            .follow_indirect = is_runtime,
                        });
                    },
                    'R' => {
                        fde_pointer_enc = try fbr.readByte();
                    },
                    'S', 'B', 'G' => {},
                    else => return bad(),
                }
            }

            // aug_data_len can include padding so the CIE ends on an address boundary
            fbr.pos = aug_data_start + aug_data_len;
            break :blk aug_str;
        } else &[_]u8{};

        const initial_instructions = cie_bytes[fbr.pos..];
        return .{
            .length_offset = length_offset,
            .version = version,
            .address_size = address_size,
            .format = format,
            .segment_selector_size = segment_selector_size,
            .code_alignment_factor = code_alignment_factor,
            .data_alignment_factor = data_alignment_factor,
            .return_address_register = return_address_register,
            .aug_str = aug_str,
            .aug_data = aug_data,
            .lsda_pointer_enc = lsda_pointer_enc,
            .personality_enc = personality_enc,
            .personality_routine_pointer = personality_routine_pointer,
            .fde_pointer_enc = fde_pointer_enc,
            .initial_instructions = initial_instructions,
        };
    }
};

pub const FrameDescriptionEntry = struct {
    // Offset into eh_frame where the CIE for this FDE is stored
    cie_length_offset: u64,

    pc_begin: u64,
    pc_range: u64,
    lsda_pointer: ?u64,
    aug_data: []const u8,
    instructions: []const u8,

    /// This function expects to read the FDE starting at the PC Begin field.
    /// The returned struct references memory backed by `fde_bytes`.
    ///
    /// `pc_rel_offset` specifies an offset to be applied to pc_rel_base values
    /// used when decoding pointers. This should be set to zero if fde_bytes is
    /// backed by the memory of a .eh_frame / .debug_frame section in the running executable.
    /// Otherwise, it should be the relative offset to translate addresses from
    /// where the section is currently stored in memory, to where it *would* be
    /// stored at runtime: section base addr - backing data base ptr.
    ///
    /// Similarly, `is_runtime` specifies this function is being called on a runtime
    /// section, and so indirect pointers can be followed.
    pub fn parse(
        fde_bytes: []const u8,
        pc_rel_offset: i64,
        is_runtime: bool,
        cie: CommonInformationEntry,
        addr_size_bytes: u8,
        endian: std.builtin.Endian,
    ) !FrameDescriptionEntry {
        if (addr_size_bytes > 8) return error.InvalidAddrSize;

        var fbr: FixedBufferReader = .{ .buf = fde_bytes, .endian = endian };

        const pc_begin = try readEhPointer(&fbr, cie.fde_pointer_enc, addr_size_bytes, .{
            .pc_rel_base = try pcRelBase(@intFromPtr(&fde_bytes[fbr.pos]), pc_rel_offset),
            .follow_indirect = is_runtime,
        }) orelse return bad();

        const pc_range = try readEhPointer(&fbr, cie.fde_pointer_enc, addr_size_bytes, .{
            .pc_rel_base = 0,
            .follow_indirect = false,
        }) orelse return bad();

        var aug_data: []const u8 = &[_]u8{};
        const lsda_pointer = if (cie.aug_str.len > 0) blk: {
            const aug_data_len = try fbr.readUleb128(usize);
            const aug_data_start = fbr.pos;
            aug_data = fde_bytes[aug_data_start..][0..aug_data_len];

            const lsda_pointer = if (cie.lsda_pointer_enc != EH.PE.omit)
                try readEhPointer(&fbr, cie.lsda_pointer_enc, addr_size_bytes, .{
                    .pc_rel_base = try pcRelBase(@intFromPtr(&fde_bytes[fbr.pos]), pc_rel_offset),
                    .follow_indirect = is_runtime,
                })
            else
                null;

            fbr.pos = aug_data_start + aug_data_len;
            break :blk lsda_pointer;
        } else null;

        const instructions = fde_bytes[fbr.pos..];
        return .{
            .cie_length_offset = cie.length_offset,
            .pc_begin = pc_begin,
            .pc_range = pc_range,
            .lsda_pointer = lsda_pointer,
            .aug_data = aug_data,
            .instructions = instructions,
        };
    }
};

const num_sections = std.enums.directEnumArrayLen(Section.Id, 0);
pub const SectionArray = [num_sections]?Section;
pub const null_section_array = [_]?Section{null} ** num_sections;

pub const OpenError = ScanError;

/// Initialize DWARF info. The caller has the responsibility to initialize most
/// the `Dwarf` fields before calling. `binary_mem` is the raw bytes of the
/// main binary file (not the secondary debug info file).
pub fn open(d: *Dwarf, gpa: Allocator) OpenError!void {
    try d.scanAllFunctions(gpa);
    try d.scanAllCompileUnits(gpa);
}

const PcRange = struct {
    start: u64,
    end: u64,
};

const Func = struct {
    pc_range: ?PcRange,
    name: ?[]const u8,
};

pub fn section(di: Dwarf, dwarf_section: Section.Id) ?[]const u8 {
    return if (di.sections[@intFromEnum(dwarf_section)]) |s| s.data else null;
}

pub fn sectionVirtualOffset(di: Dwarf, dwarf_section: Section.Id, base_address: usize) ?i64 {
    return if (di.sections[@intFromEnum(dwarf_section)]) |s| s.virtualOffset(base_address) else null;
}

pub fn deinit(di: *Dwarf, gpa: Allocator) void {
    for (di.sections) |opt_section| {
        if (opt_section) |s| if (s.owned) gpa.free(s.data);
    }
    for (di.abbrev_table_list.items) |*abbrev| {
        abbrev.deinit(gpa);
    }
    di.abbrev_table_list.deinit(gpa);
    for (di.compile_unit_list.items) |*cu| {
        if (cu.src_loc_cache) |*slc| {
            slc.line_table.deinit(gpa);
            gpa.free(slc.directories);
            gpa.free(slc.files);
        }
        cu.die.deinit(gpa);
    }
    di.compile_unit_list.deinit(gpa);
    di.func_list.deinit(gpa);
    di.cie_map.deinit(gpa);
    di.fde_list.deinit(gpa);
    di.ranges.deinit(gpa);
    di.* = undefined;
}

pub fn getSymbolName(di: *Dwarf, address: u64) ?[]const u8 {
    for (di.func_list.items) |*func| {
        if (func.pc_range) |range| {
            if (address >= range.start and address < range.end) {
                return func.name;
            }
        }
    }

    return null;
}

pub const ScanError = error{
    InvalidDebugInfo,
    MissingDebugInfo,
} || Allocator.Error || std.debug.FixedBufferReader.Error;

fn scanAllFunctions(di: *Dwarf, allocator: Allocator) ScanError!void {
    var fbr: FixedBufferReader = .{ .buf = di.section(.debug_info).?, .endian = di.endian };
    var this_unit_offset: u64 = 0;

    while (this_unit_offset < fbr.buf.len) {
        try fbr.seekTo(this_unit_offset);

        const unit_header = try readUnitHeader(&fbr, null);
        if (unit_header.unit_length == 0) return;
        const next_offset = unit_header.header_length + unit_header.unit_length;

        const version = try fbr.readInt(u16);
        if (version < 2 or version > 5) return bad();

        var address_size: u8 = undefined;
        var debug_abbrev_offset: u64 = undefined;
        if (version >= 5) {
            const unit_type = try fbr.readInt(u8);
            if (unit_type != DW.UT.compile) return bad();
            address_size = try fbr.readByte();
            debug_abbrev_offset = try fbr.readAddress(unit_header.format);
        } else {
            debug_abbrev_offset = try fbr.readAddress(unit_header.format);
            address_size = try fbr.readByte();
        }
        if (address_size != @sizeOf(usize)) return bad();

        const abbrev_table = try di.getAbbrevTable(allocator, debug_abbrev_offset);

        var max_attrs: usize = 0;
        var zig_padding_abbrev_code: u7 = 0;
        for (abbrev_table.abbrevs) |abbrev| {
            max_attrs = @max(max_attrs, abbrev.attrs.len);
            if (cast(u7, abbrev.code)) |code| {
                if (abbrev.tag_id == DW.TAG.ZIG_padding and
                    !abbrev.has_children and
                    abbrev.attrs.len == 0)
                {
                    zig_padding_abbrev_code = code;
                }
            }
        }
        const attrs_buf = try allocator.alloc(Die.Attr, max_attrs * 3);
        defer allocator.free(attrs_buf);
        var attrs_bufs: [3][]Die.Attr = undefined;
        for (&attrs_bufs, 0..) |*buf, index| buf.* = attrs_buf[index * max_attrs ..][0..max_attrs];

        const next_unit_pos = this_unit_offset + next_offset;

        var compile_unit: CompileUnit = .{
            .version = version,
            .format = unit_header.format,
            .die = undefined,
            .pc_range = null,

            .str_offsets_base = 0,
            .addr_base = 0,
            .rnglists_base = 0,
            .loclists_base = 0,
            .frame_base = null,
            .src_loc_cache = null,
        };

        while (true) {
            fbr.pos = std.mem.indexOfNonePos(u8, fbr.buf, fbr.pos, &.{
                zig_padding_abbrev_code, 0,
            }) orelse fbr.buf.len;
            if (fbr.pos >= next_unit_pos) break;
            var die_obj = (try parseDie(
                &fbr,
                attrs_bufs[0],
                abbrev_table,
                unit_header.format,
            )) orelse continue;

            switch (die_obj.tag_id) {
                DW.TAG.compile_unit => {
                    compile_unit.die = die_obj;
                    compile_unit.die.attrs = attrs_bufs[1][0..die_obj.attrs.len];
                    @memcpy(compile_unit.die.attrs, die_obj.attrs);

                    compile_unit.str_offsets_base = if (die_obj.getAttr(AT.str_offsets_base)) |fv| try fv.getUInt(usize) else 0;
                    compile_unit.addr_base = if (die_obj.getAttr(AT.addr_base)) |fv| try fv.getUInt(usize) else 0;
                    compile_unit.rnglists_base = if (die_obj.getAttr(AT.rnglists_base)) |fv| try fv.getUInt(usize) else 0;
                    compile_unit.loclists_base = if (die_obj.getAttr(AT.loclists_base)) |fv| try fv.getUInt(usize) else 0;
                    compile_unit.frame_base = die_obj.getAttr(AT.frame_base);
                },
                DW.TAG.subprogram, DW.TAG.inlined_subroutine, DW.TAG.subroutine, DW.TAG.entry_point => {
                    const fn_name = x: {
                        var this_die_obj = die_obj;
                        // Prevent endless loops
                        for (0..3) |_| {
                            if (this_die_obj.getAttr(AT.name)) |_| {
                                break :x try this_die_obj.getAttrString(di, AT.name, di.section(.debug_str), compile_unit);
                            } else if (this_die_obj.getAttr(AT.abstract_origin)) |_| {
                                const after_die_offset = fbr.pos;
                                defer fbr.pos = after_die_offset;

                                // Follow the DIE it points to and repeat
                                const ref_offset = try this_die_obj.getAttrRef(AT.abstract_origin, this_unit_offset, next_offset);
                                try fbr.seekTo(ref_offset);
                                this_die_obj = (try parseDie(
                                    &fbr,
                                    attrs_bufs[2],
                                    abbrev_table, // wrong abbrev table for different cu
                                    unit_header.format,
                                )) orelse return bad();
                            } else if (this_die_obj.getAttr(AT.specification)) |_| {
                                const after_die_offset = fbr.pos;
                                defer fbr.pos = after_die_offset;

                                // Follow the DIE it points to and repeat
                                const ref_offset = try this_die_obj.getAttrRef(AT.specification, this_unit_offset, next_offset);
                                try fbr.seekTo(ref_offset);
                                this_die_obj = (try parseDie(
                                    &fbr,
                                    attrs_bufs[2],
                                    abbrev_table, // wrong abbrev table for different cu
                                    unit_header.format,
                                )) orelse return bad();
                            } else {
                                break :x null;
                            }
                        }

                        break :x null;
                    };

                    var range_added = if (die_obj.getAttrAddr(di, AT.low_pc, compile_unit)) |low_pc| blk: {
                        if (die_obj.getAttr(AT.high_pc)) |high_pc_value| {
                            const pc_end = switch (high_pc_value.*) {
                                .addr => |value| value,
                                .udata => |offset| low_pc + offset,
                                else => return bad(),
                            };

                            try di.func_list.append(allocator, .{
                                .name = fn_name,
                                .pc_range = .{
                                    .start = low_pc,
                                    .end = pc_end,
                                },
                            });

                            break :blk true;
                        }

                        break :blk false;
                    } else |err| blk: {
                        if (err != error.MissingDebugInfo) return err;
                        break :blk false;
                    };

                    if (die_obj.getAttr(AT.ranges)) |ranges_value| blk: {
                        var iter = DebugRangeIterator.init(ranges_value, di, &compile_unit) catch |err| {
                            if (err != error.MissingDebugInfo) return err;
                            break :blk;
                        };

                        while (try iter.next()) |range| {
                            range_added = true;
                            try di.func_list.append(allocator, .{
                                .name = fn_name,
                                .pc_range = .{
                                    .start = range.start,
                                    .end = range.end,
                                },
                            });
                        }
                    }

                    if (fn_name != null and !range_added) {
                        try di.func_list.append(allocator, .{
                            .name = fn_name,
                            .pc_range = null,
                        });
                    }
                },
                else => {},
            }
        }

        this_unit_offset += next_offset;
    }
}

fn scanAllCompileUnits(di: *Dwarf, allocator: Allocator) ScanError!void {
    var fbr: FixedBufferReader = .{ .buf = di.section(.debug_info).?, .endian = di.endian };
    var this_unit_offset: u64 = 0;

    var attrs_buf = std.ArrayList(Die.Attr).init(allocator);
    defer attrs_buf.deinit();

    while (this_unit_offset < fbr.buf.len) {
        try fbr.seekTo(this_unit_offset);

        const unit_header = try readUnitHeader(&fbr, null);
        if (unit_header.unit_length == 0) return;
        const next_offset = unit_header.header_length + unit_header.unit_length;

        const version = try fbr.readInt(u16);
        if (version < 2 or version > 5) return bad();

        var address_size: u8 = undefined;
        var debug_abbrev_offset: u64 = undefined;
        if (version >= 5) {
            const unit_type = try fbr.readInt(u8);
            if (unit_type != UT.compile) return bad();
            address_size = try fbr.readByte();
            debug_abbrev_offset = try fbr.readAddress(unit_header.format);
        } else {
            debug_abbrev_offset = try fbr.readAddress(unit_header.format);
            address_size = try fbr.readByte();
        }
        if (address_size != @sizeOf(usize)) return bad();

        const abbrev_table = try di.getAbbrevTable(allocator, debug_abbrev_offset);

        var max_attrs: usize = 0;
        for (abbrev_table.abbrevs) |abbrev| {
            max_attrs = @max(max_attrs, abbrev.attrs.len);
        }
        try attrs_buf.resize(max_attrs);

        var compile_unit_die = (try parseDie(
            &fbr,
            attrs_buf.items,
            abbrev_table,
            unit_header.format,
        )) orelse return bad();

        if (compile_unit_die.tag_id != DW.TAG.compile_unit) return bad();

        compile_unit_die.attrs = try allocator.dupe(Die.Attr, compile_unit_die.attrs);

        var compile_unit: CompileUnit = .{
            .version = version,
            .format = unit_header.format,
            .pc_range = null,
            .die = compile_unit_die,
            .str_offsets_base = if (compile_unit_die.getAttr(AT.str_offsets_base)) |fv| try fv.getUInt(usize) else 0,
            .addr_base = if (compile_unit_die.getAttr(AT.addr_base)) |fv| try fv.getUInt(usize) else 0,
            .rnglists_base = if (compile_unit_die.getAttr(AT.rnglists_base)) |fv| try fv.getUInt(usize) else 0,
            .loclists_base = if (compile_unit_die.getAttr(AT.loclists_base)) |fv| try fv.getUInt(usize) else 0,
            .frame_base = compile_unit_die.getAttr(AT.frame_base),
            .src_loc_cache = null,
        };

        compile_unit.pc_range = x: {
            if (compile_unit_die.getAttrAddr(di, AT.low_pc, compile_unit)) |low_pc| {
                if (compile_unit_die.getAttr(AT.high_pc)) |high_pc_value| {
                    const pc_end = switch (high_pc_value.*) {
                        .addr => |value| value,
                        .udata => |offset| low_pc + offset,
                        else => return bad(),
                    };
                    break :x PcRange{
                        .start = low_pc,
                        .end = pc_end,
                    };
                } else {
                    break :x null;
                }
            } else |err| {
                if (err != error.MissingDebugInfo) return err;
                break :x null;
            }
        };

        try di.compile_unit_list.append(allocator, compile_unit);

        this_unit_offset += next_offset;
    }
}

pub fn populateRanges(d: *Dwarf, gpa: Allocator) ScanError!void {
    assert(d.ranges.items.len == 0);

    for (d.compile_unit_list.items, 0..) |*cu, cu_index| {
        if (cu.pc_range) |range| {
            try d.ranges.append(gpa, .{
                .start = range.start,
                .end = range.end,
                .compile_unit_index = cu_index,
            });
            continue;
        }
        const ranges_value = cu.die.getAttr(AT.ranges) orelse continue;
        var iter = DebugRangeIterator.init(ranges_value, d, cu) catch continue;
        while (try iter.next()) |range| {
            // Not sure why LLVM thinks it's OK to emit these...
            if (range.start == range.end) continue;

            try d.ranges.append(gpa, .{
                .start = range.start,
                .end = range.end,
                .compile_unit_index = cu_index,
            });
        }
    }

    std.mem.sortUnstable(Range, d.ranges.items, {}, struct {
        pub fn lessThan(ctx: void, a: Range, b: Range) bool {
            _ = ctx;
            return a.start < b.start;
        }
    }.lessThan);
}

const DebugRangeIterator = struct {
    base_address: u64,
    section_type: Section.Id,
    di: *const Dwarf,
    compile_unit: *const CompileUnit,
    fbr: FixedBufferReader,

    pub fn init(ranges_value: *const FormValue, di: *const Dwarf, compile_unit: *const CompileUnit) !@This() {
        const section_type = if (compile_unit.version >= 5) Section.Id.debug_rnglists else Section.Id.debug_ranges;
        const debug_ranges = di.section(section_type) orelse return error.MissingDebugInfo;

        const ranges_offset = switch (ranges_value.*) {
            .sec_offset, .udata => |off| off,
            .rnglistx => |idx| off: {
                switch (compile_unit.format) {
                    .@"32" => {
                        const offset_loc = @as(usize, @intCast(compile_unit.rnglists_base + 4 * idx));
                        if (offset_loc + 4 > debug_ranges.len) return bad();
                        const offset = mem.readInt(u32, debug_ranges[offset_loc..][0..4], di.endian);
                        break :off compile_unit.rnglists_base + offset;
                    },
                    .@"64" => {
                        const offset_loc = @as(usize, @intCast(compile_unit.rnglists_base + 8 * idx));
                        if (offset_loc + 8 > debug_ranges.len) return bad();
                        const offset = mem.readInt(u64, debug_ranges[offset_loc..][0..8], di.endian);
                        break :off compile_unit.rnglists_base + offset;
                    },
                }
            },
            else => return bad(),
        };

        // All the addresses in the list are relative to the value
        // specified by DW_AT.low_pc or to some other value encoded
        // in the list itself.
        // If no starting value is specified use zero.
        const base_address = compile_unit.die.getAttrAddr(di, AT.low_pc, compile_unit.*) catch |err| switch (err) {
            error.MissingDebugInfo => 0,
            else => return err,
        };

        return .{
            .base_address = base_address,
            .section_type = section_type,
            .di = di,
            .compile_unit = compile_unit,
            .fbr = .{
                .buf = debug_ranges,
                .pos = cast(usize, ranges_offset) orelse return bad(),
                .endian = di.endian,
            },
        };
    }

    // Returns the next range in the list, or null if the end was reached.
    pub fn next(self: *@This()) !?PcRange {
        switch (self.section_type) {
            .debug_rnglists => {
                const kind = try self.fbr.readByte();
                switch (kind) {
                    RLE.end_of_list => return null,
                    RLE.base_addressx => {
                        const index = try self.fbr.readUleb128(usize);
                        self.base_address = try self.di.readDebugAddr(self.compile_unit.*, index);
                        return try self.next();
                    },
                    RLE.startx_endx => {
                        const start_index = try self.fbr.readUleb128(usize);
                        const start_addr = try self.di.readDebugAddr(self.compile_unit.*, start_index);

                        const end_index = try self.fbr.readUleb128(usize);
                        const end_addr = try self.di.readDebugAddr(self.compile_unit.*, end_index);

                        return .{
                            .start = start_addr,
                            .end = end_addr,
                        };
                    },
                    RLE.startx_length => {
                        const start_index = try self.fbr.readUleb128(usize);
                        const start_addr = try self.di.readDebugAddr(self.compile_unit.*, start_index);

                        const len = try self.fbr.readUleb128(usize);
                        const end_addr = start_addr + len;

                        return .{
                            .start = start_addr,
                            .end = end_addr,
                        };
                    },
                    RLE.offset_pair => {
                        const start_addr = try self.fbr.readUleb128(usize);
                        const end_addr = try self.fbr.readUleb128(usize);

                        // This is the only kind that uses the base address
                        return .{
                            .start = self.base_address + start_addr,
                            .end = self.base_address + end_addr,
                        };
                    },
                    RLE.base_address => {
                        self.base_address = try self.fbr.readInt(usize);
                        return try self.next();
                    },
                    RLE.start_end => {
                        const start_addr = try self.fbr.readInt(usize);
                        const end_addr = try self.fbr.readInt(usize);

                        return .{
                            .start = start_addr,
                            .end = end_addr,
                        };
                    },
                    RLE.start_length => {
                        const start_addr = try self.fbr.readInt(usize);
                        const len = try self.fbr.readUleb128(usize);
                        const end_addr = start_addr + len;

                        return .{
                            .start = start_addr,
                            .end = end_addr,
                        };
                    },
                    else => return bad(),
                }
            },
            .debug_ranges => {
                const start_addr = try self.fbr.readInt(usize);
                const end_addr = try self.fbr.readInt(usize);
                if (start_addr == 0 and end_addr == 0) return null;

                // This entry selects a new value for the base address
                if (start_addr == maxInt(usize)) {
                    self.base_address = end_addr;
                    return try self.next();
                }

                return .{
                    .start = self.base_address + start_addr,
                    .end = self.base_address + end_addr,
                };
            },
            else => unreachable,
        }
    }
};

/// TODO: change this to binary searching the sorted compile unit list
pub fn findCompileUnit(di: *const Dwarf, target_address: u64) !*CompileUnit {
    for (di.compile_unit_list.items) |*compile_unit| {
        if (compile_unit.pc_range) |range| {
            if (target_address >= range.start and target_address < range.end) return compile_unit;
        }

        const ranges_value = compile_unit.die.getAttr(AT.ranges) orelse continue;
        var iter = DebugRangeIterator.init(ranges_value, di, compile_unit) catch continue;
        while (try iter.next()) |range| {
            if (target_address >= range.start and target_address < range.end) return compile_unit;
        }
    }

    return missing();
}

/// Gets an already existing AbbrevTable given the abbrev_offset, or if not found,
/// seeks in the stream and parses it.
fn getAbbrevTable(di: *Dwarf, allocator: Allocator, abbrev_offset: u64) !*const Abbrev.Table {
    for (di.abbrev_table_list.items) |*table| {
        if (table.offset == abbrev_offset) {
            return table;
        }
    }
    try di.abbrev_table_list.append(
        allocator,
        try di.parseAbbrevTable(allocator, abbrev_offset),
    );
    return &di.abbrev_table_list.items[di.abbrev_table_list.items.len - 1];
}

fn parseAbbrevTable(di: *Dwarf, allocator: Allocator, offset: u64) !Abbrev.Table {
    var fbr: FixedBufferReader = .{
        .buf = di.section(.debug_abbrev).?,
        .pos = cast(usize, offset) orelse return bad(),
        .endian = di.endian,
    };

    var abbrevs = std.ArrayList(Abbrev).init(allocator);
    defer {
        for (abbrevs.items) |*abbrev| {
            abbrev.deinit(allocator);
        }
        abbrevs.deinit();
    }

    var attrs = std.ArrayList(Abbrev.Attr).init(allocator);
    defer attrs.deinit();

    while (true) {
        const code = try fbr.readUleb128(u64);
        if (code == 0) break;
        const tag_id = try fbr.readUleb128(u64);
        const has_children = (try fbr.readByte()) == DW.CHILDREN.yes;

        while (true) {
            const attr_id = try fbr.readUleb128(u64);
            const form_id = try fbr.readUleb128(u64);
            if (attr_id == 0 and form_id == 0) break;
            try attrs.append(.{
                .id = attr_id,
                .form_id = form_id,
                .payload = switch (form_id) {
                    FORM.implicit_const => try fbr.readIleb128(i64),
                    else => undefined,
                },
            });
        }

        try abbrevs.append(.{
            .code = code,
            .tag_id = tag_id,
            .has_children = has_children,
            .attrs = try attrs.toOwnedSlice(),
        });
    }

    return .{
        .offset = offset,
        .abbrevs = try abbrevs.toOwnedSlice(),
    };
}

fn parseDie(
    fbr: *FixedBufferReader,
    attrs_buf: []Die.Attr,
    abbrev_table: *const Abbrev.Table,
    format: Format,
) ScanError!?Die {
    const abbrev_code = try fbr.readUleb128(u64);
    if (abbrev_code == 0) return null;
    const table_entry = abbrev_table.get(abbrev_code) orelse return bad();

    const attrs = attrs_buf[0..table_entry.attrs.len];
    for (attrs, table_entry.attrs) |*result_attr, attr| result_attr.* = Die.Attr{
        .id = attr.id,
        .value = try parseFormValue(
            fbr,
            attr.form_id,
            format,
            attr.payload,
        ),
    };
    return .{
        .tag_id = table_entry.tag_id,
        .has_children = table_entry.has_children,
        .attrs = attrs,
    };
}

/// Ensures that addresses in the returned LineTable are monotonically increasing.
fn runLineNumberProgram(d: *Dwarf, gpa: Allocator, compile_unit: *CompileUnit) !CompileUnit.SrcLocCache {
    const compile_unit_cwd = try compile_unit.die.getAttrString(d, AT.comp_dir, d.section(.debug_line_str), compile_unit.*);
    const line_info_offset = try compile_unit.die.getAttrSecOffset(AT.stmt_list);

    var fbr: FixedBufferReader = .{
        .buf = d.section(.debug_line).?,
        .endian = d.endian,
    };
    try fbr.seekTo(line_info_offset);

    const unit_header = try readUnitHeader(&fbr, null);
    if (unit_header.unit_length == 0) return missing();

    const next_offset = unit_header.header_length + unit_header.unit_length;

    const version = try fbr.readInt(u16);
    if (version < 2) return bad();

    const addr_size: u8, const seg_size: u8 = if (version >= 5) .{
        try fbr.readByte(),
        try fbr.readByte(),
    } else .{
        switch (unit_header.format) {
            .@"32" => 4,
            .@"64" => 8,
        },
        0,
    };
    _ = addr_size;
    _ = seg_size;

    const prologue_length = try fbr.readAddress(unit_header.format);
    const prog_start_offset = fbr.pos + prologue_length;

    const minimum_instruction_length = try fbr.readByte();
    if (minimum_instruction_length == 0) return bad();

    if (version >= 4) {
        const maximum_operations_per_instruction = try fbr.readByte();
        _ = maximum_operations_per_instruction;
    }

    const default_is_stmt = (try fbr.readByte()) != 0;
    const line_base = try fbr.readByteSigned();

    const line_range = try fbr.readByte();
    if (line_range == 0) return bad();

    const opcode_base = try fbr.readByte();

    const standard_opcode_lengths = try fbr.readBytes(opcode_base - 1);

    var directories: std.ArrayListUnmanaged(FileEntry) = .empty;
    defer directories.deinit(gpa);
    var file_entries: std.ArrayListUnmanaged(FileEntry) = .empty;
    defer file_entries.deinit(gpa);

    if (version < 5) {
        try directories.append(gpa, .{ .path = compile_unit_cwd });

        while (true) {
            const dir = try fbr.readBytesTo(0);
            if (dir.len == 0) break;
            try directories.append(gpa, .{ .path = dir });
        }

        while (true) {
            const file_name = try fbr.readBytesTo(0);
            if (file_name.len == 0) break;
            const dir_index = try fbr.readUleb128(u32);
            const mtime = try fbr.readUleb128(u64);
            const size = try fbr.readUleb128(u64);
            try file_entries.append(gpa, .{
                .path = file_name,
                .dir_index = dir_index,
                .mtime = mtime,
                .size = size,
            });
        }
    } else {
        const FileEntFmt = struct {
            content_type_code: u16,
            form_code: u16,
        };
        {
            var dir_ent_fmt_buf: [10]FileEntFmt = undefined;
            const directory_entry_format_count = try fbr.readByte();
            if (directory_entry_format_count > dir_ent_fmt_buf.len) return bad();
            for (dir_ent_fmt_buf[0..directory_entry_format_count]) |*ent_fmt| {
                ent_fmt.* = .{
                    .content_type_code = try fbr.readUleb128(u8),
                    .form_code = try fbr.readUleb128(u16),
                };
            }

            const directories_count = try fbr.readUleb128(usize);

            for (try directories.addManyAsSlice(gpa, directories_count)) |*e| {
                e.* = .{ .path = &.{} };
                for (dir_ent_fmt_buf[0..directory_entry_format_count]) |ent_fmt| {
                    const form_value = try parseFormValue(
                        &fbr,
                        ent_fmt.form_code,
                        unit_header.format,
                        null,
                    );
                    switch (ent_fmt.content_type_code) {
                        DW.LNCT.path => e.path = try form_value.getString(d.*),
                        DW.LNCT.directory_index => e.dir_index = try form_value.getUInt(u32),
                        DW.LNCT.timestamp => e.mtime = try form_value.getUInt(u64),
                        DW.LNCT.size => e.size = try form_value.getUInt(u64),
                        DW.LNCT.MD5 => e.md5 = switch (form_value) {
                            .data16 => |data16| data16.*,
                            else => return bad(),
                        },
                        else => continue,
                    }
                }
            }
        }

        var file_ent_fmt_buf: [10]FileEntFmt = undefined;
        const file_name_entry_format_count = try fbr.readByte();
        if (file_name_entry_format_count > file_ent_fmt_buf.len) return bad();
        for (file_ent_fmt_buf[0..file_name_entry_format_count]) |*ent_fmt| {
            ent_fmt.* = .{
                .content_type_code = try fbr.readUleb128(u16),
                .form_code = try fbr.readUleb128(u16),
            };
        }

        const file_names_count = try fbr.readUleb128(usize);
        try file_entries.ensureUnusedCapacity(gpa, file_names_count);

        for (try file_entries.addManyAsSlice(gpa, file_names_count)) |*e| {
            e.* = .{ .path = &.{} };
            for (file_ent_fmt_buf[0..file_name_entry_format_count]) |ent_fmt| {
                const form_value = try parseFormValue(
                    &fbr,
                    ent_fmt.form_code,
                    unit_header.format,
                    null,
                );
                switch (ent_fmt.content_type_code) {
                    DW.LNCT.path => e.path = ```
