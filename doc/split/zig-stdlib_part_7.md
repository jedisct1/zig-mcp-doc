```
 .{
        .root_dir = ws.zig_lib_directory,
        .sub_path = "docs/wasm/html_render.zig",
    };

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;

    try argv.appendSlice(arena, &.{
        ws.zig_exe_path, "build-exe", //
        "-fno-entry", //
        "-O", @tagName(optimize_mode), //
        "-target", fuzzer_arch_os_abi, //
        "-mcpu", fuzzer_cpu_features, //
        "--cache-dir", ws.global_cache_directory.path orelse ".", //
        "--global-cache-dir", ws.global_cache_directory.path orelse ".", //
        "--name", fuzzer_bin_name, //
        "-rdynamic", //
        "-fsingle-threaded", //
        "--dep", "Walk", //
        "--dep", "html_render", //
        try std.fmt.allocPrint(arena, "-Mroot={}", .{main_src_path}), //
        try std.fmt.allocPrint(arena, "-MWalk={}", .{walk_src_path}), //
        "--dep", "Walk", //
        try std.fmt.allocPrint(arena, "-Mhtml_render={}", .{html_render_src_path}), //
        "--listen=-",
    });

    var child = std.process.Child.init(argv.items, gpa);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var poller = std.io.poll(gpa, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    try sendMessage(child.stdin.?, .update);
    try sendMessage(child.stdin.?, .exit);

    const Header = std.zig.Server.Message.Header;
    var result: ?Path = null;
    var result_error_bundle = std.zig.ErrorBundle.empty;

    const stdout = poller.fifo(.stdout);

    poll: while (true) {
        while (stdout.readableLength() < @sizeOf(Header)) {
            if (!(try poller.poll())) break :poll;
        }
        const header = stdout.reader().readStruct(Header) catch unreachable;
        while (stdout.readableLength() < header.bytes_len) {
            if (!(try poller.poll())) break :poll;
        }
        const body = stdout.readableSliceOfLen(header.bytes_len);

        switch (header.tag) {
            .zig_version => {
                if (!std.mem.eql(u8, builtin.zig_version_string, body)) {
                    return error.ZigProtocolVersionMismatch;
                }
            },
            .error_bundle => {
                const EbHdr = std.zig.Server.Message.ErrorBundle;
                const eb_hdr = @as(*align(1) const EbHdr, @ptrCast(body));
                const extra_bytes =
                    body[@sizeOf(EbHdr)..][0 .. @sizeOf(u32) * eb_hdr.extra_len];
                const string_bytes =
                    body[@sizeOf(EbHdr) + extra_bytes.len ..][0..eb_hdr.string_bytes_len];
                // TODO: use @ptrCast when the compiler supports it
                const unaligned_extra = std.mem.bytesAsSlice(u32, extra_bytes);
                const extra_array = try arena.alloc(u32, unaligned_extra.len);
                @memcpy(extra_array, unaligned_extra);
                result_error_bundle = .{
                    .string_bytes = try arena.dupe(u8, string_bytes),
                    .extra = extra_array,
                };
            },
            .emit_digest => {
                const EmitDigest = std.zig.Server.Message.EmitDigest;
                const ebp_hdr = @as(*align(1) const EmitDigest, @ptrCast(body));
                if (!ebp_hdr.flags.cache_hit) {
                    log.info("source changes detected; rebuilt wasm component", .{});
                }
                const digest = body[@sizeOf(EmitDigest)..][0..Cache.bin_digest_len];
                result = .{
                    .root_dir = ws.global_cache_directory,
                    .sub_path = try arena.dupe(u8, "o" ++ std.fs.path.sep_str ++ Cache.binToHex(digest.*)),
                };
            },
            else => {}, // ignore other messages
        }

        stdout.discard(body.len);
    }

    const stderr = poller.fifo(.stderr);
    if (stderr.readableLength() > 0) {
        const owned_stderr = try stderr.toOwnedSlice();
        defer gpa.free(owned_stderr);
        std.debug.print("{s}", .{owned_stderr});
    }

    // Send EOF to stdin.
    child.stdin.?.close();
    child.stdin = null;

    switch (try child.wait()) {
        .Exited => |code| {
            if (code != 0) {
                log.err(
                    "the following command exited with error code {d}:\n{s}",
                    .{ code, try Build.Step.allocPrintCmd(arena, null, argv.items) },
                );
                return error.WasmCompilationFailed;
            }
        },
        .Signal, .Stopped, .Unknown => {
            log.err(
                "the following command terminated unexpectedly:\n{s}",
                .{try Build.Step.allocPrintCmd(arena, null, argv.items)},
            );
            return error.WasmCompilationFailed;
        },
    }

    if (result_error_bundle.errorMessageCount() > 0) {
        const color = std.zig.Color.auto;
        result_error_bundle.renderToStdErr(color.renderOptions());
        log.err("the following command failed with {d} compilation errors:\n{s}", .{
            result_error_bundle.errorMessageCount(),
            try Build.Step.allocPrintCmd(arena, null, argv.items),
        });
        return error.WasmCompilationFailed;
    }

    return result orelse {
        log.err("child process failed to report result\n{s}", .{
            try Build.Step.allocPrintCmd(arena, null, argv.items),
        });
        return error.WasmCompilationFailed;
    };
}

fn sendMessage(file: std.fs.File, tag: std.zig.Client.Message.Tag) !void {
    const header: std.zig.Client.Message.Header = .{
        .tag = tag,
        .bytes_len = 0,
    };
    try file.writeAll(std.mem.asBytes(&header));
}

fn serveWebSocket(ws: *WebServer, web_socket: *std.http.WebSocket) !void {
    ws.coverage_mutex.lock();
    defer ws.coverage_mutex.unlock();

    // On first connection, the client needs to know what time the server
    // thinks it is to rebase timestamps.
    {
        const timestamp_message: abi.CurrentTime = .{ .base = ws.now() };
        try web_socket.writeMessage(std.mem.asBytes(&timestamp_message), .binary);
    }

    // On first connection, the client needs all the coverage information
    // so that subsequent updates can contain only the updated bits.
    var prev_unique_runs: usize = 0;
    var prev_entry_points: usize = 0;
    try sendCoverageContext(ws, web_socket, &prev_unique_runs, &prev_entry_points);
    while (true) {
        ws.coverage_condition.timedWait(&ws.coverage_mutex, std.time.ns_per_ms * 500) catch {};
        try sendCoverageContext(ws, web_socket, &prev_unique_runs, &prev_entry_points);
    }
}

fn sendCoverageContext(
    ws: *WebServer,
    web_socket: *std.http.WebSocket,
    prev_unique_runs: *usize,
    prev_entry_points: *usize,
) !void {
    const coverage_maps = ws.coverage_files.values();
    if (coverage_maps.len == 0) return;
    // TODO: make each events URL correspond to one coverage map
    const coverage_map = &coverage_maps[0];
    const cov_header: *const abi.SeenPcsHeader = @ptrCast(coverage_map.mapped_memory[0..@sizeOf(abi.SeenPcsHeader)]);
    const seen_pcs = cov_header.seenBits();
    const n_runs = @atomicLoad(usize, &cov_header.n_runs, .monotonic);
    const unique_runs = @atomicLoad(usize, &cov_header.unique_runs, .monotonic);
    if (prev_unique_runs.* != unique_runs) {
        // There has been an update.
        if (prev_unique_runs.* == 0) {
            // We need to send initial context.
            const header: abi.SourceIndexHeader = .{
                .flags = .{},
                .directories_len = @intCast(coverage_map.coverage.directories.entries.len),
                .files_len = @intCast(coverage_map.coverage.files.entries.len),
                .source_locations_len = @intCast(coverage_map.source_locations.len),
                .string_bytes_len = @intCast(coverage_map.coverage.string_bytes.items.len),
                .start_timestamp = coverage_map.start_timestamp,
            };
            const iovecs: [5]std.posix.iovec_const = .{
                makeIov(std.mem.asBytes(&header)),
                makeIov(std.mem.sliceAsBytes(coverage_map.coverage.directories.keys())),
                makeIov(std.mem.sliceAsBytes(coverage_map.coverage.files.keys())),
                makeIov(std.mem.sliceAsBytes(coverage_map.source_locations)),
                makeIov(coverage_map.coverage.string_bytes.items),
            };
            try web_socket.writeMessagev(&iovecs, .binary);
        }

        const header: abi.CoverageUpdateHeader = .{
            .n_runs = n_runs,
            .unique_runs = unique_runs,
        };
        const iovecs: [2]std.posix.iovec_const = .{
            makeIov(std.mem.asBytes(&header)),
            makeIov(std.mem.sliceAsBytes(seen_pcs)),
        };
        try web_socket.writeMessagev(&iovecs, .binary);

        prev_unique_runs.* = unique_runs;
    }

    if (prev_entry_points.* != coverage_map.entry_points.items.len) {
        const header: abi.EntryPointHeader = .{
            .flags = .{
                .locs_len = @intCast(coverage_map.entry_points.items.len),
            },
        };
        const iovecs: [2]std.posix.iovec_const = .{
            makeIov(std.mem.asBytes(&header)),
            makeIov(std.mem.sliceAsBytes(coverage_map.entry_points.items)),
        };
        try web_socket.writeMessagev(&iovecs, .binary);

        prev_entry_points.* = coverage_map.entry_points.items.len;
    }
}

fn serveSourcesTar(ws: *WebServer, request: *std.http.Server.Request) !void {
    const gpa = ws.gpa;

    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var send_buffer: [0x4000]u8 = undefined;
    var response = request.respondStreaming(.{
        .send_buffer = &send_buffer,
        .respond_options = .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/x-tar" },
                cache_control_header,
            },
        },
    });

    const DedupeTable = std.ArrayHashMapUnmanaged(Build.Cache.Path, void, Build.Cache.Path.TableAdapter, false);
    var dedupe_table: DedupeTable = .{};
    defer dedupe_table.deinit(gpa);

    for (ws.fuzz_run_steps) |run_step| {
        const compile_step_inputs = run_step.producer.?.step.inputs.table;
        for (compile_step_inputs.keys(), compile_step_inputs.values()) |dir_path, *file_list| {
            try dedupe_table.ensureUnusedCapacity(gpa, file_list.items.len);
            for (file_list.items) |sub_path| {
                // Special file "." means the entire directory.
                if (std.mem.eql(u8, sub_path, ".")) continue;
                const joined_path = try dir_path.join(arena, sub_path);
                _ = dedupe_table.getOrPutAssumeCapacity(joined_path);
            }
        }
    }

    const deduped_paths = dedupe_table.keys();
    const SortContext = struct {
        pub fn lessThan(this: @This(), lhs: Build.Cache.Path, rhs: Build.Cache.Path) bool {
            _ = this;
            return switch (std.mem.order(u8, lhs.root_dir.path orelse ".", rhs.root_dir.path orelse ".")) {
                .lt => true,
                .gt => false,
                .eq => std.mem.lessThan(u8, lhs.sub_path, rhs.sub_path),
            };
        }
    };
    std.mem.sortUnstable(Build.Cache.Path, deduped_paths, SortContext{}, SortContext.lessThan);

    var cwd_cache: ?[]const u8 = null;

    var archiver = std.tar.writer(response.writer());

    for (deduped_paths) |joined_path| {
        var file = joined_path.root_dir.handle.openFile(joined_path.sub_path, .{}) catch |err| {
            log.err("failed to open {}: {s}", .{ joined_path, @errorName(err) });
            continue;
        };
        defer file.close();

        archiver.prefix = joined_path.root_dir.path orelse try memoizedCwd(arena, &cwd_cache);
        try archiver.writeFile(joined_path.sub_path, file);
    }

    // intentionally omitting the pointless trailer
    //try archiver.finish();
    try response.end();
}

fn memoizedCwd(arena: Allocator, opt_ptr: *?[]const u8) ![]const u8 {
    if (opt_ptr.*) |cached| return cached;
    const result = try std.process.getCwdAlloc(arena);
    opt_ptr.* = result;
    return result;
}

const cache_control_header: std.http.Header = .{
    .name = "cache-control",
    .value = "max-age=0, must-revalidate",
};

pub fn coverageRun(ws: *WebServer) void {
    ws.mutex.lock();
    defer ws.mutex.unlock();

    while (true) {
        ws.condition.wait(&ws.mutex);
        for (ws.msg_queue.items) |msg| switch (msg) {
            .coverage => |coverage| prepareTables(ws, coverage.run, coverage.id) catch |err| switch (err) {
                error.AlreadyReported => continue,
                else => |e| log.err("failed to prepare code coverage tables: {s}", .{@errorName(e)}),
            },
            .entry_point => |entry_point| addEntryPoint(ws, entry_point.coverage_id, entry_point.addr) catch |err| switch (err) {
                error.AlreadyReported => continue,
                else => |e| log.err("failed to prepare code coverage tables: {s}", .{@errorName(e)}),
            },
        };
        ws.msg_queue.clearRetainingCapacity();
    }
}

fn prepareTables(
    ws: *WebServer,
    run_step: *Step.Run,
    coverage_id: u64,
) error{ OutOfMemory, AlreadyReported }!void {
    const gpa = ws.gpa;

    ws.coverage_mutex.lock();
    defer ws.coverage_mutex.unlock();

    const gop = try ws.coverage_files.getOrPut(gpa, coverage_id);
    if (gop.found_existing) {
        // We are fuzzing the same executable with multiple threads.
        // Perhaps the same unit test; perhaps a different one. In any
        // case, since the coverage file is the same, we only have to
        // notice changes to that one file in order to learn coverage for
        // this particular executable.
        return;
    }
    errdefer _ = ws.coverage_files.pop();

    gop.value_ptr.* = .{
        .coverage = std.debug.Coverage.init,
        .mapped_memory = undefined, // populated below
        .source_locations = undefined, // populated below
        .entry_points = .{},
        .start_timestamp = ws.now(),
    };
    errdefer gop.value_ptr.coverage.deinit(gpa);

    const rebuilt_exe_path = run_step.rebuilt_executable.?;
    var debug_info = std.debug.Info.load(gpa, rebuilt_exe_path, &gop.value_ptr.coverage) catch |err| {
        log.err("step '{s}': failed to load debug information for '{}': {s}", .{
            run_step.step.name, rebuilt_exe_path, @errorName(err),
        });
        return error.AlreadyReported;
    };
    defer debug_info.deinit(gpa);

    const coverage_file_path: Build.Cache.Path = .{
        .root_dir = run_step.step.owner.cache_root,
        .sub_path = "v/" ++ std.fmt.hex(coverage_id),
    };
    var coverage_file = coverage_file_path.root_dir.handle.openFile(coverage_file_path.sub_path, .{}) catch |err| {
        log.err("step '{s}': failed to load coverage file '{}': {s}", .{
            run_step.step.name, coverage_file_path, @errorName(err),
        });
        return error.AlreadyReported;
    };
    defer coverage_file.close();

    const file_size = coverage_file.getEndPos() catch |err| {
        log.err("unable to check len of coverage file '{}': {s}", .{ coverage_file_path, @errorName(err) });
        return error.AlreadyReported;
    };

    const mapped_memory = std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        .{ .TYPE = .SHARED },
        coverage_file.handle,
        0,
    ) catch |err| {
        log.err("failed to map coverage file '{}': {s}", .{ coverage_file_path, @errorName(err) });
        return error.AlreadyReported;
    };
    gop.value_ptr.mapped_memory = mapped_memory;

    const header: *const abi.SeenPcsHeader = @ptrCast(mapped_memory[0..@sizeOf(abi.SeenPcsHeader)]);
    const pcs = header.pcAddrs();
    const source_locations = try gpa.alloc(Coverage.SourceLocation, pcs.len);
    errdefer gpa.free(source_locations);

    // Unfortunately the PCs array that LLVM gives us from the 8-bit PC
    // counters feature is not sorted.
    var sorted_pcs: std.MultiArrayList(struct { pc: u64, index: u32, sl: Coverage.SourceLocation }) = .{};
    defer sorted_pcs.deinit(gpa);
    try sorted_pcs.resize(gpa, pcs.len);
    @memcpy(sorted_pcs.items(.pc), pcs);
    for (sorted_pcs.items(.index), 0..) |*v, i| v.* = @intCast(i);
    sorted_pcs.sortUnstable(struct {
        addrs: []const u64,

        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return ctx.addrs[a_index] < ctx.addrs[b_index];
        }
    }{ .addrs = sorted_pcs.items(.pc) });

    debug_info.resolveAddresses(gpa, sorted_pcs.items(.pc), sorted_pcs.items(.sl)) catch |err| {
        log.err("failed to resolve addresses to source locations: {s}", .{@errorName(err)});
        return error.AlreadyReported;
    };

    for (sorted_pcs.items(.index), sorted_pcs.items(.sl)) |i, sl| source_locations[i] = sl;
    gop.value_ptr.source_locations = source_locations;

    ws.coverage_condition.broadcast();
}

fn addEntryPoint(ws: *WebServer, coverage_id: u64, addr: u64) error{ AlreadyReported, OutOfMemory }!void {
    ws.coverage_mutex.lock();
    defer ws.coverage_mutex.unlock();

    const coverage_map = ws.coverage_files.getPtr(coverage_id).?;
    const header: *const abi.SeenPcsHeader = @ptrCast(coverage_map.mapped_memory[0..@sizeOf(abi.SeenPcsHeader)]);
    const pcs = header.pcAddrs();
    // Since this pcs list is unsorted, we must linear scan for the best index.
    const index = i: {
        var best: usize = 0;
        for (pcs[1..], 1..) |elem_addr, i| {
            if (elem_addr == addr) break :i i;
            if (elem_addr > addr) continue;
            if (elem_addr > pcs[best]) best = i;
        }
        break :i best;
    };
    if (index >= pcs.len) {
        log.err("unable to find unit test entry address 0x{x} in source locations (range: 0x{x} to 0x{x})", .{
            addr, pcs[0], pcs[pcs.len - 1],
        });
        return error.AlreadyReported;
    }
    if (false) {
        const sl = coverage_map.source_locations[index];
        const file_name = coverage_map.coverage.stringAt(coverage_map.coverage.fileAt(sl.file).basename);
        log.debug("server found entry point for 0x{x} at {s}:{d}:{d} - index {d} between {x} and {x}", .{
            addr, file_name, sl.line, sl.column, index, pcs[index - 1], pcs[index + 1],
        });
    }
    const gpa = ws.gpa;
    try coverage_map.entry_points.append(gpa, @intCast(index));
}

fn makeIov(s: []const u8) std.posix.iovec_const {
    return .{
        .base = s.ptr,
        .len = s.len,
    };
}
/// The one responsible for creating this module.
owner: *std.Build,
root_source_file: ?LazyPath,
/// The modules that are mapped into this module's import table.
/// Use `addImport` rather than modifying this field directly in order to
/// maintain step dependency edges.
import_table: std.StringArrayHashMapUnmanaged(*Module),

resolved_target: ?std.Build.ResolvedTarget = null,
optimize: ?std.builtin.OptimizeMode = null,
dwarf_format: ?std.dwarf.Format,

c_macros: std.ArrayListUnmanaged([]const u8),
include_dirs: std.ArrayListUnmanaged(IncludeDir),
lib_paths: std.ArrayListUnmanaged(LazyPath),
rpaths: std.ArrayListUnmanaged(RPath),
frameworks: std.StringArrayHashMapUnmanaged(LinkFrameworkOptions),
link_objects: std.ArrayListUnmanaged(LinkObject),

strip: ?bool,
unwind_tables: ?std.builtin.UnwindTables,
single_threaded: ?bool,
stack_protector: ?bool,
stack_check: ?bool,
sanitize_c: ?std.zig.SanitizeC,
sanitize_thread: ?bool,
fuzz: ?bool,
code_model: std.builtin.CodeModel,
valgrind: ?bool,
pic: ?bool,
red_zone: ?bool,
omit_frame_pointer: ?bool,
error_tracing: ?bool,
link_libc: ?bool,
link_libcpp: ?bool,

/// Symbols to be exported when compiling to WebAssembly.
export_symbol_names: []const []const u8 = &.{},

/// Caches the result of `getGraph` when called multiple times.
/// Use `getGraph` instead of accessing this field directly.
cached_graph: Graph = .{ .modules = &.{}, .names = &.{} },

pub const RPath = union(enum) {
    lazy_path: LazyPath,
    special: []const u8,
};

pub const LinkObject = union(enum) {
    static_path: LazyPath,
    other_step: *Step.Compile,
    system_lib: SystemLib,
    assembly_file: LazyPath,
    c_source_file: *CSourceFile,
    c_source_files: *CSourceFiles,
    win32_resource_file: *RcSourceFile,
};

pub const SystemLib = struct {
    name: []const u8,
    needed: bool,
    weak: bool,
    use_pkg_config: UsePkgConfig,
    preferred_link_mode: std.builtin.LinkMode,
    search_strategy: SystemLib.SearchStrategy,

    pub const UsePkgConfig = enum {
        /// Don't use pkg-config, just pass -lfoo where foo is name.
        no,
        /// Try to get information on how to link the library from pkg-config.
        /// If that fails, fall back to passing -lfoo where foo is name.
        yes,
        /// Try to get information on how to link the library from pkg-config.
        /// If that fails, error out.
        force,
    };

    pub const SearchStrategy = enum { paths_first, mode_first, no_fallback };
};

pub const CSourceLanguage = enum {
    c,
    cpp,

    objective_c,
    objective_cpp,

    /// Standard assembly
    assembly,
    /// Assembly with the C preprocessor
    assembly_with_preprocessor,

    pub fn internalIdentifier(self: CSourceLanguage) []const u8 {
        return switch (self) {
            .c => "c",
            .cpp => "c++",
            .objective_c => "objective-c",
            .objective_cpp => "objective-c++",
            .assembly => "assembler",
            .assembly_with_preprocessor => "assembler-with-cpp",
        };
    }
};

pub const CSourceFiles = struct {
    root: LazyPath,
    /// `files` is relative to `root`, which is
    /// the build root by default
    files: []const []const u8,
    flags: []const []const u8,
    /// By default, determines language of each file individually based on its file extension
    language: ?CSourceLanguage,
};

pub const CSourceFile = struct {
    file: LazyPath,
    flags: []const []const u8 = &.{},
    /// By default, determines language of each file individually based on its file extension
    language: ?CSourceLanguage = null,

    pub fn dupe(file: CSourceFile, b: *std.Build) CSourceFile {
        return .{
            .file = file.file.dupe(b),
            .flags = b.dupeStrings(file.flags),
            .language = file.language,
        };
    }
};

pub const RcSourceFile = struct {
    file: LazyPath,
    /// Any option that rc.exe accepts will work here, with the exception of:
    /// - `/fo`: The output filename is set by the build system
    /// - `/p`: Only running the preprocessor is not supported in this context
    /// - `/:no-preprocess` (non-standard option): Not supported in this context
    /// - Any MUI-related option
    /// https://learn.microsoft.com/en-us/windows/win32/menurc/using-rc-the-rc-command-line-
    ///
    /// Implicitly defined options:
    ///  /x (ignore the INCLUDE environment variable)
    ///  /D_DEBUG or /DNDEBUG depending on the optimization mode
    flags: []const []const u8 = &.{},
    /// Include paths that may or may not exist yet and therefore need to be
    /// specified as a LazyPath. Each path will be appended to the flags
    /// as `/I <resolved path>`.
    include_paths: []const LazyPath = &.{},

    pub fn dupe(file: RcSourceFile, b: *std.Build) RcSourceFile {
        const include_paths = b.allocator.alloc(LazyPath, file.include_paths.len) catch @panic("OOM");
        for (include_paths, file.include_paths) |*dest, lazy_path| dest.* = lazy_path.dupe(b);
        return .{
            .file = file.file.dupe(b),
            .flags = b.dupeStrings(file.flags),
            .include_paths = include_paths,
        };
    }
};

pub const IncludeDir = union(enum) {
    path: LazyPath,
    path_system: LazyPath,
    path_after: LazyPath,
    framework_path: LazyPath,
    framework_path_system: LazyPath,
    other_step: *Step.Compile,
    config_header_step: *Step.ConfigHeader,
    embed_path: LazyPath,

    pub fn appendZigProcessFlags(
        include_dir: IncludeDir,
        b: *std.Build,
        zig_args: *std.ArrayList([]const u8),
        asking_step: ?*Step,
    ) !void {
        switch (include_dir) {
            .path => |include_path| {
                try zig_args.appendSlice(&.{ "-I", include_path.getPath2(b, asking_step) });
            },
            .path_system => |include_path| {
                try zig_args.appendSlice(&.{ "-isystem", include_path.getPath2(b, asking_step) });
            },
            .path_after => |include_path| {
                try zig_args.appendSlice(&.{ "-idirafter", include_path.getPath2(b, asking_step) });
            },
            .framework_path => |include_path| {
                try zig_args.appendSlice(&.{ "-F", include_path.getPath2(b, asking_step) });
            },
            .framework_path_system => |include_path| {
                try zig_args.appendSlice(&.{ "-iframework", include_path.getPath2(b, asking_step) });
            },
            .other_step => |other| {
                if (other.generated_h) |header| {
                    try zig_args.appendSlice(&.{ "-isystem", std.fs.path.dirname(header.getPath()).? });
                }
                if (other.installed_headers_include_tree) |include_tree| {
                    try zig_args.appendSlice(&.{ "-I", include_tree.generated_directory.getPath() });
                }
            },
            .config_header_step => |config_header| {
                const full_file_path = config_header.output_file.getPath();
                const header_dir_path = full_file_path[0 .. full_file_path.len - config_header.include_path.len];
                try zig_args.appendSlice(&.{ "-I", header_dir_path });
            },
            .embed_path => |embed_path| {
                try zig_args.append(try std.mem.concat(b.allocator, u8, &.{ "--embed-dir=", embed_path.getPath2(b, asking_step) }));
            },
        }
    }
};

pub const LinkFrameworkOptions = struct {
    /// Causes dynamic libraries to be linked regardless of whether they are
    /// actually depended on. When false, dynamic libraries with no referenced
    /// symbols will be omitted by the linker.
    needed: bool = false,
    /// Marks all referenced symbols from this library as weak, meaning that if
    /// a same-named symbol is provided by another compilation unit, instead of
    /// emitting a "duplicate symbol" error, the linker will resolve all
    /// references to the symbol with the strong version.
    ///
    /// When the linker encounters two weak symbols, the chosen one is
    /// determined by the order compilation units are provided to the linker,
    /// priority given to later ones.
    weak: bool = false,
};

/// Unspecified options here will be inherited from parent `Module` when
/// inserted into an import table.
pub const CreateOptions = struct {
    /// This could either be a generated file, in which case the module
    /// contains exactly one file, or it could be a path to the root source
    /// file of directory of files which constitute the module.
    /// If `null`, it means this module is made up of only `link_objects`.
    root_source_file: ?LazyPath = null,

    /// The table of other modules that this module can access via `@import`.
    /// Imports are allowed to be cyclical, so this table can be added to after
    /// the `Module` is created via `addImport`.
    imports: []const Import = &.{},

    target: ?std.Build.ResolvedTarget = null,
    optimize: ?std.builtin.OptimizeMode = null,

    /// `true` requires a compilation that includes this Module to link libc.
    /// `false` causes a build failure if a compilation that includes this Module would link libc.
    /// `null` neither requires nor prevents libc from being linked.
    link_libc: ?bool = null,
    /// `true` requires a compilation that includes this Module to link libc++.
    /// `false` causes a build failure if a compilation that includes this Module would link libc++.
    /// `null` neither requires nor prevents libc++ from being linked.
    link_libcpp: ?bool = null,
    single_threaded: ?bool = null,
    strip: ?bool = null,
    unwind_tables: ?std.builtin.UnwindTables = null,
    dwarf_format: ?std.dwarf.Format = null,
    code_model: std.builtin.CodeModel = .default,
    stack_protector: ?bool = null,
    stack_check: ?bool = null,
    sanitize_c: ?std.zig.SanitizeC = null,
    sanitize_thread: ?bool = null,
    fuzz: ?bool = null,
    /// Whether to emit machine code that integrates with Valgrind.
    valgrind: ?bool = null,
    /// Position Independent Code
    pic: ?bool = null,
    red_zone: ?bool = null,
    /// Whether to omit the stack frame pointer. Frees up a register and makes it
    /// more difficult to obtain stack traces. Has target-dependent effects.
    omit_frame_pointer: ?bool = null,
    error_tracing: ?bool = null,
};

pub const Import = struct {
    name: []const u8,
    module: *Module,
};

pub fn init(
    m: *Module,
    owner: *std.Build,
    value: union(enum) { options: CreateOptions, existing: *const Module },
) void {
    const allocator = owner.allocator;

    switch (value) {
        .options => |options| {
            m.* = .{
                .owner = owner,
                .root_source_file = if (options.root_source_file) |lp| lp.dupe(owner) else null,
                .import_table = .{},
                .resolved_target = options.target,
                .optimize = options.optimize,
                .link_libc = options.link_libc,
                .link_libcpp = options.link_libcpp,
                .dwarf_format = options.dwarf_format,
                .c_macros = .{},
                .include_dirs = .{},
                .lib_paths = .{},
                .rpaths = .{},
                .frameworks = .{},
                .link_objects = .{},
                .strip = options.strip,
                .unwind_tables = options.unwind_tables,
                .single_threaded = options.single_threaded,
                .stack_protector = options.stack_protector,
                .stack_check = options.stack_check,
                .sanitize_c = options.sanitize_c,
                .sanitize_thread = options.sanitize_thread,
                .fuzz = options.fuzz,
                .code_model = options.code_model,
                .valgrind = options.valgrind,
                .pic = options.pic,
                .red_zone = options.red_zone,
                .omit_frame_pointer = options.omit_frame_pointer,
                .error_tracing = options.error_tracing,
                .export_symbol_names = &.{},
            };

            m.import_table.ensureUnusedCapacity(allocator, options.imports.len) catch @panic("OOM");
            for (options.imports) |dep| {
                m.import_table.putAssumeCapacity(dep.name, dep.module);
            }
        },
        .existing => |existing| {
            m.* = existing.*;
        },
    }
}

pub fn create(owner: *std.Build, options: CreateOptions) *Module {
    const m = owner.allocator.create(Module) catch @panic("OOM");
    m.init(owner, .{ .options = options });
    return m;
}

/// Adds an existing module to be used with `@import`.
pub fn addImport(m: *Module, name: []const u8, module: *Module) void {
    const b = m.owner;
    m.import_table.put(b.allocator, b.dupe(name), module) catch @panic("OOM");
}

/// Creates a new module and adds it to be used with `@import`.
pub fn addAnonymousImport(m: *Module, name: []const u8, options: CreateOptions) void {
    const module = create(m.owner, options);
    return addImport(m, name, module);
}

/// Converts a set of key-value pairs into a Zig source file, and then inserts it into
/// the Module's import table with the specified name. This makes the options importable
/// via `@import("module_name")`.
pub fn addOptions(m: *Module, module_name: []const u8, options: *Step.Options) void {
    addImport(m, module_name, options.createModule());
}

pub const LinkSystemLibraryOptions = struct {
    /// Causes dynamic libraries to be linked regardless of whether they are
    /// actually depended on. When false, dynamic libraries with no referenced
    /// symbols will be omitted by the linker.
    needed: bool = false,
    /// Marks all referenced symbols from this library as weak, meaning that if
    /// a same-named symbol is provided by another compilation unit, instead of
    /// emitting a "duplicate symbol" error, the linker will resolve all
    /// references to the symbol with the strong version.
    ///
    /// When the linker encounters two weak symbols, the chosen one is
    /// determined by the order compilation units are provided to the linker,
    /// priority given to later ones.
    weak: bool = false,
    use_pkg_config: SystemLib.UsePkgConfig = .yes,
    preferred_link_mode: std.builtin.LinkMode = .dynamic,
    search_strategy: SystemLib.SearchStrategy = .paths_first,
};

pub fn linkSystemLibrary(
    m: *Module,
    name: []const u8,
    options: LinkSystemLibraryOptions,
) void {
    const b = m.owner;

    const target = m.requireKnownTarget();
    if (std.zig.target.isLibCLibName(target, name)) {
        m.link_libc = true;
        return;
    }
    if (std.zig.target.isLibCxxLibName(target, name)) {
        m.link_libcpp = true;
        return;
    }

    m.link_objects.append(b.allocator, .{
        .system_lib = .{
            .name = b.dupe(name),
            .needed = options.needed,
            .weak = options.weak,
            .use_pkg_config = options.use_pkg_config,
            .preferred_link_mode = options.preferred_link_mode,
            .search_strategy = options.search_strategy,
        },
    }) catch @panic("OOM");
}

pub fn linkFramework(m: *Module, name: []const u8, options: LinkFrameworkOptions) void {
    const b = m.owner;
    m.frameworks.put(b.allocator, b.dupe(name), options) catch @panic("OOM");
}

pub const AddCSourceFilesOptions = struct {
    /// When provided, `files` are relative to `root` rather than the
    /// package that owns the `Compile` step.
    root: ?LazyPath = null,
    files: []const []const u8,
    flags: []const []const u8 = &.{},
    /// By default, determines language of each file individually based on its file extension
    language: ?CSourceLanguage = null,
};

/// Handy when you have many non-Zig source files and want them all to have the same flags.
pub fn addCSourceFiles(m: *Module, options: AddCSourceFilesOptions) void {
    const b = m.owner;
    const allocator = b.allocator;

    for (options.files) |path| {
        if (std.fs.path.isAbsolute(path)) {
            std.debug.panic(
                "file paths added with 'addCSourceFiles' must be relative, found absolute path '{s}'",
                .{path},
            );
        }
    }

    const c_source_files = allocator.create(CSourceFiles) catch @panic("OOM");
    c_source_files.* = .{
        .root = options.root orelse b.path(""),
        .files = b.dupeStrings(options.files),
        .flags = b.dupeStrings(options.flags),
        .language = options.language,
    };
    m.link_objects.append(allocator, .{ .c_source_files = c_source_files }) catch @panic("OOM");
}

pub fn addCSourceFile(m: *Module, source: CSourceFile) void {
    const b = m.owner;
    const allocator = b.allocator;
    const c_source_file = allocator.create(CSourceFile) catch @panic("OOM");
    c_source_file.* = source.dupe(b);
    m.link_objects.append(allocator, .{ .c_source_file = c_source_file }) catch @panic("OOM");
}

/// Resource files must have the extension `.rc`.
/// Can be called regardless of target. The .rc file will be ignored
/// if the target object format does not support embedded resources.
pub fn addWin32ResourceFile(m: *Module, source: RcSourceFile) void {
    const b = m.owner;
    const allocator = b.allocator;
    const target = m.requireKnownTarget();
    // Only the PE/COFF format has a Resource Table, so for any other target
    // the resource file is ignored.
    if (target.ofmt != .coff) return;

    const rc_source_file = allocator.create(RcSourceFile) catch @panic("OOM");
    rc_source_file.* = source.dupe(b);
    m.link_objects.append(allocator, .{ .win32_resource_file = rc_source_file }) catch @panic("OOM");
}

pub fn addAssemblyFile(m: *Module, source: LazyPath) void {
    const b = m.owner;
    m.link_objects.append(b.allocator, .{ .assembly_file = source.dupe(b) }) catch @panic("OOM");
}

pub fn addObjectFile(m: *Module, object: LazyPath) void {
    const b = m.owner;
    m.link_objects.append(b.allocator, .{ .static_path = object.dupe(b) }) catch @panic("OOM");
}

pub fn addObject(m: *Module, object: *Step.Compile) void {
    assert(object.kind == .obj or object.kind == .test_obj);
    m.linkLibraryOrObject(object);
}

pub fn linkLibrary(m: *Module, library: *Step.Compile) void {
    assert(library.kind == .lib);
    m.linkLibraryOrObject(library);
}

pub fn addAfterIncludePath(m: *Module, lazy_path: LazyPath) void {
    const b = m.owner;
    m.include_dirs.append(b.allocator, .{ .path_after = lazy_path.dupe(b) }) catch @panic("OOM");
}

pub fn addSystemIncludePath(m: *Module, lazy_path: LazyPath) void {
    const b = m.owner;
    m.include_dirs.append(b.allocator, .{ .path_system = lazy_path.dupe(b) }) catch @panic("OOM");
}

pub fn addIncludePath(m: *Module, lazy_path: LazyPath) void {
    const b = m.owner;
    m.include_dirs.append(b.allocator, .{ .path = lazy_path.dupe(b) }) catch @panic("OOM");
}

pub fn addConfigHeader(m: *Module, config_header: *Step.ConfigHeader) void {
    const allocator = m.owner.allocator;
    m.include_dirs.append(allocator, .{ .config_header_step = config_header }) catch @panic("OOM");
}

pub fn addSystemFrameworkPath(m: *Module, directory_path: LazyPath) void {
    const b = m.owner;
    m.include_dirs.append(b.allocator, .{ .framework_path_system = directory_path.dupe(b) }) catch
        @panic("OOM");
}

pub fn addFrameworkPath(m: *Module, directory_path: LazyPath) void {
    const b = m.owner;
    m.include_dirs.append(b.allocator, .{ .framework_path = directory_path.dupe(b) }) catch
        @panic("OOM");
}

pub fn addEmbedPath(m: *Module, lazy_path: LazyPath) void {
    const b = m.owner;
    m.include_dirs.append(b.allocator, .{ .embed_path = lazy_path.dupe(b) }) catch @panic("OOM");
}

pub fn addLibraryPath(m: *Module, directory_path: LazyPath) void {
    const b = m.owner;
    m.lib_paths.append(b.allocator, directory_path.dupe(b)) catch @panic("OOM");
}

pub fn addRPath(m: *Module, directory_path: LazyPath) void {
    const b = m.owner;
    m.rpaths.append(b.allocator, .{ .lazy_path = directory_path.dupe(b) }) catch @panic("OOM");
}

pub fn addRPathSpecial(m: *Module, bytes: []const u8) void {
    const b = m.owner;
    m.rpaths.append(b.allocator, .{ .special = b.dupe(bytes) }) catch @panic("OOM");
}

/// Equvialent to the following C code, applied to all C source files owned by
/// this `Module`:
/// ```c
/// #define name value
/// ```
/// `name` and `value` need not live longer than the function call.
pub fn addCMacro(m: *Module, name: []const u8, value: []const u8) void {
    const b = m.owner;
    m.c_macros.append(b.allocator, b.fmt("-D{s}={s}", .{ name, value })) catch @panic("OOM");
}

pub fn appendZigProcessFlags(
    m: *Module,
    zig_args: *std.ArrayList([]const u8),
    asking_step: ?*Step,
) !void {
    const b = m.owner;

    try addFlag(zig_args, m.strip, "-fstrip", "-fno-strip");
    try addFlag(zig_args, m.single_threaded, "-fsingle-threaded", "-fno-single-threaded");
    try addFlag(zig_args, m.stack_check, "-fstack-check", "-fno-stack-check");
    try addFlag(zig_args, m.stack_protector, "-fstack-protector", "-fno-stack-protector");
    try addFlag(zig_args, m.omit_frame_pointer, "-fomit-frame-pointer", "-fno-omit-frame-pointer");
    try addFlag(zig_args, m.error_tracing, "-ferror-tracing", "-fno-error-tracing");
    try addFlag(zig_args, m.sanitize_thread, "-fsanitize-thread", "-fno-sanitize-thread");
    try addFlag(zig_args, m.fuzz, "-ffuzz", "-fno-fuzz");
    try addFlag(zig_args, m.valgrind, "-fvalgrind", "-fno-valgrind");
    try addFlag(zig_args, m.pic, "-fPIC", "-fno-PIC");
    try addFlag(zig_args, m.red_zone, "-mred-zone", "-mno-red-zone");

    if (m.sanitize_c) |sc| switch (sc) {
        .off => try zig_args.append("-fno-sanitize-c"),
        .trap => try zig_args.append("-fsanitize-c=trap"),
        .full => try zig_args.append("-fsanitize-c=full"),
    };

    if (m.dwarf_format) |dwarf_format| {
        try zig_args.append(switch (dwarf_format) {
            .@"32" => "-gdwarf32",
            .@"64" => "-gdwarf64",
        });
    }

    if (m.unwind_tables) |unwind_tables| {
        try zig_args.append(switch (unwind_tables) {
            .none => "-fno-unwind-tables",
            .sync => "-funwind-tables",
            .@"async" => "-fasync-unwind-tables",
        });
    }

    try zig_args.ensureUnusedCapacity(1);
    if (m.optimize) |optimize| switch (optimize) {
        .Debug => zig_args.appendAssumeCapacity("-ODebug"),
        .ReleaseSmall => zig_args.appendAssumeCapacity("-OReleaseSmall"),
        .ReleaseFast => zig_args.appendAssumeCapacity("-OReleaseFast"),
        .ReleaseSafe => zig_args.appendAssumeCapacity("-OReleaseSafe"),
    };

    if (m.code_model != .default) {
        try zig_args.append("-mcmodel");
        try zig_args.append(@tagName(m.code_model));
    }

    if (m.resolved_target) |*target| {
        // Communicate the query via CLI since it's more compact.
        if (!target.query.isNative()) {
            try zig_args.appendSlice(&.{
                "-target", try target.query.zigTriple(b.allocator),
                "-mcpu",   try target.query.serializeCpuAlloc(b.allocator),
            });

            if (target.query.dynamic_linker.get()) |dynamic_linker| {
                try zig_args.append("--dynamic-linker");
                try zig_args.append(dynamic_linker);
            }
        }
    }

    for (m.export_symbol_names) |symbol_name| {
        try zig_args.append(b.fmt("--export={s}", .{symbol_name}));
    }

    for (m.include_dirs.items) |include_dir| {
        try include_dir.appendZigProcessFlags(b, zig_args, asking_step);
    }

    try zig_args.appendSlice(m.c_macros.items);

    try zig_args.ensureUnusedCapacity(2 * m.lib_paths.items.len);
    for (m.lib_paths.items) |lib_path| {
        zig_args.appendAssumeCapacity("-L");
        zig_args.appendAssumeCapacity(lib_path.getPath2(b, asking_step));
    }

    try zig_args.ensureUnusedCapacity(2 * m.rpaths.items.len);
    for (m.rpaths.items) |rpath| switch (rpath) {
        .lazy_path => |lp| {
            zig_args.appendAssumeCapacity("-rpath");
            zig_args.appendAssumeCapacity(lp.getPath2(b, asking_step));
        },
        .special => |bytes| {
            zig_args.appendAssumeCapacity("-rpath");
            zig_args.appendAssumeCapacity(bytes);
        },
    };
}

fn addFlag(
    args: *std.ArrayList([]const u8),
    opt: ?bool,
    then_name: []const u8,
    else_name: []const u8,
) !void {
    const cond = opt orelse return;
    return args.append(if (cond) then_name else else_name);
}

fn linkLibraryOrObject(m: *Module, other: *Step.Compile) void {
    const allocator = m.owner.allocator;
    _ = other.getEmittedBin(); // Indicate there is a dependency on the outputted binary.

    if (other.rootModuleTarget().os.tag == .windows and other.isDynamicLibrary()) {
        _ = other.getEmittedImplib(); // Indicate dependency on the outputted implib.
    }

    m.link_objects.append(allocator, .{ .other_step = other }) catch @panic("OOM");
    m.include_dirs.append(allocator, .{ .other_step = other }) catch @panic("OOM");
}

fn requireKnownTarget(m: *Module) std.Target {
    const resolved_target = m.resolved_target orelse
        @panic("this API requires the Module to be created with a known 'target' field");
    return resolved_target.result;
}

/// Elements of `modules` and `names` are matched one-to-one.
pub const Graph = struct {
    modules: []const *Module,
    names: []const []const u8,
};

/// Intended to be used during the make phase only.
///
/// Given that `root` is the root `Module` of a compilation, return all `Module`s
/// in the module graph, including `root` itself. `root` is guaranteed to be the
/// first module in the returned slice.
pub fn getGraph(root: *Module) Graph {
    if (root.cached_graph.modules.len != 0) {
        return root.cached_graph;
    }

    const arena = root.owner.graph.arena;

    var modules: std.AutoArrayHashMapUnmanaged(*std.Build.Module, []const u8) = .empty;
    var next_idx: usize = 0;

    modules.putNoClobber(arena, root, "root") catch @panic("OOM");

    while (next_idx < modules.count()) {
        const mod = modules.keys()[next_idx];
        next_idx += 1;
        modules.ensureUnusedCapacity(arena, mod.import_table.count()) catch @panic("OOM");
        for (mod.import_table.keys(), mod.import_table.values()) |import_name, other_mod| {
            modules.putAssumeCapacity(other_mod, import_name);
        }
    }

    const result: Graph = .{
        .modules = modules.keys(),
        .names = modules.values(),
    };
    root.cached_graph = result;
    return result;
}

const Module = @This();
const std = @import("std");
const assert = std.debug.assert;
const LazyPath = std.Build.LazyPath;
const Step = std.Build.Step;
id: Id,
name: []const u8,
owner: *Build,
makeFn: MakeFn,

dependencies: std.ArrayList(*Step),
/// This field is empty during execution of the user's build script, and
/// then populated during dependency loop checking in the build runner.
dependants: std.ArrayListUnmanaged(*Step),
/// Collects the set of files that retrigger this step to run.
///
/// This is used by the build system's implementation of `--watch` but it can
/// also be potentially useful for IDEs to know what effects editing a
/// particular file has.
///
/// Populated within `make`. Implementation may choose to clear and repopulate,
/// retain previous value, or update.
inputs: Inputs,

state: State,
/// Set this field to declare an upper bound on the amount of bytes of memory it will
/// take to run the step. Zero means no limit.
///
/// The idea to annotate steps that might use a high amount of RAM with an
/// upper bound. For example, perhaps a particular set of unit tests require 4
/// GiB of RAM, and those tests will be run under 4 different build
/// configurations at once. This would potentially require 16 GiB of memory on
/// the system if all 4 steps executed simultaneously, which could easily be
/// greater than what is actually available, potentially causing the system to
/// crash when using `zig build` at the default concurrency level.
///
/// This field causes the build runner to do two things:
/// 1. ulimit child processes, so that they will fail if it would exceed this
/// memory limit. This serves to enforce that this upper bound value is
/// correct.
/// 2. Ensure that the set of concurrent steps at any given time have a total
/// max_rss value that does not exceed the `max_total_rss` value of the build
/// runner. This value is configurable on the command line, and defaults to the
/// total system memory available.
max_rss: usize,

result_error_msgs: std.ArrayListUnmanaged([]const u8),
result_error_bundle: std.zig.ErrorBundle,
result_stderr: []const u8,
result_cached: bool,
result_duration_ns: ?u64,
/// 0 means unavailable or not reported.
result_peak_rss: usize,
test_results: TestResults,

/// The return address associated with creation of this step that can be useful
/// to print along with debugging messages.
debug_stack_trace: []usize,

pub const TestResults = struct {
    fail_count: u32 = 0,
    skip_count: u32 = 0,
    leak_count: u32 = 0,
    log_err_count: u32 = 0,
    test_count: u32 = 0,

    pub fn isSuccess(tr: TestResults) bool {
        return tr.fail_count == 0 and tr.leak_count == 0 and tr.log_err_count == 0;
    }

    pub fn passCount(tr: TestResults) u32 {
        return tr.test_count - tr.fail_count - tr.skip_count;
    }
};

pub const MakeOptions = struct {
    progress_node: std.Progress.Node,
    thread_pool: *std.Thread.Pool,
    watch: bool,
};

pub const MakeFn = *const fn (step: *Step, options: MakeOptions) anyerror!void;

pub const State = enum {
    precheck_unstarted,
    precheck_started,
    /// This is also used to indicate "dirty" steps that have been modified
    /// after a previous build completed, in which case, the step may or may
    /// not have been completed before. Either way, one or more of its direct
    /// file system inputs have been modified, meaning that the step needs to
    /// be re-evaluated.
    precheck_done,
    running,
    dependency_failure,
    success,
    failure,
    /// This state indicates that the step did not complete, however, it also did not fail,
    /// and it is safe to continue executing its dependencies.
    skipped,
    /// This step was skipped because it specified a max_rss that exceeded the runner's maximum.
    /// It is not safe to run its dependencies.
    skipped_oom,
};

pub const Id = enum {
    top_level,
    compile,
    install_artifact,
    install_file,
    install_dir,
    remove_dir,
    fail,
    fmt,
    translate_c,
    write_file,
    update_source_files,
    run,
    check_file,
    check_object,
    config_header,
    objcopy,
    options,
    custom,

    pub fn Type(comptime id: Id) type {
        return switch (id) {
            .top_level => Build.TopLevelStep,
            .compile => Compile,
            .install_artifact => InstallArtifact,
            .install_file => InstallFile,
            .install_dir => InstallDir,
            .remove_dir => RemoveDir,
            .fail => Fail,
            .fmt => Fmt,
            .translate_c => TranslateC,
            .write_file => WriteFile,
            .update_source_files => UpdateSourceFiles,
            .run => Run,
            .check_file => CheckFile,
            .check_object => CheckObject,
            .config_header => ConfigHeader,
            .objcopy => ObjCopy,
            .options => Options,
            .custom => @compileError("no type available for custom step"),
        };
    }
};

pub const CheckFile = @import("Step/CheckFile.zig");
pub const CheckObject = @import("Step/CheckObject.zig");
pub const ConfigHeader = @import("Step/ConfigHeader.zig");
pub const Fail = @import("Step/Fail.zig");
pub const Fmt = @import("Step/Fmt.zig");
pub const InstallArtifact = @import("Step/InstallArtifact.zig");
pub const InstallDir = @import("Step/InstallDir.zig");
pub const InstallFile = @import("Step/InstallFile.zig");
pub const ObjCopy = @import("Step/ObjCopy.zig");
pub const Compile = @import("Step/Compile.zig");
pub const Options = @import("Step/Options.zig");
pub const RemoveDir = @import("Step/RemoveDir.zig");
pub const Run = @import("Step/Run.zig");
pub const TranslateC = @import("Step/TranslateC.zig");
pub const WriteFile = @import("Step/WriteFile.zig");
pub const UpdateSourceFiles = @import("Step/UpdateSourceFiles.zig");

pub const Inputs = struct {
    table: Table,

    pub const init: Inputs = .{
        .table = .{},
    };

    pub const Table = std.ArrayHashMapUnmanaged(Build.Cache.Path, Files, Build.Cache.Path.TableAdapter, false);
    /// The special file name "." means any changes inside the directory.
    pub const Files = std.ArrayListUnmanaged([]const u8);

    pub fn populated(inputs: *Inputs) bool {
        return inputs.table.count() != 0;
    }

    pub fn clear(inputs: *Inputs, gpa: Allocator) void {
        for (inputs.table.values()) |*files| files.deinit(gpa);
        inputs.table.clearRetainingCapacity();
    }
};

pub const StepOptions = struct {
    id: Id,
    name: []const u8,
    owner: *Build,
    makeFn: MakeFn = makeNoOp,
    first_ret_addr: ?usize = null,
    max_rss: usize = 0,
};

pub fn init(options: StepOptions) Step {
    const arena = options.owner.allocator;

    return .{
        .id = options.id,
        .name = arena.dupe(u8, options.name) catch @panic("OOM"),
        .owner = options.owner,
        .makeFn = options.makeFn,
        .dependencies = std.ArrayList(*Step).init(arena),
        .dependants = .{},
        .inputs = Inputs.init,
        .state = .precheck_unstarted,
        .max_rss = options.max_rss,
        .debug_stack_trace = blk: {
            if (!std.debug.sys_can_stack_trace) break :blk &.{};
            const addresses = arena.alloc(usize, options.owner.debug_stack_frames_count) catch @panic("OOM");
            @memset(addresses, 0);
            const first_ret_addr = options.first_ret_addr orelse @returnAddress();
            var stack_trace = std.builtin.StackTrace{
                .instruction_addresses = addresses,
                .index = 0,
            };
            std.debug.captureStackTrace(first_ret_addr, &stack_trace);
            break :blk addresses;
        },
        .result_error_msgs = .{},
        .result_error_bundle = std.zig.ErrorBundle.empty,
        .result_stderr = "",
        .result_cached = false,
        .result_duration_ns = null,
        .result_peak_rss = 0,
        .test_results = .{},
    };
}

/// If the Step's `make` function reports `error.MakeFailed`, it indicates they
/// have already reported the error. Otherwise, we add a simple error report
/// here.
pub fn make(s: *Step, options: MakeOptions) error{ MakeFailed, MakeSkipped }!void {
    const arena = s.owner.allocator;

    s.makeFn(s, options) catch |err| switch (err) {
        error.MakeFailed => return error.MakeFailed,
        error.MakeSkipped => return error.MakeSkipped,
        else => {
            s.result_error_msgs.append(arena, @errorName(err)) catch @panic("OOM");
            return error.MakeFailed;
        },
    };

    if (!s.test_results.isSuccess()) {
        return error.MakeFailed;
    }

    if (s.max_rss != 0 and s.result_peak_rss > s.max_rss) {
        const msg = std.fmt.allocPrint(arena, "memory usage peaked at {d} bytes, exceeding the declared upper bound of {d}", .{
            s.result_peak_rss, s.max_rss,
        }) catch @panic("OOM");
        s.result_error_msgs.append(arena, msg) catch @panic("OOM");
        return error.MakeFailed;
    }
}

pub fn dependOn(step: *Step, other: *Step) void {
    step.dependencies.append(other) catch @panic("OOM");
}

pub fn getStackTrace(s: *Step) ?std.builtin.StackTrace {
    var len: usize = 0;
    while (len < s.debug_stack_trace.len and s.debug_stack_trace[len] != 0) {
        len += 1;
    }

    return if (len == 0) null else .{
        .instruction_addresses = s.debug_stack_trace,
        .index = len,
    };
}

fn makeNoOp(step: *Step, options: MakeOptions) anyerror!void {
    _ = options;

    var all_cached = true;

    for (step.dependencies.items) |dep| {
        all_cached = all_cached and dep.result_cached;
    }

    step.result_cached = all_cached;
}

pub fn cast(step: *Step, comptime T: type) ?*T {
    if (step.id == T.base_id) {
        return @fieldParentPtr("step", step);
    }
    return null;
}

/// For debugging purposes, prints identifying information about this Step.
pub fn dump(step: *Step, file: std.fs.File) void {
    const w = file.writer();
    const tty_config = std.io.tty.detectConfig(file);
    const debug_info = std.debug.getSelfDebugInfo() catch |err| {
        w.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{
            @errorName(err),
        }) catch {};
        return;
    };
    if (step.getStackTrace()) |stack_trace| {
        w.print("name: '{s}'. creation stack trace:\n", .{step.name}) catch {};
        std.debug.writeStackTrace(stack_trace, w, debug_info, tty_config) catch |err| {
            w.print("Unable to dump stack trace: {s}\n", .{@errorName(err)}) catch {};
            return;
        };
    } else {
        const field = "debug_stack_frames_count";
        comptime assert(@hasField(Build, field));
        tty_config.setColor(w, .yellow) catch {};
        w.print("name: '{s}'. no stack trace collected for this step, see std.Build." ++ field ++ "\n", .{step.name}) catch {};
        tty_config.setColor(w, .reset) catch {};
    }
}

const Step = @This();
const std = @import("../std.zig");
const Build = std.Build;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const builtin = @import("builtin");
const Cache = Build.Cache;
const Path = Cache.Path;

pub fn evalChildProcess(s: *Step, argv: []const []const u8) ![]u8 {
    const run_result = try captureChildProcess(s, std.Progress.Node.none, argv);
    try handleChildProcessTerm(s, run_result.term, null, argv);
    return run_result.stdout;
}

pub fn captureChildProcess(
    s: *Step,
    progress_node: std.Progress.Node,
    argv: []const []const u8,
) !std.process.Child.RunResult {
    const arena = s.owner.allocator;

    try handleChildProcUnsupported(s, null, argv);
    try handleVerbose(s.owner, null, argv);

    const result = std.process.Child.run(.{
        .allocator = arena,
        .argv = argv,
        .progress_node = progress_node,
    }) catch |err| return s.fail("failed to run {s}: {s}", .{ argv[0], @errorName(err) });

    if (result.stderr.len > 0) {
        try s.result_error_msgs.append(arena, result.stderr);
    }

    return result;
}

pub fn fail(step: *Step, comptime fmt: []const u8, args: anytype) error{ OutOfMemory, MakeFailed } {
    try step.addError(fmt, args);
    return error.MakeFailed;
}

pub fn addError(step: *Step, comptime fmt: []const u8, args: anytype) error{OutOfMemory}!void {
    const arena = step.owner.allocator;
    const msg = try std.fmt.allocPrint(arena, fmt, args);
    try step.result_error_msgs.append(arena, msg);
}

pub const ZigProcess = struct {
    child: std.process.Child,
    poller: std.io.Poller(StreamEnum),
    progress_ipc_fd: if (std.Progress.have_ipc) ?std.posix.fd_t else void,

    pub const StreamEnum = enum { stdout, stderr };
};

/// Assumes that argv contains `--listen=-` and that the process being spawned
/// is the zig compiler - the same version that compiled the build runner.
pub fn evalZigProcess(
    s: *Step,
    argv: []const []const u8,
    prog_node: std.Progress.Node,
    watch: bool,
) !?Path {
    if (s.getZigProcess()) |zp| update: {
        assert(watch);
        if (std.Progress.have_ipc) if (zp.progress_ipc_fd) |fd| prog_node.setIpcFd(fd);
        const result = zigProcessUpdate(s, zp, watch) catch |err| switch (err) {
            error.BrokenPipe => {
                // Process restart required.
                const term = zp.child.wait() catch |e| {
                    return s.fail("unable to wait for {s}: {s}", .{ argv[0], @errorName(e) });
                };
                _ = term;
                s.clearZigProcess();
                break :update;
            },
            else => |e| return e,
        };

        if (s.result_error_bundle.errorMessageCount() > 0)
            return s.fail("{d} compilation errors", .{s.result_error_bundle.errorMessageCount()});

        if (s.result_error_msgs.items.len > 0 and result == null) {
            // Crash detected.
            const term = zp.child.wait() catch |e| {
                return s.fail("unable to wait for {s}: {s}", .{ argv[0], @errorName(e) });
            };
            s.result_peak_rss = zp.child.resource_usage_statistics.getMaxRss() orelse 0;
            s.clearZigProcess();
            try handleChildProcessTerm(s, term, null, argv);
            return error.MakeFailed;
        }

        return result;
    }
    assert(argv.len != 0);
    const b = s.owner;
    const arena = b.allocator;
    const gpa = arena;

    try handleChildProcUnsupported(s, null, argv);
    try handleVerbose(s.owner, null, argv);

    var child = std.process.Child.init(argv, arena);
    child.env_map = &b.graph.env_map;
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.request_resource_usage_statistics = true;
    child.progress_node = prog_node;

    child.spawn() catch |err| return s.fail("failed to spawn zig compiler {s}: {s}", .{
        argv[0], @errorName(err),
    });

    const zp = try gpa.create(ZigProcess);
    zp.* = .{
        .child = child,
        .poller = std.io.poll(gpa, ZigProcess.StreamEnum, .{
            .stdout = child.stdout.?,
            .stderr = child.stderr.?,
        }),
        .progress_ipc_fd = if (std.Progress.have_ipc) child.progress_node.getIpcFd() else {},
    };
    if (watch) s.setZigProcess(zp);
    defer if (!watch) zp.poller.deinit();

    const result = try zigProcessUpdate(s, zp, watch);

    if (!watch) {
        // Send EOF to stdin.
        zp.child.stdin.?.close();
        zp.child.stdin = null;

        const term = zp.child.wait() catch |err| {
            return s.fail("unable to wait for {s}: {s}", .{ argv[0], @errorName(err) });
        };
        s.result_peak_rss = zp.child.resource_usage_statistics.getMaxRss() orelse 0;

        // Special handling for Compile step that is expecting compile errors.
        if (s.cast(Compile)) |compile| switch (term) {
            .Exited => {
                // Note that the exit code may be 0 in this case due to the
                // compiler server protocol.
                if (compile.expect_errors != null) {
                    return error.NeedCompileErrorCheck;
                }
            },
            else => {},
        };

        try handleChildProcessTerm(s, term, null, argv);
    }

    // This is intentionally printed for failure on the first build but not for
    // subsequent rebuilds.
    if (s.result_error_bundle.errorMessageCount() > 0) {
        return s.fail("the following command failed with {d} compilation errors:\n{s}", .{
            s.result_error_bundle.errorMessageCount(),
            try allocPrintCmd(arena, null, argv),
        });
    }

    return result;
}

fn zigProcessUpdate(s: *Step, zp: *ZigProcess, watch: bool) !?Path {
    const b = s.owner;
    const arena = b.allocator;

    var timer = try std.time.Timer.start();

    try sendMessage(zp.child.stdin.?, .update);
    if (!watch) try sendMessage(zp.child.stdin.?, .exit);

    const Header = std.zig.Server.Message.Header;
    var result: ?Path = null;

    const stdout = zp.poller.fifo(.stdout);

    poll: while (true) {
        while (stdout.readableLength() < @sizeOf(Header)) {
            if (!(try zp.poller.poll())) break :poll;
        }
        const header = stdout.reader().readStruct(Header) catch unreachable;
        while (stdout.readableLength() < header.bytes_len) {
            if (!(try zp.poller.poll())) break :poll;
        }
        const body = stdout.readableSliceOfLen(header.bytes_len);

        switch (header.tag) {
            .zig_version => {
                if (!std.mem.eql(u8, builtin.zig_version_string, body)) {
                    return s.fail(
                        "zig version mismatch build runner vs compiler: '{s}' vs '{s}'",
                        .{ builtin.zig_version_string, body },
                    );
                }
            },
            .error_bundle => {
                const EbHdr = std.zig.Server.Message.ErrorBundle;
                const eb_hdr = @as(*align(1) const EbHdr, @ptrCast(body));
                const extra_bytes =
                    body[@sizeOf(EbHdr)..][0 .. @sizeOf(u32) * eb_hdr.extra_len];
                const string_bytes =
                    body[@sizeOf(EbHdr) + extra_bytes.len ..][0..eb_hdr.string_bytes_len];
                // TODO: use @ptrCast when the compiler supports it
                const unaligned_extra = std.mem.bytesAsSlice(u32, extra_bytes);
                const extra_array = try arena.alloc(u32, unaligned_extra.len);
                @memcpy(extra_array, unaligned_extra);
                s.result_error_bundle = .{
                    .string_bytes = try arena.dupe(u8, string_bytes),
                    .extra = extra_array,
                };
                if (watch) {
                    // This message indicates the end of the update.
                    stdout.discard(body.len);
                    break;
                }
            },
            .emit_digest => {
                const EmitDigest = std.zig.Server.Message.EmitDigest;
                const emit_digest = @as(*align(1) const EmitDigest, @ptrCast(body));
                s.result_cached = emit_digest.flags.cache_hit;
                const digest = body[@sizeOf(EmitDigest)..][0..Cache.bin_digest_len];
                result = .{
                    .root_dir = b.cache_root,
                    .sub_path = try arena.dupe(u8, "o" ++ std.fs.path.sep_str ++ Cache.binToHex(digest.*)),
                };
            },
            .file_system_inputs => {
                s.clearWatchInputs();
                var it = std.mem.splitScalar(u8, body, 0);
                while (it.next()) |prefixed_path| {
                    const prefix_index: std.zig.Server.Message.PathPrefix = @enumFromInt(prefixed_path[0] - 1);
                    const sub_path = try arena.dupe(u8, prefixed_path[1..]);
                    const sub_path_dirname = std.fs.path.dirname(sub_path) orelse "";
                    switch (prefix_index) {
                        .cwd => {
                            const path: Build.Cache.Path = .{
                                .root_dir = Build.Cache.Directory.cwd(),
                                .sub_path = sub_path_dirname,
                            };
                            try addWatchInputFromPath(s, path, std.fs.path.basename(sub_path));
                        },
                        .zig_lib => zl: {
                            if (s.cast(Step.Compile)) |compile| {
                                if (compile.zig_lib_dir) |zig_lib_dir| {
                                    const lp = try zig_lib_dir.join(arena, sub_path);
                                    try addWatchInput(s, lp);
                                    break :zl;
                                }
                            }
                            const path: Build.Cache.Path = .{
                                .root_dir = s.owner.graph.zig_lib_directory,
                                .sub_path = sub_path_dirname,
                            };
                            try addWatchInputFromPath(s, path, std.fs.path.basename(sub_path));
                        },
                        .local_cache => {
                            const path: Build.Cache.Path = .{
                                .root_dir = b.cache_root,
                                .sub_path = sub_path_dirname,
                            };
                            try addWatchInputFromPath(s, path, std.fs.path.basename(sub_path));
                        },
                        .global_cache => {
                            const path: Build.Cache.Path = .{
                                .root_dir = s.owner.graph.global_cache_root,
                                .sub_path = sub_path_dirname,
                            };
                            try addWatchInputFromPath(s, path, std.fs.path.basename(sub_path));
                        },
                    }
                }
            },
            else => {}, // ignore other messages
        }

        stdout.discard(body.len);
    }

    s.result_duration_ns = timer.read();

    const stderr = zp.poller.fifo(.stderr);
    if (stderr.readableLength() > 0) {
        try s.result_error_msgs.append(arena, try stderr.toOwnedSlice());
    }

    return result;
}

pub fn getZigProcess(s: *Step) ?*ZigProcess {
    return switch (s.id) {
        .compile => s.cast(Compile).?.zig_process,
        else => null,
    };
}

fn setZigProcess(s: *Step, zp: *ZigProcess) void {
    switch (s.id) {
        .compile => s.cast(Compile).?.zig_process = zp,
        else => unreachable,
    }
}

fn clearZigProcess(s: *Step) void {
    const gpa = s.owner.allocator;
    switch (s.id) {
        .compile => {
            const compile = s.cast(Compile).?;
            if (compile.zig_process) |zp| {
                gpa.destroy(zp);
                compile.zig_process = null;
            }
        },
        else => unreachable,
    }
}

fn sendMessage(file: std.fs.File, tag: std.zig.Client.Message.Tag) !void {
    const header: std.zig.Client.Message.Header = .{
        .tag = tag,
        .bytes_len = 0,
    };
    try file.writeAll(std.mem.asBytes(&header));
}

pub fn handleVerbose(
    b: *Build,
    opt_cwd: ?[]const u8,
    argv: []const []const u8,
) error{OutOfMemory}!void {
    return handleVerbose2(b, opt_cwd, null, argv);
}

pub fn handleVerbose2(
    b: *Build,
    opt_cwd: ?[]const u8,
    opt_env: ?*const std.process.EnvMap,
    argv: []const []const u8,
) error{OutOfMemory}!void {
    if (b.verbose) {
        // Intention of verbose is to print all sub-process command lines to
        // stderr before spawning them.
        const text = try allocPrintCmd2(b.allocator, opt_cwd, opt_env, argv);
        std.debug.print("{s}\n", .{text});
    }
}

pub inline fn handleChildProcUnsupported(
    s: *Step,
    opt_cwd: ?[]const u8,
    argv: []const []const u8,
) error{ OutOfMemory, MakeFailed }!void {
    if (!std.process.can_spawn) {
        return s.fail(
            "unable to execute the following command: host cannot spawn child processes\n{s}",
            .{try allocPrintCmd(s.owner.allocator, opt_cwd, argv)},
        );
    }
}

pub fn handleChildProcessTerm(
    s: *Step,
    term: std.process.Child.Term,
    opt_cwd: ?[]const u8,
    argv: []const []const u8,
) error{ MakeFailed, OutOfMemory }!void {
    const arena = s.owner.allocator;
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                return s.fail(
                    "the following command exited with error code {d}:\n{s}",
                    .{ code, try allocPrintCmd(arena, opt_cwd, argv) },
                );
            }
        },
        .Signal, .Stopped, .Unknown => {
            return s.fail(
                "the following command terminated unexpectedly:\n{s}",
                .{try allocPrintCmd(arena, opt_cwd, argv)},
            );
        },
    }
}

pub fn allocPrintCmd(
    arena: Allocator,
    opt_cwd: ?[]const u8,
    argv: []const []const u8,
) Allocator.Error![]u8 {
    return allocPrintCmd2(arena, opt_cwd, null, argv);
}

pub fn allocPrintCmd2(
    arena: Allocator,
    opt_cwd: ?[]const u8,
    opt_env: ?*const std.process.EnvMap,
    argv: []const []const u8,
) Allocator.Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    if (opt_cwd) |cwd| try buf.writer(arena).print("cd {s} && ", .{cwd});
    if (opt_env) |env| {
        const process_env_map = std.process.getEnvMap(arena) catch std.process.EnvMap.init(arena);
        var it = env.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            if (process_env_map.get(key)) |process_value| {
                if (std.mem.eql(u8, value, process_value)) continue;
            }
            try buf.writer(arena).print("{s}={s} ", .{ key, value });
        }
    }
    for (argv) |arg| {
        try buf.writer(arena).print("{s} ", .{arg});
    }
    return buf.toOwnedSlice(arena);
}

/// Prefer `cacheHitAndWatch` unless you already added watch inputs
/// separately from using the cache system.
pub fn cacheHit(s: *Step, man: *Build.Cache.Manifest) !bool {
    s.result_cached = man.hit() catch |err| return failWithCacheError(s, man, err);
    return s.result_cached;
}

/// Clears previous watch inputs, if any, and then populates watch inputs from
/// the full set of files picked up by the cache manifest.
///
/// Must be accompanied with `writeManifestAndWatch`.
pub fn cacheHitAndWatch(s: *Step, man: *Build.Cache.Manifest) !bool {
    const is_hit = man.hit() catch |err| return failWithCacheError(s, man, err);
    s.result_cached = is_hit;
    // The above call to hit() populates the manifest with files, so in case of
    // a hit, we need to populate watch inputs.
    if (is_hit) try setWatchInputsFromManifest(s, man);
    return is_hit;
}

fn failWithCacheError(s: *Step, man: *const Build.Cache.Manifest, err: Build.Cache.Manifest.HitError) error{ OutOfMemory, MakeFailed } {
    switch (err) {
        error.CacheCheckFailed => switch (man.diagnostic) {
            .none => unreachable,
            .manifest_create, .manifest_read, .manifest_lock, .manifest_seek => |e| return s.fail("failed to check cache: {s} {s}", .{
                @tagName(man.diagnostic), @errorName(e),
            }),
            .file_open, .file_stat, .file_read, .file_hash => |op| {
                const pp = man.files.keys()[op.file_index].prefixed_path;
                const prefix = man.cache.prefixes()[pp.prefix].path orelse "";
                return s.fail("failed to check cache: '{s}{c}{s}' {s} {s}", .{
                    prefix, std.fs.path.sep, pp.sub_path, @tagName(man.diagnostic), @errorName(op.err),
                });
            },
        },
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidFormat => return s.fail("failed to check cache: invalid manifest file format", .{}),
    }
}

/// Prefer `writeManifestAndWatch` unless you already added watch inputs
/// separately from using the cache system.
pub fn writeManifest(s: *Step, man: *Build.Cache.Manifest) !void {
    if (s.test_results.isSuccess()) {
        man.writeManifest() catch |err| {
            try s.addError("unable to write cache manifest: {s}", .{@errorName(err)});
        };
    }
}

/// Clears previous watch inputs, if any, and then populates watch inputs from
/// the full set of files picked up by the cache manifest.
///
/// Must be accompanied with `cacheHitAndWatch`.
pub fn writeManifestAndWatch(s: *Step, man: *Build.Cache.Manifest) !void {
    try writeManifest(s, man);
    try setWatchInputsFromManifest(s, man);
}

fn setWatchInputsFromManifest(s: *Step, man: *Build.Cache.Manifest) !void {
    const arena = s.owner.allocator;
    const prefixes = man.cache.prefixes();
    clearWatchInputs(s);
    for (man.files.keys()) |file| {
        // The file path data is freed when the cache manifest is cleaned up at the end of `make`.
        const sub_path = try arena.dupe(u8, file.prefixed_path.sub_path);
        try addWatchInputFromPath(s, .{
            .root_dir = prefixes[file.prefixed_path.prefix],
            .sub_path = std.fs.path.dirname(sub_path) orelse "",
        }, std.fs.path.basename(sub_path));
    }
}

/// For steps that have a single input that never changes when re-running `make`.
pub fn singleUnchangingWatchInput(step: *Step, lazy_path: Build.LazyPath) Allocator.Error!void {
    if (!step.inputs.populated()) try step.addWatchInput(lazy_path);
}

pub fn clearWatchInputs(step: *Step) void {
    const gpa = step.owner.allocator;
    step.inputs.clear(gpa);
}

/// Places a *file* dependency on the path.
pub fn addWatchInput(step: *Step, lazy_file: Build.LazyPath) Allocator.Error!void {
    switch (lazy_file) {
        .src_path => |src_path| try addWatchInputFromBuilder(step, src_path.owner, src_path.sub_path),
        .dependency => |d| try addWatchInputFromBuilder(step, d.dependency.builder, d.sub_path),
        .cwd_relative => |path_string| {
            try addWatchInputFromPath(step, .{
                .root_dir = .{
                    .path = null,
                    .handle = std.fs.cwd(),
                },
                .sub_path = std.fs.path.dirname(path_string) orelse "",
            }, std.fs.path.basename(path_string));
        },
        // Nothing to watch because this dependency edge is modeled instead via `dependants`.
        .generated => {},
    }
}

/// Any changes inside the directory will trigger invalidation.
///
/// See also `addDirectoryWatchInputFromPath` which takes a `Build.Cache.Path` instead.
///
/// Paths derived from this directory should also be manually added via
/// `addDirectoryWatchInputFromPath` if and only if this function returns
/// `true`.
pub fn addDirectoryWatchInput(step: *Step, lazy_directory: Build.LazyPath) Allocator.Error!bool {
    switch (lazy_directory) {
        .src_path => |src_path| try addDirectoryWatchInputFromBuilder(step, src_path.owner, src_path.sub_path),
        .dependency => |d| try addDirectoryWatchInputFromBuilder(step, d.dependency.builder, d.sub_path),
        .cwd_relative => |path_string| {
            try addDirectoryWatchInputFromPath(step, .{
                .root_dir = .{
                    .path = null,
                    .handle = std.fs.cwd(),
                },
                .sub_path = path_string,
            });
        },
        // Nothing to watch because this dependency edge is modeled instead via `dependants`.
        .generated => return false,
    }
    return true;
}

/// Any changes inside the directory will trigger invalidation.
///
/// See also `addDirectoryWatchInput` which takes a `Build.LazyPath` instead.
///
/// This function should only be called when it has been verified that the
/// dependency on `path` is not already accounted for by a `Step` dependency.
/// In other words, before calling this function, first check that the
/// `Build.LazyPath` which this `path` is derived from is not `generated`.
pub fn addDirectoryWatchInputFromPath(step: *Step, path: Build.Cache.Path) !void {
    return addWatchInputFromPath(step, path, ".");
}

fn addWatchInputFromBuilder(step: *Step, builder: *Build, sub_path: []const u8) !void {
    return addWatchInputFromPath(step, .{
        .root_dir = builder.build_root,
        .sub_path = std.fs.path.dirname(sub_path) orelse "",
    }, std.fs.path.basename(sub_path));
}

fn addDirectoryWatchInputFromBuilder(step: *Step, builder: *Build, sub_path: []const u8) !void {
    return addDirectoryWatchInputFromPath(step, .{
        .root_dir = builder.build_root,
        .sub_path = sub_path,
    });
}

fn addWatchInputFromPath(step: *Step, path: Build.Cache.Path, basename: []const u8) !void {
    const gpa = step.owner.allocator;
    const gop = try step.inputs.table.getOrPut(gpa, path);
    if (!gop.found_existing) gop.value_ptr.* = .{};
    try gop.value_ptr.append(gpa, basename);
}

fn reset(step: *Step, gpa: Allocator) void {
    assert(step.state == .precheck_done);

    step.result_error_msgs.clearRetainingCapacity();
    step.result_stderr = "";
    step.result_cached = false;
    step.result_duration_ns = null;
    step.result_peak_rss = 0;
    step.test_results = .{};

    step.result_error_bundle.deinit(gpa);
    step.result_error_bundle = std.zig.ErrorBundle.empty;
}

/// Implementation detail of file watching. Prepares the step for being re-evaluated.
pub fn recursiveReset(step: *Step, gpa: Allocator) void {
    assert(step.state != .precheck_done);
    step.state = .precheck_done;
    step.reset(gpa);
    for (step.dependants.items) |dep| {
        if (dep.state == .precheck_done) continue;
        dep.recursiveReset(gpa);
    }
}

test {
    _ = CheckFile;
    _ = CheckObject;
    _ = Fail;
    _ = Fmt;
    _ = InstallArtifact;
    _ = InstallDir;
    _ = InstallFile;
    _ = ObjCopy;
    _ = Compile;
    _ = Options;
    _ = RemoveDir;
    _ = Run;
    _ = TranslateC;
    _ = WriteFile;
    _ = UpdateSourceFiles;
}
//! Fail the build step if a file does not match certain checks.
//! TODO: make this more flexible, supporting more kinds of checks.
//! TODO: generalize the code in std.testing.expectEqualStrings and make this
//! CheckFile step produce those helpful diagnostics when there is not a match.
const CheckFile = @This();
const std = @import("std");
const Step = std.Build.Step;
const fs = std.fs;
const mem = std.mem;

step: Step,
expected_matches: []const []const u8,
expected_exact: ?[]const u8,
source: std.Build.LazyPath,
max_bytes: usize = 20 * 1024 * 1024,

pub const base_id: Step.Id = .check_file;

pub const Options = struct {
    expected_matches: []const []const u8 = &.{},
    expected_exact: ?[]const u8 = null,
};

pub fn create(
    owner: *std.Build,
    source: std.Build.LazyPath,
    options: Options,
) *CheckFile {
    const check_file = owner.allocator.create(CheckFile) catch @panic("OOM");
    check_file.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "CheckFile",
            .owner = owner,
            .makeFn = make,
        }),
        .source = source.dupe(owner),
        .expected_matches = owner.dupeStrings(options.expected_matches),
        .expected_exact = options.expected_exact,
    };
    check_file.source.addStepDependencies(&check_file.step);
    return check_file;
}

pub fn setName(check_file: *CheckFile, name: []const u8) void {
    check_file.step.name = name;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;
    const b = step.owner;
    const check_file: *CheckFile = @fieldParentPtr("step", step);
    try step.singleUnchangingWatchInput(check_file.source);

    const src_path = check_file.source.getPath2(b, step);
    const contents = fs.cwd().readFileAlloc(b.allocator, src_path, check_file.max_bytes) catch |err| {
        return step.fail("unable to read '{s}': {s}", .{
            src_path, @errorName(err),
        });
    };

    for (check_file.expected_matches) |expected_match| {
        if (mem.indexOf(u8, contents, expected_match) == null) {
            return step.fail(
                \\
                \\========= expected to find: ===================
                \\{s}
                \\========= but file does not contain it: =======
                \\{s}
                \\===============================================
            , .{ expected_match, contents });
        }
    }

    if (check_file.expected_exact) |expected_exact| {
        if (!mem.eql(u8, expected_exact, contents)) {
            return step.fail(
                \\
                \\========= expected: =====================
                \\{s}
                \\========= but found: ====================
                \\{s}
                \\========= from the following file: ======
                \\{s}
            , .{ expected_exact, contents, src_path });
        }
    }
}
const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const testing = std.testing;

const CheckObject = @This();

const Allocator = mem.Allocator;
const Step = std.Build.Step;

pub const base_id: Step.Id = .check_object;

step: Step,
source: std.Build.LazyPath,
max_bytes: usize = 20 * 1024 * 1024,
checks: std.ArrayList(Check),
obj_format: std.Target.ObjectFormat,

pub fn create(
    owner: *std.Build,
    source: std.Build.LazyPath,
    obj_format: std.Target.ObjectFormat,
) *CheckObject {
    const gpa = owner.allocator;
    const check_object = gpa.create(CheckObject) catch @panic("OOM");
    check_object.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "CheckObject",
            .owner = owner,
            .makeFn = make,
        }),
        .source = source.dupe(owner),
        .checks = std.ArrayList(Check).init(gpa),
        .obj_format = obj_format,
    };
    check_object.source.addStepDependencies(&check_object.step);
    return check_object;
}

const SearchPhrase = struct {
    string: []const u8,
    lazy_path: ?std.Build.LazyPath = null,

    fn resolve(phrase: SearchPhrase, b: *std.Build, step: *Step) []const u8 {
        const lazy_path = phrase.lazy_path orelse return phrase.string;
        return b.fmt("{s} {s}", .{ phrase.string, lazy_path.getPath2(b, step) });
    }
};

/// There five types of actions currently supported:
/// .exact - will do an exact match against the haystack
/// .contains - will check for existence within the haystack
/// .not_present - will check for non-existence within the haystack
/// .extract - will do an exact match and extract into a variable enclosed within `{name}` braces
/// .compute_cmp - will perform an operation on the extracted global variables
/// using the MatchAction. It currently only supports an addition. The operation is required
/// to be specified in Reverse Polish Notation to ease in operator-precedence parsing (well,
/// to avoid any parsing really).
/// For example, if the two extracted values were saved as `vmaddr` and `entryoff` respectively
/// they could then be added with this simple program `vmaddr entryoff +`.
const Action = struct {
    tag: enum { exact, contains, not_present, extract, compute_cmp },
    phrase: SearchPhrase,
    expected: ?ComputeCompareExpected = null,

    /// Returns true if the `phrase` is an exact match with the haystack and variable was successfully extracted.
    fn extract(
        act: Action,
        b: *std.Build,
        step: *Step,
        haystack: []const u8,
        global_vars: anytype,
    ) !bool {
        assert(act.tag == .extract);
        const hay = mem.trim(u8, haystack, " ");
        const phrase = mem.trim(u8, act.phrase.resolve(b, step), " ");

        var candidate_vars = std.ArrayList(struct { name: []const u8, value: u64 }).init(b.allocator);
        var hay_it = mem.tokenizeScalar(u8, hay, ' ');
        var needle_it = mem.tokenizeScalar(u8, phrase, ' ');

        while (needle_it.next()) |needle_tok| {
            const hay_tok = hay_it.next() orelse break;
            if (mem.startsWith(u8, needle_tok, "{")) {
                const closing_brace = mem.indexOf(u8, needle_tok, "}") orelse return error.MissingClosingBrace;
                if (closing_brace != needle_tok.len - 1) return error.ClosingBraceNotLast;

                const name = needle_tok[1..closing_brace];
                if (name.len == 0) return error.MissingBraceValue;
                const value = std.fmt.parseInt(u64, hay_tok, 16) catch return false;
                try candidate_vars.append(.{
                    .name = name,
                    .value = value,
                });
            } else {
                if (!mem.eql(u8, hay_tok, needle_tok)) return false;
            }
        }

        if (candidate_vars.items.len == 0) return false;

        for (candidate_vars.items) |cv| try global_vars.putNoClobber(cv.name, cv.value);

        return true;
    }

    /// Returns true if the `phrase` is an exact match with the haystack.
    fn exact(
        act: Action,
        b: *std.Build,
        step: *Step,
        haystack: []const u8,
    ) bool {
        assert(act.tag == .exact);
        const hay = mem.trim(u8, haystack, " ");
        const phrase = mem.trim(u8, act.phrase.resolve(b, step), " ");
        return mem.eql(u8, hay, phrase);
    }

    /// Returns true if the `phrase` exists within the haystack.
    fn contains(
        act: Action,
        b: *std.Build,
        step: *Step,
        haystack: []const u8,
    ) bool {
        assert(act.tag == .contains);
        const hay = mem.trim(u8, haystack, " ");
        const phrase = mem.trim(u8, act.phrase.resolve(b, step), " ");
        return mem.indexOf(u8, hay, phrase) != null;
    }

    /// Returns true if the `phrase` does not exist within the haystack.
    fn notPresent(
        act: Action,
        b: *std.Build,
        step: *Step,
        haystack: []const u8,
    ) bool {
        assert(act.tag == .not_present);
        return !contains(.{
            .tag = .contains,
            .phrase = act.phrase,
            .expected = act.expected,
        }, b, step, haystack);
    }

    /// Will return true if the `phrase` is correctly parsed into an RPN program and
    /// its reduced, computed value compares using `op` with the expected value, either
    /// a literal or another extracted variable.
    fn computeCmp(act: Action, b: *std.Build, step: *Step, global_vars: anytype) !bool {
        const gpa = step.owner.allocator;
        const phrase = act.phrase.resolve(b, step);
        var op_stack = std.ArrayList(enum { add, sub, mod, mul }).init(gpa);
        var values = std.ArrayList(u64).init(gpa);

        var it = mem.tokenizeScalar(u8, phrase, ' ');
        while (it.next()) |next| {
            if (mem.eql(u8, next, "+")) {
                try op_stack.append(.add);
            } else if (mem.eql(u8, next, "-")) {
                try op_stack.append(.sub);
            } else if (mem.eql(u8, next, "%")) {
                try op_stack.append(.mod);
            } else if (mem.eql(u8, next, "*")) {
                try op_stack.append(.mul);
            } else {
                const val = std.fmt.parseInt(u64, next, 0) catch blk: {
                    break :blk global_vars.get(next) orelse {
                        try step.addError(
                            \\
                            \\========= variable was not extracted: ===========
                            \\{s}
                            \\=================================================
                        , .{next});
                        return error.UnknownVariable;
                    };
                };
                try values.append(val);
            }
        }

        var op_i: usize = 1;
        var reduced: u64 = values.items[0];
        for (op_stack.items) |op| {
            const other = values.items[op_i];
            switch (op) {
                .add => {
                    reduced += other;
                },
                .sub => {
                    reduced -= other;
                },
                .mod => {
                    reduced %= other;
                },
                .mul => {
                    reduced *= other;
                },
            }
            op_i += 1;
        }

        const exp_value = switch (act.expected.?.value) {
            .variable => |name| global_vars.get(name) orelse {
                try step.addError(
                    \\
                    \\========= variable was not extracted: ===========
                    \\{s}
                    \\=================================================
                , .{name});
                return error.UnknownVariable;
            },
            .literal => |x| x,
        };
        return math.compare(reduced, act.expected.?.op, exp_value);
    }
};

const ComputeCompareExpected = struct {
    op: math.CompareOperator,
    value: union(enum) {
        variable: []const u8,
        literal: u64,
    },

    pub fn format(
        value: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, value);
        _ = options;
        try writer.print("{s} ", .{@tagName(value.op)});
        switch (value.value) {
            .variable => |name| try writer.writeAll(name),
            .literal => |x| try writer.print("{x}", .{x}),
        }
    }
};

const Check = struct {
    kind: Kind,
    payload: Payload,
    data: std.ArrayList(u8),
    actions: std.ArrayList(Action),

    fn create(allocator: Allocator, kind: Kind) Check {
        return .{
            .kind = kind,
            .payload = .{ .none = {} },
            .data = std.ArrayList(u8).init(allocator),
            .actions = std.ArrayList(Action).init(allocator),
        };
    }

    fn dumpSection(allocator: Allocator, name: [:0]const u8) Check {
        var check = Check.create(allocator, .dump_section);
        const off: u32 = @intCast(check.data.items.len);
        check.data.writer().print("{s}\x00", .{name}) catch @panic("OOM");
        check.payload = .{ .dump_section = off };
        return check;
    }

    fn extract(check: *Check, phrase: SearchPhrase) void {
        check.actions.append(.{
            .tag = .extract,
            .phrase = phrase,
        }) catch @panic("OOM");
    }

    fn exact(check: *Check, phrase: SearchPhrase) void {
        check.actions.append(.{
            .tag = .exact,
            .phrase = phrase,
        }) catch @panic("OOM");
    }

    fn contains(check: *Check, phrase: SearchPhrase) void {
        check.actions.append(.{
            .tag = .contains,
            .phrase = phrase,
        }) catch @panic("OOM");
    }

    fn notPresent(check: *Check, phrase: SearchPhrase) void {
        check.actions.append(.{
            .tag = .not_present,
            .phrase = phrase,
        }) catch @panic("OOM");
    }

    fn computeCmp(check: *Check, phrase: SearchPhrase, expected: ComputeCompareExpected) void {
        check.actions.append(.{
            .tag = .compute_cmp,
            .phrase = phrase,
            .expected = expected,
        }) catch @panic("OOM");
    }

    const Kind = enum {
        headers,
        symtab,
        indirect_symtab,
        dynamic_symtab,
        archive_symtab,
        dynamic_section,
        dyld_rebase,
        dyld_bind,
        dyld_weak_bind,
        dyld_lazy_bind,
        exports,
        compute_compare,
        dump_section,
    };

    const Payload = union {
        none: void,
        /// Null-delimited string in the 'data' buffer.
        dump_section: u32,
    };
};

/// Creates a new empty sequence of actions.
fn checkStart(check_object: *CheckObject, kind: Check.Kind) void {
    const check = Check.create(check_object.step.owner.allocator, kind);
    check_object.checks.append(check) catch @panic("OOM");
}

/// Adds an exact match phrase to the latest created Check.
pub fn checkExact(check_object: *CheckObject, phrase: []const u8) void {
    check_object.checkExactInner(phrase, null);
}

/// Like `checkExact()` but takes an additional argument `LazyPath` which will be
/// resolved to a full search query in `make()`.
pub fn checkExactPath(check_object: *CheckObject, phrase: []const u8, lazy_path: std.Build.LazyPath) void {
    check_object.checkExactInner(phrase, lazy_path);
}

fn checkExactInner(check_object: *CheckObject, phrase: []const u8, lazy_path: ?std.Build.LazyPath) void {
    assert(check_object.checks.items.len > 0);
    const last = &check_object.checks.items[check_object.checks.items.len - 1];
    last.exact(.{ .string = check_object.step.owner.dupe(phrase), .lazy_path = lazy_path });
}

/// Adds a fuzzy match phrase to the latest created Check.
pub fn checkContains(check_object: *CheckObject, phrase: []const u8) void {
    check_object.checkContainsInner(phrase, null);
}

/// Like `checkContains()` but takes an additional argument `lazy_path` which will be
/// resolved to a full search query in `make()`.
pub fn checkContainsPath(
    check_object: *CheckObject,
    phrase: []const u8,
    lazy_path: std.Build.LazyPath,
) void {
    check_object.checkContainsInner(phrase, lazy_path);
}

fn checkContainsInner(check_object: *CheckObject, phrase: []const u8, lazy_path: ?std.Build.LazyPath) void {
    assert(check_object.checks.items.len > 0);
    const last = &check_object.checks.items[check_object.checks.items.len - 1];
    last.contains(.{ .string = check_object.step.owner.dupe(phrase), .lazy_path = lazy_path });
}

/// Adds an exact match phrase with variable extractor to the latest created Check.
pub fn checkExtract(check_object: *CheckObject, phrase: []const u8) void {
    check_object.checkExtractInner(phrase, null);
}

/// Like `checkExtract()` but takes an additional argument `LazyPath` which will be
/// resolved to a full search query in `make()`.
pub fn checkExtractLazyPath(check_object: *CheckObject, phrase: []const u8, lazy_path: std.Build.LazyPath) void {
    check_object.checkExtractInner(phrase, lazy_path);
}

fn checkExtractInner(check_object: *CheckObject, phrase: []const u8, lazy_path: ?std.Build.LazyPath) void {
    assert(check_object.checks.items.len > 0);
    const last = &check_object.checks.items[check_object.checks.items.len - 1];
    last.extract(.{ .string = check_object.step.owner.dupe(phrase), .lazy_path = lazy_path });
}

/// Adds another searched phrase to the latest created Check
/// however ensures there is no matching phrase in the output.
pub fn checkNotPresent(check_object: *CheckObject, phrase: []const u8) void {
    check_object.checkNotPresentInner(phrase, null);
}

/// Like `checkExtract()` but takes an additional argument `LazyPath` which will be
/// resolved to a full search query in `make()`.
pub fn checkNotPresentLazyPath(check_object: *CheckObject, phrase: []const u8, lazy_path: std.Build.LazyPath) void {
    check_object.checkNotPresentInner(phrase, lazy_path);
}

fn checkNotPresentInner(check_object: *CheckObject, phrase: []const u8, lazy_path: ?std.Build.LazyPath) void {
    assert(check_object.checks.items.len > 0);
    const last = &check_object.checks.items[check_object.checks.items.len - 1];
    last.notPresent(.{ .string = check_object.step.owner.dupe(phrase), .lazy_path = lazy_path });
}

/// Creates a new check checking in the file headers (section, program headers, etc.).
pub fn checkInHeaders(check_object: *CheckObject) void {
    check_object.checkStart(.headers);
}

/// Creates a new check checking specifically symbol table parsed and dumped from the object
/// file.
pub fn checkInSymtab(check_object: *CheckObject) void {
    const label = switch (check_object.obj_format) {
        .macho => MachODumper.symtab_label,
        .elf => ElfDumper.symtab_label,
        .wasm => WasmDumper.symtab_label,
        .coff => @panic("TODO symtab for coff"),
        else => @panic("TODO other file formats"),
    };
    check_object.checkStart(.symtab);
    check_object.checkExact(label);
}

/// Creates a new check checking specifically dyld rebase opcodes contents parsed and dumped
/// from the object file.
/// This check is target-dependent and applicable to MachO only.
pub fn checkInDyldRebase(check_object: *CheckObject) void {
    const label = switch (check_object.obj_format) {
        .macho => MachODumper.dyld_rebase_label,
        else => @panic("Unsupported target platform"),
    };
    check_object.checkStart(.dyld_rebase);
    check_object.checkExact(label);
}

/// Creates a new check checking specifically dyld bind opcodes contents parsed and dumped
/// from the object file.
/// This check is target-dependent and applicable to MachO only.
pub fn checkInDyldBind(check_object: *CheckObject) void {
    const label = switch (check_object.obj_format) {
        .macho => MachODumper.dyld_bind_label,
        else => @panic("Unsupported target platform"),
    };
    check_object.checkStart(.dyld_bind);
    check_object.checkExact(label);
}

/// Creates a new check checking specifically dyld weak bind opcodes contents parsed and dumped
/// from the object file.
/// This check is target-dependent and applicable to MachO only.
pub fn checkInDyldWeakBind(check_object: *CheckObject) void {
    const label = switch (check_object.obj_format) {
        .macho => MachODumper.dyld_weak_bind_label,
        else => @panic("Unsupported target platform"),
    };
    check_object.checkStart(.dyld_weak_bind);
    check_object.checkExact(label);
}

/// Creates a new check checking specifically dyld lazy bind opcodes contents parsed and dumped
/// from the object file.
/// This check is target-dependent and applicable to MachO only.
pub fn checkInDyldLazyBind(check_object: *CheckObject) void {
    const label = switch (check_object.obj_format) {
        .macho => MachODumper.dyld_lazy_bind_label,
        else => @panic("Unsupported target platform"),
    };
    check_object.checkStart(.dyld_lazy_bind);
    check_object.checkExact(label);
}

/// Creates a new check checking specifically exports info contents parsed and dumped
/// from the object file.
/// This check is target-dependent and applicable to MachO only.
pub fn checkInExports(check_object: *CheckObject) void {
    const label = switch (check_object.obj_format) {
        .macho => MachODumper.exports_label,
        else => @pani```
