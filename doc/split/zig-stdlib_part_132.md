```
        };
        defer sdk.free(args.allocator);

        try self.findNativeMsvcIncludeDir(args, sdk);
        try self.findNativeMsvcLibDir(args, sdk);
        try self.findNativeKernel32LibDir(args, sdk);
        try self.findNativeIncludeDirWindows(args, sdk);
        try self.findNativeCrtDirWindows(args, sdk);
    } else if (is_haiku) {
        try self.findNativeIncludeDirPosix(args);
        try self.findNativeGccDirHaiku(args);
        self.crt_dir = try args.allocator.dupeZ(u8, "/system/develop/lib");
    } else if (builtin.target.os.tag.isSolarish()) {
        // There is only one libc, and its headers/libraries are always in the same spot.
        self.include_dir = try args.allocator.dupeZ(u8, "/usr/include");
        self.sys_include_dir = try args.allocator.dupeZ(u8, "/usr/include");
        self.crt_dir = try args.allocator.dupeZ(u8, "/usr/lib/64");
    } else if (std.process.can_spawn) {
        try self.findNativeIncludeDirPosix(args);
        switch (builtin.target.os.tag) {
            .freebsd, .netbsd, .openbsd, .dragonfly => self.crt_dir = try args.allocator.dupeZ(u8, "/usr/lib"),
            .linux => try self.findNativeCrtDirPosix(args),
            else => {},
        }
    } else {
        return error.LibCRuntimeNotFound;
    }
    return self;
}

/// Must be the same allocator passed to `parse` or `findNative`.
pub fn deinit(self: *LibCInstallation, allocator: Allocator) void {
    const fields = std.meta.fields(LibCInstallation);
    inline for (fields) |field| {
        if (@field(self, field.name)) |payload| {
            allocator.free(payload);
        }
    }
    self.* = undefined;
}

fn findNativeIncludeDirPosix(self: *LibCInstallation, args: FindNativeOptions) FindError!void {
    const allocator = args.allocator;

    // Detect infinite loops.
    var env_map = std.process.getEnvMap(allocator) catch |err| switch (err) {
        error.Unexpected => unreachable, // WASI-only
        else => |e| return e,
    };
    defer env_map.deinit();
    const skip_cc_env_var = if (env_map.get(inf_loop_env_key)) |phase| blk: {
        if (std.mem.eql(u8, phase, "1")) {
            try env_map.put(inf_loop_env_key, "2");
            break :blk true;
        } else {
            return error.ZigIsTheCCompiler;
        }
    } else blk: {
        try env_map.put(inf_loop_env_key, "1");
        break :blk false;
    };

    const dev_null = if (is_windows) "nul" else "/dev/null";

    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();

    try appendCcExe(&argv, skip_cc_env_var);
    try argv.appendSlice(&.{
        "-E",
        "-Wp,-v",
        "-xc",
        dev_null,
    });

    const run_res = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
        .max_output_bytes = 1024 * 1024,
        .env_map = &env_map,
        // Some C compilers, such as Clang, are known to rely on argv[0] to find the path
        // to their own executable, without even bothering to resolve PATH. This results in the message:
        // error: unable to execute command: Executable "" doesn't exist!
        // So we use the expandArg0 variant of ChildProcess to give them a helping hand.
        .expand_arg0 = .expand,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            printVerboseInvocation(argv.items, null, args.verbose, null);
            return error.UnableToSpawnCCompiler;
        },
    };
    defer {
        allocator.free(run_res.stdout);
        allocator.free(run_res.stderr);
    }
    switch (run_res.term) {
        .Exited => |code| if (code != 0) {
            printVerboseInvocation(argv.items, null, args.verbose, run_res.stderr);
            return error.CCompilerExitCode;
        },
        else => {
            printVerboseInvocation(argv.items, null, args.verbose, run_res.stderr);
            return error.CCompilerCrashed;
        },
    }

    var it = std.mem.tokenizeAny(u8, run_res.stderr, "\n\r");
    var search_paths = std.ArrayList([]const u8).init(allocator);
    defer search_paths.deinit();
    while (it.next()) |line| {
        if (line.len != 0 and line[0] == ' ') {
            try search_paths.append(line);
        }
    }
    if (search_paths.items.len == 0) {
        return error.CCompilerCannotFindHeaders;
    }

    const include_dir_example_file = if (is_haiku) "posix/stdlib.h" else "stdlib.h";
    const sys_include_dir_example_file = if (is_windows)
        "sys\\types.h"
    else if (is_haiku)
        "errno.h"
    else
        "sys/errno.h";

    var path_i: usize = 0;
    while (path_i < search_paths.items.len) : (path_i += 1) {
        // search in reverse order
        const search_path_untrimmed = search_paths.items[search_paths.items.len - path_i - 1];
        const search_path = std.mem.trimLeft(u8, search_path_untrimmed, " ");
        var search_dir = fs.cwd().openDir(search_path, .{}) catch |err| switch (err) {
            error.FileNotFound,
            error.NotDir,
            error.NoDevice,
            => continue,

            else => return error.FileSystem,
        };
        defer search_dir.close();

        if (self.include_dir == null) {
            if (search_dir.accessZ(include_dir_example_file, .{})) |_| {
                self.include_dir = try allocator.dupeZ(u8, search_path);
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => return error.FileSystem,
            }
        }

        if (self.sys_include_dir == null) {
            if (search_dir.accessZ(sys_include_dir_example_file, .{})) |_| {
                self.sys_include_dir = try allocator.dupeZ(u8, search_path);
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => return error.FileSystem,
            }
        }

        if (self.include_dir != null and self.sys_include_dir != null) {
            // Success.
            return;
        }
    }

    return error.LibCStdLibHeaderNotFound;
}

fn findNativeIncludeDirWindows(
    self: *LibCInstallation,
    args: FindNativeOptions,
    sdk: std.zig.WindowsSdk,
) FindError!void {
    const allocator = args.allocator;

    var install_buf: [2]std.zig.WindowsSdk.Installation = undefined;
    const installs = fillInstallations(&install_buf, sdk);

    var result_buf = std.ArrayList(u8).init(allocator);
    defer result_buf.deinit();

    for (installs) |install| {
        result_buf.shrinkAndFree(0);
        try result_buf.writer().print("{s}\\Include\\{s}\\ucrt", .{ install.path, install.version });

        var dir = fs.cwd().openDir(result_buf.items, .{}) catch |err| switch (err) {
            error.FileNotFound,
            error.NotDir,
            error.NoDevice,
            => continue,

            else => return error.FileSystem,
        };
        defer dir.close();

        dir.accessZ("stdlib.h", .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return error.FileSystem,
        };

        self.include_dir = try result_buf.toOwnedSlice();
        return;
    }

    return error.LibCStdLibHeaderNotFound;
}

fn findNativeCrtDirWindows(
    self: *LibCInstallation,
    args: FindNativeOptions,
    sdk: std.zig.WindowsSdk,
) FindError!void {
    const allocator = args.allocator;

    var install_buf: [2]std.zig.WindowsSdk.Installation = undefined;
    const installs = fillInstallations(&install_buf, sdk);

    var result_buf = std.ArrayList(u8).init(allocator);
    defer result_buf.deinit();

    const arch_sub_dir = switch (args.target.cpu.arch) {
        .x86 => "x86",
        .x86_64 => "x64",
        .arm, .armeb => "arm",
        .aarch64 => "arm64",
        else => return error.UnsupportedArchitecture,
    };

    for (installs) |install| {
        result_buf.shrinkAndFree(0);
        try result_buf.writer().print("{s}\\Lib\\{s}\\ucrt\\{s}", .{ install.path, install.version, arch_sub_dir });

        var dir = fs.cwd().openDir(result_buf.items, .{}) catch |err| switch (err) {
            error.FileNotFound,
            error.NotDir,
            error.NoDevice,
            => continue,

            else => return error.FileSystem,
        };
        defer dir.close();

        dir.accessZ("ucrt.lib", .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return error.FileSystem,
        };

        self.crt_dir = try result_buf.toOwnedSlice();
        return;
    }
    return error.LibCRuntimeNotFound;
}

fn findNativeCrtDirPosix(self: *LibCInstallation, args: FindNativeOptions) FindError!void {
    self.crt_dir = try ccPrintFileName(.{
        .allocator = args.allocator,
        .search_basename = switch (args.target.os.tag) {
            .linux => if (args.target.abi.isAndroid()) "crtbegin_dynamic.o" else "crt1.o",
            else => "crt1.o",
        },
        .want_dirname = .only_dir,
        .verbose = args.verbose,
    });
}

fn findNativeGccDirHaiku(self: *LibCInstallation, args: FindNativeOptions) FindError!void {
    self.gcc_dir = try ccPrintFileName(.{
        .allocator = args.allocator,
        .search_basename = "crtbeginS.o",
        .want_dirname = .only_dir,
        .verbose = args.verbose,
    });
}

fn findNativeKernel32LibDir(
    self: *LibCInstallation,
    args: FindNativeOptions,
    sdk: std.zig.WindowsSdk,
) FindError!void {
    const allocator = args.allocator;

    var install_buf: [2]std.zig.WindowsSdk.Installation = undefined;
    const installs = fillInstallations(&install_buf, sdk);

    var result_buf = std.ArrayList(u8).init(allocator);
    defer result_buf.deinit();

    const arch_sub_dir = switch (args.target.cpu.arch) {
        .x86 => "x86",
        .x86_64 => "x64",
        .arm, .armeb => "arm",
        .aarch64 => "arm64",
        else => return error.UnsupportedArchitecture,
    };

    for (installs) |install| {
        result_buf.shrinkAndFree(0);
        const stream = result_buf.writer();
        try stream.print("{s}\\Lib\\{s}\\um\\{s}", .{ install.path, install.version, arch_sub_dir });

        var dir = fs.cwd().openDir(result_buf.items, .{}) catch |err| switch (err) {
            error.FileNotFound,
            error.NotDir,
            error.NoDevice,
            => continue,

            else => return error.FileSystem,
        };
        defer dir.close();

        dir.accessZ("kernel32.lib", .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return error.FileSystem,
        };

        self.kernel32_lib_dir = try result_buf.toOwnedSlice();
        return;
    }
    return error.LibCKernel32LibNotFound;
}

fn findNativeMsvcIncludeDir(
    self: *LibCInstallation,
    args: FindNativeOptions,
    sdk: std.zig.WindowsSdk,
) FindError!void {
    const allocator = args.allocator;

    const msvc_lib_dir = sdk.msvc_lib_dir orelse return error.LibCStdLibHeaderNotFound;
    const up1 = fs.path.dirname(msvc_lib_dir) orelse return error.LibCStdLibHeaderNotFound;
    const up2 = fs.path.dirname(up1) orelse return error.LibCStdLibHeaderNotFound;

    const dir_path = try fs.path.join(allocator, &[_][]const u8{ up2, "include" });
    errdefer allocator.free(dir_path);

    var dir = fs.cwd().openDir(dir_path, .{}) catch |err| switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.NoDevice,
        => return error.LibCStdLibHeaderNotFound,

        else => return error.FileSystem,
    };
    defer dir.close();

    dir.accessZ("vcruntime.h", .{}) catch |err| switch (err) {
        error.FileNotFound => return error.LibCStdLibHeaderNotFound,
        else => return error.FileSystem,
    };

    self.sys_include_dir = dir_path;
}

fn findNativeMsvcLibDir(
    self: *LibCInstallation,
    args: FindNativeOptions,
    sdk: std.zig.WindowsSdk,
) FindError!void {
    const allocator = args.allocator;
    const msvc_lib_dir = sdk.msvc_lib_dir orelse return error.LibCRuntimeNotFound;
    self.msvc_lib_dir = try allocator.dupe(u8, msvc_lib_dir);
}

pub const CCPrintFileNameOptions = struct {
    allocator: Allocator,
    search_basename: []const u8,
    want_dirname: enum { full_path, only_dir },
    verbose: bool = false,
};

/// caller owns returned memory
fn ccPrintFileName(args: CCPrintFileNameOptions) ![:0]u8 {
    const allocator = args.allocator;

    // Detect infinite loops.
    var env_map = std.process.getEnvMap(allocator) catch |err| switch (err) {
        error.Unexpected => unreachable, // WASI-only
        else => |e| return e,
    };
    defer env_map.deinit();
    const skip_cc_env_var = if (env_map.get(inf_loop_env_key)) |phase| blk: {
        if (std.mem.eql(u8, phase, "1")) {
            try env_map.put(inf_loop_env_key, "2");
            break :blk true;
        } else {
            return error.ZigIsTheCCompiler;
        }
    } else blk: {
        try env_map.put(inf_loop_env_key, "1");
        break :blk false;
    };

    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();

    const arg1 = try std.fmt.allocPrint(allocator, "-print-file-name={s}", .{args.search_basename});
    defer allocator.free(arg1);

    try appendCcExe(&argv, skip_cc_env_var);
    try argv.append(arg1);

    const run_res = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
        .max_output_bytes = 1024 * 1024,
        .env_map = &env_map,
        // Some C compilers, such as Clang, are known to rely on argv[0] to find the path
        // to their own executable, without even bothering to resolve PATH. This results in the message:
        // error: unable to execute command: Executable "" doesn't exist!
        // So we use the expandArg0 variant of ChildProcess to give them a helping hand.
        .expand_arg0 = .expand,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.UnableToSpawnCCompiler,
    };
    defer {
        allocator.free(run_res.stdout);
        allocator.free(run_res.stderr);
    }
    switch (run_res.term) {
        .Exited => |code| if (code != 0) {
            printVerboseInvocation(argv.items, args.search_basename, args.verbose, run_res.stderr);
            return error.CCompilerExitCode;
        },
        else => {
            printVerboseInvocation(argv.items, args.search_basename, args.verbose, run_res.stderr);
            return error.CCompilerCrashed;
        },
    }

    var it = std.mem.tokenizeAny(u8, run_res.stdout, "\n\r");
    const line = it.next() orelse return error.LibCRuntimeNotFound;
    // When this command fails, it returns exit code 0 and duplicates the input file name.
    // So we detect failure by checking if the output matches exactly the input.
    if (std.mem.eql(u8, line, args.search_basename)) return error.LibCRuntimeNotFound;
    switch (args.want_dirname) {
        .full_path => return allocator.dupeZ(u8, line),
        .only_dir => {
            const dirname = fs.path.dirname(line) orelse return error.LibCRuntimeNotFound;
            return allocator.dupeZ(u8, dirname);
        },
    }
}

fn printVerboseInvocation(
    argv: []const []const u8,
    search_basename: ?[]const u8,
    verbose: bool,
    stderr: ?[]const u8,
) void {
    if (!verbose) return;

    if (search_basename) |s| {
        std.debug.print("Zig attempted to find the file '{s}' by executing this command:\n", .{s});
    } else {
        std.debug.print("Zig attempted to find the path to native system libc headers by executing this command:\n", .{});
    }
    for (argv, 0..) |arg, i| {
        if (i != 0) std.debug.print(" ", .{});
        std.debug.print("{s}", .{arg});
    }
    std.debug.print("\n", .{});
    if (stderr) |s| {
        std.debug.print("Output:\n==========\n{s}\n==========\n", .{s});
    }
}

fn fillInstallations(
    installs: *[2]std.zig.WindowsSdk.Installation,
    sdk: std.zig.WindowsSdk,
) []std.zig.WindowsSdk.Installation {
    var installs_len: usize = 0;
    if (sdk.windows10sdk) |windows10sdk| {
        installs[installs_len] = windows10sdk;
        installs_len += 1;
    }
    if (sdk.windows81sdk) |windows81sdk| {
        installs[installs_len] = windows81sdk;
        installs_len += 1;
    }
    return installs[0..installs_len];
}

const inf_loop_env_key = "ZIG_IS_DETECTING_LIBC_PATHS";

fn appendCcExe(args: *std.ArrayList([]const u8), skip_cc_env_var: bool) !void {
    const default_cc_exe = if (is_windows) "cc.exe" else "cc";
    try args.ensureUnusedCapacity(1);
    if (skip_cc_env_var) {
        args.appendAssumeCapacity(default_cc_exe);
        return;
    }
    const cc_env_var = std.zig.EnvVar.CC.getPosix() orelse {
        args.appendAssumeCapacity(default_cc_exe);
        return;
    };
    // Respect space-separated flags to the C compiler.
    var it = std.mem.tokenizeScalar(u8, cc_env_var, ' ');
    while (it.next()) |arg| {
        try args.append(arg);
    }
}

/// These are basenames. This data is produced with a pure function. See also
/// `CsuPaths`.
pub const CrtBasenames = struct {
    crt0: ?[]const u8 = null,
    crti: ?[]const u8 = null,
    crtbegin: ?[]const u8 = null,
    crtend: ?[]const u8 = null,
    crtn: ?[]const u8 = null,

    pub const GetArgs = struct {
        target: std.Target,
        link_libc: bool,
        output_mode: std.builtin.OutputMode,
        link_mode: std.builtin.LinkMode,
        pie: bool,
    };

    /// Determine file system path names of C runtime startup objects for supported
    /// link modes.
    pub fn get(args: GetArgs) CrtBasenames {
        // crt objects are only required for libc.
        if (!args.link_libc) return .{};

        // Flatten crt cases.
        const mode: enum {
            dynamic_lib,
            dynamic_exe,
            dynamic_pie,
            static_exe,
            static_pie,
        } = switch (args.output_mode) {
            .Obj => return .{},
            .Lib => switch (args.link_mode) {
                .dynamic => .dynamic_lib,
                .static => return .{},
            },
            .Exe => switch (args.link_mode) {
                .dynamic => if (args.pie) .dynamic_pie else .dynamic_exe,
                .static => if (args.pie) .static_pie else .static_exe,
            },
        };

        const target = args.target;

        if (target.abi.isAndroid()) return switch (mode) {
            .dynamic_lib => .{
                .crtbegin = "crtbegin_so.o",
                .crtend = "crtend_so.o",
            },
            .dynamic_exe, .dynamic_pie => .{
                .crtbegin = "crtbegin_dynamic.o",
                .crtend = "crtend_android.o",
            },
            .static_exe, .static_pie => .{
                .crtbegin = "crtbegin_static.o",
                .crtend = "crtend_android.o",
            },
        };

        return switch (target.os.tag) {
            .linux => switch (mode) {
                .dynamic_lib => .{
                    .crti = "crti.o",
                    .crtn = "crtn.o",
                },
                .dynamic_exe => .{
                    .crt0 = "crt1.o",
                    .crti = "crti.o",
                    .crtn = "crtn.o",
                },
                .dynamic_pie => .{
                    .crt0 = "Scrt1.o",
                    .crti = "crti.o",
                    .crtn = "crtn.o",
                },
                .static_exe => .{
                    .crt0 = "crt1.o",
                    .crti = "crti.o",
                    .crtn = "crtn.o",
                },
                .static_pie => .{
                    .crt0 = "rcrt1.o",
                    .crti = "crti.o",
                    .crtn = "crtn.o",
                },
            },
            .dragonfly => switch (mode) {
                .dynamic_lib => .{
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .dynamic_exe => .{
                    .crt0 = "crt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .dynamic_pie => .{
                    .crt0 = "Scrt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .static_exe => .{
                    .crt0 = "crt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .static_pie => .{
                    .crt0 = "Scrt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
            },
            .freebsd => switch (mode) {
                .dynamic_lib => .{
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .dynamic_exe => .{
                    .crt0 = "crt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .dynamic_pie => .{
                    .crt0 = "Scrt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .static_exe => .{
                    .crt0 = "crt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginT.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .static_pie => .{
                    .crt0 = "Scrt1.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
            },
            .netbsd => switch (mode) {
                .dynamic_lib => .{
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .dynamic_exe => .{
                    .crt0 = "crt0.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .dynamic_pie => .{
                    .crt0 = "crt0.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .static_exe => .{
                    .crt0 = "crt0.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginT.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .static_pie => .{
                    .crt0 = "crt0.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginT.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
            },
            .openbsd => switch (mode) {
                .dynamic_lib => .{
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                },
                .dynamic_exe, .dynamic_pie => .{
                    .crt0 = "crt0.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                },
                .static_exe, .static_pie => .{
                    .crt0 = "rcrt0.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                },
            },
            .haiku => switch (mode) {
                .dynamic_lib => .{
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .dynamic_exe => .{
                    .crt0 = "start_dyn.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .dynamic_pie => .{
                    .crt0 = "start_dyn.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
                .static_exe => .{
                    .crt0 = "start_dyn.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbegin.o",
                    .crtend = "crtend.o",
                    .crtn = "crtn.o",
                },
                .static_pie => .{
                    .crt0 = "start_dyn.o",
                    .crti = "crti.o",
                    .crtbegin = "crtbeginS.o",
                    .crtend = "crtendS.o",
                    .crtn = "crtn.o",
                },
            },
            .solaris, .illumos => switch (mode) {
                .dynamic_lib => .{
                    .crti = "crti.o",
                    .crtn = "crtn.o",
                },
                .dynamic_exe, .dynamic_pie => .{
                    .crt0 = "crt1.o",
                    .crti = "crti.o",
                    .crtn = "crtn.o",
                },
                .static_exe, .static_pie => .{},
            },
            else => .{},
        };
    }
};

pub const CrtPaths = struct {
    crt0: ?Path = null,
    crti: ?Path = null,
    crtbegin: ?Path = null,
    crtend: ?Path = null,
    crtn: ?Path = null,
};

pub fn resolveCrtPaths(
    lci: LibCInstallation,
    arena: Allocator,
    crt_basenames: CrtBasenames,
    target: std.Target,
) error{ OutOfMemory, LibCInstallationMissingCrtDir }!CrtPaths {
    const crt_dir_path: Path = .{
        .root_dir = std.Build.Cache.Directory.cwd(),
        .sub_path = lci.crt_dir orelse return error.LibCInstallationMissingCrtDir,
    };
    switch (target.os.tag) {
        .dragonfly => {
            const gccv: []const u8 = if (target.os.version_range.semver.isAtLeast(.{
                .major = 5,
                .minor = 4,
                .patch = 0,
            }) orelse true) "gcc80" else "gcc54";
            return .{
                .crt0 = if (crt_basenames.crt0) |basename| try crt_dir_path.join(arena, basename) else null,
                .crti = if (crt_basenames.crti) |basename| try crt_dir_path.join(arena, basename) else null,
                .crtbegin = if (crt_basenames.crtbegin) |basename| .{
                    .root_dir = crt_dir_path.root_dir,
                    .sub_path = try fs.path.join(arena, &.{ crt_dir_path.sub_path, gccv, basename }),
                } else null,
                .crtend = if (crt_basenames.crtend) |basename| .{
                    .root_dir = crt_dir_path.root_dir,
                    .sub_path = try fs.path.join(arena, &.{ crt_dir_path.sub_path, gccv, basename }),
                } else null,
                .crtn = if (crt_basenames.crtn) |basename| try crt_dir_path.join(arena, basename) else null,
            };
        },
        .haiku => {
            const gcc_dir_path: Path = .{
                .root_dir = std.Build.Cache.Directory.cwd(),
                .sub_path = lci.gcc_dir orelse return error.LibCInstallationMissingCrtDir,
            };
            return .{
                .crt0 = if (crt_basenames.crt0) |basename| try crt_dir_path.join(arena, basename) else null,
                .crti = if (crt_basenames.crti) |basename| try crt_dir_path.join(arena, basename) else null,
                .crtbegin = if (crt_basenames.crtbegin) |basename| try gcc_dir_path.join(arena, basename) else null,
                .crtend = if (crt_basenames.crtend) |basename| try gcc_dir_path.join(arena, basename) else null,
                .crtn = if (crt_basenames.crtn) |basename| try crt_dir_path.join(arena, basename) else null,
            };
        },
        else => {
            return .{
                .crt0 = if (crt_basenames.crt0) |basename| try crt_dir_path.join(arena, basename) else null,
                .crti = if (crt_basenames.crti) |basename| try crt_dir_path.join(arena, basename) else null,
                .crtbegin = if (crt_basenames.crtbegin) |basename| try crt_dir_path.join(arena, basename) else null,
                .crtend = if (crt_basenames.crtend) |basename| try crt_dir_path.join(arena, basename) else null,
                .crtn = if (crt_basenames.crtn) |basename| try crt_dir_path.join(arena, basename) else null,
            };
        },
    }
}

const LibCInstallation = @This();
const std = @import("std");
const builtin = @import("builtin");
const Target = std.Target;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const Path = std.Build.Cache.Path;

const is_darwin = builtin.target.os.tag.isDarwin();
const is_windows = builtin.target.os.tag == .windows;
const is_haiku = builtin.target.os.tag == .haiku;

const log = std.log.scoped(.libc_installation);
pub const BitcodeReader = @import("llvm/BitcodeReader.zig");
pub const bitcode_writer = @import("llvm/bitcode_writer.zig");
pub const Builder = @import("llvm/Builder.zig");
const std = @import("../../std.zig");

pub const AbbrevOp = union(enum) {
    literal: u32, // 0
    fixed: u16, // 1
    fixed_runtime: type, // 1
    vbr: u16, // 2
    char6: void, // 4
    blob: void, // 5
    array_fixed: u16, // 3, 1
    array_fixed_runtime: type, // 3, 1
    array_vbr: u16, // 3, 2
    array_char6: void, // 3, 4
};

pub const Error = error{OutOfMemory};

pub fn BitcodeWriter(comptime types: []const type) type {
    return struct {
        const BcWriter = @This();

        buffer: std.ArrayList(u32),
        bit_buffer: u32 = 0,
        bit_count: u5 = 0,

        widths: [types.len]u16,

        pub fn getTypeWidth(self: BcWriter, comptime Type: type) u16 {
            return self.widths[comptime std.mem.indexOfScalar(type, types, Type).?];
        }

        pub fn init(allocator: std.mem.Allocator, widths: [types.len]u16) BcWriter {
            return .{
                .buffer = std.ArrayList(u32).init(allocator),
                .widths = widths,
            };
        }

        pub fn deinit(self: BcWriter) void {
            self.buffer.deinit();
        }

        pub fn toOwnedSlice(self: *BcWriter) Error![]const u32 {
            std.debug.assert(self.bit_count == 0);
            return self.buffer.toOwnedSlice();
        }

        pub fn length(self: BcWriter) usize {
            std.debug.assert(self.bit_count == 0);
            return self.buffer.items.len;
        }

        pub fn writeBits(self: *BcWriter, value: anytype, bits: u16) Error!void {
            if (bits == 0) return;

            var in_buffer = bufValue(value, 32);
            var in_bits = bits;

            // Store input bits in buffer if they fit otherwise store as many as possible and flush
            if (self.bit_count > 0) {
                const bits_remaining = 31 - self.bit_count + 1;
                const n: u5 = @intCast(@min(bits_remaining, in_bits));
                const v = @as(u32, @truncate(in_buffer)) << self.bit_count;
                self.bit_buffer |= v;
                in_buffer >>= n;

                self.bit_count +%= n;
                in_bits -= n;

                if (self.bit_count != 0) return;
                try self.buffer.append(std.mem.nativeToLittle(u32, self.bit_buffer));
                self.bit_buffer = 0;
            }

            // Write 32-bit chunks of input bits
            while (in_bits >= 32) {
                try self.buffer.append(std.mem.nativeToLittle(u32, @truncate(in_buffer)));

                in_buffer >>= 31;
                in_buffer >>= 1;
                in_bits -= 32;
            }

            // Store remaining input bits in buffer
            if (in_bits > 0) {
                self.bit_count = @intCast(in_bits);
                self.bit_buffer = @truncate(in_buffer);
            }
        }

        pub fn writeVBR(self: *BcWriter, value: anytype, comptime vbr_bits: usize) Error!void {
            comptime {
                std.debug.assert(vbr_bits > 1);
                if (@bitSizeOf(@TypeOf(value)) > 64) @compileError("Unsupported VBR block type: " ++ @typeName(@TypeOf(value)));
            }

            var in_buffer = bufValue(value, vbr_bits);

            const continue_bit = @as(@TypeOf(in_buffer), 1) << @intCast(vbr_bits - 1);
            const mask = continue_bit - 1;

            // If input is larger than one VBR block can store
            // then store vbr_bits - 1 bits and a continue bit
            while (in_buffer > mask) {
                try self.writeBits(in_buffer & mask | continue_bit, vbr_bits);
                in_buffer >>= @intCast(vbr_bits - 1);
            }

            // Store remaining bits
            try self.writeBits(in_buffer, vbr_bits);
        }

        pub fn bitsVBR(_: *const BcWriter, value: anytype, comptime vbr_bits: usize) u16 {
            comptime {
                std.debug.assert(vbr_bits > 1);
                if (@bitSizeOf(@TypeOf(value)) > 64) @compileError("Unsupported VBR block type: " ++ @typeName(@TypeOf(value)));
            }

            var bits: u16 = 0;

            var in_buffer = bufValue(value, vbr_bits);

            const continue_bit = @as(@TypeOf(in_buffer), 1) << @intCast(vbr_bits - 1);
            const mask = continue_bit - 1;

            // If input is larger than one VBR block can store
            // then store vbr_bits - 1 bits and a continue bit
            while (in_buffer > mask) {
                bits += @intCast(vbr_bits);
                in_buffer >>= @intCast(vbr_bits - 1);
            }

            // Store remaining bits
            bits += @intCast(vbr_bits);
            return bits;
        }

        pub fn write6BitChar(self: *BcWriter, c: u8) Error!void {
            try self.writeBits(charTo6Bit(c), 6);
        }

        pub fn writeBlob(self: *BcWriter, blob: []const u8) Error!void {
            const blob_word_size = std.mem.alignForward(usize, blob.len, 4);
            try self.buffer.ensureUnusedCapacity(blob_word_size + 1);
            self.alignTo32() catch unreachable;

            const slice = self.buffer.addManyAsSliceAssumeCapacity(blob_word_size / 4);
            const slice_bytes = std.mem.sliceAsBytes(slice);
            @memcpy(slice_bytes[0..blob.len], blob);
            @memset(slice_bytes[blob.len..], 0);
        }

        pub fn alignTo32(self: *BcWriter) Error!void {
            if (self.bit_count == 0) return;

            try self.buffer.append(std.mem.nativeToLittle(u32, self.bit_buffer));
            self.bit_buffer = 0;
            self.bit_count = 0;
        }

        pub fn enterTopBlock(self: *BcWriter, comptime SubBlock: type) Error!BlockWriter(SubBlock) {
            return BlockWriter(SubBlock).init(self, 2, true);
        }

        fn BlockWriter(comptime Block: type) type {
            return struct {
                const Self = @This();

                // The minimum abbrev id length based on the number of abbrevs present in the block
                pub const abbrev_len = std.math.log2_int_ceil(
                    u6,
                    4 + (if (@hasDecl(Block, "abbrevs")) Block.abbrevs.len else 0),
                );

                start: usize,
                bitcode: *BcWriter,

                pub fn init(bitcode: *BcWriter, comptime parent_abbrev_len: u6, comptime define_abbrevs: bool) Error!Self {
                    try bitcode.writeBits(1, parent_abbrev_len);
                    try bitcode.writeVBR(Block.id, 8);
                    try bitcode.writeVBR(abbrev_len, 4);
                    try bitcode.alignTo32();

                    // We store the index of the block size and store a dummy value as the number of words in the block
                    const start = bitcode.length();
                    try bitcode.writeBits(0, 32);

                    var self = Self{
                        .start = start,
                        .bitcode = bitcode,
                    };

                    // Predefine all block abbrevs
                    if (define_abbrevs) {
                        inline for (Block.abbrevs) |Abbrev| {
                            try self.defineAbbrev(&Abbrev.ops);
                        }
                    }

                    return self;
                }

                pub fn enterSubBlock(self: Self, comptime SubBlock: type, comptime define_abbrevs: bool) Error!BlockWriter(SubBlock) {
                    return BlockWriter(SubBlock).init(self.bitcode, abbrev_len, define_abbrevs);
                }

                pub fn end(self: *Self) Error!void {
                    try self.bitcode.writeBits(0, abbrev_len);
                    try self.bitcode.alignTo32();

                    // Set the number of words in the block at the start of the block
                    self.bitcode.buffer.items[self.start] = std.mem.nativeToLittle(u32, @truncate(self.bitcode.length() - self.start - 1));
                }

                pub fn writeUnabbrev(self: *Self, code: u32, values: []const u64) Error!void {
                    try self.bitcode.writeBits(3, abbrev_len);
                    try self.bitcode.writeVBR(code, 6);
                    try self.bitcode.writeVBR(values.len, 6);
                    for (values) |val| {
                        try self.bitcode.writeVBR(val, 6);
                    }
                }

                pub fn writeAbbrev(self: *Self, params: anytype) Error!void {
                    return self.writeAbbrevAdapted(params, struct {
                        pub fn get(_: @This(), param: anytype, comptime _: []const u8) @TypeOf(param) {
                            return param;
                        }
                    }{});
                }

                pub fn abbrevId(comptime Abbrev: type) u32 {
                    inline for (Block.abbrevs, 0..) |abbrev, i| {
                        if (Abbrev == abbrev) return i + 4;
                    }

                    @compileError("Unknown abbrev: " ++ @typeName(Abbrev));
                }

                pub fn writeAbbrevAdapted(
                    self: *Self,
                    params: anytype,
                    adapter: anytype,
                ) Error!void {
                    const Abbrev = @TypeOf(params);

                    try self.bitcode.writeBits(comptime abbrevId(Abbrev), abbrev_len);

                    const fields = std.meta.fields(Abbrev);

                    // This abbreviation might only contain literals
                    if (fields.len == 0) return;

                    comptime var field_index: usize = 0;
                    inline for (Abbrev.ops) |ty| {
                        const field_name = fields[field_index].name;
                        const param = @field(params, field_name);

                        switch (ty) {
                            .literal => continue,
                            .fixed => |len| try self.bitcode.writeBits(adapter.get(param, field_name), len),
                            .fixed_runtime => |width_ty| try self.bitcode.writeBits(
                                adapter.get(param, field_name),
                                self.bitcode.getTypeWidth(width_ty),
                            ),
                            .vbr => |len| try self.bitcode.writeVBR(adapter.get(param, field_name), len),
                            .char6 => try self.bitcode.write6BitChar(adapter.get(param, field_name)),
                            .blob => {
                                try self.bitcode.writeVBR(param.len, 6);
                                try self.bitcode.writeBlob(param);
                            },
                            .array_fixed => |len| {
                                try self.bitcode.writeVBR(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.writeBits(adapter.get(x, field_name), len);
                                }
                            },
                            .array_fixed_runtime => |width_ty| {
                                try self.bitcode.writeVBR(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.writeBits(
                                        adapter.get(x, field_name),
                                        self.bitcode.getTypeWidth(width_ty),
                                    );
                                }
                            },
                            .array_vbr => |len| {
                                try self.bitcode.writeVBR(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.writeVBR(adapter.get(x, field_name), len);
                                }
                            },
                            .array_char6 => {
                                try self.bitcode.writeVBR(param.len, 6);
                                for (param) |x| {
                                    try self.bitcode.write6BitChar(adapter.get(x, field_name));
                                }
                            },
                        }
                        field_index += 1;
                        if (field_index == fields.len) break;
                    }
                }

                pub fn defineAbbrev(self: *Self, comptime ops: []const AbbrevOp) Error!void {
                    const bitcode = self.bitcode;
                    try bitcode.writeBits(2, abbrev_len);

                    // ops.len is not accurate because arrays are actually two ops
                    try bitcode.writeVBR(blk: {
                        var count: usize = 0;
                        inline for (ops) |op| {
                            count += switch (op) {
                                .literal, .fixed, .fixed_runtime, .vbr, .char6, .blob => 1,
                                .array_fixed, .array_fixed_runtime, .array_vbr, .array_char6 => 2,
                            };
                        }
                        break :blk count;
                    }, 5);

                    inline for (ops) |op| {
                        switch (op) {
                            .literal => |value| {
                                try bitcode.writeBits(1, 1);
                                try bitcode.writeVBR(value, 8);
                            },
                            .fixed => |width| {
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(1, 3);
                                try bitcode.writeVBR(width, 5);
                            },
                            .fixed_runtime => |width_ty| {
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(1, 3);
                                try bitcode.writeVBR(bitcode.getTypeWidth(width_ty), 5);
                            },
                            .vbr => |width| {
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(2, 3);
                                try bitcode.writeVBR(width, 5);
                            },
                            .char6 => {
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(4, 3);
                            },
                            .blob => {
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(5, 3);
                            },
                            .array_fixed => |width| {
                                // Array op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(3, 3);

                                // Fixed or VBR op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(1, 3);
                                try bitcode.writeVBR(width, 5);
                            },
                            .array_fixed_runtime => |width_ty| {
                                // Array op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(3, 3);

                                // Fixed or VBR op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(1, 3);
                                try bitcode.writeVBR(bitcode.getTypeWidth(width_ty), 5);
                            },
                            .array_vbr => |width| {
                                // Array op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(3, 3);

                                // Fixed or VBR op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(2, 3);
                                try bitcode.writeVBR(width, 5);
                            },
                            .array_char6 => {
                                // Array op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(3, 3);

                                // Char6 op
                                try bitcode.writeBits(0, 1);
                                try bitcode.writeBits(4, 3);
                            },
                        }
                    }
                }
            };
        }
    };
}

fn charTo6Bit(c: u8) u8 {
    return switch (c) {
        'a'...'z' => c - 'a',
        'A'...'Z' => c - 'A' + 26,
        '0'...'9' => c - '0' + 52,
        '.' => 62,
        '_' => 63,
        else => @panic("Failed to encode byte as 6-bit char"),
    };
}

fn BufType(comptime T: type, comptime min_len: usize) type {
    return std.meta.Int(.unsigned, @max(min_len, @bitSizeOf(switch (@typeInfo(T)) {
        .comptime_int => u32,
        .int => |info| if (info.signedness == .unsigned)
            T
        else
            @compileError("Unsupported type: " ++ @typeName(T)),
        .@"enum" => |info| info.tag_type,
        .bool => u1,
        .@"struct" => |info| switch (info.layout) {
            .auto, .@"extern" => @compileError("Unsupported type: " ++ @typeName(T)),
            .@"packed" => std.meta.Int(.unsigned, @bitSizeOf(T)),
        },
        else => @compileError("Unsupported type: " ++ @typeName(T)),
    })));
}

fn bufValue(value: anytype, comptime min_len: usize) BufType(@TypeOf(value), min_len) {
    return switch (@typeInfo(@TypeOf(value))) {
        .comptime_int, .int => @intCast(value),
        .@"enum" => @intFromEnum(value),
        .bool => @intFromBool(value),
        .@"struct" => @intCast(@as(std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(value))), @bitCast(value))),
        else => unreachable,
    };
}
allocator: std.mem.Allocator,
record_arena: std.heap.ArenaAllocator.State,
reader: std.io.AnyReader,
keep_names: bool,
bit_buffer: u32,
bit_offset: u5,
stack: std.ArrayListUnmanaged(State),
block_info: std.AutoHashMapUnmanaged(u32, Block.Info),

pub const Item = union(enum) {
    start_block: Block,
    record: Record,
    end_block: Block,
};

pub const Block = struct {
    name: []const u8,
    id: u32,
    len: u32,

    const block_info: u32 = 0;
    const first_reserved: u32 = 1;
    const last_standard: u32 = 7;

    const Info = struct {
        block_name: []const u8,
        record_names: std.AutoHashMapUnmanaged(u32, []const u8),
        abbrevs: Abbrev.Store,

        const default: Info = .{
            .block_name = &.{},
            .record_names = .{},
            .abbrevs = .{ .abbrevs = .{} },
        };

        const set_bid_id: u32 = 1;
        const block_name_id: u32 = 2;
        const set_record_name_id: u32 = 3;

        fn deinit(info: *Info, allocator: std.mem.Allocator) void {
            allocator.free(info.block_name);
            var record_names_it = info.record_names.valueIterator();
            while (record_names_it.next()) |record_name| allocator.free(record_name.*);
            info.record_names.deinit(allocator);
            info.abbrevs.deinit(allocator);
            info.* = undefined;
        }
    };
};

pub const Record = struct {
    name: []const u8,
    id: u32,
    operands: []const u64,
    blob: []const u8,

    fn toOwnedAbbrev(record: Record, allocator: std.mem.Allocator) !Abbrev {
        var operands = std.ArrayList(Abbrev.Operand).init(allocator);
        defer operands.deinit();

        assert(record.id == Abbrev.Builtin.define_abbrev.toRecordId());
        var i: usize = 0;
        while (i < record.operands.len) switch (record.operands[i]) {
            Abbrev.Operand.literal_id => {
                try operands.append(.{ .literal = record.operands[i + 1] });
                i += 2;
            },
            @intFromEnum(Abbrev.Operand.Encoding.fixed) => {
                try operands.append(.{ .encoding = .{ .fixed = @intCast(record.operands[i + 1]) } });
                i += 2;
            },
            @intFromEnum(Abbrev.Operand.Encoding.vbr) => {
                try operands.append(.{ .encoding = .{ .vbr = @intCast(record.operands[i + 1]) } });
                i += 2;
            },
            @intFromEnum(Abbrev.Operand.Encoding.array) => {
                try operands.append(.{ .encoding = .{ .array = 6 } });
                i += 1;
            },
            @intFromEnum(Abbrev.Operand.Encoding.char6) => {
                try operands.append(.{ .encoding = .char6 });
                i += 1;
            },
            @intFromEnum(Abbrev.Operand.Encoding.blob) => {
                try operands.append(.{ .encoding = .{ .blob = 6 } });
                i += 1;
            },
            else => unreachable,
        };

        return .{ .operands = try operands.toOwnedSlice() };
    }
};

pub const InitOptions = struct {
    reader: std.io.AnyReader,
    keep_names: bool = false,
};
pub fn init(allocator: std.mem.Allocator, options: InitOptions) BitcodeReader {
    return .{
        .allocator = allocator,
        .record_arena = .{},
        .reader = options.reader,
        .keep_names = options.keep_names,
        .bit_buffer = 0,
        .bit_offset = 0,
        .stack = .{},
        .block_info = .{},
    };
}

pub fn deinit(bc: *BitcodeReader) void {
    var block_info_it = bc.block_info.valueIterator();
    while (block_info_it.next()) |block_info| block_info.deinit(bc.allocator);
    bc.block_info.deinit(bc.allocator);
    for (bc.stack.items) |*state| state.deinit(bc.allocator);
    bc.stack.deinit(bc.allocator);
    bc.record_arena.promote(bc.allocator).deinit();
    bc.* = undefined;
}

pub fn checkMagic(bc: *BitcodeReader, magic: *const [4]u8) !void {
    var buffer: [4]u8 = undefined;
    try bc.readBytes(&buffer);
    if (!std.mem.eql(u8, &buffer, magic)) return error.InvalidMagic;

    try bc.startBlock(null, 2);
    try bc.block_info.put(bc.allocator, Block.block_info, Block.Info.default);
}

pub fn next(bc: *BitcodeReader) !?Item {
    while (true) {
        const record = (try bc.nextRecord()) orelse
            return if (bc.stack.items.len > 1) error.EndOfStream else null;
        switch (record.id) {
            else => return .{ .record = record },
            Abbrev.Builtin.end_block.toRecordId() => {
                const block_id = bc.stack.items[bc.stack.items.len - 1].block_id.?;
                try bc.endBlock();
                return .{ .end_block = .{
                    .name = if (bc.block_info.get(block_id)) |block_info|
                        block_info.block_name
                    else
                        &.{},
                    .id = block_id,
                    .len = 0,
                } };
            },
            Abbrev.Builtin.enter_subblock.toRecordId() => {
                const block_id: u32 = @intCast(record.operands[0]);
                switch (block_id) {
                    Block.block_info => try bc.parseBlockInfoBlock(),
                    Block.first_reserved...Block.last_standard => return error.UnsupportedBlockId,
                    else => {
                        try bc.startBlock(block_id, @intCast(record.operands[1]));
                        return .{ .start_block = .{
                            .name = if (bc.block_info.get(block_id)) |block_info|
                                block_info.block_name
                            else
                                &.{},
                            .id = block_id,
                            .len = @intCast(record.operands[2]),
                        } };
                    },
                }
            },
            Abbrev.Builtin.define_abbrev.toRecordId() => try bc.stack.items[bc.stack.items.len - 1]
                .abbrevs.addOwnedAbbrev(bc.allocator, try record.toOwnedAbbrev(bc.allocator)),
        }
    }
}

pub fn skipBlock(bc: *BitcodeReader, block: Block) !void {
    assert(bc.bit_offset == 0);
    try bc.reader.skipBytes(@as(u34, block.len) * 4, .{});
    try bc.endBlock();
}

fn nextRecord(bc: *BitcodeReader) !?Record {
    const state = &bc.stack.items[bc.stack.items.len - 1];
    const abbrev_id = bc.readFixed(u32, state.abbrev_id_width) catch |err| switch (err) {
        error.EndOfStream => return null,
        else => |e| return e,
    };
    if (abbrev_id >= state.abbrevs.abbrevs.items.len) return error.InvalidAbbrevId;
    const abbrev = state.abbrevs.abbrevs.items[abbrev_id];

    var record_arena = bc.record_arena.promote(bc.allocator);
    defer bc.record_arena = record_arena.state;
    _ = record_arena.reset(.retain_capacity);

    var operands = try std.ArrayList(u64).initCapacity(record_arena.allocator(), abbrev.operands.len);
    var blob = std.ArrayList(u8).init(record_arena.allocator());
    for (abbrev.operands, 0..) |abbrev_operand, abbrev_operand_i| switch (abbrev_operand) {
        .literal => |value| operands.appendAssumeCapacity(value),
        .encoding => |abbrev_encoding| switch (abbrev_encoding) {
            .fixed => |width| operands.appendAssumeCapacity(try bc.readFixed(u64, width)),
            .vbr => |width| operands.appendAssumeCapacity(try bc.readVbr(u64, width)),
            .array => |len_width| {
                assert(abbrev_operand_i + 2 == abbrev.operands.len);
                const len: usize = @intCast(try bc.readVbr(u32, len_width));
                try operands.ensureUnusedCapacity(len);
                for (0..len) |_| switch (abbrev.operands[abbrev.operands.len - 1]) {
                    .literal => |elem_value| operands.appendAssumeCapacity(elem_value),
                    .encoding => |elem_encoding| switch (elem_encoding) {
                        .fixed => |elem_width| operands.appendAssumeCapacity(try bc.readFixed(u64, elem_width)),
                        .vbr => |elem_width| operands.appendAssumeCapacity(try bc.readVbr(u64, elem_width)),
                        .array, .blob => return error.InvalidArrayElement,
                        .char6 => operands.appendAssumeCapacity(try bc.readChar6()),
                    },
                    .align_32_bits, .block_len => return error.UnsupportedArrayElement,
                    .abbrev_op => switch (try bc.readFixed(u1, 1)) {
                        1 => try operands.appendSlice(&.{
                            Abbrev.Operand.literal_id,
                            try bc.readVbr(u64, 8),
                        }),
                        0 => {
                            const encoding: Abbrev.Operand.Encoding =
                                @enumFromInt(try bc.readFixed(u3, 3));
                            try operands.append(@intFromEnum(encoding));
                            switch (encoding) {
                                .fixed, .vbr => try operands.append(try bc.readVbr(u7, 5)),
                                .array, .char6, .blob => {},
                                _ => return error.UnsuportedAbbrevEncoding,
                            }
                        },
                    },
                };
                break;
            },
            .char6 => operands.appendAssumeCapacity(try bc.readChar6()),
            .blob => |len_width| {
                assert(abbrev_operand_i + 1 == abbrev.operands.len);
                const len = std.math.cast(usize, try bc.readVbr(u32, len_width)) orelse
                    return error.Overflow;
                bc.align32Bits();
                try bc.readBytes(try blob.addManyAsSlice(len));
                bc.align32Bits();
            },
        },
        .align_32_bits => bc.align32Bits(),
        .block_len => operands.appendAssumeCapacity(try bc.read32Bits()),
        .abbrev_op => unreachable,
    };
    return .{
        .name = name: {
            if (operands.items.len < 1) break :name &.{};
            const record_id = std.math.cast(u32, operands.items[0]) orelse break :name &.{};
            if (state.block_id) |block_id| {
                if (bc.block_info.get(block_id)) |block_info| {
                    break :name block_info.record_names.get(record_id) orelse break :name &.{};
                }
            }
            break :name &.{};
        },
        .id = std.math.cast(u32, operands.items[0]) orelse return error.InvalidRecordId,
        .operands = operands.items[1..],
        .blob = blob.items,
    };
}

fn startBlock(bc: *BitcodeReader, block_id: ?u32, new_abbrev_len: u6) !void {
    const abbrevs = if (block_id) |id|
        if (bc.block_info.get(id)) |block_info| block_info.abbrevs.abbrevs.items else &.{}
    else
        &.{};

    const state = try bc.stack.addOne(bc.allocator);
    state.* = .{
        .block_id = block_id,
        .abbrev_id_width = new_abbrev_len,
        .abbrevs = .{ .abbrevs = .{} },
    };
    try state.abbrevs.abbrevs.ensureTotalCapacity(
        bc.allocator,
        @typeInfo(Abbrev.Builtin).@"enum".fields.len + abbrevs.len,
    );

    assert(state.abbrevs.abbrevs.items.len == @intFromEnum(Abbrev.Builtin.end_block));
    try state.abbrevs.addAbbrevAssumeCapacity(bc.allocator, .{
        .operands = &.{
            .{ .literal = Abbrev.Builtin.end_block.toRecordId() },
            .align_32_bits,
        },
    });
    assert(state.abbrevs.abbrevs.items.len == @intFromEnum(Abbrev.Builtin.enter_subblock));
    try state.abbrevs.addAbbrevAssumeCapacity(bc.allocator, .{
        .operands = &.{
            .{ .literal = Abbrev.Builtin.enter_subblock.toRecordId() },
            .{ .encoding = .{ .vbr = 8 } }, // blockid
            .{ .encoding = .{ .vbr = 4 } }, // newabbrevlen
            .align_32_bits,
            .block_len,
        },
    });
    assert(state.abbrevs.abbrevs.items.len == @intFromEnum(Abbrev.Builtin.define_abbrev));
    try state.abbrevs.addAbbrevAssumeCapacity(bc.allocator, .{
        .operands = &.{
            .{ .literal = Abbrev.Builtin.define_abbrev.toRecordId() },
            .{ .encoding = .{ .array = 5 } }, // numabbrevops
            .abbrev_op,
        },
    });
    assert(state.abbrevs.abbrevs.items.len == @intFromEnum(Abbrev.Builtin.unabbrev_record));
    try state.abbrevs.addAbbrevAssumeCapacity(bc.allocator, .{
        .operands = &.{
            .{ .encoding = .{ .vbr = 6 } }, // code
            .{ .encoding = .{ .array = 6 } }, // numops
            .{ .encoding = .{ .vbr = 6 } }, // ops
        },
    });
    assert(state.abbrevs.abbrevs.items.len == @typeInfo(Abbrev.Builtin).@"enum".fields.len);
    for (abbrevs) |abbrev| try state.abbrevs.addAbbrevAssumeCapacity(bc.allocator, abbrev);
}

fn endBlock(bc: *BitcodeReader) !void {
    if (bc.stack.items.len == 0) return error.InvalidEndBlock;
    bc.stack.items[bc.stack.items.len - 1].deinit(bc.allocator);
    bc.stack.items.len -= 1;
}

fn parseBlockInfoBlock(bc: *BitcodeReader) !void {
    var block_id: ?u32 = null;
    while (true) {
        const record = (try bc.nextRecord()) orelse return error.EndOfStream;
        switch (record.id) {
            Abbrev.Builtin.end_block.toRecordId() => break,
            Abbrev.Builtin.define_abbrev.toRecordId() => {
                const gop = try bc.block_info.getOrPut(bc.allocator, block_id orelse
                    return error.UnspecifiedBlockId);
                if (!gop.found_existing) gop.value_ptr.* = Block.Info.default;
                try gop.value_ptr.abbrevs.addOwnedAbbrev(
                    bc.allocator,
                    try record.toOwnedAbbrev(bc.allocator),
                );
            },
            Block.Info.set_bid_id => block_id = std.math.cast(u32, record.operands[0]) orelse
                return error.Overflow,
            Block.Info.block_name_id => if (bc.keep_names) {
                const gop = try bc.block_info.getOrPut(bc.allocator, block_id orelse
                    return error.UnspecifiedBlockId);
                if (!gop.found_existing) gop.value_ptr.* = Block.Info.default;
                const name = try bc.allocator.alloc(u8, record.operands.len);
                errdefer bc.allocator.free(name);
                for (name, record.operands) |*byte, operand|
                    byte.* = std.math.cast(u8, operand) orelse return error.InvalidName;
                gop.value_ptr.block_name = name;
            },
            Block.Info.set_record_name_id => if (bc.keep_names) {
                const gop = try bc.block_info.getOrPut(bc.allocator, block_id orelse
                    return error.UnspecifiedBlockId);
                if (!gop.found_existing) gop.value_ptr.* = Block.Info.default;
                const name = try bc.allocator.alloc(u8, record.operands.len - 1);
                errdefer bc.allocator.free(name);
                for (name, record.operands[1..]) |*byte, operand|
                    byte.* = std.math.cast(u8, operand) orelse return error.InvalidName;
                try gop.value_ptr.record_names.put(
                    bc.allocator,
                    std.math.cast(u32, record.operands[0]) orelse return error.Overflow,
                    name,
                );
            },
            else => return error.UnsupportedBlockInfoRecord,
        }
    }
}

fn align32Bits(bc: *BitcodeReader) void {
    bc.bit_offset = 0;
}

fn read32Bits(bc: *BitcodeReader) !u32 {
    assert(bc.bit_offset == 0);
    return bc.reader.readInt(u32, .little);
}

fn readBytes(bc: *BitcodeReader, bytes: []u8) !void {
    assert(bc.bit_offset == 0);
    try bc.reader.readNoEof(bytes);

    const trailing_bytes = bytes.len % 4;
    if (trailing_bytes > 0) {
        var bit_buffer = [1]u8{0} ** 4;
        try bc.reader.readNoEof(bit_buffer[trailing_bytes..]);
        bc.bit_buffer = std.mem.readInt(u32, &bit_buffer, .little);
        bc.bit_offset = @intCast(trailing_bytes * 8);
    }
}

fn readFixed(bc: *BitcodeReader, comptime T: type, bits: u7) !T {
    var result: T = 0;
    var shift: std.math.Log2IntCeil(T) = 0;
    var remaining = bits;
    while (remaining > 0) {
        if (bc.bit_offset == 0) bc.bit_buffer = try bc.read32Bits();
        const chunk_len = @min(@as(u6, 32) - bc.bit_offset, remaining);
        const chunk_mask = @as(u32, std.math.maxInt(u32)) >> @intCast(32 - chunk_len);
        result |= @as(T, @intCast(bc.bit_buffer >> bc.bit_offset & chunk_mask)) << @intCast(shift);
        shift += @intCast(chunk_len);
        remaining -= chunk_len;
        bc.bit_offset = @truncate(bc.bit_offset + chunk_len);
    }
    return result;
}

fn readVbr(bc: *BitcodeReader, comptime T: type, bits: u7) !T {
    const chunk_bits: u6 = @intCast(bits - 1);
    const chunk_msb = @as(u64, 1) << chunk_bits;

    var result: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        const chunk = try bc.readFixed(u64, bits);
        result |= (chunk & (chunk_msb - 1)) << shift;
        if (chunk & chunk_msb == 0) break;
        shift += chunk_bits;
    }
    return @intCast(result);
}

fn readChar6(bc: *BitcodeReader) !u8 {
    return switch (try bc.readFixed(u6, 6)) {
        0...25 => |c| @as(u8, c - 0) + 'a',
        26...51 => |c| @as(u8, c - 26) + 'A',
        52...61 => |c| @as(u8, c - 52) + '0',
        62 => '.',
        63 => '_',
    };
}

const State = struct {
    block_id: ?u32,
    abbrev_id_width: u6,
    abbrevs: Abbrev.Store,

    fn deinit(state: *State, allocator: std.mem.Allocator) void {
        state.abbrevs.deinit(allocator);
        state.* = undefined;
    }
};

const Abbrev = struct {
    operands: []const Operand,

    const Builtin = enum(u2) {
        end_block,
        enter_subblock,
        define_abbrev,
        unabbrev_record,

        const first_record_id: u32 = std.math.maxInt(u32) - @typeInfo(Builtin).@"enum".fields.len + 1;
        fn toRecordId(builtin: Builtin) u32 {
            return first_record_id + @intFromEnum(builtin);
        }
    };

    const Operand = union(enum) {
        literal: u64,
        encoding: union(Encoding) {
            fixed: u7,
            vbr: u6,
            array: u3,
            char6,
            blob: u3,
        },
        align_32_bits,
        block_len,
        abbrev_op,

        const literal_id = std.math.maxInt(u64);
        const Encoding = enum(u3) {
            fixed = 1,
            vbr = 2,
            array = 3,
            char6 = 4,
            blob = 5,
            _,
        };
    };

    const Store = struct {
        abbrevs: std.ArrayListUnmanaged(Abbrev),

        fn deinit(store: *Store, allocator: std.mem.Allocator) void {
            for (store.abbrevs.items) |abbrev| allocator.free(abbrev.operands);
            store.abbrevs.deinit(allocator);
            store.* = undefined;
        }

        fn addAbbrev(store: *Store, allocator: std.mem.Allocator, abbrev: Abbrev) !void {
            try store.ensureUnusedCapacity(allocator, 1);
            store.addAbbrevAssumeCapacity(abbrev);
        }

        fn addAbbrevAssumeCapacity(store: *Store, allocator: std.mem.Allocator, abbrev: Abbrev) !void {
            store.abbrevs.appendAssumeCapacity(.{
                .operands = try allocator.dupe(Abbrev.Operand, abbrev.operands),
            });
        }

        fn addOwnedAbbrev(store: *Store, allocator: std.mem.Allocator, abbrev: Abbrev) !void {
            try store.abbrevs.ensureUnusedCapacity(allocator, 1);
            store.addOwnedAbbrevAssumeCapacity(abbrev);
        }

        fn addOwnedAbbrevAssumeCapacity(store: *Store, abbrev: Abbrev) void {
            store.abbrevs.appendAssumeCapacity(abbrev);
        }
    };
};

const assert = std.debug.assert;
const std = @import("../../std.zig");

const BitcodeReader = @This();
gpa: Allocator,
strip: bool,

source_filename: String,
data_layout: String,
target_triple: String,
module_asm: std.ArrayListUnmanaged(u8),

string_map: std.AutoArrayHashMapUnmanaged(void, void),
string_indices: std.ArrayListUnmanaged(u32),
string_bytes: std.ArrayListUnmanaged(u8),

types: std.AutoArrayHashMapUnmanaged(String, Type),
next_unnamed_type: String,
next_unique_type_id: std.AutoHashMapUnmanaged(String, u32),
type_map: std.AutoArrayHashMapUnmanaged(void, void),
type_items: std.ArrayListUnmanaged(Type.Item),
type_extra: std.ArrayListUnmanaged(u32),

attributes: std.AutoArrayHashMapUnmanaged(Attribute.Storage, void),
attributes_map: std.AutoArrayHashMapUnmanaged(void, void),
attributes_indices: std.ArrayListUnmanaged(u32),
attributes_extra: std.ArrayListUnmanaged(u32),

function_attributes_set: std.AutoArrayHashMapUnmanaged(FunctionAttributes, void),

globals: std.AutoArrayHashMapUnmanaged(StrtabString, Global),
next_unnamed_global: StrtabString,
next_replaced_global: StrtabString,
next_unique_global_id: std.AutoHashMapUnmanaged(StrtabString, u32),
aliases: std.ArrayListUnmanaged(Alias),
variables: std.ArrayListUnmanaged(Variable),
functions: std.ArrayListUnmanaged(Function),

strtab_string_map: std.AutoArrayHashMapUnmanaged(void, void),
strtab_string_indices: std.ArrayListUnmanaged(u32),
strtab_string_bytes: std.ArrayListUnmanaged(u8),

constant_map: std.AutoArrayHashMapUnmanaged(void, void),
constant_items: std.MultiArrayList(Constant.Item),
constant_extra: std.ArrayListUnmanaged(u32),
constant_limbs: std.ArrayListUnmanaged(std.math.big.Limb),

metadata_map: std.AutoArrayHashMapUnmanaged(void, void),
metadata_items: std.MultiArrayList(Metadata.Item),
metadata_extra: std.ArrayListUnmanaged(u32),
metadata_limbs: std.ArrayListUnmanaged(std.math.big.Limb),
metadata_forward_references: std.ArrayListUnmanaged(Metadata),
metadata_named: std.AutoArrayHashMapUnmanaged(MetadataString, struct {
    len: u32,
    index: Metadata.Item.ExtraIndex,
}),

metadata_string_map: std.AutoArrayHashMapUnmanaged(void, void),
metadata_string_indices: std.ArrayListUnmanaged(u32),
metadata_string_bytes: std.ArrayListUnmanaged(u8),

pub const expected_args_len = 16;
pub const expected_attrs_len = 16;
pub const expected_fields_len = 32;
pub const expected_gep_indices_len = 8;
pub const expected_cases_len = 8;
pub const expected_incoming_len = 8;

pub const Options = struct {
    allocator: Allocator,
    strip: bool = true,
    name: []const u8 = &.{},
    target: std.Target = builtin.target,
    triple: []const u8 = &.{},
};

pub const String = enum(u32) {
    none = std.math.maxInt(u31),
    empty,
    _,

    pub fn isAnon(self: String) bool {
        assert(self != .none);
        return self.toIndex() == null;
    }

    pub fn slice(self: String, builder: *const Builder) ?[]const u8 {
        const index = self.toIndex() orelse return null;
        const start = builder.string_indices.items[index];
        const end = builder.string_indices.items[index + 1];
        return builder.string_bytes.items[start..end];
    }

    const FormatData = struct {
        string: String,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (comptime std.mem.indexOfNone(u8, fmt_str, "\"r")) |_|
            @compileError("invalid format string: '" ++ fmt_str ++ "'");
        assert(data.string != .none);
        const string_slice = data.string.slice(data.builder) orelse
            return writer.print("{d}", .{@intFromEnum(data.string)});
        if (comptime std.mem.indexOfScalar(u8, fmt_str, 'r')) |_|
            return writer.writeAll(string_slice);
        try printEscapedString(
            string_slice,
            if (comptime std.mem.indexOfScalar(u8, fmt_str, '"')) |_|
                .always_quote
            else
                .quote_unless_valid_identifier,
            writer,
        );
    }
    pub fn fmt(self: String, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .string = self, .builder = builder } };
    }

    fn fromIndex(index: ?usize) String {
        return @enumFromInt(@as(u32, @intCast((index orelse return .none) +
            @intFromEnum(String.empty))));
    }

    fn toIndex(self: String) ?usize {
        return std.math.sub(u32, @intFromEnum(self), @intFromEnum(String.empty)) catch null;
    }

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: Adapter, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
        pub fn eql(ctx: Adapter, lhs_key: []const u8, _: void, rhs_index: usize) bool {
            return std.mem.eql(u8, lhs_key, String.fromIndex(rhs_index).slice(ctx.builder).?);
        }
    };
};

pub const BinaryOpcode = enum(u4) {
    add = 0,
    sub = 1,
    mul = 2,
    udiv = 3,
    sdiv = 4,
    urem = 5,
    srem = 6,
    shl = 7,
    lshr = 8,
    ashr = 9,
    @"and" = 10,
    @"or" = 11,
    xor = 12,
};

pub const CastOpcode = enum(u4) {
    trunc = 0,
    zext = 1,
    sext = 2,
    fptoui = 3,
    fptosi = 4,
    uitofp = 5,
    sitofp = 6,
    fptrunc = 7,
    fpext = 8,
    ptrtoint = 9,
    inttoptr = 10,
    bitcast = 11,
    addrspacecast = 12,
};

pub const CmpPredicate = enum(u6) {
    fcmp_false = 0,
    fcmp_oeq = 1,
    fcmp_ogt = 2,
    fcmp_oge = 3,
    fcmp_olt = 4,
    fcmp_ole = 5,
    fcmp_one = 6,
    fcmp_ord = 7,
    fcmp_uno = 8,
    fcmp_ueq = 9,
    fcmp_ugt = 10,
    fcmp_uge = 11,
    fcmp_ult = 12,
    fcmp_ule = 13,
    fcmp_une = 14,
    fcmp_true = 15,
    icmp_eq = 32,
    icmp_ne = 33,
    icmp_ugt = 34,
    icmp_uge = 35,
    icmp_ult = 36,
    icmp_ule = 37,
    icmp_sgt = 38,
    icmp_sge = 39,
    icmp_slt = 40,
    icmp_sle = 41,
};

pub const Type = enum(u32) {
    void,
    half,
    bfloat,
    float,
    double,
    fp128,
    x86_fp80,
    ppc_fp128,
    x86_amx,
    x86_mmx,
    label,
    token,
    metadata,

    i1,
    i8,
    i16,
    i29,
    i32,
    i64,
    i80,
    i128,
    ptr,
    @"ptr addrspace(4)",

    none = std.math.maxInt(u32),
    _,

    pub const ptr_amdgpu_constant =
        @field(Type, std.fmt.comptimePrint("ptr{ }", .{AddrSpace.amdgpu.constant}));

    pub const Tag = enum(u4) {
        simple,
        function,
        vararg_function,
        integer,
        pointer,
        target,
        vector,
        scalable_vector,
        small_array,
        array,
        structure,
        packed_structure,
        named_structure,
    };

    pub const Simple = enum(u5) {
        void = 2,
        half = 10,
        bfloat = 23,
        float = 3,
        double = 4,
        fp128 = 14,
        x86_fp80 = 13,
        ppc_fp128 = 15,
        x86_amx = 24,
        x86_mmx = 17,
        label = 5,
        token = 22,
        metadata = 16,
    };

    pub const Function = struct {
        ret: Type,
        params_len: u32,
        //params: [params_len]Value,

        pub const Kind = enum { normal, vararg };
    };

    pub const Target = extern struct {
        name: String,
        types_len: u32,
        ints_len: u32,
        //types: [types_len]Type,
        //ints: [ints_len]u32,
    };

    pub const Vector = extern struct {
        len: u32,
        child: Type,

        fn length(self: Vector) u32 {
            return self.len;
        }

        pub const Kind = enum { normal, scalable };
    };

    pub const Array = extern struct {
        len_lo: u32,
        len_hi: u32,
        child: Type,

        fn length(self: Array) u64 {
            return @as(u64, self.len_hi) << 32 | self.len_lo;
        }
    };

    pub const Structure = struct {
        fields_len: u32,
        //fields: [fields_len]Type,

        pub const Kind = enum { normal, @"packed" };
    };

    pub const NamedStructure = struct {
        id: String,
        body: Type,
    };

    pub const Item = packed struct(u32) {
        tag: Tag,
        data: ExtraIndex,

        pub const ExtraIndex = u28;
    };

    pub fn tag(self: Type, builder: *const Builder) Tag {
        return builder.type_items.items[@intFromEnum(self)].tag;
    }

    pub fn unnamedTag(self: Type, builder: *const Builder) Tag {
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .named_structure => builder.typeExtraData(Type.NamedStructure, item.data).body
                .unnamedTag(builder),
            else => item.tag,
        };
    }

    pub fn scalarTag(self: Type, builder: *const Builder) Tag {
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .vector, .scalable_vector => builder.typeExtraData(Type.Vector, item.data)
                .child.tag(builder),
            else => item.tag,
        };
    }

    pub fn isFloatingPoint(self: Type) bool {
        return switch (self) {
            .half, .bfloat, .float, .double, .fp128, .x86_fp80, .ppc_fp128 => true,
            else => false,
        };
    }

    pub fn isInteger(self: Type, builder: *const Builder) bool {
        return switch (self) {
            .i1, .i8, .i16, .i29, .i32, .i64, .i80, .i128 => true,
            else => switch (self.tag(builder)) {
                .integer => true,
                else => false,
            },
        };
    }

    pub fn isPointer(self: Type, builder: *const Builder) bool {
        return switch (self) {
            .ptr => true,
            else => switch (self.tag(builder)) {
                .pointer => true,
                else => false,
            },
        };
    }

    pub fn pointerAddrSpace(self: Type, builder: *const Builder) AddrSpace {
        switch (self) {
            .ptr => return .default,
            else => {
                const item = builder.type_items.items[@intFromEnum(self)];
                assert(item.tag == .pointer);
                return @enumFromInt(item.data);
            },
        }
    }

    pub fn isFunction(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .function, .vararg_function => true,
            else => false,
        };
    }

    pub fn functionKind(self: Type, builder: *const Builder) Type.Function.Kind {
        return switch (self.tag(builder)) {
            .function => .normal,
            .vararg_function => .vararg,
            else => unreachable,
        };
    }

    pub fn functionParameters(self: Type, builder: *const Builder) []const Type {
        const item = builder.type_items.items[@intFromEnum(self)];
        switch (item.tag) {
            .function,
            .vararg_function,
            => {
                var extra = builder.typeExtraDataTrail(Type.Function, item.data);
                return extra.trail.next(extra.data.params_len, Type, builder);
            },
            else => unreachable,
        }
    }

    pub fn functionReturn(self: Type, builder: *const Builder) Type {
        const item = builder.type_items.items[@intFromEnum(self)];
        switch (item.tag) {
            .function,
            .vararg_function,
            => return builder.typeExtraData(Type.Function, item.data).ret,
            else => unreachable,
        }
    }

    pub fn isVector(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .vector, .scalable_vector => true,
            else => false,
        };
    }

    pub fn vectorKind(self: Type, builder: *const Builder) Type.Vector.Kind {
        return switch (self.tag(builder)) {
            .vector => .normal,
            .scalable_vector => .scalable,
            else => unreachable,
        };
    }

    pub fn isStruct(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .structure, .packed_structure, .named_structure => true,
            else => false,
        };
    }

    pub fn structKind(self: Type, builder: *const Builder) Type.Structure.Kind {
        return switch (self.unnamedTag(builder)) {
            .structure => .normal,
            .packed_structure => .@"packed",
            else => unreachable,
        };
    }

    pub fn isAggregate(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .small_array, .array, .structure, .packed_structure, .named_structure => true,
            else => false,
        };
    }

    pub fn scalarBits(self: Type, builder: *const Builder) u24 {
        return switch (self) {
            .void, .label, .token, .metadata, .none, .x86_amx => unreachable,
            .i1 => 1,
            .i8 => 8,
            .half, .bfloat, .i16 => 16,
            .i29 => 29,
            .float, .i32 => 32,
            .double, .i64, .x86_mmx => 64,
            .x86_fp80, .i80 => 80,
            .fp128, .ppc_fp128, .i128 => 128,
            .ptr, .@"ptr addrspace(4)" => @panic("TODO: query data layout"),
            _ => {
                const item = builder.type_items.items[@intFromEnum(self)];
                return switch (item.tag) {
                    .simple,
                    .function,
                    .vararg_function,
                    => unreachable,
                    .integer => @intCast(item.data),
                    .pointer => @panic("TODO: query data layout"),
                    .target => unreachable,
                    .vector,
                    .scalable_vector,
                    => builder.typeExtraData(Type.Vector, item.data).child.scalarBits(builder),
                    .small_array,
                    .array,
                    .structure,
                    .packed_structure,
                    .named_structure,
                    => unreachable,
                };
            },
        };
    }

    pub fn childType(self: Type, builder: *const Builder) Type {
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .vector,
            .scalable_vector,
            .small_array,
            => builder.typeExtraData(Type.Vector, item.data).child,
            .array => builder.typeExtraData(Type.Array, item.data).child,
            .named_structure => builder.typeExtraData(Type.NamedStructure, item.data).body,
            else => unreachable,
        };
    }

    pub fn scalarType(self: Type, builder: *const Builder) Type {
        if (self.isFloatingPoint()) return self;
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .integer,
            .pointer,
            => self,
            .vector,
            .scalable_vector,
            => builder.typeExtraData(Type.Vector, item.data).child,
            else => unreachable,
        };
    }

    pub fn changeScalar(self: Type, scalar: Type, builder: *Builder) Allocator.Error!Type {
        try builder.ensureUnusedTypeCapacity(1, Type.Vector, 0);
        return self.changeScalarAssumeCapacity(scalar, builder);
    }

    pub fn changeScalarAssumeCapacity(self: Type, scalar: Type, builder: *Builder) Type {
        if (self.isFloatingPoint()) return scalar;
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .integer,
            .pointer,
            => scalar,
            inline .vector,
            .scalable_vector,
            => |kind| builder.vectorTypeAssumeCapacity(
                switch (kind) {
                    .vector => .normal,
                    .scalable_vector => .scalable,
                    else => unreachable,
                },
                builder.typeExtraData(Type.Vector, item.data).len,
                scalar,
            ),
            else => unreachable,
        };
    }

    pub fn vectorLen(self: Type, builder: *const Builder) u32 {
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .vector,
            .scalable_vector,
            => builder.typeExtraData(Type.Vector, item.data).len,
            else => unreachable,
        };
    }

    pub fn changeLength(self: Type, len: u32, builder: *Builder) Allocator.Error!Type {
        try builder.ensureUnusedTypeCapacity(1, Type.Array, 0);
        return self.changeLengthAssumeCapacity(len, builder);
    }

    pub fn changeLengthAssumeCapacity(self: Type, len: u32, builder: *Builder) Type {
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            inline .vector,
            .scalable_vector,
            => |kind| builder.vectorTypeAssumeCapacity(
                switch (kind) {
                    .vector => .normal,
                    .scalable_vector => .scalable,
                    else => unreachable,
                },
                len,
                builder.typeExtraData(Type.Vector, item.data).child,
            ),
            .small_array => builder.arrayTypeAssumeCapacity(
                len,
                builder.typeExtraData(Type.Vector, item.data).child,
            ),
            .array => builder.arrayTypeAssumeCapacity(
                len,
                builder.typeExtraData(Type.Array, item.data).child,
            ),
            else => unreachable,
        };
    }

    pub fn aggregateLen(self: Type, builder: *const Builder) usize {
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .vector,
            .scalable_vector,
            .small_array,
            => builder.typeExtraData(Type.Vector, item.data).len,
            .array => @intCast(builder.typeExtraData(Type.Array, item.data).length()),
            .structure,
            .packed_structure,
            => builder.typeExtraData(Type.Structure, item.data).fields_len,
            .named_structure => builder.typeExtraData(Type.NamedStructure, item.data).body
                .aggregateLen(builder),
            else => unreachable,
        };
    }

    pub fn structFields(self: Type, builder: *const Builder) []const Type {
        const item = builder.type_items.items[@intFromEnum(self)];
        switch (item.tag) {
            .structure,
            .packed_structure,
            => {
                var extra = builder.typeExtraDataTrail(Type.Structure, item.data);
                return extra.trail.next(extra.data.fields_len, Type, builder);
            },
            .named_structure => return builder.typeExtraData(Type.NamedStructure, item.data).body
                .structFields(builder),
            else => unreachable,
        }
    }

    pub fn childTypeAt(self: Type, indices: []const u32, builder: *const Builder) Type {
        if (indices.len == 0) return self;
        const item = builder.type_items.items[@intFromEnum(self)];
        return switch (item.tag) {
            .small_array => builder.typeExtraData(Type.Vector, item.data).child
                .childTypeAt(indices[1..], builder),
            .array => builder.typeExtraData(Type.Array, item.data).child
                .childTypeAt(indices[1..], builder),
            .structure,
            .packed_structure,
            => {
                var extra = builder.typeExtraDataTrail(Type.Structure, item.data);
                const fields = extra.trail.next(extra.data.fields_len, Type, builder);
                return fields[indices[0]].childTypeAt(indices[1..], builder);
            },
            .named_structure => builder.typeExtraData(Type.NamedStructure, item.data).body
                .childTypeAt(indices, builder),
            else => unreachable,
        };
    }

    pub fn targetLayoutType(self: Type, builder: *const Builder) Type {
        _ = self;
        _ = builder;
        @panic("TODO: implement targetLayoutType");
    }

    pub fn isSized(self: Type, builder: *const Builder) Allocator.Error!bool {
        var visited: IsSizedVisited = .{};
        defer visited.deinit(builder.gpa);
        const result = try self.isSizedVisited(&visited, builder);
        return result;
    }

    const FormatData = struct {
        type: Type,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        fmt_opts: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        assert(data.type != .none);
        if (comptime std.mem.eql(u8, fmt_str, "m")) {
            const item = data.builder.type_items.items[@intFromEnum(data.type)];
            switch (item.tag) {
                .simple => try writer.writeAll(switch (@as(Simple, @enumFromInt(item.data))) {
                    .void => "isVoid",
                    .half => "f16",
                    .bfloat => "bf16",
                    .float => "f32",
                    .double => "f64",
                    .fp128 => "f128",
                    .x86_fp80 => "f80",
                    .ppc_fp128 => "ppcf128",
                    .x86_amx => "x86amx",
                    .x86_mmx => "x86mmx",
                    .label, .token => unreachable,
                    .metadata => "Metadata",
                }),
                .function, .vararg_function => |kind| {
                    var extra = data.builder.typeExtraDataTrail(Type.Function, item.data);
                    const params = extra.trail.next(extra.data.params_len, Type, data.builder);
                    try writer.print("f_{m}", .{extra.data.ret.fmt(data.builder)});
                    for (params) |param| try writer.print("{m}", .{param.fmt(data.builder)});
                    switch (kind) {
                        .function => {},
                        .vararg_function => try writer.writeAll("vararg"),
                        else => unreachable,
                    }
                    try writer.writeByte('f');
                },
                .integer => try writer.print("i{d}", .{item.data}),
                .pointer => try writer.print("p{d}", .{item.data}),
                .target => {
                    var extra = data.builder.typeExtraDataTrail(Type.Target, item.data);
                    const types = extra.trail.next(extra.data.types_len, Type, data.builder);
                    const ints = extra.trail.next(extra.data.ints_len, u32, data.builder);
                    try writer.print("t{s}", .{extra.data.name.slice(data.builder).?});
                    for (types) |ty| try writer.print("_{m}", .{ty.fmt(data.builder)});
                    for (ints) |int| try writer.print("_{d}", .{int});
                    try writer.writeByte('t');
                },
                .vector, .scalable_vector => |kind| {
                    const extra = data.builder.typeExtraData(Type.Vector, item.data);
                    try writer.print("{s}v{d}{m}", .{
                        switch (kind) {
                            .vector => "",
                            .scalable_vector => "nx",
                            else => unreachable,
                        },
                        extra.len,
                        extra.child.fmt(data.builder),
                    });
                },
                inline .small_array, .array => |kind| {
                    const extra = data.builder.typeExtraData(switch (kind) {
                        .small_array => Type.Vector,
                        .array => Type.Array,
                        else => unreachable,
                    }, item.data);
                    try writer.print("a{d}{m}", .{ extra.length(), extra.child.fmt(data.builder) });
                },
                .structure, .packed_structure => {
                    var extra = data.builder.typeExtraDataTrail(Type.Structure, item.data);
                    const fields = extra.trail.next(extra.data.fields_len, Type, data.builder);
                    try writer.writeAll("sl_");
                    for (fields) |field| try writer.print("{m}", .{field.fmt(data.builder)});
                    try writer.writeByte('s');
                },
                .named_structure => {
                    const extra = data.builder.typeExtraData(Type.NamedStructure, item.data);
                    try writer.writeAll("s_");
                    if (extra.id.slice(data.builder)) |id| try writer.writeAll(id);
                },
            }
            return;
        }
        if (std.enums.tagName(Type, data.type)) |name| return writer.writeAll(name);
        const item = data.builder.type_items.items[@intFromEnum(data.type)];
        switch (item.tag) {
            .simple => unreachable,
            .function, .vararg_function => |kind| {
                var extra = data.builder.typeExtraDataTrail(Type.Function, item.data);
                const params = extra.trail.next(extra.data.params_len, Type, data.builder);
                if (!comptime std.mem.eql(u8, fmt_str, ">"))
                    try writer.print("{%} ", .{extra.data.ret.fmt(data.builder)});
                if (!comptime std.mem.eql(u8, fmt_str, "<")) {
                    try writer.writeByte('(');
                    for (params, 0..) |param, index| {
                        if (index > 0) try writer.writeAll(", ");
                        try writer.print("{%}", .{param.fmt(data.builder)});
                    }
                    switch (kind) {
                        .function => {},
                        .vararg_function => {
                            if (params.len > 0) try writer.writeAll(", ");
                            try writer.writeAll("...");
                        },
                        else => unreachable,
                    }
                    try writer.writeByte(')');
                }
            },
            .integer => try writer.print("i{d}", .{item.data}),
            .pointer => try writer.print("ptr{ }", .{@as(AddrSpace, @enumFromInt(item.data))}),
            .target => {
                var extra = data.builder.typeExtraDataTrail(Type.Target, item.data);
                const types = extra.trail.next(extra.data.types_len, Type, data.builder);
                const ints = extra.trail.next(extra.data.ints_len, u32, data.builder);
                try writer.print(
                    \\target({"}
                , .{extra.data.name.fmt(data.builder)});
                for (types) |ty| try writer.print(", {%}", .{ty.fmt(data.builder)});
                for (ints) |int| try writer.print(", {d}", .{int});
                try writer.writeByte(')');
            },
            .vector, .scalable_vector => |kind| {
                const extra = data.builder.typeExtraData(Type.Vector, item.data);
                try writer.print("<{s}{d} x {%}>", .{
                    switch (kind) {
                        .vector => "",
                        .scalable_vector => "vscale x ",
                        else => unreachable,
                    },
                    extra.len,
                    extra.child.fmt(data.builder),
                });
            },
            inline .small_array, .array => |kind| {
                const extra = data.builder.typeExtraData(switch (kind) {
                    .small_array => Type.Vector,
                    .array => Type.Array,
                    else => unreachable,
                }, item.data);
                try writer.print("[{d} x {%}]", .{ extra.length(), extra.child.fmt(data.builder) });
            },
            .structure, .packed_structure => |kind| {
                var extra = data.builder.typeExtraDataTrail(Type.Structure, item.data);
                const fields = extra.trail.next(extra.data.fields_len, Type, data.builder);
                switch (kind) {
                    .structure => {},
                    .packed_structure => try writer.writeByte('<'),
                    else => unreachable,
                }
                try writer.writeAll("{ ");
                for (fields, 0..) |field, index| {
                    if (index > 0) try writer.writeAll(", ");
                    try writer.print("{%}", .{field.fmt(data.builder)});
                }
                try writer.writeAll(" }");
                switch (kind) {
                    .structure => {},
                    .packed_structure => try writer.writeByte('>'),
                    else => unreachable,
                }
            },
            .named_structure => {
                const extra = data.builder.typeExtraData(Type.NamedStructure, item.data);
                if (comptime std.mem.eql(u8, fmt_str, "%")) try writer.print("%{}", .{
                    extra.id.fmt(data.builder),
                }) else switch (extra.body) {
                    .none => try writer.writeAll("opaque"),
                    else => try format(.{
                        .type = extra.body,
                        .builder = data.builder,
                    }, fmt_str, fmt_opts, writer),
                }
            },
        }
    }
    pub fn fmt(self: Type, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .type = self, .builder = builder } };
    }

    const IsSizedVisited = std.AutoHashMapUnmanaged(Type, void);
    fn isSizedVisited(
        self: Type,
        visited: *IsSizedVisited,
        builder: *const Builder,
    ) Allocator.Error!bool {
        return switch (self) {
            .void,
            .label,
            .token,
            .metadata,
            => false,
            .half,
            .bfloat,
            .float,
            .double,
            .fp128,
            .x86_fp80,
            .ppc_fp128,
            .x86_amx,
            .x86_mmx,
            .i1,
            .i8,
            .i16,
            .i29,
            .i32,
            .i64,
            .i80,
            .i128,
            .ptr,
            .@"ptr addrspace(4)",
            => true,
            .none => unreachable,
            _ => {
                const item = builder.type_items.items[@intFromEnum(self)];
                return switch (item.tag) {
                    .simple => unreachable,
                    .function,
                    .vararg_function,
                    => false,
                    .integer,
                    .pointer,
                    => true,
                    .target => self.targetLayoutType(builder).isSizedVisited(visited, builder),
                    .vector,
                    .scalable_vector,
                    .small_array,
                    => builder.typeExtraData(Type.Vector, item.data)
                        .child.isSizedVisited(visited, builder),
                    .array => builder.typeExtraData(Type.Array, item.data)
                        .child.isSizedVisited(visited, builder),
                    .structure,
                    .packed_structure,
                    => {
                        if (try visited.fetchPut(builder.gpa, self, {})) |_| return false;

                        var extra = builder.typeExtraDataTrail(Type.Structure, item.data);
                        const fields = extra.trail.next(extra.data.fields_len, Type, builder);
                        for (fields) |field| {
                            if (field.isVector(builder) and field.vectorKind(builder) == .scalable)
                                return false;
                            if (!try field.isSizedVisited(visited, builder))
                                return false;
                        }
                        return true;
                    },
                    .named_structure => {
                        const body = builder.typeExtraData(Type.NamedStructure, item.data).body;
                        return body != .none and try body.isSizedVisited(visited, builder);
                    },
                };
            },
        };
    }
};

pub const Attribute = union(Kind) {
    // Parameter Attributes
    zeroext,
    signext,
    inreg,
    byval: Type,
    byref: Type,
    preallocated: Type,
    inalloca: Type,
    sret: Type,
    elementtype: Type,
    @"align": Alignment,
    @"noalias",
    nocapture,
    nofree,
    nest,
    returned,
    nonnull,
    dereferenceable: u32,
    dereferenceable_or_null: u32,
    swiftself,
    swiftasync,
    swifterror,
    immarg,
    noundef,
    nofpclass: FpClass,
    alignstack: Alignment,
    allocalign,
    allocptr,
    readnone,
    readonly,
    writeonly,

    // Function Attributes
    //alignstack: Alignment,
    allockind: AllocKind,
    allocsize: Alloc```
