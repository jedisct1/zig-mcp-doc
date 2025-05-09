```
   emit_object: bool = false,

    /// Prefer populating this field (using e.g. `createModule`) instead of populating
    /// the following fields (`root_source_file` etc). In a future release, those fields
    /// will be removed, and this field will become non-optional.
    root_module: ?*Module = null,

    /// Deprecated; prefer populating `root_module`.
    root_source_file: ?LazyPath = null,
    /// Deprecated; prefer populating `root_module`.
    target: ?ResolvedTarget = null,
    /// Deprecated; prefer populating `root_module`.
    optimize: std.builtin.OptimizeMode = .Debug,
    /// Deprecated; prefer populating `root_module`.
    version: ?std.SemanticVersion = null,
    /// Deprecated; prefer populating `root_module`.
    link_libc: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    link_libcpp: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    single_threaded: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    pic: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    strip: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    unwind_tables: ?std.builtin.UnwindTables = null,
    /// Deprecated; prefer populating `root_module`.
    omit_frame_pointer: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    sanitize_thread: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    error_tracing: ?bool = null,
};

/// Creates an executable containing unit tests.
///
/// Equivalent to running the command `zig test --test-no-exec ...`.
///
/// **This step does not run the unit tests**. Typically, the result of this
/// function will be passed to `addRunArtifact`, creating a `Step.Run`. These
/// two steps are separated because they are independently configured and
/// cached.
pub fn addTest(b: *Build, options: TestOptions) *Step.Compile {
    if (options.root_module != null and options.root_source_file != null) {
        @panic("`root_module` and `root_source_file` cannot both be populated");
    }
    return .create(b, .{
        .name = options.name,
        .kind = if (options.emit_object) .test_obj else .@"test",
        .root_module = options.root_module orelse b.createModule(.{
            .root_source_file = options.root_source_file orelse @panic("`root_module` and `root_source_file` cannot both be null"),
            .target = options.target orelse b.graph.host,
            .optimize = options.optimize,
            .link_libc = options.link_libc,
            .link_libcpp = options.link_libcpp,
            .single_threaded = options.single_threaded,
            .pic = options.pic,
            .strip = options.strip,
            .unwind_tables = options.unwind_tables,
            .omit_frame_pointer = options.omit_frame_pointer,
            .sanitize_thread = options.sanitize_thread,
            .error_tracing = options.error_tracing,
        }),
        .max_rss = options.max_rss,
        .filters = if (options.filter != null and options.filters.len > 0) filters: {
            const filters = b.allocator.alloc([]const u8, 1 + options.filters.len) catch @panic("OOM");
            filters[0] = b.dupe(options.filter.?);
            for (filters[1..], options.filters) |*dest, source| dest.* = b.dupe(source);
            break :filters filters;
        } else b.dupeStrings(if (options.filter) |filter| &.{filter} else options.filters),
        .test_runner = options.test_runner,
        .use_llvm = options.use_llvm,
        .use_lld = options.use_lld,
        .zig_lib_dir = options.zig_lib_dir,
    });
}

pub const AssemblyOptions = struct {
    name: []const u8,
    source_file: LazyPath,
    /// To choose the same computer as the one building the package, pass the
    /// `host` field of the package's `Build` instance.
    target: ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    max_rss: usize = 0,
    zig_lib_dir: ?LazyPath = null,
};

/// Deprecated; prefer using `addObject` where the `root_module` has an empty
/// `root_source_file` and contains an assembly file via `Module.addAssemblyFile`.
pub fn addAssembly(b: *Build, options: AssemblyOptions) *Step.Compile {
    const root_module = b.createModule(.{
        .target = options.target,
        .optimize = options.optimize,
    });
    root_module.addAssemblyFile(options.source_file);
    return b.addObject(.{
        .name = options.name,
        .max_rss = options.max_rss,
        .zig_lib_dir = options.zig_lib_dir,
        .root_module = root_module,
    });
}

/// This function creates a module and adds it to the package's module set, making
/// it available to other packages which depend on this one.
/// `createModule` can be used instead to create a private module.
pub fn addModule(b: *Build, name: []const u8, options: Module.CreateOptions) *Module {
    const module = Module.create(b, options);
    b.modules.put(b.dupe(name), module) catch @panic("OOM");
    return module;
}

/// This function creates a private module, to be used by the current package,
/// but not exposed to other packages depending on this one.
/// `addModule` can be used instead to create a public module.
pub fn createModule(b: *Build, options: Module.CreateOptions) *Module {
    return Module.create(b, options);
}

/// Initializes a `Step.Run` with argv, which must at least have the path to the
/// executable. More command line arguments can be added with `addArg`,
/// `addArgs`, and `addArtifactArg`.
/// Be careful using this function, as it introduces a system dependency.
/// To run an executable built with zig build, see `Step.Compile.run`.
pub fn addSystemCommand(b: *Build, argv: []const []const u8) *Step.Run {
    assert(argv.len >= 1);
    const run_step = Step.Run.create(b, b.fmt("run {s}", .{argv[0]}));
    run_step.addArgs(argv);
    return run_step;
}

/// Creates a `Step.Run` with an executable built with `addExecutable`.
/// Add command line arguments with methods of `Step.Run`.
pub fn addRunArtifact(b: *Build, exe: *Step.Compile) *Step.Run {
    // It doesn't have to be native. We catch that if you actually try to run it.
    // Consider that this is declarative; the run step may not be run unless a user
    // option is supplied.
    const run_step = Step.Run.create(b, b.fmt("run {s}", .{exe.name}));
    run_step.producer = exe;
    if (exe.kind == .@"test") {
        if (exe.exec_cmd_args) |exec_cmd_args| {
            for (exec_cmd_args) |cmd_arg| {
                if (cmd_arg) |arg| {
                    run_step.addArg(arg);
                } else {
                    run_step.addArtifactArg(exe);
                }
            }
        } else {
            run_step.addArtifactArg(exe);
        }

        const test_server_mode = if (exe.test_runner) |r| r.mode == .server else true;
        if (test_server_mode) run_step.enableTestRunnerMode();
    } else {
        run_step.addArtifactArg(exe);
    }

    return run_step;
}

/// Using the `values` provided, produces a C header file, possibly based on a
/// template input file (e.g. config.h.in).
/// When an input template file is provided, this function will fail the build
/// when an option not found in the input file is provided in `values`, and
/// when an option found in the input file is missing from `values`.
pub fn addConfigHeader(
    b: *Build,
    options: Step.ConfigHeader.Options,
    values: anytype,
) *Step.ConfigHeader {
    var options_copy = options;
    if (options_copy.first_ret_addr == null)
        options_copy.first_ret_addr = @returnAddress();

    const config_header_step = Step.ConfigHeader.create(b, options_copy);
    config_header_step.addValues(values);
    return config_header_step;
}

/// Allocator.dupe without the need to handle out of memory.
pub fn dupe(b: *Build, bytes: []const u8) []u8 {
    return dupeInner(b.allocator, bytes);
}

pub fn dupeInner(allocator: std.mem.Allocator, bytes: []const u8) []u8 {
    return allocator.dupe(u8, bytes) catch @panic("OOM");
}

/// Duplicates an array of strings without the need to handle out of memory.
pub fn dupeStrings(b: *Build, strings: []const []const u8) [][]u8 {
    const array = b.allocator.alloc([]u8, strings.len) catch @panic("OOM");
    for (array, strings) |*dest, source| dest.* = b.dupe(source);
    return array;
}

/// Duplicates a path and converts all slashes to the OS's canonical path separator.
pub fn dupePath(b: *Build, bytes: []const u8) []u8 {
    return dupePathInner(b.allocator, bytes);
}

fn dupePathInner(allocator: std.mem.Allocator, bytes: []const u8) []u8 {
    const the_copy = dupeInner(allocator, bytes);
    for (the_copy) |*byte| {
        switch (byte.*) {
            '/', '\\' => byte.* = fs.path.sep,
            else => {},
        }
    }
    return the_copy;
}

pub fn addWriteFile(b: *Build, file_path: []const u8, data: []const u8) *Step.WriteFile {
    const write_file_step = b.addWriteFiles();
    _ = write_file_step.add(file_path, data);
    return write_file_step;
}

pub fn addNamedWriteFiles(b: *Build, name: []const u8) *Step.WriteFile {
    const wf = Step.WriteFile.create(b);
    b.named_writefiles.put(b.dupe(name), wf) catch @panic("OOM");
    return wf;
}

pub fn addNamedLazyPath(b: *Build, name: []const u8, lp: LazyPath) void {
    b.named_lazy_paths.put(b.dupe(name), lp.dupe(b)) catch @panic("OOM");
}

pub fn addWriteFiles(b: *Build) *Step.WriteFile {
    return Step.WriteFile.create(b);
}

pub fn addUpdateSourceFiles(b: *Build) *Step.UpdateSourceFiles {
    return Step.UpdateSourceFiles.create(b);
}

pub fn addRemoveDirTree(b: *Build, dir_path: LazyPath) *Step.RemoveDir {
    return Step.RemoveDir.create(b, dir_path);
}

pub fn addFail(b: *Build, error_msg: []const u8) *Step.Fail {
    return Step.Fail.create(b, error_msg);
}

pub fn addFmt(b: *Build, options: Step.Fmt.Options) *Step.Fmt {
    return Step.Fmt.create(b, options);
}

pub fn addTranslateC(b: *Build, options: Step.TranslateC.Options) *Step.TranslateC {
    return Step.TranslateC.create(b, options);
}

pub fn getInstallStep(b: *Build) *Step {
    return &b.install_tls.step;
}

pub fn getUninstallStep(b: *Build) *Step {
    return &b.uninstall_tls.step;
}

fn makeUninstall(uninstall_step: *Step, options: Step.MakeOptions) anyerror!void {
    _ = options;
    const uninstall_tls: *TopLevelStep = @fieldParentPtr("step", uninstall_step);
    const b: *Build = @fieldParentPtr("uninstall_tls", uninstall_tls);

    _ = b;
    @panic("TODO implement https://github.com/ziglang/zig/issues/14943");
}

/// Creates a configuration option to be passed to the build.zig script.
/// When a user directly runs `zig build`, they can set these options with `-D` arguments.
/// When a project depends on a Zig package as a dependency, it programmatically sets
/// these options when calling the dependency's build.zig script as a function.
/// `null` is returned when an option is left to default.
pub fn option(b: *Build, comptime T: type, name_raw: []const u8, description_raw: []const u8) ?T {
    const name = b.dupe(name_raw);
    const description = b.dupe(description_raw);
    const type_id = comptime typeToEnum(T);
    const enum_options = if (type_id == .@"enum" or type_id == .enum_list) blk: {
        const EnumType = if (type_id == .enum_list) @typeInfo(T).pointer.child else T;
        const fields = comptime std.meta.fields(EnumType);
        var options = ArrayList([]const u8).initCapacity(b.allocator, fields.len) catch @panic("OOM");

        inline for (fields) |field| {
            options.appendAssumeCapacity(field.name);
        }

        break :blk options.toOwnedSlice() catch @panic("OOM");
    } else null;
    const available_option = AvailableOption{
        .name = name,
        .type_id = type_id,
        .description = description,
        .enum_options = enum_options,
    };
    if ((b.available_options_map.fetchPut(name, available_option) catch @panic("OOM")) != null) {
        panic("Option '{s}' declared twice", .{name});
    }
    b.available_options_list.append(available_option) catch @panic("OOM");

    const option_ptr = b.user_input_options.getPtr(name) orelse return null;
    option_ptr.used = true;
    switch (type_id) {
        .bool => switch (option_ptr.value) {
            .flag => return true,
            .scalar => |s| {
                if (mem.eql(u8, s, "true")) {
                    return true;
                } else if (mem.eql(u8, s, "false")) {
                    return false;
                } else {
                    log.err("Expected -D{s} to be a boolean, but received '{s}'", .{ name, s });
                    b.markInvalidUserInput();
                    return null;
                }
            },
            .list, .map, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be a boolean, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
        },
        .int => switch (option_ptr.value) {
            .flag, .list, .map, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be an integer, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
            .scalar => |s| {
                const n = std.fmt.parseInt(T, s, 10) catch |err| switch (err) {
                    error.Overflow => {
                        log.err("-D{s} value {s} cannot fit into type {s}.", .{ name, s, @typeName(T) });
                        b.markInvalidUserInput();
                        return null;
                    },
                    else => {
                        log.err("Expected -D{s} to be an integer of type {s}.", .{ name, @typeName(T) });
                        b.markInvalidUserInput();
                        return null;
                    },
                };
                return n;
            },
        },
        .float => switch (option_ptr.value) {
            .flag, .map, .list, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be a float, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
            .scalar => |s| {
                const n = std.fmt.parseFloat(T, s) catch {
                    log.err("Expected -D{s} to be a float of type {s}.", .{ name, @typeName(T) });
                    b.markInvalidUserInput();
                    return null;
                };
                return n;
            },
        },
        .@"enum" => switch (option_ptr.value) {
            .flag, .map, .list, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be an enum, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
            .scalar => |s| {
                if (std.meta.stringToEnum(T, s)) |enum_lit| {
                    return enum_lit;
                } else {
                    log.err("Expected -D{s} to be of type {s}.", .{ name, @typeName(T) });
                    b.markInvalidUserInput();
                    return null;
                }
            },
        },
        .string => switch (option_ptr.value) {
            .flag, .list, .map, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be a string, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
            .scalar => |s| return s,
        },
        .build_id => switch (option_ptr.value) {
            .flag, .map, .list, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be an enum, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
            .scalar => |s| {
                if (std.zig.BuildId.parse(s)) |build_id| {
                    return build_id;
                } else |err| {
                    log.err("unable to parse option '-D{s}': {s}", .{ name, @errorName(err) });
                    b.markInvalidUserInput();
                    return null;
                }
            },
        },
        .list => switch (option_ptr.value) {
            .flag, .map, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be a list, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
            .scalar => |s| {
                return b.allocator.dupe([]const u8, &[_][]const u8{s}) catch @panic("OOM");
            },
            .list => |lst| return lst.items,
        },
        .enum_list => switch (option_ptr.value) {
            .flag, .map, .lazy_path, .lazy_path_list => {
                log.err("Expected -D{s} to be a list, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
            .scalar => |s| {
                const Child = @typeInfo(T).pointer.child;
                const value = std.meta.stringToEnum(Child, s) orelse {
                    log.err("Expected -D{s} to be of type {s}.", .{ name, @typeName(Child) });
                    b.markInvalidUserInput();
                    return null;
                };
                return b.allocator.dupe(Child, &[_]Child{value}) catch @panic("OOM");
            },
            .list => |lst| {
                const Child = @typeInfo(T).pointer.child;
                const new_list = b.allocator.alloc(Child, lst.items.len) catch @panic("OOM");
                for (new_list, lst.items) |*new_item, str| {
                    new_item.* = std.meta.stringToEnum(Child, str) orelse {
                        log.err("Expected -D{s} to be of type {s}.", .{ name, @typeName(Child) });
                        b.markInvalidUserInput();
                        b.allocator.free(new_list);
                        return null;
                    };
                }
                return new_list;
            },
        },
        .lazy_path => switch (option_ptr.value) {
            .scalar => |s| return .{ .cwd_relative = s },
            .lazy_path => |lp| return lp,
            .flag, .map, .list, .lazy_path_list => {
                log.err("Expected -D{s} to be a path, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
        },
        .lazy_path_list => switch (option_ptr.value) {
            .scalar => |s| return b.allocator.dupe(LazyPath, &[_]LazyPath{.{ .cwd_relative = s }}) catch @panic("OOM"),
            .lazy_path => |lp| return b.allocator.dupe(LazyPath, &[_]LazyPath{lp}) catch @panic("OOM"),
            .list => |lst| {
                const new_list = b.allocator.alloc(LazyPath, lst.items.len) catch @panic("OOM");
                for (new_list, lst.items) |*new_item, str| {
                    new_item.* = .{ .cwd_relative = str };
                }
                return new_list;
            },
            .lazy_path_list => |lp_list| return lp_list.items,
            .flag, .map => {
                log.err("Expected -D{s} to be a path, but received a {s}.", .{
                    name, @tagName(option_ptr.value),
                });
                b.markInvalidUserInput();
                return null;
            },
        },
    }
}

pub fn step(b: *Build, name: []const u8, description: []const u8) *Step {
    const step_info = b.allocator.create(TopLevelStep) catch @panic("OOM");
    step_info.* = .{
        .step = Step.init(.{
            .id = TopLevelStep.base_id,
            .name = name,
            .owner = b,
        }),
        .description = b.dupe(description),
    };
    const gop = b.top_level_steps.getOrPut(b.allocator, name) catch @panic("OOM");
    if (gop.found_existing) std.debug.panic("A top-level step with name \"{s}\" already exists", .{name});

    gop.key_ptr.* = step_info.step.name;
    gop.value_ptr.* = step_info;

    return &step_info.step;
}

pub const StandardOptimizeOptionOptions = struct {
    preferred_optimize_mode: ?std.builtin.OptimizeMode = null,
};

pub fn standardOptimizeOption(b: *Build, options: StandardOptimizeOptionOptions) std.builtin.OptimizeMode {
    if (options.preferred_optimize_mode) |mode| {
        if (b.option(bool, "release", "optimize for end users") orelse (b.release_mode != .off)) {
            return mode;
        } else {
            return .Debug;
        }
    }

    if (b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size",
    )) |mode| {
        return mode;
    }

    return switch (b.release_mode) {
        .off => .Debug,
        .any => {
            std.debug.print("the project does not declare a preferred optimization mode. choose: --release=fast, --release=safe, or --release=small\n", .{});
            process.exit(1);
        },
        .fast => .ReleaseFast,
        .safe => .ReleaseSafe,
        .small => .ReleaseSmall,
    };
}

pub const StandardTargetOptionsArgs = struct {
    whitelist: ?[]const Target.Query = null,
    default_target: Target.Query = .{},
};

/// Exposes standard `zig build` options for choosing a target and additionally
/// resolves the target query.
pub fn standardTargetOptions(b: *Build, args: StandardTargetOptionsArgs) ResolvedTarget {
    const query = b.standardTargetOptionsQueryOnly(args);
    return b.resolveTargetQuery(query);
}

/// Obtain a target query from a string, reporting diagnostics to stderr if the
/// parsing failed.
/// Asserts that the `diagnostics` field of `options` is `null`. This use case
/// is handled instead by calling `std.Target.Query.parse` directly.
pub fn parseTargetQuery(options: std.Target.Query.ParseOptions) error{ParseFailed}!std.Target.Query {
    assert(options.diagnostics == null);
    var diags: Target.Query.ParseOptions.Diagnostics = .{};
    var opts_copy = options;
    opts_copy.diagnostics = &diags;
    return std.Target.Query.parse(opts_copy) catch |err| switch (err) {
        error.UnknownCpuModel => {
            std.debug.print("unknown CPU: '{s}'\navailable CPUs for architecture '{s}':\n", .{
                diags.cpu_name.?, @tagName(diags.arch.?),
            });
            for (diags.arch.?.allCpuModels()) |cpu| {
                std.debug.print(" {s}\n", .{cpu.name});
            }
            return error.ParseFailed;
        },
        error.UnknownCpuFeature => {
            std.debug.print(
                \\unknown CPU feature: '{s}'
                \\available CPU features for architecture '{s}':
                \\
            , .{
                diags.unknown_feature_name.?,
                @tagName(diags.arch.?),
            });
            for (diags.arch.?.allFeaturesList()) |feature| {
                std.debug.print(" {s}: {s}\n", .{ feature.name, feature.description });
            }
            return error.ParseFailed;
        },
        error.UnknownOperatingSystem => {
            std.debug.print(
                \\unknown OS: '{s}'
                \\available operating systems:
                \\
            , .{diags.os_name.?});
            inline for (std.meta.fields(Target.Os.Tag)) |field| {
                std.debug.print(" {s}\n", .{field.name});
            }
            return error.ParseFailed;
        },
        else => |e| {
            std.debug.print("unable to parse target '{s}': {s}\n", .{
                options.arch_os_abi, @errorName(e),
            });
            return error.ParseFailed;
        },
    };
}

/// Exposes standard `zig build` options for choosing a target.
pub fn standardTargetOptionsQueryOnly(b: *Build, args: StandardTargetOptionsArgs) Target.Query {
    const maybe_triple = b.option(
        []const u8,
        "target",
        "The CPU architecture, OS, and ABI to build for",
    );
    const mcpu = b.option(
        []const u8,
        "cpu",
        "Target CPU features to add or subtract",
    );
    const ofmt = b.option(
        []const u8,
        "ofmt",
        "Target object format",
    );
    const dynamic_linker = b.option(
        []const u8,
        "dynamic-linker",
        "Path to interpreter on the target system",
    );

    if (maybe_triple == null and mcpu == null and ofmt == null and dynamic_linker == null)
        return args.default_target;

    const triple = maybe_triple orelse "native";

    const selected_target = parseTargetQuery(.{
        .arch_os_abi = triple,
        .cpu_features = mcpu,
        .object_format = ofmt,
        .dynamic_linker = dynamic_linker,
    }) catch |err| switch (err) {
        error.ParseFailed => {
            b.markInvalidUserInput();
            return args.default_target;
        },
    };

    const whitelist = args.whitelist orelse return selected_target;

    // Make sure it's a match of one of the list.
    for (whitelist) |q| {
        if (q.eql(selected_target))
            return selected_target;
    }

    for (whitelist) |q| {
        log.info("allowed target: -Dtarget={s} -Dcpu={s}", .{
            q.zigTriple(b.allocator) catch @panic("OOM"),
            q.serializeCpuAlloc(b.allocator) catch @panic("OOM"),
        });
    }
    log.err("chosen target '{s}' does not match one of the allowed targets", .{
        selected_target.zigTriple(b.allocator) catch @panic("OOM"),
    });
    b.markInvalidUserInput();
    return args.default_target;
}

pub fn addUserInputOption(b: *Build, name_raw: []const u8, value_raw: []const u8) error{OutOfMemory}!bool {
    const name = b.dupe(name_raw);
    const value = b.dupe(value_raw);
    const gop = try b.user_input_options.getOrPut(name);
    if (!gop.found_existing) {
        gop.value_ptr.* = UserInputOption{
            .name = name,
            .value = .{ .scalar = value },
            .used = false,
        };
        return false;
    }

    // option already exists
    switch (gop.value_ptr.value) {
        .scalar => |s| {
            // turn it into a list
            var list = ArrayList([]const u8).init(b.allocator);
            try list.append(s);
            try list.append(value);
            try b.user_input_options.put(name, .{
                .name = name,
                .value = .{ .list = list },
                .used = false,
            });
        },
        .list => |*list| {
            // append to the list
            try list.append(value);
            try b.user_input_options.put(name, .{
                .name = name,
                .value = .{ .list = list.* },
                .used = false,
            });
        },
        .flag => {
            log.warn("option '-D{s}={s}' conflicts with flag '-D{s}'.", .{ name, value, name });
            return true;
        },
        .map => |*map| {
            _ = map;
            log.warn("TODO maps as command line arguments is not implemented yet.", .{});
            return true;
        },
        .lazy_path, .lazy_path_list => {
            log.warn("the lazy path value type isn't added from the CLI, but somehow '{s}' is a .{}", .{ name, std.zig.fmtId(@tagName(gop.value_ptr.value)) });
            return true;
        },
    }
    return false;
}

pub fn addUserInputFlag(b: *Build, name_raw: []const u8) error{OutOfMemory}!bool {
    const name = b.dupe(name_raw);
    const gop = try b.user_input_options.getOrPut(name);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .name = name,
            .value = .{ .flag = {} },
            .used = false,
        };
        return false;
    }

    // option already exists
    switch (gop.value_ptr.value) {
        .scalar => |s| {
            log.err("Flag '-D{s}' conflicts with option '-D{s}={s}'.", .{ name, name, s });
            return true;
        },
        .list, .map, .lazy_path_list => {
            log.err("Flag '-D{s}' conflicts with multiple options of the same name.", .{name});
            return true;
        },
        .lazy_path => |lp| {
            log.err("Flag '-D{s}' conflicts with option '-D{s}={s}'.", .{ name, name, lp.getDisplayName() });
            return true;
        },

        .flag => {},
    }
    return false;
}

fn typeToEnum(comptime T: type) TypeId {
    return switch (T) {
        std.zig.BuildId => .build_id,
        LazyPath => .lazy_path,
        else => return switch (@typeInfo(T)) {
            .int => .int,
            .float => .float,
            .bool => .bool,
            .@"enum" => .@"enum",
            .pointer => |pointer| switch (pointer.child) {
                u8 => .string,
                []const u8 => .list,
                LazyPath => .lazy_path_list,
                else => switch (@typeInfo(pointer.child)) {
                    .@"enum" => .enum_list,
                    else => @compileError("Unsupported type: " ++ @typeName(T)),
                },
            },
            else => @compileError("Unsupported type: " ++ @typeName(T)),
        },
    };
}

fn markInvalidUserInput(b: *Build) void {
    b.invalid_user_input = true;
}

pub fn validateUserInputDidItFail(b: *Build) bool {
    // Make sure all args are used.
    var it = b.user_input_options.iterator();
    while (it.next()) |entry| {
        if (!entry.value_ptr.used) {
            log.err("invalid option: -D{s}", .{entry.key_ptr.*});
            b.markInvalidUserInput();
        }
    }

    return b.invalid_user_input;
}

fn allocPrintCmd(ally: Allocator, opt_cwd: ?[]const u8, argv: []const []const u8) error{OutOfMemory}![]u8 {
    var buf = ArrayList(u8).init(ally);
    if (opt_cwd) |cwd| try buf.writer().print("cd {s} && ", .{cwd});
    for (argv) |arg| {
        try buf.writer().print("{s} ", .{arg});
    }
    return buf.toOwnedSlice();
}

fn printCmd(ally: Allocator, cwd: ?[]const u8, argv: []const []const u8) void {
    const text = allocPrintCmd(ally, cwd, argv) catch @panic("OOM");
    std.debug.print("{s}\n", .{text});
}

/// This creates the install step and adds it to the dependencies of the
/// top-level install step, using all the default options.
/// See `addInstallArtifact` for a more flexible function.
pub fn installArtifact(b: *Build, artifact: *Step.Compile) void {
    b.getInstallStep().dependOn(&b.addInstallArtifact(artifact, .{}).step);
}

/// This merely creates the step; it does not add it to the dependencies of the
/// top-level install step.
pub fn addInstallArtifact(
    b: *Build,
    artifact: *Step.Compile,
    options: Step.InstallArtifact.Options,
) *Step.InstallArtifact {
    return Step.InstallArtifact.create(b, artifact, options);
}

///`dest_rel_path` is relative to prefix path
pub fn installFile(b: *Build, src_path: []const u8, dest_rel_path: []const u8) void {
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(b.path(src_path), .prefix, dest_rel_path).step);
}

pub fn installDirectory(b: *Build, options: Step.InstallDir.Options) void {
    b.getInstallStep().dependOn(&b.addInstallDirectory(options).step);
}

///`dest_rel_path` is relative to bin path
pub fn installBinFile(b: *Build, src_path: []const u8, dest_rel_path: []const u8) void {
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(b.path(src_path), .bin, dest_rel_path).step);
}

///`dest_rel_path` is relative to lib path
pub fn installLibFile(b: *Build, src_path: []const u8, dest_rel_path: []const u8) void {
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(b.path(src_path), .lib, dest_rel_path).step);
}

pub fn addObjCopy(b: *Build, source: LazyPath, options: Step.ObjCopy.Options) *Step.ObjCopy {
    return Step.ObjCopy.create(b, source, options);
}

/// `dest_rel_path` is relative to install prefix path
pub fn addInstallFile(b: *Build, source: LazyPath, dest_rel_path: []const u8) *Step.InstallFile {
    return b.addInstallFileWithDir(source, .prefix, dest_rel_path);
}

/// `dest_rel_path` is relative to bin path
pub fn addInstallBinFile(b: *Build, source: LazyPath, dest_rel_path: []const u8) *Step.InstallFile {
    return b.addInstallFileWithDir(source, .bin, dest_rel_path);
}

/// `dest_rel_path` is relative to lib path
pub fn addInstallLibFile(b: *Build, source: LazyPath, dest_rel_path: []const u8) *Step.InstallFile {
    return b.addInstallFileWithDir(source, .lib, dest_rel_path);
}

/// `dest_rel_path` is relative to header path
pub fn addInstallHeaderFile(b: *Build, source: LazyPath, dest_rel_path: []const u8) *Step.InstallFile {
    return b.addInstallFileWithDir(source, .header, dest_rel_path);
}

pub fn addInstallFileWithDir(
    b: *Build,
    source: LazyPath,
    install_dir: InstallDir,
    dest_rel_path: []const u8,
) *Step.InstallFile {
    return Step.InstallFile.create(b, source, install_dir, dest_rel_path);
}

pub fn addInstallDirectory(b: *Build, options: Step.InstallDir.Options) *Step.InstallDir {
    return Step.InstallDir.create(b, options);
}

pub fn addCheckFile(
    b: *Build,
    file_source: LazyPath,
    options: Step.CheckFile.Options,
) *Step.CheckFile {
    return Step.CheckFile.create(b, file_source, options);
}

pub fn truncateFile(b: *Build, dest_path: []const u8) (fs.Dir.MakeError || fs.Dir.StatFileError)!void {
    if (b.verbose) {
        log.info("truncate {s}", .{dest_path});
    }
    const cwd = fs.cwd();
    var src_file = cwd.createFile(dest_path, .{}) catch |err| switch (err) {
        error.FileNotFound => blk: {
            if (fs.path.dirname(dest_path)) |dirname| {
                try cwd.makePath(dirname);
            }
            break :blk try cwd.createFile(dest_path, .{});
        },
        else => |e| return e,
    };
    src_file.close();
}

/// References a file or directory relative to the source root.
pub fn path(b: *Build, sub_path: []const u8) LazyPath {
    if (fs.path.isAbsolute(sub_path)) {
        std.debug.panic("sub_path is expected to be relative to the build root, but was this absolute path: '{s}'. It is best avoid absolute paths, but if you must, it is supported by LazyPath.cwd_relative", .{
            sub_path,
        });
    }
    return .{ .src_path = .{
        .owner = b,
        .sub_path = sub_path,
    } };
}

/// This is low-level implementation details of the build system, not meant to
/// be called by users' build scripts. Even in the build system itself it is a
/// code smell to call this function.
pub fn pathFromRoot(b: *Build, sub_path: []const u8) []u8 {
    return b.pathResolve(&.{ b.build_root.path orelse ".", sub_path });
}

fn pathFromCwd(b: *Build, sub_path: []const u8) []u8 {
    const cwd = process.getCwdAlloc(b.allocator) catch @panic("OOM");
    return b.pathResolve(&.{ cwd, sub_path });
}

pub fn pathJoin(b: *Build, paths: []const []const u8) []u8 {
    return fs.path.join(b.allocator, paths) catch @panic("OOM");
}

pub fn pathResolve(b: *Build, paths: []const []const u8) []u8 {
    return fs.path.resolve(b.allocator, paths) catch @panic("OOM");
}

pub fn fmt(b: *Build, comptime format: []const u8, args: anytype) []u8 {
    return std.fmt.allocPrint(b.allocator, format, args) catch @panic("OOM");
}

fn supportedWindowsProgramExtension(ext: []const u8) bool {
    inline for (@typeInfo(std.process.Child.WindowsExtension).@"enum".fields) |field| {
        if (std.ascii.eqlIgnoreCase(ext, "." ++ field.name)) return true;
    }
    return false;
}

fn tryFindProgram(b: *Build, full_path: []const u8) ?[]const u8 {
    if (fs.realpathAlloc(b.allocator, full_path)) |p| {
        return p;
    } else |err| switch (err) {
        error.OutOfMemory => @panic("OOM"),
        else => {},
    }

    if (builtin.os.tag == .windows) {
        if (b.graph.env_map.get("PATHEXT")) |PATHEXT| {
            var it = mem.tokenizeScalar(u8, PATHEXT, fs.path.delimiter);

            while (it.next()) |ext| {
                if (!supportedWindowsProgramExtension(ext)) continue;

                return fs.realpathAlloc(b.allocator, b.fmt("{s}{s}", .{ full_path, ext })) catch |err| switch (err) {
                    error.OutOfMemory => @panic("OOM"),
                    else => continue,
                };
            }
        }
    }

    return null;
}

pub fn findProgram(b: *Build, names: []const []const u8, paths: []const []const u8) error{FileNotFound}![]const u8 {
    // TODO report error for ambiguous situations
    for (b.search_prefixes.items) |search_prefix| {
        for (names) |name| {
            if (fs.path.isAbsolute(name)) {
                return name;
            }
            return tryFindProgram(b, b.pathJoin(&.{ search_prefix, "bin", name })) orelse continue;
        }
    }
    if (b.graph.env_map.get("PATH")) |PATH| {
        for (names) |name| {
            if (fs.path.isAbsolute(name)) {
                return name;
            }
            var it = mem.tokenizeScalar(u8, PATH, fs.path.delimiter);
            while (it.next()) |p| {
                return tryFindProgram(b, b.pathJoin(&.{ p, name })) orelse continue;
            }
        }
    }
    for (names) |name| {
        if (fs.path.isAbsolute(name)) {
            return name;
        }
        for (paths) |p| {
            return tryFindProgram(b, b.pathJoin(&.{ p, name })) orelse continue;
        }
    }
    return error.FileNotFound;
}

pub fn runAllowFail(
    b: *Build,
    argv: []const []const u8,
    out_code: *u8,
    stderr_behavior: std.process.Child.StdIo,
) RunError![]u8 {
    assert(argv.len != 0);

    if (!process.can_spawn)
        return error.ExecNotSupported;

    const max_output_size = 400 * 1024;
    var child = std.process.Child.init(argv, b.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = stderr_behavior;
    child.env_map = &b.graph.env_map;

    try Step.handleVerbose2(b, null, child.env_map, argv);
    try child.spawn();

    const stdout = child.stdout.?.reader().readAllAlloc(b.allocator, max_output_size) catch {
        return error.ReadFailure;
    };
    errdefer b.allocator.free(stdout);

    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                out_code.* = @as(u8, @truncate(code));
                return error.ExitCodeFailure;
            }
            return stdout;
        },
        .Signal, .Stopped, .Unknown => |code| {
            out_code.* = @as(u8, @truncate(code));
            return error.ProcessTerminated;
        },
    }
}

/// This is a helper function to be called from build.zig scripts, *not* from
/// inside step make() functions. If any errors occur, it fails the build with
/// a helpful message.
pub fn run(b: *Build, argv: []const []const u8) []u8 {
    if (!process.can_spawn) {
        std.debug.print("unable to spawn the following command: cannot spawn child process\n{s}\n", .{
            try allocPrintCmd(b.allocator, null, argv),
        });
        process.exit(1);
    }

    var code: u8 = undefined;
    return b.runAllowFail(argv, &code, .Inherit) catch |err| {
        const printed_cmd = allocPrintCmd(b.allocator, null, argv) catch @panic("OOM");
        std.debug.print("unable to spawn the following command: {s}\n{s}\n", .{
            @errorName(err), printed_cmd,
        });
        process.exit(1);
    };
}

pub fn addSearchPrefix(b: *Build, search_prefix: []const u8) void {
    b.search_prefixes.append(b.allocator, b.dupePath(search_prefix)) catch @panic("OOM");
}

pub fn getInstallPath(b: *Build, dir: InstallDir, dest_rel_path: []const u8) []const u8 {
    assert(!fs.path.isAbsolute(dest_rel_path)); // Install paths must be relative to the prefix
    const base_dir = switch (dir) {
        .prefix => b.install_path,
        .bin => b.exe_dir,
        .lib => b.lib_dir,
        .header => b.h_dir,
        .custom => |p| b.pathJoin(&.{ b.install_path, p }),
    };
    return b.pathResolve(&.{ base_dir, dest_rel_path });
}

pub const Dependency = struct {
    builder: *Build,

    pub fn artifact(d: *Dependency, name: []const u8) *Step.Compile {
        var found: ?*Step.Compile = null;
        for (d.builder.install_tls.step.dependencies.items) |dep_step| {
            const inst = dep_step.cast(Step.InstallArtifact) orelse continue;
            if (mem.eql(u8, inst.artifact.name, name)) {
                if (found != null) panic("artifact name '{s}' is ambiguous", .{name});
                found = inst.artifact;
            }
        }
        return found orelse {
            for (d.builder.install_tls.step.dependencies.items) |dep_step| {
                const inst = dep_step.cast(Step.InstallArtifact) orelse continue;
                log.info("available artifact: '{s}'", .{inst.artifact.name});
            }
            panic("unable to find artifact '{s}'", .{name});
        };
    }

    pub fn module(d: *Dependency, name: []const u8) *Module {
        return d.builder.modules.get(name) orelse {
            panic("unable to find module '{s}'", .{name});
        };
    }

    pub fn namedWriteFiles(d: *Dependency, name: []const u8) *Step.WriteFile {
        return d.builder.named_writefiles.get(name) orelse {
            panic("unable to find named writefiles '{s}'", .{name});
        };
    }

    pub fn namedLazyPath(d: *Dependency, name: []const u8) LazyPath {
        return d.builder.named_lazy_paths.get(name) orelse {
            panic("unable to find named lazypath '{s}'", .{name});
        };
    }

    pub fn path(d: *Dependency, sub_path: []const u8) LazyPath {
        return .{
            .dependency = .{
                .dependency = d,
                .sub_path = sub_path,
            },
        };
    }
};

fn findPkgHashOrFatal(b: *Build, name: []const u8) []const u8 {
    for (b.available_deps) |dep| {
        if (mem.eql(u8, dep[0], name)) return dep[1];
    }

    const full_path = b.pathFromRoot("build.zig.zon");
    std.debug.panic("no dependency named '{s}' in '{s}'. All packages used in build.zig must be declared in this file", .{ name, full_path });
}

inline fn findImportPkgHashOrFatal(b: *Build, comptime asking_build_zig: type, comptime dep_name: []const u8) []const u8 {
    const build_runner = @import("root");
    const deps = build_runner.dependencies;

    const b_pkg_hash, const b_pkg_deps = comptime for (@typeInfo(deps.packages).@"struct".decls) |decl| {
        const pkg_hash = decl.name;
        const pkg = @field(deps.packages, pkg_hash);
        if (@hasDecl(pkg, "build_zig") and pkg.build_zig == asking_build_zig) break .{ pkg_hash, pkg.deps };
    } else .{ "", deps.root_deps };
    if (!std.mem.eql(u8, b_pkg_hash, b.pkg_hash)) {
        std.debug.panic("'{}' is not the struct that corresponds to '{s}'", .{ asking_build_zig, b.pathFromRoot("build.zig") });
    }
    comptime for (b_pkg_deps) |dep| {
        if (std.mem.eql(u8, dep[0], dep_name)) return dep[1];
    };

    const full_path = b.pathFromRoot("build.zig.zon");
    std.debug.panic("no dependency named '{s}' in '{s}'. All packages used in build.zig must be declared in this file", .{ dep_name, full_path });
}

fn markNeededLazyDep(b: *Build, pkg_hash: []const u8) void {
    b.graph.needed_lazy_dependencies.put(b.graph.arena, pkg_hash, {}) catch @panic("OOM");
}

/// When this function is called, it means that the current build does, in
/// fact, require this dependency. If the dependency is already fetched, it
/// proceeds in the same manner as `dependency`. However if the dependency was
/// not fetched, then when the build script is finished running, the build will
/// not proceed to the make phase. Instead, the parent process will
/// additionally fetch all the lazy dependencies that were actually required by
/// running the build script, rebuild the build script, and then run it again.
/// In other words, if this function returns `null` it means that the only
/// purpose of completing the configure phase is to find out all the other lazy
/// dependencies that are also required.
/// It is allowed to use this function for non-lazy dependencies, in which case
/// it will never return `null`. This allows toggling laziness via
/// build.zig.zon without changing build.zig logic.
pub fn lazyDependency(b: *Build, name: []const u8, args: anytype) ?*Dependency {
    const build_runner = @import("root");
    const deps = build_runner.dependencies;
    const pkg_hash = findPkgHashOrFatal(b, name);

    inline for (@typeInfo(deps.packages).@"struct".decls) |decl| {
        if (mem.eql(u8, decl.name, pkg_hash)) {
            const pkg = @field(deps.packages, decl.name);
            const available = !@hasDecl(pkg, "available") or pkg.available;
            if (!available) {
                markNeededLazyDep(b, pkg_hash);
                return null;
            }
            return dependencyInner(b, name, pkg.build_root, if (@hasDecl(pkg, "build_zig")) pkg.build_zig else null, pkg_hash, pkg.deps, args);
        }
    }

    unreachable; // Bad @dependencies source
}

pub fn dependency(b: *Build, name: []const u8, args: anytype) *Dependency {
    const build_runner = @import("root");
    const deps = build_runner.dependencies;
    const pkg_hash = findPkgHashOrFatal(b, name);

    inline for (@typeInfo(deps.packages).@"struct".decls) |decl| {
        if (mem.eql(u8, decl.name, pkg_hash)) {
            const pkg = @field(deps.packages, decl.name);
            if (@hasDecl(pkg, "available")) {
                std.debug.panic("dependency '{s}{s}' is marked as lazy in build.zig.zon which means it must use the lazyDependency function instead", .{ b.dep_prefix, name });
            }
            return dependencyInner(b, name, pkg.build_root, if (@hasDecl(pkg, "build_zig")) pkg.build_zig else null, pkg_hash, pkg.deps, args);
        }
    }

    unreachable; // Bad @dependencies source
}

/// In a build.zig file, this function is to `@import` what `lazyDependency` is to `dependency`.
/// If the dependency is lazy and has not yet been fetched, it instructs the parent process to fetch
/// that dependency after the build script has finished running, then returns `null`.
/// If the dependency is lazy but has already been fetched, or if it is eager, it returns
/// the build.zig struct of that dependency, just like a regular `@import`.
pub inline fn lazyImport(
    b: *Build,
    /// The build.zig struct of the package importing the dependency.
    /// When calling this function from the `build` function of a build.zig file's, you normally
    /// pass `@This()`.
    comptime asking_build_zig: type,
    comptime dep_name: []const u8,
) ?type {
    const build_runner = @import("root");
    const deps = build_runner.dependencies;
    const pkg_hash = findImportPkgHashOrFatal(b, asking_build_zig, dep_name);

    inline for (@typeInfo(deps.packages).@"struct".decls) |decl| {
        if (comptime mem.eql(u8, decl.name, pkg_hash)) {
            const pkg = @field(deps.packages, decl.name);
            const available = !@hasDecl(pkg, "available") or pkg.available;
            if (!available) {
                markNeededLazyDep(b, pkg_hash);
                return null;
            }
            return if (@hasDecl(pkg, "build_zig"))
                pkg.build_zig
            else
                @compileError("dependency '" ++ dep_name ++ "' does not have a build.zig");
        }
    }

    comptime unreachable; // Bad @dependencies source
}

pub fn dependencyFromBuildZig(
    b: *Build,
    /// The build.zig struct of the dependency, normally obtained by `@import` of the dependency.
    /// If called from the build.zig file itself, use `@This` to obtain a reference to the struct.
    comptime build_zig: type,
    args: anytype,
) *Dependency {
    const build_runner = @import("root");
    const deps = build_runner.dependencies;

    find_dep: {
        const pkg, const pkg_hash = inline for (@typeInfo(deps.packages).@"struct".decls) |decl| {
            const pkg_hash = decl.name;
            const pkg = @field(deps.packages, pkg_hash);
            if (@hasDecl(pkg, "build_zig") and pkg.build_zig == build_zig) break .{ pkg, pkg_hash };
        } else break :find_dep;
        const dep_name = for (b.available_deps) |dep| {
            if (mem.eql(u8, dep[1], pkg_hash)) break dep[1];
        } else break :find_dep;
        return dependencyInner(b, dep_name, pkg.build_root, pkg.build_zig, pkg_hash, pkg.deps, args);
    }

    const full_path = b.pathFromRoot("build.zig.zon");
    debug.panic("'{}' is not a build.zig struct of a dependency in '{s}'", .{ build_zig, full_path });
}

fn userValuesAreSame(lhs: UserValue, rhs: UserValue) bool {
    if (std.meta.activeTag(lhs) != rhs) return false;
    switch (lhs) {
        .flag => {},
        .scalar => |lhs_scalar| {
            const rhs_scalar = rhs.scalar;

            if (!std.mem.eql(u8, lhs_scalar, rhs_scalar))
                return false;
        },
        .list => |lhs_list| {
            const rhs_list = rhs.list;

            if (lhs_list.items.len != rhs_list.items.len)
                return false;

            for (lhs_list.items, rhs_list.items) |lhs_list_entry, rhs_list_entry| {
                if (!std.mem.eql(u8, lhs_list_entry, rhs_list_entry))
                    return false;
            }
        },
        .map => |lhs_map| {
            const rhs_map = rhs.map;

            if (lhs_map.count() != rhs_map.count())
                return false;

            var lhs_it = lhs_map.iterator();
            while (lhs_it.next()) |lhs_entry| {
                const rhs_value = rhs_map.get(lhs_entry.key_ptr.*) orelse return false;
                if (!userValuesAreSame(lhs_entry.value_ptr.*.*, rhs_value.*))
                    return false;
            }
        },
        .lazy_path => |lhs_lp| {
            const rhs_lp = rhs.lazy_path;
            return userLazyPathsAreTheSame(lhs_lp, rhs_lp);
        },
        .lazy_path_list => |lhs_lp_list| {
            const rhs_lp_list = rhs.lazy_path_list;
            if (lhs_lp_list.items.len != rhs_lp_list.items.len) return false;
            for (lhs_lp_list.items, rhs_lp_list.items) |lhs_lp, rhs_lp| {
                if (!userLazyPathsAreTheSame(lhs_lp, rhs_lp)) return false;
            }
            return true;
        },
    }

    return true;
}

fn userLazyPathsAreTheSame(lhs_lp: LazyPath, rhs_lp: LazyPath) bool {
    if (std.meta.activeTag(lhs_lp) != rhs_lp) return false;
    switch (lhs_lp) {
        .src_path => |lhs_sp| {
            const rhs_sp = rhs_lp.src_path;

            if (lhs_sp.owner != rhs_sp.owner) return false;
            if (std.mem.eql(u8, lhs_sp.sub_path, rhs_sp.sub_path)) return false;
        },
        .generated => |lhs_gen| {
            const rhs_gen = rhs_lp.generated;

            if (lhs_gen.file != rhs_gen.file) return false;
            if (lhs_gen.up != rhs_gen.up) return false;
            if (std.mem.eql(u8, lhs_gen.sub_path, rhs_gen.sub_path)) return false;
        },
        .cwd_relative => |lhs_rel_path| {
            const rhs_rel_path = rhs_lp.cwd_relative;

            if (!std.mem.eql(u8, lhs_rel_path, rhs_rel_path)) return false;
        },
        .dependency => |lhs_dep| {
            const rhs_dep = rhs_lp.dependency;

            if (lhs_dep.dependency != rhs_dep.dependency) return false;
            if (!std.mem.eql(u8, lhs_dep.sub_path, rhs_dep.sub_path)) return false;
        },
    }
    return true;
}

fn dependencyInner(
    b: *Build,
    name: []const u8,
    build_root_string: []const u8,
    comptime build_zig: ?type,
    pkg_hash: []const u8,
    pkg_deps: AvailableDeps,
    args: anytype,
) *Dependency {
    const user_input_options = userInputOptionsFromArgs(b.allocator, args);
    if (b.graph.dependency_cache.getContext(.{
        .build_root_string = build_root_string,
        .user_input_options = user_input_options,
    }, .{ .allocator = b.graph.arena })) |dep|
        return dep;

    const build_root: std.Build.Cache.Directory = .{
        .path = build_root_string,
        .handle = fs.cwd().openDir(build_root_string, .{}) catch |err| {
            std.debug.print("unable to open '{s}': {s}\n", .{
                build_root_string, @errorName(err),
            });
            process.exit(1);
        },
    };

    const sub_builder = b.createChild(name, build_root, pkg_hash, pkg_deps, user_input_options) catch @panic("unhandled error");
    if (build_zig) |bz| {
        sub_builder.runBuild(bz) catch @panic("unhandled error");

        if (sub_builder.validateUserInputDidItFail()) {
            std.debug.dumpCurrentStackTrace(@returnAddress());
        }
    }

    const dep = b.allocator.create(Dependency) catch @panic("OOM");
    dep.* = .{ .builder = sub_builder };

    b.graph.dependency_cache.putContext(b.graph.arena, .{
        .build_root_string = build_root_string,
        .user_input_options = user_input_options,
    }, dep, .{ .allocator = b.graph.arena }) catch @panic("OOM");
    return dep;
}

pub fn runBuild(b: *Build, build_zig: anytype) anyerror!void {
    switch (@typeInfo(@typeInfo(@TypeOf(build_zig.build)).@"fn".return_type.?)) {
        .void => build_zig.build(b),
        .error_union => try build_zig.build(b),
        else => @compileError("expected return type of build to be 'void' or '!void'"),
    }
}

/// A file that is generated by a build step.
/// This struct is an interface that is meant to be used with `@fieldParentPtr` to implement the actual path logic.
pub const GeneratedFile = struct {
    /// The step that generates the file
    step: *Step,

    /// The path to the generated file. Must be either absolute or relative to the build root.
    /// This value must be set in the `fn make()` of the `step` and must not be `null` afterwards.
    path: ?[]const u8 = null,

    pub fn getPath(gen: GeneratedFile) []const u8 {
        return gen.step.owner.pathFromRoot(gen.path orelse std.debug.panic(
            "getPath() was called on a GeneratedFile that wasn't built yet. Is there a missing Step dependency on step '{s}'?",
            .{gen.step.name},
        ));
    }
};

// dirnameAllowEmpty is a variant of fs.path.dirname
// that allows "" to refer to the root for relative paths.
//
// For context, dirname("foo") and dirname("") are both null.
// However, for relative paths, we want dirname("foo") to be ""
// so that we can join it with another path (e.g. build root, cache root, etc.)
//
// dirname("") should still be null, because we can't go up any further.
fn dirnameAllowEmpty(full_path: []const u8) ?[]const u8 {
    return fs.path.dirname(full_path) orelse {
        if (fs.path.isAbsolute(full_path) or full_path.len == 0) return null;

        return "";
    };
}

test dirnameAllowEmpty {
    try std.testing.expectEqualStrings(
        "foo",
        dirnameAllowEmpty("foo" ++ fs.path.sep_str ++ "bar") orelse @panic("unexpected null"),
    );

    try std.testing.expectEqualStrings(
        "",
        dirnameAllowEmpty("foo") orelse @panic("unexpected null"),
    );

    try std.testing.expect(dirnameAllowEmpty("") == null);
}

/// A reference to an existing or future path.
pub const LazyPath = union(enum) {
    /// A source file path relative to build root.
    src_path: struct {
        owner: *std.Build,
        sub_path: []const u8,
    },

    generated: struct {
        file: *const GeneratedFile,

        /// The number of parent directories to go up.
        /// 0 means the generated file itself.
        /// 1 means the directory of the generated file.
        /// 2 means the parent of that directory, and so on.
        up: usize = 0,

        /// Applied after `up`.
        sub_path: []const u8 = "",
    },

    /// An absolute path or a path relative to the current working directory of
    /// the build runner process.
    /// This is uncommon but used for system environment paths such as `--zig-lib-dir` which
    /// ignore the file system path of build.zig and instead are relative to the directory from
    /// which `zig build` was invoked.
    /// Use of this tag indicates a dependency on the host system.
    cwd_relative: []const u8,

    dependency: struct {
        dependency: *Dependency,
        sub_path: []const u8,
    },

    /// Returns a lazy path referring to the directory containing this path.
    ///
    /// The dirname is not allowed to escape the logical root for underlying path.
    /// For example, if the path is relative to the build root,
    /// the dirname is not allowed to traverse outside of the build root.
    /// Similarly, if the path is a generated file inside zig-cache,
    /// the dirname is not allowed to traverse outside of zig-cache.
    pub fn dirname(lazy_path: LazyPath) LazyPath {
        return switch (lazy_path) {
            .src_path => |sp| .{ .src_path = .{
                .owner = sp.owner,
                .sub_path = dirnameAllowEmpty(sp.sub_path) orelse {
                    dumpBadDirnameHelp(null, null, "dirname() attempted to traverse outside the build root\n", .{}) catch {};
                    @panic("misconfigured build script");
                },
            } },
            .generated => |generated| .{ .generated = if (dirnameAllowEmpty(generated.sub_path)) |sub_dirname| .{
                .file = generated.file,
                .up = generated.up,
                .sub_path = sub_dirname,
            } else .{
                .file = generated.file,
                .up = generated.up + 1,
                .sub_path = "",
            } },
            .cwd_relative => |rel_path| .{
                .cwd_relative = dirnameAllowEmpty(rel_path) orelse {
                    // If we get null, it means one of two things:
                    // - rel_path was absolute, and is now root
                    // - rel_path was relative, and is now ""
                    // In either case, the build script tried to go too far
                    // and we should panic.
                    if (fs.path.isAbsolute(rel_path)) {
                        dumpBadDirnameHelp(null, null,
                            \\dirname() attempted to traverse outside the root.
                            \\No more directories left to go up.
                            \\
                        , .{}) catch {};
                        @panic("misconfigured build script");
                    } else {
                        dumpBadDirnameHelp(null, null,
                            \\dirname() attempted to traverse outside the current working directory.
                            \\
                        , .{}) catch {};
                        @panic("misconfigured build script");
                    }
                },
            },
            .dependency => |dep| .{ .dependency = .{
                .dependency = dep.dependency,
                .sub_path = dirnameAllowEmpty(dep.sub_path) orelse {
                    dumpBadDirnameHelp(null, null,
                        \\dirname() attempted to traverse outside the dependency root.
                        \\
                    , .{}) catch {};
                    @panic("misconfigured build script");
                },
            } },
        };
    }

    pub fn path(lazy_path: LazyPath, b: *Build, sub_path: []const u8) LazyPath {
        return lazy_path.join(b.allocator, sub_path) catch @panic("OOM");
    }

    pub fn join(lazy_path: LazyPath, arena: Allocator, sub_path: []const u8) Allocator.Error!LazyPath {
        return switch (lazy_path) {
            .src_path => |src| .{ .src_path = .{
                .owner = src.owner,
                .sub_path = try fs.path.resolve(arena, &.{ src.sub_path, sub_path }),
            } },
            .generated => |gen| .{ .generated = .{
                .file = gen.file,
                .up = gen.up,
                .sub_path = try fs.path.resolve(arena, &.{ gen.sub_path, sub_path }),
            } },
            .cwd_relative => |cwd_relative| .{
                .cwd_relative = try fs.path.resolve(arena, &.{ cwd_relative, sub_path }),
            },
            .dependency => |dep| .{ .dependency = .{
                .dependency = dep.dependency,
                .sub_path = try fs.path.resolve(arena, &.{ dep.sub_path, sub_path }),
            } },
        };
    }

    /// Returns a string that can be shown to represent the file source.
    /// Either returns the path, `"generated"`, or `"dependency"`.
    pub fn getDisplayName(lazy_path: LazyPath) []const u8 {
        return switch (lazy_path) {
            .src_path => |sp| sp.sub_path,
            .cwd_relative => |p| p,
            .generated => "generated",
            .dependency => "dependency",
        };
    }

    /// Adds dependencies this file source implies to the given step.
    pub fn addStepDependencies(lazy_path: LazyPath, other_step: *Step) void {
        switch (lazy_path) {
            .src_path, .cwd_relative, .dependency => {},
            .generated => |gen| other_step.dependOn(gen.file.step),
        }
    }

    /// Deprecated, see `getPath3`.
    pub fn getPath(lazy_path: LazyPath, src_builder: *Build) []const u8 {
        return getPath2(lazy_path, src_builder, null);
    }

    /// Deprecated, see `getPath3`.
    pub fn getPath2(lazy_path: LazyPath, src_builder: *Build, asking_step: ?*Step) []const u8 {
        const p = getPath3(lazy_path, src_builder, asking_step);
        return src_builder.pathResolve(&.{ p.root_dir.path orelse ".", p.sub_path });
    }

    /// Intended to be used during the make phase only.
    ///
    /// `asking_step` is only used for debugging purposes; it's the step being
    /// run that is asking for the path.
    pub fn getPath3(lazy_path: LazyPath, src_builder: *Build, asking_step: ?*Step) Cache.Path {
        switch (lazy_path) {
            .src_path => |sp| return .{
                .root_dir = sp.owner.build_root,
                .sub_path = sp.sub_path,
            },
            .cwd_relative => |sub_path| return .{
                .root_dir = Cache.Directory.cwd(),
                .sub_path = sub_path,
            },
            .generated => |gen| {
                // TODO make gen.file.path not be absolute and use that as the
                // basis for not traversing up too many directories.

                var file_path: Cache.Path = .{
                    .root_dir = Cache.Directory.cwd(),
                    .sub_path = gen.file.path orelse {
                        std.debug.lockStdErr();
                        const stderr = std.io.getStdErr();
                        dumpBadGetPathHelp(gen.file.step, stderr, src_builder, asking_step) catch {};
                        std.debug.unlockStdErr();
                        @panic("misconfigured build script");
                    },
                };

                if (gen.up > 0) {
                    const cache_root_path = src_builder.cache_root.path orelse
                        (src_builder.cache_root.join(src_builder.allocator, &.{"."}) catch @panic("OOM"));

                    for (0..gen.up) |_| {
                        if (mem.eql(u8, file_path.sub_path, cache_root_path)) {
                            // If we hit the cache root and there's still more to go,
                            // the script attempted to go too far.
                            dumpBadDirnameHelp(gen.file.step, asking_step,
                                \\dirname() attempted to traverse outside the cache root.
                                \\This is not allowed.
                                \\
                            , .{}) catch {};
                            @panic("misconfigured build script");
                        }

                        // path is absolute.
                        // dirname will return null only if we're at root.
                        // Typically, we'll stop well before that at the cache root.
                        file_path.sub_path = fs.path.dirname(file_path.sub_path) orelse {
                            dumpBadDirnameHelp(gen.file.step, asking_step,
                                \\dirname() reached root.
                                \\No more directories left to go up.
                                \\
                            , .{}) catch {};
                            @panic("misconfigured build script");
                        };
                    }
                }

                return file_path.join(src_builder.allocator, gen.sub_path) catch @panic("OOM");
            },
            .dependency => |dep| return .{
                .root_dir = dep.dependency.builder.build_root,
                .sub_path = dep.sub_path,
            },
        }
    }

    /// Copies the internal strings.
    ///
    /// The `b` parameter is only used for its allocator. All *Build instances
    /// share the same allocator.
    pub fn dupe(lazy_path: LazyPath, b: *Build) LazyPath {
        return lazy_path.dupeInner(b.allocator);
    }

    fn dupeInner(lazy_path: LazyPath, allocator: std.mem.Allocator) LazyPath {
        return switch (lazy_path) {
            .src_path => |sp| .{ .src_path = .{
                .owner = sp.owner,
                .sub_path = sp.owner.dupePath(sp.sub_path),
            } },
            .cwd_relative => |p| .{ .cwd_relative = dupePathInner(allocator, p) },
            .generated => |gen| .{ .generated = .{
                .file = gen.file,
                .up = gen.up,
                .sub_path = dupePathInner(allocator, gen.sub_path),
            } },
            .dependency => |dep| .{ .dependency = dep },
        };
    }
};

fn dumpBadDirnameHelp(
    fail_step: ?*Step,
    asking_step: ?*Step,
    comptime msg: []const u8,
    args: anytype,
) anyerror!void {
    debug.lockStdErr();
    defer debug.unlockStdErr();

    const stderr = io.getStdErr();
    const w = stderr.writer();
    try w.print(msg, args);

    const tty_config = std.io.tty.detectConfig(stderr);

    if (fail_step) |s| {
        tty_config.setColor(w, .red) catch {};
        try stderr.writeAll("    The step was created by this stack trace:\n");
        tty_config.setColor(w, .reset) catch {};

        s.dump(stderr);
    }

    if (asking_step) |as| {
        tty_config.setColor(w, .red) catch {};
        try stderr.writer().print("    The step '{s}' that is missing a dependency on the above step was created by this stack trace:\n", .{as.name});
        tty_config.setColor(w, .reset) catch {};

        as.dump(stderr);
    }

    tty_config.setColor(w, .red) catch {};
    try stderr.writeAll("    Hope that helps. Proceeding to panic.\n");
    tty_config.setColor(w, .reset) catch {};
}

/// In this function the stderr mutex has already been locked.
pub fn dumpBadGetPathHelp(
    s: *Step,
    stderr: fs.File,
    src_builder: *Build,
    asking_step: ?*Step,
) anyerror!void {
    const w = stderr.writer();
    try w.print(
        \\getPath() was called on a GeneratedFile that wasn't built yet.
        \\  source package path: {s}
        \\  Is there a missing Step dependency on step '{s}'?
        \\
    , .{
        src_builder.build_root.path orelse ".",
        s.name,
    });

    const tty_config = std.io.tty.detectConfig(stderr);
    tty_config.setColor(w, .red) catch {};
    try stderr.writeAll("    The step was created by this stack trace:\n");
    tty_config.setColor(w, .reset) catch {};

    s.dump(stderr);
    if (asking_step) |as| {
        tty_config.setColor(w, .red) catch {};
        try stderr.writer().print("    The step '{s}' that is missing a dependency on the above step was created by this stack trace:\n", .{as.name});
        tty_config.setColor(w, .reset) catch {};

        as.dump(stderr);
    }
    tty_config.setColor(w, .red) catch {};
    try stderr.writeAll("    Hope that helps. Proceeding to panic.\n");
    tty_config.setColor(w, .reset) catch {};
}

pub const InstallDir = union(enum) {
    prefix: void,
    lib: void,
    bin: void,
    header: void,
    /// A path relative to the prefix
    custom: []const u8,

    /// Duplicates the install directory including the path if set to custom.
    pub fn dupe(dir: InstallDir, builder: *Build) InstallDir {
        if (dir == .custom) {
            return .{ .custom = builder.dupe(dir.custom) };
        } else {
            return dir;
        }
    }
};

/// This function is intended to be called in the `configure` phase only.
/// It returns an absolute directory path, which is potentially going to be a
/// source of API breakage in the future, so keep that in mind when using this
/// function.
pub fn makeTempPath(b: *Build) []const u8 {
    const rand_int = std.crypto.random.int(u64);
    const tmp_dir_sub_path = "tmp" ++ fs.path.sep_str ++ std.fmt.hex(rand_int);
    const result_path = b.cache_root.join(b.allocator, &.{tmp_dir_sub_path}) catch @panic("OOM");
    b.cache_root.handle.makePath(tmp_dir_sub_path) catch |err| {
        std.debug.print("unable to make tmp path '{s}': {s}\n", .{
            result_path, @errorName(err),
        });
    };
    return result_path;
}

/// Deprecated; use `std.fmt.hex` instead.
pub fn hex64(x: u64) [16]u8 {
    return std.fmt.hex(x);
}

/// A pair of target query and fully resolved target.
/// This type is generally required by build system API that need to be given a
/// target. The query is kept because the Zig toolchain needs to know which parts
/// of the target are "native". This can apply to the CPU, the OS, or even the ABI.
pub const ResolvedTarget = struct {
    query: Target.Query,
    result: Target,
};

/// Converts a target query into a fully resolved target that can be passed to
/// various parts of the API.
pub fn resolveTargetQuery(b: *Build, query: Target.Query) ResolvedTarget {
    if (query.isNative()) {
        // Hot path. This is faster than querying the native CPU and OS again.
        return b.graph.host;
    }
    return .{
        .query = query,
        .result = std.zig.system.resolveTargetQuery(query) catch
            @panic("unable to resolve target query"),
    };
}

pub fn wantSharedLibSymLinks(target: Target) bool {
    return target.os.tag != .windows;
}

pub const SystemIntegrationOptionConfig = struct {
    /// If left as null, then the default will depend on system_package_mode.
    default: ?bool = null,
};

pub fn systemIntegrationOption(
    b: *Build,
    name: []const u8,
    config: SystemIntegrationOptionConfig,
) bool {
    const gop = b.graph.system_library_options.getOrPut(b.allocator, name) catch @panic("OOM");
    if (gop.found_existing) switch (gop.value_ptr.*) {
        .user_disabled => {
            gop.value_ptr.* = .declared_disabled;
            return false;
        },
        .user_enabled => {
            gop.value_ptr.* = .declared_enabled;
            return true;
        },
        .declared_disabled => return false,
        .declared_enabled => return true,
    } else {
        gop.key_ptr.* = b.dupe(name);
        if (config.default orelse b.graph.system_package_mode) {
            gop.value_ptr.* = .declared_enabled;
            return true;
        } else {
            gop.value_ptr.* = .declared_disabled;
            return false;
        }
    }
}

test {
    _ = Cache;
    _ = Step;
}
//! Manages `zig-cache` directories.
//! This is not a general-purpose cache. It is designed to be fast and simple,
//! not to withstand attacks using specially-crafted input.

gpa: Allocator,
manifest_dir: fs.Dir,
hash: HashHelper = .{},
/// This value is accessed from multiple threads, protected by mutex.
recent_problematic_timestamp: i128 = 0,
mutex: std.Thread.Mutex = .{},

/// A set of strings such as the zig library directory or project source root, which
/// are stripped from the file paths before putting into the cache. They
/// are replaced with single-character indicators. This is not to save
/// space but to eliminate absolute file paths. This improves portability
/// and usefulness of the cache for advanced use cases.
prefixes_buffer: [4]Directory = undefined,
prefixes_len: usize = 0,

pub const Path = @import("Cache/Path.zig");
pub const Directory = @import("Cache/Directory.zig");
pub const DepTokenizer = @import("Cache/DepTokenizer.zig");

const Cache = @This();
const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const fs = std.fs;
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const fmt = std.fmt;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.cache);

pub fn addPrefix(cache: *Cache, directory: Directory) void {
    cache.prefixes_buffer[cache.prefixes_len] = directory;
    cache.prefixes_len += 1;
}

/// Be sure to call `Manifest.deinit` after successful initialization.
pub fn obtain(cache: *Cache) Manifest {
    return .{
        .cache = cache,
        .hash = cache.hash,
        .manifest_file = null,
        .manifest_dirty = false,
        .hex_digest = undefined,
    };
}

pub fn prefixes(cache: *const Cache) []const Directory {
    return cache.prefixes_buffer[0..cache.prefixes_len];
}

const PrefixedPath = struct {
    prefix: u8,
    sub_path: []const u8,

    fn eql(a: PrefixedPath, b: PrefixedPath) bool {
        return a.prefix == b.prefix and std.mem.eql(u8, a.sub_path, b.sub_path);
    }

    fn hash(pp: PrefixedPath) u32 {
        return @truncate(std.hash.Wyhash.hash(pp.prefix, pp.sub_path));
    }
};

fn findPrefix(cache: *const Cache, file_path: []const u8) !PrefixedPath {
    const gpa = cache.gpa;
    const resolved_path = try fs.path.resolve(gpa, &[_][]const u8{file_path});
    errdefer gpa.free(resolved_path);
    return findPrefixResolved(cache, resolved_path);
}

/// Takes ownership of `resolved_path` on success.
fn findPrefixResolved(cache: *const Cache, resolved_path: []u8) !PrefixedPath {
    const gpa = cache.gpa;
    const prefixes_slice = cache.prefixes();
    var i: u8 = 1; // Start at 1 to skip over checking the null prefix.
    while (i < prefixes_slice.len) : (i += 1) {
        const p = prefixes_slice[i].path.?;
        const sub_path = getPrefixSubpath(gpa, p, resolved_path) catch |err| switch (err) {
            error.NotASubPath => continue,
            else => |e| return e,
        };
        // Free the resolved path since we're not going to return it
        gpa.free(resolved_path);
        return PrefixedPath{
            .prefix = i,
            .sub_path = sub_path,
        };
    }

    return PrefixedPath{
        .prefix = 0,
        .sub_path = resolved_path,
    };
}

fn getPrefixSubpath(allocator: Allocator, prefix: []const u8, path: []u8) ![]u8 {
    const relative = try fs.path.relative(allocator, prefix, path);
    errdefer allocator.free(relative);
    var component_iterator = fs.path.NativeComponentIterator.init(relative) catch {
        return error.NotASubPath;
    };
    if (component_iterator.root() != null) {
        return error.NotASubPath;
    }
    const first_component = component_iterator.first();
    if (first_component != null and std.mem.eql(u8, first_component.?.name, "..")) {
        return error.NotASubPath;
    }
    return relative;
}

/// This is 128 bits - Even with 2^54 cache entries, the probably of a collision would be under 10^-6
pub const bin_digest_len = 16;
pub const hex_digest_len = bin_digest_len * 2;
pub const BinDigest = [bin_digest_len]u8;
pub const HexDigest = [hex_digest_len]u8;

/// This is currently just an arbitrary non-empty string that can't match another manifest line.
const manifest_header = "0";
const manifest_file_size_max = 100 * 1024 * 1024;

/// The type used for hashing file contents. Currently, this is SipHash128(1, 3), because it
/// provides enough collision resistance for the Manifest use cases, while being one of our
/// fastest options right now.
pub const Hasher = crypto.auth.siphash.SipHash128(1, 3);

/// Initial state with random bytes, that can be copied.
/// Refresh this with new random bytes when the manifest
/// format is modified in a non-backwards-compatible way.
pub const hasher_init: Hasher = Hasher.init(&[_]u8{
    0x33, 0x52, 0xa2, 0x84,
    0xcf, 0x17, 0x56, 0x57,
    0x01, 0xbb, 0xcd, 0xe4,
    0x77, 0xd6, 0xf0, 0x60,
});

pub const File = struct {
    prefixed_path: PrefixedPath,
    max_file_size: ?usize,
    /// Populated if the user calls `addOpenedFile`.
    /// The handle is not owned here.
    handle: ?fs.File,
    stat: Stat,
    bin_digest: BinDigest,
    contents: ?[]const u8,

    pub const Stat = struct {
        inode: fs.File.INode,
        size: u64,
        mtime: i128,

        pub fn fromFs(fs_stat: fs.File.Stat) Stat {
            return .{
                .inode = fs_stat.inode,
                .size = fs_stat.size,
                .mtime = fs_stat.mtime,
            };
        }
    };

    pub fn deinit(self: *File, gpa: Allocator) void {
        gpa.free(self.prefixed_path.sub_path);
        if (self.contents) |contents| {
            gpa.free(contents);
            self.contents = null;
        }
        self.* = undefined;
    }

    pub fn updateMaxSize(file: *File, new_max_size: ?usize) void {
        const new = new_max_size orelse return;
        file.max_file_size = if (file.max_file_size) |old| @max(old, new) else new;
    }

    pub fn updateHandle(file: *File, new_handle: ?fs.File) void {
        const handle = new_handle orelse return;
        file.handle = handle;
    }
};

pub const HashHelper = struct {
    hasher: Hasher = hasher_init,

    /// Record a slice of bytes as a dependency of the process being cached.
    pub fn addBytes(hh: *HashHelper, bytes: []const u8) void {
        hh.hasher.update(mem.asBytes(&bytes.len));
        hh.hasher.update(bytes);
    }

    pub fn addOptionalBytes(hh: *HashHelper, optional_bytes: ?[]const u8) void {
        hh.add(optional_bytes != null);
        hh.addBytes(optional_bytes orelse return);
    }

    pub fn addListOfBytes(hh: *HashHelper, list_of_bytes: []const []const u8) void {
        hh.add(list_of_bytes.len);
        for (list_of_bytes) |bytes| hh.addBytes(bytes);
    }

    pub fn addOptionalListOfBytes(hh: *HashHelper, optional_list_of_bytes: ?[]const []const u8) void {
        hh.add(optional_list_of_bytes != null);
        hh.addListOfBytes(optional_list_of_bytes orelse return);
    }

    /// Convert the input value into bytes and record it as a dependency of the process being cached.
    pub fn add(hh: *HashHelper, x: anytype) void {
        switch (@TypeOf(x)) {
            std.SemanticVersion => {
                hh.add(x.major);
                hh.add(x.minor);
                hh.add(x.patch);
            },
            std.Target.Os.TaggedVersionRange => {
                switch (x) {
                    .hurd => |hurd| {
                        hh.add(hurd.range.min);
                        hh.add(hurd.range.max);
                        hh.add(hurd.glibc);
                    },
                    .linux => |linux| {
                        hh.add(linux.range.min);
                        hh.add(linux.range.max);
                        hh.add(linux.glibc);
                        hh.add(linux.android);
                    },
                    .windows => |windows| {
                        hh.add(windows.min);
                        hh.add(windows.max);
                    },
                    .semver => |semver| {
                        hh.add(semver.min);
                        hh.add(semver.max);
                    },
                    .none => {},
                }
            },
            std.zig.BuildId => switch (x) {
                .none, .fast, .uuid, .sha1, .md5 => hh.add(std.meta.activeTag(x)),
                .hexstring => |hex_string| hh.addBytes(hex_string.toSlice()),
            },
            else => switch (@typeInfo(@TypeOf(x))) {
                .bool, .int, .@"enum", .array => hh.addBytes(mem.asBytes(&x)),
                else => @compileError("unable to hash type " ++ @typeName(@TypeOf(x))),
            },
        }
    }

    pub fn addOptional(hh: *HashHelper, optional: anytype) void {
        hh.add(optional != null);
        hh.add(optional orelse return);
    }

    /// Returns a hex encoded hash of the inputs, without modifying state.
    pub fn peek(hh: HashHelper) [hex_digest_len]u8 {
        var copy = hh;
        return copy.final();
    }

    pub fn peekBin(hh: HashHelper) BinDigest {
        var copy = hh;
        var bin_digest: BinDigest = undefined;
        copy.hasher.final(&bin_digest);
        return bin_digest;
    }

    /// Returns a hex encoded hash of the inputs, mutating the state of the hasher.
    pub fn final(hh: *HashHelper) HexDigest {
        var bin_digest: BinDigest = undefined;
        hh.hasher.final(&bin_digest);
        return binToHex(bin_digest);
    }

    pub fn oneShot(bytes: []const u8) [hex_digest_len]u8 {
        var hasher: Hasher = hasher_init;
        hasher.update(bytes);
        var bin_digest: BinDigest = undefined;
        hasher.final(&bin_digest);
        return binToHex(bin_digest);
    }
};

pub fn binToHex(bin_digest: BinDigest) HexDigest {
    var out_digest: HexDigest = undefined;
    _ = fmt.bufPrint(
        &out_digest,
        "{s}",
        .{fmt.fmtSliceHexLower(&bin_digest)},
    ) catch unreachable;
    return out_digest;
}

pub const Lock = struct {
    manifest_file: fs.File,

    pub fn release(lock: *Lock) void {
        if (builtin.os.tag == .windows) {
            // Windows does not guarantee that locks are immediately unlocked when
            // the file handle is closed. See LockFileEx documentation.
            lock.manifest_file.unlock();
        }

        lock.manifest_file.close();
        lock.* = undefined;
    }
};

pub const Manifest = struct {
    cache: *Cache,
    /// Current state for incremental hashing.
    hash: HashHelper,
    manifest_file: ?fs.File,
    manifest_dirty: bool,
    /// Set this flag to true before calling hit() in order to indicate that
    /// upon a cache hit, the code using the cache will not modify the files
    /// within the cache directory. This allows multiple processes to utilize
    /// the same cache directory at the same time.
    want_shared_lock: bool = true,
    have_exclusive_lock: bool = false,
    // Indicate that we want isProblematicTimestamp to perform a filesystem write in
    // order to obtain a problematic timestamp for the next call. Calls after that
    // will then use the same timestamp, to avoid unnecessary filesystem writes.
    want_refresh_timestamp: bool = true,
    files: Files = .{},
    hex_digest: HexDigest,
    diagnostic: Diagnostic = .none,
    /// Keeps track of the last time we performed a file system write to observe
    /// what time the file system thinks it is, according to its own granularity.
    recent_problematic_timestamp: i128 = 0,

    pub const Diagnostic = union(enum) {
        none,
        manifest_create: fs.File.OpenError,
        manifest_read: fs.File.ReadError,
        manifest_lock: fs.File.LockError,
        manifest_seek: fs.File.SeekError,
        file_open: FileOp,
        file_stat: FileOp,
        file_read: FileOp,
        file_hash: FileOp,

        pub const FileOp = struct {
            file_index: usize,
            err: anyerror,
        };
    };

    pub const Files = std.ArrayHashMapUnmanaged(File, void, FilesContext, false);

    pub const FilesContext = struct {
        pub fn hash(fc: FilesContext, file: File) u32 {
            _ = fc;
            return file.prefixed_path.hash();
        }

        pub fn eql(fc: FilesContext, a: File, b: File, b_index: usize) bool {
            _ = fc;
            _ = b_index;
            return a.prefixed_path.eql(b.prefixed_path);
        }
    };

    const FilesAdapter = struct {
        pub fn eql(context: @This(), a: PrefixedPath, b: File, b_index: usize) bool {
            _ = context;
            _ = b_index;
            return a.eql(b.prefixed_path);
        }

        pub fn hash(context: @This(), key: PrefixedPath) u32 {
            _ = context;
            return key.hash();
        }
    };

    /// Add a file as a dependency of process being cached. When `hit` is
    /// called, the file's contents will be checked to ensure that it matches
    /// the contents from previous times.
    ///
    /// Max file size will be used to determine the amount of space the file contents
    /// are allowed to take up in memory. If max_file_size is null, then the contents
    /// will not be loaded into memory.
    ///
    /// Returns the index of the entry in the `files` array list. You can use it
    /// to access the contents of the file after calling `hit()` like so:
    ///
    /// ```
    /// var file_contents = cache_hash.files.keys()[file_index].contents.?;
    /// ```
    pub fn addFilePath(m: *Manifest, file_path: Path, max_file_size: ?usize) !usize {
        return addOpenedFile(m, file_path, null, max_file_size);
    }

    /// Same as `addFilePath` except the file has already been opened.
    pub fn addOpenedFile(m: *Manifest, path: Path, handle: ?fs.File, max_file_size: ?usize) !usize {
        const gpa = m.cache.gpa;
        try m.files.ensureUnusedCapacity(gpa, 1);
        const resolved_path = try fs.path.resolve(gpa, &.{
            path.root_dir.path orelse ".",
            path.subPathOrDot(),
        });
        errdefer gpa.free(resolved_path);
        const prefixed_path = try m.cache.findPrefixResolved(resolved_path);
        return addFileInner(m, prefixed_path, handle, max_file_size);
    }

    /// Deprecated; use `addFilePath`.
    pub fn addFile(self: *Manifest, file_path: []const u8, max_file_size: ?usize) !usize {
        assert(self.manifest_file == null);

        const gpa = self.cache.gpa;
        try self.files.ensureUnusedCapacity(gpa, 1);
        const prefixed_path = try self.cache.findPrefix(file_path);
        errdefer gpa.free(prefixed_path.sub_path);

        return addFileInner(self, prefixed_path, null, max_file_size);
    }

    fn addFileInner(self: *Manifest, prefixed_path: PrefixedPath, handle: ?fs.File, max_file_size: ?usize) usize {
        const gop = self.files.getOrPutAssumeCapacityAdapted(prefixed_path, FilesAdapter{});
        if (gop.found_existing) {
            gop.key_ptr.updateMaxSize(max_file_size);
            gop.key_ptr.updateHandle(handle);
            return gop.index;
        }
        gop.key_ptr.* = .{
            .prefixed_path = prefixed_path,
            .contents = null,
            .max_file_size = max_file_size,
            .stat = undefined,
            .bin_digest = undefined,
            .handle = handle,
        };

        self.hash.add(prefixed_path.prefix);
        self.hash.addBytes(prefixed_path.sub_path);

        return gop.index;
    }

    /// Deprecated, use `addOptionalFilePath`.
    pub fn addOptionalFile(self: *Manifest, optional_file_path: ?[]const u8) !void {
        self.hash.add(optional_file_path != null);
        const file_path = optional_file_path orelse return;
        _ = try self.addFile(file_path, null);
    }

    pub fn addOptionalFilePath(self: *Manifest, optional_file_path: ?Path) !void {
        self.hash.add(optional_file_path != null);
        const file_path = optional_file_path orelse return;
        _ = try self.addFilePath(file_path, null);
    }

    pub fn addListOfFiles(self: *Manifest, list_of_files: []const []const u8) !void {
        self.hash.add(list_of_files.len);
        for (list_of_files) |file_path| {
            _ = try self.addFile(file_path, null);
        }
    }

    pub fn addDepFile(self: *Manifest, dir: fs.Dir, dep_file_basename: []const u8) !void {
        assert(self.manifest_file == null);
        return self.addDepFileMaybePost(dir, dep_file_basename);
    }

    pub const HitError = error{
        /// Unable to check the cache for a reason that has been recorded into
        /// the `diagnostic` field.
        CacheCheckFailed,
        /// A cache manifest file exists however it could not be parsed.
        InvalidFormat,
        OutOfMemory,
    };

    /// Check the cache to see if the input exists in it. If it exists, returns `true`.
    /// A hex encoding of its hash is available by calling `final`.
    ///
    /// This function will also acquire an exclusive lock to the manifest file. This means
    /// that a process holding a Manifest will block any other process attempting to
    /// acquire the lock. If `want_shared_lock` is `true`, a cache hit guarantees the
    /// manifest file to be locked in shared mode, and a cache miss guarantees the manifest
    /// file to be locked in exclusive mode.
    ///
    /// The lock on the manifest file is released when `deinit` is called. As another
    /// option, one may call `toOwnedLock` to obtain a smaller object which can represent
    /// the lock. `deinit` is safe to call whether or not `toOwnedLock` has been called.
    pub fn hit(self: *Manifest) HitError!bool {
        assert(self.manifest_file == null);

        self.diagnostic = .none;

        const ext = ".txt";
        var manifest_file_path: [hex_digest_len + ext.len]u8 = undefined;

        var bin_digest: BinDigest = undefined;
        self.hash.hasher.final(&bin_digest);

        self.hex_digest = binToHex(bin_digest);

        @memcpy(manifest_file_path[0..self.hex_digest.len], &self.hex_digest);
        manifest_file_path[hex_digest_len..][0..ext.len].* = ext.*;

        // We'll try to open the cache with an exclusive lock, but if that would block
        // and `want_shared_lock` is set, a shared lock might be sufficient, so we'll
        // open with a shared lock instead.
        while (true) {
            if (self.cache.manifest_dir.createFile(&manifest_file_path, .{
                .read = true,
                .truncate = false,
                .lock = .exclusive,
                .lock_nonblocking = self.want_shared_lock,
            })) |manifest_file| {
                self.manifest_file = manifest_file;
                self.have_exclusive_lock = true;
                break;
            } else |err| switch (err) {
                error.WouldBlock => {
                    self.manifest_file = self.cache.manifest_dir.openFile(&manifest_file_path, .{
                        .mode = .read_write,
                        .lock = .shared,
                    }) catch |e| {
                        self.diagnostic = .{ .manifest_create = e };
                        return error.CacheCheckFailed;
                    };
                    break;
                },
                error.FileNotFound => {
                    // There are no dir components, so the only possibility
                    // should be that the directory behind the handle has been
                    // deleted, however we have observed on macOS two processes
                    // racing to do openat() with O_CREAT manifest in ENOENT.
                    //
                    // As a workaround, we retry with exclusive=true which
                    // disambiguates by returning EEXIST, indicating original
                    // failure was a race, or ENOENT, indicating deletion of
                    // the directory of our open handle.
                    if (builtin.os.tag != .macos) {
                        self.diagnostic = .{ .manifest_create = error.FileNotFound };
                        return error.CacheCheckFailed;
                    }

                    if (self.cache.manifest_dir.createFile(&manifest_file_path, .{
                        .read = true,
                        .truncate = false,
                        .lock = .exclusive,
                        .lock_nonblocking = self.want_shared_lock,
                        .exclusive = true,
                    })) |manifest_file| {
                        self.manifest_file = manifest_file;
                        self.have_exclusive_lock = true;
                        break;
                    } else |excl_err| switch (excl_err) {
                        error.WouldBlock, error.PathAlreadyExists => continue,
                        error.FileNotFound => {
                            self.diagnostic = .{ .manifest_create = error.FileNotFound };
                            return error.CacheCheckFailed;
                        },
                        else => |e| {
                            self.diagnostic = .{ .manifest_create = e };
                            return error.CacheCheckFailed;
                        },
                    }
                },
                else => |e| {
                    self.diagnostic = .{ .manifest_create = e };
                    return error.CacheCheckFailed;
                },
            }
        }

        self.want_refresh_timestamp = true;

        const input_file_count = self.files.entries.len;

        // We're going to construct a second hash. Its input will begin with the digest we've
        // already computed (`bin_digest`), and then it'll have the digests of each input file,
        // including "post" files (see `addFilePost`). If this is a hit, we learn the set of "post"
        // files from the manifest on disk. If this is a miss, we'll learn those from future calls
        // to `addFilePost` etc. As such, the state of `self.hash.hasher` after this function
        // depends on whether this is a hit or a miss.
        //
        // If we return `true` indicating a cache hit, then `self.hash.hasher` must already include
        // the digests of the "post" files, so the caller can call `final`. Otherwise, on a cache
        // miss, `self.hash.hasher` will include the digests of all non-"post" files -- that is,
        // the ones we've already been told about. The rest will be discovered through calls to
        // `addFilePost` etc, which will update the hasher. After all files are added, the user can
        // use `final`, and will at some point `writeManifest` the file list to disk.

        self.hash.hasher = hasher_init;
        self.hash.hasher.update(&bin_digest);

        hit: {
            const file_digests_populated: usize = digests: {
                switch (try self.hitWithCurrentLock()) {
                    .hit => break :hit,
                    .miss => |m| if (!try self.upgradeToExclusiveLock()) {
                        break :digests m.file_digests_populated;
                    },
                }
                // We've just had a miss with the shared lock, and upgraded to an exclusive lock. Someone
                // else might have modified the digest, so we need to check again before deciding to miss.
                // Before trying again, we must reset `self.hash.hasher` and `self.files`.
                // This is basically just the first half of `unhit`.
                self.hash.hasher = hasher_init;
                self.hash.hasher.update(&bin_digest);
                while (self.files.count() != input_file_count) {
                    var file = self.files.pop().?;
                    file.key.deinit(self.cache.gpa);
                }
                // Also, seek the file back to the start.
                self.manifest_file.?.seekTo(0) catch |err| {
                    self.diagnostic = .{ .manifest_seek = err };
                    return error.CacheCheckFailed;
                };

                switch (try self.hitWithCurrentLock()) {
                    .hit => break :hit,
                    .miss => |m| break :digests m.file_digests_populated,
                }
            };

            // This is a guaranteed cache miss. We're almost ready to return `false`, but there's a
            // little bookkeeping to do first. The first `file_digests_populated` entries in `files`
            // have their `bin_digest` populated; there may be some left in `input_file_count` which
            // we'll need to populate ourselves. Other than that, this is basically `unhit`.
            self.manifest_dirty = true;
            self.hash.hasher = hasher_init;
            self.hash.hasher.update(&bin_digest);
            while (self.files.count() != input_file_count) {
                var file = self.files.pop().?;
                file.key.deinit(self.cache.gpa);
            }
            for (self.files.keys(), 0..) |*file, idx| {
                if (idx < file_digests_populated) {
                    // `bin_digest` is already populated by `hitWithCurrentLock`, so we can use it directly.
                    self.hash.hasher.update(&file.bin_digest);
                } else {
                    self.populateFileHash(file) catch |err| {
                        self.diagnostic = .{ .file_hash = .{
                            .file_index = idx,
                            .err = err,
                        } };
                        return error.CacheCheckFailed;
                    };
                }
            }
            return false;
        }

        if (self.want_shared_lock) {
            self.downgradeToSharedLock() catch |err| {
                self.diagnostic = .{ .manifest_lock = err };
                return error.CacheCheckFailed;
            };
        }

        return true;
    }

    /// Assumes that `self.hash.hasher` has been updated only with the original digest, that
    /// `self.files` contains only the original input files, and that `self.manifest_file.?` is
    /// seeked to the start of the file.
    fn hitWithCurrentLock(self: *Manifest) HitError!union(enum) {
        hit,
        miss: struct {
            file_digests_populated: usize,
        },
    } {
        const gpa = self.cache.gpa;
        const input_file_count = self.files.entries.len;

        const file_contents = self.manifest_file.?.reader().readAllAlloc(gpa, manifest_file_size_max) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return error.OutOfMemory,
            else => |e| {
                self.diagnostic = .{ .manifest_read = e };
                return error.CacheCheckFailed;
            },
        };
        defer gpa.free(file_contents);

        var any_file_changed = false;
        var line_iter = mem.tokenizeScalar(u8, file_contents, '\n');
        var idx: usize = 0;
        const header_valid = valid: {
            const line = line_iter.next() orelse break :valid false;
            break :valid std.mem.eql(u8, line, manifest_header);
        };
        if (!header_valid) {
            return .{ .miss = .{ .file_digests_populated = 0 } };
        }
        while (line_iter.next()) |line| {
            defer idx += 1;

            var iter = mem.tokenizeScalar(u8, line, ' ');
            const size = iter.next() orelse return error.InvalidFormat;
            const inode = iter.next() orelse return error.InvalidFormat;
            const mtime_nsec_str = iter.next() orelse return error.InvalidFormat;
            const digest_str = iter.next() orelse return error.InvalidFormat;
            const prefix_str = iter.next() orelse return error.InvalidFormat;
            const file_path = iter.rest();

            const stat_size = fmt.parseInt(u64, size, 10) catch return error.InvalidFormat;
            const stat_inode = fmt.parseInt(fs.File.INode, inode, 10) catch return error.InvalidFormat;
            const stat_mtime = fmt.parseInt(i64, mtime_nsec_str, 10) catch return error.InvalidFormat;
            const file_bin_digest = b: {
                if (digest_str.len != hex_digest_len) return error.InvalidFormat;
                var bd: BinDigest = undefined;
                _ = fmt.hexToBytes(&bd, digest_str) catch return error.InvalidFormat;
                break :b bd;
            };

            const prefix = fmt.parseInt(u8, prefi```
