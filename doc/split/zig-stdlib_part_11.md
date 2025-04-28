```
panic("OOM");
}

/// Returns whether the Run step has side effects *other than* updating the output arguments.
fn hasSideEffects(run: Run) bool {
    if (run.has_side_effects) return true;
    return switch (run.stdio) {
        .infer_from_args => !run.hasAnyOutputArgs(),
        .inherit => true,
        .check => false,
        .zig_test => false,
    };
}

fn hasAnyOutputArgs(run: Run) bool {
    if (run.captured_stdout != null) return true;
    if (run.captured_stderr != null) return true;
    for (run.argv.items) |arg| switch (arg) {
        .output_file, .output_directory => return true,
        else => continue,
    };
    return false;
}

fn checksContainStdout(checks: []const StdIo.Check) bool {
    for (checks) |check| switch (check) {
        .expect_stderr_exact,
        .expect_stderr_match,
        .expect_term,
        => continue,

        .expect_stdout_exact,
        .expect_stdout_match,
        => return true,
    };
    return false;
}

fn checksContainStderr(checks: []const StdIo.Check) bool {
    for (checks) |check| switch (check) {
        .expect_stdout_exact,
        .expect_stdout_match,
        .expect_term,
        => continue,

        .expect_stderr_exact,
        .expect_stderr_match,
        => return true,
    };
    return false;
}

const IndexedOutput = struct {
    index: usize,
    tag: @typeInfo(Arg).@"union".tag_type.?,
    output: *Output,
};
fn make(step: *Step, options: Step.MakeOptions) !void {
    const prog_node = options.progress_node;
    const b = step.owner;
    const arena = b.allocator;
    const run: *Run = @fieldParentPtr("step", step);
    const has_side_effects = run.hasSideEffects();

    var argv_list = std.ArrayList([]const u8).init(arena);
    var output_placeholders = std.ArrayList(IndexedOutput).init(arena);

    var man = b.graph.cache.obtain();
    defer man.deinit();

    if (run.env_map) |env_map| {
        const KV = struct { []const u8, []const u8 };
        var kv_pairs = try std.ArrayList(KV).initCapacity(arena, env_map.count());
        var iter = env_map.iterator();
        while (iter.next()) |entry| {
            kv_pairs.appendAssumeCapacity(.{ entry.key_ptr.*, entry.value_ptr.* });
        }

        std.mem.sortUnstable(KV, kv_pairs.items, {}, struct {
            fn lessThan(_: void, kv1: KV, kv2: KV) bool {
                const k1 = kv1[0];
                const k2 = kv2[0];

                if (k1.len != k2.len) return k1.len < k2.len;

                for (k1, k2) |c1, c2| {
                    if (c1 == c2) continue;
                    return c1 < c2;
                }
                unreachable; // two keys cannot be equal
            }
        }.lessThan);

        for (kv_pairs.items) |kv| {
            man.hash.addBytes(kv[0]);
            man.hash.addBytes(kv[1]);
        }
    }

    for (run.argv.items) |arg| {
        switch (arg) {
            .bytes => |bytes| {
                try argv_list.append(bytes);
                man.hash.addBytes(bytes);
            },
            .lazy_path => |file| {
                const file_path = file.lazy_path.getPath2(b, step);
                try argv_list.append(b.fmt("{s}{s}", .{ file.prefix, file_path }));
                man.hash.addBytes(file.prefix);
                _ = try man.addFile(file_path, null);
            },
            .directory_source => |file| {
                const file_path = file.lazy_path.getPath2(b, step);
                try argv_list.append(b.fmt("{s}{s}", .{ file.prefix, file_path }));
                man.hash.addBytes(file.prefix);
                man.hash.addBytes(file_path);
            },
            .artifact => |pa| {
                const artifact = pa.artifact;

                if (artifact.rootModuleTarget().os.tag == .windows) {
                    // On Windows we don't have rpaths so we have to add .dll search paths to PATH
                    run.addPathForDynLibs(artifact);
                }
                const file_path = artifact.installed_path orelse artifact.generated_bin.?.path.?;

                try argv_list.append(b.fmt("{s}{s}", .{ pa.prefix, file_path }));

                _ = try man.addFile(file_path, null);
            },
            .output_file, .output_directory => |output| {
                man.hash.addBytes(output.prefix);
                man.hash.addBytes(output.basename);
                // Add a placeholder into the argument list because we need the
                // manifest hash to be updated with all arguments before the
                // object directory is computed.
                try output_placeholders.append(.{
                    .index = argv_list.items.len,
                    .tag = arg,
                    .output = output,
                });
                _ = try argv_list.addOne();
            },
        }
    }

    switch (run.stdin) {
        .bytes => |bytes| {
            man.hash.addBytes(bytes);
        },
        .lazy_path => |lazy_path| {
            const file_path = lazy_path.getPath2(b, step);
            _ = try man.addFile(file_path, null);
        },
        .none => {},
    }

    if (run.captured_stdout) |output| {
        man.hash.addBytes(output.basename);
    }

    if (run.captured_stderr) |output| {
        man.hash.addBytes(output.basename);
    }

    hashStdIo(&man.hash, run.stdio);

    for (run.file_inputs.items) |lazy_path| {
        _ = try man.addFile(lazy_path.getPath2(b, step), null);
    }

    if (!has_side_effects and try step.cacheHitAndWatch(&man)) {
        // cache hit, skip running command
        const digest = man.final();

        try populateGeneratedPaths(
            arena,
            output_placeholders.items,
            run.captured_stdout,
            run.captured_stderr,
            b.cache_root,
            &digest,
        );

        step.result_cached = true;
        return;
    }

    const dep_output_file = run.dep_output_file orelse {
        // We already know the final output paths, use them directly.
        const digest = if (has_side_effects)
            man.hash.final()
        else
            man.final();

        try populateGeneratedPaths(
            arena,
            output_placeholders.items,
            run.captured_stdout,
            run.captured_stderr,
            b.cache_root,
            &digest,
        );

        const output_dir_path = "o" ++ fs.path.sep_str ++ &digest;
        for (output_placeholders.items) |placeholder| {
            const output_sub_path = b.pathJoin(&.{ output_dir_path, placeholder.output.basename });
            const output_sub_dir_path = switch (placeholder.tag) {
                .output_file => fs.path.dirname(output_sub_path).?,
                .output_directory => output_sub_path,
                else => unreachable,
            };
            b.cache_root.handle.makePath(output_sub_dir_path) catch |err| {
                return step.fail("unable to make path '{}{s}': {s}", .{
                    b.cache_root, output_sub_dir_path, @errorName(err),
                });
            };
            const output_path = placeholder.output.generated_file.path.?;
            argv_list.items[placeholder.index] = if (placeholder.output.prefix.len == 0)
                output_path
            else
                b.fmt("{s}{s}", .{ placeholder.output.prefix, output_path });
        }

        try runCommand(run, argv_list.items, has_side_effects, output_dir_path, prog_node, null);
        if (!has_side_effects) try step.writeManifestAndWatch(&man);
        return;
    };

    // We do not know the final output paths yet, use temp paths to run the command.
    const rand_int = std.crypto.random.int(u64);
    const tmp_dir_path = "tmp" ++ fs.path.sep_str ++ std.fmt.hex(rand_int);

    for (output_placeholders.items) |placeholder| {
        const output_components = .{ tmp_dir_path, placeholder.output.basename };
        const output_sub_path = b.pathJoin(&output_components);
        const output_sub_dir_path = switch (placeholder.tag) {
            .output_file => fs.path.dirname(output_sub_path).?,
            .output_directory => output_sub_path,
            else => unreachable,
        };
        b.cache_root.handle.makePath(output_sub_dir_path) catch |err| {
            return step.fail("unable to make path '{}{s}': {s}", .{
                b.cache_root, output_sub_dir_path, @errorName(err),
            });
        };
        const output_path = try b.cache_root.join(arena, &output_components);
        placeholder.output.generated_file.path = output_path;
        argv_list.items[placeholder.index] = if (placeholder.output.prefix.len == 0)
            output_path
        else
            b.fmt("{s}{s}", .{ placeholder.output.prefix, output_path });
    }

    try runCommand(run, argv_list.items, has_side_effects, tmp_dir_path, prog_node, null);

    const dep_file_dir = std.fs.cwd();
    const dep_file_basename = dep_output_file.generated_file.getPath();
    if (has_side_effects)
        try man.addDepFile(dep_file_dir, dep_file_basename)
    else
        try man.addDepFilePost(dep_file_dir, dep_file_basename);

    const digest = if (has_side_effects)
        man.hash.final()
    else
        man.final();

    const any_output = output_placeholders.items.len > 0 or
        run.captured_stdout != null or run.captured_stderr != null;

    // Rename into place
    if (any_output) {
        const o_sub_path = "o" ++ fs.path.sep_str ++ &digest;

        b.cache_root.handle.rename(tmp_dir_path, o_sub_path) catch |err| {
            if (err == error.PathAlreadyExists) {
                b.cache_root.handle.deleteTree(o_sub_path) catch |del_err| {
                    return step.fail("unable to remove dir '{}'{s}: {s}", .{
                        b.cache_root,
                        tmp_dir_path,
                        @errorName(del_err),
                    });
                };
                b.cache_root.handle.rename(tmp_dir_path, o_sub_path) catch |retry_err| {
                    return step.fail("unable to rename dir '{}{s}' to '{}{s}': {s}", .{
                        b.cache_root,          tmp_dir_path,
                        b.cache_root,          o_sub_path,
                        @errorName(retry_err),
                    });
                };
            } else {
                return step.fail("unable to rename dir '{}{s}' to '{}{s}': {s}", .{
                    b.cache_root,    tmp_dir_path,
                    b.cache_root,    o_sub_path,
                    @errorName(err),
                });
            }
        };
    }

    if (!has_side_effects) try step.writeManifestAndWatch(&man);

    try populateGeneratedPaths(
        arena,
        output_placeholders.items,
        run.captured_stdout,
        run.captured_stderr,
        b.cache_root,
        &digest,
    );
}

pub fn rerunInFuzzMode(
    run: *Run,
    web_server: *std.Build.Fuzz.WebServer,
    unit_test_index: u32,
    prog_node: std.Progress.Node,
) !void {
    const step = &run.step;
    const b = step.owner;
    const arena = b.allocator;
    var argv_list: std.ArrayListUnmanaged([]const u8) = .empty;
    for (run.argv.items) |arg| {
        switch (arg) {
            .bytes => |bytes| {
                try argv_list.append(arena, bytes);
            },
            .lazy_path => |file| {
                const file_path = file.lazy_path.getPath2(b, step);
                try argv_list.append(arena, b.fmt("{s}{s}", .{ file.prefix, file_path }));
            },
            .directory_source => |file| {
                const file_path = file.lazy_path.getPath2(b, step);
                try argv_list.append(arena, b.fmt("{s}{s}", .{ file.prefix, file_path }));
            },
            .artifact => |pa| {
                const artifact = pa.artifact;
                const file_path = if (artifact == run.producer.?)
                    b.fmt("{}", .{run.rebuilt_executable.?})
                else
                    (artifact.installed_path orelse artifact.generated_bin.?.path.?);
                try argv_list.append(arena, b.fmt("{s}{s}", .{ pa.prefix, file_path }));
            },
            .output_file, .output_directory => unreachable,
        }
    }
    const has_side_effects = false;
    const rand_int = std.crypto.random.int(u64);
    const tmp_dir_path = "tmp" ++ fs.path.sep_str ++ std.fmt.hex(rand_int);
    try runCommand(run, argv_list.items, has_side_effects, tmp_dir_path, prog_node, .{
        .unit_test_index = unit_test_index,
        .web_server = web_server,
    });
}

fn populateGeneratedPaths(
    arena: std.mem.Allocator,
    output_placeholders: []const IndexedOutput,
    captured_stdout: ?*Output,
    captured_stderr: ?*Output,
    cache_root: Build.Cache.Directory,
    digest: *const Build.Cache.HexDigest,
) !void {
    for (output_placeholders) |placeholder| {
        placeholder.output.generated_file.path = try cache_root.join(arena, &.{
            "o", digest, placeholder.output.basename,
        });
    }

    if (captured_stdout) |output| {
        output.generated_file.path = try cache_root.join(arena, &.{
            "o", digest, output.basename,
        });
    }

    if (captured_stderr) |output| {
        output.generated_file.path = try cache_root.join(arena, &.{
            "o", digest, output.basename,
        });
    }
}

fn formatTerm(
    term: ?std.process.Child.Term,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    if (term) |t| switch (t) {
        .Exited => |code| try writer.print("exited with code {}", .{code}),
        .Signal => |sig| try writer.print("terminated with signal {}", .{sig}),
        .Stopped => |sig| try writer.print("stopped with signal {}", .{sig}),
        .Unknown => |code| try writer.print("terminated for unknown reason with code {}", .{code}),
    } else {
        try writer.writeAll("exited with any code");
    }
}
fn fmtTerm(term: ?std.process.Child.Term) std.fmt.Formatter(formatTerm) {
    return .{ .data = term };
}

fn termMatches(expected: ?std.process.Child.Term, actual: std.process.Child.Term) bool {
    return if (expected) |e| switch (e) {
        .Exited => |expected_code| switch (actual) {
            .Exited => |actual_code| expected_code == actual_code,
            else => false,
        },
        .Signal => |expected_sig| switch (actual) {
            .Signal => |actual_sig| expected_sig == actual_sig,
            else => false,
        },
        .Stopped => |expected_sig| switch (actual) {
            .Stopped => |actual_sig| expected_sig == actual_sig,
            else => false,
        },
        .Unknown => |expected_code| switch (actual) {
            .Unknown => |actual_code| expected_code == actual_code,
            else => false,
        },
    } else switch (actual) {
        .Exited => true,
        else => false,
    };
}

const FuzzContext = struct {
    web_server: *std.Build.Fuzz.WebServer,
    unit_test_index: u32,
};

fn runCommand(
    run: *Run,
    argv: []const []const u8,
    has_side_effects: bool,
    output_dir_path: []const u8,
    prog_node: std.Progress.Node,
    fuzz_context: ?FuzzContext,
) !void {
    const step = &run.step;
    const b = step.owner;
    const arena = b.allocator;

    const cwd: ?[]const u8 = if (run.cwd) |lazy_cwd| lazy_cwd.getPath2(b, step) else null;

    try step.handleChildProcUnsupported(cwd, argv);
    try Step.handleVerbose2(step.owner, cwd, run.env_map, argv);

    const allow_skip = switch (run.stdio) {
        .check, .zig_test => run.skip_foreign_checks,
        else => false,
    };

    var interp_argv = std.ArrayList([]const u8).init(b.allocator);
    defer interp_argv.deinit();

    const result = spawnChildAndCollect(run, argv, has_side_effects, prog_node, fuzz_context) catch |err| term: {
        // InvalidExe: cpu arch mismatch
        // FileNotFound: can happen with a wrong dynamic linker path
        if (err == error.InvalidExe or err == error.FileNotFound) interpret: {
            // TODO: learn the target from the binary directly rather than from
            // relying on it being a Compile step. This will make this logic
            // work even for the edge case that the binary was produced by a
            // third party.
            const exe = switch (run.argv.items[0]) {
                .artifact => |exe| exe.artifact,
                else => break :interpret,
            };
            switch (exe.kind) {
                .exe, .@"test" => {},
                else => break :interpret,
            }

            const root_target = exe.rootModuleTarget();
            const need_cross_glibc = root_target.isGnuLibC() and
                exe.is_linking_libc;
            const other_target = exe.root_module.resolved_target.?.result;
            switch (std.zig.system.getExternalExecutor(b.graph.host.result, &other_target, .{
                .qemu_fixes_dl = need_cross_glibc and b.glibc_runtimes_dir != null,
                .link_libc = exe.is_linking_libc,
            })) {
                .native, .rosetta => {
                    if (allow_skip) return error.MakeSkipped;
                    break :interpret;
                },
                .wine => |bin_name| {
                    if (b.enable_wine) {
                        try interp_argv.append(bin_name);
                        try interp_argv.appendSlice(argv);
                    } else {
                        return failForeign(run, "-fwine", argv[0], exe);
                    }
                },
                .qemu => |bin_name| {
                    if (b.enable_qemu) {
                        const glibc_dir_arg = if (need_cross_glibc)
                            b.glibc_runtimes_dir orelse
                                return failForeign(run, "--glibc-runtimes", argv[0], exe)
                        else
                            null;

                        try interp_argv.append(bin_name);

                        if (glibc_dir_arg) |dir| {
                            try interp_argv.append("-L");
                            try interp_argv.append(b.pathJoin(&.{
                                dir,
                                try std.zig.target.glibcRuntimeTriple(
                                    b.allocator,
                                    root_target.cpu.arch,
                                    root_target.os.tag,
                                    root_target.abi,
                                ),
                            }));
                        }

                        try interp_argv.appendSlice(argv);
                    } else {
                        return failForeign(run, "-fqemu", argv[0], exe);
                    }
                },
                .darling => |bin_name| {
                    if (b.enable_darling) {
                        try interp_argv.append(bin_name);
                        try interp_argv.appendSlice(argv);
                    } else {
                        return failForeign(run, "-fdarling", argv[0], exe);
                    }
                },
                .wasmtime => |bin_name| {
                    if (b.enable_wasmtime) {
                        // https://github.com/bytecodealliance/wasmtime/issues/7384
                        //
                        // In Wasmtime versions prior to 14, options passed after the module name
                        // could be interpreted by Wasmtime if it recognized them. As with many CLI
                        // tools, the `--` token is used to stop that behavior and indicate that the
                        // remaining arguments are for the WASM program being executed. Historically,
                        // we passed `--` after the module name here.
                        //
                        // After version 14, the `--` can no longer be passed after the module name,
                        // but is also not necessary as Wasmtime will no longer try to interpret
                        // options after the module name. So, we could just simply omit `--` for
                        // newer Wasmtime versions. But to maintain compatibility for older versions
                        // that still try to interpret options after the module name, we have moved
                        // the `--` before the module name. This appears to work for both old and
                        // new Wasmtime versions.
                        try interp_argv.append(bin_name);
                        try interp_argv.append("--dir=.");
                        try interp_argv.append("--");
                        try interp_argv.append(argv[0]);
                        try interp_argv.appendSlice(argv[1..]);
                    } else {
                        return failForeign(run, "-fwasmtime", argv[0], exe);
                    }
                },
                .bad_dl => |foreign_dl| {
                    if (allow_skip) return error.MakeSkipped;

                    const host_dl = b.graph.host.result.dynamic_linker.get() orelse "(none)";

                    return step.fail(
                        \\the host system is unable to execute binaries from the target
                        \\  because the host dynamic linker is '{s}',
                        \\  while the target dynamic linker is '{s}'.
                        \\  consider setting the dynamic linker or enabling skip_foreign_checks in the Run step
                    , .{ host_dl, foreign_dl });
                },
                .bad_os_or_cpu => {
                    if (allow_skip) return error.MakeSkipped;

                    const host_name = try b.graph.host.result.zigTriple(b.allocator);
                    const foreign_name = try root_target.zigTriple(b.allocator);

                    return step.fail("the host system ({s}) is unable to execute binaries from the target ({s})", .{
                        host_name, foreign_name,
                    });
                },
            }

            if (root_target.os.tag == .windows) {
                // On Windows we don't have rpaths so we have to add .dll search paths to PATH
                run.addPathForDynLibs(exe);
            }

            try Step.handleVerbose2(step.owner, cwd, run.env_map, interp_argv.items);

            break :term spawnChildAndCollect(run, interp_argv.items, has_side_effects, prog_node, fuzz_context) catch |e| {
                if (!run.failing_to_execute_foreign_is_an_error) return error.MakeSkipped;

                return step.fail("unable to spawn interpreter {s}: {s}", .{
                    interp_argv.items[0], @errorName(e),
                });
            };
        }

        return step.fail("failed to spawn and capture stdio from {s}: {s}", .{ argv[0], @errorName(err) });
    };

    step.result_duration_ns = result.elapsed_ns;
    step.result_peak_rss = result.peak_rss;
    step.test_results = result.stdio.test_results;
    if (result.stdio.test_metadata) |tm|
        run.cached_test_metadata = tm.toCachedTestMetadata();

    const final_argv = if (interp_argv.items.len == 0) argv else interp_argv.items;

    if (fuzz_context != null) {
        try step.handleChildProcessTerm(result.term, cwd, final_argv);
        return;
    }

    // Capture stdout and stderr to GeneratedFile objects.
    const Stream = struct {
        captured: ?*Output,
        bytes: ?[]const u8,
    };
    for ([_]Stream{
        .{
            .captured = run.captured_stdout,
            .bytes = result.stdio.stdout,
        },
        .{
            .captured = run.captured_stderr,
            .bytes = result.stdio.stderr,
        },
    }) |stream| {
        if (stream.captured) |output| {
            const output_components = .{ output_dir_path, output.basename };
            const output_path = try b.cache_root.join(arena, &output_components);
            output.generated_file.path = output_path;

            const sub_path = b.pathJoin(&output_components);
            const sub_path_dirname = fs.path.dirname(sub_path).?;
            b.cache_root.handle.makePath(sub_path_dirname) catch |err| {
                return step.fail("unable to make path '{}{s}': {s}", .{
                    b.cache_root, sub_path_dirname, @errorName(err),
                });
            };
            b.cache_root.handle.writeFile(.{ .sub_path = sub_path, .data = stream.bytes.? }) catch |err| {
                return step.fail("unable to write file '{}{s}': {s}", .{
                    b.cache_root, sub_path, @errorName(err),
                });
            };
        }
    }

    switch (run.stdio) {
        .check => |checks| for (checks.items) |check| switch (check) {
            .expect_stderr_exact => |expected_bytes| {
                if (!mem.eql(u8, expected_bytes, result.stdio.stderr.?)) {
                    return step.fail(
                        \\
                        \\========= expected this stderr: =========
                        \\{s}
                        \\========= but found: ====================
                        \\{s}
                        \\========= from the following command: ===
                        \\{s}
                    , .{
                        expected_bytes,
                        result.stdio.stderr.?,
                        try Step.allocPrintCmd(arena, cwd, final_argv),
                    });
                }
            },
            .expect_stderr_match => |match| {
                if (mem.indexOf(u8, result.stdio.stderr.?, match) == null) {
                    return step.fail(
                        \\
                        \\========= expected to find in stderr: =========
                        \\{s}
                        \\========= but stderr does not contain it: =====
                        \\{s}
                        \\========= from the following command: =========
                        \\{s}
                    , .{
                        match,
                        result.stdio.stderr.?,
                        try Step.allocPrintCmd(arena, cwd, final_argv),
                    });
                }
            },
            .expect_stdout_exact => |expected_bytes| {
                if (!mem.eql(u8, expected_bytes, result.stdio.stdout.?)) {
                    return step.fail(
                        \\
                        \\========= expected this stdout: =========
                        \\{s}
                        \\========= but found: ====================
                        \\{s}
                        \\========= from the following command: ===
                        \\{s}
                    , .{
                        expected_bytes,
                        result.stdio.stdout.?,
                        try Step.allocPrintCmd(arena, cwd, final_argv),
                    });
                }
            },
            .expect_stdout_match => |match| {
                if (mem.indexOf(u8, result.stdio.stdout.?, match) == null) {
                    return step.fail(
                        \\
                        \\========= expected to find in stdout: =========
                        \\{s}
                        \\========= but stdout does not contain it: =====
                        \\{s}
                        \\========= from the following command: =========
                        \\{s}
                    , .{
                        match,
                        result.stdio.stdout.?,
                        try Step.allocPrintCmd(arena, cwd, final_argv),
                    });
                }
            },
            .expect_term => |expected_term| {
                if (!termMatches(expected_term, result.term)) {
                    return step.fail("the following command {} (expected {}):\n{s}", .{
                        fmtTerm(result.term),
                        fmtTerm(expected_term),
                        try Step.allocPrintCmd(arena, cwd, final_argv),
                    });
                }
            },
        },
        .zig_test => {
            const prefix: []const u8 = p: {
                if (result.stdio.test_metadata) |tm| {
                    if (tm.next_index > 0 and tm.next_index <= tm.names.len) {
                        const name = tm.testName(tm.next_index - 1);
                        break :p b.fmt("while executing test '{s}', ", .{name});
                    }
                }
                break :p "";
            };
            const expected_term: std.process.Child.Term = .{ .Exited = 0 };
            if (!termMatches(expected_term, result.term)) {
                return step.fail("{s}the following command {} (expected {}):\n{s}", .{
                    prefix,
                    fmtTerm(result.term),
                    fmtTerm(expected_term),
                    try Step.allocPrintCmd(arena, cwd, final_argv),
                });
            }
            if (!result.stdio.test_results.isSuccess()) {
                return step.fail(
                    "{s}the following test command failed:\n{s}",
                    .{ prefix, try Step.allocPrintCmd(arena, cwd, final_argv) },
                );
            }
        },
        else => {
            try step.handleChildProcessTerm(result.term, cwd, final_argv);
        },
    }
}

const ChildProcResult = struct {
    term: std.process.Child.Term,
    elapsed_ns: u64,
    peak_rss: usize,

    stdio: StdIoResult,
};

fn spawnChildAndCollect(
    run: *Run,
    argv: []const []const u8,
    has_side_effects: bool,
    prog_node: std.Progress.Node,
    fuzz_context: ?FuzzContext,
) !ChildProcResult {
    const b = run.step.owner;
    const arena = b.allocator;

    if (fuzz_context != null) {
        assert(!has_side_effects);
        assert(run.stdio == .zig_test);
    }

    var child = std.process.Child.init(argv, arena);
    if (run.cwd) |lazy_cwd| {
        child.cwd = lazy_cwd.getPath2(b, &run.step);
    } else {
        child.cwd = b.build_root.path;
        child.cwd_dir = b.build_root.handle;
    }
    child.env_map = run.env_map orelse &b.graph.env_map;
    child.request_resource_usage_statistics = true;

    child.stdin_behavior = switch (run.stdio) {
        .infer_from_args => if (has_side_effects) .Inherit else .Ignore,
        .inherit => .Inherit,
        .check => .Ignore,
        .zig_test => .Pipe,
    };
    child.stdout_behavior = switch (run.stdio) {
        .infer_from_args => if (has_side_effects) .Inherit else .Ignore,
        .inherit => .Inherit,
        .check => |checks| if (checksContainStdout(checks.items)) .Pipe else .Ignore,
        .zig_test => .Pipe,
    };
    child.stderr_behavior = switch (run.stdio) {
        .infer_from_args => if (has_side_effects) .Inherit else .Pipe,
        .inherit => .Inherit,
        .check => .Pipe,
        .zig_test => .Pipe,
    };
    if (run.captured_stdout != null) child.stdout_behavior = .Pipe;
    if (run.captured_stderr != null) child.stderr_behavior = .Pipe;
    if (run.stdin != .none) {
        assert(run.stdio != .inherit);
        child.stdin_behavior = .Pipe;
    }

    const inherit = child.stdout_behavior == .Inherit or child.stderr_behavior == .Inherit;

    if (run.stdio != .zig_test and !run.disable_zig_progress and !inherit) {
        child.progress_node = prog_node;
    }

    const term, const result, const elapsed_ns = t: {
        if (inherit) std.debug.lockStdErr();
        defer if (inherit) std.debug.unlockStdErr();

        try child.spawn();
        errdefer {
            _ = child.kill() catch {};
        }

        // We need to report `error.InvalidExe` *now* if applicable.
        try child.waitForSpawn();

        var timer = try std.time.Timer.start();

        const result = if (run.stdio == .zig_test)
            try evalZigTest(run, &child, prog_node, fuzz_context)
        else
            try evalGeneric(run, &child);

        break :t .{ try child.wait(), result, timer.read() };
    };

    return .{
        .stdio = result,
        .term = term,
        .elapsed_ns = elapsed_ns,
        .peak_rss = child.resource_usage_statistics.getMaxRss() orelse 0,
    };
}

const StdIoResult = struct {
    stdout: ?[]const u8,
    stderr: ?[]const u8,
    test_results: Step.TestResults,
    test_metadata: ?TestMetadata,
};

fn evalZigTest(
    run: *Run,
    child: *std.process.Child,
    prog_node: std.Progress.Node,
    fuzz_context: ?FuzzContext,
) !StdIoResult {
    const gpa = run.step.owner.allocator;
    const arena = run.step.owner.allocator;

    var poller = std.io.poll(gpa, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    // If this is `true`, we avoid ever entering the polling loop below, because the stdin pipe has
    // somehow already closed; instead, we go straight to capturing stderr in case it has anything
    // useful.
    const first_write_failed = if (fuzz_context) |fuzz| failed: {
        sendRunTestMessage(child.stdin.?, .start_fuzzing, fuzz.unit_test_index) catch |err| {
            try run.step.addError("unable to write stdin: {s}", .{@errorName(err)});
            break :failed true;
        };
        break :failed false;
    } else failed: {
        run.fuzz_tests.clearRetainingCapacity();
        sendMessage(child.stdin.?, .query_test_metadata) catch |err| {
            try run.step.addError("unable to write stdin: {s}", .{@errorName(err)});
            break :failed true;
        };
        break :failed false;
    };

    const Header = std.zig.Server.Message.Header;

    const stdout = poller.fifo(.stdout);
    const stderr = poller.fifo(.stderr);

    var fail_count: u32 = 0;
    var skip_count: u32 = 0;
    var leak_count: u32 = 0;
    var test_count: u32 = 0;
    var log_err_count: u32 = 0;

    var metadata: ?TestMetadata = null;
    var coverage_id: ?u64 = null;

    var sub_prog_node: ?std.Progress.Node = null;
    defer if (sub_prog_node) |n| n.end();

    const any_write_failed = first_write_failed or poll: while (true) {
        while (stdout.readableLength() < @sizeOf(Header)) {
            if (!(try poller.poll())) break :poll false;
        }
        const header = stdout.reader().readStruct(Header) catch unreachable;
        while (stdout.readableLength() < header.bytes_len) {
            if (!(try poller.poll())) break :poll false;
        }
        const body = stdout.readableSliceOfLen(header.bytes_len);

        switch (header.tag) {
            .zig_version => {
                if (!std.mem.eql(u8, builtin.zig_version_string, body)) {
                    return run.step.fail(
                        "zig version mismatch build runner vs compiler: '{s}' vs '{s}'",
                        .{ builtin.zig_version_string, body },
                    );
                }
            },
            .test_metadata => {
                assert(fuzz_context == null);
                const TmHdr = std.zig.Server.Message.TestMetadata;
                const tm_hdr = @as(*align(1) const TmHdr, @ptrCast(body));
                test_count = tm_hdr.tests_len;

                const names_bytes = body[@sizeOf(TmHdr)..][0 .. test_count * @sizeOf(u32)];
                const expected_panic_msgs_bytes = body[@sizeOf(TmHdr) + names_bytes.len ..][0 .. test_count * @sizeOf(u32)];
                const string_bytes = body[@sizeOf(TmHdr) + names_bytes.len + expected_panic_msgs_bytes.len ..][0..tm_hdr.string_bytes_len];

                const names = std.mem.bytesAsSlice(u32, names_bytes);
                const expected_panic_msgs = std.mem.bytesAsSlice(u32, expected_panic_msgs_bytes);
                const names_aligned = try arena.alloc(u32, names.len);
                for (names_aligned, names) |*dest, src| dest.* = src;

                const expected_panic_msgs_aligned = try arena.alloc(u32, expected_panic_msgs.len);
                for (expected_panic_msgs_aligned, expected_panic_msgs) |*dest, src| dest.* = src;

                prog_node.setEstimatedTotalItems(names.len);
                metadata = .{
                    .string_bytes = try arena.dupe(u8, string_bytes),
                    .names = names_aligned,
                    .expected_panic_msgs = expected_panic_msgs_aligned,
                    .next_index = 0,
                    .prog_node = prog_node,
                };

                requestNextTest(child.stdin.?, &metadata.?, &sub_prog_node) catch |err| {
                    try run.step.addError("unable to write stdin: {s}", .{@errorName(err)});
                    break :poll true;
                };
            },
            .test_results => {
                assert(fuzz_context == null);
                const md = metadata.?;

                const TrHdr = std.zig.Server.Message.TestResults;
                const tr_hdr = @as(*align(1) const TrHdr, @ptrCast(body));
                fail_count +|= @intFromBool(tr_hdr.flags.fail);
                skip_count +|= @intFromBool(tr_hdr.flags.skip);
                leak_count +|= @intFromBool(tr_hdr.flags.leak);
                log_err_count +|= tr_hdr.flags.log_err_count;

                if (tr_hdr.flags.fuzz) try run.fuzz_tests.append(gpa, tr_hdr.index);

                if (tr_hdr.flags.fail or tr_hdr.flags.leak or tr_hdr.flags.log_err_count > 0) {
                    const name = std.mem.sliceTo(md.string_bytes[md.names[tr_hdr.index]..], 0);
                    const orig_msg = stderr.readableSlice(0);
                    defer stderr.discard(orig_msg.len);
                    const msg = std.mem.trim(u8, orig_msg, "\n");
                    const label = if (tr_hdr.flags.fail)
                        "failed"
                    else if (tr_hdr.flags.leak)
                        "leaked"
                    else if (tr_hdr.flags.log_err_count > 0)
                        "logged errors"
                    else
                        unreachable;
                    if (msg.len > 0) {
                        try run.step.addError("'{s}' {s}: {s}", .{ name, label, msg });
                    } else {
                        try run.step.addError("'{s}' {s}", .{ name, label });
                    }
                }

                requestNextTest(child.stdin.?, &metadata.?, &sub_prog_node) catch |err| {
                    try run.step.addError("unable to write stdin: {s}", .{@errorName(err)});
                    break :poll true;
                };
            },
            .coverage_id => {
                const web_server = fuzz_context.?.web_server;
                const msg_ptr: *align(1) const u64 = @ptrCast(body);
                coverage_id = msg_ptr.*;
                {
                    web_server.mutex.lock();
                    defer web_server.mutex.unlock();
                    try web_server.msg_queue.append(web_server.gpa, .{ .coverage = .{
                        .id = coverage_id.?,
                        .run = run,
                    } });
                    web_server.condition.signal();
                }
            },
            .fuzz_start_addr => {
                const web_server = fuzz_context.?.web_server;
                const msg_ptr: *align(1) const u64 = @ptrCast(body);
                const addr = msg_ptr.*;
                {
                    web_server.mutex.lock();
                    defer web_server.mutex.unlock();
                    try web_server.msg_queue.append(web_server.gpa, .{ .entry_point = .{
                        .addr = addr,
                        .coverage_id = coverage_id.?,
                    } });
                    web_server.condition.signal();
                }
            },
            else => {}, // ignore other messages
        }

        stdout.discard(body.len);
    };

    if (any_write_failed) {
        // The compiler unexpectedly closed stdin; something is very wrong and has probably crashed.
        // We want to make sure we've captured all of stderr so that it's logged below.
        while (try poller.poll()) {}
    }

    if (stderr.readableLength() > 0) {
        const msg = std.mem.trim(u8, try stderr.toOwnedSlice(), "\n");
        if (msg.len > 0) run.step.result_stderr = msg;
    }

    // Send EOF to stdin.
    child.stdin.?.close();
    child.stdin = null;

    return .{
        .stdout = null,
        .stderr = null,
        .test_results = .{
            .test_count = test_count,
            .fail_count = fail_count,
            .skip_count = skip_count,
            .leak_count = leak_count,
            .log_err_count = log_err_count,
        },
        .test_metadata = metadata,
    };
}

const TestMetadata = struct {
    names: []const u32,
    expected_panic_msgs: []const u32,
    string_bytes: []const u8,
    next_index: u32,
    prog_node: std.Progress.Node,

    fn toCachedTestMetadata(tm: TestMetadata) CachedTestMetadata {
        return .{
            .names = tm.names,
            .string_bytes = tm.string_bytes,
        };
    }

    fn testName(tm: TestMetadata, index: u32) []const u8 {
        return tm.toCachedTestMetadata().testName(index);
    }
};

pub const CachedTestMetadata = struct {
    names: []const u32,
    string_bytes: []const u8,

    pub fn testName(tm: CachedTestMetadata, index: u32) []const u8 {
        return std.mem.sliceTo(tm.string_bytes[tm.names[index]..], 0);
    }
};

fn requestNextTest(in: fs.File, metadata: *TestMetadata, sub_prog_node: *?std.Progress.Node) !void {
    while (metadata.next_index < metadata.names.len) {
        const i = metadata.next_index;
        metadata.next_index += 1;

        if (metadata.expected_panic_msgs[i] != 0) continue;

        const name = metadata.testName(i);
        if (sub_prog_node.*) |n| n.end();
        sub_prog_node.* = metadata.prog_node.start(name, 0);

        try sendRunTestMessage(in, .run_test, i);
        return;
    } else {
        try sendMessage(in, .exit);
    }
}

fn sendMessage(file: std.fs.File, tag: std.zig.Client.Message.Tag) !void {
    const header: std.zig.Client.Message.Header = .{
        .tag = tag,
        .bytes_len = 0,
    };
    try file.writeAll(std.mem.asBytes(&header));
}

fn sendRunTestMessage(file: std.fs.File, tag: std.zig.Client.Message.Tag, index: u32) !void {
    const header: std.zig.Client.Message.Header = .{
        .tag = tag,
        .bytes_len = 4,
    };
    const full_msg = std.mem.asBytes(&header) ++ std.mem.asBytes(&index);
    try file.writeAll(full_msg);
}

fn evalGeneric(run: *Run, child: *std.process.Child) !StdIoResult {
    const b = run.step.owner;
    const arena = b.allocator;

    switch (run.stdin) {
        .bytes => |bytes| {
            child.stdin.?.writeAll(bytes) catch |err| {
                return run.step.fail("unable to write stdin: {s}", .{@errorName(err)});
            };
            child.stdin.?.close();
            child.stdin = null;
        },
        .lazy_path => |lazy_path| {
            const path = lazy_path.getPath2(b, &run.step);
            const file = b.build_root.handle.openFile(path, .{}) catch |err| {
                return run.step.fail("unable to open stdin file: {s}", .{@errorName(err)});
            };
            defer file.close();
            child.stdin.?.writeFileAll(file, .{}) catch |err| {
                return run.step.fail("unable to write file to stdin: {s}", .{@errorName(err)});
            };
            child.stdin.?.close();
            child.stdin = null;
        },
        .none => {},
    }

    var stdout_bytes: ?[]const u8 = null;
    var stderr_bytes: ?[]const u8 = null;

    if (child.stdout) |stdout| {
        if (child.stderr) |stderr| {
            var poller = std.io.poll(arena, enum { stdout, stderr }, .{
                .stdout = stdout,
                .stderr = stderr,
            });
            defer poller.deinit();

            while (try poller.poll()) {
                if (poller.fifo(.stdout).count > run.max_stdio_size)
                    return error.StdoutStreamTooLong;
                if (poller.fifo(.stderr).count > run.max_stdio_size)
                    return error.StderrStreamTooLong;
            }

            stdout_bytes = try poller.fifo(.stdout).toOwnedSlice();
            stderr_bytes = try poller.fifo(.stderr).toOwnedSlice();
        } else {
            stdout_bytes = try stdout.reader().readAllAlloc(arena, run.max_stdio_size);
        }
    } else if (child.stderr) |stderr| {
        stderr_bytes = try stderr.reader().readAllAlloc(arena, run.max_stdio_size);
    }

    if (stderr_bytes) |bytes| if (bytes.len > 0) {
        // Treat stderr as an error message.
        const stderr_is_diagnostic = run.captured_stderr == null and switch (run.stdio) {
            .check => |checks| !checksContainStderr(checks.items),
            else => true,
        };
        if (stderr_is_diagnostic) {
            run.step.result_stderr = bytes;
        }
    };

    return .{
        .stdout = stdout_bytes,
        .stderr = stderr_bytes,
        .test_results = .{},
        .test_metadata = null,
    };
}

fn addPathForDynLibs(run: *Run, artifact: *Step.Compile) void {
    const b = run.step.owner;
    const compiles = artifact.getCompileDependencies(true);
    for (compiles) |compile| {
        if (compile.root_module.resolved_target.?.result.os.tag == .windows and
            compile.isDynamicLibrary())
        {
            addPathDir(run, fs.path.dirname(compile.getEmittedBin().getPath2(b, &run.step)).?);
        }
    }
}

fn failForeign(
    run: *Run,
    suggested_flag: []const u8,
    argv0: []const u8,
    exe: *Step.Compile,
) error{ MakeFailed, MakeSkipped, OutOfMemory } {
    switch (run.stdio) {
        .check, .zig_test => {
            if (run.skip_foreign_checks)
                return error.MakeSkipped;

            const b = run.step.owner;
            const host_name = try b.graph.host.result.zigTriple(b.allocator);
            const foreign_name = try exe.rootModuleTarget().zigTriple(b.allocator);

            return run.step.fail(
                \\unable to spawn foreign binary '{s}' ({s}) on host system ({s})
                \\  consider using {s} or enabling skip_foreign_checks in the Run step
            , .{ argv0, foreign_name, host_name, suggested_flag });
        },
        else => {
            return run.step.fail("unable to spawn foreign binary '{s}'", .{argv0});
        },
    }
}

fn hashStdIo(hh: *std.Build.Cache.HashHelper, stdio: StdIo) void {
    switch (stdio) {
        .infer_from_args, .inherit, .zig_test => {},
        .check => |checks| for (checks.items) |check| {
            hh.add(@as(std.meta.Tag(StdIo.Check), check));
            switch (check) {
                .expect_stderr_exact,
                .expect_stderr_match,
                .expect_stdout_exact,
                .expect_stdout_match,
                => |s| hh.addBytes(s),

                .expect_term => |term| {
                    hh.add(@as(std.meta.Tag(std.process.Child.Term), term));
                    switch (term) {
                        .Exited => |x| hh.add(x),
                        .Signal, .Stopped, .Unknown => |x| hh.add(x),
                    }
                },
            }
        },
    }
}
const std = @import("std");
const Step = std.Build.Step;
const LazyPath = std.Build.LazyPath;
const fs = std.fs;
const mem = std.mem;

const TranslateC = @This();

pub const base_id: Step.Id = .translate_c;

step: Step,
source: std.Build.LazyPath,
include_dirs: std.ArrayList(std.Build.Module.IncludeDir),
c_macros: std.ArrayList([]const u8),
out_basename: []const u8,
target: std.Build.ResolvedTarget,
optimize: std.builtin.OptimizeMode,
output_file: std.Build.GeneratedFile,
link_libc: bool,
use_clang: bool,

pub const Options = struct {
    root_source_file: std.Build.LazyPath,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    link_libc: bool = true,
    use_clang: bool = true,
};

pub fn create(owner: *std.Build, options: Options) *TranslateC {
    const translate_c = owner.allocator.create(TranslateC) catch @panic("OOM");
    const source = options.root_source_file.dupe(owner);
    translate_c.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "translate-c",
            .owner = owner,
            .makeFn = make,
        }),
        .source = source,
        .include_dirs = std.ArrayList(std.Build.Module.IncludeDir).init(owner.allocator),
        .c_macros = std.ArrayList([]const u8).init(owner.allocator),
        .out_basename = undefined,
        .target = options.target,
        .optimize = options.optimize,
        .output_file = .{ .step = &translate_c.step },
        .link_libc = options.link_libc,
        .use_clang = options.use_clang,
    };
    source.addStepDependencies(&translate_c.step);
    return translate_c;
}

pub const AddExecutableOptions = struct {
    name: ?[]const u8 = null,
    version: ?std.SemanticVersion = null,
    target: ?std.Build.ResolvedTarget = null,
    optimize: ?std.builtin.OptimizeMode = null,
    linkage: ?std.builtin.LinkMode = null,
};

pub fn getOutput(translate_c: *TranslateC) std.Build.LazyPath {
    return .{ .generated = .{ .file = &translate_c.output_file } };
}

/// Deprecated: use `createModule` or `addModule` with `std.Build.addExecutable` instead.
/// Creates a step to build an executable from the translated source.
pub fn addExecutable(translate_c: *TranslateC, options: AddExecutableOptions) *Step.Compile {
    return translate_c.step.owner.addExecutable(.{
        .root_source_file = translate_c.getOutput(),
        .name = options.name orelse "translated_c",
        .version = options.version,
        .target = options.target orelse translate_c.target,
        .optimize = options.optimize orelse translate_c.optimize,
        .linkage = options.linkage,
    });
}

/// Creates a module from the translated source and adds it to the package's
/// module set making it available to other packages which depend on this one.
/// `createModule` can be used instead to create a private module.
pub fn addModule(translate_c: *TranslateC, name: []const u8) *std.Build.Module {
    return translate_c.step.owner.addModule(name, .{
        .root_source_file = translate_c.getOutput(),
        .target = translate_c.target,
        .optimize = translate_c.optimize,
        .link_libc = translate_c.link_libc,
    });
}

/// Creates a private module from the translated source to be used by the
/// current package, but not exposed to other packages depending on this one.
/// `addModule` can be used instead to create a public module.
pub fn createModule(translate_c: *TranslateC) *std.Build.Module {
    return translate_c.step.owner.createModule(.{
        .root_source_file = translate_c.getOutput(),
        .target = translate_c.target,
        .optimize = translate_c.optimize,
        .link_libc = translate_c.link_libc,
    });
}

pub fn addAfterIncludePath(translate_c: *TranslateC, lazy_path: LazyPath) void {
    const b = translate_c.step.owner;
    translate_c.include_dirs.append(.{ .path_after = lazy_path.dupe(b) }) catch
        @panic("OOM");
    lazy_path.addStepDependencies(&translate_c.step);
}

pub fn addSystemIncludePath(translate_c: *TranslateC, lazy_path: LazyPath) void {
    const b = translate_c.step.owner;
    translate_c.include_dirs.append(.{ .path_system = lazy_path.dupe(b) }) catch
        @panic("OOM");
    lazy_path.addStepDependencies(&translate_c.step);
}

pub fn addIncludePath(translate_c: *TranslateC, lazy_path: LazyPath) void {
    const b = translate_c.step.owner;
    translate_c.include_dirs.append(.{ .path = lazy_path.dupe(b) }) catch
        @panic("OOM");
    lazy_path.addStepDependencies(&translate_c.step);
}

pub fn addConfigHeader(translate_c: *TranslateC, config_header: *Step.ConfigHeader) void {
    translate_c.include_dirs.append(.{ .config_header_step = config_header }) catch
        @panic("OOM");
    translate_c.step.dependOn(&config_header.step);
}

pub fn addSystemFrameworkPath(translate_c: *TranslateC, directory_path: LazyPath) void {
    const b = translate_c.step.owner;
    translate_c.include_dirs.append(.{ .framework_path_system = directory_path.dupe(b) }) catch
        @panic("OOM");
    directory_path.addStepDependencies(&translate_c.step);
}

pub fn addFrameworkPath(translate_c: *TranslateC, directory_path: LazyPath) void {
    const b = translate_c.step.owner;
    translate_c.include_dirs.append(.{ .framework_path = directory_path.dupe(b) }) catch
        @panic("OOM");
    directory_path.addStepDependencies(&translate_c.step);
}

pub fn addCheckFile(translate_c: *TranslateC, expected_matches: []const []const u8) *Step.CheckFile {
    return Step.CheckFile.create(
        translate_c.step.owner,
        translate_c.getOutput(),
        .{ .expected_matches = expected_matches },
    );
}

/// If the value is omitted, it is set to 1.
/// `name` and `value` need not live longer than the function call.
pub fn defineCMacro(translate_c: *TranslateC, name: []const u8, value: ?[]const u8) void {
    const macro = translate_c.step.owner.fmt("{s}={s}", .{ name, value orelse "1" });
    translate_c.c_macros.append(macro) catch @panic("OOM");
}

/// name_and_value looks like [name]=[value]. If the value is omitted, it is set to 1.
pub fn defineCMacroRaw(translate_c: *TranslateC, name_and_value: []const u8) void {
    translate_c.c_macros.append(translate_c.step.owner.dupe(name_and_value)) catch @panic("OOM");
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    const prog_node = options.progress_node;
    const b = step.owner;
    const translate_c: *TranslateC = @fieldParentPtr("step", step);

    var argv_list = std.ArrayList([]const u8).init(b.allocator);
    try argv_list.append(b.graph.zig_exe);
    try argv_list.append("translate-c");
    if (translate_c.link_libc) {
        try argv_list.append("-lc");
    }
    if (!translate_c.use_clang) {
        try argv_list.append("-fno-clang");
    }

    try argv_list.append("--listen=-");

    if (!translate_c.target.query.isNative()) {
        try argv_list.append("-target");
        try argv_list.append(try translate_c.target.query.zigTriple(b.allocator));
    }

    switch (translate_c.optimize) {
        .Debug => {}, // Skip since it's the default.
        else => try argv_list.append(b.fmt("-O{s}", .{@tagName(translate_c.optimize)})),
    }

    for (translate_c.include_dirs.items) |include_dir| {
        try include_dir.appendZigProcessFlags(b, &argv_list, step);
    }

    for (translate_c.c_macros.items) |c_macro| {
        try argv_list.append("-D");
        try argv_list.append(c_macro);
    }

    const c_source_path = translate_c.source.getPath2(b, step);
    try argv_list.append(c_source_path);

    const output_dir = try step.evalZigProcess(argv_list.items, prog_node, false);

    const basename = std.fs.path.stem(std.fs.path.basename(c_source_path));
    translate_c.out_basename = b.fmt("{s}.zig", .{basename});
    translate_c.output_file.path = output_dir.?.joinString(b.allocator, translate_c.out_basename) catch @panic("OOM");
}
//! Writes data to paths relative to the package root, effectively mutating the
//! package's source files. Be careful with the latter functionality; it should
//! not be used during the normal build process, but as a utility run by a
//! developer with intention to update source files, which will then be
//! committed to version control.
const std = @import("std");
const Step = std.Build.Step;
const fs = std.fs;
const ArrayList = std.ArrayList;
const UpdateSourceFiles = @This();

step: Step,
output_source_files: std.ArrayListUnmanaged(OutputSourceFile),

pub const base_id: Step.Id = .update_source_files;

pub const OutputSourceFile = struct {
    contents: Contents,
    sub_path: []const u8,
};

pub const Contents = union(enum) {
    bytes: []const u8,
    copy: std.Build.LazyPath,
};

pub fn create(owner: *std.Build) *UpdateSourceFiles {
    const usf = owner.allocator.create(UpdateSourceFiles) catch @panic("OOM");
    usf.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "UpdateSourceFiles",
            .owner = owner,
            .makeFn = make,
        }),
        .output_source_files = .{},
    };
    return usf;
}

/// A path relative to the package root.
///
/// Be careful with this because it updates source files. This should not be
/// used as part of the normal build process, but as a utility occasionally
/// run by a developer with intent to modify source files and then commit
/// those changes to version control.
pub fn addCopyFileToSource(usf: *UpdateSourceFiles, source: std.Build.LazyPath, sub_path: []const u8) void {
    const b = usf.step.owner;
    usf.output_source_files.append(b.allocator, .{
        .contents = .{ .copy = source },
        .sub_path = sub_path,
    }) catch @panic("OOM");
    source.addStepDependencies(&usf.step);
}

/// A path relative to the package root.
///
/// Be careful with this because it updates source files. This should not be
/// used as part of the normal build process, but as a utility occasionally
/// run by a developer with intent to modify source files and then commit
/// those changes to version control.
pub fn addBytesToSource(usf: *UpdateSourceFiles, bytes: []const u8, sub_path: []const u8) void {
    const b = usf.step.owner;
    usf.output_source_files.append(b.allocator, .{
        .contents = .{ .bytes = bytes },
        .sub_path = sub_path,
    }) catch @panic("OOM");
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;
    const b = step.owner;
    const usf: *UpdateSourceFiles = @fieldParentPtr("step", step);

    var any_miss = false;
    for (usf.output_source_files.items) |output_source_file| {
        if (fs.path.dirname(output_source_file.sub_path)) |dirname| {
            b.build_root.handle.makePath(dirname) catch |err| {
                return step.fail("unable to make path '{}{s}': {s}", .{
                    b.build_root, dirname, @errorName(err),
                });
            };
        }
        switch (output_source_file.contents) {
            .bytes => |bytes| {
                b.build_root.handle.writeFile(.{ .sub_path = output_source_file.sub_path, .data = bytes }) catch |err| {
                    return step.fail("unable to write file '{}{s}': {s}", .{
                        b.build_root, output_source_file.sub_path, @errorName(err),
                    });
                };
                any_miss = true;
            },
            .copy => |file_source| {
                if (!step.inputs.populated()) try step.addWatchInput(file_source);

                const source_path = file_source.getPath2(b, step);
                const prev_status = fs.Dir.updateFile(
                    fs.cwd(),
                    source_path,
                    b.build_root.handle,
                    output_source_file.sub_path,
                    .{},
                ) catch |err| {
                    return step.fail("unable to update file from '{s}' to '{}{s}': {s}", .{
                        source_path, b.build_root, output_source_file.sub_path, @errorName(err),
                    });
                };
                any_miss = any_miss or prev_status == .stale;
            },
        }
    }

    step.result_cached = !any_miss;
}
//! WriteFile is used to create a directory in an appropriate location inside
//! the local cache which has a set of files that have either been generated
//! during the build, or are copied from the source package.
const std = @import("std");
const Step = std.Build.Step;
const fs = std.fs;
const ArrayList = std.ArrayList;
const WriteFile = @This();

step: Step,

// The elements here are pointers because we need stable pointers for the GeneratedFile field.
files: std.ArrayListUnmanaged(File),
directories: std.ArrayListUnmanaged(Directory),
generated_directory: std.Build.GeneratedFile,

pub const base_id: Step.Id = .write_file;

pub const File = struct {
    sub_path: []const u8,
    contents: Contents,
};

pub const Directory = struct {
    source: std.Build.LazyPath,
    sub_path: []const u8,
    options: Options,

    pub const Options = struct {
        /// File paths that end in any of these suffixes will be excluded from copying.
        exclude_extensions: []const []const u8 = &.{},
        /// Only file paths that end in any of these suffixes will be included in copying.
        /// `null` means that all suffixes will be included.
        /// `exclude_extensions` takes precedence over `include_extensions`.
        include_extensions: ?[]const []const u8 = null,

        pub fn dupe(opts: Options, b: *std.Build) Options {
            return .{
                .exclude_extensions = b.dupeStrings(opts.exclude_extensions),
                .include_extensions = if (opts.include_extensions) |incs| b.dupeStrings(incs) else null,
            };
        }

        pub fn pathIncluded(opts: Options, path: []const u8) bool {
            for (opts.exclude_extensions) |ext| {
                if (std.mem.endsWith(u8, path, ext))
                    return false;
            }
            if (opts.include_extensions) |incs| {
                for (incs) |inc| {
                    if (std.mem.endsWith(u8, path, inc))
                        return true;
                } else {
                    return false;
                }
            }
            return true;
        }
    };
};

pub const Contents = union(enum) {
    bytes: []const u8,
    copy: std.Build.LazyPath,
};

pub fn create(owner: *std.Build) *WriteFile {
    const write_file = owner.allocator.create(WriteFile) catch @panic("OOM");
    write_file.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "WriteFile",
            .owner = owner,
            .makeFn = make,
        }),
        .files = .{},
        .directories = .{},
        .generated_directory = .{ .step = &write_file.step },
    };
    return write_file;
}

pub fn add(write_file: *WriteFile, sub_path: []const u8, bytes: []const u8) std.Build.LazyPath {
    const b = write_file.step.owner;
    const gpa = b.allocator;
    const file = File{
        .sub_path = b.dupePath(sub_path),
        .contents = .{ .bytes = b.dupe(bytes) },
    };
    write_file.files.append(gpa, file) catch @panic("OOM");
    write_file.maybeUpdateName();
    return .{
        .generated = .{
            .file = &write_file.generated_directory,
            .sub_path = file.sub_path,
        },
    };
}

/// Place the file into the generated directory within the local cache,
/// along with all the rest of the files added to this step. The parameter
/// here is the destination path relative to the local cache directory
/// associated with this WriteFile. It may be a basename, or it may
/// include sub-directories, in which case this step will ensure the
/// required sub-path exists.
/// This is the option expected to be used most commonly with `addCopyFile`.
pub fn addCopyFile(write_file: *WriteFile, source: std.Build.LazyPath, sub_path: []const u8) std.Build.LazyPath {
    const b = write_file.step.owner;
    const gpa = b.allocator;
    const file = File{
        .sub_path = b.dupePath(sub_path),
        .contents = .{ .copy = source },
    };
    write_file.files.append(gpa, file) catch @panic("OOM");

    write_file.maybeUpdateName();
    source.addStepDependencies(&write_file.step);
    return .{
        .generated = .{
            .file = &write_file.generated_directory,
            .sub_path = file.sub_path,
        },
    };
}

/// Copy files matching the specified exclude/include patterns to the specified subdirectory
/// relative to this step's generated directory.
/// The returned value is a lazy path to the generated subdirectory.
pub fn addCopyDirectory(
    write_file: *WriteFile,
    source: std.Build.LazyPath,
    sub_path: []const u8,
    options: Directory.Options,
) std.Build.LazyPath {
    const b = write_file.step.owner;
    const gpa = b.allocator;
    const dir = Directory{
        .source = source.dupe(b),
        .sub_path = b.dupePath(sub_path),
        .options = options.dupe(b),
    };
    write_file.directories.append(gpa, dir) catch @panic("OOM");

    write_file.maybeUpdateName();
    source.addStepDependencies(&write_file.step);
    return .{
        .generated = .{
            .file = &write_file.generated_directory,
            .sub_path = dir.sub_path,
        },
    };
}

/// Returns a `LazyPath` representing the base directory that contains all the
/// files from this `WriteFile`.
pub fn getDirectory(write_file: *WriteFile) std.Build.LazyPath {
    return .{ .generated = .{ .file = &write_file.generated_directory } };
}

fn maybeUpdateName(write_file: *WriteFile) void {
    if (write_file.files.items.len == 1 and write_file.directories.items.len == 0) {
        // First time adding a file; update name.
        if (std.mem.eql(u8, write_file.step.name, "WriteFile")) {
            write_file.step.name = write_file.step.owner.fmt("WriteFile {s}", .{write_file.files.items[0].sub_path});
        }
    } else if (write_file.directories.items.len == 1 and write_file.files.items.len == 0) {
        // First time adding a directory; update name.
        if (std.mem.eql(u8, write_file.step.name, "WriteFile")) {
            write_file.step.name = write_file.step.owner.fmt("WriteFile {s}", .{write_file.directories.items[0].sub_path});
        }
    }
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;
    const b = step.owner;
    const arena = b.allocator;
    const gpa = arena;
    const write_file: *WriteFile = @fieldParentPtr("step", step);
    step.clearWatchInputs();

    // The cache is used here not really as a way to speed things up - because writing
    // the data to a file would probably be very fast - but as a way to find a canonical
    // location to put build artifacts.

    // If, for example, a hard-coded path was used as the location to put WriteFile
    // files, then two WriteFiles executing in parallel might clobber each other.

    var man = b.graph.cache.obtain();
    defer man.deinit();

    for (write_file.files.items) |file| {
        man.hash.addBytes(file.sub_path);

        switch (file.contents) {
            .bytes => |bytes| {
                man.hash.addBytes(bytes);
            },
            .copy => |lazy_path| {
                const path = lazy_path.getPath3(b, step);
                _ = try man.addFilePath(path, null);
                try step.addWatchInput(lazy_path);
            },
        }
    }

    const open_dir_cache = try arena.alloc(fs.Dir, write_file.directories.items.len);
    var open_dirs_count: usize = 0;
    defer closeDirs(open_dir_cache[0..open_dirs_count]);

    for (write_file.directories.items, open_dir_cache) |dir, *open_dir_cache_elem| {
        man.hash.addBytes(dir.sub_path);
        for (dir.options.exclude_extensions) |ext| man.hash.addBytes(ext);
        if (dir.options.include_extensions) |incs| for (incs) |inc| man.hash.addBytes(inc);

        const need_derived_inputs = try step.addDirectoryWatchInput(dir.source);
        const src_dir_path = dir.source.getPath3(b, step);

        var src_dir = src_dir_path.root_dir.handle.openDir(src_dir_path.subPathOrDot(), .{ .iterate = true }) catch |err| {
            return step.fail("unable to open source directory '{}': {s}", .{
                src_dir_path, @errorName(err),
            });
        };
        open_dir_cache_elem.* = src_dir;
        open_dirs_count += 1;

        var it = try src_dir.walk(gpa);
        defer it.deinit();
        while (try it.next()) |entry| {
            if (!dir.options.pathIncluded(entry.path)) continue;

            switch (entry.kind) {
                .directory => {
                    if (need_derived_inputs) {
                        const entry_path = try src_dir_path.join(arena, entry.path);
                        try step.addDirectoryWatchInputFromPath(entry_path);
                    }
                },
                .file => {
                    const entry_path = try src_dir_path.join(arena, entry.path);
                    _ = try man.addFilePath(entry_path, null);
                },
                else => continue,
            }
        }
    }

    if (try step.cacheHit(&man)) {
        const digest = man.final();
        write_file.generated_directory.path = try b.cache_root.join(arena, &.{ "o", &digest });
        step.result_cached = true;
        return;
    }

    const digest = man.final();
    const cache_path = "o" ++ fs.path.sep_str ++ digest;

    write_file.generated_directory.path = try b.cache_root.join(arena, &.{ "o", &digest });

    var cache_dir = b.cache_root.handle.makeOpenPath(cache_path, .{}) catch |err| {
        return step.fail("unable to make path '{}{s}': {s}", .{
            b.cache_root, cache_path, @errorName(err),
        });
    };
    defer cache_dir.close();

    const cwd = fs.cwd();

    for (write_file.files.items) |file| {
        if (fs.path.dirname(file.sub_path)) |dirname| {
            cache_dir.makePath(dirname) catch |err| {
                return step.fail("unable to make path '{}{s}{c}{s}': {s}", .{
                    b.cache_root, cache_path, fs.path.sep, dirname, @errorName(err),
                });
            };
        }
        switch (file.contents) {
            .bytes => |bytes| {
                cache_dir.writeFile(.{ .sub_path = file.sub_path, .data = bytes }) catch |err| {
                    return step.fail("unable to write file '{}{s}{c}{s}': {s}", .{
                        b.cache_root, cache_path, fs.path.sep, file.sub_path, @errorName(err),
                    });
                };
            },
            .copy => |file_source| {
                const source_path = file_source.getPath2(b, step);
                const prev_status = fs.Dir.updateFile(
                    cwd,
                    source_path,
                    cache_dir,
                    file.sub_path,
                    .{},
                ) catch |err| {
                    return step.fail("unable to update file from '{s}' to '{}{s}{c}{s}': {s}", .{
                        source_path,
                        b.cache_root,
                        cache_path,
                        fs.path.sep,
                        file.sub_path,
                        @errorName(err),
                    });
                };
                // At this point we already will mark the step as a cache miss.
                // But this is kind of a partial cache hit since individual
                // file copies may be avoided. Oh well, this information is
                // discarded.
                _ = prev_status;
            },
        }
    }

    for (write_file.directories.items, open_dir_cache) |dir, already_open_dir| {
        const src_dir_path = dir.source.getPath3(b, step);
        const dest_dirname = dir.sub_path;

        if (dest_dirname.len != 0) {
            cache_dir.makePath(dest_dirname) catch |err| {
                return step.fail("unable to make path '{}{s}{c}{s}': {s}", .{
                    b.cache_root, cache_path, fs.path.sep, dest_dirname, @errorName(err),
                });
            };
        }

        var it = try already_open_dir.walk(gpa);
        defer it.deinit();
        while (try it.next()) |entry| {
            if (!dir.options.pathIncluded(entry.path)) continue;

            const src_entry_path = try src_dir_path.join(arena, entry.path);
            const dest_path = b.pathJoin(&.{ dest_dirname, entry.path });
            switch (entry.kind) {
                .directory => try cache_dir.makePath(dest_path),
                .file => {
                    const prev_status = fs.Dir.updateFile(
                        src_entry_path.root_dir.handle,
                        src_entry_path.sub_path,
                        cache_dir,
                        dest_path,
                        .{},
                    ) catch |err| {
                        return step.fail("unable to update file from '{}' to '{}{s}{c}{s}': {s}", .{
                            src_entry_path, b.cache_root, cache_path, fs.path.sep, dest_path, @errorName(err),
                        });
                    };
                    _ = prev_status;
                },
                else => continue,
            }
        }
    }

    try step.writeManifest(&man);
}

fn closeDirs(dirs: []fs.Dir) void {
    for (dirs) |*d| d.close();
}
const builtin = @import("builtin");
const std = @import("../std.zig");
const Watch = @This();
const Step = std.Build.Step;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const fatal = std.zig.fatal;

dir_table: DirTable,
os: Os,
generation: Generation,

pub const have_impl = Os != void;

/// Key is the directory to watch which contains one or more files we are
/// interested in noticing changes to.
///
/// Value is generation.
const DirTable = std.ArrayHashMapUnmanaged(Cache.Path, void, Cache.Path.TableAdapter, false);

/// Special key of "." means any changes in this directory trigger the steps.
const ReactionSet = std.StringArrayHashMapUnmanaged(StepSet);
const StepSet = std.AutoArrayHashMapUnmanaged(*Step, Generation);

const Generation = u8;

const Hash = std.hash.Wyhash;
const Cache = std.Build.Cache;

const Os = switch (builtin.os.tag) {
    .linux => struct {
        const posix = std.posix;

        /// Keyed differently but indexes correspond 1:1 with `dir_table`.
        handle_table: HandleTable,
        poll_fds: [1]posix.pollfd,

        const HandleTable = std.ArrayHashMapUnmanaged(FileHandle, ReactionSet, FileHandle.Adapter, false);

        const fan_mask: std.os.linux.fanotify.MarkMask = .{
            .CLOSE_WRITE = true,
            .CREATE = true,
            .DELETE = true,
            .DELETE_SELF = true,
            .EVENT_ON_CHILD = true,
            .MOVED_FROM = true,
            .MOVED_TO = true,
            .MOVE_SELF = true,
            .ONDIR = true,
        };

        const FileHandle = struct {
            handle: *align(1) std.os.linux.file_handle,

            fn clone(lfh: FileHandle, gpa: Allocator) Allocator.Error!FileHandle {
                const bytes = lfh.slice();
                const new_ptr = try gpa.alignedAlloc(
                    u8,
                    .of(std.os.linux.file_handle),
                    @sizeOf(std.os.linux.file_handle) + bytes.len,
                );
                const new_header: *std.os.linux.file_handle = @ptrCast(new_ptr);
                new_header.* = lfh.handle.*;
                const new: FileHandle = .{ .handle = new_header };
                @memcpy(new.slice(), lfh.slice());
                return new;
            }

            fn destroy(lfh: FileHandle, gpa: Allocator) void {
                const ptr: [*]u8 = @ptrCast(lfh.handle);
                const allocated_slice = ptr[0 .. @sizeOf(std.os.linux.file_handle) + lfh.handle.handle_bytes];
                return gpa.free(allocated_slice);
            }

            fn slice(lfh: FileHandle) []u8 {
                const ptr: [*]u8 = &lfh.handle.f_handle;
                return ptr[0..lfh.handle.handle_bytes];
            }

            const Adapter = struct {
                pub fn hash(self: Adapter, a: FileHandle) u32 {
                    _ = self;
                    const unsigned_type: u32 = @bitCast(a.handle.handle_type);
                    return @truncate(Hash.hash(unsigned_type, a.slice()));
                }
                pub fn eql(self: Adapter, a: FileHandle, b: FileHandle, b_index: usize) bool {
                    _ = self;
                    _ = b_index;
                    return a.handle.handle_type == b.handle.handle_type and std.mem.eql(u8, a.slice(), b.slice());
                }
            };
        };

        fn init() !Watch {
            const fan_fd = std.posix.fanotify_init(.{
                .CLASS = .NOTIF,
                .CLOEXEC = true,
                .NONBLOCK = true,
                .REPORT_NAME = true,
                .REPORT_DIR_FID = true,
                .REPORT_FID = true,
                .REPORT_TARGET_FID = true,
            }, 0) catch |err| switch (err) {
                error.UnsupportedFlags => fatal("fanotify_init failed due to old kernel; requires 5.17+", .{}),
                else => |e| return e,
            };
            return .{
                .dir_table = .{},
                .os = switch (builtin.os.tag) {
                    .linux => .{
                        .handle_table = .{},
                        .poll_fds = .{
                            .{
                                .fd = fan_fd,
                                .events = std.posix.POLL.IN,
                                .revents = undefined,
                            },
                        },
                    },
                    else => {},
                },
                .generation = 0,
            };
        }

        fn getDirHandle(gpa: Allocator, path: std.Build.Cache.Path) !FileHandle {
            var file_handle_buffer: [@sizeOf(std.os.linux.file_handle) + 128]u8 align(@alignOf(std.os.linux.file_handle)) = undefined;
            var mount_id: i32 = undefined;
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const adjusted_path = if (path.sub_path.len == 0) "./" else std.fmt.bufPrint(&buf, "{s}/", .{
                path.sub_path,
            }) catch return error.NameTooLong;
            const stack_ptr: *std.os.linux.file_handle = @ptrCast(&file_handle_buffer);
            stack_ptr.handle_bytes = file_handle_buffer.len - @sizeOf(std.os.linux.file_handle);
            try posix.name_to_handle_at(path.root_dir.handle.fd, adjusted_path, stack_ptr, &mount_id, std.os.linux.AT.HANDLE_FID);
            const stack_lfh: FileHandle = .{ .handle = stack_ptr };
            return stack_lfh.clone(gpa);
        }

        fn markDirtySteps(w: *Watch, gpa: Allocator) !bool {
            const fan_fd = w.os.getFanFd();
            const fanotify = std.os.linux.fanotify;
            const M = fanotify.event_metadata;
            var events_buf: [256 + 4096]u8 = undefined;
            var any_dirty = false;
            while (true) {
                var len = posix.read(fan_fd, &events_buf) catch |err| switch (err) {
                    error.WouldBlock => return any_dirty,
                    else => |e| return e,
                };
                var meta: [*]align(1) M = @ptrCast(&events_buf);
                while (len >= @sizeOf(M) and meta[0].event_len >= @sizeOf(M) and meta[0].event_len <= len) : ({
                    len -= meta[0].event_len;
                    meta = @ptrCast(@as([*]u8, @ptrCast(meta)) + meta[0].event_len);
                }) {
                    assert(meta[0].vers == M.VERSION);
                    if (meta[0].mask.Q_OVERFLOW) {
                        any_dirty = true;
                        std.log.warn("file system watch queue overflowed; falling back to fstat", .{});
                        markAllFilesDirty(w, gpa);
                        return true;
                    }
                    const fid: *align(1) fanotify.event_info_fid = @ptrCast(meta + 1);
                    switch (fid.hdr.info_type) {
                        .DFID_NAME => {
                            const file_handle: *align(1) std.os.linux.file_handle = @ptrCast(&fid.handle);
                            const file_name_z: [*:0]u8 = @ptrCast((&file_handle.f_handle).ptr + file_handle.handle_bytes);
                            const file_name = std.mem.span(file_name_z);
                            const lfh: FileHandle = .{ .handle = file_handle };
                            if (w.os.handle_table.getPtr(lfh)) |reaction_set| {
                                if (reaction_set.getPtr(".")) |glob_set|
                                    any_dirty = markStepSetDirty(gpa, glob_set, any_dirty);
                                if (reaction_set.getPtr(file_name)) |step_set|
                                    any_dirty = markStepSetDirty(gpa, step_set, any_dirty);
                            }
                        },
                        else => |t| std.log.warn("unexpected fanotify event '{s}'", .{@tagName(t)}),
                    }
                }
            }
        }

        fn getFanFd(os: *const @This()) posix.fd_t {
            return os.poll_fds[0].fd;
        }

        fn update(w: *Watch, gpa: Allocator, steps: []const *Step) !void {
            const fan_fd = w.os.getFanFd();
            // Add missing marks and note persisted ones.
            for (steps) |step| {
                for (step.inputs.table.keys(), step.inputs.table.values()) |path, *files| {
                    const reaction_set = rs: {
                        const gop = try w.dir_table.getOrPut(gpa, path);
                        if (!gop.found_existing) {
                            const dir_handle = try Os.getDirHandle(gpa, path);
                            // `dir_handle` may already be present in the table in
                            // the case that we have multiple Cache.Path instances
                            // that compare inequal but ultimately point to the same
                            // directory on the file system.
                            // In such case, we must revert adding this directory, but keep
                            // the additions to the step set.
                            const dh_gop = try w.os.handle_table.getOrPut(gpa, dir_handle);
                            if (dh_gop.found_existing) {
                                _ = w.dir_table.pop();
                            } else {
                                assert(dh_gop.index == gop.index);
                                dh_gop.value_ptr.* = .{};
                                posix.fanotify_mark(fan_fd, .{
                                    .ADD = true,
                                    .ONLYDIR = true,
                                }, fan_mask, path.root_dir.handle.fd, path.subPathOrDot()) catch |err| {
                                    fatal("unable to watch {}: {s}", .{ path, @errorName(err) });
                                };
                            }
                            break :rs dh_gop.value_ptr;
                        }
                        break :rs &w.os.handle_table.values()[gop.index];
                    };
                    for (files.items) |basename| {
                        const gop = try reaction_set.getOrPut(gpa, basename);
                        if (!gop.found_existing) gop.value_ptr.* = .{};
                        try gop.value_ptr.put(gpa, step, w.generation);
                    }
                }
            }

            {
                // Remove marks for files that are no longer inputs.
                var i: usize = 0;
                while (i < w.os.handle_table.entries.len) {
                    {
                        const reaction_set = &w.os.handle_table.values()[i];
                        var step_set_i: usize = 0;
                        while (step_set_i < reaction_set.entries.len) {
                            const step_set = &reaction_set.values()[step_set_i];
                            var dirent_i: usize = 0;
                            while (dirent_i < step_set.entries.len) {
                                const generations = step_set.values();
                                if (generations[dirent_i] == w.generation) {
                                    dirent_i += 1;
                                    continue;
                                }
                                step_set.swapRemoveAt(dirent_i);
                            }
                            if (step_set.entries.len > 0) {
                                step_set_i += 1;
                                continue;
                            }
                            reaction_set.swapRemoveAt(step_set_i);
                        }
                        if (reaction_set.entries.len > 0) {
                            i += 1;
                            continue;
                        }
                    }

                    const path = w.dir_table.keys()[i];

                    posix.fanotify_mark(fan_fd, .{
                        .REMOVE = true,
                        .ONLYDIR = true,
                    }, fan_mask, path.root_dir.handle.fd, path.subPathOrDot()) catch |err| switch (err) {
                        error.FileNotFound => {}, // Expected, harmless.
                        else => |e| std.log.warn("unable to unwatch '{}': {s}", .{ path, @errorName(e) }),
                    };

                    w.dir_table.swapRemoveAt(i);
                    w.os.handle_table.swapRemoveAt(i);
                }
                w.generation +%= 1;
            }
        }

        fn wait(w: *Watch, gpa: Allocator, timeout: Timeout) !WaitResult {
            const events_len = try std.posix.poll(&w.os.poll_fds, timeout.to_i32_ms());
            return if (events_len == 0)
                .timeout
            else if (try Os.markDirtySteps(w, gpa))
                .dirty
            else
                .clean;
        }
    },
    .windows => struct {
        const windows = std.os.windows;

        /// Keyed differently but indexes correspond 1:1 with `dir_table`.
        handle_table: HandleTable,
        dir_list: std.AutoArrayHashMapUnmanaged(usize, *Directory),
        io_cp: ?windows.HANDLE,
        counter: usize = 0,

        const HandleTable = std.AutoArrayHashMapUnmanaged(FileId, ReactionSet);

        const FileId = struct {
            volumeSerialNumber: windows.ULONG,
            indexNumber: windows.LARGE_INTEGER,
        };

        const Directory = struct {
            handle: windows.HANDLE,
            id: FileId,
            overlapped: windows.OVERLAPPED,
            // 64 KB is the packet size limit when monitoring over a network.
            // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw#remarks
            buffer: [64 * 1024]u8 align(@alignOf(windows.FILE_NOTIFY_INFORMATION)) = undefined,

            /// Start listening for events, buffer field will be overwritten eventually.
            fn startListening(self: *@This()) !void {
                const r = windows.kernel32.ReadDirectoryChangesW(
                    self.handle,
                    @ptrCast(&self.buffer),
                    self.buffer.len,
                    0,
                    .{
                        .creation = true,
                        .dir_name = true,
                        .file_name = true,
                        .last_write = true,
                        .size = true,
                    },
                    null,
                    &self.overlapped,
                    null,
                );
                if (r == windows.FALSE) {
                    switch (windows.GetLastError()) {
                        .INVALID_FUNCTION => return error.ReadDirectoryChangesUnsupported,
                        else => |err| return windows.unexpectedError(err),
                    }
                }
            }

            fn init(gpa: Allocator, path: Cache.Path) !*@This() {
                // The following code is a drawn out NtCreateFile call. (mostly adapted from std.fs.Dir.makeOpenDirAccessMaskW)
                // It's necessary in order to get the specific flags that are required when calling ReadDirectoryChangesW.
                var dir_handle: windows.HANDLE = undefined;
                const root_fd = path.root_dir.handle.fd;
                const sub_path = path.subPathOrDot();
                const sub_path_w = try windows.sliceToPrefixedFileW(root_fd, sub_path);
                const path_len_bytes = std.math.cast(u16, sub_path_w.len * 2) orelse return error.NameTooLong;

                var nt_name = windows.UNICODE_STRING{
                    .Length = @intCast(path_len_bytes),
                    .MaximumLength = @intCast(path_len_bytes),
                    .Buffer = @constCast(sub_path_w.span().ptr),
                };
                var attr = windows.OBJECT_ATTRIBUTES{
                    .Length = @sizeOf(windows.OBJECT_ATTRIBUTES),
                    .RootDirectory = if (std.fs.path.isAbsoluteWindowsW(sub_path_w.span())) null else root_fd,
                    .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
                    .ObjectName = &nt_name,
                    .SecurityDescriptor = null,
                    .SecurityQualityOfService = null,
                };
                var io: windows.IO_STATUS_BLOCK = undefined;

                switch (windows.ntdll.NtCreateFile(
                    &dir_handle,
                    windows.SYNCHRONIZE | windows.GENERIC_READ | windows.FILE_LIST_DIRECTORY,
                    &attr,
                    &io,
                    null,
                    0,
                    windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE,
                    windows.FILE_OPEN,
                    windows.FILE_DIRECTORY_FILE | windows.FILE_OPEN_FOR_BACKUP_INTENT,
                    null,
                    0,
                )) {
                    .SUCCESS => {},
                    .OBJECT_NAME_INVALID => return error.BadPathName,
                    .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
                    .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
                    .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
                    .NOT_A_DIRECTORY => return error.NotDir,
                    // This can happen if the directory has 'List folder contents' permission set to 'Deny'
                    .ACCESS_DENIED => return error.AccessDenied,
                    .INVALID_PARAMETER => unreachable,
                    else => |rc| return windows.unexpectedStatus(rc),
                }
                assert(dir_handle != windows.INVALID_HANDLE_VALUE);
                errdefer windows.CloseHandle(dir_handle);

                const dir_id = try getFileId(dir_handle);

                const dir_ptr = try gpa.create(@This());
                dir_ptr.* = .{
                    .handle = dir_handle,
                    .id = dir_id,
                    .overlapped = std.mem.zeroes(windows.OVERLAPPED),
                };
                return dir_ptr;
            }

            fn deinit(self: *@This(), gpa: Allocator) void {
                _ = windows.kernel32.CancelIo(self.handle);
                windows.CloseHandle(self.handle);
                gpa.destroy(self);
            }
        };

        fn init() !Watch {
            return .{
                .dir_table = .{},
                .os = switch (builtin.os.tag) {
                    .windows => .{
                        .handle_table = .{},
                        .dir_list = .{},
                        .io_cp = null,
                    },
                    else => {},
                },
                .generation = 0,
            };
        }

        fn getFileId(handle: windows.HANDLE) !FileId {
            var file_id: FileId = undefined;
            var io_status: windows.IO_STATUS_BLOCK = undefined;
            var volume_info: windows.FILE_FS_VOLUME_INFORMATION = undefined;
            switch (windows.ntdll.NtQueryVolumeInformationFile(
                handle,
                &io_status,
                &volume_info,
                @sizeOf(windows.FILE_FS_VOLUME_INFORMATION),
                .FileFsVolumeInformation,
            )) {
                .SUCCESS => {},
                // Buffer overflow here indicates that there is more information available than was able to be stored in the buffer
                // size provided. This is treated as success because the type of variable-length information that this would be relevant for
                // (name, volume name, etc) we don't care about.
                .BUFFER_OVERFLOW => {},
                else => |rc| return windows.unexpectedStatus(rc),
            }
            file_id.volumeSerialNumber = volume_info.VolumeSerialNumber;
            var internal_info: windows.FILE_INTERNAL_INFORMATION = undefined;
            switch (windows.ntdll.NtQueryInformationFile(
                handle,
                &io_status,
                &internal_info,
                @sizeOf(windows.FILE_INTERNAL_INFORMATION),
                .FileInternalInformation,
            )) {
                .SUCCESS => {},
                else => |rc| return windows.unexpectedStatus(rc),
            }
            file_id.indexNumber = internal_info.IndexNumber;
            return file_id;
        }

        fn markDirtySteps(w: *Watch, gpa: Allocator, dir: *Directory) !bool {
            var any_dirty = false;
            const bytes_returned = try windows.GetOverlappedResult(dir.handle, &dir.overlapped, false);
            if (bytes_returned == 0) {
                std.log.warn("file system watch queue overflowed; falling back to fstat", .{});
                markAllFilesDirty(w, gpa);
                try dir.startListening();
                return true;
            }
            var file_name_buf: [std.fs.max_path_bytes]u8 = undefined;
            var notify: *align(1) windows.FILE_NOTIFY_INFORMATION = undefined;
            var offset: usize = 0;
            while (true) {
                notify = @ptrCast(&dir.buffer[offset]);
                const file_name_field: [*]u16 = @ptrFromInt(@intFromPtr(notify) + @sizeOf(windows.FILE_NOTIFY_INFORMATION));
                const file_name_len = std.unicode.wtf16LeToWtf8(&file_name_buf, file_name_field[0 .. notify.FileNameLength / 2]);
                const file_name = file_name_buf[0..file_name_len];
                if (w.os.handle_table.getIndex(dir.id)) |reaction_set_i| {
                    const reaction_set = w.os.handle_table.values()[reaction_set_i];
                    if (reaction_set.getPtr(".")) |glob_set|
                        any_dirty = markStepSetDirty(gpa, glob_set, any_dirty);
                    if (reaction_set.getPtr(file_name)) |step_set| {
                        any_dirty = markStepSetDirty(gpa, step_set, any_dirty);
                    }
                }
                if (notify.NextEntryOffset == 0)
                    break;

                offset += notify.NextEntryOffset;
            }

            // We call this now since at this point we have finished reading dir.buffer.
            try dir.startListening();
            return any_dirty;
        }

        fn update(w: *Watch, gpa: Allocator, steps: []const *Step) !void {
            // Add missing marks and note persisted ones.
            for (steps) |step| {
                for (step.inputs.table.keys(), step.inputs.table.values()) |path, *files| {
                    const reaction_set = rs: {
                        const gop = try w.dir_table.getOrPut(gpa, path);
                        if (!gop.found_existing) {
                            const dir = try Os.Directory.init(gpa, path);
                            errdefer dir.deinit(gpa);
                            // `dir.id` may already be present in the table in
                            // the case that we have multiple Cache.Path instances
                            // that compare inequal but ultimately point to the same
                            // directory on the file system.
                            // In such case, we must revert adding this directory, but keep
                            // the additions to the step set.
                            const dh_gop = try w.os.handle_table.getOrPut(gpa, dir.id);
                            if (dh_gop.found_existing) {
                                dir.deinit(gpa);
                                _ = w.dir_table.pop();
                            } else {
                                assert(dh_gop.index == gop.index);
                                dh_gop.value_ptr.* = .{};
                                try dir.startListening();
                                const key = w.os.counter;
                                w.os.counter +%= 1;
                                try w.os.dir_list.put(gpa, key, dir);
                                w.os.io_cp = try windows.CreateIoCompletionPort(
                                    dir.handle,
                                    w.os.io_cp,
                                    key,
                                    0,
                                );
                            }
                            break :rs &w.os.handle_table.values()[dh_gop.index];
                        }
                        break :rs &w.os.handle_table.values()[gop.index];
                    };
                    for (files.items) |basename| {
                        const gop = try reaction_set.getOrPut(gpa, basename);
                        if (!gop.found_existing) gop.value_ptr.* = .{};
                        try gop.value_ptr.put(gpa, step, w.generation);
                    }
                }
            }

            {
                // Remove marks for files that are no longer inputs.
                var i: usize = 0;
                while (i < w.os.handle_table.entries.len) {
                    {
                        const reaction_set = &w.os.handle_table.values()[i];
                        var step_set_i: usize = 0;
                        while (step_set_i < reaction_set.entries.len) {
                            const step_set = &reaction_set.values()[step_set_i];
                            var dirent_i: usize = 0;
                            while (dirent_i < step_set.entries.len) {
                                const generations = step_set.values();
                                if (generations[dirent_i] == w.generation) {
                                    dirent_i += 1;
                                    continue;
                                }
                                step_set.swapRemoveAt(dirent_i);
                            }
                            if (step_set.entries.len > 0) {
                                step_set_i += 1;
                                continue;
                            }
                            reaction_set.swapRemoveAt(step_set_i);
                        }
                        if (reaction_set.entries.len > 0) {
                            i += 1;
                            continue;
                        }
                    }

                    w.os.dir_list.values()[i].deinit(gpa);
                    w.os.dir_list.swapRemoveAt(i);
                    w.dir_table.swapRemoveAt(i);
                    w.os.handle_table.swapRemoveAt(i);
                }
                w.generation +%= 1;
            }
        }

        fn wait(w: *Watch, gpa: Allocator, timeout: Timeout) !WaitResult {
            var bytes_transferred: std.os.windows.DWORD = undefined;
            var key: usize = undefined;
            var overlapped_ptr: ?*std.os.windows.OVERLAPPED = undefined;
            return while (true) switch (std.os.windows.GetQueuedCompletionStatus(
                w.os.io_cp.?,
                &bytes_transferred,
                &key,
                &overlapped_ptr,
                @bitCast(timeout.to_i32_ms()),
            )) {
                .Normal => {
                    if (bytes_transferred == 0)
                        break error.Unexpected;

                    // This 'orelse' detects a race condition that happens when we receive a
                    // completion notification for a directory that no longer exists in our list.
                    const dir = w.os.dir_list.get(key) orelse break .clean;

                    break if (try Os.markDirtySteps(w, gpa, dir))
                        .dirty
                    else
                        .clean;
                },
                ```
