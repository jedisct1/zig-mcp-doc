```
            return std.fmt.allocPrint(allocator, "{s}{s}", .{ root_name, suffix });
            },
            .Obj => return std.fmt.allocPrint(allocator, "{s}.obj", .{root_name}),
        },
        .elf, .goff, .xcoff => switch (options.output_mode) {
            .Exe => return allocator.dupe(u8, root_name),
            .Lib => {
                switch (options.link_mode orelse .static) {
                    .static => return std.fmt.allocPrint(allocator, "{s}{s}.a", .{
                        t.libPrefix(), root_name,
                    }),
                    .dynamic => {
                        if (options.version) |ver| {
                            return std.fmt.allocPrint(allocator, "{s}{s}.so.{d}.{d}.{d}", .{
                                t.libPrefix(), root_name, ver.major, ver.minor, ver.patch,
                            });
                        } else {
                            return std.fmt.allocPrint(allocator, "{s}{s}.so", .{
                                t.libPrefix(), root_name,
                            });
                        }
                    },
                }
            },
            .Obj => return std.fmt.allocPrint(allocator, "{s}.o", .{root_name}),
        },
        .macho => switch (options.output_mode) {
            .Exe => return allocator.dupe(u8, root_name),
            .Lib => {
                switch (options.link_mode orelse .static) {
                    .static => return std.fmt.allocPrint(allocator, "{s}{s}.a", .{
                        t.libPrefix(), root_name,
                    }),
                    .dynamic => {
                        if (options.version) |ver| {
                            return std.fmt.allocPrint(allocator, "{s}{s}.{d}.{d}.{d}.dylib", .{
                                t.libPrefix(), root_name, ver.major, ver.minor, ver.patch,
                            });
                        } else {
                            return std.fmt.allocPrint(allocator, "{s}{s}.dylib", .{
                                t.libPrefix(), root_name,
                            });
                        }
                    },
                }
            },
            .Obj => return std.fmt.allocPrint(allocator, "{s}.o", .{root_name}),
        },
        .wasm => switch (options.output_mode) {
            .Exe => return std.fmt.allocPrint(allocator, "{s}{s}", .{ root_name, t.exeFileExt() }),
            .Lib => {
                switch (options.link_mode orelse .static) {
                    .static => return std.fmt.allocPrint(allocator, "{s}{s}.a", .{
                        t.libPrefix(), root_name,
                    }),
                    .dynamic => return std.fmt.allocPrint(allocator, "{s}.wasm", .{root_name}),
                }
            },
            .Obj => return std.fmt.allocPrint(allocator, "{s}.o", .{root_name}),
        },
        .c => return std.fmt.allocPrint(allocator, "{s}.c", .{root_name}),
        .spirv => return std.fmt.allocPrint(allocator, "{s}.spv", .{root_name}),
        .hex => return std.fmt.allocPrint(allocator, "{s}.ihex", .{root_name}),
        .raw => return std.fmt.allocPrint(allocator, "{s}.bin", .{root_name}),
        .plan9 => switch (options.output_mode) {
            .Exe => return allocator.dupe(u8, root_name),
            .Obj => return std.fmt.allocPrint(allocator, "{s}{s}", .{
                root_name, t.ofmt.fileExt(t.cpu.arch),
            }),
            .Lib => return std.fmt.allocPrint(allocator, "{s}{s}.a", .{
                t.libPrefix(), root_name,
            }),
        },
        .nvptx => return std.fmt.allocPrint(allocator, "{s}.ptx", .{root_name}),
    }
}

pub const SanitizeC = enum {
    off,
    trap,
    full,
};

pub const BuildId = union(enum) {
    none,
    fast,
    uuid,
    sha1,
    md5,
    hexstring: HexString,

    pub fn eql(a: BuildId, b: BuildId) bool {
        const Tag = @typeInfo(BuildId).@"union".tag_type.?;
        const a_tag: Tag = a;
        const b_tag: Tag = b;
        if (a_tag != b_tag) return false;
        return switch (a) {
            .none, .fast, .uuid, .sha1, .md5 => true,
            .hexstring => |a_hexstring| std.mem.eql(u8, a_hexstring.toSlice(), b.hexstring.toSlice()),
        };
    }

    pub const HexString = struct {
        bytes: [32]u8,
        len: u8,

        /// Result is byte values, *not* hex-encoded.
        pub fn toSlice(hs: *const HexString) []const u8 {
            return hs.bytes[0..hs.len];
        }
    };

    /// Input is byte values, *not* hex-encoded.
    /// Asserts `bytes` fits inside `HexString`
    pub fn initHexString(bytes: []const u8) BuildId {
        var result: BuildId = .{ .hexstring = .{
            .bytes = undefined,
            .len = @intCast(bytes.len),
        } };
        @memcpy(result.hexstring.bytes[0..bytes.len], bytes);
        return result;
    }

    /// Converts UTF-8 text to a `BuildId`.
    pub fn parse(text: []const u8) !BuildId {
        if (std.mem.eql(u8, text, "none")) {
            return .none;
        } else if (std.mem.eql(u8, text, "fast")) {
            return .fast;
        } else if (std.mem.eql(u8, text, "uuid")) {
            return .uuid;
        } else if (std.mem.eql(u8, text, "sha1") or std.mem.eql(u8, text, "tree")) {
            return .sha1;
        } else if (std.mem.eql(u8, text, "md5")) {
            return .md5;
        } else if (std.mem.startsWith(u8, text, "0x")) {
            var result: BuildId = .{ .hexstring = undefined };
            const slice = try std.fmt.hexToBytes(&result.hexstring.bytes, text[2..]);
            result.hexstring.len = @as(u8, @intCast(slice.len));
            return result;
        }
        return error.InvalidBuildIdStyle;
    }

    test parse {
        try std.testing.expectEqual(BuildId.md5, try parse("md5"));
        try std.testing.expectEqual(BuildId.none, try parse("none"));
        try std.testing.expectEqual(BuildId.fast, try parse("fast"));
        try std.testing.expectEqual(BuildId.uuid, try parse("uuid"));
        try std.testing.expectEqual(BuildId.sha1, try parse("sha1"));
        try std.testing.expectEqual(BuildId.sha1, try parse("tree"));

        try std.testing.expect(BuildId.initHexString("").eql(try parse("0x")));
        try std.testing.expect(BuildId.initHexString("\x12\x34\x56").eql(try parse("0x123456")));
        try std.testing.expectError(error.InvalidLength, parse("0x12-34"));
        try std.testing.expectError(error.InvalidCharacter, parse("0xfoobbb"));
        try std.testing.expectError(error.InvalidBuildIdStyle, parse("yaddaxxx"));
    }
};

pub const LtoMode = enum { none, full, thin };

/// Renders a `std.Target.Cpu` value into a textual representation that can be parsed
/// via the `-mcpu` flag passed to the Zig compiler.
/// Appends the result to `buffer`.
pub fn serializeCpu(buffer: *std.ArrayList(u8), cpu: std.Target.Cpu) Allocator.Error!void {
    const all_features = cpu.arch.allFeaturesList();
    var populated_cpu_features = cpu.model.features;
    populated_cpu_features.populateDependencies(all_features);

    try buffer.appendSlice(cpu.model.name);

    if (populated_cpu_features.eql(cpu.features)) {
        // The CPU name alone is sufficient.
        return;
    }

    for (all_features, 0..) |feature, i_usize| {
        const i: std.Target.Cpu.Feature.Set.Index = @intCast(i_usize);
        const in_cpu_set = populated_cpu_features.isEnabled(i);
        const in_actual_set = cpu.features.isEnabled(i);
        try buffer.ensureUnusedCapacity(feature.name.len + 1);
        if (in_cpu_set and !in_actual_set) {
            buffer.appendAssumeCapacity('-');
            buffer.appendSliceAssumeCapacity(feature.name);
        } else if (!in_cpu_set and in_actual_set) {
            buffer.appendAssumeCapacity('+');
            buffer.appendSliceAssumeCapacity(feature.name);
        }
    }
}

pub fn serializeCpuAlloc(ally: Allocator, cpu: std.Target.Cpu) Allocator.Error![]u8 {
    var buffer = std.ArrayList(u8).init(ally);
    try serializeCpu(&buffer, cpu);
    return buffer.toOwnedSlice();
}

const std = @import("std.zig");
const tokenizer = @import("zig/tokenizer.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Return a Formatter for a Zig identifier, escaping it with `@""` syntax if needed.
///
/// - An empty `{}` format specifier escapes invalid identifiers, identifiers that shadow primitives
///   and the reserved `_` identifier.
/// - Add `p` to the specifier to render identifiers that shadow primitives unescaped.
/// - Add `_` to the specifier to render the reserved `_` identifier unescaped.
/// - `p` and `_` can be combined, e.g. `{p_}`.
///
pub fn fmtId(bytes: []const u8) std.fmt.Formatter(formatId) {
    return .{ .data = bytes };
}

test fmtId {
    const expectFmt = std.testing.expectFmt;
    try expectFmt("@\"while\"", "{}", .{fmtId("while")});
    try expectFmt("@\"while\"", "{p}", .{fmtId("while")});
    try expectFmt("@\"while\"", "{_}", .{fmtId("while")});
    try expectFmt("@\"while\"", "{p_}", .{fmtId("while")});
    try expectFmt("@\"while\"", "{_p}", .{fmtId("while")});

    try expectFmt("hello", "{}", .{fmtId("hello")});
    try expectFmt("hello", "{p}", .{fmtId("hello")});
    try expectFmt("hello", "{_}", .{fmtId("hello")});
    try expectFmt("hello", "{p_}", .{fmtId("hello")});
    try expectFmt("hello", "{_p}", .{fmtId("hello")});

    try expectFmt("@\"type\"", "{}", .{fmtId("type")});
    try expectFmt("type", "{p}", .{fmtId("type")});
    try expectFmt("@\"type\"", "{_}", .{fmtId("type")});
    try expectFmt("type", "{p_}", .{fmtId("type")});
    try expectFmt("type", "{_p}", .{fmtId("type")});

    try expectFmt("@\"_\"", "{}", .{fmtId("_")});
    try expectFmt("@\"_\"", "{p}", .{fmtId("_")});
    try expectFmt("_", "{_}", .{fmtId("_")});
    try expectFmt("_", "{p_}", .{fmtId("_")});
    try expectFmt("_", "{_p}", .{fmtId("_")});

    try expectFmt("@\"i123\"", "{}", .{fmtId("i123")});
    try expectFmt("i123", "{p}", .{fmtId("i123")});
    try expectFmt("@\"4four\"", "{}", .{fmtId("4four")});
    try expectFmt("_underscore", "{}", .{fmtId("_underscore")});
    try expectFmt("@\"11\\\"23\"", "{}", .{fmtId("11\"23")});
    try expectFmt("@\"11\\x0f23\"", "{}", .{fmtId("11\x0F23")});

    // These are technically not currently legal in Zig.
    try expectFmt("@\"\"", "{}", .{fmtId("")});
    try expectFmt("@\"\\x00\"", "{}", .{fmtId("\x00")});
}

/// Print the string as a Zig identifier, escaping it with `@""` syntax if needed.
fn formatId(
    bytes: []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    const allow_primitive, const allow_underscore = comptime parse_fmt: {
        var allow_primitive = false;
        var allow_underscore = false;
        for (fmt) |char| {
            switch (char) {
                'p' => if (!allow_primitive) {
                    allow_primitive = true;
                    continue;
                },
                '_' => if (!allow_underscore) {
                    allow_underscore = true;
                    continue;
                },
                else => {},
            }
            @compileError("expected {}, {p}, {_}, {p_} or {_p}, found {" ++ fmt ++ "}");
        }
        break :parse_fmt .{ allow_primitive, allow_underscore };
    };

    if (isValidId(bytes) and
        (allow_primitive or !std.zig.isPrimitive(bytes)) and
        (allow_underscore or !isUnderscore(bytes)))
    {
        return writer.writeAll(bytes);
    }
    try writer.writeAll("@\"");
    try stringEscape(bytes, "", options, writer);
    try writer.writeByte('"');
}

/// Return a Formatter for Zig Escapes of a double quoted string.
/// The format specifier must be one of:
///  * `{}` treats contents as a double-quoted string.
///  * `{'}` treats contents as a single-quoted string.
pub fn fmtEscapes(bytes: []const u8) std.fmt.Formatter(stringEscape) {
    return .{ .data = bytes };
}

test fmtEscapes {
    const expectFmt = std.testing.expectFmt;
    try expectFmt("\\x0f", "{}", .{fmtEscapes("\x0f")});
    try expectFmt(
        \\" \\ hi \x07 \x11 " derp \'"
    , "\"{'}\"", .{fmtEscapes(" \\ hi \x07 \x11 \" derp '")});
    try expectFmt(
        \\" \\ hi \x07 \x11 \" derp '"
    , "\"{}\"", .{fmtEscapes(" \\ hi \x07 \x11 \" derp '")});
}

/// Print the string as escaped contents of a double quoted or single-quoted string.
/// Format `{}` treats contents as a double-quoted string.
/// Format `{'}` treats contents as a single-quoted string.
pub fn stringEscape(
    bytes: []const u8,
    comptime f: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    for (bytes) |byte| switch (byte) {
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        '\\' => try writer.writeAll("\\\\"),
        '"' => {
            if (f.len == 1 and f[0] == '\'') {
                try writer.writeByte('"');
            } else if (f.len == 0) {
                try writer.writeAll("\\\"");
            } else {
                @compileError("expected {} or {'}, found {" ++ f ++ "}");
            }
        },
        '\'' => {
            if (f.len == 1 and f[0] == '\'') {
                try writer.writeAll("\\'");
            } else if (f.len == 0) {
                try writer.writeByte('\'');
            } else {
                @compileError("expected {} or {'}, found {" ++ f ++ "}");
            }
        },
        ' ', '!', '#'...'&', '('...'[', ']'...'~' => try writer.writeByte(byte),
        // Use hex escapes for rest any unprintable characters.
        else => {
            try writer.writeAll("\\x");
            try std.fmt.formatInt(byte, 16, .lower, .{ .width = 2, .fill = '0' }, writer);
        },
    };
}

pub fn isValidId(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    for (bytes, 0..) |c, i| {
        switch (c) {
            '_', 'a'...'z', 'A'...'Z' => {},
            '0'...'9' => if (i == 0) return false,
            else => return false,
        }
    }
    return std.zig.Token.getKeyword(bytes) == null;
}

test isValidId {
    try std.testing.expect(!isValidId(""));
    try std.testing.expect(isValidId("foobar"));
    try std.testing.expect(!isValidId("a b c"));
    try std.testing.expect(!isValidId("3d"));
    try std.testing.expect(!isValidId("enum"));
    try std.testing.expect(isValidId("i386"));
}

pub fn isUnderscore(bytes: []const u8) bool {
    return bytes.len == 1 and bytes[0] == '_';
}

test isUnderscore {
    try std.testing.expect(isUnderscore("_"));
    try std.testing.expect(!isUnderscore("__"));
    try std.testing.expect(!isUnderscore("_foo"));
    try std.testing.expect(isUnderscore("\x5f"));
    try std.testing.expect(!isUnderscore("\\x5f"));
}

pub fn readSourceFileToEndAlloc(gpa: Allocator, input: std.fs.File, size_hint: ?usize) ![:0]u8 {
    const source_code = input.readToEndAllocOptions(
        gpa,
        max_src_size,
        size_hint,
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.ConnectionResetByPeer => unreachable,
        error.ConnectionTimedOut => unreachable,
        error.NotOpenForReading => unreachable,
        else => |e| return e,
    };
    errdefer gpa.free(source_code);

    // Detect unsupported file types with their Byte Order Mark
    const unsupported_boms = [_][]const u8{
        "\xff\xfe\x00\x00", // UTF-32 little endian
        "\xfe\xff\x00\x00", // UTF-32 big endian
        "\xfe\xff", // UTF-16 big endian
    };
    for (unsupported_boms) |bom| {
        if (std.mem.startsWith(u8, source_code, bom)) {
            return error.UnsupportedEncoding;
        }
    }

    // If the file starts with a UTF-16 little endian BOM, translate it to UTF-8
    if (std.mem.startsWith(u8, source_code, "\xff\xfe")) {
        if (source_code.len % 2 != 0) return error.InvalidEncoding;
        // TODO: after wrangle-writer-buffering branch is merged,
        // avoid this unnecessary allocation
        const aligned_copy = try gpa.alloc(u16, source_code.len / 2);
        defer gpa.free(aligned_copy);
        @memcpy(std.mem.sliceAsBytes(aligned_copy), source_code);
        const source_code_utf8 = std.unicode.utf16LeToUtf8AllocZ(gpa, aligned_copy) catch |err| switch (err) {
            error.DanglingSurrogateHalf => error.UnsupportedEncoding,
            error.ExpectedSecondSurrogateHalf => error.UnsupportedEncoding,
            error.UnexpectedSecondSurrogateHalf => error.UnsupportedEncoding,
            else => |e| return e,
        };
        gpa.free(source_code);
        return source_code_utf8;
    }

    return source_code;
}

pub fn printAstErrorsToStderr(gpa: Allocator, tree: Ast, path: []const u8, color: Color) !void {
    var wip_errors: std.zig.ErrorBundle.Wip = undefined;
    try wip_errors.init(gpa);
    defer wip_errors.deinit();

    try putAstErrorsIntoBundle(gpa, tree, path, &wip_errors);

    var error_bundle = try wip_errors.toOwnedBundle("");
    defer error_bundle.deinit(gpa);
    error_bundle.renderToStdErr(color.renderOptions());
}

pub fn putAstErrorsIntoBundle(
    gpa: Allocator,
    tree: Ast,
    path: []const u8,
    wip_errors: *std.zig.ErrorBundle.Wip,
) Allocator.Error!void {
    var zir = try AstGen.generate(gpa, tree);
    defer zir.deinit(gpa);

    try wip_errors.addZirErrorMessages(zir, tree, tree.source, path);
}

pub fn resolveTargetQueryOrFatal(target_query: std.Target.Query) std.Target {
    return std.zig.system.resolveTargetQuery(target_query) catch |err|
        fatal("unable to resolve target: {s}", .{@errorName(err)});
}

pub fn parseTargetQueryOrReportFatalError(
    allocator: Allocator,
    opts: std.Target.Query.ParseOptions,
) std.Target.Query {
    var opts_with_diags = opts;
    var diags: std.Target.Query.ParseOptions.Diagnostics = .{};
    if (opts_with_diags.diagnostics == null) {
        opts_with_diags.diagnostics = &diags;
    }
    return std.Target.Query.parse(opts_with_diags) catch |err| switch (err) {
        error.UnknownCpuModel => {
            help: {
                var help_text = std.ArrayList(u8).init(allocator);
                defer help_text.deinit();
                for (diags.arch.?.allCpuModels()) |cpu| {
                    help_text.writer().print(" {s}\n", .{cpu.name}) catch break :help;
                }
                std.log.info("available CPUs for architecture '{s}':\n{s}", .{
                    @tagName(diags.arch.?), help_text.items,
                });
            }
            fatal("unknown CPU: '{s}'", .{diags.cpu_name.?});
        },
        error.UnknownCpuFeature => {
            help: {
                var help_text = std.ArrayList(u8).init(allocator);
                defer help_text.deinit();
                for (diags.arch.?.allFeaturesList()) |feature| {
                    help_text.writer().print(" {s}: {s}\n", .{ feature.name, feature.description }) catch break :help;
                }
                std.log.info("available CPU features for architecture '{s}':\n{s}", .{
                    @tagName(diags.arch.?), help_text.items,
                });
            }
            fatal("unknown CPU feature: '{s}'", .{diags.unknown_feature_name.?});
        },
        error.UnknownObjectFormat => {
            help: {
                var help_text = std.ArrayList(u8).init(allocator);
                defer help_text.deinit();
                inline for (@typeInfo(std.Target.ObjectFormat).@"enum".fields) |field| {
                    help_text.writer().print(" {s}\n", .{field.name}) catch break :help;
                }
                std.log.info("available object formats:\n{s}", .{help_text.items});
            }
            fatal("unknown object format: '{s}'", .{opts.object_format.?});
        },
        error.UnknownArchitecture => {
            help: {
                var help_text = std.ArrayList(u8).init(allocator);
                defer help_text.deinit();
                inline for (@typeInfo(std.Target.Cpu.Arch).@"enum".fields) |field| {
                    help_text.writer().print(" {s}\n", .{field.name}) catch break :help;
                }
                std.log.info("available architectures:\n{s} native\n", .{help_text.items});
            }
            fatal("unknown architecture: '{s}'", .{diags.unknown_architecture_name.?});
        },
        else => |e| fatal("unable to parse target query '{s}': {s}", .{
            opts.arch_os_abi, @errorName(e),
        }),
    };
}

/// Deprecated; see `std.process.fatal`.
pub const fatal = std.process.fatal;

/// Collects all the environment variables that Zig could possibly inspect, so
/// that we can do reflection on this and print them with `zig env`.
pub const EnvVar = enum {
    ZIG_GLOBAL_CACHE_DIR,
    ZIG_LOCAL_CACHE_DIR,
    ZIG_LIB_DIR,
    ZIG_LIBC,
    ZIG_BUILD_RUNNER,
    ZIG_VERBOSE_LINK,
    ZIG_VERBOSE_CC,
    ZIG_BTRFS_WORKAROUND,
    ZIG_DEBUG_CMD,
    CC,
    NO_COLOR,
    CLICOLOR_FORCE,
    XDG_CACHE_HOME,
    HOME,

    pub fn isSet(comptime ev: EnvVar) bool {
        return std.process.hasNonEmptyEnvVarConstant(@tagName(ev));
    }

    pub fn get(ev: EnvVar, arena: std.mem.Allocator) !?[]u8 {
        if (std.process.getEnvVarOwned(arena, @tagName(ev))) |value| {
            return value;
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => return null,
            else => |e| return e,
        }
    }

    pub fn getPosix(comptime ev: EnvVar) ?[:0]const u8 {
        return std.posix.getenvZ(@tagName(ev));
    }
};

pub const SimpleComptimeReason = enum(u32) {
    // Evaluating at comptime because a builtin operand must be comptime-known.
    // These messages all mention a specific builtin.
    operand_Type,
    operand_setEvalBranchQuota,
    operand_setFloatMode,
    operand_branchHint,
    operand_setRuntimeSafety,
    operand_embedFile,
    operand_cImport,
    operand_cDefine_macro_name,
    operand_cDefine_macro_value,
    operand_cInclude_file_name,
    operand_cUndef_macro_name,
    operand_shuffle_mask,
    operand_atomicRmw_operation,
    operand_reduce_operation,

    // Evaluating at comptime because an operand must be comptime-known.
    // These messages do not mention a specific builtin (and may not be about a builtin at all).
    export_target,
    export_options,
    extern_options,
    prefetch_options,
    call_modifier,
    compile_error_string,
    inline_assembly_code,
    atomic_order,
    array_mul_factor,
    slice_cat_operand,
    inline_call_target,
    generic_call_target,
    wasm_memory_index,
    work_group_dim_index,

    // Evaluating at comptime because types must be comptime-known.
    // Reasons other than `.type` are just more specific messages.
    type,
    array_sentinel,
    pointer_sentinel,
    slice_sentinel,
    array_length,
    vector_length,
    error_set_contents,
    struct_fields,
    enum_fields,
    union_fields,
    function_ret_ty,
    function_parameters,

    // Evaluating at comptime because decl/field name must be comptime-known.
    decl_name,
    field_name,
    struct_field_name,
    enum_field_name,
    union_field_name,
    tuple_field_name,
    tuple_field_index,

    // Evaluating at comptime because it is an attribute of a global declaration.
    container_var_init,
    @"callconv",
    @"align",
    @"addrspace",
    @"linksection",

    // Miscellaneous reasons.
    comptime_keyword,
    comptime_call_modifier,
    inline_loop_operand,
    switch_item,
    tuple_field_default_value,
    struct_field_default_value,
    enum_field_tag_value,
    slice_single_item_ptr_bounds,
    stored_to_comptime_field,
    stored_to_comptime_var,
    casted_to_comptime_enum,
    casted_to_comptime_int,
    casted_to_comptime_float,
    panic_handler,

    pub fn message(r: SimpleComptimeReason) []const u8 {
        return switch (r) {
            // zig fmt: off
            .operand_Type                => "operand to '@Type' must be comptime-known",
            .operand_setEvalBranchQuota  => "operand to '@setEvalBranchQuota' must be comptime-known",
            .operand_setFloatMode        => "operand to '@setFloatMode' must be comptime-known",
            .operand_branchHint          => "operand to '@branchHint' must be comptime-known",
            .operand_setRuntimeSafety    => "operand to '@setRuntimeSafety' must be comptime-known",
            .operand_embedFile           => "operand to '@embedFile' must be comptime-known",
            .operand_cImport             => "operand to '@cImport' is evaluated at comptime",
            .operand_cDefine_macro_name  => "'@cDefine' macro name must be comptime-known",
            .operand_cDefine_macro_value => "'@cDefine' macro value must be comptime-known",
            .operand_cInclude_file_name  => "'@cInclude' file name must be comptime-known",
            .operand_cUndef_macro_name   => "'@cUndef' macro name must be comptime-known",
            .operand_shuffle_mask        => "'@shuffle' mask must be comptime-known",
            .operand_atomicRmw_operation => "'@atomicRmw' operation must be comptime-known",
            .operand_reduce_operation    => "'@reduce' operation must be comptime-known",

            .export_target        => "export target must be comptime-known",
            .export_options       => "export options must be comptime-known",
            .extern_options       => "extern options must be comptime-known",
            .prefetch_options     => "prefetch options must be comptime-known",
            .call_modifier        => "call modifier must be comptime-known",
            .compile_error_string => "compile error string must be comptime-known",
            .inline_assembly_code => "inline assembly code must be comptime-known",
            .atomic_order         => "atomic order must be comptime-known",
            .array_mul_factor     => "array multiplication factor must be comptime-known",
            .slice_cat_operand    => "slice being concatenated must be comptime-known",
            .inline_call_target   => "function being called inline must be comptime-known",
            .generic_call_target  => "generic function being called must be comptime-known",
            .wasm_memory_index    => "wasm memory index must be comptime-known",
            .work_group_dim_index => "work group dimension index must be comptime-known",

            .type                => "types must be comptime-known",
            .array_sentinel      => "array sentinel value must be comptime-known",
            .pointer_sentinel    => "pointer sentinel value must be comptime-known",
            .slice_sentinel      => "slice sentinel value must be comptime-known",
            .array_length        => "array length must be comptime-known",
            .vector_length       => "vector length must be comptime-known",
            .error_set_contents  => "error set contents must be comptime-known",
            .struct_fields       => "struct fields must be comptime-known",
            .enum_fields         => "enum fields must be comptime-known",
            .union_fields        => "union fields must be comptime-known",
            .function_ret_ty     => "function return type must be comptime-known",
            .function_parameters => "function parameters must be comptime-known",

            .decl_name         => "declaration name must be comptime-known",
            .field_name        => "field name must be comptime-known",
            .struct_field_name => "struct field name must be comptime-known",
            .enum_field_name   => "enum field name must be comptime-known",
            .union_field_name  => "union field name must be comptime-known",
            .tuple_field_name  => "tuple field name must be comptime-known",
            .tuple_field_index => "tuple field index must be comptime-known",

            .container_var_init => "initializer of container-level variable must be comptime-known",
            .@"callconv"        => "calling convention must be comptime-known",
            .@"align"           => "alignment must be comptime-known",
            .@"addrspace"       => "address space must be comptime-known",
            .@"linksection"     => "linksection must be comptime-known",

            .comptime_keyword             => "'comptime' keyword forces comptime evaluation",
            .comptime_call_modifier       => "'.compile_time' call modifier forces comptime evaluation",
            .inline_loop_operand          => "inline loop condition must be comptime-known",
            .switch_item                  => "switch prong values must be comptime-known",
            .tuple_field_default_value    => "tuple field default value must be comptime-known",
            .struct_field_default_value   => "struct field default value must be comptime-known",
            .enum_field_tag_value         => "enum field tag value must be comptime-known",
            .slice_single_item_ptr_bounds => "slice of single-item pointer must have comptime-known bounds",
            .stored_to_comptime_field     => "value stored to a comptime field must be comptime-known",
            .stored_to_comptime_var       => "value stored to a comptime variable must be comptime-known",
            .casted_to_comptime_enum      => "value casted to enum with 'comptime_int' tag type must be comptime-known",
            .casted_to_comptime_int       => "value casted to 'comptime_int' must be comptime-known",
            .casted_to_comptime_float     => "value casted to 'comptime_float' must be comptime-known",
            .panic_handler                => "panic handler must be comptime-known",
            // zig fmt: on
        };
    }
};

test {
    _ = Ast;
    _ = AstRlAnnotate;
    _ = BuiltinFn;
    _ = Client;
    _ = ErrorBundle;
    _ = LibCDirs;
    _ = LibCInstallation;
    _ = Server;
    _ = WindowsSdk;
    _ = number_literal;
    _ = primitives;
    _ = string_literal;
    _ = system;
    _ = target;
    _ = c_translation;
}
//! Abstract Syntax Tree for Zig source code.
//! For Zig syntax, the root node is at nodes[0] and contains the list of
//! sub-nodes.
//! For Zon syntax, the root node is at nodes[0] and contains lhs as the node
//! index of the main expression.

/// Reference to externally-owned data.
source: [:0]const u8,

tokens: TokenList.Slice,
nodes: NodeList.Slice,
extra_data: []u32,
mode: Mode = .zig,

errors: []const Error,

pub const ByteOffset = u32;

pub const TokenList = std.MultiArrayList(struct {
    tag: Token.Tag,
    start: ByteOffset,
});
pub const NodeList = std.MultiArrayList(Node);

/// Index into `tokens`.
pub const TokenIndex = u32;

/// Index into `tokens`, or null.
pub const OptionalTokenIndex = enum(u32) {
    none = std.math.maxInt(u32),
    _,

    pub fn unwrap(oti: OptionalTokenIndex) ?TokenIndex {
        return if (oti == .none) null else @intFromEnum(oti);
    }

    pub fn fromToken(ti: TokenIndex) OptionalTokenIndex {
        return @enumFromInt(ti);
    }

    pub fn fromOptional(oti: ?TokenIndex) OptionalTokenIndex {
        return if (oti) |ti| @enumFromInt(ti) else .none;
    }
};

/// A relative token index.
pub const TokenOffset = enum(i32) {
    zero = 0,
    _,

    pub fn init(base: TokenIndex, destination: TokenIndex) TokenOffset {
        const base_i64: i64 = base;
        const destination_i64: i64 = destination;
        return @enumFromInt(destination_i64 - base_i64);
    }

    pub fn toOptional(to: TokenOffset) OptionalTokenOffset {
        const result: OptionalTokenOffset = @enumFromInt(@intFromEnum(to));
        assert(result != .none);
        return result;
    }

    pub fn toAbsolute(offset: TokenOffset, base: TokenIndex) TokenIndex {
        return @intCast(@as(i64, base) + @intFromEnum(offset));
    }
};

/// A relative token index, or null.
pub const OptionalTokenOffset = enum(i32) {
    none = std.math.maxInt(i32),
    _,

    pub fn unwrap(oto: OptionalTokenOffset) ?TokenOffset {
        return if (oto == .none) null else @enumFromInt(@intFromEnum(oto));
    }
};

pub fn tokenTag(tree: *const Ast, token_index: TokenIndex) Token.Tag {
    return tree.tokens.items(.tag)[token_index];
}

pub fn tokenStart(tree: *const Ast, token_index: TokenIndex) ByteOffset {
    return tree.tokens.items(.start)[token_index];
}

pub fn nodeTag(tree: *const Ast, node: Node.Index) Node.Tag {
    return tree.nodes.items(.tag)[@intFromEnum(node)];
}

pub fn nodeMainToken(tree: *const Ast, node: Node.Index) TokenIndex {
    return tree.nodes.items(.main_token)[@intFromEnum(node)];
}

pub fn nodeData(tree: *const Ast, node: Node.Index) Node.Data {
    return tree.nodes.items(.data)[@intFromEnum(node)];
}

pub fn isTokenPrecededByTags(
    tree: *const Ast,
    ti: TokenIndex,
    expected_token_tags: []const Token.Tag,
) bool {
    return std.mem.endsWith(
        Token.Tag,
        tree.tokens.items(.tag)[0..ti],
        expected_token_tags,
    );
}

pub const Location = struct {
    line: usize,
    column: usize,
    line_start: usize,
    line_end: usize,
};

pub const Span = struct {
    start: u32,
    end: u32,
    main: u32,
};

pub fn deinit(tree: *Ast, gpa: Allocator) void {
    tree.tokens.deinit(gpa);
    tree.nodes.deinit(gpa);
    gpa.free(tree.extra_data);
    gpa.free(tree.errors);
    tree.* = undefined;
}

pub const RenderError = error{
    /// Ran out of memory allocating call stack frames to complete rendering, or
    /// ran out of memory allocating space in the output buffer.
    OutOfMemory,
};

pub const Mode = enum { zig, zon };

/// Result should be freed with tree.deinit() when there are
/// no more references to any of the tokens or nodes.
pub fn parse(gpa: Allocator, source: [:0]const u8, mode: Mode) Allocator.Error!Ast {
    var tokens = Ast.TokenList{};
    defer tokens.deinit(gpa);

    // Empirically, the zig std lib has an 8:1 ratio of source bytes to token count.
    const estimated_token_count = source.len / 8;
    try tokens.ensureTotalCapacity(gpa, estimated_token_count);

    var tokenizer = std.zig.Tokenizer.init(source);
    while (true) {
        const token = tokenizer.next();
        try tokens.append(gpa, .{
            .tag = token.tag,
            .start = @intCast(token.loc.start),
        });
        if (token.tag == .eof) break;
    }

    var parser: Parse = .{
        .source = source,
        .gpa = gpa,
        .tokens = tokens.slice(),
        .errors = .{},
        .nodes = .{},
        .extra_data = .{},
        .scratch = .{},
        .tok_i = 0,
    };
    defer parser.errors.deinit(gpa);
    defer parser.nodes.deinit(gpa);
    defer parser.extra_data.deinit(gpa);
    defer parser.scratch.deinit(gpa);

    // Empirically, Zig source code has a 2:1 ratio of tokens to AST nodes.
    // Make sure at least 1 so we can use appendAssumeCapacity on the root node below.
    const estimated_node_count = (tokens.len + 2) / 2;
    try parser.nodes.ensureTotalCapacity(gpa, estimated_node_count);

    switch (mode) {
        .zig => try parser.parseRoot(),
        .zon => try parser.parseZon(),
    }

    const extra_data = try parser.extra_data.toOwnedSlice(gpa);
    errdefer gpa.free(extra_data);
    const errors = try parser.errors.toOwnedSlice(gpa);
    errdefer gpa.free(errors);

    // TODO experiment with compacting the MultiArrayList slices here
    return Ast{
        .source = source,
        .mode = mode,
        .tokens = tokens.toOwnedSlice(),
        .nodes = parser.nodes.toOwnedSlice(),
        .extra_data = extra_data,
        .errors = errors,
    };
}

/// `gpa` is used for allocating the resulting formatted source code.
/// Caller owns the returned slice of bytes, allocated with `gpa`.
pub fn render(tree: Ast, gpa: Allocator) RenderError![]u8 {
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    try tree.renderToArrayList(&buffer, .{});
    return buffer.toOwnedSlice();
}

pub const Fixups = private_render.Fixups;

pub fn renderToArrayList(tree: Ast, buffer: *std.ArrayList(u8), fixups: Fixups) RenderError!void {
    return @import("./render.zig").renderTree(buffer, tree, fixups);
}

/// Returns an extra offset for column and byte offset of errors that
/// should point after the token in the error message.
pub fn errorOffset(tree: Ast, parse_error: Error) u32 {
    return if (parse_error.token_is_prev)
        @as(u32, @intCast(tree.tokenSlice(parse_error.token).len))
    else
        0;
}

pub fn tokenLocation(self: Ast, start_offset: ByteOffset, token_index: TokenIndex) Location {
    var loc = Location{
        .line = 0,
        .column = 0,
        .line_start = start_offset,
        .line_end = self.source.len,
    };
    const token_start = self.tokenStart(token_index);

    // Scan to by line until we go past the token start
    while (std.mem.indexOfScalarPos(u8, self.source, loc.line_start, '\n')) |i| {
        if (i >= token_start) {
            break; // Went past
        }
        loc.line += 1;
        loc.line_start = i + 1;
    }

    const offset = loc.line_start;
    for (self.source[offset..], 0..) |c, i| {
        if (i + offset == token_start) {
            loc.line_end = i + offset;
            while (loc.line_end < self.source.len and self.source[loc.line_end] != '\n') {
                loc.line_end += 1;
            }
            return loc;
        }
        if (c == '\n') {
            loc.line += 1;
            loc.column = 0;
            loc.line_start = i + 1;
        } else {
            loc.column += 1;
        }
    }
    return loc;
}

pub fn tokenSlice(tree: Ast, token_index: TokenIndex) []const u8 {
    const token_tag = tree.tokenTag(token_index);

    // Many tokens can be determined entirely by their tag.
    if (token_tag.lexeme()) |lexeme| {
        return lexeme;
    }

    // For some tokens, re-tokenization is needed to find the end.
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = tree.tokenStart(token_index),
    };
    const token = tokenizer.next();
    assert(token.tag == token_tag);
    return tree.source[token.loc.start..token.loc.end];
}

pub fn extraDataSlice(tree: Ast, range: Node.SubRange, comptime T: type) []const T {
    return @ptrCast(tree.extra_data[@intFromEnum(range.start)..@intFromEnum(range.end)]);
}

pub fn extraDataSliceWithLen(tree: Ast, start: ExtraIndex, len: u32, comptime T: type) []const T {
    return @ptrCast(tree.extra_data[@intFromEnum(start)..][0..len]);
}

pub fn extraData(tree: Ast, index: ExtraIndex, comptime T: type) T {
    const fields = std.meta.fields(T);
    var result: T = undefined;
    inline for (fields, 0..) |field, i| {
        @field(result, field.name) = switch (field.type) {
            Node.Index,
            Node.OptionalIndex,
            OptionalTokenIndex,
            ExtraIndex,
            => @enumFromInt(tree.extra_data[@intFromEnum(index) + i]),
            TokenIndex => tree.extra_data[@intFromEnum(index) + i],
            else => @compileError("unexpected field type: " ++ @typeName(field.type)),
        };
    }
    return result;
}

fn loadOptionalNodesIntoBuffer(comptime size: usize, buffer: *[size]Node.Index, items: [size]Node.OptionalIndex) []Node.Index {
    for (buffer, items, 0..) |*node, opt_node, i| {
        node.* = opt_node.unwrap() orelse return buffer[0..i];
    }
    return buffer[0..];
}

pub fn rootDecls(tree: Ast) []const Node.Index {
    switch (tree.mode) {
        .zig => return tree.extraDataSlice(tree.nodeData(.root).extra_range, Node.Index),
        // Ensure that the returned slice points into the existing memory of the Ast
        .zon => return (&tree.nodes.items(.data)[@intFromEnum(Node.Index.root)].node)[0..1],
    }
}

pub fn renderError(tree: Ast, parse_error: Error, stream: anytype) !void {
    switch (parse_error.tag) {
        .asterisk_after_ptr_deref => {
            // Note that the token will point at the `.*` but ideally the source
            // location would point to the `*` after the `.*`.
            return stream.writeAll("'.*' cannot be followed by '*'. Are you missing a space?");
        },
        .chained_comparison_operators => {
            return stream.writeAll("comparison operators cannot be chained");
        },
        .decl_between_fields => {
            return stream.writeAll("declarations are not allowed between container fields");
        },
        .expected_block => {
            return stream.print("expected block, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_block_or_assignment => {
            return stream.print("expected block or assignment, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_block_or_expr => {
            return stream.print("expected block or expression, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_block_or_field => {
            return stream.print("expected block or field, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_container_members => {
            return stream.print("expected test, comptime, var decl, or container field, found '{s}'", .{
                tree.tokenTag(parse_error.token).symbol(),
            });
        },
        .expected_expr => {
            return stream.print("expected expression, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_expr_or_assignment => {
            return stream.print("expected expression or assignment, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_expr_or_var_decl => {
            return stream.print("expected expression or var decl, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_fn => {
            return stream.print("expected function, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_inlinable => {
            return stream.print("expected 'while' or 'for', found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_labelable => {
            return stream.print("expected 'while', 'for', 'inline', or '{{', found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_param_list => {
            return stream.print("expected parameter list, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_prefix_expr => {
            return stream.print("expected prefix expression, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_primary_type_expr => {
            return stream.print("expected primary type expression, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_pub_item => {
            return stream.writeAll("expected function or variable declaration after pub");
        },
        .expected_return_type => {
            return stream.print("expected return type expression, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_semi_or_else => {
            return stream.writeAll("expected ';' or 'else' after statement");
        },
        .expected_semi_or_lbrace => {
            return stream.writeAll("expected ';' or block after function prototype");
        },
        .expected_statement => {
            return stream.print("expected statement, found '{s}'", .{
                tree.tokenTag(parse_error.token).symbol(),
            });
        },
        .expected_suffix_op => {
            return stream.print("expected pointer dereference, optional unwrap, or field access, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_type_expr => {
            return stream.print("expected type expression, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_var_decl => {
            return stream.print("expected variable declaration, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_var_decl_or_fn => {
            return stream.print("expected variable declaration or function, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_loop_payload => {
            return stream.print("expected loop payload, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .expected_container => {
            return stream.print("expected a struct, enum or union, found '{s}'", .{
                tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev)).symbol(),
            });
        },
        .extern_fn_body => {
            return stream.writeAll("extern functions have no body");
        },
        .extra_addrspace_qualifier => {
            return stream.writeAll("extra addrspace qualifier");
        },
        .extra_align_qualifier => {
            return stream.writeAll("extra align qualifier");
        },
        .extra_allowzero_qualifier => {
            return stream.writeAll("extra allowzero qualifier");
        },
        .extra_const_qualifier => {
            return stream.writeAll("extra const qualifier");
        },
        .extra_volatile_qualifier => {
            return stream.writeAll("extra volatile qualifier");
        },
        .ptr_mod_on_array_child_type => {
            return stream.print("pointer modifier '{s}' not allowed on array child type", .{
                tree.tokenTag(parse_error.token).symbol(),
            });
        },
        .invalid_bit_range => {
            return stream.writeAll("bit range not allowed on slices and arrays");
        },
        .same_line_doc_comment => {
            return stream.writeAll("same line documentation comment");
        },
        .unattached_doc_comment => {
            return stream.writeAll("unattached documentation comment");
        },
        .test_doc_comment => {
            return stream.writeAll("documentation comments cannot be attached to tests");
        },
        .comptime_doc_comment => {
            return stream.writeAll("documentation comments cannot be attached to comptime blocks");
        },
        .varargs_nonfinal => {
            return stream.writeAll("function prototype has parameter after varargs");
        },
        .expected_continue_expr => {
            return stream.writeAll("expected ':' before while continue expression");
        },

        .expected_semi_after_decl => {
            return stream.writeAll("expected ';' after declaration");
        },
        .expected_semi_after_stmt => {
            return stream.writeAll("expected ';' after statement");
        },
        .expected_comma_after_field => {
            return stream.writeAll("expected ',' after field");
        },
        .expected_comma_after_arg => {
            return stream.writeAll("expected ',' after argument");
        },
        .expected_comma_after_param => {
            return stream.writeAll("expected ',' after parameter");
        },
        .expected_comma_after_initializer => {
            return stream.writeAll("expected ',' after initializer");
        },
        .expected_comma_after_switch_prong => {
            return stream.writeAll("expected ',' after switch prong");
        },
        .expected_comma_after_for_operand => {
            return stream.writeAll("expected ',' after for operand");
        },
        .expected_comma_after_capture => {
            return stream.writeAll("expected ',' after for capture");
        },
        .expected_initializer => {
            return stream.writeAll("expected field initializer");
        },
        .mismatched_binary_op_whitespace => {
            return stream.print("binary operator `{s}` has whitespace on one side, but not the other.", .{tree.tokenTag(parse_error.token).lexeme().?});
        },
        .invalid_ampersand_ampersand => {
            return stream.writeAll("ambiguous use of '&&'; use 'and' for logical AND, or change whitespace to ' & &' for bitwise AND");
        },
        .c_style_container => {
            return stream.print("'{s} {s}' is invalid", .{
                parse_error.extra.expected_tag.symbol(), tree.tokenSlice(parse_error.token),
            });
        },
        .zig_style_container => {
            return stream.print("to declare a container do 'const {s} = {s}'", .{
                tree.tokenSlice(parse_error.token), parse_error.extra.expected_tag.symbol(),
            });
        },
        .previous_field => {
            return stream.writeAll("field before declarations here");
        },
        .next_field => {
            return stream.writeAll("field after declarations here");
        },
        .expected_var_const => {
            return stream.writeAll("expected 'var' or 'const' before variable declaration");
        },
        .wrong_equal_var_decl => {
            return stream.writeAll("variable initialized with '==' instead of '='");
        },
        .var_const_decl => {
            return stream.writeAll("use 'var' or 'const' to declare variable");
        },
        .extra_for_capture => {
            return stream.writeAll("extra capture in for loop");
        },
        .for_input_not_captured => {
            return stream.writeAll("for input is not captured");
        },

        .invalid_byte => {
            const tok_slice = tree.source[tree.tokens.items(.start)[parse_error.token]..];
            return stream.print("{s} contains invalid byte: '{'}'", .{
                switch (tok_slice[0]) {
                    '\'' => "character literal",
                    '"', '\\' => "string literal",
                    '/' => "comment",
                    else => unreachable,
                },
                std.zig.fmtEscapes(tok_slice[parse_error.extra.offset..][0..1]),
            });
        },

        .expected_token => {
            const found_tag = tree.tokenTag(parse_error.token + @intFromBool(parse_error.token_is_prev));
            const expected_symbol = parse_error.extra.expected_tag.symbol();
            switch (found_tag) {
                .invalid => return stream.print("expected '{s}', found invalid bytes", .{
                    expected_symbol,
                }),
                else => return stream.print("expected '{s}', found '{s}'", .{
                    expected_symbol, found_tag.symbol(),
                }),
            }
        },
    }
}

pub fn firstToken(tree: Ast, node: Node.Index) TokenIndex {
    var end_offset: u32 = 0;
    var n = node;
    while (true) switch (tree.nodeTag(n)) {
        .root => return 0,

        .test_decl,
        .@"errdefer",
        .@"defer",
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .@"await",
        .optional_type,
        .@"switch",
        .switch_comma,
        .if_simple,
        .@"if",
        .@"suspend",
        .@"resume",
        .@"continue",
        .@"break",
        .@"return",
        .anyframe_type,
        .identifier,
        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .string_literal,
        .multiline_string_literal,
        .grouped_expression,
        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        .error_set_decl,
        .@"comptime",
        .@"nosuspend",
        .asm_simple,
        .@"asm",
        .array_type,
        .array_type_sentinel,
        .error_value,
        => return tree.nodeMainToken(n) - end_offset,

        .array_init_dot,
        .array_init_dot_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .enum_literal,
        => return tree.nodeMainToken(n) - 1 - end_offset,

        .@"catch",
        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_add,
        .assign_sub,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_xor,
        .assign_bit_or,
        .assign_mul_wrap,
        .assign_add_wrap,
        .assign_sub_wrap,
        .assign_mul_sat,
        .assign_add_sat,
        .assign_sub_sat,
        .assign,
        .merge_error_sets,
        .mul,
        .div,
        .mod,
        .array_mult,
        .mul_wrap,
        .mul_sat,
        .add,
        .sub,
        .array_cat,
        .add_wrap,
        .sub_wrap,
        .add_sat,
        .sub_sat,
        .shl,
        .shl_sat,
        .shr,
        .bit_and,
        .bit_xor,
        .bit_or,
        .@"orelse",
        .bool_and,
        .bool_or,
        .slice_open,
        .array_access,
        .array_init_one,
        .array_init_one_comma,
        .switch_range,
        .error_union,
        => n = tree.nodeData(n).node_and_node[0],

        .for_range,
        .call_one,
        .call_one_comma,
        .struct_init_one,
        .struct_init_one_comma,
        => n = tree.nodeData(n).node_and_opt_node[0],

        .field_access,
        .unwrap_optional,
        => n = tree.nodeData(n).node_and_token[0],

        .slice,
        .slice_sentinel,
        .array_init,
        .array_init_comma,
        .struct_init,
        .struct_init_comma,
        .call,
        .call_comma,
        => n = tree.nodeData(n).node_and_extra[0],

        .deref => n = tree.nodeData(n).node,

        .assign_destructure => n = tree.assignDestructure(n).ast.variables[0],

        .fn_decl,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var i = tree.nodeMainToken(n); // fn token
            while (i > 0) {
                i -= 1;
                switch (tree.tokenTag(i)) {
                    .keyword_extern,
                    .keyword_export,
                    .keyword_pub,
                    .keyword_inline,
                    .keyword_noinline,
                    .string_literal,
                    => continue,

                    else => return i + 1 - end_offset,
                }
            }
            return i - end_offset;
        },

        .@"usingnamespace" => {
            const main_token: TokenIndex = tree.nodeMainToken(n);
            const has_visib_token = tree.isTokenPrecededByTags(main_token, &.{.keyword_pub});
            end_offset += @intFromBool(has_visib_token);
            return main_token - end_offset;
        },

        .async_call_one,
        .async_call_one_comma,
        => {
            end_offset += 1; // async token
            n = tree.nodeData(n).node_and_opt_node[0];
        },

        .async_call,
        .async_call_comma,
        => {
            end_offset += 1; // async token
            n = tree.nodeData(n).node_and_extra[0];
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => {
            const name_token = tree.nodeMainToken(n);
            const has_comptime_token = tree.isTokenPrecededByTags(name_token, &.{.keyword_comptime});
            end_offset += @intFromBool(has_comptime_token);
            return name_token - end_offset;
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            var i = tree.nodeMainToken(n); // mut token
            while (i > 0) {
                i -= 1;
                switch (tree.tokenTag(i)) {
                    .keyword_extern,
                    .keyword_export,
                    .keyword_comptime,
                    .keyword_pub,
                    .keyword_threadlocal,
                    .string_literal,
                    => continue,

                    else => return i + 1 - end_offset,
                }
            }
            return i - end_offset;
        },

        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => {
            // Look for a label.
            const lbrace = tree.nodeMainToken(n);
            if (tree.isTokenPrecededByTags(lbrace, &.{ .identifier, .colon })) {
                end_offset += 2;
            }
            return lbrace - end_offset;
        },

        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => {
            const main_token = tree.nodeMainToken(n);
            switch (tree.tokenTag(main_token -| 1)) {
                .keyword_packed, .keyword_extern => end_offset += 1,
                else => {},
            }
            return main_token - end_offset;
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => return tree.nodeMainToken(n) - end_offset,

        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => {
            const full_switch = tree.fullSwitchCase(n).?;
            if (full_switch.inline_token) |inline_token| {
                return inline_token;
            } else if (full_switch.ast.values.len == 0) {
                return full_switch.ast.arrow_token - 1 - end_offset; // else token
            } else {
                n = full_switch.ast.values[0];
            }
        },

        .asm_output, .asm_input => {
            assert(tree.tokenTag(tree.nodeMainToken(n) - 1) == .l_bracket);
            return tree.nodeMainToken(n) - 1 - end_offset;
        },

        .while_simple,
        .while_cont,
        .@"while",
        .for_simple,
        .@"for",
        => {
            // Look for a label and inline.
            const main_token = tree.nodeMainToken(n);
            var result = main_token;
            if (tree.isTokenPrecededByTags(result, &.{.keyword_inline})) {
                result = result - 1;
            }
            if (tree.isTokenPrecededByTags(result, &.{ .identifier, .colon })) {
                result = result - 2;
            }
            return result - end_offset;
        },
    };
}

pub fn lastToken(tree: Ast, node: Node.Index) TokenIndex {
    var n = node;
    var end_offset: u32 = 0;
    while (true) switch (tree.nodeTag(n)) {
        .root => return @intCast(tree.tokens.len - 1),

        .@"usingnamespace",
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .@"await",
        .optional_type,
        .@"suspend",
        .@"resume",
        .@"nosuspend",
        .@"comptime",
        => n = tree.nodeData(n).node,

        .@"catch",
        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_add,
        .assign_sub,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_xor,
        .assign_bit_or,
        .assign_mul_wrap,
        .assign_add_wrap,
        .assign_sub_wrap,
        .assign_mul_sat,
        .assign_add_sat,
        .assign_sub_sat,
        .assign,
        .merge_error_sets,
        .mul,
        .div,
        .mod,
        .array_mult,
        .mul_wrap,
        .mul_sat,
        .add,
        .sub,
        .array_cat,
        .add_wrap,
        .sub_wrap,
        .add_sat,
        .sub_sat,
        .shl,
        .shl_sat,
        .shr,
        .bit_and,
        .bit_xor,
        .bit_or,
        .@"orelse",
        .bool_and,
        .bool_or,
        .error_union,
        .if_simple,
        .while_simple,
        .for_simple,
        .fn_decl,
        .array_type,
        .switch_range,
        => n = tree.nodeData(n).node_and_node[1],

        .test_decl, .@"errdefer" => n = tree.nodeData(n).opt_token_and_node[1],
        .@"defer" => n = tree.nodeData(n).node,
        .anyframe_type => n = tree.nodeData(n).token_and_node[1],

        .switch_case_one,
        .switch_case_inline_one,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        => n = tree.nodeData(n).opt_node_and_node[1],

        .assign_destructure,
        .ptr_type,
        .ptr_type_bit_range,
        .switch_case,
        .switch_case_inline,
        => n = tree.nodeData(n).extra_and_node[1],

        .fn_proto_simple => n = tree.nodeData(n).opt_node_and_opt_node[1].unwrap().?,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => n = tree.nodeData(n).extra_and_opt_node[1].unwrap().?,

        .for_range => {
            n = tree.nodeData(n).node_and_opt_node[1].unwrap() orelse {
                return tree.nodeMainToken(n) + end_offset;
            };
        },

        .field_access,
        .unwrap_optional,
        .asm_simple,
        => return tree.nodeData(n).node_and_token[1] + end_offset,
        .grouped_expression, .asm_input => return tree.nodeData(n).node_and_token[1] + end_offset,
        .multiline_string_literal, .error_set_decl => return tree.nodeData(n).token_and_token[1] + end_offset,
        .asm_output => return tree.nodeData(n).opt_node_and_token[1] + end_offset,
        .error_value => return tree.nodeMainToken(n) + 2 + end_offset,

        .anyframe_literal,
        .char_literal,
        .number_literal,
        .unreachable_literal,
        .identifier,
        .deref,
        .enum_literal,
        .string_literal,
        => return tree.nodeMainToken(n) + end_offset,

        .@"return" => {
            n = tree.nodeData(n).opt_node.unwrap() orelse {
                return tree.nodeMainToken(n) + end_offset;
            };
        },

        .call, .async_call => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const params = tree.extraData(extra_index, Node.SubRange);
            assert(params.start != params.end);
            end_offset += 1; // for the rparen
            n = @enumFromInt(tree.extra_data[@intFromEnum(params.end) - 1]); // last parameter
        },
        .tagged_union_enum_tag => {
            const arg, const extra_index = tree.nodeData(n).node_and_extra;
            const members = tree.extraData(extra_index, Node.SubRange);
            if (members.start == members.end) {
                end_offset += 4; // for the rparen + rparen + lbrace + rbrace
                n = arg;
            } else {
                end_offset += 1; // for the rbrace
                n = @enumFromInt(tree.extra_data[@intFromEnum(members.end) - 1]); // last parameter
            }
        },
        .call_comma,
        .async_call_comma,
        .tagged_union_enum_tag_trailing,
        => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const params = tree.extraData(extra_index, Node.SubRange);
            assert(params.start != params.end);
            end_offset += 2; // for the comma/semicolon + rparen/rbrace
            n = @enumFromInt(tree.extra_data[@intFromEnum(params.end) - 1]); // last parameter
        },
        .@"switch" => {
            const condition, const extra_index = tree.nodeData(n).node_and_extra;
            const cases = tree.extraData(extra_index, Node.SubRange);
            if (cases.start == cases.end) {
                end_offset += 3; // rparen, lbrace, rbrace
                n = condition;
            } else {
                end_offset += 1; // for the rbrace
                n = @enumFromInt(tree.extra_data[@intFromEnum(cases.end) - 1]); // last case
            }
        },
        .container_decl_arg => {
            const arg, const extra_index = tree.nodeData(n).node_and_extra;
            const members = tree.extraData(extra_index, Node.SubRange);
            if (members.end == members.start) {
                end_offset += 3; // for the rparen + lbrace + rbrace
                n = arg;
            } else {
                end_offset += 1; // for the rbrace
                n = @enumFromInt(tree.extra_data[@intFromEnum(members.end) - 1]); // last parameter
            }
        },
        .@"asm" => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.Asm);
            return extra.rparen + end_offset;
        },
        .array_init,
        .struct_init,
        => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const elements = tree.extraData(extra_index, Node.SubRange);
            assert(elements.start != elements.end);
            end_offset += 1; // for the rbrace
            n = @enumFromInt(tree.extra_data[@intFromEnum(elements.end) - 1]); // last element
        },
        .array_init_comma,
        .struct_init_comma,
        .container_decl_arg_trailing,
        .switch_comma,
        => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const members = tree.extraData(extra_index, Node.SubRange);
            assert(members.start != members.end);
            end_offset += 2; // for the comma + rbrace
            n = @enumFromInt(tree.extra_data[@intFromEnum(members.end) - 1]); // last parameter
        },
        .array_init_dot,
        .struct_init_dot,
        .block,
        .container_decl,
        .tagged_union,
        .builtin_call,
        => {
            const range = tree.nodeData(n).extra_range;
            assert(range.start != range.end);
            end_offset += 1; // for the rbrace
            n = @enumFromInt(tree.extra_data[@intFromEnum(range.end) - 1]); // last statement
        },
        .array_init_dot_comma,
        .struct_init_dot_comma,
        .block_semicolon,
        .container_decl_trailing,
        .tagged_union_trailing,
        .builtin_call_comma,
        => {
            const range = tree.nodeData(n).extra_range;
            assert(range.start != range.end);
            end_offset += 2; // for the comma/semicolon + rbrace/rparen
            n = @enumFromInt(tree.extra_data[@intFromEnum(range.end) - 1]); // last member
        },
        .call_one,
        .async_call_one,
        => {
            _, const first_param = tree.nodeData(n).node_and_opt_node;
            end_offset += 1; // for the rparen
            n = first_param.unwrap() orelse {
                return tree.nodeMainToken(n) + end_offset;
            };
        },

        .array_init_dot_two,
        .block_two,
        .builtin_call_two,
        .struct_init_dot_two,
        .container_decl_two,
        .tagged_union_two,
        => {
            const opt_lhs, const opt_rhs = tree.nodeData(n).opt_node_and_opt_node;
            if (opt_rhs.unwrap()) |rhs| {
                end_offset += 1; // for the rparen/rbrace
                n = rhs;
            } else if (opt_lhs.unwrap()) |lhs| {
                end_offset += 1; // for the rparen/rbrace
                n = lhs;
            } else {
                switch (tree.nodeTag(n)) {
                    .array_init_dot_two,
                    .block_two,
                    .struct_init_dot_two,
                    => end_offset += 1, // rbrace
                    .builtin_call_two => end_offset += 2, // lparen/lbrace + rparen/rbrace
                    .container_decl_two => {
                        var i: u32 = 2; // lbrace + rbrace
                        while (tree.tokenTag(tree.nodeMainToken(n) + i) == .container_doc_comment) i += 1;
                        end_offset += i;
                    },
                    .tagged_union_two => {
                        var i: u32 = 5; // (enum) {}
                        while (tree.tokenTag(tree.nodeMainToken(n) + i) == .container_doc_comment) i += 1;
                        end_offset += i;
                    },
                    else => unreachable,
                }
                return tree.nodeMainToken(n) + end_offset;
            }
        },
        .array_init_dot_two_comma,
        .builtin_call_two_comma,
        .block_two_semicolon,
        .struct_init_dot_two_comma,
        .container_decl_two_trailing,
        .tagged_union_two_trailing,
        => {
            const opt_lhs, const opt_rhs = tree.nodeData(n).opt_node_and_opt_node;
            end_offset += 2; // for the comma/semicolon + rbrace/rparen
            if (opt_rhs.unwrap()) |rhs| {
                n = rhs;
            } else if (opt_lhs.unwrap()) |lhs| {
                n = lhs;
            } else {
                unreachable;
            }
        },
        .simple_var_decl => {
            const type_node, const init_node = tree.nodeData(n).opt_node_and_opt_node;
            if (init_node.unwrap()) |rhs| {
                n = rhs;
            } else if (type_node.unwrap()) |lhs| {
                n = lhs;
            } else {
                end_offset += 1; // from mut token to name
                return tree.nodeMainToken(n) + end_offset;
            }
        },
        .aligned_var_decl => {
            const align_node, const init_node = tree.nodeData(n).node_and_opt_node;
            if (init_node.unwrap()) |rhs| {
                n = rhs;
            } else {
                end_offset += 1; // for the rparen
                n = align_node;
            }
        },
        .global_var_decl => {
            const extra_index, const init_node = tree.nodeData(n).extra_and_opt_node;
            if (init_node.unwrap()) |rhs| {
                n = rhs;
            } else {
                const extra = tree.extraData(extra_index, Node.GlobalVarDecl);
                if (extra.section_node.unwrap()) |section_node| {
                    end_offset += 1; // for the rparen
                    n = section_node;
                } else if (extra.align_node.unwrap()) |align_node| {
                    end_offset += 1; // for the rparen
                    n = align_node;
                } else if (extra.type_node.unwrap()) |type_node| {
                    n = type_node;
                } else {
                    end_offset += 1; // from mut token to name
                    return tree.nodeMainToken(n) + end_offset;
                }
            }
        },
        .local_var_decl => {
            const extra_index, const init_node = tree.nodeData(n).extra_and_opt_node;
            if (init_node.unwrap()) |rhs| {
                n = rhs;
            } else {
                const extra = tree.extraData(extra_index, Node.LocalVarDecl);
                end_offset += 1; // for the rparen
                n = extra.align_node;
            }
        },
        .container_field_init => {
            const type_expr, const value_expr = tree.nodeData(n).node_and_opt_node;
            n = value_expr.unwrap() orelse type_expr;
        },

        .array_access,
        .array_init_one,
        .container_field_align,
        => {
            _, const rhs = tree.nodeData(n).node_and_node;
            end_offset += 1; // for the rbracket/rbrace/rparen
            n = rhs;
        },
        .container_field => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.ContainerField);
            n = extra.value_expr;
        },

        .struct_init_one => {
            _, const first_field = tree.nodeData(n).node_and_opt_node;
            end_offset += 1; // rbrace
            n = first_field.unwrap() orelse {
                return tree.nodeMainToken(n) + end_offset;
            };
        },
        .slice_open => {
            _, const start_node = tree.nodeData(n).node_and_node;
            end_offset += 2; // ellipsis2 + rbracket, or comma + rparen
            n = start_node;
        },
        .array_init_one_comma => {
            _, const first_element = tree.nodeData(n).node_and_node;
            end_offset += 2; // comma + rbrace
            n = first_element;
        },
        .call_one_comma,
        .async_call_one_comma,
        .struct_init_one_comma,
        => {
            _, const first_field = tree.nodeData(n).node_and_opt_node;
            end_offset += 2; // ellipsis2 + rbracket, or comma + rparen
            n = first_field.unwrap().?;
        },
        .slice => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.Slice);
            end_offset += 1; // rbracket
            n = extra.end;
        },
        .slice_sentinel => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.SliceSentinel);
            end_offset += 1; // rbracket
            n = extra.sentinel;
        },

        .@"continue", .@"break" => {
            const opt_label, const opt_rhs = tree.nodeData(n).opt_token_and_opt_node;
            if (opt_rhs.unwrap()) |rhs| {
                n = rhs;
            } else if (opt_label.unwrap()) |lhs| {
                return lhs + end_offset;
            } else {
                return tree.nodeMainToken(n) + end_offset;
            }
        },
        .while_cont => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.WhileCont);
            n = extra.then_expr;
        },
        .@"while" => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.While);
            n = extra.else_expr;
        },
        .@"if" => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.If);
            n = extra.else_expr;
        },
        .@"for" => {
            const extra_index, const extra = tree.nodeData(n).@"for";
            const index = @intFromEnum(extra_index) + extra.inputs + @intFromBool(extra.has_else);
            n = @enumFromInt(tree.extra_data[index]);
        },
        .array_type_sentinel => {
            _, const extra_index = tree.nodeData(n).node_and_extra;
            const extra = tree.extraData(extra_index, Node.ArrayTypeSentinel);
            n = extra.elem_type;
        },
    };
}

pub fn tokensOnSameLine(tree: Ast, token1: TokenIndex, token2: TokenIndex) bool {
    const source = tree.source[tree.tokenStart(token1)..tree.tokenStart(token2)];
    return mem.indexOfScalar(u8, source, '\n') == null;
}

pub fn getNodeSource(tree: Ast, node: Node.Index) []const u8 {
    const first_token = tree.firstToken(node);
    const last_token = tree.lastToken(node);
    const start = tree.tokenStart(first_token);
    const end = tree.tokenStart(last_token) + tree.tokenSlice(last_token).len;
    return tree.source[start..end];
}

pub fn globalVarDecl(tree: Ast, node: Node.Index) full.VarDecl {
    assert(tree.nodeTag(node) == .global_var_decl);
    const extra_index, const init_node = tree.nodeData(node).extra_and_opt_node;
    const extra = tree.extraData(extra_index, Node.GlobalVarDecl);
    return tree.fullVarDeclComponents(.{
        .type_node = extra.type_node,
        .align_node = extra.align_node,
        .addrspace_node = extra.addrspace_node,
        .section_node = extra.section_node,
        .init_node = init_node,
        .mut_token = tree.nodeMainToken(node),
    });
}

pub fn localVarDecl(tree: Ast, node: Node.Index) full.VarDecl {
    assert(tree.nodeTag(node) == .local_var_decl);
    const extra_index, const init_node = tree.nodeData(node).extra_and_opt_node;
    const extra = tree.extraData(extra_index, Node.LocalVarDecl);
    return tree.fullVarDeclComponents(.{
        .type_node = extra.type_node.toOptional(),
        .align_node = extra.align_node.toOptional(),
        .addrspace_node = .none,
        .section_node = .none,
        .init_node = init_node,
        .mut_token = tree.nodeMainToken(node),
    });
}

pub fn simpleVarDecl(tree: Ast, node: Node.Index) full.VarDecl {
    assert(tree.nodeTag(node) == .simple_var_decl);
    const type_node, const init_node = tree.nodeData(node).opt_node_and_opt_node;
    return tree.fullVarDeclComponents(.{
        .type_node = type_node,
        .align_node = .none,
        .addrspace_node = .none,
        .section_node = .none,
        .init_node = init_node,
        .mut_token = tree.nodeMainToken(node),
    });
}

pub fn alignedVarDecl(tree: Ast, node: Node.Index) full.VarDecl {
    assert(tree.nodeTag(node) == .aligned_var_decl);
    const align_node, const init_node = tree.nodeData(node).node_and_opt_node;
    return tree.fullVarDeclComponents(.{
        .type_node = .none,
        .align_node = align_node.toOptional(),
        .addrspace_node = .none,
        .section_node = .none,
        .init_node = init_node,
        .mut_token = tree.nodeMainToken(node),
    });
}

pub fn assignDestructure(tree: Ast, node: Node.Index) full.AssignDestructure {
    const extra_index, const value_expr = tree.nodeData(node).extra_and_node;
    const variable_count = tree.extra_data[@intFromEnum(extra_index)];
    return tree.fullAssignDestructureComponents(.{
        .variables = tree.extraDataSliceWithLen(@enumFromInt(@intFromEnum(extra_index) + 1), variable_count, Node.Index),
        .equal_token = tree.nodeMainToken(node),
        .value_expr = value_expr,
    });
}

pub fn ifSimple(tree: Ast, node: Node.Index) full.If {
    assert(tree.nodeTag(node) == .if_simple);
    const cond_expr, const then_expr = tree.nodeData(node).node_and_node;
    return tree.fullIfComponents(.{
        .cond_expr = cond_expr,
        .then_expr = then_expr,
        .else_expr = .none,
        .if_token = tree.nodeMainToken(node),
    });
}

pub fn ifFull(tree: Ast, node: Node.Index) full.If {
    assert(tree.nodeTag(node) == .@"if");
    const cond_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.If);
    return tree.fullIfComponents(.{
        .cond_expr = cond_expr,
        .then_expr = extra.then_expr,
        .else_expr = extra.else_expr.toOptional(),
        .if_token = tree.nodeMainToken(node),
    });
}

pub fn containerField(tree: Ast, node: Node.Index) full.ContainerField {
    assert(tree.nodeTag(node) == .container_field);
    const type_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.ContainerField);
    const main_token = tree.nodeMainToken(node);
    return tree.fullContainerFieldComponents(.{
        .main_token = main_token,
        .type_expr = type_expr.toOptional(),
        .align_expr = extra.align_expr.toOptional(),
        .value_expr = extra.value_expr.toOptional(),
        .tuple_like = tree.tokenTag(main_token) != .identifier or
            tree.tokenTag(main_token + 1) != .colon,
    });
}

pub fn containerFieldInit(tree: Ast, node: Node.Index) full.ContainerField {
    assert(tree.nodeTag(node) == .container_field_init);
    const type_expr, const value_expr = tree.nodeData(node).node_and_opt_node;
    const main_token = tree.nodeMainToken(node);
    return tree.fullContainerFieldComponents(.{
        .main_token = main_token,
        .type_expr = type_expr.toOptional(),
        .align_expr = .none,
        .value_expr = value_expr,
        .tuple_like = tree.tokenTag(main_token) != .identifier or
            tree.tokenTag(main_token + 1) != .colon,
    });
}

pub fn containerFieldAlign(tree: Ast, node: Node.Index) full.ContainerField {
    assert(tree.nodeTag(node) == .container_field_align);
    const type_expr, const align_expr = tree.nodeData(node).node_and_node;
    const main_token = tree.nodeMainToken(node);
    return tree.fullContainerFieldComponents(.{
        .main_token = main_token,
        .type_expr = type_expr.toOptional(),
        .align_expr = align_expr.toOptional(),
        .value_expr = .none,
        .tuple_like = tree.tokenTag(main_token) != .identifier or
            tree.tokenTag(main_token + 1) != .colon,
    });
}

pub fn fnProtoSimple(tree: Ast, buffer: *[1]Node.Index, node: Node.Index) full.FnProto {
    assert(tree.nodeTag(node) == .fn_proto_simple);
    const first_param, const return_type = tree.nodeData(node).opt_node_and_opt_node;
    const params = loadOptionalNodesIntoBuffer(1, buffer, .{first_param});
    return tree.fullFnProtoComponents(.{
        .proto_node = node,
        .fn_token = tree.nodeMainToken(node),
        .return_type = return_type,
        .params = params,
        .align_expr = .none,
        .addrspace_expr = .none,
        .section_expr = .none,
        .callconv_expr = .none,
    });
}

pub fn fnProtoMulti(tree: Ast, node: Node.Index) full.FnProto {
    assert(tree.nodeTag(node) == .fn_proto_multi);
    const extra_index, const return_type = tree.nodeData(node).extra_and_opt_node;
    const params = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
    return tree.fullFnProtoComponents(.{
        .proto_node = node,
        .fn_token = tree.nodeMainToken(node),
        .return_type = return_type,
        .params = params,
        .align_expr = .none,
        .addrspace_expr = .none,
        .section_expr = .none,
        .callconv_expr = .none,
    });
}

pub fn fnProtoOne(tree: Ast, buffer: *[1]Node.Index, node: Node.Index) full.FnProto {
    assert(tree.nodeTag(node) == .fn_proto_one);
    const extra_index, const return_type = tree.nodeData(node).extra_and_opt_node;
    const extra = tree.extraData(extra_index, Node.FnProtoOne);
    const params = loadOptionalNodesIntoBuffer(1, buffer, .{extra.param});
    return tree.fullFnProtoComponents(.{
        .proto_node = node,
        .fn_token = tree.nodeMainToken(node),
        .return_type = return_type,
        .params = params,
        .align_expr = extra.align_expr,
        .addrspace_expr = extra.addrspace_expr,
        .section_expr = extra.section_expr,
        .callconv_expr = extra.callconv_expr,
    });
}

pub fn fnProto(tree: Ast, node: Node.Index) full.FnProto {
    assert(tree.nodeTag(node) == .fn_proto);
    const extra_index, const return_type = tree.nodeData(node).extra_and_opt_node;
    const extra = tree.extraData(extra_index, Node.FnProto);
    const params = tree.extraDataSlice(.{ .start = extra.params_start, .end = extra.params_end }, Node.Index);
    return tree.fullFnProtoComponents(.{
        .proto_node = node,
        .fn_token = tree.nodeMainToken(node),
        .return_type = return_type,
        .params = params,
        .align_expr = extra.align_expr,
        .addrspace_expr = extra.addrspace_expr,
        .section_expr = extra.section_expr,
        .callconv_expr = extra.callconv_expr,
    });
}

pub fn structInitOne(tree: Ast, buffer: *[1]Node.Index, node: Node.Index) full.StructInit {
    assert(tree.nodeTag(node) == .struct_init_one or
        tree.nodeTag(node) == .struct_init_one_comma);
    const type_expr, const first_field = tree.nodeData(node).node_and_opt_node;
    const fields = loadOptionalNodesIntoBuffer(1, buffer, .{first_field});
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .fields = fields,
            .type_expr = type_expr.toOptional(),
        },
    };
}

pub fn structInitDotTwo(tree: Ast, buffer: *[2]Node.Index, node: Node.Index) full.StructInit {
    assert(tree.nodeTag(node) == .struct_init_dot_two or
        tree.nodeTag(node) == .struct_init_dot_two_comma);
    const fields = loadOptionalNodesIntoBuffer(2, buffer, tree.nodeData(node).opt_node_and_opt_node);
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .fields = fields,
            .type_expr = .none,
        },
    };
}

pub fn structInitDot(tree: Ast, node: Node.Index) full.StructInit {
    assert(tree.nodeTag(node) == .struct_init_dot or
        tree.nodeTag(node) == .struct_init_dot_comma);
    const fields = tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index);
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .fields = fields,
            .type_expr = .none,
        },
    };
}

pub fn structInit(tree: Ast, node: Node.Index) full.StructInit {
    assert(tree.nodeTag(node) == .struct_init or
        tree.nodeTag(node) == .struct_init_comma);
    const type_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const fields = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .fields = fields,
            .type_expr = type_expr.toOptional(),
        },
    };
}

pub fn arrayInitOne(tree: Ast, buffer: *[1]Node.Index, node: Node.Index) full.ArrayInit {
    assert(tree.nodeTag(node) == .array_init_one or
        tree.nodeTag(node) == .array_init_one_comma);
    const type_expr, buffer[0] = tree.nodeData(node).node_and_node;
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .elements = buffer[0..1],
            .type_expr = type_expr.toOptional(),
        },
    };
}

pub fn arrayInitDotTwo(tree: Ast, buffer: *[2]Node.Index, node: Node.Index) full.ArrayInit {
    assert(tree.nodeTag(node) == .array_init_dot_two or
        tree.nodeTag(node) == .array_init_dot_two_comma);
    const elements = loadOptionalNodesIntoBuffer(2, buffer, tree.nodeData(node).opt_node_and_opt_node);
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .elements = elements,
            .type_expr = .none,
        },
    };
}

pub fn arrayInitDot(tree: Ast, node: Node.Index) full.ArrayInit {
    assert(tree.nodeTag(node) == .array_init_dot or
        tree.nodeTag(node) == .array_init_dot_comma);
    const elements = tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index);
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .elements = elements,
            .type_expr = .none,
        },
    };
}

pub fn arrayInit(tree: Ast, node: Node.Index) full.ArrayInit {
    assert(tree.nodeTag(node) == .array_init or
        tree.nodeTag(node) == .array_init_comma);
    const type_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const elements = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
    return .{
        .ast = .{
            .lbrace = tree.nodeMainToken(node),
            .elements = elements,
            .type_expr = type_expr.toOptional(),
        },
    };
}

pub fn arrayType(tree: Ast, node: Node.Index) full.ArrayType {
    assert(tree.nodeTag(node) == .array_type);
    const elem_count, const elem_type = tree.nodeData(node).node_and_node;
    return .{
        .ast = .{
            .lbracket = tree.nodeMainToken(node),
            .elem_count = elem_count,
            .sentinel = .none,
            .elem_type = elem_type,
        },
    };
}

pub fn arrayTypeSentinel(tree: Ast, node: Node.Index) full.ArrayType {
    assert(tree.nodeTag(node) == .array_type_sentinel);
    const elem_count, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.ArrayTypeSentinel);
    return .{
        .ast = .{
            .lbracket = tree.nodeMainToken(node),
            .elem_count = elem_count,
            .sentinel = extra.sentinel.toOptional(),
            .elem_type = extra.elem_type,
        },
    };
}

pub fn ptrTypeAligned(tree: Ast, node: Node.Index) full.PtrType {
    assert(tree.nodeTag(node) == .ptr_type_aligned);
    const align_node, const child_type = tree.nodeData(node).opt_node_and_node;
    return tree.fullPtrTypeComponents(.{
        .main_token = tree.nodeMainToken(node),
        .align_node = align_node,
        .addrspace_node = .none,
        .sentinel = .none,
        .bit_range_start = .none,
        .bit_range_end = .none,
        .child_type = child_type,
    });
}

pub fn ptrTypeSentinel(tree: Ast, node: Node.Index) full.PtrType {
    assert(tree.nodeTag(node) == .ptr_type_sentinel);
    const sentinel, const child_type = tree.nodeData(node).opt_node_and_node;
    return tree.fullPtrTypeComponents(.{
        .main_token = tree.nodeMainToken(node),
        .align_node = .none,
        .addrspace_node = .none,
        .sentinel = sentinel,
        .bit_range_start = .none,
        .bit_range_end = .none,
        .child_type = child_type,
    });
}

pub fn ptrType(tree: Ast, node: Node.Index) full.PtrType {
    assert(tree.nodeTag(node) == .ptr_type);
    const extra_index, const child_type = tree.nodeData(node).extra_and_node;
    const extra = tree.extraData(extra_index, Node.PtrType);
    return tree.fullPtrTypeComponents(.{
        .main_token = tree.nodeMainToken(node),
        .align_node = extra.align_node,
        .addrspace_node = extra.addrspace_node,
        .sentinel = extra.sentinel,
        .bit_range_start = .none,
        .bit_range_end = .none,
        .child_type = child_type,
    });
}

pub fn ptrTypeBitRange(tree: Ast, node: Node.Index) full.PtrType {
    assert(tree.nodeTag(node) == .ptr_type_bit_range);
    const extra_index, const child_type = tree.nodeData(node).extra_and_node;
    const extra = tree.extraData(extra_index, Node.PtrTypeBitRange);
    return tree.fullPtrTypeComponents(.{
        .main_token = tree.nodeMainToken(node),
        .align_node = extra.align_node.toOptional(),
        .addrspace_node = extra.addrspace_node,
        .sentinel = extra.sentinel,
        .bit_range_start = extra.bit_range_start.toOptional(),
        .bit_range_end = extra.bit_range_end.toOptional(),
        .child_type = child_type,
    });
}

pub fn sliceOpen(tree: Ast, node: Node.Index) full.Slice {
    assert(tree.nodeTag(node) == .slice_open);
    const sliced, const start = tree.nodeData(node).node_and_node;
    return .{
        .ast = .{
            .sliced = sliced,
            .lbracket = tree.nodeMainToken(node),
            .start = start,
            .end = .none,
            .sentinel = .none,
        },
    };
}

pub fn slice(tree: Ast, node: Node.Index) full.Slice {
    assert(tree.nodeTag(node) == .slice);
    const sliced, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.Slice);
    return .{
        .ast = .{
            .sliced = sliced,
            .lbracket = tree.nodeMainToken(node),
            .start = extra.start,
            .end = extra.end.toOptional(),
            .sentinel = .none,
        },
    };
}

pub fn sliceSentinel(tree: Ast, node: Node.Index) full.Slice {
    assert(tree.nodeTag(node) == .slice_sentinel);
    const sliced, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.SliceSentinel);
    return .{
        .ast = .{
            .sliced = sliced,
            .lbracket = tree.nodeMainToken(node),
            .start = extra.start,
            .end = extra.end,
            .sentinel = extra.sentinel.toOptional(),
        },
    };
}

pub fn containerDeclTwo(tree: Ast, buffer: *[2]Node.Index, node: Node.Index) full.ContainerDecl {
    assert(tree.nodeTag(node) == .container_decl_two or
        tree.nodeTag(node) == .container_decl_two_trailing);
    const members = loadOptionalNodesIntoBuffer(2, buffer, tree.nodeData(node).opt_node_and_opt_node);
    return tree.fullContainerDeclComponents(.{
        .main_token = tree.nodeMainToken(node),
        .enum_token = null,
        .members = members,
        .arg = .none,
    });
}

pub fn containerDecl(tree: Ast, node: Node.Index) full.ContainerDecl {
    assert(tree.nodeTag(node) == .container_decl or
        tree.nodeTag(node) == .container_decl_trailing);
    const members = tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index);
    return tree.fullContainerDeclComponents(.{
        .main_token = tree.nodeMainToken(node),
        .enum_token = null,
        .members = members,
        .arg = .none,
    });
}

pub fn containerDeclArg(tree: Ast, node: Node.Index) full.ContainerDecl {
    assert(tree.nodeTag(node) == .container_decl_arg or
        tree.nodeTag(node) == .container_decl_arg_trailing);
    const arg, const extra_index = tree.nodeData(node).node_and_extra;
    const members = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
    return tree.fullContainerDeclComponents(.{
        .main_token = tree.nodeMainToken(node),
        .enum_token = null,
        .members = members,
        .arg = arg.toOptional(),
    });
}

pub fn containerDeclRoot(tree: Ast) full.ContainerDecl {
    return .{
        .layout_token = null,
        .ast = .{
            .main_token = 0,
            .enum_token = null,
            .members = tree.rootDecls(),
            .arg = .none,
        },
    };
}

pub fn taggedUnionTwo(tree: Ast, buffer: *[2]Node.Index, node: Node.Index) full.ContainerDecl {
    assert(tree.nodeTag(node) == .tagged_union_two or
        tree.nodeTag(node) == .tagged_union_two_trailing);
    const members = loadOptionalNodesIntoBuffer(2, buffer, tree.nodeData(node).opt_node_and_opt_node);
    const main_token = tree.nodeMainToken(node);
    return tree.fullContainerDeclComponents(.{
        .main_token = main_token,
        .enum_token = main_token + 2, // union lparen enum
        .members = members,
        .arg = .none,
    });
}

pub fn taggedUnion(tree: Ast, node: Node.Index) full.ContainerDecl {
    assert(tree.nodeTag(node) == .tagged_union or
        tree.nodeTag(node) == .tagged_union_trailing);
    const members = tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index);
    const main_token = tree.nodeMainToken(node);
    return tree.fullContainerDeclComponents(.{
        .main_token = main_token,
        .enum_token = main_token + 2, // union lparen enum
        .members = members,
        .arg = .none,
    });
}

pub fn taggedUnionEnumTag(tree: Ast, node: Node.Index) full.ContainerDecl {
    assert(tree.nodeTag(node) == .tagged_union_enum_tag or
        tree.nodeTag(node) == .tagged_union_enum_tag_trailing);
    const arg, const extra_index = tree.nodeData(node).node_and_extra;
    const members = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
    const main_token = tree.nodeMainToken(node);
    return tree.fullContainerDeclComponents(.{
        .main_token = main_token,
        .enum_token = main_token + 2, // union lparen enum
        .members = members,
        .arg = arg.toOptional(),
    });
}

pub fn switchFull(tree: Ast, node: Node.Index) full.Switch {
    const main_token = tree.nodeMainToken(node);
    const switch_token: TokenIndex, const label_token: ?TokenIndex = switch (tree.tokenTag(main_token)) {
        .identifier => .{ main_token + 2, main_token },
        .keyword_switch => .{ main_token, null },
        else => unreachable,
    };
    const condition, const extra_index = tree.nodeData(node).node_and_extra;
    const cases = tree.extraDataSlice(tree.extraData(extra_index, Ast.Node.SubRange), Node.Index);
    return .{
        .ast = .{
            .switch_token = switch_token,
            .condition = condition,
            .cases = cases,
        },
        .label_token = label_token,
    };
}

pub fn switchCaseOne(tree: Ast, node: Node.Index) full.SwitchCase {
    const first_value, const target_expr = tree.nodeData(node).opt_node_and_node;
    return tree.fullSwitchCaseComponents(.{
        .values = if (first_value == .none)
            &.{}
        else
            // Ensure that the returned slice points into the existing memory of the Ast
            (@as(*const Node.Index, @ptrCast(&tree.nodes.items(.data)[@intFromEnum(node)].opt_node_and_node[0])))[0..1],
        .arrow_token = tree.nodeMainToken(node),
        .target_expr = target_expr,
    }, node);
}

pub fn switchCase(tree: Ast, node: Node.Index) full.SwitchCase {
    const extra_index, const target_expr = tree.nodeData(node).extra_and_node;
    const values = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
    return tree.fullSwitchCaseComponents(.{
        .values = values,
        .arrow_token = tree.nodeMainToken(node),
        .target_expr = target_expr,
    }, node);
}

pub fn asmSimple(tree: Ast, node: Node.Index) full.Asm {
    const template, const rparen = tree.nodeData(node).node_and_token;
    return tree.fullAsmComponents(.{
        .asm_token = tree.nodeMainToken(node),
        .template = template,
        .items = &.{},
        .rparen = rparen,
    });
}

pub fn asmFull(tree: Ast, node: Node.Index) full.Asm {
    const template, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.Asm);
    const items = tree.extraDataSlice(.{ .start = extra.items_start, .end = extra.items_end }, Node.Index);
    return tree.fullAsmComponents(.{
        .asm_token = tree.nodeMainToken(node),
        .template = template,
        .items = items,
        .rparen = extra.rparen,
    });
}

pub fn whileSimple(tree: Ast, node: Node.Index) full.While {
    const cond_expr, const then_expr = tree.nodeData(node).node_and_node;
    return tree.fullWhileComponents(.{
        .while_token = tree.nodeMainToken(node),
        .cond_expr = cond_expr,
        .cont_expr = .none,
        .then_expr = then_expr,
        .else_expr = .none,
    });
}

pub fn whileCont(tree: Ast, node: Node.Index) full.While {
    const cond_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.WhileCont);
    return tree.fullWhileComponents(.{
        .while_token = tree.nodeMainToken(node),
        .cond_expr = cond_expr,
        .cont_expr = extra.cont_expr.toOptional(),
        .then_expr = extra.then_expr,
        .else_expr = .none,
    });
}

pub fn whileFull(tree: Ast, node: Node.Index) full.While {
    const cond_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Node.While);
    return tree.fullWhileComponents(.{
        .while_token = tree.nodeMainToken(node),
        .cond_expr = cond_expr,
        .cont_expr = extra.cont_expr,
        .then_expr = extra.then_expr,
        .else_expr = extra.else_expr.toOptional(),
    });
}

pub fn forSimple(tree: Ast, ```
