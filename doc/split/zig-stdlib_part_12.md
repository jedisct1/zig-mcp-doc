```
.Timeout => break .timeout,
                // This status is issued because CancelIo was called, skip and try again.
                .Cancelled => continue,
                else => break error.Unexpected,
            };
        }
    },
    .dragonfly, .freebsd, .netbsd, .openbsd, .ios, .macos, .tvos, .visionos, .watchos, .haiku => struct {
        const posix = std.posix;

        kq_fd: i32,
        /// Indexes correspond 1:1 with `dir_table`.
        handles: std.MultiArrayList(struct {
            rs: ReactionSet,
            /// If the corresponding dir_table Path has sub_path == "", then it
            /// suffices as the open directory handle, and this value will be
            /// -1. Otherwise, it needs to be opened in update(), and will be
            /// stored here.
            dir_fd: i32,
        }),

        const dir_open_flags: posix.O = f: {
            var f: posix.O = .{
                .ACCMODE = .RDONLY,
                .NOFOLLOW = false,
                .DIRECTORY = true,
                .CLOEXEC = true,
            };
            if (@hasField(posix.O, "EVTONLY")) f.EVTONLY = true;
            if (@hasField(posix.O, "PATH")) f.PATH = true;
            break :f f;
        };

        const EV = std.c.EV;
        const NOTE = std.c.NOTE;

        fn init() !Watch {
            const kq_fd = try posix.kqueue();
            errdefer posix.close(kq_fd);
            return .{
                .dir_table = .{},
                .os = .{
                    .kq_fd = kq_fd,
                    .handles = .empty,
                },
                .generation = 0,
            };
        }

        fn update(w: *Watch, gpa: Allocator, steps: []const *Step) !void {
            const handles = &w.os.handles;
            for (steps) |step| {
                for (step.inputs.table.keys(), step.inputs.table.values()) |path, *files| {
                    const reaction_set = rs: {
                        const gop = try w.dir_table.getOrPut(gpa, path);
                        if (!gop.found_existing) {
                            const skip_open_dir = path.sub_path.len == 0;
                            const dir_fd = if (skip_open_dir)
                                path.root_dir.handle.fd
                            else
                                posix.openat(path.root_dir.handle.fd, path.sub_path, dir_open_flags, 0) catch |err| {
                                    fatal("failed to open directory {}: {s}", .{ path, @errorName(err) });
                                };
                            // Empirically the dir has to stay open or else no events are triggered.
                            errdefer if (!skip_open_dir) posix.close(dir_fd);
                            const changes = [1]posix.Kevent{.{
                                .ident = @bitCast(@as(isize, dir_fd)),
                                .filter = std.c.EVFILT.VNODE,
                                .flags = EV.ADD | EV.ENABLE | EV.CLEAR,
                                .fflags = NOTE.DELETE | NOTE.WRITE | NOTE.RENAME | NOTE.REVOKE,
                                .data = 0,
                                .udata = gop.index,
                            }};
                            _ = try posix.kevent(w.os.kq_fd, &changes, &.{}, null);
                            assert(handles.len == gop.index);
                            try handles.append(gpa, .{
                                .rs = .{},
                                .dir_fd = if (skip_open_dir) -1 else dir_fd,
                            });
                        }

                        break :rs &handles.items(.rs)[gop.index];
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
                while (i < handles.len) {
                    {
                        const reaction_set = &handles.items(.rs)[i];
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

                    // If the sub_path == "" then this patch has already the
                    // dir fd that we need to use as the ident to remove the
                    // event. If it was opened above with openat() then we need
                    // to access that data via the dir_fd field.
                    const path = w.dir_table.keys()[i];
                    const dir_fd = if (path.sub_path.len == 0)
                        path.root_dir.handle.fd
                    else
                        handles.items(.dir_fd)[i];
                    assert(dir_fd != -1);

                    // The changelist also needs to update the udata field of the last
                    // event, since we are doing a swap remove, and we store the dir_table
                    // index in the udata field.
                    const last_dir_fd = fd: {
                        const last_path = w.dir_table.keys()[handles.len - 1];
                        const last_dir_fd = if (last_path.sub_path.len == 0)
                            last_path.root_dir.handle.fd
                        else
                            handles.items(.dir_fd)[handles.len - 1];
                        assert(last_dir_fd != -1);
                        break :fd last_dir_fd;
                    };
                    const changes = [_]posix.Kevent{
                        .{
                            .ident = @bitCast(@as(isize, dir_fd)),
                            .filter = std.c.EVFILT.VNODE,
                            .flags = EV.DELETE,
                            .fflags = 0,
                            .data = 0,
                            .udata = i,
                        },
                        .{
                            .ident = @bitCast(@as(isize, last_dir_fd)),
                            .filter = std.c.EVFILT.VNODE,
                            .flags = EV.ADD,
                            .fflags = NOTE.DELETE | NOTE.WRITE | NOTE.RENAME | NOTE.REVOKE,
                            .data = 0,
                            .udata = i,
                        },
                    };
                    const filtered_changes = if (i == handles.len - 1) changes[0..1] else &changes;
                    _ = try posix.kevent(w.os.kq_fd, filtered_changes, &.{}, null);
                    if (path.sub_path.len != 0) posix.close(dir_fd);

                    w.dir_table.swapRemoveAt(i);
                    handles.swapRemove(i);
                }
                w.generation +%= 1;
            }
        }

        fn wait(w: *Watch, gpa: Allocator, timeout: Timeout) !WaitResult {
            var timespec_buffer: posix.timespec = undefined;
            var event_buffer: [100]posix.Kevent = undefined;
            var n = try posix.kevent(w.os.kq_fd, &.{}, &event_buffer, timeout.toTimespec(&timespec_buffer));
            if (n == 0) return .timeout;
            const reaction_sets = w.os.handles.items(.rs);
            var any_dirty = markDirtySteps(gpa, reaction_sets, event_buffer[0..n], false);
            timespec_buffer = .{ .sec = 0, .nsec = 0 };
            while (n == event_buffer.len) {
                n = try posix.kevent(w.os.kq_fd, &.{}, &event_buffer, &timespec_buffer);
                if (n == 0) break;
                any_dirty = markDirtySteps(gpa, reaction_sets, event_buffer[0..n], any_dirty);
            }
            return if (any_dirty) .dirty else .clean;
        }

        fn markDirtySteps(
            gpa: Allocator,
            reaction_sets: []ReactionSet,
            events: []const std.c.Kevent,
            start_any_dirty: bool,
        ) bool {
            var any_dirty = start_any_dirty;
            for (events) |event| {
                const index: usize = @intCast(event.udata);
                const reaction_set = &reaction_sets[index];
                // If we knew the basename of the changed file, here we would
                // mark only the step set dirty, and possibly the glob set:
                //if (reaction_set.getPtr(".")) |glob_set|
                //    any_dirty = markStepSetDirty(gpa, glob_set, any_dirty);
                //if (reaction_set.getPtr(file_name)) |step_set|
                //    any_dirty = markStepSetDirty(gpa, step_set, any_dirty);
                // However we don't know the file name so just mark all the
                // sets dirty for this directory.
                for (reaction_set.values()) |*step_set| {
                    any_dirty = markStepSetDirty(gpa, step_set, any_dirty);
                }
            }
            return any_dirty;
        }
    },
    else => void,
};

pub fn init() !Watch {
    return Os.init();
}

pub const Match = struct {
    /// Relative to the watched directory, the file path that triggers this
    /// match.
    basename: []const u8,
    /// The step to re-run when file corresponding to `basename` is changed.
    step: *Step,

    pub const Context = struct {
        pub fn hash(self: Context, a: Match) u32 {
            _ = self;
            var hasher = Hash.init(0);
            std.hash.autoHash(&hasher, a.step);
            hasher.update(a.basename);
            return @truncate(hasher.final());
        }
        pub fn eql(self: Context, a: Match, b: Match, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return a.step == b.step and std.mem.eql(u8, a.basename, b.basename);
        }
    };
};

fn markAllFilesDirty(w: *Watch, gpa: Allocator) void {
    for (w.os.handle_table.values()) |reaction_set| {
        for (reaction_set.values()) |step_set| {
            for (step_set.keys()) |step| {
                step.recursiveReset(gpa);
            }
        }
    }
}

fn markStepSetDirty(gpa: Allocator, step_set: *StepSet, any_dirty: bool) bool {
    var this_any_dirty = false;
    for (step_set.keys()) |step| {
        if (step.state != .precheck_done) {
            step.recursiveReset(gpa);
            this_any_dirty = true;
        }
    }
    return any_dirty or this_any_dirty;
}

pub fn update(w: *Watch, gpa: Allocator, steps: []const *Step) !void {
    return Os.update(w, gpa, steps);
}

pub const Timeout = union(enum) {
    none,
    ms: u16,

    pub fn to_i32_ms(t: Timeout) i32 {
        return switch (t) {
            .none => -1,
            .ms => |ms| ms,
        };
    }

    pub fn toTimespec(t: Timeout, buf: *std.posix.timespec) ?*std.posix.timespec {
        return switch (t) {
            .none => null,
            .ms => |ms_u16| {
                const ms: isize = ms_u16;
                buf.* = .{
                    .sec = @divTrunc(ms, std.time.ms_per_s),
                    .nsec = @rem(ms, std.time.ms_per_s) * std.time.ns_per_ms,
                };
                return buf;
            },
        };
    }
};

pub const WaitResult = enum {
    timeout,
    /// File system watching triggered on files that were marked as inputs to at least one Step.
    /// Relevant steps have been marked dirty.
    dirty,
    /// File system watching triggered but none of the events were relevant to
    /// what we are listening to. There is nothing to do.
    clean,
};

pub fn wait(w: *Watch, gpa: Allocator, timeout: Timeout) !WaitResult {
    return Os.wait(w, gpa, timeout);
}
//! Types and values provided by the Zig language.

const builtin = @import("builtin");

/// `explicit_subsystem` is missing when the subsystem is automatically detected,
/// so Zig standard library has the subsystem detection logic here. This should generally be
/// used rather than `explicit_subsystem`.
/// On non-Windows targets, this is `null`.
pub const subsystem: ?std.Target.SubSystem = blk: {
    if (@hasDecl(builtin, "explicit_subsystem")) break :blk builtin.explicit_subsystem;
    switch (builtin.os.tag) {
        .windows => {
            if (builtin.is_test) {
                break :blk std.Target.SubSystem.Console;
            }
            if (@hasDecl(root, "main") or
                @hasDecl(root, "WinMain") or
                @hasDecl(root, "wWinMain") or
                @hasDecl(root, "WinMainCRTStartup") or
                @hasDecl(root, "wWinMainCRTStartup"))
            {
                break :blk std.Target.SubSystem.Windows;
            } else {
                break :blk std.Target.SubSystem.Console;
            }
        },
        else => break :blk null,
    }
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const StackTrace = struct {
    index: usize,
    instruction_addresses: []usize,

    pub fn format(
        self: StackTrace,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);

        // TODO: re-evaluate whether to use format() methods at all.
        // Until then, avoid an error when using GeneralPurposeAllocator with WebAssembly
        // where it tries to call detectTTYConfig here.
        if (builtin.os.tag == .freestanding) return;

        _ = options;
        const debug_info = std.debug.getSelfDebugInfo() catch |err| {
            return writer.print("\nUnable to print stack trace: Unable to open debug info: {s}\n", .{@errorName(err)});
        };
        const tty_config = std.io.tty.detectConfig(std.io.getStdErr());
        try writer.writeAll("\n");
        std.debug.writeStackTrace(self, writer, debug_info, tty_config) catch |err| {
            try writer.print("Unable to print stack trace: {s}\n", .{@errorName(err)});
        };
    }
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const GlobalLinkage = enum {
    internal,
    strong,
    weak,
    link_once,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const SymbolVisibility = enum {
    default,
    hidden,
    protected,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const AtomicOrder = enum {
    unordered,
    monotonic,
    acquire,
    release,
    acq_rel,
    seq_cst,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const ReduceOp = enum {
    And,
    Or,
    Xor,
    Min,
    Max,
    Add,
    Mul,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const AtomicRmwOp = enum {
    /// Exchange - store the operand unmodified.
    /// Supports enums, integers, and floats.
    Xchg,
    /// Add operand to existing value.
    /// Supports integers and floats.
    /// For integers, two's complement wraparound applies.
    Add,
    /// Subtract operand from existing value.
    /// Supports integers and floats.
    /// For integers, two's complement wraparound applies.
    Sub,
    /// Perform bitwise AND on existing value with operand.
    /// Supports integers.
    And,
    /// Perform bitwise NAND on existing value with operand.
    /// Supports integers.
    Nand,
    /// Perform bitwise OR on existing value with operand.
    /// Supports integers.
    Or,
    /// Perform bitwise XOR on existing value with operand.
    /// Supports integers.
    Xor,
    /// Store operand if it is larger than the existing value.
    /// Supports integers and floats.
    Max,
    /// Store operand if it is smaller than the existing value.
    /// Supports integers and floats.
    Min,
};

/// The code model puts constraints on the location of symbols and the size of code and data.
/// The selection of a code model is a trade off on speed and restrictions that needs to be selected on a per application basis to meet its requirements.
/// A slightly more detailed explanation can be found in (for example) the [System V Application Binary Interface (x86_64)](https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf) 3.5.1.
///
/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const CodeModel = enum {
    default,
    extreme,
    kernel,
    large,
    medany,
    medium,
    medlow,
    medmid,
    normal,
    small,
    tiny,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const OptimizeMode = enum {
    Debug,
    ReleaseSafe,
    ReleaseFast,
    ReleaseSmall,
};

/// Deprecated; use OptimizeMode.
pub const Mode = OptimizeMode;

/// The calling convention of a function defines how arguments and return values are passed, as well
/// as any other requirements which callers and callees must respect, such as register preservation
/// and stack alignment.
///
/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const CallingConvention = union(enum(u8)) {
    pub const Tag = @typeInfo(CallingConvention).@"union".tag_type.?;

    /// This is an alias for the default C calling convention for this target.
    /// Functions marked as `extern` or `export` are given this calling convention by default.
    pub const c = builtin.target.cCallingConvention().?;

    pub const winapi: CallingConvention = switch (builtin.target.cpu.arch) {
        .x86_64 => .{ .x86_64_win = .{} },
        .x86 => .{ .x86_stdcall = .{} },
        .aarch64 => .{ .aarch64_aapcs_win = .{} },
        .thumb => .{ .arm_aapcs_vfp = .{} },
        else => unreachable,
    };

    pub const kernel: CallingConvention = switch (builtin.target.cpu.arch) {
        .amdgcn => .amdgcn_kernel,
        .nvptx, .nvptx64 => .nvptx_kernel,
        .spirv, .spirv32, .spirv64 => .spirv_kernel,
        else => unreachable,
    };

    /// Deprecated; use `.auto`.
    pub const Unspecified: CallingConvention = .auto;
    /// Deprecated; use `.c`.
    pub const C: CallingConvention = .c;
    /// Deprecated; use `.naked`.
    pub const Naked: CallingConvention = .naked;
    /// Deprecated; use `.@"async"`.
    pub const Async: CallingConvention = .@"async";
    /// Deprecated; use `.@"inline"`.
    pub const Inline: CallingConvention = .@"inline";
    /// Deprecated; use `.x86_64_interrupt`, `.x86_interrupt`, or `.avr_interrupt`.
    pub const Interrupt: CallingConvention = switch (builtin.target.cpu.arch) {
        .x86_64 => .{ .x86_64_interrupt = .{} },
        .x86 => .{ .x86_interrupt = .{} },
        .avr => .avr_interrupt,
        else => unreachable,
    };
    /// Deprecated; use `.avr_signal`.
    pub const Signal: CallingConvention = .avr_signal;
    /// Deprecated; use `.x86_stdcall`.
    pub const Stdcall: CallingConvention = .{ .x86_stdcall = .{} };
    /// Deprecated; use `.x86_fastcall`.
    pub const Fastcall: CallingConvention = .{ .x86_fastcall = .{} };
    /// Deprecated; use `.x86_64_vectorcall`, `.x86_vectorcall`, or `aarch64_vfabi`.
    pub const Vectorcall: CallingConvention = switch (builtin.target.cpu.arch) {
        .x86_64 => .{ .x86_64_vectorcall = .{} },
        .x86 => .{ .x86_vectorcall = .{} },
        .aarch64, .aarch64_be => .{ .aarch64_vfabi = .{} },
        else => unreachable,
    };
    /// Deprecated; use `.x86_thiscall`.
    pub const Thiscall: CallingConvention = .{ .x86_thiscall = .{} };
    /// Deprecated; use `.arm_aapcs`.
    pub const AAPCS: CallingConvention = .{ .arm_aapcs = .{} };
    /// Deprecated; use `.arm_aapcs_vfp`.
    pub const AAPCSVFP: CallingConvention = .{ .arm_aapcs_vfp = .{} };
    /// Deprecated; use `.x86_64_sysv`.
    pub const SysV: CallingConvention = .{ .x86_64_sysv = .{} };
    /// Deprecated; use `.x86_64_win`.
    pub const Win64: CallingConvention = .{ .x86_64_win = .{} };
    /// Deprecated; use `.kernel`.
    pub const Kernel: CallingConvention = .kernel;
    /// Deprecated; use `.spirv_fragment`.
    pub const Fragment: CallingConvention = .spirv_fragment;
    /// Deprecated; use `.spirv_vertex`.
    pub const Vertex: CallingConvention = .spirv_vertex;

    /// The default Zig calling convention when neither `export` nor `inline` is specified.
    /// This calling convention makes no guarantees about stack alignment, registers, etc.
    /// It can only be used within this Zig compilation unit.
    auto,

    /// The calling convention of a function that can be called with `async` syntax. An `async` call
    /// of a runtime-known function must target a function with this calling convention.
    /// Comptime-known functions with other calling conventions may be coerced to this one.
    @"async",

    /// Functions with this calling convention have no prologue or epilogue, making the function
    /// uncallable in regular Zig code. This can be useful when integrating with assembly.
    naked,

    /// This calling convention is exactly equivalent to using the `inline` keyword on a function
    /// definition. This function will be semantically inlined by the Zig compiler at call sites.
    /// Pointers to inline functions are comptime-only.
    @"inline",

    // Calling conventions for the `x86_64` architecture.
    x86_64_sysv: CommonOptions,
    x86_64_win: CommonOptions,
    x86_64_regcall_v3_sysv: CommonOptions,
    x86_64_regcall_v4_win: CommonOptions,
    x86_64_vectorcall: CommonOptions,
    x86_64_interrupt: CommonOptions,

    // Calling conventions for the `x86` architecture.
    x86_sysv: X86RegparmOptions,
    x86_win: X86RegparmOptions,
    x86_stdcall: X86RegparmOptions,
    x86_fastcall: CommonOptions,
    x86_thiscall: CommonOptions,
    x86_thiscall_mingw: CommonOptions,
    x86_regcall_v3: CommonOptions,
    x86_regcall_v4_win: CommonOptions,
    x86_vectorcall: CommonOptions,
    x86_interrupt: CommonOptions,

    // Calling conventions for the `aarch64` and `aarch64_be` architectures.
    aarch64_aapcs: CommonOptions,
    aarch64_aapcs_darwin: CommonOptions,
    aarch64_aapcs_win: CommonOptions,
    aarch64_vfabi: CommonOptions,
    aarch64_vfabi_sve: CommonOptions,

    // Calling convetions for the `arm`, `armeb`, `thumb`, and `thumbeb` architectures.
    /// ARM Architecture Procedure Call Standard
    arm_aapcs: CommonOptions,
    /// ARM Architecture Procedure Call Standard Vector Floating-Point
    arm_aapcs_vfp: CommonOptions,
    arm_interrupt: ArmInterruptOptions,

    // Calling conventions for the `mips64` and `mips64el` architectures.
    mips64_n64: CommonOptions,
    mips64_n32: CommonOptions,
    mips64_interrupt: MipsInterruptOptions,

    // Calling conventions for the `mips` and `mipsel` architectures.
    mips_o32: CommonOptions,
    mips_interrupt: MipsInterruptOptions,

    // Calling conventions for the `riscv64` architecture.
    riscv64_lp64: CommonOptions,
    riscv64_lp64_v: CommonOptions,
    riscv64_interrupt: RiscvInterruptOptions,

    // Calling conventions for the `riscv32` architecture.
    riscv32_ilp32: CommonOptions,
    riscv32_ilp32_v: CommonOptions,
    riscv32_interrupt: RiscvInterruptOptions,

    // Calling conventions for the `sparc64` architecture.
    sparc64_sysv: CommonOptions,

    // Calling conventions for the `sparc` architecture.
    sparc_sysv: CommonOptions,

    // Calling conventions for the `powerpc64` and `powerpc64le` architectures.
    powerpc64_elf: CommonOptions,
    powerpc64_elf_altivec: CommonOptions,
    powerpc64_elf_v2: CommonOptions,

    // Calling conventions for the `powerpc` and `powerpcle` architectures.
    powerpc_sysv: CommonOptions,
    powerpc_sysv_altivec: CommonOptions,
    powerpc_aix: CommonOptions,
    powerpc_aix_altivec: CommonOptions,

    /// The standard `wasm32` and `wasm64` calling convention, as specified in the WebAssembly Tool Conventions.
    wasm_mvp: CommonOptions,

    /// The standard `arc` calling convention.
    arc_sysv: CommonOptions,

    // Calling conventions for the `avr` architecture.
    avr_gnu,
    avr_builtin,
    avr_signal,
    avr_interrupt,

    /// The standard `bpfel`/`bpfeb` calling convention.
    bpf_std: CommonOptions,

    // Calling conventions for the `csky` architecture.
    csky_sysv: CommonOptions,
    csky_interrupt: CommonOptions,

    // Calling conventions for the `hexagon` architecture.
    hexagon_sysv: CommonOptions,
    hexagon_sysv_hvx: CommonOptions,

    /// The standard `lanai` calling convention.
    lanai_sysv: CommonOptions,

    /// The standard `loongarch64` calling convention.
    loongarch64_lp64: CommonOptions,

    /// The standard `loongarch32` calling convention.
    loongarch32_ilp32: CommonOptions,

    // Calling conventions for the `m68k` architecture.
    m68k_sysv: CommonOptions,
    m68k_gnu: CommonOptions,
    m68k_rtd: CommonOptions,
    m68k_interrupt: CommonOptions,

    /// The standard `msp430` calling convention.
    msp430_eabi: CommonOptions,

    /// The standard `propeller` calling convention.
    propeller_sysv: CommonOptions,

    // Calling conventions for the `s390x` architecture.
    s390x_sysv: CommonOptions,
    s390x_sysv_vx: CommonOptions,

    /// The standard `ve` calling convention.
    ve_sysv: CommonOptions,

    // Calling conventions for the `xcore` architecture.
    xcore_xs1: CommonOptions,
    xcore_xs2: CommonOptions,

    // Calling conventions for the `xtensa` architecture.
    xtensa_call0: CommonOptions,
    xtensa_windowed: CommonOptions,

    // Calling conventions for the `amdgcn` architecture.
    amdgcn_device: CommonOptions,
    amdgcn_kernel,
    amdgcn_cs: CommonOptions,

    // Calling conventions for the `nvptx` and `nvptx64` architectures.
    nvptx_device,
    nvptx_kernel,

    // Calling conventions for kernels and shaders on the `spirv`, `spirv32`, and `spirv64` architectures.
    spirv_device,
    spirv_kernel,
    spirv_fragment,
    spirv_vertex,

    /// Options shared across most calling conventions.
    pub const CommonOptions = struct {
        /// The boundary the stack is aligned to when the function is called.
        /// `null` means the default for this calling convention.
        incoming_stack_alignment: ?u64 = null,
    };

    /// Options for x86 calling conventions which support the regparm attribute to pass some
    /// arguments in registers.
    pub const X86RegparmOptions = struct {
        /// The boundary the stack is aligned to when the function is called.
        /// `null` means the default for this calling convention.
        incoming_stack_alignment: ?u64 = null,
        /// The number of arguments to pass in registers before passing the remaining arguments
        /// according to the calling convention.
        /// Equivalent to `__attribute__((regparm(x)))` in Clang and GCC.
        register_params: u2 = 0,
    };

    /// Options for the `arm_interrupt` calling convention.
    pub const ArmInterruptOptions = struct {
        /// The boundary the stack is aligned to when the function is called.
        /// `null` means the default for this calling convention.
        incoming_stack_alignment: ?u64 = null,
        /// The kind of interrupt being received.
        type: InterruptType = .generic,

        pub const InterruptType = enum(u3) {
            generic,
            irq,
            fiq,
            swi,
            abort,
            undef,
        };
    };

    /// Options for the `mips_interrupt` and `mips64_interrupt` calling conventions.
    pub const MipsInterruptOptions = struct {
        /// The boundary the stack is aligned to when the function is called.
        /// `null` means the default for this calling convention.
        incoming_stack_alignment: ?u64 = null,
        /// The interrupt mode.
        mode: InterruptMode = .eic,

        pub const InterruptMode = enum(u4) {
            eic,
            sw0,
            sw1,
            hw0,
            hw1,
            hw2,
            hw3,
            hw4,
            hw5,
        };
    };

    /// Options for the `riscv32_interrupt` and `riscv64_interrupt` calling conventions.
    pub const RiscvInterruptOptions = struct {
        /// The boundary the stack is aligned to when the function is called.
        /// `null` means the default for this calling convention.
        incoming_stack_alignment: ?u64 = null,
        /// The privilege mode.
        mode: PrivilegeMode,

        pub const PrivilegeMode = enum(u2) {
            supervisor,
            machine,
        };
    };

    /// Returns the array of `std.Target.Cpu.Arch` to which this `CallingConvention` applies.
    /// Asserts that `cc` is not `.auto`, `.@"async"`, `.naked`, or `.@"inline"`.
    pub fn archs(cc: CallingConvention) []const std.Target.Cpu.Arch {
        return std.Target.Cpu.Arch.fromCallingConvention(cc);
    }

    pub fn eql(a: CallingConvention, b: CallingConvention) bool {
        return std.meta.eql(a, b);
    }

    pub fn withStackAlign(cc: CallingConvention, incoming_stack_alignment: u64) CallingConvention {
        const tag: CallingConvention.Tag = cc;
        var result = cc;
        @field(result, @tagName(tag)).incoming_stack_alignment = incoming_stack_alignment;
        return result;
    }
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const AddressSpace = enum(u5) {
    /// The places where a user can specify an address space attribute
    pub const Context = enum {
        /// A function is specified to be placed in a certain address space.
        function,
        /// A (global) variable is specified to be placed in a certain address space.
        /// In contrast to .constant, these values (and thus the address space they will be
        /// placed in) are required to be mutable.
        variable,
        /// A (global) constant value is specified to be placed in a certain address space.
        /// In contrast to .variable, values placed in this address space are not required to be mutable.
        constant,
        /// A pointer is ascripted to point into a certain address space.
        pointer,
    };

    // CPU address spaces.
    generic,
    gs,
    fs,
    ss,

    // GPU address spaces.
    global,
    constant,
    param,
    shared,
    local,
    input,
    output,
    uniform,
    push_constant,
    storage_buffer,

    // AVR address spaces.
    flash,
    flash1,
    flash2,
    flash3,
    flash4,
    flash5,

    // Propeller address spaces.

    /// This address space only addresses the cog-local ram.
    cog,

    /// This address space only addresses shared hub ram.
    hub,

    /// This address space only addresses the "lookup" ram
    lut,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const SourceLocation = struct {
    /// The name chosen when compiling. Not a file path.
    module: [:0]const u8,
    /// Relative to the root directory of its module.
    file: [:0]const u8,
    fn_name: [:0]const u8,
    line: u32,
    column: u32,
};

pub const TypeId = std.meta.Tag(Type);

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const Type = union(enum) {
    type: void,
    void: void,
    bool: void,
    noreturn: void,
    int: Int,
    float: Float,
    pointer: Pointer,
    array: Array,
    @"struct": Struct,
    comptime_float: void,
    comptime_int: void,
    undefined: void,
    null: void,
    optional: Optional,
    error_union: ErrorUnion,
    error_set: ErrorSet,
    @"enum": Enum,
    @"union": Union,
    @"fn": Fn,
    @"opaque": Opaque,
    frame: Frame,
    @"anyframe": AnyFrame,
    vector: Vector,
    enum_literal: void,

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Int = struct {
        signedness: Signedness,
        bits: u16,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Float = struct {
        bits: u16,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Pointer = struct {
        size: Size,
        is_const: bool,
        is_volatile: bool,
        /// TODO make this u16 instead of comptime_int
        alignment: comptime_int,
        address_space: AddressSpace,
        child: type,
        is_allowzero: bool,

        /// The type of the sentinel is the element type of the pointer, which is
        /// the value of the `child` field in this struct. However there is no way
        /// to refer to that type here, so we use `*const anyopaque`.
        /// See also: `sentinel`
        sentinel_ptr: ?*const anyopaque,

        /// Loads the pointer type's sentinel value from `sentinel_ptr`.
        /// Returns `null` if the pointer type has no sentinel.
        pub inline fn sentinel(comptime ptr: Pointer) ?ptr.child {
            const sp: *const ptr.child = @ptrCast(@alignCast(ptr.sentinel_ptr orelse return null));
            return sp.*;
        }

        /// This data structure is used by the Zig language code generation and
        /// therefore must be kept in sync with the compiler implementation.
        pub const Size = enum(u2) {
            one,
            many,
            slice,
            c,
        };
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Array = struct {
        len: comptime_int,
        child: type,

        /// The type of the sentinel is the element type of the array, which is
        /// the value of the `child` field in this struct. However there is no way
        /// to refer to that type here, so we use `*const anyopaque`.
        /// See also: `sentinel`.
        sentinel_ptr: ?*const anyopaque,

        /// Loads the array type's sentinel value from `sentinel_ptr`.
        /// Returns `null` if the array type has no sentinel.
        pub inline fn sentinel(comptime arr: Array) ?arr.child {
            const sp: *const arr.child = @ptrCast(@alignCast(arr.sentinel_ptr orelse return null));
            return sp.*;
        }
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const ContainerLayout = enum(u2) {
        auto,
        @"extern",
        @"packed",
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const StructField = struct {
        name: [:0]const u8,
        type: type,
        /// The type of the default value is the type of this struct field, which
        /// is the value of the `type` field in this struct. However there is no
        /// way to refer to that type here, so we use `*const anyopaque`.
        /// See also: `defaultValue`.
        default_value_ptr: ?*const anyopaque,
        is_comptime: bool,
        alignment: comptime_int,

        /// Loads the field's default value from `default_value_ptr`.
        /// Returns `null` if the field has no default value.
        pub inline fn defaultValue(comptime sf: StructField) ?sf.type {
            const dp: *const sf.type = @ptrCast(@alignCast(sf.default_value_ptr orelse return null));
            return dp.*;
        }
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Struct = struct {
        layout: ContainerLayout,
        /// Only valid if layout is .@"packed"
        backing_integer: ?type = null,
        fields: []const StructField,
        decls: []const Declaration,
        is_tuple: bool,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Optional = struct {
        child: type,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const ErrorUnion = struct {
        error_set: type,
        payload: type,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Error = struct {
        name: [:0]const u8,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const ErrorSet = ?[]const Error;

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const EnumField = struct {
        name: [:0]const u8,
        value: comptime_int,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Enum = struct {
        tag_type: type,
        fields: []const EnumField,
        decls: []const Declaration,
        is_exhaustive: bool,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const UnionField = struct {
        name: [:0]const u8,
        type: type,
        alignment: comptime_int,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Union = struct {
        layout: ContainerLayout,
        tag_type: ?type,
        fields: []const UnionField,
        decls: []const Declaration,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Fn = struct {
        calling_convention: CallingConvention,
        is_generic: bool,
        is_var_args: bool,
        /// TODO change the language spec to make this not optional.
        return_type: ?type,
        params: []const Param,

        /// This data structure is used by the Zig language code generation and
        /// therefore must be kept in sync with the compiler implementation.
        pub const Param = struct {
            is_generic: bool,
            is_noalias: bool,
            type: ?type,
        };
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Opaque = struct {
        decls: []const Declaration,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Frame = struct {
        function: *const anyopaque,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const AnyFrame = struct {
        child: ?type,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Vector = struct {
        len: comptime_int,
        child: type,
    };

    /// This data structure is used by the Zig language code generation and
    /// therefore must be kept in sync with the compiler implementation.
    pub const Declaration = struct {
        name: [:0]const u8,
    };
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const FloatMode = enum {
    strict,
    optimized,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const Endian = enum {
    big,
    little,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const Signedness = enum {
    signed,
    unsigned,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const OutputMode = enum {
    Exe,
    Lib,
    Obj,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const LinkMode = enum {
    static,
    dynamic,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const UnwindTables = enum {
    none,
    sync,
    @"async",
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const WasiExecModel = enum {
    command,
    reactor,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const CallModifier = enum {
    /// Equivalent to function call syntax.
    auto,

    /// Equivalent to async keyword used with function call syntax.
    async_kw,

    /// Prevents tail call optimization. This guarantees that the return
    /// address will point to the callsite, as opposed to the callsite's
    /// callsite. If the call is otherwise required to be tail-called
    /// or inlined, a compile error is emitted instead.
    never_tail,

    /// Guarantees that the call will not be inlined. If the call is
    /// otherwise required to be inlined, a compile error is emitted instead.
    never_inline,

    /// Asserts that the function call will not suspend. This allows a
    /// non-async function to call an async function.
    no_async,

    /// Guarantees that the call will be generated with tail call optimization.
    /// If this is not possible, a compile error is emitted instead.
    always_tail,

    /// Guarantees that the call will be inlined at the callsite.
    /// If this is not possible, a compile error is emitted instead.
    always_inline,

    /// Evaluates the call at compile-time. If the call cannot be completed at
    /// compile-time, a compile error is emitted instead.
    compile_time,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const VaListAarch64 = extern struct {
    __stack: *anyopaque,
    __gr_top: *anyopaque,
    __vr_top: *anyopaque,
    __gr_offs: c_int,
    __vr_offs: c_int,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const VaListHexagon = extern struct {
    __gpr: c_long,
    __fpr: c_long,
    __overflow_arg_area: *anyopaque,
    __reg_save_area: *anyopaque,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const VaListPowerPc = extern struct {
    gpr: u8,
    fpr: u8,
    reserved: c_ushort,
    overflow_arg_area: *anyopaque,
    reg_save_area: *anyopaque,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const VaListS390x = extern struct {
    __current_saved_reg_area_pointer: *anyopaque,
    __saved_reg_area_end_pointer: *anyopaque,
    __overflow_area_pointer: *anyopaque,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const VaListX86_64 = extern struct {
    gp_offset: c_uint,
    fp_offset: c_uint,
    overflow_arg_area: *anyopaque,
    reg_save_area: *anyopaque,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const VaListXtensa = extern struct {
    __va_stk: *c_int,
    __va_reg: *c_int,
    __va_ndx: c_int,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const VaList = switch (builtin.cpu.arch) {
    .aarch64, .aarch64_be => switch (builtin.os.tag) {
        .windows => *u8,
        .ios, .macos, .tvos, .watchos, .visionos => *u8,
        else => @compileError("disabled due to miscompilations"), // VaListAarch64,
    },
    .arm, .armeb, .thumb, .thumbeb => switch (builtin.os.tag) {
        .ios, .macos, .tvos, .watchos, .visionos => *u8,
        else => *anyopaque,
    },
    .amdgcn => *u8,
    .avr => *anyopaque,
    .bpfel, .bpfeb => *anyopaque,
    .hexagon => if (builtin.target.abi.isMusl()) VaListHexagon else *u8,
    .loongarch32, .loongarch64 => *anyopaque,
    .mips, .mipsel, .mips64, .mips64el => *anyopaque,
    .riscv32, .riscv64 => *anyopaque,
    .powerpc, .powerpcle => switch (builtin.os.tag) {
        .ios, .macos, .tvos, .watchos, .visionos, .aix => *u8,
        else => VaListPowerPc,
    },
    .powerpc64, .powerpc64le => *u8,
    .sparc, .sparc64 => *anyopaque,
    .spirv32, .spirv64 => *anyopaque,
    .s390x => VaListS390x,
    .wasm32, .wasm64 => *anyopaque,
    .x86 => *u8,
    .x86_64 => switch (builtin.os.tag) {
        .windows => @compileError("disabled due to miscompilations"), // *u8,
        else => VaListX86_64,
    },
    .xtensa => VaListXtensa,
    else => @compileError("VaList not supported for this target yet"),
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const PrefetchOptions = struct {
    /// Whether the prefetch should prepare for a read or a write.
    rw: Rw = .read,
    /// The data's locality in an inclusive range from 0 to 3.
    ///
    /// 0 means no temporal locality. That is, the data can be immediately
    /// dropped from the cache after it is accessed.
    ///
    /// 3 means high temporal locality. That is, the data should be kept in
    /// the cache as it is likely to be accessed again soon.
    locality: u2 = 3,
    /// The cache that the prefetch should be performed on.
    cache: Cache = .data,

    pub const Rw = enum(u1) {
        read,
        write,
    };

    pub const Cache = enum(u1) {
        instruction,
        data,
    };
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const ExportOptions = struct {
    name: []const u8,
    linkage: GlobalLinkage = .strong,
    section: ?[]const u8 = null,
    visibility: SymbolVisibility = .default,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const ExternOptions = struct {
    name: []const u8,
    library_name: ?[]const u8 = null,
    linkage: GlobalLinkage = .strong,
    is_thread_local: bool = false,
    is_dll_import: bool = false,
};

/// This data structure is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const BranchHint = enum(u3) {
    /// Equivalent to no hint given.
    none,
    /// This branch of control flow is more likely to be reached than its peers.
    /// The optimizer should optimize for reaching it.
    likely,
    /// This branch of control flow is less likely to be reached than its peers.
    /// The optimizer should optimize for not reaching it.
    unlikely,
    /// This branch of control flow is unlikely to *ever* be reached.
    /// The optimizer may place it in a different page of memory to optimize other branches.
    cold,
    /// It is difficult to predict whether this branch of control flow will be reached.
    /// The optimizer should avoid branching behavior with expensive mispredictions.
    unpredictable,
};

/// This enum is set by the compiler and communicates which compiler backend is
/// used to produce machine code.
/// Think carefully before deciding to observe this value. Nearly all code should
/// be agnostic to the backend that implements the language. The use case
/// to use this value is to **work around problems with compiler implementations.**
///
/// Avoid failing the compilation if the compiler backend does not match a
/// whitelist of backends; rather one should detect that a known problem would
/// occur in a blacklist of backends.
///
/// The enum is nonexhaustive so that alternate Zig language implementations may
/// choose a number as their tag (please use a random number generator rather
/// than a "cute" number) and codebases can interact with these values even if
/// this upstream enum does not have a name for the number. Of course, upstream
/// is happy to accept pull requests to add Zig implementations to this enum.
///
/// This data structure is part of the Zig language specification.
pub const CompilerBackend = enum(u64) {
    /// It is allowed for a compiler implementation to not reveal its identity,
    /// in which case this value is appropriate. Be cool and make sure your
    /// code supports `other` Zig compilers!
    other = 0,
    /// The original Zig compiler created in 2015 by Andrew Kelley. Implemented
    /// in C++. Used LLVM. Deleted from the ZSF ziglang/zig codebase on
    /// December 6th, 2022.
    stage1 = 1,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// LLVM backend.
    stage2_llvm = 2,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// backend that generates C source code.
    /// Note that one can observe whether the compilation will output C code
    /// directly with `object_format` value rather than the `compiler_backend` value.
    stage2_c = 3,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// WebAssembly backend.
    stage2_wasm = 4,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// arm backend.
    stage2_arm = 5,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// x86_64 backend.
    stage2_x86_64 = 6,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// aarch64 backend.
    stage2_aarch64 = 7,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// x86 backend.
    stage2_x86 = 8,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// riscv64 backend.
    stage2_riscv64 = 9,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// sparc64 backend.
    stage2_sparc64 = 10,
    /// The reference implementation self-hosted compiler of Zig, using the
    /// spirv backend.
    stage2_spirv64 = 11,

    _,
};

/// This function type is used by the Zig language code generation and
/// therefore must be kept in sync with the compiler implementation.
pub const TestFn = struct {
    name: []const u8,
    func: *const fn () anyerror!void,
};

/// Deprecated, use the `Panic` namespace instead.
/// To be deleted after 0.14.0 is released.
pub const PanicFn = fn ([]const u8, ?*StackTrace, ?usize) noreturn;

/// This namespace is used by the Zig compiler to emit various kinds of safety
/// panics. These can be overridden by making a public `panic` namespace in the
/// root source file.
pub const panic: type = p: {
    if (@hasDecl(root, "panic")) {
        if (@TypeOf(root.panic) != type) {
            // Deprecated; make `panic` a namespace instead.
            break :p std.debug.FullPanic(struct {
                fn panic(msg: []const u8, ra: ?usize) noreturn {
                    root.panic(msg, @errorReturnTrace(), ra);
                }
            }.panic);
        }
        break :p root.panic;
    }
    if (@hasDecl(root, "Panic")) {
        break :p root.Panic; // Deprecated; use `panic` instead.
    }
    if (builtin.zig_backend == .stage2_riscv64) {
        break :p std.debug.simple_panic;
    }
    break :p std.debug.FullPanic(std.debug.defaultPanic);
};

pub noinline fn returnError() void {
    @branchHint(.unlikely);
    @setRuntimeSafety(false);
    const st = @errorReturnTrace().?;
    if (st.index < st.instruction_addresses.len)
        st.instruction_addresses[st.index] = @returnAddress();
    st.index += 1;
}

const std = @import("std.zig");
const root = @import("root");
const std = @import("std");
const builtin = @import("builtin");
const c = @This();
const maxInt = std.math.maxInt;
const assert = std.debug.assert;
const page_size = std.heap.page_size_min;
const native_abi = builtin.abi;
const native_arch = builtin.cpu.arch;
const native_os = builtin.os.tag;
const linux = std.os.linux;
const emscripten = std.os.emscripten;
const wasi = std.os.wasi;
const windows = std.os.windows;
const ws2_32 = std.os.windows.ws2_32;
const darwin = @import("c/darwin.zig");
const freebsd = @import("c/freebsd.zig");
const solaris = @import("c/solaris.zig");
const netbsd = @import("c/netbsd.zig");
const dragonfly = @import("c/dragonfly.zig");
const haiku = @import("c/haiku.zig");
const openbsd = @import("c/openbsd.zig");
const serenity = @import("c/serenity.zig");

// These constants are shared among all operating systems even when not linking
// libc.

pub const iovec = std.posix.iovec;
pub const iovec_const = std.posix.iovec_const;
pub const LOCK = std.posix.LOCK;
pub const winsize = std.posix.winsize;

/// The value of the link editor defined symbol _MH_EXECUTE_SYM is the address
/// of the mach header in a Mach-O executable file type.  It does not appear in
/// any file type other than a MH_EXECUTE file type.  The type of the symbol is
/// absolute as the header is not part of any section.
/// This symbol is populated when linking the system's libc, which is guaranteed
/// on this operating system. However when building object files or libraries,
/// the system libc won't be linked until the final executable. So we
/// export a weak symbol here, to be overridden by the real one.
pub extern var _mh_execute_header: mach_hdr;
var dummy_execute_header: mach_hdr = undefined;
comptime {
    if (native_os.isDarwin()) {
        @export(&dummy_execute_header, .{ .name = "_mh_execute_header", .linkage = .weak });
    }
}

/// * If not linking libc, returns `false`.
/// * If linking musl libc, returns `true`.
/// * If linking GNU libc (glibc), returns `true` if the target version is greater than or equal to
///   `version`.
/// * If linking Android libc (bionic), returns `true` if the target API level is greater than or
///   equal to `version.major`, ignoring other components.
/// * If linking a libc other than these, returns `false`.
pub inline fn versionCheck(comptime version: std.SemanticVersion) bool {
    return comptime blk: {
        if (!builtin.link_libc) break :blk false;
        if (native_abi.isMusl()) break :blk true;
        if (builtin.target.isGnuLibC()) {
            const ver = builtin.os.versionRange().gnuLibCVersion().?;
            break :blk switch (ver.order(version)) {
                .gt, .eq => true,
                .lt => false,
            };
        } else if (builtin.abi.isAndroid()) {
            break :blk builtin.os.version_range.linux.android >= version.major;
        } else {
            break :blk false;
        }
    };
}

pub const ino_t = switch (native_os) {
    .linux => linux.ino_t,
    .emscripten => emscripten.ino_t,
    .wasi => wasi.inode_t,
    .windows => windows.LARGE_INTEGER,
    .haiku => i64,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L38
    else => u64,
};

pub const off_t = switch (native_os) {
    .linux => linux.off_t,
    .emscripten => emscripten.off_t,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L39
    else => i64,
};

pub const timespec = switch (native_os) {
    .linux => linux.timespec,
    .emscripten => emscripten.timespec,
    .wasi => extern struct {
        sec: time_t,
        nsec: isize,

        pub fn fromTimestamp(tm: wasi.timestamp_t) timespec {
            const sec: wasi.timestamp_t = tm / 1_000_000_000;
            const nsec = tm - sec * 1_000_000_000;
            return .{
                .sec = @as(time_t, @intCast(sec)),
                .nsec = @as(isize, @intCast(nsec)),
            };
        }

        pub fn toTimestamp(ts: timespec) wasi.timestamp_t {
            return @as(wasi.timestamp_t, @intCast(ts.sec * 1_000_000_000)) +
                @as(wasi.timestamp_t, @intCast(ts.nsec));
        }
    },
    // https://github.com/SerenityOS/serenity/blob/0a78056453578c18e0a04a0b45ebfb1c96d59005/Kernel/API/POSIX/time.h#L17-L20
    .windows, .serenity => extern struct {
        sec: time_t,
        nsec: c_long,
    },
    .dragonfly, .freebsd, .macos, .ios, .tvos, .watchos, .visionos => extern struct {
        sec: isize,
        nsec: isize,
    },
    .netbsd, .solaris, .illumos => extern struct {
        sec: i64,
        nsec: isize,
    },
    .openbsd, .haiku => extern struct {
        sec: time_t,
        nsec: isize,
    },
    else => void,
};

pub const dev_t = switch (native_os) {
    .linux => linux.dev_t,
    .emscripten => emscripten.dev_t,
    .wasi => wasi.device_t,
    .openbsd, .haiku, .solaris, .illumos, .macos, .ios, .tvos, .watchos, .visionos => i32,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L43
    .netbsd, .freebsd, .serenity => u64,
    else => void,
};

pub const mode_t = switch (native_os) {
    .linux => linux.mode_t,
    .emscripten => emscripten.mode_t,
    .openbsd, .haiku, .netbsd, .solaris, .illumos, .wasi, .windows => u32,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L44
    .freebsd, .macos, .ios, .tvos, .watchos, .visionos, .dragonfly, .serenity => u16,
    else => u0,
};

pub const nlink_t = switch (native_os) {
    .linux => linux.nlink_t,
    .emscripten => emscripten.nlink_t,
    .wasi => c_ulonglong,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L45
    .freebsd, .serenity => u64,
    .openbsd, .netbsd, .solaris, .illumos => u32,
    .haiku => i32,
    else => void,
};

pub const uid_t = switch (native_os) {
    .linux => linux.uid_t,
    .emscripten => emscripten.uid_t,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L28
    else => u32,
};

pub const gid_t = switch (native_os) {
    .linux => linux.gid_t,
    .emscripten => emscripten.gid_t,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L29
    else => u32,
};

pub const blksize_t = switch (native_os) {
    .linux => linux.blksize_t,
    .emscripten => emscripten.blksize_t,
    .wasi => c_long,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L42
    .serenity => u64,
    else => i32,
};

pub const passwd = switch (native_os) {
    // https://github.com/SerenityOS/serenity/blob/7442cfb5072b74a62c0e061e6e9ff44fda08780d/Userland/Libraries/LibC/pwd.h#L15-L23
    .linux, .serenity => extern struct {
        name: ?[*:0]const u8, // username
        passwd: ?[*:0]const u8, // user password
        uid: uid_t, // user ID
        gid: gid_t, // group ID
        gecos: ?[*:0]const u8, // user information
        dir: ?[*:0]const u8, // home directory
        shell: ?[*:0]const u8, // shell program
    },
    .netbsd, .openbsd, .macos => extern struct {
        name: ?[*:0]const u8, // user name
        passwd: ?[*:0]const u8, // encrypted password
        uid: uid_t, // user uid
        gid: gid_t, // user gid
        change: time_t, // password change time
        class: ?[*:0]const u8, // user access class
        gecos: ?[*:0]const u8, // Honeywell login info
        dir: ?[*:0]const u8, // home directory
        shell: ?[*:0]const u8, // default shell
        expire: time_t, // account expiration
    },
    else => void,
};

pub const blkcnt_t = switch (native_os) {
    .linux => linux.blkcnt_t,
    .emscripten => emscripten.blkcnt_t,
    .wasi => c_longlong,
    // https://github.com/SerenityOS/serenity/blob/b98f537f117b341788023ab82e0c11ca9ae29a57/Kernel/API/POSIX/sys/types.h#L41
    .serenity => u64,
    else => i64,
};

pub const fd_t = switch (native_os) {
    .linux => linux.fd_t,
    .wasi => wasi.fd_t,
    .windows => windows.HANDLE,
    .serenity => c_int,
    else => i32,
};

pub const ARCH = switch (native_os) {
    .linux => linux.ARCH,
    else => void,
};

// For use with posix.timerfd_create()
// Actually, the parameter for the timerfd_create() function is an integer,
// which means that the developer has to figure out which value is appropriate.
// To make this easier and, above all, safer, because an incorrect value leads
// to a panic, an enum is introduced which only allows the values
// that actually work.
pub const TIMERFD_CLOCK = timerfd_clockid_t;
pub const timerfd_clockid_t = switch (native_os) {
    .freebsd => enum(u32) {
        REALTIME = 0,
        MONOTONIC = 4,
        _,
    },
    .linux => linux.timerfd_clockid_t,
    else => clockid_t,
};

pub const CLOCK = clockid_t;
pub const clockid_t = switch (native_os) {
    .linux, .emscripten => linux.clockid_t,
    .wasi => wasi.clockid_t,
    .macos, .ios, .tvos, .watchos, .visionos => enum(u32) {
        REALTIME = 0,
        MONOTONIC = 6,
        MONOTONIC_RAW = 4,
        MONOTONIC_RAW_APPROX = 5,
        UPTIME_RAW = 8,
        UPTIME_RAW_APPROX = 9,
        PROCESS_CPUTIME_ID = 12,
        THREAD_CPUTIME_ID = 16,
        _,
    },
    .haiku => enum(i32) {
        /// system-wide monotonic clock (aka system time)
        MONOTONIC = 0,
        /// system-wide real time clock
        REALTIME = -1,
        /// clock measuring the used CPU time of the current process
        PROCESS_CPUTIME_ID = -2,
        /// clock measuring the used CPU time of the current thread
        THREAD_CPUTIME_ID = -3,
    },
    .freebsd => enum(u32) {
        REALTIME = 0,
        VIRTUAL = 1,
        PROF = 2,
        MONOTONIC = 4,
        UPTIME = 5,
        UPTIME_PRECISE = 7,
        UPTIME_FAST = 8,
        REALTIME_PRECISE = 9,
        REALTIME_FAST = 10,
        MONOTONIC_PRECISE = 11,
        MONOTONIC_FAST = 12,
        SECOND = 13,
        THREAD_CPUTIME_ID = 14,
        PROCESS_CPUTIME_ID = 15,
    },
    .solaris, .illumos => enum(u32) {
        VIRTUAL = 1,
        THREAD_CPUTIME_ID = 2,
        REALTIME = 3,
        MONOTONIC = 4,
        PROCESS_CPUTIME_ID = 5,
    },
    .netbsd => enum(u32) {
        REALTIME = 0,
        VIRTUAL = 1,
        PROF = 2,
        MONOTONIC = 3,
        THREAD_CPUTIME_ID = 0x20000000,
        PROCESS_CPUTIME_ID = 0x40000000,
    },
    .dragonfly => enum(u32) {
        REALTIME = 0,
        VIRTUAL = 1,
        PROF = 2,
        MONOTONIC = 4,
        UPTIME = 5,
        UPTIME_PRECISE = 7,
        UPTIME_FAST = 8,
        REALTIME_PRECISE = 9,
        REALTIME_FAST = 10,
        MONOTONIC_PRECISE = 11,
        MONOTONIC_FAST = 12,
        SECOND = 13,
        THREAD_CPUTIME_ID = 14,
        PROCESS_CPUTIME_ID = 15,
    },
    .openbsd => enum(u32) {
        REALTIME = 0,
        PROCESS_CPUTIME_ID = 2,
        MONOTONIC = 3,
        THREAD_CPUTIME_ID = 4,
    },
    // https://github.com/SerenityOS/serenity/blob/0a78056453578c18e0a04a0b45ebfb1c96d59005/Kernel/API/POSIX/time.h#L24-L36
    .serenity => enum(c_int) {
        REALTIME = 0,
        MONOTONIC = 1,
        MONOTONIC_RAW = 2,
        REALTIME_COARSE = 3,
        MONOTONIC_COARSE = 4,
    },
    else => void,
};
pub const CPU_COUNT = switch (native_os) {
    .linux => linux.CPU_COUNT,
    .emscripten => emscripten.CPU_COUNT,
    else => void,
};
pub const E = switch (native_os) {
    .linux => linux.E,
    .emscripten => emscripten.E,
    .wasi => wasi.errno_t,
    .windows => enum(u16) {
        /// No error occurred.
        SUCCESS = 0,
        PERM = 1,
        NOENT = 2,
        SRCH = 3,
        INTR = 4,
        IO = 5,
        NXIO = 6,
        @"2BIG" = 7,
        NOEXEC = 8,
        BADF = 9,
        CHILD = 10,
        AGAIN = 11,
        NOMEM = 12,
        ACCES = 13,
        FAULT = 14,
        BUSY = 16,
        EXIST = 17,
        XDEV = 18,
        NODEV = 19,
        NOTDIR = 20,
        ISDIR = 21,
        NFILE = 23,
        MFILE = 24,
        NOTTY = 25,
        FBIG = 27,
        NOSPC = 28,
        SPIPE = 29,
        ROFS = 30,
        MLINK = 31,
        PIPE = 32,
        DOM = 33,
        /// Also means `DEADLOCK`.
        DEADLK = 36,
        NAMETOOLONG = 38,
        NOLCK = 39,
        NOSYS = 40,
        NOTEMPTY = 41,

        INVAL = 22,
        RANGE = 34,
        ILSEQ = 42,

        // POSIX Supplement
        ADDRINUSE = 100,
        ADDRNOTAVAIL = 101,
        AFNOSUPPORT = 102,
        ALREADY = 103,
        BADMSG = 104,
        CANCELED = 105,
        CONNABORTED = 106,
        CONNREFUSED = 107,
        CONNRESET = 108,
        DESTADDRREQ = 109,
        HOSTUNREACH = 110,
        IDRM = 111,
        INPROGRESS = 112,
        ISCONN = 113,
        LOOP = 114,
        MSGSIZE = 115,
        NETDOWN = 116,
        NETRESET = 117,
        NETUNREACH = 118,
        NOBUFS = 119,
        NODATA = 120,
        NOLINK = 121,
        NOMSG = 122,
        NOPROTOOPT = 123,
        NOSR = 124,
        NOSTR = 125,
        NOTCONN = 126,
        NOTRECOVERABLE = 127,
        NOTSOCK = 128,
        NOTSUP = 129,
        OPNOTSUPP = 130,
        OTHER = 131,
        OVERFLOW = 132,
        OWNERDEAD = 133,
        PROTO = 134,
        PROTONOSUPPORT = 135,
        PROTOTYPE = 136,
        TIME = 137,
        TIMEDOUT = 138,
        TXTBSY = 139,
        WOULDBLOCK = 140,
        DQUOT = 10069,
        _,
    },
    .macos, .ios, .tvos, .watchos, .visionos => darwin.E,
    .freebsd => freebsd.E,
    .solaris, .illumos => enum(u16) {
        /// No error occurred.
        SUCCESS = 0,
        /// Not super-user
        PERM = 1,
        /// No such file or directory
        NOENT = 2,
        /// No such process
        SRCH = 3,
        /// interrupted system call
        INTR = 4,
        /// I/O error
        IO = 5,
        /// No such device or address
        NXIO = 6,
        /// Arg list too long
        @"2BIG" = 7,
        /// Exec format error
        NOEXEC = 8,
        /// Bad file number
        BADF = 9,
        /// No children
        CHILD = 10,
        /// Resource temporarily unavailable.
        /// also: WOULDBLOCK: Operation would block.
        AGAIN = 11,
        /// Not enough core
        NOMEM = 12,
        /// Permission denied
        ACCES = 13,
        /// Bad address
        FAULT = 14,
        /// Block device required
        NOTBLK = 15,
        /// Mount device busy
        BUSY = 16,
        /// File exists
        EXIST = 17,
        /// Cross-device link
        XDEV = 18,
        /// No such device
        NODEV = 19,
        /// Not a directory
        NOTDIR = 20,
        /// Is a directory
        ISDIR = 21,
        /// Invalid argument
        INVAL = 22,
        /// File table overflow
        NFILE = 23,
        /// Too many open files
        MFILE = 24,
        /// Inappropriate ioctl for device
        NOTTY = 25,
        /// Text file busy
        TXTBSY = 26,
        /// File too large
        FBIG = 27,
        /// No space left on device
        NOSPC = 28,
        /// Illegal seek
        SPIPE = 29,
        /// Read only file system
        ROFS = 30,
        /// Too many links
        MLINK = 31,
        /// Broken pipe
        PIPE = 32,
        /// Math arg out of domain of func
        DOM = 33,
        /// Math result not representable
        RANGE = 34,
        /// No message of desired type
        NOMSG = 35,
        /// Identifier removed
        IDRM = 36,
        /// Channel number out of range
        CHRNG = 37,
        /// Level 2 not synchronized
        L2NSYNC = 38,
        /// Level 3 halted
        L3HLT = 39,
        /// Level 3 reset
        L3RST = 40,
        /// Link number out of range
        LNRNG = 41,
        /// Protocol driver not attached
        UNATCH = 42,
        /// No CSI structure available
        NOCSI = 43,
        /// Level 2 halted
        L2HLT = 44,
        /// Deadlock condition.
        DEADLK = 45,
        /// No record locks available.
        NOLCK = 46,
        /// Operation canceled
        CANCELED = 47,
        /// Operation not supported
        NOTSUP = 48,

        // Filesystem Quotas
        /// Disc quota exceeded
        DQUOT = 49,

        // Convergent Error Returns
        /// invalid exchange
        BADE = 50,
        /// invalid request descriptor
        BADR = 51,
        /// exchange full
        XFULL = 52,
        /// no anode
        NOANO = 53,
        /// invalid request code
        BADRQC = 54,
        /// invalid slot
        BADSLT = 55,
        /// file locking deadlock error
        DEADLOCK = 56,
        /// bad font file fmt
        BFONT = 57,

        // Interprocess Robust Locks
        /// process died with the lock
        OWNERDEAD = 58,
        /// lock is not recoverable
        NOTRECOVERABLE = 59,
        /// locked lock was unmapped
        LOCKUNMAPPED = 72,
        /// Facility is not active
        NOTACTIVE = 73,
        /// multihop attempted
        MULTIHOP = 74,
        /// trying to read unreadable message
        BADMSG = 77,
        /// path name is too long
        NAMETOOLONG = 78,
        /// value too large to be stored in data type
        OVERFLOW = 79,
        /// given log. name not unique
        NOTUNIQ = 80,
        /// f.d. invalid for this operation
        BADFD = 81,
        /// Remote address changed
        REMCHG = 82,

        // Stream Problems
        /// Device not a stream
        NOSTR = 60,
        /// no data (for no delay io)
        NODATA = 61,
        /// timer expired
        TIME = 62,
        /// out of streams resources
        NOSR = 63,
        /// Machine is not on the network
        NONET = 64,
        /// Package not installed
        NOPKG = 65,
        /// The object is remote
        REMOTE = 66,
        /// the link has been severed
        NOLINK = 67,
        /// advertise error
        ADV = 68,
        /// srmount error
        SRMNT = 69,
        /// Communication error on send
        COMM = 70,
        /// Protocol error
        PROTO = 71,

        // Shared Library Problems
        /// Can't access a needed shared lib.
        LIBACC = 83,
        /// Accessing a corrupted shared lib.
        LIBBAD = 84,
        /// .lib section in a.out corrupted.
        LIBSCN = 85,
        /// Attempting to link in too many libs.
        LIBMAX = 86,
        /// Attempting to exec a shared library.
        LIBEXEC = 87,
        /// Illegal byte sequence.
        ILSEQ = 88,
        /// Unsupported file system operation
        NOSYS = 89,
        /// Symbolic link loop
        LOOP = 90,
        /// Restartable system call
        RESTART = 91,
        /// if pipe/FIFO, don't sleep in stream head
        STRPIPE = 92,
        /// directory not empty
        NOTEMPTY = 93,
        /// Too many users (for UFS)
        USERS = 94,

        // BSD Networking Software
        // Argument Errors
        /// Socket operation on non-socket
        NOTSOCK = 95,
        /// Destination address required
        DESTADDRREQ = 96,
        /// Message too long
        MSGSIZE = 97,
        /// Protocol wrong type for socket
        PROTOTYPE = 98,
        /// Protocol not available
        NOPROTOOPT = 99,
        /// Protocol not supported
        PROTONOSUPPORT = 120,
        /// Socket type not supported
        SOCKTNOSUPPORT = 121,
        /// Operation not supported on socket
        OPNOTSUPP = 122,
        /// Protocol family not supported
        PFNOSUPPORT = 123,
        /// Address family not supported by
        AFNOSUPPORT = 124,
        /// Address already in use
        ADDRINUSE = 125,
        /// Can't assign requested address
        ADDRNOTAVAIL = 126,

        // Operational Errors
        /// Network is down
        NETDOWN = 127,
        /// Network is unreachable
        NETUNREACH = 128,
        /// Network dropped connection because
        NETRESET = 129,
        /// Software caused connection abort
        CONNABORTED = 130,
        /// Connection reset by peer
        CONNRESET = 131,
        /// No buffer space available
        NOBUFS = 132,
        /// Socket is already connected
        ISCONN = 133,
        /// Socket is not connected
        NOTCONN = 134,
        /// Can't send after socket shutdown
        SHUTDOWN = 143,
        /// Too many references: can't splice
        TOOMANYREFS = 144,
        /// Connection timed out
        TIMEDOUT = 145,
        /// Connection refused
        CONNREFUSED = 146,
        /// Host is down
        HOSTDOWN = 147,
        /// No route to host
        HOSTUNREACH = 148,
        /// operation already in progress
        ALREADY = 149,
        /// operation now in progress
        INPROGRESS = 150,

        // SUN Network File System
        /// Stale NFS file handle
        STALE = 151,

        _,
    },
    .netbsd => netbsd.E,
    .dragonfly => dragonfly.E,
    .haiku => haiku.E,
    .openbsd => openbsd.E,
    // https://github.com/SerenityOS/serenity/blob/dd59fe35c7e5bbaf6b6b3acb3f9edc56619d4b66/Kernel/API/POSIX/errno.h
    .serenity => enum(c_int) {
        SUCCESS = 0,
        PERM = 1,
        NOENT = 2,
        SRCH = 3,
        INTR = 4,
        IO = 5,
        NXIO = 6,
        @"2BIG" = 7,
        NOEXEC = 8,
        BADF = 9,
        CHILD = 10,
        AGAIN = 11,
        NOMEM = 12,
        ACCES = 13,
        FAULT = 14,
        NOTBLK = 15,
        BUSY = 16,
        EXIST = 17,
        XDEV = 18,
        NODEV = 19,
        NOTDIR = 20,
        ISDIR = 21,
        INVAL = 22,
        NFILE = 23,
        MFILE = 24,
        NOTTY = 25,
        TXTBSY = 26,
        FBIG = 27,
        NOSPC = 28,
        SPIPE = 29,
        ROFS = 30,
        MLINK = 31,
        PIPE = 32,
        RANGE = 33,
        NAMETOOLONG = 34,
        LOOP = 35,
        OVERFLOW = 36,
        OPNOTSUPP = 37,
        NOSYS = 38,
        NOTIMPL = 39,
        AFNOSUPPORT = 40,
        NOTSOCK = 41,
        ADDRINUSE = 42,
        NOTEMPTY = 43,
        DOM = 44,
        CONNREFUSED = 45,
        HOSTDOWN = 46,
        ADDRNOTAVAIL = 47,
        ISCONN = 48,
        CONNABORTED = 49,
        ALREADY = 50,
        CONNRESET = 51,
        DESTADDRREQ = 52,
        HOSTUNREACH = 53,
        ILSEQ = 54,
        MSGSIZE = 55,
        NETDOWN = 56,
        NETUNREACH = 57,
        NETRESET = 58,
        NOBUFS = 59,
        NOLCK = 60,
        NOMSG = 61,
        NOPROTOOPT = 62,
        NOTCONN = 63,
        SHUTDOWN = 64,
        TOOMANYREFS = 65,
        SOCKTNOSUPPORT = 66,
        PROTONOSUPPORT = 67,
        DEADLK = 68,
        TIMEDOUT = 69,
        PROTOTYPE = 70,
        INPROGRESS = 71,
        NOTHREAD = 72,
        PROTO = 73,
        NOTSUP = 74,
        PFNOSUPPORT = 75,
        DIRINTOSELF = 76,
        DQUOT = 77,
        NOTRECOVERABLE = 78,
        CANCELED = 79,
        PROMISEVIOLATION = 80,
        STALE = 81,
        SRCNOTFOUND = 82,
        _,
    },
    else => void,
};
pub const Elf_Symndx = switch (native_os) {
    .linux => linux.Elf_Symndx,
    else => void,
};
/// Command flags for fcntl(2).
pub const F = switch (native_os) {
    .linux => linux.F,
    .emscripten => emscripten.F,
    .wasi => struct {
        // Match `F_*` constants from lib/libc/include/wasm-wasi-musl/__header_fcntl.h
        pub const GETFD = 1;
        pub const SETFD = 2;
        pub const GETFL = 3;
        pub const SETFL = 4;
    },
    .macos, .ios, .tvos, .watchos, .visionos => struct {
        /// duplicate file descriptor
        pub const DUPFD = 0;
        /// get file descriptor flags
        pub const GETFD = 1;
        /// set file descriptor flags
        pub const SETFD = 2;
        /// get file status flags
        pub const GETFL = 3;
        /// set file status flags
        pub const SETFL = 4;
        /// get SIGIO/SIGURG proc/pgrp
        pub const GETOWN = 5;
        /// set SIGIO/SIGURG proc/pgrp
        pub const SETOWN = 6;
        /// get record locking information
        pub const GETLK = 7;
        /// set record locking information
        pub const SETLK = 8;
        /// F.SETLK; wait if blocked
        pub const SETLKW = 9;
        /// F.SETLK; wait if blocked, return on timeout
        pub const SETLKWTIMEOUT = 10;
        pub const FLUSH_DATA = 40;
        /// Used for regression test
        pub const CHKCLEAN = 41;
        /// Preallocate storage
        pub const PREALLOCATE = 42;
        /// Truncate a file without zeroing space
        pub const SETSIZE = 43;
        /// Issue an advisory read async with no copy to user
        pub const RDADVISE = 44;
        /// turn read ahead off/on for this fd
        pub const RDAHEAD = 45;
        /// turn data caching off/on for this fd
        pub const NOCACHE = 48;
        /// file offset to device offset
        pub const LOG2PHYS = 49;
        /// return the full path of the fd
        pub const GETPATH = 50;
        /// fsync + ask the drive to flush to the media
        pub const FULLFSYNC = 51;
        /// find which component (if any) is a package
        pub const PATHPKG_CHECK = 52;
        /// "freeze" all fs operations
        pub const FREEZE_FS = 53;
        /// "thaw" all fs operations
        pub const THAW_FS = 54;
        /// turn data caching off/on (globally) for this file
        pub const GLOBAL_NOCACHE = 55;
        /// add detached signatures
        pub const ADDSIGS = 59;
        /// add signature from same file (used by dyld for shared libs)
        pub const ADDFILESIGS = 61;
        /// used in conjunction with F.NOCACHE to indicate that DIRECT, synchronous writes
        /// should not be used (i.e. its ok to temporarily create cached pages)
        pub const NODIRECT = 62;
        /// Get the protection class of a file from the EA, returns int
        pub const GETPROTECTIONCLASS = 63;
        /// Set the protection class of a file for the EA, requires int
        pub const SETPROTECTIONCLASS = 64;
        /// file offset to device offset, extended
        pub const LOG2PHYS_EXT = 65;
        /// get record locking information, per-process
        pub const GETLKPID = 66;
        /// Mark the file as being the backing store for another filesystem
        pub const SETBACKINGSTORE = 70;
        /// return the full path of the FD, but error in specific mtmd circumstances
        pub const GETPATH_MTMINFO = 71;
        /// Returns the code directory, with associated hashes, to the caller
        pub const GETCODEDIR = 72;
        /// No SIGPIPE generated on EPIPE
        pub const SETNOSIGPIPE = 73;
        /// Status of SIGPIPE for this fd
        pub const GETNOSIGPIPE = 74;
        /// For some cases, we need to rewrap the key for AKS/MKB
        pub const TRANSCODEKEY = 75;
        /// file being written to a by single writer... if throttling enabled, writes
        /// may be broken into smaller chunks with throttling in between
        pub const SINGLE_WRITER = 76;
        /// Get the protection version number for this filesystem
        pub const GETPROTECTIONLEVEL = 77;
        /// Add detached code signatures (used by dyld for shared libs)
        pub const FINDSIGS = 78;
        /// Add signature from same file, only if it is signed by Apple (used by dyld for simulator)
        pub const ADDFILESIGS_FOR_DYLD_SIM = 83;
        /// fsync + issue barrier to drive
        pub const BARRIERFSYNC = 85;
        /// Add signature from same file, return end offset in structure on success
        pub const ADDFILESIGS_RETURN = 97;
        /// Check if Library Validation allows this Mach-O file to be mapped into the calling process
        pub const CHECK_LV = 98;
        /// Deallocate a range of the file
        pub const PUNCHHOLE = 99;
        /// Trim an active file
        pub const TRIM_ACTIVE_FILE = 100;
        /// mark the dup with FD_CLOEXEC
        pub const DUPFD_CLOEXEC = 67;
        /// shared or read lock
        pub const RDLCK = 1;
        /// unlock
        pub const UNLCK = 2;
        /// exclusive or write lock
        pub const WRLCK = 3;
    },
    .freebsd => struct {
        /// Duplicate file descriptor.
        pub const DUPFD = 0;
        /// Get file descriptor flags.
        pub const GETFD = 1;
        /// Set file descriptor flags.
        pub const SETFD = 2;
        /// Get file status flags.
        pub const GETFL = 3;
        /// Set file status flags.
        pub const SETFL = 4;

        /// Get SIGIO/SIGURG proc/pgrrp.
        pub const GETOWN = 5;
        /// Set SIGIO/SIGURG proc/pgrrp.
        pub const SETOWN = 6;

        /// Get record locking information.
        pub const GETLK = 11;
        /// Set record locking information.
        pub const SETLK = 12;
        /// Set record locking information and wait if blocked.
        pub const SETLKW = 13;

        /// Debugging support for remote locks.
        pub const SETLK_REMOTE = 14;
        /// Read ahead.
        pub const READAHEAD = 15;

        /// DUPFD with FD_CLOEXEC set.
        pub const DUPFD_CLOEXEC = 17;
        /// DUP2FD with FD_CLOEXEC set.
        pub const DUP2FD_CLOEXEC = 18;

        pub const ADD_SEALS = 19;
        pub const GET_SEALS = 20;
        /// Return `kinfo_file` for a file descriptor.
        pub const KINFO = 22;

        // Seals (ADD_SEALS, GET_SEALS)
        /// Prevent adding sealings.
        pub const SEAL_SEAL = 0x0001;
        /// May not shrink
        pub const SEAL_SHRINK = 0x0002;
        /// May not grow.
        pub const SEAL_GROW = 0x0004;
        /// May not write.
        pub const SEAL_WRITE = 0x0008;

        // Record locking flags (GETLK, SETLK, SETLKW).
        /// Shared or read lock.
        pub const RDLCK = 1;
        /// Unlock.
        pub const UNLCK = 2;
        /// Exclusive or write lock.
        pub const WRLCK = 3;
        /// Purge locks for a given system ID.
        pub const UNLCKSYS = 4;
        /// Cancel an async lock request.
        pub const CANCEL = 5;

        pub const SETOWN_EX = 15;
        pub const GETOWN_EX = 16;

        pub const GETOWNER_UIDS = 17;
    },
    .solaris, .illumos => struct {
        /// Unlock a previously locked region
        pub const ULOCK = 0;
        /// Lock a region for exclusive use
        pub const LOCK = 1;
        /// Test and lock a region for exclusive use
        pub const TLOCK = 2;
        /// Test a region for other processes locks
        pub const TEST = 3;

        /// Duplicate fildes
        pub const DUPFD = 0;
        /// Get fildes flags
        pub const GETFD = 1;
        /// Set fildes flags
        pub const SETFD = 2;
        /// Get file flags
        pub const GETFL = 3;
        /// Get file flags including open-only flags
        pub const GETXFL = 45;
        /// Set file flags
        pub const SETFL = 4;

        /// Unused
        pub const CHKFL = 8;
        /// Duplicate fildes at third arg
        pub const DUP2FD = 9;
        /// Like DUP2FD with O_CLOEXEC set EINVAL is fildes matches arg1
        pub const DUP2FD_CLOEXEC = 36;
        /// Like DUPFD with O_CLOEXEC set
        pub const DUPFD_CLOEXEC = 37;

        /// Is the file desc. a stream ?
        pub const ISSTREAM = 13;
        /// Turn on private access to file
        pub const PRIV = 15;
        /// Turn off private access to file
        pub const NPRIV = 16;
        /// UFS quota call
        pub const QUOTACTL = 17;
        /// Get number of BLKSIZE blocks allocated
        pub const BLOCKS = 18;
        /// Get optimal I/O block size
        pub const BLKSIZE = 19;
        /// Get owner (socket emulation)
        pub const GETOWN = 23;
        /// Set owner (socket emulation)
        pub const SETOWN = 24;
        /// Object reuse revoke access to file desc.
        pub const REVOKE = 25;
        /// Does vp have NFS locks private to lock manager
        pub const HASREMOTELOCKS = 26;

        /// Set file lock
        pub const SETLK = 6;
        /// Set file lock and wait
        pub const SETLKW = 7;
        /// Allocate file space
        pub const ALLOCSP = 10;
        /// Free file space
        pub const FREESP = 11;
        /// Get file lock
        pub const GETLK = 14;
        /// Get file lock owned by file
        pub const OFD_GETLK = 47;
        /// Set file lock owned by file
        pub const OFD_SETLK = 48;
        /// Set file lock owned by file and wait
        pub const OFD_SETLKW = 49;
        /// Set a file share reservation
        pub const SHARE = 40;
        /// Remove a file share reservation
        pub const UNSHARE = 41;
        /// Create Poison FD
        pub const BADFD = 46;

        /// Read lock
        pub const RDLCK = 1;
        /// Write lock
        pub const WRLCK = 2;
        /// Remove lock(s)
        pub const UNLCK = 3;
        /// remove remote locks for a given system
        pub const UNLKSYS = 4;

        // f_access values
        /// Read-only share access
        pub const RDACC = 0x1;
        /// Write-only share access
        pub const WRACC = 0x2;
        /// Read-Write share access
        pub const RWACC = 0x3;

        // f_deny values
        /// Don't deny others access
        pub const NODNY = 0x0;
        /// Deny others read share access
        pub const RDDNY = 0x1;
        /// Deny others write share access
        pub const WRDNY = 0x2;
        /// Deny others read or write share access
        pub const RWDNY = 0x3;
        /// private flag: Deny delete share access
        pub const RMDNY = 0x4;
    },
    .netbsd => struct {
        pub const DUPFD = 0;
        pub const GETFD = 1;
        pub const SETFD = 2;
        pub const GETFL = 3;
        pub const SETFL = 4;
        pub const GETOWN = 5;
        pub const SETOWN = 6;
        pub const GETLK = 7;
        pub const SETLK = 8;
        pub const SETLKW = 9;
        pub const CLOSEM = 10;
        pub const MAXFD = 11;
        pub const DUPFD_CLOEXEC = 12;
        pub const GETNOSIGPIPE = 13;
        pub const SETNOSIGPIPE = 14;
        pub const GETPATH = 15;

        pub const RDLCK = 1;
        pub const WRLCK = 3;
        pub const UNLCK = 2;
    },
    .dragonfly => struct {
        pub const ULOCK = 0;
        pub const LOCK = 1;
        pub const TLOCK = 2;
        pub const TEST = 3;

        pub const DUPFD = 0;
        pub const GETFD = 1;
        pub const RDLCK = 1;
        pub const SETFD = 2;
        pub const UNLCK = 2;
        pub const WRLCK = 3;
        pub const GETFL = 3;
        pub const SETFL = 4;
        pub const GETOWN = 5;
        pub const SETOWN = 6;
        pub const GETLK = 7;
        pub const SETLK = 8;
        pub const SETLKW = 9;
        pub const DUP2FD = 10;
        pub const DUPFD_CLOEXEC = 17;
        pub const DUP2FD_CLOEXEC = 18;
        pub const GETPATH = 19;
    },
    .haiku => struct {
        pub const DUPFD = 0x0001;
        pub const GETFD = 0x0002;
        pub const SETFD = 0x0004;
        pub const GETFL = 0x0008;
        pub const SETFL = 0x0010;

        pub const GETLK = 0x0020;
        pub const SETLK = 0x0080;
        pub const SETLKW = 0x0100;
        pub const DUPFD_CLOEXEC = 0x0200;

        pub const RDLCK = 0x0040;
        pub const UNLCK = 0x0200;
        pub const WRLCK = 0x0400;
    },
    .openbsd => struct {
        pub const DUPFD = 0;
        pub const GETFD = 1;
        pub const SETFD = 2;
        pub const GETFL = 3;
        pub const SETFL = 4;

        pub const GETOWN = 5;
        pub const SETOWN = 6;

        pub const GETLK = 7;
        pub const SETLK = 8;
        pub const SETLKW = 9;

        pub const RDLCK = 1;
        pub const UNLCK = 2;
        pub const WRLCK = 3;
    },
    .serenity => struct {
        // https://github.com/SerenityOS/serenity/blob/2808b0376406a40e31293bb3bcb9170374e90506/Kernel/API/POSIX/fcntl.h#L15-L24
        pub const DUPFD = 0;
        pub const GETFD = 1;
        pub const SETFD = 2;
        pub const GETFL = 3;
        pub const SETFL = 4;
        pub const ISTTY = 5;
        pub const GETLK = 6;
        pub const SETLK = 7;
        pub const SETLKW = 8;
        pub const DUPFD_CLOEXEC = 9;

        // https://github.com/SerenityOS/serenity/blob/2808b0376406a40e31293bb3bcb9170374e90506/Kernel/API/POSIX/fcntl.h#L45-L47
        pub const RDLCK = 0;
        pub const WRLCK = 1;
        pub const UNLCK = 2;
    },
    else => void,
};
pub const FD_CLOEXEC = switch (native_os) {
    .linux => linux.FD_CLOEXEC,
    .emscripten => emscripten.FD_CLOEXEC,
    else => 1,
};

/// Test for existence of file.
pub const F_OK = switch (native_os) {
    .linux => linux.F_OK,
    .emscripten => emscripten.F_OK,
    else => 0,
};
/// Test for execute or search permission.
pub const X_OK = switch (native_os) {
    .linux => linux.X_OK,
    .emscripten => emscripten.X_OK,
    else => 1,
};
/// Test for write permission.
pub const W_OK = switch (native_os) {
    .linux => linux.W_OK,
    .emscripten => emscripten.W_OK,
    else => 2,
};
/// Test for read permission.
pub const R_OK = switch (native_os) {
    .linux => linux.R_OK,
    .emscripten => emscripten.R_OK,
    else => 4,
};

pub const Flock = switch (native_os) {
    .linux => linux.Flock,
    .emscripten => emscripten.Flock,
    .openbsd, .dragonfly, .netbsd, .macos, .ios, .tvos, .watchos, .visionos => extern struct {
        start: off_t,
        len: off_t,
        pid: pid_t,
        type: i16,
        whence: i16,
    },
    .freebsd => extern struct {
        /// Starting offset.
        start: off_t,
        /// Number of consecutive bytes to be locked.
        /// A value of 0 means to the end of the file.
        len: off_t,
        /// Lock owner.
        pid: pid_t,
        /// Lock type.
        type: i16,
        /// Type of the start member.
        whence: i16,
        /// Remote system id or zero for local.
        sysid: i32,
    },
    .solaris, .illumos => extern struct {
        type: c_short,
        whence: c_short,
        start: off_t,
        // len == 0 means until end of file.
        len: off_t,
        sysid: c_int,
        pid: pid_t,
        __pad: [4]c_long,
    },
    .haiku => extern struct {
        type: i16,
        whence: i16,
        start: off_t,
        len: off_t,
        pid: pid_t,
    },
    // https://github.com/SerenityOS/serenity/blob/2808b0376406a40e31293bb3bcb9170374e90506/Kernel/API/POSIX/fcntl.h#L54-L60
    .serenity => extern struct {
        type: c_short,
        whence: c_short,
        start: off_t,
        len: off_t,
        pid: pid_t,
    },
    else => void,
};
pub const HOST_NAME_MAX = switch (native_os) {
    .linux => linux.HOST_NAME_MAX,
    .macos, .ios, .tvos, .watchos, .visionos => 72,
    .openbsd, .haiku, .dragonfly, .netbsd, .solaris, .illumos, .freebsd => 255,
    // https://github.com/SerenityOS/serenity/blob/c87557e9c1865fa1a6440de34ff6ce6fc858a2b7/Kernel/API/POSIX/sys/limits.h#L22
    .serenity => 64,
    else => {},
};
pub const IOV_MAX = switch (native_os) {
    .linux => linux.IOV_MAX,
    .emscripten => emscripten.IOV_MAX,
    // https://github.com/SerenityOS/serenity/blob/098af0f846a87b651731780ff48420205fd33754/Kernel/API/POSIX/sys/uio.h#L16
    .openbsd, .haiku, .solaris, .illumos, .wasi, .serenity => 1024,
    .macos, .ios, .tvos, .watchos, .visionos => 16,
    .dragonfly, .netbsd, .freebsd => KERN.IOV_MAX,
    else => {},
};
pub const CTL = switch (native_os) {
    .freebsd => struct {
        pub const KERN = 1;
        pub const DEBUG = 5;
    },
    .netbsd => struct {
        pub const KERN = 1;
        pub const DEBUG = 5;
    },
    .dragonfly => struct {
        pub const UNSPEC = 0;
        pub const KERN = 1;
        pub const VM = 2;
        pub const VFS = 3;
        pub const NET = 4;
        pub const DEBUG = 5;
        pub const HW = 6;
        pub const MACHDEP = 7;
        pub const USER = 8;
        pub const LWKT = 10;
        pub const MAXID = 11;
        pub const MAXNAME = 12;
    },
    .openbsd => struct {
        pub const UNSPEC = 0;
        pub const KERN = 1;
        pub const VM = 2;
        pub const FS = 3;
        pub const NET = 4;
        pub const DEBUG = 5;
        pub const HW = 6;
        pub const MACHDEP = 7;

        pub const DDB = 9;
        pub const VFS = 10;
    },
    else => void,
};
pub const KERN = switch (native_os) {
    .freebsd => struct {
        /// struct: process entries
        pub const PROC = 14;
        /// path to executable
        pub const PROC_PATHNAME = 12;
        /// file descriptors for process
        pub const PROC_FILEDESC = 33;
        pub const IOV_MAX = 35;
    },
    .netbsd => struct {
        /// struct: process argv/env
        pub const PROC_ARGS = 48;
        /// path to executable
        pub const PROC_PATHNAME = 5;
        pub const IOV_MAX = 38;
    },
    .dragonfly => struct {
        pub const PROC_ALL = 0;
        pub const OSTYPE = 1;
        pub const PROC_PID = 1;
        pub const OSRELEASE = 2;
        pub const PROC_PGRP = 2;
        pub const OSREV = 3;
        pub const PROC_SESSION = 3;
        pub const VERSION = 4;
        pub const PROC_TTY = 4;
        pub const MAXVNODES = 5;
        pub const PROC_UID = 5;
        pub const MAXPROC = 6;
        pub const PROC_RUID = 6;
        pub const MAXFILES = 7;
        pub const PROC_ARGS = 7;
        pub const ARGMAX = 8;
        pub const PROC_CWD = 8;
        pub const PROC_PATHNAME = 9;
        pub const SECURELVL = 9;
        pub const PROC_SIGTRAMP = 10;
        pub const HOSTNAME = 10;
        pub const HOSTID = 11;
        pub const CLOCKRATE = 12;
        pub const VNODE = 13;
        pub const PROC = 14;
        pub const FILE = 15;
        pub const PROC_FLAGMASK = 16;
        pub const PROF = 16;
        pub const PROC_FLAG_LWP = 16;
        pub const POSIX1 = 17;
        pub const NGROUPS = 18;
        pub const JOB_CONTROL = 19;
        pub const SAVED_IDS = 20;
        pub const BOOTTIME = 21;
        pub const NISDOMAINNAME = 22;
        pub const UPDATEINTERVAL = 23;
        pub const OSRELDATE = 24;
        pub const NTP_PLL = 25;
        pub const BOOTFILE = 26;
        pub const MAXFILESPERPROC = 27;
        pub const MAXPROCPERUID = 28;
        pub const DUMPDEV = 29;
        pub const IPC = 30;
        pub const DUMMY = 31;
        pub const PS_STRINGS = 32;
        pub const USRSTACK = 33;
        pub const LOGSIGEXIT = 34;
        pub const IOV_MAX = 35;
        pub const MAXPOSIXLOCKSPERUID = 36;
        pub const MAXID = 37;
    },
    .openbsd => struct {
        pub const OSTYPE = 1;
        pub const OSRELEASE = 2;
        pub const OSREV = 3;
        pub const VERSION = 4;
        pub const MAXVNODES = 5;
        pub const MAXPROC = 6;
        pub const MAXFILES = 7;
        pub const ARGMAX = 8;
        pub const SECURELVL = 9;
        pub const HOSTNAME = 10;
        pub const HOSTID = 11;
        pub const CLOCKRATE = 12;

        pub const PROF = 16;
        pub const POSIX1 = 17;
        pub const NGROUPS = 18;
        pub const JOB_CONTROL = 19;
        pub const SAVED_IDS = 20;
        pub const BOOTTIME = 21;
        pub const DOMAINNAME = 22;
        pub const MAXPARTITIONS = 23;
        pub const RAWPARTITION = 24;
        pub const MAXTHREAD = 25;
        pub const NTHREADS = 26;
        pub const OSVERSION = 27;
        pub const SOMAXCONN = 28;
        pub const SOMINCONN = 29;

        pub const NOSUIDCOREDUMP = 32;
        pub const FSYNC = 33;
        pub const SYSVMSG = 34;
        pub const SYSVSEM = 35;
        pub const SYSVSHM = 36;

        pub const MSGBUFSIZE = 38;
        pub const MALLOCSTATS = 39;
        pub const CPTIME = 40;
        pub const NCHSTATS = 41;
        pub const FORKSTAT = 42;
        pub const NSELCOLL = 43;
        pub const TTY = 44;
        pub const CCPU = 45;
        pub const FSCALE = 46;
        pub const NPROCS = 47;
        pub const MSGBUF = 48;
        pub const POOL = 49;
        pub const STACKGAPRANDOM = 50;
        pub const SYSVIPC_INFO = 51;
        pub const ALLOWKMEM = 52;
        pub const WITNESSWATCH = 53;
        pub const SPLASSERT = 54;
        pub const PROC_ARGS = 55;
        pub const NFILES = 56;
        pub const TTYCOUNT = 57;
        pub const NUMVNODES = 58;
        pub const MBSTAT = 59;
        pub const WITNESS = 60;
        pub const SEMINFO = 61;
        pub const SHMINFO = 62;
        pub const INTRCNT = 63;
        pub const WATCHDOG = 64;
        pub const ALLOWDT = 65;
        pub const PROC = 66;
        pub const MAXCLUSTERS = 67;
        pub const EVCOUNT = 68;
        pub const TIMECOUNTER = 69;
        pub const MAXLOCKSPERUID = 70;
        pub const CPTIME2 = 71;
        pub const CACHEPCT = 72;
        pub const FILE = 73;
        pub const WXABORT = 74;
        pub const CONSDEV = 75;
        pub const NETLIVELOCKS = 76;
        pub const POOL_DEBUG = 77;
        pub const PROC_CWD = 78;
        pub const PROC_NOBROADCASTKILL = 79;
        pub const PROC_VMMAP = 80;
        pub const GLOBAL_PTRACE = 81;
        pub const CONSBUFSIZE = 82;
        pub const CONSBUF = 83;
        pub const AUDIO = 84;
        pub const CPUSTATS = 85;
        pub const PFSTATUS = 86;
        pub const TIMEOUT_STATS = 87;
        pub const UTC_OFFSET = 88;
        pub const VIDEO = 89;

        pub const PROC_ALL = 0;
        pub const PROC_PID = 1;
        pub const PROC_PGRP = 2;
        pub const PROC_SESSION = 3;
        pub const PROC_TTY = 4;
        pub ```
