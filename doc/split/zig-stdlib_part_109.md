```
        return for (set.ints) |x| {
                    if (x != 0) break false;
                } else true;
            }

            pub fn count(set: Set) std.math.IntFittingRange(0, needed_bit_count) {
                var sum: usize = 0;
                for (set.ints) |x| sum += @popCount(x);
                return @intCast(sum);
            }

            pub fn isEnabled(set: Set, arch_feature_index: Index) bool {
                const usize_index = arch_feature_index / @bitSizeOf(usize);
                const bit_index: ShiftInt = @intCast(arch_feature_index % @bitSizeOf(usize));
                return (set.ints[usize_index] & (@as(usize, 1) << bit_index)) != 0;
            }

            /// Adds the specified feature but not its dependencies.
            pub fn addFeature(set: *Set, arch_feature_index: Index) void {
                const usize_index = arch_feature_index / @bitSizeOf(usize);
                const bit_index: ShiftInt = @intCast(arch_feature_index % @bitSizeOf(usize));
                set.ints[usize_index] |= @as(usize, 1) << bit_index;
            }

            /// Adds the specified feature set but not its dependencies.
            pub fn addFeatureSet(set: *Set, other_set: Set) void {
                if (builtin.zig_backend == .stage2_x86_64 and builtin.object_format == .coff) {
                    for (&set.ints, other_set.ints) |*set_int, other_set_int| set_int.* |= other_set_int;
                } else {
                    set.ints = @as(@Vector(usize_count, usize), set.ints) | @as(@Vector(usize_count, usize), other_set.ints);
                }
            }

            /// Removes the specified feature but not its dependents.
            pub fn removeFeature(set: *Set, arch_feature_index: Index) void {
                const usize_index = arch_feature_index / @bitSizeOf(usize);
                const bit_index: ShiftInt = @intCast(arch_feature_index % @bitSizeOf(usize));
                set.ints[usize_index] &= ~(@as(usize, 1) << bit_index);
            }

            /// Removes the specified feature but not its dependents.
            pub fn removeFeatureSet(set: *Set, other_set: Set) void {
                if (builtin.zig_backend == .stage2_x86_64 and builtin.object_format == .coff) {
                    for (&set.ints, other_set.ints) |*set_int, other_set_int| set_int.* &= ~other_set_int;
                } else {
                    set.ints = @as(@Vector(usize_count, usize), set.ints) & ~@as(@Vector(usize_count, usize), other_set.ints);
                }
            }

            pub fn populateDependencies(set: *Set, all_features_list: []const Cpu.Feature) void {
                @setEvalBranchQuota(1000000);

                var old = set.ints;
                while (true) {
                    for (all_features_list, 0..) |feature, index_usize| {
                        const index: Index = @intCast(index_usize);
                        if (set.isEnabled(index)) {
                            set.addFeatureSet(feature.dependencies);
                        }
                    }
                    const nothing_changed = std.mem.eql(usize, &old, &set.ints);
                    if (nothing_changed) return;
                    old = set.ints;
                }
            }

            pub fn asBytes(set: *const Set) *const [byte_count]u8 {
                return std.mem.sliceAsBytes(&set.ints)[0..byte_count];
            }

            pub fn eql(set: Set, other_set: Set) bool {
                return std.mem.eql(usize, &set.ints, &other_set.ints);
            }

            pub fn isSuperSetOf(set: Set, other_set: Set) bool {
                if (builtin.zig_backend == .stage2_x86_64 and builtin.object_format == .coff) {
                    var result = true;
                    for (&set.ints, other_set.ints) |*set_int, other_set_int|
                        result = result and (set_int.* & other_set_int) == other_set_int;
                    return result;
                } else {
                    const V = @Vector(usize_count, usize);
                    const set_v: V = set.ints;
                    const other_v: V = other_set.ints;
                    return @reduce(.And, (set_v & other_v) == other_v);
                }
            }
        };

        pub fn FeatureSetFns(comptime F: type) type {
            return struct {
                /// Populates only the feature bits specified.
                pub fn featureSet(features: []const F) Set {
                    var x = Set.empty;
                    for (features) |feature| {
                        x.addFeature(@intFromEnum(feature));
                    }
                    return x;
                }

                /// Returns true if the specified feature is enabled.
                pub fn featureSetHas(set: Set, feature: F) bool {
                    return set.isEnabled(@intFromEnum(feature));
                }

                /// Returns true if any specified feature is enabled.
                pub fn featureSetHasAny(set: Set, features: anytype) bool {
                    inline for (features) |feature| {
                        if (set.isEnabled(@intFromEnum(@as(F, feature)))) return true;
                    }
                    return false;
                }

                /// Returns true if every specified feature is enabled.
                pub fn featureSetHasAll(set: Set, features: anytype) bool {
                    inline for (features) |feature| {
                        if (!set.isEnabled(@intFromEnum(@as(F, feature)))) return false;
                    }
                    return true;
                }
            };
        }
    };

    pub const Arch = enum {
        amdgcn,
        arc,
        arm,
        armeb,
        thumb,
        thumbeb,
        aarch64,
        aarch64_be,
        avr,
        bpfel,
        bpfeb,
        csky,
        hexagon,
        kalimba,
        lanai,
        loongarch32,
        loongarch64,
        m68k,
        mips,
        mipsel,
        mips64,
        mips64el,
        msp430,
        nvptx,
        nvptx64,
        powerpc,
        powerpcle,
        powerpc64,
        powerpc64le,
        propeller,
        riscv32,
        riscv64,
        s390x,
        sparc,
        sparc64,
        spirv,
        spirv32,
        spirv64,
        ve,
        wasm32,
        wasm64,
        x86,
        x86_64,
        xcore,
        xtensa,

        // LLVM tags deliberately omitted:
        // - aarch64_32
        // - amdil
        // - amdil64
        // - dxil
        // - le32
        // - le64
        // - r600
        // - hsail
        // - hsail64
        // - renderscript32
        // - renderscript64
        // - shave
        // - sparcel
        // - spir
        // - spir64
        // - tce
        // - tcele

        pub inline fn isX86(arch: Arch) bool {
            return switch (arch) {
                .x86, .x86_64 => true,
                else => false,
            };
        }

        /// Note that this includes Thumb.
        pub inline fn isArm(arch: Arch) bool {
            return switch (arch) {
                .arm, .armeb => true,
                else => arch.isThumb(),
            };
        }

        pub inline fn isThumb(arch: Arch) bool {
            return switch (arch) {
                .thumb, .thumbeb => true,
                else => false,
            };
        }

        pub inline fn isAARCH64(arch: Arch) bool {
            return switch (arch) {
                .aarch64, .aarch64_be => true,
                else => false,
            };
        }

        pub inline fn isWasm(arch: Arch) bool {
            return switch (arch) {
                .wasm32, .wasm64 => true,
                else => false,
            };
        }

        pub inline fn isLoongArch(arch: Arch) bool {
            return switch (arch) {
                .loongarch32, .loongarch64 => true,
                else => false,
            };
        }

        pub inline fn isRISCV(arch: Arch) bool {
            return switch (arch) {
                .riscv32, .riscv64 => true,
                else => false,
            };
        }

        pub inline fn isMIPS(arch: Arch) bool {
            return arch.isMIPS32() or arch.isMIPS64();
        }

        pub inline fn isMIPS32(arch: Arch) bool {
            return switch (arch) {
                .mips, .mipsel => true,
                else => false,
            };
        }

        pub inline fn isMIPS64(arch: Arch) bool {
            return switch (arch) {
                .mips64, .mips64el => true,
                else => false,
            };
        }

        pub inline fn isPowerPC(arch: Arch) bool {
            return arch.isPowerPC32() or arch.isPowerPC64();
        }

        pub inline fn isPowerPC32(arch: Arch) bool {
            return switch (arch) {
                .powerpc, .powerpcle => true,
                else => false,
            };
        }

        pub inline fn isPowerPC64(arch: Arch) bool {
            return switch (arch) {
                .powerpc64, .powerpc64le => true,
                else => false,
            };
        }

        pub inline fn isSPARC(arch: Arch) bool {
            return switch (arch) {
                .sparc, .sparc64 => true,
                else => false,
            };
        }

        pub inline fn isSpirV(arch: Arch) bool {
            return switch (arch) {
                .spirv, .spirv32, .spirv64 => true,
                else => false,
            };
        }

        pub inline fn isBpf(arch: Arch) bool {
            return switch (arch) {
                .bpfel, .bpfeb => true,
                else => false,
            };
        }

        pub inline fn isNvptx(arch: Arch) bool {
            return switch (arch) {
                .nvptx, .nvptx64 => true,
                else => false,
            };
        }

        pub fn parseCpuModel(arch: Arch, cpu_name: []const u8) !*const Cpu.Model {
            for (arch.allCpuModels()) |cpu| {
                if (std.mem.eql(u8, cpu_name, cpu.name)) {
                    return cpu;
                }
            }
            return error.UnknownCpuModel;
        }

        pub fn endian(arch: Arch) std.builtin.Endian {
            return switch (arch) {
                .avr,
                .arm,
                .aarch64,
                .amdgcn,
                .bpfel,
                .csky,
                .xtensa,
                .hexagon,
                .kalimba,
                .mipsel,
                .mips64el,
                .msp430,
                .nvptx,
                .nvptx64,
                .powerpcle,
                .powerpc64le,
                .riscv32,
                .riscv64,
                .x86,
                .x86_64,
                .wasm32,
                .wasm64,
                .xcore,
                .thumb,
                .ve,
                // GPU bitness is opaque. For now, assume little endian.
                .spirv,
                .spirv32,
                .spirv64,
                .loongarch32,
                .loongarch64,
                .arc,
                .propeller,
                => .little,

                .armeb,
                .aarch64_be,
                .bpfeb,
                .m68k,
                .mips,
                .mips64,
                .powerpc,
                .powerpc64,
                .thumbeb,
                .sparc,
                .sparc64,
                .lanai,
                .s390x,
                => .big,
            };
        }

        /// Returns a name that matches the lib/std/target/* source file name.
        pub fn genericName(arch: Arch) [:0]const u8 {
            return switch (arch) {
                .arm, .armeb, .thumb, .thumbeb => "arm",
                .aarch64, .aarch64_be => "aarch64",
                .bpfel, .bpfeb => "bpf",
                .loongarch32, .loongarch64 => "loongarch",
                .mips, .mipsel, .mips64, .mips64el => "mips",
                .powerpc, .powerpcle, .powerpc64, .powerpc64le => "powerpc",
                .propeller => "propeller",
                .riscv32, .riscv64 => "riscv",
                .sparc, .sparc64 => "sparc",
                .s390x => "s390x",
                .x86, .x86_64 => "x86",
                .nvptx, .nvptx64 => "nvptx",
                .wasm32, .wasm64 => "wasm",
                .spirv, .spirv32, .spirv64 => "spirv",
                else => @tagName(arch),
            };
        }

        /// All CPU features Zig is aware of, sorted lexicographically by name.
        pub fn allFeaturesList(arch: Arch) []const Cpu.Feature {
            return switch (arch) {
                .arm, .armeb, .thumb, .thumbeb => &arm.all_features,
                .aarch64, .aarch64_be => &aarch64.all_features,
                .arc => &arc.all_features,
                .avr => &avr.all_features,
                .bpfel, .bpfeb => &bpf.all_features,
                .csky => &csky.all_features,
                .hexagon => &hexagon.all_features,
                .lanai => &lanai.all_features,
                .loongarch32, .loongarch64 => &loongarch.all_features,
                .m68k => &m68k.all_features,
                .mips, .mipsel, .mips64, .mips64el => &mips.all_features,
                .msp430 => &msp430.all_features,
                .powerpc, .powerpcle, .powerpc64, .powerpc64le => &powerpc.all_features,
                .amdgcn => &amdgcn.all_features,
                .riscv32, .riscv64 => &riscv.all_features,
                .sparc, .sparc64 => &sparc.all_features,
                .spirv, .spirv32, .spirv64 => &spirv.all_features,
                .s390x => &s390x.all_features,
                .x86, .x86_64 => &x86.all_features,
                .xcore => &xcore.all_features,
                .xtensa => &xtensa.all_features,
                .nvptx, .nvptx64 => &nvptx.all_features,
                .ve => &ve.all_features,
                .wasm32, .wasm64 => &wasm.all_features,

                else => &[0]Cpu.Feature{},
            };
        }

        /// All processors Zig is aware of, sorted lexicographically by name.
        pub fn allCpuModels(arch: Arch) []const *const Cpu.Model {
            return switch (arch) {
                .arc => comptime allCpusFromDecls(arc.cpu),
                .arm, .armeb, .thumb, .thumbeb => comptime allCpusFromDecls(arm.cpu),
                .aarch64, .aarch64_be => comptime allCpusFromDecls(aarch64.cpu),
                .avr => comptime allCpusFromDecls(avr.cpu),
                .bpfel, .bpfeb => comptime allCpusFromDecls(bpf.cpu),
                .csky => comptime allCpusFromDecls(csky.cpu),
                .hexagon => comptime allCpusFromDecls(hexagon.cpu),
                .lanai => comptime allCpusFromDecls(lanai.cpu),
                .loongarch32, .loongarch64 => comptime allCpusFromDecls(loongarch.cpu),
                .m68k => comptime allCpusFromDecls(m68k.cpu),
                .mips, .mipsel, .mips64, .mips64el => comptime allCpusFromDecls(mips.cpu),
                .msp430 => comptime allCpusFromDecls(msp430.cpu),
                .powerpc, .powerpcle, .powerpc64, .powerpc64le => comptime allCpusFromDecls(powerpc.cpu),
                .amdgcn => comptime allCpusFromDecls(amdgcn.cpu),
                .riscv32, .riscv64 => comptime allCpusFromDecls(riscv.cpu),
                .sparc, .sparc64 => comptime allCpusFromDecls(sparc.cpu),
                .spirv, .spirv32, .spirv64 => comptime allCpusFromDecls(spirv.cpu),
                .s390x => comptime allCpusFromDecls(s390x.cpu),
                .x86, .x86_64 => comptime allCpusFromDecls(x86.cpu),
                .xcore => comptime allCpusFromDecls(xcore.cpu),
                .xtensa => comptime allCpusFromDecls(xtensa.cpu),
                .nvptx, .nvptx64 => comptime allCpusFromDecls(nvptx.cpu),
                .ve => comptime allCpusFromDecls(ve.cpu),
                .wasm32, .wasm64 => comptime allCpusFromDecls(wasm.cpu),

                else => &[0]*const Model{},
            };
        }

        fn allCpusFromDecls(comptime cpus: type) []const *const Cpu.Model {
            @setEvalBranchQuota(2000);
            const decls = @typeInfo(cpus).@"struct".decls;
            var array: [decls.len]*const Cpu.Model = undefined;
            for (decls, 0..) |decl, i| {
                array[i] = &@field(cpus, decl.name);
            }
            const finalized = array;
            return &finalized;
        }

        /// 0c spim    little-endian MIPS 3000 family
        /// 1c 68000   Motorola MC68000
        /// 2c 68020   Motorola MC68020
        /// 5c arm     little-endian ARM
        /// 6c amd64   AMD64 and compatibles (e.g., Intel EM64T)
        /// 7c arm64   ARM64 (ARMv8)
        /// 8c 386     Intel x86, i486, Pentium, etc.
        /// kc sparc   Sun SPARC
        /// qc power   Power PC
        /// vc mips    big-endian MIPS 3000 family
        pub fn plan9Ext(arch: Cpu.Arch) [:0]const u8 {
            return switch (arch) {
                .arm => ".5",
                .x86_64 => ".6",
                .aarch64 => ".7",
                .x86 => ".8",
                .sparc => ".k",
                .powerpc, .powerpcle => ".q",
                .mips, .mipsel => ".v",
                // ISAs without designated characters get 'X' for lack of a better option.
                else => ".X",
            };
        }

        /// Returns the array of `Arch` to which a specific `std.builtin.CallingConvention` applies.
        /// Asserts that `cc` is not `.auto`, `.@"async"`, `.naked`, or `.@"inline"`.
        pub fn fromCallingConvention(cc: std.builtin.CallingConvention.Tag) []const Arch {
            return switch (cc) {
                .auto,
                .@"async",
                .naked,
                .@"inline",
                => unreachable,

                .x86_64_sysv,
                .x86_64_win,
                .x86_64_regcall_v3_sysv,
                .x86_64_regcall_v4_win,
                .x86_64_vectorcall,
                .x86_64_interrupt,
                => &.{.x86_64},

                .x86_sysv,
                .x86_win,
                .x86_stdcall,
                .x86_fastcall,
                .x86_thiscall,
                .x86_thiscall_mingw,
                .x86_regcall_v3,
                .x86_regcall_v4_win,
                .x86_vectorcall,
                .x86_interrupt,
                => &.{.x86},

                .aarch64_aapcs,
                .aarch64_aapcs_darwin,
                .aarch64_aapcs_win,
                .aarch64_vfabi,
                .aarch64_vfabi_sve,
                => &.{ .aarch64, .aarch64_be },

                .arm_aapcs,
                .arm_aapcs_vfp,
                .arm_interrupt,
                => &.{ .arm, .armeb, .thumb, .thumbeb },

                .mips64_n64,
                .mips64_n32,
                .mips64_interrupt,
                => &.{ .mips64, .mips64el },

                .mips_o32,
                .mips_interrupt,
                => &.{ .mips, .mipsel },

                .riscv64_lp64,
                .riscv64_lp64_v,
                .riscv64_interrupt,
                => &.{.riscv64},

                .riscv32_ilp32,
                .riscv32_ilp32_v,
                .riscv32_interrupt,
                => &.{.riscv32},

                .sparc64_sysv,
                => &.{.sparc64},

                .sparc_sysv,
                => &.{.sparc},

                .powerpc64_elf,
                .powerpc64_elf_altivec,
                .powerpc64_elf_v2,
                => &.{ .powerpc64, .powerpc64le },

                .powerpc_sysv,
                .powerpc_sysv_altivec,
                .powerpc_aix,
                .powerpc_aix_altivec,
                => &.{ .powerpc, .powerpcle },

                .wasm_mvp,
                => &.{ .wasm64, .wasm32 },

                .arc_sysv,
                => &.{.arc},

                .avr_gnu,
                .avr_builtin,
                .avr_signal,
                .avr_interrupt,
                => &.{.avr},

                .bpf_std,
                => &.{ .bpfel, .bpfeb },

                .csky_sysv,
                .csky_interrupt,
                => &.{.csky},

                .hexagon_sysv,
                .hexagon_sysv_hvx,
                => &.{.hexagon},

                .lanai_sysv,
                => &.{.lanai},

                .loongarch64_lp64,
                => &.{.loongarch64},

                .loongarch32_ilp32,
                => &.{.loongarch32},

                .m68k_sysv,
                .m68k_gnu,
                .m68k_rtd,
                .m68k_interrupt,
                => &.{.m68k},

                .msp430_eabi,
                => &.{.msp430},

                .propeller_sysv,
                => &.{.propeller},

                .s390x_sysv,
                .s390x_sysv_vx,
                => &.{.s390x},

                .ve_sysv,
                => &.{.ve},

                .xcore_xs1,
                .xcore_xs2,
                => &.{.xcore},

                .xtensa_call0,
                .xtensa_windowed,
                => &.{.xtensa},

                .amdgcn_device,
                .amdgcn_kernel,
                .amdgcn_cs,
                => &.{.amdgcn},

                .nvptx_device,
                .nvptx_kernel,
                => &.{ .nvptx, .nvptx64 },

                .spirv_device,
                .spirv_kernel,
                .spirv_fragment,
                .spirv_vertex,
                => &.{ .spirv, .spirv32, .spirv64 },
            };
        }
    };

    pub const Model = struct {
        name: []const u8,
        llvm_name: ?[:0]const u8,
        features: Feature.Set,

        pub fn toCpu(model: *const Model, arch: Arch) Cpu {
            var features = model.features;
            features.populateDependencies(arch.allFeaturesList());
            return .{
                .arch = arch,
                .model = model,
                .features = features,
            };
        }

        /// Returns the most bare-bones CPU model that is valid for `arch`. Note that this function
        /// can return CPU models that are understood by LLVM, but *not* understood by Clang. If
        /// Clang compatibility is important, consider using `baseline` instead.
        pub fn generic(arch: Arch) *const Model {
            const S = struct {
                const generic_model = Model{
                    .name = "generic",
                    .llvm_name = null,
                    .features = Cpu.Feature.Set.empty,
                };
            };
            return switch (arch) {
                .amdgcn => &amdgcn.cpu.gfx600,
                .arc => &arc.cpu.generic,
                .arm, .armeb, .thumb, .thumbeb => &arm.cpu.generic,
                .aarch64, .aarch64_be => &aarch64.cpu.generic,
                .avr => &avr.cpu.avr1,
                .bpfel, .bpfeb => &bpf.cpu.generic,
                .csky => &csky.cpu.generic,
                .hexagon => &hexagon.cpu.generic,
                .lanai => &lanai.cpu.generic,
                .loongarch32 => &loongarch.cpu.generic_la32,
                .loongarch64 => &loongarch.cpu.generic_la64,
                .m68k => &m68k.cpu.generic,
                .mips, .mipsel => &mips.cpu.mips32,
                .mips64, .mips64el => &mips.cpu.mips64,
                .msp430 => &msp430.cpu.generic,
                .powerpc, .powerpcle => &powerpc.cpu.ppc,
                .powerpc64, .powerpc64le => &powerpc.cpu.ppc64,
                .propeller => &propeller.cpu.p1,
                .riscv32 => &riscv.cpu.generic_rv32,
                .riscv64 => &riscv.cpu.generic_rv64,
                .spirv, .spirv32, .spirv64 => &spirv.cpu.generic,
                .sparc => &sparc.cpu.generic,
                .sparc64 => &sparc.cpu.v9, // 64-bit SPARC needs v9 as the baseline
                .s390x => &s390x.cpu.generic,
                .x86 => &x86.cpu.i386,
                .x86_64 => &x86.cpu.x86_64,
                .nvptx, .nvptx64 => &nvptx.cpu.sm_20,
                .ve => &ve.cpu.generic,
                .wasm32, .wasm64 => &wasm.cpu.mvp,
                .xcore => &xcore.cpu.generic,
                .xtensa => &xtensa.cpu.generic,

                .kalimba,
                => &S.generic_model,
            };
        }

        /// Returns a conservative CPU model for `arch` that is expected to be compatible with the
        /// vast majority of hardware available. This function is guaranteed to return CPU models
        /// that are understood by both LLVM and Clang, unlike `generic`.
        ///
        /// For certain `os` values, this function will additionally bump the baseline higher than
        /// the baseline would be for `arch` in isolation; for example, for `aarch64-macos`, the
        /// baseline is considered to be `apple_m1`. To avoid this behavior entirely, pass
        /// `Os.Tag.freestanding`.
        pub fn baseline(arch: Arch, os: Os) *const Model {
            return switch (arch) {
                .amdgcn => &amdgcn.cpu.gfx906,
                .arm, .armeb, .thumb, .thumbeb => &arm.cpu.baseline,
                .aarch64 => switch (os.tag) {
                    .driverkit, .macos => &aarch64.cpu.apple_m1,
                    .ios, .tvos => &aarch64.cpu.apple_a7,
                    .visionos => &aarch64.cpu.apple_m2,
                    .watchos => &aarch64.cpu.apple_s4,
                    else => generic(arch),
                },
                .avr => &avr.cpu.avr2,
                .bpfel, .bpfeb => &bpf.cpu.v3,
                .csky => &csky.cpu.ck810, // gcc/clang do not have a generic csky model.
                .hexagon => &hexagon.cpu.hexagonv68, // gcc/clang do not have a generic hexagon model.
                .lanai => &lanai.cpu.v11, // clang does not have a generic lanai model.
                .loongarch64 => &loongarch.cpu.loongarch64,
                .m68k => &m68k.cpu.M68000,
                .mips, .mipsel => &mips.cpu.mips32r2,
                .mips64, .mips64el => &mips.cpu.mips64r2,
                .msp430 => &msp430.cpu.msp430,
                .nvptx, .nvptx64 => &nvptx.cpu.sm_52,
                .powerpc64le => &powerpc.cpu.ppc64le,
                .riscv32 => &riscv.cpu.baseline_rv32,
                .riscv64 => &riscv.cpu.baseline_rv64,
                .s390x => &s390x.cpu.arch8, // gcc/clang do not have a generic s390x model.
                .sparc => &sparc.cpu.v9, // glibc does not work with 'plain' v8.
                .x86 => &x86.cpu.pentium4,
                .x86_64 => switch (os.tag) {
                    .driverkit => &x86.cpu.nehalem,
                    .ios, .macos, .tvos, .visionos, .watchos => &x86.cpu.core2,
                    .ps4 => &x86.cpu.btver2,
                    .ps5 => &x86.cpu.znver2,
                    else => generic(arch),
                },
                .xcore => &xcore.cpu.xs1b_generic,
                .wasm32, .wasm64 => &wasm.cpu.lime1,

                else => generic(arch),
            };
        }
    };

    /// The "default" set of CPU features for cross-compiling. A conservative set
    /// of features that is expected to be supported on most available hardware.
    pub fn baseline(arch: Arch, os: Os) Cpu {
        return Model.baseline(arch, os).toCpu(arch);
    }

    /// Returns whether this architecture supports `address_space`. If `context` is `null`, this
    /// function simply answers the general question of whether the architecture has any concept
    /// of `address_space`; if non-`null`, the function additionally checks whether
    /// `address_space` is valid in that context.
    pub fn supportsAddressSpace(
        cpu: Cpu,
        address_space: std.builtin.AddressSpace,
        context: ?std.builtin.AddressSpace.Context,
    ) bool {
        const arch = cpu.arch;

        const is_nvptx = arch.isNvptx();
        const is_spirv = arch.isSpirV();
        const is_gpu = is_nvptx or is_spirv or arch == .amdgcn;

        return switch (address_space) {
            .generic => true,
            .fs, .gs, .ss => (arch == .x86_64 or arch == .x86) and (context == null or context == .pointer),
            .flash, .flash1, .flash2, .flash3, .flash4, .flash5 => arch == .avr, // TODO this should also check how many flash banks the cpu has
            .cog, .hub => arch == .propeller,
            .lut => arch == .propeller and std.Target.propeller.featureSetHas(cpu.features, .p2),

            .global, .local, .shared => is_gpu,
            .constant => is_gpu and (context == null or context == .constant),
            .param => is_nvptx,
            .input, .output, .uniform, .push_constant, .storage_buffer => is_spirv,
        };
    }
};

pub fn zigTriple(target: Target, allocator: Allocator) Allocator.Error![]u8 {
    return Query.fromTarget(target).zigTriple(allocator);
}

pub fn hurdTupleSimple(allocator: Allocator, arch: Cpu.Arch, abi: Abi) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ @tagName(arch), @tagName(abi) });
}

pub fn hurdTuple(target: Target, allocator: Allocator) ![]u8 {
    return hurdTupleSimple(allocator, target.cpu.arch, target.abi);
}

pub fn linuxTripleSimple(allocator: Allocator, arch: Cpu.Arch, os_tag: Os.Tag, abi: Abi) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}-{s}-{s}", .{ @tagName(arch), @tagName(os_tag), @tagName(abi) });
}

pub fn linuxTriple(target: Target, allocator: Allocator) ![]u8 {
    return linuxTripleSimple(allocator, target.cpu.arch, target.os.tag, target.abi);
}

pub fn exeFileExt(target: Target) [:0]const u8 {
    return target.os.tag.exeFileExt(target.cpu.arch);
}

pub fn staticLibSuffix(target: Target) [:0]const u8 {
    return target.os.tag.staticLibSuffix(target.abi);
}

pub fn dynamicLibSuffix(target: Target) [:0]const u8 {
    return target.os.tag.dynamicLibSuffix();
}

pub fn libPrefix(target: Target) [:0]const u8 {
    return target.os.tag.libPrefix(target.abi);
}

pub inline fn isMinGW(target: Target) bool {
    return target.os.tag == .windows and target.abi.isGnu();
}

pub inline fn isGnuLibC(target: Target) bool {
    return switch (target.os.tag) {
        .hurd, .linux => target.abi.isGnu(),
        else => false,
    };
}

pub inline fn isMuslLibC(target: Target) bool {
    return target.os.tag == .linux and target.abi.isMusl();
}

pub inline fn isDarwinLibC(target: Target) bool {
    return switch (target.abi) {
        .none, .macabi, .simulator => target.os.tag.isDarwin(),
        else => false,
    };
}

pub inline fn isWasiLibC(target: Target) bool {
    return target.os.tag == .wasi and target.abi.isMusl();
}

pub const DynamicLinker = struct {
    /// Contains the memory used to store the dynamic linker path. This field
    /// should not be used directly. See `get` and `set`. This field exists so
    /// that this API requires no allocator.
    buffer: [255]u8,

    /// Used to construct the dynamic linker path. This field should not be used
    /// directly. See `get` and `set`.
    len: u8,

    pub const none: DynamicLinker = .{ .buffer = undefined, .len = 0 };

    /// Asserts that the length is less than or equal to 255 bytes.
    pub fn init(maybe_path: ?[]const u8) DynamicLinker {
        var dl: DynamicLinker = undefined;
        dl.set(maybe_path);
        return dl;
    }

    pub fn initFmt(comptime fmt_str: []const u8, args: anytype) !DynamicLinker {
        var dl: DynamicLinker = undefined;
        try dl.setFmt(fmt_str, args);
        return dl;
    }

    /// The returned memory has the same lifetime as the `DynamicLinker`.
    pub fn get(dl: *const DynamicLinker) ?[]const u8 {
        return if (dl.len > 0) dl.buffer[0..dl.len] else null;
    }

    /// Asserts that the length is less than or equal to 255 bytes.
    pub fn set(dl: *DynamicLinker, maybe_path: ?[]const u8) void {
        const path = maybe_path orelse "";
        @memcpy(dl.buffer[0..path.len], path);
        dl.len = @intCast(path.len);
    }

    /// Asserts that the length is less than or equal to 255 bytes.
    pub fn setFmt(dl: *DynamicLinker, comptime fmt_str: []const u8, args: anytype) !void {
        dl.len = @intCast((try std.fmt.bufPrint(&dl.buffer, fmt_str, args)).len);
    }

    pub fn eql(lhs: DynamicLinker, rhs: DynamicLinker) bool {
        return std.mem.eql(u8, lhs.buffer[0..lhs.len], rhs.buffer[0..rhs.len]);
    }

    pub const Kind = enum {
        /// No dynamic linker.
        none,
        /// Dynamic linker path is determined by the arch/OS components.
        arch_os,
        /// Dynamic linker path is determined by the arch/OS/ABI components.
        arch_os_abi,
    };

    pub fn kind(os: Os.Tag) Kind {
        return switch (os) {
            .fuchsia,

            .haiku,
            .serenity,

            .dragonfly,
            .freebsd,
            .netbsd,
            .openbsd,

            .driverkit,
            .ios,
            .macos,
            .tvos,
            .visionos,
            .watchos,

            .illumos,
            .solaris,
            => .arch_os,
            .hurd,
            .linux,
            => .arch_os_abi,
            .freestanding,
            .other,

            .contiki,
            .hermit,

            .aix,
            .plan9,
            .rtems,
            .zos,

            .uefi,
            .windows,

            .emscripten,
            .wasi,

            .amdhsa,
            .amdpal,
            .cuda,
            .mesa3d,
            .nvcl,
            .opencl,
            .opengl,
            .vulkan,

            .ps3,
            .ps4,
            .ps5,
            => .none,
        };
    }

    /// The strictness of this function depends on the value of `kind(os.tag)`:
    ///
    /// * `.none`: Ignores all arguments and just returns `none`.
    /// * `.arch_os`: Ignores `abi` and returns the dynamic linker matching `cpu` and `os`.
    /// * `.arch_os_abi`: Returns the dynamic linker matching `cpu`, `os`, and `abi`.
    ///
    /// In the case of `.arch_os` in particular, callers should be aware that a valid dynamic linker
    /// being returned only means that the `cpu` + `os` combination represents a platform that
    /// actually exists and which has an established dynamic linker path that does not change with
    /// the ABI; it does not necessarily mean that `abi` makes any sense at all for that platform.
    /// The responsibility for determining whether `abi` is valid in this case rests with the
    /// caller. `Abi.default()` can be used to pick a best-effort default ABI for such platforms.
    pub fn standard(cpu: Cpu, os: Os, abi: Abi) DynamicLinker {
        return switch (os.tag) {
            .fuchsia => switch (cpu.arch) {
                .aarch64,
                .riscv64,
                .x86_64,
                => init("ld.so.1"), // Fuchsia is unusual in that `DT_INTERP` is just a basename.
                else => none,
            },

            .haiku => switch (cpu.arch) {
                .arm,
                .thumb,
                .aarch64,
                .m68k,
                .powerpc,
                .riscv64,
                .sparc64,
                .x86,
                .x86_64,
                => init("/system/runtime_loader"),
                else => none,
            },

            .hurd => switch (cpu.arch) {
                .aarch64,
                .aarch64_be,
                => |arch| if (abi == .gnu) initFmt("/lib/ld-{s}.so.1", .{@tagName(arch)}) else none,

                .x86 => if (abi == .gnu) init("/lib/ld.so.1") else none,
                .x86_64 => initFmt("/lib/ld-{s}.so.1", .{switch (abi) {
                    .gnu => "x86-64",
                    .gnux32 => "x32",
                    else => return none,
                }}),

                else => none,
            },

            .linux => if (abi.isAndroid())
                switch (cpu.arch) {
                    .arm,
                    .thumb,
                    => if (abi == .androideabi) init("/system/bin/linker") else none,

                    .aarch64,
                    .riscv64,
                    .x86,
                    .x86_64,
                    => if (abi == .android) initFmt("/system/bin/linker{s}", .{
                        if (ptrBitWidth_cpu_abi(cpu, abi) == 64) "64" else "",
                    }) else none,

                    else => none,
                }
            else if (abi.isMusl())
                switch (cpu.arch) {
                    .arm,
                    .armeb,
                    .thumb,
                    .thumbeb,
                    => |arch| initFmt("/lib/ld-musl-arm{s}{s}.so.1", .{
                        if (arch == .armeb or arch == .thumbeb) "eb" else "",
                        switch (abi) {
                            .musleabi => "",
                            .musleabihf => "hf",
                            else => return none,
                        },
                    }),

                    .loongarch32,
                    .loongarch64,
                    => |arch| initFmt("/lib/ld-musl-{s}{s}.so.1", .{
                        @tagName(arch),
                        switch (abi) {
                            .musl => "",
                            .muslf32 => "-sp",
                            .muslsf => "-sf",
                            else => return none,
                        },
                    }),

                    .aarch64,
                    .aarch64_be,
                    .m68k,
                    .powerpc64,
                    .powerpc64le,
                    .s390x,
                    => |arch| if (abi == .musl) initFmt("/lib/ld-musl-{s}.so.1", .{@tagName(arch)}) else none,

                    .mips,
                    .mipsel,
                    => |arch| initFmt("/lib/ld-musl-mips{s}{s}{s}.so.1", .{
                        if (mips.featureSetHas(cpu.features, .mips32r6)) "r6" else "",
                        if (arch == .mipsel) "el" else "",
                        switch (abi) {
                            .musleabi => "-sf",
                            .musleabihf => "",
                            else => return none,
                        },
                    }),

                    .mips64,
                    .mips64el,
                    => |arch| initFmt("/lib/ld-musl-mips{s}{s}{s}.so.1", .{
                        switch (abi) {
                            .muslabi64 => "64",
                            .muslabin32 => "n32",
                            else => return none,
                        },
                        if (mips.featureSetHas(cpu.features, .mips64r6)) "r6" else "",
                        if (arch == .mips64el) "el" else "",
                    }),

                    .powerpc => initFmt("/lib/ld-musl-powerpc{s}.so.1", .{switch (abi) {
                        .musleabi => "-sf",
                        .musleabihf => "",
                        else => return none,
                    }}),

                    .riscv32,
                    .riscv64,
                    => |arch| if (abi == .musl) initFmt("/lib/ld-musl-{s}{s}.so.1", .{
                        @tagName(arch),
                        if (riscv.featureSetHas(cpu.features, .d))
                            ""
                        else if (riscv.featureSetHas(cpu.features, .f))
                            "-sp"
                        else
                            "-sf",
                    }) else none,

                    .x86 => if (abi == .musl) init("/lib/ld-musl-i386.so.1") else none,
                    .x86_64 => initFmt("/lib/ld-musl-{s}.so.1", .{switch (abi) {
                        .musl => "x86_64",
                        .muslx32 => "x32",
                        else => return none,
                    }}),

                    else => none,
                }
            else if (abi.isGnu())
                switch (cpu.arch) {
                    // TODO: `eb` architecture support.
                    // TODO: `700` ABI support.
                    .arc => if (abi == .gnu) init("/lib/ld-linux-arc.so.2") else none,

                    .arm,
                    .armeb,
                    .thumb,
                    .thumbeb,
                    => initFmt("/lib/ld-linux{s}.so.3", .{switch (abi) {
                        .gnueabi => "",
                        .gnueabihf => "-armhf",
                        else => return none,
                    }}),

                    .aarch64,
                    .aarch64_be,
                    => |arch| if (abi == .gnu) initFmt("/lib/ld-linux-{s}.so.1", .{@tagName(arch)}) else none,

                    // TODO: `-be` architecture support.
                    .csky => initFmt("/lib/ld-linux-cskyv2{s}.so.1", .{switch (abi) {
                        .gnueabi => "",
                        .gnueabihf => "-hf",
                        else => return none,
                    }}),

                    .loongarch64 => initFmt("/lib64/ld-linux-loongarch-{s}.so.1", .{switch (abi) {
                        .gnu => "lp64d",
                        .gnuf32 => "lp64f",
                        .gnusf => "lp64s",
                        else => return none,
                    }}),

                    .m68k => if (abi == .gnu) init("/lib/ld.so.1") else none,

                    .mips,
                    .mipsel,
                    => switch (abi) {
                        .gnueabi,
                        .gnueabihf,
                        => initFmt("/lib/ld{s}.so.1", .{
                            if (mips.featureSetHas(cpu.features, .nan2008)) "-linux-mipsn8" else "",
                        }),
                        else => none,
                    },

                    .mips64,
                    .mips64el,
                    => initFmt("/lib{s}/ld{s}.so.1", .{
                        switch (abi) {
                            .gnuabi64 => "64",
                            .gnuabin32 => "32",
                            else => return none,
                        },
                        if (mips.featureSetHas(cpu.features, .nan2008)) "-linux-mipsn8" else "",
                    }),

                    .powerpc => switch (abi) {
                        .gnueabi,
                        .gnueabihf,
                        => init("/lib/ld.so.1"),
                        else => none,
                    },
                    // TODO: ELFv2 ABI (`/lib64/ld64.so.2`) opt-in support.
                    .powerpc64 => if (abi == .gnu) init("/lib64/ld64.so.1") else none,
                    .powerpc64le => if (abi == .gnu) init("/lib64/ld64.so.2") else none,

                    .riscv32,
                    .riscv64,
                    => |arch| if (abi == .gnu) initFmt("/lib/ld-linux-{s}{s}.so.1", .{
                        switch (arch) {
                            .riscv32 => "riscv32-ilp32",
                            .riscv64 => "riscv64-lp64",
                            else => unreachable,
                        },
                        if (riscv.featureSetHas(cpu.features, .d))
                            "d"
                        else if (riscv.featureSetHas(cpu.features, .f))
                            "f"
                        else
                            "",
                    }) else none,

                    .s390x => if (abi == .gnu) init("/lib/ld64.so.1") else none,

                    .sparc => if (abi == .gnu) init("/lib/ld-linux.so.2") else none,
                    .sparc64 => if (abi == .gnu) init("/lib64/ld-linux.so.2") else none,

                    .x86 => if (abi == .gnu) init("/lib/ld-linux.so.2") else none,
                    .x86_64 => switch (abi) {
                        .gnu => init("/lib64/ld-linux-x86-64.so.2"),
                        .gnux32 => init("/libx32/ld-linux-x32.so.2"),
                        else => none,
                    },

                    .xtensa => if (abi == .gnu) init("/lib/ld.so.1") else none,

                    else => none,
                }
            else
                none, // Not a known Linux libc.

            .serenity => switch (cpu.arch) {
                .aarch64,
                .riscv64,
                .x86_64,
                => init("/usr/lib/Loader.so"),
                else => none,
            },

            .dragonfly => if (cpu.arch == .x86_64) initFmt("{s}/libexec/ld-elf.so.2", .{
                if (os.version_range.semver.isAtLeast(.{ .major = 3, .minor = 8, .patch = 0 }) orelse false)
                    ""
                else
                    "/usr",
            }) else none,

            .freebsd => switch (cpu.arch) {
                .arm,
                .armeb,
                .thumb,
                .thumbeb,
                .aarch64,
                .mips,
                .mipsel,
                .mips64,
                .mips64el,
                .powerpc,
                .powerpc64,
                .powerpc64le,
                .riscv64,
                .sparc64,
                .x86,
                .x86_64,
                => initFmt("{s}/libexec/ld-elf.so.1", .{
                    if (os.version_range.semver.isAtLeast(.{ .major = 6, .minor = 0, .patch = 0 }) orelse false)
                        ""
                    else
                        "/usr",
                }),
                else => none,
            },

            .netbsd => switch (cpu.arch) {
                .arm,
                .armeb,
                .thumb,
                .thumbeb,
                .aarch64,
                .aarch64_be,
                .m68k,
                .mips,
                .mipsel,
                .mips64,
                .mips64el,
                .powerpc,
                .riscv64,
                .sparc,
                .sparc64,
                .x86,
                .x86_64,
                => init("/libexec/ld.elf_so"),
                else => none,
            },

            .openbsd => switch (cpu.arch) {
                .arm,
                .thumb,
                .aarch64,
                .mips64,
                .mips64el,
                .powerpc,
                .powerpc64,
                .riscv64,
                .sparc64,
                .x86,
                .x86_64,
                => init("/usr/libexec/ld.so"),
                else => none,
            },

            .driverkit,
            .ios,
            .macos,
            .tvos,
            .visionos,
            .watchos,
            => switch (cpu.arch) {
                .aarch64,
                .x86_64,
                => init("/usr/lib/dyld"),
                else => none,
            },

            .illumos,
            .solaris,
            => switch (cpu.arch) {
                .sparc,
                .sparc64,
                .x86,
                .x86_64,
                => initFmt("/lib/{s}ld.so.1", .{if (ptrBitWidth_cpu_abi(cpu, .none) == 64) "64/" else ""}),
                else => none,
            },

            // Operating systems in this list have been verified as not having a standard
            // dynamic linker path.
            .freestanding,
            .other,

            .contiki,
            .hermit,

            .aix,
            .plan9,
            .rtems,
            .zos,

            .uefi,
            .windows,

            .emscripten,
            .wasi,

            .amdhsa,
            .amdpal,
            .cuda,
            .mesa3d,
            .nvcl,
            .opencl,
            .opengl,
            .vulkan,
            => none,

            // TODO go over each item in this list and either move it to the above list, or
            // implement the standard dynamic linker path code for it.
            .ps3,
            .ps4,
            .ps5,
            => none,
        } catch unreachable;
    }
};

pub fn standardDynamicLinkerPath(target: Target) DynamicLinker {
    return DynamicLinker.standard(target.cpu, target.os, target.abi);
}

pub fn ptrBitWidth_cpu_abi(cpu: Cpu, abi: Abi) u16 {
    switch (abi) {
        .gnux32, .muslx32, .gnuabin32, .muslabin32, .ilp32 => return 32,
        .gnuabi64, .muslabi64 => return 64,
        else => {},
    }
    return switch (cpu.arch) {
        .avr,
        .msp430,
        => 16,

        .arc,
        .arm,
        .armeb,
        .csky,
        .hexagon,
        .m68k,
        .mips,
        .mipsel,
        .powerpc,
        .powerpcle,
        .riscv32,
        .thumb,
        .thumbeb,
        .x86,
        .xcore,
        .nvptx,
        .kalimba,
        .lanai,
        .wasm32,
        .sparc,
        .spirv32,
        .loongarch32,
        .xtensa,
        .propeller,
        => 32,

        .aarch64,
        .aarch64_be,
        .mips64,
        .mips64el,
        .powerpc64,
        .powerpc64le,
        .riscv64,
        .x86_64,
        .nvptx64,
        .wasm64,
        .amdgcn,
        .bpfel,
        .bpfeb,
        .sparc64,
        .s390x,
        .ve,
        .spirv,
        .spirv64,
        .loongarch64,
        => 64,
    };
}

pub fn ptrBitWidth(target: Target) u16 {
    return ptrBitWidth_cpu_abi(target.cpu, target.abi);
}

pub fn stackAlignment(target: Target) u16 {
    // Overrides for when the stack alignment is not equal to the pointer width.
    switch (target.cpu.arch) {
        .m68k,
        => return 2,
        .amdgcn,
        => return 4,
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        .lanai,
        .mips,
        .mipsel,
        .sparc,
        => return 8,
        .aarch64,
        .aarch64_be,
        .bpfeb,
        .bpfel,
        .loongarch32,
        .loongarch64,
        .mips64,
        .mips64el,
        .sparc64,
        .ve,
        .wasm32,
        .wasm64,
        => return 16,
        // Some of the following prongs should really be testing the ABI, but our current `Abi` enum
        // can't handle that level of nuance yet.
        .powerpc64,
        .powerpc64le,
        => if (target.os.tag == .linux or target.os.tag == .aix) return 16,
        .riscv32,
        .riscv64,
        => if (!Target.riscv.featureSetHas(target.cpu.features, .e)) return 16,
        .x86 => if (target.os.tag != .windows and target.os.tag != .uefi) return 16,
        .x86_64 => return 16,
        else => {},
    }

    return @divExact(target.ptrBitWidth(), 8);
}

/// Default signedness of `char` for the native C compiler for this target
/// Note that char signedness is implementation-defined and many compilers provide
/// an option to override the default signedness e.g. GCC's -funsigned-char / -fsigned-char
pub fn cCharSignedness(target: Target) std.builtin.Signedness {
    if (target.os.tag.isDarwin() or target.os.tag == .windows or target.os.tag == .uefi) return .signed;

    return switch (target.cpu.arch) {
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        .aarch64,
        .aarch64_be,
        .arc,
        .csky,
        .hexagon,
        .msp430,
        .powerpc,
        .powerpcle,
        .powerpc64,
        .powerpc64le,
        .s390x,
        .riscv32,
        .riscv64,
        .xcore,
        .xtensa,
        => .unsigned,
        else => .signed,
    };
}

pub const CType = enum {
    char,
    short,
    ushort,
    int,
    uint,
    long,
    ulong,
    longlong,
    ulonglong,
    float,
    double,
    longdouble,
};

pub fn cTypeByteSize(t: Target, c_type: CType) u16 {
    return switch (c_type) {
        .char,
        .short,
        .ushort,
        .int,
        .uint,
        .long,
        .ulong,
        .longlong,
        .ulonglong,
        .float,
        .double,
        => @divExact(cTypeBitSize(t, c_type), 8),

        .longdouble => switch (cTypeBitSize(t, c_type)) {
            16 => 2,
            32 => 4,
            64 => 8,
            80 => @intCast(std.mem.alignForward(usize, 10, cTypeAlignment(t, .longdouble))),
            128 => 16,
            else => unreachable,
        },
    };
}

pub fn cTypeBitSize(target: Target, c_type: CType) u16 {
    switch (target.os.tag) {
        .freestanding, .other => switch (target.cpu.arch) {
            .msp430 => switch (c_type) {
                .char => return 8,
                .short, .ushort, .int, .uint => return 16,
                .float, .long, .ulong => return 32,
                .longlong, .ulonglong, .double, .longdouble => return 64,
            },
            .avr => switch (c_type) {
                .char => return 8,
                .short, .ushort, .int, .uint => return 16,
                .long, .ulong, .float, .double, .longdouble => return 32,
                .longlong, .ulonglong => return 64,
            },
            .mips64, .mips64el => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => switch (target.abi) {
                    .gnuabin32, .muslabin32 => return 32,
                    else => return 64,
                },
                .longlong, .ulonglong, .double => return 64,
                .longdouble => return 128,
            },
            .x86_64 => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => switch (target.abi) {
                    .gnux32, .muslx32 => return 32,
                    else => return 64,
                },
                .longlong, .ulonglong, .double => return 64,
                .longdouble => return 80,
            },
            else => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => return target.ptrBitWidth(),
                .longlong, .ulonglong, .double => return 64,
                .longdouble => switch (target.cpu.arch) {
                    .x86 => switch (target.abi) {
                        .android => return 64,
                        else => return 80,
                    },

                    .powerpc,
                    .powerpcle,
                    .powerpc64,
                    .powerpc64le,
                    => switch (target.abi) {
                        .musl,
                        .muslabin32,
                        .muslabi64,
                        .musleabi,
                        .musleabihf,
                        .muslx32,
                        => return 64,
                        else => return 128,
                    },

                    .riscv32,
                    .riscv64,
                    .aarch64,
                    .aarch64_be,
                    .s390x,
                    .sparc64,
                    .wasm32,
                    .wasm64,
                    .loongarch32,
                    .loongarch64,
                    .ve,
                    => return 128,

                    else => return 64,
                },
            },
        },

        .fuchsia,
        .hermit,

        .aix,
        .haiku,
        .hurd,
        .linux,
        .plan9,
        .rtems,
        .serenity,
        .zos,

        .freebsd,
        .dragonfly,
        .netbsd,
        .openbsd,

        .illumos,
        .solaris,

        .wasi,
        .emscripten,
        => switch (target.cpu.arch) {
            .msp430 => switch (c_type) {
                .char => return 8,
                .short, .ushort, .int, .uint => return 16,
                .long, .ulong, .float => return 32,
                .longlong, .ulonglong, .double, .longdouble => return 64,
            },
            .avr => switch (c_type) {
                .char => return 8,
                .short, .ushort, .int, .uint => return 16,
                .long, .ulong, .float, .double, .longdouble => return 32,
                .longlong, .ulonglong => return 64,
            },
            .mips64, .mips64el => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => switch (target.abi) {
                    .gnuabin32, .muslabin32 => return 32,
                    else => return 64,
                },
                .longlong, .ulonglong, .double => return 64,
                .longdouble => if (target.os.tag == .freebsd) return 64 else return 128,
            },
            .x86_64 => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => switch (target.abi) {
                    .gnux32, .muslx32 => return 32,
                    else => return 64,
                },
                .longlong, .ulonglong, .double => return 64,
                .longdouble => return 80,
            },
            else => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => return target.ptrBitWidth(),
                .longlong, .ulonglong, .double => return 64,
                .longdouble => switch (target.cpu.arch) {
                    .x86 => switch (target.abi) {
                        .android => return 64,
                        else => return 80,
                    },

                    .powerpc,
                    .powerpcle,
                    => switch (target.abi) {
                        .musl,
                        .muslabin32,
                        .muslabi64,
                        .musleabi,
                        .musleabihf,
                        .muslx32,
                        => return 64,
                        else => switch (target.os.tag) {
                            .aix, .freebsd, .netbsd, .openbsd => return 64,
                            else => return 128,
                        },
                    },

                    .powerpc64,
                    .powerpc64le,
                    => switch (target.abi) {
                        .musl,
                        .muslabin32,
                        .muslabi64,
                        .musleabi,
                        .musleabihf,
                        .muslx32,
                        => return 64,
                        else => switch (target.os.tag) {
                            .aix, .freebsd, .openbsd => return 64,
                            else => return 128,
                        },
                    },

                    .riscv32,
                    .riscv64,
                    .aarch64,
                    .aarch64_be,
                    .s390x,
                    .mips64,
                    .mips64el,
                    .sparc64,
                    .wasm32,
                    .wasm64,
                    .loongarch32,
                    .loongarch64,
                    .ve,
                    => return 128,

                    else => return 64,
                },
            },
        },

        .windows, .uefi => switch (target.cpu.arch) {
            .x86 => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => return 32,
                .longlong, .ulonglong, .double => return 64,
                .longdouble => switch (target.abi) {
                    .gnu, .ilp32, .cygnus => return 80,
                    else => return 64,
                },
            },
            .x86_64 => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => switch (target.abi) {
                    .cygnus => return 64,
                    else => return 32,
                },
                .longlong, .ulonglong, .double => return 64,
                .longdouble => switch (target.abi) {
                    .gnu, .ilp32, .cygnus => return 80,
                    else => return 64,
                },
            },
            else => switch (c_type) {
                .char => return 8,
                .short, .ushort => return 16,
                .int, .uint, .float => return 32,
                .long, .ulong => return 32,
                .longlong, .ulonglong, .double => return 64,
                .longdouble => return 64,
            },
        },

        .driverkit,
        .ios,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => switch (c_type) {
            .char => return 8,
            .short, .ushort => return 16,
            .int, .uint, .float => return 32,
            .long, .ulong => switch (target.cpu.arch) {
                .x86_64 => return 64,
                else => switch (target.abi) {
                    .ilp32 => return 32,
                    else => return 64,
                },
            },
            .longlong, .ulonglong, .double => return 64,
            .longdouble => switch (target.cpu.arch) {
                .x86_64 => return 80,
                else => return 64,
            },
        },

        .nvcl, .cuda => switch (c_type) {
            .char => return 8,
            .short, .ushort => return 16,
            .int, .uint, .float => return 32,
            .long, .ulong => switch (target.cpu.arch) {
                .nvptx => return 32,
                .nvptx64 => return 64,
                else => return 64,
            },
            .longlong, .ulonglong, .double => return 64,
            .longdouble => return 64,
        },

        .amdhsa, .amdpal, .mesa3d => switch (c_type) {
            .char => return 8,
            .short, .ushort => return 16,
            .int, .uint, .float => return 32,
            .long, .ulong, .longlong, .ulonglong, .double => return 64,
            .longdouble => return 128,
        },

        .opencl, .vulkan => switch (c_type) {
            .char => return 8,
            .short, .ushort => return 16,
            .int, .uint, .float => return 32,
            .long, .ulong, .double => return 64,
            .longlong, .ulonglong => return 128,
            // Note: The OpenCL specification does not guarantee a particular size for long double,
            // but clang uses 128 bits.
            .longdouble => return 128,
        },

        .ps4, .ps5 => switch (c_type) {
            .char => return 8,
            .short, .ushort => return 16,
            .int, .uint, .float => return 32,
            .long, .ulong => return 64,
            .longlong, .ulonglong, .double => return 64,
            .longdouble => return 80,
        },

        .ps3,
        .contiki,
        .opengl,
        => @panic("specify the C integer and float type sizes for this OS"),
    }
}

pub fn cTypeAlignment(target: Target, c_type: CType) u16 {
    // Overrides for unusual alignments
    switch (target.cpu.arch) {
        .avr => return 1,
        .x86 => switch (target.os.tag) {
            .windows, .uefi => switch (c_type) {
                .longlong, .ulonglong, .double => return 8,
                .longdouble => switch (target.abi) {
                    .gnu, .ilp32, .cygnus => return 4,
                    else => return 8,
                },
                else => {},
            },
            else => {},
        },
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => switch (target.os.tag) {
            .aix => switch (c_type) {
                .double, .longdouble => return 4,
                else => {},
            },
            else => {},
        },
        .wasm32, .wasm64 => switch (target.os.tag) {
            .emscripten => switch (c_type) {
                .longdouble => return 8,
                else => {},
            },
            else => {},
        },
        else => {},
    }

    // Next-power-of-two-aligned, up to a maximum.
    return @min(
        std.math.ceilPowerOfTwoAssert(u16, (cTypeBitSize(target, c_type) + 7) / 8),
        @as(u16, switch (target.cpu.arch) {
            .msp430,
            => 2,

            .arc,
            .csky,
            .x86,
            .xcore,
            .kalimba,
            .xtensa,
            .propeller,
            => 4,

            .arm,
            .armeb,
            .thumb,
            .thumbeb,
            .amdgcn,
            .bpfel,
            .bpfeb,
            .hexagon,
            .m68k,
            .mips,
            .mipsel,
            .sparc,
            .lanai,
            .nvptx,
            .nvptx64,
            .s390x,
            => 8,

            .aarch64,
            .aarch64_be,
            .loongarch32,
            .loongarch64,
            .mips64,
            .mips64el,
            .powerpc,
            .powerpcle,
            .powerpc64,
            .powerpc64le,
            .riscv32,
            .riscv64,
            .sparc64,
            .spirv,
            .spirv32,
            .spirv64,
            .x86_64,
            .ve,
            .wasm32,
            .wasm64,
            => 16,

            .avr,
            => unreachable, // Handled above.
        }),
    );
}

pub fn cTypePreferredAlignment(target: Target, c_type: CType) u16 {
    // Overrides for unusual alignments
    switch (target.cpu.arch) {
        .arc => switch (c_type) {
            .longdouble => return 4,
            else => {},
        },
        .avr => return 1,
        .x86 => switch (target.os.tag) {
            .windows, .uefi => switch (c_type) {
                .longdouble => switch (target.abi) {
                    .gnu, .ilp32, .cygnus => return 4,
                    else => return 8,
                },
                else => {},
            },
            else => switch (c_type) {
                .longdouble => return 4,
                else => {},
            },
        },
        .wasm32, .wasm64 => switch (target.os.tag) {
            .emscripten => switch (c_type) {
                .longdouble => return 8,
                else => {},
            },
            else => {},
        },
        else => {},
    }

    // Next-power-of-two-aligned, up to a maximum.
    return @min(
        std.math.ceilPowerOfTwoAssert(u16, (cTypeBitSize(target, c_type) + 7) / 8),
        @as(u16, switch (target.cpu.arch) {
            .msp430 => 2,

            .csky,
            .xcore,
            .kalimba,
            .xtensa,
            .propeller,
            => 4,

            .arc,
            .arm,
            .armeb,
            .thumb,
            .thumbeb,
            .amdgcn,
            .bpfel,
            .bpfeb,
            .hexagon,
            .x86,
            .m68k,
            .mips,
            .mipsel,
            .sparc,
            .lanai,
            .nvptx,
            .nvptx64,
            .s390x,
            => 8,

            .aarch64,
            .aarch64_be,
            .loongarch32,
            .loongarch64,
            .mips64,
            .mips64el,
            .powerpc,
            .powerpcle,
            .powerpc64,
            .powerpc64le,
            .riscv32,
            .riscv64,
            .sparc64,
            .spirv,
            .spirv32,
            .spirv64,
            .x86_64,
            .ve,
            .wasm32,
            .wasm64,
            => 16,

            .avr,
            => unreachable, // Handled above.
        }),
    );
}

pub fn cMaxIntAlignment(target: std.Target) u16 {
    return switch (target.cpu.arch) {
        .avr => 1,

        .msp430 => 2,

        .xcore,
        .propeller,
        => 4,

        .amdgcn,
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        .lanai,
        .hexagon,
        .mips,
        .mipsel,
        .powerpc,
        .powerpcle,
        .riscv32,
        .s390x,
        => 8,

        // Even LLVMABIAlignmentOfType(i128) agrees on these targets.
        .aarch64,
        .aarch64_be,
        .bpfel,
        .bpfeb,
        .mips64,
        .mips64el,
        .nvptx,
        .nvptx64,
        .powerpc64,
        .powerpc64le,
        .riscv64,
        .sparc,
        .sparc64,
        .wasm32,
        .wasm64,
        .x86,
        .x86_64,
        => 16,

        // Below this comment are unverified but based on the fact that C requires
        // int128_t to be 16 bytes aligned, it's a safe default.
        .arc,
        .csky,
        .kalimba,
        .loongarch32,
        .loongarch64,
        .m68k,
        .spirv,
        .spirv32,
        .spirv64,
        .ve,
        .xtensa,
        => 16,
    };
}

pub fn cCallingConvention(target: Target) ?std.builtin.CallingConvention {
    return switch (target.cpu.arch) {
        .x86_64 => switch (target.os.tag) {
            .windows, .uefi => .{ .x86_64_win = .{} },
            else => .{ .x86_64_sysv = .{} },
        },
        .x86 => switch (target.os.tag) {
            .windows, .uefi => .{ .x86_win = .{} },
            else => .{ .x86_sysv = .{} },
        },
        .aarch64, .aarch64_be => if (target.os.tag.isDarwin()) cc: {
            break :cc .{ .aarch64_aapcs_darwin = .{} };
        } else switch (target.os.tag) {
            .windows => .{ .aarch64_aapcs_win = .{} },
            else => .{ .aarch64_aapcs = .{} },
        },
        .arm, .armeb, .thumb, .thumbeb => switch (target.abi.float()) {
            .soft => .{ .arm_aapcs = .{} },
            .hard => .{ .arm_aapcs_vfp = .{} },
        },
        .mips64, .mips64el => switch (target.abi) {
            .gnuabin32 => .{ .mips64_n32 = .{} },
            else => .{ .mips64_n64 = .{} },
        },
        .mips, .mipsel => .{ .mips_o32 = .{} },
        .riscv64 => .{ .riscv64_lp64 = .{} },
        .riscv32 => .{ .riscv32_ilp32 = .{} },
        .sparc64 => .{ .sparc64_sysv = .{} },
        .sparc => .{ .sparc_sysv = .{} },
        .powerpc64 => if (target.abi.isMusl())
            .{ .powerpc64_elf_v2 = .{} }
        else
            .{ .powerpc64_elf = .{} },
        .powerpc64le => .{ .powerpc64_elf_v2 = .{} },
        .powerpc, .powerpcle => switch (target.os.tag) {
            .aix => .{ .powerpc_aix = .{} },
            else => .{ .powerpc_sysv = .{} },
        },
        .wasm32, .wasm64 => .{ .wasm_mvp = .{} },
        .arc => .{ .arc_sysv = .{} },
        .avr => .avr_gnu,
        .bpfel, .bpfeb => .{ .bpf_std = .{} },
        .csky => .{ .csky_sysv = .{} },
        .hexagon => .{ .hexagon_sysv = .{} },
        .kalimba => null,
        .lanai => .{ .lanai_sysv = .{} },
        .loongarch64 => .{ .loongarch64_lp64 = .{} },
        .loongarch32 => .{ .loongarch32_ilp32 = .{} },
        .m68k => if (target.abi.isGnu() or target.abi.isMusl())
            .{ .m68k_gnu = .{} }
        else
            .{ .m68k_sysv = .{} },
        .msp430 => .{ .msp430_eabi = .{} },
        .propeller => .{ .propeller_sysv = .{} },
        .s390x => .{ .s390x_sysv = .{} },
        .ve => .{ .ve_sysv = .{} },
        .xcore => .{ .xcore_xs1 = .{} },
        .xtensa => .{ .xtensa_call0 = .{} },
        .amdgcn => .{ .amdgcn_device = .{} },
        .nvptx, .nvptx64 => .nvptx_device,
        .spirv, .spirv32, .spirv64 => .spirv_device,
    };
}

const Target = @This();
const std = @import("std.zig");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

test {
    std.testing.refAllDecls(Cpu.Arch);
}
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    addr_lsl_slow_14,
    aes,
    aggressive_fma,
    alternate_sextload_cvt_f32_pattern,
    altnzcv,
    alu_lsl_fast,
    am,
    amvs,
    arith_bcc_fusion,
    arith_cbz_fusion,
    ascend_store_address,
    avoid_ldapur,
    balance_fp_ops,
    bf16,
    brbe,
    bti,
    call_saved_x10,
    call_saved_x11,
    call_saved_x12,
    call_saved_x13,
    call_saved_x14,
    call_saved_x15,
    call_saved_x18,
    call_saved_x8,
    call_saved_x9,
    ccdp,
    ccidx,
    ccpp,
    chk,
    clrbhb,
    cmp_bcc_fusion,
    cmpbr,
    complxnum,
    contextidr_el2,
    cpa,
    crc,
    crypto,
    cssc,
    d128,
    disable_latency_sched_heuristic,
    disable_ldp,
    disable_stp,
    dit,
    dotprod,
    ecv,
    el2vmsa,
    el3,
    enable_select_opt,
    ete,
    exynos_cheap_as_move,
    f32mm,
    f64mm,
    f8f16mm,
    f8f32mm,
    faminmax,
    fgt,
    fix_cortex_a53_835769,
    flagm,
    fmv,
    force_32bit_jump_tables,
    fp16fml,
    fp8,
    fp8dot2,
    fp8dot4,
    fp8fma,
    fp_armv8,
    fpac,
    fprcvt,
    fptoint,
    fujitsu_monaka,
    fullfp16,
    fuse_address,
    fuse_addsub_2reg_const1,
    fuse_adrp_add,
    fuse_aes,
    fuse_arith_logic,
    fuse_crypto_eor,
    fuse_csel,
    fuse_literals,
    gcs,
    harden_sls_blr,
    harden_sls_nocomdat,
    harden_sls_retbr,
    hbc,
    hcx,
    i8mm,
    ite,
    jsconv,
    ldp_aligned_only,
    lor,
    ls64,
    lse,
    lse128,
    lse2,
    lsfe,
    lsui,
    lut,
    mec,
    mops,
    mpam,
    mte,
    neon,
    nmi,
    no_bti_at_return_twice,
    no_neg_immediates,
    no_sve_fp_ld1r,
    no_zcz_fp,
    nv,
    occmo,
    outline_atomics,
    pan,
    pan_rwv,
    pauth,
    pauth_lr,
    pcdphint,
    perfmon,
    pops,
    predictable_select_expensive,
    predres,
    prfm_slc_target,
    rand,
    ras,
    rasv2,
    rcpc,
    rcpc3,
    rcpc_immo,
    rdm,
    reserve_lr_for_ra,
    reserve_x1,
    reserve_x10,
    reserve_x11,
    reserve_x12,
    reserve_x13,
    reserve_x14,
    reserve_x15,
    reserve_x18,
    reserve_x2,
    reserve_x20,
    reserve_x21,
    reserve_x22,
    reserve_x23,
    reserve_x24,
    reserve_x25,
    reserve_x26,
    reserve_x27,
    reserve_x28,
    reserve_x3,
    reserve_x4,
    reserve_x5,
    reserve_x6,
    reserve_x7,
    reserve_x9,
    rme,
    sb,
    sel2,
    sha2,
    sha3,
    slow_misaligned_128store,
    slow_paired_128,
    slow_strqro_store,
    sm4,
    sme,
    sme2,
    sme2p1,
    sme2p2,
    sme_b16b16,
    sme_f16f16,
    sme_f64f64,
    sme_f8f16,
    sme_f8f32,
    sme_fa64,
    sme_i16i64,
    sme_lutv2,
    sme_mop4,
    sme_tmop,
    spe,
    spe_eef,
    specres2,
    specrestrict,
    ssbs,
    ssve_aes,
    ssve_bitperm,
    ssve_fp8dot2,
    ssve_fp8dot4,
    ssve_fp8fma,
    store_pair_suppress,
    stp_aligned_only,
    strict_align,
    sve,
    sve2,
    sve2_aes,
    sve2_bitperm,
    sve2_sha3,
    sve2_sm4,
    sve2p1,
    sve2p2,
    sve_aes,
    sve_aes2,
    sve_b16b16,
    sve_bfscale,
    sve_bitperm,
    sve_f16f32mm,
    tagged_globals,
    the,
    tlb_rmi,
    tlbiw,
    tme,
    tpidr_el1,
    tpidr_el2,
    tpidr_el3,
    tpidrro_el0,
    tracev8_4,
    trbe,
    uaops,
    use_experimental_zeroing_pseudos,
    use_fixed_over_scalable_if_equal_cost,
    use_postra_scheduler,
    use_reciprocal_square_root,
    v8_1a,
    v8_2a,
    v8_3a,
    v8_4a,
    v8_5a,
    v8_6a,
    v8_7a,
    v8_8a,
    v8_9a,
    v8a,
    v8r,
    v9_1a,
    v9_2a,
    v9_3a,
    v9_4a,
    v9_5a,
    v9_6a,
    v9a,
    vh,
    wfxt,
    xs,
    zcm,
    zcz,
    zcz_fp_workaround,
    zcz_gp,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    @setEvalBranchQuota(2000);
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.addr_lsl_slow_14)] = .{
        .llvm_name = "addr-lsl-slow-14",
        .description = "Address operands with shift amount of 1 or 4 are slow",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aes)] = .{
        .llvm_name = "aes",
        .description = "Enable AES support",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.aggressive_fma)] = .{
        .llvm_name = "aggressive-fma",
        .description = "Enable Aggressive FMA for floating-point.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.alternate_sextload_cvt_f32_pattern)] = .{
        .llvm_name = "alternate-sextload-cvt-f32-pattern",
        .description = "Use alternative pattern for sextload convert to f32",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.altnzcv)] = .{
        .llvm_name = "altnzcv",
        .description = "Enable alternative NZCV format for floating point comparisons",
        .dependencies = featureSet(&[_]Feature{
            .flagm,
        }),
    };
    result[@intFromEnum(Feature.alu_lsl_fast)] = .{
        .llvm_name = "alu-lsl-fast",
        .description = "Add/Sub operations with lsl shift <= 4 are cheap",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.am)] = .{
        .llvm_name = "am",
        .description = "Enable Armv8.4-A Activity Monitors extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.amvs)] = .{
        .llvm_name = "amvs",
        .description = "Enable Armv8.6-A Activity Monitors Virtualization support",
        .dependencies = featureSet(&[_]Feature{
            .am,
        }),
    };
    result[@intFromEnum(Feature.arith_bcc_fusion)] = .{
        .llvm_name = "arith-bcc-fusion",
        .description = "CPU fuses arithmetic+bcc operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.arith_cbz_fusion)] = .{
        .llvm_name = "arith-cbz-fusion",
        .description = "CPU fuses arithmetic + cbz/cbnz operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ascend_store_address)] = .{
        .llvm_name = "ascend-store-address",
        .description = "Schedule vector stores by ascending address",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.avoid_ldapur)] = .{
        .llvm_name = "avoid-ldapur",
        .description = "Prefer add+ldapr to offset ldapur",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.balance_fp_ops)] = .{
        .llvm_name = "balance-fp-ops",
        .description = "balance mix of odd and even D-registers for fp multiply(-accumulate) ops",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bf16)] = .{
        .llvm_name = "bf16",
        .description = "Enable BFloat16 Extension",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.brbe)] = .{
        .llvm_name = "brbe",
        .description = "Enable Branch Record Buffer Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bti)] = .{
        .llvm_name = "bti",
        .description = "Enable Branch Target Identification",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x10)] = .{
        .llvm_name = "call-saved-x10",
        .description = "Make X10 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x11)] = .{
        .llvm_name = "call-saved-x11",
        .description = "Make X11 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x12)] = .{
        .llvm_name = "call-saved-x12",
        .description = "Make X12 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x13)] = .{
        .llvm_name = "call-saved-x13",
        .description = "Make X13 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x14)] = .{
        .llvm_name = "call-saved-x14",
        .description = "Make X14 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x15)] = .{
        .llvm_name = "call-saved-x15",
        .description = "Make X15 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x18)] = .{
        .llvm_name = "call-saved-x18",
        .description = "Make X18 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x8)] = .{
        .llvm_name = "call-saved-x8",
        .description = "Make X8 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.call_saved_x9)] = .{
        .llvm_name = "call-saved-x9",
        .description = "Make X9 callee saved.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ccdp)] = .{
        .llvm_name = "ccdp",
        .description = "Enable Armv8.5-A Cache Clean to Point of Deep Persistence",
        .dependencies = featureSet(&[_]Feature{
            .ccpp,
        }),
    };
    result[@intFromEnum(Feature.ccidx)] = .{
        .llvm_name = "ccidx",
        .description = "Enable Armv8.3-A Extend of the CCSIDR number of sets",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ccpp)] = .{
        .llvm_name = "ccpp",
        .description = "Enable Armv8.2-A data Cache Clean to Point of Persistence",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.chk)] = .{
        .llvm_name = "chk",
        .description = "Enable Armv8.0-A Check Feature Status Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.clrbhb)] = .{
        .llvm_name = "clrbhb",
        .description = "Enable Clear BHB instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cmp_bcc_fusion)] = .{
        .llvm_name = "cmp-bcc-fusion",
        .description = "CPU fuses cmp+bcc operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cmpbr)] = .{
        .llvm_name = "cmpbr",
        .description = "Enable Armv9.6-A base compare and branch instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.complxnum)] = .{
        .llvm_name = "complxnum",
        .description = "Enable Armv8.3-A Floating-point complex number support",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.contextidr_el2)] = .{
        .llvm_name = "CONTEXTIDREL2",
        .description = "Enable RW operand Context ID Register (EL2)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cpa)] = .{
        .llvm_name = "cpa",
        .description = "Enable Armv9.5-A Checked Pointer Arithmetic",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.crc)] = .{
        .llvm_name = "crc",
        .description = "Enable Armv8.0-A CRC-32 checksum instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.crypto)] = .{
        .llvm_name = "crypto",
        .description = "Enable cryptographic instructions",
        .dependencies = featureSet(&[_]Feature{
            .aes,
            .sha2,
        }),
    };
    result[@intFromEnum(Feature.cssc)] = .{
        .llvm_name = "cssc",
        .description = "Enable Common Short Sequence Compression (CSSC) instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.d128)] = .{
        .llvm_name = "d128",
        .description = "Enable Armv9.4-A 128-bit Page Table Descriptors, System Registers and instructions",
        .dependencies = featureSet(&[_]Feature{
            .lse128,
        }),
    };
    result[@intFromEnum(Feature.disable_latency_sched_heuristic)] = .{
        .llvm_name = "disable-latency-sched-heuristic",
        .description = "Disable latency scheduling heuristic",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.disable_ldp)] = .{
        .llvm_name = "disable-ldp",
        .description = "Do not emit ldp",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.disable_stp)] = .{
        .llvm_name = "disable-stp",
        .description = "Do not emit stp",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dit)] = .{
        .llvm_name = "dit",
        .description = "Enable Armv8.4-A Data Independent Timing instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dotprod)] = .{
        .llvm_name = "dotprod",
        .description = "Enable dot product support",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.ecv)] = .{
        .llvm_name = "ecv",
        .description = "Enable enhanced counter virtualization extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.el2vmsa)] = .{
        .llvm_name = "el2vmsa",
        .description = "Enable Exception Level 2 Virtual Memory System Architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.el3)] = .{
        .llvm_name = "el3",
        .description = "Enable Exception Level 3",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.enable_select_opt)] = .{
        .llvm_name = "enable-select-opt",
        .description = "Enable the select optimize pass for select loop heuristics",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ete)] = .{
        .llvm_name = "ete",
        .description = "Enable Embedded Trace Extension",
        .dependencies = featureSet(&[_]Feature{
            .trbe,
        }),
    };
    result[@intFromEnum(Feature.exynos_cheap_as_move)] = .{
        .llvm_name = "exynos-cheap-as-move",
        .description = "Use Exynos specific handling of cheap instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.f32mm)] = .{
        .llvm_name = "f32mm",
        .description = "Enable Matrix Multiply FP32 Extension",
        .dependencies = featureSet(&[_]Feature{
            .sve,
        }),
    };
    result[@intFromEnum(Feature.f64mm)] = .{
        .llvm_name = "f64mm",
        .description = "Enable Matrix Multiply FP64 Extension",
        .dependencies = featureSet(&[_]Feature{
            .sve,
        }),
    };
    result[@intFromEnum(Feature.f8f16mm)] = .{
        .llvm_name = "f8f16mm",
        .description = "Enable Armv9.6-A FP8 to Half-Precision Matrix Multiplication",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
        }),
    };
    result[@intFromEnum(Feature.f8f32mm)] = .{
        .llvm_name = "f8f32mm",
        .description = "Enable Armv9.6-A FP8 to Single-Precision Matrix Multiplication",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
        }),
    };
    result[@intFromEnum(Feature.faminmax)] = .{
        .llvm_name = "faminmax",
        .description = "Enable FAMIN and FAMAX instructions",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.fgt)] = .{
        .llvm_name = "fgt",
        .description = "Enable fine grained virtualization traps extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_cortex_a53_835769)] = .{
        .llvm_name = "fix-cortex-a53-835769",
        .description = "Mitigate Cortex-A53 Erratum 835769",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flagm)] = .{
        .llvm_name = "flagm",
        .description = "Enable Armv8.4-A Flag Manipulation instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fmv)] = .{
        .llvm_name = "fmv",
        .description = "Enable Function Multi Versioning support.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.force_32bit_jump_tables)] = .{
        .llvm_name = "force-32bit-jump-tables",
        .description = "Force jump table entries to be 32-bits wide except at MinSize",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp16fml)] = .{
        .llvm_name = "fp16fml",
        .description = "Enable FP16 FML instructions",
        .dependencies = featureSet(&[_]Feature{
            .fullfp16,
            .neon,
        }),
    };
    result[@intFromEnum(Feature.fp8)] = .{
        .llvm_name = "fp8",
        .description = "Enable FP8 instructions",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.fp8dot2)] = .{
        .llvm_name = "fp8dot2",
        .description = "Enable FP8 2-way dot instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
        }),
    };
    result[@intFromEnum(Feature.fp8dot4)] = .{
        .llvm_name = "fp8dot4",
        .description = "Enable FP8 4-way dot instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
        }),
    };
    result[@intFromEnum(Feature.fp8fma)] = .{
        .llvm_name = "fp8fma",
        .description = "Enable Armv9.5-A FP8 multiply-add instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
        }),
    };
    result[@intFromEnum(Feature.fp_armv8)] = .{
        .llvm_name = "fp-armv8",
        .description = "Enable Armv8.0-A Floating Point Extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fpac)] = .{
        .llvm_name = "fpac",
        .description = "Enable Armv8.3-A Pointer Authentication Faulting enhancement",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fprcvt)] = .{
        .llvm_name = "fprcvt",
        .description = "Enable Armv9.6-A base convert instructions for SIMD&FP scalar register operands of different input and output sizes",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8,
        }),
    };
    result[@intFromEnum(Feature.fptoint)] = .{
        .llvm_name = "fptoint",
        .description = "Enable FRInt[32|64][Z|X] instructions that round a floating-point number to an integer (in FP format) forcing it to fit into a 32- or 64-bit int",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8,
        }),
    };
    result[@intFromEnum(Feature.fujitsu_monaka)] = .{
        .llvm_name = "fujitsu-monaka",
        .description = "Fujitsu FUJITSU-MONAKA processors",
        .dependencies = featureSet(&[_]Feature{
            .arith_bcc_fusion,
            .enable_select_opt,
            .predictable_select_expensive,
            .use_postra_scheduler,
        }),
    };
    result[@intFromEnum(Feature.fullfp16)] = .{
        .llvm_name = "fullfp16",
        .description = "Enable half-precision floating-point data processing",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8,
        }),
    };
    result[@intFromEnum(Feature.fuse_address)] = .{
        .llvm_name = "fuse-address",
        .description = "CPU fuses address generation and memory operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_addsub_2reg_const1)] = .{
        .llvm_name = "fuse-addsub-2reg-const1",
        .description = "CPU fuses (a + b + 1) and (a - b - 1)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_adrp_add)] = .{
        .llvm_name = "fuse-adrp-add",
        .description = "CPU fuses adrp+add operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_aes)] = .{
        .llvm_name = "fuse-aes",
        .description = "CPU fuses AES crypto operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_arith_logic)] = .{
        .llvm_name = "fuse-arith-logic",
        .description = "CPU fuses arithmetic and logic operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_crypto_eor)] = .{
        .llvm_name = "fuse-crypto-eor",
        .description = "CPU fuses AES/PMULL and EOR operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_csel)] = .{
        .llvm_name = "fuse-csel",
        .description = "CPU fuses conditional select operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_literals)] = .{
        .llvm_name = "fuse-literals",
        .description = "CPU fuses literal generation operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gcs)] = .{
        .llvm_name = "gcs",
        .description = "Enable Armv9.4-A Guarded Call Stack Extension",
        .dependencies = featureSet(&[_]Feature{
            .chk,
        }),
    };
    result[@intFromEnum(Feature.harden_sls_blr)] = .{
        .llvm_name = "harden-sls-blr",
        .description = "Harden against straight line speculation across BLR instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.harden_sls_nocomdat)] = .{
        .llvm_name = "harden-sls-nocomdat",
        .description = "Generate thunk code for SLS mitigation in the normal text section",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.harden_sls_retbr)] = .{
        .llvm_name = "harden-sls-retbr",
        .description = "Harden against straight line speculation across RET and BR instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hbc)] = .{
        .llvm_name = "hbc",
        .description = "Enable Armv8.8-A Hinted Conditional Branches Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hcx)] = .{
        .llvm_name = "hcx",
        .description = "Enable Armv8.7-A HCRX_EL2 system register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.i8mm)] = .{
        .llvm_name = "i8mm",
        .description = "Enable Matrix Multiply Int8 Extension",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.ite)] = .{
        .llvm_name = "ite",
        .description = "Enable Armv9.4-A Instrumentation Extension",
        .dependencies = featureSet(&[_]Feature{
            .ete,
        }),
    };
    result[@intFromEnum(Feature.jsconv)] = .{
        .llvm_name = "jsconv",
        .description = "Enable Armv8.3-A JavaScript FP conversion instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8,
        }),
    };
    result[@intFromEnum(Feature.ldp_aligned_only)] = .{
        .llvm_name = "ldp-aligned-only",
        .description = "In order to emit ldp, first check if the load will be aligned to 2 * element_size",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lor)] = .{
        .llvm_name = "lor",
        .description = "Enable Armv8.1-A Limited Ordering Regions extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ls64)] = .{
        .llvm_name = "ls64",
        .description = "Enable Armv8.7-A LD64B/ST64B Accelerator Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lse)] = .{
        .llvm_name = "lse",
        .description = "Enable Armv8.1-A Large System Extension (LSE) atomic instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lse128)] = .{
        .llvm_name = "lse128",
        .description = "Enable Armv9.4-A 128-bit Atomic instructions",
        .dependencies = featureSet(&[_]Feature{
            .lse,
        }),
    };
    result[@intFromEnum(Feature.lse2)] = .{
        .llvm_name = "lse2",
        .description = "Enable Armv8.4-A Large System Extension 2 (LSE2) atomicity rules",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lsfe)] = .{
        .llvm_name = "lsfe",
        .description = "Enable Armv9.6-A base Atomic floating-point in-memory instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8,
        }),
    };
    result[@intFromEnum(Feature.lsui)] = .{
        .llvm_name = "lsui",
        .description = "Enable Armv9.6-A unprivileged load/store instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lut)] = .{
        .llvm_name = "lut",
        .description = "Enable Lookup Table instructions",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.mec)] = .{
        .llvm_name = "mec",
        .description = "Enable Memory Encryption Contexts Extension",
        .dependencies = featureSet(&[_]Feature{
            .rme,
        }),
    };
    result[@intFromEnum(Feature.mops)] = .{
        .llvm_name = "mops",
        .description = "Enable Armv8.8-A memcpy and memset acceleration instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mpam)] = .{
        .llvm_name = "mpam",
        .description = "Enable Armv8.4-A Memory system Partitioning and Monitoring extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mte)] = .{
        .llvm_name = "mte",
        .description = "Enable Memory Tagging Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.neon)] = .{
        .llvm_name = "neon",
        .description = "Enable Advanced SIMD instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8,
        }),
    };
    result[@intFromEnum(Feature.nmi)] = .{
        .llvm_name = "nmi",
        .description = "Enable Armv8.8-A Non-maskable Interrupts",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_bti_at_return_twice)] = .{
        .llvm_name = "no-bti-at-return-twice",
        .description = "Don't place a BTI instruction after a return-twice",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_neg_immediates)] = .{
        .llvm_name = "no-neg-immediates",
        .description = "Convert immediates and instructions to their negated or complemented equivalent when the immediate does not fit in the encoding.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_sve_fp_ld1r)] = .{
        .llvm_name = "no-sve-fp-ld1r",
        .description = "Avoid using LD1RX instructions for FP",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_zcz_fp)] = .{
        .llvm_name = "no-zcz-fp",
        .description = "Has no zero-cycle zeroing instructions for FP registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nv)] = .{
        .llvm_name = "nv",
        .description = "Enable Armv8.4-A Nested Virtualization Enchancement",
        .dependencies = featureSet(&[_]Feature{}),
    };
  ```
