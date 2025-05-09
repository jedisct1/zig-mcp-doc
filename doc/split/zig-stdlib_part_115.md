```
       .isa_v30_instructions,
            .power8_altivec,
        }),
    };
    result[@intFromEnum(Feature.power9_vector)] = .{
        .llvm_name = "power9-vector",
        .description = "Enable POWER9 vector instructions",
        .dependencies = featureSet(&[_]Feature{
            .power8_vector,
            .power9_altivec,
        }),
    };
    result[@intFromEnum(Feature.ppc4xx)] = .{
        .llvm_name = "ppc4xx",
        .description = "Enable PPC 4xx instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ppc6xx)] = .{
        .llvm_name = "ppc6xx",
        .description = "Enable PPC 6xx instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ppc_postra_sched)] = .{
        .llvm_name = "ppc-postra-sched",
        .description = "Use PowerPC post-RA scheduling strategy",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ppc_prera_sched)] = .{
        .llvm_name = "ppc-prera-sched",
        .description = "Use PowerPC pre-RA scheduling strategy",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.predictable_select_expensive)] = .{
        .llvm_name = "predictable-select-expensive",
        .description = "Prefer likely predicted branches over selects",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prefix_instrs)] = .{
        .llvm_name = "prefix-instrs",
        .description = "Enable prefixed instructions",
        .dependencies = featureSet(&[_]Feature{
            .isa_v31_instructions,
        }),
    };
    result[@intFromEnum(Feature.privileged)] = .{
        .llvm_name = "privileged",
        .description = "Add privileged instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.quadword_atomics)] = .{
        .llvm_name = "quadword-atomics",
        .description = "Enable lqarx and stqcx.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.recipprec)] = .{
        .llvm_name = "recipprec",
        .description = "Assume higher precision reciprocal estimates",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rop_protect)] = .{
        .llvm_name = "rop-protect",
        .description = "Add ROP protect",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.secure_plt)] = .{
        .llvm_name = "secure-plt",
        .description = "Enable secure plt mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_popcntd)] = .{
        .llvm_name = "slow-popcntd",
        .description = "Has slow popcnt[dw] instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.spe)] = .{
        .llvm_name = "spe",
        .description = "Enable SPE instructions",
        .dependencies = featureSet(&[_]Feature{
            .hard_float,
        }),
    };
    result[@intFromEnum(Feature.stfiwx)] = .{
        .llvm_name = "stfiwx",
        .description = "Enable the stfiwx instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.two_const_nr)] = .{
        .llvm_name = "two-const-nr",
        .description = "Requires two constant Newton-Raphson computation",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vectors_use_two_units)] = .{
        .llvm_name = "vectors-use-two-units",
        .description = "Vectors use two units",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vsx)] = .{
        .llvm_name = "vsx",
        .description = "Enable VSX instructions",
        .dependencies = featureSet(&[_]Feature{
            .altivec,
        }),
    };
    const ti = @typeInfo(Feature);
    for (&result, 0..) |*elem, i| {
        elem.index = i;
        elem.name = ti.@"enum".fields[i].name;
    }
    break :blk result;
};

pub const cpu = struct {
    pub const @"440": CpuModel = .{
        .name = "440",
        .llvm_name = "440",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
            .isel,
            .msync,
        }),
    };
    pub const @"450": CpuModel = .{
        .name = "450",
        .llvm_name = "450",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
            .isel,
            .msync,
        }),
    };
    pub const @"601": CpuModel = .{
        .name = "601",
        .llvm_name = "601",
        .features = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    pub const @"602": CpuModel = .{
        .name = "602",
        .llvm_name = "602",
        .features = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    pub const @"603": CpuModel = .{
        .name = "603",
        .llvm_name = "603",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const @"603e": CpuModel = .{
        .name = "603e",
        .llvm_name = "603e",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const @"603ev": CpuModel = .{
        .name = "603ev",
        .llvm_name = "603ev",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const @"604": CpuModel = .{
        .name = "604",
        .llvm_name = "604",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const @"604e": CpuModel = .{
        .name = "604e",
        .llvm_name = "604e",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const @"620": CpuModel = .{
        .name = "620",
        .llvm_name = "620",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const @"7400": CpuModel = .{
        .name = "7400",
        .llvm_name = "7400",
        .features = featureSet(&[_]Feature{
            .altivec,
            .fres,
            .frsqrte,
        }),
    };
    pub const @"7450": CpuModel = .{
        .name = "7450",
        .llvm_name = "7450",
        .features = featureSet(&[_]Feature{
            .altivec,
            .fres,
            .frsqrte,
        }),
    };
    pub const @"750": CpuModel = .{
        .name = "750",
        .llvm_name = "750",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const @"970": CpuModel = .{
        .name = "970",
        .llvm_name = "970",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .fres,
            .frsqrte,
            .fsqrt,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const a2: CpuModel = .{
        .name = "a2",
        .llvm_name = "a2",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .booke,
            .cmpb,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .isa_v206_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .recipprec,
            .slow_popcntd,
            .stfiwx,
        }),
    };
    pub const e500: CpuModel = .{
        .name = "e500",
        .llvm_name = "e500",
        .features = featureSet(&[_]Feature{
            .isel,
            .msync,
            .spe,
        }),
    };
    pub const e500mc: CpuModel = .{
        .name = "e500mc",
        .llvm_name = "e500mc",
        .features = featureSet(&[_]Feature{
            .booke,
            .isel,
            .stfiwx,
        }),
    };
    pub const e5500: CpuModel = .{
        .name = "e5500",
        .llvm_name = "e5500",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .booke,
            .isel,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const future: CpuModel = .{
        .name = "future",
        .llvm_name = "future",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_unaligned_fp_access,
            .bpermd,
            .cmpb,
            .crbits,
            .crypto,
            .direct_move,
            .extdiv,
            .fast_MFLR,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .fuse_add_logical,
            .fuse_arith_add,
            .fuse_logical,
            .fuse_logical_add,
            .fuse_sha3,
            .fuse_store,
            .htm,
            .icbt,
            .isa_future_instructions,
            .isa_v206_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .mma,
            .partword_atomics,
            .pcrelative_memops,
            .popcntd,
            .power10_vector,
            .ppc_postra_sched,
            .ppc_prera_sched,
            .predictable_select_expensive,
            .quadword_atomics,
            .recipprec,
            .stfiwx,
            .two_const_nr,
        }),
    };
    pub const g3: CpuModel = .{
        .name = "g3",
        .llvm_name = "g3",
        .features = featureSet(&[_]Feature{
            .fres,
            .frsqrte,
        }),
    };
    pub const g4: CpuModel = .{
        .name = "g4",
        .llvm_name = "g4",
        .features = featureSet(&[_]Feature{
            .altivec,
            .fres,
            .frsqrte,
        }),
    };
    pub const @"g4+": CpuModel = .{
        .name = "g4+",
        .llvm_name = "g4+",
        .features = featureSet(&[_]Feature{
            .altivec,
            .fres,
            .frsqrte,
        }),
    };
    pub const g5: CpuModel = .{
        .name = "g5",
        .llvm_name = "g5",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .fres,
            .frsqrte,
            .fsqrt,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .hard_float,
        }),
    };
    pub const ppc: CpuModel = .{
        .name = "ppc",
        .llvm_name = "ppc",
        .features = featureSet(&[_]Feature{
            .hard_float,
        }),
    };
    pub const ppc64: CpuModel = .{
        .name = "ppc64",
        .llvm_name = "ppc64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .fres,
            .frsqrte,
            .fsqrt,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const ppc64le: CpuModel = .{
        .name = "ppc64le",
        .llvm_name = "ppc64le",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_unaligned_fp_access,
            .bpermd,
            .cmpb,
            .crbits,
            .crypto,
            .direct_move,
            .extdiv,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .fuse_addi_load,
            .fuse_addis_load,
            .htm,
            .icbt,
            .isa_v206_instructions,
            .isa_v207_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .partword_atomics,
            .popcntd,
            .power8_vector,
            .predictable_select_expensive,
            .quadword_atomics,
            .recipprec,
            .stfiwx,
            .two_const_nr,
        }),
    };
    pub const pwr10: CpuModel = .{
        .name = "pwr10",
        .llvm_name = "pwr10",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_unaligned_fp_access,
            .bpermd,
            .cmpb,
            .crbits,
            .crypto,
            .direct_move,
            .extdiv,
            .fast_MFLR,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .fuse_add_logical,
            .fuse_arith_add,
            .fuse_logical,
            .fuse_logical_add,
            .fuse_sha3,
            .fuse_store,
            .htm,
            .icbt,
            .isa_v206_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .mma,
            .partword_atomics,
            .pcrelative_memops,
            .popcntd,
            .power10_vector,
            .ppc_postra_sched,
            .ppc_prera_sched,
            .predictable_select_expensive,
            .quadword_atomics,
            .recipprec,
            .stfiwx,
            .two_const_nr,
        }),
    };
    pub const pwr11: CpuModel = .{
        .name = "pwr11",
        .llvm_name = "pwr11",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_unaligned_fp_access,
            .bpermd,
            .cmpb,
            .crbits,
            .crypto,
            .direct_move,
            .extdiv,
            .fast_MFLR,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .fuse_add_logical,
            .fuse_arith_add,
            .fuse_logical,
            .fuse_logical_add,
            .fuse_sha3,
            .fuse_store,
            .htm,
            .icbt,
            .isa_v206_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .mma,
            .partword_atomics,
            .pcrelative_memops,
            .popcntd,
            .power10_vector,
            .ppc_postra_sched,
            .ppc_prera_sched,
            .predictable_select_expensive,
            .quadword_atomics,
            .recipprec,
            .stfiwx,
            .two_const_nr,
        }),
    };
    pub const pwr3: CpuModel = .{
        .name = "pwr3",
        .llvm_name = "pwr3",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .fres,
            .frsqrte,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const pwr4: CpuModel = .{
        .name = "pwr4",
        .llvm_name = "pwr4",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .fres,
            .frsqrte,
            .fsqrt,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const pwr5: CpuModel = .{
        .name = "pwr5",
        .llvm_name = "pwr5",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const pwr5x: CpuModel = .{
        .name = "pwr5x",
        .llvm_name = "pwr5x",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .mfocrf,
            .stfiwx,
        }),
    };
    pub const pwr6: CpuModel = .{
        .name = "pwr6",
        .llvm_name = "pwr6",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .cmpb,
            .fcpsgn,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .lfiwax,
            .mfocrf,
            .recipprec,
            .stfiwx,
        }),
    };
    pub const pwr6x: CpuModel = .{
        .name = "pwr6x",
        .llvm_name = "pwr6x",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .altivec,
            .cmpb,
            .fcpsgn,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .lfiwax,
            .mfocrf,
            .recipprec,
            .stfiwx,
        }),
    };
    pub const pwr7: CpuModel = .{
        .name = "pwr7",
        .llvm_name = "pwr7",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_unaligned_fp_access,
            .bpermd,
            .cmpb,
            .extdiv,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .isa_v206_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .popcntd,
            .recipprec,
            .stfiwx,
            .two_const_nr,
            .vsx,
        }),
    };
    pub const pwr8: CpuModel = .{
        .name = "pwr8",
        .llvm_name = "pwr8",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_unaligned_fp_access,
            .bpermd,
            .cmpb,
            .crbits,
            .crypto,
            .direct_move,
            .extdiv,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .fuse_addi_load,
            .fuse_addis_load,
            .htm,
            .icbt,
            .isa_v206_instructions,
            .isa_v207_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .partword_atomics,
            .popcntd,
            .power8_vector,
            .predictable_select_expensive,
            .quadword_atomics,
            .recipprec,
            .stfiwx,
            .two_const_nr,
        }),
    };
    pub const pwr9: CpuModel = .{
        .name = "pwr9",
        .llvm_name = "pwr9",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_unaligned_fp_access,
            .bpermd,
            .cmpb,
            .crbits,
            .crypto,
            .direct_move,
            .extdiv,
            .fcpsgn,
            .fpcvt,
            .fprnd,
            .fre,
            .fres,
            .frsqrte,
            .frsqrtes,
            .fsqrt,
            .htm,
            .icbt,
            .isa_v206_instructions,
            .isel,
            .ldbrx,
            .lfiwax,
            .mfocrf,
            .partword_atomics,
            .popcntd,
            .power9_vector,
            .ppc_postra_sched,
            .ppc_prera_sched,
            .predictable_select_expensive,
            .quadword_atomics,
            .recipprec,
            .stfiwx,
            .two_const_nr,
            .vectors_use_two_units,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    p2,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.p2)] = .{
        .llvm_name = null,
        .description = "Enable Propeller 2",
        .dependencies = featureSet(&[_]Feature{}),
    };
    const ti = @typeInfo(Feature);
    for (&result, 0..) |*elem, i| {
        elem.index = i;
        elem.name = ti.@"enum".fields[i].name;
    }
    break :blk result;
};

pub const cpu = struct {
    pub const p1: CpuModel = .{
        .name = "p1",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{}),
    };
    pub const p2: CpuModel = .{
        .name = "p2",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .p2,
        }),
    };
};
//! Contains all the same data as `Target`, additionally introducing the
//! concept of "the native target". The purpose of this abstraction is to
//! provide meaningful and unsurprising defaults. This struct does reference
//! any resources and it is copyable.

/// `null` means native.
cpu_arch: ?Target.Cpu.Arch = null,

cpu_model: CpuModel = .determined_by_arch_os,

/// Sparse set of CPU features to add to the set from `cpu_model`.
cpu_features_add: Target.Cpu.Feature.Set = .empty,

/// Sparse set of CPU features to remove from the set from `cpu_model`.
cpu_features_sub: Target.Cpu.Feature.Set = .empty,

/// `null` means native.
os_tag: ?Target.Os.Tag = null,

/// `null` means the default version range for `os_tag`. If `os_tag` is `null` (native)
/// then `null` for this field means native.
os_version_min: ?OsVersion = null,

/// When cross compiling, `null` means default (latest known OS version).
/// When `os_tag` is native, `null` means equal to the native OS version.
os_version_max: ?OsVersion = null,

/// `null` means default when cross compiling, or native when `os_tag` is native.
/// If `isGnu()` is `false`, this must be `null` and is ignored.
glibc_version: ?SemanticVersion = null,

/// `null` means default when cross compiling, or native when `os_tag` is native.
/// If `isAndroid()` is `false`, this must be `null` and is ignored.
android_api_level: ?u32 = null,

/// `null` means the native C ABI, if `os_tag` is native, otherwise it means the default C ABI.
abi: ?Target.Abi = null,

/// When `os_tag` is `null`, then `null` means native. Otherwise it means the standard path
/// based on the `os_tag`.
dynamic_linker: Target.DynamicLinker = .none,

/// `null` means default for the cpu/arch/os combo.
ofmt: ?Target.ObjectFormat = null,

pub const CpuModel = union(enum) {
    /// Always native
    native,

    /// Always baseline
    baseline,

    /// If CPU Architecture is native, then the CPU model will be native. Otherwise,
    /// it will be baseline.
    determined_by_arch_os,

    explicit: *const Target.Cpu.Model,

    pub fn eql(a: CpuModel, b: CpuModel) bool {
        const Tag = @typeInfo(CpuModel).@"union".tag_type.?;
        const a_tag: Tag = a;
        const b_tag: Tag = b;
        if (a_tag != b_tag) return false;
        return switch (a) {
            .native, .baseline, .determined_by_arch_os => true,
            .explicit => |a_model| a_model == b.explicit,
        };
    }
};

pub const OsVersion = union(enum) {
    none: void,
    semver: SemanticVersion,
    windows: Target.Os.WindowsVersion,

    pub fn eql(a: OsVersion, b: OsVersion) bool {
        const Tag = @typeInfo(OsVersion).@"union".tag_type.?;
        const a_tag: Tag = a;
        const b_tag: Tag = b;
        if (a_tag != b_tag) return false;
        return switch (a) {
            .none => true,
            .semver => |a_semver| a_semver.order(b.semver) == .eq,
            .windows => |a_windows| a_windows == b.windows,
        };
    }

    pub fn eqlOpt(a: ?OsVersion, b: ?OsVersion) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        return OsVersion.eql(a.?, b.?);
    }
};

pub const SemanticVersion = std.SemanticVersion;

pub fn fromTarget(target: Target) Query {
    var result: Query = .{
        .cpu_arch = target.cpu.arch,
        .cpu_model = .{ .explicit = target.cpu.model },
        .os_tag = target.os.tag,
        .os_version_min = undefined,
        .os_version_max = undefined,
        .abi = target.abi,
        .glibc_version = if (target.abi.isGnu()) target.os.versionRange().gnuLibCVersion() else null,
        .android_api_level = if (target.abi.isAndroid()) target.os.version_range.linux.android else null,
    };
    result.updateOsVersionRange(target.os);

    const all_features = target.cpu.arch.allFeaturesList();
    var cpu_model_set = target.cpu.model.features;
    cpu_model_set.populateDependencies(all_features);
    {
        // The "add" set is the full set with the CPU Model set removed.
        const add_set = &result.cpu_features_add;
        add_set.* = target.cpu.features;
        add_set.removeFeatureSet(cpu_model_set);
    }
    {
        // The "sub" set is the features that are on in CPU Model set and off in the full set.
        const sub_set = &result.cpu_features_sub;
        sub_set.* = cpu_model_set;
        sub_set.removeFeatureSet(target.cpu.features);
    }
    return result;
}

fn updateOsVersionRange(self: *Query, os: Target.Os) void {
    self.os_version_min, self.os_version_max = switch (os.tag.versionRangeTag()) {
        .none => .{ .{ .none = {} }, .{ .none = {} } },
        .semver => .{
            .{ .semver = os.version_range.semver.min },
            .{ .semver = os.version_range.semver.max },
        },
        inline .hurd, .linux => |t| .{
            .{ .semver = @field(os.version_range, @tagName(t)).range.min },
            .{ .semver = @field(os.version_range, @tagName(t)).range.max },
        },
        .windows => .{
            .{ .windows = os.version_range.windows.min },
            .{ .windows = os.version_range.windows.max },
        },
    };
}

pub const ParseOptions = struct {
    /// This is sometimes called a "triple". It looks roughly like this:
    ///     riscv64-linux-musl
    /// The fields are, respectively:
    /// * CPU Architecture
    /// * Operating System (and optional version range)
    /// * C ABI (optional, with optional glibc version or Android API level)
    /// The string "native" can be used for CPU architecture as well as Operating System.
    /// If the CPU Architecture is specified as "native", then the Operating System and C ABI may be omitted.
    arch_os_abi: []const u8 = "native",

    /// Looks like "name+a+b-c-d+e", where "name" is a CPU Model name, "a", "b", and "e"
    /// are examples of CPU features to add to the set, and "c" and "d" are examples of CPU features
    /// to remove from the set.
    /// The following special strings are recognized for CPU Model name:
    /// * "baseline" - The "default" set of CPU features for cross-compiling. A conservative set
    ///                of features that is expected to be supported on most available hardware.
    /// * "native"   - The native CPU model is to be detected when compiling.
    /// If this field is not provided (`null`), then the value will depend on the
    /// parsed CPU Architecture. If native, then this will be "native". Otherwise, it will be "baseline".
    cpu_features: ?[]const u8 = null,

    /// Absolute path to dynamic linker, to override the default, which is either a natively
    /// detected path, or a standard path.
    dynamic_linker: ?[]const u8 = null,

    object_format: ?[]const u8 = null,

    /// If this is provided, the function will populate some information about parsing failures,
    /// so that user-friendly error messages can be delivered.
    diagnostics: ?*Diagnostics = null,

    pub const Diagnostics = struct {
        /// If the architecture was determined, this will be populated.
        arch: ?Target.Cpu.Arch = null,

        /// If the OS name was determined, this will be populated.
        os_name: ?[]const u8 = null,

        /// If the OS tag was determined, this will be populated.
        os_tag: ?Target.Os.Tag = null,

        /// If the ABI was determined, this will be populated.
        abi: ?Target.Abi = null,

        /// If the CPU name was determined, this will be populated.
        cpu_name: ?[]const u8 = null,

        /// If error.UnknownCpuFeature is returned, this will be populated.
        unknown_feature_name: ?[]const u8 = null,

        /// If error.UnknownArchitecture is returned, this will be populated.
        unknown_architecture_name: ?[]const u8 = null,
    };
};

pub fn parse(args: ParseOptions) !Query {
    var dummy_diags: ParseOptions.Diagnostics = undefined;
    const diags = args.diagnostics orelse &dummy_diags;

    var result: Query = .{
        .dynamic_linker = Target.DynamicLinker.init(args.dynamic_linker),
    };

    var it = mem.splitScalar(u8, args.arch_os_abi, '-');
    const arch_name = it.first();
    const arch_is_native = mem.eql(u8, arch_name, "native");
    if (!arch_is_native) {
        result.cpu_arch = std.meta.stringToEnum(Target.Cpu.Arch, arch_name) orelse {
            diags.unknown_architecture_name = arch_name;
            return error.UnknownArchitecture;
        };
    }
    const arch = result.cpu_arch orelse builtin.cpu.arch;
    diags.arch = arch;

    if (it.next()) |os_text| {
        try parseOs(&result, diags, os_text);
    } else if (!arch_is_native) {
        return error.MissingOperatingSystem;
    }

    const opt_abi_text = it.next();
    if (opt_abi_text) |abi_text| {
        var abi_it = mem.splitScalar(u8, abi_text, '.');
        const abi = std.meta.stringToEnum(Target.Abi, abi_it.first()) orelse
            return error.UnknownApplicationBinaryInterface;
        result.abi = abi;
        diags.abi = abi;

        const abi_ver_text = abi_it.rest();
        if (abi_it.next() != null) {
            if (abi.isGnu()) {
                result.glibc_version = parseVersion(abi_ver_text) catch |err| switch (err) {
                    error.Overflow => return error.InvalidAbiVersion,
                    error.InvalidVersion => return error.InvalidAbiVersion,
                };
            } else if (abi.isAndroid()) {
                result.android_api_level = std.fmt.parseUnsigned(u32, abi_ver_text, 10) catch |err| switch (err) {
                    error.InvalidCharacter => return error.InvalidVersion,
                    error.Overflow => return error.Overflow,
                };
            } else {
                return error.InvalidAbiVersion;
            }
        }
    }

    if (it.next() != null) return error.UnexpectedExtraField;

    if (args.cpu_features) |cpu_features| {
        const all_features = arch.allFeaturesList();
        var index: usize = 0;
        while (index < cpu_features.len and
            cpu_features[index] != '+' and
            cpu_features[index] != '-')
        {
            index += 1;
        }
        const cpu_name = cpu_features[0..index];
        diags.cpu_name = cpu_name;

        const add_set = &result.cpu_features_add;
        const sub_set = &result.cpu_features_sub;
        if (mem.eql(u8, cpu_name, "native")) {
            result.cpu_model = .native;
        } else if (mem.eql(u8, cpu_name, "baseline")) {
            result.cpu_model = .baseline;
        } else {
            result.cpu_model = .{ .explicit = try arch.parseCpuModel(cpu_name) };
        }

        while (index < cpu_features.len) {
            const op = cpu_features[index];
            const set = switch (op) {
                '+' => add_set,
                '-' => sub_set,
                else => unreachable,
            };
            index += 1;
            const start = index;
            while (index < cpu_features.len and
                cpu_features[index] != '+' and
                cpu_features[index] != '-')
            {
                index += 1;
            }
            const feature_name = cpu_features[start..index];
            for (all_features, 0..) |feature, feat_index_usize| {
                const feat_index = @as(Target.Cpu.Feature.Set.Index, @intCast(feat_index_usize));
                if (mem.eql(u8, feature_name, feature.name)) {
                    set.addFeature(feat_index);
                    break;
                }
            } else {
                diags.unknown_feature_name = feature_name;
                return error.UnknownCpuFeature;
            }
        }
    }

    if (args.object_format) |ofmt_name| {
        result.ofmt = std.meta.stringToEnum(Target.ObjectFormat, ofmt_name) orelse
            return error.UnknownObjectFormat;
    }

    return result;
}

/// Similar to `parse` except instead of fully parsing, it only determines the CPU
/// architecture and returns it if it can be determined, and returns `null` otherwise.
/// This is intended to be used if the API user of Query needs to learn the
/// target CPU architecture in order to fully populate `ParseOptions`.
pub fn parseCpuArch(args: ParseOptions) ?Target.Cpu.Arch {
    var it = mem.splitScalar(u8, args.arch_os_abi, '-');
    const arch_name = it.first();
    const arch_is_native = mem.eql(u8, arch_name, "native");
    if (arch_is_native) {
        return builtin.cpu.arch;
    } else {
        return std.meta.stringToEnum(Target.Cpu.Arch, arch_name);
    }
}

/// Similar to `SemanticVersion.parse`, but with following changes:
/// * Leading zeroes are allowed.
/// * Supports only 2 or 3 version components (major, minor, [patch]). If 3-rd component is omitted, it will be 0.
pub fn parseVersion(ver: []const u8) error{ InvalidVersion, Overflow }!SemanticVersion {
    const parseVersionComponentFn = (struct {
        fn parseVersionComponentInner(component: []const u8) error{ InvalidVersion, Overflow }!usize {
            return std.fmt.parseUnsigned(usize, component, 10) catch |err| switch (err) {
                error.InvalidCharacter => return error.InvalidVersion,
                error.Overflow => return error.Overflow,
            };
        }
    }).parseVersionComponentInner;
    var version_components = mem.splitScalar(u8, ver, '.');
    const major = version_components.first();
    const minor = version_components.next() orelse return error.InvalidVersion;
    const patch = version_components.next() orelse "0";
    if (version_components.next() != null) return error.InvalidVersion;
    return .{
        .major = try parseVersionComponentFn(major),
        .minor = try parseVersionComponentFn(minor),
        .patch = try parseVersionComponentFn(patch),
    };
}

test parseVersion {
    try std.testing.expectError(error.InvalidVersion, parseVersion("1"));
    try std.testing.expectEqual(SemanticVersion{ .major = 1, .minor = 2, .patch = 0 }, try parseVersion("1.2"));
    try std.testing.expectEqual(SemanticVersion{ .major = 1, .minor = 2, .patch = 3 }, try parseVersion("1.2.3"));
    try std.testing.expectError(error.InvalidVersion, parseVersion("1.2.3.4"));
}

pub fn isNativeCpu(self: Query) bool {
    return self.cpu_arch == null and
        (self.cpu_model == .native or self.cpu_model == .determined_by_arch_os) and
        self.cpu_features_sub.isEmpty() and self.cpu_features_add.isEmpty();
}

pub fn isNativeOs(self: Query) bool {
    return self.os_tag == null and self.os_version_min == null and self.os_version_max == null and
        self.dynamic_linker.get() == null and self.glibc_version == null and self.android_api_level == null;
}

pub fn isNativeAbi(self: Query) bool {
    return self.os_tag == null and self.abi == null;
}

pub fn isNativeTriple(self: Query) bool {
    return self.isNativeCpu() and self.isNativeOs() and self.isNativeAbi();
}

pub fn isNative(self: Query) bool {
    return self.isNativeTriple() and self.ofmt == null;
}

pub fn canDetectLibC(self: Query) bool {
    if (self.isNativeOs()) return true;
    if (self.os_tag) |os| {
        if (builtin.os.tag == .macos and os.isDarwin()) return true;
        if (os == .linux) {
            if (self.abi) |abi| if (abi.isAndroid()) return true;
        }
    }
    return false;
}

/// Formats a version with the patch component omitted if it is zero,
/// unlike SemanticVersion.format which formats all its version components regardless.
fn formatVersion(version: SemanticVersion, writer: anytype) !void {
    if (version.patch == 0) {
        try writer.print("{d}.{d}", .{ version.major, version.minor });
    } else {
        try writer.print("{d}.{d}.{d}", .{ version.major, version.minor, version.patch });
    }
}

pub fn zigTriple(self: Query, allocator: Allocator) Allocator.Error![]u8 {
    if (self.isNativeTriple())
        return allocator.dupe(u8, "native");

    const arch_name = if (self.cpu_arch) |arch| @tagName(arch) else "native";
    const os_name = if (self.os_tag) |os_tag| @tagName(os_tag) else "native";

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.writer().print("{s}-{s}", .{ arch_name, os_name });

    // The zig target syntax does not allow specifying a max os version with no min, so
    // if either are present, we need the min.
    if (self.os_version_min) |min| {
        switch (min) {
            .none => {},
            .semver => |v| {
                try result.writer().writeAll(".");
                try formatVersion(v, result.writer());
            },
            .windows => |v| {
                try result.writer().print("{s}", .{v});
            },
        }
    }
    if (self.os_version_max) |max| {
        switch (max) {
            .none => {},
            .semver => |v| {
                try result.writer().writeAll("...");
                try formatVersion(v, result.writer());
            },
            .windows => |v| {
                // This is counting on a custom format() function defined on `WindowsVersion`
                // to add a prefix '.' and make there be a total of three dots.
                try result.writer().print("..{s}", .{v});
            },
        }
    }

    if (self.glibc_version) |v| {
        const name = if (self.abi) |abi| @tagName(abi) else "gnu";
        try result.ensureUnusedCapacity(name.len + 2);
        result.appendAssumeCapacity('-');
        result.appendSliceAssumeCapacity(name);
        result.appendAssumeCapacity('.');
        try formatVersion(v, result.writer());
    } else if (self.android_api_level) |lvl| {
        const name = if (self.abi) |abi| @tagName(abi) else "android";
        try result.ensureUnusedCapacity(name.len + 2);
        result.appendAssumeCapacity('-');
        result.appendSliceAssumeCapacity(name);
        result.appendAssumeCapacity('.');
        try result.writer().print("{d}", .{lvl});
    } else if (self.abi) |abi| {
        const name = @tagName(abi);
        try result.ensureUnusedCapacity(name.len + 1);
        result.appendAssumeCapacity('-');
        result.appendSliceAssumeCapacity(name);
    }

    return result.toOwnedSlice();
}

/// Renders the query into a textual representation that can be parsed via the
/// `-mcpu` flag passed to the Zig compiler.
/// Appends the result to `buffer`.
pub fn serializeCpu(q: Query, buffer: *std.ArrayList(u8)) Allocator.Error!void {
    try buffer.ensureUnusedCapacity(8);
    switch (q.cpu_model) {
        .native => {
            buffer.appendSliceAssumeCapacity("native");
        },
        .baseline => {
            buffer.appendSliceAssumeCapacity("baseline");
        },
        .determined_by_arch_os => {
            if (q.cpu_arch == null) {
                buffer.appendSliceAssumeCapacity("native");
            } else {
                buffer.appendSliceAssumeCapacity("baseline");
            }
        },
        .explicit => |model| {
            try buffer.appendSlice(model.name);
        },
    }

    if (q.cpu_features_add.isEmpty() and q.cpu_features_sub.isEmpty()) {
        // The CPU name alone is sufficient.
        return;
    }

    const cpu_arch = q.cpu_arch orelse builtin.cpu.arch;
    const all_features = cpu_arch.allFeaturesList();

    for (all_features, 0..) |feature, i_usize| {
        const i: Target.Cpu.Feature.Set.Index = @intCast(i_usize);
        try buffer.ensureUnusedCapacity(feature.name.len + 1);
        if (q.cpu_features_sub.isEnabled(i)) {
            buffer.appendAssumeCapacity('-');
            buffer.appendSliceAssumeCapacity(feature.name);
        } else if (q.cpu_features_add.isEnabled(i)) {
            buffer.appendAssumeCapacity('+');
            buffer.appendSliceAssumeCapacity(feature.name);
        }
    }
}

pub fn serializeCpuAlloc(q: Query, ally: Allocator) Allocator.Error![]u8 {
    var buffer = std.ArrayList(u8).init(ally);
    try serializeCpu(q, &buffer);
    return buffer.toOwnedSlice();
}

pub fn allocDescription(self: Query, allocator: Allocator) ![]u8 {
    // TODO is there anything else worthy of the description that is not
    // already captured in the triple?
    return self.zigTriple(allocator);
}

pub fn setGnuLibCVersion(self: *Query, major: u32, minor: u32, patch: u32) void {
    self.glibc_version = SemanticVersion{ .major = major, .minor = minor, .patch = patch };
}

fn parseOs(result: *Query, diags: *ParseOptions.Diagnostics, text: []const u8) !void {
    var it = mem.splitScalar(u8, text, '.');
    const os_name = it.first();
    diags.os_name = os_name;
    const os_is_native = mem.eql(u8, os_name, "native");
    if (!os_is_native) {
        result.os_tag = std.meta.stringToEnum(Target.Os.Tag, os_name) orelse
            return error.UnknownOperatingSystem;
    }
    const tag = result.os_tag orelse builtin.os.tag;
    diags.os_tag = tag;

    const version_text = it.rest();
    if (version_text.len > 0) switch (tag.versionRangeTag()) {
        .none => return error.InvalidOperatingSystemVersion,
        .semver, .hurd, .linux => {
            var range_it = mem.splitSequence(u8, version_text, "...");
            result.os_version_min = .{
                .semver = parseVersion(range_it.first()) catch |err| switch (err) {
                    error.Overflow => return error.InvalidOperatingSystemVersion,
                    error.InvalidVersion => return error.InvalidOperatingSystemVersion,
                },
            };
            if (range_it.next()) |v| {
                result.os_version_max = .{
                    .semver = parseVersion(v) catch |err| switch (err) {
                        error.Overflow => return error.InvalidOperatingSystemVersion,
                        error.InvalidVersion => return error.InvalidOperatingSystemVersion,
                    },
                };
            }
        },
        .windows => {
            var range_it = mem.splitSequence(u8, version_text, "...");
            result.os_version_min = .{
                .windows = try Target.Os.WindowsVersion.parse(range_it.first()),
            };
            if (range_it.next()) |v| {
                result.os_version_max = .{
                    .windows = try Target.Os.WindowsVersion.parse(v),
                };
            }
        },
    };
}

pub fn eql(a: Query, b: Query) bool {
    if (a.cpu_arch != b.cpu_arch) return false;
    if (!a.cpu_model.eql(b.cpu_model)) return false;
    if (!a.cpu_features_add.eql(b.cpu_features_add)) return false;
    if (!a.cpu_features_sub.eql(b.cpu_features_sub)) return false;
    if (a.os_tag != b.os_tag) return false;
    if (!OsVersion.eqlOpt(a.os_version_min, b.os_version_min)) return false;
    if (!OsVersion.eqlOpt(a.os_version_max, b.os_version_max)) return false;
    if (!versionEqualOpt(a.glibc_version, b.glibc_version)) return false;
    if (a.android_api_level != b.android_api_level) return false;
    if (a.abi != b.abi) return false;
    if (!a.dynamic_linker.eql(b.dynamic_linker)) return false;
    if (a.ofmt != b.ofmt) return false;

    return true;
}

fn versionEqualOpt(a: ?SemanticVersion, b: ?SemanticVersion) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return SemanticVersion.order(a.?, b.?) == .eq;
}

const Query = @This();
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Target = std.Target;
const mem = std.mem;
const Allocator = std.mem.Allocator;

test parse {
    if (builtin.target.isGnuLibC()) {
        var query = try Query.parse(.{});
        query.setGnuLibCVersion(2, 1, 1);

        const text = try query.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);

        try std.testing.expectEqualSlices(u8, "native-native-gnu.2.1.1", text);
    }
    if (builtin.target.abi.isAndroid()) {
        var query = try Query.parse(.{});
        query.android_api_level = 30;

        const text = try query.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);

        try std.testing.expectEqualSlices(u8, "native-native-android.30", text);
    }
    {
        const query = try Query.parse(.{
            .arch_os_abi = "aarch64-linux",
            .cpu_features = "native",
        });

        try std.testing.expect(query.cpu_arch.? == .aarch64);
        try std.testing.expect(query.cpu_model == .native);
    }
    {
        const query = try Query.parse(.{ .arch_os_abi = "native" });

        try std.testing.expect(query.cpu_arch == null);
        try std.testing.expect(query.isNative());

        const text = try query.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "native", text);
    }
    {
        const query = try Query.parse(.{
            .arch_os_abi = "x86_64-linux-gnu",
            .cpu_features = "x86_64-sse-sse2-avx-cx8",
        });
        const target = try std.zig.system.resolveTargetQuery(query);

        try std.testing.expect(target.os.tag == .linux);
        try std.testing.expect(target.abi == .gnu);
        try std.testing.expect(target.cpu.arch == .x86_64);
        try std.testing.expect(!Target.x86.featureSetHas(target.cpu.features, .sse));
        try std.testing.expect(!Target.x86.featureSetHas(target.cpu.features, .avx));
        try std.testing.expect(!Target.x86.featureSetHas(target.cpu.features, .cx8));
        try std.testing.expect(Target.x86.featureSetHas(target.cpu.features, .cmov));
        try std.testing.expect(Target.x86.featureSetHas(target.cpu.features, .fxsr));

        try std.testing.expect(Target.x86.featureSetHasAny(target.cpu.features, .{ .sse, .avx, .cmov }));
        try std.testing.expect(!Target.x86.featureSetHasAny(target.cpu.features, .{ .sse, .avx }));
        try std.testing.expect(Target.x86.featureSetHasAll(target.cpu.features, .{ .mmx, .x87 }));
        try std.testing.expect(!Target.x86.featureSetHasAll(target.cpu.features, .{ .mmx, .x87, .sse }));

        const text = try query.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "x86_64-linux-gnu", text);
    }
    {
        const query = try Query.parse(.{
            .arch_os_abi = "arm-linux-musleabihf",
            .cpu_features = "generic+v8a",
        });
        const target = try std.zig.system.resolveTargetQuery(query);

        try std.testing.expect(target.os.tag == .linux);
        try std.testing.expect(target.abi == .musleabihf);
        try std.testing.expect(target.cpu.arch == .arm);
        try std.testing.expect(target.cpu.model == &Target.arm.cpu.generic);
        try std.testing.expect(Target.arm.featureSetHas(target.cpu.features, .v8a));

        const text = try query.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "arm-linux-musleabihf", text);
    }
    {
        const query = try Query.parse(.{
            .arch_os_abi = "aarch64-linux.3.10...4.4.1-gnu.2.27",
            .cpu_features = "generic+v8a",
        });
        const target = try std.zig.system.resolveTargetQuery(query);

        try std.testing.expect(target.cpu.arch == .aarch64);
        try std.testing.expect(target.os.tag == .linux);
        try std.testing.expect(target.os.version_range.linux.range.min.major == 3);
        try std.testing.expect(target.os.version_range.linux.range.min.minor == 10);
        try std.testing.expect(target.os.version_range.linux.range.min.patch == 0);
        try std.testing.expect(target.os.version_range.linux.range.max.major == 4);
        try std.testing.expect(target.os.version_range.linux.range.max.minor == 4);
        try std.testing.expect(target.os.version_range.linux.range.max.patch == 1);
        try std.testing.expect(target.os.version_range.linux.glibc.major == 2);
        try std.testing.expect(target.os.version_range.linux.glibc.minor == 27);
        try std.testing.expect(target.os.version_range.linux.glibc.patch == 0);
        try std.testing.expect(target.abi == .gnu);

        const text = try query.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "aarch64-linux.3.10...4.4.1-gnu.2.27", text);
    }
    {
        const query = try Query.parse(.{
            .arch_os_abi = "aarch64-linux.3.10...4.4.1-android.30",
        });
        const target = try std.zig.system.resolveTargetQuery(query);

        try std.testing.expect(target.cpu.arch == .aarch64);
        try std.testing.expect(target.os.tag == .linux);
        try std.testing.expect(target.os.version_range.linux.range.min.major == 3);
        try std.testing.expect(target.os.version_range.linux.range.min.minor == 10);
        try std.testing.expect(target.os.version_range.linux.range.min.patch == 0);
        try std.testing.expect(target.os.version_range.linux.range.max.major == 4);
        try std.testing.expect(target.os.version_range.linux.range.max.minor == 4);
        try std.testing.expect(target.os.version_range.linux.range.max.patch == 1);
        try std.testing.expect(target.os.version_range.linux.android == 30);
        try std.testing.expect(target.abi == .android);

        const text = try query.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "aarch64-linux.3.10...4.4.1-android.30", text);
    }
}
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    @"32bit",
    @"64bit",
    a,
    auipc_addi_fusion,
    b,
    c,
    conditional_cmv_fusion,
    d,
    disable_latency_sched_heuristic,
    dlen_factor_2,
    e,
    experimental,
    experimental_rvm23u32,
    experimental_sdext,
    experimental_sdtrig,
    experimental_smctr,
    experimental_ssctr,
    experimental_svukte,
    experimental_xqcia,
    experimental_xqciac,
    experimental_xqcicli,
    experimental_xqcicm,
    experimental_xqcics,
    experimental_xqcicsr,
    experimental_xqciint,
    experimental_xqcilo,
    experimental_xqcilsm,
    experimental_xqcisls,
    experimental_zalasr,
    experimental_zicfilp,
    experimental_zicfiss,
    experimental_zvbc32e,
    experimental_zvkgs,
    f,
    forced_atomics,
    h,
    i,
    ld_add_fusion,
    lui_addi_fusion,
    m,
    mips_p8700,
    no_default_unroll,
    no_rvc_hints,
    no_sink_splat_operands,
    no_trailing_seq_cst_fence,
    optimized_nf2_segment_load_store,
    optimized_nf3_segment_load_store,
    optimized_nf4_segment_load_store,
    optimized_nf5_segment_load_store,
    optimized_nf6_segment_load_store,
    optimized_nf7_segment_load_store,
    optimized_nf8_segment_load_store,
    optimized_zero_stride_load,
    predictable_select_expensive,
    prefer_w_inst,
    relax,
    reserve_x1,
    reserve_x10,
    reserve_x11,
    reserve_x12,
    reserve_x13,
    reserve_x14,
    reserve_x15,
    reserve_x16,
    reserve_x17,
    reserve_x18,
    reserve_x19,
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
    reserve_x29,
    reserve_x3,
    reserve_x30,
    reserve_x31,
    reserve_x4,
    reserve_x5,
    reserve_x6,
    reserve_x7,
    reserve_x8,
    reserve_x9,
    rva20s64,
    rva20u64,
    rva22s64,
    rva22u64,
    rva23s64,
    rva23u64,
    rvb23s64,
    rvb23u64,
    rvi20u32,
    rvi20u64,
    save_restore,
    sha,
    shcounterenw,
    shgatpa,
    shifted_zextw_fusion,
    short_forward_branch_opt,
    shtvala,
    shvsatpa,
    shvstvala,
    shvstvecd,
    smaia,
    smcdeleg,
    smcsrind,
    smdbltrp,
    smepmp,
    smmpm,
    smnpm,
    smrnmi,
    smstateen,
    ssaia,
    ssccfg,
    ssccptr,
    sscofpmf,
    sscounterenw,
    sscsrind,
    ssdbltrp,
    ssnpm,
    sspm,
    ssqosid,
    ssstateen,
    ssstrict,
    sstc,
    sstvala,
    sstvecd,
    ssu64xl,
    supm,
    svade,
    svadu,
    svbare,
    svinval,
    svnapot,
    svpbmt,
    svvptc,
    tagged_globals,
    unaligned_scalar_mem,
    unaligned_vector_mem,
    use_postra_scheduler,
    v,
    ventana_veyron,
    vxrm_pipeline_flush,
    xcvalu,
    xcvbi,
    xcvbitmanip,
    xcvelw,
    xcvmac,
    xcvmem,
    xcvsimd,
    xmipscmove,
    xmipslsp,
    xsfcease,
    xsfvcp,
    xsfvfnrclipxfqf,
    xsfvfwmaccqqq,
    xsfvqmaccdod,
    xsfvqmaccqoq,
    xsifivecdiscarddlone,
    xsifivecflushdlone,
    xtheadba,
    xtheadbb,
    xtheadbs,
    xtheadcmo,
    xtheadcondmov,
    xtheadfmemidx,
    xtheadmac,
    xtheadmemidx,
    xtheadmempair,
    xtheadsync,
    xtheadvdot,
    xventanacondops,
    xwchc,
    za128rs,
    za64rs,
    zaamo,
    zabha,
    zacas,
    zalrsc,
    zama16b,
    zawrs,
    zba,
    zbb,
    zbc,
    zbkb,
    zbkc,
    zbkx,
    zbs,
    zca,
    zcb,
    zcd,
    zce,
    zcf,
    zcmop,
    zcmp,
    zcmt,
    zdinx,
    zexth_fusion,
    zextw_fusion,
    zfa,
    zfbfmin,
    zfh,
    zfhmin,
    zfinx,
    zhinx,
    zhinxmin,
    zic64b,
    zicbom,
    zicbop,
    zicboz,
    ziccamoa,
    ziccif,
    zicclsm,
    ziccrse,
    zicntr,
    zicond,
    zicsr,
    zifencei,
    zihintntl,
    zihintpause,
    zihpm,
    zimop,
    zk,
    zkn,
    zknd,
    zkne,
    zknh,
    zkr,
    zks,
    zksed,
    zksh,
    zkt,
    zmmul,
    ztso,
    zvbb,
    zvbc,
    zve32f,
    zve32x,
    zve64d,
    zve64f,
    zve64x,
    zvfbfmin,
    zvfbfwma,
    zvfh,
    zvfhmin,
    zvkb,
    zvkg,
    zvkn,
    zvknc,
    zvkned,
    zvkng,
    zvknha,
    zvknhb,
    zvks,
    zvksc,
    zvksed,
    zvksg,
    zvksh,
    zvkt,
    zvl1024b,
    zvl128b,
    zvl16384b,
    zvl2048b,
    zvl256b,
    zvl32768b,
    zvl32b,
    zvl4096b,
    zvl512b,
    zvl64b,
    zvl65536b,
    zvl8192b,
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
    result[@intFromEnum(Feature.@"32bit")] = .{
        .llvm_name = "32bit",
        .description = "Implements RV32",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.@"64bit")] = .{
        .llvm_name = "64bit",
        .description = "Implements RV64",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.a)] = .{
        .llvm_name = "a",
        .description = "'A' (Atomic Instructions)",
        .dependencies = featureSet(&[_]Feature{
            .zaamo,
            .zalrsc,
        }),
    };
    result[@intFromEnum(Feature.auipc_addi_fusion)] = .{
        .llvm_name = "auipc-addi-fusion",
        .description = "Enable AUIPC+ADDI macrofusion",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.b)] = .{
        .llvm_name = "b",
        .description = "'B' (the collection of the Zba, Zbb, Zbs extensions)",
        .dependencies = featureSet(&[_]Feature{
            .zba,
            .zbb,
            .zbs,
        }),
    };
    result[@intFromEnum(Feature.c)] = .{
        .llvm_name = "c",
        .description = "'C' (Compressed Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.conditional_cmv_fusion)] = .{
        .llvm_name = "conditional-cmv-fusion",
        .description = "Enable branch+c.mv fusion",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.d)] = .{
        .llvm_name = "d",
        .description = "'D' (Double-Precision Floating-Point)",
        .dependencies = featureSet(&[_]Feature{
            .f,
        }),
    };
    result[@intFromEnum(Feature.disable_latency_sched_heuristic)] = .{
        .llvm_name = "disable-latency-sched-heuristic",
        .description = "Disable latency scheduling heuristic",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dlen_factor_2)] = .{
        .llvm_name = "dlen-factor-2",
        .description = "Vector unit DLEN(data path width) is half of VLEN",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.e)] = .{
        .llvm_name = "e",
        .description = "'E' (Embedded Instruction Set with 16 GPRs)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental)] = .{
        .llvm_name = "experimental",
        .description = "Experimental intrinsics",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_rvm23u32)] = .{
        .llvm_name = "experimental-rvm23u32",
        .description = "RISC-V experimental-rvm23u32 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"32bit",
            .b,
            .i,
            .m,
            .zce,
            .zcmop,
            .zicbop,
            .zicond,
            .zihintntl,
            .zihintpause,
            .zimop,
        }),
    };
    result[@intFromEnum(Feature.experimental_sdext)] = .{
        .llvm_name = "experimental-sdext",
        .description = "'Sdext' (External debugger)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_sdtrig)] = .{
        .llvm_name = "experimental-sdtrig",
        .description = "'Sdtrig' (Debugger triggers)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_smctr)] = .{
        .llvm_name = "experimental-smctr",
        .description = "'Smctr' (Control Transfer Records Machine Level)",
        .dependencies = featureSet(&[_]Feature{
            .sscsrind,
        }),
    };
    result[@intFromEnum(Feature.experimental_ssctr)] = .{
        .llvm_name = "experimental-ssctr",
        .description = "'Ssctr' (Control Transfer Records Supervisor Level)",
        .dependencies = featureSet(&[_]Feature{
            .sscsrind,
        }),
    };
    result[@intFromEnum(Feature.experimental_svukte)] = .{
        .llvm_name = "experimental-svukte",
        .description = "'Svukte' (Address-Independent Latency of User-Mode Faults to Supervisor Addresses)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_xqcia)] = .{
        .llvm_name = "experimental-xqcia",
        .description = "'Xqcia' (Qualcomm uC Arithmetic Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_xqciac)] = .{
        .llvm_name = "experimental-xqciac",
        .description = "'Xqciac' (Qualcomm uC Load-Store Address Calculation Extension)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
        }),
    };
    result[@intFromEnum(Feature.experimental_xqcicli)] = .{
        .llvm_name = "experimental-xqcicli",
        .description = "'Xqcicli' (Qualcomm uC Conditional Load Immediate Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_xqcicm)] = .{
        .llvm_name = "experimental-xqcicm",
        .description = "'Xqcicm' (Qualcomm uC Conditional Move Extension)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
        }),
    };
    result[@intFromEnum(Feature.experimental_xqcics)] = .{
        .llvm_name = "experimental-xqcics",
        .description = "'Xqcics' (Qualcomm uC Conditional Select Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_xqcicsr)] = .{
        .llvm_name = "experimental-xqcicsr",
        .description = "'Xqcicsr' (Qualcomm uC CSR Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_xqciint)] = .{
        .llvm_name = "experimental-xqciint",
        .description = "'Xqciint' (Qualcomm uC Interrupts Extension)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
        }),
    };
    result[@intFromEnum(Feature.experimental_xqcilo)] = .{
        .llvm_name = "experimental-xqcilo",
        .description = "'Xqcilo' (Qualcomm uC Large Offset Load Store Extension)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
        }),
    };
    result[@intFromEnum(Feature.experimental_xqcilsm)] = .{
        .llvm_name = "experimental-xqcilsm",
        .description = "'Xqcilsm' (Qualcomm uC Load Store Multiple Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_xqcisls)] = .{
        .llvm_name = "experimental-xqcisls",
        .description = "'Xqcisls' (Qualcomm uC Scaled Load Store Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_zalasr)] = .{
        .llvm_name = "experimental-zalasr",
        .description = "'Zalasr' (Load-Acquire and Store-Release Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.experimental_zicfilp)] = .{
        .llvm_name = "experimental-zicfilp",
        .description = "'Zicfilp' (Landing pad)",
        .dependencies = featureSet(&[_]Feature{
            .zicsr,
        }),
    };
    result[@intFromEnum(Feature.experimental_zicfiss)] = .{
        .llvm_name = "experimental-zicfiss",
        .description = "'Zicfiss' (Shadow stack)",
        .dependencies = featureSet(&[_]Feature{
            .zicsr,
            .zimop,
        }),
    };
    result[@intFromEnum(Feature.experimental_zvbc32e)] = .{
        .llvm_name = "experimental-zvbc32e",
        .description = "'Zvbc32e' (Vector Carryless Multiplication with 32-bits elements)",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.experimental_zvkgs)] = .{
        .llvm_name = "experimental-zvkgs",
        .description = "'Zvkgs' (Vector-Scalar GCM instructions for Cryptography)",
        .dependencies = featureSet(&[_]Feature{
            .zvkg,
        }),
    };
    result[@intFromEnum(Feature.f)] = .{
        .llvm_name = "f",
        .description = "'F' (Single-Precision Floating-Point)",
        .dependencies = featureSet(&[_]Feature{
            .zicsr,
        }),
    };
    result[@intFromEnum(Feature.forced_atomics)] = .{
        .llvm_name = "forced-atomics",
        .description = "Assume that lock-free native-width atomics are available",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.h)] = .{
        .llvm_name = "h",
        .description = "'H' (Hypervisor)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.i)] = .{
        .llvm_name = "i",
        .description = "'I' (Base Integer Instruction Set)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ld_add_fusion)] = .{
        .llvm_name = "ld-add-fusion",
        .description = "Enable LD+ADD macrofusion",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lui_addi_fusion)] = .{
        .llvm_name = "lui-addi-fusion",
        .description = "Enable LUI+ADDI macro fusion",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.m)] = .{
        .llvm_name = "m",
        .description = "'M' (Integer Multiplication and Division)",
        .dependencies = featureSet(&[_]Feature{
            .zmmul,
        }),
    };
    result[@intFromEnum(Feature.mips_p8700)] = .{
        .llvm_name = "mips-p8700",
        .description = "MIPS p8700 processor",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_default_unroll)] = .{
        .llvm_name = "no-default-unroll",
        .description = "Disable default unroll preference.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_rvc_hints)] = .{
        .llvm_name = "no-rvc-hints",
        .description = "Disable RVC Hint Instructions.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_sink_splat_operands)] = .{
        .llvm_name = "no-sink-splat-operands",
        .description = "Disable sink splat operands to enable .vx, .vf,.wx, and .wf instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_trailing_seq_cst_fence)] = .{
        .llvm_name = "no-trailing-seq-cst-fence",
        .description = "Disable trailing fence for seq-cst store.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_nf2_segment_load_store)] = .{
        .llvm_name = "optimized-nf2-segment-load-store",
        .description = "vlseg2eN.v and vsseg2eN.v areimplemented as a wide memory op and shuffle",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_nf3_segment_load_store)] = .{
        .llvm_name = "optimized-nf3-segment-load-store",
        .description = "vlseg3eN.v and vsseg3eN.v areimplemented as a wide memory op and shuffle",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_nf4_segment_load_store)] = .{
        .llvm_name = "optimized-nf4-segment-load-store",
        .description = "vlseg4eN.v and vsseg4eN.v areimplemented as a wide memory op and shuffle",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_nf5_segment_load_store)] = .{
        .llvm_name = "optimized-nf5-segment-load-store",
        .description = "vlseg5eN.v and vsseg5eN.v areimplemented as a wide memory op and shuffle",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_nf6_segment_load_store)] = .{
        .llvm_name = "optimized-nf6-segment-load-store",
        .description = "vlseg6eN.v and vsseg6eN.v areimplemented as a wide memory op and shuffle",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_nf7_segment_load_store)] = .{
        .llvm_name = "optimized-nf7-segment-load-store",
        .description = "vlseg7eN.v and vsseg7eN.v areimplemented as a wide memory op and shuffle",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_nf8_segment_load_store)] = .{
        .llvm_name = "optimized-nf8-segment-load-store",
        .description = "vlseg8eN.v and vsseg8eN.v areimplemented as a wide memory op and shuffle",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.optimized_zero_stride_load)] = .{
        .llvm_name = "optimized-zero-stride-load",
        .description = "Optimized (perform fewer memory operations)zero-stride vector load",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.predictable_select_expensive)] = .{
        .llvm_name = "predictable-select-expensive",
        .description = "Prefer likely predicted branches over selects",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prefer_w_inst)] = .{
        .llvm_name = "prefer-w-inst",
        .description = "Prefer instructions with W suffix",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.relax)] = .{
        .llvm_name = "relax",
        .description = "Enable Linker relaxation.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x1)] = .{
        .llvm_name = "reserve-x1",
        .description = "Reserve X1",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x10)] = .{
        .llvm_name = "reserve-x10",
        .description = "Reserve X10",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x11)] = .{
        .llvm_name = "reserve-x11",
        .description = "Reserve X11",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x12)] = .{
        .llvm_name = "reserve-x12",
        .description = "Reserve X12",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x13)] = .{
        .llvm_name = "reserve-x13",
        .description = "Reserve X13",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x14)] = .{
        .llvm_name = "reserve-x14",
        .description = "Reserve X14",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x15)] = .{
        .llvm_name = "reserve-x15",
        .description = "Reserve X15",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x16)] = .{
        .llvm_name = "reserve-x16",
        .description = "Reserve X16",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x17)] = .{
        .llvm_name = "reserve-x17",
        .description = "Reserve X17",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x18)] = .{
        .llvm_name = "reserve-x18",
        .description = "Reserve X18",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x19)] = .{
        .llvm_name = "reserve-x19",
        .description = "Reserve X19",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x2)] = .{
        .llvm_name = "reserve-x2",
        .description = "Reserve X2",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x20)] = .{
        .llvm_name = "reserve-x20",
        .description = "Reserve X20",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x21)] = .{
        .llvm_name = "reserve-x21",
        .description = "Reserve X21",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x22)] = .{
        .llvm_name = "reserve-x22",
        .description = "Reserve X22",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x23)] = .{
        .llvm_name = "reserve-x23",
        .description = "Reserve X23",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x24)] = .{
        .llvm_name = "reserve-x24",
        .description = "Reserve X24",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x25)] = .{
        .llvm_name = "reserve-x25",
        .description = "Reserve X25",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x26)] = .{
        .llvm_name = "reserve-x26",
        .description = "Reserve X26",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x27)] = .{
        .llvm_name = "reserve-x27",
        .description = "Reserve X27",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x28)] = .{
        .llvm_name = "reserve-x28",
        .description = "Reserve X28",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x29)] = .{
        .llvm_name = "reserve-x29",
        .description = "Reserve X29",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x3)] = .{
        .llvm_name = "reserve-x3",
        .description = "Reserve X3",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x30)] = .{
        .llvm_name = "reserve-x30",
        .description = "Reserve X30",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x31)] = .{
        .llvm_name = "reserve-x31",
        .description = "Reserve X31",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x4)] = .{
        .llvm_name = "reserve-x4",
        .description = "Reserve X4",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x5)] = .{
        .llvm_name = "reserve-x5",
        .description = "Reserve X5",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x6)] = .{
        .llvm_name = "reserve-x6",
        .description = "Reserve X6",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x7)] = .{
        .llvm_name = "reserve-x7",
        .description = "Reserve X7",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x8)] = .{
        .llvm_name = "reserve-x8",
        .description = "Reserve X8",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x9)] = .{
        .llvm_name = "reserve-x9",
        .description = "Reserve X9",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rva20s64)] = .{
        .llvm_name = "rva20s64",
        .description = "RISC-V rva20s64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .ssccptr,
            .sstvala,
            .sstvecd,
            .svade,
            .svbare,
            .za128rs,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
            .zifencei,
        }),
    };
    result[@intFromEnum(Feature.rva20u64)] = .{
        .llvm_name = "rva20u64",
        .description = "RISC-V rva20u64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .za128rs,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
        }),
    };
    result[@intFromEnum(Feature.rva22s64)] = .{
        .llvm_name = "rva22s64",
        .description = "RISC-V rva22s64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .d,
            .i,
            .m,
            .ssccptr,
            .sscounterenw,
            .sstvala,
            .sstvecd,
            .svade,
            .svbare,
            .svinval,
            .svpbmt,
            .za64rs,
            .zfhmin,
            .zic64b,
            .zicbom,
            .zicbop,
            .zicboz,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
            .zifencei,
            .zihintpause,
            .zihpm,
            .zkt,
        }),
    };
    result[@intFromEnum(Feature.rva22u64)] = .{
        .llvm_name = "rva22u64",
        .description = "RISC-V rva22u64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .d,
            .i,
            .m,
            .za64rs,
            .zfhmin,
            .zic64b,
            .zicbom,
            .zicbop,
            .zicboz,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
            .zihintpause,
            .zihpm,
            .zkt,
        }),
    };
    result[@intFromEnum(Feature.rva23s64)] = .{
        .llvm_name = "rva23s64",
        .description = "RISC-V rva23s64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .i,
            .m,
            .sha,
            .ssccptr,
            .sscofpmf,
            .sscounterenw,
            .ssnpm,
            .sstc,
            .sstvala,
            .sstvecd,
            .ssu64xl,
            .supm,
            .svade,
            .svbare,
            .svinval,
            .svnapot,
            .svpbmt,
            .v,
            .za64rs,
            .zawrs,
            .zcb,
            .zcmop,
            .zfa,
            .zfhmin,
            .zic64b,
            .zicbom,
            .zicbop,
            .zicboz,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
            .zicond,
            .zifencei,
            .zihintntl,
            .zihintpause,
            .zihpm,
            .zimop,
            .zkt,
            .zvbb,
            .zvfhmin,
            .zvkt,
        }),
    };
    result[@intFromEnum(Feature.rva23u64)] = .{
        .llvm_name = "rva23u64",
        .description = "RISC-V rva23u64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .i,
            .m,
            .supm,
            .v,
            .za64rs,
            .zawrs,
            .zcb,
            .zcmop,
            .zfa,
            .zfhmin,
            .zic64b,
            .zicbom,
            .zicbop,
            .zicboz,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
            .zicond,
            .zihintntl,
            .zihintpause,
            .zihpm,
            .zimop,
            .zkt,
            .zvbb,
            .zvfhmin,
            .zvkt,
        }),
    };
    result[@intFromEnum(Feature.rvb23s64)] = .{
        .llvm_name = "rvb23s64",
        .description = "RISC-V rvb23s64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .d,
            .i,
            .m,
            .ssccptr,
            .sscofpmf,
            .sscounterenw,
            .sstc,
            .sstvala,
            .sstvecd,
            .ssu64xl,
            .svade,
            .svbare,
            .svinval,
            .svnapot,
            .svpbmt,
            .za64rs,
            .zawrs,
            .zcb,
            .zcmop,
            .zfa,
            .zic64b,
            .zicbom,
            .zicbop,
            .zicboz,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
            .zicond,
            .zifencei,
            .zihintntl,
            .zihintpause,
            .zihpm,
            .zimop,
            .zkt,
        }),
    };
    result[@intFromEnum(Feature.rvb23u64)] = .{
        .llvm_name = "rvb23u64",
        .description = "RISC-V rvb23u64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .d,
            .i,
            .m,
            .za64rs,
            .zawrs,
            .zcb,
            .zcmop,
            .zfa,
            .zic64b,
            .zicbom,
            .zicbop,
            .zicboz,
            .ziccamoa,
            .ziccif,
            .zicclsm,
            .ziccrse,
            .zicntr,
            .zicond,
            .zihintntl,
            .zihintpause,
            .zihpm,
            .zimop,
            .zkt,
        }),
    };
    result[@intFromEnum(Feature.rvi20u32)] = .{
        .llvm_name = "rvi20u32",
        .description = "RISC-V rvi20u32 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"32bit",
            .i,
        }),
    };
    result[@intFromEnum(Feature.rvi20u64)] = .{
        .llvm_name = "rvi20u64",
        .description = "RISC-V rvi20u64 profile",
        .dependencies = featureSet(&[_]Feature{
            .@"64bit",
            .i,
        }),
    };
    result[@intFromEnum(Feature.save_restore)] = .{
        .llvm_name = "save-restore",
        .description = "Enable save/restore.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sha)] = .{
        .llvm_name = "sha",
        .description = "'Sha' (Augmented Hypervisor)",
        .dependencies = featureSet(&[_]Feature{
            .h,
            .shcounterenw,
            .shgatpa,
            .shtvala,
            .shvsatpa,
            .shvstvala,
            .shvstvecd,
            .ssstateen,
        }),
    };
    result[@intFromEnum(Feature.shcounterenw)] = .{
        .llvm_name = "shcounterenw",
        .description = "'Shcounterenw' (Support writeable hcounteren enable bit for any hpmcounter that is not read-only zero)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shgatpa)] = .{
        .llvm_name = "shgatpa",
        .description = "'Shgatpa' (SvNNx4 mode supported for all modes supported by satp, as well as Bare)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shifted_zextw_fusion)] = .{
        .llvm_name = "shifted-zextw-fusion",
        .description = "Enable SLLI+SRLI to be fused when computing (shifted) word zero extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.short_forward_branch_opt)] = .{
        .llvm_name = "short-forward-branch-opt",
        .description = "Enable short forward branch optimization",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shtvala)] = .{
        .llvm_name = "shtvala",
        .description = "'Shtvala' (htval provides all needed values)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shvsatpa)] = .{
        .llvm_name = "shvsatpa",
        .description = "'Shvsatpa' (vsatp supports all modes supported by satp)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shvstvala)] = .{
        .llvm_name = "shvstvala",
        .description = "'Shvstvala' (vstval provides all needed values)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shvstvecd)] = .{
        .llvm_name = "shvstvecd",
        .description = "'Shvstvecd' (vstvec supports Direct mode)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smaia)] = .{
        .llvm_name = "smaia",
        .description = "'Smaia' (Advanced Interrupt Architecture Machine Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smcdeleg)] = .{
        .llvm_name = "smcdeleg",
        .description = "'Smcdeleg' (Counter Delegation Machine Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smcsrind)] = .{
        .llvm_name = "smcsrind",
        .description = "'Smcsrind' (Indirect CSR Access Machine Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smdbltrp)] = .{
        .llvm_name = "smdbltrp",
        .description = "'Smdbltrp' (Double Trap Machine Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smepmp)] = .{
        .llvm_name = "smepmp",
        .description = "'Smepmp' (Enhanced Physical Memory Protection)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smmpm)] = .{
        .llvm_name = "smmpm",
        .description = "'Smmpm' (Machine-level Pointer Masking for M-mode)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smnpm)] = .{
        .llvm_name = "smnpm",
        .description = "'Smnpm' (Machine-level Pointer Masking for next lower privilege mode)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smrnmi)] = .{
        .llvm_name = "smrnmi",
        .description = "'Smrnmi' (Resumable Non-Maskable Interrupts)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smstateen)] = .{
        .llvm_name = "smstateen",
        .description = "'Smstateen' (Machine-mode view of the state-enable extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssaia)] = .{
        .llvm_name = "ssaia",
        .description = "'Ssaia' (Advanced Interrupt Architecture Supervisor Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssccfg)] = .{
        .llvm_name = "ssccfg",
        .description = "'Ssccfg' (Counter Configuration Supervisor Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssccptr)] = .{
        .llvm_name = "ssccptr",
        .description = "'Ssccptr' (Main memory supports page table reads)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sscofpmf)] = .{
        .llvm_name = "sscofpmf",
        .description = "'Sscofpmf' (Count Overflow and Mode-Based Filtering)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sscounterenw)] = .{
        .llvm_name = "sscounterenw",
        .description = "'Sscounterenw' (Support writeable scounteren enable bit for any hpmcounter that is not read-only zero)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sscsrind)] = .{
        .llvm_name = "sscsrind",
        .description = "'Sscsrind' (Indirect CSR Access Supervisor Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssdbltrp)] = .{
        .llvm_name = "ssdbltrp",
        .description = "'Ssdbltrp' (Double Trap Supervisor Level)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssnpm)] = .{
        .llvm_name = "ssnpm",
        .description = "'Ssnpm' (Supervisor-level Pointer Masking for next lower privilege mode)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sspm)] = .{
        .llvm_name = "sspm",
        .description = "'Sspm' (Indicates Supervisor-mode Pointer Masking)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssqosid)] = .{
        .llvm_name = "ssqosid",
        .description = "'Ssqosid' (Quality-of-Service (QoS) Identifiers)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssstateen)] = .{
        .llvm_name = "ssstateen",
        .description = "'Ssstateen' (Supervisor-mode view of the state-enable extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssstrict)] = .{
        .llvm_name = "ssstrict",
        .description = "'Ssstrict' (No non-conforming extensions are present)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sstc)] = .{
        .llvm_name = "sstc",
        .description = "'Sstc' (Supervisor-mode timer interrupts)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sstvala)] = .{
        .llvm_name = "sstvala",
        .description = "'Sstvala' (stval provides all needed values)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sstvecd)] = .{
        .llvm_name = "sstvecd",
        .description = "'Sstvecd' (stvec supports Direct mode)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssu64xl)] = .{
        .llvm_name = "ssu64xl",
        .description = "'Ssu64xl' (UXLEN=64 supported)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.supm)] = .{
        .llvm_name = "supm",
        .description = "'Supm' (Indicates User-mode Pointer Masking)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.svade)] = .{
        .llvm_name = "svade",
        .description = "'Svade' (Raise exceptions on improper A/D bits)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.svadu)] = .{
        .llvm_name = "svadu",
        .description = "'Svadu' (Hardware A/D updates)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.svbare)] = .{
        .llvm_name = "svbare",
        .description = "'Svbare' (satp mode Bare supported)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.svinval)] = .{
        .llvm_name = "svinval",
        .description = "'Svinval' (Fine-Grained Address-Translation Cache Invalidation)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.svnapot)] = .{
        .llvm_name = "svnapot",
        .description = "'Svnapot' (NAPOT Translation Contiguity)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.svpbmt)] = .{
        .llvm_name = "svpbmt",
        .description = "'Svpbmt' (Page-Based Memory Types)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.svvptc)] = .{
        .llvm_name = "svvptc",
        .description = "'Svvptc' (Obviating Memory-Management Instructions after Marking PTEs Valid)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tagged_globals)] = .{
        .llvm_name = "tagged-globals",
        .description = "Use an instruction sequence for taking the address of a global that allows a memory tag in the upper address bits",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unaligned_scalar_mem)] = .{
        .llvm_name = "unaligned-scalar-mem",
        .description = "Has reasonably performant unaligned scalar loads and stores",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unaligned_vector_mem)] = .{
        .llvm_name = "unaligned-vector-mem",
        .description = "Has reasonably performant unaligned vector loads and stores",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_postra_scheduler)] = .{
        .llvm_name = "use-postra-scheduler",
        .description = "Schedule again after register allocation",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v)] = .{
        .llvm_name = "v",
        .description = "'V' (Vector Extension for Application Processors)",
        .dependencies = featureSet(&[_]Feature{
            .zve64d,
            .zvl128b,
        }),
    };
    result[@intFromEnum(Feature.ventana_veyron)] = .{
        .llvm_name = "ventana-veyron",
        .description = "Ventana Veyron-Series processors",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vxrm_pipeline_flush)] = .{
        .llvm_name = "vxrm-pipeline-flush",
        .description = "VXRM writes causes pipeline flush",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xcvalu)] = .{
        .llvm_name = "xcvalu",
        .description = "'XCValu' (CORE-V ALU Operations)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xcvbi)] = .{
        .llvm_name = "xcvbi",
        .description = "'XCVbi' (CORE-V Immediate Branching)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xcvbitmanip)] = .{
        .llvm_name = "xcvbitmanip",
        .description = "'XCVbitmanip' (CORE-V Bit Manipulation)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xcvelw)] = .{
        .llvm_name = "xcvelw",
        .description = "'XCVelw' (CORE-V Event Load Word)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xcvmac)] = .{
        .llvm_name = "xcvmac",
        .description = "'XCVmac' (CORE-V Multiply-Accumulate)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xcvmem)] = .{
        .llvm_name = "xcvmem",
        .description = "'XCVmem' (CORE-V Post-incrementing Load & Store)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xcvsimd)] = .{
        .llvm_name = "xcvsimd",
        .description = "'XCVsimd' (CORE-V SIMD ALU)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xmipscmove)] = .{
        .llvm_name = "xmipscmove",
        .description = "'XMIPSCMove' (MIPS conditional move instruction(s) (ccmov))",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xmipslsp)] = .{
        .llvm_name = "xmipslsp",
        .description = "'XMIPSLSP' (MIPS optimization for hardware load-store bonding)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xsfcease)] = .{
        .llvm_name = "xsfcease",
        .description = "'XSfcease' (SiFive sf.cease Instruction)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xsfvcp)] = .{
        .llvm_name = "xsfvcp",
        .description = "'XSfvcp' (SiFive Custom Vector Coprocessor Interface Instructions)",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.xsfvfnrclipxfqf)] = .{
        .llvm_name = "xsfvfnrclipxfqf",
        .description = "'XSfvfnrclipxfqf' (SiFive FP32-to-int8 Ranged Clip Instructions)",
        .dependencies = featureSet(&[_]Feature{
            .zve32f,
        }),
    };
    result[@intFromEnum(Feature.xsfvfwmaccqqq)] = .{
        .llvm_name = "xsfvfwmaccqqq",
        .description = "'XSfvfwmaccqqq' (SiFive Matrix Multiply Accumulate Instruction and 4-by-4))",
        .dependencies = featureSet(&[_]Feature{
            .zvfbfmin,
        }),
    };
    result[@intFromEnum(Feature.xsfvqmaccdod)] = .{
        .llvm_name = "xsfvqmaccdod",
        .description = "'XSfvqmaccdod' (SiFive Int8 Matrix Multiplication Instructions (2-by-8 and 8-by-2))",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.xsfvqmaccqoq)] = .{
        .llvm_name = "xsfvqmaccqoq",
        .description = "'XSfvqmaccqoq' (SiFive Int8 Matrix Multiplication Instructions (4-by-8 and 8-by-4))",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.xsifivecdiscarddlone)] = .{
        .llvm_name = "xsifivecdiscarddlone",
        .description = "'XSiFivecdiscarddlone' (SiFive sf.cdiscard.d.l1 Instruction)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xsifivecflushdlone)] = .{
        .llvm_name = "xsifivecflushdlone",
        .description = "'XSiFivecflushdlone' (SiFive sf.cflush.d.l1 Instruction)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadba)] = .{
        .llvm_name = "xtheadba",
        .description = "'XTHeadBa' (T-Head address calculation instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadbb)] = .{
        .llvm_name = "xtheadbb",
        .description = "'XTHeadBb' (T-Head basic bit-manipulation instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadbs)] = .{
        .llvm_name = "xtheadbs",
        .description = "'XTHeadBs' (T-Head single-bit instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadcmo)] = .{
        .llvm_name = "xtheadcmo",
        .description = "'XTHeadCmo' (T-Head cache management instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadcondmov)] = .{
        .llvm_name = "xtheadcondmov",
        .description = "'XTHeadCondMov' (T-Head conditional move instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadfmemidx)] = .{
        .llvm_name = "xtheadfmemidx",
        .description = "'XTHeadFMemIdx' (T-Head FP Indexed Memory Operations)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadmac)] = .{
        .llvm_name = "xtheadmac",
        .description = "'XTHeadMac' (T-Head Multiply-Accumulate Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadmemidx)] = .{
        .llvm_name = "xtheadmemidx",
        .description = "'XTHeadMemIdx' (T-Head Indexed Memory Operations)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadmempair)] = .{
        .llvm_name = "xtheadmempair",
        .description = "'XTHeadMemPair' (T-Head two-GPR Memory Operations)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadsync)] = .{
        .llvm_name = "xtheadsync",
        .description = "'XTHeadSync' (T-Head multicore synchronization instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xtheadvdot)] = .{
        .llvm_name = "xtheadvdot",
        .description = "'XTHeadVdot' (T-Head Vector Extensions for Dot)",
        .dependencies = featureSet(&[_]Feature{
            .v,
        }),
    };
    result[@intFromEnum(Feature.xventanacondops)] = .{
        .llvm_name = "xventanacondops",
        .description = "'XVentanaCondOps' (Ventana Conditional Ops)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xwchc)] = .{
        .llvm_name = "xwchc",
        .description = "'Xwchc' (WCH/QingKe additional compressed opcodes)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.za128rs)] = .{
        .llvm_name = "za128rs",
        .description = "'Za128rs' (Reservation Set Size of at Most 128 Bytes)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.za64rs)] = .{
        .llvm_name = "za64rs",
        .description = "'Za64rs' (Reservation Set Size of at Most 64 Bytes)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zaamo)] = .{
        .llvm_name = "zaamo",
        .description = "'Zaamo' (Atomic Memory Operations)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zabha)] = .{
        .llvm_name = "zabha",
        .description = "'Zabha' (Byte and Halfword Atomic Memory Operations)",
        .dependencies = featureSet(&[_]Feature{
            .zaamo,
        }),
    };
    result[@intFromEnum(Feature.zacas)] = .{
        .llvm_name = "zacas",
        .description = "'Zacas' (Atomic Compare-And-Swap Instructions)",
        .dependencies = featureSet(&[_]Featur```
