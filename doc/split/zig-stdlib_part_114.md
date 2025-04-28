```
1,
            .fpuv2_df,
            .fpuv2_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdspv1,
        }),
    };
    pub const ck810et: CpuModel = .{
        .name = "ck810et",
        .llvm_name = "ck810et",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .dsp1e2,
            .dspe60,
            .edsp,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const ck810etv: CpuModel = .{
        .name = "ck810etv",
        .llvm_name = "ck810etv",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .ck810v,
            .dsp1e2,
            .dspe60,
            .edsp,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdspv1,
        }),
    };
    pub const ck810ev: CpuModel = .{
        .name = "ck810ev",
        .llvm_name = "ck810ev",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .ck810v,
            .dsp1e2,
            .dspe60,
            .edsp,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdspv1,
        }),
    };
    pub const ck810f: CpuModel = .{
        .name = "ck810f",
        .llvm_name = "ck810f",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .dsp1e2,
            .dspe60,
            .edsp,
            .fdivdu,
            .float1e2,
            .floate1,
            .fpuv2_df,
            .fpuv2_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const ck810ft: CpuModel = .{
        .name = "ck810ft",
        .llvm_name = "ck810ft",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .dsp1e2,
            .dspe60,
            .edsp,
            .fdivdu,
            .float1e2,
            .floate1,
            .fpuv2_df,
            .fpuv2_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const ck810ftv: CpuModel = .{
        .name = "ck810ftv",
        .llvm_name = "ck810ftv",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .ck810v,
            .dsp1e2,
            .dspe60,
            .edsp,
            .fdivdu,
            .float1e2,
            .floate1,
            .fpuv2_df,
            .fpuv2_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdspv1,
        }),
    };
    pub const ck810fv: CpuModel = .{
        .name = "ck810fv",
        .llvm_name = "ck810fv",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .ck810v,
            .dsp1e2,
            .dspe60,
            .edsp,
            .fdivdu,
            .float1e2,
            .floate1,
            .fpuv2_df,
            .fpuv2_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdspv1,
        }),
    };
    pub const ck810t: CpuModel = .{
        .name = "ck810t",
        .llvm_name = "ck810t",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .dsp1e2,
            .dspe60,
            .edsp,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const ck810tv: CpuModel = .{
        .name = "ck810tv",
        .llvm_name = "ck810tv",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .ck810v,
            .dsp1e2,
            .dspe60,
            .edsp,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdspv1,
        }),
    };
    pub const ck810v: CpuModel = .{
        .name = "ck810v",
        .llvm_name = "ck810v",
        .features = featureSet(&[_]Feature{
            .@"7e10",
            .cache,
            .ck810,
            .ck810v,
            .dsp1e2,
            .dspe60,
            .edsp,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdspv1,
        }),
    };
    pub const ck860: CpuModel = .{
        .name = "ck860",
        .llvm_name = "ck860",
        .features = featureSet(&[_]Feature{
            .@"10e60",
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .cache,
            .ck860,
            .dspe60,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const ck860f: CpuModel = .{
        .name = "ck860f",
        .llvm_name = "ck860f",
        .features = featureSet(&[_]Feature{
            .@"10e60",
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .cache,
            .ck860,
            .dspe60,
            .float7e60,
            .fpuv3_df,
            .fpuv3_hf,
            .fpuv3_hi,
            .fpuv3_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const ck860fv: CpuModel = .{
        .name = "ck860fv",
        .llvm_name = "ck860fv",
        .features = featureSet(&[_]Feature{
            .@"10e60",
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .cache,
            .ck860,
            .ck860v,
            .dspe60,
            .float7e60,
            .fpuv3_df,
            .fpuv3_hf,
            .fpuv3_hi,
            .fpuv3_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdsp2e60f,
            .vdspv2,
        }),
    };
    pub const ck860v: CpuModel = .{
        .name = "ck860v",
        .llvm_name = "ck860v",
        .features = featureSet(&[_]Feature{
            .@"10e60",
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .cache,
            .ck860,
            .ck860v,
            .dspe60,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
            .vdsp2e60f,
            .vdspv2,
        }),
    };
    pub const e801: CpuModel = .{
        .name = "e801",
        .llvm_name = "e801",
        .features = featureSet(&[_]Feature{
            .btst16,
            .ck801,
            .e1,
            .trust,
        }),
    };
    pub const e802: CpuModel = .{
        .name = "e802",
        .llvm_name = "e802",
        .features = featureSet(&[_]Feature{
            .btst16,
            .ck802,
            .e2,
            .nvic,
            .trust,
        }),
    };
    pub const e802t: CpuModel = .{
        .name = "e802t",
        .llvm_name = "e802t",
        .features = featureSet(&[_]Feature{
            .btst16,
            .ck802,
            .e2,
            .nvic,
            .trust,
        }),
    };
    pub const e803: CpuModel = .{
        .name = "e803",
        .llvm_name = "e803",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const e803t: CpuModel = .{
        .name = "e803t",
        .llvm_name = "e803t",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const e804d: CpuModel = .{
        .name = "e804d",
        .llvm_name = "e804d",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck804,
            .dspv2,
            .high_registers,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const e804df: CpuModel = .{
        .name = "e804df",
        .llvm_name = "e804df",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck804,
            .dspv2,
            .float1e3,
            .floate1,
            .fpuv2_sf,
            .high_registers,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const e804dft: CpuModel = .{
        .name = "e804dft",
        .llvm_name = "e804dft",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck804,
            .dspv2,
            .float1e3,
            .floate1,
            .fpuv2_sf,
            .high_registers,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const e804dt: CpuModel = .{
        .name = "e804dt",
        .llvm_name = "e804dt",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck804,
            .dspv2,
            .high_registers,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const e804f: CpuModel = .{
        .name = "e804f",
        .llvm_name = "e804f",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck804,
            .float1e3,
            .floate1,
            .fpuv2_sf,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const e804ft: CpuModel = .{
        .name = "e804ft",
        .llvm_name = "e804ft",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck804,
            .float1e3,
            .floate1,
            .fpuv2_sf,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .btst16,
        }),
    };
    pub const @"i805": CpuModel = .{
        .name = "i805",
        .llvm_name = "i805",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck805,
            .high_registers,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
            .vdsp2e3,
            .vdspv2,
        }),
    };
    pub const i805f: CpuModel = .{
        .name = "i805f",
        .llvm_name = "i805f",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .ck805,
            .float1e3,
            .floate1,
            .fpuv2_sf,
            .high_registers,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
            .vdsp2e3,
            .vdspv2,
        }),
    };
    pub const r807: CpuModel = .{
        .name = "r807",
        .llvm_name = "r807",
        .features = featureSet(&[_]Feature{
            .cache,
            .ck807,
            .dsp1e2,
            .dspe60,
            .edsp,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const r807f: CpuModel = .{
        .name = "r807f",
        .llvm_name = "r807f",
        .features = featureSet(&[_]Feature{
            .cache,
            .ck807,
            .dsp1e2,
            .dspe60,
            .edsp,
            .fdivdu,
            .float1e2,
            .float1e3,
            .float3e4,
            .floate1,
            .fpuv2_df,
            .fpuv2_sf,
            .hard_tp,
            .high_registers,
            .hwdiv,
            .mp,
            .mp1e2,
            .nvic,
            .trust,
        }),
    };
    pub const s802: CpuModel = .{
        .name = "s802",
        .llvm_name = "s802",
        .features = featureSet(&[_]Feature{
            .btst16,
            .ck802,
            .e2,
            .nvic,
            .trust,
        }),
    };
    pub const s802t: CpuModel = .{
        .name = "s802t",
        .llvm_name = "s802t",
        .features = featureSet(&[_]Feature{
            .btst16,
            .ck802,
            .e2,
            .nvic,
            .trust,
        }),
    };
    pub const s803: CpuModel = .{
        .name = "s803",
        .llvm_name = "s803",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
    pub const s803t: CpuModel = .{
        .name = "s803t",
        .llvm_name = "s803t",
        .features = featureSet(&[_]Feature{
            .@"3e3r2",
            .@"3e3r3",
            .btst16,
            .ck803,
            .hwdiv,
            .mp,
            .nvic,
            .trust,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    audio,
    cabac,
    compound,
    duplex,
    hvx,
    hvx_ieee_fp,
    hvx_length128b,
    hvx_length64b,
    hvx_qfloat,
    hvxv60,
    hvxv62,
    hvxv65,
    hvxv66,
    hvxv67,
    hvxv68,
    hvxv69,
    hvxv71,
    hvxv73,
    hvxv75,
    hvxv79,
    long_calls,
    mem_noshuf,
    memops,
    noreturn_stack_elim,
    nvj,
    nvs,
    packets,
    prev65,
    reserved_r19,
    small_data,
    tinycore,
    unsafe_fp,
    v5,
    v55,
    v60,
    v62,
    v65,
    v66,
    v67,
    v68,
    v69,
    v71,
    v73,
    v75,
    v79,
    zreg,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.audio)] = .{
        .llvm_name = "audio",
        .description = "Hexagon Audio extension instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cabac)] = .{
        .llvm_name = "cabac",
        .description = "Emit the CABAC instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.compound)] = .{
        .llvm_name = "compound",
        .description = "Use compound instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.duplex)] = .{
        .llvm_name = "duplex",
        .description = "Enable generation of duplex instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hvx)] = .{
        .llvm_name = "hvx",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hvx_ieee_fp)] = .{
        .llvm_name = "hvx-ieee-fp",
        .description = "Hexagon HVX IEEE floating point instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hvx_length128b)] = .{
        .llvm_name = "hvx-length128b",
        .description = "Hexagon HVX 128B instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvx,
        }),
    };
    result[@intFromEnum(Feature.hvx_length64b)] = .{
        .llvm_name = "hvx-length64b",
        .description = "Hexagon HVX 64B instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvx,
        }),
    };
    result[@intFromEnum(Feature.hvx_qfloat)] = .{
        .llvm_name = "hvx-qfloat",
        .description = "Hexagon HVX QFloating point instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hvxv60)] = .{
        .llvm_name = "hvxv60",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvx,
        }),
    };
    result[@intFromEnum(Feature.hvxv62)] = .{
        .llvm_name = "hvxv62",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv60,
        }),
    };
    result[@intFromEnum(Feature.hvxv65)] = .{
        .llvm_name = "hvxv65",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv62,
        }),
    };
    result[@intFromEnum(Feature.hvxv66)] = .{
        .llvm_name = "hvxv66",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv65,
            .zreg,
        }),
    };
    result[@intFromEnum(Feature.hvxv67)] = .{
        .llvm_name = "hvxv67",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv66,
        }),
    };
    result[@intFromEnum(Feature.hvxv68)] = .{
        .llvm_name = "hvxv68",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv67,
        }),
    };
    result[@intFromEnum(Feature.hvxv69)] = .{
        .llvm_name = "hvxv69",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv68,
        }),
    };
    result[@intFromEnum(Feature.hvxv71)] = .{
        .llvm_name = "hvxv71",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv69,
        }),
    };
    result[@intFromEnum(Feature.hvxv73)] = .{
        .llvm_name = "hvxv73",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv71,
        }),
    };
    result[@intFromEnum(Feature.hvxv75)] = .{
        .llvm_name = "hvxv75",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv73,
        }),
    };
    result[@intFromEnum(Feature.hvxv79)] = .{
        .llvm_name = "hvxv79",
        .description = "Hexagon HVX instructions",
        .dependencies = featureSet(&[_]Feature{
            .hvxv75,
        }),
    };
    result[@intFromEnum(Feature.long_calls)] = .{
        .llvm_name = "long-calls",
        .description = "Use constant-extended calls",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mem_noshuf)] = .{
        .llvm_name = "mem_noshuf",
        .description = "Supports mem_noshuf feature",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.memops)] = .{
        .llvm_name = "memops",
        .description = "Use memop instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.noreturn_stack_elim)] = .{
        .llvm_name = "noreturn-stack-elim",
        .description = "Eliminate stack allocation in a noreturn function when possible",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nvj)] = .{
        .llvm_name = "nvj",
        .description = "Support for new-value jumps",
        .dependencies = featureSet(&[_]Feature{
            .packets,
        }),
    };
    result[@intFromEnum(Feature.nvs)] = .{
        .llvm_name = "nvs",
        .description = "Support for new-value stores",
        .dependencies = featureSet(&[_]Feature{
            .packets,
        }),
    };
    result[@intFromEnum(Feature.packets)] = .{
        .llvm_name = "packets",
        .description = "Support for instruction packets",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prev65)] = .{
        .llvm_name = "prev65",
        .description = "Support features deprecated in v65",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserved_r19)] = .{
        .llvm_name = "reserved-r19",
        .description = "Reserve register R19",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.small_data)] = .{
        .llvm_name = "small-data",
        .description = "Allow GP-relative addressing of global variables",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tinycore)] = .{
        .llvm_name = "tinycore",
        .description = "Hexagon Tiny Core",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unsafe_fp)] = .{
        .llvm_name = "unsafe-fp",
        .description = "Use unsafe FP math",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v5)] = .{
        .llvm_name = "v5",
        .description = "Enable Hexagon V5 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v55)] = .{
        .llvm_name = "v55",
        .description = "Enable Hexagon V55 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v60)] = .{
        .llvm_name = "v60",
        .description = "Enable Hexagon V60 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v62)] = .{
        .llvm_name = "v62",
        .description = "Enable Hexagon V62 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v65)] = .{
        .llvm_name = "v65",
        .description = "Enable Hexagon V65 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v66)] = .{
        .llvm_name = "v66",
        .description = "Enable Hexagon V66 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v67)] = .{
        .llvm_name = "v67",
        .description = "Enable Hexagon V67 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v68)] = .{
        .llvm_name = "v68",
        .description = "Enable Hexagon V68 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v69)] = .{
        .llvm_name = "v69",
        .description = "Enable Hexagon V69 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v71)] = .{
        .llvm_name = "v71",
        .description = "Enable Hexagon V71 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v73)] = .{
        .llvm_name = "v73",
        .description = "Enable Hexagon V73 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v75)] = .{
        .llvm_name = "v75",
        .description = "Enable Hexagon V75 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v79)] = .{
        .llvm_name = "v79",
        .description = "Enable Hexagon V79 architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zreg)] = .{
        .llvm_name = "zreg",
        .description = "Hexagon ZReg extension instructions",
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
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .memops,
            .nvj,
            .nvs,
            .prev65,
            .small_data,
            .v5,
            .v55,
            .v60,
        }),
    };
    pub const hexagonv5: CpuModel = .{
        .name = "hexagonv5",
        .llvm_name = "hexagonv5",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .memops,
            .nvj,
            .nvs,
            .prev65,
            .small_data,
            .v5,
        }),
    };
    pub const hexagonv55: CpuModel = .{
        .name = "hexagonv55",
        .llvm_name = "hexagonv55",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .memops,
            .nvj,
            .nvs,
            .prev65,
            .small_data,
            .v5,
            .v55,
        }),
    };
    pub const hexagonv60: CpuModel = .{
        .name = "hexagonv60",
        .llvm_name = "hexagonv60",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .memops,
            .nvj,
            .nvs,
            .prev65,
            .small_data,
            .v5,
            .v55,
            .v60,
        }),
    };
    pub const hexagonv62: CpuModel = .{
        .name = "hexagonv62",
        .llvm_name = "hexagonv62",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .memops,
            .nvj,
            .nvs,
            .prev65,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
        }),
    };
    pub const hexagonv65: CpuModel = .{
        .name = "hexagonv65",
        .llvm_name = "hexagonv65",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
        }),
    };
    pub const hexagonv66: CpuModel = .{
        .name = "hexagonv66",
        .llvm_name = "hexagonv66",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
        }),
    };
    pub const hexagonv67: CpuModel = .{
        .name = "hexagonv67",
        .llvm_name = "hexagonv67",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
        }),
    };
    pub const hexagonv67t: CpuModel = .{
        .name = "hexagonv67t",
        .llvm_name = "hexagonv67t",
        .features = featureSet(&[_]Feature{
            .audio,
            .compound,
            .mem_noshuf,
            .memops,
            .nvs,
            .small_data,
            .tinycore,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
        }),
    };
    pub const hexagonv68: CpuModel = .{
        .name = "hexagonv68",
        .llvm_name = "hexagonv68",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
            .v68,
        }),
    };
    pub const hexagonv69: CpuModel = .{
        .name = "hexagonv69",
        .llvm_name = "hexagonv69",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
            .v68,
            .v69,
        }),
    };
    pub const hexagonv71: CpuModel = .{
        .name = "hexagonv71",
        .llvm_name = "hexagonv71",
        .features = featureSet(&[_]Feature{
            .cabac,
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
            .v68,
            .v69,
            .v71,
        }),
    };
    pub const hexagonv71t: CpuModel = .{
        .name = "hexagonv71t",
        .llvm_name = "hexagonv71t",
        .features = featureSet(&[_]Feature{
            .audio,
            .compound,
            .mem_noshuf,
            .memops,
            .nvs,
            .small_data,
            .tinycore,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
            .v68,
            .v69,
            .v71,
        }),
    };
    pub const hexagonv73: CpuModel = .{
        .name = "hexagonv73",
        .llvm_name = "hexagonv73",
        .features = featureSet(&[_]Feature{
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
            .v68,
            .v69,
            .v71,
            .v73,
        }),
    };
    pub const hexagonv75: CpuModel = .{
        .name = "hexagonv75",
        .llvm_name = "hexagonv75",
        .features = featureSet(&[_]Feature{
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
            .v68,
            .v69,
            .v71,
            .v73,
            .v75,
        }),
    };
    pub const hexagonv79: CpuModel = .{
        .name = "hexagonv79",
        .llvm_name = "hexagonv79",
        .features = featureSet(&[_]Feature{
            .compound,
            .duplex,
            .mem_noshuf,
            .memops,
            .nvj,
            .nvs,
            .small_data,
            .v5,
            .v55,
            .v60,
            .v62,
            .v65,
            .v66,
            .v67,
            .v68,
            .v69,
            .v71,
            .v73,
            .v75,
            .v79,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    const ti = @typeInfo(Feature);
    for (&result, 0..) |*elem, i| {
        elem.index = i;
        elem.name = ti.@"enum".fields[i].name;
    }
    break :blk result;
};

pub const cpu = struct {
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{}),
    };
    pub const v11: CpuModel = .{
        .name = "v11",
        .llvm_name = "v11",
        .features = featureSet(&[_]Feature{}),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    @"32bit",
    @"64bit",
    d,
    div32,
    f,
    frecipe,
    la_global_with_abs,
    la_global_with_pcrel,
    la_local_with_abs,
    lam_bh,
    lamcas,
    lasx,
    lbt,
    ld_seq_sa,
    lsx,
    lvz,
    prefer_w_inst,
    relax,
    scq,
    ual,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.@"32bit")] = .{
        .llvm_name = "32bit",
        .description = "LA32 Basic Integer and Privilege Instruction Set",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.@"64bit")] = .{
        .llvm_name = "64bit",
        .description = "LA64 Basic Integer and Privilege Instruction Set",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.d)] = .{
        .llvm_name = "d",
        .description = "'D' (Double-Precision Floating-Point)",
        .dependencies = featureSet(&[_]Feature{
            .f,
        }),
    };
    result[@intFromEnum(Feature.div32)] = .{
        .llvm_name = "div32",
        .description = "Assume div.w[u] and mod.w[u] can handle inputs that are not sign-extended",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.f)] = .{
        .llvm_name = "f",
        .description = "'F' (Single-Precision Floating-Point)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.frecipe)] = .{
        .llvm_name = "frecipe",
        .description = "Support frecipe.{s/d} and frsqrte.{s/d} instructions.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.la_global_with_abs)] = .{
        .llvm_name = "la-global-with-abs",
        .description = "Expand la.global as la.abs",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.la_global_with_pcrel)] = .{
        .llvm_name = "la-global-with-pcrel",
        .description = "Expand la.global as la.pcrel",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.la_local_with_abs)] = .{
        .llvm_name = "la-local-with-abs",
        .description = "Expand la.local as la.abs",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lam_bh)] = .{
        .llvm_name = "lam-bh",
        .description = "Support amswap[_db].{b/h} and amadd[_db].{b/h} instructions.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lamcas)] = .{
        .llvm_name = "lamcas",
        .description = "Support amcas[_db].{b/h/w/d}.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lasx)] = .{
        .llvm_name = "lasx",
        .description = "'LASX' (Loongson Advanced SIMD Extension)",
        .dependencies = featureSet(&[_]Feature{
            .lsx,
        }),
    };
    result[@intFromEnum(Feature.lbt)] = .{
        .llvm_name = "lbt",
        .description = "'LBT' (Loongson Binary Translation Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ld_seq_sa)] = .{
        .llvm_name = "ld-seq-sa",
        .description = "Don't use load-load barrier (dbar 0x700).",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lsx)] = .{
        .llvm_name = "lsx",
        .description = "'LSX' (Loongson SIMD Extension)",
        .dependencies = featureSet(&[_]Feature{
            .d,
        }),
    };
    result[@intFromEnum(Feature.lvz)] = .{
        .llvm_name = "lvz",
        .description = "'LVZ' (Loongson Virtualization Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prefer_w_inst)] = .{
        .llvm_name = "prefer-w-inst",
        .description = "Prefer instructions with W suffix",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.relax)] = .{
        .llvm_name = "relax",
        .description = "Enable Linker relaxation",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.scq)] = .{
        .llvm_name = "scq",
        .description = "Support sc.q instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ual)] = .{
        .llvm_name = "ual",
        .description = "Allow memory accesses to be unaligned",
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
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{}),
    };
    pub const generic_la32: CpuModel = .{
        .name = "generic_la32",
        .llvm_name = "generic-la32",
        .features = featureSet(&[_]Feature{
            .@"32bit",
        }),
    };
    pub const generic_la64: CpuModel = .{
        .name = "generic_la64",
        .llvm_name = "generic-la64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .lsx,
            .ual,
        }),
    };
    pub const la464: CpuModel = .{
        .name = "la464",
        .llvm_name = "la464",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .lasx,
            .lbt,
            .lvz,
            .ual,
        }),
    };
    pub const la664: CpuModel = .{
        .name = "la664",
        .llvm_name = "la664",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .div32,
            .frecipe,
            .lam_bh,
            .lamcas,
            .lasx,
            .lbt,
            .ld_seq_sa,
            .lvz,
            .scq,
            .ual,
        }),
    };
    pub const loongarch64: CpuModel = .{
        .name = "loongarch64",
        .llvm_name = "loongarch64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .d,
            .ual,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    isa_68000,
    isa_68010,
    isa_68020,
    isa_68030,
    isa_68040,
    isa_68060,
    isa_68881,
    isa_68882,
    reserve_a0,
    reserve_a1,
    reserve_a2,
    reserve_a3,
    reserve_a4,
    reserve_a5,
    reserve_a6,
    reserve_d0,
    reserve_d1,
    reserve_d2,
    reserve_d3,
    reserve_d4,
    reserve_d5,
    reserve_d6,
    reserve_d7,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.isa_68000)] = .{
        .llvm_name = "isa-68000",
        .description = "Is M68000 ISA supported",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.isa_68010)] = .{
        .llvm_name = "isa-68010",
        .description = "Is M68010 ISA supported",
        .dependencies = featureSet(&[_]Feature{
            .isa_68000,
        }),
    };
    result[@intFromEnum(Feature.isa_68020)] = .{
        .llvm_name = "isa-68020",
        .description = "Is M68020 ISA supported",
        .dependencies = featureSet(&[_]Feature{
            .isa_68010,
        }),
    };
    result[@intFromEnum(Feature.isa_68030)] = .{
        .llvm_name = "isa-68030",
        .description = "Is M68030 ISA supported",
        .dependencies = featureSet(&[_]Feature{
            .isa_68020,
        }),
    };
    result[@intFromEnum(Feature.isa_68040)] = .{
        .llvm_name = "isa-68040",
        .description = "Is M68040 ISA supported",
        .dependencies = featureSet(&[_]Feature{
            .isa_68030,
            .isa_68882,
        }),
    };
    result[@intFromEnum(Feature.isa_68060)] = .{
        .llvm_name = "isa-68060",
        .description = "Is M68060 ISA supported",
        .dependencies = featureSet(&[_]Feature{
            .isa_68040,
        }),
    };
    result[@intFromEnum(Feature.isa_68881)] = .{
        .llvm_name = "isa-68881",
        .description = "Is M68881 (FPU) ISA supported",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.isa_68882)] = .{
        .llvm_name = "isa-68882",
        .description = "Is M68882 (FPU) ISA supported",
        .dependencies = featureSet(&[_]Feature{
            .isa_68881,
        }),
    };
    result[@intFromEnum(Feature.reserve_a0)] = .{
        .llvm_name = "reserve-a0",
        .description = "Reserve A0 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_a1)] = .{
        .llvm_name = "reserve-a1",
        .description = "Reserve A1 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_a2)] = .{
        .llvm_name = "reserve-a2",
        .description = "Reserve A2 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_a3)] = .{
        .llvm_name = "reserve-a3",
        .description = "Reserve A3 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_a4)] = .{
        .llvm_name = "reserve-a4",
        .description = "Reserve A4 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_a5)] = .{
        .llvm_name = "reserve-a5",
        .description = "Reserve A5 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_a6)] = .{
        .llvm_name = "reserve-a6",
        .description = "Reserve A6 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d0)] = .{
        .llvm_name = "reserve-d0",
        .description = "Reserve D0 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d1)] = .{
        .llvm_name = "reserve-d1",
        .description = "Reserve D1 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d2)] = .{
        .llvm_name = "reserve-d2",
        .description = "Reserve D2 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d3)] = .{
        .llvm_name = "reserve-d3",
        .description = "Reserve D3 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d4)] = .{
        .llvm_name = "reserve-d4",
        .description = "Reserve D4 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d5)] = .{
        .llvm_name = "reserve-d5",
        .description = "Reserve D5 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d6)] = .{
        .llvm_name = "reserve-d6",
        .description = "Reserve D6 register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_d7)] = .{
        .llvm_name = "reserve-d7",
        .description = "Reserve D7 register",
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
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .isa_68000,
        }),
    };
    pub const M68000: CpuModel = .{
        .name = "M68000",
        .llvm_name = "M68000",
        .features = featureSet(&[_]Feature{
            .isa_68000,
        }),
    };
    pub const M68010: CpuModel = .{
        .name = "M68010",
        .llvm_name = "M68010",
        .features = featureSet(&[_]Feature{
            .isa_68010,
        }),
    };
    pub const M68020: CpuModel = .{
        .name = "M68020",
        .llvm_name = "M68020",
        .features = featureSet(&[_]Feature{
            .isa_68020,
        }),
    };
    pub const M68030: CpuModel = .{
        .name = "M68030",
        .llvm_name = "M68030",
        .features = featureSet(&[_]Feature{
            .isa_68030,
        }),
    };
    pub const M68040: CpuModel = .{
        .name = "M68040",
        .llvm_name = "M68040",
        .features = featureSet(&[_]Feature{
            .isa_68040,
        }),
    };
    pub const M68060: CpuModel = .{
        .name = "M68060",
        .llvm_name = "M68060",
        .features = featureSet(&[_]Feature{
            .isa_68060,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    abs2008,
    cnmips,
    cnmipsp,
    crc,
    dsp,
    dspr2,
    dspr3,
    eva,
    fp64,
    fpxx,
    ginv,
    gp64,
    long_calls,
    micromips,
    mips1,
    mips16,
    mips2,
    mips3,
    mips32,
    mips32r2,
    mips32r3,
    mips32r5,
    mips32r6,
    mips3_32,
    mips3_32r2,
    mips3d,
    mips4,
    mips4_32,
    mips4_32r2,
    mips5,
    mips5_32r2,
    mips64,
    mips64r2,
    mips64r3,
    mips64r5,
    mips64r6,
    msa,
    mt,
    nan2008,
    noabicalls,
    nomadd4,
    nooddspreg,
    p5600,
    ptr64,
    single_float,
    soft_float,
    strict_align,
    sym32,
    use_indirect_jump_hazard,
    use_tcc_in_div,
    vfpu,
    virt,
    xgot,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.abs2008)] = .{
        .llvm_name = "abs2008",
        .description = "Disable IEEE 754-2008 abs.fmt mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cnmips)] = .{
        .llvm_name = "cnmips",
        .description = "Octeon cnMIPS Support",
        .dependencies = featureSet(&[_]Feature{
            .mips64r2,
        }),
    };
    result[@intFromEnum(Feature.cnmipsp)] = .{
        .llvm_name = "cnmipsp",
        .description = "Octeon+ cnMIPS Support",
        .dependencies = featureSet(&[_]Feature{
            .cnmips,
        }),
    };
    result[@intFromEnum(Feature.crc)] = .{
        .llvm_name = "crc",
        .description = "Mips R6 CRC ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dsp)] = .{
        .llvm_name = "dsp",
        .description = "Mips DSP ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dspr2)] = .{
        .llvm_name = "dspr2",
        .description = "Mips DSP-R2 ASE",
        .dependencies = featureSet(&[_]Feature{
            .dsp,
        }),
    };
    result[@intFromEnum(Feature.dspr3)] = .{
        .llvm_name = "dspr3",
        .description = "Mips DSP-R3 ASE",
        .dependencies = featureSet(&[_]Feature{
            .dspr2,
        }),
    };
    result[@intFromEnum(Feature.eva)] = .{
        .llvm_name = "eva",
        .description = "Mips EVA ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp64)] = .{
        .llvm_name = "fp64",
        .description = "Support 64-bit FP registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fpxx)] = .{
        .llvm_name = "fpxx",
        .description = "Support for FPXX",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ginv)] = .{
        .llvm_name = "ginv",
        .description = "Mips Global Invalidate ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gp64)] = .{
        .llvm_name = "gp64",
        .description = "General Purpose Registers are 64-bit wide",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.long_calls)] = .{
        .llvm_name = "long-calls",
        .description = "Disable use of the jal instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.micromips)] = .{
        .llvm_name = "micromips",
        .description = "microMips mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips1)] = .{
        .llvm_name = "mips1",
        .description = "Mips I ISA Support [highly experimental]",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips16)] = .{
        .llvm_name = "mips16",
        .description = "Mips16 mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips2)] = .{
        .llvm_name = "mips2",
        .description = "Mips II ISA Support [highly experimental]",
        .dependencies = featureSet(&[_]Feature{
            .mips1,
        }),
    };
    result[@intFromEnum(Feature.mips3)] = .{
        .llvm_name = "mips3",
        .description = "MIPS III ISA Support [highly experimental]",
        .dependencies = featureSet(&[_]Feature{
            .fp64,
            .gp64,
            .mips2,
            .mips3_32,
            .mips3_32r2,
        }),
    };
    result[@intFromEnum(Feature.mips32)] = .{
        .llvm_name = "mips32",
        .description = "Mips32 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips2,
            .mips3_32,
            .mips4_32,
        }),
    };
    result[@intFromEnum(Feature.mips32r2)] = .{
        .llvm_name = "mips32r2",
        .description = "Mips32r2 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips32,
            .mips3_32r2,
            .mips4_32r2,
            .mips5_32r2,
        }),
    };
    result[@intFromEnum(Feature.mips32r3)] = .{
        .llvm_name = "mips32r3",
        .description = "Mips32r3 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips32r2,
        }),
    };
    result[@intFromEnum(Feature.mips32r5)] = .{
        .llvm_name = "mips32r5",
        .description = "Mips32r5 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips32r3,
        }),
    };
    result[@intFromEnum(Feature.mips32r6)] = .{
        .llvm_name = "mips32r6",
        .description = "Mips32r6 ISA Support [experimental]",
        .dependencies = featureSet(&[_]Feature{
            .abs2008,
            .fp64,
            .mips32r5,
            .nan2008,
        }),
    };
    result[@intFromEnum(Feature.mips3_32)] = .{
        .llvm_name = "mips3_32",
        .description = "Subset of MIPS-III that is also in MIPS32 [highly experimental]",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips3_32r2)] = .{
        .llvm_name = "mips3_32r2",
        .description = "Subset of MIPS-III that is also in MIPS32r2 [highly experimental]",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips3d)] = .{
        .llvm_name = "mips3d",
        .description = "Mips 3D ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips4)] = .{
        .llvm_name = "mips4",
        .description = "MIPS IV ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips3,
            .mips4_32,
            .mips4_32r2,
        }),
    };
    result[@intFromEnum(Feature.mips4_32)] = .{
        .llvm_name = "mips4_32",
        .description = "Subset of MIPS-IV that is also in MIPS32 [highly experimental]",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips4_32r2)] = .{
        .llvm_name = "mips4_32r2",
        .description = "Subset of MIPS-IV that is also in MIPS32r2 [highly experimental]",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips5)] = .{
        .llvm_name = "mips5",
        .description = "MIPS V ISA Support [highly experimental]",
        .dependencies = featureSet(&[_]Feature{
            .mips4,
            .mips5_32r2,
        }),
    };
    result[@intFromEnum(Feature.mips5_32r2)] = .{
        .llvm_name = "mips5_32r2",
        .description = "Subset of MIPS-V that is also in MIPS32r2 [highly experimental]",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mips64)] = .{
        .llvm_name = "mips64",
        .description = "Mips64 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips32,
            .mips5,
        }),
    };
    result[@intFromEnum(Feature.mips64r2)] = .{
        .llvm_name = "mips64r2",
        .description = "Mips64r2 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips32r2,
            .mips64,
        }),
    };
    result[@intFromEnum(Feature.mips64r3)] = .{
        .llvm_name = "mips64r3",
        .description = "Mips64r3 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips32r3,
            .mips64r2,
        }),
    };
    result[@intFromEnum(Feature.mips64r5)] = .{
        .llvm_name = "mips64r5",
        .description = "Mips64r5 ISA Support",
        .dependencies = featureSet(&[_]Feature{
            .mips32r5,
            .mips64r3,
        }),
    };
    result[@intFromEnum(Feature.mips64r6)] = .{
        .llvm_name = "mips64r6",
        .description = "Mips64r6 ISA Support [experimental]",
        .dependencies = featureSet(&[_]Feature{
            .mips32r6,
            .mips64r5,
        }),
    };
    result[@intFromEnum(Feature.msa)] = .{
        .llvm_name = "msa",
        .description = "Mips MSA ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mt)] = .{
        .llvm_name = "mt",
        .description = "Mips MT ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nan2008)] = .{
        .llvm_name = "nan2008",
        .description = "IEEE 754-2008 NaN encoding",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.noabicalls)] = .{
        .llvm_name = "noabicalls",
        .description = "Disable SVR4-style position-independent code",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nomadd4)] = .{
        .llvm_name = "nomadd4",
        .description = "Disable 4-operand madd.fmt and related instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nooddspreg)] = .{
        .llvm_name = "nooddspreg",
        .description = "Disable odd numbered single-precision registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.p5600)] = .{
        .llvm_name = "p5600",
        .description = "The P5600 Processor",
        .dependencies = featureSet(&[_]Feature{
            .mips32r5,
        }),
    };
    result[@intFromEnum(Feature.ptr64)] = .{
        .llvm_name = "ptr64",
        .description = "Pointers are 64-bit wide",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.single_float)] = .{
        .llvm_name = "single-float",
        .description = "Only supports single precision float",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.soft_float)] = .{
        .llvm_name = "soft-float",
        .description = "Does not support floating point instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.strict_align)] = .{
        .llvm_name = "strict-align",
        .description = "Disable unaligned load store for r6",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sym32)] = .{
        .llvm_name = "sym32",
        .description = "Symbols are 32 bit on Mips64",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_indirect_jump_hazard)] = .{
        .llvm_name = "use-indirect-jump-hazard",
        .description = "Use indirect jump guards to prevent certain speculation based attacks",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_tcc_in_div)] = .{
        .llvm_name = "use-tcc-in-div",
        .description = "Force the assembler to use trapping",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vfpu)] = .{
        .llvm_name = "vfpu",
        .description = "Enable vector FPU instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.virt)] = .{
        .llvm_name = "virt",
        .description = "Mips Virtualization ASE",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xgot)] = .{
        .llvm_name = "xgot",
        .description = "Assume 32-bit GOT",
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
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .mips32,
        }),
    };
    pub const mips1: CpuModel = .{
        .name = "mips1",
        .llvm_name = "mips1",
        .features = featureSet(&[_]Feature{
            .mips1,
        }),
    };
    pub const mips2: CpuModel = .{
        .name = "mips2",
        .llvm_name = "mips2",
        .features = featureSet(&[_]Feature{
            .mips2,
        }),
    };
    pub const mips3: CpuModel = .{
        .name = "mips3",
        .llvm_name = "mips3",
        .features = featureSet(&[_]Feature{
            .mips3,
        }),
    };
    pub const mips32: CpuModel = .{
        .name = "mips32",
        .llvm_name = "mips32",
        .features = featureSet(&[_]Feature{
            .mips32,
        }),
    };
    pub const mips32r2: CpuModel = .{
        .name = "mips32r2",
        .llvm_name = "mips32r2",
        .features = featureSet(&[_]Feature{
            .mips32r2,
        }),
    };
    pub const mips32r3: CpuModel = .{
        .name = "mips32r3",
        .llvm_name = "mips32r3",
        .features = featureSet(&[_]Feature{
            .mips32r3,
        }),
    };
    pub const mips32r5: CpuModel = .{
        .name = "mips32r5",
        .llvm_name = "mips32r5",
        .features = featureSet(&[_]Feature{
            .mips32r5,
        }),
    };
    pub const mips32r6: CpuModel = .{
        .name = "mips32r6",
        .llvm_name = "mips32r6",
        .features = featureSet(&[_]Feature{
            .mips32r6,
        }),
    };
    pub const mips4: CpuModel = .{
        .name = "mips4",
        .llvm_name = "mips4",
        .features = featureSet(&[_]Feature{
            .mips4,
        }),
    };
    pub const mips5: CpuModel = .{
        .name = "mips5",
        .llvm_name = "mips5",
        .features = featureSet(&[_]Feature{
            .mips5,
        }),
    };
    pub const mips64: CpuModel = .{
        .name = "mips64",
        .llvm_name = "mips64",
        .features = featureSet(&[_]Feature{
            .mips64,
        }),
    };
    pub const mips64r2: CpuModel = .{
        .name = "mips64r2",
        .llvm_name = "mips64r2",
        .features = featureSet(&[_]Feature{
            .mips64r2,
        }),
    };
    pub const mips64r3: CpuModel = .{
        .name = "mips64r3",
        .llvm_name = "mips64r3",
        .features = featureSet(&[_]Feature{
            .mips64r3,
        }),
    };
    pub const mips64r5: CpuModel = .{
        .name = "mips64r5",
        .llvm_name = "mips64r5",
        .features = featureSet(&[_]Feature{
            .mips64r5,
        }),
    };
    pub const mips64r6: CpuModel = .{
        .name = "mips64r6",
        .llvm_name = "mips64r6",
        .features = featureSet(&[_]Feature{
            .mips64r6,
        }),
    };
    pub const octeon: CpuModel = .{
        .name = "octeon",
        .llvm_name = "octeon",
        .features = featureSet(&[_]Feature{
            .cnmips,
        }),
    };
    pub const @"octeon+": CpuModel = .{
        .name = "octeon+",
        .llvm_name = "octeon+",
        .features = featureSet(&[_]Feature{
            .cnmipsp,
        }),
    };
    pub const p5600: CpuModel = .{
        .name = "p5600",
        .llvm_name = "p5600",
        .features = featureSet(&[_]Feature{
            .p5600,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    ext,
    hwmult16,
    hwmult32,
    hwmultf5,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.ext)] = .{
        .llvm_name = "ext",
        .description = "Enable MSP430-X extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hwmult16)] = .{
        .llvm_name = "hwmult16",
        .description = "Enable 16-bit hardware multiplier",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hwmult32)] = .{
        .llvm_name = "hwmult32",
        .description = "Enable 32-bit hardware multiplier",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hwmultf5)] = .{
        .llvm_name = "hwmultf5",
        .description = "Enable F5 series hardware multiplier",
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
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{}),
    };
    pub const msp430: CpuModel = .{
        .name = "msp430",
        .llvm_name = "msp430",
        .features = featureSet(&[_]Feature{}),
    };
    pub const msp430x: CpuModel = .{
        .name = "msp430x",
        .llvm_name = "msp430x",
        .features = featureSet(&[_]Feature{
            .ext,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    ptx32,
    ptx40,
    ptx41,
    ptx42,
    ptx43,
    ptx50,
    ptx60,
    ptx61,
    ptx62,
    ptx63,
    ptx64,
    ptx65,
    ptx70,
    ptx71,
    ptx72,
    ptx73,
    ptx74,
    ptx75,
    ptx76,
    ptx77,
    ptx78,
    ptx80,
    ptx81,
    ptx82,
    ptx83,
    ptx84,
    ptx85,
    ptx86,
    ptx87,
    sm_100,
    sm_100a,
    sm_101,
    sm_101a,
    sm_120,
    sm_120a,
    sm_20,
    sm_21,
    sm_30,
    sm_32,
    sm_35,
    sm_37,
    sm_50,
    sm_52,
    sm_53,
    sm_60,
    sm_61,
    sm_62,
    sm_70,
    sm_72,
    sm_75,
    sm_80,
    sm_86,
    sm_87,
    sm_89,
    sm_90,
    sm_90a,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.ptx32)] = .{
        .llvm_name = "ptx32",
        .description = "Use PTX version 32",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx40)] = .{
        .llvm_name = "ptx40",
        .description = "Use PTX version 40",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx41)] = .{
        .llvm_name = "ptx41",
        .description = "Use PTX version 41",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx42)] = .{
        .llvm_name = "ptx42",
        .description = "Use PTX version 42",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx43)] = .{
        .llvm_name = "ptx43",
        .description = "Use PTX version 43",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx50)] = .{
        .llvm_name = "ptx50",
        .description = "Use PTX version 50",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx60)] = .{
        .llvm_name = "ptx60",
        .description = "Use PTX version 60",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx61)] = .{
        .llvm_name = "ptx61",
        .description = "Use PTX version 61",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx62)] = .{
        .llvm_name = "ptx62",
        .description = "Use PTX version 62",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx63)] = .{
        .llvm_name = "ptx63",
        .description = "Use PTX version 63",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx64)] = .{
        .llvm_name = "ptx64",
        .description = "Use PTX version 64",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx65)] = .{
        .llvm_name = "ptx65",
        .description = "Use PTX version 65",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx70)] = .{
        .llvm_name = "ptx70",
        .description = "Use PTX version 70",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx71)] = .{
        .llvm_name = "ptx71",
        .description = "Use PTX version 71",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx72)] = .{
        .llvm_name = "ptx72",
        .description = "Use PTX version 72",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx73)] = .{
        .llvm_name = "ptx73",
        .description = "Use PTX version 73",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx74)] = .{
        .llvm_name = "ptx74",
        .description = "Use PTX version 74",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx75)] = .{
        .llvm_name = "ptx75",
        .description = "Use PTX version 75",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx76)] = .{
        .llvm_name = "ptx76",
        .description = "Use PTX version 76",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx77)] = .{
        .llvm_name = "ptx77",
        .description = "Use PTX version 77",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx78)] = .{
        .llvm_name = "ptx78",
        .description = "Use PTX version 78",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx80)] = .{
        .llvm_name = "ptx80",
        .description = "Use PTX version 80",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx81)] = .{
        .llvm_name = "ptx81",
        .description = "Use PTX version 81",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx82)] = .{
        .llvm_name = "ptx82",
        .description = "Use PTX version 82",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx83)] = .{
        .llvm_name = "ptx83",
        .description = "Use PTX version 83",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx84)] = .{
        .llvm_name = "ptx84",
        .description = "Use PTX version 84",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx85)] = .{
        .llvm_name = "ptx85",
        .description = "Use PTX version 85",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx86)] = .{
        .llvm_name = "ptx86",
        .description = "Use PTX version 86",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ptx87)] = .{
        .llvm_name = "ptx87",
        .description = "Use PTX version 87",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_100)] = .{
        .llvm_name = "sm_100",
        .description = "Target SM 100",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_100a)] = .{
        .llvm_name = "sm_100a",
        .description = "Target SM 100a",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_101)] = .{
        .llvm_name = "sm_101",
        .description = "Target SM 101",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_101a)] = .{
        .llvm_name = "sm_101a",
        .description = "Target SM 101a",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_120)] = .{
        .llvm_name = "sm_120",
        .description = "Target SM 120",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_120a)] = .{
        .llvm_name = "sm_120a",
        .description = "Target SM 120a",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_20)] = .{
        .llvm_name = "sm_20",
        .description = "Target SM 20",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_21)] = .{
        .llvm_name = "sm_21",
        .description = "Target SM 21",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_30)] = .{
        .llvm_name = "sm_30",
        .description = "Target SM 30",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_32)] = .{
        .llvm_name = "sm_32",
        .description = "Target SM 32",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_35)] = .{
        .llvm_name = "sm_35",
        .description = "Target SM 35",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_37)] = .{
        .llvm_name = "sm_37",
        .description = "Target SM 37",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_50)] = .{
        .llvm_name = "sm_50",
        .description = "Target SM 50",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_52)] = .{
        .llvm_name = "sm_52",
        .description = "Target SM 52",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_53)] = .{
        .llvm_name = "sm_53",
        .description = "Target SM 53",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_60)] = .{
        .llvm_name = "sm_60",
        .description = "Target SM 60",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_61)] = .{
        .llvm_name = "sm_61",
        .description = "Target SM 61",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_62)] = .{
        .llvm_name = "sm_62",
        .description = "Target SM 62",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_70)] = .{
        .llvm_name = "sm_70",
        .description = "Target SM 70",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_72)] = .{
        .llvm_name = "sm_72",
        .description = "Target SM 72",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_75)] = .{
        .llvm_name = "sm_75",
        .description = "Target SM 75",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_80)] = .{
        .llvm_name = "sm_80",
        .description = "Target SM 80",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_86)] = .{
        .llvm_name = "sm_86",
        .description = "Target SM 86",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_87)] = .{
        .llvm_name = "sm_87",
        .description = "Target SM 87",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_89)] = .{
        .llvm_name = "sm_89",
        .description = "Target SM 89",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_90)] = .{
        .llvm_name = "sm_90",
        .description = "Target SM 90",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm_90a)] = .{
        .llvm_name = "sm_90a",
        .description = "Target SM 90a",
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
    pub const sm_100: CpuModel = .{
        .name = "sm_100",
        .llvm_name = "sm_100",
        .features = featureSet(&[_]Feature{
            .ptx86,
            .sm_100,
        }),
    };
    pub const sm_100a: CpuModel = .{
        .name = "sm_100a",
        .llvm_name = "sm_100a",
        .features = featureSet(&[_]Feature{
            .ptx86,
            .sm_100a,
        }),
    };
    pub const sm_101: CpuModel = .{
        .name = "sm_101",
        .llvm_name = "sm_101",
        .features = featureSet(&[_]Feature{
            .ptx86,
            .sm_101,
        }),
    };
    pub const sm_101a: CpuModel = .{
        .name = "sm_101a",
        .llvm_name = "sm_101a",
        .features = featureSet(&[_]Feature{
            .ptx86,
            .sm_101a,
        }),
    };
    pub const sm_120: CpuModel = .{
        .name = "sm_120",
        .llvm_name = "sm_120",
        .features = featureSet(&[_]Feature{
            .ptx87,
            .sm_120,
        }),
    };
    pub const sm_120a: CpuModel = .{
        .name = "sm_120a",
        .llvm_name = "sm_120a",
        .features = featureSet(&[_]Feature{
            .ptx87,
            .sm_120a,
        }),
    };
    pub const sm_20: CpuModel = .{
        .name = "sm_20",
        .llvm_name = "sm_20",
        .features = featureSet(&[_]Feature{
            .ptx32,
            .sm_20,
        }),
    };
    pub const sm_21: CpuModel = .{
        .name = "sm_21",
        .llvm_name = "sm_21",
        .features = featureSet(&[_]Feature{
            .ptx32,
            .sm_21,
        }),
    };
    pub const sm_30: CpuModel = .{
        .name = "sm_30",
        .llvm_name = "sm_30",
        .features = featureSet(&[_]Feature{
            .sm_30,
        }),
    };
    pub const sm_32: CpuModel = .{
        .name = "sm_32",
        .llvm_name = "sm_32",
        .features = featureSet(&[_]Feature{
            .ptx40,
            .sm_32,
        }),
    };
    pub const sm_35: CpuModel = .{
        .name = "sm_35",
        .llvm_name = "sm_35",
        .features = featureSet(&[_]Feature{
            .ptx32,
            .sm_35,
        }),
    };
    pub const sm_37: CpuModel = .{
        .name = "sm_37",
        .llvm_name = "sm_37",
        .features = featureSet(&[_]Feature{
            .ptx41,
            .sm_37,
        }),
    };
    pub const sm_50: CpuModel = .{
        .name = "sm_50",
        .llvm_name = "sm_50",
        .features = featureSet(&[_]Feature{
            .ptx40,
            .sm_50,
        }),
    };
    pub const sm_52: CpuModel = .{
        .name = "sm_52",
        .llvm_name = "sm_52",
        .features = featureSet(&[_]Feature{
            .ptx41,
            .sm_52,
        }),
    };
    pub const sm_53: CpuModel = .{
        .name = "sm_53",
        .llvm_name = "sm_53",
        .features = featureSet(&[_]Feature{
            .ptx42,
            .sm_53,
        }),
    };
    pub const sm_60: CpuModel = .{
        .name = "sm_60",
        .llvm_name = "sm_60",
        .features = featureSet(&[_]Feature{
            .ptx50,
            .sm_60,
        }),
    };
    pub const sm_61: CpuModel = .{
        .name = "sm_61",
        .llvm_name = "sm_61",
        .features = featureSet(&[_]Feature{
            .ptx50,
            .sm_61,
        }),
    };
    pub const sm_62: CpuModel = .{
        .name = "sm_62",
        .llvm_name = "sm_62",
        .features = featureSet(&[_]Feature{
            .ptx50,
            .sm_62,
        }),
    };
    pub const sm_70: CpuModel = .{
        .name = "sm_70",
        .llvm_name = "sm_70",
        .features = featureSet(&[_]Feature{
            .ptx60,
            .sm_70,
        }),
    };
    pub const sm_72: CpuModel = .{
        .name = "sm_72",
        .llvm_name = "sm_72",
        .features = featureSet(&[_]Feature{
            .ptx61,
            .sm_72,
        }),
    };
    pub const sm_75: CpuModel = .{
        .name = "sm_75",
        .llvm_name = "sm_75",
        .features = featureSet(&[_]Feature{
            .ptx63,
            .sm_75,
        }),
    };
    pub const sm_80: CpuModel = .{
        .name = "sm_80",
        .llvm_name = "sm_80",
        .features = featureSet(&[_]Feature{
            .ptx70,
            .sm_80,
        }),
    };
    pub const sm_86: CpuModel = .{
        .name = "sm_86",
        .llvm_name = "sm_86",
        .features = featureSet(&[_]Feature{
            .ptx71,
            .sm_86,
        }),
    };
    pub const sm_87: CpuModel = .{
        .name = "sm_87",
        .llvm_name = "sm_87",
        .features = featureSet(&[_]Feature{
            .ptx74,
            .sm_87,
        }),
    };
    pub const sm_89: CpuModel = .{
        .name = "sm_89",
        .llvm_name = "sm_89",
        .features = featureSet(&[_]Feature{
            .ptx78,
            .sm_89,
        }),
    };
    pub const sm_90: CpuModel = .{
        .name = "sm_90",
        .llvm_name = "sm_90",
        .features = featureSet(&[_]Feature{
            .ptx78,
            .sm_90,
        }),
    };
    pub const sm_90a: CpuModel = .{
        .name = "sm_90a",
        .llvm_name = "sm_90a",
        .features = featureSet(&[_]Feature{
            .ptx80,
            .sm_90a,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    @"64bit",
    @"64bitregs",
    aix,
    aix_shared_lib_tls_model_opt,
    aix_small_local_dynamic_tls,
    aix_small_local_exec_tls,
    allow_unaligned_fp_access,
    altivec,
    booke,
    bpermd,
    cmpb,
    crbits,
    crypto,
    direct_move,
    e500,
    efpu2,
    extdiv,
    fast_MFLR,
    fcpsgn,
    float128,
    fpcvt,
    fprnd,
    fpu,
    fre,
    fres,
    frsqrte,
    frsqrtes,
    fsqrt,
    fuse_add_logical,
    fuse_addi_load,
    fuse_addis_load,
    fuse_arith_add,
    fuse_back2back,
    fuse_cmp,
    fuse_logical,
    fuse_logical_add,
    fuse_sha3,
    fuse_store,
    fuse_wideimm,
    fuse_zeromove,
    fusion,
    hard_float,
    htm,
    icbt,
    invariant_function_descriptors,
    isa_future_instructions,
    isa_v206_instructions,
    isa_v207_instructions,
    isa_v30_instructions,
    isa_v31_instructions,
    isel,
    ldbrx,
    lfiwax,
    longcall,
    mfocrf,
    mma,
    modern_aix_as,
    msync,
    paired_vector_memops,
    partword_atomics,
    pcrelative_memops,
    popcntd,
    power10_vector,
    power8_altivec,
    power8_vector,
    power9_altivec,
    power9_vector,
    ppc4xx,
    ppc6xx,
    ppc_postra_sched,
    ppc_prera_sched,
    predictable_select_expensive,
    prefix_instrs,
    privileged,
    quadword_atomics,
    recipprec,
    rop_protect,
    secure_plt,
    slow_popcntd,
    spe,
    stfiwx,
    two_const_nr,
    vectors_use_two_units,
    vsx,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.@"64bit")] = .{
        .llvm_name = "64bit",
        .description = "Enable 64-bit instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.@"64bitregs")] = .{
        .llvm_name = "64bitregs",
        .description = "Enable 64-bit registers usage for ppc32 [beta]",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aix)] = .{
        .llvm_name = "aix",
        .description = "AIX OS",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aix_shared_lib_tls_model_opt)] = .{
        .llvm_name = "aix-shared-lib-tls-model-opt",
        .description = "Tune TLS model at function level in shared library loaded with the main program (for 64-bit AIX only)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aix_small_local_dynamic_tls)] = .{
        .llvm_name = "aix-small-local-dynamic-tls",
        .description = "Produce a faster local-dynamic TLS sequence for this function for 64-bit AIX",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aix_small_local_exec_tls)] = .{
        .llvm_name = "aix-small-local-exec-tls",
        .description = "Produce a TOC-free local-exec TLS sequence for this function for 64-bit AIX",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.allow_unaligned_fp_access)] = .{
        .llvm_name = "allow-unaligned-fp-access",
        .description = "CPU does not trap on unaligned FP access",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.altivec)] = .{
        .llvm_name = "altivec",
        .description = "Enable Altivec instructions",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.booke)] = .{
        .llvm_name = "booke",
        .description = "Enable Book E instructions",
        .dependencies = featureSet(&[_]Feature{
            .icbt,
        }),
    };
    result[@intFromEnum(Feature.bpermd)] = .{
        .llvm_name = "bpermd",
        .description = "Enable the bpermd instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cmpb)] = .{
        .llvm_name = "cmpb",
        .description = "Enable the cmpb instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.crbits)] = .{
        .llvm_name = "crbits",
        .description = "Use condition-register bits individually",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.crypto)] = .{
        .llvm_name = "crypto",
        .description = "Enable POWER8 Crypto instructions",
        .dependencies = featureSet(&[_]Feature{
            .power8_altivec,
        }),
    };
    result[@intFromEnum(Feature.direct_move)] = .{
        .llvm_name = "direct-move",
        .description = "Enable Power8 direct move instructions",
        .dependencies = featureSet(&[_]Feature{
            .vsx,
        }),
    };
    result[@intFromEnum(Feature.e500)] = .{
        .llvm_name = "e500",
        .description = "Enable E500/E500mc instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.efpu2)] = .{
        .llvm_name = "efpu2",
        .description = "Enable Embedded Floating-Point APU 2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .spe,
        }),
    };
    result[@intFromEnum(Feature.extdiv)] = .{
        .llvm_name = "extdiv",
        .description = "Enable extended divide instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fast_MFLR)] = .{
        .llvm_name = "fast-MFLR",
        .description = "MFLR is a fast instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fcpsgn)] = .{
        .llvm_name = "fcpsgn",
        .description = "Enable the fcpsgn instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.float128)] = .{
        .llvm_name = "float128",
        .description = "Enable the __float128 data type for IEEE-754R Binary128.",
        .dependencies = featureSet(&[_]Feature{
            .vsx,
        }),
    };
    result[@intFromEnum(Feature.fpcvt)] = .{
        .llvm_name = "fpcvt",
        .description = "Enable fc[ft]* (unsigned and single-precision) and lfiwzx instructions",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.fprnd)] = .{
        .llvm_name = "fprnd",
        .description = "Enable the fri[mnpz] instructions",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.fpu)] = .{
        .llvm_name = "fpu",
        .description = "Enable classic FPU instructions",
        .dependencies = featureSet(&[_]Feature{
            .hard_float,
        }),
    };
    result[@intFromEnum(Feature.fre)] = .{
        .llvm_name = "fre",
        .description = "Enable the fre instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.fres)] = .{
        .llvm_name = "fres",
        .description = "Enable the fres instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.frsqrte)] = .{
        .llvm_name = "frsqrte",
        .description = "Enable the frsqrte instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.frsqrtes)] = .{
        .llvm_name = "frsqrtes",
        .description = "Enable the frsqrtes instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.fsqrt)] = .{
        .llvm_name = "fsqrt",
        .description = "Enable the fsqrt instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.fuse_add_logical)] = .{
        .llvm_name = "fuse-add-logical",
        .description = "Target supports Add with Logical Operations fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_addi_load)] = .{
        .llvm_name = "fuse-addi-load",
        .description = "Power8 Addi-Load fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_addis_load)] = .{
        .llvm_name = "fuse-addis-load",
        .description = "Power8 Addis-Load fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_arith_add)] = .{
        .llvm_name = "fuse-arith-add",
        .description = "Target supports Arithmetic Operations with Add fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_back2back)] = .{
        .llvm_name = "fuse-back2back",
        .description = "Target supports general back to back fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_cmp)] = .{
        .llvm_name = "fuse-cmp",
        .description = "Target supports Comparison Operations fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_logical)] = .{
        .llvm_name = "fuse-logical",
        .description = "Target supports Logical Operations fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_logical_add)] = .{
        .llvm_name = "fuse-logical-add",
        .description = "Target supports Logical with Add Operations fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_sha3)] = .{
        .llvm_name = "fuse-sha3",
        .description = "Target supports SHA3 assist fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_store)] = .{
        .llvm_name = "fuse-store",
        .description = "Target supports store clustering",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_wideimm)] = .{
        .llvm_name = "fuse-wideimm",
        .description = "Target supports Wide-Immediate fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fuse_zeromove)] = .{
        .llvm_name = "fuse-zeromove",
        .description = "Target supports move to SPR with branch fusion",
        .dependencies = featureSet(&[_]Feature{
            .fusion,
        }),
    };
    result[@intFromEnum(Feature.fusion)] = .{
        .llvm_name = "fusion",
        .description = "Target supports instruction fusion",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hard_float)] = .{
        .llvm_name = "hard-float",
        .description = "Enable floating-point instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.htm)] = .{
        .llvm_name = "htm",
        .description = "Enable Hardware Transactional Memory instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.icbt)] = .{
        .llvm_name = "icbt",
        .description = "Enable icbt instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.invariant_function_descriptors)] = .{
        .llvm_name = "invariant-function-descriptors",
        .description = "Assume function descriptors are invariant",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.isa_future_instructions)] = .{
        .llvm_name = "isa-future-instructions",
        .description = "Enable instructions for Future ISA.",
        .dependencies = featureSet(&[_]Feature{
            .isa_v31_instructions,
        }),
    };
    result[@intFromEnum(Feature.isa_v206_instructions)] = .{
        .llvm_name = "isa-v206-instructions",
        .description = "Enable instructions in ISA 2.06.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.isa_v207_instructions)] = .{
        .llvm_name = "isa-v207-instructions",
        .description = "Enable instructions in ISA 2.07.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.isa_v30_instructions)] = .{
        .llvm_name = "isa-v30-instructions",
        .description = "Enable instructions in ISA 3.0.",
        .dependencies = featureSet(&[_]Feature{
            .isa_v207_instructions,
        }),
    };
    result[@intFromEnum(Feature.isa_v31_instructions)] = .{
        .llvm_name = "isa-v31-instructions",
        .description = "Enable instructions in ISA 3.1.",
        .dependencies = featureSet(&[_]Feature{
            .isa_v30_instructions,
        }),
    };
    result[@intFromEnum(Feature.isel)] = .{
        .llvm_name = "isel",
        .description = "Enable the isel instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ldbrx)] = .{
        .llvm_name = "ldbrx",
        .description = "Enable the ldbrx instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lfiwax)] = .{
        .llvm_name = "lfiwax",
        .description = "Enable the lfiwax instruction",
        .dependencies = featureSet(&[_]Feature{
            .fpu,
        }),
    };
    result[@intFromEnum(Feature.longcall)] = .{
        .llvm_name = "longcall",
        .description = "Always use indirect calls",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mfocrf)] = .{
        .llvm_name = "mfocrf",
        .description = "Enable the MFOCRF instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mma)] = .{
        .llvm_name = "mma",
        .description = "Enable MMA instructions",
        .dependencies = featureSet(&[_]Feature{
            .paired_vector_memops,
            .power8_vector,
            .power9_altivec,
        }),
    };
    result[@intFromEnum(Feature.modern_aix_as)] = .{
        .llvm_name = "modern-aix-as",
        .description = "AIX system assembler is modern enough to support new mnes",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.msync)] = .{
        .llvm_name = "msync",
        .description = "Has only the msync instruction instead of sync",
        .dependencies = featureSet(&[_]Feature{
            .booke,
        }),
    };
    result[@intFromEnum(Feature.paired_vector_memops)] = .{
        .llvm_name = "paired-vector-memops",
        .description = "32Byte load and store instructions",
        .dependencies = featureSet(&[_]Feature{
            .isa_v30_instructions,
        }),
    };
    result[@intFromEnum(Feature.partword_atomics)] = .{
        .llvm_name = "partword-atomics",
        .description = "Enable l[bh]arx and st[bh]cx.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pcrelative_memops)] = .{
        .llvm_name = "pcrelative-memops",
        .description = "Enable PC relative Memory Ops",
        .dependencies = featureSet(&[_]Feature{
            .prefix_instrs,
        }),
    };
    result[@intFromEnum(Feature.popcntd)] = .{
        .llvm_name = "popcntd",
        .description = "Enable the popcnt[dw] instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.power10_vector)] = .{
        .llvm_name = "power10-vector",
        .description = "Enable POWER10 vector instructions",
        .dependencies = featureSet(&[_]Feature{
            .isa_v31_instructions,
            .power9_vector,
        }),
    };
    result[@intFromEnum(Feature.power8_altivec)] = .{
        .llvm_name = "power8-altivec",
        .description = "Enable POWER8 Altivec instructions",
        .dependencies = featureSet(&[_]Feature{
            .altivec,
        }),
    };
    result[@intFromEnum(Feature.power8_vector)] = .{
        .llvm_name = "power8-vector",
        .description = "Enable POWER8 vector instructions",
        .dependencies = featureSet(&[_]Feature{
            .power8_altivec,
            .vsx,
        }),
    };
    result[@intFromEnum(Feature.power9_altivec)] = .{
        .llvm_name = "power9-altivec",
        .description = "Enable POWER9 Altivec instructions",
        .dependencies = featureSet(&[_]Feature{
     ```
