```
instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v4t,
        }),
    };
    result[@intFromEnum(Feature.has_v5te)] = .{
        .llvm_name = "v5te",
        .description = "Support ARM v5TE, v5TEj, and v5TExp instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v5t,
        }),
    };
    result[@intFromEnum(Feature.has_v6)] = .{
        .llvm_name = "v6",
        .description = "Support ARM v6 instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v5te,
        }),
    };
    result[@intFromEnum(Feature.has_v6k)] = .{
        .llvm_name = "v6k",
        .description = "Support ARM v6k instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v6,
        }),
    };
    result[@intFromEnum(Feature.has_v6m)] = .{
        .llvm_name = "v6m",
        .description = "Support ARM v6M instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v6,
        }),
    };
    result[@intFromEnum(Feature.has_v6t2)] = .{
        .llvm_name = "v6t2",
        .description = "Support ARM v6t2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v6k,
            .has_v8m,
            .thumb2,
        }),
    };
    result[@intFromEnum(Feature.has_v7)] = .{
        .llvm_name = "v7",
        .description = "Support ARM v7 instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v6t2,
            .has_v7clrex,
        }),
    };
    result[@intFromEnum(Feature.has_v7clrex)] = .{
        .llvm_name = "v7clrex",
        .description = "Has v7 clrex instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.has_v8)] = .{
        .llvm_name = "v8",
        .description = "Support ARM v8 instructions",
        .dependencies = featureSet(&[_]Feature{
            .acquire_release,
            .has_v7,
            .perfmon,
        }),
    };
    result[@intFromEnum(Feature.has_v8_1a)] = .{
        .llvm_name = "v8.1a",
        .description = "Support ARM v8.1a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8,
        }),
    };
    result[@intFromEnum(Feature.has_v8_1m_main)] = .{
        .llvm_name = "v8.1m.main",
        .description = "Support ARM v8-1M Mainline instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8m_main,
        }),
    };
    result[@intFromEnum(Feature.has_v8_2a)] = .{
        .llvm_name = "v8.2a",
        .description = "Support ARM v8.2a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_1a,
        }),
    };
    result[@intFromEnum(Feature.has_v8_3a)] = .{
        .llvm_name = "v8.3a",
        .description = "Support ARM v8.3a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_2a,
        }),
    };
    result[@intFromEnum(Feature.has_v8_4a)] = .{
        .llvm_name = "v8.4a",
        .description = "Support ARM v8.4a instructions",
        .dependencies = featureSet(&[_]Feature{
            .dotprod,
            .has_v8_3a,
        }),
    };
    result[@intFromEnum(Feature.has_v8_5a)] = .{
        .llvm_name = "v8.5a",
        .description = "Support ARM v8.5a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_4a,
            .sb,
        }),
    };
    result[@intFromEnum(Feature.has_v8_6a)] = .{
        .llvm_name = "v8.6a",
        .description = "Support ARM v8.6a instructions",
        .dependencies = featureSet(&[_]Feature{
            .bf16,
            .has_v8_5a,
            .i8mm,
        }),
    };
    result[@intFromEnum(Feature.has_v8_7a)] = .{
        .llvm_name = "v8.7a",
        .description = "Support ARM v8.7a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_6a,
        }),
    };
    result[@intFromEnum(Feature.has_v8_8a)] = .{
        .llvm_name = "v8.8a",
        .description = "Support ARM v8.8a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_7a,
        }),
    };
    result[@intFromEnum(Feature.has_v8_9a)] = .{
        .llvm_name = "v8.9a",
        .description = "Support ARM v8.9a instructions",
        .dependencies = featureSet(&[_]Feature{
            .clrbhb,
            .has_v8_8a,
        }),
    };
    result[@intFromEnum(Feature.has_v8m)] = .{
        .llvm_name = "v8m",
        .description = "Support ARM v8M Baseline instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v6m,
        }),
    };
    result[@intFromEnum(Feature.has_v8m_main)] = .{
        .llvm_name = "v8m.main",
        .description = "Support ARM v8M Mainline instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v7,
        }),
    };
    result[@intFromEnum(Feature.has_v9_1a)] = .{
        .llvm_name = "v9.1a",
        .description = "Support ARM v9.1a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_6a,
            .has_v9a,
        }),
    };
    result[@intFromEnum(Feature.has_v9_2a)] = .{
        .llvm_name = "v9.2a",
        .description = "Support ARM v9.2a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_7a,
            .has_v9_1a,
        }),
    };
    result[@intFromEnum(Feature.has_v9_3a)] = .{
        .llvm_name = "v9.3a",
        .description = "Support ARM v9.3a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_8a,
            .has_v9_2a,
        }),
    };
    result[@intFromEnum(Feature.has_v9_4a)] = .{
        .llvm_name = "v9.4a",
        .description = "Support ARM v9.4a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_9a,
            .has_v9_3a,
        }),
    };
    result[@intFromEnum(Feature.has_v9_5a)] = .{
        .llvm_name = "v9.5a",
        .description = "Support ARM v9.5a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v9_4a,
        }),
    };
    result[@intFromEnum(Feature.has_v9_6a)] = .{
        .llvm_name = "v9.6a",
        .description = "Support ARM v9.6a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v9_5a,
        }),
    };
    result[@intFromEnum(Feature.has_v9a)] = .{
        .llvm_name = "v9a",
        .description = "Support ARM v9a instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8_5a,
        }),
    };
    result[@intFromEnum(Feature.hwdiv)] = .{
        .llvm_name = "hwdiv",
        .description = "Enable divide instructions in Thumb",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hwdiv_arm)] = .{
        .llvm_name = "hwdiv-arm",
        .description = "Enable divide instructions in ARM mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.i8mm)] = .{
        .llvm_name = "i8mm",
        .description = "Enable Matrix Multiply Int8 Extension",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.iwmmxt)] = .{
        .llvm_name = "iwmmxt",
        .description = "ARMv5te architecture",
        .dependencies = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    result[@intFromEnum(Feature.iwmmxt2)] = .{
        .llvm_name = "iwmmxt2",
        .description = "ARMv5te architecture",
        .dependencies = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    result[@intFromEnum(Feature.lob)] = .{
        .llvm_name = "lob",
        .description = "Enable Low Overhead Branch extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.long_calls)] = .{
        .llvm_name = "long-calls",
        .description = "Generate calls via indirect call instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.loop_align)] = .{
        .llvm_name = "loop-align",
        .description = "Prefer 32-bit alignment for branch targets",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.m55)] = .{
        .llvm_name = "m55",
        .description = "Cortex-M55 ARM processors",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.m85)] = .{
        .llvm_name = "m85",
        .description = "Cortex-M85 ARM processors",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mclass)] = .{
        .llvm_name = "mclass",
        .description = "Is microcontroller profile ('M' series)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mp)] = .{
        .llvm_name = "mp",
        .description = "Supports Multiprocessing extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.muxed_units)] = .{
        .llvm_name = "muxed-units",
        .description = "Has muxed AGU and NEON/FPU",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mve)] = .{
        .llvm_name = "mve",
        .description = "Support M-Class Vector Extension with integer ops",
        .dependencies = featureSet(&[_]Feature{
            .dsp,
            .fpregs16,
            .fpregs64,
            .has_v8_1m_main,
        }),
    };
    result[@intFromEnum(Feature.mve1beat)] = .{
        .llvm_name = "mve1beat",
        .description = "Model MVE instructions as a 1 beat per tick architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mve2beat)] = .{
        .llvm_name = "mve2beat",
        .description = "Model MVE instructions as a 2 beats per tick architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mve4beat)] = .{
        .llvm_name = "mve4beat",
        .description = "Model MVE instructions as a 4 beats per tick architecture",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mve_fp)] = .{
        .llvm_name = "mve.fp",
        .description = "Support M-Class Vector Extension with integer and floating ops",
        .dependencies = featureSet(&[_]Feature{
            .fullfp16,
            .mve,
        }),
    };
    result[@intFromEnum(Feature.nacl_trap)] = .{
        .llvm_name = "nacl-trap",
        .description = "NaCl trap",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.neon)] = .{
        .llvm_name = "neon",
        .description = "Enable NEON instructions",
        .dependencies = featureSet(&[_]Feature{
            .vfp3,
        }),
    };
    result[@intFromEnum(Feature.neon_fpmovs)] = .{
        .llvm_name = "neon-fpmovs",
        .description = "Convert VMOVSR, VMOVRS, VMOVS to NEON",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.neonfp)] = .{
        .llvm_name = "neonfp",
        .description = "Use NEON for single precision FP",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_branch_predictor)] = .{
        .llvm_name = "no-branch-predictor",
        .description = "Has no branch predictor",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_bti_at_return_twice)] = .{
        .llvm_name = "no-bti-at-return-twice",
        .description = "Don't place a BTI instruction after a return-twice",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_movt)] = .{
        .llvm_name = "no-movt",
        .description = "Don't use movt/movw pairs for 32-bit imms",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_neg_immediates)] = .{
        .llvm_name = "no-neg-immediates",
        .description = "Convert immediates and instructions to their negated or complemented equivalent when the immediate does not fit in the encoding.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.noarm)] = .{
        .llvm_name = "noarm",
        .description = "Does not support ARM mode execution",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nonpipelined_vfp)] = .{
        .llvm_name = "nonpipelined-vfp",
        .description = "VFP instructions are not pipelined",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pacbti)] = .{
        .llvm_name = "pacbti",
        .description = "Enable Pointer Authentication and Branch Target Identification",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.perfmon)] = .{
        .llvm_name = "perfmon",
        .description = "Enable support for Performance Monitor extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prefer_ishst)] = .{
        .llvm_name = "prefer-ishst",
        .description = "Prefer ISHST barriers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prefer_vmovsr)] = .{
        .llvm_name = "prefer-vmovsr",
        .description = "Prefer VMOVSR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prof_unpr)] = .{
        .llvm_name = "prof-unpr",
        .description = "Is profitable to unpredicate",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ras)] = .{
        .llvm_name = "ras",
        .description = "Enable Reliability, Availability and Serviceability extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rclass)] = .{
        .llvm_name = "rclass",
        .description = "Is realtime profile ('R' series)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.read_tp_tpidrprw)] = .{
        .llvm_name = "read-tp-tpidrprw",
        .description = "Reading thread pointer from TPIDRPRW register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.read_tp_tpidruro)] = .{
        .llvm_name = "read-tp-tpidruro",
        .description = "Reading thread pointer from TPIDRURO register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.read_tp_tpidrurw)] = .{
        .llvm_name = "read-tp-tpidrurw",
        .description = "Reading thread pointer from TPIDRURW register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_r9)] = .{
        .llvm_name = "reserve-r9",
        .description = "Reserve R9, making it unavailable as GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ret_addr_stack)] = .{
        .llvm_name = "ret-addr-stack",
        .description = "Has return address stack",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sb)] = .{
        .llvm_name = "sb",
        .description = "Enable v8.5a Speculation Barrier",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sha2)] = .{
        .llvm_name = "sha2",
        .description = "Enable SHA1 and SHA256 support",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.slow_fp_brcc)] = .{
        .llvm_name = "slow-fp-brcc",
        .description = "FP compare + branch is slow",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_load_D_subreg)] = .{
        .llvm_name = "slow-load-D-subreg",
        .description = "Loading into D subregs is slow",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_odd_reg)] = .{
        .llvm_name = "slow-odd-reg",
        .description = "VLDM/VSTM starting with an odd register is slow",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_vdup32)] = .{
        .llvm_name = "slow-vdup32",
        .description = "Has slow VDUP32 - prefer VMOV",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_vgetlni32)] = .{
        .llvm_name = "slow-vgetlni32",
        .description = "Has slow VGETLNi32 - prefer VMOV",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slowfpvfmx)] = .{
        .llvm_name = "slowfpvfmx",
        .description = "Disable VFP / NEON FMA instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slowfpvmlx)] = .{
        .llvm_name = "slowfpvmlx",
        .description = "Disable VFP / NEON MAC instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.soft_float)] = .{
        .llvm_name = "soft-float",
        .description = "Use software floating point features.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.splat_vfp_neon)] = .{
        .llvm_name = "splat-vfp-neon",
        .description = "Splat register from VFP to NEON",
        .dependencies = featureSet(&[_]Feature{
            .dont_widen_vmovs,
        }),
    };
    result[@intFromEnum(Feature.strict_align)] = .{
        .llvm_name = "strict-align",
        .description = "Disallow all unaligned memory access",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.thumb2)] = .{
        .llvm_name = "thumb2",
        .description = "Enable Thumb2 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.thumb_mode)] = .{
        .llvm_name = "thumb-mode",
        .description = "Thumb mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.trustzone)] = .{
        .llvm_name = "trustzone",
        .description = "Enable support for TrustZone security extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_mipipeliner)] = .{
        .llvm_name = "use-mipipeliner",
        .description = "Use the MachinePipeliner",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_misched)] = .{
        .llvm_name = "use-misched",
        .description = "Use the MachineScheduler",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v2)] = .{
        .llvm_name = null,
        .description = "ARMv2 architecture",
        .dependencies = featureSet(&[_]Feature{
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v2a)] = .{
        .llvm_name = null,
        .description = "ARMv2a architecture",
        .dependencies = featureSet(&[_]Feature{
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v3)] = .{
        .llvm_name = null,
        .description = "ARMv3 architecture",
        .dependencies = featureSet(&[_]Feature{
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v3m)] = .{
        .llvm_name = null,
        .description = "ARMv3m architecture",
        .dependencies = featureSet(&[_]Feature{
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v4)] = .{
        .llvm_name = "armv4",
        .description = "ARMv4 architecture",
        .dependencies = featureSet(&[_]Feature{
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v4t)] = .{
        .llvm_name = "armv4t",
        .description = "ARMv4t architecture",
        .dependencies = featureSet(&[_]Feature{
            .has_v4t,
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v5t)] = .{
        .llvm_name = "armv5t",
        .description = "ARMv5t architecture",
        .dependencies = featureSet(&[_]Feature{
            .has_v5t,
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v5te)] = .{
        .llvm_name = "armv5te",
        .description = "ARMv5te architecture",
        .dependencies = featureSet(&[_]Feature{
            .has_v5te,
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v5tej)] = .{
        .llvm_name = "armv5tej",
        .description = "ARMv5tej architecture",
        .dependencies = featureSet(&[_]Feature{
            .has_v5te,
            .strict_align,
        }),
    };
    result[@intFromEnum(Feature.v6)] = .{
        .llvm_name = "armv6",
        .description = "ARMv6 architecture",
        .dependencies = featureSet(&[_]Feature{
            .dsp,
            .has_v6,
        }),
    };
    result[@intFromEnum(Feature.v6j)] = .{
        .llvm_name = "armv6j",
        .description = "ARMv7a architecture",
        .dependencies = featureSet(&[_]Feature{
            .v6,
        }),
    };
    result[@intFromEnum(Feature.v6k)] = .{
        .llvm_name = "armv6k",
        .description = "ARMv6k architecture",
        .dependencies = featureSet(&[_]Feature{
            .has_v6k,
        }),
    };
    result[@intFromEnum(Feature.v6kz)] = .{
        .llvm_name = "armv6kz",
        .description = "ARMv6kz architecture",
        .dependencies = featureSet(&[_]Feature{
            .has_v6k,
            .trustzone,
        }),
    };
    result[@intFromEnum(Feature.v6m)] = .{
        .llvm_name = "armv6-m",
        .description = "ARMv6m architecture",
        .dependencies = featureSet(&[_]Feature{
            .db,
            .has_v6m,
            .mclass,
            .noarm,
            .strict_align,
            .thumb_mode,
        }),
    };
    result[@intFromEnum(Feature.v6sm)] = .{
        .llvm_name = "armv6s-m",
        .description = "ARMv6sm architecture",
        .dependencies = featureSet(&[_]Feature{
            .db,
            .has_v6m,
            .mclass,
            .noarm,
            .strict_align,
            .thumb_mode,
        }),
    };
    result[@intFromEnum(Feature.v6t2)] = .{
        .llvm_name = "armv6t2",
        .description = "ARMv6t2 architecture",
        .dependencies = featureSet(&[_]Feature{
            .dsp,
            .has_v6t2,
        }),
    };
    result[@intFromEnum(Feature.v7a)] = .{
        .llvm_name = "armv7-a",
        .description = "ARMv7a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .db,
            .dsp,
            .has_v7,
            .neon,
            .perfmon,
        }),
    };
    result[@intFromEnum(Feature.v7em)] = .{
        .llvm_name = "armv7e-m",
        .description = "ARMv7em architecture",
        .dependencies = featureSet(&[_]Feature{
            .db,
            .dsp,
            .has_v7,
            .hwdiv,
            .mclass,
            .noarm,
            .thumb_mode,
        }),
    };
    result[@intFromEnum(Feature.v7m)] = .{
        .llvm_name = "armv7-m",
        .description = "ARMv7m architecture",
        .dependencies = featureSet(&[_]Feature{
            .db,
            .has_v7,
            .hwdiv,
            .mclass,
            .noarm,
            .thumb_mode,
        }),
    };
    result[@intFromEnum(Feature.v7r)] = .{
        .llvm_name = "armv7-r",
        .description = "ARMv7r architecture",
        .dependencies = featureSet(&[_]Feature{
            .db,
            .dsp,
            .has_v7,
            .hwdiv,
            .perfmon,
            .rclass,
        }),
    };
    result[@intFromEnum(Feature.v7ve)] = .{
        .llvm_name = "armv7ve",
        .description = "ARMv7ve architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .db,
            .dsp,
            .has_v7,
            .mp,
            .neon,
            .perfmon,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_1a)] = .{
        .llvm_name = "armv8.1-a",
        .description = "ARMv81a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_1a,
            .mp,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_1m_main)] = .{
        .llvm_name = "armv8.1-m.main",
        .description = "ARMv81mMainline architecture",
        .dependencies = featureSet(&[_]Feature{
            .@"8msecext",
            .acquire_release,
            .db,
            .has_v8_1m_main,
            .hwdiv,
            .lob,
            .mclass,
            .noarm,
            .ras,
            .thumb_mode,
        }),
    };
    result[@intFromEnum(Feature.v8_2a)] = .{
        .llvm_name = "armv8.2-a",
        .description = "ARMv82a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_2a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_3a)] = .{
        .llvm_name = "armv8.3-a",
        .description = "ARMv83a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_3a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_4a)] = .{
        .llvm_name = "armv8.4-a",
        .description = "ARMv84a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_4a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_5a)] = .{
        .llvm_name = "armv8.5-a",
        .description = "ARMv85a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_5a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_6a)] = .{
        .llvm_name = "armv8.6-a",
        .description = "ARMv86a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_6a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_7a)] = .{
        .llvm_name = "armv8.7-a",
        .description = "ARMv87a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_7a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_8a)] = .{
        .llvm_name = "armv8.8-a",
        .description = "ARMv88a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_8a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8_9a)] = .{
        .llvm_name = "armv8.9-a",
        .description = "ARMv89a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8_9a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8a)] = .{
        .llvm_name = "armv8-a",
        .description = "ARMv8a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v8,
            .mp,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v8m)] = .{
        .llvm_name = "armv8-m.base",
        .description = "ARMv8mBaseline architecture",
        .dependencies = featureSet(&[_]Feature{
            .@"8msecext",
            .acquire_release,
            .db,
            .has_v7clrex,
            .has_v8m,
            .hwdiv,
            .mclass,
            .noarm,
            .strict_align,
            .thumb_mode,
        }),
    };
    result[@intFromEnum(Feature.v8m_main)] = .{
        .llvm_name = "armv8-m.main",
        .description = "ARMv8mMainline architecture",
        .dependencies = featureSet(&[_]Feature{
            .@"8msecext",
            .acquire_release,
            .db,
            .has_v8m_main,
            .hwdiv,
            .mclass,
            .noarm,
            .thumb_mode,
        }),
    };
    result[@intFromEnum(Feature.v8r)] = .{
        .llvm_name = "armv8-r",
        .description = "ARMv8r architecture",
        .dependencies = featureSet(&[_]Feature{
            .crc,
            .db,
            .dfb,
            .dsp,
            .fp_armv8d16sp,
            .has_v8,
            .mp,
            .rclass,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v9_1a)] = .{
        .llvm_name = "armv9.1-a",
        .description = "ARMv91a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .db,
            .dsp,
            .fp_armv8,
            .has_v9_1a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v9_2a)] = .{
        .llvm_name = "armv9.2-a",
        .description = "ARMv92a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .db,
            .dsp,
            .fp_armv8,
            .has_v9_2a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v9_3a)] = .{
        .llvm_name = "armv9.3-a",
        .description = "ARMv93a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .crypto,
            .db,
            .dsp,
            .fp_armv8,
            .has_v9_3a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v9_4a)] = .{
        .llvm_name = "armv9.4-a",
        .description = "ARMv94a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .db,
            .dsp,
            .fp_armv8,
            .has_v9_4a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v9_5a)] = .{
        .llvm_name = "armv9.5-a",
        .description = "ARMv95a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .db,
            .dsp,
            .fp_armv8,
            .has_v9_5a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v9_6a)] = .{
        .llvm_name = "armv9.6-a",
        .description = "ARMv96a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .db,
            .dsp,
            .fp_armv8,
            .has_v9_6a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.v9a)] = .{
        .llvm_name = "armv9-a",
        .description = "ARMv9a architecture",
        .dependencies = featureSet(&[_]Feature{
            .aclass,
            .crc,
            .db,
            .dsp,
            .fp_armv8,
            .has_v9a,
            .mp,
            .ras,
            .trustzone,
            .virtualization,
        }),
    };
    result[@intFromEnum(Feature.vfp2)] = .{
        .llvm_name = "vfp2",
        .description = "Enable VFP2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp64,
            .vfp2sp,
        }),
    };
    result[@intFromEnum(Feature.vfp2sp)] = .{
        .llvm_name = "vfp2sp",
        .description = "Enable VFP2 instructions with no double precision",
        .dependencies = featureSet(&[_]Feature{
            .fpregs,
        }),
    };
    result[@intFromEnum(Feature.vfp3)] = .{
        .llvm_name = "vfp3",
        .description = "Enable VFP3 instructions",
        .dependencies = featureSet(&[_]Feature{
            .vfp3d16,
            .vfp3sp,
        }),
    };
    result[@intFromEnum(Feature.vfp3d16)] = .{
        .llvm_name = "vfp3d16",
        .description = "Enable VFP3 instructions with only 16 d-registers",
        .dependencies = featureSet(&[_]Feature{
            .vfp2,
            .vfp3d16sp,
        }),
    };
    result[@intFromEnum(Feature.vfp3d16sp)] = .{
        .llvm_name = "vfp3d16sp",
        .description = "Enable VFP3 instructions with only 16 d-registers and no double precision",
        .dependencies = featureSet(&[_]Feature{
            .vfp2sp,
        }),
    };
    result[@intFromEnum(Feature.vfp3sp)] = .{
        .llvm_name = "vfp3sp",
        .description = "Enable VFP3 instructions with no double precision",
        .dependencies = featureSet(&[_]Feature{
            .d32,
            .vfp3d16sp,
        }),
    };
    result[@intFromEnum(Feature.vfp4)] = .{
        .llvm_name = "vfp4",
        .description = "Enable VFP4 instructions",
        .dependencies = featureSet(&[_]Feature{
            .vfp3,
            .vfp4d16,
            .vfp4sp,
        }),
    };
    result[@intFromEnum(Feature.vfp4d16)] = .{
        .llvm_name = "vfp4d16",
        .description = "Enable VFP4 instructions with only 16 d-registers",
        .dependencies = featureSet(&[_]Feature{
            .vfp3d16,
            .vfp4d16sp,
        }),
    };
    result[@intFromEnum(Feature.vfp4d16sp)] = .{
        .llvm_name = "vfp4d16sp",
        .description = "Enable VFP4 instructions with only 16 d-registers and no double precision",
        .dependencies = featureSet(&[_]Feature{
            .fp16,
            .vfp3d16sp,
        }),
    };
    result[@intFromEnum(Feature.vfp4sp)] = .{
        .llvm_name = "vfp4sp",
        .description = "Enable VFP4 instructions with no double precision",
        .dependencies = featureSet(&[_]Feature{
            .vfp3sp,
            .vfp4d16sp,
        }),
    };
    result[@intFromEnum(Feature.virtualization)] = .{
        .llvm_name = "virtualization",
        .description = "Supports Virtualization extension",
        .dependencies = featureSet(&[_]Feature{
            .hwdiv,
            .hwdiv_arm,
        }),
    };
    result[@intFromEnum(Feature.vldn_align)] = .{
        .llvm_name = "vldn-align",
        .description = "Check for VLDn unaligned access",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vmlx_forwarding)] = .{
        .llvm_name = "vmlx-forwarding",
        .description = "Has multiplier accumulator forwarding",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vmlx_hazards)] = .{
        .llvm_name = "vmlx-hazards",
        .description = "Has VMLx hazards",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.wide_stride_vfp)] = .{
        .llvm_name = "wide-stride-vfp",
        .description = "Use a wide stride when allocating VFP registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xscale)] = .{
        .llvm_name = "xscale",
        .description = "ARMv5te architecture",
        .dependencies = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    result[@intFromEnum(Feature.zcz)] = .{
        .llvm_name = "zcz",
        .description = "Has zero-cycle zeroing instructions",
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
    pub const arm1020e: CpuModel = .{
        .name = "arm1020e",
        .llvm_name = "arm1020e",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm1020t: CpuModel = .{
        .name = "arm1020t",
        .llvm_name = "arm1020t",
        .features = featureSet(&[_]Feature{
            .v5t,
        }),
    };
    pub const arm1022e: CpuModel = .{
        .name = "arm1022e",
        .llvm_name = "arm1022e",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm10e: CpuModel = .{
        .name = "arm10e",
        .llvm_name = "arm10e",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm10tdmi: CpuModel = .{
        .name = "arm10tdmi",
        .llvm_name = "arm10tdmi",
        .features = featureSet(&[_]Feature{
            .v5t,
        }),
    };
    pub const arm1136j_s: CpuModel = .{
        .name = "arm1136j_s",
        .llvm_name = "arm1136j-s",
        .features = featureSet(&[_]Feature{
            .v6,
        }),
    };
    pub const arm1136jf_s: CpuModel = .{
        .name = "arm1136jf_s",
        .llvm_name = "arm1136jf-s",
        .features = featureSet(&[_]Feature{
            .slowfpvmlx,
            .v6,
            .vfp2,
        }),
    };
    pub const arm1156t2_s: CpuModel = .{
        .name = "arm1156t2_s",
        .llvm_name = "arm1156t2-s",
        .features = featureSet(&[_]Feature{
            .v6t2,
        }),
    };
    pub const arm1156t2f_s: CpuModel = .{
        .name = "arm1156t2f_s",
        .llvm_name = "arm1156t2f-s",
        .features = featureSet(&[_]Feature{
            .slowfpvmlx,
            .v6t2,
            .vfp2,
        }),
    };
    pub const arm1176jz_s: CpuModel = .{
        .name = "arm1176jz_s",
        .llvm_name = "arm1176jz-s",
        .features = featureSet(&[_]Feature{
            .v6kz,
        }),
    };
    pub const arm1176jzf_s: CpuModel = .{
        .name = "arm1176jzf_s",
        .llvm_name = "arm1176jzf-s",
        .features = featureSet(&[_]Feature{
            .slowfpvmlx,
            .v6kz,
            .vfp2,
        }),
    };
    pub const arm710t: CpuModel = .{
        .name = "arm710t",
        .llvm_name = "arm710t",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm720t: CpuModel = .{
        .name = "arm720t",
        .llvm_name = "arm720t",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm7tdmi: CpuModel = .{
        .name = "arm7tdmi",
        .llvm_name = "arm7tdmi",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm7tdmi_s: CpuModel = .{
        .name = "arm7tdmi_s",
        .llvm_name = "arm7tdmi-s",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm8: CpuModel = .{
        .name = "arm8",
        .llvm_name = "arm8",
        .features = featureSet(&[_]Feature{
            .v4,
        }),
    };
    pub const arm810: CpuModel = .{
        .name = "arm810",
        .llvm_name = "arm810",
        .features = featureSet(&[_]Feature{
            .v4,
        }),
    };
    pub const arm9: CpuModel = .{
        .name = "arm9",
        .llvm_name = "arm9",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm920: CpuModel = .{
        .name = "arm920",
        .llvm_name = "arm920",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm920t: CpuModel = .{
        .name = "arm920t",
        .llvm_name = "arm920t",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm922t: CpuModel = .{
        .name = "arm922t",
        .llvm_name = "arm922t",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm926ej_s: CpuModel = .{
        .name = "arm926ej_s",
        .llvm_name = "arm926ej-s",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm940t: CpuModel = .{
        .name = "arm940t",
        .llvm_name = "arm940t",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const arm946e_s: CpuModel = .{
        .name = "arm946e_s",
        .llvm_name = "arm946e-s",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm966e_s: CpuModel = .{
        .name = "arm966e_s",
        .llvm_name = "arm966e-s",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm968e_s: CpuModel = .{
        .name = "arm968e_s",
        .llvm_name = "arm968e-s",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm9e: CpuModel = .{
        .name = "arm9e",
        .llvm_name = "arm9e",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const arm9tdmi: CpuModel = .{
        .name = "arm9tdmi",
        .llvm_name = "arm9tdmi",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const baseline: CpuModel = .{
        .name = "baseline",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .v7a,
        }),
    };
    pub const cortex_a12: CpuModel = .{
        .name = "cortex_a12",
        .llvm_name = "cortex-a12",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .mp,
            .ret_addr_stack,
            .trustzone,
            .v7a,
            .vfp4,
            .virtualization,
            .vmlx_forwarding,
        }),
    };
    pub const cortex_a15: CpuModel = .{
        .name = "cortex_a15",
        .llvm_name = "cortex-a15",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .mp,
            .muxed_units,
            .ret_addr_stack,
            .splat_vfp_neon,
            .trustzone,
            .v7a,
            .vfp4,
            .virtualization,
            .vldn_align,
        }),
    };
    pub const cortex_a17: CpuModel = .{
        .name = "cortex_a17",
        .llvm_name = "cortex-a17",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .mp,
            .ret_addr_stack,
            .trustzone,
            .v7a,
            .vfp4,
            .virtualization,
            .vmlx_forwarding,
        }),
    };
    pub const cortex_a32: CpuModel = .{
        .name = "cortex_a32",
        .llvm_name = "cortex-a32",
        .features = featureSet(&[_]Feature{
            .v8a,
        }),
    };
    pub const cortex_a35: CpuModel = .{
        .name = "cortex_a35",
        .llvm_name = "cortex-a35",
        .features = featureSet(&[_]Feature{
            .v8a,
        }),
    };
    pub const cortex_a5: CpuModel = .{
        .name = "cortex_a5",
        .llvm_name = "cortex-a5",
        .features = featureSet(&[_]Feature{
            .mp,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slowfpvfmx,
            .slowfpvmlx,
            .trustzone,
            .v7a,
            .vfp4,
            .vmlx_forwarding,
        }),
    };
    pub const cortex_a510: CpuModel = .{
        .name = "cortex_a510",
        .llvm_name = "cortex-a510",
        .features = featureSet(&[_]Feature{
            .bf16,
            .fp16fml,
            .i8mm,
            .v9a,
        }),
    };
    pub const cortex_a53: CpuModel = .{
        .name = "cortex_a53",
        .llvm_name = "cortex-a53",
        .features = featureSet(&[_]Feature{
            .fpao,
            .v8a,
        }),
    };
    pub const cortex_a55: CpuModel = .{
        .name = "cortex_a55",
        .llvm_name = "cortex-a55",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .v8_2a,
        }),
    };
    pub const cortex_a57: CpuModel = .{
        .name = "cortex_a57",
        .llvm_name = "cortex-a57",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .cheap_predicable_cpsr,
            .fix_cortex_a57_aes_1742098,
            .fpao,
            .v8a,
        }),
    };
    pub const cortex_a7: CpuModel = .{
        .name = "cortex_a7",
        .llvm_name = "cortex-a7",
        .features = featureSet(&[_]Feature{
            .mp,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slowfpvfmx,
            .slowfpvmlx,
            .trustzone,
            .v7a,
            .vfp4,
            .virtualization,
            .vmlx_forwarding,
            .vmlx_hazards,
        }),
    };
    pub const cortex_a710: CpuModel = .{
        .name = "cortex_a710",
        .llvm_name = "cortex-a710",
        .features = featureSet(&[_]Feature{
            .bf16,
            .fp16fml,
            .i8mm,
            .v9a,
        }),
    };
    pub const cortex_a72: CpuModel = .{
        .name = "cortex_a72",
        .llvm_name = "cortex-a72",
        .features = featureSet(&[_]Feature{
            .fix_cortex_a57_aes_1742098,
            .v8a,
        }),
    };
    pub const cortex_a73: CpuModel = .{
        .name = "cortex_a73",
        .llvm_name = "cortex-a73",
        .features = featureSet(&[_]Feature{
            .v8a,
        }),
    };
    pub const cortex_a75: CpuModel = .{
        .name = "cortex_a75",
        .llvm_name = "cortex-a75",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .v8_2a,
        }),
    };
    pub const cortex_a76: CpuModel = .{
        .name = "cortex_a76",
        .llvm_name = "cortex-a76",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cortex_a76ae: CpuModel = .{
        .name = "cortex_a76ae",
        .llvm_name = "cortex-a76ae",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cortex_a77: CpuModel = .{
        .name = "cortex_a77",
        .llvm_name = "cortex-a77",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cortex_a78: CpuModel = .{
        .name = "cortex_a78",
        .llvm_name = "cortex-a78",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cortex_a78ae: CpuModel = .{
        .name = "cortex_a78ae",
        .llvm_name = "cortex-a78ae",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cortex_a78c: CpuModel = .{
        .name = "cortex_a78c",
        .llvm_name = "cortex-a78c",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cortex_a8: CpuModel = .{
        .name = "cortex_a8",
        .llvm_name = "cortex-a8",
        .features = featureSet(&[_]Feature{
            .nonpipelined_vfp,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slowfpvfmx,
            .slowfpvmlx,
            .trustzone,
            .v7a,
            .vmlx_forwarding,
            .vmlx_hazards,
        }),
    };
    pub const cortex_a9: CpuModel = .{
        .name = "cortex_a9",
        .llvm_name = "cortex-a9",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .expand_fp_mlx,
            .fp16,
            .mp,
            .muxed_units,
            .neon_fpmovs,
            .prefer_vmovsr,
            .ret_addr_stack,
            .trustzone,
            .v7a,
            .vldn_align,
            .vmlx_forwarding,
            .vmlx_hazards,
        }),
    };
    pub const cortex_m0: CpuModel = .{
        .name = "cortex_m0",
        .llvm_name = "cortex-m0",
        .features = featureSet(&[_]Feature{
            .no_branch_predictor,
            .v6m,
        }),
    };
    pub const cortex_m0plus: CpuModel = .{
        .name = "cortex_m0plus",
        .llvm_name = "cortex-m0plus",
        .features = featureSet(&[_]Feature{
            .no_branch_predictor,
            .v6m,
        }),
    };
    pub const cortex_m1: CpuModel = .{
        .name = "cortex_m1",
        .llvm_name = "cortex-m1",
        .features = featureSet(&[_]Feature{
            .no_branch_predictor,
            .v6m,
        }),
    };
    pub const cortex_m23: CpuModel = .{
        .name = "cortex_m23",
        .llvm_name = "cortex-m23",
        .features = featureSet(&[_]Feature{
            .no_branch_predictor,
            .no_movt,
            .v8m,
        }),
    };
    pub const cortex_m3: CpuModel = .{
        .name = "cortex_m3",
        .llvm_name = "cortex-m3",
        .features = featureSet(&[_]Feature{
            .loop_align,
            .no_branch_predictor,
            .use_misched,
            .v7m,
        }),
    };
    pub const cortex_m33: CpuModel = .{
        .name = "cortex_m33",
        .llvm_name = "cortex-m33",
        .features = featureSet(&[_]Feature{
            .avoid_muls,
            .fix_cmse_cve_2021_35465,
            .loop_align,
            .no_branch_predictor,
            .slowfpvfmx,
            .slowfpvmlx,
            .use_misched,
            .v8m_main,
        }),
    };
    pub const cortex_m35p: CpuModel = .{
        .name = "cortex_m35p",
        .llvm_name = "cortex-m35p",
        .features = featureSet(&[_]Feature{
            .fix_cmse_cve_2021_35465,
            .loop_align,
            .no_branch_predictor,
            .slowfpvfmx,
            .slowfpvmlx,
            .use_misched,
            .v8m_main,
        }),
    };
    pub const cortex_m4: CpuModel = .{
        .name = "cortex_m4",
        .llvm_name = "cortex-m4",
        .features = featureSet(&[_]Feature{
            .loop_align,
            .no_branch_predictor,
            .slowfpvfmx,
            .slowfpvmlx,
            .use_misched,
            .v7em,
        }),
    };
    pub const cortex_m52: CpuModel = .{
        .name = "cortex_m52",
        .llvm_name = "cortex-m52",
        .features = featureSet(&[_]Feature{
            .fp_armv8d16,
            .loop_align,
            .mve1beat,
            .mve_fp,
            .no_branch_predictor,
            .pacbti,
            .slowfpvmlx,
            .use_misched,
            .v8_1m_main,
        }),
    };
    pub const cortex_m55: CpuModel = .{
        .name = "cortex_m55",
        .llvm_name = "cortex-m55",
        .features = featureSet(&[_]Feature{
            .dsp,
            .fix_cmse_cve_2021_35465,
            .loop_align,
            .m55,
            .no_branch_predictor,
            .slowfpvmlx,
            .use_misched,
            .v8_1m_main,
        }),
    };
    pub const cortex_m7: CpuModel = .{
        .name = "cortex_m7",
        .llvm_name = "cortex-m7",
        .features = featureSet(&[_]Feature{
            .branch_align_64,
            .use_mipipeliner,
            .use_misched,
            .v7em,
        }),
    };
    pub const cortex_m85: CpuModel = .{
        .name = "cortex_m85",
        .llvm_name = "cortex-m85",
        .features = featureSet(&[_]Feature{
            .branch_align_64,
            .dsp,
            .m85,
            .use_misched,
            .v8_1m_main,
        }),
    };
    pub const cortex_r4: CpuModel = .{
        .name = "cortex_r4",
        .llvm_name = "cortex-r4",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .ret_addr_stack,
            .v7r,
        }),
    };
    pub const cortex_r4f: CpuModel = .{
        .name = "cortex_r4f",
        .llvm_name = "cortex-r4f",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slowfpvfmx,
            .slowfpvmlx,
            .v7r,
            .vfp3d16,
        }),
    };
    pub const cortex_r5: CpuModel = .{
        .name = "cortex_r5",
        .llvm_name = "cortex-r5",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .hwdiv_arm,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slowfpvfmx,
            .slowfpvmlx,
            .v7r,
            .vfp3d16,
        }),
    };
    pub const cortex_r52: CpuModel = .{
        .name = "cortex_r52",
        .llvm_name = "cortex-r52",
        .features = featureSet(&[_]Feature{
            .fp_armv8,
            .fpao,
            .neon,
            .use_misched,
            .v8r,
        }),
    };
    pub const cortex_r52plus: CpuModel = .{
        .name = "cortex_r52plus",
        .llvm_name = "cortex-r52plus",
        .features = featureSet(&[_]Feature{
            .fp_armv8,
            .fpao,
            .neon,
            .use_misched,
            .v8r,
        }),
    };
    pub const cortex_r7: CpuModel = .{
        .name = "cortex_r7",
        .llvm_name = "cortex-r7",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .fp16,
            .hwdiv_arm,
            .mp,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slowfpvfmx,
            .slowfpvmlx,
            .v7r,
            .vfp3d16,
        }),
    };
    pub const cortex_r8: CpuModel = .{
        .name = "cortex_r8",
        .llvm_name = "cortex-r8",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .fp16,
            .hwdiv_arm,
            .mp,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slowfpvfmx,
            .slowfpvmlx,
            .v7r,
            .vfp3d16,
        }),
    };
    pub const cortex_x1: CpuModel = .{
        .name = "cortex_x1",
        .llvm_name = "cortex-x1",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cortex_x1c: CpuModel = .{
        .name = "cortex_x1c",
        .llvm_name = "cortex-x1c",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .fullfp16,
            .v8_2a,
        }),
    };
    pub const cyclone: CpuModel = .{
        .name = "cyclone",
        .llvm_name = "cyclone",
        .features = featureSet(&[_]Feature{
            .avoid_movs_shop,
            .avoid_partial_cpsr,
            .disable_postra_scheduler,
            .neonfp,
            .ret_addr_stack,
            .slowfpvfmx,
            .slowfpvmlx,
            .use_misched,
            .v8a,
            .zcz,
        }),
    };
    pub const ep9312: CpuModel = .{
        .name = "ep9312",
        .llvm_name = "ep9312",
        .features = featureSet(&[_]Feature{
            .v4t,
        }),
    };
    pub const exynos_m1: CpuModel = .{
        .name = "exynos_m1",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .expand_fp_mlx,
            .fuse_aes,
            .fuse_literals,
            .prof_unpr,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slow_vdup32,
            .slow_vgetlni32,
            .slowfpvfmx,
            .slowfpvmlx,
            .splat_vfp_neon,
            .v8a,
            .wide_stride_vfp,
            .zcz,
        }),
    };
    pub const exynos_m2: CpuModel = .{
        .name = "exynos_m2",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .expand_fp_mlx,
            .fuse_aes,
            .fuse_literals,
            .prof_unpr,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slow_vdup32,
            .slow_vgetlni32,
            .slowfpvfmx,
            .slowfpvmlx,
            .splat_vfp_neon,
            .v8a,
            .wide_stride_vfp,
            .zcz,
        }),
    };
    pub const exynos_m3: CpuModel = .{
        .name = "exynos_m3",
        .llvm_name = "exynos-m3",
        .features = featureSet(&[_]Feature{
            .expand_fp_mlx,
            .fuse_aes,
            .fuse_literals,
            .prof_unpr,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slow_vdup32,
            .slow_vgetlni32,
            .slowfpvfmx,
            .slowfpvmlx,
            .splat_vfp_neon,
            .v8a,
            .wide_stride_vfp,
            .zcz,
        }),
    };
    pub const exynos_m4: CpuModel = .{
        .name = "exynos_m4",
        .llvm_name = "exynos-m4",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .expand_fp_mlx,
            .fullfp16,
            .fuse_aes,
            .fuse_literals,
            .prof_unpr,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slow_vdup32,
            .slow_vgetlni32,
            .slowfpvfmx,
            .slowfpvmlx,
            .splat_vfp_neon,
            .v8_2a,
            .wide_stride_vfp,
            .zcz,
        }),
    };
    pub const exynos_m5: CpuModel = .{
        .name = "exynos_m5",
        .llvm_name = "exynos-m5",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .expand_fp_mlx,
            .fullfp16,
            .fuse_aes,
            .fuse_literals,
            .prof_unpr,
            .ret_addr_stack,
            .slow_fp_brcc,
            .slow_vdup32,
            .slow_vgetlni32,
            .slowfpvfmx,
            .slowfpvmlx,
            .splat_vfp_neon,
            .v8_2a,
            .wide_stride_vfp,
            .zcz,
        }),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{}),
    };
    pub const iwmmxt: CpuModel = .{
        .name = "iwmmxt",
        .llvm_name = "iwmmxt",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
    pub const krait: CpuModel = .{
        .name = "krait",
        .llvm_name = "krait",
        .features = featureSet(&[_]Feature{
            .avoid_partial_cpsr,
            .hwdiv,
            .hwdiv_arm,
            .muxed_units,
            .ret_addr_stack,
            .v7a,
            .vfp4,
            .vldn_align,
            .vmlx_forwarding,
        }),
    };
    pub const kryo: CpuModel = .{
        .name = "kryo",
        .llvm_name = "kryo",
        .features = featureSet(&[_]Feature{
            .v8a,
        }),
    };
    pub const mpcore: CpuModel = .{
        .name = "mpcore",
        .llvm_name = "mpcore",
        .features = featureSet(&[_]Feature{
            .slowfpvmlx,
            .v6k,
            .vfp2,
        }),
    };
    pub const mpcorenovfp: CpuModel = .{
        .name = "mpcorenovfp",
        .llvm_name = "mpcorenovfp",
        .features = featureSet(&[_]Feature{
            .v6k,
        }),
    };
    pub const neoverse_n1: CpuModel = .{
        .name = "neoverse_n1",
        .llvm_name = "neoverse-n1",
        .features = featureSet(&[_]Feature{
            .dotprod,
            .v8_2a,
        }),
    };
    pub const neoverse_n2: CpuModel = .{
        .name = "neoverse_n2",
        .llvm_name = "neoverse-n2",
        .features = featureSet(&[_]Feature{
            .bf16,
            .fp16fml,
            .i8mm,
            .v9a,
        }),
    };
    pub const neoverse_v1: CpuModel = .{
        .name = "neoverse_v1",
        .llvm_name = "neoverse-v1",
        .features = featureSet(&[_]Feature{
            .bf16,
            .fullfp16,
            .i8mm,
            .v8_4a,
        }),
    };
    pub const sc000: CpuModel = .{
        .name = "sc000",
        .llvm_name = "sc000",
        .features = featureSet(&[_]Feature{
            .no_branch_predictor,
            .v6m,
        }),
    };
    pub const sc300: CpuModel = .{
        .name = "sc300",
        .llvm_name = "sc300",
        .features = featureSet(&[_]Feature{
            .no_branch_predictor,
            .use_misched,
            .v7m,
        }),
    };
    pub const star_mc1: CpuModel = .{
        .name = "star_mc1",
        .llvm_name = "star-mc1",
        .features = featureSet(&[_]Feature{
            .dsp,
            .fix_cmse_cve_2021_35465,
            .fp_armv8d16sp,
            .loop_align,
            .no_branch_predictor,
            .slowfpvfmx,
            .slowfpvmlx,
            .use_misched,
            .v8m_main,
        }),
    };
    pub const strongarm: CpuModel = .{
        .name = "strongarm",
        .llvm_name = "strongarm",
        .features = featureSet(&[_]Feature{
            .v4,
        }),
    };
    pub const strongarm110: CpuModel = .{
        .name = "strongarm110",
        .llvm_name = "strongarm110",
        .features = featureSet(&[_]Feature{
            .v4,
        }),
    };
    pub const strongarm1100: CpuModel = .{
        .name = "strongarm1100",
        .llvm_name = "strongarm1100",
        .features = featureSet(&[_]Feature{
            .v4,
        }),
    };
    pub const strongarm1110: CpuModel = .{
        .name = "strongarm1110",
        .llvm_name = "strongarm1110",
        .features = featureSet(&[_]Feature{
            .v4,
        }),
    };
    pub const swift: CpuModel = .{
        .name = "swift",
        .llvm_name = "swift",
        .features = featureSet(&[_]Feature{
            .avoid_movs_shop,
            .avoid_partial_cpsr,
            .disable_postra_scheduler,
            .hwdiv,
            .hwdiv_arm,
            .mp,
            .neonfp,
            .prefer_ishst,
            .prof_unpr,
            .ret_addr_stack,
            .slow_load_D_subreg,
            .slow_odd_reg,
            .slow_vdup32,
            .slow_vgetlni32,
            .slowfpvfmx,
            .slowfpvmlx,
            .use_misched,
            .v7a,
            .vfp4,
            .vmlx_hazards,
            .wide_stride_vfp,
        }),
    };
    pub const xscale: CpuModel = .{
        .name = "xscale",
        .llvm_name = "xscale",
        .features = featureSet(&[_]Feature{
            .v5te,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    addsubiw,
    avr0,
    avr1,
    avr2,
    avr25,
    avr3,
    avr31,
    avr35,
    avr4,
    avr5,
    avr51,
    avr6,
    avrtiny,
    @"break",
    des,
    eijmpcall,
    elpm,
    elpmx,
    ijmpcall,
    jmpcall,
    lowbytefirst,
    lpm,
    lpmx,
    memmappedregs,
    movw,
    mul,
    rmw,
    smallstack,
    special,
    spm,
    spmx,
    sram,
    tinyencoding,
    wrappingrjmp,
    xmega,
    xmega3,
    xmegau,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.addsubiw)] = .{
        .llvm_name = "addsubiw",
        .description = "Enable 16-bit register-immediate addition and subtraction instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.avr0)] = .{
        .llvm_name = "avr0",
        .description = "The device is a part of the avr0 family",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.avr1)] = .{
        .llvm_name = "avr1",
        .description = "The device is a part of the avr1 family",
        .dependencies = featureSet(&[_]Feature{
            .avr0,
            .lpm,
            .memmappedregs,
        }),
    };
    result[@intFromEnum(Feature.avr2)] = .{
        .llvm_name = "avr2",
        .description = "The device is a part of the avr2 family",
        .dependencies = featureSet(&[_]Feature{
            .addsubiw,
            .avr1,
            .ijmpcall,
            .sram,
        }),
    };
    result[@intFromEnum(Feature.avr25)] = .{
        .llvm_name = "avr25",
        .description = "The device is a part of the avr25 family",
        .dependencies = featureSet(&[_]Feature{
            .avr2,
            .@"break",
            .lpmx,
            .movw,
            .spm,
        }),
    };
    result[@intFromEnum(Feature.avr3)] = .{
        .llvm_name = "avr3",
        .description = "The device is a part of the avr3 family",
        .dependencies = featureSet(&[_]Feature{
            .avr2,
            .jmpcall,
        }),
    };
    result[@intFromEnum(Feature.avr31)] = .{
        .llvm_name = "avr31",
        .description = "The device is a part of the avr31 family",
        .dependencies = featureSet(&[_]Feature{
            .avr3,
            .elpm,
        }),
    };
    result[@intFromEnum(Feature.avr35)] = .{
        .llvm_name = "avr35",
        .description = "The device is a part of the avr35 family",
        .dependencies = featureSet(&[_]Feature{
            .avr3,
            .@"break",
            .lpmx,
            .movw,
            .spm,
        }),
    };
    result[@intFromEnum(Feature.avr4)] = .{
        .llvm_name = "avr4",
        .description = "The device is a part of the avr4 family",
        .dependencies = featureSet(&[_]Feature{
            .avr2,
            .@"break",
            .lpmx,
            .movw,
            .mul,
            .spm,
        }),
    };
    result[@intFromEnum(Feature.avr5)] = .{
        .llvm_name = "avr5",
        .description = "The device is a part of the avr5 family",
        .dependencies = featureSet(&[_]Feature{
            .avr3,
            .@"break",
            .lpmx,
            .movw,
            .mul,
            .spm,
        }),
    };
    result[@intFromEnum(Feature.avr51)] = .{
        .llvm_name = "avr51",
        .description = "The device is a part of the avr51 family",
        .dependencies = featureSet(&[_]Feature{
            .avr5,
            .elpm,
            .elpmx,
        }),
    };
    result[@intFromEnum(Feature.avr6)] = .{
        .llvm_name = "avr6",
        .description = "The device is a part of the avr6 family",
        .dependencies = featureSet(&[_]Feature{
            .avr51,
            .eijmpcall,
        }),
    };
    result[@intFromEnum(Feature.avrtiny)] = .{
        .llvm_name = "avrtiny",
        .description = "The device is a part of the avrtiny family",
        .dependencies = featureSet(&[_]Feature{
            .avr0,
            .@"break",
            .smallstack,
            .sram,
            .tinyencoding,
        }),
    };
    result[@intFromEnum(Feature.@"break")] = .{
        .llvm_name = "break",
        .description = "The device supports the `BREAK` debugging instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.des)] = .{
        .llvm_name = "des",
        .description = "The device supports the `DES k` encryption instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.eijmpcall)] = .{
        .llvm_name = "eijmpcall",
        .description = "The device supports the `EIJMP`/`EICALL` instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.elpm)] = .{
        .llvm_name = "elpm",
        .description = "The device supports the ELPM instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.elpmx)] = .{
        .llvm_name = "elpmx",
        .description = "The device supports the `ELPM Rd, Z[+]` instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ijmpcall)] = .{
        .llvm_name = "ijmpcall",
        .description = "The device supports `IJMP`/`ICALL`instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.jmpcall)] = .{
        .llvm_name = "jmpcall",
        .description = "The device supports the `JMP` and `CALL` instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lowbytefirst)] = .{
        .llvm_name = "lowbytefirst",
        .description = "Do the low byte first when writing a 16-bit port or storing a 16-bit word",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lpm)] = .{
        .llvm_name = "lpm",
        .description = "The device supports the `LPM` instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lpmx)] = .{
        .llvm_name = "lpmx",
        .description = "The device supports the `LPM Rd, Z[+]` instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.memmappedregs)] = .{
        .llvm_name = "memmappedregs",
        .description = "The device has CPU registers mapped in data address space",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.movw)] = .{
        .llvm_name = "movw",
        .description = "The device supports the 16-bit MOVW instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mul)] = .{
        .llvm_name = "mul",
        .description = "The device supports the multiplication instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rmw)] = .{
        .llvm_name = "rmw",
        .description = "The device supports the read-write-modify instructions: XCH, LAS, LAC, LAT",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smallstack)] = .{
        .llvm_name = "smallstack",
        .description = "The device has an 8-bit stack pointer",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.special)] = .{
        .llvm_name = "special",
        .description = "Enable use of the entire instruction set - used for debugging",
        .dependencies = featureSet(&[_]Feature{
            .addsubiw,
            .@"break",
            .des,
            .eijmpcall,
            .elpm,
            .elpmx,
            .ijmpcall,
            .jmpcall,
            .lpm,
            .lpmx,
            .memmappedregs,
            .movw,
            .mul,
            .rmw,
            .spm,
            .spmx,
            .sram,
        }),
    };
    result[@intFromEnum(Feature.spm)] = .{
        .llvm_name = "spm",
        .description = "The device supports the `SPM` instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.spmx)] = .{
        .llvm_name = "spmx",
        .description = "The device supports the `SPM Z+` instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sram)] = .{
        .llvm_name = "sram",
        .description = "The device has random access memory",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tinyencoding)] = .{
        .llvm_name = "tinyencoding",
        .description = "The device has Tiny core specific instruction encodings",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.wrappingrjmp)] = .{
        .llvm_name = "wrappingrjmp",
        .description = "The device potentially requires emitting rjmp that wraps across the flash boundary",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xmega)] = .{
        .llvm_name = "xmega",
        .description = "The device is a part of the xmega family",
        .dependencies = featureSet(&[_]Feature{
            .addsubiw,
            .avr0,
            .@"break",
            .des,
            .eijmpcall,
            .elpm,
            .elpmx,
            .ijmpcall,
            .jmpcall,
            .lowbytefirst,
            .lpm,
            .lpmx,
            .movw,
            .mul,
            .spm,
            .spmx,
            .sram,
        }),
    };
    result[@intFromEnum(Feature.xmega3)] = .{
        .llvm_name = "xmega3",
        .description = "The device is a part of the xmega3 family",
        .dependencies = featureSet(&[_]Feature{
            .addsubiw,
            .avr0,
            .@"break",
            .ijmpcall,
            .jmpcall,
            .lowbytefirst,
            .lpm,
            .lpmx,
            .movw,
            .mul,
            .sram,
        }),
    };
    result[@intFromEnum(Feature.xmegau)] = .{
        .llvm_name = "xmegau",
        .description = "The device is a part of the xmegau family",
        .dependencies = featureSet(&[_]Feature{
            .rmw,
            .xmega,
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
    pub const at43usb320: CpuModel = .{
        .name = "at43usb320",
        .llvm_name = "at43usb320",
        .features = featureSet(&[_]Feature{
            .avr31,
        }),
    };
    pub const at43usb355: CpuModel = .{
        .name = "at43usb355",
        .llvm_name = "at43usb355",
        .features = featureSet(&[_]Feature{
            .avr3,
        }),
    };
    pub const at76c711: CpuModel = .{
        .name = "at76c711",
        .llvm_name = "at76c711",
        .features = featureSet(&[_]Feature{
            .avr3,
        }),
    };
    pub const at86rf401: CpuModel = .{
        .name = "at86rf401",
        .llvm_name = "at86rf401",
        .features = featureSet(&[_]Feature{
            .avr2,
            .lpmx,
            .movw,
        }),
    };
    pub const at90c8534: CpuModel = .{
        .name = "at90c8534",
        .llvm_name = "at90c8534",
        .features = featureSet(&[_]Feature{
            .avr2,
            .wrappingrjmp,
        }),
    };
    pub const at90can128: CpuModel = .{
        .name = "at90can128",
        .llvm_name = "at90can128",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const at90can32: CpuModel = .{
        .name = "at90can32",
        .llvm_name = "at90can32",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90can64: CpuModel = .{
        .name = "at90can64",
        .llvm_name = "at90can64",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90pwm1: CpuModel = .{
        .name = "at90pwm1",
        .llvm_name = "at90pwm1",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const at90pwm161: CpuModel = .{
        .name = "at90pwm161",
        .llvm_name = "at90pwm161",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90pwm2: CpuModel = .{
        .name = "at90pwm2",
        .llvm_name = "at90pwm2",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const at90pwm216: CpuModel = .{
        .name = "at90pwm216",
        .llvm_name = "at90pwm216",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90pwm2b: CpuModel = .{
        .name = "at90pwm2b",
        .llvm_name = "at90pwm2b",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const at90pwm3: CpuModel = .{
        .name = "at90pwm3",
        .llvm_name = "at90pwm3",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const at90pwm316: CpuModel = .{
        .name = "at90pwm316",
        .llvm_name = "at90pwm316",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90pwm3b: CpuModel = .{
        .name = "at90pwm3b",
        .llvm_name = "at90pwm3b",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const at90pwm81: CpuModel = .{
        .name = "at90pwm81",
        .llvm_name = "at90pwm81",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const at90s1200: CpuModel = .{
        .name = "at90s1200",
        .llvm_name = "at90s1200",
        .features = featureSet(&[_]Feature{
            .avr0,
            .smallstack,
        }),
    };
    pub const at90s2313: CpuModel = .{
        .name = "at90s2313",
        .llvm_name = "at90s2313",
        .features = featureSet(&[_]Feature{
            .avr2,
            .smallstack,
        }),
    };
    pub const at90s2323: CpuModel = .{
        .name = "at90s2323",
        .llvm_name = "at90s2323",
        .features = featureSet(&[_]Feature{
            .avr2,
            .smallstack,
        }),
    };
    pub const at90s2333: CpuModel = .{
        .name = "at90s2333",
        .llvm_name = "at90s2333",
        .features = featureSet(&[_]Feature{
            .avr2,
            .smallstack,
        }),
    };
    pub const at90s2343: CpuModel = .{
        .name = "at90s2343",
        .llvm_name = "at90s2343",
        .features = featureSet(&[_]Feature{
            .avr2,
            .smallstack,
        }),
    };
    pub const at90s4414: CpuModel = .{
        .name = "at90s4414",
        .llvm_name = "at90s4414",
        .features = featureSet(&[_]Feature{
            .avr2,
            .smallstack,
        }),
    };
    pub const at90s4433: CpuModel = .{
        .name = "at90s4433",
        .llvm_name = "at90s4433",
        .features = featureSet(&[_]Feature{
            .avr2,
            .smallstack,
        }),
    };
    pub const at90s4434: CpuModel = .{
        .name = "at90s4434",
        .llvm_name = "at90s4434",
        .features = featureSet(&[_]Feature{
            .avr2,
            .smallstack,
        }),
    };
    pub const at90s8515: CpuModel = .{
        .name = "at90s8515",
        .llvm_name = "at90s8515",
        .features = featureSet(&[_]Feature{
            .avr2,
            .wrappingrjmp,
        }),
    };
    pub const at90s8535: CpuModel = .{
        .name = "at90s8535",
        .llvm_name = "at90s8535",
        .features = featureSet(&[_]Feature{
            .avr2,
            .wrappingrjmp,
        }),
    };
    pub const at90scr100: CpuModel = .{
        .name = "at90scr100",
        .llvm_name = "at90scr100",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90usb1286: CpuModel = .{
        .name = "at90usb1286",
        .llvm_name = "at90usb1286",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const at90usb1287: CpuModel = .{
        .name = "at90usb1287",
        .llvm_name = "at90usb1287",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const at90usb162: CpuModel = .{
        .name = "at90usb162",
        .llvm_name = "at90usb162",
        .features = featureSet(&[_]Feature{
            .avr35,
        }),
    };
    pub const at90usb646: CpuModel = .{
        .name = "at90usb646",
        .llvm_name = "at90usb646",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90usb647: CpuModel = .{
        .name = "at90usb647",
        .llvm_name = "at90usb647",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const at90usb82: CpuModel = .{
        .name = "at90usb82",
        .llvm_name = "at90usb82",
        .features = featureSet(&[_]Feature{
            .avr35,
        }),
    };
    pub const at94k: CpuModel = .{
        .name = "at94k",
        .llvm_name = "at94k",
        .features = featureSet(&[_]Feature{
            .avr3,
            .lpmx,
            .movw,
            .mul,
        }),
    };
    pub const ata5272: CpuModel = .{
        .name = "ata5272",
        .llvm_name = "ata5272",
        .features = featureSet(&[_]Feature{
            .avr25,
            .wrappingrjmp,
        }),
    };
    pub const ata5505: CpuModel = .{
        .name = "ata5505",
        .llvm_name = "ata5505",
        .features = featureSet(&[_]Feature{
            .avr35,
        }),
    };
    pub const ata5702m322: CpuModel = .{
        .name = "ata5702m322",
        .llvm_name = "ata5702m322",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata5782: CpuModel = .{
        .name = "ata5782",
        .llvm_name = "ata5782",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata5790: CpuModel = .{
        .name = "ata5790",
        .llvm_name = "ata5790",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata5790n: CpuModel = .{
        .name = "ata5790n",
        .llvm_name = "ata5790n",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata5791: CpuModel = .{
        .name = "ata5791",
        .llvm_name = "ata5791",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata5795: CpuModel = .{
        .name = "ata5795",
        .llvm_name = "ata5795",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata5831: CpuModel = .{
        .name = "ata5831",
        .llvm_name = "ata5831",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata6285: CpuModel = .{
        .name = "ata6285",
        .llvm_name = "ata6285",
        .features = featureSet(&[_]Feature{
            .avr4,
            .wrappingrjmp,
        }),
    };
    pub const ata6286: CpuModel = .{
        .name = "ata6286",
        .llvm_name = "ata6286",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const ata6289: CpuModel = .{
        .name = "ata6289",
        .llvm_name = "ata6289",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const ata6612c: CpuModel = .{
        .name = "ata6612c",
        .llvm_name = "ata6612c",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const ata6613c: CpuModel = .{
        .name = "ata6613c",
        .llvm_name = "ata6613c",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata6614q: CpuModel = .{
        .name = "ata6614q",
        .llvm_name = "ata6614q",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata6616c: CpuModel = .{
        .name = "ata6616c",
        .llvm_name = "ata6616c",
        .features = featureSet(&[_]Feature{
            .avr25,
            .wrappingrjmp,
        }),
    };
    pub const ata6617c: CpuModel = .{
        .name = "ata6617c",
        .llvm_name = "ata6617c",
        .features = featureSet(&[_]Feature{
            .avr35,
        }),
    };
    pub const ata664251: CpuModel = .{
        .name = "ata664251",
        .llvm_name = "ata664251",
        .features = featureSet(&[_]Feature{
            .avr35,
        }),
    };
    pub const ata8210: CpuModel = .{
        .name = "ata8210",
        .llvm_name = "ata8210",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const ata8510: CpuModel = .{
        .name = "ata8510",
        .llvm_name = "ata8510",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega103: CpuModel = .{
        .name = "atmega103",
        .llvm_name = "atmega103",
        .features = featureSet(&[_]Feature{
            .avr31,
        }),
    };
    pub const atmega128: CpuModel = .{
        .name = "atmega128",
        .llvm_name = "atmega128",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega1280: CpuModel = .{
        .name = "atmega1280",
        .llvm_name = "atmega1280",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega1281: CpuModel = .{
        .name = "atmega1281",
        .llvm_name = "atmega1281",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega1284: CpuModel = .{
        .name = "atmega1284",
        .llvm_name = "atmega1284",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega1284p: CpuModel = .{
        .name = "atmega1284p",
        .llvm_name = "atmega1284p",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega1284rfr2: CpuModel = .{
        .name = "atmega1284rfr2",
        .llvm_name = "atmega1284rfr2",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega128a: CpuModel = .{
        .name = "atmega128a",
        .llvm_name = "atmega128a",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega128rfa1: CpuModel = .{
        .name = "atmega128rfa1",
        .llvm_name = "atmega128rfa1",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega128rfr2: CpuModel = .{
        .name = "atmega128rfr2",
        .llvm_name = "atmega128rfr2",
        .features = featureSet(&[_]Feature{
            .avr51,
        }),
    };
    pub const atmega16: CpuModel = .{
        .name = "atmega16",
        .llvm_name = "atmega16",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega1608: CpuModel = .{
        .name = "atmega1608",
        .llvm_name = "atmega1608",
        .features = featureSet(&[_]Feature{
            .xmega3,
        }),
    };
    pub const atmega1609: CpuModel = .{
        .name = "atmega1609",
        .llvm_name = "atmega1609",
        .features = featureSet(&[_]Feature{
            .xmega3,
        }),
    };
    pub const atmega161: CpuModel = .{
        .name = "atmega161",
        .llvm_name = "atmega161",
        .features = featureSet(&[_]Feature{
            .avr3,
            .lpmx,
            .movw,
            .mul,
            .spm,
        }),
    };
    pub const atmega162: CpuModel = .{
        .name = "atmega162",
        .llvm_name = "atmega162",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega163: CpuModel = .{
        .name = "atmega163",
        .llvm_name = "atmega163",
        .features = featureSet(&[_]Feature{
            .avr3,
            .lpmx,
            .movw,
            .mul,
            .spm,
        }),
    };
    pub const atmega164a: CpuModel = .{
        .name = "atmega164a",
        .llvm_name = "atmega164a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega164p: CpuModel = .{
        .name = "atmega164p",
        .llvm_name = "atmega164p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega164pa: CpuModel = .{
        .name = "atmega164pa",
        .llvm_name = "atmega164pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega165: CpuModel = .{
        .name = "atmega165",
        .llvm_name = "atmega165",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega165a: CpuModel = .{
        .name = "atmega165a",
        .llvm_name = "atmega165a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega165p: CpuModel = .{
        .name = "atmega165p",
        .llvm_name = "atmega165p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega165pa: CpuModel = .{
        .name = "atmega165pa",
        .llvm_name = "atmega165pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega168: CpuModel = .{
        .name = "atmega168",
        .llvm_name = "atmega168",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega168a: CpuModel = .{
        .name = "atmega168a",
        .llvm_name = "atmega168a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega168p: CpuModel = .{
        .name = "atmega168p",
        .llvm_name = "atmega168p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega168pa: CpuModel = .{
        .name = "atmega168pa",
        .llvm_name = "atmega168pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega168pb: CpuModel = .{
        .name = "atmega168pb",
        .llvm_name = "atmega168pb",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega169: CpuModel = .{
        .name = "atmega169",
        .llvm_name = "atmega169",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega169a: CpuModel = .{
        .name = "atmega169a",
        .llvm_name = "atmega169a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega169p: CpuModel = .{
        .name = "atmega169p",
        .llvm_name = "atmega169p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega169pa: CpuModel = .{
        .name = "atmega169pa",
        .llvm_name = "atmega169pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega16a: CpuModel = .{
        .name = "atmega16a",
        .llvm_name = "atmega16a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega16hva: CpuModel = .{
        .name = "atmega16hva",
        .llvm_name = "atmega16hva",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega16hva2: CpuModel = .{
        .name = "atmega16hva2",
        .llvm_name = "atmega16hva2",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega16hvb: CpuModel = .{
        .name = "atmega16hvb",
        .llvm_name = "atmega16hvb",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega16hvbrevb: CpuModel = .{
        .name = "atmega16hvbrevb",
        .llvm_name = "atmega16hvbrevb",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega16m1: CpuModel = .{
        .name = "atmega16m1",
        .llvm_name = "atmega16m1",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega16u2: CpuModel = .{
        .name = "atmega16u2",
        .llvm_name = "atmega16u2",
        .features = featureSet(&[_]Feature{
            .avr35,
        }),
    };
    pub const atmega16u4: CpuModel = .{
        .name = "atmega16u4",
        .llvm_name = "atmega16u4",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega2560: CpuModel = .{
        .name = "atmega2560",
        .llvm_name = "atmega2560",
        .features = featureSet(&[_]Feature{
            .avr6,
        }),
    };
    pub const atmega2561: CpuModel = .{
        .name = "atmega2561",
        .llvm_name = "atmega2561",
        .features = featureSet(&[_]Feature{
            .avr6,
        }),
    };
    pub const atmega2564rfr2: CpuModel = .{
        .name = "atmega2564rfr2",
        .llvm_name = "atmega2564rfr2",
        .features = featureSet(&[_]Feature{
            .avr6,
        }),
    };
    pub const atmega256rfr2: CpuModel = .{
        .name = "atmega256rfr2",
        .llvm_name = "atmega256rfr2",
        .features = featureSet(&[_]Feature{
            .avr6,
        }),
    };
    pub const atmega32: CpuModel = .{
        .name = "atmega32",
        .llvm_name = "atmega32",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3208: CpuModel = .{
        .name = "atmega3208",
        .llvm_name = "atmega3208",
        .features = featureSet(&[_]Feature{
            .xmega3,
        }),
    };
    pub const atmega3209: CpuModel = .{
        .name = "atmega3209",
        .llvm_name = "atmega3209",
        .features = featureSet(&[_]Feature{
            .xmega3,
        }),
    };
    pub const atmega323: CpuModel = .{
        .name = "atmega323",
        .llvm_name = "atmega323",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega324a: CpuModel = .{
        .name = "atmega324a",
        .llvm_name = "atmega324a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega324p: CpuModel = .{
        .name = "atmega324p",
        .llvm_name = "atmega324p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega324pa: CpuModel = .{
        .name = "atmega324pa",
        .llvm_name = "atmega324pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega324pb: CpuModel = .{
        .name = "atmega324pb",
        .llvm_name = "atmega324pb",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega325: CpuModel = .{
        .name = "atmega325",
        .llvm_name = "atmega325",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3250: CpuModel = .{
        .name = "atmega3250",
        .llvm_name = "atmega3250",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3250a: CpuModel = .{
        .name = "atmega3250a",
        .llvm_name = "atmega3250a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3250p: CpuModel = .{
        .name = "atmega3250p",
        .llvm_name = "atmega3250p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3250pa: CpuModel = .{
        .name = "atmega3250pa",
        .llvm_name = "atmega3250pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega325a: CpuModel = .{
        .name = "atmega325a",
        .llvm_name = "atmega325a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega325p: CpuModel = .{
        .name = "atmega325p",
        .llvm_name = "atmega325p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega325pa: CpuModel = .{
        .name = "atmega325pa",
        .llvm_name = "atmega325pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega328: CpuModel = .{
        .name = "atmega328",
        .llvm_name = "atmega328",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega328p: CpuModel = .{
        .name = "atmega328p",
        .llvm_name = "atmega328p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega328pb: CpuModel = .{
        .name = "atmega328pb",
        .llvm_name = "atmega328pb",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega329: CpuModel = .{
        .name = "atmega329",
        .llvm_name = "atmega329",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3290: CpuModel = .{
        .name = "atmega3290",
        .llvm_name = "atmega3290",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3290a: CpuModel = .{
        .name = "atmega3290a",
        .llvm_name = "atmega3290a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3290p: CpuModel = .{
        .name = "atmega3290p",
        .llvm_name = "atmega3290p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega3290pa: CpuModel = .{
        .name = "atmega3290pa",
        .llvm_name = "atmega3290pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega329a: CpuModel = .{
        .name = "atmega329a",
        .llvm_name = "atmega329a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega329p: CpuModel = .{
        .name = "atmega329p",
        .llvm_name = "atmega329p",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega329pa: CpuModel = .{
        .name = "atmega329pa",
        .llvm_name = "atmega329pa",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega32a: CpuModel = .{
        .name = "atmega32a",
        .llvm_name = "atmega32a",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega32c1: CpuModel = .{
        .name = "atmega32c1",
        .llvm_name = "atmega32c1",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega32hvb: CpuModel = .{
        .name = "atmega32hvb",
        .llvm_name = "atmega32hvb",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega32hvbrevb: CpuModel = .{
        .name = "atmega32hvbrevb",
        .llvm_name = "atmega32hvbrevb",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega32m1: CpuModel = .{
        .name = "atmega32m1",
        .llvm_name = "atmega32m1",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega32u2: CpuModel = .{
        .name = "atmega32u2",
        .llvm_name = "atmega32u2",
        .features = featureSet(&[_]Feature{
            .avr35,
        }),
    };
    pub const atmega32u4: CpuModel = .{
        .name = "atmega32u4",
        .llvm_name = "atmega32u4",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega32u6: CpuModel = .{
        .name = "atmega32u6",
        .llvm_name = "atmega32u6",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega406: CpuModel = .{
        .name = "atmega406",
        .llvm_name = "atmega406",
        .features = featureSet(&[_]Feature{
            .avr5,
        }),
    };
    pub const atmega48: CpuModel = .{
        .name = "atmega48",
        .llvm_name = "atmega48",
        .features = featureSet(&[_]Feature{
            .avr4,
        }),
    };
    pub const atmega4808: CpuModel = .{
        .name = "atmega4808",
        .llvm_name = "atmega4808",
        ```
