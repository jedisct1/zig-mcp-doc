```
 .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pconfig,
            .pku,
            .popcnt,
            .prefer_256_bit,
            .prfchw,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .sha,
            .tuning_fast_imm_vector_shift,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .wbnoinvd,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const ivybridge: CpuModel = .{
        .name = "ivybridge",
        .llvm_name = "ivybridge",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .f16c,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .macrofusion,
            .mmx,
            .no_bypass_delay_mov,
            .nopl,
            .pclmul,
            .popcnt,
            .rdrnd,
            .sahf,
            .slow_3ops_lea,
            .slow_unaligned_mem_32,
            .smep,
            .vzeroupper,
            .x87,
            .xsaveopt,
        }),
    };
    pub const k6: CpuModel = .{
        .name = "k6",
        .llvm_name = "k6",
        .features = featureSet(&[_]Feature{
            .cx8,
            .mmx,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const k6_2: CpuModel = .{
        .name = "k6_2",
        .llvm_name = "k6-2",
        .features = featureSet(&[_]Feature{
            .@"3dnow",
            .cx8,
            .prfchw,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const k6_3: CpuModel = .{
        .name = "k6_3",
        .llvm_name = "k6-3",
        .features = featureSet(&[_]Feature{
            .@"3dnow",
            .cx8,
            .prfchw,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const k8: CpuModel = .{
        .name = "k8",
        .llvm_name = "k8",
        .features = featureSet(&[_]Feature{
            .@"3dnowa",
            .@"64bit",
            .cmov,
            .cx8,
            .fast_scalar_shift_masks,
            .fxsr,
            .nopl,
            .prfchw,
            .sbb_dep_breaking,
            .slow_shld,
            .slow_unaligned_mem_16,
            .sse2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const k8_sse3: CpuModel = .{
        .name = "k8_sse3",
        .llvm_name = "k8-sse3",
        .features = featureSet(&[_]Feature{
            .@"3dnowa",
            .@"64bit",
            .cmov,
            .cx16,
            .fast_scalar_shift_masks,
            .fxsr,
            .nopl,
            .prfchw,
            .sbb_dep_breaking,
            .slow_shld,
            .slow_unaligned_mem_16,
            .sse3,
            .vzeroupper,
            .x87,
        }),
    };
    pub const knl: CpuModel = .{
        .name = "knl",
        .llvm_name = "knl",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .aes,
            .avx512cd,
            .avx512er,
            .avx512pf,
            .bmi,
            .bmi2,
            .cmov,
            .cx16,
            .evex512,
            .fast_gather,
            .fast_imm16,
            .fast_movbe,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .lzcnt,
            .mmx,
            .movbe,
            .nopl,
            .pclmul,
            .popcnt,
            .prefer_mask_registers,
            .prefetchwt1,
            .prfchw,
            .rdrnd,
            .rdseed,
            .sahf,
            .slow_3ops_lea,
            .slow_incdec,
            .slow_pmaddwd,
            .slow_two_mem_ops,
            .x87,
            .xsaveopt,
        }),
    };
    pub const knm: CpuModel = .{
        .name = "knm",
        .llvm_name = "knm",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .aes,
            .avx512cd,
            .avx512er,
            .avx512pf,
            .avx512vpopcntdq,
            .bmi,
            .bmi2,
            .cmov,
            .cx16,
            .evex512,
            .fast_gather,
            .fast_imm16,
            .fast_movbe,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .lzcnt,
            .mmx,
            .movbe,
            .nopl,
            .pclmul,
            .popcnt,
            .prefer_mask_registers,
            .prefetchwt1,
            .prfchw,
            .rdrnd,
            .rdseed,
            .sahf,
            .slow_3ops_lea,
            .slow_incdec,
            .slow_pmaddwd,
            .slow_two_mem_ops,
            .x87,
            .xsaveopt,
        }),
    };
    pub const lakemont: CpuModel = .{
        .name = "lakemont",
        .llvm_name = "lakemont",
        .features = featureSet(&[_]Feature{
            .cx8,
            .slow_unaligned_mem_16,
            .soft_float,
            .vzeroupper,
        }),
    };
    pub const lunarlake: CpuModel = .{
        .name = "lunarlake",
        .llvm_name = "lunarlake",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avxifma,
            .avxneconvert,
            .avxvnni,
            .avxvnniint16,
            .avxvnniint8,
            .bmi,
            .bmi2,
            .cldemote,
            .clflushopt,
            .clwb,
            .cmov,
            .cmpccxadd,
            .cx16,
            .enqcmd,
            .f16c,
            .false_deps_perm,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .gfni,
            .hreset,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pconfig,
            .pku,
            .popcnt,
            .prefer_movmsk_over_vtest,
            .prfchw,
            .ptwrite,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .serialize,
            .sha,
            .sha512,
            .shstk,
            .slow_3ops_lea,
            .sm3,
            .sm4,
            .tuning_fast_imm_vector_shift,
            .uintr,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .waitpkg,
            .widekl,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const meteorlake: CpuModel = .{
        .name = "meteorlake",
        .llvm_name = "meteorlake",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avxvnni,
            .bmi,
            .bmi2,
            .cldemote,
            .clflushopt,
            .clwb,
            .cmov,
            .cx16,
            .f16c,
            .false_deps_perm,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .gfni,
            .hreset,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pconfig,
            .pku,
            .popcnt,
            .prefer_movmsk_over_vtest,
            .prfchw,
            .ptwrite,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .serialize,
            .sha,
            .shstk,
            .slow_3ops_lea,
            .smap,
            .smep,
            .tuning_fast_imm_vector_shift,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .waitpkg,
            .widekl,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const nehalem: CpuModel = .{
        .name = "nehalem",
        .llvm_name = "nehalem",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .fxsr,
            .idivq_to_divl,
            .macrofusion,
            .mmx,
            .no_bypass_delay_mov,
            .nopl,
            .popcnt,
            .sahf,
            .sse4_2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const nocona: CpuModel = .{
        .name = "nocona",
        .llvm_name = "nocona",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .sse3,
            .vzeroupper,
            .x87,
        }),
    };
    pub const opteron: CpuModel = .{
        .name = "opteron",
        .llvm_name = "opteron",
        .features = featureSet(&[_]Feature{
            .@"3dnowa",
            .@"64bit",
            .cmov,
            .cx8,
            .fast_scalar_shift_masks,
            .fxsr,
            .nopl,
            .prfchw,
            .sbb_dep_breaking,
            .slow_shld,
            .slow_unaligned_mem_16,
            .sse2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const opteron_sse3: CpuModel = .{
        .name = "opteron_sse3",
        .llvm_name = "opteron-sse3",
        .features = featureSet(&[_]Feature{
            .@"3dnowa",
            .@"64bit",
            .cmov,
            .cx16,
            .fast_scalar_shift_masks,
            .fxsr,
            .nopl,
            .prfchw,
            .sbb_dep_breaking,
            .slow_shld,
            .slow_unaligned_mem_16,
            .sse3,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pantherlake: CpuModel = .{
        .name = "pantherlake",
        .llvm_name = "pantherlake",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avxifma,
            .avxneconvert,
            .avxvnni,
            .avxvnniint16,
            .avxvnniint8,
            .bmi,
            .bmi2,
            .cldemote,
            .clflushopt,
            .clwb,
            .cmov,
            .cmpccxadd,
            .cx16,
            .enqcmd,
            .f16c,
            .false_deps_perm,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .gfni,
            .hreset,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pconfig,
            .pku,
            .popcnt,
            .prefer_movmsk_over_vtest,
            .prefetchi,
            .prfchw,
            .ptwrite,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .serialize,
            .sha,
            .sha512,
            .shstk,
            .slow_3ops_lea,
            .sm3,
            .sm4,
            .tuning_fast_imm_vector_shift,
            .uintr,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .waitpkg,
            .widekl,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const penryn: CpuModel = .{
        .name = "penryn",
        .llvm_name = "penryn",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .fxsr,
            .macrofusion,
            .mmx,
            .nopl,
            .sahf,
            .slow_unaligned_mem_16,
            .sse4_1,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentium: CpuModel = .{
        .name = "pentium",
        .llvm_name = "pentium",
        .features = featureSet(&[_]Feature{
            .cx8,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentium2: CpuModel = .{
        .name = "pentium2",
        .llvm_name = "pentium2",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentium3: CpuModel = .{
        .name = "pentium3",
        .llvm_name = "pentium3",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .sse,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentium3m: CpuModel = .{
        .name = "pentium3m",
        .llvm_name = "pentium3m",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .sse,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentium4: CpuModel = .{
        .name = "pentium4",
        .llvm_name = "pentium4",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .sse2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentium_m: CpuModel = .{
        .name = "pentium_m",
        .llvm_name = "pentium-m",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .sse2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentium_mmx: CpuModel = .{
        .name = "pentium_mmx",
        .llvm_name = "pentium-mmx",
        .features = featureSet(&[_]Feature{
            .cx8,
            .mmx,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const pentiumpro: CpuModel = .{
        .name = "pentiumpro",
        .llvm_name = "pentiumpro",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .nopl,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const prescott: CpuModel = .{
        .name = "prescott",
        .llvm_name = "prescott",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .sse3,
            .vzeroupper,
            .x87,
        }),
    };
    pub const raptorlake: CpuModel = .{
        .name = "raptorlake",
        .llvm_name = "raptorlake",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avxvnni,
            .bmi,
            .bmi2,
            .cldemote,
            .clflushopt,
            .clwb,
            .cmov,
            .cx16,
            .f16c,
            .false_deps_perm,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .gfni,
            .hreset,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pconfig,
            .pku,
            .popcnt,
            .prefer_movmsk_over_vtest,
            .prfchw,
            .ptwrite,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .serialize,
            .sha,
            .shstk,
            .slow_3ops_lea,
            .smap,
            .smep,
            .tuning_fast_imm_vector_shift,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .waitpkg,
            .widekl,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const rocketlake: CpuModel = .{
        .name = "rocketlake",
        .llvm_name = "rocketlake",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avx512bitalg,
            .avx512cd,
            .avx512dq,
            .avx512ifma,
            .avx512vbmi,
            .avx512vbmi2,
            .avx512vl,
            .avx512vnni,
            .avx512vpopcntdq,
            .bmi,
            .bmi2,
            .clflushopt,
            .cmov,
            .cx16,
            .ermsb,
            .evex512,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fsgsbase,
            .fsrm,
            .fxsr,
            .gfni,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pku,
            .popcnt,
            .prefer_256_bit,
            .prfchw,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .sha,
            .smap,
            .smep,
            .tuning_fast_imm_vector_shift,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const sandybridge: CpuModel = .{
        .name = "sandybridge",
        .llvm_name = "sandybridge",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .avx,
            .cmov,
            .cx16,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fxsr,
            .idivq_to_divl,
            .macrofusion,
            .mmx,
            .no_bypass_delay_mov,
            .nopl,
            .pclmul,
            .popcnt,
            .sahf,
            .slow_3ops_lea,
            .slow_unaligned_mem_32,
            .vzeroupper,
            .x87,
            .xsaveopt,
        }),
    };
    pub const sapphirerapids: CpuModel = .{
        .name = "sapphirerapids",
        .llvm_name = "sapphirerapids",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .amx_bf16,
            .amx_int8,
            .avx512bf16,
            .avx512bitalg,
            .avx512cd,
            .avx512fp16,
            .avx512ifma,
            .avx512vbmi,
            .avx512vbmi2,
            .avx512vnni,
            .avx512vpopcntdq,
            .avxvnni,
            .bmi,
            .bmi2,
            .cldemote,
            .clflushopt,
            .clwb,
            .cmov,
            .cx16,
            .enqcmd,
            .ermsb,
            .evex512,
            .false_deps_getmant,
            .false_deps_mulc,
            .false_deps_mullq,
            .false_deps_perm,
            .false_deps_range,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fsgsbase,
            .fsrm,
            .fxsr,
            .gfni,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pconfig,
            .pku,
            .popcnt,
            .prefer_256_bit,
            .prfchw,
            .ptwrite,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .serialize,
            .sha,
            .shstk,
            .smap,
            .smep,
            .tsxldtrk,
            .tuning_fast_imm_vector_shift,
            .uintr,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .waitpkg,
            .wbnoinvd,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const sierraforest: CpuModel = .{
        .name = "sierraforest",
        .llvm_name = "sierraforest",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .avxifma,
            .avxneconvert,
            .avxvnni,
            .avxvnniint8,
            .bmi,
            .bmi2,
            .cldemote,
            .clflushopt,
            .clwb,
            .cmov,
            .cmpccxadd,
            .cx16,
            .enqcmd,
            .f16c,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_scalar_fsqrt,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .gfni,
            .hreset,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .nopl,
            .pconfig,
            .pku,
            .popcnt,
            .prfchw,
            .ptwrite,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .serialize,
            .sha,
            .shstk,
            .slow_3ops_lea,
            .uintr,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .waitpkg,
            .widekl,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const silvermont: CpuModel = .{
        .name = "silvermont",
        .llvm_name = "silvermont",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .false_deps_popcnt,
            .fast_7bytenop,
            .fast_imm16,
            .fast_movbe,
            .fxsr,
            .idivq_to_divl,
            .mmx,
            .movbe,
            .no_bypass_delay,
            .nopl,
            .pclmul,
            .popcnt,
            .prfchw,
            .rdrnd,
            .sahf,
            .slow_incdec,
            .slow_lea,
            .slow_pmulld,
            .slow_two_mem_ops,
            .smep,
            .sse4_2,
            .use_slm_arith_costs,
            .vzeroupper,
            .x87,
        }),
    };
    pub const skx: CpuModel = .{
        .name = "skx",
        .llvm_name = "skx",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .aes,
            .allow_light_256_bit,
            .avx512bw,
            .avx512cd,
            .avx512dq,
            .avx512vl,
            .bmi,
            .bmi2,
            .clflushopt,
            .clwb,
            .cmov,
            .cx16,
            .ermsb,
            .evex512,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .faster_shift_than_shuffle,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pclmul,
            .pku,
            .popcnt,
            .prefer_256_bit,
            .prfchw,
            .rdrnd,
            .rdseed,
            .sahf,
            .slow_3ops_lea,
            .smap,
            .smep,
            .tuning_fast_imm_vector_shift,
            .vzeroupper,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const skylake: CpuModel = .{
        .name = "skylake",
        .llvm_name = "skylake",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .aes,
            .allow_light_256_bit,
            .avx2,
            .bmi,
            .bmi2,
            .clflushopt,
            .cmov,
            .cx16,
            .ermsb,
            .f16c,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pclmul,
            .popcnt,
            .prfchw,
            .rdrnd,
            .rdseed,
            .sahf,
            .slow_3ops_lea,
            .smap,
            .smep,
            .vzeroupper,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const skylake_avx512: CpuModel = .{
        .name = "skylake_avx512",
        .llvm_name = "skylake-avx512",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .aes,
            .allow_light_256_bit,
            .avx512bw,
            .avx512cd,
            .avx512dq,
            .avx512vl,
            .bmi,
            .bmi2,
            .clflushopt,
            .clwb,
            .cmov,
            .cx16,
            .ermsb,
            .evex512,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .faster_shift_than_shuffle,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pclmul,
            .pku,
            .popcnt,
            .prefer_256_bit,
            .prfchw,
            .rdrnd,
            .rdseed,
            .sahf,
            .slow_3ops_lea,
            .tuning_fast_imm_vector_shift,
            .vzeroupper,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const slm: CpuModel = .{
        .name = "slm",
        .llvm_name = "slm",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .false_deps_popcnt,
            .fast_7bytenop,
            .fast_imm16,
            .fast_movbe,
            .fxsr,
            .idivq_to_divl,
            .mmx,
            .movbe,
            .no_bypass_delay,
            .nopl,
            .pclmul,
            .popcnt,
            .prfchw,
            .rdrnd,
            .sahf,
            .slow_incdec,
            .slow_lea,
            .slow_pmulld,
            .slow_two_mem_ops,
            .sse4_2,
            .use_slm_arith_costs,
            .vzeroupper,
            .x87,
        }),
    };
    pub const tigerlake: CpuModel = .{
        .name = "tigerlake",
        .llvm_name = "tigerlake",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avx512bitalg,
            .avx512cd,
            .avx512dq,
            .avx512ifma,
            .avx512vbmi,
            .avx512vbmi2,
            .avx512vl,
            .avx512vnni,
            .avx512vp2intersect,
            .avx512vpopcntdq,
            .bmi,
            .bmi2,
            .clflushopt,
            .clwb,
            .cmov,
            .cx16,
            .ermsb,
            .evex512,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fsgsbase,
            .fsrm,
            .fxsr,
            .gfni,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .no_bypass_delay_blend,
            .no_bypass_delay_mov,
            .no_bypass_delay_shuffle,
            .nopl,
            .pku,
            .popcnt,
            .prefer_256_bit,
            .prfchw,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .sha,
            .shstk,
            .smap,
            .smep,
            .tuning_fast_imm_vector_shift,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const tremont: CpuModel = .{
        .name = "tremont",
        .llvm_name = "tremont",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .aes,
            .clflushopt,
            .clwb,
            .cmov,
            .cx16,
            .fast_imm16,
            .fast_movbe,
            .fsgsbase,
            .fxsr,
            .gfni,
            .mmx,
            .movbe,
            .no_bypass_delay,
            .nopl,
            .pclmul,
            .popcnt,
            .prfchw,
            .ptwrite,
            .rdpid,
            .rdrnd,
            .rdseed,
            .sahf,
            .sha,
            .slow_incdec,
            .slow_lea,
            .slow_two_mem_ops,
            .sse4_2,
            .use_glm_div_sqrt_costs,
            .vzeroupper,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const westmere: CpuModel = .{
        .name = "westmere",
        .llvm_name = "westmere",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .fxsr,
            .idivq_to_divl,
            .macrofusion,
            .mmx,
            .no_bypass_delay_mov,
            .nopl,
            .pclmul,
            .popcnt,
            .sahf,
            .sse4_2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const winchip2: CpuModel = .{
        .name = "winchip2",
        .llvm_name = "winchip2",
        .features = featureSet(&[_]Feature{
            .@"3dnow",
            .prfchw,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const winchip_c6: CpuModel = .{
        .name = "winchip_c6",
        .llvm_name = "winchip-c6",
        .features = featureSet(&[_]Feature{
            .mmx,
            .slow_unaligned_mem_16,
            .vzeroupper,
            .x87,
        }),
    };
    pub const x86_64: CpuModel = .{
        .name = "x86_64",
        .llvm_name = "x86-64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx8,
            .fxsr,
            .idivq_to_divl,
            .macrofusion,
            .mmx,
            .nopl,
            .slow_3ops_lea,
            .slow_incdec,
            .sse2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const x86_64_v2: CpuModel = .{
        .name = "x86_64_v2",
        .llvm_name = "x86-64-v2",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .cmov,
            .cx16,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fxsr,
            .idivq_to_divl,
            .macrofusion,
            .mmx,
            .nopl,
            .popcnt,
            .sahf,
            .slow_3ops_lea,
            .slow_unaligned_mem_32,
            .sse4_2,
            .vzeroupper,
            .x87,
        }),
    };
    pub const x86_64_v3: CpuModel = .{
        .name = "x86_64_v3",
        .llvm_name = "x86-64-v3",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_light_256_bit,
            .avx2,
            .bmi,
            .bmi2,
            .cmov,
            .cx16,
            .f16c,
            .false_deps_lzcnt_tzcnt,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fma,
            .fxsr,
            .idivq_to_divl,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .nopl,
            .popcnt,
            .sahf,
            .slow_3ops_lea,
            .vzeroupper,
            .x87,
            .xsave,
        }),
    };
    pub const x86_64_v4: CpuModel = .{
        .name = "x86_64_v4",
        .llvm_name = "x86-64-v4",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .allow_light_256_bit,
            .avx512bw,
            .avx512cd,
            .avx512dq,
            .avx512vl,
            .bmi,
            .bmi2,
            .cmov,
            .cx16,
            .evex512,
            .false_deps_popcnt,
            .fast_15bytenop,
            .fast_gather,
            .fast_scalar_fsqrt,
            .fast_shld_rotate,
            .fast_variable_crosslane_shuffle,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fxsr,
            .idivq_to_divl,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .nopl,
            .popcnt,
            .prefer_256_bit,
            .sahf,
            .slow_3ops_lea,
            .vzeroupper,
            .x87,
            .xsave,
        }),
    };
    pub const yonah: CpuModel = .{
        .name = "yonah",
        .llvm_name = "yonah",
        .features = featureSet(&[_]Feature{
            .cmov,
            .cx8,
            .fxsr,
            .mmx,
            .nopl,
            .slow_unaligned_mem_16,
            .sse3,
            .vzeroupper,
            .x87,
        }),
    };
    pub const znver1: CpuModel = .{
        .name = "znver1",
        .llvm_name = "znver1",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .aes,
            .allow_light_256_bit,
            .avx2,
            .bmi,
            .bmi2,
            .branchfusion,
            .clflushopt,
            .clzero,
            .cmov,
            .cx16,
            .f16c,
            .fast_15bytenop,
            .fast_bextr,
            .fast_imm16,
            .fast_lzcnt,
            .fast_movbe,
            .fast_scalar_fsqrt,
            .fast_scalar_shift_masks,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .lzcnt,
            .mmx,
            .movbe,
            .mwaitx,
            .nopl,
            .pclmul,
            .popcnt,
            .prfchw,
            .rdrnd,
            .rdseed,
            .sahf,
            .sbb_dep_breaking,
            .sha,
            .slow_shld,
            .smap,
            .smep,
            .sse4a,
            .vzeroupper,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const znver2: CpuModel = .{
        .name = "znver2",
        .llvm_name = "znver2",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .aes,
            .allow_light_256_bit,
            .avx2,
            .bmi,
            .bmi2,
            .branchfusion,
            .clflushopt,
            .clwb,
            .clzero,
            .cmov,
            .cx16,
            .f16c,
            .fast_15bytenop,
            .fast_bextr,
            .fast_imm16,
            .fast_lzcnt,
            .fast_movbe,
            .fast_scalar_fsqrt,
            .fast_scalar_shift_masks,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fxsr,
            .idivq_to_divl,
            .lzcnt,
            .mmx,
            .movbe,
            .mwaitx,
            .nopl,
            .pclmul,
            .popcnt,
            .prfchw,
            .rdpid,
            .rdpru,
            .rdrnd,
            .rdseed,
            .sahf,
            .sbb_dep_breaking,
            .sha,
            .slow_shld,
            .smap,
            .smep,
            .sse4a,
            .vzeroupper,
            .wbnoinvd,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const znver3: CpuModel = .{
        .name = "znver3",
        .llvm_name = "znver3",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .bmi,
            .bmi2,
            .branchfusion,
            .clflushopt,
            .clwb,
            .clzero,
            .cmov,
            .cx16,
            .f16c,
            .fast_15bytenop,
            .fast_bextr,
            .fast_imm16,
            .fast_lzcnt,
            .fast_movbe,
            .fast_scalar_fsqrt,
            .fast_scalar_shift_masks,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fma,
            .fsgsbase,
            .fsrm,
            .fxsr,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .mwaitx,
            .nopl,
            .pku,
            .popcnt,
            .prfchw,
            .rdpid,
            .rdpru,
            .rdrnd,
            .rdseed,
            .sahf,
            .sbb_dep_breaking,
            .sha,
            .slow_shld,
            .smap,
            .smep,
            .sse4a,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .wbnoinvd,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const znver4: CpuModel = .{
        .name = "znver4",
        .llvm_name = "znver4",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avx512bf16,
            .avx512bitalg,
            .avx512cd,
            .avx512dq,
            .avx512ifma,
            .avx512vbmi,
            .avx512vbmi2,
            .avx512vl,
            .avx512vnni,
            .avx512vpopcntdq,
            .bmi,
            .bmi2,
            .branchfusion,
            .clflushopt,
            .clwb,
            .clzero,
            .cmov,
            .cx16,
            .evex512,
            .fast_15bytenop,
            .fast_bextr,
            .fast_dpwssd,
            .fast_imm16,
            .fast_lzcnt,
            .fast_movbe,
            .fast_scalar_fsqrt,
            .fast_scalar_shift_masks,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fsgsbase,
            .fsrm,
            .fxsr,
            .gfni,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .mwaitx,
            .nopl,
            .pku,
            .popcnt,
            .prfchw,
            .rdpid,
            .rdpru,
            .rdrnd,
            .rdseed,
            .sahf,
            .sbb_dep_breaking,
            .sha,
            .shstk,
            .slow_shld,
            .smap,
            .smep,
            .sse4a,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .wbnoinvd,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
        }),
    };
    pub const znver5: CpuModel = .{
        .name = "znver5",
        .llvm_name = "znver5",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .adx,
            .allow_light_256_bit,
            .avx512bf16,
            .avx512bitalg,
            .avx512cd,
            .avx512dq,
            .avx512ifma,
            .avx512vbmi,
            .avx512vbmi2,
            .avx512vl,
            .avx512vnni,
            .avx512vp2intersect,
            .avx512vpopcntdq,
            .avxvnni,
            .bmi,
            .bmi2,
            .branchfusion,
            .clflushopt,
            .clwb,
            .clzero,
            .cmov,
            .cx16,
            .evex512,
            .fast_15bytenop,
            .fast_bextr,
            .fast_dpwssd,
            .fast_imm16,
            .fast_lzcnt,
            .fast_movbe,
            .fast_scalar_fsqrt,
            .fast_scalar_shift_masks,
            .fast_variable_perlane_shuffle,
            .fast_vector_fsqrt,
            .fsgsbase,
            .fsrm,
            .fxsr,
            .gfni,
            .idivq_to_divl,
            .invpcid,
            .lzcnt,
            .macrofusion,
            .mmx,
            .movbe,
            .movdir64b,
            .movdiri,
            .mwaitx,
            .nopl,
            .pku,
            .popcnt,
            .prefetchi,
            .prfchw,
            .rdpid,
            .rdpru,
            .rdrnd,
            .rdseed,
            .sahf,
            .sbb_dep_breaking,
            .sha,
            .shstk,
            .slow_shld,
            .smap,
            .smep,
            .sse4a,
            .vaes,
            .vpclmulqdq,
            .vzeroupper,
            .wbnoinvd,
            .x87,
            .xsavec,
            .xsaveopt,
            .xsaves,
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
    pub const xs1b_generic: CpuModel = .{
        .name = "xs1b_generic",
        .llvm_name = "xs1b-generic",
        .features = featureSet(&[_]Feature{}),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    density,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.density)] = .{
        .llvm_name = "density",
        .description = "Enable Density instructions",
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
};
const std = @import("std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const math = std.math;

/// Provides deterministic randomness in unit tests.
/// Initialized on startup. Read-only after that.
pub var random_seed: u32 = 0;

pub const FailingAllocator = @import("testing/FailingAllocator.zig");
pub const failing_allocator = failing_allocator_instance.allocator();
var failing_allocator_instance = FailingAllocator.init(base_allocator_instance.allocator(), .{
    .fail_index = 0,
});
var base_allocator_instance = std.heap.FixedBufferAllocator.init("");

/// This should only be used in temporary test programs.
pub const allocator = allocator_instance.allocator();
pub var allocator_instance: std.heap.GeneralPurposeAllocator(.{
    .stack_trace_frames = if (std.debug.sys_can_stack_trace) 10 else 0,
    .resize_stack_traces = true,
    // A unique value so that when a default-constructed
    // GeneralPurposeAllocator is incorrectly passed to testing allocator, or
    // vice versa, panic occurs.
    .canary = @truncate(0x2731e675c3a701ba),
}) = b: {
    if (!builtin.is_test) @compileError("testing allocator used when not testing");
    break :b .init;
};

/// TODO https://github.com/ziglang/zig/issues/5738
pub var log_level = std.log.Level.warn;

// Disable printing in tests for simple backends.
pub const backend_can_print = !(builtin.zig_backend == .stage2_spirv64 or builtin.zig_backend == .stage2_riscv64);

fn print(comptime fmt: []const u8, args: anytype) void {
    if (@inComptime()) {
        @compileError(std.fmt.comptimePrint(fmt, args));
    } else if (backend_can_print) {
        std.debug.print(fmt, args);
    }
}

/// This function is intended to be used only in tests. It prints diagnostics to stderr
/// and then returns a test failure error when actual_error_union is not expected_error.
pub fn expectError(expected_error: anyerror, actual_error_union: anytype) !void {
    if (actual_error_union) |actual_payload| {
        print("expected error.{s}, found {any}\n", .{ @errorName(expected_error), actual_payload });
        return error.TestExpectedError;
    } else |actual_error| {
        if (expected_error != actual_error) {
            print("expected error.{s}, found error.{s}\n", .{
                @errorName(expected_error),
                @errorName(actual_error),
            });
            return error.TestUnexpectedError;
        }
    }
}

/// This function is intended to be used only in tests. When the two values are not
/// equal, prints diagnostics to stderr to show exactly how they are not equal,
/// then returns a test failure error.
/// `actual` and `expected` are coerced to a common type using peer type resolution.
pub inline fn expectEqual(expected: anytype, actual: anytype) !void {
    const T = @TypeOf(expected, actual);
    return expectEqualInner(T, expected, actual);
}

fn expectEqualInner(comptime T: type, expected: T, actual: T) !void {
    switch (@typeInfo(@TypeOf(actual))) {
        .noreturn,
        .@"opaque",
        .frame,
        .@"anyframe",
        => @compileError("value of type " ++ @typeName(@TypeOf(actual)) ++ " encountered"),

        .undefined,
        .null,
        .void,
        => return,

        .type => {
            if (actual != expected) {
                print("expected type {s}, found type {s}\n", .{ @typeName(expected), @typeName(actual) });
                return error.TestExpectedEqual;
            }
        },

        .bool,
        .int,
        .float,
        .comptime_float,
        .comptime_int,
        .enum_literal,
        .@"enum",
        .@"fn",
        .error_set,
        => {
            if (actual != expected) {
                print("expected {}, found {}\n", .{ expected, actual });
                return error.TestExpectedEqual;
            }
        },

        .pointer => |pointer| {
            switch (pointer.size) {
                .one, .many, .c => {
                    if (actual != expected) {
                        print("expected {*}, found {*}\n", .{ expected, actual });
                        return error.TestExpectedEqual;
                    }
                },
                .slice => {
                    if (actual.ptr != expected.ptr) {
                        print("expected slice ptr {*}, found {*}\n", .{ expected.ptr, actual.ptr });
                        return error.TestExpectedEqual;
                    }
                    if (actual.len != expected.len) {
                        print("expected slice len {}, found {}\n", .{ expected.len, actual.len });
                        return error.TestExpectedEqual;
                    }
                },
            }
        },

        .array => |array| try expectEqualSlices(array.child, &expected, &actual),

        .vector => |info| {
            var i: usize = 0;
            while (i < info.len) : (i += 1) {
                if (!std.meta.eql(expected[i], actual[i])) {
                    print("index {d} incorrect. expected {any}, found {any}\n", .{
                        i, expected[i], actual[i],
                    });
                    return error.TestExpectedEqual;
                }
            }
        },

        .@"struct" => |structType| {
            inline for (structType.fields) |field| {
                try expectEqual(@field(expected, field.name), @field(actual, field.name));
            }
        },

        .@"union" => |union_info| {
            if (union_info.tag_type == null) {
                @compileError("Unable to compare untagged union values for type " ++ @typeName(@TypeOf(actual)));
            }

            const Tag = std.meta.Tag(@TypeOf(expected));

            const expectedTag = @as(Tag, expected);
            const actualTag = @as(Tag, actual);

            try expectEqual(expectedTag, actualTag);

            // we only reach this switch if the tags are equal
            switch (expected) {
                inline else => |val, tag| try expectEqual(val, @field(actual, @tagName(tag))),
            }
        },

        .optional => {
            if (expected) |expected_payload| {
                if (actual) |actual_payload| {
                    try expectEqual(expected_payload, actual_payload);
                } else {
                    print("expected {any}, found null\n", .{expected_payload});
                    return error.TestExpectedEqual;
                }
            } else {
                if (actual) |actual_payload| {
                    print("expected null, found {any}\n", .{actual_payload});
                    return error.TestExpectedEqual;
                }
            }
        },

        .error_union => {
            if (expected) |expected_payload| {
                if (actual) |actual_payload| {
                    try expectEqual(expected_payload, actual_payload);
                } else |actual_err| {
                    print("expected {any}, found {}\n", .{ expected_payload, actual_err });
                    return error.TestExpectedEqual;
                }
            } else |expected_err| {
                if (actual) |actual_payload| {
                    print("expected {}, found {any}\n", .{ expected_err, actual_payload });
                    return error.TestExpectedEqual;
                } else |actual_err| {
                    try expectEqual(expected_err, actual_err);
                }
            }
        },
    }
}

test "expectEqual.union(enum)" {
    const T = union(enum) {
        a: i32,
        b: f32,
    };

    const a10 = T{ .a = 10 };

    try expectEqual(a10, a10);
}

test "expectEqual union with comptime-only field" {
    const U = union(enum) {
        a: void,
        b: void,
        c: comptime_int,
    };

    try expectEqual(U{ .a = {} }, .a);
}

test "expectEqual nested array" {
    const a = [2][2]f32{
        [_]f32{ 1.0, 0.0 },
        [_]f32{ 0.0, 1.0 },
    };

    const b = [2][2]f32{
        [_]f32{ 1.0, 0.0 },
        [_]f32{ 0.0, 1.0 },
    };

    try expectEqual(a, b);
}

test "expectEqual vector" {
    const a: @Vector(4, u32) = @splat(4);
    const b: @Vector(4, u32) = @splat(4);

    try expectEqual(a, b);
}

test "expectEqual null" {
    const a = .{null};
    const b = @Vector(1, ?*u8){null};

    try expectEqual(a, b);
}

/// This function is intended to be used only in tests. When the formatted result of the template
/// and its arguments does not equal the expected text, it prints diagnostics to stderr to show how
/// they are not equal, then returns an error. It depends on `expectEqualStrings()` for printing
/// diagnostics.
pub fn expectFmt(expected: []const u8, comptime template: []const u8, args: anytype) !void {
    const actual = try std.fmt.allocPrint(allocator, template, args);
    defer allocator.free(actual);
    return expectEqualStrings(expected, actual);
}

/// This function is intended to be used only in tests. When the actual value is
/// not approximately equal to the expected value, prints diagnostics to stderr
/// to show exactly how they are not equal, then returns a test failure error.
/// See `math.approxEqAbs` for more information on the tolerance parameter.
/// The types must be floating-point.
/// `actual` and `expected` are coerced to a common type using peer type resolution.
pub inline fn expectApproxEqAbs(expected: anytype, actual: anytype, tolerance: anytype) !void {
    const T = @TypeOf(expected, actual, tolerance);
    return expectApproxEqAbsInner(T, expected, actual, tolerance);
}

fn expectApproxEqAbsInner(comptime T: type, expected: T, actual: T, tolerance: T) !void {
    switch (@typeInfo(T)) {
        .float => if (!math.approxEqAbs(T, expected, actual, tolerance)) {
            print("actual {}, not within absolute tolerance {} of expected {}\n", .{ actual, tolerance, expected });
            return error.TestExpectedApproxEqAbs;
        },

        .comptime_float => @compileError("Cannot approximately compare two comptime_float values"),

        else => @compileError("Unable to compare non floating point values"),
    }
}

test expectApproxEqAbs {
    inline for ([_]type{ f16, f32, f64, f128 }) |T| {
        const pos_x: T = 12.0;
        const pos_y: T = 12.06;
        const neg_x: T = -12.0;
        const neg_y: T = -12.06;

        try expectApproxEqAbs(pos_x, pos_y, 0.1);
        try expectApproxEqAbs(neg_x, neg_y, 0.1);
    }
}

/// This function is intended to be used only in tests. When the actual value is
/// not approximately equal to the expected value, prints diagnostics to stderr
/// to show exactly how they are not equal, then returns a test failure error.
/// See `math.approxEqRel` for more information on the tolerance parameter.
/// The types must be floating-point.
/// `actual` and `expected` are coerced to a common type using peer type resolution.
pub inline fn expectApproxEqRel(expected: anytype, actual: anytype, tolerance: anytype) !void {
    const T = @TypeOf(expected, actual, tolerance);
    return expectApproxEqRelInner(T, expected, actual, tolerance);
}

fn expectApproxEqRelInner(comptime T: type, expected: T, actual: T, tolerance: T) !void {
    switch (@typeInfo(T)) {
        .float => if (!math.approxEqRel(T, expected, actual, tolerance)) {
            print("actual {}, not within relative tolerance {} of expected {}\n", .{ actual, tolerance, expected });
            return error.TestExpectedApproxEqRel;
        },

        .comptime_float => @compileError("Cannot approximately compare two comptime_float values"),

        else => @compileError("Unable to compare non floating point values"),
    }
}

test expectApproxEqRel {
    inline for ([_]type{ f16, f32, f64, f128 }) |T| {
        const eps_value = comptime math.floatEps(T);
        const sqrt_eps_value = comptime @sqrt(eps_value);

        const pos_x: T = 12.0;
        const pos_y: T = pos_x + 2 * eps_value;
        const neg_x: T = -12.0;
        const neg_y: T = neg_x - 2 * eps_value;

        try expectApproxEqRel(pos_x, pos_y, sqrt_eps_value);
        try expectApproxEqRel(neg_x, neg_y, sqrt_eps_value);
    }
}

/// This function is intended to be used only in tests. When the two slices are not
/// equal, prints diagnostics to stderr to show exactly how they are not equal (with
/// the differences highlighted in red), then returns a test failure error.
/// The colorized output is optional and controlled by the return of `std.io.tty.detectConfig()`.
/// If your inputs are UTF-8 encoded strings, consider calling `expectEqualStrings` instead.
pub fn expectEqualSlices(comptime T: type, expected: []const T, actual: []const T) !void {
    if (expected.ptr == actual.ptr and expected.len == actual.len) {
        return;
    }
    const diff_index: usize = diff_index: {
        const shortest = @min(expected.len, actual.len);
        var index: usize = 0;
        while (index < shortest) : (index += 1) {
            if (!std.meta.eql(actual[index], expected[index])) break :diff_index index;
        }
        break :diff_index if (expected.len == actual.len) return else shortest;
    };

    if (!backend_can_print) {
        return error.TestExpectedEqual;
    }

    print("slices differ. first difference occurs at index {d} (0x{X})\n", .{ diff_index, diff_index });

    // TODO: Should this be configurable by the caller?
    const max_lines: usize = 16;
    const max_window_size: usize = if (T == u8) max_lines * 16 else max_lines;

    // Print a maximum of max_window_size items of each input, starting just before the
    // first difference to give a bit of context.
    var window_start: usize = 0;
    if (@max(actual.len, expected.len) > max_window_size) {
        const alignment = if (T == u8) 16 else 2;
        window_start = std.mem.alignBackward(usize, diff_index - @min(diff_index, alignment), alignment);
    }
    const expected_window = expected[window_start..@min(expected.len, window_start + max_window_size)];
    const expected_truncated = window_start + expected_window.len < expected.len;
    const actual_window = actual[window_start..@min(actual.len, window_start + max_window_size)];
    const actual_truncated = window_start + actual_window.len < actual.len;

    const stderr = std.io.getStdErr();
    const ttyconf = std.io.tty.detectConfig(stderr);
    var differ = if (T == u8) BytesDiffer{
        .expected = expected_window,
        .actual = actual_window,
        .ttyconf = ttyconf,
    } else SliceDiffer(T){
        .start_index = window_start,
        .expected = expected_window,
        .actual = actual_window,
        .ttyconf = ttyconf,
    };

    // Print indexes as hex for slices of u8 since it's more likely to be binary data where
    // that is usually useful.
    const index_fmt = if (T == u8) "0x{X}" else "{}";

    print("\n============ expected this output: =============  len: {} (0x{X})\n\n", .{ expected.len, expected.len });
    if (window_start > 0) {
        if (T == u8) {
            print("... truncated, start index: " ++ index_fmt ++ " ...\n", .{window_start});
        } else {
            print("... truncated ...\n", .{});
        }
    }
    differ.write(stderr.writer()) catch {};
    if (expected_truncated) {
        const end_offset = window_start + expected_window.len;
        const num_missing_items = expected.len - (window_start + expected_window.len);
        if (T == u8) {
            print("... truncated, indexes [" ++ index_fmt ++ "..] not shown, remaining bytes: " ++ index_fmt ++ " ...\n", .{ end_offset, num_missing_items });
        } else {
            print("... truncated, remaining items: " ++ index_fmt ++ " ...\n", .{num_missing_items});
        }
    }

    // now reverse expected/actual and print again
    differ.expected = actual_window;
    differ.actual = expected_window;
    print("\n============= instead found this: ==============  len: {} (0x{X})\n\n", .{ actual.len, actual.len });
    if (window_start > 0) {
        if (T == u8) {
            print("... truncated, start index: " ++ index_fmt ++ " ...\n", .{window_start});
        } else {
            print("... truncated ...\n", .{});
        }
    }
    differ.write(stderr.writer()) catch {};
    if (actual_truncated) {
        const end_offset = window_start + actual_window.len;
        const num_missing_items = actual.len - (window_start + actual_window.len);
        if (T == u8) {
            print("... truncated, indexes [" ++ index_fmt ++ "..] not shown, remaining bytes: " ++ index_fmt ++ " ...\n", .{ end_offset, num_missing_items });
        } else {
            print("... truncated, remaining items: " ++ index_fmt ++ " ...\n", .{num_missing_items});
        }
    }
    print("\n================================================\n\n", .{});

    return error.TestExpectedEqual;
}

fn SliceDiffer(comptime T: type) type {
    return struct {
        start_index: usize,
        expected: []const T,
        actual: []const T,
        ttyconf: std.io.tty.Config,

        const Self = @This();

        pub fn write(self: Self, writer: anytype) !void {
            for (self.expected, 0..) |value, i| {
                const full_index = self.start_index + i;
                const diff = if (i < self.actual.len) !std.meta.eql(self.actual[i], value) else true;
                if (diff) try self.ttyconf.setColor(writer, .red);
                if (@typeInfo(T) == .pointer) {
                    try writer.print("[{}]{*}: {any}\n", .{ full_index, value, value });
                } else {
                    try writer.print("[{}]: {any}\n", .{ full_index, value });
                }
                if (diff) try self.ttyconf.setColor(writer, .reset);
            }
        }
    };
}

const BytesDiffer = struct {
    expected: []const u8,
    actual: []const u8,
    ttyconf: std.io.tty.Config,

    pub fn write(self: BytesDiffer, writer: anytype) !void {
        var expected_iterator = std.mem.window(u8, self.expected, 16, 16);
        var row: usize = 0;
        while (expected_iterator.next()) |chunk| {
            // to avoid having to calculate diffs twice per chunk
            var diffs: std.bit_set.IntegerBitSet(16) = .{ .mask = 0 };
            for (chunk, 0..) |byte, col| {
                const absolute_byte_index = col + row * 16;
                const diff = if (absolute_byte_index < self.actual.len) self.actual[absolute_byte_index] != byte else true;
                if (diff) diffs.set(col);
                try self.writeDiff(writer, "{X:0>2} ", .{byte}, diff);
                if (col == 7) try writer.writeByte(' ');
            }
            try writer.writeByte(' ');
            if (chunk.len < 16) {
                var missing_columns = (16 - chunk.len) * 3;
                if (chunk.len < 8) missing_columns += 1;
                try writer.writeByteNTimes(' ', missing_columns);
            }
            for (chunk, 0..) |byte, col| {
                const diff = diffs.isSet(col);
                if (std.ascii.isPrint(byte)) {
                    try self.writeDiff(writer, "{c}", .{byte}, diff);
                } else {
                    // TODO: remove this `if` when https://github.com/ziglang/zig/issues/7600 is fixed
                    if (self.ttyconf == .windows_api) {
                        try self.writeDiff(writer, ".", .{}, diff);
                        continue;
                    }

                    // Let's print some common control codes as graphical Unicode symbols.
                    // We don't want to do this for all control codes because most control codes apart from
                    // the ones that Zig has escape sequences for are likely not very useful to print as symbols.
                    switch (byte) {
                        '\n' => try self.writeDiff(writer, "␊", .{}, diff),
                        '\r' => try self.writeDiff(writer, "␍", .{}, diff),
                        '\t' => try self.writeDiff(writer, "␉", .{}, diff),
                        else => try self.writeDiff(writer, ".", .{}, diff),
                    }
                }
            }
            try writer.writeByte('\n');
            row += 1;
        }
    }

    fn writeDiff(self: BytesDiffer, writer: anytype, comptime fmt: []const u8, args: anytype, diff: bool) !void {
        if (diff) try self.ttyconf.setColor(writer, .red);
        try writer.print(fmt, args);
        if (diff) try self.ttyconf.setColor(writer, .reset);
    }
};

test {
    try expectEqualSlices(u8, "foo\x00", "foo\x00");
    try expectEqualSlices(u16, &[_]u16{ 100, 200, 300, 400 }, &[_]u16{ 100, 200, 300, 400 });
    const E = enum { foo, bar };
    const S = struct {
        v: E,
    };
    try expectEqualSlices(
        S,
        &[_]S{ .{ .v = .foo }, .{ .v = .bar }, .{ .v = .foo }, .{ .v = .bar } },
        &[_]S{ .{ .v = .foo }, .{ .v = .bar }, .{ .v = .foo }, .{ .v = .bar } },
    );
}

/// This function is intended to be used only in tests. Checks that two slices or two arrays are equal,
/// including that their sentinel (if any) are the same. Will error if given another type.
pub fn expectEqualSentinel(comptime T: type, comptime sentinel: T, expected: [:sentinel]const T, actual: [:sentinel]const T) !void {
    try expectEqualSlices(T, expected, actual);

    const expected_value_sentinel = blk: {
        switch (@typeInfo(@TypeOf(expected))) {
            .pointer => {
                break :blk expected[expected.len];
            },
            .array => |array_info| {
                const indexable_outside_of_bounds = @as([]const array_info.child, &expected);
                break :blk indexable_outside_of_bounds[indexable_outside_of_bounds.len];
            },
            else => {},
        }
    };

    const actual_value_sentinel = blk: {
        switch (@typeInfo(@TypeOf(actual))) {
            .pointer => {
                break :blk actual[actual.len];
            },
            .array => |array_info| {
                const indexable_outside_of_bounds = @as([]const array_info.child, &actual);
                break :blk indexable_outside_of_bounds[indexable_outside_of_bounds.len];
            },
            else => {},
        }
    };

    if (!std.meta.eql(sentinel, expected_value_sentinel)) {
        print("expectEqualSentinel: 'expected' sentinel in memory is different from its type sentinel. type sentinel {}, in memory sentinel {}\n", .{ sentinel, expected_value_sentinel });
        return error.TestExpectedEqual;
    }

    if (!std.meta.eql(sentinel, actual_value_sentinel)) {
        print("expectEqualSentinel: 'actual' sentinel in memory is different from its type sentinel. type sentinel {}, in memory sentinel {}\n", .{ sentinel, actual_value_sentinel });
        return error.TestExpectedEqual;
    }
}

/// This function is intended to be used only in tests.
/// When `ok` is false, returns a test failure error.
pub fn expect(ok: bool) !void {
    if (!ok) return error.TestUnexpectedResult;
}

pub const TmpDir = struct {
    dir: std.fs.Dir,
    parent_dir: std.fs.Dir,
    sub_path: [sub_path_len]u8,

    const random_bytes_count = 12;
    const sub_path_len = std.fs.base64_encoder.calcSize(random_bytes_count);

    pub fn cleanup(self: *TmpDir) void {
        self.dir.close();
        self.parent_dir.deleteTree(&self.sub_path) catch {};
        self.parent_dir.close();
        self.* = undefined;
    }
};

pub fn tmpDir(opts: std.fs.Dir.OpenOptions) TmpDir {
    var random_bytes: [TmpDir.random_bytes_count]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var sub_path: [TmpDir.sub_path_len]u8 = undefined;
    _ = std.fs.base64_encoder.encode(&sub_path, &random_bytes);

    const cwd = std.fs.cwd();
    var cache_dir = cwd.makeOpenPath(".zig-cache", .{}) catch
        @panic("unable to make tmp dir for testing: unable to make and open .zig-cache dir");
    defer cache_dir.close();
    const parent_dir = cache_dir.makeOpenPath("tmp", .{}) catch
        @panic("unable to make tmp dir for testing: unable to make and open .zig-cache/tmp dir");
    const dir = parent_dir.makeOpenPath(&sub_path, opts) catch
        @panic("unable to make tmp dir for testing: unable to make and open the tmp dir");

    return .{
        .dir = dir,
        .parent_dir = parent_dir,
        .sub_path = sub_path,
    };
}

pub fn expectEqualStrings(expected: []const u8, actual: []const u8) !void {
    if (std.mem.indexOfDiff(u8, actual, expected)) |diff_index| {
        print("\n====== expected this output: =========\n", .{});
        printWithVisibleNewlines(expected);
        print("\n======== instead found this: =========\n", .{});
        printWithVisibleNewlines(actual);
        print("\n======================================\n", .{});

        var diff_line_number: usize = 1;
        for (expected[0..diff_index]) |value| {
            if (value == '\n') diff_line_number += 1;
        }
        print("First difference occurs on line {d}:\n", .{diff_line_number});

        print("expected:\n", .{});
        printIndicatorLine(expected, diff_index);

        print("found:\n", .{});
        printIndicatorLine(actual, diff_index);

        return error.TestExpectedEqual;
    }
}

pub fn expectStringStartsWith(actual: []const u8, expected_starts_with: []const u8) !void {
    if (std.mem.startsWith(u8, actual, expected_starts_with))
        return;

    const shortened_actual = if (actual.len >= expected_starts_with.len)
        actual[0..expected_starts_with.len]
    else
        actual;

    print("\n====== expected to start with: =========\n", .{});
    printWithVisibleNewlines(expected_starts_with);
    print("\n====== instead started with: ===========\n", .{});
    printWithVisibleNewlines(shortened_actual);
    print("\n========= full output: ==============\n", .{});
    printWithVisibleNewlines(actual);
    print("\n======================================\n", .{});

    return error.TestExpectedStartsWith;
}

pub fn expectStringEndsWith(actual: []const u8, expected_ends_with: []const u8) !void {
    if (std.mem.endsWith(u8, actual, expected_ends_with))
        return;

    const shortened_actual = if (actual.len >= expected_ends_with.len)
        actual[(actual.len - expected_ends_with.len)..]
    else
        actual;

    print("\n====== expected to end with: =========\n", .{});
    printWithVisibleNewlines(expected_ends_with);
    print("\n====== instead ended with: ===========\n", .{});
    printWithVisibleNewlines(shortened_actual);
    print("\n========= full output: ==============\n", .{});
    printWithVisibleNewlines(actual);
    print("\n======================================\n", .{});

    return error.TestExpectedEndsWith;
}

/// This function is intended to be used only in tests. When the two values are not
/// deeply equal, prints diagnostics to stderr to show exactly how they are not equal,
/// then returns a test failure error.
/// `actual` and `expected` are coerced to a common type using peer type resolution.
///
/// Deeply equal is defined as follows:
/// Primitive types are deeply equal if they are equal using `==` operator.
/// Struct values are deeply equal if their corresponding fields are deeply equal.
/// Container types(like Array/Slice/Vector) deeply equal when their corresponding elements are deeply equal.
/// Pointer values are deeply equal if values they point to are deeply equal.
///
/// Note: Self-referential structs are supported (e.g. things like std.SinglyLinkedList)
/// but may cause infinite recursion or stack overflow when a container has a pointer to itself.
pub inline fn expectEqualDeep(expected: anytype, actual: anytype) error{TestExpectedEqual}!void {
    const T = @TypeOf(expected, actual);
    return expectEqualDeepInner(T, expected, actual);
}

fn expectEqualDeepInner(comptime T: type, expected: T, actual: T) error{TestExpectedEqual}!void {
    switch (@typeInfo(@TypeOf(actual))) {
        .noreturn,
        .@"opaque",
        .frame,
        .@"anyframe",
        => @compileError("value of type " ++ @typeName(@TypeOf(actual)) ++ " encountered"),

        .undefined,
        .null,
        .void,
        => return,

        .type => {
            if (actual != expected) {
                print("expected type {s}, found type {s}\n", .{ @typeName(expected), @typeName(actual) });
                return error.TestExpectedEqual;
            }
        },

        .bool,
        .int,
        .float,
        .comptime_float,
        .comptime_int,
        .enum_literal,
        .@"enum",
        .@"fn",
        .error_set,
        => {
            if (actual != expected) {
                print("expected {}, found {}\n", .{ expected, actual });
                return error.TestExpectedEqual;
            }
        },

        .pointer => |pointer| {
            switch (pointer.size) {
                // We have no idea what is behind those pointers, so the best we can do is `==` check.
                .c, .many => {
                    if (actual != expected) {
                        print("expected {*}, found {*}\n", .{ expected, actual });
                        return error.TestExpectedEqual;
                    }
                },
                .one => {
                    // Length of those pointers are runtime value, so the best we can do is `==` check.
                    switch (@typeInfo(pointer.child)) {
                        .@"fn", .@"opaque" => {
                            if (actual != expected) {
                                print("expected {*}, found {*}\n", .{ expected, actual });
                                return error.TestExpectedEqual;
                            }
                        },
                        else => try expectEqualDeep(expected.*, actual.*),
                    }
                },
                .slice => {
                    if (expected.len != actual.len) {
                        print("Slice len not the same, expected {d}, found {d}\n", .{ expected.len, actual.len });
                        return error.TestExpectedEqual;
                    }
                    var i: usize = 0;
                    while (i < expected.len) : (i += 1) {
                        expectEqualDeep(expected[i], actual[i]) catch |e| {
                            print("index {d} incorrect. expected {any}, found {any}\n", .{
                                i, expected[i], actual[i],
                            });
                            return e;
                        };
                    }
                },
            }
        },

        .array => |_| {
            if (expected.len != actual.len) {
                print("Array len not the same, expected {d}, found {d}\n", .{ expected.len, actual.len });
                return error.TestExpectedEqual;
            }
            var i: usize = 0;
            while (i < expected.len) : (i += 1) {
                expectEqualDeep(expected[i], actual[i]) catch |e| {
                    print("index {d} incorrect. expected {any}, found {any}\n", .{
                        i, expected[i], actual[i],
                    });
                    return e;
                };
            }
        },

        .vector => |info| {
            if (info.len != @typeInfo(@TypeOf(actual)).vector.len) {
                print("Vector len not the same, expected {d}, found {d}\n", .{ info.len, @typeInfo(@TypeOf(actual)).vector.len });
                return error.TestExpectedEqual;
            }
            var i: usize = 0;
            while (i < info.len) : (i += 1) {
                expectEqualDeep(expected[i], actual[i]) catch |e| {
                    print("index {d} incorrect. expected {any}, found {any}\n", .{
                        i, expected[i], actual[i],
                    });
                    return e;
                };
            }
        },

        .@"struct" => |structType| {
            inline for (structType.fields) |field| {
                expectEqualDeep(@field(expected, field.name), @field(actual, field.name)) catch |e| {
                    print("Field {s} incorrect. expected {any}, found {any}\n", .{ field.name, @field(expected, field.name), @field(actual, field.name) });
                    return e;
                };
            }
        },

        .@"union" => |union_info| {
            if (union_info.tag_type == null) {
                @compileError("Unable to compare untagged union values for type " ++ @typeName(@TypeOf(actual)));
            }

            const Tag = std.meta.Tag(@TypeOf(expected));

            const expectedTag = @as(Tag, expected);
            const actualTag = @as(Tag, actual);

            try expectEqual(expectedTag, actualTag);

            // we only reach this switch if the tags are equal
            switch (expected) {
                inline else => |val, tag| {
                    try expectEqualDeep(val, @field(actual, @tagName(tag)));
                },
            }
        },

        .optional => {
            if (expected) |expected_payload| {
                if (actual) |actual_payload| {
                    try expectEqualDeep(expected_payload, actual_payload);
                } else {
                    print("expected {any}, found null\n", .{expected_payload});
                    return error.TestExpectedEqual;
                }
            } else {
                if (actual) |actual_payload| {
                    print("expected null, found {any}\n", .{actual_payload});
                    return error.TestExpectedEqual;
                }
            }
        },

        .error_union => {
            if (expected) |expected_payload| {
                if (actual) |actual_payload| {
                    try expectEqualDeep(expected_payload, actual_payload);
                } else |actual_err| {
                    print("expected {any}, found {any}\n", .{ expected_payload, actual_err });
                    return error.TestExpectedEqual;
                }
            } else |expected_err| {
                if (actual) |actual_payload| {
                    print("expected {any}, found {any}\n", .{ expected_err, actual_payload });
                    return error.TestExpectedEqual;
                } else |actual_err| {
                    try expectEqualDeep(expected_err, actual_err);
                }
            }
        },
    }
}

test "expectEqualDeep primitive type" {
    try expectEqualDeep(1, 1);
    try expectEqualDeep(true, true);
    try expectEqualDeep(1.5, 1.5);
    try expectEqualDeep(u8, u8);
    try expectEqualDeep(error.Bad, error.Bad);

    // optional
    {
        const foo: ?u32 = 1;
        const bar: ?u32 = 1;
        try expectEqualDeep(foo, bar);
        try expectEqualDeep(?u32, ?u32);
    }
    // function type
    {
        const fnType = struct {
            fn foo() void {
                unreachable;
            }
        }.foo;
        try expectEqualDeep(fnType, fnType);
    }
}

test "expectEqualDeep pointer" {
    const a = 1;
    const b = 1;
    try expectEqualDeep(&a, &b);
}

test "expectEqualDeep composite type" {
    try expectEqualDeep("abc", "abc");
    const s1: []const u8 = "abc";
    const s2 = "abcd";
    const s3: []const u8 = s2[0..3];
    try expectEqualDeep(s1, s3);

    const TestStruct = struct { s: []const u8 };
    try expectEqualDeep(TestStruct{ .s = "abc" }, TestStruct{ .s = "abc" });
    try expectEqualDeep([_][]const u8{ "a", "b", "c" }, [_][]const u8{ "a", "b", "c" });

    // vector
    try expectEqualDeep(@as(@Vector(4, u32), @splat(4)), @as(@Vector(4, u32), @splat(4)));

    // nested array
    {
        const a = [2][2]f32{
            [_]f32{ 1.0, 0.0 },
            [_]f32{ 0.0, 1.0 },
        };

        const b = [2][2]f32{
            [_]f32{ 1.0, 0.0 },
            [_]f32{ 0.0, 1.0 },
        };

        try expectEqualDeep(a, b);
        try expectEqualDeep(&a, &b);
    }

    // inferred union
    const TestStruct2 = struct {
        const A = union(enum) { b: B, c: C };
        const B = struct {};
        const C = struct { a: *const A };
    };

    const union1 = TestStruct2.A{ .b = .{} };
    try expectEqualDeep(
        TestStruct2.A{ .c = .{ .a = &union1 } },
        TestStruct2.A{ .c = .{ .a = &union1 } },
    );
}

fn printIndicatorLine(source: []const u8, indicator_index: usize) void {
    const line_begin_index = if (std.mem.lastIndexOfScalar(u8, source[0..indicator_index], '\n')) |line_begin|
        line_begin + 1
    else
        0;
    const line_end_index = if (std.mem.indexOfScalar(u8, source[indicator_index..], '\n')) |line_end|
        (indicator_index + line_end)
    else
        source.len;

    printLine(source[line_begin_index..line_end_index]);
    for (line_begin_index..indicator_index) |_|
        print(" ", .{});
    if (indicator_index >= source.len)
        print("^ (end of string)\n", .{})
    else
        print("^ ('\\x{x:0>2}')\n", .{source[indicator_index]});
}

fn printWithVisibleNewlines(source: []const u8) void {
    var i: usize = 0;
    while (std.mem.indexOfScalar(u8, source[i..], '\n')) |nl| : (i += nl + 1) {
        printLine(source[i..][0..nl]);
    }
    print("{s}␃\n", .{source[i..]}); // End of Text symbol (ETX)
}

fn printLine(line: []const u8) void {
    if (line.len != 0) switch (line[line.len - 1]) {
        ' ', '\t' => return print("{s}⏎\n", .{line}), // Return symbol
        else => {},
    };
    print("{s}\n", .{line});
}

test {
    try expectEqualStrings("foo", "foo");
}

/// Exhaustively check that allocation failures within `test_fn` are handled without
/// introducing memory leaks. If used with the `testing.allocator` as the `backing_allocator`,
/// it will also be able to detect double frees, etc (when runtime safety is enabled).
///
/// The provided `test_fn` must have a `std.mem.Allocator` as its first argument,
/// and must have a return type of `!void`. Any extra arguments of `test_fn` can
/// be provided via the `extra_args` tuple.
///
/// Any relevant state shared between runs of `test_fn` *must* be reset within `test_fn`.
///
/// The strategy employed is to:
/// - Run the test function once to get the total number of allocations.
/// - Then, iterate and run the function X more times, incrementing
///   the failing index each iteration (where X is the total number of
///   allocations determined previously)
///
/// Expects that `test_fn` has a deterministic number of memory allocations:
/// - If an allocation was made to fail during a run of `test_fn`, but `test_fn`
///   didn't return `error.OutOfMemory`, then `error.SwallowedOutOfMemoryError`
///   is returned from `checkAllAllocationFailures`. You may want to ignore this
///   depending on whether or not the code you're testing includes some strategies
///   for recovering from `error.OutOfMemory`.
/// - If a run of `test_fn` with an expected allocation failure executes without
///   an allocation failure being induced, then `error.NondeterministicMemoryUsage`
///   is returned. This error means that there are allocation points that won't be
///   tested by the strategy this function employs (that is, there are sometimes more
///   points of allocation than the initial run of `test_fn` detects).
///
/// ---
///
/// Here's an example using a simple test case that will cause a leak when the
/// allocation of `bar` fails (but will pass normally):
///
/// ```zig
/// test {
///     const length: usize = 10;
///     const allocator = std.testing.allocator;
///     var foo = try allocator.alloc(u8, length);
///     var bar = try allocator.alloc(u8, length);
///
///     allocator.free(foo);
///     allocator.free(bar);
/// }
/// ```
///
/// The test case can be converted to something that this function can use by
/// doing:
///
/// ```zig
/// fn testImpl(allocator: std.mem.Allocator, length: usize) !void {
///     var foo = try allocator.alloc(u8, length);
///     var bar = try allocator.alloc(u8, length);
///
///     allocator.free(foo);
///     allocator.free(bar);
/// }
///
/// test {
///     const length: usize = 10;
///     const allocator = std.testing.allocator;
///     try std.testing.checkAllAllocationFailures(allocator, testImpl, .{length});
/// }
/// ```
///
/// Running this test will show that `foo` is leaked when the allocation of
/// `bar` fails. The simplest fix, in this case, would be to use defer like so:
///
/// ```zig
/// fn testImpl(allocator: std.mem.Allocator, length: usize) !void {
///     var foo = try allocator.alloc(u8, length);
///     defer allocator.free(foo);
///     var bar = try allocator.alloc(u8, length);
///     defer allocator.free(bar);
/// }
/// ```
pub fn checkAllAllocationFailures(backing_allocator: std.mem.Allocator, comptime test_fn: anytype, extra_args: anytype) !void {
    switch (@typeInfo(@typeInfo(@TypeOf(test_fn)).@"fn".return_type.?)) {
        .error_union => |info| {
            if (info.payload != void) {
                @compileError("Return type must be !void");
            }
        },
        else => @compileError("Return type must be !void"),
    }
    if (@typeInfo(@TypeOf(extra_args)) != .@"struct") {
        @compileError("Expected tuple or struct argument, found " ++ @typeName(@TypeOf(extra_args)));
    }

    const ArgsTuple = std.meta.ArgsTuple(@TypeOf(test_fn));
    const fn_args_fields = @typeInfo(ArgsTuple).@"struct".fields;
    if (fn_args_fields.len == 0 or fn_args_fields[0].type != std.mem.Allocator) {
        @compileError("The provided function must have an " ++ @typeName(std.mem.Allocator) ++ " as its first argument");
    }
    const expected_args_tuple_len = fn_args_fields.len - 1;
    if (extra_args.len != expected_args_tuple_len) {
        @compileError("The provided function expects " ++ std.fmt.comptimePrint("{d}", .{expected_args_tuple_len}) ++ " extra arguments, but the provided tuple contains " ++ std.fmt.comptimePrint("{d}", .{extra_args.len}));
    }

    // Setup the tuple that will actually be used with @call (we'll need to insert
    // the failing allocator in field @"0" before each @call)
    var args: ArgsTuple = undefined;
    inline for (@typeInfo(@TypeOf(extra_args)).@"struct".fields, 0..) |field, i| {
        const arg_i_str = comptime str: {
            var str_buf: [100]u8 = undefined;
            const args_i = i + 1;
            const str_len = std.fmt.formatIntBuf(&str_buf, args_i, 10, .lower, .{});
            break :str str_buf[0..str_len];
        };
        @field(args, arg_i_str) = @field(extra_args, field.name);
    }

    // Try it once with unlimited memory, make sure it works
    const needed_alloc_count = x: {
        var failing_allocator_inst = std.testing.FailingAllocator.init(backing_allocator, .{});
        args.@"0" = failing_allocator_inst.allocator();

        try @call(.auto, test_fn, args);
        break :x failing_allocator_inst.alloc_index;
    };

    var fail_index: usize = 0;
    while (fail_index < needed_alloc_count) : (fail_index += 1) {
        var failing_allocator_inst = std.testing.FailingAllocator.init(backing_allocator, .{ .fail_index = fail_index });
        args.@"0" = failing_allocator_inst.allocator();

        if (@call(.auto, test_fn, args)) |_| {
            if (failing_allocator_inst.has_induced_failure) {
                return error.SwallowedOutOfMemoryError;
            } else {
                return error.NondeterministicMemoryUsage;
            }
        } else |err| switch (err) {
            error.OutOfMemory => {
                if (failing_allocator_inst.allocated_bytes != failing_allocator_inst.freed_bytes) {
                    print(
                        "\nfail_index: {d}/{d}\nallocated bytes: {d}\nfreed bytes: {d}\nallocations: {d}\ndeallocations: {d}\nallocation that was made to fail: {}",
                        .{
                            fail_index,
                            needed_alloc_count,
                            failing_allocator_inst.allocated_bytes,
                            failing_allocator_inst.freed_bytes,
                            failing_allocator_inst.allocations,
                            failing_allocator_inst.deallocations,
                            failing_allocator_inst.getStackTrace(),
                        },
                    );
                    return error.MemoryLeakDetected;
                }
            },
            else => return err,
        }
    }
}

/// Given a type, references all the declarations inside, so that the semantic analyzer sees them.
pub fn refAllDecls(comptime T: type) void {
    if (!builtin.is_test) return;
    inline for (comptime std.meta.declarations(T)) |decl| {
        _ = &@field(T, decl.name);
    }
}

/// Given a type, recursively references all the declarations inside, so that the semantic analyzer sees them.
/// For deep types, you may use `@setEvalBranchQuota`.
pub fn refAllDeclsRecursive(comptime T: type) void {
    if (!builtin.is_test) return;
    inline for (comptime std.meta.declarations(T)) |decl| {
        if (@TypeOf(@field(T, decl.name)) == type) {
            switch (@typeInfo(@field(T, decl.name))) {
                .@"struct", .@"enum", .@"union", .@"opaque" => refAllDeclsRecursive(@field(T, decl.name)),
                else => {},
            }
        }
        _ = &@field(T, decl.name);
    }
}

pub const FuzzInputOptions = struct {
    corpus: []const []const u8 = &.{},
};

/// Inline to avoid coverage instrumentation.
pub inline fn fuzz(
    context: anytype,
    comptime testOne: fn (context: @TypeOf(context), input: []const u8) anyerror!void,
    options: FuzzInputOptions,
) anyerror!void {
    return @import("root").fuzz(context, testOne, options);
}
//! Allocator that fails after N allocations, useful for making sure out of
//! memory conditions are handled correctly.
const std = @import("../std.zig");
const mem = std.mem;
const FailingAllocator = @This();

alloc_index: usize,
resize_index: usize,
internal_allocator: mem.Allocator,
allocated_bytes: usize,
freed_bytes: usize,
allocations: usize,
deallocations: usize,
stack_addresses: [num_stack_frames]usize,
has_induced_failure: bool,
fail_index: usize,
resize_fail_index: usize,

const num_stack_frames = if (std.debug.sys_can_stack_trace) 16 else 0;

pub const Config = struct {
    /// The number of successful allocations you can expect from this allocator.
    /// The next allocation will fail.
    fail_index: usize = std.math.maxInt(usize),

    /// Number of successful resizes to expect from this allocator. The next resize will fail.
    resize_fail_index: usize = std.math.maxInt(usize),
};

pub fn init(internal_allocator: mem.Allocator, config: Config) FailingAllocator {
    return FailingAllocator{
        .internal_allocator = internal_allocator,
        .alloc_index = 0,
        .resize_index = 0,
        .allocated_bytes = 0,
        .freed_bytes = 0,
        .allocations = 0,
        .deallocations = 0,
        .stack_addresses = undefined,
        .has_induced_failure = false,
        .fail_index = config.fail_index,
        .resize_fail_index = config.resize_fail_index,
    };
}

pub fn allocator(self: *FailingAllocator) mem.Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        },
    };
}

fn alloc(
    ctx: *anyopaque,
    len: usize,
    alignment: mem.Alignment,
    return_address: usize,
) ?[*]u8 {
    const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
    if (self.alloc_index == self.fail_index) {
        if (!self.has_induced_failure) {
            @memset(&self.stack_addresses, 0);
            var stack_trace = std.builtin.StackTrace{
                .instruction_addresses = &self.stack_addresses,
                .index = 0,
            };
            std.debug.captureStackTrace(return_address, &stack_trace);
            self.has_induced_failure = true;
        }
        return null;
    }
    const result = self.internal_allocator.rawAlloc(len, alignment, return_address) orelse
        return null;
    self.allocated_bytes += len;
    self.allocations += 1;
    self.alloc_index += 1;
    return result;
}

fn resize(
    ctx: *anyopaque,
    memory: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    ra: usize,
) bool {
    const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
    if (self.resize_index == self.resize_fail_index)
        return false;
    if (!self.internal_allocator.rawResize(memory, alignment, new_len, ra))
        return false;
    if (new_len < memory.len) {
        self.freed_bytes += memory.len - new_len;
    } else {
        self.allocated_bytes += new_len - memory.len;
    }
    self.resize_index += 1;
    return true;
}

fn remap(
    ctx: *anyopaque,
    memory: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    ra: usize,
) ?[*]u8 {
    const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
    if (self.resize_index == self.resize_fail_index) return null;
    const new_ptr = self.internal_allocator.rawRemap(memory, alignment, new_len, ra) orelse return null;
    if (new_len < memory.len) {
        self.freed_bytes += memory.len - new_len;
    } else {
        self.allocated_bytes += new_len - memory.len;
    }
    self.resize_index += 1;
    return new_ptr;
}

fn free(
    ctx: *anyopaque,
    old_mem: []u8,
    alignment: mem.Alignment,
    ra: usize,
) void {
    const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
    self.internal_allocator.rawFree(old_mem, alignment, ra);
    self.deallocations += 1;
    self.freed_bytes += old_mem.len;
}

/// Only valid once `has_induced_failure == true`
pub fn getStackTrace(self: *FailingAllocator) std.builtin.StackTrace {
    std.debug.assert(self.has_induced_failure);
    var len: usize = 0;
    while (len < self.stack_addresses.len and self.stack_addresses[len] != 0) {
        len += 1;
    }
    return .{
        .instruction_addresses = &self.stack_addresses,
        .index = len,
    };
}

test FailingAllocator {
    // Fail on allocation
    {
        var failing_allocator_state = FailingAllocator.init(std.testing.allocator, .{
            .fail_index = 2,
        });
        const failing_alloc = failing_allocator_state.allocator();

        const a = try failing_alloc.create(i32);
        defer failing_alloc.destroy(a);
        const b = try failing_alloc.create(i32);
        defer failing_alloc.destroy(b);
        try std.testing.expectError(error.OutOfMemory, failing_alloc.create(i32));
    }
    // Fail on resize
    {
        var failing_allocator_state = FailingAllocator.init(std.testing.allocator, .{
            .resize_fail_index = 1,
        });
        const failing_alloc = failing_allocator_state.allocator();

        const resized_slice = blk: {
            const slice = try failing_alloc.alloc(u8, 8);
            errdefer failing_alloc.free(slice);

            break :blk failing_alloc.remap(slice, 6) orelse return error.UnexpectedRemapFailure;
        };
        defer failing_alloc.free(resized_slice);

        // Remap and resize should fail from here on out
        try std.testing.expectEqual(null, failing_alloc.remap(resized_slice, 4));
        try std.testing.expectEqual(false, failing_alloc.resize(resized_slice, 4));

        // Note: realloc could succeed because it falls back to free+alloc
    }
}
//! This struct represents a kernel thread, and acts as a namespace for concurrency
//! primitives that operate on kernel threads. For concurrency primitives that support
//! both evented I/O and async I/O, see the respective names in the top level std namespace.

const std = @import("std.zig");
const builtin = @import("builtin");
const math = std.math;
const assert = std.debug.assert;
const target = builtin.target;
const native_os = builtin.os.tag;
const posix = std.posix;
const windows = std.os.windows;

pub const Futex = @import("Thread/Futex.zig");
pub const ResetEvent = @import("Thread/ResetEvent.zig");
pub const Mutex = @import("Thread/Mutex.zig");
pub const Semaphore = @import("Thread/Semaphore.zig");
pub const Condition = @import("Thread/Condition.zig");
pub const RwLock = @import("Thread/RwLock.zig");
pub const Pool = @import("Thread/Pool.zig");
pub const WaitGroup = @import("Thread/WaitGroup.zig");

pub const use_pthreads = native_os != .windows and native_os != .wasi and builtin.link_libc;

/// Spurious wakeups are possible and no precision of timing is guaranteed.
pub fn sleep(nanoseconds: u64) void {
    if (builtin.os.tag == .windows) {
        const big_ms_from_ns = nanoseconds / std.time.ns_per_ms;
        const ms = math.cast(windows.DWORD, big_ms_from_ns) orelse math.maxInt(windows.DWORD);
        windows.kernel32.Sleep(ms);
        return;
    }

    if (builtin.os.tag == .wasi) {
        const w = std.os.wasi;
        const userdata: w.userdata_t = 0x0123_45678;
        const clock: w.subscription_clock_t = .{
            .id = .MONOTONIC,
            .timeout = nanoseconds,
            .precision = 0,
            .flags = 0,
        };
        const in: w.subscription_t = .{
            .userdata = userdata,
            .u = .{
                .tag = .CLOCK,
                .u = .{ .clock = clock },
            },
        };

        var event: w.event_t = undefined;
        var nevents: usize = undefined;
        _ = w.poll_oneoff(&in, &event, 1, &nevents);
        return;
    }

    if (builtin.os.tag == .uefi) {
        const boot_services = std.os.uefi.system_table.boot_services.?;
        const us_from_ns ```
