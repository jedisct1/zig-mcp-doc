```
  result[@intFromEnum(Feature.occmo)] = .{
        .llvm_name = "occmo",
        .description = "Enable Armv9.6-A Outer cacheable cache maintenance operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.outline_atomics)] = .{
        .llvm_name = "outline-atomics",
        .description = "Enable out of line atomics to support LSE instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pan)] = .{
        .llvm_name = "pan",
        .description = "Enable Armv8.1-A Privileged Access-Never extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pan_rwv)] = .{
        .llvm_name = "pan-rwv",
        .description = "Enable Armv8.2-A PAN s1e1R and s1e1W Variants",
        .dependencies = featureSet(&[_]Feature{
            .pan,
        }),
    };
    result[@intFromEnum(Feature.pauth)] = .{
        .llvm_name = "pauth",
        .description = "Enable Armv8.3-A Pointer Authentication extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pauth_lr)] = .{
        .llvm_name = "pauth-lr",
        .description = "Enable Armv9.5-A PAC enhancements",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pcdphint)] = .{
        .llvm_name = "pcdphint",
        .description = "Enable Armv9.6-A Producer Consumer Data Placement hints",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.perfmon)] = .{
        .llvm_name = "perfmon",
        .description = "Enable Armv8.0-A PMUv3 Performance Monitors extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pops)] = .{
        .llvm_name = "pops",
        .description = "Enable Armv9.6-A Point Of Physical Storage (PoPS) DC instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.predictable_select_expensive)] = .{
        .llvm_name = "predictable-select-expensive",
        .description = "Prefer likely predicted branches over selects",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.predres)] = .{
        .llvm_name = "predres",
        .description = "Enable Armv8.5-A execution and data prediction invalidation instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prfm_slc_target)] = .{
        .llvm_name = "prfm-slc-target",
        .description = "Enable SLC target for PRFM instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rand)] = .{
        .llvm_name = "rand",
        .description = "Enable Random Number generation instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ras)] = .{
        .llvm_name = "ras",
        .description = "Enable Armv8.0-A Reliability, Availability and Serviceability Extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rasv2)] = .{
        .llvm_name = "rasv2",
        .description = "Enable Armv8.9-A Reliability, Availability and Serviceability Extensions",
        .dependencies = featureSet(&[_]Feature{
            .ras,
        }),
    };
    result[@intFromEnum(Feature.rcpc)] = .{
        .llvm_name = "rcpc",
        .description = "Enable support for RCPC extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rcpc3)] = .{
        .llvm_name = "rcpc3",
        .description = "Enable Armv8.9-A RCPC instructions for A64 and Advanced SIMD and floating-point instruction set",
        .dependencies = featureSet(&[_]Feature{
            .rcpc_immo,
        }),
    };
    result[@intFromEnum(Feature.rcpc_immo)] = .{
        .llvm_name = "rcpc-immo",
        .description = "Enable Armv8.4-A RCPC instructions with Immediate Offsets",
        .dependencies = featureSet(&[_]Feature{
            .rcpc,
        }),
    };
    result[@intFromEnum(Feature.rdm)] = .{
        .llvm_name = "rdm",
        .description = "Enable Armv8.1-A Rounding Double Multiply Add/Subtract instructions",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.reserve_lr_for_ra)] = .{
        .llvm_name = "reserve-lr-for-ra",
        .description = "Reserve LR for call use only",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x1)] = .{
        .llvm_name = "reserve-x1",
        .description = "Reserve X1, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x10)] = .{
        .llvm_name = "reserve-x10",
        .description = "Reserve X10, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x11)] = .{
        .llvm_name = "reserve-x11",
        .description = "Reserve X11, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x12)] = .{
        .llvm_name = "reserve-x12",
        .description = "Reserve X12, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x13)] = .{
        .llvm_name = "reserve-x13",
        .description = "Reserve X13, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x14)] = .{
        .llvm_name = "reserve-x14",
        .description = "Reserve X14, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x15)] = .{
        .llvm_name = "reserve-x15",
        .description = "Reserve X15, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x18)] = .{
        .llvm_name = "reserve-x18",
        .description = "Reserve X18, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x2)] = .{
        .llvm_name = "reserve-x2",
        .description = "Reserve X2, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x20)] = .{
        .llvm_name = "reserve-x20",
        .description = "Reserve X20, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x21)] = .{
        .llvm_name = "reserve-x21",
        .description = "Reserve X21, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x22)] = .{
        .llvm_name = "reserve-x22",
        .description = "Reserve X22, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x23)] = .{
        .llvm_name = "reserve-x23",
        .description = "Reserve X23, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x24)] = .{
        .llvm_name = "reserve-x24",
        .description = "Reserve X24, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x25)] = .{
        .llvm_name = "reserve-x25",
        .description = "Reserve X25, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x26)] = .{
        .llvm_name = "reserve-x26",
        .description = "Reserve X26, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x27)] = .{
        .llvm_name = "reserve-x27",
        .description = "Reserve X27, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x28)] = .{
        .llvm_name = "reserve-x28",
        .description = "Reserve X28, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x3)] = .{
        .llvm_name = "reserve-x3",
        .description = "Reserve X3, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x4)] = .{
        .llvm_name = "reserve-x4",
        .description = "Reserve X4, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x5)] = .{
        .llvm_name = "reserve-x5",
        .description = "Reserve X5, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x6)] = .{
        .llvm_name = "reserve-x6",
        .description = "Reserve X6, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x7)] = .{
        .llvm_name = "reserve-x7",
        .description = "Reserve X7, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_x9)] = .{
        .llvm_name = "reserve-x9",
        .description = "Reserve X9, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.rme)] = .{
        .llvm_name = "rme",
        .description = "Enable Realm Management Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sb)] = .{
        .llvm_name = "sb",
        .description = "Enable Armv8.5-A Speculation Barrier",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sel2)] = .{
        .llvm_name = "sel2",
        .description = "Enable Armv8.4-A Secure Exception Level 2 extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sha2)] = .{
        .llvm_name = "sha2",
        .description = "Enable SHA1 and SHA256 support",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.sha3)] = .{
        .llvm_name = "sha3",
        .description = "Enable SHA512 and SHA3 support",
        .dependencies = featureSet(&[_]Feature{
            .sha2,
        }),
    };
    result[@intFromEnum(Feature.slow_misaligned_128store)] = .{
        .llvm_name = "slow-misaligned-128store",
        .description = "Misaligned 128 bit stores are slow",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_paired_128)] = .{
        .llvm_name = "slow-paired-128",
        .description = "Paired 128 bit loads and stores are slow",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_strqro_store)] = .{
        .llvm_name = "slow-strqro-store",
        .description = "STR of Q register with register offset is slow",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sm4)] = .{
        .llvm_name = "sm4",
        .description = "Enable SM3 and SM4 support",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.sme)] = .{
        .llvm_name = "sme",
        .description = "Enable Scalable Matrix Extension (SME)",
        .dependencies = featureSet(&[_]Feature{
            .bf16,
            .fullfp16,
        }),
    };
    result[@intFromEnum(Feature.sme2)] = .{
        .llvm_name = "sme2",
        .description = "Enable Scalable Matrix Extension 2 (SME2) instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme,
        }),
    };
    result[@intFromEnum(Feature.sme2p1)] = .{
        .llvm_name = "sme2p1",
        .description = "Enable Scalable Matrix Extension 2.1 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.sme2p2)] = .{
        .llvm_name = "sme2p2",
        .description = "Enable Armv9.6-A Scalable Matrix Extension 2.2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme2p1,
        }),
    };
    result[@intFromEnum(Feature.sme_b16b16)] = .{
        .llvm_name = "sme-b16b16",
        .description = "Enable SME2.1 ZA-targeting non-widening BFloat16 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
            .sve_b16b16,
        }),
    };
    result[@intFromEnum(Feature.sme_f16f16)] = .{
        .llvm_name = "sme-f16f16",
        .description = "Enable SME non-widening Float16 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.sme_f64f64)] = .{
        .llvm_name = "sme-f64f64",
        .description = "Enable Scalable Matrix Extension (SME) F64F64 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme,
        }),
    };
    result[@intFromEnum(Feature.sme_f8f16)] = .{
        .llvm_name = "sme-f8f16",
        .description = "Enable Scalable Matrix Extension (SME) F8F16 instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.sme_f8f32)] = .{
        .llvm_name = "sme-f8f32",
        .description = "Enable Scalable Matrix Extension (SME) F8F32 instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.sme_fa64)] = .{
        .llvm_name = "sme-fa64",
        .description = "Enable the full A64 instruction set in streaming SVE mode",
        .dependencies = featureSet(&[_]Feature{
            .sme,
            .sve2,
        }),
    };
    result[@intFromEnum(Feature.sme_i16i64)] = .{
        .llvm_name = "sme-i16i64",
        .description = "Enable Scalable Matrix Extension (SME) I16I64 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme,
        }),
    };
    result[@intFromEnum(Feature.sme_lutv2)] = .{
        .llvm_name = "sme-lutv2",
        .description = "Enable Scalable Matrix Extension (SME) LUTv2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.sme_mop4)] = .{
        .llvm_name = "sme-mop4",
        .description = "Enable SME Quarter-tile outer product instructions",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.sme_tmop)] = .{
        .llvm_name = "sme-tmop",
        .description = "Enable SME Structured sparsity outer product instructions.",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.spe)] = .{
        .llvm_name = "spe",
        .description = "Enable Statistical Profiling extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.spe_eef)] = .{
        .llvm_name = "spe-eef",
        .description = "Enable extra register in the Statistical Profiling Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.specres2)] = .{
        .llvm_name = "specres2",
        .description = "Enable Speculation Restriction Instruction",
        .dependencies = featureSet(&[_]Feature{
            .predres,
        }),
    };
    result[@intFromEnum(Feature.specrestrict)] = .{
        .llvm_name = "specrestrict",
        .description = "Enable architectural speculation restriction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssbs)] = .{
        .llvm_name = "ssbs",
        .description = "Enable Speculative Store Bypass Safe bit",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ssve_aes)] = .{
        .llvm_name = "ssve-aes",
        .description = "Enable Armv9.6-A SVE AES support in streaming SVE mode",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
            .sve_aes,
        }),
    };
    result[@intFromEnum(Feature.ssve_bitperm)] = .{
        .llvm_name = "ssve-bitperm",
        .description = "Enable Armv9.6-A SVE BitPerm support in streaming SVE mode",
        .dependencies = featureSet(&[_]Feature{
            .sme2,
            .sve_bitperm,
        }),
    };
    result[@intFromEnum(Feature.ssve_fp8dot2)] = .{
        .llvm_name = "ssve-fp8dot2",
        .description = "Enable SVE2 FP8 2-way dot product instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.ssve_fp8dot4)] = .{
        .llvm_name = "ssve-fp8dot4",
        .description = "Enable SVE2 FP8 4-way dot product instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.ssve_fp8fma)] = .{
        .llvm_name = "ssve-fp8fma",
        .description = "Enable SVE2 FP8 multiply-add instructions",
        .dependencies = featureSet(&[_]Feature{
            .fp8,
            .sme2,
        }),
    };
    result[@intFromEnum(Feature.store_pair_suppress)] = .{
        .llvm_name = "store-pair-suppress",
        .description = "Enable Store Pair Suppression heuristics",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.stp_aligned_only)] = .{
        .llvm_name = "stp-aligned-only",
        .description = "In order to emit stp, first check if the store will be aligned to 2 * element_size",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.strict_align)] = .{
        .llvm_name = "strict-align",
        .description = "Disallow all unaligned memory access",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sve)] = .{
        .llvm_name = "sve",
        .description = "Enable Scalable Vector Extension (SVE) instructions",
        .dependencies = featureSet(&[_]Feature{
            .fullfp16,
        }),
    };
    result[@intFromEnum(Feature.sve2)] = .{
        .llvm_name = "sve2",
        .description = "Enable Scalable Vector Extension 2 (SVE2) instructions",
        .dependencies = featureSet(&[_]Feature{
            .sve,
        }),
    };
    result[@intFromEnum(Feature.sve2_aes)] = .{
        .llvm_name = "sve2-aes",
        .description = "Shorthand for +sve2+sve-aes",
        .dependencies = featureSet(&[_]Feature{
            .sve2,
            .sve_aes,
        }),
    };
    result[@intFromEnum(Feature.sve2_bitperm)] = .{
        .llvm_name = "sve2-bitperm",
        .description = "Shorthand for +sve2+sve-bitperm",
        .dependencies = featureSet(&[_]Feature{
            .sve2,
            .sve_bitperm,
        }),
    };
    result[@intFromEnum(Feature.sve2_sha3)] = .{
        .llvm_name = "sve2-sha3",
        .description = "Enable SHA3 SVE2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sha3,
            .sve2,
        }),
    };
    result[@intFromEnum(Feature.sve2_sm4)] = .{
        .llvm_name = "sve2-sm4",
        .description = "Enable SM4 SVE2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sm4,
            .sve2,
        }),
    };
    result[@intFromEnum(Feature.sve2p1)] = .{
        .llvm_name = "sve2p1",
        .description = "Enable Scalable Vector Extension 2.1 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sve2,
        }),
    };
    result[@intFromEnum(Feature.sve2p2)] = .{
        .llvm_name = "sve2p2",
        .description = "Enable Armv9.6-A Scalable Vector Extension 2.2 instructions",
        .dependencies = featureSet(&[_]Feature{
            .sve2p1,
        }),
    };
    result[@intFromEnum(Feature.sve_aes)] = .{
        .llvm_name = "sve-aes",
        .description = "Enable SVE AES and quadword SVE polynomial multiply instructions",
        .dependencies = featureSet(&[_]Feature{
            .aes,
        }),
    };
    result[@intFromEnum(Feature.sve_aes2)] = .{
        .llvm_name = "sve-aes2",
        .description = "Enable Armv9.6-A SVE multi-vector AES and multi-vector quadword polynomial multiply instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sve_b16b16)] = .{
        .llvm_name = "sve-b16b16",
        .description = "Enable SVE2 non-widening and SME2 Z-targeting non-widening BFloat16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sve_bfscale)] = .{
        .llvm_name = "sve-bfscale",
        .description = "Enable Armv9.6-A SVE BFloat16 scaling instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sve_bitperm)] = .{
        .llvm_name = "sve-bitperm",
        .description = "Enable bit permutation SVE2 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sve_f16f32mm)] = .{
        .llvm_name = "sve-f16f32mm",
        .description = "Enable Armv9.6-A FP16 to FP32 Matrix Multiply instructions",
        .dependencies = featureSet(&[_]Feature{
            .sve,
        }),
    };
    result[@intFromEnum(Feature.tagged_globals)] = .{
        .llvm_name = "tagged-globals",
        .description = "Use an instruction sequence for taking the address of a global that allows a memory tag in the upper address bits",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.the)] = .{
        .llvm_name = "the",
        .description = "Enable Armv8.9-A Translation Hardening Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tlb_rmi)] = .{
        .llvm_name = "tlb-rmi",
        .description = "Enable Armv8.4-A TLB Range and Maintenance instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tlbiw)] = .{
        .llvm_name = "tlbiw",
        .description = "Enable Armv9.5-A TLBI VMALL for Dirty State",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tme)] = .{
        .llvm_name = "tme",
        .description = "Enable Transactional Memory Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tpidr_el1)] = .{
        .llvm_name = "tpidr-el1",
        .description = "Permit use of TPIDR_EL1 for the TLS base",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tpidr_el2)] = .{
        .llvm_name = "tpidr-el2",
        .description = "Permit use of TPIDR_EL2 for the TLS base",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tpidr_el3)] = .{
        .llvm_name = "tpidr-el3",
        .description = "Permit use of TPIDR_EL3 for the TLS base",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tpidrro_el0)] = .{
        .llvm_name = "tpidrro-el0",
        .description = "Permit use of TPIDRRO_EL0 for the TLS base",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tracev8_4)] = .{
        .llvm_name = "tracev8.4",
        .description = "Enable Armv8.4-A Trace extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.trbe)] = .{
        .llvm_name = "trbe",
        .description = "Enable Trace Buffer Extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.uaops)] = .{
        .llvm_name = "uaops",
        .description = "Enable Armv8.2-A UAO PState",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_experimental_zeroing_pseudos)] = .{
        .llvm_name = "use-experimental-zeroing-pseudos",
        .description = "Hint to the compiler that the MOVPRFX instruction is merged with destructive operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_fixed_over_scalable_if_equal_cost)] = .{
        .llvm_name = "use-fixed-over-scalable-if-equal-cost",
        .description = "Prefer fixed width loop vectorization over scalable if the cost-model assigns equal costs",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_postra_scheduler)] = .{
        .llvm_name = "use-postra-scheduler",
        .description = "Schedule again after register allocation",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.use_reciprocal_square_root)] = .{
        .llvm_name = "use-reciprocal-square-root",
        .description = "Use the reciprocal square root approximation",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v8_1a)] = .{
        .llvm_name = "v8.1a",
        .description = "Support ARM v8.1a architecture",
        .dependencies = featureSet(&[_]Feature{
            .crc,
            .lor,
            .lse,
            .pan,
            .rdm,
            .v8a,
            .vh,
        }),
    };
    result[@intFromEnum(Feature.v8_2a)] = .{
        .llvm_name = "v8.2a",
        .description = "Support ARM v8.2a architecture",
        .dependencies = featureSet(&[_]Feature{
            .ccpp,
            .pan_rwv,
            .ras,
            .uaops,
            .v8_1a,
        }),
    };
    result[@intFromEnum(Feature.v8_3a)] = .{
        .llvm_name = "v8.3a",
        .description = "Support ARM v8.3a architecture",
        .dependencies = featureSet(&[_]Feature{
            .ccidx,
            .complxnum,
            .jsconv,
            .pauth,
            .rcpc,
            .v8_2a,
        }),
    };
    result[@intFromEnum(Feature.v8_4a)] = .{
        .llvm_name = "v8.4a",
        .description = "Support ARM v8.4a architecture",
        .dependencies = featureSet(&[_]Feature{
            .am,
            .dit,
            .dotprod,
            .flagm,
            .lse2,
            .mpam,
            .nv,
            .rcpc_immo,
            .sel2,
            .tlb_rmi,
            .tracev8_4,
            .v8_3a,
        }),
    };
    result[@intFromEnum(Feature.v8_5a)] = .{
        .llvm_name = "v8.5a",
        .description = "Support ARM v8.5a architecture",
        .dependencies = featureSet(&[_]Feature{
            .altnzcv,
            .bti,
            .ccdp,
            .fptoint,
            .predres,
            .sb,
            .specrestrict,
            .ssbs,
            .v8_4a,
        }),
    };
    result[@intFromEnum(Feature.v8_6a)] = .{
        .llvm_name = "v8.6a",
        .description = "Support ARM v8.6a architecture",
        .dependencies = featureSet(&[_]Feature{
            .amvs,
            .bf16,
            .ecv,
            .fgt,
            .i8mm,
            .v8_5a,
        }),
    };
    result[@intFromEnum(Feature.v8_7a)] = .{
        .llvm_name = "v8.7a",
        .description = "Support ARM v8.7a architecture",
        .dependencies = featureSet(&[_]Feature{
            .hcx,
            .spe_eef,
            .v8_6a,
            .wfxt,
            .xs,
        }),
    };
    result[@intFromEnum(Feature.v8_8a)] = .{
        .llvm_name = "v8.8a",
        .description = "Support ARM v8.8a architecture",
        .dependencies = featureSet(&[_]Feature{
            .hbc,
            .mops,
            .nmi,
            .v8_7a,
        }),
    };
    result[@intFromEnum(Feature.v8_9a)] = .{
        .llvm_name = "v8.9a",
        .description = "Support ARM v8.9a architecture",
        .dependencies = featureSet(&[_]Feature{
            .chk,
            .clrbhb,
            .cssc,
            .prfm_slc_target,
            .rasv2,
            .specres2,
            .v8_8a,
        }),
    };
    result[@intFromEnum(Feature.v8a)] = .{
        .llvm_name = "v8a",
        .description = "Support ARM v8a architecture",
        .dependencies = featureSet(&[_]Feature{
            .el2vmsa,
            .el3,
            .neon,
        }),
    };
    result[@intFromEnum(Feature.v8r)] = .{
        .llvm_name = "v8r",
        .description = "Support ARM v8r architecture",
        .dependencies = featureSet(&[_]Feature{
            .ccidx,
            .ccpp,
            .complxnum,
            .contextidr_el2,
            .crc,
            .dit,
            .dotprod,
            .flagm,
            .fp16fml,
            .jsconv,
            .lse,
            .pan_rwv,
            .pauth,
            .ras,
            .rcpc_immo,
            .rdm,
            .sb,
            .sel2,
            .specrestrict,
            .ssbs,
            .tlb_rmi,
            .tracev8_4,
            .uaops,
        }),
    };
    result[@intFromEnum(Feature.v9_1a)] = .{
        .llvm_name = "v9.1a",
        .description = "Support ARM v9.1a architecture",
        .dependencies = featureSet(&[_]Feature{
            .rme,
            .v8_6a,
            .v9a,
        }),
    };
    result[@intFromEnum(Feature.v9_2a)] = .{
        .llvm_name = "v9.2a",
        .description = "Support ARM v9.2a architecture",
        .dependencies = featureSet(&[_]Feature{
            .mec,
            .v8_7a,
            .v9_1a,
        }),
    };
    result[@intFromEnum(Feature.v9_3a)] = .{
        .llvm_name = "v9.3a",
        .description = "Support ARM v9.3a architecture",
        .dependencies = featureSet(&[_]Feature{
            .v8_8a,
            .v9_2a,
        }),
    };
    result[@intFromEnum(Feature.v9_4a)] = .{
        .llvm_name = "v9.4a",
        .description = "Support ARM v9.4a architecture",
        .dependencies = featureSet(&[_]Feature{
            .sve2p1,
            .v8_9a,
            .v9_3a,
        }),
    };
    result[@intFromEnum(Feature.v9_5a)] = .{
        .llvm_name = "v9.5a",
        .description = "Support ARM v9.5a architecture",
        .dependencies = featureSet(&[_]Feature{
            .cpa,
            .faminmax,
            .lut,
            .v9_4a,
        }),
    };
    result[@intFromEnum(Feature.v9_6a)] = .{
        .llvm_name = "v9.6a",
        .description = "Support ARM v9.6a architecture",
        .dependencies = featureSet(&[_]Feature{
            .cmpbr,
            .fprcvt,
            .lsui,
            .occmo,
            .sve2p2,
            .v9_5a,
        }),
    };
    result[@intFromEnum(Feature.v9a)] = .{
        .llvm_name = "v9a",
        .description = "Support ARM v9a architecture",
        .dependencies = featureSet(&[_]Feature{
            .sve2,
            .v8_5a,
        }),
    };
    result[@intFromEnum(Feature.vh)] = .{
        .llvm_name = "vh",
        .description = "Enable Armv8.1-A Virtual Host extension",
        .dependencies = featureSet(&[_]Feature{
            .contextidr_el2,
        }),
    };
    result[@intFromEnum(Feature.wfxt)] = .{
        .llvm_name = "wfxt",
        .description = "Enable Armv8.7-A WFET and WFIT instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xs)] = .{
        .llvm_name = "xs",
        .description = "Enable Armv8.7-A limited-TLB-maintenance instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zcm)] = .{
        .llvm_name = "zcm",
        .description = "Has zero-cycle register moves",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zcz)] = .{
        .llvm_name = "zcz",
        .description = "Has zero-cycle zeroing instructions",
        .dependencies = featureSet(&[_]Feature{
            .zcz_gp,
        }),
    };
    result[@intFromEnum(Feature.zcz_fp_workaround)] = .{
        .llvm_name = "zcz-fp-workaround",
        .description = "The zero-cycle floating-point zeroing instruction has a bug",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zcz_gp)] = .{
        .llvm_name = "zcz-gp",
        .description = "Has zero-cycle zeroing instructions for generic registers",
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
    pub const a64fx: CpuModel = .{
        .name = "a64fx",
        .llvm_name = "a64fx",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .arith_bcc_fusion,
            .complxnum,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .sve,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const ampere1: CpuModel = .{
        .name = "ampere1",
        .llvm_name = "ampere1",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .alu_lsl_fast,
            .arith_bcc_fusion,
            .cmp_bcc_fusion,
            .fullfp16,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_literals,
            .ldp_aligned_only,
            .perfmon,
            .rand,
            .sha3,
            .store_pair_suppress,
            .stp_aligned_only,
            .use_postra_scheduler,
            .v8_6a,
        }),
    };
    pub const ampere1a: CpuModel = .{
        .name = "ampere1a",
        .llvm_name = "ampere1a",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .alu_lsl_fast,
            .arith_bcc_fusion,
            .cmp_bcc_fusion,
            .fullfp16,
            .fuse_address,
            .fuse_addsub_2reg_const1,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_literals,
            .ldp_aligned_only,
            .mte,
            .perfmon,
            .rand,
            .sha3,
            .sm4,
            .store_pair_suppress,
            .stp_aligned_only,
            .use_postra_scheduler,
            .v8_6a,
        }),
    };
    pub const ampere1b: CpuModel = .{
        .name = "ampere1b",
        .llvm_name = "ampere1b",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .alu_lsl_fast,
            .arith_bcc_fusion,
            .cmp_bcc_fusion,
            .cssc,
            .enable_select_opt,
            .fullfp16,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_literals,
            .ldp_aligned_only,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .sha3,
            .sm4,
            .store_pair_suppress,
            .stp_aligned_only,
            .use_postra_scheduler,
            .v8_7a,
        }),
    };
    pub const apple_a10: CpuModel = .{
        .name = "apple_a10",
        .llvm_name = "apple-a10",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .crc,
            .disable_latency_sched_heuristic,
            .fuse_aes,
            .fuse_crypto_eor,
            .lor,
            .pan,
            .perfmon,
            .rdm,
            .sha2,
            .store_pair_suppress,
            .v8a,
            .vh,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a11: CpuModel = .{
        .name = "apple_a11",
        .llvm_name = "apple-a11",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fullfp16,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8_2a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a12: CpuModel = .{
        .name = "apple_a12",
        .llvm_name = "apple-a12",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fullfp16,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8_3a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a13: CpuModel = .{
        .name = "apple_a13",
        .llvm_name = "apple-a13",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha3,
            .store_pair_suppress,
            .v8_4a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a14: CpuModel = .{
        .name = "apple_a14",
        .llvm_name = "apple-a14",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .alternate_sextload_cvt_f32_pattern,
            .altnzcv,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .ccdp,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fptoint,
            .fuse_address,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .predres,
            .sb,
            .sha3,
            .specrestrict,
            .ssbs,
            .store_pair_suppress,
            .v8_4a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a15: CpuModel = .{
        .name = "apple_a15",
        .llvm_name = "apple-a15",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fpac,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .sha3,
            .store_pair_suppress,
            .v8_6a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a16: CpuModel = .{
        .name = "apple_a16",
        .llvm_name = "apple-a16",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fpac,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .hcx,
            .perfmon,
            .sha3,
            .store_pair_suppress,
            .v8_6a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a17: CpuModel = .{
        .name = "apple_a17",
        .llvm_name = "apple-a17",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fpac,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .hcx,
            .perfmon,
            .sha3,
            .store_pair_suppress,
            .v8_6a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_a7: CpuModel = .{
        .name = "apple_a7",
        .llvm_name = "apple-a7",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8a,
            .zcm,
            .zcz,
            .zcz_fp_workaround,
        }),
    };
    pub const apple_a8: CpuModel = .{
        .name = "apple_a8",
        .llvm_name = "apple-a8",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8a,
            .zcm,
            .zcz,
            .zcz_fp_workaround,
        }),
    };
    pub const apple_a9: CpuModel = .{
        .name = "apple_a9",
        .llvm_name = "apple-a9",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8a,
            .zcm,
            .zcz,
            .zcz_fp_workaround,
        }),
    };
    pub const apple_m1: CpuModel = .{
        .name = "apple_m1",
        .llvm_name = "apple-m1",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .alternate_sextload_cvt_f32_pattern,
            .altnzcv,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .ccdp,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fptoint,
            .fuse_address,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .predres,
            .sb,
            .sha3,
            .specrestrict,
            .ssbs,
            .store_pair_suppress,
            .v8_4a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_m2: CpuModel = .{
        .name = "apple_m2",
        .llvm_name = "apple-m2",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fpac,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .sha3,
            .store_pair_suppress,
            .v8_6a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_m3: CpuModel = .{
        .name = "apple_m3",
        .llvm_name = "apple-m3",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fpac,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .hcx,
            .perfmon,
            .sha3,
            .store_pair_suppress,
            .v8_6a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_m4: CpuModel = .{
        .name = "apple_m4",
        .llvm_name = "apple-m4",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fp16fml,
            .fpac,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_crypto_eor,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .sha3,
            .sme2,
            .sme_f64f64,
            .sme_i16i64,
            .v8_7a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_s4: CpuModel = .{
        .name = "apple_s4",
        .llvm_name = "apple-s4",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fullfp16,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8_3a,
            .zcm,
            .zcz,
        }),
    };
    pub const apple_s5: CpuModel = .{
        .name = "apple_s5",
        .llvm_name = "apple-s5",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fullfp16,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8_3a,
            .zcm,
            .zcz,
        }),
    };
    pub const carmel: CpuModel = .{
        .name = "carmel",
        .llvm_name = "carmel",
        .features = featureSet(&[_]Feature{
            .aes,
            .fullfp16,
            .sha2,
            .v8_2a,
        }),
    };
    pub const cobalt_100: CpuModel = .{
        .name = "cobalt_100",
        .llvm_name = "cobalt-100",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .bf16,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const cortex_a34: CpuModel = .{
        .name = "cortex_a34",
        .llvm_name = "cortex-a34",
        .features = featureSet(&[_]Feature{
            .aes,
            .crc,
            .perfmon,
            .sha2,
            .v8a,
        }),
    };
    pub const cortex_a35: CpuModel = .{
        .name = "cortex_a35",
        .llvm_name = "cortex-a35",
        .features = featureSet(&[_]Feature{
            .aes,
            .crc,
            .perfmon,
            .sha2,
            .v8a,
        }),
    };
    pub const cortex_a510: CpuModel = .{
        .name = "cortex_a510",
        .llvm_name = "cortex-a510",
        .features = featureSet(&[_]Feature{
            .bf16,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const cortex_a520: CpuModel = .{
        .name = "cortex_a520",
        .llvm_name = "cortex-a520",
        .features = featureSet(&[_]Feature{
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const cortex_a520ae: CpuModel = .{
        .name = "cortex_a520ae",
        .llvm_name = "cortex-a520ae",
        .features = featureSet(&[_]Feature{
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const cortex_a53: CpuModel = .{
        .name = "cortex_a53",
        .llvm_name = "cortex-a53",
        .features = featureSet(&[_]Feature{
            .aes,
            .balance_fp_ops,
            .crc,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .sha2,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const cortex_a55: CpuModel = .{
        .name = "cortex_a55",
        .llvm_name = "cortex-a55",
        .features = featureSet(&[_]Feature{
            .aes,
            .dotprod,
            .fullfp16,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .rcpc,
            .sha2,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const cortex_a57: CpuModel = .{
        .name = "cortex_a57",
        .llvm_name = "cortex-a57",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .balance_fp_ops,
            .crc,
            .enable_select_opt,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_literals,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const cortex_a65: CpuModel = .{
        .name = "cortex_a65",
        .llvm_name = "cortex-a65",
        .features = featureSet(&[_]Feature{
            .aes,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_literals,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .ssbs,
            .v8_2a,
        }),
    };
    pub const cortex_a65ae: CpuModel = .{
        .name = "cortex_a65ae",
        .llvm_name = "cortex-a65ae",
        .features = featureSet(&[_]Feature{
            .aes,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_literals,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .ssbs,
            .v8_2a,
        }),
    };
    pub const cortex_a710: CpuModel = .{
        .name = "cortex_a710",
        .llvm_name = "cortex-a710",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .bf16,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const cortex_a715: CpuModel = .{
        .name = "cortex_a715",
        .llvm_name = "cortex-a715",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .bf16,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .spe,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const cortex_a72: CpuModel = .{
        .name = "cortex_a72",
        .llvm_name = "cortex-a72",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .crc,
            .enable_select_opt,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_literals,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .v8a,
        }),
    };
    pub const cortex_a720: CpuModel = .{
        .name = "cortex_a720",
        .llvm_name = "cortex-a720",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .spe,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const cortex_a720ae: CpuModel = .{
        .name = "cortex_a720ae",
        .llvm_name = "cortex-a720ae",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .spe,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const cortex_a725: CpuModel = .{
        .name = "cortex_a725",
        .llvm_name = "cortex-a725",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .spe,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const cortex_a73: CpuModel = .{
        .name = "cortex_a73",
        .llvm_name = "cortex-a73",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .crc,
            .enable_select_opt,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .v8a,
        }),
    };
    pub const cortex_a75: CpuModel = .{
        .name = "cortex_a75",
        .llvm_name = "cortex-a75",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .v8_2a,
        }),
    };
    pub const cortex_a76: CpuModel = .{
        .name = "cortex_a76",
        .llvm_name = "cortex-a76",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .ssbs,
            .v8_2a,
        }),
    };
    pub const cortex_a76ae: CpuModel = .{
        .name = "cortex_a76ae",
        .llvm_name = "cortex-a76ae",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .ssbs,
            .v8_2a,
        }),
    };
    pub const cortex_a77: CpuModel = .{
        .name = "cortex_a77",
        .llvm_name = "cortex-a77",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .ssbs,
            .v8_2a,
        }),
    };
    pub const cortex_a78: CpuModel = .{
        .name = "cortex_a78",
        .llvm_name = "cortex-a78",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .spe,
            .ssbs,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const cortex_a78ae: CpuModel = .{
        .name = "cortex_a78ae",
        .llvm_name = "cortex-a78ae",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .spe,
            .ssbs,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const cortex_a78c: CpuModel = .{
        .name = "cortex_a78c",
        .llvm_name = "cortex-a78c",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .dotprod,
            .enable_select_opt,
            .flagm,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .pauth,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .spe,
            .ssbs,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const cortex_r82: CpuModel = .{
        .name = "cortex_r82",
        .llvm_name = "cortex-r82",
        .features = featureSet(&[_]Feature{
            .ccdp,
            .perfmon,
            .predres,
            .use_postra_scheduler,
            .v8r,
        }),
    };
    pub const cortex_r82ae: CpuModel = .{
        .name = "cortex_r82ae",
        .llvm_name = "cortex-r82ae",
        .features = featureSet(&[_]Feature{
            .ccdp,
            .perfmon,
            .predres,
            .use_postra_scheduler,
            .v8r,
        }),
    };
    pub const cortex_x1: CpuModel = .{
        .name = "cortex_x1",
        .llvm_name = "cortex-x1",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .spe,
            .ssbs,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const cortex_x1c: CpuModel = .{
        .name = "cortex_x1c",
        .llvm_name = "cortex-x1c",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .cmp_bcc_fusion,
            .dotprod,
            .enable_select_opt,
            .flagm,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .lse2,
            .pauth,
            .perfmon,
            .predictable_select_expensive,
            .rcpc_immo,
            .sha2,
            .spe,
            .ssbs,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const cortex_x2: CpuModel = .{
        .name = "cortex_x2",
        .llvm_name = "cortex-x2",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .bf16,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .sve_bitperm,
            .use_fixed_over_scalable_if_equal_cost,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const cortex_x3: CpuModel = .{
        .name = "cortex_x3",
        .llvm_name = "cortex-x3",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .avoid_ldapur,
            .bf16,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .spe,
            .sve_bitperm,
            .use_fixed_over_scalable_if_equal_cost,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const cortex_x4: CpuModel = .{
        .name = "cortex_x4",
        .llvm_name = "cortex-x4",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .avoid_ldapur,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .spe,
            .sve_bitperm,
            .use_fixed_over_scalable_if_equal_cost,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const cortex_x925: CpuModel = .{
        .name = "cortex_x925",
        .llvm_name = "cortex-x925",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .avoid_ldapur,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .spe,
            .sve_bitperm,
            .use_fixed_over_scalable_if_equal_cost,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const cyclone: CpuModel = .{
        .name = "cyclone",
        .llvm_name = "cyclone",
        .features = featureSet(&[_]Feature{
            .aes,
            .alternate_sextload_cvt_f32_pattern,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .disable_latency_sched_heuristic,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .v8a,
            .zcm,
            .zcz,
            .zcz_fp_workaround,
        }),
    };
    pub const emag: CpuModel = .{
        .name = "emag",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .crc,
            .crypto,
            .perfmon,
            .v8a,
        }),
    };
    pub const exynos_m1: CpuModel = .{
        .name = "exynos_m1",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .crc,
            .crypto,
            .exynos_cheap_as_move,
            .force_32bit_jump_tables,
            .fuse_aes,
            .perfmon,
            .slow_misaligned_128store,
            .slow_paired_128,
            .use_postra_scheduler,
            .use_reciprocal_square_root,
            .v8a,
        }),
    };
    pub const exynos_m2: CpuModel = .{
        .name = "exynos_m2",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .crc,
            .crypto,
            .exynos_cheap_as_move,
            .force_32bit_jump_tables,
            .fuse_aes,
            .perfmon,
            .slow_misaligned_128store,
            .slow_paired_128,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const exynos_m3: CpuModel = .{
        .name = "exynos_m3",
        .llvm_name = "exynos-m3",
        .features = featureSet(&[_]Feature{
            .aes,
            .alu_lsl_fast,
            .crc,
            .exynos_cheap_as_move,
            .force_32bit_jump_tables,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const exynos_m4: CpuModel = .{
        .name = "exynos_m4",
        .llvm_name = "exynos-m4",
        .features = featureSet(&[_]Feature{
            .aes,
            .alu_lsl_fast,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .dotprod,
            .exynos_cheap_as_move,
            .force_32bit_jump_tables,
            .fullfp16,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8_2a,
            .zcz,
        }),
    };
    pub const exynos_m5: CpuModel = .{
        .name = "exynos_m5",
        .llvm_name = "exynos-m5",
        .features = featureSet(&[_]Feature{
            .aes,
            .alu_lsl_fast,
            .arith_bcc_fusion,
            .arith_cbz_fusion,
            .dotprod,
            .exynos_cheap_as_move,
            .force_32bit_jump_tables,
            .fullfp16,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_arith_logic,
            .fuse_csel,
            .fuse_literals,
            .perfmon,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8_2a,
            .zcz,
        }),
    };
    pub const falkor: CpuModel = .{
        .name = "falkor",
        .llvm_name = "falkor",
        .features = featureSet(&[_]Feature{
            .aes,
            .alu_lsl_fast,
            .crc,
            .perfmon,
            .predictable_select_expensive,
            .rdm,
            .sha2,
            .slow_strqro_store,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8a,
            .zcz,
        }),
    };
    pub const fujitsu_monaka: CpuModel = .{
        .name = "fujitsu_monaka",
        .llvm_name = "fujitsu-monaka",
        .features = featureSet(&[_]Feature{
            .clrbhb,
            .ete,
            .faminmax,
            .fp16fml,
            .fp8dot2,
            .fpac,
            .fujitsu_monaka,
            .ls64,
            .lut,
            .perfmon,
            .rand,
            .specres2,
            .sve2_sha3,
            .sve2_sm4,
            .sve_aes,
            .sve_bitperm,
            .v9_3a,
        }),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .enable_select_opt,
            .ete,
            .fuse_adrp_add,
            .fuse_aes,
            .neon,
            .use_postra_scheduler,
        }),
    };
    pub const grace: CpuModel = .{
        .name = "grace",
        .llvm_name = "grace",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .avoid_ldapur,
            .bf16,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .spe,
            .sve_bitperm,
            .use_fixed_over_scalable_if_equal_cost,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const kryo: CpuModel = .{
        .name = "kryo",
        .llvm_name = "kryo",
        .features = featureSet(&[_]Feature{
            .aes,
            .alu_lsl_fast,
            .crc,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8a,
            .zcz,
        }),
    };
    pub const neoverse_512tvb: CpuModel = .{
        .name = "neoverse_512tvb",
        .llvm_name = "neoverse-512tvb",
        .features = featureSet(&[_]Feature{
            .aes,
            .alu_lsl_fast,
            .bf16,
            .ccdp,
            .enable_select_opt,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .sha3,
            .sm4,
            .spe,
            .ssbs,
            .sve,
            .use_postra_scheduler,
            .v8_4a,
        }),
    };
    pub const neoverse_e1: CpuModel = .{
        .name = "neoverse_e1",
        .llvm_name = "neoverse-e1",
        .features = featureSet(&[_]Feature{
            .aes,
            .dotprod,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .rcpc,
            .sha2,
            .ssbs,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const neoverse_n1: CpuModel = .{
        .name = "neoverse_n1",
        .llvm_name = "neoverse-n1",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .dotprod,
            .enable_select_opt,
            .fullfp16,
            .fuse_adrp_add,
            .fuse_aes,
            .perfmon,
            .predictable_select_expensive,
            .rcpc,
            .sha2,
            .spe,
            .ssbs,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const neoverse_n2: CpuModel = .{
        .name = "neoverse_n2",
        .llvm_name = "neoverse-n2",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .bf16,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const neoverse_n3: CpuModel = .{
        .name = "neoverse_n3",
        .llvm_name = "neoverse-n3",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .spe,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const neoverse_v1: CpuModel = .{
        .name = "neoverse_v1",
        .llvm_name = "neoverse-v1",
        .features = featureSet(&[_]Feature{
            .addr_lsl_slow_14,
            .aes,
            .alu_lsl_fast,
            .bf16,
            .ccdp,
            .enable_select_opt,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .no_sve_fp_ld1r,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .sha3,
            .sm4,
            .spe,
            .ssbs,
            .sve,
            .use_postra_scheduler,
            .v8_4a,
        }),
    };
    pub const neoverse_v2: CpuModel = .{
        .name = "neoverse_v2",
        .llvm_name = "neoverse-v2",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .avoid_ldapur,
            .bf16,
            .cmp_bcc_fusion,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .i8mm,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .spe,
            .sve_bitperm,
            .use_fixed_over_scalable_if_equal_cost,
            .use_postra_scheduler,
            .v9a,
        }),
    };
    pub const neoverse_v3: CpuModel = .{
        .name = "neoverse_v3",
        .llvm_name = "neoverse-v3",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .avoid_ldapur,
            .brbe,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .ls64,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .spe,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const neoverse_v3ae: CpuModel = .{
        .name = "neoverse_v3ae",
        .llvm_name = "neoverse-v3ae",
        .features = featureSet(&[_]Feature{
            .alu_lsl_fast,
            .avoid_ldapur,
            .brbe,
            .enable_select_opt,
            .ete,
            .fp16fml,
            .fuse_adrp_add,
            .fuse_aes,
            .ls64,
            .mte,
            .perfmon,
            .predictable_select_expensive,
            .rand,
            .spe,
            .sve_bitperm,
            .use_postra_scheduler,
            .v9_2a,
        }),
    };
    pub const oryon_1: CpuModel = .{
        .name = "oryon_1",
        .llvm_name = "oryon-1",
        .features = featureSet(&[_]Feature{
            .aes,
            .enable_select_opt,
            .fp16fml,
            .fuse_address,
            .fuse_adrp_add,
            .fuse_aes,
            .fuse_crypto_eor,
            .perfmon,
            .rand,
            .sha3,
            .sm4,
            .spe,
            .use_postra_scheduler,
            .v8_6a,
        }),
    };
    pub const saphira: CpuModel = .{
        .name = "saphira",
        .llvm_name = "saphira",
        .features = featureSet(&[_]Feature{
            .aes,
            .alu_lsl_fast,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .spe,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8_4a,
            .zcz,
        }),
    };
    pub const thunderx: CpuModel = .{
        .name = "thunderx",
        .llvm_name = "thunderx",
        .features = featureSet(&[_]Feature{
            .aes,
            .crc,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const thunderx2t99: CpuModel = .{
        .name = "thunderx2t99",
        .llvm_name = "thunderx2t99",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .arith_bcc_fusion,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8_1a,
        }),
    };
    pub const thunderx3t110: CpuModel = .{
        .name = "thunderx3t110",
        .llvm_name = "thunderx3t110",
        .features = featureSet(&[_]Feature{
            .aes,
            .aggressive_fma,
            .arith_bcc_fusion,
            .balance_fp_ops,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .strict_align,
            .use_postra_scheduler,
            .v8_3a,
        }),
    };
    pub const thunderxt81: CpuModel = .{
        .name = "thunderxt81",
        .llvm_name = "thunderxt81",
        .features = featureSet(&[_]Feature{
            .aes,
            .crc,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const thunderxt83: CpuModel = .{
        .name = "thunderxt83",
        .llvm_name = "thunderxt83",
        .features = featureSet(&[_]Feature{
            .aes,
            .crc,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const thunderxt88: CpuModel = .{
        .name = "thunderxt88",
        .llvm_name = "thunderxt88",
        .features = featureSet(&[_]Feature{
            .aes,
            .crc,
            .perfmon,
            .predictable_select_expensive,
            .sha2,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8a,
        }),
    };
    pub const tsv110: CpuModel = .{
        .name = "tsv110",
        .llvm_name = "tsv110",
        .features = featureSet(&[_]Feature{
            .aes,
            .complxnum,
            .dotprod,
            .fp16fml,
            .fuse_aes,
            .jsconv,
            .perfmon,
            .sha2,
            .spe,
            .store_pair_suppress,
            .use_postra_scheduler,
            .v8_2a,
        }),
    };
    pub const xgene1: CpuModel = .{
        .name = "xgene1",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .perfmon,
            .v8a,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    @"16_bit_insts",
    a16,
    add_no_carry_insts,
    addressablelocalmemorysize163840,
    addressablelocalmemorysize32768,
    addressablelocalmemorysize65536,
    agent_scope_fine_grained_remote_memory_atomics,
    allocate1_5xvgprs,
    aperture_regs,
    architected_flat_scratch,
    architected_sgprs,
    ashr_pk_insts,
    atomic_buffer_global_pk_add_f16_insts,
    atomic_buffer_global_pk_add_f16_no_rtn_insts,
    atomic_buffer_pk_add_bf16_inst,
    atomic_csub_no_rtn_insts,
    atomic_ds_pk_add_16_insts,
    atomic_fadd_no_rtn_insts,
    atomic_fadd_rtn_insts,
    atomic_flat_pk_add_16_insts,
    atomic_fmin_fmax_flat_f32,
    atomic_fmin_fmax_flat_f64,
    atomic_fmin_fmax_global_f32,
    atomic_fmin_fmax_global_f64,
    atomic_global_pk_add_bf16_inst,
    auto_waitcnt_before_barrier,
    back_off_barrier,
    bf16_cvt_insts,
    bf8_cvt_scale_insts,
    bitop3_insts,
    ci_insts,
    cumode,
    cvt_fp8_vop1_bug,
    cvt_pk_f16_f32_inst,
    default_component_broadcast,
    default_component_zero,
    dl_insts,
    dot10_insts,
    dot11_insts,
    dot12_insts,
    dot13_insts,
    dot1_insts,
    dot2_insts,
    dot3_insts,
    dot4_insts,
    dot5_insts,
    dot6_insts,
    dot7_insts,
    dot8_insts,
    dot9_insts,
    dpp,
    dpp8,
    dpp_64bit,
    dpp_src1_sgpr,
    ds128,
    ds_src2_insts,
    extended_image_insts,
    f16bf16_to_fp6bf6_cvt_scale_insts,
    f32_to_f16bf16_cvt_sr_insts,
    fast_denormal_f32,
    fast_fmaf,
    flat_address_space,
    flat_atomic_fadd_f32_inst,
    flat_buffer_global_fadd_f64_inst,
    flat_for_global,
    flat_global_insts,
    flat_inst_offsets,
    flat_scratch,
    flat_scratch_insts,
    flat_segment_offset_bug,
    fma_mix_insts,
    fmacf64_inst,
    fmaf,
    force_store_sc0_sc1,
    fp4_cvt_scale_insts,
    fp64,
    fp6bf6_cvt_scale_insts,
    fp8_conversion_insts,
    fp8_cvt_scale_insts,
    fp8_insts,
    full_rate_64_ops,
    g16,
    gcn3_encoding,
    gds,
    get_wave_id_inst,
    gfx10,
    gfx10_3_insts,
    gfx10_a_encoding,
    gfx10_b_encoding,
    gfx10_insts,
    gfx11,
    gfx11_insts,
    gfx12,
    gfx12_insts,
    gfx7_gfx8_gfx9_insts,
    gfx8_insts,
    gfx9,
    gfx90a_insts,
    gfx940_insts,
    gfx950_insts,
    gfx9_insts,
    gws,
    half_rate_64_ops,
    image_gather4_d16_bug,
    image_insts,
    image_store_d16_bug,
    inst_fwd_prefetch_bug,
    int_clamp_insts,
    inv_2pi_inline_imm,
    kernarg_preload,
    lds_branch_vmem_war_hazard,
    lds_misaligned_bug,
    ldsbankcount16,
    ldsbankcount32,
    load_store_opt,
    mad_intra_fwd_bug,
    mad_mac_f32_insts,
    mad_mix_insts,
    mai_insts,
    max_hard_clause_length_32,
    max_hard_clause_length_63,
    max_private_element_size_16,
    max_private_element_size_4,
    max_private_element_size_8,
    memory_atomic_fadd_f32_denormal_support,
    mfma_inline_literal_bug,
    mimg_r128,
    minimum3_maximum3_f16,
    minimum3_maximum3_f32,
    minimum3_maximum3_pkf16,
    movrel,
    msaa_load_dst_sel_bug,
    negative_scratch_offset_bug,
    negative_unaligned_scratch_offset_bug,
    no_data_dep_hazard,
    no_sdst_cmpx,
    nsa_clause_bug,
    nsa_encoding,
    nsa_to_vmem_bug,
    offset_3f_bug,
    packed_fp32_ops,
    packed_tid,
    partial_nsa_encoding,
    permlane16_swap,
    permlane32_swap,
    pk_fmac_f16_inst,
    precise_memory,
    priv_enabled_trap2_nop_bug,
    prng_inst,
    promote_alloca,
    prt_strict_null,
    pseudo_scalar_trans,
    r128_a16,
    real_true16,
    required_export_priority,
    requires_cov6,
    restricted_soffset,
    s_memrealtime,
    s_memtime_inst,
    salu_float,
    scalar_atomics,
    scalar_dwordx3_loads,
    scalar_flat_scratch_insts,
    scalar_stores,
    sdwa,
    sdwa_mav,
    sdwa_omod,
    sdwa_out_mods_vopc,
    sdwa_scalar,
    sdwa_sdst,
    sea_islands,
    sgpr_init_bug,
    shader_cycles_hi_lo_registers,
    shader_cycles_register,
    si_scheduler,
    smem_to_vector_write_hazard,
    southern_islands,
    sramecc,
    sramecc_support,
    tgsplit,
    trap_handler,
    trig_reduced_range,
    true16,
    unaligned_access_mode,
    unaligned_buffer_access,
    unaligned_ds_access,
    unaligned_scratch_access,
    unpacked_d16_vmem,
    unsafe_ds_offset_folding,
    user_sgpr_init16_bug,
    valu_trans_use_hazard,
    vcmpx_exec_war_hazard,
    vcmpx_permlane_hazard,
    vgpr_index_mode,
    vmem_to_scalar_write_hazard,
    vmem_write_vgpr_in_order,
    volcanic_islands,
    vop3_literal,
    vop3p,
    vopd,
    vscnt,
    wavefrontsize16,
    wavefrontsize32,
    wavefrontsize64,
    xf32_insts,
    xnack,
    xnack_support,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.@"16_bit_insts")] = .{
        .llvm_name = "16-bit-insts",
        .description = "Has i16/f16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.a16)] = .{
        .llvm_name = "a16",
        .description = "Support A16 for 16-bit coordinates/gradients/lod/clamp/mip image operands",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.add_no_carry_insts)] = .{
        .llvm_name = "add-no-carry-insts",
        .description = "Have VALU add/sub instructions without carry out",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.addressablelocalmemorysize163840)] = .{
        .llvm_name = "addressablelocalmemorysize163840",
        .description = "The size of local memory in bytes",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.addressablelocalmemorysize32768)] = .{
        .llvm_name = "addressablelocalmemorysize32768",
        .description = "The size of local memory in bytes",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.addressablelocalmemorysize65536)] = .{
        .llvm_name = "addressablelocalmemorysize65536",
        .description = "The size of local memory in bytes",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.agent_scope_fine_grained_remote_memory_atomics)] = .{
        .llvm_name = "agent-scope-fine-grained-remote-memory-atomics",
        .description = "Agent (device) scoped atomic operations, excluding those directly supported by PCIe (i.e. integer atomic add, exchange, and compare-and-swap), are functional for allocations in host or peer device memory.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.allocate1_5xvgprs)] = .{
        .llvm_name = "allocate1_5xvgprs",
        .description = "Has 50% more physical VGPRs and 50% larger allocation granule",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aperture_regs)] = .{
        .llvm_name = "aperture-regs",
        .description = "Has Memory Aperture Base and Size Registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.architected_flat_scratch)] = .{
        .llvm_name = "architected-flat-scratch",
        .description = "Flat Scratch register is a readonly SPI initialized architected register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.architected_sgprs)] = .{
        .llvm_name = "architected-sgprs",
        .description = "Enable the architected SGPRs",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ashr_pk_insts)] = .{
        .llvm_name = "ashr-pk-insts",
        .description = "Has Arithmetic Shift Pack instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_buffer_global_pk_add_f16_insts)] = .{
        .llvm_name = "atomic-buffer-global-pk-add-f16-insts",
        .description = "Has buffer_atomic_pk_add_f16 and global_atomic_pk_add_f16 instructions that can return original value",
        .dependencies = featureSet(&[_]Feature{
            .flat_global_insts,
        }),
    };
    result[@intFromEnum(Feature.atomic_buffer_global_pk_add_f16_no_rtn_insts)] = .{
        .llvm_name = "atomic-buffer-global-pk-add-f16-no-rtn-insts",
        .description = "Has buffer_atomic_pk_add_f16 and global_atomic_pk_add_f16 instructions that don't return original value",
        .dependencies = featureSet(&[_]Feature{
            .flat_global_insts,
        }),
    };
    result[@intFromEnum(Feature.atomic_buffer_pk_add_bf16_inst)] = .{
        .llvm_name = "atomic-buffer-pk-add-bf16-inst",
        .description = "Has buffer_atomic_pk_add_bf16 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_csub_no_rtn_insts)] = .{
        .llvm_name = "atomic-csub-no-rtn-insts",
        .description = "Has buffer_atomic_csub and global_atomic_csub instructions that don't return original value",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_ds_pk_add_16_insts)] = .{
        .llvm_name = "atomic-ds-pk-add-16-insts",
        .description = "Has ds_pk_add_bf16, ds_pk_add_f16, ds_pk_add_rtn_bf16, ds_pk_add_rtn_f16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_fadd_no_rtn_insts)] = .{
        .llvm_name = "atomic-fadd-no-rtn-insts",
        .description = "Has buffer_atomic_add_f32 and global_atomic_add_f32 instructions that don't return original value",
        .dependencies = featureSet(&[_]Feature{
            .flat_global_insts,
        }),
    };
    result[@intFromEnum(Feature.atomic_fadd_rtn_insts)] = .{
        .llvm_name = "atomic-fadd-rtn-insts",
        .description = "Has buffer_atomic_add_f32 and global_atomic_add_f32 instructions that return original value",
        .dependencies = featureSet(&[_]Feature{
            .flat_global_insts,
        }),
    };
    result[@intFromEnum(Feature.atomic_flat_pk_add_16_insts)] = .{
        .llvm_name = "atomic-flat-pk-add-16-insts",
        .description = "Has flat_atomic_pk_add_f16 and flat_atomic_pk_add_bf16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_fmin_fmax_flat_f32)] = .{
        .llvm_name = "atomic-fmin-fmax-flat-f32",
        .description = "Has flat memory instructions for atomicrmw fmin/fmax for float",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_fmin_fmax_flat_f64)] = .{
        .llvm_name = "atomic-fmin-fmax-flat-f64",
        .description = "Has flat memory instructions for atomicrmw fmin/fmax for double",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_fmin_fmax_global_f32)] = .{
        .llvm_name = "atomic-fmin-fmax-global-f32",
        .description = "Has global/buffer instructions for atomicrmw fmin/fmax for float",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_fmin_fmax_global_f64)] = .{
        .llvm_name = "atomic-fmin-fmax-global-f64",
        .description = "Has global/buffer instructions for atomicrmw fmin/fmax for float",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.atomic_global_pk_add_bf16_inst)] = .{
        .llvm_name = "atomic-global-pk-add-bf16-inst",
        .description = "Has global_atomic_pk_add_bf16 instruction",
        .dependencies = featureSet(&[_]Feature{
            .flat_global_insts,
        }),
    };
    result[@intFromEnum(Feature.auto_waitcnt_before_barrier)] = .{
        .llvm_name = "auto-waitcnt-before-barrier",
        .description = "Hardware automatically inserts waitcnt before barrier",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.back_off_barrier)] = .{
        .llvm_name = "back-off-barrier",
        .description = "Hardware supports backing off s_barrier if an exception occurs",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bf16_cvt_insts)] = .{
        .llvm_name = "bf16-cvt-insts",
        .description = "Has bf16 conversion instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bf8_cvt_scale_insts)] = .{
        .llvm_name = "bf8-cvt-scale-insts",
        .description = "Has bf8 conversion scale instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bitop3_insts)] = .{
        .llvm_name = "bitop3-insts",
        .description = "Has v_bitop3_b32/v_bitop3_b16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ci_insts)] = .{
        .llvm_name = "ci-insts",
        .description = "Additional instructions for CI+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cumode)] = .{
        .llvm_name = "cumode",
        .description = "Enable CU wavefront execution mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cvt_fp8_vop1_bug)] = .{
        .llvm_name = "cvt-fp8-vop1-bug",
        .description = "FP8/BF8 VOP1 form of conversion to F32 is unreliable",
        .dependencies = featureSet(&[_]Feature{
            .fp8_conversion_insts,
        }),
    };
    result[@intFromEnum(Feature.cvt_pk_f16_f32_inst)] = .{
        .llvm_name = "cvt-pk-f16-f32-inst",
        .description = "Has cvt_pk_f16_f32 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.default_component_broadcast)] = .{
        .llvm_name = "default-component-broadcast",
        .description = "BUFFER/IMAGE store instructions set unspecified components to x component (GFX12)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.default_component_zero)] = .{
        .llvm_name = "default-component-zero",
        .description = "BUFFER/IMAGE store instructions set unspecified components to zero (before GFX12)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dl_insts)] = .{
        .llvm_name = "dl-insts",
        .description = "Has v_fmac_f32 and v_xnor_b32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot10_insts)] = .{
        .llvm_name = "dot10-insts",
        .description = "Has v_dot2_f32_f16 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot11_insts)] = .{
        .llvm_name = "dot11-insts",
        .description = "Has v_dot4_f32_fp8_fp8, v_dot4_f32_fp8_bf8, v_dot4_f32_bf8_fp8, v_dot4_f32_bf8_bf8 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot12_insts)] = .{
        .llvm_name = "dot12-insts",
        .description = "Has v_dot2_f32_bf16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot13_insts)] = .{
        .llvm_name = "dot13-insts",
        .description = "Has v_dot2c_f32_bf16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot1_insts)] = .{
        .llvm_name = "dot1-insts",
        .description = "Has v_dot4_i32_i8 and v_dot8_i32_i4 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot2_insts)] = .{
        .llvm_name = "dot2-insts",
        .description = "Has v_dot2_i32_i16, v_dot2_u32_u16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot3_insts)] = .{
        .llvm_name = "dot3-insts",
        .description = "Has v_dot8c_i32_i4 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot4_insts)] = .{
        .llvm_name = "dot4-insts",
        .description = "Has v_dot2c_i32_i16 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot5_insts)] = .{
        .llvm_name = "dot5-insts",
        .description = "Has v_dot2c_f32_f16 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot6_insts)] = .{
        .llvm_name = "dot6-insts",
        .description = "Has v_dot4c_i32_i8 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot7_insts)] = .{
        .llvm_name = "dot7-insts",
        .description = "Has v_dot4_u32_u8, v_dot8_u32_u4 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot8_insts)] = .{
        .llvm_name = "dot8-insts",
        .description = "Has v_dot4_i32_iu8, v_dot8_i32_iu4 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dot9_insts)] = .{
        .llvm_name = "dot9-insts",
        .description = "Has v_dot2_f16_f16, v_dot2_bf16_bf16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dpp)] = .{
        .llvm_name = "dpp",
        .description = "Support DPP (Data Parallel Primitives) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dpp8)] = .{
        .llvm_name = "dpp8",
        .description = "Support DPP8 (Data Parallel Primitives) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dpp_64bit)] = .{
        .llvm_name = "dpp-64bit",
        .description = "Support DPP (Data Parallel Primitives) extension in DP ALU",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dpp_src1_sgpr)] = .{
        .llvm_name = "dpp-src1-sgpr",
        .description = "Support SGPR for Src1 of DPP instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ds128)] = .{
        .llvm_name = "enable-ds128",
        .description = "Use ds_{read|write}_b128",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ds_src2_insts)] = .{
        .llvm_name = "ds-src2-insts",
        .description = "Has ds_*_src2 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.extended_image_insts)] = .{
        .llvm_name = "extended-image-insts",
        .description = "Support mips != 0, lod != 0, gather4, and get_lod",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.f16bf16_to_fp6bf6_cvt_scale_insts)] = .{
        .llvm_name = "f16bf16-to-fp6bf6-cvt-scale-insts",
        .description = "Has f16bf16 to fp6bf6 conversion scale instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.f32_to_f16bf16_cvt_sr_insts)] = .{
        .llvm_name = "f32-to-f16bf16-cvt-sr-insts",
        .description = "Has f32 to f16bf16 conversion scale instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fast_denormal_f32)] = .{
        .llvm_name = "fast-denormal-f32",
        .description = "Enabling denormals does not cause f32 instructions to run at f64 rates",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fast_fmaf)] = .{
        .llvm_name = "fast-fmaf",
        .description = "Assuming f32 fma is at least as fast as mul + add",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_address_space)] = .{
        .llvm_name = "flat-address-space",
        .description = "Support flat address space",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_atomic_fadd_f32_inst)] = .{
        .llvm_name = "flat-atomic-fadd-f32-inst",
        .description = "Has flat_atomic_add_f32 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_buffer_global_fadd_f64_inst)] = .{
        .llvm_name = "flat-buffer-global-fadd-f64-inst",
        .description = "Has flat, buffer, and global instructions for f64 atomic fadd",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_for_global)] = .{
        .llvm_name = "flat-for-global",
        .description = "Force to generate flat instruction for global",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_global_insts)] = .{
        .llvm_name = "flat-global-insts",
        .description = "Have global_* flat memory instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_inst_offsets)] = .{
        .llvm_name = "flat-inst-offsets",
        .description = "Flat instructions have immediate offset addressing mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_scratch)] = .{
        .llvm_name = "enable-flat-scratch",
        .description = "Use scratch_* flat memory instructions to access scratch",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_scratch_insts)] = .{
        .llvm_name = "flat-scratch-insts",
        .description = "Have scratch_* flat memory instructions",```
