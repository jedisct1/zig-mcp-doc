```

        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.flat_segment_offset_bug)] = .{
        .llvm_name = "flat-segment-offset-bug",
        .description = "GFX10 bug where inst_offset is ignored when flat instructions access global memory",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fma_mix_insts)] = .{
        .llvm_name = "fma-mix-insts",
        .description = "Has v_fma_mix_f32, v_fma_mixlo_f16, v_fma_mixhi_f16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fmacf64_inst)] = .{
        .llvm_name = "fmacf64-inst",
        .description = "Has v_fmac_f64 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fmaf)] = .{
        .llvm_name = "fmaf",
        .description = "Enable single precision FMA (not as fast as mul+add, but fused)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.force_store_sc0_sc1)] = .{
        .llvm_name = "force-store-sc0-sc1",
        .description = "Has SC0 and SC1 on stores",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp4_cvt_scale_insts)] = .{
        .llvm_name = "fp4-cvt-scale-insts",
        .description = "Has fp4 conversion scale instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp64)] = .{
        .llvm_name = "fp64",
        .description = "Enable double precision operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp6bf6_cvt_scale_insts)] = .{
        .llvm_name = "fp6bf6-cvt-scale-insts",
        .description = "Has fp6 and bf6 conversion scale instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp8_conversion_insts)] = .{
        .llvm_name = "fp8-conversion-insts",
        .description = "Has fp8 and bf8 conversion instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp8_cvt_scale_insts)] = .{
        .llvm_name = "fp8-cvt-scale-insts",
        .description = "Has fp8 conversion scale instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp8_insts)] = .{
        .llvm_name = "fp8-insts",
        .description = "Has fp8 and bf8 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.full_rate_64_ops)] = .{
        .llvm_name = "full-rate-64-ops",
        .description = "Most fp64 instructions are full rate",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.g16)] = .{
        .llvm_name = "g16",
        .description = "Support G16 for 16-bit gradient image operands",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gcn3_encoding)] = .{
        .llvm_name = "gcn3-encoding",
        .description = "Encoding format for VI",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gds)] = .{
        .llvm_name = "gds",
        .description = "Has Global Data Share",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.get_wave_id_inst)] = .{
        .llvm_name = "get-wave-id-inst",
        .description = "Has s_get_waveid_in_workgroup instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx10)] = .{
        .llvm_name = "gfx10",
        .description = "GFX10 GPU generation",
        .dependencies = featureSet(&[_]Feature{
            .@"16_bit_insts",
            .a16,
            .add_no_carry_insts,
            .addressablelocalmemorysize65536,
            .aperture_regs,
            .atomic_fmin_fmax_flat_f32,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f32,
            .atomic_fmin_fmax_global_f64,
            .ci_insts,
            .default_component_zero,
            .dpp,
            .dpp8,
            .extended_image_insts,
            .fast_denormal_f32,
            .fast_fmaf,
            .flat_address_space,
            .flat_global_insts,
            .flat_inst_offsets,
            .flat_scratch_insts,
            .fma_mix_insts,
            .fp64,
            .g16,
            .gds,
            .gfx10_insts,
            .gfx8_insts,
            .gfx9_insts,
            .gws,
            .image_insts,
            .int_clamp_insts,
            .inv_2pi_inline_imm,
            .max_hard_clause_length_63,
            .mimg_r128,
            .movrel,
            .no_data_dep_hazard,
            .no_sdst_cmpx,
            .pk_fmac_f16_inst,
            .s_memrealtime,
            .s_memtime_inst,
            .sdwa,
            .sdwa_omod,
            .sdwa_scalar,
            .sdwa_sdst,
            .unaligned_buffer_access,
            .unaligned_ds_access,
            .unaligned_scratch_access,
            .vmem_write_vgpr_in_order,
            .vop3_literal,
            .vop3p,
            .vscnt,
        }),
    };
    result[@intFromEnum(Feature.gfx10_3_insts)] = .{
        .llvm_name = "gfx10-3-insts",
        .description = "Additional instructions for GFX10.3",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx10_a_encoding)] = .{
        .llvm_name = "gfx10_a-encoding",
        .description = "Has BVH ray tracing instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx10_b_encoding)] = .{
        .llvm_name = "gfx10_b-encoding",
        .description = "Encoding format GFX10_B",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx10_insts)] = .{
        .llvm_name = "gfx10-insts",
        .description = "Additional instructions for GFX10+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx11)] = .{
        .llvm_name = "gfx11",
        .description = "GFX11 GPU generation",
        .dependencies = featureSet(&[_]Feature{
            .@"16_bit_insts",
            .a16,
            .add_no_carry_insts,
            .addressablelocalmemorysize65536,
            .aperture_regs,
            .atomic_fmin_fmax_flat_f32,
            .atomic_fmin_fmax_global_f32,
            .ci_insts,
            .default_component_zero,
            .dpp,
            .dpp8,
            .extended_image_insts,
            .fast_denormal_f32,
            .fast_fmaf,
            .flat_address_space,
            .flat_global_insts,
            .flat_inst_offsets,
            .flat_scratch_insts,
            .fma_mix_insts,
            .fp64,
            .g16,
            .gds,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .gfx10_insts,
            .gfx11_insts,
            .gfx8_insts,
            .gfx9_insts,
            .gws,
            .int_clamp_insts,
            .inv_2pi_inline_imm,
            .max_hard_clause_length_32,
            .mimg_r128,
            .movrel,
            .no_data_dep_hazard,
            .no_sdst_cmpx,
            .pk_fmac_f16_inst,
            .true16,
            .unaligned_buffer_access,
            .unaligned_ds_access,
            .unaligned_scratch_access,
            .vmem_write_vgpr_in_order,
            .vop3_literal,
            .vop3p,
            .vopd,
            .vscnt,
        }),
    };
    result[@intFromEnum(Feature.gfx11_insts)] = .{
        .llvm_name = "gfx11-insts",
        .description = "Additional instructions for GFX11+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx12)] = .{
        .llvm_name = "gfx12",
        .description = "GFX12 GPU generation",
        .dependencies = featureSet(&[_]Feature{
            .@"16_bit_insts",
            .a16,
            .add_no_carry_insts,
            .addressablelocalmemorysize65536,
            .agent_scope_fine_grained_remote_memory_atomics,
            .aperture_regs,
            .atomic_fmin_fmax_flat_f32,
            .atomic_fmin_fmax_global_f32,
            .ci_insts,
            .default_component_broadcast,
            .dpp,
            .dpp8,
            .fast_denormal_f32,
            .fast_fmaf,
            .flat_address_space,
            .flat_global_insts,
            .flat_inst_offsets,
            .flat_scratch_insts,
            .fma_mix_insts,
            .fp64,
            .g16,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .gfx10_insts,
            .gfx11_insts,
            .gfx12_insts,
            .gfx8_insts,
            .gfx9_insts,
            .int_clamp_insts,
            .inv_2pi_inline_imm,
            .max_hard_clause_length_32,
            .mimg_r128,
            .minimum3_maximum3_f16,
            .minimum3_maximum3_f32,
            .movrel,
            .no_data_dep_hazard,
            .no_sdst_cmpx,
            .pk_fmac_f16_inst,
            .true16,
            .unaligned_buffer_access,
            .unaligned_ds_access,
            .unaligned_scratch_access,
            .vop3_literal,
            .vop3p,
            .vopd,
            .vscnt,
        }),
    };
    result[@intFromEnum(Feature.gfx12_insts)] = .{
        .llvm_name = "gfx12-insts",
        .description = "Additional instructions for GFX12+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx7_gfx8_gfx9_insts)] = .{
        .llvm_name = "gfx7-gfx8-gfx9-insts",
        .description = "Instructions shared in GFX7, GFX8, GFX9",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx8_insts)] = .{
        .llvm_name = "gfx8-insts",
        .description = "Additional instructions for GFX8+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx9)] = .{
        .llvm_name = "gfx9",
        .description = "GFX9 GPU generation",
        .dependencies = featureSet(&[_]Feature{
            .@"16_bit_insts",
            .a16,
            .add_no_carry_insts,
            .aperture_regs,
            .ci_insts,
            .default_component_zero,
            .dpp,
            .fast_denormal_f32,
            .fast_fmaf,
            .flat_address_space,
            .flat_global_insts,
            .flat_inst_offsets,
            .flat_scratch_insts,
            .fp64,
            .gcn3_encoding,
            .gfx7_gfx8_gfx9_insts,
            .gfx8_insts,
            .gfx9_insts,
            .gws,
            .int_clamp_insts,
            .inv_2pi_inline_imm,
            .negative_scratch_offset_bug,
            .r128_a16,
            .s_memrealtime,
            .s_memtime_inst,
            .scalar_atomics,
            .scalar_flat_scratch_insts,
            .scalar_stores,
            .sdwa,
            .sdwa_omod,
            .sdwa_scalar,
            .sdwa_sdst,
            .unaligned_buffer_access,
            .unaligned_ds_access,
            .unaligned_scratch_access,
            .vgpr_index_mode,
            .vmem_write_vgpr_in_order,
            .vop3p,
            .wavefrontsize64,
            .xnack_support,
        }),
    };
    result[@intFromEnum(Feature.gfx90a_insts)] = .{
        .llvm_name = "gfx90a-insts",
        .description = "Additional instructions for GFX90A+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx940_insts)] = .{
        .llvm_name = "gfx940-insts",
        .description = "Additional instructions for GFX940+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gfx950_insts)] = .{
        .llvm_name = "gfx950-insts",
        .description = "Additional instructions for GFX950+",
        .dependencies = featureSet(&[_]Feature{
            .ashr_pk_insts,
            .bf8_cvt_scale_insts,
            .cvt_pk_f16_f32_inst,
            .f16bf16_to_fp6bf6_cvt_scale_insts,
            .f32_to_f16bf16_cvt_sr_insts,
            .fp4_cvt_scale_insts,
            .fp6bf6_cvt_scale_insts,
            .fp8_cvt_scale_insts,
            .minimum3_maximum3_f32,
            .minimum3_maximum3_pkf16,
            .permlane16_swap,
            .permlane32_swap,
        }),
    };
    result[@intFromEnum(Feature.gfx9_insts)] = .{
        .llvm_name = "gfx9-insts",
        .description = "Additional instructions for GFX9+",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.gws)] = .{
        .llvm_name = "gws",
        .description = "Has Global Wave Sync",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.half_rate_64_ops)] = .{
        .llvm_name = "half-rate-64-ops",
        .description = "Most fp64 instructions are half rate instead of quarter",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.image_gather4_d16_bug)] = .{
        .llvm_name = "image-gather4-d16-bug",
        .description = "Image Gather4 D16 hardware bug",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.image_insts)] = .{
        .llvm_name = "image-insts",
        .description = "Support image instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.image_store_d16_bug)] = .{
        .llvm_name = "image-store-d16-bug",
        .description = "Image Store D16 hardware bug",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.inst_fwd_prefetch_bug)] = .{
        .llvm_name = "inst-fwd-prefetch-bug",
        .description = "S_INST_PREFETCH instruction causes shader to hang",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.int_clamp_insts)] = .{
        .llvm_name = "int-clamp-insts",
        .description = "Support clamp for integer destination",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.inv_2pi_inline_imm)] = .{
        .llvm_name = "inv-2pi-inline-imm",
        .description = "Has 1 / (2 * pi) as inline immediate",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.kernarg_preload)] = .{
        .llvm_name = "kernarg-preload",
        .description = "Hardware supports preloading of kernel arguments in user SGPRs.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lds_branch_vmem_war_hazard)] = .{
        .llvm_name = "lds-branch-vmem-war-hazard",
        .description = "Switching between LDS and VMEM-tex not waiting VM_VSRC=0",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.lds_misaligned_bug)] = .{
        .llvm_name = "lds-misaligned-bug",
        .description = "Some GFX10 bug with multi-dword LDS and flat access that is not naturally aligned in WGP mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ldsbankcount16)] = .{
        .llvm_name = "ldsbankcount16",
        .description = "The number of LDS banks per compute unit.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ldsbankcount32)] = .{
        .llvm_name = "ldsbankcount32",
        .description = "The number of LDS banks per compute unit.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.load_store_opt)] = .{
        .llvm_name = "load-store-opt",
        .description = "Enable SI load/store optimizer pass",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mad_intra_fwd_bug)] = .{
        .llvm_name = "mad-intra-fwd-bug",
        .description = "MAD_U64/I64 intra instruction forwarding bug",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mad_mac_f32_insts)] = .{
        .llvm_name = "mad-mac-f32-insts",
        .description = "Has v_mad_f32/v_mac_f32/v_madak_f32/v_madmk_f32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mad_mix_insts)] = .{
        .llvm_name = "mad-mix-insts",
        .description = "Has v_mad_mix_f32, v_mad_mixlo_f16, v_mad_mixhi_f16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mai_insts)] = .{
        .llvm_name = "mai-insts",
        .description = "Has mAI instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.max_hard_clause_length_32)] = .{
        .llvm_name = "max-hard-clause-length-32",
        .description = "Maximum number of instructions in an explicit S_CLAUSE is 32",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.max_hard_clause_length_63)] = .{
        .llvm_name = "max-hard-clause-length-63",
        .description = "Maximum number of instructions in an explicit S_CLAUSE is 63",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.max_private_element_size_16)] = .{
        .llvm_name = "max-private-element-size-16",
        .description = "Maximum private access size may be 16",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.max_private_element_size_4)] = .{
        .llvm_name = "max-private-element-size-4",
        .description = "Maximum private access size may be 4",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.max_private_element_size_8)] = .{
        .llvm_name = "max-private-element-size-8",
        .description = "Maximum private access size may be 8",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.memory_atomic_fadd_f32_denormal_support)] = .{
        .llvm_name = "memory-atomic-fadd-f32-denormal-support",
        .description = "global/flat/buffer atomic fadd for float supports denormal handling",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mfma_inline_literal_bug)] = .{
        .llvm_name = "mfma-inline-literal-bug",
        .description = "MFMA cannot use inline literal as SrcC",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.mimg_r128)] = .{
        .llvm_name = "mimg-r128",
        .description = "Support 128-bit texture resources",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.minimum3_maximum3_f16)] = .{
        .llvm_name = "minimum3-maximum3-f16",
        .description = "Has v_minimum3_f16 and v_maximum3_f16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.minimum3_maximum3_f32)] = .{
        .llvm_name = "minimum3-maximum3-f32",
        .description = "Has v_minimum3_f32 and v_maximum3_f32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.minimum3_maximum3_pkf16)] = .{
        .llvm_name = "minimum3-maximum3-pkf16",
        .description = "Has v_pk_minimum3_f16 and v_pk_maximum3_f16 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.movrel)] = .{
        .llvm_name = "movrel",
        .description = "Has v_movrel*_b32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.msaa_load_dst_sel_bug)] = .{
        .llvm_name = "msaa-load-dst-sel-bug",
        .description = "MSAA loads not honoring dst_sel bug",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.negative_scratch_offset_bug)] = .{
        .llvm_name = "negative-scratch-offset-bug",
        .description = "Negative immediate offsets in scratch instructions with an SGPR offset page fault on GFX9",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.negative_unaligned_scratch_offset_bug)] = .{
        .llvm_name = "negative-unaligned-scratch-offset-bug",
        .description = "Scratch instructions with a VGPR offset and a negative immediate offset that is not a multiple of 4 read wrong memory on GFX10",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_data_dep_hazard)] = .{
        .llvm_name = "no-data-dep-hazard",
        .description = "Does not need SW waitstates",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_sdst_cmpx)] = .{
        .llvm_name = "no-sdst-cmpx",
        .description = "V_CMPX does not write VCC/SGPR in addition to EXEC",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nsa_clause_bug)] = .{
        .llvm_name = "nsa-clause-bug",
        .description = "MIMG-NSA in a hard clause has unpredictable results on GFX10.1",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nsa_encoding)] = .{
        .llvm_name = "nsa-encoding",
        .description = "Support NSA encoding for image instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nsa_to_vmem_bug)] = .{
        .llvm_name = "nsa-to-vmem-bug",
        .description = "MIMG-NSA followed by VMEM fail if EXEC_LO or EXEC_HI equals zero",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.offset_3f_bug)] = .{
        .llvm_name = "offset-3f-bug",
        .description = "Branch offset of 3f hardware bug",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.packed_fp32_ops)] = .{
        .llvm_name = "packed-fp32-ops",
        .description = "Support packed fp32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.packed_tid)] = .{
        .llvm_name = "packed-tid",
        .description = "Workitem IDs are packed into v0 at kernel launch",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.partial_nsa_encoding)] = .{
        .llvm_name = "partial-nsa-encoding",
        .description = "Support partial NSA encoding for image instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.permlane16_swap)] = .{
        .llvm_name = "permlane16-swap",
        .description = "Has v_permlane16_swap_b32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.permlane32_swap)] = .{
        .llvm_name = "permlane32-swap",
        .description = "Has v_permlane32_swap_b32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pk_fmac_f16_inst)] = .{
        .llvm_name = "pk-fmac-f16-inst",
        .description = "Has v_pk_fmac_f16 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.precise_memory)] = .{
        .llvm_name = "precise-memory",
        .description = "Enable precise memory mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.priv_enabled_trap2_nop_bug)] = .{
        .llvm_name = "priv-enabled-trap2-nop-bug",
        .description = "Hardware that runs with PRIV=1 interpreting 's_trap 2' as a nop bug",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prng_inst)] = .{
        .llvm_name = "prng-inst",
        .description = "Has v_prng_b32 instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.promote_alloca)] = .{
        .llvm_name = "promote-alloca",
        .description = "Enable promote alloca pass",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.prt_strict_null)] = .{
        .llvm_name = "enable-prt-strict-null",
        .description = "Enable zeroing of result registers for sparse texture fetches",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.pseudo_scalar_trans)] = .{
        .llvm_name = "pseudo-scalar-trans",
        .description = "Has Pseudo Scalar Transcendental instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.r128_a16)] = .{
        .llvm_name = "r128-a16",
        .description = "Support gfx9-style A16 for 16-bit coordinates/gradients/lod/clamp/mip image operands, where a16 is aliased with r128",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.real_true16)] = .{
        .llvm_name = "real-true16",
        .description = "Use true 16-bit registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.required_export_priority)] = .{
        .llvm_name = "required-export-priority",
        .description = "Export priority must be explicitly manipulated on GFX11.5",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.requires_cov6)] = .{
        .llvm_name = "requires-cov6",
        .description = "Target Requires Code Object V6",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.restricted_soffset)] = .{
        .llvm_name = "restricted-soffset",
        .description = "Has restricted SOffset (immediate not supported).",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.s_memrealtime)] = .{
        .llvm_name = "s-memrealtime",
        .description = "Has s_memrealtime instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.s_memtime_inst)] = .{
        .llvm_name = "s-memtime-inst",
        .description = "Has s_memtime instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.salu_float)] = .{
        .llvm_name = "salu-float",
        .description = "Has SALU floating point instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.scalar_atomics)] = .{
        .llvm_name = "scalar-atomics",
        .description = "Has atomic scalar memory instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.scalar_dwordx3_loads)] = .{
        .llvm_name = "scalar-dwordx3-loads",
        .description = "Has 96-bit scalar load instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.scalar_flat_scratch_insts)] = .{
        .llvm_name = "scalar-flat-scratch-insts",
        .description = "Have s_scratch_* flat memory instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.scalar_stores)] = .{
        .llvm_name = "scalar-stores",
        .description = "Has store scalar memory instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sdwa)] = .{
        .llvm_name = "sdwa",
        .description = "Support SDWA (Sub-DWORD Addressing) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sdwa_mav)] = .{
        .llvm_name = "sdwa-mav",
        .description = "Support v_mac_f32/f16 with SDWA (Sub-DWORD Addressing) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sdwa_omod)] = .{
        .llvm_name = "sdwa-omod",
        .description = "Support OMod with SDWA (Sub-DWORD Addressing) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sdwa_out_mods_vopc)] = .{
        .llvm_name = "sdwa-out-mods-vopc",
        .description = "Support clamp for VOPC with SDWA (Sub-DWORD Addressing) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sdwa_scalar)] = .{
        .llvm_name = "sdwa-scalar",
        .description = "Support scalar register with SDWA (Sub-DWORD Addressing) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sdwa_sdst)] = .{
        .llvm_name = "sdwa-sdst",
        .description = "Support scalar dst for VOPC with SDWA (Sub-DWORD Addressing) extension",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sea_islands)] = .{
        .llvm_name = "sea-islands",
        .description = "SEA_ISLANDS GPU generation",
        .dependencies = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .atomic_fmin_fmax_flat_f32,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f32,
            .atomic_fmin_fmax_global_f64,
            .ci_insts,
            .default_component_zero,
            .ds_src2_insts,
            .extended_image_insts,
            .flat_address_space,
            .fp64,
            .gds,
            .gfx7_gfx8_gfx9_insts,
            .gws,
            .image_insts,
            .mad_mac_f32_insts,
            .mimg_r128,
            .movrel,
            .s_memtime_inst,
            .trig_reduced_range,
            .unaligned_buffer_access,
            .vmem_write_vgpr_in_order,
            .wavefrontsize64,
        }),
    };
    result[@intFromEnum(Feature.sgpr_init_bug)] = .{
        .llvm_name = "sgpr-init-bug",
        .description = "VI SGPR initialization bug requiring a fixed SGPR allocation size",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shader_cycles_hi_lo_registers)] = .{
        .llvm_name = "shader-cycles-hi-lo-registers",
        .description = "Has SHADER_CYCLES_HI/LO hardware registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.shader_cycles_register)] = .{
        .llvm_name = "shader-cycles-register",
        .description = "Has SHADER_CYCLES hardware register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.si_scheduler)] = .{
        .llvm_name = "si-scheduler",
        .description = "Enable SI Machine Scheduler",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.smem_to_vector_write_hazard)] = .{
        .llvm_name = "smem-to-vector-write-hazard",
        .description = "s_load_dword followed by v_cmp page faults",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.southern_islands)] = .{
        .llvm_name = "southern-islands",
        .description = "SOUTHERN_ISLANDS GPU generation",
        .dependencies = featureSet(&[_]Feature{
            .addressablelocalmemorysize32768,
            .atomic_fmin_fmax_global_f32,
            .atomic_fmin_fmax_global_f64,
            .default_component_zero,
            .ds_src2_insts,
            .extended_image_insts,
            .fp64,
            .gds,
            .gws,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .mimg_r128,
            .movrel,
            .s_memtime_inst,
            .trig_reduced_range,
            .vmem_write_vgpr_in_order,
            .wavefrontsize64,
        }),
    };
    result[@intFromEnum(Feature.sramecc)] = .{
        .llvm_name = "sramecc",
        .description = "Enable SRAMECC",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.sramecc_support)] = .{
        .llvm_name = "sramecc-support",
        .description = "Hardware supports SRAMECC",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.tgsplit)] = .{
        .llvm_name = "tgsplit",
        .description = "Enable threadgroup split execution",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.trap_handler)] = .{
        .llvm_name = "trap-handler",
        .description = "Trap handler support",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.trig_reduced_range)] = .{
        .llvm_name = "trig-reduced-range",
        .description = "Requires use of fract on arguments to trig instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.true16)] = .{
        .llvm_name = "true16",
        .description = "True 16-bit operand instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unaligned_access_mode)] = .{
        .llvm_name = "unaligned-access-mode",
        .description = "Enable unaligned global, local and region loads and stores if the hardware supports it",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unaligned_buffer_access)] = .{
        .llvm_name = "unaligned-buffer-access",
        .description = "Hardware supports unaligned global loads and stores",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unaligned_ds_access)] = .{
        .llvm_name = "unaligned-ds-access",
        .description = "Hardware supports unaligned local and region loads and stores",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unaligned_scratch_access)] = .{
        .llvm_name = "unaligned-scratch-access",
        .description = "Support unaligned scratch loads and stores",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unpacked_d16_vmem)] = .{
        .llvm_name = "unpacked-d16-vmem",
        .description = "Has unpacked d16 vmem instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unsafe_ds_offset_folding)] = .{
        .llvm_name = "unsafe-ds-offset-folding",
        .description = "Force using DS instruction immediate offsets on SI",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.user_sgpr_init16_bug)] = .{
        .llvm_name = "user-sgpr-init16-bug",
        .description = "Bug requiring at least 16 user+system SGPRs to be enabled",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.valu_trans_use_hazard)] = .{
        .llvm_name = "valu-trans-use-hazard",
        .description = "Hazard when TRANS instructions are closely followed by a use of the result",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vcmpx_exec_war_hazard)] = .{
        .llvm_name = "vcmpx-exec-war-hazard",
        .description = "V_CMPX WAR hazard on EXEC (V_CMPX issue ONLY)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vcmpx_permlane_hazard)] = .{
        .llvm_name = "vcmpx-permlane-hazard",
        .description = "TODO: describe me",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vgpr_index_mode)] = .{
        .llvm_name = "vgpr-index-mode",
        .description = "Has VGPR mode register indexing",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vmem_to_scalar_write_hazard)] = .{
        .llvm_name = "vmem-to-scalar-write-hazard",
        .description = "VMEM instruction followed by scalar writing to EXEC mask, M0 or SGPR leads to incorrect execution.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vmem_write_vgpr_in_order)] = .{
        .llvm_name = "vmem-write-vgpr-in-order",
        .description = "VMEM instructions of the same type write VGPR results in order",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.volcanic_islands)] = .{
        .llvm_name = "volcanic-islands",
        .description = "VOLCANIC_ISLANDS GPU generation",
        .dependencies = featureSet(&[_]Feature{
            .@"16_bit_insts",
            .addressablelocalmemorysize65536,
            .ci_insts,
            .default_component_zero,
            .dpp,
            .ds_src2_insts,
            .extended_image_insts,
            .fast_denormal_f32,
            .flat_address_space,
            .fp64,
            .gcn3_encoding,
            .gds,
            .gfx7_gfx8_gfx9_insts,
            .gfx8_insts,
            .gws,
            .image_insts,
            .int_clamp_insts,
            .inv_2pi_inline_imm,
            .mad_mac_f32_insts,
            .mimg_r128,
            .movrel,
            .s_memrealtime,
            .s_memtime_inst,
            .scalar_stores,
            .sdwa,
            .sdwa_mav,
            .sdwa_out_mods_vopc,
            .trig_reduced_range,
            .unaligned_buffer_access,
            .vgpr_index_mode,
            .vmem_write_vgpr_in_order,
            .wavefrontsize64,
        }),
    };
    result[@intFromEnum(Feature.vop3_literal)] = .{
        .llvm_name = "vop3-literal",
        .description = "Can use one literal in VOP3",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vop3p)] = .{
        .llvm_name = "vop3p",
        .description = "Has VOP3P packed instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vopd)] = .{
        .llvm_name = "vopd",
        .description = "Has VOPD dual issue wave32 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vscnt)] = .{
        .llvm_name = "vscnt",
        .description = "Has separate store vscnt counter",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.wavefrontsize16)] = .{
        .llvm_name = "wavefrontsize16",
        .description = "The number of threads per wavefront",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.wavefrontsize32)] = .{
        .llvm_name = "wavefrontsize32",
        .description = "The number of threads per wavefront",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.wavefrontsize64)] = .{
        .llvm_name = "wavefrontsize64",
        .description = "The number of threads per wavefront",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xf32_insts)] = .{
        .llvm_name = "xf32-insts",
        .description = "Has instructions that support xf32 format, such as v_mfma_f32_16x16x8_xf32 and v_mfma_f32_32x32x4_xf32",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xnack)] = .{
        .llvm_name = "xnack",
        .description = "Enable XNACK support",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.xnack_support)] = .{
        .llvm_name = "xnack-support",
        .description = "Hardware supports XNACK",
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
    pub const bonaire: CpuModel = .{
        .name = "bonaire",
        .llvm_name = "bonaire",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sea_islands,
        }),
    };
    pub const carrizo: CpuModel = .{
        .name = "carrizo",
        .llvm_name = "carrizo",
        .features = featureSet(&[_]Feature{
            .fast_fmaf,
            .half_rate_64_ops,
            .ldsbankcount32,
            .unpacked_d16_vmem,
            .volcanic_islands,
            .xnack_support,
        }),
    };
    pub const fiji: CpuModel = .{
        .name = "fiji",
        .llvm_name = "fiji",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{
            .gds,
            .gws,
        }),
    };
    pub const generic_hsa: CpuModel = .{
        .name = "generic_hsa",
        .llvm_name = "generic-hsa",
        .features = featureSet(&[_]Feature{
            .flat_address_space,
            .gds,
            .gws,
        }),
    };
    pub const gfx1010: CpuModel = .{
        .name = "gfx1010",
        .llvm_name = "gfx1010",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .ds_src2_insts,
            .flat_segment_offset_bug,
            .get_wave_id_inst,
            .gfx10,
            .inst_fwd_prefetch_bug,
            .lds_branch_vmem_war_hazard,
            .lds_misaligned_bug,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .negative_unaligned_scratch_offset_bug,
            .nsa_clause_bug,
            .nsa_encoding,
            .nsa_to_vmem_bug,
            .offset_3f_bug,
            .scalar_atomics,
            .scalar_flat_scratch_insts,
            .scalar_stores,
            .smem_to_vector_write_hazard,
            .vcmpx_exec_war_hazard,
            .vcmpx_permlane_hazard,
            .vmem_to_scalar_write_hazard,
            .xnack_support,
        }),
    };
    pub const gfx1011: CpuModel = .{
        .name = "gfx1011",
        .llvm_name = "gfx1011",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .ds_src2_insts,
            .flat_segment_offset_bug,
            .get_wave_id_inst,
            .gfx10,
            .inst_fwd_prefetch_bug,
            .lds_branch_vmem_war_hazard,
            .lds_misaligned_bug,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .negative_unaligned_scratch_offset_bug,
            .nsa_clause_bug,
            .nsa_encoding,
            .nsa_to_vmem_bug,
            .offset_3f_bug,
            .scalar_atomics,
            .scalar_flat_scratch_insts,
            .scalar_stores,
            .smem_to_vector_write_hazard,
            .vcmpx_exec_war_hazard,
            .vcmpx_permlane_hazard,
            .vmem_to_scalar_write_hazard,
            .xnack_support,
        }),
    };
    pub const gfx1012: CpuModel = .{
        .name = "gfx1012",
        .llvm_name = "gfx1012",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .ds_src2_insts,
            .flat_segment_offset_bug,
            .get_wave_id_inst,
            .gfx10,
            .inst_fwd_prefetch_bug,
            .lds_branch_vmem_war_hazard,
            .lds_misaligned_bug,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .negative_unaligned_scratch_offset_bug,
            .nsa_clause_bug,
            .nsa_encoding,
            .nsa_to_vmem_bug,
            .offset_3f_bug,
            .scalar_atomics,
            .scalar_flat_scratch_insts,
            .scalar_stores,
            .smem_to_vector_write_hazard,
            .vcmpx_exec_war_hazard,
            .vcmpx_permlane_hazard,
            .vmem_to_scalar_write_hazard,
            .xnack_support,
        }),
    };
    pub const gfx1013: CpuModel = .{
        .name = "gfx1013",
        .llvm_name = "gfx1013",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .ds_src2_insts,
            .flat_segment_offset_bug,
            .get_wave_id_inst,
            .gfx10,
            .gfx10_a_encoding,
            .inst_fwd_prefetch_bug,
            .lds_branch_vmem_war_hazard,
            .lds_misaligned_bug,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .negative_unaligned_scratch_offset_bug,
            .nsa_clause_bug,
            .nsa_encoding,
            .nsa_to_vmem_bug,
            .offset_3f_bug,
            .scalar_atomics,
            .scalar_flat_scratch_insts,
            .scalar_stores,
            .smem_to_vector_write_hazard,
            .vcmpx_exec_war_hazard,
            .vcmpx_permlane_hazard,
            .vmem_to_scalar_write_hazard,
            .xnack_support,
        }),
    };
    pub const gfx1030: CpuModel = .{
        .name = "gfx1030",
        .llvm_name = "gfx1030",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .shader_cycles_register,
        }),
    };
    pub const gfx1031: CpuModel = .{
        .name = "gfx1031",
        .llvm_name = "gfx1031",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .shader_cycles_register,
        }),
    };
    pub const gfx1032: CpuModel = .{
        .name = "gfx1032",
        .llvm_name = "gfx1032",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .shader_cycles_register,
        }),
    };
    pub const gfx1033: CpuModel = .{
        .name = "gfx1033",
        .llvm_name = "gfx1033",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .shader_cycles_register,
        }),
    };
    pub const gfx1034: CpuModel = .{
        .name = "gfx1034",
        .llvm_name = "gfx1034",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .shader_cycles_register,
        }),
    };
    pub const gfx1035: CpuModel = .{
        .name = "gfx1035",
        .llvm_name = "gfx1035",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .shader_cycles_register,
        }),
    };
    pub const gfx1036: CpuModel = .{
        .name = "gfx1036",
        .llvm_name = "gfx1036",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .shader_cycles_register,
        }),
    };
    pub const gfx10_1_generic: CpuModel = .{
        .name = "gfx10_1_generic",
        .llvm_name = "gfx10-1-generic",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .ds_src2_insts,
            .flat_segment_offset_bug,
            .get_wave_id_inst,
            .gfx10,
            .inst_fwd_prefetch_bug,
            .lds_branch_vmem_war_hazard,
            .lds_misaligned_bug,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .negative_unaligned_scratch_offset_bug,
            .nsa_clause_bug,
            .nsa_encoding,
            .nsa_to_vmem_bug,
            .offset_3f_bug,
            .requires_cov6,
            .scalar_atomics,
            .scalar_flat_scratch_insts,
            .scalar_stores,
            .smem_to_vector_write_hazard,
            .vcmpx_exec_war_hazard,
            .vcmpx_permlane_hazard,
            .vmem_to_scalar_write_hazard,
            .xnack_support,
        }),
    };
    pub const gfx10_3_generic: CpuModel = .{
        .name = "gfx10_3_generic",
        .llvm_name = "gfx10-3-generic",
        .features = featureSet(&[_]Feature{
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .gfx10,
            .gfx10_3_insts,
            .gfx10_a_encoding,
            .gfx10_b_encoding,
            .ldsbankcount32,
            .nsa_encoding,
            .requires_cov6,
            .shader_cycles_register,
        }),
    };
    pub const gfx1100: CpuModel = .{
        .name = "gfx1100",
        .llvm_name = "gfx1100",
        .features = featureSet(&[_]Feature{
            .allocate1_5xvgprs,
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .mad_intra_fwd_bug,
            .memory_atomic_fadd_f32_denormal_support,
            .msaa_load_dst_sel_bug,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .priv_enabled_trap2_nop_bug,
            .shader_cycles_register,
            .user_sgpr_init16_bug,
            .valu_trans_use_hazard,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1101: CpuModel = .{
        .name = "gfx1101",
        .llvm_name = "gfx1101",
        .features = featureSet(&[_]Feature{
            .allocate1_5xvgprs,
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .mad_intra_fwd_bug,
            .memory_atomic_fadd_f32_denormal_support,
            .msaa_load_dst_sel_bug,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .priv_enabled_trap2_nop_bug,
            .shader_cycles_register,
            .valu_trans_use_hazard,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1102: CpuModel = .{
        .name = "gfx1102",
        .llvm_name = "gfx1102",
        .features = featureSet(&[_]Feature{
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .mad_intra_fwd_bug,
            .memory_atomic_fadd_f32_denormal_support,
            .msaa_load_dst_sel_bug,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .priv_enabled_trap2_nop_bug,
            .shader_cycles_register,
            .user_sgpr_init16_bug,
            .valu_trans_use_hazard,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1103: CpuModel = .{
        .name = "gfx1103",
        .llvm_name = "gfx1103",
        .features = featureSet(&[_]Feature{
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .mad_intra_fwd_bug,
            .memory_atomic_fadd_f32_denormal_support,
            .msaa_load_dst_sel_bug,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .priv_enabled_trap2_nop_bug,
            .shader_cycles_register,
            .valu_trans_use_hazard,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1150: CpuModel = .{
        .name = "gfx1150",
        .llvm_name = "gfx1150",
        .features = featureSet(&[_]Feature{
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .dpp_src1_sgpr,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .memory_atomic_fadd_f32_denormal_support,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .required_export_priority,
            .salu_float,
            .shader_cycles_register,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1151: CpuModel = .{
        .name = "gfx1151",
        .llvm_name = "gfx1151",
        .features = featureSet(&[_]Feature{
            .allocate1_5xvgprs,
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .dpp_src1_sgpr,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .memory_atomic_fadd_f32_denormal_support,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .required_export_priority,
            .salu_float,
            .shader_cycles_register,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1152: CpuModel = .{
        .name = "gfx1152",
        .llvm_name = "gfx1152",
        .features = featureSet(&[_]Feature{
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .dpp_src1_sgpr,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .memory_atomic_fadd_f32_denormal_support,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .required_export_priority,
            .salu_float,
            .shader_cycles_register,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1153: CpuModel = .{
        .name = "gfx1153",
        .llvm_name = "gfx1153",
        .features = featureSet(&[_]Feature{
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .dpp_src1_sgpr,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .memory_atomic_fadd_f32_denormal_support,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .required_export_priority,
            .salu_float,
            .shader_cycles_register,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx11_generic: CpuModel = .{
        .name = "gfx11_generic",
        .llvm_name = "gfx11-generic",
        .features = featureSet(&[_]Feature{
            .architected_flat_scratch,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot5_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .flat_atomic_fadd_f32_inst,
            .gfx11,
            .image_insts,
            .ldsbankcount32,
            .mad_intra_fwd_bug,
            .memory_atomic_fadd_f32_denormal_support,
            .msaa_load_dst_sel_bug,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .priv_enabled_trap2_nop_bug,
            .required_export_priority,
            .requires_cov6,
            .shader_cycles_register,
            .user_sgpr_init16_bug,
            .valu_trans_use_hazard,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1200: CpuModel = .{
        .name = "gfx1200",
        .llvm_name = "gfx1200",
        .features = featureSet(&[_]Feature{
            .allocate1_5xvgprs,
            .architected_flat_scratch,
            .architected_sgprs,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_buffer_pk_add_bf16_inst,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_global_pk_add_bf16_inst,
            .dl_insts,
            .dot10_insts,
            .dot11_insts,
            .dot12_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .dpp_src1_sgpr,
            .extended_image_insts,
            .flat_atomic_fadd_f32_inst,
            .fp8_conversion_insts,
            .gfx12,
            .image_insts,
            .ldsbankcount32,
            .memory_atomic_fadd_f32_denormal_support,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .pseudo_scalar_trans,
            .restricted_soffset,
            .salu_float,
            .scalar_dwordx3_loads,
            .shader_cycles_hi_lo_registers,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx1201: CpuModel = .{
        .name = "gfx1201",
        .llvm_name = "gfx1201",
        .features = featureSet(&[_]Feature{
            .allocate1_5xvgprs,
            .architected_flat_scratch,
            .architected_sgprs,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_buffer_pk_add_bf16_inst,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_global_pk_add_bf16_inst,
            .dl_insts,
            .dot10_insts,
            .dot11_insts,
            .dot12_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .dpp_src1_sgpr,
            .extended_image_insts,
            .flat_atomic_fadd_f32_inst,
            .fp8_conversion_insts,
            .gfx12,
            .image_insts,
            .ldsbankcount32,
            .memory_atomic_fadd_f32_denormal_support,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .pseudo_scalar_trans,
            .restricted_soffset,
            .salu_float,
            .scalar_dwordx3_loads,
            .shader_cycles_hi_lo_registers,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx12_generic: CpuModel = .{
        .name = "gfx12_generic",
        .llvm_name = "gfx12-generic",
        .features = featureSet(&[_]Feature{
            .allocate1_5xvgprs,
            .architected_flat_scratch,
            .architected_sgprs,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_buffer_pk_add_bf16_inst,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_global_pk_add_bf16_inst,
            .dl_insts,
            .dot10_insts,
            .dot11_insts,
            .dot12_insts,
            .dot7_insts,
            .dot8_insts,
            .dot9_insts,
            .dpp_src1_sgpr,
            .extended_image_insts,
            .flat_atomic_fadd_f32_inst,
            .fp8_conversion_insts,
            .gfx12,
            .image_insts,
            .ldsbankcount32,
            .memory_atomic_fadd_f32_denormal_support,
            .nsa_encoding,
            .packed_tid,
            .partial_nsa_encoding,
            .pseudo_scalar_trans,
            .requires_cov6,
            .restricted_soffset,
            .salu_float,
            .scalar_dwordx3_loads,
            .shader_cycles_hi_lo_registers,
            .vcmpx_permlane_hazard,
        }),
    };
    pub const gfx600: CpuModel = .{
        .name = "gfx600",
        .llvm_name = "gfx600",
        .features = featureSet(&[_]Feature{
            .fast_fmaf,
            .half_rate_64_ops,
            .southern_islands,
        }),
    };
    pub const gfx601: CpuModel = .{
        .name = "gfx601",
        .llvm_name = "gfx601",
        .features = featureSet(&[_]Feature{
            .southern_islands,
        }),
    };
    pub const gfx602: CpuModel = .{
        .name = "gfx602",
        .llvm_name = "gfx602",
        .features = featureSet(&[_]Feature{
            .southern_islands,
        }),
    };
    pub const gfx700: CpuModel = .{
        .name = "gfx700",
        .llvm_name = "gfx700",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sea_islands,
        }),
    };
    pub const gfx701: CpuModel = .{
        .name = "gfx701",
        .llvm_name = "gfx701",
        .features = featureSet(&[_]Feature{
            .fast_fmaf,
            .half_rate_64_ops,
            .ldsbankcount32,
            .sea_islands,
        }),
    };
    pub const gfx702: CpuModel = .{
        .name = "gfx702",
        .llvm_name = "gfx702",
        .features = featureSet(&[_]Feature{
            .fast_fmaf,
            .ldsbankcount16,
            .sea_islands,
        }),
    };
    pub const gfx703: CpuModel = .{
        .name = "gfx703",
        .llvm_name = "gfx703",
        .features = featureSet(&[_]Feature{
            .ldsbankcount16,
            .sea_islands,
        }),
    };
    pub const gfx704: CpuModel = .{
        .name = "gfx704",
        .llvm_name = "gfx704",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sea_islands,
        }),
    };
    pub const gfx705: CpuModel = .{
        .name = "gfx705",
        .llvm_name = "gfx705",
        .features = featureSet(&[_]Feature{
            .ldsbankcount16,
            .sea_islands,
        }),
    };
    pub const gfx801: CpuModel = .{
        .name = "gfx801",
        .llvm_name = "gfx801",
        .features = featureSet(&[_]Feature{
            .fast_fmaf,
            .half_rate_64_ops,
            .ldsbankcount32,
            .unpacked_d16_vmem,
            .volcanic_islands,
            .xnack_support,
        }),
    };
    pub const gfx802: CpuModel = .{
        .name = "gfx802",
        .llvm_name = "gfx802",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sgpr_init_bug,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const gfx803: CpuModel = .{
        .name = "gfx803",
        .llvm_name = "gfx803",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const gfx805: CpuModel = .{
        .name = "gfx805",
        .llvm_name = "gfx805",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sgpr_init_bug,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const gfx810: CpuModel = .{
        .name = "gfx810",
        .llvm_name = "gfx810",
        .features = featureSet(&[_]Feature{
            .image_gather4_d16_bug,
            .image_store_d16_bug,
            .ldsbankcount16,
            .volcanic_islands,
            .xnack_support,
        }),
    };
    pub const gfx900: CpuModel = .{
        .name = "gfx900",
        .llvm_name = "gfx900",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .ds_src2_insts,
            .extended_image_insts,
            .gds,
            .gfx9,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .mad_mix_insts,
        }),
    };
    pub const gfx902: CpuModel = .{
        .name = "gfx902",
        .llvm_name = "gfx902",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .ds_src2_insts,
            .extended_image_insts,
            .gds,
            .gfx9,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .mad_mix_insts,
        }),
    };
    pub const gfx904: CpuModel = .{
        .name = "gfx904",
        .llvm_name = "gfx904",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .ds_src2_insts,
            .extended_image_insts,
            .fma_mix_insts,
            .gds,
            .gfx9,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
        }),
    };
    pub const gfx906: CpuModel = .{
        .name = "gfx906",
        .llvm_name = "gfx906",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot7_insts,
            .ds_src2_insts,
            .extended_image_insts,
            .fma_mix_insts,
            .gds,
            .gfx9,
            .half_rate_64_ops,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .sramecc_support,
        }),
    };
    pub const gfx908: CpuModel = .{
        .name = "gfx908",
        .llvm_name = "gfx908",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .atomic_buffer_global_pk_add_f16_no_rtn_insts,
            .atomic_fadd_no_rtn_insts,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot3_insts,
            .dot4_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .ds_src2_insts,
            .extended_image_insts,
            .fma_mix_insts,
            .gds,
            .gfx9,
            .half_rate_64_ops,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .mai_insts,
            .mfma_inline_literal_bug,
            .pk_fmac_f16_inst,
            .sramecc_support,
        }),
    };
    pub const gfx909: CpuModel = .{
        .name = "gfx909",
        .llvm_name = "gfx909",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .ds_src2_insts,
            .extended_image_insts,
            .gds,
            .gfx9,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .mad_mix_insts,
        }),
    };
    pub const gfx90a: CpuModel = .{
        .name = "gfx90a",
        .llvm_name = "gfx90a",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f64,
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot3_insts,
            .dot4_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .dpp_64bit,
            .flat_buffer_global_fadd_f64_inst,
            .fma_mix_insts,
            .fmacf64_inst,
            .full_rate_64_ops,
            .gfx9,
            .gfx90a_insts,
            .image_insts,
            .kernarg_preload,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .mai_insts,
            .packed_fp32_ops,
            .packed_tid,
            .pk_fmac_f16_inst,
            .sramecc_support,
        }),
    };
    pub const gfx90c: CpuModel = .{
        .name = "gfx90c",
        .llvm_name = "gfx90c",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .ds_src2_insts,
            .extended_image_insts,
            .gds,
            .gfx9,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .mad_mix_insts,
        }),
    };
    pub const gfx940: CpuModel = .{
        .name = "gfx940",
        .llvm_name = "gfx940",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .agent_scope_fine_grained_remote_memory_atomics,
            .architected_flat_scratch,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f64,
            .atomic_global_pk_add_bf16_inst,
            .back_off_barrier,
            .cvt_fp8_vop1_bug,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot3_insts,
            .dot4_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .dpp_64bit,
            .flat_atomic_fadd_f32_inst,
            .flat_buffer_global_fadd_f64_inst,
            .fma_mix_insts,
            .fmacf64_inst,
            .force_store_sc0_sc1,
            .fp8_insts,
            .full_rate_64_ops,
            .gfx9,
            .gfx90a_insts,
            .gfx940_insts,
            .kernarg_preload,
            .ldsbankcount32,
            .mai_insts,
            .memory_atomic_fadd_f32_denormal_support,
            .packed_fp32_ops,
            .packed_tid,
            .pk_fmac_f16_inst,
            .sramecc_support,
            .xf32_insts,
        }),
    };
    pub const gfx941: CpuModel = .{
        .name = "gfx941",
        .llvm_name = "gfx941",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .agent_scope_fine_grained_remote_memory_atomics,
            .architected_flat_scratch,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f64,
            .atomic_global_pk_add_bf16_inst,
            .back_off_barrier,
            .cvt_fp8_vop1_bug,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot3_insts,
            .dot4_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .dpp_64bit,
            .flat_atomic_fadd_f32_inst,
            .flat_buffer_global_fadd_f64_inst,
            .fma_mix_insts,
            .fmacf64_inst,
            .force_store_sc0_sc1,
            .fp8_insts,
            .full_rate_64_ops,
            .gfx9,
            .gfx90a_insts,
            .gfx940_insts,
            .kernarg_preload,
            .ldsbankcount32,
            .mai_insts,
            .memory_atomic_fadd_f32_denormal_support,
            .packed_fp32_ops,
            .packed_tid,
            .pk_fmac_f16_inst,
            .sramecc_support,
            .xf32_insts,
        }),
    };
    pub const gfx942: CpuModel = .{
        .name = "gfx942",
        .llvm_name = "gfx942",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .agent_scope_fine_grained_remote_memory_atomics,
            .architected_flat_scratch,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f64,
            .atomic_global_pk_add_bf16_inst,
            .back_off_barrier,
            .cvt_fp8_vop1_bug,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot3_insts,
            .dot4_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .dpp_64bit,
            .flat_atomic_fadd_f32_inst,
            .flat_buffer_global_fadd_f64_inst,
            .fma_mix_insts,
            .fmacf64_inst,
            .fp8_insts,
            .full_rate_64_ops,
            .gfx9,
            .gfx90a_insts,
            .gfx940_insts,
            .kernarg_preload,
            .ldsbankcount32,
            .mai_insts,
            .memory_atomic_fadd_f32_denormal_support,
            .packed_fp32_ops,
            .packed_tid,
            .pk_fmac_f16_inst,
            .sramecc_support,
            .xf32_insts,
        }),
    };
    pub const gfx950: CpuModel = .{
        .name = "gfx950",
        .llvm_name = "gfx950",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize163840,
            .agent_scope_fine_grained_remote_memory_atomics,
            .architected_flat_scratch,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_buffer_pk_add_bf16_inst,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f64,
            .atomic_global_pk_add_bf16_inst,
            .back_off_barrier,
            .bf16_cvt_insts,
            .bitop3_insts,
            .dl_insts,
            .dot10_insts,
            .dot12_insts,
            .dot13_insts,
            .dot1_insts,
            .dot2_insts,
            .dot3_insts,
            .dot4_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .dpp_64bit,
            .flat_atomic_fadd_f32_inst,
            .flat_buffer_global_fadd_f64_inst,
            .fma_mix_insts,
            .fmacf64_inst,
            .fp8_conversion_insts,
            .fp8_insts,
            .full_rate_64_ops,
            .gfx9,
            .gfx90a_insts,
            .gfx940_insts,
            .gfx950_insts,
            .kernarg_preload,
            .ldsbankcount32,
            .mai_insts,
            .memory_atomic_fadd_f32_denormal_support,
            .packed_fp32_ops,
            .packed_tid,
            .pk_fmac_f16_inst,
            .prng_inst,
            .sramecc_support,
        }),
    };
    pub const gfx9_4_generic: CpuModel = .{
        .name = "gfx9_4_generic",
        .llvm_name = "gfx9-4-generic",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .agent_scope_fine_grained_remote_memory_atomics,
            .architected_flat_scratch,
            .atomic_buffer_global_pk_add_f16_insts,
            .atomic_ds_pk_add_16_insts,
            .atomic_fadd_no_rtn_insts,
            .atomic_fadd_rtn_insts,
            .atomic_flat_pk_add_16_insts,
            .atomic_fmin_fmax_flat_f64,
            .atomic_fmin_fmax_global_f64,
            .atomic_global_pk_add_bf16_inst,
            .back_off_barrier,
            .dl_insts,
            .dot10_insts,
            .dot1_insts,
            .dot2_insts,
            .dot3_insts,
            .dot4_insts,
            .dot5_insts,
            .dot6_insts,
            .dot7_insts,
            .dpp_64bit,
            .flat_atomic_fadd_f32_inst,
            .flat_buffer_global_fadd_f64_inst,
            .fma_mix_insts,
            .fmacf64_inst,
            .full_rate_64_ops,
            .gfx9,
            .gfx90a_insts,
            .gfx940_insts,
            .kernarg_preload,
            .ldsbankcount32,
            .mai_insts,
            .memory_atomic_fadd_f32_denormal_support,
            .packed_fp32_ops,
            .packed_tid,
            .pk_fmac_f16_inst,
            .requires_cov6,
            .sramecc_support,
        }),
    };
    pub const gfx9_generic: CpuModel = .{
        .name = "gfx9_generic",
        .llvm_name = "gfx9-generic",
        .features = featureSet(&[_]Feature{
            .addressablelocalmemorysize65536,
            .ds_src2_insts,
            .extended_image_insts,
            .gds,
            .gfx9,
            .image_gather4_d16_bug,
            .image_insts,
            .ldsbankcount32,
            .mad_mac_f32_insts,
            .requires_cov6,
        }),
    };
    pub const hainan: CpuModel = .{
        .name = "hainan",
        .llvm_name = "hainan",
        .features = featureSet(&[_]Feature{
            .southern_islands,
        }),
    };
    pub const hawaii: CpuModel = .{
        .name = "hawaii",
        .llvm_name = "hawaii",
        .features = featureSet(&[_]Feature{
            .fast_fmaf,
            .half_rate_64_ops,
            .ldsbankcount32,
            .sea_islands,
        }),
    };
    pub const iceland: CpuModel = .{
        .name = "iceland",
        .llvm_name = "iceland",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sgpr_init_bug,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const kabini: CpuModel = .{
        .name = "kabini",
        .llvm_name = "kabini",
        .features = featureSet(&[_]Feature{
            .ldsbankcount16,
            .sea_islands,
        }),
    };
    pub const kaveri: CpuModel = .{
        .name = "kaveri",
        .llvm_name = "kaveri",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sea_islands,
        }),
    };
    pub const mullins: CpuModel = .{
        .name = "mullins",
        .llvm_name = "mullins",
        .features = featureSet(&[_]Feature{
            .ldsbankcount16,
            .sea_islands,
        }),
    };
    pub const oland: CpuModel = .{
        .name = "oland",
        .llvm_name = "oland",
        .features = featureSet(&[_]Feature{
            .southern_islands,
        }),
    };
    pub const pitcairn: CpuModel = .{
        .name = "pitcairn",
        .llvm_name = "pitcairn",
        .features = featureSet(&[_]Feature{
            .southern_islands,
        }),
    };
    pub const polaris10: CpuModel = .{
        .name = "polaris10",
        .llvm_name = "polaris10",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const polaris11: CpuModel = .{
        .name = "polaris11",
        .llvm_name = "polaris11",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const stoney: CpuModel = .{
        .name = "stoney",
        .llvm_name = "stoney",
        .features = featureSet(&[_]Feature{
            .image_gather4_d16_bug,
            .image_store_d16_bug,
            .ldsbankcount16,
            .volcanic_islands,
            .xnack_support,
        }),
    };
    pub const tahiti: CpuModel = .{
        .name = "tahiti",
        .llvm_name = "tahiti",
        .features = featureSet(&[_]Feature{
            .fast_fmaf,
            .half_rate_64_ops,
            .southern_islands,
        }),
    };
    pub const tonga: CpuModel = .{
        .name = "tonga",
        .llvm_name = "tonga",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sgpr_init_bug,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const tongapro: CpuModel = .{
        .name = "tongapro",
        .llvm_name = "tongapro",
        .features = featureSet(&[_]Feature{
            .ldsbankcount32,
            .sgpr_init_bug,
            .unpacked_d16_vmem,
            .volcanic_islands,
        }),
    };
    pub const verde: CpuModel = .{
        .name = "verde",
        .llvm_name = "verde",
        .features = featureSet(&[_]Feature{
            .southern_islands,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    norm,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.norm)] = .{
        .llvm_name = "norm",
        .description = "Enable support for norm instruction.",
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
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    @"32bit",
    @"8msecext",
    aapcs_frame_chain,
    aclass,
    acquire_release,
    aes,
    atomics_32,
    avoid_movs_shop,
    avoid_muls,
    avoid_partial_cpsr,
    bf16,
    big_endian_instructions,
    branch_align_64,
    cde,
    cdecp0,
    cdecp1,
    cdecp2,
    cdecp3,
    cdecp4,
    cdecp5,
    cdecp6,
    cdecp7,
    cheap_predicable_cpsr,
    clrbhb,
    cortex_a510,
    crc,
    crypto,
    d32,
    db,
    dfb,
    disable_postra_scheduler,
    dont_widen_vmovs,
    dotprod,
    dsp,
    execute_only,
    expand_fp_mlx,
    fix_cmse_cve_2021_35465,
    fix_cortex_a57_aes_1742098,
    fp16,
    fp16fml,
    fp64,
    fp_armv8,
    fp_armv8d16,
    fp_armv8d16sp,
    fp_armv8sp,
    fpao,
    fpregs,
    fpregs16,
    fpregs64,
    fullfp16,
    fuse_aes,
    fuse_literals,
    harden_sls_blr,
    harden_sls_nocomdat,
    harden_sls_retbr,
    has_v4t,
    has_v5t,
    has_v5te,
    has_v6,
    has_v6k,
    has_v6m,
    has_v6t2,
    has_v7,
    has_v7clrex,
    has_v8,
    has_v8_1a,
    has_v8_1m_main,
    has_v8_2a,
    has_v8_3a,
    has_v8_4a,
    has_v8_5a,
    has_v8_6a,
    has_v8_7a,
    has_v8_8a,
    has_v8_9a,
    has_v8m,
    has_v8m_main,
    has_v9_1a,
    has_v9_2a,
    has_v9_3a,
    has_v9_4a,
    has_v9_5a,
    has_v9_6a,
    has_v9a,
    hwdiv,
    hwdiv_arm,
    i8mm,
    iwmmxt,
    iwmmxt2,
    lob,
    long_calls,
    loop_align,
    m55,
    m85,
    mclass,
    mp,
    muxed_units,
    mve,
    mve1beat,
    mve2beat,
    mve4beat,
    mve_fp,
    nacl_trap,
    neon,
    neon_fpmovs,
    neonfp,
    no_branch_predictor,
    no_bti_at_return_twice,
    no_movt,
    no_neg_immediates,
    noarm,
    nonpipelined_vfp,
    pacbti,
    perfmon,
    prefer_ishst,
    prefer_vmovsr,
    prof_unpr,
    ras,
    rclass,
    read_tp_tpidrprw,
    read_tp_tpidruro,
    read_tp_tpidrurw,
    reserve_r9,
    ret_addr_stack,
    sb,
    sha2,
    slow_fp_brcc,
    slow_load_D_subreg,
    slow_odd_reg,
    slow_vdup32,
    slow_vgetlni32,
    slowfpvfmx,
    slowfpvmlx,
    soft_float,
    splat_vfp_neon,
    strict_align,
    thumb2,
    thumb_mode,
    trustzone,
    use_mipipeliner,
    use_misched,
    v2,
    v2a,
    v3,
    v3m,
    v4,
    v4t,
    v5t,
    v5te,
    v5tej,
    v6,
    v6j,
    v6k,
    v6kz,
    v6m,
    v6sm,
    v6t2,
    v7a,
    v7em,
    v7m,
    v7r,
    v7ve,
    v8_1a,
    v8_1m_main,
    v8_2a,
    v8_3a,
    v8_4a,
    v8_5a,
    v8_6a,
    v8_7a,
    v8_8a,
    v8_9a,
    v8a,
    v8m,
    v8m_main,
    v8r,
    v9_1a,
    v9_2a,
    v9_3a,
    v9_4a,
    v9_5a,
    v9_6a,
    v9a,
    vfp2,
    vfp2sp,
    vfp3,
    vfp3d16,
    vfp3d16sp,
    vfp3sp,
    vfp4,
    vfp4d16,
    vfp4d16sp,
    vfp4sp,
    virtualization,
    vldn_align,
    vmlx_forwarding,
    vmlx_hazards,
    wide_stride_vfp,
    xscale,
    zcz,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    @setEvalBranchQuota(10000);
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.@"32bit")] = .{
        .llvm_name = "32bit",
        .description = "Prefer 32-bit Thumb instrs",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.@"8msecext")] = .{
        .llvm_name = "8msecext",
        .description = "Enable support for ARMv8-M Security Extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aapcs_frame_chain)] = .{
        .llvm_name = "aapcs-frame-chain",
        .description = "Create an AAPCS compliant frame chain",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aclass)] = .{
        .llvm_name = "aclass",
        .description = "Is application profile ('A' series)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.acquire_release)] = .{
        .llvm_name = "acquire-release",
        .description = "Has v8 acquire/release (lda/ldaex  etc) instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.aes)] = .{
        .llvm_name = "aes",
        .description = "Enable AES support",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.atomics_32)] = .{
        .llvm_name = "atomics-32",
        .description = "Assume that lock-free 32-bit atomics are available",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.avoid_movs_shop)] = .{
        .llvm_name = "avoid-movs-shop",
        .description = "Avoid movs instructions with shifter operand",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.avoid_muls)] = .{
        .llvm_name = "avoid-muls",
        .description = "Avoid MULS instructions for M class cores",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.avoid_partial_cpsr)] = .{
        .llvm_name = "avoid-partial-cpsr",
        .description = "Avoid CPSR partial update for OOO execution",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bf16)] = .{
        .llvm_name = "bf16",
        .description = "Enable support for BFloat16 instructions",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.big_endian_instructions)] = .{
        .llvm_name = "big-endian-instructions",
        .description = "Expect instructions to be stored big-endian.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.branch_align_64)] = .{
        .llvm_name = "branch-align-64",
        .description = "Prefer 64-bit alignment for branch targets",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cde)] = .{
        .llvm_name = "cde",
        .description = "Support CDE instructions",
        .dependencies = featureSet(&[_]Feature{
            .has_v8m_main,
        }),
    };
    result[@intFromEnum(Feature.cdecp0)] = .{
        .llvm_name = "cdecp0",
        .description = "Coprocessor 0 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cdecp1)] = .{
        .llvm_name = "cdecp1",
        .description = "Coprocessor 1 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cdecp2)] = .{
        .llvm_name = "cdecp2",
        .description = "Coprocessor 2 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cdecp3)] = .{
        .llvm_name = "cdecp3",
        .description = "Coprocessor 3 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cdecp4)] = .{
        .llvm_name = "cdecp4",
        .description = "Coprocessor 4 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cdecp5)] = .{
        .llvm_name = "cdecp5",
        .description = "Coprocessor 5 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cdecp6)] = .{
        .llvm_name = "cdecp6",
        .description = "Coprocessor 6 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cdecp7)] = .{
        .llvm_name = "cdecp7",
        .description = "Coprocessor 7 ISA is CDEv1",
        .dependencies = featureSet(&[_]Feature{
            .cde,
        }),
    };
    result[@intFromEnum(Feature.cheap_predicable_cpsr)] = .{
        .llvm_name = "cheap-predicable-cpsr",
        .description = "Disable +1 predication cost for instructions updating CPSR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.clrbhb)] = .{
        .llvm_name = "clrbhb",
        .description = "Enable Clear BHB instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.cortex_a510)] = .{
        .llvm_name = "cortex-a510",
        .description = "Cortex-A510 ARM processors",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.crc)] = .{
        .llvm_name = "crc",
        .description = "Enable support for CRC instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.crypto)] = .{
        .llvm_name = "crypto",
        .description = "Enable support for Cryptography extensions",
        .dependencies = featureSet(&[_]Feature{
            .aes,
            .sha2,
        }),
    };
    result[@intFromEnum(Feature.d32)] = .{
        .llvm_name = "d32",
        .description = "Extend FP to 32 double registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.db)] = .{
        .llvm_name = "db",
        .description = "Has data barrier (dmb/dsb) instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dfb)] = .{
        .llvm_name = "dfb",
        .description = "Has full data barrier (dfb) instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.disable_postra_scheduler)] = .{
        .llvm_name = "disable-postra-scheduler",
        .description = "Don't schedule again after register allocation",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dont_widen_vmovs)] = .{
        .llvm_name = "dont-widen-vmovs",
        .description = "Don't widen VMOVS to VMOVD",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dotprod)] = .{
        .llvm_name = "dotprod",
        .description = "Enable support for dot product instructions",
        .dependencies = featureSet(&[_]Feature{
            .neon,
        }),
    };
    result[@intFromEnum(Feature.dsp)] = .{
        .llvm_name = "dsp",
        .description = "Supports DSP instructions in ARM and/or Thumb2",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.execute_only)] = .{
        .llvm_name = "execute-only",
        .description = "Enable the generation of execute only code.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.expand_fp_mlx)] = .{
        .llvm_name = "expand-fp-mlx",
        .description = "Expand VFP/NEON MLA/MLS instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_cmse_cve_2021_35465)] = .{
        .llvm_name = "fix-cmse-cve-2021-35465",
        .description = "Mitigate against the cve-2021-35465 security vulnurability",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_cortex_a57_aes_1742098)] = .{
        .llvm_name = "fix-cortex-a57-aes-1742098",
        .description = "Work around Cortex-A57 Erratum 1742098 / Cortex-A72 Erratum 1655431 (AES)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp16)] = .{
        .llvm_name = "fp16",
        .description = "Enable half-precision floating point",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp16fml)] = .{
        .llvm_name = "fp16fml",
        .description = "Enable full half-precision floating point fml instructions",
        .dependencies = featureSet(&[_]Feature{
            .fullfp16,
        }),
    };
    result[@intFromEnum(Feature.fp64)] = .{
        .llvm_name = "fp64",
        .description = "Floating point unit supports double precision",
        .dependencies = featureSet(&[_]Feature{
            .fpregs64,
        }),
    };
    result[@intFromEnum(Feature.fp_armv8)] = .{
        .llvm_name = "fp-armv8",
        .description = "Enable ARMv8 FP",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8d16,
            .fp_armv8sp,
            .vfp4,
        }),
    };
    result[@intFromEnum(Feature.fp_armv8d16)] = .{
        .llvm_name = "fp-armv8d16",
        .description = "Enable ARMv8 FP with only 16 d-registers",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8d16sp,
            .vfp4d16,
        }),
    };
    result[@intFromEnum(Feature.fp_armv8d16sp)] = .{
        .llvm_name = "fp-armv8d16sp",
        .description = "Enable ARMv8 FP with only 16 d-registers and no double precision",
        .dependencies = featureSet(&[_]Feature{
            .vfp4d16sp,
        }),
    };
    result[@intFromEnum(Feature.fp_armv8sp)] = .{
        .llvm_name = "fp-armv8sp",
        .description = "Enable ARMv8 FP with no double precision",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8d16sp,
            .vfp4sp,
        }),
    };
    result[@intFromEnum(Feature.fpao)] = .{
        .llvm_name = "fpao",
        .description = "Enable fast computation of positive address offsets",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fpregs)] = .{
        .llvm_name = "fpregs",
        .description = "Enable FP registers",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fpregs16)] = .{
        .llvm_name = "fpregs16",
        .description = "Enable 16-bit FP registers",
        .dependencies = featureSet(&[_]Feature{
            .fpregs,
        }),
    };
    result[@intFromEnum(Feature.fpregs64)] = .{
        .llvm_name = "fpregs64",
        .description = "Enable 64-bit FP registers",
        .dependencies = featureSet(&[_]Feature{
            .fpregs,
        }),
    };
    result[@intFromEnum(Feature.fullfp16)] = .{
        .llvm_name = "fullfp16",
        .description = "Enable full half-precision floating point",
        .dependencies = featureSet(&[_]Feature{
            .fp_armv8d16sp,
            .fpregs16,
        }),
    };
    result[@intFromEnum(Feature.fuse_aes)] = .{
        .llvm_name = "fuse-aes",
        .description = "CPU fuses AES crypto operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fuse_literals)] = .{
        .llvm_name = "fuse-literals",
        .description = "CPU fuses literal generation operations",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.harden_sls_blr)] = .{
        .llvm_name = "harden-sls-blr",
        .description = "Harden against straight line speculation across indirect calls",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.harden_sls_nocomdat)] = .{
        .llvm_name = "harden-sls-nocomdat",
        .description = "Generate thunk code for SLS mitigation in the normal text section",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.harden_sls_retbr)] = .{
        .llvm_name = "harden-sls-retbr",
        .description = "Harden against straight line speculation across RETurn and BranchRegister instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.has_v4t)] = .{
        .llvm_name = "v4t",
        .description = "Support ARM v4T instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.has_v5t)] = .{
        .llvm_name = "v5t",
        .description = "Support ARM v5T ```
