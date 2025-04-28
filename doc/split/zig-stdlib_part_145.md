```

    cet_s: bool,
    hdc: bool,
    uintr: bool,
    lbr: bool,
    hwp: bool,
    xtilecfg: bool,
    xtiledata: bool,
    apx: bool,
    _reserved: u12,
};

fn setFeature(cpu: *Target.Cpu, feature: Target.x86.Feature, enabled: bool) void {
    const idx = @as(Target.Cpu.Feature.Set.Index, @intFromEnum(feature));

    if (enabled) cpu.features.addFeature(idx) else cpu.features.removeFeature(idx);
}

inline fn bit(input: u32, offset: u5) bool {
    return (input >> offset) & 1 != 0;
}

inline fn hasMask(input: u32, mask: u32) bool {
    return (input & mask) == mask;
}

pub fn detectNativeCpuAndFeatures(arch: Target.Cpu.Arch, os: Target.Os, query: Target.Query) Target.Cpu {
    _ = query;
    var cpu = Target.Cpu{
        .arch = arch,
        .model = Target.Cpu.Model.generic(arch),
        .features = Target.Cpu.Feature.Set.empty,
    };

    // First we detect features, to use as hints when detecting CPU Model.
    detectNativeFeatures(&cpu, os.tag);

    var leaf = cpuid(0, 0);
    const max_leaf = leaf.eax;
    const vendor = leaf.ebx;

    if (max_leaf > 0) {
        leaf = cpuid(0x1, 0);

        const brand_id = leaf.ebx & 0xff;

        // Detect model and family
        var family = (leaf.eax >> 8) & 0xf;
        var model = (leaf.eax >> 4) & 0xf;
        if (family == 6 or family == 0xf) {
            if (family == 0xf) {
                family += (leaf.eax >> 20) & 0xff;
            }
            model += ((leaf.eax >> 16) & 0xf) << 4;
        }

        // Now we detect the model.
        switch (vendor) {
            0x756e6547 => {
                detectIntelProcessor(&cpu, family, model, brand_id);
            },
            0x68747541 => {
                if (detectAMDProcessor(cpu.features, family, model)) |m| cpu.model = m;
            },
            else => {},
        }
    }

    // Add the CPU model's feature set into the working set, but then
    // override with actual detected features again.
    cpu.features.addFeatureSet(cpu.model.features);
    detectNativeFeatures(&cpu, os.tag);

    cpu.features.populateDependencies(cpu.arch.allFeaturesList());

    return cpu;
}

fn detectIntelProcessor(cpu: *Target.Cpu, family: u32, model: u32, brand_id: u32) void {
    if (brand_id != 0) {
        return;
    }
    switch (family) {
        3 => {
            cpu.model = &Target.x86.cpu.i386;
            return;
        },
        4 => {
            cpu.model = &Target.x86.cpu.i486;
            return;
        },
        5 => {
            if (Target.x86.featureSetHas(cpu.features, .mmx)) {
                cpu.model = &Target.x86.cpu.pentium_mmx;
                return;
            }
            cpu.model = &Target.x86.cpu.pentium;
            return;
        },
        6 => {
            switch (model) {
                0x01 => {
                    cpu.model = &Target.x86.cpu.pentiumpro;
                    return;
                },
                0x03, 0x05, 0x06 => {
                    cpu.model = &Target.x86.cpu.pentium2;
                    return;
                },
                0x07, 0x08, 0x0a, 0x0b => {
                    cpu.model = &Target.x86.cpu.pentium3;
                    return;
                },
                0x09, 0x0d, 0x15 => {
                    cpu.model = &Target.x86.cpu.pentium_m;
                    return;
                },
                0x0e => {
                    cpu.model = &Target.x86.cpu.yonah;
                    return;
                },
                0x0f, 0x16 => {
                    cpu.model = &Target.x86.cpu.core2;
                    return;
                },
                0x17, 0x1d => {
                    cpu.model = &Target.x86.cpu.penryn;
                    return;
                },
                0x1a, 0x1e, 0x1f, 0x2e => {
                    cpu.model = &Target.x86.cpu.nehalem;
                    return;
                },
                0x25, 0x2c, 0x2f => {
                    cpu.model = &Target.x86.cpu.westmere;
                    return;
                },
                0x2a, 0x2d => {
                    cpu.model = &Target.x86.cpu.sandybridge;
                    return;
                },
                0x3a, 0x3e => {
                    cpu.model = &Target.x86.cpu.ivybridge;
                    return;
                },
                0x3c, 0x3f, 0x45, 0x46 => {
                    cpu.model = &Target.x86.cpu.haswell;
                    return;
                },
                0x3d, 0x47, 0x4f, 0x56 => {
                    cpu.model = &Target.x86.cpu.broadwell;
                    return;
                },
                0x4e, 0x5e, 0x8e, 0x9e, 0xa5, 0xa6 => {
                    cpu.model = &Target.x86.cpu.skylake;
                    return;
                },
                0xa7 => {
                    cpu.model = &Target.x86.cpu.rocketlake;
                    return;
                },
                0x55 => {
                    if (Target.x86.featureSetHas(cpu.features, .avx512bf16)) {
                        cpu.model = &Target.x86.cpu.cooperlake;
                        return;
                    } else if (Target.x86.featureSetHas(cpu.features, .avx512vnni)) {
                        cpu.model = &Target.x86.cpu.cascadelake;
                        return;
                    } else {
                        cpu.model = &Target.x86.cpu.skylake_avx512;
                        return;
                    }
                },
                0x66 => {
                    cpu.model = &Target.x86.cpu.cannonlake;
                    return;
                },
                0x7d, 0x7e => {
                    cpu.model = &Target.x86.cpu.icelake_client;
                    return;
                },
                0x6a, 0x6c => {
                    cpu.model = &Target.x86.cpu.icelake_server;
                    return;
                },
                0x8c, 0x8d => {
                    cpu.model = &Target.x86.cpu.tigerlake;
                    return;
                },
                0x97, 0x9a => {
                    cpu.model = &Target.x86.cpu.alderlake;
                    return;
                },
                0xbe => {
                    cpu.model = &Target.x86.cpu.gracemont;
                    return;
                },
                0xb7, 0xba, 0xbf => {
                    cpu.model = &Target.x86.cpu.raptorlake;
                    return;
                },
                0xaa, 0xac => {
                    cpu.model = &Target.x86.cpu.meteorlake;
                    return;
                },
                0xc5, 0xb5 => {
                    cpu.model = &Target.x86.cpu.arrowlake;
                    return;
                },
                0xc6 => {
                    cpu.model = &Target.x86.cpu.arrowlake_s;
                    return;
                },
                0xbd => {
                    cpu.model = &Target.x86.cpu.lunarlake;
                    return;
                },
                0xcc => {
                    cpu.model = &Target.x86.cpu.pantherlake;
                    return;
                },
                0xad => {
                    cpu.model = &Target.x86.cpu.graniterapids;
                    return;
                },
                0xae => {
                    cpu.model = &Target.x86.cpu.graniterapids_d;
                    return;
                },
                0xcf => {
                    cpu.model = &Target.x86.cpu.emeraldrapids;
                    return;
                },
                0x8f => {
                    cpu.model = &Target.x86.cpu.sapphirerapids;
                    return;
                },
                0x1c, 0x26, 0x27, 0x35, 0x36 => {
                    cpu.model = &Target.x86.cpu.bonnell;
                    return;
                },
                0x37, 0x4a, 0x4d, 0x5a, 0x5d, 0x4c => {
                    cpu.model = &Target.x86.cpu.silvermont;
                    return;
                },
                0x5c, 0x5f => {
                    cpu.model = &Target.x86.cpu.goldmont;
                    return;
                },
                0x7a => {
                    cpu.model = &Target.x86.cpu.goldmont_plus;
                    return;
                },
                0x86, 0x8a, 0x96, 0x9c => {
                    cpu.model = &Target.x86.cpu.tremont;
                    return;
                },
                0xaf => {
                    cpu.model = &Target.x86.cpu.sierraforest;
                    return;
                },
                0xb6 => {
                    cpu.model = &Target.x86.cpu.grandridge;
                    return;
                },
                0xdd => {
                    cpu.model = &Target.x86.cpu.clearwaterforest;
                    return;
                },
                0x57 => {
                    cpu.model = &Target.x86.cpu.knl;
                    return;
                },
                0x85 => {
                    cpu.model = &Target.x86.cpu.knm;
                    return;
                },
                else => return, // Unknown CPU Model
            }
        },
        15 => {
            if (Target.x86.featureSetHas(cpu.features, .@"64bit")) {
                cpu.model = &Target.x86.cpu.nocona;
                return;
            }
            if (Target.x86.featureSetHas(cpu.features, .sse3)) {
                cpu.model = &Target.x86.cpu.prescott;
                return;
            }
            cpu.model = &Target.x86.cpu.pentium4;
            return;
        },
        else => return, // Unknown CPU Model
    }
}

fn detectAMDProcessor(features: Target.Cpu.Feature.Set, family: u32, model: u32) ?*const Target.Cpu.Model {
    return switch (family) {
        4 => &Target.x86.cpu.i486,
        5 => switch (model) {
            6, 7 => &Target.x86.cpu.k6,
            8 => &Target.x86.cpu.k6_2,
            9, 13 => &Target.x86.cpu.k6_3,
            10 => &Target.x86.cpu.geode,
            else => &Target.x86.cpu.pentium,
        },
        6 => if (Target.x86.featureSetHas(features, .sse))
            &Target.x86.cpu.athlon_xp
        else
            &Target.x86.cpu.athlon,
        15 => if (Target.x86.featureSetHas(features, .sse3))
            &Target.x86.cpu.k8_sse3
        else
            &Target.x86.cpu.k8,
        16, 18 => &Target.x86.cpu.amdfam10,
        20 => &Target.x86.cpu.btver1,
        21 => switch (model) {
            0x60...0x7f => &Target.x86.cpu.bdver4,
            0x30...0x3f => &Target.x86.cpu.bdver3,
            0x02, 0x10...0x1f => &Target.x86.cpu.bdver2,
            else => &Target.x86.cpu.bdver1,
        },
        22 => &Target.x86.cpu.btver2,
        23 => switch (model) {
            0x30...0x3f, 0x47, 0x60...0x6f, 0x70...0x7f, 0x84...0x87, 0x90...0x9f, 0xa0...0xaf => &Target.x86.cpu.znver2,
            else => &Target.x86.cpu.znver1,
        },
        25 => switch (model) {
            0x10...0x1f, 0x60...0x6f, 0x70...0x7f, 0xa0...0xaf => &Target.x86.cpu.znver4,
            else => &Target.x86.cpu.znver3,
        },
        26 => &Target.x86.cpu.znver5,
        else => null,
    };
}

fn detectNativeFeatures(cpu: *Target.Cpu, os_tag: Target.Os.Tag) void {
    var leaf = cpuid(0, 0);

    const max_level = leaf.eax;

    leaf = cpuid(1, 0);

    setFeature(cpu, .sse3, bit(leaf.ecx, 0));
    setFeature(cpu, .pclmul, bit(leaf.ecx, 1));
    setFeature(cpu, .ssse3, bit(leaf.ecx, 9));
    setFeature(cpu, .cx16, bit(leaf.ecx, 13));
    setFeature(cpu, .sse4_1, bit(leaf.ecx, 19));
    setFeature(cpu, .sse4_2, bit(leaf.ecx, 20));
    setFeature(cpu, .movbe, bit(leaf.ecx, 22));
    setFeature(cpu, .popcnt, bit(leaf.ecx, 23));
    setFeature(cpu, .aes, bit(leaf.ecx, 25));
    setFeature(cpu, .rdrnd, bit(leaf.ecx, 30));

    setFeature(cpu, .cx8, bit(leaf.edx, 8));
    setFeature(cpu, .cmov, bit(leaf.edx, 15));
    setFeature(cpu, .mmx, bit(leaf.edx, 23));
    setFeature(cpu, .fxsr, bit(leaf.edx, 24));
    setFeature(cpu, .sse, bit(leaf.edx, 25));
    setFeature(cpu, .sse2, bit(leaf.edx, 26));

    const has_xsave = bit(leaf.ecx, 27);
    const has_avx = bit(leaf.ecx, 28);

    // Make sure not to call xgetbv if xsave is not supported
    const xcr0: Xcr0 = if (has_xsave and has_avx) @bitCast(getXCR0()) else @bitCast(@as(u32, 0));

    const has_avx_save = xcr0.sse and xcr0.avx;

    // LLVM approaches avx512_save by hardcoding it to true on Darwin,
    // because the kernel saves the context even if the bit is not set.
    // https://github.com/llvm/llvm-project/blob/bca373f73fc82728a8335e7d6cd164e8747139ec/llvm/lib/Support/Host.cpp#L1378
    //
    // Google approaches this by using a different series of checks and flags,
    // and this may report the feature more accurately on a technically correct
    // but ultimately less useful level.
    // https://github.com/google/cpu_features/blob/b5c271c53759b2b15ff91df19bd0b32f2966e275/src/cpuinfo_x86.c#L113
    // (called from https://github.com/google/cpu_features/blob/b5c271c53759b2b15ff91df19bd0b32f2966e275/src/cpuinfo_x86.c#L1052)
    //
    // Right now, we use LLVM's approach, because even if the target doesn't support
    // the feature, the kernel should provide the same functionality transparently,
    // so the implementation details don't make a difference.
    // That said, this flag impacts other CPU features' availability,
    // so until we can verify that this doesn't come with side affects,
    // we'll say TODO verify this.

    // Darwin lazily saves the AVX512 context on first use: trust that the OS will
    // save the AVX512 context if we use AVX512 instructions, even if the bit is not
    // set right now.
    const has_avx512_save = if (os_tag.isDarwin())
        true
    else
        xcr0.zmm_hi256 and xcr0.hi16_zmm;

    // AMX requires additional context to be saved by the OS.
    const has_amx_save = xcr0.xtilecfg and xcr0.xtiledata;

    setFeature(cpu, .avx, has_avx_save);
    setFeature(cpu, .fma, bit(leaf.ecx, 12) and has_avx_save);
    // Only enable XSAVE if OS has enabled support for saving YMM state.
    setFeature(cpu, .xsave, bit(leaf.ecx, 26) and has_avx_save);
    setFeature(cpu, .f16c, bit(leaf.ecx, 29) and has_avx_save);

    leaf = cpuid(0x80000000, 0);
    const max_ext_level = leaf.eax;

    if (max_ext_level >= 0x80000001) {
        leaf = cpuid(0x80000001, 0);

        setFeature(cpu, .sahf, bit(leaf.ecx, 0));
        setFeature(cpu, .lzcnt, bit(leaf.ecx, 5));
        setFeature(cpu, .sse4a, bit(leaf.ecx, 6));
        setFeature(cpu, .prfchw, bit(leaf.ecx, 8));
        setFeature(cpu, .xop, bit(leaf.ecx, 11) and has_avx_save);
        setFeature(cpu, .lwp, bit(leaf.ecx, 15));
        setFeature(cpu, .fma4, bit(leaf.ecx, 16) and has_avx_save);
        setFeature(cpu, .tbm, bit(leaf.ecx, 21));
        setFeature(cpu, .mwaitx, bit(leaf.ecx, 29));

        setFeature(cpu, .@"64bit", bit(leaf.edx, 29));
    } else {
        for ([_]Target.x86.Feature{
            .sahf,
            .lzcnt,
            .sse4a,
            .prfchw,
            .xop,
            .lwp,
            .fma4,
            .tbm,
            .mwaitx,

            .@"64bit",
        }) |feat| {
            setFeature(cpu, feat, false);
        }
    }

    // Misc. memory-related features.
    if (max_ext_level >= 0x80000008) {
        leaf = cpuid(0x80000008, 0);

        setFeature(cpu, .clzero, bit(leaf.ebx, 0));
        setFeature(cpu, .rdpru, bit(leaf.ebx, 4));
        setFeature(cpu, .wbnoinvd, bit(leaf.ebx, 9));
    } else {
        for ([_]Target.x86.Feature{
            .clzero,
            .rdpru,
            .wbnoinvd,
        }) |feat| {
            setFeature(cpu, feat, false);
        }
    }

    if (max_level >= 0x7) {
        leaf = cpuid(0x7, 0);

        setFeature(cpu, .fsgsbase, bit(leaf.ebx, 0));
        setFeature(cpu, .sgx, bit(leaf.ebx, 2));
        setFeature(cpu, .bmi, bit(leaf.ebx, 3));
        // AVX2 is only supported if we have the OS save support from AVX.
        setFeature(cpu, .avx2, bit(leaf.ebx, 5) and has_avx_save);
        setFeature(cpu, .smep, bit(leaf.ebx, 7));
        setFeature(cpu, .bmi2, bit(leaf.ebx, 8));
        setFeature(cpu, .invpcid, bit(leaf.ebx, 10));
        setFeature(cpu, .rtm, bit(leaf.ebx, 11));
        // AVX512 is only supported if the OS supports the context save for it.
        setFeature(cpu, .avx512f, bit(leaf.ebx, 16) and has_avx512_save);
        setFeature(cpu, .evex512, bit(leaf.ebx, 16) and has_avx512_save);
        setFeature(cpu, .avx512dq, bit(leaf.ebx, 17) and has_avx512_save);
        setFeature(cpu, .rdseed, bit(leaf.ebx, 18));
        setFeature(cpu, .adx, bit(leaf.ebx, 19));
        setFeature(cpu, .smap, bit(leaf.ebx, 20));
        setFeature(cpu, .avx512ifma, bit(leaf.ebx, 21) and has_avx512_save);
        setFeature(cpu, .clflushopt, bit(leaf.ebx, 23));
        setFeature(cpu, .clwb, bit(leaf.ebx, 24));
        setFeature(cpu, .avx512pf, bit(leaf.ebx, 26) and has_avx512_save);
        setFeature(cpu, .avx512er, bit(leaf.ebx, 27) and has_avx512_save);
        setFeature(cpu, .avx512cd, bit(leaf.ebx, 28) and has_avx512_save);
        setFeature(cpu, .sha, bit(leaf.ebx, 29));
        setFeature(cpu, .avx512bw, bit(leaf.ebx, 30) and has_avx512_save);
        setFeature(cpu, .avx512vl, bit(leaf.ebx, 31) and has_avx512_save);

        setFeature(cpu, .prefetchwt1, bit(leaf.ecx, 0));
        setFeature(cpu, .avx512vbmi, bit(leaf.ecx, 1) and has_avx512_save);
        setFeature(cpu, .pku, bit(leaf.ecx, 4));
        setFeature(cpu, .waitpkg, bit(leaf.ecx, 5));
        setFeature(cpu, .avx512vbmi2, bit(leaf.ecx, 6) and has_avx512_save);
        setFeature(cpu, .shstk, bit(leaf.ecx, 7));
        setFeature(cpu, .gfni, bit(leaf.ecx, 8));
        setFeature(cpu, .vaes, bit(leaf.ecx, 9) and has_avx_save);
        setFeature(cpu, .vpclmulqdq, bit(leaf.ecx, 10) and has_avx_save);
        setFeature(cpu, .avx512vnni, bit(leaf.ecx, 11) and has_avx512_save);
        setFeature(cpu, .avx512bitalg, bit(leaf.ecx, 12) and has_avx512_save);
        setFeature(cpu, .avx512vpopcntdq, bit(leaf.ecx, 14) and has_avx512_save);
        setFeature(cpu, .rdpid, bit(leaf.ecx, 22));
        setFeature(cpu, .kl, bit(leaf.ecx, 23));
        setFeature(cpu, .cldemote, bit(leaf.ecx, 25));
        setFeature(cpu, .movdiri, bit(leaf.ecx, 27));
        setFeature(cpu, .movdir64b, bit(leaf.ecx, 28));
        setFeature(cpu, .enqcmd, bit(leaf.ecx, 29));

        // There are two CPUID leafs which information associated with the pconfig
        // instruction:
        // EAX=0x7, ECX=0x0 indicates the availability of the instruction (via the 18th
        // bit of EDX), while the EAX=0x1b leaf returns information on the
        // availability of specific pconfig leafs.
        // The target feature here only refers to the the first of these two.
        // Users might need to check for the availability of specific pconfig
        // leaves using cpuid, since that information is ignored while
        // detecting features using the "-march=native" flag.
        // For more info, see X86 ISA docs.
        setFeature(cpu, .uintr, bit(leaf.edx, 5));
        setFeature(cpu, .avx512vp2intersect, bit(leaf.edx, 8) and has_avx512_save);
        setFeature(cpu, .serialize, bit(leaf.edx, 14));
        setFeature(cpu, .tsxldtrk, bit(leaf.edx, 16));
        setFeature(cpu, .pconfig, bit(leaf.edx, 18));
        setFeature(cpu, .amx_bf16, bit(leaf.edx, 22) and has_amx_save);
        setFeature(cpu, .avx512fp16, bit(leaf.edx, 23) and has_avx512_save);
        setFeature(cpu, .amx_tile, bit(leaf.edx, 24) and has_amx_save);
        setFeature(cpu, .amx_int8, bit(leaf.edx, 25) and has_amx_save);

        if (leaf.eax >= 1) {
            leaf = cpuid(0x7, 0x1);

            setFeature(cpu, .sha512, bit(leaf.eax, 0));
            setFeature(cpu, .sm3, bit(leaf.eax, 1));
            setFeature(cpu, .sm4, bit(leaf.eax, 2));
            setFeature(cpu, .raoint, bit(leaf.eax, 3));
            setFeature(cpu, .avxvnni, bit(leaf.eax, 4) and has_avx_save);
            setFeature(cpu, .avx512bf16, bit(leaf.eax, 5) and has_avx512_save);
            setFeature(cpu, .cmpccxadd, bit(leaf.eax, 7));
            setFeature(cpu, .amx_fp16, bit(leaf.eax, 21) and has_amx_save);
            setFeature(cpu, .hreset, bit(leaf.eax, 22));
            setFeature(cpu, .avxifma, bit(leaf.eax, 23) and has_avx_save);

            setFeature(cpu, .avxvnniint8, bit(leaf.edx, 4) and has_avx_save);
            setFeature(cpu, .avxneconvert, bit(leaf.edx, 5) and has_avx_save);
            setFeature(cpu, .amx_complex, bit(leaf.edx, 8) and has_amx_save);
            setFeature(cpu, .avxvnniint16, bit(leaf.edx, 10) and has_avx_save);
            setFeature(cpu, .prefetchi, bit(leaf.edx, 14));
            setFeature(cpu, .usermsr, bit(leaf.edx, 15));
            setFeature(cpu, .avx10_1_256, bit(leaf.edx, 19));
            // APX
            setFeature(cpu, .egpr, bit(leaf.edx, 21));
            setFeature(cpu, .push2pop2, bit(leaf.edx, 21));
            setFeature(cpu, .ppx, bit(leaf.edx, 21));
            setFeature(cpu, .ndd, bit(leaf.edx, 21));
            setFeature(cpu, .ccmp, bit(leaf.edx, 21));
            setFeature(cpu, .cf, bit(leaf.edx, 21));
        } else {
            for ([_]Target.x86.Feature{
                .sha512,
                .sm3,
                .sm4,
                .raoint,
                .avxvnni,
                .avx512bf16,
                .cmpccxadd,
                .amx_fp16,
                .hreset,
                .avxifma,

                .avxvnniint8,
                .avxneconvert,
                .amx_complex,
                .avxvnniint16,
                .prefetchi,
                .usermsr,
                .avx10_1_256,
                .egpr,
                .push2pop2,
                .ppx,
                .ndd,
                .ccmp,
                .cf,
            }) |feat| {
                setFeature(cpu, feat, false);
            }
        }
    } else {
        for ([_]Target.x86.Feature{
            .fsgsbase,
            .sgx,
            .bmi,
            .avx2,
            .smep,
            .bmi2,
            .invpcid,
            .rtm,
            .avx512f,
            .evex512,
            .avx512dq,
            .rdseed,
            .adx,
            .smap,
            .avx512ifma,
            .clflushopt,
            .clwb,
            .avx512pf,
            .avx512er,
            .avx512cd,
            .sha,
            .avx512bw,
            .avx512vl,

            .prefetchwt1,
            .avx512vbmi,
            .pku,
            .waitpkg,
            .avx512vbmi2,
            .shstk,
            .gfni,
            .vaes,
            .vpclmulqdq,
            .avx512vnni,
            .avx512bitalg,
            .avx512vpopcntdq,
            .rdpid,
            .kl,
            .cldemote,
            .movdiri,
            .movdir64b,
            .enqcmd,

            .uintr,
            .avx512vp2intersect,
            .serialize,
            .tsxldtrk,
            .pconfig,
            .amx_bf16,
            .avx512fp16,
            .amx_tile,
            .amx_int8,

            .sha512,
            .sm3,
            .sm4,
            .raoint,
            .avxvnni,
            .avx512bf16,
            .cmpccxadd,
            .amx_fp16,
            .hreset,
            .avxifma,

            .avxvnniint8,
            .avxneconvert,
            .amx_complex,
            .avxvnniint16,
            .prefetchi,
            .usermsr,
            .avx10_1_256,
            .egpr,
            .push2pop2,
            .ppx,
            .ndd,
            .ccmp,
            .cf,
        }) |feat| {
            setFeature(cpu, feat, false);
        }
    }

    if (max_level >= 0xD and has_avx_save) {
        leaf = cpuid(0xD, 0x1);

        // Only enable XSAVE if OS has enabled support for saving YMM state.
        setFeature(cpu, .xsaveopt, bit(leaf.eax, 0));
        setFeature(cpu, .xsavec, bit(leaf.eax, 1));
        setFeature(cpu, .xsaves, bit(leaf.eax, 3));
    } else {
        for ([_]Target.x86.Feature{
            .xsaveopt,
            .xsavec,
            .xsaves,
        }) |feat| {
            setFeature(cpu, feat, false);
        }
    }

    if (max_level >= 0x14) {
        leaf = cpuid(0x14, 0);

        setFeature(cpu, .ptwrite, bit(leaf.ebx, 4));
    } else {
        for ([_]Target.x86.Feature{
            .ptwrite,
        }) |feat| {
            setFeature(cpu, feat, false);
        }
    }

    if (max_level >= 0x19) {
        leaf = cpuid(0x19, 0);

        setFeature(cpu, .widekl, bit(leaf.ebx, 2));
    } else {
        for ([_]Target.x86.Feature{
            .widekl,
        }) |feat| {
            setFeature(cpu, feat, false);
        }
    }

    if (max_level >= 0x24) {
        leaf = cpuid(0x24, 0);

        setFeature(cpu, .avx10_1_512, bit(leaf.ebx, 18));
    } else {
        for ([_]Target.x86.Feature{
            .avx10_1_512,
        }) |feat| {
            setFeature(cpu, feat, false);
        }
    }
}

const CpuidLeaf = packed struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

/// This is a workaround for the C backend until zig has the ability to put
/// C code in inline assembly.
extern fn zig_x86_cpuid(leaf_id: u32, subid: u32, eax: *u32, ebx: *u32, ecx: *u32, edx: *u32) callconv(.c) void;

fn cpuid(leaf_id: u32, subid: u32) CpuidLeaf {
    // valid for both x86 and x86_64
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    if (builtin.zig_backend == .stage2_c) {
        zig_x86_cpuid(leaf_id, subid, &eax, &ebx, &ecx, &edx);
    } else {
        asm volatile ("cpuid"
            : [_] "={eax}" (eax),
              [_] "={ebx}" (ebx),
              [_] "={ecx}" (ecx),
              [_] "={edx}" (edx),
            : [_] "{eax}" (leaf_id),
              [_] "{ecx}" (subid),
        );
    }

    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

/// This is a workaround for the C backend until zig has the ability to put
/// C code in inline assembly.
extern fn zig_x86_get_xcr0() callconv(.c) u32;

// Read control register 0 (XCR0). Used to detect features such as AVX.
fn getXCR0() u32 {
    if (builtin.zig_backend == .stage2_c) {
        return zig_x86_get_xcr0();
    }

    return asm volatile (
        \\ xor %%ecx, %%ecx
        \\ xgetbv
        : [_] "={eax}" (-> u32),
        :
        : "edx", "ecx"
    );
}
pub const ArchOsAbi = struct {
    arch: std.Target.Cpu.Arch,
    os: std.Target.Os.Tag,
    abi: std.Target.Abi,
    os_ver: ?std.SemanticVersion = null,

    /// Minimum glibc version that provides support for the arch/OS when ABI is GNU. Note that Zig
    /// can only target glibc 2.2.5+, so `null` means the minimum is older than that.
    glibc_min: ?std.SemanticVersion = null,
    /// Override for `glibcRuntimeTriple` when glibc has an unusual directory name for the target.
    glibc_triple: ?[]const u8 = null,
};

pub const available_libcs = [_]ArchOsAbi{
    .{ .arch = .arc, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 4, .minor = 2, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 32, .patch = 0 } },
    .{ .arch = .arm, .os = .linux, .abi = .gnueabi, .os_ver = .{ .major = 2, .minor = 1, .patch = 0 } },
    .{ .arch = .arm, .os = .linux, .abi = .gnueabihf, .os_ver = .{ .major = 2, .minor = 1, .patch = 0 } },
    .{ .arch = .arm, .os = .linux, .abi = .musleabi, .os_ver = .{ .major = 2, .minor = 1, .patch = 0 } },
    .{ .arch = .arm, .os = .linux, .abi = .musleabihf, .os_ver = .{ .major = 2, .minor = 1, .patch = 0 } },
    .{ .arch = .armeb, .os = .linux, .abi = .gnueabi, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .armeb, .os = .linux, .abi = .gnueabihf, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .armeb, .os = .linux, .abi = .musleabi, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .armeb, .os = .linux, .abi = .musleabihf, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .thumb, .os = .linux, .abi = .musleabi, .os_ver = .{ .major = 2, .minor = 1, .patch = 0 } },
    .{ .arch = .thumb, .os = .linux, .abi = .musleabihf, .os_ver = .{ .major = 2, .minor = 1, .patch = 0 } },
    .{ .arch = .thumb, .os = .windows, .abi = .gnu },
    .{ .arch = .thumbeb, .os = .linux, .abi = .musleabi, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .thumbeb, .os = .linux, .abi = .musleabihf, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .aarch64, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 3, .minor = 7, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 17, .patch = 0 } },
    .{ .arch = .aarch64, .os = .linux, .abi = .musl, .os_ver = .{ .major = 3, .minor = 7, .patch = 0 } },
    .{ .arch = .aarch64, .os = .macos, .abi = .none, .os_ver = .{ .major = 11, .minor = 0, .patch = 0 } },
    .{ .arch = .aarch64, .os = .windows, .abi = .gnu },
    .{ .arch = .aarch64_be, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 3, .minor = 13, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 17, .patch = 0 } },
    .{ .arch = .aarch64_be, .os = .linux, .abi = .musl, .os_ver = .{ .major = 3, .minor = 13, .patch = 0 } },
    .{ .arch = .csky, .os = .linux, .abi = .gnueabi, .os_ver = .{ .major = 4, .minor = 20, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 29, .patch = 0 }, .glibc_triple = "csky-linux-gnuabiv2-soft" },
    .{ .arch = .csky, .os = .linux, .abi = .gnueabihf, .os_ver = .{ .major = 4, .minor = 20, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 29, .patch = 0 }, .glibc_triple = "csky-linux-gnuabiv2" },
    .{ .arch = .hexagon, .os = .linux, .abi = .musl, .os_ver = .{ .major = 3, .minor = 2, .patch = 102 } },
    .{ .arch = .loongarch64, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 5, .minor = 19, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 36, .patch = 0 }, .glibc_triple = "loongarch64-linux-gnu-lp64d" },
    .{ .arch = .loongarch64, .os = .linux, .abi = .gnusf, .os_ver = .{ .major = 5, .minor = 19, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 36, .patch = 0 }, .glibc_triple = "loongarch64-linux-gnu-lp64s" },
    .{ .arch = .loongarch64, .os = .linux, .abi = .musl, .os_ver = .{ .major = 5, .minor = 19, .patch = 0 } },
    .{ .arch = .loongarch64, .os = .linux, .abi = .muslsf, .os_ver = .{ .major = 5, .minor = 19, .patch = 0 } },
    .{ .arch = .m68k, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 1, .minor = 3, .patch = 94 } },
    .{ .arch = .m68k, .os = .linux, .abi = .musl, .os_ver = .{ .major = 1, .minor = 3, .patch = 94 } },
    .{ .arch = .mips, .os = .linux, .abi = .gnueabi, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 }, .glibc_triple = "mips-linux-gnu-soft" },
    .{ .arch = .mips, .os = .linux, .abi = .gnueabihf, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 }, .glibc_triple = "mips-linux-gnu" },
    .{ .arch = .mips, .os = .linux, .abi = .musleabi, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 } },
    .{ .arch = .mips, .os = .linux, .abi = .musleabihf, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 } },
    .{ .arch = .mipsel, .os = .linux, .abi = .gnueabi, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 }, .glibc_triple = "mipsel-linux-gnu-soft" },
    .{ .arch = .mipsel, .os = .linux, .abi = .gnueabihf, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 }, .glibc_triple = "mipsel-linux-gnu" },
    .{ .arch = .mipsel, .os = .linux, .abi = .musleabi, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 } },
    .{ .arch = .mipsel, .os = .linux, .abi = .musleabihf, .os_ver = .{ .major = 1, .minor = 1, .patch = 82 } },
    .{ .arch = .mips64, .os = .linux, .abi = .gnuabi64, .os_ver = .{ .major = 2, .minor = 3, .patch = 48 }, .glibc_triple = "mips64-linux-gnu-n64" },
    .{ .arch = .mips64, .os = .linux, .abi = .gnuabin32, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 }, .glibc_triple = "mips64-linux-gnu-n32" },
    .{ .arch = .mips64, .os = .linux, .abi = .muslabi64, .os_ver = .{ .major = 2, .minor = 3, .patch = 48 } },
    .{ .arch = .mips64, .os = .linux, .abi = .muslabin32, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .mips64el, .os = .linux, .abi = .gnuabi64, .os_ver = .{ .major = 2, .minor = 3, .patch = 48 }, .glibc_triple = "mips64el-linux-gnu-n64" },
    .{ .arch = .mips64el, .os = .linux, .abi = .gnuabin32, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 }, .glibc_triple = "mips64el-linux-gnu-n32" },
    .{ .arch = .mips64el, .os = .linux, .abi = .muslabi64, .os_ver = .{ .major = 2, .minor = 3, .patch = 48 } },
    .{ .arch = .mips64el, .os = .linux, .abi = .muslabin32, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .powerpc, .os = .linux, .abi = .gnueabi, .os_ver = .{ .major = 1, .minor = 3, .patch = 45 }, .glibc_triple = "powerpc-linux-gnu-soft" },
    .{ .arch = .powerpc, .os = .linux, .abi = .gnueabihf, .os_ver = .{ .major = 1, .minor = 3, .patch = 45 }, .glibc_triple = "powerpc-linux-gnu" },
    .{ .arch = .powerpc, .os = .linux, .abi = .musleabi, .os_ver = .{ .major = 1, .minor = 3, .patch = 45 } },
    .{ .arch = .powerpc, .os = .linux, .abi = .musleabihf, .os_ver = .{ .major = 1, .minor = 3, .patch = 45 } },
    .{ .arch = .powerpc64, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .powerpc64, .os = .linux, .abi = .musl, .os_ver = .{ .major = 2, .minor = 6, .patch = 0 } },
    .{ .arch = .powerpc64le, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 3, .minor = 14, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 19, .patch = 0 } },
    .{ .arch = .powerpc64le, .os = .linux, .abi = .musl, .os_ver = .{ .major = 3, .minor = 14, .patch = 0 } },
    .{ .arch = .riscv32, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 4, .minor = 15, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 33, .patch = 0 }, .glibc_triple = "riscv32-linux-gnu-rv32imafdc-ilp32d" },
    .{ .arch = .riscv32, .os = .linux, .abi = .musl, .os_ver = .{ .major = 4, .minor = 15, .patch = 0 } },
    .{ .arch = .riscv64, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 4, .minor = 15, .patch = 0 }, .glibc_min = .{ .major = 2, .minor = 27, .patch = 0 }, .glibc_triple = "riscv64-linux-gnu-rv64imafdc-lp64d" },
    .{ .arch = .riscv64, .os = .linux, .abi = .musl, .os_ver = .{ .major = 4, .minor = 15, .patch = 0 } },
    .{ .arch = .s390x, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 2, .minor = 4, .patch = 2 } },
    .{ .arch = .s390x, .os = .linux, .abi = .musl, .os_ver = .{ .major = 2, .minor = 4, .patch = 2 } },
    .{ .arch = .sparc, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 2, .minor = 1, .patch = 19 }, .glibc_triple = "sparcv9-linux-gnu" },
    .{ .arch = .sparc64, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 2, .minor = 1, .patch = 19 } },
    .{ .arch = .wasm32, .os = .wasi, .abi = .musl },
    .{ .arch = .x86, .os = .linux, .abi = .gnu, .glibc_triple = "i686-linux-gnu" },
    .{ .arch = .x86, .os = .linux, .abi = .musl },
    .{ .arch = .x86, .os = .windows, .abi = .gnu },
    .{ .arch = .x86_64, .os = .linux, .abi = .gnu, .os_ver = .{ .major = 2, .minor = 6, .patch = 4 } },
    .{ .arch = .x86_64, .os = .linux, .abi = .gnux32, .os_ver = .{ .major = 3, .minor = 4, .patch = 0 }, .glibc_triple = "x86_64-linux-gnu-x32" },
    .{ .arch = .x86_64, .os = .linux, .abi = .musl, .os_ver = .{ .major = 2, .minor = 6, .patch = 4 } },
    .{ .arch = .x86_64, .os = .linux, .abi = .muslx32, .os_ver = .{ .major = 3, .minor = 4, .patch = 0 } },
    .{ .arch = .x86_64, .os = .macos, .abi = .none, .os_ver = .{ .major = 10, .minor = 7, .patch = 0 } },
    .{ .arch = .x86_64, .os = .windows, .abi = .gnu },
};

pub fn canBuildLibC(target: std.Target) bool {
    for (available_libcs) |libc| {
        if (target.cpu.arch == libc.arch and target.os.tag == libc.os and target.abi == libc.abi) {
            if (libc.os_ver) |libc_os_ver| {
                if (switch (target.os.versionRange()) {
                    .semver => |v| v,
                    .linux => |v| v.range,
                    else => null,
                }) |ver| {
                    if (ver.min.order(libc_os_ver) == .lt) return false;
                }
            }
            if (libc.glibc_min) |glibc_min| {
                if (target.os.versionRange().gnuLibCVersion().?.order(glibc_min) == .lt) return false;
            }
            return true;
        }
    }
    return false;
}

/// Returns the subdirectory triple to be used to find the correct glibc for the given `arch`, `os`,
/// and `abi` in an installation directory created by glibc's `build-many-glibcs.py` script.
///
/// `os` must be `.linux` or `.hurd`. `abi` must be a GNU ABI, i.e. `.isGnu()`.
pub fn glibcRuntimeTriple(
    allocator: Allocator,
    arch: std.Target.Cpu.Arch,
    os: std.Target.Os.Tag,
    abi: std.Target.Abi,
) Allocator.Error![]const u8 {
    assert(abi.isGnu());

    for (available_libcs) |libc| {
        if (libc.arch == arch and libc.os == os and libc.abi == abi) {
            if (libc.glibc_triple) |triple| return allocator.dupe(u8, triple);
        }
    }

    return switch (os) {
        .hurd => std.Target.hurdTupleSimple(allocator, arch, abi),
        .linux => std.Target.linuxTripleSimple(allocator, arch, os, abi),
        else => unreachable,
    };
}

pub fn osArchName(target: std.Target) [:0]const u8 {
    return switch (target.os.tag) {
        .linux => switch (target.cpu.arch) {
            .arm, .armeb, .thumb, .thumbeb => "arm",
            .aarch64, .aarch64_be => "aarch64",
            .loongarch32, .loongarch64 => "loongarch",
            .mips, .mipsel, .mips64, .mips64el => "mips",
            .powerpc, .powerpcle, .powerpc64, .powerpc64le => "powerpc",
            .riscv32, .riscv64 => "riscv",
            .sparc, .sparc64 => "sparc",
            .x86, .x86_64 => "x86",
            else => @tagName(target.cpu.arch),
        },
        else => @tagName(target.cpu.arch),
    };
}

pub fn muslArchName(arch: std.Target.Cpu.Arch, abi: std.Target.Abi) [:0]const u8 {
    return switch (abi) {
        .muslabin32 => "mipsn32",
        .muslx32 => "x32",
        else => switch (arch) {
            .arm, .armeb, .thumb, .thumbeb => "arm",
            .aarch64, .aarch64_be => "aarch64",
            .hexagon => "hexagon",
            .loongarch64 => "loongarch64",
            .m68k => "m68k",
            .mips, .mipsel => "mips",
            .mips64el, .mips64 => "mips64",
            .powerpc => "powerpc",
            .powerpc64, .powerpc64le => "powerpc64",
            .riscv32 => "riscv32",
            .riscv64 => "riscv64",
            .s390x => "s390x",
            .wasm32, .wasm64 => "wasm",
            .x86 => "i386",
            .x86_64 => "x86_64",
            else => unreachable,
        },
    };
}

pub fn muslArchNameHeaders(arch: std.Target.Cpu.Arch) [:0]const u8 {
    return switch (arch) {
        .x86 => "x86",
        else => muslArchName(arch, .musl),
    };
}

pub fn muslAbiNameHeaders(abi: std.Target.Abi) [:0]const u8 {
    return switch (abi) {
        .muslabin32 => "muslabin32",
        .muslx32 => "muslx32",
        else => "musl",
    };
}

pub fn isLibCLibName(target: std.Target, name: []const u8) bool {
    const ignore_case = target.os.tag.isDarwin() or target.os.tag == .windows;

    if (eqlIgnoreCase(ignore_case, name, "c"))
        return true;

    if (target.isMinGW()) {
        if (eqlIgnoreCase(ignore_case, name, "adsiid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "amstrmid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "bits"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "delayimp"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dloadhelper"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dmoguids"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dxerr8"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dxerr9"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dxguid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "ksguid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "largeint"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "m"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "mfuuid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "mingw32"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "mingwex"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "mingwthrd"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "moldname"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "msvcrt-os"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "portabledeviceguids"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "pthread"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "scrnsave"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "scrnsavw"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "strmiids"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "uuid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "wbemuuid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "wiaguid"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "winpthread"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "wmcodecdspuuid"))
            return true;

        return false;
    }

    if (target.abi.isGnu() or target.abi.isMusl()) {
        if (eqlIgnoreCase(ignore_case, name, "m"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "rt"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "pthread"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "util"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "resolv"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dl"))
            return true;
    }

    if (target.abi.isMusl()) {
        if (eqlIgnoreCase(ignore_case, name, "crypt"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "xnet"))
            return true;

        if (target.os.tag == .wasi) {
            if (eqlIgnoreCase(ignore_case, name, "wasi-emulated-getpid"))
                return true;
            if (eqlIgnoreCase(ignore_case, name, "wasi-emulated-mman"))
                return true;
            if (eqlIgnoreCase(ignore_case, name, "wasi-emulated-process-clocks"))
                return true;
            if (eqlIgnoreCase(ignore_case, name, "wasi-emulated-signal"))
                return true;
        }
    }

    if (target.os.tag.isDarwin()) {
        if (eqlIgnoreCase(ignore_case, name, "System"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dbm"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "dl"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "info"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "m"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "poll"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "proc"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "pthread"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "rpcsvc"))
            return true;
    }

    if (target.os.isAtLeast(.macos, .{ .major = 10, .minor = 8, .patch = 0 }) orelse false) {
        if (eqlIgnoreCase(ignore_case, name, "mx"))
            return true;
    }

    if (target.os.tag == .haiku) {
        if (eqlIgnoreCase(ignore_case, name, "root"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "network"))
            return true;
    }

    if (target.os.tag == .serenity) {
        if (eqlIgnoreCase(ignore_case, name, "dl"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "m"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "pthread"))
            return true;
        if (eqlIgnoreCase(ignore_case, name, "ssp"))
            return true;
    }

    return false;
}

pub fn isLibCxxLibName(target: std.Target, name: []const u8) bool {
    const ignore_case = target.os.tag.isDarwin() or target.os.tag == .windows;

    return eqlIgnoreCase(ignore_case, name, "c++") or
        eqlIgnoreCase(ignore_case, name, "stdc++") or
        eqlIgnoreCase(ignore_case, name, "c++abi") or
        eqlIgnoreCase(ignore_case, name, "supc++");
}

fn eqlIgnoreCase(ignore_case: bool, a: []const u8, b: []const u8) bool {
    if (ignore_case) {
        return std.ascii.eqlIgnoreCase(a, b);
    } else {
        return std.mem.eql(u8, a, b);
    }
}

pub fn intByteSize(target: std.Target, bits: u16) u19 {
    return std.mem.alignForward(u19, @intCast((@as(u17, bits) + 7) / 8), intAlignment(target, bits));
}

pub fn intAlignment(target: std.Target, bits: u16) u16 {
    return switch (target.cpu.arch) {
        .x86 => switch (bits) {
            0 => 0,
            1...8 => 1,
            9...16 => 2,
            17...32 => 4,
            33...64 => switch (target.os.tag) {
                .uefi, .windows => 8,
                else => 4,
            },
            else => 16,
        },
        .x86_64 => switch (bits) {
            0 => 0,
            1...8 => 1,
            9...16 => 2,
            17...32 => 4,
            33...64 => 8,
            else => 16,
        },
        else => return @min(
            std.math.ceilPowerOfTwoPromote(u16, @as(u16, @intCast((@as(u17, bits) + 7) / 8))),
            target.cMaxIntAlignment(),
        ),
    };
}

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const std = @import("../std.zig");

pub const Token = struct {
    tag: Tag,
    loc: Loc,

    pub const Loc = struct {
        start: usize,
        end: usize,
    };

    pub const keywords = std.StaticStringMap(Tag).initComptime(.{
        .{ "addrspace", .keyword_addrspace },
        .{ "align", .keyword_align },
        .{ "allowzero", .keyword_allowzero },
        .{ "and", .keyword_and },
        .{ "anyframe", .keyword_anyframe },
        .{ "anytype", .keyword_anytype },
        .{ "asm", .keyword_asm },
        .{ "async", .keyword_async },
        .{ "await", .keyword_await },
        .{ "break", .keyword_break },
        .{ "callconv", .keyword_callconv },
        .{ "catch", .keyword_catch },
        .{ "comptime", .keyword_comptime },
        .{ "const", .keyword_const },
        .{ "continue", .keyword_continue },
        .{ "defer", .keyword_defer },
        .{ "else", .keyword_else },
        .{ "enum", .keyword_enum },
        .{ "errdefer", .keyword_errdefer },
        .{ "error", .keyword_error },
        .{ "export", .keyword_export },
        .{ "extern", .keyword_extern },
        .{ "fn", .keyword_fn },
        .{ "for", .keyword_for },
        .{ "if", .keyword_if },
        .{ "inline", .keyword_inline },
        .{ "noalias", .keyword_noalias },
        .{ "noinline", .keyword_noinline },
        .{ "nosuspend", .keyword_nosuspend },
        .{ "opaque", .keyword_opaque },
        .{ "or", .keyword_or },
        .{ "orelse", .keyword_orelse },
        .{ "packed", .keyword_packed },
        .{ "pub", .keyword_pub },
        .{ "resume", .keyword_resume },
        .{ "return", .keyword_return },
        .{ "linksection", .keyword_linksection },
        .{ "struct", .keyword_struct },
        .{ "suspend", .keyword_suspend },
        .{ "switch", .keyword_switch },
        .{ "test", .keyword_test },
        .{ "threadlocal", .keyword_threadlocal },
        .{ "try", .keyword_try },
        .{ "union", .keyword_union },
        .{ "unreachable", .keyword_unreachable },
        .{ "usingnamespace", .keyword_usingnamespace },
        .{ "var", .keyword_var },
        .{ "volatile", .keyword_volatile },
        .{ "while", .keyword_while },
    });

    pub fn getKeyword(bytes: []const u8) ?Tag {
        return keywords.get(bytes);
    }

    pub const Tag = enum {
        invalid,
        invalid_periodasterisks,
        identifier,
        string_literal,
        multiline_string_literal_line,
        char_literal,
        eof,
        builtin,
        bang,
        pipe,
        pipe_pipe,
        pipe_equal,
        equal,
        equal_equal,
        equal_angle_bracket_right,
        bang_equal,
        l_paren,
        r_paren,
        semicolon,
        percent,
        percent_equal,
        l_brace,
        r_brace,
        l_bracket,
        r_bracket,
        period,
        period_asterisk,
        ellipsis2,
        ellipsis3,
        caret,
        caret_equal,
        plus,
        plus_plus,
        plus_equal,
        plus_percent,
        plus_percent_equal,
        plus_pipe,
        plus_pipe_equal,
        minus,
        minus_equal,
        minus_percent,
        minus_percent_equal,
        minus_pipe,
        minus_pipe_equal,
        asterisk,
        asterisk_equal,
        asterisk_asterisk,
        asterisk_percent,
        asterisk_percent_equal,
        asterisk_pipe,
        asterisk_pipe_equal,
        arrow,
        colon,
        slash,
        slash_equal,
        comma,
        ampersand,
        ampersand_equal,
        question_mark,
        angle_bracket_left,
        angle_bracket_left_equal,
        angle_bracket_angle_bracket_left,
        angle_bracket_angle_bracket_left_equal,
        angle_bracket_angle_bracket_left_pipe,
        angle_bracket_angle_bracket_left_pipe_equal,
        angle_bracket_right,
        angle_bracket_right_equal,
        angle_bracket_angle_bracket_right,
        angle_bracket_angle_bracket_right_equal,
        tilde,
        number_literal,
        doc_comment,
        container_doc_comment,
        keyword_addrspace,
        keyword_align,
        keyword_allowzero,
        keyword_and,
        keyword_anyframe,
        keyword_anytype,
        keyword_asm,
        keyword_async,
        keyword_await,
        keyword_break,
        keyword_callconv,
        keyword_catch,
        keyword_comptime,
        keyword_const,
        keyword_continue,
        keyword_defer,
        keyword_else,
        keyword_enum,
        keyword_errdefer,
        keyword_error,
        keyword_export,
        keyword_extern,
        keyword_fn,
        keyword_for,
        keyword_if,
        keyword_inline,
        keyword_noalias,
        keyword_noinline,
        keyword_nosuspend,
        keyword_opaque,
        keyword_or,
        keyword_orelse,
        keyword_packed,
        keyword_pub,
        keyword_resume,
        keyword_return,
        keyword_linksection,
        keyword_struct,
        keyword_suspend,
        keyword_switch,
        keyword_test,
        keyword_threadlocal,
        keyword_try,
        keyword_union,
        keyword_unreachable,
        keyword_usingnamespace,
        keyword_var,
        keyword_volatile,
        keyword_while,

        pub fn lexeme(tag: Tag) ?[]const u8 {
            return switch (tag) {
                .invalid,
                .identifier,
                .string_literal,
                .multiline_string_literal_line,
                .char_literal,
                .eof,
                .builtin,
                .number_literal,
                .doc_comment,
                .container_doc_comment,
                => null,

                .invalid_periodasterisks => ".**",
                .bang => "!",
                .pipe => "|",
                .pipe_pipe => "||",
                .pipe_equal => "|=",
                .equal => "=",
                .equal_equal => "==",
                .equal_angle_bracket_right => "=>",
                .bang_equal => "!=",
                .l_paren => "(",
                .r_paren => ")",
                .semicolon => ";",
                .percent => "%",
                .percent_equal => "%=",
                .l_brace => "{",
                .r_brace => "}",
                .l_bracket => "[",
                .r_bracket => "]",
                .period => ".",
                .period_asterisk => ".*",
                .ellipsis2 => "..",
                .ellipsis3 => "...",
                .caret => "^",
                .caret_equal => "^=",
                .plus => "+",
                .plus_plus => "++",
                .plus_equal => "+=",
                .plus_percent => "+%",
                .plus_percent_equal => "+%=",
                .plus_pipe => "+|",
                .plus_pipe_equal => "+|=",
                .minus => "-",
                .minus_equal => "-=",
                .minus_percent => "-%",
                .minus_percent_equal => "-%=",
                .minus_pipe => "-|",
                .minus_pipe_equal => "-|=",
                .asterisk => "*",
                .asterisk_equal => "*=",
                .asterisk_asterisk => "**",
                .asterisk_percent => "*%",
                .asterisk_percent_equal => "*%=",
                .asterisk_pipe => "*|",
                .asterisk_pipe_equal => "*|=",
                .arrow => "->",
                .colon => ":",
                .slash => "/",
                .slash_equal => "/=",
                .comma => ",",
                .ampersand => "&",
                .ampersand_equal => "&=",
                .question_mark => "?",
                .angle_bracket_left => "<",
                .angle_bracket_left_equal => "<=",
                .angle_bracket_angle_bracket_left => "<<",
                .angle_bracket_angle_bracket_left_equal => "<<=",
                .angle_bracket_angle_bracket_left_pipe => "<<|",
                .angle_bracket_angle_bracket_left_pipe_equal => "<<|=",
                .angle_bracket_right => ">",
                .angle_bracket_right_equal => ">=",
                .angle_bracket_angle_bracket_right => ">>",
                .angle_bracket_angle_bracket_right_equal => ">>=",
                .tilde => "~",
                .keyword_addrspace => "addrspace",
                .keyword_align => "align",
                .keyword_allowzero => "allowzero",
                .keyword_and => "and",
                .keyword_anyframe => "anyframe",
                .keyword_anytype => "anytype",
                .keyword_asm => "asm",
                .keyword_async => "async",
                .keyword_await => "await",
                .keyword_break => "break",
                .keyword_callconv => "callconv",
                .keyword_catch => "catch",
                .keyword_comptime => "comptime",
                .keyword_const => "const",
                .keyword_continue => "continue",
                .keyword_defer => "defer",
                .keyword_else => "else",
                .keyword_enum => "enum",
                .keyword_errdefer => "errdefer",
                .keyword_error => "error",
                .keyword_export => "export",
                .keyword_extern => "extern",
                .keyword_fn => "fn",
                .keyword_for => "for",
                .keyword_if => "if",
                .keyword_inline => "inline",
                .keyword_noalias => "noalias",
                .keyword_noinline => "noinline",
                .keyword_nosuspend => "nosuspend",
                .keyword_opaque => "opaque",
                .keyword_or => "or",
                .keyword_orelse => "orelse",
                .keyword_packed => "packed",
                .keyword_pub => "pub",
                .keyword_resume => "resume",
                .keyword_return => "return",
                .keyword_linksection => "linksection",
                .keyword_struct => "struct",
                .keyword_suspend => "suspend",
                .keyword_switch => "switch",
                .keyword_test => "test",
                .keyword_threadlocal => "threadlocal",
                .keyword_try => "try",
                .keyword_union => "union",
                .keyword_unreachable => "unreachable",
                .keyword_usingnamespace => "usingnamespace",
                .keyword_var => "var",
                .keyword_volatile => "volatile",
                .keyword_while => "while",
            };
        }

        pub fn symbol(tag: Tag) []const u8 {
            return tag.lexeme() orelse switch (tag) {
                .invalid => "invalid token",
                .identifier => "an identifier",
                .string_literal, .multiline_string_literal_line => "a string literal",
                .char_literal => "a character literal",
                .eof => "EOF",
                .builtin => "a builtin function",
                .number_literal => "a number literal",
                .doc_comment, .container_doc_comment => "a document comment",
                else => unreachable,
            };
        }
    };
};

pub const Tokenizer = struct {
    buffer: [:0]const u8,
    index: usize,

    /// For debugging purposes.
    pub fn dump(self: *Tokenizer, token: *const Token) void {
        std.debug.print("{s} \"{s}\"\n", .{ @tagName(token.tag), self.buffer[token.loc.start..token.loc.end] });
    }

    pub fn init(buffer: [:0]const u8) Tokenizer {
        // Skip the UTF-8 BOM if present.
        return .{
            .buffer = buffer,
            .index = if (std.mem.startsWith(u8, buffer, "\xEF\xBB\xBF")) 3 else 0,
        };
    }

    const State = enum {
        start,
        expect_newline,
        identifier,
        builtin,
        string_literal,
        string_literal_backslash,
        multiline_string_literal_line,
        char_literal,
        char_literal_backslash,
        backslash,
        equal,
        bang,
        pipe,
        minus,
        minus_percent,
        minus_pipe,
        asterisk,
        asterisk_percent,
        asterisk_pipe,
        slash,
        line_comment_start,
        line_comment,
        doc_comment_start,
        doc_comment,
        int,
        int_exponent,
        int_period,
        float,
        float_exponent,
        ampersand,
        caret,
        percent,
        plus,
        plus_percent,
        plus_pipe,
        angle_bracket_left,
        angle_bracket_angle_bracket_left,
        angle_bracket_angle_bracket_left_pipe,
        angle_bracket_right,
        angle_bracket_angle_bracket_right,
        period,
        period_2,
        period_asterisk,
        saw_at_sign,
        invalid,
    };

    /// After this returns invalid, it will reset on the next newline, returning tokens starting from there.
    /// An eof token will always be returned at the end.
    pub fn next(self: *Tokenizer) Token {
        var result: Token = .{
            .tag = undefined,
            .loc = .{
                .start = self.index,
                .end = undefined,
            },
        };
        state: switch (State.start) {
            .start => switch (self.buffer[self.index]) {
                0 => {
                    if (self.index == self.buffer.len) {
                        return .{
                            .tag = .eof,
                            .loc = .{
                                .start = self.index,
                                .end = self.index,
                            },
                        };
                    } else {
                        continue :state .invalid;
                    }
                },
                ' ', '\n', '\t', '\r' => {
                    self.index += 1;
                    result.loc.start = self.index;
                    continue :state .start;
                },
                '"' => {
                    result.tag = .string_literal;
                    continue :state .string_literal;
                },
                '\'' => {
                    result.tag = .char_literal;
                    continue :state .char_literal;
                },
                'a'...'z', 'A'...'Z', '_' => {
                    result.tag = .identifier;
                    continue :state .identifier;
                },
                '@' => continue :state .saw_at_sign,
                '=' => continue :state .equal,
                '!' => continue :state .bang,
                '|' => continue :state .pipe,
                '(' => {
                    result.tag = .l_paren;
                    self.index += 1;
                },
                ')' => {
                    result.tag = .r_paren;
                    self.index += 1;
                },
                '[' => {
                    result.tag = .l_bracket;
                    self.index += 1;
                },
                ']' => {
                    result.tag = .r_bracket;
                    self.index += 1;
                },
                ';' => {
                    result.tag = .semicolon;
                    self.index += 1;
                },
                ',' => {
                    result.tag = .comma;
                    self.index += 1;
                },
                '?' => {
                    result.tag = .question_mark;
                    self.index += 1;
                },
                ':' => {
                    result.tag = .colon;
                    self.index += 1;
                },
                '%' => continue :state .percent,
                '*' => continue :state .asterisk,
                '+' => continue :state .plus,
                '<' => continue :state .angle_bracket_left,
                '>' => continue :state .angle_bracket_right,
                '^' => continue :state .caret,
                '\\' => {
                    result.tag = .multiline_string_literal_line;
                    continue :state .backslash;
                },
                '{' => {
                    result.tag = .l_brace;
                    self.index += 1;
                },
                '}' => {
                    result.tag = .r_brace;
                    self.index += 1;
                },
                '~' => {
                    result.tag = .tilde;
                    self.index += 1;
                },
                '.' => continue :state .period,
                '-' => continue :state .minus,
                '/' => continue :state .slash,
                '&' => continue :state .ampersand,
                '0'...'9' => {
                    result.tag = .number_literal;
                    self.index += 1;
                    continue :state .int;
                },
                else => continue :state .invalid,
            },

            .expect_newline => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index == self.buffer.len) {
                            result.tag = .invalid;
                        } else {
                            continue :state .invalid;
                        }
                    },
                    '\n' => {
                        self.index += 1;
                        result.loc.start = self.index;
                        continue :state .start;
                    },
                    else => continue :state .invalid,
                }
            },

            .invalid => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => if (self.index == self.buffer.len) {
                        result.tag = .invalid;
                    } else {
                        continue :state .invalid;
                    },
                    '\n' => result.tag = .invalid,
                    else => continue :state .invalid,
                }
            },

            .saw_at_sign => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0, '\n' => result.tag = .invalid,
                    '"' => {
                        result.tag = .identifier;
                        continue :state .string_literal;
                    },
                    'a'...'z', 'A'...'Z', '_' => {
                        result.tag = .builtin;
                        continue :state .builtin;
                    },
                    else => continue :state .invalid,
                }
            },

            .ampersand => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .ampersand_equal;
                        self.index += 1;
                    },
                    else => result.tag = .ampersand,
                }
            },

            .asterisk => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .asterisk_equal;
                        self.index += 1;
                    },
                    '*' => {
                        result.tag = .asterisk_asterisk;
                        self.index += 1;
                    },
                    '%' => continue :state .asterisk_percent,
                    '|' => continue :state .asterisk_pipe,
                    else => result.tag = .asterisk,
                }
            },

            .asterisk_percent => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .asterisk_percent_equal;
                        self.index += 1;
                    },
                    else => result.tag = .asterisk_percent,
                }
            },

            .asterisk_pipe => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .asterisk_pipe_equal;
                        self.index += 1;
                    },
                    else => result.tag = .asterisk_pipe,
                }
            },

            .percent => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .percent_equal;
                        self.index += 1;
                    },
                    else => result.tag = .percent,
                }
            },

            .plus => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .plus_equal;
                        self.index += 1;
                    },
                    '+' => {
                        result.tag = .plus_plus;
                        self.index += 1;
                    },
                    '%' => continue :state .plus_percent,
                    '|' => continue :state .plus_pipe,
                    else => result.tag = .plus,
                }
            },

            .plus_percent => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .plus_percent_equal;
                        self.index += 1;
                    },
                    else => result.tag = .plus_percent,
                }
            },

            .plus_pipe => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .plus_pipe_equal;
                        self.index += 1;
                    },
                    else => result.tag = .plus_pipe,
                }
            },

            .caret => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .caret_equal;
                        self.index += 1;
                    },
                    else => result.tag = .caret,
                }
            },

            .identifier => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    'a'...'z', 'A'...'Z', '_', '0'...'9' => continue :state .identifier,
                    else => {
                        const ident = self.buffer[result.loc.start..self.index];
                        if (Token.getKeyword(ident)) |tag| {
                            result.tag = tag;
                        }
                    },
                }
            },
            .builtin => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    'a'...'z', 'A'...'Z', '_', '0'...'9' => continue :state .builtin,
                    else => {},
                }
            },
            .backslash => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => result.tag = .invalid,
                    '\\' => continue :state .multiline_string_literal_line,
                    '\n' => result.tag = .invalid,
                    else => continue :state .invalid,
                }
            },
            .string_literal => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index != self.buffer.len) {
                            continue :state .invalid;
                        } else {
                            result.tag = .invalid;
                        }
                    },
                    '\n' => result.tag = .invalid,
                    '\\' => continue :state .string_literal_backslash,
                    '"' => self.index += 1,
                    0x01...0x09, 0x0b...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => continue :state .string_literal,
                }
            },

            .string_literal_backslash => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0, '\n' => result.tag = .invalid,
                    else => continue :state .string_literal,
                }
            },

            .char_literal => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index != self.buffer.len) {
                            continue :state .invalid;
                        } else {
                            result.tag = .invalid;
                        }
                    },
                    '\n' => result.tag = .invalid,
                    '\\' => continue :state .char_literal_backslash,
                    '\'' => self.index += 1,
                    0x01...0x09, 0x0b...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => continue :state .char_literal,
                }
            },

            .char_literal_backslash => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index != self.buffer.len) {
                            continue :state .invalid;
                        } else {
                            result.tag = .invalid;
                        }
                    },
                    '\n' => result.tag = .invalid,
                    0x01...0x09, 0x0b...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => continue :state .char_literal,
                }
            },

            .multiline_string_literal_line => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => if (self.index != self.buffer.len) {
                        continue :state .invalid;
                    },
                    '\n' => {},
                    '\r' => if (self.buffer[self.index + 1] != '\n') {
                        continue :state .invalid;
                    },
                    0x01...0x09, 0x0b...0x0c, 0x0e...0x1f, 0x7f => continue :state .invalid,
                    else => continue :state .multiline_string_literal_line,
                }
            },

            .bang => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .bang_equal;
                        self.index += 1;
                    },
                    else => result.tag = .bang,
                }
            },

            .pipe => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .pipe_equal;
                        self.index += 1;
                    },
                    '|' => {
                        result.tag = .pipe_pipe;
                        self.index += 1;
                    },
                    else => result.tag = .pipe,
                }
            },

            .equal => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .equal_equal;
                        self.index += 1;
                    },
                    '>' => {
                        result.tag = .equal_angle_bracket_right;
                        self.index += 1;
                    },
                    else => result.tag = .equal,
                }
            },

            .minus => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '>' => {
                        result.tag = .arrow;
                        self.index += 1;
                    },
                    '=' => {
                        result.tag = .minus_equal;
                        self.index += 1;
                    },
                    '%' => continue :state .minus_percent,
                    '|' => continue :state .minus_pipe,
                    else => result.tag = .minus,
                }
            },

            .minus_percent => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .minus_percent_equal;
                        self.index += 1;
                    },
                    else => result.tag = .minus_percent,
                }
            },
            .minus_pipe => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .minus_pipe_equal;
                        self.index += 1;
                    },
                    else => result.tag = .minus_pipe,
                }
            },

            .angle_bracket_left => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '<' => continue :state .angle_bracket_angle_bracket_left,
                    '=' => {
                        result.tag = .angle_bracket_left_equal;
                        self.index += 1;
                    },
                    else => result.tag = .angle_bracket_left,
                }
            },

            .angle_bracket_angle_bracket_left => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .angle_bracket_angle_bracket_left_equal;
                        self.index += 1;
                    },
                    '|' => continue :state .angle_bracket_angle_bracket_left_pipe,
                    else => result.tag = .angle_bracket_angle_bracket_left,
                }
            },

            .angle_bracket_angle_bracket_left_pipe => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .angle_bracket_angle_bracket_left_pipe_equal;
                        self.index += 1;
                    },
                    else => result.tag = .angle_bracket_angle_bracket_left_pipe,
                }
            },

            .angle_bracket_right => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '>' => continue :state .angle_bracket_angle_bracket_right,
                    '=' => {
                        result.tag = .angle_bracket_right_equal;
                        self.index += 1;
                    },
                    else => result.tag = .angle_bracket_right,
                }
            },

            .angle_bracket_angle_bracket_right => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '=' => {
                        result.tag = .angle_bracket_angle_bracket_right_equal;
                        self.index += 1;
                    },
                    else => result.tag = .angle_bracket_angle_bracket_right,
                }
            },

            .period => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '.' => continue :state .period_2,
                    '*' => continue :state .period_asterisk,
                    else => result.tag = .period,
                }
            },

            .period_2 => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '.' => {
                        result.tag = .ellipsis3;
                        self.index += 1;
                    },
                    else => result.tag = .ellipsis2,
                }
            },

            .period_asterisk => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '*' => result.tag = .invalid_periodasterisks,
                    else => result.tag = .period_asterisk,
                }
            },

            .slash => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '/' => continue :state .line_comment_start,
                    '=' => {
                        result.tag = .slash_equal;
                        self.index += 1;
                    },
                    else => result.tag = .slash,
                }
            },
            .line_comment_start => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index != self.buffer.len) {
                            continue :state .invalid;
                        } else return .{
                            .tag = .eof,
                            .loc = .{
                                .start = self.index,
                                .end = self.index,
                            },
                        };
                    },
                    '!' => {
                        result.tag = .container_doc_comment;
                        continue :state .doc_comment;
                    },
                    '\n' => {
                        self.index += 1;
                        result.loc.start = self.index;
                        continue :state .start;
                    },
                    '/' => continue :state .doc_comment_start,
                    '\r' => continue :state .expect_newline,
                    0x01...0x09, 0x0b...0x0c, 0x0e...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => continue :state .line_comment,
                }
            },
            .doc_comment_start => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0, '\n' => result.tag = .doc_comment,
                    '\r' => {
                        if (self.buffer[self.index + 1] == '\n') {
                            result.tag = .doc_comment;
                        } else {
                            continue :state .invalid;
                        }
                    },
                    '/' => continue :state .line_comment,
                    0x01...0x09, 0x0b...0x0c, 0x0e...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => {
                        result.tag = .doc_comment;
                        continue :state .doc_comment;
                    },
                }
            },
            .line_comment => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index != self.buffer.len) {
                            continue :state .invalid;
                        } else return .{
                            .tag = .eof,
                            .loc = .{
                                .start = self.index,
                                .end = self.index,
                            },
                        };
                    },
                    '\n' => {
                        self.index += 1;
                        result.loc.start = self.index;
                        continue :state .start;
                    },
                    '\r' => continue :state .expect_newline,
                    0x01...0x09, 0x0b...0x0c, 0x0e...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => continue :state .line_comment,
                }
            },
            .doc_comment => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    0, '\n' => {},
                    '\r' => if (self.buffer[self.index + 1] != '\n') {
                        continue :state .invalid;
                    },
                    0x01...0x09, 0x0b...0x0c, 0x0e...0x1f, 0x7f => {
                        continue :state .invalid;
                    },
                    else => continue :state .doc_comment,
                }
            },
            .int => switch (self.buffer[self.index]) {
                '.' => continue :state .int_period,
                '_', 'a'...'d', 'f'...'o', 'q'...'z', 'A'...'D', 'F'...'O', 'Q'...'Z', '0'...'9' => {
                    self.index += 1;
                    continue :state .int;
                },
                'e', 'E', 'p', 'P' => {
                    continue :state .int_exponent;
                },
                else => {},
            },
            .int_exponent => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '-', '+' => {
                        self.index += 1;
                        continue :state .float;
                    },
                    else => continue :state .int,
                }
            },
            .int_period => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '_', 'a'...'d', 'f'...'o', 'q'...'z', 'A'...'D', 'F'...'O', 'Q'...'Z', '0'...'9' => {
                        self.index += 1;
                        continue :state .float;
                    },
                    'e', 'E', 'p', 'P' => {
                        continue :state .float_exponent;
                    },
                    else => self.index -= 1,
                }
            },
            .float => switch (self.buffer[self.index]) {
                '_', 'a'...'d', 'f'...'o', 'q'...'z', 'A'...'D', 'F'...'O', 'Q'...'Z', '0'...'9' => {
                    self.index += 1;
                    continue :state .float;
                },
                'e', 'E', 'p', 'P' => {
                    continue :state .float_exponent;
                },
                else => {},
            },
            .float_exponent => {
                self.index += 1;
                switch (self.buffer[self.index]) {
                    '-', '+' => {
                        self.index += 1;
                        continue :state .float;
                    },
                    else => continue :state .float,
                }
            },
        }

        result.loc.end = self.index;
        return result;
    }
};

test "keywords" {
    try testTokenize("test const else", &.{ .keyword_test, .keyword_const, .keyword_else });
}

test "line comment followed by top-level comptime" {
    try testTokenize(
        \\// line comment
        \\comptime {}
        \\
    , &.{
        .keyword_comptime,
        .l_brace,
        .r_brace,
    });
}

test "unknown length pointer and then c pointer" {
    try testTokenize(
        \\[*]u8
        \\[*c]u8
    , &.{
        .l_bracket,
        .asterisk,
        .r_bracket,
        .identifier,
        .l_bracket,
        .asterisk,
        .identifier,
        .r_bracket,
        .identifier,
    });
}

test "code point literal with hex escape" {
    try testTokenize(
        \\'\x1b'
    , &.{.char_literal});
    try testTokenize(
        \\'\x1'
    , &.{.char_literal});
}

test "newline in char literal" {
    try testTokenize(
        \\'
        \\'
    , &.{ .invalid, .invalid });
}

test "newline in string literal" {
    try testTokenize(
        \\"
        \\"
    , &.{ .invalid, .invalid });
}

test "code point literal with unicode escapes" {
    // Valid unicode escapes
    try testTokenize(
        \\'\u{3}'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{01}'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{2a}'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{3f9}'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{6E09aBc1523}'
    , &.{.char_literal});
    try testTokenize(
        \\"\u{440}"
    , &.{.string_literal});

    // Invalid unicode escapes
    try testTokenize(
        \\'\u'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{{'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{}'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{s}'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{2z}'
    , &.{.char_literal});
    try testTokenize(
        \\'\u{4a'
    , &.{.char_literal});

    // Test old-style unicode literals
    try testTokenize(
        \\'\u0333'
    , &.{.char_literal});
    try testTokenize(
        \\'\U0333'
    , &.{.char_literal});
}

test "code point literal with unicode code point" {
    try testTokenize(
        \\'💩'
    , &.{.char_literal});
}

test "float literal e exponent" {
    try testTokenize("a = 4.94065645841246544177e-324;\n", &.{
        .identifier,
        .equal,
        .number_literal,
        .semicolon,
    });
}

test "float literal p exponent" {
    try testTokenize("a = 0x1.a827999fcef32p+1022;\n", &.{
        .identifier,
        .equal,
        .number_literal,
        .semicolon,
    });
}

test "chars" {
    try testTokenize("'c'", &.{.char_literal});
}

test "invalid token characters" {
    try testTokenize("#", &.{.invalid});
    try testTokenize("`", &.{.invalid});
    try testTokenize("'c", &.{.invalid});
    try testTokenize("'", &.{.invalid});
    try testTokenize("''", &.{.char_literal});
    try testTokenize("'\n'", &.{ .invalid, .invalid });
}

test "invalid literal/comment characters" {
    try testTokenize("\"\x00\"", &.{.invalid});
    try testTokenize("`\x00`", &.{.invalid});
    try testTokenize("//\x00", &.{.invalid});
    try testTokenize("//\x1f", &.{.invalid});
    try testTokenize("//\x7f", &.{.invalid});
}

test "utf8" {
    try testTokenize("//\xc2\x80", &.{});
    try testTokenize("//\xf4\x8f\xbf\xbf", &.{});
}

test "invalid utf8" {
    try testTokenize("//\x80", &.{});
    try testTokenize("//\xbf", &.{});
    try testTokenize("//\xf8", &.{});
    try testTokenize("//\xff", &.{});
    try testTokenize("//\xc2\xc0", &.{});
    try testTokenize("//\xe0", &.{});
    try testTokenize("//\xf0", &.{});
    try testTokenize("//\xf0\x90\x80\xc0", &.{});
}

test "illegal unicode codepoints" {
    // unicode newline characters.U+0085, U+2028, U+2029
    try testTokenize("//\xc2\x84", &.{});
    try testTokenize("//\xc2\x85", &.{});
    try testTokenize("//\xc2\x86", &.{});
    try testTokenize("//\xe2\x80\xa7", &.{});
    try testTokenize("//\xe2\x80\xa8", &.{});
    try testTokenize("//\xe2\x80\xa9", &.{});
    try testTokenize("//\xe2\x80\xaa", &.{});
}

test "string identifier and builtin fns" {
    try testTokenize(
        \\const @"if" = @import("std");
    , &.{
        .keyword_const,
        .identifier,
        .equal,
        .builtin,
        .l_paren,
        .string_literal,
        .r_paren,
        .semicolon,
    });
}

test "pipe and then invalid" {
    try testTokenize("||=", &.{
        .pipe_pipe,
        .equal,
    });
}

test "line comment and doc comment" {
    try testTokenize("//", &.{});
    try testTokenize("// a / b", &.{});
    try testTokenize("// /", &.{});
    try testTokenize("/// a", &.{.doc_comment});
    try testTokenize("///", &.{.doc_comment});
    try testTokenize("////", &.{});
    try testTokenize("//!", &.{.container_doc_comment});
    try testTokenize("//!!", &.{.container_doc_comment});
}

test "line comment followed by identifier" {
    try testTokenize(
        \\    Unexpected,
        \\    // another
        \\    Another,
    , &.{
        .identifier,
        .comma,
        .identifier,
        .comma,
    });
}

test "UTF-8 BOM is recognized and skipped" {
    try testTokenize("\xEF\xBB\xBFa;\n", &.{
        .identifier,
        .semicolon,
    });
}

test "correctly parse pointer assignment" {
    try testTokenize("b.*=3;\n", &.{
        .identifier,
        .period_asterisk,
        .equal,
        .number_literal,
        .semicolon,
    });
}

test "correctly parse pointer dereference followed by asterisk" {
    try testTokenize("\"b\".* ** 10", &.{
        .string_literal,
        .period_asterisk,
        .asterisk_asterisk,
        .number_literal,
    });

    try testTokenize("(\"b\".*)** 10", &.{
        .l_paren,
        .string_literal,
        .period_asterisk,
        .r_paren,
        .asterisk_asterisk,
        .number_literal,
    });

    try testTokenize("\"b\".*** 10", &.{
        .string_literal,
        .invalid_periodasterisks,
        .asterisk_asterisk,
        .number_literal,
    });
}

test "range literals" {
    try testTokenize("0...9", &.{ .number_literal, .ellipsis3, .number_literal });
    try testTokenize("'0'...'9'", &.{ .char_literal, .ellipsis3, .char_literal });
    try testTokenize("0x00...0x09", &.{ .number_literal, .ellipsis3, .number_literal });
    try testTokenize("0b00...0b11", &.{ .number_literal, .ellipsis3, .number_literal });
    try testTokenize("0o00...0o11", &.{ .number_literal, .ellipsis3, .number_literal });
}

test "number literals decimal" {
    try testTokenize("0", &.{.number_literal});
    try testTokenize("1", &.{.number_literal});
    try testTokenize("2", &.{.number_literal});
    try testTokenize("3", &.{.number_literal});
    try testTokenize("4", &.{.number_literal});
    try testTokenize("5", &.{.number_literal});
    try testTokenize("6", &.{.number_literal});
    try testTokenize("7", &.{.number_literal});
    try testTokenize("8", &.{.number_literal});
    try testTokenize("9", &.{.number_literal});
    try testTokenize("1..", &.{ .number_literal, .ellipsis2 });
    try testTokenize("0a", &.{.number_literal});
    try testTokenize("9b", &.{.number_literal});
    try testTokenize("1z", &.{.number_literal});
    try testTokenize("1z_1", &.{.number_literal});
    try testTokenize("9z3", &.{.number_literal});

    try testTokenize("0_0", &.{.number_literal});
    try testTokenize("0001", &.{.number_literal});
    try testTokenize("01234567890", &.{.number_literal});
    try testTokenize("012_345_6789_0", &.{.number_literal});
    try testTokenize("0_1_2_3_4_5_6_7_8_9_0", &.{.number_literal});

    try testTokenize("00_", &.{.number_literal});
    try testTokenize("0_0_", &.{.number_literal});
    try testTokenize("0__0", &.{.number_literal});
    try testTokenize("0_0f", &.{.number_literal});
    try testTokenize("0_0_f", &.{.number_literal});
    try testTokenize("0_0_f_00", &.{.number_literal});
    try testTokenize("1_,", &.{ .number_literal, .comma });

    try testTokenize("0.0", &.{.number_literal});
    try testTokenize("1.0", &.{.number_literal});
    try testTokenize("10.0", &.{.number_literal});
    try testTokenize("0e0", &.{.number_literal});
    try testTokenize("1e0", &.{.number_literal});
    try testTokenize("1e100", &.{.number_literal});
    try testTokenize("1.0e100", &.{.number_literal});
    try testTokenize("1.0e+100", &.{.number_literal});
    try testTokenize("1.0e-100", &.{.number_literal});
    try testTokenize("1_0_0_0.0_0_0_0_0_1e1_0_0_0", &.{.number_literal});

    try testTokenize("1.", &.{ .number_literal, .period });
    try testTokenize("1e", &.{.number_literal});
    try testTokenize("1.e100", &.{.number_literal});
    try testTokenize("1.0e1f0", &.{.number_literal});
    try testTokenize("1.0p100", &.{.number_literal});
    try testTokenize("1.0p-100", &.{.number_literal});
    try testTokenize("1.0p1f0", &.{.number_literal});
    try testTokenize("1.0_,", &.{ .number_literal, .comma });
    try testTokenize("1_.0", &.{.number_literal});
    try testTokenize("1._", &.{.number_literal});
    try testTokenize("1.a", &.{.number_literal});
    try testTokenize("1.z", &.{.number_literal});
    try testTokenize("1._0", &.{.number_literal});
    try testTokenize("1.+", &.{ .number_literal, .period, .plus });
    try testTokenize("1._+", &.{ .number_literal, .plus });
    try testTokenize("1._e", &.{.number_literal});
    try testTokenize("1.0e", &.{.number_literal});
    try testTokenize("1.0e,", &.{ .number_literal, .comma });
    try testTokenize("1.0e_", &.{.number_literal});
    try testTokenize("1.0e+_", &.{.number_literal});
    try testTokenize("1.0e-_", &.{.number_literal});
    try testTokenize("1.0e0_+", &.{ .number_literal, .plus });
}

test "number literals binary" {
    try testTokenize("0b0", &.{.number_literal});
    try testTokenize("0b1", &.{.number_literal});
    try testTokenize("0b2", &.{.number_literal});
    try testTokenize("0b3", &.{.number_literal});
    try testTokenize("0b4", &.{.number_literal});
    try testTokenize("0b5", &.{.number_literal});
    try testTokenize("0b6", &.{.number_literal});
    try testTokenize("0b7", &.{.number_literal});
    try testTokenize("0b8", &.{.number_literal});
    try testTokenize("0b9", &.{.number_literal});
    try testTokenize("0ba", &.{.number_literal});
    try testTokenize("0bb", &.{.number_literal});
    try testTokenize("0bc", &.{.number_literal});
    try testTokenize("0bd", &.{.number_literal});
    try testTokenize("0be", &.{.number_literal});
    try testTokenize("0bf", &.{.number_literal});
    try testTokenize("0bz", &.{.number_literal});

    try testTokenize("0b0000_0000", &.{.number_literal});
    try testTokenize("0b1111_1111", &.{.number_literal});
    try testTokenize("0b10_10_10_10", &.{.number_literal});
    try testTokenize("0b0_1_0_1_0_1_0_1", &.{.number_literal});
    try testTokenize("0b1.", &.{ .number_literal, .period });
    try testTokenize("0b1.0", &.{.number_literal});

    try testTokenize("0B0", &.{.number_literal});
    try testTokenize("0b_", &.{.number_literal});
    try testTokenize("0b_0", &.{.number_literal});
    try testTokenize("0b1_", &.{.number_literal});
    try testTokenize("0b0__1", &.{.number_literal});
    try testTokenize("0b0_1_", &.{.number_literal});
    try testTokenize("0b1e", &.{.number_literal});
    try testTokenize("0b1p", &.{.number_literal});
    try testTokenize("0b1e0", &.{.number_literal});
    try testTokenize("0b1p0", &.{.number_literal});
    try testTokenize("0b1_,", &.{ .number_literal, .comma });
}

test "number literals octal" {
    try testTokenize("0o0", &.{.number_literal});
    try testTokenize("0o1", &.{.number_literal});
    try testTokenize("0o2", &.{.number_literal});
    try testTokenize("0o3", &.{.number_literal});
    try testTokenize("0o4", &.{.number_literal});
    try testTokenize("0o5", &.{.number_literal});
    try testTokenize("0o6", &.{.number_literal});
    try testTokenize("0o7", &.{.number_literal});
    try testTokenize("0o8", &.{.number_literal});
    try testTokenize("0o9", &.{.number_literal});
    try testTokenize("0oa", &.{.number_literal});
    try testTokenize("0ob", &.{.number_literal});
    try testTokenize("0oc", &.{.number_literal});
    try testTokenize("0od", &.{.number_literal});
    try testTokenize("0oe", &.{.number_literal});
    try testTokenize("0of", &.{.number_literal});
    try testTokenize("0oz", &.{.number_literal});

    try testTokenize("0o01234567", &.{.number_literal});
    try testTokenize("0o0123_4567", &.{.number_literal});
    try testTokenize("0o01_23_45_67", &.{.number_literal});
    try testTokenize("0o0_1_2_3_4_5_6_7", &.{.number_literal});
    try testTokenize("0o7.", &.{ .number_literal, .period });
    try testTokenize("0o7.0", &.{.number_literal});

    try testTokenize("0O0", &.{.number_literal});
    try testTokenize("0o_", &.{.number_literal});
    try testTokenize("0o_0", &.{.number_literal});
    try testTokenize("0o1_", &.{.number_literal});
    try testTokenize("0o0__1", &.{.number_literal});
    try testTokenize("0o0_1_", &.{.number_literal});
    try testTokenize("0o1e", &.{.number_literal});
    try testTokenize("0o1p", &.{.number_literal});
    try testTokenize("0o1e0", &.{.number_literal});
    try testTokenize("0o1p0", &.{.number_literal});
    try testTokenize("0o_,", &.{ .number_literal, .comma });
}

test "number literals hexadecimal" {
    try testTokenize("0x0", &.{.number_literal});
    try testTokenize("0x1", &.{.number_literal});
    try testTokenize("0x2", &.{.number_literal});
    try testTokenize("0x3", &.{.number_literal});
    try testTokenize("0x4", &.{.number_literal});
    try testTokenize("0x5", &.{.number_literal});
    try testTokenize("0x6", &.{.number_literal});
    try testTokenize("0x7", &.{.number_literal});
    try testTokenize("0x8", &.{.number_literal});
    try testTokenize("0x9", &.{.number_literal});
    try testTokenize("0xa", &.{.number_literal});
    try testTokenize("0xb", &.{.number_literal});
    try testTokenize("0xc", &.{.number_literal});
    try testTokenize("0xd", &.{.number_literal});
    try testTokenize("0xe", &.{.number_literal});
    try testTokenize("0xf", &.{.number_literal});
    try testTokenize("0xA", &.{.number_literal});
    try testTokenize("0xB", &.{.number_literal});
    try testTokenize("0xC", &.{.number_literal});
    try testTokenize("0xD", &.{.number_literal});
    try testTokenize("0xE", &.{.number_literal});
    try testTokenize("0xF", &.{.number_literal});
    try testTokenize("0x0z", &.{.number_literal});
    try testTokenize("0xz", &.{.number_literal});

    try testTokenize("0x0123456789ABCDEF", &.{.number_literal});
    try testTokenize("0x0123_4567_89AB_CDEF", &.{.number_literal});
    try testTokenize("0x01_23_45_67_89AB_CDE_F", &.{.number_literal});
    try testTokenize("0x0_1_2_3_4_5_6_7_8_9_A_B_C_D_E_F", &.{.number_literal});

    try testTokenize("0X0", &.{.number_literal});
    try testTokenize("0x_", &.{.number_literal});
    try testTokenize("0x_1", &.{.number_literal});
    try testTokenize("0x1_", &.{.number_literal});
    try testTokenize("0x0__1", &.{.number_literal});
    try testTokenize("0x0_1_", &.{.number_literal});
    try testTokenize("0x_,", &.{ .number_literal, .comma });

    try testTokenize("0x1.0", &.{.number_literal});
    try testTokenize("0xF.0", &.{.number_literal});
    try testTokenize("0xF.F", &.{.n```
