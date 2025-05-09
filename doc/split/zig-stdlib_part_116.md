```
e{
            .zaamo,
        }),
    };
    result[@intFromEnum(Feature.zalrsc)] = .{
        .llvm_name = "zalrsc",
        .description = "'Zalrsc' (Load-Reserved/Store-Conditional)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zama16b)] = .{
        .llvm_name = "zama16b",
        .description = "'Zama16b' (Atomic 16-byte misaligned loads, stores and AMOs)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zawrs)] = .{
        .llvm_name = "zawrs",
        .description = "'Zawrs' (Wait on Reservation Set)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zba)] = .{
        .llvm_name = "zba",
        .description = "'Zba' (Address Generation Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zbb)] = .{
        .llvm_name = "zbb",
        .description = "'Zbb' (Basic Bit-Manipulation)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zbc)] = .{
        .llvm_name = "zbc",
        .description = "'Zbc' (Carry-Less Multiplication)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zbkb)] = .{
        .llvm_name = "zbkb",
        .description = "'Zbkb' (Bitmanip instructions for Cryptography)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zbkc)] = .{
        .llvm_name = "zbkc",
        .description = "'Zbkc' (Carry-less multiply instructions for Cryptography)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zbkx)] = .{
        .llvm_name = "zbkx",
        .description = "'Zbkx' (Crossbar permutation instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zbs)] = .{
        .llvm_name = "zbs",
        .description = "'Zbs' (Single-Bit Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zca)] = .{
        .llvm_name = "zca",
        .description = "'Zca' (part of the C extension, excluding compressed floating point loads/stores)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zcb)] = .{
        .llvm_name = "zcb",
        .description = "'Zcb' (Compressed basic bit manipulation instructions)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
        }),
    };
    result[@intFromEnum(Feature.zcd)] = .{
        .llvm_name = "zcd",
        .description = "'Zcd' (Compressed Double-Precision Floating-Point Instructions)",
        .dependencies = featureSet(&[_]Feature{
            .d,
            .zca,
        }),
    };
    result[@intFromEnum(Feature.zce)] = .{
        .llvm_name = "zce",
        .description = "'Zce' (Compressed extensions for microcontrollers)",
        .dependencies = featureSet(&[_]Feature{
            .zcb,
            .zcmp,
            .zcmt,
        }),
    };
    result[@intFromEnum(Feature.zcf)] = .{
        .llvm_name = "zcf",
        .description = "'Zcf' (Compressed Single-Precision Floating-Point Instructions)",
        .dependencies = featureSet(&[_]Feature{
            .f,
            .zca,
        }),
    };
    result[@intFromEnum(Feature.zcmop)] = .{
        .llvm_name = "zcmop",
        .description = "'Zcmop' (Compressed May-Be-Operations)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
        }),
    };
    result[@intFromEnum(Feature.zcmp)] = .{
        .llvm_name = "zcmp",
        .description = "'Zcmp' (sequenced instructions for code-size reduction)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
        }),
    };
    result[@intFromEnum(Feature.zcmt)] = .{
        .llvm_name = "zcmt",
        .description = "'Zcmt' (table jump instructions for code-size reduction)",
        .dependencies = featureSet(&[_]Feature{
            .zca,
            .zicsr,
        }),
    };
    result[@intFromEnum(Feature.zdinx)] = .{
        .llvm_name = "zdinx",
        .description = "'Zdinx' (Double in Integer)",
        .dependencies = featureSet(&[_]Feature{
            .zfinx,
        }),
    };
    result[@intFromEnum(Feature.zexth_fusion)] = .{
        .llvm_name = "zexth-fusion",
        .description = "Enable SLLI+SRLI to be fused to zero extension of halfword",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zextw_fusion)] = .{
        .llvm_name = "zextw-fusion",
        .description = "Enable SLLI+SRLI to be fused to zero extension of word",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zfa)] = .{
        .llvm_name = "zfa",
        .description = "'Zfa' (Additional Floating-Point)",
        .dependencies = featureSet(&[_]Feature{
            .f,
        }),
    };
    result[@intFromEnum(Feature.zfbfmin)] = .{
        .llvm_name = "zfbfmin",
        .description = "'Zfbfmin' (Scalar BF16 Converts)",
        .dependencies = featureSet(&[_]Feature{
            .f,
        }),
    };
    result[@intFromEnum(Feature.zfh)] = .{
        .llvm_name = "zfh",
        .description = "'Zfh' (Half-Precision Floating-Point)",
        .dependencies = featureSet(&[_]Feature{
            .zfhmin,
        }),
    };
    result[@intFromEnum(Feature.zfhmin)] = .{
        .llvm_name = "zfhmin",
        .description = "'Zfhmin' (Half-Precision Floating-Point Minimal)",
        .dependencies = featureSet(&[_]Feature{
            .f,
        }),
    };
    result[@intFromEnum(Feature.zfinx)] = .{
        .llvm_name = "zfinx",
        .description = "'Zfinx' (Float in Integer)",
        .dependencies = featureSet(&[_]Feature{
            .zicsr,
        }),
    };
    result[@intFromEnum(Feature.zhinx)] = .{
        .llvm_name = "zhinx",
        .description = "'Zhinx' (Half Float in Integer)",
        .dependencies = featureSet(&[_]Feature{
            .zhinxmin,
        }),
    };
    result[@intFromEnum(Feature.zhinxmin)] = .{
        .llvm_name = "zhinxmin",
        .description = "'Zhinxmin' (Half Float in Integer Minimal)",
        .dependencies = featureSet(&[_]Feature{
            .zfinx,
        }),
    };
    result[@intFromEnum(Feature.zic64b)] = .{
        .llvm_name = "zic64b",
        .description = "'Zic64b' (Cache Block Size Is 64 Bytes)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zicbom)] = .{
        .llvm_name = "zicbom",
        .description = "'Zicbom' (Cache-Block Management Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zicbop)] = .{
        .llvm_name = "zicbop",
        .description = "'Zicbop' (Cache-Block Prefetch Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zicboz)] = .{
        .llvm_name = "zicboz",
        .description = "'Zicboz' (Cache-Block Zero Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ziccamoa)] = .{
        .llvm_name = "ziccamoa",
        .description = "'Ziccamoa' (Main Memory Supports All Atomics in A)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ziccif)] = .{
        .llvm_name = "ziccif",
        .description = "'Ziccif' (Main Memory Supports Instruction Fetch with Atomicity Requirement)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zicclsm)] = .{
        .llvm_name = "zicclsm",
        .description = "'Zicclsm' (Main Memory Supports Misaligned Loads/Stores)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ziccrse)] = .{
        .llvm_name = "ziccrse",
        .description = "'Ziccrse' (Main Memory Supports Forward Progress on LR/SC Sequences)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zicntr)] = .{
        .llvm_name = "zicntr",
        .description = "'Zicntr' (Base Counters and Timers)",
        .dependencies = featureSet(&[_]Feature{
            .zicsr,
        }),
    };
    result[@intFromEnum(Feature.zicond)] = .{
        .llvm_name = "zicond",
        .description = "'Zicond' (Integer Conditional Operations)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zicsr)] = .{
        .llvm_name = "zicsr",
        .description = "'Zicsr' (CSRs)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zifencei)] = .{
        .llvm_name = "zifencei",
        .description = "'Zifencei' (fence.i)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zihintntl)] = .{
        .llvm_name = "zihintntl",
        .description = "'Zihintntl' (Non-Temporal Locality Hints)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zihintpause)] = .{
        .llvm_name = "zihintpause",
        .description = "'Zihintpause' (Pause Hint)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zihpm)] = .{
        .llvm_name = "zihpm",
        .description = "'Zihpm' (Hardware Performance Counters)",
        .dependencies = featureSet(&[_]Feature{
            .zicsr,
        }),
    };
    result[@intFromEnum(Feature.zimop)] = .{
        .llvm_name = "zimop",
        .description = "'Zimop' (May-Be-Operations)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zk)] = .{
        .llvm_name = "zk",
        .description = "'Zk' (Standard scalar cryptography extension)",
        .dependencies = featureSet(&[_]Feature{
            .zkn,
            .zkr,
            .zkt,
        }),
    };
    result[@intFromEnum(Feature.zkn)] = .{
        .llvm_name = "zkn",
        .description = "'Zkn' (NIST Algorithm Suite)",
        .dependencies = featureSet(&[_]Feature{
            .zbkb,
            .zbkc,
            .zbkx,
            .zknd,
            .zkne,
            .zknh,
        }),
    };
    result[@intFromEnum(Feature.zknd)] = .{
        .llvm_name = "zknd",
        .description = "'Zknd' (NIST Suite: AES Decryption)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zkne)] = .{
        .llvm_name = "zkne",
        .description = "'Zkne' (NIST Suite: AES Encryption)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zknh)] = .{
        .llvm_name = "zknh",
        .description = "'Zknh' (NIST Suite: Hash Function Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zkr)] = .{
        .llvm_name = "zkr",
        .description = "'Zkr' (Entropy Source Extension)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zks)] = .{
        .llvm_name = "zks",
        .description = "'Zks' (ShangMi Algorithm Suite)",
        .dependencies = featureSet(&[_]Feature{
            .zbkb,
            .zbkc,
            .zbkx,
            .zksed,
            .zksh,
        }),
    };
    result[@intFromEnum(Feature.zksed)] = .{
        .llvm_name = "zksed",
        .description = "'Zksed' (ShangMi Suite: SM4 Block Cipher Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zksh)] = .{
        .llvm_name = "zksh",
        .description = "'Zksh' (ShangMi Suite: SM3 Hash Function Instructions)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zkt)] = .{
        .llvm_name = "zkt",
        .description = "'Zkt' (Data Independent Execution Latency)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zmmul)] = .{
        .llvm_name = "zmmul",
        .description = "'Zmmul' (Integer Multiplication)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.ztso)] = .{
        .llvm_name = "ztso",
        .description = "'Ztso' (Memory Model - Total Store Order)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zvbb)] = .{
        .llvm_name = "zvbb",
        .description = "'Zvbb' (Vector basic bit-manipulation instructions)",
        .dependencies = featureSet(&[_]Feature{
            .zvkb,
        }),
    };
    result[@intFromEnum(Feature.zvbc)] = .{
        .llvm_name = "zvbc",
        .description = "'Zvbc' (Vector Carryless Multiplication)",
        .dependencies = featureSet(&[_]Feature{
            .zve64x,
        }),
    };
    result[@intFromEnum(Feature.zve32f)] = .{
        .llvm_name = "zve32f",
        .description = "'Zve32f' (Vector Extensions for Embedded Processors with maximal 32 EEW and F extension)",
        .dependencies = featureSet(&[_]Feature{
            .f,
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.zve32x)] = .{
        .llvm_name = "zve32x",
        .description = "'Zve32x' (Vector Extensions for Embedded Processors with maximal 32 EEW)",
        .dependencies = featureSet(&[_]Feature{
            .zicsr,
            .zvl32b,
        }),
    };
    result[@intFromEnum(Feature.zve64d)] = .{
        .llvm_name = "zve64d",
        .description = "'Zve64d' (Vector Extensions for Embedded Processors with maximal 64 EEW, F and D extension)",
        .dependencies = featureSet(&[_]Feature{
            .d,
            .zve64f,
        }),
    };
    result[@intFromEnum(Feature.zve64f)] = .{
        .llvm_name = "zve64f",
        .description = "'Zve64f' (Vector Extensions for Embedded Processors with maximal 64 EEW and F extension)",
        .dependencies = featureSet(&[_]Feature{
            .zve32f,
            .zve64x,
        }),
    };
    result[@intFromEnum(Feature.zve64x)] = .{
        .llvm_name = "zve64x",
        .description = "'Zve64x' (Vector Extensions for Embedded Processors with maximal 64 EEW)",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
            .zvl64b,
        }),
    };
    result[@intFromEnum(Feature.zvfbfmin)] = .{
        .llvm_name = "zvfbfmin",
        .description = "'Zvfbfmin' (Vector BF16 Converts)",
        .dependencies = featureSet(&[_]Feature{
            .zve32f,
        }),
    };
    result[@intFromEnum(Feature.zvfbfwma)] = .{
        .llvm_name = "zvfbfwma",
        .description = "'Zvfbfwma' (Vector BF16 widening mul-add)",
        .dependencies = featureSet(&[_]Feature{
            .zfbfmin,
            .zvfbfmin,
        }),
    };
    result[@intFromEnum(Feature.zvfh)] = .{
        .llvm_name = "zvfh",
        .description = "'Zvfh' (Vector Half-Precision Floating-Point)",
        .dependencies = featureSet(&[_]Feature{
            .zfhmin,
            .zvfhmin,
        }),
    };
    result[@intFromEnum(Feature.zvfhmin)] = .{
        .llvm_name = "zvfhmin",
        .description = "'Zvfhmin' (Vector Half-Precision Floating-Point Minimal)",
        .dependencies = featureSet(&[_]Feature{
            .zve32f,
        }),
    };
    result[@intFromEnum(Feature.zvkb)] = .{
        .llvm_name = "zvkb",
        .description = "'Zvkb' (Vector Bit-manipulation used in Cryptography)",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.zvkg)] = .{
        .llvm_name = "zvkg",
        .description = "'Zvkg' (Vector GCM instructions for Cryptography)",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.zvkn)] = .{
        .llvm_name = "zvkn",
        .description = "'Zvkn' (shorthand for 'Zvkned', 'Zvknhb', 'Zvkb', and 'Zvkt')",
        .dependencies = featureSet(&[_]Feature{
            .zvkb,
            .zvkned,
            .zvknhb,
            .zvkt,
        }),
    };
    result[@intFromEnum(Feature.zvknc)] = .{
        .llvm_name = "zvknc",
        .description = "'Zvknc' (shorthand for 'Zvknc' and 'Zvbc')",
        .dependencies = featureSet(&[_]Feature{
            .zvbc,
            .zvkn,
        }),
    };
    result[@intFromEnum(Feature.zvkned)] = .{
        .llvm_name = "zvkned",
        .description = "'Zvkned' (Vector AES Encryption & Decryption (Single Round))",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.zvkng)] = .{
        .llvm_name = "zvkng",
        .description = "'Zvkng' (shorthand for 'Zvkn' and 'Zvkg')",
        .dependencies = featureSet(&[_]Feature{
            .zvkg,
            .zvkn,
        }),
    };
    result[@intFromEnum(Feature.zvknha)] = .{
        .llvm_name = "zvknha",
        .description = "'Zvknha' (Vector SHA-2 (SHA-256 only))",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.zvknhb)] = .{
        .llvm_name = "zvknhb",
        .description = "'Zvknhb' (Vector SHA-2 (SHA-256 and SHA-512))",
        .dependencies = featureSet(&[_]Feature{
            .zve64x,
        }),
    };
    result[@intFromEnum(Feature.zvks)] = .{
        .llvm_name = "zvks",
        .description = "'Zvks' (shorthand for 'Zvksed', 'Zvksh', 'Zvkb', and 'Zvkt')",
        .dependencies = featureSet(&[_]Feature{
            .zvkb,
            .zvksed,
            .zvksh,
            .zvkt,
        }),
    };
    result[@intFromEnum(Feature.zvksc)] = .{
        .llvm_name = "zvksc",
        .description = "'Zvksc' (shorthand for 'Zvks' and 'Zvbc')",
        .dependencies = featureSet(&[_]Feature{
            .zvbc,
            .zvks,
        }),
    };
    result[@intFromEnum(Feature.zvksed)] = .{
        .llvm_name = "zvksed",
        .description = "'Zvksed' (SM4 Block Cipher Instructions)",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.zvksg)] = .{
        .llvm_name = "zvksg",
        .description = "'Zvksg' (shorthand for 'Zvks' and 'Zvkg')",
        .dependencies = featureSet(&[_]Feature{
            .zvkg,
            .zvks,
        }),
    };
    result[@intFromEnum(Feature.zvksh)] = .{
        .llvm_name = "zvksh",
        .description = "'Zvksh' (SM3 Hash Function Instructions)",
        .dependencies = featureSet(&[_]Feature{
            .zve32x,
        }),
    };
    result[@intFromEnum(Feature.zvkt)] = .{
        .llvm_name = "zvkt",
        .description = "'Zvkt' (Vector Data-Independent Execution Latency)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zvl1024b)] = .{
        .llvm_name = "zvl1024b",
        .description = "'Zvl1024b' (Minimum Vector Length 1024)",
        .dependencies = featureSet(&[_]Feature{
            .zvl512b,
        }),
    };
    result[@intFromEnum(Feature.zvl128b)] = .{
        .llvm_name = "zvl128b",
        .description = "'Zvl128b' (Minimum Vector Length 128)",
        .dependencies = featureSet(&[_]Feature{
            .zvl64b,
        }),
    };
    result[@intFromEnum(Feature.zvl16384b)] = .{
        .llvm_name = "zvl16384b",
        .description = "'Zvl16384b' (Minimum Vector Length 16384)",
        .dependencies = featureSet(&[_]Feature{
            .zvl8192b,
        }),
    };
    result[@intFromEnum(Feature.zvl2048b)] = .{
        .llvm_name = "zvl2048b",
        .description = "'Zvl2048b' (Minimum Vector Length 2048)",
        .dependencies = featureSet(&[_]Feature{
            .zvl1024b,
        }),
    };
    result[@intFromEnum(Feature.zvl256b)] = .{
        .llvm_name = "zvl256b",
        .description = "'Zvl256b' (Minimum Vector Length 256)",
        .dependencies = featureSet(&[_]Feature{
            .zvl128b,
        }),
    };
    result[@intFromEnum(Feature.zvl32768b)] = .{
        .llvm_name = "zvl32768b",
        .description = "'Zvl32768b' (Minimum Vector Length 32768)",
        .dependencies = featureSet(&[_]Feature{
            .zvl16384b,
        }),
    };
    result[@intFromEnum(Feature.zvl32b)] = .{
        .llvm_name = "zvl32b",
        .description = "'Zvl32b' (Minimum Vector Length 32)",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.zvl4096b)] = .{
        .llvm_name = "zvl4096b",
        .description = "'Zvl4096b' (Minimum Vector Length 4096)",
        .dependencies = featureSet(&[_]Feature{
            .zvl2048b,
        }),
    };
    result[@intFromEnum(Feature.zvl512b)] = .{
        .llvm_name = "zvl512b",
        .description = "'Zvl512b' (Minimum Vector Length 512)",
        .dependencies = featureSet(&[_]Feature{
            .zvl256b,
        }),
    };
    result[@intFromEnum(Feature.zvl64b)] = .{
        .llvm_name = "zvl64b",
        .description = "'Zvl64b' (Minimum Vector Length 64)",
        .dependencies = featureSet(&[_]Feature{
            .zvl32b,
        }),
    };
    result[@intFromEnum(Feature.zvl65536b)] = .{
        .llvm_name = "zvl65536b",
        .description = "'Zvl65536b' (Minimum Vector Length 65536)",
        .dependencies = featureSet(&[_]Feature{
            .zvl32768b,
        }),
    };
    result[@intFromEnum(Feature.zvl8192b)] = .{
        .llvm_name = "zvl8192b",
        .description = "'Zvl8192b' (Minimum Vector Length 8192)",
        .dependencies = featureSet(&[_]Feature{
            .zvl4096b,
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
    pub const baseline_rv32: CpuModel = .{
        .name = "baseline_rv32",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .d,
            .i,
            .m,
        }),
    };
    pub const baseline_rv64: CpuModel = .{
        .name = "baseline_rv64",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
        }),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{}),
    };
    pub const generic_rv32: CpuModel = .{
        .name = "generic_rv32",
        .llvm_name = "generic-rv32",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .i,
            .optimized_nf2_segment_load_store,
        }),
    };
    pub const generic_rv64: CpuModel = .{
        .name = "generic_rv64",
        .llvm_name = "generic-rv64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .i,
            .optimized_nf2_segment_load_store,
        }),
    };
    pub const mips_p8700: CpuModel = .{
        .name = "mips_p8700",
        .llvm_name = "mips-p8700",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .mips_p8700,
            .xmipscmove,
            .xmipslsp,
            .zba,
            .zbb,
            .zifencei,
        }),
    };
    pub const rocket: CpuModel = .{
        .name = "rocket",
        .llvm_name = "rocket",
        .features = featureSet(&[_]Feature{}),
    };
    pub const rocket_rv32: CpuModel = .{
        .name = "rocket_rv32",
        .llvm_name = "rocket-rv32",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .i,
            .zicsr,
            .zifencei,
        }),
    };
    pub const rocket_rv64: CpuModel = .{
        .name = "rocket_rv64",
        .llvm_name = "rocket-rv64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .i,
            .zicsr,
            .zifencei,
        }),
    };
    pub const rp2350_hazard3: CpuModel = .{
        .name = "rp2350_hazard3",
        .llvm_name = "rp2350-hazard3",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .i,
            .m,
            .zba,
            .zbb,
            .zbkb,
            .zbs,
            .zcb,
            .zcmp,
            .zicsr,
            .zifencei,
        }),
    };
    pub const sifive_7_series: CpuModel = .{
        .name = "sifive_7_series",
        .llvm_name = "sifive-7-series",
        .features = featureSet(&[_]Feature{
            .no_default_unroll,
            .short_forward_branch_opt,
            .use_postra_scheduler,
        }),
    };
    pub const sifive_e20: CpuModel = .{
        .name = "sifive_e20",
        .llvm_name = "sifive-e20",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .c,
            .i,
            .m,
            .zicsr,
            .zifencei,
        }),
    };
    pub const sifive_e21: CpuModel = .{
        .name = "sifive_e21",
        .llvm_name = "sifive-e21",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .i,
            .m,
            .zicsr,
            .zifencei,
        }),
    };
    pub const sifive_e24: CpuModel = .{
        .name = "sifive_e24",
        .llvm_name = "sifive-e24",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .f,
            .i,
            .m,
            .zifencei,
        }),
    };
    pub const sifive_e31: CpuModel = .{
        .name = "sifive_e31",
        .llvm_name = "sifive-e31",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .i,
            .m,
            .zicsr,
            .zifencei,
        }),
    };
    pub const sifive_e34: CpuModel = .{
        .name = "sifive_e34",
        .llvm_name = "sifive-e34",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .f,
            .i,
            .m,
            .zifencei,
        }),
    };
    pub const sifive_e76: CpuModel = .{
        .name = "sifive_e76",
        .llvm_name = "sifive-e76",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .f,
            .i,
            .m,
            .no_default_unroll,
            .short_forward_branch_opt,
            .use_postra_scheduler,
            .zifencei,
        }),
    };
    pub const sifive_p450: CpuModel = .{
        .name = "sifive_p450",
        .llvm_name = "sifive-p450",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .auipc_addi_fusion,
            .b,
            .c,
            .conditional_cmv_fusion,
            .d,
            .i,
            .lui_addi_fusion,
            .m,
            .no_default_unroll,
            .unaligned_scalar_mem,
            .unaligned_vector_mem,
            .use_postra_scheduler,
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
            .zihintntl,
            .zihintpause,
            .zihpm,
            .zkt,
        }),
    };
    pub const sifive_p470: CpuModel = .{
        .name = "sifive_p470",
        .llvm_name = "sifive-p470",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .auipc_addi_fusion,
            .b,
            .c,
            .conditional_cmv_fusion,
            .i,
            .lui_addi_fusion,
            .m,
            .no_default_unroll,
            .no_sink_splat_operands,
            .unaligned_scalar_mem,
            .unaligned_vector_mem,
            .use_postra_scheduler,
            .v,
            .vxrm_pipeline_flush,
            .xsifivecdiscarddlone,
            .xsifivecflushdlone,
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
            .zihintntl,
            .zihintpause,
            .zihpm,
            .zkt,
            .zvbb,
            .zvknc,
            .zvkng,
            .zvksc,
            .zvksg,
        }),
    };
    pub const sifive_p550: CpuModel = .{
        .name = "sifive_p550",
        .llvm_name = "sifive-p550",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .auipc_addi_fusion,
            .c,
            .conditional_cmv_fusion,
            .d,
            .i,
            .lui_addi_fusion,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .zba,
            .zbb,
            .zifencei,
        }),
    };
    pub const sifive_p670: CpuModel = .{
        .name = "sifive_p670",
        .llvm_name = "sifive-p670",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .auipc_addi_fusion,
            .b,
            .c,
            .conditional_cmv_fusion,
            .i,
            .lui_addi_fusion,
            .m,
            .no_default_unroll,
            .no_sink_splat_operands,
            .unaligned_scalar_mem,
            .unaligned_vector_mem,
            .use_postra_scheduler,
            .v,
            .vxrm_pipeline_flush,
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
            .zihintntl,
            .zihintpause,
            .zihpm,
            .zkt,
            .zvbb,
            .zvknc,
            .zvkng,
            .zvksc,
            .zvksg,
        }),
    };
    pub const sifive_s21: CpuModel = .{
        .name = "sifive_s21",
        .llvm_name = "sifive-s21",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .i,
            .m,
            .zicsr,
            .zifencei,
        }),
    };
    pub const sifive_s51: CpuModel = .{
        .name = "sifive_s51",
        .llvm_name = "sifive-s51",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .i,
            .m,
            .zicsr,
            .zifencei,
        }),
    };
    pub const sifive_s54: CpuModel = .{
        .name = "sifive_s54",
        .llvm_name = "sifive-s54",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .zifencei,
        }),
    };
    pub const sifive_s76: CpuModel = .{
        .name = "sifive_s76",
        .llvm_name = "sifive-s76",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .no_default_unroll,
            .short_forward_branch_opt,
            .use_postra_scheduler,
            .zifencei,
            .zihintpause,
        }),
    };
    pub const sifive_u54: CpuModel = .{
        .name = "sifive_u54",
        .llvm_name = "sifive-u54",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .zifencei,
        }),
    };
    pub const sifive_u74: CpuModel = .{
        .name = "sifive_u74",
        .llvm_name = "sifive-u74",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .no_default_unroll,
            .short_forward_branch_opt,
            .use_postra_scheduler,
            .zifencei,
        }),
    };
    pub const sifive_x280: CpuModel = .{
        .name = "sifive_x280",
        .llvm_name = "sifive-x280",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .dlen_factor_2,
            .i,
            .m,
            .no_default_unroll,
            .optimized_nf2_segment_load_store,
            .optimized_zero_stride_load,
            .short_forward_branch_opt,
            .use_postra_scheduler,
            .v,
            .zba,
            .zbb,
            .zfh,
            .zifencei,
            .zvfh,
            .zvl512b,
        }),
    };
    pub const spacemit_x60: CpuModel = .{
        .name = "spacemit_x60",
        .llvm_name = "spacemit-x60",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .dlen_factor_2,
            .i,
            .m,
            .optimized_nf2_segment_load_store,
            .optimized_nf3_segment_load_store,
            .optimized_nf4_segment_load_store,
            .ssccptr,
            .sscofpmf,
            .sscounterenw,
            .sstc,
            .sstvala,
            .sstvecd,
            .svade,
            .svbare,
            .svinval,
            .svnapot,
            .svpbmt,
            .unaligned_scalar_mem,
            .v,
            .vxrm_pipeline_flush,
            .za64rs,
            .zbc,
            .zbkc,
            .zfh,
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
            .zihintpause,
            .zihpm,
            .zkt,
            .zvfh,
            .zvkt,
            .zvl256b,
        }),
    };
    pub const syntacore_scr1_base: CpuModel = .{
        .name = "syntacore_scr1_base",
        .llvm_name = "syntacore-scr1-base",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .c,
            .i,
            .no_default_unroll,
            .zicsr,
            .zifencei,
        }),
    };
    pub const syntacore_scr1_max: CpuModel = .{
        .name = "syntacore_scr1_max",
        .llvm_name = "syntacore-scr1-max",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .c,
            .i,
            .m,
            .no_default_unroll,
            .zicsr,
            .zifencei,
        }),
    };
    pub const syntacore_scr3_rv32: CpuModel = .{
        .name = "syntacore_scr3_rv32",
        .llvm_name = "syntacore-scr3-rv32",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .c,
            .i,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .zicsr,
            .zifencei,
        }),
    };
    pub const syntacore_scr3_rv64: CpuModel = .{
        .name = "syntacore_scr3_rv64",
        .llvm_name = "syntacore-scr3-rv64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .i,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .zicsr,
            .zifencei,
        }),
    };
    pub const syntacore_scr4_rv32: CpuModel = .{
        .name = "syntacore_scr4_rv32",
        .llvm_name = "syntacore-scr4-rv32",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .c,
            .d,
            .i,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .zifencei,
        }),
    };
    pub const syntacore_scr4_rv64: CpuModel = .{
        .name = "syntacore_scr4_rv64",
        .llvm_name = "syntacore-scr4-rv64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .zifencei,
        }),
    };
    pub const syntacore_scr5_rv32: CpuModel = .{
        .name = "syntacore_scr5_rv32",
        .llvm_name = "syntacore-scr5-rv32",
        .features = featureSet(&[_]Feature{
            .@"32bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .zifencei,
        }),
    };
    pub const syntacore_scr5_rv64: CpuModel = .{
        .name = "syntacore_scr5_rv64",
        .llvm_name = "syntacore-scr5-rv64",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .zifencei,
        }),
    };
    pub const syntacore_scr7: CpuModel = .{
        .name = "syntacore_scr7",
        .llvm_name = "syntacore-scr7",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .i,
            .m,
            .no_default_unroll,
            .use_postra_scheduler,
            .v,
            .zba,
            .zbb,
            .zbc,
            .zbs,
            .zifencei,
            .zkn,
        }),
    };
    pub const tt_ascalon_d8: CpuModel = .{
        .name = "tt_ascalon_d8",
        .llvm_name = "tt-ascalon-d8",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .b,
            .c,
            .i,
            .m,
            .no_default_unroll,
            .optimized_zero_stride_load,
            .sha,
            .smaia,
            .ssaia,
            .ssccptr,
            .sscofpmf,
            .sscounterenw,
            .ssnpm,
            .ssstrict,
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
            .unaligned_scalar_mem,
            .unaligned_vector_mem,
            .use_postra_scheduler,
            .v,
            .za64rs,
            .zawrs,
            .zcb,
            .zcmop,
            .zfa,
            .zfh,
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
            .zvbc,
            .zvfbfwma,
            .zvfh,
            .zvkng,
            .zvl256b,
        }),
    };
    pub const veyron_v1: CpuModel = .{
        .name = "veyron_v1",
        .llvm_name = "veyron-v1",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .auipc_addi_fusion,
            .c,
            .d,
            .i,
            .ld_add_fusion,
            .lui_addi_fusion,
            .m,
            .shifted_zextw_fusion,
            .ventana_veyron,
            .xventanacondops,
            .zba,
            .zbb,
            .zbc,
            .zbs,
            .zexth_fusion,
            .zextw_fusion,
            .zicbom,
            .zicbop,
            .zicboz,
            .zicntr,
            .zifencei,
            .zihintpause,
            .zihpm,
        }),
    };
    pub const xiangshan_nanhu: CpuModel = .{
        .name = "xiangshan_nanhu",
        .llvm_name = "xiangshan-nanhu",
        .features = featureSet(&[_]Feature{
            .@"64bit",
            .a,
            .c,
            .d,
            .i,
            .m,
            .no_default_unroll,
            .shifted_zextw_fusion,
            .svinval,
            .zba,
            .zbb,
            .zbc,
            .zbs,
            .zexth_fusion,
            .zextw_fusion,
            .zicbom,
            .zicboz,
            .zifencei,
            .zkn,
            .zksed,
            .zksh,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    backchain,
    bear_enhancement,
    concurrent_functions,
    deflate_conversion,
    dfp_packed_conversion,
    dfp_zoned_conversion,
    distinct_ops,
    enhanced_dat_2,
    enhanced_sort,
    execution_hint,
    fast_serialization,
    fp_extension,
    guarded_storage,
    high_word,
    insert_reference_bits_multiple,
    interlocked_access1,
    load_and_trap,
    load_and_zero_rightmost_byte,
    load_store_on_cond,
    load_store_on_cond_2,
    message_security_assist_extension12,
    message_security_assist_extension3,
    message_security_assist_extension4,
    message_security_assist_extension5,
    message_security_assist_extension7,
    message_security_assist_extension8,
    message_security_assist_extension9,
    miscellaneous_extensions,
    miscellaneous_extensions_2,
    miscellaneous_extensions_3,
    miscellaneous_extensions_4,
    nnp_assist,
    population_count,
    processor_activity_instrumentation,
    processor_assist,
    reset_dat_protection,
    reset_reference_bits_multiple,
    soft_float,
    test_pending_external_interruption,
    transactional_execution,
    unaligned_symbols,
    vector,
    vector_enhancements_1,
    vector_enhancements_2,
    vector_enhancements_3,
    vector_packed_decimal,
    vector_packed_decimal_enhancement,
    vector_packed_decimal_enhancement_2,
    vector_packed_decimal_enhancement_3,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.backchain)] = .{
        .llvm_name = "backchain",
        .description = "Store the address of the caller's frame into the callee's stack frame",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bear_enhancement)] = .{
        .llvm_name = "bear-enhancement",
        .description = "Assume that the BEAR-enhancement facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.concurrent_functions)] = .{
        .llvm_name = "concurrent-functions",
        .description = "Assume that the concurrent-functions facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.deflate_conversion)] = .{
        .llvm_name = "deflate-conversion",
        .description = "Assume that the deflate-conversion facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dfp_packed_conversion)] = .{
        .llvm_name = "dfp-packed-conversion",
        .description = "Assume that the DFP packed-conversion facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.dfp_zoned_conversion)] = .{
        .llvm_name = "dfp-zoned-conversion",
        .description = "Assume that the DFP zoned-conversion facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.distinct_ops)] = .{
        .llvm_name = "distinct-ops",
        .description = "Assume that the distinct-operands facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.enhanced_dat_2)] = .{
        .llvm_name = "enhanced-dat-2",
        .description = "Assume that the enhanced-DAT facility 2 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.enhanced_sort)] = .{
        .llvm_name = "enhanced-sort",
        .description = "Assume that the enhanced-sort facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.execution_hint)] = .{
        .llvm_name = "execution-hint",
        .description = "Assume that the execution-hint facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fast_serialization)] = .{
        .llvm_name = "fast-serialization",
        .description = "Assume that the fast-serialization facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fp_extension)] = .{
        .llvm_name = "fp-extension",
        .description = "Assume that the floating-point extension facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.guarded_storage)] = .{
        .llvm_name = "guarded-storage",
        .description = "Assume that the guarded-storage facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.high_word)] = .{
        .llvm_name = "high-word",
        .description = "Assume that the high-word facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.insert_reference_bits_multiple)] = .{
        .llvm_name = "insert-reference-bits-multiple",
        .description = "Assume that the insert-reference-bits-multiple facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.interlocked_access1)] = .{
        .llvm_name = "interlocked-access1",
        .description = "Assume that interlocked-access facility 1 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.load_and_trap)] = .{
        .llvm_name = "load-and-trap",
        .description = "Assume that the load-and-trap facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.load_and_zero_rightmost_byte)] = .{
        .llvm_name = "load-and-zero-rightmost-byte",
        .description = "Assume that the load-and-zero-rightmost-byte facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.load_store_on_cond)] = .{
        .llvm_name = "load-store-on-cond",
        .description = "Assume that the load/store-on-condition facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.load_store_on_cond_2)] = .{
        .llvm_name = "load-store-on-cond-2",
        .description = "Assume that the load/store-on-condition facility 2 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.message_security_assist_extension12)] = .{
        .llvm_name = "message-security-assist-extension12",
        .description = "Assume that the message-security-assist extension facility 12 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.message_security_assist_extension3)] = .{
        .llvm_name = "message-security-assist-extension3",
        .description = "Assume that the message-security-assist extension facility 3 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.message_security_assist_extension4)] = .{
        .llvm_name = "message-security-assist-extension4",
        .description = "Assume that the message-security-assist extension facility 4 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.message_security_assist_extension5)] = .{
        .llvm_name = "message-security-assist-extension5",
        .description = "Assume that the message-security-assist extension facility 5 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.message_security_assist_extension7)] = .{
        .llvm_name = "message-security-assist-extension7",
        .description = "Assume that the message-security-assist extension facility 7 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.message_security_assist_extension8)] = .{
        .llvm_name = "message-security-assist-extension8",
        .description = "Assume that the message-security-assist extension facility 8 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.message_security_assist_extension9)] = .{
        .llvm_name = "message-security-assist-extension9",
        .description = "Assume that the message-security-assist extension facility 9 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.miscellaneous_extensions)] = .{
        .llvm_name = "miscellaneous-extensions",
        .description = "Assume that the miscellaneous-extensions facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.miscellaneous_extensions_2)] = .{
        .llvm_name = "miscellaneous-extensions-2",
        .description = "Assume that the miscellaneous-extensions facility 2 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.miscellaneous_extensions_3)] = .{
        .llvm_name = "miscellaneous-extensions-3",
        .description = "Assume that the miscellaneous-extensions facility 3 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.miscellaneous_extensions_4)] = .{
        .llvm_name = "miscellaneous-extensions-4",
        .description = "Assume that the miscellaneous-extensions facility 4 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.nnp_assist)] = .{
        .llvm_name = "nnp-assist",
        .description = "Assume that the NNP-assist facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.population_count)] = .{
        .llvm_name = "population-count",
        .description = "Assume that the population-count facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.processor_activity_instrumentation)] = .{
        .llvm_name = "processor-activity-instrumentation",
        .description = "Assume that the processor-activity-instrumentation facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.processor_assist)] = .{
        .llvm_name = "processor-assist",
        .description = "Assume that the processor-assist facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reset_dat_protection)] = .{
        .llvm_name = "reset-dat-protection",
        .description = "Assume that the reset-DAT-protection facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reset_reference_bits_multiple)] = .{
        .llvm_name = "reset-reference-bits-multiple",
        .description = "Assume that the reset-reference-bits-multiple facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.soft_float)] = .{
        .llvm_name = "soft-float",
        .description = "Use software emulation for floating point",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.test_pending_external_interruption)] = .{
        .llvm_name = "test-pending-external-interruption",
        .description = "Assume that the test-pending-external-interruption facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.transactional_execution)] = .{
        .llvm_name = "transactional-execution",
        .description = "Assume that the transactional-execution facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.unaligned_symbols)] = .{
        .llvm_name = "unaligned-symbols",
        .description = "Don't apply the ABI minimum alignment to external symbols.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector)] = .{
        .llvm_name = "vector",
        .description = "Assume that the vectory facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector_enhancements_1)] = .{
        .llvm_name = "vector-enhancements-1",
        .description = "Assume that the vector enhancements facility 1 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector_enhancements_2)] = .{
        .llvm_name = "vector-enhancements-2",
        .description = "Assume that the vector enhancements facility 2 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector_enhancements_3)] = .{
        .llvm_name = "vector-enhancements-3",
        .description = "Assume that the vector enhancements facility 3 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector_packed_decimal)] = .{
        .llvm_name = "vector-packed-decimal",
        .description = "Assume that the vector packed decimal facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector_packed_decimal_enhancement)] = .{
        .llvm_name = "vector-packed-decimal-enhancement",
        .description = "Assume that the vector packed decimal enhancement facility is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector_packed_decimal_enhancement_2)] = .{
        .llvm_name = "vector-packed-decimal-enhancement-2",
        .description = "Assume that the vector packed decimal enhancement facility 2 is installed",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vector_packed_decimal_enhancement_3)] = .{
        .llvm_name = "vector-packed-decimal-enhancement-3",
        .description = "Assume that the vector packed decimal enhancement facility 3 is installed",
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
    pub const arch10: CpuModel = .{
        .name = "arch10",
        .llvm_name = "arch10",
        .features = featureSet(&[_]Feature{
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .high_word,
            .interlocked_access1,
            .load_and_trap,
            .load_store_on_cond,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .miscellaneous_extensions,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .transactional_execution,
        }),
    };
    pub const arch11: CpuModel = .{
        .name = "arch11",
        .llvm_name = "arch11",
        .features = featureSet(&[_]Feature{
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .high_word,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .miscellaneous_extensions,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .transactional_execution,
            .vector,
        }),
    };
    pub const arch12: CpuModel = .{
        .name = "arch12",
        .llvm_name = "arch12",
        .features = featureSet(&[_]Feature{
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .guarded_storage,
            .high_word,
            .insert_reference_bits_multiple,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .message_security_assist_extension7,
            .message_security_assist_extension8,
            .miscellaneous_extensions,
            .miscellaneous_extensions_2,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .test_pending_external_interruption,
            .transactional_execution,
            .vector,
            .vector_enhancements_1,
            .vector_packed_decimal,
        }),
    };
    pub const arch13: CpuModel = .{
        .name = "arch13",
        .llvm_name = "arch13",
        .features = featureSet(&[_]Feature{
            .deflate_conversion,
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .enhanced_sort,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .guarded_storage,
            .high_word,
            .insert_reference_bits_multiple,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .message_security_assist_extension7,
            .message_security_assist_extension8,
            .message_security_assist_extension9,
            .miscellaneous_extensions,
            .miscellaneous_extensions_2,
            .miscellaneous_extensions_3,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .test_pending_external_interruption,
            .transactional_execution,
            .vector,
            .vector_enhancements_1,
            .vector_enhancements_2,
            .vector_packed_decimal,
            .vector_packed_decimal_enhancement,
        }),
    };
    pub const arch14: CpuModel = .{
        .name = "arch14",
        .llvm_name = "arch14",
        .features = featureSet(&[_]Feature{
            .bear_enhancement,
            .deflate_conversion,
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .enhanced_sort,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .guarded_storage,
            .high_word,
            .insert_reference_bits_multiple,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .message_security_assist_extension7,
            .message_security_assist_extension8,
            .message_security_assist_extension9,
            .miscellaneous_extensions,
            .miscellaneous_extensions_2,
            .miscellaneous_extensions_3,
            .nnp_assist,
            .population_count,
            .processor_activity_instrumentation,
            .processor_assist,
            .reset_dat_protection,
            .reset_reference_bits_multiple,
            .test_pending_external_interruption,
            .transactional_execution,
            .vector,
            .vector_enhancements_1,
            .vector_enhancements_2,
            .vector_packed_decimal,
            .vector_packed_decimal_enhancement,
            .vector_packed_decimal_enhancement_2,
        }),
    };
    pub const arch15: CpuModel = .{
        .name = "arch15",
        .llvm_name = "arch15",
        .features = featureSet(&[_]Feature{
            .bear_enhancement,
            .concurrent_functions,
            .deflate_conversion,
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .enhanced_sort,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .guarded_storage,
            .high_word,
            .insert_reference_bits_multiple,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension12,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .message_security_assist_extension7,
            .message_security_assist_extension8,
            .message_security_assist_extension9,
            .miscellaneous_extensions,
            .miscellaneous_extensions_2,
            .miscellaneous_extensions_3,
            .miscellaneous_extensions_4,
            .nnp_assist,
            .population_count,
            .processor_activity_instrumentation,
            .processor_assist,
            .reset_dat_protection,
            .reset_reference_bits_multiple,
            .test_pending_external_interruption,
            .transactional_execution,
            .vector,
            .vector_enhancements_1,
            .vector_enhancements_2,
            .vector_enhancements_3,
            .vector_packed_decimal,
            .vector_packed_decimal_enhancement,
            .vector_packed_decimal_enhancement_2,
            .vector_packed_decimal_enhancement_3,
        }),
    };
    pub const arch8: CpuModel = .{
        .name = "arch8",
        .llvm_name = "arch8",
        .features = featureSet(&[_]Feature{}),
    };
    pub const arch9: CpuModel = .{
        .name = "arch9",
        .llvm_name = "arch9",
        .features = featureSet(&[_]Feature{
            .distinct_ops,
            .fast_serialization,
            .fp_extension,
            .high_word,
            .interlocked_access1,
            .load_store_on_cond,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .population_count,
            .reset_reference_bits_multiple,
        }),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{}),
    };
    pub const z10: CpuModel = .{
        .name = "z10",
        .llvm_name = "z10",
        .features = featureSet(&[_]Feature{}),
    };
    pub const z13: CpuModel = .{
        .name = "z13",
        .llvm_name = "z13",
        .features = featureSet(&[_]Feature{
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .high_word,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .miscellaneous_extensions,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .transactional_execution,
            .vector,
        }),
    };
    pub const z14: CpuModel = .{
        .name = "z14",
        .llvm_name = "z14",
        .features = featureSet(&[_]Feature{
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .guarded_storage,
            .high_word,
            .insert_reference_bits_multiple,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .message_security_assist_extension7,
            .message_security_assist_extension8,
            .miscellaneous_extensions,
            .miscellaneous_extensions_2,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .test_pending_external_interruption,
            .transactional_execution,
            .vector,
            .vector_enhancements_1,
            .vector_packed_decimal,
        }),
    };
    pub const z15: CpuModel = .{
        .name = "z15",
        .llvm_name = "z15",
        .features = featureSet(&[_]Feature{
            .deflate_conversion,
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .enhanced_sort,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .guarded_storage,
            .high_word,
            .insert_reference_bits_multiple,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .message_security_assist_extension7,
            .message_security_assist_extension8,
            .message_security_assist_extension9,
            .miscellaneous_extensions,
            .miscellaneous_extensions_2,
            .miscellaneous_extensions_3,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .test_pending_external_interruption,
            .transactional_execution,
            .vector,
            .vector_enhancements_1,
            .vector_enhancements_2,
            .vector_packed_decimal,
            .vector_packed_decimal_enhancement,
        }),
    };
    pub const z16: CpuModel = .{
        .name = "z16",
        .llvm_name = "z16",
        .features = featureSet(&[_]Feature{
            .bear_enhancement,
            .deflate_conversion,
            .dfp_packed_conversion,
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .enhanced_sort,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .guarded_storage,
            .high_word,
            .insert_reference_bits_multiple,
            .interlocked_access1,
            .load_and_trap,
            .load_and_zero_rightmost_byte,
            .load_store_on_cond,
            .load_store_on_cond_2,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .message_security_assist_extension5,
            .message_security_assist_extension7,
            .message_security_assist_extension8,
            .message_security_assist_extension9,
            .miscellaneous_extensions,
            .miscellaneous_extensions_2,
            .miscellaneous_extensions_3,
            .nnp_assist,
            .population_count,
            .processor_activity_instrumentation,
            .processor_assist,
            .reset_dat_protection,
            .reset_reference_bits_multiple,
            .test_pending_external_interruption,
            .transactional_execution,
            .vector,
            .vector_enhancements_1,
            .vector_enhancements_2,
            .vector_packed_decimal,
            .vector_packed_decimal_enhancement,
            .vector_packed_decimal_enhancement_2,
        }),
    };
    pub const z196: CpuModel = .{
        .name = "z196",
        .llvm_name = "z196",
        .features = featureSet(&[_]Feature{
            .distinct_ops,
            .fast_serialization,
            .fp_extension,
            .high_word,
            .interlocked_access1,
            .load_store_on_cond,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .population_count,
            .reset_reference_bits_multiple,
        }),
    };
    pub const zEC12: CpuModel = .{
        .name = "zEC12",
        .llvm_name = "zEC12",
        .features = featureSet(&[_]Feature{
            .dfp_zoned_conversion,
            .distinct_ops,
            .enhanced_dat_2,
            .execution_hint,
            .fast_serialization,
            .fp_extension,
            .high_word,
            .interlocked_access1,
            .load_and_trap,
            .load_store_on_cond,
            .message_security_assist_extension3,
            .message_security_assist_extension4,
            .miscellaneous_extensions,
            .population_count,
            .processor_assist,
            .reset_reference_bits_multiple,
            .transactional_execution,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    deprecated_v8,
    detectroundchange,
    fix_tn0009,
    fix_tn0010,
    fix_tn0011,
    fix_tn0012,
    fix_tn0013,
    fixallfdivsqrt,
    hard_quad_float,
    hasleoncasa,
    hasumacsmac,
    insertnopload,
    leon,
    leoncyclecounter,
    leonpwrpsr,
    no_fmuls,
    no_fsmuld,
    popc,
    reserve_g1,
    reserve_g2,
    reserve_g3,
    reserve_g4,
    reserve_g5,
    reserve_g6,
    reserve_g7,
    reserve_i0,
    reserve_i1,
    reserve_i2,
    reserve_i3,
    reserve_i4,
    reserve_i5,
    reserve_l0,
    reserve_l1,
    reserve_l2,
    reserve_l3,
    reserve_l4,
    reserve_l5,
    reserve_l6,
    reserve_l7,
    reserve_o0,
    reserve_o1,
    reserve_o2,
    reserve_o3,
    reserve_o4,
    reserve_o5,
    slow_rdpc,
    soft_float,
    soft_mul_div,
    v8plus,
    v9,
    vis,
    vis2,
    vis3,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.deprecated_v8)] = .{
        .llvm_name = "deprecated-v8",
        .description = "Enable deprecated V8 instructions in V9 mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.detectroundchange)] = .{
        .llvm_name = "detectroundchange",
        .description = "LEON3 erratum detection: Detects any rounding mode change request: use only the round-to-nearest rounding mode",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_tn0009)] = .{
        .llvm_name = "fix-tn0009",
        .description = "Enable workaround for errata described in GRLIB-TN-0009",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_tn0010)] = .{
        .llvm_name = "fix-tn0010",
        .description = "Enable workaround for errata described in GRLIB-TN-0010",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_tn0011)] = .{
        .llvm_name = "fix-tn0011",
        .description = "Enable workaround for errata described in GRLIB-TN-0011",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_tn0012)] = .{
        .llvm_name = "fix-tn0012",
        .description = "Enable workaround for errata described in GRLIB-TN-0012",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fix_tn0013)] = .{
        .llvm_name = "fix-tn0013",
        .description = "Enable workaround for errata described in GRLIB-TN-0013",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.fixallfdivsqrt)] = .{
        .llvm_name = "fixallfdivsqrt",
        .description = "LEON erratum fix: Fix FDIVS/FDIVD/FSQRTS/FSQRTD instructions with NOPs and floating-point store",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hard_quad_float)] = .{
        .llvm_name = "hard-quad-float",
        .description = "Enable quad-word floating point instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hasleoncasa)] = .{
        .llvm_name = "hasleoncasa",
        .description = "Enable CASA instruction for LEON3 and LEON4 processors",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.hasumacsmac)] = .{
        .llvm_name = "hasumacsmac",
        .description = "Enable UMAC and SMAC for LEON3 and LEON4 processors",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.insertnopload)] = .{
        .llvm_name = "insertnopload",
        .description = "LEON3 erratum fix: Insert a NOP instruction after every single-cycle load instruction when the next instruction is another load/store instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.leon)] = .{
        .llvm_name = "leon",
        .description = "Enable LEON extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.leoncyclecounter)] = .{
        .llvm_name = "leoncyclecounter",
        .description = "Use the Leon cycle counter register",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.leonpwrpsr)] = .{
        .llvm_name = "leonpwrpsr",
        .description = "Enable the PWRPSR instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_fmuls)] = .{
        .llvm_name = "no-fmuls",
        .description = "Disable the fmuls instruction.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.no_fsmuld)] = .{
        .llvm_name = "no-fsmuld",
        .description = "Disable the fsmuld instruction.",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.popc)] = .{
        .llvm_name = "popc",
        .description = "Use the popc (population count) instruction",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_g1)] = .{
        .llvm_name = "reserve-g1",
        .description = "Reserve G1, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_g2)] = .{
        .llvm_name = "reserve-g2",
        .description = "Reserve G2, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_g3)] = .{
        .llvm_name = "reserve-g3",
        .description = "Reserve G3, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_g4)] = .{
        .llvm_name = "reserve-g4",
        .description = "Reserve G4, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_g5)] = .{
        .llvm_name = "reserve-g5",
        .description = "Reserve G5, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_g6)] = .{
        .llvm_name = "reserve-g6",
        .description = "Reserve G6, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_g7)] = .{
        .llvm_name = "reserve-g7",
        .description = "Reserve G7, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_i0)] = .{
        .llvm_name = "reserve-i0",
        .description = "Reserve I0, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_i1)] = .{
        .llvm_name = "reserve-i1",
        .description = "Reserve I1, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_i2)] = .{
        .llvm_name = "reserve-i2",
        .description = "Reserve I2, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_i3)] = .{
        .llvm_name = "reserve-i3",
        .description = "Reserve I3, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_i4)] = .{
        .llvm_name = "reserve-i4",
        .description = "Reserve I4, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_i5)] = .{
        .llvm_name = "reserve-i5",
        .description = "Reserve I5, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l0)] = .{
        .llvm_name = "reserve-l0",
        .description = "Reserve L0, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l1)] = .{
        .llvm_name = "reserve-l1",
        .description = "Reserve L1, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l2)] = .{
        .llvm_name = "reserve-l2",
        .description = "Reserve L2, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l3)] = .{
        .llvm_name = "reserve-l3",
        .description = "Reserve L3, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l4)] = .{
        .llvm_name = "reserve-l4",
        .description = "Reserve L4, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l5)] = .{
        .llvm_name = "reserve-l5",
        .description = "Reserve L5, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l6)] = .{
        .llvm_name = "reserve-l6",
        .description = "Reserve L6, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_l7)] = .{
        .llvm_name = "reserve-l7",
        .description = "Reserve L7, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_o0)] = .{
        .llvm_name = "reserve-o0",
        .description = "Reserve O0, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_o1)] = .{
        .llvm_name = "reserve-o1",
        .description = "Reserve O1, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_o2)] = .{
        .llvm_name = "reserve-o2",
        .description = "Reserve O2, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_o3)] = .{
        .llvm_name = "reserve-o3",
        .description = "Reserve O3, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_o4)] = .{
        .llvm_name = "reserve-o4",
        .description = "Reserve O4, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.reserve_o5)] = .{
        .llvm_name = "reserve-o5",
        .description = "Reserve O5, making it unavailable as a GPR",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.slow_rdpc)] = .{
        .llvm_name = "slow-rdpc",
        .description = "rd %pc, %XX is slow",
        .dependencies = featureSet(&[_]Feature{
            .v9,
        }),
    };
    result[@intFromEnum(Feature.soft_float)] = .{
        .llvm_name = "soft-float",
        .description = "Use software emulation for floating point",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.soft_mul_div)] = .{
        .llvm_name = "soft-mul-div",
        .description = "Use software emulation for integer multiply and divide",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v8plus)] = .{
        .llvm_name = "v8plus",
        .description = "Enable V8+ mode, allowing use of 64-bit V9 instructions in 32-bit code",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v9)] = .{
        .llvm_name = "v9",
        .description = "Enable SPARC-V9 instructions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vis)] = .{
        .llvm_name = "vis",
        .description = "Enable UltraSPARC Visual Instruction Set extensions",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vis2)] = .{
        .llvm_name = "vis2",
        .description = "Enable Visual Instruction Set extensions II",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.vis3)] = .{
        .llvm_name = "vis3",
        .description = "Enable Visual Instruction Set extensions III",
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
    pub const at697e: CpuModel = .{
        .name = "at697e",
        .llvm_name = "at697e",
        .features = featureSet(&[_]Feature{
            .insertnopload,
            .leon,
        }),
    };
    pub const at697f: CpuModel = .{
        .name = "at697f",
        .llvm_name = "at697f",
        .features = featureSet(&[_]Feature{
            .insertnopload,
            .leon,
        }),
    };
    pub const f934: CpuModel = .{
        .name = "f934",
        .llvm_name = "f934",
        .features = featureSet(&[_]Feature{}),
    };
    pub const generic: CpuModel = .{
        .name = "generic",
        .llvm_name = "generic",
        .features = featureSet(&[_]Feature{}),
    };
    pub const gr712rc: CpuModel = .{
        .name = "gr712rc",
        .llvm_name = "gr712rc",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const gr740: CpuModel = .{
        .name = "gr740",
        .llvm_name = "gr740",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .hasumacsmac,
            .leon,
            .leoncyclecounter,
            .leonpwrpsr,
        }),
    };
    pub const hypersparc: CpuModel = .{
        .name = "hypersparc",
        .llvm_name = "hypersparc",
        .features = featureSet(&[_]Feature{}),
    };
    pub const leon2: CpuModel = .{
        .name = "leon2",
        .llvm_name = "leon2",
        .features = featureSet(&[_]Feature{
            .leon,
        }),
    };
    pub const leon3: CpuModel = .{
        .name = "leon3",
        .llvm_name = "leon3",
        .features = featureSet(&[_]Feature{
            .hasumacsmac,
            .leon,
        }),
    };
    pub const leon4: CpuModel = .{
        .name = "leon4",
        .llvm_name = "leon4",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .hasumacsmac,
            .leon,
        }),
    };
    pub const ma2080: CpuModel = .{
        .name = "ma2080",
        .llvm_name = "ma2080",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2085: CpuModel = .{
        .name = "ma2085",
        .llvm_name = "ma2085",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2100: CpuModel = .{
        .name = "ma2100",
        .llvm_name = "ma2100",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2150: CpuModel = .{
        .name = "ma2150",
        .llvm_name = "ma2150",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2155: CpuModel = .{
        .name = "ma2155",
        .llvm_name = "ma2155",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2450: CpuModel = .{
        .name = "ma2450",
        .llvm_name = "ma2450",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2455: CpuModel = .{
        .name = "ma2455",
        .llvm_name = "ma2455",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2480: CpuModel = .{
        .name = "ma2480",
        .llvm_name = "ma2480",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2485: CpuModel = .{
        .name = "ma2485",
        .llvm_name = "ma2485",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2x5x: CpuModel = .{
        .name = "ma2x5x",
        .llvm_name = "ma2x5x",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const ma2x8x: CpuModel = .{
        .name = "ma2x8x",
        .llvm_name = "ma2x8x",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const myriad2: CpuModel = .{
        .name = "myriad2",
        .llvm_name = "myriad2",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const myriad2_1: CpuModel = .{
        .name = "myriad2_1",
        .llvm_name = "myriad2.1",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const myriad2_2: CpuModel = .{
        .name = "myriad2_2",
        .llvm_name = "myriad2.2",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const myriad2_3: CpuModel = .{
        .name = "myriad2_3",
        .llvm_name = "myriad2.3",
        .features = featureSet(&[_]Feature{
            .hasleoncasa,
            .leon,
        }),
    };
    pub const niagara: CpuModel = .{
        .name = "niagara",
        .llvm_name = "niagara",
        .features = featureSet(&[_]Feature{
            .deprecated_v8,
            .v9,
            .vis,
            .vis2,
        }),
    };
    pub const niagara2: CpuModel = .{
        .name = "niagara2",
        .llvm_name = "niagara2",
        .features = featureSet(&[_]Feature{
            .deprecated_v8,
            .popc,
            .v9,
            .vis,
            .vis2,
        }),
    };
    pub const niagara3: CpuModel = .{
        .name = "niagara3",
        .llvm_name = "niagara3",
        .features = featureSet(&[_]Feature{
            .deprecated_v8,
            .popc,
            .v9,
            .vis,
            .vis2,
        }),
    };
    pub const niagara4: CpuModel = .{
        .name = "niagara4",
        .llvm_name = "niagara4",
        .features = featureSet(&[_]Feature{
            .deprecated_v8,
            .popc,
            .v9,
            .vis,
            .vis2,
            .vis3,
        }),
    };
    pub const sparclet: CpuModel = .{
        .name = "sparclet",
        .llvm_name = "sparclet",
        .features = featureSet(&[_]Feature{}),
    };
    pub const sparclite: CpuModel = .{
        .name = "sparclite",
        .llvm_name = "sparclite",
        .features = featureSet(&[_]Feature{}),
    };
    pub const sparclite86x: CpuModel = .{
        .name = "sparclite86x",
        .llvm_name = "sparclite86x",
        .features = featureSet(&[_]Feature{}),
    };
    pub const supersparc: CpuModel = .{
        .name = "supersparc",
        .llvm_name = "supersparc",
        .features = featureSet(&[_]Feature{}),
    };
    pub const tsc701: CpuModel = .{
        .name = "tsc701",
        .llvm_name = "tsc701",
        .features = featureSet(&[_]Feature{}),
    };
    pub const ultrasparc: CpuModel = .{
        .name = "ultrasparc",
        .llvm_name = "ultrasparc",
        .features = featureSet(&[_]Feature{
            .deprecated_v8,
            .slow_rdpc,
            .vis,
        }),
    };
    pub const ultrasparc3: CpuModel = .{
        .name = "ultrasparc3",
        .llvm_name = "ultrasparc3",
        .features = featureSet(&[_]Feature{
            .deprecated_v8,
            .slow_rdpc,
            .vis,
            .vis2,
        }),
    };
    pub const ut699: CpuModel = .{
        .name = "ut699",
        .llvm_name = "ut699",
        .features = featureSet(&[_]Feature{
            .fixallfdivsqrt,
            .insertnopload,
            .leon,
            .no_fmuls,
            .no_fsmuld,
        }),
    };
    pub const v7: CpuModel = .{
        .name = "v7",
        .llvm_name = "v7",
        .features = featureSet(&[_]Feature{
            .no_fsmuld,
            .soft_mul_div,
        }),
    };
    pub const v8: CpuModel = .{
        .name = "v8",
        .llvm_name = "v8",
        .features = featureSet(&[_]Feature{}),
    };
    pub const v9: CpuModel = .{
        .name = "v9",
        .llvm_name = "v9",
        .features = featureSet(&[_]Feature{
            .v9,
        }),
    };
};
const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    v1_0,
    v1_1,
    v1_2,
    v1_3,
    v1_4,
    v1_5,
    v1_6,
    int64,
    float16,
    float64,
    matrix,
    storage_push_constant16,
    arbitrary_precision_integers,
    kernel,
    addresses,
    generic_pointer,
    vector16,
    shader,
    physical_storage_buffer,
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
    result[@intFromEnum(Feature.v1_0)] = .{
        .llvm_name = null,
        .description = "Enable version 1.0",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.v1_1)] = .{
        .llvm_name = null,
        .description = "Enable version 1.1",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
    };
    result[@intFromEnum(Feature.v1_2)] = .{
        .llvm_name = null,
        .description = "Enable version 1.2",
        .dependencies = featureSet(&[_]Feature{.v1_1}),
    };
    result[@intFromEnum(Feature.v1_3)] = .{
        .llvm_name = null,
        .description = "Enable version 1.3",
        .dependencies = featureSet(&[_]Feature{.v1_2}),
    };
    result[@intFromEnum(Feature.v1_4)] = .{
        .llvm_name = null,
        .description = "Enable version 1.4",
        .dependencies = featureSet(&[_]Feature{.v1_3}),
    };
    result[@intFromEnum(Feature.v1_5)] = .{
        .llvm_name = null,
        .description = "Enable version 1.5",
        .dependencies = featureSet(&[_]Feature{.v1_4}),
    };
    result[@intFromEnum(Feature.v1_6)] = .{
        .llvm_name = null,
        .description = "Enable version 1.6",
        .dependencies = featureSet(&[_]Feature{.v1_5}),
    };
    result[@intFromEnum(Feature.int64)] = .{
        .llvm_name = null,
        .description = "Enable Int64 capability",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
    };
    result[@intFromEnum(Feature.float16)] = .{
        .llvm_name = null,
        .description = "Enable Float16 capability",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
    };
    result[@intFromEnum(Feature.float64)] = .{
        .llvm_name = null,
        .description = "Enable Float64 capability",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
    };
    result[@intFromEnum(Feature.matrix)] = .{
        .llvm_name = null,
        .description = "Enable Matrix capability",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
    };
    result[@intFromEnum(Feature.storage_push_constant16)] = .{
        .llvm_name = null,
        .description = "Enable SPV_KHR_16bit_storage extension and the StoragePushConstant16 capability",
        .dependencies = featureSet(&[_]Feature{.v1_3}),
    };
    result[@intFromEnum(Feature.arbitrary_precision_integers)] = .{
        .llvm_name = null,
        .description = "Enable SPV_INTEL_arbitrary_precision_integers extension and the ArbitraryPrecisionIntegersINTEL capability",
        .dependencies = featureSet(&[_]Feature{.v1_5}),
    };
    result[@intFromEnum(Feature.kernel)] = .{
        .llvm_name = null,
        .description = "Enable Kernel capability",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
    };
    result[@intFromEnum(Feature.addresses)] = .{
        .llvm_name = null,
        .description = "Enable Addresses capability",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
    };
    result[@intFromEnum(Feature.generic_pointer)] = .{
        .llvm_name = null,
        .description = "Enable GenericPointer capability",
        .dependencies = featureSet(&[_]Feature{ .v1_0, .addresses }),
    };
    result[@intFromEnum(Feature.vector16)] = .{
        .llvm_name = null,
        .description = "Enable Vector16 capability",
        .dependencies = featureSet(&[_]Feature{ .v1_0, .kernel }),
    };
    result[@intFromEnum(Feature.shader)] = .{
        .llvm_name = null,
        .description = "Enable Shader capability",
        .dependencies = featureSet(&[_]Feature{ .v1_0, .matrix }),
    };
    result[@intFromEnum(Feature.physical_storage_buffer)] = .{
        .llvm_name = null,
        .description = "Enable SPV_KHR_physical_storage_buffer extension and the PhysicalStorageBufferAddresses capability",
        .dependencies = featureSet(&[_]Feature{.v1_0}),
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
        .features = featureSet(&[_]Feature{.v1_0}),
    };

    pub const vulkan_v1_2: CpuModel = .{
        .name = "vulkan_v1_2",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{ .v1_5, .shader, .physical_storage_buffer }),
    };

    pub const opencl_v2: CpuModel = .{
        .name = "opencl_v2",
        .llvm_name = null,
        .features = featureSet(&[_]Feature{ .v1_2, .kernel, .addresses, .generic_pointer }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    vpu,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.vpu)] = .{
        .llvm_name = "vpu",
        .description = "Enable the VPU",
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
            .vpu,
        }),
    };
};
//! This file is auto-generated by tools/update_cpu_features.zig.

const std = @import("../std.zig");
const CpuFeature = std.Target.Cpu.Feature;
const CpuModel = std.Target.Cpu.Model;

pub const Feature = enum {
    atomics,
    bulk_memory,
    bulk_memory_opt,
    call_indirect_overlong,
    exception_handling,
    extended_const,
    fp16,
    multimemory,
    multivalue,
    mutable_globals,
    nontrapping_bulk_memory_len0,
    nontrapping_fptoint,
    reference_types,
    relaxed_simd,
    sign_ext,
    simd128,
    tail_call,
    wide_arithmetic,
};

pub const featureSet = CpuFeature.FeatureSetFns(Feature).featureSet;
pub const featureSetHas = CpuFeature.FeatureSetFns(Feature).featureSetHas;
pub const featureSetHasAny = CpuFeature.FeatureSetFns(Feature).featureSetHasAny;
pub const featureSetHasAll = CpuFeature.FeatureSetFns(Feature).featureSetHasAll;

pub const all_features = blk: {
    const len = @typeInfo(Feature).@"enum".fields.len;
    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
    var result: [len]CpuFeature = undefined;
    result[@intFromEnum(Feature.atomics)] = .{
        .llvm_name = "atomics",
        .description = "Enable Atomics",
        .dependencies = featureSet(&[_]Feature{}),
    };
    result[@intFromEnum(Feature.bulk_memory)] = .{
        .llvm_name = "bulk-memory",
        .description = "Enable bulk memory operations",
        .dependencies = featureSet(&[_]Feature{
            .bulk_memory_opt,
        }),
    };
    result[@intFromEnum(Feature.bulk_memo```
