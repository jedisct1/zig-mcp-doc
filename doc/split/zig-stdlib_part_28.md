```
x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    var result: [60]u8 = undefined;
    const key = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const nonce = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 };

    ChaCha20With64BitNonce.xor(result[0..], m[0..], 0, key, nonce);
    try testing.expectEqualSlices(u8, &expected_result, &result);
}

test "test vector 4" {
    const expected_result = [_]u8{
        0xef, 0x3f, 0xdf, 0xd6, 0xc6, 0x15, 0x78, 0xfb,
        0xf5, 0xcf, 0x35, 0xbd, 0x3d, 0xd3, 0x3b, 0x80,
        0x09, 0x63, 0x16, 0x34, 0xd2, 0x1e, 0x42, 0xac,
        0x33, 0x96, 0x0b, 0xd1, 0x38, 0xe5, 0x0d, 0x32,
        0x11, 0x1e, 0x4c, 0xaf, 0x23, 0x7e, 0xe5, 0x3c,
        0xa8, 0xad, 0x64, 0x26, 0x19, 0x4a, 0x88, 0x54,
        0x5d, 0xdc, 0x49, 0x7a, 0x0b, 0x46, 0x6e, 0x7d,
        0x6b, 0xbd, 0xb0, 0x04, 0x1b, 0x2f, 0x58, 0x6b,
    };
    const m = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    var result: [64]u8 = undefined;
    const key = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const nonce = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };

    ChaCha20With64BitNonce.xor(result[0..], m[0..], 0, key, nonce);
    try testing.expectEqualSlices(u8, &expected_result, &result);
}

test "test vector 5" {
    const expected_result = [_]u8{
        0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69,
        0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b, 0xb7, 0x75,
        0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93,
        0xec, 0x01, 0xac, 0x56, 0xf8, 0x5a, 0xc3, 0xc1,
        0x34, 0xa4, 0x54, 0x7b, 0x73, 0x3b, 0x46, 0x41,
        0x30, 0x42, 0xc9, 0x44, 0x00, 0x49, 0x17, 0x69,
        0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1,
        0x59, 0x16, 0x15, 0x5c, 0x2b, 0xe8, 0x24, 0x1a,

        0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc, 0x35, 0x94,
        0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66,
        0x89, 0xde, 0x95, 0x26, 0x49, 0x86, 0xd9, 0x58,
        0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd,
        0x9a, 0x5a, 0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56,
        0x3e, 0xb9, 0xb3, 0xa4, 0xa4, 0x72, 0xf8, 0x2e,
        0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e,
        0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0, 0x31, 0xc7,

        0x9d, 0xb9, 0xd4, 0xf7, 0xc7, 0xa8, 0x99, 0x15,
        0x1b, 0x9a, 0x47, 0x50, 0x32, 0xb6, 0x3f, 0xc3,
        0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a,
        0x97, 0xa5, 0xf5, 0x76, 0xfe, 0x06, 0x40, 0x25,
        0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5,
        0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69,
        0x59, 0x66, 0x09, 0x96, 0x54, 0x6c, 0xc9, 0xc4,
        0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7,

        0x0e, 0xaf, 0x46, 0xf7, 0x6d, 0xad, 0x39, 0x79,
        0xe5, 0xc5, 0x36, 0x0c, 0x33, 0x17, 0x16, 0x6a,
        0x1c, 0x89, 0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a,
        0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2,
        0xcc, 0xb2, 0x7d, 0x5a, 0xaa, 0xe0, 0xad, 0x7a,
        0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b, 0x54, 0x09,
        0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a,
        0x6d, 0xeb, 0x3a, 0xb7, 0x8f, 0xab, 0x78, 0xc9,
    };
    const m = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    var result: [256]u8 = undefined;
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    ChaCha20With64BitNonce.xor(result[0..], m[0..], 0, key, nonce);
    try testing.expectEqualSlices(u8, &expected_result, &result);
}

test "seal" {
    {
        const m = "";
        const ad = "";
        const key = [_]u8{
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        };
        const nonce = [_]u8{ 0x7, 0x0, 0x0, 0x0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
        const exp_out = [_]u8{ 0xa0, 0x78, 0x4d, 0x7a, 0x47, 0x16, 0xf3, 0xfe, 0xb4, 0xf6, 0x4e, 0x7f, 0x4b, 0x39, 0xbf, 0x4 };

        var out: [exp_out.len]u8 = undefined;
        ChaCha20Poly1305.encrypt(out[0..m.len], out[m.len..], m, ad, nonce, key);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }
    {
        const m = [_]u8{
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        };
        const ad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
        const key = [_]u8{
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        };
        const nonce = [_]u8{ 0x7, 0x0, 0x0, 0x0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
        const exp_out = [_]u8{
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x8,  0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0xa,  0x9e, 0x6,  0xb,  0x29, 0x5,  0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x3,  0xae, 0xe3, 0x28, 0x9,  0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16, 0x1a, 0xe1, 0xb,  0x59, 0x4f, 0x9,  0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x6,  0x91,
        };

        var out: [exp_out.len]u8 = undefined;
        ChaCha20Poly1305.encrypt(out[0..m.len], out[m.len..], m[0..], ad[0..], nonce, key);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }
}

test "open" {
    {
        const c = [_]u8{ 0xa0, 0x78, 0x4d, 0x7a, 0x47, 0x16, 0xf3, 0xfe, 0xb4, 0xf6, 0x4e, 0x7f, 0x4b, 0x39, 0xbf, 0x4 };
        const ad = "";
        const key = [_]u8{
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        };
        const nonce = [_]u8{ 0x7, 0x0, 0x0, 0x0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
        const exp_out = "";

        var out: [exp_out.len]u8 = undefined;
        try ChaCha20Poly1305.decrypt(out[0..], c[0..exp_out.len], c[exp_out.len..].*, ad[0..], nonce, key);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }
    {
        const c = [_]u8{
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x8,  0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0xa,  0x9e, 0x6,  0xb,  0x29, 0x5,  0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x3,  0xae, 0xe3, 0x28, 0x9,  0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16, 0x1a, 0xe1, 0xb,  0x59, 0x4f, 0x9,  0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x6,  0x91,
        };
        const ad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
        const key = [_]u8{
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        };
        const nonce = [_]u8{ 0x7, 0x0, 0x0, 0x0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
        const exp_out = [_]u8{
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        };

        var out: [exp_out.len]u8 = undefined;
        try ChaCha20Poly1305.decrypt(out[0..], c[0..exp_out.len], c[exp_out.len..].*, ad[0..], nonce, key);
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);

        // corrupting the ciphertext, data, key, or nonce should cause a failure
        var bad_c = c;
        bad_c[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(out[0..], bad_c[0..out.len], bad_c[out.len..].*, ad[0..], nonce, key));
        var bad_ad = ad;
        bad_ad[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(out[0..], c[0..out.len], c[out.len..].*, bad_ad[0..], nonce, key));
        var bad_key = key;
        bad_key[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(out[0..], c[0..out.len], c[out.len..].*, ad[0..], nonce, bad_key));
        var bad_nonce = nonce;
        bad_nonce[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(out[0..], c[0..out.len], c[out.len..].*, ad[0..], bad_nonce, key));
    }
}

test "xchacha20" {
    const key = [_]u8{69} ** 32;
    const nonce = [_]u8{42} ** 24;
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    {
        var c: [m.len]u8 = undefined;
        XChaCha20IETF.xor(c[0..], m[0..], 0, key, nonce);
        var buf: [2 * c.len]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&c)}), "E0A1BCF939654AFDBDC1746EC49832647C19D891F0D1A81FC0C1703B4514BDEA584B512F6908C2C5E9DD18D5CBC1805DE5803FE3B9CA5F193FB8359E91FAB0C3BB40309A292EB1CF49685C65C4A3ADF4F11DB0CD2B6B67FBC174BC2E860E8F769FD3565BBFAD1C845E05A0FED9BE167C240D");
    }
    {
        const ad = "Additional data";
        var c: [m.len + XChaCha20Poly1305.tag_length]u8 = undefined;
        XChaCha20Poly1305.encrypt(c[0..m.len], c[m.len..], m, ad, nonce, key);
        var out: [m.len]u8 = undefined;
        try XChaCha20Poly1305.decrypt(out[0..], c[0..m.len], c[m.len..].*, ad, nonce, key);
        var buf: [2 * c.len]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.fmtSliceHexUpper(&c)}), "994D2DD32333F48E53650C02C7A2ABB8E018B0836D7175AEC779F52E961780768F815C58F1AA52D211498DB89B9216763F569C9433A6BBFCEFB4D4A49387A4C5207FBB3B5A92B5941294DF30588C6740D39DC16FA1F0E634F7246CF7CDCB978E44347D89381B7A74EB7084F754B90BDE9AAF5A94B8F2A85EFD0B50692AE2D425E234");
        try testing.expectEqualSlices(u8, out[0..], m);
        c[0] +%= 1;
        try testing.expectError(error.AuthenticationFailed, XChaCha20Poly1305.decrypt(out[0..], c[0..m.len], c[m.len..].*, ad, nonce, key));
    }
}
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

/// CMAC with AES-128 - RFC 4493 https://www.rfc-editor.org/rfc/rfc4493
pub const CmacAes128 = Cmac(crypto.core.aes.Aes128);

/// NIST Special Publication 800-38B - The CMAC Mode for Authentication
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
pub fn Cmac(comptime BlockCipher: type) type {
    const BlockCipherCtx = @typeInfo(@TypeOf(BlockCipher.initEnc)).@"fn".return_type.?;
    const Block = [BlockCipher.block.block_length]u8;

    return struct {
        const Self = @This();
        pub const key_length = BlockCipher.key_bits / 8;
        pub const block_length = BlockCipher.block.block_length;
        pub const mac_length = block_length;

        cipher_ctx: BlockCipherCtx,
        k1: Block,
        k2: Block,
        buf: Block = [_]u8{0} ** block_length,
        pos: usize = 0,

        pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
            var ctx = Self.init(key);
            ctx.update(msg);
            ctx.final(out);
        }

        pub fn init(key: *const [key_length]u8) Self {
            const cipher_ctx = BlockCipher.initEnc(key.*);
            const zeros = [_]u8{0} ** block_length;
            var k1: Block = undefined;
            cipher_ctx.encrypt(&k1, &zeros);
            k1 = double(k1);
            return Self{
                .cipher_ctx = cipher_ctx,
                .k1 = k1,
                .k2 = double(k1),
            };
        }

        pub fn update(self: *Self, msg: []const u8) void {
            const left = block_length - self.pos;
            var m = msg;
            if (m.len > left) {
                for (self.buf[self.pos..], 0..) |*b, i| b.* ^= m[i];
                m = m[left..];
                self.cipher_ctx.encrypt(&self.buf, &self.buf);
                self.pos = 0;
            }
            while (m.len > block_length) {
                for (self.buf[0..block_length], 0..) |*b, i| b.* ^= m[i];
                m = m[block_length..];
                self.cipher_ctx.encrypt(&self.buf, &self.buf);
                self.pos = 0;
            }
            if (m.len > 0) {
                for (self.buf[self.pos..][0..m.len], 0..) |*b, i| b.* ^= m[i];
                self.pos += m.len;
            }
        }

        pub fn final(self: *Self, out: *[mac_length]u8) void {
            var mac = self.k1;
            if (self.pos < block_length) {
                mac = self.k2;
                mac[self.pos] ^= 0x80;
            }
            for (&mac, 0..) |*b, i| b.* ^= self.buf[i];
            self.cipher_ctx.encrypt(out, &mac);
        }

        fn double(l: Block) Block {
            const Int = std.meta.Int(.unsigned, block_length * 8);
            const l_ = mem.readInt(Int, &l, .big);
            const l_2 = switch (block_length) {
                8 => (l_ << 1) ^ (0x1b & -%(l_ >> 63)), // mod x^64 + x^4 + x^3 + x + 1
                16 => (l_ << 1) ^ (0x87 & -%(l_ >> 127)), // mod x^128 + x^7 + x^2 + x + 1
                32 => (l_ << 1) ^ (0x0425 & -%(l_ >> 255)), // mod x^256 + x^10 + x^5 + x^2 + 1
                64 => (l_ << 1) ^ (0x0125 & -%(l_ >> 511)), // mod x^512 + x^8 + x^5 + x^2 + 1
                else => @compileError("unsupported block length"),
            };
            var l2: Block = undefined;
            mem.writeInt(Int, &l2, l_2, .big);
            return l2;
        }
    };
}

const testing = std.testing;

test "CmacAes128 - Example 1: len = 0" {
    const key = [_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    var msg: [0]u8 = undefined;
    const exp = [_]u8{
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
    };
    var out: [CmacAes128.mac_length]u8 = undefined;
    CmacAes128.create(&out, &msg, &key);
    try testing.expectEqualSlices(u8, &out, &exp);
}

test "CmacAes128 - Example 2: len = 16" {
    const key = [_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const msg = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    const exp = [_]u8{
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
    };
    var out: [CmacAes128.mac_length]u8 = undefined;
    CmacAes128.create(&out, &msg, &key);
    try testing.expectEqualSlices(u8, &out, &exp);
}

test "CmacAes128 - Example 3: len = 40" {
    const key = [_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const msg = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    const exp = [_]u8{
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
    };
    var out: [CmacAes128.mac_length]u8 = undefined;
    CmacAes128.create(&out, &msg, &key);
    try testing.expectEqualSlices(u8, &out, &exp);
}

test "CmacAes128 - Example 4: len = 64" {
    const key = [_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const msg = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const exp = [_]u8{
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
    };
    var out: [CmacAes128.mac_length]u8 = undefined;
    CmacAes128.create(&out, &msg, &key);
    try testing.expectEqualSlices(u8, &out, &exp);
}
pub const asn1 = @import("codecs/asn1.zig");
pub const Base64 = @import("codecs/base64_hex_ct.zig").Base64;
pub const Hex = @import("codecs/base64_hex_ct.zig").Hex;
//! ASN.1 types for public consumption.
const std = @import("std");
pub const der = @import("./asn1/der.zig");
pub const Oid = @import("./asn1/Oid.zig");

pub const Index = u32;

pub const Tag = struct {
    number: Number,
    /// Whether this ASN.1 type contains other ASN.1 types.
    constructed: bool,
    class: Class,

    /// These values apply to class == .universal.
    pub const Number = enum(u16) {
        // 0 is reserved by spec
        boolean = 1,
        integer = 2,
        bitstring = 3,
        octetstring = 4,
        null = 5,
        oid = 6,
        object_descriptor = 7,
        real = 9,
        enumerated = 10,
        embedded = 11,
        string_utf8 = 12,
        oid_relative = 13,
        time = 14,
        // 15 is reserved to mean that the tag is >= 32
        sequence = 16,
        /// Elements may appear in any order.
        sequence_of = 17,
        string_numeric = 18,
        string_printable = 19,
        string_teletex = 20,
        string_videotex = 21,
        string_ia5 = 22,
        utc_time = 23,
        generalized_time = 24,
        string_graphic = 25,
        string_visible = 26,
        string_general = 27,
        string_universal = 28,
        string_char = 29,
        string_bmp = 30,
        date = 31,
        time_of_day = 32,
        date_time = 33,
        duration = 34,
        /// IRI = Internationalized Resource Identifier
        oid_iri = 35,
        oid_iri_relative = 36,
        _,
    };

    pub const Class = enum(u2) {
        universal,
        application,
        context_specific,
        private,
    };

    pub fn init(number: Tag.Number, constructed: bool, class: Tag.Class) Tag {
        return .{ .number = number, .constructed = constructed, .class = class };
    }

    pub fn universal(number: Tag.Number, constructed: bool) Tag {
        return .{ .number = number, .constructed = constructed, .class = .universal };
    }

    pub fn decode(reader: anytype) !Tag {
        const tag1: FirstTag = @bitCast(try reader.readByte());
        var number: u14 = tag1.number;

        if (tag1.number == 15) {
            const tag2: NextTag = @bitCast(try reader.readByte());
            number = tag2.number;
            if (tag2.continues) {
                const tag3: NextTag = @bitCast(try reader.readByte());
                number = (number << 7) + tag3.number;
                if (tag3.continues) return error.InvalidLength;
            }
        }

        return Tag{
            .number = @enumFromInt(number),
            .constructed = tag1.constructed,
            .class = tag1.class,
        };
    }

    pub fn encode(self: Tag, writer: anytype) @TypeOf(writer).Error!void {
        var tag1 = FirstTag{
            .number = undefined,
            .constructed = self.constructed,
            .class = self.class,
        };

        var buffer: [3]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        var writer2 = stream.writer();

        switch (@intFromEnum(self.number)) {
            0...std.math.maxInt(u5) => |n| {
                tag1.number = @intCast(n);
                writer2.writeByte(@bitCast(tag1)) catch unreachable;
            },
            std.math.maxInt(u5) + 1...std.math.maxInt(u7) => |n| {
                tag1.number = 15;
                const tag2 = NextTag{ .number = @intCast(n), .continues = false };
                writer2.writeByte(@bitCast(tag1)) catch unreachable;
                writer2.writeByte(@bitCast(tag2)) catch unreachable;
            },
            else => |n| {
                tag1.number = 15;
                const tag2 = NextTag{ .number = @intCast(n >> 7), .continues = true };
                const tag3 = NextTag{ .number = @truncate(n), .continues = false };
                writer2.writeByte(@bitCast(tag1)) catch unreachable;
                writer2.writeByte(@bitCast(tag2)) catch unreachable;
                writer2.writeByte(@bitCast(tag3)) catch unreachable;
            },
        }

        _ = try writer.write(stream.getWritten());
    }

    const FirstTag = packed struct(u8) { number: u5, constructed: bool, class: Tag.Class };
    const NextTag = packed struct(u8) { number: u7, continues: bool };

    pub fn toExpected(self: Tag) ExpectedTag {
        return ExpectedTag{
            .number = self.number,
            .constructed = self.constructed,
            .class = self.class,
        };
    }

    pub fn fromZig(comptime T: type) Tag {
        switch (@typeInfo(T)) {
            .@"struct", .@"enum", .@"union" => {
                if (@hasDecl(T, "asn1_tag")) return T.asn1_tag;
            },
            else => {},
        }

        switch (@typeInfo(T)) {
            .@"struct", .@"union" => return universal(.sequence, true),
            .bool => return universal(.boolean, false),
            .int => return universal(.integer, false),
            .@"enum" => |e| {
                if (@hasDecl(T, "oids")) return Oid.asn1_tag;
                return universal(if (e.is_exhaustive) .enumerated else .integer, false);
            },
            .optional => |o| return fromZig(o.child),
            .null => return universal(.null, false),
            else => @compileError("cannot map Zig type to asn1_tag " ++ @typeName(T)),
        }
    }
};

test Tag {
    const buf = [_]u8{0xa3};
    var stream = std.io.fixedBufferStream(&buf);
    const t = Tag.decode(stream.reader());
    try std.testing.expectEqual(Tag.init(@enumFromInt(3), true, .context_specific), t);
}

/// A decoded view.
pub const Element = struct {
    tag: Tag,
    slice: Slice,

    pub const Slice = struct {
        start: Index,
        end: Index,

        pub fn len(self: Slice) Index {
            return self.end - self.start;
        }

        pub fn view(self: Slice, bytes: []const u8) []const u8 {
            return bytes[self.start..self.end];
        }
    };

    pub const DecodeError = error{ InvalidLength, EndOfStream };

    /// Safely decode a DER/BER/CER element at `index`:
    /// - Ensures length uses shortest form
    /// - Ensures length is within `bytes`
    /// - Ensures length is less than `std.math.maxInt(Index)`
    pub fn decode(bytes: []const u8, index: Index) DecodeError!Element {
        var stream = std.io.fixedBufferStream(bytes[index..]);
        var reader = stream.reader();

        const tag = try Tag.decode(reader);
        const size_or_len_size = try reader.readByte();

        var start = index + 2;
        var end = start + size_or_len_size;
        // short form between 0-127
        if (size_or_len_size < 128) {
            if (end > bytes.len) return error.InvalidLength;
        } else {
            // long form between 0 and std.math.maxInt(u1024)
            const len_size: u7 = @truncate(size_or_len_size);
            start += len_size;
            if (len_size > @sizeOf(Index)) return error.InvalidLength;

            const len = try reader.readVarInt(Index, .big, len_size);
            if (len < 128) return error.InvalidLength; // should have used short form

            end = std.math.add(Index, start, len) catch return error.InvalidLength;
            if (end > bytes.len) return error.InvalidLength;
        }

        return Element{ .tag = tag, .slice = Slice{ .start = start, .end = end } };
    }
};

test Element {
    const short_form = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x09 };
    try std.testing.expectEqual(Element{
        .tag = Tag.universal(.sequence, true),
        .slice = Element.Slice{ .start = 2, .end = short_form.len },
    }, Element.decode(&short_form, 0));

    const long_form = [_]u8{ 0x30, 129, 129 } ++ [_]u8{0} ** 129;
    try std.testing.expectEqual(Element{
        .tag = Tag.universal(.sequence, true),
        .slice = Element.Slice{ .start = 3, .end = long_form.len },
    }, Element.decode(&long_form, 0));
}

/// For decoding.
pub const ExpectedTag = struct {
    number: ?Tag.Number = null,
    constructed: ?bool = null,
    class: ?Tag.Class = null,

    pub fn init(number: ?Tag.Number, constructed: ?bool, class: ?Tag.Class) ExpectedTag {
        return .{ .number = number, .constructed = constructed, .class = class };
    }

    pub fn primitive(number: ?Tag.Number) ExpectedTag {
        return .{ .number = number, .constructed = false, .class = .universal };
    }

    pub fn match(self: ExpectedTag, tag: Tag) bool {
        if (self.number) |e| {
            if (tag.number != e) return false;
        }
        if (self.constructed) |e| {
            if (tag.constructed != e) return false;
        }
        if (self.class) |e| {
            if (tag.class != e) return false;
        }
        return true;
    }
};

pub const FieldTag = struct {
    number: std.meta.Tag(Tag.Number),
    class: Tag.Class,
    explicit: bool = true,

    pub fn initExplicit(number: std.meta.Tag(Tag.Number), class: Tag.Class) FieldTag {
        return .{ .number = number, .class = class, .explicit = true };
    }

    pub fn initImplicit(number: std.meta.Tag(Tag.Number), class: Tag.Class) FieldTag {
        return .{ .number = number, .class = class, .explicit = false };
    }

    pub fn fromContainer(comptime Container: type, comptime field_name: []const u8) ?FieldTag {
        if (@hasDecl(Container, "asn1_tags") and @hasField(@TypeOf(Container.asn1_tags), field_name)) {
            return @field(Container.asn1_tags, field_name);
        }

        return null;
    }

    pub fn toTag(self: FieldTag) Tag {
        return Tag.init(@enumFromInt(self.number), self.explicit, self.class);
    }
};

pub const BitString = struct {
    /// Number of bits in rightmost byte that are unused.
    right_padding: u3 = 0,
    bytes: []const u8,

    pub fn bitLen(self: BitString) usize {
        return self.bytes.len * 8 - self.right_padding;
    }

    const asn1_tag = Tag.universal(.bitstring, false);

    pub fn decodeDer(decoder: *der.Decoder) !BitString {
        const ele = try decoder.element(asn1_tag.toExpected());
        const bytes = decoder.view(ele);

        if (bytes.len < 1) return error.InvalidBitString;
        const padding = bytes[0];
        if (padding >= 8) return error.InvalidBitString;
        const right_padding: u3 = @intCast(padding);

        // DER requires that unused bits be zero.
        if (@ctz(bytes[bytes.len - 1]) < right_padding) return error.InvalidBitString;

        return BitString{ .bytes = bytes[1..], .right_padding = right_padding };
    }

    pub fn encodeDer(self: BitString, encoder: *der.Encoder) !void {
        try encoder.writer().writeAll(self.bytes);
        try encoder.writer().writeByte(self.right_padding);
        try encoder.length(self.bytes.len + 1);
        try encoder.tag(asn1_tag);
    }
};

pub fn Opaque(comptime tag: Tag) type {
    return struct {
        bytes: []const u8,

        pub fn decodeDer(decoder: *der.Decoder) !@This() {
            const ele = try decoder.element(tag.toExpected());
            if (tag.constructed) decoder.index = ele.slice.end;
            return .{ .bytes = decoder.view(ele) };
        }

        pub fn encodeDer(self: @This(), encoder: *der.Encoder) !void {
            try encoder.tagBytes(tag, self.bytes);
        }
    };
}

/// Use sparingly.
pub const Any = struct {
    tag: Tag,
    bytes: []const u8,

    pub fn decodeDer(decoder: *der.Decoder) !@This() {
        const ele = try decoder.element(ExpectedTag{});
        return .{ .tag = ele.tag, .bytes = decoder.view(ele) };
    }

    pub fn encodeDer(self: @This(), encoder: *der.Encoder) !void {
        try encoder.tagBytes(self.tag, self.bytes);
    }
};

test {
    _ = der;
    _ = Oid;
    _ = @import("asn1/test.zig");
}
//! Distinguised Encoding Rules as defined in X.690 and X.691.
//!
//! Subset of Basic Encoding Rules (BER) which eliminates flexibility in
//! an effort to acheive normality. Used in PKI.
const std = @import("std");
const asn1 = @import("../asn1.zig");

pub const Decoder = @import("der/Decoder.zig");
pub const Encoder = @import("der/Encoder.zig");

pub fn decode(comptime T: type, encoded: []const u8) !T {
    var decoder = Decoder{ .bytes = encoded };
    const res = try decoder.any(T);
    std.debug.assert(decoder.index == encoded.len);
    return res;
}

/// Caller owns returned memory.
pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    try encoder.any(value);
    return try encoder.buffer.toOwnedSlice();
}

test encode {
    // https://lapo.it/asn1js/#MAgGAyoDBAIBBA
    const Value = struct { a: asn1.Oid, b: i32 };
    const test_case = .{
        .value = Value{ .a = asn1.Oid.fromDotComptime("1.2.3.4"), .b = 4 },
        .encoded = &[_]u8{ 0x30, 0x08, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x02, 0x01, 0x04 },
    };
    const allocator = std.testing.allocator;
    const actual = try encode(allocator, test_case.value);
    defer allocator.free(actual);

    try std.testing.expectEqualSlices(u8, test_case.encoded, actual);
}

test decode {
    // https://lapo.it/asn1js/#MAgGAyoDBAIBBA
    const Value = struct { a: asn1.Oid, b: i32 };
    const test_case = .{
        .value = Value{ .a = asn1.Oid.fromDotComptime("1.2.3.4"), .b = 4 },
        .encoded = &[_]u8{ 0x30, 0x08, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x02, 0x01, 0x04 },
    };
    const decoded = try decode(Value, test_case.encoded);

    try std.testing.expectEqualDeep(test_case.value, decoded);
}

test {
    _ = Decoder;
    _ = Encoder;
}
//! An ArrayList that grows backwards. Counts nested prefix length fields
//! in O(n) instead of O(n^depth) at the cost of extra buffering.
//!
//! Laid out in memory like:
//! capacity  |--------------------------|
//! data                   |-------------|
data: []u8,
capacity: usize,
allocator: Allocator,

const ArrayListReverse = @This();
const Error = Allocator.Error;

pub fn init(allocator: Allocator) ArrayListReverse {
    return .{ .data = &.{}, .capacity = 0, .allocator = allocator };
}

pub fn deinit(self: *ArrayListReverse) void {
    self.allocator.free(self.allocatedSlice());
}

pub fn ensureCapacity(self: *ArrayListReverse, new_capacity: usize) Error!void {
    if (self.capacity >= new_capacity) return;

    const old_memory = self.allocatedSlice();
    // Just make a new allocation to not worry about aliasing.
    const new_memory = try self.allocator.alloc(u8, new_capacity);
    @memcpy(new_memory[new_capacity - self.data.len ..], self.data);
    self.allocator.free(old_memory);
    self.data.ptr = new_memory.ptr + new_capacity - self.data.len;
    self.capacity = new_memory.len;
}

pub fn prependSlice(self: *ArrayListReverse, data: []const u8) Error!void {
    try self.ensureCapacity(self.data.len + data.len);
    const old_len = self.data.len;
    const new_len = old_len + data.len;
    assert(new_len <= self.capacity);
    self.data.len = new_len;

    const end = self.data.ptr;
    const begin = end - data.len;
    const slice = begin[0..data.len];
    @memcpy(slice, data);
    self.data.ptr = begin;
}

pub const Writer = std.io.Writer(*ArrayListReverse, Error, prependSliceSize);
/// Warning: This writer writes backwards. `fn print` will NOT work as expected.
pub fn writer(self: *ArrayListReverse) Writer {
    return .{ .context = self };
}

fn prependSliceSize(self: *ArrayListReverse, data: []const u8) Error!usize {
    try self.prependSlice(data);
    return data.len;
}

fn allocatedSlice(self: *ArrayListReverse) []u8 {
    return (self.data.ptr + self.data.len - self.capacity)[0..self.capacity];
}

/// Invalidates all element pointers.
pub fn clearAndFree(self: *ArrayListReverse) void {
    self.allocator.free(self.allocatedSlice());
    self.data.len = 0;
    self.capacity = 0;
}

/// The caller owns the returned memory.
/// Capacity is cleared, making deinit() safe but unnecessary to call.
pub fn toOwnedSlice(self: *ArrayListReverse) Error![]u8 {
    const new_memory = try self.allocator.alloc(u8, self.data.len);
    @memcpy(new_memory, self.data);
    @memset(self.data, undefined);
    self.clearAndFree();
    return new_memory;
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;

test ArrayListReverse {
    var b = ArrayListReverse.init(testing.allocator);
    defer b.deinit();
    const data: []const u8 = &.{ 4, 5, 6 };
    try b.prependSlice(data);
    try testing.expectEqual(data.len, b.data.len);
    try testing.expectEqualSlices(u8, data, b.data);

    const data2: []const u8 = &.{ 1, 2, 3 };
    try b.prependSlice(data2);
    try testing.expectEqual(data.len + data2.len, b.data.len);
    try testing.expectEqualSlices(u8, data2 ++ data, b.data);
}
//! A secure DER parser that:
//! - Prefers calling `fn decodeDer(self: @This(), decoder: *der.Decoder)`
//! - Does NOT allocate. If you wish to parse lists you can do so lazily
//!   with an opaque type.
//! - Does NOT read memory outside `bytes`.
//! - Does NOT return elements with slices outside `bytes`.
//! - Errors on values that do NOT follow DER rules:
//!   - Lengths that could be represented in a shorter form.
//!   - Booleans that are not 0xff or 0x00.
bytes: []const u8,
index: Index = 0,
/// The field tag of the most recently visited field.
/// This is needed because we might visit an implicitly tagged container with a `fn decodeDer`.
field_tag: ?FieldTag = null,

/// Expect a value.
pub fn any(self: *Decoder, comptime T: type) !T {
    if (std.meta.hasFn(T, "decodeDer")) return try T.decodeDer(self);

    const tag = Tag.fromZig(T).toExpected();
    switch (@typeInfo(T)) {
        .@"struct" => {
            const ele = try self.element(tag);
            defer self.index = ele.slice.end; // don't force parsing all fields

            var res: T = undefined;

            inline for (std.meta.fields(T)) |f| {
                self.field_tag = FieldTag.fromContainer(T, f.name);

                if (self.field_tag) |ft| {
                    if (ft.explicit) {
                        const seq = try self.element(ft.toTag().toExpected());
                        self.index = seq.slice.start;
                        self.field_tag = null;
                    }
                }

                @field(res, f.name) = self.any(f.type) catch |err| brk: {
                    if (f.defaultValue()) |d| {
                        break :brk d;
                    }
                    return err;
                };
                // DER encodes null values by skipping them.
                if (@typeInfo(f.type) == .optional and @field(res, f.name) == null) {
                    if (f.defaultValue()) |d| @field(res, f.name) = d;
                }
            }

            return res;
        },
        .bool => {
            const ele = try self.element(tag);
            const bytes = self.view(ele);
            if (bytes.len != 1) return error.InvalidBool;

            return switch (bytes[0]) {
                0x00 => false,
                0xff => true,
                else => error.InvalidBool,
            };
        },
        .int => {
            const ele = try self.element(tag);
            const bytes = self.view(ele);
            return try int(T, bytes);
        },
        .@"enum" => |e| {
            const ele = try self.element(tag);
            const bytes = self.view(ele);
            if (@hasDecl(T, "oids")) {
                return T.oids.oidToEnum(bytes) orelse return error.UnknownOid;
            }
            return @enumFromInt(try int(e.tag_type, bytes));
        },
        .optional => |o| return self.any(o.child) catch return null,
        else => @compileError("cannot decode type " ++ @typeName(T)),
    }
}

//// Expect a sequence.
pub fn sequence(self: *Decoder) !Element {
    return try self.element(ExpectedTag.init(.sequence, true, .universal));
}

//// Expect an element.
pub fn element(
    self: *Decoder,
    expected: ExpectedTag,
) (error{ EndOfStream, UnexpectedElement } || Element.DecodeError)!Element {
    if (self.index >= self.bytes.len) return error.EndOfStream;

    const res = try Element.decode(self.bytes, self.index);
    var e = expected;
    if (self.field_tag) |ft| {
        e.number = @enumFromInt(ft.number);
        e.class = ft.class;
    }
    if (!e.match(res.tag)) {
        return error.UnexpectedElement;
    }

    self.index = if (res.tag.constructed) res.slice.start else res.slice.end;
    return res;
}

/// View of element bytes.
pub fn view(self: Decoder, elem: Element) []const u8 {
    return elem.slice.view(self.bytes);
}

fn int(comptime T: type, value: []const u8) error{ NonCanonical, LargeValue }!T {
    if (@typeInfo(T).int.bits % 8 != 0) @compileError("T must be byte aligned");

    var bytes = value;
    if (bytes.len >= 2) {
        if (bytes[0] == 0) {
            if (@clz(bytes[1]) > 0) return error.NonCanonical;
            bytes.ptr += 1;
        }
        if (bytes[0] == 0xff and @clz(bytes[1]) == 0) return error.NonCanonical;
    }

    if (bytes.len > @sizeOf(T)) return error.LargeValue;
    if (@sizeOf(T) == 1) return @bitCast(bytes[0]);

    return std.mem.readVarInt(T, bytes, .big);
}

test int {
    try expectEqual(@as(u8, 1), try int(u8, &[_]u8{1}));
    try expectError(error.NonCanonical, int(u8, &[_]u8{ 0, 1 }));
    try expectError(error.NonCanonical, int(u8, &[_]u8{ 0xff, 0xff }));

    const big = [_]u8{ 0xef, 0xff };
    try expectError(error.LargeValue, int(u8, &big));
    try expectEqual(0xefff, int(u16, &big));
}

test Decoder {
    var parser = Decoder{ .bytes = @embedFile("./testdata/id_ecc.pub.der") };
    const seq = try parser.sequence();

    {
        const seq2 = try parser.sequence();
        _ = try parser.element(ExpectedTag.init(.oid, false, .universal));
        _ = try parser.element(ExpectedTag.init(.oid, false, .universal));

        try std.testing.expectEqual(parser.index, seq2.slice.end);
    }
    _ = try parser.element(ExpectedTag.init(.bitstring, false, .universal));

    try std.testing.expectEqual(parser.index, seq.slice.end);
    try std.testing.expectEqual(parser.index, parser.bytes.len);
}

const std = @import("std");
const builtin = @import("builtin");
const asn1 = @import("../../asn1.zig");
const Oid = @import("../Oid.zig");

const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const Decoder = @This();
const Index = asn1.Index;
const Tag = asn1.Tag;
const FieldTag = asn1.FieldTag;
const ExpectedTag = asn1.ExpectedTag;
const Element = asn1.Element;
//! A buffered DER encoder.
//!
//! Prefers calling container's `fn encodeDer(self: @This(), encoder: *der.Encoder)`.
//! That function should encode values, lengths, then tags.
buffer: ArrayListReverse,
/// The field tag set by a parent container.
/// This is needed because we might visit an implicitly tagged container with a `fn encodeDer`.
field_tag: ?FieldTag = null,

pub fn init(allocator: std.mem.Allocator) Encoder {
    return Encoder{ .buffer = ArrayListReverse.init(allocator) };
}

pub fn deinit(self: *Encoder) void {
    self.buffer.deinit();
}

/// Encode any value.
pub fn any(self: *Encoder, val: anytype) !void {
    const T = @TypeOf(val);
    try self.anyTag(Tag.fromZig(T), val);
}

fn anyTag(self: *Encoder, tag_: Tag, val: anytype) !void {
    const T = @TypeOf(val);
    if (std.meta.hasFn(T, "encodeDer")) return try val.encodeDer(self);
    const start = self.buffer.data.len;
    const merged_tag = self.mergedTag(tag_);

    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (0..info.fields.len) |i| {
                const f = info.fields[info.fields.len - i - 1];
                const field_val = @field(val, f.name);
                const field_tag = FieldTag.fromContainer(T, f.name);

                // > The encoding of a set value or sequence value shall not include an encoding for any
                // > component value which is equal to its default value.
                const is_default = if (f.is_comptime) false else if (f.default_value_ptr) |v| brk: {
                    const default_val: *const f.type = @alignCast(@ptrCast(v));
                    break :brk std.mem.eql(u8, std.mem.asBytes(default_val), std.mem.asBytes(&field_val));
                } else false;

                if (!is_default) {
                    const start2 = self.buffer.data.len;
                    self.field_tag = field_tag;
                    // will merge with self.field_tag.
                    // may mutate self.field_tag.
                    try self.anyTag(Tag.fromZig(f.type), field_val);
                    if (field_tag) |ft| {
                        if (ft.explicit) {
                            try self.length(self.buffer.data.len - start2);
                            try self.tag(ft.toTag());
                            self.field_tag = null;
                        }
                    }
                }
            }
        },
        .bool => try self.buffer.prependSlice(&[_]u8{if (val) 0xff else 0}),
        .int => try self.int(T, val),
        .@"enum" => |e| {
            if (@hasDecl(T, "oids")) {
                return self.any(T.oids.enumToOid(val));
            } else {
                try self.int(e.tag_type, @intFromEnum(val));
            }
        },
        .optional => if (val) |v| return try self.anyTag(tag_, v),
        .null => {},
        else => @compileError("cannot encode type " ++ @typeName(T)),
    }

    try self.length(self.buffer.data.len - start);
    try self.tag(merged_tag);
}

/// Encode a tag.
pub fn tag(self: *Encoder, tag_: Tag) !void {
    const t = self.mergedTag(tag_);
    try t.encode(self.writer());
}

fn mergedTag(self: *Encoder, tag_: Tag) Tag {
    var res = tag_;
    if (self.field_tag) |ft| {
        if (!ft.explicit) {
            res.number = @enumFromInt(ft.number);
            res.class = ft.class;
        }
    }
    return res;
}

/// Encode a length.
pub fn length(self: *Encoder, len: usize) !void {
    const writer_ = self.writer();
    if (len < 128) {
        try writer_.writeInt(u8, @intCast(len), .big);
        return;
    }
    inline for ([_]type{ u8, u16, u32 }) |T| {
        if (len < std.math.maxInt(T)) {
            try writer_.writeInt(T, @intCast(len), .big);
            try writer_.writeInt(u8, @sizeOf(T) | 0x80, .big);
            return;
        }
    }
    return error.InvalidLength;
}

/// Encode a tag and length-prefixed bytes.
pub fn tagBytes(self: *Encoder, tag_: Tag, bytes: []const u8) !void {
    try self.buffer.prependSlice(bytes);
    try self.length(bytes.len);
    try self.tag(tag_);
}

/// Warning: This writer writes backwards. `fn print` will NOT work as expected.
pub fn writer(self: *Encoder) ArrayListReverse.Writer {
    return self.buffer.writer();
}

fn int(self: *Encoder, comptime T: type, value: T) !void {
    const big = std.mem.nativeTo(T, value, .big);
    const big_bytes = std.mem.asBytes(&big);

    const bits_needed = @bitSizeOf(T) - @clz(value);
    const needs_padding: u1 = if (value == 0)
        1
    else if (bits_needed > 8) brk: {
        const RightShift = std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(bits_needed)) - 1);
        const right_shift: RightShift = @intCast(bits_needed - 9);
        break :brk if (value >> right_shift == 0x1ff) 1 else 0;
    } else 0;
    const bytes_needed = try std.math.divCeil(usize, bits_needed, 8) + needs_padding;

    const writer_ = self.writer();
    for (0..bytes_needed - needs_padding) |i| try writer_.writeByte(big_bytes[big_bytes.len - i - 1]);
    if (needs_padding == 1) try writer_.writeByte(0);
}

test int {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.int(u8, 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0}, encoder.buffer.data);

    encoder.buffer.clearAndFree();
    try encoder.int(u16, 0x00ff);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xff}, encoder.buffer.data);

    encoder.buffer.clearAndFree();
    try encoder.int(u32, 0xffff);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0xff, 0xff }, encoder.buffer.data);
}

const std = @import("std");
const Oid = @import("../Oid.zig");
const asn1 = @import("../../asn1.zig");
const ArrayListReverse = @import("./ArrayListReverse.zig");
const Tag = asn1.Tag;
const FieldTag = asn1.FieldTag;
const Encoder = @This();
//! Globally unique hierarchical identifier made of a sequence of integers.
//!
//! Commonly used to identify standards, algorithms, certificate extensions,
//! organizations, or policy documents.
encoded: []const u8,

pub const InitError = std.fmt.ParseIntError || error{MissingPrefix} || std.io.FixedBufferStream(u8).WriteError;

pub fn fromDot(dot_notation: []const u8, out: []u8) InitError!Oid {
    var split = std.mem.splitScalar(u8, dot_notation, '.');
    const first_str = split.next() orelse return error.MissingPrefix;
    const second_str = split.next() orelse return error.MissingPrefix;

    const first = try std.fmt.parseInt(u8, first_str, 10);
    const second = try std.fmt.parseInt(u8, second_str, 10);

    var stream = std.io.fixedBufferStream(out);
    var writer = stream.writer();

    try writer.writeByte(first * 40 + second);

    var i: usize = 1;
    while (split.next()) |s| {
        var parsed = try std.fmt.parseUnsigned(Arc, s, 10);
        const n_bytes = if (parsed == 0) 0 else std.math.log(Arc, encoding_base, parsed);

        for (0..n_bytes) |j| {
            const place = std.math.pow(Arc, encoding_base, n_bytes - @as(Arc, @intCast(j)));
            const digit: u8 = @intCast(@divFloor(parsed, place));

            try writer.writeByte(digit | 0x80);
            parsed -= digit * place;

            i += 1;
        }
        try writer.writeByte(@intCast(parsed));
        i += 1;
    }

    return .{ .encoded = stream.getWritten() };
}

test fromDot {
    var buf: [256]u8 = undefined;
    for (test_cases) |t| {
        const actual = try fromDot(t.dot_notation, &buf);
        try std.testing.expectEqualSlices(u8, t.encoded, actual.encoded);
    }
}

pub fn toDot(self: Oid, writer: anytype) @TypeOf(writer).Error!void {
    const encoded = self.encoded;
    const first = @divTrunc(encoded[0], 40);
    const second = encoded[0] - first * 40;
    try writer.print("{d}.{d}", .{ first, second });

    var i: usize = 1;
    while (i != encoded.len) {
        const n_bytes: usize = brk: {
            var res: usize = 1;
            var j: usize = i;
            while (encoded[j] & 0x80 != 0) {
                res += 1;
                j += 1;
            }
            break :brk res;
        };

        var n: usize = 0;
        for (0..n_bytes) |j| {
            const place = std.math.pow(usize, encoding_base, n_bytes - j - 1);
            n += place * (encoded[i] & 0b01111111);
            i += 1;
        }
        try writer.print(".{d}", .{n});
    }
}

test toDot {
    var buf: [256]u8 = undefined;

    for (test_cases) |t| {
        var stream = std.io.fixedBufferStream(&buf);
        try toDot(Oid{ .encoded = t.encoded }, stream.writer());
        try std.testing.expectEqualStrings(t.dot_notation, stream.getWritten());
    }
}

const TestCase = struct {
    encoded: []const u8,
    dot_notation: []const u8,

    pub fn init(comptime hex: []const u8, dot_notation: []const u8) TestCase {
        return .{ .encoded = &hexToBytes(hex), .dot_notation = dot_notation };
    }
};

const test_cases = [_]TestCase{
    // https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    TestCase.init("2b0601040182371514", "1.3.6.1.4.1.311.21.20"),
    // https://luca.ntop.org/Teaching/Appunti/asn1.html
    TestCase.init("2a864886f70d", "1.2.840.113549"),
    // https://www.sysadmins.lv/blog-en/how-to-encode-object-identifier-to-an-asn1-der-encoded-string.aspx
    TestCase.init("2a868d20", "1.2.100000"),
    TestCase.init("2a864886f70d01010b", "1.2.840.113549.1.1.11"),
    TestCase.init("2b6570", "1.3.101.112"),
};

pub const asn1_tag = asn1.Tag.init(.oid, false, .universal);

pub fn decodeDer(decoder: *der.Decoder) !Oid {
    const ele = try decoder.element(asn1_tag.toExpected());
    return Oid{ .encoded = decoder.view(ele) };
}

pub fn encodeDer(self: Oid, encoder: *der.Encoder) !void {
    try encoder.tagBytes(asn1_tag, self.encoded);
}

fn encodedLen(dot_notation: []const u8) usize {
    var buf: [256]u8 = undefined;
    const oid = fromDot(dot_notation, &buf) catch unreachable;
    return oid.encoded.len;
}

/// Returns encoded bytes of OID.
fn encodeComptime(comptime dot_notation: []const u8) [encodedLen(dot_notation)]u8 {
    @setEvalBranchQuota(4000);
    comptime var buf: [256]u8 = undefined;
    const oid = comptime fromDot(dot_notation, &buf) catch unreachable;
    return oid.encoded[0..oid.encoded.len].*;
}

test encodeComptime {
    try std.testing.expectEqual(
        hexToBytes("2b0601040182371514"),
        comptime encodeComptime("1.3.6.1.4.1.311.21.20"),
    );
}

pub fn fromDotComptime(comptime dot_notation: []const u8) Oid {
    const tmp = comptime encodeComptime(dot_notation);
    return Oid{ .encoded = &tmp };
}

/// Maps of:
/// - Oid -> enum
/// - Enum -> oid
pub fn StaticMap(comptime Enum: type) type {
    const enum_info = @typeInfo(Enum).@"enum";
    const EnumToOid = std.EnumArray(Enum, []const u8);
    const ReturnType = struct {
        oid_to_enum: std.StaticStringMap(Enum),
        enum_to_oid: EnumToOid,

        pub fn oidToEnum(self: @This(), encoded: []const u8) ?Enum {
            return self.oid_to_enum.get(encoded);
        }

        pub fn enumToOid(self: @This(), value: Enum) Oid {
            const bytes = self.enum_to_oid.get(value);
            return .{ .encoded = bytes };
        }
    };

    return struct {
        pub fn initComptime(comptime key_pairs: anytype) ReturnType {
            const struct_info = @typeInfo(@TypeOf(key_pairs)).@"struct";
            const error_msg = "Each field of '" ++ @typeName(Enum) ++ "' must map to exactly one OID";
            if (!enum_info.is_exhaustive or enum_info.fields.len != struct_info.fields.len) {
                @compileError(error_msg);
            }

            comptime var enum_to_oid = EnumToOid.initUndefined();

            const KeyPair = struct { []const u8, Enum };
            comptime var static_key_pairs: [enum_info.fields.len]KeyPair = undefined;

            comptime for (enum_info.fields, 0..) |f, i| {
                if (!@hasField(@TypeOf(key_pairs), f.name)) {
                    @compileError("Field '" ++ f.name ++ "' missing Oid.StaticMap entry");
                }
                const encoded = &encodeComptime(@field(key_pairs, f.name));
                const tag: Enum = @enumFromInt(f.value);
                static_key_pairs[i] = .{ encoded, tag };
                enum_to_oid.set(tag, encoded);
            };

            const oid_to_enum = std.StaticStringMap(Enum).initComptime(static_key_pairs);
            if (oid_to_enum.values().len != enum_info.fields.len) @compileError(error_msg);

            return ReturnType{ .oid_to_enum = oid_to_enum, .enum_to_oid = enum_to_oid };
        }
    };
}

/// Strictly for testing.
fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var res: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&res, hex) catch unreachable;
    return res;
}

const std = @import("std");
const Oid = @This();
const Arc = u32;
const encoding_base = 128;
const Allocator = std.mem.Allocator;
const der = @import("der.zig");
const asn1 = @import("../asn1.zig");
const std = @import("std");
const asn1 = @import("../asn1.zig");

const der = asn1.der;
const Tag = asn1.Tag;
const FieldTag = asn1.FieldTag;

/// An example that uses all ASN1 types and available implementation features.
const AllTypes = struct {
    a: u8 = 0,
    b: asn1.BitString,
    c: C,
    d: asn1.Opaque(Tag.universal(.string_utf8, false)),
    e: asn1.Opaque(Tag.universal(.octetstring, false)),
    f: ?u16,
    g: ?Nested,
    h: asn1.Any,

    pub const asn1_tags = .{
        .a = FieldTag.initExplicit(0, .context_specific),
        .b = FieldTag.initExplicit(1, .context_specific),
        .c = FieldTag.initImplicit(2, .context_specific),
        .g = FieldTag.initImplicit(3, .context_specific),
    };

    const C = enum {
        a,
        b,

        pub const oids = asn1.Oid.StaticMap(@This()).initComptime(.{
            .a = "1.2.3.4",
            .b = "1.2.3.5",
        });
    };

    const Nested = struct {
        inner: Asn1T,
        sum: i16,

        const Asn1T = struct { a: u8, b: i16 };

        pub fn decodeDer(decoder: *der.Decoder) !Nested {
            const inner = try decoder.any(Asn1T);
            return Nested{ .inner = inner, .sum = inner.a + inner.b };
        }

        pub fn encodeDer(self: Nested, encoder: *der.Encoder) !void {
            try encoder.any(self.inner);
        }
    };
};

test AllTypes {
    const expected = AllTypes{
        .a = 2,
        .b = asn1.BitString{ .bytes = &[_]u8{ 0x04, 0xa0 } },
        .c = .a,
        .d = .{ .bytes = "asdf" },
        .e = .{ .bytes = "fdsa" },
        .f = (1 << 8) + 1,
        .g = .{ .inner = .{ .a = 4, .b = 5 }, .sum = 9 },
        .h = .{ .tag = Tag.init(.string_ia5, false, .universal), .bytes = "asdf" },
    };
    // https://lapo.it/asn1js/#MC-gAwIBAqEFAwMABKCCAyoDBAwEYXNkZgQEZmRzYQICAQGjBgIBBAIBBRYEYXNkZg
    const path = "./der/testdata/all_types.der";
    const encoded = @embedFile(path);
    const actual = try asn1.der.decode(AllTypes, encoded);
    try std.testing.expectEqualDeep(expected, actual);

    const allocator = std.testing.allocator;
    const buf = try asn1.der.encode(allocator, expected);
    defer allocator.free(buf);
    try std.testing.expectEqualSlices(u8, encoded, buf);

    // Use this to update test file.
    // const dir = try std.fs.cwd().openDir("lib/std/crypto/asn1", .{});
    // var file = try dir.createFile(path, .{});
    // defer file.close();
    // try file.writeAll(buf);
}
//! Hexadecimal and Base64 codecs designed for cryptographic use.
//! This file provides (best-effort) constant-time encoding and decoding functions for hexadecimal and Base64 formats.
//! This is designed to be used in cryptographic applications where timing attacks are a concern.
const std = @import("std");
const testing = std.testing;
const StaticBitSet = std.StaticBitSet;

pub const Error = error{
    /// An invalid character was found in the input.
    InvalidCharacter,
    /// The input is not properly padded.
    InvalidPadding,
    /// The input buffer is too small to hold the output.
    NoSpaceLeft,
    /// The input and output buffers are not the same size.
    SizeMismatch,
};

/// (best-effort) constant time hexadecimal encoding and decoding.
pub const hex = struct {
    /// Encodes a binary buffer into a hexadecimal string.
    /// The output buffer must be twice the size of the input buffer.
    pub fn encode(encoded: []u8, bin: []const u8, comptime case: std.fmt.Case) error{SizeMismatch}!void {
        if (encoded.len / 2 != bin.len) {
            return error.SizeMismatch;
        }
        for (bin, 0..) |v, i| {
            const b: u16 = v >> 4;
            const c: u16 = v & 0xf;
            const off = if (case == .upper) 32 else 0;
            const x =
                ((87 - off + c + (((c -% 10) >> 8) & ~@as(u16, 38 - off))) & 0xff) << 8 |
                ((87 - off + b + (((b -% 10) >> 8) & ~@as(u16, 38 - off))) & 0xff);
            encoded[i * 2] = @truncate(x);
            encoded[i * 2 + 1] = @truncate(x >> 8);
        }
    }

    /// Decodes a hexadecimal string into a binary buffer.
    /// The output buffer must be half the size of the input buffer.
    pub fn decode(bin: []u8, encoded: []const u8) error{ SizeMismatch, InvalidCharacter, InvalidPadding }!void {
        if (encoded.len % 2 != 0) {
            return error.InvalidPadding;
        }
        if (bin.len < encoded.len / 2) {
            return error.SizeMismatch;
        }
        _ = decodeAny(bin, encoded, null) catch |err| {
            switch (err) {
                error.InvalidCharacter => return error.InvalidCharacter,
                error.InvalidPadding => return error.InvalidPadding,
                else => unreachable,
            }
        };
    }

    /// A decoder that ignores certain characters.
    /// The decoder will skip any characters that are in the ignore list.
    pub const DecoderWithIgnore = struct {
        /// The characters to ignore.
        ignored_chars: StaticBitSet(256) = undefined,

        /// Decodes a hexadecimal string into a binary buffer.
        /// The output buffer must be half the size of the input buffer.
        pub fn decode(
            self: DecoderWithIgnore,
            bin: []u8,
            encoded: []const u8,
        ) error{ NoSpaceLeft, InvalidCharacter, InvalidPadding }![]const u8 {
            return decodeAny(bin, encoded, self.ignored_chars);
        }

        /// Returns the decoded length of a hexadecimal string, ignoring any characters in the ignore list.
        /// This operation does not run in constant time, but it aims to avoid leaking information about the underlying hexadecimal string.
        pub fn decodedLenForSlice(decoder: DecoderWithIgnore, encoded: []const u8) !usize {
            var hex_len = encoded.len;
            for (encoded) |c| {
                if (decoder.ignored_chars.isSet(c)) hex_len -= 1;
            }
            if (hex_len % 2 != 0) {
                return error.InvalidPadding;
            }
            return hex_len / 2;
        }

        /// Returns the maximum possible decoded size for a given input length after skipping ignored characters.
        pub fn decodedLenUpperBound(hex_len: usize) usize {
            return hex_len / 2;
        }
    };

    /// Creates a new decoder that ignores certain characters.
    /// The decoder will skip any characters that are in the ignore list.
    /// The ignore list must not contain any valid hexadecimal characters.
    pub fn decoderWithIgnore(ignore_chars: []const u8) error{InvalidCharacter}!DecoderWithIgnore {
        var ignored_chars = StaticBitSet(256).initEmpty();
        for (ignore_chars) |c| {
            switch (c) {
                '0'...'9', 'a'...'f', 'A'...'F' => return error.InvalidCharacter,
                else => if (ignored_chars.isSet(c)) return error.InvalidCharacter,
            }
            ignored_chars.set(c);
        }
        return DecoderWithIgnore{ .ignored_chars = ignored_chars };
    }

    fn decodeAny(
        bin: []u8,
        encoded: []const u8,
        ignored_chars: ?StaticBitSet(256),
    ) error{ NoSpaceLeft, InvalidCharacter, InvalidPadding }![]const u8 {
        var bin_pos: usize = 0;
        var state: bool = false;
        var c_acc: u8 = 0;
        for (encoded) |c| {
            const c_num = c ^ 48;
            const c_num0: u8 = @truncate((@as(u16, c_num) -% 10) >> 8);
            const c_alpha: u8 = (c & ~@as(u8, 32)) -% 55;
            const c_alpha0: u8 = @truncate(((@as(u16, c_alpha) -% 10) ^ (@as(u16, c_alpha) -% 16)) >> 8);
            if ((c_num0 | c_alpha0) == 0) {
                if (ignored_chars) |set| {
                    if (set.isSet(c)) {
                        continue;
                    }
                }
                return error.InvalidCharacter;
            }
            const c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
            if (bin_pos >= bin.len) {
                return error.NoSpaceLeft;
            }
            if (!state) {
                c_acc = c_val << 4;
            } else {
                bin[bin_pos] = c_acc | c_val;
                bin_pos += 1;
            }
            state = !state;
        }
        if (state) {
            return error.InvalidPadding;
        }
        return bin[0..bin_pos];
    }
};

/// (best-effort) constant time base64 encoding and decoding.
pub const base64 = struct {
    /// The base64 variant to use.
    pub const Variant = packed struct {
        /// Use the URL-safe alphabet instead of the standard alphabet.
        urlsafe_alphabet: bool = false,
        /// Enable padding with '=' characters.
        padding: bool = true,

        /// The standard base64 variant.
        pub const standard: Variant = .{ .urlsafe_alphabet = false, .padding = true };
        /// The URL-safe base64 variant.
        pub const urlsafe: Variant = .{ .urlsafe_alphabet = true, .padding = true };
        /// The standard base64 variant without padding.
        pub const standard_nopad: Variant = .{ .urlsafe_alphabet = false, .padding = false };
        /// The URL-safe base64 variant without padding.
        pub const urlsafe_nopad: Variant = .{ .urlsafe_alphabet = true, .padding = false };
    };

    /// Returns the length of the encoded base64 string for a given length.
    pub fn encodedLen(bin_len: usize, variant: Variant) usize {
        if (variant.padding) {
            return (bin_len + 2) / 3 * 4;
        } else {
            const leftover = bin_len % 3;
            return bin_len / 3 * 4 + (leftover * 4 + 2) / 3;
        }
    }

    /// Returns the maximum possible decoded size for a given input length - The actual length may be less if the input includes padding.
    /// `InvalidPadding` is returned if the input length is not valid.
    pub fn decodedLen(b64_len: usize, variant: Variant) !usize {
        var result = b64_len / 4 * 3;
        const leftover = b64_len % 4;
        if (variant.padding) {
            if (leftover % 4 != 0) return error.InvalidPadding;
        } else {
            if (leftover % 4 == 1) return error.InvalidPadding;
            result += leftover * 3 / 4;
        }
        return result;
    }

    /// Encodes a binary buffer into a base64 string.
    /// The output buffer must be at least `encodedLen(bin.len)` bytes long.
    pub fn encode(encoded: []u8, bin: []const u8, comptime variant: Variant) error{NoSpaceLeft}![]const u8 {
        var acc_len: u4 = 0;
        var b64_pos: usize = 0;
        var acc: u16 = 0;
        const nibbles = bin.len / 3;
        const remainder = bin.len - 3 * nibbles;
        var b64_len = nibbles * 4;
        if (remainder != 0) {
            b64_len += if (variant.padding) 4 else 2 + (remainder >> 1);
        }
        if (encoded.len < b64_len) {
            return error.NoSpaceLeft;
        }
        const urlsafe = variant.urlsafe_alphabet;
        for (bin) |v| {
            acc = (acc << 8) + v;
            acc_len += 8;
            while (acc_len >= 6) {
                acc_len -= 6;
                encoded[b64_pos] = charFromByte(@as(u6, @truncate(acc >> acc_len)), urlsafe);
                b64_pos += 1;
            }
        }
        if (acc_len > 0) {
            encoded[b64_pos] = charFromByte(@as(u6, @truncate(acc << (6 - acc_len))), urlsafe);
            b64_pos += 1;
        }
        while (b64_pos < b64_len) {
            encoded[b64_pos] = '=';
            b64_pos += 1;
        }
        return encoded[0..b64_pos];
    }

    /// Decodes a base64 string into a binary buffer.
    /// The output buffer must be at least `decodedLenUpperBound(encoded.len)` bytes long.
    pub fn decode(bin: []u8, encoded: []const u8, comptime variant: Variant) error{ InvalidCharacter, InvalidPadding }![]const u8 {
        return decodeAny(bin, encoded, variant, null) catch |err| {
            switch (err) {
                error.InvalidCharacter => return error.InvalidCharacter,
                error.InvalidPadding => return error.InvalidPadding,
                else => unreachable,
            }
        };
    }

    //// A decoder that ignores certain characters.
    pub const DecoderWithIgnore = struct {
        /// The characters to ignore.
        ignored_chars: StaticBitSet(256) = undefined,

        /// Decodes a base64 string into a binary buffer.
        /// The output buffer must be at least `decodedLenUpperBound(encoded.len)` bytes long.
        pub fn decode(
            self: DecoderWithIgnore,
            bin: []u8,
            encoded: []const u8,
            comptime variant: Variant,
        ) error{ NoSpaceLeft, InvalidCharacter, InvalidPadding }![]const u8 {
            return decodeAny(bin, encoded, variant, self.ignored_chars);
        }

        /// Returns the decoded length of a base64 string, ignoring any characters in the ignore list.
        /// This operation does not run in constant time, but it aims to avoid leaking information about the underlying base64 string.
        pub fn decodedLenForSlice(decoder: DecoderWithIgnore, encoded: []const u8, variant: Variant) !usize {
            var b64_len = encoded.len;
            for (encoded) |c| {
                if (decoder.ignored_chars.isSet(c)) b64_len -= 1;
            }
            return base64.decodedLen(b64_len, variant);
        }

        /// Returns the maximum possible decoded size for a given input length after skipping ignored characters.
        pub fn decodedLenUpperBound(b64_len: usize) usize {
            return b64_len / 3 * 4;
        }
    };

    /// Creates a new decoder that ignores certain characters.
    pub fn decoderWithIgnore(ignore_chars: []const u8) error{InvalidCharacter}!DecoderWithIgnore {
        var ignored_chars = StaticBitSet(256).initEmpty();
        for (ignore_chars) |c| {
            switch (c) {
                'A'...'Z', 'a'...'z', '0'...'9' => return error.InvalidCharacter,
                else => if (ignored_chars.isSet(c)) return error.InvalidCharacter,
            }
            ignored_chars.set(c);
        }
        return DecoderWithIgnore{ .ignored_chars = ignored_chars };
    }

    inline fn eq(x: u8, y: u8) u8 {
        return ~@as(u8, @truncate((0 -% (@as(u16, x) ^ @as(u16, y))) >> 8));
    }

    inline fn gt(x: u8, y: u8) u8 {
        return @truncate((@as(u16, y) -% @as(u16, x)) >> 8);
    }

    inline fn ge(x: u8, y: u8) u8 {
        return ~gt(y, x);
    }

    inline fn lt(x: u8, y: u8) u8 {
        return gt(y, x);
    }

    inline fn le(x: u8, y: u8) u8 {
        return ge(y, x);
    }

    inline fn charFromByte(x: u8, comptime urlsafe: bool) u8 {
        return (lt(x, 26) & (x +% 'A')) |
            (ge(x, 26) & lt(x, 52) & (x +% 'a' -% 26)) |
            (ge(x, 52) & lt(x, 62) & (x +% '0' -% 52)) |
            (eq(x, 62) & '+') | (eq(x, 63) & if (urlsafe) '_' else '/');
    }

    inline fn byteFromChar(c: u8, comptime urlsafe: bool) u8 {
        const x =
            (ge(c, 'A') & le(c, 'Z') & (c -% 'A')) |
            (ge(c, 'a') & le(c, 'z') & (c -% 'a' +% 26)) |
            (ge(c, '0') & le(c, '9') & (c -% '0' +% 52)) |
            (eq(c, '+') & 62) | (eq(c, if (urlsafe) '_' else '/') & 63);
        return x | (eq(x, 0) & ~eq(c, 'A'));
    }

    fn skipPadding(
        encoded: []const u8,
        padding_len: usize,
        ignored_chars: ?StaticBitSet(256),
    ) error{InvalidPadding}![]const u8 {
        var b64_pos: usize = 0;
        var i = padding_len;
        while (i > 0) {
            if (b64_pos >= encoded.len) {
                return error.InvalidPadding;
            }
            const c = encoded[b64_pos];
            if (c == '=') {
                i -= 1;
            } else if (ignored_chars) |set| {
                if (!set.isSet(c)) {
                    return error.InvalidPadding;
                }
            }
            b64_pos += 1;
        }
        return encoded[b64_pos..];
    }

    fn decodeAny(
        bin: []u8,
        encoded: []const u8,
        comptime variant: Variant,
        ignored_chars: ?StaticBitSet(256),
    ) error{ NoSpaceLeft, InvalidCharacter, InvalidPadding }![]const u8 {
        var acc: u16 = 0;
        var acc_len: u4 = 0;
        var bin_pos: usize = 0;
        var premature_end: ?usize = null;
        const urlsafe = variant.urlsafe_alphabet;
        for (encoded, 0..) |c, b64_pos| {
            const d = byteFromChar(c, urlsafe);
            if (d == 0xff) {
                if (ignored_chars) |set| {
                    if (set.isSet(c)) continue;
                }
                premature_end = b64_pos;
                break;
            }
            acc = (acc << 6) + d;
            acc_len += 6;
            if (acc_len >= 8) {
                acc_len -= 8;
                if (bin_pos >= bin.len) {
                    return error.NoSpaceLeft;
                }
                bin[bin_pos] = @truncate(acc >> acc_len);
                bin_pos += 1;
            }
        }
        if (acc_len > 4 or (acc & ((@as(u16, 1) << acc_len) -% 1)) != 0) {
            return error.InvalidCharacter;
        }
        const padding_len = acc_len / 2;
        if (premature_end) |pos| {
            const remaining =
                if (variant.padding)
                    try skipPadding(encoded[pos..], padding_len, ignored_chars)
                else
                    encoded[pos..];
            if (ignored_chars) |set| {
                for (remaining) |c| {
                    if (!set.isSet(c)) {
                        return error.InvalidCharacter;
                    }
                }
            } else if (remaining.len != 0) {
                return error.InvalidCharacter;
            }
        } else if (variant.padding and padding_len != 0) {
            return error.InvalidPadding;
        }
        return bin[0..bin_pos];
    }
};

test "hex" {
    var default_rng = std.Random.DefaultPrng.init(testing.random_seed);
    var rng = default_rng.random();
    var bin_buf: [1000]u8 = undefined;
    rng.bytes(&bin_buf);
    var bin2_buf: [bin_buf.len]u8 = undefined;
    var hex_buf: [bin_buf.len * 2]u8 = undefined;
    for (0..1000) |_| {
        const bin_len = rng.intRangeAtMost(usize, 0, bin_buf.len);
        const bin = bin_buf[0..bin_len];
        const bin2 = bin2_buf[0..bin_len];
        inline for (.{ .lower, .upper }) |case| {
            const hex_len = bin_len * 2;
            const encoded = hex_buf[0..hex_len];
            try hex.encode(encoded, bin, case);
            try hex.decode(bin2, encoded);
            try testing.expectEqualSlices(u8, bin, bin2);
        }
    }
}

test "base64" {
    var default_rng = std.Random.DefaultPrng.init(testing.random_seed);
    var rng = default_rng.random();
    var bin_buf: [1000]u8 = undefined;
    rng.bytes(&bin_buf);
    var bin2_buf: [bin_buf.len]u8 = undefined;
    var b64_buf: [(bin_buf.len + 3) / 3 * 4]u8 = undefined;
    for (0..1000) |_| {
        const bin_len = rng.intRangeAtMost(usize, 0, bin_buf.len);
        const bin = bin_buf[0..bin_len];
        const bin2 = bin2_buf[0..bin_len];
        inline for ([_]base64.Variant{
            .standard,
            .standard_nopad,
            .urlsafe,
            .urlsafe_nopad,
        }) |variant| {
            const b64_len = base64.encodedLen(bin_len, variant);
            const encoded_buf = b64_buf[0..b64_len];
            const encoded = try base64.encode(encoded_buf, bin, variant);
            const decoded = try base64.decode(bin2, encoded, variant);
            try testing.expectEqualSlices(u8, bin, decoded);
        }
    }
}

test "hex with ignored chars" {
    const encoded = "01020304050607\n08090A0B0C0D0E0F\n";
    const expected = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    var bin_buf: [encoded.len / 2]u8 = undefined;
    try testing.expectError(error.InvalidCharacter, hex.decode(&bin_buf, encoded));
    const bin = try (try hex.decoderWithIgnore("\r\n")).decode(&bin_buf, encoded);
    try testing.expectEqualSlices(u8, &expected, bin);
}

test "base64 with ignored chars" {
    const encoded = "dGVzdCBi\r\nYXNlNjQ=\n";
    const expected = "test base64";
    var bin_buf: [base64.DecoderWithIgnore.decodedLenUpperBound(encoded.len)]u8 = undefined;
    try testing.expectError(error.InvalidCharacter, base64.decode(&bin_buf, encoded, .standard));
    const bin = try (try base64.decoderWithIgnore("\r\n")).decode(&bin_buf, encoded, .standard);
    try testing.expectEqualSlices(u8, expected, bin);
}
const builtin = @import("builtin");
const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const sha3 = crypto.hash.sha3;
const testing = std.testing;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const SignatureVerificationError = crypto.errors.SignatureVerificationError;

/// ECDSA over P-256 with SHA-256.
pub const EcdsaP256Sha256 = Ecdsa(crypto.ecc.P256, crypto.hash.sha2.Sha256);
/// ECDSA over P-256 with SHA3-256.
pub const EcdsaP256Sha3_256 = Ecdsa(crypto.ecc.P256, crypto.hash.sha3.Sha3_256);
/// ECDSA over P-384 with SHA-384.
pub const EcdsaP384Sha384 = Ecdsa(crypto.ecc.P384, crypto.hash.sha2.Sha384);
/// ECDSA over P-384 with SHA3-384.
pub const EcdsaP384Sha3_384 = Ecdsa(crypto.ecc.P384, crypto.hash.sha3.Sha3_384);
/// ECDSA over Secp256k1 with SHA-256.
pub const EcdsaSecp256k1Sha256 = Ecdsa(crypto.ecc.Secp256k1, crypto.hash.sha2.Sha256);
/// ECDSA over Secp256k1 with SHA-256(SHA-256()) -- The Bitcoin signature system.
pub const EcdsaSecp256k1Sha256oSha256 = Ecdsa(crypto.ecc.Secp256k1, crypto.hash.composition.Sha256oSha256);

/// Elliptic Curve Digital Signature Algorithm (ECDSA).
pub fn Ecdsa(comptime Curve: type, comptime Hash: type) type {
    const Prf = switch (Hash) {
        sha3.Shake128 => sha3.KMac128,
        sha3.Shake256 => sha3.KMac256,
        else => crypto.auth.hmac.Hmac(Hash),
    };

    return struct {
        /// Length (in bytes) of optional random bytes, for non-deterministic signatures.
        pub const noise_length = Curve.scalar.encoded_length;

        /// An ECDSA secret key.
        pub const SecretKey = struct {
            /// Length (in bytes) of a raw secret key.
            pub const encoded_length = Curve.scalar.encoded_length;

            bytes: Curve.scalar.CompressedScalar,

            pub fn fromBytes(bytes: [encoded_length]u8) !SecretKey {
                return SecretKey{ .bytes = bytes };
            }

            pub fn toBytes(sk: SecretKey) [encoded_length]u8 {
                return sk.bytes;
            }
        };

        /// An ECDSA public key.
        pub const PublicKey = struct {
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const compressed_sec1_encoded_length = 1 + Curve.Fe.encoded_length;
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const uncompressed_sec1_encoded_length = 1 + 2 * Curve.Fe.encoded_length;

            p: Curve,

            /// Create a public key from a SEC-1 representation.
            pub fn fromSec1(sec1: []const u8) !PublicKey {
                return PublicKey{ .p = try Curve.fromSec1(sec1) };
            }

            /// Encode the public key using the compressed SEC-1 format.
            pub fn toCompressedSec1(pk: PublicKey) [compressed_sec1_encoded_length]u8 {
                return pk.p.toCompressedSec1();
            }

            /// Encoding the public key using the uncompressed SEC-1 format.
            pub fn toUncompressedSec1(pk: PublicKey) [uncompressed_sec1_encoded_length]u8 {
                return pk.p.toUncompressedSec1();
            }
        };

        /// An ECDSA signature.
        pub const Signature = struct {
            /// Length (in bytes) of a raw signature.
            pub const encoded_length = Curve.scalar.encoded_length * 2;
            /// Maximum length (in bytes) of a DER-encoded signature.
            pub const der_encoded_length_max = encoded_length + 2 + 2 * 3;

            /// The R component of an ECDSA signature.
            r: Curve.scalar.CompressedScalar,
            /// The S component of an ECDSA signature.
            s: Curve.scalar.CompressedScalar,

            /// Create a Verifier for incremental verification of a signature.
            pub fn verifier(sig: Signature, public_key: PublicKey) Verifier.InitError!Verifier {
                return Verifier.init(sig, public_key);
            }

            pub const VerifyError = Verifier.InitError || Verifier.VerifyError;

            /// Verify the signature against a message and public key.
            /// Return IdentityElement or NonCanonical if the public key or signature are not in the expected range,
            /// or SignatureVerificationError if the signature is invalid for the given message and key.
            pub fn verify(sig: Signature, msg: []const u8, public_key: PublicKey) VerifyError!void {
                var st = try sig.verifier(public_key);
                st.update(msg);
                try st.verify();
            }

            /// Verify the signature against a pre-hashed message and public key.
            /// The message must have already been hashed using the scheme's hash function.
            /// Returns SignatureVerificationError if the signature is invalid for the given message and key.
            pub fn verifyPrehashed(sig: Signature, msg_hash: [Hash.digest_length]u8, public_key: PublicKey) VerifyError!void {
                var st = try sig.verifier(public_key);
                return st.verifyPrehashed(msg_hash);
            }

            /// Return the raw signature (r, s) in big-endian format.
            pub fn toBytes(sig: Signature) [encoded_length]u8 {
                var bytes: [encoded_length]u8 = undefined;
                @memcpy(bytes[0 .. encoded_length / 2], &sig.r);
                @memcpy(bytes[encoded_length / 2 ..], &sig.s);
                return bytes;
            }

            /// Create a signature from a raw encoding of (r, s).
            /// ECDSA always assumes big-endian.
            pub fn fromBytes(bytes: [encoded_length]u8) Signature {
                return Signature{
                    .r = bytes[0 .. encoded_length / 2].*,
                    .s = bytes[encoded_length / 2 ..].*,
                };
            }

            /// Encode the signature using the DER format.
            /// The maximum length of the DER encoding is der_encoded_length_max.
            /// The function returns a slice, that can be shorter than der_encoded_length_max.
            pub fn toDer(sig: Signature, buf: *[der_encoded_length_max]u8) []u8 {
                var fb = io.fixedBufferStream(buf);
                const w = fb.writer();
                const r_len = @as(u8, @intCast(sig.r.len + (sig.r[0] >> 7)));
                const s_len = @as(u8, @intCast(sig.s.len + (sig.s[0] >> 7)));
                const seq_len = @as(u8, @intCast(2 + r_len + 2 + s_len));
                w.writeAll(&[_]u8{ 0x30, seq_len }) catch unreachable;
                w.writeAll(&[_]u8{ 0x02, r_len }) catch unreachable;
                if (sig.r[0] >> 7 != 0) {
                    w.writeByte(0x00) catch unreachable;
                }
                w.writeAll(&sig.r) catch unreachable;
                w.writeAll(&[_]u8{ 0x02, s_len }) catch unreachable;
                if (sig.s[0] >> 7 != 0) {
                    w.writeByte(0x00) catch unreachable;
                }
                w.writeAll(&sig.s) catch unreachable;
                return fb.getWritten();
            }

            // Read a DER-encoded integer.
            fn readDerInt(out: []u8, reader: anytype) EncodingError!void {
                var buf: [2]u8 = undefined;
                _ = reader.readNoEof(&buf) catch return error.InvalidEncoding;
                if (buf[0] != 0x02) return error.InvalidEncoding;
                var expected_len = @as(usize, buf[1]);
                if (expected_len == 0 or expected_len > 1 + out.len) return error.InvalidEncoding;
                var has_top_bit = false;
                if (expected_len == 1 + out.len) {
                    if ((reader.readByte() catch return error.InvalidEncoding) != 0) return error.InvalidEncoding;
                    expected_len -= 1;
                    has_top_bit = true;
                }
                const out_slice = out[out.len - expected_len ..];
                reader.readNoEof(out_slice) catch return error.InvalidEncoding;
                if (@intFromBool(has_top_bit) != out[0] >> 7) return error.InvalidEncoding;
            }

            /// Create a signature from a DER representation.
            /// Returns InvalidEncoding if the DER encoding is invalid.
            pub fn fromDer(der: []const u8) EncodingError!Signature {
                var sig: Signature = mem.zeroInit(Signature, .{});
                var fb = io.fixedBufferStream(der);
                const reader = fb.reader();
                var buf: [2]u8 = undefined;
                _ = reader.readNoEof(&buf) catch return error.InvalidEncoding;
                if (buf[0] != 0x30 or @as(usize, buf[1]) + 2 != der.len) {
                    return error.InvalidEncoding;
                }
                try readDerInt(&sig.r, reader);
                try readDerInt(&sig.s, reader);
                if (fb.getPos() catch unreachable != der.len) return error.InvalidEncoding;

                return sig;
            }
        };

        /// A Signer is used to incrementally compute a signature.
        /// It can be obtained from a `KeyPair`, using the `signer()` function.
        pub const Signer = struct {
            h: Hash,
            secret_key: SecretKey,
            noise: ?[noise_length]u8,

            fn init(secret_key: SecretKey, noise: ?[noise_length]u8) !Signer {
                return Signer{
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                    .noise = noise,
                };
            }

            /// Add new data to the message being signed.
            pub fn update(self: *Signer, data: []const u8) void {
                self.h.update(data);
            }

            /// Compute a signature over a hash.
            fn finalizePrehashed(self: *Signer, msg_hash: [Hash.digest_length]u8) (IdentityElementError || NonCanonicalError)!Signature {
                const scalar_encoded_length = Curve.scalar.encoded_length;
                const h_len = @max(Hash.digest_length, scalar_encoded_length);
                var h: [h_len]u8 = [_]u8{0} ** (h_len - Hash.digest_length) ++ msg_hash;

                std.debug.assert(h.len >= scalar_encoded_length);
                const z = reduceToScalar(scalar_encoded_length, h[0..scalar_encoded_length].*);

                const k = deterministicScalar(msg_hash, self.secret_key.bytes, self.noise);

                const p = try Curve.basePoint.mul(k.toBytes(.big), .big);
                const xs = p.affineCoordinates().x.toBytes(.big);
                const r = reduceToScalar(Curve.Fe.encoded_length, xs);
                if (r.isZero()) return error.IdentityElement;

                const k_inv = k.invert();
                const zrs = z.add(r.mul(try Curve.scalar.Scalar.fromBytes(self.secret_key.bytes, .big)));
                const s = k_inv.mul(zrs);
                if (s.isZero()) return error.IdentityElement;

                return Signature{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
            }

            /// Compute a signature over the entire message.
            pub fn finalize(self: *Signer) (IdentityElementError || NonCanonicalError)!Signature {
                var h_slice: [Hash.digest_length]u8 = undefined;
                self.h.final(&h_slice);
                return self.finalizePrehashed(h_slice);
            }
        };

        /// A Verifier is used to incrementally verify a signature.
        /// It can be obtained from a `Signature`, using the `verifier()` function.
        pub const Verifier = struct {
            h: Hash,
            r: Curve.scalar.Scalar,
            s: Curve.scalar.Scalar,
            public_key: PublicKey,

            pub const InitError = IdentityElementError || NonCanonicalError;

            fn init(sig: Signature, public_key: PublicKey) InitError!Verifier {
                const r = try Curve.scalar.Scalar.fromBytes(sig.r, .big);
                const s = try Curve.scalar.Scalar.fromBytes(sig.s, .big);
                if (r.isZero() or s.isZero()) return error.IdentityElement;

                return Verifier{
                    .h = Hash.init(.{}),
                    .r = r,
                    .s = s,
                    .public_key = public_key,
                };
            }

            /// Add new content to the message to be verified.
            pub fn update(self: *Verifier, data: []const u8) void {
                self.h.update(data);
            }

            pub const VerifyError = IdentityElementError || NonCanonicalError ||
                SignatureVerificationError;

            /// Verify that the signature is valid for the hash.
            fn verifyPrehashed(self: *Verifier, msg_hash: [Hash.digest_length]u8) VerifyError!void {
                const ht = Curve.scalar.encoded_length;
                const h_len = @max(Hash.digest_length, ht);
                var h: [h_len]u8 = [_]u8{0} ** (h_len - Hash.digest_length) ++ msg_hash;

                const z = reduceToScalar(ht, h[0..ht].*);
                if (z.isZero()) {
                    return error.SignatureVerificationFailed;
                }

                const s_inv = self.s.invert();
                const v1 = z.mul(s_inv).toBytes(.little);
                const v2 = self.r.mul(s_inv).toBytes(.little);
                const v1g = try Curve.basePoint.mulPublic(v1, .little);
                const v2pk = try self.public_key.p.mulPublic(v2, .little);
                const vxs = v1g.add(v2pk).affineCoordinates().x.toBytes(.big);
                const vr = reduceToScalar(Curve.Fe.encoded_length, vxs);
                if (!self.r.equivalent(vr)) {
                    return error.SignatureVerificationFailed;
                }
            }

            /// Verify that the signature is valid for the entire message.
            pub fn verify(self: *Verifier) VerifyError!void {
                var h_slice: [Hash.digest_length]u8 = undefined;
                self.h.final(&h_slice);
                return self.verifyPrehashed(h_slice);
            }
        };

        /// An ECDSA key pair.
        pub const KeyPair = struct {
            /// Length (in bytes) of a seed required to create a key pair.
            pub const seed_length = noise_length;

            /// Public part.
            public_key: PublicKey,
            /// Secret scalar.
            secret_key: SecretKey,

            /// Deterministically derive a key pair from a cryptograpically secure secret seed.
            ///
            /// Except in tests, applications should generally call `generate()` instead of this function.
            pub fn generateDeterministic(seed: [seed_length]u8) IdentityElementError!KeyPair {
                const h = [_]u8{0x00} ** Hash.digest_length;
                const k0 = [_]u8{0x01} ** SecretKey.encoded_length;
                const secret_key = deterministicScalar(h, k0, seed).toBytes(.big);
                return fromSecretKey(SecretKey{ .bytes = secret_key });
            }

            /// Generate a new, random key pair.
            pub fn generate() KeyPair {
                var random_seed: [seed_length]u8 = undefined;
                while (true) {
                    crypto.random.bytes(&random_seed);
                    return generateDeterministic(random_seed) catch {
                        @branchHint(.unlikely);
                        continue;
                    };
                }
            }

            /// Return the public key corresponding to the secret key.
            pub fn fromSecretKey(secret_key: SecretKey) IdentityElementError!KeyPair {
                const public_key = try Curve.basePoint.mul(secret_key.bytes, .big);
                return KeyPair{ .secret_key = secret_key, .public_key = PublicKey{ .p = public_key } };
            }

            /// Sign a message using the key pair.
            /// The noise can be null in order to create deterministic signatures.
            /// If deterministic signatures are not required, the noise should be randomly generated instead.
            /// This helps defend against fault attacks.
            pub fn sign(key_pair: KeyPair, msg: []const u8, noise: ?[noise_length]u8) (IdentityElementError || NonCanonicalError)!Signature {
                var st = try key_pair.signer(noise);
                st.update(msg);
                return st.finalize();
            }

            /// Sign a pre-hashed message using the key pair.
            /// The message must have already been hashed using the scheme's hash function.
            /// The noise parameter can be null for deterministic signatures, or random bytes for enhanced security against fault attacks.
            pub fn signPrehashed(key_pair: KeyPair, msg_hash: [Hash.digest_length]u8, noise: ?[noise_length]u8) (IdentityElementError || NonCanonicalError)!Signature {
                var st = try key_pair.signer(noise);
                return st.finalizePrehashed(msg_hash);
            }

            /// Create a Signer, that can be used for incremental signature verification.
            pub fn signer(key_pair: KeyPair, noise: ?[noise_length]u8) !Signer {
                return Signer.init(key_pair.secret_key, noise);
            }
        };

        // Reduce the coordinate of a field element to the scalar field.
        fn reduceToScalar(comptime unreduced_len: usize, s: [unreduced_len]u8) Curve.scalar.Scalar {
            if (unreduced_len >= 48) {
                var xs = [_]u8{0} ** 64;
                @memcpy(xs[xs.len - s.len ..], s[0..]);
                return Curve.scalar.Scalar.fromBytes64(xs, .big);
            }
            var xs = [_]u8{0} ** 48;
            @memcpy(xs[xs.len - s.len ..], s[0..]);
            return Curve.scalar.Scalar.fromBytes48(xs, .big);
        }

        // Create a deterministic scalar according to a secret key and optional noise.
        // This uses the overly conservative scheme from the "Deterministic ECDSA and EdDSA Signatures with Additional Randomness" draft.
        fn deterministicScalar(h: [Hash.digest_length]u8, secret_key: Curve.scalar.CompressedScalar, noise: ?[noise_length]u8) Curve.scalar.Scalar {
            var k = [_]u8{0x00} ** h.len;
            var m = [_]u8{0x00} ** (h.len + 1 + noise_length + secret_key.len + h.len);
            var t = [_]u8{0x00} ** Curve.scalar.encoded_length;
            const m_v = m[0..h.len];
            const m_i = &m[m_v.len];
            const m_z = m[m_v.len + 1 ..][0..noise_length];
            const m_x = m[m_v.len + 1 + noise_length ..][0..secret_key.len];
            const m_h = m[m.len - h.len ..];

            @memset(m_v, 0x01);
            m_i.* = 0x00;
            if (noise) |n| @memcpy(m_z, &n);
            @memcpy(m_x, &secret_key);
            @memcpy(m_h, &h);
            Prf.create(&k, &m, &k);
            Prf.create(m_v, m_v, &k);
            m_i.* = 0x01;
            Prf.create(&k, &m, &k);
            Prf.create(m_v, m_v, &k);
            while (true) {
                var t_off: usize = 0;
                while (t_off < t.len) : (t_off += m_v.len) {
                    const t_end = @min(t_off + m_v.len, t.len);
                    Prf.create(m_v, m_v, &k);
                    @memcpy(t[t_off..t_end], m_v[0 .. t_end - t_off]);
                }
                if (Curve.scalar.Scalar.fromBytes(t, .big)) |s| return s else |_| {}
                m_i.* = 0x00;
                Prf.create(&k, m[0 .. m_v.len + 1], &k);
                Prf.create(m_v, m_v, &k);
            }
        }
    };
}

test "Basic operations over EcdsaP384Sha384" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const Scheme = EcdsaP384Sha384;
    const kp = Scheme.KeyPair.generate();
    const msg = "test";

    var noise: [Scheme.noise_length]u8 = undefined;
    crypto.random.bytes(&noise);
    const sig = try kp.sign(msg, noise);
    try sig.verify(msg, kp.public_key);

    const sig2 = try kp.sign(msg, null);
    try sig2.verify(msg, kp.public_key);
}

test "Basic operations over Secp256k1" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const Scheme = EcdsaSecp256k1Sha256oSha256;
    const kp = Scheme.KeyPair.generate();
    const msg = "test";

    var noise: [Scheme.noise_length]u8 = undefined;
    crypto.random.bytes(&noise);
    const sig = try kp.sign(msg, noise);
    try sig.verify(msg, kp.public_key);

    const sig2 = try kp.sign(msg, null);
    try sig2.verify(msg, kp.public_key);
}

test "Basic operations over EcdsaP384Sha256" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const Scheme = Ecdsa(crypto.ecc.P384, crypto.hash.sha2.Sha256);
    const kp = Scheme.KeyPair.generate();
    const msg = "test";

    var noise: [Scheme.noise_length]u8 = undefined;
    crypto.random.bytes(&noise);
    const sig = try kp.sign(msg, noise);
    try sig.verify(msg, kp.public_key);

    const sig2 = try kp.sign(msg, null);
    try sig2.verify(msg, kp.public_key);
}

test "Verifying a existing signature with EcdsaP384Sha256" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const Scheme = Ecdsa(crypto.ecc.P384, crypto.hash.sha2.Sha256);
    // zig fmt: off
    const sk_bytes = [_]u8{
    0x6a, 0x53, 0x9c, 0x83, 0x0f, 0x06, 0x86, 0xd9, 0xef, 0xf1, 0xe7, 0x5c, 0xae,
    0x93, 0xd9, 0x5b, 0x16, 0x1e, 0x96, 0x7c, 0xb0, 0x86, 0x35, 0xc9, 0xea, 0x20,
    0xdc, 0x2b, 0x02, 0x37, 0x6d, 0xd2, 0x89, 0x72, 0x0a, 0x37, 0xf6, 0x5d, 0x4f,
    0x4d, 0xf7, 0x97, 0xcb, 0x8b, 0x03, 0x63, 0xc3, 0x2d
    };
    const msg = [_]u8{
    0x64, 0x61, 0x74, 0x61, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x67, 0x6e,
    0x69, 0x6e, 0x67, 0x0a
    };
    const sig_ans_bytes = [_]u8{
    0x30, 0x64, 0x02, 0x30, 0x7a, 0x31, 0xd8, 0xe0, 0xf8, 0x40, 0x7d, 0x6a, 0xf3,
    0x1a, 0x5d, 0x02, 0xe5, 0xcb, 0x24, 0x29, 0x1a, 0xac, 0x15, 0x94, 0xd1, 0x5b,
    0xcd, 0x75, 0x2f, 0x45, 0x79, 0x98, 0xf7, 0x60, 0x9a, 0xd5, 0xca, 0x80, 0x15,
    0x87, 0x9b, 0x0c, 0x27, 0xe3, 0x01, 0x8b, 0x73, 0x4e, 0x57, 0xa3, 0xd2, 0x9a,
    0x02, 0x30, 0x33, 0xe0, 0x04, 0x5e, 0x76, 0x1f, 0xc8, 0xcf, 0xda, 0xbe, 0x64,
    0x95, 0x0a, 0xd4, 0x85, 0x34, 0x33, 0x08, 0x7a, 0x81, 0xf2, 0xf6, 0xb6, 0x94,
    0x68, 0xc3, 0x8c, 0x5f, 0x88, 0x92, 0x27, 0x5e, 0x4e, 0x84, 0x96, 0x48, 0x42,
    0x84, 0x28, 0xac, 0x37, 0x93, 0x07, 0xd3, 0x50, 0x32, 0x71, 0xb0
    };
    // zig fmt: on

    const sk = try Scheme.SecretKey.fromBytes(sk_bytes);
    const kp = try Scheme.KeyPair.fromSecretKey(sk);

    const sig_ans = try Scheme.Signature.fromDer(&sig_ans_bytes);
    try sig_ans.verify(&msg, kp.public_key);

    const sig = try kp.sign(&msg, null);
    try sig.verify(&msg, kp.public_key);
}

test "Prehashed message operations" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    const Scheme = EcdsaP256Sha256;
    const kp = Scheme.KeyPair.generate();
    const msg = "test message for prehashed signing";

    const Hash = crypto.hash.sha2.Sha256;
    var msg_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &msg_hash, .{});

    const sig = try kp.signPrehashed(msg_hash, null);
    try sig.verifyPrehashed(msg_hash, kp.public_key);

    var bad_hash = msg_hash;
    bad_hash[0] ^= 1;
    try testing.expectError(error.SignatureVerificationFailed, sig.verifyPrehashed(bad_hash, kp.public_key));

    var noise: [Scheme.noise_length]u8 = undefined;
    crypto.random.bytes(&noise);
    const sig_wit```
