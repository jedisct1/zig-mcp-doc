```
L(0xc6), L(0x66), L(0x66), L(0xba), L(0x81), L(0xef),
                L(0x67), L(0xe4), L(0xe6), L(0x3c), L(0xc),  L(0xca), L(0xa4), L(0xa),  L(0x79), L(0xb3), L(0x57), L(0x8b), L(0x8a), L(0x75),
                L(0x98), L(0x18), L(0x42), L(0x2f), L(0x29), L(0xa3), L(0x82), L(0xef), L(0x9f), L(0x86), L(0x6),  L(0x23), L(0xe1), L(0x75),
                L(0xfa), L(0x8),  L(0xb1), L(0xde), L(0x17), L(0x4a),
            },
        },
        TestCase{
            .input = "huffman-rand-limit.input",
            .want = "huffman-rand-limit.{s}.expect",
            .want_no_input = "huffman-rand-limit.{s}.expect-noinput",
            .tokens = &[_]Token{
                L(0x61), M(1, 74), L(0xa),  L(0xf8), L(0x8b), L(0x96), L(0x76), L(0x48), L(0xa),  L(0x85), L(0x94), L(0x25), L(0x80),
                L(0xaf), L(0xc2),  L(0xfe), L(0x8d), L(0xe8), L(0x20), L(0xeb), L(0x17), L(0x86), L(0xc9), L(0xb7), L(0xc5), L(0xde),
                L(0x6),  L(0xea),  L(0x7d), L(0x18), L(0x8b), L(0xe7), L(0x3e), L(0x7),  L(0xda), L(0xdf), L(0xff), L(0x6c), L(0x73),
                L(0xde), L(0xcc),  L(0xe7), L(0x6d), L(0x8d), L(0x4),  L(0x19), L(0x49), L(0x7f), L(0x47), L(0x1f), L(0x48), L(0x15),
                L(0xb0), L(0xe8),  L(0x9e), L(0xf2), L(0x31), L(0x59), L(0xde), L(0x34), L(0xb4), L(0x5b), L(0xe5), L(0xe0), L(0x9),
                L(0x11), L(0x30),  L(0xc2), L(0x88), L(0x5b), L(0x7c), L(0x5d), L(0x14), L(0x13), L(0x6f), L(0x23), L(0xa9), L(0xa),
                L(0xbc), L(0x2d),  L(0x23), L(0xbe), L(0xd9), L(0xed), L(0x75), L(0x4),  L(0x6c), L(0x99), L(0xdf), L(0xfd), L(0x70),
                L(0x66), L(0xe6),  L(0xee), L(0xd9), L(0xb1), L(0x9e), L(0x6e), L(0x83), L(0x59), L(0xd5), L(0xd4), L(0x80), L(0x59),
                L(0x98), L(0x77),  L(0x89), L(0x43), L(0x38), L(0xc9), L(0xaf), L(0x30), L(0x32), L(0x9a), L(0x20), L(0x1b), L(0x46),
                L(0x3d), L(0x67),  L(0x6e), L(0xd7), L(0x72), L(0x9e), L(0x4e), L(0x21), L(0x4f), L(0xc6), L(0xe0), L(0xd4), L(0x7b),
                L(0x4),  L(0x8d),  L(0xa5), L(0x3),  L(0xf6), L(0x5),  L(0x9b), L(0x6b), L(0xdc), L(0x2a), L(0x93), L(0x77), L(0x28),
                L(0xfd), L(0xb4),  L(0x62), L(0xda), L(0x20), L(0xe7), L(0x1f), L(0xab), L(0x6b), L(0x51), L(0x43), L(0x39), L(0x2f),
                L(0xa0), L(0x92),  L(0x1),  L(0x6c), L(0x75), L(0x3e), L(0xf4), L(0x35), L(0xfd), L(0x43), L(0x2e), L(0xf7), L(0xa4),
                L(0x75), L(0xda),  L(0xea), L(0x9b), L(0xa),
            },
        },
        TestCase{
            .input = "huffman-shifts.input",
            .want = "huffman-shifts.{s}.expect",
            .want_no_input = "huffman-shifts.{s}.expect-noinput",
            .tokens = &[_]Token{
                L('1'),    L('0'),    M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258),
                M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258),
                M(2, 258), M(2, 76),  L(0xd),    L(0xa),    L('2'),    L('3'),    M(2, 258), M(2, 258),
                M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 258), M(2, 256),
            },
        },
        TestCase{
            .input = "huffman-text-shift.input",
            .want = "huffman-text-shift.{s}.expect",
            .want_no_input = "huffman-text-shift.{s}.expect-noinput",
            .tokens = &[_]Token{
                L('/'),   L('/'), L('C'),   L('o'), L('p'),   L('y'),   L('r'),   L('i'),
                L('g'),   L('h'), L('t'),   L('2'), L('0'),   L('0'),   L('9'),   L('T'),
                L('h'),   L('G'), L('o'),   L('A'), L('u'),   L('t'),   L('h'),   L('o'),
                L('r'),   L('.'), L('A'),   L('l'), L('l'),   M(23, 5), L('r'),   L('r'),
                L('v'),   L('d'), L('.'),   L(0xd), L(0xa),   L('/'),   L('/'),   L('U'),
                L('o'),   L('f'), L('t'),   L('h'), L('i'),   L('o'),   L('u'),   L('r'),
                L('c'),   L('c'), L('o'),   L('d'), L('i'),   L('g'),   L('o'),   L('v'),
                L('r'),   L('n'), L('d'),   L('b'), L('y'),   L('B'),   L('S'),   L('D'),
                L('-'),   L('t'), L('y'),   L('l'), M(33, 4), L('l'),   L('i'),   L('c'),
                L('n'),   L('t'), L('h'),   L('t'), L('c'),   L('n'),   L('b'),   L('f'),
                L('o'),   L('u'), L('n'),   L('d'), L('i'),   L('n'),   L('t'),   L('h'),
                L('L'),   L('I'), L('C'),   L('E'), L('N'),   L('S'),   L('E'),   L('f'),
                L('i'),   L('l'), L('.'),   L(0xd), L(0xa),   L(0xd),   L(0xa),   L('p'),
                L('c'),   L('k'), L('g'),   L('m'), L('i'),   L('n'),   M(11, 4), L('i'),
                L('m'),   L('p'), L('o'),   L('r'), L('t'),   L('"'),   L('o'),   L('"'),
                M(13, 4), L('f'), L('u'),   L('n'), L('c'),   L('m'),   L('i'),   L('n'),
                L('('),   L(')'), L('{'),   L(0xd), L(0xa),   L(0x9),   L('v'),   L('r'),
                L('b'),   L('='), L('m'),   L('k'), L('('),   L('['),   L(']'),   L('b'),
                L('y'),   L('t'), L(','),   L('6'), L('5'),   L('5'),   L('3'),   L('5'),
                L(')'),   L(0xd), L(0xa),   L(0x9), L('f'),   L(','),   L('_'),   L(':'),
                L('='),   L('o'), L('.'),   L('C'), L('r'),   L('t'),   L('('),   L('"'),
                L('h'),   L('u'), L('f'),   L('f'), L('m'),   L('n'),   L('-'),   L('n'),
                L('u'),   L('l'), L('l'),   L('-'), L('m'),   L('x'),   L('.'),   L('i'),
                L('n'),   L('"'), M(34, 5), L('.'), L('W'),   L('r'),   L('i'),   L('t'),
                L('('),   L('b'), L(')'),   L(0xd), L(0xa),   L('}'),   L(0xd),   L(0xa),
                L('A'),   L('B'), L('C'),   L('D'), L('E'),   L('F'),   L('G'),   L('H'),
                L('I'),   L('J'), L('K'),   L('L'), L('M'),   L('N'),   L('O'),   L('P'),
                L('Q'),   L('R'), L('S'),   L('T'), L('U'),   L('V'),   L('X'),   L('x'),
                L('y'),   L('z'), L('!'),   L('"'), L('#'),   L(0xc2),  L(0xa4),  L('%'),
                L('&'),   L('/'), L('?'),   L('"'),
            },
        },
        TestCase{
            .input = "huffman-text.input",
            .want = "huffman-text.{s}.expect",
            .want_no_input = "huffman-text.{s}.expect-noinput",
            .tokens = &[_]Token{
                L('/'),    L('/'),    L(' '),   L('z'),    L('i'), L('g'), L(' '), L('v'),
                L('0'),    L('.'),    L('1'),   L('0'),    L('.'), L('0'), L(0xa), L('/'),
                L('/'),    L(' '),    L('c'),   L('r'),    L('e'), L('a'), L('t'), L('e'),
                L(' '),    L('a'),    L(' '),   L('f'),    L('i'), L('l'), L('e'), M(5, 4),
                L('l'),    L('e'),    L('d'),   L(' '),    L('w'), L('i'), L('t'), L('h'),
                L(' '),    L('0'),    L('x'),   L('0'),    L('0'), L(0xa), L('c'), L('o'),
                L('n'),    L('s'),    L('t'),   L(' '),    L('s'), L('t'), L('d'), L(' '),
                L('='),    L(' '),    L('@'),   L('i'),    L('m'), L('p'), L('o'), L('r'),
                L('t'),    L('('),    L('"'),   L('s'),    L('t'), L('d'), L('"'), L(')'),
                L(';'),    L(0xa),    L(0xa),   L('p'),    L('u'), L('b'), L(' '), L('f'),
                L('n'),    L(' '),    L('m'),   L('a'),    L('i'), L('n'), L('('), L(')'),
                L(' '),    L('!'),    L('v'),   L('o'),    L('i'), L('d'), L(' '), L('{'),
                L(0xa),    L(' '),    L(' '),   L(' '),    L(' '), L('v'), L('a'), L('r'),
                L(' '),    L('b'),    L(' '),   L('='),    L(' '), L('['), L('1'), L(']'),
                L('u'),    L('8'),    L('{'),   L('0'),    L('}'), L(' '), L('*'), L('*'),
                L(' '),    L('6'),    L('5'),   L('5'),    L('3'), L('5'), L(';'), M(31, 5),
                M(86, 6),  L('f'),    L(' '),   L('='),    L(' '), L('t'), L('r'), L('y'),
                M(94, 4),  L('.'),    L('f'),   L('s'),    L('.'), L('c'), L('w'), L('d'),
                L('('),    L(')'),    L('.'),   M(144, 6), L('F'), L('i'), L('l'), L('e'),
                L('('),    M(43, 5),  M(1, 4),  L('"'),    L('h'), L('u'), L('f'), L('f'),
                L('m'),    L('a'),    L('n'),   L('-'),    L('n'), L('u'), L('l'), L('l'),
                L('-'),    L('m'),    L('a'),   L('x'),    L('.'), L('i'), L('n'), L('"'),
                L(','),    M(31, 9),  L('.'),   L('{'),    L(' '), L('.'), L('r'), L('e'),
                L('a'),    L('d'),    M(79, 5), L('u'),    L('e'), L(' '), L('}'), M(27, 6),
                L(')'),    M(108, 6), L('d'),   L('e'),    L('f'), L('e'), L('r'), L(' '),
                L('f'),    L('.'),    L('c'),   L('l'),    L('o'), L('s'), L('e'), L('('),
                M(183, 4), M(22, 4),  L('_'),   M(124, 7), L('f'), L('.'), L('w'), L('r'),
                L('i'),    L('t'),    L('e'),   L('A'),    L('l'), L('l'), L('('), L('b'),
                L('['),    L('0'),    L('.'),   L('.'),    L(']'), L(')'), L(';'), L(0xa),
                L('}'),    L(0xa),
            },
        },
        TestCase{
            .input = "huffman-zero.input",
            .want = "huffman-zero.{s}.expect",
            .want_no_input = "huffman-zero.{s}.expect-noinput",
            .tokens = &[_]Token{ L(0x30), ml, M(1, 49) },
        },
        TestCase{
            .input = "",
            .want = "",
            .want_no_input = "null-long-match.{s}.expect-noinput",
            .tokens = &[_]Token{
                L(0x0), ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, ml,      ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml, ml,
                ml,     ml, ml, M(1, 8),
            },
        },
    };
};
//! Token cat be literal: single byte of data or match; reference to the slice of
//! data in the same stream represented with <length, distance>. Where length
//! can be 3 - 258 bytes, and distance 1 - 32768 bytes.
//!
const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;
const expect = std.testing.expect;
const consts = @import("consts.zig").match;

const Token = @This();

pub const Kind = enum(u1) {
    literal,
    match,
};

// Distance range 1 - 32768, stored in dist as 0 - 32767 (fits u15)
dist: u15 = 0,
// Length range 3 - 258, stored in len_lit as 0 - 255 (fits u8)
len_lit: u8 = 0,
kind: Kind = .literal,

pub fn literal(t: Token) u8 {
    return t.len_lit;
}

pub fn distance(t: Token) u16 {
    return @as(u16, t.dist) + consts.min_distance;
}

pub fn length(t: Token) u16 {
    return @as(u16, t.len_lit) + consts.base_length;
}

pub fn initLiteral(lit: u8) Token {
    return .{ .kind = .literal, .len_lit = lit };
}

// distance range 1 - 32768, stored in dist as 0 - 32767 (u15)
// length range 3 - 258, stored in len_lit as 0 - 255 (u8)
pub fn initMatch(dist: u16, len: u16) Token {
    assert(len >= consts.min_length and len <= consts.max_length);
    assert(dist >= consts.min_distance and dist <= consts.max_distance);
    return .{
        .kind = .match,
        .dist = @intCast(dist - consts.min_distance),
        .len_lit = @intCast(len - consts.base_length),
    };
}

pub fn eql(t: Token, o: Token) bool {
    return t.kind == o.kind and
        t.dist == o.dist and
        t.len_lit == o.len_lit;
}

pub fn lengthCode(t: Token) u16 {
    return match_lengths[match_lengths_index[t.len_lit]].code;
}

pub fn lengthEncoding(t: Token) MatchLength {
    var c = match_lengths[match_lengths_index[t.len_lit]];
    c.extra_length = t.len_lit - c.base_scaled;
    return c;
}

// Returns the distance code corresponding to a specific distance.
// Distance code is in range: 0 - 29.
pub fn distanceCode(t: Token) u8 {
    var dist: u16 = t.dist;
    if (dist < match_distances_index.len) {
        return match_distances_index[dist];
    }
    dist >>= 7;
    if (dist < match_distances_index.len) {
        return match_distances_index[dist] + 14;
    }
    dist >>= 7;
    return match_distances_index[dist] + 28;
}

pub fn distanceEncoding(t: Token) MatchDistance {
    var c = match_distances[t.distanceCode()];
    c.extra_distance = t.dist - c.base_scaled;
    return c;
}

pub fn lengthExtraBits(code: u32) u8 {
    return match_lengths[code - length_codes_start].extra_bits;
}

pub fn matchLength(code: u8) MatchLength {
    return match_lengths[code];
}

pub fn matchDistance(code: u8) MatchDistance {
    return match_distances[code];
}

pub fn distanceExtraBits(code: u32) u8 {
    return match_distances[code].extra_bits;
}

pub fn show(t: Token) void {
    if (t.kind == .literal) {
        print("L('{c}'), ", .{t.literal()});
    } else {
        print("M({d}, {d}), ", .{ t.distance(), t.length() });
    }
}

// Returns index in match_lengths table for each length in range 0-255.
const match_lengths_index = [_]u8{
    0,  1,  2,  3,  4,  5,  6,  7,  8,  8,
    9,  9,  10, 10, 11, 11, 12, 12, 12, 12,
    13, 13, 13, 13, 14, 14, 14, 14, 15, 15,
    15, 15, 16, 16, 16, 16, 16, 16, 16, 16,
    17, 17, 17, 17, 17, 17, 17, 17, 18, 18,
    18, 18, 18, 18, 18, 18, 19, 19, 19, 19,
    19, 19, 19, 19, 20, 20, 20, 20, 20, 20,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
    21, 21, 21, 21, 21, 21, 22, 22, 22, 22,
    22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
    22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
    23, 23, 23, 23, 23, 23, 23, 23, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 28,
};

const MatchLength = struct {
    code: u16,
    base_scaled: u8, // base - 3, scaled to fit into u8 (0-255), same as lit_len field in Token.
    base: u16, // 3-258
    extra_length: u8 = 0,
    extra_bits: u4,
};

// match_lengths represents table from rfc (https://datatracker.ietf.org/doc/html/rfc1951#page-12)
//
//      Extra               Extra               Extra
// Code Bits Length(s) Code Bits Lengths   Code Bits Length(s)
// ---- ---- ------     ---- ---- -------   ---- ---- -------
//  257   0     3       267   1   15,16     277   4   67-82
//  258   0     4       268   1   17,18     278   4   83-98
//  259   0     5       269   2   19-22     279   4   99-114
//  260   0     6       270   2   23-26     280   4  115-130
//  261   0     7       271   2   27-30     281   5  131-162
//  262   0     8       272   2   31-34     282   5  163-194
//  263   0     9       273   3   35-42     283   5  195-226
//  264   0    10       274   3   43-50     284   5  227-257
//  265   1  11,12      275   3   51-58     285   0    258
//  266   1  13,14      276   3   59-66
//
pub const length_codes_start = 257;

const match_lengths = [_]MatchLength{
    .{ .extra_bits = 0, .base_scaled = 0, .base = 3, .code = 257 },
    .{ .extra_bits = 0, .base_scaled = 1, .base = 4, .code = 258 },
    .{ .extra_bits = 0, .base_scaled = 2, .base = 5, .code = 259 },
    .{ .extra_bits = 0, .base_scaled = 3, .base = 6, .code = 260 },
    .{ .extra_bits = 0, .base_scaled = 4, .base = 7, .code = 261 },
    .{ .extra_bits = 0, .base_scaled = 5, .base = 8, .code = 262 },
    .{ .extra_bits = 0, .base_scaled = 6, .base = 9, .code = 263 },
    .{ .extra_bits = 0, .base_scaled = 7, .base = 10, .code = 264 },
    .{ .extra_bits = 1, .base_scaled = 8, .base = 11, .code = 265 },
    .{ .extra_bits = 1, .base_scaled = 10, .base = 13, .code = 266 },
    .{ .extra_bits = 1, .base_scaled = 12, .base = 15, .code = 267 },
    .{ .extra_bits = 1, .base_scaled = 14, .base = 17, .code = 268 },
    .{ .extra_bits = 2, .base_scaled = 16, .base = 19, .code = 269 },
    .{ .extra_bits = 2, .base_scaled = 20, .base = 23, .code = 270 },
    .{ .extra_bits = 2, .base_scaled = 24, .base = 27, .code = 271 },
    .{ .extra_bits = 2, .base_scaled = 28, .base = 31, .code = 272 },
    .{ .extra_bits = 3, .base_scaled = 32, .base = 35, .code = 273 },
    .{ .extra_bits = 3, .base_scaled = 40, .base = 43, .code = 274 },
    .{ .extra_bits = 3, .base_scaled = 48, .base = 51, .code = 275 },
    .{ .extra_bits = 3, .base_scaled = 56, .base = 59, .code = 276 },
    .{ .extra_bits = 4, .base_scaled = 64, .base = 67, .code = 277 },
    .{ .extra_bits = 4, .base_scaled = 80, .base = 83, .code = 278 },
    .{ .extra_bits = 4, .base_scaled = 96, .base = 99, .code = 279 },
    .{ .extra_bits = 4, .base_scaled = 112, .base = 115, .code = 280 },
    .{ .extra_bits = 5, .base_scaled = 128, .base = 131, .code = 281 },
    .{ .extra_bits = 5, .base_scaled = 160, .base = 163, .code = 282 },
    .{ .extra_bits = 5, .base_scaled = 192, .base = 195, .code = 283 },
    .{ .extra_bits = 5, .base_scaled = 224, .base = 227, .code = 284 },
    .{ .extra_bits = 0, .base_scaled = 255, .base = 258, .code = 285 },
};

// Used in distanceCode fn to get index in match_distance table for each distance in range 0-32767.
const match_distances_index = [_]u8{
    0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,
    8,  8,  8,  8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
};

const MatchDistance = struct {
    base_scaled: u16, // base - 1, same as Token dist field
    base: u16,
    extra_distance: u16 = 0,
    code: u8,
    extra_bits: u4,
};

// match_distances represents table from rfc (https://datatracker.ietf.org/doc/html/rfc1951#page-12)
//
//      Extra           Extra               Extra
// Code Bits Dist  Code Bits   Dist     Code Bits Distance
// ---- ---- ----  ---- ----  ------    ---- ---- --------
//   0   0    1     10   4     33-48    20    9   1025-1536
//   1   0    2     11   4     49-64    21    9   1537-2048
//   2   0    3     12   5     65-96    22   10   2049-3072
//   3   0    4     13   5     97-128   23   10   3073-4096
//   4   1   5,6    14   6    129-192   24   11   4097-6144
//   5   1   7,8    15   6    193-256   25   11   6145-8192
//   6   2   9-12   16   7    257-384   26   12  8193-12288
//   7   2  13-16   17   7    385-512   27   12 12289-16384
//   8   3  17-24   18   8    513-768   28   13 16385-24576
//   9   3  25-32   19   8   769-1024   29   13 24577-32768
//
const match_distances = [_]MatchDistance{
    .{ .extra_bits = 0, .base_scaled = 0x0000, .code = 0, .base = 1 },
    .{ .extra_bits = 0, .base_scaled = 0x0001, .code = 1, .base = 2 },
    .{ .extra_bits = 0, .base_scaled = 0x0002, .code = 2, .base = 3 },
    .{ .extra_bits = 0, .base_scaled = 0x0003, .code = 3, .base = 4 },
    .{ .extra_bits = 1, .base_scaled = 0x0004, .code = 4, .base = 5 },
    .{ .extra_bits = 1, .base_scaled = 0x0006, .code = 5, .base = 7 },
    .{ .extra_bits = 2, .base_scaled = 0x0008, .code = 6, .base = 9 },
    .{ .extra_bits = 2, .base_scaled = 0x000c, .code = 7, .base = 13 },
    .{ .extra_bits = 3, .base_scaled = 0x0010, .code = 8, .base = 17 },
    .{ .extra_bits = 3, .base_scaled = 0x0018, .code = 9, .base = 25 },
    .{ .extra_bits = 4, .base_scaled = 0x0020, .code = 10, .base = 33 },
    .{ .extra_bits = 4, .base_scaled = 0x0030, .code = 11, .base = 49 },
    .{ .extra_bits = 5, .base_scaled = 0x0040, .code = 12, .base = 65 },
    .{ .extra_bits = 5, .base_scaled = 0x0060, .code = 13, .base = 97 },
    .{ .extra_bits = 6, .base_scaled = 0x0080, .code = 14, .base = 129 },
    .{ .extra_bits = 6, .base_scaled = 0x00c0, .code = 15, .base = 193 },
    .{ .extra_bits = 7, .base_scaled = 0x0100, .code = 16, .base = 257 },
    .{ .extra_bits = 7, .base_scaled = 0x0180, .code = 17, .base = 385 },
    .{ .extra_bits = 8, .base_scaled = 0x0200, .code = 18, .base = 513 },
    .{ .extra_bits = 8, .base_scaled = 0x0300, .code = 19, .base = 769 },
    .{ .extra_bits = 9, .base_scaled = 0x0400, .code = 20, .base = 1025 },
    .{ .extra_bits = 9, .base_scaled = 0x0600, .code = 21, .base = 1537 },
    .{ .extra_bits = 10, .base_scaled = 0x0800, .code = 22, .base = 2049 },
    .{ .extra_bits = 10, .base_scaled = 0x0c00, .code = 23, .base = 3073 },
    .{ .extra_bits = 11, .base_scaled = 0x1000, .code = 24, .base = 4097 },
    .{ .extra_bits = 11, .base_scaled = 0x1800, .code = 25, .base = 6145 },
    .{ .extra_bits = 12, .base_scaled = 0x2000, .code = 26, .base = 8193 },
    .{ .extra_bits = 12, .base_scaled = 0x3000, .code = 27, .base = 12289 },
    .{ .extra_bits = 13, .base_scaled = 0x4000, .code = 28, .base = 16385 },
    .{ .extra_bits = 13, .base_scaled = 0x6000, .code = 29, .base = 24577 },
};

test "size" {
    try expect(@sizeOf(Token) == 4);
}

// testing table https://datatracker.ietf.org/doc/html/rfc1951#page-12
test "MatchLength" {
    var c = Token.initMatch(1, 4).lengthEncoding();
    try expect(c.code == 258);
    try expect(c.extra_bits == 0);
    try expect(c.extra_length == 0);

    c = Token.initMatch(1, 11).lengthEncoding();
    try expect(c.code == 265);
    try expect(c.extra_bits == 1);
    try expect(c.extra_length == 0);

    c = Token.initMatch(1, 12).lengthEncoding();
    try expect(c.code == 265);
    try expect(c.extra_bits == 1);
    try expect(c.extra_length == 1);

    c = Token.initMatch(1, 130).lengthEncoding();
    try expect(c.code == 280);
    try expect(c.extra_bits == 4);
    try expect(c.extra_length == 130 - 115);
}

test "MatchDistance" {
    var c = Token.initMatch(1, 4).distanceEncoding();
    try expect(c.code == 0);
    try expect(c.extra_bits == 0);
    try expect(c.extra_distance == 0);

    c = Token.initMatch(192, 4).distanceEncoding();
    try expect(c.code == 14);
    try expect(c.extra_bits == 6);
    try expect(c.extra_distance == 192 - 129);
}

test "match_lengths" {
    for (match_lengths, 0..) |ml, i| {
        try expect(@as(u16, ml.base_scaled) + 3 == ml.base);
        try expect(i + 257 == ml.code);
    }

    for (match_distances, 0..) |mo, i| {
        try expect(mo.base_scaled + 1 == mo.base);
        try expect(i == mo.code);
    }
}
const deflate = @import("flate/deflate.zig");
const inflate = @import("flate/inflate.zig");

/// Decompress compressed data from reader and write plain data to the writer.
pub fn decompress(reader: anytype, writer: anytype) !void {
    try inflate.decompress(.gzip, reader, writer);
}

/// Decompressor type
pub fn Decompressor(comptime ReaderType: type) type {
    return inflate.Decompressor(.gzip, ReaderType);
}

/// Create Decompressor which will read compressed data from reader.
pub fn decompressor(reader: anytype) Decompressor(@TypeOf(reader)) {
    return inflate.decompressor(.gzip, reader);
}

/// Compression level, trades between speed and compression size.
pub const Options = deflate.Options;

/// Compress plain data from reader and write compressed data to the writer.
pub fn compress(reader: anytype, writer: anytype, options: Options) !void {
    try deflate.compress(.gzip, reader, writer, options);
}

/// Compressor type
pub fn Compressor(comptime WriterType: type) type {
    return deflate.Compressor(.gzip, WriterType);
}

/// Create Compressor which outputs compressed data to the writer.
pub fn compressor(writer: anytype, options: Options) !Compressor(@TypeOf(writer)) {
    return try deflate.compressor(.gzip, writer, options);
}

/// Huffman only compression. Without Lempel-Ziv match searching. Faster
/// compression, less memory requirements but bigger compressed sizes.
pub const huffman = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.huffman.compress(.gzip, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.huffman.Compressor(.gzip, WriterType);
    }

    pub fn compressor(writer: anytype) !huffman.Compressor(@TypeOf(writer)) {
        return deflate.huffman.compressor(.gzip, writer);
    }
};

// No compression store only. Compressed size is slightly bigger than plain.
pub const store = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.store.compress(.gzip, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.store.Compressor(.gzip, WriterType);
    }

    pub fn compressor(writer: anytype) !store.Compressor(@TypeOf(writer)) {
        return deflate.store.compressor(.gzip, writer);
    }
};
const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const Allocator = std.mem.Allocator;

pub const decode = @import("lzma/decode.zig");

pub fn decompress(
    allocator: Allocator,
    reader: anytype,
) !Decompress(@TypeOf(reader)) {
    return decompressWithOptions(allocator, reader, .{});
}

pub fn decompressWithOptions(
    allocator: Allocator,
    reader: anytype,
    options: decode.Options,
) !Decompress(@TypeOf(reader)) {
    const params = try decode.Params.readHeader(reader, options);
    return Decompress(@TypeOf(reader)).init(allocator, reader, params, options.memlimit);
}

pub fn Decompress(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        pub const Error =
            ReaderType.Error ||
            Allocator.Error ||
            error{ CorruptInput, EndOfStream, Overflow };

        pub const Reader = std.io.Reader(*Self, Error, read);

        allocator: Allocator,
        in_reader: ReaderType,
        to_read: std.ArrayListUnmanaged(u8),

        buffer: decode.lzbuffer.LzCircularBuffer,
        decoder: decode.rangecoder.RangeDecoder,
        state: decode.DecoderState,

        pub fn init(allocator: Allocator, source: ReaderType, params: decode.Params, memlimit: ?usize) !Self {
            return Self{
                .allocator = allocator,
                .in_reader = source,
                .to_read = .{},

                .buffer = decode.lzbuffer.LzCircularBuffer.init(params.dict_size, memlimit orelse math.maxInt(usize)),
                .decoder = try decode.rangecoder.RangeDecoder.init(source),
                .state = try decode.DecoderState.init(allocator, params.properties, params.unpacked_size),
            };
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn deinit(self: *Self) void {
            self.to_read.deinit(self.allocator);
            self.buffer.deinit(self.allocator);
            self.state.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn read(self: *Self, output: []u8) Error!usize {
            const writer = self.to_read.writer(self.allocator);
            while (self.to_read.items.len < output.len) {
                switch (try self.state.process(self.allocator, self.in_reader, writer, &self.buffer, &self.decoder)) {
                    .continue_ => {},
                    .finished => {
                        try self.buffer.finish(writer);
                        break;
                    },
                }
            }
            const input = self.to_read.items;
            const n = @min(input.len, output.len);
            @memcpy(output[0..n], input[0..n]);
            std.mem.copyForwards(u8, input[0 .. input.len - n], input[n..]);
            self.to_read.shrinkRetainingCapacity(input.len - n);
            return n;
        }
    };
}

test {
    _ = @import("lzma/test.zig");
    _ = @import("lzma/vec2d.zig");
}
const std = @import("../../std.zig");
const assert = std.debug.assert;
const math = std.math;
const Allocator = std.mem.Allocator;

pub const lzbuffer = @import("decode/lzbuffer.zig");
pub const rangecoder = @import("decode/rangecoder.zig");

const LzCircularBuffer = lzbuffer.LzCircularBuffer;
const BitTree = rangecoder.BitTree;
const LenDecoder = rangecoder.LenDecoder;
const RangeDecoder = rangecoder.RangeDecoder;
const Vec2D = @import("vec2d.zig").Vec2D;

pub const Options = struct {
    unpacked_size: UnpackedSize = .read_from_header,
    memlimit: ?usize = null,
    allow_incomplete: bool = false,
};

pub const UnpackedSize = union(enum) {
    read_from_header,
    read_header_but_use_provided: ?u64,
    use_provided: ?u64,
};

const ProcessingStatus = enum {
    continue_,
    finished,
};

pub const Properties = struct {
    lc: u4,
    lp: u3,
    pb: u3,

    fn validate(self: Properties) void {
        assert(self.lc <= 8);
        assert(self.lp <= 4);
        assert(self.pb <= 4);
    }
};

pub const Params = struct {
    properties: Properties,
    dict_size: u32,
    unpacked_size: ?u64,

    pub fn readHeader(reader: anytype, options: Options) !Params {
        var props = try reader.readByte();
        if (props >= 225) {
            return error.CorruptInput;
        }

        const lc = @as(u4, @intCast(props % 9));
        props /= 9;
        const lp = @as(u3, @intCast(props % 5));
        props /= 5;
        const pb = @as(u3, @intCast(props));

        const dict_size_provided = try reader.readInt(u32, .little);
        const dict_size = @max(0x1000, dict_size_provided);

        const unpacked_size = switch (options.unpacked_size) {
            .read_from_header => blk: {
                const unpacked_size_provided = try reader.readInt(u64, .little);
                const marker_mandatory = unpacked_size_provided == 0xFFFF_FFFF_FFFF_FFFF;
                break :blk if (marker_mandatory)
                    null
                else
                    unpacked_size_provided;
            },
            .read_header_but_use_provided => |x| blk: {
                _ = try reader.readInt(u64, .little);
                break :blk x;
            },
            .use_provided => |x| x,
        };

        return Params{
            .properties = Properties{ .lc = lc, .lp = lp, .pb = pb },
            .dict_size = dict_size,
            .unpacked_size = unpacked_size,
        };
    }
};

pub const DecoderState = struct {
    lzma_props: Properties,
    unpacked_size: ?u64,
    literal_probs: Vec2D(u16),
    pos_slot_decoder: [4]BitTree(6),
    align_decoder: BitTree(4),
    pos_decoders: [115]u16,
    is_match: [192]u16,
    is_rep: [12]u16,
    is_rep_g0: [12]u16,
    is_rep_g1: [12]u16,
    is_rep_g2: [12]u16,
    is_rep_0long: [192]u16,
    state: usize,
    rep: [4]usize,
    len_decoder: LenDecoder,
    rep_len_decoder: LenDecoder,

    pub fn init(
        allocator: Allocator,
        lzma_props: Properties,
        unpacked_size: ?u64,
    ) !DecoderState {
        return .{
            .lzma_props = lzma_props,
            .unpacked_size = unpacked_size,
            .literal_probs = try Vec2D(u16).init(allocator, 0x400, .{ @as(usize, 1) << (lzma_props.lc + lzma_props.lp), 0x300 }),
            .pos_slot_decoder = @splat(.{}),
            .align_decoder = .{},
            .pos_decoders = @splat(0x400),
            .is_match = @splat(0x400),
            .is_rep = @splat(0x400),
            .is_rep_g0 = @splat(0x400),
            .is_rep_g1 = @splat(0x400),
            .is_rep_g2 = @splat(0x400),
            .is_rep_0long = @splat(0x400),
            .state = 0,
            .rep = @splat(0),
            .len_decoder = .{},
            .rep_len_decoder = .{},
        };
    }

    pub fn deinit(self: *DecoderState, allocator: Allocator) void {
        self.literal_probs.deinit(allocator);
        self.* = undefined;
    }

    pub fn resetState(self: *DecoderState, allocator: Allocator, new_props: Properties) !void {
        new_props.validate();
        if (self.lzma_props.lc + self.lzma_props.lp == new_props.lc + new_props.lp) {
            self.literal_probs.fill(0x400);
        } else {
            self.literal_probs.deinit(allocator);
            self.literal_probs = try Vec2D(u16).init(allocator, 0x400, .{ @as(usize, 1) << (new_props.lc + new_props.lp), 0x300 });
        }

        self.lzma_props = new_props;
        for (&self.pos_slot_decoder) |*t| t.reset();
        self.align_decoder.reset();
        self.pos_decoders = @splat(0x400);
        self.is_match = @splat(0x400);
        self.is_rep = @splat(0x400);
        self.is_rep_g0 = @splat(0x400);
        self.is_rep_g1 = @splat(0x400);
        self.is_rep_g2 = @splat(0x400);
        self.is_rep_0long = @splat(0x400);
        self.state = 0;
        self.rep = @splat(0);
        self.len_decoder.reset();
        self.rep_len_decoder.reset();
    }

    fn processNextInner(
        self: *DecoderState,
        allocator: Allocator,
        reader: anytype,
        writer: anytype,
        buffer: anytype,
        decoder: *RangeDecoder,
        update: bool,
    ) !ProcessingStatus {
        const pos_state = buffer.len & ((@as(usize, 1) << self.lzma_props.pb) - 1);

        if (!try decoder.decodeBit(
            reader,
            &self.is_match[(self.state << 4) + pos_state],
            update,
        )) {
            const byte: u8 = try self.decodeLiteral(reader, buffer, decoder, update);

            if (update) {
                try buffer.appendLiteral(allocator, byte, writer);

                self.state = if (self.state < 4)
                    0
                else if (self.state < 10)
                    self.state - 3
                else
                    self.state - 6;
            }
            return .continue_;
        }

        var len: usize = undefined;
        if (try decoder.decodeBit(reader, &self.is_rep[self.state], update)) {
            if (!try decoder.decodeBit(reader, &self.is_rep_g0[self.state], update)) {
                if (!try decoder.decodeBit(
                    reader,
                    &self.is_rep_0long[(self.state << 4) + pos_state],
                    update,
                )) {
                    if (update) {
                        self.state = if (self.state < 7) 9 else 11;
                        const dist = self.rep[0] + 1;
                        try buffer.appendLz(allocator, 1, dist, writer);
                    }
                    return .continue_;
                }
            } else {
                const idx: usize = if (!try decoder.decodeBit(reader, &self.is_rep_g1[self.state], update))
                    1
                else if (!try decoder.decodeBit(reader, &self.is_rep_g2[self.state], update))
                    2
                else
                    3;
                if (update) {
                    const dist = self.rep[idx];
                    var i = idx;
                    while (i > 0) : (i -= 1) {
                        self.rep[i] = self.rep[i - 1];
                    }
                    self.rep[0] = dist;
                }
            }

            len = try self.rep_len_decoder.decode(reader, decoder, pos_state, update);

            if (update) {
                self.state = if (self.state < 7) 8 else 11;
            }
        } else {
            if (update) {
                self.rep[3] = self.rep[2];
                self.rep[2] = self.rep[1];
                self.rep[1] = self.rep[0];
            }

            len = try self.len_decoder.decode(reader, decoder, pos_state, update);

            if (update) {
                self.state = if (self.state < 7) 7 else 10;
            }

            const rep_0 = try self.decodeDistance(reader, decoder, len, update);

            if (update) {
                self.rep[0] = rep_0;
                if (self.rep[0] == 0xFFFF_FFFF) {
                    if (decoder.isFinished()) {
                        return .finished;
                    }
                    return error.CorruptInput;
                }
            }
        }

        if (update) {
            len += 2;

            const dist = self.rep[0] + 1;
            try buffer.appendLz(allocator, len, dist, writer);
        }

        return .continue_;
    }

    fn processNext(
        self: *DecoderState,
        allocator: Allocator,
        reader: anytype,
        writer: anytype,
        buffer: anytype,
        decoder: *RangeDecoder,
    ) !ProcessingStatus {
        return self.processNextInner(allocator, reader, writer, buffer, decoder, true);
    }

    pub fn process(
        self: *DecoderState,
        allocator: Allocator,
        reader: anytype,
        writer: anytype,
        buffer: anytype,
        decoder: *RangeDecoder,
    ) !ProcessingStatus {
        process_next: {
            if (self.unpacked_size) |unpacked_size| {
                if (buffer.len >= unpacked_size) {
                    break :process_next;
                }
            } else if (decoder.isFinished()) {
                break :process_next;
            }

            switch (try self.processNext(allocator, reader, writer, buffer, decoder)) {
                .continue_ => return .continue_,
                .finished => break :process_next,
            }
        }

        if (self.unpacked_size) |unpacked_size| {
            if (buffer.len != unpacked_size) {
                return error.CorruptInput;
            }
        }

        return .finished;
    }

    fn decodeLiteral(
        self: *DecoderState,
        reader: anytype,
        buffer: anytype,
        decoder: *RangeDecoder,
        update: bool,
    ) !u8 {
        const def_prev_byte = 0;
        const prev_byte = @as(usize, buffer.lastOr(def_prev_byte));

        var result: usize = 1;
        const lit_state = ((buffer.len & ((@as(usize, 1) << self.lzma_props.lp) - 1)) << self.lzma_props.lc) +
            (prev_byte >> (8 - self.lzma_props.lc));
        const probs = try self.literal_probs.getMut(lit_state);

        if (self.state >= 7) {
            var match_byte = @as(usize, try buffer.lastN(self.rep[0] + 1));

            while (result < 0x100) {
                const match_bit = (match_byte >> 7) & 1;
                match_byte <<= 1;
                const bit = @intFromBool(try decoder.decodeBit(
                    reader,
                    &probs[((@as(usize, 1) + match_bit) << 8) + result],
                    update,
                ));
                result = (result << 1) ^ bit;
                if (match_bit != bit) {
                    break;
                }
            }
        }

        while (result < 0x100) {
            result = (result << 1) ^ @intFromBool(try decoder.decodeBit(reader, &probs[result], update));
        }

        return @as(u8, @truncate(result - 0x100));
    }

    fn decodeDistance(
        self: *DecoderState,
        reader: anytype,
        decoder: *RangeDecoder,
        length: usize,
        update: bool,
    ) !usize {
        const len_state = if (length > 3) 3 else length;

        const pos_slot = @as(usize, try self.pos_slot_decoder[len_state].parse(reader, decoder, update));
        if (pos_slot < 4)
            return pos_slot;

        const num_direct_bits = @as(u5, @intCast((pos_slot >> 1) - 1));
        var result = (2 ^ (pos_slot & 1)) << num_direct_bits;

        if (pos_slot < 14) {
            result += try decoder.parseReverseBitTree(
                reader,
                num_direct_bits,
                &self.pos_decoders,
                result - pos_slot,
                update,
            );
        } else {
            result += @as(usize, try decoder.get(reader, num_direct_bits - 4)) << 4;
            result += try self.align_decoder.parseReverse(reader, decoder, update);
        }

        return result;
    }
};
const std = @import("../../../std.zig");
const math = std.math;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

/// An accumulating buffer for LZ sequences
pub const LzAccumBuffer = struct {
    /// Buffer
    buf: ArrayListUnmanaged(u8),

    /// Buffer memory limit
    memlimit: usize,

    /// Total number of bytes sent through the buffer
    len: usize,

    const Self = @This();

    pub fn init(memlimit: usize) Self {
        return Self{
            .buf = .{},
            .memlimit = memlimit,
            .len = 0,
        };
    }

    pub fn appendByte(self: *Self, allocator: Allocator, byte: u8) !void {
        try self.buf.append(allocator, byte);
        self.len += 1;
    }

    /// Reset the internal dictionary
    pub fn reset(self: *Self, writer: anytype) !void {
        try writer.writeAll(self.buf.items);
        self.buf.clearRetainingCapacity();
        self.len = 0;
    }

    /// Retrieve the last byte or return a default
    pub fn lastOr(self: Self, lit: u8) u8 {
        const buf_len = self.buf.items.len;
        return if (buf_len == 0)
            lit
        else
            self.buf.items[buf_len - 1];
    }

    /// Retrieve the n-th last byte
    pub fn lastN(self: Self, dist: usize) !u8 {
        const buf_len = self.buf.items.len;
        if (dist > buf_len) {
            return error.CorruptInput;
        }

        return self.buf.items[buf_len - dist];
    }

    /// Append a literal
    pub fn appendLiteral(
        self: *Self,
        allocator: Allocator,
        lit: u8,
        writer: anytype,
    ) !void {
        _ = writer;
        if (self.len >= self.memlimit) {
            return error.CorruptInput;
        }
        try self.buf.append(allocator, lit);
        self.len += 1;
    }

    /// Fetch an LZ sequence (length, distance) from inside the buffer
    pub fn appendLz(
        self: *Self,
        allocator: Allocator,
        len: usize,
        dist: usize,
        writer: anytype,
    ) !void {
        _ = writer;

        const buf_len = self.buf.items.len;
        if (dist > buf_len) {
            return error.CorruptInput;
        }

        var offset = buf_len - dist;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            const x = self.buf.items[offset];
            try self.buf.append(allocator, x);
            offset += 1;
        }
        self.len += len;
    }

    pub fn finish(self: *Self, writer: anytype) !void {
        try writer.writeAll(self.buf.items);
        self.buf.clearRetainingCapacity();
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.buf.deinit(allocator);
        self.* = undefined;
    }
};

/// A circular buffer for LZ sequences
pub const LzCircularBuffer = struct {
    /// Circular buffer
    buf: ArrayListUnmanaged(u8),

    /// Length of the buffer
    dict_size: usize,

    /// Buffer memory limit
    memlimit: usize,

    /// Current position
    cursor: usize,

    /// Total number of bytes sent through the buffer
    len: usize,

    const Self = @This();

    pub fn init(dict_size: usize, memlimit: usize) Self {
        return Self{
            .buf = .{},
            .dict_size = dict_size,
            .memlimit = memlimit,
            .cursor = 0,
            .len = 0,
        };
    }

    pub fn get(self: Self, index: usize) u8 {
        return if (0 <= index and index < self.buf.items.len)
            self.buf.items[index]
        else
            0;
    }

    pub fn set(self: *Self, allocator: Allocator, index: usize, value: u8) !void {
        if (index >= self.memlimit) {
            return error.CorruptInput;
        }
        try self.buf.ensureTotalCapacity(allocator, index + 1);
        while (self.buf.items.len < index) {
            self.buf.appendAssumeCapacity(0);
        }
        self.buf.appendAssumeCapacity(value);
    }

    /// Retrieve the last byte or return a default
    pub fn lastOr(self: Self, lit: u8) u8 {
        return if (self.len == 0)
            lit
        else
            self.get((self.dict_size + self.cursor - 1) % self.dict_size);
    }

    /// Retrieve the n-th last byte
    pub fn lastN(self: Self, dist: usize) !u8 {
        if (dist > self.dict_size or dist > self.len) {
            return error.CorruptInput;
        }

        const offset = (self.dict_size + self.cursor - dist) % self.dict_size;
        return self.get(offset);
    }

    /// Append a literal
    pub fn appendLiteral(
        self: *Self,
        allocator: Allocator,
        lit: u8,
        writer: anytype,
    ) !void {
        try self.set(allocator, self.cursor, lit);
        self.cursor += 1;
        self.len += 1;

        // Flush the circular buffer to the output
        if (self.cursor == self.dict_size) {
            try writer.writeAll(self.buf.items);
            self.cursor = 0;
        }
    }

    /// Fetch an LZ sequence (length, distance) from inside the buffer
    pub fn appendLz(
        self: *Self,
        allocator: Allocator,
        len: usize,
        dist: usize,
        writer: anytype,
    ) !void {
        if (dist > self.dict_size or dist > self.len) {
            return error.CorruptInput;
        }

        var offset = (self.dict_size + self.cursor - dist) % self.dict_size;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            const x = self.get(offset);
            try self.appendLiteral(allocator, x, writer);
            offset += 1;
            if (offset == self.dict_size) {
                offset = 0;
            }
        }
    }

    pub fn finish(self: *Self, writer: anytype) !void {
        if (self.cursor > 0) {
            try writer.writeAll(self.buf.items[0..self.cursor]);
            self.cursor = 0;
        }
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.buf.deinit(allocator);
        self.* = undefined;
    }
};
const std = @import("../../../std.zig");
const mem = std.mem;

pub const RangeDecoder = struct {
    range: u32,
    code: u32,

    pub fn init(reader: anytype) !RangeDecoder {
        const reserved = try reader.readByte();
        if (reserved != 0) {
            return error.CorruptInput;
        }
        return RangeDecoder{
            .range = 0xFFFF_FFFF,
            .code = try reader.readInt(u32, .big),
        };
    }

    pub fn fromParts(
        range: u32,
        code: u32,
    ) RangeDecoder {
        return .{
            .range = range,
            .code = code,
        };
    }

    pub fn set(self: *RangeDecoder, range: u32, code: u32) void {
        self.range = range;
        self.code = code;
    }

    pub inline fn isFinished(self: RangeDecoder) bool {
        return self.code == 0;
    }

    inline fn normalize(self: *RangeDecoder, reader: anytype) !void {
        if (self.range < 0x0100_0000) {
            self.range <<= 8;
            self.code = (self.code << 8) ^ @as(u32, try reader.readByte());
        }
    }

    inline fn getBit(self: *RangeDecoder, reader: anytype) !bool {
        self.range >>= 1;

        const bit = self.code >= self.range;
        if (bit)
            self.code -= self.range;

        try self.normalize(reader);
        return bit;
    }

    pub fn get(self: *RangeDecoder, reader: anytype, count: usize) !u32 {
        var result: u32 = 0;
        var i: usize = 0;
        while (i < count) : (i += 1)
            result = (result << 1) ^ @intFromBool(try self.getBit(reader));
        return result;
    }

    pub inline fn decodeBit(self: *RangeDecoder, reader: anytype, prob: *u16, update: bool) !bool {
        const bound = (self.range >> 11) * prob.*;

        if (self.code < bound) {
            if (update)
                prob.* += (0x800 - prob.*) >> 5;
            self.range = bound;

            try self.normalize(reader);
            return false;
        } else {
            if (update)
                prob.* -= prob.* >> 5;
            self.code -= bound;
            self.range -= bound;

            try self.normalize(reader);
            return true;
        }
    }

    fn parseBitTree(
        self: *RangeDecoder,
        reader: anytype,
        num_bits: u5,
        probs: []u16,
        update: bool,
    ) !u32 {
        var tmp: u32 = 1;
        var i: @TypeOf(num_bits) = 0;
        while (i < num_bits) : (i += 1) {
            const bit = try self.decodeBit(reader, &probs[tmp], update);
            tmp = (tmp << 1) ^ @intFromBool(bit);
        }
        return tmp - (@as(u32, 1) << num_bits);
    }

    pub fn parseReverseBitTree(
        self: *RangeDecoder,
        reader: anytype,
        num_bits: u5,
        probs: []u16,
        offset: usize,
        update: bool,
    ) !u32 {
        var result: u32 = 0;
        var tmp: usize = 1;
        var i: @TypeOf(num_bits) = 0;
        while (i < num_bits) : (i += 1) {
            const bit = @intFromBool(try self.decodeBit(reader, &probs[offset + tmp], update));
            tmp = (tmp << 1) ^ bit;
            result ^= @as(u32, bit) << i;
        }
        return result;
    }
};

pub fn BitTree(comptime num_bits: usize) type {
    return struct {
        probs: [1 << num_bits]u16 = @splat(0x400),

        const Self = @This();

        pub fn parse(
            self: *Self,
            reader: anytype,
            decoder: *RangeDecoder,
            update: bool,
        ) !u32 {
            return decoder.parseBitTree(reader, num_bits, &self.probs, update);
        }

        pub fn parseReverse(
            self: *Self,
            reader: anytype,
            decoder: *RangeDecoder,
            update: bool,
        ) !u32 {
            return decoder.parseReverseBitTree(reader, num_bits, &self.probs, 0, update);
        }

        pub fn reset(self: *Self) void {
            @memset(&self.probs, 0x400);
        }
    };
}

pub const LenDecoder = struct {
    choice: u16 = 0x400,
    choice2: u16 = 0x400,
    low_coder: [16]BitTree(3) = @splat(.{}),
    mid_coder: [16]BitTree(3) = @splat(.{}),
    high_coder: BitTree(8) = .{},

    pub fn decode(
        self: *LenDecoder,
        reader: anytype,
        decoder: *RangeDecoder,
        pos_state: usize,
        update: bool,
    ) !usize {
        if (!try decoder.decodeBit(reader, &self.choice, update)) {
            return @as(usize, try self.low_coder[pos_state].parse(reader, decoder, update));
        } else if (!try decoder.decodeBit(reader, &self.choice2, update)) {
            return @as(usize, try self.mid_coder[pos_state].parse(reader, decoder, update)) + 8;
        } else {
            return @as(usize, try self.high_coder.parse(reader, decoder, update)) + 16;
        }
    }

    pub fn reset(self: *LenDecoder) void {
        self.choice = 0x400;
        self.choice2 = 0x400;
        for (&self.low_coder) |*t| t.reset();
        for (&self.mid_coder) |*t| t.reset();
        self.high_coder.reset();
    }
};
const std = @import("../../std.zig");
const lzma = @import("../lzma.zig");

fn testDecompress(compressed: []const u8) ![]u8 {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream(compressed);
    var decompressor = try lzma.decompress(allocator, stream.reader());
    defer decompressor.deinit();
    const reader = decompressor.reader();
    return reader.readAllAlloc(allocator, std.math.maxInt(usize));
}

fn testDecompressEqual(expected: []const u8, compressed: []const u8) !void {
    const allocator = std.testing.allocator;
    const decomp = try testDecompress(compressed);
    defer allocator.free(decomp);
    try std.testing.expectEqualSlices(u8, expected, decomp);
}

fn testDecompressError(expected: anyerror, compressed: []const u8) !void {
    return std.testing.expectError(expected, testDecompress(compressed));
}

test "decompress empty world" {
    try testDecompressEqual(
        "",
        &[_]u8{
            0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x83, 0xff,
            0xfb, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
        },
    );
}

test "decompress hello world" {
    try testDecompressEqual(
        "Hello world\n",
        &[_]u8{
            0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x24, 0x19,
            0x49, 0x98, 0x6f, 0x10, 0x19, 0xc6, 0xd7, 0x31, 0xeb, 0x36, 0x50, 0xb2, 0x98, 0x48, 0xff, 0xfe,
            0xa5, 0xb0, 0x00,
        },
    );
}

test "decompress huge dict" {
    try testDecompressEqual(
        "Hello world\n",
        &[_]u8{
            0x5d, 0x7f, 0x7f, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x24, 0x19,
            0x49, 0x98, 0x6f, 0x10, 0x19, 0xc6, 0xd7, 0x31, 0xeb, 0x36, 0x50, 0xb2, 0x98, 0x48, 0xff, 0xfe,
            0xa5, 0xb0, 0x00,
        },
    );
}

test "unknown size with end of payload marker" {
    try testDecompressEqual(
        "Hello\nWorld!\n",
        @embedFile("testdata/good-unknown_size-with_eopm.lzma"),
    );
}

test "known size without end of payload marker" {
    try testDecompressEqual(
        "Hello\nWorld!\n",
        @embedFile("testdata/good-known_size-without_eopm.lzma"),
    );
}

test "known size with end of payload marker" {
    try testDecompressEqual(
        "Hello\nWorld!\n",
        @embedFile("testdata/good-known_size-with_eopm.lzma"),
    );
}

test "too big uncompressed size in header" {
    try testDecompressError(
        error.CorruptInput,
        @embedFile("testdata/bad-too_big_size-with_eopm.lzma"),
    );
}

test "too small uncompressed size in header" {
    try testDecompressError(
        error.CorruptInput,
        @embedFile("testdata/bad-too_small_size-without_eopm-3.lzma"),
    );
}

test "reading one byte" {
    const compressed = @embedFile("testdata/good-known_size-with_eopm.lzma");
    var stream = std.io.fixedBufferStream(compressed);
    var decompressor = try lzma.decompress(std.testing.allocator, stream.reader());
    defer decompressor.deinit();

    var buffer = [1]u8{0};
    _ = try decompressor.read(buffer[0..]);
}
const std = @import("../../std.zig");
const math = std.math;
const mem = std.mem;
const Allocator = std.mem.Allocator;

pub fn Vec2D(comptime T: type) type {
    return struct {
        data: []T,
        cols: usize,

        const Self = @This();

        pub fn init(allocator: Allocator, value: T, size: struct { usize, usize }) !Self {
            const len = try math.mul(usize, size[0], size[1]);
            const data = try allocator.alloc(T, len);
            @memset(data, value);
            return Self{
                .data = data,
                .cols = size[1],
            };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.data);
            self.* = undefined;
        }

        pub fn fill(self: *Self, value: T) void {
            @memset(self.data, value);
        }

        inline fn _get(self: Self, row: usize) ![]T {
            const start_row = try math.mul(usize, row, self.cols);
            const end_row = try math.add(usize, start_row, self.cols);
            return self.data[start_row..end_row];
        }

        pub fn get(self: Self, row: usize) ![]const T {
            return self._get(row);
        }

        pub fn getMut(self: *Self, row: usize) ![]T {
            return self._get(row);
        }
    };
}

const testing = std.testing;
const expectEqualSlices = std.testing.expectEqualSlices;
const expectError = std.testing.expectError;

test "init" {
    const allocator = testing.allocator;
    var vec2d = try Vec2D(i32).init(allocator, 1, .{ 2, 3 });
    defer vec2d.deinit(allocator);

    try expectEqualSlices(i32, &.{ 1, 1, 1 }, try vec2d.get(0));
    try expectEqualSlices(i32, &.{ 1, 1, 1 }, try vec2d.get(1));
}

test "init overflow" {
    const allocator = testing.allocator;
    try expectError(
        error.Overflow,
        Vec2D(i32).init(allocator, 1, .{ math.maxInt(usize), math.maxInt(usize) }),
    );
}

test "fill" {
    const allocator = testing.allocator;
    var vec2d = try Vec2D(i32).init(allocator, 0, .{ 2, 3 });
    defer vec2d.deinit(allocator);

    vec2d.fill(7);

    try expectEqualSlices(i32, &.{ 7, 7, 7 }, try vec2d.get(0));
    try expectEqualSlices(i32, &.{ 7, 7, 7 }, try vec2d.get(1));
}

test "get" {
    var data = [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const vec2d = Vec2D(i32){
        .data = &data,
        .cols = 2,
    };

    try expectEqualSlices(i32, &.{ 0, 1 }, try vec2d.get(0));
    try expectEqualSlices(i32, &.{ 2, 3 }, try vec2d.get(1));
    try expectEqualSlices(i32, &.{ 4, 5 }, try vec2d.get(2));
    try expectEqualSlices(i32, &.{ 6, 7 }, try vec2d.get(3));
}

test "getMut" {
    var data = [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var vec2d = Vec2D(i32){
        .data = &data,
        .cols = 2,
    };

    const row = try vec2d.getMut(1);
    row[1] = 9;

    try expectEqualSlices(i32, &.{ 0, 1 }, try vec2d.get(0));
    // (1, 1) should be 9.
    try expectEqualSlices(i32, &.{ 2, 9 }, try vec2d.get(1));
    try expectEqualSlices(i32, &.{ 4, 5 }, try vec2d.get(2));
    try expectEqualSlices(i32, &.{ 6, 7 }, try vec2d.get(3));
}

test "get multiplication overflow" {
    const allocator = testing.allocator;
    var matrix = try Vec2D(i32).init(allocator, 0, .{ 3, 4 });
    defer matrix.deinit(allocator);

    const row = (math.maxInt(usize) / 4) + 1;
    try expectError(error.Overflow, matrix.get(row));
    try expectError(error.Overflow, matrix.getMut(row));
}

test "get addition overflow" {
    const allocator = testing.allocator;
    var matrix = try Vec2D(i32).init(allocator, 0, .{ 3, 5 });
    defer matrix.deinit(allocator);

    const row = math.maxInt(usize) / 5;
    try expectError(error.Overflow, matrix.get(row));
    try expectError(error.Overflow, matrix.getMut(row));
}
const std = @import("../std.zig");
const Allocator = std.mem.Allocator;

pub const decode = @import("lzma2/decode.zig");

pub fn decompress(
    allocator: Allocator,
    reader: anytype,
    writer: anytype,
) !void {
    var decoder = try decode.Decoder.init(allocator);
    defer decoder.deinit(allocator);
    return decoder.decompress(allocator, reader, writer);
}

test {
    const expected = "Hello\nWorld!\n";
    const compressed = &[_]u8{ 0x01, 0x00, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x0A, 0x02, 0x00, 0x06, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0A, 0x00 };

    const allocator = std.testing.allocator;
    var decomp = std.ArrayList(u8).init(allocator);
    defer decomp.deinit();
    var stream = std.io.fixedBufferStream(compressed);
    try decompress(allocator, stream.reader(), decomp.writer());
    try std.testing.expectEqualSlices(u8, expected, decomp.items);
}
const std = @import("../../std.zig");
const Allocator = std.mem.Allocator;

const lzma = @import("../lzma.zig");
const DecoderState = lzma.decode.DecoderState;
const LzAccumBuffer = lzma.decode.lzbuffer.LzAccumBuffer;
const Properties = lzma.decode.Properties;
const RangeDecoder = lzma.decode.rangecoder.RangeDecoder;

pub const Decoder = struct {
    lzma_state: DecoderState,

    pub fn init(allocator: Allocator) !Decoder {
        return Decoder{
            .lzma_state = try DecoderState.init(
                allocator,
                Properties{
                    .lc = 0,
                    .lp = 0,
                    .pb = 0,
                },
                null,
            ),
        };
    }

    pub fn deinit(self: *Decoder, allocator: Allocator) void {
        self.lzma_state.deinit(allocator);
        self.* = undefined;
    }

    pub fn decompress(
        self: *Decoder,
        allocator: Allocator,
        reader: anytype,
        writer: anytype,
    ) !void {
        var accum = LzAccumBuffer.init(std.math.maxInt(usize));
        defer accum.deinit(allocator);

        while (true) {
            const status = try reader.readByte();

            switch (status) {
                0 => break,
                1 => try parseUncompressed(allocator, reader, writer, &accum, true),
                2 => try parseUncompressed(allocator, reader, writer, &accum, false),
                else => try self.parseLzma(allocator, reader, writer, &accum, status),
            }
        }

        try accum.finish(writer);
    }

    fn parseLzma(
        self: *Decoder,
        allocator: Allocator,
        reader: anytype,
        writer: anytype,
        accum: *LzAccumBuffer,
        status: u8,
    ) !void {
        if (status & 0x80 == 0) {
            return error.CorruptInput;
        }

        const Reset = struct {
            dict: bool,
            state: bool,
            props: bool,
        };

        const reset = switch ((status >> 5) & 0x3) {
            0 => Reset{
                .dict = false,
                .state = false,
                .props = false,
            },
            1 => Reset{
                .dict = false,
                .state = true,
                .props = false,
            },
            2 => Reset{
                .dict = false,
                .state = true,
                .props = true,
            },
            3 => Reset{
                .dict = true,
                .state = true,
                .props = true,
            },
            else => unreachable,
        };

        const unpacked_size = blk: {
            var tmp: u64 = status & 0x1F;
            tmp <<= 16;
            tmp |= try reader.readInt(u16, .big);
            break :blk tmp + 1;
        };

        const packed_size = blk: {
            const tmp: u17 = try reader.readInt(u16, .big);
            break :blk tmp + 1;
        };

        if (reset.dict) {
            try accum.reset(writer);
        }

        if (reset.state) {
            var new_props = self.lzma_state.lzma_props;

            if (reset.props) {
                var props = try reader.readByte();
                if (props >= 225) {
                    return error.CorruptInput;
                }

                const lc = @as(u4, @intCast(props % 9));
                props /= 9;
                const lp = @as(u3, @intCast(props % 5));
                props /= 5;
                const pb = @as(u3, @intCast(props));

                if (lc + lp > 4) {
                    return error.CorruptInput;
                }

                new_props = Properties{ .lc = lc, .lp = lp, .pb = pb };
            }

            try self.lzma_state.resetState(allocator, new_props);
        }

        self.lzma_state.unpacked_size = unpacked_size + accum.len;

        var counter = std.io.countingReader(reader);
        const counter_reader = counter.reader();

        var rangecoder = try RangeDecoder.init(counter_reader);
        while (try self.lzma_state.process(allocator, counter_reader, writer, accum, &rangecoder) == .continue_) {}

        if (counter.bytes_read != packed_size) {
            return error.CorruptInput;
        }
    }

    fn parseUncompressed(
        allocator: Allocator,
        reader: anytype,
        writer: anytype,
        accum: *LzAccumBuffer,
        reset_dict: bool,
    ) !void {
        const unpacked_size = @as(u17, try reader.readInt(u16, .big)) + 1;

        if (reset_dict) {
            try accum.reset(writer);
        }

        var i: @TypeOf(unpacked_size) = 0;
        while (i < unpacked_size) : (i += 1) {
            try accum.appendByte(allocator, try reader.readByte());
        }
    }
};
const std = @import("std");
const block = @import("xz/block.zig");
const Allocator = std.mem.Allocator;
const Crc32 = std.hash.Crc32;

pub const Check = enum(u4) {
    none = 0x00,
    crc32 = 0x01,
    crc64 = 0x04,
    sha256 = 0x0A,
    _,
};

fn readStreamFlags(reader: anytype, check: *Check) !void {
    var bit_reader = std.io.bitReader(.little, reader);

    const reserved1 = try bit_reader.readBitsNoEof(u8, 8);
    if (reserved1 != 0)
        return error.CorruptInput;

    check.* = @as(Check, @enumFromInt(try bit_reader.readBitsNoEof(u4, 4)));

    const reserved2 = try bit_reader.readBitsNoEof(u4, 4);
    if (reserved2 != 0)
        return error.CorruptInput;
}

pub fn decompress(allocator: Allocator, reader: anytype) !Decompress(@TypeOf(reader)) {
    return Decompress(@TypeOf(reader)).init(allocator, reader);
}

pub fn Decompress(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        pub const Error = ReaderType.Error || block.Decoder(ReaderType).Error;
        pub const Reader = std.io.Reader(*Self, Error, read);

        allocator: Allocator,
        block_decoder: block.Decoder(ReaderType),
        in_reader: ReaderType,

        fn init(allocator: Allocator, source: ReaderType) !Self {
            const magic = try source.readBytesNoEof(6);
            if (!std.mem.eql(u8, &magic, &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 }))
                return error.BadHeader;

            var check: Check = undefined;
            const hash_a = blk: {
                var hasher = std.compress.hashedReader(source, Crc32.init());
                try readStreamFlags(hasher.reader(), &check);
                break :blk hasher.hasher.final();
            };

            const hash_b = try source.readInt(u32, .little);
            if (hash_a != hash_b)
                return error.WrongChecksum;

            return Self{
                .allocator = allocator,
                .block_decoder = try block.decoder(allocator, source, check),
                .in_reader = source,
            };
        }

        pub fn deinit(self: *Self) void {
            self.block_decoder.deinit();
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn read(self: *Self, buffer: []u8) Error!usize {
            if (buffer.len == 0)
                return 0;

            const r = try self.block_decoder.read(buffer);
            if (r != 0)
                return r;

            const index_size = blk: {
                var hasher = std.compress.hashedReader(self.in_reader, Crc32.init());
                hasher.hasher.update(&[1]u8{0x00});

                var counter = std.io.countingReader(hasher.reader());
                counter.bytes_read += 1;

                const counting_reader = counter.reader();

                const record_count = try std.leb.readUleb128(u64, counting_reader);
                if (record_count != self.block_decoder.block_count)
                    return error.CorruptInput;

                var i: usize = 0;
                while (i < record_count) : (i += 1) {
                    // TODO: validate records
                    _ = try std.leb.readUleb128(u64, counting_reader);
                    _ = try std.leb.readUleb128(u64, counting_reader);
                }

                while (counter.bytes_read % 4 != 0) {
                    if (try counting_reader.readByte() != 0)
                        return error.CorruptInput;
                }

                const hash_a = hasher.hasher.final();
                const hash_b = try counting_reader.readInt(u32, .little);
                if (hash_a != hash_b)
                    return error.WrongChecksum;

                break :blk counter.bytes_read;
            };

            const hash_a = try self.in_reader.readInt(u32, .little);

            const hash_b = blk: {
                var hasher = std.compress.hashedReader(self.in_reader, Crc32.init());
                const hashed_reader = hasher.reader();

                const backward_size = (@as(u64, try hashed_reader.readInt(u32, .little)) + 1) * 4;
                if (backward_size != index_size)
                    return error.CorruptInput;

                var check: Check = undefined;
                try readStreamFlags(hashed_reader, &check);

                break :blk hasher.hasher.final();
            };

            if (hash_a != hash_b)
                return error.WrongChecksum;

            const magic = try self.in_reader.readBytesNoEof(2);
            if (!std.mem.eql(u8, &magic, &.{ 'Y', 'Z' }))
                return error.CorruptInput;

            return 0;
        }
    };
}

test {
    _ = @import("xz/test.zig");
}
const std = @import("../../std.zig");
const lzma2 = std.compress.lzma2;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Crc32 = std.hash.Crc32;
const Crc64 = std.hash.crc.Crc64Xz;
const Sha256 = std.crypto.hash.sha2.Sha256;
const xz = std.compress.xz;

const DecodeError = error{
    CorruptInput,
    EndOfStream,
    EndOfStreamWithNoError,
    WrongChecksum,
    Unsupported,
    Overflow,
};

pub fn decoder(allocator: Allocator, reader: anytype, check: xz.Check) !Decoder(@TypeOf(reader)) {
    return Decoder(@TypeOf(reader)).init(allocator, reader, check);
}

pub fn Decoder(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        pub const Error =
            ReaderType.Error ||
            DecodeError ||
            Allocator.Error;
        pub const Reader = std.io.Reader(*Self, Error, read);

        allocator: Allocator,
        inner_reader: ReaderType,
        check: xz.Check,
        err: ?Error,
        to_read: ArrayListUnmanaged(u8),
        read_pos: usize,
        block_count: usize,

        fn init(allocator: Allocator, in_reader: ReaderType, check: xz.Check) !Self {
            return Self{
                .allocator = allocator,
                .inner_reader = in_reader,
                .check = check,
                .err = null,
                .to_read = .{},
                .read_pos = 0,
                .block_count = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            self.to_read.deinit(self.allocator);
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn read(self: *Self, output: []u8) Error!usize {
            while (true) {
                const unread_len = self.to_read.items.len - self.read_pos;
                if (unread_len > 0) {
                    const n = @min(unread_len, output.len);
                    @memcpy(output[0..n], self.to_read.items[self.read_pos..][0..n]);
                    self.read_pos += n;
                    return n;
                }
                if (self.err) |e| {
                    if (e == DecodeError.EndOfStreamWithNoError) {
                        return 0;
                    }
                    return e;
                }
                if (self.read_pos > 0) {
                    self.to_read.shrinkRetainingCapacity(0);
                    self.read_pos = 0;
                }
                self.readBlock() catch |e| {
                    self.err = e;
                };
            }
        }

        fn readBlock(self: *Self) Error!void {
            var block_counter = std.io.countingReader(self.inner_reader);
            const block_reader = block_counter.reader();

            var packed_size: ?u64 = null;
            var unpacked_size: ?u64 = null;

            // Block Header
            {
                var header_hasher = std.compress.hashedReader(block_reader, Crc32.init());
                const header_reader = header_hasher.reader();

                const header_size = @as(u64, try header_reader.readByte()) * 4;
                if (header_size == 0)
                    return error.EndOfStreamWithNoError;

                const Flags = packed struct(u8) {
                    last_filter_index: u2,
                    reserved: u4,
                    has_packed_size: bool,
                    has_unpacked_size: bool,
                };

                const flags = @as(Flags, @bitCast(try header_reader.readByte()));
                const filter_count = @as(u3, flags.last_filter_index) + 1;
                if (filter_count > 1)
                    return error.Unsupported;

                if (flags.has_packed_size)
                    packed_size = try std.leb.readUleb128(u64, header_reader);

                if (flags.has_unpacked_size)
                    unpacked_size = try std.leb.readUleb128(u64, header_reader);

                const FilterId = enum(u64) {
                    lzma2 = 0x21,
                    _,
                };

                const filter_id = @as(
                    FilterId,
                    @enumFromInt(try std.leb.readUleb128(u64, header_reader)),
                );

                if (@intFromEnum(filter_id) >= 0x4000_0000_0000_0000)
                    return error.CorruptInput;

                if (filter_id != .lzma2)
                    return error.Unsupported;

                const properties_size = try std.leb.readUleb128(u64, header_reader);
                if (properties_size != 1)
                    return error.CorruptInput;

                // TODO: use filter properties
                _ = try header_reader.readByte();

                while (block_counter.bytes_read != header_size) {
                    if (try header_reader.readByte() != 0)
                        return error.CorruptInput;
                }

                const hash_a = header_hasher.hasher.final();
                const hash_b = try header_reader.readInt(u32, .little);
                if (hash_a != hash_b)
                    return error.WrongChecksum;
            }

            // Compressed Data
            var packed_counter = std.io.countingReader(block_reader);
            try lzma2.decompress(
                self.allocator,
                packed_counter.reader(),
                self.to_read.writer(self.allocator),
            );

            if (packed_size) |s| {
                if (s != packed_counter.bytes_read)
                    return error.CorruptInput;
            }

            const unpacked_bytes = self.to_read.items;
            if (unpacked_size) |s| {
                if (s != unpacked_bytes.len)
                    return error.CorruptInput;
            }

            // Block Padding
            while (block_counter.bytes_read % 4 != 0) {
                if (try block_reader.readByte() != 0)
                    return error.CorruptInput;
            }

            switch (self.check) {
                .none => {},
                .crc32 => {
                    const hash_a = Crc32.hash(unpacked_bytes);
                    const hash_b = try self.inner_reader.readInt(u32, .little);
                    if (hash_a != hash_b)
                        return error.WrongChecksum;
                },
                .crc64 => {
                    const hash_a = Crc64.hash(unpacked_bytes);
                    const hash_b = try self.inner_reader.readInt(u64, .little);
                    if (hash_a != hash_b)
                        return error.WrongChecksum;
                },
                .sha256 => {
                    var hash_a: [Sha256.digest_length]u8 = undefined;
                    Sha256.hash(unpacked_bytes, &hash_a, .{});

                    var hash_b: [Sha256.digest_length]u8 = undefined;
                    try self.inner_reader.readNoEof(&hash_b);

                    if (!std.mem.eql(u8, &hash_a, &hash_b))
                        return error.WrongChecksum;
                },
                else => return error.Unsupported,
            }

            self.block_count += 1;
        }
    };
}
const std = @import("../../std.zig");
const testing = std.testing;
const xz = std.compress.xz;

fn decompress(data: []const u8) ![]u8 {
    var in_stream = std.io.fixedBufferStream(data);

    var xz_stream = try xz.decompress(testing.allocator, in_stream.reader());
    defer xz_stream.deinit();

    return xz_stream.reader().readAllAlloc(testing.allocator, std.math.maxInt(usize));
}

fn testReader(data: []const u8, comptime expected: []const u8) !void {
    const buf = try decompress(data);
    defer testing.allocator.free(buf);

    try testing.expectEqualSlices(u8, expected, buf);
}

test "compressed data" {
    try testReader(@embedFile("testdata/good-0-empty.xz"), "");

    inline for ([_][]const u8{
        "good-1-check-none.xz",
        "good-1-check-crc32.xz",
        "good-1-check-crc64.xz",
        "good-1-check-sha256.xz",
        "good-2-lzma2.xz",
        "good-1-block_header-1.xz",
        "good-1-block_header-2.xz",
        "good-1-block_header-3.xz",
    }) |filename| {
        try testReader(@embedFile("testdata/" ++ filename),
            \\Hello
            \\World!
            \\
        );
    }

    inline for ([_][]const u8{
        "good-1-lzma2-1.xz",
        "good-1-lzma2-2.xz",
        "good-1-lzma2-3.xz",
        "good-1-lzma2-4.xz",
    }) |filename| {
        try testReader(@embedFile("testdata/" ++ filename),
            \\Lorem ipsum dolor sit amet, consectetur adipisicing 
            \\elit, sed do eiusmod tempor incididunt ut 
            \\labore et dolore magna aliqua. Ut enim 
            \\ad minim veniam, quis nostrud exercitation ullamco 
            \\laboris nisi ut aliquip ex ea commodo 
            \\consequat. Duis aute irure dolor in reprehenderit 
            \\in voluptate velit esse cillum dolore eu 
            \\fugiat nulla pariatur. Excepteur sint occaecat cupidatat 
            \\non proident, sunt in culpa qui officia 
            \\deserunt mollit anim id est laborum. 
            \\
        );
    }

    try testReader(@embedFile("testdata/good-1-lzma2-5.xz"), "");
}

test "unsupported" {
    inline for ([_][]const u8{
        "good-1-delta-lzma2.tiff.xz",
        "good-1-x86-lzma2.xz",
        "good-1-sparc-lzma2.xz",
        "good-1-arm64-lzma2-1.xz",
        "good-1-arm64-lzma2-2.xz",
        "good-1-3delta-lzma2.xz",
        "good-1-empty-bcj-lzma2.xz",
    }) |filename| {
        try testing.expectError(
            error.Unsupported,
            decompress(@embedFile("testdata/" ++ filename)),
        );
    }
}

fn testDontPanic(data: []const u8) !void {
    const buf = decompress(data) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        else => return,
    };
    defer testing.allocator.free(buf);
}

test "size fields: integer overflow avoidance" {
    // These cases were found via fuzz testing and each previously caused
    // an integer overflow when decoding. We just want to ensure they no longer
    // cause a panic
    const header_size_overflow = "\xfd7zXZ\x00\x00\x01i\"\xde6z";
    try testDontPanic(header_size_overflow);
    const lzma2_chunk_size_overflow = "\xfd7zXZ\x00\x00\x01i\"\xde6\x02\x00!\x01\x08\x00\x00\x00\xd8\x0f#\x13\x01\xff\xff";
    try testDontPanic(lzma2_chunk_size_overflow);
    const backward_size_overflow = "\xfd7zXZ\x00\x00\x01i\"\xde6\x00\x00\x00\x00\x1c\xdfD!\x90B\x99\r\x01\x00\x00\xff\xff\x10\x00\x00\x00\x01DD\xff\xff\xff\x01";
    try testDontPanic(backward_size_overflow);
}
const deflate = @import("flate/deflate.zig");
const inflate = @import("flate/inflate.zig");

/// Decompress compressed data from reader and write plain data to the writer.
pub fn decompress(reader: anytype, writer: anytype) !void {
    try inflate.decompress(.zlib, reader, writer);
}

/// Decompressor type
pub fn Decompressor(comptime ReaderType: type) type {
    return inflate.Decompressor(.zlib, ReaderType);
}

/// Create Decompressor which will read compressed data from reader.
pub fn decompressor(reader: anytype) Decompressor(@TypeOf(reader)) {
    return inflate.decompressor(.zlib, reader);
}

/// Compression level, trades between speed and compression size.
pub const Options = deflate.Options;

/// Compress plain data from reader and write compressed data to the writer.
pub fn compress(reader: anytype, writer: anytype, options: Options) !void {
    try deflate.compress(.zlib, reader, writer, options);
}

/// Compressor type
pub fn Compressor(comptime WriterType: type) type {
    return deflate.Compressor(.zlib, WriterType);
}

/// Create Compressor which outputs compressed data to the writer.
pub fn compressor(writer: anytype, options: Options) !Compressor(@TypeOf(writer)) {
    return try deflate.compressor(.zlib, writer, options);
}

/// Huffman only compression. Without Lempel-Ziv match searching. Faster
/// compression, less memory requirements but bigger compressed sizes.
pub const huffman = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.huffman.compress(.zlib, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.huffman.Compressor(.zlib, WriterType);
    }

    pub fn compressor(writer: anytype) !huffman.Compressor(@TypeOf(writer)) {
        return deflate.huffman.compressor(.zlib, writer);
    }
};

// No compression store only. Compressed size is slightly bigger than plain.
pub const store = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.store.compress(.zlib, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.store.Compressor(.zlib, WriterType);
    }

    pub fn compressor(writer: anytype) !store.Compressor(@TypeOf(writer)) {
        return deflate.store.compressor(.zlib, writer);
    }
};

test "should not overshoot" {
    const std = @import("std");

    // Compressed zlib data with extra 4 bytes at the end.
    const data = [_]u8{
        0x78, 0x9c, 0x73, 0xce, 0x2f, 0xa8, 0x2c, 0xca, 0x4c, 0xcf, 0x28, 0x51, 0x08, 0xcf, 0xcc, 0xc9,
        0x49, 0xcd, 0x55, 0x28, 0x4b, 0xcc, 0x53, 0x08, 0x4e, 0xce, 0x48, 0xcc, 0xcc, 0xd6, 0x51, 0x08,
        0xce, 0xcc, 0x4b, 0x4f, 0x2c, 0xc8, 0x2f, 0x4a, 0x55, 0x30, 0xb4, 0xb4, 0x34, 0xd5, 0xb5, 0x34,
        0x03, 0x00, 0x8b, 0x61, 0x0f, 0xa4, 0x52, 0x5a, 0x94, 0x12,
    };

    var stream = std.io.fixedBufferStream(data[0..]);
    const reader = stream.reader();

    var dcp = decompressor(reader);
    var out: [128]u8 = undefined;

    // Decompress
    var n = try dcp.reader().readAll(out[0..]);

    // Expected decompressed data
    try std.testing.expectEqual(46, n);
    try std.testing.expectEqualStrings("Copyright Willem van Schaik, Singapore 1995-96", out[0..n]);

    // Decompressor don't overshoot underlying reader.
    // It is leaving it at the end of compressed data chunk.
    try std.testing.expectEqual(data.len - 4, stream.getPos());
    try std.testing.expectEqual(0, dcp.unreadBytes());

    // 4 bytes after compressed chunk are available in reader.
    n = try reader.readAll(out[0..]);
    try std.testing.expectEqual(n, 4);
    try std.testing.expectEqualSlices(u8, data[data.len - 4 .. data.len], out[0..n]);
}
const std = @import("std");
const RingBuffer = std.RingBuffer;

const types = @import("zstandard/types.zig");
pub const frame = types.frame;
pub const compressed_block = types.compressed_block;

pub const decompress = @import("zstandard/decompress.zig");

pub const DecompressorOptions = struct {
    verify_checksum: bool = true,
    window_buffer: []u8,

    /// Recommended amount by the standard. Lower than this may result
    /// in inability to decompress common streams.
    pub const default_window_buffer_len = 8 * 1024 * 1024;
};

pub fn Decompressor(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        const table_size_max = types.compressed_block.table_size_max;

        source: std.io.CountingReader(ReaderType),
        state: enum { NewFrame, InFrame, LastBlock },
        decode_state: decompress.block.DecodeState,
        frame_context: decompress.FrameContext,
        buffer: WindowBuffer,
        literal_fse_buffer: [table_size_max.literal]types.compressed_block.Table.Fse,
        match_fse_buffer: [table_size_max.match]types.compressed_block.Table.Fse,
        offset_fse_buffer: [table_size_max.offset]types.compressed_block.Table.Fse,
        literals_buffer: [types.block_size_max]u8,
        sequence_buffer: [types.block_size_max]u8,
        verify_checksum: bool,
        checksum: ?u32,
        current_frame_decompressed_size: usize,

        const WindowBuffer = struct {
            data: []u8 = undefined,
            read_index: usize = 0,
            write_index: usize = 0,
        };

        pub const Error = ReaderType.Error || error{
            ChecksumFailure,
            DictionaryIdFlagUnsupported,
            MalformedBlock,
            MalformedFrame,
            OutOfMemory,
        };

        pub const Reader = std.io.Reader(*Self, Error, read);

        pub fn init(source: ReaderType, options: DecompressorOptions) Self {
            return .{
                .source = std.io.countingReader(source),
                .state = .NewFrame,
                .decode_state = undefined,
                .frame_context = undefined,
                .buffer = .{ .data = options.window_buffer },
                .literal_fse_buffer = undefined,
                .match_fse_buffer = undefined,
                .offset_fse_buffer = undefined,
                .literals_buffer = undefined,
                .sequence_buffer = undefined,
                .verify_checksum = options.verify_checksum,
                .checksum = undefined,
                .current_frame_decompressed_size = undefined,
            };
        }

        fn frameInit(self: *Self) !void {
            const source_reader = self.source.reader();
            switch (try decompress.decodeFrameHeader(source_reader)) {
                .skippable => |header| {
                    try source_reader.skipBytes(header.frame_size, .{});
                    self.state = .NewFrame;
                },
                .zstandard => |header| {
                    const frame_context = try decompress.FrameContext.init(
                        header,
                        self.buffer.data.len,
                        self.verify_checksum,
                    );

                    const decode_state = decompress.block.DecodeState.init(
                        &self.literal_fse_buffer,
                        &self.match_fse_buffer,
                        &self.offset_fse_buffer,
                    );

                    self.decode_state = decode_state;
                    self.frame_context = frame_context;

                    self.checksum = null;
                    self.current_frame_decompressed_size = 0;

                    self.state = .InFrame;
                },
            }
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn read(self: *Self, buffer: []u8) Error!usize {
            if (buffer.len == 0) return 0;

            var size: usize = 0;
            while (size == 0) {
                while (self.state == .NewFrame) {
                    const initial_count = self.source.bytes_read;
                    self.frameInit() catch |err| switch (err) {
                        error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
                        error.EndOfStream => return if (self.source.bytes_read == initial_count)
                            0
                        else
                            error.MalformedFrame,
                        else => return error.MalformedFrame,
                    };
                }
                size = try self.readInner(buffer);
            }
            return size;
        }

        fn readInner(self: *Self, buffer: []u8) Error!usize {
            std.debug.assert(self.state != .NewFrame);

            var ring_buffer = RingBuffer{
                .data = self.buffer.data,
                .read_index = self.buffer.read_index,
                .write_index = self.buffer.write_index,
            };
            defer {
                self.buffer.read_index = ring_buffer.read_index;
                self.buffer.write_index = ring_buffer.write_index;
            }

            const source_reader = self.source.reader();
            while (ring_buffer.isEmpty() and self.state != .LastBlock) {
                const header_bytes = source_reader.readBytesNoEof(3) catch
                    return error.MalformedFrame;
                const block_header = decompress.block.decodeBlockHeader(&header_bytes);

                decompress.block.decodeBlockReader(
                    &ring_buffer,
                    source_reader,
                    block_header,
                    &self.decode_state,
                    self.frame_context.block_size_max,
                    &self.literals_buffer,
                    &self.sequence_buffer,
                ) catch
                    return error.MalformedBlock;

                if (self.frame_context.content_size) |size| {
                    if (self.current_frame_decompressed_size > size) return error.MalformedFrame;
                }

                const size = ring_buffer.len();
                self.current_frame_decompressed_size += size;

                if (self.frame_context.hasher_opt) |*hasher| {
                    if (size > 0) {
                        const written_slice = ring_buffer.sliceLast(size);
                        hasher.update(written_slice.first);
                        hasher.update(written_slice.second);
                    }
                }
                if (block_header.last_block) {
                    self.state = .LastBlock;
                    if (self.frame_context.has_checksum) {
                        const checksum = source_reader.readInt(u32, .little) catch
                            return error.MalformedFrame;
                        if (self.verify_checksum) {
                            if (self.frame_context.hasher_opt) |*hasher| {
                                if (checksum != decompress.computeChecksum(hasher))
                                    return error.ChecksumFailure;
                            }
                        }
                    }
                    if (self.frame_context.content_size) |content_size| {
                        if (content_size != self.current_frame_decompressed_size) {
                            return error.MalformedFrame;
                        }
                    }
                }
            }

            const size = @min(ring_buffer.len(), buffer.len);
            if (size > 0) {
                ring_buffer.readFirstAssumeLength(buffer, size);
            }
            if (self.state == .LastBlock and ring_buffer.len() == 0) {
                self.state = .NewFrame;
            }
            return size;
        }
    };
}

pub fn decompressor(reader: anytype, options: DecompressorOptions) Decompressor(@TypeOf(reader)) {
    return Decompressor(@TypeOf(reader)).init(reader, options);
}

fn testDecompress(data: []const u8) ![]u8 {
    const window_buffer = try std.testing.allocator.alloc(u8, 1 << 23);
    defer std.testing.allocator.free(window_buffer);

    var in_stream = std.io.fixedBufferStream(data);
    var zstd_stream = decompressor(in_stream.reader(), .{ .window_buffer = window_buffer });
    const result = zstd_stream.reader().readAllAlloc(std.testing.allocator, std.math.maxInt(usize));
    return result;
}

fn testReader(data: []const u8, comptime expected: []const u8) !void {
    const buf = try testDecompress(data);
    defer std.testing.allocator.free(buf);
    try std.testing.expectEqualSlices(u8, expected, buf);
}

test "decompression" {
    const uncompressed = @embedFile("testdata/rfc8478.txt");
    const compressed3 = @embedFile("testdata/rfc8478.txt.zst.3");
    const compressed19 = @embedFile("testdata/rfc8478.txt.zst.19");

    const buffer = try std.testing.allocator.alloc(u8, uncompressed.len);
    defer std.testing.allocator.free(buffer);

    const res3 = try decompress.decode(buffer, compressed3, true);
    try std.testing.expectEqual(uncompressed.len, res3);
    try std.testing.expectEqualSlices(u8, uncompressed, buffer);

    @memset(buffer, undefined);
    const res19 = try decompress.decode(buffer, compressed19, true);
    try std.testing.expectEqual(uncompressed.len, res19);
    try std.testing.expectEqualSlices(u8, uncompressed, buffer);

    try testReader(compressed3, uncompressed);
    try testReader(compressed19, uncompressed);
}

fn expectEqualDecoded(expected: []const u8, input: []const u8) !void {
    {
        const result = try decompress.decodeAlloc(std.testing.allocator, input, false, 1 << 23);
        defer std.testing.allocator.free(result);
        try std.testing.expectEqualStrings(expected, result);
    }

    {
        var buffer = try std.testing.allocator.alloc(u8, 2 * expected.len);
        defer std.testing.allocator.free(buffer);

        const size = try decompress.decode(buffer, input, false);
        try std.testing.expectEqualStrings(expected, buffer[0..size]);
    }
}

fn expectEqualDecodedStreaming(expected: []const u8, input: []const u8) !void {
    const window_buffer = try std.testing.allocator.alloc(u8, 1 << 23);
    defer std.testing.allocator.free(window_buffer);

    var in_stream = std.io.fixedBufferStream(input);
    var stream = decompressor(in_stream.reader(), .{ .window_buffer = window_buffer });

    const result = try stream.reader().readAllAlloc(std.testing.allocator, std.math.maxInt(usize));
    defer std.testing.allocator.free(result);

    try std.testing.expectEqualStrings(expected, result);
}

test "zero sized block" {
    const input_raw =
        "\x28\xb5\x2f\xfd" ++ // zstandard frame magic number
        "\x20\x00" ++ // frame header: only single_segment_flag set, frame_content_size zero
        "\x01\x00\x00"; // block header with: last_block set, block_type raw, block_size zero

    const input_rle =
        "\x28\xb5\x2f\xfd" ++ // zstandard frame magic number
        "\x20\x00" ++ // frame header: only single_segment_flag set, frame_content_size zero
        "\x03\x00\x00" ++ // block header with: last_block set, block_type rle, block_size zero
        "\xaa"; // block_content

    try expectEqualDecoded("", input_raw);
    try expectEqualDecoded("", input_rle);
    try expectEqualDecodedStreaming("", input_raw);
    try expectEqualDecodedStreaming("", input_rle);
}

test "declared raw literals size too large" {
    const input_raw =
        "\x28\xb5\x2f\xfd" ++ // zstandard frame magic number
        "\x00\x00" ++ // frame header: everything unset, window descriptor zero
        "\x95\x00\x00" ++ // block header with: last_block set, block_type compressed, block_size 18
        "\xbc\xf3\xae" ++ // literals section header with: type raw, size_format 3, regenerated_size 716603
        "\xa5\x9f\xe3"; // some bytes of literal content - the content is shorter than regenerated_size

    // Note that the regenerated_size in the above input is larger than block maximum size, so the
    // block can't be valid as it is a raw literals block.

    var fbs = std.io.fixedBufferStream(input_raw);
    var window: [1024]u8 = undefined;
    var stream = decompressor(fbs.reader(), .{ .window_buffer = &window });

    var buf: [1024]u8 = undefined;
    try std.testing.expectError(error.MalformedBlock, stream.read(&buf));
}
const std = @import("std");
const assert = std.debug.assert;
const RingBuffer = std.RingBuffer;

const types = @import("../types.zig");
const frame = types.frame;
const Table = types.compressed_block.Table;
const LiteralsSection = types.compressed_block.LiteralsSection;
const SequencesSection = types.compressed_block.SequencesSection;

const huffman = @import("huffman.zig");
const readers = @import("../readers.zig");

const decodeFseTable = @import("fse.zig").decodeFseTable;

pub const Error = error{
    BlockSizeOverMaximum,
    MalformedBlockSize,
    ReservedBlock,
    MalformedRleBlock,
    MalformedCompressedBlock,
};

pub const DecodeState = struct {
    repeat_offsets: [3]u32,

    offset: StateData(8),
    match: StateData(9),
    literal: StateData(9),

    offset_fse_buffer: []Table.Fse,
    match_fse_buffer: []Table.Fse,
    literal_fse_buffer: []Table.Fse,

    fse_tables_undefined: bool,

    literal_stream_reader: readers.ReverseBitReader,
    literal_stream_index: usize,
    literal_streams: Litera```
