```
                  return .true;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_f => {
                    switch (try self.expectByte()) {
                        'a' => {
                            self.cursor += 1;
                            self.state = .literal_fa;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_fa => {
                    switch (try self.expectByte()) {
                        'l' => {
                            self.cursor += 1;
                            self.state = .literal_fal;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_fal => {
                    switch (try self.expectByte()) {
                        's' => {
                            self.cursor += 1;
                            self.state = .literal_fals;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_fals => {
                    switch (try self.expectByte()) {
                        'e' => {
                            self.cursor += 1;
                            self.state = .post_value;
                            return .false;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_n => {
                    switch (try self.expectByte()) {
                        'u' => {
                            self.cursor += 1;
                            self.state = .literal_nu;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_nu => {
                    switch (try self.expectByte()) {
                        'l' => {
                            self.cursor += 1;
                            self.state = .literal_nul;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },
                .literal_nul => {
                    switch (try self.expectByte()) {
                        'l' => {
                            self.cursor += 1;
                            self.state = .post_value;
                            return .null;
                        },
                        else => return error.SyntaxError,
                    }
                },
            }
            unreachable;
        }
    }

    /// Seeks ahead in the input until the first byte of the next token (or the end of the input)
    /// determines which type of token will be returned from the next `next*()` call.
    /// This function is idempotent, only advancing past commas, colons, and inter-token whitespace.
    pub fn peekNextTokenType(self: *@This()) PeekError!TokenType {
        state_loop: while (true) {
            switch (self.state) {
                .value => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        '{' => return .object_begin,
                        '[' => return .array_begin,
                        '"' => return .string,
                        '-', '0'...'9' => return .number,
                        't' => return .true,
                        'f' => return .false,
                        'n' => return .null,
                        else => return error.SyntaxError,
                    }
                },

                .post_value => {
                    if (try self.skipWhitespaceCheckEnd()) return .end_of_document;

                    const c = self.input[self.cursor];
                    if (self.string_is_object_key) {
                        self.string_is_object_key = false;
                        switch (c) {
                            ':' => {
                                self.cursor += 1;
                                self.state = .value;
                                continue :state_loop;
                            },
                            else => return error.SyntaxError,
                        }
                    }

                    switch (c) {
                        '}' => return .object_end,
                        ']' => return .array_end,
                        ',' => {
                            switch (self.stack.peek()) {
                                OBJECT_MODE => {
                                    self.state = .object_post_comma;
                                },
                                ARRAY_MODE => {
                                    self.state = .value;
                                },
                            }
                            self.cursor += 1;
                            continue :state_loop;
                        },
                        else => return error.SyntaxError,
                    }
                },

                .object_start => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        '"' => return .string,
                        '}' => return .object_end,
                        else => return error.SyntaxError,
                    }
                },
                .object_post_comma => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        '"' => return .string,
                        else => return error.SyntaxError,
                    }
                },

                .array_start => {
                    switch (try self.skipWhitespaceExpectByte()) {
                        ']' => return .array_end,
                        else => {
                            self.state = .value;
                            continue :state_loop;
                        },
                    }
                },

                .number_minus,
                .number_leading_zero,
                .number_int,
                .number_post_dot,
                .number_frac,
                .number_post_e,
                .number_post_e_sign,
                .number_exp,
                => return .number,

                .string,
                .string_backslash,
                .string_backslash_u,
                .string_backslash_u_1,
                .string_backslash_u_2,
                .string_backslash_u_3,
                .string_surrogate_half,
                .string_surrogate_half_backslash,
                .string_surrogate_half_backslash_u,
                .string_surrogate_half_backslash_u_1,
                .string_surrogate_half_backslash_u_2,
                .string_surrogate_half_backslash_u_3,
                => return .string,

                .string_utf8_last_byte,
                .string_utf8_second_to_last_byte,
                .string_utf8_second_to_last_byte_guard_against_overlong,
                .string_utf8_second_to_last_byte_guard_against_surrogate_half,
                .string_utf8_third_to_last_byte,
                .string_utf8_third_to_last_byte_guard_against_overlong,
                .string_utf8_third_to_last_byte_guard_against_too_large,
                => return .string,

                .literal_t,
                .literal_tr,
                .literal_tru,
                => return .true,
                .literal_f,
                .literal_fa,
                .literal_fal,
                .literal_fals,
                => return .false,
                .literal_n,
                .literal_nu,
                .literal_nul,
                => return .null,
            }
            unreachable;
        }
    }

    const State = enum {
        value,
        post_value,

        object_start,
        object_post_comma,

        array_start,

        number_minus,
        number_leading_zero,
        number_int,
        number_post_dot,
        number_frac,
        number_post_e,
        number_post_e_sign,
        number_exp,

        string,
        string_backslash,
        string_backslash_u,
        string_backslash_u_1,
        string_backslash_u_2,
        string_backslash_u_3,
        string_surrogate_half,
        string_surrogate_half_backslash,
        string_surrogate_half_backslash_u,
        string_surrogate_half_backslash_u_1,
        string_surrogate_half_backslash_u_2,
        string_surrogate_half_backslash_u_3,

        // From http://unicode.org/mail-arch/unicode-ml/y2003-m02/att-0467/01-The_Algorithm_to_Valide_an_UTF-8_String
        string_utf8_last_byte, // State A
        string_utf8_second_to_last_byte, // State B
        string_utf8_second_to_last_byte_guard_against_overlong, // State C
        string_utf8_second_to_last_byte_guard_against_surrogate_half, // State D
        string_utf8_third_to_last_byte, // State E
        string_utf8_third_to_last_byte_guard_against_overlong, // State F
        string_utf8_third_to_last_byte_guard_against_too_large, // State G

        literal_t,
        literal_tr,
        literal_tru,
        literal_f,
        literal_fa,
        literal_fal,
        literal_fals,
        literal_n,
        literal_nu,
        literal_nul,
    };

    fn expectByte(self: *const @This()) !u8 {
        if (self.cursor < self.input.len) {
            return self.input[self.cursor];
        }
        // No byte.
        if (self.is_end_of_input) return error.UnexpectedEndOfInput;
        return error.BufferUnderrun;
    }

    fn skipWhitespace(self: *@This()) void {
        while (self.cursor < self.input.len) : (self.cursor += 1) {
            switch (self.input[self.cursor]) {
                // Whitespace
                ' ', '\t', '\r' => continue,
                '\n' => {
                    if (self.diagnostics) |diag| {
                        diag.line_number += 1;
                        // This will count the newline itself,
                        // which means a straight-forward subtraction will give a 1-based column number.
                        diag.line_start_cursor = self.cursor;
                    }
                    continue;
                },
                else => return,
            }
        }
    }

    fn skipWhitespaceExpectByte(self: *@This()) !u8 {
        self.skipWhitespace();
        return self.expectByte();
    }

    fn skipWhitespaceCheckEnd(self: *@This()) !bool {
        self.skipWhitespace();
        if (self.cursor >= self.input.len) {
            // End of buffer.
            if (self.is_end_of_input) {
                // End of everything.
                if (self.stackHeight() == 0) {
                    // We did it!
                    return true;
                }
                return error.UnexpectedEndOfInput;
            }
            return error.BufferUnderrun;
        }
        if (self.stackHeight() == 0) return error.SyntaxError;
        return false;
    }

    fn takeValueSlice(self: *@This()) []const u8 {
        const slice = self.input[self.value_start..self.cursor];
        self.value_start = self.cursor;
        return slice;
    }
    fn takeValueSliceMinusTrailingOffset(self: *@This(), trailing_negative_offset: usize) []const u8 {
        // Check if the escape sequence started before the current input buffer.
        // (The algebra here is awkward to avoid unsigned underflow,
        //  but it's just making sure the slice on the next line isn't UB.)
        if (self.cursor <= self.value_start + trailing_negative_offset) return "";
        const slice = self.input[self.value_start .. self.cursor - trailing_negative_offset];
        // When trailing_negative_offset is non-zero, setting self.value_start doesn't matter,
        // because we always set it again while emitting the .partial_string_escaped_*.
        self.value_start = self.cursor;
        return slice;
    }

    fn endOfBufferInNumber(self: *@This(), allow_end: bool) !Token {
        const slice = self.takeValueSlice();
        if (self.is_end_of_input) {
            if (!allow_end) return error.UnexpectedEndOfInput;
            self.state = .post_value;
            return Token{ .number = slice };
        }
        if (slice.len == 0) return error.BufferUnderrun;
        return Token{ .partial_number = slice };
    }

    fn endOfBufferInString(self: *@This()) !Token {
        if (self.is_end_of_input) return error.UnexpectedEndOfInput;
        const slice = self.takeValueSliceMinusTrailingOffset(switch (self.state) {
            // Don't include the escape sequence in the partial string.
            .string_backslash => 1,
            .string_backslash_u => 2,
            .string_backslash_u_1 => 3,
            .string_backslash_u_2 => 4,
            .string_backslash_u_3 => 5,
            .string_surrogate_half => 6,
            .string_surrogate_half_backslash => 7,
            .string_surrogate_half_backslash_u => 8,
            .string_surrogate_half_backslash_u_1 => 9,
            .string_surrogate_half_backslash_u_2 => 10,
            .string_surrogate_half_backslash_u_3 => 11,

            // Include everything up to the cursor otherwise.
            .string,
            .string_utf8_last_byte,
            .string_utf8_second_to_last_byte,
            .string_utf8_second_to_last_byte_guard_against_overlong,
            .string_utf8_second_to_last_byte_guard_against_surrogate_half,
            .string_utf8_third_to_last_byte,
            .string_utf8_third_to_last_byte_guard_against_overlong,
            .string_utf8_third_to_last_byte_guard_against_too_large,
            => 0,

            else => unreachable,
        });
        if (slice.len == 0) return error.BufferUnderrun;
        return Token{ .partial_string = slice };
    }

    fn partialStringCodepoint(code_point: u21) Token {
        var buf: [4]u8 = undefined;
        switch (std.unicode.utf8Encode(code_point, &buf) catch unreachable) {
            1 => return Token{ .partial_string_escaped_1 = buf[0..1].* },
            2 => return Token{ .partial_string_escaped_2 = buf[0..2].* },
            3 => return Token{ .partial_string_escaped_3 = buf[0..3].* },
            4 => return Token{ .partial_string_escaped_4 = buf[0..4].* },
            else => unreachable,
        }
    }
};

const OBJECT_MODE = 0;
const ARRAY_MODE = 1;

fn appendSlice(list: *std.ArrayList(u8), buf: []const u8, max_value_len: usize) !void {
    const new_len = std.math.add(usize, list.items.len, buf.len) catch return error.ValueTooLong;
    if (new_len > max_value_len) return error.ValueTooLong;
    try list.appendSlice(buf);
}

/// For the slice you get from a `Token.number` or `Token.allocated_number`,
/// this function returns true if the number doesn't contain any fraction or exponent components, and is not `-0`.
/// Note, the numeric value encoded by the value may still be an integer, such as `1.0`.
/// This function is meant to give a hint about whether integer parsing or float parsing should be used on the value.
/// This function will not give meaningful results on non-numeric input.
pub fn isNumberFormattedLikeAnInteger(value: []const u8) bool {
    if (std.mem.eql(u8, value, "-0")) return false;
    return std.mem.indexOfAny(u8, value, ".eE") == null;
}

test {
    _ = @import("./scanner_test.zig");
}
const std = @import("std");
const testing = std.testing;
const ArenaAllocator = std.heap.ArenaAllocator;
const Allocator = std.mem.Allocator;

const parseFromSlice = @import("./static.zig").parseFromSlice;
const parseFromSliceLeaky = @import("./static.zig").parseFromSliceLeaky;
const parseFromTokenSource = @import("./static.zig").parseFromTokenSource;
const parseFromTokenSourceLeaky = @import("./static.zig").parseFromTokenSourceLeaky;
const innerParse = @import("./static.zig").innerParse;
const parseFromValue = @import("./static.zig").parseFromValue;
const parseFromValueLeaky = @import("./static.zig").parseFromValueLeaky;
const ParseOptions = @import("./static.zig").ParseOptions;

const JsonScanner = @import("./scanner.zig").Scanner;
const jsonReader = @import("./scanner.zig").reader;
const Diagnostics = @import("./scanner.zig").Diagnostics;

const Value = @import("./dynamic.zig").Value;

const Primitives = struct {
    bool: bool,
    // f16, f80, f128: don't work in std.fmt.parseFloat(T).
    f32: f32,
    f64: f64,
    u0: u0,
    i0: i0,
    u1: u1,
    i1: i1,
    u8: u8,
    i8: i8,
    i130: i130,
};

const primitives_0 = Primitives{
    .bool = false,
    .f32 = 0,
    .f64 = 0,
    .u0 = 0,
    .i0 = 0,
    .u1 = 0,
    .i1 = 0,
    .u8 = 0,
    .i8 = 0,
    .i130 = 0,
};
const primitives_0_doc_0 =
    \\{
    \\  "bool": false,
    \\  "f32": 0,
    \\  "f64": 0,
    \\  "u0": 0,
    \\  "i0": 0,
    \\  "u1": 0,
    \\  "i1": 0,
    \\  "u8": 0,
    \\  "i8": 0,
    \\  "i130": 0
    \\}
;
const primitives_0_doc_1 = // looks like a float.
    \\{
    \\  "bool": false,
    \\  "f32": 0.0,
    \\  "f64": 0.0,
    \\  "u0": 0.0,
    \\  "i0": 0.0,
    \\  "u1": 0.0,
    \\  "i1": 0.0,
    \\  "u8": 0.0,
    \\  "i8": 0.0,
    \\  "i130": 0.0
    \\}
;

const primitives_1 = Primitives{
    .bool = true,
    .f32 = 1073741824,
    .f64 = 1152921504606846976,
    .u0 = 0,
    .i0 = 0,
    .u1 = 1,
    .i1 = -1,
    .u8 = 255,
    .i8 = -128,
    .i130 = -680564733841876926926749214863536422911,
};
const primitives_1_doc_0 =
    \\{
    \\  "bool": true,
    \\  "f32": 1073741824,
    \\  "f64": 1152921504606846976,
    \\  "u0": 0,
    \\  "i0": 0,
    \\  "u1": 1,
    \\  "i1": -1,
    \\  "u8": 255,
    \\  "i8": -128,
    \\  "i130": -680564733841876926926749214863536422911
    \\}
;
const primitives_1_doc_1 = // float rounding.
    \\{
    \\  "bool": true,
    \\  "f32": 1073741825,
    \\  "f64": 1152921504606846977,
    \\  "u0": 0,
    \\  "i0": 0,
    \\  "u1": 1,
    \\  "i1": -1,
    \\  "u8": 255,
    \\  "i8": -128,
    \\  "i130": -680564733841876926926749214863536422911
    \\}
;

const Aggregates = struct {
    optional: ?i32,
    array: [4]i32,
    vector: @Vector(4, i32),
    pointer: *i32,
    pointer_const: *const i32,
    slice: []i32,
    slice_const: []const i32,
    slice_sentinel: [:0]i32,
    slice_sentinel_const: [:0]const i32,
};

var zero: i32 = 0;
const zero_const: i32 = 0;
var array_of_zeros: [4:0]i32 = [_:0]i32{ 0, 0, 0, 0 };
var one: i32 = 1;
const one_const: i32 = 1;
var array_countdown: [4:0]i32 = [_:0]i32{ 4, 3, 2, 1 };

const aggregates_0 = Aggregates{
    .optional = null,
    .array = [4]i32{ 0, 0, 0, 0 },
    .vector = @Vector(4, i32){ 0, 0, 0, 0 },
    .pointer = &zero,
    .pointer_const = &zero_const,
    .slice = array_of_zeros[0..0],
    .slice_const = &[_]i32{},
    .slice_sentinel = array_of_zeros[0..0 :0],
    .slice_sentinel_const = &[_:0]i32{},
};
const aggregates_0_doc =
    \\{
    \\  "optional": null,
    \\  "array": [0, 0, 0, 0],
    \\  "vector": [0, 0, 0, 0],
    \\  "pointer": 0,
    \\  "pointer_const": 0,
    \\  "slice": [],
    \\  "slice_const": [],
    \\  "slice_sentinel": [],
    \\  "slice_sentinel_const": []
    \\}
;

const aggregates_1 = Aggregates{
    .optional = 1,
    .array = [4]i32{ 1, 2, 3, 4 },
    .vector = @Vector(4, i32){ 1, 2, 3, 4 },
    .pointer = &one,
    .pointer_const = &one_const,
    .slice = array_countdown[0..],
    .slice_const = array_countdown[0..],
    .slice_sentinel = array_countdown[0.. :0],
    .slice_sentinel_const = array_countdown[0.. :0],
};
const aggregates_1_doc =
    \\{
    \\  "optional": 1,
    \\  "array": [1, 2, 3, 4],
    \\  "vector": [1, 2, 3, 4],
    \\  "pointer": 1,
    \\  "pointer_const": 1,
    \\  "slice": [4, 3, 2, 1],
    \\  "slice_const": [4, 3, 2, 1],
    \\  "slice_sentinel": [4, 3, 2, 1],
    \\  "slice_sentinel_const": [4, 3, 2, 1]
    \\}
;

const Strings = struct {
    slice_u8: []u8,
    slice_const_u8: []const u8,
    array_u8: [4]u8,
    slice_sentinel_u8: [:0]u8,
    slice_const_sentinel_u8: [:0]const u8,
    array_sentinel_u8: [4:0]u8,
};

var abcd = [4:0]u8{ 'a', 'b', 'c', 'd' };
const strings_0 = Strings{
    .slice_u8 = abcd[0..],
    .slice_const_u8 = "abcd",
    .array_u8 = [4]u8{ 'a', 'b', 'c', 'd' },
    .slice_sentinel_u8 = abcd[0..],
    .slice_const_sentinel_u8 = "abcd",
    .array_sentinel_u8 = [4:0]u8{ 'a', 'b', 'c', 'd' },
};
const strings_0_doc_0 =
    \\{
    \\  "slice_u8": "abcd",
    \\  "slice_const_u8": "abcd",
    \\  "array_u8": "abcd",
    \\  "slice_sentinel_u8": "abcd",
    \\  "slice_const_sentinel_u8": "abcd",
    \\  "array_sentinel_u8": "abcd"
    \\}
;
const strings_0_doc_1 =
    \\{
    \\  "slice_u8": [97, 98, 99, 100],
    \\  "slice_const_u8": [97, 98, 99, 100],
    \\  "array_u8": [97, 98, 99, 100],
    \\  "slice_sentinel_u8": [97, 98, 99, 100],
    \\  "slice_const_sentinel_u8": [97, 98, 99, 100],
    \\  "array_sentinel_u8": [97, 98, 99, 100]
    \\}
;

const Subnamespaces = struct {
    packed_struct: packed struct { a: u32, b: u32 },
    union_enum: union(enum) { i: i32, s: []const u8, v },
    inferred_enum: enum { a, b },
    explicit_enum: enum(u8) { a = 0, b = 1 },

    custom_struct: struct {
        pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) !@This() {
            _ = allocator;
            _ = options;
            try source.skipValue();
            return @This(){};
        }
        pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !@This() {
            _ = allocator;
            _ = source;
            _ = options;
            return @This(){};
        }
    },
    custom_union: union(enum) {
        i: i32,
        s: []const u8,
        pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) !@This() {
            _ = allocator;
            _ = options;
            try source.skipValue();
            return @This(){ .i = 0 };
        }
        pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !@This() {
            _ = allocator;
            _ = source;
            _ = options;
            return @This(){ .i = 0 };
        }
    },
    custom_enum: enum {
        a,
        b,
        pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) !@This() {
            _ = allocator;
            _ = options;
            try source.skipValue();
            return .a;
        }
        pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !@This() {
            _ = allocator;
            _ = source;
            _ = options;
            return .a;
        }
    },
};

const subnamespaces_0 = Subnamespaces{
    .packed_struct = .{ .a = 0, .b = 0 },
    .union_enum = .{ .i = 0 },
    .inferred_enum = .a,
    .explicit_enum = .a,
    .custom_struct = .{},
    .custom_union = .{ .i = 0 },
    .custom_enum = .a,
};
const subnamespaces_0_doc =
    \\{
    \\  "packed_struct": {"a": 0, "b": 0},
    \\  "union_enum": {"i": 0},
    \\  "inferred_enum": "a",
    \\  "explicit_enum": "a",
    \\  "custom_struct": null,
    \\  "custom_union": null,
    \\  "custom_enum": null
    \\}
;

fn testAllParseFunctions(comptime T: type, expected: T, doc: []const u8) !void {
    // First do the one with the debug info in case we get a SyntaxError or something.
    {
        var scanner = JsonScanner.initCompleteInput(testing.allocator, doc);
        defer scanner.deinit();
        var diagnostics = Diagnostics{};
        scanner.enableDiagnostics(&diagnostics);
        var parsed = parseFromTokenSource(T, testing.allocator, &scanner, .{}) catch |e| {
            std.debug.print("at line,col: {}:{}\n", .{ diagnostics.getLine(), diagnostics.getColumn() });
            return e;
        };
        defer parsed.deinit();
        try testing.expectEqualDeep(expected, parsed.value);
    }
    {
        const parsed = try parseFromSlice(T, testing.allocator, doc, .{});
        defer parsed.deinit();
        try testing.expectEqualDeep(expected, parsed.value);
    }
    {
        var stream = std.io.fixedBufferStream(doc);
        var json_reader = jsonReader(std.testing.allocator, stream.reader());
        defer json_reader.deinit();
        var parsed = try parseFromTokenSource(T, testing.allocator, &json_reader, .{});
        defer parsed.deinit();
        try testing.expectEqualDeep(expected, parsed.value);
    }

    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    {
        try testing.expectEqualDeep(expected, try parseFromSliceLeaky(T, arena.allocator(), doc, .{}));
    }
    {
        var scanner = JsonScanner.initCompleteInput(testing.allocator, doc);
        defer scanner.deinit();
        try testing.expectEqualDeep(expected, try parseFromTokenSourceLeaky(T, arena.allocator(), &scanner, .{}));
    }
    {
        var stream = std.io.fixedBufferStream(doc);
        var json_reader = jsonReader(std.testing.allocator, stream.reader());
        defer json_reader.deinit();
        try testing.expectEqualDeep(expected, try parseFromTokenSourceLeaky(T, arena.allocator(), &json_reader, .{}));
    }

    const parsed_dynamic = try parseFromSlice(Value, testing.allocator, doc, .{});
    defer parsed_dynamic.deinit();
    {
        const parsed = try parseFromValue(T, testing.allocator, parsed_dynamic.value, .{});
        defer parsed.deinit();
        try testing.expectEqualDeep(expected, parsed.value);
    }
    {
        try testing.expectEqualDeep(expected, try parseFromValueLeaky(T, arena.allocator(), parsed_dynamic.value, .{}));
    }
}

test "test all types" {
    if (true) return error.SkipZigTest; // See https://github.com/ziglang/zig/issues/16108
    try testAllParseFunctions(Primitives, primitives_0, primitives_0_doc_0);
    try testAllParseFunctions(Primitives, primitives_0, primitives_0_doc_1);
    try testAllParseFunctions(Primitives, primitives_1, primitives_1_doc_0);
    try testAllParseFunctions(Primitives, primitives_1, primitives_1_doc_1);

    try testAllParseFunctions(Aggregates, aggregates_0, aggregates_0_doc);
    try testAllParseFunctions(Aggregates, aggregates_1, aggregates_1_doc);

    try testAllParseFunctions(Strings, strings_0, strings_0_doc_0);
    try testAllParseFunctions(Strings, strings_0, strings_0_doc_1);

    try testAllParseFunctions(Subnamespaces, subnamespaces_0, subnamespaces_0_doc);
}

test "parse" {
    try testing.expectEqual(false, try parseFromSliceLeaky(bool, testing.allocator, "false", .{}));
    try testing.expectEqual(true, try parseFromSliceLeaky(bool, testing.allocator, "true", .{}));
    try testing.expectEqual(1, try parseFromSliceLeaky(u1, testing.allocator, "1", .{}));
    try testing.expectError(error.Overflow, parseFromSliceLeaky(u1, testing.allocator, "50", .{}));
    try testing.expectEqual(42, try parseFromSliceLeaky(u64, testing.allocator, "42", .{}));
    try testing.expectEqual(42, try parseFromSliceLeaky(f64, testing.allocator, "42.0", .{}));
    try testing.expectEqual(null, try parseFromSliceLeaky(?bool, testing.allocator, "null", .{}));
    try testing.expectEqual(true, try parseFromSliceLeaky(?bool, testing.allocator, "true", .{}));

    try testing.expectEqual("foo".*, try parseFromSliceLeaky([3]u8, testing.allocator, "\"foo\"", .{}));
    try testing.expectEqual("foo".*, try parseFromSliceLeaky([3]u8, testing.allocator, "[102, 111, 111]", .{}));
    try testing.expectEqual(undefined, try parseFromSliceLeaky([0]u8, testing.allocator, "[]", .{}));

    try testing.expectEqual(12345678901234567890, try parseFromSliceLeaky(u64, testing.allocator, "\"12345678901234567890\"", .{}));
    try testing.expectEqual(123.456, try parseFromSliceLeaky(f64, testing.allocator, "\"123.456\"", .{}));
}

test "parse into enum" {
    const T = enum(u32) {
        Foo = 42,
        Bar,
        @"with\\escape",
    };
    try testing.expectEqual(.Foo, try parseFromSliceLeaky(T, testing.allocator, "\"Foo\"", .{}));
    try testing.expectEqual(.Foo, try parseFromSliceLeaky(T, testing.allocator, "42", .{}));
    try testing.expectEqual(.@"with\\escape", try parseFromSliceLeaky(T, testing.allocator, "\"with\\\\escape\"", .{}));
    try testing.expectError(error.InvalidEnumTag, parseFromSliceLeaky(T, testing.allocator, "5", .{}));
    try testing.expectError(error.InvalidEnumTag, parseFromSliceLeaky(T, testing.allocator, "\"Qux\"", .{}));
}

test "parse into that allocates a slice" {
    {
        // string as string
        const parsed = try parseFromSlice([]u8, testing.allocator, "\"foo\"", .{});
        defer parsed.deinit();
        try testing.expectEqualSlices(u8, "foo", parsed.value);
    }
    {
        // string as array of u8 integers
        const parsed = try parseFromSlice([]u8, testing.allocator, "[102, 111, 111]", .{});
        defer parsed.deinit();
        try testing.expectEqualSlices(u8, "foo", parsed.value);
    }
    {
        const parsed = try parseFromSlice([]u8, testing.allocator, "\"with\\\\escape\"", .{});
        defer parsed.deinit();
        try testing.expectEqualSlices(u8, "with\\escape", parsed.value);
    }
}

test "parse into sentinel slice" {
    const parsed = try parseFromSlice([:0]const u8, testing.allocator, "\"\\n\"", .{});
    defer parsed.deinit();
    try testing.expect(std.mem.eql(u8, parsed.value, "\n"));
}

test "parse into tagged union" {
    const T = union(enum) {
        nothing,
        int: i32,
        float: f64,
        string: []const u8,
    };
    try testing.expectEqual(T{ .float = 1.5 }, try parseFromSliceLeaky(T, testing.allocator, "{\"float\":1.5}", .{}));
    try testing.expectEqual(T{ .int = 1 }, try parseFromSliceLeaky(T, testing.allocator, "{\"int\":1}", .{}));
    try testing.expectEqual(T{ .nothing = {} }, try parseFromSliceLeaky(T, testing.allocator, "{\"nothing\":{}}", .{}));
    const parsed = try parseFromSlice(T, testing.allocator, "{\"string\":\"foo\"}", .{});
    defer parsed.deinit();
    try testing.expectEqualSlices(u8, "foo", parsed.value.string);
}

test "parse into tagged union errors" {
    const T = union(enum) {
        nothing,
        int: i32,
        float: f64,
        string: []const u8,
    };
    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.UnexpectedToken, parseFromSliceLeaky(T, arena.allocator(), "42", .{}));
    try testing.expectError(error.SyntaxError, parseFromSliceLeaky(T, arena.allocator(), "{\"int\":1} 42", .{}));
    try testing.expectError(error.UnexpectedToken, parseFromSliceLeaky(T, arena.allocator(), "{}", .{}));
    try testing.expectError(error.UnknownField, parseFromSliceLeaky(T, arena.allocator(), "{\"bogus\":1}", .{}));
    try testing.expectError(error.UnexpectedToken, parseFromSliceLeaky(T, arena.allocator(), "{\"int\":1, \"int\":1", .{}));
    try testing.expectError(error.UnexpectedToken, parseFromSliceLeaky(T, arena.allocator(), "{\"int\":1, \"float\":1.0}", .{}));
    try testing.expectError(error.UnexpectedToken, parseFromSliceLeaky(T, arena.allocator(), "{\"nothing\":null}", .{}));
    try testing.expectError(error.UnexpectedToken, parseFromSliceLeaky(T, arena.allocator(), "{\"nothing\":{\"no\":0}}", .{}));

    // Allocator failure
    try testing.expectError(error.OutOfMemory, parseFromSlice(T, testing.failing_allocator, "{\"string\"\"foo\"}", .{}));
}

test "parse into struct with no fields" {
    const T = struct {};
    const parsed = try parseFromSlice(T, testing.allocator, "{}", .{});
    defer parsed.deinit();
    try testing.expectEqual(T{}, parsed.value);
}

const test_const_value: usize = 123;

test "parse into struct with default const pointer field" {
    const T = struct { a: *const usize = &test_const_value };
    const parsed = try parseFromSlice(T, testing.allocator, "{}", .{});
    defer parsed.deinit();
    try testing.expectEqual(T{}, parsed.value);
}

const test_default_usize: usize = 123;
const test_default_usize_ptr: *align(1) const usize = &test_default_usize;
const test_default_str: []const u8 = "test str";
const test_default_str_slice: [2][]const u8 = [_][]const u8{
    "test1",
    "test2",
};

test "freeing parsed structs with pointers to default values" {
    const T = struct {
        int: *const usize = &test_default_usize,
        int_ptr: *allowzero align(1) const usize = test_default_usize_ptr,
        str: []const u8 = test_default_str,
        str_slice: []const []const u8 = &test_default_str_slice,
    };

    var parsed = try parseFromSlice(T, testing.allocator, "{}", .{});
    try testing.expectEqual(T{}, parsed.value);
    defer parsed.deinit();
}

test "parse into struct where destination and source lengths mismatch" {
    const T = struct { a: [2]u8 };
    try testing.expectError(error.LengthMismatch, parseFromSlice(T, testing.allocator, "{\"a\": \"bbb\"}", .{}));
}

test "parse into struct with misc fields" {
    const T = struct {
        int: i64,
        float: f64,
        @"with\\escape": bool,
        @"withąunicode😂": bool,
        language: []const u8,
        optional: ?bool,
        default_field: i32 = 42,
        static_array: [3]f64,
        dynamic_array: []f64,

        complex: struct {
            nested: []const u8,
        },

        veryComplex: []struct {
            foo: []const u8,
        },

        a_union: Union,
        const Union = union(enum) {
            x: u8,
            float: f64,
            string: []const u8,
        };
    };
    const document_str =
        \\{
        \\  "int": 420,
        \\  "float": 3.14,
        \\  "with\\escape": true,
        \\  "with\u0105unicode\ud83d\ude02": false,
        \\  "language": "zig",
        \\  "optional": null,
        \\  "static_array": [66.6, 420.420, 69.69],
        \\  "dynamic_array": [66.6, 420.420, 69.69],
        \\  "complex": {
        \\    "nested": "zig"
        \\  },
        \\  "veryComplex": [
        \\    {
        \\      "foo": "zig"
        \\    }, {
        \\      "foo": "rocks"
        \\    }
        \\  ],
        \\  "a_union": {
        \\    "float": 100000
        \\  }
        \\}
    ;
    const parsed = try parseFromSlice(T, testing.allocator, document_str, .{});
    defer parsed.deinit();
    const r = &parsed.value;
    try testing.expectEqual(@as(i64, 420), r.int);
    try testing.expectEqual(@as(f64, 3.14), r.float);
    try testing.expectEqual(true, r.@"with\\escape");
    try testing.expectEqual(false, r.@"withąunicode😂");
    try testing.expectEqualSlices(u8, "zig", r.language);
    try testing.expectEqual(@as(?bool, null), r.optional);
    try testing.expectEqual(@as(i32, 42), r.default_field);
    try testing.expectEqual(@as(f64, 66.6), r.static_array[0]);
    try testing.expectEqual(@as(f64, 420.420), r.static_array[1]);
    try testing.expectEqual(@as(f64, 69.69), r.static_array[2]);
    try testing.expectEqual(@as(usize, 3), r.dynamic_array.len);
    try testing.expectEqual(@as(f64, 66.6), r.dynamic_array[0]);
    try testing.expectEqual(@as(f64, 420.420), r.dynamic_array[1]);
    try testing.expectEqual(@as(f64, 69.69), r.dynamic_array[2]);
    try testing.expectEqualSlices(u8, r.complex.nested, "zig");
    try testing.expectEqualSlices(u8, "zig", r.veryComplex[0].foo);
    try testing.expectEqualSlices(u8, "rocks", r.veryComplex[1].foo);
    try testing.expectEqual(T.Union{ .float = 100000 }, r.a_union);
}

test "parse into struct with strings and arrays with sentinels" {
    const T = struct {
        language: [:0]const u8,
        language_without_sentinel: []const u8,
        data: [:99]const i32,
        simple_data: []const i32,
    };
    const document_str =
        \\{
        \\  "language": "zig",
        \\  "language_without_sentinel": "zig again!",
        \\  "data": [1, 2, 3],
        \\  "simple_data": [4, 5, 6]
        \\}
    ;
    const parsed = try parseFromSlice(T, testing.allocator, document_str, .{});
    defer parsed.deinit();

    try testing.expectEqualSentinel(u8, 0, "zig", parsed.value.language);

    const data = [_:99]i32{ 1, 2, 3 };
    try testing.expectEqualSentinel(i32, 99, data[0..data.len], parsed.value.data);

    // Make sure that arrays who aren't supposed to have a sentinel still parse without one.
    try testing.expectEqual(@as(?i32, null), std.meta.sentinel(@TypeOf(parsed.value.simple_data)));
    try testing.expectEqual(@as(?u8, null), std.meta.sentinel(@TypeOf(parsed.value.language_without_sentinel)));
}

test "parse into struct with duplicate field" {
    const options_first = ParseOptions{ .duplicate_field_behavior = .use_first };
    const options_last = ParseOptions{ .duplicate_field_behavior = .use_last };

    const str = "{ \"a\": 1, \"a\": 0.25 }";

    const T1 = struct { a: *u64 };
    // both .use_first and .use_last should fail because second "a" value isn't a u64
    try testing.expectError(error.InvalidNumber, parseFromSlice(T1, testing.allocator, str, options_first));
    try testing.expectError(error.InvalidNumber, parseFromSlice(T1, testing.allocator, str, options_last));

    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const T2 = struct { a: f64 };
    try testing.expectEqual(T2{ .a = 1.0 }, try parseFromSliceLeaky(T2, arena.allocator(), str, options_first));
    try testing.expectEqual(T2{ .a = 0.25 }, try parseFromSliceLeaky(T2, arena.allocator(), str, options_last));
}

test "parse into struct ignoring unknown fields" {
    const T = struct {
        int: i64,
        language: []const u8,
    };

    const str =
        \\{
        \\  "int": 420,
        \\  "float": 3.14,
        \\  "with\\escape": true,
        \\  "with\u0105unicode\ud83d\ude02": false,
        \\  "optional": null,
        \\  "static_array": [66.6, 420.420, 69.69],
        \\  "dynamic_array": [66.6, 420.420, 69.69],
        \\  "complex": {
        \\    "nested": "zig"
        \\  },
        \\  "veryComplex": [
        \\    {
        \\      "foo": "zig"
        \\    }, {
        \\      "foo": "rocks"
        \\    }
        \\  ],
        \\  "a_union": {
        \\    "float": 100000
        \\  },
        \\  "language": "zig"
        \\}
    ;
    const parsed = try parseFromSlice(T, testing.allocator, str, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try testing.expectEqual(@as(i64, 420), parsed.value.int);
    try testing.expectEqualSlices(u8, "zig", parsed.value.language);
}

test "parse into tuple" {
    const Union = union(enum) {
        char: u8,
        float: f64,
        string: []const u8,
    };
    const T = std.meta.Tuple(&.{
        i64,
        f64,
        bool,
        []const u8,
        ?bool,
        struct {
            foo: i32,
            bar: []const u8,
        },
        std.meta.Tuple(&.{ u8, []const u8, u8 }),
        Union,
    });
    const str =
        \\[
        \\  420,
        \\  3.14,
        \\  true,
        \\  "zig",
        \\  null,
        \\  {
        \\    "foo": 1,
        \\    "bar": "zero"
        \\  },
        \\  [4, "två", 42],
        \\  {"float": 12.34}
        \\]
    ;
    const parsed = try parseFromSlice(T, testing.allocator, str, .{});
    defer parsed.deinit();
    const r = parsed.value;
    try testing.expectEqual(@as(i64, 420), r[0]);
    try testing.expectEqual(@as(f64, 3.14), r[1]);
    try testing.expectEqual(true, r[2]);
    try testing.expectEqualSlices(u8, "zig", r[3]);
    try testing.expectEqual(@as(?bool, null), r[4]);
    try testing.expectEqual(@as(i32, 1), r[5].foo);
    try testing.expectEqualSlices(u8, "zero", r[5].bar);
    try testing.expectEqual(@as(u8, 4), r[6][0]);
    try testing.expectEqualSlices(u8, "två", r[6][1]);
    try testing.expectEqual(@as(u8, 42), r[6][2]);
    try testing.expectEqual(Union{ .float = 12.34 }, r[7]);
}

const ParseIntoRecursiveUnionDefinitionValue = union(enum) {
    integer: i64,
    array: []const ParseIntoRecursiveUnionDefinitionValue,
};

test "parse into recursive union definition" {
    const T = struct {
        values: ParseIntoRecursiveUnionDefinitionValue,
    };

    const parsed = try parseFromSlice(T, testing.allocator, "{\"values\":{\"array\":[{\"integer\":58}]}}", .{});
    defer parsed.deinit();

    try testing.expectEqual(@as(i64, 58), parsed.value.values.array[0].integer);
}

const ParseIntoDoubleRecursiveUnionValueFirst = union(enum) {
    integer: i64,
    array: []const ParseIntoDoubleRecursiveUnionValueSecond,
};

const ParseIntoDoubleRecursiveUnionValueSecond = union(enum) {
    boolean: bool,
    array: []const ParseIntoDoubleRecursiveUnionValueFirst,
};

test "parse into double recursive union definition" {
    const T = struct {
        values: ParseIntoDoubleRecursiveUnionValueFirst,
    };

    const parsed = try parseFromSlice(T, testing.allocator, "{\"values\":{\"array\":[{\"array\":[{\"integer\":58}]}]}}", .{});
    defer parsed.deinit();

    try testing.expectEqual(@as(i64, 58), parsed.value.values.array[0].array[0].integer);
}

test "parse exponential into int" {
    const T = struct { int: i64 };
    const r = try parseFromSliceLeaky(T, testing.allocator, "{ \"int\": 4.2e2 }", .{});
    try testing.expectEqual(@as(i64, 420), r.int);
    try testing.expectError(error.InvalidNumber, parseFromSliceLeaky(T, testing.allocator, "{ \"int\": 0.042e2 }", .{}));
    try testing.expectError(error.Overflow, parseFromSliceLeaky(T, testing.allocator, "{ \"int\": 18446744073709551616.0 }", .{}));
}

test "parseFromTokenSource" {
    {
        var scanner = JsonScanner.initCompleteInput(testing.allocator, "123");
        defer scanner.deinit();
        var parsed = try parseFromTokenSource(u32, testing.allocator, &scanner, .{});
        defer parsed.deinit();
        try testing.expectEqual(@as(u32, 123), parsed.value);
    }

    {
        var stream = std.io.fixedBufferStream("123");
        var json_reader = jsonReader(std.testing.allocator, stream.reader());
        defer json_reader.deinit();
        var parsed = try parseFromTokenSource(u32, testing.allocator, &json_reader, .{});
        defer parsed.deinit();
        try testing.expectEqual(@as(u32, 123), parsed.value);
    }
}

test "max_value_len" {
    try testing.expectError(error.ValueTooLong, parseFromSlice([]u8, testing.allocator, "\"0123456789\"", .{ .max_value_len = 5 }));
}

test "parse into vector" {
    const T = struct {
        vec_i32: @Vector(4, i32),
        vec_f32: @Vector(2, f32),
    };
    const s =
        \\{
        \\  "vec_f32": [1.5, 2.5],
        \\  "vec_i32": [4, 5, 6, 7]
        \\}
    ;
    const parsed = try parseFromSlice(T, testing.allocator, s, .{});
    defer parsed.deinit();
    try testing.expectApproxEqAbs(@as(f32, 1.5), parsed.value.vec_f32[0], 0.0000001);
    try testing.expectApproxEqAbs(@as(f32, 2.5), parsed.value.vec_f32[1], 0.0000001);
    try testing.expectEqual(@Vector(4, i32){ 4, 5, 6, 7 }, parsed.value.vec_i32);
}

fn assertKey(
    allocator: Allocator,
    test_string: []const u8,
    scanner: anytype,
) !void {
    const token_outer = try scanner.nextAlloc(allocator, .alloc_always);
    switch (token_outer) {
        .allocated_string => |string| {
            try testing.expectEqualSlices(u8, string, test_string);
            allocator.free(string);
        },
        else => return error.UnexpectedToken,
    }
}
test "json parse partial" {
    const Inner = struct {
        num: u32,
        yes: bool,
    };
    const str =
        \\{
        \\  "outer": {
        \\    "key1": {
        \\      "num": 75,
        \\      "yes": true
        \\    },
        \\    "key2": {
        \\      "num": 95,
        \\      "yes": false
        \\    }
        \\  }
        \\}
    ;
    const allocator = testing.allocator;
    var scanner = JsonScanner.initCompleteInput(allocator, str);
    defer scanner.deinit();

    var arena = ArenaAllocator.init(allocator);
    defer arena.deinit();

    // Peel off the outer object
    try testing.expectEqual(try scanner.next(), .object_begin);
    try assertKey(allocator, "outer", &scanner);
    try testing.expectEqual(try scanner.next(), .object_begin);
    try assertKey(allocator, "key1", &scanner);

    // Parse the inner object to an Inner struct
    const inner_token = try innerParse(
        Inner,
        arena.allocator(),
        &scanner,
        .{ .max_value_len = scanner.input.len },
    );
    try testing.expectEqual(inner_token.num, 75);
    try testing.expectEqual(inner_token.yes, true);

    // Get they next key
    try assertKey(allocator, "key2", &scanner);
    const inner_token_2 = try innerParse(
        Inner,
        arena.allocator(),
        &scanner,
        .{ .max_value_len = scanner.input.len },
    );
    try testing.expectEqual(inner_token_2.num, 95);
    try testing.expectEqual(inner_token_2.yes, false);
    try testing.expectEqual(try scanner.next(), .object_end);
}

test "json parse allocate when streaming" {
    const T = struct {
        not_const: []u8,
        is_const: []const u8,
    };
    const str =
        \\{
        \\  "not_const": "non const string",
        \\  "is_const": "const string"
        \\}
    ;
    const allocator = testing.allocator;
    var arena = ArenaAllocator.init(allocator);
    defer arena.deinit();

    var stream = std.io.fixedBufferStream(str);
    var json_reader = jsonReader(std.testing.allocator, stream.reader());

    const parsed = parseFromTokenSourceLeaky(T, arena.allocator(), &json_reader, .{}) catch |err| {
        json_reader.deinit();
        return err;
    };
    // Deinit our reader to invalidate its buffer
    json_reader.deinit();

    // If either of these was invalidated, it would be full of '0xAA'
    try testing.expectEqualSlices(u8, parsed.not_const, "non const string");
    try testing.expectEqualSlices(u8, parsed.is_const, "const string");
}

test "parse at comptime" {
    const doc =
        \\{
        \\    "vals": {
        \\        "testing": 1,
        \\        "production": 42
        \\    },
        \\    "uptime": 9999
        \\}
    ;
    const Config = struct {
        vals: struct { testing: u8, production: u8 },
        uptime: u64,
    };
    const config = comptime x: {
        var buf: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        const res = parseFromSliceLeaky(Config, fba.allocator(), doc, .{});
        // Assert no error can occur since we are
        // parsing this JSON at comptime!
        break :x res catch unreachable;
    };
    comptime testing.expectEqual(@as(u64, 9999), config.uptime) catch unreachable;
}

test "parse with zero-bit field" {
    const str =
        \\{
        \\    "a": ["a", "a"],
        \\    "b": "a"
        \\}
    ;
    const ZeroSizedEnum = enum { a };
    try testing.expectEqual(0, @sizeOf(ZeroSizedEnum));

    const Inner = struct { a: []const ZeroSizedEnum, b: ZeroSizedEnum };
    const expected: Inner = .{ .a = &.{ .a, .a }, .b = .a };

    try testAllParseFunctions(Inner, expected, str);
}
const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const Scanner = @import("./scanner.zig").Scanner;
const Token = @import("./scanner.zig").Token;
const AllocWhen = @import("./scanner.zig").AllocWhen;
const default_max_value_len = @import("./scanner.zig").default_max_value_len;
const isNumberFormattedLikeAnInteger = @import("./scanner.zig").isNumberFormattedLikeAnInteger;

const Value = @import("./dynamic.zig").Value;
const Array = @import("./dynamic.zig").Array;

/// Controls how to deal with various inconsistencies between the JSON document and the Zig struct type passed in.
/// For duplicate fields or unknown fields, set options in this struct.
/// For missing fields, give the Zig struct fields default values.
pub const ParseOptions = struct {
    /// Behaviour when a duplicate field is encountered.
    /// The default is to return `error.DuplicateField`.
    duplicate_field_behavior: enum {
        use_first,
        @"error",
        use_last,
    } = .@"error",

    /// If false, finding an unknown field returns `error.UnknownField`.
    ignore_unknown_fields: bool = false,

    /// Passed to `std.json.Scanner.nextAllocMax` or `std.json.Reader.nextAllocMax`.
    /// The default for `parseFromSlice` or `parseFromTokenSource` with a `*std.json.Scanner` input
    /// is the length of the input slice, which means `error.ValueTooLong` will never be returned.
    /// The default for `parseFromTokenSource` with a `*std.json.Reader` is `std.json.default_max_value_len`.
    /// Ignored for `parseFromValue` and `parseFromValueLeaky`.
    max_value_len: ?usize = null,

    /// This determines whether strings should always be copied,
    /// or if a reference to the given buffer should be preferred if possible.
    /// The default for `parseFromSlice` or `parseFromTokenSource` with a `*std.json.Scanner` input
    /// is `.alloc_if_needed`.
    /// The default with a `*std.json.Reader` input is `.alloc_always`.
    /// Ignored for `parseFromValue` and `parseFromValueLeaky`.
    allocate: ?AllocWhen = null,

    /// When parsing to a `std.json.Value`, set this option to false to always emit
    /// JSON numbers as unparsed `std.json.Value.number_string`.
    /// Otherwise, JSON numbers are parsed as either `std.json.Value.integer`,
    /// `std.json.Value.float` or left as unparsed `std.json.Value.number_string`
    /// depending on the format and value of the JSON number.
    /// When this option is true, JSON numbers encoded as floats (see `std.json.isNumberFormattedLikeAnInteger`)
    /// may lose precision when being parsed into `std.json.Value.float`.
    parse_numbers: bool = true,
};

pub fn Parsed(comptime T: type) type {
    return struct {
        arena: *ArenaAllocator,
        value: T,

        pub fn deinit(self: @This()) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }
    };
}

/// Parses the json document from `s` and returns the result packaged in a `std.json.Parsed`.
/// You must call `deinit()` of the returned object to clean up allocated resources.
/// If you are using a `std.heap.ArenaAllocator` or similar, consider calling `parseFromSliceLeaky` instead.
/// Note that `error.BufferUnderrun` is not actually possible to return from this function.
pub fn parseFromSlice(
    comptime T: type,
    allocator: Allocator,
    s: []const u8,
    options: ParseOptions,
) ParseError(Scanner)!Parsed(T) {
    var scanner = Scanner.initCompleteInput(allocator, s);
    defer scanner.deinit();

    return parseFromTokenSource(T, allocator, &scanner, options);
}

/// Parses the json document from `s` and returns the result.
/// Allocations made during this operation are not carefully tracked and may not be possible to individually clean up.
/// It is recommended to use a `std.heap.ArenaAllocator` or similar.
pub fn parseFromSliceLeaky(
    comptime T: type,
    allocator: Allocator,
    s: []const u8,
    options: ParseOptions,
) ParseError(Scanner)!T {
    var scanner = Scanner.initCompleteInput(allocator, s);
    defer scanner.deinit();

    return parseFromTokenSourceLeaky(T, allocator, &scanner, options);
}

/// `scanner_or_reader` must be either a `*std.json.Scanner` with complete input or a `*std.json.Reader`.
/// Note that `error.BufferUnderrun` is not actually possible to return from this function.
pub fn parseFromTokenSource(
    comptime T: type,
    allocator: Allocator,
    scanner_or_reader: anytype,
    options: ParseOptions,
) ParseError(@TypeOf(scanner_or_reader.*))!Parsed(T) {
    var parsed = Parsed(T){
        .arena = try allocator.create(ArenaAllocator),
        .value = undefined,
    };
    errdefer allocator.destroy(parsed.arena);
    parsed.arena.* = ArenaAllocator.init(allocator);
    errdefer parsed.arena.deinit();

    parsed.value = try parseFromTokenSourceLeaky(T, parsed.arena.allocator(), scanner_or_reader, options);

    return parsed;
}

/// `scanner_or_reader` must be either a `*std.json.Scanner` with complete input or a `*std.json.Reader`.
/// Allocations made during this operation are not carefully tracked and may not be possible to individually clean up.
/// It is recommended to use a `std.heap.ArenaAllocator` or similar.
pub fn parseFromTokenSourceLeaky(
    comptime T: type,
    allocator: Allocator,
    scanner_or_reader: anytype,
    options: ParseOptions,
) ParseError(@TypeOf(scanner_or_reader.*))!T {
    if (@TypeOf(scanner_or_reader.*) == Scanner) {
        assert(scanner_or_reader.is_end_of_input);
    }
    var resolved_options = options;
    if (resolved_options.max_value_len == null) {
        if (@TypeOf(scanner_or_reader.*) == Scanner) {
            resolved_options.max_value_len = scanner_or_reader.input.len;
        } else {
            resolved_options.max_value_len = default_max_value_len;
        }
    }
    if (resolved_options.allocate == null) {
        if (@TypeOf(scanner_or_reader.*) == Scanner) {
            resolved_options.allocate = .alloc_if_needed;
        } else {
            resolved_options.allocate = .alloc_always;
        }
    }

    const value = try innerParse(T, allocator, scanner_or_reader, resolved_options);

    assert(.end_of_document == try scanner_or_reader.next());

    return value;
}

/// Like `parseFromSlice`, but the input is an already-parsed `std.json.Value` object.
/// Only `options.ignore_unknown_fields` is used from `options`.
pub fn parseFromValue(
    comptime T: type,
    allocator: Allocator,
    source: Value,
    options: ParseOptions,
) ParseFromValueError!Parsed(T) {
    var parsed = Parsed(T){
        .arena = try allocator.create(ArenaAllocator),
        .value = undefined,
    };
    errdefer allocator.destroy(parsed.arena);
    parsed.arena.* = ArenaAllocator.init(allocator);
    errdefer parsed.arena.deinit();

    parsed.value = try parseFromValueLeaky(T, parsed.arena.allocator(), source, options);

    return parsed;
}

pub fn parseFromValueLeaky(
    comptime T: type,
    allocator: Allocator,
    source: Value,
    options: ParseOptions,
) ParseFromValueError!T {
    // I guess this function doesn't need to exist,
    // but the flow of the sourcecode is easy to follow and grouped nicely with
    // this pub redirect function near the top and the implementation near the bottom.
    return innerParseFromValue(T, allocator, source, options);
}

/// The error set that will be returned when parsing from `*Source`.
/// Note that this may contain `error.BufferUnderrun`, but that error will never actually be returned.
pub fn ParseError(comptime Source: type) type {
    // A few of these will either always be present or present enough of the time that
    // omitting them is more confusing than always including them.
    return ParseFromValueError || Source.NextError || Source.PeekError || Source.AllocError;
}

pub const ParseFromValueError = std.fmt.ParseIntError || std.fmt.ParseFloatError || Allocator.Error || error{
    UnexpectedToken,
    InvalidNumber,
    Overflow,
    InvalidEnumTag,
    DuplicateField,
    UnknownField,
    MissingField,
    LengthMismatch,
};

/// This is an internal function called recursively
/// during the implementation of `parseFromTokenSourceLeaky` and similar.
/// It is exposed primarily to enable custom `jsonParse()` methods to call back into the `parseFrom*` system,
/// such as if you're implementing a custom container of type `T`;
/// you can call `innerParse(T, ...)` for each of the container's items.
/// Note that `null` fields are not allowed on the `options` when calling this function.
/// (The `options` you get in your `jsonParse` method has no `null` fields.)
pub fn innerParse(
    comptime T: type,
    allocator: Allocator,
    source: anytype,
    options: ParseOptions,
) ParseError(@TypeOf(source.*))!T {
    switch (@typeInfo(T)) {
        .bool => {
            return switch (try source.next()) {
                .true => true,
                .false => false,
                else => error.UnexpectedToken,
            };
        },
        .float, .comptime_float => {
            const token = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
            defer freeAllocated(allocator, token);
            const slice = switch (token) {
                inline .number, .allocated_number, .string, .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            return try std.fmt.parseFloat(T, slice);
        },
        .int, .comptime_int => {
            const token = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
            defer freeAllocated(allocator, token);
            const slice = switch (token) {
                inline .number, .allocated_number, .string, .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            return sliceToInt(T, slice);
        },
        .optional => |optionalInfo| {
            switch (try source.peekNextTokenType()) {
                .null => {
                    _ = try source.next();
                    return null;
                },
                else => {
                    return try innerParse(optionalInfo.child, allocator, source, options);
                },
            }
        },
        .@"enum" => {
            if (std.meta.hasFn(T, "jsonParse")) {
                return T.jsonParse(allocator, source, options);
            }

            const token = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
            defer freeAllocated(allocator, token);
            const slice = switch (token) {
                inline .number, .allocated_number, .string, .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            return sliceToEnum(T, slice);
        },
        .@"union" => |unionInfo| {
            if (std.meta.hasFn(T, "jsonParse")) {
                return T.jsonParse(allocator, source, options);
            }

            if (unionInfo.tag_type == null) @compileError("Unable to parse into untagged union '" ++ @typeName(T) ++ "'");

            if (.object_begin != try source.next()) return error.UnexpectedToken;

            var result: ?T = null;
            var name_token: ?Token = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
            const field_name = switch (name_token.?) {
                inline .string, .allocated_string => |slice| slice,
                else => {
                    return error.UnexpectedToken;
                },
            };

            inline for (unionInfo.fields) |u_field| {
                if (std.mem.eql(u8, u_field.name, field_name)) {
                    // Free the name token now in case we're using an allocator that optimizes freeing the last allocated object.
                    // (Recursing into innerParse() might trigger more allocations.)
                    freeAllocated(allocator, name_token.?);
                    name_token = null;
                    if (u_field.type == void) {
                        // void isn't really a json type, but we can support void payload union tags with {} as a value.
                        if (.object_begin != try source.next()) return error.UnexpectedToken;
                        if (.object_end != try source.next()) return error.UnexpectedToken;
                        result = @unionInit(T, u_field.name, {});
                    } else {
                        // Recurse.
                        result = @unionInit(T, u_field.name, try innerParse(u_field.type, allocator, source, options));
                    }
                    break;
                }
            } else {
                // Didn't match anything.
                return error.UnknownField;
            }

            if (.object_end != try source.next()) return error.UnexpectedToken;

            return result.?;
        },

        .@"struct" => |structInfo| {
            if (structInfo.is_tuple) {
                if (.array_begin != try source.next()) return error.UnexpectedToken;

                var r: T = undefined;
                inline for (0..structInfo.fields.len) |i| {
                    r[i] = try innerParse(structInfo.fields[i].type, allocator, source, options);
                }

                if (.array_end != try source.next()) return error.UnexpectedToken;

                return r;
            }

            if (std.meta.hasFn(T, "jsonParse")) {
                return T.jsonParse(allocator, source, options);
            }

            if (.object_begin != try source.next()) return error.UnexpectedToken;

            var r: T = undefined;
            var fields_seen = [_]bool{false} ** structInfo.fields.len;

            while (true) {
                var name_token: ?Token = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
                const field_name = switch (name_token.?) {
                    inline .string, .allocated_string => |slice| slice,
                    .object_end => { // No more fields.
                        break;
                    },
                    else => {
                        return error.UnexpectedToken;
                    },
                };

                inline for (structInfo.fields, 0..) |field, i| {
                    if (field.is_comptime) @compileError("comptime fields are not supported: " ++ @typeName(T) ++ "." ++ field.name);
                    if (std.mem.eql(u8, field.name, field_name)) {
                        // Free the name token now in case we're using an allocator that optimizes freeing the last allocated object.
                        // (Recursing into innerParse() might trigger more allocations.)
                        freeAllocated(allocator, name_token.?);
                        name_token = null;
                        if (fields_seen[i]) {
                            switch (options.duplicate_field_behavior) {
                                .use_first => {
                                    // Parse and ignore the redundant value.
                                    // We don't want to skip the value, because we want type checking.
                                    _ = try innerParse(field.type, allocator, source, options);
                                    break;
                                },
                                .@"error" => return error.DuplicateField,
                                .use_last => {},
                            }
                        }
                        @field(r, field.name) = try innerParse(field.type, allocator, source, options);
                        fields_seen[i] = true;
                        break;
                    }
                } else {
                    // Didn't match anything.
                    freeAllocated(allocator, name_token.?);
                    if (options.ignore_unknown_fields) {
                        try source.skipValue();
                    } else {
                        return error.UnknownField;
                    }
                }
            }
            try fillDefaultStructValues(T, &r, &fields_seen);
            return r;
        },

        .array => |arrayInfo| {
            switch (try source.peekNextTokenType()) {
                .array_begin => {
                    // Typical array.
                    return internalParseArray(T, arrayInfo.child, arrayInfo.len, allocator, source, options);
                },
                .string => {
                    if (arrayInfo.child != u8) return error.UnexpectedToken;
                    // Fixed-length string.

                    var r: T = undefined;
                    var i: usize = 0;
                    while (true) {
                        switch (try source.next()) {
                            .string => |slice| {
                                if (i + slice.len != r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..slice.len], slice);
                                break;
                            },
                            .partial_string => |slice| {
                                if (i + slice.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..slice.len], slice);
                                i += slice.len;
                            },
                            .partial_string_escaped_1 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            .partial_string_escaped_2 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            .partial_string_escaped_3 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            .partial_string_escaped_4 => |arr| {
                                if (i + arr.len > r.len) return error.LengthMismatch;
                                @memcpy(r[i..][0..arr.len], arr[0..]);
                                i += arr.len;
                            },
                            else => unreachable,
                        }
                    }

                    return r;
                },

                else => return error.UnexpectedToken,
            }
        },

        .vector => |vecInfo| {
            switch (try source.peekNextTokenType()) {
                .array_begin => {
                    return internalParseArray(T, vecInfo.child, vecInfo.len, allocator, source, options);
                },
                else => return error.UnexpectedToken,
            }
        },

        .pointer => |ptrInfo| {
            switch (ptrInfo.size) {
                .one => {
                    const r: *ptrInfo.child = try allocator.create(ptrInfo.child);
                    r.* = try innerParse(ptrInfo.child, allocator, source, options);
                    return r;
                },
                .slice => {
                    switch (try source.peekNextTokenType()) {
                        .array_begin => {
                            _ = try source.next();

                            // Typical array.
                            var arraylist = ArrayList(ptrInfo.child).init(allocator);
                            while (true) {
                                switch (try source.peekNextTokenType()) {
                                    .array_end => {
                                        _ = try source.next();
                                        break;
                                    },
                                    else => {},
                                }

                                try arraylist.ensureUnusedCapacity(1);
                                arraylist.appendAssumeCapacity(try innerParse(ptrInfo.child, allocator, source, options));
                            }

                            if (ptrInfo.sentinel()) |s| {
                                return try arraylist.toOwnedSliceSentinel(s);
                            }

                            return try arraylist.toOwnedSlice();
                        },
                        .string => {
                            if (ptrInfo.child != u8) return error.UnexpectedToken;

                            // Dynamic length string.
                            if (ptrInfo.sentinel()) |s| {
                                // Use our own array list so we can append the sentinel.
                                var value_list = ArrayList(u8).init(allocator);
                                _ = try source.allocNextIntoArrayList(&value_list, .alloc_always);
                                return try value_list.toOwnedSliceSentinel(s);
                            }
                            if (ptrInfo.is_const) {
                                switch (try source.nextAllocMax(allocator, options.allocate.?, options.max_value_len.?)) {
                                    inline .string, .allocated_string => |slice| return slice,
                                    else => unreachable,
                                }
                            } else {
                                // Have to allocate to get a mutable copy.
                                switch (try source.nextAllocMax(allocator, .alloc_always, options.max_value_len.?)) {
                                    .allocated_string => |slice| return slice,
                                    else => unreachable,
                                }
                            }
                        },
                        else => return error.UnexpectedToken,
                    }
                },
                else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
            }
        },
        else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
    }
    unreachable;
}

fn internalParseArray(
    comptime T: type,
    comptime Child: type,
    comptime len: comptime_int,
    allocator: Allocator,
    source: anytype,
    options: ParseOptions,
) !T {
    assert(.array_begin == try source.next());

    var r: T = undefined;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        r[i] = try innerParse(Child, allocator, source, options);
    }

    if (.array_end != try source.next()) return error.UnexpectedToken;

    return r;
}

/// This is an internal function called recursively
/// during the implementation of `parseFromValueLeaky`.
/// It is exposed primarily to enable custom `jsonParseFromValue()` methods to call back into the `parseFromValue*` system,
/// such as if you're implementing a custom container of type `T`;
/// you can call `innerParseFromValue(T, ...)` for each of the container's items.
pub fn innerParseFromValue(
    comptime T: type,
    allocator: Allocator,
    source: Value,
    options: ParseOptions,
) ParseFromValueError!T {
    switch (@typeInfo(T)) {
        .bool => {
            switch (source) {
                .bool => |b| return b,
                else => return error.UnexpectedToken,
            }
        },
        .float, .comptime_float => {
            switch (source) {
                .float => |f| return @as(T, @floatCast(f)),
                .integer => |i| return @as(T, @floatFromInt(i)),
                .number_string, .string => |s| return std.fmt.parseFloat(T, s),
                else => return error.UnexpectedToken,
            }
        },
        .int, .comptime_int => {
            switch (source) {
                .float => |f| {
                    if (@round(f) != f) return error.InvalidNumber;
                    if (f > std.math.maxInt(T)) return error.Overflow;
                    if (f < std.math.minInt(T)) return error.Overflow;
                    return @as(T, @intFromFloat(f));
                },
                .integer => |i| {
                    if (i > std.math.maxInt(T)) return error.Overflow;
                    if (i < std.math.minInt(T)) return error.Overflow;
                    return @as(T, @intCast(i));
                },
                .number_string, .string => |s| {
                    return sliceToInt(T, s);
                },
                else => return error.UnexpectedToken,
            }
        },
        .optional => |optionalInfo| {
            switch (source) {
                .null => return null,
                else => return try innerParseFromValue(optionalInfo.child, allocator, source, options),
            }
        },
        .@"enum" => {
            if (std.meta.hasFn(T, "jsonParseFromValue")) {
                return T.jsonParseFromValue(allocator, source, options);
            }

            switch (source) {
                .float => return error.InvalidEnumTag,
                .integer => |i| return std.meta.intToEnum(T, i),
                .number_string, .string => |s| return sliceToEnum(T, s),
                else => return error.UnexpectedToken,
            }
        },
        .@"union" => |unionInfo| {
            if (std.meta.hasFn(T, "jsonParseFromValue")) {
                return T.jsonParseFromValue(allocator, source, options);
            }

            if (unionInfo.tag_type == null) @compileError("Unable to parse into untagged union '" ++ @typeName(T) ++ "'");

            if (source != .object) return error.UnexpectedToken;
            if (source.object.count() != 1) return error.UnexpectedToken;

            var it = source.object.iterator();
            const kv = it.next().?;
            const field_name = kv.key_ptr.*;

            inline for (unionInfo.fields) |u_field| {
                if (std.mem.eql(u8, u_field.name, field_name)) {
                    if (u_field.type == void) {
                        // void isn't really a json type, but we can support void payload union tags with {} as a value.
                        if (kv.value_ptr.* != .object) return error.UnexpectedToken;
                        if (kv.value_ptr.*.object.count() != 0) return error.UnexpectedToken;
                        return @unionInit(T, u_field.name, {});
                    }
                    // Recurse.
                    return @unionInit(T, u_field.name, try innerParseFromValue(u_field.type, allocator, kv.value_ptr.*, options));
                }
            }
            // Didn't match anything.
            return error.UnknownField;
        },

        .@"struct" => |structInfo| {
            if (structInfo.is_tuple) {
                if (source != .array) return error.UnexpectedToken;
                if (source.array.items.len != structInfo.fields.len) return error.UnexpectedToken;

                var r: T = undefined;
                inline for (0..structInfo.fields.len, source.array.items) |i, item| {
                    r[i] = try innerParseFromValue(structInfo.fields[i].type, allocator, item, options);
                }

                return r;
            }

            if (std.meta.hasFn(T, "jsonParseFromValue")) {
                return T.jsonParseFromValue(allocator, source, options);
            }

            if (source != .object) return error.UnexpectedToken;

            var r: T = undefined;
            var fields_seen = [_]bool{false} ** structInfo.fields.len;

            var it = source.object.iterator();
            while (it.next()) |kv| {
                const field_name = kv.key_ptr.*;

                inline for (structInfo.fields, 0..) |field, i| {
                    if (field.is_comptime) @compileError("comptime fields are not supported: " ++ @typeName(T) ++ "." ++ field.name);
                    if (std.mem.eql(u8, field.name, field_name)) {
                        assert(!fields_seen[i]); // Can't have duplicate keys in a Value.object.
                        @field(r, field.name) = try innerParseFromValue(field.type, allocator, kv.value_ptr.*, options);
                        fields_seen[i] = true;
                        break;
                    }
                } else {
                    // Didn't match anything.
                    if (!options.ignore_unknown_fields) return error.UnknownField;
                }
            }
            try fillDefaultStructValues(T, &r, &fields_seen);
            return r;
        },

        .array => |arrayInfo| {
            switch (source) {
                .array => |array| {
                    // Typical array.
                    return innerParseArrayFromArrayValue(T, arrayInfo.child, arrayInfo.len, allocator, array, options);
                },
                .string => |s| {
                    if (arrayInfo.child != u8) return error.UnexpectedToken;
                    // Fixed-length string.

                    if (s.len != arrayInfo.len) return error.LengthMismatch;

                    var r: T = undefined;
                    @memcpy(r[0..], s);
                    return r;
                },

                else => return error.UnexpectedToken,
            }
        },

        .vector => |vecInfo| {
            switch (source) {
                .array => |array| {
                    return innerParseArrayFromArrayValue(T, vecInfo.child, vecInfo.len, allocator, array, options);
                },
                else => return error.UnexpectedToken,
            }
        },

        .pointer => |ptrInfo| {
            switch (ptrInfo.size) {
                .one => {
                    const r: *ptrInfo.child = try allocator.create(ptrInfo.child);
                    r.* = try innerParseFromValue(ptrInfo.child, allocator, source, options);
                    return r;
                },
                .slice => {
                    switch (source) {
                        .array => |array| {
                            const r = if (ptrInfo.sentinel()) |sentinel|
                                try allocator.allocSentinel(ptrInfo.child, array.items.len, sentinel)
                            else
                                try allocator.alloc(ptrInfo.child, array.items.len);

                            for (array.items, r) |item, *dest| {
                                dest.* = try innerParseFromValue(ptrInfo.child, allocator, item, options);
                            }

                            return r;
                        },
                        .string => |s| {
                            if (ptrInfo.child != u8) return error.UnexpectedToken;
                            // Dynamic length string.

                            const r = if (ptrInfo.sentinel()) |sentinel|
                                try allocator.allocSentinel(ptrInfo.child, s.len, sentinel)
                            else
                                try allocator.alloc(ptrInfo.child, s.len);
                            @memcpy(r[0..], s);

                            return r;
                        },
                        else => return error.UnexpectedToken,
                    }
                },
                else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
            }
        },
        else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
    }
}

fn innerParseArrayFromArrayValue(
    comptime T: type,
    comptime Child: type,
    comptime len: comptime_int,
    allocator: Allocator,
    array: Array,
    options: ParseOptions,
) !T {
    if (array.items.len != len) return error.LengthMismatch;

    var r: T = undefined;
    for (array.items, 0..) |item, i| {
        r[i] = try innerParseFromValue(Child, allocator, item, options);
    }

    return r;
}

fn sliceToInt(comptime T: type, slice: []const u8) !T {
    if (isNumberFormattedLikeAnInteger(slice))
        return std.fmt.parseInt(T, slice, 10);
    // Try to coerce a float to an integer.
    const float = try std.fmt.parseFloat(f128, slice);
    if (@round(float) != float) return error.InvalidNumber;
    if (float > std.math.maxInt(T) or float < std.math.minInt(T)) return error.Overflow;
    return @as(T, @intCast(@as(i128, @intFromFloat(float))));
}

fn sliceToEnum(comptime T: type, slice: []const u8) !T {
    // Check for a named value.
    if (std.meta.stringToEnum(T, slice)) |value| return value;
    // Check for a numeric value.
    if (!isNumberFormattedLikeAnInteger(slice)) return error.InvalidEnumTag;
    const n = std.fmt.parseInt(@typeInfo(T).@"enum".tag_type, slice, 10) catch return error.InvalidEnumTag;
    return std.meta.intToEnum(T, n);
}

fn fillDefaultStructValues(comptime T: type, r: *T, fields_seen: *[@typeInfo(T).@"struct".fields.len]bool) !void {
    inline for (@typeInfo(T).@"struct".fields, 0..) |field, i| {
        if (!fields_seen[i]) {
            if (field.defaultValue()) |default| {
                @field(r, field.name) = default;
            } else {
                return error.MissingField;
            }
        }
    }
}

fn freeAllocated(allocator: Allocator, token: Token) void {
    switch (token) {
        .allocated_number, .allocated_string => |slice| {
            allocator.free(slice);
        },
        else => {},
    }
}

test {
    _ = @import("./static_test.zig");
}
const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const ObjectMap = @import("dynamic.zig").ObjectMap;
const Value = @import("dynamic.zig").Value;

const StringifyOptions = @import("stringify.zig").StringifyOptions;
const stringify = @import("stringify.zig").stringify;
const stringifyMaxDepth = @import("stringify.zig").stringifyMaxDepth;
const stringifyArbitraryDepth = @import("stringify.zig").stringifyArbitraryDepth;
const stringifyAlloc = @import("stringify.zig").stringifyAlloc;
const writeStream = @import("stringify.zig").writeStream;
const writeStreamMaxDepth = @import("stringify.zig").writeStreamMaxDepth;
const writeStreamArbitraryDepth = @import("stringify.zig").writeStreamArbitraryDepth;

test "json write stream" {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixedBufferStream(&out_buf);
    const out = slice_stream.writer();

    {
        var w = writeStream(out, .{ .whitespace = .indent_2 });
        try testBasicWriteStream(&w, &slice_stream);
    }

    {
        var w = writeStreamMaxDepth(out, .{ .whitespace = .indent_2 }, 8);
        try testBasicWriteStream(&w, &slice_stream);
    }

    {
        var w = writeStreamMaxDepth(out, .{ .whitespace = .indent_2 }, null);
        try testBasicWriteStream(&w, &slice_stream);
    }

    {
        var w = writeStreamArbitraryDepth(testing.allocator, out, .{ .whitespace = .indent_2 });
        defer w.deinit();
        try testBasicWriteStream(&w, &slice_stream);
    }
}

fn testBasicWriteStream(w: anytype, slice_stream: anytype) !void {
    slice_stream.reset();

    try w.beginObject();

    try w.objectField("object");
    var arena_allocator = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_allocator.deinit();
    try w.write(try getJsonObject(arena_allocator.allocator()));

    try w.objectFieldRaw("\"string\"");
    try w.write("This is a string");

    try w.objectField("array");
    try w.beginArray();
    try w.write("Another string");
    try w.write(@as(i32, 1));
    try w.write(@as(f32, 3.5));
    try w.endArray();

    try w.objectField("int");
    try w.write(@as(i32, 10));

    try w.objectField("float");
    try w.write(@as(f32, 3.5));

    try w.endObject();

    const result = slice_stream.getWritten();
    const expected =
        \\{
        \\  "object": {
        \\    "one": 1,
        \\    "two": 2e0
        \\  },
        \\  "string": "This is a string",
        \\  "array": [
        \\    "Another string",
        \\    1,
        \\    3.5e0
        \\  ],
        \\  "int": 10,
        \\  "float": 3.5e0
        \\}
    ;
    try std.testing.expectEqualStrings(expected, result);
}

fn getJsonObject(allocator: std.mem.Allocator) !Value {
    var value = Value{ .object = ObjectMap.init(allocator) };
    try value.object.put("one", Value{ .integer = @as(i64, @intCast(1)) });
    try value.object.put("two", Value{ .float = 2.0 });
    return value;
}

test "stringify null optional fields" {
    const MyStruct = struct {
        optional: ?[]const u8 = null,
        required: []const u8 = "something",
        another_optional: ?[]const u8 = null,
        another_required: []const u8 = "something else",
    };
    try testStringify(
        \\{"optional":null,"required":"something","another_optional":null,"another_required":"something else"}
    ,
        MyStruct{},
        .{},
    );
    try testStringify(
        \\{"required":"something","another_required":"something else"}
    ,
        MyStruct{},
        .{ .emit_null_optional_fields = false },
    );
}

test "stringify basic types" {
    try testStringify("false", false, .{});
    try testStringify("true", true, .{});
    try testStringify("null", @as(?u8, null), .{});
    try testStringify("null", @as(?*u32, null), .{});
    try testStringify("42", 42, .{});
    try testStringify("4.2e1", 42.0, .{});
    try testStringify("42", @as(u8, 42), .{});
    try testStringify("42", @as(u128, 42), .{});
    try testStringify("9999999999999999", 9999999999999999, .{});
    try testStringify("4.2e1", @as(f32, 42), .{});
    try testStringify("4.2e1", @as(f64, 42), .{});
    try testStringify("\"ItBroke\"", @as(anyerror, error.ItBroke), .{});
    try testStringify("\"ItBroke\"", error.ItBroke, .{});
}

test "stringify string" {
    try testStringify("\"hello\"", "hello", .{});
    try testStringify("\"with\\nescapes\\r\"", "with\nescapes\r", .{});
    try testStringify("\"with\\nescapes\\r\"", "with\nescapes\r", .{ .escape_unicode = true });
    try testStringify("\"with unicode\\u0001\"", "with unicode\u{1}", .{});
    try testStringify("\"with unicode\\u0001\"", "with unicode\u{1}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{80}\"", "with unicode\u{80}", .{});
    try testStringify("\"with unicode\\u0080\"", "with unicode\u{80}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{FF}\"", "with unicode\u{FF}", .{});
    try testStringify("\"with unicode\\u00ff\"", "with unicode\u{FF}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{100}\"", "with unicode\u{100}", .{});
    try testStringify("\"with unicode\\u0100\"", "with unicode\u{100}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{800}\"", "with unicode\u{800}", .{});
    try testStringify("\"with unicode\\u0800\"", "with unicode\u{800}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{8000}\"", "with unicode\u{8000}", .{});
    try testStringify("\"with unicode\\u8000\"", "with unicode\u{8000}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{D799}\"", "with unicode\u{D799}", .{});
    try testStringify("\"with unicode\\ud799\"", "with unicode\u{D799}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{10000}\"", "with unicode\u{10000}", .{});
    try testStringify("\"with unicode\\ud800\\udc00\"", "with unicode\u{10000}", .{ .escape_unicode = true });
    try testStringify("\"with unicode\u{10FFFF}\"", "with unicode\u{10FFFF}", .{});
    try testStringify("\"with unicode\\udbff\\udfff\"", "with unicode\u{10FFFF}", .{ .escape_unicode = true });
}

test "stringify many-item sentinel-terminated string" {
    try testStringify("\"hello\"", @as([*:0]const u8, "hello"), .{});
    try testStringify("\"with\\nescapes\\r\"", @as([*:0]const u8, "with\nescapes\r"), .{ .escape_unicode = true });
    try testStringify("\"with unicode\\u0001\"", @as([*:0]const u8, "with unicode\u{1}"), .{ .escape_unicode = true });
}

test "stringify enums" {
    const E = enum {
        foo,
        bar,
    };
    try testStringify("\"foo\"", E.foo, .{});
    try testStringify("\"bar\"", E.bar, .{});
}

test "stringify non-exhaustive enum" {
    const E = enum(u8) {
        foo = 0,
        _,
    };
    try testStringify("\"foo\"", E.foo, .{});
    try testStringify("1", @as(E, @enumFromInt(1)), .{});
}

test "stringify enum literals" {
    try testStringify("\"foo\"", .foo, .{});
    try testStringify("\"bar\"", .bar, .{});
}

test "stringify tagged unions" {
    const T = union(enum) {
        nothing,
        foo: u32,
        bar: bool,
    };
    try testStringify("{\"nothing\":{}}", T{ .nothing = {} }, .{});
    try testStringify("{\"foo\":42}", T{ .foo = 42 }, .{});
    try testStringify("{\"bar\":true}", T{ .bar = true }, .{});
}

test "stringify struct" {
    try testStringify("{\"foo\":42}", struct {
        foo: u32,
    }{ .foo = 42 }, .{});
}

test "emit_strings_as_arrays" {
    // Should only affect string values, not object keys.
    try testStringify("{\"foo\":\"bar\"}", .{ .foo = "bar" }, .{});
    try testStringify("{\"foo\":[98,97,114]}", .{ .foo = "bar" }, .{ .emit_strings_as_arrays = true });
    // Should *not* affect these types:
    try testStringify("\"foo\"", @as(enum { foo, bar }, .foo), .{ .emit_strings_as_arrays = true });
    try testStringify("\"ItBroke\"", error.ItBroke, .{ .emit_strings_as_arrays = true });
    // Should work on these:
    try testStringify("\"bar\"", @Vector(3, u8){ 'b', 'a', 'r' }, .{});
    try testStringify("[98,97,114]", @Vector(3, u8){ 'b', 'a', 'r' }, .{ .emit_strings_as_arrays = true });
    try testStringify("\"bar\"", [3]u8{ 'b', 'a', 'r' }, .{});
    try testStringify("[98,97,114]", [3]u8{ 'b', 'a', 'r' }, .{ .emit_strings_as_arrays = true });
}

test "stringify struct with indentation" {
    try testStringify(
        \\{
        \\    "foo": 42,
        \\    "bar": [
        \\        1,
        \\        2,
        \\        3
        \\    ]
        \\}
    ,
        struct {
            foo: u32,
            bar: [3]u32,
        }{
            .foo = 42,
            .bar = .{ 1, 2, 3 },
        },
        .{ .whitespace = .indent_4 },
    );
    try testStringify(
        "{\n\t\"foo\": 42,\n\t\"bar\": [\n\t\t1,\n\t\t2,\n\t\t3\n\t]\n}",
        struct {
            foo: u32,
            bar: [3]u32,
        }{
            .foo = 42,
            .bar = .{ 1, 2, 3 },
        },
        .{ .whitespace = .indent_tab },
    );
    try testStringify(
        \\{"foo":42,"bar":[1,2,3]}
    ,
        struct {
            foo: u32,
            bar: [3]u32,
        }{
            .foo = 42,
            .bar = .{ 1, 2, 3 },
        },
        .{ .whitespace = .minified },
    );
}

test "stringify struct with void field" {
    try testStringify("{\"foo\":42}", struct {
        foo: u32,
        bar: void = {},
    }{ .foo = 42 }, .{});
}

test "stringify array of structs" {
    const MyStruct = struct {
        foo: u32,
    };
    try testStringify("[{\"foo\":42},{\"foo\":100},{\"foo\":1000}]", [_]MyStruct{
        MyStruct{ .foo = 42 },
        MyStruct{ .foo = 100 },
        MyStruct{ .foo = 1000 },
    }, .{});
}

test "stringify struct with custom stringifier" {
    try testStringify("[\"something special\",42]", struct {
        foo: u32,
        const Self = @This();
        pub fn jsonStringify(value: @This(), jws: anytype) !void {
            _ = value;
            try jws.beginArray();
            try jws.write("something special");
            try jws.write(42);
            try jws.endArray();
        }
    }{ .foo = 42 }, .{});
}

test "stringify vector" {
    try testStringify("[1,1]", @as(@Vector(2, u32), @splat(1)), .{});
    try testStringify("\"AA\"", @as(@Vector(2, u8), @splat('A')), .{});
    try testStringify("[65,65]", @as(@Vector(2, u8), @splat('A')), .{ .emit_strings_as_arrays = true });
}

test "stringify tuple" {
    try testStringify("[\"foo\",42]", std.meta.Tuple(&.{ []const u8, usize }){ "foo", 42 }, .{});
}

fn testStringify(expected: []const u8, value: anytype, options: StringifyOptions) !void {
    const ValidationWriter = struct {
        const Self = @This();
        pub const Writer = std.io.Writer(*Self, Error, write);
        pub const Error = error{
            TooMuchData,
            DifferentData,
        };

        expected_remaining: []const u8,

        fn init(exp: []const u8) Self {
            return .{ .expected_remaining = exp };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        fn write(self: *Self, bytes: []const u8) Error!usize {
            if (self.expected_remaining.len < bytes.len) {
                std.debug.print(
                    \\====== expected this output: =========
                    \\{s}
                    \\======== instead found this: =========
                    \\{s}
                    \\======================================
                , .{
                    self.expected_remaining,
                    bytes,
                });
                return error.TooMuchData;
            }
            if (!mem.eql(u8, self.expected_remaining[0..bytes.len], bytes)) {
                std.debug.print(
                    \\====== expected this output: =========
                    \\{s}
                    \\======== instead found this: =========
                    \\{s}
                    \\======================================
                , .{
                    self.expected_remaining[0..bytes.len],
                    bytes,
                });
                return error.DifferentData;
            }
            self.expected_remaining = self.expected_remaining[bytes.len..];
            return bytes.len;
        }
    };

    var vos = ValidationWriter.init(expected);
    try stringifyArbitraryDepth(testing.allocator, value, options, vos.writer());
    if (vos.expected_remaining.len > 0) return error.NotEnoughData;

    // Also test with safety disabled.
    try testStringifyMaxDepth(expected, value, options, null);
    try testStringifyArbitraryDepth(expected, value, options);
}

fn testStringifyMaxDepth(expected: []const u8, value: anytype, options: StringifyOptions, comptime max_depth: ?usize) !void {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixedBufferStream(&out_buf);
    const out = slice_stream.writer();

    try stringifyMaxDepth(value, options, out, max_depth);
    const got = slice_stream.getWritten();

    try testing.expectEqualStrings(expected, got);
}

fn testStringifyArbitraryDepth(expected: []const u8, value: anytype, options: StringifyOptions) !void {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixedBufferStream(&out_buf);
    const out = slice_stream.writer();

    try stringifyArbitraryDepth(testing.allocator, value, options, out);
    const got = slice_stream.getWritten();

    try testing.expectEqualStrings(expected, got);
}

test "stringify alloc" {
    const allocator = std.testing.allocator;
    const expected =
        \\{"foo":"bar","answer":42,"my_friend":"sammy"}
    ;
    const actual = try stringifyAlloc(allocator, .{ .foo = "bar", .answer = 42, .my_friend = "sammy" }, .{});
    defer allocator.free(actual);

    try std.testing.expectEqualStrings(expected, actual);
}

test "comptime stringify" {
    comptime testStringifyMaxDepth("false", false, .{}, null) catch unreachable;
    comptime testStringifyMaxDepth("false", false, .{}, 0) catch unreachable;
    comptime testStringifyArbitraryDepth("false", false, .{}) catch unreachable;

    const MyStruct = struct {
        foo: u32,
    };
    comptime testStringifyMaxDepth("[{\"foo\":42},{\"foo\":100},{\"foo\":1000}]", [_]MyStruct{
        MyStruct{ .foo = 42 },
        MyStruct{ .foo = 100 },
        MyStruct{ .foo = 1000 },
    }, .{}, null) catch unreachable;
    comptime testStringifyMaxDepth("[{\"foo\":42},{\"foo\":100},{\"foo\":1000}]", [_]MyStruct{
        MyStruct{ .foo = 42 },
        MyStruct{ .foo = 100 },
        MyStruct{ .foo = 1000 },
    }, .{}, 8) catch unreachable;
}

test "print" {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixedBufferStream(&out_buf);
    const out = slice_stream.writer();

    var w = writeStream(out, .{ .whitespace = .indent_2 });
    defer w.deinit();

    try w.beginObject();
    try w.objectField("a");
    try w.print("[  ]", .{});
    try w.objectField("b");
    try w.beginArray();
    try w.print("[{s}] ", .{"[]"});
    try w.print("  {}", .{12345});
    try w.endArray();
    try w.endObject();

    const result = slice_stream.getWritten();
    const expected =
        \\{
        \\  "a": [  ],
        \\  "b": [
        \\    [[]] ,
        \\      12345
        \\  ]
        \\}
    ;
    try std.testing.expectEqualStrings(expected, result);
}

test "nonportable numbers" {
    try testStringify("9999999999999999", 9999999999999999, .{});
    try testStringify("\"9999999999999999\"", 9999999999999999, .{ .emit_nonportable_numbers_as_strings = true });
}

test "stringify raw streaming" {
    var out_buf: [1024]u8 = undefined;
    var slice_stream = std.io.fixedBufferStream(&out_buf);
    const out = slice_stream.writer();

    {
        var w = writeStream(out, .{ .whitespace = .indent_2 });
        try testRawStreaming(&w, &slice_stream);
    }

    {
        var w = writeStreamMaxDepth(out, .{ .whitespace = .indent_2 }, 8);
        try testRawStreaming(&w, &slice_stream);
    }

    {
        var w = writeStreamMaxDepth(out, .{ .whitespace = .indent_2 }, null);
        try testRawStreaming(&w, &slice_stream);
    }

    {
        var w = writeStreamArbitraryDepth(testing.allocator, out, .{ .whitespace = .indent_2 });
        defer w.deinit();
        try testRawStreaming(&w, &slice_stream);
    }
}

fn testRawStreaming(w: anytype, slice_stream: anytype) !void {
    slice_stream.reset();

    try w.beginObject();
    try w.beginObjectFieldRaw();
    try w.stream.writeAll("\"long");
    try w.stream.writeAll(" key\"");
    w.endObjectFieldRaw();
    try w.beginWriteRaw();
    try w.stream.writeAll("\"long");
    try w.stream.writeAll(" value\"");
    w.endWriteRaw();
    try w.endObject();

    const result = slice_stream.getWritten();
    const expected =
        \\{
        \\  "long key": "long value"
        \\}
    ;
    try std.testing.expectEqualStrings(expected, result);
}
const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const BitStack = std.BitStack;

const OBJECT_MODE = 0;
const ARRAY_MODE = 1;

pub const StringifyOptions = struct {
    /// Controls the whitespace emitted.
    /// The default `.minified` is a compact encoding with no whitespace between tokens.
    /// Any setting other than `.minified` will use newlines, indentation, and a space after each ':'.
    /// `.indent_1` means 1 space for each indentation level, `.indent_2` means 2 spaces, etc.
    /// `.indent_tab` uses a tab for each indentation level.
    whitespace: enum {
        minified,
        indent_1,
        indent_2,
        indent_3,
        indent_4,
        indent_8,
        indent_tab,
    } = .minified,

    /// Should optional fields with null value be written?
    emit_null_optional_fields: bool = true,

    /// Arrays/slices of u8 are typically encoded as JSON strings.
    /// This option emits them as arrays of numbers instead.
    /// Does not affect calls to `objectField*()`.
    emit_strings_as_arrays: bool = false,

    /// Should unicode characters be escaped in strings?
    escape_unicode: bool = false,

    /// When true, renders numbers outside the range `+-1<<53` (the precise integer range of f64) as JSON strings in base 10.
    emit_nonportable_numbers_as_strings: bool = false,
};

/// Writes the given value to the `std.io.Writer` stream.
/// See `WriteStream` for how the given value is serialized into JSON.
/// The maximum nesting depth of the output JSON document is 256.
/// See also `stringifyMaxDepth` and `stringifyArbitraryDepth`.
pub fn stringify(
    value: anytype,
    options: StringifyOptions,
    out_stream: anytype,
) @TypeOf(out_stream).Error!void {
    var jw = writeStream(out_stream, options);
    defer jw.deinit();
    try jw.write(value);
}

/// Like `stringify` with configurable nesting depth.
/// `max_depth` is rounded up to the neares```
