```
t multiple of 8.
/// Give `null` for `max_depth` to disable some safety checks and allow arbitrary nesting depth.
/// See `writeStreamMaxDepth` for more info.
pub fn stringifyMaxDepth(
    value: anytype,
    options: StringifyOptions,
    out_stream: anytype,
    comptime max_depth: ?usize,
) @TypeOf(out_stream).Error!void {
    var jw = writeStreamMaxDepth(out_stream, options, max_depth);
    try jw.write(value);
}

/// Like `stringify` but takes an allocator to facilitate safety checks while allowing arbitrary nesting depth.
/// These safety checks can be helpful when debugging custom `jsonStringify` implementations;
/// See `WriteStream`.
pub fn stringifyArbitraryDepth(
    allocator: Allocator,
    value: anytype,
    options: StringifyOptions,
    out_stream: anytype,
) WriteStream(@TypeOf(out_stream), .checked_to_arbitrary_depth).Error!void {
    var jw = writeStreamArbitraryDepth(allocator, out_stream, options);
    defer jw.deinit();
    try jw.write(value);
}

/// Calls `stringifyArbitraryDepth` and stores the result in dynamically allocated memory
/// instead of taking a `std.io.Writer`.
///
/// Caller owns returned memory.
pub fn stringifyAlloc(
    allocator: Allocator,
    value: anytype,
    options: StringifyOptions,
) error{OutOfMemory}![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();
    try stringifyArbitraryDepth(allocator, value, options, list.writer());
    return list.toOwnedSlice();
}

/// See `WriteStream` for documentation.
/// Equivalent to calling `writeStreamMaxDepth` with a depth of `256`.
///
/// The caller does *not* need to call `deinit()` on the returned object.
pub fn writeStream(
    out_stream: anytype,
    options: StringifyOptions,
) WriteStream(@TypeOf(out_stream), .{ .checked_to_fixed_depth = 256 }) {
    return writeStreamMaxDepth(out_stream, options, 256);
}

/// See `WriteStream` for documentation.
/// The returned object includes 1 bit of size per `max_depth` to enable safety checks on the order of method calls;
/// see the grammar in the `WriteStream` documentation.
/// `max_depth` is rounded up to the nearest multiple of 8.
/// If the nesting depth exceeds `max_depth`, it is detectable illegal behavior.
/// Give `null` for `max_depth` to disable safety checks for the grammar and allow arbitrary nesting depth.
/// In `ReleaseFast` and `ReleaseSmall`, `max_depth` is ignored, effectively equivalent to passing `null`.
/// Alternatively, see `writeStreamArbitraryDepth` to do safety checks to arbitrary depth.
///
/// The caller does *not* need to call `deinit()` on the returned object.
pub fn writeStreamMaxDepth(
    out_stream: anytype,
    options: StringifyOptions,
    comptime max_depth: ?usize,
) WriteStream(
    @TypeOf(out_stream),
    if (max_depth) |d| .{ .checked_to_fixed_depth = d } else .assumed_correct,
) {
    return WriteStream(
        @TypeOf(out_stream),
        if (max_depth) |d| .{ .checked_to_fixed_depth = d } else .assumed_correct,
    ).init(undefined, out_stream, options);
}

/// See `WriteStream` for documentation.
/// This version of the write stream enables safety checks to arbitrarily deep nesting levels
/// by using the given allocator.
/// The caller should call `deinit()` on the returned object to free allocated memory.
///
/// In `ReleaseFast` and `ReleaseSmall` mode, this function is effectively equivalent to calling `writeStreamMaxDepth(..., null)`;
/// in those build modes, the allocator is *not used*.
pub fn writeStreamArbitraryDepth(
    allocator: Allocator,
    out_stream: anytype,
    options: StringifyOptions,
) WriteStream(@TypeOf(out_stream), .checked_to_arbitrary_depth) {
    return WriteStream(@TypeOf(out_stream), .checked_to_arbitrary_depth).init(allocator, out_stream, options);
}

/// Writes JSON ([RFC8259](https://tools.ietf.org/html/rfc8259)) formatted data
/// to a stream.
///
/// The sequence of method calls to write JSON content must follow this grammar:
/// ```
///  <once> = <value>
///  <value> =
///    | <object>
///    | <array>
///    | write
///    | print
///    | <writeRawStream>
///  <object> = beginObject ( <field> <value> )* endObject
///  <field> = objectField | objectFieldRaw | <objectFieldRawStream>
///  <array> = beginArray ( <value> )* endArray
///  <writeRawStream> = beginWriteRaw ( stream.writeAll )* endWriteRaw
///  <objectFieldRawStream> = beginObjectFieldRaw ( stream.writeAll )* endObjectFieldRaw
/// ```
///
/// The `safety_checks_hint` parameter determines how much memory is used to enable assertions that the above grammar is being followed,
/// e.g. tripping an assertion rather than allowing `endObject` to emit the final `}` in `[[[]]}`.
/// "Depth" in this context means the depth of nested `[]` or `{}` expressions
/// (or equivalently the amount of recursion on the `<value>` grammar expression above).
/// For example, emitting the JSON `[[[]]]` requires a depth of 3.
/// If `.checked_to_fixed_depth` is used, there is additionally an assertion that the nesting depth never exceeds the given limit.
/// `.checked_to_arbitrary_depth` requires a runtime allocator for the memory.
/// `.checked_to_fixed_depth` embeds the storage required in the `WriteStream` struct.
/// `.assumed_correct` requires no space and performs none of these assertions.
/// In `ReleaseFast` and `ReleaseSmall` mode, the given `safety_checks_hint` is ignored and is always treated as `.assumed_correct`.
pub fn WriteStream(
    comptime OutStream: type,
    comptime safety_checks_hint: union(enum) {
        checked_to_arbitrary_depth,
        checked_to_fixed_depth: usize, // Rounded up to the nearest multiple of 8.
        assumed_correct,
    },
) type {
    return struct {
        const Self = @This();
        const build_mode_has_safety = switch (@import("builtin").mode) {
            .Debug, .ReleaseSafe => true,
            .ReleaseFast, .ReleaseSmall => false,
        };
        const safety_checks: @TypeOf(safety_checks_hint) = if (build_mode_has_safety)
            safety_checks_hint
        else
            .assumed_correct;

        pub const Stream = OutStream;
        pub const Error = switch (safety_checks) {
            .checked_to_arbitrary_depth => Stream.Error || error{OutOfMemory},
            .checked_to_fixed_depth, .assumed_correct => Stream.Error,
        };

        options: StringifyOptions,

        stream: OutStream,
        indent_level: usize = 0,
        next_punctuation: enum {
            the_beginning,
            none,
            comma,
            colon,
        } = .the_beginning,

        nesting_stack: switch (safety_checks) {
            .checked_to_arbitrary_depth => BitStack,
            .checked_to_fixed_depth => |fixed_buffer_size| [(fixed_buffer_size + 7) >> 3]u8,
            .assumed_correct => void,
        },

        raw_streaming_mode: if (build_mode_has_safety)
            enum { none, value, objectField }
        else
            void = if (build_mode_has_safety) .none else {},

        pub fn init(safety_allocator: Allocator, stream: OutStream, options: StringifyOptions) Self {
            return .{
                .options = options,
                .stream = stream,
                .nesting_stack = switch (safety_checks) {
                    .checked_to_arbitrary_depth => BitStack.init(safety_allocator),
                    .checked_to_fixed_depth => |fixed_buffer_size| [_]u8{0} ** ((fixed_buffer_size + 7) >> 3),
                    .assumed_correct => {},
                },
            };
        }

        /// Only necessary with .checked_to_arbitrary_depth.
        pub fn deinit(self: *Self) void {
            switch (safety_checks) {
                .checked_to_arbitrary_depth => self.nesting_stack.deinit(),
                .checked_to_fixed_depth, .assumed_correct => {},
            }
            self.* = undefined;
        }

        pub fn beginArray(self: *Self) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            try self.valueStart();
            try self.stream.writeByte('[');
            try self.pushIndentation(ARRAY_MODE);
            self.next_punctuation = .none;
        }

        pub fn beginObject(self: *Self) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            try self.valueStart();
            try self.stream.writeByte('{');
            try self.pushIndentation(OBJECT_MODE);
            self.next_punctuation = .none;
        }

        pub fn endArray(self: *Self) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            self.popIndentation(ARRAY_MODE);
            switch (self.next_punctuation) {
                .none => {},
                .comma => {
                    try self.indent();
                },
                .the_beginning, .colon => unreachable,
            }
            try self.stream.writeByte(']');
            self.valueDone();
        }

        pub fn endObject(self: *Self) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            self.popIndentation(OBJECT_MODE);
            switch (self.next_punctuation) {
                .none => {},
                .comma => {
                    try self.indent();
                },
                .the_beginning, .colon => unreachable,
            }
            try self.stream.writeByte('}');
            self.valueDone();
        }

        fn pushIndentation(self: *Self, mode: u1) !void {
            switch (safety_checks) {
                .checked_to_arbitrary_depth => {
                    try self.nesting_stack.push(mode);
                    self.indent_level += 1;
                },
                .checked_to_fixed_depth => {
                    BitStack.pushWithStateAssumeCapacity(&self.nesting_stack, &self.indent_level, mode);
                },
                .assumed_correct => {
                    self.indent_level += 1;
                },
            }
        }
        fn popIndentation(self: *Self, assert_its_this_one: u1) void {
            switch (safety_checks) {
                .checked_to_arbitrary_depth => {
                    assert(self.nesting_stack.pop() == assert_its_this_one);
                    self.indent_level -= 1;
                },
                .checked_to_fixed_depth => {
                    assert(BitStack.popWithState(&self.nesting_stack, &self.indent_level) == assert_its_this_one);
                },
                .assumed_correct => {
                    self.indent_level -= 1;
                },
            }
        }

        fn indent(self: *Self) !void {
            var char: u8 = ' ';
            const n_chars = switch (self.options.whitespace) {
                .minified => return,
                .indent_1 => 1 * self.indent_level,
                .indent_2 => 2 * self.indent_level,
                .indent_3 => 3 * self.indent_level,
                .indent_4 => 4 * self.indent_level,
                .indent_8 => 8 * self.indent_level,
                .indent_tab => blk: {
                    char = '\t';
                    break :blk self.indent_level;
                },
            };
            try self.stream.writeByte('\n');
            try self.stream.writeByteNTimes(char, n_chars);
        }

        fn valueStart(self: *Self) !void {
            if (self.isObjectKeyExpected()) |is_it| assert(!is_it); // Call objectField*(), not write(), for object keys.
            return self.valueStartAssumeTypeOk();
        }
        fn objectFieldStart(self: *Self) !void {
            if (self.isObjectKeyExpected()) |is_it| assert(is_it); // Expected write(), not objectField*().
            return self.valueStartAssumeTypeOk();
        }
        fn valueStartAssumeTypeOk(self: *Self) !void {
            assert(!self.isComplete()); // JSON document already complete.
            switch (self.next_punctuation) {
                .the_beginning => {
                    // No indentation for the very beginning.
                },
                .none => {
                    // First item in a container.
                    try self.indent();
                },
                .comma => {
                    // Subsequent item in a container.
                    try self.stream.writeByte(',');
                    try self.indent();
                },
                .colon => {
                    try self.stream.writeByte(':');
                    if (self.options.whitespace != .minified) {
                        try self.stream.writeByte(' ');
                    }
                },
            }
        }
        fn valueDone(self: *Self) void {
            self.next_punctuation = .comma;
        }

        // Only when safety is enabled:
        fn isObjectKeyExpected(self: *const Self) ?bool {
            switch (safety_checks) {
                .checked_to_arbitrary_depth => return self.indent_level > 0 and
                    self.nesting_stack.peek() == OBJECT_MODE and
                    self.next_punctuation != .colon,
                .checked_to_fixed_depth => return self.indent_level > 0 and
                    BitStack.peekWithState(&self.nesting_stack, self.indent_level) == OBJECT_MODE and
                    self.next_punctuation != .colon,
                .assumed_correct => return null,
            }
        }
        fn isComplete(self: *const Self) bool {
            return self.indent_level == 0 and self.next_punctuation == .comma;
        }

        /// An alternative to calling `write` that formats a value with `std.fmt`.
        /// This function does the usual punctuation and indentation formatting
        /// assuming the resulting formatted string represents a single complete value;
        /// e.g. `"1"`, `"[]"`, `"[1,2]"`, not `"1,2"`.
        /// This function may be useful for doing your own number formatting.
        pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            try self.valueStart();
            try self.stream.print(fmt, args);
            self.valueDone();
        }

        /// An alternative to calling `write` that allows you to write directly to the `.stream` field, e.g. with `.stream.writeAll()`.
        /// Call `beginWriteRaw()`, then write a complete value (including any quotes if necessary) directly to the `.stream` field,
        /// then call `endWriteRaw()`.
        /// This can be useful for streaming very long strings into the output without needing it all buffered in memory.
        pub fn beginWriteRaw(self: *Self) !void {
            if (build_mode_has_safety) {
                assert(self.raw_streaming_mode == .none);
                self.raw_streaming_mode = .value;
            }
            try self.valueStart();
        }

        /// See `beginWriteRaw`.
        pub fn endWriteRaw(self: *Self) void {
            if (build_mode_has_safety) {
                assert(self.raw_streaming_mode == .value);
                self.raw_streaming_mode = .none;
            }
            self.valueDone();
        }

        /// See `WriteStream` for when to call this method.
        /// `key` is the string content of the property name.
        /// Surrounding quotes will be added and any special characters will be escaped.
        /// See also `objectFieldRaw`.
        pub fn objectField(self: *Self, key: []const u8) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            try self.objectFieldStart();
            try encodeJsonString(key, self.options, self.stream);
            self.next_punctuation = .colon;
        }
        /// See `WriteStream` for when to call this method.
        /// `quoted_key` is the complete bytes of the key including quotes and any necessary escape sequences.
        /// A few assertions are performed on the given value to ensure that the caller of this function understands the API contract.
        /// See also `objectField`.
        pub fn objectFieldRaw(self: *Self, quoted_key: []const u8) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            assert(quoted_key.len >= 2 and quoted_key[0] == '"' and quoted_key[quoted_key.len - 1] == '"'); // quoted_key should be "quoted".
            try self.objectFieldStart();
            try self.stream.writeAll(quoted_key);
            self.next_punctuation = .colon;
        }

        /// In the rare case that you need to write very long object field names,
        /// this is an alternative to `objectField` and `objectFieldRaw` that allows you to write directly to the `.stream` field
        /// similar to `beginWriteRaw`.
        /// Call `endObjectFieldRaw()` when you're done.
        pub fn beginObjectFieldRaw(self: *Self) !void {
            if (build_mode_has_safety) {
                assert(self.raw_streaming_mode == .none);
                self.raw_streaming_mode = .objectField;
            }
            try self.objectFieldStart();
        }

        /// See `beginObjectFieldRaw`.
        pub fn endObjectFieldRaw(self: *Self) void {
            if (build_mode_has_safety) {
                assert(self.raw_streaming_mode == .objectField);
                self.raw_streaming_mode = .none;
            }
            self.next_punctuation = .colon;
        }

        /// Renders the given Zig value as JSON.
        ///
        /// Supported types:
        ///  * Zig `bool` -> JSON `true` or `false`.
        ///  * Zig `?T` -> `null` or the rendering of `T`.
        ///  * Zig `i32`, `u64`, etc. -> JSON number or string.
        ///      * When option `emit_nonportable_numbers_as_strings` is true, if the value is outside the range `+-1<<53` (the precise integer range of f64), it is rendered as a JSON string in base 10. Otherwise, it is rendered as JSON number.
        ///  * Zig floats -> JSON number or string.
        ///      * If the value cannot be precisely represented by an f64, it is rendered as a JSON string. Otherwise, it is rendered as JSON number.
        ///      * TODO: Float rendering will likely change in the future, e.g. to remove the unnecessary "e+00".
        ///  * Zig `[]const u8`, `[]u8`, `*[N]u8`, `@Vector(N, u8)`, and similar -> JSON string.
        ///      * See `StringifyOptions.emit_strings_as_arrays`.
        ///      * If the content is not valid UTF-8, rendered as an array of numbers instead.
        ///  * Zig `[]T`, `[N]T`, `*[N]T`, `@Vector(N, T)`, and similar -> JSON array of the rendering of each item.
        ///  * Zig tuple -> JSON array of the rendering of each item.
        ///  * Zig `struct` -> JSON object with each field in declaration order.
        ///      * If the struct declares a method `pub fn jsonStringify(self: *@This(), jw: anytype) !void`, it is called to do the serialization instead of the default behavior. The given `jw` is a pointer to this `WriteStream`. See `std.json.Value` for an example.
        ///      * See `StringifyOptions.emit_null_optional_fields`.
        ///  * Zig `union(enum)` -> JSON object with one field named for the active tag and a value representing the payload.
        ///      * If the payload is `void`, then the emitted value is `{}`.
        ///      * If the union declares a method `pub fn jsonStringify(self: *@This(), jw: anytype) !void`, it is called to do the serialization instead of the default behavior. The given `jw` is a pointer to this `WriteStream`.
        ///  * Zig `enum` -> JSON string naming the active tag.
        ///      * If the enum declares a method `pub fn jsonStringify(self: *@This(), jw: anytype) !void`, it is called to do the serialization instead of the default behavior. The given `jw` is a pointer to this `WriteStream`.
        ///      * If the enum is non-exhaustive, unnamed values are rendered as integers.
        ///  * Zig untyped enum literal -> JSON string naming the active tag.
        ///  * Zig error -> JSON string naming the error.
        ///  * Zig `*T` -> the rendering of `T`. Note there is no guard against circular-reference infinite recursion.
        ///
        /// See also alternative functions `print` and `beginWriteRaw`.
        /// For writing object field names, use `objectField` instead.
        pub fn write(self: *Self, value: anytype) Error!void {
            if (build_mode_has_safety) assert(self.raw_streaming_mode == .none);
            const T = @TypeOf(value);
            switch (@typeInfo(T)) {
                .int => {
                    try self.valueStart();
                    if (self.options.emit_nonportable_numbers_as_strings and
                        (value <= -(1 << 53) or value >= (1 << 53)))
                    {
                        try self.stream.print("\"{}\"", .{value});
                    } else {
                        try self.stream.print("{}", .{value});
                    }
                    self.valueDone();
                    return;
                },
                .comptime_int => {
                    return self.write(@as(std.math.IntFittingRange(value, value), value));
                },
                .float, .comptime_float => {
                    if (@as(f64, @floatCast(value)) == value) {
                        try self.valueStart();
                        try self.stream.print("{}", .{@as(f64, @floatCast(value))});
                        self.valueDone();
                        return;
                    }
                    try self.valueStart();
                    try self.stream.print("\"{}\"", .{value});
                    self.valueDone();
                    return;
                },

                .bool => {
                    try self.valueStart();
                    try self.stream.writeAll(if (value) "true" else "false");
                    self.valueDone();
                    return;
                },
                .null => {
                    try self.valueStart();
                    try self.stream.writeAll("null");
                    self.valueDone();
                    return;
                },
                .optional => {
                    if (value) |payload| {
                        return try self.write(payload);
                    } else {
                        return try self.write(null);
                    }
                },
                .@"enum" => |enum_info| {
                    if (std.meta.hasFn(T, "jsonStringify")) {
                        return value.jsonStringify(self);
                    }

                    if (!enum_info.is_exhaustive) {
                        inline for (enum_info.fields) |field| {
                            if (value == @field(T, field.name)) {
                                break;
                            }
                        } else {
                            return self.write(@intFromEnum(value));
                        }
                    }

                    return self.stringValue(@tagName(value));
                },
                .enum_literal => {
                    return self.stringValue(@tagName(value));
                },
                .@"union" => {
                    if (std.meta.hasFn(T, "jsonStringify")) {
                        return value.jsonStringify(self);
                    }

                    const info = @typeInfo(T).@"union";
                    if (info.tag_type) |UnionTagType| {
                        try self.beginObject();
                        inline for (info.fields) |u_field| {
                            if (value == @field(UnionTagType, u_field.name)) {
                                try self.objectField(u_field.name);
                                if (u_field.type == void) {
                                    // void value is {}
                                    try self.beginObject();
                                    try self.endObject();
                                } else {
                                    try self.write(@field(value, u_field.name));
                                }
                                break;
                            }
                        } else {
                            unreachable; // No active tag?
                        }
                        try self.endObject();
                        return;
                    } else {
                        @compileError("Unable to stringify untagged union '" ++ @typeName(T) ++ "'");
                    }
                },
                .@"struct" => |S| {
                    if (std.meta.hasFn(T, "jsonStringify")) {
                        return value.jsonStringify(self);
                    }

                    if (S.is_tuple) {
                        try self.beginArray();
                    } else {
                        try self.beginObject();
                    }
                    inline for (S.fields) |Field| {
                        // don't include void fields
                        if (Field.type == void) continue;

                        var emit_field = true;

                        // don't include optional fields that are null when emit_null_optional_fields is set to false
                        if (@typeInfo(Field.type) == .optional) {
                            if (self.options.emit_null_optional_fields == false) {
                                if (@field(value, Field.name) == null) {
                                    emit_field = false;
                                }
                            }
                        }

                        if (emit_field) {
                            if (!S.is_tuple) {
                                try self.objectField(Field.name);
                            }
                            try self.write(@field(value, Field.name));
                        }
                    }
                    if (S.is_tuple) {
                        try self.endArray();
                    } else {
                        try self.endObject();
                    }
                    return;
                },
                .error_set => return self.stringValue(@errorName(value)),
                .pointer => |ptr_info| switch (ptr_info.size) {
                    .one => switch (@typeInfo(ptr_info.child)) {
                        .array => {
                            // Coerce `*[N]T` to `[]const T`.
                            const Slice = []const std.meta.Elem(ptr_info.child);
                            return self.write(@as(Slice, value));
                        },
                        else => {
                            return self.write(value.*);
                        },
                    },
                    .many, .slice => {
                        if (ptr_info.size == .many and ptr_info.sentinel() == null)
                            @compileError("unable to stringify type '" ++ @typeName(T) ++ "' without sentinel");
                        const slice = if (ptr_info.size == .many) std.mem.span(value) else value;

                        if (ptr_info.child == u8) {
                            // This is a []const u8, or some similar Zig string.
                            if (!self.options.emit_strings_as_arrays and std.unicode.utf8ValidateSlice(slice)) {
                                return self.stringValue(slice);
                            }
                        }

                        try self.beginArray();
                        for (slice) |x| {
                            try self.write(x);
                        }
                        try self.endArray();
                        return;
                    },
                    else => @compileError("Unable to stringify type '" ++ @typeName(T) ++ "'"),
                },
                .array => {
                    // Coerce `[N]T` to `*const [N]T` (and then to `[]const T`).
                    return self.write(&value);
                },
                .vector => |info| {
                    const array: [info.len]info.child = value;
                    return self.write(&array);
                },
                else => @compileError("Unable to stringify type '" ++ @typeName(T) ++ "'"),
            }
            unreachable;
        }

        fn stringValue(self: *Self, s: []const u8) !void {
            try self.valueStart();
            try encodeJsonString(s, self.options, self.stream);
            self.valueDone();
        }
    };
}

fn outputUnicodeEscape(codepoint: u21, out_stream: anytype) !void {
    if (codepoint <= 0xFFFF) {
        // If the character is in the Basic Multilingual Plane (U+0000 through U+FFFF),
        // then it may be represented as a six-character sequence: a reverse solidus, followed
        // by the lowercase letter u, followed by four hexadecimal digits that encode the character's code point.
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(codepoint, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    } else {
        assert(codepoint <= 0x10FFFF);
        // To escape an extended character that is not in the Basic Multilingual Plane,
        // the character is represented as a 12-character sequence, encoding the UTF-16 surrogate pair.
        const high = @as(u16, @intCast((codepoint - 0x10000) >> 10)) + 0xD800;
        const low = @as(u16, @intCast(codepoint & 0x3FF)) + 0xDC00;
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(high, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(low, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    }
}

fn outputSpecialEscape(c: u8, writer: anytype) !void {
    switch (c) {
        '\\' => try writer.writeAll("\\\\"),
        '\"' => try writer.writeAll("\\\""),
        0x08 => try writer.writeAll("\\b"),
        0x0C => try writer.writeAll("\\f"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        else => try outputUnicodeEscape(c, writer),
    }
}

/// Write `string` to `writer` as a JSON encoded string.
pub fn encodeJsonString(string: []const u8, options: StringifyOptions, writer: anytype) !void {
    try writer.writeByte('\"');
    try encodeJsonStringChars(string, options, writer);
    try writer.writeByte('\"');
}

/// Write `chars` to `writer` as JSON encoded string characters.
pub fn encodeJsonStringChars(chars: []const u8, options: StringifyOptions, writer: anytype) !void {
    var write_cursor: usize = 0;
    var i: usize = 0;
    if (options.escape_unicode) {
        while (i < chars.len) : (i += 1) {
            switch (chars[i]) {
                // normal ascii character
                0x20...0x21, 0x23...0x5B, 0x5D...0x7E => {},
                0x00...0x1F, '\\', '\"' => {
                    // Always must escape these.
                    try writer.writeAll(chars[write_cursor..i]);
                    try outputSpecialEscape(chars[i], writer);
                    write_cursor = i + 1;
                },
                0x7F...0xFF => {
                    try writer.writeAll(chars[write_cursor..i]);
                    const ulen = std.unicode.utf8ByteSequenceLength(chars[i]) catch unreachable;
                    const codepoint = std.unicode.utf8Decode(chars[i..][0..ulen]) catch unreachable;
                    try outputUnicodeEscape(codepoint, writer);
                    i += ulen - 1;
                    write_cursor = i + 1;
                },
            }
        }
    } else {
        while (i < chars.len) : (i += 1) {
            switch (chars[i]) {
                // normal bytes
                0x20...0x21, 0x23...0x5B, 0x5D...0xFF => {},
                0x00...0x1F, '\\', '\"' => {
                    // Always must escape these.
                    try writer.writeAll(chars[write_cursor..i]);
                    try outputSpecialEscape(chars[i], writer);
                    write_cursor = i + 1;
                },
            }
        }
    }
    try writer.writeAll(chars[write_cursor..chars.len]);
}

test {
    _ = @import("./stringify_test.zig");
}
const std = @import("std");
const testing = std.testing;
const parseFromSlice = @import("./static.zig").parseFromSlice;
const validate = @import("./scanner.zig").validate;
const JsonScanner = @import("./scanner.zig").Scanner;
const Value = @import("./dynamic.zig").Value;
const stringifyAlloc = @import("./stringify.zig").stringifyAlloc;

// Support for JSONTestSuite.zig
pub fn ok(s: []const u8) !void {
    try testLowLevelScanner(s);
    try testHighLevelDynamicParser(s);
}
pub fn err(s: []const u8) !void {
    try testing.expect(std.meta.isError(testLowLevelScanner(s)));
    try testing.expect(std.meta.isError(testHighLevelDynamicParser(s)));
}
pub fn any(s: []const u8) !void {
    testLowLevelScanner(s) catch {};
    testHighLevelDynamicParser(s) catch {};
}
fn testLowLevelScanner(s: []const u8) !void {
    var scanner = JsonScanner.initCompleteInput(testing.allocator, s);
    defer scanner.deinit();
    while (true) {
        const token = try scanner.next();
        if (token == .end_of_document) break;
    }
}
fn testHighLevelDynamicParser(s: []const u8) !void {
    var parsed = try parseFromSlice(Value, testing.allocator, s, .{
        .duplicate_field_behavior = .use_first,
    });
    defer parsed.deinit();
}

// Additional tests not part of test JSONTestSuite.
test "y_trailing_comma_after_empty" {
    try roundTrip(
        \\{"1":[],"2":{},"3":"4"}
    );
}
test "n_object_closed_missing_value" {
    try err(
        \\{"a":}
    );
}

fn roundTrip(s: []const u8) !void {
    try testing.expect(try validate(testing.allocator, s));

    var parsed = try parseFromSlice(Value, testing.allocator, s, .{});
    defer parsed.deinit();

    const rendered = try stringifyAlloc(testing.allocator, parsed.value, .{});
    defer testing.allocator.free(rendered);

    try testing.expectEqualStrings(s, rendered);
}

test "truncated UTF-8 sequence" {
    try err("\"\xc2\"");
    try err("\"\xdf\"");
    try err("\"\xed\xa0\"");
    try err("\"\xf0\x80\"");
    try err("\"\xf0\x80\x80\"");
}

test "invalid continuation byte" {
    try err("\"\xc2\x00\"");
    try err("\"\xc2\x7f\"");
    try err("\"\xc2\xc0\"");
    try err("\"\xc3\xc1\"");
    try err("\"\xc4\xf5\"");
    try err("\"\xc5\xff\"");
    try err("\"\xe4\x80\x00\"");
    try err("\"\xe5\x80\x10\"");
    try err("\"\xe6\x80\xc0\"");
    try err("\"\xe7\x80\xf5\"");
    try err("\"\xe8\x00\x80\"");
    try err("\"\xf2\x00\x80\x80\"");
    try err("\"\xf0\x80\x00\x80\"");
    try err("\"\xf1\x80\xc0\x80\"");
    try err("\"\xf2\x80\x80\x00\"");
    try err("\"\xf3\x80\x80\xc0\"");
    try err("\"\xf4\x80\x80\xf5\"");
}

test "disallowed overlong form" {
    try err("\"\xc0\x80\"");
    try err("\"\xc0\x90\"");
    try err("\"\xc1\x80\"");
    try err("\"\xc1\x90\"");
    try err("\"\xe0\x80\x80\"");
    try err("\"\xf0\x80\x80\x80\"");
}

test "out of UTF-16 range" {
    try err("\"\xf4\x90\x80\x80\"");
    try err("\"\xf5\x80\x80\x80\"");
    try err("\"\xf6\x80\x80\x80\"");
    try err("\"\xf7\x80\x80\x80\"");
    try err("\"\xf8\x80\x80\x80\"");
    try err("\"\xf9\x80\x80\x80\"");
    try err("\"\xfa\x80\x80\x80\"");
    try err("\"\xfb\x80\x80\x80\"");
    try err("\"\xfc\x80\x80\x80\"");
    try err("\"\xfd\x80\x80\x80\"");
    try err("\"\xfe\x80\x80\x80\"");
    try err("\"\xff\x80\x80\x80\"");
}
const std = @import("std");
const testing = std.testing;

/// Read a single unsigned LEB128 value from the given reader as type T,
/// or error.Overflow if the value cannot fit.
pub fn readUleb128(comptime T: type, reader: anytype) !T {
    const U = if (@typeInfo(T).int.bits < 8) u8 else T;
    const ShiftT = std.math.Log2Int(U);

    const max_group = (@typeInfo(U).int.bits + 6) / 7;

    var value: U = 0;
    var group: ShiftT = 0;

    while (group < max_group) : (group += 1) {
        const byte = try reader.readByte();

        const ov = @shlWithOverflow(@as(U, byte & 0x7f), group * 7);
        if (ov[1] != 0) return error.Overflow;

        value |= ov[0];
        if (byte & 0x80 == 0) break;
    } else {
        return error.Overflow;
    }

    // only applies in the case that we extended to u8
    if (U != T) {
        if (value > std.math.maxInt(T)) return error.Overflow;
    }

    return @as(T, @truncate(value));
}

/// Deprecated: use `readUleb128`
pub const readULEB128 = readUleb128;

/// Write a single unsigned integer as unsigned LEB128 to the given writer.
pub fn writeUleb128(writer: anytype, arg: anytype) !void {
    const Arg = @TypeOf(arg);
    const Int = switch (Arg) {
        comptime_int => std.math.IntFittingRange(arg, arg),
        else => Arg,
    };
    const Value = if (@typeInfo(Int).int.bits < 8) u8 else Int;
    var value: Value = arg;

    while (true) {
        const byte: u8 = @truncate(value & 0x7f);
        value >>= 7;
        if (value == 0) {
            try writer.writeByte(byte);
            break;
        } else {
            try writer.writeByte(byte | 0x80);
        }
    }
}

/// Deprecated: use `writeUleb128`
pub const writeULEB128 = writeUleb128;

/// Read a single signed LEB128 value from the given reader as type T,
/// or error.Overflow if the value cannot fit.
pub fn readIleb128(comptime T: type, reader: anytype) !T {
    const S = if (@typeInfo(T).int.bits < 8) i8 else T;
    const U = std.meta.Int(.unsigned, @typeInfo(S).int.bits);
    const ShiftU = std.math.Log2Int(U);

    const max_group = (@typeInfo(U).int.bits + 6) / 7;

    var value = @as(U, 0);
    var group = @as(ShiftU, 0);

    while (group < max_group) : (group += 1) {
        const byte = try reader.readByte();

        const shift = group * 7;
        const ov = @shlWithOverflow(@as(U, byte & 0x7f), shift);
        if (ov[1] != 0) {
            // Overflow is ok so long as the sign bit is set and this is the last byte
            if (byte & 0x80 != 0) return error.Overflow;
            if (@as(S, @bitCast(ov[0])) >= 0) return error.Overflow;

            // and all the overflowed bits are 1
            const remaining_shift = @as(u3, @intCast(@typeInfo(U).int.bits - @as(u16, shift)));
            const remaining_bits = @as(i8, @bitCast(byte | 0x80)) >> remaining_shift;
            if (remaining_bits != -1) return error.Overflow;
        } else {
            // If we don't overflow and this is the last byte and the number being decoded
            // is negative, check that the remaining bits are 1
            if ((byte & 0x80 == 0) and (@as(S, @bitCast(ov[0])) < 0)) {
                const remaining_shift = @as(u3, @intCast(@typeInfo(U).int.bits - @as(u16, shift)));
                const remaining_bits = @as(i8, @bitCast(byte | 0x80)) >> remaining_shift;
                if (remaining_bits != -1) return error.Overflow;
            }
        }

        value |= ov[0];
        if (byte & 0x80 == 0) {
            const needs_sign_ext = group + 1 < max_group;
            if (byte & 0x40 != 0 and needs_sign_ext) {
                const ones = @as(S, -1);
                value |= @as(U, @bitCast(ones)) << (shift + 7);
            }
            break;
        }
    } else {
        return error.Overflow;
    }

    const result = @as(S, @bitCast(value));
    // Only applies if we extended to i8
    if (S != T) {
        if (result > std.math.maxInt(T) or result < std.math.minInt(T)) return error.Overflow;
    }

    return @as(T, @truncate(result));
}

/// Deprecated: use `readIleb128`
pub const readILEB128 = readIleb128;

/// Write a single signed integer as signed LEB128 to the given writer.
pub fn writeIleb128(writer: anytype, arg: anytype) !void {
    const Arg = @TypeOf(arg);
    const Int = switch (Arg) {
        comptime_int => std.math.IntFittingRange(-@abs(arg), @abs(arg)),
        else => Arg,
    };
    const Signed = if (@typeInfo(Int).int.bits < 8) i8 else Int;
    const Unsigned = std.meta.Int(.unsigned, @typeInfo(Signed).int.bits);
    var value: Signed = arg;

    while (true) {
        const unsigned: Unsigned = @bitCast(value);
        const byte: u8 = @truncate(unsigned);
        value >>= 6;
        if (value == -1 or value == 0) {
            try writer.writeByte(byte & 0x7F);
            break;
        } else {
            value >>= 1;
            try writer.writeByte(byte | 0x80);
        }
    }
}

/// This is an "advanced" function. It allows one to use a fixed amount of memory to store a
/// ULEB128. This defeats the entire purpose of using this data encoding; it will no longer use
/// fewer bytes to store smaller numbers. The advantage of using a fixed width is that it makes
/// fields have a predictable size and so depending on the use case this tradeoff can be worthwhile.
/// An example use case of this is in emitting DWARF info where one wants to make a ULEB128 field
/// "relocatable", meaning that it becomes possible to later go back and patch the number to be a
/// different value without shifting all the following code.
pub fn writeUnsignedFixed(comptime l: usize, ptr: *[l]u8, int: std.meta.Int(.unsigned, l * 7)) void {
    writeUnsignedExtended(ptr, int);
}

/// Same as `writeUnsignedFixed` but with a runtime-known length.
/// Asserts `slice.len > 0`.
pub fn writeUnsignedExtended(slice: []u8, arg: anytype) void {
    const Arg = @TypeOf(arg);
    const Int = switch (Arg) {
        comptime_int => std.math.IntFittingRange(arg, arg),
        else => Arg,
    };
    const Value = if (@typeInfo(Int).int.bits < 8) u8 else Int;
    var value: Value = arg;

    for (slice[0 .. slice.len - 1]) |*byte| {
        byte.* = @truncate(0x80 | value);
        value >>= 7;
    }
    slice[slice.len - 1] = @as(u7, @intCast(value));
}

/// Deprecated: use `writeIleb128`
pub const writeILEB128 = writeIleb128;

test writeUnsignedFixed {
    {
        var buf: [4]u8 = undefined;
        writeUnsignedFixed(4, &buf, 0);
        try testing.expect((try test_read_uleb128(u64, &buf)) == 0);
    }
    {
        var buf: [4]u8 = undefined;
        writeUnsignedFixed(4, &buf, 1);
        try testing.expect((try test_read_uleb128(u64, &buf)) == 1);
    }
    {
        var buf: [4]u8 = undefined;
        writeUnsignedFixed(4, &buf, 1000);
        try testing.expect((try test_read_uleb128(u64, &buf)) == 1000);
    }
    {
        var buf: [4]u8 = undefined;
        writeUnsignedFixed(4, &buf, 10000000);
        try testing.expect((try test_read_uleb128(u64, &buf)) == 10000000);
    }
}

/// This is an "advanced" function. It allows one to use a fixed amount of memory to store an
/// ILEB128. This defeats the entire purpose of using this data encoding; it will no longer use
/// fewer bytes to store smaller numbers. The advantage of using a fixed width is that it makes
/// fields have a predictable size and so depending on the use case this tradeoff can be worthwhile.
/// An example use case of this is in emitting DWARF info where one wants to make a ILEB128 field
/// "relocatable", meaning that it becomes possible to later go back and patch the number to be a
/// different value without shifting all the following code.
pub fn writeSignedFixed(comptime l: usize, ptr: *[l]u8, int: std.meta.Int(.signed, l * 7)) void {
    const T = @TypeOf(int);
    const U = if (@typeInfo(T).int.bits < 8) u8 else T;
    var value: U = @intCast(int);

    comptime var i = 0;
    inline while (i < (l - 1)) : (i += 1) {
        const byte: u8 = @bitCast(@as(i8, @truncate(value)) | -0b1000_0000);
        value >>= 7;
        ptr[i] = byte;
    }
    ptr[i] = @as(u7, @bitCast(@as(i7, @truncate(value))));
}

test writeSignedFixed {
    {
        var buf: [4]u8 = undefined;
        writeSignedFixed(4, &buf, 0);
        try testing.expect((try test_read_ileb128(i64, &buf)) == 0);
    }
    {
        var buf: [4]u8 = undefined;
        writeSignedFixed(4, &buf, 1);
        try testing.expect((try test_read_ileb128(i64, &buf)) == 1);
    }
    {
        var buf: [4]u8 = undefined;
        writeSignedFixed(4, &buf, -1);
        try testing.expect((try test_read_ileb128(i64, &buf)) == -1);
    }
    {
        var buf: [4]u8 = undefined;
        writeSignedFixed(4, &buf, 1000);
        try testing.expect((try test_read_ileb128(i64, &buf)) == 1000);
    }
    {
        var buf: [4]u8 = undefined;
        writeSignedFixed(4, &buf, -1000);
        try testing.expect((try test_read_ileb128(i64, &buf)) == -1000);
    }
    {
        var buf: [4]u8 = undefined;
        writeSignedFixed(4, &buf, -10000000);
        try testing.expect((try test_read_ileb128(i64, &buf)) == -10000000);
    }
    {
        var buf: [4]u8 = undefined;
        writeSignedFixed(4, &buf, 10000000);
        try testing.expect((try test_read_ileb128(i64, &buf)) == 10000000);
    }
}

// tests
fn test_read_stream_ileb128(comptime T: type, encoded: []const u8) !T {
    var reader = std.io.fixedBufferStream(encoded);
    return try readIleb128(T, reader.reader());
}

fn test_read_stream_uleb128(comptime T: type, encoded: []const u8) !T {
    var reader = std.io.fixedBufferStream(encoded);
    return try readUleb128(T, reader.reader());
}

fn test_read_ileb128(comptime T: type, encoded: []const u8) !T {
    var reader = std.io.fixedBufferStream(encoded);
    const v1 = try readIleb128(T, reader.reader());
    return v1;
}

fn test_read_uleb128(comptime T: type, encoded: []const u8) !T {
    var reader = std.io.fixedBufferStream(encoded);
    const v1 = try readUleb128(T, reader.reader());
    return v1;
}

fn test_read_ileb128_seq(comptime T: type, comptime N: usize, encoded: []const u8) !void {
    var reader = std.io.fixedBufferStream(encoded);
    var i: usize = 0;
    while (i < N) : (i += 1) {
        _ = try readIleb128(T, reader.reader());
    }
}

fn test_read_uleb128_seq(comptime T: type, comptime N: usize, encoded: []const u8) !void {
    var reader = std.io.fixedBufferStream(encoded);
    var i: usize = 0;
    while (i < N) : (i += 1) {
        _ = try readUleb128(T, reader.reader());
    }
}

test "deserialize signed LEB128" {
    // Truncated
    try testing.expectError(error.EndOfStream, test_read_stream_ileb128(i64, "\x80"));

    // Overflow
    try testing.expectError(error.Overflow, test_read_ileb128(i8, "\x80\x80\x40"));
    try testing.expectError(error.Overflow, test_read_ileb128(i16, "\x80\x80\x80\x40"));
    try testing.expectError(error.Overflow, test_read_ileb128(i32, "\x80\x80\x80\x80\x40"));
    try testing.expectError(error.Overflow, test_read_ileb128(i64, "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x40"));
    try testing.expectError(error.Overflow, test_read_ileb128(i8, "\xff\x7e"));
    try testing.expectError(error.Overflow, test_read_ileb128(i32, "\x80\x80\x80\x80\x08"));
    try testing.expectError(error.Overflow, test_read_ileb128(i64, "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"));

    // Decode SLEB128
    try testing.expect((try test_read_ileb128(i64, "\x00")) == 0);
    try testing.expect((try test_read_ileb128(i64, "\x01")) == 1);
    try testing.expect((try test_read_ileb128(i64, "\x3f")) == 63);
    try testing.expect((try test_read_ileb128(i64, "\x40")) == -64);
    try testing.expect((try test_read_ileb128(i64, "\x41")) == -63);
    try testing.expect((try test_read_ileb128(i64, "\x7f")) == -1);
    try testing.expect((try test_read_ileb128(i64, "\x80\x01")) == 128);
    try testing.expect((try test_read_ileb128(i64, "\x81\x01")) == 129);
    try testing.expect((try test_read_ileb128(i64, "\xff\x7e")) == -129);
    try testing.expect((try test_read_ileb128(i64, "\x80\x7f")) == -128);
    try testing.expect((try test_read_ileb128(i64, "\x81\x7f")) == -127);
    try testing.expect((try test_read_ileb128(i64, "\xc0\x00")) == 64);
    try testing.expect((try test_read_ileb128(i64, "\xc7\x9f\x7f")) == -12345);
    try testing.expect((try test_read_ileb128(i8, "\xff\x7f")) == -1);
    try testing.expect((try test_read_ileb128(i16, "\xff\xff\x7f")) == -1);
    try testing.expect((try test_read_ileb128(i32, "\xff\xff\xff\xff\x7f")) == -1);
    try testing.expect((try test_read_ileb128(i32, "\x80\x80\x80\x80\x78")) == -0x80000000);
    try testing.expect((try test_read_ileb128(i64, "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x7f")) == @as(i64, @bitCast(@as(u64, @intCast(0x8000000000000000)))));
    try testing.expect((try test_read_ileb128(i64, "\x80\x80\x80\x80\x80\x80\x80\x80\x40")) == -0x4000000000000000);
    try testing.expect((try test_read_ileb128(i64, "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x7f")) == -0x8000000000000000);

    // Decode unnormalized SLEB128 with extra padding bytes.
    try testing.expect((try test_read_ileb128(i64, "\x80\x00")) == 0);
    try testing.expect((try test_read_ileb128(i64, "\x80\x80\x00")) == 0);
    try testing.expect((try test_read_ileb128(i64, "\xff\x00")) == 0x7f);
    try testing.expect((try test_read_ileb128(i64, "\xff\x80\x00")) == 0x7f);
    try testing.expect((try test_read_ileb128(i64, "\x80\x81\x00")) == 0x80);
    try testing.expect((try test_read_ileb128(i64, "\x80\x81\x80\x00")) == 0x80);

    // Decode sequence of SLEB128 values
    try test_read_ileb128_seq(i64, 4, "\x81\x01\x3f\x80\x7f\x80\x80\x80\x00");
}

test "deserialize unsigned LEB128" {
    // Truncated
    try testing.expectError(error.EndOfStream, test_read_stream_uleb128(u64, "\x80"));

    // Overflow
    try testing.expectError(error.Overflow, test_read_uleb128(u8, "\x80\x02"));
    try testing.expectError(error.Overflow, test_read_uleb128(u8, "\x80\x80\x40"));
    try testing.expectError(error.Overflow, test_read_uleb128(u16, "\x80\x80\x84"));
    try testing.expectError(error.Overflow, test_read_uleb128(u16, "\x80\x80\x80\x40"));
    try testing.expectError(error.Overflow, test_read_uleb128(u32, "\x80\x80\x80\x80\x90"));
    try testing.expectError(error.Overflow, test_read_uleb128(u32, "\x80\x80\x80\x80\x40"));
    try testing.expectError(error.Overflow, test_read_uleb128(u64, "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x40"));

    // Decode ULEB128
    try testing.expect((try test_read_uleb128(u64, "\x00")) == 0);
    try testing.expect((try test_read_uleb128(u64, "\x01")) == 1);
    try testing.expect((try test_read_uleb128(u64, "\x3f")) == 63);
    try testing.expect((try test_read_uleb128(u64, "\x40")) == 64);
    try testing.expect((try test_read_uleb128(u64, "\x7f")) == 0x7f);
    try testing.expect((try test_read_uleb128(u64, "\x80\x01")) == 0x80);
    try testing.expect((try test_read_uleb128(u64, "\x81\x01")) == 0x81);
    try testing.expect((try test_read_uleb128(u64, "\x90\x01")) == 0x90);
    try testing.expect((try test_read_uleb128(u64, "\xff\x01")) == 0xff);
    try testing.expect((try test_read_uleb128(u64, "\x80\x02")) == 0x100);
    try testing.expect((try test_read_uleb128(u64, "\x81\x02")) == 0x101);
    try testing.expect((try test_read_uleb128(u64, "\x80\xc1\x80\x80\x10")) == 4294975616);
    try testing.expect((try test_read_uleb128(u64, "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01")) == 0x8000000000000000);

    // Decode ULEB128 with extra padding bytes
    try testing.expect((try test_read_uleb128(u64, "\x80\x00")) == 0);
    try testing.expect((try test_read_uleb128(u64, "\x80\x80\x00")) == 0);
    try testing.expect((try test_read_uleb128(u64, "\xff\x00")) == 0x7f);
    try testing.expect((try test_read_uleb128(u64, "\xff\x80\x00")) == 0x7f);
    try testing.expect((try test_read_uleb128(u64, "\x80\x81\x00")) == 0x80);
    try testing.expect((try test_read_uleb128(u64, "\x80\x81\x80\x00")) == 0x80);

    // Decode sequence of ULEB128 values
    try test_read_uleb128_seq(u64, 4, "\x81\x01\x3f\x80\x7f\x80\x80\x80\x00");
}

fn test_write_leb128(value: anytype) !void {
    const T = @TypeOf(value);
    const signedness = @typeInfo(T).int.signedness;
    const t_signed = signedness == .signed;

    const writeStream = if (t_signed) writeIleb128 else writeUleb128;
    const readStream = if (t_signed) readIleb128 else readUleb128;

    // decode to a larger bit size too, to ensure sign extension
    // is working as expected
    const larger_type_bits = ((@typeInfo(T).int.bits + 8) / 8) * 8;
    const B = std.meta.Int(signedness, larger_type_bits);

    const bytes_needed = bn: {
        if (@typeInfo(T).int.bits <= 7) break :bn @as(u16, 1);

        const unused_bits = if (value < 0) @clz(~value) else @clz(value);
        const used_bits: u16 = (@typeInfo(T).int.bits - unused_bits) + @intFromBool(t_signed);
        if (used_bits <= 7) break :bn @as(u16, 1);
        break :bn ((used_bits + 6) / 7);
    };

    const max_groups = if (@typeInfo(T).int.bits == 0) 1 else (@typeInfo(T).int.bits + 6) / 7;

    var buf: [max_groups]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    // stream write
    try writeStream(fbs.writer(), value);
    const w1_pos = fbs.pos;
    try testing.expect(w1_pos == bytes_needed);

    // stream read
    fbs.pos = 0;
    const sr = try readStream(T, fbs.reader());
    try testing.expect(fbs.pos == w1_pos);
    try testing.expect(sr == value);

    // bigger type stream read
    fbs.pos = 0;
    const bsr = try readStream(B, fbs.reader());
    try testing.expect(fbs.pos == w1_pos);
    try testing.expect(bsr == value);
}

test "serialize unsigned LEB128" {
    const max_bits = 18;

    comptime var t = 0;
    inline while (t <= max_bits) : (t += 1) {
        const T = std.meta.Int(.unsigned, t);
        const min = std.math.minInt(T);
        const max = std.math.maxInt(T);
        var i = @as(std.meta.Int(.unsigned, @typeInfo(T).int.bits + 1), min);

        while (i <= max) : (i += 1) try test_write_leb128(@as(T, @intCast(i)));
    }
}

test "serialize signed LEB128" {
    // explicitly test i0 because starting `t` at 0
    // will break the while loop
    try test_write_leb128(@as(i0, 0));

    const max_bits = 18;

    comptime var t = 1;
    inline while (t <= max_bits) : (t += 1) {
        const T = std.meta.Int(.signed, t);
        const min = std.math.minInt(T);
        const max = std.math.maxInt(T);
        var i = @as(std.meta.Int(.signed, @typeInfo(T).int.bits + 1), min);

        while (i <= max) : (i += 1) try test_write_leb128(@as(T, @intCast(i)));
    }
}
//! std.log is a standardized interface for logging which allows for the logging
//! of programs and libraries using this interface to be formatted and filtered
//! by the implementer of the `std.options.logFn` function.
//!
//! Each log message has an associated scope enum, which can be used to give
//! context to the logging. The logging functions in std.log implicitly use a
//! scope of .default.
//!
//! A logging namespace using a custom scope can be created using the
//! std.log.scoped function, passing the scope as an argument; the logging
//! functions in the resulting struct use the provided scope parameter.
//! For example, a library called 'libfoo' might use
//! `const log = std.log.scoped(.libfoo);` to use .libfoo as the scope of its
//! log messages.
//!
//! An example `logFn` might look something like this:
//!
//! ```
//! const std = @import("std");
//!
//! pub const std_options = .{
//!     // Set the log level to info
//!     .log_level = .info,
//!
//!     // Define logFn to override the std implementation
//!     .logFn = myLogFn,
//! };
//!
//! pub fn myLogFn(
//!     comptime level: std.log.Level,
//!     comptime scope: @Type(.enum_literal),
//!     comptime format: []const u8,
//!     args: anytype,
//! ) void {
//!     // Ignore all non-error logging from sources other than
//!     // .my_project, .nice_library and the default
//!     const scope_prefix = "(" ++ switch (scope) {
//!         .my_project, .nice_library, std.log.default_log_scope => @tagName(scope),
//!         else => if (@intFromEnum(level) <= @intFromEnum(std.log.Level.err))
//!             @tagName(scope)
//!         else
//!             return,
//!     } ++ "): ";
//!
//!     const prefix = "[" ++ comptime level.asText() ++ "] " ++ scope_prefix;
//!
//!     // Print the message to stderr, silently ignoring any errors
//!     std.debug.lockStdErr();
//!     defer std.debug.unlockStdErr();
//!     const stderr = std.io.getStdErr().writer();
//!     nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
//! }
//!
//! pub fn main() void {
//!     // Using the default scope:
//!     std.log.debug("A borderline useless debug log message", .{}); // Won't be printed as log_level is .info
//!     std.log.info("Flux capacitor is starting to overheat", .{});
//!
//!     // Using scoped logging:
//!     const my_project_log = std.log.scoped(.my_project);
//!     const nice_library_log = std.log.scoped(.nice_library);
//!     const verbose_lib_log = std.log.scoped(.verbose_lib);
//!
//!     my_project_log.debug("Starting up", .{}); // Won't be printed as log_level is .info
//!     nice_library_log.warn("Something went very wrong, sorry", .{});
//!     verbose_lib_log.warn("Added 1 + 1: {}", .{1 + 1}); // Won't be printed as it gets filtered out by our log function
//! }
//! ```
//! Which produces the following output:
//! ```
//! [info] (default): Flux capacitor is starting to overheat
//! [warning] (nice_library): Something went very wrong, sorry
//! ```

const std = @import("std.zig");
const builtin = @import("builtin");

pub const Level = enum {
    /// Error: something has gone wrong. This might be recoverable or might
    /// be followed by the program exiting.
    err,
    /// Warning: it is uncertain if something has gone wrong or not, but the
    /// circumstances would be worth investigating.
    warn,
    /// Info: general messages about the state of the program.
    info,
    /// Debug: messages only useful for debugging.
    debug,

    /// Returns a string literal of the given level in full text form.
    pub fn asText(comptime self: Level) []const u8 {
        return switch (self) {
            .err => "error",
            .warn => "warning",
            .info => "info",
            .debug => "debug",
        };
    }
};

/// The default log level is based on build mode.
pub const default_level: Level = switch (builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe => .info,
    .ReleaseFast, .ReleaseSmall => .err,
};

const level = std.options.log_level;

pub const ScopeLevel = struct {
    scope: @Type(.enum_literal),
    level: Level,
};

const scope_levels = std.options.log_scope_levels;

fn log(
    comptime message_level: Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime !logEnabled(message_level, scope)) return;

    std.options.logFn(message_level, scope, format, args);
}

/// Determine if a specific log message level and scope combination are enabled for logging.
pub fn logEnabled(comptime message_level: Level, comptime scope: @Type(.enum_literal)) bool {
    inline for (scope_levels) |scope_level| {
        if (scope_level.scope == scope) return @intFromEnum(message_level) <= @intFromEnum(scope_level.level);
    }
    return @intFromEnum(message_level) <= @intFromEnum(level);
}

/// Determine if a specific log message level using the default log scope is enabled for logging.
pub fn defaultLogEnabled(comptime message_level: Level) bool {
    return comptime logEnabled(message_level, default_log_scope);
}

/// The default implementation for the log function, custom log functions may
/// forward log messages to this function.
pub fn defaultLog(
    comptime message_level: Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime message_level.asText();
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const stderr = std.io.getStdErr().writer();
    var bw = std.io.bufferedWriter(stderr);
    const writer = bw.writer();

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    nosuspend {
        writer.print(level_txt ++ prefix2 ++ format ++ "\n", args) catch return;
        bw.flush() catch return;
    }
}

/// Returns a scoped logging namespace that logs all messages using the scope
/// provided here.
pub fn scoped(comptime scope: @Type(.enum_literal)) type {
    return struct {
        /// Log an error message. This log level is intended to be used
        /// when something has gone wrong. This might be recoverable or might
        /// be followed by the program exiting.
        pub fn err(
            comptime format: []const u8,
            args: anytype,
        ) void {
            @branchHint(.cold);
            log(.err, scope, format, args);
        }

        /// Log a warning message. This log level is intended to be used if
        /// it is uncertain whether something has gone wrong or not, but the
        /// circumstances would be worth investigating.
        pub fn warn(
            comptime format: []const u8,
            args: anytype,
        ) void {
            log(.warn, scope, format, args);
        }

        /// Log an info message. This log level is intended to be used for
        /// general messages about the state of the program.
        pub fn info(
            comptime format: []const u8,
            args: anytype,
        ) void {
            log(.info, scope, format, args);
        }

        /// Log a debug message. This log level is intended to be used for
        /// messages which are only useful for debugging.
        pub fn debug(
            comptime format: []const u8,
            args: anytype,
        ) void {
            log(.debug, scope, format, args);
        }
    };
}

pub const default_log_scope = .default;

/// The default scoped logging namespace.
pub const default = scoped(default_log_scope);

/// Log an error message using the default scope. This log level is intended to
/// be used when something has gone wrong. This might be recoverable or might
/// be followed by the program exiting.
pub const err = default.err;

/// Log a warning message using the default scope. This log level is intended
/// to be used if it is uncertain whether something has gone wrong or not, but
/// the circumstances would be worth investigating.
pub const warn = default.warn;

/// Log an info message using the default scope. This log level is intended to
/// be used for general messages about the state of the program.
pub const info = default.info;

/// Log a debug message using the default scope. This log level is intended to
/// be used for messages which are only useful for debugging.
pub const debug = default.debug;
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const io = std.io;
const mem = std.mem;
const meta = std.meta;
const testing = std.testing;

const Allocator = mem.Allocator;

pub const cpu_type_t = c_int;
pub const cpu_subtype_t = c_int;
pub const vm_prot_t = c_int;

pub const mach_header = extern struct {
    magic: u32,
    cputype: cpu_type_t,
    cpusubtype: cpu_subtype_t,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
};

pub const mach_header_64 = extern struct {
    magic: u32 = MH_MAGIC_64,
    cputype: cpu_type_t = 0,
    cpusubtype: cpu_subtype_t = 0,
    filetype: u32 = 0,
    ncmds: u32 = 0,
    sizeofcmds: u32 = 0,
    flags: u32 = 0,
    reserved: u32 = 0,
};

pub const fat_header = extern struct {
    magic: u32,
    nfat_arch: u32,
};

pub const fat_arch = extern struct {
    cputype: cpu_type_t,
    cpusubtype: cpu_subtype_t,
    offset: u32,
    size: u32,
    @"align": u32,
};

pub const load_command = extern struct {
    cmd: LC,
    cmdsize: u32,
};

/// The uuid load command contains a single 128-bit unique random number that
/// identifies an object produced by the static link editor.
pub const uuid_command = extern struct {
    /// LC_UUID
    cmd: LC = .UUID,

    /// sizeof(struct uuid_command)
    cmdsize: u32 = @sizeOf(uuid_command),

    /// the 128-bit uuid
    uuid: [16]u8 = undefined,
};

/// The version_min_command contains the min OS version on which this
/// binary was built to run.
pub const version_min_command = extern struct {
    /// LC_VERSION_MIN_MACOSX or LC_VERSION_MIN_IPHONEOS or LC_VERSION_MIN_WATCHOS or LC_VERSION_MIN_TVOS
    cmd: LC,

    /// sizeof(struct version_min_command)
    cmdsize: u32 = @sizeOf(version_min_command),

    /// X.Y.Z is encoded in nibbles xxxx.yy.zz
    version: u32,

    /// X.Y.Z is encoded in nibbles xxxx.yy.zz
    sdk: u32,
};

/// The source_version_command is an optional load command containing
/// the version of the sources used to build the binary.
pub const source_version_command = extern struct {
    /// LC_SOURCE_VERSION
    cmd: LC = .SOURCE_VERSION,

    /// sizeof(source_version_command)
    cmdsize: u32 = @sizeOf(source_version_command),

    /// A.B.C.D.E packed as a24.b10.c10.d10.e10
    version: u64,
};

/// The build_version_command contains the min OS version on which this
/// binary was built to run for its platform. The list of known platforms and
/// tool values following it.
pub const build_version_command = extern struct {
    /// LC_BUILD_VERSION
    cmd: LC = .BUILD_VERSION,

    /// sizeof(struct build_version_command) plus
    /// ntools * sizeof(struct build_version_command)
    cmdsize: u32,

    /// platform
    platform: PLATFORM,

    /// X.Y.Z is encoded in nibbles xxxx.yy.zz
    minos: u32,

    /// X.Y.Z is encoded in nibbles xxxx.yy.zz
    sdk: u32,

    /// number of tool entries following this
    ntools: u32,
};

pub const build_tool_version = extern struct {
    /// enum for the tool
    tool: TOOL,

    /// version number of the tool
    version: u32,
};

pub const PLATFORM = enum(u32) {
    UNKNOWN = 0,
    ANY = 0xffffffff,
    MACOS = 1,
    IOS = 2,
    TVOS = 3,
    WATCHOS = 4,
    BRIDGEOS = 5,
    MACCATALYST = 6,
    IOSSIMULATOR = 7,
    TVOSSIMULATOR = 8,
    WATCHOSSIMULATOR = 9,
    DRIVERKIT = 10,
    VISIONOS = 11,
    VISIONOSSIMULATOR = 12,
    _,
};

pub const TOOL = enum(u32) {
    CLANG = 0x1,
    SWIFT = 0x2,
    LD = 0x3,
    LLD = 0x4, // LLVM's stock LLD linker
    ZIG = 0x5, // Unofficially Zig
    _,
};

/// The entry_point_command is a replacement for thread_command.
/// It is used for main executables to specify the location (file offset)
/// of main(). If -stack_size was used at link time, the stacksize
/// field will contain the stack size needed for the main thread.
pub const entry_point_command = extern struct {
    /// LC_MAIN only used in MH_EXECUTE filetypes
    cmd: LC = .MAIN,

    /// sizeof(struct entry_point_command)
    cmdsize: u32 = @sizeOf(entry_point_command),

    /// file (__TEXT) offset of main()
    entryoff: u64 = 0,

    /// if not zero, initial stack size
    stacksize: u64 = 0,
};

/// The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
/// "stab" style symbol table information as described in the header files
/// <nlist.h> and <stab.h>.
pub const symtab_command = extern struct {
    /// LC_SYMTAB
    cmd: LC = .SYMTAB,

    /// sizeof(struct symtab_command)
    cmdsize: u32 = @sizeOf(symtab_command),

    /// symbol table offset
    symoff: u32 = 0,

    /// number of symbol table entries
    nsyms: u32 = 0,

    /// string table offset
    stroff: u32 = 0,

    /// string table size in bytes
    strsize: u32 = 0,
};

/// This is the second set of the symbolic information which is used to support
/// the data structures for the dynamically link editor.
///
/// The original set of symbolic information in the symtab_command which contains
/// the symbol and string tables must also be present when this load command is
/// present.  When this load command is present the symbol table is organized
/// into three groups of symbols:
///  local symbols (static and debugging symbols) - grouped by module
///  defined external symbols - grouped by module (sorted by name if not lib)
///  undefined external symbols (sorted by name if MH_BINDATLOAD is not set,
///  and in order the were seen by the static linker if MH_BINDATLOAD is set)
/// In this load command there are offsets and counts to each of the three groups
/// of symbols.
///
/// This load command contains a the offsets and sizes of the following new
/// symbolic information tables:
///  table of contents
///  module table
///  reference symbol table
///  indirect symbol table
/// The first three tables above (the table of contents, module table and
/// reference symbol table) are only present if the file is a dynamically linked
/// shared library.  For executable and object modules, which are files
/// containing only one module, the information that would be in these three
/// tables is determined as follows:
///  table of contents - the defined external symbols are sorted by name
///  module table - the file contains only one module so everything in the file
///  is part of the module.
///  reference symbol table - is the defined and undefined external symbols
///
/// For dynamically linked shared library files this load command also contains
/// offsets and sizes to the pool of relocation entries for all sections
/// separated into two groups:
///  external relocation entries
///  local relocation entries
/// For executable and object modules the relocation entries continue to hang
/// off the section structures.
pub const dysymtab_command = extern struct {
    /// LC_DYSYMTAB
    cmd: LC = .DYSYMTAB,

    /// sizeof(struct dysymtab_command)
    cmdsize: u32 = @sizeOf(dysymtab_command),

    // The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
    // are grouped into the following three groups:
    //    local symbols (further grouped by the module they are from)
    //    defined external symbols (further grouped by the module they are from)
    //    undefined symbols
    //
    // The local symbols are used only for debugging.  The dynamic binding
    // process may have to use them to indicate to the debugger the local
    // symbols for a module that is being bound.
    //
    // The last two groups are used by the dynamic binding process to do the
    // binding (indirectly through the module table and the reference symbol
    // table when this is a dynamically linked shared library file).

    /// index of local symbols
    ilocalsym: u32 = 0,

    /// number of local symbols
    nlocalsym: u32 = 0,

    /// index to externally defined symbols
    iextdefsym: u32 = 0,

    /// number of externally defined symbols
    nextdefsym: u32 = 0,

    /// index to undefined symbols
    iundefsym: u32 = 0,

    /// number of undefined symbols
    nundefsym: u32 = 0,

    // For the for the dynamic binding process to find which module a symbol
    // is defined in the table of contents is used (analogous to the ranlib
    // structure in an archive) which maps defined external symbols to modules
    // they are defined in.  This exists only in a dynamically linked shared
    // library file.  For executable and object modules the defined external
    // symbols are sorted by name and is use as the table of contents.

    /// file offset to table of contents
    tocoff: u32 = 0,

    /// number of entries in table of contents
    ntoc: u32 = 0,

    // To support dynamic binding of "modules" (whole object files) the symbol
    // table must reflect the modules that the file was created from.  This is
    // done by having a module table that has indexes and counts into the merged
    // tables for each module.  The module structure that these two entries
    // refer to is described below.  This exists only in a dynamically linked
    // shared library file.  For executable and object modules the file only
    // contains one module so everything in the file belongs to the module.

    /// file offset to module table
    modtaboff: u32 = 0,

    /// number of module table entries
    nmodtab: u32 = 0,

    // To support dynamic module binding the module structure for each module
    // indicates the external references (defined and undefined) each module
    // makes.  For each module there is an offset and a count into the
    // reference symbol table for the symbols that the module references.
    // This exists only in a dynamically linked shared library file.  For
    // executable and object modules the defined external symbols and the
    // undefined external symbols indicates the external references.

    /// offset to referenced symbol table
    extrefsymoff: u32 = 0,

    /// number of referenced symbol table entries
    nextrefsyms: u32 = 0,

    // The sections that contain "symbol pointers" and "routine stubs" have
    // indexes and (implied counts based on the size of the section and fixed
    // size of the entry) into the "indirect symbol" table for each pointer
    // and stub.  For every section of these two types the index into the
    // indirect symbol table is stored in the section header in the field
    // reserved1.  An indirect symbol table entry is simply a 32bit index into
    // the symbol table to the symbol that the pointer or stub is referring to.
    // The indirect symbol table is ordered to match the entries in the section.

    /// file offset to the indirect symbol table
    indirectsymoff: u32 = 0,

    /// number of indirect symbol table entries
    nindirectsyms: u32 = 0,

    // To support relocating an individual module in a library file quickly the
    // external relocation entries for each module in the library need to be
    // accessed efficiently.  Since the relocation entries can't be accessed
    // through the section headers for a library file they are separated into
    // groups of local and external entries further grouped by module.  In this
    // case the presents of this load command who's extreloff, nextrel,
    // locreloff and nlocrel fields are non-zero indicates that the relocation
    // entries of non-merged sections are not referenced through the section
    // structures (and the reloff and nreloc fields in the section headers are
    // set to zero).
    //
    // Since the relocation entries are not accessed through the section headers
    // this requires the r_address field to be something other than a section
    // offset to identify the item to be relocated.  In this case r_address is
    // set to the offset from the vmaddr of the first LC_SEGMENT command.
    // For MH_SPLIT_SEGS images r_address is set to the the offset from the
    // vmaddr of the first read-write LC_SEGMENT command.
    //
    // The relocation entries are grouped by module and the module table
    // entries have indexes and counts into them for the group of external
    // relocation entries for that the module.
    //
    // For sections that are merged across modules there must not be any
    // remaining external relocation entries for them (for merged sections
    // remaining relocation entries must be local).

    /// offset to external relocation entries
    extreloff: u32 = 0,

    /// number of external relocation entries
    nextrel: u32 = 0,

    // All the local relocation entries are grouped together (they are not
    // grouped by their module since they are only used if the object is moved
    // from its statically link edited address).

    /// offset to local relocation entries
    locreloff: u32 = 0,

    /// number of local relocation entries
    nlocrel: u32 = 0,
};

/// The linkedit_data_command contains the offsets and sizes of a blob
/// of data in the __LINKEDIT segment.
pub const linkedit_data_command = extern struct {
    /// LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS or LC_LINKER_OPTIMIZATION_HINT.
    cmd: LC,

    /// sizeof(struct linkedit_data_command)
    cmdsize: u32 = @sizeOf(linkedit_data_command),

    /// file offset of data in __LINKEDIT segment
    dataoff: u32 = 0,

    /// file size of data in __LINKEDIT segment
    datasize: u32 = 0,
};

/// The dyld_info_command contains the file offsets and sizes of
/// the new compressed form of the information dyld needs to
/// load the image.  This information is used by dyld on Mac OS X
/// 10.6 and later.  All information pointed to by this command
/// is encoded using byte streams, so no endian swapping is needed
/// to interpret it.
pub const dyld_info_command = extern struct {
    /// LC_DYLD_INFO or LC_DYLD_INFO_ONLY
    cmd: LC = .DYLD_INFO_ONLY,

    /// sizeof(struct dyld_info_command)
    cmdsize: u32 = @sizeOf(dyld_info_command),

    // Dyld rebases an image whenever dyld loads it at an address different
    // from its preferred address.  The rebase information is a stream
    // of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
    // Conceptually the rebase information is a table of tuples:
    //    <seg-index, seg-offset, type>
    // The opcodes are a compressed way to encode the table by only
    // encoding when a column changes.  In addition simple patterns
    // like "every n'th offset for m times" can be encoded in a few
    // bytes.

    /// file offset to rebase info
    rebase_off: u32 = 0,

    /// size of rebase info
    rebase_size: u32 = 0,

    // Dyld binds an image during the loading process, if the image
    // requires any pointers to be initialized to symbols in other images.
    // The bind information is a stream of byte sized
    // opcodes whose symbolic names start with BIND_OPCODE_.
    // Conceptually the bind information is a table of tuples:
    //    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
    // The opcodes are a compressed way to encode the table by only
    // encoding when a column changes.  In addition simple patterns
    // like for runs of pointers initialized to the same value can be
    // encoded in a few bytes.

    /// file offset to binding info
    bind_off: u32 = 0,

    /// size of binding info
    bind_size: u32 = 0,

    // Some C++ programs require dyld to unique symbols so that all
    // images in the process use the same copy of some code/data.
    // This step is done after binding. The content of the weak_bind
    // info is an opcode stream like the bind_info.  But it is sorted
    // alphabetically by symbol name.  This enable dyld to walk
    // all images with weak binding information in order and look
    // for collisions.  If there are no collisions, dyld does
    // no updating.  That means that some fixups are also encoded
    // in the bind_info.  For instance, all calls to "operator new"
    // are first bound to libstdc++.dylib using the information
    // in bind_info.  Then if some image overrides operator new
    // that is detected when the weak_bind information is processed
    // and the call to operator new is then rebound.

    /// file offset to weak binding info
    weak_bind_off: u32 = 0,

    /// size of weak binding info
    weak_bind_size: u32 = 0,

    // Some uses of external symbols do not need to be bound immediately.
    // Instead they can be lazily bound on first use.  The lazy_bind
    // are contains a stream of BIND opcodes to bind all lazy symbols.
    // Normal use is that dyld ignores the lazy_bind section when
    // loading an image.  Instead the static linker arranged for the
    // lazy pointer to initially point to a helper function which
    // pushes the offset into the lazy_bind area for the symbol
    // needing to be bound, then jumps to dyld which simply adds
    // the offset to lazy_bind_off to get the information on what
    // to bind.

    /// file offset to lazy binding info
    lazy_bind_off: u32 = 0,

    /// size of lazy binding info
    lazy_bind_size: u32 = 0,

    // The symbols exported by a dylib are encoded in a trie.  This
    // is a compact representation that factors out common prefixes.
    // It also reduces LINKEDIT pages in RAM because it encodes all
    // information (name, address, flags) in one small, contiguous range.
    // The export area is a stream of nodes.  The first node sequentially
    // is the start node for the trie.
    //
    // Nodes for a symbol start with a uleb128 that is the length of
    // the exported symbol information for the string so far.
    // If there is no exported symbol, the node starts with a zero byte.
    // If there is exported info, it follows the length.
    //
    // First is a uleb128 containing flags. Normally, it is followed by
    // a uleb128 encoded offset which is location of the content named
    // by the symbol from the mach_header for the image.  If the flags
    // is EXPORT_SYMBOL_FLAGS_REEXPORT, then following the flags is
    // a uleb128 encoded library ordinal, then a zero terminated
    // UTF8 string.  If the string is zero length, then the symbol
    // is re-export from the specified dylib with the same name.
    // If the flags is EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, then following
    // the flags is two uleb128s: the stub offset and the resolver offset.
    // The stub is used by non-lazy pointers.  The resolver is used
    // by lazy pointers and must be called to get the actual address to use.
    //
    // After the optional exported symbol information is a byte of
    // how many edges (0-255) that this node has leaving it,
    // followed by each edge.
    // Each edge is a zero terminated UTF8 of the addition chars
    // in the symbol, followed by a uleb128 offset for the node that
    // edge points to.

    /// file offset to lazy binding info
    export_off: u32 = 0,

    /// size of lazy binding info
    export_size: u32 = 0,
};

/// A program that uses a dynamic linker contains a dylinker_command to identify
/// the name of the dynamic linker (LC_LOAD_DYLINKER). And a dynamic linker
/// contains a dylinker_command to identify the dynamic linker (LC_ID_DYLINKER).
/// A file can have at most one of these.
/// This struct is also used for the LC_DYLD_ENVIRONMENT load command and contains
/// string for dyld to treat like an environment variable.
pub const dylinker_command = extern struct {
    /// LC_ID_DYLINKER, LC_LOAD_DYLINKER, or LC_DYLD_ENVIRONMENT
    cmd: LC,

    /// includes pathname string
    cmdsize: u32,

    /// A variable length string in a load command is represented by an lc_str
    /// union.  The strings are stored just after the load command structure and
    /// the offset is from the start of the load command structure.  The size
    /// of the string is reflected in the cmdsize field of the load command.
    /// Once again any padded bytes to bring the cmdsize field to a multiple
    /// of 4 bytes must be zero.
    name: u32,
};

/// A dynamically linked shared library (filetype == MH_DYLIB in the mach header)
/// contains a dylib_command (cmd == LC_ID_DYLIB) to identify the library.
/// An object that uses a dynamically linked shared library also contains a
/// dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or
/// LC_REEXPORT_DYLIB) for each library it uses.
pub const dylib_command = extern struct {
    /// LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB, LC_LOAD_DYLIB, LC_REEXPORT_DYLIB
    cmd: LC,

    /// includes pathname string
    cmdsize: u32,

    /// the library identification
    dylib: dylib,
};

/// Dynamically linked shared libraries are identified by two things.  The
/// pathname (the name of the library as found for execution), and the
/// compatibility version number.  The pathname must match and the compatibility
/// number in the user of the library must be greater than or equal to the
/// library being used.  The time stamp is used to record the time a library was
/// built and copied into user so it can be use to determined if the library used
/// at runtime is exactly the same as used to build the program.
pub const dylib = extern struct {
    /// library's pathname (offset pointing at the end of dylib_command)
    name: u32,

    /// library's build timestamp
    timestamp: u32,

    /// library's current version number
    current_version: u32,

    /// library's compatibility version number
    compatibility_version: u32,
};

/// The rpath_command contains a path which at runtime should be added to the current
/// run path used to find @rpath prefixed dylibs.
pub const rpath_command = extern struct {
    /// LC_RPATH
    cmd: LC = .RPATH,

    /// includes string
    cmdsize: u32,

    /// path to add to run path
    path: u32,
};

/// The segment load command indicates that a part of this file is to be
/// mapped into the task's address space.  The size of this segment in memory,
/// vmsize, maybe equal to or larger than the amount to map from this file,
/// filesize.  The file is mapped starting at fileoff to the beginning of
/// the segment in memory, vmaddr.  The rest of the memory of the segment,
/// if any, is allocated zero fill on demand.  The segment's maximum virtual
/// memory protection and initial virtual memory protection are specified
/// by the maxprot and initprot fields.  If the segment has sections then the
/// section structures directly follow the segment command and their size is
/// reflected in cmdsize.
pub const segment_command = extern struct {
    /// LC_SEGMENT
    cmd: LC = .SEGMENT,

    /// includes sizeof section structs
    cmdsize: u32,

    /// segment name
    segname: [16]u8,

    /// memory address of this segment
    vmaddr: u32,

    /// memory size of this segment
    vmsize: u32,

    /// file offset of this segment
    fileoff: u32,

    /// amount to map from the file
    filesize: u32,

    /// maximum VM protection
    maxprot: vm_prot_t,

    /// initial VM protection
    initprot: vm_prot_t,

    /// number of sections in segment
    nsects: u32,
    flags: u32,
};

/// The 64-bit segment load command indicates that a part of this file is to be
/// mapped into a 64-bit task's address space.  If the 64-bit segment has
/// sections then section_64 structures directly follow the 64-bit segment
/// command and their size is reflected in cmdsize.
pub const segment_command_64 = extern struct {
    /// LC_SEGMENT_64
    cmd: LC = .SEGMENT_64,

    /// includes sizeof section_64 structs
    cmdsize: u32,
    // TODO lazy values in stage2
    // cmdsize: u32 = @sizeOf(segment_command_64),

    /// segment name
    segname: [16]u8,

    /// memory address of this segment
    vmaddr: u64 = 0,

    /// memory size of this segment
    vmsize: u64 = 0,

    /// file offset of this segment
    fileoff: u64 = 0,

    /// amount to map from the file
    filesize: u64 = 0,

    /// maximum VM protection
    maxprot: vm_prot_t = PROT.NONE,

    /// initial VM protection
    initprot: vm_prot_t = PROT.NONE,

    /// number of sections in segment
    nsects: u32 = 0,
    flags: u32 = 0,

    pub fn segName(seg: *const segment_command_64) []const u8 {
        return parseName(&seg.segname);
    }

    pub fn isWriteable(seg: segment_command_64) bool {
        return seg.initprot & PROT.WRITE != 0;
    }
};

pub const PROT = struct {
    /// [MC2] no permissions
    pub const NONE: vm_prot_t = 0x00;
    /// [MC2] pages can be read
    pub const READ: vm_prot_t = 0x01;
    /// [MC2] pages can be written
    pub const WRITE: vm_prot_t = 0x02;
    /// [MC2] pages can be executed
    pub const EXEC: vm_prot_t = 0x04;
    /// When a caller finds that they cannot obtain write permission on a
    /// mapped entry, the following flag can be used. The entry will be
    /// made "needs copy" effectively copying the object (using COW),
    /// and write permission will be added to the maximum protections for
    /// the associated entry.
    pub const COPY: vm_prot_t = 0x10;
};

/// A segment is made up of zero or more sections.  Non-MH_OBJECT files have
/// all of their segments with the proper sections in each, and padded to the
/// specified segment alignment when produced by the link editor.  The first
/// segment of a MH_EXECUTE and MH_FVMLIB format file contains the mach_header
/// and load commands of the object file before its first section.  The zero
/// fill sections are always last in their segment (in all formats).  This
/// allows the zeroed segment padding to be mapped into memory where zero fill
/// sections might be. The gigabyte zero fill sections, those with the section
/// type S_GB_ZEROFILL, can only be in a segment with sections of this type.
/// These segments are then placed after all other segments.
///
/// The MH_OBJECT format has all of its sections in one segment for
/// compactness.  There is no padding to a specified segment boundary and the
/// mach_header and load commands are not part of the segment.
///
/// Sections with the same section name, sectname, going into the same segment,
/// segname, are combined by the link editor.  The resulting section is aligned
/// to the maximum alignment of the combined sections and is the new section's
/// alignment.  The combined sections are aligned to their original alignment in
/// the combined section.  Any padded bytes to get the specified alignment are
/// zeroed.
///
/// The format of the relocation entries referenced by the reloff and nreloc
/// fields of the section structure for mach object files is described in the
/// header file <reloc.h>.
pub const section = extern struct {
    /// name of this section
    sectname: [16]u8,

    /// segment this section goes in
    segname: [16]u8,

    /// memory address of this section
    addr: u32,

    /// size in bytes of this section
    size: u32,

    /// file offset of this section
    offset: u32,

    /// section alignment (power of 2)
    @"align": u32,

    /// file offset of relocation entries
    reloff: u32,

    /// number of relocation entries
    nreloc: u32,

    /// flags (section type and attributes
    flags: u32,

    /// reserved (for offset or index)
    reserved1: u32,

    /// reserved (for count or sizeof)
    reserved2: u32,
};

pub const section_64 = extern struct {
    /// name of this section
    sectname: [16]u8,

    /// segment this section goes in
    segname: [16]u8,

    /// memory address of this section
    addr: u64 = 0,

    /// size in bytes of this section
    size: u64 = 0,

    /// file offset of this section
    offset: u32 = 0,

    /// section alignment (power of 2)
    @"align": u32 = 0,

    /// file offset of relocation entries
    reloff: u32 = 0,

    /// number of relocation entries
    nreloc: u32 = 0,

    /// flags (section type and attributes
    flags: u32 = S_REGULAR,

    /// reserved (for offset or index)
    reserved1: u32 = 0,

    /// reserved (for count or sizeof)
    reserved2: u32 = 0,

    /// reserved
    reserved3: u32 = 0,

    pub fn sectName(sect: *const section_64) []const u8 {
        return parseName(&sect.sectname);
    }

    pub fn segName(sect: *const section_64) []const u8 {
        return parseName(&sect.segname);
    }

    pub fn @"type"(sect: section_64) u8 {
        return @as(u8, @truncate(sect.flags & 0xff));
    }

    pub fn attrs(sect: section_64) u32 {
        return sect.flags & 0xffffff00;
    }

    pub fn isCode(sect: section_64) bool {
        const attr = sect.attrs();
        return attr & S_ATTR_PURE_INSTRUCTIONS != 0 or attr & S_ATTR_SOME_INSTRUCTIONS != 0;
    }

    pub fn isZerofill(sect: section_64) bool {
        const tt = sect.type();
        return tt == S_ZEROFILL or tt == S_GB_ZEROFILL or tt == S_THREAD_LOCAL_ZEROFILL;
    }

    pub fn isSymbolStubs(sect: section_64) bool {
        const tt = sect.type();
        return tt == S_SYMBOL_STUBS;
    }

    pub fn isDebug(sect: section_64) bool {
        return sect.attrs() & S_ATTR_DEBUG != 0;
    }

    pub fn isDontDeadStrip(sect: section_64) bool {
        return sect.attrs() & S_ATTR_NO_DEAD_STRIP != 0;
    }

    pub fn isDontDeadStripIfReferencesLive(sect: section_64) bool {
        return sect.attrs() & S_ATTR_LIVE_SUPPORT != 0;
    }
};

fn parseName(name: *const [16]u8) []const u8 {
    const len = mem.indexOfScalar(u8, name, @as(u8, 0)) orelse name.len;
    return name[0..len];
}

pub const nlist = extern struct {
    n_strx: u32,
    n_type: u8,
    n_sect: u8,
    n_desc: i16,
    n_value: u32,
};

pub const nlist_64 = extern struct {
    n_strx: u32,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,

    pub fn stab(sym: nlist_64) bool {
        return N_STAB & sym.n_type != 0;
    }

    pub fn pext(sym: nlist_64) bool {
        return N_PEXT & sym.n_type != 0;
    }

    pub fn ext(sym: nlist_64) bool {
        return N_EXT & sym.n_type != 0;
    }

    pub fn sect(sym: nlist_64) bool {
        const type_ = N_TYPE & sym.n_type;
        return type_ == N_SECT;
    }

    pub fn undf(sym: nlist_64) bool {
        const type_ = N_TYPE & sym.n_type;
        return type_ == N_UNDF;
    }

    pub fn indr(sym: nlist_64) bool {
        const type_ = N_TYPE & sym.n_type;
        return type_ == N_INDR;
    }

    pub fn abs(sym: nlist_64) bool {
        const type_ = N_TYPE & sym.n_type;
        return type_ == N_ABS;
    }

    pub fn weakDef(sym: nlist_64) bool {
        return sym.n_desc & N_WEAK_DEF != 0;
    }

    pub fn weakRef(sym: nlist_64) bool {
        return sym.n_desc & N_WEAK_REF != 0;
    }

    pub fn discarded(sym: nlist_64) bool {
        return sym.n_desc & N_DESC_DISCARDED != 0;
    }

    pub fn noDeadStrip(sym: nlist_64) bool {
        return sym.n_desc & N_NO_DEAD_STRIP != 0;
    }

    pub fn tentative(sym: nlist_64) bool {
        if (!sym.undf()) return false;
        return sym.n_value != 0;
    }
};

/// Format of a relocation entry of a Mach-O file.  Modified from the 4.3BSD
/// format.  The modifications from the original format were changing the value
/// of the r_symbolnum field for "local" (r_extern == 0) relocation entries.
/// This modification is required to support symbols in an arbitrary number of
/// sections not just the three sections (text, data and bss) in a 4.3BSD file.
/// Also the last 4 bits have had the r_type tag added to them.
pub const relocation_info = packed struct {
    /// offset in the section to what is being relocated
    r_address: i32,

    /// symbol index if r_extern == 1 or section ordinal if r_extern == 0
    r_symbolnum: u24,

    /// was relocated pc relative already
    r_pcrel: u1,

    /// 0=byte, 1=word, 2=long, 3=quad
    r_length: u2,

    /// does not include value of sym referenced
    r_extern: u1,

    /// if not 0, machine specific relocation type
    r_type: u4,
};

/// After MacOS X 10.1 when a new load command is added that is required to be
/// understood by the dynamic linker for the image to execute properly the
/// LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
/// linker sees such a load command it it does not understand will issue a
/// "unknown load command required for execution" error and refuse to use the
/// image.  Other load commands without this bit that are not understood will
/// simply be ignored.
pub const LC_REQ_DYLD = 0x80000000;

pub const LC = enum(u32) {
    /// No load command - invalid
    NONE = 0x0,

    /// segment of this file to be mapped
    SEGMENT = 0x1,

    /// link-edit stab symbol table info
    SYMTAB = 0x2,

    /// link-edit gdb symbol table info (obsolete)
    SYMSEG = 0x3,

    /// thread
    THREAD = 0x4,

    /// unix thread (includes a stack)
    UNIXTHREAD = 0x5,

    /// load a specified fixed VM shared library
    LOADFVMLIB = 0x6,

    /// fixed VM shared library identification
    IDFVMLIB = 0x7,

    /// object identification info (obsolete)
    IDENT = 0x8,

    /// fixed VM file inclusion (internal use)
    FVMFILE = 0x9,

    /// prepage command (internal use)
    PREPAGE = 0xa,

    /// dynamic link-edit symbol table info
    DYSYMTAB = 0xb,

    /// load a dynamically linked shared library
    LOAD_DYLIB = 0xc,

    /// dynamically linked shared lib ident
    ID_DYLIB = 0xd,

    /// load a dynamic linker
    LOAD_DYLINKER = 0xe,

    /// dynamic linker identification
    ID_DYLINKER = 0xf,

    /// modules prebound for a dynamically
    PREBOUND_DYLIB = 0x10,

    /// image routines
    ROUTINES = 0x11,

    /// sub framework
    SUB_FRAMEWORK = 0x12,

    /// sub umbrella
    SUB_UMBRELLA = 0x13,

    /// sub client
    SUB_CLIENT = 0x14,

    /// sub library
    SUB_LIBRARY = 0x15,

    /// two-level namespace lookup hints
    TWOLEVEL_HINTS = 0x16,

    /// prebind checksum
    PREBIND_CKSUM = 0x17,

    /// load a dynamically linked shared library that is allowed to be missing
    /// (all symbols are weak imported).
    LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD,

    /// 64-bit segment of this file to be mapped
    SEGMENT_64 = 0x19,

    /// 64-bit image routines
    ROUTINES_64 = 0x1a,

    /// the uuid
    UUID = 0x1b,

    /// runpath additions
    RPATH = 0x1c | LC_REQ_DYLD,

    /// local of code signature
    CODE_SIGNATURE = 0x1d,

    /// local of info to split segments
    SEGMENT_SPLIT_INFO = 0x1e,

    /// load and re-export dylib
    REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD,

    /// delay load of dylib until first use
    LAZY_LOAD_DYLIB = 0x20,

    /// encrypted segment information
    ENCRYPTION_INFO = 0x21,

    /// compressed dyld information
    DYLD_INFO = 0x22,

    /// compressed dyld information only
    DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD,

    /// load upward dylib
    LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD,

    /// build for MacOSX min OS version
    VERSION_MIN_MACOSX = 0x24,

    /// build for iPhoneOS min OS version
    VERSION_MIN_IPHONEOS = 0x25,

    /// compressed table of function start addresses
    FUNCTION_STARTS = 0x26,

    /// string for dyld to treat like environment variable
    DYLD_ENVIRONMENT = 0x27,

    /// replacement for LC_UNIXTHREAD
    MAIN = 0x28 | LC_REQ_DYLD,

    /// table of non-instructions in __text
    DATA_IN_CODE = 0x29,

    /// source version used to build binary
    SOURCE_VERSION = 0x2A,

    /// Code signing DRs copied from linked dylibs
    DYLIB_CODE_SIGN_DRS = 0x2B,

    /// 64-bit encrypted segment information
    ENCRYPTION_INFO_64 = 0x2C,

    /// linker options in MH_OBJECT files
    LINKER_OPTION = 0x2D,

    /// optimization hints in MH_OBJECT files
    LINKER_OPTIMIZATION_HINT = 0x2E,

    /// build for AppleTV min OS version
    VERSION_MIN_TVOS = 0x2F,

    /// build for Watch min OS version
    VERSION_MIN_WATCHOS = 0x30,

    /// arbitrary data included within a Mach-O file
    NOTE = 0x31,

    /// build for platform min OS version
    BUILD_VERSION = 0x32,

    /// used with linkedit_data_command, payload is trie
    DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD,

    /// used with linkedit_data_command
    DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD,

    _,
};

/// the mach magic number
pub const MH_MAGIC = 0xfeedface;

/// NXSwapInt(MH_MAGIC)
pub const MH_CIGAM = 0xcefaedfe;

/// the 64-bit mach magic number
pub const MH_MAGIC_64 = 0xfeedfacf;

/// NXSwapInt(MH_MAGIC_64)
pub const MH_CIGAM_64 = 0xcffaedfe;

/// relocatable object file
pub const MH_OBJECT = 0x1;

/// demand paged executable file
pub const MH_EXECUTE = 0x2;

/// fixed VM shared library file
pub const MH_FVMLIB = 0x3;

/// core file
pub const MH_CORE = 0x4;

/// preloaded executable file
pub const MH_PRELOAD = 0x5;

/// dynamically bound shared library
pub const MH_DYLIB = 0x6;

/// dynamic link editor
pub const MH_DYLINKER = 0x7;

/// dynamically bound bundle file
pub const MH_BUNDLE = 0x8;

/// shared library stub for static linking only, no section contents
pub const MH_DYLIB_STUB = 0x9;

/// companion file with only debug sections
pub const MH_DSYM = 0xa;

/// x86_64 kexts
pub const MH_KEXT_BUNDLE = 0xb;

// Constants for the flags field of the mach_header

/// the object file has no undefined references
pub const MH_NOUNDEFS = 0x1;

/// the object file is the output of an incremental link against a base file and can't be link edited again
pub const MH_INCRLINK = 0x2;

/// the object file is input for the dynamic linker and can't be statically link edited again
pub const MH_DYLDLINK =```
