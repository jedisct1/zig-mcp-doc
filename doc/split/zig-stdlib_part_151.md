```
 options: SerializeContainerOptions,
            ) Writer.Error!Tuple {
                try self.fieldPrefix();
                return self.container.serializer.beginTuple(options);
            }

            /// Print a field prefix. This prints any necessary commas, and whitespace as
            /// configured. Useful if you want to serialize the field value yourself.
            pub fn fieldPrefix(self: *Tuple) Writer.Error!void {
                try self.container.fieldPrefix(null);
            }
        };

        /// Writes ZON structs field by field.
        pub const Struct = struct {
            container: Container,

            fn begin(parent: *Self, options: SerializeContainerOptions) Writer.Error!Struct {
                return .{
                    .container = try Container.begin(parent, .named, options),
                };
            }

            /// Finishes serializing the struct.
            ///
            /// Prints a trailing comma as configured when appropriate, and the closing bracket.
            pub fn end(self: *Struct) Writer.Error!void {
                try self.container.end();
                self.* = undefined;
            }

            /// Serialize a field. Equivalent to calling `fieldPrefix` followed by `value`.
            pub fn field(
                self: *Struct,
                name: []const u8,
                val: anytype,
                options: ValueOptions,
            ) Writer.Error!void {
                try self.container.field(name, val, options);
            }

            /// Serialize a field. Equivalent to calling `fieldPrefix` followed by `valueMaxDepth`.
            pub fn fieldMaxDepth(
                self: *Struct,
                name: []const u8,
                val: anytype,
                options: ValueOptions,
                depth: usize,
            ) (Writer.Error || error{ExceededMaxDepth})!void {
                try self.container.fieldMaxDepth(name, val, options, depth);
            }

            /// Serialize a field. Equivalent to calling `fieldPrefix` followed by
            /// `valueArbitraryDepth`.
            pub fn fieldArbitraryDepth(
                self: *Struct,
                name: []const u8,
                val: anytype,
                options: ValueOptions,
            ) Writer.Error!void {
                try self.container.fieldArbitraryDepth(name, val, options);
            }

            /// Starts a field with a struct as a value. Returns the struct.
            pub fn beginStructField(
                self: *Struct,
                name: []const u8,
                options: SerializeContainerOptions,
            ) Writer.Error!Struct {
                try self.fieldPrefix(name);
                return self.container.serializer.beginStruct(options);
            }

            /// Starts a field with a tuple as a value. Returns the tuple.
            pub fn beginTupleField(
                self: *Struct,
                name: []const u8,
                options: SerializeContainerOptions,
            ) Writer.Error!Tuple {
                try self.fieldPrefix(name);
                return self.container.serializer.beginTuple(options);
            }

            /// Print a field prefix. This prints any necessary commas, the field name (escaped if
            /// necessary) and whitespace as configured. Useful if you want to serialize the field
            /// value yourself.
            pub fn fieldPrefix(self: *Struct, name: []const u8) Writer.Error!void {
                try self.container.fieldPrefix(name);
            }
        };

        const Container = struct {
            const FieldStyle = enum { named, anon };

            serializer: *Self,
            field_style: FieldStyle,
            options: SerializeContainerOptions,
            empty: bool,

            fn begin(
                sz: *Self,
                field_style: FieldStyle,
                options: SerializeContainerOptions,
            ) Writer.Error!Container {
                if (options.shouldWrap()) sz.indent_level +|= 1;
                try sz.writer.writeAll(".{");
                return .{
                    .serializer = sz,
                    .field_style = field_style,
                    .options = options,
                    .empty = true,
                };
            }

            fn end(self: *Container) Writer.Error!void {
                if (self.options.shouldWrap()) self.serializer.indent_level -|= 1;
                if (!self.empty) {
                    if (self.options.shouldWrap()) {
                        if (self.serializer.options.whitespace) {
                            try self.serializer.writer.writeByte(',');
                        }
                        try self.serializer.newline();
                        try self.serializer.indent();
                    } else if (!self.shouldElideSpaces()) {
                        try self.serializer.space();
                    }
                }
                try self.serializer.writer.writeByte('}');
                self.* = undefined;
            }

            fn fieldPrefix(self: *Container, name: ?[]const u8) Writer.Error!void {
                if (!self.empty) {
                    try self.serializer.writer.writeByte(',');
                }
                self.empty = false;
                if (self.options.shouldWrap()) {
                    try self.serializer.newline();
                } else if (!self.shouldElideSpaces()) {
                    try self.serializer.space();
                }
                if (self.options.shouldWrap()) try self.serializer.indent();
                if (name) |n| {
                    try self.serializer.ident(n);
                    try self.serializer.space();
                    try self.serializer.writer.writeByte('=');
                    try self.serializer.space();
                }
            }

            fn field(
                self: *Container,
                name: ?[]const u8,
                val: anytype,
                options: ValueOptions,
            ) Writer.Error!void {
                comptime assert(!typeIsRecursive(@TypeOf(val)));
                try self.fieldArbitraryDepth(name, val, options);
            }

            fn fieldMaxDepth(
                self: *Container,
                name: ?[]const u8,
                val: anytype,
                options: ValueOptions,
                depth: usize,
            ) (Writer.Error || error{ExceededMaxDepth})!void {
                try checkValueDepth(val, depth);
                try self.fieldArbitraryDepth(name, val, options);
            }

            fn fieldArbitraryDepth(
                self: *Container,
                name: ?[]const u8,
                val: anytype,
                options: ValueOptions,
            ) Writer.Error!void {
                try self.fieldPrefix(name);
                try self.serializer.valueArbitraryDepth(val, options);
            }

            fn shouldElideSpaces(self: *const Container) bool {
                return switch (self.options.whitespace_style) {
                    .fields => |fields| self.field_style != .named and fields == 1,
                    else => false,
                };
            }
        };
    };
}

/// Creates a new `Serializer` with the given writer and options.
pub fn serializer(writer: anytype, options: SerializerOptions) Serializer(@TypeOf(writer)) {
    return .init(writer, options);
}

fn expectSerializeEqual(
    expected: []const u8,
    value: anytype,
    options: SerializeOptions,
) !void {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try serialize(value, options, buf.writer());
    try std.testing.expectEqualStrings(expected, buf.items);
}

test "std.zon stringify whitespace, high level API" {
    try expectSerializeEqual(".{}", .{}, .{});
    try expectSerializeEqual(".{}", .{}, .{ .whitespace = false });

    try expectSerializeEqual(".{1}", .{1}, .{});
    try expectSerializeEqual(".{1}", .{1}, .{ .whitespace = false });

    try expectSerializeEqual(".{1}", @as([1]u32, .{1}), .{});
    try expectSerializeEqual(".{1}", @as([1]u32, .{1}), .{ .whitespace = false });

    try expectSerializeEqual(".{1}", @as([]const u32, &.{1}), .{});
    try expectSerializeEqual(".{1}", @as([]const u32, &.{1}), .{ .whitespace = false });

    try expectSerializeEqual(".{ .x = 1 }", .{ .x = 1 }, .{});
    try expectSerializeEqual(".{.x=1}", .{ .x = 1 }, .{ .whitespace = false });

    try expectSerializeEqual(".{ 1, 2 }", .{ 1, 2 }, .{});
    try expectSerializeEqual(".{1,2}", .{ 1, 2 }, .{ .whitespace = false });

    try expectSerializeEqual(".{ 1, 2 }", @as([2]u32, .{ 1, 2 }), .{});
    try expectSerializeEqual(".{1,2}", @as([2]u32, .{ 1, 2 }), .{ .whitespace = false });

    try expectSerializeEqual(".{ 1, 2 }", @as([]const u32, &.{ 1, 2 }), .{});
    try expectSerializeEqual(".{1,2}", @as([]const u32, &.{ 1, 2 }), .{ .whitespace = false });

    try expectSerializeEqual(".{ .x = 1, .y = 2 }", .{ .x = 1, .y = 2 }, .{});
    try expectSerializeEqual(".{.x=1,.y=2}", .{ .x = 1, .y = 2 }, .{ .whitespace = false });

    try expectSerializeEqual(
        \\.{
        \\    1,
        \\    2,
        \\    3,
        \\}
    , .{ 1, 2, 3 }, .{});
    try expectSerializeEqual(".{1,2,3}", .{ 1, 2, 3 }, .{ .whitespace = false });

    try expectSerializeEqual(
        \\.{
        \\    1,
        \\    2,
        \\    3,
        \\}
    , @as([3]u32, .{ 1, 2, 3 }), .{});
    try expectSerializeEqual(".{1,2,3}", @as([3]u32, .{ 1, 2, 3 }), .{ .whitespace = false });

    try expectSerializeEqual(
        \\.{
        \\    1,
        \\    2,
        \\    3,
        \\}
    , @as([]const u32, &.{ 1, 2, 3 }), .{});
    try expectSerializeEqual(
        ".{1,2,3}",
        @as([]const u32, &.{ 1, 2, 3 }),
        .{ .whitespace = false },
    );

    try expectSerializeEqual(
        \\.{
        \\    .x = 1,
        \\    .y = 2,
        \\    .z = 3,
        \\}
    , .{ .x = 1, .y = 2, .z = 3 }, .{});
    try expectSerializeEqual(
        ".{.x=1,.y=2,.z=3}",
        .{ .x = 1, .y = 2, .z = 3 },
        .{ .whitespace = false },
    );

    const Union = union(enum) { a: bool, b: i32, c: u8 };

    try expectSerializeEqual(".{ .b = 1 }", Union{ .b = 1 }, .{});
    try expectSerializeEqual(".{.b=1}", Union{ .b = 1 }, .{ .whitespace = false });

    // Nested indentation where outer object doesn't wrap
    try expectSerializeEqual(
        \\.{ .inner = .{
        \\    1,
        \\    2,
        \\    3,
        \\} }
    , .{ .inner = .{ 1, 2, 3 } }, .{});

    const UnionWithVoid = union(enum) { a, b: void, c: u8 };

    try expectSerializeEqual(
        \\.a
    , UnionWithVoid.a, .{});
}

test "std.zon stringify whitespace, low level API" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    inline for (.{ true, false }) |whitespace| {
        sz.options = .{ .whitespace = whitespace };

        // Empty containers
        {
            var container = try sz.beginStruct(.{});
            try container.end();
            try std.testing.expectEqualStrings(".{}", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{});
            try container.end();
            try std.testing.expectEqualStrings(".{}", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .wrap = false } });
            try container.end();
            try std.testing.expectEqualStrings(".{}", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .wrap = false } });
            try container.end();
            try std.testing.expectEqualStrings(".{}", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .fields = 0 } });
            try container.end();
            try std.testing.expectEqualStrings(".{}", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .fields = 0 } });
            try container.end();
            try std.testing.expectEqualStrings(".{}", buf.items);
            buf.clearRetainingCapacity();
        }

        // Size 1
        {
            var container = try sz.beginStruct(.{});
            try container.field("a", 1, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    .a = 1,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{});
            try container.field(1, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    1,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .wrap = false } });
            try container.field("a", 1, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ .a = 1 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            // We get extra spaces here, since we didn't know up front that there would only be one
            // field.
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .wrap = false } });
            try container.field(1, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ 1 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .fields = 1 } });
            try container.field("a", 1, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ .a = 1 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .fields = 1 } });
            try container.field(1, .{});
            try container.end();
            try std.testing.expectEqualStrings(".{1}", buf.items);
            buf.clearRetainingCapacity();
        }

        // Size 2
        {
            var container = try sz.beginStruct(.{});
            try container.field("a", 1, .{});
            try container.field("b", 2, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    .a = 1,
                    \\    .b = 2,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1,.b=2}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{});
            try container.field(1, .{});
            try container.field(2, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    1,
                    \\    2,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1,2}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .wrap = false } });
            try container.field("a", 1, .{});
            try container.field("b", 2, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ .a = 1, .b = 2 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1,.b=2}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .wrap = false } });
            try container.field(1, .{});
            try container.field(2, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ 1, 2 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1,2}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .fields = 2 } });
            try container.field("a", 1, .{});
            try container.field("b", 2, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ .a = 1, .b = 2 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1,.b=2}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .fields = 2 } });
            try container.field(1, .{});
            try container.field(2, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ 1, 2 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1,2}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        // Size 3
        {
            var container = try sz.beginStruct(.{});
            try container.field("a", 1, .{});
            try container.field("b", 2, .{});
            try container.field("c", 3, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    .a = 1,
                    \\    .b = 2,
                    \\    .c = 3,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1,.b=2,.c=3}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{});
            try container.field(1, .{});
            try container.field(2, .{});
            try container.field(3, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    1,
                    \\    2,
                    \\    3,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1,2,3}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .wrap = false } });
            try container.field("a", 1, .{});
            try container.field("b", 2, .{});
            try container.field("c", 3, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ .a = 1, .b = 2, .c = 3 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1,.b=2,.c=3}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .wrap = false } });
            try container.field(1, .{});
            try container.field(2, .{});
            try container.field(3, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(".{ 1, 2, 3 }", buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1,2,3}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .fields = 3 } });
            try container.field("a", 1, .{});
            try container.field("b", 2, .{});
            try container.field("c", 3, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    .a = 1,
                    \\    .b = 2,
                    \\    .c = 3,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{.a=1,.b=2,.c=3}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            var container = try sz.beginTuple(.{ .whitespace_style = .{ .fields = 3 } });
            try container.field(1, .{});
            try container.field(2, .{});
            try container.field(3, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{
                    \\    1,
                    \\    2,
                    \\    3,
                    \\}
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(".{1,2,3}", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        // Nested objects where the outer container doesn't wrap but the inner containers do
        {
            var container = try sz.beginStruct(.{ .whitespace_style = .{ .wrap = false } });
            try container.field("first", .{ 1, 2, 3 }, .{});
            try container.field("second", .{ 4, 5, 6 }, .{});
            try container.end();
            if (whitespace) {
                try std.testing.expectEqualStrings(
                    \\.{ .first = .{
                    \\    1,
                    \\    2,
                    \\    3,
                    \\}, .second = .{
                    \\    4,
                    \\    5,
                    \\    6,
                    \\} }
                , buf.items);
            } else {
                try std.testing.expectEqualStrings(
                    ".{.first=.{1,2,3},.second=.{4,5,6}}",
                    buf.items,
                );
            }
            buf.clearRetainingCapacity();
        }
    }
}

test "std.zon stringify utf8 codepoints" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    // Printable ASCII
    try sz.int('a');
    try std.testing.expectEqualStrings("97", buf.items);
    buf.clearRetainingCapacity();

    try sz.codePoint('a');
    try std.testing.expectEqualStrings("'a'", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('a', .{ .emit_codepoint_literals = .always });
    try std.testing.expectEqualStrings("'a'", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('a', .{ .emit_codepoint_literals = .printable_ascii });
    try std.testing.expectEqualStrings("'a'", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('a', .{ .emit_codepoint_literals = .never });
    try std.testing.expectEqualStrings("97", buf.items);
    buf.clearRetainingCapacity();

    // Short escaped codepoint
    try sz.int('\n');
    try std.testing.expectEqualStrings("10", buf.items);
    buf.clearRetainingCapacity();

    try sz.codePoint('\n');
    try std.testing.expectEqualStrings("'\\n'", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('\n', .{ .emit_codepoint_literals = .always });
    try std.testing.expectEqualStrings("'\\n'", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('\n', .{ .emit_codepoint_literals = .printable_ascii });
    try std.testing.expectEqualStrings("10", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('\n', .{ .emit_codepoint_literals = .never });
    try std.testing.expectEqualStrings("10", buf.items);
    buf.clearRetainingCapacity();

    // Large codepoint
    try sz.int('⚡');
    try std.testing.expectEqualStrings("9889", buf.items);
    buf.clearRetainingCapacity();

    try sz.codePoint('⚡');
    try std.testing.expectEqualStrings("'\\xe2\\x9a\\xa1'", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('⚡', .{ .emit_codepoint_literals = .always });
    try std.testing.expectEqualStrings("'\\xe2\\x9a\\xa1'", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('⚡', .{ .emit_codepoint_literals = .printable_ascii });
    try std.testing.expectEqualStrings("9889", buf.items);
    buf.clearRetainingCapacity();

    try sz.value('⚡', .{ .emit_codepoint_literals = .never });
    try std.testing.expectEqualStrings("9889", buf.items);
    buf.clearRetainingCapacity();

    // Invalid codepoint
    try std.testing.expectError(error.InvalidCodepoint, sz.codePoint(0x110000 + 1));

    try sz.int(0x110000 + 1);
    try std.testing.expectEqualStrings("1114113", buf.items);
    buf.clearRetainingCapacity();

    try sz.value(0x110000 + 1, .{ .emit_codepoint_literals = .always });
    try std.testing.expectEqualStrings("1114113", buf.items);
    buf.clearRetainingCapacity();

    try sz.value(0x110000 + 1, .{ .emit_codepoint_literals = .printable_ascii });
    try std.testing.expectEqualStrings("1114113", buf.items);
    buf.clearRetainingCapacity();

    try sz.value(0x110000 + 1, .{ .emit_codepoint_literals = .never });
    try std.testing.expectEqualStrings("1114113", buf.items);
    buf.clearRetainingCapacity();

    // Valid codepoint, not a codepoint type
    try sz.value(@as(u22, 'a'), .{ .emit_codepoint_literals = .always });
    try std.testing.expectEqualStrings("97", buf.items);
    buf.clearRetainingCapacity();

    try sz.value(@as(u22, 'a'), .{ .emit_codepoint_literals = .printable_ascii });
    try std.testing.expectEqualStrings("97", buf.items);
    buf.clearRetainingCapacity();

    try sz.value(@as(i32, 'a'), .{ .emit_codepoint_literals = .never });
    try std.testing.expectEqualStrings("97", buf.items);
    buf.clearRetainingCapacity();

    // Make sure value options are passed to children
    try sz.value(.{ .c = '⚡' }, .{ .emit_codepoint_literals = .always });
    try std.testing.expectEqualStrings(".{ .c = '\\xe2\\x9a\\xa1' }", buf.items);
    buf.clearRetainingCapacity();

    try sz.value(.{ .c = '⚡' }, .{ .emit_codepoint_literals = .never });
    try std.testing.expectEqualStrings(".{ .c = 9889 }", buf.items);
    buf.clearRetainingCapacity();
}

test "std.zon stringify strings" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    // Minimal case
    try sz.string("abc⚡\n");
    try std.testing.expectEqualStrings("\"abc\\xe2\\x9a\\xa1\\n\"", buf.items);
    buf.clearRetainingCapacity();

    try sz.tuple("abc⚡\n", .{});
    try std.testing.expectEqualStrings(
        \\.{
        \\    97,
        \\    98,
        \\    99,
        \\    226,
        \\    154,
        \\    161,
        \\    10,
        \\}
    , buf.items);
    buf.clearRetainingCapacity();

    try sz.value("abc⚡\n", .{});
    try std.testing.expectEqualStrings("\"abc\\xe2\\x9a\\xa1\\n\"", buf.items);
    buf.clearRetainingCapacity();

    try sz.value("abc⚡\n", .{ .emit_strings_as_containers = true });
    try std.testing.expectEqualStrings(
        \\.{
        \\    97,
        \\    98,
        \\    99,
        \\    226,
        \\    154,
        \\    161,
        \\    10,
        \\}
    , buf.items);
    buf.clearRetainingCapacity();

    // Value options are inherited by children
    try sz.value(.{ .str = "abc" }, .{});
    try std.testing.expectEqualStrings(".{ .str = \"abc\" }", buf.items);
    buf.clearRetainingCapacity();

    try sz.value(.{ .str = "abc" }, .{ .emit_strings_as_containers = true });
    try std.testing.expectEqualStrings(
        \\.{ .str = .{
        \\    97,
        \\    98,
        \\    99,
        \\} }
    , buf.items);
    buf.clearRetainingCapacity();

    // Arrays (rather than pointers to arrays) of u8s are not considered strings, so that data can
    // round trip correctly.
    try sz.value("abc".*, .{});
    try std.testing.expectEqualStrings(
        \\.{
        \\    97,
        \\    98,
        \\    99,
        \\}
    , buf.items);
    buf.clearRetainingCapacity();
}

test "std.zon stringify multiline strings" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    inline for (.{ true, false }) |whitespace| {
        sz.options.whitespace = whitespace;

        {
            try sz.multilineString("", .{ .top_level = true });
            try std.testing.expectEqualStrings("\\\\", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            try sz.multilineString("abc⚡", .{ .top_level = true });
            try std.testing.expectEqualStrings("\\\\abc⚡", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            try sz.multilineString("abc⚡\ndef", .{ .top_level = true });
            try std.testing.expectEqualStrings("\\\\abc⚡\n\\\\def", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            try sz.multilineString("abc⚡\r\ndef", .{ .top_level = true });
            try std.testing.expectEqualStrings("\\\\abc⚡\n\\\\def", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            try sz.multilineString("\nabc⚡", .{ .top_level = true });
            try std.testing.expectEqualStrings("\\\\\n\\\\abc⚡", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            try sz.multilineString("\r\nabc⚡", .{ .top_level = true });
            try std.testing.expectEqualStrings("\\\\\n\\\\abc⚡", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            try sz.multilineString("abc\ndef", .{});
            if (whitespace) {
                try std.testing.expectEqualStrings("\n\\\\abc\n\\\\def\n", buf.items);
            } else {
                try std.testing.expectEqualStrings("\\\\abc\n\\\\def\n", buf.items);
            }
            buf.clearRetainingCapacity();
        }

        {
            const str: []const u8 = &.{ 'a', '\r', 'c' };
            try sz.string(str);
            try std.testing.expectEqualStrings("\"a\\rc\"", buf.items);
            buf.clearRetainingCapacity();
        }

        {
            try std.testing.expectError(
                error.InnerCarriageReturn,
                sz.multilineString(@as([]const u8, &.{ 'a', '\r', 'c' }), .{}),
            );
            try std.testing.expectError(
                error.InnerCarriageReturn,
                sz.multilineString(@as([]const u8, &.{ 'a', '\r', 'c', '\n' }), .{}),
            );
            try std.testing.expectError(
                error.InnerCarriageReturn,
                sz.multilineString(@as([]const u8, &.{ 'a', '\r', 'c', '\r', '\n' }), .{}),
            );
            try std.testing.expectEqualStrings("", buf.items);
            buf.clearRetainingCapacity();
        }
    }
}

test "std.zon stringify skip default fields" {
    const Struct = struct {
        x: i32 = 2,
        y: i8,
        z: u32 = 4,
        inner1: struct { a: u8 = 'z', b: u8 = 'y', c: u8 } = .{
            .a = '1',
            .b = '2',
            .c = '3',
        },
        inner2: struct { u8, u8, u8 } = .{
            'a',
            'b',
            'c',
        },
        inner3: struct { u8, u8, u8 } = .{
            'a',
            'b',
            'c',
        },
    };

    // Not skipping if not set
    try expectSerializeEqual(
        \\.{
        \\    .x = 2,
        \\    .y = 3,
        \\    .z = 4,
        \\    .inner1 = .{
        \\        .a = '1',
        \\        .b = '2',
        \\        .c = '3',
        \\    },
        \\    .inner2 = .{
        \\        'a',
        \\        'b',
        \\        'c',
        \\    },
        \\    .inner3 = .{
        \\        'a',
        \\        'b',
        \\        'd',
        \\    },
        \\}
    ,
        Struct{
            .y = 3,
            .z = 4,
            .inner1 = .{
                .a = '1',
                .b = '2',
                .c = '3',
            },
            .inner3 = .{
                'a',
                'b',
                'd',
            },
        },
        .{ .emit_codepoint_literals = .always },
    );

    // Top level defaults
    try expectSerializeEqual(
        \\.{ .y = 3, .inner3 = .{
        \\    'a',
        \\    'b',
        \\    'd',
        \\} }
    ,
        Struct{
            .y = 3,
            .z = 4,
            .inner1 = .{
                .a = '1',
                .b = '2',
                .c = '3',
            },
            .inner3 = .{
                'a',
                'b',
                'd',
            },
        },
        .{
            .emit_default_optional_fields = false,
            .emit_codepoint_literals = .always,
        },
    );

    // Inner types having defaults, and defaults changing the number of fields affecting the
    // formatting
    try expectSerializeEqual(
        \\.{
        \\    .y = 3,
        \\    .inner1 = .{ .b = '2', .c = '3' },
        \\    .inner3 = .{
        \\        'a',
        \\        'b',
        \\        'd',
        \\    },
        \\}
    ,
        Struct{
            .y = 3,
            .z = 4,
            .inner1 = .{
                .a = 'z',
                .b = '2',
                .c = '3',
            },
            .inner3 = .{
                'a',
                'b',
                'd',
            },
        },
        .{
            .emit_default_optional_fields = false,
            .emit_codepoint_literals = .always,
        },
    );

    const DefaultStrings = struct {
        foo: []const u8 = "abc",
    };
    try expectSerializeEqual(
        \\.{}
    ,
        DefaultStrings{ .foo = "abc" },
        .{ .emit_default_optional_fields = false },
    );
    try expectSerializeEqual(
        \\.{ .foo = "abcd" }
    ,
        DefaultStrings{ .foo = "abcd" },
        .{ .emit_default_optional_fields = false },
    );
}

test "std.zon depth limits" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    const Recurse = struct { r: []const @This() };

    // Normal operation
    try serializeMaxDepth(.{ 1, .{ 2, 3 } }, .{}, buf.writer(), 16);
    try std.testing.expectEqualStrings(".{ 1, .{ 2, 3 } }", buf.items);
    buf.clearRetainingCapacity();

    try serializeArbitraryDepth(.{ 1, .{ 2, 3 } }, .{}, buf.writer());
    try std.testing.expectEqualStrings(".{ 1, .{ 2, 3 } }", buf.items);
    buf.clearRetainingCapacity();

    // Max depth failing on non recursive type
    try std.testing.expectError(
        error.ExceededMaxDepth,
        serializeMaxDepth(.{ 1, .{ 2, .{ 3, 4 } } }, .{}, buf.writer(), 3),
    );
    try std.testing.expectEqualStrings("", buf.items);
    buf.clearRetainingCapacity();

    // Max depth passing on recursive type
    {
        const maybe_recurse = Recurse{ .r = &.{} };
        try serializeMaxDepth(maybe_recurse, .{}, buf.writer(), 2);
        try std.testing.expectEqualStrings(".{ .r = .{} }", buf.items);
        buf.clearRetainingCapacity();
    }

    // Unchecked passing on recursive type
    {
        const maybe_recurse = Recurse{ .r = &.{} };
        try serializeArbitraryDepth(maybe_recurse, .{}, buf.writer());
        try std.testing.expectEqualStrings(".{ .r = .{} }", buf.items);
        buf.clearRetainingCapacity();
    }

    // Max depth failing on recursive type due to depth
    {
        var maybe_recurse = Recurse{ .r = &.{} };
        maybe_recurse.r = &.{.{ .r = &.{} }};
        try std.testing.expectError(
            error.ExceededMaxDepth,
            serializeMaxDepth(maybe_recurse, .{}, buf.writer(), 2),
        );
        try std.testing.expectEqualStrings("", buf.items);
        buf.clearRetainingCapacity();
    }

    // Same but for a slice
    {
        var temp: [1]Recurse = .{.{ .r = &.{} }};
        const maybe_recurse: []const Recurse = &temp;

        try std.testing.expectError(
            error.ExceededMaxDepth,
            serializeMaxDepth(maybe_recurse, .{}, buf.writer(), 2),
        );
        try std.testing.expectEqualStrings("", buf.items);
        buf.clearRetainingCapacity();

        var sz = serializer(buf.writer(), .{});

        try std.testing.expectError(
            error.ExceededMaxDepth,
            sz.tupleMaxDepth(maybe_recurse, .{}, 2),
        );
        try std.testing.expectEqualStrings("", buf.items);
        buf.clearRetainingCapacity();

        try sz.tupleArbitraryDepth(maybe_recurse, .{});
        try std.testing.expectEqualStrings(".{.{ .r = .{} }}", buf.items);
        buf.clearRetainingCapacity();
    }

    // A slice succeeding
    {
        var temp: [1]Recurse = .{.{ .r = &.{} }};
        const maybe_recurse: []const Recurse = &temp;

        try serializeMaxDepth(maybe_recurse, .{}, buf.writer(), 3);
        try std.testing.expectEqualStrings(".{.{ .r = .{} }}", buf.items);
        buf.clearRetainingCapacity();

        var sz = serializer(buf.writer(), .{});

        try sz.tupleMaxDepth(maybe_recurse, .{}, 3);
        try std.testing.expectEqualStrings(".{.{ .r = .{} }}", buf.items);
        buf.clearRetainingCapacity();

        try sz.tupleArbitraryDepth(maybe_recurse, .{});
        try std.testing.expectEqualStrings(".{.{ .r = .{} }}", buf.items);
        buf.clearRetainingCapacity();
    }

    // Max depth failing on recursive type due to recursion
    {
        var temp: [1]Recurse = .{.{ .r = &.{} }};
        temp[0].r = &temp;
        const maybe_recurse: []const Recurse = &temp;

        try std.testing.expectError(
            error.ExceededMaxDepth,
            serializeMaxDepth(maybe_recurse, .{}, buf.writer(), 128),
        );
        try std.testing.expectEqualStrings("", buf.items);
        buf.clearRetainingCapacity();

        var sz = serializer(buf.writer(), .{});
        try std.testing.expectError(
            error.ExceededMaxDepth,
            sz.tupleMaxDepth(maybe_recurse, .{}, 128),
        );
        try std.testing.expectEqualStrings("", buf.items);
        buf.clearRetainingCapacity();
    }

    // Max depth on other parts of the lower level API
    {
        var sz = serializer(buf.writer(), .{});

        const maybe_recurse: []const Recurse = &.{};

        try std.testing.expectError(error.ExceededMaxDepth, sz.valueMaxDepth(1, .{}, 0));
        try sz.valueMaxDepth(2, .{}, 1);
        try sz.value(3, .{});
        try sz.valueArbitraryDepth(maybe_recurse, .{});

        var s = try sz.beginStruct(.{});
        try std.testing.expectError(error.ExceededMaxDepth, s.fieldMaxDepth("a", 1, .{}, 0));
        try s.fieldMaxDepth("b", 4, .{}, 1);
        try s.field("c", 5, .{});
        try s.fieldArbitraryDepth("d", maybe_recurse, .{});
        try s.end();

        var t = try sz.beginTuple(.{});
        try std.testing.expectError(error.ExceededMaxDepth, t.fieldMaxDepth(1, .{}, 0));
        try t.fieldMaxDepth(6, .{}, 1);
        try t.field(7, .{});
        try t.fieldArbitraryDepth(maybe_recurse, .{});
        try t.end();

        var a = try sz.beginTuple(.{});
        try std.testing.expectError(error.ExceededMaxDepth, a.fieldMaxDepth(1, .{}, 0));
        try a.fieldMaxDepth(8, .{}, 1);
        try a.field(9, .{});
        try a.fieldArbitraryDepth(maybe_recurse, .{});
        try a.end();

        try std.testing.expectEqualStrings(
            \\23.{}.{
            \\    .b = 4,
            \\    .c = 5,
            \\    .d = .{},
            \\}.{
            \\    6,
            \\    7,
            \\    .{},
            \\}.{
            \\    8,
            \\    9,
            \\    .{},
            \\}
        , buf.items);
    }
}

test "std.zon stringify primitives" {
    // Issue: https://github.com/ziglang/zig/issues/20880
    if (@import("builtin").zig_backend == .stage2_c) return error.SkipZigTest;

    try expectSerializeEqual(
        \\.{
        \\    .a = 1.5,
        \\    .b = 0.3333333333333333333333333333333333,
        \\    .c = 3.1415926535897932384626433832795028,
        \\    .d = 0,
        \\    .e = 0,
        \\    .f = -0.0,
        \\    .g = inf,
        \\    .h = -inf,
        \\    .i = nan,
        \\}
    ,
        .{
            .a = @as(f128, 1.5), // Make sure explicit f128s work
            .b = 1.0 / 3.0,
            .c = std.math.pi,
            .d = 0.0,
            .e = -0.0,
            .f = @as(f128, -0.0),
            .g = std.math.inf(f32),
            .h = -std.math.inf(f32),
            .i = std.math.nan(f32),
        },
        .{},
    );

    try expectSerializeEqual(
        \\.{
        \\    .a = 18446744073709551616,
        \\    .b = -18446744073709551616,
        \\    .c = 680564733841876926926749214863536422912,
        \\    .d = -680564733841876926926749214863536422912,
        \\    .e = 0,
        \\}
    ,
        .{
            .a = 18446744073709551616,
            .b = -18446744073709551616,
            .c = 680564733841876926926749214863536422912,
            .d = -680564733841876926926749214863536422912,
            .e = 0,
        },
        .{},
    );

    try expectSerializeEqual(
        \\.{
        \\    .a = true,
        \\    .b = false,
        \\    .c = .foo,
        \\    .e = null,
        \\}
    ,
        .{
            .a = true,
            .b = false,
            .c = .foo,
            .e = null,
        },
        .{},
    );

    const Struct = struct { x: f32, y: f32 };
    try expectSerializeEqual(
        ".{ .a = .{ .x = 1, .y = 2 }, .b = null }",
        .{
            .a = @as(?Struct, .{ .x = 1, .y = 2 }),
            .b = @as(?Struct, null),
        },
        .{},
    );

    const E = enum(u8) {
        foo,
        bar,
    };
    try expectSerializeEqual(
        ".{ .a = .foo, .b = .foo }",
        .{
            .a = .foo,
            .b = E.foo,
        },
        .{},
    );
}

test "std.zon stringify ident" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    try expectSerializeEqual(".{ .a = 0 }", .{ .a = 0 }, .{});
    try sz.ident("a");
    try std.testing.expectEqualStrings(".a", buf.items);
    buf.clearRetainingCapacity();

    try sz.ident("foo_1");
    try std.testing.expectEqualStrings(".foo_1", buf.items);
    buf.clearRetainingCapacity();

    try sz.ident("_foo_1");
    try std.testing.expectEqualStrings("._foo_1", buf.items);
    buf.clearRetainingCapacity();

    try sz.ident("foo bar");
    try std.testing.expectEqualStrings(".@\"foo bar\"", buf.items);
    buf.clearRetainingCapacity();

    try sz.ident("1foo");
    try std.testing.expectEqualStrings(".@\"1foo\"", buf.items);
    buf.clearRetainingCapacity();

    try sz.ident("var");
    try std.testing.expectEqualStrings(".@\"var\"", buf.items);
    buf.clearRetainingCapacity();

    try sz.ident("true");
    try std.testing.expectEqualStrings(".true", buf.items);
    buf.clearRetainingCapacity();

    try sz.ident("_");
    try std.testing.expectEqualStrings("._", buf.items);
    buf.clearRetainingCapacity();

    const Enum = enum {
        @"foo bar",
    };
    try expectSerializeEqual(".{ .@\"var\" = .@\"foo bar\", .@\"1\" = .@\"foo bar\" }", .{
        .@"var" = .@"foo bar",
        .@"1" = Enum.@"foo bar",
    }, .{});
}

test "std.zon stringify as tuple" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    // Tuples
    try sz.tuple(.{ 1, 2 }, .{});
    try std.testing.expectEqualStrings(".{ 1, 2 }", buf.items);
    buf.clearRetainingCapacity();

    // Slice
    try sz.tuple(@as([]const u8, &.{ 1, 2 }), .{});
    try std.testing.expectEqualStrings(".{ 1, 2 }", buf.items);
    buf.clearRetainingCapacity();

    // Array
    try sz.tuple([2]u8{ 1, 2 }, .{});
    try std.testing.expectEqualStrings(".{ 1, 2 }", buf.items);
    buf.clearRetainingCapacity();
}

test "std.zon stringify as float" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    // Comptime float
    try sz.float(2.5);
    try std.testing.expectEqualStrings("2.5", buf.items);
    buf.clearRetainingCapacity();

    // Sized float
    try sz.float(@as(f32, 2.5));
    try std.testing.expectEqualStrings("2.5", buf.items);
    buf.clearRetainingCapacity();
}

test "std.zon stringify vector" {
    try expectSerializeEqual(
        \\.{
        \\    .{},
        \\    .{
        \\        true,
        \\        false,
        \\        true,
        \\    },
        \\    .{},
        \\    .{
        \\        1.5,
        \\        2.5,
        \\        3.5,
        \\    },
        \\    .{},
        \\    .{
        \\        2,
        \\        4,
        \\        6,
        \\    },
        \\    .{ 1, 2 },
        \\    .{
        \\        3,
        \\        4,
        \\        null,
        \\    },
        \\}
    ,
        .{
            @Vector(0, bool){},
            @Vector(3, bool){ true, false, true },
            @Vector(0, f32){},
            @Vector(3, f32){ 1.5, 2.5, 3.5 },
            @Vector(0, u8){},
            @Vector(3, u8){ 2, 4, 6 },
            @Vector(2, *const u8){ &1, &2 },
            @Vector(3, ?*const u8){ &3, &4, null },
        },
        .{},
    );
}

test "std.zon pointers" {
    // Primitive with varying levels of pointers
    try expectSerializeEqual("10", &@as(u32, 10), .{});
    try expectSerializeEqual("10", &&@as(u32, 10), .{});
    try expectSerializeEqual("10", &&&@as(u32, 10), .{});

    // Primitive optional with varying levels of pointers
    try expectSerializeEqual("10", @as(?*const u32, &10), .{});
    try expectSerializeEqual("null", @as(?*const u32, null), .{});
    try expectSerializeEqual("10", @as(?*const u32, &10), .{});
    try expectSerializeEqual("null", @as(*const ?u32, &null), .{});

    try expectSerializeEqual("10", @as(?*const *const u32, &&10), .{});
    try expectSerializeEqual("null", @as(?*const *const u32, null), .{});
    try expectSerializeEqual("10", @as(*const ?*const u32, &&10), .{});
    try expectSerializeEqual("null", @as(*const ?*const u32, &null), .{});
    try expectSerializeEqual("10", @as(*const *const ?u32, &&10), .{});
    try expectSerializeEqual("null", @as(*const *const ?u32, &&null), .{});

    try expectSerializeEqual(".{ 1, 2 }", &[2]u32{ 1, 2 }, .{});

    // A complicated type with nested internal pointers and string allocations
    {
        const Inner = struct {
            f1: *const ?*const []const u8,
            f2: *const ?*const []const u8,
        };
        const Outer = struct {
            f1: *const ?*const Inner,
            f2: *const ?*const Inner,
        };
        const val: ?*const Outer = &.{
            .f1 = &&.{
                .f1 = &null,
                .f2 = &&"foo",
            },
            .f2 = &null,
        };

        try expectSerializeEqual(
            \\.{ .f1 = .{ .f1 = null, .f2 = "foo" }, .f2 = null }
        , val, .{});
    }
}

test "std.zon tuple/struct field" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var sz = serializer(buf.writer(), .{});

    // Test on structs
    {
        var root = try sz.beginStruct(.{});
        {
            var tuple = try root.beginTupleField("foo", .{});
            try tuple.field(0, .{});
            try tuple.field(1, .{});
            try tuple.end();
        }
        {
            var strct = try root.beginStructField("bar", .{});
            try strct.field("a", 0, .{});
            try strct.field("b", 1, .{});
            try strct.end();
        }
        try root.end();

        try std.testing.expectEqualStrings(
            \\.{
            \\    .foo = .{
            \\        0,
            \\        1,
            \\    },
            \\    .bar = .{
            \\        .a = 0,
            \\        .b = 1,
            \\    },
            \\}
        , buf.items);
        buf.clearRetainingCapacity();
    }

    // Test on tuples
    {
        var root = try sz.beginTuple(.{});
        {
            var tuple = try root.beginTupleField(.{});
            try tuple.field(0, .{});
            try tuple.field(1, .{});
            try tuple.end();
        }
        {
            var strct = try root.beginStructField(.{});
            try strct.field("a", 0, .{});
            try strct.field("b", 1, .{});
            try strct.end();
        }
        try root.end();

        try std.testing.expectEqualStrings(
            \\.{
            \\    .{
            \\        0,
            \\        1,
            \\    },
            \\    .{
            \\        .a = 0,
            \\        .b = 1,
            \\    },
            \\}
        , buf.items);
        buf.clearRetainingCapacity();
    }
}
```
