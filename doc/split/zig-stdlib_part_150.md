```
efer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Union, gpa, ".{.x=1}", &diag, .{}),
        );
        try std.testing.expectFmt("1:6: error: expected type 'void'\n", "{}", .{diag});
    }

    // Extra field
    {
        const Union = union { x: f32, y: bool };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Union, gpa, ".{.x = 1.5, .y = true}", &diag, .{}),
        );
        try std.testing.expectFmt("1:2: error: expected union\n", "{}", .{diag});
    }

    // No fields
    {
        const Union = union { x: f32, y: bool };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Union, gpa, ".{}", &diag, .{}),
        );
        try std.testing.expectFmt("1:2: error: expected union\n", "{}", .{diag});
    }

    // Enum literals cannot coerce into untagged unions
    {
        const Union = union { x: void };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(Union, gpa, ".x", &diag, .{}));
        try std.testing.expectFmt("1:2: error: expected union\n", "{}", .{diag});
    }

    // Unknown field for enum literal coercion
    {
        const Union = union(enum) { x: void };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(Union, gpa, ".y", &diag, .{}));
        try std.testing.expectFmt(
            \\1:2: error: unexpected field 'y'
            \\1:2: note: supported: 'x'
            \\
        ,
            "{}",
            .{diag},
        );
    }

    // Non void field for enum literal coercion
    {
        const Union = union(enum) { x: f32 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(Union, gpa, ".x", &diag, .{}));
        try std.testing.expectFmt("1:2: error: expected union\n", "{}", .{diag});
    }
}

test "std.zon structs" {
    const gpa = std.testing.allocator;

    // Structs (various sizes tested since they're parsed differently)
    {
        const Vec0 = struct {};
        const Vec1 = struct { x: f32 };
        const Vec2 = struct { x: f32, y: f32 };
        const Vec3 = struct { x: f32, y: f32, z: f32 };

        const zero = try fromSlice(Vec0, gpa, ".{}", null, .{});
        try std.testing.expectEqual(Vec0{}, zero);

        const one = try fromSlice(Vec1, gpa, ".{.x = 1.2}", null, .{});
        try std.testing.expectEqual(Vec1{ .x = 1.2 }, one);

        const two = try fromSlice(Vec2, gpa, ".{.x = 1.2, .y = 3.4}", null, .{});
        try std.testing.expectEqual(Vec2{ .x = 1.2, .y = 3.4 }, two);

        const three = try fromSlice(Vec3, gpa, ".{.x = 1.2, .y = 3.4, .z = 5.6}", null, .{});
        try std.testing.expectEqual(Vec3{ .x = 1.2, .y = 3.4, .z = 5.6 }, three);
    }

    // Deep free (structs and arrays)
    {
        const Foo = struct { bar: []const u8, baz: []const []const u8 };

        const parsed = try fromSlice(
            Foo,
            gpa,
            ".{.bar = \"qux\", .baz = .{\"a\", \"b\"}}",
            null,
            .{},
        );
        defer free(gpa, parsed);
        try std.testing.expectEqualDeep(Foo{ .bar = "qux", .baz = &.{ "a", "b" } }, parsed);
    }

    // Unknown field
    {
        const Vec2 = struct { x: f32, y: f32 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Vec2, gpa, ".{.x=1.5, .z=2.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            \\1:12: error: unexpected field 'z'
            \\1:12: note: supported: 'x', 'y'
            \\
        ,
            "{}",
            .{diag},
        );
    }

    // Duplicate field
    {
        const Vec2 = struct { x: f32, y: f32 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Vec2, gpa, ".{.x=1.5, .x=2.5, .x=3.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            \\1:4: error: duplicate struct field name
            \\1:12: note: duplicate name here
            \\
        , "{}", .{diag});
    }

    // Ignore unknown fields
    {
        const Vec2 = struct { x: f32, y: f32 = 2.0 };
        const parsed = try fromSlice(Vec2, gpa, ".{ .x = 1.0, .z = 3.0 }", null, .{
            .ignore_unknown_fields = true,
        });
        try std.testing.expectEqual(Vec2{ .x = 1.0, .y = 2.0 }, parsed);
    }

    // Unknown field when struct has no fields (regression test)
    {
        const Vec2 = struct {};
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Vec2, gpa, ".{.x=1.5, .z=2.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            \\1:4: error: unexpected field 'x'
            \\1:4: note: none expected
            \\
        , "{}", .{diag});
    }

    // Missing field
    {
        const Vec2 = struct { x: f32, y: f32 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Vec2, gpa, ".{.x=1.5}", &diag, .{}),
        );
        try std.testing.expectFmt("1:2: error: missing required field y\n", "{}", .{diag});
    }

    // Default field
    {
        const Vec2 = struct { x: f32, y: f32 = 1.5 };
        const parsed = try fromSlice(Vec2, gpa, ".{.x = 1.2}", null, .{});
        try std.testing.expectEqual(Vec2{ .x = 1.2, .y = 1.5 }, parsed);
    }

    // Comptime field
    {
        const Vec2 = struct { x: f32, comptime y: f32 = 1.5 };
        const parsed = try fromSlice(Vec2, gpa, ".{.x = 1.2}", null, .{});
        try std.testing.expectEqual(Vec2{ .x = 1.2, .y = 1.5 }, parsed);
    }

    // Comptime field assignment
    {
        const Vec2 = struct { x: f32, comptime y: f32 = 1.5 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        const parsed = fromSlice(Vec2, gpa, ".{.x = 1.2, .y = 1.5}", &diag, .{});
        try std.testing.expectError(error.ParseZon, parsed);
        try std.testing.expectFmt(
            \\1:18: error: cannot initialize comptime field
            \\
        , "{}", .{diag});
    }

    // Enum field (regression test, we were previously getting the field name in an
    // incorrect way that broke for enum values)
    {
        const Vec0 = struct { x: enum { x } };
        const parsed = try fromSlice(Vec0, gpa, ".{ .x = .x }", null, .{});
        try std.testing.expectEqual(Vec0{ .x = .x }, parsed);
    }

    // Enum field and struct field with @
    {
        const Vec0 = struct { @"x x": enum { @"x x" } };
        const parsed = try fromSlice(Vec0, gpa, ".{ .@\"x x\" = .@\"x x\" }", null, .{});
        try std.testing.expectEqual(Vec0{ .@"x x" = .@"x x" }, parsed);
    }

    // Type expressions are not allowed
    {
        // Structs
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            const parsed = fromSlice(struct {}, gpa, "Empty{}", &diag, .{});
            try std.testing.expectError(error.ParseZon, parsed);
            try std.testing.expectFmt(
                \\1:1: error: types are not available in ZON
                \\1:1: note: replace the type with '.'
                \\
            , "{}", .{diag});
        }

        // Arrays
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            const parsed = fromSlice([3]u8, gpa, "[3]u8{1, 2, 3}", &diag, .{});
            try std.testing.expectError(error.ParseZon, parsed);
            try std.testing.expectFmt(
                \\1:1: error: types are not available in ZON
                \\1:1: note: replace the type with '.'
                \\
            , "{}", .{diag});
        }

        // Slices
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            const parsed = fromSlice([]u8, gpa, "[]u8{1, 2, 3}", &diag, .{});
            try std.testing.expectError(error.ParseZon, parsed);
            try std.testing.expectFmt(
                \\1:1: error: types are not available in ZON
                \\1:1: note: replace the type with '.'
                \\
            , "{}", .{diag});
        }

        // Tuples
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            const parsed = fromSlice(
                struct { u8, u8, u8 },
                gpa,
                "Tuple{1, 2, 3}",
                &diag,
                .{},
            );
            try std.testing.expectError(error.ParseZon, parsed);
            try std.testing.expectFmt(
                \\1:1: error: types are not available in ZON
                \\1:1: note: replace the type with '.'
                \\
            , "{}", .{diag});
        }

        // Nested
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            const parsed = fromSlice(struct {}, gpa, ".{ .x = Tuple{1, 2, 3} }", &diag, .{});
            try std.testing.expectError(error.ParseZon, parsed);
            try std.testing.expectFmt(
                \\1:9: error: types are not available in ZON
                \\1:9: note: replace the type with '.'
                \\
            , "{}", .{diag});
        }
    }
}

test "std.zon tuples" {
    const gpa = std.testing.allocator;

    // Structs (various sizes tested since they're parsed differently)
    {
        const Tuple0 = struct {};
        const Tuple1 = struct { f32 };
        const Tuple2 = struct { f32, bool };
        const Tuple3 = struct { f32, bool, u8 };

        const zero = try fromSlice(Tuple0, gpa, ".{}", null, .{});
        try std.testing.expectEqual(Tuple0{}, zero);

        const one = try fromSlice(Tuple1, gpa, ".{1.2}", null, .{});
        try std.testing.expectEqual(Tuple1{1.2}, one);

        const two = try fromSlice(Tuple2, gpa, ".{1.2, true}", null, .{});
        try std.testing.expectEqual(Tuple2{ 1.2, true }, two);

        const three = try fromSlice(Tuple3, gpa, ".{1.2, false, 3}", null, .{});
        try std.testing.expectEqual(Tuple3{ 1.2, false, 3 }, three);
    }

    // Deep free
    {
        const Tuple = struct { []const u8, []const u8 };
        const parsed = try fromSlice(Tuple, gpa, ".{\"hello\", \"world\"}", null, .{});
        defer free(gpa, parsed);
        try std.testing.expectEqualDeep(Tuple{ "hello", "world" }, parsed);
    }

    // Extra field
    {
        const Tuple = struct { f32, bool };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Tuple, gpa, ".{0.5, true, 123}", &diag, .{}),
        );
        try std.testing.expectFmt("1:14: error: index 2 outside of tuple length 2\n", "{}", .{diag});
    }

    // Extra field
    {
        const Tuple = struct { f32, bool };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Tuple, gpa, ".{0.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:2: error: missing tuple field with index 1\n",
            "{}",
            .{diag},
        );
    }

    // Tuple with unexpected field names
    {
        const Tuple = struct { f32 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Tuple, gpa, ".{.foo = 10.0}", &diag, .{}),
        );
        try std.testing.expectFmt("1:2: error: expected tuple\n", "{}", .{diag});
    }

    // Struct with missing field names
    {
        const Struct = struct { foo: f32 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Struct, gpa, ".{10.0}", &diag, .{}),
        );
        try std.testing.expectFmt("1:2: error: expected struct\n", "{}", .{diag});
    }

    // Comptime field
    {
        const Vec2 = struct { f32, comptime f32 = 1.5 };
        const parsed = try fromSlice(Vec2, gpa, ".{ 1.2 }", null, .{});
        try std.testing.expectEqual(Vec2{ 1.2, 1.5 }, parsed);
    }

    // Comptime field assignment
    {
        const Vec2 = struct { f32, comptime f32 = 1.5 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        const parsed = fromSlice(Vec2, gpa, ".{ 1.2, 1.5}", &diag, .{});
        try std.testing.expectError(error.ParseZon, parsed);
        try std.testing.expectFmt(
            \\1:9: error: cannot initialize comptime field
            \\
        , "{}", .{diag});
    }
}

// Test sizes 0 to 3 since small sizes get parsed differently
test "std.zon arrays and slices" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/20881

    const gpa = std.testing.allocator;

    // Literals
    {
        // Arrays
        {
            const zero = try fromSlice([0]u8, gpa, ".{}", null, .{});
            try std.testing.expectEqualSlices(u8, &@as([0]u8, .{}), &zero);

            const one = try fromSlice([1]u8, gpa, ".{'a'}", null, .{});
            try std.testing.expectEqualSlices(u8, &@as([1]u8, .{'a'}), &one);

            const two = try fromSlice([2]u8, gpa, ".{'a', 'b'}", null, .{});
            try std.testing.expectEqualSlices(u8, &@as([2]u8, .{ 'a', 'b' }), &two);

            const two_comma = try fromSlice([2]u8, gpa, ".{'a', 'b',}", null, .{});
            try std.testing.expectEqualSlices(u8, &@as([2]u8, .{ 'a', 'b' }), &two_comma);

            const three = try fromSlice([3]u8, gpa, ".{'a', 'b', 'c'}", null, .{});
            try std.testing.expectEqualSlices(u8, &.{ 'a', 'b', 'c' }, &three);

            const sentinel = try fromSlice([3:'z']u8, gpa, ".{'a', 'b', 'c'}", null, .{});
            const expected_sentinel: [3:'z']u8 = .{ 'a', 'b', 'c' };
            try std.testing.expectEqualSlices(u8, &expected_sentinel, &sentinel);
        }

        // Slice literals
        {
            const zero = try fromSlice([]const u8, gpa, ".{}", null, .{});
            defer free(gpa, zero);
            try std.testing.expectEqualSlices(u8, @as([]const u8, &.{}), zero);

            const one = try fromSlice([]u8, gpa, ".{'a'}", null, .{});
            defer free(gpa, one);
            try std.testing.expectEqualSlices(u8, &.{'a'}, one);

            const two = try fromSlice([]const u8, gpa, ".{'a', 'b'}", null, .{});
            defer free(gpa, two);
            try std.testing.expectEqualSlices(u8, &.{ 'a', 'b' }, two);

            const two_comma = try fromSlice([]const u8, gpa, ".{'a', 'b',}", null, .{});
            defer free(gpa, two_comma);
            try std.testing.expectEqualSlices(u8, &.{ 'a', 'b' }, two_comma);

            const three = try fromSlice([]u8, gpa, ".{'a', 'b', 'c'}", null, .{});
            defer free(gpa, three);
            try std.testing.expectEqualSlices(u8, &.{ 'a', 'b', 'c' }, three);

            const sentinel = try fromSlice([:'z']const u8, gpa, ".{'a', 'b', 'c'}", null, .{});
            defer free(gpa, sentinel);
            const expected_sentinel: [:'z']const u8 = &.{ 'a', 'b', 'c' };
            try std.testing.expectEqualSlices(u8, expected_sentinel, sentinel);
        }
    }

    // Deep free
    {
        // Arrays
        {
            const parsed = try fromSlice([1][]const u8, gpa, ".{\"abc\"}", null, .{});
            defer free(gpa, parsed);
            const expected: [1][]const u8 = .{"abc"};
            try std.testing.expectEqualDeep(expected, parsed);
        }

        // Slice literals
        {
            const parsed = try fromSlice([]const []const u8, gpa, ".{\"abc\"}", null, .{});
            defer free(gpa, parsed);
            const expected: []const []const u8 = &.{"abc"};
            try std.testing.expectEqualDeep(expected, parsed);
        }
    }

    // Sentinels and alignment
    {
        // Arrays
        {
            const sentinel = try fromSlice([1:2]u8, gpa, ".{1}", null, .{});
            try std.testing.expectEqual(@as(usize, 1), sentinel.len);
            try std.testing.expectEqual(@as(u8, 1), sentinel[0]);
            try std.testing.expectEqual(@as(u8, 2), sentinel[1]);
        }

        // Slice literals
        {
            const sentinel = try fromSlice([:2]align(4) u8, gpa, ".{1}", null, .{});
            defer free(gpa, sentinel);
            try std.testing.expectEqual(@as(usize, 1), sentinel.len);
            try std.testing.expectEqual(@as(u8, 1), sentinel[0]);
            try std.testing.expectEqual(@as(u8, 2), sentinel[1]);
        }
    }

    // Expect 0 find 3
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([0]u8, gpa, ".{'a', 'b', 'c'}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:3: error: index 0 outside of array of length 0\n",
            "{}",
            .{diag},
        );
    }

    // Expect 1 find 2
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([1]u8, gpa, ".{'a', 'b'}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:8: error: index 1 outside of array of length 1\n",
            "{}",
            .{diag},
        );
    }

    // Expect 2 find 1
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([2]u8, gpa, ".{'a'}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:2: error: expected 2 array elements; found 1\n",
            "{}",
            .{diag},
        );
    }

    // Expect 3 find 0
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([3]u8, gpa, ".{}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:2: error: expected 3 array elements; found 0\n",
            "{}",
            .{diag},
        );
    }

    // Wrong inner type
    {
        // Array
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([3]bool, gpa, ".{'a', 'b', 'c'}", &diag, .{}),
            );
            try std.testing.expectFmt("1:3: error: expected type 'bool'\n", "{}", .{diag});
        }

        // Slice
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]bool, gpa, ".{'a', 'b', 'c'}", &diag, .{}),
            );
            try std.testing.expectFmt("1:3: error: expected type 'bool'\n", "{}", .{diag});
        }
    }

    // Complete wrong type
    {
        // Array
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([3]u8, gpa, "'a'", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }

        // Slice
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]u8, gpa, "'a'", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }
    }

    // Address of is not allowed (indirection for slices in ZON is implicit)
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([]u8, gpa, "  &.{'a', 'b', 'c'}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:3: error: pointers are not available in ZON\n",
            "{}",
            .{diag},
        );
    }
}

test "std.zon string literal" {
    const gpa = std.testing.allocator;

    // Basic string literal
    {
        const parsed = try fromSlice([]const u8, gpa, "\"abc\"", null, .{});
        defer free(gpa, parsed);
        try std.testing.expectEqualStrings(@as([]const u8, "abc"), parsed);
    }

    // String literal with escape characters
    {
        const parsed = try fromSlice([]const u8, gpa, "\"ab\\nc\"", null, .{});
        defer free(gpa, parsed);
        try std.testing.expectEqualStrings(@as([]const u8, "ab\nc"), parsed);
    }

    // String literal with embedded null
    {
        const parsed = try fromSlice([]const u8, gpa, "\"ab\\x00c\"", null, .{});
        defer free(gpa, parsed);
        try std.testing.expectEqualStrings(@as([]const u8, "ab\x00c"), parsed);
    }

    // Passing string literal to a mutable slice
    {
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]u8, gpa, "\"abcd\"", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }

        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]u8, gpa, "\\\\abcd", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }
    }

    // Passing string literal to a array
    {
        {
            var ast = try std.zig.Ast.parse(gpa, "\"abcd\"", .zon);
            defer ast.deinit(gpa);
            var zoir = try ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
            defer zoir.deinit(gpa);
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([4:0]u8, gpa, "\"abcd\"", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }

        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([4:0]u8, gpa, "\\\\abcd", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }
    }

    // Zero terminated slices
    {
        {
            const parsed: [:0]const u8 = try fromSlice(
                [:0]const u8,
                gpa,
                "\"abc\"",
                null,
                .{},
            );
            defer free(gpa, parsed);
            try std.testing.expectEqualStrings("abc", parsed);
            try std.testing.expectEqual(@as(u8, 0), parsed[3]);
        }

        {
            const parsed: [:0]const u8 = try fromSlice(
                [:0]const u8,
                gpa,
                "\\\\abc",
                null,
                .{},
            );
            defer free(gpa, parsed);
            try std.testing.expectEqualStrings("abc", parsed);
            try std.testing.expectEqual(@as(u8, 0), parsed[3]);
        }
    }

    // Other value terminated slices
    {
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([:1]const u8, gpa, "\"foo\"", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }

        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([:1]const u8, gpa, "\\\\foo", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }
    }

    // Expecting string literal, getting something else
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([]const u8, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected string\n", "{}", .{diag});
    }

    // Expecting string literal, getting an incompatible tuple
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([]const u8, gpa, ".{false}", &diag, .{}),
        );
        try std.testing.expectFmt("1:3: error: expected type 'u8'\n", "{}", .{diag});
    }

    // Invalid string literal
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice([]const i8, gpa, "\"\\a\"", &diag, .{}),
        );
        try std.testing.expectFmt("1:3: error: invalid escape character: 'a'\n", "{}", .{diag});
    }

    // Slice wrong child type
    {
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]const i8, gpa, "\"a\"", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }

        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]const i8, gpa, "\\\\a", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }
    }

    // Bad alignment
    {
        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]align(2) const u8, gpa, "\"abc\"", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }

        {
            var diag: Diagnostics = .{};
            defer diag.deinit(gpa);
            try std.testing.expectError(
                error.ParseZon,
                fromSlice([]align(2) const u8, gpa, "\\\\abc", &diag, .{}),
            );
            try std.testing.expectFmt("1:1: error: expected array\n", "{}", .{diag});
        }
    }

    // Multi line strings
    inline for (.{ []const u8, [:0]const u8 }) |String| {
        // Nested
        {
            const S = struct {
                message: String,
                message2: String,
                message3: String,
            };
            const parsed = try fromSlice(S, gpa,
                \\.{
                \\    .message =
                \\        \\hello, world!
                \\
                \\        \\this is a multiline string!
                \\        \\
                \\        \\...
                \\
                \\    ,
                \\    .message2 =
                \\        \\this too...sort of.
                \\    ,
                \\    .message3 =
                \\        \\
                \\        \\and this.
                \\}
            , null, .{});
            defer free(gpa, parsed);
            try std.testing.expectEqualStrings(
                "hello, world!\nthis is a multiline string!\n\n...",
                parsed.message,
            );
            try std.testing.expectEqualStrings("this too...sort of.", parsed.message2);
            try std.testing.expectEqualStrings("\nand this.", parsed.message3);
        }
    }
}

test "std.zon enum literals" {
    const gpa = std.testing.allocator;

    const Enum = enum {
        foo,
        bar,
        baz,
        @"ab\nc",
    };

    // Tags that exist
    try std.testing.expectEqual(Enum.foo, try fromSlice(Enum, gpa, ".foo", null, .{}));
    try std.testing.expectEqual(Enum.bar, try fromSlice(Enum, gpa, ".bar", null, .{}));
    try std.testing.expectEqual(Enum.baz, try fromSlice(Enum, gpa, ".baz", null, .{}));
    try std.testing.expectEqual(
        Enum.@"ab\nc",
        try fromSlice(Enum, gpa, ".@\"ab\\nc\"", null, .{}),
    );

    // Bad tag
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Enum, gpa, ".qux", &diag, .{}),
        );
        try std.testing.expectFmt(
            \\1:2: error: unexpected enum literal 'qux'
            \\1:2: note: supported: 'foo', 'bar', 'baz', '@"ab\nc"'
            \\
        ,
            "{}",
            .{diag},
        );
    }

    // Bad tag that's too long for parser
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Enum, gpa, ".@\"foobarbaz\"", &diag, .{}),
        );
        try std.testing.expectFmt(
            \\1:2: error: unexpected enum literal 'foobarbaz'
            \\1:2: note: supported: 'foo', 'bar', 'baz', '@"ab\nc"'
            \\
        ,
            "{}",
            .{diag},
        );
    }

    // Bad type
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Enum, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected enum literal\n", "{}", .{diag});
    }

    // Test embedded nulls in an identifier
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Enum, gpa, ".@\"\\x00\"", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:2: error: identifier cannot contain null bytes\n",
            "{}",
            .{diag},
        );
    }
}

test "std.zon parse bool" {
    const gpa = std.testing.allocator;

    // Correct bools
    try std.testing.expectEqual(true, try fromSlice(bool, gpa, "true", null, .{}));
    try std.testing.expectEqual(false, try fromSlice(bool, gpa, "false", null, .{}));

    // Errors
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(bool, gpa, " foo", &diag, .{}),
        );
        try std.testing.expectFmt(
            \\1:2: error: invalid expression
            \\1:2: note: ZON allows identifiers 'true', 'false', 'null', 'inf', and 'nan'
            \\1:2: note: precede identifier with '.' for an enum literal
            \\
        , "{}", .{diag});
    }
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(bool, gpa, "123", &diag, .{}));
        try std.testing.expectFmt("1:1: error: expected type 'bool'\n", "{}", .{diag});
    }
}

test "std.zon intFromFloatExact" {
    // Valid conversions
    try std.testing.expectEqual(@as(u8, 10), intFromFloatExact(u8, @as(f32, 10.0)).?);
    try std.testing.expectEqual(@as(i8, -123), intFromFloatExact(i8, @as(f64, @as(f64, -123.0))).?);
    try std.testing.expectEqual(@as(i16, 45), intFromFloatExact(i16, @as(f128, @as(f128, 45.0))).?);

    // Out of range
    try std.testing.expectEqual(@as(?u4, null), intFromFloatExact(u4, @as(f32, 16.0)));
    try std.testing.expectEqual(@as(?i4, null), intFromFloatExact(i4, @as(f64, -17.0)));
    try std.testing.expectEqual(@as(?u8, null), intFromFloatExact(u8, @as(f128, -2.0)));

    // Not a whole number
    try std.testing.expectEqual(@as(?u8, null), intFromFloatExact(u8, @as(f32, 0.5)));
    try std.testing.expectEqual(@as(?i8, null), intFromFloatExact(i8, @as(f64, 0.01)));

    // Infinity and NaN
    try std.testing.expectEqual(@as(?u8, null), intFromFloatExact(u8, std.math.inf(f32)));
    try std.testing.expectEqual(@as(?u8, null), intFromFloatExact(u8, -std.math.inf(f32)));
    try std.testing.expectEqual(@as(?u8, null), intFromFloatExact(u8, std.math.nan(f32)));
}

test "std.zon parse int" {
    const gpa = std.testing.allocator;

    // Test various numbers and types
    try std.testing.expectEqual(@as(u8, 10), try fromSlice(u8, gpa, "10", null, .{}));
    try std.testing.expectEqual(@as(i16, 24), try fromSlice(i16, gpa, "24", null, .{}));
    try std.testing.expectEqual(@as(i14, -4), try fromSlice(i14, gpa, "-4", null, .{}));
    try std.testing.expectEqual(@as(i32, -123), try fromSlice(i32, gpa, "-123", null, .{}));

    // Test limits
    try std.testing.expectEqual(@as(i8, 127), try fromSlice(i8, gpa, "127", null, .{}));
    try std.testing.expectEqual(@as(i8, -128), try fromSlice(i8, gpa, "-128", null, .{}));

    // Test characters
    try std.testing.expectEqual(@as(u8, 'a'), try fromSlice(u8, gpa, "'a'", null, .{}));
    try std.testing.expectEqual(@as(u8, 'z'), try fromSlice(u8, gpa, "'z'", null, .{}));

    // Test big integers
    try std.testing.expectEqual(
        @as(u65, 36893488147419103231),
        try fromSlice(u65, gpa, "36893488147419103231", null, .{}),
    );
    try std.testing.expectEqual(
        @as(u65, 36893488147419103231),
        try fromSlice(u65, gpa, "368934_881_474191032_31", null, .{}),
    );

    // Test big integer limits
    try std.testing.expectEqual(
        @as(i66, 36893488147419103231),
        try fromSlice(i66, gpa, "36893488147419103231", null, .{}),
    );
    try std.testing.expectEqual(
        @as(i66, -36893488147419103232),
        try fromSlice(i66, gpa, "-36893488147419103232", null, .{}),
    );
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(
            i66,
            gpa,
            "36893488147419103232",
            &diag,
            .{},
        ));
        try std.testing.expectFmt(
            "1:1: error: type 'i66' cannot represent value\n",
            "{}",
            .{diag},
        );
    }
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(
            i66,
            gpa,
            "-36893488147419103233",
            &diag,
            .{},
        ));
        try std.testing.expectFmt(
            "1:1: error: type 'i66' cannot represent value\n",
            "{}",
            .{diag},
        );
    }

    // Test parsing whole number floats as integers
    try std.testing.expectEqual(@as(i8, -1), try fromSlice(i8, gpa, "-1.0", null, .{}));
    try std.testing.expectEqual(@as(i8, 123), try fromSlice(i8, gpa, "123.0", null, .{}));

    // Test non-decimal integers
    try std.testing.expectEqual(@as(i16, 0xff), try fromSlice(i16, gpa, "0xff", null, .{}));
    try std.testing.expectEqual(@as(i16, -0xff), try fromSlice(i16, gpa, "-0xff", null, .{}));
    try std.testing.expectEqual(@as(i16, 0o77), try fromSlice(i16, gpa, "0o77", null, .{}));
    try std.testing.expectEqual(@as(i16, -0o77), try fromSlice(i16, gpa, "-0o77", null, .{}));
    try std.testing.expectEqual(@as(i16, 0b11), try fromSlice(i16, gpa, "0b11", null, .{}));
    try std.testing.expectEqual(@as(i16, -0b11), try fromSlice(i16, gpa, "-0b11", null, .{}));

    // Test non-decimal big integers
    try std.testing.expectEqual(@as(u65, 0x1ffffffffffffffff), try fromSlice(
        u65,
        gpa,
        "0x1ffffffffffffffff",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(i66, 0x1ffffffffffffffff), try fromSlice(
        i66,
        gpa,
        "0x1ffffffffffffffff",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(i66, -0x1ffffffffffffffff), try fromSlice(
        i66,
        gpa,
        "-0x1ffffffffffffffff",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(u65, 0x1ffffffffffffffff), try fromSlice(
        u65,
        gpa,
        "0o3777777777777777777777",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(i66, 0x1ffffffffffffffff), try fromSlice(
        i66,
        gpa,
        "0o3777777777777777777777",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(i66, -0x1ffffffffffffffff), try fromSlice(
        i66,
        gpa,
        "-0o3777777777777777777777",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(u65, 0x1ffffffffffffffff), try fromSlice(
        u65,
        gpa,
        "0b11111111111111111111111111111111111111111111111111111111111111111",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(i66, 0x1ffffffffffffffff), try fromSlice(
        i66,
        gpa,
        "0b11111111111111111111111111111111111111111111111111111111111111111",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(i66, -0x1ffffffffffffffff), try fromSlice(
        i66,
        gpa,
        "-0b11111111111111111111111111111111111111111111111111111111111111111",
        null,
        .{},
    ));

    // Number with invalid character in the middle
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "32a32", &diag, .{}));
        try std.testing.expectFmt(
            "1:3: error: invalid digit 'a' for decimal base\n",
            "{}",
            .{diag},
        );
    }

    // Failing to parse as int
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "true", &diag, .{}));
        try std.testing.expectFmt("1:1: error: expected type 'u8'\n", "{}", .{diag});
    }

    // Failing because an int is out of range
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "256", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: type 'u8' cannot represent value\n",
            "{}",
            .{diag},
        );
    }

    // Failing because a negative int is out of range
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i8, gpa, "-129", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: type 'i8' cannot represent value\n",
            "{}",
            .{diag},
        );
    }

    // Failing because an unsigned int is negative
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "-1", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: type 'u8' cannot represent value\n",
            "{}",
            .{diag},
        );
    }

    // Failing because a float is non-whole
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "1.5", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: type 'u8' cannot represent value\n",
            "{}",
            .{diag},
        );
    }

    // Failing because a float is negative
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "-1.0", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: type 'u8' cannot represent value\n",
            "{}",
            .{diag},
        );
    }

    // Negative integer zero
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i8, gpa, "-0", &diag, .{}));
        try std.testing.expectFmt(
            \\1:2: error: integer literal '-0' is ambiguous
            \\1:2: note: use '0' for an integer zero
            \\1:2: note: use '-0.0' for a floating-point signed zero
            \\
        , "{}", .{diag});
    }

    // Negative integer zero casted to float
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(f32, gpa, "-0", &diag, .{}));
        try std.testing.expectFmt(
            \\1:2: error: integer literal '-0' is ambiguous
            \\1:2: note: use '0' for an integer zero
            \\1:2: note: use '-0.0' for a floating-point signed zero
            \\
        , "{}", .{diag});
    }

    // Negative float 0 is allowed
    try std.testing.expect(
        std.math.isNegativeZero(try fromSlice(f32, gpa, "-0.0", null, .{})),
    );
    try std.testing.expect(std.math.isPositiveZero(try fromSlice(f32, gpa, "0.0", null, .{})));

    // Double negation is not allowed
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i8, gpa, "--2", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: expected number or 'inf' after '-'\n",
            "{}",
            .{diag},
        );
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(f32, gpa, "--2.0", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:1: error: expected number or 'inf' after '-'\n",
            "{}",
            .{diag},
        );
    }

    // Invalid int literal
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "0xg", &diag, .{}));
        try std.testing.expectFmt("1:3: error: invalid digit 'g' for hex base\n", "{}", .{diag});
    }

    // Notes on invalid int literal
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa, "0123", &diag, .{}));
        try std.testing.expectFmt(
            \\1:1: error: number '0123' has leading zero
            \\1:1: note: use '0o' prefix for octal literals
            \\
        , "{}", .{diag});
    }
}

test "std.zon negative char" {
    const gpa = std.testing.allocator;

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(f32, gpa, "-'a'", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: expected number or 'inf' after '-'\n",
            "{}",
            .{diag},
        );
    }
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i16, gpa, "-'a'", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: expected number or 'inf' after '-'\n",
            "{}",
            .{diag},
        );
    }
}

test "std.zon parse float" {
    const gpa = std.testing.allocator;

    // Test decimals
    try std.testing.expectEqual(@as(f16, 0.5), try fromSlice(f16, gpa, "0.5", null, .{}));
    try std.testing.expectEqual(
        @as(f32, 123.456),
        try fromSlice(f32, gpa, "123.456", null, .{}),
    );
    try std.testing.expectEqual(
        @as(f64, -123.456),
        try fromSlice(f64, gpa, "-123.456", null, .{}),
    );
    try std.testing.expectEqual(@as(f128, 42.5), try fromSlice(f128, gpa, "42.5", null, .{}));

    // Test whole numbers with and without decimals
    try std.testing.expectEqual(@as(f16, 5.0), try fromSlice(f16, gpa, "5.0", null, .{}));
    try std.testing.expectEqual(@as(f16, 5.0), try fromSlice(f16, gpa, "5", null, .{}));
    try std.testing.expectEqual(@as(f32, -102), try fromSlice(f32, gpa, "-102.0", null, .{}));
    try std.testing.expectEqual(@as(f32, -102), try fromSlice(f32, gpa, "-102", null, .{}));

    // Test characters and negated characters
    try std.testing.expectEqual(@as(f32, 'a'), try fromSlice(f32, gpa, "'a'", null, .{}));
    try std.testing.expectEqual(@as(f32, 'z'), try fromSlice(f32, gpa, "'z'", null, .{}));

    // Test big integers
    try std.testing.expectEqual(
        @as(f32, 36893488147419103231),
        try fromSlice(f32, gpa, "36893488147419103231", null, .{}),
    );
    try std.testing.expectEqual(
        @as(f32, -36893488147419103231),
        try fromSlice(f32, gpa, "-36893488147419103231", null, .{}),
    );
    try std.testing.expectEqual(@as(f128, 0x1ffffffffffffffff), try fromSlice(
        f128,
        gpa,
        "0x1ffffffffffffffff",
        null,
        .{},
    ));
    try std.testing.expectEqual(@as(f32, 0x1ffffffffffffffff), try fromSlice(
        f32,
        gpa,
        "0x1ffffffffffffffff",
        null,
        .{},
    ));

    // Exponents, underscores
    try std.testing.expectEqual(
        @as(f32, 123.0E+77),
        try fromSlice(f32, gpa, "12_3.0E+77", null, .{}),
    );

    // Hexadecimal
    try std.testing.expectEqual(
        @as(f32, 0x103.70p-5),
        try fromSlice(f32, gpa, "0x103.70p-5", null, .{}),
    );
    try std.testing.expectEqual(
        @as(f32, -0x103.70),
        try fromSlice(f32, gpa, "-0x103.70", null, .{}),
    );
    try std.testing.expectEqual(
        @as(f32, 0x1234_5678.9ABC_CDEFp-10),
        try fromSlice(f32, gpa, "0x1234_5678.9ABC_CDEFp-10", null, .{}),
    );

    // inf, nan
    try std.testing.expect(std.math.isPositiveInf(try fromSlice(f32, gpa, "inf", null, .{})));
    try std.testing.expect(std.math.isNegativeInf(try fromSlice(f32, gpa, "-inf", null, .{})));
    try std.testing.expect(std.math.isNan(try fromSlice(f32, gpa, "nan", null, .{})));

    // Negative nan not allowed
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(f32, gpa, "-nan", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: expected number or 'inf' after '-'\n",
            "{}",
            .{diag},
        );
    }

    // nan as int not allowed
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i8, gpa, "nan", &diag, .{}));
        try std.testing.expectFmt("1:1: error: expected type 'i8'\n", "{}", .{diag});
    }

    // nan as int not allowed
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i8, gpa, "nan", &diag, .{}));
        try std.testing.expectFmt("1:1: error: expected type 'i8'\n", "{}", .{diag});
    }

    // inf as int not allowed
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i8, gpa, "inf", &diag, .{}));
        try std.testing.expectFmt("1:1: error: expected type 'i8'\n", "{}", .{diag});
    }

    // -inf as int not allowed
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(i8, gpa, "-inf", &diag, .{}));
        try std.testing.expectFmt("1:1: error: expected type 'i8'\n", "{}", .{diag});
    }

    // Bad identifier as float
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(f32, gpa, "foo", &diag, .{}));
        try std.testing.expectFmt(
            \\1:1: error: invalid expression
            \\1:1: note: ZON allows identifiers 'true', 'false', 'null', 'inf', and 'nan'
            \\1:1: note: precede identifier with '.' for an enum literal
            \\
        , "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(f32, gpa, "-foo", &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: expected number or 'inf' after '-'\n",
            "{}",
            .{diag},
        );
    }

    // Non float as float
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(f32, gpa, "\"foo\"", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected type 'f32'\n", "{}", .{diag});
    }
}

test "std.zon free on error" {
    // Test freeing partially allocated structs
    {
        const Struct = struct {
            x: []const u8,
            y: []const u8,
            z: bool,
        };
        try std.testing.expectError(error.ParseZon, fromSlice(Struct, std.testing.allocator,
            \\.{
            \\    .x = "hello",
            \\    .y = "world",
            \\    .z = "fail",
            \\}
        , null, .{}));
    }

    // Test freeing partially allocated tuples
    {
        const Struct = struct {
            []const u8,
            []const u8,
            bool,
        };
        try std.testing.expectError(error.ParseZon, fromSlice(Struct, std.testing.allocator,
            \\.{
            \\    "hello",
            \\    "world",
            \\    "fail",
            \\}
        , null, .{}));
    }

    // Test freeing structs with missing fields
    {
        const Struct = struct {
            x: []const u8,
            y: bool,
        };
        try std.testing.expectError(error.ParseZon, fromSlice(Struct, std.testing.allocator,
            \\.{
            \\    .x = "hello",
            \\}
        , null, .{}));
    }

    // Test freeing partially allocated arrays
    {
        try std.testing.expectError(error.ParseZon, fromSlice(
            [3][]const u8,
            std.testing.allocator,
            \\.{
            \\    "hello",
            \\    false,
            \\    false,
            \\}
        ,
            null,
            .{},
        ));
    }

    // Test freeing partially allocated slices
    {
        try std.testing.expectError(error.ParseZon, fromSlice(
            [][]const u8,
            std.testing.allocator,
            \\.{
            \\    "hello",
            \\    "world",
            \\    false,
            \\}
        ,
            null,
            .{},
        ));
    }

    // We can parse types that can't be freed, as long as they contain no allocations, e.g. untagged
    // unions.
    try std.testing.expectEqual(
        @as(f32, 1.5),
        (try fromSlice(union { x: f32 }, std.testing.allocator, ".{ .x = 1.5 }", null, .{})).x,
    );

    // We can also parse types that can't be freed if it's impossible for an error to occur after
    // the allocation, as is the case here.
    {
        const result = try fromSlice(
            union { x: []const u8 },
            std.testing.allocator,
            ".{ .x = \"foo\" }",
            null,
            .{},
        );
        defer free(std.testing.allocator, result.x);
        try std.testing.expectEqualStrings("foo", result.x);
    }

    // However, if it's possible we could get an error requiring we free the value, but the value
    // cannot be freed (e.g. untagged unions) then we need to turn off `free_on_error` for it to
    // compile.
    {
        const S = struct {
            union { x: []const u8 },
            bool,
        };
        const result = try fromSlice(
            S,
            std.testing.allocator,
            ".{ .{ .x = \"foo\" }, true }",
            null,
            .{ .free_on_error = false },
        );
        defer free(std.testing.allocator, result[0].x);
        try std.testing.expectEqualStrings("foo", result[0].x);
        try std.testing.expect(result[1]);
    }

    // Again but for structs.
    {
        const S = struct {
            a: union { x: []const u8 },
            b: bool,
        };
        const result = try fromSlice(
            S,
            std.testing.allocator,
            ".{ .a = .{ .x = \"foo\" }, .b = true }",
            null,
            .{
                .free_on_error = false,
            },
        );
        defer free(std.testing.allocator, result.a.x);
        try std.testing.expectEqualStrings("foo", result.a.x);
        try std.testing.expect(result.b);
    }

    // Again but for arrays.
    {
        const S = [2]union { x: []const u8 };
        const result = try fromSlice(
            S,
            std.testing.allocator,
            ".{ .{ .x = \"foo\" }, .{ .x = \"bar\" } }",
            null,
            .{
                .free_on_error = false,
            },
        );
        defer free(std.testing.allocator, result[0].x);
        defer free(std.testing.allocator, result[1].x);
        try std.testing.expectEqualStrings("foo", result[0].x);
        try std.testing.expectEqualStrings("bar", result[1].x);
    }

    // Again but for slices.
    {
        const S = []union { x: []const u8 };
        const result = try fromSlice(
            S,
            std.testing.allocator,
            ".{ .{ .x = \"foo\" }, .{ .x = \"bar\" } }",
            null,
            .{
                .free_on_error = false,
            },
        );
        defer std.testing.allocator.free(result);
        defer free(std.testing.allocator, result[0].x);
        defer free(std.testing.allocator, result[1].x);
        try std.testing.expectEqualStrings("foo", result[0].x);
        try std.testing.expectEqualStrings("bar", result[1].x);
    }
}

test "std.zon vector" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/15330
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/15329

    const gpa = std.testing.allocator;

    // Passing cases
    try std.testing.expectEqual(
        @Vector(0, bool){},
        try fromSlice(@Vector(0, bool), gpa, ".{}", null, .{}),
    );
    try std.testing.expectEqual(
        @Vector(3, bool){ true, false, true },
        try fromSlice(@Vector(3, bool), gpa, ".{true, false, true}", null, .{}),
    );

    try std.testing.expectEqual(
        @Vector(0, f32){},
        try fromSlice(@Vector(0, f32), gpa, ".{}", null, .{}),
    );
    try std.testing.expectEqual(
        @Vector(3, f32){ 1.5, 2.5, 3.5 },
        try fromSlice(@Vector(3, f32), gpa, ".{1.5, 2.5, 3.5}", null, .{}),
    );

    try std.testing.expectEqual(
        @Vector(0, u8){},
        try fromSlice(@Vector(0, u8), gpa, ".{}", null, .{}),
    );
    try std.testing.expectEqual(
        @Vector(3, u8){ 2, 4, 6 },
        try fromSlice(@Vector(3, u8), gpa, ".{2, 4, 6}", null, .{}),
    );

    {
        try std.testing.expectEqual(
            @Vector(0, *const u8){},
            try fromSlice(@Vector(0, *const u8), gpa, ".{}", null, .{}),
        );
        const pointers = try fromSlice(@Vector(3, *const u8), gpa, ".{2, 4, 6}", null, .{});
        defer free(gpa, pointers);
        try std.testing.expectEqualDeep(@Vector(3, *const u8){ &2, &4, &6 }, pointers);
    }

    {
        try std.testing.expectEqual(
            @Vector(0, ?*const u8){},
            try fromSlice(@Vector(0, ?*const u8), gpa, ".{}", null, .{}),
        );
        const pointers = try fromSlice(@Vector(3, ?*const u8), gpa, ".{2, null, 6}", null, .{});
        defer free(gpa, pointers);
        try std.testing.expectEqualDeep(@Vector(3, ?*const u8){ &2, null, &6 }, pointers);
    }

    // Too few fields
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(@Vector(2, f32), gpa, ".{0.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:2: error: expected 2 vector elements; found 1\n",
            "{}",
            .{diag},
        );
    }

    // Too many fields
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(@Vector(2, f32), gpa, ".{0.5, 1.5, 2.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:2: error: expected 2 vector elements; found 3\n",
            "{}",
            .{diag},
        );
    }

    // Wrong type fields
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(@Vector(3, f32), gpa, ".{0.5, true, 2.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            "1:8: error: expected type 'f32'\n",
            "{}",
            .{diag},
        );
    }

    // Wrong type
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(@Vector(3, u8), gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected type '@Vector(3, u8)'\n", "{}", .{diag});
    }

    // Elements should get freed on error
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(@Vector(3, *u8), gpa, ".{1, true, 3}", &diag, .{}),
        );
        try std.testing.expectFmt("1:6: error: expected type 'u8'\n", "{}", .{diag});
    }
}

test "std.zon add pointers" {
    const gpa = std.testing.allocator;

    // Primitive with varying levels of pointers
    {
        const result = try fromSlice(*u32, gpa, "10", null, .{});
        defer free(gpa, result);
        try std.testing.expectEqual(@as(u32, 10), result.*);
    }

    {
        const result = try fromSlice(**u32, gpa, "10", null, .{});
        defer free(gpa, result);
        try std.testing.expectEqual(@as(u32, 10), result.*.*);
    }

    {
        const result = try fromSlice(***u32, gpa, "10", null, .{});
        defer free(gpa, result);
        try std.testing.expectEqual(@as(u32, 10), result.*.*.*);
    }

    // Primitive optional with varying levels of pointers
    {
        const some = try fromSlice(?*u32, gpa, "10", null, .{});
        defer free(gpa, some);
        try std.testing.expectEqual(@as(u32, 10), some.?.*);

        const none = try fromSlice(?*u32, gpa, "null", null, .{});
        defer free(gpa, none);
        try std.testing.expectEqual(null, none);
    }

    {
        const some = try fromSlice(*?u32, gpa, "10", null, .{});
        defer free(gpa, some);
        try std.testing.expectEqual(@as(u32, 10), some.*.?);

        const none = try fromSlice(*?u32, gpa, "null", null, .{});
        defer free(gpa, none);
        try std.testing.expectEqual(null, none.*);
    }

    {
        const some = try fromSlice(?**u32, gpa, "10", null, .{});
        defer free(gpa, some);
        try std.testing.expectEqual(@as(u32, 10), some.?.*.*);

        const none = try fromSlice(?**u32, gpa, "null", null, .{});
        defer free(gpa, none);
        try std.testing.expectEqual(null, none);
    }

    {
        const some = try fromSlice(*?*u32, gpa, "10", null, .{});
        defer free(gpa, some);
        try std.testing.expectEqual(@as(u32, 10), some.*.?.*);

        const none = try fromSlice(*?*u32, gpa, "null", null, .{});
        defer free(gpa, none);
        try std.testing.expectEqual(null, none.*);
    }

    {
        const some = try fromSlice(**?u32, gpa, "10", null, .{});
        defer free(gpa, some);
        try std.testing.expectEqual(@as(u32, 10), some.*.*.?);

        const none = try fromSlice(**?u32, gpa, "null", null, .{});
        defer free(gpa, none);
        try std.testing.expectEqual(null, none.*.*);
    }

    // Pointer to an array
    {
        const result = try fromSlice(*[3]u8, gpa, ".{ 1, 2, 3 }", null, .{});
        defer free(gpa, result);
        try std.testing.expectEqual([3]u8{ 1, 2, 3 }, result.*);
    }

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
        const expected: Outer = .{
            .f1 = &&.{
                .f1 = &null,
                .f2 = &&"foo",
            },
            .f2 = &null,
        };

        const found = try fromSlice(?*Outer, gpa,
            \\.{
            \\    .f1 = .{
            \\        .f1 = null,
            \\        .f2 = "foo",
            \\    },
            \\    .f2 = null,
            \\}
        , null, .{});
        defer free(gpa, found);

        try std.testing.expectEqualDeep(expected, found.?.*);
    }

    // Test that optional types are flattened correctly in errors
    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const u8, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected type '?u8'\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const f32, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected type '?f32'\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const @Vector(3, u8), gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected type '?@Vector(3, u8)'\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const bool, gpa, "10", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected type '?bool'\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const struct { a: i32 }, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional struct\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const struct { i32 }, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional tuple\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const union { x: void }, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional union\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const [3]u8, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional array\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(?[3]u8, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional array\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const []u8, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional array\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(?[]u8, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional array\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const []const u8, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional string\n", "{}", .{diag});
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(*const ?*const enum { foo }, gpa, "true", &diag, .{}),
        );
        try std.testing.expectFmt("1:1: error: expected optional enum literal\n", "{}", .{diag});
    }
}

test "std.zon stop on node" {
    const gpa = std.testing.allocator;

    {
        const Vec2 = struct {
            x: Zoir.Node.Index,
            y: f32,
        };

        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        const result = try fromSlice(Vec2, gpa, ".{ .x = 1.5, .y = 2.5 }", &diag, .{});
        try std.testing.expectEqual(result.y, 2.5);
        try std.testing.expectEqual(Zoir.Node{ .float_literal = 1.5 }, result.x.get(diag.zoir));
    }

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        const result = try fromSlice(Zoir.Node.Index, gpa, "1.23", &diag, .{});
        try std.testing.expectEqual(Zoir.Node{ .float_literal = 1.23 }, result.get(diag.zoir));
    }
}
//! ZON can be serialized with `serialize`.
//!
//! The following functions are provided for serializing recursive types:
//! * `serializeMaxDepth`
//! * `serializeArbitraryDepth`
//!
//! For additional control over serialization, see `Serializer`.
//!
//! The following types and any types that contain them may not be serialized:
//! * `type`
//! * `void`, except as a union payload
//! * `noreturn`
//! * Error sets/error unions
//! * Untagged unions
//! * Many-pointers or C-pointers
//! * Opaque types, including `anyopaque`
//! * Async frame types, including `anyframe` and `anyframe->T`
//! * Functions
//!
//! All other types are valid. Unsupported types will fail to serialize at compile time. Pointers
//! are followed.

const std = @import("std");
const assert = std.debug.assert;

/// Options for `serialize`.
pub const SerializeOptions = struct {
    /// If false, whitespace is omitted. Otherwise whitespace is emitted in standard Zig style.
    whitespace: bool = true,
    /// Determines when to emit Unicode code point literals as opposed to integer literals.
    emit_codepoint_literals: EmitCodepointLiterals = .never,
    /// If true, slices of `u8`s, and pointers to arrays of `u8` are serialized as containers.
    /// Otherwise they are serialized as string literals.
    emit_strings_as_containers: bool = false,
    /// If false, struct fields are not written if they are equal to their default value. Comparison
    /// is done by `std.meta.eql`.
    emit_default_optional_fields: bool = true,
};

/// Serialize the given value as ZON.
///
/// It is asserted at comptime that `@TypeOf(val)` is not a recursive type.
pub fn serialize(
    val: anytype,
    options: SerializeOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    var sz = serializer(writer, .{
        .whitespace = options.whitespace,
    });
    try sz.value(val, .{
        .emit_codepoint_literals = options.emit_codepoint_literals,
        .emit_strings_as_containers = options.emit_strings_as_containers,
        .emit_default_optional_fields = options.emit_default_optional_fields,
    });
}

/// Like `serialize`, but recursive types are allowed.
///
/// Returns `error.ExceededMaxDepth` if `depth` is exceeded. Every nested value adds one to a
/// value's depth.
pub fn serializeMaxDepth(
    val: anytype,
    options: SerializeOptions,
    writer: anytype,
    depth: usize,
) (@TypeOf(writer).Error || error{ExceededMaxDepth})!void {
    var sz = serializer(writer, .{
        .whitespace = options.whitespace,
    });
    try sz.valueMaxDepth(val, .{
        .emit_codepoint_literals = options.emit_codepoint_literals,
        .emit_strings_as_containers = options.emit_strings_as_containers,
        .emit_default_optional_fields = options.emit_default_optional_fields,
    }, depth);
}

/// Like `serialize`, but recursive types are allowed.
///
/// It is the caller's responsibility to ensure that `val` does not contain cycles.
pub fn serializeArbitraryDepth(
    val: anytype,
    options: SerializeOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    var sz = serializer(writer, .{
        .whitespace = options.whitespace,
    });
    try sz.valueArbitraryDepth(val, .{
        .emit_codepoint_literals = options.emit_codepoint_literals,
        .emit_strings_as_containers = options.emit_strings_as_containers,
        .emit_default_optional_fields = options.emit_default_optional_fields,
    });
}

fn typeIsRecursive(comptime T: type) bool {
    return comptime typeIsRecursiveImpl(T, &.{});
}

fn typeIsRecursiveImpl(comptime T: type, comptime prev_visited: []const type) bool {
    for (prev_visited) |V| {
        if (V == T) return true;
    }
    const visited = prev_visited ++ .{T};

    return switch (@typeInfo(T)) {
        .pointer => |pointer| typeIsRecursiveImpl(pointer.child, visited),
        .optional => |optional| typeIsRecursiveImpl(optional.child, visited),
        .array => |array| typeIsRecursiveImpl(array.child, visited),
        .vector => |vector| typeIsRecursiveImpl(vector.child, visited),
        .@"struct" => |@"struct"| for (@"struct".fields) |field| {
            if (typeIsRecursiveImpl(field.type, visited)) break true;
        } else false,
        .@"union" => |@"union"| inline for (@"union".fields) |field| {
            if (typeIsRecursiveImpl(field.type, visited)) break true;
        } else false,
        else => false,
    };
}

fn canSerializeType(T: type) bool {
    comptime return canSerializeTypeInner(T, &.{}, false);
}

fn canSerializeTypeInner(
    T: type,
    /// Visited structs and unions, to avoid infinite recursion.
    /// Tracking more types is unnecessary, and a little complex due to optional nesting.
    visited: []const type,
    parent_is_optional: bool,
) bool {
    return switch (@typeInfo(T)) {
        .bool,
        .int,
        .float,
        .comptime_float,
        .comptime_int,
        .null,
        .enum_literal,
        => true,

        .noreturn,
        .void,
        .type,
        .undefined,
        .error_union,
        .error_set,
        .@"fn",
        .frame,
        .@"anyframe",
        .@"opaque",
        => false,

        .@"enum" => |@"enum"| @"enum".is_exhaustive,

        .pointer => |pointer| switch (pointer.size) {
            .one => canSerializeTypeInner(pointer.child, visited, parent_is_optional),
            .slice => canSerializeTypeInner(pointer.child, visited, false),
            .many, .c => false,
        },

        .optional => |optional| if (parent_is_optional)
            false
        else
            canSerializeTypeInner(optional.child, visited, true),

        .array => |array| canSerializeTypeInner(array.child, visited, false),
        .vector => |vector| canSerializeTypeInner(vector.child, visited, false),

        .@"struct" => |@"struct"| {
            for (visited) |V| if (T == V) return true;
            const new_visited = visited ++ .{T};
            for (@"struct".fields) |field| {
                if (!canSerializeTypeInner(field.type, new_visited, false)) return false;
            }
            return true;
        },
        .@"union" => |@"union"| {
            for (visited) |V| if (T == V) return true;
            const new_visited = visited ++ .{T};
            if (@"union".tag_type == null) return false;
            for (@"union".fields) |field| {
                if (field.type != void and !canSerializeTypeInner(field.type, new_visited, false)) {
                    return false;
                }
            }
            return true;
        },
    };
}

fn isNestedOptional(T: type) bool {
    comptime switch (@typeInfo(T)) {
        .optional => |optional| return isNestedOptionalInner(optional.child),
        else => return false,
    };
}

fn isNestedOptionalInner(T: type) bool {
    switch (@typeInfo(T)) {
        .pointer => |pointer| {
            if (pointer.size == .one) {
                return isNestedOptionalInner(pointer.child);
            } else {
                return false;
            }
        },
        .optional => return true,
        else => return false,
    }
}

test "std.zon stringify canSerializeType" {
    try std.testing.expect(!comptime canSerializeType(void));
    try std.testing.expect(!comptime canSerializeType(struct { f: [*]u8 }));
    try std.testing.expect(!comptime canSerializeType(struct { error{foo} }));
    try std.testing.expect(!comptime canSerializeType(union(enum) { a: void, f: [*c]u8 }));
    try std.testing.expect(!comptime canSerializeType(@Vector(0, [*c]u8)));
    try std.testing.expect(!comptime canSerializeType(*?[*c]u8));
    try std.testing.expect(!comptime canSerializeType(enum(u8) { _ }));
    try std.testing.expect(!comptime canSerializeType(union { foo: void }));
    try std.testing.expect(comptime canSerializeType(union(enum) { foo: void }));
    try std.testing.expect(comptime canSerializeType(comptime_float));
    try std.testing.expect(comptime canSerializeType(comptime_int));
    try std.testing.expect(!comptime canSerializeType(struct { comptime foo: ??u8 = null }));
    try std.testing.expect(comptime canSerializeType(@TypeOf(.foo)));
    try std.testing.expect(comptime canSerializeType(?u8));
    try std.testing.expect(comptime canSerializeType(*?*u8));
    try std.testing.expect(comptime canSerializeType(?struct {
        foo: ?struct {
            ?union(enum) {
                a: ?@Vector(0, ?*u8),
            },
            ?struct {
                f: ?[]?u8,
            },
        },
    }));
    try std.testing.expect(!comptime canSerializeType(??u8));
    try std.testing.expect(!comptime canSerializeType(?*?u8));
    try std.testing.expect(!comptime canSerializeType(*?*?*u8));
    try std.testing.expect(comptime canSerializeType(struct { x: comptime_int = 2 }));
    try std.testing.expect(comptime canSerializeType(struct { x: comptime_float = 2 }));
    try std.testing.expect(comptime canSerializeType(struct { comptime_int }));
    try std.testing.expect(comptime canSerializeType(struct { comptime x: @TypeOf(.foo) = .foo }));
    const Recursive = struct { foo: ?*@This() };
    try std.testing.expect(comptime canSerializeType(Recursive));

    // Make sure we validate nested optional before we early out due to already having seen
    // a type recursion!
    try std.testing.expect(!comptime canSerializeType(struct {
        add_to_visited: ?u8,
        retrieve_from_visited: ??u8,
    }));
}

test "std.zon typeIsRecursive" {
    try std.testing.expect(!typeIsRecursive(bool));
    try std.testing.expect(!typeIsRecursive(struct { x: i32, y: i32 }));
    try std.testing.expect(!typeIsRecursive(struct { i32, i32 }));
    try std.testing.expect(typeIsRecursive(struct { x: i32, y: i32, z: *@This() }));
    try std.testing.expect(typeIsRecursive(struct {
        a: struct {
            const A = @This();
            b: struct {
                c: *struct {
                    a: ?A,
                },
            },
        },
    }));
    try std.testing.expect(typeIsRecursive(struct {
        a: [3]*@This(),
    }));
    try std.testing.expect(typeIsRecursive(struct {
        a: union { a: i32, b: *@This() },
    }));
}

fn checkValueDepth(val: anytype, depth: usize) error{ExceededMaxDepth}!void {
    if (depth == 0) return error.ExceededMaxDepth;
    const child_depth = depth - 1;

    switch (@typeInfo(@TypeOf(val))) {
        .pointer => |pointer| switch (pointer.size) {
            .one => try checkValueDepth(val.*, child_depth),
            .slice => for (val) |item| {
                try checkValueDepth(item, child_depth);
            },
            .c, .many => {},
        },
        .array => for (val) |item| {
            try checkValueDepth(item, child_depth);
        },
        .@"struct" => |@"struct"| inline for (@"struct".fields) |field_info| {
            try checkValueDepth(@field(val, field_info.name), child_depth);
        },
        .@"union" => |@"union"| if (@"union".tag_type == null) {
            return;
        } else switch (val) {
            inline else => |payload| {
                return checkValueDepth(payload, child_depth);
            },
        },
        .optional => if (val) |inner| try checkValueDepth(inner, child_depth),
        else => {},
    }
}

fn expectValueDepthEquals(expected: usize, value: anytype) !void {
    try checkValueDepth(value, expected);
    try std.testing.expectError(error.ExceededMaxDepth, checkValueDepth(value, expected - 1));
}

test "std.zon checkValueDepth" {
    try expectValueDepthEquals(1, 10);
    try expectValueDepthEquals(2, .{ .x = 1, .y = 2 });
    try expectValueDepthEquals(2, .{ 1, 2 });
    try expectValueDepthEquals(3, .{ 1, .{ 2, 3 } });
    try expectValueDepthEquals(3, .{ .{ 1, 2 }, 3 });
    try expectValueDepthEquals(3, .{ .x = 0, .y = 1, .z = .{ .x = 3 } });
    try expectValueDepthEquals(3, .{ .x = 0, .y = .{ .x = 1 }, .z = 2 });
    try expectValueDepthEquals(3, .{ .x = .{ .x = 0 }, .y = 1, .z = 2 });
    try expectValueDepthEquals(2, @as(?u32, 1));
    try expectValueDepthEquals(1, @as(?u32, null));
    try expectValueDepthEquals(1, null);
    try expectValueDepthEquals(2, &1);
    try expectValueDepthEquals(3, &@as(?u32, 1));

    const Union = union(enum) {
        x: u32,
        y: struct { x: u32 },
    };
    try expectValueDepthEquals(2, Union{ .x = 1 });
    try expectValueDepthEquals(3, Union{ .y = .{ .x = 1 } });

    const Recurse = struct { r: ?*const @This() };
    try expectValueDepthEquals(2, Recurse{ .r = null });
    try expectValueDepthEquals(5, Recurse{ .r = &Recurse{ .r = null } });
    try expectValueDepthEquals(8, Recurse{ .r = &Recurse{ .r = &Recurse{ .r = null } } });

    try expectValueDepthEquals(2, @as([]const u8, &.{ 1, 2, 3 }));
    try expectValueDepthEquals(3, @as([]const []const u8, &.{&.{ 1, 2, 3 }}));
}

/// Options for `Serializer`.
pub const SerializerOptions = struct {
    /// If false, only syntactically necessary whitespace is emitted.
    whitespace: bool = true,
};

/// Determines when to emit Unicode code point literals as opposed to integer literals.
pub const EmitCodepointLiterals = enum {
    /// Never emit Unicode code point literals.
    never,
    /// Emit Unicode code point literals for any `u8` in the printable ASCII range.
    printable_ascii,
    /// Emit Unicode code point literals for any unsigned integer with 21 bits or fewer
    /// whose value is a valid non-surrogate code point.
    always,

    /// If the value should be emitted as a Unicode codepoint, return it as a u21.
    fn emitAsCodepoint(self: @This(), val: anytype) ?u21 {
        // Rule out incompatible integer types
        switch (@typeInfo(@TypeOf(val))) {
            .int => |int_info| if (int_info.signedness == .signed or int_info.bits > 21) {
                return null;
            },
            .comptime_int => {},
            else => comptime unreachable,
        }

        // Return null if the value shouldn't be printed as a Unicode codepoint, or the value casted
        // to a u21 if it should.
        switch (self) {
            .always => {
                const c = std.math.cast(u21, val) orelse return null;
                if (!std.unicode.utf8ValidCodepoint(c)) return null;
                return c;
            },
            .printable_ascii => {
                const c = std.math.cast(u8, val) orelse return null;
                if (!std.ascii.isPrint(c)) return null;
                return c;
            },
            .never => {
                return null;
            },
        }
    }
};

/// Options for serialization of an individual value.
///
/// See `SerializeOptions` for more information on these options.
pub const ValueOptions = struct {
    emit_codepoint_literals: EmitCodepointLiterals = .never,
    emit_strings_as_containers: bool = false,
    emit_default_optional_fields: bool = true,
};

/// Options for manual serialization of container types.
pub const SerializeContainerOptions = struct {
    /// The whitespace style that should be used for this container. Ignored if whitespace is off.
    whitespace_style: union(enum) {
        /// If true, wrap every field. If false do not.
        wrap: bool,
        /// Automatically decide whether to wrap or not based on the number of fields. Following
        /// the standard rule of thumb, containers with more than two fields are wrapped.
        fields: usize,
    } = .{ .wrap = true },

    fn shouldWrap(self: SerializeContainerOptions) bool {
        return switch (self.whitespace_style) {
            .wrap => |wrap| wrap,
            .fields => |fields| fields > 2,
        };
    }
};

/// Lower level control over serialization, you can create a new instance with `serializer`.
///
/// Useful when you want control over which fields are serialized, how they're represented,
/// or want to write a ZON object that does not exist in memory.
///
/// You can serialize values with `value`. To serialize recursive types, the following are provided:
/// * `valueMaxDepth`
/// * `valueArbitraryDepth`
///
/// You can also serialize values using specific notations:
/// * `int`
/// * `float`
/// * `codePoint`
/// * `tuple`
/// * `tupleMaxDepth`
/// * `tupleArbitraryDepth`
/// * `string`
/// * `multilineString`
///
/// For manual serialization of containers, see:
/// * `beginStruct`
/// * `beginTuple`
///
/// # Example
/// ```zig
/// var sz = serializer(writer, .{});
/// var vec2 = try sz.beginStruct(.{});
/// try vec2.field("x", 1.5, .{});
/// try vec2.fieldPrefix();
/// try sz.value(2.5);
/// try vec2.end();
/// ```
pub fn Serializer(Writer: type) type {
    return struct {
        const Self = @This();

        options: SerializerOptions,
        indent_level: u8,
        writer: Writer,

        /// Initialize a serializer.
        fn init(writer: Writer, options: SerializerOptions) Self {
            return .{
                .options = options,
                .writer = writer,
                .indent_level = 0,
            };
        }

        /// Serialize a value, similar to `serialize`.
        pub fn value(self: *Self, val: anytype, options: ValueOptions) Writer.Error!void {
            comptime assert(!typeIsRecursive(@TypeOf(val)));
            return self.valueArbitraryDepth(val, options);
        }

        /// Serialize a value, similar to `serializeMaxDepth`.
        pub fn valueMaxDepth(
            self: *Self,
            val: anytype,
            options: ValueOptions,
            depth: usize,
        ) (Writer.Error || error{ExceededMaxDepth})!void {
            try checkValueDepth(val, depth);
            return self.valueArbitraryDepth(val, options);
        }

        /// Serialize a value, similar to `serializeArbitraryDepth`.
        pub fn valueArbitraryDepth(
            self: *Self,
            val: anytype,
            options: ValueOptions,
        ) Writer.Error!void {
            comptime assert(canSerializeType(@TypeOf(val)));
            switch (@typeInfo(@TypeOf(val))) {
                .int, .comptime_int => if (options.emit_codepoint_literals.emitAsCodepoint(val)) |c| {
                    self.codePoint(c) catch |err| switch (err) {
                        error.InvalidCodepoint => unreachable, // Already validated
                        else => |e| return e,
                    };
                } else {
                    try self.int(val);
                },
                .float, .comptime_float => try self.float(val),
                .bool, .null => try std.fmt.format(self.writer, "{}", .{val}),
                .enum_literal => try self.ident(@tagName(val)),
                .@"enum" => try self.ident(@tagName(val)),
                .pointer => |pointer| {
                    // Try to serialize as a string
                    const item: ?type = switch (@typeInfo(pointer.child)) {
                        .array => |array| array.child,
                        else => if (pointer.size == .slice) pointer.child else null,
                    };
                    if (item == u8 and
                        (pointer.sentinel() == null or pointer.sentinel() == 0) and
                        !options.emit_strings_as_containers)
                    {
                        return try self.string(val);
                    }

                    // Serialize as either a tuple or as the child type
                    switch (pointer.size) {
                        .slice => try self.tupleImpl(val, options),
                        .one => try self.valueArbitraryDepth(val.*, options),
                        else => comptime unreachable,
                    }
                },
                .array => {
                    var container = try self.beginTuple(
                        .{ .whitespace_style = .{ .fields = val.len } },
                    );
                    for (val) |item_val| {
                        try container.fieldArbitraryDepth(item_val, options);
                    }
                    try container.end();
                },
                .@"struct" => |@"struct"| if (@"struct".is_tuple) {
                    var container = try self.beginTuple(
                        .{ .whitespace_style = .{ .fields = @"struct".fields.len } },
                    );
                    inline for (val) |field_value| {
                        try container.fieldArbitraryDepth(field_value, options);
                    }
                    try container.end();
                } else {
                    // Decide which fields to emit
                    const fields, const skipped: [@"struct".fields.len]bool = if (options.emit_default_optional_fields) b: {
                        break :b .{ @"struct".fields.len, @splat(false) };
                    } else b: {
                        var fields = @"struct".fields.len;
                        var skipped: [@"struct".fields.len]bool = @splat(false);
                        inline for (@"struct".fields, &skipped) |field_info, *skip| {
                            if (field_info.default_value_ptr) |ptr| {
                                const default: *const field_info.type = @ptrCast(@alignCast(ptr));
                                const field_value = @field(val, field_info.name);
                                if (std.meta.eql(field_value, default.*)) {
                                    skip.* = true;
                                    fields -= 1;
                                }
                            }
                        }
                        break :b .{ fields, skipped };
                    };

                    // Emit those fields
                    var container = try self.beginStruct(
                        .{ .whitespace_style = .{ .fields = fields } },
                    );
                    inline for (@"struct".fields, skipped) |field_info, skip| {
                        if (!skip) {
                            try container.fieldArbitraryDepth(
                                field_info.name,
                                @field(val, field_info.name),
                                options,
                            );
                        }
                    }
                    try container.end();
                },
                .@"union" => |@"union"| {
                    comptime assert(@"union".tag_type != null);
                    switch (val) {
                        inline else => |pl, tag| if (@TypeOf(pl) == void)
                            try self.writer.print(".{s}", .{@tagName(tag)})
                        else {
                            var container = try self.beginStruct(.{ .whitespace_style = .{ .fields = 1 } });

                            try container.fieldArbitraryDepth(
                                @tagName(tag),
                                pl,
                                options,
                            );

                            try container.end();
                        },
                    }
                },
                .optional => if (val) |inner| {
                    try self.valueArbitraryDepth(inner, options);
                } else {
                    try self.writer.writeAll("null");
                },
                .vector => |vector| {
                    var container = try self.beginTuple(
                        .{ .whitespace_style = .{ .fields = vector.len } },
                    );
                    for (0..vector.len) |i| {
                        try container.fieldArbitraryDepth(val[i], options);
                    }
                    try container.end();
                },

                else => comptime unreachable,
            }
        }

        /// Serialize an integer.
        pub fn int(self: *Self, val: anytype) Writer.Error!void {
            try std.fmt.formatInt(val, 10, .lower, .{}, self.writer);
        }

        /// Serialize a float.
        pub fn float(self: *Self, val: anytype) Writer.Error!void {
            switch (@typeInfo(@TypeOf(val))) {
                .float => if (std.math.isNan(val)) {
                    return self.writer.writeAll("nan");
                } else if (std.math.isPositiveInf(val)) {
                    return self.writer.writeAll("inf");
                } else if (std.math.isNegativeInf(val)) {
                    return self.writer.writeAll("-inf");
                } else if (std.math.isNegativeZero(val)) {
                    return self.writer.writeAll("-0.0");
                } else {
                    try std.fmt.format(self.writer, "{d}", .{val});
                },
                .comptime_float => if (val == 0) {
                    return self.writer.writeAll("0");
                } else {
                    try std.fmt.format(self.writer, "{d}", .{val});
                },
                else => comptime unreachable,
            }
        }

        /// Serialize `name` as an identifier prefixed with `.`.
        ///
        /// Escapes the identifier if necessary.
        pub fn ident(self: *Self, name: []const u8) Writer.Error!void {
            try self.writer.print(".{p_}", .{std.zig.fmtId(name)});
        }

        /// Serialize `val` as a Unicode codepoint.
        ///
        /// Returns `error.InvalidCodepoint` if `val` is not a valid Unicode codepoint.
        pub fn codePoint(
            self: *Self,
            val: u21,
        ) (Writer.Error || error{InvalidCodepoint})!void {
            var buf: [8]u8 = undefined;
            const len = std.unicode.utf8Encode(val, &buf) catch return error.InvalidCodepoint;
            const str = buf[0..len];
            try std.fmt.format(self.writer, "'{'}'", .{std.zig.fmtEscapes(str)});
        }

        /// Like `value`, but always serializes `val` as a tuple.
        ///
        /// Will fail at comptime if `val` is not a tuple, array, pointer to an array, or slice.
        pub fn tuple(self: *Self, val: anytype, options: ValueOptions) Writer.Error!void {
            comptime assert(!typeIsRecursive(@TypeOf(val)));
            try self.tupleArbitraryDepth(val, options);
        }

        /// Like `tuple`, but recursive types are allowed.
        ///
        /// Returns `error.ExceededMaxDepth` if `depth` is exceeded.
        pub fn tupleMaxDepth(
            self: *Self,
            val: anytype,
            options: ValueOptions,
            depth: usize,
        ) (Writer.Error || error{ExceededMaxDepth})!void {
            try checkValueDepth(val, depth);
            try self.tupleArbitraryDepth(val, options);
        }

        /// Like `tuple`, but recursive types are allowed.
        ///
        /// It is the caller's responsibility to ensure that `val` does not contain cycles.
        pub fn tupleArbitraryDepth(
            self: *Self,
            val: anytype,
            options: ValueOptions,
        ) Writer.Error!void {
            try self.tupleImpl(val, options);
        }

        fn tupleImpl(self: *Self, val: anytype, options: ValueOptions) Writer.Error!void {
            comptime assert(canSerializeType(@TypeOf(val)));
            switch (@typeInfo(@TypeOf(val))) {
                .@"struct" => {
                    var container = try self.beginTuple(.{ .whitespace_style = .{ .fields = val.len } });
                    inline for (val) |item_val| {
                        try container.fieldArbitraryDepth(item_val, options);
                    }
                    try container.end();
                },
                .pointer, .array => {
                    var container = try self.beginTuple(.{ .whitespace_style = .{ .fields = val.len } });
                    for (val) |item_val| {
                        try container.fieldArbitraryDepth(item_val, options);
                    }
                    try container.end();
                },
                else => comptime unreachable,
            }
        }

        /// Like `value`, but always serializes `val` as a string.
        pub fn string(self: *Self, val: []const u8) Writer.Error!void {
            try std.fmt.format(self.writer, "\"{}\"", .{std.zig.fmtEscapes(val)});
        }

        /// Options for formatting multiline strings.
        pub const MultilineStringOptions = struct {
            /// If top level is true, whitespace before and after the multiline string is elided.
            /// If it is true, a newline is printed, then the value, followed by a newline, and if
            /// whitespace is true any necessary indentation follows.
            top_level: bool = false,
        };

        /// Like `value`, but always serializes to a multiline string literal.
        ///
        /// Returns `error.InnerCarriageReturn` if `val` contains a CR not followed by a newline,
        /// since multiline strings cannot represent CR without a following newline.
        pub fn multilineString(
            self: *Self,
            val: []const u8,
            options: MultilineStringOptions,
        ) (Writer.Error || error{InnerCarriageReturn})!void {
            // Make sure the string does not contain any carriage returns not followed by a newline
            var i: usize = 0;
            while (i < val.len) : (i += 1) {
                if (val[i] == '\r') {
                    if (i + 1 < val.len) {
                        if (val[i + 1] == '\n') {
                            i += 1;
                            continue;
                        }
                    }
                    return error.InnerCarriageReturn;
                }
            }

            if (!options.top_level) {
                try self.newline();
                try self.indent();
            }

            try self.writer.writeAll("\\\\");
            for (val) |c| {
                if (c != '\r') {
                    try self.writer.writeByte(c); // We write newlines here even if whitespace off
                    if (c == '\n') {
                        try self.indent();
                        try self.writer.writeAll("\\\\");
                    }
                }
            }

            if (!options.top_level) {
                try self.writer.writeByte('\n'); // Even if whitespace off
                try self.indent();
            }
        }

        /// Create a `Struct` for writing ZON structs field by field.
        pub fn beginStruct(
            self: *Self,
            options: SerializeContainerOptions,
        ) Writer.Error!Struct {
            return Struct.begin(self, options);
        }

        /// Creates a `Tuple` for writing ZON tuples field by field.
        pub fn beginTuple(
            self: *Self,
            options: SerializeContainerOptions,
        ) Writer.Error!Tuple {
            return Tuple.begin(self, options);
        }

        fn indent(self: *Self) Writer.Error!void {
            if (self.options.whitespace) {
                try self.writer.writeByteNTimes(' ', 4 * self.indent_level);
            }
        }

        fn newline(self: *Self) Writer.Error!void {
            if (self.options.whitespace) {
                try self.writer.writeByte('\n');
            }
        }

        fn newlineOrSpace(self: *Self, len: usize) Writer.Error!void {
            if (self.containerShouldWrap(len)) {
                try self.newline();
            } else {
                try self.space();
            }
        }

        fn space(self: *Self) Writer.Error!void {
            if (self.options.whitespace) {
                try self.writer.writeByte(' ');
            }
        }

        /// Writes ZON tuples field by field.
        pub const Tuple = struct {
            container: Container,

            fn begin(parent: *Self, options: SerializeContainerOptions) Writer.Error!Tuple {
                return .{
                    .container = try Container.begin(parent, .anon, options),
                };
            }

            /// Finishes serializing the tuple.
            ///
            /// Prints a trailing comma as configured when appropriate, and the closing bracket.
            pub fn end(self: *Tuple) Writer.Error!void {
                try self.container.end();
                self.* = undefined;
            }

            /// Serialize a field. Equivalent to calling `fieldPrefix` followed by `value`.
            pub fn field(
                self: *Tuple,
                val: anytype,
                options: ValueOptions,
            ) Writer.Error!void {
                try self.container.field(null, val, options);
            }

            /// Serialize a field. Equivalent to calling `fieldPrefix` followed by `valueMaxDepth`.
            pub fn fieldMaxDepth(
                self: *Tuple,
                val: anytype,
                options: ValueOptions,
                depth: usize,
            ) (Writer.Error || error{ExceededMaxDepth})!void {
                try self.container.fieldMaxDepth(null, val, options, depth);
            }

            /// Serialize a field. Equivalent to calling `fieldPrefix` followed by
            /// `valueArbitraryDepth`.
            pub fn fieldArbitraryDepth(
                self: *Tuple,
                val: anytype,
                options: ValueOptions,
            ) Writer.Error!void {
                try self.container.fieldArbitraryDepth(null, val, options);
            }

            /// Starts a field with a struct as a value. Returns the struct.
            pub fn beginStructField(
                self: *Tuple,
                options: SerializeContainerOptions,
            ) Writer.Error!Struct {
                try self.fieldPrefix();
                return self.container.serializer.beginStruct(options);
            }

            /// Starts a field with a tuple as a value. Returns the tuple.
            pub fn beginTupleField(
                self: *Tuple,
               ```
