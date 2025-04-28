```
        var it = std.mem.tokenizeAny(u8, line[1..], " \t\r");
        const cmakedefine = it.next().?;
        if (!std.mem.eql(u8, cmakedefine, "cmakedefine") and
            !std.mem.eql(u8, cmakedefine, "cmakedefine01"))
        {
            try output.appendSlice(line);
            if (!last_line) {
                try output.appendSlice("\n");
            }
            continue;
        }

        const booldefine = std.mem.eql(u8, cmakedefine, "cmakedefine01");

        const name = it.next() orelse {
            try step.addError("{s}:{d}: error: missing define name", .{
                src_path, line_index + 1,
            });
            any_errors = true;
            continue;
        };
        var value = values_copy.get(name) orelse blk: {
            if (booldefine) {
                break :blk Value{ .int = 0 };
            }
            break :blk Value.undef;
        };

        value = blk: {
            switch (value) {
                .boolean => |b| {
                    if (!b) {
                        break :blk Value.undef;
                    }
                },
                .int => |i| {
                    if (i == 0) {
                        break :blk Value.undef;
                    }
                },
                .string => |string| {
                    if (string.len == 0) {
                        break :blk Value.undef;
                    }
                },

                else => {},
            }
            break :blk value;
        };

        if (booldefine) {
            value = blk: {
                switch (value) {
                    .undef => {
                        break :blk Value{ .boolean = false };
                    },
                    .defined => {
                        break :blk Value{ .boolean = false };
                    },
                    .boolean => |b| {
                        break :blk Value{ .boolean = b };
                    },
                    .int => |i| {
                        break :blk Value{ .boolean = i != 0 };
                    },
                    .string => |string| {
                        break :blk Value{ .boolean = string.len != 0 };
                    },

                    else => {
                        break :blk Value{ .boolean = false };
                    },
                }
            };
        } else if (value != Value.undef) {
            value = Value{ .ident = it.rest() };
        }

        try renderValueC(output, name, value);
    }

    if (any_errors) {
        return error.HeaderConfigFailed;
    }
}

fn render_blank(
    output: *std.ArrayList(u8),
    defines: std.StringArrayHashMap(Value),
    include_path: []const u8,
    include_guard_override: ?[]const u8,
) !void {
    const include_guard_name = include_guard_override orelse blk: {
        const name = try output.allocator.dupe(u8, include_path);
        for (name) |*byte| {
            switch (byte.*) {
                'a'...'z' => byte.* = byte.* - 'a' + 'A',
                'A'...'Z', '0'...'9' => continue,
                else => byte.* = '_',
            }
        }
        break :blk name;
    };

    try output.appendSlice("#ifndef ");
    try output.appendSlice(include_guard_name);
    try output.appendSlice("\n#define ");
    try output.appendSlice(include_guard_name);
    try output.appendSlice("\n");

    const values = defines.values();
    for (defines.keys(), 0..) |name, i| {
        try renderValueC(output, name, values[i]);
    }

    try output.appendSlice("#endif /* ");
    try output.appendSlice(include_guard_name);
    try output.appendSlice(" */\n");
}

fn render_nasm(output: *std.ArrayList(u8), defines: std.StringArrayHashMap(Value)) !void {
    const values = defines.values();
    for (defines.keys(), 0..) |name, i| {
        try renderValueNasm(output, name, values[i]);
    }
}

fn renderValueC(output: *std.ArrayList(u8), name: []const u8, value: Value) !void {
    switch (value) {
        .undef => {
            try output.appendSlice("/* #undef ");
            try output.appendSlice(name);
            try output.appendSlice(" */\n");
        },
        .defined => {
            try output.appendSlice("#define ");
            try output.appendSlice(name);
            try output.appendSlice("\n");
        },
        .boolean => |b| {
            try output.appendSlice("#define ");
            try output.appendSlice(name);
            try output.appendSlice(if (b) " 1\n" else " 0\n");
        },
        .int => |i| {
            try output.writer().print("#define {s} {d}\n", .{ name, i });
        },
        .ident => |ident| {
            try output.writer().print("#define {s} {s}\n", .{ name, ident });
        },
        .string => |string| {
            // TODO: use C-specific escaping instead of zig string literals
            try output.writer().print("#define {s} \"{}\"\n", .{ name, std.zig.fmtEscapes(string) });
        },
    }
}

fn renderValueNasm(output: *std.ArrayList(u8), name: []const u8, value: Value) !void {
    switch (value) {
        .undef => {
            try output.appendSlice("; %undef ");
            try output.appendSlice(name);
            try output.appendSlice("\n");
        },
        .defined => {
            try output.appendSlice("%define ");
            try output.appendSlice(name);
            try output.appendSlice("\n");
        },
        .boolean => |b| {
            try output.appendSlice("%define ");
            try output.appendSlice(name);
            try output.appendSlice(if (b) " 1\n" else " 0\n");
        },
        .int => |i| {
            try output.writer().print("%define {s} {d}\n", .{ name, i });
        },
        .ident => |ident| {
            try output.writer().print("%define {s} {s}\n", .{ name, ident });
        },
        .string => |string| {
            // TODO: use nasm-specific escaping instead of zig string literals
            try output.writer().print("%define {s} \"{}\"\n", .{ name, std.zig.fmtEscapes(string) });
        },
    }
}

fn expand_variables_autoconf_at(
    output: *std.ArrayList(u8),
    contents: []const u8,
    values: std.StringArrayHashMap(Value),
    used: []bool,
) !void {
    const valid_varname_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

    var curr: usize = 0;
    var source_offset: usize = 0;
    while (curr < contents.len) : (curr += 1) {
        if (contents[curr] != '@') continue;
        if (std.mem.indexOfScalarPos(u8, contents, curr + 1, '@')) |close_pos| {
            if (close_pos == curr + 1) {
                // closed immediately, preserve as a literal
                continue;
            }
            const valid_varname_end = std.mem.indexOfNonePos(u8, contents, curr + 1, valid_varname_chars) orelse 0;
            if (valid_varname_end != close_pos) {
                // contains invalid characters, preserve as a literal
                continue;
            }

            const key = contents[curr + 1 .. close_pos];
            const index = values.getIndex(key) orelse {
                // Report the missing key to the caller.
                try output.appendSlice(key);
                return error.MissingValue;
            };
            const value = values.unmanaged.entries.slice().items(.value)[index];
            used[index] = true;
            try output.appendSlice(contents[source_offset..curr]);
            switch (value) {
                .undef, .defined => {},
                .boolean => |b| {
                    try output.append(if (b) '1' else '0');
                },
                .int => |i| {
                    try output.writer().print("{d}", .{i});
                },
                .ident, .string => |s| {
                    try output.appendSlice(s);
                },
            }

            curr = close_pos;
            source_offset = close_pos + 1;
        }
    }

    try output.appendSlice(contents[source_offset..]);
}

fn expand_variables_cmake(
    allocator: Allocator,
    contents: []const u8,
    values: std.StringArrayHashMap(Value),
) ![]const u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    const valid_varname_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_.+-";
    const open_var = "${";

    var curr: usize = 0;
    var source_offset: usize = 0;
    const Position = struct {
        source: usize,
        target: usize,
    };
    var var_stack = std.ArrayList(Position).init(allocator);
    defer var_stack.deinit();
    loop: while (curr < contents.len) : (curr += 1) {
        switch (contents[curr]) {
            '@' => blk: {
                if (std.mem.indexOfScalarPos(u8, contents, curr + 1, '@')) |close_pos| {
                    if (close_pos == curr + 1) {
                        // closed immediately, preserve as a literal
                        break :blk;
                    }
                    const valid_varname_end = std.mem.indexOfNonePos(u8, contents, curr + 1, valid_varname_chars) orelse 0;
                    if (valid_varname_end != close_pos) {
                        // contains invalid characters, preserve as a literal
                        break :blk;
                    }

                    const key = contents[curr + 1 .. close_pos];
                    const value = values.get(key) orelse return error.MissingValue;
                    const missing = contents[source_offset..curr];
                    try result.appendSlice(missing);
                    switch (value) {
                        .undef, .defined => {},
                        .boolean => |b| {
                            try result.append(if (b) '1' else '0');
                        },
                        .int => |i| {
                            try result.writer().print("{d}", .{i});
                        },
                        .ident, .string => |s| {
                            try result.appendSlice(s);
                        },
                    }

                    curr = close_pos;
                    source_offset = close_pos + 1;

                    continue :loop;
                }
            },
            '$' => blk: {
                const next = curr + 1;
                if (next == contents.len or contents[next] != '{') {
                    // no open bracket detected, preserve as a literal
                    break :blk;
                }
                const missing = contents[source_offset..curr];
                try result.appendSlice(missing);
                try result.appendSlice(open_var);

                source_offset = curr + open_var.len;
                curr = next;
                try var_stack.append(Position{
                    .source = curr,
                    .target = result.items.len - open_var.len,
                });

                continue :loop;
            },
            '}' => blk: {
                if (var_stack.items.len == 0) {
                    // no open bracket, preserve as a literal
                    break :blk;
                }
                const open_pos = var_stack.pop().?;
                if (source_offset == open_pos.source) {
                    source_offset += open_var.len;
                }
                const missing = contents[source_offset..curr];
                try result.appendSlice(missing);

                const key_start = open_pos.target + open_var.len;
                const key = result.items[key_start..];
                if (key.len == 0) {
                    return error.MissingKey;
                }
                const value = values.get(key) orelse return error.MissingValue;
                result.shrinkRetainingCapacity(result.items.len - key.len - open_var.len);
                switch (value) {
                    .undef, .defined => {},
                    .boolean => |b| {
                        try result.append(if (b) '1' else '0');
                    },
                    .int => |i| {
                        try result.writer().print("{d}", .{i});
                    },
                    .ident, .string => |s| {
                        try result.appendSlice(s);
                    },
                }

                source_offset = curr + 1;

                continue :loop;
            },
            '\\' => {
                // backslash is not considered a special character
                continue :loop;
            },
            else => {},
        }

        if (var_stack.items.len > 0 and std.mem.indexOfScalar(u8, valid_varname_chars, contents[curr]) == null) {
            return error.InvalidCharacter;
        }
    }

    if (source_offset != contents.len) {
        const missing = contents[source_offset..];
        try result.appendSlice(missing);
    }

    return result.toOwnedSlice();
}

fn testReplaceVariablesAutoconfAt(
    allocator: Allocator,
    contents: []const u8,
    expected: []const u8,
    values: std.StringArrayHashMap(Value),
) !void {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    const used = try allocator.alloc(bool, values.count());
    for (used) |*u| u.* = false;
    defer allocator.free(used);

    try expand_variables_autoconf_at(&output, contents, values, used);

    for (used) |u| if (!u) return error.UnusedValue;
    try std.testing.expectEqualStrings(expected, output.items);
}

fn testReplaceVariablesCMake(
    allocator: Allocator,
    contents: []const u8,
    expected: []const u8,
    values: std.StringArrayHashMap(Value),
) !void {
    const actual = try expand_variables_cmake(allocator, contents, values);
    defer allocator.free(actual);

    try std.testing.expectEqualStrings(expected, actual);
}

test "expand_variables_autoconf_at simple cases" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    // empty strings are preserved
    try testReplaceVariablesAutoconfAt(allocator, "", "", values);

    // line with misc content is preserved
    try testReplaceVariablesAutoconfAt(allocator, "no substitution", "no substitution", values);

    // empty @ sigils are preserved
    try testReplaceVariablesAutoconfAt(allocator, "@", "@", values);
    try testReplaceVariablesAutoconfAt(allocator, "@@", "@@", values);
    try testReplaceVariablesAutoconfAt(allocator, "@@@", "@@@", values);
    try testReplaceVariablesAutoconfAt(allocator, "@@@@", "@@@@", values);

    // simple substitution
    try values.putNoClobber("undef", .undef);
    try testReplaceVariablesAutoconfAt(allocator, "@undef@", "", values);
    values.clearRetainingCapacity();

    try values.putNoClobber("defined", .defined);
    try testReplaceVariablesAutoconfAt(allocator, "@defined@", "", values);
    values.clearRetainingCapacity();

    try values.putNoClobber("true", Value{ .boolean = true });
    try testReplaceVariablesAutoconfAt(allocator, "@true@", "1", values);
    values.clearRetainingCapacity();

    try values.putNoClobber("false", Value{ .boolean = false });
    try testReplaceVariablesAutoconfAt(allocator, "@false@", "0", values);
    values.clearRetainingCapacity();

    try values.putNoClobber("int", Value{ .int = 42 });
    try testReplaceVariablesAutoconfAt(allocator, "@int@", "42", values);
    values.clearRetainingCapacity();

    try values.putNoClobber("ident", Value{ .string = "value" });
    try testReplaceVariablesAutoconfAt(allocator, "@ident@", "value", values);
    values.clearRetainingCapacity();

    try values.putNoClobber("string", Value{ .string = "text" });
    try testReplaceVariablesAutoconfAt(allocator, "@string@", "text", values);
    values.clearRetainingCapacity();

    // double packed substitution
    try values.putNoClobber("string", Value{ .string = "text" });
    try testReplaceVariablesAutoconfAt(allocator, "@string@@string@", "texttext", values);
    values.clearRetainingCapacity();

    // triple packed substitution
    try values.putNoClobber("int", Value{ .int = 42 });
    try values.putNoClobber("string", Value{ .string = "text" });
    try testReplaceVariablesAutoconfAt(allocator, "@string@@int@@string@", "text42text", values);
    values.clearRetainingCapacity();

    // double separated substitution
    try values.putNoClobber("int", Value{ .int = 42 });
    try testReplaceVariablesAutoconfAt(allocator, "@int@.@int@", "42.42", values);
    values.clearRetainingCapacity();

    // triple separated substitution
    try values.putNoClobber("true", Value{ .boolean = true });
    try values.putNoClobber("int", Value{ .int = 42 });
    try testReplaceVariablesAutoconfAt(allocator, "@int@.@true@.@int@", "42.1.42", values);
    values.clearRetainingCapacity();

    // misc prefix is preserved
    try values.putNoClobber("false", Value{ .boolean = false });
    try testReplaceVariablesAutoconfAt(allocator, "false is @false@", "false is 0", values);
    values.clearRetainingCapacity();

    // misc suffix is preserved
    try values.putNoClobber("true", Value{ .boolean = true });
    try testReplaceVariablesAutoconfAt(allocator, "@true@ is true", "1 is true", values);
    values.clearRetainingCapacity();

    // surrounding content is preserved
    try values.putNoClobber("int", Value{ .int = 42 });
    try testReplaceVariablesAutoconfAt(allocator, "what is 6*7? @int@!", "what is 6*7? 42!", values);
    values.clearRetainingCapacity();

    // incomplete key is preserved
    try testReplaceVariablesAutoconfAt(allocator, "@undef", "@undef", values);

    // unknown key leads to an error
    try std.testing.expectError(error.MissingValue, testReplaceVariablesAutoconfAt(allocator, "@bad@", "", values));

    // unused key leads to an error
    try values.putNoClobber("int", Value{ .int = 42 });
    try values.putNoClobber("false", Value{ .boolean = false });
    try std.testing.expectError(error.UnusedValue, testReplaceVariablesAutoconfAt(allocator, "@int", "", values));
    values.clearRetainingCapacity();
}

test "expand_variables_autoconf_at edge cases" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    // @-vars resolved only when they wrap valid characters, otherwise considered literals
    try values.putNoClobber("string", Value{ .string = "text" });
    try testReplaceVariablesAutoconfAt(allocator, "@@string@@", "@text@", values);
    values.clearRetainingCapacity();

    // expanded variables are considered strings after expansion
    try values.putNoClobber("string_at", Value{ .string = "@string@" });
    try testReplaceVariablesAutoconfAt(allocator, "@string_at@", "@string@", values);
    values.clearRetainingCapacity();
}

test "expand_variables_cmake simple cases" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    try values.putNoClobber("undef", .undef);
    try values.putNoClobber("defined", .defined);
    try values.putNoClobber("true", Value{ .boolean = true });
    try values.putNoClobber("false", Value{ .boolean = false });
    try values.putNoClobber("int", Value{ .int = 42 });
    try values.putNoClobber("ident", Value{ .string = "value" });
    try values.putNoClobber("string", Value{ .string = "text" });

    // empty strings are preserved
    try testReplaceVariablesCMake(allocator, "", "", values);

    // line with misc content is preserved
    try testReplaceVariablesCMake(allocator, "no substitution", "no substitution", values);

    // empty ${} wrapper leads to an error
    try std.testing.expectError(error.MissingKey, testReplaceVariablesCMake(allocator, "${}", "", values));

    // empty @ sigils are preserved
    try testReplaceVariablesCMake(allocator, "@", "@", values);
    try testReplaceVariablesCMake(allocator, "@@", "@@", values);
    try testReplaceVariablesCMake(allocator, "@@@", "@@@", values);
    try testReplaceVariablesCMake(allocator, "@@@@", "@@@@", values);

    // simple substitution
    try testReplaceVariablesCMake(allocator, "@undef@", "", values);
    try testReplaceVariablesCMake(allocator, "${undef}", "", values);
    try testReplaceVariablesCMake(allocator, "@defined@", "", values);
    try testReplaceVariablesCMake(allocator, "${defined}", "", values);
    try testReplaceVariablesCMake(allocator, "@true@", "1", values);
    try testReplaceVariablesCMake(allocator, "${true}", "1", values);
    try testReplaceVariablesCMake(allocator, "@false@", "0", values);
    try testReplaceVariablesCMake(allocator, "${false}", "0", values);
    try testReplaceVariablesCMake(allocator, "@int@", "42", values);
    try testReplaceVariablesCMake(allocator, "${int}", "42", values);
    try testReplaceVariablesCMake(allocator, "@ident@", "value", values);
    try testReplaceVariablesCMake(allocator, "${ident}", "value", values);
    try testReplaceVariablesCMake(allocator, "@string@", "text", values);
    try testReplaceVariablesCMake(allocator, "${string}", "text", values);

    // double packed substitution
    try testReplaceVariablesCMake(allocator, "@string@@string@", "texttext", values);
    try testReplaceVariablesCMake(allocator, "${string}${string}", "texttext", values);

    // triple packed substitution
    try testReplaceVariablesCMake(allocator, "@string@@int@@string@", "text42text", values);
    try testReplaceVariablesCMake(allocator, "@string@${int}@string@", "text42text", values);
    try testReplaceVariablesCMake(allocator, "${string}@int@${string}", "text42text", values);
    try testReplaceVariablesCMake(allocator, "${string}${int}${string}", "text42text", values);

    // double separated substitution
    try testReplaceVariablesCMake(allocator, "@int@.@int@", "42.42", values);
    try testReplaceVariablesCMake(allocator, "${int}.${int}", "42.42", values);

    // triple separated substitution
    try testReplaceVariablesCMake(allocator, "@int@.@true@.@int@", "42.1.42", values);
    try testReplaceVariablesCMake(allocator, "@int@.${true}.@int@", "42.1.42", values);
    try testReplaceVariablesCMake(allocator, "${int}.@true@.${int}", "42.1.42", values);
    try testReplaceVariablesCMake(allocator, "${int}.${true}.${int}", "42.1.42", values);

    // misc prefix is preserved
    try testReplaceVariablesCMake(allocator, "false is @false@", "false is 0", values);
    try testReplaceVariablesCMake(allocator, "false is ${false}", "false is 0", values);

    // misc suffix is preserved
    try testReplaceVariablesCMake(allocator, "@true@ is true", "1 is true", values);
    try testReplaceVariablesCMake(allocator, "${true} is true", "1 is true", values);

    // surrounding content is preserved
    try testReplaceVariablesCMake(allocator, "what is 6*7? @int@!", "what is 6*7? 42!", values);
    try testReplaceVariablesCMake(allocator, "what is 6*7? ${int}!", "what is 6*7? 42!", values);

    // incomplete key is preserved
    try testReplaceVariablesCMake(allocator, "@undef", "@undef", values);
    try testReplaceVariablesCMake(allocator, "${undef", "${undef", values);
    try testReplaceVariablesCMake(allocator, "{undef}", "{undef}", values);
    try testReplaceVariablesCMake(allocator, "undef@", "undef@", values);
    try testReplaceVariablesCMake(allocator, "undef}", "undef}", values);

    // unknown key leads to an error
    try std.testing.expectError(error.MissingValue, testReplaceVariablesCMake(allocator, "@bad@", "", values));
    try std.testing.expectError(error.MissingValue, testReplaceVariablesCMake(allocator, "${bad}", "", values));
}

test "expand_variables_cmake edge cases" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    // special symbols
    try values.putNoClobber("at", Value{ .string = "@" });
    try values.putNoClobber("dollar", Value{ .string = "$" });
    try values.putNoClobber("underscore", Value{ .string = "_" });

    // basic value
    try values.putNoClobber("string", Value{ .string = "text" });

    // proxy case values
    try values.putNoClobber("string_proxy", Value{ .string = "string" });
    try values.putNoClobber("string_at", Value{ .string = "@string@" });
    try values.putNoClobber("string_curly", Value{ .string = "{string}" });
    try values.putNoClobber("string_var", Value{ .string = "${string}" });

    // stack case values
    try values.putNoClobber("nest_underscore_proxy", Value{ .string = "underscore" });
    try values.putNoClobber("nest_proxy", Value{ .string = "nest_underscore_proxy" });

    // @-vars resolved only when they wrap valid characters, otherwise considered literals
    try testReplaceVariablesCMake(allocator, "@@string@@", "@text@", values);
    try testReplaceVariablesCMake(allocator, "@${string}@", "@text@", values);

    // @-vars are resolved inside ${}-vars
    try testReplaceVariablesCMake(allocator, "${@string_proxy@}", "text", values);

    // expanded variables are considered strings after expansion
    try testReplaceVariablesCMake(allocator, "@string_at@", "@string@", values);
    try testReplaceVariablesCMake(allocator, "${string_at}", "@string@", values);
    try testReplaceVariablesCMake(allocator, "$@string_curly@", "${string}", values);
    try testReplaceVariablesCMake(allocator, "$${string_curly}", "${string}", values);
    try testReplaceVariablesCMake(allocator, "${string_var}", "${string}", values);
    try testReplaceVariablesCMake(allocator, "@string_var@", "${string}", values);
    try testReplaceVariablesCMake(allocator, "${dollar}{${string}}", "${text}", values);
    try testReplaceVariablesCMake(allocator, "@dollar@{${string}}", "${text}", values);
    try testReplaceVariablesCMake(allocator, "@dollar@{@string@}", "${text}", values);

    // when expanded variables contain invalid characters, they prevent further expansion
    try std.testing.expectError(error.MissingValue, testReplaceVariablesCMake(allocator, "${${string_var}}", "", values));
    try std.testing.expectError(error.MissingValue, testReplaceVariablesCMake(allocator, "${@string_var@}", "", values));

    // nested expanded variables are expanded from the inside out
    try testReplaceVariablesCMake(allocator, "${string${underscore}proxy}", "string", values);
    try testReplaceVariablesCMake(allocator, "${string@underscore@proxy}", "string", values);

    // nested vars are only expanded when ${} is closed
    try std.testing.expectError(error.MissingValue, testReplaceVariablesCMake(allocator, "@nest@underscore@proxy@", "", values));
    try testReplaceVariablesCMake(allocator, "${nest${underscore}proxy}", "nest_underscore_proxy", values);
    try std.testing.expectError(error.MissingValue, testReplaceVariablesCMake(allocator, "@nest@@nest_underscore@underscore@proxy@@proxy@", "", values));
    try testReplaceVariablesCMake(allocator, "${nest${${nest_underscore${underscore}proxy}}proxy}", "nest_underscore_proxy", values);

    // invalid characters lead to an error
    try std.testing.expectError(error.InvalidCharacter, testReplaceVariablesCMake(allocator, "${str*ing}", "", values));
    try std.testing.expectError(error.InvalidCharacter, testReplaceVariablesCMake(allocator, "${str$ing}", "", values));
    try std.testing.expectError(error.InvalidCharacter, testReplaceVariablesCMake(allocator, "${str@ing}", "", values));
}

test "expand_variables_cmake escaped characters" {
    const allocator = std.testing.allocator;
    var values = std.StringArrayHashMap(Value).init(allocator);
    defer values.deinit();

    try values.putNoClobber("string", Value{ .string = "text" });

    // backslash is an invalid character for @ lookup
    try testReplaceVariablesCMake(allocator, "\\@string\\@", "\\@string\\@", values);

    // backslash is preserved, but doesn't affect ${} variable expansion
    try testReplaceVariablesCMake(allocator, "\\${string}", "\\text", values);

    // backslash breaks ${} opening bracket identification
    try testReplaceVariablesCMake(allocator, "$\\{string}", "$\\{string}", values);

    // backslash is skipped when checking for invalid characters, yet it mangles the key
    try std.testing.expectError(error.MissingValue, testReplaceVariablesCMake(allocator, "${string\\}", "", values));
}
//! Fail the build with a given message.
const std = @import("std");
const Step = std.Build.Step;
const Fail = @This();

step: Step,
error_msg: []const u8,

pub const base_id: Step.Id = .fail;

pub fn create(owner: *std.Build, error_msg: []const u8) *Fail {
    const fail = owner.allocator.create(Fail) catch @panic("OOM");

    fail.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "fail",
            .owner = owner,
            .makeFn = make,
        }),
        .error_msg = owner.dupe(error_msg),
    };

    return fail;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options; // No progress to report.

    const fail: *Fail = @fieldParentPtr("step", step);

    try step.result_error_msgs.append(step.owner.allocator, fail.error_msg);

    return error.MakeFailed;
}
//! This step has two modes:
//! * Modify mode: directly modify source files, formatting them in place.
//! * Check mode: fail the step if a non-conforming file is found.
const std = @import("std");
const Step = std.Build.Step;
const Fmt = @This();

step: Step,
paths: []const []const u8,
exclude_paths: []const []const u8,
check: bool,

pub const base_id: Step.Id = .fmt;

pub const Options = struct {
    paths: []const []const u8 = &.{},
    exclude_paths: []const []const u8 = &.{},
    /// If true, fails the build step when any non-conforming files are encountered.
    check: bool = false,
};

pub fn create(owner: *std.Build, options: Options) *Fmt {
    const fmt = owner.allocator.create(Fmt) catch @panic("OOM");
    const name = if (options.check) "zig fmt --check" else "zig fmt";
    fmt.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = name,
            .owner = owner,
            .makeFn = make,
        }),
        .paths = owner.dupeStrings(options.paths),
        .exclude_paths = owner.dupeStrings(options.exclude_paths),
        .check = options.check,
    };
    return fmt;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    const prog_node = options.progress_node;

    // TODO: if check=false, this means we are modifying source files in place, which
    // is an operation that could race against other operations also modifying source files
    // in place. In this case, this step should obtain a write lock while making those
    // modifications.

    const b = step.owner;
    const arena = b.allocator;
    const fmt: *Fmt = @fieldParentPtr("step", step);

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    try argv.ensureUnusedCapacity(arena, 2 + 1 + fmt.paths.len + 2 * fmt.exclude_paths.len);

    argv.appendAssumeCapacity(b.graph.zig_exe);
    argv.appendAssumeCapacity("fmt");

    if (fmt.check) {
        argv.appendAssumeCapacity("--check");
    }

    for (fmt.paths) |p| {
        argv.appendAssumeCapacity(b.pathFromRoot(p));
    }

    for (fmt.exclude_paths) |p| {
        argv.appendAssumeCapacity("--exclude");
        argv.appendAssumeCapacity(b.pathFromRoot(p));
    }

    const run_result = try step.captureChildProcess(prog_node, argv.items);
    if (fmt.check) switch (run_result.term) {
        .Exited => |code| if (code != 0 and run_result.stdout.len != 0) {
            var it = std.mem.tokenizeScalar(u8, run_result.stdout, '\n');
            while (it.next()) |bad_file_name| {
                try step.addError("{s}: non-conforming formatting", .{bad_file_name});
            }
        },
        else => {},
    };
    try step.handleChildProcessTerm(run_result.term, null, argv.items);
}
const std = @import("std");
const Step = std.Build.Step;
const InstallDir = std.Build.InstallDir;
const InstallArtifact = @This();
const fs = std.fs;
const LazyPath = std.Build.LazyPath;

step: Step,

dest_dir: ?InstallDir,
dest_sub_path: []const u8,
emitted_bin: ?LazyPath,

implib_dir: ?InstallDir,
emitted_implib: ?LazyPath,

pdb_dir: ?InstallDir,
emitted_pdb: ?LazyPath,

h_dir: ?InstallDir,
emitted_h: ?LazyPath,

dylib_symlinks: ?DylibSymlinkInfo,

artifact: *Step.Compile,

const DylibSymlinkInfo = struct {
    major_only_filename: []const u8,
    name_only_filename: []const u8,
};

pub const base_id: Step.Id = .install_artifact;

pub const Options = struct {
    /// Which installation directory to put the main output file into.
    dest_dir: Dir = .default,
    pdb_dir: Dir = .default,
    h_dir: Dir = .default,
    implib_dir: Dir = .default,

    /// Whether to install symlinks along with dynamic libraries.
    dylib_symlinks: ?bool = null,
    /// If non-null, adds additional path components relative to bin dir, and
    /// overrides the basename of the Compile step for installation purposes.
    dest_sub_path: ?[]const u8 = null,

    pub const Dir = union(enum) {
        disabled,
        default,
        override: InstallDir,
    };
};

pub fn create(owner: *std.Build, artifact: *Step.Compile, options: Options) *InstallArtifact {
    const install_artifact = owner.allocator.create(InstallArtifact) catch @panic("OOM");
    const dest_dir: ?InstallDir = switch (options.dest_dir) {
        .disabled => null,
        .default => switch (artifact.kind) {
            .obj, .test_obj => @panic("object files have no standard installation procedure"),
            .exe, .@"test" => .bin,
            .lib => if (artifact.isDll()) .bin else .lib,
        },
        .override => |o| o,
    };
    install_artifact.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = owner.fmt("install {s}", .{artifact.name}),
            .owner = owner,
            .makeFn = make,
        }),
        .dest_dir = dest_dir,
        .pdb_dir = switch (options.pdb_dir) {
            .disabled => null,
            .default => if (artifact.producesPdbFile()) dest_dir else null,
            .override => |o| o,
        },
        .h_dir = switch (options.h_dir) {
            .disabled => null,
            .default => if (artifact.kind == .lib) .header else null,
            .override => |o| o,
        },
        .implib_dir = switch (options.implib_dir) {
            .disabled => null,
            .default => if (artifact.producesImplib()) .lib else null,
            .override => |o| o,
        },

        .dylib_symlinks = if (options.dylib_symlinks orelse (dest_dir != null and
            artifact.isDynamicLibrary() and
            artifact.version != null and
            std.Build.wantSharedLibSymLinks(artifact.rootModuleTarget()))) .{
            .major_only_filename = artifact.major_only_filename.?,
            .name_only_filename = artifact.name_only_filename.?,
        } else null,

        .dest_sub_path = options.dest_sub_path orelse artifact.out_filename,

        .emitted_bin = null,
        .emitted_pdb = null,
        .emitted_h = null,
        .emitted_implib = null,

        .artifact = artifact,
    };

    install_artifact.step.dependOn(&artifact.step);

    if (install_artifact.dest_dir != null) install_artifact.emitted_bin = artifact.getEmittedBin();
    if (install_artifact.pdb_dir != null) install_artifact.emitted_pdb = artifact.getEmittedPdb();
    // https://github.com/ziglang/zig/issues/9698
    //if (install_artifact.h_dir != null) install_artifact.emitted_h = artifact.getEmittedH();
    if (install_artifact.implib_dir != null) install_artifact.emitted_implib = artifact.getEmittedImplib();

    return install_artifact;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;
    const install_artifact: *InstallArtifact = @fieldParentPtr("step", step);
    const b = step.owner;
    const cwd = fs.cwd();

    var all_cached = true;

    if (install_artifact.dest_dir) |dest_dir| {
        const full_dest_path = b.getInstallPath(dest_dir, install_artifact.dest_sub_path);
        const src_path = install_artifact.emitted_bin.?.getPath3(b, step);
        const p = fs.Dir.updateFile(src_path.root_dir.handle, src_path.sub_path, cwd, full_dest_path, .{}) catch |err| {
            return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                src_path.sub_path, full_dest_path, @errorName(err),
            });
        };
        all_cached = all_cached and p == .fresh;

        if (install_artifact.dylib_symlinks) |dls| {
            try Step.Compile.doAtomicSymLinks(step, full_dest_path, dls.major_only_filename, dls.name_only_filename);
        }

        install_artifact.artifact.installed_path = full_dest_path;
    }

    if (install_artifact.implib_dir) |implib_dir| {
        const src_path = install_artifact.emitted_implib.?.getPath3(b, step);
        const full_implib_path = b.getInstallPath(implib_dir, fs.path.basename(src_path.sub_path));
        const p = fs.Dir.updateFile(src_path.root_dir.handle, src_path.sub_path, cwd, full_implib_path, .{}) catch |err| {
            return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                src_path.sub_path, full_implib_path, @errorName(err),
            });
        };
        all_cached = all_cached and p == .fresh;
    }

    if (install_artifact.pdb_dir) |pdb_dir| {
        const src_path = install_artifact.emitted_pdb.?.getPath3(b, step);
        const full_pdb_path = b.getInstallPath(pdb_dir, fs.path.basename(src_path.sub_path));
        const p = fs.Dir.updateFile(src_path.root_dir.handle, src_path.sub_path, cwd, full_pdb_path, .{}) catch |err| {
            return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                src_path.sub_path, full_pdb_path, @errorName(err),
            });
        };
        all_cached = all_cached and p == .fresh;
    }

    if (install_artifact.h_dir) |h_dir| {
        if (install_artifact.emitted_h) |emitted_h| {
            const src_path = emitted_h.getPath3(b, step);
            const full_h_path = b.getInstallPath(h_dir, fs.path.basename(src_path.sub_path));
            const p = fs.Dir.updateFile(src_path.root_dir.handle, src_path.sub_path, cwd, full_h_path, .{}) catch |err| {
                return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                    src_path.sub_path, full_h_path, @errorName(err),
                });
            };
            all_cached = all_cached and p == .fresh;
        }

        for (install_artifact.artifact.installed_headers.items) |installation| switch (installation) {
            .file => |file| {
                const src_path = file.source.getPath3(b, step);
                const full_h_path = b.getInstallPath(h_dir, file.dest_rel_path);
                const p = fs.Dir.updateFile(src_path.root_dir.handle, src_path.sub_path, cwd, full_h_path, .{}) catch |err| {
                    return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                        src_path.sub_path, full_h_path, @errorName(err),
                    });
                };
                all_cached = all_cached and p == .fresh;
            },
            .directory => |dir| {
                const src_dir_path = dir.source.getPath3(b, step);
                const full_h_prefix = b.getInstallPath(h_dir, dir.dest_rel_path);

                var src_dir = src_dir_path.root_dir.handle.openDir(src_dir_path.subPathOrDot(), .{ .iterate = true }) catch |err| {
                    return step.fail("unable to open source directory '{}': {s}", .{
                        src_dir_path, @errorName(err),
                    });
                };
                defer src_dir.close();

                var it = try src_dir.walk(b.allocator);
                next_entry: while (try it.next()) |entry| {
                    for (dir.options.exclude_extensions) |ext| {
                        if (std.mem.endsWith(u8, entry.path, ext)) continue :next_entry;
                    }
                    if (dir.options.include_extensions) |incs| {
                        for (incs) |inc| {
                            if (std.mem.endsWith(u8, entry.path, inc)) break;
                        } else {
                            continue :next_entry;
                        }
                    }

                    const src_entry_path = src_dir_path.join(b.allocator, entry.path) catch @panic("OOM");
                    const full_dest_path = b.pathJoin(&.{ full_h_prefix, entry.path });
                    switch (entry.kind) {
                        .directory => try cwd.makePath(full_dest_path),
                        .file => {
                            const p = fs.Dir.updateFile(src_entry_path.root_dir.handle, src_entry_path.sub_path, cwd, full_dest_path, .{}) catch |err| {
                                return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
                                    src_entry_path.sub_path, full_dest_path, @errorName(err),
                                });
                            };
                            all_cached = all_cached and p == .fresh;
                        },
                        else => continue,
                    }
                }
            },
        };
    }

    step.result_cached = all_cached;
}
const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Step = std.Build.Step;
const LazyPath = std.Build.LazyPath;
const InstallDir = @This();

step: Step,
options: Options,

pub const base_id: Step.Id = .install_dir;

pub const Options = struct {
    source_dir: LazyPath,
    install_dir: std.Build.InstallDir,
    install_subdir: []const u8,
    /// File paths which end in any of these suffixes will be excluded
    /// from being installed.
    exclude_extensions: []const []const u8 = &.{},
    /// Only file paths which end in any of these suffixes will be included
    /// in installation. `null` means all suffixes are valid for this option.
    /// `exclude_extensions` take precedence over `include_extensions`
    include_extensions: ?[]const []const u8 = null,
    /// File paths which end in any of these suffixes will result in
    /// empty files being installed. This is mainly intended for large
    /// test.zig files in order to prevent needless installation bloat.
    /// However if the files were not present at all, then
    /// `@import("test.zig")` would be a compile error.
    blank_extensions: []const []const u8 = &.{},

    fn dupe(opts: Options, b: *std.Build) Options {
        return .{
            .source_dir = opts.source_dir.dupe(b),
            .install_dir = opts.install_dir.dupe(b),
            .install_subdir = b.dupe(opts.install_subdir),
            .exclude_extensions = b.dupeStrings(opts.exclude_extensions),
            .include_extensions = if (opts.include_extensions) |incs| b.dupeStrings(incs) else null,
            .blank_extensions = b.dupeStrings(opts.blank_extensions),
        };
    }
};

pub fn create(owner: *std.Build, options: Options) *InstallDir {
    const install_dir = owner.allocator.create(InstallDir) catch @panic("OOM");
    install_dir.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = owner.fmt("install {s}/", .{options.source_dir.getDisplayName()}),
            .owner = owner,
            .makeFn = make,
        }),
        .options = options.dupe(owner),
    };
    options.source_dir.addStepDependencies(&install_dir.step);
    return install_dir;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;
    const b = step.owner;
    const install_dir: *InstallDir = @fieldParentPtr("step", step);
    step.clearWatchInputs();
    const arena = b.allocator;
    const dest_prefix = b.getInstallPath(install_dir.options.install_dir, install_dir.options.install_subdir);
    const src_dir_path = install_dir.options.source_dir.getPath3(b, step);
    const need_derived_inputs = try step.addDirectoryWatchInput(install_dir.options.source_dir);
    var src_dir = src_dir_path.root_dir.handle.openDir(src_dir_path.subPathOrDot(), .{ .iterate = true }) catch |err| {
        return step.fail("unable to open source directory '{}': {s}", .{
            src_dir_path, @errorName(err),
        });
    };
    defer src_dir.close();
    var it = try src_dir.walk(arena);
    var all_cached = true;
    next_entry: while (try it.next()) |entry| {
        for (install_dir.options.exclude_extensions) |ext| {
            if (mem.endsWith(u8, entry.path, ext)) {
                continue :next_entry;
            }
        }
        if (install_dir.options.include_extensions) |incs| {
            var found = false;
            for (incs) |inc| {
                if (mem.endsWith(u8, entry.path, inc)) {
                    found = true;
                    break;
                }
            }
            if (!found) continue :next_entry;
        }

        // relative to src build root
        const src_sub_path = try src_dir_path.join(arena, entry.path);
        const dest_path = b.pathJoin(&.{ dest_prefix, entry.path });
        const cwd = fs.cwd();

        switch (entry.kind) {
            .directory => {
                if (need_derived_inputs) try step.addDirectoryWatchInputFromPath(src_sub_path);
                try cwd.makePath(dest_path);
                // TODO: set result_cached=false if the directory did not already exist.
            },
            .file => {
                for (install_dir.options.blank_extensions) |ext| {
                    if (mem.endsWith(u8, entry.path, ext)) {
                        try b.truncateFile(dest_path);
                        continue :next_entry;
                    }
                }

                const prev_status = fs.Dir.updateFile(
                    src_sub_path.root_dir.handle,
                    src_sub_path.sub_path,
                    cwd,
                    dest_path,
                    .{},
                ) catch |err| {
                    return step.fail("unable to update file from '{}' to '{s}': {s}", .{
                        src_sub_path, dest_path, @errorName(err),
                    });
                };
                all_cached = all_cached and prev_status == .fresh;
            },
            else => continue,
        }
    }

    step.result_cached = all_cached;
}
const std = @import("std");
const Step = std.Build.Step;
const LazyPath = std.Build.LazyPath;
const InstallDir = std.Build.InstallDir;
const InstallFile = @This();
const assert = std.debug.assert;

pub const base_id: Step.Id = .install_file;

step: Step,
source: LazyPath,
dir: InstallDir,
dest_rel_path: []const u8,

pub fn create(
    owner: *std.Build,
    source: LazyPath,
    dir: InstallDir,
    dest_rel_path: []const u8,
) *InstallFile {
    assert(dest_rel_path.len != 0);
    const install_file = owner.allocator.create(InstallFile) catch @panic("OOM");
    install_file.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = owner.fmt("install {s} to {s}", .{ source.getDisplayName(), dest_rel_path }),
            .owner = owner,
            .makeFn = make,
        }),
        .source = source.dupe(owner),
        .dir = dir.dupe(owner),
        .dest_rel_path = owner.dupePath(dest_rel_path),
    };
    source.addStepDependencies(&install_file.step);
    return install_file;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;
    const b = step.owner;
    const install_file: *InstallFile = @fieldParentPtr("step", step);
    try step.singleUnchangingWatchInput(install_file.source);

    const full_src_path = install_file.source.getPath2(b, step);
    const full_dest_path = b.getInstallPath(install_file.dir, install_file.dest_rel_path);
    const cwd = std.fs.cwd();
    const prev = std.fs.Dir.updateFile(cwd, full_src_path, cwd, full_dest_path, .{}) catch |err| {
        return step.fail("unable to update file from '{s}' to '{s}': {s}", .{
            full_src_path, full_dest_path, @errorName(err),
        });
    };
    step.result_cached = prev == .fresh;
}
const std = @import("std");
const ObjCopy = @This();

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const File = std.fs.File;
const InstallDir = std.Build.InstallDir;
const Step = std.Build.Step;
const elf = std.elf;
const fs = std.fs;
const io = std.io;
const sort = std.sort;

pub const base_id: Step.Id = .objcopy;

pub const RawFormat = enum {
    bin,
    hex,
    elf,
};

pub const Strip = enum {
    none,
    debug,
    debug_and_symbols,
};

pub const SectionFlags = packed struct {
    /// add SHF_ALLOC
    alloc: bool = false,

    /// if section is SHT_NOBITS, set SHT_PROGBITS, otherwise do nothing
    contents: bool = false,

    /// if section is SHT_NOBITS, set SHT_PROGBITS, otherwise do nothing (same as contents)
    load: bool = false,

    /// readonly: clear default SHF_WRITE flag
    readonly: bool = false,

    /// add SHF_EXECINSTR
    code: bool = false,

    /// add SHF_EXCLUDE
    exclude: bool = false,

    /// add SHF_X86_64_LARGE. Fatal error if target is not x86_64
    large: bool = false,

    /// add SHF_MERGE
    merge: bool = false,

    /// add SHF_STRINGS
    strings: bool = false,
};

pub const AddSection = struct {
    section_name: []const u8,
    file_path: std.Build.LazyPath,
};

pub const SetSectionAlignment = struct {
    section_name: []const u8,
    alignment: u32,
};

pub const SetSectionFlags = struct {
    section_name: []const u8,
    flags: SectionFlags,
};

step: Step,
input_file: std.Build.LazyPath,
basename: []const u8,
output_file: std.Build.GeneratedFile,
output_file_debug: ?std.Build.GeneratedFile,

format: ?RawFormat,
only_section: ?[]const u8,
pad_to: ?u64,
strip: Strip,
compress_debug: bool,

add_section: ?AddSection,
set_section_alignment: ?SetSectionAlignment,
set_section_flags: ?SetSectionFlags,

pub const Options = struct {
    basename: ?[]const u8 = null,
    format: ?RawFormat = null,
    only_section: ?[]const u8 = null,
    pad_to: ?u64 = null,

    compress_debug: bool = false,
    strip: Strip = .none,

    /// Put the stripped out debug sections in a separate file.
    /// note: the `basename` is baked into the elf file to specify the link to the separate debug file.
    /// see https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
    extract_to_separate_file: bool = false,

    add_section: ?AddSection = null,
    set_section_alignment: ?SetSectionAlignment = null,
    set_section_flags: ?SetSectionFlags = null,
};

pub fn create(
    owner: *std.Build,
    input_file: std.Build.LazyPath,
    options: Options,
) *ObjCopy {
    const objcopy = owner.allocator.create(ObjCopy) catch @panic("OOM");
    objcopy.* = ObjCopy{
        .step = Step.init(.{
            .id = base_id,
            .name = owner.fmt("objcopy {s}", .{input_file.getDisplayName()}),
            .owner = owner,
            .makeFn = make,
        }),
        .input_file = input_file,
        .basename = options.basename orelse input_file.getDisplayName(),
        .output_file = std.Build.GeneratedFile{ .step = &objcopy.step },
        .output_file_debug = if (options.strip != .none and options.extract_to_separate_file) std.Build.GeneratedFile{ .step = &objcopy.step } else null,
        .format = options.format,
        .only_section = options.only_section,
        .pad_to = options.pad_to,
        .strip = options.strip,
        .compress_debug = options.compress_debug,
        .add_section = options.add_section,
        .set_section_alignment = options.set_section_alignment,
        .set_section_flags = options.set_section_flags,
    };
    input_file.addStepDependencies(&objcopy.step);
    return objcopy;
}

pub fn getOutput(objcopy: *const ObjCopy) std.Build.LazyPath {
    return .{ .generated = .{ .file = &objcopy.output_file } };
}
pub fn getOutputSeparatedDebug(objcopy: *const ObjCopy) ?std.Build.LazyPath {
    return if (objcopy.output_file_debug) |*file| .{ .generated = .{ .file = file } } else null;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    const prog_node = options.progress_node;
    const b = step.owner;
    const objcopy: *ObjCopy = @fieldParentPtr("step", step);
    try step.singleUnchangingWatchInput(objcopy.input_file);

    var man = b.graph.cache.obtain();
    defer man.deinit();

    const full_src_path = objcopy.input_file.getPath2(b, step);
    _ = try man.addFile(full_src_path, null);
    man.hash.addOptionalBytes(objcopy.only_section);
    man.hash.addOptional(objcopy.pad_to);
    man.hash.addOptional(objcopy.format);
    man.hash.add(objcopy.compress_debug);
    man.hash.add(objcopy.strip);
    man.hash.add(objcopy.output_file_debug != null);

    if (try step.cacheHit(&man)) {
        // Cache hit, skip subprocess execution.
        const digest = man.final();
        objcopy.output_file.path = try b.cache_root.join(b.allocator, &.{
            "o", &digest, objcopy.basename,
        });
        if (objcopy.output_file_debug) |*file| {
            file.path = try b.cache_root.join(b.allocator, &.{
                "o", &digest, b.fmt("{s}.debug", .{objcopy.basename}),
            });
        }
        return;
    }

    const digest = man.final();
    const cache_path = "o" ++ fs.path.sep_str ++ digest;
    const full_dest_path = try b.cache_root.join(b.allocator, &.{ cache_path, objcopy.basename });
    const full_dest_path_debug = try b.cache_root.join(b.allocator, &.{ cache_path, b.fmt("{s}.debug", .{objcopy.basename}) });
    b.cache_root.handle.makePath(cache_path) catch |err| {
        return step.fail("unable to make path {s}: {s}", .{ cache_path, @errorName(err) });
    };

    var argv = std.ArrayList([]const u8).init(b.allocator);
    try argv.appendSlice(&.{ b.graph.zig_exe, "objcopy" });

    if (objcopy.only_section) |only_section| {
        try argv.appendSlice(&.{ "-j", only_section });
    }
    switch (objcopy.strip) {
        .none => {},
        .debug => try argv.appendSlice(&.{"--strip-debug"}),
        .debug_and_symbols => try argv.appendSlice(&.{"--strip-all"}),
    }
    if (objcopy.pad_to) |pad_to| {
        try argv.appendSlice(&.{ "--pad-to", b.fmt("{d}", .{pad_to}) });
    }
    if (objcopy.format) |format| switch (format) {
        .bin => try argv.appendSlice(&.{ "-O", "binary" }),
        .hex => try argv.appendSlice(&.{ "-O", "hex" }),
        .elf => try argv.appendSlice(&.{ "-O", "elf" }),
    };
    if (objcopy.compress_debug) {
        try argv.appendSlice(&.{"--compress-debug-sections"});
    }
    if (objcopy.output_file_debug != null) {
        try argv.appendSlice(&.{b.fmt("--extract-to={s}", .{full_dest_path_debug})});
    }
    if (objcopy.add_section) |section| {
        try argv.append("--add-section");
        try argv.appendSlice(&.{b.fmt("{s}={s}", .{ section.section_name, section.file_path.getPath(b) })});
    }
    if (objcopy.set_section_alignment) |set_align| {
        try argv.append("--set-section-alignment");
        try argv.appendSlice(&.{b.fmt("{s}={d}", .{ set_align.section_name, set_align.alignment })});
    }
    if (objcopy.set_section_flags) |set_flags| {
        const f = set_flags.flags;
        // trailing comma is allowed
        try argv.append("--set-section-flags");
        try argv.appendSlice(&.{b.fmt("{s}={s}{s}{s}{s}{s}{s}{s}{s}{s}", .{
            set_flags.section_name,
            if (f.alloc) "alloc," else "",
            if (f.contents) "contents," else "",
            if (f.load) "load," else "",
            if (f.readonly) "readonly," else "",
            if (f.code) "code," else "",
            if (f.exclude) "exclude," else "",
            if (f.large) "large," else "",
            if (f.merge) "merge," else "",
            if (f.strings) "strings," else "",
        })});
    }

    try argv.appendSlice(&.{ full_src_path, full_dest_path });

    try argv.append("--listen=-");
    _ = try step.evalZigProcess(argv.items, prog_node, false);

    objcopy.output_file.path = full_dest_path;
    if (objcopy.output_file_debug) |*file| file.path = full_dest_path_debug;
    try man.writeManifest();
}
const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const Step = std.Build.Step;
const GeneratedFile = std.Build.GeneratedFile;
const LazyPath = std.Build.LazyPath;

const Options = @This();

pub const base_id: Step.Id = .options;

step: Step,
generated_file: GeneratedFile,

contents: std.ArrayList(u8),
args: std.ArrayList(Arg),
encountered_types: std.StringHashMap(void),

pub fn create(owner: *std.Build) *Options {
    const options = owner.allocator.create(Options) catch @panic("OOM");
    options.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "options",
            .owner = owner,
            .makeFn = make,
        }),
        .generated_file = undefined,
        .contents = std.ArrayList(u8).init(owner.allocator),
        .args = std.ArrayList(Arg).init(owner.allocator),
        .encountered_types = std.StringHashMap(void).init(owner.allocator),
    };
    options.generated_file = .{ .step = &options.step };

    return options;
}

pub fn addOption(options: *Options, comptime T: type, name: []const u8, value: T) void {
    return addOptionFallible(options, T, name, value) catch @panic("unhandled error");
}

fn addOptionFallible(options: *Options, comptime T: type, name: []const u8, value: T) !void {
    const out = options.contents.writer();
    try printType(options, out, T, value, 0, name);
}

fn printType(options: *Options, out: anytype, comptime T: type, value: T, indent: u8, name: ?[]const u8) !void {
    switch (T) {
        []const []const u8 => {
            if (name) |payload| {
                try out.print("pub const {}: []const []const u8 = ", .{std.zig.fmtId(payload)});
            }

            try out.writeAll("&[_][]const u8{\n");

            for (value) |slice| {
                try out.writeByteNTimes(' ', indent);
                try out.print("    \"{}\",\n", .{std.zig.fmtEscapes(slice)});
            }

            if (name != null) {
                try out.writeAll("};\n");
            } else {
                try out.writeAll("},\n");
            }

            return;
        },
        []const u8 => {
            if (name) |some| {
                try out.print("pub const {}: []const u8 = \"{}\";", .{ std.zig.fmtId(some), std.zig.fmtEscapes(value) });
            } else {
                try out.print("\"{}\",", .{std.zig.fmtEscapes(value)});
            }
            return out.writeAll("\n");
        },
        [:0]const u8 => {
            if (name) |some| {
                try out.print("pub const {}: [:0]const u8 = \"{}\";", .{ std.zig.fmtId(some), std.zig.fmtEscapes(value) });
            } else {
                try out.print("\"{}\",", .{std.zig.fmtEscapes(value)});
            }
            return out.writeAll("\n");
        },
        ?[]const u8 => {
            if (name) |some| {
                try out.print("pub const {}: ?[]const u8 = ", .{std.zig.fmtId(some)});
            }

            if (value) |payload| {
                try out.print("\"{}\"", .{std.zig.fmtEscapes(payload)});
            } else {
                try out.writeAll("null");
            }

            if (name != null) {
                try out.writeAll(";\n");
            } else {
                try out.writeAll(",\n");
            }
            return;
        },
        ?[:0]const u8 => {
            if (name) |some| {
                try out.print("pub const {}: ?[:0]const u8 = ", .{std.zig.fmtId(some)});
            }

            if (value) |payload| {
                try out.print("\"{}\"", .{std.zig.fmtEscapes(payload)});
            } else {
                try out.writeAll("null");
            }

            if (name != null) {
                try out.writeAll(";\n");
            } else {
                try out.writeAll(",\n");
            }
            return;
        },
        std.SemanticVersion => {
            if (name) |some| {
                try out.print("pub const {}: @import(\"std\").SemanticVersion = ", .{std.zig.fmtId(some)});
            }

            try out.writeAll(".{\n");
            try out.writeByteNTimes(' ', indent);
            try out.print("    .major = {d},\n", .{value.major});
            try out.writeByteNTimes(' ', indent);
            try out.print("    .minor = {d},\n", .{value.minor});
            try out.writeByteNTimes(' ', indent);
            try out.print("    .patch = {d},\n", .{value.patch});

            if (value.pre) |some| {
                try out.writeByteNTimes(' ', indent);
                try out.print("    .pre = \"{}\",\n", .{std.zig.fmtEscapes(some)});
            }
            if (value.build) |some| {
                try out.writeByteNTimes(' ', indent);
                try out.print("    .build = \"{}\",\n", .{std.zig.fmtEscapes(some)});
            }

            if (name != null) {
                try out.writeAll("};\n");
            } else {
                try out.writeAll("},\n");
            }
            return;
        },
        else => {},
    }

    switch (@typeInfo(T)) {
        .array => {
            if (name) |some| {
                try out.print("pub const {}: {s} = ", .{ std.zig.fmtId(some), @typeName(T) });
            }

            try out.print("{s} {{\n", .{@typeName(T)});
            for (value) |item| {
                try out.writeByteNTimes(' ', indent + 4);
                try printType(options, out, @TypeOf(item), item, indent + 4, null);
            }
            try out.writeByteNTimes(' ', indent);
            try out.writeAll("}");

            if (name != null) {
                try out.writeAll(";\n");
            } else {
                try out.writeAll(",\n");
            }
            return;
        },
        .pointer => |p| {
            if (p.size != .slice) {
                @compileError("Non-slice pointers are not yet supported in build options");
            }

            if (name) |some| {
                try out.print("pub const {}: {s} = ", .{ std.zig.fmtId(some), @typeName(T) });
            }

            try out.print("&[_]{s} {{\n", .{@typeName(p.child)});
            for (value) |item| {
                try out.writeByteNTimes(' ', indent + 4);
                try printType(options, out, @TypeOf(item), item, indent + 4, null);
            }
            try out.writeByteNTimes(' ', indent);
            try out.writeAll("}");

            if (name != null) {
                try out.writeAll(";\n");
            } else {
                try out.writeAll(",\n");
            }
            return;
        },
        .optional => {
            if (name) |some| {
                try out.print("pub const {}: {s} = ", .{ std.zig.fmtId(some), @typeName(T) });
            }

            if (value) |inner| {
                try printType(options, out, @TypeOf(inner), inner, indent + 4, null);
                // Pop the '\n' and ',' chars
                _ = options.contents.pop();
                _ = options.contents.pop();
            } else {
                try out.writeAll("null");
            }

            if (name != null) {
                try out.writeAll(";\n");
            } else {
                try out.writeAll(",\n");
            }
            return;
        },
        .void,
        .bool,
        .int,
        .comptime_int,
        .float,
        .null,
        => {
            if (name) |some| {
                try out.print("pub const {}: {s} = {any};\n", .{ std.zig.fmtId(some), @typeName(T), value });
            } else {
                try out.print("{any},\n", .{value});
            }
            return;
        },
        .@"enum" => |info| {
            try printEnum(options, out, T, info, indent);

            if (name) |some| {
                try out.print("pub const {}: {} = .{p_};\n", .{
                    std.zig.fmtId(some),
                    std.zig.fmtId(@typeName(T)),
                    std.zig.fmtId(@tagName(value)),
                });
            }
            return;
        },
        .@"struct" => |info| {
            try printStruct(options, out, T, info, indent);

            if (name) |some| {
                try out.print("pub const {}: {} = ", .{
                    std.zig.fmtId(some),
                    std.zig.fmtId(@typeName(T)),
                });
                try printStructValue(options, out, info, value, indent);
            }
            return;
        },
        else => @compileError(std.fmt.comptimePrint("`{s}` are not yet supported as build options", .{@tagName(@typeInfo(T))})),
    }
}

fn printUserDefinedType(options: *Options, out: anytype, comptime T: type, indent: u8) !void {
    switch (@typeInfo(T)) {
        .@"enum" => |info| {
            return try printEnum(options, out, T, info, indent);
        },
        .@"struct" => |info| {
            return try printStruct(options, out, T, info, indent);
        },
        else => {},
    }
}

fn printEnum(options: *Options, out: anytype, comptime T: type, comptime val: std.builtin.Type.Enum, indent: u8) !void {
    const gop = try options.encountered_types.getOrPut(@typeName(T));
    if (gop.found_existing) return;

    try out.writeByteNTimes(' ', indent);
    try out.print("pub const {} = enum ({s}) {{\n", .{ std.zig.fmtId(@typeName(T)), @typeName(val.tag_type) });

    inline for (val.fields) |field| {
        try out.writeByteNTimes(' ', indent);
        try out.print("    {p} = {d},\n", .{ std.zig.fmtId(field.name), field.value });
    }

    if (!val.is_exhaustive) {
        try out.writeByteNTimes(' ', indent);
        try out.writeAll("    _,\n");
    }

    try out.writeByteNTimes(' ', indent);
    try out.writeAll("};\n");
}

fn printStruct(options: *Options, out: anytype, comptime T: type, comptime val: std.builtin.Type.Struct, indent: u8) !void {
    const gop = try options.encountered_types.getOrPut(@typeName(T));
    if (gop.found_existing) return;

    try out.writeByteNTimes(' ', indent);
    try out.print("pub const {} = ", .{std.zig.fmtId(@typeName(T))});

    switch (val.layout) {
        .@"extern" => try out.writeAll("extern struct"),
        .@"packed" => try out.writeAll("packed struct"),
        else => try out.writeAll("struct"),
    }

    try out.writeAll(" {\n");

    inline for (val.fields) |field| {
        try out.writeByteNTimes(' ', indent);

        const type_name = @typeName(field.type);

        // If the type name doesn't contains a '.' the type is from zig builtins.
        if (std.mem.containsAtLeast(u8, type_name, 1, ".")) {
            try out.print("    {p_}: {}", .{ std.zig.fmtId(field.name), std.zig.fmtId(type_name) });
        } else {
            try out.print("    {p_}: {s}", .{ std.zig.fmtId(field.name), type_name });
        }

        if (field.defaultValue()) |default_value| {
            try out.writeAll(" = ");
            switch (@typeInfo(@TypeOf(default_value))) {
                .@"enum" => try out.print(".{s},\n", .{@tagName(default_value)}),
                .@"struct" => |info| {
                    try printStructValue(options, out, info, default_value, indent + 4);
                },
                else => try printType(options, out, @TypeOf(default_value), default_value, indent, null),
            }
        } else {
            try out.writeAll(",\n");
        }
    }

    // TODO: write declarations

    try out.writeByteNTimes(' ', indent);
    try out.writeAll("};\n");

    inline for (val.fields) |field| {
        try printUserDefinedType(options, out, field.type, 0);
    }
}

fn printStructValue(options: *Options, out: anytype, comptime struct_val: std.builtin.Type.Struct, val: anytype, indent: u8) !void {
    try out.writeAll(".{\n");

    if (struct_val.is_tuple) {
        inline for (struct_val.fields) |field| {
            try out.writeByteNTimes(' ', indent);
            try printType(options, out, @TypeOf(@field(val, field.name)), @field(val, field.name), indent, null);
        }
    } else {
        inline for (struct_val.fields) |field| {
            try out.writeByteNTimes(' ', indent);
            try out.print("    .{p_} = ", .{std.zig.fmtId(field.name)});

            const field_name = @field(val, field.name);
            switch (@typeInfo(@TypeOf(field_name))) {
                .@"enum" => try out.print(".{s},\n", .{@tagName(field_name)}),
                .@"struct" => |struct_info| {
                    try printStructValue(options, out, struct_info, field_name, indent + 4);
                },
                else => try printType(options, out, @TypeOf(field_name), field_name, indent, null),
            }
        }
    }

    if (indent == 0) {
        try out.writeAll("};\n");
    } else {
        try out.writeByteNTimes(' ', indent);
        try out.writeAll("},\n");
    }
}

/// The value is the path in the cache dir.
/// Adds a dependency automatically.
pub fn addOptionPath(
    options: *Options,
    name: []const u8,
    path: LazyPath,
) void {
    options.args.append(.{
        .name = options.step.owner.dupe(name),
        .path = path.dupe(options.step.owner),
    }) catch @panic("OOM");
    path.addStepDependencies(&options.step);
}

pub fn createModule(options: *Options) *std.Build.Module {
    return options.step.owner.createModule(.{
        .root_source_file = options.getOutput(),
    });
}

/// Returns the main artifact of this Build Step which is a Zig source file
/// generated from the key-value pairs of the Options.
pub fn getOutput(options: *Options) LazyPath {
    return .{ .generated = .{ .file = &options.generated_file } };
}

fn make(step: *Step, make_options: Step.MakeOptions) !void {
    // This step completes so quickly that no progress reporting is necessary.
    _ = make_options;

    const b = step.owner;
    const options: *Options = @fieldParentPtr("step", step);

    for (options.args.items) |item| {
        options.addOption(
            []const u8,
            item.name,
            item.path.getPath2(b, step),
        );
    }
    if (!step.inputs.populated()) for (options.args.items) |item| {
        try step.addWatchInput(item.path);
    };

    const basename = "options.zig";

    // Hash contents to file name.
    var hash = b.graph.cache.hash;
    // Random bytes to make unique. Refresh this with new random bytes when
    // implementation is modified in a non-backwards-compatible way.
    hash.add(@as(u32, 0xad95e922));
    hash.addBytes(options.contents.items);
    const sub_path = "c" ++ fs.path.sep_str ++ hash.final() ++ fs.path.sep_str ++ basename;

    options.generated_file.path = try b.cache_root.join(b.allocator, &.{sub_path});

    // Optimize for the hot path. Stat the file, and if it already exists,
    // cache hit.
    if (b.cache_root.handle.access(sub_path, .{})) |_| {
        // This is the hot path, success.
        step.result_cached = true;
        return;
    } else |outer_err| switch (outer_err) {
        error.FileNotFound => {
            const sub_dirname = fs.path.dirname(sub_path).?;
            b.cache_root.handle.makePath(sub_dirname) catch |e| {
                return step.fail("unable to make path '{}{s}': {s}", .{
                    b.cache_root, sub_dirname, @errorName(e),
                });
            };

            const rand_int = std.crypto.random.int(u64);
            const tmp_sub_path = "tmp" ++ fs.path.sep_str ++
                std.fmt.hex(rand_int) ++ fs.path.sep_str ++
                basename;
            const tmp_sub_path_dirname = fs.path.dirname(tmp_sub_path).?;

            b.cache_root.handle.makePath(tmp_sub_path_dirname) catch |err| {
                return step.fail("unable to make temporary directory '{}{s}': {s}", .{
                    b.cache_root, tmp_sub_path_dirname, @errorName(err),
                });
            };

            b.cache_root.handle.writeFile(.{ .sub_path = tmp_sub_path, .data = options.contents.items }) catch |err| {
                return step.fail("unable to write options to '{}{s}': {s}", .{
                    b.cache_root, tmp_sub_path, @errorName(err),
                });
            };

            b.cache_root.handle.rename(tmp_sub_path, sub_path) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    // Other process beat us to it. Clean up the temp file.
                    b.cache_root.handle.deleteFile(tmp_sub_path) catch |e| {
                        try step.addError("warning: unable to delete temp file '{}{s}': {s}", .{
                            b.cache_root, tmp_sub_path, @errorName(e),
                        });
                    };
                    step.result_cached = true;
                    return;
                },
                else => {
                    return step.fail("unable to rename options from '{}{s}' to '{}{s}': {s}", .{
                        b.cache_root,    tmp_sub_path,
                        b.cache_root,    sub_path,
                        @errorName(err),
                    });
                },
            };
        },
        else => |e| return step.fail("unable to access options file '{}{s}': {s}", .{
            b.cache_root, sub_path, @errorName(e),
        }),
    }
}

const Arg = struct {
    name: []const u8,
    path: LazyPath,
};

test Options {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var graph: std.Build.Graph = .{
        .arena = arena.allocator(),
        .cache = .{
            .gpa = arena.allocator(),
            .manifest_dir = std.fs.cwd(),
        },
        .zig_exe = "test",
        .env_map = std.process.EnvMap.init(arena.allocator()),
        .global_cache_root = .{ .path = "test", .handle = std.fs.cwd() },
        .host = .{
            .query = .{},
            .result = try std.zig.system.resolveTargetQuery(.{}),
        },
        .zig_lib_directory = std.Build.Cache.Directory.cwd(),
    };

    var builder = try std.Build.create(
        &graph,
        .{ .path = "test", .handle = std.fs.cwd() },
        .{ .path = "test", .handle = std.fs.cwd() },
        &.{},
    );

    const options = builder.addOptions();

    const KeywordEnum = enum {
        @"0.8.1",
    };

    const NormalEnum = enum {
        foo,
        bar,
    };

    const nested_array = [2][2]u16{
        [2]u16{ 300, 200 },
        [2]u16{ 300, 200 },
    };
    const nested_slice: []const []const u16 = &[_][]const u16{ &nested_array[0], &nested_array[1] };

    const NormalStruct = struct {
        hello: ?[]const u8,
        world: bool = true,
    };

    const NestedStruct = struct {
        normal_struct: NormalStruct,
        normal_enum: NormalEnum = .foo,
    };

    options.addOption(usize, "option1", 1);
    options.addOption(?usize, "option2", null);
    options.addOption(?usize, "option3", 3);
    options.addOption(comptime_int, "option4", 4);
    options.addOption([]const u8, "string", "zigisthebest");
    options.addOption(?[]const u8, "optional_string", null);
    options.addOption([2][2]u16, "nested_array", nested_array);
    options.addOption([]const []const u16, "nested_slice", nested_slice);
    options.addOption(KeywordEnum, "keyword_enum", .@"0.8.1");
    options.addOption(std.SemanticVersion, "semantic_version", try std.SemanticVersion.parse("0.1.2-foo+bar"));
    options.addOption(NormalEnum, "normal1_enum", NormalEnum.foo);
    options.addOption(NormalEnum, "normal2_enum", NormalEnum.bar);
    options.addOption(NormalStruct, "normal1_struct", NormalStruct{
        .hello = "foo",
    });
    options.addOption(NormalStruct, "normal2_struct", NormalStruct{
        .hello = null,
        .world = false,
    });
    options.addOption(NestedStruct, "nested_struct", NestedStruct{
        .normal_struct = .{ .hello = "bar" },
    });

    try std.testing.expectEqualStrings(
        \\pub const option1: usize = 1;
        \\pub const option2: ?usize = null;
        \\pub const option3: ?usize = 3;
        \\pub const option4: comptime_int = 4;
        \\pub const string: []const u8 = "zigisthebest";
        \\pub const optional_string: ?[]const u8 = null;
        \\pub const nested_array: [2][2]u16 = [2][2]u16 {
        \\    [2]u16 {
        \\        300,
        \\        200,
        \\    },
        \\    [2]u16 {
        \\        300,
        \\        200,
        \\    },
        \\};
        \\pub const nested_slice: []const []const u16 = &[_][]const u16 {
        \\    &[_]u16 {
        \\        300,
        \\        200,
        \\    },
        \\    &[_]u16 {
        \\        300,
        \\        200,
        \\    },
        \\};
        \\pub const @"Build.Step.Options.decltest.Options.KeywordEnum" = enum (u0) {
        \\    @"0.8.1" = 0,
        \\};
        \\pub const keyword_enum: @"Build.Step.Options.decltest.Options.KeywordEnum" = .@"0.8.1";
        \\pub const semantic_version: @import("std").SemanticVersion = .{
        \\    .major = 0,
        \\    .minor = 1,
        \\    .patch = 2,
        \\    .pre = "foo",
        \\    .build = "bar",
        \\};
        \\pub const @"Build.Step.Options.decltest.Options.NormalEnum" = enum (u1) {
        \\    foo = 0,
        \\    bar = 1,
        \\};
        \\pub const normal1_enum: @"Build.Step.Options.decltest.Options.NormalEnum" = .foo;
        \\pub const normal2_enum: @"Build.Step.Options.decltest.Options.NormalEnum" = .bar;
        \\pub const @"Build.Step.Options.decltest.Options.NormalStruct" = struct {
        \\    hello: ?[]const u8,
        \\    world: bool = true,
        \\};
        \\pub const normal1_struct: @"Build.Step.Options.decltest.Options.NormalStruct" = .{
        \\    .hello = "foo",
        \\    .world = true,
        \\};
        \\pub const normal2_struct: @"Build.Step.Options.decltest.Options.NormalStruct" = .{
        \\    .hello = null,
        \\    .world = false,
        \\};
        \\pub const @"Build.Step.Options.decltest.Options.NestedStruct" = struct {
        \\    normal_struct: @"Build.Step.Options.decltest.Options.NormalStruct",
        \\    normal_enum: @"Build.Step.Options.decltest.Options.NormalEnum" = .foo,
        \\};
        \\pub const nested_struct: @"Build.Step.Options.decltest.Options.NestedStruct" = .{
        \\    .normal_struct = .{
        \\        .hello = "bar",
        \\        .world = true,
        \\    },
        \\    .normal_enum = .foo,
        \\};
        \\
    , options.contents.items);

    _ = try std.zig.Ast.parse(arena.allocator(), try options.contents.toOwnedSliceSentinel(0), .zig);
}
const std = @import("std");
const fs = std.fs;
const Step = std.Build.Step;
const RemoveDir = @This();
const LazyPath = std.Build.LazyPath;

pub const base_id: Step.Id = .remove_dir;

step: Step,
doomed_path: LazyPath,

pub fn create(owner: *std.Build, doomed_path: LazyPath) *RemoveDir {
    const remove_dir = owner.allocator.create(RemoveDir) catch @panic("OOM");
    remove_dir.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = owner.fmt("RemoveDir {s}", .{doomed_path.getDisplayName()}),
            .owner = owner,
            .makeFn = make,
        }),
        .doomed_path = doomed_path.dupe(owner),
    };
    return remove_dir;
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    _ = options;

    const b = step.owner;
    const remove_dir: *RemoveDir = @fieldParentPtr("step", step);

    step.clearWatchInputs();
    try step.addWatchInput(remove_dir.doomed_path);

    const full_doomed_path = remove_dir.doomed_path.getPath2(b, step);

    b.build_root.handle.deleteTree(full_doomed_path) catch |err| {
        if (b.build_root.path) |base| {
            return step.fail("unable to recursively delete path '{s}/{s}': {s}", .{
                base, full_doomed_path, @errorName(err),
            });
        } else {
            return step.fail("unable to recursively delete path '{s}': {s}", .{
                full_doomed_path, @errorName(err),
            });
        }
    };
}
const std = @import("std");
const builtin = @import("builtin");
const Build = std.Build;
const Step = Build.Step;
const fs = std.fs;
const mem = std.mem;
const process = std.process;
const EnvMap = process.EnvMap;
const assert = std.debug.assert;
const Path = Build.Cache.Path;

const Run = @This();

pub const base_id: Step.Id = .run;

step: Step,

/// See also addArg and addArgs to modifying this directly
argv: std.ArrayListUnmanaged(Arg),

/// Use `setCwd` to set the initial current working directory
cwd: ?Build.LazyPath,

/// Override this field to modify the environment, or use setEnvironmentVariable
env_map: ?*EnvMap,

/// When `true` prevents `ZIG_PROGRESS` environment variable from being passed
/// to the child process, which otherwise would be used for the child to send
/// progress updates to the parent.
disable_zig_progress: bool,

/// Configures whether the Run step is considered to have side-effects, and also
/// whether the Run step will inherit stdio streams, forwarding them to the
/// parent process, in which case will require a global lock to prevent other
/// steps from interfering with stdio while the subprocess associated with this
/// Run step is running.
/// If the Run step is determined to not have side-effects, then execution will
/// be skipped if all output files are up-to-date and input files are
/// unchanged.
stdio: StdIo,

/// This field must be `.none` if stdio is `inherit`.
/// It should be only set using `setStdIn`.
stdin: StdIn,

/// Additional input files that, when modified, indicate that the Run step
/// should be re-executed.
/// If the Run step is determined to have side-effects, the Run step is always
/// executed when it appears in the build graph, regardless of whether these
/// files have been modified.
file_inputs: std.ArrayListUnmanaged(std.Build.LazyPath),

/// After adding an output argument, this step will by default rename itself
/// for a better display name in the build summary.
/// This can be disabled by setting this to false.
rename_step_with_output_arg: bool,

/// If this is true, a Run step which is configured to check the output of the
/// executed binary will not fail the build if the binary cannot be executed
/// due to being for a foreign binary to the host system which is running the
/// build graph.
/// Command-line arguments such as -fqemu and -fwasmtime may affect whether a
/// binary is detected as foreign, as well as system configuration such as
/// Rosetta (macOS) and binfmt_misc (Linux).
/// If this Run step is considered to have side-effects, then this flag does
/// nothing.
skip_foreign_checks: bool,

/// If this is true, failing to execute a foreign binary will be considered an
/// error. However if this is false, the step will be skipped on failure instead.
///
/// This allows for a Run step to attempt to execute a foreign binary using an
/// external executor (such as qemu) but not fail if the executor is unavailable.
failing_to_execute_foreign_is_an_error: bool,

/// If stderr or stdout exceeds this amount, the child process is killed and
/// the step fails.
max_stdio_size: usize,

captured_stdout: ?*Output,
captured_stderr: ?*Output,

dep_output_file: ?*Output,

has_side_effects: bool,

/// If this is a Zig unit test binary, this tracks the indexes of the unit
/// tests that are also fuzz tests.
fuzz_tests: std.ArrayListUnmanaged(u32),
cached_test_metadata: ?CachedTestMetadata = null,

/// Populated during the fuzz phase if this run step corresponds to a unit test
/// executable that contains fuzz tests.
rebuilt_executable: ?Path,

/// If this Run step was produced by a Compile step, it is tracked here.
producer: ?*Step.Compile,

pub const StdIn = union(enum) {
    none,
    bytes: []const u8,
    lazy_path: std.Build.LazyPath,
};

pub const StdIo = union(enum) {
    /// Whether the Run step has side-effects will be determined by whether or not one
    /// of the args is an output file (added with `addOutputFileArg`).
    /// If the Run step is determined to have side-effects, this is the same as `inherit`.
    /// The step will fail if the subprocess crashes or returns a non-zero exit code.
    infer_from_args,
    /// Causes the Run step to be considered to have side-effects, and therefore
    /// always execute when it appears in the build graph.
    /// It also means that this step will obtain a global lock to prevent other
    /// steps from running in the meantime.
    /// The step will fail if the subprocess crashes or returns a non-zero exit code.
    inherit,
    /// Causes the Run step to be considered to *not* have side-effects. The
    /// process will be re-executed if any of the input dependencies are
    /// modified. The exit code and standard I/O streams will be checked for
    /// certain conditions, and the step will succeed or fail based on these
    /// conditions.
    /// Note that an explicit check for exit code 0 needs to be added to this
    /// list if such a check is desirable.
    check: std.ArrayListUnmanaged(Check),
    /// This Run step is running a zig unit test binary and will communicate
    /// extra metadata over the IPC protocol.
    zig_test,

    pub const Check = union(enum) {
        expect_stderr_exact: []const u8,
        expect_stderr_match: []const u8,
        expect_stdout_exact: []const u8,
        expect_stdout_match: []const u8,
        expect_term: std.process.Child.Term,
    };
};

pub const Arg = union(enum) {
    artifact: PrefixedArtifact,
    lazy_path: PrefixedLazyPath,
    directory_source: PrefixedLazyPath,
    bytes: []u8,
    output_file: *Output,
    output_directory: *Output,
};

pub const PrefixedArtifact = struct {
    prefix: []const u8,
    artifact: *Step.Compile,
};

pub const PrefixedLazyPath = struct {
    prefix: []const u8,
    lazy_path: std.Build.LazyPath,
};

pub const Output = struct {
    generated_file: std.Build.GeneratedFile,
    prefix: []const u8,
    basename: []const u8,
};

pub fn create(owner: *std.Build, name: []const u8) *Run {
    const run = owner.allocator.create(Run) catch @panic("OOM");
    run.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = name,
            .owner = owner,
            .makeFn = make,
        }),
        .argv = .{},
        .cwd = null,
        .env_map = null,
        .disable_zig_progress = false,
        .stdio = .infer_from_args,
        .stdin = .none,
        .file_inputs = .{},
        .rename_step_with_output_arg = true,
        .skip_foreign_checks = false,
        .failing_to_execute_foreign_is_an_error = true,
        .max_stdio_size = 10 * 1024 * 1024,
        .captured_stdout = null,
        .captured_stderr = null,
        .dep_output_file = null,
        .has_side_effects = false,
        .fuzz_tests = .{},
        .rebuilt_executable = null,
        .producer = null,
    };
    return run;
}

pub fn setName(run: *Run, name: []const u8) void {
    run.step.name = name;
    run.rename_step_with_output_arg = false;
}

pub fn enableTestRunnerMode(run: *Run) void {
    const b = run.step.owner;
    const arena = b.allocator;
    run.stdio = .zig_test;
    run.addArgs(&.{
        std.fmt.allocPrint(arena, "--seed=0x{x}", .{b.graph.random_seed}) catch @panic("OOM"),
        std.fmt.allocPrint(arena, "--cache-dir={s}", .{b.cache_root.path orelse ""}) catch @panic("OOM"),
        "--listen=-",
    });
}

pub fn addArtifactArg(run: *Run, artifact: *Step.Compile) void {
    run.addPrefixedArtifactArg("", artifact);
}

pub fn addPrefixedArtifactArg(run: *Run, prefix: []const u8, artifact: *Step.Compile) void {
    const b = run.step.owner;

    const prefixed_artifact: PrefixedArtifact = .{
        .prefix = b.dupe(prefix),
        .artifact = artifact,
    };
    run.argv.append(b.allocator, .{ .artifact = prefixed_artifact }) catch @panic("OOM");

    const bin_file = artifact.getEmittedBin();
    bin_file.addStepDependencies(&run.step);
}

/// Provides a file path as a command line argument to the command being run.
///
/// Returns a `std.Build.LazyPath` which can be used as inputs to other APIs
/// throughout the build system.
///
/// Related:
/// * `addPrefixedOutputFileArg` - same thing but prepends a string to the argument
/// * `addFileArg` - for input files given to the child process
pub fn addOutputFileArg(run: *Run, basename: []const u8) std.Build.LazyPath {
    return run.addPrefixedOutputFileArg("", basename);
}

/// Provides a file path as a command line argument to the command being run.
/// Asserts `basename` is not empty.
///
/// For example, a prefix of "-o" and basename of "output.txt" will result in
/// the child process seeing something like this: "-ozig-cache/.../output.txt"
///
/// The child process will see a single argument, regardless of whether the
/// prefix or basename have spaces.
///
/// The returned `std.Build.LazyPath` can be used as inputs to other APIs
/// throughout the build system.
///
/// Related:
/// * `addOutputFileArg` - same thing but without the prefix
/// * `addFileArg` - for input files given to the child process
pub fn addPrefixedOutputFileArg(
    run: *Run,
    prefix: []const u8,
    basename: []const u8,
) std.Build.LazyPath {
    const b = run.step.owner;
    if (basename.len == 0) @panic("basename must not be empty");

    const output = b.allocator.create(Output) catch @panic("OOM");
    output.* = .{
        .prefix = b.dupe(prefix),
        .basename = b.dupe(basename),
        .generated_file = .{ .step = &run.step },
    };
    run.argv.append(b.allocator, .{ .output_file = output }) catch @panic("OOM");

    if (run.rename_step_with_output_arg) {
        run.setName(b.fmt("{s} ({s})", .{ run.step.name, basename }));
    }

    return .{ .generated = .{ .file = &output.generated_file } };
}

/// Appends an input file to the command line arguments.
///
/// The child process will see a file path. Modifications to this file will be
/// detected as a cache miss in subsequent builds, causing the child process to
/// be re-executed.
///
/// Related:
/// * `addPrefixedFileArg` - same thing but prepends a string to the argument
/// * `addOutputFileArg` - for files generated by the child process
pub fn addFileArg(run: *Run, lp: std.Build.LazyPath) void {
    run.addPrefixedFileArg("", lp);
}

/// Appends an input file to the command line arguments prepended with a string.
///
/// For example, a prefix of "-F" will result in the child process seeing something
/// like this: "-Fexample.txt"
///
/// The child process will see a single argument, even if the prefix has
/// spaces. Modifications to this file will be detected as a cache miss in
/// subsequent builds, causing the child process to be re-executed.
///
/// Related:
/// * `addFileArg` - same thing but without the prefix
/// * `addOutputFileArg` - for files generated by the child process
pub fn addPrefixedFileArg(run: *Run, prefix: []const u8, lp: std.Build.LazyPath) void {
    const b = run.step.owner;

    const prefixed_file_source: PrefixedLazyPath = .{
        .prefix = b.dupe(prefix),
        .lazy_path = lp.dupe(b),
    };
    run.argv.append(b.allocator, .{ .lazy_path = prefixed_file_source }) catch @panic("OOM");
    lp.addStepDependencies(&run.step);
}

/// Provides a directory path as a command line argument to the command being run.
///
/// Returns a `std.Build.LazyPath` which can be used as inputs to other APIs
/// throughout the build system.
///
/// Related:
/// * `addPrefixedOutputDirectoryArg` - same thing but prepends a string to the argument
/// * `addDirectoryArg` - for input directories given to the child process
pub fn addOutputDirectoryArg(run: *Run, basename: []const u8) std.Build.LazyPath {
    return run.addPrefixedOutputDirectoryArg("", basename);
}

/// Provides a directory path as a command line argument to the command being run.
/// Asserts `basename` is not empty.
///
/// For example, a prefix of "-o" and basename of "output_dir" will result in
/// the child process seeing something like this: "-ozig-cache/.../output_dir"
///
/// The child process will see a single argument, regardless of whether the
/// prefix or basename have spaces.
///
/// The returned `std.Build.LazyPath` can be used as inputs to other APIs
/// throughout the build system.
///
/// Related:
/// * `addOutputDirectoryArg` - same thing but without the prefix
/// * `addDirectoryArg` - for input directories given to the child process
pub fn addPrefixedOutputDirectoryArg(
    run: *Run,
    prefix: []const u8,
    basename: []const u8,
) std.Build.LazyPath {
    if (basename.len == 0) @panic("basename must not be empty");
    const b = run.step.owner;

    const output = b.allocator.create(Output) catch @panic("OOM");
    output.* = .{
        .prefix = b.dupe(prefix),
        .basename = b.dupe(basename),
        .generated_file = .{ .step = &run.step },
    };
    run.argv.append(b.allocator, .{ .output_directory = output }) catch @panic("OOM");

    if (run.rename_step_with_output_arg) {
        run.setName(b.fmt("{s} ({s})", .{ run.step.name, basename }));
    }

    return .{ .generated = .{ .file = &output.generated_file } };
}

pub fn addDirectoryArg(run: *Run, directory_source: std.Build.LazyPath) void {
    run.addPrefixedDirectoryArg("", directory_source);
}

pub fn addPrefixedDirectoryArg(run: *Run, prefix: []const u8, directory_source: std.Build.LazyPath) void {
    const b = run.step.owner;

    const prefixed_directory_source: PrefixedLazyPath = .{
        .prefix = b.dupe(prefix),
        .lazy_path = directory_source.dupe(b),
    };
    run.argv.append(b.allocator, .{ .directory_source = prefixed_directory_source }) catch @panic("OOM");
    directory_source.addStepDependencies(&run.step);
}

/// Add a path argument to a dep file (.d) for the child process to write its
/// discovered additional dependencies.
/// Only one dep file argument is allowed by instance.
pub fn addDepFileOutputArg(run: *Run, basename: []const u8) std.Build.LazyPath {
    return run.addPrefixedDepFileOutputArg("", basename);
}

/// Add a prefixed path argument to a dep file (.d) for the child process to
/// write its discovered additional dependencies.
/// Only one dep file argument is allowed by instance.
pub fn addPrefixedDepFileOutputArg(run: *Run, prefix: []const u8, basename: []const u8) std.Build.LazyPath {
    const b = run.step.owner;
    assert(run.dep_output_file == null);

    const dep_file = b.allocator.create(Output) catch @panic("OOM");
    dep_file.* = .{
        .prefix = b.dupe(prefix),
        .basename = b.dupe(basename),
        .generated_file = .{ .step = &run.step },
    };

    run.dep_output_file = dep_file;

    run.argv.append(b.allocator, .{ .output_file = dep_file }) catch @panic("OOM");

    return .{ .generated = .{ .file = &dep_file.generated_file } };
}

pub fn addArg(run: *Run, arg: []const u8) void {
    const b = run.step.owner;
    run.argv.append(b.allocator, .{ .bytes = b.dupe(arg) }) catch @panic("OOM");
}

pub fn addArgs(run: *Run, args: []const []const u8) void {
    for (args) |arg| run.addArg(arg);
}

pub fn setStdIn(run: *Run, stdin: StdIn) void {
    switch (stdin) {
        .lazy_path => |lazy_path| lazy_path.addStepDependencies(&run.step),
        .bytes, .none => {},
    }
    run.stdin = stdin;
}

pub fn setCwd(run: *Run, cwd: Build.LazyPath) void {
    cwd.addStepDependencies(&run.step);
    run.cwd = cwd.dupe(run.step.owner);
}

pub fn clearEnvironment(run: *Run) void {
    const b = run.step.owner;
    const new_env_map = b.allocator.create(EnvMap) catch @panic("OOM");
    new_env_map.* = EnvMap.init(b.allocator);
    run.env_map = new_env_map;
}

pub fn addPathDir(run: *Run, search_path: []const u8) void {
    const b = run.step.owner;
    const env_map = getEnvMapInternal(run);

    const key = "PATH";
    const prev_path = env_map.get(key);

    if (prev_path) |pp| {
        const new_path = b.fmt("{s}" ++ [1]u8{fs.path.delimiter} ++ "{s}", .{ pp, search_path });
        env_map.put(key, new_path) catch @panic("OOM");
    } else {
        env_map.put(key, b.dupePath(search_path)) catch @panic("OOM");
    }
}

pub fn getEnvMap(run: *Run) *EnvMap {
    return getEnvMapInternal(run);
}

fn getEnvMapInternal(run: *Run) *EnvMap {
    const arena = run.step.owner.allocator;
    return run.env_map orelse {
        const env_map = arena.create(EnvMap) catch @panic("OOM");
        env_map.* = process.getEnvMap(arena) catch @panic("unhandled error");
        run.env_map = env_map;
        return env_map;
    };
}

pub fn setEnvironmentVariable(run: *Run, key: []const u8, value: []const u8) void {
    const b = run.step.owner;
    const env_map = run.getEnvMap();
    env_map.put(b.dupe(key), b.dupe(value)) catch @panic("unhandled error");
}

pub fn removeEnvironmentVariable(run: *Run, key: []const u8) void {
    run.getEnvMap().remove(key);
}

/// Adds a check for exact stderr match. Does not add any other checks.
pub fn expectStdErrEqual(run: *Run, bytes: []const u8) void {
    const new_check: StdIo.Check = .{ .expect_stderr_exact = run.step.owner.dupe(bytes) };
    run.addCheck(new_check);
}

/// Adds a check for exact stdout match as well as a check for exit code 0, if
/// there is not already an expected termination check.
pub fn expectStdOutEqual(run: *Run, bytes: []const u8) void {
    const new_check: StdIo.Check = .{ .expect_stdout_exact = run.step.owner.dupe(bytes) };
    run.addCheck(new_check);
    if (!run.hasTermCheck()) {
        run.expectExitCode(0);
    }
}

pub fn expectExitCode(run: *Run, code: u8) void {
    const new_check: StdIo.Check = .{ .expect_term = .{ .Exited = code } };
    run.addCheck(new_check);
}

pub fn hasTermCheck(run: Run) bool {
    for (run.stdio.check.items) |check| switch (check) {
        .expect_term => return true,
        else => continue,
    };
    return false;
}

pub fn addCheck(run: *Run, new_check: StdIo.Check) void {
    const b = run.step.owner;

    switch (run.stdio) {
        .infer_from_args => {
            run.stdio = .{ .check = .{} };
            run.stdio.check.append(b.allocator, new_check) catch @panic("OOM");
        },
        .check => |*checks| checks.append(b.allocator, new_check) catch @panic("OOM"),
        else => @panic("illegal call to addCheck: conflicting helper method calls. Suggest to directly set stdio field of Run instead"),
    }
}

pub fn captureStdErr(run: *Run) std.Build.LazyPath {
    assert(run.stdio != .inherit);

    if (run.captured_stderr) |output| return .{ .generated = .{ .file = &output.generated_file } };

    const output = run.step.owner.allocator.create(Output) catch @panic("OOM");
    output.* = .{
        .prefix = "",
        .basename = "stderr",
        .generated_file = .{ .step = &run.step },
    };
    run.captured_stderr = output;
    return .{ .generated = .{ .file = &output.generated_file } };
}

pub fn captureStdOut(run: *Run) std.Build.LazyPath {
    assert(run.stdio != .inherit);

    if (run.captured_stdout) |output| return .{ .generated = .{ .file = &output.generated_file } };

    const output = run.step.owner.allocator.create(Output) catch @panic("OOM");
    output.* = .{
        .prefix = "",
        .basename = "stdout",
        .generated_file = .{ .step = &run.step },
    };
    run.captured_stdout = output;
    return .{ .generated = .{ .file = &output.generated_file } };
}

/// Adds an additional input files that, when modified, indicates that this Run
/// step should be re-executed.
/// If the Run step is determined to have side-effects, the Run step is always
/// executed when it appears in the build graph, regardless of whether this
/// file has been modified.
pub fn addFileInput(self: *Run, file_input: std.Build.LazyPath) void {
    file_input.addStepDependencies(&self.step);
    self.file_inputs.append(self.step.owner.allocator, file_input.dupe(self.step.owner)) catch @```
