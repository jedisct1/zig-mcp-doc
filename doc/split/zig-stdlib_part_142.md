```
x();
        \\}
        \\
    );
}

test "recovery: top level" {
    try testError(
        \\test "" {inline}
        \\test "" {inline}
    , &[_]Error{
        .expected_inlinable,
        .expected_inlinable,
    });
}

test "recovery: block statements" {
    try testError(
        \\test "" {
        \\    foo + +;
        \\    inline;
        \\}
    , &[_]Error{
        .expected_expr,
        .expected_semi_after_stmt,
        .expected_statement,
        .expected_inlinable,
    });
}

test "recovery: missing comma" {
    try testError(
        \\test "" {
        \\    switch (foo) {
        \\        2 => {}
        \\        3 => {}
        \\        else => {
        \\            foo & bar +;
        \\        }
        \\    }
        \\}
    , &[_]Error{
        .expected_comma_after_switch_prong,
        .expected_comma_after_switch_prong,
        .expected_expr,
    });
}

test "recovery: non-associative operators" {
    try testError(
        \\const x = a == b == c;
        \\const x = a == b != c;
    , &[_]Error{
        .chained_comparison_operators,
        .chained_comparison_operators,
    });
}

test "recovery: extra qualifier" {
    try testError(
        \\const a: *const const u8;
        \\test ""
    , &[_]Error{
        .extra_const_qualifier,
        .expected_block,
    });
}

test "recovery: missing return type" {
    try testError(
        \\fn foo() {
        \\    a & b;
        \\}
        \\test ""
    , &[_]Error{
        .expected_return_type,
        .expected_block,
    });
}

test "recovery: continue after invalid decl" {
    try testError(
        \\fn foo {
        \\    inline;
        \\}
        \\pub test "" {
        \\    async a & b;
        \\}
    , &[_]Error{
        .expected_token,
        .expected_pub_item,
        .expected_param_list,
    });
    try testError(
        \\threadlocal test "" {
        \\    @a & b;
        \\}
    , &[_]Error{
        .expected_var_decl,
        .expected_param_list,
    });
}

test "recovery: invalid extern/inline" {
    try testError(
        \\inline test "" { a & b; }
    , &[_]Error{
        .expected_fn,
    });
    try testError(
        \\extern "" test "" { a & b; }
    , &[_]Error{
        .expected_var_decl_or_fn,
    });
}

test "recovery: missing semicolon" {
    try testError(
        \\test "" {
        \\    comptime a & b
        \\    c & d
        \\    @foo
        \\}
    , &[_]Error{
        .expected_semi_after_stmt,
        .expected_semi_after_stmt,
        .expected_param_list,
        .expected_semi_after_stmt,
    });
}

test "recovery: invalid container members" {
    try testError(
        \\usingnamespace;
        \\@foo()+
        \\@bar()@,
        \\while (a == 2) { test "" {}}
        \\test "" {
        \\    a & b
        \\}
    , &[_]Error{
        .expected_expr,
        .expected_comma_after_field,
        .expected_semi_after_stmt,
    });
}

// TODO after https://github.com/ziglang/zig/issues/35 is implemented,
// we should be able to recover from this *at any indentation level*,
// reporting a parse error and yet also parsing all the decls even
// inside structs.
test "recovery: extra '}' at top level" {
    try testError(
        \\}}}
        \\test "" {
        \\    a & b;
        \\}
    , &[_]Error{
        .expected_token,
    });
}

test "recovery: mismatched bracket at top level" {
    try testError(
        \\const S = struct {
        \\    arr: 128]?G
        \\};
    , &[_]Error{
        .expected_comma_after_field,
    });
}

test "recovery: invalid global error set access" {
    try testError(
        \\test "" {
        \\    error & foo;
        \\}
    , &[_]Error{
        .expected_token,
        .expected_token,
    });
}

test "recovery: invalid asterisk after pointer dereference" {
    try testError(
        \\test "" {
        \\    var sequence = "repeat".*** 10;
        \\}
    , &[_]Error{
        .asterisk_after_ptr_deref,
        .mismatched_binary_op_whitespace,
    });
    try testError(
        \\test "" {
        \\    var sequence = "repeat".** 10&a;
        \\}
    , &[_]Error{
        .asterisk_after_ptr_deref,
        .mismatched_binary_op_whitespace,
    });
}

test "recovery: missing semicolon after if, for, while stmt" {
    try testError(
        \\test "" {
        \\    if (foo) bar
        \\    for (foo) |a| bar
        \\    while (foo) bar
        \\    a & b;
        \\}
    , &[_]Error{
        .expected_semi_or_else,
        .expected_semi_or_else,
        .expected_semi_or_else,
    });
}

test "recovery: invalid comptime" {
    try testError(
        \\comptime
    , &[_]Error{
        .expected_type_expr,
    });
}

test "recovery: missing block after suspend" {
    try testError(
        \\fn foo() void {
        \\    suspend;
        \\    nosuspend;
        \\}
    , &[_]Error{
        .expected_block_or_expr,
        .expected_block_or_expr,
    });
}

test "recovery: missing block after for/while loops" {
    try testError(
        \\test "" { while (foo) }
    , &[_]Error{
        .expected_block_or_assignment,
    });
    try testError(
        \\test "" { for (foo) |bar| }
    , &[_]Error{
        .expected_block_or_assignment,
    });
}

test "recovery: missing for payload" {
    try testError(
        \\comptime {
        \\    const a = for(a) {};
        \\    const a: for(a) blk: {} = {};
        \\    for(a) {}
        \\}
    , &[_]Error{
        .expected_loop_payload,
        .expected_loop_payload,
        .expected_loop_payload,
    });
}

test "recovery: missing comma in params" {
    try testError(
        \\fn foo(comptime bool what what) void { }
        \\fn bar(a: i32, b: i32 c) void { }
        \\
    , &[_]Error{
        .expected_comma_after_param,
        .expected_comma_after_param,
        .expected_comma_after_param,
    });
}

test "recovery: missing while rbrace" {
    try testError(
        \\fn a() b {
        \\    while (d) {
        \\}
    , &[_]Error{
        .expected_statement,
    });
}

test "recovery: nonfinal varargs" {
    try testError(
        \\extern fn f(a: u32, ..., b: u32) void;
        \\extern fn g(a: u32, ..., b: anytype) void;
        \\extern fn h(a: u32, ..., ...) void;
    , &[_]Error{
        .varargs_nonfinal,
        .varargs_nonfinal,
        .varargs_nonfinal,
    });
}

test "recovery: eof in c pointer" {
    try testError(
        \\const Ptr = [*c
    , &[_]Error{
        .expected_token,
    });
}

test "matching whitespace on minus op" {
    try testError(
        \\ _ = 2 -1, 
        \\ _ = 2- 1, 
        \\ _ = 2-
        \\     2,
        \\ _ = 2
        \\     -2,
    , &[_]Error{
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
    });

    try testError(
        \\ _ = - 1,
        \\ _ = -1,
        \\ _ = 2 - -1,
        \\ _ = 2 - 1,
        \\ _ = 2-1, 
        \\ _ = 2 -
        \\1,
        \\ _ = 2
        \\     - 1,
    , &[_]Error{});
}

test "ampersand" {
    try testError(
        \\ _ = bar && foo,
        \\ _ = bar&&foo, 
        \\ _ = bar& & foo, 
        \\ _ = bar& &foo,
    , &.{
        .invalid_ampersand_ampersand,
        .invalid_ampersand_ampersand,
        .mismatched_binary_op_whitespace,
        .mismatched_binary_op_whitespace,
    });

    try testError(
        \\ _ = bar & &foo, 
        \\ _ = bar & &&foo, 
        \\ _ = &&foo, 
    , &.{});
}

const std = @import("std");
const mem = std.mem;
const print = std.debug.print;
const io = std.io;
const maxInt = std.math.maxInt;

var fixed_buffer_mem: [100 * 1024]u8 = undefined;

fn testParse(source: [:0]const u8, allocator: mem.Allocator, anything_changed: *bool) ![]u8 {
    const stderr = io.getStdErr().writer();

    var tree = try std.zig.Ast.parse(allocator, source, .zig);
    defer tree.deinit(allocator);

    for (tree.errors) |parse_error| {
        const loc = tree.tokenLocation(0, parse_error.token);
        try stderr.print("(memory buffer):{d}:{d}: error: ", .{ loc.line + 1, loc.column + 1 });
        try tree.renderError(parse_error, stderr);
        try stderr.print("\n{s}\n", .{source[loc.line_start..loc.line_end]});
        {
            var i: usize = 0;
            while (i < loc.column) : (i += 1) {
                try stderr.writeAll(" ");
            }
            try stderr.writeAll("^");
        }
        try stderr.writeAll("\n");
    }
    if (tree.errors.len != 0) {
        return error.ParseError;
    }

    const formatted = try tree.render(allocator);
    anything_changed.* = !mem.eql(u8, formatted, source);
    return formatted;
}
fn testTransformImpl(allocator: mem.Allocator, fba: *std.heap.FixedBufferAllocator, source: [:0]const u8, expected_source: []const u8) !void {
    // reset the fixed buffer allocator each run so that it can be re-used for each
    // iteration of the failing index
    fba.reset();
    var anything_changed: bool = undefined;
    const result_source = try testParse(source, allocator, &anything_changed);
    try std.testing.expectEqualStrings(expected_source, result_source);
    const changes_expected = source.ptr != expected_source.ptr;
    if (anything_changed != changes_expected) {
        print("std.zig.render returned {} instead of {}\n", .{ anything_changed, changes_expected });
        return error.TestFailed;
    }
    try std.testing.expect(anything_changed == changes_expected);
    allocator.free(result_source);
}
fn testTransform(source: [:0]const u8, expected_source: []const u8) !void {
    var fixed_allocator = std.heap.FixedBufferAllocator.init(fixed_buffer_mem[0..]);
    return std.testing.checkAllAllocationFailures(fixed_allocator.allocator(), testTransformImpl, .{ &fixed_allocator, source, expected_source });
}
fn testCanonical(source: [:0]const u8) !void {
    return testTransform(source, source);
}

const Error = std.zig.Ast.Error.Tag;

fn testError(source: [:0]const u8, expected_errors: []const Error) !void {
    var tree = try std.zig.Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    std.testing.expectEqual(expected_errors.len, tree.errors.len) catch |err| {
        std.debug.print("errors found: {any}\n", .{tree.errors});
        return err;
    };
    for (expected_errors, 0..) |expected, i| {
        try std.testing.expectEqual(expected, tree.errors[i].tag);
    }
}
const std = @import("std");
const mem = std.mem;
const Tokenizer = std.zig.Tokenizer;
const io = std.io;
const fmtIntSizeBin = std.fmt.fmtIntSizeBin;

const source = @embedFile("../os.zig");
var fixed_buffer_mem: [10 * 1024 * 1024]u8 = undefined;

pub fn main() !void {
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    const start = timer.lap();
    const iterations = 100;
    var memory_used: usize = 0;
    while (i < iterations) : (i += 1) {
        memory_used += testOnce();
    }
    const end = timer.read();
    memory_used /= iterations;
    const elapsed_s = @as(f64, @floatFromInt(end - start)) / std.time.ns_per_s;
    const bytes_per_sec_float = @as(f64, @floatFromInt(source.len * iterations)) / elapsed_s;
    const bytes_per_sec = @as(u64, @intFromFloat(@floor(bytes_per_sec_float)));

    var stdout_file = std.io.getStdOut();
    const stdout = stdout_file.writer();
    try stdout.print("parsing speed: {:.2}/s, {:.2} used \n", .{
        fmtIntSizeBin(bytes_per_sec),
        fmtIntSizeBin(memory_used),
    });
}

fn testOnce() usize {
    var fixed_buf_alloc = std.heap.FixedBufferAllocator.init(fixed_buffer_mem[0..]);
    const allocator = fixed_buf_alloc.allocator();
    _ = std.zig.Ast.parse(allocator, source, .zig) catch @panic("parse failure");
    return fixed_buf_alloc.end_index;
}
const std = @import("std");

/// Set of primitive type and value names.
/// Does not include `_` or integer type names.
pub const names = std.StaticStringMap(void).initComptime(.{
    .{"anyerror"},
    .{"anyframe"},
    .{"anyopaque"},
    .{"bool"},
    .{"c_int"},
    .{"c_long"},
    .{"c_longdouble"},
    .{"c_longlong"},
    .{"c_char"},
    .{"c_short"},
    .{"c_uint"},
    .{"c_ulong"},
    .{"c_ulonglong"},
    .{"c_ushort"},
    .{"comptime_float"},
    .{"comptime_int"},
    .{"f128"},
    .{"f16"},
    .{"f32"},
    .{"f64"},
    .{"f80"},
    .{"false"},
    .{"isize"},
    .{"noreturn"},
    .{"null"},
    .{"true"},
    .{"type"},
    .{"undefined"},
    .{"usize"},
    .{"void"},
});

/// Returns true if a name matches a primitive type or value, excluding `_`.
/// Integer type names like `u8` or `i32` are only matched for syntax,
/// so this will still return true when they have an oversized bit count
/// or leading zeroes.
pub fn isPrimitive(name: []const u8) bool {
    if (names.get(name) != null) return true;
    if (name.len < 2) return false;
    const first_c = name[0];
    if (first_c != 'i' and first_c != 'u') return false;
    for (name[1..]) |c| switch (c) {
        '0'...'9' => {},
        else => return false,
    };
    return true;
}

test isPrimitive {
    const expect = std.testing.expect;
    try expect(!isPrimitive(""));
    try expect(!isPrimitive("_"));
    try expect(!isPrimitive("haberdasher"));
    try expect(isPrimitive("bool"));
    try expect(isPrimitive("false"));
    try expect(isPrimitive("comptime_float"));
    try expect(isPrimitive("u1"));
    try expect(isPrimitive("i99999999999999"));
}
const std = @import("../std.zig");
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const meta = std.meta;
const Ast = std.zig.Ast;
const Token = std.zig.Token;
const primitives = std.zig.primitives;

const indent_delta = 4;
const asm_indent_delta = 2;

pub const Error = Ast.RenderError;

const Ais = AutoIndentingStream(std.ArrayList(u8).Writer);

pub const Fixups = struct {
    /// The key is the mut token (`var`/`const`) of the variable declaration
    /// that should have a `_ = foo;` inserted afterwards.
    unused_var_decls: std.AutoHashMapUnmanaged(Ast.TokenIndex, void) = .empty,
    /// The functions in this unordered set of AST fn decl nodes will render
    /// with a function body of `@trap()` instead, with all parameters
    /// discarded.
    gut_functions: std.AutoHashMapUnmanaged(Ast.Node.Index, void) = .empty,
    /// These global declarations will be omitted.
    omit_nodes: std.AutoHashMapUnmanaged(Ast.Node.Index, void) = .empty,
    /// These expressions will be replaced with the string value.
    replace_nodes_with_string: std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8) = .empty,
    /// The string value will be inserted directly after the node.
    append_string_after_node: std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8) = .empty,
    /// These nodes will be replaced with a different node.
    replace_nodes_with_node: std.AutoHashMapUnmanaged(Ast.Node.Index, Ast.Node.Index) = .empty,
    /// Change all identifier names matching the key to be value instead.
    rename_identifiers: std.StringArrayHashMapUnmanaged([]const u8) = .empty,

    /// All `@import` builtin calls which refer to a file path will be prefixed
    /// with this path.
    rebase_imported_paths: ?[]const u8 = null,

    pub fn count(f: Fixups) usize {
        return f.unused_var_decls.count() +
            f.gut_functions.count() +
            f.omit_nodes.count() +
            f.replace_nodes_with_string.count() +
            f.append_string_after_node.count() +
            f.replace_nodes_with_node.count() +
            f.rename_identifiers.count() +
            @intFromBool(f.rebase_imported_paths != null);
    }

    pub fn clearRetainingCapacity(f: *Fixups) void {
        f.unused_var_decls.clearRetainingCapacity();
        f.gut_functions.clearRetainingCapacity();
        f.omit_nodes.clearRetainingCapacity();
        f.replace_nodes_with_string.clearRetainingCapacity();
        f.append_string_after_node.clearRetainingCapacity();
        f.replace_nodes_with_node.clearRetainingCapacity();
        f.rename_identifiers.clearRetainingCapacity();

        f.rebase_imported_paths = null;
    }

    pub fn deinit(f: *Fixups, gpa: Allocator) void {
        f.unused_var_decls.deinit(gpa);
        f.gut_functions.deinit(gpa);
        f.omit_nodes.deinit(gpa);
        f.replace_nodes_with_string.deinit(gpa);
        f.append_string_after_node.deinit(gpa);
        f.replace_nodes_with_node.deinit(gpa);
        f.rename_identifiers.deinit(gpa);
        f.* = undefined;
    }
};

const Render = struct {
    gpa: Allocator,
    ais: *Ais,
    tree: Ast,
    fixups: Fixups,
};

pub fn renderTree(buffer: *std.ArrayList(u8), tree: Ast, fixups: Fixups) Error!void {
    assert(tree.errors.len == 0); // Cannot render an invalid tree.
    var auto_indenting_stream = Ais.init(buffer, indent_delta);
    defer auto_indenting_stream.deinit();
    var r: Render = .{
        .gpa = buffer.allocator,
        .ais = &auto_indenting_stream,
        .tree = tree,
        .fixups = fixups,
    };

    // Render all the line comments at the beginning of the file.
    const comment_end_loc = tree.tokenStart(0);
    _ = try renderComments(&r, 0, comment_end_loc);

    if (tree.tokenTag(0) == .container_doc_comment) {
        try renderContainerDocComments(&r, 0);
    }

    switch (tree.mode) {
        .zig => try renderMembers(&r, tree.rootDecls()),
        .zon => {
            try renderExpression(
                &r,
                tree.rootDecls()[0],
                .newline,
            );
        },
    }

    if (auto_indenting_stream.disabled_offset) |disabled_offset| {
        try writeFixingWhitespace(auto_indenting_stream.underlying_writer, tree.source[disabled_offset..]);
    }
}

/// Render all members in the given slice, keeping empty lines where appropriate
fn renderMembers(r: *Render, members: []const Ast.Node.Index) Error!void {
    const tree = r.tree;
    if (members.len == 0) return;
    const container: Container = for (members) |member| {
        if (tree.fullContainerField(member)) |field| if (!field.ast.tuple_like) break .other;
    } else .tuple;
    try renderMember(r, container, members[0], .newline);
    for (members[1..]) |member| {
        try renderExtraNewline(r, member);
        try renderMember(r, container, member, .newline);
    }
}

const Container = enum {
    @"enum",
    tuple,
    other,
};

fn renderMember(
    r: *Render,
    container: Container,
    decl: Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    if (r.fixups.omit_nodes.contains(decl)) return;
    try renderDocComments(r, tree.firstToken(decl));
    switch (tree.nodeTag(decl)) {
        .fn_decl => {
            // Some examples:
            // pub extern "foo" fn ...
            // export fn ...
            const fn_proto, const body_node = tree.nodeData(decl).node_and_node;
            const fn_token = tree.nodeMainToken(fn_proto);
            // Go back to the first token we should render here.
            var i = fn_token;
            while (i > 0) {
                i -= 1;
                switch (tree.tokenTag(i)) {
                    .keyword_extern,
                    .keyword_export,
                    .keyword_pub,
                    .string_literal,
                    .keyword_inline,
                    .keyword_noinline,
                    => continue,

                    else => {
                        i += 1;
                        break;
                    },
                }
            }

            while (i < fn_token) : (i += 1) {
                try renderToken(r, i, .space);
            }
            switch (tree.nodeTag(fn_proto)) {
                .fn_proto_one, .fn_proto => {
                    var buf: [1]Ast.Node.Index = undefined;
                    const opt_callconv_expr = if (tree.nodeTag(fn_proto) == .fn_proto_one)
                        tree.fnProtoOne(&buf, fn_proto).ast.callconv_expr
                    else
                        tree.fnProto(fn_proto).ast.callconv_expr;

                    // Keep in sync with logic in `renderFnProto`. Search this file for the marker PROMOTE_CALLCONV_INLINE
                    if (opt_callconv_expr.unwrap()) |callconv_expr| {
                        if (tree.nodeTag(callconv_expr) == .enum_literal) {
                            if (mem.eql(u8, "@\"inline\"", tree.tokenSlice(tree.nodeMainToken(callconv_expr)))) {
                                try ais.writer().writeAll("inline ");
                            }
                        }
                    }
                },
                .fn_proto_simple, .fn_proto_multi => {},
                else => unreachable,
            }
            try renderExpression(r, fn_proto, .space);
            if (r.fixups.gut_functions.contains(decl)) {
                try ais.pushIndent(.normal);
                const lbrace = tree.nodeMainToken(body_node);
                try renderToken(r, lbrace, .newline);
                try discardAllParams(r, fn_proto);
                try ais.writer().writeAll("@trap();");
                ais.popIndent();
                try ais.insertNewline();
                try renderToken(r, tree.lastToken(body_node), space); // rbrace
            } else if (r.fixups.unused_var_decls.count() != 0) {
                try ais.pushIndent(.normal);
                const lbrace = tree.nodeMainToken(body_node);
                try renderToken(r, lbrace, .newline);

                var fn_proto_buf: [1]Ast.Node.Index = undefined;
                const full_fn_proto = tree.fullFnProto(&fn_proto_buf, fn_proto).?;
                var it = full_fn_proto.iterate(&tree);
                while (it.next()) |param| {
                    const name_ident = param.name_token.?;
                    assert(tree.tokenTag(name_ident) == .identifier);
                    if (r.fixups.unused_var_decls.contains(name_ident)) {
                        const w = ais.writer();
                        try w.writeAll("_ = ");
                        try w.writeAll(tokenSliceForRender(r.tree, name_ident));
                        try w.writeAll(";\n");
                    }
                }
                var statements_buf: [2]Ast.Node.Index = undefined;
                const statements = tree.blockStatements(&statements_buf, body_node).?;
                return finishRenderBlock(r, body_node, statements, space);
            } else {
                return renderExpression(r, body_node, space);
            }
        },
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            // Extern function prototypes are parsed as these tags.
            // Go back to the first token we should render here.
            const fn_token = tree.nodeMainToken(decl);
            var i = fn_token;
            while (i > 0) {
                i -= 1;
                switch (tree.tokenTag(i)) {
                    .keyword_extern,
                    .keyword_export,
                    .keyword_pub,
                    .string_literal,
                    .keyword_inline,
                    .keyword_noinline,
                    => continue,

                    else => {
                        i += 1;
                        break;
                    },
                }
            }
            while (i < fn_token) : (i += 1) {
                try renderToken(r, i, .space);
            }
            try renderExpression(r, decl, .none);
            return renderToken(r, tree.lastToken(decl) + 1, space); // semicolon
        },

        .@"usingnamespace" => {
            const main_token = tree.nodeMainToken(decl);
            const expr = tree.nodeData(decl).node;
            if (tree.isTokenPrecededByTags(main_token, &.{.keyword_pub})) {
                try renderToken(r, main_token - 1, .space); // pub
            }
            try renderToken(r, main_token, .space); // usingnamespace
            try renderExpression(r, expr, .none);
            return renderToken(r, tree.lastToken(expr) + 1, space); // ;
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            try ais.pushSpace(.semicolon);
            try renderVarDecl(r, tree.fullVarDecl(decl).?, false, .semicolon);
            ais.popSpace();
        },

        .test_decl => {
            const test_token = tree.nodeMainToken(decl);
            const opt_name_token, const block_node = tree.nodeData(decl).opt_token_and_node;
            try renderToken(r, test_token, .space);
            if (opt_name_token.unwrap()) |name_token| {
                switch (tree.tokenTag(name_token)) {
                    .string_literal => try renderToken(r, name_token, .space),
                    .identifier => try renderIdentifier(r, name_token, .space, .preserve_when_shadowing),
                    else => unreachable,
                }
            }
            try renderExpression(r, block_node, space);
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => return renderContainerField(r, container, tree.fullContainerField(decl).?, space),

        .@"comptime" => return renderExpression(r, decl, space),

        .root => unreachable,
        else => unreachable,
    }
}

/// Render all expressions in the slice, keeping empty lines where appropriate
fn renderExpressions(r: *Render, expressions: []const Ast.Node.Index, space: Space) Error!void {
    if (expressions.len == 0) return;
    try renderExpression(r, expressions[0], space);
    for (expressions[1..]) |expression| {
        try renderExtraNewline(r, expression);
        try renderExpression(r, expression, space);
    }
}

fn renderExpression(r: *Render, node: Ast.Node.Index, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    if (r.fixups.replace_nodes_with_string.get(node)) |replacement| {
        try ais.writer().writeAll(replacement);
        try renderOnlySpace(r, space);
        return;
    } else if (r.fixups.replace_nodes_with_node.get(node)) |replacement| {
        return renderExpression(r, replacement, space);
    }
    switch (tree.nodeTag(node)) {
        .identifier => {
            const token_index = tree.nodeMainToken(node);
            return renderIdentifier(r, token_index, space, .preserve_when_shadowing);
        },

        .number_literal,
        .char_literal,
        .unreachable_literal,
        .anyframe_literal,
        .string_literal,
        => return renderToken(r, tree.nodeMainToken(node), space),

        .multiline_string_literal => {
            try ais.maybeInsertNewline();

            const first_tok, const last_tok = tree.nodeData(node).token_and_token;
            for (first_tok..last_tok + 1) |i| {
                try renderToken(r, @intCast(i), .newline);
            }

            const next_token = last_tok + 1;
            const next_token_tag = tree.tokenTag(next_token);

            // dedent the next thing that comes after a multiline string literal
            if (!ais.indentStackEmpty() and
                next_token_tag != .colon and
                ((next_token_tag != .semicolon and next_token_tag != .comma) or
                    ais.lastSpaceModeIndent() < ais.currentIndent()))
            {
                ais.popIndent();
                try ais.pushIndent(.normal);
            }

            switch (space) {
                .none, .space, .newline, .skip => {},
                .semicolon => if (next_token_tag == .semicolon) try renderTokenOverrideSpaceMode(r, next_token, .newline, .semicolon),
                .comma => if (next_token_tag == .comma) try renderTokenOverrideSpaceMode(r, next_token, .newline, .comma),
                .comma_space => if (next_token_tag == .comma) try renderToken(r, next_token, .space),
            }
        },

        .error_value => {
            const main_token = tree.nodeMainToken(node);
            try renderToken(r, main_token, .none);
            try renderToken(r, main_token + 1, .none);
            return renderIdentifier(r, main_token + 2, space, .eagerly_unquote);
        },

        .block_two,
        .block_two_semicolon,
        .block,
        .block_semicolon,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const statements = tree.blockStatements(&buf, node).?;
            return renderBlock(r, node, statements, space);
        },

        .@"errdefer" => {
            const defer_token = tree.nodeMainToken(node);
            const maybe_payload_token, const expr = tree.nodeData(node).opt_token_and_node;

            try renderToken(r, defer_token, .space);
            if (maybe_payload_token.unwrap()) |payload_token| {
                try renderToken(r, payload_token - 1, .none); // |
                try renderIdentifier(r, payload_token, .none, .preserve_when_shadowing); // identifier
                try renderToken(r, payload_token + 1, .space); // |
            }
            return renderExpression(r, expr, space);
        },

        .@"defer",
        .@"comptime",
        .@"nosuspend",
        .@"suspend",
        => {
            const main_token = tree.nodeMainToken(node);
            const item = tree.nodeData(node).node;
            try renderToken(r, main_token, .space);
            return renderExpression(r, item, space);
        },

        .@"catch" => {
            const main_token = tree.nodeMainToken(node);
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            const fallback_first = tree.firstToken(rhs);

            const same_line = tree.tokensOnSameLine(main_token, fallback_first);
            const after_op_space = if (same_line) Space.space else Space.newline;

            try renderExpression(r, lhs, .space); // target

            try ais.pushIndent(.normal);
            if (tree.tokenTag(fallback_first - 1) == .pipe) {
                try renderToken(r, main_token, .space); // catch keyword
                try renderToken(r, main_token + 1, .none); // pipe
                try renderIdentifier(r, main_token + 2, .none, .preserve_when_shadowing); // payload identifier
                try renderToken(r, main_token + 3, after_op_space); // pipe
            } else {
                assert(tree.tokenTag(fallback_first - 1) == .keyword_catch);
                try renderToken(r, main_token, after_op_space); // catch keyword
            }
            try renderExpression(r, rhs, space); // fallback
            ais.popIndent();
        },

        .field_access => {
            const lhs, const name_token = tree.nodeData(node).node_and_token;
            const dot_token = name_token - 1;

            try ais.pushIndent(.field_access);
            try renderExpression(r, lhs, .none);

            // Allow a line break between the lhs and the dot if the lhs and rhs
            // are on different lines.
            const lhs_last_token = tree.lastToken(lhs);
            const same_line = tree.tokensOnSameLine(lhs_last_token, name_token);
            if (!same_line and !hasComment(tree, lhs_last_token, dot_token)) try ais.insertNewline();

            try renderToken(r, dot_token, .none);

            try renderIdentifier(r, name_token, space, .eagerly_unquote); // field
            ais.popIndent();
        },

        .error_union,
        .switch_range,
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            try renderExpression(r, lhs, .none);
            try renderToken(r, tree.nodeMainToken(node), .none);
            return renderExpression(r, rhs, space);
        },
        .for_range => {
            const start, const opt_end = tree.nodeData(node).node_and_opt_node;
            try renderExpression(r, start, .none);
            if (opt_end.unwrap()) |end| {
                try renderToken(r, tree.nodeMainToken(node), .none);
                return renderExpression(r, end, space);
            } else {
                return renderToken(r, tree.nodeMainToken(node), space);
            }
        },

        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_sub_sat,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_add_sat,
        .assign_mul,
        .assign_mul_wrap,
        .assign_mul_sat,
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            try renderExpression(r, lhs, .space);
            const op_token = tree.nodeMainToken(node);
            try ais.pushIndent(.after_equals);
            if (tree.tokensOnSameLine(op_token, op_token + 1)) {
                try renderToken(r, op_token, .space);
            } else {
                try renderToken(r, op_token, .newline);
            }
            try renderExpression(r, rhs, space);
            ais.popIndent();
        },

        .add,
        .add_wrap,
        .add_sat,
        .array_cat,
        .array_mult,
        .bang_equal,
        .bit_and,
        .bit_or,
        .shl,
        .shl_sat,
        .shr,
        .bit_xor,
        .bool_and,
        .bool_or,
        .div,
        .equal_equal,
        .greater_or_equal,
        .greater_than,
        .less_or_equal,
        .less_than,
        .merge_error_sets,
        .mod,
        .mul,
        .mul_wrap,
        .mul_sat,
        .sub,
        .sub_wrap,
        .sub_sat,
        .@"orelse",
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            try renderExpression(r, lhs, .space);
            const op_token = tree.nodeMainToken(node);
            try ais.pushIndent(.binop);
            if (tree.tokensOnSameLine(op_token, op_token + 1)) {
                try renderToken(r, op_token, .space);
            } else {
                try renderToken(r, op_token, .newline);
            }
            try renderExpression(r, rhs, space);
            ais.popIndent();
        },

        .assign_destructure => {
            const full = tree.assignDestructure(node);
            if (full.comptime_token) |comptime_token| {
                try renderToken(r, comptime_token, .space);
            }

            for (full.ast.variables, 0..) |variable_node, i| {
                const variable_space: Space = if (i == full.ast.variables.len - 1) .space else .comma_space;
                switch (tree.nodeTag(variable_node)) {
                    .global_var_decl,
                    .local_var_decl,
                    .simple_var_decl,
                    .aligned_var_decl,
                    => {
                        try renderVarDecl(r, tree.fullVarDecl(variable_node).?, true, variable_space);
                    },
                    else => try renderExpression(r, variable_node, variable_space),
                }
            }
            try ais.pushIndent(.after_equals);
            if (tree.tokensOnSameLine(full.ast.equal_token, full.ast.equal_token + 1)) {
                try renderToken(r, full.ast.equal_token, .space);
            } else {
                try renderToken(r, full.ast.equal_token, .newline);
            }
            try renderExpression(r, full.ast.value_expr, space);
            ais.popIndent();
        },

        .bit_not,
        .bool_not,
        .negation,
        .negation_wrap,
        .optional_type,
        .address_of,
        => {
            try renderToken(r, tree.nodeMainToken(node), .none);
            return renderExpression(r, tree.nodeData(node).node, space);
        },

        .@"try",
        .@"resume",
        .@"await",
        => {
            try renderToken(r, tree.nodeMainToken(node), .space);
            return renderExpression(r, tree.nodeData(node).node, space);
        },

        .array_type,
        .array_type_sentinel,
        => return renderArrayType(r, tree.fullArrayType(node).?, space),

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => return renderPtrType(r, tree.fullPtrType(node).?, space),

        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            var elements: [2]Ast.Node.Index = undefined;
            return renderArrayInit(r, tree.fullArrayInit(&elements, node).?, space);
        },

        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            return renderStructInit(r, node, tree.fullStructInit(&buf, node).?, space);
        },

        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            return renderCall(r, tree.fullCall(&buf, node).?, space);
        },

        .array_access => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            const lbracket = tree.firstToken(rhs) - 1;
            const rbracket = tree.lastToken(rhs) + 1;
            const one_line = tree.tokensOnSameLine(lbracket, rbracket);
            const inner_space = if (one_line) Space.none else Space.newline;
            try renderExpression(r, lhs, .none);
            try ais.pushIndent(.normal);
            try renderToken(r, lbracket, inner_space); // [
            try renderExpression(r, rhs, inner_space);
            ais.popIndent();
            return renderToken(r, rbracket, space); // ]
        },

        .slice_open,
        .slice,
        .slice_sentinel,
        => return renderSlice(r, node, tree.fullSlice(node).?, space),

        .deref => {
            try renderExpression(r, tree.nodeData(node).node, .none);
            return renderToken(r, tree.nodeMainToken(node), space);
        },

        .unwrap_optional => {
            const lhs, const question_mark = tree.nodeData(node).node_and_token;
            const dot_token = question_mark - 1;
            try renderExpression(r, lhs, .none);
            try renderToken(r, dot_token, .none);
            return renderToken(r, question_mark, space);
        },

        .@"break", .@"continue" => {
            const main_token = tree.nodeMainToken(node);
            const opt_label_token, const opt_target = tree.nodeData(node).opt_token_and_opt_node;
            if (opt_label_token == .none and opt_target == .none) {
                try renderToken(r, main_token, space); // break/continue
            } else if (opt_label_token == .none and opt_target != .none) {
                const target = opt_target.unwrap().?;
                try renderToken(r, main_token, .space); // break/continue
                try renderExpression(r, target, space);
            } else if (opt_label_token != .none and opt_target == .none) {
                const label_token = opt_label_token.unwrap().?;
                try renderToken(r, main_token, .space); // break/continue
                try renderToken(r, label_token - 1, .none); // :
                try renderIdentifier(r, label_token, space, .eagerly_unquote); // identifier
            } else if (opt_label_token != .none and opt_target != .none) {
                const label_token = opt_label_token.unwrap().?;
                const target = opt_target.unwrap().?;
                try renderToken(r, main_token, .space); // break/continue
                try renderToken(r, label_token - 1, .none); // :
                try renderIdentifier(r, label_token, .space, .eagerly_unquote); // identifier
                try renderExpression(r, target, space);
            } else unreachable;
        },

        .@"return" => {
            if (tree.nodeData(node).opt_node.unwrap()) |expr| {
                try renderToken(r, tree.nodeMainToken(node), .space);
                try renderExpression(r, expr, space);
            } else {
                try renderToken(r, tree.nodeMainToken(node), space);
            }
        },

        .grouped_expression => {
            const expr, const rparen = tree.nodeData(node).node_and_token;
            try ais.pushIndent(.normal);
            try renderToken(r, tree.nodeMainToken(node), .none); // lparen
            try renderExpression(r, expr, .none);
            ais.popIndent();
            return renderToken(r, rparen, space);
        },

        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            return renderContainerDecl(r, node, tree.fullContainerDecl(&buf, node).?, space);
        },

        .error_set_decl => {
            const error_token = tree.nodeMainToken(node);
            const lbrace, const rbrace = tree.nodeData(node).token_and_token;

            try renderToken(r, error_token, .none);

            if (lbrace + 1 == rbrace) {
                // There is nothing between the braces so render condensed: `error{}`
                try renderToken(r, lbrace, .none);
                return renderToken(r, rbrace, space);
            } else if (lbrace + 2 == rbrace and tree.tokenTag(lbrace + 1) == .identifier) {
                // There is exactly one member and no trailing comma or
                // comments, so render without surrounding spaces: `error{Foo}`
                try renderToken(r, lbrace, .none);
                try renderIdentifier(r, lbrace + 1, .none, .eagerly_unquote); // identifier
                return renderToken(r, rbrace, space);
            } else if (tree.tokenTag(rbrace - 1) == .comma) {
                // There is a trailing comma so render each member on a new line.
                try ais.pushIndent(.normal);
                try renderToken(r, lbrace, .newline);
                var i = lbrace + 1;
                while (i < rbrace) : (i += 1) {
                    if (i > lbrace + 1) try renderExtraNewlineToken(r, i);
                    switch (tree.tokenTag(i)) {
                        .doc_comment => try renderToken(r, i, .newline),
                        .identifier => {
                            try ais.pushSpace(.comma);
                            try renderIdentifier(r, i, .comma, .eagerly_unquote);
                            ais.popSpace();
                        },
                        .comma => {},
                        else => unreachable,
                    }
                }
                ais.popIndent();
                return renderToken(r, rbrace, space);
            } else {
                // There is no trailing comma so render everything on one line.
                try renderToken(r, lbrace, .space);
                var i = lbrace + 1;
                while (i < rbrace) : (i += 1) {
                    switch (tree.tokenTag(i)) {
                        .doc_comment => unreachable, // TODO
                        .identifier => try renderIdentifier(r, i, .comma_space, .eagerly_unquote),
                        .comma => {},
                        else => unreachable,
                    }
                }
                return renderToken(r, rbrace, space);
            }
        },

        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const params = tree.builtinCallParams(&buf, node).?;
            return renderBuiltinCall(r, tree.nodeMainToken(node), params, space);
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            return renderFnProto(r, tree.fullFnProto(&buf, node).?, space);
        },

        .anyframe_type => {
            const main_token = tree.nodeMainToken(node);
            try renderToken(r, main_token, .none); // anyframe
            try renderToken(r, main_token + 1, .none); // ->
            return renderExpression(r, tree.nodeData(node).token_and_node[1], space);
        },

        .@"switch",
        .switch_comma,
        => {
            const full = tree.switchFull(node);

            if (full.label_token) |label_token| {
                try renderIdentifier(r, label_token, .none, .eagerly_unquote); // label
                try renderToken(r, label_token + 1, .space); // :
            }

            const rparen = tree.lastToken(full.ast.condition) + 1;

            try renderToken(r, full.ast.switch_token, .space); // switch
            try renderToken(r, full.ast.switch_token + 1, .none); // (
            try renderExpression(r, full.ast.condition, .none); // condition expression
            try renderToken(r, rparen, .space); // )

            try ais.pushIndent(.normal);
            if (full.ast.cases.len == 0) {
                try renderToken(r, rparen + 1, .none); // {
            } else {
                try renderToken(r, rparen + 1, .newline); // {
                try ais.pushSpace(.comma);
                try renderExpressions(r, full.ast.cases, .comma);
                ais.popSpace();
            }
            ais.popIndent();
            return renderToken(r, tree.lastToken(node), space); // }
        },

        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => return renderSwitchCase(r, tree.fullSwitchCase(node).?, space),

        .while_simple,
        .while_cont,
        .@"while",
        => return renderWhile(r, tree.fullWhile(node).?, space),

        .for_simple,
        .@"for",
        => return renderFor(r, tree.fullFor(node).?, space),

        .if_simple,
        .@"if",
        => return renderIf(r, tree.fullIf(node).?, space),

        .asm_simple,
        .@"asm",
        => return renderAsm(r, tree.fullAsm(node).?, space),

        .enum_literal => {
            try renderToken(r, tree.nodeMainToken(node) - 1, .none); // .
            return renderIdentifier(r, tree.nodeMainToken(node), space, .eagerly_unquote); // name
        },

        .fn_decl => unreachable,
        .container_field => unreachable,
        .container_field_init => unreachable,
        .container_field_align => unreachable,
        .root => unreachable,
        .global_var_decl => unreachable,
        .local_var_decl => unreachable,
        .simple_var_decl => unreachable,
        .aligned_var_decl => unreachable,
        .@"usingnamespace" => unreachable,
        .test_decl => unreachable,
        .asm_output => unreachable,
        .asm_input => unreachable,
    }
}

/// Same as `renderExpression`, but afterwards looks for any
/// append_string_after_node fixups to apply
fn renderExpressionFixup(r: *Render, node: Ast.Node.Index, space: Space) Error!void {
    const ais = r.ais;
    try renderExpression(r, node, space);
    if (r.fixups.append_string_after_node.get(node)) |bytes| {
        try ais.writer().writeAll(bytes);
    }
}

fn renderArrayType(
    r: *Render,
    array_type: Ast.full.ArrayType,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const rbracket = tree.firstToken(array_type.ast.elem_type) - 1;
    const one_line = tree.tokensOnSameLine(array_type.ast.lbracket, rbracket);
    const inner_space = if (one_line) Space.none else Space.newline;
    try ais.pushIndent(.normal);
    try renderToken(r, array_type.ast.lbracket, inner_space); // lbracket
    try renderExpression(r, array_type.ast.elem_count, inner_space);
    if (array_type.ast.sentinel.unwrap()) |sentinel| {
        try renderToken(r, tree.firstToken(sentinel) - 1, inner_space); // colon
        try renderExpression(r, sentinel, inner_space);
    }
    ais.popIndent();
    try renderToken(r, rbracket, .none); // rbracket
    return renderExpression(r, array_type.ast.elem_type, space);
}

fn renderPtrType(r: *Render, ptr_type: Ast.full.PtrType, space: Space) Error!void {
    const tree = r.tree;
    const main_token = ptr_type.ast.main_token;
    switch (ptr_type.size) {
        .one => {
            // Since ** tokens exist and the same token is shared by two
            // nested pointer types, we check to see if we are the parent
            // in such a relationship. If so, skip rendering anything for
            // this pointer type and rely on the child to render our asterisk
            // as well when it renders the ** token.
            if (tree.tokenTag(main_token) == .asterisk_asterisk and
                main_token == tree.nodeMainToken(ptr_type.ast.child_type))
            {
                return renderExpression(r, ptr_type.ast.child_type, space);
            }
            try renderToken(r, main_token, .none); // asterisk
        },
        .many => {
            if (ptr_type.ast.sentinel.unwrap()) |sentinel| {
                try renderToken(r, main_token, .none); // lbracket
                try renderToken(r, main_token + 1, .none); // asterisk
                try renderToken(r, main_token + 2, .none); // colon
                try renderExpression(r, sentinel, .none);
                try renderToken(r, tree.lastToken(sentinel) + 1, .none); // rbracket
            } else {
                try renderToken(r, main_token, .none); // lbracket
                try renderToken(r, main_token + 1, .none); // asterisk
                try renderToken(r, main_token + 2, .none); // rbracket
            }
        },
        .c => {
            try renderToken(r, main_token, .none); // lbracket
            try renderToken(r, main_token + 1, .none); // asterisk
            try renderToken(r, main_token + 2, .none); // c
            try renderToken(r, main_token + 3, .none); // rbracket
        },
        .slice => {
            if (ptr_type.ast.sentinel.unwrap()) |sentinel| {
                try renderToken(r, main_token, .none); // lbracket
                try renderToken(r, main_token + 1, .none); // colon
                try renderExpression(r, sentinel, .none);
                try renderToken(r, tree.lastToken(sentinel) + 1, .none); // rbracket
            } else {
                try renderToken(r, main_token, .none); // lbracket
                try renderToken(r, main_token + 1, .none); // rbracket
            }
        },
    }

    if (ptr_type.allowzero_token) |allowzero_token| {
        try renderToken(r, allowzero_token, .space);
    }

    if (ptr_type.ast.align_node.unwrap()) |align_node| {
        const align_first = tree.firstToken(align_node);
        try renderToken(r, align_first - 2, .none); // align
        try renderToken(r, align_first - 1, .none); // lparen
        try renderExpression(r, align_node, .none);
        if (ptr_type.ast.bit_range_start.unwrap()) |bit_range_start| {
            const bit_range_end = ptr_type.ast.bit_range_end.unwrap().?;
            try renderToken(r, tree.firstToken(bit_range_start) - 1, .none); // colon
            try renderExpression(r, bit_range_start, .none);
            try renderToken(r, tree.firstToken(bit_range_end) - 1, .none); // colon
            try renderExpression(r, bit_range_end, .none);
            try renderToken(r, tree.lastToken(bit_range_end) + 1, .space); // rparen
        } else {
            try renderToken(r, tree.lastToken(align_node) + 1, .space); // rparen
        }
    }

    if (ptr_type.ast.addrspace_node.unwrap()) |addrspace_node| {
        const addrspace_first = tree.firstToken(addrspace_node);
        try renderToken(r, addrspace_first - 2, .none); // addrspace
        try renderToken(r, addrspace_first - 1, .none); // lparen
        try renderExpression(r, addrspace_node, .none);
        try renderToken(r, tree.lastToken(addrspace_node) + 1, .space); // rparen
    }

    if (ptr_type.const_token) |const_token| {
        try renderToken(r, const_token, .space);
    }

    if (ptr_type.volatile_token) |volatile_token| {
        try renderToken(r, volatile_token, .space);
    }

    try renderExpression(r, ptr_type.ast.child_type, space);
}

fn renderSlice(
    r: *Render,
    slice_node: Ast.Node.Index,
    slice: Ast.full.Slice,
    space: Space,
) Error!void {
    const tree = r.tree;
    const after_start_space_bool = nodeCausesSliceOpSpace(tree.nodeTag(slice.ast.start)) or
        if (slice.ast.end.unwrap()) |end| nodeCausesSliceOpSpace(tree.nodeTag(end)) else false;
    const after_start_space = if (after_start_space_bool) Space.space else Space.none;
    const after_dots_space = if (slice.ast.end != .none)
        after_start_space
    else if (slice.ast.sentinel != .none) Space.space else Space.none;

    try renderExpression(r, slice.ast.sliced, .none);
    try renderToken(r, slice.ast.lbracket, .none); // lbracket

    const start_last = tree.lastToken(slice.ast.start);
    try renderExpression(r, slice.ast.start, after_start_space);
    try renderToken(r, start_last + 1, after_dots_space); // ellipsis2 ("..")

    if (slice.ast.end.unwrap()) |end| {
        const after_end_space = if (slice.ast.sentinel != .none) Space.space else Space.none;
        try renderExpression(r, end, after_end_space);
    }

    if (slice.ast.sentinel.unwrap()) |sentinel| {
        try renderToken(r, tree.firstToken(sentinel) - 1, .none); // colon
        try renderExpression(r, sentinel, .none);
    }

    try renderToken(r, tree.lastToken(slice_node), space); // rbracket
}

fn renderAsmOutput(
    r: *Render,
    asm_output: Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    assert(tree.nodeTag(asm_output) == .asm_output);
    const symbolic_name = tree.nodeMainToken(asm_output);

    try renderToken(r, symbolic_name - 1, .none); // lbracket
    try renderIdentifier(r, symbolic_name, .none, .eagerly_unquote); // ident
    try renderToken(r, symbolic_name + 1, .space); // rbracket
    try renderToken(r, symbolic_name + 2, .space); // "constraint"
    try renderToken(r, symbolic_name + 3, .none); // lparen

    if (tree.tokenTag(symbolic_name + 4) == .arrow) {
        const type_expr, const rparen = tree.nodeData(asm_output).opt_node_and_token;
        try renderToken(r, symbolic_name + 4, .space); // ->
        try renderExpression(r, type_expr.unwrap().?, Space.none);
        return renderToken(r, rparen, space);
    } else {
        try renderIdentifier(r, symbolic_name + 4, .none, .eagerly_unquote); // ident
        return renderToken(r, symbolic_name + 5, space); // rparen
    }
}

fn renderAsmInput(
    r: *Render,
    asm_input: Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    assert(tree.nodeTag(asm_input) == .asm_input);
    const symbolic_name = tree.nodeMainToken(asm_input);
    const expr, const rparen = tree.nodeData(asm_input).node_and_token;

    try renderToken(r, symbolic_name - 1, .none); // lbracket
    try renderIdentifier(r, symbolic_name, .none, .eagerly_unquote); // ident
    try renderToken(r, symbolic_name + 1, .space); // rbracket
    try renderToken(r, symbolic_name + 2, .space); // "constraint"
    try renderToken(r, symbolic_name + 3, .none); // lparen
    try renderExpression(r, expr, Space.none);
    return renderToken(r, rparen, space);
}

fn renderVarDecl(
    r: *Render,
    var_decl: Ast.full.VarDecl,
    /// Destructures intentionally ignore leading `comptime` tokens.
    ignore_comptime_token: bool,
    /// `comma_space` and `space` are used for destructure LHS decls.
    space: Space,
) Error!void {
    try renderVarDeclWithoutFixups(r, var_decl, ignore_comptime_token, space);
    if (r.fixups.unused_var_decls.contains(var_decl.ast.mut_token + 1)) {
        // Discard the variable like this: `_ = foo;`
        const w = r.ais.writer();
        try w.writeAll("_ = ");
        try w.writeAll(tokenSliceForRender(r.tree, var_decl.ast.mut_token + 1));
        try w.writeAll(";\n");
    }
}

fn renderVarDeclWithoutFixups(
    r: *Render,
    var_decl: Ast.full.VarDecl,
    /// Destructures intentionally ignore leading `comptime` tokens.
    ignore_comptime_token: bool,
    /// `comma_space` and `space` are used for destructure LHS decls.
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    if (var_decl.visib_token) |visib_token| {
        try renderToken(r, visib_token, Space.space); // pub
    }

    if (var_decl.extern_export_token) |extern_export_token| {
        try renderToken(r, extern_export_token, Space.space); // extern

        if (var_decl.lib_name) |lib_name| {
            try renderToken(r, lib_name, Space.space); // "lib"
        }
    }

    if (var_decl.threadlocal_token) |thread_local_token| {
        try renderToken(r, thread_local_token, Space.space); // threadlocal
    }

    if (!ignore_comptime_token) {
        if (var_decl.comptime_token) |comptime_token| {
            try renderToken(r, comptime_token, Space.space); // comptime
        }
    }

    try renderToken(r, var_decl.ast.mut_token, .space); // var

    if (var_decl.ast.type_node != .none or var_decl.ast.align_node != .none or
        var_decl.ast.addrspace_node != .none or var_decl.ast.section_node != .none or
        var_decl.ast.init_node != .none)
    {
        const name_space = if (var_decl.ast.type_node == .none and
            (var_decl.ast.align_node != .none or
                var_decl.ast.addrspace_node != .none or
                var_decl.ast.section_node != .none or
                var_decl.ast.init_node != .none))
            Space.space
        else
            Space.none;

        try renderIdentifier(r, var_decl.ast.mut_token + 1, name_space, .preserve_when_shadowing); // name
    } else {
        return renderIdentifier(r, var_decl.ast.mut_token + 1, space, .preserve_when_shadowing); // name
    }

    if (var_decl.ast.type_node.unwrap()) |type_node| {
        try renderToken(r, var_decl.ast.mut_token + 2, Space.space); // :
        if (var_decl.ast.align_node != .none or var_decl.ast.addrspace_node != .none or
            var_decl.ast.section_node != .none or var_decl.ast.init_node != .none)
        {
            try renderExpression(r, type_node, .space);
        } else {
            return renderExpression(r, type_node, space);
        }
    }

    if (var_decl.ast.align_node.unwrap()) |align_node| {
        const lparen = tree.firstToken(align_node) - 1;
        const align_kw = lparen - 1;
        const rparen = tree.lastToken(align_node) + 1;
        try renderToken(r, align_kw, Space.none); // align
        try renderToken(r, lparen, Space.none); // (
        try renderExpression(r, align_node, Space.none);
        if (var_decl.ast.addrspace_node != .none or var_decl.ast.section_node != .none or
            var_decl.ast.init_node != .none)
        {
            try renderToken(r, rparen, .space); // )
        } else {
            return renderToken(r, rparen, space); // )
        }
    }

    if (var_decl.ast.addrspace_node.unwrap()) |addrspace_node| {
        const lparen = tree.firstToken(addrspace_node) - 1;
        const addrspace_kw = lparen - 1;
        const rparen = tree.lastToken(addrspace_node) + 1;
        try renderToken(r, addrspace_kw, Space.none); // addrspace
        try renderToken(r, lparen, Space.none); // (
        try renderExpression(r, addrspace_node, Space.none);
        if (var_decl.ast.section_node != .none or var_decl.ast.init_node != .none) {
            try renderToken(r, rparen, .space); // )
        } else {
            try renderToken(r, rparen, .none); // )
            return renderToken(r, rparen + 1, Space.newline); // ;
        }
    }

    if (var_decl.ast.section_node.unwrap()) |section_node| {
        const lparen = tree.firstToken(section_node) - 1;
        const section_kw = lparen - 1;
        const rparen = tree.lastToken(section_node) + 1;
        try renderToken(r, section_kw, Space.none); // linksection
        try renderToken(r, lparen, Space.none); // (
        try renderExpression(r, section_node, Space.none);
        if (var_decl.ast.init_node != .none) {
            try renderToken(r, rparen, .space); // )
        } else {
            return renderToken(r, rparen, space); // )
        }
    }

    const init_node = var_decl.ast.init_node.unwrap().?;

    const eq_token = tree.firstToken(init_node) - 1;
    const eq_space: Space = if (tree.tokensOnSameLine(eq_token, eq_token + 1)) .space else .newline;
    try ais.pushIndent(.after_equals);
    try renderToken(r, eq_token, eq_space); // =
    try renderExpression(r, init_node, space); // ;
    ais.popIndent();
}

fn renderIf(r: *Render, if_node: Ast.full.If, space: Space) Error!void {
    return renderWhile(r, .{
        .ast = .{
            .while_token = if_node.ast.if_token,
            .cond_expr = if_node.ast.cond_expr,
            .cont_expr = .none,
            .then_expr = if_node.ast.then_expr,
            .else_expr = if_node.ast.else_expr,
        },
        .inline_token = null,
        .label_token = null,
        .payload_token = if_node.payload_token,
        .else_token = if_node.else_token,
        .error_token = if_node.error_token,
    }, space);
}

/// Note that this function is additionally used to render if expressions, with
/// respective values set to null.
fn renderWhile(r: *Render, while_node: Ast.full.While, space: Space) Error!void {
    const tree = r.tree;

    if (while_node.label_token) |label| {
        try renderIdentifier(r, label, .none, .eagerly_unquote); // label
        try renderToken(r, label + 1, .space); // :
    }

    if (while_node.inline_token) |inline_token| {
        try renderToken(r, inline_token, .space); // inline
    }

    try renderToken(r, while_node.ast.while_token, .space); // if/for/while
    try renderToken(r, while_node.ast.while_token + 1, .none); // lparen
    try renderExpression(r, while_node.ast.cond_expr, .none); // condition

    var last_prefix_token = tree.lastToken(while_node.ast.cond_expr) + 1; // rparen

    if (while_node.payload_token) |payload_token| {
        try renderToken(r, last_prefix_token, .space);
        try renderToken(r, payload_token - 1, .none); // |
        const ident = blk: {
            if (tree.tokenTag(payload_token) == .asterisk) {
                try renderToken(r, payload_token, .none); // *
                break :blk payload_token + 1;
            } else {
                break :blk payload_token;
            }
        };
        try renderIdentifier(r, ident, .none, .preserve_when_shadowing); // identifier
        const pipe = blk: {
            if (tree.tokenTag(ident + 1) == .comma) {
                try renderToken(r, ident + 1, .space); // ,
                try renderIdentifier(r, ident + 2, .none, .preserve_when_shadowing); // index
                break :blk ident + 3;
            } else {
                break :blk ident + 1;
            }
        };
        last_prefix_token = pipe;
    }

    if (while_node.ast.cont_expr.unwrap()) |cont_expr| {
        try renderToken(r, last_prefix_token, .space);
        const lparen = tree.firstToken(cont_expr) - 1;
        try renderToken(r, lparen - 1, .space); // :
        try renderToken(r, lparen, .none); // lparen
        try renderExpression(r, cont_expr, .none);
        last_prefix_token = tree.lastToken(cont_expr) + 1; // rparen
    }

    try renderThenElse(
        r,
        last_prefix_token,
        while_node.ast.then_expr,
        while_node.else_token,
        while_node.error_token,
        while_node.ast.else_expr,
        space,
    );
}

fn renderThenElse(
    r: *Render,
    last_prefix_token: Ast.TokenIndex,
    then_expr: Ast.Node.Index,
    else_token: ?Ast.TokenIndex,
    maybe_error_token: ?Ast.TokenIndex,
    opt_else_expr: Ast.Node.OptionalIndex,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const then_expr_is_block = nodeIsBlock(tree.nodeTag(then_expr));
    const indent_then_expr = !then_expr_is_block and
        !tree.tokensOnSameLine(last_prefix_token, tree.firstToken(then_expr));

    if (indent_then_expr) try ais.pushIndent(.normal);

    if (then_expr_is_block and ais.isLineOverIndented()) {
        ais.disableIndentCommitting();
        try renderToken(r, last_prefix_token, .newline);
        ais.enableIndentCommitting();
    } else if (indent_then_expr) {
        try renderToken(r, last_prefix_token, .newline);
    } else {
        try renderToken(r, last_prefix_token, .space);
    }

    if (opt_else_expr.unwrap()) |else_expr| {
        if (indent_then_expr) {
            try renderExpression(r, then_expr, .newline);
        } else {
            try renderExpression(r, then_expr, .space);
        }

        if (indent_then_expr) ais.popIndent();

        var last_else_token = else_token.?;

        if (maybe_error_token) |error_token| {
            try renderToken(r, last_else_token, .space); // else
            try renderToken(r, error_token - 1, .none); // |
            try renderIdentifier(r, error_token, .none, .preserve_when_shadowing); // identifier
            last_else_token = error_token + 1; // |
        }

        const indent_else_expr = indent_then_expr and
            !nodeIsBlock(tree.nodeTag(else_expr)) and
            !nodeIsIfForWhileSwitch(tree.nodeTag(else_expr));
        if (indent_else_expr) {
            try ais.pushIndent(.normal);
            try renderToken(r, last_else_token, .newline);
            try renderExpression(r, else_expr, space);
            ais.popIndent();
        } else {
            try renderToken(r, last_else_token, .space);
            try renderExpression(r, else_expr, space);
        }
    } else {
        try renderExpression(r, then_expr, space);
        if (indent_then_expr) ais.popIndent();
    }
}

fn renderFor(r: *Render, for_node: Ast.full.For, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);

    if (for_node.label_token) |label| {
        try renderIdentifier(r, label, .none, .eagerly_unquote); // label
        try renderToken(r, label + 1, .space); // :
    }

    if (for_node.inline_token) |inline_token| {
        try renderToken(r, inline_token, .space); // inline
    }

    try renderToken(r, for_node.ast.for_token, .space); // if/for/while

    const lparen = for_node.ast.for_token + 1;
    try renderParamList(r, lparen, for_node.ast.inputs, .space);

    var cur = for_node.payload_token;
    const pipe = std.mem.indexOfScalarPos(std.zig.Token.Tag, token_tags, cur, .pipe).?;
    if (tree.tokenTag(@intCast(pipe - 1)) == .comma) {
        try ais.pushIndent(.normal);
        try renderToken(r, cur - 1, .newline); // |
        while (true) {
            if (tree.tokenTag(cur) == .asterisk) {
                try renderToken(r, cur, .none); // *
                cur += 1;
            }
            try renderIdentifier(r, cur, .none, .preserve_when_shadowing); // identifier
            cur += 1;
            if (tree.tokenTag(cur) == .comma) {
                try renderToken(r, cur, .newline); // ,
                cur += 1;
            }
            if (tree.tokenTag(cur) == .pipe) {
                break;
            }
        }
        ais.popIndent();
    } else {
        try renderToken(r, cur - 1, .none); // |
        while (true) {
            if (tree.tokenTag(cur) == .asterisk) {
                try renderToken(r, cur, .none); // *
                cur += 1;
            }
            try renderIdentifier(r, cur, .none, .preserve_when_shadowing); // identifier
            cur += 1;
            if (tree.tokenTag(cur) == .comma) {
                try renderToken(r, cur, .space); // ,
                cur += 1;
            }
            if (tree.tokenTag(cur) == .pipe) {
                break;
            }
        }
    }

    try renderThenElse(
        r,
        cur,
        for_node.ast.then_expr,
        for_node.else_token,
        null,
        for_node.ast.else_expr,
        space,
    );
}

fn renderContainerField(
    r: *Render,
    container: Container,
    field_param: Ast.full.ContainerField,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    var field = field_param;
    if (container != .tuple) field.convertToNonTupleLike(&tree);
    const quote: QuoteBehavior = switch (container) {
        .@"enum" => .eagerly_unquote_except_underscore,
        .tuple, .other => .eagerly_unquote,
    };

    if (field.comptime_token) |t| {
        try renderToken(r, t, .space); // comptime
    }
    if (field.ast.type_expr == .none and field.ast.value_expr == .none) {
        if (field.ast.align_expr.unwrap()) |align_expr| {
            try renderIdentifier(r, field.ast.main_token, .space, quote); // name
            const lparen_token = tree.firstToken(align_expr) - 1;
            const align_kw = lparen_token - 1;
            const rparen_token = tree.lastToken(align_expr) + 1;
            try renderToken(r, align_kw, .none); // align
            try renderToken(r, lparen_token, .none); // (
            try renderExpression(r, align_expr, .none); // alignment
            return renderToken(r, rparen_token, .space); // )
        }
        return renderIdentifierComma(r, field.ast.main_token, space, quote); // name
    }
    if (field.ast.type_expr != .none and field.ast.value_expr == .none) {
        const type_expr = field.ast.type_expr.unwrap().?;
        if (!field.ast.tuple_like) {
            try renderIdentifier(r, field.ast.main_token, .none, quote); // name
            try renderToken(r, field.ast.main_token + 1, .space); // :
        }

        if (field.ast.align_expr.unwrap()) |align_expr| {
            try renderExpression(r, type_expr, .space); // type
            const align_token = tree.firstToken(align_expr) - 2;
            try renderToken(r, align_token, .none); // align
            try renderToken(r, align_token + 1, .none); // (
            try renderExpression(r, align_expr, .none); // alignment
            const rparen = tree.lastToken(align_expr) + 1;
            return renderTokenComma(r, rparen, space); // )
        } else {
            return renderExpressionComma(r, type_expr, space); // type
        }
    }
    if (field.ast.type_expr == .none and field.ast.value_expr != .none) {
        const value_expr = field.ast.value_expr.unwrap().?;

        try renderIdentifier(r, field.ast.main_token, .space, quote); // name
        if (field.ast.align_expr.unwrap()) |align_expr| {
            const lparen_token = tree.firstToken(align_expr) - 1;
            const align_kw = lparen_token - 1;
            const rparen_token = tree.lastToken(align_expr) + 1;
            try renderToken(r, align_kw, .none); // align
            try renderToken(r, lparen_token, .none); // (
            try renderExpression(r, align_expr, .none); // alignment
            try renderToken(r, rparen_token, .space); // )
        }
        try renderToken(r, field.ast.main_token + 1, .space); // =
        return renderExpressionComma(r, value_expr, space); // value
    }
    if (!field.ast.tuple_like) {
        try renderIdentifier(r, field.ast.main_token, .none, quote); // name
        try renderToken(r, field.ast.main_token + 1, .space); // :
    }

    const type_expr = field.ast.type_expr.unwrap().?;
    const value_expr = field.ast.value_expr.unwrap().?;

    try renderExpression(r, type_expr, .space); // type

    if (field.ast.align_expr.unwrap()) |align_expr| {
        const lparen_token = tree.firstToken(align_expr) - 1;
        const align_kw = lparen_token - 1;
        const rparen_token = tree.lastToken(align_expr) + 1;
        try renderToken(r, align_kw, .none); // align
        try renderToken(r, lparen_token, .none); // (
        try renderExpression(r, align_expr, .none); // alignment
        try renderToken(r, rparen_token, .space); // )
    }
    const eq_token = tree.firstToken(value_expr) - 1;
    const eq_space: Space = if (tree.tokensOnSameLine(eq_token, eq_token + 1)) .space else .newline;

    try ais.pushIndent(.after_equals);
    try renderToken(r, eq_token, eq_space); // =

    if (eq_space == .space) {
        ais.popIndent();
        try renderExpressionComma(r, value_expr, space); // value
        return;
    }

    const maybe_comma = tree.lastToken(value_expr) + 1;

    if (tree.tokenTag(maybe_comma) == .comma) {
        try renderExpression(r, value_expr, .none); // value
        ais.popIndent();
        try renderToken(r, maybe_comma, .newline);
    } else {
        try renderExpression(r, value_expr, space); // value
        ais.popIndent();
    }
}

fn renderBuiltinCall(
    r: *Render,
    builtin_token: Ast.TokenIndex,
    params: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    try renderToken(r, builtin_token, .none); // @name

    if (params.len == 0) {
        try renderToken(r, builtin_token + 1, .none); // (
        return renderToken(r, builtin_token + 2, space); // )
    }

    if (r.fixups.rebase_imported_paths) |prefix| {
        const slice = tree.tokenSlice(builtin_token);
        if (mem.eql(u8, slice, "@import")) f: {
            const param = params[0];
            const str_lit_token = tree.nodeMainToken(param);
            assert(tree.tokenTag(str_lit_token) == .string_literal);
            const token_bytes = tree.tokenSlice(str_lit_token);
            const imported_string = std.zig.string_literal.parseAlloc(r.gpa, token_bytes) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidLiteral => break :f,
            };
            defer r.gpa.free(imported_string);
            const new_string = try std.fs.path.resolvePosix(r.gpa, &.{ prefix, imported_string });
            defer r.gpa.free(new_string);

            try renderToken(r, builtin_token + 1, .none); // (
            try ais.writer().print("\"{}\"", .{std.zig.fmtEscapes(new_string)});
            return renderToken(r, str_lit_token + 1, space); // )
        }
    }

    const last_param = params[params.len - 1];
    const after_last_param_token = tree.lastToken(last_param) + 1;

    if (tree.tokenTag(after_last_param_token) != .comma) {
        // Render all on one line, no trailing comma.
        try renderToken(r, builtin_token + 1, .none); // (

        for (params, 0..) |param_node, i| {
            const first_param_token = tree.firstToken(param_node);
            if (tree.tokenTag(first_param_token) == .multiline_string_literal_line or
                hasSameLineComment(tree, first_param_token - 1))
            {
                try ais.pushIndent(.normal);
                try renderExpression(r, param_node, .none);
                ais.popIndent();
            } else {
                try renderExpression(r, param_node, .none);
            }

            if (i + 1 < params.len) {
                const comma_token = tree.lastToken(param_node) + 1;
                try renderToken(r, comma_token, .space); // ,
            }
        }
        return renderToken(r, after_last_param_token, space); // )
    } else {
        // Render one param per line.
        try ais.pushIndent(.normal);
        try renderToken(r, builtin_token + 1, Space.newline); // (

        for (params) |param_node| {
            try ais.pushSpace(.comma);
            try renderExpression(r, param_node, .comma);
            ais.popSpace();
        }
        ais.popIndent();

        return renderToken(r, after_last_param_token + 1, space); // )
    }
}

fn renderFnProto(r: *Render, fn_proto: Ast.full.FnProto, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    const after_fn_token = fn_proto.ast.fn_token + 1;
    const lparen = if (tree.tokenTag(after_fn_token) == .identifier) blk: {
        try renderToken(r, fn_proto.ast.fn_token, .space); // fn
        try renderIdentifier(r, after_fn_token, .none, .preserve_when_shadowing); // name
        break :blk after_fn_token + 1;
    } else blk: {
        try renderToken(r, fn_proto.ast.fn_token, .space); // fn
        break :blk fn_proto.ast.fn_token + 1;
    };
    assert(tree.tokenTag(lparen) == .l_paren);

    const return_type = fn_proto.ast.return_type.unwrap().?;
    const maybe_bang = tree.firstToken(return_type) - 1;
    const rparen = blk: {
        // These may appear in any order, so we have to check the token_starts array
        // to find out which is first.
        var rparen = if (tree.tokenTag(maybe_bang) == .bang) maybe_bang - 1 else maybe_bang;
        var smallest_start = tree.tokenStart(maybe_bang);
        if (fn_proto.ast.align_expr.unwrap()) |align_expr| {
            const tok = tree.firstToken(align_expr) - 3;
            const start = tree.tokenStart(tok);
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        if (fn_proto.ast.addrspace_expr.unwrap()) |addrspace_expr| {
            const tok = tree.firstToken(addrspace_expr) - 3;
            const start = tree.tokenStart(tok);
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        if (fn_proto.ast.section_expr.unwrap()) |section_expr| {
            const tok = tree.firstToken(section_expr) - 3;
            const start = tree.tokenStart(tok);
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr| {
            const tok = tree.firstToken(callconv_expr) - 3;
            const start = tree.tokenStart(tok);
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        break :blk rparen;
    };
    assert(tree.tokenTag(rparen) == .r_paren);

    // The params list is a sparse set that does *not* include anytype or ... parameters.

    const trailing_comma = tree.tokenTag(rparen - 1) == .comma;
    if (!trailing_comma and !hasComment(tree, lparen, rparen)) {
        // Render all on one line, no trailing comma.
        try renderToken(r, lparen, .none); // (

        var param_i: usize = 0;
        var last_param_token = lparen;
        while (true) {
            last_param_token += 1;
            switch (tree.tokenTag(last_param_token)) {
                .doc_comment => {
                    try renderToken(r, last_param_token, .newline);
                    continue;
                },
                .ellipsis3 => {
                    try renderToken(r, last_param_token, .none); // ...
                    break;
                },
                .keyword_noalias, .keyword_comptime => {
                    try renderToken(r, last_param_token, .space);
                    last_param_token += 1;
                },
                .identifier => {},
                .keyword_anytype => {
                    try renderToken(r, last_param_token, .none); // anytype
                    continue;
                },
                .r_paren => break,
                .comma => {
                    try renderToken(r, last_param_token, .space); // ,
                    continue;
                },
                else => {}, // Parameter type without a name.
            }
            if (tree.tokenTag(last_param_token) == .identifier and
                tree.tokenTag(last_param_token + 1) == .colon)
            {
                try renderIdentifier(r, last_param_token, .none, .preserve_when_shadowing); // name
                last_param_token = last_param_token + 1;
                try renderToken(r, last_param_token, .space); // :
                last_param_token += 1;
            }
            if (tree.tokenTag(last_param_token) == .keyword_anytype) {
                try renderToken(r, last_param_token, .none); // anytype
                continue;
            }
            const param = fn_proto.ast.params[param_i];
            param_i += 1;
            try renderExpression(r, param, .none);
            last_param_token = tree.lastToken(param);
        }
    } else {
        // One param per line.
        try ais.pushIndent(.normal);
        try renderToken(r, lparen, .newline); // (

        var param_i: usize = 0;
        var last_param_token = lparen;
        while (true) {
            last_param_token += 1;
            switch (tree.tokenTag(last_param_token)) {
                .doc_comment => {
                    try renderToken(r, last_param_token, .newline);
                    continue;
                },
                .ellipsis3 => {
                    try renderToken(r, last_param_token, .comma); // ...
                    break;
                },
                .keyword_noalias, .keyword_comptime => {
                    try renderToken(r, last_param_token, .space);
                    last_param_token += 1;
                },
                .identifier => {},
                .keyword_anytype => {
                    try renderToken(r, last_param_token, .comma); // anytype
                    if (tree.tokenTag(last_param_token + 1) == .comma)
                        last_param_token += 1;
                    continue;
                },
                .r_paren => break,
                else => {}, // Parameter type without a name.
            }
            if (tree.tokenTag(last_param_token) == .identifier and
                tree.tokenTag(last_param_token + 1) == .colon)
            {
                try renderIdentifier(r, last_param_token, .none, .preserve_when_shadowing); // name
                last_param_token += 1;
                try renderToken(r, last_param_token, .space); // :
                last_param_token += 1;
            }
            if (tree.tokenTag(last_param_token) == .keyword_anytype) {
                try renderToken(r, last_param_token, .comma); // anytype
                if (tree.tokenTag(last_param_token + 1) == .comma)
                    last_param_token += 1;
                continue;
            }
            const param = fn_proto.ast.params[param_i];
            param_i += 1;
            try ais.pushSpace(.comma);
            try renderExpression(r, param, .comma);
            ais.popSpace();
            last_param_token = tree.lastToken(param);
            if (tree.tokenTag(last_param_token + 1) == .comma) last_param_token += 1;
        }
        ais.popIndent();
    }

    try renderToken(r, rparen, .space); // )

    if (fn_proto.ast.align_expr.unwrap()) |align_expr| {
        const align_lparen = tree.firstToken(align_expr) - 1;
        const align_rparen = tree.lastToken(align_expr) + 1;

        try renderToken(r, align_lparen - 1, .none); // align
        try renderToken(r, align_lparen, .none); // (
        try renderExpression(r, align_expr, .none);
        try renderToken(r, align_rparen, .space); // )
    }

    if (fn_proto.ast.addrspace_expr.unwrap()) |addrspace_expr| {
        const align_lparen = tree.firstToken(addrspace_expr) - 1;
        const align_rparen = tree.lastToken(addrspace_expr) + 1;

        try renderToken(r, align_lparen - 1, .none); // addrspace
        try renderToken(r, align_lparen, .none); // (
        try renderExpression(r, addrspace_expr, .none);
        try renderToken(r, align_rparen, .space); // )
    }

    if (fn_proto.ast.section_expr.unwrap()) |section_expr| {
        const section_lparen = tree.firstToken(section_expr) - 1;
        const section_rparen = tree.lastToken(section_expr) + 1;

        try renderToken(r, section_lparen - 1, .none); // section
        try renderToken(r, section_lparen, .none); // (
        try renderExpression(r, section_expr, .none);
        try renderToken(r, section_rparen, .space); // )
    }

    if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr| {
        // Keep in sync with logic in `renderMember`. Search this file for the marker PROMOTE_CALLCONV_INLINE
        const is_callconv_inline = mem.eql(u8, "@\"inline\"", tree.tokenSlice(tree.nodeMainToken(callconv_expr)));
        const is_declaration = fn_proto.name_token != null;
        if (!(is_declaration and is_callconv_inline)) {
            const callconv_lparen = tree.firstToken(callconv_expr) - 1;
            const callconv_rparen = tree.lastToken(callconv_expr) + 1;

            try renderToken(r, callconv_lparen - 1, .none); // callconv
            try renderToken(r, callconv_lparen, .none); // (
            try renderExpression(r, callconv_expr, .none);
            try renderToken(r, callconv_rparen, .space); // )
        }
    }

    if (tree.tokenTag(maybe_bang) == .bang) {
        try renderToken(r, maybe_bang, .none); // !
    }
    return renderExpression(r, return_type, space);
}

fn renderSwitchCase(
    r: *Render,
    switch_case: Ast.full.SwitchCase,
    space: Space,
) Error!void {
    const ais = r.ais;
    const tree = r.tree;
    const trailing_comma = tree.tokenTag(switch_case.ast.arrow_token - 1) == .comma;
    const has_comment_before_arrow = blk: {
        if (switch_case.ast.values.len == 0) break :blk false;
        break :blk hasComment(tree, tree.firstToken(switch_case.ast.values[0]), switch_case.ast.arrow_token);
    };

    // render inline keyword
    if (switch_case.inline_token) |some| {
        try renderToken(r, some, .space);
    }

    // Render everything before the arrow
    if (switch_case.ast.values.len == 0) {
        try renderToken(r, switch_case.ast.arrow_token - 1, .space); // else keyword
    } else if (trailing_comma or has_comment_before_arrow) {
        // Render each value on a new line
        try ais.pushSpace(.comma);
        try renderExpressions(r, switch_case.ast.values, .comma);
        ais.popSpace();
    } else {
        // Render on one line
        for (switch_case.ast.values) |value_expr| {
            try renderExpression(r, value_expr, .comma_space);
        }
    }

    // Render the arrow and everything after it
    const pre_target_space = if (tree.nodeTag(switch_case.ast.target_expr) == .multiline_string_literal)
        // Newline gets inserted when rendering the target expr.
        Space.none
    else
        Space.space;
    const after_arrow_space: Space = if (switch_case.payload_token == null) pre_target_space else .space;
    try renderToken(r, switch_case.ast.arrow_token, after_arrow_space); // =>

    if (switch_case.payload_token) |payload_token| {
        try renderToken(r, payload_token - 1, .none); // pipe
        const ident = payload_token + @intFromBool(tree.tokenTag(payload_token) == .asterisk);
        if (tree.tokenTag(payload_token) == .asterisk) {
            try renderToken(r, payload_token, .none); // asterisk
        }
        try renderIdentifier(r, ident, .none, .preserve_when_shadowing); // identifier
        if (tree.tokenTag(ident + 1) == .comma) {
            try renderToken(r, ident + 1, .space); // ,
            try renderIdentifier(r, ident + 2, .none, .preserve_when_shadowing); // identifier
            try renderToken(r, ident + 3, pre_target_space); // pipe
        } else {
            try renderToken(r, ident + 1, pre_target_space); // pipe
        }
    }

    try renderExpression(r, switch_case.ast.target_expr, space);
}

fn renderBlock(
    r: *Render,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const lbrace = tree.nodeMainToken(block_node);

    if (tree.isTokenPrecededByTags(lbrace, &.{ .identifier, .colon })) {
        try renderIdentifier(r, lbrace - 2, .none, .eagerly_unquote); // identifier
        try renderToken(r, lbrace - 1, .space); // :
    }
    try ais.pushIndent(.normal);
    if (statements.len == 0) {
        try renderToken(r, lbrace, .none);
        ais.popIndent();
        try renderToken(r, tree.lastToken(block_node), space); // rbrace
        return;
    }
    try renderToken(r, lbrace, .newline);
    return finishRenderBlock(r, block_node, statements, space);
}

fn finishRenderBlock(
    r: *Render,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    for (statements, 0..) |stmt, i| {
        if (i != 0) try renderExtraNewline(r, stmt);
        if (r.fixups.omit_nodes.contains(stmt)) continue;
        try ais.pushSpace(.semicolon);
        switch (tree.nodeTag(stmt)) {
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => try renderVarDecl(r, tree.fullVarDecl(stmt).?, false, .semicolon),

            else => try renderExpression(r, stmt, .semicolon),
        }
        ais.popSpace();
    }
    ais.popIndent();

    try renderToken(r, tree.lastToken(block_node), space); // rbrace
}

fn renderStructInit(
    r: *Render,
    struct_node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    if (struct_init.ast.type_expr.unwrap()) |type_expr| {
        try renderExpression(r, type_expr, .none); // T
    } else {
        try renderToken(r, struct_init.ast.lbrace - 1, .none); // .
    }

    if (struct_init.ast.fields.len == 0) {
        try ais.pushIndent(.normal);
        try renderToken(r, struct_init.ast.lbrace, .none); // lbrace
        ais.popIndent();
        return renderToken(r, struct_init.ast.lbrace + 1, space); // rbrace
    }

    const rbrace = tree.lastToken(struct_node);
    const trailing_comma = tree.tokenTag(rbrace - 1) == .comma;
    if (trailing_comma or hasComment(tree, struct_init.ast.lbrace, rbrace)) {
        // Render one field init per line.
        try ais.pushIndent(.normal);
        try renderToken(r, struct_init.ast.lbrace, .newline);

        try renderToken(r, struct_init.ast.lbrace + 1, .none); // .
        try renderIdentifier(r, struct_init.ast.lbrace + 2, .space, .eagerly_unquote); // name
        // Don't output a space after the = if expression is a multiline string,
        // since then it will start on the next line.
        const field_node = struct_init.ast.fields[0];
        const expr = tree.nodeTag(field_node);
        var space_after_equal: Space = if (expr == .multiline_string_literal) .none else .space;
        try renderToken(r, struct_init.ast.lbrace + 3, space_after_equal); // =

        try ais.pushSpace(.comma);
        try renderExpressionFixup(r, field_node, .comma);
        ais.popSpace();

        for (struct_init.ast.fields[1..]) |field_init| {
            const init_token = tree.firstToken(field_init);
            try renderExtraNewlineToken(r, init_token - 3);
            try renderToken(r, init_token - 3, .none); // .
            try renderIdentifier(r, init_token - 2, .space, .eagerly_unquote); // name
            space_after_equal = if (tree.nodeTag(field_init) == .multiline_string_literal) .none else .space;
            try renderToken(r, init_token - 1, space_after_equal); // =

            try ais.pushSpace(.comma);
            try renderExpressionFixup(r, field_init, .comma);
            ais.popSpace();
        }

        ais.popIndent();
    } else {
        // Render all on one line, no trailing comma.
        try renderToken(r, struct_init.ast.lbrace, .space);

        for (struct_init.ast.fields) |field_init| {
            const init_token = tree.firstToken(field_init);
            try renderToken(r, init_token - 3, .none); // .
            try renderIdentifier(r, init_token - 2, .space, .eagerly_unquote); // name
            try renderToken(r, init_token - 1, .space); // =
            try renderExpressionFixup(r, field_init, .comma_space);
        }
    }

    return renderToken(r, rbrace, space);
}

fn renderArrayInit(
    r: *Render,
    array_init: Ast.full.ArrayInit,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const gpa = r.gpa;

    if (array_init.ast.type_expr.unwrap()) |type_expr| {
        try renderExpression(r, type_expr, .none); // T
    } else {
        try renderToken(r, array_init.ast.lbrace - 1, .none); // .
    }

    if (array_init.ast.elements.len == 0) {
        try ais.pushIndent(.normal);
        try renderToken(r, array_init.ast.lbrace, .none); // lbrace
        ais.popIndent();
        return renderToken(r, array_init.ast.lbrace + 1, space); // rbrace
    }

    const last_elem = array_init.ast.elements[array_init.ast.elements.len - 1];
    const last_elem_token = tree.lastToken(last_elem);
    const trailing_comma = tree.tokenTag(last_elem_token + 1) == .comma;
    const rbrace = if (trailing_comma) last_elem_token + 2 else last_elem_token + 1;
    assert(tree.tokenTag(rbrace) == .r_brace);

    if (array_init.ast.elements.len == 1) {
        const only_elem = array_init.ast.elements[0];
        const first_token = tree.firstToken(only_elem);
        if (tree.tokenTag(first_token) != .multiline_string_literal_line and
            !anythingBetween(tree, last_elem_token, rbrace))
        {
            try renderToken(r, array_init.ast.lbrace, .none);
            try renderExpression(r, only_elem, .none);
            return renderToken(r, rbrace, space);
        }
    }

    const contains_comment = hasComment(tree, array_init.ast.lbrace, rbrace);
    const contains_multiline_string = hasMultilineString(tree, array_init.ast.lbrace, rbrace);

    if (!trailing_comma and !contains_comment and !contains_multiline_string) {
        // Render all on one line, no trailing comma.
        if (array_init.ast.elements.len == 1) {
            // If there is only one element, we don't use spaces
            try renderToken(r, array_init.ast.lbrace, .none);
            try renderExpression(r, array_init.ast.elements[0], .none);
        } else {
            try renderToken(r, array_init.ast.lbrace, .space);
            for (array_init.ast.elements) |elem| {
                try renderExpression(r, elem, .comma_space);
            }
        }
        return renderToken(r, last_elem_token + 1, space); // rbrace
    }

    try ais.pushIndent(.normal);
    try renderToken(r, array_init.ast.lbrace, .newline);

    var expr_index: usize = 0;
    while (true) {
        const row_size = rowSize(tree, array_init.ast.elements[expr_index..], rbrace);
        const row_exprs = array_init.ast.elements[expr_index..];
        // A place to store the width of each expression and its column's maximum
        const widths = try gpa.alloc(usize, row_exprs.len + row_size);
        defer gpa.free(widths);
        @memset(widths, 0);

        const expr_newlines = try gpa.alloc(bool, row_exprs.len);
        defer gpa.free(expr_newlines);
        @memset(expr_newlines, false);

        const expr_widths = widths[0..row_exprs.len];
        const column_widths = widths[row_exprs.len..];

        // Find next row with trailing comment (if any) to end the current section.
        const section_end = sec_end: {
            var this_line_first_expr: usize = 0;
            var this_line_size = rowSize(tree, row_exprs, rbrace);
            for (row_exprs, 0..) |expr, i| {
                // Ignore comment on first line of this section.
                if (i == 0) continue;
                const expr_last_token = tree.lastToken(expr);
                if (tree.tokensOnSameLine(tree.firstToken(row_exprs[0]), expr_last_token))
                    continue;
                // Track start of line containing comment.
                if (!tree.tokensOnSameLine(tree.firstToken(row_exprs[this_line_first_expr]), expr_last_token)) {
                    this_line_first_expr = i;
                    this_line_size = rowSize(tree, row_exprs[this_line_first_expr..], rbrace);
                }

                const maybe_comma = expr_last_token + 1;
                if (tree.tokenTag(maybe_comma) == .comma) {
                    if (hasSameLineComment(tree, maybe_comma))
                        break :sec_end i - this_line_size + 1;
                }
            }
            break :sec_end row_exprs.len;
        };
        expr_index += section_end;

        const section_exprs = row_exprs[0..section_end];

        var sub_expr_buffer = std.ArrayList(u8).init(gpa);
        defer sub_expr_buffer.deinit();

        const sub_expr_buffer_starts = try gpa.alloc(usize, section_exprs.len + 1);
        defer gpa.free(sub_expr_buffer_starts);

        var auto_indenting_stream = Ais.init(&sub_expr_buffer, indent_delta);
        defer auto_indenting_stream.deinit();
        var sub_render: Render = .{
            .gpa = r.gpa,
            .ais = &auto_indenting_stream,
            .tree = r.tree,
            .fixups = r.fixups,
        };

        // Calculate size of columns in current section
        var column_counter: usize = 0;
        var single_line = true;
        var contains_newline = false;
        for (section_exprs, 0..) |expr, i| {
            const start = sub_expr_buffer.items.len;
            sub_expr_buffer_starts[i] = start;

            if (i + 1 < section_exprs.len) {
                try renderExpression(&sub_render, expr, .none);
                const width = sub_expr_buffer.items.len - start;
                const this_contains_newline = mem.indexOfScalar(u8, sub_expr_buffer.items[start..], '\n') != null;
                contains_newline = contains_newline or this_contains_newline;
                expr_widths[i] = width;
                expr_newlines[i] = this_contains_newline;

                if (!this_contains_newline) {
                    const column = column_counter % row_size;
                    column_widths[column] = @max(column_widths[column], width);

                    const expr_last_token = tree.lastToken(expr) + 1;
                    const next_expr = section_exprs[i + 1];
                    column_counter += 1;
                    if (!tree.tokensOnSameLine(expr_last_token, tree.firstToken(next_expr))) single_line = false;
                } else {
                    single_line = false;
                    column_counter = 0;
                }
            } else {
                try ais.pushSpace(.comma);
                try renderExpression(&sub_render, expr, .comma);
                ais.popSpace();

                const width = sub_expr_buffer.items.len - start - 2;
                const this_contains_newline = mem.indexOfScalar(u8, sub_expr_buffer.items[start .. sub_expr_buffer.items.len - 1], '\n') != null;
                contains_newline = contains_newline or this_contains_newline;
                expr_widths[i] = width;
                expr_newlines[i] = contains_newline;

                if (!contains_newline) {
                    const column = column_counter % row_size;
                    column_widths[column] = @max(column_widths[column], width);
                }
            }
        }
        sub_expr_buffer_starts[section_exprs.len] = sub_expr_buffer.items.len;

        // Render exprs in current section.
        column_counter = 0;
        for (section_exprs, 0..) |expr, i| {
            const start = sub_expr_buffer_starts[i];
            const end = sub_expr_buffer_starts[i + 1];
            const expr_text = sub_expr_buffer.items[start..end];
            if (!expr_newlines[i]) {
                try ais.writer().writeAll(expr_text);
            } else {
                var by_line = std.mem.splitScalar(u8, expr_text, '\n');
                var last_line_was_empty = false;
           ```
