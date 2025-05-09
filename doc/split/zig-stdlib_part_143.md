```
     try ais.writer().writeAll(by_line.first());
                while (by_line.next()) |line| {
                    if (std.mem.startsWith(u8, line, "//") and last_line_was_empty) {
                        try ais.insertNewline();
                    } else {
                        try ais.maybeInsertNewline();
                    }
                    last_line_was_empty = (line.len == 0);
                    try ais.writer().writeAll(line);
                }
            }

            if (i + 1 < section_exprs.len) {
                const next_expr = section_exprs[i + 1];
                const comma = tree.lastToken(expr) + 1;

                if (column_counter != row_size - 1) {
                    if (!expr_newlines[i] and !expr_newlines[i + 1]) {
                        // Neither the current or next expression is multiline
                        try renderToken(r, comma, .space); // ,
                        assert(column_widths[column_counter % row_size] >= expr_widths[i]);
                        const padding = column_widths[column_counter % row_size] - expr_widths[i];
                        try ais.writer().writeByteNTimes(' ', padding);

                        column_counter += 1;
                        continue;
                    }
                }

                if (single_line and row_size != 1) {
                    try renderToken(r, comma, .space); // ,
                    continue;
                }

                column_counter = 0;
                try renderToken(r, comma, .newline); // ,
                try renderExtraNewline(r, next_expr);
            }
        }

        if (expr_index == array_init.ast.elements.len)
            break;
    }

    ais.popIndent();
    return renderToken(r, rbrace, space); // rbrace
}

fn renderContainerDecl(
    r: *Render,
    container_decl_node: Ast.Node.Index,
    container_decl: Ast.full.ContainerDecl,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    if (container_decl.layout_token) |layout_token| {
        try renderToken(r, layout_token, .space);
    }

    const container: Container = switch (tree.tokenTag(container_decl.ast.main_token)) {
        .keyword_enum => .@"enum",
        .keyword_struct => for (container_decl.ast.members) |member| {
            if (tree.fullContainerField(member)) |field| if (!field.ast.tuple_like) break .other;
        } else .tuple,
        else => .other,
    };

    var lbrace: Ast.TokenIndex = undefined;
    if (container_decl.ast.enum_token) |enum_token| {
        try renderToken(r, container_decl.ast.main_token, .none); // union
        try renderToken(r, enum_token - 1, .none); // lparen
        try renderToken(r, enum_token, .none); // enum
        if (container_decl.ast.arg.unwrap()) |arg| {
            try renderToken(r, enum_token + 1, .none); // lparen
            try renderExpression(r, arg, .none);
            const rparen = tree.lastToken(arg) + 1;
            try renderToken(r, rparen, .none); // rparen
            try renderToken(r, rparen + 1, .space); // rparen
            lbrace = rparen + 2;
        } else {
            try renderToken(r, enum_token + 1, .space); // rparen
            lbrace = enum_token + 2;
        }
    } else if (container_decl.ast.arg.unwrap()) |arg| {
        try renderToken(r, container_decl.ast.main_token, .none); // union
        try renderToken(r, container_decl.ast.main_token + 1, .none); // lparen
        try renderExpression(r, arg, .none);
        const rparen = tree.lastToken(arg) + 1;
        try renderToken(r, rparen, .space); // rparen
        lbrace = rparen + 1;
    } else {
        try renderToken(r, container_decl.ast.main_token, .space); // union
        lbrace = container_decl.ast.main_token + 1;
    }

    const rbrace = tree.lastToken(container_decl_node);

    if (container_decl.ast.members.len == 0) {
        try ais.pushIndent(.normal);
        if (tree.tokenTag(lbrace + 1) == .container_doc_comment) {
            try renderToken(r, lbrace, .newline); // lbrace
            try renderContainerDocComments(r, lbrace + 1);
        } else {
            try renderToken(r, lbrace, .none); // lbrace
        }
        ais.popIndent();
        return renderToken(r, rbrace, space); // rbrace
    }

    const src_has_trailing_comma = tree.tokenTag(rbrace - 1) == .comma;
    if (!src_has_trailing_comma) one_line: {
        // We print all the members in-line unless one of the following conditions are true:

        // 1. The container has comments or multiline strings.
        if (hasComment(tree, lbrace, rbrace) or hasMultilineString(tree, lbrace, rbrace)) {
            break :one_line;
        }

        // 2. The container has a container comment.
        if (tree.tokenTag(lbrace + 1) == .container_doc_comment) break :one_line;

        // 3. A member of the container has a doc comment.
        for (tree.tokens.items(.tag)[lbrace + 1 .. rbrace - 1]) |tag| {
            if (tag == .doc_comment) break :one_line;
        }

        // 4. The container has non-field members.
        for (container_decl.ast.members) |member| {
            if (tree.fullContainerField(member) == null) break :one_line;
        }

        // Print all the declarations on the same line.
        try renderToken(r, lbrace, .space); // lbrace
        for (container_decl.ast.members) |member| {
            try renderMember(r, container, member, .space);
        }
        return renderToken(r, rbrace, space); // rbrace
    }

    // One member per line.
    try ais.pushIndent(.normal);
    try renderToken(r, lbrace, .newline); // lbrace
    if (tree.tokenTag(lbrace + 1) == .container_doc_comment) {
        try renderContainerDocComments(r, lbrace + 1);
    }
    for (container_decl.ast.members, 0..) |member, i| {
        if (i != 0) try renderExtraNewline(r, member);
        switch (tree.nodeTag(member)) {
            // For container fields, ensure a trailing comma is added if necessary.
            .container_field_init,
            .container_field_align,
            .container_field,
            => {
                try ais.pushSpace(.comma);
                try renderMember(r, container, member, .comma);
                ais.popSpace();
            },

            else => try renderMember(r, container, member, .newline),
        }
    }
    ais.popIndent();

    return renderToken(r, rbrace, space); // rbrace
}

fn renderAsm(
    r: *Render,
    asm_node: Ast.full.Asm,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    try renderToken(r, asm_node.ast.asm_token, .space); // asm

    if (asm_node.volatile_token) |volatile_token| {
        try renderToken(r, volatile_token, .space); // volatile
        try renderToken(r, volatile_token + 1, .none); // lparen
    } else {
        try renderToken(r, asm_node.ast.asm_token + 1, .none); // lparen
    }

    if (asm_node.ast.items.len == 0) {
        try ais.forcePushIndent(.normal);
        if (asm_node.first_clobber) |first_clobber| {
            // asm ("foo" ::: "a", "b")
            // asm ("foo" ::: "a", "b",)
            try renderExpression(r, asm_node.ast.template, .space);
            // Render the three colons.
            try renderToken(r, first_clobber - 3, .none);
            try renderToken(r, first_clobber - 2, .none);
            try renderToken(r, first_clobber - 1, .space);

            var tok_i = first_clobber;
            while (true) : (tok_i += 1) {
                try renderToken(r, tok_i, .none);
                tok_i += 1;
                switch (tree.tokenTag(tok_i)) {
                    .r_paren => {
                        ais.popIndent();
                        return renderToken(r, tok_i, space);
                    },
                    .comma => {
                        if (tree.tokenTag(tok_i + 1) == .r_paren) {
                            ais.popIndent();
                            return renderToken(r, tok_i + 1, space);
                        } else {
                            try renderToken(r, tok_i, .space);
                        }
                    },
                    else => unreachable,
                }
            }
        } else {
            // asm ("foo")
            try renderExpression(r, asm_node.ast.template, .none);
            ais.popIndent();
            return renderToken(r, asm_node.ast.rparen, space); // rparen
        }
    }

    try ais.forcePushIndent(.normal);
    try renderExpression(r, asm_node.ast.template, .newline);
    ais.setIndentDelta(asm_indent_delta);
    const colon1 = tree.lastToken(asm_node.ast.template) + 1;

    const colon2 = if (asm_node.outputs.len == 0) colon2: {
        try renderToken(r, colon1, .newline); // :
        break :colon2 colon1 + 1;
    } else colon2: {
        try renderToken(r, colon1, .space); // :

        try ais.forcePushIndent(.normal);
        for (asm_node.outputs, 0..) |asm_output, i| {
            if (i + 1 < asm_node.outputs.len) {
                const next_asm_output = asm_node.outputs[i + 1];
                try renderAsmOutput(r, asm_output, .none);

                const comma = tree.firstToken(next_asm_output) - 1;
                try renderToken(r, comma, .newline); // ,
                try renderExtraNewlineToken(r, tree.firstToken(next_asm_output));
            } else if (asm_node.inputs.len == 0 and asm_node.first_clobber == null) {
                try ais.pushSpace(.comma);
                try renderAsmOutput(r, asm_output, .comma);
                ais.popSpace();
                ais.popIndent();
                ais.setIndentDelta(indent_delta);
                ais.popIndent();
                return renderToken(r, asm_node.ast.rparen, space); // rparen
            } else {
                try ais.pushSpace(.comma);
                try renderAsmOutput(r, asm_output, .comma);
                ais.popSpace();
                const comma_or_colon = tree.lastToken(asm_output) + 1;
                ais.popIndent();
                break :colon2 switch (tree.tokenTag(comma_or_colon)) {
                    .comma => comma_or_colon + 1,
                    else => comma_or_colon,
                };
            }
        } else unreachable;
    };

    const colon3 = if (asm_node.inputs.len == 0) colon3: {
        try renderToken(r, colon2, .newline); // :
        break :colon3 colon2 + 1;
    } else colon3: {
        try renderToken(r, colon2, .space); // :
        try ais.forcePushIndent(.normal);
        for (asm_node.inputs, 0..) |asm_input, i| {
            if (i + 1 < asm_node.inputs.len) {
                const next_asm_input = asm_node.inputs[i + 1];
                try renderAsmInput(r, asm_input, .none);

                const first_token = tree.firstToken(next_asm_input);
                try renderToken(r, first_token - 1, .newline); // ,
                try renderExtraNewlineToken(r, first_token);
            } else if (asm_node.first_clobber == null) {
                try ais.pushSpace(.comma);
                try renderAsmInput(r, asm_input, .comma);
                ais.popSpace();
                ais.popIndent();
                ais.setIndentDelta(indent_delta);
                ais.popIndent();
                return renderToken(r, asm_node.ast.rparen, space); // rparen
            } else {
                try ais.pushSpace(.comma);
                try renderAsmInput(r, asm_input, .comma);
                ais.popSpace();
                const comma_or_colon = tree.lastToken(asm_input) + 1;
                ais.popIndent();
                break :colon3 switch (tree.tokenTag(comma_or_colon)) {
                    .comma => comma_or_colon + 1,
                    else => comma_or_colon,
                };
            }
        }
        unreachable;
    };

    try renderToken(r, colon3, .space); // :
    const first_clobber = asm_node.first_clobber.?;
    var tok_i = first_clobber;
    while (true) {
        switch (tree.tokenTag(tok_i + 1)) {
            .r_paren => {
                ais.setIndentDelta(indent_delta);
                try renderToken(r, tok_i, .newline);
                ais.popIndent();
                return renderToken(r, tok_i + 1, space);
            },
            .comma => {
                switch (tree.tokenTag(tok_i + 2)) {
                    .r_paren => {
                        ais.setIndentDelta(indent_delta);
                        try renderToken(r, tok_i, .newline);
                        ais.popIndent();
                        return renderToken(r, tok_i + 2, space);
                    },
                    else => {
                        try renderToken(r, tok_i, .none);
                        try renderToken(r, tok_i + 1, .space);
                        tok_i += 2;
                    },
                }
            },
            else => unreachable,
        }
    }
}

fn renderCall(
    r: *Render,
    call: Ast.full.Call,
    space: Space,
) Error!void {
    if (call.async_token) |async_token| {
        try renderToken(r, async_token, .space);
    }
    try renderExpression(r, call.ast.fn_expr, .none);
    try renderParamList(r, call.ast.lparen, call.ast.params, space);
}

fn renderParamList(
    r: *Render,
    lparen: Ast.TokenIndex,
    params: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    if (params.len == 0) {
        try ais.pushIndent(.normal);
        try renderToken(r, lparen, .none);
        ais.popIndent();
        return renderToken(r, lparen + 1, space); // )
    }

    const last_param = params[params.len - 1];
    const after_last_param_tok = tree.lastToken(last_param) + 1;
    if (tree.tokenTag(after_last_param_tok) == .comma) {
        try ais.pushIndent(.normal);
        try renderToken(r, lparen, .newline); // (
        for (params, 0..) |param_node, i| {
            if (i + 1 < params.len) {
                try renderExpression(r, param_node, .none);

                const comma = tree.lastToken(param_node) + 1;
                try renderToken(r, comma, .newline); // ,

                try renderExtraNewline(r, params[i + 1]);
            } else {
                try ais.pushSpace(.comma);
                try renderExpression(r, param_node, .comma);
                ais.popSpace();
            }
        }
        ais.popIndent();
        return renderToken(r, after_last_param_tok + 1, space); // )
    }

    try ais.pushIndent(.normal);
    try renderToken(r, lparen, .none); // (
    for (params, 0..) |param_node, i| {
        try renderExpression(r, param_node, .none);

        if (i + 1 < params.len) {
            const comma = tree.lastToken(param_node) + 1;
            const next_multiline_string =
                tree.tokenTag(tree.firstToken(params[i + 1])) == .multiline_string_literal_line;
            const comma_space: Space = if (next_multiline_string) .none else .space;
            try renderToken(r, comma, comma_space);
        }
    }
    ais.popIndent();
    return renderToken(r, after_last_param_tok, space); // )
}

/// Render an expression, and the comma that follows it, if it is present in the source.
/// If a comma is present, and `space` is `Space.comma`, render only a single comma.
fn renderExpressionComma(r: *Render, node: Ast.Node.Index, space: Space) Error!void {
    const tree = r.tree;
    const maybe_comma = tree.lastToken(node) + 1;
    if (tree.tokenTag(maybe_comma) == .comma and space != .comma) {
        try renderExpression(r, node, .none);
        return renderToken(r, maybe_comma, space);
    } else {
        return renderExpression(r, node, space);
    }
}

/// Render a token, and the comma that follows it, if it is present in the source.
/// If a comma is present, and `space` is `Space.comma`, render only a single comma.
fn renderTokenComma(r: *Render, token: Ast.TokenIndex, space: Space) Error!void {
    const tree = r.tree;
    const maybe_comma = token + 1;
    if (tree.tokenTag(maybe_comma) == .comma and space != .comma) {
        try renderToken(r, token, .none);
        return renderToken(r, maybe_comma, space);
    } else {
        return renderToken(r, token, space);
    }
}

/// Render an identifier, and the comma that follows it, if it is present in the source.
/// If a comma is present, and `space` is `Space.comma`, render only a single comma.
fn renderIdentifierComma(r: *Render, token: Ast.TokenIndex, space: Space, quote: QuoteBehavior) Error!void {
    const tree = r.tree;
    const maybe_comma = token + 1;
    if (tree.tokenTag(maybe_comma) == .comma and space != .comma) {
        try renderIdentifier(r, token, .none, quote);
        return renderToken(r, maybe_comma, space);
    } else {
        return renderIdentifier(r, token, space, quote);
    }
}

const Space = enum {
    /// Output the token lexeme only.
    none,
    /// Output the token lexeme followed by a single space.
    space,
    /// Output the token lexeme followed by a newline.
    newline,
    /// If the next token is a comma, render it as well. If not, insert one.
    /// In either case, a newline will be inserted afterwards.
    comma,
    /// Additionally consume the next token if it is a comma.
    /// In either case, a space will be inserted afterwards.
    comma_space,
    /// Additionally consume the next token if it is a semicolon.
    /// In either case, a newline will be inserted afterwards.
    semicolon,
    /// Skip rendering whitespace and comments. If this is used, the caller
    /// *must* handle whitespace and comments manually.
    skip,
};

fn renderToken(r: *Render, token_index: Ast.TokenIndex, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const lexeme = tokenSliceForRender(tree, token_index);
    try ais.writer().writeAll(lexeme);
    try renderSpace(r, token_index, lexeme.len, space);
}

fn renderTokenOverrideSpaceMode(r: *Render, token_index: Ast.TokenIndex, space: Space, override_space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const lexeme = tokenSliceForRender(tree, token_index);
    try ais.writer().writeAll(lexeme);
    ais.enableSpaceMode(override_space);
    defer ais.disableSpaceMode();
    try renderSpace(r, token_index, lexeme.len, space);
}

fn renderSpace(r: *Render, token_index: Ast.TokenIndex, lexeme_len: usize, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    const next_token_tag = tree.tokenTag(token_index + 1);

    if (space == .skip) return;

    if (space == .comma and next_token_tag != .comma) {
        try ais.writer().writeByte(',');
    }
    if (space == .semicolon or space == .comma) ais.enableSpaceMode(space);
    defer ais.disableSpaceMode();
    const comment = try renderComments(
        r,
        tree.tokenStart(token_index) + lexeme_len,
        tree.tokenStart(token_index + 1),
    );
    switch (space) {
        .none => {},
        .space => if (!comment) try ais.writer().writeByte(' '),
        .newline => if (!comment) try ais.insertNewline(),

        .comma => if (next_token_tag == .comma) {
            try renderToken(r, token_index + 1, .newline);
        } else if (!comment) {
            try ais.insertNewline();
        },

        .comma_space => if (next_token_tag == .comma) {
            try renderToken(r, token_index + 1, .space);
        } else if (!comment) {
            try ais.writer().writeByte(' ');
        },

        .semicolon => if (next_token_tag == .semicolon) {
            try renderToken(r, token_index + 1, .newline);
        } else if (!comment) {
            try ais.insertNewline();
        },

        .skip => unreachable,
    }
}

fn renderOnlySpace(r: *Render, space: Space) Error!void {
    const ais = r.ais;
    switch (space) {
        .none => {},
        .space => try ais.writer().writeByte(' '),
        .newline => try ais.insertNewline(),
        .comma => try ais.writer().writeAll(",\n"),
        .comma_space => try ais.writer().writeAll(", "),
        .semicolon => try ais.writer().writeAll(";\n"),
        .skip => unreachable,
    }
}

const QuoteBehavior = enum {
    preserve_when_shadowing,
    eagerly_unquote,
    eagerly_unquote_except_underscore,
};

fn renderIdentifier(r: *Render, token_index: Ast.TokenIndex, space: Space, quote: QuoteBehavior) Error!void {
    const tree = r.tree;
    assert(tree.tokenTag(token_index) == .identifier);
    const lexeme = tokenSliceForRender(tree, token_index);

    if (r.fixups.rename_identifiers.get(lexeme)) |mangled| {
        try r.ais.writer().writeAll(mangled);
        try renderSpace(r, token_index, lexeme.len, space);
        return;
    }

    if (lexeme[0] != '@') {
        return renderToken(r, token_index, space);
    }

    assert(lexeme.len >= 3);
    assert(lexeme[0] == '@');
    assert(lexeme[1] == '\"');
    assert(lexeme[lexeme.len - 1] == '\"');
    const contents = lexeme[2 .. lexeme.len - 1]; // inside the @"" quotation

    // Empty name can't be unquoted.
    if (contents.len == 0) {
        return renderQuotedIdentifier(r, token_index, space, false);
    }

    // Special case for _.
    if (std.zig.isUnderscore(contents)) switch (quote) {
        .eagerly_unquote => return renderQuotedIdentifier(r, token_index, space, true),
        .eagerly_unquote_except_underscore,
        .preserve_when_shadowing,
        => return renderQuotedIdentifier(r, token_index, space, false),
    };

    // Scan the entire name for characters that would (after un-escaping) be illegal in a symbol,
    // i.e. contents don't match: [A-Za-z_][A-Za-z0-9_]*
    var contents_i: usize = 0;
    while (contents_i < contents.len) {
        switch (contents[contents_i]) {
            '0'...'9' => if (contents_i == 0) return renderQuotedIdentifier(r, token_index, space, false),
            'A'...'Z', 'a'...'z', '_' => {},
            '\\' => {
                var esc_offset = contents_i;
                const res = std.zig.string_literal.parseEscapeSequence(contents, &esc_offset);
                switch (res) {
                    .success => |char| switch (char) {
                        '0'...'9' => if (contents_i == 0) return renderQuotedIdentifier(r, token_index, space, false),
                        'A'...'Z', 'a'...'z', '_' => {},
                        else => return renderQuotedIdentifier(r, token_index, space, false),
                    },
                    .failure => return renderQuotedIdentifier(r, token_index, space, false),
                }
                contents_i += esc_offset;
                continue;
            },
            else => return renderQuotedIdentifier(r, token_index, space, false),
        }
        contents_i += 1;
    }

    // Read enough of the name (while un-escaping) to determine if it's a keyword or primitive.
    // If it's too long to fit in this buffer, we know it's neither and quoting is unnecessary.
    // If we read the whole thing, we have to do further checks.
    const longest_keyword_or_primitive_len = comptime blk: {
        var longest = 0;
        for (primitives.names.keys()) |key| {
            if (key.len > longest) longest = key.len;
        }
        for (std.zig.Token.keywords.keys()) |key| {
            if (key.len > longest) longest = key.len;
        }
        break :blk longest;
    };
    var buf: [longest_keyword_or_primitive_len]u8 = undefined;

    contents_i = 0;
    var buf_i: usize = 0;
    while (contents_i < contents.len and buf_i < longest_keyword_or_primitive_len) {
        if (contents[contents_i] == '\\') {
            const res = std.zig.string_literal.parseEscapeSequence(contents, &contents_i).success;
            buf[buf_i] = @as(u8, @intCast(res));
            buf_i += 1;
        } else {
            buf[buf_i] = contents[contents_i];
            contents_i += 1;
            buf_i += 1;
        }
    }

    // We read the whole thing, so it could be a keyword or primitive.
    if (contents_i == contents.len) {
        if (!std.zig.isValidId(buf[0..buf_i])) {
            return renderQuotedIdentifier(r, token_index, space, false);
        }
        if (primitives.isPrimitive(buf[0..buf_i])) switch (quote) {
            .eagerly_unquote,
            .eagerly_unquote_except_underscore,
            => return renderQuotedIdentifier(r, token_index, space, true),
            .preserve_when_shadowing => return renderQuotedIdentifier(r, token_index, space, false),
        };
    }

    try renderQuotedIdentifier(r, token_index, space, true);
}

// Renders a @"" quoted identifier, normalizing escapes.
// Unnecessary escapes are un-escaped, and \u escapes are normalized to \x when they fit.
// If unquote is true, the @"" is removed and the result is a bare symbol whose validity is asserted.
fn renderQuotedIdentifier(r: *Render, token_index: Ast.TokenIndex, space: Space, comptime unquote: bool) !void {
    const tree = r.tree;
    const ais = r.ais;
    assert(tree.tokenTag(token_index) == .identifier);
    const lexeme = tokenSliceForRender(tree, token_index);
    assert(lexeme.len >= 3 and lexeme[0] == '@');

    if (!unquote) try ais.writer().writeAll("@\"");
    const contents = lexeme[2 .. lexeme.len - 1];
    try renderIdentifierContents(ais.writer(), contents);
    if (!unquote) try ais.writer().writeByte('\"');

    try renderSpace(r, token_index, lexeme.len, space);
}

fn renderIdentifierContents(writer: anytype, bytes: []const u8) !void {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const byte = bytes[pos];
        switch (byte) {
            '\\' => {
                const old_pos = pos;
                const res = std.zig.string_literal.parseEscapeSequence(bytes, &pos);
                const escape_sequence = bytes[old_pos..pos];
                switch (res) {
                    .success => |codepoint| {
                        if (codepoint <= 0x7f) {
                            const buf = [1]u8{@as(u8, @intCast(codepoint))};
                            try std.fmt.format(writer, "{}", .{std.zig.fmtEscapes(&buf)});
                        } else {
                            try writer.writeAll(escape_sequence);
                        }
                    },
                    .failure => {
                        try writer.writeAll(escape_sequence);
                    },
                }
            },
            0x00...('\\' - 1), ('\\' + 1)...0x7f => {
                const buf = [1]u8{byte};
                try std.fmt.format(writer, "{}", .{std.zig.fmtEscapes(&buf)});
                pos += 1;
            },
            0x80...0xff => {
                try writer.writeByte(byte);
                pos += 1;
            },
        }
    }
}

/// Returns true if there exists a line comment between any of the tokens from
/// `start_token` to `end_token`. This is used to determine if e.g. a
/// fn_proto should be wrapped and have a trailing comma inserted even if
/// there is none in the source.
fn hasComment(tree: Ast, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    for (start_token..end_token) |i| {
        const token: Ast.TokenIndex = @intCast(i);
        const start = tree.tokenStart(token) + tree.tokenSlice(token).len;
        const end = tree.tokenStart(token + 1);
        if (mem.indexOf(u8, tree.source[start..end], "//") != null) return true;
    }

    return false;
}

/// Returns true if there exists a multiline string literal between the start
/// of token `start_token` and the start of token `end_token`.
fn hasMultilineString(tree: Ast, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    return std.mem.indexOfScalar(
        Token.Tag,
        tree.tokens.items(.tag)[start_token..end_token],
        .multiline_string_literal_line,
    ) != null;
}

/// Assumes that start is the first byte past the previous token and
/// that end is the last byte before the next token.
fn renderComments(r: *Render, start: usize, end: usize) Error!bool {
    const tree = r.tree;
    const ais = r.ais;

    var index: usize = start;
    while (mem.indexOf(u8, tree.source[index..end], "//")) |offset| {
        const comment_start = index + offset;

        // If there is no newline, the comment ends with EOF
        const newline_index = mem.indexOfScalar(u8, tree.source[comment_start..end], '\n');
        const newline = if (newline_index) |i| comment_start + i else null;

        const untrimmed_comment = tree.source[comment_start .. newline orelse tree.source.len];
        const trimmed_comment = mem.trimRight(u8, untrimmed_comment, &std.ascii.whitespace);

        // Don't leave any whitespace at the start of the file
        if (index != 0) {
            if (index == start and mem.containsAtLeast(u8, tree.source[index..comment_start], 2, "\n")) {
                // Leave up to one empty line before the first comment
                try ais.insertNewline();
                try ais.insertNewline();
            } else if (mem.indexOfScalar(u8, tree.source[index..comment_start], '\n') != null) {
                // Respect the newline directly before the comment.
                // Note: This allows an empty line between comments
                try ais.insertNewline();
            } else if (index == start) {
                // Otherwise if the first comment is on the same line as
                // the token before it, prefix it with a single space.
                try ais.writer().writeByte(' ');
            }
        }

        index = 1 + (newline orelse end - 1);

        const comment_content = mem.trimLeft(u8, trimmed_comment["//".len..], &std.ascii.whitespace);
        if (ais.disabled_offset != null and mem.eql(u8, comment_content, "zig fmt: on")) {
            // Write the source for which formatting was disabled directly
            // to the underlying writer, fixing up invalid whitespace.
            const disabled_source = tree.source[ais.disabled_offset.?..comment_start];
            try writeFixingWhitespace(ais.underlying_writer, disabled_source);
            // Write with the canonical single space.
            try ais.underlying_writer.writeAll("// zig fmt: on\n");
            ais.disabled_offset = null;
        } else if (ais.disabled_offset == null and mem.eql(u8, comment_content, "zig fmt: off")) {
            // Write with the canonical single space.
            try ais.writer().writeAll("// zig fmt: off\n");
            ais.disabled_offset = index;
        } else {
            // Write the comment minus trailing whitespace.
            try ais.writer().print("{s}\n", .{trimmed_comment});
        }
    }

    if (index != start and mem.containsAtLeast(u8, tree.source[index - 1 .. end], 2, "\n")) {
        // Don't leave any whitespace at the end of the file
        if (end != tree.source.len) {
            try ais.insertNewline();
        }
    }

    return index != start;
}

fn renderExtraNewline(r: *Render, node: Ast.Node.Index) Error!void {
    return renderExtraNewlineToken(r, r.tree.firstToken(node));
}

/// Check if there is an empty line immediately before the given token. If so, render it.
fn renderExtraNewlineToken(r: *Render, token_index: Ast.TokenIndex) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_start = tree.tokenStart(token_index);
    if (token_start == 0) return;
    const prev_token_end = if (token_index == 0)
        0
    else
        tree.tokenStart(token_index - 1) + tokenSliceForRender(tree, token_index - 1).len;

    // If there is a immediately preceding comment or doc_comment,
    // skip it because required extra newline has already been rendered.
    if (mem.indexOf(u8, tree.source[prev_token_end..token_start], "//") != null) return;
    if (tree.isTokenPrecededByTags(token_index, &.{.doc_comment})) return;

    // Iterate backwards to the end of the previous token, stopping if a
    // non-whitespace character is encountered or two newlines have been found.
    var i = token_start - 1;
    var newlines: u2 = 0;
    while (std.ascii.isWhitespace(tree.source[i])) : (i -= 1) {
        if (tree.source[i] == '\n') newlines += 1;
        if (newlines == 2) return ais.insertNewline();
        if (i == prev_token_end) break;
    }
}

/// end_token is the token one past the last doc comment token. This function
/// searches backwards from there.
fn renderDocComments(r: *Render, end_token: Ast.TokenIndex) Error!void {
    const tree = r.tree;
    // Search backwards for the first doc comment.
    if (end_token == 0) return;
    var tok = end_token - 1;
    while (tree.tokenTag(tok) == .doc_comment) {
        if (tok == 0) break;
        tok -= 1;
    } else {
        tok += 1;
    }
    const first_tok = tok;
    if (first_tok == end_token) return;

    if (first_tok != 0) {
        const prev_token_tag = tree.tokenTag(first_tok - 1);

        // Prevent accidental use of `renderDocComments` for a function argument doc comment
        assert(prev_token_tag != .l_paren);

        if (prev_token_tag != .l_brace) {
            try renderExtraNewlineToken(r, first_tok);
        }
    }

    while (tree.tokenTag(tok) == .doc_comment) : (tok += 1) {
        try renderToken(r, tok, .newline);
    }
}

/// start_token is first container doc comment token.
fn renderContainerDocComments(r: *Render, start_token: Ast.TokenIndex) Error!void {
    const tree = r.tree;
    var tok = start_token;
    while (tree.tokenTag(tok) == .container_doc_comment) : (tok += 1) {
        try renderToken(r, tok, .newline);
    }
    // Render extra newline if there is one between final container doc comment and
    // the next token. If the next token is a doc comment, that code path
    // will have its own logic to insert a newline.
    if (tree.tokenTag(tok) != .doc_comment) {
        try renderExtraNewlineToken(r, tok);
    }
}

fn discardAllParams(r: *Render, fn_proto_node: Ast.Node.Index) Error!void {
    const tree = &r.tree;
    const ais = r.ais;
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = tree.fullFnProto(&buf, fn_proto_node).?;
    var it = fn_proto.iterate(tree);
    while (it.next()) |param| {
        const name_ident = param.name_token.?;
        assert(tree.tokenTag(name_ident) == .identifier);
        const w = ais.writer();
        try w.writeAll("_ = ");
        try w.writeAll(tokenSliceForRender(r.tree, name_ident));
        try w.writeAll(";\n");
    }
}

fn tokenSliceForRender(tree: Ast, token_index: Ast.TokenIndex) []const u8 {
    var ret = tree.tokenSlice(token_index);
    switch (tree.tokenTag(token_index)) {
        .container_doc_comment, .doc_comment => {
            ret = mem.trimRight(u8, ret, &std.ascii.whitespace);
        },
        else => {},
    }
    return ret;
}

fn hasSameLineComment(tree: Ast, token_index: Ast.TokenIndex) bool {
    const between_source = tree.source[tree.tokenStart(token_index)..tree.tokenStart(token_index + 1)];
    for (between_source) |byte| switch (byte) {
        '\n' => return false,
        '/' => return true,
        else => continue,
    };
    return false;
}

/// Returns `true` if and only if there are any tokens or line comments between
/// start_token and end_token.
fn anythingBetween(tree: Ast, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    if (start_token + 1 != end_token) return true;
    const between_source = tree.source[tree.tokenStart(start_token)..tree.tokenStart(start_token + 1)];
    for (between_source) |byte| switch (byte) {
        '/' => return true,
        else => continue,
    };
    return false;
}

fn writeFixingWhitespace(writer: std.ArrayList(u8).Writer, slice: []const u8) Error!void {
    for (slice) |byte| switch (byte) {
        '\t' => try writer.writeAll(" " ** indent_delta),
        '\r' => {},
        else => try writer.writeByte(byte),
    };
}

fn nodeIsBlock(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => true,
        else => false,
    };
}

fn nodeIsIfForWhileSwitch(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .@"if",
        .if_simple,
        .@"for",
        .for_simple,
        .@"while",
        .while_simple,
        .while_cont,
        .@"switch",
        .switch_comma,
        => true,
        else => false,
    };
}

fn nodeCausesSliceOpSpace(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .@"catch",
        .add,
        .add_wrap,
        .array_cat,
        .array_mult,
        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_shl,
        .assign_shr,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_mul,
        .assign_mul_wrap,
        .bang_equal,
        .bit_and,
        .bit_or,
        .shl,
        .shr,
        .bit_xor,
        .bool_and,
        .bool_or,
        .div,
        .equal_equal,
        .error_union,
        .greater_or_equal,
        .greater_than,
        .less_or_equal,
        .less_than,
        .merge_error_sets,
        .mod,
        .mul,
        .mul_wrap,
        .sub,
        .sub_wrap,
        .@"orelse",
        => true,

        else => false,
    };
}

// Returns the number of nodes in `exprs` that are on the same line as `rtoken`.
fn rowSize(tree: Ast, exprs: []const Ast.Node.Index, rtoken: Ast.TokenIndex) usize {
    const first_token = tree.firstToken(exprs[0]);
    if (tree.tokensOnSameLine(first_token, rtoken)) {
        const maybe_comma = rtoken - 1;
        if (tree.tokenTag(maybe_comma) == .comma)
            return 1;
        return exprs.len; // no newlines
    }

    var count: usize = 1;
    for (exprs, 0..) |expr, i| {
        if (i + 1 < exprs.len) {
            const expr_last_token = tree.lastToken(expr) + 1;
            if (!tree.tokensOnSameLine(expr_last_token, tree.firstToken(exprs[i + 1]))) return count;
            count += 1;
        } else {
            return count;
        }
    }
    unreachable;
}

/// Automatically inserts indentation of written data by keeping
/// track of the current indentation level
///
/// We introduce a new indentation scope with pushIndent/popIndent whenever
/// we potentially want to introduce an indent after the next newline.
///
/// Indentation should only ever increment by one from one line to the next,
/// no matter how many new indentation scopes are introduced. This is done by
/// only realizing the indentation from the most recent scope. As an example:
///
///         while (foo) if (bar)
///             f(x);
///
/// The body of `while` introduces a new indentation scope and the body of
/// `if` also introduces a new indentation scope. When the newline is seen,
/// only the indentation scope of the `if` is realized, and the `while` is
/// not.
///
/// As comments are rendered during space rendering, we need to keep track
/// of the appropriate indentation level for them with pushSpace/popSpace.
/// This should be done whenever a scope that ends in a .semicolon or a
/// .comma is introduced.
fn AutoIndentingStream(comptime UnderlyingWriter: type) type {
    return struct {
        const Self = @This();
        pub const WriteError = UnderlyingWriter.Error;
        pub const Writer = std.io.Writer(*Self, WriteError, write);

        pub const IndentType = enum {
            normal,
            after_equals,
            binop,
            field_access,
        };
        const StackElem = struct {
            indent_type: IndentType,
            realized: bool,
        };
        const SpaceElem = struct {
            space: Space,
            indent_count: usize,
        };

        underlying_writer: UnderlyingWriter,

        /// Offset into the source at which formatting has been disabled with
        /// a `zig fmt: off` comment.
        ///
        /// If non-null, the AutoIndentingStream will not write any bytes
        /// to the underlying writer. It will however continue to track the
        /// indentation level.
        disabled_offset: ?usize = null,

        indent_count: usize = 0,
        indent_delta: usize,
        indent_stack: std.ArrayList(StackElem),
        space_stack: std.ArrayList(SpaceElem),
        space_mode: ?usize = null,
        disable_indent_committing: usize = 0,
        current_line_empty: bool = true,
        /// the most recently applied indent
        applied_indent: usize = 0,

        pub fn init(buffer: *std.ArrayList(u8), indent_delta_: usize) Self {
            return .{
                .underlying_writer = buffer.writer(),
                .indent_delta = indent_delta_,
                .indent_stack = std.ArrayList(StackElem).init(buffer.allocator),
                .space_stack = std.ArrayList(SpaceElem).init(buffer.allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.indent_stack.deinit();
            self.space_stack.deinit();
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
            if (bytes.len == 0)
                return @as(usize, 0);

            try self.applyIndent();
            return self.writeNoIndent(bytes);
        }

        // Change the indent delta without changing the final indentation level
        pub fn setIndentDelta(self: *Self, new_indent_delta: usize) void {
            if (self.indent_delta == new_indent_delta) {
                return;
            } else if (self.indent_delta > new_indent_delta) {
                assert(self.indent_delta % new_indent_delta == 0);
                self.indent_count = self.indent_count * (self.indent_delta / new_indent_delta);
            } else {
                // assert that the current indentation (in spaces) in a multiple of the new delta
                assert((self.indent_count * self.indent_delta) % new_indent_delta == 0);
                self.indent_count = self.indent_count / (new_indent_delta / self.indent_delta);
            }
            self.indent_delta = new_indent_delta;
        }

        fn writeNoIndent(self: *Self, bytes: []const u8) WriteError!usize {
            if (bytes.len == 0)
                return @as(usize, 0);

            if (self.disabled_offset == null) try self.underlying_writer.writeAll(bytes);
            if (bytes[bytes.len - 1] == '\n')
                self.resetLine();
            return bytes.len;
        }

        pub fn insertNewline(self: *Self) WriteError!void {
            _ = try self.writeNoIndent("\n");
        }

        fn resetLine(self: *Self) void {
            self.current_line_empty = true;

            if (self.disable_indent_committing > 0) return;

            if (self.indent_stack.items.len > 0) {
                // By default, we realize the most recent indentation scope.
                var to_realize = self.indent_stack.items.len - 1;

                if (self.indent_stack.items.len >= 2 and
                    self.indent_stack.items[to_realize - 1].indent_type == .after_equals and
                    self.indent_stack.items[to_realize - 1].realized and
                    self.indent_stack.items[to_realize].indent_type == .binop)
                {
                    // If we are in a .binop scope and our direct parent is .after_equals, don't indent.
                    // This ensures correct indentation in the below example:
                    //
                    //        const foo =
                    //            (x >= 'a' and x <= 'z') or         //<-- we are here
                    //            (x >= 'A' and x <= 'Z');
                    //
                    return;
                }

                if (self.indent_stack.items[to_realize].indent_type == .field_access) {
                    // Only realize the top-most field_access in a chain.
                    while (to_realize > 0 and self.indent_stack.items[to_realize - 1].indent_type == .field_access)
                        to_realize -= 1;
                }

                if (self.indent_stack.items[to_realize].realized) return;
                self.indent_stack.items[to_realize].realized = true;
                self.indent_count += 1;
            }
        }

        /// Disables indentation level changes during the next newlines until re-enabled.
        pub fn disableIndentCommitting(self: *Self) void {
            self.disable_indent_committing += 1;
        }

        pub fn enableIndentCommitting(self: *Self) void {
            assert(self.disable_indent_committing > 0);
            self.disable_indent_committing -= 1;
        }

        pub fn pushSpace(self: *Self, space: Space) !void {
            try self.space_stack.append(.{ .space = space, .indent_count = self.indent_count });
        }

        pub fn popSpace(self: *Self) void {
            _ = self.space_stack.pop();
        }

        /// Sets current indentation level to be the same as that of the last pushSpace.
        pub fn enableSpaceMode(self: *Self, space: Space) void {
            if (self.space_stack.items.len == 0) return;
            const curr = self.space_stack.getLast();
            if (curr.space != space) return;
            self.space_mode = curr.indent_count;
        }

        pub fn disableSpaceMode(self: *Self) void {
            self.space_mode = null;
        }

        pub fn lastSpaceModeIndent(self: *Self) usize {
            if (self.space_stack.items.len == 0) return 0;
            return self.space_stack.getLast().indent_count * self.indent_delta;
        }

        /// Insert a newline unless the current line is blank
        pub fn maybeInsertNewline(self: *Self) WriteError!void {
            if (!self.current_line_empty)
                try self.insertNewline();
        }

        /// Push default indentation
        /// Doesn't actually write any indentation.
        /// Just primes the stream to be able to write the correct indentation if it needs to.
        pub fn pushIndent(self: *Self, indent_type: IndentType) !void {
            try self.indent_stack.append(.{ .indent_type = indent_type, .realized = false });
        }

        /// Forces an indentation level to be realized.
        pub fn forcePushIndent(self: *Self, indent_type: IndentType) !void {
            try self.indent_stack.append(.{ .indent_type = indent_type, .realized = true });
            self.indent_count += 1;
        }

        pub fn popIndent(self: *Self) void {
            if (self.indent_stack.pop().?.realized) {
                assert(self.indent_count > 0);
                self.indent_count -= 1;
            }
        }

        pub fn indentStackEmpty(self: *Self) bool {
            return self.indent_stack.items.len == 0;
        }

        /// Writes ' ' bytes if the current line is empty
        fn applyIndent(self: *Self) WriteError!void {
            const current_indent = self.currentIndent();
            if (self.current_line_empty and current_indent > 0) {
                if (self.disabled_offset == null) {
                    try self.underlying_writer.writeByteNTimes(' ', current_indent);
                }
                self.applied_indent = current_indent;
            }
            self.current_line_empty = false;
        }

        /// Checks to see if the most recent indentation exceeds the currently pushed indents
        pub fn isLineOverIndented(self: *Self) bool {
            if (self.current_line_empty) return false;
            return self.applied_indent > self.currentIndent();
        }

        fn currentIndent(self: *Self) usize {
            const indent_count = self.space_mode orelse self.indent_count;
            return indent_count * self.indent_delta;
        }
    };
}
in: std.fs.File,
out: std.fs.File,
receive_fifo: std.fifo.LinearFifo(u8, .Dynamic),

pub const Message = struct {
    pub const Header = extern struct {
        tag: Tag,
        /// Size of the body only; does not include this Header.
        bytes_len: u32,
    };

    pub const Tag = enum(u32) {
        /// Body is a UTF-8 string.
        zig_version,
        /// Body is an ErrorBundle.
        error_bundle,
        /// Body is a EmitDigest.
        emit_digest,
        /// Body is a TestMetadata
        test_metadata,
        /// Body is a TestResults
        test_results,
        /// Body is a series of strings, delimited by null bytes.
        /// Each string is a prefixed file path.
        /// The first byte indicates the file prefix path (see prefixes fields
        /// of Cache). This byte is sent over the wire incremented so that null
        /// bytes are not confused with string terminators.
        /// The remaining bytes is the file path relative to that prefix.
        /// The prefixes are hard-coded in Compilation.create (cwd, zig lib dir, local cache dir)
        file_system_inputs,
        /// Body is a u64le that indicates the file path within the cache used
        /// to store coverage information. The integer is a hash of the PCs
        /// stored within that file.
        coverage_id,
        /// Body is a u64le that indicates the function pointer virtual memory
        /// address of the fuzz unit test. This is used to provide a starting
        /// point to view coverage.
        fuzz_start_addr,

        _,
    };

    pub const PathPrefix = enum(u8) {
        cwd,
        zig_lib,
        local_cache,
        global_cache,
    };

    /// Trailing:
    /// * extra: [extra_len]u32,
    /// * string_bytes: [string_bytes_len]u8,
    /// See `std.zig.ErrorBundle`.
    pub const ErrorBundle = extern struct {
        extra_len: u32,
        string_bytes_len: u32,
    };

    /// Trailing:
    /// * name: [tests_len]u32
    ///   - null-terminated string_bytes index
    /// * expected_panic_msg: [tests_len]u32,
    ///   - null-terminated string_bytes index
    ///   - 0 means does not expect panic
    /// * string_bytes: [string_bytes_len]u8,
    pub const TestMetadata = extern struct {
        string_bytes_len: u32,
        tests_len: u32,
    };

    pub const TestResults = extern struct {
        index: u32,
        flags: Flags,

        pub const Flags = packed struct(u32) {
            fail: bool,
            skip: bool,
            leak: bool,
            fuzz: bool,
            log_err_count: u28 = 0,
        };
    };

    /// Trailing:
    /// * the hex digest of the cache directory within the /o/ subdirectory.
    pub const EmitDigest = extern struct {
        flags: Flags,

        pub const Flags = packed struct(u8) {
            cache_hit: bool,
            reserved: u7 = 0,
        };
    };
};

pub const Options = struct {
    gpa: Allocator,
    in: std.fs.File,
    out: std.fs.File,
    zig_version: []const u8,
};

pub fn init(options: Options) !Server {
    var s: Server = .{
        .in = options.in,
        .out = options.out,
        .receive_fifo = std.fifo.LinearFifo(u8, .Dynamic).init(options.gpa),
    };
    try s.serveStringMessage(.zig_version, options.zig_version);
    return s;
}

pub fn deinit(s: *Server) void {
    s.receive_fifo.deinit();
    s.* = undefined;
}

pub fn receiveMessage(s: *Server) !InMessage.Header {
    const Header = InMessage.Header;
    const fifo = &s.receive_fifo;
    var last_amt_zero = false;

    while (true) {
        const buf = fifo.readableSlice(0);
        assert(fifo.readableLength() == buf.len);
        if (buf.len >= @sizeOf(Header)) {
            const header: *align(1) const Header = @ptrCast(buf[0..@sizeOf(Header)]);
            const bytes_len = bswap(header.bytes_len);
            const tag = bswap(header.tag);

            if (buf.len - @sizeOf(Header) >= bytes_len) {
                fifo.discard(@sizeOf(Header));
                return .{
                    .tag = tag,
                    .bytes_len = bytes_len,
                };
            } else {
                const needed = bytes_len - (buf.len - @sizeOf(Header));
                const write_buffer = try fifo.writableWithSize(needed);
                const amt = try s.in.read(write_buffer);
                fifo.update(amt);
                continue;
            }
        }

        const write_buffer = try fifo.writableWithSize(256);
        const amt = try s.in.read(write_buffer);
        fifo.update(amt);
        if (amt == 0) {
            if (last_amt_zero) return error.BrokenPipe;
            last_amt_zero = true;
        }
    }
}

pub fn receiveBody_u32(s: *Server) !u32 {
    const fifo = &s.receive_fifo;
    const buf = fifo.readableSlice(0);
    const result = @as(*align(1) const u32, @ptrCast(buf[0..4])).*;
    fifo.discard(4);
    return bswap(result);
}

pub fn serveStringMessage(s: *Server, tag: OutMessage.Tag, msg: []const u8) !void {
    return s.serveMessage(.{
        .tag = tag,
        .bytes_len = @as(u32, @intCast(msg.len)),
    }, &.{msg});
}

pub fn serveMessage(
    s: *const Server,
    header: OutMessage.Header,
    bufs: []const []const u8,
) !void {
    var iovecs: [10]std.posix.iovec_const = undefined;
    const header_le = bswap(header);
    iovecs[0] = .{
        .base = @as([*]const u8, @ptrCast(&header_le)),
        .len = @sizeOf(OutMessage.Header),
    };
    for (bufs, iovecs[1 .. bufs.len + 1]) |buf, *iovec| {
        iovec.* = .{
            .base = buf.ptr,
            .len = buf.len,
        };
    }
    try s.out.writevAll(iovecs[0 .. bufs.len + 1]);
}

pub fn serveU64Message(s: *Server, tag: OutMessage.Tag, int: u64) !void {
    const msg_le = bswap(int);
    return s.serveMessage(.{
        .tag = tag,
        .bytes_len = @sizeOf(u64),
    }, &.{std.mem.asBytes(&msg_le)});
}

pub fn serveEmitDigest(
    s: *Server,
    digest: *const [Cache.bin_digest_len]u8,
    header: OutMessage.EmitDigest,
) !void {
    try s.serveMessage(.{
        .tag = .emit_digest,
        .bytes_len = @intCast(digest.len + @sizeOf(OutMessage.EmitDigest)),
    }, &.{
        std.mem.asBytes(&header),
        digest,
    });
}

pub fn serveTestResults(
    s: *Server,
    msg: OutMessage.TestResults,
) !void {
    const msg_le = bswap(msg);
    try s.serveMessage(.{
        .tag = .test_results,
        .bytes_len = @intCast(@sizeOf(OutMessage.TestResults)),
    }, &.{
        std.mem.asBytes(&msg_le),
    });
}

pub fn serveErrorBundle(s: *Server, error_bundle: std.zig.ErrorBundle) !void {
    const eb_hdr: OutMessage.ErrorBundle = .{
        .extra_len = @intCast(error_bundle.extra.len),
        .string_bytes_len = @intCast(error_bundle.string_bytes.len),
    };
    const bytes_len = @sizeOf(OutMessage.ErrorBundle) +
        4 * error_bundle.extra.len + error_bundle.string_bytes.len;
    try s.serveMessage(.{
        .tag = .error_bundle,
        .bytes_len = @intCast(bytes_len),
    }, &.{
        std.mem.asBytes(&eb_hdr),
        // TODO: implement @ptrCast between slices changing the length
        std.mem.sliceAsBytes(error_bundle.extra),
        error_bundle.string_bytes,
    });
}

pub const TestMetadata = struct {
    names: []u32,
    expected_panic_msgs: []u32,
    string_bytes: []const u8,
};

pub fn serveTestMetadata(s: *Server, test_metadata: TestMetadata) !void {
    const header: OutMessage.TestMetadata = .{
        .tests_len = bswap(@as(u32, @intCast(test_metadata.names.len))),
        .string_bytes_len = bswap(@as(u32, @intCast(test_metadata.string_bytes.len))),
    };
    const trailing = 2;
    const bytes_len = @sizeOf(OutMessage.TestMetadata) +
        trailing * @sizeOf(u32) * test_metadata.names.len + test_metadata.string_bytes.len;

    if (need_bswap) {
        bswap_u32_array(test_metadata.names);
        bswap_u32_array(test_metadata.expected_panic_msgs);
    }
    defer if (need_bswap) {
        bswap_u32_array(test_metadata.names);
        bswap_u32_array(test_metadata.expected_panic_msgs);
    };

    return s.serveMessage(.{
        .tag = .test_metadata,
        .bytes_len = @intCast(bytes_len),
    }, &.{
        std.mem.asBytes(&header),
        // TODO: implement @ptrCast between slices changing the length
        std.mem.sliceAsBytes(test_metadata.names),
        std.mem.sliceAsBytes(test_metadata.expected_panic_msgs),
        test_metadata.string_bytes,
    });
}

fn bswap(x: anytype) @TypeOf(x) {
    if (!need_bswap) return x;

    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .@"enum" => return @as(T, @enumFromInt(@byteSwap(@intFromEnum(x)))),
        .int => return @byteSwap(x),
        .@"struct" => |info| switch (info.layout) {
            .@"extern" => {
                var result: T = undefined;
                inline for (info.fields) |field| {
                    @field(result, field.name) = bswap(@field(x, field.name));
                }
                return result;
            },
            .@"packed" => {
                const I = info.backing_integer.?;
                return @as(T, @bitCast(@byteSwap(@as(I, @bitCast(x)))));
            },
            .auto => @compileError("auto layout struct"),
        },
        else => @compileError("bswap on type " ++ @typeName(T)),
    }
}

fn bswap_u32_array(slice: []u32) void {
    comptime assert(need_bswap);
    for (slice) |*elem| elem.* = @byteSwap(elem.*);
}

const OutMessage = std.zig.Server.Message;
const InMessage = std.zig.Client.Message;

const Server = @This();
const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const native_endian = builtin.target.cpu.arch.endian();
const need_bswap = native_endian != .little;
const Cache = std.Build.Cache;
const std = @import("../std.zig");
const assert = std.debug.assert;
const utf8Encode = std.unicode.utf8Encode;

pub const ParseError = error{
    OutOfMemory,
    InvalidLiteral,
};

pub const ParsedCharLiteral = union(enum) {
    success: u21,
    failure: Error,
};

pub const Result = union(enum) {
    success,
    failure: Error,
};

pub const Error = union(enum) {
    /// The character after backslash is missing or not recognized.
    invalid_escape_character: usize,
    /// Expected hex digit at this index.
    expected_hex_digit: usize,
    /// Unicode escape sequence had no digits with rbrace at this index.
    empty_unicode_escape_sequence: usize,
    /// Expected hex digit or '}' at this index.
    expected_hex_digit_or_rbrace: usize,
    /// Invalid unicode codepoint at this index.
    invalid_unicode_codepoint: usize,
    /// Expected '{' at this index.
    expected_lbrace: usize,
    /// Expected '}' at this index.
    expected_rbrace: usize,
    /// Expected '\'' at this index.
    expected_single_quote: usize,
    /// The character at this index cannot be represented without an escape sequence.
    invalid_character: usize,
    /// `''`. Not returned for string literals.
    empty_char_literal,

    const FormatMessage = struct {
        err: Error,
        raw_string: []const u8,
    };

    fn formatMessage(
        self: FormatMessage,
        comptime f: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = f;
        _ = options;
        switch (self.err) {
            .invalid_escape_character => |bad_index| try writer.print(
                "invalid escape character: '{c}'",
                .{self.raw_string[bad_index]},
            ),
            .expected_hex_digit => |bad_index| try writer.print(
                "expected hex digit, found '{c}'",
                .{self.raw_string[bad_index]},
            ),
            .empty_unicode_escape_sequence => try writer.writeAll(
                "empty unicode escape sequence",
            ),
            .expected_hex_digit_or_rbrace => |bad_index| try writer.print(
                "expected hex digit or '}}', found '{c}'",
                .{self.raw_string[bad_index]},
            ),
            .invalid_unicode_codepoint => try writer.writeAll(
                "unicode escape does not correspond to a valid unicode scalar value",
            ),
            .expected_lbrace => |bad_index| try writer.print(
                "expected '{{', found '{c}'",
                .{self.raw_string[bad_index]},
            ),
            .expected_rbrace => |bad_index| try writer.print(
                "expected '}}', found '{c}'",
                .{self.raw_string[bad_index]},
            ),
            .expected_single_quote => |bad_index| try writer.print(
                "expected single quote ('), found '{c}'",
                .{self.raw_string[bad_index]},
            ),
            .invalid_character => |bad_index| try writer.print(
                "invalid byte in string or character literal: '{c}'",
                .{self.raw_string[bad_index]},
            ),
            .empty_char_literal => try writer.writeAll(
                "empty character literal",
            ),
        }
    }

    pub fn fmt(self: @This(), raw_string: []const u8) std.fmt.Formatter(formatMessage) {
        return .{ .data = .{
            .err = self,
            .raw_string = raw_string,
        } };
    }

    pub fn offset(err: Error) usize {
        return switch (err) {
            inline .invalid_escape_character,
            .expected_hex_digit,
            .empty_unicode_escape_sequence,
            .expected_hex_digit_or_rbrace,
            .invalid_unicode_codepoint,
            .expected_lbrace,
            .expected_rbrace,
            .expected_single_quote,
            .invalid_character,
            => |n| n,
            .empty_char_literal => 0,
        };
    }
};

/// Asserts the slice starts and ends with single-quotes.
/// Returns an error if there is not exactly one UTF-8 codepoint in between.
pub fn parseCharLiteral(slice: []const u8) ParsedCharLiteral {
    if (slice.len < 3) return .{ .failure = .empty_char_literal };
    assert(slice[0] == '\'');
    assert(slice[slice.len - 1] == '\'');

    switch (slice[1]) {
        '\\' => {
            var offset: usize = 1;
            const result = parseEscapeSequence(slice, &offset);
            if (result == .success and (offset + 1 != slice.len or slice[offset] != '\''))
                return .{ .failure = .{ .expected_single_quote = offset } };

            return result;
        },
        0 => return .{ .failure = .{ .invalid_character = 1 } },
        else => {
            const inner = slice[1 .. slice.len - 1];
            const n = std.unicode.utf8ByteSequenceLength(inner[0]) catch return .{
                .failure = .{ .invalid_unicode_codepoint = 1 },
            };
            if (inner.len > n) return .{ .failure = .{ .expected_single_quote = 1 + n } };
            const codepoint = switch (n) {
                1 => inner[0],
                2 => std.unicode.utf8Decode2(inner[0..2].*),
                3 => std.unicode.utf8Decode3(inner[0..3].*),
                4 => std.unicode.utf8Decode4(inner[0..4].*),
                else => unreachable,
            } catch return .{ .failure = .{ .invalid_unicode_codepoint = 1 } };
            return .{ .success = codepoint };
        },
    }
}

/// Parse an escape sequence from `slice[offset..]`. If parsing is successful,
/// offset is updated to reflect the characters consumed.
pub fn parseEscapeSequence(slice: []const u8, offset: *usize) ParsedCharLiteral {
    assert(slice.len > offset.*);
    assert(slice[offset.*] == '\\');

    if (slice.len == offset.* + 1)
        return .{ .failure = .{ .invalid_escape_character = offset.* + 1 } };

    offset.* += 2;
    switch (slice[offset.* - 1]) {
        'n' => return .{ .success = '\n' },
        'r' => return .{ .success = '\r' },
        '\\' => return .{ .success = '\\' },
        't' => return .{ .success = '\t' },
        '\'' => return .{ .success = '\'' },
        '"' => return .{ .success = '"' },
        'x' => {
            var value: u8 = 0;
            var i: usize = offset.*;
            while (i < offset.* + 2) : (i += 1) {
                if (i == slice.len) return .{ .failure = .{ .expected_hex_digit = i } };

                const c = slice[i];
                switch (c) {
                    '0'...'9' => {
                        value *= 16;
                        value += c - '0';
                    },
                    'a'...'f' => {
                        value *= 16;
                        value += c - 'a' + 10;
                    },
                    'A'...'F' => {
                        value *= 16;
                        value += c - 'A' + 10;
                    },
                    else => {
                        return .{ .failure = .{ .expected_hex_digit = i } };
                    },
                }
            }
            offset.* = i;
            return .{ .success = value };
        },
        'u' => {
            var i: usize = offset.*;
            if (i >= slice.len or slice[i] != '{') return .{ .failure = .{ .expected_lbrace = i } };
            i += 1;
            if (i >= slice.len) return .{ .failure = .{ .expected_hex_digit_or_rbrace = i } };
            if (slice[i] == '}') return .{ .failure = .{ .empty_unicode_escape_sequence = i } };

            var value: u32 = 0;
            while (i < slice.len) : (i += 1) {
                const c = slice[i];
                switch (c) {
                    '0'...'9' => {
                        value *= 16;
                        value += c - '0';
                    },
                    'a'...'f' => {
                        value *= 16;
                        value += c - 'a' + 10;
                    },
                    'A'...'F' => {
                        value *= 16;
                        value += c - 'A' + 10;
                    },
                    '}' => {
                        i += 1;
                        break;
                    },
                    else => return .{ .failure = .{ .expected_hex_digit_or_rbrace = i } },
                }
                if (value > 0x10ffff) {
                    return .{ .failure = .{ .invalid_unicode_codepoint = i } };
                }
            } else {
                return .{ .failure = .{ .expected_rbrace = i } };
            }
            offset.* = i;
            return .{ .success = @as(u21, @intCast(value)) };
        },
        else => return .{ .failure = .{ .invalid_escape_character = offset.* - 1 } },
    }
}

test parseCharLiteral {
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 'a' },
        parseCharLiteral("'a'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 'ä' },
        parseCharLiteral("'ä'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0 },
        parseCharLiteral("'\\x00'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0x4f },
        parseCharLiteral("'\\x4f'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0x4f },
        parseCharLiteral("'\\x4F'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0x3041 },
        parseCharLiteral("'ぁ'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0 },
        parseCharLiteral("'\\u{0}'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0x3041 },
        parseCharLiteral("'\\u{3041}'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0x7f },
        parseCharLiteral("'\\u{7f}'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .success = 0x7fff },
        parseCharLiteral("'\\u{7FFF}'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .expected_hex_digit = 4 } },
        parseCharLiteral("'\\x0'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .expected_single_quote = 5 } },
        parseCharLiteral("'\\x000'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .invalid_escape_character = 2 } },
        parseCharLiteral("'\\y'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .expected_lbrace = 3 } },
        parseCharLiteral("'\\u'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .expected_lbrace = 3 } },
        parseCharLiteral("'\\uFFFF'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .empty_unicode_escape_sequence = 4 } },
        parseCharLiteral("'\\u{}'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .invalid_unicode_codepoint = 9 } },
        parseCharLiteral("'\\u{FFFFFF}'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .expected_hex_digit_or_rbrace = 8 } },
        parseCharLiteral("'\\u{FFFF'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .expected_single_quote = 9 } },
        parseCharLiteral("'\\u{FFFF}x'"),
    );
    try std.testing.expectEqual(
        ParsedCharLiteral{ .failure = .{ .invalid_character = 1 } },
        parseCharLiteral("'\x00'"),
    );
}

/// Parses `bytes` as a Zig string literal and writes the result to the std.io.Writer type.
/// Asserts `bytes` has '"' at beginning and end.
pub fn parseWrite(writer: anytype, bytes: []const u8) error{OutOfMemory}!Result {
    assert(bytes.len >= 2 and bytes[0] == '"' and bytes[bytes.len - 1] == '"');

    var index: usize = 1;
    while (true) {
        const b = bytes[index];

        switch (b) {
            '\\' => {
                const escape_char_index = index + 1;
                const result = parseEscapeSequence(bytes, &index);
                switch (result) {
                    .success => |codepoint| {
                        if (bytes[escape_char_index] == 'u') {
                            var buf: [4]u8 = undefined;
                            const len = utf8Encode(codepoint, &buf) catch {
                                return Result{ .failure = .{ .invalid_unicode_codepoint = escape_char_index + 1 } };
                            };
                            try writer.writeAll(buf[0..len]);
                        } else {
                            try writer.writeByte(@as(u8, @intCast(codepoint)));
                        }
                    },
                    .failure => |err| return Result{ .failure = err },
                }
            },
            '\n' => return Result{ .failure = .{ .invalid_character = index } },
            '"' => return Result.success,
            else => {
                try writer.writeByte(b);
                index += 1;
            },
        }
    }
}

/// Higher level API. Does not return extra info about parse errors.
/// Caller owns returned memory.
pub fn parseAlloc(allocator: std.mem.Allocator, bytes: []const u8) ParseError![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    switch (try parseWrite(buf.writer(), bytes)) {
        .success => return buf.toOwnedSlice(),
        .failure => return error.InvalidLiteral,
    }
}

test parseAlloc {
    const expect = std.testing.expect;
    const expectError = std.testing.expectError;
    const eql = std.mem.eql;

    var fixed_buf_mem: [512]u8 = undefined;
    var fixed_buf_alloc = std.heap.FixedBufferAllocator.init(&fixed_buf_mem);
    const alloc = fixed_buf_alloc.allocator();

    try expectError(error.InvalidLiteral, parseAlloc(alloc, "\"\\x6\""));
    try expect(eql(u8, "foo\nbar", try parseAlloc(alloc, "\"foo\\nbar\"")));
    try expect(eql(u8, "\x12foo", try parseAlloc(alloc, "\"\\x12foo\"")));
    try expect(eql(u8, "bytes\u{1234}foo", try parseAlloc(alloc, "\"bytes\\u{1234}foo\"")));
    try expect(eql(u8, "foo", try parseAlloc(alloc, "\"foo\"")));
    try expect(eql(u8, "foo", try parseAlloc(alloc, "\"f\x6f\x6f\"")));
    try expect(eql(u8, "f💯", try parseAlloc(alloc, "\"f\u{1f4af}\"")));
}
pub const NativePaths = @import("system/NativePaths.zig");

pub const windows = @import("system/windows.zig");
pub const darwin = @import("system/darwin.zig");
pub const linux = @import("system/linux.zig");

pub const Executor = union(enum) {
    native,
    rosetta,
    qemu: []const u8,
    wine: []const u8,
    wasmtime: []const u8,
    darling: []const u8,
    bad_dl: []const u8,
    bad_os_or_cpu,
};

pub const GetExternalExecutorOptions = struct {
    allow_darling: bool = true,
    allow_qemu: bool = true,
    allow_rosetta: bool = true,
    allow_wasmtime: bool = true,
    allow_wine: bool = true,
    qemu_fixes_dl: bool = false,
    link_libc: bool = false,
};

/// Return whether or not the given host is capable of running executables of
/// the other target.
pub fn getExternalExecutor(
    host: std.Target,
    candidate: *const std.Target,
    options: GetExternalExecutorOptions,
) Executor {
    const os_match = host.os.tag == candidate.os.tag;
    const cpu_ok = cpu_ok: {
        if (host.cpu.arch == candidate.cpu.arch)
            break :cpu_ok true;

        if (host.cpu.arch == .x86_64 and candidate.cpu.arch == .x86)
            break :cpu_ok true;

        if (host.cpu.arch == .aarch64 and candidate.cpu.arch == .arm)
            break :cpu_ok true;

        if (host.cpu.arch == .aarch64_be and candidate.cpu.arch == .armeb)
            break :cpu_ok true;

        // TODO additionally detect incompatible CPU features.
        // Note that in some cases the OS kernel will emulate missing CPU features
        // when an illegal instruction is encountered.

        break :cpu_ok false;
    };

    var bad_result: Executor = .bad_os_or_cpu;

    if (os_match and cpu_ok) native: {
        if (options.link_libc) {
            if (candidate.dynamic_linker.get()) |candidate_dl| {
                fs.cwd().access(candidate_dl, .{}) catch {
                    bad_result = .{ .bad_dl = candidate_dl };
                    break :native;
                };
            }
        }
        return .native;
    }

    // If the OS match and OS is macOS and CPU is arm64, we can use Rosetta 2
    // to emulate the foreign architecture.
    if (options.allow_rosetta and os_match and
        host.os.tag == .macos and host.cpu.arch == .aarch64)
    {
        switch (candidate.cpu.arch) {
            .x86_64 => return .rosetta,
            else => return bad_result,
        }
    }

    // If the OS matches, we can use QEMU to emulate a foreign architecture.
    if (options.allow_qemu and os_match and (!cpu_ok or options.qemu_fixes_dl)) {
        return switch (candidate.cpu.arch) {
            .aarch64 => Executor{ .qemu = "qemu-aarch64" },
            .aarch64_be => Executor{ .qemu = "qemu-aarch64_be" },
            .arm, .thumb => Executor{ .qemu = "qemu-arm" },
            .armeb, .thumbeb => Executor{ .qemu = "qemu-armeb" },
            .hexagon => Executor{ .qemu = "qemu-hexagon" },
            .loongarch64 => Executor{ .qemu = "qemu-loongarch64" },
            .m68k => Executor{ .qemu = "qemu-m68k" },
            .mips => Executor{ .qemu = "qemu-mips" },
            .mipsel => Executor{ .qemu = "qemu-mipsel" },
            .mips64 => Executor{
                .qemu = switch (candidate.abi) {
                    .gnuabin32, .muslabin32 => "qemu-mipsn32",
                    else => "qemu-mips64",
                },
            },
            .mips64el => Executor{
                .qemu = switch (candidate.abi) {
                    .gnuabin32, .muslabin32 => "qemu-mipsn32el",
                    else => "qemu-mips64el",
                },
            },
            .powerpc => Executor{ .qemu = "qemu-ppc" },
            .powerpc64 => Executor{ .qemu = "qemu-ppc64" },
            .powerpc64le => Executor{ .qemu = "qemu-ppc64le" },
            .riscv32 => Executor{ .qemu = "qemu-riscv32" },
            .riscv64 => Executor{ .qemu = "qemu-riscv64" },
            .s390x => Executor{ .qemu = "qemu-s390x" },
            .sparc => Executor{
                .qemu = if (std.Target.sparc.featureSetHas(candidate.cpu.features, .v9))
                    "qemu-sparc32plus"
                else
                    "qemu-sparc",
            },
            .sparc64 => Executor{ .qemu = "qemu-sparc64" },
            .x86 => Executor{ .qemu = "qemu-i386" },
            .x86_64 => switch (candidate.abi) {
                .gnux32, .muslx32 => return bad_result,
                else => Executor{ .qemu = "qemu-x86_64" },
            },
            .xtensa => Executor{ .qemu = "qemu-xtensa" },
            else => return bad_result,
        };
    }

    if (options.allow_wasmtime and candidate.cpu.arch.isWasm()) {
        return Executor{ .wasmtime = "wasmtime" };
    }

    switch (candidate.os.tag) {
        .windows => {
            if (options.allow_wine) {
                const wine_supported = switch (candidate.cpu.arch) {
                    .thumb => switch (host.cpu.arch) {
                        .arm, .thumb, .aarch64 => true,
                        else => false,
                    },
                    .aarch64 => host.cpu.arch == .aarch64,
                    .x86 => host.cpu.arch.isX86(),
                    .x86_64 => host.cpu.arch == .x86_64,
                    else => false,
                };
                return if (wine_supported) Executor{ .wine = "wine" } else bad_result;
            }
            return bad_result;
        },
        .driverkit, .macos => {
            if (options.allow_darling) {
                // This check can be loosened once darling adds a QEMU-based emulation
                // layer for non-host architectures:
                // https://github.com/darlinghq/darling/issues/863
                if (candidate.cpu.arch != host.cpu.arch) {
                    return bad_result;
                }
                return Executor{ .darling = "darling" };
            }
            return bad_result;
        },
        else => return bad_result,
    }
}

pub const DetectError = error{
    FileSystem,
    SystemResources,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    DeviceBusy,
    OSVersionDetectionFail,
    Unexpected,
    ProcessNotFound,
};

/// Given a `Target.Query`, which specifies in detail which parts of the
/// target should be detected natively, which should be standard or default,
/// and which are provided explicitly, this function resolves the native
/// components by detecting the native system, and then resolves
/// standard/default parts relative to that.
pub fn resolveTargetQuery(query: Target.Query) DetectError!Target {
    // Until https://github.com/ziglang/zig/issues/4592 is implemented (support detecting the
    // native CPU architecture as being different than the current target), we use this:
    const query_cpu_arch = query.cpu_arch orelse builtin.cpu.arch;
    const query_os_tag = query.os_tag orelse builtin.os.tag;
    const query_abi = query.abi orelse builtin.abi;
    var os = query_os_tag.defaultVersionRange(query_cpu_arch, query_abi);
    if (query.os_tag == null) {
        switch (builtin.target.os.tag) {
            .linux => {
                const uts = posix.uname();
                const release = mem.sliceTo(&uts.release, 0);
                // The release field sometimes has a weird format,
                // `Version.parse` will attempt to find some meaningful interpretation.
                if (std.SemanticVersion.parse(release)) |ver| {
                    os.version_range.linux.range.min = ver;
                    os.version_range.linux.range.max = ver;
                } else |err| switch (err) {
                    error.Overflow => {},
                    error.InvalidVersion => {},
                }
            },
            .solaris, .illumos => {
                const uts = posix.uname();
                const release = mem.sliceTo(&uts.release, 0);
                if (std.SemanticVersion.parse(release)) |ver| {
                    os.version_range.semver.min = ver;
                    os.version_range.semver.max = ver;
                } else |err| switch (err) {
                    error.Overflow => {},
                    error.InvalidVersion => {},
                }
            },
            .windows => {
                const detected_version = windows.detectRuntimeVersion();
                os.version_range.windows.min = detected_version;
                os.version_range.windows.max = detected_version;
            },
            .macos => try darwin.macos.detect(&os),
            .freebsd, .netbsd, .dragonfly => {
                const key = switch (builtin.target.os.tag) {
                    .freebsd => "kern.osreldate",
                    .netbsd, .dragonfly => "kern.osrevision",
                    else => unreachable,
                };
                var value: u32 = undefined;
                var len: usize = @sizeOf(@TypeOf(value));

                posix.sysctlbynameZ(key, &value, &len, null, 0) catch |err| switch (err) {
                    error.NameTooLong => unreachable, // constant, known good value
                    error.PermissionDenied => unreachable, // only when setting values,
                    error.SystemResources => unreachable, // memory already on the stack
                    error.UnknownName => unreachable, // constant, known good value
                    error.Unexpected => return error.OSVersionDetectionFail,
                };

                switch (builtin.target.os.tag) {
                    .freebsd => {
                        // https://www.freebsd.org/doc/en_US.ISO8859-1/books/porters-handbook/versions.html
                        // Major * 100,000 has been convention since FreeBSD 2.2 (1997)
                        // Minor * 1(0),000 summed has been convention since FreeBSD 2.2 (1997)
                        // e.g. 492101 = 4.11-STABLE = 4.(9+2)
                        const major = value / 100_000;
                        const minor1 = value % 100_000 / 10_000; // usually 0 since 5.1
                        const minor2 = value % 10_000 / 1_000; // 0 before 5.1, minor version since
                        const patch = value % 1_000;
                        os.version_range.semver.min = .{ .major = major, .minor = minor1 + minor2, .patch = patch };
                        os.version_range.semver.max = os.version_range.semver.min;
                    },
                    .netbsd => {
                        // #define __NetBSD_Version__ MMmmrrpp00
                        //
                        // M = major version
                        // m = minor version; a minor number of 99 indicates current.
                        // r = 0 (*)
                        // p = patchlevel
                        const major = value / 100_000_000;
                        const minor = value % 100_000_000 / 1_000_000;
                        const patch = value % 10_000 / 100;
                        os.version_range.semver.min = .{ .major = major, .minor = minor, .patch = patch };
                        os.version_range.semver.max = os.version_range.semver.min;
                    },
                    .dragonfly => {
                        // https://github.com/DragonFlyBSD/DragonFlyBSD/blob/cb2cde83771754aeef9bb3251ee48959138dec87/Makefile.inc1#L15-L17
                        // flat base10 format: Mmmmpp
                        //   M = major
                        //   m = minor; odd-numbers indicate current dev branch
                        //   p = patch
                        const major = value / 100_000;
                        const minor = value % 100_000 / 100;
                        const patch = value % 100;
                        os.version_range.semver.min = .{ .major = major, .minor = minor, .patch = patch };
                        os.version_range.semver.max = os.version_range.semver.min;
                    },
                    else => unreachable,
                }
            },
            .openbsd => {
                const mib: [2]c_int = [_]c_int{
                    posix.CTL.KERN,
                    posix.KERN.OSRELEASE,
                };
                var buf: [64]u8 = undefined;
                // consider that sysctl result includes null-termination
                // reserve 1 byte to ensure we never overflow when appending ".0"
                var len: usize = buf.len - 1;

                posix.sysctl(&mib, &buf, &len, null, 0) catch |err| switch (err) {
                    error.NameTooLong => unreachable, // constant, known good value
                    error.PermissionDenied => unreachable, // only when setting values,
                    error.SystemResources => unreachable, // memory already on the stack
                    error.UnknownName => unreachable, // constant, known good value
                    error.Unexpected => return error.OSVersionDetectionFail,
                };

                // append ".0" to satisfy semver
                buf[len - 1] = '.';
                buf[len] = '0';
                len += 1;

                if (std.SemanticVersion.parse(buf[0..len])) |ver| {
                    os.version_range.semver.min = ver;
                    os.version_range.semver.max = ver;
                } else |_| {
                    return error.OSVersionDetectionFail;
                }
            },
            else => {
                // Unimplemented, fall back to default version range.
            },
        }
    }

    if (query.os_version_min) |min| switch (min) {
        .none => {},
        .semver => |semver| switch (os.tag.versionRangeTag()) {
            inline .hurd, .linux => |t| @field(os.version_range, @tagName(t)).range.min = semver,
            else => os.version_range.semver.min = semver,
        },
        .windows => |win_ver| os.version_range.windows.min = win_ver,
    };

    if (query.os_version_max) |max| switch (max) {
        .none => {},
        .semver => |semver| switch (os.tag.versionRangeTag()) {
            inline .hurd, .linux => |t| @field(os.version_range, @tagName(t)).range.max = semver,
            else => os.version_range.semver.max = semver,
        },
        .windows => |win_ver| os.version_range.windows.max = win_ver,
    };

    if (query.glibc_version) |glibc| {
        switch (os.tag.versionRangeTag()) {
            inline .hurd, .linux => |t| @field(os.version_range, @tagName(t)).glibc = glibc,
            else => {},
        }
    }

    if (query.android_api_level) |android| {
        os.version_range.linux.android = android;
    }

    var cpu = switch (query.cpu_model) {
        .native => detectNativeCpuAndFeatures(query_cpu_arch, os, query),
        .baseline => Target.Cpu.baseline(query_cpu_arch, os),
        .determined_by_arch_os => if (query.cpu_arch == null)
            detectNativeCpuAndFeatures(query_cpu_arch, os, query)
        else
            Target.Cpu.baseline(query_cpu_arch, os),
        .explicit => |model| model.toCpu(query_cpu_arch),
    } orelse backup_cpu_detection: {
        break :backup_cpu_detection Target.Cpu.baseline(query_cpu_arch, os);
    };

    // For x86, we need to populate some CPU feature flags depending on architecture
    // and mode:
    //  * 16bit_mode => if the abi is code16
    //  * 32bit_mode => if the arch is x86
    // However, the "mode" flags can be used as overrides, so if the user explicitly
    // sets one of them, that takes precedence.
    switch (query_cpu_arch) {
        .x86 => {
            if (!Target.x86.featureSetHasAny(query.cpu_features_add, .{
                .@"16bit_mode", .@"32bit_mode",
            })) {
                switch (query_abi) {
                    .code16 => cpu.features.addFeature(
                        @intFromEnum(Target.x86.Feature.@"16bit_mode"),
                    ),
                    else => cpu.features.addFeature(
                        @intFromEnum(Target.x86.Feature.@"32bit_mode"),
                    ),
                }
            }
        },
        .arm, .armeb => {
            // XXX What do we do if the target has the noarm feature?
            //     What do we do if the user specifies +thumb_mode?
        },
        .thumb, .thumbeb => {
            cpu.features.addFeature(
                @intFromEnum(Target.arm.Feature.thumb_mode),
            );
        },
        else => {},
    }
    updateCpuFeatures(
        &cpu.features,
        cpu.arch.allFeaturesList(),
        query.cpu_features_add,
        query.cpu_features_sub,
    );

    var result = try detectAbiAndDynamicLinker(cpu, os, query);

    // These CPU feature hacks have to come after ABI detection.
    {
        if (result.cpu.arch == .hexagon) {
            // Both LLVM and LLD have broken support for the small data area. Yet LLVM has the
            // feature on by default for all Hexagon CPUs. Clang sort of solves this by defaulting
            // the `-gpsize` command line parameter for the Hexagon backend to 0, so that no
            // constants get placed in the SDA. (This of course breaks down if the user passes
            // `-G <n>` to Clang...) We can't do the `-gpsize` hack because we can have multiple
            // concurrent LLVM emit jobs, and command line options in LLVM are shared globally. So
            // just force this feature off. Lovely stuff.
            result.cpu.features.removeFeature(@intFromEnum(Target.hexagon.Feature.small_data));
        }

        // https://github.com/llvm/llvm-project/issues/105978
        if (result.cpu.arch.isArm() and result.abi.float() == .soft) {
            result.cpu.features.removeFeature(@intFromEnum(Target.arm.Feature.vfp2));
        }

        // https://github.com/llvm/llvm-project/issues/135283
        if (result.cpu.arch.isMIPS() and result.abi.float() == .soft) {
            result.cpu.features.addFeature(@intFromEnum(Target.mips.Feature.soft_float));
        }
    }

    // It's possible that we detect the native ABI, but fail to detect the OS version or were told
    // to use the default OS version range. In that case, while we can't determine the exact native
    // OS version, we do at least know that some ABIs require a particular OS version (by way of
    // `std.zig.target.available_libcs`). So in this case, adjust the OS version to the minimum that
    // we know is required.
    if (result.abi != query_abi and query.os_version_min == null) {
        const result_ver_range = &result.os.version_range;
        const abi_ver_range = result.os.tag.defaultVersionRange(result.cpu.arch, result.abi).version_range;

        switch (result.os.tag.versionRangeTag()) {
            .none => {},
            .semver => if (result_ver_range.semver.min.order(abi_ver_range.semver.min) == .lt) {
                result_ver_range.semver.min = abi_ver_range.semver.min;
            },
            inline .hurd, .linux => |t| {
                if (@field(result_ver_range, @tagName(t)).range.min.order(@field(abi_ver_range, @tagName(t)).range.min) == .lt) {
                    @field(result_ver_range, @tagName(t)).range.min = @field(abi_ver_range, @tagName(t)).range.min;
                }

                if (@field(result_ver_range, @tagName(t)).glibc.order(@field(abi_ver_range, @tagName(t)).glibc) == .lt and
                    query.glibc_version == null)
                {
                    @field(result_ver_range, @tagName(t)).glibc = @field(abi_ver_range, @tagName(t)).glibc;
                }
            },
            .windows => if (!result_ver_range.windows.min.isAtLeast(abi_ver_range.windows.min)) {
                result_ver_range.windows.min = abi_ver_range.windows.min;
            },
        }
    }

    return result;
}

fn updateCpuFeatures(
    set: *Target.Cpu.Feature.Set,
    all_features_list: []const Target.Cpu.Feature,
    add_set: Target.Cpu.Feature.Set,
    sub_set: Target.Cpu.Feature.Set,
) void {
    set.removeFeatureSet(sub_set);
    set.addFeatureSet(add_set);
    set.populateDependencies(all_features_list);
    set.removeFeatureSet(sub_set);
}

fn detectNativeCpuAndFeatures(cpu_arch: Target.Cpu.Arch, os: Target.Os, query: Target.Query) ?Target.Cpu {
    // Here we switch on a comptime value rather than `cpu_arch`. This is valid because `cpu_arch`,
    // although it is a runtime value, is guaranteed to be one of the architectures in the set
    // of the respective switch prong.
    switch (builtin.cpu.arch) {
        .x86_64, .x86 => {
            return @import("system/x86.zig").detectNativeCpuAndFeatures(cpu_arch, os, query);
        },
        else => {},
    }

    switch (builtin.os.tag) {
        .linux => return linux.detectNativeCpuAndFeatures(),
        .macos => return darwin.macos.detectNativeCpuAndFeatures(),
        .windows => return windows.detectNativeCpuAndFeatures(),
        else => {},
    }

    // This architecture does not have CPU model & feature detection yet.
    // See https://github.com/ziglang/zig/issues/4591
    return null;
}

pub const AbiAndDynamicLinkerFromFileError = error{
    FileSystem,
    SystemResources,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    UnableToReadElfFile,
    InvalidElfClass,
    InvalidElfVersion,
    InvalidElfEndian,
    InvalidElfFile,
    InvalidElfMagic,
    Unexpected,
    UnexpectedEndOfFile,
    NameTooLong,
    ProcessNotFound,
    StaticElfFile,
};

pub fn abiAndDynamicLinkerFromFile(
    file: fs.File,
    cpu: Target.Cpu,
    os: Target.Os,
    ld_info_list: []const LdInfo,
    query: Target.Query,
) AbiAndDynamicLinkerFromFileError!Target {
    var hdr_buf: [@sizeOf(elf.Elf64_Ehdr)]u8 align(@alignOf(elf.Elf64_Ehdr)) = undefined;
    _ = try preadAtLeast(file, &hdr_buf, 0, hdr_buf.len);
    const hdr32: *elf.Elf32_Ehdr = @ptrCast(&hdr_buf);
    const hdr64: *elf.Elf64_Ehdr = @ptrCast(&hdr_buf);
    if (!mem.eql(u8, hdr32.e_ident[0..4], elf.MAGIC)) return error.InvalidElfMagic;
    const elf_endian: std.builtin.Endian = switch (hdr32.e_ident[elf.EI_DATA]) {
        elf.ELFDATA2LSB => .little,
        elf.ELFDATA2MSB => .big,
        else => return error.InvalidElfEndian,
    };
    const need_bswap = elf_endian != native_endian;
    if (hdr32.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

    const is_64 = switch (hdr32.e_ident[elf.EI_CLASS]) {
        elf.ELFCLASS32 => false,
        elf.ELFCLASS64 => true,
        else => return error.InvalidElfClass,
    };
    var phoff = elfInt(is_64, need_bswap, hdr32.e_phoff, hdr64.e_phoff);
    const phentsize = elfInt(is_64, need_bswap, hdr32.e_phentsize, hdr64.e_phentsize);
    const phnum = elfInt(is_64, need_bswap, hdr32.e_phnum, hdr64.e_phnum);

    var result: Target = .{
        .cpu = cpu,
        .os = os,
        .abi = query.abi orelse Target.Abi.default(cpu.arch, os.tag),
        .ofmt = query.ofmt orelse Target.ObjectFormat.default(os.tag, cpu.arch),
        .dynamic_linker = query.dynamic_linker,
    };
    var rpath_offset: ?u64 = null; // Found inside PT_DYNAMIC
    const look_for_ld = query.dynamic_linker.get() == null;

    var ph_buf: [16 * @sizeOf(elf.Elf64_Phdr)]u8 align(@alignOf(elf.Elf64_Phdr)) = undefined;
    if (phentsize > @sizeOf(elf.Elf64_Phdr)) return error.InvalidElfFile;

    var ph_i: u16 = 0;
    var got_dyn_section: bool = false;

    while (ph_i < phnum) {
        // Reserve some bytes so that we can deref the 64-bit struct fields
        // even when the ELF file is 32-bits.
        const ph_reserve: usize = @sizeOf(elf.Elf64_Phdr) - @sizeOf(elf.Elf32_Phdr);
        const ph_read_byte_len = try preadAtLeast(file, ph_buf[0 .. ph_buf.len - ph_reserve], phoff, phentsize);
        var ph_buf_i: usize = 0;
        while (ph_buf_i < ph_read_byte_len and ph_i < phnum) : ({
            ph_i += 1;
            phoff += phentsize;
            ph_buf_i += phentsize;
        }) {
            const ph32: *elf.Elf32_Phdr = @ptrCast(@alignCast(&ph_buf[ph_buf_i]));
            const ph64: *elf.Elf64_Phdr = @ptrCast(@alignCast(&ph_buf[ph_buf_i]));
            const p_type = elfInt(is_64, need_bswap, ph32.p_type, ph64.p_type);
            switch (p_type) {
                elf.PT_INTERP => {
                    got_dyn_section = true;

                    if (look_for_ld) {
                        const p_offset = elfInt(is_64, need_bswap, ph32.p_offset, ph64.p_offset);
                        const p_filesz = elfInt(is_64, need_bswap, ph32.p_filesz, ph64.p_filesz);
                        if (p_filesz > result.dynamic_linker.buffer.len) return error.NameTooLong;
                        const filesz: usize = @intCast(p_filesz);
                        _ = try preadAtLeast(file, result.dynamic_linker.buffer[0..filesz], p_offset, filesz);
                        // PT_INTERP includes a null byte in filesz.
                        const len = filesz - 1;
                        // dynamic_linker.max_byte is "max", not "len".
                        // We know it will fit in u8 because we check against dynamic_linker.buffer.len above.
                        result.dynamic_linker.len = @intCast(len);

                        // Use it to determine ABI.
                        const full_ld_path = result.dynamic_linker.buffer[0..len];
                        for (ld_info_list) |ld_info| {
                            const standard_ld_basename = fs.path.basename(ld_info.ld.get().?);
                            if (std.mem.endsWith(u8, full_ld_path, standard_ld_basename)) {
                                result.abi = ld_info.abi;
                                break;
                            }
                        }
                    }
                },
                // We only need this for detecting glibc version.
                elf.PT_DYNAMIC => {
                    got_dyn_section = true;

                    if (builtin.target.os.tag == .linux and result.isGnuLibC() and
                        query.glibc_version == null)
                    {
                        var dyn_off = elfInt(is_64, need_bswap, ph32.p_offset, ph64.p_offset);
                        const p_filesz = elfInt(is_64, need_bswap, ph32.p_filesz, ph64.p_filesz);
                        const dyn_size: usize = if (is_64) @sizeOf(elf.Elf64_Dyn) else @sizeOf(elf.Elf32_Dyn);
                        const dyn_num = p_filesz / dyn_size;
                        var dyn_buf: [16 * @sizeOf(elf.Elf64_Dyn)]u8 align(@alignOf(elf.Elf64_Dyn)) = undefined;
                        var dyn_i: usize = 0;
                        dyn: while (dyn_i < dyn_num) {
                            // Reserve some bytes so that we can deref the 64-bit struct fields
                            // even when the ELF file is 32-bits.
                            const dyn_reserve: usize = @sizeOf(elf.Elf64_Dyn) - @sizeOf(elf.Elf32_Dyn);
                            const dyn_read_byte_len = try preadAtLeast(
                                file,
                                dyn_buf[0 .. dyn_buf.len - dyn_reserve],
                                dyn_off,
                                dyn_size,
                            );
                            var dyn_buf_i: usize = 0;
                            while (dyn_buf_i < dyn_read_byte_len and dyn_i < dyn_num) : ({
                                dyn_i += 1;
                                dyn_off += dyn_size;
                                dyn_buf_i += dyn_size;
                            }) {
                                const dyn32: *elf.Elf32_Dyn = @ptrCast(@alignCast(&dyn_buf[dyn_buf_i]));
                                const dyn64: *elf.Elf64_Dyn = @ptrCast(@alignCast(&dyn_buf[dyn_buf_i]));
                                const tag = elfInt(is_64, need_bswap, dyn32.d_tag, dyn64.d_tag);
                                const val = elfInt(is_64, need_bswap, dyn32.d_val, dyn64.d_val);
                                if (tag == elf.DT_RUNPATH) {
                                    rpath_offset = val;
                                    break :dyn;
                                }
                            }
                        }
                    }
                },
                else => continue,
            }
        }
    }

    if (!got_dyn_section) {
     ```
