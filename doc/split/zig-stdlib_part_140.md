```
 if (p.eatToken(.r_brace)) |_| break;
            const next = try p.expectFieldInit();
            try p.scratch.append(p.gpa, next);
        }
        const comma = (p.tokenTag(p.tok_i - 2)) == .comma;
        const inits = p.scratch.items[scratch_top..];
        std.debug.assert(inits.len != 0);
        if (inits.len <= 1) {
            return try p.addNode(.{
                .tag = if (comma) .struct_init_one_comma else .struct_init_one,
                .main_token = lbrace,
                .data = .{ .node_and_opt_node = .{
                    lhs,
                    inits[0].toOptional(),
                } },
            });
        } else {
            return try p.addNode(.{
                .tag = if (comma) .struct_init_comma else .struct_init,
                .main_token = lbrace,
                .data = .{ .node_and_extra = .{
                    lhs,
                    try p.addExtra(try p.listToSpan(inits)),
                } },
            });
        }
    }

    while (true) {
        if (p.eatToken(.r_brace)) |_| break;
        const elem_init = try p.expectExpr();
        try p.scratch.append(p.gpa, elem_init);
        switch (p.tokenTag(p.tok_i)) {
            .comma => p.tok_i += 1,
            .r_brace => {
                p.tok_i += 1;
                break;
            },
            .colon, .r_paren, .r_bracket => return p.failExpected(.r_brace),
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_initializer),
        }
    }
    const comma = (p.tokenTag(p.tok_i - 2)) == .comma;
    const inits = p.scratch.items[scratch_top..];
    switch (inits.len) {
        0 => return try p.addNode(.{
            .tag = .struct_init_one,
            .main_token = lbrace,
            .data = .{ .node_and_opt_node = .{
                lhs,
                .none,
            } },
        }),
        1 => return try p.addNode(.{
            .tag = if (comma) .array_init_one_comma else .array_init_one,
            .main_token = lbrace,
            .data = .{ .node_and_node = .{
                lhs,
                inits[0],
            } },
        }),
        else => return try p.addNode(.{
            .tag = if (comma) .array_init_comma else .array_init,
            .main_token = lbrace,
            .data = .{ .node_and_extra = .{
                lhs,
                try p.addExtra(try p.listToSpan(inits)),
            } },
        }),
    }
}

/// ErrorUnionExpr <- SuffixExpr (EXCLAMATIONMARK TypeExpr)?
fn parseErrorUnionExpr(p: *Parse) !?Node.Index {
    const suffix_expr = try p.parseSuffixExpr() orelse return null;
    const bang = p.eatToken(.bang) orelse return suffix_expr;
    return try p.addNode(.{
        .tag = .error_union,
        .main_token = bang,
        .data = .{ .node_and_node = .{
            suffix_expr,
            try p.expectTypeExpr(),
        } },
    });
}

/// SuffixExpr
///     <- KEYWORD_async PrimaryTypeExpr SuffixOp* FnCallArguments
///      / PrimaryTypeExpr (SuffixOp / FnCallArguments)*
///
/// FnCallArguments <- LPAREN ExprList RPAREN
///
/// ExprList <- (Expr COMMA)* Expr?
fn parseSuffixExpr(p: *Parse) !?Node.Index {
    if (p.eatToken(.keyword_async)) |_| {
        var res = try p.expectPrimaryTypeExpr();
        while (true) {
            res = try p.parseSuffixOp(res) orelse break;
        }
        const lparen = p.eatToken(.l_paren) orelse {
            try p.warn(.expected_param_list);
            return res;
        };
        const scratch_top = p.scratch.items.len;
        defer p.scratch.shrinkRetainingCapacity(scratch_top);
        while (true) {
            if (p.eatToken(.r_paren)) |_| break;
            const param = try p.expectExpr();
            try p.scratch.append(p.gpa, param);
            switch (p.tokenTag(p.tok_i)) {
                .comma => p.tok_i += 1,
                .r_paren => {
                    p.tok_i += 1;
                    break;
                },
                .colon, .r_brace, .r_bracket => return p.failExpected(.r_paren),
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warn(.expected_comma_after_arg),
            }
        }
        const comma = (p.tokenTag(p.tok_i - 2)) == .comma;
        const params = p.scratch.items[scratch_top..];
        if (params.len <= 1) {
            return try p.addNode(.{
                .tag = if (comma) .async_call_one_comma else .async_call_one,
                .main_token = lparen,
                .data = .{ .node_and_opt_node = .{
                    res,
                    if (params.len >= 1) params[0].toOptional() else .none,
                } },
            });
        } else {
            return try p.addNode(.{
                .tag = if (comma) .async_call_comma else .async_call,
                .main_token = lparen,
                .data = .{ .node_and_extra = .{
                    res,
                    try p.addExtra(try p.listToSpan(params)),
                } },
            });
        }
    }

    var res = try p.parsePrimaryTypeExpr() orelse return null;
    while (true) {
        const opt_suffix_op = try p.parseSuffixOp(res);
        if (opt_suffix_op) |suffix_op| {
            res = suffix_op;
            continue;
        }
        const lparen = p.eatToken(.l_paren) orelse return res;
        const scratch_top = p.scratch.items.len;
        defer p.scratch.shrinkRetainingCapacity(scratch_top);
        while (true) {
            if (p.eatToken(.r_paren)) |_| break;
            const param = try p.expectExpr();
            try p.scratch.append(p.gpa, param);
            switch (p.tokenTag(p.tok_i)) {
                .comma => p.tok_i += 1,
                .r_paren => {
                    p.tok_i += 1;
                    break;
                },
                .colon, .r_brace, .r_bracket => return p.failExpected(.r_paren),
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warn(.expected_comma_after_arg),
            }
        }
        const comma = (p.tokenTag(p.tok_i - 2)) == .comma;
        const params = p.scratch.items[scratch_top..];
        res = switch (params.len) {
            0, 1 => try p.addNode(.{
                .tag = if (comma) .call_one_comma else .call_one,
                .main_token = lparen,
                .data = .{ .node_and_opt_node = .{
                    res,
                    if (params.len >= 1) .fromOptional(params[0]) else .none,
                } },
            }),
            else => try p.addNode(.{
                .tag = if (comma) .call_comma else .call,
                .main_token = lparen,
                .data = .{ .node_and_extra = .{
                    res,
                    try p.addExtra(try p.listToSpan(params)),
                } },
            }),
        };
    }
}

/// PrimaryTypeExpr
///     <- BUILTINIDENTIFIER FnCallArguments
///      / CHAR_LITERAL
///      / ContainerDecl
///      / DOT IDENTIFIER
///      / DOT InitList
///      / ErrorSetDecl
///      / FLOAT
///      / FnProto
///      / GroupedExpr
///      / LabeledTypeExpr
///      / IDENTIFIER
///      / IfTypeExpr
///      / INTEGER
///      / KEYWORD_comptime TypeExpr
///      / KEYWORD_error DOT IDENTIFIER
///      / KEYWORD_anyframe
///      / KEYWORD_unreachable
///      / STRINGLITERAL
///
/// ContainerDecl <- (KEYWORD_extern / KEYWORD_packed)? ContainerDeclAuto
///
/// ContainerDeclAuto <- ContainerDeclType LBRACE container_doc_comment? ContainerMembers RBRACE
///
/// InitList
///     <- LBRACE FieldInit (COMMA FieldInit)* COMMA? RBRACE
///      / LBRACE Expr (COMMA Expr)* COMMA? RBRACE
///      / LBRACE RBRACE
///
/// ErrorSetDecl <- KEYWORD_error LBRACE IdentifierList RBRACE
///
/// GroupedExpr <- LPAREN Expr RPAREN
///
/// IfTypeExpr <- IfPrefix TypeExpr (KEYWORD_else Payload? TypeExpr)?
///
/// LabeledTypeExpr
///     <- BlockLabel Block
///      / BlockLabel? LoopTypeExpr
///      / BlockLabel? SwitchExpr
///
/// LoopTypeExpr <- KEYWORD_inline? (ForTypeExpr / WhileTypeExpr)
fn parsePrimaryTypeExpr(p: *Parse) !?Node.Index {
    switch (p.tokenTag(p.tok_i)) {
        .char_literal => return try p.addNode(.{
            .tag = .char_literal,
            .main_token = p.nextToken(),
            .data = undefined,
        }),
        .number_literal => return try p.addNode(.{
            .tag = .number_literal,
            .main_token = p.nextToken(),
            .data = undefined,
        }),
        .keyword_unreachable => return try p.addNode(.{
            .tag = .unreachable_literal,
            .main_token = p.nextToken(),
            .data = undefined,
        }),
        .keyword_anyframe => return try p.addNode(.{
            .tag = .anyframe_literal,
            .main_token = p.nextToken(),
            .data = undefined,
        }),
        .string_literal => {
            const main_token = p.nextToken();
            return try p.addNode(.{
                .tag = .string_literal,
                .main_token = main_token,
                .data = undefined,
            });
        },

        .builtin => return try p.parseBuiltinCall(),
        .keyword_fn => return try p.parseFnProto(),
        .keyword_if => return try p.parseIf(expectTypeExpr),
        .keyword_switch => return try p.expectSwitchExpr(false),

        .keyword_extern,
        .keyword_packed,
        => {
            p.tok_i += 1;
            return try p.parseContainerDeclAuto();
        },

        .keyword_struct,
        .keyword_opaque,
        .keyword_enum,
        .keyword_union,
        => return try p.parseContainerDeclAuto(),

        .keyword_comptime => return try p.addNode(.{
            .tag = .@"comptime",
            .main_token = p.nextToken(),
            .data = .{ .node = try p.expectTypeExpr() },
        }),
        .multiline_string_literal_line => {
            const first_line = p.nextToken();
            while (p.tokenTag(p.tok_i) == .multiline_string_literal_line) {
                p.tok_i += 1;
            }
            return try p.addNode(.{
                .tag = .multiline_string_literal,
                .main_token = first_line,
                .data = .{ .token_and_token = .{
                    first_line,
                    p.tok_i - 1,
                } },
            });
        },
        .identifier => switch (p.tokenTag(p.tok_i + 1)) {
            .colon => switch (p.tokenTag(p.tok_i + 2)) {
                .keyword_inline => {
                    p.tok_i += 3;
                    switch (p.tokenTag(p.tok_i)) {
                        .keyword_for => return try p.parseFor(expectTypeExpr),
                        .keyword_while => return try p.parseWhileTypeExpr(),
                        else => return p.fail(.expected_inlinable),
                    }
                },
                .keyword_for => {
                    p.tok_i += 2;
                    return try p.parseFor(expectTypeExpr);
                },
                .keyword_while => {
                    p.tok_i += 2;
                    return try p.parseWhileTypeExpr();
                },
                .keyword_switch => {
                    p.tok_i += 2;
                    return try p.expectSwitchExpr(true);
                },
                .l_brace => {
                    p.tok_i += 2;
                    return try p.parseBlock();
                },
                else => return try p.addNode(.{
                    .tag = .identifier,
                    .main_token = p.nextToken(),
                    .data = undefined,
                }),
            },
            else => return try p.addNode(.{
                .tag = .identifier,
                .main_token = p.nextToken(),
                .data = undefined,
            }),
        },
        .keyword_inline => {
            p.tok_i += 1;
            switch (p.tokenTag(p.tok_i)) {
                .keyword_for => return try p.parseFor(expectTypeExpr),
                .keyword_while => return try p.parseWhileTypeExpr(),
                else => return p.fail(.expected_inlinable),
            }
        },
        .keyword_for => return try p.parseFor(expectTypeExpr),
        .keyword_while => return try p.parseWhileTypeExpr(),
        .period => switch (p.tokenTag(p.tok_i + 1)) {
            .identifier => {
                p.tok_i += 1;
                return try p.addNode(.{
                    .tag = .enum_literal,
                    .main_token = p.nextToken(), // identifier
                    .data = undefined,
                });
            },
            .l_brace => {
                const lbrace = p.tok_i + 1;
                p.tok_i = lbrace + 1;

                // If there are 0, 1, or 2 items, we can use ArrayInitDotTwo/StructInitDotTwo;
                // otherwise we use the full ArrayInitDot/StructInitDot.

                const scratch_top = p.scratch.items.len;
                defer p.scratch.shrinkRetainingCapacity(scratch_top);
                const opt_field_init = try p.parseFieldInit();
                if (opt_field_init) |field_init| {
                    try p.scratch.append(p.gpa, field_init);
                    while (true) {
                        switch (p.tokenTag(p.tok_i)) {
                            .comma => p.tok_i += 1,
                            .r_brace => {
                                p.tok_i += 1;
                                break;
                            },
                            .colon, .r_paren, .r_bracket => return p.failExpected(.r_brace),
                            // Likely just a missing comma; give error but continue parsing.
                            else => try p.warn(.expected_comma_after_initializer),
                        }
                        if (p.eatToken(.r_brace)) |_| break;
                        const next = try p.expectFieldInit();
                        try p.scratch.append(p.gpa, next);
                    }
                    const comma = (p.tokenTag(p.tok_i - 2)) == .comma;
                    const inits = p.scratch.items[scratch_top..];
                    std.debug.assert(inits.len != 0);
                    if (inits.len <= 2) {
                        return try p.addNode(.{
                            .tag = if (comma) .struct_init_dot_two_comma else .struct_init_dot_two,
                            .main_token = lbrace,
                            .data = .{ .opt_node_and_opt_node = .{
                                if (inits.len >= 1) .fromOptional(inits[0]) else .none,
                                if (inits.len >= 2) .fromOptional(inits[1]) else .none,
                            } },
                        });
                    } else {
                        return try p.addNode(.{
                            .tag = if (comma) .struct_init_dot_comma else .struct_init_dot,
                            .main_token = lbrace,
                            .data = .{ .extra_range = try p.listToSpan(inits) },
                        });
                    }
                }

                while (true) {
                    if (p.eatToken(.r_brace)) |_| break;
                    const elem_init = try p.expectExpr();
                    try p.scratch.append(p.gpa, elem_init);
                    switch (p.tokenTag(p.tok_i)) {
                        .comma => p.tok_i += 1,
                        .r_brace => {
                            p.tok_i += 1;
                            break;
                        },
                        .colon, .r_paren, .r_bracket => return p.failExpected(.r_brace),
                        // Likely just a missing comma; give error but continue parsing.
                        else => try p.warn(.expected_comma_after_initializer),
                    }
                }
                const comma = (p.tokenTag(p.tok_i - 2)) == .comma;
                const inits = p.scratch.items[scratch_top..];
                if (inits.len <= 2) {
                    return try p.addNode(.{
                        .tag = if (inits.len == 0)
                            .struct_init_dot_two
                        else if (comma) .array_init_dot_two_comma else .array_init_dot_two,
                        .main_token = lbrace,
                        .data = .{ .opt_node_and_opt_node = .{
                            if (inits.len >= 1) inits[0].toOptional() else .none,
                            if (inits.len >= 2) inits[1].toOptional() else .none,
                        } },
                    });
                } else {
                    return try p.addNode(.{
                        .tag = if (comma) .array_init_dot_comma else .array_init_dot,
                        .main_token = lbrace,
                        .data = .{ .extra_range = try p.listToSpan(inits) },
                    });
                }
            },
            else => return null,
        },
        .keyword_error => switch (p.tokenTag(p.tok_i + 1)) {
            .l_brace => {
                const error_token = p.tok_i;
                p.tok_i += 2;
                while (true) {
                    if (p.eatToken(.r_brace)) |_| break;
                    _ = try p.eatDocComments();
                    _ = try p.expectToken(.identifier);
                    switch (p.tokenTag(p.tok_i)) {
                        .comma => p.tok_i += 1,
                        .r_brace => {
                            p.tok_i += 1;
                            break;
                        },
                        .colon, .r_paren, .r_bracket => return p.failExpected(.r_brace),
                        // Likely just a missing comma; give error but continue parsing.
                        else => try p.warn(.expected_comma_after_field),
                    }
                }
                return try p.addNode(.{
                    .tag = .error_set_decl,
                    .main_token = error_token,
                    .data = .{
                        .token_and_token = .{
                            error_token + 1, // lbrace
                            p.tok_i - 1, // rbrace
                        },
                    },
                });
            },
            else => {
                const main_token = p.nextToken();
                const period = p.eatToken(.period);
                if (period == null) try p.warnExpected(.period);
                const identifier = p.eatToken(.identifier);
                if (identifier == null) try p.warnExpected(.identifier);
                return try p.addNode(.{
                    .tag = .error_value,
                    .main_token = main_token,
                    .data = undefined,
                });
            },
        },
        .l_paren => return try p.addNode(.{
            .tag = .grouped_expression,
            .main_token = p.nextToken(),
            .data = .{ .node_and_token = .{
                try p.expectExpr(),
                try p.expectToken(.r_paren),
            } },
        }),
        else => return null,
    }
}

fn expectPrimaryTypeExpr(p: *Parse) !Node.Index {
    return try p.parsePrimaryTypeExpr() orelse return p.fail(.expected_primary_type_expr);
}

/// WhilePrefix <- KEYWORD_while LPAREN Expr RPAREN PtrPayload? WhileContinueExpr?
///
/// WhileTypeExpr <- WhilePrefix TypeExpr (KEYWORD_else Payload? TypeExpr)?
fn parseWhileTypeExpr(p: *Parse) !?Node.Index {
    const while_token = p.eatToken(.keyword_while) orelse return null;
    _ = try p.expectToken(.l_paren);
    const condition = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    _ = try p.parsePtrPayload();
    const cont_expr = try p.parseWhileContinueExpr();

    const then_expr = try p.expectTypeExpr();
    _ = p.eatToken(.keyword_else) orelse {
        if (cont_expr == null) {
            return try p.addNode(.{
                .tag = .while_simple,
                .main_token = while_token,
                .data = .{ .node_and_node = .{
                    condition,
                    then_expr,
                } },
            });
        } else {
            return try p.addNode(.{
                .tag = .while_cont,
                .main_token = while_token,
                .data = .{ .node_and_extra = .{
                    condition, try p.addExtra(Node.WhileCont{
                        .cont_expr = cont_expr.?,
                        .then_expr = then_expr,
                    }),
                } },
            });
        }
    };
    _ = try p.parsePayload();
    const else_expr = try p.expectTypeExpr();
    return try p.addNode(.{
        .tag = .@"while",
        .main_token = while_token,
        .data = .{ .node_and_extra = .{
            condition, try p.addExtra(Node.While{
                .cont_expr = .fromOptional(cont_expr),
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        } },
    });
}

/// SwitchExpr <- KEYWORD_switch LPAREN Expr RPAREN LBRACE SwitchProngList RBRACE
fn parseSwitchExpr(p: *Parse, is_labeled: bool) !?Node.Index {
    const switch_token = p.eatToken(.keyword_switch) orelse return null;
    return try p.expectSwitchSuffix(if (is_labeled) switch_token - 2 else switch_token);
}

fn expectSwitchExpr(p: *Parse, is_labeled: bool) !Node.Index {
    const switch_token = p.assertToken(.keyword_switch);
    return try p.expectSwitchSuffix(if (is_labeled) switch_token - 2 else switch_token);
}

fn expectSwitchSuffix(p: *Parse, main_token: TokenIndex) !Node.Index {
    _ = try p.expectToken(.l_paren);
    const expr_node = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    _ = try p.expectToken(.l_brace);
    const cases = try p.parseSwitchProngList();
    const trailing_comma = p.tokenTag(p.tok_i - 1) == .comma;
    _ = try p.expectToken(.r_brace);

    return p.addNode(.{
        .tag = if (trailing_comma) .switch_comma else .@"switch",
        .main_token = main_token,
        .data = .{ .node_and_extra = .{
            expr_node,
            try p.addExtra(Node.SubRange{
                .start = cases.start,
                .end = cases.end,
            }),
        } },
    });
}

/// AsmExpr <- KEYWORD_asm KEYWORD_volatile? LPAREN Expr AsmOutput? RPAREN
///
/// AsmOutput <- COLON AsmOutputList AsmInput?
///
/// AsmInput <- COLON AsmInputList AsmClobbers?
///
/// AsmClobbers <- COLON StringList
///
/// StringList <- (STRINGLITERAL COMMA)* STRINGLITERAL?
///
/// AsmOutputList <- (AsmOutputItem COMMA)* AsmOutputItem?
///
/// AsmInputList <- (AsmInputItem COMMA)* AsmInputItem?
fn expectAsmExpr(p: *Parse) !Node.Index {
    const asm_token = p.assertToken(.keyword_asm);
    _ = p.eatToken(.keyword_volatile);
    _ = try p.expectToken(.l_paren);
    const template = try p.expectExpr();

    if (p.eatToken(.r_paren)) |rparen| {
        return p.addNode(.{
            .tag = .asm_simple,
            .main_token = asm_token,
            .data = .{ .node_and_token = .{
                template,
                rparen,
            } },
        });
    }

    _ = try p.expectToken(.colon);

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    while (true) {
        const output_item = try p.parseAsmOutputItem() orelse break;
        try p.scratch.append(p.gpa, output_item);
        switch (p.tokenTag(p.tok_i)) {
            .comma => p.tok_i += 1,
            // All possible delimiters.
            .colon, .r_paren, .r_brace, .r_bracket => break,
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warnExpected(.comma),
        }
    }
    if (p.eatToken(.colon)) |_| {
        while (true) {
            const input_item = try p.parseAsmInputItem() orelse break;
            try p.scratch.append(p.gpa, input_item);
            switch (p.tokenTag(p.tok_i)) {
                .comma => p.tok_i += 1,
                // All possible delimiters.
                .colon, .r_paren, .r_brace, .r_bracket => break,
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warnExpected(.comma),
            }
        }
        if (p.eatToken(.colon)) |_| {
            while (p.eatToken(.string_literal)) |_| {
                switch (p.tokenTag(p.tok_i)) {
                    .comma => p.tok_i += 1,
                    .colon, .r_paren, .r_brace, .r_bracket => break,
                    // Likely just a missing comma; give error but continue parsing.
                    else => try p.warnExpected(.comma),
                }
            }
        }
    }
    const rparen = try p.expectToken(.r_paren);
    const span = try p.listToSpan(p.scratch.items[scratch_top..]);
    return p.addNode(.{
        .tag = .@"asm",
        .main_token = asm_token,
        .data = .{ .node_and_extra = .{
            template,
            try p.addExtra(Node.Asm{
                .items_start = span.start,
                .items_end = span.end,
                .rparen = rparen,
            }),
        } },
    });
}

/// AsmOutputItem <- LBRACKET IDENTIFIER RBRACKET STRINGLITERAL LPAREN (MINUSRARROW TypeExpr / IDENTIFIER) RPAREN
fn parseAsmOutputItem(p: *Parse) !?Node.Index {
    _ = p.eatToken(.l_bracket) orelse return null;
    const identifier = try p.expectToken(.identifier);
    _ = try p.expectToken(.r_bracket);
    _ = try p.expectToken(.string_literal);
    _ = try p.expectToken(.l_paren);
    const type_expr: Node.OptionalIndex = blk: {
        if (p.eatToken(.arrow)) |_| {
            break :blk .fromOptional(try p.expectTypeExpr());
        } else {
            _ = try p.expectToken(.identifier);
            break :blk .none;
        }
    };
    const rparen = try p.expectToken(.r_paren);
    return try p.addNode(.{
        .tag = .asm_output,
        .main_token = identifier,
        .data = .{ .opt_node_and_token = .{
            type_expr,
            rparen,
        } },
    });
}

/// AsmInputItem <- LBRACKET IDENTIFIER RBRACKET STRINGLITERAL LPAREN Expr RPAREN
fn parseAsmInputItem(p: *Parse) !?Node.Index {
    _ = p.eatToken(.l_bracket) orelse return null;
    const identifier = try p.expectToken(.identifier);
    _ = try p.expectToken(.r_bracket);
    _ = try p.expectToken(.string_literal);
    _ = try p.expectToken(.l_paren);
    const expr = try p.expectExpr();
    const rparen = try p.expectToken(.r_paren);
    return try p.addNode(.{
        .tag = .asm_input,
        .main_token = identifier,
        .data = .{ .node_and_token = .{
            expr,
            rparen,
        } },
    });
}

/// BreakLabel <- COLON IDENTIFIER
fn parseBreakLabel(p: *Parse) Error!OptionalTokenIndex {
    _ = p.eatToken(.colon) orelse return .none;
    const next_token = try p.expectToken(.identifier);
    return .fromToken(next_token);
}

/// BlockLabel <- IDENTIFIER COLON
fn parseBlockLabel(p: *Parse) ?TokenIndex {
    return p.eatTokens(&.{ .identifier, .colon });
}

/// FieldInit <- DOT IDENTIFIER EQUAL Expr
fn parseFieldInit(p: *Parse) !?Node.Index {
    if (p.eatTokens(&.{ .period, .identifier, .equal })) |_| {
        return try p.expectExpr();
    }
    return null;
}

fn expectFieldInit(p: *Parse) !Node.Index {
    if (p.eatTokens(&.{ .period, .identifier, .equal })) |_| {
        return try p.expectExpr();
    }
    return p.fail(.expected_initializer);
}

/// WhileContinueExpr <- COLON LPAREN AssignExpr RPAREN
fn parseWhileContinueExpr(p: *Parse) !?Node.Index {
    _ = p.eatToken(.colon) orelse {
        if (p.tokenTag(p.tok_i) == .l_paren and
            p.tokensOnSameLine(p.tok_i - 1, p.tok_i))
            return p.fail(.expected_continue_expr);
        return null;
    };
    _ = try p.expectToken(.l_paren);
    const node = try p.parseAssignExpr() orelse return p.fail(.expected_expr_or_assignment);
    _ = try p.expectToken(.r_paren);
    return node;
}

/// LinkSection <- KEYWORD_linksection LPAREN Expr RPAREN
fn parseLinkSection(p: *Parse) !?Node.Index {
    _ = p.eatToken(.keyword_linksection) orelse return null;
    _ = try p.expectToken(.l_paren);
    const expr_node = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    return expr_node;
}

/// CallConv <- KEYWORD_callconv LPAREN Expr RPAREN
fn parseCallconv(p: *Parse) !?Node.Index {
    _ = p.eatToken(.keyword_callconv) orelse return null;
    _ = try p.expectToken(.l_paren);
    const expr_node = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    return expr_node;
}

/// AddrSpace <- KEYWORD_addrspace LPAREN Expr RPAREN
fn parseAddrSpace(p: *Parse) !?Node.Index {
    _ = p.eatToken(.keyword_addrspace) orelse return null;
    _ = try p.expectToken(.l_paren);
    const expr_node = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    return expr_node;
}

/// This function can return null nodes and then still return nodes afterwards,
/// such as in the case of anytype and `...`. Caller must look for rparen to find
/// out when there are no more param decls left.
///
/// ParamDecl
///     <- doc_comment? (KEYWORD_noalias / KEYWORD_comptime)? (IDENTIFIER COLON)? ParamType
///      / DOT3
///
/// ParamType
///     <- KEYWORD_anytype
///      / TypeExpr
fn expectParamDecl(p: *Parse) !?Node.Index {
    _ = try p.eatDocComments();
    switch (p.tokenTag(p.tok_i)) {
        .keyword_noalias, .keyword_comptime => p.tok_i += 1,
        .ellipsis3 => {
            p.tok_i += 1;
            return null;
        },
        else => {},
    }
    _ = p.eatTokens(&.{ .identifier, .colon });
    if (p.eatToken(.keyword_anytype)) |_| {
        return null;
    } else {
        return try p.expectTypeExpr();
    }
}

/// Payload <- PIPE IDENTIFIER PIPE
fn parsePayload(p: *Parse) Error!OptionalTokenIndex {
    _ = p.eatToken(.pipe) orelse return .none;
    const identifier = try p.expectToken(.identifier);
    _ = try p.expectToken(.pipe);
    return .fromToken(identifier);
}

/// PtrPayload <- PIPE ASTERISK? IDENTIFIER PIPE
fn parsePtrPayload(p: *Parse) Error!OptionalTokenIndex {
    _ = p.eatToken(.pipe) orelse return .none;
    _ = p.eatToken(.asterisk);
    const identifier = try p.expectToken(.identifier);
    _ = try p.expectToken(.pipe);
    return .fromToken(identifier);
}

/// Returns the first identifier token, if any.
///
/// PtrIndexPayload <- PIPE ASTERISK? IDENTIFIER (COMMA IDENTIFIER)? PIPE
fn parsePtrIndexPayload(p: *Parse) Error!OptionalTokenIndex {
    _ = p.eatToken(.pipe) orelse return .none;
    _ = p.eatToken(.asterisk);
    const identifier = try p.expectToken(.identifier);
    if (p.eatToken(.comma) != null) {
        _ = try p.expectToken(.identifier);
    }
    _ = try p.expectToken(.pipe);
    return .fromToken(identifier);
}

/// SwitchProng <- KEYWORD_inline? SwitchCase EQUALRARROW PtrIndexPayload? AssignExpr
///
/// SwitchCase
///     <- SwitchItem (COMMA SwitchItem)* COMMA?
///      / KEYWORD_else
fn parseSwitchProng(p: *Parse) !?Node.Index {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    const is_inline = p.eatToken(.keyword_inline) != null;

    if (p.eatToken(.keyword_else) == null) {
        while (true) {
            const item = try p.parseSwitchItem() orelse break;
            try p.scratch.append(p.gpa, item);
            if (p.eatToken(.comma) == null) break;
        }
        if (scratch_top == p.scratch.items.len) {
            if (is_inline) p.tok_i -= 1;
            return null;
        }
    }
    const arrow_token = try p.expectToken(.equal_angle_bracket_right);
    _ = try p.parsePtrIndexPayload();

    const items = p.scratch.items[scratch_top..];
    if (items.len <= 1) {
        return try p.addNode(.{
            .tag = if (is_inline) .switch_case_inline_one else .switch_case_one,
            .main_token = arrow_token,
            .data = .{ .opt_node_and_node = .{
                if (items.len >= 1) items[0].toOptional() else .none,
                try p.expectSingleAssignExpr(),
            } },
        });
    } else {
        return try p.addNode(.{
            .tag = if (is_inline) .switch_case_inline else .switch_case,
            .main_token = arrow_token,
            .data = .{ .extra_and_node = .{
                try p.addExtra(try p.listToSpan(items)),
                try p.expectSingleAssignExpr(),
            } },
        });
    }
}

/// SwitchItem <- Expr (DOT3 Expr)?
fn parseSwitchItem(p: *Parse) !?Node.Index {
    const expr = try p.parseExpr() orelse return null;

    if (p.eatToken(.ellipsis3)) |token| {
        return try p.addNode(.{
            .tag = .switch_range,
            .main_token = token,
            .data = .{ .node_and_node = .{
                expr,
                try p.expectExpr(),
            } },
        });
    }
    return expr;
}

/// The following invariant will hold:
/// - `(bit_range_start == .none) == (bit_range_end == .none)`
/// - `bit_range_start != .none` implies `align_node != .none`
/// - `bit_range_end != .none` implies `align_node != .none`
const PtrModifiers = struct {
    align_node: Node.OptionalIndex,
    addrspace_node: Node.OptionalIndex,
    bit_range_start: Node.OptionalIndex,
    bit_range_end: Node.OptionalIndex,
};

fn parsePtrModifiers(p: *Parse) !PtrModifiers {
    var result: PtrModifiers = .{
        .align_node = .none,
        .addrspace_node = .none,
        .bit_range_start = .none,
        .bit_range_end = .none,
    };
    var saw_const = false;
    var saw_volatile = false;
    var saw_allowzero = false;
    while (true) {
        switch (p.tokenTag(p.tok_i)) {
            .keyword_align => {
                if (result.align_node != .none) {
                    try p.warn(.extra_align_qualifier);
                }
                p.tok_i += 1;
                _ = try p.expectToken(.l_paren);
                result.align_node = (try p.expectExpr()).toOptional();

                if (p.eatToken(.colon)) |_| {
                    result.bit_range_start = (try p.expectExpr()).toOptional();
                    _ = try p.expectToken(.colon);
                    result.bit_range_end = (try p.expectExpr()).toOptional();
                }

                _ = try p.expectToken(.r_paren);
            },
            .keyword_const => {
                if (saw_const) {
                    try p.warn(.extra_const_qualifier);
                }
                p.tok_i += 1;
                saw_const = true;
            },
            .keyword_volatile => {
                if (saw_volatile) {
                    try p.warn(.extra_volatile_qualifier);
                }
                p.tok_i += 1;
                saw_volatile = true;
            },
            .keyword_allowzero => {
                if (saw_allowzero) {
                    try p.warn(.extra_allowzero_qualifier);
                }
                p.tok_i += 1;
                saw_allowzero = true;
            },
            .keyword_addrspace => {
                if (result.addrspace_node != .none) {
                    try p.warn(.extra_addrspace_qualifier);
                }
                result.addrspace_node = .fromOptional(try p.parseAddrSpace());
            },
            else => return result,
        }
    }
}

/// SuffixOp
///     <- LBRACKET Expr (DOT2 (Expr? (COLON Expr)?)?)? RBRACKET
///      / DOT IDENTIFIER
///      / DOTASTERISK
///      / DOTQUESTIONMARK
fn parseSuffixOp(p: *Parse, lhs: Node.Index) !?Node.Index {
    switch (p.tokenTag(p.tok_i)) {
        .l_bracket => {
            const lbracket = p.nextToken();
            const index_expr = try p.expectExpr();

            if (p.eatToken(.ellipsis2)) |_| {
                const opt_end_expr = try p.parseExpr();
                if (p.eatToken(.colon)) |_| {
                    const sentinel = try p.expectExpr();
                    _ = try p.expectToken(.r_bracket);
                    return try p.addNode(.{
                        .tag = .slice_sentinel,
                        .main_token = lbracket,
                        .data = .{ .node_and_extra = .{
                            lhs, try p.addExtra(Node.SliceSentinel{
                                .start = index_expr,
                                .end = .fromOptional(opt_end_expr),
                                .sentinel = sentinel,
                            }),
                        } },
                    });
                }
                _ = try p.expectToken(.r_bracket);
                const end_expr = opt_end_expr orelse {
                    return try p.addNode(.{
                        .tag = .slice_open,
                        .main_token = lbracket,
                        .data = .{ .node_and_node = .{
                            lhs,
                            index_expr,
                        } },
                    });
                };
                return try p.addNode(.{
                    .tag = .slice,
                    .main_token = lbracket,
                    .data = .{ .node_and_extra = .{
                        lhs, try p.addExtra(Node.Slice{
                            .start = index_expr,
                            .end = end_expr,
                        }),
                    } },
                });
            }
            _ = try p.expectToken(.r_bracket);
            return try p.addNode(.{
                .tag = .array_access,
                .main_token = lbracket,
                .data = .{ .node_and_node = .{
                    lhs,
                    index_expr,
                } },
            });
        },
        .period_asterisk => return try p.addNode(.{
            .tag = .deref,
            .main_token = p.nextToken(),
            .data = .{ .node = lhs },
        }),
        .invalid_periodasterisks => {
            try p.warn(.asterisk_after_ptr_deref);
            return try p.addNode(.{
                .tag = .deref,
                .main_token = p.nextToken(),
                .data = .{ .node = lhs },
            });
        },
        .period => switch (p.tokenTag(p.tok_i + 1)) {
            .identifier => return try p.addNode(.{
                .tag = .field_access,
                .main_token = p.nextToken(),
                .data = .{ .node_and_token = .{
                    lhs,
                    p.nextToken(),
                } },
            }),
            .question_mark => return try p.addNode(.{
                .tag = .unwrap_optional,
                .main_token = p.nextToken(),
                .data = .{ .node_and_token = .{
                    lhs,
                    p.nextToken(),
                } },
            }),
            .l_brace => {
                // this a misplaced `.{`, handle the error somewhere else
                return null;
            },
            else => {
                p.tok_i += 1;
                try p.warn(.expected_suffix_op);
                return null;
            },
        },
        else => return null,
    }
}

/// Caller must have already verified the first token.
///
/// ContainerDeclAuto <- ContainerDeclType LBRACE container_doc_comment? ContainerMembers RBRACE
///
/// ContainerDeclType
///     <- KEYWORD_struct (LPAREN Expr RPAREN)?
///      / KEYWORD_opaque
///      / KEYWORD_enum (LPAREN Expr RPAREN)?
///      / KEYWORD_union (LPAREN (KEYWORD_enum (LPAREN Expr RPAREN)? / Expr) RPAREN)?
fn parseContainerDeclAuto(p: *Parse) !?Node.Index {
    const main_token = p.nextToken();
    const arg_expr = switch (p.tokenTag(main_token)) {
        .keyword_opaque => null,
        .keyword_struct, .keyword_enum => blk: {
            if (p.eatToken(.l_paren)) |_| {
                const expr = try p.expectExpr();
                _ = try p.expectToken(.r_paren);
                break :blk expr;
            } else {
                break :blk null;
            }
        },
        .keyword_union => blk: {
            if (p.eatToken(.l_paren)) |_| {
                if (p.eatToken(.keyword_enum)) |_| {
                    if (p.eatToken(.l_paren)) |_| {
                        const enum_tag_expr = try p.expectExpr();
                        _ = try p.expectToken(.r_paren);
                        _ = try p.expectToken(.r_paren);

                        _ = try p.expectToken(.l_brace);
                        const members = try p.parseContainerMembers();
                        const members_span = try members.toSpan(p);
                        _ = try p.expectToken(.r_brace);
                        return try p.addNode(.{
                            .tag = switch (members.trailing) {
                                true => .tagged_union_enum_tag_trailing,
                                false => .tagged_union_enum_tag,
                            },
                            .main_token = main_token,
                            .data = .{ .node_and_extra = .{
                                enum_tag_expr,
                                try p.addExtra(members_span),
                            } },
                        });
                    } else {
                        _ = try p.expectToken(.r_paren);

                        _ = try p.expectToken(.l_brace);
                        const members = try p.parseContainerMembers();
                        _ = try p.expectToken(.r_brace);
                        if (members.len <= 2) {
                            return try p.addNode(.{
                                .tag = switch (members.trailing) {
                                    true => .tagged_union_two_trailing,
                                    false => .tagged_union_two,
                                },
                                .main_token = main_token,
                                .data = members.data,
                            });
                        } else {
                            const span = try members.toSpan(p);
                            return try p.addNode(.{
                                .tag = switch (members.trailing) {
                                    true => .tagged_union_trailing,
                                    false => .tagged_union,
                                },
                                .main_token = main_token,
                                .data = .{ .extra_range = span },
                            });
                        }
                    }
                } else {
                    const expr = try p.expectExpr();
                    _ = try p.expectToken(.r_paren);
                    break :blk expr;
                }
            } else {
                break :blk null;
            }
        },
        else => {
            p.tok_i -= 1;
            return p.fail(.expected_container);
        },
    };
    _ = try p.expectToken(.l_brace);
    const members = try p.parseContainerMembers();
    _ = try p.expectToken(.r_brace);
    if (arg_expr == null) {
        if (members.len <= 2) {
            return try p.addNode(.{
                .tag = switch (members.trailing) {
                    true => .container_decl_two_trailing,
                    false => .container_decl_two,
                },
                .main_token = main_token,
                .data = members.data,
            });
        } else {
            const span = try members.toSpan(p);
            return try p.addNode(.{
                .tag = switch (members.trailing) {
                    true => .container_decl_trailing,
                    false => .container_decl,
                },
                .main_token = main_token,
                .data = .{ .extra_range = span },
            });
        }
    } else {
        const span = try members.toSpan(p);
        return try p.addNode(.{
            .tag = switch (members.trailing) {
                true => .container_decl_arg_trailing,
                false => .container_decl_arg,
            },
            .main_token = main_token,
            .data = .{ .node_and_extra = .{
                arg_expr.?,
                try p.addExtra(Node.SubRange{
                    .start = span.start,
                    .end = span.end,
                }),
            } },
        });
    }
}

/// Give a helpful error message for those transitioning from
/// C's 'struct Foo {};' to Zig's 'const Foo = struct {};'.
fn parseCStyleContainer(p: *Parse) Error!bool {
    const main_token = p.tok_i;
    switch (p.tokenTag(p.tok_i)) {
        .keyword_enum, .keyword_union, .keyword_struct => {},
        else => return false,
    }
    const identifier = p.tok_i + 1;
    if (p.tokenTag(identifier) != .identifier) return false;
    p.tok_i += 2;

    try p.warnMsg(.{
        .tag = .c_style_container,
        .token = identifier,
        .extra = .{ .expected_tag = p.tokenTag(main_token) },
    });
    try p.warnMsg(.{
        .tag = .zig_style_container,
        .is_note = true,
        .token = identifier,
        .extra = .{ .expected_tag = p.tokenTag(main_token) },
    });

    _ = try p.expectToken(.l_brace);
    _ = try p.parseContainerMembers();
    _ = try p.expectToken(.r_brace);
    try p.expectSemicolon(.expected_semi_after_decl, true);
    return true;
}

/// Holds temporary data until we are ready to construct the full ContainerDecl AST node.
///
/// ByteAlign <- KEYWORD_align LPAREN Expr RPAREN
fn parseByteAlign(p: *Parse) !?Node.Index {
    _ = p.eatToken(.keyword_align) orelse return null;
    _ = try p.expectToken(.l_paren);
    const expr = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    return expr;
}

/// SwitchProngList <- (SwitchProng COMMA)* SwitchProng?
fn parseSwitchProngList(p: *Parse) !Node.SubRange {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    while (true) {
        const item = try parseSwitchProng(p) orelse break;

        try p.scratch.append(p.gpa, item);

        switch (p.tokenTag(p.tok_i)) {
            .comma => p.tok_i += 1,
            // All possible delimiters.
            .colon, .r_paren, .r_brace, .r_bracket => break,
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_switch_prong),
        }
    }
    return p.listToSpan(p.scratch.items[scratch_top..]);
}

/// ParamDeclList <- (ParamDecl COMMA)* ParamDecl?
fn parseParamDeclList(p: *Parse) !SmallSpan {
    _ = try p.expectToken(.l_paren);
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);
    var varargs: union(enum) { none, seen, nonfinal: TokenIndex } = .none;
    while (true) {
        if (p.eatToken(.r_paren)) |_| break;
        if (varargs == .seen) varargs = .{ .nonfinal = p.tok_i };
        const opt_param = try p.expectParamDecl();
        if (opt_param) |param| {
            try p.scratch.append(p.gpa, param);
        } else if (p.tokenTag(p.tok_i - 1) == .ellipsis3) {
            if (varargs == .none) varargs = .seen;
        }
        switch (p.tokenTag(p.tok_i)) {
            .comma => p.tok_i += 1,
            .r_paren => {
                p.tok_i += 1;
                break;
            },
            .colon, .r_brace, .r_bracket => return p.failExpected(.r_paren),
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_param),
        }
    }
    if (varargs == .nonfinal) {
        try p.warnMsg(.{ .tag = .varargs_nonfinal, .token = varargs.nonfinal });
    }
    const params = p.scratch.items[scratch_top..];
    return switch (params.len) {
        0 => .{ .zero_or_one = .none },
        1 => .{ .zero_or_one = params[0].toOptional() },
        else => .{ .multi = try p.listToSpan(params) },
    };
}

/// FnCallArguments <- LPAREN ExprList RPAREN
///
/// ExprList <- (Expr COMMA)* Expr?
fn parseBuiltinCall(p: *Parse) !Node.Index {
    const builtin_token = p.assertToken(.builtin);
    _ = p.eatToken(.l_paren) orelse {
        try p.warn(.expected_param_list);
        // Pretend this was an identifier so we can continue parsing.
        return p.addNode(.{
            .tag = .identifier,
            .main_token = builtin_token,
            .data = undefined,
        });
    };
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);
    while (true) {
        if (p.eatToken(.r_paren)) |_| break;
        const param = try p.expectExpr();
        try p.scratch.append(p.gpa, param);
        switch (p.tokenTag(p.tok_i)) {
            .comma => p.tok_i += 1,
            .r_paren => {
                p.tok_i += 1;
                break;
            },
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_arg),
        }
    }
    const comma = (p.tokenTag(p.tok_i - 2)) == .comma;
    const params = p.scratch.items[scratch_top..];
    if (params.len <= 2) {
        return p.addNode(.{
            .tag = if (comma) .builtin_call_two_comma else .builtin_call_two,
            .main_token = builtin_token,
            .data = .{ .opt_node_and_opt_node = .{
                if (params.len >= 1) .fromOptional(params[0]) else .none,
                if (params.len >= 2) .fromOptional(params[1]) else .none,
            } },
        });
    } else {
        const span = try p.listToSpan(params);
        return p.addNode(.{
            .tag = if (comma) .builtin_call_comma else .builtin_call,
            .main_token = builtin_token,
            .data = .{ .extra_range = span },
        });
    }
}

/// IfPrefix <- KEYWORD_if LPAREN Expr RPAREN PtrPayload?
fn parseIf(p: *Parse, comptime bodyParseFn: fn (p: *Parse) Error!Node.Index) !?Node.Index {
    const if_token = p.eatToken(.keyword_if) orelse return null;
    _ = try p.expectToken(.l_paren);
    const condition = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    _ = try p.parsePtrPayload();

    const then_expr = try bodyParseFn(p);

    _ = p.eatToken(.keyword_else) orelse return try p.addNode(.{
        .tag = .if_simple,
        .main_token = if_token,
        .data = .{ .node_and_node = .{
            condition,
            then_expr,
        } },
    });
    _ = try p.parsePayload();
    const else_expr = try bodyParseFn(p);

    return try p.addNode(.{
        .tag = .@"if",
        .main_token = if_token,
        .data = .{ .node_and_extra = .{
            condition,
            try p.addExtra(Node.If{
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        } },
    });
}

/// ForExpr <- ForPrefix Expr (KEYWORD_else Expr)?
///
/// ForTypeExpr <- ForPrefix TypeExpr (KEYWORD_else TypeExpr)?
fn parseFor(p: *Parse, comptime bodyParseFn: fn (p: *Parse) Error!Node.Index) !?Node.Index {
    const for_token = p.eatToken(.keyword_for) orelse return null;

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);
    const inputs = try p.forPrefix();

    const then_expr = try bodyParseFn(p);
    var has_else = false;
    if (p.eatToken(.keyword_else)) |_| {
        try p.scratch.append(p.gpa, then_expr);
        const else_expr = try bodyParseFn(p);
        try p.scratch.append(p.gpa, else_expr);
        has_else = true;
    } else if (inputs == 1) {
        return try p.addNode(.{
            .tag = .for_simple,
            .main_token = for_token,
            .data = .{ .node_and_node = .{
                p.scratch.items[scratch_top],
                then_expr,
            } },
        });
    } else {
        try p.scratch.append(p.gpa, then_expr);
    }
    return try p.addNode(.{
        .tag = .@"for",
        .main_token = for_token,
        .data = .{ .@"for" = .{
            (try p.listToSpan(p.scratch.items[scratch_top..])).start,
            .{ .inputs = @intCast(inputs), .has_else = has_else },
        } },
    });
}

/// Skips over doc comment tokens. Returns the first one, if any.
fn eatDocComments(p: *Parse) Allocator.Error!?TokenIndex {
    if (p.eatToken(.doc_comment)) |tok| {
        var first_line = tok;
        if (tok > 0 and tokensOnSameLine(p, tok - 1, tok)) {
            try p.warnMsg(.{
                .tag = .same_line_doc_comment,
                .token = tok,
            });
            first_line = p.eatToken(.doc_comment) orelse return null;
        }
        while (p.eatToken(.doc_comment)) |_| {}
        return first_line;
    }
    return null;
}

fn tokensOnSameLine(p: *Parse, token1: TokenIndex, token2: TokenIndex) bool {
    return std.mem.indexOfScalar(u8, p.source[p.tokenStart(token1)..p.tokenStart(token2)], '\n') == null;
}

fn eatToken(p: *Parse, tag: Token.Tag) ?TokenIndex {
    return if (p.tokenTag(p.tok_i) == tag) p.nextToken() else null;
}

fn eatTokens(p: *Parse, tags: []const Token.Tag) ?TokenIndex {
    const available_tags = p.tokens.items(.tag)[p.tok_i..];
    if (!std.mem.startsWith(Token.Tag, available_tags, tags)) return null;
    const result = p.tok_i;
    p.tok_i += @intCast(tags.len);
    return result;
}

fn assertToken(p: *Parse, tag: Token.Tag) TokenIndex {
    const token = p.nextToken();
    assert(p.tokenTag(token) == tag);
    return token;
}

fn expectToken(p: *Parse, tag: Token.Tag) Error!TokenIndex {
    if (p.tokenTag(p.tok_i) != tag) {
        return p.failMsg(.{
            .tag = .expected_token,
            .token = p.tok_i,
            .extra = .{ .expected_tag = tag },
        });
    }
    return p.nextToken();
}

fn expectSemicolon(p: *Parse, error_tag: AstError.Tag, recoverable: bool) Error!void {
    if (p.tokenTag(p.tok_i) == .semicolon) {
        _ = p.nextToken();
        return;
    }
    try p.warn(error_tag);
    if (!recoverable) return error.ParseError;
}

fn nextToken(p: *Parse) TokenIndex {
    const result = p.tok_i;
    p.tok_i += 1;
    return result;
}

const Parse = @This();
const std = @import("../std.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const Node = Ast.Node;
const AstError = Ast.Error;
const TokenIndex = Ast.TokenIndex;
const OptionalTokenIndex = Ast.OptionalTokenIndex;
const ExtraIndex = Ast.ExtraIndex;
const Token = std.zig.Token;

test {
    _ = @import("parser_test.zig");
}
test "zig fmt: remove extra whitespace at start and end of file with comment between" {
    try testTransform(
        \\
        \\
        \\// hello
        \\
        \\
    ,
        \\// hello
        \\
    );
}

test "zig fmt: tuple struct" {
    try testCanonical(
        \\const T = struct {
        \\    /// doc comment on tuple field
        \\    comptime comptime u32,
        \\    /// another doc comment on tuple field
        \\    *u32 = 1,
        \\    // needs to be wrapped in parentheses to not be parsed as a function decl
        \\    (fn () void) align(1),
        \\};
        \\
    );
}

test "zig fmt: preserves clobbers in inline asm with stray comma" {
    try testCanonical(
        \\fn foo() void {
        \\    asm volatile (""
        \\        : [_] "" (-> type),
        \\        :
        \\        : "clobber"
        \\    );
        \\    asm volatile (""
        \\        :
        \\        : [_] "" (type),
        \\        : "clobber"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: remove trailing comma at the end of assembly clobber" {
    try testTransform(
        \\fn foo() void {
        \\    asm volatile (""
        \\        : [_] "" (-> type),
        \\        :
        \\        : "clobber1", "clobber2",
        \\    );
        \\}
        \\
    ,
        \\fn foo() void {
        \\    asm volatile (""
        \\        : [_] "" (-> type),
        \\        :
        \\        : "clobber1", "clobber2"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: respect line breaks in struct field value declaration" {
    try testCanonical(
        \\const Foo = struct {
        \\    bar: u32 =
        \\        42,
        \\    bar: u32 =
        \\        // a comment
        \\        42,
        \\    bar: u32 =
        \\        42,
        \\    // a comment
        \\    bar: []const u8 =
        \\        \\ foo
        \\        \\ bar
        \\        \\ baz
        \\    ,
        \\    bar: u32 =
        \\        blk: {
        \\            break :blk 42;
        \\        },
        \\};
        \\
    );
}

test "zig fmt: respect line breaks before functions" {
    try testCanonical(
        \\const std = @import("std");
        \\
        \\inline fn foo() void {}
        \\
        \\noinline fn foo() void {}
        \\
        \\export fn foo() void {}
        \\
        \\extern fn foo() void;
        \\
        \\extern "foo" fn foo() void;
        \\
    );
}

test "zig fmt: rewrite callconv(.@\"inline\") to the inline keyword" {
    try testTransform(
        \\fn foo() callconv(.@"inline") void {}
        \\const bar: @import("std").builtin.CallingConvention = .@"inline";
        \\fn foo() callconv(bar) void {}
        \\
    ,
        \\inline fn foo() void {}
        \\const bar: @import("std").builtin.CallingConvention = .@"inline";
        \\fn foo() callconv(bar) void {}
        \\
    );
}

test "zig fmt: simple top level comptime block" {
    try testCanonical(
        \\// line comment
        \\comptime {}
        \\
    );
}

test "zig fmt: two spaced line comments before decl" {
    try testCanonical(
        \\// line comment
        \\
        \\// another
        \\comptime {}
        \\
    );
}

test "zig fmt: respect line breaks after var declarations" {
    try testCanonical(
        \\const crc =
        \\    lookup_tables[0][p[7]] ^
        \\    lookup_tables[1][p[6]] ^
        \\    lookup_tables[2][p[5]] ^
        \\    lookup_tables[3][p[4]] ^
        \\    lookup_tables[4][@as(u8, self.crc >> 24)] ^
        \\    lookup_tables[5][@as(u8, self.crc >> 16)] ^
        \\    lookup_tables[6][@as(u8, self.crc >> 8)] ^
        \\    lookup_tables[7][@as(u8, self.crc >> 0)];
        \\
    );
}

test "zig fmt: multiline string mixed with comments" {
    try testCanonical(
        \\const s1 =
        \\    //\\one
        \\    \\two)
        \\    \\three
        \\;
        \\const s2 =
        \\    \\one
        \\    \\two)
        \\    //\\three
        \\;
        \\const s3 =
        \\    \\one
        \\    //\\two)
        \\    \\three
        \\;
        \\const s4 =
        \\    \\one
        \\    //\\two
        \\    \\three
        \\    //\\four
        \\    \\five
        \\;
        \\const a =
        \\    1;
        \\
    );
}

test "zig fmt: empty file" {
    try testCanonical(
        \\
    );
}

test "zig fmt: file ends in comment" {
    try testTransform(
        \\     //foobar
    ,
        \\//foobar
        \\
    );
}

test "zig fmt: file ends in multi line comment" {
    try testTransform(
        \\     \\foobar
    ,
        \\\\foobar
        \\
    );
}

test "zig fmt: file ends in comment after var decl" {
    try testTransform(
        \\const x = 42;
        \\     //foobar
    ,
        \\const x = 42;
        \\//foobar
        \\
    );
}

test "zig fmt: if statement" {
    try testCanonical(
        \\test "" {
        \\    if (optional()) |some|
        \\        bar = some.foo();
        \\}
        \\
    );
}

test "zig fmt: top-level fields" {
    try testCanonical(
        \\a: did_you_know,
        \\b: all_files_are,
        \\structs: ?x,
        \\
    );
}

test "zig fmt: top-level tuple function call type" {
    try testCanonical(
        \\foo()
        \\
    );
}

test "zig fmt: top-level enum missing 'const name ='" {
    try testError(
        \\enum(u32)
        \\
    , &[_]Error{.expected_token});
}

test "zig fmt: top-level for/while loop" {
    try testCanonical(
        \\for (foo) |_| foo
        \\
    );
    try testCanonical(
        \\while (foo) |_| foo
        \\
    );
}

test "zig fmt: top-level bare asterisk+identifier" {
    try testCanonical(
        \\*x
        \\
    );
}

test "zig fmt: top-level bare asterisk+asterisk+identifier" {
    try testCanonical(
        \\**x
        \\
    );
}

test "zig fmt: C style containers" {
    try testError(
        \\struct Foo {
        \\    a: u32,
        \\};
    , &[_]Error{
        .c_style_container,
        .zig_style_container,
    });
    try testError(
        \\test {
        \\    struct Foo {
        \\        a: u32,
        \\    };
        \\}
    , &[_]Error{
        .c_style_container,
        .zig_style_container,
    });
}

test "zig fmt: decl between fields" {
    try testError(
        \\const S = struct {
        \\    const foo = 2;
        \\    const bar = 2;
        \\    const baz = 2;
        \\    a: usize,
        \\    const foo1 = 2;
        \\    const bar1 = 2;
        \\    const baz1 = 2;
        \\    b: usize,
        \\};
    , &[_]Error{
        .decl_between_fields,
        .previous_field,
        .next_field,
    });
}

test "zig fmt: errdefer with payload" {
    try testCanonical(
        \\pub fn main() anyerror!void {
        \\    errdefer |a| x += 1;
        \\    errdefer |a| {}
        \\    errdefer |a| {
        \\        x += 1;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: nosuspend block" {
    try testCanonical(
        \\pub fn main() anyerror!void {
        \\    nosuspend {
        \\        var foo: Foo = .{ .bar = 42 };
        \\    }
        \\}
        \\
    );
}

test "zig fmt: nosuspend await" {
    try testCanonical(
        \\fn foo() void {
        \\    x = nosuspend await y;
        \\}
        \\
    );
}

test "zig fmt: container declaration, single line" {
    try testCanonical(
        \\const X = struct { foo: i32 };
        \\const X = struct { foo: i32, bar: i32 };
        \\const X = struct { foo: i32 = 1, bar: i32 = 2 };
        \\const X = struct { foo: i32 align(4), bar: i32 align(4) };
        \\const X = struct { foo: i32 align(4) = 1, bar: i32 align(4) = 2 };
        \\
    );
}

test "zig fmt: container declaration, one item, multi line trailing comma" {
    try testCanonical(
        \\test "" {
        \\    comptime {
        \\        const X = struct {
        \\            x: i32,
        \\        };
        \\    }
        \\}
        \\
    );
}

test "zig fmt: container declaration, no trailing comma on separate line" {
    try testTransform(
        \\test "" {
        \\    comptime {
        \\        const X = struct {
        \\            x: i32
        \\        };
        \\    }
        \\}
        \\
    ,
        \\test "" {
        \\    comptime {
        \\        const X = struct { x: i32 };
        \\    }
        \\}
        \\
    );
}

test "zig fmt: container declaration, line break, no trailing comma" {
    try testTransform(
        \\const X = struct {
        \\    foo: i32, bar: i8 };
    ,
        \\const X = struct { foo: i32, bar: i8 };
        \\
    );
}

test "zig fmt: container declaration, transform trailing comma" {
    try testTransform(
        \\const X = struct {
        \\    foo: i32, bar: i8, };
    ,
        \\const X = struct {
        \\    foo: i32,
        \\    bar: i8,
        \\};
        \\
    );
}

test "zig fmt: container declaration, comment, add trailing comma" {
    try testTransform(
        \\const X = struct {
        \\    foo: i32, // foo
        \\    bar: i8
        \\};
    ,
        \\const X = struct {
        \\    foo: i32, // foo
        \\    bar: i8,
        \\};
        \\
    );
    try testTransform(
        \\const X = struct {
        \\    foo: i32 // foo
        \\};
    ,
        \\const X = struct {
        \\    foo: i32, // foo
        \\};
        \\
    );
}

test "zig fmt: container declaration, multiline string, add trailing comma" {
    try testTransform(
        \\const X = struct {
        \\    foo: []const u8 =
        \\        \\ foo
        \\    ,
        \\    bar: i8
        \\};
    ,
        \\const X = struct {
        \\    foo: []const u8 =
        \\        \\ foo
        \\    ,
        \\    bar: i8,
        \\};
        \\
    );
}

test "zig fmt: container declaration, doc comment on member, add trailing comma" {
    try testTransform(
        \\pub const Pos = struct {
        \\    /// X-axis.
        \\    x: u32,
        \\    /// Y-axis.
        \\    y: u32
        \\};
    ,
        \\pub const Pos = struct {
        \\    /// X-axis.
        \\    x: u32,
        \\    /// Y-axis.
        \\    y: u32,
        \\};
        \\
    );
}

test "zig fmt: remove empty lines at start/end of container decl" {
    try testTransform(
        \\const X = struct {
        \\
        \\    foo: i32,
        \\
        \\    bar: i8,
        \\
        \\};
        \\
    ,
        \\const X = struct {
        \\    foo: i32,
        \\
        \\    bar: i8,
        \\};
        \\
    );
}

test "zig fmt: remove empty lines at start/end of block" {
    try testTransform(
        \\test {
        \\
        \\    if (foo) {
        \\        foo();
        \\    }
        \\
        \\}
        \\
    ,
        \\test {
        \\    if (foo) {
        \\        foo();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: allow empty line before comment at start of block" {
    try testCanonical(
        \\test {
        \\
        \\    // foo
        \\    const x = 42;
        \\}
        \\
    );
}

test "zig fmt: trailing comma in fn parameter list" {
    try testCanonical(
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) addrspace(.generic) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) linksection(".text") i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) callconv(.c) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) linksection(".text") i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) callconv(.c) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) align(8) linksection(".text") callconv(.c) i32 {}
        \\pub fn f(
        \\    a: i32,
        \\    b: i32,
        \\) linksection(".text") callconv(.c) i32 {}
        \\
    );
}

test "zig fmt: comptime struct field" {
    try testCanonical(
        \\const Foo = struct {
        \\    a: i32,
        \\    comptime b: i32 = 1234,
        \\};
        \\
    );
}

test "zig fmt: break from block" {
    try testCanonical(
        \\const a = blk: {
        \\    break :blk 42;
        \\};
        \\const b = blk: {
        \\    break :blk;
        \\};
        \\const c = {
        \\    break 42;
        \\};
        \\const d = {
        \\    break;
        \\};
        \\
    );
}

test "zig fmt: grouped expressions (parentheses)" {
    try testCanonical(
        \\const r = (x + y) * (a + b);
        \\
    );
}

test "zig fmt: c pointer type" {
    try testCanonical(
        \\pub extern fn repro() [*c]const u8;
        \\
    );
}

test "zig fmt: builtin call with trailing comma" {
    try testCanonical(
        \\pub fn main() void {
        \\    @breakpoint();
        \\    _ = @intFromBool(a);
        \\    _ = @call(
        \\        a,
        \\        b,
        \\        c,
        \\    );
        \\}
        \\
    );
}

test "zig fmt: asm expression with comptime content" {
    try testCanonical(
        \\comptime {
        \\    asm ("foo" ++ "bar");
        \\}
        \\pub fn main() void {
        \\    asm volatile ("foo" ++ "bar");
        \\    asm volatile ("foo" ++ "bar"
        \\        : [_] "" (x),
        \\    );
        \\    asm volatile ("foo" ++ "bar"
        \\        : [_] "" (x),
        \\        : [_] "" (y),
        \\    );
        \\    asm volatile ("foo" ++ "bar"
        \\        : [_] "" (x),
        \\        : [_] "" (y),
        \\        : "h", "e", "l", "l", "o"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: array types last token" {
    try testCanonical(
        \\test {
        \\    const x = [40]u32;
        \\}
        \\
        \\test {
        \\    const x = [40:0]u32;
        \\}
        \\
    );
}

test "zig fmt: sentinel-terminated array type" {
    try testCanonical(
        \\pub fn cStrToPrefixedFileW(s: [*:0]const u8) ![PATH_MAX_WIDE:0]u16 {
        \\    return sliceToPrefixedFileW(mem.toSliceConst(u8, s));
        \\}
        \\
    );
}

test "zig fmt: sentinel-terminated slice type" {
    try testCanonical(
        \\pub fn toSlice(self: Buffer) [:0]u8 {
        \\    return self.list.toSlice()[0..self.len()];
        \\}
        \\
    );
}

test "zig fmt: pointer-to-one with modifiers" {
    try testCanonical(
        \\const x: *u32 = undefined;
        \\const y: *allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const z: *allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: pointer-to-many with modifiers" {
    try testCanonical(
        \\const x: [*]u32 = undefined;
        \\const y: [*]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const z: [*]allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: sentinel pointer with modifiers" {
    try testCanonical(
        \\const x: [*:42]u32 = undefined;
        \\const y: [*:42]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const y: [*:42]allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: c pointer with modifiers" {
    try testCanonical(
        \\const x: [*c]u32 = undefined;
        \\const y: [*c]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\const z: [*c]allowzero align(8:4:2) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: slice with modifiers" {
    try testCanonical(
        \\const x: []u32 = undefined;
        \\const y: []allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: sentinel slice with modifiers" {
    try testCanonical(
        \\const x: [:42]u32 = undefined;
        \\const y: [:42]allowzero align(8) addrspace(.generic) const volatile u32 = undefined;
        \\
    );
}

test "zig fmt: anon literal in array" {
    try testCanonical(
        \\var arr: [2]Foo = .{
        \\    .{ .a = 2 },
        \\    .{ .b = 3 },
        \\};
        \\
    );
}

test "zig fmt: alignment in anonymous literal" {
    try testTransform(
        \\const a = .{
        \\    "U",     "L",     "F",
        \\    "U'",
        \\    "L'",
        \\    "F'",
        \\};
        \\
    ,
        \\const a = .{
        \\    "U",  "L",  "F",
        \\    "U'", "L'", "F'",
        \\};
        \\
    );
}

test "zig fmt: anon struct literal 0 element" {
    try testCanonical(
        \\test {
        \\    const x = .{};
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 1 element" {
    try testCanonical(
        \\test {
        \\    const x = .{ .a = b };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 1 element comma" {
    try testCanonical(
        \\test {
        \\    const x = .{
        \\        .a = b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 2 element" {
    try testCanonical(
        \\test {
        \\    const x = .{ .a = b, .c = d };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 2 element comma" {
    try testCanonical(
        \\test {
        \\    const x = .{
        \\        .a = b,
        \\        .c = d,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 3 element" {
    try testCanonical(
        \\test {
        \\    const x = .{ .a = b, .c = d, .e = f };
        \\}
        \\
    );
}

test "zig fmt: anon struct literal 3 element comma" {
    try testCanonical(
        \\test {
        \\    const x = .{
        \\        .a = b,
        \\        .c = d,
        \\        .e = f,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: struct literal 0 element" {
    try testCanonical(
        \\test {
        \\    const x = X{};
        \\}
        \\
    );
}

test "zig fmt: struct literal 1 element" {
    try testCanonical(
        \\test {
        \\    const x = X{ .a = b };
        \\}
        \\
    );
}

test "zig fmt: Unicode code point literal larger than u8" {
    try testCanonical(
        \\test {
        \\    const x = X{
        \\        .a = b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: struct literal 2 element" {
    try testCanonical(
        \\test {
        \\    const x = X{ .a = b, .c = d };
        \\}
        \\
    );
}

test "zig fmt: struct literal 2 element comma" {
    try testCanonical(
        \\test {
        \\    const x = X{
        \\        .a = b,
        \\        .c = d,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: struct literal 3 element" {
    try testCanonical(
        \\test {
        \\    const x = X{ .a = b, .c = d, .e = f };
        \\}
        \\
    );
}

test "zig fmt: struct literal 3 element comma" {
    try testCanonical(
        \\test {
        \\    const x = X{
        \\        .a = b,
        \\        .c = d,
        \\        .e = f,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 1 element" {
    try testCanonical(
        \\test {
        \\    const x = .{a};
        \\}
        \\
    );
}

test "zig fmt: anon list literal 1 element comma" {
    try testCanonical(
        \\test {
        \\    const x = .{
        \\        a,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 2 element" {
    try testCanonical(
        \\test {
        \\    const x = .{ a, b };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 2 element comma" {
    try testCanonical(
        \\test {
        \\    const x = .{
        \\        a,
        \\        b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 3 element" {
    try testCanonical(
        \\test {
        \\    const x = .{ a, b, c };
        \\}
        \\
    );
}

test "zig fmt: anon list literal 3 element comma" {
    try testCanonical(
        \\test {
        \\    const x = .{
        \\        a,
        \\        // foo
        \\        b,
        \\
        \\        c,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: array literal 0 element" {
    try testCanonical(
        \\test {
        \\    const x = [_]u32{};
        \\}
        \\
    );
}

test "zig fmt: array literal 1 element" {
    try testCanonical(
        \\test {
        \\    const x = [_]u32{a};
        \\}
        \\
    );
}

test "zig fmt: array literal 1 element comma" {
    try testCanonical(
        \\test {
        \\    const x = [1]u32{
        \\        a,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: array literal 2 element" {
    try testCanonical(
        \\test {
        \\    const x = [_]u32{ a, b };
        \\}
        \\
    );
}

test "zig fmt: array literal 2 element comma" {
    try testCanonical(
        \\test {
        \\    const x = [2]u32{
        \\        a,
        \\        b,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: array literal 3 element" {
    try testCanonical(
        \\test {
        \\    const x = [_]u32{ a, b, c };
        \\}
        \\
    );
}

test "zig fmt: array literal 3 element comma" {
    try testCanonical(
        \\test {
        \\    const x = [3]u32{
        \\        a,
        \\        b,
        \\        c,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: sentinel array literal 1 element" {
    try testCanonical(
        \\test {
        \\    const x = [_:9000]u32{a};
        \\}
        \\
    );
}

test "zig fmt: slices" {
    try testCanonical(
        \\const a = b[0..];
        \\const c = d[0..1];
        \\const d = f[0.. :0];
        \\const e = f[0..1 :0];
        \\
    );
}

test "zig fmt: slices with spaces in bounds" {
    try testCanonical(
        \\const a = b[0 + 0 ..];
        \\const c = d[0 + 0 .. 1];
        \\const c = d[0 + 0 .. :0];
        \\const e = f[0 .. 1 + 1 :0];
        \\
    );
}

test "zig fmt: block in slice expression" {
    try testCanonical(
        \\const a = b[{
        \\    _ = x;
        \\}..];
        \\const c = d[0..{
        \\    _ = x;
        \\    _ = y;
        \\}];
        \\const e = f[0..1 :{
        \\    _ = x;
        \\    _ = y;
        \\    _ = z;
        \\}];
        \\
    );
}

test "zig fmt: async function" {
    try testCanonical(
        \\pub const Server = struct {
        \\    handleRequestFn: fn (*Server, *const std.net.Address, File) callconv(.@"async") void,
        \\};
        \\test "hi" {
        \\    var ptr: fn (i32) callconv(.@"async") void = @ptrCast(other);
        \\}
        \\
    );
}

test "zig fmt: whitespace fixes" {
    try testTransform("test \"\" {\r\n\tconst hi = x;\r\n}\n// zig fmt: off\ntest \"\"{\r\n\tconst a  = b;}\r\n",
        \\test "" {
        \\    const hi = x;
        \\}
        \\// zig fmt: off
        \\test ""{
        \\    const a  = b;}
        \\
    );
}

test "zig fmt: while else err prong with no block" {
    try testCanonical(
        \\test "" {
        \\    const result = while (returnError()) |value| {
        \\        break value;
        \\    } else |err| @as(i32, 2);
        \\    try expect(result == 2);
        \\}
        \\
    );
}

test "zig fmt: tagged union with enum values" {
    try testCanonical(
        \\const MultipleChoice2 = union(enum(u32)) {
        \\    Unspecified1: i32,
        \\    A: f32 = 20,
        \\    Unspecified2: void,
        \\    B: bool = 40,
        \\    Unspecified3: i32,
        \\    C: i8 = 60,
        \\    Unspecified4: void,
        \\    D: void = 1000,
        \\    Unspecified5: i32,
        \\};
        \\
    );
}

test "zig fmt: tagged union enum tag last token" {
    try testCanonical(
        \\test {
        \\    const U = union(enum(u32)) {};
        \\}
        \\
        \\test {
        \\    const U = union(enum(u32)) { foo };
        \\}
        \\
        \\test {
        \\    const U = union(enum(u32)) {
        \\        foo,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: allowzero pointer" {
    try testCanonical(
        \\const T = [*]allowzero const u8;
        \\
    );
}

test "zig fmt: empty enum decls" {
    try testCanonical(
        \\const A = enum {};
        \\const B = enum(u32) {};
        \\const C = extern enum(c_int) {};
        \\const D = packed enum(u8) {};
        \\
    );
}

test "zig fmt: empty union decls" {
    try testCanonical(
        \\const A = union {};
        \\const B = union(enum) {};
        \\const C = union(Foo) {};
        \\const D = extern union {};
        \\const E = packed union {};
        \\
    );
}

test "zig fmt: enum literal" {
    try testCanonical(
        \\const x = .hi;
        \\
    );
}

test "zig fmt: enum literal inside array literal" {
    try testCanonical(
        \\test "enums in arrays" {
        \\    var colors = []Color{.Green};
        \\    colors = []Colors{ .Green, .Cyan };
        \\    colors = []Colors{
        \\        .Grey,
        \\        .Green,
        \\        .Cyan,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: character literal larger than u8" {
    try testCanonical(
        \\const x = '\u{01f4a9}';
        \\
    );
}

test "zig fmt: infix operator and then multiline string literal" {
    try testCanonical(
        \\const x = "" ++
        \\    \\ hi
        \\;
        \\
    );
}

test "zig fmt: infix operator and then multiline string literal over multiple lines" {
    try testCanonical(
        \\const x = "" ++
        \\    \\ hi0
        \\    \\ hi1
        \\    \\ hi2
        \\;
        \\
    );
}

test "zig fmt: C pointers" {
    try testCanonical(
        \\const Ptr = [*c]i32;
        \\
    );
}

test "zig fmt: threadlocal" {
    try testCanonical(
        \\threadlocal var x: i32 = 1234;
        \\
    );
}

test "zig fmt: linksection" {
    try testCanonical(
        \\export var aoeu: u64 linksection(".text.derp") = 1234;
        \\export fn _start() linksection(".text.boot") callconv(.naked) noreturn {}
        \\
    );
}

test "zig fmt: addrspace" {
    try testCanonical(
        \\export var python_length: u64 align(1) addrspace(.generic);
        \\export var python_color: Color addrspace(.generic) = .green;
        \\export var python_legs: u0 align(8) addrspace(.generic) linksection(".python") = 0;
        \\export fn python_hiss() align(8) addrspace(.generic) linksection(".python") void;
        \\
    );
}

test "zig fmt: correctly space struct fields with doc comments" {
    try testTransform(
        \\pub const S = struct {
        \\    /// A
        \\    a: u8,
        \\    /// B
        \\    /// B (cont)
        \\    b: u8,
        \\
        \\
        \\    /// C
        \\    c: u8,
        \\};
        \\
    ,
        \\pub const S = struct {
        \\    /// A
        \\    a: u8,
        \\    /// B
        \\    /// B (cont)
        \\    b: u8,
        \\
        \\    /// C
        \\    c: u8,
        \\};
        \\
    );
}

test "zig fmt: doc comments on param decl" {
    try testCanonical(
        \\pub const Allocator = struct {
        \\    shrinkFn: fn (
        \\        self: Allocator,
        \\        /// Guaranteed to be the same as what was returned from most recent call to
        \\        /// `allocFn`, `reallocFn`, or `shrinkFn`.
        \\        old_mem: []u8,
        \\        /// Guaranteed to be the same as what was returned from most recent call to
        \\        /// `allocFn`, `reallocFn`, or `shrinkFn`.
        \\        old_alignment: u29,
        \\        /// Guaranteed to be less than or equal to `old_mem.len`.
        \\        new_byte_count: usize,
        \\        /// Guaranteed to be less than or equal to `old_alignment`.
        \\        new_alignment: u29,
        \\    ) []u8,
        \\};
        \\
    );
}

test "zig fmt: aligned struct field" {
    try testCanonical(
        \\pub const S = struct {
        \\    f: i32 align(32),
        \\};
        \\
    );
    try testCanonical(
        \\pub const S = struct {
        \\    f: i32 align(32) = 1,
        \\};
        \\
    );
}

test "zig fmt: comment to disable/enable zig fmt first" {
    try testCanonical(
        \\// Test trailing comma syntax
        \\// zig fmt: off
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
    );
}

test "zig fmt: 'zig fmt: (off|on)' can be surrounded by arbitrary whitespace" {
    try testTransform(
        \\// Test trailing comma syntax
        \\//     zig fmt: off
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
        \\
        \\//   zig fmt: on
    ,
        \\// Test trailing comma syntax
        \\// zig fmt: off
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
        \\
        \\// zig fmt: on
        \\
    );
}

test "zig fmt: comment to disable/enable zig fmt" {
    try testTransform(
        \\const  a  =  b;
        \\// zig fmt: off
        \\const  c  =  d;
        \\// zig fmt: on
        \\const  e  =  f;
    ,
        \\const a = b;
        \\// zig fmt: off
        \\const  c  =  d;
        \\// zig fmt: on
        \\const e = f;
        \\
    );
}

test "zig fmt: line comment following 'zig fmt: off'" {
    try testCanonical(
        \\// zig fmt: off
        \\// Test
        \\const  e  =  f;
    );
}

test "zig fmt: doc comment following 'zig fmt: off'" {
    try testCanonical(
        \\// zig fmt: off
        \\/// test
        \\const  e  =  f;
    );
}

test "zig fmt: line and doc comment following 'zig fmt: off'" {
    try testCanonical(
        \\// zig fmt: off
        \\// test 1
        \\/// test 2
        \\const  e  =  f;
    );
}

test "zig fmt: doc and line comment following 'zig fmt: off'" {
    try testCanonical(
        \\// zig fmt: off
        \\/// test 1
        \\// test 2
        \\const  e  =  f;
    );
}

test "zig fmt: alternating 'zig fmt: off' and 'zig fmt: on'" {
    try testCanonical(
        \\// zig fmt: off
        \\// zig fmt: on
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: off
        \\// zig fmt: on
        \\// zig fmt: off
        \\const  a  =  b;
        \\// zig fmt: on
        \\const c = d;
        \\// zig fmt: on
        \\
    );
}

test "zig fmt: line comment following 'zig fmt: on'" {
    try testCanonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\// test
        \\const e = f;
        \\
    );
}

test "zig fmt: doc comment following 'zig fmt: on'" {
    try testCanonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\/// test
        \\const e = f;
        \\
    );
}

test "zig fmt: line and doc comment following 'zig fmt: on'" {
    try testCanonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\// test1
        \\/// test2
        \\const e = f;
        \\
    );
}

test "zig fmt: doc and line comment following 'zig fmt: on'" {
    try testCanonical(
        \\// zig fmt: off
        \\const  e  =  f;
        \\// zig fmt: on
        \\/// test1
        \\// test2
        \\const e = f;
        \\
    );
}

test "zig fmt: 'zig fmt: (off|on)' works in the middle of code" {
    try testTransform(
        \\test "" {
        \\    const x = 42;
        \\
        \\    if (foobar) |y| {
        \\    // zig fmt: off
        \\            }// zig fmt: on
        \\
        \\    const  z  = 420;
        \\}
        \\
    ,
        \\test "" {
        \\    const x = 42;
        \\
        \\    if (foobar) |y| {
        \\        // zig fmt: off
        \\            }// zig fmt: on
        \\
        \\    const z = 420;
        \\}
        \\
    );
}

test "zig fmt: 'zig fmt: on' indentation is unchanged" {
    try testCanonical(
        \\fn initOptionsAndLayouts(output: *Output, context: *Context) !void {
        \\    // zig fmt: off
        \\    try output.main_amount.init(output, "main_amount"); errdefer optput.main_amount.deinit();
        \\    try output.main_factor.init(output, "main_factor"); errdefer optput.main_factor.deinit();
        \\    try output.view_padding.init(output, "view_padding"); errdefer optput.view_padding.deinit();
        \\    try output.outer_padding.init(output, "outer_padding"); errdefer optput.outer_padding.deinit();
        \\    // zig fmt: on
        \\
        \\    // zig fmt: off
        \\    try output.top.init(output, .top); errdefer optput.top.deinit();
        \\    try output.right.init(output, .right); errdefer optput.right.deinit();
        \\    try output.bottom.init(output, .bottom); errdefer optput.bottom.deinit();
        \\    try output.left.init(output, .left); errdefer optput.left.deinit();
        \\        // zig fmt: on
        \\}
        \\
    );
}

test "zig fmt: pointer of unknown length" {
    try testCanonical(
        \\fn foo(ptr: [*]u8) void {}
        \\
    );
}

test "zig fmt: spaces around slice operator" {
    try testCanonical(
        \\var a = b[c..d];
        \\var a = b[c..d :0];
        \\var a = b[c + 1 .. d];
        \\var a = b[c + 1 ..];
        \\var a = b[c .. d + 1];
        \\var a = b[c .. d + 1 :0];
        \\var a = b[c.a..d.e];
        \\var a = b[c.a..d.e :0];
        \\
    );
}

test "zig fmt: async call in if condition" {
    try testCanonical(
        \\comptime {
        \\    if (async b()) {
        \\        a();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: 2nd arg multiline string" {
    try testCanonical(
        \\comptime {
        \\    cases.addAsm("hello world linux x86_64",
        \\        \\.text
        \\    , "Hello, world!\n");
        \\}
        \\
    );
    try testTransform(
        \\comptime {
        \\    cases.addAsm("hello world linux x86_64",
        \\        \\.text
        \\    , "Hello, world!\n",);
        \\}
    ,
        \\comptime {
        \\    cases.addAsm(
        \\        "hello world linux x86_64",
        \\        \\.text
        \\    ,
        \\        "Hello, world!\n",
        \\    );
        \\}
        \\
    );
}

test "zig fmt: 2nd arg multiline string many args" {
    try testCanonical(
        \\comptime {
        \\    cases.addAsm("hello world linux x86_64",
        \\        \\.text
        \\    , "Hello, world!\n", "Hello, world!\n");
        \\}
        \\
    );
}

test "zig fmt: final arg multiline string" {
    try testCanonical(
        \\comptime {
        \\    cases.addAsm("hello world linux x86_64", "Hello, world!\n",
        \\        \\.text
        \\    );
        \\}
        \\
    );
}

test "zig fmt: if condition wraps" {
    try testTransform(
        \\comptime {
        \\    if (cond and
        \\        cond) {
        \\        return x;
        \\    }
        \\    while (cond and
        \\        cond) {
        \\        return x;
        \\    }
        \\    if (a == b and
        \\        c) {
        \\        a = b;
        \\    }
        \\    while (a == b and
        \\        c) {
        \\        a = b;
        \\    }
        \\    if ((cond and
        \\        cond)) {
        \\        return x;
        \\    }
        \\    while ((cond and
        \\        cond)) {
        \\        return x;
        \\    }
        \\    var a = if (a) |*f| x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\    var a = if (cond and
        \\                cond) |*f|
        \\    x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\}
    ,
        \\comptime {
        \\    if (cond and
        \\        cond)
        \\    {
        \\        return x;
        \\    }
        \\    while (cond and
        \\        cond)
        \\    {
        \\        return x;
        \\    }
        \\    if (a == b and
        \\        c)
        \\    {
        \\        a = b;
        \\    }
        \\    while (a == b and
        \\        c)
        \\    {
        \\        a = b;
        \\    }
        \\    if ((cond and
        \\        cond))
        \\    {
        \\        return x;
        \\    }
        \\    while ((cond and
        \\        cond))
        \\    {
        \\        return x;
        \\    }
        \\    var a = if (a) |*f| x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\    var a = if (cond and
        \\        cond) |*f|
        \\    x: {
        \\        break :x &a.b;
        \\    } else |err| err;
        \\}
        \\
    );
}

test "zig fmt: if condition has line break but must not wrap" {
    try testCanonical(
        \\comptime {
        \\    if (self.user_input_options.put(
        \\        name,
        \\        UserInputOption{
        \\            .name = name,
        \\            .used = false,
        \\        },
        \\    ) catch unreachable) |*prev_value| {
        \\        foo();
        \\        bar();
        \\    }
        \\    if (put(
        \\        a,
        \\        b,
        \\    )) {
        \\        foo();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: if condition has line break but must not wrap (no fn call comma)" {
    try testCanonical(
        \\comptime {
        \\    if (self.user_input_options.put(name, UserInputOption{
        \\        .name = name,
        \\        .used = false,
        \\    }) catch unreachable) |*prev_value| {
        \\        foo();
        \\        bar();
        \\    }
        \\    if (put(
        \\        a,
        \\        b,
        \\    )) {
        \\        foo();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: function call with multiline argument" {
    try testCanonical(
        \\comptime {
        \\    self.user_input_options.put(name, UserInputOption{
        \\        .name = name,
        \\        .used = false,
        \\    });
        \\}
        \\
    );
}

test "zig fmt: if-else with comment before else" {
    try testCanonical(
        \\comptime {
        \\    // cexp(finite|nan +- i inf|nan) = nan + i nan
        \\    if ((hx & 0x7fffffff) != 0x7f800000) {
        \\        return Complex(f32).init(y - y, y - y);
        \\    } // cexp(-inf +- i inf|nan) = 0 + i0
        \\    else if (hx & 0x80000000 != 0) {
        \\        return Complex(f32).init(0, 0);
        \\    } // cexp(+inf +- i inf|nan) = inf + i nan
        \\    else {
        \\        return Complex(f32).init(x, y - y);
        \\    }
        \\}
        \\
    );
}

test "zig fmt: if nested" {
    try testCanonical(
        \\pub fn foo() void {
        \\    return if ((aInt & bInt) >= 0)
        \\        if (aInt < bInt)
        \\            GE_LESS
        \\        else if (aInt == bInt)
        \\            GE_EQUAL
        \\        else
        \\            GE_GREATER
        \\            // comment
        \\    else if (aInt > bInt)
        \\        GE_LESS
        \\    else if (aInt == bInt)
        \\        GE_EQUAL
        \\    else
        \\        GE_GREATER;
        \\    // comment
        \\}
        \\
    );
}

test "zig fmt: respect line breaks in if-else" {
    try testCanonical(
        \\comptime {
        \\    return if (cond) a else b;
        \\    return if (cond)
        \\        a
        \\    else
        \\        b;
        \\    return if (cond)
        \\        a
        \\    else if (cond)
        \\        b
        \\    else
        \\        c;
        \\}
        \\
    );
}

test "zig fmt: respect line breaks after infix operators" {
    try testCanonical(
        \\comptime {
        \\    self.crc =
        \\        lookup_tables[0][p[7]] ^
        \\        lookup_tables[1][p[6]] ^
        \\        lookup_tables[2][p[5]] ^
        \\        lookup_tables[3][p[4]] ^
        \\        lookup_tables[4][@as(u8, self.crc >> 24)] ^
        \\        lookup_tables[5][@as(u8, self.crc >> 16)] ^
        \\        lookup_tables[6][@as(u8, self.crc >> 8)] ^
        \\        lookup_tables[7][@as(u8, self.crc >> 0)];
        \\}
        \\
    );
}

test "zig fmt: fn decl with trailing comma" {
    try testTransform(
        \\fn foo(a: i32, b: i32,) void {}
    ,
        \\fn foo(
        \\    a: i32,
        \\    b: i32,
        \\) void {}
        \\
    );
}

test "zig fmt: enum decl with no trailing comma" {
    try testTransform(
        \\const StrLitKind = enum {Normal, C};
    ,
        \\const StrLitKind = enum { Normal, C };
        \\
    );
}

test "zig fmt: switch comment before prong" {
    try testCanonical(
        \\comptime {
        \\    switch (a) {
        \\        // hi
        \\        0 => {},
        \\    }
        \\}
        \\
    );
}

test "zig fmt: switch comment after prong" {
    try testCanonical(
        \\comptime {
        \\    switch (a) {
        \\        0,
        \\        // hi
        \\        => {},
        \\    }
        \\}
        \\
    );
}

test "zig fmt: struct literal no trailing comma" {
    try testTransform(
        \\const a = foo{ .x = 1, .y = 2 };
        \\const a = foo{ .x = 1,
        \\    .y = 2 };
        \\const a = foo{ .x = 1,
        \\    .y = 2, };
    ,
        \\const a = foo{ .x = 1, .y = 2 };
        \\const a = foo{ .x = 1, .y = 2 };
        \\const a = foo{
        \\    .x = 1,
        \\    .y = 2,
        \\};
        \\
    );
}

test "zig fmt: struct literal containing a multiline expression" {
    try testTransform(
        \\const a = A{ .x = if (f1()) 10 else 20 };
        \\const a = A{ .x = if (f1()) 10 else 20, };
        \\const a = A{ .x = if (f1())
        \\    10 else 20 };
        \\const a = A{ .x = if (f1())
        \\    10 else 20,};
        \\const a = A{ .x = if (f1()) 10 else 20, .y = f2() + 100 };
        \\const a = A{ .x = if (f1()) 10 else 20, .y = f2() + 100, };
        \\const a = A{ .x = if (f1())
        \\    10 else 20};
        \\const a = A{ .x = if (f1())
        \\    10 else 20,};
        \\const a = A{ .x = switch(g) {0 => "ok", else => "no"} };
        \\const a = A{ .x = switch(g) {0 => "ok", else => "no"}, };
        \\
    ,
        \\const a = A{ .x = if (f1()) 10 else 20 };
        \\const a = A{
        \\    .x = if (f1()) 10 else 20,
        \\};
        \\const a = A{ .x = if (f1())
        \\    10
        \\else
        \\    20 };
        \\const a = A{
        \\    .x = if (f1())
        \\        10
        \\    else
        \\        20,
        \\};
        \\const a = A{ .x = if (f1()) 10 else 20, .y = f2() + 100 };
        \\const a = A{
        \\    .x = if (f1()) 10 else 20,
        \\    .y = f2() + 100,
        \\};
        \\const a = A{ .x = if (f1())
        \\    10
        \\else
        \\    20 };
        \\const a = A{
        \\    .x = if (f1())
        \\        10
        \\    else
        \\        20,
        \\};
        \\const a = A{ .x = switch (g) {
        \\    0 => "ok",
        \\    else => "no",
        \\} };
        \\const a = A{
        \\    .x = switch (g) {
        \\        0 => "ok",
        \\        else => "no",
        \\    },
        \\};
        \\
    );
}

test "zig fmt: array literal with hint" {
    try testTransform(
        \\const a = []u8{
        \\    1, 2, //
        \\    3,
        \\    4,
        \\    5,
        \\    6,
        \\    7 };
        \\const a = []u8{
        \\    1, 2, //
        \\    3,
        \\    4,
        \\    5,
        \\    6,
        \\    7, 8 };
        \\const a = []u8{
        \\    1, 2, //
        \\    3,
        \\    4,
        \\    5,
        \\    6, // blah
        \\    7, 8 };
        \\const a = []u8{
        \\    1, 2, //
        \\    3, //
        \\    4,
        \\    5,
        \\    6,
        \\    7 };
        \\const a = []u8{
        \\    1,
        \\    2,
        \\    3, 4, //
        \\    5, 6, //
        \\    7, 8, //
        \\};
    ,
        \\const a = []u8{
        \\    1, 2, //
        \\    3, 4,
        \\    5, 6,
        \\    7,
        \\};
        \\const a = []u8{
        \\    1, 2, //
        \\    3, 4,
        \\    5, 6,
        \\    7, 8,
        \\};
        \\const a = []u8{
        \\    1, 2, //
        \\    3, 4,
        \\    5,
        \\    6, // blah
        \\    7,
        \\    8,
        \\};
        \\const a = []u8{
        \\    1, 2, //
        \\    3, //
        \\    4,
        \\    5,
        \\    6,
        \\    7,
        \\};
        \\const a = []u8{
        \\    1,
        \\    2,
        \\    3, 4, //
        \\    5, 6, //
        \\    7, 8, //
        \\};
        \\
    );
}

test "zig fmt: array literal vertical column alignment" {
    try testTransform(
        \\const a = []u8{
        \\    1000, 200,
        \\    30, 4,
        \\    50000, 60,
        \\};
        \\const a = []u8{0,   1, 2, 3, 40,
        \\    4,5,600,7,
        \\           80,
        \\    9, 10, 11, 0, 13, 14, 15,};
        \\const a = [12]u8{
        \\    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        \\const a = [12]u8{
        \\    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, };
        \\
    ,
        \\const a = []u8{
        \\    1000,```
