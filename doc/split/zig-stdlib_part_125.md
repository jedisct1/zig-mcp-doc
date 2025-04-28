```
nit_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        .@"switch",
        .switch_comma,
        .@"for",
        .for_simple,
        .@"suspend",
        .@"continue",
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        .fn_decl,
        .anyframe_type,
        .anyframe_literal,
        .error_set_decl,
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .@"comptime",
        .@"nosuspend",
        .error_value,
        => return astgen.failNode(node, "invalid left-hand side to assignment", .{}),

        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            const builtin_token = tree.nodeMainToken(node);
            const builtin_name = tree.tokenSlice(builtin_token);
            // If the builtin is an invalid name, we don't cause an error here; instead
            // let it pass, and the error will be "invalid builtin function" later.
            if (BuiltinFn.list.get(builtin_name)) |info| {
                if (!info.allows_lvalue) {
                    return astgen.failNode(node, "invalid left-hand side to assignment", .{});
                }
            }
        },

        // These can be assigned to.
        .unwrap_optional,
        .deref,
        .field_access,
        .array_access,
        .identifier,
        .grouped_expression,
        .@"orelse",
        => {},
    }
    return expr(gz, scope, .{ .rl = .ref }, node);
}

/// Turn Zig AST into untyped ZIR instructions.
/// When `rl` is discard, ptr, inferred_ptr, or inferred_ptr, the
/// result instruction can be used to inspect whether it is isNoReturn() but that is it,
/// it must otherwise not be used.
fn expr(gz: *GenZir, scope: *Scope, ri: ResultInfo, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const prev_anon_name_strategy = gz.anon_name_strategy;
    defer gz.anon_name_strategy = prev_anon_name_strategy;
    if (!nodeUsesAnonNameStrategy(tree, node)) {
        gz.anon_name_strategy = .anon;
    }

    switch (tree.nodeTag(node)) {
        .root => unreachable, // Top-level declaration.
        .@"usingnamespace" => unreachable, // Top-level declaration.
        .test_decl => unreachable, // Top-level declaration.
        .container_field_init => unreachable, // Top-level declaration.
        .container_field_align => unreachable, // Top-level declaration.
        .container_field => unreachable, // Top-level declaration.
        .fn_decl => unreachable, // Top-level declaration.

        .global_var_decl => unreachable, // Handled in `blockExpr`.
        .local_var_decl => unreachable, // Handled in `blockExpr`.
        .simple_var_decl => unreachable, // Handled in `blockExpr`.
        .aligned_var_decl => unreachable, // Handled in `blockExpr`.
        .@"defer" => unreachable, // Handled in `blockExpr`.
        .@"errdefer" => unreachable, // Handled in `blockExpr`.

        .switch_case => unreachable, // Handled in `switchExpr`.
        .switch_case_inline => unreachable, // Handled in `switchExpr`.
        .switch_case_one => unreachable, // Handled in `switchExpr`.
        .switch_case_inline_one => unreachable, // Handled in `switchExpr`.
        .switch_range => unreachable, // Handled in `switchExpr`.

        .asm_output => unreachable, // Handled in `asmExpr`.
        .asm_input => unreachable, // Handled in `asmExpr`.

        .for_range => unreachable, // Handled in `forExpr`.

        .assign => {
            try assign(gz, scope, node);
            return rvalue(gz, ri, .void_value, node);
        },

        .assign_destructure => {
            // Note that this variant does not declare any new var/const: that
            // variant is handled by `blockExprStmts`.
            try assignDestructure(gz, scope, node);
            return rvalue(gz, ri, .void_value, node);
        },

        .assign_shl => {
            try assignShift(gz, scope, node, .shl);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_shl_sat => {
            try assignShiftSat(gz, scope, node);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_shr => {
            try assignShift(gz, scope, node, .shr);
            return rvalue(gz, ri, .void_value, node);
        },

        .assign_bit_and => {
            try assignOp(gz, scope, node, .bit_and);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_bit_or => {
            try assignOp(gz, scope, node, .bit_or);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_bit_xor => {
            try assignOp(gz, scope, node, .xor);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_div => {
            try assignOp(gz, scope, node, .div);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_sub => {
            try assignOp(gz, scope, node, .sub);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_sub_wrap => {
            try assignOp(gz, scope, node, .subwrap);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_sub_sat => {
            try assignOp(gz, scope, node, .sub_sat);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mod => {
            try assignOp(gz, scope, node, .mod_rem);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_add => {
            try assignOp(gz, scope, node, .add);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_add_wrap => {
            try assignOp(gz, scope, node, .addwrap);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_add_sat => {
            try assignOp(gz, scope, node, .add_sat);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mul => {
            try assignOp(gz, scope, node, .mul);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mul_wrap => {
            try assignOp(gz, scope, node, .mulwrap);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mul_sat => {
            try assignOp(gz, scope, node, .mul_sat);
            return rvalue(gz, ri, .void_value, node);
        },

        // zig fmt: off
        .shl => return shiftOp(gz, scope, ri, node, tree.nodeData(node).node_and_node[0], tree.nodeData(node).node_and_node[1], .shl),
        .shr => return shiftOp(gz, scope, ri, node, tree.nodeData(node).node_and_node[0], tree.nodeData(node).node_and_node[1], .shr),

        .add      => return simpleBinOp(gz, scope, ri, node, .add),
        .add_wrap => return simpleBinOp(gz, scope, ri, node, .addwrap),
        .add_sat  => return simpleBinOp(gz, scope, ri, node, .add_sat),
        .sub      => return simpleBinOp(gz, scope, ri, node, .sub),
        .sub_wrap => return simpleBinOp(gz, scope, ri, node, .subwrap),
        .sub_sat  => return simpleBinOp(gz, scope, ri, node, .sub_sat),
        .mul      => return simpleBinOp(gz, scope, ri, node, .mul),
        .mul_wrap => return simpleBinOp(gz, scope, ri, node, .mulwrap),
        .mul_sat  => return simpleBinOp(gz, scope, ri, node, .mul_sat),
        .div      => return simpleBinOp(gz, scope, ri, node, .div),
        .mod      => return simpleBinOp(gz, scope, ri, node, .mod_rem),
        .shl_sat  => return simpleBinOp(gz, scope, ri, node, .shl_sat),

        .bit_and          => return simpleBinOp(gz, scope, ri, node, .bit_and),
        .bit_or           => return simpleBinOp(gz, scope, ri, node, .bit_or),
        .bit_xor          => return simpleBinOp(gz, scope, ri, node, .xor),
        .bang_equal       => return simpleBinOp(gz, scope, ri, node, .cmp_neq),
        .equal_equal      => return simpleBinOp(gz, scope, ri, node, .cmp_eq),
        .greater_than     => return simpleBinOp(gz, scope, ri, node, .cmp_gt),
        .greater_or_equal => return simpleBinOp(gz, scope, ri, node, .cmp_gte),
        .less_than        => return simpleBinOp(gz, scope, ri, node, .cmp_lt),
        .less_or_equal    => return simpleBinOp(gz, scope, ri, node, .cmp_lte),
        .array_cat        => return simpleBinOp(gz, scope, ri, node, .array_cat),

        .array_mult => {
            // This syntax form does not currently use the result type in the language specification.
            // However, the result type can be used to emit more optimal code for large multiplications by
            // having Sema perform a coercion before the multiplication operation.
            const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;
            const result = try gz.addPlNode(.array_mul, node, Zir.Inst.ArrayMul{
                .res_ty = if (try ri.rl.resultType(gz, node)) |t| t else .none,
                .lhs = try expr(gz, scope, .{ .rl = .none }, lhs_node),
                .rhs = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, rhs_node, .array_mul_factor),
            });
            return rvalue(gz, ri, result, node);
        },

        .error_union, .merge_error_sets => |tag| {
            const inst_tag: Zir.Inst.Tag = switch (tag) {
                .error_union => .error_union_type,
                .merge_error_sets => .merge_error_sets,
                else => unreachable,
            };
            const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;
            const lhs = try reachableTypeExpr(gz, scope, lhs_node, node);
            const rhs = try reachableTypeExpr(gz, scope, rhs_node, node);
            const result = try gz.addPlNode(inst_tag, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs });
            return rvalue(gz, ri, result, node);
        },

        .bool_and => return boolBinOp(gz, scope, ri, node, .bool_br_and),
        .bool_or  => return boolBinOp(gz, scope, ri, node, .bool_br_or),

        .bool_not => return simpleUnOp(gz, scope, ri, node, coerced_bool_ri, tree.nodeData(node).node, .bool_not),
        .bit_not  => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none }, tree.nodeData(node).node, .bit_not),

        .negation      => return   negation(gz, scope, ri, node),
        .negation_wrap => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none }, tree.nodeData(node).node, .negate_wrap),

        .identifier => return identifier(gz, scope, ri, node, null),

        .asm_simple,
        .@"asm",
        => return asmExpr(gz, scope, ri, node, tree.fullAsm(node).?),

        .string_literal           => return stringLiteral(gz, ri, node),
        .multiline_string_literal => return multilineStringLiteral(gz, ri, node),

        .number_literal => return numberLiteral(gz, ri, node, node, .positive),
        // zig fmt: on

        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const params = tree.builtinCallParams(&buf, node).?;
            return builtinCall(gz, scope, ri, node, params, false);
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
            return callExpr(gz, scope, ri, .none, node, tree.fullCall(&buf, node).?);
        },

        .unreachable_literal => {
            try emitDbgNode(gz, node);
            _ = try gz.addAsIndex(.{
                .tag = .@"unreachable",
                .data = .{ .@"unreachable" = .{
                    .src_node = gz.nodeIndexToRelative(node),
                } },
            });
            return Zir.Inst.Ref.unreachable_value;
        },
        .@"return" => return ret(gz, scope, node),
        .field_access => return fieldAccess(gz, scope, ri, node),

        .if_simple,
        .@"if",
        => {
            const if_full = tree.fullIf(node).?;
            no_switch_on_err: {
                const error_token = if_full.error_token orelse break :no_switch_on_err;
                const else_node = if_full.ast.else_expr.unwrap() orelse break :no_switch_on_err;
                const full_switch = tree.fullSwitch(else_node) orelse break :no_switch_on_err;
                if (full_switch.label_token != null) break :no_switch_on_err;
                if (tree.nodeTag(full_switch.ast.condition) != .identifier) break :no_switch_on_err;
                if (!mem.eql(u8, tree.tokenSlice(error_token), tree.tokenSlice(tree.nodeMainToken(full_switch.ast.condition)))) break :no_switch_on_err;
                return switchExprErrUnion(gz, scope, ri.br(), node, .@"if");
            }
            return ifExpr(gz, scope, ri.br(), node, if_full);
        },

        .while_simple,
        .while_cont,
        .@"while",
        => return whileExpr(gz, scope, ri.br(), node, tree.fullWhile(node).?, false),

        .for_simple, .@"for" => return forExpr(gz, scope, ri.br(), node, tree.fullFor(node).?, false),

        .slice_open,
        .slice,
        .slice_sentinel,
        => {
            const full = tree.fullSlice(node).?;
            if (full.ast.end != .none and
                tree.nodeTag(full.ast.sliced) == .slice_open and
                nodeIsTriviallyZero(tree, full.ast.start))
            {
                const lhs_extra = tree.sliceOpen(full.ast.sliced).ast;

                const lhs = try expr(gz, scope, .{ .rl = .ref }, lhs_extra.sliced);
                const start = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, lhs_extra.start);
                const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
                const len = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, full.ast.end.unwrap().?);
                const sentinel = if (full.ast.sentinel.unwrap()) |sentinel| try expr(gz, scope, .{ .rl = .none }, sentinel) else .none;
                try emitDbgStmt(gz, cursor);
                const result = try gz.addPlNode(.slice_length, node, Zir.Inst.SliceLength{
                    .lhs = lhs,
                    .start = start,
                    .len = len,
                    .start_src_node_offset = gz.nodeIndexToRelative(full.ast.sliced),
                    .sentinel = sentinel,
                });
                return rvalue(gz, ri, result, node);
            }
            const lhs = try expr(gz, scope, .{ .rl = .ref }, full.ast.sliced);

            const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
            const start = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, full.ast.start);
            const end = if (full.ast.end.unwrap()) |end| try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, end) else .none;
            const sentinel = if (full.ast.sentinel.unwrap()) |sentinel| s: {
                const sentinel_ty = try gz.addUnNode(.slice_sentinel_ty, lhs, node);
                break :s try expr(gz, scope, .{ .rl = .{ .coerced_ty = sentinel_ty } }, sentinel);
            } else .none;
            try emitDbgStmt(gz, cursor);
            if (sentinel != .none) {
                const result = try gz.addPlNode(.slice_sentinel, node, Zir.Inst.SliceSentinel{
                    .lhs = lhs,
                    .start = start,
                    .end = end,
                    .sentinel = sentinel,
                });
                return rvalue(gz, ri, result, node);
            } else if (end != .none) {
                const result = try gz.addPlNode(.slice_end, node, Zir.Inst.SliceEnd{
                    .lhs = lhs,
                    .start = start,
                    .end = end,
                });
                return rvalue(gz, ri, result, node);
            } else {
                const result = try gz.addPlNode(.slice_start, node, Zir.Inst.SliceStart{
                    .lhs = lhs,
                    .start = start,
                });
                return rvalue(gz, ri, result, node);
            }
        },

        .deref => {
            const lhs = try expr(gz, scope, .{ .rl = .none }, tree.nodeData(node).node);
            _ = try gz.addUnNode(.validate_deref, lhs, node);
            switch (ri.rl) {
                .ref, .ref_coerced_ty => return lhs,
                else => {
                    const result = try gz.addUnNode(.load, lhs, node);
                    return rvalue(gz, ri, result, node);
                },
            }
        },
        .address_of => {
            const operand_rl: ResultInfo.Loc = if (try ri.rl.resultType(gz, node)) |res_ty_inst| rl: {
                _ = try gz.addUnTok(.validate_ref_ty, res_ty_inst, tree.firstToken(node));
                break :rl .{ .ref_coerced_ty = res_ty_inst };
            } else .ref;
            const result = try expr(gz, scope, .{ .rl = operand_rl }, tree.nodeData(node).node);
            return rvalue(gz, ri, result, node);
        },
        .optional_type => {
            const operand = try typeExpr(gz, scope, tree.nodeData(node).node);
            const result = try gz.addUnNode(.optional_type, operand, node);
            return rvalue(gz, ri, result, node);
        },
        .unwrap_optional => switch (ri.rl) {
            .ref, .ref_coerced_ty => {
                const lhs = try expr(gz, scope, .{ .rl = .ref }, tree.nodeData(node).node_and_token[0]);

                const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
                try emitDbgStmt(gz, cursor);

                return gz.addUnNode(.optional_payload_safe_ptr, lhs, node);
            },
            else => {
                const lhs = try expr(gz, scope, .{ .rl = .none }, tree.nodeData(node).node_and_token[0]);

                const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
                try emitDbgStmt(gz, cursor);

                return rvalue(gz, ri, try gz.addUnNode(.optional_payload_safe, lhs, node), node);
            },
        },
        .block_two,
        .block_two_semicolon,
        .block,
        .block_semicolon,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const statements = tree.blockStatements(&buf, node).?;
            return blockExpr(gz, scope, ri, node, statements, .normal);
        },
        .enum_literal => if (try ri.rl.resultType(gz, node)) |res_ty| {
            const str_index = try astgen.identAsString(tree.nodeMainToken(node));
            const res = try gz.addPlNode(.decl_literal, node, Zir.Inst.Field{
                .lhs = res_ty,
                .field_name_start = str_index,
            });
            switch (ri.rl) {
                .discard, .none, .ref => unreachable, // no result type
                .ty, .coerced_ty => return res, // `decl_literal` does the coercion for us
                .ref_coerced_ty, .ptr, .inferred_ptr, .destructure => return rvalue(gz, ri, res, node),
            }
        } else return simpleStrTok(gz, ri, tree.nodeMainToken(node), node, .enum_literal),
        .error_value => return simpleStrTok(gz, ri, tree.nodeMainToken(node) + 2, node, .error_value),
        // TODO restore this when implementing https://github.com/ziglang/zig/issues/6025
        // .anyframe_literal => return rvalue(gz, ri, .anyframe_type, node),
        .anyframe_literal => {
            const result = try gz.addUnNode(.anyframe_type, .void_type, node);
            return rvalue(gz, ri, result, node);
        },
        .anyframe_type => {
            const return_type = try typeExpr(gz, scope, tree.nodeData(node).token_and_node[1]);
            const result = try gz.addUnNode(.anyframe_type, return_type, node);
            return rvalue(gz, ri, result, node);
        },
        .@"catch" => {
            const catch_token = tree.nodeMainToken(node);
            const payload_token: ?Ast.TokenIndex = if (tree.tokenTag(catch_token + 1) == .pipe)
                catch_token + 2
            else
                null;
            no_switch_on_err: {
                const capture_token = payload_token orelse break :no_switch_on_err;
                const full_switch = tree.fullSwitch(tree.nodeData(node).node_and_node[1]) orelse break :no_switch_on_err;
                if (full_switch.label_token != null) break :no_switch_on_err;
                if (tree.nodeTag(full_switch.ast.condition) != .identifier) break :no_switch_on_err;
                if (!mem.eql(u8, tree.tokenSlice(capture_token), tree.tokenSlice(tree.nodeMainToken(full_switch.ast.condition)))) break :no_switch_on_err;
                return switchExprErrUnion(gz, scope, ri.br(), node, .@"catch");
            }
            switch (ri.rl) {
                .ref, .ref_coerced_ty => return orelseCatchExpr(
                    gz,
                    scope,
                    ri,
                    node,
                    .is_non_err_ptr,
                    .err_union_payload_unsafe_ptr,
                    .err_union_code_ptr,
                    payload_token,
                ),
                else => return orelseCatchExpr(
                    gz,
                    scope,
                    ri,
                    node,
                    .is_non_err,
                    .err_union_payload_unsafe,
                    .err_union_code,
                    payload_token,
                ),
            }
        },
        .@"orelse" => switch (ri.rl) {
            .ref, .ref_coerced_ty => return orelseCatchExpr(
                gz,
                scope,
                ri,
                node,
                .is_non_null_ptr,
                .optional_payload_unsafe_ptr,
                undefined,
                null,
            ),
            else => return orelseCatchExpr(
                gz,
                scope,
                ri,
                node,
                .is_non_null,
                .optional_payload_unsafe,
                undefined,
                null,
            ),
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => return ptrType(gz, scope, ri, node, tree.fullPtrType(node).?),

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
            return containerDecl(gz, scope, ri, node, tree.fullContainerDecl(&buf, node).?);
        },

        .@"break" => return breakExpr(gz, scope, node),
        .@"continue" => return continueExpr(gz, scope, node),
        .grouped_expression => return expr(gz, scope, ri, tree.nodeData(node).node_and_token[0]),
        .array_type => return arrayType(gz, scope, ri, node),
        .array_type_sentinel => return arrayTypeSentinel(gz, scope, ri, node),
        .char_literal => return charLiteral(gz, ri, node),
        .error_set_decl => return errorSetDecl(gz, ri, node),
        .array_access => return arrayAccess(gz, scope, ri, node),
        .@"comptime" => return comptimeExprAst(gz, scope, ri, node),
        .@"switch", .switch_comma => return switchExpr(gz, scope, ri.br(), node, tree.fullSwitch(node).?),

        .@"nosuspend" => return nosuspendExpr(gz, scope, ri, node),
        .@"suspend" => return suspendExpr(gz, scope, node),
        .@"await" => return awaitExpr(gz, scope, ri, node),
        .@"resume" => return resumeExpr(gz, scope, ri, node),

        .@"try" => return tryExpr(gz, scope, ri, node, tree.nodeData(node).node),

        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            return arrayInitExpr(gz, scope, ri, node, tree.fullArrayInit(&buf, node).?);
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
            return structInitExpr(gz, scope, ri, node, tree.fullStructInit(&buf, node).?);
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            return fnProtoExpr(gz, scope, ri, node, tree.fullFnProto(&buf, node).?);
        },
    }
}

fn nosuspendExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const body_node = tree.nodeData(node).node;
    if (gz.nosuspend_node.unwrap()) |nosuspend_node| {
        try astgen.appendErrorNodeNotes(node, "redundant nosuspend block", .{}, &[_]u32{
            try astgen.errNoteNode(nosuspend_node, "other nosuspend block here", .{}),
        });
    }
    gz.nosuspend_node = node.toOptional();
    defer gz.nosuspend_node = .none;
    return expr(gz, scope, ri, body_node);
}

fn suspendExpr(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const body_node = tree.nodeData(node).node;

    if (gz.nosuspend_node.unwrap()) |nosuspend_node| {
        return astgen.failNodeNotes(node, "suspend inside nosuspend block", .{}, &[_]u32{
            try astgen.errNoteNode(nosuspend_node, "nosuspend block here", .{}),
        });
    }
    if (gz.suspend_node.unwrap()) |suspend_node| {
        return astgen.failNodeNotes(node, "cannot suspend inside suspend block", .{}, &[_]u32{
            try astgen.errNoteNode(suspend_node, "other suspend block here", .{}),
        });
    }

    const suspend_inst = try gz.makeBlockInst(.suspend_block, node);
    try gz.instructions.append(gpa, suspend_inst);

    var suspend_scope = gz.makeSubBlock(scope);
    suspend_scope.suspend_node = node.toOptional();
    defer suspend_scope.unstack();

    const body_result = try fullBodyExpr(&suspend_scope, &suspend_scope.base, .{ .rl = .none }, body_node, .normal);
    if (!gz.refIsNoReturn(body_result)) {
        _ = try suspend_scope.addBreak(.break_inline, suspend_inst, .void_value);
    }
    try suspend_scope.setBlockBody(suspend_inst);

    return suspend_inst.toRef();
}

fn awaitExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const rhs_node = tree.nodeData(node).node;

    if (gz.suspend_node.unwrap()) |suspend_node| {
        return astgen.failNodeNotes(node, "cannot await inside suspend block", .{}, &[_]u32{
            try astgen.errNoteNode(suspend_node, "suspend block here", .{}),
        });
    }
    const operand = try expr(gz, scope, .{ .rl = .ref }, rhs_node);
    const result = if (gz.nosuspend_node != .none)
        try gz.addExtendedPayload(.await_nosuspend, Zir.Inst.UnNode{
            .node = gz.nodeIndexToRelative(node),
            .operand = operand,
        })
    else
        try gz.addUnNode(.@"await", operand, node);

    return rvalue(gz, ri, result, node);
}

fn resumeExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const rhs_node = tree.nodeData(node).node;
    const operand = try expr(gz, scope, .{ .rl = .ref }, rhs_node);
    const result = try gz.addUnNode(.@"resume", operand, node);
    return rvalue(gz, ri, result, node);
}

fn fnProtoExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    if (fn_proto.name_token) |some| {
        return astgen.failTok(some, "function type cannot have a name", .{});
    }

    if (fn_proto.ast.align_expr.unwrap()) |align_expr| {
        return astgen.failNode(align_expr, "function type cannot have an alignment", .{});
    }

    if (fn_proto.ast.addrspace_expr.unwrap()) |addrspace_expr| {
        return astgen.failNode(addrspace_expr, "function type cannot have an addrspace", .{});
    }

    if (fn_proto.ast.section_expr.unwrap()) |section_expr| {
        return astgen.failNode(section_expr, "function type cannot have a linksection", .{});
    }

    const return_type = fn_proto.ast.return_type.unwrap().?;
    const maybe_bang = tree.firstToken(return_type) - 1;
    const is_inferred_error = tree.tokenTag(maybe_bang) == .bang;
    if (is_inferred_error) {
        return astgen.failTok(maybe_bang, "function type cannot have an inferred error set", .{});
    }

    const is_extern = blk: {
        const maybe_extern_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_extern_token) == .keyword_extern;
    };
    assert(!is_extern);

    return fnProtoExprInner(gz, scope, ri, node, fn_proto, false);
}

fn fnProtoExprInner(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
    implicit_ccc: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    var block_scope = gz.makeSubBlock(scope);
    defer block_scope.unstack();

    const block_inst = try gz.makeBlockInst(.block_inline, node);

    var noalias_bits: u32 = 0;
    const is_var_args = is_var_args: {
        var param_type_i: usize = 0;
        var it = fn_proto.iterate(tree);
        while (it.next()) |param| : (param_type_i += 1) {
            const is_comptime = if (param.comptime_noalias) |token| switch (tree.tokenTag(token)) {
                .keyword_noalias => is_comptime: {
                    noalias_bits |= @as(u32, 1) << (std.math.cast(u5, param_type_i) orelse
                        return astgen.failTok(token, "this compiler implementation only supports 'noalias' on the first 32 parameters", .{}));
                    break :is_comptime false;
                },
                .keyword_comptime => true,
                else => false,
            } else false;

            const is_anytype = if (param.anytype_ellipsis3) |token| blk: {
                switch (tree.tokenTag(token)) {
                    .keyword_anytype => break :blk true,
                    .ellipsis3 => break :is_var_args true,
                    else => unreachable,
                }
            } else false;

            const param_name = if (param.name_token) |name_token| blk: {
                if (mem.eql(u8, "_", tree.tokenSlice(name_token)))
                    break :blk .empty;

                break :blk try astgen.identAsString(name_token);
            } else .empty;

            if (is_anytype) {
                const name_token = param.name_token orelse param.anytype_ellipsis3.?;

                const tag: Zir.Inst.Tag = if (is_comptime)
                    .param_anytype_comptime
                else
                    .param_anytype;
                _ = try block_scope.addStrTok(tag, param_name, name_token);
            } else {
                const param_type_node = param.type_expr.?;
                var param_gz = block_scope.makeSubBlock(scope);
                defer param_gz.unstack();
                param_gz.is_comptime = true;
                const param_type = try fullBodyExpr(&param_gz, scope, coerced_type_ri, param_type_node, .normal);
                const param_inst_expected: Zir.Inst.Index = @enumFromInt(astgen.instructions.len + 1);
                _ = try param_gz.addBreakWithSrcNode(.break_inline, param_inst_expected, param_type, param_type_node);
                const name_token = param.name_token orelse tree.nodeMainToken(param_type_node);
                const tag: Zir.Inst.Tag = if (is_comptime) .param_comptime else .param;
                // We pass `prev_param_insts` as `&.{}` here because a function prototype can't refer to previous
                // arguments (we haven't set up scopes here).
                const param_inst = try block_scope.addParam(&param_gz, &.{}, false, tag, name_token, param_name);
                assert(param_inst_expected == param_inst);
            }
        }
        break :is_var_args false;
    };

    const cc: Zir.Inst.Ref = if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr|
        try comptimeExpr(
            &block_scope,
            scope,
            .{ .rl = .{ .coerced_ty = try block_scope.addBuiltinValue(callconv_expr, .calling_convention) } },
            callconv_expr,
            .@"callconv",
        )
    else if (implicit_ccc)
        try block_scope.addBuiltinValue(node, .calling_convention_c)
    else
        .none;

    const ret_ty_node = fn_proto.ast.return_type.unwrap().?;
    const ret_ty = try comptimeExpr(&block_scope, scope, coerced_type_ri, ret_ty_node, .function_ret_ty);

    const result = try block_scope.addFunc(.{
        .src_node = fn_proto.ast.proto_node,

        .cc_ref = cc,
        .cc_gz = null,
        .ret_ref = ret_ty,
        .ret_gz = null,

        .ret_param_refs = &.{},
        .param_insts = &.{},
        .ret_ty_is_generic = false,

        .param_block = block_inst,
        .body_gz = null,
        .is_var_args = is_var_args,
        .is_inferred_error = false,
        .is_noinline = false,
        .noalias_bits = noalias_bits,

        .proto_hash = undefined, // ignored for `body_gz == null`
    });

    _ = try block_scope.addBreak(.break_inline, block_inst, result);
    try block_scope.setBlockBody(block_inst);
    try gz.instructions.append(astgen.gpa, block_inst);

    return rvalue(gz, ri, block_inst.toRef(), fn_proto.ast.proto_node);
}

fn arrayInitExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    array_init: Ast.full.ArrayInit,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    assert(array_init.ast.elements.len != 0); // Otherwise it would be struct init.

    const array_ty: Zir.Inst.Ref, const elem_ty: Zir.Inst.Ref = inst: {
        const type_expr = array_init.ast.type_expr.unwrap() orelse break :inst .{ .none, .none };

        infer: {
            const array_type: Ast.full.ArrayType = tree.fullArrayType(type_expr) orelse break :infer;
            // This intentionally does not support `@"_"` syntax.
            if (tree.nodeTag(array_type.ast.elem_count) == .identifier and
                mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(array_type.ast.elem_count)), "_"))
            {
                const len_inst = try gz.addInt(array_init.ast.elements.len);
                const elem_type = try typeExpr(gz, scope, array_type.ast.elem_type);
                if (array_type.ast.sentinel == .none) {
                    const array_type_inst = try gz.addPlNode(.array_type, type_expr, Zir.Inst.Bin{
                        .lhs = len_inst,
                        .rhs = elem_type,
                    });
                    break :inst .{ array_type_inst, elem_type };
                } else {
                    const sentinel_node = array_type.ast.sentinel.unwrap().?;
                    const sentinel = try comptimeExpr(gz, scope, .{ .rl = .{ .ty = elem_type } }, sentinel_node, .array_sentinel);
                    const array_type_inst = try gz.addPlNode(
                        .array_type_sentinel,
                        type_expr,
                        Zir.Inst.ArrayTypeSentinel{
                            .len = len_inst,
                            .elem_type = elem_type,
                            .sentinel = sentinel,
                        },
                    );
                    break :inst .{ array_type_inst, elem_type };
                }
            }
        }
        const array_type_inst = try typeExpr(gz, scope, type_expr);
        _ = try gz.addPlNode(.validate_array_init_ty, node, Zir.Inst.ArrayInit{
            .ty = array_type_inst,
            .init_count = @intCast(array_init.ast.elements.len),
        });
        break :inst .{ array_type_inst, .none };
    };

    if (array_ty != .none) {
        // Typed inits do not use RLS for language simplicity.
        switch (ri.rl) {
            .discard => {
                if (elem_ty != .none) {
                    const elem_ri: ResultInfo = .{ .rl = .{ .ty = elem_ty } };
                    for (array_init.ast.elements) |elem_init| {
                        _ = try expr(gz, scope, elem_ri, elem_init);
                    }
                } else {
                    for (array_init.ast.elements, 0..) |elem_init, i| {
                        const this_elem_ty = try gz.add(.{
                            .tag = .array_init_elem_type,
                            .data = .{ .bin = .{
                                .lhs = array_ty,
                                .rhs = @enumFromInt(i),
                            } },
                        });
                        _ = try expr(gz, scope, .{ .rl = .{ .ty = this_elem_ty } }, elem_init);
                    }
                }
                return .void_value;
            },
            .ref => return arrayInitExprTyped(gz, scope, node, array_init.ast.elements, array_ty, elem_ty, true),
            else => {
                const array_inst = try arrayInitExprTyped(gz, scope, node, array_init.ast.elements, array_ty, elem_ty, false);
                return rvalue(gz, ri, array_inst, node);
            },
        }
    }

    switch (ri.rl) {
        .none => return arrayInitExprAnon(gz, scope, node, array_init.ast.elements),
        .discard => {
            for (array_init.ast.elements) |elem_init| {
                _ = try expr(gz, scope, .{ .rl = .discard }, elem_init);
            }
            return Zir.Inst.Ref.void_value;
        },
        .ref => {
            const result = try arrayInitExprAnon(gz, scope, node, array_init.ast.elements);
            return gz.addUnTok(.ref, result, tree.firstToken(node));
        },
        .ref_coerced_ty => |ptr_ty_inst| {
            const dest_arr_ty_inst = try gz.addPlNode(.validate_array_init_ref_ty, node, Zir.Inst.ArrayInitRefTy{
                .ptr_ty = ptr_ty_inst,
                .elem_count = @intCast(array_init.ast.elements.len),
            });
            return arrayInitExprTyped(gz, scope, node, array_init.ast.elements, dest_arr_ty_inst, .none, true);
        },
        .ty, .coerced_ty => |result_ty_inst| {
            _ = try gz.addPlNode(.validate_array_init_result_ty, node, Zir.Inst.ArrayInit{
                .ty = result_ty_inst,
                .init_count = @intCast(array_init.ast.elements.len),
            });
            return arrayInitExprTyped(gz, scope, node, array_init.ast.elements, result_ty_inst, .none, false);
        },
        .ptr => |ptr| {
            try arrayInitExprPtr(gz, scope, node, array_init.ast.elements, ptr.inst);
            return .void_value;
        },
        .inferred_ptr => {
            // We can't get elem pointers of an untyped inferred alloc, so must perform a
            // standard anonymous initialization followed by an rvalue store.
            // See corresponding logic in structInitExpr.
            const result = try arrayInitExprAnon(gz, scope, node, array_init.ast.elements);
            return rvalue(gz, ri, result, node);
        },
        .destructure => |destructure| {
            // Untyped init - destructure directly into result pointers
            if (array_init.ast.elements.len != destructure.components.len) {
                return astgen.failNodeNotes(node, "expected {} elements for destructure, found {}", .{
                    destructure.components.len,
                    array_init.ast.elements.len,
                }, &.{
                    try astgen.errNoteNode(destructure.src_node, "result destructured here", .{}),
                });
            }
            for (array_init.ast.elements, destructure.components) |elem_init, ds_comp| {
                const elem_ri: ResultInfo = .{ .rl = switch (ds_comp) {
                    .typed_ptr => |ptr_rl| .{ .ptr = ptr_rl },
                    .inferred_ptr => |ptr_inst| .{ .inferred_ptr = ptr_inst },
                    .discard => .discard,
                } };
                _ = try expr(gz, scope, elem_ri, elem_init);
            }
            return .void_value;
        },
    }
}

/// An array initialization expression using an `array_init_anon` instruction.
fn arrayInitExprAnon(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    elements: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;

    const payload_index = try addExtra(astgen, Zir.Inst.MultiOp{
        .operands_len = @intCast(elements.len),
    });
    var extra_index = try reserveExtra(astgen, elements.len);

    for (elements) |elem_init| {
        const elem_ref = try expr(gz, scope, .{ .rl = .none }, elem_init);
        astgen.extra.items[extra_index] = @intFromEnum(elem_ref);
        extra_index += 1;
    }
    return try gz.addPlNodePayloadIndex(.array_init_anon, node, payload_index);
}

/// An array initialization expression using an `array_init` or `array_init_ref` instruction.
fn arrayInitExprTyped(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    elements: []const Ast.Node.Index,
    ty_inst: Zir.Inst.Ref,
    maybe_elem_ty_inst: Zir.Inst.Ref,
    is_ref: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;

    const len = elements.len + 1; // +1 for type
    const payload_index = try addExtra(astgen, Zir.Inst.MultiOp{
        .operands_len = @intCast(len),
    });
    var extra_index = try reserveExtra(astgen, len);
    astgen.extra.items[extra_index] = @intFromEnum(ty_inst);
    extra_index += 1;

    if (maybe_elem_ty_inst != .none) {
        const elem_ri: ResultInfo = .{ .rl = .{ .coerced_ty = maybe_elem_ty_inst } };
        for (elements) |elem_init| {
            const elem_inst = try expr(gz, scope, elem_ri, elem_init);
            astgen.extra.items[extra_index] = @intFromEnum(elem_inst);
            extra_index += 1;
        }
    } else {
        for (elements, 0..) |elem_init, i| {
            const ri: ResultInfo = .{ .rl = .{ .coerced_ty = try gz.add(.{
                .tag = .array_init_elem_type,
                .data = .{ .bin = .{
                    .lhs = ty_inst,
                    .rhs = @enumFromInt(i),
                } },
            }) } };

            const elem_inst = try expr(gz, scope, ri, elem_init);
            astgen.extra.items[extra_index] = @intFromEnum(elem_inst);
            extra_index += 1;
        }
    }

    const tag: Zir.Inst.Tag = if (is_ref) .array_init_ref else .array_init;
    return try gz.addPlNodePayloadIndex(tag, node, payload_index);
}

/// An array initialization expression using element pointers.
fn arrayInitExprPtr(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    elements: []const Ast.Node.Index,
    ptr_inst: Zir.Inst.Ref,
) InnerError!void {
    const astgen = gz.astgen;

    const array_ptr_inst = try gz.addUnNode(.opt_eu_base_ptr_init, ptr_inst, node);

    const payload_index = try addExtra(astgen, Zir.Inst.Block{
        .body_len = @intCast(elements.len),
    });
    var extra_index = try reserveExtra(astgen, elements.len);

    for (elements, 0..) |elem_init, i| {
        const elem_ptr_inst = try gz.addPlNode(.array_init_elem_ptr, elem_init, Zir.Inst.ElemPtrImm{
            .ptr = array_ptr_inst,
            .index = @intCast(i),
        });
        astgen.extra.items[extra_index] = @intFromEnum(elem_ptr_inst.toIndex().?);
        extra_index += 1;
        _ = try expr(gz, scope, .{ .rl = .{ .ptr = .{ .inst = elem_ptr_inst } } }, elem_init);
    }

    _ = try gz.addPlNodePayloadIndex(.validate_ptr_array_init, node, payload_index);
}

fn structInitExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    if (struct_init.ast.type_expr == .none) {
        if (struct_init.ast.fields.len == 0) {
            // Anonymous init with no fields.
            switch (ri.rl) {
                .discard => return .void_value,
                .ref_coerced_ty => |ptr_ty_inst| return gz.addUnNode(.struct_init_empty_ref_result, ptr_ty_inst, node),
                .ty, .coerced_ty => |ty_inst| return gz.addUnNode(.struct_init_empty_result, ty_inst, node),
                .ptr => {
                    // TODO: should we modify this to use RLS for the field stores here?
                    const ty_inst = (try ri.rl.resultType(gz, node)).?;
                    const val = try gz.addUnNode(.struct_init_empty_result, ty_inst, node);
                    return rvalue(gz, ri, val, node);
                },
                .none, .ref, .inferred_ptr => {
                    return rvalue(gz, ri, .empty_tuple, node);
                },
                .destructure => |destructure| {
                    return astgen.failNodeNotes(node, "empty initializer cannot be destructured", .{}, &.{
                        try astgen.errNoteNode(destructure.src_node, "result destructured here", .{}),
                    });
                },
            }
        }
    } else array: {
        const type_expr = struct_init.ast.type_expr.unwrap().?;
        const array_type: Ast.full.ArrayType = tree.fullArrayType(type_expr) orelse {
            if (struct_init.ast.fields.len == 0) {
                const ty_inst = try typeExpr(gz, scope, type_expr);
                const result = try gz.addUnNode(.struct_init_empty, ty_inst, node);
                return rvalue(gz, ri, result, node);
            }
            break :array;
        };
        const is_inferred_array_len = tree.nodeTag(array_type.ast.elem_count) == .identifier and
            // This intentionally does not support `@"_"` syntax.
            mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(array_type.ast.elem_count)), "_");
        if (struct_init.ast.fields.len == 0) {
            if (is_inferred_array_len) {
                const elem_type = try typeExpr(gz, scope, array_type.ast.elem_type);
                const array_type_inst = if (array_type.ast.sentinel == .none) blk: {
                    break :blk try gz.addPlNode(.array_type, type_expr, Zir.Inst.Bin{
                        .lhs = .zero_usize,
                        .rhs = elem_type,
                    });
                } else blk: {
                    const sentinel_node = array_type.ast.sentinel.unwrap().?;
                    const sentinel = try comptimeExpr(gz, scope, .{ .rl = .{ .ty = elem_type } }, sentinel_node, .array_sentinel);
                    break :blk try gz.addPlNode(
                        .array_type_sentinel,
                        type_expr,
                        Zir.Inst.ArrayTypeSentinel{
                            .len = .zero_usize,
                            .elem_type = elem_type,
                            .sentinel = sentinel,
                        },
                    );
                };
                const result = try gz.addUnNode(.struct_init_empty, array_type_inst, node);
                return rvalue(gz, ri, result, node);
            }
            const ty_inst = try typeExpr(gz, scope, type_expr);
            const result = try gz.addUnNode(.struct_init_empty, ty_inst, node);
            return rvalue(gz, ri, result, node);
        } else {
            return astgen.failNode(
                type_expr,
                "initializing array with struct syntax",
                .{},
            );
        }
    }

    {
        var sfba = std.heap.stackFallback(256, astgen.arena);
        const sfba_allocator = sfba.get();

        var duplicate_names = std.AutoArrayHashMap(Zir.NullTerminatedString, ArrayListUnmanaged(Ast.TokenIndex)).init(sfba_allocator);
        try duplicate_names.ensureTotalCapacity(@intCast(struct_init.ast.fields.len));

        // When there aren't errors, use this to avoid a second iteration.
        var any_duplicate = false;

        for (struct_init.ast.fields) |field| {
            const name_token = tree.firstToken(field) - 2;
            const name_index = try astgen.identAsString(name_token);

            const gop = try duplicate_names.getOrPut(name_index);

            if (gop.found_existing) {
                try gop.value_ptr.append(sfba_allocator, name_token);
                any_duplicate = true;
            } else {
                gop.value_ptr.* = .{};
                try gop.value_ptr.append(sfba_allocator, name_token);
            }
        }

        if (any_duplicate) {
            var it = duplicate_names.iterator();

            while (it.next()) |entry| {
                const record = entry.value_ptr.*;
                if (record.items.len > 1) {
                    var error_notes = std.ArrayList(u32).init(astgen.arena);

                    for (record.items[1..]) |duplicate| {
                        try error_notes.append(try astgen.errNoteTok(duplicate, "duplicate name here", .{}));
                    }

                    try error_notes.append(try astgen.errNoteNode(node, "struct declared here", .{}));

                    try astgen.appendErrorTokNotes(
                        record.items[0],
                        "duplicate struct field name",
                        .{},
                        error_notes.items,
                    );
                }
            }

            return error.AnalysisFail;
        }
    }

    if (struct_init.ast.type_expr.unwrap()) |type_expr| {
        // Typed inits do not use RLS for language simplicity.
        const ty_inst = try typeExpr(gz, scope, type_expr);
        _ = try gz.addUnNode(.validate_struct_init_ty, ty_inst, node);
        switch (ri.rl) {
            .ref => return structInitExprTyped(gz, scope, node, struct_init, ty_inst, true),
            else => {
                const struct_inst = try structInitExprTyped(gz, scope, node, struct_init, ty_inst, false);
                return rvalue(gz, ri, struct_inst, node);
            },
        }
    }

    switch (ri.rl) {
        .none => return structInitExprAnon(gz, scope, node, struct_init),
        .discard => {
            // Even if discarding we must perform side-effects.
            for (struct_init.ast.fields) |field_init| {
                _ = try expr(gz, scope, .{ .rl = .discard }, field_init);
            }
            return .void_value;
        },
        .ref => {
            const result = try structInitExprAnon(gz, scope, node, struct_init);
            return gz.addUnTok(.ref, result, tree.firstToken(node));
        },
        .ref_coerced_ty => |ptr_ty_inst| {
            const result_ty_inst = try gz.addUnNode(.elem_type, ptr_ty_inst, node);
            _ = try gz.addUnNode(.validate_struct_init_result_ty, result_ty_inst, node);
            return structInitExprTyped(gz, scope, node, struct_init, result_ty_inst, true);
        },
        .ty, .coerced_ty => |result_ty_inst| {
            _ = try gz.addUnNode(.validate_struct_init_result_ty, result_ty_inst, node);
            return structInitExprTyped(gz, scope, node, struct_init, result_ty_inst, false);
        },
        .ptr => |ptr| {
            try structInitExprPtr(gz, scope, node, struct_init, ptr.inst);
            return .void_value;
        },
        .inferred_ptr => {
            // We can't get field pointers of an untyped inferred alloc, so must perform a
            // standard anonymous initialization followed by an rvalue store.
            // See corresponding logic in arrayInitExpr.
            const struct_inst = try structInitExprAnon(gz, scope, node, struct_init);
            return rvalue(gz, ri, struct_inst, node);
        },
        .destructure => |destructure| {
            // This is an untyped init, so is an actual struct, which does
            // not support destructuring.
            return astgen.failNodeNotes(node, "struct value cannot be destructured", .{}, &.{
                try astgen.errNoteNode(destructure.src_node, "result destructured here", .{}),
            });
        },
    }
}

/// A struct initialization expression using a `struct_init_anon` instruction.
fn structInitExprAnon(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const payload_index = try addExtra(astgen, Zir.Inst.StructInitAnon{
        .abs_node = node,
        .abs_line = astgen.source_line,
        .fields_len = @intCast(struct_init.ast.fields.len),
    });
    const field_size = @typeInfo(Zir.Inst.StructInitAnon.Item).@"struct".fields.len;
    var extra_index: usize = try reserveExtra(astgen, struct_init.ast.fields.len * field_size);

    for (struct_init.ast.fields) |field_init| {
        const name_token = tree.firstToken(field_init) - 2;
        const str_index = try astgen.identAsString(name_token);
        setExtra(astgen, extra_index, Zir.Inst.StructInitAnon.Item{
            .field_name = str_index,
            .init = try expr(gz, scope, .{ .rl = .none }, field_init),
        });
        extra_index += field_size;
    }

    return gz.addPlNodePayloadIndex(.struct_init_anon, node, payload_index);
}

/// A struct initialization expression using a `struct_init` or `struct_init_ref` instruction.
fn structInitExprTyped(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
    ty_inst: Zir.Inst.Ref,
    is_ref: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const payload_index = try addExtra(astgen, Zir.Inst.StructInit{
        .abs_node = node,
        .abs_line = astgen.source_line,
        .fields_len = @intCast(struct_init.ast.fields.len),
    });
    const field_size = @typeInfo(Zir.Inst.StructInit.Item).@"struct".fields.len;
    var extra_index: usize = try reserveExtra(astgen, struct_init.ast.fields.len * field_size);

    for (struct_init.ast.fields) |field_init| {
        const name_token = tree.firstToken(field_init) - 2;
        const str_index = try astgen.identAsString(name_token);
        const field_ty_inst = try gz.addPlNode(.struct_init_field_type, field_init, Zir.Inst.FieldType{
            .container_type = ty_inst,
            .name_start = str_index,
        });
        setExtra(astgen, extra_index, Zir.Inst.StructInit.Item{
            .field_type = field_ty_inst.toIndex().?,
            .init = try expr(gz, scope, .{ .rl = .{ .coerced_ty = field_ty_inst } }, field_init),
        });
        extra_index += field_size;
    }

    const tag: Zir.Inst.Tag = if (is_ref) .struct_init_ref else .struct_init;
    return gz.addPlNodePayloadIndex(tag, node, payload_index);
}

/// A struct initialization expression using field pointers.
fn structInitExprPtr(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
    ptr_inst: Zir.Inst.Ref,
) InnerError!void {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const struct_ptr_inst = try gz.addUnNode(.opt_eu_base_ptr_init, ptr_inst, node);

    const payload_index = try addExtra(astgen, Zir.Inst.Block{
        .body_len = @intCast(struct_init.ast.fields.len),
    });
    var extra_index = try reserveExtra(astgen, struct_init.ast.fields.len);

    for (struct_init.ast.fields) |field_init| {
        const name_token = tree.firstToken(field_init) - 2;
        const str_index = try astgen.identAsString(name_token);
        const field_ptr = try gz.addPlNode(.struct_init_field_ptr, field_init, Zir.Inst.Field{
            .lhs = struct_ptr_inst,
            .field_name_start = str_index,
        });
        astgen.extra.items[extra_index] = @intFromEnum(field_ptr.toIndex().?);
        extra_index += 1;
        _ = try expr(gz, scope, .{ .rl = .{ .ptr = .{ .inst = field_ptr } } }, field_init);
    }

    _ = try gz.addPlNodePayloadIndex(.validate_ptr_struct_init, node, payload_index);
}

/// This explicitly calls expr in a comptime scope by wrapping it in a `block_comptime` if
/// necessary. It should be used whenever we need to force compile-time evaluation of something,
/// such as a type.
/// The function corresponding to `comptime` expression syntax is `comptimeExprAst`.
fn comptimeExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    reason: std.zig.SimpleComptimeReason,
) InnerError!Zir.Inst.Ref {
    return comptimeExpr2(gz, scope, ri, node, node, reason);
}

/// Like `comptimeExpr`, but draws a distinction between `node`, the expression to evaluate at comptime,
/// and `src_node`, the node to attach to the `block_comptime`.
fn comptimeExpr2(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    src_node: Ast.Node.Index,
    reason: std.zig.SimpleComptimeReason,
) InnerError!Zir.Inst.Ref {
    if (gz.is_comptime) {
        // No need to change anything!
        return expr(gz, scope, ri, node);
    }

    // There's an optimization here: if the body will be evaluated at comptime regardless, there's
    // no need to wrap it in a block. This is hard to determine in general, but we can identify a
    // common subset of trivially comptime expressions to take down the size of the ZIR a bit.
    const tree = gz.astgen.tree;
    switch (tree.nodeTag(node)) {
        .identifier => {
            // Many identifiers can be handled without a `block_comptime`, so `AstGen.identifier` has
            // special handling for this case.
            return identifier(gz, scope, ri, node, .{ .src_node = src_node, .reason = reason });
        },

        // These are leaf nodes which are always comptime-known.
        .number_literal,
        .char_literal,
        .string_literal,
        .multiline_string_literal,
        .enum_literal,
        .error_value,
        .anyframe_literal,
        .error_set_decl,
        // These nodes are not leaves, but will force comptime evaluation of all sub-expressions, and
        // hence behave the same regardless of whether they're in a comptime scope.
        .error_union,
        .merge_error_sets,
        .optional_type,
        .anyframe_type,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .array_type,
        .array_type_sentinel,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
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
            // No need to worry about result location here, we're not creating a comptime block!
            return expr(gz, scope, ri, node);
        },

        // Lastly, for labelled blocks, avoid emitting a labelled block directly inside this
        // comptime block, because that would be silly! Note that we don't bother doing this for
        // unlabelled blocks, since they don't generate blocks at comptime anyway (see `blockExpr`).
        .block_two, .block_two_semicolon, .block, .block_semicolon => {
            const lbrace = tree.nodeMainToken(node);
            // Careful! We can't pass in the real result location here, since it may
            // refer to runtime memory. A runtime-to-comptime boundary has to remove
            // result location information, compute the result, and copy it to the true
            // result location at runtime. We do this below as well.
            const ty_only_ri: ResultInfo = .{
                .ctx = ri.ctx,
                .rl = if (try ri.rl.resultType(gz, node)) |res_ty|
                    .{ .coerced_ty = res_ty }
                else
                    .none,
            };
            if (tree.isTokenPrecededByTags(lbrace, &.{ .identifier, .colon })) {
                var buf: [2]Ast.Node.Index = undefined;
                const stmts = tree.blockStatements(&buf, node).?;

                // Replace result location and copy back later - see above.
                const block_ref = try labeledBlockExpr(gz, scope, ty_only_ri, node, stmts, true, .normal);
                return rvalue(gz, ri, block_ref, node);
            }
        },

        // In other cases, we don't optimize anything - we need a wrapper comptime block.
        else => {},
    }

    var block_scope = gz.makeSubBlock(scope);
    block_scope.is_comptime = true;
    defer block_scope.unstack();

    const block_inst = try gz.makeBlockInst(.block_comptime, src_node);
    // Replace result location and copy back later - see above.
    const ty_only_ri: ResultInfo = .{
        .ctx = ri.ctx,
        .rl = if (try ri.rl.resultType(gz, src_node)) |res_ty|
            .{ .coerced_ty = res_ty }
        else
            .none,
    };
    const block_result = try fullBodyExpr(&block_scope, scope, ty_only_ri, node, .normal);
    if (!gz.refIsNoReturn(block_result)) {
        _ = try block_scope.addBreak(.break_inline, block_inst, block_result);
    }
    try block_scope.setBlockComptimeBody(block_inst, reason);
    try gz.instructions.append(gz.astgen.gpa, block_inst);

    return rvalue(gz, ri, block_inst.toRef(), src_node);
}

/// This one is for an actual `comptime` syntax, and will emit a compile error if
/// the scope is already known to be comptime-evaluated.
/// See `comptimeExpr` for the helper function for calling expr in a comptime scope.
fn comptimeExprAst(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    if (gz.is_comptime) {
        try astgen.appendErrorNode(node, "redundant comptime keyword in already comptime scope", .{});
    }
    const tree = astgen.tree;
    const body_node = tree.nodeData(node).node;
    return comptimeExpr2(gz, scope, ri, body_node, node, .comptime_keyword);
}

/// Restore the error return trace index. Performs the restore only if the result is a non-error or
/// if the result location is a non-error-handling expression.
fn restoreErrRetIndex(
    gz: *GenZir,
    bt: GenZir.BranchTarget,
    ri: ResultInfo,
    node: Ast.Node.Index,
    result: Zir.Inst.Ref,
) !void {
    const op = switch (nodeMayEvalToError(gz.astgen.tree, node)) {
        .always => return, // never restore/pop
        .never => .none, // always restore/pop
        .maybe => switch (ri.ctx) {
            .error_handling_expr, .@"return", .fn_arg, .const_init => switch (ri.rl) {
                .ptr => |ptr_res| try gz.addUnNode(.load, ptr_res.inst, node),
                .inferred_ptr => blk: {
                    // This is a terrible workaround for Sema's inability to load from a .alloc_inferred ptr
                    // before its type has been resolved. There is no valid operand to use here, so error
                    // traces will be popped prematurely.
                    // TODO: Update this to do a proper load from the rl_ptr, once Sema can support it.
                    break :blk .none;
                },
                .destructure => return, // value must be a tuple or array, so never restore/pop
                else => result,
            },
            else => .none, // always restore/pop
        },
    };
    _ = try gz.addRestoreErrRetIndex(bt, .{ .if_non_error = op }, node);
}

fn breakExpr(parent_gz: *GenZir, parent_scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;
    const opt_break_label, const opt_rhs = tree.nodeData(node).opt_token_and_opt_node;

    // Look for the label in the scope.
    var scope = parent_scope;
    while (true) {
        switch (scope.tag) {
            .gen_zir => {
                const block_gz = scope.cast(GenZir).?;

                if (block_gz.cur_defer_node.unwrap()) |cur_defer_node| {
                    // We are breaking out of a `defer` block.
                    return astgen.failNodeNotes(node, "cannot break out of defer expression", .{}, &.{
                        try astgen.errNoteNode(
                            cur_defer_node,
                            "defer expression here",
                            .{},
                        ),
                    });
                }

                const block_inst = blk: {
                    if (opt_break_label.unwrap()) |break_label| {
                        if (block_gz.label) |*label| {
                            if (try astgen.tokenIdentEql(label.token, break_label)) {
                                label.used = true;
                                break :blk label.block_inst;
                            }
                        }
                    } else if (block_gz.break_block.unwrap()) |i| {
                        break :blk i;
                    }
                    // If not the target, start over with the parent
                    scope = block_gz.parent;
                    continue;
                };
                // If we made it here, this block is the target of the break expr

                const break_tag: Zir.Inst.Tag = if (block_gz.is_inline)
                    .break_inline
                else
                    .@"break";

                const rhs = opt_rhs.unwrap() orelse {
                    _ = try rvalue(parent_gz, block_gz.break_result_info, .void_value, node);

                    try genDefers(parent_gz, scope, parent_scope, .normal_only);

                    // As our last action before the break, "pop" the error trace if needed
                    if (!block_gz.is_comptime)
                        _ = try parent_gz.addRestoreErrRetIndex(.{ .block = block_inst }, .always, node);

                    _ = try parent_gz.addBreak(break_tag, block_inst, .void_value);
                    return Zir.Inst.Ref.unreachable_value;
                };

                const operand = try reachableExpr(parent_gz, parent_scope, block_gz.break_result_info, rhs, node);

                try genDefers(parent_gz, scope, parent_scope, .normal_only);

                // As our last action before the break, "pop" the error trace if needed
                if (!block_gz.is_comptime)
                    try restoreErrRetIndex(parent_gz, .{ .block = block_inst }, block_gz.break_result_info, rhs, operand);

                switch (block_gz.break_result_info.rl) {
                    .ptr => {
                        // In this case we don't have any mechanism to intercept it;
                        // we assume the result location is written, and we break with void.
                        _ = try parent_gz.addBreak(break_tag, block_inst, .void_value);
                    },
                    .discard => {
                        _ = try parent_gz.addBreak(break_tag, block_inst, .void_value);
                    },
                    else => {
                        _ = try parent_gz.addBreakWithSrcNode(break_tag, block_inst, operand, rhs);
                    },
                }
                return Zir.Inst.Ref.unreachable_value;
            },
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .namespace => break,
            .defer_normal, .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .top => unreachable,
        }
    }
    if (opt_break_label.unwrap()) |break_label| {
        const label_name = try astgen.identifierTokenString(break_label);
        return astgen.failTok(break_label, "label not found: '{s}'", .{label_name});
    } else {
        return astgen.failNode(node, "break expression outside loop", .{});
    }
}

fn continueExpr(parent_gz: *GenZir, parent_scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;
    const opt_break_label, const opt_rhs = tree.nodeData(node).opt_token_and_opt_node;

    if (opt_break_label == .none and opt_rhs != .none) {
        return astgen.failNode(node, "cannot continue with operand without label", .{});
    }

    // Look for the label in the scope.
    var scope = parent_scope;
    while (true) {
        switch (scope.tag) {
            .gen_zir => {
                const gen_zir = scope.cast(GenZir).?;

                if (gen_zir.cur_defer_node.unwrap()) |cur_defer_node| {
                    return astgen.failNodeNotes(node, "cannot continue out of defer expression", .{}, &.{
                        try astgen.errNoteNode(
                            cur_defer_node,
                            "defer expression here",
                            .{},
                        ),
                    });
                }
                const continue_block = gen_zir.continue_block.unwrap() orelse {
                    scope = gen_zir.parent;
                    continue;
                };
                if (opt_break_label.unwrap()) |break_label| blk: {
                    if (gen_zir.label) |*label| {
                        if (try astgen.tokenIdentEql(label.token, break_label)) {
                            const maybe_switch_tag = astgen.instructions.items(.tag)[@intFromEnum(label.block_inst)];
                            if (opt_rhs != .none) switch (maybe_switch_tag) {
                                .switch_block, .switch_block_ref => {},
                                else => return astgen.failNode(node, "cannot continue loop with operand", .{}),
                            } else switch (maybe_switch_tag) {
                                .switch_block, .switch_block_ref => return astgen.failNode(node, "cannot continue switch without operand", .{}),
                                else => {},
                            }

                            label.used = true;
                            label.used_for_continue = true;
                            break :blk;
                        }
                    }
                    // found continue but either it has a different label, or no label
                    scope = gen_zir.parent;
                    continue;
                } else if (gen_zir.label) |label| {
                    // This `continue` is unlabeled. If the gz we've found corresponds to a labeled
                    // `switch`, ignore it and continue to parent scopes.
                    switch (astgen.instructions.items(.tag)[@intFromEnum(label.block_inst)]) {
                        .switch_block, .switch_block_ref => {
                            scope = gen_zir.parent;
                            continue;
                        },
                        else => {},
                    }
                }

                if (opt_rhs.unwrap()) |rhs| {
                    // We need to figure out the result info to use.
                    // The type should match
                    const operand = try reachableExpr(parent_gz, parent_scope, gen_zir.continue_result_info, rhs, node);

                    try genDefers(parent_gz, scope, parent_scope, .normal_only);

                    // As our last action before the continue, "pop" the error trace if needed
                    if (!gen_zir.is_comptime)
                        _ = try parent_gz.addRestoreErrRetIndex(.{ .block = continue_block }, .always, node);

                    _ = try parent_gz.addBreakWithSrcNode(.switch_continue, continue_block, operand, rhs);
                    return Zir.Inst.Ref.unreachable_value;
                }

                try genDefers(parent_gz, scope, parent_scope, .normal_only);

                const break_tag: Zir.Inst.Tag = if (gen_zir.is_inline)
                    .break_inline
                else
                    .@"break";
                if (break_tag == .break_inline) {
                    _ = try parent_gz.addUnNode(.check_comptime_control_flow, continue_block.toRef(), node);
                }

                // As our last action before the continue, "pop" the error trace if needed
                if (!gen_zir.is_comptime)
                    _ = try parent_gz.addRestoreErrRetIndex(.{ .block = continue_block }, .always, node);

                _ = try parent_gz.addBreak(break_tag, continue_block, .void_value);
                return Zir.Inst.Ref.unreachable_value;
            },
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal, .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .namespace => break,
            .top => unreachable,
        }
    }
    if (opt_break_label.unwrap()) |break_label| {
        const label_name = try astgen.identifierTokenString(break_label);
        return astgen.failTok(break_label, "label not found: '{s}'", .{label_name});
    } else {
        return astgen.failNode(node, "continue expression outside loop", .{});
    }
}

/// Similar to `expr`, but intended for use when `gz` corresponds to a body
/// which will contain only this node's code. Differs from `expr` in that if the
/// root expression is an unlabeled block, does not emit an actual block.
/// Instead, the block contents are emitted directly into `gz`.
fn fullBodyExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    block_kind: BlockKind,
) InnerError!Zir.Inst.Ref {
    const tree = gz.astgen.tree;

    var stmt_buf: [2]Ast.Node.Index = undefined;
    const statements = tree.blockStatements(&stmt_buf, node) orelse
        return expr(gz, scope, ri, node);

    const lbrace = tree.nodeMainToken(node);

    if (tree.isTokenPrecededByTags(lbrace, &.{ .identifier, .colon })) {
        // Labeled blocks are tricky - forwarding result location information properly is non-trivial,
        // plus if this block is exited with a `break_inline` we aren't allowed multiple breaks. This
        // case is rare, so just treat it as a normal expression and create a nested block.
        return blockExpr(gz, scope, ri, node, statements, block_kind);
    }

    var sub_gz = gz.makeSubBlock(scope);
    try blockExprStmts(&sub_gz, &sub_gz.base, statements, block_kind);

    return rvalue(gz, ri, .void_value, node);
}

const BlockKind = enum { normal, allow_branch_hint };

fn blockExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
    kind: BlockKind,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lbrace = tree.nodeMainToken(block_node);
    if (tree.isTokenPrecededByTags(lbrace, &.{ .identifier, .colon })) {
        return labeledBlockExpr(gz, scope, ri, block_node, statements, false, kind);
    }

    if (!gz.is_comptime) {
        // Since this block is unlabeled, its control flow is effectively linear and we
        // can *almost* get away with inlining the block here. However, we actually need
        // to preserve the .block for Sema, to properly pop the error return trace.

        const block_tag: Zir.Inst.Tag = .block;
        const block_inst = try gz.makeBlockInst(block_tag, block_node);
        try gz.instructions.append(astgen.gpa, block_inst);

        var block_scope = gz.makeSubBlock(scope);
        defer block_scope.unstack();

        try blockExprStmts(&block_scope, &block_scope.base, statements, kind);

        if (!block_scope.endsWithNoReturn()) {
            // As our last action before the break, "pop" the error trace if needed
            _ = try gz.addRestoreErrRetIndex(.{ .block = block_inst }, .always, block_node);
            // No `rvalue` call here, as the block result is always `void`, so we do that below.
            _ = try block_scope.addBreak(.@"break", block_inst, .void_value);
        }

        try block_scope.setBlockBody(block_inst);
    } else {
        var sub_gz = gz.makeSubBlock(scope);
        try blockExprStmts(&sub_gz, &sub_gz.base, statements, kind);
    }

    return rvalue(gz, ri, .void_value, block_node);
}

fn checkLabelRedefinition(astgen: *AstGen, parent_scope: *Scope, label: Ast.TokenIndex) !void {
    // Look for the label in the scope.
    var scope = parent_scope;
    while (true) {
        switch (scope.tag) {
            .gen_zir => {
                const gen_zir = scope.cast(GenZir).?;
                if (gen_zir.label) |prev_label| {
                    if (try astgen.tokenIdentEql(label, prev_label.token)) {
                        const label_name = try astgen.identifierTokenString(label);
                        return astgen.failTokNotes(label, "redefinition of label '{s}'", .{
                            label_name,
                        }, &[_]u32{
                            try astgen.errNoteTok(
                                prev_label.token,
                                "previous definition here",
                                .{},
                            ),
                        });
                    }
                }
                scope = gen_zir.parent;
            },
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal, .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .namespace => break,
            .top => unreachable,
        }
    }
}

fn labeledBlockExpr(
    gz: *GenZir,
    parent_scope: *Scope,
    ri: ResultInfo,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
    force_comptime: bool,
    block_kind: BlockKind,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lbrace = tree.nodeMainToken(block_node);
    const label_token = lbrace - 2;
    assert(tree.tokenTag(label_token) == .identifier);

    try astgen.checkLabelRedefinition(parent_scope, label_token);

    const need_rl = astgen.nodes_need_rl.contains(block_node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.resultType(gz, block_node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).@"union".tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    // Reserve the Block ZIR instruction index so that we can put it into the GenZir struct
    // so that break statements can reference it.
    const block_inst = try gz.makeBlockInst(if (force_comptime) .block_comptime else .block, block_node);
    try gz.instructions.append(astgen.gpa, block_inst);
    var block_scope = gz.makeSubBlock(parent_scope);
    block_scope.is_inline = force_comptime;
    block_scope.label = GenZir.Label{
        .token = label_token,
        .block_inst = block_inst,
    };
    block_scope.setBreakResultInfo(block_ri);
    if (force_comptime) block_scope.is_comptime = true;
    defer block_scope.unstack();

    try blockExprStmts(&block_scope, &block_scope.base, statements, block_kind);
    if (!block_scope.endsWithNoReturn()) {
        // As our last action before the return, "pop" the error trace if needed
        _ = try gz.addRestoreErrRetIndex(.{ .block = block_inst }, .always, block_node);
        const result = try rvalue(gz, block_scope.break_result_info, .void_value, block_node);
        const break_tag: Zir.Inst.Tag = if (force_comptime) .break_inline else .@"break";
        _ = try block_scope.addBreak(break_tag, block_inst, result);
    }

    if (!block_scope.label.?.used) {
        try astgen.appendErrorTok(label_token, "unused block label", .{});
    }

    if (force_comptime) {
        try block_scope.setBlockComptimeBody(block_inst, .comptime_keyword);
    } else {
        try block_scope.setBlockBody(block_inst);
    }

    if (need_result_rvalue) {
        return rvalue(gz, ri, block_inst.toRef(), block_node);
    } else {
        return block_inst.toRef();
    }
}

fn blockExprStmts(gz: *GenZir, parent_scope: *Scope, statements: []const Ast.Node.Index, block_kind: BlockKind) !void {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    if (statements.len == 0) return;

    var block_arena = std.heap.ArenaAllocator.init(gz.astgen.gpa);
    defer block_arena.deinit();
    const block_arena_allocator = block_arena.allocator();

    var noreturn_src_node: Ast.Node.OptionalIndex = .none;
    var scope = parent_scope;
    for (statements, 0..) |statement, stmt_idx| {
        if (noreturn_src_node.unwrap()) |src_node| {
            try astgen.appendErrorNodeNotes(
                statement,
                "unreachable code",
                .{},
                &[_]u32{
                    try astgen.errNoteNode(
                        src_node,
                        "control flow is diverted here",
                        .{},
                    ),
                },
            );
        }
        const allow_branch_hint = switch (block_kind) {
            .normal => false,
            .allow_branch_hint => stmt_idx == 0,
        };
        var inner_node = statement;
        while (true) {
            switch (tree.nodeTag(inner_node)) {
                // zig fmt: off
                .global_var_decl,
                .local_var_decl,
                .simple_var_decl,
                .aligned_var_decl, => scope = try varDecl(gz, scope, statement, block_arena_allocator, tree.fullVarDecl(statement).?),

                .assign_destructure => scope = try assignDestructureMaybeDecls(gz, scope, statement, block_arena_allocator),

                .@"defer"    => scope = try deferStmt(gz, scope, statement, block_arena_allocator, .defer_normal),
                .@"errdefer" => scope = try deferStmt(gz, scope, statement, block_arena_allocator, .defer_error),

                .assign => try assign(gz, scope, statement),

                .assign_shl => try assignShift(gz, scope, statement, .shl),
                .assign_shr => try assignShift(gz, scope, statement, .shr),

                .assign_bit_and  => try assignOp(gz, scope, statement, .bit_and),
                .assign_bit_or   => try assignOp(gz, scope, statement, .bit_or),
                .assign_bit_xor  => try assignOp(gz, scope, statement, .xor),
                .assign_div      => try assignOp(gz, scope, statement, .div),
                .assign_sub      => try assignOp(gz, scope, statement, .sub),
                .assign_sub_wrap => try assignOp(gz, scope, statement, .subwrap),
                .assign_mod      => try assignOp(gz, scope, statement, .mod_rem),
                .assign_add      => try assignOp(gz, scope, statement, .add),
                .assign_add_wrap => try assignOp(gz, scope, statement, .addwrap),
                .assign_mul      => try assignOp(gz, scope, statement, .mul),
                .assign_mul_wrap => try assignOp(gz, scope, statement, .mulwrap),

                .grouped_expression => {
                    inner_node = tree.nodeData(statement).node_and_token[0];
                    continue;
                },

                .while_simple,
                .while_cont,
                .@"while", => _ = try whileExpr(gz, scope, .{ .rl = .none }, inner_node, tree.fullWhile(inner_node).?, true),

                .for_simple,
                .@"for", => _ = try forExpr(gz, scope, .{ .rl = .none }, inner_node, tree.fullFor(inner_node).?, true),
                // zig fmt: on

                // These cases are here to allow branch hints.
                .builtin_call_two,
                .builtin_call_two_comma,
                .builtin_call,
                .builtin_call_comma,
                => {
                    var buf: [2]Ast.Node.Index = undefined;
                    const params = tree.builtinCallParams(&buf, inner_node).?;

                    try emitDbgNode(gz, inner_node);
                    const result = try builtinCall(gz, scope, .{ .rl = .none }, inner_node, params, allow_branch_hint);
                    noreturn_src_node = try addEnsureResult(gz, result, inner_node);
                },

                else => noreturn_src_node = try unusedResultExpr(gz, scope, inner_node),
            }
            break;
        }
    }

    if (noreturn_src_node == .none) {
        try genDefers(gz, parent_scope, scope, .normal_only);
    }
    try checkUsed(gz, parent_scope, scope);
}

/// Returns AST source node of the thing that is noreturn if the statement is
/// definitely `noreturn`. Otherwise returns .none.
fn unusedResultExpr(gz: *GenZir, scope: *Scope, statement: Ast.Node.Index) InnerError!Ast.Node.OptionalIndex {
    try emitDbgNode(gz, statement);
    // We need to emit an error if the result is not `noreturn` or `void`, but
    // we want to avoid adding the ZIR instruction if possible for performance.
    const maybe_unused_result = try expr(gz, scope, .{ .rl = .none }, statement);
    return addEnsureResult(gz, maybe_unused_result, statement);
}

fn addEnsureResult(gz: *GenZir, maybe_unused_result: Zir.Inst.Ref, statement: Ast.Node.Index) InnerError!Ast.Node.OptionalIndex {
    var noreturn_src_node: Ast.Node.OptionalIndex = .none;
    const elide_check = if (maybe_unused_result.toIndex()) |inst| b: {
        // Note that this array becomes invalid after appending more items to it
        // in the above while loop.
        const zir_tags = gz.astgen.instructions.items(.tag);
        switch (zir_tags[@intFromEnum(inst)]) {
            // For some instructions, modify the zir data
            // so we can avoid a separate ensure_result_used instruction.
            .call, .field_call => {
                const break_extra = gz.astgen.instructions.items(.data)[@intFromEnum(inst)].pl_node.payload_index;
                comptime assert(std.meta.fieldIndex(Zir.Inst.Call, "flags") ==
                    std.meta.fieldIndex(Zir.Inst.FieldCall, "flags"));
                const flags: *Zir.Inst.Call.Flags = @ptrCast(&gz.astgen.extra.items[
                    break_extra + std.meta.fieldIndex(Zir.Inst.Call, "flags").?
                ]);
                flags.ensure_result_used = true;
                break :b true;
            },
            .builtin_call => {
                const break_extra = gz.astgen.instructions.items(.data)[@intFromEnum(inst)].pl_node.payload_index;
                const flags: *Zir.Inst.BuiltinCall.Flags = @ptrCast(&gz.astgen.extra.items[
                    break_extra + std.meta.fieldIndex(Zir.Inst.BuiltinCall, "flags").?
                ]);
                flags.ensure_result_used = true;
                break :b true;
            },

            // ZIR instructions that might be a type other than `noreturn` or `void`.
            .add,
            .addwrap,
            .add_sat,
            .add_unsafe,
            .param,
            .param_comptime,
            .param_anytype,
            .param_anytype_comptime,
            .alloc,
            .alloc_mut,
            .alloc_comptime_mut,
            .alloc_inferred,
            .alloc_inferred_mut,
            .alloc_inferred_comptime,
            .alloc_inferred_comptime_mut,
            .make_ptr_const,
            .array_cat,
            .array_mul,
            .array_type,
            .array_type_sentinel,
            .elem_type,
            .indexable_ptr_elem_type,
            .vec_arr_elem_type,
            .vector_type,
            .indexable_ptr_len,
            .anyframe_type,
            .as_node,
            .as_shift_operand,
            .bit_and,
            .bitcast,
            .bit_or,
            .block,
            .block_comptime,
            .block_inline,
            .declaration,
            .suspend_block,
            .loop,
            .bool_br_and,
            .bool_br_or,
            .bool_not,
            .cmp_lt,
            .cmp_lte,
            .cmp_eq,
            .cmp_gte,
            .cmp_gt,
            .cmp_neq,
            .decl_ref,
            .decl_val,
            .load,
            .div,
            .elem_ptr,
            .elem_val,
            .elem_ptr_node,
            .elem_val_node,
            .elem_val_imm,
            .field_ptr,
            .field_val,
            .field_ptr_named,
            .field_val_named,
            .func,
            .func_inferred,
            .func_fancy,
            .int,
            .int_big,
            .float,
            .float128,
            .int_type,
            .is_non_null,
            .is_non_null_ptr,
            .is_non_err,
            .is_non_err_ptr,
            .ret_is_non_err,
            .mod_rem,
            .mul,
            .mulwrap,
            .mul_sat,
            .ref,
            .shl,
            .shl_sat,
            .shr,
            .str,
            .sub,
            .subwrap,
            .sub_sat,
            .negate,
            .negate_wrap,
            .typeof,
            .typeof_builtin,
            .xor,
            .optional_type,
            .optional_payload_safe,
            .optional_payload_unsafe,
            .optional_payload_safe_ptr,
            .optional_payload_unsafe_ptr,
            .err_union_payload_unsafe,
            .err_union_payload_unsafe_ptr,
            .err_union_code,
            .err_union_code_ptr,
            .ptr_type,
            .enum_literal,
            .decl_literal,
            .decl_literal_no_coerce,
            .merge_error_sets,
            .error_union_type,
            .bit_not,
            .error_value,
            .slice_start,
            .slice_end,
            .slice_sentinel,
            .slice_length,
            .slice_sentinel_ty,
            .import,
            .switch_block,
            .switch_block_ref,
            .switch_block_err_union,
            .union_init,
            .field_type_ref,
            .error_set_decl,
            .enum_from_int,
            .int_from_enum,
            .type_info,
            .size_of,
            .bit_size_of,
            .typeof_log2_int_type,
            .int_from_ptr,
            .align_of,
            .int_from_bool,
            .embed_file,
            .error_name,
            .sqrt,
            .sin,
            .cos,
            .tan,
            .exp,
            .exp2,
            .log,
            .log2,
            .log10,
            .abs,
            .floor,
            .ceil,
            .trunc,
            .round,
            .tag_name,
            .type_name,
            .frame_type,
            .frame_size,
            .int_from_float,
            .float_from_int,
            .ptr_from_int,
            .float_cast,
            .int_cast,
            .ptr_cast,
            .truncate,
            .has_decl,
            .has_field,
            .clz,
            .ctz,
            .pop_count,
            .byte_swap,
            .bit_reverse,
            .div_exact,
            .div_floor,
            .div_trunc,
            .mod,
            .rem,
            .shl_exact,
            .shr_exact,
            .bit_offset_of,
            .offset_of,
            .splat,
            .reduce,
            .shuffle,
            .atomic_load,
            .atomic_rmw,
            .mul_add,
            .max,
            .min,
            .c_import,
            .@"resume",
            .@"await",
            .ret_err_value_code,
            .ret_ptr,
            .ret_type,
            .for_len,
            .@"try",
            .try_ptr,
            .opt_eu_base_ptr_init,
            .coerce_ptr_elem_ty,
            .struct_init_empty,
            .struct_init_empty_result,
            .struct_init_empty_ref_result,
            .struct_init_anon,
            .struct_init,
            .struct_init_ref,
            .struct_init_field_type,
            .struct_init_field_ptr,
            .array_init_anon,
            .array_init,
            .array_init_ref,
            .validate_array_init_ref_ty,
            .array_init_elem_type,
            .array_init_elem_ptr,
            => break :b false,

            .extended => switch (gz.astgen.instructions.items(.data)[@intFromEnum(inst)].extended.opcode) {
                .breakpoint,
                .disable_instrumentation,
                .disable_intrinsics,
                .set_float_mode,
                .branch_hint,
                => break :b true,
                else => break :b false,
            },

            // ZIR instructions that are always `noreturn`.
            .@"break",
            .break_inline,
            .condbr,
            .condbr_inline,
            .compile_error,
            .ret_node,
            .ret_load,
            .ret_implicit,
            .ret_err_value,
            .@"unreachable",
            .repeat,
            .repeat_inline,
            .panic,
            .trap,
            .check_comptime_control_flow,
            .switch_continue,
            => {
                noreturn_src_node = statement.toOptional();
                break :b true;
            },

            // ZIR instructions that are always `void`.
            .dbg_stmt,
            .dbg_var_ptr,
            .dbg_var_val,
            .ensure_result_used,
            .ensure_result_non_error,
            .ensure_err_union_payload_void,
            .@"export",
            .set_eval_branch_quota,
            .atomic_store,
            .store_node,
            .store_to_inferred_ptr,
            .resolve_inferred_alloc,
            .set_runtime_safety,
            .memcpy,
            .memset,
            .memmove,
            .validate_deref,
            .validate_destructure,
            .save_err_ret_index,
            .restore_err_ret_index_unconditional,
            .restore_err_ret_index_fn_entry,
            .validate_struct_init_ty,
            .validate_struct_init_result_ty,
            .validate_ptr_struct_init,
            .validate_array_init_ty,
            .validate_array_init_result_ty,
            .validate_ptr_array_init,
            .validate_ref_ty,
            .validate_const,
            => break :b true,

            .@"defer" => unreachable,
            .defer_err_code => unreachable,
        }
    } else switch (maybe_unused_result) {
        .none => unreachable,

        .unreachable_value => b: {
            noreturn_src_node = statement.toOptional();
            break :b true;
        },

        .void_value => true,

        else => false,
    };
    if (!elide_check) {
        _ = try gz.addUnNode(.ensure_result_used, maybe_unused_result, statement);
    }
    return noreturn_src_node;
}

fn countDefers(outer_scope: *Scope, inner_scope: *Scope) struct {
    have_any: bool,
    have_normal: bool,
    have_err: bool,
    need_err_code: bool,
} {
    var have_normal = false;
    var have_err = false;
    var need_err_code = false;
    var scope = inner_scope;
    while (scope != outer_scope) {
        switch (scope.tag) {
            .gen_zir => scope = scope.cast(GenZir).?.parent,
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;

                have_normal = true;
            },
            .defer_error => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;

                have_err = true;

                const have_err_payload = defer_scope.remapped_err_code != .none;
                need_err_code = need_err_code or have_err_payload;
            },
            .namespace => unreachable,
            .top => unreachable,
        }
    }
    return .{
        .have_any = have_normal or have_err,
        .have_normal = have_normal,
        .have_err = have_err,
        .need_err_code = need_err_code,
    };
}

const DefersToEmit = union(enum) {
    both: Zir.Inst.Ref, // err code
    both_sans_err,
    normal_only,
};

fn genDefers(
    gz: *GenZir,
    outer_scope: *Scope,
    inner_scope: *Scope,
    which_ones: DefersToEmit,
) InnerError!void {
    const gpa = gz.astgen.gpa;

    var scope = inner_scope;
    while (scope != outer_scope) {
        switch (scope.tag) {
            .gen_zir => scope = scope.cast(GenZir).?.parent,
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;
                try gz.addDefer(defer_scope.index, defer_scope.len);
            },
            .defer_error => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;
                switch (which_ones) {
                    .both_sans_err => {
                        try gz.addDefer(defer_scope.index, defer_scope.len);
                    },
                    .both => |err_code| {
                        if (defer_scope.remapped_err_code.unwrap()) |remapped_err_code| {
                            try gz.instructions.ensureUnusedCapacity(gpa, 1);
                            try gz.astgen.instructions.ensureUnusedCapacity(gpa, 1);

                            const payload_index = try gz.astgen.addExtra(Zir.Inst.DeferErrCode{
                                .remapped_err_code = remapped_err_code,
                                .index = defer_scope.index,
                                .len = defer_scope.len,
                            });
                            const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
                            gz.astgen.instructions.appendAssumeCapacity(.{
                                .tag = .defer_err_code,
                                .data = .{ .defer_err_code = .{
                                    .err_code = err_code,
                                    .payload_index = payload_index,
                                } },
                            });
                            gz.instructions.appendAssumeCapacity(new_index);
                        } else {
                            try gz.addDefer(defer_scope.index, defer_scope.len);
                        }
                    },
                    .normal_only => continue,
                }
            },
            .namespace => unreachable,
            .top =>```
