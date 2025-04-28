```
abel_token != null) t: {
        break :t try parent_gz.addUnNode(.typeof, raw_operand, operand_node);
    } else undefined;

    // This contains the data that goes into the `extra` array for the SwitchBlock/SwitchBlockMulti,
    // except the first cases_nodes.len slots are a table that indexes payloads later in the array, with
    // the special case index coming first, then scalar_case_len indexes, then multi_cases_len indexes
    const payloads = &astgen.scratch;
    const scratch_top = astgen.scratch.items.len;
    const case_table_start = scratch_top;
    const scalar_case_table = case_table_start + @intFromBool(special_prong != .none);
    const multi_case_table = scalar_case_table + scalar_cases_len;
    const case_table_end = multi_case_table + multi_cases_len;
    try astgen.scratch.resize(gpa, case_table_end);
    defer astgen.scratch.items.len = scratch_top;

    var block_scope = parent_gz.makeSubBlock(scope);
    // block_scope not used for collecting instructions
    block_scope.instructions_top = GenZir.unstacked_top;
    block_scope.setBreakResultInfo(block_ri);

    // Sema expects a dbg_stmt immediately before switch_block(_ref)
    try emitDbgStmtForceCurrentIndex(parent_gz, operand_lc);
    // This gets added to the parent block later, after the item expressions.
    const switch_tag: Zir.Inst.Tag = if (any_payload_is_ref) .switch_block_ref else .switch_block;
    const switch_block = try parent_gz.makeBlockInst(switch_tag, node);

    if (switch_full.label_token) |label_token| {
        block_scope.continue_block = switch_block.toOptional();
        block_scope.continue_result_info = .{
            .rl = if (any_payload_is_ref)
                .{ .ref_coerced_ty = raw_operand_ty_ref }
            else
                .{ .coerced_ty = raw_operand_ty_ref },
        };

        block_scope.label = .{
            .token = label_token,
            .block_inst = switch_block,
        };
        // `break` can target this via `label.block_inst`
        // `break_result_info` already set by `setBreakResultInfo`
    }

    // We re-use this same scope for all cases, including the special prong, if any.
    var case_scope = parent_gz.makeSubBlock(&block_scope.base);
    case_scope.instructions_top = GenZir.unstacked_top;

    // If any prong has an inline tag capture, allocate a shared dummy instruction for it
    const tag_inst = if (any_has_tag_capture) tag_inst: {
        const inst: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        try astgen.instructions.append(astgen.gpa, .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .value_placeholder,
                .small = undefined,
                .operand = undefined,
            } },
        });
        break :tag_inst inst;
    } else undefined;

    // In this pass we generate all the item and prong expressions.
    var multi_case_index: u32 = 0;
    var scalar_case_index: u32 = 0;
    for (case_nodes) |case_node| {
        const case = tree.fullSwitchCase(case_node).?;

        const is_multi_case = case.ast.values.len > 1 or
            (case.ast.values.len == 1 and tree.nodeTag(case.ast.values[0]) == .switch_range);

        var dbg_var_name: Zir.NullTerminatedString = .empty;
        var dbg_var_inst: Zir.Inst.Ref = undefined;
        var dbg_var_tag_name: Zir.NullTerminatedString = .empty;
        var dbg_var_tag_inst: Zir.Inst.Ref = undefined;
        var has_tag_capture = false;
        var capture_val_scope: Scope.LocalVal = undefined;
        var tag_scope: Scope.LocalVal = undefined;

        var capture: Zir.Inst.SwitchBlock.ProngInfo.Capture = .none;

        const sub_scope = blk: {
            const payload_token = case.payload_token orelse break :blk &case_scope.base;
            const capture_is_ref = tree.tokenTag(payload_token) == .asterisk;
            const ident = payload_token + @intFromBool(capture_is_ref);

            capture = if (capture_is_ref) .by_ref else .by_val;

            const ident_slice = tree.tokenSlice(ident);
            var payload_sub_scope: *Scope = undefined;
            if (mem.eql(u8, ident_slice, "_")) {
                if (capture_is_ref) {
                    return astgen.failTok(payload_token, "pointer modifier invalid on discard", .{});
                }
                payload_sub_scope = &case_scope.base;
            } else {
                const capture_name = try astgen.identAsString(ident);
                try astgen.detectLocalShadowing(&case_scope.base, capture_name, ident, ident_slice, .capture);
                capture_val_scope = .{
                    .parent = &case_scope.base,
                    .gen_zir = &case_scope,
                    .name = capture_name,
                    .inst = switch_block.toRef(),
                    .token_src = ident,
                    .id_cat = .capture,
                };
                dbg_var_name = capture_name;
                dbg_var_inst = switch_block.toRef();
                payload_sub_scope = &capture_val_scope.base;
            }

            const tag_token = if (tree.tokenTag(ident + 1) == .comma)
                ident + 2
            else
                break :blk payload_sub_scope;
            const tag_slice = tree.tokenSlice(tag_token);
            if (mem.eql(u8, tag_slice, "_")) {
                try astgen.appendErrorTok(tag_token, "discard of tag capture; omit it instead", .{});
            } else if (case.inline_token == null) {
                return astgen.failTok(tag_token, "tag capture on non-inline prong", .{});
            }
            const tag_name = try astgen.identAsString(tag_token);
            try astgen.detectLocalShadowing(payload_sub_scope, tag_name, tag_token, tag_slice, .@"switch tag capture");

            assert(any_has_tag_capture);
            has_tag_capture = true;

            tag_scope = .{
                .parent = payload_sub_scope,
                .gen_zir = &case_scope,
                .name = tag_name,
                .inst = tag_inst.toRef(),
                .token_src = tag_token,
                .id_cat = .@"switch tag capture",
            };
            dbg_var_tag_name = tag_name;
            dbg_var_tag_inst = tag_inst.toRef();
            break :blk &tag_scope.base;
        };

        const header_index: u32 = @intCast(payloads.items.len);
        const body_len_index = if (is_multi_case) blk: {
            payloads.items[multi_case_table + multi_case_index] = header_index;
            multi_case_index += 1;
            try payloads.resize(gpa, header_index + 3); // items_len, ranges_len, body_len

            // items
            var items_len: u32 = 0;
            for (case.ast.values) |item_node| {
                if (tree.nodeTag(item_node) == .switch_range) continue;
                items_len += 1;

                const item_inst = try comptimeExpr(parent_gz, scope, item_ri, item_node, .switch_item);
                try payloads.append(gpa, @intFromEnum(item_inst));
            }

            // ranges
            var ranges_len: u32 = 0;
            for (case.ast.values) |range| {
                if (tree.nodeTag(range) != .switch_range) continue;
                ranges_len += 1;

                const first_node, const last_node = tree.nodeData(range).node_and_node;
                const first = try comptimeExpr(parent_gz, scope, item_ri, first_node, .switch_item);
                const last = try comptimeExpr(parent_gz, scope, item_ri, last_node, .switch_item);
                try payloads.appendSlice(gpa, &[_]u32{
                    @intFromEnum(first), @intFromEnum(last),
                });
            }

            payloads.items[header_index] = items_len;
            payloads.items[header_index + 1] = ranges_len;
            break :blk header_index + 2;
        } else if (case_node.toOptional() == special_node) blk: {
            payloads.items[case_table_start] = header_index;
            try payloads.resize(gpa, header_index + 1); // body_len
            break :blk header_index;
        } else blk: {
            payloads.items[scalar_case_table + scalar_case_index] = header_index;
            scalar_case_index += 1;
            try payloads.resize(gpa, header_index + 2); // item, body_len
            const item_node = case.ast.values[0];
            const item_inst = try comptimeExpr(parent_gz, scope, item_ri, item_node, .switch_item);
            payloads.items[header_index] = @intFromEnum(item_inst);
            break :blk header_index + 1;
        };

        {
            // temporarily stack case_scope on parent_gz
            case_scope.instructions_top = parent_gz.instructions.items.len;
            defer case_scope.unstack();

            if (dbg_var_name != .empty) {
                try case_scope.addDbgVar(.dbg_var_val, dbg_var_name, dbg_var_inst);
            }
            if (dbg_var_tag_name != .empty) {
                try case_scope.addDbgVar(.dbg_var_val, dbg_var_tag_name, dbg_var_tag_inst);
            }
            const target_expr_node = case.ast.target_expr;
            const case_result = try fullBodyExpr(&case_scope, sub_scope, block_scope.break_result_info, target_expr_node, .allow_branch_hint);
            try checkUsed(parent_gz, &case_scope.base, sub_scope);
            if (!parent_gz.refIsNoReturn(case_result)) {
                _ = try case_scope.addBreakWithSrcNode(.@"break", switch_block, case_result, target_expr_node);
            }

            const case_slice = case_scope.instructionsSlice();
            const extra_insts: []const Zir.Inst.Index = if (has_tag_capture) &.{ switch_block, tag_inst } else &.{switch_block};
            const body_len = astgen.countBodyLenAfterFixupsExtraRefs(case_slice, extra_insts);
            try payloads.ensureUnusedCapacity(gpa, body_len);
            payloads.items[body_len_index] = @bitCast(Zir.Inst.SwitchBlock.ProngInfo{
                .body_len = @intCast(body_len),
                .capture = capture,
                .is_inline = case.inline_token != null,
                .has_tag_capture = has_tag_capture,
            });
            appendBodyWithFixupsExtraRefsArrayList(astgen, payloads, case_slice, extra_insts);
        }
    }

    if (switch_full.label_token) |label_token| if (!block_scope.label.?.used) {
        try astgen.appendErrorTok(label_token, "unused switch label", .{});
    };

    // Now that the item expressions are generated we can add this.
    try parent_gz.instructions.append(gpa, switch_block);

    try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.SwitchBlock).@"struct".fields.len +
        @intFromBool(multi_cases_len != 0) +
        @intFromBool(any_has_tag_capture) +
        payloads.items.len - case_table_end +
        (case_table_end - case_table_start) * @typeInfo(Zir.Inst.As).@"struct".fields.len);

    const payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.SwitchBlock{
        .operand = raw_operand,
        .bits = Zir.Inst.SwitchBlock.Bits{
            .has_multi_cases = multi_cases_len != 0,
            .has_else = special_prong == .@"else",
            .has_under = special_prong == .under,
            .any_has_tag_capture = any_has_tag_capture,
            .any_non_inline_capture = any_non_inline_capture,
            .has_continue = switch_full.label_token != null and block_scope.label.?.used_for_continue,
            .scalar_cases_len = @intCast(scalar_cases_len),
        },
    });

    if (multi_cases_len != 0) {
        astgen.extra.appendAssumeCapacity(multi_cases_len);
    }

    if (any_has_tag_capture) {
        astgen.extra.appendAssumeCapacity(@intFromEnum(tag_inst));
    }

    const zir_datas = astgen.instructions.items(.data);
    zir_datas[@intFromEnum(switch_block)].pl_node.payload_index = payload_index;

    for (payloads.items[case_table_start..case_table_end], 0..) |start_index, i| {
        var body_len_index = start_index;
        var end_index = start_index;
        const table_index = case_table_start + i;
        if (table_index < scalar_case_table) {
            end_index += 1;
        } else if (table_index < multi_case_table) {
            body_len_index += 1;
            end_index += 2;
        } else {
            body_len_index += 2;
            const items_len = payloads.items[start_index];
            const ranges_len = payloads.items[start_index + 1];
            end_index += 3 + items_len + 2 * ranges_len;
        }
        const prong_info: Zir.Inst.SwitchBlock.ProngInfo = @bitCast(payloads.items[body_len_index]);
        end_index += prong_info.body_len;
        astgen.extra.appendSliceAssumeCapacity(payloads.items[start_index..end_index]);
    }

    if (need_result_rvalue) {
        return rvalue(parent_gz, ri, switch_block.toRef(), node);
    } else {
        return switch_block.toRef();
    }
}

fn ret(gz: *GenZir, scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    if (astgen.fn_block == null) {
        return astgen.failNode(node, "'return' outside function scope", .{});
    }

    if (gz.any_defer_node.unwrap()) |any_defer_node| {
        return astgen.failNodeNotes(node, "cannot return from defer expression", .{}, &.{
            try astgen.errNoteNode(
                any_defer_node,
                "defer expression here",
                .{},
            ),
        });
    }

    // Ensure debug line/column information is emitted for this return expression.
    // Then we will save the line/column so that we can emit another one that goes
    // "backwards" because we want to evaluate the operand, but then put the debug
    // info back at the return keyword for error return tracing.
    if (!gz.is_comptime) {
        try emitDbgNode(gz, node);
    }
    const ret_lc: LineColumn = .{ astgen.source_line - gz.decl_line, astgen.source_column };

    const defer_outer = &astgen.fn_block.?.base;

    const operand_node = tree.nodeData(node).opt_node.unwrap() orelse {
        // Returning a void value; skip error defers.
        try genDefers(gz, defer_outer, scope, .normal_only);

        // As our last action before the return, "pop" the error trace if needed
        _ = try gz.addRestoreErrRetIndex(.ret, .always, node);

        _ = try gz.addUnNode(.ret_node, .void_value, node);
        return Zir.Inst.Ref.unreachable_value;
    };

    if (tree.nodeTag(operand_node) == .error_value) {
        // Hot path for `return error.Foo`. This bypasses result location logic as well as logic
        // for detecting whether to add something to the function's inferred error set.
        const ident_token = tree.nodeMainToken(operand_node) + 2;
        const err_name_str_index = try astgen.identAsString(ident_token);
        const defer_counts = countDefers(defer_outer, scope);
        if (!defer_counts.need_err_code) {
            try genDefers(gz, defer_outer, scope, .both_sans_err);
            try emitDbgStmt(gz, ret_lc);
            _ = try gz.addStrTok(.ret_err_value, err_name_str_index, ident_token);
            return Zir.Inst.Ref.unreachable_value;
        }
        const err_code = try gz.addStrTok(.ret_err_value_code, err_name_str_index, ident_token);
        try genDefers(gz, defer_outer, scope, .{ .both = err_code });
        try emitDbgStmt(gz, ret_lc);
        _ = try gz.addUnNode(.ret_node, err_code, node);
        return Zir.Inst.Ref.unreachable_value;
    }

    const ri: ResultInfo = if (astgen.nodes_need_rl.contains(node)) .{
        .rl = .{ .ptr = .{ .inst = try gz.addNode(.ret_ptr, node) } },
        .ctx = .@"return",
    } else .{
        .rl = .{ .coerced_ty = astgen.fn_ret_ty },
        .ctx = .@"return",
    };
    const prev_anon_name_strategy = gz.anon_name_strategy;
    gz.anon_name_strategy = .func;
    const operand = try reachableExpr(gz, scope, ri, operand_node, node);
    gz.anon_name_strategy = prev_anon_name_strategy;

    switch (nodeMayEvalToError(tree, operand_node)) {
        .never => {
            // Returning a value that cannot be an error; skip error defers.
            try genDefers(gz, defer_outer, scope, .normal_only);

            // As our last action before the return, "pop" the error trace if needed
            _ = try gz.addRestoreErrRetIndex(.ret, .always, node);

            try emitDbgStmt(gz, ret_lc);
            try gz.addRet(ri, operand, node);
            return Zir.Inst.Ref.unreachable_value;
        },
        .always => {
            // Value is always an error. Emit both error defers and regular defers.
            const err_code = if (ri.rl == .ptr) try gz.addUnNode(.load, ri.rl.ptr.inst, node) else operand;
            try genDefers(gz, defer_outer, scope, .{ .both = err_code });
            try emitDbgStmt(gz, ret_lc);
            try gz.addRet(ri, operand, node);
            return Zir.Inst.Ref.unreachable_value;
        },
        .maybe => {
            const defer_counts = countDefers(defer_outer, scope);
            if (!defer_counts.have_err) {
                // Only regular defers; no branch needed.
                try genDefers(gz, defer_outer, scope, .normal_only);
                try emitDbgStmt(gz, ret_lc);

                // As our last action before the return, "pop" the error trace if needed
                const result = if (ri.rl == .ptr) try gz.addUnNode(.load, ri.rl.ptr.inst, node) else operand;
                _ = try gz.addRestoreErrRetIndex(.ret, .{ .if_non_error = result }, node);

                try gz.addRet(ri, operand, node);
                return Zir.Inst.Ref.unreachable_value;
            }

            // Emit conditional branch for generating errdefers.
            const result = if (ri.rl == .ptr) try gz.addUnNode(.load, ri.rl.ptr.inst, node) else operand;
            const is_non_err = try gz.addUnNode(.ret_is_non_err, result, node);
            const condbr = try gz.addCondBr(.condbr, node);

            var then_scope = gz.makeSubBlock(scope);
            defer then_scope.unstack();

            try genDefers(&then_scope, defer_outer, scope, .normal_only);

            // As our last action before the return, "pop" the error trace if needed
            _ = try then_scope.addRestoreErrRetIndex(.ret, .always, node);

            try emitDbgStmt(&then_scope, ret_lc);
            try then_scope.addRet(ri, operand, node);

            var else_scope = gz.makeSubBlock(scope);
            defer else_scope.unstack();

            const which_ones: DefersToEmit = if (!defer_counts.need_err_code) .both_sans_err else .{
                .both = try else_scope.addUnNode(.err_union_code, result, node),
            };
            try genDefers(&else_scope, defer_outer, scope, which_ones);
            try emitDbgStmt(&else_scope, ret_lc);
            try else_scope.addRet(ri, operand, node);

            try setCondBrPayload(condbr, is_non_err, &then_scope, &else_scope);

            return Zir.Inst.Ref.unreachable_value;
        },
    }
}

/// Parses the string `buf` as a base 10 integer of type `u16`.
///
/// Unlike std.fmt.parseInt, does not allow the '_' character in `buf`.
fn parseBitCount(buf: []const u8) std.fmt.ParseIntError!u16 {
    if (buf.len == 0) return error.InvalidCharacter;

    var x: u16 = 0;

    for (buf) |c| {
        const digit = switch (c) {
            '0'...'9' => c - '0',
            else => return error.InvalidCharacter,
        };

        if (x != 0) x = try std.math.mul(u16, x, 10);
        x = try std.math.add(u16, x, digit);
    }

    return x;
}

const ComptimeBlockInfo = struct {
    src_node: Ast.Node.Index,
    reason: std.zig.SimpleComptimeReason,
};

fn identifier(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    ident: Ast.Node.Index,
    force_comptime: ?ComptimeBlockInfo,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const ident_token = tree.nodeMainToken(ident);
    const ident_name_raw = tree.tokenSlice(ident_token);
    if (mem.eql(u8, ident_name_raw, "_")) {
        return astgen.failNode(ident, "'_' used as an identifier without @\"_\" syntax", .{});
    }

    // if not @"" syntax, just use raw token slice
    if (ident_name_raw[0] != '@') {
        if (primitive_instrs.get(ident_name_raw)) |zir_const_ref| {
            return rvalue(gz, ri, zir_const_ref, ident);
        }

        if (ident_name_raw.len >= 2) integer: {
            // Keep in sync with logic in `comptimeExpr2`.
            const first_c = ident_name_raw[0];
            if (first_c == 'i' or first_c == 'u') {
                const signedness: std.builtin.Signedness = switch (first_c == 'i') {
                    true => .signed,
                    false => .unsigned,
                };
                if (ident_name_raw.len >= 3 and ident_name_raw[1] == '0') {
                    return astgen.failNode(
                        ident,
                        "primitive integer type '{s}' has leading zero",
                        .{ident_name_raw},
                    );
                }
                const bit_count = parseBitCount(ident_name_raw[1..]) catch |err| switch (err) {
                    error.Overflow => return astgen.failNode(
                        ident,
                        "primitive integer type '{s}' exceeds maximum bit width of 65535",
                        .{ident_name_raw},
                    ),
                    error.InvalidCharacter => break :integer,
                };
                const result = try gz.add(.{
                    .tag = .int_type,
                    .data = .{ .int_type = .{
                        .src_node = gz.nodeIndexToRelative(ident),
                        .signedness = signedness,
                        .bit_count = bit_count,
                    } },
                });
                return rvalue(gz, ri, result, ident);
            }
        }
    }

    // Local variables, including function parameters, and container-level declarations.

    if (force_comptime) |fc| {
        // Mirrors the logic at the end of `comptimeExpr2`.
        const block_inst = try gz.makeBlockInst(.block_comptime, fc.src_node);

        var comptime_gz = gz.makeSubBlock(scope);
        comptime_gz.is_comptime = true;
        defer comptime_gz.unstack();

        const sub_ri: ResultInfo = .{
            .ctx = ri.ctx,
            .rl = .none, // no point providing a result type, it won't change anything
        };
        const block_result = try localVarRef(&comptime_gz, scope, sub_ri, ident, ident_token);
        assert(!comptime_gz.endsWithNoReturn());
        _ = try comptime_gz.addBreak(.break_inline, block_inst, block_result);

        try comptime_gz.setBlockComptimeBody(block_inst, fc.reason);
        try gz.instructions.append(astgen.gpa, block_inst);

        return rvalue(gz, ri, block_inst.toRef(), fc.src_node);
    } else {
        return localVarRef(gz, scope, ri, ident, ident_token);
    }
}

fn localVarRef(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    ident: Ast.Node.Index,
    ident_token: Ast.TokenIndex,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const name_str_index = try astgen.identAsString(ident_token);
    var s = scope;
    var found_already: ?Ast.Node.Index = null; // we have found a decl with the same name already
    var found_needs_tunnel: bool = undefined; // defined when `found_already != null`
    var found_namespaces_out: u32 = undefined; // defined when `found_already != null`

    // The number of namespaces above `gz` we currently are
    var num_namespaces_out: u32 = 0;
    // defined by `num_namespaces_out != 0`
    var capturing_namespace: *Scope.Namespace = undefined;

    while (true) switch (s.tag) {
        .local_val => {
            const local_val = s.cast(Scope.LocalVal).?;

            if (local_val.name == name_str_index) {
                // Locals cannot shadow anything, so we do not need to look for ambiguous
                // references in this case.
                if (ri.rl == .discard and ri.ctx == .assignment) {
                    local_val.discarded = .fromToken(ident_token);
                } else {
                    local_val.used = .fromToken(ident_token);
                }

                if (local_val.is_used_or_discarded) |ptr| ptr.* = true;

                const value_inst = if (num_namespaces_out != 0) try tunnelThroughClosure(
                    gz,
                    ident,
                    num_namespaces_out,
                    .{ .ref = local_val.inst },
                    .{ .token = local_val.token_src },
                    name_str_index,
                ) else local_val.inst;

                return rvalueNoCoercePreRef(gz, ri, value_inst, ident);
            }
            s = local_val.parent;
        },
        .local_ptr => {
            const local_ptr = s.cast(Scope.LocalPtr).?;
            if (local_ptr.name == name_str_index) {
                if (ri.rl == .discard and ri.ctx == .assignment) {
                    local_ptr.discarded = .fromToken(ident_token);
                } else {
                    local_ptr.used = .fromToken(ident_token);
                }

                // Can't close over a runtime variable
                if (num_namespaces_out != 0 and !local_ptr.maybe_comptime and !gz.is_typeof) {
                    const ident_name = try astgen.identifierTokenString(ident_token);
                    return astgen.failNodeNotes(ident, "mutable '{s}' not accessible from here", .{ident_name}, &.{
                        try astgen.errNoteTok(local_ptr.token_src, "declared mutable here", .{}),
                        try astgen.errNoteNode(capturing_namespace.node, "crosses namespace boundary here", .{}),
                    });
                }

                switch (ri.rl) {
                    .ref, .ref_coerced_ty => {
                        const ptr_inst = if (num_namespaces_out != 0) try tunnelThroughClosure(
                            gz,
                            ident,
                            num_namespaces_out,
                            .{ .ref = local_ptr.ptr },
                            .{ .token = local_ptr.token_src },
                            name_str_index,
                        ) else local_ptr.ptr;
                        local_ptr.used_as_lvalue = true;
                        return ptr_inst;
                    },
                    else => {
                        const val_inst = if (num_namespaces_out != 0) try tunnelThroughClosure(
                            gz,
                            ident,
                            num_namespaces_out,
                            .{ .ref_load = local_ptr.ptr },
                            .{ .token = local_ptr.token_src },
                            name_str_index,
                        ) else try gz.addUnNode(.load, local_ptr.ptr, ident);
                        return rvalueNoCoercePreRef(gz, ri, val_inst, ident);
                    },
                }
            }
            s = local_ptr.parent;
        },
        .gen_zir => s = s.cast(GenZir).?.parent,
        .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
        .namespace => {
            const ns = s.cast(Scope.Namespace).?;
            if (ns.decls.get(name_str_index)) |i| {
                if (found_already) |f| {
                    return astgen.failNodeNotes(ident, "ambiguous reference", .{}, &.{
                        try astgen.errNoteNode(f, "declared here", .{}),
                        try astgen.errNoteNode(i, "also declared here", .{}),
                    });
                }
                // We found a match but must continue looking for ambiguous references to decls.
                found_already = i;
                found_needs_tunnel = ns.maybe_generic;
                found_namespaces_out = num_namespaces_out;
            }
            num_namespaces_out += 1;
            capturing_namespace = ns;
            s = ns.parent;
        },
        .top => break,
    };
    if (found_already == null) {
        const ident_name = try astgen.identifierTokenString(ident_token);
        return astgen.failNode(ident, "use of undeclared identifier '{s}'", .{ident_name});
    }

    // Decl references happen by name rather than ZIR index so that when unrelated
    // decls are modified, ZIR code containing references to them can be unmodified.

    if (found_namespaces_out > 0 and found_needs_tunnel) {
        switch (ri.rl) {
            .ref, .ref_coerced_ty => return tunnelThroughClosure(
                gz,
                ident,
                found_namespaces_out,
                .{ .decl_ref = name_str_index },
                .{ .node = found_already.? },
                name_str_index,
            ),
            else => {
                const result = try tunnelThroughClosure(
                    gz,
                    ident,
                    found_namespaces_out,
                    .{ .decl_val = name_str_index },
                    .{ .node = found_already.? },
                    name_str_index,
                );
                return rvalueNoCoercePreRef(gz, ri, result, ident);
            },
        }
    }

    switch (ri.rl) {
        .ref, .ref_coerced_ty => return gz.addStrTok(.decl_ref, name_str_index, ident_token),
        else => {
            const result = try gz.addStrTok(.decl_val, name_str_index, ident_token);
            return rvalueNoCoercePreRef(gz, ri, result, ident);
        },
    }
}

/// Access a ZIR instruction through closure. May tunnel through arbitrarily
/// many namespaces, adding closure captures as required.
/// Returns the index of the `closure_get` instruction added to `gz`.
fn tunnelThroughClosure(
    gz: *GenZir,
    /// The node which references the value to be captured.
    inner_ref_node: Ast.Node.Index,
    /// The number of namespaces being tunnelled through. At least 1.
    num_tunnels: u32,
    /// The value being captured.
    value: union(enum) {
        ref: Zir.Inst.Ref,
        ref_load: Zir.Inst.Ref,
        decl_val: Zir.NullTerminatedString,
        decl_ref: Zir.NullTerminatedString,
    },
    /// The location of the value's declaration.
    decl_src: union(enum) {
        token: Ast.TokenIndex,
        node: Ast.Node.Index,
    },
    name_str_index: Zir.NullTerminatedString,
) !Zir.Inst.Ref {
    switch (value) {
        .ref => |v| if (v.toIndex() == null) return v, // trivial value; do not need tunnel
        .ref_load => |v| assert(v.toIndex() != null), // there are no constant pointer refs
        .decl_val, .decl_ref => {},
    }

    const astgen = gz.astgen;
    const gpa = astgen.gpa;

    // Otherwise we need a tunnel. First, figure out the path of namespaces we
    // are tunneling through. This is usually only going to be one or two, so
    // use an SFBA to optimize for the common case.
    var sfba = std.heap.stackFallback(@sizeOf(usize) * 2, astgen.arena);
    var intermediate_tunnels = try sfba.get().alloc(*Scope.Namespace, num_tunnels - 1);

    const root_ns = ns: {
        var i: usize = num_tunnels - 1;
        var scope: *Scope = gz.parent;
        while (i > 0) {
            if (scope.cast(Scope.Namespace)) |mid_ns| {
                i -= 1;
                intermediate_tunnels[i] = mid_ns;
            }
            scope = scope.parent().?;
        }
        while (true) {
            if (scope.cast(Scope.Namespace)) |ns| break :ns ns;
            scope = scope.parent().?;
        }
    };

    // Now that we know the scopes we're tunneling through, begin adding
    // captures as required, starting with the outermost namespace.
    const root_capture: Zir.Inst.Capture = .wrap(switch (value) {
        .ref => |v| .{ .instruction = v.toIndex().? },
        .ref_load => |v| .{ .instruction_load = v.toIndex().? },
        .decl_val => |str| .{ .decl_val = str },
        .decl_ref => |str| .{ .decl_ref = str },
    });

    const root_gop = try root_ns.captures.getOrPut(gpa, root_capture);
    root_gop.value_ptr.* = name_str_index;
    var cur_capture_index = std.math.cast(u16, root_gop.index) orelse return astgen.failNodeNotes(
        root_ns.node,
        "this compiler implementation only supports up to 65536 captures per namespace",
        .{},
        &.{
            switch (decl_src) {
                .token => |t| try astgen.errNoteTok(t, "captured value here", .{}),
                .node => |n| try astgen.errNoteNode(n, "captured value here", .{}),
            },
            try astgen.errNoteNode(inner_ref_node, "value used here", .{}),
        },
    );

    for (intermediate_tunnels) |tunnel_ns| {
        const tunnel_gop = try tunnel_ns.captures.getOrPut(gpa, .wrap(.{ .nested = cur_capture_index }));
        tunnel_gop.value_ptr.* = name_str_index;
        cur_capture_index = std.math.cast(u16, tunnel_gop.index) orelse return astgen.failNodeNotes(
            tunnel_ns.node,
            "this compiler implementation only supports up to 65536 captures per namespace",
            .{},
            &.{
                switch (decl_src) {
                    .token => |t| try astgen.errNoteTok(t, "captured value here", .{}),
                    .node => |n| try astgen.errNoteNode(n, "captured value here", .{}),
                },
                try astgen.errNoteNode(inner_ref_node, "value used here", .{}),
            },
        );
    }

    // Incorporate the capture index into the source hash, so that changes in
    // the order of captures cause suitable re-analysis.
    astgen.src_hasher.update(std.mem.asBytes(&cur_capture_index));

    // Add an instruction to get the value from the closure.
    return gz.addExtendedNodeSmall(.closure_get, inner_ref_node, cur_capture_index);
}

fn stringLiteral(
    gz: *GenZir,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const str_lit_token = tree.nodeMainToken(node);
    const str = try astgen.strLitAsString(str_lit_token);
    const result = try gz.add(.{
        .tag = .str,
        .data = .{ .str = .{
            .start = str.index,
            .len = str.len,
        } },
    });
    return rvalue(gz, ri, result, node);
}

fn multilineStringLiteral(
    gz: *GenZir,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const str = try astgen.strLitNodeAsString(node);
    const result = try gz.add(.{
        .tag = .str,
        .data = .{ .str = .{
            .start = str.index,
            .len = str.len,
        } },
    });
    return rvalue(gz, ri, result, node);
}

fn charLiteral(gz: *GenZir, ri: ResultInfo, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_token = tree.nodeMainToken(node);
    const slice = tree.tokenSlice(main_token);

    switch (std.zig.parseCharLiteral(slice)) {
        .success => |codepoint| {
            const result = try gz.addInt(codepoint);
            return rvalue(gz, ri, result, node);
        },
        .failure => |err| return astgen.failWithStrLitError(err, main_token, slice, 0),
    }
}

const Sign = enum { negative, positive };

fn numberLiteral(gz: *GenZir, ri: ResultInfo, node: Ast.Node.Index, source_node: Ast.Node.Index, sign: Sign) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const num_token = tree.nodeMainToken(node);
    const bytes = tree.tokenSlice(num_token);

    const result: Zir.Inst.Ref = switch (std.zig.parseNumberLiteral(bytes)) {
        .int => |num| switch (num) {
            0 => if (sign == .positive) .zero else return astgen.failTokNotes(
                num_token,
                "integer literal '-0' is ambiguous",
                .{},
                &.{
                    try astgen.errNoteTok(num_token, "use '0' for an integer zero", .{}),
                    try astgen.errNoteTok(num_token, "use '-0.0' for a floating-point signed zero", .{}),
                },
            ),
            1 => {
                // Handle the negation here!
                const result: Zir.Inst.Ref = switch (sign) {
                    .positive => .one,
                    .negative => .negative_one,
                };
                return rvalue(gz, ri, result, source_node);
            },
            else => try gz.addInt(num),
        },
        .big_int => |base| big: {
            const gpa = astgen.gpa;
            var big_int = try std.math.big.int.Managed.init(gpa);
            defer big_int.deinit();
            const prefix_offset: usize = if (base == .decimal) 0 else 2;
            big_int.setString(@intFromEnum(base), bytes[prefix_offset..]) catch |err| switch (err) {
                error.InvalidCharacter => unreachable, // caught in `parseNumberLiteral`
                error.InvalidBase => unreachable, // we only pass 16, 8, 2, see above
                error.OutOfMemory => return error.OutOfMemory,
            };

            const limbs = big_int.limbs[0..big_int.len()];
            assert(big_int.isPositive());
            break :big try gz.addIntBig(limbs);
        },
        .float => {
            const unsigned_float_number = std.fmt.parseFloat(f128, bytes) catch |err| switch (err) {
                error.InvalidCharacter => unreachable, // validated by tokenizer
            };
            const float_number = switch (sign) {
                .negative => -unsigned_float_number,
                .positive => unsigned_float_number,
            };
            // If the value fits into a f64 without losing any precision, store it that way.
            @setFloatMode(.strict);
            const smaller_float: f64 = @floatCast(float_number);
            const bigger_again: f128 = smaller_float;
            if (bigger_again == float_number) {
                const result = try gz.addFloat(smaller_float);
                return rvalue(gz, ri, result, source_node);
            }
            // We need to use 128 bits. Break the float into 4 u32 values so we can
            // put it into the `extra` array.
            const int_bits: u128 = @bitCast(float_number);
            const result = try gz.addPlNode(.float128, node, Zir.Inst.Float128{
                .piece0 = @truncate(int_bits),
                .piece1 = @truncate(int_bits >> 32),
                .piece2 = @truncate(int_bits >> 64),
                .piece3 = @truncate(int_bits >> 96),
            });
            return rvalue(gz, ri, result, source_node);
        },
        .failure => |err| return astgen.failWithNumberError(err, num_token, bytes),
    };

    if (sign == .positive) {
        return rvalue(gz, ri, result, source_node);
    } else {
        const negated = try gz.addUnNode(.negate, result, source_node);
        return rvalue(gz, ri, negated, source_node);
    }
}

fn failWithNumberError(astgen: *AstGen, err: std.zig.number_literal.Error, token: Ast.TokenIndex, bytes: []const u8) InnerError {
    const is_float = std.mem.indexOfScalar(u8, bytes, '.') != null;
    switch (err) {
        .leading_zero => if (is_float) {
            return astgen.failTok(token, "number '{s}' has leading zero", .{bytes});
        } else {
            return astgen.failTokNotes(token, "number '{s}' has leading zero", .{bytes}, &.{
                try astgen.errNoteTok(token, "use '0o' prefix for octal literals", .{}),
            });
        },
        .digit_after_base => return astgen.failTok(token, "expected a digit after base prefix", .{}),
        .upper_case_base => |i| return astgen.failOff(token, @intCast(i), "base prefix must be lowercase", .{}),
        .invalid_float_base => |i| return astgen.failOff(token, @intCast(i), "invalid base for float literal", .{}),
        .repeated_underscore => |i| return astgen.failOff(token, @intCast(i), "repeated digit separator", .{}),
        .invalid_underscore_after_special => |i| return astgen.failOff(token, @intCast(i), "expected digit before digit separator", .{}),
        .invalid_digit => |info| return astgen.failOff(token, @intCast(info.i), "invalid digit '{c}' for {s} base", .{ bytes[info.i], @tagName(info.base) }),
        .invalid_digit_exponent => |i| return astgen.failOff(token, @intCast(i), "invalid digit '{c}' in exponent", .{bytes[i]}),
        .duplicate_exponent => |i| return astgen.failOff(token, @intCast(i), "duplicate exponent", .{}),
        .exponent_after_underscore => |i| return astgen.failOff(token, @intCast(i), "expected digit before exponent", .{}),
        .special_after_underscore => |i| return astgen.failOff(token, @intCast(i), "expected digit before '{c}'", .{bytes[i]}),
        .trailing_special => |i| return astgen.failOff(token, @intCast(i), "expected digit after '{c}'", .{bytes[i - 1]}),
        .trailing_underscore => |i| return astgen.failOff(token, @intCast(i), "trailing digit separator", .{}),
        .duplicate_period => unreachable, // Validated by tokenizer
        .invalid_character => unreachable, // Validated by tokenizer
        .invalid_exponent_sign => |i| {
            assert(bytes.len >= 2 and bytes[0] == '0' and bytes[1] == 'x'); // Validated by tokenizer
            return astgen.failOff(token, @intCast(i), "sign '{c}' cannot follow digit '{c}' in hex base", .{ bytes[i], bytes[i - 1] });
        },
        .period_after_exponent => |i| return astgen.failOff(token, @intCast(i), "unexpected period after exponent", .{}),
    }
}

fn asmExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    full: Ast.full.Asm,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const TagAndTmpl = struct { tag: Zir.Inst.Extended, tmpl: Zir.NullTerminatedString };
    const tag_and_tmpl: TagAndTmpl = switch (tree.nodeTag(full.ast.template)) {
        .string_literal => .{
            .tag = .@"asm",
            .tmpl = (try astgen.strLitAsString(tree.nodeMainToken(full.ast.template))).index,
        },
        .multiline_string_literal => .{
            .tag = .@"asm",
            .tmpl = (try astgen.strLitNodeAsString(full.ast.template)).index,
        },
        else => .{
            .tag = .asm_expr,
            .tmpl = @enumFromInt(@intFromEnum(try comptimeExpr(gz, scope, .{ .rl = .none }, full.ast.template, .inline_assembly_code))),
        },
    };

    // See https://github.com/ziglang/zig/issues/215 and related issues discussing
    // possible inline assembly improvements. Until then here is status quo AstGen
    // for assembly syntax. It's used by std lib crypto aesni.zig.
    const is_container_asm = astgen.fn_block == null;
    if (is_container_asm) {
        if (full.volatile_token) |t|
            return astgen.failTok(t, "volatile is meaningless on global assembly", .{});
        if (full.outputs.len != 0 or full.inputs.len != 0 or full.first_clobber != null)
            return astgen.failNode(node, "global assembly cannot have inputs, outputs, or clobbers", .{});
    } else {
        if (full.outputs.len == 0 and full.volatile_token == null) {
            return astgen.failNode(node, "assembly expression with no output must be marked volatile", .{});
        }
    }
    if (full.outputs.len >= 16) {
        return astgen.failNode(full.outputs[16], "too many asm outputs", .{});
    }
    var outputs_buffer: [15]Zir.Inst.Asm.Output = undefined;
    const outputs = outputs_buffer[0..full.outputs.len];

    var output_type_bits: u32 = 0;

    for (full.outputs, 0..) |output_node, i| {
        const symbolic_name = tree.nodeMainToken(output_node);
        const name = try astgen.identAsString(symbolic_name);
        const constraint_token = symbolic_name + 2;
        const constraint = (try astgen.strLitAsString(constraint_token)).index;
        const has_arrow = tree.tokenTag(symbolic_name + 4) == .arrow;
        if (has_arrow) {
            if (output_type_bits != 0) {
                return astgen.failNode(output_node, "inline assembly allows up to one output value", .{});
            }
            output_type_bits |= @as(u32, 1) << @intCast(i);
            const out_type_node = tree.nodeData(output_node).opt_node_and_token[0].unwrap().?;
            const out_type_inst = try typeExpr(gz, scope, out_type_node);
            outputs[i] = .{
                .name = name,
                .constraint = constraint,
                .operand = out_type_inst,
            };
        } else {
            const ident_token = symbolic_name + 4;
            // TODO have a look at #215 and related issues and decide how to
            // handle outputs. Do we want this to be identifiers?
            // Or maybe we want to force this to be expressions with a pointer type.
            outputs[i] = .{
                .name = name,
                .constraint = constraint,
                .operand = try localVarRef(gz, scope, .{ .rl = .ref }, node, ident_token),
            };
        }
    }

    if (full.inputs.len >= 32) {
        return astgen.failNode(full.inputs[32], "too many asm inputs", .{});
    }
    var inputs_buffer: [31]Zir.Inst.Asm.Input = undefined;
    const inputs = inputs_buffer[0..full.inputs.len];

    for (full.inputs, 0..) |input_node, i| {
        const symbolic_name = tree.nodeMainToken(input_node);
        const name = try astgen.identAsString(symbolic_name);
        const constraint_token = symbolic_name + 2;
        const constraint = (try astgen.strLitAsString(constraint_token)).index;
        const operand = try expr(gz, scope, .{ .rl = .none }, tree.nodeData(input_node).node_and_token[0]);
        inputs[i] = .{
            .name = name,
            .constraint = constraint,
            .operand = operand,
        };
    }

    var clobbers_buffer: [63]u32 = undefined;
    var clobber_i: usize = 0;
    if (full.first_clobber) |first_clobber| clobbers: {
        // asm ("foo" ::: "a", "b")
        // asm ("foo" ::: "a", "b",)
        var tok_i = first_clobber;
        while (true) : (tok_i += 1) {
            if (clobber_i >= clobbers_buffer.len) {
                return astgen.failTok(tok_i, "too many asm clobbers", .{});
            }
            clobbers_buffer[clobber_i] = @intFromEnum((try astgen.strLitAsString(tok_i)).index);
            clobber_i += 1;
            tok_i += 1;
            switch (tree.tokenTag(tok_i)) {
                .r_paren => break :clobbers,
                .comma => {
                    if (tree.tokenTag(tok_i + 1) == .r_paren) {
                        break :clobbers;
                    } else {
                        continue;
                    }
                },
                else => unreachable,
            }
        }
    }

    const result = try gz.addAsm(.{
        .tag = tag_and_tmpl.tag,
        .node = node,
        .asm_source = tag_and_tmpl.tmpl,
        .is_volatile = full.volatile_token != null,
        .output_type_bits = output_type_bits,
        .outputs = outputs,
        .inputs = inputs,
        .clobbers = clobbers_buffer[0..clobber_i],
    });
    return rvalue(gz, ri, result, node);
}

fn as(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs: Ast.Node.Index,
    rhs: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const dest_type = try typeExpr(gz, scope, lhs);
    const result = try reachableExpr(gz, scope, .{ .rl = .{ .ty = dest_type } }, rhs, node);
    return rvalue(gz, ri, result, node);
}

fn unionInit(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const union_type = try typeExpr(gz, scope, params[0]);
    const field_name = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[1], .union_field_name);
    const field_type = try gz.addPlNode(.field_type_ref, node, Zir.Inst.FieldTypeRef{
        .container_type = union_type,
        .field_name = field_name,
    });
    const init = try reachableExpr(gz, scope, .{ .rl = .{ .ty = field_type } }, params[2], node);
    const result = try gz.addPlNode(.union_init, node, Zir.Inst.UnionInit{
        .union_type = union_type,
        .init = init,
        .field_name = field_name,
    });
    return rvalue(gz, ri, result, node);
}

fn bitCast(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const dest_type = try ri.rl.resultTypeForCast(gz, node, "@bitCast");
    const operand = try reachableExpr(gz, scope, .{ .rl = .none }, operand_node, node);
    const result = try gz.addPlNode(.bitcast, node, Zir.Inst.Bin{
        .lhs = dest_type,
        .rhs = operand,
    });
    return rvalue(gz, ri, result, node);
}

/// Handle one or more nested pointer cast builtins:
/// * @ptrCast
/// * @alignCast
/// * @addrSpaceCast
/// * @constCast
/// * @volatileCast
/// Any sequence of such builtins is treated as a single operation. This allowed
/// for sequences like `@ptrCast(@alignCast(ptr))` to work correctly despite the
/// intermediate result type being unknown.
fn ptrCast(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    root_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const FlagsInt = @typeInfo(Zir.Inst.FullPtrCastFlags).@"struct".backing_integer.?;
    var flags: Zir.Inst.FullPtrCastFlags = .{};

    // Note that all pointer cast builtins have one parameter, so we only need
    // to handle `builtin_call_two`.
    var node = root_node;
    while (true) {
        switch (tree.nodeTag(node)) {
            .builtin_call_two, .builtin_call_two_comma => {},
            .grouped_expression => {
                // Handle the chaining even with redundant parentheses
                node = tree.nodeData(node).node_and_token[0];
                continue;
            },
            else => break,
        }

        var buf: [2]Ast.Node.Index = undefined;
        const args = tree.builtinCallParams(&buf, node).?;
        std.debug.assert(args.len <= 2);

        if (args.len == 0) break; // 0 args

        const builtin_token = tree.nodeMainToken(node);
        const builtin_name = tree.tokenSlice(builtin_token);
        const info = BuiltinFn.list.get(builtin_name) orelse break;
        if (args.len == 1) {
            if (info.param_count != 1) break;

            switch (info.tag) {
                else => break,
                inline .ptr_cast,
                .align_cast,
                .addrspace_cast,
                .const_cast,
                .volatile_cast,
                => |tag| {
                    if (@field(flags, @tagName(tag))) {
                        return astgen.failNode(node, "redundant {s}", .{builtin_name});
                    }
                    @field(flags, @tagName(tag)) = true;
                },
            }

            node = args[0];
        } else {
            std.debug.assert(args.len == 2);
            if (info.param_count != 2) break;

            switch (info.tag) {
                else => break,
                .field_parent_ptr => {
                    if (flags.ptr_cast) break;

                    const flags_int: FlagsInt = @bitCast(flags);
                    const cursor = maybeAdvanceSourceCursorToMainToken(gz, root_node);
                    const parent_ptr_type = try ri.rl.resultTypeForCast(gz, root_node, "@alignCast");
                    const field_name = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, args[0], .field_name);
                    const field_ptr = try expr(gz, scope, .{ .rl = .none }, args[1]);
                    try emitDbgStmt(gz, cursor);
                    const result = try gz.addExtendedPayloadSmall(.field_parent_ptr, flags_int, Zir.Inst.FieldParentPtr{
                        .src_node = gz.nodeIndexToRelative(node),
                        .parent_ptr_type = parent_ptr_type,
                        .field_name = field_name,
                        .field_ptr = field_ptr,
                    });
                    return rvalue(gz, ri, result, root_node);
                },
            }
        }
    }

    const flags_int: FlagsInt = @bitCast(flags);
    assert(flags_int != 0);

    const ptr_only: Zir.Inst.FullPtrCastFlags = .{ .ptr_cast = true };
    if (flags_int == @as(FlagsInt, @bitCast(ptr_only))) {
        // Special case: simpler representation
        return typeCast(gz, scope, ri, root_node, node, .ptr_cast, "@ptrCast");
    }

    const no_result_ty_flags: Zir.Inst.FullPtrCastFlags = .{
        .const_cast = true,
        .volatile_cast = true,
    };
    if ((flags_int & ~@as(FlagsInt, @bitCast(no_result_ty_flags))) == 0) {
        // Result type not needed
        const cursor = maybeAdvanceSourceCursorToMainToken(gz, root_node);
        const operand = try expr(gz, scope, .{ .rl = .none }, node);
        try emitDbgStmt(gz, cursor);
        const result = try gz.addExtendedPayloadSmall(.ptr_cast_no_dest, flags_int, Zir.Inst.UnNode{
            .node = gz.nodeIndexToRelative(root_node),
            .operand = operand,
        });
        return rvalue(gz, ri, result, root_node);
    }

    // Full cast including result type

    const cursor = maybeAdvanceSourceCursorToMainToken(gz, root_node);
    const result_type = try ri.rl.resultTypeForCast(gz, root_node, flags.needResultTypeBuiltinName());
    const operand = try expr(gz, scope, .{ .rl = .none }, node);
    try emitDbgStmt(gz, cursor);
    const result = try gz.addExtendedPayloadSmall(.ptr_cast_full, flags_int, Zir.Inst.BinNode{
        .node = gz.nodeIndexToRelative(root_node),
        .lhs = result_type,
        .rhs = operand,
    });
    return rvalue(gz, ri, result, root_node);
}

fn typeOf(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    args: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    if (args.len < 1) {
        return astgen.failNode(node, "expected at least 1 argument, found 0", .{});
    }
    const gpa = astgen.gpa;
    if (args.len == 1) {
        const typeof_inst = try gz.makeBlockInst(.typeof_builtin, node);

        var typeof_scope = gz.makeSubBlock(scope);
        typeof_scope.is_comptime = false;
        typeof_scope.is_typeof = true;
        typeof_scope.c_import = false;
        defer typeof_scope.unstack();

        const ty_expr = try reachableExpr(&typeof_scope, &typeof_scope.base, .{ .rl = .none }, args[0], node);
        if (!gz.refIsNoReturn(ty_expr)) {
            _ = try typeof_scope.addBreak(.break_inline, typeof_inst, ty_expr);
        }
        try typeof_scope.setBlockBody(typeof_inst);

        // typeof_scope unstacked now, can add new instructions to gz
        try gz.instructions.append(gpa, typeof_inst);
        return rvalue(gz, ri, typeof_inst.toRef(), node);
    }
    const payload_size: u32 = std.meta.fields(Zir.Inst.TypeOfPeer).len;
    const payload_index = try reserveExtra(astgen, payload_size + args.len);
    const args_index = payload_index + payload_size;

    const typeof_inst = try gz.addExtendedMultiOpPayloadIndex(.typeof_peer, payload_index, args.len);

    var typeof_scope = gz.makeSubBlock(scope);
    typeof_scope.is_comptime = false;

    for (args, 0..) |arg, i| {
        const param_ref = try reachableExpr(&typeof_scope, &typeof_scope.base, .{ .rl = .none }, arg, node);
        astgen.extra.items[args_index + i] = @intFromEnum(param_ref);
    }
    _ = try typeof_scope.addBreak(.break_inline, typeof_inst.toIndex().?, .void_value);

    const body = typeof_scope.instructionsSlice();
    const body_len = astgen.countBodyLenAfterFixups(body);
    astgen.setExtra(payload_index, Zir.Inst.TypeOfPeer{
        .body_len = @intCast(body_len),
        .body_index = @intCast(astgen.extra.items.len),
        .src_node = gz.nodeIndexToRelative(node),
    });
    try astgen.extra.ensureUnusedCapacity(gpa, body_len);
    astgen.appendBodyWithFixups(body);
    typeof_scope.unstack();

    return rvalue(gz, ri, typeof_inst, node);
}

fn minMax(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    args: []const Ast.Node.Index,
    comptime op: enum { min, max },
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    if (args.len < 2) {
        return astgen.failNode(node, "expected at least 2 arguments, found {}", .{args.len});
    }
    if (args.len == 2) {
        const tag: Zir.Inst.Tag = switch (op) {
            .min => .min,
            .max => .max,
        };
        const a = try expr(gz, scope, .{ .rl = .none }, args[0]);
        const b = try expr(gz, scope, .{ .rl = .none }, args[1]);
        const result = try gz.addPlNode(tag, node, Zir.Inst.Bin{
            .lhs = a,
            .rhs = b,
        });
        return rvalue(gz, ri, result, node);
    }
    const payload_index = try addExtra(astgen, Zir.Inst.NodeMultiOp{
        .src_node = gz.nodeIndexToRelative(node),
    });
    var extra_index = try reserveExtra(gz.astgen, args.len);
    for (args) |arg| {
        const arg_ref = try expr(gz, scope, .{ .rl = .none }, arg);
        astgen.extra.items[extra_index] = @intFromEnum(arg_ref);
        extra_index += 1;
    }
    const tag: Zir.Inst.Extended = switch (op) {
        .min => .min_multi,
        .max => .max_multi,
    };
    const result = try gz.addExtendedMultiOpPayloadIndex(tag, payload_index, args.len);
    return rvalue(gz, ri, result, node);
}

fn builtinCall(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
    allow_branch_hint: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const builtin_token = tree.nodeMainToken(node);
    const builtin_name = tree.tokenSlice(builtin_token);

    // We handle the different builtins manually because they have different semantics depending
    // on the function. For example, `@as` and others participate in result location semantics,
    // and `@cImport` creates a special scope that collects a .c source code text buffer.
    // Also, some builtins have a variable number of parameters.

    const info = BuiltinFn.list.get(builtin_name) orelse {
        return astgen.failNode(node, "invalid builtin function: '{s}'", .{
            builtin_name,
        });
    };
    if (info.param_count) |expected| {
        if (expected != params.len) {
            const s = if (expected == 1) "" else "s";
            return astgen.failNode(node, "expected {d} argument{s}, found {d}", .{
                expected, s, params.len,
            });
        }
    }

    // Check function scope-only builtins

    if (astgen.fn_block == null and info.illegal_outside_function)
        return astgen.failNode(node, "'{s}' outside function scope", .{builtin_name});

    switch (info.tag) {
        .branch_hint => {
            if (!allow_branch_hint) {
                return astgen.failNode(node, "'@branchHint' must appear as the first statement in a function or conditional branch", .{});
            }
            const hint_ty = try gz.addBuiltinValue(node, .branch_hint);
            const hint_val = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = hint_ty } }, params[0], .operand_branchHint);
            _ = try gz.addExtendedPayload(.branch_hint, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = hint_val,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .import => {
            const operand_node = params[0];

            if (tree.nodeTag(operand_node) != .string_literal) {
                // Spec reference: https://github.com/ziglang/zig/issues/2206
                return astgen.failNode(operand_node, "@import operand must be a string literal", .{});
            }
            const str_lit_token = tree.nodeMainToken(operand_node);
            const str = try astgen.strLitAsString(str_lit_token);
            const str_slice = astgen.string_bytes.items[@intFromEnum(str.index)..][0..str.len];
            if (mem.indexOfScalar(u8, str_slice, 0) != null) {
                return astgen.failTok(str_lit_token, "import path cannot contain null bytes", .{});
            } else if (str.len == 0) {
                return astgen.failTok(str_lit_token, "import path cannot be empty", .{});
            }
            const res_ty = try ri.rl.resultType(gz, node) orelse .none;
            const payload_index = try addExtra(gz.astgen, Zir.Inst.Import{
                .res_ty = res_ty,
                .path = str.index,
            });
            const result = try gz.add(.{
                .tag = .import,
                .data = .{ .pl_tok = .{
                    .src_tok = gz.tokenIndexToRelative(str_lit_token),
                    .payload_index = payload_index,
                } },
            });
            const gop = try astgen.imports.getOrPut(astgen.gpa, str.index);
            if (!gop.found_existing) {
                gop.value_ptr.* = str_lit_token;
            }
            return rvalue(gz, ri, result, node);
        },
        .compile_log => {
            const payload_index = try addExtra(gz.astgen, Zir.Inst.NodeMultiOp{
                .src_node = gz.nodeIndexToRelative(node),
            });
            var extra_index = try reserveExtra(gz.astgen, params.len);
            for (params) |param| {
                const param_ref = try expr(gz, scope, .{ .rl = .none }, param);
                astgen.extra.items[extra_index] = @intFromEnum(param_ref);
                extra_index += 1;
            }
            const result = try gz.addExtendedMultiOpPayloadIndex(.compile_log, payload_index, params.len);
            return rvalue(gz, ri, result, node);
        },
        .field => {
            if (ri.rl == .ref or ri.rl == .ref_coerced_ty) {
                return gz.addPlNode(.field_ptr_named, node, Zir.Inst.FieldNamed{
                    .lhs = try expr(gz, scope, .{ .rl = .ref }, params[0]),
                    .field_name = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[1], .field_name),
                });
            }
            const result = try gz.addPlNode(.field_val_named, node, Zir.Inst.FieldNamed{
                .lhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .field_name = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[1], .field_name),
            });
            return rvalue(gz, ri, result, node);
        },
        .FieldType => {
            const ty_inst = try typeExpr(gz, scope, params[0]);
            const name_inst = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[1], .field_name);
            const result = try gz.addPlNode(.field_type_ref, node, Zir.Inst.FieldTypeRef{
                .container_type = ty_inst,
                .field_name = name_inst,
            });
            return rvalue(gz, ri, result, node);
        },

        // zig fmt: off
        .as         => return as(       gz, scope, ri, node, params[0], params[1]),
        .bit_cast   => return bitCast(  gz, scope, ri, node, params[0]),
        .TypeOf     => return typeOf(   gz, scope, ri, node, params),
        .union_init => return unionInit(gz, scope, ri, node, params),
        .c_import   => return cImport(  gz, scope,     node, params[0]),
        .min        => return minMax(   gz, scope, ri, node, params, .min),
        .max        => return minMax(   gz, scope, ri, node, params, .max),
        // zig fmt: on

        .@"export" => {
            const exported = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const export_options_ty = try gz.addBuiltinValue(node, .export_options);
            const options = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = export_options_ty } }, params[1], .export_options);
            _ = try gz.addPlNode(.@"export", node, Zir.Inst.Export{
                .exported = exported,
                .options = options,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .@"extern" => {
            const type_inst = try typeExpr(gz, scope, params[0]);
            const extern_options_ty = try gz.addBuiltinValue(node, .extern_options);
            const options = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = extern_options_ty } }, params[1], .extern_options);
            const result = try gz.addExtendedPayload(.builtin_extern, Zir.Inst.BinNode{
                .node = gz.nodeIndexToRelative(node),
                .lhs = type_inst,
                .rhs = options,
            });
            return rvalue(gz, ri, result, node);
        },
        .set_float_mode => {
            const float_mode_ty = try gz.addBuiltinValue(node, .float_mode);
            const order = try expr(gz, scope, .{ .rl = .{ .coerced_ty = float_mode_ty } }, params[0]);
            _ = try gz.addExtendedPayload(.set_float_mode, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = order,
            });
            return rvalue(gz, ri, .void_value, node);
        },

        .src => {
            // Incorporate the source location into the source hash, so that
            // changes in the source location of `@src()` result in re-analysis.
            astgen.src_hasher.update(
                std.mem.asBytes(&astgen.source_line) ++
                    std.mem.asBytes(&astgen.source_column),
            );

            const node_start = tree.tokenStart(tree.firstToken(node));
            astgen.advanceSourceCursor(node_start);
            const result = try gz.addExtendedPayload(.builtin_src, Zir.Inst.Src{
                .node = gz.nodeIndexToRelative(node),
                .line = astgen.source_line,
                .column = astgen.source_column,
            });
            return rvalue(gz, ri, result, node);
        },

        // zig fmt: off
        .This                    => return rvalue(gz, ri, try gz.addNodeExtended(.this,                    node), node),
        .return_address          => return rvalue(gz, ri, try gz.addNodeExtended(.ret_addr,                node), node),
        .error_return_trace      => return rvalue(gz, ri, try gz.addNodeExtended(.error_return_trace,      node), node),
        .frame                   => return rvalue(gz, ri, try gz.addNodeExtended(.frame,                   node), node),
        .frame_address           => return rvalue(gz, ri, try gz.addNodeExtended(.frame_address,           node), node),
        .breakpoint              => return rvalue(gz, ri, try gz.addNodeExtended(.breakpoint,              node), node),
        .disable_instrumentation => return rvalue(gz, ri, try gz.addNodeExtended(.disable_instrumentation, node), node),
        .disable_intrinsics      => return rvalue(gz, ri, try gz.addNodeExtended(.disable_intrinsics,      node), node),

        .type_info   => return simpleUnOpType(gz, scope, ri, node, params[0], .type_info),
        .size_of     => return simpleUnOpType(gz, scope, ri, node, params[0], .size_of),
        .bit_size_of => return simpleUnOpType(gz, scope, ri, node, params[0], .bit_size_of),
        .align_of    => return simpleUnOpType(gz, scope, ri, node, params[0], .align_of),

        .int_from_ptr          => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .int_from_ptr),
        .compile_error         => return simpleUnOp(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } },   params[0], .compile_error),
        .set_eval_branch_quota => return simpleUnOp(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .u32_type } },              params[0], .set_eval_branch_quota),
        .int_from_enum         => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .int_from_enum),
        .int_from_bool         => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .int_from_bool),
        .embed_file            => return simpleUnOp(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } },   params[0], .embed_file),
        .error_name            => return simpleUnOp(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .anyerror_type } },         params[0], .error_name),
        .set_runtime_safety    => return simpleUnOp(gz, scope, ri, node, coerced_bool_ri,                                      params[0], .set_runtime_safety),
        .sqrt                  => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .sqrt),
        .sin                   => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .sin),
        .cos                   => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .cos),
        .tan                   => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .tan),
        .exp                   => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .exp),
        .exp2                  => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .exp2),
        .log                   => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .log),
        .log2                  => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .log2),
        .log10                 => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .log10),
        .abs                   => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .abs),
        .floor                 => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .floor),
        .ceil                  => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .ceil),
        .trunc                 => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .trunc),
        .round                 => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .round),
        .tag_name              => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .tag_name),
        .type_name             => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .type_name),
        .Frame                 => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .frame_type),
        .frame_size            => return simpleUnOp(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .frame_size),

        .int_from_float => return typeCast(gz, scope, ri, node, params[0], .int_from_float, builtin_name),
        .float_from_int => return typeCast(gz, scope, ri, node, params[0], .float_from_int, builtin_name),
        .ptr_from_int   => return typeCast(gz, scope, ri, node, params[0], .ptr_from_int, builtin_name),
        .enum_from_int  => return typeCast(gz, scope, ri, node, params[0], .enum_from_int, builtin_name),
        .float_cast     => return typeCast(gz, scope, ri, node, params[0], .float_cast, builtin_name),
        .int_cast       => return typeCast(gz, scope, ri, node, params[0], .int_cast, builtin_name),
        .truncate       => return typeCast(gz, scope, ri, node, params[0], .truncate, builtin_name),
        // zig fmt: on

        .in_comptime => if (gz.is_comptime) {
            return astgen.failNode(node, "redundant '@inComptime' in comptime scope", .{});
        } else {
            return rvalue(gz, ri, try gz.addNodeExtended(.in_comptime, node), node);
        },

        .Type => {
            const type_info_ty = try gz.addBuiltinValue(node, .type_info);
            const operand = try expr(gz, scope, .{ .rl = .{ .coerced_ty = type_info_ty } }, params[0]);

            const gpa = gz.astgen.gpa;

            try gz.instructions.ensureUnusedCapacity(gpa, 1);
            try gz.astgen.instructions.ensureUnusedCapacity(gpa, 1);

            const payload_index = try gz.astgen.addExtra(Zir.Inst.Reify{
                .node = node, // Absolute node index -- see the definition of `Reify`.
                .operand = operand,
                .src_line = astgen.source_line,
            });
            const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
            gz.astgen.instructions.appendAssumeCapacity(.{
                .tag = .extended,
                .data = .{ .extended = .{
                    .opcode = .reify,
                    .small = @intFromEnum(gz.anon_name_strategy),
                    .operand = payload_index,
                } },
            });
            gz.instructions.appendAssumeCapacity(new_index);
            const result = new_index.toRef();
            return rvalue(gz, ri, result, node);
        },
        .panic => {
            try emitDbgNode(gz, node);
            return simpleUnOp(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[0], .panic);
        },
        .trap => {
            try emitDbgNode(gz, node);
            _ = try gz.addNode(.trap, node);
            return rvalue(gz, ri, .unreachable_value, node);
        },
        .int_from_error => {
            const operand = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const result = try gz.addExtendedPayload(.int_from_error, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .error_from_int => {
            const operand = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const result = try gz.addExtendedPayload(.error_from_int, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .error_cast => {
            try emitDbgNode(gz, node);

            const result = try gz.addExtendedPayload(.error_cast, Zir.Inst.BinNode{
                .lhs = try ri.rl.resultTypeForCast(gz, node, builtin_name),
                .rhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .node = gz.nodeIndexToRelative(node),
            });
            return rvalue(gz, ri, result, node);
        },
        .ptr_cast,
        .align_cast,
        .addrspace_cast,
        .const_cast,
        .volatile_cast,
        => return ptrCast(gz, scope, ri, node),

        // zig fmt: off
        .has_decl  => return hasDeclOrField(gz, scope, ri, node, params[0], params[1], .has_decl),
        .has_field => return hasDeclOrField(gz, scope, ri, node, params[0], params[1], .has_field),

        .clz         => return bitBuiltin(gz, scope, ri, node, params[0], .clz),
        .ctz         => return bitBuiltin(gz, scope, ri, node, params[0], .ctz),
        .pop_count   => return bitBuiltin(gz, scope, ri, node, params[0], .pop_count),
        .byte_swap   => return bitBuiltin(gz, scope, ri, node, params[0], .byte_swap),
        .bit_reverse => return bitBuiltin(gz, scope, ri, node, params[0], .bit_reverse),

        .div_exact => return divBuiltin(gz, scope, ri, node, params[0], params[1], .div_exact),
        .div_floor => return divBuiltin(gz, scope, ri, node, params[0], params[1], .div_floor),
        .div_trunc => return divBuiltin(gz, scope, ri, node, params[0], params[1], .div_trunc),
        .mod       => return divBuiltin(gz, scope, ri, node, params[0], params[1], .mod),
        .rem       => return divBuiltin(gz, scope, ri, node, params[0], params[1], .rem),

        .shl_exact => return shiftOp(gz, scope, ri, node, params[0], params[1], .shl_exact),
        .shr_exact => return shiftOp(gz, scope, ri, node, params[0], params[1], .shr_exact),

        .bit_offset_of => return offsetOf(gz, scope, ri, node, params[0], params[1], .bit_offset_of),
        .offset_of     => return offsetOf(gz, scope, ri, node, params[0], params[1], .offset_of),

        .c_undef   => return simpleCBuiltin(gz, scope, ri, node, params[0], .c_undef),
        .c_include => return simpleCBuiltin(gz, scope, ri, node, params[0], .c_include),

        .cmpxchg_strong => return cmpxchg(gz, scope, ri, node, params, 1),
        .cmpxchg_weak   => return cmpxchg(gz, scope, ri, node, params, 0),
        // zig fmt: on

        .wasm_memory_size => {
            const operand = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0], .wasm_memory_index);
            const result = try gz.addExtendedPayload(.wasm_memory_size, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .wasm_memory_grow => {
            const index_arg = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0], .wasm_memory_index);
            const delta_arg = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, params[1]);
            const result = try gz.addExtendedPayload(.wasm_memory_grow, Zir.Inst.BinNode{
                .node = gz.nodeIndexToRelative(node),
                .lhs = index_arg,
                .rhs = delta_arg,
            });
            return rvalue(gz, ri, result, node);
        },
        .c_define => {
            if (!gz.c_import) return gz.astgen.failNode(node, "C define valid only inside C import block", .{});
            const name = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[0], .operand_cDefine_macro_name);
            const value = try comptimeExpr(gz, scope, .{ .rl = .none }, params[1], .operand_cDefine_macro_value);
            const result = try gz.addExtendedPayload(.c_define, Zir.Inst.BinNode{
                .node = gz.nodeIndexToRelative(node),
                .lhs = name,
                .rhs = value,
            });
            return rvalue(gz, ri, result, node);
        },

        .splat => {
            const result_type = try ri.rl.resultTypeForCast(gz, node, builtin_name);
            const elem_type = try gz.addUnNode(.vec_arr_elem_type, result_type, node);
            const scalar = try expr(gz, scope, .{ .rl = .{ .ty = elem_type } }, params[0]);
            const result = try gz.addPlNode(.splat, node, Zir.Inst.Bin{
                .lhs = result_type,
                .rhs = scalar,
            });
            return rvalue(gz, ri, result, node);
        },
        .reduce => {
            const reduce_op_ty = try gz.addBuiltinValue(node, .reduce_op);
            const op = try expr(gz, scope, .{ .rl = .{ .coerced_ty = reduce_op_ty } }, params[0]);
            const scalar = try expr(gz, scope, .{ .rl = .none }, params[1]);
            const result = try gz.addPlNode(.reduce, node, Zir.Inst.Bin{
                .lhs = op,
                .rhs = scalar,
            });
            return rvalue(gz, ri, result, node);
        },

        .add_with_overflow => return overflowArithmetic(gz, scope, ri, node, params, .add_with_overflow),
        .sub_with_overflow => return overflowArithmetic(gz, scope, ri, node, params, .sub_with_overflow),
        .mul_with_overflow => return overflowArithmetic(gz, scope, ri, node, params, .mul_with_overflow),
        .shl_with_overflow => return overflowArithmetic(gz, scope, ri, node, params, .shl_with_overflow),

        .atomic_load => {
            const atomic_order_type = try gz.addBuiltinValue(node, .atomic_order);
            const result = try gz.addPlNode(.atomic_load, node, Zir.Inst.AtomicLoad{
                // zig fmt: off
                .elem_type = try typeExpr(gz, scope,                                                  params[0]),
                .ptr       = try expr    (gz, scope, .{ .rl = .none },                                params[1]),
                .ordering  = try expr    (gz, scope, .{ .rl = .{ .coerced_ty = atomic_order_type } }, params[2]),
                // zig fmt: on
            });
            return rvalue(gz, ri, result, node);
        },
        .atomic_rmw => {
            const atomic_order_type = try gz.addBuiltinValue(node, .atomic_order);
            const atomic_rmw_op_type = try gz.addBuiltinValue(node, .atomic_rmw_op);
            const int_type = try typeExpr(gz, scope, params[0]);
            const result = try gz.addPlNode(.atomic_rmw, node, Zir.Inst.AtomicRmw{
                // zig fmt: off
                .ptr       = try expr(gz, scope, .{ .rl = .none },                                 params[1]),
                .operation = try expr(gz, scope, .{ .rl = .{ .coerced_ty = atomic_rmw_op_type } }, params[2]),
                .operand   = try expr(gz, scope, .{ .rl = .{ .ty = int_type } },                   params[3]),
                .ordering  = try expr(gz, scope, .{ .rl = .{ .coerced_ty = atomic_order_type } },  params[4]),
                // zig fmt: on
            });
            return rvalue(gz, ri, result, node);
        },
        .atomic_store => {
            const atomic_order_type = try gz.addBuiltinValue(node, .atomic_order);
            const int_type = try typeExpr(gz, scope, params[0]);
            _ = try gz.addPlNode(.atomic_store, node, Zir.Inst.AtomicStore{
                // zig fmt: off
                .ptr      = try expr(gz, scope, .{ .rl = .none },                                params[1]),
                .operand  = try expr(gz, scope, .{ .rl = .{ .ty = int_type } },                  params[2]),
                .ordering = try expr(gz, scope, .{ .rl = .{ .coerced_ty = atomic_order_type } }, params[3]),
                // zig fmt: on
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .mul_add => {
            const float_type = try typeExpr(gz, scope, params[0]);
            const mulend1 = try expr(gz, scope, .{ .rl = .{ .coerced_ty = float_type } }, params[1]);
            const mulend2 = try expr(gz, scope, .{ .rl = .{ .coerced_ty = float_type } }, params[2]);
            const addend = try expr(gz, scope, .{ .rl = .{ .ty = float_type } }, params[3]);
            const result = try gz.addPlNode(.mul_add, node, Zir.Inst.MulAdd{
                .mulend1 = mulend1,
                .mulend2 = mulend2,
                .addend = addend,
            });
            return rvalue(gz, ri, result, node);
        },
        .call => {
            const call_modifier_ty = try gz.addBuiltinValue(node, .call_modifier);
            const modifier = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = call_modifier_ty } }, params[0], .call_modifier);
            const callee = try expr(gz, scope, .{ .rl = .none }, params[1]);
            const args = try expr(gz, scope, .{ .rl = .none }, params[2]);
            const result = try gz.addPlNode(.builtin_call, node, Zir.Inst.BuiltinCall{
                .modifier = modifier,
                .callee = callee,
                .args = args,
                .flags = .{
                    .is_nosuspend = gz.nosuspend_node != .none,
                    .ensure_result_used = false,
                },
            });
            return rvalue(gz, ri, result, node);
        },
        .field_parent_ptr => {
            const parent_ptr_type = try ri.rl.resultTypeForCast(gz, node, builtin_name);
            const field_name = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[0], .field_name);
            const result = try gz.addExtendedPayloadSmall(.field_parent_ptr, 0, Zir.Inst.FieldParentPtr{
                .src_node = gz.nodeIndexToRelative(node),
                .parent_ptr_type = parent_ptr_type,
                .field_name = field_name,
                .field_ptr = try expr(gz, scope, .{ .rl = .none }, params[1]),
            });
            return rvalue(gz, ri, result, node);
        },
        .memcpy => {
            _ = try gz.addPlNode(.memcpy, node, Zir.Inst.Bin{
                .lhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .rhs = try expr(gz, scope, .{ .rl = .none }, params[1]),
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .memset => {
            const lhs = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const lhs_ty = try gz.addUnNode(.typeof, lhs, params[0]);
            const elem_ty = try gz.addUnNode(.indexable_ptr_elem_type, lhs_ty, params[0]);
            _ = try gz.addPlNode(.memset, node, Zir.Inst.Bin{
                .lhs = lhs,
                .rhs = try expr(gz, scope, .{ .rl = .{ .coerced_ty = elem_ty } }, params[1]),
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .memmove => {
            _ = try gz.addPlNode(.memmove, node, Zir.Inst.Bin{
                .lhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .rhs = try expr(gz, scope, .{ .rl = .none }, params[1]),
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .shuffle => {
            const result = try gz.addPlNode(.shuffle, node, Zir.Inst.Shuffle{
                .elem_type = try typeExpr(gz, scope, params[0]),
                .a = try expr(gz, scope, .{ .rl = .none }, params[1]),
                .b = try expr(gz, scope, .{ .rl = .none }, params[2]),
                .mask = try comptimeExpr(gz, scope, .{ .rl = .none }, params[3], .operand_shuffle_mask),
            });
            return rvalue(gz, ri, result, node);
        },
        .select => {
            const result = try gz.addExtendedPayload(.select, Zir.Inst.Select{
                .node = gz.nodeIndexToRelative(node),
                .elem_type = try typeExpr(gz, scope, params[0]),
                .pred = try expr(gz, scope, .{ .rl = .none }, params[1]),
                .a = try expr(gz, scope, .{ .rl = .none }, params[2]),
                .b = try expr(gz, scope, .{ .rl = .none }, params[3]),
            });
            return rvalue(gz, ri, result, node);
        },
        .async_call => {
            const result = try gz.addExtendedPayload(.builtin_async_call, Zir.Inst.AsyncCall{
                .node = gz.nodeIndexToRelative(node),
                .frame_buffer = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .result_ptr = try expr(gz, scope, .{ .rl = .none }, params[1]),
                .fn_ptr = try expr(gz, scope, .{ .rl = .none }, params[2]),
                .args = try expr(gz, scope, .{ .rl = .none }, params[3]),
            });
            return rvalue(gz, ri, result, node);
        },
        .Vector => {
            const result = try gz.addPlNode(.vector_type, node, Zir.Inst.Bin{
                .lhs = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0], .type),
                .rhs = try typeExpr(gz, scope, params[1]),
            });
            return rvalue(gz, ri, result, node);
        },
        .prefetch => {
            const prefetch_options_ty = try gz.addBuiltinValue(node, .prefetch_options);
            const ptr = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const options = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = prefetch_options_ty } }, params[1], .prefetch_options);
            _ = try gz.addExtendedPayload(.prefetch, Zir.Inst.BinNode{
                .node = gz.nodeIndexToRelative(node),
                .lhs = ptr,
                .rhs = options,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .c_va_arg => {
            const result = try gz.addExtendedPayload(.c_va_arg, Zir.Inst.BinNode{
                .node = gz.nodeIndexToRelative(node),
                .lhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .rhs = try typeExpr(gz, scope, params[1]),
            });
            return rvalue(gz, ri, result, node);
        },
        .c_va_copy => {
            const result = try gz.addExtendedPayload(.c_va_copy, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = try expr(gz, scope, .{ .rl = .none }, params[0]),
            });
            return rvalue(gz, ri, result, node);
        },
        .c_va_end => {
            const result = try gz.addExtendedPayload(.c_va_end, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = try expr(gz, scope, .{ .rl = .none }, params[0]),
            });
            return rvalue(gz, ri, result, node);
        },
        .c_va_start => {
            if (!astgen.fn_var_args) {
                return astgen.failNode(node, "'@cVaStart' in a non-variadic function", .{});
            }
            return rvalue(gz, ri, try gz.addNodeExtended(.c_va_start, node), node);
        },

        .work_item_id => {
            const operand = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0], .work_group_dim_index);
            const result = try gz.addExtendedPayload(.work_item_id, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .work_group_size => {
            const operand = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0], .work_group_dim_index);
            const result = try gz.addExtendedPayload(.work_group_size, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .work_group_id => {
            const operand = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0], .work_group_dim_index);
            const result = try gz.addExtendedPayload(.work_group_id, Zir.Inst.UnNode{
                .node = gz.nodeIndexToRelative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
    }
}

fn hasDeclOrField(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const container_type = try typeExpr(gz, scope, lhs_node);
    const name = try comptimeExpr(
        gz,
        scope,
        .{ .rl = .{ .coerced_ty = .slice_const_u8_type } },
        rhs_node,
        if (tag == .has_decl) .decl_name else .field_name,
    );
    const result = try gz.addPlNode(tag, node, Zir.Inst.Bin{
        .lhs = container_type,
        .rhs = name,
    });
    return rvalue(gz, ri, result, node);
}

fn typeCast(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
    builtin_name: []const u8,
) InnerError!Zir.Inst.Ref {
    const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
    const result_type = try ri.rl.resultTypeForCast(gz, node, builtin_name);
    const operand = try expr(gz, scope, .{ .rl = .none }, operand_node);

    try emitDbgStmt(gz, cursor);
    const result = try gz.addPlNode(tag, node, Zir.Inst.Bin{
        .lhs = result_type,
        .rhs = operand,
    });
    return rvalue(gz, ri, result, node);
}

fn simpleUnOpType(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const operand = try typeExpr(gz, scope, operand_node);
    const result = try gz.addUnNode(tag, operand, node);
    return rvalue(gz, ri, result, node);
}

fn simpleUnOp(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_ri: ResultInfo,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
    const operand = if (tag == .compile_error)
        try comptimeExpr(gz, scope, operand_ri, operand_node, .compile_error_string)
    else
        try expr(gz, scope, operand_ri, operand_node);
    switch (tag) {
        .tag_name, .error_name, .int_from_ptr => try emitDbgStmt(gz, cursor),
        else => {},
    }
    const result = try gz.addUnNode(tag, operand, node);
    return rvalue(gz, ri, result, node);
}

fn negation(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    // Check for float literal as the sub-expression because we want to preserve
    // its negativity rather than having it go through comptime subtraction.
    const operand_node = tree.nodeData(node).node;
    if (tree.nodeTag(operand_node) == .number_literal) {
        return numberLiteral(gz, ri, operand_node, node, .negative);
    }

    const operand = try expr(gz, scope, .{ .rl = .none }, operand_node);
    const result = try gz.addUnNode(.negate, operand, node);
    return rvalue(gz, ri, result, node);
}

fn cmpxchg(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
    small: u16,
) InnerError!Zir.Inst.Ref {
    const int_type = try typeExpr(gz, scope, params[0]);
    const atomic_order_type = try gz.addBuiltinValue(node, .atomic_order);
    const result = try gz.addExtendedPayloadSmall(.cmpxchg, small, Zir.Inst.Cmpxchg{
        // zig fmt: off
        .node           = gz.nodeIndexToRelative(node),
        .ptr            = try expr(gz, scope, .{ .rl = .none },                                params[1]),
        .expected_value = try expr(gz, scope, .{ .rl = .{ .ty = int_type } },                  params[2]),
        .new_value      = try expr(gz, scope, .{ .rl = .{ .coerced_ty = int_type } },          params[3]),
        .success_order  = try expr(gz, scope, .{ .rl = .{ .coerced_ty = atomic_order_type } }, params[4]),
        .failure_order  = try expr(gz, scope, .{ .rl = .{ .coerced_ty = atomic_order_type } }, params[5]),
        // zig fmt: on
    });
    return rvalue(gz, ri, result, node);
}

fn bitBuiltin(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const operand = try expr(gz, scope, .{ .rl = .none }, operand_node);
    const result = try gz.addUnNode(tag, operand, node);
    return rvalue(gz, ri, result, node);
}

fn divBuiltin(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
    const lhs = try expr(gz, scope, .{ .rl = .none }, lhs_node);
    const rhs = try expr(gz, scope, .{ .rl = .none }, rhs_node);

    try emitDbgStmt(gz, cursor);
    const result = try gz.addPlNode(tag, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs });
    return rvalue(gz, ri, result, node);
}

fn simpleCBuiltin(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Extended,
) InnerError!Zir.Inst.Ref {
    const name: []const u8 = if (tag == .c_undef) "C undef" else "C include";
    if (!gz.c_import) return gz.astgen.failNode(node, "{s} valid only inside C import block", .{name});
    const operand = try comptimeExpr(
        gz,
        scope,
        .{ .rl = .{ .coerced_ty = .slice_const_u8_type } },
        operand_node,
        if (tag == .c_undef) .operand_cUndef_macro_name else .operand_cInclude_file_name,
    );
    _ = try gz.addExtendedPayload(tag, Zir.Inst.UnNode{
        .node = gz.nodeIndexToRelative(node),
        .operand = operand,
    });
    return rvalue(gz, ri, .void_value, node);
}

fn offsetOf(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const type_inst = try typeExpr(gz, scope, lhs_node);
    const field_name = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, rhs_node, .field_name);
    const result = try gz.addPlNode(tag, node, Zir.Inst.Bin{
        .lhs = type_inst,
        .rhs = field_name,
    });
    return rvalue(gz, ri, result, node);
}

fn shiftOp(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const lhs = try expr(gz, scope, .{ .rl = .none }, lhs_node);

    const cursor = switch (gz.astgen.tree.nodeTag(node)) {
        .shl, .shr => maybeAdvanceSourceCursorToMainToken(gz, node),
        else => undefined,
    };

    const log2_int_type = try gz.addUnNode(.typeof_log2_int_type, lhs, lhs_node);
    const rhs = try expr(gz, scope, .{ .rl = .{ .ty = log2_int_type }, .ctx = .shift_op }, rhs_node);

    switch (gz.astgen.tree.nodeTag(node)) {
        .shl, .shr => try emitDbgStmt(gz, cursor),
        else => undefined,
    }

    const result = try gz.addPlNode(tag, node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    return rvalue(gz, ri, result, node);
}

fn cImport(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    body_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;

    if (gz.c_import) return gz.astgen.failNode(node, "cannot nest @cImport", .{});

    var block_scope = gz.makeSubBlock(scope);
    block_scope.is_comptime = true;
    block_scope.c_import = true;
    defer block_scope.unstack();

    const block_inst = try gz.makeBlockInst(.c_import, node);
    const block_result = try fullBodyExpr(&block_scope, &block_scope.base, .{ .rl = .none }, body_node, .normal);
    _ = try gz.addUnNode(.ensure_result_used, block_result, node);
    if (!gz.refIsNoReturn(block_result)) {
        _ = try block_scope.addBreak(.break_inline, block_inst, .void_value);
    }
    try block_scope.setBlockBody(block_inst);
    // block_scope unstacked now, can add new instructions to gz
    try gz.instructions.append(gpa, block_inst);

    return block_inst.toRef();
}

fn overflowArithmetic(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
    tag: Zir.Inst.Extended,
) InnerError!Zir.Inst.Ref {
    const lhs = try expr(gz, scope, .{ .rl = .none }, params[0]);
    const rhs = try expr(gz, scope, .{ .rl = .none }, params[1]);
    const result = try gz.addExtendedPayload(tag, Zir.Inst.BinNode{
        .node = gz.nodeIndexToRelative(node),
        .lhs = lhs,
        .rhs = rhs,
    });
    return rvalue(gz, ri, result, node);
}

fn callExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    /// If this is not `.none` and this call is a decl literal form (`.foo(...)`), then this
    /// type is used as the decl literal result type instead of the result type from `ri.rl`.
    override_decl_literal_type: Zir.Inst.Ref,
    node: Ast.Node.Index,
    call: Ast.full.Call,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;

    const callee = try calleeExpr(gz, scope, ri.rl, override_decl_literal_type, call.ast.fn_expr);
    const modifier: std.builtin.CallModifier = blk: {
        if (call.as```
