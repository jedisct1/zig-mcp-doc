```
                       ),
                    },
                );
            }
            const tag_value = try expr(&block_scope, &block_scope.base, .{ .rl = .{ .ty = arg_inst } }, value_expr);
            wip_members.appendToField(@intFromEnum(tag_value));
        }
    }

    var fields_hash: std.zig.SrcHash = undefined;
    astgen.src_hasher.final(&fields_hash);

    if (!block_scope.isEmpty()) {
        _ = try block_scope.addBreak(.break_inline, decl_inst, .void_value);
    }

    const body = block_scope.instructionsSlice();
    const body_len = astgen.countBodyLenAfterFixups(body);

    try gz.setUnion(decl_inst, .{
        .src_node = node,
        .layout = layout,
        .tag_type = arg_inst,
        .captures_len = @intCast(namespace.captures.count()),
        .body_len = body_len,
        .fields_len = field_count,
        .decls_len = decl_count,
        .auto_enum_tag = auto_enum_tok != null,
        .any_aligned_fields = any_aligned_fields,
        .fields_hash = fields_hash,
    });

    wip_members.finishBits(bits_per_field);
    const decls_slice = wip_members.declsSlice();
    const fields_slice = wip_members.fieldsSlice();
    try astgen.extra.ensureUnusedCapacity(gpa, namespace.captures.count() * 2 + decls_slice.len + body_len + fields_slice.len);
    astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.keys()));
    astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.values()));
    astgen.extra.appendSliceAssumeCapacity(decls_slice);
    astgen.appendBodyWithFixups(body);
    astgen.extra.appendSliceAssumeCapacity(fields_slice);

    block_scope.unstack();
    return decl_inst.toRef();
}

fn containerDecl(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    container_decl: Ast.full.ContainerDecl,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;

    const prev_fn_block = astgen.fn_block;
    astgen.fn_block = null;
    defer astgen.fn_block = prev_fn_block;

    // We must not create any types until Sema. Here the goal is only to generate
    // ZIR for all the field types, alignments, and default value expressions.

    switch (tree.tokenTag(container_decl.ast.main_token)) {
        .keyword_struct => {
            const layout: std.builtin.Type.ContainerLayout = if (container_decl.layout_token) |t| switch (tree.tokenTag(t)) {
                .keyword_packed => .@"packed",
                .keyword_extern => .@"extern",
                else => unreachable,
            } else .auto;

            const result = try structDeclInner(gz, scope, node, container_decl, layout, container_decl.ast.arg);
            return rvalue(gz, ri, result, node);
        },
        .keyword_union => {
            const layout: std.builtin.Type.ContainerLayout = if (container_decl.layout_token) |t| switch (tree.tokenTag(t)) {
                .keyword_packed => .@"packed",
                .keyword_extern => .@"extern",
                else => unreachable,
            } else .auto;

            const result = try unionDeclInner(gz, scope, node, container_decl.ast.members, layout, container_decl.ast.arg, container_decl.ast.enum_token);
            return rvalue(gz, ri, result, node);
        },
        .keyword_enum => {
            if (container_decl.layout_token) |t| {
                return astgen.failTok(t, "enums do not support 'packed' or 'extern'; instead provide an explicit integer tag type", .{});
            }
            // Count total fields as well as how many have explicitly provided tag values.
            const counts = blk: {
                var values: usize = 0;
                var total_fields: usize = 0;
                var decls: usize = 0;
                var opt_nonexhaustive_node: Ast.Node.OptionalIndex = .none;
                var nonfinal_nonexhaustive = false;
                for (container_decl.ast.members) |member_node| {
                    var member = tree.fullContainerField(member_node) orelse {
                        decls += 1;
                        continue;
                    };
                    member.convertToNonTupleLike(astgen.tree);
                    if (member.ast.tuple_like) {
                        return astgen.failTok(member.ast.main_token, "enum field missing name", .{});
                    }
                    if (member.comptime_token) |comptime_token| {
                        return astgen.failTok(comptime_token, "enum fields cannot be marked comptime", .{});
                    }
                    if (member.ast.type_expr.unwrap()) |type_expr| {
                        return astgen.failNodeNotes(
                            type_expr,
                            "enum fields do not have types",
                            .{},
                            &[_]u32{
                                try astgen.errNoteNode(
                                    node,
                                    "consider 'union(enum)' here to make it a tagged union",
                                    .{},
                                ),
                            },
                        );
                    }
                    if (member.ast.align_expr.unwrap()) |align_expr| {
                        return astgen.failNode(align_expr, "enum fields cannot be aligned", .{});
                    }

                    const name_token = member.ast.main_token;
                    if (mem.eql(u8, tree.tokenSlice(name_token), "_")) {
                        if (opt_nonexhaustive_node.unwrap()) |nonexhaustive_node| {
                            return astgen.failNodeNotes(
                                member_node,
                                "redundant non-exhaustive enum mark",
                                .{},
                                &[_]u32{
                                    try astgen.errNoteNode(
                                        nonexhaustive_node,
                                        "other mark here",
                                        .{},
                                    ),
                                },
                            );
                        }
                        opt_nonexhaustive_node = member_node.toOptional();
                        if (member.ast.value_expr.unwrap()) |value_expr| {
                            return astgen.failNode(value_expr, "'_' is used to mark an enum as non-exhaustive and cannot be assigned a value", .{});
                        }
                        continue;
                    } else if (opt_nonexhaustive_node != .none) {
                        nonfinal_nonexhaustive = true;
                    }
                    total_fields += 1;
                    if (member.ast.value_expr.unwrap()) |value_expr| {
                        if (container_decl.ast.arg == .none) {
                            return astgen.failNode(value_expr, "value assigned to enum tag with inferred tag type", .{});
                        }
                        values += 1;
                    }
                }
                if (nonfinal_nonexhaustive) {
                    return astgen.failNode(opt_nonexhaustive_node.unwrap().?, "'_' field of non-exhaustive enum must be last", .{});
                }
                break :blk .{
                    .total_fields = total_fields,
                    .values = values,
                    .decls = decls,
                    .nonexhaustive_node = opt_nonexhaustive_node,
                };
            };
            if (counts.nonexhaustive_node != .none and container_decl.ast.arg == .none) {
                const nonexhaustive_node = counts.nonexhaustive_node.unwrap().?;
                return astgen.failNodeNotes(
                    node,
                    "non-exhaustive enum missing integer tag type",
                    .{},
                    &[_]u32{
                        try astgen.errNoteNode(
                            nonexhaustive_node,
                            "marked non-exhaustive here",
                            .{},
                        ),
                    },
                );
            }
            // In this case we must generate ZIR code for the tag values, similar to
            // how structs are handled above.
            const nonexhaustive = counts.nonexhaustive_node != .none;

            const decl_inst = try gz.reserveInstructionIndex();

            var namespace: Scope.Namespace = .{
                .parent = scope,
                .node = node,
                .inst = decl_inst,
                .declaring_gz = gz,
                .maybe_generic = astgen.within_fn,
            };
            defer namespace.deinit(gpa);

            // The enum_decl instruction introduces a scope in which the decls of the enum
            // are in scope, so that tag values can refer to decls within the enum itself.
            astgen.advanceSourceCursorToNode(node);
            var block_scope: GenZir = .{
                .parent = &namespace.base,
                .decl_node_index = node,
                .decl_line = gz.decl_line,
                .astgen = astgen,
                .is_comptime = true,
                .instructions = gz.instructions,
                .instructions_top = gz.instructions.items.len,
            };
            defer block_scope.unstack();

            _ = try astgen.scanContainer(&namespace, container_decl.ast.members, .@"enum");
            namespace.base.tag = .namespace;

            const arg_inst: Zir.Inst.Ref = if (container_decl.ast.arg.unwrap()) |arg|
                try comptimeExpr(&block_scope, &namespace.base, coerced_type_ri, arg, .type)
            else
                .none;

            const bits_per_field = 1;
            const max_field_size = 2;
            var wip_members = try WipMembers.init(gpa, &astgen.scratch, @intCast(counts.decls), @intCast(counts.total_fields), bits_per_field, max_field_size);
            defer wip_members.deinit();

            const old_hasher = astgen.src_hasher;
            defer astgen.src_hasher = old_hasher;
            astgen.src_hasher = std.zig.SrcHasher.init(.{});
            if (container_decl.ast.arg.unwrap()) |arg| {
                astgen.src_hasher.update(tree.getNodeSource(arg));
            }
            astgen.src_hasher.update(&.{@intFromBool(nonexhaustive)});

            for (container_decl.ast.members) |member_node| {
                if (member_node.toOptional() == counts.nonexhaustive_node)
                    continue;
                astgen.src_hasher.update(tree.getNodeSource(member_node));
                var member = switch (try containerMember(&block_scope, &namespace.base, &wip_members, member_node)) {
                    .decl => continue,
                    .field => |field| field,
                };
                member.convertToNonTupleLike(astgen.tree);
                assert(member.comptime_token == null);
                assert(member.ast.type_expr == .none);
                assert(member.ast.align_expr == .none);

                const field_name = try astgen.identAsString(member.ast.main_token);
                wip_members.appendToField(@intFromEnum(field_name));

                const have_value = member.ast.value_expr != .none;
                wip_members.nextField(bits_per_field, .{have_value});

                if (member.ast.value_expr.unwrap()) |value_expr| {
                    if (arg_inst == .none) {
                        return astgen.failNodeNotes(
                            node,
                            "explicitly valued enum missing integer tag type",
                            .{},
                            &[_]u32{
                                try astgen.errNoteNode(
                                    value_expr,
                                    "tag value specified here",
                                    .{},
                                ),
                            },
                        );
                    }
                    const tag_value_inst = try expr(&block_scope, &namespace.base, .{ .rl = .{ .ty = arg_inst } }, value_expr);
                    wip_members.appendToField(@intFromEnum(tag_value_inst));
                }
            }

            if (!block_scope.isEmpty()) {
                _ = try block_scope.addBreak(.break_inline, decl_inst, .void_value);
            }

            var fields_hash: std.zig.SrcHash = undefined;
            astgen.src_hasher.final(&fields_hash);

            const body = block_scope.instructionsSlice();
            const body_len = astgen.countBodyLenAfterFixups(body);

            try gz.setEnum(decl_inst, .{
                .src_node = node,
                .nonexhaustive = nonexhaustive,
                .tag_type = arg_inst,
                .captures_len = @intCast(namespace.captures.count()),
                .body_len = body_len,
                .fields_len = @intCast(counts.total_fields),
                .decls_len = @intCast(counts.decls),
                .fields_hash = fields_hash,
            });

            wip_members.finishBits(bits_per_field);
            const decls_slice = wip_members.declsSlice();
            const fields_slice = wip_members.fieldsSlice();
            try astgen.extra.ensureUnusedCapacity(gpa, namespace.captures.count() * 2 + decls_slice.len + body_len + fields_slice.len);
            astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.keys()));
            astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.values()));
            astgen.extra.appendSliceAssumeCapacity(decls_slice);
            astgen.appendBodyWithFixups(body);
            astgen.extra.appendSliceAssumeCapacity(fields_slice);

            block_scope.unstack();
            return rvalue(gz, ri, decl_inst.toRef(), node);
        },
        .keyword_opaque => {
            assert(container_decl.ast.arg == .none);

            const decl_inst = try gz.reserveInstructionIndex();

            var namespace: Scope.Namespace = .{
                .parent = scope,
                .node = node,
                .inst = decl_inst,
                .declaring_gz = gz,
                .maybe_generic = astgen.within_fn,
            };
            defer namespace.deinit(gpa);

            astgen.advanceSourceCursorToNode(node);
            var block_scope: GenZir = .{
                .parent = &namespace.base,
                .decl_node_index = node,
                .decl_line = gz.decl_line,
                .astgen = astgen,
                .is_comptime = true,
                .instructions = gz.instructions,
                .instructions_top = gz.instructions.items.len,
            };
            defer block_scope.unstack();

            const decl_count = try astgen.scanContainer(&namespace, container_decl.ast.members, .@"opaque");

            var wip_members = try WipMembers.init(gpa, &astgen.scratch, decl_count, 0, 0, 0);
            defer wip_members.deinit();

            if (container_decl.layout_token) |layout_token| {
                return astgen.failTok(layout_token, "opaque types do not support 'packed' or 'extern'", .{});
            }

            for (container_decl.ast.members) |member_node| {
                const res = try containerMember(&block_scope, &namespace.base, &wip_members, member_node);
                if (res == .field) {
                    return astgen.failNode(member_node, "opaque types cannot have fields", .{});
                }
            }

            try gz.setOpaque(decl_inst, .{
                .src_node = node,
                .captures_len = @intCast(namespace.captures.count()),
                .decls_len = decl_count,
            });

            wip_members.finishBits(0);
            const decls_slice = wip_members.declsSlice();
            try astgen.extra.ensureUnusedCapacity(gpa, namespace.captures.count() * 2 + decls_slice.len);
            astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.keys()));
            astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.values()));
            astgen.extra.appendSliceAssumeCapacity(decls_slice);

            block_scope.unstack();
            return rvalue(gz, ri, decl_inst.toRef(), node);
        },
        else => unreachable,
    }
}

const ContainerMemberResult = union(enum) { decl, field: Ast.full.ContainerField };

fn containerMember(
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    member_node: Ast.Node.Index,
) InnerError!ContainerMemberResult {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    switch (tree.nodeTag(member_node)) {
        .container_field_init,
        .container_field_align,
        .container_field,
        => return ContainerMemberResult{ .field = tree.fullContainerField(member_node).? },

        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const full = tree.fullFnProto(&buf, member_node).?;

            const body: Ast.Node.OptionalIndex = if (tree.nodeTag(member_node) == .fn_decl)
                tree.nodeData(member_node).node_and_node[1].toOptional()
            else
                .none;

            const prev_decl_index = wip_members.decl_index;
            astgen.fnDecl(gz, scope, wip_members, member_node, body, full) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {
                    wip_members.decl_index = prev_decl_index;
                    try addFailedDeclaration(
                        wip_members,
                        gz,
                        .@"const",
                        try astgen.identAsString(full.name_token.?),
                        full.ast.proto_node,
                        full.visib_token != null,
                    );
                },
            };
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const full = tree.fullVarDecl(member_node).?;
            const prev_decl_index = wip_members.decl_index;
            astgen.globalVarDecl(gz, scope, wip_members, member_node, full) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {
                    wip_members.decl_index = prev_decl_index;
                    try addFailedDeclaration(
                        wip_members,
                        gz,
                        .@"const", // doesn't really matter
                        try astgen.identAsString(full.ast.mut_token + 1),
                        member_node,
                        full.visib_token != null,
                    );
                },
            };
        },

        .@"comptime" => {
            const prev_decl_index = wip_members.decl_index;
            astgen.comptimeDecl(gz, scope, wip_members, member_node) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {
                    wip_members.decl_index = prev_decl_index;
                    try addFailedDeclaration(
                        wip_members,
                        gz,
                        .@"comptime",
                        .empty,
                        member_node,
                        false,
                    );
                },
            };
        },
        .@"usingnamespace" => {
            const prev_decl_index = wip_members.decl_index;
            astgen.usingnamespaceDecl(gz, scope, wip_members, member_node) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {
                    wip_members.decl_index = prev_decl_index;
                    try addFailedDeclaration(
                        wip_members,
                        gz,
                        .@"usingnamespace",
                        .empty,
                        member_node,
                        tree.isTokenPrecededByTags(tree.nodeMainToken(member_node), &.{.keyword_pub}),
                    );
                },
            };
        },
        .test_decl => {
            const prev_decl_index = wip_members.decl_index;
            // We need to have *some* decl here so that the decl count matches what's expected.
            // Since it doesn't strictly matter *what* this is, let's save ourselves the trouble
            // of duplicating the test name logic, and just assume this is an unnamed test.
            astgen.testDecl(gz, scope, wip_members, member_node) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {
                    wip_members.decl_index = prev_decl_index;
                    try addFailedDeclaration(
                        wip_members,
                        gz,
                        .unnamed_test,
                        .empty,
                        member_node,
                        false,
                    );
                },
            };
        },
        else => unreachable,
    }
    return .decl;
}

fn errorSetDecl(gz: *GenZir, ri: ResultInfo, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;

    const payload_index = try reserveExtra(astgen, @typeInfo(Zir.Inst.ErrorSetDecl).@"struct".fields.len);
    var fields_len: usize = 0;
    {
        var idents: std.AutoHashMapUnmanaged(Zir.NullTerminatedString, Ast.TokenIndex) = .empty;
        defer idents.deinit(gpa);

        const lbrace, const rbrace = tree.nodeData(node).token_and_token;
        for (lbrace + 1..rbrace) |i| {
            const tok_i: Ast.TokenIndex = @intCast(i);
            switch (tree.tokenTag(tok_i)) {
                .doc_comment, .comma => {},
                .identifier => {
                    const str_index = try astgen.identAsString(tok_i);
                    const gop = try idents.getOrPut(gpa, str_index);
                    if (gop.found_existing) {
                        const name = try gpa.dupe(u8, mem.span(astgen.nullTerminatedString(str_index)));
                        defer gpa.free(name);
                        return astgen.failTokNotes(
                            tok_i,
                            "duplicate error set field '{s}'",
                            .{name},
                            &[_]u32{
                                try astgen.errNoteTok(
                                    gop.value_ptr.*,
                                    "previous declaration here",
                                    .{},
                                ),
                            },
                        );
                    }
                    gop.value_ptr.* = tok_i;

                    try astgen.extra.append(gpa, @intFromEnum(str_index));
                    fields_len += 1;
                },
                else => unreachable,
            }
        }
    }

    setExtra(astgen, payload_index, Zir.Inst.ErrorSetDecl{
        .fields_len = @intCast(fields_len),
    });
    const result = try gz.addPlNodePayloadIndex(.error_set_decl, node, payload_index);
    return rvalue(gz, ri, result, node);
}

fn tryExpr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;

    const fn_block = astgen.fn_block orelse {
        return astgen.failNode(node, "'try' outside function scope", .{});
    };

    if (parent_gz.any_defer_node.unwrap()) |any_defer_node| {
        return astgen.failNodeNotes(node, "'try' not allowed inside defer expression", .{}, &.{
            try astgen.errNoteNode(
                any_defer_node,
                "defer expression here",
                .{},
            ),
        });
    }

    // Ensure debug line/column information is emitted for this try expression.
    // Then we will save the line/column so that we can emit another one that goes
    // "backwards" because we want to evaluate the operand, but then put the debug
    // info back at the try keyword for error return tracing.
    if (!parent_gz.is_comptime) {
        try emitDbgNode(parent_gz, node);
    }
    const try_lc: LineColumn = .{ astgen.source_line - parent_gz.decl_line, astgen.source_column };

    const operand_rl: ResultInfo.Loc, const block_tag: Zir.Inst.Tag = switch (ri.rl) {
        .ref, .ref_coerced_ty => .{ .ref, .try_ptr },
        else => .{ .none, .@"try" },
    };
    const operand_ri: ResultInfo = .{ .rl = operand_rl, .ctx = .error_handling_expr };
    const operand = operand: {
        // As a special case, we need to detect this form:
        // `try .foo(...)`
        // This is a decl literal form, even though we don't propagate a result type through `try`.
        var buf: [1]Ast.Node.Index = undefined;
        if (astgen.tree.fullCall(&buf, operand_node)) |full_call| {
            const res_ty: Zir.Inst.Ref = try ri.rl.resultType(parent_gz, operand_node) orelse .none;
            break :operand try callExpr(parent_gz, scope, operand_ri, res_ty, operand_node, full_call);
        }

        // This could be a pointer or value depending on the `ri` parameter.
        break :operand try reachableExpr(parent_gz, scope, operand_ri, operand_node, node);
    };

    const try_inst = try parent_gz.makeBlockInst(block_tag, node);
    try parent_gz.instructions.append(astgen.gpa, try_inst);

    var else_scope = parent_gz.makeSubBlock(scope);
    defer else_scope.unstack();

    const err_tag = switch (ri.rl) {
        .ref, .ref_coerced_ty => Zir.Inst.Tag.err_union_code_ptr,
        else => Zir.Inst.Tag.err_union_code,
    };
    const err_code = try else_scope.addUnNode(err_tag, operand, node);
    try genDefers(&else_scope, &fn_block.base, scope, .{ .both = err_code });
    try emitDbgStmt(&else_scope, try_lc);
    _ = try else_scope.addUnNode(.ret_node, err_code, node);

    try else_scope.setTryBody(try_inst, operand);
    const result = try_inst.toRef();
    switch (ri.rl) {
        .ref, .ref_coerced_ty => return result,
        else => return rvalue(parent_gz, ri, result, node),
    }
}

fn orelseCatchExpr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    cond_op: Zir.Inst.Tag,
    unwrap_op: Zir.Inst.Tag,
    unwrap_code_op: Zir.Inst.Tag,
    payload_token: ?Ast.TokenIndex,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;

    const lhs, const rhs = tree.nodeData(node).node_and_node;

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.resultType(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).@"union".tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    const do_err_trace = astgen.fn_block != null and (cond_op == .is_non_err or cond_op == .is_non_err_ptr);

    var block_scope = parent_gz.makeSubBlock(scope);
    block_scope.setBreakResultInfo(block_ri);
    defer block_scope.unstack();

    const operand_ri: ResultInfo = switch (block_scope.break_result_info.rl) {
        .ref, .ref_coerced_ty => .{ .rl = .ref, .ctx = if (do_err_trace) .error_handling_expr else .none },
        else => .{ .rl = .none, .ctx = if (do_err_trace) .error_handling_expr else .none },
    };
    // This could be a pointer or value depending on the `operand_ri` parameter.
    // We cannot use `block_scope.break_result_info` because that has the bare
    // type, whereas this expression has the optional type. Later we make
    // up for this fact by calling rvalue on the else branch.
    const operand = try reachableExpr(&block_scope, &block_scope.base, operand_ri, lhs, rhs);
    const cond = try block_scope.addUnNode(cond_op, operand, node);
    const condbr = try block_scope.addCondBr(.condbr, node);

    const block = try parent_gz.makeBlockInst(.block, node);
    try block_scope.setBlockBody(block);
    // block_scope unstacked now, can add new instructions to parent_gz
    try parent_gz.instructions.append(astgen.gpa, block);

    var then_scope = block_scope.makeSubBlock(scope);
    defer then_scope.unstack();

    // This could be a pointer or value depending on `unwrap_op`.
    const unwrapped_payload = try then_scope.addUnNode(unwrap_op, operand, node);
    const then_result = switch (ri.rl) {
        .ref, .ref_coerced_ty => unwrapped_payload,
        else => try rvalue(&then_scope, block_scope.break_result_info, unwrapped_payload, node),
    };
    _ = try then_scope.addBreakWithSrcNode(.@"break", block, then_result, node);

    var else_scope = block_scope.makeSubBlock(scope);
    defer else_scope.unstack();

    // We know that the operand (almost certainly) modified the error return trace,
    // so signal to Sema that it should save the new index for restoring later.
    if (do_err_trace and nodeMayAppendToErrorTrace(tree, lhs))
        _ = try else_scope.addSaveErrRetIndex(.always);

    var err_val_scope: Scope.LocalVal = undefined;
    const else_sub_scope = blk: {
        const payload = payload_token orelse break :blk &else_scope.base;
        const err_str = tree.tokenSlice(payload);
        if (mem.eql(u8, err_str, "_")) {
            try astgen.appendErrorTok(payload, "discard of error capture; omit it instead", .{});
            break :blk &else_scope.base;
        }
        const err_name = try astgen.identAsString(payload);

        try astgen.detectLocalShadowing(scope, err_name, payload, err_str, .capture);

        err_val_scope = .{
            .parent = &else_scope.base,
            .gen_zir = &else_scope,
            .name = err_name,
            .inst = try else_scope.addUnNode(unwrap_code_op, operand, node),
            .token_src = payload,
            .id_cat = .capture,
        };
        break :blk &err_val_scope.base;
    };

    const else_result = try fullBodyExpr(&else_scope, else_sub_scope, block_scope.break_result_info, rhs, .allow_branch_hint);
    if (!else_scope.endsWithNoReturn()) {
        // As our last action before the break, "pop" the error trace if needed
        if (do_err_trace)
            try restoreErrRetIndex(&else_scope, .{ .block = block }, block_scope.break_result_info, rhs, else_result);

        _ = try else_scope.addBreakWithSrcNode(.@"break", block, else_result, rhs);
    }
    try checkUsed(parent_gz, &else_scope.base, else_sub_scope);

    try setCondBrPayload(condbr, cond, &then_scope, &else_scope);

    if (need_result_rvalue) {
        return rvalue(parent_gz, ri, block.toRef(), node);
    } else {
        return block.toRef();
    }
}

/// Return whether the identifier names of two tokens are equal. Resolves @""
/// tokens without allocating.
/// OK in theory it could do it without allocating. This implementation
/// allocates when the @"" form is used.
fn tokenIdentEql(astgen: *AstGen, token1: Ast.TokenIndex, token2: Ast.TokenIndex) !bool {
    const ident_name_1 = try astgen.identifierTokenString(token1);
    const ident_name_2 = try astgen.identifierTokenString(token2);
    return mem.eql(u8, ident_name_1, ident_name_2);
}

fn fieldAccess(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    switch (ri.rl) {
        .ref, .ref_coerced_ty => return addFieldAccess(.field_ptr, gz, scope, .{ .rl = .ref }, node),
        else => {
            const access = try addFieldAccess(.field_val, gz, scope, .{ .rl = .none }, node);
            return rvalue(gz, ri, access, node);
        },
    }
}

fn addFieldAccess(
    tag: Zir.Inst.Tag,
    gz: *GenZir,
    scope: *Scope,
    lhs_ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const object_node, const field_ident = tree.nodeData(node).node_and_token;
    const str_index = try astgen.identAsString(field_ident);
    const lhs = try expr(gz, scope, lhs_ri, object_node);

    const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);
    try emitDbgStmt(gz, cursor);

    return gz.addPlNode(tag, node, Zir.Inst.Field{
        .lhs = lhs,
        .field_name_start = str_index,
    });
}

fn arrayAccess(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const tree = gz.astgen.tree;
    switch (ri.rl) {
        .ref, .ref_coerced_ty => {
            const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;
            const lhs = try expr(gz, scope, .{ .rl = .ref }, lhs_node);

            const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);

            const rhs = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, rhs_node);
            try emitDbgStmt(gz, cursor);

            return gz.addPlNode(.elem_ptr_node, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs });
        },
        else => {
            const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;
            const lhs = try expr(gz, scope, .{ .rl = .none }, lhs_node);

            const cursor = maybeAdvanceSourceCursorToMainToken(gz, node);

            const rhs = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, rhs_node);
            try emitDbgStmt(gz, cursor);

            return rvalue(gz, ri, try gz.addPlNode(.elem_val_node, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs }), node);
        },
    }
}

fn simpleBinOp(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;

    if (op_inst_tag == .cmp_neq or op_inst_tag == .cmp_eq) {
        const str = if (op_inst_tag == .cmp_eq) "==" else "!=";
        if (tree.nodeTag(lhs_node) == .string_literal or
            tree.nodeTag(rhs_node) == .string_literal)
            return astgen.failNode(node, "cannot compare strings with {s}", .{str});
    }

    const lhs = try reachableExpr(gz, scope, .{ .rl = .none }, lhs_node, node);
    const cursor = switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => maybeAdvanceSourceCursorToMainToken(gz, node),
        else => undefined,
    };
    const rhs = try reachableExpr(gz, scope, .{ .rl = .none }, rhs_node, node);

    switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => {
            try emitDbgStmt(gz, cursor);
        },
        else => {},
    }
    const result = try gz.addPlNode(op_inst_tag, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs });
    return rvalue(gz, ri, result, node);
}

fn simpleStrTok(
    gz: *GenZir,
    ri: ResultInfo,
    ident_token: Ast.TokenIndex,
    node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const str_index = try astgen.identAsString(ident_token);
    const result = try gz.addStrTok(op_inst_tag, str_index, ident_token);
    return rvalue(gz, ri, result, node);
}

fn boolBinOp(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    zir_tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;
    const lhs = try expr(gz, scope, coerced_bool_ri, lhs_node);
    const bool_br = (try gz.addPlNodePayloadIndex(zir_tag, node, undefined)).toIndex().?;

    var rhs_scope = gz.makeSubBlock(scope);
    defer rhs_scope.unstack();
    const rhs = try fullBodyExpr(&rhs_scope, &rhs_scope.base, coerced_bool_ri, rhs_node, .allow_branch_hint);
    if (!gz.refIsNoReturn(rhs)) {
        _ = try rhs_scope.addBreakWithSrcNode(.break_inline, bool_br, rhs, rhs_node);
    }
    try rhs_scope.setBoolBrBody(bool_br, lhs);

    const block_ref = bool_br.toRef();
    return rvalue(gz, ri, block_ref, node);
}

fn ifExpr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    if_full: Ast.full.If,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;

    const do_err_trace = astgen.fn_block != null and if_full.error_token != null;

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.resultType(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).@"union".tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    var block_scope = parent_gz.makeSubBlock(scope);
    block_scope.setBreakResultInfo(block_ri);
    defer block_scope.unstack();

    const payload_is_ref = if (if_full.payload_token) |payload_token|
        tree.tokenTag(payload_token) == .asterisk
    else
        false;

    try emitDbgNode(parent_gz, if_full.ast.cond_expr);
    const cond: struct {
        inst: Zir.Inst.Ref,
        bool_bit: Zir.Inst.Ref,
    } = c: {
        if (if_full.error_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none, .ctx = .error_handling_expr };
            const err_union = try expr(&block_scope, &block_scope.base, cond_ri, if_full.ast.cond_expr);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_err_ptr else .is_non_err;
            break :c .{
                .inst = err_union,
                .bool_bit = try block_scope.addUnNode(tag, err_union, if_full.ast.cond_expr),
            };
        } else if (if_full.payload_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none };
            const optional = try expr(&block_scope, &block_scope.base, cond_ri, if_full.ast.cond_expr);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_null_ptr else .is_non_null;
            break :c .{
                .inst = optional,
                .bool_bit = try block_scope.addUnNode(tag, optional, if_full.ast.cond_expr),
            };
        } else {
            const cond = try expr(&block_scope, &block_scope.base, coerced_bool_ri, if_full.ast.cond_expr);
            break :c .{
                .inst = cond,
                .bool_bit = cond,
            };
        }
    };

    const condbr = try block_scope.addCondBr(.condbr, node);

    const block = try parent_gz.makeBlockInst(.block, node);
    try block_scope.setBlockBody(block);
    // block_scope unstacked now, can add new instructions to parent_gz
    try parent_gz.instructions.append(astgen.gpa, block);

    var then_scope = parent_gz.makeSubBlock(scope);
    defer then_scope.unstack();

    var payload_val_scope: Scope.LocalVal = undefined;

    const then_node = if_full.ast.then_expr;
    const then_sub_scope = s: {
        if (if_full.error_token != null) {
            if (if_full.payload_token) |payload_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_payload_unsafe_ptr
                else
                    .err_union_payload_unsafe;
                const payload_inst = try then_scope.addUnNode(tag, cond.inst, then_node);
                const token_name_index = payload_token + @intFromBool(payload_is_ref);
                const ident_name = try astgen.identAsString(token_name_index);
                const token_name_str = tree.tokenSlice(token_name_index);
                if (mem.eql(u8, "_", token_name_str)) {
                    if (payload_is_ref) return astgen.failTok(payload_token, "pointer modifier invalid on discard", .{});
                    break :s &then_scope.base;
                }
                try astgen.detectLocalShadowing(&then_scope.base, ident_name, token_name_index, token_name_str, .capture);
                payload_val_scope = .{
                    .parent = &then_scope.base,
                    .gen_zir = &then_scope,
                    .name = ident_name,
                    .inst = payload_inst,
                    .token_src = token_name_index,
                    .id_cat = .capture,
                };
                try then_scope.addDbgVar(.dbg_var_val, ident_name, payload_inst);
                break :s &payload_val_scope.base;
            } else {
                _ = try then_scope.addUnNode(.ensure_err_union_payload_void, cond.inst, node);
                break :s &then_scope.base;
            }
        } else if (if_full.payload_token) |payload_token| {
            const ident_token = payload_token + @intFromBool(payload_is_ref);
            const tag: Zir.Inst.Tag = if (payload_is_ref)
                .optional_payload_unsafe_ptr
            else
                .optional_payload_unsafe;
            const ident_bytes = tree.tokenSlice(ident_token);
            if (mem.eql(u8, "_", ident_bytes)) {
                if (payload_is_ref) return astgen.failTok(payload_token, "pointer modifier invalid on discard", .{});
                break :s &then_scope.base;
            }
            const payload_inst = try then_scope.addUnNode(tag, cond.inst, then_node);
            const ident_name = try astgen.identAsString(ident_token);
            try astgen.detectLocalShadowing(&then_scope.base, ident_name, ident_token, ident_bytes, .capture);
            payload_val_scope = .{
                .parent = &then_scope.base,
                .gen_zir = &then_scope,
                .name = ident_name,
                .inst = payload_inst,
                .token_src = ident_token,
                .id_cat = .capture,
            };
            try then_scope.addDbgVar(.dbg_var_val, ident_name, payload_inst);
            break :s &payload_val_scope.base;
        } else {
            break :s &then_scope.base;
        }
    };

    const then_result = try fullBodyExpr(&then_scope, then_sub_scope, block_scope.break_result_info, then_node, .allow_branch_hint);
    try checkUsed(parent_gz, &then_scope.base, then_sub_scope);
    if (!then_scope.endsWithNoReturn()) {
        _ = try then_scope.addBreakWithSrcNode(.@"break", block, then_result, then_node);
    }

    var else_scope = parent_gz.makeSubBlock(scope);
    defer else_scope.unstack();

    // We know that the operand (almost certainly) modified the error return trace,
    // so signal to Sema that it should save the new index for restoring later.
    if (do_err_trace and nodeMayAppendToErrorTrace(tree, if_full.ast.cond_expr))
        _ = try else_scope.addSaveErrRetIndex(.always);

    if (if_full.ast.else_expr.unwrap()) |else_node| {
        const sub_scope = s: {
            if (if_full.error_token) |error_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_code_ptr
                else
                    .err_union_code;
                const payload_inst = try else_scope.addUnNode(tag, cond.inst, if_full.ast.cond_expr);
                const ident_name = try astgen.identAsString(error_token);
                const error_token_str = tree.tokenSlice(error_token);
                if (mem.eql(u8, "_", error_token_str))
                    break :s &else_scope.base;
                try astgen.detectLocalShadowing(&else_scope.base, ident_name, error_token, error_token_str, .capture);
                payload_val_scope = .{
                    .parent = &else_scope.base,
                    .gen_zir = &else_scope,
                    .name = ident_name,
                    .inst = payload_inst,
                    .token_src = error_token,
                    .id_cat = .capture,
                };
                try else_scope.addDbgVar(.dbg_var_val, ident_name, payload_inst);
                break :s &payload_val_scope.base;
            } else {
                break :s &else_scope.base;
            }
        };
        const else_result = try fullBodyExpr(&else_scope, sub_scope, block_scope.break_result_info, else_node, .allow_branch_hint);
        if (!else_scope.endsWithNoReturn()) {
            // As our last action before the break, "pop" the error trace if needed
            if (do_err_trace)
                try restoreErrRetIndex(&else_scope, .{ .block = block }, block_scope.break_result_info, else_node, else_result);
            _ = try else_scope.addBreakWithSrcNode(.@"break", block, else_result, else_node);
        }
        try checkUsed(parent_gz, &else_scope.base, sub_scope);
    } else {
        const result = try rvalue(&else_scope, ri, .void_value, node);
        _ = try else_scope.addBreak(.@"break", block, result);
    }

    try setCondBrPayload(condbr, cond.bool_bit, &then_scope, &else_scope);

    if (need_result_rvalue) {
        return rvalue(parent_gz, ri, block.toRef(), node);
    } else {
        return block.toRef();
    }
}

/// Supports `else_scope` stacked on `then_scope`. Unstacks `else_scope` then `then_scope`.
fn setCondBrPayload(
    condbr: Zir.Inst.Index,
    cond: Zir.Inst.Ref,
    then_scope: *GenZir,
    else_scope: *GenZir,
) !void {
    defer then_scope.unstack();
    defer else_scope.unstack();
    const astgen = then_scope.astgen;
    const then_body = then_scope.instructionsSliceUpto(else_scope);
    const else_body = else_scope.instructionsSlice();
    const then_body_len = astgen.countBodyLenAfterFixups(then_body);
    const else_body_len = astgen.countBodyLenAfterFixups(else_body);
    try astgen.extra.ensureUnusedCapacity(
        astgen.gpa,
        @typeInfo(Zir.Inst.CondBr).@"struct".fields.len + then_body_len + else_body_len,
    );

    const zir_datas = astgen.instructions.items(.data);
    zir_datas[@intFromEnum(condbr)].pl_node.payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.CondBr{
        .condition = cond,
        .then_body_len = then_body_len,
        .else_body_len = else_body_len,
    });
    astgen.appendBodyWithFixups(then_body);
    astgen.appendBodyWithFixups(else_body);
}

fn whileExpr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    while_full: Ast.full.While,
    is_statement: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.resultType(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).@"union".tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    if (while_full.label_token) |label_token| {
        try astgen.checkLabelRedefinition(scope, label_token);
    }

    const is_inline = while_full.inline_token != null;
    if (parent_gz.is_comptime and is_inline) {
        try astgen.appendErrorTok(while_full.inline_token.?, "redundant inline keyword in comptime scope", .{});
    }
    const loop_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .loop;
    const loop_block = try parent_gz.makeBlockInst(loop_tag, node);
    try parent_gz.instructions.append(astgen.gpa, loop_block);

    var loop_scope = parent_gz.makeSubBlock(scope);
    loop_scope.is_inline = is_inline;
    loop_scope.setBreakResultInfo(block_ri);
    defer loop_scope.unstack();

    var cond_scope = parent_gz.makeSubBlock(&loop_scope.base);
    defer cond_scope.unstack();

    const payload_is_ref = if (while_full.payload_token) |payload_token|
        tree.tokenTag(payload_token) == .asterisk
    else
        false;

    try emitDbgNode(parent_gz, while_full.ast.cond_expr);
    const cond: struct {
        inst: Zir.Inst.Ref,
        bool_bit: Zir.Inst.Ref,
    } = c: {
        if (while_full.error_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none };
            const err_union = try fullBodyExpr(&cond_scope, &cond_scope.base, cond_ri, while_full.ast.cond_expr, .normal);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_err_ptr else .is_non_err;
            break :c .{
                .inst = err_union,
                .bool_bit = try cond_scope.addUnNode(tag, err_union, while_full.ast.cond_expr),
            };
        } else if (while_full.payload_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none };
            const optional = try fullBodyExpr(&cond_scope, &cond_scope.base, cond_ri, while_full.ast.cond_expr, .normal);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_null_ptr else .is_non_null;
            break :c .{
                .inst = optional,
                .bool_bit = try cond_scope.addUnNode(tag, optional, while_full.ast.cond_expr),
            };
        } else {
            const cond = try fullBodyExpr(&cond_scope, &cond_scope.base, coerced_bool_ri, while_full.ast.cond_expr, .normal);
            break :c .{
                .inst = cond,
                .bool_bit = cond,
            };
        }
    };

    const condbr_tag: Zir.Inst.Tag = if (is_inline) .condbr_inline else .condbr;
    const condbr = try cond_scope.addCondBr(condbr_tag, node);
    const block_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .block;
    const cond_block = try loop_scope.makeBlockInst(block_tag, node);
    try cond_scope.setBlockBody(cond_block);
    // cond_scope unstacked now, can add new instructions to loop_scope
    try loop_scope.instructions.append(astgen.gpa, cond_block);

    // make scope now but don't stack on parent_gz until loop_scope
    // gets unstacked after cont_expr is emitted and added below
    var then_scope = parent_gz.makeSubBlock(&cond_scope.base);
    then_scope.instructions_top = GenZir.unstacked_top;
    defer then_scope.unstack();

    var dbg_var_name: Zir.NullTerminatedString = .empty;
    var dbg_var_inst: Zir.Inst.Ref = undefined;
    var opt_payload_inst: Zir.Inst.OptionalIndex = .none;
    var payload_val_scope: Scope.LocalVal = undefined;
    const then_sub_scope = s: {
        if (while_full.error_token != null) {
            if (while_full.payload_token) |payload_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_payload_unsafe_ptr
                else
                    .err_union_payload_unsafe;
                // will add this instruction to then_scope.instructions below
                const payload_inst = try then_scope.makeUnNode(tag, cond.inst, while_full.ast.cond_expr);
                opt_payload_inst = payload_inst.toOptional();
                const ident_token = payload_token + @intFromBool(payload_is_ref);
                const ident_bytes = tree.tokenSlice(ident_token);
                if (mem.eql(u8, "_", ident_bytes)) {
                    if (payload_is_ref) return astgen.failTok(payload_token, "pointer modifier invalid on discard", .{});
                    break :s &then_scope.base;
                }
                const ident_name = try astgen.identAsString(ident_token);
                try astgen.detectLocalShadowing(&then_scope.base, ident_name, ident_token, ident_bytes, .capture);
                payload_val_scope = .{
                    .parent = &then_scope.base,
                    .gen_zir = &then_scope,
                    .name = ident_name,
                    .inst = payload_inst.toRef(),
                    .token_src = ident_token,
                    .id_cat = .capture,
                };
                dbg_var_name = ident_name;
                dbg_var_inst = payload_inst.toRef();
                break :s &payload_val_scope.base;
            } else {
                _ = try then_scope.addUnNode(.ensure_err_union_payload_void, cond.inst, node);
                break :s &then_scope.base;
            }
        } else if (while_full.payload_token) |payload_token| {
            const tag: Zir.Inst.Tag = if (payload_is_ref)
                .optional_payload_unsafe_ptr
            else
                .optional_payload_unsafe;
            // will add this instruction to then_scope.instructions below
            const payload_inst = try then_scope.makeUnNode(tag, cond.inst, while_full.ast.cond_expr);
            opt_payload_inst = payload_inst.toOptional();
            const ident_token = payload_token + @intFromBool(payload_is_ref);
            const ident_name = try astgen.identAsString(ident_token);
            const ident_bytes = tree.tokenSlice(ident_token);
            if (mem.eql(u8, "_", ident_bytes)) {
                if (payload_is_ref) return astgen.failTok(payload_token, "pointer modifier invalid on discard", .{});
                break :s &then_scope.base;
            }
            try astgen.detectLocalShadowing(&then_scope.base, ident_name, ident_token, ident_bytes, .capture);
            payload_val_scope = .{
                .parent = &then_scope.base,
                .gen_zir = &then_scope,
                .name = ident_name,
                .inst = payload_inst.toRef(),
                .token_src = ident_token,
                .id_cat = .capture,
            };
            dbg_var_name = ident_name;
            dbg_var_inst = payload_inst.toRef();
            break :s &payload_val_scope.base;
        } else {
            break :s &then_scope.base;
        }
    };

    var continue_scope = parent_gz.makeSubBlock(then_sub_scope);
    continue_scope.instructions_top = GenZir.unstacked_top;
    defer continue_scope.unstack();
    const continue_block = try then_scope.makeBlockInst(block_tag, node);

    const repeat_tag: Zir.Inst.Tag = if (is_inline) .repeat_inline else .repeat;
    _ = try loop_scope.addNode(repeat_tag, node);

    try loop_scope.setBlockBody(loop_block);
    loop_scope.break_block = loop_block.toOptional();
    loop_scope.continue_block = continue_block.toOptional();
    if (while_full.label_token) |label_token| {
        loop_scope.label = .{
            .token = label_token,
            .block_inst = loop_block,
        };
    }

    // done adding instructions to loop_scope, can now stack then_scope
    then_scope.instructions_top = then_scope.instructions.items.len;

    const then_node = while_full.ast.then_expr;
    if (opt_payload_inst.unwrap()) |payload_inst| {
        try then_scope.instructions.append(astgen.gpa, payload_inst);
    }
    if (dbg_var_name != .empty) try then_scope.addDbgVar(.dbg_var_val, dbg_var_name, dbg_var_inst);
    try then_scope.instructions.append(astgen.gpa, continue_block);
    // This code could be improved to avoid emitting the continue expr when there
    // are no jumps to it. This happens when the last statement of a while body is noreturn
    // and there are no `continue` statements.
    // Tracking issue: https://github.com/ziglang/zig/issues/9185
    if (while_full.ast.cont_expr.unwrap()) |cont_expr| {
        _ = try unusedResultExpr(&then_scope, then_sub_scope, cont_expr);
    }

    continue_scope.instructions_top = continue_scope.instructions.items.len;
    {
        try emitDbgNode(&continue_scope, then_node);
        const unused_result = try fullBodyExpr(&continue_scope, &continue_scope.base, .{ .rl = .none }, then_node, .allow_branch_hint);
        _ = try addEnsureResult(&continue_scope, unused_result, then_node);
    }
    try checkUsed(parent_gz, &then_scope.base, then_sub_scope);
    const break_tag: Zir.Inst.Tag = if (is_inline) .break_inline else .@"break";
    if (!continue_scope.endsWithNoReturn()) {
        astgen.advanceSourceCursor(tree.tokenStart(tree.lastToken(then_node)));
        try emitDbgStmt(parent_gz, .{ astgen.source_line - parent_gz.decl_line, astgen.source_column });
        _ = try parent_gz.add(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .dbg_empty_stmt,
                .small = undefined,
                .operand = undefined,
            } },
        });
        _ = try continue_scope.addBreak(break_tag, continue_block, .void_value);
    }
    try continue_scope.setBlockBody(continue_block);
    _ = try then_scope.addBreak(break_tag, cond_block, .void_value);

    var else_scope = parent_gz.makeSubBlock(&cond_scope.base);
    defer else_scope.unstack();

    if (while_full.ast.else_expr.unwrap()) |else_node| {
        const sub_scope = s: {
            if (while_full.error_token) |error_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_code_ptr
                else
                    .err_union_code;
                const else_payload_inst = try else_scope.addUnNode(tag, cond.inst, while_full.ast.cond_expr);
                const ident_name = try astgen.identAsString(error_token);
                const ident_bytes = tree.tokenSlice(error_token);
                if (mem.eql(u8, ident_bytes, "_"))
                    break :s &else_scope.base;
                try astgen.detectLocalShadowing(&else_scope.base, ident_name, error_token, ident_bytes, .capture);
                payload_val_scope = .{
                    .parent = &else_scope.base,
                    .gen_zir = &else_scope,
                    .name = ident_name,
                    .inst = else_payload_inst,
                    .token_src = error_token,
                    .id_cat = .capture,
                };
                try else_scope.addDbgVar(.dbg_var_val, ident_name, else_payload_inst);
                break :s &payload_val_scope.base;
            } else {
                break :s &else_scope.base;
            }
        };
        // Remove the continue block and break block so that `continue` and `break`
        // control flow apply to outer loops; not this one.
        loop_scope.continue_block = .none;
        loop_scope.break_block = .none;
        const else_result = try fullBodyExpr(&else_scope, sub_scope, loop_scope.break_result_info, else_node, .allow_branch_hint);
        if (is_statement) {
            _ = try addEnsureResult(&else_scope, else_result, else_node);
        }

        try checkUsed(parent_gz, &else_scope.base, sub_scope);
        if (!else_scope.endsWithNoReturn()) {
            _ = try else_scope.addBreakWithSrcNode(break_tag, loop_block, else_result, else_node);
        }
    } else {
        const result = try rvalue(&else_scope, ri, .void_value, node);
        _ = try else_scope.addBreak(break_tag, loop_block, result);
    }

    if (loop_scope.label) |some| {
        if (!some.used) {
            try astgen.appendErrorTok(some.token, "unused while loop label", .{});
        }
    }

    try setCondBrPayload(condbr, cond.bool_bit, &then_scope, &else_scope);

    const result = if (need_result_rvalue)
        try rvalue(parent_gz, ri, loop_block.toRef(), node)
    else
        loop_block.toRef();

    if (is_statement) {
        _ = try parent_gz.addUnNode(.ensure_result_used, result, node);
    }

    return result;
}

fn forExpr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    for_full: Ast.full.For,
    is_statement: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;

    if (for_full.label_token) |label_token| {
        try astgen.checkLabelRedefinition(scope, label_token);
    }

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.resultType(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).@"union".tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    const is_inline = for_full.inline_token != null;
    if (parent_gz.is_comptime and is_inline) {
        try astgen.appendErrorTok(for_full.inline_token.?, "redundant inline keyword in comptime scope", .{});
    }
    const tree = astgen.tree;
    const gpa = astgen.gpa;

    // For counters, this is the start value; for indexables, this is the base
    // pointer that can be used with elem_ptr and similar instructions.
    // Special value `none` means that this is a counter and its start value is
    // zero, indicating that the main index counter can be used directly.
    const indexables = try gpa.alloc(Zir.Inst.Ref, for_full.ast.inputs.len);
    defer gpa.free(indexables);
    // elements of this array can be `none`, indicating no length check.
    const lens = try gpa.alloc([2]Zir.Inst.Ref, for_full.ast.inputs.len);
    defer gpa.free(lens);

    // We will use a single zero-based counter no matter how many indexables there are.
    const index_ptr = blk: {
        const alloc_tag: Zir.Inst.Tag = if (is_inline) .alloc_comptime_mut else .alloc;
        const index_ptr = try parent_gz.addUnNode(alloc_tag, .usize_type, node);
        // initialize to zero
        _ = try parent_gz.addPlNode(.store_node, node, Zir.Inst.Bin{
            .lhs = index_ptr,
            .rhs = .zero_usize,
        });
        break :blk index_ptr;
    };

    var any_len_checks = false;

    {
        var capture_token = for_full.payload_token;
        for (for_full.ast.inputs, indexables, lens) |input, *indexable_ref, *len_refs| {
            const capture_is_ref = tree.tokenTag(capture_token) == .asterisk;
            const ident_tok = capture_token + @intFromBool(capture_is_ref);
            const is_discard = mem.eql(u8, tree.tokenSlice(ident_tok), "_");

            if (is_discard and capture_is_ref) {
                return astgen.failTok(capture_token, "pointer modifier invalid on discard", .{});
            }
            // Skip over the comma, and on to the next capture (or the ending pipe character).
            capture_token = ident_tok + 2;

            try emitDbgNode(parent_gz, input);
            if (tree.nodeTag(input) == .for_range) {
                if (capture_is_ref) {
                    return astgen.failTok(ident_tok, "cannot capture reference to range", .{});
                }
                const start_node, const end_node = tree.nodeData(input).node_and_opt_node;
                const start_val = try expr(parent_gz, scope, .{ .rl = .{ .ty = .usize_type } }, start_node);

                const end_val = if (end_node.unwrap()) |end|
                    try expr(parent_gz, scope, .{ .rl = .{ .ty = .usize_type } }, end)
                else
                    .none;

                if (end_val == .none and is_discard) {
                    try astgen.appendErrorTok(ident_tok, "discard of unbounded counter", .{});
                }

                if (end_val == .none) {
                    len_refs.* = .{ .none, .none };
                } else {
                    any_len_checks = true;
                    len_refs.* = .{ start_val, end_val };
                }

                const start_is_zero = nodeIsTriviallyZero(tree, start_node);
                indexable_ref.* = if (start_is_zero) .none else start_val;
            } else {
                const indexable = try expr(parent_gz, scope, .{ .rl = .none }, input);

                any_len_checks = true;
                indexable_ref.* = indexable;
                len_refs.* = .{ indexable, .none };
            }
        }
    }

    if (!any_len_checks) {
        return astgen.failNode(node, "unbounded for loop", .{});
    }

    // We use a dedicated ZIR instruction to assert the lengths to assist with
    // nicer error reporting as well as fewer ZIR bytes emitted.
    const len: Zir.Inst.Ref = len: {
        const all_lens = @as([*]Zir.Inst.Ref, @ptrCast(lens))[0 .. lens.len * 2];
        const lens_len: u32 = @intCast(all_lens.len);
        try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.MultiOp).@"struct".fields.len + lens_len);
        const len = try parent_gz.addPlNode(.for_len, node, Zir.Inst.MultiOp{
            .operands_len = lens_len,
        });
        appendRefsAssumeCapacity(astgen, all_lens);
        break :len len;
    };

    const loop_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .loop;
    const loop_block = try parent_gz.makeBlockInst(loop_tag, node);
    try parent_gz.instructions.append(gpa, loop_block);

    var loop_scope = parent_gz.makeSubBlock(scope);
    loop_scope.is_inline = is_inline;
    loop_scope.setBreakResultInfo(block_ri);
    defer loop_scope.unstack();

    // We need to finish loop_scope later once we have the deferred refs from then_scope. However, the
    // load must be removed from instructions in the meantime or it appears to be part of parent_gz.
    const index = try loop_scope.addUnNode(.load, index_ptr, node);
    _ = loop_scope.instructions.pop();

    var cond_scope = parent_gz.makeSubBlock(&loop_scope.base);
    defer cond_scope.unstack();

    // Check the condition.
    const cond = try cond_scope.addPlNode(.cmp_lt, node, Zir.Inst.Bin{
        .lhs = index,
        .rhs = len,
    });

    const condbr_tag: Zir.Inst.Tag = if (is_inline) .condbr_inline else .condbr;
    const condbr = try cond_scope.addCondBr(condbr_tag, node);
    const block_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .block;
    const cond_block = try loop_scope.makeBlockInst(block_tag, node);
    try cond_scope.setBlockBody(cond_block);

    loop_scope.break_block = loop_block.toOptional();
    loop_scope.continue_block = cond_block.toOptional();
    if (for_full.label_token) |label_token| {
        loop_scope.label = .{
            .token = label_token,
            .block_inst = loop_block,
        };
    }

    const then_node = for_full.ast.then_expr;
    var then_scope = parent_gz.makeSubBlock(&cond_scope.base);
    defer then_scope.unstack();

    const capture_scopes = try gpa.alloc(Scope.LocalVal, for_full.ast.inputs.len);
    defer gpa.free(capture_scopes);

    const then_sub_scope = blk: {
        var capture_token = for_full.payload_token;
        var capture_sub_scope: *Scope = &then_scope.base;
        for (for_full.ast.inputs, indexables, capture_scopes) |input, indexable_ref, *capture_scope| {
            const capture_is_ref = tree.tokenTag(capture_token) == .asterisk;
            const ident_tok = capture_token + @intFromBool(capture_is_ref);
            const capture_name = tree.tokenSlice(ident_tok);
            // Skip over the comma, and on to the next capture (or the ending pipe character).
            capture_token = ident_tok + 2;

            if (mem.eql(u8, capture_name, "_")) continue;

            const name_str_index = try astgen.identAsString(ident_tok);
            try astgen.detectLocalShadowing(capture_sub_scope, name_str_index, ident_tok, capture_name, .capture);

            const capture_inst = inst: {
                const is_counter = tree.nodeTag(input) == .for_range;

                if (indexable_ref == .none) {
                    // Special case: the main index can be used directly.
                    assert(is_counter);
                    assert(!capture_is_ref);
                    break :inst index;
                }

                // For counters, we add the index variable to the start value; for
                // indexables, we use it as an element index. This is so similar
                // that they can share the same code paths, branching only on the
                // ZIR tag.
                const switch_cond = (@as(u2, @intFromBool(capture_is_ref)) << 1) | @intFromBool(is_counter);
                const tag: Zir.Inst.Tag = switch (switch_cond) {
                    0b00 => .elem_val,
                    0b01 => .add,
                    0b10 => .elem_ptr,
                    0b11 => unreachable, // compile error emitted already
                };
                break :inst try then_scope.addPlNode(tag, input, Zir.Inst.Bin{
                    .lhs = indexable_ref,
                    .rhs = index,
                });
            };

            capture_scope.* = .{
                .parent = capture_sub_scope,
                .gen_zir = &then_scope,
                .name = name_str_index,
                .inst = capture_inst,
                .token_src = ident_tok,
                .id_cat = .capture,
            };

            try then_scope.addDbgVar(.dbg_var_val, name_str_index, capture_inst);
            capture_sub_scope = &capture_scope.base;
        }

        break :blk capture_sub_scope;
    };

    const then_result = try fullBodyExpr(&then_scope, then_sub_scope, .{ .rl = .none }, then_node, .allow_branch_hint);
    _ = try addEnsureResult(&then_scope, then_result, then_node);

    try checkUsed(parent_gz, &then_scope.base, then_sub_scope);

    astgen.advanceSourceCursor(tree.tokenStart(tree.lastToken(then_node)));
    try emitDbgStmt(parent_gz, .{ astgen.source_line - parent_gz.decl_line, astgen.source_column });
    _ = try parent_gz.add(.{
        .tag = .extended,
        .data = .{ .extended = .{
            .opcode = .dbg_empty_stmt,
            .small = undefined,
            .operand = undefined,
        } },
    });

    const break_tag: Zir.Inst.Tag = if (is_inline) .break_inline else .@"break";
    _ = try then_scope.addBreak(break_tag, cond_block, .void_value);

    var else_scope = parent_gz.makeSubBlock(&cond_scope.base);
    defer else_scope.unstack();

    if (for_full.ast.else_expr.unwrap()) |else_node| {
        const sub_scope = &else_scope.base;
        // Remove the continue block and break block so that `continue` and `break`
        // control flow apply to outer loops; not this one.
        loop_scope.continue_block = .none;
        loop_scope.break_block = .none;
        const else_result = try fullBodyExpr(&else_scope, sub_scope, loop_scope.break_result_info, else_node, .allow_branch_hint);
        if (is_statement) {
            _ = try addEnsureResult(&else_scope, else_result, else_node);
        }
        if (!else_scope.endsWithNoReturn()) {
            _ = try else_scope.addBreakWithSrcNode(break_tag, loop_block, else_result, else_node);
        }
    } else {
        const result = try rvalue(&else_scope, ri, .void_value, node);
        _ = try else_scope.addBreak(break_tag, loop_block, result);
    }

    if (loop_scope.label) |some| {
        if (!some.used) {
            try astgen.appendErrorTok(some.token, "unused for loop label", .{});
        }
    }

    try setCondBrPayload(condbr, cond, &then_scope, &else_scope);

    // then_block and else_block unstacked now, can resurrect loop_scope to finally finish it
    {
        loop_scope.instructions_top = loop_scope.instructions.items.len;
        try loop_scope.instructions.appendSlice(gpa, &.{ index.toIndex().?, cond_block });

        // Increment the index variable.
        const index_plus_one = try loop_scope.addPlNode(.add_unsafe, node, Zir.Inst.Bin{
            .lhs = index,
            .rhs = .one_usize,
        });
        _ = try loop_scope.addPlNode(.store_node, node, Zir.Inst.Bin{
            .lhs = index_ptr,
            .rhs = index_plus_one,
        });

        const repeat_tag: Zir.Inst.Tag = if (is_inline) .repeat_inline else .repeat;
        _ = try loop_scope.addNode(repeat_tag, node);

        try loop_scope.setBlockBody(loop_block);
    }

    const result = if (need_result_rvalue)
        try rvalue(parent_gz, ri, loop_block.toRef(), node)
    else
        loop_block.toRef();

    if (is_statement) {
        _ = try parent_gz.addUnNode(.ensure_result_used, result, node);
    }
    return result;
}

fn switchExprErrUnion(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    catch_or_if_node: Ast.Node.Index,
    node_ty: enum { @"catch", @"if" },
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;

    const if_full = switch (node_ty) {
        .@"catch" => undefined,
        .@"if" => tree.fullIf(catch_or_if_node).?,
    };

    const switch_node, const operand_node, const error_payload = switch (node_ty) {
        .@"catch" => .{
            tree.nodeData(catch_or_if_node).node_and_node[1],
            tree.nodeData(catch_or_if_node).node_and_node[0],
            tree.nodeMainToken(catch_or_if_node) + 2,
        },
        .@"if" => .{
            if_full.ast.else_expr.unwrap().?,
            if_full.ast.cond_expr,
            if_full.error_token.?,
        },
    };
    const switch_full = tree.fullSwitch(switch_node).?;

    const do_err_trace = astgen.fn_block != null;
    const need_rl = astgen.nodes_need_rl.contains(catch_or_if_node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.resultType(parent_gz, catch_or_if_node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };

    const payload_is_ref = switch (node_ty) {
        .@"if" => if_full.payload_token != null and tree.tokenTag(if_full.payload_token.?) == .asterisk,
        .@"catch" => ri.rl == .ref or ri.rl == .ref_coerced_ty,
    };

    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).@"union".tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);
    var scalar_cases_len: u32 = 0;
    var multi_cases_len: u32 = 0;
    var inline_cases_len: u32 = 0;
    var has_else = false;
    var else_node: Ast.Node.OptionalIndex = .none;
    var else_src: ?Ast.TokenIndex = null;
    for (switch_full.ast.cases) |case_node| {
        const case = tree.fullSwitchCase(case_node).?;

        if (case.ast.values.len == 0) {
            const case_src = case.ast.arrow_token - 1;
            if (else_src) |src| {
                return astgen.failTokNotes(
                    case_src,
                    "multiple else prongs in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.errNoteTok(
                            src,
                            "previous else prong here",
                            .{},
                        ),
                    },
                );
            }
            has_else = true;
            else_node = case_node.toOptional();
            else_src = case_src;
            continue;
        } else if (case.ast.values.len == 1 and
            tree.nodeTag(case.ast.values[0]) == .identifier and
            mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(case.ast.values[0])), "_"))
        {
            const case_src = case.ast.arrow_token - 1;
            return astgen.failTokNotes(
                case_src,
                "'_' prong is not allowed when switching on errors",
                .{},
                &[_]u32{
                    try astgen.errNoteTok(
                        case_src,
                        "consider using 'else'",
                        .{},
                    ),
                },
            );
        }

        for (case.ast.values) |val| {
            if (tree.nodeTag(val) == .string_literal)
                return astgen.failNode(val, "cannot switch on strings", .{});
        }

        if (case.ast.values.len == 1 and tree.nodeTag(case.ast.values[0]) != .switch_range) {
            scalar_cases_len += 1;
        } else {
            multi_cases_len += 1;
        }
        if (case.inline_token != null) {
            inline_cases_len += 1;
        }
    }

    const operand_ri: ResultInfo = .{
        .rl = if (payload_is_ref) .ref else .none,
        .ctx = .error_handling_expr,
    };

    astgen.advanceSourceCursorToNode(operand_node);
    const operand_lc: LineColumn = .{ astgen.source_line - parent_gz.decl_line, astgen.source_column };

    const raw_operand = try reachableExpr(parent_gz, scope, operand_ri, operand_node, switch_node);
    const item_ri: ResultInfo = .{ .rl = .none };

    // This contains the data that goes into the `extra` array for the SwitchBlockErrUnion, except
    // the first cases_nodes.len slots are a table that indexes payloads later in the array,
    // with the non-error and else case indices coming first, then scalar_cases_len indexes, then
    // multi_cases_len indexes
    const payloads = &astgen.scratch;
    const scratch_top = astgen.scratch.items.len;
    const case_table_start = scratch_top;
    const scalar_case_table = case_table_start + 1 + @intFromBool(has_else);
    const multi_case_table = scalar_case_table + scalar_cases_len;
    const case_table_end = multi_case_table + multi_cases_len;

    try astgen.scratch.resize(gpa, case_table_end);
    defer astgen.scratch.items.len = scratch_top;

    var block_scope = parent_gz.makeSubBlock(scope);
    // block_scope not used for collecting instructions
    block_scope.instructions_top = GenZir.unstacked_top;
    block_scope.setBreakResultInfo(block_ri);

    // Sema expects a dbg_stmt immediately before switch_block_err_union
    try emitDbgStmtForceCurrentIndex(parent_gz, operand_lc);
    // This gets added to the parent block later, after the item expressions.
    const switch_block = try parent_gz.makeBlockInst(.switch_block_err_union, switch_node);

    // We re-use this same scope for all cases, including the special prong, if any.
    var case_scope = parent_gz.makeSubBlock(&block_scope.base);
    case_scope.instructions_top = GenZir.unstacked_top;

    {
        const body_len_index: u32 = @intCast(payloads.items.len);
        payloads.items[case_table_start] = body_len_index;
        try payloads.resize(gpa, body_len_index + 1); // body_len

        case_scope.instructions_top = parent_gz.instructions.items.len;
        defer case_scope.unstack();

        const unwrap_payload_tag: Zir.Inst.Tag = if (payload_is_ref)
            .err_union_payload_unsafe_ptr
        else
            .err_union_payload_unsafe;

        const unwrapped_payload = try case_scope.addUnNode(
            unwrap_payload_tag,
            raw_operand,
            catch_or_if_node,
        );

        switch (node_ty) {
            .@"catch" => {
                const case_result = switch (ri.rl) {
                    .ref, .ref_coerced_ty => unwrapped_payload,
                    else => try rvalue(
                        &case_scope,
                        block_scope.break_result_info,
                        unwrapped_payload,
                        catch_or_if_node,
                    ),
                };
                _ = try case_scope.addBreakWithSrcNode(
                    .@"break",
                    switch_block,
                    case_result,
                    catch_or_if_node,
                );
            },
            .@"if" => {
                var payload_val_scope: Scope.LocalVal = undefined;

                const then_node = if_full.ast.then_expr;
                const then_sub_scope = s: {
                    assert(if_full.error_token != null);
                    if (if_full.payload_token) |payload_token| {
                        const token_name_index = payload_token + @intFromBool(payload_is_ref);
                        const ident_name = try astgen.identAsString(token_name_index);
                        const token_name_str = tree.tokenSlice(token_name_index);
                        if (mem.eql(u8, "_", token_name_str))
                            break :s &case_scope.base;
                        try astgen.detectLocalShadowing(
                            &case_scope.base,
                            ident_name,
                            token_name_index,
                            token_name_str,
                            .capture,
                        );
                        payload_val_scope = .{
                            .parent = &case_scope.base,
                            .gen_zir = &case_scope,
                            .name = ident_name,
                            .inst = unwrapped_payload,
                            .token_src = token_name_index,
                            .id_cat = .capture,
                        };
                        try case_scope.addDbgVar(.dbg_var_val, ident_name, unwrapped_payload);
                        break :s &payload_val_scope.base;
                    } else {
                        _ = try case_scope.addUnNode(
                            .ensure_err_union_payload_void,
                            raw_operand,
                            catch_or_if_node,
                        );
                        break :s &case_scope.base;
                    }
                };
                const then_result = try expr(
                    &case_scope,
                    then_sub_scope,
                    block_scope.break_result_info,
                    then_node,
                );
                try checkUsed(parent_gz, &case_scope.base, then_sub_scope);
                if (!case_scope.endsWithNoReturn()) {
                    _ = try case_scope.addBreakWithSrcNode(
                        .@"break",
                        switch_block,
                        then_result,
                        then_node,
                    );
                }
            },
        }

        const case_slice = case_scope.instructionsSlice();
        const body_len = astgen.countBodyLenAfterFixupsExtraRefs(case_slice, &.{switch_block});
        try payloads.ensureUnusedCapacity(gpa, body_len);
        const capture: Zir.Inst.SwitchBlock.ProngInfo.Capture = switch (node_ty) {
            .@"catch" => .none,
            .@"if" => if (if_full.payload_token == null)
                .none
            else if (payload_is_ref)
                .by_ref
            else
                .by_val,
        };
        payloads.items[body_len_index] = @bitCast(Zir.Inst.SwitchBlock.ProngInfo{
            .body_len = @intCast(body_len),
            .capture = capture,
            .is_inline = false,
            .has_tag_capture = false,
        });
        appendBodyWithFixupsExtraRefsArrayList(astgen, payloads, case_slice, &.{switch_block});
    }

    const err_name = blk: {
        const err_str = tree.tokenSlice(error_payload);
        if (mem.eql(u8, err_str, "_")) {
            // This is fatal because we already know we're switching on the captured error.
            return astgen.failTok(error_payload, "discard of error capture; omit it instead", .{});
        }
        const err_name = try astgen.identAsString(error_payload);
        try astgen.detectLocalShadowing(scope, err_name, error_payload, err_str, .capture);

        break :blk err_name;
    };

    // allocate a shared dummy instruction for the error capture
    const err_inst = err_inst: {
        const inst: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        try astgen.instructions.append(astgen.gpa, .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .value_placeholder,
                .small = undefined,
                .operand = undefined,
            } },
        });
        break :err_inst inst;
    };

    // In this pass we generate all the item and prong expressions for error cases.
    var multi_case_index: u32 = 0;
    var scalar_case_index: u32 = 0;
    var any_uses_err_capture = false;
    for (switch_full.ast.cases) |case_node| {
        const case = tree.fullSwitchCase(case_node).?;

        const is_multi_case = case.ast.values.len > 1 or
            (case.ast.values.len == 1 and tree.nodeTag(case.ast.values[0]) == .switch_range);

        var dbg_var_name: Zir.NullTerminatedString = .empty;
        var dbg_var_inst: Zir.Inst.Ref = undefined;
        var err_scope: Scope.LocalVal = undefined;
        var capture_scope: Scope.LocalVal = undefined;

        const sub_scope = blk: {
            err_scope = .{
                .parent = &case_scope.base,
                .gen_zir = &case_scope,
                .name = err_name,
                .inst = err_inst.toRef(),
                .token_src = error_payload,
                .id_cat = .capture,
            };

            const capture_token = case.payload_token orelse break :blk &err_scope.base;
            if (tree.tokenTag(capture_token) != .identifier) {
                return astgen.failTok(capture_token + 1, "error set cannot be captured by reference", .{});
            }

            const capture_slice = tree.tokenSlice(capture_token);
            if (mem.eql(u8, capture_slice, "_")) {
                try astgen.appendErrorTok(capture_token, "discard of error capture; omit it instead", .{});
            }
            const tag_name = try astgen.identAsString(capture_token);
            try astgen.detectLocalShadowing(&case_scope.base, tag_name, capture_token, capture_slice, .capture);

            capture_scope = .{
                .parent = &case_scope.base,
                .gen_zir = &case_scope,
                .name = tag_name,
                .inst = switch_block.toRef(),
                .token_src = capture_token,
                .id_cat = .capture,
            };
            dbg_var_name = tag_name;
            dbg_var_inst = switch_block.toRef();

            err_scope.parent = &capture_scope.base;

            break :blk &err_scope.base;
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
        } else if (case_node.toOptional() == else_node) blk: {
            payloads.items[case_table_start + 1] = header_index;
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

            if (do_err_trace and nodeMayAppendToErrorTrace(tree, operand_node))
                _ = try case_scope.addSaveErrRetIndex(.always);

            if (dbg_var_name != .empty) {
                try case_scope.addDbgVar(.dbg_var_val, dbg_var_name, dbg_var_inst);
            }

            const target_expr_node = case.ast.target_expr;
            const case_result = try fullBodyExpr(&case_scope, sub_scope, block_scope.break_result_info, target_expr_node, .allow_branch_hint);
            // check capture_scope, not err_scope to avoid false positive unused error capture
            try checkUsed(parent_gz, &case_scope.base, err_scope.parent);
            const uses_err = err_scope.used != .none or err_scope.discarded != .none;
            if (uses_err) {
                try case_scope.addDbgVar(.dbg_var_val, err_name, err_inst.toRef());
                any_uses_err_capture = true;
            }

            if (!parent_gz.refIsNoReturn(case_result)) {
                if (do_err_trace)
                    try restoreErrRetIndex(
                        &case_scope,
                        .{ .block = switch_block },
                        block_scope.break_result_info,
                        target_expr_node,
                        case_result,
                    );

                _ = try case_scope.addBreakWithSrcNode(.@"break", switch_block, case_result, target_expr_node);
            }

            const case_slice = case_scope.instructionsSlice();
            const extra_insts: []const Zir.Inst.Index = if (uses_err) &.{ switch_block, err_inst } else &.{switch_block};
            const body_len = astgen.countBodyLenAfterFixupsExtraRefs(case_slice, extra_insts);
            try payloads.ensureUnusedCapacity(gpa, body_len);
            payloads.items[body_len_index] = @bitCast(Zir.Inst.SwitchBlock.ProngInfo{
                .body_len = @intCast(body_len),
                .capture = if (case.payload_token != null) .by_val else .none,
                .is_inline = case.inline_token != null,
                .has_tag_capture = false,
            });
            appendBodyWithFixupsExtraRefsArrayList(astgen, payloads, case_slice, extra_insts);
        }
    }
    // Now that the item expressions are generated we can add this.
    try parent_gz.instructions.append(gpa, switch_block);

    try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.SwitchBlockErrUnion).@"struct".fields.len +
        @intFromBool(multi_cases_len != 0) +
        payloads.items.len - case_table_end +
        (case_table_end - case_table_start) * @typeInfo(Zir.Inst.As).@"struct".fields.len);

    const payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.SwitchBlockErrUnion{
        .operand = raw_operand,
        .bits = Zir.Inst.SwitchBlockErrUnion.Bits{
            .has_multi_cases = multi_cases_len != 0,
            .has_else = has_else,
            .scalar_cases_len = @intCast(scalar_cases_len),
            .any_uses_err_capture = any_uses_err_capture,
            .payload_is_ref = payload_is_ref,
        },
        .main_src_node_offset = parent_gz.nodeIndexToRelative(catch_or_if_node),
    });

    if (multi_cases_len != 0) {
        astgen.extra.appendAssumeCapacity(multi_cases_len);
    }

    if (any_uses_err_capture) {
        astgen.extra.appendAssumeCapacity(@intFromEnum(err_inst));
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
        return rvalue(parent_gz, ri, switch_block.toRef(), switch_node);
    } else {
        return switch_block.toRef();
    }
}

fn switchExpr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    switch_full: Ast.full.Switch,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const operand_node = switch_full.ast.condition;
    const case_nodes = switch_full.ast.cases;

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.resultType(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).@"union".tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    if (switch_full.label_token) |label_token| {
        try astgen.checkLabelRedefinition(scope, label_token);
    }

    // We perform two passes over the AST. This first pass is to collect information
    // for the following variables, make note of the special prong AST node index,
    // and bail out with a compile error if there are multiple special prongs present.
    var any_payload_is_ref = false;
    var any_has_tag_capture = false;
    var any_non_inline_capture = false;
    var scalar_cases_len: u32 = 0;
    var multi_cases_len: u32 = 0;
    var inline_cases_len: u32 = 0;
    var special_prong: Zir.SpecialProng = .none;
    var special_node: Ast.Node.OptionalIndex = .none;
    var else_src: ?Ast.TokenIndex = null;
    var underscore_src: ?Ast.TokenIndex = null;
    for (case_nodes) |case_node| {
        const case = tree.fullSwitchCase(case_node).?;
        if (case.payload_token) |payload_token| {
            const ident = if (tree.tokenTag(payload_token) == .asterisk) blk: {
                any_payload_is_ref = true;
                break :blk payload_token + 1;
            } else payload_token;
            if (tree.tokenTag(ident + 1) == .comma) {
                any_has_tag_capture = true;
            }

            // If the first capture is ignored, then there is no runtime-known
            // capture, as the tag capture must be for an inline prong.
            // This check isn't perfect, because for things like enums, the
            // first prong *is* comptime-known for inline prongs! But such
            // knowledge requires semantic analysis.
            if (!mem.eql(u8, tree.tokenSlice(ident), "_")) {
                any_non_inline_capture = true;
            }
        }
        // Check for else/`_` prong.
        if (case.ast.values.len == 0) {
            const case_src = case.ast.arrow_token - 1;
            if (else_src) |src| {
                return astgen.failTokNotes(
                    case_src,
                    "multiple else prongs in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.errNoteTok(
                            src,
                            "previous else prong here",
                            .{},
                        ),
                    },
                );
            } else if (underscore_src) |some_underscore| {
                return astgen.failNodeNotes(
                    node,
                    "else and '_' prong in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.errNoteTok(
                            case_src,
                            "else prong here",
                            .{},
                        ),
                        try astgen.errNoteTok(
                            some_underscore,
                            "'_' prong here",
                            .{},
                        ),
                    },
                );
            }
            special_node = case_node.toOptional();
            special_prong = .@"else";
            else_src = case_src;
            continue;
        } else if (case.ast.values.len == 1 and
            tree.nodeTag(case.ast.values[0]) == .identifier and
            mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(case.ast.values[0])), "_"))
        {
            const case_src = case.ast.arrow_token - 1;
            if (underscore_src) |src| {
                return astgen.failTokNotes(
                    case_src,
                    "multiple '_' prongs in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.errNoteTok(
                            src,
                            "previous '_' prong here",
                            .{},
                        ),
                    },
                );
            } else if (else_src) |some_else| {
                return astgen.failNodeNotes(
                    node,
                    "else and '_' prong in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.errNoteTok(
                            some_else,
                            "else prong here",
                            .{},
                        ),
                        try astgen.errNoteTok(
                            case_src,
                            "'_' prong here",
                            .{},
                        ),
                    },
                );
            }
            if (case.inline_token != null) {
                return astgen.failTok(case_src, "cannot inline '_' prong", .{});
            }
            special_node = case_node.toOptional();
            special_prong = .under;
            underscore_src = case_src;
            continue;
        }

        for (case.ast.values) |val| {
            if (tree.nodeTag(val) == .string_literal)
                return astgen.failNode(val, "cannot switch on strings", .{});
        }

        if (case.ast.values.len == 1 and tree.nodeTag(case.ast.values[0]) != .switch_range) {
            scalar_cases_len += 1;
        } else {
            multi_cases_len += 1;
        }
        if (case.inline_token != null) {
            inline_cases_len += 1;
        }
    }

    const operand_ri: ResultInfo = .{ .rl = if (any_payload_is_ref) .ref else .none };

    astgen.advanceSourceCursorToNode(operand_node);
    const operand_lc: LineColumn = .{ astgen.source_line - parent_gz.decl_line, astgen.source_column };

    const raw_operand = try expr(parent_gz, scope, operand_ri, operand_node);
    const item_ri: ResultInfo = .{ .rl = .none };

    // If this switch is labeled, it may have `continue`s targeting it, and thus we need the operand type
    // to provide a result type.
    const raw_operand_ty_ref = if (switch_full.l```
