```
 unreachable,
        }
    }
}

fn checkUsed(gz: *GenZir, outer_scope: *Scope, inner_scope: *Scope) InnerError!void {
    const astgen = gz.astgen;

    var scope = inner_scope;
    while (scope != outer_scope) {
        switch (scope.tag) {
            .gen_zir => scope = scope.cast(GenZir).?.parent,
            .local_val => {
                const s = scope.cast(Scope.LocalVal).?;
                if (s.used == .none and s.discarded == .none) {
                    try astgen.appendErrorTok(s.token_src, "unused {s}", .{@tagName(s.id_cat)});
                } else if (s.used != .none and s.discarded != .none) {
                    try astgen.appendErrorTokNotes(s.discarded.unwrap().?, "pointless discard of {s}", .{@tagName(s.id_cat)}, &[_]u32{
                        try gz.astgen.errNoteTok(s.used.unwrap().?, "used here", .{}),
                    });
                }
                scope = s.parent;
            },
            .local_ptr => {
                const s = scope.cast(Scope.LocalPtr).?;
                if (s.used == .none and s.discarded == .none) {
                    try astgen.appendErrorTok(s.token_src, "unused {s}", .{@tagName(s.id_cat)});
                } else {
                    if (s.used != .none and s.discarded != .none) {
                        try astgen.appendErrorTokNotes(s.discarded.unwrap().?, "pointless discard of {s}", .{@tagName(s.id_cat)}, &[_]u32{
                            try astgen.errNoteTok(s.used.unwrap().?, "used here", .{}),
                        });
                    }
                    if (s.id_cat == .@"local variable" and !s.used_as_lvalue) {
                        try astgen.appendErrorTokNotes(s.token_src, "local variable is never mutated", .{}, &.{
                            try astgen.errNoteTok(s.token_src, "consider using 'const'", .{}),
                        });
                    }
                }

                scope = s.parent;
            },
            .defer_normal, .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .namespace => unreachable,
            .top => unreachable,
        }
    }
}

fn deferStmt(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    block_arena: Allocator,
    scope_tag: Scope.Tag,
) InnerError!*Scope {
    var defer_gen = gz.makeSubBlock(scope);
    defer_gen.cur_defer_node = node.toOptional();
    defer_gen.any_defer_node = node.toOptional();
    defer defer_gen.unstack();

    const tree = gz.astgen.tree;
    var local_val_scope: Scope.LocalVal = undefined;
    var opt_remapped_err_code: Zir.Inst.OptionalIndex = .none;
    const sub_scope = if (scope_tag != .defer_error) &defer_gen.base else blk: {
        const payload_token = tree.nodeData(node).opt_token_and_node[0].unwrap() orelse break :blk &defer_gen.base;
        const ident_name = try gz.astgen.identAsString(payload_token);
        if (std.mem.eql(u8, tree.tokenSlice(payload_token), "_")) {
            try gz.astgen.appendErrorTok(payload_token, "discard of error capture; omit it instead", .{});
            break :blk &defer_gen.base;
        }
        const remapped_err_code: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        opt_remapped_err_code = remapped_err_code.toOptional();
        try gz.astgen.instructions.append(gz.astgen.gpa, .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .value_placeholder,
                .small = undefined,
                .operand = undefined,
            } },
        });
        const remapped_err_code_ref = remapped_err_code.toRef();
        local_val_scope = .{
            .parent = &defer_gen.base,
            .gen_zir = gz,
            .name = ident_name,
            .inst = remapped_err_code_ref,
            .token_src = payload_token,
            .id_cat = .capture,
        };
        try gz.addDbgVar(.dbg_var_val, ident_name, remapped_err_code_ref);
        break :blk &local_val_scope.base;
    };
    const expr_node = switch (scope_tag) {
        .defer_normal => tree.nodeData(node).node,
        .defer_error => tree.nodeData(node).opt_token_and_node[1],
        else => unreachable,
    };
    _ = try unusedResultExpr(&defer_gen, sub_scope, expr_node);
    try checkUsed(gz, scope, sub_scope);
    _ = try defer_gen.addBreak(.break_inline, @enumFromInt(0), .void_value);

    const body = defer_gen.instructionsSlice();
    const extra_insts: []const Zir.Inst.Index = if (opt_remapped_err_code.unwrap()) |ec| &.{ec} else &.{};
    const body_len = gz.astgen.countBodyLenAfterFixupsExtraRefs(body, extra_insts);

    const index: u32 = @intCast(gz.astgen.extra.items.len);
    try gz.astgen.extra.ensureUnusedCapacity(gz.astgen.gpa, body_len);
    gz.astgen.appendBodyWithFixupsExtraRefsArrayList(&gz.astgen.extra, body, extra_insts);

    const defer_scope = try block_arena.create(Scope.Defer);

    defer_scope.* = .{
        .base = .{ .tag = scope_tag },
        .parent = scope,
        .index = index,
        .len = body_len,
        .remapped_err_code = opt_remapped_err_code,
    };
    return &defer_scope.base;
}

fn varDecl(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    block_arena: Allocator,
    var_decl: Ast.full.VarDecl,
) InnerError!*Scope {
    try emitDbgNode(gz, node);
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const name_token = var_decl.ast.mut_token + 1;
    const ident_name_raw = tree.tokenSlice(name_token);
    if (mem.eql(u8, ident_name_raw, "_")) {
        return astgen.failTok(name_token, "'_' used as an identifier without @\"_\" syntax", .{});
    }
    const ident_name = try astgen.identAsString(name_token);

    try astgen.detectLocalShadowing(
        scope,
        ident_name,
        name_token,
        ident_name_raw,
        if (tree.tokenTag(var_decl.ast.mut_token) == .keyword_const) .@"local constant" else .@"local variable",
    );

    const init_node = var_decl.ast.init_node.unwrap() orelse {
        return astgen.failNode(node, "variables must be initialized", .{});
    };

    if (var_decl.ast.addrspace_node.unwrap()) |addrspace_node| {
        return astgen.failTok(tree.nodeMainToken(addrspace_node), "cannot set address space of local variable '{s}'", .{ident_name_raw});
    }

    if (var_decl.ast.section_node.unwrap()) |section_node| {
        return astgen.failTok(tree.nodeMainToken(section_node), "cannot set section of local variable '{s}'", .{ident_name_raw});
    }

    const align_inst: Zir.Inst.Ref = if (var_decl.ast.align_node.unwrap()) |align_node|
        try expr(gz, scope, coerced_align_ri, align_node)
    else
        .none;

    switch (tree.tokenTag(var_decl.ast.mut_token)) {
        .keyword_const => {
            if (var_decl.comptime_token) |comptime_token| {
                try astgen.appendErrorTok(comptime_token, "'comptime const' is redundant; instead wrap the initialization expression with 'comptime'", .{});
            }

            // `comptime const` is a non-fatal error; treat it like the init was marked `comptime`.
            const force_comptime = var_decl.comptime_token != null;

            // Depending on the type of AST the initialization expression is, we may need an lvalue
            // or an rvalue as a result location. If it is an rvalue, we can use the instruction as
            // the variable, no memory location needed.
            if (align_inst == .none and
                !astgen.nodes_need_rl.contains(node))
            {
                const result_info: ResultInfo = if (var_decl.ast.type_node.unwrap()) |type_node| .{
                    .rl = .{ .ty = try typeExpr(gz, scope, type_node) },
                    .ctx = .const_init,
                } else .{ .rl = .none, .ctx = .const_init };
                const prev_anon_name_strategy = gz.anon_name_strategy;
                gz.anon_name_strategy = .dbg_var;
                const init_inst = try reachableExprComptime(gz, scope, result_info, init_node, node, if (force_comptime) .comptime_keyword else null);
                gz.anon_name_strategy = prev_anon_name_strategy;

                _ = try gz.addUnNode(.validate_const, init_inst, init_node);
                try gz.addDbgVar(.dbg_var_val, ident_name, init_inst);

                // The const init expression may have modified the error return trace, so signal
                // to Sema that it should save the new index for restoring later.
                if (nodeMayAppendToErrorTrace(tree, init_node))
                    _ = try gz.addSaveErrRetIndex(.{ .if_of_error_type = init_inst });

                const sub_scope = try block_arena.create(Scope.LocalVal);
                sub_scope.* = .{
                    .parent = scope,
                    .gen_zir = gz,
                    .name = ident_name,
                    .inst = init_inst,
                    .token_src = name_token,
                    .id_cat = .@"local constant",
                };
                return &sub_scope.base;
            }

            const is_comptime = gz.is_comptime or
                tree.nodeTag(init_node) == .@"comptime";

            const init_rl: ResultInfo.Loc = if (var_decl.ast.type_node.unwrap()) |type_node| init_rl: {
                const type_inst = try typeExpr(gz, scope, type_node);
                if (align_inst == .none) {
                    break :init_rl .{ .ptr = .{ .inst = try gz.addUnNode(.alloc, type_inst, node) } };
                } else {
                    break :init_rl .{ .ptr = .{ .inst = try gz.addAllocExtended(.{
                        .node = node,
                        .type_inst = type_inst,
                        .align_inst = align_inst,
                        .is_const = true,
                        .is_comptime = is_comptime,
                    }) } };
                }
            } else init_rl: {
                const alloc_inst = if (align_inst == .none) ptr: {
                    const tag: Zir.Inst.Tag = if (is_comptime)
                        .alloc_inferred_comptime
                    else
                        .alloc_inferred;
                    break :ptr try gz.addNode(tag, node);
                } else ptr: {
                    break :ptr try gz.addAllocExtended(.{
                        .node = node,
                        .type_inst = .none,
                        .align_inst = align_inst,
                        .is_const = true,
                        .is_comptime = is_comptime,
                    });
                };
                break :init_rl .{ .inferred_ptr = alloc_inst };
            };
            const var_ptr: Zir.Inst.Ref, const resolve_inferred: bool = switch (init_rl) {
                .ptr => |ptr| .{ ptr.inst, false },
                .inferred_ptr => |inst| .{ inst, true },
                else => unreachable,
            };
            const init_result_info: ResultInfo = .{ .rl = init_rl, .ctx = .const_init };

            const prev_anon_name_strategy = gz.anon_name_strategy;
            gz.anon_name_strategy = .dbg_var;
            defer gz.anon_name_strategy = prev_anon_name_strategy;
            const init_inst = try reachableExprComptime(gz, scope, init_result_info, init_node, node, if (force_comptime) .comptime_keyword else null);

            // The const init expression may have modified the error return trace, so signal
            // to Sema that it should save the new index for restoring later.
            if (nodeMayAppendToErrorTrace(tree, init_node))
                _ = try gz.addSaveErrRetIndex(.{ .if_of_error_type = init_inst });

            const const_ptr = if (resolve_inferred)
                try gz.addUnNode(.resolve_inferred_alloc, var_ptr, node)
            else
                try gz.addUnNode(.make_ptr_const, var_ptr, node);

            try gz.addDbgVar(.dbg_var_ptr, ident_name, const_ptr);

            const sub_scope = try block_arena.create(Scope.LocalPtr);
            sub_scope.* = .{
                .parent = scope,
                .gen_zir = gz,
                .name = ident_name,
                .ptr = const_ptr,
                .token_src = name_token,
                .maybe_comptime = true,
                .id_cat = .@"local constant",
            };
            return &sub_scope.base;
        },
        .keyword_var => {
            if (var_decl.comptime_token != null and gz.is_comptime)
                return astgen.failTok(var_decl.comptime_token.?, "'comptime var' is redundant in comptime scope", .{});
            const is_comptime = var_decl.comptime_token != null or gz.is_comptime;
            const alloc: Zir.Inst.Ref, const resolve_inferred: bool, const result_info: ResultInfo = if (var_decl.ast.type_node.unwrap()) |type_node| a: {
                const type_inst = try typeExpr(gz, scope, type_node);
                const alloc = alloc: {
                    if (align_inst == .none) {
                        const tag: Zir.Inst.Tag = if (is_comptime)
                            .alloc_comptime_mut
                        else
                            .alloc_mut;
                        break :alloc try gz.addUnNode(tag, type_inst, node);
                    } else {
                        break :alloc try gz.addAllocExtended(.{
                            .node = node,
                            .type_inst = type_inst,
                            .align_inst = align_inst,
                            .is_const = false,
                            .is_comptime = is_comptime,
                        });
                    }
                };
                break :a .{ alloc, false, .{ .rl = .{ .ptr = .{ .inst = alloc } } } };
            } else a: {
                const alloc = alloc: {
                    if (align_inst == .none) {
                        const tag: Zir.Inst.Tag = if (is_comptime)
                            .alloc_inferred_comptime_mut
                        else
                            .alloc_inferred_mut;
                        break :alloc try gz.addNode(tag, node);
                    } else {
                        break :alloc try gz.addAllocExtended(.{
                            .node = node,
                            .type_inst = .none,
                            .align_inst = align_inst,
                            .is_const = false,
                            .is_comptime = is_comptime,
                        });
                    }
                };
                break :a .{ alloc, true, .{ .rl = .{ .inferred_ptr = alloc } } };
            };
            const prev_anon_name_strategy = gz.anon_name_strategy;
            gz.anon_name_strategy = .dbg_var;
            _ = try reachableExprComptime(
                gz,
                scope,
                result_info,
                init_node,
                node,
                if (var_decl.comptime_token != null) .comptime_keyword else null,
            );
            gz.anon_name_strategy = prev_anon_name_strategy;
            const final_ptr: Zir.Inst.Ref = if (resolve_inferred) ptr: {
                break :ptr try gz.addUnNode(.resolve_inferred_alloc, alloc, node);
            } else alloc;

            try gz.addDbgVar(.dbg_var_ptr, ident_name, final_ptr);

            const sub_scope = try block_arena.create(Scope.LocalPtr);
            sub_scope.* = .{
                .parent = scope,
                .gen_zir = gz,
                .name = ident_name,
                .ptr = final_ptr,
                .token_src = name_token,
                .maybe_comptime = is_comptime,
                .id_cat = .@"local variable",
            };
            return &sub_scope.base;
        },
        else => unreachable,
    }
}

fn emitDbgNode(gz: *GenZir, node: Ast.Node.Index) !void {
    // The instruction emitted here is for debugging runtime code.
    // If the current block will be evaluated only during semantic analysis
    // then no dbg_stmt ZIR instruction is needed.
    if (gz.is_comptime) return;
    const astgen = gz.astgen;
    astgen.advanceSourceCursorToNode(node);
    const line = astgen.source_line - gz.decl_line;
    const column = astgen.source_column;
    try emitDbgStmt(gz, .{ line, column });
}

fn assign(gz: *GenZir, scope: *Scope, infix_node: Ast.Node.Index) InnerError!void {
    try emitDbgNode(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lhs, const rhs = tree.nodeData(infix_node).node_and_node;
    if (tree.nodeTag(lhs) == .identifier) {
        // This intentionally does not support `@"_"` syntax.
        const ident_name = tree.tokenSlice(tree.nodeMainToken(lhs));
        if (mem.eql(u8, ident_name, "_")) {
            _ = try expr(gz, scope, .{ .rl = .discard, .ctx = .assignment }, rhs);
            return;
        }
    }
    const lvalue = try lvalExpr(gz, scope, lhs);
    _ = try expr(gz, scope, .{ .rl = .{ .ptr = .{
        .inst = lvalue,
        .src_node = infix_node,
    } } }, rhs);
}

/// Handles destructure assignments where no LHS is a `const` or `var` decl.
fn assignDestructure(gz: *GenZir, scope: *Scope, node: Ast.Node.Index) InnerError!void {
    try emitDbgNode(gz, node);
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const full = tree.assignDestructure(node);
    if (full.comptime_token != null and gz.is_comptime) {
        return astgen.appendErrorNode(node, "redundant comptime keyword in already comptime scope", .{});
    }

    // If this expression is marked comptime, we must wrap the whole thing in a comptime block.
    var gz_buf: GenZir = undefined;
    const inner_gz = if (full.comptime_token) |_| bs: {
        gz_buf = gz.makeSubBlock(scope);
        gz_buf.is_comptime = true;
        break :bs &gz_buf;
    } else gz;
    defer if (full.comptime_token) |_| inner_gz.unstack();

    const rl_components = try astgen.arena.alloc(ResultInfo.Loc.DestructureComponent, full.ast.variables.len);
    for (rl_components, full.ast.variables) |*variable_rl, variable_node| {
        if (tree.nodeTag(variable_node) == .identifier) {
            // This intentionally does not support `@"_"` syntax.
            const ident_name = tree.tokenSlice(tree.nodeMainToken(variable_node));
            if (mem.eql(u8, ident_name, "_")) {
                variable_rl.* = .discard;
                continue;
            }
        }
        variable_rl.* = .{ .typed_ptr = .{
            .inst = try lvalExpr(inner_gz, scope, variable_node),
            .src_node = variable_node,
        } };
    }

    const ri: ResultInfo = .{ .rl = .{ .destructure = .{
        .src_node = node,
        .components = rl_components,
    } } };

    _ = try expr(inner_gz, scope, ri, full.ast.value_expr);

    if (full.comptime_token) |_| {
        const comptime_block_inst = try gz.makeBlockInst(.block_comptime, node);
        _ = try inner_gz.addBreak(.break_inline, comptime_block_inst, .void_value);
        try inner_gz.setBlockComptimeBody(comptime_block_inst, .comptime_keyword);
        try gz.instructions.append(gz.astgen.gpa, comptime_block_inst);
    }
}

/// Handles destructure assignments where the LHS may contain `const` or `var` decls.
fn assignDestructureMaybeDecls(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    block_arena: Allocator,
) InnerError!*Scope {
    try emitDbgNode(gz, node);
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const full = tree.assignDestructure(node);
    if (full.comptime_token != null and gz.is_comptime) {
        try astgen.appendErrorNode(node, "redundant comptime keyword in already comptime scope", .{});
    }

    const is_comptime = full.comptime_token != null or gz.is_comptime;
    const value_is_comptime = tree.nodeTag(full.ast.value_expr) == .@"comptime";

    // When declaring consts via a destructure, we always use a result pointer.
    // This avoids the need to create tuple types, and is also likely easier to
    // optimize, since it's a bit tricky for the optimizer to "split up" the
    // value into individual pointer writes down the line.

    // We know this rl information won't live past the evaluation of this
    // expression, so it may as well go in the block arena.
    const rl_components = try block_arena.alloc(ResultInfo.Loc.DestructureComponent, full.ast.variables.len);
    var any_non_const_variables = false;
    var any_lvalue_expr = false;
    for (rl_components, full.ast.variables) |*variable_rl, variable_node| {
        switch (tree.nodeTag(variable_node)) {
            .identifier => {
                // This intentionally does not support `@"_"` syntax.
                const ident_name = tree.tokenSlice(tree.nodeMainToken(variable_node));
                if (mem.eql(u8, ident_name, "_")) {
                    any_non_const_variables = true;
                    variable_rl.* = .discard;
                    continue;
                }
            },
            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                const full_var_decl = tree.fullVarDecl(variable_node).?;

                const name_token = full_var_decl.ast.mut_token + 1;
                const ident_name_raw = tree.tokenSlice(name_token);
                if (mem.eql(u8, ident_name_raw, "_")) {
                    return astgen.failTok(name_token, "'_' used as an identifier without @\"_\" syntax", .{});
                }

                // We detect shadowing in the second pass over these, while we're creating scopes.

                if (full_var_decl.ast.addrspace_node.unwrap()) |addrspace_node| {
                    return astgen.failTok(tree.nodeMainToken(addrspace_node), "cannot set address space of local variable '{s}'", .{ident_name_raw});
                }
                if (full_var_decl.ast.section_node.unwrap()) |section_node| {
                    return astgen.failTok(tree.nodeMainToken(section_node), "cannot set section of local variable '{s}'", .{ident_name_raw});
                }

                const is_const = switch (tree.tokenTag(full_var_decl.ast.mut_token)) {
                    .keyword_var => false,
                    .keyword_const => true,
                    else => unreachable,
                };
                if (!is_const) any_non_const_variables = true;

                // We also mark `const`s as comptime if the RHS is definitely comptime-known.
                const this_variable_comptime = is_comptime or (is_const and value_is_comptime);

                const align_inst: Zir.Inst.Ref = if (full_var_decl.ast.align_node.unwrap()) |align_node|
                    try expr(gz, scope, coerced_align_ri, align_node)
                else
                    .none;

                if (full_var_decl.ast.type_node.unwrap()) |type_node| {
                    // Typed alloc
                    const type_inst = try typeExpr(gz, scope, type_node);
                    const ptr = if (align_inst == .none) ptr: {
                        const tag: Zir.Inst.Tag = if (is_const)
                            .alloc
                        else if (this_variable_comptime)
                            .alloc_comptime_mut
                        else
                            .alloc_mut;
                        break :ptr try gz.addUnNode(tag, type_inst, node);
                    } else try gz.addAllocExtended(.{
                        .node = node,
                        .type_inst = type_inst,
                        .align_inst = align_inst,
                        .is_const = is_const,
                        .is_comptime = this_variable_comptime,
                    });
                    variable_rl.* = .{ .typed_ptr = .{ .inst = ptr } };
                } else {
                    // Inferred alloc
                    const ptr = if (align_inst == .none) ptr: {
                        const tag: Zir.Inst.Tag = if (is_const) tag: {
                            break :tag if (this_variable_comptime) .alloc_inferred_comptime else .alloc_inferred;
                        } else tag: {
                            break :tag if (this_variable_comptime) .alloc_inferred_comptime_mut else .alloc_inferred_mut;
                        };
                        break :ptr try gz.addNode(tag, node);
                    } else try gz.addAllocExtended(.{
                        .node = node,
                        .type_inst = .none,
                        .align_inst = align_inst,
                        .is_const = is_const,
                        .is_comptime = this_variable_comptime,
                    });
                    variable_rl.* = .{ .inferred_ptr = ptr };
                }

                continue;
            },
            else => {},
        }
        // This variable is just an lvalue expression.
        // We will fill in its result pointer later, inside a comptime block.
        any_non_const_variables = true;
        any_lvalue_expr = true;
        variable_rl.* = .{ .typed_ptr = .{
            .inst = undefined,
            .src_node = variable_node,
        } };
    }

    if (full.comptime_token != null and !any_non_const_variables) {
        try astgen.appendErrorTok(full.comptime_token.?, "'comptime const' is redundant; instead wrap the initialization expression with 'comptime'", .{});
        // Note that this is non-fatal; we will still evaluate at comptime.
    }

    // If this expression is marked comptime, we must wrap it in a comptime block.
    var gz_buf: GenZir = undefined;
    const inner_gz = if (full.comptime_token) |_| bs: {
        gz_buf = gz.makeSubBlock(scope);
        gz_buf.is_comptime = true;
        break :bs &gz_buf;
    } else gz;
    defer if (full.comptime_token) |_| inner_gz.unstack();

    if (any_lvalue_expr) {
        // At least one variable was an lvalue expr. Iterate again in order to
        // evaluate the lvalues from within the possible block_comptime.
        for (rl_components, full.ast.variables) |*variable_rl, variable_node| {
            if (variable_rl.* != .typed_ptr) continue;
            switch (tree.nodeTag(variable_node)) {
                .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => continue,
                else => {},
            }
            variable_rl.typed_ptr.inst = try lvalExpr(inner_gz, scope, variable_node);
        }
    }

    // We can't give a reasonable anon name strategy for destructured inits, so
    // leave it at its default of `.anon`.
    _ = try reachableExpr(inner_gz, scope, .{ .rl = .{ .destructure = .{
        .src_node = node,
        .components = rl_components,
    } } }, full.ast.value_expr, node);

    if (full.comptime_token) |_| {
        // Finish the block_comptime. Inferred alloc resolution etc will occur
        // in the parent block.
        const comptime_block_inst = try gz.makeBlockInst(.block_comptime, node);
        _ = try inner_gz.addBreak(.break_inline, comptime_block_inst, .void_value);
        try inner_gz.setBlockComptimeBody(comptime_block_inst, .comptime_keyword);
        try gz.instructions.append(gz.astgen.gpa, comptime_block_inst);
    }

    // Now, iterate over the variable exprs to construct any new scopes.
    // If there were any inferred allocations, resolve them.
    // If there were any `const` decls, make the pointer constant.
    var cur_scope = scope;
    for (rl_components, full.ast.variables) |variable_rl, variable_node| {
        switch (tree.nodeTag(variable_node)) {
            .local_var_decl, .simple_var_decl, .aligned_var_decl => {},
            else => continue, // We were mutating an existing lvalue - nothing to do
        }
        const full_var_decl = tree.fullVarDecl(variable_node).?;
        const raw_ptr, const resolve_inferred = switch (variable_rl) {
            .discard => unreachable,
            .typed_ptr => |typed_ptr| .{ typed_ptr.inst, false },
            .inferred_ptr => |ptr_inst| .{ ptr_inst, true },
        };
        const is_const = switch (tree.tokenTag(full_var_decl.ast.mut_token)) {
            .keyword_var => false,
            .keyword_const => true,
            else => unreachable,
        };

        // If the alloc was inferred, resolve it. If the alloc was const, make it const.
        const final_ptr = if (resolve_inferred)
            try gz.addUnNode(.resolve_inferred_alloc, raw_ptr, variable_node)
        else if (is_const)
            try gz.addUnNode(.make_ptr_const, raw_ptr, node)
        else
            raw_ptr;

        const name_token = full_var_decl.ast.mut_token + 1;
        const ident_name_raw = tree.tokenSlice(name_token);
        const ident_name = try astgen.identAsString(name_token);
        try astgen.detectLocalShadowing(
            cur_scope,
            ident_name,
            name_token,
            ident_name_raw,
            if (is_const) .@"local constant" else .@"local variable",
        );
        try gz.addDbgVar(.dbg_var_ptr, ident_name, final_ptr);
        // Finally, create the scope.
        const sub_scope = try block_arena.create(Scope.LocalPtr);
        sub_scope.* = .{
            .parent = cur_scope,
            .gen_zir = gz,
            .name = ident_name,
            .ptr = final_ptr,
            .token_src = name_token,
            .maybe_comptime = is_const or is_comptime,
            .id_cat = if (is_const) .@"local constant" else .@"local variable",
        };
        cur_scope = &sub_scope.base;
    }

    return cur_scope;
}

fn assignOp(
    gz: *GenZir,
    scope: *Scope,
    infix_node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!void {
    try emitDbgNode(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lhs_node, const rhs_node = tree.nodeData(infix_node).node_and_node;
    const lhs_ptr = try lvalExpr(gz, scope, lhs_node);

    const cursor = switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => maybeAdvanceSourceCursorToMainToken(gz, infix_node),
        else => undefined,
    };
    const lhs = try gz.addUnNode(.load, lhs_ptr, infix_node);

    const rhs_res_ty = switch (op_inst_tag) {
        .add,
        .sub,
        => try gz.add(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .inplace_arith_result_ty,
                .small = @intFromEnum(@as(Zir.Inst.InplaceOp, switch (op_inst_tag) {
                    .add => .add_eq,
                    .sub => .sub_eq,
                    else => unreachable,
                })),
                .operand = @intFromEnum(lhs),
            } },
        }),
        else => try gz.addUnNode(.typeof, lhs, infix_node), // same as LHS type
    };
    // Not `coerced_ty` since `add`/etc won't coerce to this type.
    const rhs = try expr(gz, scope, .{ .rl = .{ .ty = rhs_res_ty } }, rhs_node);

    switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => {
            try emitDbgStmt(gz, cursor);
        },
        else => {},
    }
    const result = try gz.addPlNode(op_inst_tag, infix_node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    _ = try gz.addPlNode(.store_node, infix_node, Zir.Inst.Bin{
        .lhs = lhs_ptr,
        .rhs = result,
    });
}

fn assignShift(
    gz: *GenZir,
    scope: *Scope,
    infix_node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!void {
    try emitDbgNode(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lhs_node, const rhs_node = tree.nodeData(infix_node).node_and_node;
    const lhs_ptr = try lvalExpr(gz, scope, lhs_node);
    const lhs = try gz.addUnNode(.load, lhs_ptr, infix_node);
    const rhs_type = try gz.addUnNode(.typeof_log2_int_type, lhs, infix_node);
    const rhs = try expr(gz, scope, .{ .rl = .{ .ty = rhs_type } }, rhs_node);

    const result = try gz.addPlNode(op_inst_tag, infix_node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    _ = try gz.addPlNode(.store_node, infix_node, Zir.Inst.Bin{
        .lhs = lhs_ptr,
        .rhs = result,
    });
}

fn assignShiftSat(gz: *GenZir, scope: *Scope, infix_node: Ast.Node.Index) InnerError!void {
    try emitDbgNode(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const lhs_node, const rhs_node = tree.nodeData(infix_node).node_and_node;
    const lhs_ptr = try lvalExpr(gz, scope, lhs_node);
    const lhs = try gz.addUnNode(.load, lhs_ptr, infix_node);
    // Saturating shift-left allows any integer type for both the LHS and RHS.
    const rhs = try expr(gz, scope, .{ .rl = .none }, rhs_node);

    const result = try gz.addPlNode(.shl_sat, infix_node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    _ = try gz.addPlNode(.store_node, infix_node, Zir.Inst.Bin{
        .lhs = lhs_ptr,
        .rhs = result,
    });
}

fn ptrType(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    ptr_info: Ast.full.PtrType,
) InnerError!Zir.Inst.Ref {
    if (ptr_info.size == .c and ptr_info.allowzero_token != null) {
        return gz.astgen.failTok(ptr_info.allowzero_token.?, "C pointers always allow address zero", .{});
    }

    const source_offset = gz.astgen.source_offset;
    const source_line = gz.astgen.source_line;
    const source_column = gz.astgen.source_column;
    const elem_type = try typeExpr(gz, scope, ptr_info.ast.child_type);

    var sentinel_ref: Zir.Inst.Ref = .none;
    var align_ref: Zir.Inst.Ref = .none;
    var addrspace_ref: Zir.Inst.Ref = .none;
    var bit_start_ref: Zir.Inst.Ref = .none;
    var bit_end_ref: Zir.Inst.Ref = .none;
    var trailing_count: u32 = 0;

    if (ptr_info.ast.sentinel.unwrap()) |sentinel| {
        // These attributes can appear in any order and they all come before the
        // element type so we need to reset the source cursor before generating them.
        gz.astgen.source_offset = source_offset;
        gz.astgen.source_line = source_line;
        gz.astgen.source_column = source_column;

        sentinel_ref = try comptimeExpr(
            gz,
            scope,
            .{ .rl = .{ .ty = elem_type } },
            sentinel,
            switch (ptr_info.size) {
                .slice => .slice_sentinel,
                else => .pointer_sentinel,
            },
        );
        trailing_count += 1;
    }
    if (ptr_info.ast.addrspace_node.unwrap()) |addrspace_node| {
        gz.astgen.source_offset = source_offset;
        gz.astgen.source_line = source_line;
        gz.astgen.source_column = source_column;

        const addrspace_ty = try gz.addBuiltinValue(addrspace_node, .address_space);
        addrspace_ref = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = addrspace_ty } }, addrspace_node, .@"addrspace");
        trailing_count += 1;
    }
    if (ptr_info.ast.align_node.unwrap()) |align_node| {
        gz.astgen.source_offset = source_offset;
        gz.astgen.source_line = source_line;
        gz.astgen.source_column = source_column;

        align_ref = try comptimeExpr(gz, scope, coerced_align_ri, align_node, .@"align");
        trailing_count += 1;
    }
    if (ptr_info.ast.bit_range_start.unwrap()) |bit_range_start| {
        const bit_range_end = ptr_info.ast.bit_range_end.unwrap().?;
        bit_start_ref = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u16_type } }, bit_range_start, .type);
        bit_end_ref = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = .u16_type } }, bit_range_end, .type);
        trailing_count += 2;
    }

    const gpa = gz.astgen.gpa;
    try gz.instructions.ensureUnusedCapacity(gpa, 1);
    try gz.astgen.instructions.ensureUnusedCapacity(gpa, 1);
    try gz.astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.PtrType).@"struct".fields.len +
        trailing_count);

    const payload_index = gz.astgen.addExtraAssumeCapacity(Zir.Inst.PtrType{
        .elem_type = elem_type,
        .src_node = gz.nodeIndexToRelative(node),
    });
    if (sentinel_ref != .none) {
        gz.astgen.extra.appendAssumeCapacity(@intFromEnum(sentinel_ref));
    }
    if (align_ref != .none) {
        gz.astgen.extra.appendAssumeCapacity(@intFromEnum(align_ref));
    }
    if (addrspace_ref != .none) {
        gz.astgen.extra.appendAssumeCapacity(@intFromEnum(addrspace_ref));
    }
    if (bit_start_ref != .none) {
        gz.astgen.extra.appendAssumeCapacity(@intFromEnum(bit_start_ref));
        gz.astgen.extra.appendAssumeCapacity(@intFromEnum(bit_end_ref));
    }

    const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
    const result = new_index.toRef();
    gz.astgen.instructions.appendAssumeCapacity(.{ .tag = .ptr_type, .data = .{
        .ptr_type = .{
            .flags = .{
                .is_allowzero = ptr_info.allowzero_token != null,
                .is_mutable = ptr_info.const_token == null,
                .is_volatile = ptr_info.volatile_token != null,
                .has_sentinel = sentinel_ref != .none,
                .has_align = align_ref != .none,
                .has_addrspace = addrspace_ref != .none,
                .has_bit_range = bit_start_ref != .none,
            },
            .size = ptr_info.size,
            .payload_index = payload_index,
        },
    } });
    gz.instructions.appendAssumeCapacity(new_index);

    return rvalue(gz, ri, result, node);
}

fn arrayType(gz: *GenZir, scope: *Scope, ri: ResultInfo, node: Ast.Node.Index) !Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const len_node, const elem_type_node = tree.nodeData(node).node_and_node;
    if (tree.nodeTag(len_node) == .identifier and
        mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(len_node)), "_"))
    {
        return astgen.failNode(len_node, "unable to infer array size", .{});
    }
    const len = try reachableExprComptime(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, len_node, node, .type);
    const elem_type = try typeExpr(gz, scope, elem_type_node);

    const result = try gz.addPlNode(.array_type, node, Zir.Inst.Bin{
        .lhs = len,
        .rhs = elem_type,
    });
    return rvalue(gz, ri, result, node);
}

fn arrayTypeSentinel(gz: *GenZir, scope: *Scope, ri: ResultInfo, node: Ast.Node.Index) !Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const len_node, const extra_index = tree.nodeData(node).node_and_extra;
    const extra = tree.extraData(extra_index, Ast.Node.ArrayTypeSentinel);

    if (tree.nodeTag(len_node) == .identifier and
        mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(len_node)), "_"))
    {
        return astgen.failNode(len_node, "unable to infer array size", .{});
    }
    const len = try reachableExprComptime(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, len_node, node, .array_length);
    const elem_type = try typeExpr(gz, scope, extra.elem_type);
    const sentinel = try reachableExprComptime(gz, scope, .{ .rl = .{ .coerced_ty = elem_type } }, extra.sentinel, node, .array_sentinel);

    const result = try gz.addPlNode(.array_type_sentinel, node, Zir.Inst.ArrayTypeSentinel{
        .len = len,
        .elem_type = elem_type,
        .sentinel = sentinel,
    });
    return rvalue(gz, ri, result, node);
}

const WipMembers = struct {
    payload: *ArrayListUnmanaged(u32),
    payload_top: usize,
    field_bits_start: u32,
    fields_start: u32,
    fields_end: u32,
    decl_index: u32 = 0,
    field_index: u32 = 0,

    const Self = @This();

    fn init(gpa: Allocator, payload: *ArrayListUnmanaged(u32), decl_count: u32, field_count: u32, comptime bits_per_field: u32, comptime max_field_size: u32) Allocator.Error!Self {
        const payload_top: u32 = @intCast(payload.items.len);
        const field_bits_start = payload_top + decl_count;
        const fields_start = field_bits_start + if (bits_per_field > 0) blk: {
            const fields_per_u32 = 32 / bits_per_field;
            break :blk (field_count + fields_per_u32 - 1) / fields_per_u32;
        } else 0;
        const payload_end = fields_start + field_count * max_field_size;
        try payload.resize(gpa, payload_end);
        return .{
            .payload = payload,
            .payload_top = payload_top,
            .field_bits_start = field_bits_start,
            .fields_start = fields_start,
            .fields_end = fields_start,
        };
    }

    fn nextDecl(self: *Self, decl_inst: Zir.Inst.Index) void {
        self.payload.items[self.payload_top + self.decl_index] = @intFromEnum(decl_inst);
        self.decl_index += 1;
    }

    fn nextField(self: *Self, comptime bits_per_field: u32, bits: [bits_per_field]bool) void {
        const fields_per_u32 = 32 / bits_per_field;
        const index = self.field_bits_start + self.field_index / fields_per_u32;
        assert(index < self.fields_start);
        var bit_bag: u32 = if (self.field_index % fields_per_u32 == 0) 0 else self.payload.items[index];
        bit_bag >>= bits_per_field;
        comptime var i = 0;
        inline while (i < bits_per_field) : (i += 1) {
            bit_bag |= @as(u32, @intFromBool(bits[i])) << (32 - bits_per_field + i);
        }
        self.payload.items[index] = bit_bag;
        self.field_index += 1;
    }

    fn appendToField(self: *Self, data: u32) void {
        assert(self.fields_end < self.payload.items.len);
        self.payload.items[self.fields_end] = data;
        self.fields_end += 1;
    }

    fn finishBits(self: *Self, comptime bits_per_field: u32) void {
        if (bits_per_field > 0) {
            const fields_per_u32 = 32 / bits_per_field;
            const empty_field_slots = fields_per_u32 - (self.field_index % fields_per_u32);
            if (self.field_index > 0 and empty_field_slots < fields_per_u32) {
                const index = self.field_bits_start + self.field_index / fields_per_u32;
                self.payload.items[index] >>= @intCast(empty_field_slots * bits_per_field);
            }
        }
    }

    fn declsSlice(self: *Self) []u32 {
        return self.payload.items[self.payload_top..][0..self.decl_index];
    }

    fn fieldsSlice(self: *Self) []u32 {
        return self.payload.items[self.field_bits_start..self.fields_end];
    }

    fn deinit(self: *Self) void {
        self.payload.items.len = self.payload_top;
    }
};

fn fnDecl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    decl_node: Ast.Node.Index,
    body_node: Ast.Node.OptionalIndex,
    fn_proto: Ast.full.FnProto,
) InnerError!void {
    const tree = astgen.tree;

    const old_hasher = astgen.src_hasher;
    defer astgen.src_hasher = old_hasher;
    astgen.src_hasher = std.zig.SrcHasher.init(.{});
    // We don't add the full source yet, because we also need the prototype hash!
    // The source slice is added towards the *end* of this function.
    astgen.src_hasher.update(std.mem.asBytes(&astgen.source_column));

    // missing function name already checked in scanContainer()
    const fn_name_token = fn_proto.name_token.?;

    // We insert this at the beginning so that its instruction index marks the
    // start of the top level declaration.
    const decl_inst = try gz.makeDeclaration(fn_proto.ast.proto_node);
    astgen.advanceSourceCursorToNode(decl_node);

    const saved_cursor = astgen.saveSourceCursor();

    const decl_column = astgen.source_column;

    // Set this now, since parameter types, return type, etc may be generic.
    const prev_within_fn = astgen.within_fn;
    defer astgen.within_fn = prev_within_fn;
    astgen.within_fn = true;

    const is_pub = fn_proto.visib_token != null;
    const is_export = blk: {
        const maybe_export_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_export_token) == .keyword_export;
    };
    const is_extern = blk: {
        const maybe_extern_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_extern_token) == .keyword_extern;
    };
    const has_inline_keyword = blk: {
        const maybe_inline_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_inline_token) == .keyword_inline;
    };
    const lib_name = if (fn_proto.lib_name) |lib_name_token| blk: {
        const lib_name_str = try astgen.strLitAsString(lib_name_token);
        const lib_name_slice = astgen.string_bytes.items[@intFromEnum(lib_name_str.index)..][0..lib_name_str.len];
        if (mem.indexOfScalar(u8, lib_name_slice, 0) != null) {
            return astgen.failTok(lib_name_token, "library name cannot contain null bytes", .{});
        } else if (lib_name_str.len == 0) {
            return astgen.failTok(lib_name_token, "library name cannot be empty", .{});
        }
        break :blk lib_name_str.index;
    } else .empty;
    if (fn_proto.ast.callconv_expr != .none and has_inline_keyword) {
        return astgen.failNode(
            fn_proto.ast.callconv_expr.unwrap().?,
            "explicit callconv incompatible with inline keyword",
            .{},
        );
    }

    const return_type = fn_proto.ast.return_type.unwrap().?;
    const maybe_bang = tree.firstToken(return_type) - 1;
    const is_inferred_error = tree.tokenTag(maybe_bang) == .bang;
    if (body_node == .none) {
        if (!is_extern) {
            return astgen.failTok(fn_proto.ast.fn_token, "non-extern function has no body", .{});
        }
        if (is_inferred_error) {
            return astgen.failTok(maybe_bang, "function prototype may not have inferred error set", .{});
        }
    } else {
        assert(!is_extern); // validated by parser (TODO why???)
    }

    wip_members.nextDecl(decl_inst);

    var type_gz: GenZir = .{
        .is_comptime = true,
        .decl_node_index = fn_proto.ast.proto_node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer type_gz.unstack();

    if (is_extern) {
        // We include a function *type*, not a value.
        const type_inst = try fnProtoExprInner(&type_gz, &type_gz.base, .{ .rl = .none }, decl_node, fn_proto, true);
        _ = try type_gz.addBreakWithSrcNode(.break_inline, decl_inst, type_inst, decl_node);
    }

    var align_gz = type_gz.makeSubBlock(scope);
    defer align_gz.unstack();

    if (fn_proto.ast.align_expr.unwrap()) |align_expr| {
        astgen.restoreSourceCursor(saved_cursor);
        const inst = try expr(&align_gz, &align_gz.base, coerced_align_ri, align_expr);
        _ = try align_gz.addBreakWithSrcNode(.break_inline, decl_inst, inst, decl_node);
    }

    var linksection_gz = align_gz.makeSubBlock(scope);
    defer linksection_gz.unstack();

    if (fn_proto.ast.section_expr.unwrap()) |section_expr| {
        astgen.restoreSourceCursor(saved_cursor);
        const inst = try expr(&linksection_gz, &linksection_gz.base, coerced_linksection_ri, section_expr);
        _ = try linksection_gz.addBreakWithSrcNode(.break_inline, decl_inst, inst, decl_node);
    }

    var addrspace_gz = linksection_gz.makeSubBlock(scope);
    defer addrspace_gz.unstack();

    if (fn_proto.ast.addrspace_expr.unwrap()) |addrspace_expr| {
        astgen.restoreSourceCursor(saved_cursor);
        const addrspace_ty = try addrspace_gz.addBuiltinValue(addrspace_expr, .address_space);
        const inst = try expr(&addrspace_gz, &addrspace_gz.base, .{ .rl = .{ .coerced_ty = addrspace_ty } }, addrspace_expr);
        _ = try addrspace_gz.addBreakWithSrcNode(.break_inline, decl_inst, inst, decl_node);
    }

    var value_gz = addrspace_gz.makeSubBlock(scope);
    defer value_gz.unstack();

    if (!is_extern) {
        // We include a function *value*, not a type.
        astgen.restoreSourceCursor(saved_cursor);
        try astgen.fnDeclInner(&value_gz, &value_gz.base, saved_cursor, decl_inst, decl_node, body_node.unwrap().?, fn_proto);
    }

    // *Now* we can incorporate the full source code into the hasher.
    astgen.src_hasher.update(tree.getNodeSource(decl_node));

    var hash: std.zig.SrcHash = undefined;
    astgen.src_hasher.final(&hash);
    try setDeclaration(decl_inst, .{
        .src_hash = hash,
        .src_line = type_gz.decl_line,
        .src_column = decl_column,

        .kind = .@"const",
        .name = try astgen.identAsString(fn_name_token),
        .is_pub = is_pub,
        .is_threadlocal = false,
        .linkage = if (is_extern) .@"extern" else if (is_export) .@"export" else .normal,
        .lib_name = lib_name,

        .type_gz = &type_gz,
        .align_gz = &align_gz,
        .linksection_gz = &linksection_gz,
        .addrspace_gz = &addrspace_gz,
        .value_gz = &value_gz,
    });
}

fn fnDeclInner(
    astgen: *AstGen,
    decl_gz: *GenZir,
    scope: *Scope,
    saved_cursor: SourceCursor,
    decl_inst: Zir.Inst.Index,
    decl_node: Ast.Node.Index,
    body_node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
) InnerError!void {
    const tree = astgen.tree;

    const is_noinline = blk: {
        const maybe_noinline_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_noinline_token) == .keyword_noinline;
    };
    const has_inline_keyword = blk: {
        const maybe_inline_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_inline_token) == .keyword_inline;
    };

    const return_type = fn_proto.ast.return_type.unwrap().?;
    const maybe_bang = tree.firstToken(return_type) - 1;
    const is_inferred_error = tree.tokenTag(maybe_bang) == .bang;

    // Note that the capacity here may not be sufficient, as this does not include `anytype` parameters.
    var param_insts: std.ArrayListUnmanaged(Zir.Inst.Index) = try .initCapacity(astgen.arena, fn_proto.ast.params.len);

    // We use this as `is_used_or_discarded` to figure out if parameters / return types are generic.
    var any_param_used = false;

    var noalias_bits: u32 = 0;
    var params_scope = scope;
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

            const param_name: Zir.NullTerminatedString = if (param.name_token) |name_token| blk: {
                const name_bytes = tree.tokenSlice(name_token);
                if (mem.eql(u8, "_", name_bytes))
                    break :blk .empty;

                const param_name = try astgen.identAsString(name_token);
                try astgen.detectLocalShadowing(params_scope, param_name, name_token, name_bytes, .@"function parameter");
                break :blk param_name;
            } else {
                if (param.anytype_ellipsis3) |tok| {
                    return astgen.failTok(tok, "missing parameter name", .{});
                } else {
                    const type_expr = param.type_expr.?;
                    ambiguous: {
                        if (tree.nodeTag(type_expr) != .identifier) break :ambiguous;
                        const main_token = tree.nodeMainToken(type_expr);
                        const identifier_str = tree.tokenSlice(main_token);
                        if (isPrimitive(identifier_str)) break :ambiguous;
                        return astgen.failNodeNotes(
                            type_expr,
                            "missing parameter name or type",
                            .{},
                            &[_]u32{
                                try astgen.errNoteNode(
                                    type_expr,
                                    "if this is a name, annotate its type '{s}: T'",
                                    .{identifier_str},
                                ),
                                try astgen.errNoteNode(
                                    type_expr,
                                    "if this is a type, give it a name '<name>: {s}'",
                                    .{identifier_str},
                                ),
                            },
                        );
                    }
                    return astgen.failNode(type_expr, "missing parameter name", .{});
                }
            };

            const param_inst = if (is_anytype) param: {
                const name_token = param.name_token orelse param.anytype_ellipsis3.?;
                const tag: Zir.Inst.Tag = if (is_comptime)
                    .param_anytype_comptime
                else
                    .param_anytype;
                break :param try decl_gz.addStrTok(tag, param_name, name_token);
            } else param: {
                const param_type_node = param.type_expr.?;
                any_param_used = false; // we will check this later
                var param_gz = decl_gz.makeSubBlock(scope);
                defer param_gz.unstack();
                const param_type = try fullBodyExpr(&param_gz, params_scope, coerced_type_ri, param_type_node, .normal);
                const param_inst_expected: Zir.Inst.Index = @enumFromInt(astgen.instructions.len + 1);
                _ = try param_gz.addBreakWithSrcNode(.break_inline, param_inst_expected, param_type, param_type_node);
                const param_type_is_generic = any_param_used;

                const name_token = param.name_token orelse tree.nodeMainToken(param_type_node);
                const tag: Zir.Inst.Tag = if (is_comptime) .param_comptime else .param;
                const param_inst = try decl_gz.addParam(&param_gz, param_insts.items, param_type_is_generic, tag, name_token, param_name);
                assert(param_inst_expected == param_inst);
                break :param param_inst.toRef();
            };

            if (param_name == .empty) continue;

            const sub_scope = try astgen.arena.create(Scope.LocalVal);
            sub_scope.* = .{
                .parent = params_scope,
                .gen_zir = decl_gz,
                .name = param_name,
                .inst = param_inst,
                .token_src = param.name_token.?,
                .id_cat = .@"function parameter",
                .is_used_or_discarded = &any_param_used,
            };
            params_scope = &sub_scope.base;
            try param_insts.append(astgen.arena, param_inst.toIndex().?);
        }
        break :is_var_args false;
    };

    // After creating the function ZIR instruction, it will need to update the break
    // instructions inside the expression blocks for cc and ret_ty to use the function
    // instruction as the body to break from.

    var ret_gz = decl_gz.makeSubBlock(params_scope);
    defer ret_gz.unstack();
    any_param_used = false; // we will check this later
    const ret_ref: Zir.Inst.Ref = inst: {
        // Parameters are in scope for the return type, so we use `params_scope` here.
        // The calling convention will not have parameters in scope, so we'll just use `scope`.
        // See #22263 for a proposal to solve the inconsistency here.
        const inst = try fullBodyExpr(&ret_gz, params_scope, coerced_type_ri, fn_proto.ast.return_type.unwrap().?, .normal);
        if (ret_gz.instructionsSlice().len == 0) {
            // In this case we will send a len=0 body which can be encoded more efficiently.
            break :inst inst;
        }
        _ = try ret_gz.addBreak(.break_inline, @enumFromInt(0), inst);
        break :inst inst;
    };
    const ret_body_param_refs = try astgen.fetchRemoveRefEntries(param_insts.items);
    const ret_ty_is_generic = any_param_used;

    // We're jumping back in source, so restore the cursor.
    astgen.restoreSourceCursor(saved_cursor);

    var cc_gz = decl_gz.makeSubBlock(scope);
    defer cc_gz.unstack();
    const cc_ref: Zir.Inst.Ref = blk: {
        if (fn_proto.ast.callconv_expr.unwrap()) |callconv_expr| {
            const inst = try expr(
                &cc_gz,
                scope,
                .{ .rl = .{ .coerced_ty = try cc_gz.addBuiltinValue(callconv_expr, .calling_convention) } },
                callconv_expr,
            );
            if (cc_gz.instructionsSlice().len == 0) {
                // In this case we will send a len=0 body which can be encoded more efficiently.
                break :blk inst;
            }
            _ = try cc_gz.addBreak(.break_inline, @enumFromInt(0), inst);
            break :blk inst;
        } else if (has_inline_keyword) {
            const inst = try cc_gz.addBuiltinValue(decl_node, .calling_convention_inline);
            _ = try cc_gz.addBreak(.break_inline, @enumFromInt(0), inst);
            break :blk inst;
        } else {
            break :blk .none;
        }
    };

    var body_gz: GenZir = .{
        .is_comptime = false,
        .decl_node_index = fn_proto.ast.proto_node,
        .decl_line = decl_gz.decl_line,
        .parent = params_scope,
        .astgen = astgen,
        .instructions = decl_gz.instructions,
        .instructions_top = decl_gz.instructions.items.len,
    };
    defer body_gz.unstack();

    // The scope stack looks like this:
    //  body_gz (top)
    //  param2
    //  param1
    //  param0
    //  decl_gz (bottom)

    // Construct the prototype hash.
    // Leave `astgen.src_hasher` unmodified; this will be used for hashing
    // the *whole* function declaration, including its body.
    var proto_hasher = astgen.src_hasher;
    const proto_node = tree.nodeData(decl_node).node_and_node[0];
    proto_hasher.update(tree.getNodeSource(proto_node));
    var proto_hash: std.zig.SrcHash = undefined;
    proto_hasher.final(&proto_hash);

    const prev_fn_block = astgen.fn_block;
    const prev_fn_ret_ty = astgen.fn_ret_ty;
    defer {
        astgen.fn_block = prev_fn_block;
        astgen.fn_ret_ty = prev_fn_ret_ty;
    }
    astgen.fn_block = &body_gz;
    astgen.fn_ret_ty = if (is_inferred_error or ret_ref.toIndex() != null) r: {
        // We're essentially guaranteed to need the return type at some point,
        // since the return type is likely not `void` or `noreturn` so there
        // will probably be an explicit return requiring RLS. Fetch this
        // return type now so the rest of the function can use it.
        break :r try body_gz.addNode(.ret_type, decl_node);
    } else ret_ref;

    const prev_var_args = astgen.fn_var_args;
    astgen.fn_var_args = is_var_args;
    defer astgen.fn_var_args = prev_var_args;

    astgen.advanceSourceCursorToNode(body_node);
    const lbrace_line = astgen.source_line - decl_gz.decl_line;
    const lbrace_column = astgen.source_column;

    _ = try fullBodyExpr(&body_gz, &body_gz.base, .{ .rl = .none }, body_node, .allow_branch_hint);
    try checkUsed(decl_gz, scope, params_scope);

    if (!body_gz.endsWithNoReturn()) {
        // As our last action before the return, "pop" the error trace if needed
        _ = try body_gz.addRestoreErrRetIndex(.ret, .always, decl_node);

        // Add implicit return at end of function.
        _ = try body_gz.addUnTok(.ret_implicit, .void_value, tree.lastToken(body_node));
    }

    const func_inst = try decl_gz.addFunc(.{
        .src_node = decl_node,
        .cc_ref = cc_ref,
        .cc_gz = &cc_gz,
        .ret_ref = ret_ref,
        .ret_gz = &ret_gz,
        .ret_param_refs = ret_body_param_refs,
        .ret_ty_is_generic = ret_ty_is_generic,
        .lbrace_line = lbrace_line,
        .lbrace_column = lbrace_column,
        .param_block = decl_inst,
        .param_insts = param_insts.items,
        .body_gz = &body_gz,
        .is_var_args = is_var_args,
        .is_inferred_error = is_inferred_error,
        .is_noinline = is_noinline,
        .noalias_bits = noalias_bits,
        .proto_hash = proto_hash,
    });
    _ = try decl_gz.addBreakWithSrcNode(.break_inline, decl_inst, func_inst, decl_node);
}

fn globalVarDecl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
    var_decl: Ast.full.VarDecl,
) InnerError!void {
    const tree = astgen.tree;

    const old_hasher = astgen.src_hasher;
    defer astgen.src_hasher = old_hasher;
    astgen.src_hasher = std.zig.SrcHasher.init(.{});
    astgen.src_hasher.update(tree.getNodeSource(node));
    astgen.src_hasher.update(std.mem.asBytes(&astgen.source_column));

    const is_mutable = tree.tokenTag(var_decl.ast.mut_token) == .keyword_var;
    const name_token = var_decl.ast.mut_token + 1;
    const is_pub = var_decl.visib_token != null;
    const is_export = blk: {
        const maybe_export_token = var_decl.extern_export_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_export_token) == .keyword_export;
    };
    const is_extern = blk: {
        const maybe_extern_token = var_decl.extern_export_token orelse break :blk false;
        break :blk tree.tokenTag(maybe_extern_token) == .keyword_extern;
    };
    const is_threadlocal = if (var_decl.threadlocal_token) |tok| blk: {
        if (!is_mutable) {
            return astgen.failTok(tok, "threadlocal variable cannot be constant", .{});
        }
        break :blk true;
    } else false;
    const lib_name = if (var_decl.lib_name) |lib_name_token| blk: {
        const lib_name_str = try astgen.strLitAsString(lib_name_token);
        const lib_name_slice = astgen.string_bytes.items[@intFromEnum(lib_name_str.index)..][0..lib_name_str.len];
        if (mem.indexOfScalar(u8, lib_name_slice, 0) != null) {
            return astgen.failTok(lib_name_token, "library name cannot contain null bytes", .{});
        } else if (lib_name_str.len == 0) {
            return astgen.failTok(lib_name_token, "library name cannot be empty", .{});
        }
        break :blk lib_name_str.index;
    } else .empty;

    astgen.advanceSourceCursorToNode(node);

    const decl_column = astgen.source_column;

    const decl_inst = try gz.makeDeclaration(node);
    wip_members.nextDecl(decl_inst);

    if (var_decl.ast.init_node.unwrap()) |init_node| {
        if (is_extern) {
            return astgen.failNode(
                init_node,
                "extern variables have no initializers",
                .{},
            );
        }
    } else {
        if (!is_extern) {
            return astgen.failNode(node, "variables must be initialized", .{});
        }
    }

    if (is_extern and var_decl.ast.type_node == .none) {
        return astgen.failNode(node, "unable to infer variable type", .{});
    }

    assert(var_decl.comptime_token == null); // handled by parser

    var type_gz: GenZir = .{
        .parent = scope,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .astgen = astgen,
        .is_comptime = true,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer type_gz.unstack();

    if (var_decl.ast.type_node.unwrap()) |type_node| {
        const type_inst = try expr(&type_gz, &type_gz.base, coerced_type_ri, type_node);
        _ = try type_gz.addBreakWithSrcNode(.break_inline, decl_inst, type_inst, node);
    }

    var align_gz = type_gz.makeSubBlock(scope);
    defer align_gz.unstack();

    if (var_decl.ast.align_node.unwrap()) |align_node| {
        const align_inst = try expr(&align_gz, &align_gz.base, coerced_align_ri, align_node);
        _ = try align_gz.addBreakWithSrcNode(.break_inline, decl_inst, align_inst, node);
    }

    var linksection_gz = type_gz.makeSubBlock(scope);
    defer linksection_gz.unstack();

    if (var_decl.ast.section_node.unwrap()) |section_node| {
        const linksection_inst = try expr(&linksection_gz, &linksection_gz.base, coerced_linksection_ri, section_node);
        _ = try linksection_gz.addBreakWithSrcNode(.break_inline, decl_inst, linksection_inst, node);
    }

    var addrspace_gz = type_gz.makeSubBlock(scope);
    defer addrspace_gz.unstack();

    if (var_decl.ast.addrspace_node.unwrap()) |addrspace_node| {
        const addrspace_ty = try addrspace_gz.addBuiltinValue(addrspace_node, .address_space);
        const addrspace_inst = try expr(&addrspace_gz, &addrspace_gz.base, .{ .rl = .{ .coerced_ty = addrspace_ty } }, addrspace_node);
        _ = try addrspace_gz.addBreakWithSrcNode(.break_inline, decl_inst, addrspace_inst, node);
    }

    var init_gz = type_gz.makeSubBlock(scope);
    defer init_gz.unstack();

    if (var_decl.ast.init_node.unwrap()) |init_node| {
        init_gz.anon_name_strategy = .parent;
        const init_ri: ResultInfo = if (var_decl.ast.type_node != .none) .{
            .rl = .{ .coerced_ty = decl_inst.toRef() },
        } else .{ .rl = .none };
        const init_inst = try expr(&init_gz, &init_gz.base, init_ri, init_node);
        _ = try init_gz.addBreakWithSrcNode(.break_inline, decl_inst, init_inst, node);
    }

    var hash: std.zig.SrcHash = undefined;
    astgen.src_hasher.final(&hash);
    try setDeclaration(decl_inst, .{
        .src_hash = hash,
        .src_line = type_gz.decl_line,
        .src_column = decl_column,

        .kind = if (is_mutable) .@"var" else .@"const",
        .name = try astgen.identAsString(name_token),
        .is_pub = is_pub,
        .is_threadlocal = is_threadlocal,
        .linkage = if (is_extern) .@"extern" else if (is_export) .@"export" else .normal,
        .lib_name = lib_name,

        .type_gz = &type_gz,
        .align_gz = &align_gz,
        .linksection_gz = &linksection_gz,
        .addrspace_gz = &addrspace_gz,
        .value_gz = &init_gz,
    });
}

fn comptimeDecl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
) InnerError!void {
    const tree = astgen.tree;
    const body_node = tree.nodeData(node).node;

    const old_hasher = astgen.src_hasher;
    defer astgen.src_hasher = old_hasher;
    astgen.src_hasher = std.zig.SrcHasher.init(.{});
    astgen.src_hasher.update(tree.getNodeSource(node));
    astgen.src_hasher.update(std.mem.asBytes(&astgen.source_column));

    // Up top so the ZIR instruction index marks the start range of this
    // top-level declaration.
    const decl_inst = try gz.makeDeclaration(node);
    wip_members.nextDecl(decl_inst);
    astgen.advanceSourceCursorToNode(node);

    // This is just needed for the `setDeclaration` call.
    var dummy_gz = gz.makeSubBlock(scope);
    defer dummy_gz.unstack();

    var comptime_gz: GenZir = .{
        .is_comptime = true,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = dummy_gz.instructions,
        .instructions_top = dummy_gz.instructions.items.len,
    };
    defer comptime_gz.unstack();

    const decl_column = astgen.source_column;

    const block_result = try fullBodyExpr(&comptime_gz, &comptime_gz.base, .{ .rl = .none }, body_node, .normal);
    if (comptime_gz.isEmpty() or !comptime_gz.refIsNoReturn(block_result)) {
        _ = try comptime_gz.addBreak(.break_inline, decl_inst, .void_value);
    }

    var hash: std.zig.SrcHash = undefined;
    astgen.src_hasher.final(&hash);
    try setDeclaration(decl_inst, .{
        .src_hash = hash,
        .src_line = comptime_gz.decl_line,
        .src_column = decl_column,
        .kind = .@"comptime",
        .name = .empty,
        .is_pub = false,
        .is_threadlocal = false,
        .linkage = .normal,
        .type_gz = &dummy_gz,
        .align_gz = &dummy_gz,
        .linksection_gz = &dummy_gz,
        .addrspace_gz = &dummy_gz,
        .value_gz = &comptime_gz,
    });
}

fn usingnamespaceDecl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
) InnerError!void {
    const tree = astgen.tree;

    const old_hasher = astgen.src_hasher;
    defer astgen.src_hasher = old_hasher;
    astgen.src_hasher = std.zig.SrcHasher.init(.{});
    astgen.src_hasher.update(tree.getNodeSource(node));
    astgen.src_hasher.update(std.mem.asBytes(&astgen.source_column));

    const type_expr = tree.nodeData(node).node;
    const is_pub = tree.isTokenPrecededByTags(tree.nodeMainToken(node), &.{.keyword_pub});

    // Up top so the ZIR instruction index marks the start range of this
    // top-level declaration.
    const decl_inst = try gz.makeDeclaration(node);
    wip_members.nextDecl(decl_inst);
    astgen.advanceSourceCursorToNode(node);

    // This is just needed for the `setDeclaration` call.
    var dummy_gz = gz.makeSubBlock(scope);
    defer dummy_gz.unstack();

    var usingnamespace_gz: GenZir = .{
        .is_comptime = true,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer usingnamespace_gz.unstack();

    const decl_column = astgen.source_column;

    const namespace_inst = try typeExpr(&usingnamespace_gz, &usingnamespace_gz.base, type_expr);
    _ = try usingnamespace_gz.addBreak(.break_inline, decl_inst, namespace_inst);

    var hash: std.zig.SrcHash = undefined;
    astgen.src_hasher.final(&hash);
    try setDeclaration(decl_inst, .{
        .src_hash = hash,
        .src_line = usingnamespace_gz.decl_line,
        .src_column = decl_column,
        .kind = .@"usingnamespace",
        .name = .empty,
        .is_pub = is_pub,
        .is_threadlocal = false,
        .linkage = .normal,
        .type_gz = &dummy_gz,
        .align_gz = &dummy_gz,
        .linksection_gz = &dummy_gz,
        .addrspace_gz = &dummy_gz,
        .value_gz = &usingnamespace_gz,
    });
}

fn testDecl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
) InnerError!void {
    const tree = astgen.tree;
    _, const body_node = tree.nodeData(node).opt_token_and_node;

    const old_hasher = astgen.src_hasher;
    defer astgen.src_hasher = old_hasher;
    astgen.src_hasher = std.zig.SrcHasher.init(.{});
    astgen.src_hasher.update(tree.getNodeSource(node));
    astgen.src_hasher.update(std.mem.asBytes(&astgen.source_column));

    // Up top so the ZIR instruction index marks the start range of this
    // top-level declaration.
    const decl_inst = try gz.makeDeclaration(node);

    wip_members.nextDecl(decl_inst);
    astgen.advanceSourceCursorToNode(node);

    // This is just needed for the `setDeclaration` call.
    var dummy_gz: GenZir = gz.makeSubBlock(scope);
    defer dummy_gz.unstack();

    var decl_block: GenZir = .{
        .is_comptime = true,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = dummy_gz.instructions,
        .instructions_top = dummy_gz.instructions.items.len,
    };
    defer decl_block.unstack();

    const decl_column = astgen.source_column;

    const test_token = tree.nodeMainToken(node);

    const test_name_token = test_token + 1;
    const test_name: Zir.NullTerminatedString = switch (tree.tokenTag(test_name_token)) {
        else => .empty,
        .string_literal => name: {
            const name = try astgen.strLitAsString(test_name_token);
            const slice = astgen.string_bytes.items[@intFromEnum(name.index)..][0..name.len];
            if (mem.indexOfScalar(u8, slice, 0) != null) {
                return astgen.failTok(test_name_token, "test name cannot contain null bytes", .{});
            } else if (slice.len == 0) {
                return astgen.failTok(test_name_token, "empty test name must be omitted", .{});
            }
            break :name name.index;
        },
        .identifier => name: {
            const ident_name_raw = tree.tokenSlice(test_name_token);

            if (mem.eql(u8, ident_name_raw, "_")) return astgen.failTok(test_name_token, "'_' used as an identifier without @\"_\" syntax", .{});

            // if not @"" syntax, just use raw token slice
            if (ident_name_raw[0] != '@') {
                if (isPrimitive(ident_name_raw)) return astgen.failTok(test_name_token, "cannot test a primitive", .{});
            }

            // Local variables, including function parameters.
            const name_str_index = try astgen.identAsString(test_name_token);
            var s = scope;
            var found_already: ?Ast.Node.Index = null; // we have found a decl with the same name already
            var num_namespaces_out: u32 = 0;
            var capturing_namespace: ?*Scope.Namespace = null;
            while (true) switch (s.tag) {
                .local_val => {
                    const local_val = s.cast(Scope.LocalVal).?;
                    if (local_val.name == name_str_index) {
                        local_val.used = .fromToken(test_name_token);
                        return astgen.failTokNotes(test_name_token, "cannot test a {s}", .{
                            @tagName(local_val.id_cat),
                        }, &[_]u32{
                            try astgen.errNoteTok(local_val.token_src, "{s} declared here", .{
                                @tagName(local_val.id_cat),
                            }),
                        });
                    }
                    s = local_val.parent;
                },
                .local_ptr => {
                    const local_ptr = s.cast(Scope.LocalPtr).?;
                    if (local_ptr.name == name_str_index) {
                        local_ptr.used = .fromToken(test_name_token);
                        return astgen.failTokNotes(test_name_token, "cannot test a {s}", .{
                            @tagName(local_ptr.id_cat),
                        }, &[_]u32{
                            try astgen.errNoteTok(local_ptr.token_src, "{s} declared here", .{
                                @tagName(local_ptr.id_cat),
                            }),
                        });
                    }
                    s = local_ptr.parent;
                },
                .gen_zir => s = s.cast(GenZir).?.parent,
                .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
                .namespace => {
                    const ns = s.cast(Scope.Namespace).?;
                    if (ns.decls.get(name_str_index)) |i| {
                        if (found_already) |f| {
                            return astgen.failTokNotes(test_name_token, "ambiguous reference", .{}, &.{
                                try astgen.errNoteNode(f, "declared here", .{}),
                                try astgen.errNoteNode(i, "also declared here", .{}),
                            });
                        }
                        // We found a match but must continue looking for ambiguous references to decls.
                        found_already = i;
                    }
                    num_namespaces_out += 1;
                    capturing_namespace = ns;
                    s = ns.parent;
                },
                .top => break,
            };
            if (found_already == null) {
                const ident_name = try astgen.identifierTokenString(test_name_token);
                return astgen.failTok(test_name_token, "use of undeclared identifier '{s}'", .{ident_name});
            }

            break :name try astgen.identAsString(test_name_token);
        },
    };

    var fn_block: GenZir = .{
        .is_comptime = false,
        .decl_node_index = node,
        .decl_line = decl_block.decl_line,
        .parent = &decl_block.base,
        .astgen = astgen,
        .instructions = decl_block.instructions,
        .instructions_top = decl_block.instructions.items.len,
    };
    defer fn_block.unstack();

    const prev_within_fn = astgen.within_fn;
    const prev_fn_block = astgen.fn_block;
    const prev_fn_ret_ty = astgen.fn_ret_ty;
    astgen.within_fn = true;
    astgen.fn_block = &fn_block;
    astgen.fn_ret_ty = .anyerror_void_error_union_type;
    defer {
        astgen.within_fn = prev_within_fn;
        astgen.fn_block = prev_fn_block;
        astgen.fn_ret_ty = prev_fn_ret_ty;
    }

    astgen.advanceSourceCursorToNode(body_node);
    const lbrace_line = astgen.source_line - decl_block.decl_line;
    const lbrace_column = astgen.source_column;

    const block_result = try fullBodyExpr(&fn_block, &fn_block.base, .{ .rl = .none }, body_node, .normal);
    if (fn_block.isEmpty() or !fn_block.refIsNoReturn(block_result)) {

        // As our last action before the return, "pop" the error trace if needed
        _ = try fn_block.addRestoreErrRetIndex(.ret, .always, node);

        // Add implicit return at end of function.
        _ = try fn_block.addUnTok(.ret_implicit, .void_value, tree.lastToken(body_node));
    }

    const func_inst = try decl_block.addFunc(.{
        .src_node = node,

        .cc_ref = .none,
        .cc_gz = null,
        .ret_ref = .anyerror_void_error_union_type,
        .ret_gz = null,

        .ret_param_refs = &.{},
        .param_insts = &.{},
        .ret_ty_is_generic = false,

        .lbrace_line = lbrace_line,
        .lbrace_column = lbrace_column,
        .param_block = decl_inst,
        .body_gz = &fn_block,
        .is_var_args = false,
        .is_inferred_error = false,
        .is_noinline = false,
        .noalias_bits = 0,

        // Tests don't have a prototype that needs hashing
        .proto_hash = .{0} ** 16,
    });

    _ = try decl_block.addBreak(.break_inline, decl_inst, func_inst);

    var hash: std.zig.SrcHash = undefined;
    astgen.src_hasher.final(&hash);
    try setDeclaration(decl_inst, .{
        .src_hash = hash,
        .src_line = decl_block.decl_line,
        .src_column = decl_column,

        .kind = switch (tree.tokenTag(test_name_token)) {
            .string_literal => .@"test",
            .identifier => .decltest,
            else => .unnamed_test,
        },
        .name = test_name,
        .is_pub = false,
        .is_threadlocal = false,
        .linkage = .normal,

        .type_gz = &dummy_gz,
        .align_gz = &dummy_gz,
        .linksection_gz = &dummy_gz,
        .addrspace_gz = &dummy_gz,
        .value_gz = &decl_block,
    });
}

fn structDeclInner(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    container_decl: Ast.full.ContainerDecl,
    layout: std.builtin.Type.ContainerLayout,
    backing_int_node: Ast.Node.OptionalIndex,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;

    is_tuple: {
        const tuple_field_node = for (container_decl.ast.members) |member_node| {
            const container_field = tree.fullContainerField(member_node) orelse continue;
            if (container_field.ast.tuple_like) break member_node;
        } else break :is_tuple;

        if (node == .root) {
            return astgen.failNode(tuple_field_node, "file cannot be a tuple", .{});
        } else {
            return tupleDecl(gz, scope, node, container_decl, layout, backing_int_node);
        }
    }

    const decl_inst = try gz.reserveInstructionIndex();

    if (container_decl.ast.members.len == 0 and backing_int_node == .none) {
        try gz.setStruct(decl_inst, .{
            .src_node = node,
            .layout = layout,
            .captures_len = 0,
            .fields_len = 0,
            .decls_len = 0,
            .has_backing_int = false,
            .known_non_opv = false,
            .known_comptime_only = false,
            .any_comptime_fields = false,
            .any_default_inits = false,
            .any_aligned_fields = false,
            .fields_hash = std.zig.hashSrc(@tagName(layout)),
        });
        return decl_inst.toRef();
    }

    var namespace: Scope.Namespace = .{
        .parent = scope,
        .node = node,
        .inst = decl_inst,
        .declaring_gz = gz,
        .maybe_generic = astgen.within_fn,
    };
    defer namespace.deinit(gpa);

    // The struct_decl instruction introduces a scope in which the decls of the struct
    // are in scope, so that field types, alignments, and default value expressions
    // can refer to decls within the struct itself.
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

    const scratch_top = astgen.scratch.items.len;
    defer astgen.scratch.items.len = scratch_top;

    var backing_int_body_len: usize = 0;
    const backing_int_ref: Zir.Inst.Ref = blk: {
        if (backing_int_node.unwrap()) |arg| {
            if (layout != .@"packed") {
                return astgen.failNode(arg, "non-packed struct does not support backing integer type", .{});
            } else {
                const backing_int_ref = try typeExpr(&block_scope, &namespace.base, arg);
                if (!block_scope.isEmpty()) {
                    if (!block_scope.endsWithNoReturn()) {
                        _ = try block_scope.addBreak(.break_inline, decl_inst, backing_int_ref);
                    }

                    const body = block_scope.instructionsSlice();
                    const old_scratch_len = astgen.scratch.items.len;
                    try astgen.scratch.ensureUnusedCapacity(gpa, countBodyLenAfterFixups(astgen, body));
                    appendBodyWithFixupsArrayList(astgen, &astgen.scratch, body);
                    backing_int_body_len = astgen.scratch.items.len - old_scratch_len;
                    block_scope.instructions.items.len = block_scope.instructions_top;
                }
                break :blk backing_int_ref;
            }
        } else {
            break :blk .none;
        }
    };

    const decl_count = try astgen.scanContainer(&namespace, container_decl.ast.members, .@"struct");
    const field_count: u32 = @intCast(container_decl.ast.members.len - decl_count);

    const bits_per_field = 4;
    const max_field_size = 5;
    var wip_members = try WipMembers.init(gpa, &astgen.scratch, decl_count, field_count, bits_per_field, max_field_size);
    defer wip_members.deinit();

    // We will use the scratch buffer, starting here, for the bodies:
    //    bodies: { // for every fields_len
    //        field_type_body_inst: Inst, // for each field_type_body_len
    //        align_body_inst: Inst, // for each align_body_len
    //        init_body_inst: Inst, // for each init_body_len
    //    }
    // Note that the scratch buffer is simultaneously being used by WipMembers, however
    // it will not access any elements beyond this point in the ArrayList. It also
    // accesses via the ArrayList items field so it can handle the scratch buffer being
    // reallocated.
    // No defer needed here because it is handled by `wip_members.deinit()` above.
    const bodies_start = astgen.scratch.items.len;

    const old_hasher = astgen.src_hasher;
    defer astgen.src_hasher = old_hasher;
    astgen.src_hasher = std.zig.SrcHasher.init(.{});
    astgen.src_hasher.update(@tagName(layout));
    if (backing_int_node.unwrap()) |arg| {
        astgen.src_hasher.update(tree.getNodeSource(arg));
    }

    var known_non_opv = false;
    var known_comptime_only = false;
    var any_comptime_fields = false;
    var any_aligned_fields = false;
    var any_default_inits = false;
    for (container_decl.ast.members) |member_node| {
        var member = switch (try containerMember(&block_scope, &namespace.base, &wip_members, member_node)) {
            .decl => continue,
            .field => |field| field,
        };

        astgen.src_hasher.update(tree.getNodeSource(member_node));

        const field_name = try astgen.identAsString(member.ast.main_token);
        member.convertToNonTupleLike(astgen.tree);
        assert(!member.ast.tuple_like);
        wip_members.appendToField(@intFromEnum(field_name));

        const type_expr = member.ast.type_expr.unwrap() orelse {
            return astgen.failTok(member.ast.main_token, "struct field missing type", .{});
        };

        const field_type = try typeExpr(&block_scope, &namespace.base, type_expr);
        const have_type_body = !block_scope.isEmpty();
        const have_align = member.ast.align_expr != .none;
        const have_value = member.ast.value_expr != .none;
        const is_comptime = member.comptime_token != null;

        if (is_comptime) {
            switch (layout) {
                .@"packed", .@"extern" => return astgen.failTok(member.comptime_token.?, "{s} struct fields cannot be marked comptime", .{@tagName(layout)}),
                .auto => any_comptime_fields = true,
            }
        } else {
            known_non_opv = known_non_opv or
                nodeImpliesMoreThanOnePossibleValue(tree, type_expr);
            known_comptime_only = known_comptime_only or
                nodeImpliesComptimeOnly(tree, type_expr);
        }
        wip_members.nextField(bits_per_field, .{ have_align, have_value, is_comptime, have_type_body });

        if (have_type_body) {
            if (!block_scope.endsWithNoReturn()) {
                _ = try block_scope.addBreak(.break_inline, decl_inst, field_type);
            }
            const body = block_scope.instructionsSlice();
            const old_scratch_len = astgen.scratch.items.len;
            try astgen.scratch.ensureUnusedCapacity(gpa, countBodyLenAfterFixups(astgen, body));
            appendBodyWithFixupsArrayList(astgen, &astgen.scratch, body);
            wip_members.appendToField(@intCast(astgen.scratch.items.len - old_scratch_len));
            block_scope.instructions.items.len = block_scope.instructions_top;
        } else {
            wip_members.appendToField(@intFromEnum(field_type));
        }

        if (member.ast.align_expr.unwrap()) |align_expr| {
            if (layout == .@"packed") {
                return astgen.failNode(align_expr, "unable to override alignment of packed struct fields", .{});
            }
            any_aligned_fields = true;
            const align_ref = try expr(&block_scope, &namespace.base, coerced_align_ri, align_expr);
            if (!block_scope.endsWithNoReturn()) {
                _ = try block_scope.addBreak(.break_inline, decl_inst, align_ref);
            }
            const body = block_scope.instructionsSlice();
            const old_scratch_len = astgen.scratch.items.len;
            try astgen.scratch.ensureUnusedCapacity(gpa, countBodyLenAfterFixups(astgen, body));
            appendBodyWithFixupsArrayList(astgen, &astgen.scratch, body);
            wip_members.appendToField(@intCast(astgen.scratch.items.len - old_scratch_len));
            block_scope.instructions.items.len = block_scope.instructions_top;
        }

        if (member.ast.value_expr.unwrap()) |value_expr| {
            any_default_inits = true;

            // The decl_inst is used as here so that we can easily reconstruct a mapping
            // between it and the field type when the fields inits are analyzed.
            const ri: ResultInfo = .{ .rl = if (field_type == .none) .none else .{ .coerced_ty = decl_inst.toRef() } };

            const default_inst = try expr(&block_scope, &namespace.base, ri, value_expr);
            if (!block_scope.endsWithNoReturn()) {
                _ = try block_scope.addBreak(.break_inline, decl_inst, default_inst);
            }
            const body = block_scope.instructionsSlice();
            const old_scratch_len = astgen.scratch.items.len;
            try astgen.scratch.ensureUnusedCapacity(gpa, countBodyLenAfterFixups(astgen, body));
            appendBodyWithFixupsArrayList(astgen, &astgen.scratch, body);
            wip_members.appendToField(@intCast(astgen.scratch.items.len - old_scratch_len));
            block_scope.instructions.items.len = block_scope.instructions_top;
        } else if (member.comptime_token) |comptime_token| {
            return astgen.failTok(comptime_token, "comptime field without default initialization value", .{});
        }
    }

    var fields_hash: std.zig.SrcHash = undefined;
    astgen.src_hasher.final(&fields_hash);

    try gz.setStruct(decl_inst, .{
        .src_node = node,
        .layout = layout,
        .captures_len = @intCast(namespace.captures.count()),
        .fields_len = field_count,
        .decls_len = decl_count,
        .has_backing_int = backing_int_ref != .none,
        .known_non_opv = known_non_opv,
        .known_comptime_only = known_comptime_only,
        .any_comptime_fields = any_comptime_fields,
        .any_default_inits = any_default_inits,
        .any_aligned_fields = any_aligned_fields,
        .fields_hash = fields_hash,
    });

    wip_members.finishBits(bits_per_field);
    const decls_slice = wip_members.declsSlice();
    const fields_slice = wip_members.fieldsSlice();
    const bodies_slice = astgen.scratch.items[bodies_start..];
    try astgen.extra.ensureUnusedCapacity(gpa, backing_int_body_len + 2 +
        decls_slice.len + namespace.captures.count() * 2 + fields_slice.len + bodies_slice.len);
    astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.keys()));
    astgen.extra.appendSliceAssumeCapacity(@ptrCast(namespace.captures.values()));
    if (backing_int_ref != .none) {
        astgen.extra.appendAssumeCapacity(@intCast(backing_int_body_len));
        if (backing_int_body_len == 0) {
            astgen.extra.appendAssumeCapacity(@intFromEnum(backing_int_ref));
        } else {
            astgen.extra.appendSliceAssumeCapacity(astgen.scratch.items[scratch_top..][0..backing_int_body_len]);
        }
    }
    astgen.extra.appendSliceAssumeCapacity(decls_slice);
    astgen.extra.appendSliceAssumeCapacity(fields_slice);
    astgen.extra.appendSliceAssumeCapacity(bodies_slice);

    block_scope.unstack();
    return decl_inst.toRef();
}

fn tupleDecl(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    container_decl: Ast.full.ContainerDecl,
    layout: std.builtin.Type.ContainerLayout,
    backing_int_node: Ast.Node.OptionalIndex,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;

    switch (layout) {
        .auto => {},
        .@"extern", .@"packed" => return astgen.failNode(node, "{s} tuples are not supported", .{@tagName(layout)}),
    }

    if (backing_int_node.unwrap()) |arg| {
        return astgen.failNode(arg, "tuple does not support backing integer type", .{});
    }

    // We will use the scratch buffer, starting here, for the field data:
    // 1. fields: { // for every `fields_len` (stored in `extended.small`)
    //        type: Inst.Ref,
    //        init: Inst.Ref, // `.none` for non-`comptime` fields
    //    }
    const fields_start = astgen.scratch.items.len;
    defer astgen.scratch.items.len = fields_start;

    try astgen.scratch.ensureUnusedCapacity(gpa, container_decl.ast.members.len * 2);

    for (container_decl.ast.members) |member_node| {
        const field = tree.fullContainerField(member_node) orelse {
            const tuple_member = for (container_decl.ast.members) |maybe_tuple| switch (tree.nodeTag(maybe_tuple)) {
                .container_field_init,
                .container_field_align,
                .container_field,
                => break maybe_tuple,
                else => {},
            } else unreachable;
            return astgen.failNodeNotes(
                member_node,
                "tuple declarations cannot contain declarations",
                .{},
                &.{try astgen.errNoteNode(tuple_member, "tuple field here", .{})},
            );
        };

        if (!field.ast.tuple_like) {
            return astgen.failTok(field.ast.main_token, "tuple field has a name", .{});
        }

        if (field.ast.align_expr != .none) {
            return astgen.failTok(field.ast.main_token, "tuple field has alignment", .{});
        }

        if (field.ast.value_expr != .none and field.comptime_token == null) {
            return astgen.failTok(field.ast.main_token, "non-comptime tuple field has default initialization value", .{});
        }

        if (field.ast.value_expr == .none and field.comptime_token != null) {
            return astgen.failTok(field.comptime_token.?, "comptime field without default initialization value", .{});
        }

        const field_type_ref = try typeExpr(gz, scope, field.ast.type_expr.unwrap().?);
        astgen.scratch.appendAssumeCapacity(@intFromEnum(field_type_ref));

        if (field.ast.value_expr.unwrap()) |value_expr| {
            const field_init_ref = try comptimeExpr(gz, scope, .{ .rl = .{ .coerced_ty = field_type_ref } }, value_expr, .tuple_field_default_value);
            astgen.scratch.appendAssumeCapacity(@intFromEnum(field_init_ref));
        } else {
            astgen.scratch.appendAssumeCapacity(@intFromEnum(Zir.Inst.Ref.none));
        }
    }

    const fields_len = std.math.cast(u16, container_decl.ast.members.len) orelse {
        return astgen.failNode(node, "this compiler implementation only supports 65535 tuple fields", .{});
    };

    const extra_trail = astgen.scratch.items[fields_start..];
    assert(extra_trail.len == fields_len * 2);
    try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.TupleDecl).@"struct".fields.len + extra_trail.len);
    const payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.TupleDecl{
        .src_node = gz.nodeIndexToRelative(node),
    });
    astgen.extra.appendSliceAssumeCapacity(extra_trail);

    return gz.add(.{
        .tag = .extended,
        .data = .{ .extended = .{
            .opcode = .tuple_decl,
            .small = fields_len,
            .operand = payload_index,
        } },
    });
}

fn unionDeclInner(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    members: []const Ast.Node.Index,
    layout: std.builtin.Type.ContainerLayout,
    opt_arg_node: Ast.Node.OptionalIndex,
    auto_enum_tok: ?Ast.TokenIndex,
) InnerError!Zir.Inst.Ref {
    const decl_inst = try gz.reserveInstructionIndex();

    const astgen = gz.astgen;
    const gpa = astgen.gpa;

    var namespace: Scope.Namespace = .{
        .parent = scope,
        .node = node,
        .inst = decl_inst,
        .declaring_gz = gz,
        .maybe_generic = astgen.within_fn,
    };
    defer namespace.deinit(gpa);

    // The union_decl instruction introduces a scope in which the decls of the union
    // are in scope, so that field types, alignments, and default value expressions
    // can refer to decls within the union itself.
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

    const decl_count = try astgen.scanContainer(&namespace, members, .@"union");
    const field_count: u32 = @intCast(members.len - decl_count);

    if (layout != .auto and (auto_enum_tok != null or opt_arg_node != .none)) {
        if (opt_arg_node.unwrap()) |arg_node| {
            return astgen.failNode(arg_node, "{s} union does not support enum tag type", .{@tagName(layout)});
        } else {
            return astgen.failTok(auto_enum_tok.?, "{s} union does not support enum tag type", .{@tagName(layout)});
        }
    }

    const arg_inst: Zir.Inst.Ref = if (opt_arg_node.unwrap()) |arg_node|
        try typeExpr(&block_scope, &namespace.base, arg_node)
    else
        .none;

    const bits_per_field = 4;
    const max_field_size = 4;
    var any_aligned_fields = false;
    var wip_members = try WipMembers.init(gpa, &astgen.scratch, decl_count, field_count, bits_per_field, max_field_size);
    defer wip_members.deinit();

    const old_hasher = astgen.src_hasher;
    defer astgen.src_hasher = old_hasher;
    astgen.src_hasher = std.zig.SrcHasher.init(.{});
    astgen.src_hasher.update(@tagName(layout));
    astgen.src_hasher.update(&.{@intFromBool(auto_enum_tok != null)});
    if (opt_arg_node.unwrap()) |arg_node| {
        astgen.src_hasher.update(astgen.tree.getNodeSource(arg_node));
    }

    for (members) |member_node| {
        var member = switch (try containerMember(&block_scope, &namespace.base, &wip_members, member_node)) {
            .decl => continue,
            .field => |field| field,
        };
        astgen.src_hasher.update(astgen.tree.getNodeSource(member_node));
        member.convertToNonTupleLike(astgen.tree);
        if (member.ast.tuple_like) {
            return astgen.failTok(member.ast.main_token, "union field missing name", .{});
        }
        if (member.comptime_token) |comptime_token| {
            return astgen.failTok(comptime_token, "union fields cannot be marked comptime", .{});
        }

        const field_name = try astgen.identAsString(member.ast.main_token);
        wip_members.appendToField(@intFromEnum(field_name));

        const have_type = member.ast.type_expr != .none;
        const have_align = member.ast.align_expr != .none;
        const have_value = member.ast.value_expr != .none;
        const unused = false;
        wip_members.nextField(bits_per_field, .{ have_type, have_align, have_value, unused });

        if (member.ast.type_expr.unwrap()) |type_expr| {
            const field_type = try typeExpr(&block_scope, &namespace.base, type_expr);
            wip_members.appendToField(@intFromEnum(field_type));
        } else if (arg_inst == .none and auto_enum_tok == null) {
            return astgen.failNode(member_node, "union field missing type", .{});
        }
        if (member.ast.align_expr.unwrap()) |align_expr| {
            const align_inst = try expr(&block_scope, &block_scope.base, coerced_align_ri, align_expr);
            wip_members.appendToField(@intFromEnum(align_inst));
            any_aligned_fields = true;
        }
        if (member.ast.value_expr.unwrap()) |value_expr| {
            if (arg_inst == .none) {
                return astgen.failNodeNotes(
                    node,
                    "explicitly valued tagged union missing integer tag type",
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
            if (auto_enum_tok == null) {
                return astgen.failNodeNotes(
                    node,
                    "explicitly valued tagged union requires inferred enum tag type",
                    .{},
                    &[_]u32{
                        try astgen.errNoteNode(
                            value_expr,
                            "tag value specified here",
                            .{},
 ```
