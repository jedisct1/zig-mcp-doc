```
node: Node.Index) full.For {
    const data = &tree.nodes.items(.data)[@intFromEnum(node)].node_and_node;
    return tree.fullForComponents(.{
        .for_token = tree.nodeMainToken(node),
        .inputs = (&data[0])[0..1],
        .then_expr = data[1],
        .else_expr = .none,
    });
}

pub fn forFull(tree: Ast, node: Node.Index) full.For {
    const extra_index, const extra = tree.nodeData(node).@"for";
    const inputs = tree.extraDataSliceWithLen(extra_index, extra.inputs, Node.Index);
    const then_expr: Node.Index = @enumFromInt(tree.extra_data[@intFromEnum(extra_index) + extra.inputs]);
    const else_expr: Node.OptionalIndex = if (extra.has_else) @enumFromInt(tree.extra_data[@intFromEnum(extra_index) + extra.inputs + 1]) else .none;
    return tree.fullForComponents(.{
        .for_token = tree.nodeMainToken(node),
        .inputs = inputs,
        .then_expr = then_expr,
        .else_expr = else_expr,
    });
}

pub fn callOne(tree: Ast, buffer: *[1]Node.Index, node: Node.Index) full.Call {
    const fn_expr, const first_param = tree.nodeData(node).node_and_opt_node;
    const params = loadOptionalNodesIntoBuffer(1, buffer, .{first_param});
    return tree.fullCallComponents(.{
        .lparen = tree.nodeMainToken(node),
        .fn_expr = fn_expr,
        .params = params,
    });
}

pub fn callFull(tree: Ast, node: Node.Index) full.Call {
    const fn_expr, const extra_index = tree.nodeData(node).node_and_extra;
    const params = tree.extraDataSlice(tree.extraData(extra_index, Node.SubRange), Node.Index);
    return tree.fullCallComponents(.{
        .lparen = tree.nodeMainToken(node),
        .fn_expr = fn_expr,
        .params = params,
    });
}

fn fullVarDeclComponents(tree: Ast, info: full.VarDecl.Components) full.VarDecl {
    var result: full.VarDecl = .{
        .ast = info,
        .visib_token = null,
        .extern_export_token = null,
        .lib_name = null,
        .threadlocal_token = null,
        .comptime_token = null,
    };
    var i = info.mut_token;
    while (i > 0) {
        i -= 1;
        switch (tree.tokenTag(i)) {
            .keyword_extern, .keyword_export => result.extern_export_token = i,
            .keyword_comptime => result.comptime_token = i,
            .keyword_pub => result.visib_token = i,
            .keyword_threadlocal => result.threadlocal_token = i,
            .string_literal => result.lib_name = i,
            else => break,
        }
    }
    return result;
}

fn fullAssignDestructureComponents(tree: Ast, info: full.AssignDestructure.Components) full.AssignDestructure {
    var result: full.AssignDestructure = .{
        .comptime_token = null,
        .ast = info,
    };
    const first_variable_token = tree.firstToken(info.variables[0]);
    const maybe_comptime_token = switch (tree.nodeTag(info.variables[0])) {
        .global_var_decl,
        .local_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => first_variable_token,
        else => first_variable_token - 1,
    };
    if (tree.tokenTag(maybe_comptime_token) == .keyword_comptime) {
        result.comptime_token = maybe_comptime_token;
    }
    return result;
}

fn fullIfComponents(tree: Ast, info: full.If.Components) full.If {
    var result: full.If = .{
        .ast = info,
        .payload_token = null,
        .error_token = null,
        .else_token = undefined,
    };
    // if (cond_expr) |x|
    //              ^ ^
    const payload_pipe = tree.lastToken(info.cond_expr) + 2;
    if (tree.tokenTag(payload_pipe) == .pipe) {
        result.payload_token = payload_pipe + 1;
    }
    if (info.else_expr != .none) {
        // then_expr else |x|
        //           ^    ^
        result.else_token = tree.lastToken(info.then_expr) + 1;
        if (tree.tokenTag(result.else_token + 1) == .pipe) {
            result.error_token = result.else_token + 2;
        }
    }
    return result;
}

fn fullContainerFieldComponents(tree: Ast, info: full.ContainerField.Components) full.ContainerField {
    var result: full.ContainerField = .{
        .ast = info,
        .comptime_token = null,
    };
    if (tree.isTokenPrecededByTags(info.main_token, &.{.keyword_comptime})) {
        // comptime type = init,
        // ^        ^
        // comptime name: type = init,
        // ^        ^
        result.comptime_token = info.main_token - 1;
    }
    return result;
}

fn fullFnProtoComponents(tree: Ast, info: full.FnProto.Components) full.FnProto {
    var result: full.FnProto = .{
        .ast = info,
        .visib_token = null,
        .extern_export_inline_token = null,
        .lib_name = null,
        .name_token = null,
        .lparen = undefined,
    };
    var i = info.fn_token;
    while (i > 0) {
        i -= 1;
        switch (tree.tokenTag(i)) {
            .keyword_extern,
            .keyword_export,
            .keyword_inline,
            .keyword_noinline,
            => result.extern_export_inline_token = i,
            .keyword_pub => result.visib_token = i,
            .string_literal => result.lib_name = i,
            else => break,
        }
    }
    const after_fn_token = info.fn_token + 1;
    if (tree.tokenTag(after_fn_token) == .identifier) {
        result.name_token = after_fn_token;
        result.lparen = after_fn_token + 1;
    } else {
        result.lparen = after_fn_token;
    }
    assert(tree.tokenTag(result.lparen) == .l_paren);

    return result;
}

fn fullPtrTypeComponents(tree: Ast, info: full.PtrType.Components) full.PtrType {
    const size: std.builtin.Type.Pointer.Size = switch (tree.tokenTag(info.main_token)) {
        .asterisk,
        .asterisk_asterisk,
        => .one,
        .l_bracket => switch (tree.tokenTag(info.main_token + 1)) {
            .asterisk => if (tree.tokenTag(info.main_token + 2) == .identifier) .c else .many,
            else => .slice,
        },
        else => unreachable,
    };
    var result: full.PtrType = .{
        .size = size,
        .allowzero_token = null,
        .const_token = null,
        .volatile_token = null,
        .ast = info,
    };
    // We need to be careful that we don't iterate over any sub-expressions
    // here while looking for modifiers as that could result in false
    // positives. Therefore, start after a sentinel if there is one and
    // skip over any align node and bit range nodes.
    var i = if (info.sentinel.unwrap()) |sentinel| tree.lastToken(sentinel) + 1 else switch (size) {
        .many, .c => info.main_token + 1,
        else => info.main_token,
    };
    const end = tree.firstToken(info.child_type);
    while (i < end) : (i += 1) {
        switch (tree.tokenTag(i)) {
            .keyword_allowzero => result.allowzero_token = i,
            .keyword_const => result.const_token = i,
            .keyword_volatile => result.volatile_token = i,
            .keyword_align => {
                const align_node = info.align_node.unwrap().?;
                if (info.bit_range_end.unwrap()) |bit_range_end| {
                    assert(info.bit_range_start != .none);
                    i = tree.lastToken(bit_range_end) + 1;
                } else {
                    i = tree.lastToken(align_node) + 1;
                }
            },
            else => {},
        }
    }
    return result;
}

fn fullContainerDeclComponents(tree: Ast, info: full.ContainerDecl.Components) full.ContainerDecl {
    var result: full.ContainerDecl = .{
        .ast = info,
        .layout_token = null,
    };

    if (info.main_token == 0) return result; // .root
    const previous_token = info.main_token - 1;

    switch (tree.tokenTag(previous_token)) {
        .keyword_extern, .keyword_packed => result.layout_token = previous_token,
        else => {},
    }
    return result;
}

fn fullSwitchComponents(tree: Ast, info: full.Switch.Components) full.Switch {
    const tok_i = info.switch_token -| 1;
    var result: full.Switch = .{
        .ast = info,
        .label_token = null,
    };
    if (tree.tokenTag(tok_i) == .colon and
        tree.tokenTag(tok_i -| 1) == .identifier)
    {
        result.label_token = tok_i - 1;
    }
    return result;
}

fn fullSwitchCaseComponents(tree: Ast, info: full.SwitchCase.Components, node: Node.Index) full.SwitchCase {
    var result: full.SwitchCase = .{
        .ast = info,
        .payload_token = null,
        .inline_token = null,
    };
    if (tree.tokenTag(info.arrow_token + 1) == .pipe) {
        result.payload_token = info.arrow_token + 2;
    }
    result.inline_token = switch (tree.nodeTag(node)) {
        .switch_case_inline, .switch_case_inline_one => if (result.ast.values.len == 0)
            info.arrow_token - 2
        else
            tree.firstToken(result.ast.values[0]) - 1,
        else => null,
    };
    return result;
}

fn fullAsmComponents(tree: Ast, info: full.Asm.Components) full.Asm {
    var result: full.Asm = .{
        .ast = info,
        .volatile_token = null,
        .inputs = &.{},
        .outputs = &.{},
        .first_clobber = null,
    };
    if (tree.tokenTag(info.asm_token + 1) == .keyword_volatile) {
        result.volatile_token = info.asm_token + 1;
    }
    const outputs_end: usize = for (info.items, 0..) |item, i| {
        switch (tree.nodeTag(item)) {
            .asm_output => continue,
            else => break i,
        }
    } else info.items.len;

    result.outputs = info.items[0..outputs_end];
    result.inputs = info.items[outputs_end..];

    if (info.items.len == 0) {
        // asm ("foo" ::: "a", "b");
        const template_token = tree.lastToken(info.template);
        if (tree.tokenTag(template_token + 1) == .colon and
            tree.tokenTag(template_token + 2) == .colon and
            tree.tokenTag(template_token + 3) == .colon and
            tree.tokenTag(template_token + 4) == .string_literal)
        {
            result.first_clobber = template_token + 4;
        }
    } else if (result.inputs.len != 0) {
        // asm ("foo" :: [_] "" (y) : "a", "b");
        const last_input = result.inputs[result.inputs.len - 1];
        const rparen = tree.lastToken(last_input);
        var i = rparen + 1;
        // Allow a (useless) comma right after the closing parenthesis.
        if (tree.tokenTag(i) == .comma) i = i + 1;
        if (tree.tokenTag(i) == .colon and
            tree.tokenTag(i + 1) == .string_literal)
        {
            result.first_clobber = i + 1;
        }
    } else {
        // asm ("foo" : [_] "" (x) :: "a", "b");
        const last_output = result.outputs[result.outputs.len - 1];
        const rparen = tree.lastToken(last_output);
        var i = rparen + 1;
        // Allow a (useless) comma right after the closing parenthesis.
        if (tree.tokenTag(i) == .comma) i = i + 1;
        if (tree.tokenTag(i) == .colon and
            tree.tokenTag(i + 1) == .colon and
            tree.tokenTag(i + 2) == .string_literal)
        {
            result.first_clobber = i + 2;
        }
    }

    return result;
}

fn fullWhileComponents(tree: Ast, info: full.While.Components) full.While {
    var result: full.While = .{
        .ast = info,
        .inline_token = null,
        .label_token = null,
        .payload_token = null,
        .else_token = undefined,
        .error_token = null,
    };
    var tok_i = info.while_token;
    if (tree.isTokenPrecededByTags(tok_i, &.{.keyword_inline})) {
        result.inline_token = tok_i - 1;
        tok_i = tok_i - 1;
    }
    if (tree.isTokenPrecededByTags(tok_i, &.{ .identifier, .colon })) {
        result.label_token = tok_i - 2;
    }
    const last_cond_token = tree.lastToken(info.cond_expr);
    if (tree.tokenTag(last_cond_token + 2) == .pipe) {
        result.payload_token = last_cond_token + 3;
    }
    if (info.else_expr != .none) {
        // then_expr else |x|
        //           ^    ^
        result.else_token = tree.lastToken(info.then_expr) + 1;
        if (tree.tokenTag(result.else_token + 1) == .pipe) {
            result.error_token = result.else_token + 2;
        }
    }
    return result;
}

fn fullForComponents(tree: Ast, info: full.For.Components) full.For {
    var result: full.For = .{
        .ast = info,
        .inline_token = null,
        .label_token = null,
        .payload_token = undefined,
        .else_token = undefined,
    };
    var tok_i = info.for_token;
    if (tree.isTokenPrecededByTags(tok_i, &.{.keyword_inline})) {
        result.inline_token = tok_i - 1;
        tok_i = tok_i - 1;
    }
    if (tree.isTokenPrecededByTags(tok_i, &.{ .identifier, .colon })) {
        result.label_token = tok_i - 2;
    }
    const last_cond_token = tree.lastToken(info.inputs[info.inputs.len - 1]);
    result.payload_token = last_cond_token + @as(u32, 3) + @intFromBool(tree.tokenTag(last_cond_token + 1) == .comma);
    if (info.else_expr != .none) {
        result.else_token = tree.lastToken(info.then_expr) + 1;
    }
    return result;
}

fn fullCallComponents(tree: Ast, info: full.Call.Components) full.Call {
    var result: full.Call = .{
        .ast = info,
        .async_token = null,
    };
    const first_token = tree.firstToken(info.fn_expr);
    if (tree.isTokenPrecededByTags(first_token, &.{.keyword_async})) {
        result.async_token = first_token - 1;
    }
    return result;
}

pub fn fullVarDecl(tree: Ast, node: Node.Index) ?full.VarDecl {
    return switch (tree.nodeTag(node)) {
        .global_var_decl => tree.globalVarDecl(node),
        .local_var_decl => tree.localVarDecl(node),
        .aligned_var_decl => tree.alignedVarDecl(node),
        .simple_var_decl => tree.simpleVarDecl(node),
        else => null,
    };
}

pub fn fullIf(tree: Ast, node: Node.Index) ?full.If {
    return switch (tree.nodeTag(node)) {
        .if_simple => tree.ifSimple(node),
        .@"if" => tree.ifFull(node),
        else => null,
    };
}

pub fn fullWhile(tree: Ast, node: Node.Index) ?full.While {
    return switch (tree.nodeTag(node)) {
        .while_simple => tree.whileSimple(node),
        .while_cont => tree.whileCont(node),
        .@"while" => tree.whileFull(node),
        else => null,
    };
}

pub fn fullFor(tree: Ast, node: Node.Index) ?full.For {
    return switch (tree.nodeTag(node)) {
        .for_simple => tree.forSimple(node),
        .@"for" => tree.forFull(node),
        else => null,
    };
}

pub fn fullContainerField(tree: Ast, node: Node.Index) ?full.ContainerField {
    return switch (tree.nodeTag(node)) {
        .container_field_init => tree.containerFieldInit(node),
        .container_field_align => tree.containerFieldAlign(node),
        .container_field => tree.containerField(node),
        else => null,
    };
}

pub fn fullFnProto(tree: Ast, buffer: *[1]Ast.Node.Index, node: Node.Index) ?full.FnProto {
    return switch (tree.nodeTag(node)) {
        .fn_proto => tree.fnProto(node),
        .fn_proto_multi => tree.fnProtoMulti(node),
        .fn_proto_one => tree.fnProtoOne(buffer, node),
        .fn_proto_simple => tree.fnProtoSimple(buffer, node),
        .fn_decl => tree.fullFnProto(buffer, tree.nodeData(node).node_and_node[0]),
        else => null,
    };
}

pub fn fullStructInit(tree: Ast, buffer: *[2]Ast.Node.Index, node: Node.Index) ?full.StructInit {
    return switch (tree.nodeTag(node)) {
        .struct_init_one, .struct_init_one_comma => tree.structInitOne(buffer[0..1], node),
        .struct_init_dot_two, .struct_init_dot_two_comma => tree.structInitDotTwo(buffer, node),
        .struct_init_dot, .struct_init_dot_comma => tree.structInitDot(node),
        .struct_init, .struct_init_comma => tree.structInit(node),
        else => null,
    };
}

pub fn fullArrayInit(tree: Ast, buffer: *[2]Node.Index, node: Node.Index) ?full.ArrayInit {
    return switch (tree.nodeTag(node)) {
        .array_init_one, .array_init_one_comma => tree.arrayInitOne(buffer[0..1], node),
        .array_init_dot_two, .array_init_dot_two_comma => tree.arrayInitDotTwo(buffer, node),
        .array_init_dot, .array_init_dot_comma => tree.arrayInitDot(node),
        .array_init, .array_init_comma => tree.arrayInit(node),
        else => null,
    };
}

pub fn fullArrayType(tree: Ast, node: Node.Index) ?full.ArrayType {
    return switch (tree.nodeTag(node)) {
        .array_type => tree.arrayType(node),
        .array_type_sentinel => tree.arrayTypeSentinel(node),
        else => null,
    };
}

pub fn fullPtrType(tree: Ast, node: Node.Index) ?full.PtrType {
    return switch (tree.nodeTag(node)) {
        .ptr_type_aligned => tree.ptrTypeAligned(node),
        .ptr_type_sentinel => tree.ptrTypeSentinel(node),
        .ptr_type => tree.ptrType(node),
        .ptr_type_bit_range => tree.ptrTypeBitRange(node),
        else => null,
    };
}

pub fn fullSlice(tree: Ast, node: Node.Index) ?full.Slice {
    return switch (tree.nodeTag(node)) {
        .slice_open => tree.sliceOpen(node),
        .slice => tree.slice(node),
        .slice_sentinel => tree.sliceSentinel(node),
        else => null,
    };
}

pub fn fullContainerDecl(tree: Ast, buffer: *[2]Ast.Node.Index, node: Node.Index) ?full.ContainerDecl {
    return switch (tree.nodeTag(node)) {
        .root => tree.containerDeclRoot(),
        .container_decl, .container_decl_trailing => tree.containerDecl(node),
        .container_decl_arg, .container_decl_arg_trailing => tree.containerDeclArg(node),
        .container_decl_two, .container_decl_two_trailing => tree.containerDeclTwo(buffer, node),
        .tagged_union, .tagged_union_trailing => tree.taggedUnion(node),
        .tagged_union_enum_tag, .tagged_union_enum_tag_trailing => tree.taggedUnionEnumTag(node),
        .tagged_union_two, .tagged_union_two_trailing => tree.taggedUnionTwo(buffer, node),
        else => null,
    };
}

pub fn fullSwitch(tree: Ast, node: Node.Index) ?full.Switch {
    return switch (tree.nodeTag(node)) {
        .@"switch", .switch_comma => tree.switchFull(node),
        else => null,
    };
}

pub fn fullSwitchCase(tree: Ast, node: Node.Index) ?full.SwitchCase {
    return switch (tree.nodeTag(node)) {
        .switch_case_one, .switch_case_inline_one => tree.switchCaseOne(node),
        .switch_case, .switch_case_inline => tree.switchCase(node),
        else => null,
    };
}

pub fn fullAsm(tree: Ast, node: Node.Index) ?full.Asm {
    return switch (tree.nodeTag(node)) {
        .asm_simple => tree.asmSimple(node),
        .@"asm" => tree.asmFull(node),
        else => null,
    };
}

pub fn fullCall(tree: Ast, buffer: *[1]Ast.Node.Index, node: Node.Index) ?full.Call {
    return switch (tree.nodeTag(node)) {
        .call, .call_comma, .async_call, .async_call_comma => tree.callFull(node),
        .call_one, .call_one_comma, .async_call_one, .async_call_one_comma => tree.callOne(buffer, node),
        else => null,
    };
}

pub fn builtinCallParams(tree: Ast, buffer: *[2]Ast.Node.Index, node: Ast.Node.Index) ?[]const Node.Index {
    return switch (tree.nodeTag(node)) {
        .builtin_call_two, .builtin_call_two_comma => loadOptionalNodesIntoBuffer(2, buffer, tree.nodeData(node).opt_node_and_opt_node),
        .builtin_call, .builtin_call_comma => tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index),
        else => null,
    };
}

pub fn blockStatements(tree: Ast, buffer: *[2]Ast.Node.Index, node: Ast.Node.Index) ?[]const Node.Index {
    return switch (tree.nodeTag(node)) {
        .block_two, .block_two_semicolon => loadOptionalNodesIntoBuffer(2, buffer, tree.nodeData(node).opt_node_and_opt_node),
        .block, .block_semicolon => tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index),
        else => null,
    };
}

/// Fully assembled AST node information.
pub const full = struct {
    pub const VarDecl = struct {
        visib_token: ?TokenIndex,
        extern_export_token: ?TokenIndex,
        lib_name: ?TokenIndex,
        threadlocal_token: ?TokenIndex,
        comptime_token: ?TokenIndex,
        ast: Components,

        pub const Components = struct {
            mut_token: TokenIndex,
            type_node: Node.OptionalIndex,
            align_node: Node.OptionalIndex,
            addrspace_node: Node.OptionalIndex,
            section_node: Node.OptionalIndex,
            init_node: Node.OptionalIndex,
        };

        pub fn firstToken(var_decl: VarDecl) TokenIndex {
            return var_decl.visib_token orelse
                var_decl.extern_export_token orelse
                var_decl.threadlocal_token orelse
                var_decl.comptime_token orelse
                var_decl.ast.mut_token;
        }
    };

    pub const AssignDestructure = struct {
        comptime_token: ?TokenIndex,
        ast: Components,

        pub const Components = struct {
            variables: []const Node.Index,
            equal_token: TokenIndex,
            value_expr: Node.Index,
        };
    };

    pub const If = struct {
        /// Points to the first token after the `|`. Will either be an identifier or
        /// a `*` (with an identifier immediately after it).
        payload_token: ?TokenIndex,
        /// Points to the identifier after the `|`.
        error_token: ?TokenIndex,
        /// Populated only if else_expr != .none.
        else_token: TokenIndex,
        ast: Components,

        pub const Components = struct {
            if_token: TokenIndex,
            cond_expr: Node.Index,
            then_expr: Node.Index,
            else_expr: Node.OptionalIndex,
        };
    };

    pub const While = struct {
        ast: Components,
        inline_token: ?TokenIndex,
        label_token: ?TokenIndex,
        payload_token: ?TokenIndex,
        error_token: ?TokenIndex,
        /// Populated only if else_expr != none.
        else_token: TokenIndex,

        pub const Components = struct {
            while_token: TokenIndex,
            cond_expr: Node.Index,
            cont_expr: Node.OptionalIndex,
            then_expr: Node.Index,
            else_expr: Node.OptionalIndex,
        };
    };

    pub const For = struct {
        ast: Components,
        inline_token: ?TokenIndex,
        label_token: ?TokenIndex,
        payload_token: TokenIndex,
        /// Populated only if else_expr != .none.
        else_token: ?TokenIndex,

        pub const Components = struct {
            for_token: TokenIndex,
            inputs: []const Node.Index,
            then_expr: Node.Index,
            else_expr: Node.OptionalIndex,
        };
    };

    pub const ContainerField = struct {
        comptime_token: ?TokenIndex,
        ast: Components,

        pub const Components = struct {
            main_token: TokenIndex,
            /// Can only be `.none` after calling `convertToNonTupleLike`.
            type_expr: Node.OptionalIndex,
            align_expr: Node.OptionalIndex,
            value_expr: Node.OptionalIndex,
            tuple_like: bool,
        };

        pub fn firstToken(cf: ContainerField) TokenIndex {
            return cf.comptime_token orelse cf.ast.main_token;
        }

        pub fn convertToNonTupleLike(cf: *ContainerField, tree: *const Ast) void {
            if (!cf.ast.tuple_like) return;
            if (tree.nodeTag(cf.ast.type_expr.unwrap().?) != .identifier) return;

            cf.ast.type_expr = .none;
            cf.ast.tuple_like = false;
        }
    };

    pub const FnProto = struct {
        visib_token: ?TokenIndex,
        extern_export_inline_token: ?TokenIndex,
        lib_name: ?TokenIndex,
        name_token: ?TokenIndex,
        lparen: TokenIndex,
        ast: Components,

        pub const Components = struct {
            proto_node: Node.Index,
            fn_token: TokenIndex,
            return_type: Node.OptionalIndex,
            params: []const Node.Index,
            align_expr: Node.OptionalIndex,
            addrspace_expr: Node.OptionalIndex,
            section_expr: Node.OptionalIndex,
            callconv_expr: Node.OptionalIndex,
        };

        pub const Param = struct {
            first_doc_comment: ?TokenIndex,
            name_token: ?TokenIndex,
            comptime_noalias: ?TokenIndex,
            anytype_ellipsis3: ?TokenIndex,
            type_expr: ?Node.Index,
        };

        pub fn firstToken(fn_proto: FnProto) TokenIndex {
            return fn_proto.visib_token orelse
                fn_proto.extern_export_inline_token orelse
                fn_proto.ast.fn_token;
        }

        /// Abstracts over the fact that anytype and ... are not included
        /// in the params slice, since they are simple identifiers and
        /// not sub-expressions.
        pub const Iterator = struct {
            tree: *const Ast,
            fn_proto: *const FnProto,
            param_i: usize,
            tok_i: TokenIndex,
            tok_flag: bool,

            pub fn next(it: *Iterator) ?Param {
                const tree = it.tree;
                while (true) {
                    var first_doc_comment: ?TokenIndex = null;
                    var comptime_noalias: ?TokenIndex = null;
                    var name_token: ?TokenIndex = null;
                    if (!it.tok_flag) {
                        if (it.param_i >= it.fn_proto.ast.params.len) {
                            return null;
                        }
                        const param_type = it.fn_proto.ast.params[it.param_i];
                        var tok_i = tree.firstToken(param_type) - 1;
                        while (true) : (tok_i -= 1) switch (tree.tokenTag(tok_i)) {
                            .colon => continue,
                            .identifier => name_token = tok_i,
                            .doc_comment => first_doc_comment = tok_i,
                            .keyword_comptime, .keyword_noalias => comptime_noalias = tok_i,
                            else => break,
                        };
                        it.param_i += 1;
                        it.tok_i = tree.lastToken(param_type) + 1;
                        // Look for anytype and ... params afterwards.
                        if (tree.tokenTag(it.tok_i) == .comma) {
                            it.tok_i += 1;
                        }
                        it.tok_flag = true;
                        return Param{
                            .first_doc_comment = first_doc_comment,
                            .comptime_noalias = comptime_noalias,
                            .name_token = name_token,
                            .anytype_ellipsis3 = null,
                            .type_expr = param_type,
                        };
                    }
                    if (tree.tokenTag(it.tok_i) == .comma) {
                        it.tok_i += 1;
                    }
                    if (tree.tokenTag(it.tok_i) == .r_paren) {
                        return null;
                    }
                    if (tree.tokenTag(it.tok_i) == .doc_comment) {
                        first_doc_comment = it.tok_i;
                        while (tree.tokenTag(it.tok_i) == .doc_comment) {
                            it.tok_i += 1;
                        }
                    }
                    switch (tree.tokenTag(it.tok_i)) {
                        .ellipsis3 => {
                            it.tok_flag = false; // Next iteration should return null.
                            return Param{
                                .first_doc_comment = first_doc_comment,
                                .comptime_noalias = null,
                                .name_token = null,
                                .anytype_ellipsis3 = it.tok_i,
                                .type_expr = null,
                            };
                        },
                        .keyword_noalias, .keyword_comptime => {
                            comptime_noalias = it.tok_i;
                            it.tok_i += 1;
                        },
                        else => {},
                    }
                    if (tree.tokenTag(it.tok_i) == .identifier and
                        tree.tokenTag(it.tok_i + 1) == .colon)
                    {
                        name_token = it.tok_i;
                        it.tok_i += 2;
                    }
                    if (tree.tokenTag(it.tok_i) == .keyword_anytype) {
                        it.tok_i += 1;
                        return Param{
                            .first_doc_comment = first_doc_comment,
                            .comptime_noalias = comptime_noalias,
                            .name_token = name_token,
                            .anytype_ellipsis3 = it.tok_i - 1,
                            .type_expr = null,
                        };
                    }
                    it.tok_flag = false;
                }
            }
        };

        pub fn iterate(fn_proto: *const FnProto, tree: *const Ast) Iterator {
            return .{
                .tree = tree,
                .fn_proto = fn_proto,
                .param_i = 0,
                .tok_i = fn_proto.lparen + 1,
                .tok_flag = true,
            };
        }
    };

    pub const StructInit = struct {
        ast: Components,

        pub const Components = struct {
            lbrace: TokenIndex,
            fields: []const Node.Index,
            type_expr: Node.OptionalIndex,
        };
    };

    pub const ArrayInit = struct {
        ast: Components,

        pub const Components = struct {
            lbrace: TokenIndex,
            elements: []const Node.Index,
            type_expr: Node.OptionalIndex,
        };
    };

    pub const ArrayType = struct {
        ast: Components,

        pub const Components = struct {
            lbracket: TokenIndex,
            elem_count: Node.Index,
            sentinel: Node.OptionalIndex,
            elem_type: Node.Index,
        };
    };

    pub const PtrType = struct {
        size: std.builtin.Type.Pointer.Size,
        allowzero_token: ?TokenIndex,
        const_token: ?TokenIndex,
        volatile_token: ?TokenIndex,
        ast: Components,

        pub const Components = struct {
            main_token: TokenIndex,
            align_node: Node.OptionalIndex,
            addrspace_node: Node.OptionalIndex,
            sentinel: Node.OptionalIndex,
            bit_range_start: Node.OptionalIndex,
            bit_range_end: Node.OptionalIndex,
            child_type: Node.Index,
        };
    };

    pub const Slice = struct {
        ast: Components,

        pub const Components = struct {
            sliced: Node.Index,
            lbracket: TokenIndex,
            start: Node.Index,
            end: Node.OptionalIndex,
            sentinel: Node.OptionalIndex,
        };
    };

    pub const ContainerDecl = struct {
        layout_token: ?TokenIndex,
        ast: Components,

        pub const Components = struct {
            main_token: TokenIndex,
            /// Populated when main_token is Keyword_union.
            enum_token: ?TokenIndex,
            members: []const Node.Index,
            arg: Node.OptionalIndex,
        };
    };

    pub const Switch = struct {
        ast: Components,
        label_token: ?TokenIndex,

        pub const Components = struct {
            switch_token: TokenIndex,
            condition: Node.Index,
            cases: []const Node.Index,
        };
    };

    pub const SwitchCase = struct {
        inline_token: ?TokenIndex,
        /// Points to the first token after the `|`. Will either be an identifier or
        /// a `*` (with an identifier immediately after it).
        payload_token: ?TokenIndex,
        ast: Components,

        pub const Components = struct {
            /// If empty, this is an else case
            values: []const Node.Index,
            arrow_token: TokenIndex,
            target_expr: Node.Index,
        };
    };

    pub const Asm = struct {
        ast: Components,
        volatile_token: ?TokenIndex,
        first_clobber: ?TokenIndex,
        outputs: []const Node.Index,
        inputs: []const Node.Index,

        pub const Components = struct {
            asm_token: TokenIndex,
            template: Node.Index,
            items: []const Node.Index,
            rparen: TokenIndex,
        };
    };

    pub const Call = struct {
        ast: Components,
        async_token: ?TokenIndex,

        pub const Components = struct {
            lparen: TokenIndex,
            fn_expr: Node.Index,
            params: []const Node.Index,
        };
    };
};

pub const Error = struct {
    tag: Tag,
    is_note: bool = false,
    /// True if `token` points to the token before the token causing an issue.
    token_is_prev: bool = false,
    token: TokenIndex,
    extra: union {
        none: void,
        expected_tag: Token.Tag,
        offset: usize,
    } = .{ .none = {} },

    pub const Tag = enum {
        asterisk_after_ptr_deref,
        chained_comparison_operators,
        decl_between_fields,
        expected_block,
        expected_block_or_assignment,
        expected_block_or_expr,
        expected_block_or_field,
        expected_container_members,
        expected_expr,
        expected_expr_or_assignment,
        expected_expr_or_var_decl,
        expected_fn,
        expected_inlinable,
        expected_labelable,
        expected_param_list,
        expected_prefix_expr,
        expected_primary_type_expr,
        expected_pub_item,
        expected_return_type,
        expected_semi_or_else,
        expected_semi_or_lbrace,
        expected_statement,
        expected_suffix_op,
        expected_type_expr,
        expected_var_decl,
        expected_var_decl_or_fn,
        expected_loop_payload,
        expected_container,
        extern_fn_body,
        extra_addrspace_qualifier,
        extra_align_qualifier,
        extra_allowzero_qualifier,
        extra_const_qualifier,
        extra_volatile_qualifier,
        ptr_mod_on_array_child_type,
        invalid_bit_range,
        same_line_doc_comment,
        unattached_doc_comment,
        test_doc_comment,
        comptime_doc_comment,
        varargs_nonfinal,
        expected_continue_expr,
        expected_semi_after_decl,
        expected_semi_after_stmt,
        expected_comma_after_field,
        expected_comma_after_arg,
        expected_comma_after_param,
        expected_comma_after_initializer,
        expected_comma_after_switch_prong,
        expected_comma_after_for_operand,
        expected_comma_after_capture,
        expected_initializer,
        mismatched_binary_op_whitespace,
        invalid_ampersand_ampersand,
        c_style_container,
        expected_var_const,
        wrong_equal_var_decl,
        var_const_decl,
        extra_for_capture,
        for_input_not_captured,

        zig_style_container,
        previous_field,
        next_field,

        /// `expected_tag` is populated.
        expected_token,

        /// `offset` is populated
        invalid_byte,
    };
};

/// Index into `extra_data`.
pub const ExtraIndex = enum(u32) {
    _,
};

pub const Node = struct {
    tag: Tag,
    main_token: TokenIndex,
    data: Data,

    /// Index into `nodes`.
    pub const Index = enum(u32) {
        root = 0,
        _,

        pub fn toOptional(i: Index) OptionalIndex {
            const result: OptionalIndex = @enumFromInt(@intFromEnum(i));
            assert(result != .none);
            return result;
        }

        pub fn toOffset(base: Index, destination: Index) Offset {
            const base_i64: i64 = @intFromEnum(base);
            const destination_i64: i64 = @intFromEnum(destination);
            return @enumFromInt(destination_i64 - base_i64);
        }
    };

    /// Index into `nodes`, or null.
    pub const OptionalIndex = enum(u32) {
        root = 0,
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(oi: OptionalIndex) ?Index {
            return if (oi == .none) null else @enumFromInt(@intFromEnum(oi));
        }

        pub fn fromOptional(oi: ?Index) OptionalIndex {
            return if (oi) |i| i.toOptional() else .none;
        }
    };

    /// A relative node index.
    pub const Offset = enum(i32) {
        zero = 0,
        _,

        pub fn toOptional(o: Offset) OptionalOffset {
            const result: OptionalOffset = @enumFromInt(@intFromEnum(o));
            assert(result != .none);
            return result;
        }

        pub fn toAbsolute(offset: Offset, base: Index) Index {
            return @enumFromInt(@as(i64, @intFromEnum(base)) + @intFromEnum(offset));
        }
    };

    /// A relative node index, or null.
    pub const OptionalOffset = enum(i32) {
        none = std.math.maxInt(i32),
        _,

        pub fn unwrap(oo: OptionalOffset) ?Offset {
            return if (oo == .none) null else @enumFromInt(@intFromEnum(oo));
        }
    };

    comptime {
        // Goal is to keep this under one byte for efficiency.
        assert(@sizeOf(Tag) == 1);

        if (!std.debug.runtime_safety) {
            assert(@sizeOf(Data) == 8);
        }
    }

    /// The FooComma/FooSemicolon variants exist to ease the implementation of
    /// `Ast.lastToken()`
    pub const Tag = enum {
        /// The root node which is guaranteed to be at `Node.Index.root`.
        /// The meaning of the `data` field depends on whether it is a `.zig` or
        /// `.zon` file.
        ///
        /// The `main_token` field is the first token for the source file.
        root,
        /// `usingnamespace expr;`.
        ///
        /// The `data` field is a `.node` to expr.
        ///
        /// The `main_token` field is the `usingnamespace` token.
        @"usingnamespace",
        /// `test {}`,
        /// `test "name" {}`,
        /// `test identifier {}`.
        ///
        /// The `data` field is a `.opt_token_and_node`:
        ///   1. a `OptionalTokenIndex` to the test name token (must be string literal or identifier), if any.
        ///   2. a `Node.Index` to the block.
        ///
        /// The `main_token` field is the `test` token.
        test_decl,
        /// The `data` field is a `.extra_and_opt_node`:
        ///   1. a `ExtraIndex` to `GlobalVarDecl`.
        ///   2. a `Node.OptionalIndex` to the initialization expression.
        ///
        /// The `main_token` field is the `var` or `const` token.
        ///
        /// The initialization expression can't be `.none` unless it is part of
        /// a `assign_destructure` node or a parsing error occured.
        global_var_decl,
        /// `var a: b align(c) = d`.
        /// `const main_token: type_node align(align_node) = init_expr`.
        ///
        /// The `data` field is a `.extra_and_opt_node`:
        ///   1. a `ExtraIndex` to `LocalVarDecl`.
        ///   2. a `Node.OptionalIndex` to the initialization expression-
        ///
        /// The `main_token` field is the `var` or `const` token.
        ///
        /// The initialization expression can't be `.none` unless it is part of
        /// a `assign_destructure` node or a parsing error occured.
        local_var_decl,
        /// `var a: b = c`.
        /// `const name_token: type_expr = init_expr`.
        /// Can be local or global.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the type expression, if any.
        ///   2. a `Node.OptionalIndex` to the initialization expression.
        ///
        /// The `main_token` field is the `var` or `const` token.
        ///
        /// The initialization expression can't be `.none` unless it is part of
        /// a `assign_destructure` node or a parsing error occured.
        simple_var_decl,
        /// `var a align(b) = c`.
        /// `const name_token align(align_expr) = init_expr`.
        /// Can be local or global.
        ///
        /// The `data` field is a `.node_and_opt_node`:
        ///   1. a `Node.Index` to the alignment expression.
        ///   2. a `Node.OptionalIndex` to the initialization expression.
        ///
        /// The `main_token` field is the `var` or `const` token.
        ///
        /// The initialization expression can't be `.none` unless it is part of
        /// a `assign_destructure` node or a parsing error occured.
        aligned_var_decl,
        /// `errdefer expr`,
        /// `errdefer |payload| expr`.
        ///
        /// The `data` field is a `.opt_token_and_node`:
        ///   1. a `OptionalTokenIndex` to the payload identifier, if any.
        ///   2. a `Node.Index` to the deferred expression.
        ///
        /// The `main_token` field is the `errdefer` token.
        @"errdefer",
        /// `defer expr`.
        ///
        /// The `data` field is a `.node` to the deferred expression.
        ///
        /// The `main_token` field is the `defer`.
        @"defer",
        /// `lhs catch rhs`,
        /// `lhs catch |err| rhs`.
        ///
        /// The `main_token` field is the `catch` token.
        ///
        /// The error payload is determined by looking at the next token after
        /// the `catch` token.
        @"catch",
        /// `lhs.a`.
        ///
        /// The `data` field is a `.node_and_token`:
        ///   1. a `Node.Index` to the left side of the field access.
        ///   2. a `TokenIndex` to the field name identifier.
        ///
        /// The `main_token` field is the `.` token.
        field_access,
        /// `lhs.?`.
        ///
        /// The `data` field is a `.node_and_token`:
        ///   1. a `Node.Index` to the left side of the optional unwrap.
        ///   2. a `TokenIndex` to the `?` token.
        ///
        /// The `main_token` field is the `.` token.
        unwrap_optional,
        /// `lhs == rhs`. The `main_token` field is the `==` token.
        equal_equal,
        /// `lhs != rhs`. The `main_token` field is the `!=` token.
        bang_equal,
        /// `lhs < rhs`. The `main_token` field is the `<` token.
        less_than,
        /// `lhs > rhs`. The `main_token` field is the `>` token.
        greater_than,
        /// `lhs <= rhs`. The `main_token` field is the `<=` token.
        less_or_equal,
        /// `lhs >= rhs`. The `main_token` field is the `>=` token.
        greater_or_equal,
        /// `lhs *= rhs`. The `main_token` field is the `*=` token.
        assign_mul,
        /// `lhs /= rhs`. The `main_token` field is the `/=` token.
        assign_div,
        /// `lhs %= rhs`. The `main_token` field is the `%=` token.
        assign_mod,
        /// `lhs += rhs`. The `main_token` field is the `+=` token.
        assign_add,
        /// `lhs -= rhs`. The `main_token` field is the `-=` token.
        assign_sub,
        /// `lhs <<= rhs`. The `main_token` field is the `<<=` token.
        assign_shl,
        /// `lhs <<|= rhs`. The `main_token` field is the `<<|=` token.
        assign_shl_sat,
        /// `lhs >>= rhs`. The `main_token` field is the `>>=` token.
        assign_shr,
        /// `lhs &= rhs`. The `main_token` field is the `&=` token.
        assign_bit_and,
        /// `lhs ^= rhs`. The `main_token` field is the `^=` token.
        assign_bit_xor,
        /// `lhs |= rhs`. The `main_token` field is the `|=` token.
        assign_bit_or,
        /// `lhs *%= rhs`. The `main_token` field is the `*%=` token.
        assign_mul_wrap,
        /// `lhs +%= rhs`. The `main_token` field is the `+%=` token.
        assign_add_wrap,
        /// `lhs -%= rhs`. The `main_token` field is the `-%=` token.
        assign_sub_wrap,
        /// `lhs *|= rhs`. The `main_token` field is the `*%=` token.
        assign_mul_sat,
        /// `lhs +|= rhs`. The `main_token` field is the `+|=` token.
        assign_add_sat,
        /// `lhs -|= rhs`. The `main_token` field is the `-|=` token.
        assign_sub_sat,
        /// `lhs = rhs`. The `main_token` field is the `=` token.
        assign,
        /// `a, b, ... = rhs`.
        ///
        /// The `data` field is a `.extra_and_node`:
        ///   1. a `ExtraIndex`. Further explained below.
        ///   2. a `Node.Index` to the initialization expression.
        ///
        /// The `main_token` field is the `=` token.
        ///
        /// The `ExtraIndex` stores the following data:
        /// ```
        /// elem_count: u32,
        /// variables: [elem_count]Node.Index,
        /// ```
        ///
        /// Each node in `variables` has one of the following tags:
        ///   - `global_var_decl`
        ///   - `local_var_decl`
        ///   - `simple_var_decl`
        ///   - `aligned_var_decl`
        ///   - Any expression node
        ///
        /// The first 4 tags correspond to a `var` or `const` lhs node (note
        /// that their initialization expression is always `.none`).
        /// An expression node corresponds to a standard assignment LHS (which
        /// must be evaluated as an lvalue). There may be a preceding
        /// `comptime` token, which does not create a corresponding `comptime`
        /// node so must be manually detected.
        assign_destructure,
        /// `lhs || rhs`. The `main_token` field is the `||` token.
        merge_error_sets,
        /// `lhs * rhs`. The `main_token` field is the `*` token.
        mul,
        /// `lhs / rhs`. The `main_token` field is the `/` token.
        div,
        /// `lhs % rhs`. The `main_token` field is the `%` token.
        mod,
        /// `lhs ** rhs`. The `main_token` field is the `**` token.
        array_mult,
        /// `lhs *% rhs`. The `main_token` field is the `*%` token.
        mul_wrap,
        /// `lhs *| rhs`. The `main_token` field is the `*|` token.
        mul_sat,
        /// `lhs + rhs`. The `main_token` field is the `+` token.
        add,
        /// `lhs - rhs`. The `main_token` field is the `-` token.
        sub,
        /// `lhs ++ rhs`. The `main_token` field is the `++` token.
        array_cat,
        /// `lhs +% rhs`. The `main_token` field is the `+%` token.
        add_wrap,
        /// `lhs -% rhs`. The `main_token` field is the `-%` token.
        sub_wrap,
        /// `lhs +| rhs`. The `main_token` field is the `+|` token.
        add_sat,
        /// `lhs -| rhs`. The `main_token` field is the `-|` token.
        sub_sat,
        /// `lhs << rhs`. The `main_token` field is the `<<` token.
        shl,
        /// `lhs <<| rhs`. The `main_token` field is the `<<|` token.
        shl_sat,
        /// `lhs >> rhs`. The `main_token` field is the `>>` token.
        shr,
        /// `lhs & rhs`. The `main_token` field is the `&` token.
        bit_and,
        /// `lhs ^ rhs`. The `main_token` field is the `^` token.
        bit_xor,
        /// `lhs | rhs`. The `main_token` field is the `|` token.
        bit_or,
        /// `lhs orelse rhs`. The `main_token` field is the `orelse` token.
        @"orelse",
        /// `lhs and rhs`. The `main_token` field is the `and` token.
        bool_and,
        /// `lhs or rhs`. The `main_token` field is the `or` token.
        bool_or,
        /// `!expr`. The `main_token` field is the `!` token.
        bool_not,
        /// `-expr`. The `main_token` field is the `-` token.
        negation,
        /// `~expr`. The `main_token` field is the `~` token.
        bit_not,
        /// `-%expr`. The `main_token` field is the `-%` token.
        negation_wrap,
        /// `&expr`. The `main_token` field is the `&` token.
        address_of,
        /// `try expr`. The `main_token` field is the `try` token.
        @"try",
        /// `await expr`. The `main_token` field is the `await` token.
        @"await",
        /// `?expr`. The `main_token` field is the `?` token.
        optional_type,
        /// `[lhs]rhs`. The `main_token` field is the `[` token.
        array_type,
        /// `[lhs:a]b`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the length expression.
        ///   2. a `ExtraIndex` to `ArrayTypeSentinel`.
        ///
        /// The `main_token` field is the `[` token.
        array_type_sentinel,
        /// `[*]align(lhs) rhs`,
        /// `*align(lhs) rhs`,
        /// `[]rhs`.
        ///
        /// The `data` field is a `.opt_node_and_node`:
        ///   1. a `Node.OptionalIndex` to the alignment expression, if any.
        ///   2. a `Node.Index` to the element type expression.
        ///
        /// The `main_token` is the asterisk if a single item pointer or the
        /// lbracket if a slice, many-item pointer, or C-pointer.
        /// The `main_token` might be a ** token, which is shared with a
        /// parent/child pointer type and may require special handling.
        ptr_type_aligned,
        /// `[*:lhs]rhs`,
        /// `*rhs`,
        /// `[:lhs]rhs`.
        ///
        /// The `data` field is a `.opt_node_and_node`:
        ///   1. a `Node.OptionalIndex` to the sentinel expression, if any.
        ///   2. a `Node.Index` to the element type expression.
        ///
        /// The `main_token` is the asterisk if a single item pointer or the
        /// lbracket if a slice, many-item pointer, or C-pointer.
        /// The `main_token` might be a ** token, which is shared with a
        /// parent/child pointer type and may require special handling.
        ptr_type_sentinel,
        /// The `data` field is a `.opt_node_and_node`:
        ///   1. a `ExtraIndex` to `PtrType`.
        ///   2. a `Node.Index` to the element type expression.
        ///
        /// The `main_token` is the asterisk if a single item pointer or the
        /// lbracket if a slice, many-item pointer, or C-pointer.
        /// The `main_token` might be a ** token, which is shared with a
        /// parent/child pointer type and may require special handling.
        ptr_type,
        /// The `data` field is a `.opt_node_and_node`:
        ///   1. a `ExtraIndex` to `PtrTypeBitRange`.
        ///   2. a `Node.Index` to the element type expression.
        ///
        /// The `main_token` is the asterisk if a single item pointer or the
        /// lbracket if a slice, many-item pointer, or C-pointer.
        /// The `main_token` might be a ** token, which is shared with a
        /// parent/child pointer type and may require special handling.
        ptr_type_bit_range,
        /// `lhs[rhs..]`
        ///
        /// The `main_token` field is the `[` token.
        slice_open,
        /// `sliced[start..end]`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the sliced expression.
        ///   2. a `ExtraIndex` to `Slice`.
        ///
        /// The `main_token` field is the `[` token.
        slice,
        /// `sliced[start..end :sentinel]`,
        /// `sliced[start.. :sentinel]`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the sliced expression.
        ///   2. a `ExtraIndex` to `SliceSentinel`.
        ///
        /// The `main_token` field is the `[` token.
        slice_sentinel,
        /// `expr.*`.
        ///
        /// The `data` field is a `.node` to expr.
        ///
        /// The `main_token` field is the `*` token.
        deref,
        /// `lhs[rhs]`.
        ///
        /// The `main_token` field is the `[` token.
        array_access,
        /// `lhs{rhs}`.
        ///
        /// The `main_token` field is the `{` token.
        array_init_one,
        /// Same as `array_init_one` except there is known to be a trailing
        /// comma before the final rbrace.
        array_init_one_comma,
        /// `.{a}`,
        /// `.{a, b}`.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the first element. Never `.none`
        ///   2. a `Node.OptionalIndex` to the second element, if any.
        ///
        /// The `main_token` field is the `{` token.
        array_init_dot_two,
        /// Same as `array_init_dot_two` except there is known to be a trailing
        /// comma before the final rbrace.
        array_init_dot_two_comma,
        /// `.{a, b, c}`.
        ///
        /// The `data` field is a `.extra_range` that stores a `Node.Index` for
        /// each element.
        ///
        /// The `main_token` field is the `{` token.
        array_init_dot,
        /// Same as `array_init_dot` except there is known to be a trailing
        /// comma before the final rbrace.
        array_init_dot_comma,
        /// `a{b, c}`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the type expression.
        ///   2. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each element.
        ///
        /// The `main_token` field is the `{` token.
        array_init,
        /// Same as `array_init` except there is known to be a trailing comma
        /// before the final rbrace.
        array_init_comma,
        /// `a{.x = b}`, `a{}`.
        ///
        /// The `data` field is a `.node_and_opt_node`:
        ///   1. a `Node.Index` to the type expression.
        ///   2. a `Node.OptionalIndex` to the first field initialization, if any.
        ///
        /// The `main_token` field is the `{` token.
        ///
        /// The field name is determined by looking at the tokens preceding the
        /// field initialization.
        struct_init_one,
        /// Same as `struct_init_one` except there is known to be a trailing comma
        /// before the final rbrace.
        struct_init_one_comma,
        /// `.{.x = a, .y = b}`.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the first field initialization. Never `.none`
        ///   2. a `Node.OptionalIndex` to the second field initialization, if any.
        ///
        /// The `main_token` field is the '{' token.
        ///
        /// The field name is determined by looking at the tokens preceding the
        /// field initialization.
        struct_init_dot_two,
        /// Same as `struct_init_dot_two` except there is known to be a trailing
        /// comma before the final rbrace.
        struct_init_dot_two_comma,
        /// `.{.x = a, .y = b, .z = c}`.
        ///
        /// The `data` field is a `.extra_range` that stores a `Node.Index` for
        /// each field initialization.
        ///
        /// The `main_token` field is the `{` token.
        ///
        /// The field name is determined by looking at the tokens preceding the
        /// field initialization.
        struct_init_dot,
        /// Same as `struct_init_dot` except there is known to be a trailing
        /// comma before the final rbrace.
        struct_init_dot_comma,
        /// `a{.x = b, .y = c}`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the type expression.
        ///   2. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each field initialization.
        ///
        /// The `main_token` field is the `{` token.
        ///
        /// The field name is determined by looking at the tokens preceding the
        /// field initialization.
        struct_init,
        /// Same as `struct_init` except there is known to be a trailing comma
        /// before the final rbrace.
        struct_init_comma,
        /// `a(b)`, `a()`.
        ///
        /// The `data` field is a `.node_and_opt_node`:
        ///   1. a `Node.Index` to the function expression.
        ///   2. a `Node.OptionalIndex` to the first argument, if any.
        ///
        /// The `main_token` field is the `(` token.
        call_one,
        /// Same as `call_one` except there is known to be a trailing comma
        /// before the final rparen.
        call_one_comma,
        /// `async a(b)`, `async a()`.
        ///
        /// The `data` field is a `.node_and_opt_node`:
        ///   1. a `Node.Index` to the function expression.
        ///   2. a `Node.OptionalIndex` to the first argument, if any.
        ///
        /// The `main_token` field is the `(` token.
        async_call_one,
        /// Same as `async_call_one` except there is known to be a trailing
        /// comma before the final rparen.
        async_call_one_comma,
        /// `a(b, c, d)`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the function expression.
        ///   2. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each argument.
        ///
        /// The `main_token` field is the `(` token.
        call,
        /// Same as `call` except there is known to be a trailing comma before
        /// the final rparen.
        call_comma,
        /// `async a(b, c, d)`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the function expression.
        ///   2. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each argument.
        ///
        /// The `main_token` field is the `(` token.
        async_call,
        /// Same as `async_call` except there is known to be a trailing comma
        /// before the final rparen.
        async_call_comma,
        /// `switch(a) {}`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the switch operand.
        ///   2. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each switch case.
        ///
        /// `The `main_token` field` is the identifier of a preceding label, if any; otherwise `switch`.
        @"switch",
        /// Same as `switch` except there is known to be a trailing comma before
        /// the final rbrace.
        switch_comma,
        /// `a => b`,
        /// `else => b`.
        ///
        /// The `data` field is a `.opt_node_and_node`:
        ///   1. a `Node.OptionalIndex` where `.none` means `else`.
        ///   2. a `Node.Index` to the target expression.
        ///
        /// The `main_token` field is the `=>` token.
        switch_case_one,
        /// Same as `switch_case_one` but the case is inline.
        switch_case_inline_one,
        /// `a, b, c => d`.
        ///
        /// The `data` field is a `.extra_and_node`:
        ///   1. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each switch item.
        ///   2. a `Node.Index` to the target expression.
        ///
        /// The `main_token` field is the `=>` token.
        switch_case,
        /// Same as `switch_case` but the case is inline.
        switch_case_inline,
        /// `lhs...rhs`.
        ///
        /// The `main_token` field is the `...` token.
        switch_range,
        /// `while (a) b`,
        /// `while (a) |x| b`.
        while_simple,
        /// `while (a) : (b) c`,
        /// `while (a) |x| : (b) c`.
        while_cont,
        /// `while (a) : (b) c else d`,
        /// `while (a) |x| : (b) c else d`,
        /// `while (a) |x| : (b) c else |y| d`.
        /// The continue expression part `: (b)` may be omitted.
        @"while",
        /// `for (a) b`.
        for_simple,
        /// `for (lhs[0..inputs]) lhs[inputs + 1] else lhs[inputs + 2]`. `For[rhs]`.
        @"for",
        /// `lhs..rhs`, `lhs..`.
        for_range,
        /// `if (a) b`.
        /// `if (b) |x| b`.
        if_simple,
        /// `if (a) b else c`.
        /// `if (a) |x| b else c`.
        /// `if (a) |x| b else |y| d`.
        @"if",
        /// `suspend expr`.
        ///
        /// The `data` field is a `.node` to expr.
        ///
        /// The `main_token` field is the `suspend` token.
        @"suspend",
        /// `resume expr`.
        ///
        /// The `data` field is a `.node` to expr.
        ///
        /// The `main_token` field is the `resume` token.
        @"resume",
        /// `continue :label expr`,
        /// `continue expr`,
        /// `continue :label`,
        /// `continue`.
        ///
        /// The `data` field is a `.opt_token_and_opt_node`:
        ///   1. a `OptionalTokenIndex` to the label identifier, if any.
        ///   2. a `Node.OptionalIndex` to the target expression, if any.
        ///
        /// The `main_token` field is the `continue` token.
        @"continue",
        /// `break :label expr`,
        /// `break expr`,
        /// `break :label`,
        /// `break`.
        ///
        /// The `data` field is a `.opt_token_and_opt_node`:
        ///   1. a `OptionalTokenIndex` to the label identifier, if any.
        ///   2. a `Node.OptionalIndex` to the target expression, if any.
        ///
        /// The `main_token` field is the `break` token.
        @"break",
        /// `return expr`, `return`.
        ///
        /// The `data` field is a `.opt_node` to the return value, if any.
        ///
        /// The `main_token` field is the `return` token.
        @"return",
        /// `fn (a: type_expr) return_type`.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the first parameter type expression, if any.
        ///   2. a `Node.OptionalIndex` to the return type expression. Can't be
        ///      `.none` unless a parsing error occured.
        ///
        /// The `main_token` field is the `fn` token.
        ///
        /// `anytype` and `...` parameters are omitted from the AST tree.
        /// Extern function declarations use this tag.
        fn_proto_simple,
        /// `fn (a: b, c: d) return_type`.
        ///
        /// The `data` field is a `.extra_and_opt_node`:
        ///   1. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each parameter type expression.
        ///   2. a `Node.OptionalIndex` to the return type expression. Can't be
        ///      `.none` unless a parsing error occured.
        ///
        /// The `main_token` field is the `fn` token.
        ///
        /// `anytype` and `...` parameters are omitted from the AST tree.
        /// Extern function declarations use this tag.
        fn_proto_multi,
        /// `fn (a: b) addrspace(e) linksection(f) callconv(g) return_type`.
        /// zero or one parameters.
        ///
        /// The `data` field is a `.extra_and_opt_node`:
        ///   1. a `Node.ExtraIndex` to `FnProtoOne`.
        ///   2. a `Node.OptionalIndex` to the return type expression. Can't be
        ///      `.none` unless a parsing error occured.
        ///
        /// The `main_token` field is the `fn` token.
        ///
        /// `anytype` and `...` parameters are omitted from the AST tree.
        /// Extern function declarations use this tag.
        fn_proto_one,
        /// `fn (a: b, c: d) addrspace(e) linksection(f) callconv(g) return_type`.
        ///
        /// The `data` field is a `.extra_and_opt_node`:
        ///   1. a `Node.ExtraIndex` to `FnProto`.
        ///   2. a `Node.OptionalIndex` to the return type expression. Can't be
        ///      `.none` unless a parsing error occured.
        ///
        /// The `main_token` field is the `fn` token.
        ///
        /// `anytype` and `...` parameters are omitted from the AST tree.
        /// Extern function declarations use this tag.
        fn_proto,
        /// Extern function declarations use the fn_proto tags rather than this one.
        ///
        /// The `data` field is a `.node_and_node`:
        ///   1. a `Node.Index` to `fn_proto_*`.
        ///   2. a `Node.Index` to function body block.
        ///
        /// The `main_token` field is the `fn` token.
        fn_decl,
        /// `anyframe->return_type`.
        ///
        /// The `data` field is a `.token_and_node`:
        ///   1. a `TokenIndex` to the `->` token.
        ///   2. a `Node.Index` to the function frame return type expression.
        ///
        /// The `main_token` field is the `anyframe` token.
        anyframe_type,
        /// The `data` field is unused.
        anyframe_literal,
        /// The `data` field is unused.
        char_literal,
        /// The `data` field is unused.
        number_literal,
        /// The `data` field is unused.
        unreachable_literal,
        /// The `data` field is unused.
        ///
        /// Most identifiers will not have explicit AST nodes, however for
        /// expressions which could be one of many different kinds of AST nodes,
        /// there will be an identifier AST node for it.
        identifier,
        /// `.foo`.
        ///
        /// The `data` field is unused.
        ///
        /// The `main_token` field is the identifier.
        enum_literal,
        /// The `data` field is unused.
        ///
        /// The `main_token` field is the string literal token.
        string_literal,
        /// The `data` field is a `.token_and_token`:
        ///   1. a `TokenIndex` to the first `.multiline_string_literal_line` token.
        ///   2. a `TokenIndex` to the last `.multiline_string_literal_line` token.
        ///
        /// The `main_token` field is the first token index (redundant with `data`).
        multiline_string_literal,
        /// `(expr)`.
        ///
        /// The `data` field is a `.node_and_token`:
        ///   1. a `Node.Index` to the sub-expression
        ///   2. a `TokenIndex` to the `)` token.
        ///
        /// The `main_token` field is the `(` token.
        grouped_expression,
        /// `@a(b, c)`.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the first argument, if any.
        ///   2. a `Node.OptionalIndex` to the second argument, if any.
        ///
        /// The `main_token` field is the builtin token.
        builtin_call_two,
        /// Same as `builtin_call_two` except there is known to be a trailing comma
        /// before the final rparen.
        builtin_call_two_comma,
        /// `@a(b, c, d)`.
        ///
        /// The `data` field is a `.extra_range` that stores a `Node.Index` for
        /// each argument.
        ///
        /// The `main_token` field is the builtin token.
        builtin_call,
        /// Same as `builtin_call` except there is known to be a trailing comma
        /// before the final rparen.
        builtin_call_comma,
        /// `error{a, b}`.
        ///
        /// The `data` field is a `.token_and_token`:
        ///   1. a `TokenIndex` to the `{` token.
        ///   2. a `TokenIndex` to the `}` token.
        ///
        /// The `main_token` field is the `error`.
        error_set_decl,
        /// `struct {}`, `union {}`, `opaque {}`, `enum {}`.
        ///
        /// The `data` field is a `.extra_range` that stores a `Node.Index` for
        /// each container member.
        ///
        /// The `main_token` field is the `struct`, `union`, `opaque` or `enum` token.
        container_decl,
        /// Same as `container_decl` except there is known to be a trailing
        /// comma before the final rbrace.
        container_decl_trailing,
        /// `struct {lhs, rhs}`, `union {lhs, rhs}`, `opaque {lhs, rhs}`, `enum {lhs, rhs}`.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the first container member, if any.
        ///   2. a `Node.OptionalIndex` to the second container member, if any.
        ///
        /// The `main_token` field is the `struct`, `union`, `opaque` or `enum` token.
        container_decl_two,
        /// Same as `container_decl_two` except there is known to be a trailing
        /// comma before the final rbrace.
        container_decl_two_trailing,
        /// `struct(arg)`, `union(arg)`, `enum(arg)`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to arg.
        ///   2. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each container member.
        ///
        /// The `main_token` field is the `struct`, `union` or `enum` token.
        container_decl_arg,
        /// Same as `container_decl_arg` except there is known to be a trailing
        /// comma before the final rbrace.
        container_decl_arg_trailing,
        /// `union(enum) {}`.
        ///
        /// The `data` field is a `.extra_range` that stores a `Node.Index` for
        /// each container member.
        ///
        /// The `main_token` field is the `union` token.
        ///
        /// A tagged union with explicitly provided enums will instead be
        /// represented by `container_decl_arg`.
        tagged_union,
        /// Same as `tagged_union` except there is known to be a trailing comma
        /// before the final rbrace.
        tagged_union_trailing,
        /// `union(enum) {lhs, rhs}`.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the first container member, if any.
        ///   2. a `Node.OptionalIndex` to the second container member, if any.
        ///
        /// The `main_token` field is the `union` token.
        ///
        /// A tagged union with explicitly provided enums will instead be
        /// represented by `container_decl_arg`.
        tagged_union_two,
        /// Same as `tagged_union_two` except there is known to be a trailing
        /// comma before the final rbrace.
        tagged_union_two_trailing,
        /// `union(enum(arg)) {}`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to arg.
        ///   2. a `ExtraIndex` to a `SubRange` that stores a `Node.Index` for
        ///      each container member.
        ///
        /// The `main_token` field is the `union` token.
        tagged_union_enum_tag,
        /// Same as `tagged_union_enum_tag` except there is known to be a
        /// trailing comma before the final rbrace.
        tagged_union_enum_tag_trailing,
        /// `a: lhs = rhs,`,
        /// `a: lhs,`.
        ///
        /// The `data` field is a `.node_and_opt_node`:
        ///   1. a `Node.Index` to the field type expression.
        ///   2. a `Node.OptionalIndex` to the default value expression, if any.
        ///
        /// The `main_token` field is the field name identifier.
        ///
        /// `lastToken()` does not include the possible trailing comma.
        container_field_init,
        /// `a: lhs align(rhs),`.
        ///
        /// The `data` field is a `.node_and_node`:
        ///   1. a `Node.Index` to the field type expression.
        ///   2. a `Node.Index` to the alignment expression.
        ///
        /// The `main_token` field is the field name identifier.
        ///
        /// `lastToken()` does not include the possible trailing comma.
        container_field_align,
        /// `a: lhs align(c) = d,`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to the field type expression.
        ///   2. a `ExtraIndex` to `ContainerField`.
        ///
        /// The `main_token` field is the field name identifier.
        ///
        /// `lastToken()` does not include the possible trailing comma.
        container_field,
        /// `comptime expr`.
        ///
        /// The `data` field is a `.node` to expr.
        ///
        /// The `main_token` field is the `comptime` token.
        @"comptime",
        /// `nosuspend expr`.
        ///
        /// The `data` field is a `.node` to expr.
        ///
        /// The `main_token` field is the `nosuspend` token.
        @"nosuspend",
        /// `{lhs rhs}`.
        ///
        /// The `data` field is a `.opt_node_and_opt_node`:
        ///   1. a `Node.OptionalIndex` to the first statement, if any.
        ///   2. a `Node.OptionalIndex` to the second statement, if any.
        ///
        /// The `main_token` field is the `{` token.
        block_two,
        /// Same as `block_two` except there is known to be a trailing
        /// comma before the final rbrace.
        block_two_semicolon,
        /// `{a b}`.
        ///
        /// The `data` field is a `.extra_range` that stores a `Node.Index` for
        /// each statement.
        ///
        /// The `main_token` field is the `{` token.
        block,
        /// Same as `block` except there is known to be a trailing comma before
        /// the final rbrace.
        block_semicolon,
        /// `asm(lhs)`.
        ///
        /// rhs is a `Token.Index` to the `)` token.
        /// The `main_token` field is the `asm` token.
        asm_simple,
        /// `asm(lhs, a)`.
        ///
        /// The `data` field is a `.node_and_extra`:
        ///   1. a `Node.Index` to lhs.
        ///   2. a `ExtraIndex` to `Asm`.
        ///
        /// The `main_token` field is the `asm` token.
        @"asm",
        /// `[a] "b" (c)`.
        /// `[a] "b" (-> lhs)`.
        ///
        /// The `data` field is a `.opt_node_and_token`:
        ///   1. a `Node.OptionalIndex` to lhs, if any.
        ///   2. a `TokenIndex` to the `)` token.
        ///
        /// The `main_token` field is `a`.
        asm_output,
        /// `[a] "b" (lhs)`.
        ///
        /// The `data` field is a `.node_and_token`:
        ///   1. a `Node.Index` to lhs.
        ///   2. a `TokenIndex` to the `)` token.
        ///
        /// The `main_token` field is `a`.
        asm_input,
        /// `error.a`.
        ///
        /// The `data` field is unused.
        ///
        /// The `main_token` field is `error` token.
        error_value,
        /// `lhs!rhs`.
        ///
        /// The `main_token` field is the `!` token.
        error_union,

        pub fn isContainerField(tag: Tag) bool {
            return switch (tag) {
                .container_field_init,
                .container_field_align,
                .container_field,
                => true,

                else => false,
            };
        }
    };

    pub const Data = union {
        node: Index,
        opt_node: OptionalIndex,
        token: TokenIndex,
        node_and_node: struct { Index, Index },
        opt_node_and_opt_node: struct { OptionalIndex, OptionalIndex },
        node_and_opt_node: struct { Index, OptionalIndex },
        opt_node_and_node: struct { OptionalIndex, Index },
        node_and_extra: struct { Index, ExtraIndex },
        extra_and_node: struct { ExtraIndex, Index },
        extra_and_opt_node: struct { ExtraIndex, OptionalIndex },
        node_and_token: struct { Index, TokenIndex },
        token_and_node: struct { TokenIndex, Index },
        token_and_token: struct { TokenIndex, TokenIndex },
        opt_node_and_token: struct { OptionalIndex, TokenIndex },
        opt_token_and_node: struct { OptionalTokenIndex, Index },
        opt_token_and_opt_node: struct { OptionalTokenIndex, OptionalIndex },
        opt_token_and_opt_token: struct { OptionalTokenIndex, OptionalTokenIndex },
        @"for": struct { ExtraIndex, For },
        extra_range: SubRange,
    };

    pub const LocalVarDecl = struct {
        type_node: Index,
        align_node: Index,
    };

    pub const ArrayTypeSentinel = struct {
        sentinel: Index,
        elem_type: Index,
    };

    pub const PtrType = struct {
        sentinel: OptionalIndex,
        align_node: OptionalIndex,
        addrspace_node: OptionalIndex,
    };

    pub const PtrTypeBitRange = struct {
        sentinel: OptionalIndex,
        align_node: Index,
        addrspace_node: OptionalIndex,
        bit_range_start: Index,
        bit_range_end: Index,
    };

    pub const SubRange = struct {
        /// Index into extra_data.
        start: ExtraIndex,
        /// Index into extra_data.
        end: ExtraIndex,
    };

    pub const If = struct {
        then_expr: Index,
        else_expr: Index,
    };

    pub const ContainerField = struct {
        align_expr: Index,
        value_expr: Index,
    };

    pub const GlobalVarDecl = struct {
        /// Populated if there is an explicit type ascription.
        type_node: OptionalIndex,
        /// Populated if align(A) is present.
        align_node: OptionalIndex,
        /// Populated if addrspace(A) is present.
        addrspace_node: OptionalIndex,
        /// Populated if linksection(A) is present.
        section_node: OptionalIndex,
    };

    pub const Slice = struct {
        start: Index,
        end: Index,
    };

    pub const SliceSentinel = struct {
        start: Index,
        /// May be .none if the slice is "open"
        end: OptionalIndex,
        sentinel: Index,
    };

    pub const While = struct {
        cont_expr: OptionalIndex,
        then_expr: Index,
        else_expr: Index,
    };

    pub const WhileCont = struct {
        cont_expr: Index,
        then_expr: Index,
    };

    pub const For = packed struct(u32) {
        inputs: u31,
        has_else: bool,
    };

    pub const FnProtoOne = struct {
        /// Populated if there is exactly 1 parameter. Otherwise there are 0 parameters.
        param: OptionalIndex,
        /// Populated if align(A) is present.
        align_expr: OptionalIndex,
        /// Populated if addrspace(A) is present.
        addrspace_expr: OptionalIndex,
        /// Populated if linksection(A) is present.
        section_expr: OptionalIndex,
        /// Populated if callconv(A) is present.
        callconv_expr: OptionalIndex,
    };

    pub const FnProto = struct {
        params_start: ExtraIndex,
        params_end: ExtraIndex,
        /// Populated if align(A) is present.
        align_expr: OptionalIndex,
        /// Populated if addrspace(A) is present.
        addrspace_expr: OptionalIndex,
        /// Populated if linksection(A) is present.
        section_expr: OptionalIndex,
        /// Populated if callconv(A) is present.
        callconv_expr: OptionalIndex,
    };

    pub const Asm = struct {
        items_start: ExtraIndex,
        items_end: ExtraIndex,
        /// Needed to make lastToken() work.
        rparen: TokenIndex,
    };
};

pub fn nodeToSpan(tree: *const Ast, node: Ast.Node.Index) Span {
    return tokensToSpan(
        tree,
        tree.firstToken(node),
        tree.lastToken(node),
        tree.nodeMainToken(node),
    );
}

pub fn tokenToSpan(tree: *const Ast, token: Ast.TokenIndex) Span {
    return tokensToSpan(tree, token, token, token);
}

pub fn tokensToSpan(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex, main: Ast.TokenIndex) Span {
    var start_tok = start;
    var end_tok = end;

    if (tree.tokensOnSameLine(start, end)) {
        // do nothing
    } else if (tree.tokensOnSameLine(start, main)) {
        end_tok = main;
    } else if (tree.tokensOnSameLine(main, end)) {
        start_tok = main;
    } else {
        start_tok = main;
        end_tok = main;
    }
    const start_off = tree.tokenStart(start_tok);
    const end_off = tree.tokenStart(end_tok) + @as(u32, @intCast(tree.tokenSlice(end_tok).len));
    return Span{ .start = start_off, .end = end_off, .main = tree.tokenStart(main) };
}

const std = @import("../std.zig");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const Token = std.zig.Token;
const Ast = @This();
const Allocator = std.mem.Allocator;
const Parse = @import("Parse.zig");
const private_render = @import("./render.zig");

test {
    _ = Parse;
    _ = private_render;
}
//! Ingests an AST and produces ZIR code.
const AstGen = @This();

const std = @import("std");
const Ast = std.zig.Ast;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringIndexAdapter = std.hash_map.StringIndexAdapter;
const StringIndexContext = std.hash_map.StringIndexContext;

const isPrimitive = std.zig.primitives.isPrimitive;

const Zir = std.zig.Zir;
const BuiltinFn = std.zig.BuiltinFn;
const AstRlAnnotate = std.zig.AstRlAnnotate;

gpa: Allocator,
tree: *const Ast,
/// The set of nodes which, given the choice, must expose a result pointer to
/// sub-expressions. See `AstRlAnnotate` for details.
nodes_need_rl: *const AstRlAnnotate.RlNeededSet,
instructions: std.MultiArrayList(Zir.Inst) = .{},
extra: ArrayListUnmanaged(u32) = .empty,
string_bytes: ArrayListUnmanaged(u8) = .empty,
/// Tracks the current byte offset within the source file.
/// Used to populate line deltas in the ZIR. AstGen maintains
/// this "cursor" throughout the entire AST lowering process in order
/// to avoid starting over the line/column scan for every declaration, which
/// would be O(N^2).
source_offset: u32 = 0,
/// Tracks the corresponding line of `source_offset`.
/// This value is absolute.
source_line: u32 = 0,
/// Tracks the corresponding column of `source_offset`.
/// This value is absolute.
source_column: u32 = 0,
/// Used for temporary allocations; freed after AstGen is complete.
/// The resulting ZIR code has no references to anything in this arena.
arena: Allocator,
string_table: std.HashMapUnmanaged(u32, void, StringIndexContext, std.hash_map.default_max_load_percentage) = .empty,
compile_errors: ArrayListUnmanaged(Zir.Inst.CompileErrors.Item) = .empty,
/// The topmost block of the current function.
fn_block: ?*GenZir = null,
fn_var_args: bool = false,
/// Whether we are somewhere within a function. If `true`, any container decls may be
/// generic and thus must be tunneled through closure.
within_fn: bool = false,
/// The return type of the current function. This may be a trivial `Ref`, or
/// otherwise it refers to a `ret_type` instruction.
fn_ret_ty: Zir.Inst.Ref = .none,
/// Maps string table indexes to the first `@import` ZIR instruction
/// that uses this string as the operand.
imports: std.AutoArrayHashMapUnmanaged(Zir.NullTerminatedString, Ast.TokenIndex) = .empty,
/// Used for temporary storage when building payloads.
scratch: std.ArrayListUnmanaged(u32) = .empty,
/// Whenever a `ref` instruction is needed, it is created and saved in this
/// table instead of being immediately appended to the current block body.
/// Then, when the instruction is being added to the parent block (typically from
/// setBlockBody), if it has a ref_table entry, then the ref instruction is added
/// there. This makes sure two properties are upheld:
/// 1. All pointers to the same locals return the same address. This is required
///    to be compliant with the language specification.
/// 2. `ref` instructions will dominate their uses. This is a required property
///    of ZIR.
/// The key is the ref operand; the value is the ref instruction.
ref_table: std.AutoHashMapUnmanaged(Zir.Inst.Index, Zir.Inst.Index) = .empty,
/// Any information which should trigger invalidation of incremental compilation
/// data should be used to update this hasher. The result is the final source
/// hash of the enclosing declaration/etc.
src_hasher: std.zig.SrcHasher,

const InnerError = error{ OutOfMemory, AnalysisFail };

fn addExtra(astgen: *AstGen, extra: anytype) Allocator.Error!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    try astgen.extra.ensureUnusedCapacity(astgen.gpa, fields.len);
    return addExtraAssumeCapacity(astgen, extra);
}

fn addExtraAssumeCapacity(astgen: *AstGen, extra: anytype) u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    const extra_index: u32 = @intCast(astgen.extra.items.len);
    astgen.extra.items.len += fields.len;
    setExtra(astgen, extra_index, extra);
    return extra_index;
}

fn setExtra(astgen: *AstGen, index: usize, extra: anytype) void {
    const fields = std.meta.fields(@TypeOf(extra));
    var i = index;
    inline for (fields) |field| {
        astgen.extra.items[i] = switch (field.type) {
            u32 => @field(extra, field.name),

            Zir.Inst.Ref,
            Zir.Inst.Index,
            Zir.Inst.Declaration.Name,
            std.zig.SimpleComptimeReason,
            Zir.NullTerminatedString,
            // Ast.TokenIndex is missing because it is a u32.
            Ast.OptionalTokenIndex,
            Ast.Node.Index,
            Ast.Node.OptionalIndex,
            => @intFromEnum(@field(extra, field.name)),

            Ast.TokenOffset,
            Ast.OptionalTokenOffset,
            Ast.Node.Offset,
            Ast.Node.OptionalOffset,
            => @bitCast(@intFromEnum(@field(extra, field.name))),

            i32,
            Zir.Inst.Call.Flags,
            Zir.Inst.BuiltinCall.Flags,
            Zir.Inst.SwitchBlock.Bits,
            Zir.Inst.SwitchBlockErrUnion.Bits,
            Zir.Inst.FuncFancy.Bits,
            Zir.Inst.Param.Type,
            Zir.Inst.Func.RetTy,
            => @bitCast(@field(extra, field.name)),

            else => @compileError("bad field type"),
        };
        i += 1;
    }
}

fn reserveExtra(astgen: *AstGen, size: usize) Allocator.Error!u32 {
    const extra_index: u32 = @intCast(astgen.extra.items.len);
    try astgen.extra.resize(astgen.gpa, extra_index + size);
    return extra_index;
}

fn appendRefs(astgen: *AstGen, refs: []const Zir.Inst.Ref) !void {
    return astgen.extra.appendSlice(astgen.gpa, @ptrCast(refs));
}

fn appendRefsAssumeCapacity(astgen: *AstGen, refs: []const Zir.Inst.Ref) void {
    astgen.extra.appendSliceAssumeCapacity(@ptrCast(refs));
}

pub fn generate(gpa: Allocator, tree: Ast) Allocator.Error!Zir {
    assert(tree.mode == .zig);

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var nodes_need_rl = try AstRlAnnotate.annotate(gpa, arena.allocator(), tree);
    defer nodes_need_rl.deinit(gpa);

    var astgen: AstGen = .{
        .gpa = gpa,
        .arena = arena.allocator(),
        .tree = &tree,
        .nodes_need_rl = &nodes_need_rl,
        .src_hasher = undefined, // `structDeclInner` for the root struct will set this
    };
    defer astgen.deinit(gpa);

    // String table index 0 is reserved for `NullTerminatedString.empty`.
    try astgen.string_bytes.append(gpa, 0);

    // We expect at least as many ZIR instructions and extra data items
    // as AST nodes.
    try astgen.instructions.ensureTotalCapacity(gpa, tree.nodes.len);

    // First few indexes of extra are reserved and set at the end.
    const reserved_count = @typeInfo(Zir.ExtraIndex).@"enum".fields.len;
    try astgen.extra.ensureTotalCapacity(gpa, tree.nodes.len + reserved_count);
    astgen.extra.items.len += reserved_count;

    var top_scope: Scope.Top = .{};

    var gz_instructions: std.ArrayListUnmanaged(Zir.Inst.Index) = .empty;
    var gen_scope: GenZir = .{
        .is_comptime = true,
        .parent = &top_scope.base,
        .anon_name_strategy = .parent,
        .decl_node_index = .root,
        .decl_line = 0,
        .astgen = &astgen,
        .instructions = &gz_instructions,
        .instructions_top = 0,
    };
    defer gz_instructions.deinit(gpa);

    // The AST -> ZIR lowering process assumes an AST that does not have any parse errors.
    // Parse errors, or AstGen errors in the root struct, are considered "fatal", so we emit no ZIR.
    const fatal = if (tree.errors.len == 0) fatal: {
        if (AstGen.structDeclInner(
            &gen_scope,
            &gen_scope.base,
            .root,
            tree.containerDeclRoot(),
            .auto,
            .none,
        )) |struct_decl_ref| {
            assert(struct_decl_ref.toIndex().? == .main_struct_inst);
            break :fatal false;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.AnalysisFail => break :fatal true, // Handled via compile_errors below.
        }
    } else fatal: {
        try lowerAstErrors(&astgen);
        break :fatal true;
    };

    const err_index = @intFromEnum(Zir.ExtraIndex.compile_errors);
    if (astgen.compile_errors.items.len == 0) {
        astgen.extra.items[err_index] = 0;
    } else {
        try astgen.extra.ensureUnusedCapacity(gpa, 1 + astgen.compile_errors.items.len *
            @typeInfo(Zir.Inst.CompileErrors.Item).@"struct".fields.len);

        astgen.extra.items[err_index] = astgen.addExtraAssumeCapacity(Zir.Inst.CompileErrors{
            .items_len = @intCast(astgen.compile_errors.items.len),
        });

        for (astgen.compile_errors.items) |item| {
            _ = astgen.addExtraAssumeCapacity(item);
        }
    }

    const imports_index = @intFromEnum(Zir.ExtraIndex.imports);
    if (astgen.imports.count() == 0) {
        astgen.extra.items[imports_index] = 0;
    } else {
        try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.Imports).@"struct".fields.len +
            astgen.imports.count() * @typeInfo(Zir.Inst.Imports.Item).@"struct".fields.len);

        astgen.extra.items[imports_index] = astgen.addExtraAssumeCapacity(Zir.Inst.Imports{
            .imports_len = @intCast(astgen.imports.count()),
        });

        var it = astgen.imports.iterator();
        while (it.next()) |entry| {
            _ = astgen.addExtraAssumeCapacity(Zir.Inst.Imports.Item{
                .name = entry.key_ptr.*,
                .token = entry.value_ptr.*,
            });
        }
    }

    return .{
        .instructions = if (fatal) .empty else astgen.instructions.toOwnedSlice(),
        .string_bytes = try astgen.string_bytes.toOwnedSlice(gpa),
        .extra = try astgen.extra.toOwnedSlice(gpa),
    };
}

fn deinit(astgen: *AstGen, gpa: Allocator) void {
    astgen.instructions.deinit(gpa);
    astgen.extra.deinit(gpa);
    astgen.string_table.deinit(gpa);
    astgen.string_bytes.deinit(gpa);
    astgen.compile_errors.deinit(gpa);
    astgen.imports.deinit(gpa);
    astgen.scratch.deinit(gpa);
    astgen.ref_table.deinit(gpa);
}

const ResultInfo = struct {
    /// The semantics requested for the result location
    rl: Loc,

    /// The "operator" consuming the result location
    ctx: Context = .none,

    /// Turns a `coerced_ty` back into a `ty`. Should be called at branch points
    /// such as if and switch expressions.
    fn br(ri: ResultInfo) ResultInfo {
        return switch (ri.rl) {
            .coerced_ty => |ty| .{
                .rl = .{ .ty = ty },
                .ctx = ri.ctx,
            },
            else => ri,
        };
    }

    fn zirTag(ri: ResultInfo) Zir.Inst.Tag {
        switch (ri.rl) {
            .ty => return switch (ri.ctx) {
                .shift_op => .as_shift_operand,
                else => .as_node,
            },
            else => unreachable,
        }
    }

    const Loc = union(enum) {
        /// The expression is the right-hand side of assignment to `_`. Only the side-effects of the
        /// expression should be generated. The result instruction from the expression must
        /// be ignored.
        discard,
        /// The expression has an inferred type, and it will be evaluated as an rvalue.
        none,
        /// The expression will be coerced into this type, but it will be evaluated as an rvalue.
        ty: Zir.Inst.Ref,
        /// Same as `ty` but it is guaranteed that Sema will additionally perform the coercion,
        /// so no `as` instruction needs to be emitted.
        coerced_ty: Zir.Inst.Ref,
        /// The expression must generate a pointer rather than a value. For example, the left hand side
        /// of an assignment uses this kind of result location.
        ref,
        /// The expression must generate a pointer rather than a value, and the pointer will be coerced
        /// by other code to this type, which is guaranteed by earlier instructions to be a pointer type.
        ref_coerced_ty: Zir.Inst.Ref,
        /// The expression must store its result into this typed pointer. The result instruction
        /// from the expression must be ignored.
        ptr: PtrResultLoc,
        /// The expression must store its result into this allocation, which has an inferred type.
        /// The result instruction from the expression must be ignored.
        /// Always an instruction with tag `alloc_inferred`.
        inferred_ptr: Zir.Inst.Ref,
        /// The expression has a sequence of pointers to store its results into due to a destructure
        /// operation. Each of these pointers may or may not have an inferred type.
        destructure: struct {
            /// The AST node of the destructure operation itself.
            src_node: Ast.Node.Index,
            /// The pointers to store results into.
            components: []const DestructureComponent,
        },

        const DestructureComponent = union(enum) {
            typed_ptr: PtrResultLoc,
            inferred_ptr: Zir.Inst.Ref,
            discard,
        };

        const PtrResultLoc = struct {
            inst: Zir.Inst.Ref,
            src_node: ?Ast.Node.Index = null,
        };

        /// Find the result type for a cast builtin given the result location.
        /// If the location does not have a known result type, returns `null`.
        fn resultType(rl: Loc, gz: *GenZir, node: Ast.Node.Index) !?Zir.Inst.Ref {
            return switch (rl) {
                .discard, .none, .ref, .inferred_ptr, .destructure => null,
                .ty, .coerced_ty => |ty_ref| ty_ref,
                .ref_coerced_ty => |ptr_ty| try gz.addUnNode(.elem_type, ptr_ty, node),
                .ptr => |ptr| {
                    const ptr_ty = try gz.addUnNode(.typeof, ptr.inst, node);
                    return try gz.addUnNode(.elem_type, ptr_ty, node);
                },
            };
        }

        /// Find the result type for a cast builtin given the result location.
        /// If the location does not have a known result type, emits an error on
        /// the given node.
        fn resultTypeForCast(rl: Loc, gz: *GenZir, node: Ast.Node.Index, builtin_name: []const u8) !Zir.Inst.Ref {
            const astgen = gz.astgen;
            if (try rl.resultType(gz, node)) |ty| return ty;
            switch (rl) {
                .destructure => |destructure| return astgen.failNodeNotes(node, "{s} must have a known result type", .{builtin_name}, &.{
                    try astgen.errNoteNode(destructure.src_node, "destructure expressions do not provide a single result type", .{}),
                    try astgen.errNoteNode(node, "use @as to provide explicit result type", .{}),
                }),
                else => return astgen.failNodeNotes(node, "{s} must have a known result type", .{builtin_name}, &.{
                    try astgen.errNoteNode(node, "use @as to provide explicit result type", .{}),
                }),
            }
        }
    };

    const Context = enum {
        /// The expression is the operand to a return expression.
        @"return",
        /// The expression is the input to an error-handling operator (if-else, try, or catch).
        error_handling_expr,
        /// The expression is the right-hand side of a shift operation.
        shift_op,
        /// The expression is an argument in a function call.
        fn_arg,
        /// The expression is the right-hand side of an initializer for a `const` variable
        const_init,
        /// The expression is the right-hand side of an assignment expression.
        assignment,
        /// No specific operator in particular.
        none,
    };
};

const coerced_align_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .u29_type } };
const coerced_linksection_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .slice_const_u8_type } };
const coerced_type_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .type_type } };
const coerced_bool_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .bool_type } };

fn typeExpr(gz: *GenZir, scope: *Scope, type_node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    return comptimeExpr(gz, scope, coerced_type_ri, type_node, .type);
}

fn reachableTypeExpr(
    gz: *GenZir,
    scope: *Scope,
    type_node: Ast.Node.Index,
    reachable_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    return reachableExprComptime(gz, scope, coerced_type_ri, type_node, reachable_node, .type);
}

/// Same as `expr` but fails with a compile error if the result type is `noreturn`.
fn reachableExpr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    reachable_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    return reachableExprComptime(gz, scope, ri, node, reachable_node, null);
}

fn reachableExprComptime(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    reachable_node: Ast.Node.Index,
    /// If `null`, the expression is not evaluated in a comptime context.
    comptime_reason: ?std.zig.SimpleComptimeReason,
) InnerError!Zir.Inst.Ref {
    const result_inst = if (comptime_reason) |r|
        try comptimeExpr(gz, scope, ri, node, r)
    else
        try expr(gz, scope, ri, node);

    if (gz.refIsNoReturn(result_inst)) {
        try gz.astgen.appendErrorNodeNotes(reachable_node, "unreachable code", .{}, &[_]u32{
            try gz.astgen.errNoteNode(node, "control flow is diverted here", .{}),
        });
    }
    return result_inst;
}

fn lvalExpr(gz: *GenZir, scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    switch (tree.nodeTag(node)) {
        .root => unreachable,
        .@"usingnamespace" => unreachable,
        .test_decl => unreachable,
        .global_var_decl => unreachable,
        .local_var_decl => unreachable,
        .simple_var_decl => unreachable,
        .aligned_var_decl => unreachable,
        .switch_case => unreachable,
        .switch_case_inline => unreachable,
        .switch_case_one => unreachable,
        .switch_case_inline_one => unreachable,
        .container_field_init => unreachable,
        .container_field_align => unreachable,
        .container_field => unreachable,
        .asm_output => unreachable,
        .asm_input => unreachable,

        .assign,
        .assign_destructure,
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
        .add,
        .add_wrap,
        .add_sat,
        .sub,
        .sub_wrap,
        .sub_sat,
        .mul,
        .mul_wrap,
        .mul_sat,
        .div,
        .mod,
        .bit_and,
        .bit_or,
        .shl,
        .shl_sat,
        .shr,
        .bit_xor,
        .bang_equal,
        .equal_equal,
        .greater_than,
        .greater_or_equal,
        .less_than,
        .less_or_equal,
        .array_cat,
        .array_mult,
        .bool_and,
        .bool_or,
        .@"asm",
        .asm_simple,
        .string_literal,
        .number_literal,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .unreachable_literal,
        .@"return",
        .@"if",
        .if_simple,
        .@"while",
        .while_simple,
        .while_cont,
        .bool_not,
        .address_of,
        .optional_type,
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        .@"break",
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .array_type,
        .array_type_sentinel,
        .enum_literal,
        .multiline_string_literal,
        .char_literal,
        .@"defer",
        .@"errdefer",
        .@"catch",
        .error_union,
        .merge_error_sets,
        .switch_range,
        .for_range,
        .@"await",
        .bit_not,
        .negation,
        .negation_wrap,
        .@"resume",
        .@"try",
        .slice,
        .slice_open,
        .slice_sentinel,
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_i```
