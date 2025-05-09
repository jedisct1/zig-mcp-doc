```
dex,
            } },
        });
        gz.instructions.appendAssumeCapacity(new_index);
        return new_index.toRef();
    }

    fn addAsm(
        gz: *GenZir,
        args: struct {
            tag: Zir.Inst.Extended,
            /// Absolute node index. This function does the conversion to offset from Decl.
            node: Ast.Node.Index,
            asm_source: Zir.NullTerminatedString,
            output_type_bits: u32,
            is_volatile: bool,
            outputs: []const Zir.Inst.Asm.Output,
            inputs: []const Zir.Inst.Asm.Input,
            clobbers: []const u32,
        },
    ) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        try gz.instructions.ensureUnusedCapacity(gpa, 1);
        try astgen.instructions.ensureUnusedCapacity(gpa, 1);
        try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.Asm).@"struct".fields.len +
            args.outputs.len * @typeInfo(Zir.Inst.Asm.Output).@"struct".fields.len +
            args.inputs.len * @typeInfo(Zir.Inst.Asm.Input).@"struct".fields.len +
            args.clobbers.len);

        const payload_index = gz.astgen.addExtraAssumeCapacity(Zir.Inst.Asm{
            .src_node = gz.nodeIndexToRelative(args.node),
            .asm_source = args.asm_source,
            .output_type_bits = args.output_type_bits,
        });
        for (args.outputs) |output| {
            _ = gz.astgen.addExtraAssumeCapacity(output);
        }
        for (args.inputs) |input| {
            _ = gz.astgen.addExtraAssumeCapacity(input);
        }
        gz.astgen.extra.appendSliceAssumeCapacity(args.clobbers);

        //  * 0b00000000_0000XXXX - `outputs_len`.
        //  * 0b0000000X_XXXX0000 - `inputs_len`.
        //  * 0b0XXXXXX0_00000000 - `clobbers_len`.
        //  * 0bX0000000_00000000 - is volatile
        const small: u16 = @as(u16, @as(u4, @intCast(args.outputs.len))) << 0 |
            @as(u16, @as(u5, @intCast(args.inputs.len))) << 4 |
            @as(u16, @as(u6, @intCast(args.clobbers.len))) << 9 |
            @as(u16, @intFromBool(args.is_volatile)) << 15;

        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.appendAssumeCapacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = args.tag,
                .small = small,
                .operand = payload_index,
            } },
        });
        gz.instructions.appendAssumeCapacity(new_index);
        return new_index.toRef();
    }

    /// Note that this returns a `Zir.Inst.Index` not a ref.
    /// Does *not* append the block instruction to the scope.
    /// Leaves the `payload_index` field undefined.
    fn makeBlockInst(gz: *GenZir, tag: Zir.Inst.Tag, node: Ast.Node.Index) !Zir.Inst.Index {
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        const gpa = gz.astgen.gpa;
        try gz.astgen.instructions.append(gpa, .{
            .tag = tag,
            .data = .{ .pl_node = .{
                .src_node = gz.nodeIndexToRelative(node),
                .payload_index = undefined,
            } },
        });
        return new_index;
    }

    /// Note that this returns a `Zir.Inst.Index` not a ref.
    /// Does *not* append the block instruction to the scope.
    /// Leaves the `payload_index` field undefined. Use `setDeclaration` to finalize.
    fn makeDeclaration(gz: *GenZir, node: Ast.Node.Index) !Zir.Inst.Index {
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        try gz.astgen.instructions.append(gz.astgen.gpa, .{
            .tag = .declaration,
            .data = .{ .declaration = .{
                .src_node = node,
                .payload_index = undefined,
            } },
        });
        return new_index;
    }

    /// Note that this returns a `Zir.Inst.Index` not a ref.
    /// Leaves the `payload_index` field undefined.
    fn addCondBr(gz: *GenZir, tag: Zir.Inst.Tag, node: Ast.Node.Index) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensureUnusedCapacity(gpa, 1);
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        try gz.astgen.instructions.append(gpa, .{
            .tag = tag,
            .data = .{ .pl_node = .{
                .src_node = gz.nodeIndexToRelative(node),
                .payload_index = undefined,
            } },
        });
        gz.instructions.appendAssumeCapacity(new_index);
        return new_index;
    }

    fn setStruct(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        captures_len: u32,
        fields_len: u32,
        decls_len: u32,
        has_backing_int: bool,
        layout: std.builtin.Type.ContainerLayout,
        known_non_opv: bool,
        known_comptime_only: bool,
        any_comptime_fields: bool,
        any_default_inits: bool,
        any_aligned_fields: bool,
        fields_hash: std.zig.SrcHash,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        // Node .root is valid for the root `struct_decl` of a file!
        assert(args.src_node != .root or gz.parent.tag == .top);

        const fields_hash_arr: [4]u32 = @bitCast(args.fields_hash);

        try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.StructDecl).@"struct".fields.len + 3);
        const payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.StructDecl{
            .fields_hash_0 = fields_hash_arr[0],
            .fields_hash_1 = fields_hash_arr[1],
            .fields_hash_2 = fields_hash_arr[2],
            .fields_hash_3 = fields_hash_arr[3],
            .src_line = astgen.source_line,
            .src_node = args.src_node,
        });

        if (args.captures_len != 0) {
            astgen.extra.appendAssumeCapacity(args.captures_len);
        }
        if (args.fields_len != 0) {
            astgen.extra.appendAssumeCapacity(args.fields_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.appendAssumeCapacity(args.decls_len);
        }
        astgen.instructions.set(@intFromEnum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .struct_decl,
                .small = @bitCast(Zir.Inst.StructDecl.Small{
                    .has_captures_len = args.captures_len != 0,
                    .has_fields_len = args.fields_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .has_backing_int = args.has_backing_int,
                    .known_non_opv = args.known_non_opv,
                    .known_comptime_only = args.known_comptime_only,
                    .name_strategy = gz.anon_name_strategy,
                    .layout = args.layout,
                    .any_comptime_fields = args.any_comptime_fields,
                    .any_default_inits = args.any_default_inits,
                    .any_aligned_fields = args.any_aligned_fields,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn setUnion(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        tag_type: Zir.Inst.Ref,
        captures_len: u32,
        body_len: u32,
        fields_len: u32,
        decls_len: u32,
        layout: std.builtin.Type.ContainerLayout,
        auto_enum_tag: bool,
        any_aligned_fields: bool,
        fields_hash: std.zig.SrcHash,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        assert(args.src_node != .root);

        const fields_hash_arr: [4]u32 = @bitCast(args.fields_hash);

        try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.UnionDecl).@"struct".fields.len + 5);
        const payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.UnionDecl{
            .fields_hash_0 = fields_hash_arr[0],
            .fields_hash_1 = fields_hash_arr[1],
            .fields_hash_2 = fields_hash_arr[2],
            .fields_hash_3 = fields_hash_arr[3],
            .src_line = astgen.source_line,
            .src_node = args.src_node,
        });

        if (args.tag_type != .none) {
            astgen.extra.appendAssumeCapacity(@intFromEnum(args.tag_type));
        }
        if (args.captures_len != 0) {
            astgen.extra.appendAssumeCapacity(args.captures_len);
        }
        if (args.body_len != 0) {
            astgen.extra.appendAssumeCapacity(args.body_len);
        }
        if (args.fields_len != 0) {
            astgen.extra.appendAssumeCapacity(args.fields_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.appendAssumeCapacity(args.decls_len);
        }
        astgen.instructions.set(@intFromEnum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .union_decl,
                .small = @bitCast(Zir.Inst.UnionDecl.Small{
                    .has_tag_type = args.tag_type != .none,
                    .has_captures_len = args.captures_len != 0,
                    .has_body_len = args.body_len != 0,
                    .has_fields_len = args.fields_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .name_strategy = gz.anon_name_strategy,
                    .layout = args.layout,
                    .auto_enum_tag = args.auto_enum_tag,
                    .any_aligned_fields = args.any_aligned_fields,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn setEnum(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        tag_type: Zir.Inst.Ref,
        captures_len: u32,
        body_len: u32,
        fields_len: u32,
        decls_len: u32,
        nonexhaustive: bool,
        fields_hash: std.zig.SrcHash,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        assert(args.src_node != .root);

        const fields_hash_arr: [4]u32 = @bitCast(args.fields_hash);

        try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.EnumDecl).@"struct".fields.len + 5);
        const payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.EnumDecl{
            .fields_hash_0 = fields_hash_arr[0],
            .fields_hash_1 = fields_hash_arr[1],
            .fields_hash_2 = fields_hash_arr[2],
            .fields_hash_3 = fields_hash_arr[3],
            .src_line = astgen.source_line,
            .src_node = args.src_node,
        });

        if (args.tag_type != .none) {
            astgen.extra.appendAssumeCapacity(@intFromEnum(args.tag_type));
        }
        if (args.captures_len != 0) {
            astgen.extra.appendAssumeCapacity(args.captures_len);
        }
        if (args.body_len != 0) {
            astgen.extra.appendAssumeCapacity(args.body_len);
        }
        if (args.fields_len != 0) {
            astgen.extra.appendAssumeCapacity(args.fields_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.appendAssumeCapacity(args.decls_len);
        }
        astgen.instructions.set(@intFromEnum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .enum_decl,
                .small = @bitCast(Zir.Inst.EnumDecl.Small{
                    .has_tag_type = args.tag_type != .none,
                    .has_captures_len = args.captures_len != 0,
                    .has_body_len = args.body_len != 0,
                    .has_fields_len = args.fields_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .name_strategy = gz.anon_name_strategy,
                    .nonexhaustive = args.nonexhaustive,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn setOpaque(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        captures_len: u32,
        decls_len: u32,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        assert(args.src_node != .root);

        try astgen.extra.ensureUnusedCapacity(gpa, @typeInfo(Zir.Inst.OpaqueDecl).@"struct".fields.len + 2);
        const payload_index = astgen.addExtraAssumeCapacity(Zir.Inst.OpaqueDecl{
            .src_line = astgen.source_line,
            .src_node = args.src_node,
        });

        if (args.captures_len != 0) {
            astgen.extra.appendAssumeCapacity(args.captures_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.appendAssumeCapacity(args.decls_len);
        }
        astgen.instructions.set(@intFromEnum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .opaque_decl,
                .small = @bitCast(Zir.Inst.OpaqueDecl.Small{
                    .has_captures_len = args.captures_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .name_strategy = gz.anon_name_strategy,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn add(gz: *GenZir, inst: Zir.Inst) !Zir.Inst.Ref {
        return (try gz.addAsIndex(inst)).toRef();
    }

    fn addAsIndex(gz: *GenZir, inst: Zir.Inst) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensureUnusedCapacity(gpa, 1);
        try gz.astgen.instructions.ensureUnusedCapacity(gpa, 1);

        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.appendAssumeCapacity(inst);
        gz.instructions.appendAssumeCapacity(new_index);
        return new_index;
    }

    fn reserveInstructionIndex(gz: *GenZir) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensureUnusedCapacity(gpa, 1);
        try gz.astgen.instructions.ensureUnusedCapacity(gpa, 1);

        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.len += 1;
        gz.instructions.appendAssumeCapacity(new_index);
        return new_index;
    }

    fn addRet(gz: *GenZir, ri: ResultInfo, operand: Zir.Inst.Ref, node: Ast.Node.Index) !void {
        switch (ri.rl) {
            .ptr => |ptr_res| _ = try gz.addUnNode(.ret_load, ptr_res.inst, node),
            .coerced_ty => _ = try gz.addUnNode(.ret_node, operand, node),
            else => unreachable,
        }
    }

    fn addDbgVar(gz: *GenZir, tag: Zir.Inst.Tag, name: Zir.NullTerminatedString, inst: Zir.Inst.Ref) !void {
        if (gz.is_comptime) return;

        _ = try gz.add(.{ .tag = tag, .data = .{
            .str_op = .{
                .str = name,
                .operand = inst,
            },
        } });
    }
};

/// This can only be for short-lived references; the memory becomes invalidated
/// when another string is added.
fn nullTerminatedString(astgen: AstGen, index: Zir.NullTerminatedString) [*:0]const u8 {
    return @ptrCast(astgen.string_bytes.items[@intFromEnum(index)..]);
}

/// Local variables shadowing detection, including function parameters.
fn detectLocalShadowing(
    astgen: *AstGen,
    scope: *Scope,
    ident_name: Zir.NullTerminatedString,
    name_token: Ast.TokenIndex,
    token_bytes: []const u8,
    id_cat: Scope.IdCat,
) !void {
    const gpa = astgen.gpa;
    if (token_bytes[0] != '@' and isPrimitive(token_bytes)) {
        return astgen.failTokNotes(name_token, "name shadows primitive '{s}'", .{
            token_bytes,
        }, &[_]u32{
            try astgen.errNoteTok(name_token, "consider using @\"{s}\" to disambiguate", .{
                token_bytes,
            }),
        });
    }

    var s = scope;
    var outer_scope = false;
    while (true) switch (s.tag) {
        .local_val => {
            const local_val = s.cast(Scope.LocalVal).?;
            if (local_val.name == ident_name) {
                const name_slice = mem.span(astgen.nullTerminatedString(ident_name));
                const name = try gpa.dupe(u8, name_slice);
                defer gpa.free(name);
                if (outer_scope) {
                    return astgen.failTokNotes(name_token, "{s} '{s}' shadows {s} from outer scope", .{
                        @tagName(id_cat), name, @tagName(local_val.id_cat),
                    }, &[_]u32{
                        try astgen.errNoteTok(
                            local_val.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                }
                return astgen.failTokNotes(name_token, "redeclaration of {s} '{s}'", .{
                    @tagName(local_val.id_cat), name,
                }, &[_]u32{
                    try astgen.errNoteTok(
                        local_val.token_src,
                        "previous declaration here",
                        .{},
                    ),
                });
            }
            s = local_val.parent;
        },
        .local_ptr => {
            const local_ptr = s.cast(Scope.LocalPtr).?;
            if (local_ptr.name == ident_name) {
                const name_slice = mem.span(astgen.nullTerminatedString(ident_name));
                const name = try gpa.dupe(u8, name_slice);
                defer gpa.free(name);
                if (outer_scope) {
                    return astgen.failTokNotes(name_token, "{s} '{s}' shadows {s} from outer scope", .{
                        @tagName(id_cat), name, @tagName(local_ptr.id_cat),
                    }, &[_]u32{
                        try astgen.errNoteTok(
                            local_ptr.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                }
                return astgen.failTokNotes(name_token, "redeclaration of {s} '{s}'", .{
                    @tagName(local_ptr.id_cat), name,
                }, &[_]u32{
                    try astgen.errNoteTok(
                        local_ptr.token_src,
                        "previous declaration here",
                        .{},
                    ),
                });
            }
            s = local_ptr.parent;
        },
        .namespace => {
            outer_scope = true;
            const ns = s.cast(Scope.Namespace).?;
            const decl_node = ns.decls.get(ident_name) orelse {
                s = ns.parent;
                continue;
            };
            const name_slice = mem.span(astgen.nullTerminatedString(ident_name));
            const name = try gpa.dupe(u8, name_slice);
            defer gpa.free(name);
            return astgen.failTokNotes(name_token, "{s} shadows declaration of '{s}'", .{
                @tagName(id_cat), name,
            }, &[_]u32{
                try astgen.errNoteNode(decl_node, "declared here", .{}),
            });
        },
        .gen_zir => {
            s = s.cast(GenZir).?.parent;
            outer_scope = true;
        },
        .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
        .top => break,
    };
}

const LineColumn = struct { u32, u32 };

/// Advances the source cursor to the main token of `node` if not in comptime scope.
/// Usually paired with `emitDbgStmt`.
fn maybeAdvanceSourceCursorToMainToken(gz: *GenZir, node: Ast.Node.Index) LineColumn {
    if (gz.is_comptime) return .{ gz.astgen.source_line - gz.decl_line, gz.astgen.source_column };

    const tree = gz.astgen.tree;
    const node_start = tree.tokenStart(tree.nodeMainToken(node));
    gz.astgen.advanceSourceCursor(node_start);

    return .{ gz.astgen.source_line - gz.decl_line, gz.astgen.source_column };
}

/// Advances the source cursor to the beginning of `node`.
fn advanceSourceCursorToNode(astgen: *AstGen, node: Ast.Node.Index) void {
    const tree = astgen.tree;
    const node_start = tree.tokenStart(tree.firstToken(node));
    astgen.advanceSourceCursor(node_start);
}

/// Advances the source cursor to an absolute byte offset `end` in the file.
fn advanceSourceCursor(astgen: *AstGen, end: usize) void {
    const source = astgen.tree.source;
    var i = astgen.source_offset;
    var line = astgen.source_line;
    var column = astgen.source_column;
    assert(i <= end);
    while (i < end) : (i += 1) {
        if (source[i] == '\n') {
            line += 1;
            column = 0;
        } else {
            column += 1;
        }
    }
    astgen.source_offset = i;
    astgen.source_line = line;
    astgen.source_column = column;
}

const SourceCursor = struct {
    offset: u32,
    line: u32,
    column: u32,
};

/// Get the current source cursor, to be restored later with `restoreSourceCursor`.
/// This is useful when analyzing source code out-of-order.
fn saveSourceCursor(astgen: *const AstGen) SourceCursor {
    return .{
        .offset = astgen.source_offset,
        .line = astgen.source_line,
        .column = astgen.source_column,
    };
}
fn restoreSourceCursor(astgen: *AstGen, cursor: SourceCursor) void {
    astgen.source_offset = cursor.offset;
    astgen.source_line = cursor.line;
    astgen.source_column = cursor.column;
}

/// Detects name conflicts for decls and fields, and populates `namespace.decls` with all named declarations.
/// Returns the number of declarations in the namespace, including unnamed declarations (e.g. `comptime` decls).
fn scanContainer(
    astgen: *AstGen,
    namespace: *Scope.Namespace,
    members: []const Ast.Node.Index,
    container_kind: enum { @"struct", @"union", @"enum", @"opaque" },
) !u32 {
    const gpa = astgen.gpa;
    const tree = astgen.tree;

    var any_invalid_declarations = false;

    // This type forms a linked list of source tokens declaring the same name.
    const NameEntry = struct {
        tok: Ast.TokenIndex,
        /// Using a linked list here simplifies memory management, and is acceptable since
        ///ewntries are only allocated in error situations. The entries are allocated into the
        /// AstGen arena.
        next: ?*@This(),
    };

    // The maps below are allocated into this SFBA to avoid using the GPA for small namespaces.
    var sfba_state = std.heap.stackFallback(512, astgen.gpa);
    const sfba = sfba_state.get();

    var names: std.AutoArrayHashMapUnmanaged(Zir.NullTerminatedString, NameEntry) = .empty;
    var test_names: std.AutoArrayHashMapUnmanaged(Zir.NullTerminatedString, NameEntry) = .empty;
    var decltest_names: std.AutoArrayHashMapUnmanaged(Zir.NullTerminatedString, NameEntry) = .empty;
    defer {
        names.deinit(sfba);
        test_names.deinit(sfba);
        decltest_names.deinit(sfba);
    }

    var any_duplicates = false;
    var decl_count: u32 = 0;
    for (members) |member_node| {
        const Kind = enum { decl, field };
        const kind: Kind, const name_token = switch (tree.nodeTag(member_node)) {
            .container_field_init,
            .container_field_align,
            .container_field,
            => blk: {
                var full = tree.fullContainerField(member_node).?;
                switch (container_kind) {
                    .@"struct", .@"opaque" => {},
                    .@"union", .@"enum" => full.convertToNonTupleLike(astgen.tree),
                }
                if (full.ast.tuple_like) continue;
                break :blk .{ .field, full.ast.main_token };
            },

            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => blk: {
                decl_count += 1;
                break :blk .{ .decl, tree.nodeMainToken(member_node) + 1 };
            },

            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto,
            .fn_decl,
            => blk: {
                decl_count += 1;
                const ident = tree.nodeMainToken(member_node) + 1;
                if (tree.tokenTag(ident) != .identifier) {
                    try astgen.appendErrorNode(member_node, "missing function name", .{});
                    any_invalid_declarations = true;
                    continue;
                }
                break :blk .{ .decl, ident };
            },

            .@"comptime", .@"usingnamespace" => {
                decl_count += 1;
                continue;
            },

            .test_decl => {
                decl_count += 1;
                // We don't want shadowing detection here, and test names work a bit differently, so
                // we must do the redeclaration detection ourselves.
                const test_name_token = tree.nodeMainToken(member_node) + 1;
                const new_ent: NameEntry = .{
                    .tok = test_name_token,
                    .next = null,
                };
                switch (tree.tokenTag(test_name_token)) {
                    else => {}, // unnamed test
                    .string_literal => {
                        const name = try astgen.strLitAsString(test_name_token);
                        const gop = try test_names.getOrPut(sfba, name.index);
                        if (gop.found_existing) {
                            var e = gop.value_ptr;
                            while (e.next) |n| e = n;
                            e.next = try astgen.arena.create(NameEntry);
                            e.next.?.* = new_ent;
                            any_duplicates = true;
                        } else {
                            gop.value_ptr.* = new_ent;
                        }
                    },
                    .identifier => {
                        const name = try astgen.identAsString(test_name_token);
                        const gop = try decltest_names.getOrPut(sfba, name);
                        if (gop.found_existing) {
                            var e = gop.value_ptr;
                            while (e.next) |n| e = n;
                            e.next = try astgen.arena.create(NameEntry);
                            e.next.?.* = new_ent;
                            any_duplicates = true;
                        } else {
                            gop.value_ptr.* = new_ent;
                        }
                    },
                }
                continue;
            },

            else => unreachable,
        };

        const name_str_index = try astgen.identAsString(name_token);

        if (kind == .decl) {
            // Put the name straight into `decls`, even if there are compile errors.
            // This avoids incorrect "undeclared identifier" errors later on.
            try namespace.decls.put(gpa, name_str_index, member_node);
        }

        {
            const gop = try names.getOrPut(sfba, name_str_index);
            const new_ent: NameEntry = .{
                .tok = name_token,
                .next = null,
            };
            if (gop.found_existing) {
                var e = gop.value_ptr;
                while (e.next) |n| e = n;
                e.next = try astgen.arena.create(NameEntry);
                e.next.?.* = new_ent;
                any_duplicates = true;
                continue;
            } else {
                gop.value_ptr.* = new_ent;
            }
        }

        // For fields, we only needed the duplicate check! Decls have some more checks to do, though.
        switch (kind) {
            .decl => {},
            .field => continue,
        }

        const token_bytes = astgen.tree.tokenSlice(name_token);
        if (token_bytes[0] != '@' and isPrimitive(token_bytes)) {
            try astgen.appendErrorTokNotes(name_token, "name shadows primitive '{s}'", .{
                token_bytes,
            }, &.{
                try astgen.errNoteTok(name_token, "consider using @\"{s}\" to disambiguate", .{
                    token_bytes,
                }),
            });
            any_invalid_declarations = true;
            continue;
        }

        var s = namespace.parent;
        while (true) switch (s.tag) {
            .local_val => {
                const local_val = s.cast(Scope.LocalVal).?;
                if (local_val.name == name_str_index) {
                    try astgen.appendErrorTokNotes(name_token, "declaration '{s}' shadows {s} from outer scope", .{
                        token_bytes, @tagName(local_val.id_cat),
                    }, &.{
                        try astgen.errNoteTok(
                            local_val.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                    any_invalid_declarations = true;
                    break;
                }
                s = local_val.parent;
            },
            .local_ptr => {
                const local_ptr = s.cast(Scope.LocalPtr).?;
                if (local_ptr.name == name_str_index) {
                    try astgen.appendErrorTokNotes(name_token, "declaration '{s}' shadows {s} from outer scope", .{
                        token_bytes, @tagName(local_ptr.id_cat),
                    }, &.{
                        try astgen.errNoteTok(
                            local_ptr.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                    any_invalid_declarations = true;
                    break;
                }
                s = local_ptr.parent;
            },
            .namespace => s = s.cast(Scope.Namespace).?.parent,
            .gen_zir => s = s.cast(GenZir).?.parent,
            .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
            .top => break,
        };
    }

    if (!any_duplicates) {
        if (any_invalid_declarations) return error.AnalysisFail;
        return decl_count;
    }

    for (names.keys(), names.values()) |name, first| {
        if (first.next == null) continue;
        var notes: std.ArrayListUnmanaged(u32) = .empty;
        var prev: NameEntry = first;
        while (prev.next) |cur| : (prev = cur.*) {
            try notes.append(astgen.arena, try astgen.errNoteTok(cur.tok, "duplicate name here", .{}));
        }
        try notes.append(astgen.arena, try astgen.errNoteNode(namespace.node, "{s} declared here", .{@tagName(container_kind)}));
        const name_duped = try astgen.arena.dupe(u8, mem.span(astgen.nullTerminatedString(name)));
        try astgen.appendErrorTokNotes(first.tok, "duplicate {s} member name '{s}'", .{ @tagName(container_kind), name_duped }, notes.items);
        any_invalid_declarations = true;
    }

    for (test_names.keys(), test_names.values()) |name, first| {
        if (first.next == null) continue;
        var notes: std.ArrayListUnmanaged(u32) = .empty;
        var prev: NameEntry = first;
        while (prev.next) |cur| : (prev = cur.*) {
            try notes.append(astgen.arena, try astgen.errNoteTok(cur.tok, "duplicate test here", .{}));
        }
        try notes.append(astgen.arena, try astgen.errNoteNode(namespace.node, "{s} declared here", .{@tagName(container_kind)}));
        const name_duped = try astgen.arena.dupe(u8, mem.span(astgen.nullTerminatedString(name)));
        try astgen.appendErrorTokNotes(first.tok, "duplicate test name '{s}'", .{name_duped}, notes.items);
        any_invalid_declarations = true;
    }

    for (decltest_names.keys(), decltest_names.values()) |name, first| {
        if (first.next == null) continue;
        var notes: std.ArrayListUnmanaged(u32) = .empty;
        var prev: NameEntry = first;
        while (prev.next) |cur| : (prev = cur.*) {
            try notes.append(astgen.arena, try astgen.errNoteTok(cur.tok, "duplicate decltest here", .{}));
        }
        try notes.append(astgen.arena, try astgen.errNoteNode(namespace.node, "{s} declared here", .{@tagName(container_kind)}));
        const name_duped = try astgen.arena.dupe(u8, mem.span(astgen.nullTerminatedString(name)));
        try astgen.appendErrorTokNotes(first.tok, "duplicate decltest '{s}'", .{name_duped}, notes.items);
        any_invalid_declarations = true;
    }

    assert(any_invalid_declarations);
    return error.AnalysisFail;
}

/// Assumes capacity for body has already been added. Needed capacity taking into
/// account fixups can be found with `countBodyLenAfterFixups`.
fn appendBodyWithFixups(astgen: *AstGen, body: []const Zir.Inst.Index) void {
    return appendBodyWithFixupsArrayList(astgen, &astgen.extra, body);
}

fn appendBodyWithFixupsArrayList(
    astgen: *AstGen,
    list: *std.ArrayListUnmanaged(u32),
    body: []const Zir.Inst.Index,
) void {
    astgen.appendBodyWithFixupsExtraRefsArrayList(list, body, &.{});
}

fn appendBodyWithFixupsExtraRefsArrayList(
    astgen: *AstGen,
    list: *std.ArrayListUnmanaged(u32),
    body: []const Zir.Inst.Index,
    extra_refs: []const Zir.Inst.Index,
) void {
    for (extra_refs) |extra_inst| {
        if (astgen.ref_table.fetchRemove(extra_inst)) |kv| {
            appendPossiblyRefdBodyInst(astgen, list, kv.value);
        }
    }
    for (body) |body_inst| {
        appendPossiblyRefdBodyInst(astgen, list, body_inst);
    }
}

fn appendPossiblyRefdBodyInst(
    astgen: *AstGen,
    list: *std.ArrayListUnmanaged(u32),
    body_inst: Zir.Inst.Index,
) void {
    list.appendAssumeCapacity(@intFromEnum(body_inst));
    const kv = astgen.ref_table.fetchRemove(body_inst) orelse return;
    const ref_inst = kv.value;
    return appendPossiblyRefdBodyInst(astgen, list, ref_inst);
}

fn countBodyLenAfterFixups(astgen: *AstGen, body: []const Zir.Inst.Index) u32 {
    return astgen.countBodyLenAfterFixupsExtraRefs(body, &.{});
}

/// Return the number of instructions in `body` after prepending the `ref` instructions in `ref_table`.
/// As well as all instructions in `body`, we also prepend `ref`s of any instruction in `extra_refs`.
/// For instance, if an index has been reserved with a special meaning to a child block, it must be
/// passed to `extra_refs` to ensure `ref`s of that index are added correctly.
fn countBodyLenAfterFixupsExtraRefs(astgen: *AstGen, body: []const Zir.Inst.Index, extra_refs: []const Zir.Inst.Index) u32 {
    var count = body.len;
    for (body) |body_inst| {
        var check_inst = body_inst;
        while (astgen.ref_table.get(check_inst)) |ref_inst| {
            count += 1;
            check_inst = ref_inst;
        }
    }
    for (extra_refs) |extra_inst| {
        var check_inst = extra_inst;
        while (astgen.ref_table.get(check_inst)) |ref_inst| {
            count += 1;
            check_inst = ref_inst;
        }
    }
    return @intCast(count);
}

fn emitDbgStmt(gz: *GenZir, lc: LineColumn) !void {
    if (gz.is_comptime) return;
    if (gz.instructions.items.len > gz.instructions_top) {
        const astgen = gz.astgen;
        const last = gz.instructions.items[gz.instructions.items.len - 1];
        if (astgen.instructions.items(.tag)[@intFromEnum(last)] == .dbg_stmt) {
            astgen.instructions.items(.data)[@intFromEnum(last)].dbg_stmt = .{
                .line = lc[0],
                .column = lc[1],
            };
            return;
        }
    }

    _ = try gz.add(.{ .tag = .dbg_stmt, .data = .{
        .dbg_stmt = .{
            .line = lc[0],
            .column = lc[1],
        },
    } });
}

/// In some cases, Sema expects us to generate a `dbg_stmt` at the instruction
/// *index* directly preceding the next instruction (e.g. if a call is %10, it
/// expects a dbg_stmt at %9). TODO: this logic may allow redundant dbg_stmt
/// instructions; fix up Sema so we don't need it!
fn emitDbgStmtForceCurrentIndex(gz: *GenZir, lc: LineColumn) !void {
    const astgen = gz.astgen;
    if (gz.instructions.items.len > gz.instructions_top and
        @intFromEnum(gz.instructions.items[gz.instructions.items.len - 1]) == astgen.instructions.len - 1)
    {
        const last = astgen.instructions.len - 1;
        if (astgen.instructions.items(.tag)[last] == .dbg_stmt) {
            astgen.instructions.items(.data)[last].dbg_stmt = .{
                .line = lc[0],
                .column = lc[1],
            };
            return;
        }
    }

    _ = try gz.add(.{ .tag = .dbg_stmt, .data = .{
        .dbg_stmt = .{
            .line = lc[0],
            .column = lc[1],
        },
    } });
}

fn lowerAstErrors(astgen: *AstGen) !void {
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    assert(tree.errors.len > 0);

    var msg: std.ArrayListUnmanaged(u8) = .empty;
    defer msg.deinit(gpa);

    var notes: std.ArrayListUnmanaged(u32) = .empty;
    defer notes.deinit(gpa);

    const token_starts = tree.tokens.items(.start);
    const token_tags = tree.tokens.items(.tag);
    const parse_err = tree.errors[0];
    const tok = parse_err.token + @intFromBool(parse_err.token_is_prev);
    const tok_start = token_starts[tok];
    const start_char = tree.source[tok_start];

    if (token_tags[tok] == .invalid and
        (start_char == '\"' or start_char == '\'' or start_char == '/' or mem.startsWith(u8, tree.source[tok_start..], "\\\\")))
    {
        const tok_len: u32 = @intCast(tree.tokenSlice(tok).len);
        const tok_end = tok_start + tok_len;
        const bad_off = blk: {
            var idx = tok_start;
            while (idx < tok_end) : (idx += 1) {
                switch (tree.source[idx]) {
                    0x00...0x09, 0x0b...0x1f, 0x7f => break,
                    else => {},
                }
            }
            break :blk idx - tok_start;
        };

        const err: Ast.Error = .{
            .tag = Ast.Error.Tag.invalid_byte,
            .token = tok,
            .extra = .{ .offset = bad_off },
        };
        msg.clearRetainingCapacity();
        try tree.renderError(err, msg.writer(gpa));
        return try astgen.appendErrorTokNotesOff(tok, bad_off, "{s}", .{msg.items}, notes.items);
    }

    var cur_err = tree.errors[0];
    for (tree.errors[1..]) |err| {
        if (err.is_note) {
            try tree.renderError(err, msg.writer(gpa));
            try notes.append(gpa, try astgen.errNoteTok(err.token, "{s}", .{msg.items}));
        } else {
            // Flush error
            const extra_offset = tree.errorOffset(cur_err);
            try tree.renderError(cur_err, msg.writer(gpa));
            try astgen.appendErrorTokNotesOff(cur_err.token, extra_offset, "{s}", .{msg.items}, notes.items);
            notes.clearRetainingCapacity();
            cur_err = err;

            // TODO: `Parse` currently does not have good error recovery mechanisms, so the remaining errors could be bogus.
            // As such, we'll ignore all remaining errors for now. We should improve `Parse` so that we can report all the errors.
            return;
        }
        msg.clearRetainingCapacity();
    }

    // Flush error
    const extra_offset = tree.errorOffset(cur_err);
    try tree.renderError(cur_err, msg.writer(gpa));
    try astgen.appendErrorTokNotesOff(cur_err.token, extra_offset, "{s}", .{msg.items}, notes.items);
}

const DeclarationName = union(enum) {
    named: Ast.TokenIndex,
    named_test: Ast.TokenIndex,
    decltest: Ast.TokenIndex,
    unnamed_test,
    @"comptime",
    @"usingnamespace",
};

fn addFailedDeclaration(
    wip_members: *WipMembers,
    gz: *GenZir,
    kind: Zir.Inst.Declaration.Unwrapped.Kind,
    name: Zir.NullTerminatedString,
    src_node: Ast.Node.Index,
    is_pub: bool,
) !void {
    const decl_inst = try gz.makeDeclaration(src_node);
    wip_members.nextDecl(decl_inst);

    var dummy_gz = gz.makeSubBlock(&gz.base);

    var value_gz = gz.makeSubBlock(&gz.base); // scope doesn't matter here
    _ = try value_gz.add(.{
        .tag = .extended,
        .data = .{ .extended = .{
            .opcode = .astgen_error,
            .small = undefined,
            .operand = undefined,
        } },
    });

    try setDeclaration(decl_inst, .{
        .src_hash = @splat(0), // use a fixed hash to represent an AstGen failure; we don't care about source changes if AstGen still failed!
        .src_line = gz.astgen.source_line,
        .src_column = gz.astgen.source_column,
        .kind = kind,
        .name = name,
        .is_pub = is_pub,
        .is_threadlocal = false,
        .linkage = .normal,
        .type_gz = &dummy_gz,
        .align_gz = &dummy_gz,
        .linksection_gz = &dummy_gz,
        .addrspace_gz = &dummy_gz,
        .value_gz = &value_gz,
    });
}

/// Sets all extra data for a `declaration` instruction.
/// Unstacks `type_gz`, `align_gz`, `linksection_gz`, `addrspace_gz`, and `value_gz`.
fn setDeclaration(
    decl_inst: Zir.Inst.Index,
    args: struct {
        src_hash: std.zig.SrcHash,
        src_line: u32,
        src_column: u32,

        kind: Zir.Inst.Declaration.Unwrapped.Kind,
        name: Zir.NullTerminatedString,
        is_pub: bool,
        is_threadlocal: bool,
        linkage: Zir.Inst.Declaration.Unwrapped.Linkage,
        lib_name: Zir.NullTerminatedString = .empty,

        type_gz: *GenZir,
        /// Must be stacked on `type_gz`.
        align_gz: *GenZir,
        /// Must be stacked on `align_gz`.
        linksection_gz: *GenZir,
        /// Must be stacked on `linksection_gz`.
        addrspace_gz: *GenZir,
        /// Must be stacked on `addrspace_gz` and have nothing stacked on top of it.
        value_gz: *GenZir,
    },
) !void {
    const astgen = args.value_gz.astgen;
    const gpa = astgen.gpa;

    const type_body = args.type_gz.instructionsSliceUpto(args.align_gz);
    const align_body = args.align_gz.instructionsSliceUpto(args.linksection_gz);
    const linksection_body = args.linksection_gz.instructionsSliceUpto(args.addrspace_gz);
    const addrspace_body = args.addrspace_gz.instructionsSliceUpto(args.value_gz);
    const value_body = args.value_gz.instructionsSlice();

    const has_name = args.name != .empty;
    const has_lib_name = args.lib_name != .empty;
    const has_type_body = type_body.len != 0;
    const has_special_body = align_body.len != 0 or linksection_body.len != 0 or addrspace_body.len != 0;
    const has_value_body = value_body.len != 0;

    const id: Zir.Inst.Declaration.Flags.Id = switch (args.kind) {
        .unnamed_test => .unnamed_test,
        .@"test" => .@"test",
        .decltest => .decltest,
        .@"comptime" => .@"comptime",
        .@"usingnamespace" => if (args.is_pub) .pub_usingnamespace else .@"usingnamespace",
        .@"const" => switch (args.linkage) {
            .normal => if (args.is_pub) id: {
                if (has_special_body) break :id .pub_const;
                if (has_type_body) break :id .pub_const_typed;
                break :id .pub_const_simple;
            } else id: {
                if (has_special_body) break :id .@"const";
                if (has_type_body) break :id .const_typed;
                break :id .const_simple;
            },
            .@"extern" => if (args.is_pub) id: {
                if (has_lib_name) break :id .pub_extern_const;
                if (has_special_body) break :id .pub_extern_const;
                break :id .pub_extern_const_simple;
            } else id: {
                if (has_lib_name) break :id .extern_const;
                if (has_special_body) break :id .extern_const;
                break :id .extern_const_simple;
            },
            .@"export" => if (args.is_pub) .pub_export_const else .export_const,
        },
        .@"var" => switch (args.linkage) {
            .normal => if (args.is_pub) id: {
                if (args.is_threadlocal) break :id .pub_var_threadlocal;
                if (has_special_body) break :id .pub_var;
                if (has_type_body) break :id .pub_var;
                break :id .pub_var_simple;
            } else id: {
                if (args.is_threadlocal) break :id .var_threadlocal;
                if (has_special_body) break :id .@"var";
                if (has_type_body) break :id .@"var";
                break :id .var_simple;
            },
            .@"extern" => if (args.is_pub) id: {
                if (args.is_threadlocal) break :id .pub_extern_var_threadlocal;
                break :id .pub_extern_var;
            } else id: {
                if (args.is_threadlocal) break :id .extern_var_threadlocal;
                break :id .extern_var;
            },
            .@"export" => if (args.is_pub) id: {
                if (args.is_threadlocal) break :id .pub_export_var_threadlocal;
                break :id .pub_export_var;
            } else id: {
                if (args.is_threadlocal) break :id .export_var_threadlocal;
                break :id .export_var;
            },
        },
    };

    assert(id.hasTypeBody() or !has_type_body);
    assert(id.hasSpecialBodies() or !has_special_body);
    assert(id.hasValueBody() == has_value_body);
    assert(id.linkage() == args.linkage);
    assert(id.hasName() == has_name);
    assert(id.hasLibName() or !has_lib_name);
    assert(id.isPub() == args.is_pub);
    assert(id.isThreadlocal() == args.is_threadlocal);

    const type_len = astgen.countBodyLenAfterFixups(type_body);
    const align_len = astgen.countBodyLenAfterFixups(align_body);
    const linksection_len = astgen.countBodyLenAfterFixups(linksection_body);
    const addrspace_len = astgen.countBodyLenAfterFixups(addrspace_body);
    const value_len = astgen.countBodyLenAfterFixups(value_body);

    const src_hash_arr: [4]u32 = @bitCast(args.src_hash);
    const flags: Zir.Inst.Declaration.Flags = .{
        .src_line = @intCast(args.src_line),
        .src_column = @intCast(args.src_column),
        .id = id,
    };
    const flags_arr: [2]u32 = @bitCast(flags);

    const need_extra: usize =
        @typeInfo(Zir.Inst.Declaration).@"struct".fields.len +
        @as(usize, @intFromBool(id.hasName())) +
        @as(usize, @intFromBool(id.hasLibName())) +
        @as(usize, @intFromBool(id.hasTypeBody())) +
        3 * @as(usize, @intFromBool(id.hasSpecialBodies())) +
        @as(usize, @intFromBool(id.hasValueBody())) +
        type_len + align_len + linksection_len + addrspace_len + value_len;

    try astgen.extra.ensureUnusedCapacity(gpa, need_extra);

    const extra: Zir.Inst.Declaration = .{
        .src_hash_0 = src_hash_arr[0],
        .src_hash_1 = src_hash_arr[1],
        .src_hash_2 = src_hash_arr[2],
        .src_hash_3 = src_hash_arr[3],
        .flags_0 = flags_arr[0],
        .flags_1 = flags_arr[1],
    };
    astgen.instructions.items(.data)[@intFromEnum(decl_inst)].declaration.payload_index =
        astgen.addExtraAssumeCapacity(extra);

    if (id.hasName()) {
        astgen.extra.appendAssumeCapacity(@intFromEnum(args.name));
    }
    if (id.hasLibName()) {
        astgen.extra.appendAssumeCapacity(@intFromEnum(args.lib_name));
    }
    if (id.hasTypeBody()) {
        astgen.extra.appendAssumeCapacity(type_len);
    }
    if (id.hasSpecialBodies()) {
        astgen.extra.appendSliceAssumeCapacity(&.{
            align_len,
            linksection_len,
            addrspace_len,
        });
    }
    if (id.hasValueBody()) {
        astgen.extra.appendAssumeCapacity(value_len);
    }

    astgen.appendBodyWithFixups(type_body);
    astgen.appendBodyWithFixups(align_body);
    astgen.appendBodyWithFixups(linksection_body);
    astgen.appendBodyWithFixups(addrspace_body);
    astgen.appendBodyWithFixups(value_body);

    args.value_gz.unstack();
    args.addrspace_gz.unstack();
    args.linksection_gz.unstack();
    args.align_gz.unstack();
    args.type_gz.unstack();
}

/// Given a list of instructions, returns a list of all instructions which are a `ref` of one of the originals,
/// from `astgen.ref_table`, non-recursively. The entries are removed from `astgen.ref_table`, and the returned
/// slice can then be treated as its own body, to append `ref` instructions to a body other than the one they
/// would normally exist in.
///
/// This is used when lowering functions. Very rarely, the callconv expression, align expression, etc may reference
/// function parameters via `&param`; in this case, we need to lower to a `ref` instruction in the callconv/align/etc
/// body, rather than in the declaration body. However, we don't append these bodies to `extra` until we've evaluated
/// *all* of the bodies into a big `GenZir` stack. Therefore, we use this function to pull out these per-body `ref`
/// instructions which must be emitted.
fn fetchRemoveRefEntries(astgen: *AstGen, param_insts: []const Zir.Inst.Index) ![]Zir.Inst.Index {
    var refs: std.ArrayListUnmanaged(Zir.Inst.Index) = .empty;
    for (param_insts) |param_inst| {
        if (astgen.ref_table.fetchRemove(param_inst)) |kv| {
            try refs.append(astgen.arena, kv.value);
        }
    }
    return refs.items;
}

test {
    _ = &generate;
}
//! AstRlAnnotate is a simple pass which runs over the AST before AstGen to
//! determine which expressions require result locations.
//!
//! In some cases, AstGen can choose whether to provide a result pointer or to
//! just use standard `break` instructions from a block. The latter choice can
//! result in more efficient ZIR and runtime code, but does not allow for RLS to
//! occur. Thus, we want to provide a real result pointer (from an alloc) only
//! when necessary.
//!
//! To achieve this, we need to determine which expressions require a result
//! pointer. This pass is responsible for analyzing all syntax forms which may
//! provide a result location and, if sub-expressions consume this result
//! pointer non-trivially (e.g. writing through field pointers), marking the
//! node as requiring a result location.

const std = @import("std");
const AstRlAnnotate = @This();
const Ast = std.zig.Ast;
const Allocator = std.mem.Allocator;
const AutoHashMapUnmanaged = std.AutoHashMapUnmanaged;
const BuiltinFn = std.zig.BuiltinFn;
const assert = std.debug.assert;

gpa: Allocator,
arena: Allocator,
tree: *const Ast,

/// Certain nodes are placed in this set under the following conditions:
/// * if-else: either branch consumes the result location
/// * labeled block: any break consumes the result location
/// * switch: any prong consumes the result location
/// * orelse/catch: the RHS expression consumes the result location
/// * while/for: any break consumes the result location
/// * @as: the second operand consumes the result location
/// * const: the init expression consumes the result location
/// * return: the return expression consumes the result location
nodes_need_rl: RlNeededSet = .{},

pub const RlNeededSet = AutoHashMapUnmanaged(Ast.Node.Index, void);

const ResultInfo = packed struct {
    /// Do we have a known result type?
    have_type: bool,
    /// Do we (potentially) have a result pointer? Note that this pointer's type
    /// may not be known due to it being an inferred alloc.
    have_ptr: bool,

    const none: ResultInfo = .{ .have_type = false, .have_ptr = false };
    const typed_ptr: ResultInfo = .{ .have_type = true, .have_ptr = true };
    const inferred_ptr: ResultInfo = .{ .have_type = false, .have_ptr = true };
    const type_only: ResultInfo = .{ .have_type = true, .have_ptr = false };
};

/// A labeled block or a loop. When this block is broken from, `consumes_res_ptr`
/// should be set if the break expression consumed the result pointer.
const Block = struct {
    parent: ?*Block,
    label: ?[]const u8,
    is_loop: bool,
    ri: ResultInfo,
    consumes_res_ptr: bool,
};

pub fn annotate(gpa: Allocator, arena: Allocator, tree: Ast) Allocator.Error!RlNeededSet {
    var astrl: AstRlAnnotate = .{
        .gpa = gpa,
        .arena = arena,
        .tree = &tree,
    };
    defer astrl.deinit(gpa);

    if (tree.errors.len != 0) {
        // We can't perform analysis on a broken AST. AstGen will not run in
        // this case.
        return .{};
    }

    for (tree.containerDeclRoot().ast.members) |member_node| {
        _ = try astrl.expr(member_node, null, ResultInfo.none);
    }

    return astrl.nodes_need_rl.move();
}

fn deinit(astrl: *AstRlAnnotate, gpa: Allocator) void {
    astrl.nodes_need_rl.deinit(gpa);
}

fn containerDecl(
    astrl: *AstRlAnnotate,
    block: ?*Block,
    full: Ast.full.ContainerDecl,
) !void {
    const tree = astrl.tree;
    switch (tree.tokenTag(full.ast.main_token)) {
        .keyword_struct => {
            if (full.ast.arg.unwrap()) |arg| {
                _ = try astrl.expr(arg, block, ResultInfo.type_only);
            }
            for (full.ast.members) |member_node| {
                _ = try astrl.expr(member_node, block, ResultInfo.none);
            }
        },
        .keyword_union => {
            if (full.ast.arg.unwrap()) |arg| {
                _ = try astrl.expr(arg, block, ResultInfo.type_only);
            }
            for (full.ast.members) |member_node| {
                _ = try astrl.expr(member_node, block, ResultInfo.none);
            }
        },
        .keyword_enum => {
            if (full.ast.arg.unwrap()) |arg| {
                _ = try astrl.expr(arg, block, ResultInfo.type_only);
            }
            for (full.ast.members) |member_node| {
                _ = try astrl.expr(member_node, block, ResultInfo.none);
            }
        },
        .keyword_opaque => {
            for (full.ast.members) |member_node| {
                _ = try astrl.expr(member_node, block, ResultInfo.none);
            }
        },
        else => unreachable,
    }
}

/// Returns true if `rl` provides a result pointer and the expression consumes it.
fn expr(astrl: *AstRlAnnotate, node: Ast.Node.Index, block: ?*Block, ri: ResultInfo) Allocator.Error!bool {
    const tree = astrl.tree;
    switch (tree.nodeTag(node)) {
        .root,
        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        .switch_range,
        .for_range,
        .asm_output,
        .asm_input,
        => unreachable,

        .@"errdefer" => {
            _ = try astrl.expr(tree.nodeData(node).opt_token_and_node[1], block, ResultInfo.none);
            return false;
        },
        .@"defer" => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.none);
            return false;
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => {
            const full = tree.fullContainerField(node).?;
            const type_expr = full.ast.type_expr.unwrap().?;
            _ = try astrl.expr(type_expr, block, ResultInfo.type_only);
            if (full.ast.align_expr.unwrap()) |align_expr| {
                _ = try astrl.expr(align_expr, block, ResultInfo.type_only);
            }
            if (full.ast.value_expr.unwrap()) |value_expr| {
                _ = try astrl.expr(value_expr, block, ResultInfo.type_only);
            }
            return false;
        },
        .@"usingnamespace" => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.type_only);
            return false;
        },
        .test_decl => {
            _ = try astrl.expr(tree.nodeData(node).opt_token_and_node[1], block, ResultInfo.none);
            return false;
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const full = tree.fullVarDecl(node).?;
            const init_ri = if (full.ast.type_node.unwrap()) |type_node| init_ri: {
                _ = try astrl.expr(type_node, block, ResultInfo.type_only);
                break :init_ri ResultInfo.typed_ptr;
            } else ResultInfo.inferred_ptr;
            const init_node = full.ast.init_node.unwrap() orelse {
                // No init node, so we're done.
                return false;
            };
            switch (tree.tokenTag(full.ast.mut_token)) {
                .keyword_const => {
                    const init_consumes_rl = try astrl.expr(init_node, block, init_ri);
                    if (init_consumes_rl) {
                        try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
                    }
                    return false;
                },
                .keyword_var => {
                    // We'll create an alloc either way, so don't care if the
                    // result pointer is consumed.
                    _ = try astrl.expr(init_node, block, init_ri);
                    return false;
                },
                else => unreachable,
            }
        },
        .assign_destructure => {
            const full = tree.assignDestructure(node);
            for (full.ast.variables) |variable_node| {
                _ = try astrl.expr(variable_node, block, ResultInfo.none);
            }
            // We don't need to gather any meaningful data here, because destructures always use RLS
            _ = try astrl.expr(full.ast.value_expr, block, ResultInfo.none);
            return false;
        },
        .assign => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            _ = try astrl.expr(rhs, block, ResultInfo.typed_ptr);
            return false;
        },
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_or,
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
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            _ = try astrl.expr(rhs, block, ResultInfo.none);
            return false;
        },
        .shl, .shr => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            _ = try astrl.expr(rhs, block, ResultInfo.type_only);
            return false;
        },
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
        .shl_sat,
        .bit_and,
        .bit_or,
        .bit_xor,
        .bang_equal,
        .equal_equal,
        .greater_than,
        .greater_or_equal,
        .less_than,
        .less_or_equal,
        .array_cat,
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            _ = try astrl.expr(rhs, block, ResultInfo.none);
            return false;
        },

        .array_mult => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            _ = try astrl.expr(rhs, block, ResultInfo.type_only);
            return false;
        },
        .error_union, .merge_error_sets => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            _ = try astrl.expr(rhs, block, ResultInfo.none);
            return false;
        },
        .bool_and,
        .bool_or,
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.type_only);
            _ = try astrl.expr(rhs, block, ResultInfo.type_only);
            return false;
        },
        .bool_not => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.type_only);
            return false;
        },
        .bit_not, .negation, .negation_wrap => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.none);
            return false;
        },

        // These nodes are leaves and never consume a result location.
        .identifier,
        .string_literal,
        .multiline_string_literal,
        .number_literal,
        .unreachable_literal,
        .asm_simple,
        .@"asm",
        .enum_literal,
        .error_value,
        .anyframe_literal,
        .@"continue",
        .char_literal,
        .error_set_decl,
        => return false,

        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const params = tree.builtinCallParams(&buf, node).?;
            return astrl.builtinCall(block, ri, node, params);
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
            const full = tree.fullCall(&buf, node).?;
            _ = try astrl.expr(full.ast.fn_expr, block, ResultInfo.none);
            for (full.ast.params) |param_node| {
                _ = try astrl.expr(param_node, block, ResultInfo.type_only);
            }
            return switch (tree.nodeTag(node)) {
                .call_one,
                .call_one_comma,
                .call,
                .call_comma,
                => false, // TODO: once function calls are passed result locations this will change
                .async_call_one,
                .async_call_one_comma,
                .async_call,
                .async_call_comma,
                => ri.have_ptr, // always use result ptr for frames
                else => unreachable,
            };
        },

        .@"return" => {
            if (tree.nodeData(node).opt_node.unwrap()) |lhs| {
                const ret_val_consumes_rl = try astrl.expr(lhs, block, ResultInfo.typed_ptr);
                if (ret_val_consumes_rl) {
                    try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
                }
            }
            return false;
        },

        .field_access => {
            const lhs, _ = tree.nodeData(node).node_and_token;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            return false;
        },

        .if_simple, .@"if" => {
            const full = tree.fullIf(node).?;
            if (full.error_token != null or full.payload_token != null) {
                _ = try astrl.expr(full.ast.cond_expr, block, ResultInfo.none);
            } else {
                _ = try astrl.expr(full.ast.cond_expr, block, ResultInfo.type_only); // bool
            }

            if (full.ast.else_expr.unwrap()) |else_expr| {
                const then_uses_rl = try astrl.expr(full.ast.then_expr, block, ri);
                const else_uses_rl = try astrl.expr(else_expr, block, ri);
                const uses_rl = then_uses_rl or else_uses_rl;
                if (uses_rl) try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
                return uses_rl;
            } else {
                _ = try astrl.expr(full.ast.then_expr, block, ResultInfo.none);
                return false;
            }
        },

        .while_simple, .while_cont, .@"while" => {
            const full = tree.fullWhile(node).?;
            const label: ?[]const u8 = if (full.label_token) |label_token| label: {
                break :label try astrl.identString(label_token);
            } else null;
            if (full.error_token != null or full.payload_token != null) {
                _ = try astrl.expr(full.ast.cond_expr, block, ResultInfo.none);
            } else {
                _ = try astrl.expr(full.ast.cond_expr, block, ResultInfo.type_only); // bool
            }
            var new_block: Block = .{
                .parent = block,
                .label = label,
                .is_loop = true,
                .ri = ri,
                .consumes_res_ptr = false,
            };
            if (full.ast.cont_expr.unwrap()) |cont_expr| {
                _ = try astrl.expr(cont_expr, &new_block, ResultInfo.none);
            }
            _ = try astrl.expr(full.ast.then_expr, &new_block, ResultInfo.none);
            const else_consumes_rl = if (full.ast.else_expr.unwrap()) |else_expr| else_rl: {
                break :else_rl try astrl.expr(else_expr, block, ri);
            } else false;
            if (new_block.consumes_res_ptr or else_consumes_rl) {
                try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
                return true;
            } else {
                return false;
            }
        },

        .for_simple, .@"for" => {
            const full = tree.fullFor(node).?;
            const label: ?[]const u8 = if (full.label_token) |label_token| label: {
                break :label try astrl.identString(label_token);
            } else null;
            for (full.ast.inputs) |input| {
                if (tree.nodeTag(input) == .for_range) {
                    const lhs, const opt_rhs = tree.nodeData(input).node_and_opt_node;
                    _ = try astrl.expr(lhs, block, ResultInfo.type_only);
                    if (opt_rhs.unwrap()) |rhs| {
                        _ = try astrl.expr(rhs, block, ResultInfo.type_only);
                    }
                } else {
                    _ = try astrl.expr(input, block, ResultInfo.none);
                }
            }
            var new_block: Block = .{
                .parent = block,
                .label = label,
                .is_loop = true,
                .ri = ri,
                .consumes_res_ptr = false,
            };
            _ = try astrl.expr(full.ast.then_expr, &new_block, ResultInfo.none);
            const else_consumes_rl = if (full.ast.else_expr.unwrap()) |else_expr| else_rl: {
                break :else_rl try astrl.expr(else_expr, block, ri);
            } else false;
            if (new_block.consumes_res_ptr or else_consumes_rl) {
                try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
                return true;
            } else {
                return false;
            }
        },

        .slice_open => {
            const sliced, const start = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(sliced, block, ResultInfo.none);
            _ = try astrl.expr(start, block, ResultInfo.type_only);
            return false;
        },
        .slice => {
            const sliced, const extra_index = tree.nodeData(node).node_and_extra;
            const extra = tree.extraData(extra_index, Ast.Node.Slice);
            _ = try astrl.expr(sliced, block, ResultInfo.none);
            _ = try astrl.expr(extra.start, block, ResultInfo.type_only);
            _ = try astrl.expr(extra.end, block, ResultInfo.type_only);
            return false;
        },
        .slice_sentinel => {
            const sliced, const extra_index = tree.nodeData(node).node_and_extra;
            const extra = tree.extraData(extra_index, Ast.Node.SliceSentinel);
            _ = try astrl.expr(sliced, block, ResultInfo.none);
            _ = try astrl.expr(extra.start, block, ResultInfo.type_only);
            if (extra.end.unwrap()) |end| {
                _ = try astrl.expr(end, block, ResultInfo.type_only);
            }
            _ = try astrl.expr(extra.sentinel, block, ResultInfo.none);
            return false;
        },
        .deref => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.none);
            return false;
        },
        .address_of => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.none);
            return false;
        },
        .optional_type => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.type_only);
            return false;
        },
        .@"try",
        .@"await",
        .@"nosuspend",
        => return astrl.expr(tree.nodeData(node).node, block, ri),
        .grouped_expression,
        .unwrap_optional,
        => return astrl.expr(tree.nodeData(node).node_and_token[0], block, ri),

        .block_two,
        .block_two_semicolon,
        .block,
        .block_semicolon,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const statements = tree.blockStatements(&buf, node).?;
            return astrl.blockExpr(block, ri, node, statements);
        },
        .anyframe_type => {
            _, const child_type = tree.nodeData(node).token_and_node;
            _ = try astrl.expr(child_type, block, ResultInfo.type_only);
            return false;
        },
        .@"catch", .@"orelse" => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            const rhs_consumes_rl = try astrl.expr(rhs, block, ri);
            if (rhs_consumes_rl) {
                try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
            }
            return rhs_consumes_rl;
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => {
            const full = tree.fullPtrType(node).?;
            _ = try astrl.expr(full.ast.child_type, block, ResultInfo.type_only);
            if (full.ast.sentinel.unwrap()) |sentinel| {
                _ = try astrl.expr(sentinel, block, ResultInfo.type_only);
            }
            if (full.ast.addrspace_node.unwrap()) |addrspace_node| {
                _ = try astrl.expr(addrspace_node, block, ResultInfo.type_only);
            }
            if (full.ast.align_node.unwrap()) |align_node| {
                _ = try astrl.expr(align_node, block, ResultInfo.type_only);
            }
            if (full.ast.bit_range_start.unwrap()) |bit_range_start| {
                const bit_range_end = full.ast.bit_range_end.unwrap().?;
                _ = try astrl.expr(bit_range_start, block, ResultInfo.type_only);
                _ = try astrl.expr(bit_range_end, block, ResultInfo.type_only);
            }
            return false;
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
            try astrl.containerDecl(block, tree.fullContainerDecl(&buf, node).?);
            return false;
        },

        .@"break" => {
            const opt_label, const opt_rhs = tree.nodeData(node).opt_token_and_opt_node;
            const rhs = opt_rhs.unwrap() orelse {
                // Breaks with void are not interesting
                return false;
            };

            var opt_cur_block = block;
            if (opt_label.unwrap()) |label_token| {
                const break_label = try astrl.identString(label_token);
                while (opt_cur_block) |cur_block| : (opt_cur_block = cur_block.parent) {
                    const block_label = cur_block.label orelse continue;
                    if (std.mem.eql(u8, block_label, break_label)) break;
                }
            } else {
                // No label - we're breaking from a loop.
                while (opt_cur_block) |cur_block| : (opt_cur_block = cur_block.parent) {
                    if (cur_block.is_loop) break;
                }
            }

            if (opt_cur_block) |target_block| {
                const consumes_break_rl = try astrl.expr(rhs, block, target_block.ri);
                if (consumes_break_rl) target_block.consumes_res_ptr = true;
            } else {
                // No corresponding scope to break from - AstGen will emit an error.
                _ = try astrl.expr(rhs, block, ResultInfo.none);
            }

            return false;
        },

        .array_type => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.type_only);
            _ = try astrl.expr(rhs, block, ResultInfo.type_only);
            return false;
        },
        .array_type_sentinel => {
            const len_expr, const extra_index = tree.nodeData(node).node_and_extra;
            const extra = tree.extraData(extra_index, Ast.Node.ArrayTypeSentinel);
            _ = try astrl.expr(len_expr, block, ResultInfo.type_only);
            _ = try astrl.expr(extra.elem_type, block, ResultInfo.type_only);
            _ = try astrl.expr(extra.sentinel, block, ResultInfo.type_only);
            return false;
        },
        .array_access => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            _ = try astrl.expr(lhs, block, ResultInfo.none);
            _ = try astrl.expr(rhs, block, ResultInfo.type_only);
            return false;
        },
        .@"comptime" => {
            // AstGen will emit an error if the scope is already comptime, so we can assume it is
            // not. This means the result location is not forwarded.
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.none);
            return false;
        },
        .@"switch", .switch_comma => {
            const operand_node, const extra_index = tree.nodeData(node).node_and_extra;
            const case_nodes = tree.extraDataSlice(tree.extraData(extra_index, Ast.Node.SubRange), Ast.Node.Index);

            _ = try astrl.expr(operand_node, block, ResultInfo.none);

            var any_prong_consumed_rl = false;
            for (case_nodes) |case_node| {
                const case = tree.fullSwitchCase(case_node).?;
                for (case.ast.values) |item_node| {
                    if (tree.nodeTag(item_node) == .switch_range) {
                        const lhs, const rhs = tree.nodeData(item_node).node_and_node;
                        _ = try astrl.expr(lhs, block, ResultInfo.none);
                        _ = try astrl.expr(rhs, block, ResultInfo.none);
                    } else {
                        _ = try astrl.expr(item_node, block, ResultInfo.none);
                    }
                }
                if (try astrl.expr(case.ast.target_expr, block, ri)) {
                    any_prong_consumed_rl = true;
                }
            }
            if (any_prong_consumed_rl) {
                try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
            }
            return any_prong_consumed_rl;
        },
        .@"suspend" => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.none);
            return false;
        },
        .@"resume" => {
            _ = try astrl.expr(tree.nodeData(node).node, block, ResultInfo.none);
            return false;
        },

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
            const full = tree.fullArrayInit(&buf, node).?;

            if (full.ast.type_expr.unwrap()) |type_expr| {
                // Explicitly typed init does not participate in RLS
                _ = try astrl.expr(type_expr, block, ResultInfo.none);
                for (full.ast.elements) |elem_init| {
                    _ = try astrl.expr(elem_init, block, ResultInfo.type_only);
                }
                return false;
            }

            if (ri.have_type) {
                // Always forward type information
                // If we have a result pointer, we use and forward it
                for (full.ast.elements) |elem_init| {
                    _ = try astrl.expr(elem_init, block, ri);
                }
                return ri.have_ptr;
            } else {
                // Untyped init does not consume result location
                for (full.ast.elements) |elem_init| {
                    _ = try astrl.expr(elem_init, block, ResultInfo.none);
                }
                return false;
            }
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
            const full = tree.fullStructInit(&buf, node).?;

            if (full.ast.type_expr.unwrap()) |type_expr| {
                // Explicitly typed init does not participate in RLS
                _ = try astrl.expr(type_expr, block, ResultInfo.none);
                for (full.ast.fields) |field_init| {
                    _ = try astrl.expr(field_init, block, ResultInfo.type_only);
                }
                return false;
            }

            if (ri.have_type) {
                // Always forward type information
                // If we have a result pointer, we use and forward it
                for (full.ast.fields) |field_init| {
                    _ = try astrl.expr(field_init, block, ri);
                }
                return ri.have_ptr;
            } else {
                // Untyped init does not consume result location
                for (full.ast.fields) |field_init| {
                    _ = try astrl.expr(field_init, block, ResultInfo.none);
                }
                return false;
            }
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        .fn_decl,
        => |tag| {
            var buf: [1]Ast.Node.Index = undefined;
            const full = tree.fullFnProto(&buf, node).?;
            const body_node = if (tag == .fn_decl) tree.nodeData(node).node_and_node[1].toOptional() else .none;
            {
                var it = full.iterate(tree);
                while (it.next()) |param| {
                    if (param.anytype_ellipsis3 == null) {
                        const type_expr = param.type_expr.?;
                        _ = try astrl.expr(type_expr, block, ResultInfo.type_only);
                    }
                }
            }
            if (full.ast.align_expr.unwrap()) |align_expr| {
                _ = try astrl.expr(align_expr, block, ResultInfo.type_only);
            }
            if (full.ast.addrspace_expr.unwrap()) |addrspace_expr| {
                _ = try astrl.expr(addrspace_expr, block, ResultInfo.type_only);
            }
            if (full.ast.section_expr.unwrap()) |section_expr| {
                _ = try astrl.expr(section_expr, block, ResultInfo.type_only);
            }
            if (full.ast.callconv_expr.unwrap()) |callconv_expr| {
                _ = try astrl.expr(callconv_expr, block, ResultInfo.type_only);
            }
            const return_type = full.ast.return_type.unwrap().?;
            _ = try astrl.expr(return_type, block, ResultInfo.type_only);
            if (body_node.unwrap()) |body| {
                _ = try astrl.expr(body, block, ResultInfo.none);
            }
            return false;
        },
    }
}

fn identString(astrl: *AstRlAnnotate, token: Ast.TokenIndex) ![]const u8 {
    const tree = astrl.tree;
    assert(tree.tokenTag(token) == .identifier);
    const ident_name = tree.tokenSlice(token);
    if (!std.mem.startsWith(u8, ident_name, "@")) {
        return ident_name;
    }
    return std.zig.string_literal.parseAlloc(astrl.arena, ident_name[1..]) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidLiteral => "", // This pass can safely return garbage on invalid AST
    };
}

fn blockExpr(astrl: *AstRlAnnotate, parent_block: ?*Block, ri: ResultInfo, node: Ast.Node.Index, statements: []const Ast.Node.Index) !bool {
    const tree = astrl.tree;

    const lbrace = tree.nodeMainToken(node);
    if (tree.isTokenPrecededByTags(lbrace, &.{ .identifier, .colon })) {
        // Labeled block
        var new_block: Block = .{
            .parent = parent_block,
            .label = try astrl.identString(lbrace - 2),
            .is_loop = false,
            .ri = ri,
            .consumes_res_ptr = false,
        };
        for (statements) |statement| {
            _ = try astrl.expr(statement, &new_block, ResultInfo.none);
        }
        if (new_block.consumes_res_ptr) {
            try astrl.nodes_need_rl.putNoClobber(astrl.gpa, node, {});
        }
        return new_block.consumes_res_ptr;
    } else {
        // Unlabeled block
        for (statements) |statement| {
            _ = try astrl.expr(statement, parent_block, ResultInfo.none);
        }
        return false;
    }
}

fn builtinCall(astrl: *AstRlAnnotate, block: ?*Block, ri: ResultInfo, node: Ast.Node.Index, args: []const Ast.Node.Index) !bool {
    _ = ri; // Currently, no builtin consumes its result location.

    const tree = astrl.tree;
    const builtin_token = tree.nodeMainToken(node);
    const builtin_name = tree.tokenSlice(builtin_token);
    const info = BuiltinFn.list.get(builtin_name) orelse return false;
    if (info.param_count) |expected| {
        if (expected != args.len) return false;
    }
    switch (info.tag) {
        .import => return false,
        .branch_hint => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            return false;
        },
        .compile_log, .TypeOf => {
            for (args) |arg_node| {
                _ = try astrl.expr(arg_node, block, ResultInfo.none);
            }
            return false;
        },
        .as => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .bit_cast => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            return false;
        },
        .union_init => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            _ = try astrl.expr(args[2], block, ResultInfo.type_only);
            return false;
        },
        .c_import => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            return false;
        },
        .min, .max => {
            for (args) |arg_node| {
                _ = try astrl.expr(arg_node, block, ResultInfo.none);
            }
            return false;
        },
        .@"export" => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .@"extern" => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        // These builtins take no args and do not consume the result pointer.
        .src,
        .This,
        .return_address,
        .error_return_trace,
        .frame,
        .breakpoint,
        .disable_instrumentation,
        .disable_intrinsics,
        .in_comptime,
        .panic,
        .trap,
        .c_va_start,
        => return false,
        // TODO: this is a workaround for llvm/llvm-project#68409
        // Zig tracking issue: #16876
        .frame_address => return true,
        // These builtins take a single argument with a known result type, but do not consume their
        // result pointer.
        .size_of,
        .bit_size_of,
        .align_of,
        .compile_error,
        .set_eval_branch_quota,
        .int_from_bool,
        .int_from_error,
        .error_from_int,
        .embed_file,
        .error_name,
        .set_runtime_safety,
        .Type,
        .c_undef,
        .c_include,
        .wasm_memory_size,
        .splat,
        .set_float_mode,
        .type_info,
        .work_item_id,
        .work_group_size,
        .work_group_id,
        => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            return false;
        },
        // These builtins take a single argument with no result information and do not consume their
        // result pointer.
        .int_from_ptr,
        .int_from_enum,
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
        .Frame,
        .frame_size,
        .int_from_float,
        .float_from_int,
        .ptr_from_int,
        .enum_from_int,
        .float_cast,
        .int_cast,
        .truncate,
        .error_cast,
        .ptr_cast,
        .align_cast,
        .addrspace_cast,
        .const_cast,
        .volatile_cast,
        .clz,
        .ctz,
        .pop_count,
        .byte_swap,
        .bit_reverse,
        => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            return false;
        },
        .div_exact,
        .div_floor,
        .div_trunc,
        .mod,
        .rem,
        => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            return false;
        },
        .shl_exact, .shr_exact => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .bit_offset_of,
        .offset_of,
        .has_decl,
        .has_field,
        .field,
        .FieldType,
        => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .field_parent_ptr => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            return false;
        },
        .wasm_memory_grow => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .c_define => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            return false;
        },
        .reduce => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            return false;
        },
        .add_with_overflow, .sub_with_overflow, .mul_with_overflow, .shl_with_overflow => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            return false;
        },
        .atomic_load => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            _ = try astrl.expr(args[2], block, ResultInfo.type_only);
            return false;
        },
        .atomic_rmw => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            _ = try astrl.expr(args[2], block, ResultInfo.type_only);
            _ = try astrl.expr(args[3], block, ResultInfo.type_only);
            _ = try astrl.expr(args[4], block, ResultInfo.type_only);
            return false;
        },
        .atomic_store => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            _ = try astrl.expr(args[2], block, ResultInfo.type_only);
            _ = try astrl.expr(args[3], block, ResultInfo.type_only);
            return false;
        },
        .mul_add => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            _ = try astrl.expr(args[2], block, ResultInfo.type_only);
            return false;
        },
        .call => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            _ = try astrl.expr(args[2], block, ResultInfo.none);
            return false;
        },
        .memcpy, .memmove => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            return false;
        },
        .memset => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .shuffle => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            _ = try astrl.expr(args[2], block, ResultInfo.none);
            _ = try astrl.expr(args[3], block, ResultInfo.none);
            return false;
        },
        .select => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            _ = try astrl.expr(args[2], block, ResultInfo.none);
            _ = try astrl.expr(args[3], block, ResultInfo.none);
            return false;
        },
        .async_call => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.none);
            _ = try astrl.expr(args[2], block, ResultInfo.none);
            _ = try astrl.expr(args[3], block, ResultInfo.none);
            return false; // buffer passed as arg for frame data
        },
        .Vector => {
            _ = try astrl.expr(args[0], block, ResultInfo.type_only);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .prefetch => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .c_va_arg => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            return false;
        },
        .c_va_copy => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            return false;
        },
        .c_va_end => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            return false;
        },
        .cmpxchg_strong, .cmpxchg_weak => {
            _ = try astrl.expr(args[0], block, ResultInfo.none);
            _ = try astrl.expr(args[1], block, ResultInfo.type_only);
            _ = try astrl.expr(args[2], block, ResultInfo.type_only);
            _ = try astrl.expr(args[3], block, ResultInfo.type_only);
            _ = try astrl.expr(args[4], block, ResultInfo.type_only);
            return false;
        },
    }
}
pub const Tag = enum {
    add_with_overflow,
    addrspace_cast,
    align_cast,
    align_of,
    as,
    async_call,
    atomic_load,
    atomic_rmw,
    atomic_store,
    bit_cast,
    bit_offset_of,
    int_from_bool,
    bit_size_of,
    branch_hint,
    breakpoint,
    disable_instrumentation,
    disable_intrinsics,
    mul_add,
    byte_swap,
    bit_reverse,
    offset_of,
    call,
    c_define,
    c_import,
    c_include,
    clz,
    cmpxchg_strong,
    cmpxchg_weak,
    compile_error,
    compile_log,
    const_cast,
    ctz,
    c_undef,
    c_va_arg,
    c_va_copy,
    c_va_end,
    c_va_start,
    div_exact,
    div_floor,
    div_trunc,
    embed_file,
    int_from_enum,
    error_name,
    error_return_trace,
    int_from_error,
    error_cast,
    @"export",
    @"extern",
    field,
    field_parent_ptr,
    FieldType,
    float_cast,
    int_from_float,
    frame,
    Frame,
    frame_address,
    frame_size,
    has_decl,
    has_field,
    import,
    in_comptime,
    int_cast,
    enum_from_int,
    error_from_int,
    float_from_int,
    ptr_from_int,
    max,
    memcpy,
    memset,
    memmove,
    min,
    wasm_memory_size,
    wasm_memory_grow,
    mod,
    mul_with_overflow,
    panic,
    pop_count,
    prefetch,
    ptr_cast,
    int_from_ptr,
    rem,
    return_address,
    select,
    set_eval_branch_quota,
    set_float_mode,
    set_runtime_safety,
    shl_exact,
    shl_with_overflow,
    shr_exact,
    shuffle,
    size_of,
    splat,
    reduce,
    src,
    sqrt,
    sin,
    cos,
    tan,
    exp,
    exp2,
    log,
    log2,
    log10,
    abs,
    floor,
    ceil,
    trunc,
    round,
    sub_with_overflow,
    tag_name,
    This,
    trap,
    truncate,
    Type,
    type_info,
    type_name,
    TypeOf,
    union_init,
    Vector,
    volatile_cast,
    work_item_id,
    work_group_size,
    work_group_id,
};

pub const EvalToError = enum {
    /// The builtin cannot possibly evaluate to an error.
    never,
    /// The builtin will always evaluate to an error.
    always,
    /// The builtin may or may not evaluate to an error depending on the parameters.
    maybe,
};

tag: Tag,

/// Info about the builtin call's possibility of returning an error.
eval_to_error: EvalToError = .never,
/// `true` if the builtin call can be the left-hand side of an expression (assigned to).
allows_lvalue: bool = false,
/// `true` if builtin call is not available outside function scope
illegal_outside_function: bool = false,
/// The number of parameters to this builtin function. `null` means variable number
/// of parameters.
param_count: ?u8,

pub const list = list: {
    @setEvalBranchQuota(3000);
    break :list std.StaticStringMap(BuiltinFn).initComptime([_]struct { []const u8, BuiltinFn }{
        .{
            "@addWithOverflow",
            .{
                .tag = .add_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@addrSpaceCast",
            .{
                .tag = .addrspace_cast,
                .param_count = 1,
            },
        },
        .{
            "@alignCast",
            .{
                .tag = .align_cast,
                .param_count = 1,
            },
        },
        .{
            "@alignOf",
            .{
                .tag = .align_of,
                .param_count = 1,
            },
        },
        .{
            "@as",
            .{
                .tag = .as,
                .eval_to_error = .maybe,
                .param_count = 2,
            },
        },
        .{
            "@asyncCall",
            .{
                .tag = .async_call,
                .param_count = 4,
            },
        },
        .{
            "@atomicLoad",
            .{
                .tag = .atomic_load,
                .param_count = 3,
            },
        },
        .{
            "@atomicRmw",
            .{
                .tag = .atomic_rmw,
                .param_count = 5,
            },
        },
        .{
            "@atomicStore",
            .{
                .tag = .atomic_store,
                .param_count = 4,
            },
        },
        .{
            "@bitCast",
            .{
                .tag = .bit_cast,
                .param_count = 1,
            },
        },
        .{
            "@bitOffsetOf",
            .{
                .tag = .bit_offset_of,
                .param_count = 2,
            },
        },
        .{
            "@intFromBool",
            .{
                .tag = .int_from_bool,
                .param_count = 1,
            },
        },
        .{
            "@bitSizeOf",
            .{
                .tag = .bit_size_of,
                .param_count = 1,
            },
        },
        .{
            "@branchHint",
            .{
                .tag = .branch_hint,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@breakpoint",
            .{
                .tag = .breakpoint,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@disableInstrumentation",
            .{
                .tag = .disable_instrumentation,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@disableIntrinsics",
            .{
                .tag = .disable_intrinsics,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@mulAdd",
            .{
                .tag = .mul_add,
                .param_count = 4,
            },
        },
        .{
            "@byteSwap",
            .{
                .tag = .byte_swap,
                .param_count = 1,
            },
        },
        .{
            "@bitReverse",
            .{
                .tag = .bit_reverse,
                .param_count = 1,
            },
        },
        .{
            "@offsetOf",
            .{
                .tag = .offset_of,
                .param_count = 2,
            },
        },
        .{
            "@call",
            .{
                .tag = .call,
                .eval_to_error = .maybe,
                .param_count = 3,
            },
        },
        .{
            "@cDefine",
            .{
                .tag = .c_define,
                .param_count = 2,
            },
        },
        .{
            "@cImport",
            .{
                .tag = .c_import,
                .param_count = 1,
            },
        },
        .{
            "@cInclude",
            .{
                .tag = .c_include,
                .param_count = 1,
            },
        },
        .{
            "@clz",
            .{
                .tag = .clz,
                .param_count = 1,
            },
        },
        .{
            "@cmpxchgStrong",
            .{
                .tag = .cmpxchg_strong,
                .param_count = 6,
            },
        },
        .{
            "@cmpxchgWeak",
            .{
                .tag = .cmpxchg_weak,
                .param_count = 6,
            },
        },
        .{
            "@compileError",
            .{
                .tag = .compile_error,
                .param_count = 1,
            },
        },
        .{
            "@compileLog",
            .{
                .tag = .compile_log,
                .param_count = null,
            },
        },
        .{
            "@constCast",
            .{
                .tag = .const_cast,
                .param_count = 1,
            },
        },
        .{
            "@ctz",
            .{
                .tag = .ctz,
                .param_count = 1,
            },
        },
        .{
            "@cUndef",
            .{
                .tag = .c_undef,
                .param_count = 1,
            },
        },
        .{
            "@cVaArg", .{
                .tag = .c_va_arg,
                .param_count = 2,
                .illegal_outside_function = true,
            },
        },
        .{
            "@cVaCopy", .{
                .tag = .c_va_copy,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@cVaEnd", .{
                .tag = .c_va_end,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@cVaStart", .{
                .tag = .c_va_start,
                .param_count = 0,
                .illegal_outside_function = true,
 ```
