```
e, broken up into 4 u32 parts.
    pub const Float128 = struct {
        piece0: u32,
        piece1: u32,
        piece2: u32,
        piece3: u32,

        pub fn get(self: Float128) f128 {
            const int_bits = @as(u128, self.piece0) |
                (@as(u128, self.piece1) << 32) |
                (@as(u128, self.piece2) << 64) |
                (@as(u128, self.piece3) << 96);
            return @as(f128, @bitCast(int_bits));
        }
    };

    /// Trailing is an item per field.
    pub const StructInit = struct {
        /// If this is an anonymous initialization (the operand is poison), this instruction becomes the owner of a type.
        /// To resolve source locations, we need an absolute source node.
        abs_node: Ast.Node.Index,
        /// Likewise, we need an absolute line number.
        abs_line: u32,
        fields_len: u32,

        pub const Item = struct {
            /// The `struct_init_field_type` ZIR instruction for this field init.
            field_type: Index,
            /// The field init expression to be used as the field value. This value will be coerced
            /// to the field type if not already.
            init: Ref,
        };
    };

    /// Trailing is an Item per field.
    /// TODO make this instead array of inits followed by array of names because
    /// it will be simpler Sema code and better for CPU cache.
    pub const StructInitAnon = struct {
        /// This is an anonymous initialization, meaning this instruction becomes the owner of a type.
        /// To resolve source locations, we need an absolute source node.
        abs_node: Ast.Node.Index,
        /// Likewise, we need an absolute line number.
        abs_line: u32,
        fields_len: u32,

        pub const Item = struct {
            /// Null-terminated string table index.
            field_name: NullTerminatedString,
            /// The field init expression to be used as the field value.
            init: Ref,
        };
    };

    pub const FieldType = struct {
        container_type: Ref,
        /// Offset into `string_bytes`, null terminated.
        name_start: NullTerminatedString,
    };

    pub const FieldTypeRef = struct {
        container_type: Ref,
        field_name: Ref,
    };

    pub const Cmpxchg = struct {
        node: Ast.Node.Offset,
        ptr: Ref,
        expected_value: Ref,
        new_value: Ref,
        success_order: Ref,
        failure_order: Ref,
    };

    pub const AtomicRmw = struct {
        ptr: Ref,
        operation: Ref,
        operand: Ref,
        ordering: Ref,
    };

    pub const UnionInit = struct {
        union_type: Ref,
        field_name: Ref,
        init: Ref,
    };

    pub const AtomicStore = struct {
        ptr: Ref,
        operand: Ref,
        ordering: Ref,
    };

    pub const AtomicLoad = struct {
        elem_type: Ref,
        ptr: Ref,
        ordering: Ref,
    };

    pub const MulAdd = struct {
        mulend1: Ref,
        mulend2: Ref,
        addend: Ref,
    };

    pub const FieldParentPtr = struct {
        src_node: Ast.Node.Offset,
        parent_ptr_type: Ref,
        field_name: Ref,
        field_ptr: Ref,
    };

    pub const Shuffle = struct {
        elem_type: Ref,
        a: Ref,
        b: Ref,
        mask: Ref,
    };

    pub const Select = struct {
        node: Ast.Node.Offset,
        elem_type: Ref,
        pred: Ref,
        a: Ref,
        b: Ref,
    };

    pub const AsyncCall = struct {
        node: Ast.Node.Offset,
        frame_buffer: Ref,
        result_ptr: Ref,
        fn_ptr: Ref,
        args: Ref,
    };

    /// Trailing: inst: Index // for every body_len
    pub const Param = struct {
        /// Null-terminated string index.
        name: NullTerminatedString,
        type: Type,

        pub const Type = packed struct(u32) {
            /// The body contains the type of the parameter.
            body_len: u31,
            /// Whether the type is generic, i.e. refers to one or more previous parameters.
            is_generic: bool,
        };
    };

    /// Trailing:
    /// 0. type_inst: Ref,  // if small 0b000X is set
    /// 1. align_inst: Ref, // if small 0b00X0 is set
    pub const AllocExtended = struct {
        src_node: Ast.Node.Offset,

        pub const Small = packed struct {
            has_type: bool,
            has_align: bool,
            is_const: bool,
            is_comptime: bool,
            _: u12 = undefined,
        };
    };

    pub const Export = struct {
        exported: Ref,
        options: Ref,
    };

    /// Trailing: `CompileErrors.Item` for each `items_len`.
    pub const CompileErrors = struct {
        items_len: u32,

        /// Trailing: `note_payload_index: u32` for each `notes_len`.
        /// It's a payload index of another `Item`.
        pub const Item = struct {
            /// null terminated string index
            msg: NullTerminatedString,
            node: Ast.Node.OptionalIndex,
            /// If node is .none then this will be populated.
            token: Ast.OptionalTokenIndex,
            /// Can be used in combination with `token`.
            byte_offset: u32,
            /// 0 or a payload index of a `Block`, each is a payload
            /// index of another `Item`.
            notes: u32,

            pub fn notesLen(item: Item, zir: Zir) u32 {
                if (item.notes == 0) return 0;
                const block = zir.extraData(Block, item.notes);
                return block.data.body_len;
            }
        };
    };

    /// Trailing: for each `imports_len` there is an Item
    pub const Imports = struct {
        imports_len: u32,

        pub const Item = struct {
            /// null terminated string index
            name: NullTerminatedString,
            /// points to the import name
            token: Ast.TokenIndex,
        };
    };

    pub const LineColumn = struct {
        line: u32,
        column: u32,
    };

    pub const ArrayInit = struct {
        ty: Ref,
        init_count: u32,
    };

    pub const Src = struct {
        node: Ast.Node.Offset,
        line: u32,
        column: u32,
    };

    pub const DeferErrCode = struct {
        remapped_err_code: Index,
        index: u32,
        len: u32,
    };

    pub const ValidateDestructure = struct {
        /// The value being destructured.
        operand: Ref,
        /// The `destructure_assign` node.
        destructure_node: Ast.Node.Offset,
        /// The expected field count.
        expect_len: u32,
    };

    pub const ArrayMul = struct {
        /// The result type of the array multiplication operation, or `.none` if none was available.
        res_ty: Ref,
        /// The LHS of the array multiplication.
        lhs: Ref,
        /// The RHS of the array multiplication.
        rhs: Ref,
    };

    pub const RestoreErrRetIndex = struct {
        src_node: Ast.Node.Offset,
        /// If `.none`, restore the trace to its state upon function entry.
        block: Ref,
        /// If `.none`, restore unconditionally.
        operand: Ref,
    };

    pub const Import = struct {
        /// The result type of the import, or `.none` if none was available.
        res_ty: Ref,
        /// The import path.
        path: NullTerminatedString,
    };
};

pub const SpecialProng = enum { none, @"else", under };

pub const DeclIterator = struct {
    extra_index: u32,
    decls_remaining: u32,
    zir: Zir,

    pub fn next(it: *DeclIterator) ?Inst.Index {
        if (it.decls_remaining == 0) return null;
        const decl_inst: Zir.Inst.Index = @enumFromInt(it.zir.extra[it.extra_index]);
        it.extra_index += 1;
        it.decls_remaining -= 1;
        assert(it.zir.instructions.items(.tag)[@intFromEnum(decl_inst)] == .declaration);
        return decl_inst;
    }
};

pub fn declIterator(zir: Zir, decl_inst: Zir.Inst.Index) DeclIterator {
    const inst = zir.instructions.get(@intFromEnum(decl_inst));
    assert(inst.tag == .extended);
    const extended = inst.data.extended;
    switch (extended.opcode) {
        .struct_decl => {
            const small: Inst.StructDecl.Small = @bitCast(extended.small);
            var extra_index: u32 = @intCast(extended.operand + @typeInfo(Inst.StructDecl).@"struct".fields.len);
            const captures_len = if (small.has_captures_len) captures_len: {
                const captures_len = zir.extra[extra_index];
                extra_index += 1;
                break :captures_len captures_len;
            } else 0;
            extra_index += @intFromBool(small.has_fields_len);
            const decls_len = if (small.has_decls_len) decls_len: {
                const decls_len = zir.extra[extra_index];
                extra_index += 1;
                break :decls_len decls_len;
            } else 0;

            extra_index += captures_len * 2;

            if (small.has_backing_int) {
                const backing_int_body_len = zir.extra[extra_index];
                extra_index += 1; // backing_int_body_len
                if (backing_int_body_len == 0) {
                    extra_index += 1; // backing_int_ref
                } else {
                    extra_index += backing_int_body_len; // backing_int_body_inst
                }
            }

            return .{
                .extra_index = extra_index,
                .decls_remaining = decls_len,
                .zir = zir,
            };
        },
        .enum_decl => {
            const small: Inst.EnumDecl.Small = @bitCast(extended.small);
            var extra_index: u32 = @intCast(extended.operand + @typeInfo(Inst.EnumDecl).@"struct".fields.len);
            extra_index += @intFromBool(small.has_tag_type);
            const captures_len = if (small.has_captures_len) captures_len: {
                const captures_len = zir.extra[extra_index];
                extra_index += 1;
                break :captures_len captures_len;
            } else 0;
            extra_index += @intFromBool(small.has_body_len);
            extra_index += @intFromBool(small.has_fields_len);
            const decls_len = if (small.has_decls_len) decls_len: {
                const decls_len = zir.extra[extra_index];
                extra_index += 1;
                break :decls_len decls_len;
            } else 0;

            extra_index += captures_len * 2;

            return .{
                .extra_index = extra_index,
                .decls_remaining = decls_len,
                .zir = zir,
            };
        },
        .union_decl => {
            const small: Inst.UnionDecl.Small = @bitCast(extended.small);
            var extra_index: u32 = @intCast(extended.operand + @typeInfo(Inst.UnionDecl).@"struct".fields.len);
            extra_index += @intFromBool(small.has_tag_type);
            const captures_len = if (small.has_captures_len) captures_len: {
                const captures_len = zir.extra[extra_index];
                extra_index += 1;
                break :captures_len captures_len;
            } else 0;
            extra_index += @intFromBool(small.has_body_len);
            extra_index += @intFromBool(small.has_fields_len);
            const decls_len = if (small.has_decls_len) decls_len: {
                const decls_len = zir.extra[extra_index];
                extra_index += 1;
                break :decls_len decls_len;
            } else 0;

            extra_index += captures_len * 2;

            return .{
                .extra_index = extra_index,
                .decls_remaining = decls_len,
                .zir = zir,
            };
        },
        .opaque_decl => {
            const small: Inst.OpaqueDecl.Small = @bitCast(extended.small);
            var extra_index: u32 = @intCast(extended.operand + @typeInfo(Inst.OpaqueDecl).@"struct".fields.len);
            const decls_len = if (small.has_decls_len) decls_len: {
                const decls_len = zir.extra[extra_index];
                extra_index += 1;
                break :decls_len decls_len;
            } else 0;
            const captures_len = if (small.has_captures_len) captures_len: {
                const captures_len = zir.extra[extra_index];
                extra_index += 1;
                break :captures_len captures_len;
            } else 0;

            extra_index += captures_len * 2;

            return .{
                .extra_index = extra_index,
                .decls_remaining = decls_len,
                .zir = zir,
            };
        },
        else => unreachable,
    }
}

/// `DeclContents` contains all "interesting" instructions found within a declaration by `findTrackable`.
/// These instructions are partitioned into a few different sets, since this makes ZIR instruction mapping
/// more effective.
pub const DeclContents = struct {
    /// This is a simple optional because ZIR guarantees that a `func`/`func_inferred`/`func_fancy` instruction
    /// can only occur once per `declaration`.
    func_decl: ?Inst.Index,
    explicit_types: std.ArrayListUnmanaged(Inst.Index),
    other: std.ArrayListUnmanaged(Inst.Index),

    pub const init: DeclContents = .{
        .func_decl = null,
        .explicit_types = .empty,
        .other = .empty,
    };

    pub fn clear(contents: *DeclContents) void {
        contents.func_decl = null;
        contents.explicit_types.clearRetainingCapacity();
        contents.other.clearRetainingCapacity();
    }

    pub fn deinit(contents: *DeclContents, gpa: Allocator) void {
        contents.explicit_types.deinit(gpa);
        contents.other.deinit(gpa);
    }
};

/// Find all tracked ZIR instructions, recursively, within a `declaration` instruction. Does not recurse through
/// nested declarations; to find all declarations, call this function recursively on the type declarations discovered
/// in `contents.explicit_types`.
///
/// This populates an `ArrayListUnmanaged` because an iterator would need to allocate memory anyway.
pub fn findTrackable(zir: Zir, gpa: Allocator, contents: *DeclContents, decl_inst: Zir.Inst.Index) !void {
    contents.clear();

    const decl = zir.getDeclaration(decl_inst);

    // `defer` instructions duplicate the same body arbitrarily many times, but we only want to traverse
    // their contents once per defer. So, we store the extra index of the body here to deduplicate.
    var found_defers: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer found_defers.deinit(gpa);

    if (decl.type_body) |b| try zir.findTrackableBody(gpa, contents, &found_defers, b);
    if (decl.align_body) |b| try zir.findTrackableBody(gpa, contents, &found_defers, b);
    if (decl.linksection_body) |b| try zir.findTrackableBody(gpa, contents, &found_defers, b);
    if (decl.addrspace_body) |b| try zir.findTrackableBody(gpa, contents, &found_defers, b);
    if (decl.value_body) |b| try zir.findTrackableBody(gpa, contents, &found_defers, b);
}

/// Like `findTrackable`, but only considers the `main_struct_inst` instruction. This may return more than
/// just that instruction because it will also traverse fields.
pub fn findTrackableRoot(zir: Zir, gpa: Allocator, contents: *DeclContents) !void {
    contents.clear();

    var found_defers: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer found_defers.deinit(gpa);

    try zir.findTrackableInner(gpa, contents, &found_defers, .main_struct_inst);
}

fn findTrackableInner(
    zir: Zir,
    gpa: Allocator,
    contents: *DeclContents,
    defers: *std.AutoHashMapUnmanaged(u32, void),
    inst: Inst.Index,
) Allocator.Error!void {
    comptime assert(Zir.inst_tracking_version == 0);

    const tags = zir.instructions.items(.tag);
    const datas = zir.instructions.items(.data);

    switch (tags[@intFromEnum(inst)]) {
        .declaration => unreachable,

        // Boring instruction tags first. These have no body and are not declarations or type declarations.
        .add,
        .addwrap,
        .add_sat,
        .add_unsafe,
        .sub,
        .subwrap,
        .sub_sat,
        .mul,
        .mulwrap,
        .mul_sat,
        .div_exact,
        .div_floor,
        .div_trunc,
        .mod,
        .rem,
        .mod_rem,
        .shl,
        .shl_exact,
        .shl_sat,
        .shr,
        .shr_exact,
        .param_anytype,
        .param_anytype_comptime,
        .array_cat,
        .array_mul,
        .array_type,
        .array_type_sentinel,
        .vector_type,
        .elem_type,
        .indexable_ptr_elem_type,
        .vec_arr_elem_type,
        .indexable_ptr_len,
        .anyframe_type,
        .as_node,
        .as_shift_operand,
        .bit_and,
        .bitcast,
        .bit_not,
        .bit_or,
        .bool_not,
        .bool_br_and,
        .bool_br_or,
        .@"break",
        .break_inline,
        .switch_continue,
        .check_comptime_control_flow,
        .builtin_call,
        .cmp_lt,
        .cmp_lte,
        .cmp_eq,
        .cmp_gte,
        .cmp_gt,
        .cmp_neq,
        .error_set_decl,
        .dbg_stmt,
        .dbg_var_ptr,
        .dbg_var_val,
        .decl_ref,
        .decl_val,
        .load,
        .div,
        .elem_ptr_node,
        .elem_ptr,
        .elem_val_node,
        .elem_val,
        .elem_val_imm,
        .ensure_result_used,
        .ensure_result_non_error,
        .ensure_err_union_payload_void,
        .error_union_type,
        .error_value,
        .@"export",
        .field_ptr,
        .field_val,
        .field_ptr_named,
        .field_val_named,
        .import,
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
        .repeat,
        .repeat_inline,
        .for_len,
        .merge_error_sets,
        .ref,
        .ret_node,
        .ret_load,
        .ret_implicit,
        .ret_err_value,
        .ret_err_value_code,
        .ret_ptr,
        .ret_type,
        .ptr_type,
        .slice_start,
        .slice_end,
        .slice_sentinel,
        .slice_length,
        .slice_sentinel_ty,
        .store_node,
        .store_to_inferred_ptr,
        .str,
        .negate,
        .negate_wrap,
        .typeof,
        .typeof_log2_int_type,
        .@"unreachable",
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
        .enum_literal,
        .decl_literal,
        .decl_literal_no_coerce,
        .validate_deref,
        .validate_destructure,
        .field_type_ref,
        .opt_eu_base_ptr_init,
        .coerce_ptr_elem_ty,
        .validate_ref_ty,
        .validate_const,
        .struct_init_empty,
        .struct_init_empty_result,
        .struct_init_empty_ref_result,
        .validate_struct_init_ty,
        .validate_struct_init_result_ty,
        .validate_ptr_struct_init,
        .struct_init_field_type,
        .struct_init_field_ptr,
        .array_init_anon,
        .array_init,
        .array_init_ref,
        .validate_array_init_ty,
        .validate_array_init_result_ty,
        .validate_array_init_ref_ty,
        .validate_ptr_array_init,
        .array_init_elem_type,
        .array_init_elem_ptr,
        .union_init,
        .type_info,
        .size_of,
        .bit_size_of,
        .int_from_ptr,
        .compile_error,
        .set_eval_branch_quota,
        .int_from_enum,
        .align_of,
        .int_from_bool,
        .embed_file,
        .error_name,
        .panic,
        .trap,
        .set_runtime_safety,
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
        .enum_from_int,
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
        .bit_offset_of,
        .offset_of,
        .splat,
        .reduce,
        .shuffle,
        .atomic_load,
        .atomic_rmw,
        .atomic_store,
        .mul_add,
        .memcpy,
        .memset,
        .memmove,
        .min,
        .max,
        .alloc,
        .alloc_mut,
        .alloc_comptime_mut,
        .alloc_inferred,
        .alloc_inferred_mut,
        .alloc_inferred_comptime,
        .alloc_inferred_comptime_mut,
        .resolve_inferred_alloc,
        .make_ptr_const,
        .@"resume",
        .@"await",
        .save_err_ret_index,
        .restore_err_ret_index_unconditional,
        .restore_err_ret_index_fn_entry,
        => return,

        // Struct initializations need tracking, as they may create anonymous struct types.
        .struct_init,
        .struct_init_ref,
        .struct_init_anon,
        => return contents.other.append(gpa, inst),

        .extended => {
            const extended = datas[@intFromEnum(inst)].extended;
            switch (extended.opcode) {
                .value_placeholder => unreachable,

                // Once again, we start with the boring tags.
                .this,
                .ret_addr,
                .builtin_src,
                .error_return_trace,
                .frame,
                .frame_address,
                .alloc,
                .builtin_extern,
                .@"asm",
                .asm_expr,
                .compile_log,
                .min_multi,
                .max_multi,
                .add_with_overflow,
                .sub_with_overflow,
                .mul_with_overflow,
                .shl_with_overflow,
                .c_undef,
                .c_include,
                .c_define,
                .wasm_memory_size,
                .wasm_memory_grow,
                .prefetch,
                .set_float_mode,
                .error_cast,
                .await_nosuspend,
                .breakpoint,
                .disable_instrumentation,
                .disable_intrinsics,
                .select,
                .int_from_error,
                .error_from_int,
                .builtin_async_call,
                .cmpxchg,
                .c_va_arg,
                .c_va_copy,
                .c_va_end,
                .c_va_start,
                .ptr_cast_full,
                .ptr_cast_no_dest,
                .work_item_id,
                .work_group_size,
                .work_group_id,
                .in_comptime,
                .restore_err_ret_index,
                .closure_get,
                .field_parent_ptr,
                .builtin_value,
                .branch_hint,
                .inplace_arith_result_ty,
                .tuple_decl,
                .dbg_empty_stmt,
                .astgen_error,
                => return,

                // `@TypeOf` has a body.
                .typeof_peer => {
                    const extra = zir.extraData(Zir.Inst.TypeOfPeer, extended.operand);
                    const body = zir.bodySlice(extra.data.body_index, extra.data.body_len);
                    try zir.findTrackableBody(gpa, contents, defers, body);
                },

                // Reifications and opaque declarations need tracking, but have no body.
                .reify, .opaque_decl => return contents.other.append(gpa, inst),

                // Struct declarations need tracking and have bodies.
                .struct_decl => {
                    try contents.explicit_types.append(gpa, inst);

                    const small: Zir.Inst.StructDecl.Small = @bitCast(extended.small);
                    const extra = zir.extraData(Zir.Inst.StructDecl, extended.operand);
                    var extra_index = extra.end;
                    const captures_len = if (small.has_captures_len) blk: {
                        const captures_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk captures_len;
                    } else 0;
                    const fields_len = if (small.has_fields_len) blk: {
                        const fields_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk fields_len;
                    } else 0;
                    const decls_len = if (small.has_decls_len) blk: {
                        const decls_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk decls_len;
                    } else 0;
                    extra_index += captures_len * 2;
                    if (small.has_backing_int) {
                        const backing_int_body_len = zir.extra[extra_index];
                        extra_index += 1;
                        if (backing_int_body_len == 0) {
                            extra_index += 1; // backing_int_ref
                        } else {
                            const body = zir.bodySlice(extra_index, backing_int_body_len);
                            extra_index += backing_int_body_len;
                            try zir.findTrackableBody(gpa, contents, defers, body);
                        }
                    }
                    extra_index += decls_len;

                    // This ZIR is structured in a slightly awkward way, so we have to split up the iteration.
                    // `extra_index` iterates `flags` (bags of bits).
                    // `fields_extra_index` iterates `fields`.
                    // We accumulate the total length of bodies into `total_bodies_len`. This is sufficient because
                    // the bodies are packed together in `extra` and we only need to traverse their instructions (we
                    // don't really care about the structure).

                    const bits_per_field = 4;
                    const fields_per_u32 = 32 / bits_per_field;
                    const bit_bags_count = std.math.divCeil(usize, fields_len, fields_per_u32) catch unreachable;
                    var cur_bit_bag: u32 = undefined;

                    var fields_extra_index = extra_index + bit_bags_count;
                    var total_bodies_len: u32 = 0;

                    for (0..fields_len) |field_i| {
                        if (field_i % fields_per_u32 == 0) {
                            cur_bit_bag = zir.extra[extra_index];
                            extra_index += 1;
                        }

                        const has_align = @as(u1, @truncate(cur_bit_bag)) != 0;
                        cur_bit_bag >>= 1;
                        const has_init = @as(u1, @truncate(cur_bit_bag)) != 0;
                        cur_bit_bag >>= 2; // also skip `is_comptime`; we don't care
                        const has_type_body = @as(u1, @truncate(cur_bit_bag)) != 0;
                        cur_bit_bag >>= 1;

                        fields_extra_index += 1; // field_name

                        if (has_type_body) {
                            const field_type_body_len = zir.extra[fields_extra_index];
                            total_bodies_len += field_type_body_len;
                        }
                        fields_extra_index += 1; // field_type or field_type_body_len

                        if (has_align) {
                            const align_body_len = zir.extra[fields_extra_index];
                            fields_extra_index += 1;
                            total_bodies_len += align_body_len;
                        }

                        if (has_init) {
                            const init_body_len = zir.extra[fields_extra_index];
                            fields_extra_index += 1;
                            total_bodies_len += init_body_len;
                        }
                    }

                    // Now, `fields_extra_index` points to `bodies`. Let's treat this as one big body.
                    const merged_bodies = zir.bodySlice(fields_extra_index, total_bodies_len);
                    try zir.findTrackableBody(gpa, contents, defers, merged_bodies);
                },

                // Union declarations need tracking and have a body.
                .union_decl => {
                    try contents.explicit_types.append(gpa, inst);

                    const small: Zir.Inst.UnionDecl.Small = @bitCast(extended.small);
                    const extra = zir.extraData(Zir.Inst.UnionDecl, extended.operand);
                    var extra_index = extra.end;
                    extra_index += @intFromBool(small.has_tag_type);
                    const captures_len = if (small.has_captures_len) blk: {
                        const captures_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk captures_len;
                    } else 0;
                    const body_len = if (small.has_body_len) blk: {
                        const body_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk body_len;
                    } else 0;
                    extra_index += @intFromBool(small.has_fields_len);
                    const decls_len = if (small.has_decls_len) blk: {
                        const decls_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk decls_len;
                    } else 0;
                    extra_index += captures_len * 2;
                    extra_index += decls_len;
                    const body = zir.bodySlice(extra_index, body_len);
                    try zir.findTrackableBody(gpa, contents, defers, body);
                },

                // Enum declarations need tracking and have a body.
                .enum_decl => {
                    try contents.explicit_types.append(gpa, inst);

                    const small: Zir.Inst.EnumDecl.Small = @bitCast(extended.small);
                    const extra = zir.extraData(Zir.Inst.EnumDecl, extended.operand);
                    var extra_index = extra.end;
                    extra_index += @intFromBool(small.has_tag_type);
                    const captures_len = if (small.has_captures_len) blk: {
                        const captures_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk captures_len;
                    } else 0;
                    const body_len = if (small.has_body_len) blk: {
                        const body_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk body_len;
                    } else 0;
                    extra_index += @intFromBool(small.has_fields_len);
                    const decls_len = if (small.has_decls_len) blk: {
                        const decls_len = zir.extra[extra_index];
                        extra_index += 1;
                        break :blk decls_len;
                    } else 0;
                    extra_index += captures_len * 2;
                    extra_index += decls_len;
                    const body = zir.bodySlice(extra_index, body_len);
                    try zir.findTrackableBody(gpa, contents, defers, body);
                },
            }
        },

        // Functions instructions are interesting and have a body.
        .func,
        .func_inferred,
        => {
            const inst_data = datas[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.Func, inst_data.payload_index);

            if (extra.data.body_len == 0) {
                // This is just a prototype. No need to track.
                assert(extra.data.ret_ty.body_len < 2);
                return;
            }

            assert(contents.func_decl == null);
            contents.func_decl = inst;

            var extra_index: usize = extra.end;
            switch (extra.data.ret_ty.body_len) {
                0 => {},
                1 => extra_index += 1,
                else => {
                    const body = zir.bodySlice(extra_index, extra.data.ret_ty.body_len);
                    extra_index += body.len;
                    try zir.findTrackableBody(gpa, contents, defers, body);
                },
            }
            const body = zir.bodySlice(extra_index, extra.data.body_len);
            return zir.findTrackableBody(gpa, contents, defers, body);
        },
        .func_fancy => {
            const inst_data = datas[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.FuncFancy, inst_data.payload_index);

            if (extra.data.body_len == 0) {
                // This is just a prototype. No need to track.
                assert(!extra.data.bits.has_cc_body);
                assert(!extra.data.bits.has_ret_ty_body);
                return;
            }

            assert(contents.func_decl == null);
            contents.func_decl = inst;

            var extra_index: usize = extra.end;

            if (extra.data.bits.has_cc_body) {
                const body_len = zir.extra[extra_index];
                extra_index += 1;
                const body = zir.bodySlice(extra_index, body_len);
                try zir.findTrackableBody(gpa, contents, defers, body);
                extra_index += body.len;
            } else if (extra.data.bits.has_cc_ref) {
                extra_index += 1;
            }

            if (extra.data.bits.has_ret_ty_body) {
                const body_len = zir.extra[extra_index];
                extra_index += 1;
                const body = zir.bodySlice(extra_index, body_len);
                try zir.findTrackableBody(gpa, contents, defers, body);
                extra_index += body.len;
            } else if (extra.data.bits.has_ret_ty_ref) {
                extra_index += 1;
            }

            extra_index += @intFromBool(extra.data.bits.has_any_noalias);

            const body = zir.bodySlice(extra_index, extra.data.body_len);
            return zir.findTrackableBody(gpa, contents, defers, body);
        },

        // Block instructions, recurse over the bodies.

        .block,
        .block_inline,
        .c_import,
        .typeof_builtin,
        .loop,
        => {
            const inst_data = datas[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.Block, inst_data.payload_index);
            const body = zir.bodySlice(extra.end, extra.data.body_len);
            return zir.findTrackableBody(gpa, contents, defers, body);
        },
        .block_comptime => {
            const inst_data = datas[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.BlockComptime, inst_data.payload_index);
            const body = zir.bodySlice(extra.end, extra.data.body_len);
            return zir.findTrackableBody(gpa, contents, defers, body);
        },
        .condbr, .condbr_inline => {
            const inst_data = datas[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.CondBr, inst_data.payload_index);
            const then_body = zir.bodySlice(extra.end, extra.data.then_body_len);
            const else_body = zir.bodySlice(extra.end + then_body.len, extra.data.else_body_len);
            try zir.findTrackableBody(gpa, contents, defers, then_body);
            try zir.findTrackableBody(gpa, contents, defers, else_body);
        },
        .@"try", .try_ptr => {
            const inst_data = datas[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.Try, inst_data.payload_index);
            const body = zir.bodySlice(extra.end, extra.data.body_len);
            try zir.findTrackableBody(gpa, contents, defers, body);
        },
        .switch_block, .switch_block_ref => return zir.findTrackableSwitch(gpa, contents, defers, inst, .normal),
        .switch_block_err_union => return zir.findTrackableSwitch(gpa, contents, defers, inst, .err_union),

        .suspend_block => @panic("TODO iterate suspend block"),

        .param, .param_comptime => {
            const inst_data = datas[@intFromEnum(inst)].pl_tok;
            const extra = zir.extraData(Inst.Param, inst_data.payload_index);
            const body = zir.bodySlice(extra.end, extra.data.type.body_len);
            try zir.findTrackableBody(gpa, contents, defers, body);
        },

        inline .call, .field_call => |tag| {
            const inst_data = datas[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(switch (tag) {
                .call => Inst.Call,
                .field_call => Inst.FieldCall,
                else => unreachable,
            }, inst_data.payload_index);
            // It's easiest to just combine all the arg bodies into one body, like we do above for `struct_decl`.
            const args_len = extra.data.flags.args_len;
            if (args_len > 0) {
                const first_arg_start_off = args_len;
                const final_arg_end_off = zir.extra[extra.end + args_len - 1];
                const args_body = zir.bodySlice(extra.end + first_arg_start_off, final_arg_end_off - first_arg_start_off);
                try zir.findTrackableBody(gpa, contents, defers, args_body);
            }
        },
        .@"defer" => {
            const inst_data = datas[@intFromEnum(inst)].@"defer";
            const gop = try defers.getOrPut(gpa, inst_data.index);
            if (!gop.found_existing) {
                const body = zir.bodySlice(inst_data.index, inst_data.len);
                try zir.findTrackableBody(gpa, contents, defers, body);
            }
        },
        .defer_err_code => {
            const inst_data = datas[@intFromEnum(inst)].defer_err_code;
            const extra = zir.extraData(Inst.DeferErrCode, inst_data.payload_index).data;
            const gop = try defers.getOrPut(gpa, extra.index);
            if (!gop.found_existing) {
                const body = zir.bodySlice(extra.index, extra.len);
                try zir.findTrackableBody(gpa, contents, defers, body);
            }
        },
    }
}

fn findTrackableSwitch(
    zir: Zir,
    gpa: Allocator,
    contents: *DeclContents,
    defers: *std.AutoHashMapUnmanaged(u32, void),
    inst: Inst.Index,
    /// Distinguishes between `switch_block[_ref]` and `switch_block_err_union`.
    comptime kind: enum { normal, err_union },
) Allocator.Error!void {
    const inst_data = zir.instructions.items(.data)[@intFromEnum(inst)].pl_node;
    const extra = zir.extraData(switch (kind) {
        .normal => Inst.SwitchBlock,
        .err_union => Inst.SwitchBlockErrUnion,
    }, inst_data.payload_index);

    var extra_index: usize = extra.end;

    const multi_cases_len = if (extra.data.bits.has_multi_cases) blk: {
        const multi_cases_len = zir.extra[extra_index];
        extra_index += 1;
        break :blk multi_cases_len;
    } else 0;

    if (switch (kind) {
        .normal => extra.data.bits.any_has_tag_capture,
        .err_union => extra.data.bits.any_uses_err_capture,
    }) {
        extra_index += 1;
    }

    const has_special = switch (kind) {
        .normal => extra.data.bits.specialProng() != .none,
        .err_union => has_special: {
            // Handle `non_err_body` first.
            const prong_info: Inst.SwitchBlock.ProngInfo = @bitCast(zir.extra[extra_index]);
            extra_index += 1;
            const body = zir.bodySlice(extra_index, prong_info.body_len);
            extra_index += body.len;

            try zir.findTrackableBody(gpa, contents, defers, body);

            break :has_special extra.data.bits.has_else;
        },
    };

    if (has_special) {
        const prong_info: Inst.SwitchBlock.ProngInfo = @bitCast(zir.extra[extra_index]);
        extra_index += 1;
        const body = zir.bodySlice(extra_index, prong_info.body_len);
        extra_index += body.len;

        try zir.findTrackableBody(gpa, contents, defers, body);
    }

    {
        const scalar_cases_len = extra.data.bits.scalar_cases_len;
        for (0..scalar_cases_len) |_| {
            extra_index += 1;
            const prong_info: Inst.SwitchBlock.ProngInfo = @bitCast(zir.extra[extra_index]);
            extra_index += 1;
            const body = zir.bodySlice(extra_index, prong_info.body_len);
            extra_index += body.len;

            try zir.findTrackableBody(gpa, contents, defers, body);
        }
    }
    {
        for (0..multi_cases_len) |_| {
            const items_len = zir.extra[extra_index];
            extra_index += 1;
            const ranges_len = zir.extra[extra_index];
            extra_index += 1;
            const prong_info: Inst.SwitchBlock.ProngInfo = @bitCast(zir.extra[extra_index]);
            extra_index += 1;

            extra_index += items_len + ranges_len * 2;

            const body = zir.bodySlice(extra_index, prong_info.body_len);
            extra_index += body.len;

            try zir.findTrackableBody(gpa, contents, defers, body);
        }
    }
}

fn findTrackableBody(
    zir: Zir,
    gpa: Allocator,
    contents: *DeclContents,
    defers: *std.AutoHashMapUnmanaged(u32, void),
    body: []const Inst.Index,
) Allocator.Error!void {
    for (body) |member| {
        try zir.findTrackableInner(gpa, contents, defers, member);
    }
}

pub const FnInfo = struct {
    param_body: []const Inst.Index,
    param_body_inst: Inst.Index,
    ret_ty_body: []const Inst.Index,
    body: []const Inst.Index,
    ret_ty_ref: Zir.Inst.Ref,
    ret_ty_is_generic: bool,
    total_params_len: u32,
    inferred_error_set: bool,
};

pub fn getParamBody(zir: Zir, fn_inst: Inst.Index) []const Zir.Inst.Index {
    const tags = zir.instructions.items(.tag);
    const datas = zir.instructions.items(.data);
    const inst_data = datas[@intFromEnum(fn_inst)].pl_node;

    const param_block_index = switch (tags[@intFromEnum(fn_inst)]) {
        .func, .func_inferred => blk: {
            const extra = zir.extraData(Inst.Func, inst_data.payload_index);
            break :blk extra.data.param_block;
        },
        .func_fancy => blk: {
            const extra = zir.extraData(Inst.FuncFancy, inst_data.payload_index);
            break :blk extra.data.param_block;
        },
        else => unreachable,
    };

    switch (tags[@intFromEnum(param_block_index)]) {
        .block, .block_comptime, .block_inline => {
            const param_block = zir.extraData(Inst.Block, datas[@intFromEnum(param_block_index)].pl_node.payload_index);
            return zir.bodySlice(param_block.end, param_block.data.body_len);
        },
        .declaration => {
            return zir.getDeclaration(param_block_index).value_body.?;
        },
        else => unreachable,
    }
}

pub fn getFnInfo(zir: Zir, fn_inst: Inst.Index) FnInfo {
    const tags = zir.instructions.items(.tag);
    const datas = zir.instructions.items(.data);
    const info: struct {
        param_block: Inst.Index,
        body: []const Inst.Index,
        ret_ty_ref: Inst.Ref,
        ret_ty_body: []const Inst.Index,
        ret_ty_is_generic: bool,
        ies: bool,
    } = switch (tags[@intFromEnum(fn_inst)]) {
        .func, .func_inferred => |tag| blk: {
            const inst_data = datas[@intFromEnum(fn_inst)].pl_node;
            const extra = zir.extraData(Inst.Func, inst_data.payload_index);

            var extra_index: usize = extra.end;
            var ret_ty_ref: Inst.Ref = .none;
            var ret_ty_body: []const Inst.Index = &.{};

            switch (extra.data.ret_ty.body_len) {
                0 => {
                    ret_ty_ref = .void_type;
                },
                1 => {
                    ret_ty_ref = @enumFromInt(zir.extra[extra_index]);
                    extra_index += 1;
                },
                else => {
                    ret_ty_body = zir.bodySlice(extra_index, extra.data.ret_ty.body_len);
                    extra_index += ret_ty_body.len;
                },
            }

            const body = zir.bodySlice(extra_index, extra.data.body_len);
            extra_index += body.len;

            break :blk .{
                .param_block = extra.data.param_block,
                .ret_ty_ref = ret_ty_ref,
                .ret_ty_body = ret_ty_body,
                .body = body,
                .ret_ty_is_generic = extra.data.ret_ty.is_generic,
                .ies = tag == .func_inferred,
            };
        },
        .func_fancy => blk: {
            const inst_data = datas[@intFromEnum(fn_inst)].pl_node;
            const extra = zir.extraData(Inst.FuncFancy, inst_data.payload_index);

            var extra_index: usize = extra.end;
            var ret_ty_ref: Inst.Ref = .none;
            var ret_ty_body: []const Inst.Index = &.{};

            if (extra.data.bits.has_cc_body) {
                extra_index += zir.extra[extra_index] + 1;
            } else if (extra.data.bits.has_cc_ref) {
                extra_index += 1;
            }
            if (extra.data.bits.has_ret_ty_body) {
                const body_len = zir.extra[extra_index];
                extra_index += 1;
                ret_ty_body = zir.bodySlice(extra_index, body_len);
                extra_index += ret_ty_body.len;
            } else if (extra.data.bits.has_ret_ty_ref) {
                ret_ty_ref = @enumFromInt(zir.extra[extra_index]);
                extra_index += 1;
            } else {
                ret_ty_ref = .void_type;
            }

            extra_index += @intFromBool(extra.data.bits.has_any_noalias);

            const body = zir.bodySlice(extra_index, extra.data.body_len);
            extra_index += body.len;
            break :blk .{
                .param_block = extra.data.param_block,
                .ret_ty_ref = ret_ty_ref,
                .ret_ty_body = ret_ty_body,
                .body = body,
                .ret_ty_is_generic = extra.data.bits.ret_ty_is_generic,
                .ies = extra.data.bits.is_inferred_error,
            };
        },
        else => unreachable,
    };
    const param_body = zir.getParamBody(fn_inst);
    var total_params_len: u32 = 0;
    for (param_body) |inst| {
        switch (tags[@intFromEnum(inst)]) {
            .param, .param_comptime, .param_anytype, .param_anytype_comptime => {
                total_params_len += 1;
            },
            else => continue,
        }
    }
    return .{
        .param_body = param_body,
        .param_body_inst = info.param_block,
        .ret_ty_body = info.ret_ty_body,
        .ret_ty_ref = info.ret_ty_ref,
        .body = info.body,
        .total_params_len = total_params_len,
        .ret_ty_is_generic = info.ret_ty_is_generic,
        .inferred_error_set = info.ies,
    };
}

pub fn getDeclaration(zir: Zir, inst: Zir.Inst.Index) Inst.Declaration.Unwrapped {
    assert(zir.instructions.items(.tag)[@intFromEnum(inst)] == .declaration);
    const pl_node = zir.instructions.items(.data)[@intFromEnum(inst)].declaration;
    const extra = zir.extraData(Inst.Declaration, pl_node.payload_index);

    const flags_vals: [2]u32 = .{ extra.data.flags_0, extra.data.flags_1 };
    const flags: Inst.Declaration.Flags = @bitCast(flags_vals);

    var extra_index = extra.end;

    const name: NullTerminatedString = if (flags.id.hasName()) name: {
        const name = zir.extra[extra_index];
        extra_index += 1;
        break :name @enumFromInt(name);
    } else .empty;

    const lib_name: NullTerminatedString = if (flags.id.hasLibName()) lib_name: {
        const lib_name = zir.extra[extra_index];
        extra_index += 1;
        break :lib_name @enumFromInt(lib_name);
    } else .empty;

    const type_body_len: u32 = if (flags.id.hasTypeBody()) len: {
        const len = zir.extra[extra_index];
        extra_index += 1;
        break :len len;
    } else 0;
    const align_body_len: u32, const linksection_body_len: u32, const addrspace_body_len: u32 = lens: {
        if (!flags.id.hasSpecialBodies()) break :lens .{ 0, 0, 0 };
        const lens = zir.extra[extra_index..][0..3].*;
        extra_index += 3;
        break :lens lens;
    };
    const value_body_len: u32 = if (flags.id.hasValueBody()) len: {
        const len = zir.extra[extra_index];
        extra_index += 1;
        break :len len;
    } else 0;

    const type_body = zir.bodySlice(extra_index, type_body_len);
    extra_index += type_body_len;
    const align_body = zir.bodySlice(extra_index, align_body_len);
    extra_index += align_body_len;
    const linksection_body = zir.bodySlice(extra_index, linksection_body_len);
    extra_index += linksection_body_len;
    const addrspace_body = zir.bodySlice(extra_index, addrspace_body_len);
    extra_index += addrspace_body_len;
    const value_body = zir.bodySlice(extra_index, value_body_len);
    extra_index += value_body_len;

    return .{
        .src_node = pl_node.src_node,

        .src_line = flags.src_line,
        .src_column = flags.src_column,

        .kind = flags.id.kind(),
        .name = name,
        .is_pub = flags.id.isPub(),
        .is_threadlocal = flags.id.isThreadlocal(),
        .linkage = flags.id.linkage(),
        .lib_name = lib_name,

        .type_body = if (type_body_len == 0) null else type_body,
        .align_body = if (align_body_len == 0) null else align_body,
        .linksection_body = if (linksection_body_len == 0) null else linksection_body,
        .addrspace_body = if (addrspace_body_len == 0) null else addrspace_body,
        .value_body = if (value_body_len == 0) null else value_body,
    };
}

pub fn getAssociatedSrcHash(zir: Zir, inst: Zir.Inst.Index) ?std.zig.SrcHash {
    const tag = zir.instructions.items(.tag);
    const data = zir.instructions.items(.data);
    switch (tag[@intFromEnum(inst)]) {
        .declaration => {
            const declaration = data[@intFromEnum(inst)].declaration;
            const extra = zir.extraData(Inst.Declaration, declaration.payload_index);
            return @bitCast([4]u32{
                extra.data.src_hash_0,
                extra.data.src_hash_1,
                extra.data.src_hash_2,
                extra.data.src_hash_3,
            });
        },
        .func, .func_inferred => {
            const pl_node = data[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.Func, pl_node.payload_index);
            if (extra.data.body_len == 0) {
                // Function type or extern fn - no associated hash
                return null;
            }
            const extra_index = extra.end +
                extra.data.ret_ty.body_len +
                extra.data.body_len +
                @typeInfo(Inst.Func.SrcLocs).@"struct".fields.len;
            return @bitCast([4]u32{
                zir.extra[extra_index + 0],
                zir.extra[extra_index + 1],
                zir.extra[extra_index + 2],
                zir.extra[extra_index + 3],
            });
        },
        .func_fancy => {
            const pl_node = data[@intFromEnum(inst)].pl_node;
            const extra = zir.extraData(Inst.FuncFancy, pl_node.payload_index);
            if (extra.data.body_len == 0) {
                // Function type or extern fn - no associated hash
                return null;
            }
            const bits = extra.data.bits;
            var extra_index = extra.end;
            if (bits.has_cc_body) {
                const body_len = zir.extra[extra_index];
                extra_index += 1 + body_len;
            } else extra_index += @intFromBool(bits.has_cc_ref);
            if (bits.has_ret_ty_body) {
                const body_len = zir.extra[extra_index];
                extra_index += 1 + body_len;
            } else extra_index += @intFromBool(bits.has_ret_ty_ref);
            extra_index += @intFromBool(bits.has_any_noalias);
            extra_index += extra.data.body_len;
            extra_index += @typeInfo(Zir.Inst.Func.SrcLocs).@"struct".fields.len;
            return @bitCast([4]u32{
                zir.extra[extra_index + 0],
                zir.extra[extra_index + 1],
                zir.extra[extra_index + 2],
                zir.extra[extra_index + 3],
            });
        },
        .extended => {},
        else => return null,
    }
    const extended = data[@intFromEnum(inst)].extended;
    switch (extended.opcode) {
        .struct_decl => {
            const extra = zir.extraData(Inst.StructDecl, extended.operand).data;
            return @bitCast([4]u32{
                extra.fields_hash_0,
                extra.fields_hash_1,
                extra.fields_hash_2,
                extra.fields_hash_3,
            });
        },
        .union_decl => {
            const extra = zir.extraData(Inst.UnionDecl, extended.operand).data;
            return @bitCast([4]u32{
                extra.fields_hash_0,
                extra.fields_hash_1,
                extra.fields_hash_2,
                extra.fields_hash_3,
            });
        },
        .enum_decl => {
            const extra = zir.extraData(Inst.EnumDecl, extended.operand).data;
            return @bitCast([4]u32{
                extra.fields_hash_0,
                extra.fields_hash_1,
                extra.fields_hash_2,
                extra.fields_hash_3,
            });
        },
        else => return null,
    }
}

/// When the ZIR update tracking logic must be modified to consider new instructions,
/// change this constant to trigger compile errors at all relevant locations.
pub const inst_tracking_version = 0;

/// Asserts that a ZIR instruction is tracked across incremental updates, and
/// thus may be given an `InternPool.TrackedInst`.
pub fn assertTrackable(zir: Zir, inst_idx: Zir.Inst.Index) void {
    comptime assert(Zir.inst_tracking_version == 0);
    const inst = zir.instructions.get(@intFromEnum(inst_idx));
    switch (inst.tag) {
        .struct_init,
        .struct_init_ref,
        .struct_init_anon,
        => {}, // tracked in order, as the owner instructions of anonymous struct types
        .func, .func_inferred => {
            // These are tracked provided they are actual function declarations, not just bodies.
            const extra = zir.extraData(Inst.Func, inst.data.pl_node.payload_index);
            assert(extra.data.body_len != 0);
        },
        .func_fancy => {
            // These are tracked provided they are actual function declarations, not just bodies.
            const extra = zir.extraData(Inst.FuncFancy, inst.data.pl_node.payload_index);
            assert(extra.data.body_len != 0);
        },
        .declaration => {}, // tracked by correlating names in the namespace of the parent container
        .extended => switch (inst.data.extended.opcode) {
            .struct_decl,
            .union_decl,
            .enum_decl,
            .opaque_decl,
            .reify,
            => {}, // tracked in order, as the owner instructions of explicit container types
            else => unreachable, // assertion failure; not trackable
        },
        else => unreachable, // assertion failure; not trackable
    }
}

pub fn typeCapturesLen(zir: Zir, type_decl: Inst.Index) u32 {
    const inst = zir.instructions.get(@intFromEnum(type_decl));
    assert(inst.tag == .extended);
    switch (inst.data.extended.opcode) {
        .struct_decl => {
            const small: Inst.StructDecl.Small = @bitCast(inst.data.extended.small);
            if (!small.has_captures_len) return 0;
            const extra = zir.extraData(Inst.StructDecl, inst.data.extended.operand);
            return zir.extra[extra.end];
        },
        .union_decl => {
            const small: Inst.UnionDecl.Small = @bitCast(inst.data.extended.small);
            if (!small.has_captures_len) return 0;
            const extra = zir.extraData(Inst.UnionDecl, inst.data.extended.operand);
            return zir.extra[extra.end + @intFromBool(small.has_tag_type)];
        },
        .enum_decl => {
            const small: Inst.EnumDecl.Small = @bitCast(inst.data.extended.small);
            if (!small.has_captures_len) return 0;
            const extra = zir.extraData(Inst.EnumDecl, inst.data.extended.operand);
            return zir.extra[extra.end + @intFromBool(small.has_tag_type)];
        },
        .opaque_decl => {
            const small: Inst.OpaqueDecl.Small = @bitCast(inst.data.extended.small);
            if (!small.has_captures_len) return 0;
            const extra = zir.extraData(Inst.OpaqueDecl, inst.data.extended.operand);
            return zir.extra[extra.end];
        },
        else => unreachable,
    }
}
//! Zig Object Intermediate Representation.
//! Simplified AST for the ZON (Zig Object Notation) format.
//! `ZonGen` converts `Ast` to `Zoir`.

nodes: std.MultiArrayList(Node.Repr).Slice,
extra: []u32,
limbs: []std.math.big.Limb,
string_bytes: []u8,

compile_errors: []Zoir.CompileError,
error_notes: []Zoir.CompileError.Note,

/// The data stored at byte offset 0 when ZOIR is stored in a file.
pub const Header = extern struct {
    nodes_len: u32,
    extra_len: u32,
    limbs_len: u32,
    string_bytes_len: u32,
    compile_errors_len: u32,
    error_notes_len: u32,

    /// We could leave this as padding, however it triggers a Valgrind warning because
    /// we read and write undefined bytes to the file system. This is harmless, but
    /// it's essentially free to have a zero field here and makes the warning go away,
    /// making it more likely that following Valgrind warnings will be taken seriously.
    unused: u64 = 0,

    stat_inode: std.fs.File.INode,
    stat_size: u64,
    stat_mtime: i128,

    comptime {
        // Check that `unused` is working as expected
        assert(std.meta.hasUniqueRepresentation(Header));
    }
};

pub fn hasCompileErrors(zoir: Zoir) bool {
    if (zoir.compile_errors.len > 0) {
        assert(zoir.nodes.len == 0);
        assert(zoir.extra.len == 0);
        assert(zoir.limbs.len == 0);
        return true;
    } else {
        assert(zoir.error_notes.len == 0);
        return false;
    }
}

pub fn deinit(zoir: Zoir, gpa: Allocator) void {
    var nodes = zoir.nodes;
    nodes.deinit(gpa);

    gpa.free(zoir.extra);
    gpa.free(zoir.limbs);
    gpa.free(zoir.string_bytes);
    gpa.free(zoir.compile_errors);
    gpa.free(zoir.error_notes);
}

pub const Node = union(enum) {
    /// A literal `true` value.
    true,
    /// A literal `false` value.
    false,
    /// A literal `null` value.
    null,
    /// A literal `inf` value.
    pos_inf,
    /// A literal `-inf` value.
    neg_inf,
    /// A literal `nan` value.
    nan,
    /// An integer literal.
    int_literal: union(enum) {
        small: i32,
        big: std.math.big.int.Const,
    },
    /// A floating-point literal.
    float_literal: f128,
    /// A Unicode codepoint literal.
    char_literal: u21,
    /// An enum literal. The string is the literal, i.e. `foo` for `.foo`.
    enum_literal: NullTerminatedString,
    /// A string literal.
    string_literal: []const u8,
    /// An empty struct/array literal, i.e. `.{}`.
    empty_literal,
    /// An array literal. The `Range` gives the elements of the array literal.
    array_literal: Node.Index.Range,
    /// A struct literal. `names.len` is always equal to `vals.len`.
    struct_literal: struct {
        names: []const NullTerminatedString,
        vals: Node.Index.Range,
    },

    pub const Index = enum(u32) {
        root = 0,
        _,

        pub fn get(idx: Index, zoir: Zoir) Node {
            const repr = zoir.nodes.get(@intFromEnum(idx));
            return switch (repr.tag) {
                .true => .true,
                .false => .false,
                .null => .null,
                .pos_inf => .pos_inf,
                .neg_inf => .neg_inf,
                .nan => .nan,
                .int_literal_small => .{ .int_literal = .{ .small = @bitCast(repr.data) } },
                .int_literal_pos, .int_literal_neg => .{ .int_literal = .{ .big = .{
                    .limbs = l: {
                        const limb_count, const limbs_idx = zoir.extra[repr.data..][0..2].*;
                        break :l zoir.limbs[limbs_idx..][0..limb_count];
                    },
                    .positive = switch (repr.tag) {
                        .int_literal_pos => true,
                        .int_literal_neg => false,
                        else => unreachable,
                    },
                } } },
                .float_literal_small => .{ .float_literal = @as(f32, @bitCast(repr.data)) },
                .float_literal => .{ .float_literal = @bitCast(zoir.extra[repr.data..][0..4].*) },
                .char_literal => .{ .char_literal = @intCast(repr.data) },
                .enum_literal => .{ .enum_literal = @enumFromInt(repr.data) },
                .string_literal => .{ .string_literal = s: {
                    const start, const len = zoir.extra[repr.data..][0..2].*;
                    break :s zoir.string_bytes[start..][0..len];
                } },
                .string_literal_null => .{ .string_literal = NullTerminatedString.get(@enumFromInt(repr.data), zoir) },
                .empty_literal => .empty_literal,
                .array_literal => .{ .array_literal = a: {
                    const elem_count, const first_elem = zoir.extra[repr.data..][0..2].*;
                    break :a .{ .start = @enumFromInt(first_elem), .len = elem_count };
                } },
                .struct_literal => .{ .struct_literal = s: {
                    const elem_count, const first_elem = zoir.extra[repr.data..][0..2].*;
                    const field_names = zoir.extra[repr.data + 2 ..][0..elem_count];
                    break :s .{
                        .names = @ptrCast(field_names),
                        .vals = .{ .start = @enumFromInt(first_elem), .len = elem_count },
                    };
                } },
            };
        }

        pub fn getAstNode(idx: Index, zoir: Zoir) std.zig.Ast.Node.Index {
            return zoir.nodes.items(.ast_node)[@intFromEnum(idx)];
        }

        pub const Range = struct {
            start: Index,
            len: u32,

            pub fn at(r: Range, i: u32) Index {
                assert(i < r.len);
                return @enumFromInt(@intFromEnum(r.start) + i);
            }
        };
    };

    pub const Repr = struct {
        tag: Tag,
        data: u32,
        ast_node: std.zig.Ast.Node.Index,

        pub const Tag = enum(u8) {
            /// `data` is ignored.
            true,
            /// `data` is ignored.
            false,
            /// `data` is ignored.
            null,
            /// `data` is ignored.
            pos_inf,
            /// `data` is ignored.
            neg_inf,
            /// `data` is ignored.
            nan,
            /// `data` is the `i32` value.
            int_literal_small,
            /// `data` is index into `extra` of:
            /// * `limb_count: u32`
            /// * `limbs_idx: u32`
            int_literal_pos,
            /// Identical to `int_literal_pos`, except the value is negative.
            int_literal_neg,
            /// `data` is the `f32` value.
            float_literal_small,
            /// `data` is index into `extra` of 4 elements which are a bitcast `f128`.
            float_literal,
            /// `data` is the `u32` value.
            char_literal,
            /// `data` is a `NullTerminatedString`.
            enum_literal,
            /// `data` is index into `extra` of:
            /// * `start: u32`
            /// * `len: u32`
            string_literal,
            /// Null-terminated string literal,
            /// `data` is a `NullTerminatedString`.
            string_literal_null,
            /// An empty struct/array literal, `.{}`.
            /// `data` is ignored.
            empty_literal,
            /// `data` is index into `extra` of:
            /// * `elem_count: u32`
            /// * `first_elem: Node.Index`
            /// The nodes `first_elem .. first_elem + elem_count` are the children.
            array_literal,
            /// `data` is index into `extra` of:
            /// * `elem_count: u32`
            /// * `first_elem: Node.Index`
            /// * `field_name: NullTerminatedString` for each `elem_count`
            /// The nodes `first_elem .. first_elem + elem_count` are the children.
            struct_literal,
        };
    };
};

pub const NullTerminatedString = enum(u32) {
    _,
    pub fn get(nts: NullTerminatedString, zoir: Zoir) [:0]const u8 {
        const idx = std.mem.indexOfScalar(u8, zoir.string_bytes[@intFromEnum(nts)..], 0).?;
        return zoir.string_bytes[@intFromEnum(nts)..][0..idx :0];
    }
};

pub const CompileError = extern struct {
    msg: NullTerminatedString,
    token: Ast.OptionalTokenIndex,
    /// If `token == .none`, this is an `Ast.Node.Index`.
    /// Otherwise, this is a byte offset into `token`.
    node_or_offset: u32,

    /// Ignored if `note_count == 0`.
    first_note: u32,
    note_count: u32,

    pub fn getNotes(err: CompileError, zoir: Zoir) []const Note {
        return zoir.error_notes[err.first_note..][0..err.note_count];
    }

    pub const Note = extern struct {
        msg: NullTerminatedString,
        token: Ast.OptionalTokenIndex,
        /// If `token == .none`, this is an `Ast.Node.Index`.
        /// Otherwise, this is a byte offset into `token`.
        node_or_offset: u32,
    };

    comptime {
        assert(std.meta.hasUniqueRepresentation(CompileError));
        assert(std.meta.hasUniqueRepresentation(Note));
    }
};

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const Zoir = @This();
//! Ingests an `Ast` and produces a `Zoir`.

gpa: Allocator,
tree: Ast,

options: Options,

nodes: std.MultiArrayList(Zoir.Node.Repr),
extra: std.ArrayListUnmanaged(u32),
limbs: std.ArrayListUnmanaged(std.math.big.Limb),
string_bytes: std.ArrayListUnmanaged(u8),
string_table: std.HashMapUnmanaged(u32, void, StringIndexContext, std.hash_map.default_max_load_percentage),

compile_errors: std.ArrayListUnmanaged(Zoir.CompileError),
error_notes: std.ArrayListUnmanaged(Zoir.CompileError.Note),

pub const Options = struct {
    /// When false, string literals are not parsed. `string_literal` nodes will contain empty
    /// strings, and errors that normally occur during string parsing will not be raised.
    ///
    /// `parseStrLit` and `strLitSizeHint` may be used to parse string literals after the fact.
    parse_str_lits: bool = true,
};

pub fn generate(gpa: Allocator, tree: Ast, options: Options) Allocator.Error!Zoir {
    assert(tree.mode == .zon);

    var zg: ZonGen = .{
        .gpa = gpa,
        .tree = tree,
        .options = options,
        .nodes = .empty,
        .extra = .empty,
        .limbs = .empty,
        .string_bytes = .empty,
        .string_table = .empty,
        .compile_errors = .empty,
        .error_notes = .empty,
    };
    defer {
        zg.nodes.deinit(gpa);
        zg.extra.deinit(gpa);
        zg.limbs.deinit(gpa);
        zg.string_bytes.deinit(gpa);
        zg.string_table.deinit(gpa);
        zg.compile_errors.deinit(gpa);
        zg.error_notes.deinit(gpa);
    }

    if (tree.errors.len == 0) {
        const root_ast_node = tree.rootDecls()[0];
        try zg.nodes.append(gpa, undefined); // index 0; root node
        try zg.expr(root_ast_node, .root);
    } else {
        try zg.lowerAstErrors();
    }

    if (zg.compile_errors.items.len > 0) {
        const string_bytes = try zg.string_bytes.toOwnedSlice(gpa);
        errdefer gpa.free(string_bytes);
        const compile_errors = try zg.compile_errors.toOwnedSlice(gpa);
        errdefer gpa.free(compile_errors);
        const error_notes = try zg.error_notes.toOwnedSlice(gpa);
        errdefer gpa.free(error_notes);

        return .{
            .nodes = .empty,
            .extra = &.{},
            .limbs = &.{},
            .string_bytes = string_bytes,
            .compile_errors = compile_errors,
            .error_notes = error_notes,
        };
    } else {
        assert(zg.error_notes.items.len == 0);

        var nodes = zg.nodes.toOwnedSlice();
        errdefer nodes.deinit(gpa);
        const extra = try zg.extra.toOwnedSlice(gpa);
        errdefer gpa.free(extra);
        const limbs = try zg.limbs.toOwnedSlice(gpa);
        errdefer gpa.free(limbs);
        const string_bytes = try zg.string_bytes.toOwnedSlice(gpa);
        errdefer gpa.free(string_bytes);

        return .{
            .nodes = nodes,
            .extra = extra,
            .limbs = limbs,
            .string_bytes = string_bytes,
            .compile_errors = &.{},
            .error_notes = &.{},
        };
    }
}

fn expr(zg: *ZonGen, node: Ast.Node.Index, dest_node: Zoir.Node.Index) Allocator.Error!void {
    const gpa = zg.gpa;
    const tree = zg.tree;

    switch (tree.nodeTag(node)) {
        .root => unreachable,
        .@"usingnamespace" => unreachable,
        .test_decl => unreachable,
        .container_field_init => unreachable,
        .container_field_align => unreachable,
        .container_field => unreachable,
        .fn_decl => unreachable,
        .global_var_decl => unreachable,
        .local_var_decl => unreachable,
        .simple_var_decl => unreachable,
        .aligned_var_decl => unreachable,
        .@"defer" => unreachable,
        .@"errdefer" => unreachable,
        .switch_case => unreachable,
        .switch_case_inline => unreachable,
        .switch_case_one => unreachable,
        .switch_case_inline_one => unreachable,
        .switch_range => unreachable,
        .asm_output => unreachable,
        .asm_input => unreachable,
        .for_range => unreachable,
        .assign => unreachable,
        .assign_destructure => unreachable,
        .assign_shl => unreachable,
        .assign_shl_sat => unreachable,
        .assign_shr => unreachable,
        .assign_bit_and => unreachable,
        .assign_bit_or => unreachable,
        .assign_bit_xor => unreachable,
        .assign_div => unreachable,
        .assign_sub => unreachable,
        .assign_sub_wrap => unreachable,
        .assign_sub_sat => unreachable,
        .assign_mod => unreachable,
        .assign_add => unreachable,
        .assign_add_wrap => unreachable,
        .assign_add_sat => unreachable,
        .assign_mul => unreachable,
        .assign_mul_wrap => unreachable,
        .assign_mul_sat => unreachable,

        .shl,
        .shr,
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
        .array_mult,
        .bool_and,
        .bool_or,
        .bool_not,
        .bit_not,
        .negation_wrap,
        => try zg.addErrorTok(tree.nodeMainToken(node), "operator '{s}' is not allowed in ZON", .{tree.tokenSlice(tree.nodeMainToken(node))}),

        .error_union,
        .merge_error_sets,
        .optional_type,
        .anyframe_literal,
        .anyframe_type,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
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
        .array_type,
        .array_type_sentinel,
        .error_set_decl,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => try zg.addErrorNode(node, "types are not available in ZON", .{}),

        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .@"return",
        .if_simple,
        .@"if",
        .while_simple,
        .while_cont,
        .@"while",
        .for_simple,
        .@"for",
        .@"catch",
        .@"orelse",
        .@"break",
        .@"continue",
        .@"switch",
        .switch_comma,
        .@"nosuspend",
        .@"suspend",
        .@"await",
        .@"resume",
        .@"try",
        .unreachable_literal,
        => try zg.addErrorNode(node, "control flow is not allowed in ZON", .{}),

        .@"comptime" => try zg.addErrorNode(node, "keyword 'comptime' is not allowed in ZON", .{}),
        .asm_simple, .@"asm" => try zg.addErrorNode(node, "inline asm is not allowed in ZON", .{}),

        .builtin_call_two,
        .builtin_call_two_comma,
        .builtin_call,
        .builtin_call_comma,
        => try zg.addErrorNode(node, "builtin function calls are not allowed in ZON", .{}),

        .field_access => try zg.addErrorNode(node, "field accesses are not allowed in ZON", .{}),

        .slice_open,
        .slice,
        .slice_sentinel,
        => try zg.addErrorNode(node, "slice operator is not allowed in ZON", .{}),

        .deref, .address_of => try zg.addErrorTok(tree.nodeMainToken(node), "pointers are not available in ZON", .{}),
        .unwrap_optional => try zg.addErrorTok(tree.nodeMainToken(node), "optionals are not available in ZON", .{}),
        .error_value => try zg.addErrorNode(node, "errors are not available in ZON", .{}),

        .array_access => try zg.addErrorNode(node, "array indexing is not allowed in ZON", .{}),

        .block_two,
        .block_two_semicolon,
        .block,
        .block_semicolon,
        => {
            var buffer: [2]Ast.Node.Index = undefined;
            const statements = tree.blockStatements(&buffer, node).?;
            if (statements.len == 0) {
                try zg.addErrorNodeNotes(node, "void literals are not available in ZON", .{}, &.{
                    try zg.errNoteNode(node, "void union payloads can be represented by enum literals", .{}),
                });
            } else {
                try zg.addErrorNode(node, "blocks are not allowed in ZON", .{});
            }
        },

        .array_init_one,
        .array_init_one_comma,
        .array_init,
        .array_init_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init,
        .struct_init_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;

            const type_node = if (tree.fullArrayInit(&buf, node)) |full|
                full.ast.type_expr.unwrap().?
            else if (tree.fullStructInit(&buf, node)) |full|
                full.ast.type_expr.unwrap().?
            else
                unreachable;

            try zg.addErrorNodeNotes(type_node, "types are not available in ZON", .{}, &.{
                try zg.errNoteNode(type_node, "replace the type with '.'", .{}),
            });
        },

        .grouped_expression => {
            try zg.addErrorTokNotes(tree.nodeMainToken(node), "expression grouping is not allowed in ZON", .{}, &.{
                try zg.errNoteTok(tree.nodeMainToken(node), "these parentheses are always redundant", .{}),
            });
            return zg.expr(tree.nodeData(node).node_and_token[0], dest_node);
        },

        .negation => {
            const child_node = tree.nodeData(node).node;
            switch (tree.nodeTag(child_node)) {
                .number_literal => return zg.numberLiteral(child_node, node, dest_node, .negative),
                .identifier => {
                    const child_ident = tree.tokenSlice(tree.nodeMainToken(child_node));
                    if (mem.eql(u8, child_ident, "inf")) {
                        zg.setNode(dest_node, .{
                            .tag = .neg_inf,
                            .data = 0, // ignored
                            .ast_node = node,
                        });
                        return;
                    }
                },
                else => {},
            }
            try zg.addErrorTok(tree.nodeMainToken(node), "expected number or 'inf' after '-'", .{});
        },
        .number_literal => try zg.numberLiteral(node, node, dest_node, .positive),
        .char_literal => try zg.charLiteral(node, dest_node),

        .identifier => try zg.identifier(node, dest_node),

        .enum_literal => {
            const str_index = zg.identAsString(tree.nodeMainToken(node)) catch |err| switch (err) {
                error.BadString => undefined, // doesn't matter, there's an error
                error.OutOfMemory => |e| return e,
            };
            zg.setNode(dest_node, .{
                .tag = .enum_literal,
                .data = @intFromEnum(str_index),
                .ast_node = node,
            });
        },
        .string_literal, .multiline_string_literal => if (zg.strLitAsString(node)) |result| switch (result) {
            .nts => |nts| zg.setNode(dest_node, .{
                .tag = .string_literal_null,
                .data = @intFromEnum(nts),
                .ast_node = node,
            }),
            .slice => |slice| {
                const extra_index: u32 = @intCast(zg.extra.items.len);
                try zg.extra.appendSlice(zg.gpa, &.{ slice.start, slice.len });
                zg.setNode(dest_node, .{
                    .tag = .string_literal,
                    .data = extra_index,
                    .ast_node = node,
                });
            },
        } else |err| switch (err) {
            error.BadString => {},
            error.OutOfMemory => |e| return e,
        },

        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const full = tree.fullArrayInit(&buf, node).?;
            assert(full.ast.elements.len != 0); // Otherwise it would be a struct init
            assert(full.ast.type_expr == .none); // The tag was `array_init_dot_*`

            const first_elem: u32 = @intCast(zg.nodes.len);
            try zg.nodes.resize(gpa, zg.nodes.len + full.ast.elements.len);

            const extra_index: u32 = @intCast(zg.extra.items.len);
            try zg.extra.appendSlice(gpa, &.{
                @intCast(full.ast.elements.len),
                first_elem,
            });

            zg.setNode(dest_node, .{
                .tag = .array_literal,
                .data = extra_index,
                .ast_node = node,
            });

            for (full.ast.elements, first_elem..) |elem_node, elem_dest_node| {
                try zg.expr(elem_node, @enumFromInt(elem_dest_node));
            }
        },

        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const full = tree.fullStructInit(&buf, node).?;
            assert(full.ast.type_expr == .none); // The tag was `struct_init_dot_*`

            if (full.ast.fields.len == 0) {
                zg.setNode(dest_node, .{
                    .tag = .empty_literal,
                    .data = 0, // ignored
                    .ast_node = node,
                });
                return;
            }

            const first_elem: u32 = @intCast(zg.nodes.len);
            try zg.nodes.resize(gpa, zg.nodes.len + full.ast.fields.len);

            const extra_index: u32 = @intCast(zg.extra.items.len);
            try zg.extra.ensureUnusedCapacity(gpa, 2 + full.ast.fields.len);
            zg.extra.appendSliceAssumeCapacity(&.{
                @intCast(full.ast.fields.len),
                first_elem,
            });
            const names_start = extra_index + 2;
            zg.extra.appendNTimesAssumeCapacity(undefined, full.ast.fields.len);

            zg.setNode(dest_node, .{
                .tag = .struct_literal,
                .data = extra_index,
                .ast_node = node,
            });

            // For short initializers, track the names on the stack rather than going through gpa.
            var sfba_state = std.heap.stackFallback(256, gpa);
            const sfba = sfba_state.get();
            var field_names: std.AutoHashMapUnmanaged(Zoir.NullTerminatedString, Ast.TokenIndex) = .empty;
            defer field_names.deinit(sfba);

            var reported_any_duplicate = false;

            for (full.ast.fields, names_start.., first_elem..) |elem_node, extra_name_idx, elem_dest_node| {
                const name_token = tree.firstToken(elem_node) - 2;
                if (zg.identAsString(name_token)) |name_str| {
                    zg.extra.items[extra_name_idx] = @intFromEnum(name_str);
                    const gop = try field_names.getOrPut(sfba, name_str);
                    if (gop.found_existing and !reported_any_duplicate) {
                        reported_any_duplicate = true;
                        const earlier_token = gop.value_ptr.*;
                        try zg.addErrorTokNotes(earlier_token, "duplicate struct field name", .{}, &.{
                            try zg.errNoteTok(name_token, "duplicate name here", .{}),
                        });
                    }
                    gop.value_ptr.* = name_token;
                } else |err| switch (err) {
                    error.BadString => {}, // there's an error, so it's fine to not populate `zg.extra`
                    error.OutOfMemory => |e| return e,
                }
                try zg.expr(elem_node, @enumFromInt(elem_dest_node));
            }
        },
    }
}

fn appendIdentStr(zg: *ZonGen, ident_token: Ast.TokenIndex) !u32 {
    const tree = zg.tree;
    assert(tree.tokenTag(ident_token) == .identifier);
    const ident_name = tree.tokenSlice(ident_token);
    if (!mem.startsWith(u8, ident_name, "@")) {
        const start = zg.string_bytes.items.len;
        try zg.string_bytes.appendSlice(zg.gpa, ident_name);
        return @intCast(start);
    } else {
        const offset = 1;
        const start: u32 = @intCast(zg.string_bytes.items.len);
        const raw_string = zg.tree.tokenSlice(ident_token)[offset..];
        try zg.string_bytes.ensureUnusedCapacity(zg.gpa, raw_string.len);
        switch (try std.zig.string_literal.parseWrite(zg.string_bytes.writer(zg.gpa), raw_string)) {
            .success => {},
            .failure => |err| {
                try zg.lowerStrLitError(err, ident_token, raw_string, offset);
                return error.BadString;
            },
        }

        const slice = zg.string_bytes.items[start..];
        if (mem.indexOfScalar(u8, slice, 0) != null) {
            try zg.addErrorTok(ident_token, "identifier cannot contain null bytes", .{});
            return error.BadString;
        } else if (slice.len == 0) {
            try zg.addErrorTok(ident_token, "identifier cannot be empty", .{});
            return error.BadString;
        }
        return start;
    }
}

/// Estimates the size of a string node without parsing it.
pub fn strLitSizeHint(tree: Ast, node: Ast.Node.Index) usize {
    switch (tree.nodeTag(node)) {
        // Parsed string literals are typically around the size of the raw strings.
        .string_literal => {
            const token = tree.nodeMainToken(node);
            const raw_string = tree.tokenSlice(token);
            return raw_string.len;
        },
        // Multiline string literal lengths can be computed exactly.
        .multiline_string_literal => {
            const first_tok, const last_tok = tree.nodeData(node).token_and_token;

            var size = tree.tokenSlice(first_tok)[2..].len;
            for (first_tok + 1..last_tok + 1) |tok_idx| {
                size += 1; // Newline
                size += tree.tokenSlice(@intCast(tok_idx))[2..].len;
            }
            return size;
        },
        else => unreachable,
    }
}

/// Parses the given node as a string literal.
pub fn parseStrLit(
    tree: Ast,
    node: Ast.Node.Index,
    writer: anytype,
) error{OutOfMemory}!std.zig.string_literal.Result {
    switch (tree.nodeTag(node)) {
        .string_literal => {
            const token = tree.nodeMainToken(node);
            const raw_string = tree.tokenSlice(token);
            return std.zig.string_literal.parseWrite(writer, raw_string);
        },
        .multiline_string_literal => {
            const first_tok, const last_tok = tree.nodeData(node).token_and_token;

            // First line: do not append a newline.
            {
                const line_bytes = tree.tokenSlice(first_tok)[2..];
                try writer.writeAll(line_bytes);
            }

            // Following lines: each line prepends a newline.
            for (first_tok + 1..last_tok + 1) |tok_idx| {
                const line_bytes = tree.tokenSlice(@intCast(tok_idx))[2..];
                try writer.writeByte('\n');
                try writer.writeAll(line_bytes);
            }

            return .success;
        },
        // Node must represent a string
        else => unreachable,
    }
}

const StringLiteralResult = union(enum) {
    nts: Zoir.NullTerminatedString,
    slice: struct { start: u32, len: u32 },
};

fn strLitAsString(zg: *ZonGen, str_node: Ast.Node.Index) !StringLiteralResult {
    if (!zg.options.parse_str_lits) return .{ .slice = .{ .start = 0, .len = 0 } };

    const gpa = zg.gpa;
    const string_bytes = &zg.string_bytes;
    const str_index: u32 = @intCast(zg.string_bytes.items.len);
    const size_hint = strLitSizeHint(zg.tree, str_node);
    try string_bytes.ensureUnusedCapacity(zg.gpa, size_hint);
    switch (try parseStrLit(zg.tree, str_node, zg.string_bytes.writer(zg.gpa))) {
        .success => {},
        .failure => |err| {
            const token = zg.tree.nodeMainToken(str_node);
            const raw_string = zg.tree.tokenSlice(token);
            try zg.lowerStrLitError(err, token, raw_string, 0);
            return error.BadString;
        },
    }
    const key: []const u8 = string_bytes.items[str_index..];
    if (std.mem.indexOfScalar(u8, key, 0) != null) return .{ .slice = .{
        .start = str_index,
        .len = @intCast(key.len),
    } };
    const gop = try zg.string_table.getOrPutContextAdapted(
        gpa,
        key,
        StringIndexAdapter{ .bytes = string_bytes },
        StringIndexContext{ .bytes = string_bytes },
    );
    if (gop.found_existing) {
        string_bytes.shrinkRetainingCapacity(str_index);
        return .{ .nts = @enumFromInt(gop.key_ptr.*) };
    }
    gop.key_ptr.* = str_index;
    try string_bytes.append(gpa, 0);
    return .{ .nts = @enumFromInt(str_index) };
}

fn identAsString(zg: *ZonGen, ident_token: Ast.TokenIndex) !Zoir.NullTerminatedString {
    const gpa = zg.gpa;
    const string_bytes = &zg.string_bytes;
    const str_index = try zg.appendIdentStr(ident_token);
    const key: []const u8 = string_bytes.items[str_index..];
    const gop = try zg.string_table.getOrPutContextAdapted(
        gpa,
        key,
        StringIndexAdapter{ .bytes = string_bytes },
        StringIndexContext{ .bytes = string_bytes },
    );
    if (gop.found_existing) {
        string_bytes.shrinkRetainingCapacity(str_index);
        return @enumFromInt(gop.key_ptr.*);
    }
    gop.key_ptr.* = str_index;
    try string_bytes.append(gpa, 0);
    return @enumFromInt(str_index);
}

fn numberLiteral(zg: *ZonGen, num_node: Ast.Node.Index, src_node: Ast.Node.Index, dest_node: Zoir.Node.Index, sign: enum { negative, positive }) !void {
    const tree = zg.tree;
    const num_token = tree.nodeMainToken(num_node);
    const num_bytes = tree.tokenSlice(num_token);

    switch (std.zig.parseNumberLiteral(num_bytes)) {
        .int => |unsigned_num| {
            if (unsigned_num == 0 and sign == .negative) {
                try zg.addErrorTokNotes(num_token, "integer literal '-0' is ambiguous", .{}, &.{
                    try zg.errNoteTok(num_token, "use '0' for an integer zero", .{}),
                    try zg.errNoteTok(num_token, "use '-0.0' for a floating-point signed zero", .{}),
                });
                return;
            }
            const num: i65 = switch (sign) {
                .positive => unsigned_num,
                .negative => -@as(i65, unsigned_num),
            };
            if (std.math.cast(i32, num)) |x| {
                zg.setNode(dest_node, .{
                    .tag = .int_literal_small,
                    .data = @bitCast(x),
                    .ast_node = src_node,
                });
                return;
            }
            const max_limbs = comptime std.math.big.int.calcTwosCompLimbCount(@bitSizeOf(@TypeOf(num)));
            var limbs: [max_limbs]std.math.big.Limb = undefined;
            var big_int: std.math.big.int.Mutable = .init(&limbs, num);
            try zg.setBigIntLiteralNode(dest_node, src_node, big_int.toConst());
        },
        .big_int => |base| {
            const gpa = zg.gpa;
            const num_without_prefix = switch (base) {
                .decimal => num_bytes,
                .hex, .binary, .octal => num_bytes[2..],
            };
            var big_int: std.math.big.int.Managed = try .init(gpa);
            defer big_int.deinit();
            big_int.setString(@intFromEnum(base), num_without_prefix) catch |err| switch (err) {
                error.InvalidCharacter => unreachable, // caught in `parseNumberLiteral`
                error.InvalidBase => unreachable, // we only pass 16, 8, 2, see above
                error.OutOfMemory => return error.OutOfMemory,
            };
            switch (sign) {
                .positive => {},
                .negative => big_int.negate(),
            }
            try zg.setBigIntLiteralNode(dest_node, src_node, big_int.toConst());
        },
        .float => {
            const unsigned_num = std.fmt.parseFloat(f128, num_bytes) catch |err| switch (err) {
                error.InvalidCharacter => unreachable, // validated by tokenizer
            };
            const num: f128 = switch (sign) {
                .positive => unsigned_num,
                .negative => -unsigned_num,
            };

            {
                // If the value fits into an f32 without losing any precision, store it that way.
                @setFloatMode(.strict);
                const smaller_float: f32 = @floatCast(num);
                const bigger_again: f128 = smaller_float;
                if (bigger_again == num) {
                    zg.setNode(dest_node, .{
                        .tag = .float_literal_small,
                        .data = @bitCast(smaller_float),
                        .ast_node = src_node,
                    });
                    return;
                }
            }

            const elems: [4]u32 = @bitCast(num);
            const extra_index: u32 = @intCast(zg.extra.items.len);
            try zg.extra.appendSlice(zg.gpa, &elems);
            zg.setNode(dest_node, .{
                .tag = .float_literal,
                .data = extra_index,
                .ast_node = src_node,
            });
        },
        .failure => |err| try zg.lowerNumberError(err, num_token, num_bytes),
    }
}

fn setBigIntLiteralNode(zg: *ZonGen, dest_node: Zoir.Node.Index, src_node: Ast.Node.Index, val: std.math.big.int.Const) !void {
    try zg.extra.ensureUnusedCapacity(zg.gpa, 2);
    try zg.limbs.ensureUnusedCapacity(zg.gpa, val.limbs.len);

    const limbs_idx: u32 = @intCast(zg.limbs.items.len);
    zg.limbs.appendSliceAssumeCapacity(val.limbs);

    const extra_idx: u32 = @intCast(zg.extra.items.len);
    zg.extra.appendSliceAssumeCapacity(&.{ @intCast(val.limbs.len), limbs_idx });

    zg.setNode(dest_node, .{
        .tag = if (val.positive) .int_literal_pos else .int_literal_neg,
        .data = extra_idx,
        .ast_node = src_node,
    });
}

fn charLiteral(zg: *ZonGen, node: Ast.Node.Index, dest_node: Zoir.Node.Index) !void {
    const tree = zg.tree;
    assert(tree.nodeTag(node) == .char_literal);
    const main_token = tree.nodeMainToken(node);
    const slice = tree.tokenSlice(main_token);
    switch (std.zig.parseCharLiteral(slice)) {
        .success => |codepoint| zg.setNode(dest_node, .{
            .tag = .char_literal,
            .data = codepoint,
            .ast_node = node,
        }),
        .failure => |err| try zg.lowerStrLitError(err, main_token, slice, 0),
    }
}

fn identifier(zg: *ZonGen, node: Ast.Node.Index, dest_node: Zoir.Node.Index) !void {
    const tree = zg.tree;
    assert(tree.nodeTag(node) == .identifier);
    const main_token = tree.nodeMainToken(node);
    const ident = tree.tokenSlice(main_token);

    const tag: Zoir.Node.Repr.Tag = t: {
        if (mem.eql(u8, ident, "true")) break :t .true;
        if (mem.eql(u8, ident, "false")) break :t .false;
        if (mem.eql(u8, ident, "null")) break :t .null;
        if (mem.eql(u8, ident, "inf")) break :t .pos_inf;
        if (mem.eql(u8, ident, "nan")) break :t .nan;
        try zg.addErrorNodeNotes(node, "invalid expression", .{}, &.{
            try zg.errNoteNode(node, "ZON allows identifiers 'true', 'false', 'null', 'inf', and 'nan'", .{}),
            try zg.errNoteNode(node, "precede identifier with '.' for an enum literal", .{}),
        });
        return;
    };

    zg.setNode(dest_node, .{
        .tag = tag,
        .data = 0, // ignored
        .ast_node = node,
    });
}

fn setNode(zg: *ZonGen, dest: Zoir.Node.Index, repr: Zoir.Node.Repr) void {
    zg.nodes.set(@intFromEnum(dest), repr);
}

fn lowerStrLitError(
    zg: *ZonGen,
    err: std.zig.string_literal.Error,
    token: Ast.TokenIndex,
    raw_string: []const u8,
    offset: u32,
) Allocator.Error!void {
    return ZonGen.addErrorTokOff(
        zg,
        token,
        @intCast(offset + err.offset()),
        "{}",
        .{err.fmt(raw_string)},
    );
}

fn lowerNumberError(zg: *ZonGen, err: std.zig.number_literal.Error, token: Ast.TokenIndex, bytes: []const u8) Allocator.Error!void {
    const is_float = std.mem.indexOfScalar(u8, bytes, '.') != null;
    switch (err) {
        .leading_zero => if (is_float) {
            try zg.addErrorTok(token, "number '{s}' has leading zero", .{bytes});
        } else {
            try zg.addErrorTokNotes(token, "number '{s}' has leading zero", .{bytes}, &.{
                try zg.errNoteTok(token, "use '0o' prefix for octal literals", .{}),
            });
        },
        .digit_after_base => try zg.addErrorTok(token, "expected a digit after base prefix", .{}),
        .upper_case_base => |i| try zg.addErrorTokOff(token, @intCast(i), "base prefix must be lowercase", .{}),
        .invalid_float_base => |i| try zg.addErrorTokOff(token, @intCast(i), "invalid base for float literal", .{}),
        .repeated_underscore => |i| try zg.addErrorTokOff(token, @intCast(i), "repeated digit separator", .{}),
        .invalid_underscore_after_special => |i| try zg.addErrorTokOff(token, @intCast(i), "expected digit before digit separator", .{}),
        .invalid_digit => |info| try zg.addErrorTokOff(token, @intCast(info.i), "invalid digit '{c}' for {s} base", .{ bytes[info.i], @tagName(info.base) }),
        .invalid_digit_exponent => |i| try zg.addErrorTokOff(token, @intCast(i), "invalid digit '{c}' in exponent", .{bytes[i]}),
        .duplicate_exponent => |i| try zg.addErrorTokOff(token, @intCast(i), "duplicate exponent", .{}),
        .exponent_after_underscore => |i| try zg.addErrorTokOff(token, @intCast(i), "expected digit before exponent", .{}),
        .special_after_underscore => |i| try zg.addErrorTokOff(token, @intCast(i), "expected digit before '{c}'", .{bytes[i]}),
        .trailing_special => |i| try zg.addErrorTokOff(token, @intCast(i), "expected digit after '{c}'", .{bytes[i - 1]}),
        .trailing_underscore => |i| try zg.addErrorTokOff(token, @intCast(i), "trailing digit separator", .{}),
        .duplicate_period => unreachable, // Validated by tokenizer
        .invalid_character => unreachable, // Validated by tokenizer
        .invalid_exponent_sign => |i| {
            assert(bytes.len >= 2 and bytes[0] == '0' and bytes[1] == 'x'); // Validated by tokenizer
            try zg.addErrorTokOff(token, @intCast(i), "sign '{c}' cannot follow digit '{c}' in hex base", .{ bytes[i], bytes[i - 1] });
        },
        .period_after_exponent => |i| try zg.addErrorTokOff(token, @intCast(i), "unexpected period after exponent", .{}),
    }
}

fn errNoteNode(zg: *ZonGen, node: Ast.Node.Index, comptime format: []const u8, args: anytype) Allocator.Error!Zoir.CompileError.Note {
    const message_idx: u32 = @intCast(zg.string_bytes.items.len);
    const writer = zg.string_bytes.writer(zg.gpa);
    try writer.print(format, args);
    try writer.writeByte(0);

    return .{
        .msg = @enumFromInt(message_idx),
        .token = .none,
        .node_or_offset = @intFromEnum(node),
    };
}

fn errNoteTok(zg: *ZonGen, tok: Ast.TokenIndex, comptime format: []const u8, args: anytype) Allocator.Error!Zoir.CompileError.Note {
    const message_idx: u32 = @intCast(zg.string_bytes.items.len);
    const writer = zg.string_bytes.writer(zg.gpa);
    try writer.print(format, args);
    try writer.writeByte(0);

    return .{
        .msg = @enumFromInt(message_idx),
        .token = .fromToken(tok),
        .node_or_offset = 0,
    };
}

fn addErrorNode(zg: *ZonGen, node: Ast.Node.Index, comptime format: []const u8, args: anytype) Allocator.Error!void {
    return zg.addErrorInner(.none, @intFromEnum(node), format, args, &.{});
}
fn addErrorTok(zg: *ZonGen, tok: Ast.TokenIndex, comptime format: []const u8, args: anytype) Allocator.Error!void {
    return zg.addErrorInner(.fromToken(tok), 0, format, args, &.{});
}
fn addErrorNodeNotes(zg: *ZonGen, node: Ast.Node.Index, comptime format: []const u8, args: anytype, notes: []const Zoir.CompileError.Note) Allocator.Error!void {
    return zg.addErrorInner(.none, @intFromEnum(node), format, args, notes);
}
fn addErrorTokNotes(zg: *ZonGen, tok: Ast.TokenIndex, comptime format: []const u8, args: anytype, notes: []const Zoir.CompileError.Note) Allocator.Error!void {
    return zg.addErrorInner(.fromToken(tok), 0, format, args, notes);
}
fn addErrorTokOff(zg: *ZonGen, tok: Ast.TokenIndex, offset: u32, comptime format: []const u8, args: anytype) Allocator.Error!void {
    return zg.addErrorInner(.fromToken(tok), offset, format, args, &.{});
}
fn addErrorTokNotesOff(zg: *ZonGen, tok: Ast.TokenIndex, offset: u32, comptime format: []const u8, args: anytype, notes: []const Zoir.CompileError.Note) Allocator.Error!void {
    return zg.addErrorInner(.fromToken(tok), offset, format, args, notes);
}

fn addErrorInner(
    zg: *ZonGen,
    token: Ast.OptionalTokenIndex,
    node_or_offset: u32,
    comptime format: []const u8,
    args: anytype,
    notes: []const Zoir.CompileError.Note,
) Allocator.Error!void {
    const gpa = zg.gpa;

    const first_note: u32 = @intCast(zg.error_notes.items.len);
    try zg.error_notes.appendSlice(gpa, notes);

    const message_idx: u32 = @intCast(zg.string_bytes.items.len);
    const writer = zg.string_bytes.writer(zg.gpa);
    try writer.print(format, args);
    try writer.writeByte(0);

    try zg.compile_errors.append(gpa, .{
        .msg = @enumFromInt(message_idx),
        .token = token,
        .node_or_offset = node_or_offset,
        .first_note = first_note,
        .note_count = @intCast(not```
