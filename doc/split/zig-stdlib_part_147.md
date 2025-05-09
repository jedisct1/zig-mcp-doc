```
,
        /// Convert a larger float type to any other float type, possibly causing
        /// a loss of precision.
        /// Uses the `pl_node` field. AST is the `@floatCast` syntax.
        /// Payload is `Bin` with lhs as the dest type, rhs the operand.
        float_cast,
        /// Implements the `@intCast` builtin.
        /// Uses `pl_node` with payload `Bin`. `lhs` is dest type, `rhs` is operand.
        /// Convert an integer value to another integer type, asserting that the destination type
        /// can hold the same mathematical value.
        int_cast,
        /// Implements the `@ptrCast` builtin.
        /// Uses `pl_node` with payload `Bin`. `lhs` is dest type, `rhs` is operand.
        /// Not every `@ptrCast` will correspond to this instruction - see also
        /// `ptr_cast_full` in `Extended`.
        ptr_cast,
        /// Implements the `@truncate` builtin.
        /// Uses `pl_node` with payload `Bin`. `lhs` is dest type, `rhs` is operand.
        truncate,

        /// Implements the `@hasDecl` builtin.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        has_decl,
        /// Implements the `@hasField` builtin.
        /// Uses the `pl_node` union field. Payload is `Bin`.
        has_field,

        /// Implements the `@clz` builtin. Uses the `un_node` union field.
        clz,
        /// Implements the `@ctz` builtin. Uses the `un_node` union field.
        ctz,
        /// Implements the `@popCount` builtin. Uses the `un_node` union field.
        pop_count,
        /// Implements the `@byteSwap` builtin. Uses the `un_node` union field.
        byte_swap,
        /// Implements the `@bitReverse` builtin. Uses the `un_node` union field.
        bit_reverse,

        /// Implements the `@bitOffsetOf` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        bit_offset_of,
        /// Implements the `@offsetOf` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        offset_of,
        /// Implements the `@splat` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        splat,
        /// Implements the `@reduce` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        reduce,
        /// Implements the `@shuffle` builtin.
        /// Uses the `pl_node` union field with payload `Shuffle`.
        shuffle,
        /// Implements the `@atomicLoad` builtin.
        /// Uses the `pl_node` union field with payload `AtomicLoad`.
        atomic_load,
        /// Implements the `@atomicRmw` builtin.
        /// Uses the `pl_node` union field with payload `AtomicRmw`.
        atomic_rmw,
        /// Implements the `@atomicStore` builtin.
        /// Uses the `pl_node` union field with payload `AtomicStore`.
        atomic_store,
        /// Implements the `@mulAdd` builtin.
        /// Uses the `pl_node` union field with payload `MulAdd`.
        /// The addend communicates the type of the builtin.
        /// The mulends need to be coerced to the same type.
        mul_add,
        /// Implements the `@memcpy` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        memcpy,
        /// Implements the `@memset` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        memset,
        /// Implements the `@memmove` builtin.
        /// Uses the `pl_node` union field with payload `Bin`.
        memmove,
        /// Implements the `@min` builtin for 2 args.
        /// Uses the `pl_node` union field with payload `Bin`
        min,
        /// Implements the `@max` builtin for 2 args.
        /// Uses the `pl_node` union field with payload `Bin`
        max,
        /// Implements the `@cImport` builtin.
        /// Uses the `pl_node` union field with payload `Block`.
        c_import,

        /// Allocates stack local memory.
        /// Uses the `un_node` union field. The operand is the type of the allocated object.
        /// The node source location points to a var decl node.
        /// A `make_ptr_const` instruction should be used once the value has
        /// been stored to the allocation. To ensure comptime value detection
        /// functions, there are some restrictions on how this pointer should be
        /// used prior to the `make_ptr_const` instruction: no pointer derived
        /// from this `alloc` may be returned from a block or stored to another
        /// address. In other words, it must be trivial to determine whether any
        /// given pointer derives from this one.
        alloc,
        /// Same as `alloc` except mutable. As such, `make_ptr_const` need not be used,
        /// and there are no restrictions on the usage of the pointer.
        alloc_mut,
        /// Allocates comptime-mutable memory.
        /// Uses the `un_node` union field. The operand is the type of the allocated object.
        /// The node source location points to a var decl node.
        alloc_comptime_mut,
        /// Same as `alloc` except the type is inferred.
        /// Uses the `node` union field.
        alloc_inferred,
        /// Same as `alloc_inferred` except mutable.
        alloc_inferred_mut,
        /// Allocates comptime const memory.
        /// Uses the `node` union field. The type of the allocated object is inferred.
        /// The node source location points to a var decl node.
        alloc_inferred_comptime,
        /// Same as `alloc_comptime_mut` except the type is inferred.
        alloc_inferred_comptime_mut,
        /// Each `store_to_inferred_ptr` puts the type of the stored value into a set,
        /// and then `resolve_inferred_alloc` triggers peer type resolution on the set.
        /// The operand is a `alloc_inferred` or `alloc_inferred_mut` instruction, which
        /// is the allocation that needs to have its type inferred.
        /// Results in the final resolved pointer. The `alloc_inferred[_comptime][_mut]`
        /// instruction should never be referred to after this instruction.
        /// Uses the `un_node` field. The AST node is the var decl.
        resolve_inferred_alloc,
        /// Turns a pointer coming from an `alloc` or `Extended.alloc` into a constant
        /// version of the same pointer. For inferred allocations this is instead implicitly
        /// handled by the `resolve_inferred_alloc` instruction.
        /// Uses the `un_node` union field.
        make_ptr_const,

        /// Implements `resume` syntax. Uses `un_node` field.
        @"resume",
        @"await",

        /// A defer statement.
        /// Uses the `defer` union field.
        @"defer",
        /// An errdefer statement with a code.
        /// Uses the `err_defer_code` union field.
        defer_err_code,

        /// Requests that Sema update the saved error return trace index for the enclosing
        /// block, if the operand is .none or of an error/error-union type.
        /// Uses the `save_err_ret_index` field.
        save_err_ret_index,
        /// Specialized form of `Extended.restore_err_ret_index`.
        /// Unconditionally restores the error return index to its last saved state
        /// in the block referred to by `operand`. If `operand` is `none`, restores
        /// to the point of function entry.
        /// Uses the `un_node` field.
        restore_err_ret_index_unconditional,
        /// Specialized form of `Extended.restore_err_ret_index`.
        /// Restores the error return index to its state at the entry of
        /// the current function conditional on `operand` being a non-error.
        /// If `operand` is `none`, restores unconditionally.
        /// Uses the `un_node` field.
        restore_err_ret_index_fn_entry,

        /// The ZIR instruction tag is one of the `Extended` ones.
        /// Uses the `extended` union field.
        extended,

        /// Returns whether the instruction is one of the control flow "noreturn" types.
        /// Function calls do not count.
        pub fn isNoReturn(tag: Tag) bool {
            return switch (tag) {
                .param,
                .param_comptime,
                .param_anytype,
                .param_anytype_comptime,
                .add,
                .addwrap,
                .add_sat,
                .add_unsafe,
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
                .call,
                .field_call,
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
                .elem_ptr,
                .elem_val,
                .elem_ptr_node,
                .elem_val_node,
                .elem_val_imm,
                .ensure_result_used,
                .ensure_result_non_error,
                .ensure_err_union_payload_void,
                .@"export",
                .field_ptr,
                .field_val,
                .field_ptr_named,
                .field_val_named,
                .func,
                .func_inferred,
                .func_fancy,
                .has_decl,
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
                .store_node,
                .store_to_inferred_ptr,
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
                .typeof_log2_int_type,
                .resolve_inferred_alloc,
                .set_eval_branch_quota,
                .switch_block,
                .switch_block_ref,
                .switch_block_err_union,
                .validate_deref,
                .validate_destructure,
                .union_init,
                .field_type_ref,
                .enum_from_int,
                .int_from_enum,
                .type_info,
                .size_of,
                .bit_size_of,
                .int_from_ptr,
                .align_of,
                .int_from_bool,
                .embed_file,
                .error_name,
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
                .float_cast,
                .int_cast,
                .ptr_cast,
                .truncate,
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
                .atomic_store,
                .mul_add,
                .builtin_call,
                .max,
                .memcpy,
                .memset,
                .memmove,
                .min,
                .c_import,
                .@"resume",
                .@"await",
                .ret_err_value_code,
                .extended,
                .ret_ptr,
                .ret_type,
                .@"try",
                .try_ptr,
                .@"defer",
                .defer_err_code,
                .save_err_ret_index,
                .for_len,
                .opt_eu_base_ptr_init,
                .coerce_ptr_elem_ty,
                .struct_init_empty,
                .struct_init_empty_result,
                .struct_init_empty_ref_result,
                .struct_init_anon,
                .struct_init,
                .struct_init_ref,
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
                .validate_ref_ty,
                .validate_const,
                .restore_err_ret_index_unconditional,
                .restore_err_ret_index_fn_entry,
                => false,

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
                => true,
            };
        }

        /// AstGen uses this to find out if `Ref.void_value` should be used in place
        /// of the result of a given instruction. This allows Sema to forego adding
        /// the instruction to the map after analysis.
        pub fn isAlwaysVoid(tag: Tag, data: Data) bool {
            return switch (tag) {
                .dbg_stmt,
                .dbg_var_ptr,
                .dbg_var_val,
                .ensure_result_used,
                .ensure_result_non_error,
                .ensure_err_union_payload_void,
                .set_eval_branch_quota,
                .atomic_store,
                .store_node,
                .store_to_inferred_ptr,
                .validate_deref,
                .validate_destructure,
                .@"export",
                .set_runtime_safety,
                .memcpy,
                .memset,
                .memmove,
                .check_comptime_control_flow,
                .@"defer",
                .defer_err_code,
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
                => true,

                .param,
                .param_comptime,
                .param_anytype,
                .param_anytype_comptime,
                .add,
                .addwrap,
                .add_sat,
                .add_unsafe,
                .alloc,
                .alloc_mut,
                .alloc_comptime_mut,
                .alloc_inferred,
                .alloc_inferred_mut,
                .alloc_inferred_comptime,
                .alloc_inferred_comptime_mut,
                .resolve_inferred_alloc,
                .make_ptr_const,
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
                .call,
                .field_call,
                .cmp_lt,
                .cmp_lte,
                .cmp_eq,
                .cmp_gte,
                .cmp_gt,
                .cmp_neq,
                .error_set_decl,
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
                .has_decl,
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
                .typeof_log2_int_type,
                .switch_block,
                .switch_block_ref,
                .switch_block_err_union,
                .union_init,
                .field_type_ref,
                .enum_from_int,
                .int_from_enum,
                .type_info,
                .size_of,
                .bit_size_of,
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
                .builtin_call,
                .max,
                .min,
                .c_import,
                .@"resume",
                .@"await",
                .ret_err_value_code,
                .@"break",
                .break_inline,
                .condbr,
                .condbr_inline,
                .switch_continue,
                .compile_error,
                .ret_node,
                .ret_load,
                .ret_implicit,
                .ret_err_value,
                .ret_ptr,
                .ret_type,
                .@"unreachable",
                .repeat,
                .repeat_inline,
                .panic,
                .trap,
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
                => false,

                .extended => switch (data.extended.opcode) {
                    .branch_hint,
                    .breakpoint,
                    .disable_instrumentation,
                    .disable_intrinsics,
                    => true,
                    else => false,
                },
            };
        }

        /// Used by debug safety-checking code.
        pub const data_tags = list: {
            @setEvalBranchQuota(2000);
            break :list std.enums.directEnumArray(Tag, Data.FieldEnum, 0, .{
                .add = .pl_node,
                .addwrap = .pl_node,
                .add_sat = .pl_node,
                .add_unsafe = .pl_node,
                .sub = .pl_node,
                .subwrap = .pl_node,
                .sub_sat = .pl_node,
                .mul = .pl_node,
                .mulwrap = .pl_node,
                .mul_sat = .pl_node,

                .param = .pl_tok,
                .param_comptime = .pl_tok,
                .param_anytype = .str_tok,
                .param_anytype_comptime = .str_tok,
                .array_cat = .pl_node,
                .array_mul = .pl_node,
                .array_type = .pl_node,
                .array_type_sentinel = .pl_node,
                .vector_type = .pl_node,
                .elem_type = .un_node,
                .indexable_ptr_elem_type = .un_node,
                .vec_arr_elem_type = .un_node,
                .indexable_ptr_len = .un_node,
                .anyframe_type = .un_node,
                .as_node = .pl_node,
                .as_shift_operand = .pl_node,
                .bit_and = .pl_node,
                .bitcast = .pl_node,
                .bit_not = .un_node,
                .bit_or = .pl_node,
                .block = .pl_node,
                .block_comptime = .pl_node,
                .block_inline = .pl_node,
                .declaration = .declaration,
                .suspend_block = .pl_node,
                .bool_not = .un_node,
                .bool_br_and = .pl_node,
                .bool_br_or = .pl_node,
                .@"break" = .@"break",
                .break_inline = .@"break",
                .switch_continue = .@"break",
                .check_comptime_control_flow = .un_node,
                .for_len = .pl_node,
                .call = .pl_node,
                .field_call = .pl_node,
                .cmp_lt = .pl_node,
                .cmp_lte = .pl_node,
                .cmp_eq = .pl_node,
                .cmp_gte = .pl_node,
                .cmp_gt = .pl_node,
                .cmp_neq = .pl_node,
                .condbr = .pl_node,
                .condbr_inline = .pl_node,
                .@"try" = .pl_node,
                .try_ptr = .pl_node,
                .error_set_decl = .pl_node,
                .dbg_stmt = .dbg_stmt,
                .dbg_var_ptr = .str_op,
                .dbg_var_val = .str_op,
                .decl_ref = .str_tok,
                .decl_val = .str_tok,
                .load = .un_node,
                .div = .pl_node,
                .elem_ptr = .pl_node,
                .elem_ptr_node = .pl_node,
                .elem_val = .pl_node,
                .elem_val_node = .pl_node,
                .elem_val_imm = .elem_val_imm,
                .ensure_result_used = .un_node,
                .ensure_result_non_error = .un_node,
                .ensure_err_union_payload_void = .un_node,
                .error_union_type = .pl_node,
                .error_value = .str_tok,
                .@"export" = .pl_node,
                .field_ptr = .pl_node,
                .field_val = .pl_node,
                .field_ptr_named = .pl_node,
                .field_val_named = .pl_node,
                .func = .pl_node,
                .func_inferred = .pl_node,
                .func_fancy = .pl_node,
                .import = .pl_tok,
                .int = .int,
                .int_big = .str,
                .float = .float,
                .float128 = .pl_node,
                .int_type = .int_type,
                .is_non_null = .un_node,
                .is_non_null_ptr = .un_node,
                .is_non_err = .un_node,
                .is_non_err_ptr = .un_node,
                .ret_is_non_err = .un_node,
                .loop = .pl_node,
                .repeat = .node,
                .repeat_inline = .node,
                .merge_error_sets = .pl_node,
                .mod_rem = .pl_node,
                .ref = .un_tok,
                .ret_node = .un_node,
                .ret_load = .un_node,
                .ret_implicit = .un_tok,
                .ret_err_value = .str_tok,
                .ret_err_value_code = .str_tok,
                .ret_ptr = .node,
                .ret_type = .node,
                .ptr_type = .ptr_type,
                .slice_start = .pl_node,
                .slice_end = .pl_node,
                .slice_sentinel = .pl_node,
                .slice_length = .pl_node,
                .slice_sentinel_ty = .un_node,
                .store_node = .pl_node,
                .store_to_inferred_ptr = .pl_node,
                .str = .str,
                .negate = .un_node,
                .negate_wrap = .un_node,
                .typeof = .un_node,
                .typeof_log2_int_type = .un_node,
                .@"unreachable" = .@"unreachable",
                .xor = .pl_node,
                .optional_type = .un_node,
                .optional_payload_safe = .un_node,
                .optional_payload_unsafe = .un_node,
                .optional_payload_safe_ptr = .un_node,
                .optional_payload_unsafe_ptr = .un_node,
                .err_union_payload_unsafe = .un_node,
                .err_union_payload_unsafe_ptr = .un_node,
                .err_union_code = .un_node,
                .err_union_code_ptr = .un_node,
                .enum_literal = .str_tok,
                .decl_literal = .pl_node,
                .decl_literal_no_coerce = .pl_node,
                .switch_block = .pl_node,
                .switch_block_ref = .pl_node,
                .switch_block_err_union = .pl_node,
                .validate_deref = .un_node,
                .validate_destructure = .pl_node,
                .field_type_ref = .pl_node,
                .union_init = .pl_node,
                .type_info = .un_node,
                .size_of = .un_node,
                .bit_size_of = .un_node,
                .opt_eu_base_ptr_init = .un_node,
                .coerce_ptr_elem_ty = .pl_node,
                .validate_ref_ty = .un_tok,
                .validate_const = .un_node,

                .int_from_ptr = .un_node,
                .compile_error = .un_node,
                .set_eval_branch_quota = .un_node,
                .int_from_enum = .un_node,
                .align_of = .un_node,
                .int_from_bool = .un_node,
                .embed_file = .un_node,
                .error_name = .un_node,
                .panic = .un_node,
                .trap = .node,
                .set_runtime_safety = .un_node,
                .sqrt = .un_node,
                .sin = .un_node,
                .cos = .un_node,
                .tan = .un_node,
                .exp = .un_node,
                .exp2 = .un_node,
                .log = .un_node,
                .log2 = .un_node,
                .log10 = .un_node,
                .abs = .un_node,
                .floor = .un_node,
                .ceil = .un_node,
                .trunc = .un_node,
                .round = .un_node,
                .tag_name = .un_node,
                .type_name = .un_node,
                .frame_type = .un_node,
                .frame_size = .un_node,

                .int_from_float = .pl_node,
                .float_from_int = .pl_node,
                .ptr_from_int = .pl_node,
                .enum_from_int = .pl_node,
                .float_cast = .pl_node,
                .int_cast = .pl_node,
                .ptr_cast = .pl_node,
                .truncate = .pl_node,
                .typeof_builtin = .pl_node,

                .has_decl = .pl_node,
                .has_field = .pl_node,

                .clz = .un_node,
                .ctz = .un_node,
                .pop_count = .un_node,
                .byte_swap = .un_node,
                .bit_reverse = .un_node,

                .div_exact = .pl_node,
                .div_floor = .pl_node,
                .div_trunc = .pl_node,
                .mod = .pl_node,
                .rem = .pl_node,

                .shl = .pl_node,
                .shl_exact = .pl_node,
                .shl_sat = .pl_node,
                .shr = .pl_node,
                .shr_exact = .pl_node,

                .bit_offset_of = .pl_node,
                .offset_of = .pl_node,
                .splat = .pl_node,
                .reduce = .pl_node,
                .shuffle = .pl_node,
                .atomic_load = .pl_node,
                .atomic_rmw = .pl_node,
                .atomic_store = .pl_node,
                .mul_add = .pl_node,
                .builtin_call = .pl_node,
                .max = .pl_node,
                .memcpy = .pl_node,
                .memset = .pl_node,
                .memmove = .pl_node,
                .min = .pl_node,
                .c_import = .pl_node,

                .alloc = .un_node,
                .alloc_mut = .un_node,
                .alloc_comptime_mut = .un_node,
                .alloc_inferred = .node,
                .alloc_inferred_mut = .node,
                .alloc_inferred_comptime = .node,
                .alloc_inferred_comptime_mut = .node,
                .resolve_inferred_alloc = .un_node,
                .make_ptr_const = .un_node,

                .@"resume" = .un_node,
                .@"await" = .un_node,

                .@"defer" = .@"defer",
                .defer_err_code = .defer_err_code,

                .save_err_ret_index = .save_err_ret_index,
                .restore_err_ret_index_unconditional = .un_node,
                .restore_err_ret_index_fn_entry = .un_node,

                .struct_init_empty = .un_node,
                .struct_init_empty_result = .un_node,
                .struct_init_empty_ref_result = .un_node,
                .struct_init_anon = .pl_node,
                .struct_init = .pl_node,
                .struct_init_ref = .pl_node,
                .validate_struct_init_ty = .un_node,
                .validate_struct_init_result_ty = .un_node,
                .validate_ptr_struct_init = .pl_node,
                .struct_init_field_type = .pl_node,
                .struct_init_field_ptr = .pl_node,
                .array_init_anon = .pl_node,
                .array_init = .pl_node,
                .array_init_ref = .pl_node,
                .validate_array_init_ty = .pl_node,
                .validate_array_init_result_ty = .pl_node,
                .validate_array_init_ref_ty = .pl_node,
                .validate_ptr_array_init = .pl_node,
                .array_init_elem_type = .bin,
                .array_init_elem_ptr = .pl_node,

                .extended = .extended,
            });
        };

        // Uncomment to view how many tag slots are available.
        //comptime {
        //    @compileLog("ZIR tags left: ", 256 - @typeInfo(Tag).@"enum".fields.len);
        //}
    };

    /// Rarer instructions are here; ones that do not fit in the 8-bit `Tag` enum.
    /// `noreturn` instructions may not go here; they must be part of the main `Tag` enum.
    pub const Extended = enum(u16) {
        /// A struct type definition. Contains references to ZIR instructions for
        /// the field types, defaults, and alignments.
        /// `operand` is payload index to `StructDecl`.
        /// `small` is `StructDecl.Small`.
        struct_decl,
        /// An enum type definition. Contains references to ZIR instructions for
        /// the field value expressions and optional type tag expression.
        /// `operand` is payload index to `EnumDecl`.
        /// `small` is `EnumDecl.Small`.
        enum_decl,
        /// A union type definition. Contains references to ZIR instructions for
        /// the field types and optional type tag expression.
        /// `operand` is payload index to `UnionDecl`.
        /// `small` is `UnionDecl.Small`.
        union_decl,
        /// An opaque type definition. Contains references to decls and captures.
        /// `operand` is payload index to `OpaqueDecl`.
        /// `small` is `OpaqueDecl.Small`.
        opaque_decl,
        /// A tuple type. Note that tuples are not namespace/container types.
        /// `operand` is payload index to `TupleDecl`.
        /// `small` is `fields_len: u16`.
        tuple_decl,
        /// Implements the `@This` builtin.
        /// `operand` is `src_node: Ast.Node.Offset`.
        this,
        /// Implements the `@returnAddress` builtin.
        /// `operand` is `src_node: Ast.Node.Offset`.
        ret_addr,
        /// Implements the `@src` builtin.
        /// `operand` is payload index to `LineColumn`.
        builtin_src,
        /// Implements the `@errorReturnTrace` builtin.
        /// `operand` is `src_node: Ast.Node.Offset`.
        error_return_trace,
        /// Implements the `@frame` builtin.
        /// `operand` is `src_node: Ast.Node.Offset`.
        frame,
        /// Implements the `@frameAddress` builtin.
        /// `operand` is `src_node: Ast.Node.Offset`.
        frame_address,
        /// Same as `alloc` from `Tag` but may contain an alignment instruction.
        /// `operand` is payload index to `AllocExtended`.
        /// `small`:
        ///  * 0b000X - has type
        ///  * 0b00X0 - has alignment
        ///  * 0b0X00 - 1=const, 0=var
        ///  * 0bX000 - is comptime
        alloc,
        /// The `@extern` builtin.
        /// `operand` is payload index to `BinNode`.
        builtin_extern,
        /// Inline assembly.
        /// `small`:
        ///  * 0b00000000_000XXXXX - `outputs_len`.
        ///  * 0b000000XX_XXX00000 - `inputs_len`.
        ///  * 0b0XXXXX00_00000000 - `clobbers_len`.
        ///  * 0bX0000000_00000000 - is volatile
        /// `operand` is payload index to `Asm`.
        @"asm",
        /// Same as `asm` except the assembly template is not a string literal but a comptime
        /// expression.
        /// The `asm_source` field of the Asm is not a null-terminated string
        /// but instead a Ref.
        asm_expr,
        /// Log compile time variables and emit an error message.
        /// `operand` is payload index to `NodeMultiOp`.
        /// `small` is `operands_len`.
        /// The AST node is the compile log builtin call.
        compile_log,
        /// The builtin `@TypeOf` which returns the type after Peer Type Resolution
        /// of one or more params.
        /// `operand` is payload index to `TypeOfPeer`.
        /// `small` is `operands_len`.
        /// The AST node is the builtin call.
        typeof_peer,
        /// Implements the `@min` builtin for more than 2 args.
        /// `operand` is payload index to `NodeMultiOp`.
        /// `small` is `operands_len`.
        /// The AST node is the builtin call.
        min_multi,
        /// Implements the `@max` builtin for more than 2 args.
        /// `operand` is payload index to `NodeMultiOp`.
        /// `small` is `operands_len`.
        /// The AST node is the builtin call.
        max_multi,
        /// Implements the `@addWithOverflow` builtin.
        /// `operand` is payload index to `BinNode`.
        /// `small` is unused.
        add_with_overflow,
        /// Implements the `@subWithOverflow` builtin.
        /// `operand` is payload index to `BinNode`.
        /// `small` is unused.
        sub_with_overflow,
        /// Implements the `@mulWithOverflow` builtin.
        /// `operand` is payload index to `BinNode`.
        /// `small` is unused.
        mul_with_overflow,
        /// Implements the `@shlWithOverflow` builtin.
        /// `operand` is payload index to `BinNode`.
        /// `small` is unused.
        shl_with_overflow,
        /// `operand` is payload index to `UnNode`.
        c_undef,
        /// `operand` is payload index to `UnNode`.
        c_include,
        /// `operand` is payload index to `BinNode`.
        c_define,
        /// `operand` is payload index to `UnNode`.
        wasm_memory_size,
        /// `operand` is payload index to `BinNode`.
        wasm_memory_grow,
        /// The `@prefetch` builtin.
        /// `operand` is payload index to `BinNode`.
        prefetch,
        /// Implement builtin `@setFloatMode`.
        /// `operand` is payload index to `UnNode`.
        set_float_mode,
        /// Implements the `@errorCast` builtin.
        /// `operand` is payload index to `BinNode`. `lhs` is dest type, `rhs` is operand.
        error_cast,
        /// `operand` is payload index to `UnNode`.
        await_nosuspend,
        /// Implements `@breakpoint`.
        /// `operand` is `src_node: Ast.Node.Offset`.
        breakpoint,
        /// Implement builtin `@disableInstrumentation`. `operand` is `src_node: Ast.Node.Offset`.
        disable_instrumentation,
        /// Implement builtin `@disableIntrinsics`. `operand` is `src_node: i32`.
        disable_intrinsics,
        /// Implements the `@select` builtin.
        /// `operand` is payload index to `Select`.
        select,
        /// Implement builtin `@errToInt`.
        /// `operand` is payload index to `UnNode`.
        int_from_error,
        /// Implement builtin `@errorFromInt`.
        /// `operand` is payload index to `UnNode`.
        error_from_int,
        /// Implement builtin `@Type`.
        /// `operand` is payload index to `Reify`.
        /// `small` contains `NameStrategy`.
        reify,
        /// Implements the `@asyncCall` builtin.
        /// `operand` is payload index to `AsyncCall`.
        builtin_async_call,
        /// Implements the `@cmpxchgStrong` and `@cmpxchgWeak` builtins.
        /// `small` 0=>weak 1=>strong
        /// `operand` is payload index to `Cmpxchg`.
        cmpxchg,
        /// Implement builtin `@cVaArg`.
        /// `operand` is payload index to `BinNode`.
        c_va_arg,
        /// Implement builtin `@cVaCopy`.
        /// `operand` is payload index to `UnNode`.
        c_va_copy,
        /// Implement builtin `@cVaEnd`.
        /// `operand` is payload index to `UnNode`.
        c_va_end,
        /// Implement builtin `@cVaStart`.
        /// `operand` is `src_node: Ast.Node.Offset`.
        c_va_start,
        /// Implements the following builtins:
        /// `@ptrCast`, `@alignCast`, `@addrSpaceCast`, `@constCast`, `@volatileCast`.
        /// Represents an arbitrary nesting of the above builtins. Such a nesting is treated as a
        /// single operation which can modify multiple components of a pointer type.
        /// `operand` is payload index to `BinNode`.
        /// `small` contains `FullPtrCastFlags`.
        /// AST node is the root of the nested casts.
        /// `lhs` is dest type, `rhs` is operand.
        ptr_cast_full,
        /// `operand` is payload index to `UnNode`.
        /// `small` contains `FullPtrCastFlags`.
        /// Guaranteed to only have flags where no explicit destination type is
        /// required (const_cast and volatile_cast).
        /// AST node is the root of the nested casts.
        ptr_cast_no_dest,
        /// Implements the `@workItemId` builtin.
        /// `operand` is payload index to `UnNode`.
        work_item_id,
        /// Implements the `@workGroupSize` builtin.
        /// `operand` is payload index to `UnNode`.
        work_group_size,
        /// Implements the `@workGroupId` builtin.
        /// `operand` is payload index to `UnNode`.
        work_group_id,
        /// Implements the `@inComptime` builtin.
        /// `operand` is `src_node: Ast.Node.Offset`.
        in_comptime,
        /// Restores the error return index to its last saved state in a given
        /// block. If the block is `.none`, restores to the state from the point
        /// of function entry. If the operand is not `.none`, the restore is
        /// conditional on the operand value not being an error.
        /// `operand` is payload index to `RestoreErrRetIndex`.
        /// `small` is undefined.
        restore_err_ret_index,
        /// Retrieves a value from the current type declaration scope's closure.
        /// `operand` is `src_node: Ast.Node.Offset`.
        /// `small` is closure index.
        closure_get,
        /// Used as a placeholder instruction which is just a dummy index for Sema to replace
        /// with a specific value. For instance, this is used for the capture of an `errdefer`.
        /// This should never appear in a body.
        value_placeholder,
        /// Implements the `@fieldParentPtr` builtin.
        /// `operand` is payload index to `FieldParentPtr`.
        /// `small` contains `FullPtrCastFlags`.
        /// Guaranteed to not have the `ptr_cast` flag.
        /// Uses the `pl_node` union field with payload `FieldParentPtr`.
        field_parent_ptr,
        /// Get a type or value from `std.builtin`.
        /// `operand` is `src_node: Ast.Node.Offset`.
        /// `small` is an `Inst.BuiltinValue`.
        builtin_value,
        /// Provide a `@branchHint` for the current block.
        /// `operand` is payload index to `UnNode`.
        /// `small` is unused.
        branch_hint,
        /// Compute the result type for in-place arithmetic, e.g. `+=`.
        /// `operand` is `Zir.Inst.Ref` of the loaded LHS (*not* its type).
        /// `small` is an `Inst.InplaceOp`.
        inplace_arith_result_ty,
        /// Marks a statement that can be stepped to but produces no code.
        /// `operand` and `small` are ignored.
        dbg_empty_stmt,
        /// At this point, AstGen encountered a fatal error which terminated ZIR lowering for this body.
        /// A file-level error has been reported. Sema should terminate semantic analysis.
        /// `operand` and `small` are ignored.
        /// This instruction is always `noreturn`, however, it is not considered as such by ZIR-level queries. This allows AstGen to assume that
        /// any code may have gone here, avoiding false-positive "unreachable code" errors.
        astgen_error,

        pub const InstData = struct {
            opcode: Extended,
            small: u16,
            operand: u32,
        };
    };

    /// The position of a ZIR instruction within the `Zir` instructions array.
    pub const Index = enum(u32) {
        /// ZIR is structured so that the outermost "main" struct of any file
        /// is always at index 0.
        main_struct_inst = 0,
        ref_start_index = static_len,
        _,

        pub const static_len = 97;

        pub fn toRef(i: Index) Inst.Ref {
            return @enumFromInt(@intFromEnum(Index.ref_start_index) + @intFromEnum(i));
        }

        pub fn toOptional(i: Index) OptionalIndex {
            return @enumFromInt(@intFromEnum(i));
        }
    };

    pub const OptionalIndex = enum(u32) {
        /// ZIR is structured so that the outermost "main" struct of any file
        /// is always at index 0.
        main_struct_inst = 0,
        ref_start_index = Index.static_len,
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(oi: OptionalIndex) ?Index {
            return if (oi == .none) null else @enumFromInt(@intFromEnum(oi));
        }
    };

    /// A reference to ZIR instruction, or to an InternPool index, or neither.
    ///
    /// If the integer tag value is < InternPool.static_len, then it
    /// corresponds to an InternPool index. Otherwise, this refers to a ZIR
    /// instruction.
    ///
    /// The tag type is specified so that it is safe to bitcast between `[]u32`
    /// and `[]Ref`.
    pub const Ref = enum(u32) {
        u0_type,
        i0_type,
        u1_type,
        u8_type,
        i8_type,
        u16_type,
        i16_type,
        u29_type,
        u32_type,
        i32_type,
        u64_type,
        i64_type,
        u80_type,
        u128_type,
        i128_type,
        usize_type,
        isize_type,
        c_char_type,
        c_short_type,
        c_ushort_type,
        c_int_type,
        c_uint_type,
        c_long_type,
        c_ulong_type,
        c_longlong_type,
        c_ulonglong_type,
        c_longdouble_type,
        f16_type,
        f32_type,
        f64_type,
        f80_type,
        f128_type,
        anyopaque_type,
        bool_type,
        void_type,
        type_type,
        anyerror_type,
        comptime_int_type,
        comptime_float_type,
        noreturn_type,
        anyframe_type,
        null_type,
        undefined_type,
        enum_literal_type,
        manyptr_u8_type,
        manyptr_const_u8_type,
        manyptr_const_u8_sentinel_0_type,
        single_const_pointer_to_comptime_int_type,
        slice_const_u8_type,
        slice_const_u8_sentinel_0_type,
        vector_16_i8_type,
        vector_32_i8_type,
        vector_1_u8_type,
        vector_2_u8_type,
        vector_4_u8_type,
        vector_8_u8_type,
        vector_16_u8_type,
        vector_32_u8_type,
        vector_8_i16_type,
        vector_16_i16_type,
        vector_8_u16_type,
        vector_16_u16_type,
        vector_4_i32_type,
        vector_8_i32_type,
        vector_4_u32_type,
        vector_8_u32_type,
        vector_2_i64_type,
        vector_4_i64_type,
        vector_2_u64_type,
        vector_4_u64_type,
        vector_4_f16_type,
        vector_8_f16_type,
        vector_2_f32_type,
        vector_4_f32_type,
        vector_8_f32_type,
        vector_2_f64_type,
        vector_4_f64_type,
        optional_noreturn_type,
        anyerror_void_error_union_type,
        adhoc_inferred_error_set_type,
        generic_poison_type,
        empty_tuple_type,
        undef,
        zero,
        zero_usize,
        zero_u8,
        one,
        one_usize,
        one_u8,
        four_u8,
        negative_one,
        void_value,
        unreachable_value,
        null_value,
        bool_true,
        bool_false,
        empty_tuple,

        /// This Ref does not correspond to any ZIR instruction or constant
        /// value and may instead be used as a sentinel to indicate null.
        none = std.math.maxInt(u32),

        _,

        pub fn toIndex(inst: Ref) ?Index {
            assert(inst != .none);
            const ref_int = @intFromEnum(inst);
            if (ref_int >= @intFromEnum(Index.ref_start_index)) {
                return @enumFromInt(ref_int - @intFromEnum(Index.ref_start_index));
            } else {
                return null;
            }
        }

        pub fn toIndexAllowNone(inst: Ref) ?Index {
            if (inst == .none) return null;
            return toIndex(inst);
        }
    };

    /// All instructions have an 8-byte payload, which is contained within
    /// this union. `Tag` determines which union field is active, as well as
    /// how to interpret the data within.
    pub const Data = union {
        /// Used for `Tag.extended`. The extended opcode determines the meaning
        /// of the `small` and `operand` fields.
        extended: Extended.InstData,
        /// Used for unary operators, with an AST node source location.
        un_node: struct {
            /// Offset from Decl AST node index.
            src_node: Ast.Node.Offset,
            /// The meaning of this operand depends on the corresponding `Tag`.
            operand: Ref,
        },
        /// Used for unary operators, with a token source location.
        un_tok: struct {
            /// Offset from Decl AST token index.
            src_tok: Ast.TokenOffset,
            /// The meaning of this operand depends on the corresponding `Tag`.
            operand: Ref,
        },
        pl_node: struct {
            /// Offset from Decl AST node index.
            /// `Tag` determines which kind of AST node this points to.
            src_node: Ast.Node.Offset,
            /// index into extra.
            /// `Tag` determines what lives there.
            payload_index: u32,
        },
        pl_tok: struct {
            /// Offset from Decl AST token index.
            src_tok: Ast.TokenOffset,
            /// index into extra.
            /// `Tag` determines what lives there.
            payload_index: u32,
        },
        bin: Bin,
        /// For strings which may contain null bytes.
        str: struct {
            /// Offset into `string_bytes`.
            start: NullTerminatedString,
            /// Number of bytes in the string.
            len: u32,

            pub fn get(self: @This(), code: Zir) []const u8 {
                return code.string_bytes[@intFromEnum(self.start)..][0..self.len];
            }
        },
        str_tok: struct {
            /// Offset into `string_bytes`. Null-terminated.
            start: NullTerminatedString,
            /// Offset from Decl AST token index.
            src_tok: Ast.TokenOffset,

            pub fn get(self: @This(), code: Zir) [:0]const u8 {
                return code.nullTerminatedString(self.start);
            }
        },
        /// Offset from Decl AST token index.
        tok: Ast.TokenOffset,
        /// Offset from Decl AST node index.
        node: Ast.Node.Offset,
        int: u64,
        float: f64,
        ptr_type: struct {
            flags: packed struct {
                is_allowzero: bool,
                is_mutable: bool,
                is_volatile: bool,
                has_sentinel: bool,
                has_align: bool,
                has_addrspace: bool,
                has_bit_range: bool,
                _: u1 = undefined,
            },
            size: std.builtin.Type.Pointer.Size,
            /// Index into extra. See `PtrType`.
            payload_index: u32,
        },
        int_type: struct {
            /// Offset from Decl AST node index.
            /// `Tag` determines which kind of AST node this points to.
            src_node: Ast.Node.Offset,
            signedness: std.builtin.Signedness,
            bit_count: u16,
        },
        @"unreachable": struct {
            /// Offset from Decl AST node index.
            /// `Tag` determines which kind of AST node this points to.
            src_node: Ast.Node.Offset,
        },
        @"break": struct {
            operand: Ref,
            /// Index of a `Break` payload.
            payload_index: u32,
        },
        dbg_stmt: LineColumn,
        /// Used for unary operators which reference an inst,
        /// with an AST node source location.
        inst_node: struct {
            /// Offset from Decl AST node index.
            src_node: Ast.Node.Offset,
            /// The meaning of this operand depends on the corresponding `Tag`.
            inst: Index,
        },
        str_op: struct {
            /// Offset into `string_bytes`. Null-terminated.
            str: NullTerminatedString,
            operand: Ref,

            pub fn getStr(self: @This(), zir: Zir) [:0]const u8 {
                return zir.nullTerminatedString(self.str);
            }
        },
        @"defer": struct {
            index: u32,
            len: u32,
        },
        defer_err_code: struct {
            err_code: Ref,
            payload_index: u32,
        },
        save_err_ret_index: struct {
            operand: Ref, // If error type (or .none), save new trace index
        },
        elem_val_imm: struct {
            /// The indexable value being accessed.
            operand: Ref,
            /// The index being accessed.
            idx: u32,
        },
        declaration: struct {
            /// This node provides a new absolute baseline node for all instructions within this struct.
            src_node: Ast.Node.Index,
            /// index into extra to a `Declaration` payload.
            payload_index: u32,
        },

        // Make sure we don't accidentally add a field to make this union
        // bigger than expected. Note that in Debug builds, Zig is allowed
        // to insert a secret field for safety checks.
        comptime {
            if (builtin.mode != .Debug and builtin.mode != .ReleaseSafe) {
                assert(@sizeOf(Data) == 8);
            }
        }

        /// TODO this has to be kept in sync with `Data` which we want to be an untagged
        /// union. There is some kind of language awkwardness here and it has to do with
        /// deserializing an untagged union (in this case `Data`) from a file, and trying
        /// to preserve the hidden safety field.
        pub const FieldEnum = enum {
            extended,
            un_node,
            un_tok,
            pl_node,
            pl_tok,
            bin,
            str,
            str_tok,
            tok,
            node,
            int,
            float,
            ptr_type,
            int_type,
            @"unreachable",
            @"break",
            dbg_stmt,
            inst_node,
            str_op,
            @"defer",
            defer_err_code,
            save_err_ret_index,
            elem_val_imm,
            declaration,
        };
    };

    pub const Break = struct {
        operand_src_node: Ast.Node.OptionalOffset,
        block_inst: Index,
    };

    /// Trailing:
    /// 0. Output for every outputs_len
    /// 1. Input for every inputs_len
    /// 2. clobber: NullTerminatedString // index into string_bytes (null terminated) for every clobbers_len.
    pub const Asm = struct {
        src_node: Ast.Node.Offset,
        // null-terminated string index
        asm_source: NullTerminatedString,
        /// 1 bit for each outputs_len: whether it uses `-> T` or not.
        ///   0b0 - operand is a pointer to where to store the output.
        ///   0b1 - operand is a type; asm expression has the output as the result.
        /// 0b0X is the first output, 0bX0 is the second, etc.
        output_type_bits: u32,

        pub const Output = struct {
            /// index into string_bytes (null terminated)
            name: NullTerminatedString,
            /// index into string_bytes (null terminated)
            constraint: NullTerminatedString,
            /// How to interpret this is determined by `output_type_bits`.
            operand: Ref,
        };

        pub const Input = struct {
            /// index into string_bytes (null terminated)
            name: NullTerminatedString,
            /// index into string_bytes (null terminated)
            constraint: NullTerminatedString,
            operand: Ref,
        };
    };

    /// Trailing:
    /// if (ret_ty.body_len == 1) {
    ///   0. return_type: Ref
    /// }
    /// if (ret_ty.body_len > 1) {
    ///   1. return_type: Index // for each ret_ty.body_len
    /// }
    /// 2. body: Index // for each body_len
    /// 3. src_locs: SrcLocs // if body_len != 0
    /// 4. proto_hash: std.zig.SrcHash // if body_len != 0; hash of function prototype
    pub const Func = struct {
        ret_ty: RetTy,
        /// Points to the block that contains the param instructions for this function.
        /// If this is a `declaration`, it refers to the declaration's value body.
        param_block: Index,
        body_len: u32,

        pub const RetTy = packed struct(u32) {
            /// 0 means `void`.
            /// 1 means the type is a simple `Ref`.
            /// Otherwise, the length of a trailing body.
            body_len: u31,
            /// Whether the return type is generic, i.e. refers to one or more previous parameters.
            is_generic: bool,
        };

        pub const SrcLocs = struct {
            /// Line index in the source file relative to the parent decl.
            lbrace_line: u32,
            /// Line index in the source file relative to the parent decl.
            rbrace_line: u32,
            /// lbrace_column is least significant bits u16
            /// rbrace_column is most significant bits u16
            columns: u32,
        };
    };

    /// Trailing:
    /// if (has_cc_ref and !has_cc_body) {
    ///   0. cc: Ref,
    /// }
    /// if (has_cc_body) {
    ///   1. cc_body_len: u32
    ///   2. cc_body: u32 // for each cc_body_len
    /// }
    /// if (has_ret_ty_ref and !has_ret_ty_body) {
    ///   3. ret_ty: Ref,
    /// }
    /// if (has_ret_ty_body) {
    ///   4. ret_ty_body_len: u32
    ///   5. ret_ty_body: u32 // for each ret_ty_body_len
    /// }
    /// 6. noalias_bits: u32 // if has_any_noalias
    ///    - each bit starting with LSB corresponds to parameter indexes
    /// 7. body: Index // for each body_len
    /// 8. src_locs: Func.SrcLocs // if body_len != 0
    /// 9. proto_hash: std.zig.SrcHash // if body_len != 0; hash of function prototype
    pub const FuncFancy = struct {
        /// Points to the block that contains the param instructions for this function.
        /// If this is a `declaration`, it refers to the declaration's value body.
        param_block: Index,
        body_len: u32,
        bits: Bits,

        /// If both has_cc_ref and has_cc_body are false, it means auto calling convention.
        /// If both has_ret_ty_ref and has_ret_ty_body are false, it means void return type.
        pub const Bits = packed struct(u32) {
            is_var_args: bool,
            is_inferred_error: bool,
            is_noinline: bool,
            has_cc_ref: bool,
            has_cc_body: bool,
            has_ret_ty_ref: bool,
            has_ret_ty_body: bool,
            has_any_noalias: bool,
            ret_ty_is_generic: bool,
            _: u23 = undefined,
        };
    };

    /// This data is stored inside extra, with trailing operands according to `operands_len`.
    /// Each operand is a `Ref`.
    pub const MultiOp = struct {
        operands_len: u32,
    };

    /// Trailing: operand: Ref, // for each `operands_len` (stored in `small`).
    pub const NodeMultiOp = struct {
        src_node: Ast.Node.Offset,
    };

    /// This data is stored inside extra, with trailing operands according to `body_len`.
    /// Each operand is an `Index`.
    pub const Block = struct {
        body_len: u32,
    };

    /// Trailing:
    /// * inst: Index // for each `body_len`
    pub const BlockComptime = struct {
        reason: std.zig.SimpleComptimeReason,
        body_len: u32,
    };

    /// Trailing:
    /// * inst: Index // for each `body_len`
    pub const BoolBr = struct {
        lhs: Ref,
        body_len: u32,
    };

    /// Trailing:
    /// 0. name: NullTerminatedString      // if `flags.id.hasName()`
    /// 1. lib_name: NullTerminatedString  // if `flags.id.hasLibName()`
    /// 2. type_body_len: u32              // if `flags.id.hasTypeBody()`
    /// 3. align_body_len: u32             // if `flags.id.hasSpecialBodies()`
    /// 4. linksection_body_len: u32       // if `flags.id.hasSpecialBodies()`
    /// 5. addrspace_body_len: u32         // if `flags.id.hasSpecialBodies()`
    /// 6. value_body_len: u32             // if `flags.id.hasValueBody()`
    /// 7. type_body_inst: Zir.Inst.Index
    ///    - for each `type_body_len`
    ///    - body to be exited via `break_inline` to this `declaration` instruction
    /// 8. align_body_inst: Zir.Inst.Index
    ///    - for each `align_body_len`
    ///    - body to be exited via `break_inline` to this `declaration` instruction
    /// 9. linksection_body_inst: Zir.Inst.Index
    ///    - for each `linksection_body_len`
    ///    - body to be exited via `break_inline` to this `declaration` instruction
    /// 10. addrspace_body_inst: Zir.Inst.Index
    ///    - for each `addrspace_body_len`
    ///    - body to be exited via `break_inline` to this `declaration` instruction
    /// 11. value_body_inst: Zir.Inst.Index
    ///    - for each `value_body_len`
    ///    - body to be exited via `break_inline` to this `declaration` instruction
    ///    - within this body, the `declaration` instruction refers to the resolved type from the type body
    pub const Declaration = struct {
        // These fields should be concatenated and reinterpreted as a `std.zig.SrcHash`.
        src_hash_0: u32,
        src_hash_1: u32,
        src_hash_2: u32,
        src_hash_3: u32,
        // These fields should be concatenated and reinterpreted as a `Flags`.
        flags_0: u32,
        flags_1: u32,

        pub const Unwrapped = struct {
            pub const Kind = enum {
                unnamed_test,
                @"test",
                decltest,
                @"comptime",
                @"usingnamespace",
                @"const",
                @"var",
            };

            pub const Linkage = enum {
                normal,
                @"extern",
                @"export",
            };

            src_node: Ast.Node.Index,

            src_line: u32,
            src_column: u32,

            kind: Kind,
            /// Always `.empty` for `kind` of `unnamed_test`, `.@"comptime"`, `.@"usingnamespace"`.
            name: NullTerminatedString,
            /// Always `false` for `kind` of `unnamed_test`, `.@"test"`, `.decltest`, `.@"comptime"`.
            is_pub: bool,
            /// Always `false` for `kind != .@"var"`.
            is_threadlocal: bool,
            /// Always `.normal` for `kind != .@"const" and kind != .@"var"`.
            linkage: Linkage,
            /// Always `.empty` for `linkage != .@"extern"`.
            lib_name: NullTerminatedString,

            /// Always populated for `linkage == .@"extern".
            type_body: ?[]const Inst.Index,
            align_body: ?[]const Inst.Index,
            linksection_body: ?[]const Inst.Index,
            addrspace_body: ?[]const Inst.Index,
            /// Always populated for `linkage != .@"extern".
            value_body: ?[]const Inst.Index,
        };

        pub const Flags = packed struct(u64) {
            src_line: u30,
            src_column: u29,
            id: Id,

            pub const Id = enum(u5) {
                unnamed_test,
                @"test",
                decltest,
                @"comptime",

                @"usingnamespace",
                pub_usingnamespace,

                const_simple,
                const_typed,
                @"const",
                pub_const_simple,
                pub_const_typed,
                pub_const,

                extern_const_simple,
                extern_const,
                pub_extern_const_simple,
                pub_extern_const,

                export_const,
                pub_export_const,

                var_simple,
                @"var",
                var_threadlocal,
                pub_var_simple,
                pub_var,
                pub_var_threadlocal,

                extern_var,
                extern_var_threadlocal,
                pub_extern_var,
                pub_extern_var_threadlocal,

                export_var,
                export_var_threadlocal,
                pub_export_var,
                pub_export_var_threadlocal,

                pub fn hasName(id: Id) bool {
                    return switch (id) {
                        .unnamed_test,
                        .@"comptime",
                        .@"usingnamespace",
                        .pub_usingnamespace,
                        => false,
                        else => true,
                    };
                }

                pub fn hasLibName(id: Id) bool {
                    return switch (id) {
                        .extern_const,
                        .pub_extern_const,
                        .extern_var,
                        .extern_var_threadlocal,
                        .pub_extern_var,
                        .pub_extern_var_threadlocal,
                        => true,
                        else => false,
                    };
                }

                pub fn hasTypeBody(id: Id) bool {
                    return switch (id) {
                        .unnamed_test,
                        .@"test",
                        .decltest,
                        .@"comptime",
                        .@"usingnamespace",
                        .pub_usingnamespace,
                        => false, // these constructs are untyped
                        .const_simple,
                        .pub_const_simple,
                        .var_simple,
                        .pub_var_simple,
                        => false, // these reprs omit type bodies
                        else => true,
                    };
                }

                pub fn hasValueBody(id: Id) bool {
                    return switch (id) {
                        .extern_const_simple,
                        .extern_const,
                        .pub_extern_const_simple,
                        .pub_extern_const,
                        .extern_var,
                        .extern_var_threadlocal,
                        .pub_extern_var,
                        .pub_extern_var_threadlocal,
                        => false, // externs do not have values
                        else => true,
                    };
                }

                pub fn hasSpecialBodies(id: Id) bool {
                    return switch (id) {
                        .unnamed_test,
                        .@"test",
                        .decltest,
                        .@"comptime",
                        .@"usingnamespace",
                        .pub_usingnamespace,
                        => false, // these constructs are untyped
                        .const_simple,
                        .const_typed,
                        .pub_const_simple,
                        .pub_const_typed,
                        .extern_const_simple,
                        .pub_extern_const_simple,
                        .var_simple,
                        .pub_var_simple,
                        => false, // these reprs omit special bodies
                        else => true,
                    };
                }

                pub fn linkage(id: Id) Declaration.Unwrapped.Linkage {
                    return switch (id) {
                        .extern_const_simple,
                        .extern_const,
                        .pub_extern_const_simple,
                        .pub_extern_const,
                        .extern_var,
                        .extern_var_threadlocal,
                        .pub_extern_var,
                        .pub_extern_var_threadlocal,
                        => .@"extern",
                        .export_const,
                        .pub_export_const,
                        .export_var,
                        .export_var_threadlocal,
                        .pub_export_var,
                        .pub_export_var_threadlocal,
                        => .@"export",
                        else => .normal,
                    };
                }

                pub fn kind(id: Id) Declaration.Unwrapped.Kind {
                    return switch (id) {
                        .unnamed_test => .unnamed_test,
                        .@"test" => .@"test",
                        .decltest => .decltest,
                        .@"comptime" => .@"comptime",
                        .@"usingnamespace", .pub_usingnamespace => .@"usingnamespace",
                        .const_simple,
                        .const_typed,
                        .@"const",
                        .pub_const_simple,
                        .pub_const_typed,
                        .pub_const,
                        .extern_const_simple,
                        .extern_const,
                        .pub_extern_const_simple,
                        .pub_extern_const,
                        .export_const,
                        .pub_export_const,
                        => .@"const",
                        .var_simple,
                        .@"var",
                        .var_threadlocal,
                        .pub_var_simple,
                        .pub_var,
                        .pub_var_threadlocal,
                        .extern_var,
                        .extern_var_threadlocal,
                        .pub_extern_var,
                        .pub_extern_var_threadlocal,
                        .export_var,
                        .export_var_threadlocal,
                        .pub_export_var,
                        .pub_export_var_threadlocal,
                        => .@"var",
                    };
                }

                pub fn isPub(id: Id) bool {
                    return switch (id) {
                        .pub_usingnamespace,
                        .pub_const_simple,
                        .pub_const_typed,
                        .pub_const,
                        .pub_extern_const_simple,
                        .pub_extern_const,
                        .pub_export_const,
                        .pub_var_simple,
                        .pub_var,
                        .pub_var_threadlocal,
                        .pub_extern_var,
                        .pub_extern_var_threadlocal,
                        .pub_export_var,
                        .pub_export_var_threadlocal,
                        => true,
                        else => false,
                    };
                }

                pub fn isThreadlocal(id: Id) bool {
                    return switch (id) {
                        .var_threadlocal,
                        .pub_var_threadlocal,
                        .extern_var_threadlocal,
                        .pub_extern_var_threadlocal,
                        .export_var_threadlocal,
                        .pub_export_var_threadlocal,
                        => true,
                        else => false,
                    };
                }
            };
        };

        pub const Name = enum(u32) {
            @"comptime" = std.math.maxInt(u32),
            @"usingnamespace" = std.math.maxInt(u32) - 1,
            unnamed_test = std.math.maxInt(u32) - 2,
            /// Other values are `NullTerminatedString` values, i.e. index into
            /// `string_bytes`. If the byte referenced is 0, the decl is a named
            /// test, and the actual name begins at the following byte.
            _,

            pub fn isNamedTest(name: Name, zir: Zir) bool {
                return switch (name) {
                    .@"comptime", .@"usingnamespace", .unnamed_test => false,
                    _ => zir.string_bytes[@intFromEnum(name)] == 0,
                };
            }
            pub fn toString(name: Name, zir: Zir) ?NullTerminatedString {
                switch (name) {
                    .@"comptime", .@"usingnamespace", .unnamed_test => return null,
                    _ => {},
                }
                const idx: u32 = @intFromEnum(name);
                if (zir.string_bytes[idx] == 0) {
                    // Named test
                    return @enumFromInt(idx + 1);
                }
                return @enumFromInt(idx);
            }
        };

        pub const Bodies = struct {
            type_body: ?[]const Index,
            align_body: ?[]const Index,
            linksection_body: ?[]const Index,
            addrspace_body: ?[]const Index,
            value_body: ?[]const Index,
        };

        pub fn getBodies(declaration: Declaration, extra_end: u32, zir: Zir) Bodies {
            var extra_index: u32 = extra_end;
            const value_body_len = declaration.value_body_len;
            const type_body_len: u32 = len: {
                if (!declaration.flags().kind.hasTypeBody()) break :len 0;
                const len = zir.extra[extra_index];
                extra_index += 1;
                break :len len;
            };
            const align_body_len, const linksection_body_len, const addrspace_body_len = lens: {
                if (!declaration.flags.kind.hasSpecialBodies()) {
                    break :lens .{ 0, 0, 0 };
                }
                const lens = zir.extra[extra_index..][0..3].*;
                extra_index += 3;
                break :lens lens;
            };
            return .{
                .type_body = if (type_body_len == 0) null else b: {
                    const b = zir.bodySlice(extra_index, type_body_len);
                    extra_index += type_body_len;
                    break :b b;
                },
                .align_body = if (align_body_len == 0) null else b: {
                    const b = zir.bodySlice(extra_index, align_body_len);
                    extra_index += align_body_len;
                    break :b b;
                },
                .linksection_body = if (linksection_body_len == 0) null else b: {
                    const b = zir.bodySlice(extra_index, linksection_body_len);
                    extra_index += linksection_body_len;
                    break :b b;
                },
                .addrspace_body = if (addrspace_body_len == 0) null else b: {
                    const b = zir.bodySlice(extra_index, addrspace_body_len);
                    extra_index += addrspace_body_len;
                    break :b b;
                },
                .value_body = if (value_body_len == 0) null else b: {
                    const b = zir.bodySlice(extra_index, value_body_len);
                    extra_index += value_body_len;
                    break :b b;
                },
            };
        }
    };

    /// Stored inside extra, with trailing arguments according to `args_len`.
    /// Implicit 0. arg_0_start: u32, // always same as `args_len`
    /// 1. arg_end: u32, // for each `args_len`
    /// arg_N_start is the same as arg_N-1_end
    pub const Call = struct {
        // Note: Flags *must* come first so that unusedResultExpr
        // can find it when it goes to modify them.
        flags: Flags,
        callee: Ref,

        pub const Flags = packed struct {
            /// std.builtin.CallModifier in packed form
            pub const PackedModifier = u3;
            pub const PackedArgsLen = u27;

            packed_modifier: PackedModifier,
            ensure_result_used: bool = false,
            pop_error_return_trace: bool,
            args_len: PackedArgsLen,

            comptime {
                if (@sizeOf(Flags) != 4 or @bitSizeOf(Flags) != 32)
                    @compileError("Layout of Call.Flags needs to be updated!");
                if (@bitSizeOf(std.builtin.CallModifier) != @bitSizeOf(PackedModifier))
                    @compileError("Call.Flags.PackedModifier needs to be updated!");
            }
        };
    };

    /// Stored inside extra, with trailing arguments according to `args_len`.
    /// Implicit 0. arg_0_start: u32, // always same as `args_len`
    /// 1. arg_end: u32, // for each `args_len`
    /// arg_N_start is the same as arg_N-1_end
    pub const FieldCall = struct {
        // Note: Flags *must* come first so that unusedResultExpr
        // can find it when it goes to modify them.
        flags: Call.Flags,
        obj_ptr: Ref,
        /// Offset into `string_bytes`.
        field_name_start: NullTerminatedString,
    };

    /// There is a body of instructions at `extra[body_index..][0..body_len]`.
    /// Trailing:
    /// 0. operand: Ref // for each `operands_len`
    pub const TypeOfPeer = struct {
        src_node: Ast.Node.Offset,
        body_len: u32,
        body_index: u32,
    };

    pub const BuiltinCall = struct {
        // Note: Flags *must* come first so that unusedResultExpr
        // can find it when it goes to modify them.
        flags: Flags,
        modifier: Ref,
        callee: Ref,
        args: Ref,

        pub const Flags = packed struct {
            is_nosuspend: bool,
            ensure_result_used: bool,
            _: u30 = undefined,

            comptime {
                if (@sizeOf(Flags) != 4 or @bitSizeOf(Flags) != 32)
                    @compileError("Layout of BuiltinCall.Flags needs to be updated!");
            }
        };
    };

    /// This data is stored inside extra, with two sets of trailing `Ref`:
    /// * 0. the then body, according to `then_body_len`.
    /// * 1. the else body, according to `else_body_len`.
    pub const CondBr = struct {
        condition: Ref,
        then_body_len: u32,
        else_body_len: u32,
    };

    /// This data is stored inside extra, trailed by:
    /// * 0. body: Index //  for each `body_len`.
    pub const Try = struct {
        /// The error union to unwrap.
        operand: Ref,
        body_len: u32,
    };

    /// Stored in extra. Depending on the flags in Data, there will be up to 5
    /// trailing Ref fields:
    /// 0. sentinel: Ref // if `has_sentinel` flag is set
    /// 1. align: Ref // if `has_align` flag is set
    /// 2. address_space: Ref // if `has_addrspace` flag is set
    /// 3. bit_start: Ref // if `has_bit_range` flag is set
    /// 4. host_size: Ref // if `has_bit_range` flag is set
    pub const PtrType = struct {
        elem_type: Ref,
        src_node: Ast.Node.Offset,
    };

    pub const ArrayTypeSentinel = struct {
        len: Ref,
        sentinel: Ref,
        elem_type: Ref,
    };

    pub const SliceStart = struct {
        lhs: Ref,
        start: Ref,
    };

    pub const SliceEnd = struct {
        lhs: Ref,
        start: Ref,
        end: Ref,
    };

    pub const SliceSentinel = struct {
        lhs: Ref,
        start: Ref,
        end: Ref,
        sentinel: Ref,
    };

    pub const SliceLength = struct {
        lhs: Ref,
        start: Ref,
        len: Ref,
        sentinel: Ref,
        start_src_node_offset: Ast.Node.Offset,
    };

    /// The meaning of these operands depends on the corresponding `Tag`.
    pub const Bin = struct {
        lhs: Ref,
        rhs: Ref,
    };

    pub const BinNode = struct {
        node: Ast.Node.Offset,
        lhs: Ref,
        rhs: Ref,
    };

    pub const UnNode = struct {
        node: Ast.Node.Offset,
        operand: Ref,
    };

    pub const ElemPtrImm = struct {
        ptr: Ref,
        index: u32,
    };

    pub const Reify = struct {
        /// This node is absolute, because `reify` instructions are tracked across updates, and
        /// this simplifies the logic for getting source locations for types.
        node: Ast.Node.Index,
        operand: Ref,
        src_line: u32,
    };

    /// Trailing:
    /// 0. multi_cases_len: u32 // if `has_multi_cases`
    /// 1. err_capture_inst: u32 // if `any_uses_err_capture`
    /// 2. non_err_body {
    ///        info: ProngInfo,
    ///        inst: Index // for every `info.body_len`
    ///     }
    /// 3. else_body { // if `has_else`
    ///        info: ProngInfo,
    ///        inst: Index // for every `info.body_len`
    ///     }
    /// 4. scalar_cases: { // for every `scalar_cases_len`
    ///        item: Ref,
    ///        info: ProngInfo,
    ///        inst: Index // for every `info.body_len`
    ///     }
    /// 5. multi_cases: { // for every `multi_cases_len`
    ///        items_len: u32,
    ///        ranges_len: u32,
    ///        info: ProngInfo,
    ///        item: Ref // for every `items_len`
    ///        ranges: { // for every `ranges_len`
    ///            item_first: Ref,
    ///            item_last: Ref,
    ///        }
    ///        inst: Index // for every `info.body_len`
    ///    }
    ///
    /// When analyzing a case body, the switch instruction itself refers to the
    /// captured error, or to the success value in `non_err_body`. Whether this
    /// is captured by reference or by value depends on whether the `byref` bit
    /// is set for the corresponding body. `err_capture_inst` refers to the error
    /// capture outside of the `switch`, i.e. `err` in
    /// `x catch |err| switch (err) { ... }`.
    pub const SwitchBlockErrUnion = struct {
        operand: Ref,
        bits: Bits,
        main_src_node_offset: Ast.Node.Offset,

        pub const Bits = packed struct(u32) {
            /// If true, one or more prongs have multiple items.
            has_multi_cases: bool,
            /// If true, there is an else prong. This is mutually exclusive with `has_under`.
            has_else: bool,
            any_uses_err_capture: bool,
            payload_is_ref: bool,
            scalar_cases_len: ScalarCasesLen,

            pub const ScalarCasesLen = u28;
        };

        pub const MultiProng = struct {
            items: []const Ref,
            body: []const Index,
        };
    };

    /// 0. multi_cases_len: u32 // If has_multi_cases is set.
    /// 1. tag_capture_inst: u32 // If any_has_tag_capture is set. Index of instruction prongs use to refer to the inline tag capture.
    /// 2. else_body { // If has_else or has_under is set.
    ///        info: ProngInfo,
    ///        body member Index for every info.body_len
    ///     }
    /// 3. scalar_cases: { // for every scalar_cases_len
    ///        item: Ref,
    ///        info: ProngInfo,
    ///        body member Index for every info.body_len
    ///     }
    /// 4. multi_cases: { // for every multi_cases_len
    ///        items_len: u32,
    ///        ranges_len: u32,
    ///        info: ProngInfo,
    ///        item: Ref // for every items_len
    ///        ranges: { // for every ranges_len
    ///            item_first: Ref,
    ///            item_last: Ref,
    ///        }
    ///        body member Index for every info.body_len
    ///    }
    ///
    /// When analyzing a case body, the switch instruction itself refers to the
    /// captured payload. Whether this is captured by reference or by value
    /// depends on whether the `byref` bit is set for the corresponding body.
    pub const SwitchBlock = struct {
        /// The operand passed to the `switch` expression. If this is a
        /// `switch_block`, this is the operand value; if `switch_block_ref` it
        /// is a pointer to the operand. `switch_block_ref` is always used if
        /// any prong has a byref capture.
        operand: Ref,
        bits: Bits,

        /// These are stored in trailing data in `extra` for each prong.
        pub const ProngInfo = packed struct(u32) {
            body_len: u28,
            capture: ProngInfo.Capture,
            is_inline: bool,
            has_tag_capture: bool,

            pub const Capture = enum(u2) {
                none,
                by_val,
                by_ref,
            };
        };

        pub const Bits = packed struct(u32) {
            /// If true, one or more prongs have multiple items.
            has_multi_cases: bool,
            /// If true, there is an else prong. This is mutually exclusive with `has_under`.
            has_else: bool,
            /// If true, there is an underscore prong. This is mutually exclusive with `has_else`.
            has_under: bool,
            /// If true, at least one prong has an inline tag capture.
            any_has_tag_capture: bool,
            /// If true, at least one prong has a capture which may not
            /// be comptime-known via `inline`.
            any_non_inline_capture: bool,
            has_continue: bool,
            scalar_cases_len: ScalarCasesLen,

            pub const ScalarCasesLen = u26;

            pub fn specialProng(bits: Bits) SpecialProng {
                const has_else: u2 = @intFromBool(bits.has_else);
                const has_under: u2 = @intFromBool(bits.has_under);
                return switch ((has_else << 1) | has_under) {
                    0b00 => .none,
                    0b01 => .under,
                    0b10 => .@"else",
                    0b11 => unreachable,
                };
            }
        };

        pub const MultiProng = struct {
            items: []const Ref,
            body: []const Index,
        };
    };

    pub const ArrayInitRefTy = struct {
        ptr_ty: Ref,
        elem_count: u32,
    };

    pub const Field = struct {
        lhs: Ref,
        /// Offset into `string_bytes`.
        field_name_start: NullTerminatedString,
    };

    pub const FieldNamed = struct {
        lhs: Ref,
        field_name: Ref,
    };

    pub const As = struct {
        dest_type: Ref,
        operand: Ref,
    };

    /// Trailing:
    /// 0. captures_len: u32 // if has_captures_len
    /// 1. fields_len: u32, // if has_fields_len
    /// 2. decls_len: u32, // if has_decls_len
    /// 3. capture: Capture // for every captures_len
    /// 4. capture_name: NullTerminatedString // for every captures_len
    /// 5. backing_int_body_len: u32, // if has_backing_int
    /// 6. backing_int_ref: Ref, // if has_backing_int and backing_int_body_len is 0
    /// 7. backing_int_body_inst: Inst, // if has_backing_int and backing_int_body_len is > 0
    /// 8. decl: Index, // for every decls_len; points to a `declaration` instruction
    /// 9. flags: u32 // for every 8 fields
    ///    - sets of 4 bits:
    ///      0b000X: whether corresponding field has an align expression
    ///      0b00X0: whether corresponding field has a default expression
    ///      0b0X00: whether corresponding field is comptime
    ///      0bX000: whether corresponding field has a type expression
    /// 10. fields: { // for every fields_len
    ///        field_name: u32,
    ///        field_type: Ref, // if corresponding bit is not set. none means anytype.
    ///        field_type_body_len: u32, // if corresponding bit is set
    ///        align_body_len: u32, // if corresponding bit is set
    ///        init_body_len: u32, // if corresponding bit is set
    ///    }
    /// 11. bodies: { // for every fields_len
    ///        field_type_body_inst: Inst, // for each field_type_body_len
    ///        align_body_inst: Inst, // for each align_body_len
    ///        init_body_inst: Inst, // for each init_body_len
    ///    }
    pub const StructDecl = struct {
        // These fields should be concatenated and reinterpreted as a `std.zig.SrcHash`.
        // This hash contains the source of all fields, and any specified attributes (`extern`, backing type, etc).
        fields_hash_0: u32,
        fields_hash_1: u32,
        fields_hash_2: u32,
        fields_hash_3: u32,
        src_line: u32,
        /// This node provides a new absolute baseline node for all instructions within this struct.
        src_node: Ast.Node.Index,

        pub const Small = packed struct {
            has_captures_len: bool,
            has_fields_len: bool,
            has_decls_len: bool,
            has_backing_int: bool,
            known_non_opv: bool,
            known_comptime_only: bool,
            name_strategy: NameStrategy,
            layout: std.builtin.Type.ContainerLayout,
            any_default_inits: bool,
            any_comptime_fields: bool,
            any_aligned_fields: bool,
            _: u3 = undefined,
        };
    };

    /// Represents a single value being captured in a type declaration's closure.
    pub const Capture = packed struct(u32) {
        tag: enum(u3) {
            /// `data` is a `u16` index into the parent closure.
            nested,
            /// `data` is a `Zir.Inst.Index` to an instruction whose value is being captured.
            instruction,
            /// `data` is a `Zir.Inst.Index` to an instruction representing an alloc whose contents is being captured.
            instruction_load,
            /// `data` is a `NullTerminatedString` to a decl name.
            decl_val,
            /// `data` is a `NullTerminatedString` to a decl name.
            decl_ref,
        },
        data: u29,
        pub const Unwrapped = union(enum) {
            nested: u16,
            instruction: Zir.Inst.Index,
            instruction_load: Zir.Inst.Index,
            decl_val: NullTerminatedString,
            decl_ref: NullTerminatedString,
        };
        pub fn wrap(cap: Unwrapped) Capture {
            return switch (cap) {
                .nested => |idx| .{
                    .tag = .nested,
                    .data = idx,
                },
                .instruction => |inst| .{
                    .tag = .instruction,
                    .data = @intCast(@intFromEnum(inst)),
                },
                .instruction_load => |inst| .{
                    .tag = .instruction_load,
                    .data = @intCast(@intFromEnum(inst)),
                },
                .decl_val => |str| .{
                    .tag = .decl_val,
                    .data = @intCast(@intFromEnum(str)),
                },
                .decl_ref => |str| .{
                    .tag = .decl_ref,
                    .data = @intCast(@intFromEnum(str)),
                },
            };
        }
        pub fn unwrap(cap: Capture) Unwrapped {
            return switch (cap.tag) {
                .nested => .{ .nested = @intCast(cap.data) },
                .instruction => .{ .instruction = @enumFromInt(cap.data) },
                .instruction_load => .{ .instruction_load = @enumFromInt(cap.data) },
                .decl_val => .{ .decl_val = @enumFromInt(cap.data) },
                .decl_ref => .{ .decl_ref = @enumFromInt(cap.data) },
            };
        }
    };

    pub const NameStrategy = enum(u2) {
        /// Use the same name as the parent declaration name.
        /// e.g. `const Foo = struct {...};`.
        parent,
        /// Use the name of the currently executing comptime function call,
        /// with the current parameters. e.g. `ArrayList(i32)`.
        func,
        /// Create an anonymous name for this declaration.
        /// Like this: "ParentDeclName_struct_69"
        anon,
        /// Use the name specified in the next `dbg_var_{val,ptr}` instruction.
        dbg_var,
    };

    pub const FullPtrCastFlags = packed struct(u5) {
        ptr_cast: bool = false,
        align_cast: bool = false,
        addrspace_cast: bool = false,
        const_cast: bool = false,
        volatile_cast: bool = false,

        pub inline fn needResultTypeBuiltinName(flags: FullPtrCastFlags) []const u8 {
            if (flags.ptr_cast) return "@ptrCast";
            if (flags.align_cast) return "@alignCast";
            if (flags.addrspace_cast) return "@addrSpaceCast";
            unreachable;
        }
    };

    pub const BuiltinValue = enum(u16) {
        // Types
        atomic_order,
        atomic_rmw_op,
        calling_convention,
        address_space,
        float_mode,
        reduce_op,
        call_modifier,
        prefetch_options,
        export_options,
        extern_options,
        type_info,
        branch_hint,
        // Values
        calling_convention_c,
        calling_convention_inline,
    };

    pub const InplaceOp = enum(u16) {
        add_eq,
        sub_eq,
    };

    /// Trailing:
    /// 0. tag_type: Ref, // if has_tag_type
    /// 1. captures_len: u32, // if has_captures_len
    /// 2. body_len: u32, // if has_body_len
    /// 3. fields_len: u32, // if has_fields_len
    /// 4. decls_len: u32, // if has_decls_len
    /// 5. capture: Capture // for every captures_len
    /// 6. capture_name: NullTerminatedString // for every captures_len
    /// 7. decl: Index, // for every decls_len; points to a `declaration` instruction
    /// 8. inst: Index // for every body_len
    /// 9. has_bits: u32 // for every 32 fields
    ///    - the bit is whether corresponding field has an value expression
    /// 10. fields: { // for every fields_len
    ///        field_name: u32,
    ///        value: Ref, // if corresponding bit is set
    ///    }
    pub const EnumDecl = struct {
        // These fields should be concatenated and reinterpreted as a `std.zig.SrcHash`.
        // This hash contains the source of all fields, and the backing type if specified.
        fields_hash_0: u32,
        fields_hash_1: u32,
        fields_hash_2: u32,
        fields_hash_3: u32,
        src_line: u32,
        /// This node provides a new absolute baseline node for all instructions within this struct.
        src_node: Ast.Node.Index,

        pub const Small = packed struct {
            has_tag_type: bool,
            has_captures_len: bool,
            has_body_len: bool,
            has_fields_len: bool,
            has_decls_len: bool,
            name_strategy: NameStrategy,
            nonexhaustive: bool,
            _: u8 = undefined,
        };
    };

    /// Trailing:
    /// 0. tag_type: Ref, // if has_tag_type
    /// 1. captures_len: u32 // if has_captures_len
    /// 2. body_len: u32, // if has_body_len
    /// 3. fields_len: u32, // if has_fields_len
    /// 4. decls_len: u32, // if has_decls_len
    /// 5. capture: Capture // for every captures_len
    /// 6. capture_name: NullTerminatedString // for every captures_len
    /// 7. decl: Index, // for every decls_len; points to a `declaration` instruction
    /// 8. inst: Index // for every body_len
    /// 9. has_bits: u32 // for every 8 fields
    ///    - sets of 4 bits:
    ///      0b000X: whether corresponding field has a type expression
    ///      0b00X0: whether corresponding field has a align expression
    ///      0b0X00: whether corresponding field has a tag value expression
    ///      0bX000: unused
    /// 10. fields: { // for every fields_len
    ///        field_name: NullTerminatedString, // null terminated string index
    ///        field_type: Ref, // if corresponding bit is set
    ///        align: Ref, // if corresponding bit is set
    ///        tag_value: Ref, // if corresponding bit is set
    ///    }
    pub const UnionDecl = struct {
        // These fields should be concatenated and reinterpreted as a `std.zig.SrcHash`.
        // This hash contains the source of all fields, and any specified attributes (`extern` etc).
        fields_hash_0: u32,
        fields_hash_1: u32,
        fields_hash_2: u32,
        fields_hash_3: u32,
        src_line: u32,
        /// This node provides a new absolute baseline node for all instructions within this struct.
        src_node: Ast.Node.Index,

        pub const Small = packed struct {
            has_tag_type: bool,
            has_captures_len: bool,
            has_body_len: bool,
            has_fields_len: bool,
            has_decls_len: bool,
            name_strategy: NameStrategy,
            layout: std.builtin.Type.ContainerLayout,
            /// has_tag_type | auto_enum_tag | result
            /// -------------------------------------
            ///    false     | false         |  union { }
            ///    false     | true          |  union(enum) { }
            ///    true      | true          |  union(enum(T)) { }
            ///    true      | false         |  union(T) { }
            auto_enum_tag: bool,
            any_aligned_fields: bool,
            _: u5 = undefined,
        };
    };

    /// Trailing:
    /// 0. captures_len: u32, // if has_captures_len
    /// 1. decls_len: u32, // if has_decls_len
    /// 2. capture: Capture, // for every captures_len
    /// 3. capture_name: NullTerminatedString // for every captures_len
    /// 4. decl: Index, // for every decls_len; points to a `declaration` instruction
    pub const OpaqueDecl = struct {
        src_line: u32,
        /// This node provides a new absolute baseline node for all instructions within this struct.
        src_node: Ast.Node.Index,

        pub const Small = packed struct {
            has_captures_len: bool,
            has_decls_len: bool,
            name_strategy: NameStrategy,
            _: u12 = undefined,
        };
    };

    /// Trailing:
    /// 1. fields: { // for every `fields_len` (stored in `extended.small`)
    ///        type: Inst.Ref,
    ///        init: Inst.Ref, // `.none` for non-`comptime` fields
    ///    }
    pub const TupleDecl = struct {
        src_node: Ast.Node.Offset,
    };

    /// Trailing:
    /// 0. field_name: NullTerminatedString // for every fields_len
    pub const ErrorSetDecl = struct {
        fields_len: u32,
    };

    /// A f128 valu```
