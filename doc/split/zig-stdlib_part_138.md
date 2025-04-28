```
ount()) |metadata_string_index| {
                    const metadata_string: MetadataString = @enumFromInt(metadata_string_index);
                    const slice = metadata_string.slice(self);
                    try bitcode.writeVBR(@as(u32, @intCast(slice.len)), 6);
                }

                try bitcode.writeBlob(self.metadata_string_bytes.items);
            }

            for (
                self.metadata_items.items(.tag)[1..],
                self.metadata_items.items(.data)[1..],
            ) |tag, data| {
                record.clearRetainingCapacity();
                switch (tag) {
                    .none => unreachable,
                    .file => {
                        const extra = self.metadataExtraData(Metadata.File, data);

                        try metadata_block.writeAbbrevAdapted(MetadataBlock.File{
                            .filename = extra.filename,
                            .directory = extra.directory,
                        }, metadata_adapter);
                    },
                    .compile_unit,
                    .@"compile_unit optimized",
                    => |kind| {
                        const extra = self.metadataExtraData(Metadata.CompileUnit, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.CompileUnit{
                            .file = extra.file,
                            .producer = extra.producer,
                            .is_optimized = switch (kind) {
                                .compile_unit => false,
                                .@"compile_unit optimized" => true,
                                else => unreachable,
                            },
                            .enums = extra.enums,
                            .globals = extra.globals,
                        }, metadata_adapter);
                    },
                    .subprogram,
                    .@"subprogram local",
                    .@"subprogram definition",
                    .@"subprogram local definition",
                    .@"subprogram optimized",
                    .@"subprogram optimized local",
                    .@"subprogram optimized definition",
                    .@"subprogram optimized local definition",
                    => |kind| {
                        const extra = self.metadataExtraData(Metadata.Subprogram, data);

                        try metadata_block.writeAbbrevAdapted(MetadataBlock.Subprogram{
                            .scope = extra.file,
                            .name = extra.name,
                            .linkage_name = extra.linkage_name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                            .scope_line = extra.scope_line,
                            .sp_flags = @bitCast(@as(u32, @as(u3, @intCast(
                                @intFromEnum(kind) - @intFromEnum(Metadata.Tag.subprogram),
                            ))) << 2),
                            .flags = extra.di_flags,
                            .compile_unit = extra.compile_unit,
                        }, metadata_adapter);
                    },
                    .lexical_block => {
                        const extra = self.metadataExtraData(Metadata.LexicalBlock, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.LexicalBlock{
                            .scope = extra.scope,
                            .file = extra.file,
                            .line = extra.line,
                            .column = extra.column,
                        }, metadata_adapter);
                    },
                    .location => {
                        const extra = self.metadataExtraData(Metadata.Location, data);
                        assert(extra.scope != .none);
                        try metadata_block.writeAbbrev(MetadataBlock.Location{
                            .line = extra.line,
                            .column = extra.column,
                            .scope = metadata_adapter.getMetadataIndex(extra.scope) - 1,
                            .inlined_at = @enumFromInt(metadata_adapter.getMetadataIndex(extra.inlined_at)),
                        });
                    },
                    .basic_bool_type,
                    .basic_unsigned_type,
                    .basic_signed_type,
                    .basic_float_type,
                    => |kind| {
                        const extra = self.metadataExtraData(Metadata.BasicType, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.BasicType{
                            .name = extra.name,
                            .size_in_bits = extra.bitSize(),
                            .encoding = switch (kind) {
                                .basic_bool_type => DW.ATE.boolean,
                                .basic_unsigned_type => DW.ATE.unsigned,
                                .basic_signed_type => DW.ATE.signed,
                                .basic_float_type => DW.ATE.float,
                                else => unreachable,
                            },
                        }, metadata_adapter);
                    },
                    .composite_struct_type,
                    .composite_union_type,
                    .composite_enumeration_type,
                    .composite_array_type,
                    .composite_vector_type,
                    => |kind| {
                        const extra = self.metadataExtraData(Metadata.CompositeType, data);

                        try metadata_block.writeAbbrevAdapted(MetadataBlock.CompositeType{
                            .tag = switch (kind) {
                                .composite_struct_type => DW.TAG.structure_type,
                                .composite_union_type => DW.TAG.union_type,
                                .composite_enumeration_type => DW.TAG.enumeration_type,
                                .composite_array_type, .composite_vector_type => DW.TAG.array_type,
                                else => unreachable,
                            },
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .scope = extra.scope,
                            .underlying_type = extra.underlying_type,
                            .size_in_bits = extra.bitSize(),
                            .align_in_bits = extra.bitAlign(),
                            .flags = if (kind == .composite_vector_type) .{ .Vector = true } else .{},
                            .elements = extra.fields_tuple,
                        }, metadata_adapter);
                    },
                    .derived_pointer_type,
                    .derived_member_type,
                    => |kind| {
                        const extra = self.metadataExtraData(Metadata.DerivedType, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.DerivedType{
                            .tag = switch (kind) {
                                .derived_pointer_type => DW.TAG.pointer_type,
                                .derived_member_type => DW.TAG.member,
                                else => unreachable,
                            },
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .scope = extra.scope,
                            .underlying_type = extra.underlying_type,
                            .size_in_bits = extra.bitSize(),
                            .align_in_bits = extra.bitAlign(),
                            .offset_in_bits = extra.bitOffset(),
                        }, metadata_adapter);
                    },
                    .subroutine_type => {
                        const extra = self.metadataExtraData(Metadata.SubroutineType, data);

                        try metadata_block.writeAbbrevAdapted(MetadataBlock.SubroutineType{
                            .types = extra.types_tuple,
                        }, metadata_adapter);
                    },
                    .enumerator_unsigned,
                    .enumerator_signed_positive,
                    .enumerator_signed_negative,
                    => |kind| {
                        const extra = self.metadataExtraData(Metadata.Enumerator, data);
                        const bigint: std.math.big.int.Const = .{
                            .limbs = self.metadata_limbs.items[extra.limbs_index..][0..extra.limbs_len],
                            .positive = switch (kind) {
                                .enumerator_unsigned,
                                .enumerator_signed_positive,
                                => true,
                                .enumerator_signed_negative => false,
                                else => unreachable,
                            },
                        };
                        const flags: MetadataBlock.Enumerator.Flags = .{
                            .unsigned = switch (kind) {
                                .enumerator_unsigned => true,
                                .enumerator_signed_positive,
                                .enumerator_signed_negative,
                                => false,
                                else => unreachable,
                            },
                        };
                        const val: i64 = if (bigint.toInt(i64)) |val|
                            val
                        else |_| if (bigint.toInt(u64)) |val|
                            @bitCast(val)
                        else |_| {
                            const limbs_len = std.math.divCeil(u32, extra.bit_width, 64) catch unreachable;
                            try record.ensureTotalCapacity(self.gpa, 3 + limbs_len);
                            record.appendAssumeCapacity(@as(
                                @typeInfo(MetadataBlock.Enumerator.Flags).@"struct".backing_integer.?,
                                @bitCast(flags),
                            ));
                            record.appendAssumeCapacity(extra.bit_width);
                            record.appendAssumeCapacity(metadata_adapter.getMetadataStringIndex(extra.name));
                            const limbs = record.addManyAsSliceAssumeCapacity(limbs_len);
                            bigint.writeTwosComplement(std.mem.sliceAsBytes(limbs), .little);
                            for (limbs) |*limb| {
                                const val = std.mem.littleToNative(i64, @bitCast(limb.*));
                                limb.* = @bitCast(if (val >= 0)
                                    val << 1 | 0
                                else
                                    -%val << 1 | 1);
                            }
                            try metadata_block.writeUnabbrev(@intFromEnum(MetadataBlock.Enumerator.id), record.items);
                            continue;
                        };
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.Enumerator{
                            .flags = flags,
                            .bit_width = extra.bit_width,
                            .name = extra.name,
                            .value = @bitCast(if (val >= 0)
                                val << 1 | 0
                            else
                                -%val << 1 | 1),
                        }, metadata_adapter);
                    },
                    .subrange => {
                        const extra = self.metadataExtraData(Metadata.Subrange, data);

                        try metadata_block.writeAbbrevAdapted(MetadataBlock.Subrange{
                            .count = extra.count,
                            .lower_bound = extra.lower_bound,
                        }, metadata_adapter);
                    },
                    .expression => {
                        var extra = self.metadataExtraDataTrail(Metadata.Expression, data);

                        const elements = extra.trail.next(extra.data.elements_len, u32, self);

                        try metadata_block.writeAbbrevAdapted(MetadataBlock.Expression{
                            .elements = elements,
                        }, metadata_adapter);
                    },
                    .tuple => {
                        var extra = self.metadataExtraDataTrail(Metadata.Tuple, data);

                        const elements = extra.trail.next(extra.data.elements_len, Metadata, self);

                        try metadata_block.writeAbbrevAdapted(MetadataBlock.Node{
                            .elements = elements,
                        }, metadata_adapter);
                    },
                    .str_tuple => {
                        var extra = self.metadataExtraDataTrail(Metadata.StrTuple, data);

                        const elements = extra.trail.next(extra.data.elements_len, Metadata, self);

                        const all_elems = try self.gpa.alloc(Metadata, elements.len + 1);
                        defer self.gpa.free(all_elems);
                        all_elems[0] = @enumFromInt(metadata_adapter.getMetadataStringIndex(extra.data.str));
                        for (elements, all_elems[1..]) |elem, *out_elem| {
                            out_elem.* = @enumFromInt(metadata_adapter.getMetadataIndex(elem));
                        }

                        try metadata_block.writeAbbrev(MetadataBlock.Node{
                            .elements = all_elems,
                        });
                    },
                    .module_flag => {
                        const extra = self.metadataExtraData(Metadata.ModuleFlag, data);
                        try metadata_block.writeAbbrev(MetadataBlock.Node{
                            .elements = &.{
                                @enumFromInt(metadata_adapter.getMetadataIndex(extra.behavior)),
                                @enumFromInt(metadata_adapter.getMetadataStringIndex(extra.name)),
                                @enumFromInt(metadata_adapter.getMetadataIndex(extra.constant)),
                            },
                        });
                    },
                    .local_var => {
                        const extra = self.metadataExtraData(Metadata.LocalVar, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.LocalVar{
                            .scope = extra.scope,
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                        }, metadata_adapter);
                    },
                    .parameter => {
                        const extra = self.metadataExtraData(Metadata.Parameter, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.Parameter{
                            .scope = extra.scope,
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                            .arg = extra.arg_no,
                        }, metadata_adapter);
                    },
                    .global_var,
                    .@"global_var local",
                    => |kind| {
                        const extra = self.metadataExtraData(Metadata.GlobalVar, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.GlobalVar{
                            .scope = extra.scope,
                            .name = extra.name,
                            .linkage_name = extra.linkage_name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                            .local = kind == .@"global_var local",
                        }, metadata_adapter);
                    },
                    .global_var_expression => {
                        const extra = self.metadataExtraData(Metadata.GlobalVarExpression, data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.GlobalVarExpression{
                            .variable = extra.variable,
                            .expression = extra.expression,
                        }, metadata_adapter);
                    },
                    .constant => {
                        const constant: Constant = @enumFromInt(data);
                        try metadata_block.writeAbbrevAdapted(MetadataBlock.Constant{
                            .ty = constant.typeOf(self),
                            .constant = constant,
                        }, metadata_adapter);
                    },
                }
            }

            // Write named metadata
            for (self.metadata_named.keys(), self.metadata_named.values()) |name, operands| {
                const slice = name.slice(self);
                try metadata_block.writeAbbrev(MetadataBlock.Name{
                    .name = slice,
                });

                const elements = self.metadata_extra.items[operands.index..][0..operands.len];
                for (elements) |*e| {
                    e.* = metadata_adapter.getMetadataIndex(@enumFromInt(e.*)) - 1;
                }

                try metadata_block.writeAbbrev(MetadataBlock.NamedNode{
                    .elements = @ptrCast(elements),
                });
            }

            // Write global attached metadata
            {
                for (globals.keys()) |global| {
                    const global_ptr = global.ptrConst(self);
                    if (global_ptr.dbg == .none) continue;

                    switch (global_ptr.kind) {
                        .function => |f| if (f.ptrConst(self).instructions.len != 0) continue,
                        else => {},
                    }

                    try metadata_block.writeAbbrev(MetadataBlock.GlobalDeclAttachment{
                        .value = @enumFromInt(constant_adapter.getConstantIndex(global.toConst())),
                        .kind = .dbg,
                        .metadata = @enumFromInt(metadata_adapter.getMetadataIndex(global_ptr.dbg) - 1),
                    });
                }
            }

            try metadata_block.end();
        }

        // OPERAND_BUNDLE_TAGS_BLOCK
        {
            const OperandBundleTags = ir.OperandBundleTags;
            var operand_bundle_tags_block = try module_block.enterSubBlock(OperandBundleTags, true);

            try operand_bundle_tags_block.writeAbbrev(OperandBundleTags.OperandBundleTag{
                .tag = "cold",
            });

            try operand_bundle_tags_block.end();
        }

        // Block info
        {
            const BlockInfo = ir.BlockInfo;
            var block_info_block = try module_block.enterSubBlock(BlockInfo, true);

            try block_info_block.writeUnabbrev(BlockInfo.set_block_id, &.{ir.FunctionBlock.id});
            inline for (ir.FunctionBlock.abbrevs) |abbrev| {
                try block_info_block.defineAbbrev(&abbrev.ops);
            }

            try block_info_block.writeUnabbrev(BlockInfo.set_block_id, &.{ir.FunctionValueSymbolTable.id});
            inline for (ir.FunctionValueSymbolTable.abbrevs) |abbrev| {
                try block_info_block.defineAbbrev(&abbrev.ops);
            }

            try block_info_block.writeUnabbrev(BlockInfo.set_block_id, &.{ir.FunctionMetadataBlock.id});
            inline for (ir.FunctionMetadataBlock.abbrevs) |abbrev| {
                try block_info_block.defineAbbrev(&abbrev.ops);
            }

            try block_info_block.writeUnabbrev(BlockInfo.set_block_id, &.{ir.MetadataAttachmentBlock.id});
            inline for (ir.MetadataAttachmentBlock.abbrevs) |abbrev| {
                try block_info_block.defineAbbrev(&abbrev.ops);
            }

            try block_info_block.end();
        }

        // FUNCTION_BLOCKS
        {
            const FunctionAdapter = struct {
                constant_adapter: ConstantAdapter,
                metadata_adapter: MetadataAdapter,
                func: *const Function,
                instruction_index: Function.Instruction.Index,

                pub fn get(adapter: @This(), value: anytype, comptime field_name: []const u8) @TypeOf(value) {
                    _ = field_name;
                    const Ty = @TypeOf(value);
                    return switch (Ty) {
                        Value => @enumFromInt(adapter.getOffsetValueIndex(value)),
                        Constant => @enumFromInt(adapter.getOffsetConstantIndex(value)),
                        FunctionAttributes => @enumFromInt(switch (value) {
                            .none => 0,
                            else => 1 + adapter.constant_adapter.builder.function_attributes_set.getIndex(value).?,
                        }),
                        else => value,
                    };
                }

                pub fn getValueIndex(adapter: @This(), value: Value) u32 {
                    return @intCast(switch (value.unwrap()) {
                        .instruction => |instruction| instruction.valueIndex(adapter.func) + adapter.firstInstr(),
                        .constant => |constant| adapter.constant_adapter.getConstantIndex(constant),
                        .metadata => |metadata| {
                            const real_metadata = metadata.unwrap(adapter.metadata_adapter.builder);
                            if (@intFromEnum(real_metadata) < Metadata.first_local_metadata)
                                return adapter.metadata_adapter.getMetadataIndex(real_metadata) - 1;

                            return @intCast(@intFromEnum(metadata) -
                                Metadata.first_local_metadata +
                                adapter.metadata_adapter.builder.metadata_string_map.count() - 1 +
                                adapter.metadata_adapter.builder.metadata_map.count() - 1);
                        },
                    });
                }

                pub fn getOffsetValueIndex(adapter: @This(), value: Value) u32 {
                    return adapter.offset() -% adapter.getValueIndex(value);
                }

                pub fn getOffsetValueSignedIndex(adapter: @This(), value: Value) i32 {
                    const signed_offset: i32 = @intCast(adapter.offset());
                    const signed_value: i32 = @intCast(adapter.getValueIndex(value));
                    return signed_offset - signed_value;
                }

                pub fn getOffsetConstantIndex(adapter: @This(), constant: Constant) u32 {
                    return adapter.offset() - adapter.constant_adapter.getConstantIndex(constant);
                }

                pub fn offset(adapter: @This()) u32 {
                    return adapter.instruction_index.valueIndex(adapter.func) + adapter.firstInstr();
                }

                fn firstInstr(adapter: @This()) u32 {
                    return adapter.constant_adapter.numConstants();
                }
            };

            for (self.functions.items, 0..) |func, func_index| {
                const FunctionBlock = ir.FunctionBlock;
                if (func.global.getReplacement(self) != .none) continue;

                if (func.instructions.len == 0) continue;

                var function_block = try module_block.enterSubBlock(FunctionBlock, false);

                try function_block.writeAbbrev(FunctionBlock.DeclareBlocks{ .num_blocks = func.blocks.len });

                var adapter: FunctionAdapter = .{
                    .constant_adapter = constant_adapter,
                    .metadata_adapter = metadata_adapter,
                    .func = &func,
                    .instruction_index = @enumFromInt(0),
                };

                // Emit function level metadata block
                if (!func.strip and func.debug_values.len > 0) {
                    const MetadataBlock = ir.FunctionMetadataBlock;
                    var metadata_block = try function_block.enterSubBlock(MetadataBlock, false);

                    for (func.debug_values) |value| {
                        try metadata_block.writeAbbrev(MetadataBlock.Value{
                            .ty = value.typeOf(@enumFromInt(func_index), self),
                            .value = @enumFromInt(adapter.getValueIndex(value.toValue())),
                        });
                    }

                    try metadata_block.end();
                }

                const tags = func.instructions.items(.tag);
                const datas = func.instructions.items(.data);

                var has_location = false;

                var block_incoming_len: u32 = undefined;
                for (tags, datas, 0..) |tag, data, instr_index| {
                    adapter.instruction_index = @enumFromInt(instr_index);
                    record.clearRetainingCapacity();

                    switch (tag) {
                        .arg => continue,
                        .block => {
                            block_incoming_len = data;
                            continue;
                        },
                        .@"unreachable" => try function_block.writeAbbrev(FunctionBlock.Unreachable{}),
                        .call,
                        .@"musttail call",
                        .@"notail call",
                        .@"tail call",
                        => |kind| {
                            var extra = func.extraDataTrail(Function.Instruction.Call, data);

                            if (extra.data.info.has_op_bundle_cold) {
                                try function_block.writeAbbrev(FunctionBlock.ColdOperandBundle{});
                            }

                            const call_conv = extra.data.info.call_conv;
                            const args = extra.trail.next(extra.data.args_len, Value, &func);
                            try function_block.writeAbbrevAdapted(FunctionBlock.Call{
                                .attributes = extra.data.attributes,
                                .call_type = switch (kind) {
                                    .call => .{ .call_conv = call_conv },
                                    .@"tail call" => .{ .tail = true, .call_conv = call_conv },
                                    .@"musttail call" => .{ .must_tail = true, .call_conv = call_conv },
                                    .@"notail call" => .{ .no_tail = true, .call_conv = call_conv },
                                    else => unreachable,
                                },
                                .type_id = extra.data.ty,
                                .callee = extra.data.callee,
                                .args = args,
                            }, adapter);
                        },
                        .@"call fast",
                        .@"musttail call fast",
                        .@"notail call fast",
                        .@"tail call fast",
                        => |kind| {
                            var extra = func.extraDataTrail(Function.Instruction.Call, data);

                            if (extra.data.info.has_op_bundle_cold) {
                                try function_block.writeAbbrev(FunctionBlock.ColdOperandBundle{});
                            }

                            const call_conv = extra.data.info.call_conv;
                            const args = extra.trail.next(extra.data.args_len, Value, &func);
                            try function_block.writeAbbrevAdapted(FunctionBlock.CallFast{
                                .attributes = extra.data.attributes,
                                .call_type = switch (kind) {
                                    .@"call fast" => .{ .call_conv = call_conv },
                                    .@"tail call fast" => .{ .tail = true, .call_conv = call_conv },
                                    .@"musttail call fast" => .{ .must_tail = true, .call_conv = call_conv },
                                    .@"notail call fast" => .{ .no_tail = true, .call_conv = call_conv },
                                    else => unreachable,
                                },
                                .fast_math = FastMath.fast,
                                .type_id = extra.data.ty,
                                .callee = extra.data.callee,
                                .args = args,
                            }, adapter);
                        },
                        .add,
                        .@"and",
                        .fadd,
                        .fdiv,
                        .fmul,
                        .mul,
                        .frem,
                        .fsub,
                        .sdiv,
                        .sub,
                        .udiv,
                        .xor,
                        .shl,
                        .lshr,
                        .@"or",
                        .urem,
                        .srem,
                        .ashr,
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Binary, data);
                            try function_block.writeAbbrev(FunctionBlock.Binary{
                                .opcode = kind.toBinaryOpcode(),
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                            });
                        },
                        .@"sdiv exact",
                        .@"udiv exact",
                        .@"lshr exact",
                        .@"ashr exact",
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Binary, data);
                            try function_block.writeAbbrev(FunctionBlock.BinaryExact{
                                .opcode = kind.toBinaryOpcode(),
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                            });
                        },
                        .@"add nsw",
                        .@"add nuw",
                        .@"add nuw nsw",
                        .@"mul nsw",
                        .@"mul nuw",
                        .@"mul nuw nsw",
                        .@"sub nsw",
                        .@"sub nuw",
                        .@"sub nuw nsw",
                        .@"shl nsw",
                        .@"shl nuw",
                        .@"shl nuw nsw",
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Binary, data);
                            try function_block.writeAbbrev(FunctionBlock.BinaryNoWrap{
                                .opcode = kind.toBinaryOpcode(),
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                                .flags = switch (kind) {
                                    .@"add nsw",
                                    .@"mul nsw",
                                    .@"sub nsw",
                                    .@"shl nsw",
                                    => .{ .no_unsigned_wrap = false, .no_signed_wrap = true },
                                    .@"add nuw",
                                    .@"mul nuw",
                                    .@"sub nuw",
                                    .@"shl nuw",
                                    => .{ .no_unsigned_wrap = true, .no_signed_wrap = false },
                                    .@"add nuw nsw",
                                    .@"mul nuw nsw",
                                    .@"sub nuw nsw",
                                    .@"shl nuw nsw",
                                    => .{ .no_unsigned_wrap = true, .no_signed_wrap = true },
                                    else => unreachable,
                                },
                            });
                        },
                        .@"fadd fast",
                        .@"fdiv fast",
                        .@"fmul fast",
                        .@"frem fast",
                        .@"fsub fast",
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Binary, data);
                            try function_block.writeAbbrev(FunctionBlock.BinaryFast{
                                .opcode = kind.toBinaryOpcode(),
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                                .fast_math = FastMath.fast,
                            });
                        },
                        .alloca,
                        .@"alloca inalloca",
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Alloca, data);
                            const alignment = extra.info.alignment.toLlvm();
                            try function_block.writeAbbrev(FunctionBlock.Alloca{
                                .inst_type = extra.type,
                                .len_type = extra.len.typeOf(@enumFromInt(func_index), self),
                                .len_value = adapter.getValueIndex(extra.len),
                                .flags = .{
                                    .align_lower = @truncate(alignment),
                                    .inalloca = kind == .@"alloca inalloca",
                                    .explicit_type = true,
                                    .swift_error = false,
                                    .align_upper = @truncate(alignment << 5),
                                },
                            });
                        },
                        .bitcast,
                        .inttoptr,
                        .ptrtoint,
                        .fptosi,
                        .fptoui,
                        .sitofp,
                        .uitofp,
                        .addrspacecast,
                        .fptrunc,
                        .trunc,
                        .fpext,
                        .sext,
                        .zext,
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Cast, data);
                            try function_block.writeAbbrev(FunctionBlock.Cast{
                                .val = adapter.getOffsetValueIndex(extra.val),
                                .type_index = extra.type,
                                .opcode = kind.toCastOpcode(),
                            });
                        },
                        .@"fcmp false",
                        .@"fcmp oeq",
                        .@"fcmp oge",
                        .@"fcmp ogt",
                        .@"fcmp ole",
                        .@"fcmp olt",
                        .@"fcmp one",
                        .@"fcmp ord",
                        .@"fcmp true",
                        .@"fcmp ueq",
                        .@"fcmp uge",
                        .@"fcmp ugt",
                        .@"fcmp ule",
                        .@"fcmp ult",
                        .@"fcmp une",
                        .@"fcmp uno",
                        .@"icmp eq",
                        .@"icmp ne",
                        .@"icmp sge",
                        .@"icmp sgt",
                        .@"icmp sle",
                        .@"icmp slt",
                        .@"icmp uge",
                        .@"icmp ugt",
                        .@"icmp ule",
                        .@"icmp ult",
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Binary, data);
                            try function_block.writeAbbrev(FunctionBlock.Cmp{
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                                .pred = kind.toCmpPredicate(),
                            });
                        },
                        .@"fcmp fast false",
                        .@"fcmp fast oeq",
                        .@"fcmp fast oge",
                        .@"fcmp fast ogt",
                        .@"fcmp fast ole",
                        .@"fcmp fast olt",
                        .@"fcmp fast one",
                        .@"fcmp fast ord",
                        .@"fcmp fast true",
                        .@"fcmp fast ueq",
                        .@"fcmp fast uge",
                        .@"fcmp fast ugt",
                        .@"fcmp fast ule",
                        .@"fcmp fast ult",
                        .@"fcmp fast une",
                        .@"fcmp fast uno",
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.Binary, data);
                            try function_block.writeAbbrev(FunctionBlock.CmpFast{
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                                .pred = kind.toCmpPredicate(),
                                .fast_math = FastMath.fast,
                            });
                        },
                        .fneg => try function_block.writeAbbrev(FunctionBlock.FNeg{
                            .val = adapter.getOffsetValueIndex(@enumFromInt(data)),
                        }),
                        .@"fneg fast" => try function_block.writeAbbrev(FunctionBlock.FNegFast{
                            .val = adapter.getOffsetValueIndex(@enumFromInt(data)),
                            .fast_math = FastMath.fast,
                        }),
                        .extractvalue => {
                            var extra = func.extraDataTrail(Function.Instruction.ExtractValue, data);
                            const indices = extra.trail.next(extra.data.indices_len, u32, &func);
                            try function_block.writeAbbrev(FunctionBlock.ExtractValue{
                                .val = adapter.getOffsetValueIndex(extra.data.val),
                                .indices = indices,
                            });
                        },
                        .extractelement => {
                            const extra = func.extraData(Function.Instruction.ExtractElement, data);
                            try function_block.writeAbbrev(FunctionBlock.ExtractElement{
                                .val = adapter.getOffsetValueIndex(extra.val),
                                .index = adapter.getOffsetValueIndex(extra.index),
                            });
                        },
                        .indirectbr => {
                            var extra =
                                func.extraDataTrail(Function.Instruction.IndirectBr, datas[instr_index]);
                            const targets =
                                extra.trail.next(extra.data.targets_len, Function.Block.Index, &func);
                            try function_block.writeAbbrevAdapted(
                                FunctionBlock.IndirectBr{
                                    .ty = extra.data.addr.typeOf(@enumFromInt(func_index), self),
                                    .addr = extra.data.addr,
                                    .targets = targets,
                                },
                                adapter,
                            );
                        },
                        .insertelement => {
                            const extra = func.extraData(Function.Instruction.InsertElement, data);
                            try function_block.writeAbbrev(FunctionBlock.InsertElement{
                                .val = adapter.getOffsetValueIndex(extra.val),
                                .elem = adapter.getOffsetValueIndex(extra.elem),
                                .index = adapter.getOffsetValueIndex(extra.index),
                            });
                        },
                        .insertvalue => {
                            var extra = func.extraDataTrail(Function.Instruction.InsertValue, datas[instr_index]);
                            const indices = extra.trail.next(extra.data.indices_len, u32, &func);
                            try function_block.writeAbbrev(FunctionBlock.InsertValue{
                                .val = adapter.getOffsetValueIndex(extra.data.val),
                                .elem = adapter.getOffsetValueIndex(extra.data.elem),
                                .indices = indices,
                            });
                        },
                        .select => {
                            const extra = func.extraData(Function.Instruction.Select, data);
                            try function_block.writeAbbrev(FunctionBlock.Select{
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                                .cond = adapter.getOffsetValueIndex(extra.cond),
                            });
                        },
                        .@"select fast" => {
                            const extra = func.extraData(Function.Instruction.Select, data);
                            try function_block.writeAbbrev(FunctionBlock.SelectFast{
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                                .cond = adapter.getOffsetValueIndex(extra.cond),
                                .fast_math = FastMath.fast,
                            });
                        },
                        .shufflevector => {
                            const extra = func.extraData(Function.Instruction.ShuffleVector, data);
                            try function_block.writeAbbrev(FunctionBlock.ShuffleVector{
                                .lhs = adapter.getOffsetValueIndex(extra.lhs),
                                .rhs = adapter.getOffsetValueIndex(extra.rhs),
                                .mask = adapter.getOffsetValueIndex(extra.mask),
                            });
                        },
                        .getelementptr,
                        .@"getelementptr inbounds",
                        => |kind| {
                            var extra = func.extraDataTrail(Function.Instruction.GetElementPtr, data);
                            const indices = extra.trail.next(extra.data.indices_len, Value, &func);
                            try function_block.writeAbbrevAdapted(
                                FunctionBlock.GetElementPtr{
                                    .is_inbounds = kind == .@"getelementptr inbounds",
                                    .type_index = extra.data.type,
                                    .base = extra.data.base,
                                    .indices = indices,
                                },
                                adapter,
                            );
                        },
                        .load => {
                            const extra = func.extraData(Function.Instruction.Load, data);
                            try function_block.writeAbbrev(FunctionBlock.Load{
                                .ptr = adapter.getOffsetValueIndex(extra.ptr),
                                .ty = extra.type,
                                .alignment = extra.info.alignment.toLlvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                            });
                        },
                        .@"load atomic" => {
                            const extra = func.extraData(Function.Instruction.Load, data);
                            try function_block.writeAbbrev(FunctionBlock.LoadAtomic{
                                .ptr = adapter.getOffsetValueIndex(extra.ptr),
                                .ty = extra.type,
                                .alignment = extra.info.alignment.toLlvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                            });
                        },
                        .store => {
                            const extra = func.extraData(Function.Instruction.Store, data);
                            try function_block.writeAbbrev(FunctionBlock.Store{
                                .ptr = adapter.getOffsetValueIndex(extra.ptr),
                                .val = adapter.getOffsetValueIndex(extra.val),
                                .alignment = extra.info.alignment.toLlvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                            });
                        },
                        .@"store atomic" => {
                            const extra = func.extraData(Function.Instruction.Store, data);
                            try function_block.writeAbbrev(FunctionBlock.StoreAtomic{
                                .ptr = adapter.getOffsetValueIndex(extra.ptr),
                                .val = adapter.getOffsetValueIndex(extra.val),
                                .alignment = extra.info.alignment.toLlvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                            });
                        },
                        .br => {
                            try function_block.writeAbbrev(FunctionBlock.BrUnconditional{
                                .block = data,
                            });
                        },
                        .br_cond => {
                            const extra = func.extraData(Function.Instruction.BrCond, data);
                            try function_block.writeAbbrev(FunctionBlock.BrConditional{
                                .then_block = @intFromEnum(extra.then),
                                .else_block = @intFromEnum(extra.@"else"),
                                .condition = adapter.getOffsetValueIndex(extra.cond),
                            });
                        },
                        .@"switch" => {
                            var extra = func.extraDataTrail(Function.Instruction.Switch, data);

                            try record.ensureUnusedCapacity(self.gpa, 3 + extra.data.cases_len * 2);

                            // Conditional type
                            record.appendAssumeCapacity(@intFromEnum(extra.data.val.typeOf(@enumFromInt(func_index), self)));

                            // Conditional
                            record.appendAssumeCapacity(adapter.getOffsetValueIndex(extra.data.val));

                            // Default block
                            record.appendAssumeCapacity(@intFromEnum(extra.data.default));

                            const vals = extra.trail.next(extra.data.cases_len, Constant, &func);
                            const blocks = extra.trail.next(extra.data.cases_len, Function.Block.Index, &func);
                            for (vals, blocks) |val, block| {
                                record.appendAssumeCapacity(adapter.constant_adapter.getConstantIndex(val));
                                record.appendAssumeCapacity(@intFromEnum(block));
                            }

                            try function_block.writeUnabbrev(12, record.items);
                        },
                        .va_arg => {
                            const extra = func.extraData(Function.Instruction.VaArg, data);
                            try function_block.writeAbbrev(FunctionBlock.VaArg{
                                .list_type = extra.list.typeOf(@enumFromInt(func_index), self),
                                .list = adapter.getOffsetValueIndex(extra.list),
                                .type = extra.type,
                            });
                        },
                        .phi,
                        .@"phi fast",
                        => |kind| {
                            var extra = func.extraDataTrail(Function.Instruction.Phi, data);
                            const vals = extra.trail.next(block_incoming_len, Value, &func);
                            const blocks = extra.trail.next(block_incoming_len, Function.Block.Index, &func);

                            try record.ensureUnusedCapacity(
                                self.gpa,
                                1 + block_incoming_len * 2 + @intFromBool(kind == .@"phi fast"),
                            );

                            record.appendAssumeCapacity(@intFromEnum(extra.data.type));

                            for (vals, blocks) |val, block| {
                                const offset_value = adapter.getOffsetValueSignedIndex(val);
                                const abs_value: u32 = @intCast(@abs(offset_value));
                                const signed_vbr = if (offset_value > 0) abs_value << 1 else ((abs_value << 1) | 1);
                                record.appendAssumeCapacity(signed_vbr);
                                record.appendAssumeCapacity(@intFromEnum(block));
                            }

                            if (kind == .@"phi fast") record.appendAssumeCapacity(@as(u8, @bitCast(FastMath{})));

                            try function_block.writeUnabbrev(16, record.items);
                        },
                        .ret => try function_block.writeAbbrev(FunctionBlock.Ret{
                            .val = adapter.getOffsetValueIndex(@enumFromInt(data)),
                        }),
                        .@"ret void" => try function_block.writeAbbrev(FunctionBlock.RetVoid{}),
                        .atomicrmw => {
                            const extra = func.extraData(Function.Instruction.AtomicRmw, data);
                            try function_block.writeAbbrev(FunctionBlock.AtomicRmw{
                                .ptr = adapter.getOffsetValueIndex(extra.ptr),
                                .val = adapter.getOffsetValueIndex(extra.val),
                                .operation = extra.info.atomic_rmw_operation,
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                                .alignment = extra.info.alignment.toLlvm(),
                            });
                        },
                        .cmpxchg,
                        .@"cmpxchg weak",
                        => |kind| {
                            const extra = func.extraData(Function.Instruction.CmpXchg, data);

                            try function_block.writeAbbrev(FunctionBlock.CmpXchg{
                                .ptr = adapter.getOffsetValueIndex(extra.ptr),
                                .cmp = adapter.getOffsetValueIndex(extra.cmp),
                                .new = adapter.getOffsetValueIndex(extra.new),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                                .failure_ordering = extra.info.failure_ordering,
                                .is_weak = kind == .@"cmpxchg weak",
                                .alignment = extra.info.alignment.toLlvm(),
                            });
                        },
                        .fence => {
                            const info: MemoryAccessInfo = @bitCast(data);
                            try function_block.writeAbbrev(FunctionBlock.Fence{
                                .ordering = info.success_ordering,
                                .sync_scope = info.sync_scope,
                            });
                        },
                    }

                    if (!func.strip) {
                        if (func.debug_locations.get(adapter.instruction_index)) |debug_location| {
                            switch (debug_location) {
                                .no_location => has_location = false,
                                .location => |location| {
                                    try function_block.writeAbbrev(FunctionBlock.DebugLoc{
                                        .line = location.line,
                                        .column = location.column,
                                        .scope = @enumFromInt(metadata_adapter.getMetadataIndex(location.scope)),
                                        .inlined_at = @enumFromInt(metadata_adapter.getMetadataIndex(location.inlined_at)),
                                    });
                                    has_location = true;
                                },
                            }
                        } else if (has_location) {
                            try function_block.writeAbbrev(FunctionBlock.DebugLocAgain{});
                        }
                    }
                }

                // VALUE_SYMTAB
                if (!func.strip) {
                    const ValueSymbolTable = ir.FunctionValueSymbolTable;

                    var value_symtab_block = try function_block.enterSubBlock(ValueSymbolTable, false);

                    for (func.blocks, 0..) |block, block_index| {
                        const name = block.instruction.name(&func);

                        if (name == .none or name == .empty) continue;

                        try value_symtab_block.writeAbbrev(ValueSymbolTable.BlockEntry{
                            .value_id = @intCast(block_index),
                            .string = name.slice(self).?,
                        });
                    }

                    // TODO: Emit non block entries if the builder ever starts assigning names to non blocks

                    try value_symtab_block.end();
                }

                // METADATA_ATTACHMENT_BLOCK
                {
                    const MetadataAttachmentBlock = ir.MetadataAttachmentBlock;
                    var metadata_attach_block = try function_block.enterSubBlock(MetadataAttachmentBlock, false);

                    dbg: {
                        if (func.strip) break :dbg;
                        const dbg = func.global.ptrConst(self).dbg;
                        if (dbg == .none) break :dbg;
                        try metadata_attach_block.writeAbbrev(MetadataAttachmentBlock.AttachmentGlobalSingle{
                            .kind = .dbg,
                            .metadata = @enumFromInt(metadata_adapter.getMetadataIndex(dbg) - 1),
                        });
                    }

                    var instr_index: u32 = 0;
                    for (func.instructions.items(.tag), func.instructions.items(.data)) |instr_tag, data| switch (instr_tag) {
                        .arg, .block => {}, // not an actual instruction
                        else => {
                            instr_index += 1;
                        },
                        .br_cond, .@"switch" => {
                            const weights = switch (instr_tag) {
                                .br_cond => func.extraData(Function.Instruction.BrCond, data).weights,
                                .@"switch" => func.extraData(Function.Instruction.Switch, data).weights,
                                else => unreachable,
                            };
                            switch (weights) {
                                .none => {},
                                .unpredictable => try metadata_attach_block.writeAbbrev(MetadataAttachmentBlock.AttachmentInstructionSingle{
                                    .inst = instr_index,
                                    .kind = .unpredictable,
                                    .metadata = @enumFromInt(metadata_adapter.getMetadataIndex(.empty_tuple) - 1),
                                }),
                                _ => try metadata_attach_block.writeAbbrev(MetadataAttachmentBlock.AttachmentInstructionSingle{
                                    .inst = instr_index,
                                    .kind = .prof,
                                    .metadata = @enumFromInt(metadata_adapter.getMetadataIndex(@enumFromInt(@intFromEnum(weights))) - 1),
                                }),
                            }
                            instr_index += 1;
                        },
                    };

                    try metadata_attach_block.end();
                }

                try function_block.end();
            }
        }

        try module_block.end();
    }

    // STRTAB_BLOCK
    {
        const Strtab = ir.Strtab;
        var strtab_block = try bitcode.enterTopBlock(Strtab);

        try strtab_block.writeAbbrev(Strtab.Blob{ .blob = self.strtab_string_bytes.items });

        try strtab_block.end();
    }

    return bitcode.toOwnedSlice();
}

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const bitcode_writer = @import("bitcode_writer.zig");
const Builder = @This();
const builtin = @import("builtin");
const DW = std.dwarf;
const ir = @import("ir.zig");
const log = std.log.scoped(.llvm);
const std = @import("../../std.zig");
const std = @import("../../std.zig");
const Builder = @import("Builder.zig");
const bitcode_writer = @import("bitcode_writer.zig");

const AbbrevOp = bitcode_writer.AbbrevOp;

pub const MAGIC: u32 = 0xdec04342;

const ValueAbbrev = AbbrevOp{ .vbr = 6 };
const ValueArrayAbbrev = AbbrevOp{ .array_vbr = 6 };

const ConstantAbbrev = AbbrevOp{ .vbr = 6 };
const ConstantArrayAbbrev = AbbrevOp{ .array_vbr = 6 };

const MetadataAbbrev = AbbrevOp{ .vbr = 16 };
const MetadataArrayAbbrev = AbbrevOp{ .array_vbr = 16 };

const LineAbbrev = AbbrevOp{ .vbr = 8 };
const ColumnAbbrev = AbbrevOp{ .vbr = 8 };

const BlockAbbrev = AbbrevOp{ .vbr = 6 };
const BlockArrayAbbrev = AbbrevOp{ .array_vbr = 6 };

/// Unused tags are commented out so that they are omitted in the generated
/// bitcode, which scans over this enum using reflection.
pub const FixedMetadataKind = enum(u8) {
    dbg = 0,
    //tbaa = 1,
    prof = 2,
    //fpmath = 3,
    //range = 4,
    //@"tbaa.struct" = 5,
    //@"invariant.load" = 6,
    //@"alias.scope" = 7,
    //@"noalias" = 8,
    //nontemporal = 9,
    //@"llvm.mem.parallel_loop_access" = 10,
    //nonnull = 11,
    //dereferenceable = 12,
    //dereferenceable_or_null = 13,
    //@"make.implicit" = 14,
    unpredictable = 15,
    //@"invariant.group" = 16,
    //@"align" = 17,
    //@"llvm.loop" = 18,
    //type = 19,
    //section_prefix = 20,
    //absolute_symbol = 21,
    //associated = 22,
    //callees = 23,
    //irr_loop = 24,
    //@"llvm.access.group" = 25,
    //callback = 26,
    //@"llvm.preserve.access.index" = 27,
    //vcall_visibility = 28,
    //noundef = 29,
    //annotation = 30,
    //nosanitize = 31,
    //func_sanitize = 32,
    //exclude = 33,
    //memprof = 34,
    //callsite = 35,
    //kcfi_type = 36,
    //pcsections = 37,
    //DIAssignID = 38,
    //@"coro.outside.frame" = 39,
};

pub const MetadataCode = enum(u8) {
    /// MDSTRING:      [values]
    STRING_OLD = 1,
    /// VALUE:         [type num, value num]
    VALUE = 2,
    /// NODE:          [n x md num]
    NODE = 3,
    /// STRING:        [values]
    NAME = 4,
    /// DISTINCT_NODE: [n x md num]
    DISTINCT_NODE = 5,
    /// [n x [id, name]]
    KIND = 6,
    /// [distinct, line, col, scope, inlined-at?]
    LOCATION = 7,
    /// OLD_NODE:      [n x (type num, value num)]
    OLD_NODE = 8,
    /// OLD_FN_NODE:   [n x (type num, value num)]
    OLD_FN_NODE = 9,
    /// NAMED_NODE:    [n x mdnodes]
    NAMED_NODE = 10,
    /// [m x [value, [n x [id, mdnode]]]
    ATTACHMENT = 11,
    /// [distinct, tag, vers, header, n x md num]
    GENERIC_DEBUG = 12,
    /// [distinct, count, lo]
    SUBRANGE = 13,
    /// [isUnsigned|distinct, value, name]
    ENUMERATOR = 14,
    /// [distinct, tag, name, size, align, enc]
    BASIC_TYPE = 15,
    /// [distinct, filename, directory, checksumkind, checksum]
    FILE = 16,
    /// [distinct, ...]
    DERIVED_TYPE = 17,
    /// [distinct, ...]
    COMPOSITE_TYPE = 18,
    /// [distinct, flags, types, cc]
    SUBROUTINE_TYPE = 19,
    /// [distinct, ...]
    COMPILE_UNIT = 20,
    /// [distinct, ...]
    SUBPROGRAM = 21,
    /// [distinct, scope, file, line, column]
    LEXICAL_BLOCK = 22,
    ///[distinct, scope, file, discriminator]
    LEXICAL_BLOCK_FILE = 23,
    /// [distinct, scope, file, name, line, exportSymbols]
    NAMESPACE = 24,
    /// [distinct, scope, name, type, ...]
    TEMPLATE_TYPE = 25,
    /// [distinct, scope, name, type, value, ...]
    TEMPLATE_VALUE = 26,
    /// [distinct, ...]
    GLOBAL_VAR = 27,
    /// [distinct, ...]
    LOCAL_VAR = 28,
    /// [distinct, n x element]
    EXPRESSION = 29,
    /// [distinct, name, file, line, ...]
    OBJC_PROPERTY = 30,
    /// [distinct, tag, scope, entity, line, name]
    IMPORTED_ENTITY = 31,
    /// [distinct, scope, name, ...]
    MODULE = 32,
    /// [distinct, macinfo, line, name, value]
    MACRO = 33,
    /// [distinct, macinfo, line, file, ...]
    MACRO_FILE = 34,
    /// [count, offset] blob([lengths][chars])
    STRINGS = 35,
    /// [valueid, n x [id, mdnode]]
    GLOBAL_DECL_ATTACHMENT = 36,
    /// [distinct, var, expr]
    GLOBAL_VAR_EXPR = 37,
    /// [offset]
    INDEX_OFFSET = 38,
    /// [bitpos]
    INDEX = 39,
    /// [distinct, scope, name, file, line]
    LABEL = 40,
    /// [distinct, name, size, align,...]
    STRING_TYPE = 41,
    /// [distinct, scope, name, variable,...]
    COMMON_BLOCK = 44,
    /// [distinct, count, lo, up, stride]
    GENERIC_SUBRANGE = 45,
    /// [n x [type num, value num]]
    ARG_LIST = 46,
    /// [distinct, ...]
    ASSIGN_ID = 47,
};

pub const Identification = struct {
    pub const id = 13;

    pub const abbrevs = [_]type{
        Version,
        Epoch,
    };

    pub const Version = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 1 },
            .{ .array_fixed = 8 },
        };
        string: []const u8,
    };

    pub const Epoch = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            .{ .vbr = 6 },
        };
        epoch: u32,
    };
};

pub const Module = struct {
    pub const id = 8;

    pub const abbrevs = [_]type{
        Version,
        String,
        Variable,
        Function,
        Alias,
    };

    pub const Version = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 1 },
            .{ .literal = 2 },
        };
    };

    pub const String = struct {
        pub const ops = [_]AbbrevOp{
            .{ .vbr = 4 },
            .{ .array_fixed = 8 },
        };
        code: u16,
        string: []const u8,
    };

    pub const Variable = struct {
        const AddrSpaceAndIsConst = packed struct {
            is_const: bool,
            one: u1 = 1,
            addr_space: Builder.AddrSpace,
        };

        pub const ops = [_]AbbrevOp{
            .{ .literal = 7 }, // Code
            .{ .vbr = 16 }, // strtab_offset
            .{ .vbr = 16 }, // strtab_size
            .{ .fixed_runtime = Builder.Type },
            .{ .fixed = @bitSizeOf(AddrSpaceAndIsConst) }, // isconst
            ConstantAbbrev, // initid
            .{ .fixed = @bitSizeOf(Builder.Linkage) },
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
            .{ .vbr = 16 }, // section
            .{ .fixed = @bitSizeOf(Builder.Visibility) },
            .{ .fixed = @bitSizeOf(Builder.ThreadLocal) }, // threadlocal
            .{ .fixed = @bitSizeOf(Builder.UnnamedAddr) },
            .{ .fixed = @bitSizeOf(Builder.ExternallyInitialized) },
            .{ .fixed = @bitSizeOf(Builder.DllStorageClass) },
            .{ .literal = 0 }, // comdat
            .{ .literal = 0 }, // attributes
            .{ .fixed = @bitSizeOf(Builder.Preemption) },
        };
        strtab_offset: usize,
        strtab_size: usize,
        type_index: Builder.Type,
        is_const: AddrSpaceAndIsConst,
        initid: u32,
        linkage: Builder.Linkage,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
        section: usize,
        visibility: Builder.Visibility,
        thread_local: Builder.ThreadLocal,
        unnamed_addr: Builder.UnnamedAddr,
        externally_initialized: Builder.ExternallyInitialized,
        dllstorageclass: Builder.DllStorageClass,
        preemption: Builder.Preemption,
    };

    pub const Function = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 8 }, // Code
            .{ .vbr = 16 }, // strtab_offset
            .{ .vbr = 16 }, // strtab_size
            .{ .fixed_runtime = Builder.Type },
            .{ .fixed = @bitSizeOf(Builder.CallConv) },
            .{ .fixed = 1 }, // isproto
            .{ .fixed = @bitSizeOf(Builder.Linkage) },
            .{ .vbr = 16 }, // paramattr
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
            .{ .vbr = 16 }, // section
            .{ .fixed = @bitSizeOf(Builder.Visibility) },
            .{ .literal = 0 }, // gc
            .{ .fixed = @bitSizeOf(Builder.UnnamedAddr) },
            .{ .literal = 0 }, // prologuedata
            .{ .fixed = @bitSizeOf(Builder.DllStorageClass) },
            .{ .literal = 0 }, // comdat
            .{ .literal = 0 }, // prefixdata
            .{ .literal = 0 }, // personalityfn
            .{ .fixed = @bitSizeOf(Builder.Preemption) },
            .{ .fixed = @bitSizeOf(Builder.AddrSpace) },
        };
        strtab_offset: usize,
        strtab_size: usize,
        type_index: Builder.Type,
        call_conv: Builder.CallConv,
        is_proto: bool,
        linkage: Builder.Linkage,
        paramattr: usize,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
        section: usize,
        visibility: Builder.Visibility,
        unnamed_addr: Builder.UnnamedAddr,
        dllstorageclass: Builder.DllStorageClass,
        preemption: Builder.Preemption,
        addr_space: Builder.AddrSpace,
    };

    pub const Alias = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 14 }, // Code
            .{ .vbr = 16 }, // strtab_offset
            .{ .vbr = 16 }, // strtab_size
            .{ .fixed_runtime = Builder.Type },
            .{ .fixed = @bitSizeOf(Builder.AddrSpace) },
            ConstantAbbrev, // aliasee val
            .{ .fixed = @bitSizeOf(Builder.Linkage) },
            .{ .fixed = @bitSizeOf(Builder.Visibility) },
            .{ .fixed = @bitSizeOf(Builder.DllStorageClass) },
            .{ .fixed = @bitSizeOf(Builder.ThreadLocal) },
            .{ .fixed = @bitSizeOf(Builder.UnnamedAddr) },
            .{ .fixed = @bitSizeOf(Builder.Preemption) },
        };
        strtab_offset: usize,
        strtab_size: usize,
        type_index: Builder.Type,
        addr_space: Builder.AddrSpace,
        aliasee: u32,
        linkage: Builder.Linkage,
        visibility: Builder.Visibility,
        dllstorageclass: Builder.DllStorageClass,
        thread_local: Builder.ThreadLocal,
        unnamed_addr: Builder.UnnamedAddr,
        preemption: Builder.Preemption,
    };
};

pub const BlockInfo = struct {
    pub const id = 0;

    pub const set_block_id = 1;

    pub const abbrevs = [_]type{};
};

pub const Type = struct {
    pub const id = 17;

    pub const abbrevs = [_]type{
        NumEntry,
        Simple,
        Opaque,
        Integer,
        StructAnon,
        StructNamed,
        StructName,
        Array,
        Vector,
        Pointer,
        Target,
        Function,
    };

    pub const NumEntry = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 1 },
            .{ .fixed = 32 },
        };
        num: u32,
    };

    pub const Simple = struct {
        pub const ops = [_]AbbrevOp{
            .{ .vbr = 4 },
        };
        code: u5,
    };

    pub const Opaque = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            .{ .literal = 0 },
        };
    };

    pub const Integer = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 7 },
            .{ .fixed = 28 },
        };
        width: u28,
    };

    pub const StructAnon = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 18 },
            .{ .fixed = 1 },
            .{ .array_fixed_runtime = Builder.Type },
        };
        is_packed: bool,
        types: []const Builder.Type,
    };

    pub const StructNamed = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 20 },
            .{ .fixed = 1 },
            .{ .array_fixed_runtime = Builder.Type },
        };
        is_packed: bool,
        types: []const Builder.Type,
    };

    pub const StructName = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 19 },
            .{ .array_fixed = 8 },
        };
        string: []const u8,
    };

    pub const Array = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 11 },
            .{ .vbr = 16 },
            .{ .fixed_runtime = Builder.Type },
        };
        len: u64,
        child: Builder.Type,
    };

    pub const Vector = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 12 },
            .{ .vbr = 16 },
            .{ .fixed_runtime = Builder.Type },
        };
        len: u64,
        child: Builder.Type,
    };

    pub const Pointer = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 25 },
            .{ .vbr = 4 },
        };
        addr_space: Builder.AddrSpace,
    };

    pub const Target = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 26 },
            .{ .vbr = 4 },
            .{ .array_fixed_runtime = Builder.Type },
            .{ .array_fixed = 32 },
        };
        num_types: u32,
        types: []const Builder.Type,
        ints: []const u32,
    };

    pub const Function = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 21 },
            .{ .fixed = 1 },
            .{ .fixed_runtime = Builder.Type },
            .{ .array_fixed_runtime = Builder.Type },
        };
        is_vararg: bool,
        return_type: Builder.Type,
        param_types: []const Builder.Type,
    };
};

pub const Paramattr = struct {
    pub const id = 9;

    pub const abbrevs = [_]type{
        Entry,
    };

    pub const Entry = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            .{ .array_vbr = 8 },
        };
        group_indices: []const u64,
    };
};

pub const ParamattrGroup = struct {
    pub const id = 10;

    pub const abbrevs = [_]type{};
};

pub const Constants = struct {
    pub const id = 11;

    pub const abbrevs = [_]type{
        SetType,
        Null,
        Undef,
        Poison,
        Integer,
        Half,
        Float,
        Double,
        Fp80,
        Fp128,
        Aggregate,
        String,
        CString,
        Cast,
        Binary,
        Cmp,
        ExtractElement,
        InsertElement,
        ShuffleVector,
        ShuffleVectorEx,
        BlockAddress,
        DsoLocalEquivalentOrNoCfi,
    };

    pub const SetType = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 1 },
            .{ .fixed_runtime = Builder.Type },
        };
        type_id: Builder.Type,
    };

    pub const Null = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
        };
    };

    pub const Undef = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 3 },
        };
    };

    pub const Poison = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 26 },
        };
    };

    pub const Integer = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 4 },
            .{ .vbr = 16 },
        };
        value: u64,
    };

    pub const Half = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            .{ .fixed = 16 },
        };
        value: u16,
    };

    pub const Float = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            .{ .fixed = 32 },
        };
        value: u32,
    };

    pub const Double = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            .{ .vbr = 6 },
        };
        value: u64,
    };

    pub const Fp80 = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            .{ .vbr = 6 },
            .{ .vbr = 6 },
        };
        hi: u64,
        lo: u16,
    };

    pub const Fp128 = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            .{ .vbr = 6 },
            .{ .vbr = 6 },
        };
        lo: u64,
        hi: u64,
    };

    pub const Aggregate = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 7 },
            .{ .array_fixed = 32 },
        };
        values: []const Builder.Constant,
    };

    pub const String = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 8 },
            .{ .array_fixed = 8 },
        };
        string: []const u8,
    };

    pub const CString = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 9 },
            .{ .array_fixed = 8 },
        };
        string: []const u8,
    };

    pub const Cast = struct {
        const CastOpcode = Builder.CastOpcode;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 11 },
            .{ .fixed = @bitSizeOf(CastOpcode) },
            .{ .fixed_runtime = Builder.Type },
            ConstantAbbrev,
        };

        opcode: CastOpcode,
        type_index: Builder.Type,
        val: Builder.Constant,
    };

    pub const Binary = struct {
        const BinaryOpcode = Builder.BinaryOpcode;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 10 },
            .{ .fixed = @bitSizeOf(BinaryOpcode) },
            ConstantAbbrev,
            ConstantAbbrev,
        };

        opcode: BinaryOpcode,
        lhs: Builder.Constant,
        rhs: Builder.Constant,
    };

    pub const Cmp = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 17 },
            .{ .fixed_runtime = Builder.Type },
            ConstantAbbrev,
            ConstantAbbrev,
            .{ .vbr = 6 },
        };

        ty: Builder.Type,
        lhs: Builder.Constant,
        rhs: Builder.Constant,
        pred: u32,
    };

    pub const ExtractElement = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 14 },
            .{ .fixed_runtime = Builder.Type },
            ConstantAbbrev,
            .{ .fixed_runtime = Builder.Type },
            ConstantAbbrev,
        };

        val_type: Builder.Type,
        val: Builder.Constant,
        index_type: Builder.Type,
        index: Builder.Constant,
    };

    pub const InsertElement = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 15 },
            ConstantAbbrev,
            ConstantAbbrev,
            .{ .fixed_runtime = Builder.Type },
            ConstantAbbrev,
        };

        val: Builder.Constant,
        elem: Builder.Constant,
        index_type: Builder.Type,
        index: Builder.Constant,
    };

    pub const ShuffleVector = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 16 },
            ValueAbbrev,
            ValueAbbrev,
            ValueAbbrev,
        };

        lhs: Builder.Constant,
        rhs: Builder.Constant,
        mask: Builder.Constant,
    };

    pub const ShuffleVectorEx = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 19 },
            .{ .fixed_runtime = Builder.Type },
            ValueAbbrev,
            ValueAbbrev,
            ValueAbbrev,
        };

        ty: Builder.Type,
        lhs: Builder.Constant,
        rhs: Builder.Constant,
        mask: Builder.Constant,
    };

    pub const BlockAddress = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 21 },
            .{ .fixed_runtime = Builder.Type },
            ConstantAbbrev,
            BlockAbbrev,
        };
        type_id: Builder.Type,
        function: u32,
        block: u32,
    };

    pub const DsoLocalEquivalentOrNoCfi = struct {
        pub const ops = [_]AbbrevOp{
            .{ .fixed = 5 },
            .{ .fixed_runtime = Builder.Type },
            ConstantAbbrev,
        };
        code: u5,
        type_id: Builder.Type,
        function: u32,
    };
};

pub const MetadataKindBlock = struct {
    pub const id = 22;

    pub const abbrevs = [_]type{
        Kind,
    };

    pub const Kind = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            .{ .vbr = 4 },
            .{ .array_fixed = 8 },
        };
        id: u32,
        name: []const u8,
    };
};

pub const MetadataAttachmentBlock = struct {
    pub const id = 16;

    pub const abbrevs = [_]type{
        AttachmentGlobalSingle,
        AttachmentInstructionSingle,
    };

    pub const AttachmentGlobalSingle = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.ATTACHMENT) },
            .{ .fixed = 1 },
            MetadataAbbrev,
        };
        kind: FixedMetadataKind,
        metadata: Builder.Metadata,
    };

    pub const AttachmentInstructionSingle = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.ATTACHMENT) },
            ValueAbbrev,
            .{ .fixed = 5 },
            MetadataAbbrev,
        };
        inst: u32,
        kind: FixedMetadataKind,
        metadata: Builder.Metadata,
    };
};

pub const MetadataBlock = struct {
    pub const id = 15;

    pub const abbrevs = [_]type{
        Strings,
        File,
        CompileUnit,
        Subprogram,
        LexicalBlock,
        Location,
        BasicType,
        CompositeType,
        DerivedType,
        SubroutineType,
        Enumerator,
        Subrange,
        Expression,
        Node,
        LocalVar,
        Parameter,
        GlobalVar,
        GlobalVarExpression,
        Constant,
        Name,
        NamedNode,
        GlobalDeclAttachment,
    };

    pub const Strings = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.STRINGS) },
            .{ .vbr = 6 },
            .{ .vbr = 6 },
            .blob,
        };
        num_strings: u32,
        strings_offset: u32,
        blob: []const u8,
    };

    pub const File = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.FILE) },
            .{ .literal = 0 }, // is distinct
            MetadataAbbrev, // filename
            MetadataAbbrev, // directory
            .{ .literal = 0 }, // checksum
            .{ .literal = 0 }, // checksum
        };

        filename: Builder.MetadataString,
        directory: Builder.MetadataString,
    };

    pub const CompileUnit = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.COMPILE_UNIT) },
            .{ .literal = 1 }, // is distinct
            .{ .literal = std.dwarf.LANG.C99 }, // source language
            MetadataAbbrev, // file
            MetadataAbbrev, // producer
            .{ .fixed = 1 }, // isOptimized
            .{ .literal = 0 }, // raw flags
            .{ .literal = 0 }, // runtime version
            .{ .literal = 0 }, // split debug file name
            .{ .literal = 1 }, // emission kind
            MetadataAbbrev, // enums
            .{ .literal = 0 }, // retained types
            .{ .literal = 0 }, // subprograms
            MetadataAbbrev, // globals
            .{ .literal = 0 }, // imported entities
            .{ .literal = 0 }, // DWO ID
            .{ .literal = 0 }, // macros
            .{ .literal = 0 }, // split debug inlining
            .{ .literal = 0 }, // debug info profiling
            .{ .literal = 0 }, // name table kind
            .{ .literal = 0 }, // ranges base address
            .{ .literal = 0 }, // raw sysroot
            .{ .literal = 0 }, // raw SDK
        };

        file: Builder.Metadata,
        producer: Builder.MetadataString,
        is_optimized: bool,
        enums: Builder.Metadata,
        globals: Builder.Metadata,
    };

    pub const Subprogram = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.SUBPROGRAM) },
            .{ .literal = 0b111 }, // is distinct | has sp flags | has flags
            MetadataAbbrev, // scope
            MetadataAbbrev, // name
            MetadataAbbrev, // linkage name
            MetadataAbbrev, // file
            LineAbbrev, // line
            MetadataAbbrev, // type
            LineAbbrev, // scope line
            .{ .literal = 0 }, // containing type
            .{ .fixed = 32 }, // sp flags
            .{ .literal = 0 }, // virtual index
            .{ .fixed = 32 }, // flags
            MetadataAbbrev, // compile unit
            .{ .literal = 0 }, // template params
            .{ .literal = 0 }, // declaration
            .{ .literal = 0 }, // retained nodes
            .{ .literal = 0 }, // this adjustment
            .{ .literal = 0 }, // thrown types
            .{ .literal = 0 }, // annotations
            .{ .literal = 0 }, // target function name
        };

        scope: Builder.Metadata,
        name: Builder.MetadataString,
        linkage_name: Builder.MetadataString,
        file: Builder.Metadata,
        line: u32,
        ty: Builder.Metadata,
        scope_line: u32,
        sp_flags: Builder.Metadata.Subprogram.DISPFlags,
        flags: Builder.Metadata.DIFlags,
        compile_unit: Builder.Metadata,
    };

    pub const LexicalBlock = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.LEXICAL_BLOCK) },
            .{ .literal = 0 }, // is distinct
            MetadataAbbrev, // scope
            MetadataAbbrev, // file
            LineAbbrev, // line
            ColumnAbbrev, // column
        };

        scope: Builder.Metadata,
        file: Builder.Metadata,
        line: u32,
        column: u32,
    };

    pub const Location = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.LOCATION) },
            .{ .literal = 0 }, // is distinct
            LineAbbrev, // line
            ColumnAbbrev, // column
            MetadataAbbrev, // scope
            MetadataAbbrev, // inlined at
            .{ .literal = 0 }, // is implicit code
        };

        line: u32,
        column: u32,
        scope: u32,
        inlined_at: Builder.Metadata,
    };

    pub const BasicType = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.BASIC_TYPE) },
            .{ .literal = 0 }, // is distinct
            .{ .literal = std.dwarf.TAG.base_type }, // tag
            MetadataAbbrev, // name
            .{ .vbr = 6 }, // size in bits
            .{ .literal = 0 }, // align in bits
            .{ .vbr = 8 }, // encoding
            .{ .literal = 0 }, // flags
        };

        name: Builder.MetadataString,
        size_in_bits: u64,
        encoding: u32,
    };

    pub const CompositeType = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.COMPOSITE_TYPE) },
            .{ .literal = 0 | 0x2 }, // is distinct | is not used in old type ref
            .{ .fixed = 32 }, // tag
            MetadataAbbrev, // name
            MetadataAbbrev, // file
            LineAbbrev, // line
            MetadataAbbrev, // scope
            MetadataAbbrev, // underlying type
            .{ .vbr = 6 }, // size in bits
            .{ .vbr = 6 }, // align in bits
            .{ .literal = 0 }, // offset in bits
            .{ .fixed = 32 }, // flags
            MetadataAbbrev, // elements
            .{ .literal = 0 }, // runtime lang
            .{ .literal = 0 }, // vtable holder
            .{ .literal = 0 }, // template params
            .{ .literal = 0 }, // raw id
            .{ .literal = 0 }, // discriminator
            .{ .literal = 0 }, // data location
            .{ .literal = 0 }, // associated
            .{ .literal = 0 }, // allocated
            .{ .literal = 0 }, // rank
            .{ .literal = 0 }, // annotations
        };

        tag: u32,
        name: Builder.MetadataString,
        file: Builder.Metadata,
        line: u32,
        scope: Builder.Metadata,
        underlying_type: Builder.Metadata,
        size_in_bits: u64,
        align_in_bits: u64,
        flags: Builder.Metadata.DIFlags,
        elements: Builder.Metadata,
    };

    pub const DerivedType = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.DERIVED_TYPE) },
            .{ .literal = 0 }, // is distinct
            .{ .fixed = 32 }, // tag
            MetadataAbbrev, // name
            MetadataAbbrev, // file
            LineAbbrev, // line
            MetadataAbbrev, // scope
            MetadataAbbrev, // underlying type
            .{ .vbr = 6 }, // size in bits
            .{ .vbr = 6 }, // align in bits
            .{ .vbr = 6 }, // offset in bits
            .{ .literal = 0 }, // flags
            .{ .literal = 0 }, // extra data
        };

        tag: u32,
        name: Builder.MetadataString,
        file: Builder.Metadata,
        line: u32,
        scope: Builder.Metadata,
        underlying_type: Builder.Metadata,
        size_in_bits: u64,
        align_in_bits: u64,
        offset_in_bits: u64,
    };

    pub const SubroutineType = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.SUBROUTINE_TYPE) },
            .{ .literal = 0 | 0x2 }, // is distinct | has no old type refs
            .{ .literal = 0 }, // flags
            MetadataAbbrev, // types
            .{ .literal = 0 }, // cc
        };

        types: Builder.Metadata,
    };

    pub const Enumerator = struct {
        pub const id: MetadataCode = .ENUMERATOR;

        pub const Flags = packed struct(u3) {
            distinct: bool = false,
            unsigned: bool,
            bigint: bool = true,
        };

        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(Enumerator.id) },
            .{ .fixed = @bitSizeOf(Flags) }, // flags
            .{ .vbr = 6 }, // bit width
            MetadataAbbrev, // name
            .{ .vbr = 16 }, // integer value
        };

        flags: Flags,
        bit_width: u32,
        name: Builder.MetadataString,
        value: u64,
    };

    pub const Subrange = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.SUBRANGE) },
            .{ .literal = 0b10 }, // is distinct | version
            MetadataAbbrev, // count
            MetadataAbbrev, // lower bound
            .{ .literal = 0 }, // upper bound
            .{ .literal = 0 }, // stride
        };

        count: Builder.Metadata,
        lower_bound: Builder.Metadata,
    };

    pub const Expression = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.EXPRESSION) },
            .{ .literal = 0 | (3 << 1) }, // is distinct | version
            MetadataArrayAbbrev, // elements
        };

        elements: []const u32,
    };

    pub const Node = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.NODE) },
            MetadataArrayAbbrev, // elements
        };

        elements: []const Builder.Metadata,
    };

    pub const LocalVar = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.LOCAL_VAR) },
            .{ .literal = 0b10 }, // is distinct | has alignment
            MetadataAbbrev, // scope
            MetadataAbbrev, // name
            MetadataAbbrev, // file
            LineAbbrev, // line
            MetadataAbbrev, // type
            .{ .literal = 0 }, // arg
            .{ .literal = 0 }, // flags
            .{ .literal = 0 }, // align bits
            .{ .literal = 0 }, // annotations
        };

        scope: Builder.Metadata,
        name: Builder.MetadataString,
        file: Builder.Metadata,
        line: u32,
        ty: Builder.Metadata,
    };

    pub const Parameter = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.LOCAL_VAR) },
            .{ .literal = 0b10 }, // is distinct | has alignment
            MetadataAbbrev, // scope
            MetadataAbbrev, // name
            MetadataAbbrev, // file
            LineAbbrev, // line
            MetadataAbbrev, // type
            .{ .vbr = 4 }, // arg
            .{ .literal = 0 }, // flags
            .{ .literal = 0 }, // align bits
            .{ .literal = 0 }, // annotations
        };

        scope: Builder.Metadata,
        name: Builder.MetadataString,
        file: Builder.Metadata,
        line: u32,
        ty: Builder.Metadata,
        arg: u32,
    };

    pub const GlobalVar = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.GLOBAL_VAR) },
            .{ .literal = 0b101 }, // is distinct | version
            MetadataAbbrev, // scope
            MetadataAbbrev, // name
            MetadataAbbrev, // linkage name
            MetadataAbbrev, // file
            LineAbbrev, // line
            MetadataAbbrev, // type
            .{ .fixed = 1 }, // local
            .{ .literal = 1 }, // defined
            .{ .literal = 0 }, // static data members declaration
            .{ .literal = 0 }, // template params
            .{ .literal = 0 }, // align in bits
            .{ .literal = 0 }, // annotations
        };

        scope: Builder.Metadata,
        name: Builder.MetadataString,
        linkage_name: Builder.MetadataString,
        file: Builder.Metadata,
        line: u32,
        ty: Builder.Metadata,
        local: bool,
    };

    pub const GlobalVarExpression = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.GLOBAL_VAR_EXPR) },
            .{ .literal = 0 }, // is distinct
            MetadataAbbrev, // variable
            MetadataAbbrev, // expression
        };

        variable: Builder.Metadata,
        expression: Builder.Metadata,
    };

    pub const Constant = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.VALUE) },
            MetadataAbbrev, // type
            MetadataAbbrev, // value
        };

        ty: Builder.Type,
        constant: Builder.Constant,
    };

    pub const Name = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.NAME) },
            .{ .array_fixed = 8 }, // name
        };

        name: []const u8,
    };

    pub const NamedNode = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.NAMED_NODE) },
            MetadataArrayAbbrev, // elements
        };

        elements: []const Builder.Metadata,
    };

    pub const GlobalDeclAttachment = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = @intFromEnum(MetadataCode.GLOBAL_DECL_ATTACHMENT) },
            ValueAbbrev, // value id
            .{ .fixed = 1 }, // kind
            MetadataAbbrev, // elements
        };

        value: Builder.Constant,
        kind: FixedMetadataKind,
        metadata: Builder.Metadata,
    };
};

pub const OperandBundleTags = struct {
    pub const id = 21;

    pub const abbrevs = [_]type{OperandBundleTag};

    pub const OperandBundleTag = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 1 },
            .array_char6,
        };
        tag: []const u8,
    };
};

pub const FunctionMetadataBlock = struct {
    pub const id = 15;

    pub const abbrevs = [_]type{
        Value,
    };

    pub const Value = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            .{ .fixed = 32 }, // variable
            .{ .fixed = 32 }, // expression
        };

        ty: Builder.Type,
        value: Builder.Value,
    };
};

pub const FunctionBlock = struct {
    pub const id = 12;

    pub const abbrevs = [_]type{
        DeclareBlocks,
        Call,
        CallFast,
        FNeg,
        FNegFast,
        Binary,
        BinaryNoWrap,
        BinaryExact,
        BinaryFast,
        Cmp,
        CmpFast,
        Select,
        SelectFast,
        Cast,
        Alloca,
        GetElementPtr,
        ExtractValue,
        InsertValue,
        ExtractElement,
        InsertElement,
        ShuffleVector,
        RetVoid,
        Ret,
        Unreachable,
        Load,
        LoadAtomic,
        Store,
        StoreAtomic,
        BrUnconditional,
        BrConditional,
        VaArg,
        AtomicRmw,
        CmpXchg,
        Fence,
        DebugLoc,
        DebugLocAgain,
        ColdOperandBundle,
        IndirectBr,
    };

    pub const DeclareBlocks = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 1 },
            .{ .vbr = 8 },
        };
        num_blocks: usize,
    };

    pub const Call = struct {
        pub const CallType = packed struct(u17) {
            tail: bool = false,
            call_conv: Builder.CallConv,
            reserved: u3 = 0,
            must_tail: bool = false,
            // We always use the explicit type version as that is what LLVM does
            explicit_type: bool = true,
            no_tail: bool = false,
        };
        pub const ops = [_]AbbrevOp{
            .{ .literal = 34 },
            .{ .fixed_runtime = Builder.FunctionAttributes },
            .{ .fixed = @bitSizeOf(CallType) },
            .{ .fixed_runtime = Builder.Type },
            ValueAbbrev, // Callee
            ValueArrayAbbrev, // Args
        };

        attributes: Builder.FunctionAttributes,
        call_type: CallType,
        type_id: Builder.Type,
        callee: Builder.Value,
        args: []const Builder.Value,
    };

    pub const CallFast = struct {
        const CallType = packed struct(u18) {
            tail: bool = false,
            call_conv: Builder.CallConv,
            reserved: u3 = 0,
            must_tail: bool = false,
            // We always use the explicit type version as that is what LLVM does
            explicit_type: bool = true,
            no_tail: bool = false,
            fast: bool = true,
        };

        pub const ops = [_]AbbrevOp{
            .{ .literal = 34 },
            .{ .fixed_runtime = Builder.FunctionAttributes },
            .{ .fixed = @bitSizeOf(CallType) },
            .{ .fixed = @bitSizeOf(Builder.FastMath) },
            .{ .fixed_runtime = Builder.Type },
            ValueAbbrev, // Callee
            ValueArrayAbbrev, // Args
        };

        attributes: Builder.FunctionAttributes,
        call_type: CallType,
        fast_math: Builder.FastMath,
        type_id: Builder.Type,
        callee: Builder.Value,
        args: []const Builder.Value,
    };

    pub const FNeg = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 56 },
            ValueAbbrev,
            .{ .literal = 0 },
        };

        val: u32,
    };

    pub const FNegFast = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 56 },
            ValueAbbrev,
            .{ .literal = 0 },
            .{ .fixed = @bitSizeOf(Builder.FastMath) },
        };

        val: u32,
        fast_math: Builder.FastMath,
    };

    pub const Binary = struct {
        const BinaryOpcode = Builder.BinaryOpcode;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(BinaryOpcode) },
        };

        lhs: u32,
        rhs: u32,
        opcode: BinaryOpcode,
    };

    pub const BinaryNoWrap = struct {
        const BinaryOpcode = Builder.BinaryOpcode;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(BinaryOpcode) },
            .{ .fixed = 2 },
        };

        lhs: u32,
        rhs: u32,
        opcode: BinaryOpcode,
        flags: packed struct(u2) {
            no_unsigned_wrap: bool,
            no_signed_wrap: bool,
        },
    };

    pub const BinaryExact = struct {
        const BinaryOpcode = Builder.BinaryOpcode;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(BinaryOpcode) },
            .{ .literal = 1 },
        };

        lhs: u32,
        rhs: u32,
        opcode: BinaryOpcode,
    };

    pub const BinaryFast = struct {
        const BinaryOpcode = Builder.BinaryOpcode;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(BinaryOpcode) },
            .{ .fixed = @bitSizeOf(Builder.FastMath) },
        };

        lhs: u32,
        rhs: u32,
        opcode: BinaryOpcode,
        fast_math: Builder.FastMath,
    };

    pub const Cmp = struct {
        const CmpPredicate = Builder.CmpPredicate;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 28 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(CmpPredicate) },
        };

        lhs: u32,
        rhs: u32,
        pred: CmpPredicate,
    };

    pub const CmpFast = struct {
        const CmpPredicate = Builder.CmpPredicate;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 28 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(CmpPredicate) },
            .{ .fixed = @bitSizeOf(Builder.FastMath) },
        };

        lhs: u32,
        rhs: u32,
        pred: CmpPredicate,
        fast_math: Builder.FastMath,
    };

    pub const Select = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 29 },
            ValueAbbrev,
            ValueAbbrev,
            ValueAbbrev,
        };

        lhs: u32,
        rhs: u32,
        cond: u32,
    };

    pub const SelectFast = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 29 },
            ValueAbbrev,
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(Builder.FastMath) },
        };

        lhs: u32,
        rhs: u32,
        cond: u32,
        fast_math: Build```
