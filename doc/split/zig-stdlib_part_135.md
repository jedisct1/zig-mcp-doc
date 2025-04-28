```
            .trunc,
                    .uitofp,
                    .zext,
                    => {
                        const extra = self.extraData(Instruction.Cast, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.Cast{
                            .val = instructions.map(extra.val),
                            .type = extra.type,
                        });
                    },
                    .alloca,
                    .@"alloca inalloca",
                    => {
                        const extra = self.extraData(Instruction.Alloca, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.Alloca{
                            .type = extra.type,
                            .len = instructions.map(extra.len),
                            .info = extra.info,
                        });
                    },
                    .arg,
                    .block,
                    => unreachable,
                    .atomicrmw => {
                        const extra = self.extraData(Instruction.AtomicRmw, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.AtomicRmw{
                            .info = extra.info,
                            .ptr = instructions.map(extra.ptr),
                            .val = instructions.map(extra.val),
                        });
                    },
                    .br,
                    .fence,
                    .@"ret void",
                    .@"unreachable",
                    => {},
                    .br_cond => {
                        const extra = self.extraData(Instruction.BrCond, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.BrCond{
                            .cond = instructions.map(extra.cond),
                            .then = extra.then,
                            .@"else" = extra.@"else",
                            .weights = extra.weights,
                        });
                    },
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => {
                        var extra = self.extraDataTrail(Instruction.Call, instruction.data);
                        const args = extra.trail.next(extra.data.args_len, Value, self);
                        instruction.data = wip_extra.addExtra(Instruction.Call{
                            .info = extra.data.info,
                            .attributes = extra.data.attributes,
                            .ty = extra.data.ty,
                            .callee = instructions.map(extra.data.callee),
                            .args_len = extra.data.args_len,
                        });
                        wip_extra.appendMappedValues(args, instructions);
                    },
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => {
                        const extra = self.extraData(Instruction.CmpXchg, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.CmpXchg{
                            .info = extra.info,
                            .ptr = instructions.map(extra.ptr),
                            .cmp = instructions.map(extra.cmp),
                            .new = instructions.map(extra.new),
                        });
                    },
                    .extractelement => {
                        const extra = self.extraData(Instruction.ExtractElement, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.ExtractElement{
                            .val = instructions.map(extra.val),
                            .index = instructions.map(extra.index),
                        });
                    },
                    .extractvalue => {
                        var extra = self.extraDataTrail(Instruction.ExtractValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, self);
                        instruction.data = wip_extra.addExtra(Instruction.ExtractValue{
                            .val = instructions.map(extra.data.val),
                            .indices_len = extra.data.indices_len,
                        });
                        wip_extra.appendSlice(indices);
                    },
                    .fneg,
                    .@"fneg fast",
                    .ret,
                    => instruction.data = @intFromEnum(instructions.map(@enumFromInt(instruction.data))),
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = self.extraDataTrail(Instruction.GetElementPtr, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, Value, self);
                        instruction.data = wip_extra.addExtra(Instruction.GetElementPtr{
                            .type = extra.data.type,
                            .base = instructions.map(extra.data.base),
                            .indices_len = extra.data.indices_len,
                        });
                        wip_extra.appendMappedValues(indices, instructions);
                    },
                    .indirectbr => {
                        var extra = self.extraDataTrail(Instruction.IndirectBr, instruction.data);
                        const targets = extra.trail.next(extra.data.targets_len, Block.Index, self);
                        instruction.data = wip_extra.addExtra(Instruction.IndirectBr{
                            .addr = instructions.map(extra.data.addr),
                            .targets_len = extra.data.targets_len,
                        });
                        wip_extra.appendSlice(targets);
                    },
                    .insertelement => {
                        const extra = self.extraData(Instruction.InsertElement, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.InsertElement{
                            .val = instructions.map(extra.val),
                            .elem = instructions.map(extra.elem),
                            .index = instructions.map(extra.index),
                        });
                    },
                    .insertvalue => {
                        var extra = self.extraDataTrail(Instruction.InsertValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, self);
                        instruction.data = wip_extra.addExtra(Instruction.InsertValue{
                            .val = instructions.map(extra.data.val),
                            .elem = instructions.map(extra.data.elem),
                            .indices_len = extra.data.indices_len,
                        });
                        wip_extra.appendSlice(indices);
                    },
                    .load,
                    .@"load atomic",
                    => {
                        const extra = self.extraData(Instruction.Load, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.Load{
                            .type = extra.type,
                            .ptr = instructions.map(extra.ptr),
                            .info = extra.info,
                        });
                    },
                    .phi,
                    .@"phi fast",
                    => {
                        const incoming_len = current_block.incoming;
                        var extra = self.extraDataTrail(Instruction.Phi, instruction.data);
                        const incoming_vals = extra.trail.next(incoming_len, Value, self);
                        const incoming_blocks = extra.trail.next(incoming_len, Block.Index, self);
                        instruction.data = wip_extra.addExtra(Instruction.Phi{
                            .type = extra.data.type,
                        });
                        wip_extra.appendMappedValues(incoming_vals, instructions);
                        wip_extra.appendSlice(incoming_blocks);
                    },
                    .select,
                    .@"select fast",
                    => {
                        const extra = self.extraData(Instruction.Select, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.Select{
                            .cond = instructions.map(extra.cond),
                            .lhs = instructions.map(extra.lhs),
                            .rhs = instructions.map(extra.rhs),
                        });
                    },
                    .shufflevector => {
                        const extra = self.extraData(Instruction.ShuffleVector, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.ShuffleVector{
                            .lhs = instructions.map(extra.lhs),
                            .rhs = instructions.map(extra.rhs),
                            .mask = instructions.map(extra.mask),
                        });
                    },
                    .store,
                    .@"store atomic",
                    => {
                        const extra = self.extraData(Instruction.Store, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.Store{
                            .val = instructions.map(extra.val),
                            .ptr = instructions.map(extra.ptr),
                            .info = extra.info,
                        });
                    },
                    .@"switch" => {
                        var extra = self.extraDataTrail(Instruction.Switch, instruction.data);
                        const case_vals = extra.trail.next(extra.data.cases_len, Constant, self);
                        const case_blocks = extra.trail.next(extra.data.cases_len, Block.Index, self);
                        instruction.data = wip_extra.addExtra(Instruction.Switch{
                            .val = instructions.map(extra.data.val),
                            .default = extra.data.default,
                            .cases_len = extra.data.cases_len,
                            .weights = extra.data.weights,
                        });
                        wip_extra.appendSlice(case_vals);
                        wip_extra.appendSlice(case_blocks);
                    },
                    .va_arg => {
                        const extra = self.extraData(Instruction.VaArg, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.VaArg{
                            .list = instructions.map(extra.list),
                            .type = extra.type,
                        });
                    },
                }
                function.instructions.appendAssumeCapacity(instruction);
                names[@intFromEnum(new_instruction_index)] = try wip_name.map(if (self.strip)
                    if (old_instruction_index.hasResultWip(self)) .empty else .none
                else
                    self.names.items[@intFromEnum(old_instruction_index)], ".");

                if (self.debug_locations.get(old_instruction_index)) |location| {
                    debug_locations.putAssumeCapacity(new_instruction_index, location);
                }

                if (self.debug_values.getIndex(old_instruction_index)) |index| {
                    debug_values[index] = new_instruction_index;
                }

                value_indices[@intFromEnum(new_instruction_index)] = value_index;
                if (old_instruction_index.hasResultWip(self)) value_index += 1;
            }
        }

        assert(function.instructions.len == final_instructions_len);
        function.extra = wip_extra.finish();
        function.blocks = blocks;
        function.names = names.ptr;
        function.value_indices = value_indices.ptr;
        function.strip = self.strip;
        function.debug_locations = debug_locations;
        function.debug_values = debug_values;
    }

    pub fn deinit(self: *WipFunction) void {
        self.extra.deinit(self.builder.gpa);
        self.debug_values.deinit(self.builder.gpa);
        self.debug_locations.deinit(self.builder.gpa);
        self.names.deinit(self.builder.gpa);
        self.instructions.deinit(self.builder.gpa);
        for (self.blocks.items) |*b| b.instructions.deinit(self.builder.gpa);
        self.blocks.deinit(self.builder.gpa);
        self.* = undefined;
    }

    fn cmpTag(
        self: *WipFunction,
        tag: Instruction.Tag,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .@"fcmp false",
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
            => assert(lhs.typeOfWip(self) == rhs.typeOfWip(self)),
            else => unreachable,
        }
        _ = try lhs.typeOfWip(self).changeScalar(.i1, self.builder);
        try self.ensureUnusedExtraCapacity(1, Instruction.Binary, 0);
        const instruction = try self.addInst(name, .{
            .tag = tag,
            .data = self.addExtraAssumeCapacity(Instruction.Binary{
                .lhs = lhs,
                .rhs = rhs,
            }),
        });
        return instruction.toValue();
    }

    fn phiTag(
        self: *WipFunction,
        tag: Instruction.Tag,
        ty: Type,
        name: []const u8,
    ) Allocator.Error!WipPhi {
        switch (tag) {
            .phi, .@"phi fast" => assert(try ty.isSized(self.builder)),
            else => unreachable,
        }
        const incoming = self.cursor.block.ptrConst(self).incoming;
        assert(incoming > 0);
        try self.ensureUnusedExtraCapacity(1, Instruction.Phi, incoming * 2);
        const instruction = try self.addInst(name, .{
            .tag = tag,
            .data = self.addExtraAssumeCapacity(Instruction.Phi{ .type = ty }),
        });
        _ = self.extra.addManyAsSliceAssumeCapacity(incoming * 2);
        return .{ .block = self.cursor.block, .instruction = instruction };
    }

    fn selectTag(
        self: *WipFunction,
        tag: Instruction.Tag,
        cond: Value,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .select, .@"select fast" => {
                assert(cond.typeOfWip(self).scalarType(self.builder) == .i1);
                assert(lhs.typeOfWip(self) == rhs.typeOfWip(self));
            },
            else => unreachable,
        }
        try self.ensureUnusedExtraCapacity(1, Instruction.Select, 0);
        const instruction = try self.addInst(name, .{
            .tag = tag,
            .data = self.addExtraAssumeCapacity(Instruction.Select{
                .cond = cond,
                .lhs = lhs,
                .rhs = rhs,
            }),
        });
        return instruction.toValue();
    }

    fn ensureUnusedExtraCapacity(
        self: *WipFunction,
        count: usize,
        comptime Extra: type,
        trail_len: usize,
    ) Allocator.Error!void {
        try self.extra.ensureUnusedCapacity(
            self.builder.gpa,
            count * (@typeInfo(Extra).@"struct".fields.len + trail_len),
        );
    }

    fn addInst(
        self: *WipFunction,
        name: ?[]const u8,
        instruction: Instruction,
    ) Allocator.Error!Instruction.Index {
        const block_instructions = &self.cursor.block.ptr(self).instructions;
        try self.instructions.ensureUnusedCapacity(self.builder.gpa, 1);
        if (!self.strip) {
            try self.names.ensureUnusedCapacity(self.builder.gpa, 1);
            try self.debug_locations.ensureUnusedCapacity(self.builder.gpa, 1);
        }
        try block_instructions.ensureUnusedCapacity(self.builder.gpa, 1);
        const final_name = if (name) |n|
            if (self.strip) .empty else try self.builder.string(n)
        else
            .none;

        const index: Instruction.Index = @enumFromInt(self.instructions.len);
        self.instructions.appendAssumeCapacity(instruction);
        if (!self.strip) {
            self.names.appendAssumeCapacity(final_name);
            if (block_instructions.items.len == 0 or
                !std.meta.eql(self.debug_location, self.prev_debug_location))
            {
                self.debug_locations.putAssumeCapacity(index, self.debug_location);
                self.prev_debug_location = self.debug_location;
            }
        }
        block_instructions.insertAssumeCapacity(self.cursor.instruction, index);
        self.cursor.instruction += 1;
        return index;
    }

    fn addExtraAssumeCapacity(self: *WipFunction, extra: anytype) Instruction.ExtraIndex {
        const result: Instruction.ExtraIndex = @intCast(self.extra.items.len);
        inline for (@typeInfo(@TypeOf(extra)).@"struct".fields) |field| {
            const value = @field(extra, field.name);
            self.extra.appendAssumeCapacity(switch (field.type) {
                u32 => value,
                Alignment,
                AtomicOrdering,
                Block.Index,
                FunctionAttributes,
                Type,
                Value,
                Instruction.BrCond.Weights,
                => @intFromEnum(value),
                MemoryAccessInfo,
                Instruction.Alloca.Info,
                Instruction.Call.Info,
                => @bitCast(value),
                else => @compileError("bad field type: " ++ field.name ++ ": " ++ @typeName(field.type)),
            });
        }
        return result;
    }

    const ExtraDataTrail = struct {
        index: Instruction.ExtraIndex,

        fn nextMut(self: *ExtraDataTrail, len: u32, comptime Item: type, wip: *WipFunction) []Item {
            const items: []Item = @ptrCast(wip.extra.items[self.index..][0..len]);
            self.index += @intCast(len);
            return items;
        }

        fn next(
            self: *ExtraDataTrail,
            len: u32,
            comptime Item: type,
            wip: *const WipFunction,
        ) []const Item {
            const items: []const Item = @ptrCast(wip.extra.items[self.index..][0..len]);
            self.index += @intCast(len);
            return items;
        }
    };

    fn extraDataTrail(
        self: *const WipFunction,
        comptime T: type,
        index: Instruction.ExtraIndex,
    ) struct { data: T, trail: ExtraDataTrail } {
        var result: T = undefined;
        const fields = @typeInfo(T).@"struct".fields;
        inline for (fields, self.extra.items[index..][0..fields.len]) |field, value|
            @field(result, field.name) = switch (field.type) {
                u32 => value,
                Alignment,
                AtomicOrdering,
                Block.Index,
                FunctionAttributes,
                Type,
                Value,
                Instruction.BrCond.Weights,
                => @enumFromInt(value),
                MemoryAccessInfo,
                Instruction.Alloca.Info,
                Instruction.Call.Info,
                => @bitCast(value),
                else => @compileError("bad field type: " ++ field.name ++ ": " ++ @typeName(field.type)),
            };
        return .{
            .data = result,
            .trail = .{ .index = index + @as(Type.Item.ExtraIndex, @intCast(fields.len)) },
        };
    }

    fn extraData(self: *const WipFunction, comptime T: type, index: Instruction.ExtraIndex) T {
        return self.extraDataTrail(T, index).data;
    }
};

pub const FloatCondition = enum(u4) {
    oeq = 1,
    ogt = 2,
    oge = 3,
    olt = 4,
    ole = 5,
    one = 6,
    ord = 7,
    uno = 8,
    ueq = 9,
    ugt = 10,
    uge = 11,
    ult = 12,
    ule = 13,
    une = 14,
};

pub const IntegerCondition = enum(u6) {
    eq = 32,
    ne = 33,
    ugt = 34,
    uge = 35,
    ult = 36,
    ule = 37,
    sgt = 38,
    sge = 39,
    slt = 40,
    sle = 41,
};

pub const MemoryAccessKind = enum(u1) {
    normal,
    @"volatile",

    pub fn format(
        self: MemoryAccessKind,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .normal) try writer.print("{s}{s}", .{ prefix, @tagName(self) });
    }
};

pub const SyncScope = enum(u1) {
    singlethread,
    system,

    pub fn format(
        self: SyncScope,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .system) try writer.print(
            \\{s}syncscope("{s}")
        , .{ prefix, @tagName(self) });
    }
};

pub const AtomicOrdering = enum(u3) {
    none = 0,
    unordered = 1,
    monotonic = 2,
    acquire = 3,
    release = 4,
    acq_rel = 5,
    seq_cst = 6,

    pub fn format(
        self: AtomicOrdering,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .none) try writer.print("{s}{s}", .{ prefix, @tagName(self) });
    }
};

const MemoryAccessInfo = packed struct(u32) {
    access_kind: MemoryAccessKind = .normal,
    atomic_rmw_operation: Function.Instruction.AtomicRmw.Operation = .none,
    sync_scope: SyncScope,
    success_ordering: AtomicOrdering,
    failure_ordering: AtomicOrdering = .none,
    alignment: Alignment = .default,
    _: u13 = undefined,
};

pub const FastMath = packed struct(u8) {
    unsafe_algebra: bool = false, // Legacy
    nnan: bool = false,
    ninf: bool = false,
    nsz: bool = false,
    arcp: bool = false,
    contract: bool = false,
    afn: bool = false,
    reassoc: bool = false,

    pub const fast = FastMath{
        .nnan = true,
        .ninf = true,
        .nsz = true,
        .arcp = true,
        .contract = true,
        .afn = true,
        .reassoc = true,
    };
};

pub const FastMathKind = enum {
    normal,
    fast,

    pub fn toCallKind(self: FastMathKind) Function.Instruction.Call.Kind {
        return switch (self) {
            .normal => .normal,
            .fast => .fast,
        };
    }
};

pub const Constant = enum(u32) {
    false,
    true,
    @"0",
    @"1",
    none,
    no_init = (1 << 30) - 1,
    _,

    const first_global: Constant = @enumFromInt(1 << 29);

    pub const Tag = enum(u7) {
        positive_integer,
        negative_integer,
        half,
        bfloat,
        float,
        double,
        fp128,
        x86_fp80,
        ppc_fp128,
        null,
        none,
        structure,
        packed_structure,
        array,
        string,
        vector,
        splat,
        zeroinitializer,
        undef,
        poison,
        blockaddress,
        dso_local_equivalent,
        no_cfi,
        trunc,
        ptrtoint,
        inttoptr,
        bitcast,
        addrspacecast,
        getelementptr,
        @"getelementptr inbounds",
        add,
        @"add nsw",
        @"add nuw",
        sub,
        @"sub nsw",
        @"sub nuw",
        shl,
        xor,
        @"asm",
        @"asm sideeffect",
        @"asm alignstack",
        @"asm sideeffect alignstack",
        @"asm inteldialect",
        @"asm sideeffect inteldialect",
        @"asm alignstack inteldialect",
        @"asm sideeffect alignstack inteldialect",
        @"asm unwind",
        @"asm sideeffect unwind",
        @"asm alignstack unwind",
        @"asm sideeffect alignstack unwind",
        @"asm inteldialect unwind",
        @"asm sideeffect inteldialect unwind",
        @"asm alignstack inteldialect unwind",
        @"asm sideeffect alignstack inteldialect unwind",

        pub fn toBinaryOpcode(self: Tag) BinaryOpcode {
            return switch (self) {
                .add,
                .@"add nsw",
                .@"add nuw",
                => .add,
                .sub,
                .@"sub nsw",
                .@"sub nuw",
                => .sub,
                .shl => .shl,
                .xor => .xor,
                else => unreachable,
            };
        }

        pub fn toCastOpcode(self: Tag) CastOpcode {
            return switch (self) {
                .trunc => .trunc,
                .ptrtoint => .ptrtoint,
                .inttoptr => .inttoptr,
                .bitcast => .bitcast,
                .addrspacecast => .addrspacecast,
                else => unreachable,
            };
        }
    };

    pub const Item = struct {
        tag: Tag,
        data: ExtraIndex,

        const ExtraIndex = u32;
    };

    pub const Integer = packed struct(u64) {
        type: Type,
        limbs_len: u32,

        pub const limbs = @divExact(@bitSizeOf(Integer), @bitSizeOf(std.math.big.Limb));
    };

    pub const Double = struct {
        lo: u32,
        hi: u32,
    };

    pub const Fp80 = struct {
        lo_lo: u32,
        lo_hi: u32,
        hi: u32,
    };

    pub const Fp128 = struct {
        lo_lo: u32,
        lo_hi: u32,
        hi_lo: u32,
        hi_hi: u32,
    };

    pub const Aggregate = struct {
        type: Type,
        //fields: [type.aggregateLen(builder)]Constant,
    };

    pub const Splat = extern struct {
        type: Type,
        value: Constant,
    };

    pub const BlockAddress = extern struct {
        function: Function.Index,
        block: Function.Block.Index,
    };

    pub const Cast = extern struct {
        val: Constant,
        type: Type,

        pub const Signedness = enum { unsigned, signed, unneeded };
    };

    pub const GetElementPtr = struct {
        type: Type,
        base: Constant,
        info: Info,
        //indices: [info.indices_len]Constant,

        pub const Kind = enum { normal, inbounds };
        pub const InRangeIndex = enum(u16) { none = std.math.maxInt(u16), _ };
        pub const Info = packed struct(u32) { indices_len: u16, inrange: InRangeIndex };
    };

    pub const Binary = extern struct {
        lhs: Constant,
        rhs: Constant,
    };

    pub const Assembly = extern struct {
        type: Type,
        assembly: String,
        constraints: String,

        pub const Info = packed struct {
            sideeffect: bool = false,
            alignstack: bool = false,
            inteldialect: bool = false,
            unwind: bool = false,
        };
    };

    pub fn unwrap(self: Constant) union(enum) {
        constant: u30,
        global: Global.Index,
    } {
        return if (@intFromEnum(self) < @intFromEnum(first_global))
            .{ .constant = @intCast(@intFromEnum(self)) }
        else
            .{ .global = @enumFromInt(@intFromEnum(self) - @intFromEnum(first_global)) };
    }

    pub fn toValue(self: Constant) Value {
        return @enumFromInt(Value.first_constant + @intFromEnum(self));
    }

    pub fn typeOf(self: Constant, builder: *Builder) Type {
        switch (self.unwrap()) {
            .constant => |constant| {
                const item = builder.constant_items.get(constant);
                return switch (item.tag) {
                    .positive_integer,
                    .negative_integer,
                    => @as(
                        *align(@alignOf(std.math.big.Limb)) Integer,
                        @ptrCast(builder.constant_limbs.items[item.data..][0..Integer.limbs]),
                    ).type,
                    .half => .half,
                    .bfloat => .bfloat,
                    .float => .float,
                    .double => .double,
                    .fp128 => .fp128,
                    .x86_fp80 => .x86_fp80,
                    .ppc_fp128 => .ppc_fp128,
                    .null,
                    .none,
                    .zeroinitializer,
                    .undef,
                    .poison,
                    => @enumFromInt(item.data),
                    .structure,
                    .packed_structure,
                    .array,
                    .vector,
                    => builder.constantExtraData(Aggregate, item.data).type,
                    .splat => builder.constantExtraData(Splat, item.data).type,
                    .string => builder.arrayTypeAssumeCapacity(
                        @as(String, @enumFromInt(item.data)).slice(builder).?.len,
                        .i8,
                    ),
                    .blockaddress => builder.ptrTypeAssumeCapacity(
                        builder.constantExtraData(BlockAddress, item.data)
                            .function.ptrConst(builder).global.ptrConst(builder).addr_space,
                    ),
                    .dso_local_equivalent,
                    .no_cfi,
                    => builder.ptrTypeAssumeCapacity(@as(Function.Index, @enumFromInt(item.data))
                        .ptrConst(builder).global.ptrConst(builder).addr_space),
                    .trunc,
                    .ptrtoint,
                    .inttoptr,
                    .bitcast,
                    .addrspacecast,
                    => builder.constantExtraData(Cast, item.data).type,
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = builder.constantExtraDataTrail(GetElementPtr, item.data);
                        const indices =
                            extra.trail.next(extra.data.info.indices_len, Constant, builder);
                        const base_ty = extra.data.base.typeOf(builder);
                        if (!base_ty.isVector(builder)) for (indices) |index| {
                            const index_ty = index.typeOf(builder);
                            if (!index_ty.isVector(builder)) continue;
                            return index_ty.changeScalarAssumeCapacity(base_ty, builder);
                        };
                        return base_ty;
                    },
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .shl,
                    .xor,
                    => builder.constantExtraData(Binary, item.data).lhs.typeOf(builder),
                    .@"asm",
                    .@"asm sideeffect",
                    .@"asm alignstack",
                    .@"asm sideeffect alignstack",
                    .@"asm inteldialect",
                    .@"asm sideeffect inteldialect",
                    .@"asm alignstack inteldialect",
                    .@"asm sideeffect alignstack inteldialect",
                    .@"asm unwind",
                    .@"asm sideeffect unwind",
                    .@"asm alignstack unwind",
                    .@"asm sideeffect alignstack unwind",
                    .@"asm inteldialect unwind",
                    .@"asm sideeffect inteldialect unwind",
                    .@"asm alignstack inteldialect unwind",
                    .@"asm sideeffect alignstack inteldialect unwind",
                    => .ptr,
                };
            },
            .global => |global| return builder.ptrTypeAssumeCapacity(
                global.ptrConst(builder).addr_space,
            ),
        }
    }

    pub fn isZeroInit(self: Constant, builder: *const Builder) bool {
        switch (self.unwrap()) {
            .constant => |constant| {
                const item = builder.constant_items.get(constant);
                return switch (item.tag) {
                    .positive_integer => {
                        const extra: *align(@alignOf(std.math.big.Limb)) Integer =
                            @ptrCast(builder.constant_limbs.items[item.data..][0..Integer.limbs]);
                        const limbs = builder.constant_limbs
                            .items[item.data + Integer.limbs ..][0..extra.limbs_len];
                        return std.mem.eql(std.math.big.Limb, limbs, &.{0});
                    },
                    .half, .bfloat, .float => item.data == 0,
                    .double => {
                        const extra = builder.constantExtraData(Constant.Double, item.data);
                        return extra.lo == 0 and extra.hi == 0;
                    },
                    .fp128, .ppc_fp128 => {
                        const extra = builder.constantExtraData(Constant.Fp128, item.data);
                        return extra.lo_lo == 0 and extra.lo_hi == 0 and
                            extra.hi_lo == 0 and extra.hi_hi == 0;
                    },
                    .x86_fp80 => {
                        const extra = builder.constantExtraData(Constant.Fp80, item.data);
                        return extra.lo_lo == 0 and extra.lo_hi == 0 and extra.hi == 0;
                    },
                    .vector => {
                        var extra = builder.constantExtraDataTrail(Aggregate, item.data);
                        const len: u32 = @intCast(extra.data.type.aggregateLen(builder));
                        const vals = extra.trail.next(len, Constant, builder);
                        for (vals) |val| if (!val.isZeroInit(builder)) return false;
                        return true;
                    },
                    .null, .zeroinitializer => true,
                    else => false,
                };
            },
            .global => return false,
        }
    }

    pub fn getBase(self: Constant, builder: *const Builder) Global.Index {
        var cur = self;
        while (true) switch (cur.unwrap()) {
            .constant => |constant| {
                const item = builder.constant_items.get(constant);
                switch (item.tag) {
                    .ptrtoint,
                    .inttoptr,
                    .bitcast,
                    => cur = builder.constantExtraData(Cast, item.data).val,
                    .getelementptr => cur = builder.constantExtraData(GetElementPtr, item.data).base,
                    .add => {
                        const extra = builder.constantExtraData(Binary, item.data);
                        const lhs_base = extra.lhs.getBase(builder);
                        const rhs_base = extra.rhs.getBase(builder);
                        return if (lhs_base != .none and rhs_base != .none)
                            .none
                        else if (lhs_base != .none) lhs_base else rhs_base;
                    },
                    .sub => {
                        const extra = builder.constantExtraData(Binary, item.data);
                        if (extra.rhs.getBase(builder) != .none) return .none;
                        cur = extra.lhs;
                    },
                    else => return .none,
                }
            },
            .global => |global| switch (global.ptrConst(builder).kind) {
                .alias => |alias| cur = alias.ptrConst(builder).aliasee,
                .variable, .function => return global,
                .replaced => unreachable,
            },
        };
    }

    const FormatData = struct {
        constant: Constant,
        builder: *Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (comptime std.mem.indexOfNone(u8, fmt_str, ", %")) |_|
            @compileError("invalid format string: '" ++ fmt_str ++ "'");
        if (comptime std.mem.indexOfScalar(u8, fmt_str, ',') != null) {
            if (data.constant == .no_init) return;
            try writer.writeByte(',');
        }
        if (comptime std.mem.indexOfScalar(u8, fmt_str, ' ') != null) {
            if (data.constant == .no_init) return;
            try writer.writeByte(' ');
        }
        if (comptime std.mem.indexOfScalar(u8, fmt_str, '%') != null)
            try writer.print("{%} ", .{data.constant.typeOf(data.builder).fmt(data.builder)});
        assert(data.constant != .no_init);
        if (std.enums.tagName(Constant, data.constant)) |name| return writer.writeAll(name);
        switch (data.constant.unwrap()) {
            .constant => |constant| {
                const item = data.builder.constant_items.get(constant);
                switch (item.tag) {
                    .positive_integer,
                    .negative_integer,
                    => |tag| {
                        const extra: *align(@alignOf(std.math.big.Limb)) const Integer =
                            @ptrCast(data.builder.constant_limbs.items[item.data..][0..Integer.limbs]);
                        const limbs = data.builder.constant_limbs
                            .items[item.data + Integer.limbs ..][0..extra.limbs_len];
                        const bigint: std.math.big.int.Const = .{
                            .limbs = limbs,
                            .positive = switch (tag) {
                                .positive_integer => true,
                                .negative_integer => false,
                                else => unreachable,
                            },
                        };
                        const ExpectedContents = extern struct {
                            const expected_limbs = @divExact(512, @bitSizeOf(std.math.big.Limb));
                            string: [
                                (std.math.big.int.Const{
                                    .limbs = &([1]std.math.big.Limb{
                                        std.math.maxInt(std.math.big.Limb),
                                    } ** expected_limbs),
                                    .positive = false,
                                }).sizeInBaseUpperBound(10)
                            ]u8,
                            limbs: [
                                std.math.big.int.calcToStringLimbsBufferLen(expected_limbs, 10)
                            ]std.math.big.Limb,
                        };
                        var stack align(@alignOf(ExpectedContents)) =
                            std.heap.stackFallback(@sizeOf(ExpectedContents), data.builder.gpa);
                        const allocator = stack.get();
                        const str = try bigint.toStringAlloc(allocator, 10, undefined);
                        defer allocator.free(str);
                        try writer.writeAll(str);
                    },
                    .half,
                    .bfloat,
                    => |tag| try writer.print("0x{c}{X:0>4}", .{ @as(u8, switch (tag) {
                        .half => 'H',
                        .bfloat => 'R',
                        else => unreachable,
                    }), item.data >> switch (tag) {
                        .half => 0,
                        .bfloat => 16,
                        else => unreachable,
                    } }),
                    .float => {
                        const Float = struct {
                            fn Repr(comptime T: type) type {
                                return packed struct(std.meta.Int(.unsigned, @bitSizeOf(T))) {
                                    mantissa: std.meta.Int(.unsigned, std.math.floatMantissaBits(T)),
                                    exponent: std.meta.Int(.unsigned, std.math.floatExponentBits(T)),
                                    sign: u1,
                                };
                            }
                        };
                        const Mantissa64 = @FieldType(Float.Repr(f64), "mantissa");
                        const Exponent32 = @FieldType(Float.Repr(f32), "exponent");
                        const Exponent64 = @FieldType(Float.Repr(f64), "exponent");

                        const repr: Float.Repr(f32) = @bitCast(item.data);
                        const denormal_shift = switch (repr.exponent) {
                            std.math.minInt(Exponent32) => @as(
                                std.math.Log2Int(Mantissa64),
                                @clz(repr.mantissa),
                            ) + 1,
                            else => 0,
                        };
                        try writer.print("0x{X:0>16}", .{@as(u64, @bitCast(Float.Repr(f64){
                            .mantissa = std.math.shl(
                                Mantissa64,
                                repr.mantissa,
                                std.math.floatMantissaBits(f64) - std.math.floatMantissaBits(f32) +
                                    denormal_shift,
                            ),
                            .exponent = switch (repr.exponent) {
                                std.math.minInt(Exponent32) => if (repr.mantissa > 0)
                                    @as(Exponent64, std.math.floatExponentMin(f32) +
                                        std.math.floatExponentMax(f64)) - denormal_shift
                                else
                                    std.math.minInt(Exponent64),
                                else => @as(Exponent64, repr.exponent) +
                                    (std.math.floatExponentMax(f64) - std.math.floatExponentMax(f32)),
                                std.math.maxInt(Exponent32) => std.math.maxInt(Exponent64),
                            },
                            .sign = repr.sign,
                        }))});
                    },
                    .double => {
                        const extra = data.builder.constantExtraData(Double, item.data);
                        try writer.print("0x{X:0>8}{X:0>8}", .{ extra.hi, extra.lo });
                    },
                    .fp128,
                    .ppc_fp128,
                    => |tag| {
                        const extra = data.builder.constantExtraData(Fp128, item.data);
                        try writer.print("0x{c}{X:0>8}{X:0>8}{X:0>8}{X:0>8}", .{
                            @as(u8, switch (tag) {
                                .fp128 => 'L',
                                .ppc_fp128 => 'M',
                                else => unreachable,
                            }),
                            extra.lo_hi,
                            extra.lo_lo,
                            extra.hi_hi,
                            extra.hi_lo,
                        });
                    },
                    .x86_fp80 => {
                        const extra = data.builder.constantExtraData(Fp80, item.data);
                        try writer.print("0xK{X:0>4}{X:0>8}{X:0>8}", .{
                            extra.hi, extra.lo_hi, extra.lo_lo,
                        });
                    },
                    .null,
                    .none,
                    .zeroinitializer,
                    .undef,
                    .poison,
                    => |tag| try writer.writeAll(@tagName(tag)),
                    .structure,
                    .packed_structure,
                    .array,
                    .vector,
                    => |tag| {
                        var extra = data.builder.constantExtraDataTrail(Aggregate, item.data);
                        const len: u32 = @intCast(extra.data.type.aggregateLen(data.builder));
                        const vals = extra.trail.next(len, Constant, data.builder);
                        try writer.writeAll(switch (tag) {
                            .structure => "{ ",
                            .packed_structure => "<{ ",
                            .array => "[",
                            .vector => "<",
                            else => unreachable,
                        });
                        for (vals, 0..) |val, index| {
                            if (index > 0) try writer.writeAll(", ");
                            try writer.print("{%}", .{val.fmt(data.builder)});
                        }
                        try writer.writeAll(switch (tag) {
                            .structure => " }",
                            .packed_structure => " }>",
                            .array => "]",
                            .vector => ">",
                            else => unreachable,
                        });
                    },
                    .splat => {
                        const extra = data.builder.constantExtraData(Splat, item.data);
                        const len = extra.type.vectorLen(data.builder);
                        try writer.writeByte('<');
                        for (0..len) |index| {
                            if (index > 0) try writer.writeAll(", ");
                            try writer.print("{%}", .{extra.value.fmt(data.builder)});
                        }
                        try writer.writeByte('>');
                    },
                    .string => try writer.print("c{\"}", .{
                        @as(String, @enumFromInt(item.data)).fmt(data.builder),
                    }),
                    .blockaddress => |tag| {
                        const extra = data.builder.constantExtraData(BlockAddress, item.data);
                        const function = extra.function.ptrConst(data.builder);
                        try writer.print("{s}({}, {})", .{
                            @tagName(tag),
                            function.global.fmt(data.builder),
                            extra.block.toInst(function).fmt(extra.function, data.builder),
                        });
                    },
                    .dso_local_equivalent,
                    .no_cfi,
                    => |tag| {
                        const function: Function.Index = @enumFromInt(item.data);
                        try writer.print("{s} {}", .{
                            @tagName(tag),
                            function.ptrConst(data.builder).global.fmt(data.builder),
                        });
                    },
                    .trunc,
                    .ptrtoint,
                    .inttoptr,
                    .bitcast,
                    .addrspacecast,
                    => |tag| {
                        const extra = data.builder.constantExtraData(Cast, item.data);
                        try writer.print("{s} ({%} to {%})", .{
                            @tagName(tag),
                            extra.val.fmt(data.builder),
                            extra.type.fmt(data.builder),
                        });
                    },
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => |tag| {
                        var extra = data.builder.constantExtraDataTrail(GetElementPtr, item.data);
                        const indices =
                            extra.trail.next(extra.data.info.indices_len, Constant, data.builder);
                        try writer.print("{s} ({%}, {%}", .{
                            @tagName(tag),
                            extra.data.type.fmt(data.builder),
                            extra.data.base.fmt(data.builder),
                        });
                        for (indices) |index| try writer.print(", {%}", .{index.fmt(data.builder)});
                        try writer.writeByte(')');
                    },
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .shl,
                    .xor,
                    => |tag| {
                        const extra = data.builder.constantExtraData(Binary, item.data);
                        try writer.print("{s} ({%}, {%})", .{
                            @tagName(tag),
                            extra.lhs.fmt(data.builder),
                            extra.rhs.fmt(data.builder),
                        });
                    },
                    .@"asm",
                    .@"asm sideeffect",
                    .@"asm alignstack",
                    .@"asm sideeffect alignstack",
                    .@"asm inteldialect",
                    .@"asm sideeffect inteldialect",
                    .@"asm alignstack inteldialect",
                    .@"asm sideeffect alignstack inteldialect",
                    .@"asm unwind",
                    .@"asm sideeffect unwind",
                    .@"asm alignstack unwind",
                    .@"asm sideeffect alignstack unwind",
                    .@"asm inteldialect unwind",
                    .@"asm sideeffect inteldialect unwind",
                    .@"asm alignstack inteldialect unwind",
                    .@"asm sideeffect alignstack inteldialect unwind",
                    => |tag| {
                        const extra = data.builder.constantExtraData(Assembly, item.data);
                        try writer.print("{s} {\"}, {\"}", .{
                            @tagName(tag),
                            extra.assembly.fmt(data.builder),
                            extra.constraints.fmt(data.builder),
                        });
                    },
                }
            },
            .global => |global| try writer.print("{}", .{global.fmt(data.builder)}),
        }
    }
    pub fn fmt(self: Constant, builder: *Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .constant = self, .builder = builder } };
    }
};

pub const Value = enum(u32) {
    none = std.math.maxInt(u31),
    false = first_constant + @intFromEnum(Constant.false),
    true = first_constant + @intFromEnum(Constant.true),
    @"0" = first_constant + @intFromEnum(Constant.@"0"),
    @"1" = first_constant + @intFromEnum(Constant.@"1"),
    _,

    const first_constant = 1 << 30;
    const first_metadata = 1 << 31;

    pub fn unwrap(self: Value) union(enum) {
        instruction: Function.Instruction.Index,
        constant: Constant,
        metadata: Metadata,
    } {
        return if (@intFromEnum(self) < first_constant)
            .{ .instruction = @enumFromInt(@intFromEnum(self)) }
        else if (@intFromEnum(self) < first_metadata)
            .{ .constant = @enumFromInt(@intFromEnum(self) - first_constant) }
        else
            .{ .metadata = @enumFromInt(@intFromEnum(self) - first_metadata) };
    }

    pub fn typeOfWip(self: Value, wip: *const WipFunction) Type {
        return switch (self.unwrap()) {
            .instruction => |instruction| instruction.typeOfWip(wip),
            .constant => |constant| constant.typeOf(wip.builder),
            .metadata => .metadata,
        };
    }

    pub fn typeOf(self: Value, function: Function.Index, builder: *Builder) Type {
        return switch (self.unwrap()) {
            .instruction => |instruction| instruction.typeOf(function, builder),
            .constant => |constant| constant.typeOf(builder),
            .metadata => .metadata,
        };
    }

    pub fn toConst(self: Value) ?Constant {
        return switch (self.unwrap()) {
            .instruction, .metadata => null,
            .constant => |constant| constant,
        };
    }

    const FormatData = struct {
        value: Value,
        function: Function.Index,
        builder: *Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        fmt_opts: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        switch (data.value.unwrap()) {
            .instruction => |instruction| try Function.Instruction.Index.format(.{
                .instruction = instruction,
                .function = data.function,
                .builder = data.builder,
            }, fmt_str, fmt_opts, writer),
            .constant => |constant| try Constant.format(.{
                .constant = constant,
                .builder = data.builder,
            }, fmt_str, fmt_opts, writer),
            .metadata => unreachable,
        }
    }
    pub fn fmt(self: Value, function: Function.Index, builder: *Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .value = self, .function = function, .builder = builder } };
    }
};

pub const MetadataString = enum(u32) {
    none = 0,
    _,

    pub fn slice(self: MetadataString, builder: *const Builder) []const u8 {
        const index = @intFromEnum(self);
        const start = builder.metadata_string_indices.items[index];
        const end = builder.metadata_string_indices.items[index + 1];
        return builder.metadata_string_bytes.items[start..end];
    }

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: Adapter, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
        pub fn eql(ctx: Adapter, lhs_key: []const u8, _: void, rhs_index: usize) bool {
            const rhs_metadata_string: MetadataString = @enumFromInt(rhs_index);
            return std.mem.eql(u8, lhs_key, rhs_metadata_string.slice(ctx.builder));
        }
    };

    const FormatData = struct {
        metadata_string: MetadataString,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try printEscapedString(data.metadata_string.slice(data.builder), .always_quote, writer);
    }
    fn fmt(self: MetadataString, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .metadata_string = self, .builder = builder } };
    }
};

pub const Metadata = enum(u32) {
    none = 0,
    empty_tuple = 1,
    _,

    const first_forward_reference = 1 << 29;
    const first_local_metadata = 1 << 30;

    pub const Tag = enum(u6) {
        none,
        file,
        compile_unit,
        @"compile_unit optimized",
        subprogram,
        @"subprogram local",
        @"subprogram definition",
        @"subprogram local definition",
        @"subprogram optimized",
        @"subprogram optimized local",
        @"subprogram optimized definition",
        @"subprogram optimized local definition",
        lexical_block,
        location,
        basic_bool_type,
        basic_unsigned_type,
        basic_signed_type,
        basic_float_type,
        composite_struct_type,
        composite_union_type,
        composite_enumeration_type,
        composite_array_type,
        composite_vector_type,
        derived_pointer_type,
        derived_member_type,
        subroutine_type,
        enumerator_unsigned,
        enumerator_signed_positive,
        enumerator_signed_negative,
        subrange,
        tuple,
        str_tuple,
        module_flag,
        expression,
        local_var,
        parameter,
        global_var,
        @"global_var local",
        global_var_expression,
        constant,

        pub fn isInline(tag: Tag) bool {
            return switch (tag) {
                .none,
                .expression,
                .constant,
                => true,
                .file,
                .compile_unit,
                .@"compile_unit optimized",
                .subprogram,
                .@"subprogram local",
                .@"subprogram definition",
                .@"subprogram local definition",
                .@"subprogram optimized",
                .@"subprogram optimized local",
                .@"subprogram optimized definition",
                .@"subprogram optimized local definition",
                .lexical_block,
                .location,
                .basic_bool_type,
                .basic_unsigned_type,
                .basic_signed_type,
                .basic_float_type,
                .composite_struct_type,
                .composite_union_type,
                .composite_enumeration_type,
                .composite_array_type,
                .composite_vector_type,
                .derived_pointer_type,
                .derived_member_type,
                .subroutine_type,
                .enumerator_unsigned,
                .enumerator_signed_positive,
                .enumerator_signed_negative,
                .subrange,
                .tuple,
                .str_tuple,
                .module_flag,
                .local_var,
                .parameter,
                .global_var,
                .@"global_var local",
                .global_var_expression,
                => false,
            };
        }
    };

    pub fn isInline(self: Metadata, builder: *const Builder) bool {
        return builder.metadata_items.items(.tag)[@intFromEnum(self)].isInline();
    }

    pub fn unwrap(self: Metadata, builder: *const Builder) Metadata {
        var metadata = self;
        while (@intFromEnum(metadata) >= Metadata.first_forward_reference and
            @intFromEnum(metadata) < Metadata.first_local_metadata)
        {
            const index = @intFromEnum(metadata) - Metadata.first_forward_reference;
            metadata = builder.metadata_forward_references.items[index];
            assert(metadata != .none);
        }
        return metadata;
    }

    pub const Item = struct {
        tag: Tag,
        data: ExtraIndex,

        const ExtraIndex = u32;
    };

    pub const DIFlags = packed struct(u32) {
        Visibility: enum(u2) { Zero, Private, Protected, Public } = .Zero,
        FwdDecl: bool = false,
        AppleBlock: bool = false,
        ReservedBit4: u1 = 0,
        Virtual: bool = false,
        Artificial: bool = false,
        Explicit: bool = false,
        Prototyped: bool = false,
        ObjcClassComplete: bool = false,
        ObjectPointer: bool = false,
        Vector: bool = false,
        StaticMember: bool = false,
        LValueReference: bool = false,
        RValueReference: bool = false,
        ExportSymbols: bool = false,
        Inheritance: enum(u2) {
            Zero,
            SingleInheritance,
            MultipleInheritance,
            VirtualInheritance,
        } = .Zero,
        IntroducedVirtual: bool = false,
        BitField: bool = false,
        NoReturn: bool = false,
        ReservedBit21: u1 = 0,
        TypePassbyValue: bool = false,
        TypePassbyReference: bool = false,
        EnumClass: bool = false,
        Thunk: bool = false,
        NonTrivial: bool = false,
        BigEndian: bool = false,
        LittleEndian: bool = false,
        AllCallsDescribed: bool = false,
        Unused: u2 = 0,

        pub fn format(
            self: DIFlags,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            var need_pipe = false;
            inline for (@typeInfo(DIFlags).@"struct".fields) |field| {
                switch (@typeInfo(field.type)) {
                    .bool => if (@field(self, field.name)) {
                        if (need_pipe) try writer.writeAll(" | ") else need_pipe = true;
                        try writer.print("DIFlag{s}", .{field.name});
                    },
                    .@"enum" => if (@field(self, field.name) != .Zero) {
                        if (need_pipe) try writer.writeAll(" | ") else need_pipe = true;
                        try writer.print("DIFlag{s}", .{@tagName(@field(self, field.name))});
                    },
                    .int => assert(@field(self, field.name) == 0),
                    else => @compileError("bad field type: " ++ field.name ++ ": " ++
                        @typeName(field.type)),
                }
            }
            if (!need_pipe) try writer.writeByte('0');
        }
    };

    pub const File = struct {
        filename: MetadataString,
        directory: MetadataString,
    };

    pub const CompileUnit = struct {
        pub const Options = struct {
            optimized: bool,
        };

        file: Metadata,
        producer: MetadataString,
        enums: Metadata,
        globals: Metadata,
    };

    pub const Subprogram = struct {
        pub const Options = struct {
            di_flags: DIFlags,
            sp_flags: DISPFlags,
        };

        pub const DISPFlags = packed struct(u32) {
            Virtuality: enum(u2) { Zero, Virtual, PureVirtual } = .Zero,
            LocalToUnit: bool = false,
            Definition: bool = false,
            Optimized: bool = false,
            Pure: bool = false,
            Elemental: bool = false,
            Recursive: bool = false,
            MainSubprogram: bool = false,
            Deleted: bool = false,
            ReservedBit10: u1 = 0,
            ObjCDirect: bool = false,
            Unused: u20 = 0,

            pub fn format(
                self: DISPFlags,
                comptime _: []const u8,
                _: std.fmt.FormatOptions,
                writer: anytype,
            ) @TypeOf(writer).Error!void {
                var need_pipe = false;
                inline for (@typeInfo(DISPFlags).@"struct".fields) |field| {
                    switch (@typeInfo(field.type)) {
                        .bool => if (@field(self, field.name)) {
                            if (need_pipe) try writer.writeAll(" | ") else need_pipe = true;
                            try writer.print("DISPFlag{s}", .{field.name});
                        },
                        .@"enum" => if (@field(self, field.name) != .Zero) {
                            if (need_pipe) try writer.writeAll(" | ") else need_pipe = true;
                            try writer.print("DISPFlag{s}", .{@tagName(@field(self, field.name))});
                        },
                        .int => assert(@field(self, field.name) == 0),
                        else => @compileError("bad field type: " ++ field.name ++ ": " ++
                            @typeName(field.type)),
                    }
                }
                if (!need_pipe) try writer.writeByte('0');
            }
        };

        file: Metadata,
        name: MetadataString,
        linkage_name: MetadataString,
        line: u32,
        scope_line: u32,
        ty: Metadata,
        di_flags: DIFlags,
        compile_unit: Metadata,
    };

    pub const LexicalBlock = struct {
        scope: Metadata,
        file: Metadata,
        line: u32,
        column: u32,
    };

    pub const Location = struct {
        line: u32,
        column: u32,
        scope: Metadata,
        inlined_at: Metadata,
    };

    pub const BasicType = struct {
        name: MetadataString,
        size_in_bits_lo: u32,
        size_in_bits_hi: u32,

        pub fn bitSize(self: BasicType) u64 {
            return @as(u64, self.size_in_bits_hi) << 32 | self.size_in_bits_lo;
        }
    };

    pub const CompositeType = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        underlying_type: Metadata,
        size_in_bits_lo: u32,
        size_in_bits_hi: u32,
        align_in_bits_lo: u32,
        align_in_bits_hi: u32,
        fields_tuple: Metadata,

        pub fn bitSize(self: CompositeType) u64 {
            return @as(u64, self.size_in_bits_hi) << 32 | self.size_in_bits_lo;
        }
        pub fn bitAlign(self: CompositeType) u64 {
            return @as(u64, self.align_in_bits_hi) << 32 | self.align_in_bits_lo;
        }
    };

    pub const DerivedType = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        underlying_type: Metadata,
        size_in_bits_lo: u32,
        size_in_bits_hi: u32,
        align_in_bits_lo: u32,
        align_in_bits_hi: u32,
        offset_in_bits_lo: u32,
        offset_in_bits_hi: u32,

        pub fn bitSize(self: DerivedType) u64 {
            return @as(u64, self.size_in_bits_hi) << 32 | self.size_in_bits_lo;
        }
        pub fn bitAlign(self: DerivedType) u64 {
            return @as(u64, self.align_in_bits_hi) << 32 | self.align_in_bits_lo;
        }
        pub fn bitOffset(self: DerivedType) u64 {
            return @as(u64, self.offset_in_bits_hi) << 32 | self.offset_in_bits_lo;
        }
    };

    pub const SubroutineType = struct {
        types_tuple: Metadata,
    };

    pub const Enumerator = struct {
        name: MetadataString,
        bit_width: u32,
        limbs_index: u32,
        limbs_len: u32,
    };

    pub const Subrange = struct {
        lower_bound: Metadata,
        count: Metadata,
    };

    pub const Expression = struct {
        elements_len: u32,

        // elements: [elements_len]u32
    };

    pub const Tuple = struct {
        elements_len: u32,

        // elements: [elements_len]Metadata
    };

    pub const StrTuple = struct {
        str: MetadataString,
        elements_len: u32,

        // elements: [elements_len]Metadata
    };

    pub const ModuleFlag = struct {
        behavior: Metadata,
        name: MetadataString,
        constant: Metadata,
    };

    pub const LocalVar = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        ty: Metadata,
    };

    pub const Parameter = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        ty: Metadata,
        arg_no: u32,
    };

    pub const GlobalVar = struct {
        pub const Options = struct {
            local: bool,
        };

        name: MetadataString,
        linkage_name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        ty: Metadata,
        variable: Variable.Index,
    };

    pub const GlobalVarExpression = struct {
        variable: Metadata,
        expression: Metadata,
    };

    pub fn toValue(self: Metadata) Value {
        return @enumFromInt(Value.first_metadata + @intFromEnum(self));
    }

    const Formatter = struct {
        builder: *Builder,
        need_comma: bool,
        map: std.AutoArrayHashMapUnmanaged(union(enum) {
            metadata: Metadata,
            debug_location: DebugLocation.Location,
        }, void) = .{},

        const FormatData = struct {
            formatter: *Formatter,
            prefix: []const u8 = "",
            node: Node,

            const Node = union(enum) {
                none,
                @"inline": Metadata,
                index: u32,

                local_value: ValueData,
                local_metadata: ValueData,
                local_inline: Metadata,
                local_index: u32,

                string: MetadataString,
                bool: bool,
                u32: u32,
                u64: u64,
                di_flags: DIFlags,
                sp_flags: Subprogram.DISPFlags,
                raw: []const u8,

                const ValueData = struct {
                    value: Value,
                    function: Function.Index,
                };
            };
        };
        fn format(
            data: FormatData,
            comptime fmt_str: []const u8,
            fmt_opts: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            if (data.node == .none) return;

            const is_specialized = fmt_str.len > 0 and fmt_str[0] == 'S';
            const recurse_fmt_str = if (is_specialized) fmt_str[1..] else fmt_str;

            if (data.formatter.need_comma) try writer.writeAll(", ");
            defer data.formatter.need_comma = true;
            try writer.writeAll(data.prefix);

            const builder = data.formatter.builder;
            switch (data.node) {
                .none => unreachable,
                .@"inline" => |node| {
                    const needed_comma = data.formatter.need_comma;
                    defer data.formatter.need_comma = needed_comma;
                    data.formatter.need_comma = false;

                    const item = builder.metadata_items.get(@intFromEnum(node));
                    switch (item.tag) {
                        .expression => {
                            var extra = builder.metadataExtraDataTrail(Expression, item.data);
                            const elements = extra.trail.next(extra.data.elements_len, u32, builder);
                            try writer.writeAll("!DIExpression(");
                            for (elements) |element| try format(.{
                                .formatter = data.formatter,
                                .node = .{ .u64 = element },
                            }, "%", fmt_opts, writer);
                            try writer.writeByte(')');
                        },
                        .constant => try Constant.format(.{
                            .constant = @enumFromInt(item.data),
                            .builder = builder,
                        }, recurse_fmt_str, fmt_opts, writer),
                        else => unreachable,
                    }
                },
                .index => |node| try writer.print("!{d}", .{node}),
                inline .local_value, .local_metadata => |node, tag| try Value.format(.{
                    .value = node.value,
                    .function = node.function,
                    .builder = builder,
                }, switch (tag) {
                    .local_value => recurse_fmt_str,
                    .local_metadata => "%",
                    else => unreachable,
                }, fmt_opts, writer),
                inline .local_inline, .local_index => |node, tag| {
                    if (comptime std.mem.eql(u8, recurse_fmt_str, "%"))
                        try writer.print("{%} ", .{Type.metadata.fmt(builder)});
                    try format(.{
                        .formatter = data.formatter,
                        .node = @unionInit(FormatData.Node, @tagName(tag)["local_".len..], node),
                    }, "%", fmt_opts, writer);
                },
                .string => |node| try writer.print((if (is_specialized) "" else "!") ++ "{}", .{
                    node.fmt(builder),
                }),
                inline .bool,
                .u32,
                .u64,
                .di_flags,
                .sp_flags,
                => |node| try writer.print("{}", .{node}),
                .raw => |node| try writer.writeAll(node),
            }
        }
        inline fn fmt(formatter: *Formatter, prefix: []const u8, node: anytype) switch (@TypeOf(node)) {
            Metadata => Allocator.Error,
            else => error{},
        }!std.fmt.Formatter(format) {
            const Node = @TypeOf(node);
            const MaybeNode = switch (@typeInfo(Node)) {
                .optional => Node,
                .null => ?noreturn,
                else => ?Node,
            };
            const Some = @typeInfo(MaybeNode).optional.child;
            return .{ .data = .{
                .formatter = formatter,
                .prefix = prefix,
                .node = if (@as(MaybeNode, node)) |some| switch (@typeInfo(Some)) {
                    .@"enum" => |enum_info| switch (Some) {
                        Metadata => switch (some) {
                            .none => .none,
                            else => try formatter.refUnwrapped(some.unwrap(formatter.builder)),
                        },
                        MetadataString => .{ .string = some },
                        else => if (enum_info.is_exhaustive)
                            .{ .raw = @tagName(some) }
                        else
                            @compileError("unknown type to format: " ++ @typeName(Node)),
                    },
                    .enum_literal => .{ .raw = @tagName(some) },
                    .bool => .{ .bool = some },
                    .@"struct" => switch (Some) {
                        DIFlags => .{ .di_flags = some },
                        Subprogram.DISPFlags => .{ .sp_flags = some },
                        else => @compileError("unknown type to format: " ++ @typeName(Node)),
                    },
                    .int, .comptime_int => .{ .u64 = some },
                    .pointer => .{ .raw = some },
                    else => @compileError("unknown type to format: " ++ @typeName(Node)),
                } else switch (@typeInfo(Node)) {
                    .optional, .null => .none,
                    else => unreachable,
                },
            } };
        }
        inline fn fmtLocal(
            formatter: *Formatter,
            prefix: []const u8,
            value: Value,
            function: Function.Index,
        ) Allocator.Error!std.fmt.Formatter(format) {
            return .{ .data = .{
                .formatter = formatter,
                .prefix = prefix,
                .node = switch (value.unwrap()) {
                    .instruction, .constant => .{ .local_value = .{
                        .value = value,
                        .function = function,
                    } },
                    .metadata => |metadata| if (value == .none) .none else node: {
                        const unwrapped = metadata.unwrap(formatter.builder);
                        break :node if (@intFromEnum(unwrapped) >= first_local_metadata)
                            .{ .local_metadata = .{
                                .value = function.ptrConst(formatter.builder).debug_values[
                                    @intFromEnum(unwrapped) - first_local_metadata
                                ].toValue(),
                                .function = function,
                            } }
                        else switch (try formatter.refUnwrapped(unwrapped)) {
                            .@"inline" => |node| .{ .local_inline = node },
                            .index => |node| .{ .local_index = node },
                            else => unreachable,
                        };
                    },
                },
            } };
        }
        fn refUnwrapped(formatter: *Formatter, node: Metadata) Allocator.Error!FormatData.Node {
            assert(node != .none);
            assert(@intFromEnum(node) < first_forward_reference);
            const builder = formatter.builder;
            const unwrapped_metadata = node.unwrap(builder);
            const tag = formatter.builder.metadata_items.items(.tag)[@intFromEnum(unwrapped_metadata)];
            switch (tag) {
                .none => unreachable,
                .expression, .constant => return .{ .@"inline" = unwrapped_metadata },
                else => {
                    assert(!tag.isInline());
                    const gop = try formatter.map.getOrPut(builder.gpa, .{ .metadata = unwrapped_metadata });
                    return .{ .index = @intCast(gop.index) };
                },
            }
        }

        inline fn specialized(
            formatter: *Formatter,
            distinct: enum { @"!", @"distinct !" },
            node: enum {
                DIFile,
                DICompileUnit,
                DISubprogram,
                DILexicalBlock,
                DILocation,
                DIBasicType,
                DICompositeType,
                DIDerivedType,
                DISubroutineType,
                DIEnumerator,
                DISubrange,
                DILocalVariable,
                DIGlobalVariable,
                DIGlobalVariableExpression,
            },
            nodes: anytype,
            writer: anytype,
        ) !void {
            comptime var fmt_str: []const u8 = "";
            const names = comptime std.meta.fieldNames(@TypeOf(nodes));
            comptime var fields: [2 + names.len]std.builtin.Type.StructField = undefined;
            inline for (fields[0..2], .{ "distinct", "node" }) |*field, name| {
                fmt_str = fmt_str ++ "{[" ++ name ++ "]s}";
                field.* = .{
                    .name = name,
                    .type = []const u8,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = 0,
                };
            }
            fmt_str = fmt_str ++ "(";
            inline for (fields[2..], names) |*field, name| {
                fmt_str = fmt_str ++ "{[" ++ name ++ "]S}";
                field.* = .{
                    .name = name,
                    .type = std.fmt.Formatter(format),
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = 0,
                };
            }
            fmt_str = fmt_str ++ ")\n";

            var fmt_args: @Type(.{ .@"struct" = .{
                .layout = .auto,
                .fields = &fields,
                .decls = &.{},
                .is_tuple = false,
            } }) = undefined;
            fmt_args.distinct = @tagName(distinct);
            fmt_args.node = @tagName(node);
            inline for (names) |name| @field(fmt_args, name) = try formatter.fmt(
                name ++ ": ",
                @field(nodes, name),
            );
            try writer.print(fmt_str, fmt_args);
        }
    };
};

pub fn init(options: Options) Allocator.Error!Builder {
    var self: Builder = .{
        .gpa = options.allocator,
        .strip = options.strip,

        .source_filename = .none,
        .data_layout = .none,
        .target_triple = .none,
        .module_asm = .{},

        .string_map = .{},
        .string_indices = .{},
        .string_bytes = .{},

        .types = .{},
        .next_unnamed_type = @enumFromInt(0),
        .next_unique_type_id = .{},
        .type_map = .{},
        .type_items = .{},
        .type_extra = .{},

        .attributes = .{},
        .attributes_map = .{},
        .attributes_indices = .{},
        .attributes_extra = .{},

        .function_attributes_set = .{},

        .globals = .{},
        .next_unnamed_global = @enumFromInt(0),
        .next_replaced_global = .none,
        .next_unique_global_id = .{},
        .aliases = .{},
        .variables = .{},
        .functions = .{},

        .strtab_string_map = .{},
        .strtab_string_indices = .{},
        .strtab_string_bytes = .{},

        .constant_map = .{},
        .constant_items = .{},
        .constant_extra = .{},
        .constant_limbs = .{},

        .metadata_map = .{},
        .metadata_items = .{},
        .metadata_extra = .{},
        .metadata_limbs = .{},
        .metadata_forward_references = .{},
        .metadata_named = .{},
        .metadata_string_map = .{},
        .metadata_string_indices = .{},
        .metadata_string_bytes = .{},
    };
    errdefer self.deinit();

    try self.string_indices.append(self.gpa, 0);
    assert(try self.string("") == .empty);

    try self.strtab_string_indices.append(self.gpa, 0);
    assert(try self.strtabString("") == .empty);

    if (options.name.len > 0) self.source_filename = try self.string(options.name);

    if (options.triple.len > 0) {
        self.target_triple = try self.string(options.triple);
    }

    {
        const static_len = @typeInfo(Type).@"enum".fields.len - 1;
        try self.type_map.ensureTotalCapacity(self.gpa, static_len);
        try self.type_items.ensureTotalCapacity(self.gpa, static_len);
        inline for (@typeInfo(Type.Simple).@"enum".fields) |simple_field| {
            const result = self.getOrPutTypeNoExtraAssumeCapacity(
                .{ .tag = .simple, .data = simple_field.value },
            );
            assert(result.new and result.type == @field(Type, simple_field.name));
        }
        inline for (.{ 1, 8, 16, 29, 32, 64, 80, 128 }) |bits|
            assert(self.intTypeAssumeCapacity(bits) ==
                @field(Type, std.fmt.comptimePrint("i{d}", .{bits})));
        inline for (.{ 0, 4 }) |addr_space_index| {
            const addr_space: AddrSpace = @enumFromInt(addr_space_index);
            assert(self.ptrTypeAssumeCapacity(addr_space) ==
                @field(Type, std.fmt.comptimePrint("ptr{ }", .{addr_space})));
        }
    }

    {
        try self.attributes_indices.append(self.gpa, 0);
        assert(try self.attrs(&.{}) == .none);
        assert(try self.fnAttrs(&.{}) == .none);
    }

    assert(try self.intConst(.i1, 0) == .false);
    assert(try self.intConst(.i1, 1) == .true);
    assert(try self.intConst(.i32, 0) == .@"0");
    assert(try self.intConst(.i32, 1) == .@"1");
    assert(try self.noneConst(.token) == .none);

    assert(try self.metadataNone() == .none);
    assert(try self.metadataTuple(&.{}) == .empty_tuple);

    try self.metadata_string_indices.append(self.gpa, 0);
    assert(try self.metadataString("") == .none);

    return self;
}

pub fn clearAndFree(self: *Builder) void {
    self.module_asm.clearAndFree(self.gpa);

    self.string_map.clearAndFree(self.gpa);
    self.string_indices.clearAndFree(self.gpa);
    self.string_bytes.clearAndFree(self.gpa);

    self.types.clearAndFree(self.gpa);
    self.next_unique_type_id.clearAndFree(self.gpa);
    self.type_map.clearAndFree(self.gpa);
    self.type_items.clearAndFree(self.gpa);
    self.type_extra.clearAndFree(self.gpa);

    self.attributes.clearAndFree(self.gpa);
    self.attributes_map.clearAndFree(self.gpa);
    self.attributes_indices.clearAndFree(self.gpa);
    self.attributes_extra.clearAndFree(self.gpa);

    self.function_attributes_set.clearAndFree(self.gpa);

    self.globals.clearAndFree(self.gpa);
    self.next_unique_global_id.clearAndFree(self.gpa);
    self.aliases.clearAndFree(self.gpa);
    self.variables.clearAndFree(self.gpa);
    for (self.functions.items) |*function| function.deinit(self.gpa);
    self.functions.clearAndFree(self.gpa);

    self.strtab_string_map.clearAndFree(self.gpa);
    self.strtab_string_indices.clearAndFree(self.gpa);
    self.strtab_string_bytes.clearAndFree(self.gpa);

    self.constant_map.clearAndFree(self.gpa);
    self.constant_items.shrinkAndFree(self.gpa, 0);
    self.constant_extra.clearAndFree(self.gpa);
    self.constant_limbs.clearAndFree(self.gpa);

    self.metadata_map.clearAndFree(self.gpa);
    self.metadata_items.shrinkAndFree(self.gpa, 0);
    self.metadata_extra.clearAndFree(self.gpa);
    self.metadata_limbs.clearAndFree(self.gpa);
    self.metadata_forward_references.clearAndFree(self.gpa);
    self.metadata_named.clearAndFree(self.gpa);

    self.metadata_string_map.clearAndFree(self.gpa);
    self.metadata_string_indices.clearAndFree(self.gpa);
    self.metadata_string_bytes.clearAndFree(self.gpa);
}

pub fn deinit(self: *Builder) void {
    self.module_asm.deinit(self.gpa);

    self.string_map.deinit(self.gpa);
    self.string_indices.deinit(self.gpa);
    self.string_bytes.deinit(self.gpa);

    self.types.deinit(self.gpa);
    self.next_unique_type_id.deinit(self.gpa);
    self.type_map.deinit(self.gpa);
    self.type_items.deinit(self.gpa);
    self.type_extra.deinit(self.gpa);

    self.attributes.deinit(self.gpa);
    self.attributes_map.deinit(self.gpa);
    self.attributes_indices.deinit(self.gpa);
    self.attributes_extra.deinit(self.gpa);

    self.function_attributes_set.deinit(self.gpa);

    self.globals.deinit(self.gpa);
    self.next_unique_global_id.deinit(self.gpa);
    self.aliases.deinit(self.gpa);
    self.variables.deinit(self.gpa);
    for (self.functions.items) |*function| function.deinit(self.gpa);
    self.functions.deinit(self.gpa);

    self.strtab_string_map.deinit(self.gpa);
    self.strtab_string_indices.deinit(self.gpa);
    self.strtab_string_bytes.deinit(self.gpa);

    self.constant_map.deinit(self.gpa);
    self.constant_items.deinit(self.gpa);
    self.constant_extra.deinit(self.gpa);
    self.constant_limbs.deinit(self.gpa);

    self.metadata_map.deinit(self.gpa);
    self.metadata_items.deinit(self.gpa);
    self.metadata_extra.deinit(self.gpa);
    self.metadata_limbs.deinit(self.gpa);
    self.metadata_forward_references.deinit(self.gpa);
    self.metadata_named.deinit(self.gpa);

    self.metadata_string_map.deinit(self.gpa);
    self.metadata_string_indices.deinit(self.gpa);
    self.metadata_string_bytes.deinit(self.gpa);

    self.* = undefined;
}

pub fn setModuleAsm(self: *Builder) std.ArrayListUnmanaged(u8).Writer {
    self.module_asm.clearRetainingCapacity();
    return self.appendModuleAsm();
}

pub fn appendModuleAsm(self: *Builder) std.ArrayListUnmanaged(u8).Writer {
    return self.module_asm.writer(self.gpa);
}

pub fn finishModuleAsm(self: *Builder) Allocator.Error!void {
    if (self.module_asm.getLastOrNull()) |last| if (last != '\n')
        try self.module_asm.append(self.gpa, '\n');
}

pub fn string(self: *Builder, bytes: []const u8) Allocator.Error!String {
    try self.string_bytes.ensureUnusedCapacity(self.gpa, bytes.len);
    try self.string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.string_map.ensureUnusedCapacity(self.gpa, 1);

    const gop = self.string_map.getOrPutAssumeCapacityAdapted(bytes, String.Adapter{ .builder = self });
    if (!gop.found_existing) {
        self.string_bytes.appendSliceAssumeCapacity(bytes);
        self.string_indices.appendAssumeCapacity(@intCast(self.string_bytes.items.len));
    }
    return String.fromIndex(gop.index);
}

pub fn stringNull(self: *Builder, bytes: [:0]const u8) Allocator.Error!String {
    return self.string(bytes[0 .. bytes.len + 1]);
}

pub fn stringIfExists(self: *const Builder, bytes: []const u8) ?String {
    return String.fromIndex(
        self.string_map.getIndexAdapted(bytes, String.Adapter{ .builder = self }) orelse return null,
    );
}

pub fn fmt(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) Allocator.Error!String {
    try self.string_map.ensureUnusedCapacity(self.gpa, 1);
    try self.string_bytes.ensureUnusedCapacity(self.gpa, @intCast(std.fmt.count(fmt_str, fmt_args)));
    try self.string_indices.ensureUnusedCapacity(self.gpa, 1);
    return self.fmtAssumeCapacity(fmt_str, fmt_args);
}

pub fn fmtAssumeCapacity(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) String {
    self.string_bytes.writer(undefined).print(fmt_str, fmt_args) catch unreachable;
    return self.trailingStringAssumeCapacity();
}

pub fn trailingString(self: *Builder) Allocator.Error!String {
    try self.string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.string_map.ensureUnusedCapacity(self.gpa, 1);
    return self.trailingStringAssumeCapacity();
}

pub fn trailingStringAssumeCapacity(self: *Builder) String {
    const start = self.string_indices.getLast();
    const bytes: []const u8 = self.string_bytes.items[start..];
    const gop = self.string_map.getOrPutAssumeCapacityAdapted(bytes, String.Adapter{ .builder = self });
    if (gop.found_existing) {
        self.string_bytes.shrinkRetainingCapacity(start);
    } else {
        self.string_indices.appendAssumeCapacity(@intCast(self.string_bytes.items.len));
    }
    return String.fromIndex(gop.index);
}

pub fn fnType(
    self: *Builder,
    ret: Type,
    params: []const Type,
    kind: Type.Function.Kind,
) Allocator.Error!Type {
    try self.ensureUnusedTypeCapacity(1, Type.Function, params.len);
    switch (kind) {
        inline else => |comptime_kind| return self.fnTypeAssumeCapacity(ret, params, comptime_kind),
    }
}

pub fn intType(self: *Builder, bits: u24) Allocator.Error!Type {
    try self.ensureUnusedTypeCapacity(1, NoExtra, 0);
    return self.intTypeAssumeCapacity(bits);
}

pub fn ptrType(self: *Builder, addr_space: AddrSpace) Allocator.Error!Type {
    try self.ensureUnusedTypeCapacity(1, NoExtra, 0);
    return self.ptrTypeAssumeCapacity(addr_space);
}

pub fn vectorType(
    self: *Builder,
    kind: Type.Vector.Kind,
    len: u32,
    child: Type,
) Allocator.Error!Type {
    try self.ensureUnusedTypeCapacity(1, Type.Vector, 0);
    switch (kind) {
        inline else => |comptime_kind| return self.vectorTypeAssumeCapacity(comptime_kind, len, child),
    }
}

pub fn arrayType(self: *Builder, len: u64, child: Type) Allocator.Error!Type {
    comptime assert(@sizeOf(Type.Array) >= @sizeOf(Type.Vector));
    try self.ensureUnusedTypeCapacity(1, Type.Array, 0);
    return self.arrayTypeAssumeCapacity(len, child);
}

pub fn structType(
    self: *Builder,
    kind: Type.Structure.Kind,
    fields: []const Type,
) Allocator.Error!Type {
    try self.ensureUnusedTypeCapacity(1, Type.Structure, fields.len);
    switch (kind) {
        inline else => |comptime_kind| return self.structTypeAssumeCapacity(comptime_kind, fields),
    }
}

pub fn opaqueType(self: *Builder, name: String) Allocator.Error!Type {
    try self.string_map.ensureUnusedCapacity(self.gpa, 1);
    if (name.slice(self)) |id| {
        const count: usize = comptime std.fmt.count("{d}", .{std.math.maxInt(u32)});
        try self.string_bytes.ensureUnusedCapacity(self.gpa, id.len + count);
    }
    try self.string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.types.ensureUnusedCapacity(self.gpa, 1);
    try self.next_unique_type_id.ensureUnusedCapacity(self.gpa, 1);
    try self.ensureUnusedTypeCapacity(1, Type.NamedStructure, 0);
    return self.opaqueTypeAssumeCapacity(name);
}

pub fn namedTypeSetBody(
    self: *Builder,
    named_type: Type,
    body_type: Type,
) void {
    const named_item = self.type_items.items[@intFromEnum(named_type)];
    self.type_extra.items[named_item.data + std.meta.fieldIndex(Type.NamedStructure, "body").?] =
        @intFromEnum(body_type);
}

pub fn attr(self: *Builder, attribute: Attribute) Allocator.Error!Attribute.Index {
    try self.attributes.ensureUnusedCapacity(self.gpa, 1);

    const gop = self.attributes.getOrPutAssumeCapacity(attribute.toStorage());
    if (!gop.found_existing) gop.value_ptr.* = {};
    return @enumFromInt(gop.index);
}

pub fn attrs(self: *Builder, attributes: []Attribute.Index) Allocator.Error!Attributes {
    std.sort.heap(Attribute.Index, attributes, self, struct {
        pub fn lessThan(builder: *const Builder, lhs: Attribute.Index, rhs: Attribute.Index) bool {
            const lhs_kind = lhs.getKind(builder);
            const rhs_kind = rhs.getKind(builder);
            assert(lhs_kind != rhs_kind);
            return @intFromEnum(lhs_kind) < @intFromEnum(rhs_kind);
        }
    }.lessThan);
    return @enumFromInt(try self.attrGeneric(@ptrCast(attributes)));
}

pub fn fnAttrs(self: *Builder, fn_attributes: []const Attributes) Allocator.Error!FunctionAttributes {
    try self.function_attributes_set.ensureUnusedCapacity(self.gpa, 1);
    const function_attributes: FunctionAttributes = @enumFromInt(try self.attrGeneric(@ptrCast(
        fn_attributes[0..if (std.mem.lastIndexOfNone(Attributes, fn_attributes, &.{.none})) |last|
            last + 1
        else
            0],
    )));

    _ = self.function_attributes_set.getOrPutAssumeCapacity(function_attributes);
    return function_attributes;
}

pub fn addGlobal(self: *Builder, name: StrtabString, global: Global) Allocator.Error!Global.Index {
    assert(!name.isAnon());
    try self.ensureUnusedTypeCapacity(1, NoExtra, 0);
    try self.ensureUnusedGlobalCapacity(name);
    return self.addGlobalAssumeCapacity(name, global);
}

pub fn addGlobalAssumeCapacity(self: *Builder, name: StrtabString, global: Global) Global.Index {
    _ = self.ptrTypeAssumeCapacity(global.addr_space);
    var id = name;
    if (name == .empty) {
        id = self.next_unnamed_global;
        assert(id != self.next_replaced_global);
        self.next_unnamed_global = @enumFromInt(@intFromEnum(id) + 1);
    }
    while (true) {
        const global_gop = self.globals.getOrPutAssumeCapacity(id);
        if (!global_gop.found_existing) {
            global_gop.value_ptr.* = global;
            const global_index: Global.Index = @enumFromInt(global_gop.index);
            global_index.updateDsoLocal(self);
            return global_index;
        }

        const unique_gop = self.next_unique_global_id.getOrPutAssumeCapacity(name);
        if (!unique_gop.found_existing) unique_gop.value_ptr.* = 2;
        id = self.strtabStringFmtAssumeCapacity("{s}.{d}", .{ name.slice(self).?, unique_gop.value_ptr.* });
        unique_gop.value_ptr.* += 1;
    }
}

pub fn getGlobal(self: *const Builder, name: StrtabString) ?Global.Index {
    return @enumFromInt(self.globals.getIndex(name) orelse return null);
}

pub fn addAlias(
    self: *Builder,
    name: StrtabString,
    ty: Type,
    addr_space: AddrSpace,
    aliasee: Constant,
) Allocator.Error!Alias.Index {
    assert(!name.isAnon());
    try self.ensureUnusedTypeCapacity(1, NoExtra, 0);
    try self.ensureUnusedGlobalCapacity(name);
    try self.aliases.ensureUnusedCapacity(self.gpa, 1);
    return self.addAliasAssumeCapacity(name, ty, addr_space, aliasee);
}

pub fn addAliasAssumeCapacity(
    self: *Builder,
    name: StrtabString,
    ty: Type,
    addr_space: AddrSpace,
    aliasee: Constant,
) Alias.Index {
    const alias_index: Alias.Index = @enumFromInt(self.aliases.items.len);
    self.aliases.appendAssumeCapacity(.{ .global = self.addGlobalAssumeCapacity(name, .{
        .addr_space = addr_space,
        .type = ty,
        .kind = .{ .alias = alias_index },
    }), .aliasee = aliasee });
    return alias_index;
}

pub fn addVariable(
    self: *Builder,
    name: StrtabString,
    ty: Type,
    addr_space: AddrSpace,
) Allocator.Error!Variable.Index {
    assert(!name.isAnon());
    try self.ensureUnusedTypeCapacity(1, NoExtra, 0);
    try self.ensureUnusedGlobalCapacity(name);
    try self.variables.ensureUnusedCapacity(self.gpa, 1);
    return self.addVariableAssumeCapacity(ty, name, addr_space);
}

pub fn addVariableAssumeCapacity(
    self: *Builder,
    ty: Type,
    name: StrtabString,
    addr_space: AddrSpace,
) Variable.Index {
    const variable_index: Variable.Index = @enumFromInt(self.variables.items.len);
    self.variables.appendAssumeCapacity(.{ .global = self.addGlobalAssumeCapacity(name, .{
        .addr_space = addr_space,
        .type = ty,
        .kind = .{ .variable = variable_index },
    }) });
    return variable_index;
}

pub fn addFunction(
    self: *Builder,
    ty: Type,
    name: StrtabString,
    addr_space: AddrSpace,
) Allocator.Error!Function.Index {
    assert(!name.isAnon());
    try self.ensureUnusedTypeCapacity(1, NoExtra, 0);
    try self.ensureUnusedGlobalCapacity(name);
    try self.functions.ensureUnusedCapacity(self.gpa, 1);
    return self.addFunctionAssumeCapacity(ty, name, addr_space);
}

pub fn addFunctionAssumeCapacity(
    self: *Builder,
    ty: Type,
    name: StrtabString,
    addr_space: AddrSpace,
) Function.Index {
    assert(ty.isFunction(self));
    const function_index: Function.Index = @enumFromInt(self.functions.items.len);
    self.functions.appendAssumeCapacity(.{
        .global = self.addGlobalAssumeCapacity(name, .{
            .addr_space = addr_space,
            .type = ty,
            .kind = .{ .function = function_index },
        }),
        .strip = undefined,
    });
    return function_index;
}

pub fn getIntrinsic(
    self: *Builder,
    id: Intrinsic,
    overload: []const Type,
) Allocator.Error!Function.Index {
    const ExpectedContents = extern union {
        attrs: extern struct {
            params: [expected_args_len]Type,
            fn_attrs: [FunctionAttributes.params_index + expected_args_len]Attributes,
            attrs: [expected_attrs_len]Attribute.Index,
            fields: [expected_fields_len]Type,
        },
    };
    var stack align(@max(@alignOf(std.heap.StackFallbackAllocator(0)), @alignOf(ExpectedContents))) =
        std.heap.stackFallback(@sizeOf(ExpectedContents), self.gpa);
    const allocator = stack.get();

    const name = name: {
        const writer = self.strtab_string_bytes.writer(self.gpa);
        try writer.print("llvm.{s}", .{@tagName(id)});
        for (overload) |ty| try writer.print(".{m}", .{ty.fmt(self)});
        break :name try self.trailingStrtabString();
    };
    if (self.getGlobal(name)) |global| return global.ptrConst(self).kind.function;

    const signature = Intrinsic.signatures.get(id);
    const param_types = try allocator.alloc(Type, signature.params.len);
    defer allocator.free(param_types);
    const function_attributes = try allocator.alloc(
        Attributes,
        FunctionAttributes.params_index + (signature.params.len - signature.ret_len),
    );
    defer allocator.free(function_attributes);

    var attributes: struct {
        builder: *Builder,
        list: std.ArrayList(Attribute.Index),

        fn deinit(state: *@This()) void {
            state.list.deinit();
            state.* = undefined;
        }

        fn get(state: *@This(), attributes: []const Attribute) Allocator.Error!Attributes {
            try state.list.resize(attributes.len);
            for (state.list.items, attributes) |*item, attribute|
                item.* = try state.builder.attr(attribute);
            return state.builder.attrs(state.list.items);
        }
    } = .{ .builder = self, .list = std.ArrayList(Attribute.Index).init(allocator) };
    defer attributes.deinit();

    var overload_index: usize = 0;
    function_attributes[FunctionAttributes.function_index] = try attributes.get(signature.attrs);
    function_attributes[FunctionAttributes.return_index] = .none; // needed for void return
    for (0.., param_types, signature.params) |param_index, *param_type, signature_param| {
        switch (signature_param.kind) {
            .type => |ty| param_type.* = ty,
            .overloaded => {
                param_type.* = overload[overload_index];
                overload_index += 1;
            },
            .matches, .matches_scalar, .matches_changed_scalar => {},
        }
        function_attributes[
            if (param_index < signature.ret_len)
                FunctionAttributes.return_index
            else
                FunctionAttributes.params_index + (param_index - signature.ret_len)
        ] = try attributes.get(signature_param.attrs);
    }
    assert(overload_index == overload.len);
    for (param_types, signature.params) |*param_type, signature_param| {
        param_type.* = switch (signature_param.kind) {
            .type, .overloaded => continue,
            .matches => |param_index| param_types[param_index],
            .matches_scalar => |param_index| param_types[param_index].scalarType(self),
            .matches_changed_scalar => |info| try param_types[info.index]
                .changeScalar(info.scalar, self),
        };
    }

    const function_index = try self.addFunction(try self.fnType(switch (signature.ret_len) {
        0 => .void,
        1 => param_types[0],
        else => try self.structType(.normal, param_types[0..signature.ret_len]),
    }, param_types[signature.ret_len..], .normal), name, .default);
    function_index.ptr(self).attributes = try self.fnAttrs(function_attributes);
    return function_index;
}

pub```
