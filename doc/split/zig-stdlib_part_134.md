```
 = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .expect = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"expect.with.probability" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .double }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .assume = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.noundef} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .write } } },
        },
        .@"ssa.copy" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 }, .attrs = &.{.returned} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"type.test" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"type.checked.load" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"type.checked.load.relative" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"arithmetic.fence" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .donothing = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"load.relative" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .argmem = .read } } },
        },
        .sideeffect = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .@"is.constant" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .convergent, .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ptrmask = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"threadlocal.address" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{.nonnull} },
                .{ .kind = .{ .matches = 0 }, .attrs = &.{.nonnull} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .vscale = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"dbg.declare" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"dbg.value" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"amdgcn.workitem.id.x" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workitem.id.y" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workitem.id.z" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workgroup.id.x" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workgroup.id.y" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workgroup.id.z" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.dispatch.ptr" = .{
            .ret_len = 1,
            .params = &.{
                .{
                    .kind = .{ .type = Type.ptr_amdgpu_constant },
                    .attrs = &.{.{ .@"align" = Builder.Alignment.fromByteUnits(4) }},
                },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"nvvm.read.ptx.sreg.tid.x" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },
        .@"nvvm.read.ptx.sreg.tid.y" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },
        .@"nvvm.read.ptx.sreg.tid.z" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },

        .@"nvvm.read.ptx.sreg.ntid.x" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },
        .@"nvvm.read.ptx.sreg.ntid.y" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },
        .@"nvvm.read.ptx.sreg.ntid.z" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },

        .@"nvvm.read.ptx.sreg.ctaid.x" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },
        .@"nvvm.read.ptx.sreg.ctaid.y" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },
        .@"nvvm.read.ptx.sreg.ctaid.z" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nounwind, .readnone },
        },

        .@"wasm.memory.size" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"wasm.memory.grow" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
    });
};

pub const Function = struct {
    global: Global.Index,
    call_conv: CallConv = CallConv.default,
    attributes: FunctionAttributes = .none,
    section: String = .none,
    alignment: Alignment = .default,
    blocks: []const Block = &.{},
    instructions: std.MultiArrayList(Instruction) = .{},
    names: [*]const String = &[0]String{},
    value_indices: [*]const u32 = &[0]u32{},
    strip: bool,
    debug_locations: std.AutoHashMapUnmanaged(Instruction.Index, DebugLocation) = .empty,
    debug_values: []const Instruction.Index = &.{},
    extra: []const u32 = &.{},

    pub const Index = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn ptr(self: Index, builder: *Builder) *Function {
            return &builder.functions.items[@intFromEnum(self)];
        }

        pub fn ptrConst(self: Index, builder: *const Builder) *const Function {
            return &builder.functions.items[@intFromEnum(self)];
        }

        pub fn name(self: Index, builder: *const Builder) StrtabString {
            return self.ptrConst(builder).global.name(builder);
        }

        pub fn rename(self: Index, new_name: StrtabString, builder: *Builder) Allocator.Error!void {
            return self.ptrConst(builder).global.rename(new_name, builder);
        }

        pub fn typeOf(self: Index, builder: *const Builder) Type {
            return self.ptrConst(builder).global.typeOf(builder);
        }

        pub fn toConst(self: Index, builder: *const Builder) Constant {
            return self.ptrConst(builder).global.toConst();
        }

        pub fn toValue(self: Index, builder: *const Builder) Value {
            return self.toConst(builder).toValue();
        }

        pub fn setLinkage(self: Index, linkage: Linkage, builder: *Builder) void {
            return self.ptrConst(builder).global.setLinkage(linkage, builder);
        }

        pub fn setUnnamedAddr(self: Index, unnamed_addr: UnnamedAddr, builder: *Builder) void {
            return self.ptrConst(builder).global.setUnnamedAddr(unnamed_addr, builder);
        }

        pub fn setCallConv(self: Index, call_conv: CallConv, builder: *Builder) void {
            self.ptr(builder).call_conv = call_conv;
        }

        pub fn setAttributes(
            self: Index,
            new_function_attributes: FunctionAttributes,
            builder: *Builder,
        ) void {
            self.ptr(builder).attributes = new_function_attributes;
        }

        pub fn setSection(self: Index, section: String, builder: *Builder) void {
            self.ptr(builder).section = section;
        }

        pub fn setAlignment(self: Index, alignment: Alignment, builder: *Builder) void {
            self.ptr(builder).alignment = alignment;
        }

        pub fn setSubprogram(self: Index, subprogram: Metadata, builder: *Builder) void {
            self.ptrConst(builder).global.setDebugMetadata(subprogram, builder);
        }
    };

    pub const Block = struct {
        instruction: Instruction.Index,

        pub const Index = WipFunction.Block.Index;
    };

    pub const Instruction = struct {
        tag: Tag,
        data: u32,

        pub const Tag = enum(u8) {
            add,
            @"add nsw",
            @"add nuw",
            @"add nuw nsw",
            addrspacecast,
            alloca,
            @"alloca inalloca",
            @"and",
            arg,
            ashr,
            @"ashr exact",
            atomicrmw,
            bitcast,
            block,
            br,
            br_cond,
            call,
            @"call fast",
            cmpxchg,
            @"cmpxchg weak",
            extractelement,
            extractvalue,
            fadd,
            @"fadd fast",
            @"fcmp false",
            @"fcmp fast false",
            @"fcmp fast oeq",
            @"fcmp fast oge",
            @"fcmp fast ogt",
            @"fcmp fast ole",
            @"fcmp fast olt",
            @"fcmp fast one",
            @"fcmp fast ord",
            @"fcmp fast true",
            @"fcmp fast ueq",
            @"fcmp fast uge",
            @"fcmp fast ugt",
            @"fcmp fast ule",
            @"fcmp fast ult",
            @"fcmp fast une",
            @"fcmp fast uno",
            @"fcmp oeq",
            @"fcmp oge",
            @"fcmp ogt",
            @"fcmp ole",
            @"fcmp olt",
            @"fcmp one",
            @"fcmp ord",
            @"fcmp true",
            @"fcmp ueq",
            @"fcmp uge",
            @"fcmp ugt",
            @"fcmp ule",
            @"fcmp ult",
            @"fcmp une",
            @"fcmp uno",
            fdiv,
            @"fdiv fast",
            fence,
            fmul,
            @"fmul fast",
            fneg,
            @"fneg fast",
            fpext,
            fptosi,
            fptoui,
            fptrunc,
            frem,
            @"frem fast",
            fsub,
            @"fsub fast",
            getelementptr,
            @"getelementptr inbounds",
            @"icmp eq",
            @"icmp ne",
            @"icmp sge",
            @"icmp sgt",
            @"icmp sle",
            @"icmp slt",
            @"icmp uge",
            @"icmp ugt",
            @"icmp ule",
            @"icmp ult",
            indirectbr,
            insertelement,
            insertvalue,
            inttoptr,
            load,
            @"load atomic",
            lshr,
            @"lshr exact",
            mul,
            @"mul nsw",
            @"mul nuw",
            @"mul nuw nsw",
            @"musttail call",
            @"musttail call fast",
            @"notail call",
            @"notail call fast",
            @"or",
            phi,
            @"phi fast",
            ptrtoint,
            ret,
            @"ret void",
            sdiv,
            @"sdiv exact",
            select,
            @"select fast",
            sext,
            shl,
            @"shl nsw",
            @"shl nuw",
            @"shl nuw nsw",
            shufflevector,
            sitofp,
            srem,
            store,
            @"store atomic",
            sub,
            @"sub nsw",
            @"sub nuw",
            @"sub nuw nsw",
            @"switch",
            @"tail call",
            @"tail call fast",
            trunc,
            udiv,
            @"udiv exact",
            urem,
            uitofp,
            @"unreachable",
            va_arg,
            xor,
            zext,

            pub fn toBinaryOpcode(self: Tag) BinaryOpcode {
                return switch (self) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .fadd,
                    .@"fadd fast",
                    => .add,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .fsub,
                    .@"fsub fast",
                    => .sub,
                    .sdiv,
                    .@"sdiv exact",
                    .fdiv,
                    .@"fdiv fast",
                    => .sdiv,
                    .fmul,
                    .@"fmul fast",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    => .mul,
                    .srem,
                    .frem,
                    .@"frem fast",
                    => .srem,
                    .udiv,
                    .@"udiv exact",
                    => .udiv,
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    => .shl,
                    .lshr,
                    .@"lshr exact",
                    => .lshr,
                    .ashr,
                    .@"ashr exact",
                    => .ashr,
                    .@"and" => .@"and",
                    .@"or" => .@"or",
                    .xor => .xor,
                    .urem => .urem,
                    else => unreachable,
                };
            }

            pub fn toCastOpcode(self: Tag) CastOpcode {
                return switch (self) {
                    .trunc => .trunc,
                    .zext => .zext,
                    .sext => .sext,
                    .fptoui => .fptoui,
                    .fptosi => .fptosi,
                    .uitofp => .uitofp,
                    .sitofp => .sitofp,
                    .fptrunc => .fptrunc,
                    .fpext => .fpext,
                    .ptrtoint => .ptrtoint,
                    .inttoptr => .inttoptr,
                    .bitcast => .bitcast,
                    .addrspacecast => .addrspacecast,
                    else => unreachable,
                };
            }

            pub fn toCmpPredicate(self: Tag) CmpPredicate {
                return switch (self) {
                    .@"fcmp false",
                    .@"fcmp fast false",
                    => .fcmp_false,
                    .@"fcmp oeq",
                    .@"fcmp fast oeq",
                    => .fcmp_oeq,
                    .@"fcmp oge",
                    .@"fcmp fast oge",
                    => .fcmp_oge,
                    .@"fcmp ogt",
                    .@"fcmp fast ogt",
                    => .fcmp_ogt,
                    .@"fcmp ole",
                    .@"fcmp fast ole",
                    => .fcmp_ole,
                    .@"fcmp olt",
                    .@"fcmp fast olt",
                    => .fcmp_olt,
                    .@"fcmp one",
                    .@"fcmp fast one",
                    => .fcmp_one,
                    .@"fcmp ord",
                    .@"fcmp fast ord",
                    => .fcmp_ord,
                    .@"fcmp true",
                    .@"fcmp fast true",
                    => .fcmp_true,
                    .@"fcmp ueq",
                    .@"fcmp fast ueq",
                    => .fcmp_ueq,
                    .@"fcmp uge",
                    .@"fcmp fast uge",
                    => .fcmp_uge,
                    .@"fcmp ugt",
                    .@"fcmp fast ugt",
                    => .fcmp_ugt,
                    .@"fcmp ule",
                    .@"fcmp fast ule",
                    => .fcmp_ule,
                    .@"fcmp ult",
                    .@"fcmp fast ult",
                    => .fcmp_ult,
                    .@"fcmp une",
                    .@"fcmp fast une",
                    => .fcmp_une,
                    .@"fcmp uno",
                    .@"fcmp fast uno",
                    => .fcmp_uno,
                    .@"icmp eq" => .icmp_eq,
                    .@"icmp ne" => .icmp_ne,
                    .@"icmp sge" => .icmp_sge,
                    .@"icmp sgt" => .icmp_sgt,
                    .@"icmp sle" => .icmp_sle,
                    .@"icmp slt" => .icmp_slt,
                    .@"icmp uge" => .icmp_uge,
                    .@"icmp ugt" => .icmp_ugt,
                    .@"icmp ule" => .icmp_ule,
                    .@"icmp ult" => .icmp_ult,
                    else => unreachable,
                };
            }
        };

        pub const Index = enum(u32) {
            none = std.math.maxInt(u31),
            _,

            pub fn name(self: Instruction.Index, function: *const Function) String {
                return function.names[@intFromEnum(self)];
            }

            pub fn valueIndex(self: Instruction.Index, function: *const Function) u32 {
                return function.value_indices[@intFromEnum(self)];
            }

            pub fn toValue(self: Instruction.Index) Value {
                return @enumFromInt(@intFromEnum(self));
            }

            pub fn isTerminatorWip(self: Instruction.Index, wip: *const WipFunction) bool {
                return switch (wip.instructions.items(.tag)[@intFromEnum(self)]) {
                    .br,
                    .br_cond,
                    .indirectbr,
                    .ret,
                    .@"ret void",
                    .@"switch",
                    .@"unreachable",
                    => true,
                    else => false,
                };
            }

            pub fn hasResultWip(self: Instruction.Index, wip: *const WipFunction) bool {
                return switch (wip.instructions.items(.tag)[@intFromEnum(self)]) {
                    .br,
                    .br_cond,
                    .fence,
                    .indirectbr,
                    .ret,
                    .@"ret void",
                    .store,
                    .@"store atomic",
                    .@"switch",
                    .@"unreachable",
                    .block,
                    => false,
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => self.typeOfWip(wip) != .void,
                    else => true,
                };
            }

            pub fn typeOfWip(self: Instruction.Index, wip: *const WipFunction) Type {
                const instruction = wip.instructions.get(@intFromEnum(self));
                return switch (instruction.tag) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .@"and",
                    .ashr,
                    .@"ashr exact",
                    .fadd,
                    .@"fadd fast",
                    .fdiv,
                    .@"fdiv fast",
                    .fmul,
                    .@"fmul fast",
                    .frem,
                    .@"frem fast",
                    .fsub,
                    .@"fsub fast",
                    .lshr,
                    .@"lshr exact",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    .@"or",
                    .sdiv,
                    .@"sdiv exact",
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .srem,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => wip.extraData(Binary, instruction.data).lhs.typeOfWip(wip),
                    .addrspacecast,
                    .bitcast,
                    .fpext,
                    .fptosi,
                    .fptoui,
                    .fptrunc,
                    .inttoptr,
                    .ptrtoint,
                    .sext,
                    .sitofp,
                    .trunc,
                    .uitofp,
                    .zext,
                    => wip.extraData(Cast, instruction.data).type,
                    .alloca,
                    .@"alloca inalloca",
                    => wip.builder.ptrTypeAssumeCapacity(
                        wip.extraData(Alloca, instruction.data).info.addr_space,
                    ),
                    .arg => wip.function.typeOf(wip.builder)
                        .functionParameters(wip.builder)[instruction.data],
                    .atomicrmw => wip.extraData(AtomicRmw, instruction.data).val.typeOfWip(wip),
                    .block => .label,
                    .br,
                    .br_cond,
                    .fence,
                    .indirectbr,
                    .ret,
                    .@"ret void",
                    .store,
                    .@"store atomic",
                    .@"switch",
                    .@"unreachable",
                    => .none,
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => wip.extraData(Call, instruction.data).ty.functionReturn(wip.builder),
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => wip.builder.structTypeAssumeCapacity(.normal, &.{
                        wip.extraData(CmpXchg, instruction.data).cmp.typeOfWip(wip),
                        .i1,
                    }),
                    .extractelement => wip.extraData(ExtractElement, instruction.data)
                        .val.typeOfWip(wip).childType(wip.builder),
                    .extractvalue => {
                        var extra = wip.extraDataTrail(ExtractValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, wip);
                        return extra.data.val.typeOfWip(wip).childTypeAt(indices, wip.builder);
                    },
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
                    => wip.extraData(Binary, instruction.data).lhs.typeOfWip(wip)
                        .changeScalarAssumeCapacity(.i1, wip.builder),
                    .fneg,
                    .@"fneg fast",
                    => @as(Value, @enumFromInt(instruction.data)).typeOfWip(wip),
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = wip.extraDataTrail(GetElementPtr, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, Value, wip);
                        const base_ty = extra.data.base.typeOfWip(wip);
                        if (!base_ty.isVector(wip.builder)) for (indices) |index| {
                            const index_ty = index.typeOfWip(wip);
                            if (!index_ty.isVector(wip.builder)) continue;
                            return index_ty.changeScalarAssumeCapacity(base_ty, wip.builder);
                        };
                        return base_ty;
                    },
                    .insertelement => wip.extraData(InsertElement, instruction.data).val.typeOfWip(wip),
                    .insertvalue => wip.extraData(InsertValue, instruction.data).val.typeOfWip(wip),
                    .load,
                    .@"load atomic",
                    => wip.extraData(Load, instruction.data).type,
                    .phi,
                    .@"phi fast",
                    => wip.extraData(Phi, instruction.data).type,
                    .select,
                    .@"select fast",
                    => wip.extraData(Select, instruction.data).lhs.typeOfWip(wip),
                    .shufflevector => {
                        const extra = wip.extraData(ShuffleVector, instruction.data);
                        return extra.lhs.typeOfWip(wip).changeLengthAssumeCapacity(
                            extra.mask.typeOfWip(wip).vectorLen(wip.builder),
                            wip.builder,
                        );
                    },
                    .va_arg => wip.extraData(VaArg, instruction.data).type,
                };
            }

            pub fn typeOf(
                self: Instruction.Index,
                function_index: Function.Index,
                builder: *Builder,
            ) Type {
                const function = function_index.ptrConst(builder);
                const instruction = function.instructions.get(@intFromEnum(self));
                return switch (instruction.tag) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .@"and",
                    .ashr,
                    .@"ashr exact",
                    .fadd,
                    .@"fadd fast",
                    .fdiv,
                    .@"fdiv fast",
                    .fmul,
                    .@"fmul fast",
                    .frem,
                    .@"frem fast",
                    .fsub,
                    .@"fsub fast",
                    .lshr,
                    .@"lshr exact",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    .@"or",
                    .sdiv,
                    .@"sdiv exact",
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .srem,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => function.extraData(Binary, instruction.data).lhs.typeOf(function_index, builder),
                    .addrspacecast,
                    .bitcast,
                    .fpext,
                    .fptosi,
                    .fptoui,
                    .fptrunc,
                    .inttoptr,
                    .ptrtoint,
                    .sext,
                    .sitofp,
                    .trunc,
                    .uitofp,
                    .zext,
                    => function.extraData(Cast, instruction.data).type,
                    .alloca,
                    .@"alloca inalloca",
                    => builder.ptrTypeAssumeCapacity(
                        function.extraData(Alloca, instruction.data).info.addr_space,
                    ),
                    .arg => function.global.typeOf(builder)
                        .functionParameters(builder)[instruction.data],
                    .atomicrmw => function.extraData(AtomicRmw, instruction.data)
                        .val.typeOf(function_index, builder),
                    .block => .label,
                    .br,
                    .br_cond,
                    .fence,
                    .indirectbr,
                    .ret,
                    .@"ret void",
                    .store,
                    .@"store atomic",
                    .@"switch",
                    .@"unreachable",
                    => .none,
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => function.extraData(Call, instruction.data).ty.functionReturn(builder),
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => builder.structTypeAssumeCapacity(.normal, &.{
                        function.extraData(CmpXchg, instruction.data)
                            .cmp.typeOf(function_index, builder),
                        .i1,
                    }),
                    .extractelement => function.extraData(ExtractElement, instruction.data)
                        .val.typeOf(function_index, builder).childType(builder),
                    .extractvalue => {
                        var extra = function.extraDataTrail(ExtractValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, function);
                        return extra.data.val.typeOf(function_index, builder)
                            .childTypeAt(indices, builder);
                    },
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
                    => function.extraData(Binary, instruction.data).lhs.typeOf(function_index, builder)
                        .changeScalarAssumeCapacity(.i1, builder),
                    .fneg,
                    .@"fneg fast",
                    => @as(Value, @enumFromInt(instruction.data)).typeOf(function_index, builder),
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = function.extraDataTrail(GetElementPtr, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, Value, function);
                        const base_ty = extra.data.base.typeOf(function_index, builder);
                        if (!base_ty.isVector(builder)) for (indices) |index| {
                            const index_ty = index.typeOf(function_index, builder);
                            if (!index_ty.isVector(builder)) continue;
                            return index_ty.changeScalarAssumeCapacity(base_ty, builder);
                        };
                        return base_ty;
                    },
                    .insertelement => function.extraData(InsertElement, instruction.data)
                        .val.typeOf(function_index, builder),
                    .insertvalue => function.extraData(InsertValue, instruction.data)
                        .val.typeOf(function_index, builder),
                    .load,
                    .@"load atomic",
                    => function.extraData(Load, instruction.data).type,
                    .phi,
                    .@"phi fast",
                    => function.extraData(Phi, instruction.data).type,
                    .select,
                    .@"select fast",
                    => function.extraData(Select, instruction.data).lhs.typeOf(function_index, builder),
                    .shufflevector => {
                        const extra = function.extraData(ShuffleVector, instruction.data);
                        return extra.lhs.typeOf(function_index, builder).changeLengthAssumeCapacity(
                            extra.mask.typeOf(function_index, builder).vectorLen(builder),
                            builder,
                        );
                    },
                    .va_arg => function.extraData(VaArg, instruction.data).type,
                };
            }

            const FormatData = struct {
                instruction: Instruction.Index,
                function: Function.Index,
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
                    if (data.instruction == .none) return;
                    try writer.writeByte(',');
                }
                if (comptime std.mem.indexOfScalar(u8, fmt_str, ' ') != null) {
                    if (data.instruction == .none) return;
                    try writer.writeByte(' ');
                }
                if (comptime std.mem.indexOfScalar(u8, fmt_str, '%') != null) try writer.print(
                    "{%} ",
                    .{data.instruction.typeOf(data.function, data.builder).fmt(data.builder)},
                );
                assert(data.instruction != .none);
                try writer.print("%{}", .{
                    data.instruction.name(data.function.ptrConst(data.builder)).fmt(data.builder),
                });
            }
            pub fn fmt(
                self: Instruction.Index,
                function: Function.Index,
                builder: *Builder,
            ) std.fmt.Formatter(format) {
                return .{ .data = .{ .instruction = self, .function = function, .builder = builder } };
            }
        };

        pub const ExtraIndex = u32;

        pub const BrCond = struct {
            cond: Value,
            then: Block.Index,
            @"else": Block.Index,
            weights: Weights,
            pub const Weights = enum(u32) {
                // We can do this as metadata indices 0 and 1 are reserved.
                none = 0,
                unpredictable = 1,
                /// These values should be converted to `Metadata` to be used
                /// in a `prof` annotation providing branch weights.
                _,
            };
        };

        pub const Switch = struct {
            val: Value,
            default: Block.Index,
            cases_len: u32,
            weights: BrCond.Weights,
            //case_vals: [cases_len]Constant,
            //case_blocks: [cases_len]Block.Index,
        };

        pub const IndirectBr = struct {
            addr: Value,
            targets_len: u32,
            //targets: [targets_len]Block.Index,
        };

        pub const Binary = struct {
            lhs: Value,
            rhs: Value,
        };

        pub const ExtractElement = struct {
            val: Value,
            index: Value,
        };

        pub const InsertElement = struct {
            val: Value,
            elem: Value,
            index: Value,
        };

        pub const ShuffleVector = struct {
            lhs: Value,
            rhs: Value,
            mask: Value,
        };

        pub const ExtractValue = struct {
            val: Value,
            indices_len: u32,
            //indices: [indices_len]u32,
        };

        pub const InsertValue = struct {
            val: Value,
            elem: Value,
            indices_len: u32,
            //indices: [indices_len]u32,
        };

        pub const Alloca = struct {
            type: Type,
            len: Value,
            info: Info,

            pub const Kind = enum { normal, inalloca };
            pub const Info = packed struct(u32) {
                alignment: Alignment,
                addr_space: AddrSpace,
                _: u2 = undefined,
            };
        };

        pub const Load = struct {
            info: MemoryAccessInfo,
            type: Type,
            ptr: Value,
        };

        pub const Store = struct {
            info: MemoryAccessInfo,
            val: Value,
            ptr: Value,
        };

        pub const CmpXchg = struct {
            info: MemoryAccessInfo,
            ptr: Value,
            cmp: Value,
            new: Value,

            pub const Kind = enum { strong, weak };
        };

        pub const AtomicRmw = struct {
            info: MemoryAccessInfo,
            ptr: Value,
            val: Value,

            pub const Operation = enum(u5) {
                xchg = 0,
                add = 1,
                sub = 2,
                @"and" = 3,
                nand = 4,
                @"or" = 5,
                xor = 6,
                max = 7,
                min = 8,
                umax = 9,
                umin = 10,
                fadd = 11,
                fsub = 12,
                fmax = 13,
                fmin = 14,
                none = std.math.maxInt(u5),
            };
        };

        pub const GetElementPtr = struct {
            type: Type,
            base: Value,
            indices_len: u32,
            //indices: [indices_len]Value,

            pub const Kind = Constant.GetElementPtr.Kind;
        };

        pub const Cast = struct {
            val: Value,
            type: Type,

            pub const Signedness = Constant.Cast.Signedness;
        };

        pub const Phi = struct {
            type: Type,
            //incoming_vals: [block.incoming]Value,
            //incoming_blocks: [block.incoming]Block.Index,
        };

        pub const Select = struct {
            cond: Value,
            lhs: Value,
            rhs: Value,
        };

        pub const Call = struct {
            info: Info,
            attributes: FunctionAttributes,
            ty: Type,
            callee: Value,
            args_len: u32,
            //args: [args_len]Value,

            pub const Kind = enum {
                normal,
                fast,
                musttail,
                musttail_fast,
                notail,
                notail_fast,
                tail,
                tail_fast,
            };
            pub const Info = packed struct(u32) {
                call_conv: CallConv,
                has_op_bundle_cold: bool,
                _: u21 = undefined,
            };
        };

        pub const VaArg = struct {
            list: Value,
            type: Type,
        };
    };

    pub fn deinit(self: *Function, gpa: Allocator) void {
        gpa.free(self.extra);
        gpa.free(self.debug_values);
        self.debug_locations.deinit(gpa);
        gpa.free(self.value_indices[0..self.instructions.len]);
        gpa.free(self.names[0..self.instructions.len]);
        self.instructions.deinit(gpa);
        gpa.free(self.blocks);
        self.* = undefined;
    }

    pub fn arg(self: *const Function, index: u32) Value {
        const argument = self.instructions.get(index);
        assert(argument.tag == .arg);
        assert(argument.data == index);

        const argument_index: Instruction.Index = @enumFromInt(index);
        return argument_index.toValue();
    }

    const ExtraDataTrail = struct {
        index: Instruction.ExtraIndex,

        fn nextMut(self: *ExtraDataTrail, len: u32, comptime Item: type, function: *Function) []Item {
            const items: []Item = @ptrCast(function.extra[self.index..][0..len]);
            self.index += @intCast(len);
            return items;
        }

        fn next(
            self: *ExtraDataTrail,
            len: u32,
            comptime Item: type,
            function: *const Function,
        ) []const Item {
            const items: []const Item = @ptrCast(function.extra[self.index..][0..len]);
            self.index += @intCast(len);
            return items;
        }
    };

    fn extraDataTrail(
        self: *const Function,
        comptime T: type,
        index: Instruction.ExtraIndex,
    ) struct { data: T, trail: ExtraDataTrail } {
        var result: T = undefined;
        const fields = @typeInfo(T).@"struct".fields;
        inline for (fields, self.extra[index..][0..fields.len]) |field, value|
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

    fn extraData(self: *const Function, comptime T: type, index: Instruction.ExtraIndex) T {
        return self.extraDataTrail(T, index).data;
    }
};

pub const DebugLocation = union(enum) {
    no_location: void,
    location: Location,

    pub const Location = struct {
        line: u32,
        column: u32,
        scope: Builder.Metadata,
        inlined_at: Builder.Metadata,
    };

    pub fn toMetadata(self: DebugLocation, builder: *Builder) Allocator.Error!Metadata {
        return switch (self) {
            .no_location => .none,
            .location => |location| try builder.debugLocation(
                location.line,
                location.column,
                location.scope,
                location.inlined_at,
            ),
        };
    }
};

pub const WipFunction = struct {
    builder: *Builder,
    function: Function.Index,
    prev_debug_location: DebugLocation,
    debug_location: DebugLocation,
    cursor: Cursor,
    blocks: std.ArrayListUnmanaged(Block),
    instructions: std.MultiArrayList(Instruction),
    names: std.ArrayListUnmanaged(String),
    strip: bool,
    debug_locations: std.AutoArrayHashMapUnmanaged(Instruction.Index, DebugLocation),
    debug_values: std.AutoArrayHashMapUnmanaged(Instruction.Index, void),
    extra: std.ArrayListUnmanaged(u32),

    pub const Cursor = struct { block: Block.Index, instruction: u32 = 0 };

    pub const Block = struct {
        name: String,
        incoming: u32,
        branches: u32 = 0,
        instructions: std.ArrayListUnmanaged(Instruction.Index),

        const Index = enum(u32) {
            entry,
            _,

            pub fn ptr(self: Index, wip: *WipFunction) *Block {
                return &wip.blocks.items[@intFromEnum(self)];
            }

            pub fn ptrConst(self: Index, wip: *const WipFunction) *const Block {
                return &wip.blocks.items[@intFromEnum(self)];
            }

            pub fn toInst(self: Index, function: *const Function) Instruction.Index {
                return function.blocks[@intFromEnum(self)].instruction;
            }
        };
    };

    pub const Instruction = Function.Instruction;

    pub fn init(builder: *Builder, options: struct {
        function: Function.Index,
        strip: bool,
    }) Allocator.Error!WipFunction {
        var self: WipFunction = .{
            .builder = builder,
            .function = options.function,
            .prev_debug_location = .no_location,
            .debug_location = .no_location,
            .cursor = undefined,
            .blocks = .{},
            .instructions = .{},
            .names = .{},
            .strip = options.strip,
            .debug_locations = .{},
            .debug_values = .{},
            .extra = .{},
        };
        errdefer self.deinit();

        const params_len = options.function.typeOf(self.builder).functionParameters(self.builder).len;
        try self.ensureUnusedExtraCapacity(params_len, NoExtra, 0);
        try self.instructions.ensureUnusedCapacity(self.builder.gpa, params_len);
        if (!self.strip) {
            try self.names.ensureUnusedCapacity(self.builder.gpa, params_len);
        }
        for (0..params_len) |param_index| {
            self.instructions.appendAssumeCapacity(.{ .tag = .arg, .data = @intCast(param_index) });
            if (!self.strip) {
                self.names.appendAssumeCapacity(.empty); // TODO: param names
            }
        }

        return self;
    }

    pub fn arg(self: *const WipFunction, index: u32) Value {
        const argument = self.instructions.get(index);
        assert(argument.tag == .arg);
        assert(argument.data == index);

        const argument_index: Instruction.Index = @enumFromInt(index);
        return argument_index.toValue();
    }

    pub fn block(self: *WipFunction, incoming: u32, name: []const u8) Allocator.Error!Block.Index {
        try self.blocks.ensureUnusedCapacity(self.builder.gpa, 1);

        const index: Block.Index = @enumFromInt(self.blocks.items.len);
        const final_name = if (self.strip) .empty else try self.builder.string(name);
        self.blocks.appendAssumeCapacity(.{
            .name = final_name,
            .incoming = incoming,
            .instructions = .{},
        });
        return index;
    }

    pub fn ret(self: *WipFunction, val: Value) Allocator.Error!Instruction.Index {
        assert(val.typeOfWip(self) == self.function.typeOf(self.builder).functionReturn(self.builder));
        try self.ensureUnusedExtraCapacity(1, NoExtra, 0);
        return try self.addInst(null, .{ .tag = .ret, .data = @intFromEnum(val) });
    }

    pub fn retVoid(self: *WipFunction) Allocator.Error!Instruction.Index {
        try self.ensureUnusedExtraCapacity(1, NoExtra, 0);
        return try self.addInst(null, .{ .tag = .@"ret void", .data = undefined });
    }

    pub fn br(self: *WipFunction, dest: Block.Index) Allocator.Error!Instruction.Index {
        try self.ensureUnusedExtraCapacity(1, NoExtra, 0);
        const instruction = try self.addInst(null, .{ .tag = .br, .data = @intFromEnum(dest) });
        dest.ptr(self).branches += 1;
        return instruction;
    }

    pub fn brCond(
        self: *WipFunction,
        cond: Value,
        then: Block.Index,
        @"else": Block.Index,
        weights: enum { none, unpredictable, then_likely, else_likely },
    ) Allocator.Error!Instruction.Index {
        assert(cond.typeOfWip(self) == .i1);
        try self.ensureUnusedExtraCapacity(1, Instruction.BrCond, 0);
        const instruction = try self.addInst(null, .{
            .tag = .br_cond,
            .data = self.addExtraAssumeCapacity(Instruction.BrCond{
                .cond = cond,
                .then = then,
                .@"else" = @"else",
                .weights = switch (weights) {
                    .none => .none,
                    .unpredictable => .unpredictable,
                    .then_likely, .else_likely => w: {
                        const branch_weights_str = try self.builder.metadataString("branch_weights");
                        const unlikely_const = try self.builder.metadataConstant(try self.builder.intConst(.i32, 1));
                        const likely_const = try self.builder.metadataConstant(try self.builder.intConst(.i32, 2000));
                        const weight_vals: [2]Metadata = switch (weights) {
                            .none, .unpredictable => unreachable,
                            .then_likely => .{ likely_const, unlikely_const },
                            .else_likely => .{ unlikely_const, likely_const },
                        };
                        const tuple = try self.builder.strTuple(branch_weights_str, &weight_vals);
                        break :w @enumFromInt(@intFromEnum(tuple));
                    },
                },
            }),
        });
        then.ptr(self).branches += 1;
        @"else".ptr(self).branches += 1;
        return instruction;
    }

    pub const WipSwitch = struct {
        index: u32,
        instruction: Instruction.Index,

        pub fn addCase(
            self: *WipSwitch,
            val: Constant,
            dest: Block.Index,
            wip: *WipFunction,
        ) Allocator.Error!void {
            const instruction = wip.instructions.get(@intFromEnum(self.instruction));
            var extra = wip.extraDataTrail(Instruction.Switch, instruction.data);
            assert(val.typeOf(wip.builder) == extra.data.val.typeOfWip(wip));
            extra.trail.nextMut(extra.data.cases_len, Constant, wip)[self.index] = val;
            extra.trail.nextMut(extra.data.cases_len, Block.Index, wip)[self.index] = dest;
            self.index += 1;
            dest.ptr(wip).branches += 1;
        }

        pub fn finish(self: WipSwitch, wip: *WipFunction) void {
            const instruction = wip.instructions.get(@intFromEnum(self.instruction));
            const extra = wip.extraData(Instruction.Switch, instruction.data);
            assert(self.index == extra.cases_len);
        }
    };

    pub fn @"switch"(
        self: *WipFunction,
        val: Value,
        default: Block.Index,
        cases_len: u32,
        weights: Instruction.BrCond.Weights,
    ) Allocator.Error!WipSwitch {
        try self.ensureUnusedExtraCapacity(1, Instruction.Switch, cases_len * 2);
        const instruction = try self.addInst(null, .{
            .tag = .@"switch",
            .data = self.addExtraAssumeCapacity(Instruction.Switch{
                .val = val,
                .default = default,
                .cases_len = cases_len,
                .weights = weights,
            }),
        });
        _ = self.extra.addManyAsSliceAssumeCapacity(cases_len * 2);
        default.ptr(self).branches += 1;
        return .{ .index = 0, .instruction = instruction };
    }

    pub fn indirectbr(
        self: *WipFunction,
        addr: Value,
        targets: []const Block.Index,
    ) Allocator.Error!Instruction.Index {
        try self.ensureUnusedExtraCapacity(1, Instruction.IndirectBr, targets.len);
        const instruction = try self.addInst(null, .{
            .tag = .indirectbr,
            .data = self.addExtraAssumeCapacity(Instruction.IndirectBr{
                .addr = addr,
                .targets_len = @intCast(targets.len),
            }),
        });
        _ = self.extra.appendSliceAssumeCapacity(@ptrCast(targets));
        for (targets) |target| target.ptr(self).branches += 1;
        return instruction;
    }

    pub fn @"unreachable"(self: *WipFunction) Allocator.Error!Instruction.Index {
        try self.ensureUnusedExtraCapacity(1, NoExtra, 0);
        return try self.addInst(null, .{ .tag = .@"unreachable", .data = undefined });
    }

    pub fn un(
        self: *WipFunction,
        tag: Instruction.Tag,
        val: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .fneg,
            .@"fneg fast",
            => assert(val.typeOfWip(self).scalarType(self.builder).isFloatingPoint()),
            else => unreachable,
        }
        try self.ensureUnusedExtraCapacity(1, NoExtra, 0);
        const instruction = try self.addInst(name, .{ .tag = tag, .data = @intFromEnum(val) });
        return instruction.toValue();
    }

    pub fn not(self: *WipFunction, val: Value, name: []const u8) Allocator.Error!Value {
        const ty = val.typeOfWip(self);
        const all_ones = try self.builder.splatValue(
            ty,
            try self.builder.intConst(ty.scalarType(self.builder), -1),
        );
        return self.bin(.xor, val, all_ones, name);
    }

    pub fn neg(self: *WipFunction, val: Value, name: []const u8) Allocator.Error!Value {
        return self.bin(.sub, try self.builder.zeroInitValue(val.typeOfWip(self)), val, name);
    }

    pub fn bin(
        self: *WipFunction,
        tag: Instruction.Tag,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .add,
            .@"add nsw",
            .@"add nuw",
            .@"and",
            .ashr,
            .@"ashr exact",
            .fadd,
            .@"fadd fast",
            .fdiv,
            .@"fdiv fast",
            .fmul,
            .@"fmul fast",
            .frem,
            .@"frem fast",
            .fsub,
            .@"fsub fast",
            .lshr,
            .@"lshr exact",
            .mul,
            .@"mul nsw",
            .@"mul nuw",
            .@"or",
            .sdiv,
            .@"sdiv exact",
            .shl,
            .@"shl nsw",
            .@"shl nuw",
            .srem,
            .sub,
            .@"sub nsw",
            .@"sub nuw",
            .udiv,
            .@"udiv exact",
            .urem,
            .xor,
            => assert(lhs.typeOfWip(self) == rhs.typeOfWip(self)),
            else => unreachable,
        }
        try self.ensureUnusedExtraCapacity(1, Instruction.Binary, 0);
        const instruction = try self.addInst(name, .{
            .tag = tag,
            .data = self.addExtraAssumeCapacity(Instruction.Binary{ .lhs = lhs, .rhs = rhs }),
        });
        return instruction.toValue();
    }

    pub fn extractElement(
        self: *WipFunction,
        val: Value,
        index: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(val.typeOfWip(self).isVector(self.builder));
        assert(index.typeOfWip(self).isInteger(self.builder));
        try self.ensureUnusedExtraCapacity(1, Instruction.ExtractElement, 0);
        const instruction = try self.addInst(name, .{
            .tag = .extractelement,
            .data = self.addExtraAssumeCapacity(Instruction.ExtractElement{
                .val = val,
                .index = index,
            }),
        });
        return instruction.toValue();
    }

    pub fn insertElement(
        self: *WipFunction,
        val: Value,
        elem: Value,
        index: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(val.typeOfWip(self).scalarType(self.builder) == elem.typeOfWip(self));
        assert(index.typeOfWip(self).isInteger(self.builder));
        try self.ensureUnusedExtraCapacity(1, Instruction.InsertElement, 0);
        const instruction = try self.addInst(name, .{
            .tag = .insertelement,
            .data = self.addExtraAssumeCapacity(Instruction.InsertElement{
                .val = val,
                .elem = elem,
                .index = index,
            }),
        });
        return instruction.toValue();
    }

    pub fn shuffleVector(
        self: *WipFunction,
        lhs: Value,
        rhs: Value,
        mask: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(lhs.typeOfWip(self).isVector(self.builder));
        assert(lhs.typeOfWip(self) == rhs.typeOfWip(self));
        assert(mask.typeOfWip(self).scalarType(self.builder).isInteger(self.builder));
        _ = try self.ensureUnusedExtraCapacity(1, Instruction.ShuffleVector, 0);
        const instruction = try self.addInst(name, .{
            .tag = .shufflevector,
            .data = self.addExtraAssumeCapacity(Instruction.ShuffleVector{
                .lhs = lhs,
                .rhs = rhs,
                .mask = mask,
            }),
        });
        return instruction.toValue();
    }

    pub fn splatVector(
        self: *WipFunction,
        ty: Type,
        elem: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const scalar_ty = try ty.changeLength(1, self.builder);
        const mask_ty = try ty.changeScalar(.i32, self.builder);
        const poison = try self.builder.poisonValue(scalar_ty);
        const mask = try self.builder.splatValue(mask_ty, .@"0");
        const scalar = try self.insertElement(poison, elem, .@"0", name);
        return self.shuffleVector(scalar, poison, mask, name);
    }

    pub fn extractValue(
        self: *WipFunction,
        val: Value,
        indices: []const u32,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(indices.len > 0);
        _ = val.typeOfWip(self).childTypeAt(indices, self.builder);
        try self.ensureUnusedExtraCapacity(1, Instruction.ExtractValue, indices.len);
        const instruction = try self.addInst(name, .{
            .tag = .extractvalue,
            .data = self.addExtraAssumeCapacity(Instruction.ExtractValue{
                .val = val,
                .indices_len = @intCast(indices.len),
            }),
        });
        self.extra.appendSliceAssumeCapacity(indices);
        return instruction.toValue();
    }

    pub fn insertValue(
        self: *WipFunction,
        val: Value,
        elem: Value,
        indices: []const u32,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(indices.len > 0);
        assert(val.typeOfWip(self).childTypeAt(indices, self.builder) == elem.typeOfWip(self));
        try self.ensureUnusedExtraCapacity(1, Instruction.InsertValue, indices.len);
        const instruction = try self.addInst(name, .{
            .tag = .insertvalue,
            .data = self.addExtraAssumeCapacity(Instruction.InsertValue{
                .val = val,
                .elem = elem,
                .indices_len = @intCast(indices.len),
            }),
        });
        self.extra.appendSliceAssumeCapacity(indices);
        return instruction.toValue();
    }

    pub fn buildAggregate(
        self: *WipFunction,
        ty: Type,
        elems: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ty.aggregateLen(self.builder) == elems.len);
        var cur = try self.builder.poisonValue(ty);
        for (elems, 0..) |elem, index|
            cur = try self.insertValue(cur, elem, &[_]u32{@intCast(index)}, name);
        return cur;
    }

    pub fn alloca(
        self: *WipFunction,
        kind: Instruction.Alloca.Kind,
        ty: Type,
        len: Value,
        alignment: Alignment,
        addr_space: AddrSpace,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(len == .none or len.typeOfWip(self).isInteger(self.builder));
        _ = try self.builder.ptrType(addr_space);
        try self.ensureUnusedExtraCapacity(1, Instruction.Alloca, 0);
        const instruction = try self.addInst(name, .{
            .tag = switch (kind) {
                .normal => .alloca,
                .inalloca => .@"alloca inalloca",
            },
            .data = self.addExtraAssumeCapacity(Instruction.Alloca{
                .type = ty,
                .len = switch (len) {
                    .none => .@"1",
                    else => len,
                },
                .info = .{ .alignment = alignment, .addr_space = addr_space },
            }),
        });
        return instruction.toValue();
    }

    pub fn load(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        ty: Type,
        ptr: Value,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.loadAtomic(access_kind, ty, ptr, .system, .none, alignment, name);
    }

    pub fn loadAtomic(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        ty: Type,
        ptr: Value,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ptr.typeOfWip(self).isPointer(self.builder));
        try self.ensureUnusedExtraCapacity(1, Instruction.Load, 0);
        const instruction = try self.addInst(name, .{
            .tag = switch (ordering) {
                .none => .load,
                else => .@"load atomic",
            },
            .data = self.addExtraAssumeCapacity(Instruction.Load{
                .info = .{
                    .access_kind = access_kind,
                    .sync_scope = switch (ordering) {
                        .none => .system,
                        else => sync_scope,
                    },
                    .success_ordering = ordering,
                    .alignment = alignment,
                },
                .type = ty,
                .ptr = ptr,
            }),
        });
        return instruction.toValue();
    }

    pub fn store(
        self: *WipFunction,
        kind: MemoryAccessKind,
        val: Value,
        ptr: Value,
        alignment: Alignment,
    ) Allocator.Error!Instruction.Index {
        return self.storeAtomic(kind, val, ptr, .system, .none, alignment);
    }

    pub fn storeAtomic(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        val: Value,
        ptr: Value,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
        alignment: Alignment,
    ) Allocator.Error!Instruction.Index {
        assert(ptr.typeOfWip(self).isPointer(self.builder));
        try self.ensureUnusedExtraCapacity(1, Instruction.Store, 0);
        const instruction = try self.addInst(null, .{
            .tag = switch (ordering) {
                .none => .store,
                else => .@"store atomic",
            },
            .data = self.addExtraAssumeCapacity(Instruction.Store{
                .info = .{
                    .access_kind = access_kind,
                    .sync_scope = switch (ordering) {
                        .none => .system,
                        else => sync_scope,
                    },
                    .success_ordering = ordering,
                    .alignment = alignment,
                },
                .val = val,
                .ptr = ptr,
            }),
        });
        return instruction;
    }

    pub fn fence(
        self: *WipFunction,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
    ) Allocator.Error!Instruction.Index {
        assert(ordering != .none);
        try self.ensureUnusedExtraCapacity(1, NoExtra, 0);
        const instruction = try self.addInst(null, .{
            .tag = .fence,
            .data = @bitCast(MemoryAccessInfo{
                .sync_scope = sync_scope,
                .success_ordering = ordering,
            }),
        });
        return instruction;
    }

    pub fn cmpxchg(
        self: *WipFunction,
        kind: Instruction.CmpXchg.Kind,
        access_kind: MemoryAccessKind,
        ptr: Value,
        cmp: Value,
        new: Value,
        sync_scope: SyncScope,
        success_ordering: AtomicOrdering,
        failure_ordering: AtomicOrdering,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ptr.typeOfWip(self).isPointer(self.builder));
        const ty = cmp.typeOfWip(self);
        assert(ty == new.typeOfWip(self));
        assert(success_ordering != .none);
        assert(failure_ordering != .none);

        _ = try self.builder.structType(.normal, &.{ ty, .i1 });
        try self.ensureUnusedExtraCapacity(1, Instruction.CmpXchg, 0);
        const instruction = try self.addInst(name, .{
            .tag = switch (kind) {
                .strong => .cmpxchg,
                .weak => .@"cmpxchg weak",
            },
            .data = self.addExtraAssumeCapacity(Instruction.CmpXchg{
                .info = .{
                    .access_kind = access_kind,
                    .sync_scope = sync_scope,
                    .success_ordering = success_ordering,
                    .failure_ordering = failure_ordering,
                    .alignment = alignment,
                },
                .ptr = ptr,
                .cmp = cmp,
                .new = new,
            }),
        });
        return instruction.toValue();
    }

    pub fn atomicrmw(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        operation: Instruction.AtomicRmw.Operation,
        ptr: Value,
        val: Value,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ptr.typeOfWip(self).isPointer(self.builder));
        assert(ordering != .none);

        try self.ensureUnusedExtraCapacity(1, Instruction.AtomicRmw, 0);
        const instruction = try self.addInst(name, .{
            .tag = .atomicrmw,
            .data = self.addExtraAssumeCapacity(Instruction.AtomicRmw{
                .info = .{
                    .access_kind = access_kind,
                    .atomic_rmw_operation = operation,
                    .sync_scope = sync_scope,
                    .success_ordering = ordering,
                    .alignment = alignment,
                },
                .ptr = ptr,
                .val = val,
            }),
        });
        return instruction.toValue();
    }

    pub fn gep(
        self: *WipFunction,
        kind: Instruction.GetElementPtr.Kind,
        ty: Type,
        base: Value,
        indices: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const base_ty = base.typeOfWip(self);
        const base_is_vector = base_ty.isVector(self.builder);

        const VectorInfo = struct {
            kind: Type.Vector.Kind,
            len: u32,

            fn init(vector_ty: Type, builder: *const Builder) @This() {
                return .{ .kind = vector_ty.vectorKind(builder), .len = vector_ty.vectorLen(builder) };
            }
        };
        var vector_info: ?VectorInfo =
            if (base_is_vector) VectorInfo.init(base_ty, self.builder) else null;
        for (indices) |index| {
            const index_ty = index.typeOfWip(self);
            switch (index_ty.tag(self.builder)) {
                .integer => {},
                .vector, .scalable_vector => {
                    const index_info = VectorInfo.init(index_ty, self.builder);
                    if (vector_info) |info|
                        assert(std.meta.eql(info, index_info))
                    else
                        vector_info = index_info;
                },
                else => unreachable,
            }
        }
        if (!base_is_vector) if (vector_info) |info| switch (info.kind) {
            inline else => |vector_kind| _ = try self.builder.vectorType(
                vector_kind,
                info.len,
                base_ty,
            ),
        };

        try self.ensureUnusedExtraCapacity(1, Instruction.GetElementPtr, indices.len);
        const instruction = try self.addInst(name, .{
            .tag = switch (kind) {
                .normal => .getelementptr,
                .inbounds => .@"getelementptr inbounds",
            },
            .data = self.addExtraAssumeCapacity(Instruction.GetElementPtr{
                .type = ty,
                .base = base,
                .indices_len = @intCast(indices.len),
            }),
        });
        self.extra.appendSliceAssumeCapacity(@ptrCast(indices));
        return instruction.toValue();
    }

    pub fn gepStruct(
        self: *WipFunction,
        ty: Type,
        base: Value,
        index: usize,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ty.isStruct(self.builder));
        return self.gep(.inbounds, ty, base, &.{ .@"0", try self.builder.intValue(.i32, index) }, name);
    }

    pub fn conv(
        self: *WipFunction,
        signedness: Instruction.Cast.Signedness,
        val: Value,
        ty: Type,
        name: []const u8,
    ) Allocator.Error!Value {
        const val_ty = val.typeOfWip(self);
        if (val_ty == ty) return val;
        return self.cast(self.builder.convTag(signedness, val_ty, ty), val, ty, name);
    }

    pub fn cast(
        self: *WipFunction,
        tag: Instruction.Tag,
        val: Value,
        ty: Type,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .addrspacecast,
            .bitcast,
            .fpext,
            .fptosi,
            .fptoui,
            .fptrunc,
            .inttoptr,
            .ptrtoint,
            .sext,
            .sitofp,
            .trunc,
            .uitofp,
            .zext,
            => {},
            else => unreachable,
        }
        if (val.typeOfWip(self) == ty) return val;
        try self.ensureUnusedExtraCapacity(1, Instruction.Cast, 0);
        const instruction = try self.addInst(name, .{
            .tag = tag,
            .data = self.addExtraAssumeCapacity(Instruction.Cast{
                .val = val,
                .type = ty,
            }),
        });
        return instruction.toValue();
    }

    pub fn icmp(
        self: *WipFunction,
        cond: IntegerCondition,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.cmpTag(switch (cond) {
            inline else => |tag| @field(Instruction.Tag, "icmp " ++ @tagName(tag)),
        }, lhs, rhs, name);
    }

    pub fn fcmp(
        self: *WipFunction,
        fast: FastMathKind,
        cond: FloatCondition,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.cmpTag(switch (fast) {
            inline else => |fast_tag| switch (cond) {
                inline else => |cond_tag| @field(Instruction.Tag, "fcmp " ++ switch (fast_tag) {
                    .normal => "",
                    .fast => "fast ",
                } ++ @tagName(cond_tag)),
            },
        }, lhs, rhs, name);
    }

    pub const WipPhi = struct {
        block: Block.Index,
        instruction: Instruction.Index,

        pub fn toValue(self: WipPhi) Value {
            return self.instruction.toValue();
        }

        pub fn finish(
            self: WipPhi,
            vals: []const Value,
            blocks: []const Block.Index,
            wip: *WipFunction,
        ) void {
            const incoming_len = self.block.ptrConst(wip).incoming;
            assert(vals.len == incoming_len and blocks.len == incoming_len);
            const instruction = wip.instructions.get(@intFromEnum(self.instruction));
            var extra = wip.extraDataTrail(Instruction.Phi, instruction.data);
            for (vals) |val| assert(val.typeOfWip(wip) == extra.data.type);
            @memcpy(extra.trail.nextMut(incoming_len, Value, wip), vals);
            @memcpy(extra.trail.nextMut(incoming_len, Block.Index, wip), blocks);
        }
    };

    pub fn phi(self: *WipFunction, ty: Type, name: []const u8) Allocator.Error!WipPhi {
        return self.phiTag(.phi, ty, name);
    }

    pub fn phiFast(self: *WipFunction, ty: Type, name: []const u8) Allocator.Error!WipPhi {
        return self.phiTag(.@"phi fast", ty, name);
    }

    pub fn select(
        self: *WipFunction,
        fast: FastMathKind,
        cond: Value,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.selectTag(switch (fast) {
            .normal => .select,
            .fast => .@"select fast",
        }, cond, lhs, rhs, name);
    }

    pub fn call(
        self: *WipFunction,
        kind: Instruction.Call.Kind,
        call_conv: CallConv,
        function_attributes: FunctionAttributes,
        ty: Type,
        callee: Value,
        args: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.callInner(kind, call_conv, function_attributes, ty, callee, args, name, false);
    }

    fn callInner(
        self: *WipFunction,
        kind: Instruction.Call.Kind,
        call_conv: CallConv,
        function_attributes: FunctionAttributes,
        ty: Type,
        callee: Value,
        args: []const Value,
        name: []const u8,
        has_op_bundle_cold: bool,
    ) Allocator.Error!Value {
        const ret_ty = ty.functionReturn(self.builder);
        assert(ty.isFunction(self.builder));
        assert(callee.typeOfWip(self).isPointer(self.builder));
        const params = ty.functionParameters(self.builder);
        for (params, args[0..params.len]) |param, arg_val| assert(param == arg_val.typeOfWip(self));

        try self.ensureUnusedExtraCapacity(1, Instruction.Call, args.len);
        const instruction = try self.addInst(switch (ret_ty) {
            .void => null,
            else => name,
        }, .{
            .tag = switch (kind) {
                .normal => .call,
                .fast => .@"call fast",
                .musttail => .@"musttail call",
                .musttail_fast => .@"musttail call fast",
                .notail => .@"notail call",
                .notail_fast => .@"notail call fast",
                .tail => .@"tail call",
                .tail_fast => .@"tail call fast",
            },
            .data = self.addExtraAssumeCapacity(Instruction.Call{
                .info = .{
                    .call_conv = call_conv,
                    .has_op_bundle_cold = has_op_bundle_cold,
                },
                .attributes = function_attributes,
                .ty = ty,
                .callee = callee,
                .args_len = @intCast(args.len),
            }),
        });
        self.extra.appendSliceAssumeCapacity(@ptrCast(args));
        return instruction.toValue();
    }

    pub fn callAsm(
        self: *WipFunction,
        function_attributes: FunctionAttributes,
        ty: Type,
        kind: Constant.Assembly.Info,
        assembly: String,
        constraints: String,
        args: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const callee = try self.builder.asmValue(ty, kind, assembly, constraints);
        return self.call(.normal, CallConv.default, function_attributes, ty, callee, args, name);
    }

    pub fn callIntrinsic(
        self: *WipFunction,
        fast: FastMathKind,
        function_attributes: FunctionAttributes,
        id: Intrinsic,
        overload: []const Type,
        args: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const intrinsic = try self.builder.getIntrinsic(id, overload);
        return self.call(
            fast.toCallKind(),
            CallConv.default,
            function_attributes,
            intrinsic.typeOf(self.builder),
            intrinsic.toValue(self.builder),
            args,
            name,
        );
    }

    pub fn callIntrinsicAssumeCold(self: *WipFunction) Allocator.Error!Value {
        const intrinsic = try self.builder.getIntrinsic(.assume, &.{});
        return self.callInner(
            .normal,
            CallConv.default,
            .none,
            intrinsic.typeOf(self.builder),
            intrinsic.toValue(self.builder),
            &.{try self.builder.intValue(.i1, 1)},
            "",
            true,
        );
    }

    pub fn callMemCpy(
        self: *WipFunction,
        dst: Value,
        dst_align: Alignment,
        src: Value,
        src_align: Alignment,
        len: Value,
        kind: MemoryAccessKind,
        @"inline": bool,
    ) Allocator.Error!Instruction.Index {
        var dst_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = dst_align })};
        var src_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = src_align })};
        const value = try self.callIntrinsic(
            .normal,
            try self.builder.fnAttrs(&.{
                .none,
                .none,
                try self.builder.attrs(&dst_attrs),
                try self.builder.attrs(&src_attrs),
            }),
            if (@"inline") .@"memcpy.inline" else .memcpy,
            &.{ dst.typeOfWip(self), src.typeOfWip(self), len.typeOfWip(self) },
            &.{ dst, src, len, switch (kind) {
                .normal => Value.false,
                .@"volatile" => Value.true,
            } },
            undefined,
        );
        return value.unwrap().instruction;
    }

    pub fn callMemMove(
        self: *WipFunction,
        dst: Value,
        dst_align: Alignment,
        src: Value,
        src_align: Alignment,
        len: Value,
        kind: MemoryAccessKind,
    ) Allocator.Error!Instruction.Index {
        var dst_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = dst_align })};
        var src_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = src_align })};
        const value = try self.callIntrinsic(
            .normal,
            try self.builder.fnAttrs(&.{
                .none,
                .none,
                try self.builder.attrs(&dst_attrs),
                try self.builder.attrs(&src_attrs),
            }),
            .memmove,
            &.{ dst.typeOfWip(self), src.typeOfWip(self), len.typeOfWip(self) },
            &.{ dst, src, len, switch (kind) {
                .normal => Value.false,
                .@"volatile" => Value.true,
            } },
            undefined,
        );
        return value.unwrap().instruction;
    }

    pub fn callMemSet(
        self: *WipFunction,
        dst: Value,
        dst_align: Alignment,
        val: Value,
        len: Value,
        kind: MemoryAccessKind,
        @"inline": bool,
    ) Allocator.Error!Instruction.Index {
        var dst_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = dst_align })};
        const value = try self.callIntrinsic(
            .normal,
            try self.builder.fnAttrs(&.{ .none, .none, try self.builder.attrs(&dst_attrs) }),
            if (@"inline") .@"memset.inline" else .memset,
            &.{ dst.typeOfWip(self), len.typeOfWip(self) },
            &.{ dst, val, len, switch (kind) {
                .normal => Value.false,
                .@"volatile" => Value.true,
            } },
            undefined,
        );
        return value.unwrap().instruction;
    }

    pub fn vaArg(self: *WipFunction, list: Value, ty: Type, name: []const u8) Allocator.Error!Value {
        try self.ensureUnusedExtraCapacity(1, Instruction.VaArg, 0);
        const instruction = try self.addInst(name, .{
            .tag = .va_arg,
            .data = self.addExtraAssumeCapacity(Instruction.VaArg{
                .list = list,
                .type = ty,
            }),
        });
        return instruction.toValue();
    }

    pub fn debugValue(self: *WipFunction, value: Value) Allocator.Error!Metadata {
        if (self.strip) return .none;
        return switch (value.unwrap()) {
            .instruction => |instr_index| blk: {
                const gop = try self.debug_values.getOrPut(self.builder.gpa, instr_index);

                const metadata: Metadata = @enumFromInt(Metadata.first_local_metadata + gop.index);
                if (!gop.found_existing) gop.key_ptr.* = instr_index;

                break :blk metadata;
            },
            .constant => |constant| try self.builder.metadataConstant(constant),
            .metadata => |metadata| metadata,
        };
    }

    pub fn finish(self: *WipFunction) Allocator.Error!void {
        const gpa = self.builder.gpa;
        const function = self.function.ptr(self.builder);
        const params_len = self.function.typeOf(self.builder).functionParameters(self.builder).len;
        const final_instructions_len = self.blocks.items.len + self.instructions.len;

        const blocks = try gpa.alloc(Function.Block, self.blocks.items.len);
        errdefer gpa.free(blocks);

        const instructions: struct {
            items: []Instruction.Index,

            fn map(instructions: @This(), val: Value) Value {
                if (val == .none) return .none;
                return switch (val.unwrap()) {
                    .instruction => |instruction| instructions.items[
                        @intFromEnum(instruction)
                    ].toValue(),
                    .constant => |constant| constant.toValue(),
                    .metadata => |metadata| metadata.toValue(),
                };
            }
        } = .{ .items = try gpa.alloc(Instruction.Index, self.instructions.len) };
        defer gpa.free(instructions.items);

        const names = try gpa.alloc(String, final_instructions_len);
        errdefer gpa.free(names);

        const value_indices = try gpa.alloc(u32, final_instructions_len);
        errdefer gpa.free(value_indices);

        var debug_locations: std.AutoHashMapUnmanaged(Instruction.Index, DebugLocation) = .empty;
        errdefer debug_locations.deinit(gpa);
        try debug_locations.ensureUnusedCapacity(gpa, @intCast(self.debug_locations.count()));

        const debug_values = try gpa.alloc(Instruction.Index, self.debug_values.count());
        errdefer gpa.free(debug_values);

        var wip_extra: struct {
            index: Instruction.ExtraIndex = 0,
            items: []u32,

            fn addExtra(wip_extra: *@This(), extra: anytype) Instruction.ExtraIndex {
                const result = wip_extra.index;
                inline for (@typeInfo(@TypeOf(extra)).@"struct".fields) |field| {
                    const value = @field(extra, field.name);
                    wip_extra.items[wip_extra.index] = switch (field.type) {
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
                    };
                    wip_extra.index += 1;
                }
                return result;
            }

            fn appendSlice(wip_extra: *@This(), slice: anytype) void {
                if (@typeInfo(@TypeOf(slice)).pointer.child == Value)
                    @compileError("use appendMappedValues");
                const data: []const u32 = @ptrCast(slice);
                @memcpy(wip_extra.items[wip_extra.index..][0..data.len], data);
                wip_extra.index += @intCast(data.len);
            }

            fn appendMappedValues(wip_extra: *@This(), vals: []const Value, ctx: anytype) void {
                for (wip_extra.items[wip_extra.index..][0..vals.len], vals) |*extra, val|
                    extra.* = @intFromEnum(ctx.map(val));
                wip_extra.index += @intCast(vals.len);
            }

            fn finish(wip_extra: *const @This()) []const u32 {
                assert(wip_extra.index == wip_extra.items.len);
                return wip_extra.items;
            }
        } = .{ .items = try gpa.alloc(u32, self.extra.items.len) };
        errdefer gpa.free(wip_extra.items);

        gpa.free(function.blocks);
        function.blocks = &.{};
        gpa.free(function.names[0..function.instructions.len]);
        function.debug_locations.deinit(gpa);
        function.debug_locations = .{};
        gpa.free(function.debug_values);
        function.debug_values = &.{};
        gpa.free(function.extra);
        function.extra = &.{};

        function.instructions.shrinkRetainingCapacity(0);
        try function.instructions.setCapacity(gpa, final_instructions_len);
        errdefer function.instructions.shrinkRetainingCapacity(0);

        {
            var final_instruction_index: Instruction.Index = @enumFromInt(0);
            for (0..params_len) |param_index| {
                instructions.items[param_index] = final_instruction_index;
                final_instruction_index = @enumFromInt(@intFromEnum(final_instruction_index) + 1);
            }
            for (blocks, self.blocks.items) |*final_block, current_block| {
                assert(current_block.incoming == current_block.branches);
                final_block.instruction = final_instruction_index;
                final_instruction_index = @enumFromInt(@intFromEnum(final_instruction_index) + 1);
                for (current_block.instructions.items) |instruction| {
                    instructions.items[@intFromEnum(instruction)] = final_instruction_index;
                    final_instruction_index = @enumFromInt(@intFromEnum(final_instruction_index) + 1);
                }
            }
        }

        var wip_name: struct {
            next_name: String = @enumFromInt(0),
            next_unique_name: std.AutoHashMap(String, String),
            builder: *Builder,

            fn map(wip_name: *@This(), name: String, sep: []const u8) Allocator.Error!String {
                switch (name) {
                    .none => return .none,
                    .empty => {
                        assert(wip_name.next_name != .none);
                        defer wip_name.next_name = @enumFromInt(@intFromEnum(wip_name.next_name) + 1);
                        return wip_name.next_name;
                    },
                    _ => {
                        assert(!name.isAnon());
                        const gop = try wip_name.next_unique_name.getOrPut(name);
                        if (!gop.found_existing) {
                            gop.value_ptr.* = @enumFromInt(0);
                            return name;
                        }

                        while (true) {
                            gop.value_ptr.* = @enumFromInt(@intFromEnum(gop.value_ptr.*) + 1);
                            const unique_name = try wip_name.builder.fmt("{r}{s}{r}", .{
                                name.fmt(wip_name.builder),
                                sep,
                                gop.value_ptr.fmt(wip_name.builder),
                            });
                            const unique_gop = try wip_name.next_unique_name.getOrPut(unique_name);
                            if (!unique_gop.found_existing) {
                                unique_gop.value_ptr.* = @enumFromInt(0);
                                return unique_name;
                            }
                        }
                    },
                }
            }
        } = .{
            .next_unique_name = std.AutoHashMap(String, String).init(gpa),
            .builder = self.builder,
        };
        defer wip_name.next_unique_name.deinit();

        var value_index: u32 = 0;
        for (0..params_len) |param_index| {
            const old_argument_index: Instruction.Index = @enumFromInt(param_index);
            const new_argument_index: Instruction.Index = @enumFromInt(function.instructions.len);
            const argument = self.instructions.get(@intFromEnum(old_argument_index));
            assert(argument.tag == .arg);
            assert(argument.data == param_index);
            value_indices[function.instructions.len] = value_index;
            value_index += 1;
            function.instructions.appendAssumeCapacity(argument);
            names[@intFromEnum(new_argument_index)] = try wip_name.map(
                if (self.strip) .empty else self.names.items[@intFromEnum(old_argument_index)],
                ".",
            );
            if (self.debug_locations.get(old_argument_index)) |location| {
                debug_locations.putAssumeCapacity(new_argument_index, location);
            }
            if (self.debug_values.getIndex(old_argument_index)) |index| {
                debug_values[index] = new_argument_index;
            }
        }
        for (self.blocks.items) |current_block| {
            const new_block_index: Instruction.Index = @enumFromInt(function.instructions.len);
            value_indices[function.instructions.len] = value_index;
            function.instructions.appendAssumeCapacity(.{
                .tag = .block,
                .data = current_block.incoming,
            });
            names[@intFromEnum(new_block_index)] = try wip_name.map(current_block.name, "");
            for (current_block.instructions.items) |old_instruction_index| {
                const new_instruction_index: Instruction.Index = @enumFromInt(function.instructions.len);
                var instruction = self.instructions.get(@intFromEnum(old_instruction_index));
                switch (instruction.tag) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .@"and",
                    .ashr,
                    .@"ashr exact",
                    .fadd,
                    .@"fadd fast",
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
                    .fdiv,
                    .@"fdiv fast",
                    .fmul,
                    .@"fmul fast",
                    .frem,
                    .@"frem fast",
                    .fsub,
                    .@"fsub fast",
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
                    .lshr,
                    .@"lshr exact",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    .@"or",
                    .sdiv,
                    .@"sdiv exact",
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .srem,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => {
                        const extra = self.extraData(Instruction.Binary, instruction.data);
                        instruction.data = wip_extra.addExtra(Instruction.Binary{
                            .lhs = instructions.map(extra.lhs),
                            .rhs = instructions.map(extra.rhs),
                        });
                    },
                    .addrspacecast,
                    .bitcast,
                    .fpext,
                    .fptosi,
                    .fptoui,
                    .fptrunc,
                    .inttoptr,
                    .ptrtoint,
                    .sext,
                    .sitofp,
        ```
