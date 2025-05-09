```
 fn intConst(self: *Builder, ty: Type, value: anytype) Allocator.Error!Constant {
    const int_value = switch (@typeInfo(@TypeOf(value))) {
        .int, .comptime_int => value,
        .@"enum" => @intFromEnum(value),
        else => @compileError("intConst expected an integral value, got " ++ @typeName(@TypeOf(value))),
    };
    var limbs: [
        switch (@typeInfo(@TypeOf(int_value))) {
            .int => |info| std.math.big.int.calcTwosCompLimbCount(info.bits),
            .comptime_int => std.math.big.int.calcLimbLen(int_value),
            else => unreachable,
        }
    ]std.math.big.Limb = undefined;
    return self.bigIntConst(ty, std.math.big.int.Mutable.init(&limbs, int_value).toConst());
}

pub fn intValue(self: *Builder, ty: Type, value: anytype) Allocator.Error!Value {
    return (try self.intConst(ty, value)).toValue();
}

pub fn bigIntConst(self: *Builder, ty: Type, value: std.math.big.int.Const) Allocator.Error!Constant {
    try self.constant_map.ensureUnusedCapacity(self.gpa, 1);
    try self.constant_items.ensureUnusedCapacity(self.gpa, 1);
    try self.constant_limbs.ensureUnusedCapacity(self.gpa, Constant.Integer.limbs + value.limbs.len);
    return self.bigIntConstAssumeCapacity(ty, value);
}

pub fn bigIntValue(self: *Builder, ty: Type, value: std.math.big.int.Const) Allocator.Error!Value {
    return (try self.bigIntConst(ty, value)).toValue();
}

pub fn fpConst(self: *Builder, ty: Type, comptime val: comptime_float) Allocator.Error!Constant {
    return switch (ty) {
        .half => try self.halfConst(val),
        .bfloat => try self.bfloatConst(val),
        .float => try self.floatConst(val),
        .double => try self.doubleConst(val),
        .fp128 => try self.fp128Const(val),
        .x86_fp80 => try self.x86_fp80Const(val),
        .ppc_fp128 => try self.ppc_fp128Const(.{ val, -0.0 }),
        else => unreachable,
    };
}

pub fn fpValue(self: *Builder, ty: Type, comptime value: comptime_float) Allocator.Error!Value {
    return (try self.fpConst(ty, value)).toValue();
}

pub fn nanConst(self: *Builder, ty: Type) Allocator.Error!Constant {
    return switch (ty) {
        .half => try self.halfConst(std.math.nan(f16)),
        .bfloat => try self.bfloatConst(std.math.nan(f32)),
        .float => try self.floatConst(std.math.nan(f32)),
        .double => try self.doubleConst(std.math.nan(f64)),
        .fp128 => try self.fp128Const(std.math.nan(f128)),
        .x86_fp80 => try self.x86_fp80Const(std.math.nan(f80)),
        .ppc_fp128 => try self.ppc_fp128Const(.{std.math.nan(f64)} ** 2),
        else => unreachable,
    };
}

pub fn nanValue(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.nanConst(ty)).toValue();
}

pub fn halfConst(self: *Builder, val: f16) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.halfConstAssumeCapacity(val);
}

pub fn halfValue(self: *Builder, ty: Type, value: f16) Allocator.Error!Value {
    return (try self.halfConst(ty, value)).toValue();
}

pub fn bfloatConst(self: *Builder, val: f32) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.bfloatConstAssumeCapacity(val);
}

pub fn bfloatValue(self: *Builder, ty: Type, value: f32) Allocator.Error!Value {
    return (try self.bfloatConst(ty, value)).toValue();
}

pub fn floatConst(self: *Builder, val: f32) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.floatConstAssumeCapacity(val);
}

pub fn floatValue(self: *Builder, ty: Type, value: f32) Allocator.Error!Value {
    return (try self.floatConst(ty, value)).toValue();
}

pub fn doubleConst(self: *Builder, val: f64) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Double, 0);
    return self.doubleConstAssumeCapacity(val);
}

pub fn doubleValue(self: *Builder, ty: Type, value: f64) Allocator.Error!Value {
    return (try self.doubleConst(ty, value)).toValue();
}

pub fn fp128Const(self: *Builder, val: f128) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Fp128, 0);
    return self.fp128ConstAssumeCapacity(val);
}

pub fn fp128Value(self: *Builder, ty: Type, value: f128) Allocator.Error!Value {
    return (try self.fp128Const(ty, value)).toValue();
}

pub fn x86_fp80Const(self: *Builder, val: f80) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Fp80, 0);
    return self.x86_fp80ConstAssumeCapacity(val);
}

pub fn x86_fp80Value(self: *Builder, ty: Type, value: f80) Allocator.Error!Value {
    return (try self.x86_fp80Const(ty, value)).toValue();
}

pub fn ppc_fp128Const(self: *Builder, val: [2]f64) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Fp128, 0);
    return self.ppc_fp128ConstAssumeCapacity(val);
}

pub fn ppc_fp128Value(self: *Builder, ty: Type, value: [2]f64) Allocator.Error!Value {
    return (try self.ppc_fp128Const(ty, value)).toValue();
}

pub fn nullConst(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.nullConstAssumeCapacity(ty);
}

pub fn nullValue(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.nullConst(ty)).toValue();
}

pub fn noneConst(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.noneConstAssumeCapacity(ty);
}

pub fn noneValue(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.noneConst(ty)).toValue();
}

pub fn structConst(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Aggregate, vals.len);
    return self.structConstAssumeCapacity(ty, vals);
}

pub fn structValue(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Value {
    return (try self.structConst(ty, vals)).toValue();
}

pub fn arrayConst(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Aggregate, vals.len);
    return self.arrayConstAssumeCapacity(ty, vals);
}

pub fn arrayValue(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Value {
    return (try self.arrayConst(ty, vals)).toValue();
}

pub fn stringConst(self: *Builder, val: String) Allocator.Error!Constant {
    try self.ensureUnusedTypeCapacity(1, Type.Array, 0);
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.stringConstAssumeCapacity(val);
}

pub fn stringValue(self: *Builder, val: String) Allocator.Error!Value {
    return (try self.stringConst(val)).toValue();
}

pub fn vectorConst(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Aggregate, vals.len);
    return self.vectorConstAssumeCapacity(ty, vals);
}

pub fn vectorValue(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Value {
    return (try self.vectorConst(ty, vals)).toValue();
}

pub fn splatConst(self: *Builder, ty: Type, val: Constant) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Splat, 0);
    return self.splatConstAssumeCapacity(ty, val);
}

pub fn splatValue(self: *Builder, ty: Type, val: Constant) Allocator.Error!Value {
    return (try self.splatConst(ty, val)).toValue();
}

pub fn zeroInitConst(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Fp128, 0);
    try self.constant_limbs.ensureUnusedCapacity(
        self.gpa,
        Constant.Integer.limbs + comptime std.math.big.int.calcLimbLen(0),
    );
    return self.zeroInitConstAssumeCapacity(ty);
}

pub fn zeroInitValue(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.zeroInitConst(ty)).toValue();
}

pub fn undefConst(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.undefConstAssumeCapacity(ty);
}

pub fn undefValue(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.undefConst(ty)).toValue();
}

pub fn poisonConst(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.poisonConstAssumeCapacity(ty);
}

pub fn poisonValue(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.poisonConst(ty)).toValue();
}

pub fn blockAddrConst(
    self: *Builder,
    function: Function.Index,
    block: Function.Block.Index,
) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.BlockAddress, 0);
    return self.blockAddrConstAssumeCapacity(function, block);
}

pub fn blockAddrValue(
    self: *Builder,
    function: Function.Index,
    block: Function.Block.Index,
) Allocator.Error!Value {
    return (try self.blockAddrConst(function, block)).toValue();
}

pub fn dsoLocalEquivalentConst(self: *Builder, function: Function.Index) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.dsoLocalEquivalentConstAssumeCapacity(function);
}

pub fn dsoLocalEquivalentValue(self: *Builder, function: Function.Index) Allocator.Error!Value {
    return (try self.dsoLocalEquivalentConst(function)).toValue();
}

pub fn noCfiConst(self: *Builder, function: Function.Index) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, NoExtra, 0);
    return self.noCfiConstAssumeCapacity(function);
}

pub fn noCfiValue(self: *Builder, function: Function.Index) Allocator.Error!Value {
    return (try self.noCfiConst(function)).toValue();
}

pub fn convConst(
    self: *Builder,
    val: Constant,
    ty: Type,
) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Cast, 0);
    return self.convConstAssumeCapacity(val, ty);
}

pub fn convValue(
    self: *Builder,
    val: Constant,
    ty: Type,
) Allocator.Error!Value {
    return (try self.convConst(val, ty)).toValue();
}

pub fn castConst(self: *Builder, tag: Constant.Tag, val: Constant, ty: Type) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Cast, 0);
    return self.castConstAssumeCapacity(tag, val, ty);
}

pub fn castValue(self: *Builder, tag: Constant.Tag, val: Constant, ty: Type) Allocator.Error!Value {
    return (try self.castConst(tag, val, ty)).toValue();
}

pub fn gepConst(
    self: *Builder,
    comptime kind: Constant.GetElementPtr.Kind,
    ty: Type,
    base: Constant,
    inrange: ?u16,
    indices: []const Constant,
) Allocator.Error!Constant {
    try self.ensureUnusedTypeCapacity(1, Type.Vector, 0);
    try self.ensureUnusedConstantCapacity(1, Constant.GetElementPtr, indices.len);
    return self.gepConstAssumeCapacity(kind, ty, base, inrange, indices);
}

pub fn gepValue(
    self: *Builder,
    comptime kind: Constant.GetElementPtr.Kind,
    ty: Type,
    base: Constant,
    inrange: ?u16,
    indices: []const Constant,
) Allocator.Error!Value {
    return (try self.gepConst(kind, ty, base, inrange, indices)).toValue();
}

pub fn binConst(
    self: *Builder,
    tag: Constant.Tag,
    lhs: Constant,
    rhs: Constant,
) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Binary, 0);
    return self.binConstAssumeCapacity(tag, lhs, rhs);
}

pub fn binValue(self: *Builder, tag: Constant.Tag, lhs: Constant, rhs: Constant) Allocator.Error!Value {
    return (try self.binConst(tag, lhs, rhs)).toValue();
}

pub fn asmConst(
    self: *Builder,
    ty: Type,
    info: Constant.Assembly.Info,
    assembly: String,
    constraints: String,
) Allocator.Error!Constant {
    try self.ensureUnusedConstantCapacity(1, Constant.Assembly, 0);
    return self.asmConstAssumeCapacity(ty, info, assembly, constraints);
}

pub fn asmValue(
    self: *Builder,
    ty: Type,
    info: Constant.Assembly.Info,
    assembly: String,
    constraints: String,
) Allocator.Error!Value {
    return (try self.asmConst(ty, info, assembly, constraints)).toValue();
}

pub fn dump(self: *Builder) void {
    self.print(std.io.getStdErr().writer()) catch {};
}

pub fn printToFile(self: *Builder, path: []const u8) Allocator.Error!bool {
    var file = std.fs.cwd().createFile(path, .{}) catch |err| {
        log.err("failed printing LLVM module to \"{s}\": {s}", .{ path, @errorName(err) });
        return false;
    };
    defer file.close();
    self.print(file.writer()) catch |err| {
        log.err("failed printing LLVM module to \"{s}\": {s}", .{ path, @errorName(err) });
        return false;
    };
    return true;
}

pub fn print(self: *Builder, writer: anytype) (@TypeOf(writer).Error || Allocator.Error)!void {
    var bw = std.io.bufferedWriter(writer);
    try self.printUnbuffered(bw.writer());
    try bw.flush();
}

fn WriterWithErrors(comptime BackingWriter: type, comptime ExtraErrors: type) type {
    return struct {
        backing_writer: BackingWriter,

        pub const Error = BackingWriter.Error || ExtraErrors;
        pub const Writer = std.io.Writer(*const Self, Error, write);

        const Self = @This();

        pub fn writer(self: *const Self) Writer {
            return .{ .context = self };
        }

        pub fn write(self: *const Self, bytes: []const u8) Error!usize {
            return self.backing_writer.write(bytes);
        }
    };
}
fn writerWithErrors(
    backing_writer: anytype,
    comptime ExtraErrors: type,
) WriterWithErrors(@TypeOf(backing_writer), ExtraErrors) {
    return .{ .backing_writer = backing_writer };
}

pub fn printUnbuffered(
    self: *Builder,
    backing_writer: anytype,
) (@TypeOf(backing_writer).Error || Allocator.Error)!void {
    const writer_with_errors = writerWithErrors(backing_writer, Allocator.Error);
    const writer = writer_with_errors.writer();

    var need_newline = false;
    var metadata_formatter: Metadata.Formatter = .{ .builder = self, .need_comma = undefined };
    defer metadata_formatter.map.deinit(self.gpa);

    if (self.source_filename != .none or self.data_layout != .none or self.target_triple != .none) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        if (self.source_filename != .none) try writer.print(
            \\; ModuleID = '{s}'
            \\source_filename = {"}
            \\
        , .{ self.source_filename.slice(self).?, self.source_filename.fmt(self) });
        if (self.data_layout != .none) try writer.print(
            \\target datalayout = {"}
            \\
        , .{self.data_layout.fmt(self)});
        if (self.target_triple != .none) try writer.print(
            \\target triple = {"}
            \\
        , .{self.target_triple.fmt(self)});
    }

    if (self.module_asm.items.len > 0) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        var line_it = std.mem.tokenizeScalar(u8, self.module_asm.items, '\n');
        while (line_it.next()) |line| {
            try writer.writeAll("module asm ");
            try printEscapedString(line, .always_quote, writer);
            try writer.writeByte('\n');
        }
    }

    if (self.types.count() > 0) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        for (self.types.keys(), self.types.values()) |id, ty| try writer.print(
            \\%{} = type {}
            \\
        , .{ id.fmt(self), ty.fmt(self) });
    }

    if (self.variables.items.len > 0) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        for (self.variables.items) |variable| {
            if (variable.global.getReplacement(self) != .none) continue;
            const global = variable.global.ptrConst(self);
            metadata_formatter.need_comma = true;
            defer metadata_formatter.need_comma = undefined;
            try writer.print(
                \\{} ={}{}{}{}{ }{}{ }{} {s} {%}{ }{, }{}
                \\
            , .{
                variable.global.fmt(self),
                Linkage.fmtOptional(if (global.linkage == .external and
                    variable.init != .no_init) null else global.linkage),
                global.preemption,
                global.visibility,
                global.dll_storage_class,
                variable.thread_local,
                global.unnamed_addr,
                global.addr_space,
                global.externally_initialized,
                @tagName(variable.mutability),
                global.type.fmt(self),
                variable.init.fmt(self),
                variable.alignment,
                try metadata_formatter.fmt("!dbg ", global.dbg),
            });
        }
    }

    if (self.aliases.items.len > 0) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        for (self.aliases.items) |alias| {
            if (alias.global.getReplacement(self) != .none) continue;
            const global = alias.global.ptrConst(self);
            metadata_formatter.need_comma = true;
            defer metadata_formatter.need_comma = undefined;
            try writer.print(
                \\{} ={}{}{}{}{ }{} alias {%}, {%}{}
                \\
            , .{
                alias.global.fmt(self),
                global.linkage,
                global.preemption,
                global.visibility,
                global.dll_storage_class,
                alias.thread_local,
                global.unnamed_addr,
                global.type.fmt(self),
                alias.aliasee.fmt(self),
                try metadata_formatter.fmt("!dbg ", global.dbg),
            });
        }
    }

    var attribute_groups: std.AutoArrayHashMapUnmanaged(Attributes, void) = .empty;
    defer attribute_groups.deinit(self.gpa);

    for (0.., self.functions.items) |function_i, function| {
        if (function.global.getReplacement(self) != .none) continue;
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        const function_index: Function.Index = @enumFromInt(function_i);
        const global = function.global.ptrConst(self);
        const params_len = global.type.functionParameters(self).len;
        const function_attributes = function.attributes.func(self);
        if (function_attributes != .none) try writer.print(
            \\; Function Attrs:{}
            \\
        , .{function_attributes.fmt(self)});
        try writer.print(
            \\{s}{}{}{}{}{}{"} {%} {}(
        , .{
            if (function.instructions.len > 0) "define" else "declare",
            global.linkage,
            global.preemption,
            global.visibility,
            global.dll_storage_class,
            function.call_conv,
            function.attributes.ret(self).fmt(self),
            global.type.functionReturn(self).fmt(self),
            function.global.fmt(self),
        });
        for (0..params_len) |arg| {
            if (arg > 0) try writer.writeAll(", ");
            try writer.print(
                \\{%}{"}
            , .{
                global.type.functionParameters(self)[arg].fmt(self),
                function.attributes.param(arg, self).fmt(self),
            });
            if (function.instructions.len > 0)
                try writer.print(" {}", .{function.arg(@intCast(arg)).fmt(function_index, self)})
            else
                try writer.print(" %{d}", .{arg});
        }
        switch (global.type.functionKind(self)) {
            .normal => {},
            .vararg => {
                if (params_len > 0) try writer.writeAll(", ");
                try writer.writeAll("...");
            },
        }
        try writer.print("){}{ }", .{ global.unnamed_addr, global.addr_space });
        if (function_attributes != .none) try writer.print(" #{d}", .{
            (try attribute_groups.getOrPutValue(self.gpa, function_attributes, {})).index,
        });
        {
            metadata_formatter.need_comma = false;
            defer metadata_formatter.need_comma = undefined;
            try writer.print("{ }{}", .{
                function.alignment,
                try metadata_formatter.fmt(" !dbg ", global.dbg),
            });
        }
        if (function.instructions.len > 0) {
            var block_incoming_len: u32 = undefined;
            try writer.writeAll(" {\n");
            var maybe_dbg_index: ?u32 = null;
            for (params_len..function.instructions.len) |instruction_i| {
                const instruction_index: Function.Instruction.Index = @enumFromInt(instruction_i);
                const instruction = function.instructions.get(@intFromEnum(instruction_index));
                if (function.debug_locations.get(instruction_index)) |debug_location| switch (debug_location) {
                    .no_location => maybe_dbg_index = null,
                    .location => |location| {
                        const gop = try metadata_formatter.map.getOrPut(self.gpa, .{
                            .debug_location = location,
                        });
                        maybe_dbg_index = @intCast(gop.index);
                    },
                };
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
                    .srem,
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => |tag| {
                        const extra = function.extraData(Function.Instruction.Binary, instruction.data);
                        try writer.print("  %{} = {s} {%}, {}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.lhs.fmt(function_index, self),
                            extra.rhs.fmt(function_index, self),
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
                    .trunc,
                    .uitofp,
                    .zext,
                    => |tag| {
                        const extra = function.extraData(Function.Instruction.Cast, instruction.data);
                        try writer.print("  %{} = {s} {%} to {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.val.fmt(function_index, self),
                            extra.type.fmt(self),
                        });
                    },
                    .alloca,
                    .@"alloca inalloca",
                    => |tag| {
                        const extra = function.extraData(Function.Instruction.Alloca, instruction.data);
                        try writer.print("  %{} = {s} {%}{,%}{, }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.type.fmt(self),
                            Value.fmt(switch (extra.len) {
                                .@"1" => .none,
                                else => extra.len,
                            }, function_index, self),
                            extra.info.alignment,
                            extra.info.addr_space,
                        });
                    },
                    .arg => unreachable,
                    .atomicrmw => |tag| {
                        const extra =
                            function.extraData(Function.Instruction.AtomicRmw, instruction.data);
                        try writer.print("  %{} = {s}{ } {s} {%}, {%}{ }{ }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.info.access_kind,
                            @tagName(extra.info.atomic_rmw_operation),
                            extra.ptr.fmt(function_index, self),
                            extra.val.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.alignment,
                        });
                    },
                    .block => {
                        block_incoming_len = instruction.data;
                        const name = instruction_index.name(&function);
                        if (@intFromEnum(instruction_index) > params_len)
                            try writer.writeByte('\n');
                        try writer.print("{}:\n", .{name.fmt(self)});
                        continue;
                    },
                    .br => |tag| {
                        const target: Function.Block.Index = @enumFromInt(instruction.data);
                        try writer.print("  {s} {%}", .{
                            @tagName(tag), target.toInst(&function).fmt(function_index, self),
                        });
                    },
                    .br_cond => {
                        const extra = function.extraData(Function.Instruction.BrCond, instruction.data);
                        try writer.print("  br {%}, {%}, {%}", .{
                            extra.cond.fmt(function_index, self),
                            extra.then.toInst(&function).fmt(function_index, self),
                            extra.@"else".toInst(&function).fmt(function_index, self),
                        });
                        metadata_formatter.need_comma = true;
                        defer metadata_formatter.need_comma = undefined;
                        switch (extra.weights) {
                            .none => {},
                            .unpredictable => try writer.writeAll("!unpredictable !{}"),
                            _ => try writer.print("{}", .{
                                try metadata_formatter.fmt("!prof ", @as(Metadata, @enumFromInt(@intFromEnum(extra.weights)))),
                            }),
                        }
                    },
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => |tag| {
                        var extra =
                            function.extraDataTrail(Function.Instruction.Call, instruction.data);
                        const args = extra.trail.next(extra.data.args_len, Value, &function);
                        try writer.writeAll("  ");
                        const ret_ty = extra.data.ty.functionReturn(self);
                        switch (ret_ty) {
                            .void => {},
                            else => try writer.print("%{} = ", .{
                                instruction_index.name(&function).fmt(self),
                            }),
                            .none => unreachable,
                        }
                        try writer.print("{s}{}{}{} {%} {}(", .{
                            @tagName(tag),
                            extra.data.info.call_conv,
                            extra.data.attributes.ret(self).fmt(self),
                            extra.data.callee.typeOf(function_index, self).pointerAddrSpace(self),
                            switch (extra.data.ty.functionKind(self)) {
                                .normal => ret_ty,
                                .vararg => extra.data.ty,
                            }.fmt(self),
                            extra.data.callee.fmt(function_index, self),
                        });
                        for (0.., args) |arg_index, arg| {
                            if (arg_index > 0) try writer.writeAll(", ");
                            metadata_formatter.need_comma = false;
                            defer metadata_formatter.need_comma = undefined;
                            try writer.print("{%}{}{}", .{
                                arg.typeOf(function_index, self).fmt(self),
                                extra.data.attributes.param(arg_index, self).fmt(self),
                                try metadata_formatter.fmtLocal(" ", arg, function_index),
                            });
                        }
                        try writer.writeByte(')');
                        if (extra.data.info.has_op_bundle_cold) {
                            try writer.writeAll(" [ \"cold\"() ]");
                        }
                        const call_function_attributes = extra.data.attributes.func(self);
                        if (call_function_attributes != .none) try writer.print(" #{d}", .{
                            (try attribute_groups.getOrPutValue(
                                self.gpa,
                                call_function_attributes,
                                {},
                            )).index,
                        });
                    },
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => |tag| {
                        const extra =
                            function.extraData(Function.Instruction.CmpXchg, instruction.data);
                        try writer.print("  %{} = {s}{ } {%}, {%}, {%}{ }{ }{ }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.info.access_kind,
                            extra.ptr.fmt(function_index, self),
                            extra.cmp.fmt(function_index, self),
                            extra.new.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.failure_ordering,
                            extra.info.alignment,
                        });
                    },
                    .extractelement => |tag| {
                        const extra =
                            function.extraData(Function.Instruction.ExtractElement, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.val.fmt(function_index, self),
                            extra.index.fmt(function_index, self),
                        });
                    },
                    .extractvalue => |tag| {
                        var extra = function.extraDataTrail(
                            Function.Instruction.ExtractValue,
                            instruction.data,
                        );
                        const indices = extra.trail.next(extra.data.indices_len, u32, &function);
                        try writer.print("  %{} = {s} {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.data.val.fmt(function_index, self),
                        });
                        for (indices) |index| try writer.print(", {d}", .{index});
                    },
                    .fence => |tag| {
                        const info: MemoryAccessInfo = @bitCast(instruction.data);
                        try writer.print("  {s}{ }{ }", .{
                            @tagName(tag),
                            info.sync_scope,
                            info.success_ordering,
                        });
                    },
                    .fneg,
                    .@"fneg fast",
                    => |tag| {
                        const val: Value = @enumFromInt(instruction.data);
                        try writer.print("  %{} = {s} {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            val.fmt(function_index, self),
                        });
                    },
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => |tag| {
                        var extra = function.extraDataTrail(
                            Function.Instruction.GetElementPtr,
                            instruction.data,
                        );
                        const indices = extra.trail.next(extra.data.indices_len, Value, &function);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.data.type.fmt(self),
                            extra.data.base.fmt(function_index, self),
                        });
                        for (indices) |index| try writer.print(", {%}", .{
                            index.fmt(function_index, self),
                        });
                    },
                    .indirectbr => |tag| {
                        var extra =
                            function.extraDataTrail(Function.Instruction.IndirectBr, instruction.data);
                        const targets =
                            extra.trail.next(extra.data.targets_len, Function.Block.Index, &function);
                        try writer.print("  {s} {%}, [", .{
                            @tagName(tag),
                            extra.data.addr.fmt(function_index, self),
                        });
                        for (0.., targets) |target_index, target| {
                            if (target_index > 0) try writer.writeAll(", ");
                            try writer.print("{%}", .{
                                target.toInst(&function).fmt(function_index, self),
                            });
                        }
                        try writer.writeByte(']');
                    },
                    .insertelement => |tag| {
                        const extra =
                            function.extraData(Function.Instruction.InsertElement, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.val.fmt(function_index, self),
                            extra.elem.fmt(function_index, self),
                            extra.index.fmt(function_index, self),
                        });
                    },
                    .insertvalue => |tag| {
                        var extra =
                            function.extraDataTrail(Function.Instruction.InsertValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, &function);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.data.val.fmt(function_index, self),
                            extra.data.elem.fmt(function_index, self),
                        });
                        for (indices) |index| try writer.print(", {d}", .{index});
                    },
                    .load,
                    .@"load atomic",
                    => |tag| {
                        const extra = function.extraData(Function.Instruction.Load, instruction.data);
                        try writer.print("  %{} = {s}{ } {%}, {%}{ }{ }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.info.access_kind,
                            extra.type.fmt(self),
                            extra.ptr.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.alignment,
                        });
                    },
                    .phi,
                    .@"phi fast",
                    => |tag| {
                        var extra = function.extraDataTrail(Function.Instruction.Phi, instruction.data);
                        const vals = extra.trail.next(block_incoming_len, Value, &function);
                        const blocks =
                            extra.trail.next(block_incoming_len, Function.Block.Index, &function);
                        try writer.print("  %{} = {s} {%} ", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            vals[0].typeOf(function_index, self).fmt(self),
                        });
                        for (0.., vals, blocks) |incoming_index, incoming_val, incoming_block| {
                            if (incoming_index > 0) try writer.writeAll(", ");
                            try writer.print("[ {}, {} ]", .{
                                incoming_val.fmt(function_index, self),
                                incoming_block.toInst(&function).fmt(function_index, self),
                            });
                        }
                    },
                    .ret => |tag| {
                        const val: Value = @enumFromInt(instruction.data);
                        try writer.print("  {s} {%}", .{
                            @tagName(tag),
                            val.fmt(function_index, self),
                        });
                    },
                    .@"ret void",
                    .@"unreachable",
                    => |tag| try writer.print("  {s}", .{@tagName(tag)}),
                    .select,
                    .@"select fast",
                    => |tag| {
                        const extra = function.extraData(Function.Instruction.Select, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.cond.fmt(function_index, self),
                            extra.lhs.fmt(function_index, self),
                            extra.rhs.fmt(function_index, self),
                        });
                    },
                    .shufflevector => |tag| {
                        const extra =
                            function.extraData(Function.Instruction.ShuffleVector, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.lhs.fmt(function_index, self),
                            extra.rhs.fmt(function_index, self),
                            extra.mask.fmt(function_index, self),
                        });
                    },
                    .store,
                    .@"store atomic",
                    => |tag| {
                        const extra = function.extraData(Function.Instruction.Store, instruction.data);
                        try writer.print("  {s}{ } {%}, {%}{ }{ }{, }", .{
                            @tagName(tag),
                            extra.info.access_kind,
                            extra.val.fmt(function_index, self),
                            extra.ptr.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.alignment,
                        });
                    },
                    .@"switch" => |tag| {
                        var extra =
                            function.extraDataTrail(Function.Instruction.Switch, instruction.data);
                        const vals = extra.trail.next(extra.data.cases_len, Constant, &function);
                        const blocks =
                            extra.trail.next(extra.data.cases_len, Function.Block.Index, &function);
                        try writer.print("  {s} {%}, {%} [\n", .{
                            @tagName(tag),
                            extra.data.val.fmt(function_index, self),
                            extra.data.default.toInst(&function).fmt(function_index, self),
                        });
                        for (vals, blocks) |case_val, case_block| try writer.print(
                            "    {%}, {%}\n",
                            .{
                                case_val.fmt(self),
                                case_block.toInst(&function).fmt(function_index, self),
                            },
                        );
                        try writer.writeAll("  ]");
                        metadata_formatter.need_comma = true;
                        defer metadata_formatter.need_comma = undefined;
                        switch (extra.data.weights) {
                            .none => {},
                            .unpredictable => try writer.writeAll("!unpredictable !{}"),
                            _ => try writer.print("{}", .{
                                try metadata_formatter.fmt("!prof ", @as(Metadata, @enumFromInt(@intFromEnum(extra.data.weights)))),
                            }),
                        }
                    },
                    .va_arg => |tag| {
                        const extra = function.extraData(Function.Instruction.VaArg, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tagName(tag),
                            extra.list.fmt(function_index, self),
                            extra.type.fmt(self),
                        });
                    },
                }

                if (maybe_dbg_index) |dbg_index| {
                    try writer.print(", !dbg !{}", .{dbg_index});
                }
                try writer.writeByte('\n');
            }
            try writer.writeByte('}');
        }
        try writer.writeByte('\n');
    }

    if (attribute_groups.count() > 0) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        for (0.., attribute_groups.keys()) |attribute_group_index, attribute_group|
            try writer.print(
                \\attributes #{d} = {{{#"} }}
                \\
            , .{ attribute_group_index, attribute_group.fmt(self) });
    }

    if (self.metadata_named.count() > 0) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        for (self.metadata_named.keys(), self.metadata_named.values()) |name, data| {
            const elements: []const Metadata =
                @ptrCast(self.metadata_extra.items[data.index..][0..data.len]);
            try writer.writeByte('!');
            try printEscapedString(name.slice(self), .quote_unless_valid_identifier, writer);
            try writer.writeAll(" = !{");
            metadata_formatter.need_comma = false;
            defer metadata_formatter.need_comma = undefined;
            for (elements) |element| try writer.print("{}", .{try metadata_formatter.fmt("", element)});
            try writer.writeAll("}\n");
        }
    }

    if (metadata_formatter.map.count() > 0) {
        if (need_newline) try writer.writeByte('\n') else need_newline = true;
        var metadata_index: usize = 0;
        while (metadata_index < metadata_formatter.map.count()) : (metadata_index += 1) {
            @setEvalBranchQuota(10_000);
            try writer.print("!{} = ", .{metadata_index});
            metadata_formatter.need_comma = false;
            defer metadata_formatter.need_comma = undefined;

            const key = metadata_formatter.map.keys()[metadata_index];
            const metadata_item = switch (key) {
                .debug_location => |location| {
                    try metadata_formatter.specialized(.@"!", .DILocation, .{
                        .line = location.line,
                        .column = location.column,
                        .scope = location.scope,
                        .inlinedAt = location.inlined_at,
                        .isImplicitCode = false,
                    }, writer);
                    continue;
                },
                .metadata => |metadata| self.metadata_items.get(@intFromEnum(metadata)),
            };

            switch (metadata_item.tag) {
                .none, .expression, .constant => unreachable,
                .file => {
                    const extra = self.metadataExtraData(Metadata.File, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIFile, .{
                        .filename = extra.filename,
                        .directory = extra.directory,
                        .checksumkind = null,
                        .checksum = null,
                        .source = null,
                    }, writer);
                },
                .compile_unit,
                .@"compile_unit optimized",
                => |kind| {
                    const extra = self.metadataExtraData(Metadata.CompileUnit, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DICompileUnit, .{
                        .language = .DW_LANG_C99,
                        .file = extra.file,
                        .producer = extra.producer,
                        .isOptimized = switch (kind) {
                            .compile_unit => false,
                            .@"compile_unit optimized" => true,
                            else => unreachable,
                        },
                        .flags = null,
                        .runtimeVersion = 0,
                        .splitDebugFilename = null,
                        .emissionKind = .FullDebug,
                        .enums = extra.enums,
                        .retainedTypes = null,
                        .globals = extra.globals,
                        .imports = null,
                        .macros = null,
                        .dwoId = null,
                        .splitDebugInlining = false,
                        .debugInfoForProfiling = null,
                        .nameTableKind = null,
                        .rangesBaseAddress = null,
                        .sysroot = null,
                        .sdk = null,
                    }, writer);
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
                    const extra = self.metadataExtraData(Metadata.Subprogram, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DISubprogram, .{
                        .name = extra.name,
                        .linkageName = extra.linkage_name,
                        .scope = extra.file,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .scopeLine = extra.scope_line,
                        .containingType = null,
                        .virtualIndex = null,
                        .thisAdjustment = null,
                        .flags = extra.di_flags,
                        .spFlags = @as(Metadata.Subprogram.DISPFlags, @bitCast(@as(u32, @as(u3, @intCast(
                            @intFromEnum(kind) - @intFromEnum(Metadata.Tag.subprogram),
                        ))) << 2)),
                        .unit = extra.compile_unit,
                        .templateParams = null,
                        .declaration = null,
                        .retainedNodes = null,
                        .thrownTypes = null,
                        .annotations = null,
                        .targetFuncName = null,
                    }, writer);
                },
                .lexical_block => {
                    const extra = self.metadataExtraData(Metadata.LexicalBlock, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DILexicalBlock, .{
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .column = extra.column,
                    }, writer);
                },
                .location => {
                    const extra = self.metadataExtraData(Metadata.Location, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DILocation, .{
                        .line = extra.line,
                        .column = extra.column,
                        .scope = extra.scope,
                        .inlinedAt = extra.inlined_at,
                        .isImplicitCode = false,
                    }, writer);
                },
                .basic_bool_type,
                .basic_unsigned_type,
                .basic_signed_type,
                .basic_float_type,
                => |kind| {
                    const extra = self.metadataExtraData(Metadata.BasicType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIBasicType, .{
                        .tag = null,
                        .name = switch (extra.name) {
                            .none => null,
                            else => extra.name,
                        },
                        .size = extra.bitSize(),
                        .@"align" = null,
                        .encoding = @as(enum {
                            DW_ATE_boolean,
                            DW_ATE_unsigned,
                            DW_ATE_signed,
                            DW_ATE_float,
                        }, switch (kind) {
                            .basic_bool_type => .DW_ATE_boolean,
                            .basic_unsigned_type => .DW_ATE_unsigned,
                            .basic_signed_type => .DW_ATE_signed,
                            .basic_float_type => .DW_ATE_float,
                            else => unreachable,
                        }),
                        .flags = null,
                    }, writer);
                },
                .composite_struct_type,
                .composite_union_type,
                .composite_enumeration_type,
                .composite_array_type,
                .composite_vector_type,
                => |kind| {
                    const extra = self.metadataExtraData(Metadata.CompositeType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DICompositeType, .{
                        .tag = @as(enum {
                            DW_TAG_structure_type,
                            DW_TAG_union_type,
                            DW_TAG_enumeration_type,
                            DW_TAG_array_type,
                        }, switch (kind) {
                            .composite_struct_type => .DW_TAG_structure_type,
                            .composite_union_type => .DW_TAG_union_type,
                            .composite_enumeration_type => .DW_TAG_enumeration_type,
                            .composite_array_type, .composite_vector_type => .DW_TAG_array_type,
                            else => unreachable,
                        }),
                        .name = switch (extra.name) {
                            .none => null,
                            else => extra.name,
                        },
                        .scope = extra.scope,
                        .file = null,
                        .line = null,
                        .baseType = extra.underlying_type,
                        .size = extra.bitSize(),
                        .@"align" = extra.bitAlign(),
                        .offset = null,
                        .flags = null,
                        .elements = extra.fields_tuple,
                        .runtimeLang = null,
                        .vtableHolder = null,
                        .templateParams = null,
                        .identifier = null,
                        .discriminator = null,
                        .dataLocation = null,
                        .associated = null,
                        .allocated = null,
                        .rank = null,
                        .annotations = null,
                    }, writer);
                },
                .derived_pointer_type,
                .derived_member_type,
                => |kind| {
                    const extra = self.metadataExtraData(Metadata.DerivedType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIDerivedType, .{
                        .tag = @as(enum {
                            DW_TAG_pointer_type,
                            DW_TAG_member,
                        }, switch (kind) {
                            .derived_pointer_type => .DW_TAG_pointer_type,
                            .derived_member_type => .DW_TAG_member,
                            else => unreachable,
                        }),
                        .name = switch (extra.name) {
                            .none => null,
                            else => extra.name,
                        },
                        .scope = extra.scope,
                        .file = null,
                        .line = null,
                        .baseType = extra.underlying_type,
                        .size = extra.bitSize(),
                        .@"align" = extra.bitAlign(),
                        .offset = switch (extra.bitOffset()) {
                            0 => null,
                            else => |bit_offset| bit_offset,
                        },
                        .flags = null,
                        .extraData = null,
                        .dwarfAddressSpace = null,
                        .annotations = null,
                    }, writer);
                },
                .subroutine_type => {
                    const extra = self.metadataExtraData(Metadata.SubroutineType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DISubroutineType, .{
                        .flags = null,
                        .cc = null,
                        .types = extra.types_tuple,
                    }, writer);
                },
                .enumerator_unsigned,
                .enumerator_signed_positive,
                .enumerator_signed_negative,
                => |kind| {
                    const extra = self.metadataExtraData(Metadata.Enumerator, metadata_item.data);

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
                        std.heap.stackFallback(@sizeOf(ExpectedContents), self.gpa);
                    const allocator = stack.get();

                    const limbs = self.metadata_limbs.items[extra.limbs_index..][0..extra.limbs_len];
                    const bigint: std.math.big.int.Const = .{
                        .limbs = limbs,
                        .positive = switch (kind) {
                            .enumerator_unsigned,
                            .enumerator_signed_positive,
                            => true,
                            .enumerator_signed_negative => false,
                            else => unreachable,
                        },
                    };
                    const str = try bigint.toStringAlloc(allocator, 10, undefined);
                    defer allocator.free(str);

                    try metadata_formatter.specialized(.@"!", .DIEnumerator, .{
                        .name = extra.name,
                        .value = str,
                        .isUnsigned = switch (kind) {
                            .enumerator_unsigned => true,
                            .enumerator_signed_positive,
                            .enumerator_signed_negative,
                            => false,
                            else => unreachable,
                        },
                    }, writer);
                },
                .subrange => {
                    const extra = self.metadataExtraData(Metadata.Subrange, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DISubrange, .{
                        .count = extra.count,
                        .lowerBound = extra.lower_bound,
                        .upperBound = null,
                        .stride = null,
                    }, writer);
                },
                .tuple => {
                    var extra = self.metadataExtraDataTrail(Metadata.Tuple, metadata_item.data);
                    const elements = extra.trail.next(extra.data.elements_len, Metadata, self);
                    try writer.writeAll("!{");
                    for (elements) |element| try writer.print("{[element]%}", .{
                        .element = try metadata_formatter.fmt("", element),
                    });
                    try writer.writeAll("}\n");
                },
                .str_tuple => {
                    var extra = self.metadataExtraDataTrail(Metadata.StrTuple, metadata_item.data);
                    const elements = extra.trail.next(extra.data.elements_len, Metadata, self);
                    try writer.print("!{{{[str]%}", .{
                        .str = try metadata_formatter.fmt("", extra.data.str),
                    });
                    for (elements) |element| try writer.print("{[element]%}", .{
                        .element = try metadata_formatter.fmt("", element),
                    });
                    try writer.writeAll("}\n");
                },
                .module_flag => {
                    const extra = self.metadataExtraData(Metadata.ModuleFlag, metadata_item.data);
                    try writer.print("!{{{[behavior]%}{[name]%}{[constant]%}}}\n", .{
                        .behavior = try metadata_formatter.fmt("", extra.behavior),
                        .name = try metadata_formatter.fmt("", extra.name),
                        .constant = try metadata_formatter.fmt("", extra.constant),
                    });
                },
                .local_var => {
                    const extra = self.metadataExtraData(Metadata.LocalVar, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DILocalVariable, .{
                        .name = extra.name,
                        .arg = null,
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .flags = null,
                        .@"align" = null,
                        .annotations = null,
                    }, writer);
                },
                .parameter => {
                    const extra = self.metadataExtraData(Metadata.Parameter, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DILocalVariable, .{
                        .name = extra.name,
                        .arg = extra.arg_no,
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .flags = null,
                        .@"align" = null,
                        .annotations = null,
                    }, writer);
                },
                .global_var,
                .@"global_var local",
                => |kind| {
                    const extra = self.metadataExtraData(Metadata.GlobalVar, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DIGlobalVariable, .{
                        .name = extra.name,
                        .linkageName = extra.linkage_name,
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .isLocal = switch (kind) {
                            .global_var => false,
                            .@"global_var local" => true,
                            else => unreachable,
                        },
                        .isDefinition = true,
                        .declaration = null,
                        .templateParams = null,
                        .@"align" = null,
                        .annotations = null,
                    }, writer);
                },
                .global_var_expression => {
                    const extra =
                        self.metadataExtraData(Metadata.GlobalVarExpression, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIGlobalVariableExpression, .{
                        .@"var" = extra.variable,
                        .expr = extra.expression,
                    }, writer);
                },
            }
        }
    }
}

const NoExtra = struct {};

fn isValidIdentifier(id: []const u8) bool {
    for (id, 0..) |byte, index| switch (byte) {
        '$', '-', '.', 'A'...'Z', '_', 'a'...'z' => {},
        '0'...'9' => if (index == 0) return false,
        else => return false,
    };
    return true;
}

const QuoteBehavior = enum { always_quote, quote_unless_valid_identifier };
fn printEscapedString(
    slice: []const u8,
    quotes: QuoteBehavior,
    writer: anytype,
) @TypeOf(writer).Error!void {
    const need_quotes = switch (quotes) {
        .always_quote => true,
        .quote_unless_valid_identifier => !isValidIdentifier(slice),
    };
    if (need_quotes) try writer.writeByte('"');
    for (slice) |byte| switch (byte) {
        '\\' => try writer.writeAll("\\\\"),
        ' '...'"' - 1, '"' + 1...'\\' - 1, '\\' + 1...'~' => try writer.writeByte(byte),
        else => try writer.print("\\{X:0>2}", .{byte}),
    };
    if (need_quotes) try writer.writeByte('"');
}

fn ensureUnusedGlobalCapacity(self: *Builder, name: StrtabString) Allocator.Error!void {
    try self.strtab_string_map.ensureUnusedCapacity(self.gpa, 1);
    if (name.slice(self)) |id| {
        const count: usize = comptime std.fmt.count("{d}", .{std.math.maxInt(u32)});
        try self.strtab_string_bytes.ensureUnusedCapacity(self.gpa, id.len + count);
    }
    try self.strtab_string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.globals.ensureUnusedCapacity(self.gpa, 1);
    try self.next_unique_global_id.ensureUnusedCapacity(self.gpa, 1);
}

fn fnTypeAssumeCapacity(
    self: *Builder,
    ret: Type,
    params: []const Type,
    comptime kind: Type.Function.Kind,
) Type {
    const tag: Type.Tag = switch (kind) {
        .normal => .function,
        .vararg => .vararg_function,
    };
    const Key = struct { ret: Type, params: []const Type };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(comptime std.hash.uint32(@intFromEnum(tag)));
            hasher.update(std.mem.asBytes(&key.ret));
            hasher.update(std.mem.sliceAsBytes(key.params));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            if (rhs_data.tag != tag) return false;
            var rhs_extra = ctx.builder.typeExtraDataTrail(Type.Function, rhs_data.data);
            const rhs_params = rhs_extra.trail.next(rhs_extra.data.params_len, Type, ctx.builder);
            return lhs_key.ret == rhs_extra.data.ret and std.mem.eql(Type, lhs_key.params, rhs_params);
        }
    };
    const gop = self.type_map.getOrPutAssumeCapacityAdapted(
        Key{ .ret = ret, .params = params },
        Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addTypeExtraAssumeCapacity(Type.Function{
                .ret = ret,
                .params_len = @intCast(params.len),
            }),
        });
        self.type_extra.appendSliceAssumeCapacity(@ptrCast(params));
    }
    return @enumFromInt(gop.index);
}

fn intTypeAssumeCapacity(self: *Builder, bits: u24) Type {
    assert(bits > 0);
    const result = self.getOrPutTypeNoExtraAssumeCapacity(.{ .tag = .integer, .data = bits });
    return result.type;
}

fn ptrTypeAssumeCapacity(self: *Builder, addr_space: AddrSpace) Type {
    const result = self.getOrPutTypeNoExtraAssumeCapacity(
        .{ .tag = .pointer, .data = @intFromEnum(addr_space) },
    );
    return result.type;
}

fn vectorTypeAssumeCapacity(
    self: *Builder,
    comptime kind: Type.Vector.Kind,
    len: u32,
    child: Type,
) Type {
    assert(child.isFloatingPoint() or child.isInteger(self) or child.isPointer(self));
    const tag: Type.Tag = switch (kind) {
        .normal => .vector,
        .scalable => .scalable_vector,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Type.Vector) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(tag)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Type.Vector, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            return rhs_data.tag == tag and
                std.meta.eql(lhs_key, ctx.builder.typeExtraData(Type.Vector, rhs_data.data));
        }
    };
    const data = Type.Vector{ .len = len, .child = child };
    const gop = self.type_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addTypeExtraAssumeCapacity(data),
        });
    }
    return @enumFromInt(gop.index);
}

fn arrayTypeAssumeCapacity(self: *Builder, len: u64, child: Type) Type {
    if (std.math.cast(u32, len)) |small_len| {
        const Adapter = struct {
            builder: *const Builder,
            pub fn hash(_: @This(), key: Type.Vector) u32 {
                return @truncate(std.hash.Wyhash.hash(
                    comptime std.hash.uint32(@intFromEnum(Type.Tag.small_array)),
                    std.mem.asBytes(&key),
                ));
            }
            pub fn eql(ctx: @This(), lhs_key: Type.Vector, _: void, rhs_index: usize) bool {
                const rhs_data = ctx.builder.type_items.items[rhs_index];
                return rhs_data.tag == .small_array and
                    std.meta.eql(lhs_key, ctx.builder.typeExtraData(Type.Vector, rhs_data.data));
            }
        };
        const data = Type.Vector{ .len = small_len, .child = child };
        const gop = self.type_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
        if (!gop.found_existing) {
            gop.key_ptr.* = {};
            gop.value_ptr.* = {};
            self.type_items.appendAssumeCapacity(.{
                .tag = .small_array,
                .data = self.addTypeExtraAssumeCapacity(data),
            });
        }
        return @enumFromInt(gop.index);
    } else {
        const Adapter = struct {
            builder: *const Builder,
            pub fn hash(_: @This(), key: Type.Array) u32 {
                return @truncate(std.hash.Wyhash.hash(
                    comptime std.hash.uint32(@intFromEnum(Type.Tag.array)),
                    std.mem.asBytes(&key),
                ));
            }
            pub fn eql(ctx: @This(), lhs_key: Type.Array, _: void, rhs_index: usize) bool {
                const rhs_data = ctx.builder.type_items.items[rhs_index];
                return rhs_data.tag == .array and
                    std.meta.eql(lhs_key, ctx.builder.typeExtraData(Type.Array, rhs_data.data));
            }
        };
        const data = Type.Array{
            .len_lo = @truncate(len),
            .len_hi = @intCast(len >> 32),
            .child = child,
        };
        const gop = self.type_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
        if (!gop.found_existing) {
            gop.key_ptr.* = {};
            gop.value_ptr.* = {};
            self.type_items.appendAssumeCapacity(.{
                .tag = .array,
                .data = self.addTypeExtraAssumeCapacity(data),
            });
        }
        return @enumFromInt(gop.index);
    }
}

fn structTypeAssumeCapacity(
    self: *Builder,
    comptime kind: Type.Structure.Kind,
    fields: []const Type,
) Type {
    const tag: Type.Tag = switch (kind) {
        .normal => .structure,
        .@"packed" => .packed_structure,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: []const Type) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(tag)),
                std.mem.sliceAsBytes(key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: []const Type, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            if (rhs_data.tag != tag) return false;
            var rhs_extra = ctx.builder.typeExtraDataTrail(Type.Structure, rhs_data.data);
            const rhs_fields = rhs_extra.trail.next(rhs_extra.data.fields_len, Type, ctx.builder);
            return std.mem.eql(Type, lhs_key, rhs_fields);
        }
    };
    const gop = self.type_map.getOrPutAssumeCapacityAdapted(fields, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addTypeExtraAssumeCapacity(Type.Structure{
                .fields_len = @intCast(fields.len),
            }),
        });
        self.type_extra.appendSliceAssumeCapacity(@ptrCast(fields));
    }
    return @enumFromInt(gop.index);
}

fn opaqueTypeAssumeCapacity(self: *Builder, name: String) Type {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: String) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Type.Tag.named_structure)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: String, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            return rhs_data.tag == .named_structure and
                lhs_key == ctx.builder.typeExtraData(Type.NamedStructure, rhs_data.data).id;
        }
    };
    var id = name;
    if (name == .empty) {
        id = self.next_unnamed_type;
        assert(id != .none);
        self.next_unnamed_type = @enumFromInt(@intFromEnum(id) + 1);
    } else assert(!name.isAnon());
    while (true) {
        const type_gop = self.types.getOrPutAssumeCapacity(id);
        if (!type_gop.found_existing) {
            const gop = self.type_map.getOrPutAssumeCapacityAdapted(id, Adapter{ .builder = self });
            assert(!gop.found_existing);
            gop.key_ptr.* = {};
            gop.value_ptr.* = {};
            self.type_items.appendAssumeCapacity(.{
                .tag = .named_structure,
                .data = self.addTypeExtraAssumeCapacity(Type.NamedStructure{
                    .id = id,
                    .body = .none,
                }),
            });
            const result: Type = @enumFromInt(gop.index);
            type_gop.value_ptr.* = result;
            return result;
        }

        const unique_gop = self.next_unique_type_id.getOrPutAssumeCapacity(name);
        if (!unique_gop.found_existing) unique_gop.value_ptr.* = 2;
        id = self.fmtAssumeCapacity("{s}.{d}", .{ name.slice(self).?, unique_gop.value_ptr.* });
        unique_gop.value_ptr.* += 1;
    }
}

fn ensureUnusedTypeCapacity(
    self: *Builder,
    count: usize,
    comptime Extra: type,
    trail_len: usize,
) Allocator.Error!void {
    try self.type_map.ensureUnusedCapacity(self.gpa, count);
    try self.type_items.ensureUnusedCapacity(self.gpa, count);
    try self.type_extra.ensureUnusedCapacity(
        self.gpa,
        count * (@typeInfo(Extra).@"struct".fields.len + trail_len),
    );
}

fn getOrPutTypeNoExtraAssumeCapacity(self: *Builder, item: Type.Item) struct { new: bool, type: Type } {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Type.Item) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Type.Tag.simple)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Type.Item, _: void, rhs_index: usize) bool {
            const lhs_bits: u32 = @bitCast(lhs_key);
            const rhs_bits: u32 = @bitCast(ctx.builder.type_items.items[rhs_index]);
            return lhs_bits == rhs_bits;
        }
    };
    const gop = self.type_map.getOrPutAssumeCapacityAdapted(item, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.appendAssumeCapacity(item);
    }
    return .{ .new = !gop.found_existing, .type = @enumFromInt(gop.index) };
}

fn addTypeExtraAssumeCapacity(self: *Builder, extra: anytype) Type.Item.ExtraIndex {
    const result: Type.Item.ExtraIndex = @intCast(self.type_extra.items.len);
    inline for (@typeInfo(@TypeOf(extra)).@"struct".fields) |field| {
        const value = @field(extra, field.name);
        self.type_extra.appendAssumeCapacity(switch (field.type) {
            u32 => value,
            String, Type => @intFromEnum(value),
            else => @compileError("bad field type: " ++ field.name ++ ": " ++ @typeName(field.type)),
        });
    }
    return result;
}

const TypeExtraDataTrail = struct {
    index: Type.Item.ExtraIndex,

    fn nextMut(self: *TypeExtraDataTrail, len: u32, comptime Item: type, builder: *Builder) []Item {
        const items: []Item = @ptrCast(builder.type_extra.items[self.index..][0..len]);
        self.index += @intCast(len);
        return items;
    }

    fn next(
        self: *TypeExtraDataTrail,
        len: u32,
        comptime Item: type,
        builder: *const Builder,
    ) []const Item {
        const items: []const Item = @ptrCast(builder.type_extra.items[self.index..][0..len]);
        self.index += @intCast(len);
        return items;
    }
};

fn typeExtraDataTrail(
    self: *const Builder,
    comptime T: type,
    index: Type.Item.ExtraIndex,
) struct { data: T, trail: TypeExtraDataTrail } {
    var result: T = undefined;
    const fields = @typeInfo(T).@"struct".fields;
    inline for (fields, self.type_extra.items[index..][0..fields.len]) |field, value|
        @field(result, field.name) = switch (field.type) {
            u32 => value,
            String, Type => @enumFromInt(value),
            else => @compileError("bad field type: " ++ @typeName(field.type)),
        };
    return .{
        .data = result,
        .trail = .{ .index = index + @as(Type.Item.ExtraIndex, @intCast(fields.len)) },
    };
}

fn typeExtraData(self: *const Builder, comptime T: type, index: Type.Item.ExtraIndex) T {
    return self.typeExtraDataTrail(T, index).data;
}

fn attrGeneric(self: *Builder, data: []const u32) Allocator.Error!u32 {
    try self.attributes_map.ensureUnusedCapacity(self.gpa, 1);
    try self.attributes_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.attributes_extra.ensureUnusedCapacity(self.gpa, data.len);

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: []const u32) u32 {
            return @truncate(std.hash.Wyhash.hash(1, std.mem.sliceAsBytes(key)));
        }
        pub fn eql(ctx: @This(), lhs_key: []const u32, _: void, rhs_index: usize) bool {
            const start = ctx.builder.attributes_indices.items[rhs_index];
            const end = ctx.builder.attributes_indices.items[rhs_index + 1];
            return std.mem.eql(u32, lhs_key, ctx.builder.attributes_extra.items[start..end]);
        }
    };
    const gop = self.attributes_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        self.attributes_extra.appendSliceAssumeCapacity(data);
        self.attributes_indices.appendAssumeCapacity(@intCast(self.attributes_extra.items.len));
    }
    return @intCast(gop.index);
}

fn bigIntConstAssumeCapacity(
    self: *Builder,
    ty: Type,
    value: std.math.big.int.Const,
) Allocator.Error!Constant {
    const type_item = self.type_items.items[@intFromEnum(ty)];
    assert(type_item.tag == .integer);
    const bits = type_item.data;

    const ExpectedContents = [64 / @sizeOf(std.math.big.Limb)]std.math.big.Limb;
    var stack align(@alignOf(ExpectedContents)) =
        std.heap.stackFallback(@sizeOf(ExpectedContents), self.gpa);
    const allocator = stack.get();

    var limbs: []std.math.big.Limb = &.{};
    defer allocator.free(limbs);
    const canonical_value = if (value.fitsInTwosComp(.signed, bits)) value else canon: {
        assert(value.fitsInTwosComp(.unsigned, bits));
        limbs = try allocator.alloc(std.math.big.Limb, std.math.big.int.calcTwosCompLimbCount(bits));
        var temp_value = std.math.big.int.Mutable.init(limbs, 0);
        temp_value.truncate(value, .signed, bits);
        break :canon temp_value.toConst();
    };
    assert(canonical_value.fitsInTwosComp(.signed, bits));

    const ExtraPtr = *align(@alignOf(std.math.big.Limb)) Constant.Integer;
    const Key = struct { tag: Constant.Tag, type: Type, limbs: []const std.math.big.Limb };
    const tag: Constant.Tag = switch (canonical_value.positive) {
        true => .positive_integer,
        false => .negative_integer,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(key.tag)));
            hasher.update(std.mem.asBytes(&key.type));
            hasher.update(std.mem.sliceAsBytes(key.limbs));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra: ExtraPtr =
                @ptrCast(ctx.builder.constant_limbs.items[rhs_data..][0..Constant.Integer.limbs]);
            const rhs_limbs = ctx.builder.constant_limbs
                .items[rhs_data + Constant.Integer.limbs ..][0..rhs_extra.limbs_len];
            return lhs_key.type == rhs_extra.type and
                std.mem.eql(std.math.big.Limb, lhs_key.limbs, rhs_limbs);
        }
    };

    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(
        Key{ .tag = tag, .type = ty, .limbs = canonical_value.limbs },
        Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = @intCast(self.constant_limbs.items.len),
        });
        const extra: ExtraPtr =
            @ptrCast(self.constant_limbs.addManyAsArrayAssumeCapacity(Constant.Integer.limbs));
        extra.* = .{ .type = ty, .limbs_len = @intCast(canonical_value.limbs.len) };
        self.constant_limbs.appendSliceAssumeCapacity(canonical_value.limbs);
    }
    return @enumFromInt(gop.index);
}

fn halfConstAssumeCapacity(self: *Builder, val: f16) Constant {
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .half, .data = @as(u16, @bitCast(val)) },
    );
    return result.constant;
}

fn bfloatConstAssumeCapacity(self: *Builder, val: f32) Constant {
    assert(@as(u16, @truncate(@as(u32, @bitCast(val)))) == 0);
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .bfloat, .data = @bitCast(val) },
    );
    return result.constant;
}

fn floatConstAssumeCapacity(self: *Builder, val: f32) Constant {
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .float, .data = @bitCast(val) },
    );
    return result.constant;
}

fn doubleConstAssumeCapacity(self: *Builder, val: f64) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: f64) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Constant.Tag.double)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: f64, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .double) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Double, rhs_data);
            return @as(u64, @bitCast(lhs_key)) == @as(u64, rhs_extra.hi) << 32 | rhs_extra.lo;
        }
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = .double,
            .data = self.addConstantExtraAssumeCapacity(Constant.Double{
                .lo = @truncate(@as(u64, @bitCast(val))),
                .hi = @intCast(@as(u64, @bitCast(val)) >> 32),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn fp128ConstAssumeCapacity(self: *Builder, val: f128) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: f128) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Constant.Tag.fp128)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: f128, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .fp128) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Fp128, rhs_data);
            return @as(u128, @bitCast(lhs_key)) == @as(u128, rhs_extra.hi_hi) << 96 |
                @as(u128, rhs_extra.hi_lo) << 64 | @as(u128, rhs_extra.lo_hi) << 32 | rhs_extra.lo_lo;
        }
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = .fp128,
            .data = self.addConstantExtraAssumeCapacity(Constant.Fp128{
                .lo_lo = @truncate(@as(u128, @bitCast(val))),
                .lo_hi = @truncate(@as(u128, @bitCast(val)) >> 32),
                .hi_lo = @truncate(@as(u128, @bitCast(val)) >> 64),
                .hi_hi = @intCast(@as(u128, @bitCast(val)) >> 96),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn x86_fp80ConstAssumeCapacity(self: *Builder, val: f80) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: f80) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Constant.Tag.x86_fp80)),
                std.mem.asBytes(&key)[0..10],
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: f80, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .x86_fp80) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Fp80, rhs_data);
            return @as(u80, @bitCast(lhs_key)) == @as(u80, rhs_extra.hi) << 64 |
                @as(u80, rhs_extra.lo_hi) << 32 | rhs_extra.lo_lo;
        }
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = .x86_fp80,
            .data = self.addConstantExtraAssumeCapacity(Constant.Fp80{
                .lo_lo = @truncate(@as(u80, @bitCast(val))),
                .lo_hi = @truncate(@as(u80, @bitCast(val)) >> 32),
                .hi = @intCast(@as(u80, @bitCast(val)) >> 64),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn ppc_fp128ConstAssumeCapacity(self: *Builder, val: [2]f64) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: [2]f64) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Constant.Tag.ppc_fp128)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: [2]f64, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .ppc_fp128) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Fp128, rhs_data);
            return @as(u64, @bitCast(lhs_key[0])) == @as(u64, rhs_extra.lo_hi) << 32 | rhs_extra.lo_lo and
                @as(u64, @bitCast(lhs_key[1])) == @as(u64, rhs_extra.hi_hi) << 32 | rhs_extra.hi_lo;
        }
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = .ppc_fp128,
            .data = self.addConstantExtraAssumeCapacity(Constant.Fp128{
                .lo_lo = @truncate(@as(u64, @bitCast(val[0]))),
                .lo_hi = @intCast(@as(u64, @bitCast(val[0])) >> 32),
                .hi_lo = @truncate(@as(u64, @bitCast(val[1]))),
                .hi_hi = @intCast(@as(u64, @bitCast(val[1])) >> 32),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn nullConstAssumeCapacity(self: *Builder, ty: Type) Constant {
    assert(self.type_items.items[@intFromEnum(ty)].tag == .pointer);
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .null, .data = @intFromEnum(ty) },
    );
    return result.constant;
}

fn noneConstAssumeCapacity(self: *Builder, ty: Type) Constant {
    assert(ty == .token);
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .none, .data = @intFromEnum(ty) },
    );
    return result.constant;
}

fn structConstAssumeCapacity(self: *Builder, ty: Type, vals: []const Constant) Constant {
    const type_item = self.type_items.items[@intFromEnum(ty)];
    var extra = self.typeExtraDataTrail(Type.Structure, switch (type_item.tag) {
        .structure, .packed_structure => type_item.data,
        .named_structure => data: {
            const body_ty = self.typeExtraData(Type.NamedStructure, type_item.data).body;
            const body_item = self.type_items.items[@intFromEnum(body_ty)];
            switch (body_item.tag) {
                .structure, .packed_structure => break :data body_item.data,
                else => unreachable,
            }
        },
        else => unreachable,
    });
    const fields = extra.trail.next(extra.data.fields_len, Type, self);
    for (fields, vals) |field, val| assert(field == val.typeOf(self));

    for (vals) |val| {
        if (!val.isZeroInit(self)) break;
    } else return self.zeroInitConstAssumeCapacity(ty);

    const tag: Constant.Tag = switch (ty.unnamedTag(self)) {
        .structure => .structure,
        .packed_structure => .packed_structure,
        else => unreachable,
    };
    const result = self.getOrPutConstantAggregateAssumeCapacity(tag, ty, vals);
    return result.constant;
}

fn arrayConstAssumeCapacity(self: *Builder, ty: Type, vals: []const Constant) Constant {
    const type_item = self.type_items.items[@intFromEnum(ty)];
    const type_extra: struct { len: u64, child: Type } = switch (type_item.tag) {
        inline .small_array, .array => |kind| extra: {
            const extra = self.typeExtraData(switch (kind) {
                .small_array => Type.Vector,
                .array => Type.Array,
                else => unreachable,
            }, type_item.data);
            break :extra .{ .len = extra.length(), .child = extra.child };
        },
        else => unreachable,
    };
    assert(type_extra.len == vals.len);
    for (vals) |val| assert(type_extra.child == val.typeOf(self));

    for (vals) |val| {
        if (!val.isZeroInit(self)) break;
    } else return self.zeroInitConstAssumeCapacity(ty);

    const result = self.getOrPutConstantAggregateAssumeCapacity(.array, ty, vals);
    return result.constant;
}

fn stringConstAssumeCapacity(self: *Builder, val: String) Constant {
    const slice = val.slice(self).?;
    const ty = self.arrayTypeAssumeCapacity(slice.len, .i8);
    if (std.mem.allEqual(u8, slice, 0)) return self.zeroInitConstAssumeCapacity(ty);
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .string, .data = @intFromEnum(val) },
    );
    return result.constant;
}

fn vectorConstAssumeCapacity(self: *Builder, ty: Type, vals: []const Constant) Constant {
    assert(ty.isVector(self));
    assert(ty.vectorLen(self) == vals.len);
    for (vals) |val| assert(ty.childType(self) == val.typeOf(self));

    for (vals[1..]) |val| {
        if (vals[0] != val) break;
    } else return self.splatConstAssumeCapacity(ty, vals[0]);
    for (vals) |val| {
        if (!val.isZeroInit(self)) break;
    } else return self.zeroInitConstAssumeCapacity(ty);

    const result = self.getOrPutConstantAggregateAssumeCapacity(.vector, ty, vals);
    return result.constant;
}

fn splatConstAssumeCapacity(self: *Builder, ty: Type, val: Constant) Constant {
    assert(ty.scalarType(self) == val.typeOf(self));

    if (!ty.isVector(self)) return val;
    if (val.isZeroInit(self)) return self.zeroInitConstAssumeCapacity(ty);

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant.Splat) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Constant.Tag.splat)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Constant.Splat, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .splat) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Splat, rhs_data);
            return std.meta.eql(lhs_key, rhs_extra);
        }
    };
    const data = Constant.Splat{ .type = ty, .value = val };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = .splat,
            .data = self.addConstantExtraAssumeCapacity(data),
        });
    }
    return @enumFromInt(gop.index);
}

fn zeroInitConstAssumeCapacity(self: *Builder, ty: Type) Constant {
    switch (ty) {
        inline .half,
        .bfloat,
        .float,
        .double,
        .fp128,
        .x86_fp80,
        => |tag| return @field(Builder, @tagName(tag) ++ "ConstAssumeCapacity")(self, 0.0),
        .ppc_fp128 => return self.ppc_fp128ConstAssumeCapacity(.{ 0.0, 0.0 }),
        .token => return .none,
        .i1 => return .false,
        else => switch (self.type_items.items[@intFromEnum(ty)].tag) {
            .simple,
            .function,
            .vararg_function,
            => unreachable,
            .integer => {
                var limbs: [std.math.big.int.calcLimbLen(0)]std.math.big.Limb = undefined;
                const bigint = std.math.big.int.Mutable.init(&limbs, 0);
                return self.bigIntConstAssumeCapacity(ty, bigint.toConst()) catch unreachable;
            },
            .pointer => return self.nullConstAssumeCapacity(ty),
            .target,
            .vector,
            .scalable_vector,
            .small_array,
            .array,
            .structure,
            .packed_structure,
            .named_structure,
            => {},
        },
    }
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .zeroinitializer, .data = @intFromEnum(ty) },
    );
    return result.constant;
}

fn undefConstAssumeCapacity(self: *Builder, ty: Type) Constant {
    switch (self.type_items.items[@intFromEnum(ty)].tag) {
        .simple => switch (ty) {
            .void, .label => unreachable,
            else => {},
        },
        .function, .vararg_function => unreachable,
        else => {},
    }
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .undef, .data = @intFromEnum(ty) },
    );
    return result.constant;
}

fn poisonConstAssumeCapacity(self: *Builder, ty: Type) Constant {
    switch (self.type_items.items[@intFromEnum(ty)].tag) {
        .simple => switch (ty) {
            .void, .label => unreachable,
            else => {},
        },
        .function, .vararg_function => unreachable,
        else => {},
    }
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .poison, .data = @intFromEnum(ty) },
    );
    return result.constant;
}

fn blockAddrConstAssumeCapacity(
    self: *Builder,
    function: Function.Index,
    block: Function.Block.Index,
) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant.BlockAddress) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@intFromEnum(Constant.Tag.blockaddress)),
                std.mem.asBytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Constant.BlockAddress, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .blockaddress) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.BlockAddress, rhs_data);
            return std.meta.eql(lhs_key, rhs_extra);
        }
    };
    const data = Constant.BlockAddress{ .function = function, .block = block };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = .blockaddress,
            .data = self.addConstantExtraAssumeCapacity(data),
        });
    }
    return @enumFromInt(gop.index);
}

fn dsoLocalEquivalentConstAssumeCapacity(self: *Builder, function: Function.Index) Constant {
    const result = self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .dso_local_equivalent, .data = @intFromEnum(function) },
    );
    return result.constant;
}

fn noCfiConstAssumeCapacity(self: *Builder, function: Function.Index) Constant {
    const result ```
