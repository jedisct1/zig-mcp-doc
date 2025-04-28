```
= self.getOrPutConstantNoExtraAssumeCapacity(
        .{ .tag = .no_cfi, .data = @intFromEnum(function) },
    );
    return result.constant;
}

fn convTag(
    self: *Builder,
    signedness: Constant.Cast.Signedness,
    val_ty: Type,
    ty: Type,
) Function.Instruction.Tag {
    assert(val_ty != ty);
    return switch (val_ty.scalarTag(self)) {
        .simple => switch (ty.scalarTag(self)) {
            .simple => switch (std.math.order(val_ty.scalarBits(self), ty.scalarBits(self))) {
                .lt => .fpext,
                .eq => unreachable,
                .gt => .fptrunc,
            },
            .integer => switch (signedness) {
                .unsigned => .fptoui,
                .signed => .fptosi,
                .unneeded => unreachable,
            },
            else => unreachable,
        },
        .integer => switch (ty.scalarTag(self)) {
            .simple => switch (signedness) {
                .unsigned => .uitofp,
                .signed => .sitofp,
                .unneeded => unreachable,
            },
            .integer => switch (std.math.order(val_ty.scalarBits(self), ty.scalarBits(self))) {
                .lt => switch (signedness) {
                    .unsigned => .zext,
                    .signed => .sext,
                    .unneeded => unreachable,
                },
                .eq => unreachable,
                .gt => .trunc,
            },
            .pointer => .inttoptr,
            else => unreachable,
        },
        .pointer => switch (ty.scalarTag(self)) {
            .integer => .ptrtoint,
            .pointer => .addrspacecast,
            else => unreachable,
        },
        else => unreachable,
    };
}

fn convConstTag(
    self: *Builder,
    val_ty: Type,
    ty: Type,
) Constant.Tag {
    assert(val_ty != ty);
    return switch (val_ty.scalarTag(self)) {
        .integer => switch (ty.scalarTag(self)) {
            .integer => switch (std.math.order(val_ty.scalarBits(self), ty.scalarBits(self))) {
                .gt => .trunc,
                else => unreachable,
            },
            .pointer => .inttoptr,
            else => unreachable,
        },
        .pointer => switch (ty.scalarTag(self)) {
            .integer => .ptrtoint,
            .pointer => .addrspacecast,
            else => unreachable,
        },
        else => unreachable,
    };
}

fn convConstAssumeCapacity(
    self: *Builder,
    val: Constant,
    ty: Type,
) Constant {
    const val_ty = val.typeOf(self);
    if (val_ty == ty) return val;
    return self.castConstAssumeCapacity(self.convConstTag(val_ty, ty), val, ty);
}

fn castConstAssumeCapacity(self: *Builder, tag: Constant.Tag, val: Constant, ty: Type) Constant {
    const Key = struct { tag: Constant.Tag, cast: Constant.Cast };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@intFromEnum(key.tag)),
                std.mem.asBytes(&key.cast),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Cast, rhs_data);
            return std.meta.eql(lhs_key.cast, rhs_extra);
        }
    };
    const data = Key{ .tag = tag, .cast = .{ .val = val, .type = ty } };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addConstantExtraAssumeCapacity(data.cast),
        });
    }
    return @enumFromInt(gop.index);
}

fn gepConstAssumeCapacity(
    self: *Builder,
    comptime kind: Constant.GetElementPtr.Kind,
    ty: Type,
    base: Constant,
    inrange: ?u16,
    indices: []const Constant,
) Constant {
    const tag: Constant.Tag = switch (kind) {
        .normal => .getelementptr,
        .inbounds => .@"getelementptr inbounds",
    };
    const base_ty = base.typeOf(self);
    const base_is_vector = base_ty.isVector(self);

    const VectorInfo = struct {
        kind: Type.Vector.Kind,
        len: u32,

        fn init(vector_ty: Type, builder: *const Builder) @This() {
            return .{ .kind = vector_ty.vectorKind(builder), .len = vector_ty.vectorLen(builder) };
        }
    };
    var vector_info: ?VectorInfo = if (base_is_vector) VectorInfo.init(base_ty, self) else null;
    for (indices) |index| {
        const index_ty = index.typeOf(self);
        switch (index_ty.tag(self)) {
            .integer => {},
            .vector, .scalable_vector => {
                const index_info = VectorInfo.init(index_ty, self);
                if (vector_info) |info|
                    assert(std.meta.eql(info, index_info))
                else
                    vector_info = index_info;
            },
            else => unreachable,
        }
    }
    if (!base_is_vector) if (vector_info) |info| switch (info.kind) {
        inline else => |vector_kind| _ = self.vectorTypeAssumeCapacity(vector_kind, info.len, base_ty),
    };

    const Key = struct {
        type: Type,
        base: Constant,
        inrange: Constant.GetElementPtr.InRangeIndex,
        indices: []const Constant,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(comptime std.hash.uint32(@intFromEnum(tag)));
            hasher.update(std.mem.asBytes(&key.type));
            hasher.update(std.mem.asBytes(&key.base));
            hasher.update(std.mem.asBytes(&key.inrange));
            hasher.update(std.mem.sliceAsBytes(key.indices));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != tag) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.constantExtraDataTrail(Constant.GetElementPtr, rhs_data);
            const rhs_indices =
                rhs_extra.trail.next(rhs_extra.data.info.indices_len, Constant, ctx.builder);
            return lhs_key.type == rhs_extra.data.type and lhs_key.base == rhs_extra.data.base and
                lhs_key.inrange == rhs_extra.data.info.inrange and
                std.mem.eql(Constant, lhs_key.indices, rhs_indices);
        }
    };
    const data = Key{
        .type = ty,
        .base = base,
        .inrange = if (inrange) |index| @enumFromInt(index) else .none,
        .indices = indices,
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addConstantExtraAssumeCapacity(Constant.GetElementPtr{
                .type = ty,
                .base = base,
                .info = .{ .indices_len = @intCast(indices.len), .inrange = data.inrange },
            }),
        });
        self.constant_extra.appendSliceAssumeCapacity(@ptrCast(indices));
    }
    return @enumFromInt(gop.index);
}

fn binConstAssumeCapacity(
    self: *Builder,
    tag: Constant.Tag,
    lhs: Constant,
    rhs: Constant,
) Constant {
    switch (tag) {
        .add,
        .@"add nsw",
        .@"add nuw",
        .sub,
        .@"sub nsw",
        .@"sub nuw",
        .shl,
        .xor,
        => {},
        else => unreachable,
    }
    const Key = struct { tag: Constant.Tag, extra: Constant.Binary };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@intFromEnum(key.tag)),
                std.mem.asBytes(&key.extra),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Binary, rhs_data);
            return std.meta.eql(lhs_key.extra, rhs_extra);
        }
    };
    const data = Key{ .tag = tag, .extra = .{ .lhs = lhs, .rhs = rhs } };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addConstantExtraAssumeCapacity(data.extra),
        });
    }
    return @enumFromInt(gop.index);
}

fn asmConstAssumeCapacity(
    self: *Builder,
    ty: Type,
    info: Constant.Assembly.Info,
    assembly: String,
    constraints: String,
) Constant {
    assert(ty.functionKind(self) == .normal);

    const Key = struct { tag: Constant.Tag, extra: Constant.Assembly };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@intFromEnum(key.tag)),
                std.mem.asBytes(&key.extra),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constantExtraData(Constant.Assembly, rhs_data);
            return std.meta.eql(lhs_key.extra, rhs_extra);
        }
    };

    const data = Key{
        .tag = @enumFromInt(@intFromEnum(Constant.Tag.@"asm") + @as(u4, @bitCast(info))),
        .extra = .{ .type = ty, .assembly = assembly, .constraints = constraints },
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = data.tag,
            .data = self.addConstantExtraAssumeCapacity(data.extra),
        });
    }
    return @enumFromInt(gop.index);
}

fn ensureUnusedConstantCapacity(
    self: *Builder,
    count: usize,
    comptime Extra: type,
    trail_len: usize,
) Allocator.Error!void {
    try self.constant_map.ensureUnusedCapacity(self.gpa, count);
    try self.constant_items.ensureUnusedCapacity(self.gpa, count);
    try self.constant_extra.ensureUnusedCapacity(
        self.gpa,
        count * (@typeInfo(Extra).@"struct".fields.len + trail_len),
    );
}

fn getOrPutConstantNoExtraAssumeCapacity(
    self: *Builder,
    item: Constant.Item,
) struct { new: bool, constant: Constant } {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant.Item) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@intFromEnum(key.tag)),
                std.mem.asBytes(&key.data),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Constant.Item, _: void, rhs_index: usize) bool {
            return std.meta.eql(lhs_key, ctx.builder.constant_items.get(rhs_index));
        }
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(item, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(item);
    }
    return .{ .new = !gop.found_existing, .constant = @enumFromInt(gop.index) };
}

fn getOrPutConstantAggregateAssumeCapacity(
    self: *Builder,
    tag: Constant.Tag,
    ty: Type,
    vals: []const Constant,
) struct { new: bool, constant: Constant } {
    switch (tag) {
        .structure, .packed_structure, .array, .vector => {},
        else => unreachable,
    }
    const Key = struct { tag: Constant.Tag, type: Type, vals: []const Constant };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(key.tag)));
            hasher.update(std.mem.asBytes(&key.type));
            hasher.update(std.mem.sliceAsBytes(key.vals));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.constantExtraDataTrail(Constant.Aggregate, rhs_data);
            if (lhs_key.type != rhs_extra.data.type) return false;
            const rhs_vals = rhs_extra.trail.next(@intCast(lhs_key.vals.len), Constant, ctx.builder);
            return std.mem.eql(Constant, lhs_key.vals, rhs_vals);
        }
    };
    const gop = self.constant_map.getOrPutAssumeCapacityAdapted(
        Key{ .tag = tag, .type = ty, .vals = vals },
        Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addConstantExtraAssumeCapacity(Constant.Aggregate{ .type = ty }),
        });
        self.constant_extra.appendSliceAssumeCapacity(@ptrCast(vals));
    }
    return .{ .new = !gop.found_existing, .constant = @enumFromInt(gop.index) };
}

fn addConstantExtraAssumeCapacity(self: *Builder, extra: anytype) Constant.Item.ExtraIndex {
    const result: Constant.Item.ExtraIndex = @intCast(self.constant_extra.items.len);
    inline for (@typeInfo(@TypeOf(extra)).@"struct".fields) |field| {
        const value = @field(extra, field.name);
        self.constant_extra.appendAssumeCapacity(switch (field.type) {
            u32 => value,
            String, Type, Constant, Function.Index, Function.Block.Index => @intFromEnum(value),
            Constant.GetElementPtr.Info => @bitCast(value),
            else => @compileError("bad field type: " ++ @typeName(field.type)),
        });
    }
    return result;
}

const ConstantExtraDataTrail = struct {
    index: Constant.Item.ExtraIndex,

    fn nextMut(self: *ConstantExtraDataTrail, len: u32, comptime Item: type, builder: *Builder) []Item {
        const items: []Item = @ptrCast(builder.constant_extra.items[self.index..][0..len]);
        self.index += @intCast(len);
        return items;
    }

    fn next(
        self: *ConstantExtraDataTrail,
        len: u32,
        comptime Item: type,
        builder: *const Builder,
    ) []const Item {
        const items: []const Item = @ptrCast(builder.constant_extra.items[self.index..][0..len]);
        self.index += @intCast(len);
        return items;
    }
};

fn constantExtraDataTrail(
    self: *const Builder,
    comptime T: type,
    index: Constant.Item.ExtraIndex,
) struct { data: T, trail: ConstantExtraDataTrail } {
    var result: T = undefined;
    const fields = @typeInfo(T).@"struct".fields;
    inline for (fields, self.constant_extra.items[index..][0..fields.len]) |field, value|
        @field(result, field.name) = switch (field.type) {
            u32 => value,
            String, Type, Constant, Function.Index, Function.Block.Index => @enumFromInt(value),
            Constant.GetElementPtr.Info => @bitCast(value),
            else => @compileError("bad field type: " ++ @typeName(field.type)),
        };
    return .{
        .data = result,
        .trail = .{ .index = index + @as(Constant.Item.ExtraIndex, @intCast(fields.len)) },
    };
}

fn constantExtraData(self: *const Builder, comptime T: type, index: Constant.Item.ExtraIndex) T {
    return self.constantExtraDataTrail(T, index).data;
}

fn ensureUnusedMetadataCapacity(
    self: *Builder,
    count: usize,
    comptime Extra: type,
    trail_len: usize,
) Allocator.Error!void {
    try self.metadata_map.ensureUnusedCapacity(self.gpa, count);
    try self.metadata_items.ensureUnusedCapacity(self.gpa, count);
    try self.metadata_extra.ensureUnusedCapacity(
        self.gpa,
        count * (@typeInfo(Extra).@"struct".fields.len + trail_len),
    );
}

fn addMetadataExtraAssumeCapacity(self: *Builder, extra: anytype) Metadata.Item.ExtraIndex {
    const result: Metadata.Item.ExtraIndex = @intCast(self.metadata_extra.items.len);
    inline for (@typeInfo(@TypeOf(extra)).@"struct".fields) |field| {
        const value = @field(extra, field.name);
        self.metadata_extra.appendAssumeCapacity(switch (field.type) {
            u32 => value,
            MetadataString, Metadata, Variable.Index, Value => @intFromEnum(value),
            Metadata.DIFlags => @bitCast(value),
            else => @compileError("bad field type: " ++ @typeName(field.type)),
        });
    }
    return result;
}

const MetadataExtraDataTrail = struct {
    index: Metadata.Item.ExtraIndex,

    fn nextMut(self: *MetadataExtraDataTrail, len: u32, comptime Item: type, builder: *Builder) []Item {
        const items: []Item = @ptrCast(builder.metadata_extra.items[self.index..][0..len]);
        self.index += @intCast(len);
        return items;
    }

    fn next(
        self: *MetadataExtraDataTrail,
        len: u32,
        comptime Item: type,
        builder: *const Builder,
    ) []const Item {
        const items: []const Item = @ptrCast(builder.metadata_extra.items[self.index..][0..len]);
        self.index += @intCast(len);
        return items;
    }
};

fn metadataExtraDataTrail(
    self: *const Builder,
    comptime T: type,
    index: Metadata.Item.ExtraIndex,
) struct { data: T, trail: MetadataExtraDataTrail } {
    var result: T = undefined;
    const fields = @typeInfo(T).@"struct".fields;
    inline for (fields, self.metadata_extra.items[index..][0..fields.len]) |field, value|
        @field(result, field.name) = switch (field.type) {
            u32 => value,
            MetadataString, Metadata, Variable.Index, Value => @enumFromInt(value),
            Metadata.DIFlags => @bitCast(value),
            else => @compileError("bad field type: " ++ @typeName(field.type)),
        };
    return .{
        .data = result,
        .trail = .{ .index = index + @as(Metadata.Item.ExtraIndex, @intCast(fields.len)) },
    };
}

fn metadataExtraData(self: *const Builder, comptime T: type, index: Metadata.Item.ExtraIndex) T {
    return self.metadataExtraDataTrail(T, index).data;
}

pub fn metadataString(self: *Builder, bytes: []const u8) Allocator.Error!MetadataString {
    try self.metadata_string_bytes.ensureUnusedCapacity(self.gpa, bytes.len);
    try self.metadata_string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.metadata_string_map.ensureUnusedCapacity(self.gpa, 1);

    const gop = self.metadata_string_map.getOrPutAssumeCapacityAdapted(
        bytes,
        MetadataString.Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        self.metadata_string_bytes.appendSliceAssumeCapacity(bytes);
        self.metadata_string_indices.appendAssumeCapacity(@intCast(self.metadata_string_bytes.items.len));
    }
    return @enumFromInt(gop.index);
}

pub fn metadataStringFromStrtabString(self: *Builder, str: StrtabString) Allocator.Error!MetadataString {
    if (str == .none or str == .empty) return MetadataString.none;
    return try self.metadataString(str.slice(self).?);
}

pub fn metadataStringFmt(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) Allocator.Error!MetadataString {
    try self.metadata_string_map.ensureUnusedCapacity(self.gpa, 1);
    try self.metadata_string_bytes.ensureUnusedCapacity(self.gpa, @intCast(std.fmt.count(fmt_str, fmt_args)));
    try self.metadata_string_indices.ensureUnusedCapacity(self.gpa, 1);
    return self.metadataStringFmtAssumeCapacity(fmt_str, fmt_args);
}

pub fn metadataStringFmtAssumeCapacity(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) MetadataString {
    self.metadata_string_bytes.writer(undefined).print(fmt_str, fmt_args) catch unreachable;
    return self.trailingMetadataStringAssumeCapacity();
}

pub fn trailingMetadataString(self: *Builder) Allocator.Error!MetadataString {
    try self.metadata_string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.metadata_string_map.ensureUnusedCapacity(self.gpa, 1);
    return self.trailingMetadataStringAssumeCapacity();
}

pub fn trailingMetadataStringAssumeCapacity(self: *Builder) MetadataString {
    const start = self.metadata_string_indices.getLast();
    const bytes: []const u8 = self.metadata_string_bytes.items[start..];
    const gop = self.metadata_string_map.getOrPutAssumeCapacityAdapted(bytes, String.Adapter{ .builder = self });
    if (gop.found_existing) {
        self.metadata_string_bytes.shrinkRetainingCapacity(start);
    } else {
        self.metadata_string_indices.appendAssumeCapacity(@intCast(self.metadata_string_bytes.items.len));
    }
    return @enumFromInt(gop.index);
}

pub fn metadataNamed(self: *Builder, name: MetadataString, operands: []const Metadata) Allocator.Error!void {
    try self.metadata_extra.ensureUnusedCapacity(self.gpa, operands.len);
    try self.metadata_named.ensureUnusedCapacity(self.gpa, 1);
    self.metadataNamedAssumeCapacity(name, operands);
}

fn metadataNone(self: *Builder) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, NoExtra, 0);
    return self.metadataNoneAssumeCapacity();
}

pub fn debugFile(
    self: *Builder,
    filename: MetadataString,
    directory: MetadataString,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.File, 0);
    return self.debugFileAssumeCapacity(filename, directory);
}

pub fn debugCompileUnit(
    self: *Builder,
    file: Metadata,
    producer: MetadataString,
    enums: Metadata,
    globals: Metadata,
    options: Metadata.CompileUnit.Options,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.CompileUnit, 0);
    return self.debugCompileUnitAssumeCapacity(file, producer, enums, globals, options);
}

pub fn debugSubprogram(
    self: *Builder,
    file: Metadata,
    name: MetadataString,
    linkage_name: MetadataString,
    line: u32,
    scope_line: u32,
    ty: Metadata,
    options: Metadata.Subprogram.Options,
    compile_unit: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.Subprogram, 0);
    return self.debugSubprogramAssumeCapacity(
        file,
        name,
        linkage_name,
        line,
        scope_line,
        ty,
        options,
        compile_unit,
    );
}

pub fn debugLexicalBlock(self: *Builder, scope: Metadata, file: Metadata, line: u32, column: u32) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.LexicalBlock, 0);
    return self.debugLexicalBlockAssumeCapacity(scope, file, line, column);
}

pub fn debugLocation(self: *Builder, line: u32, column: u32, scope: Metadata, inlined_at: Metadata) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.Location, 0);
    return self.debugLocationAssumeCapacity(line, column, scope, inlined_at);
}

pub fn debugBoolType(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.BasicType, 0);
    return self.debugBoolTypeAssumeCapacity(name, size_in_bits);
}

pub fn debugUnsignedType(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.BasicType, 0);
    return self.debugUnsignedTypeAssumeCapacity(name, size_in_bits);
}

pub fn debugSignedType(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.BasicType, 0);
    return self.debugSignedTypeAssumeCapacity(name, size_in_bits);
}

pub fn debugFloatType(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.BasicType, 0);
    return self.debugFloatTypeAssumeCapacity(name, size_in_bits);
}

pub fn debugForwardReference(self: *Builder) Allocator.Error!Metadata {
    try self.metadata_forward_references.ensureUnusedCapacity(self.gpa, 1);
    return self.debugForwardReferenceAssumeCapacity();
}

pub fn debugStructType(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.CompositeType, 0);
    return self.debugStructTypeAssumeCapacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debugUnionType(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.CompositeType, 0);
    return self.debugUnionTypeAssumeCapacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debugEnumerationType(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.CompositeType, 0);
    return self.debugEnumerationTypeAssumeCapacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debugArrayType(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.CompositeType, 0);
    return self.debugArrayTypeAssumeCapacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debugVectorType(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.CompositeType, 0);
    return self.debugVectorTypeAssumeCapacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debugPointerType(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.DerivedType, 0);
    return self.debugPointerTypeAssumeCapacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        offset_in_bits,
    );
}

pub fn debugMemberType(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.DerivedType, 0);
    return self.debugMemberTypeAssumeCapacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        offset_in_bits,
    );
}

pub fn debugSubroutineType(
    self: *Builder,
    types_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.SubroutineType, 0);
    return self.debugSubroutineTypeAssumeCapacity(types_tuple);
}

pub fn debugEnumerator(
    self: *Builder,
    name: MetadataString,
    unsigned: bool,
    bit_width: u32,
    value: std.math.big.int.Const,
) Allocator.Error!Metadata {
    assert(!(unsigned and !value.positive));
    try self.ensureUnusedMetadataCapacity(1, Metadata.Enumerator, 0);
    try self.metadata_limbs.ensureUnusedCapacity(self.gpa, value.limbs.len);
    return self.debugEnumeratorAssumeCapacity(name, unsigned, bit_width, value);
}

pub fn debugSubrange(
    self: *Builder,
    lower_bound: Metadata,
    count: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.Subrange, 0);
    return self.debugSubrangeAssumeCapacity(lower_bound, count);
}

pub fn debugExpression(
    self: *Builder,
    elements: []const u32,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.Expression, elements.len);
    return self.debugExpressionAssumeCapacity(elements);
}

pub fn metadataTuple(
    self: *Builder,
    elements: []const Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.Tuple, elements.len);
    return self.metadataTupleAssumeCapacity(elements);
}

pub fn strTuple(
    self: *Builder,
    str: MetadataString,
    elements: []const Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.StrTuple, elements.len);
    return self.strTupleAssumeCapacity(str, elements);
}

pub fn metadataModuleFlag(
    self: *Builder,
    behavior: Metadata,
    name: MetadataString,
    constant: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.ModuleFlag, 0);
    return self.metadataModuleFlagAssumeCapacity(behavior, name, constant);
}

pub fn debugLocalVar(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.LocalVar, 0);
    return self.debugLocalVarAssumeCapacity(name, file, scope, line, ty);
}

pub fn debugParameter(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    arg_no: u32,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.Parameter, 0);
    return self.debugParameterAssumeCapacity(name, file, scope, line, ty, arg_no);
}

pub fn debugGlobalVar(
    self: *Builder,
    name: MetadataString,
    linkage_name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    variable: Variable.Index,
    options: Metadata.GlobalVar.Options,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.GlobalVar, 0);
    return self.debugGlobalVarAssumeCapacity(
        name,
        linkage_name,
        file,
        scope,
        line,
        ty,
        variable,
        options,
    );
}

pub fn debugGlobalVarExpression(
    self: *Builder,
    variable: Metadata,
    expression: Metadata,
) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, Metadata.GlobalVarExpression, 0);
    return self.debugGlobalVarExpressionAssumeCapacity(variable, expression);
}

pub fn metadataConstant(self: *Builder, value: Constant) Allocator.Error!Metadata {
    try self.ensureUnusedMetadataCapacity(1, NoExtra, 0);
    return self.metadataConstantAssumeCapacity(value);
}

pub fn debugForwardReferenceSetType(self: *Builder, fwd_ref: Metadata, ty: Metadata) void {
    assert(
        @intFromEnum(fwd_ref) >= Metadata.first_forward_reference and
            @intFromEnum(fwd_ref) <= Metadata.first_local_metadata,
    );
    const index = @intFromEnum(fwd_ref) - Metadata.first_forward_reference;
    self.metadata_forward_references.items[index] = ty;
}

fn metadataSimpleAssumeCapacity(self: *Builder, tag: Metadata.Tag, value: anytype) Metadata {
    const Key = struct {
        tag: Metadata.Tag,
        value: @TypeOf(value),
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(key.tag)));
            inline for (std.meta.fields(@TypeOf(value))) |field| {
                hasher.update(std.mem.asBytes(&@field(key.value, field.name)));
            }
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.metadataExtraData(@TypeOf(value), rhs_data);
            return std.meta.eql(lhs_key.value, rhs_extra);
        }
    };

    const gop = self.metadata_map.getOrPutAssumeCapacityAdapted(
        Key{ .tag = tag, .value = value },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addMetadataExtraAssumeCapacity(value),
        });
    }
    return @enumFromInt(gop.index);
}

fn metadataDistinctAssumeCapacity(self: *Builder, tag: Metadata.Tag, value: anytype) Metadata {
    const Key = struct { tag: Metadata.Tag, index: Metadata };
    const Adapter = struct {
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@intFromEnum(key.tag)),
                std.mem.asBytes(&key.index),
            ));
        }

        pub fn eql(_: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            return @intFromEnum(lhs_key.index) == rhs_index;
        }
    };

    const gop = self.metadata_map.getOrPutAssumeCapacityAdapted(
        Key{ .tag = tag, .index = @enumFromInt(self.metadata_map.count()) },
        Adapter{},
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addMetadataExtraAssumeCapacity(value),
        });
    }
    return @enumFromInt(gop.index);
}

fn metadataNamedAssumeCapacity(self: *Builder, name: MetadataString, operands: []const Metadata) void {
    assert(name != .none);
    const extra_index: u32 = @intCast(self.metadata_extra.items.len);
    self.metadata_extra.appendSliceAssumeCapacity(@ptrCast(operands));

    const gop = self.metadata_named.getOrPutAssumeCapacity(name);
    gop.value_ptr.* = .{
        .index = extra_index,
        .len = @intCast(operands.len),
    };
}

pub fn metadataNoneAssumeCapacity(self: *Builder) Metadata {
    return self.metadataSimpleAssumeCapacity(.none, .{});
}

fn debugFileAssumeCapacity(
    self: *Builder,
    filename: MetadataString,
    directory: MetadataString,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.file, Metadata.File{
        .filename = filename,
        .directory = directory,
    });
}

pub fn debugCompileUnitAssumeCapacity(
    self: *Builder,
    file: Metadata,
    producer: MetadataString,
    enums: Metadata,
    globals: Metadata,
    options: Metadata.CompileUnit.Options,
) Metadata {
    assert(!self.strip);
    return self.metadataDistinctAssumeCapacity(
        if (options.optimized) .@"compile_unit optimized" else .compile_unit,
        Metadata.CompileUnit{
            .file = file,
            .producer = producer,
            .enums = enums,
            .globals = globals,
        },
    );
}

fn debugSubprogramAssumeCapacity(
    self: *Builder,
    file: Metadata,
    name: MetadataString,
    linkage_name: MetadataString,
    line: u32,
    scope_line: u32,
    ty: Metadata,
    options: Metadata.Subprogram.Options,
    compile_unit: Metadata,
) Metadata {
    assert(!self.strip);
    const tag: Metadata.Tag = @enumFromInt(@intFromEnum(Metadata.Tag.subprogram) +
        @as(u3, @truncate(@as(u32, @bitCast(options.sp_flags)) >> 2)));
    return self.metadataDistinctAssumeCapacity(tag, Metadata.Subprogram{
        .file = file,
        .name = name,
        .linkage_name = linkage_name,
        .line = line,
        .scope_line = scope_line,
        .ty = ty,
        .di_flags = options.di_flags,
        .compile_unit = compile_unit,
    });
}

fn debugLexicalBlockAssumeCapacity(self: *Builder, scope: Metadata, file: Metadata, line: u32, column: u32) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.lexical_block, Metadata.LexicalBlock{
        .scope = scope,
        .file = file,
        .line = line,
        .column = column,
    });
}

fn debugLocationAssumeCapacity(self: *Builder, line: u32, column: u32, scope: Metadata, inlined_at: Metadata) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.location, Metadata.Location{
        .line = line,
        .column = column,
        .scope = scope,
        .inlined_at = inlined_at,
    });
}

fn debugBoolTypeAssumeCapacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.basic_bool_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debugUnsignedTypeAssumeCapacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.basic_unsigned_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debugSignedTypeAssumeCapacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.basic_signed_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debugFloatTypeAssumeCapacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.basic_float_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debugForwardReferenceAssumeCapacity(self: *Builder) Metadata {
    assert(!self.strip);
    const index = Metadata.first_forward_reference + self.metadata_forward_references.items.len;
    self.metadata_forward_references.appendAssumeCapacity(.none);
    return @enumFromInt(index);
}

fn debugStructTypeAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debugCompositeTypeAssumeCapacity(
        .composite_struct_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debugUnionTypeAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debugCompositeTypeAssumeCapacity(
        .composite_union_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debugEnumerationTypeAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debugCompositeTypeAssumeCapacity(
        .composite_enumeration_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debugArrayTypeAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debugCompositeTypeAssumeCapacity(
        .composite_array_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debugVectorTypeAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debugCompositeTypeAssumeCapacity(
        .composite_vector_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debugCompositeTypeAssumeCapacity(
    self: *Builder,
    tag: Metadata.Tag,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(tag, Metadata.CompositeType{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .underlying_type = underlying_type,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
        .align_in_bits_lo = @truncate(align_in_bits),
        .align_in_bits_hi = @truncate(align_in_bits >> 32),
        .fields_tuple = fields_tuple,
    });
}

fn debugPointerTypeAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.derived_pointer_type, Metadata.DerivedType{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .underlying_type = underlying_type,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
        .align_in_bits_lo = @truncate(align_in_bits),
        .align_in_bits_hi = @truncate(align_in_bits >> 32),
        .offset_in_bits_lo = @truncate(offset_in_bits),
        .offset_in_bits_hi = @truncate(offset_in_bits >> 32),
    });
}

fn debugMemberTypeAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.derived_member_type, Metadata.DerivedType{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .underlying_type = underlying_type,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
        .align_in_bits_lo = @truncate(align_in_bits),
        .align_in_bits_hi = @truncate(align_in_bits >> 32),
        .offset_in_bits_lo = @truncate(offset_in_bits),
        .offset_in_bits_hi = @truncate(offset_in_bits >> 32),
    });
}

fn debugSubroutineTypeAssumeCapacity(
    self: *Builder,
    types_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.subroutine_type, Metadata.SubroutineType{
        .types_tuple = types_tuple,
    });
}

fn debugEnumeratorAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    unsigned: bool,
    bit_width: u32,
    value: std.math.big.int.Const,
) Metadata {
    assert(!self.strip);
    const Key = struct {
        tag: Metadata.Tag,
        name: MetadataString,
        bit_width: u32,
        value: std.math.big.int.Const,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(key.tag)));
            hasher.update(std.mem.asBytes(&key.name));
            hasher.update(std.mem.asBytes(&key.bit_width));
            hasher.update(std.mem.sliceAsBytes(key.value.limbs));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.metadataExtraData(Metadata.Enumerator, rhs_data);
            const limbs = ctx.builder.metadata_limbs
                .items[rhs_extra.limbs_index..][0..rhs_extra.limbs_len];
            const rhs_value = std.math.big.int.Const{
                .limbs = limbs,
                .positive = lhs_key.value.positive,
            };
            return lhs_key.name == rhs_extra.name and
                lhs_key.bit_width == rhs_extra.bit_width and
                lhs_key.value.eql(rhs_value);
        }
    };

    const tag: Metadata.Tag = if (unsigned)
        .enumerator_unsigned
    else if (value.positive)
        .enumerator_signed_positive
    else
        .enumerator_signed_negative;

    assert(!(tag == .enumerator_unsigned and !value.positive));

    const gop = self.metadata_map.getOrPutAssumeCapacityAdapted(
        Key{
            .tag = tag,
            .name = name,
            .bit_width = bit_width,
            .value = value,
        },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.appendAssumeCapacity(.{
            .tag = tag,
            .data = self.addMetadataExtraAssumeCapacity(Metadata.Enumerator{
                .name = name,
                .bit_width = bit_width,
                .limbs_index = @intCast(self.metadata_limbs.items.len),
                .limbs_len = @intCast(value.limbs.len),
            }),
        });
        self.metadata_limbs.appendSliceAssumeCapacity(value.limbs);
    }
    return @enumFromInt(gop.index);
}

fn debugSubrangeAssumeCapacity(
    self: *Builder,
    lower_bound: Metadata,
    count: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.subrange, Metadata.Subrange{
        .lower_bound = lower_bound,
        .count = count,
    });
}

fn debugExpressionAssumeCapacity(
    self: *Builder,
    elements: []const u32,
) Metadata {
    assert(!self.strip);
    const Key = struct {
        elements: []const u32,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = comptime std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(Metadata.Tag.expression)));
            hasher.update(std.mem.sliceAsBytes(key.elements));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (Metadata.Tag.expression != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.metadataExtraDataTrail(Metadata.Expression, rhs_data);
            return std.mem.eql(
                u32,
                lhs_key.elements,
                rhs_extra.trail.next(rhs_extra.data.elements_len, u32, ctx.builder),
            );
        }
    };

    const gop = self.metadata_map.getOrPutAssumeCapacityAdapted(
        Key{ .elements = elements },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.appendAssumeCapacity(.{
            .tag = .expression,
            .data = self.addMetadataExtraAssumeCapacity(Metadata.Expression{
                .elements_len = @intCast(elements.len),
            }),
        });
        self.metadata_extra.appendSliceAssumeCapacity(@ptrCast(elements));
    }
    return @enumFromInt(gop.index);
}

fn metadataTupleAssumeCapacity(
    self: *Builder,
    elements: []const Metadata,
) Metadata {
    const Key = struct {
        elements: []const Metadata,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = comptime std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(Metadata.Tag.tuple)));
            hasher.update(std.mem.sliceAsBytes(key.elements));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (Metadata.Tag.tuple != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.metadataExtraDataTrail(Metadata.Tuple, rhs_data);
            return std.mem.eql(
                Metadata,
                lhs_key.elements,
                rhs_extra.trail.next(rhs_extra.data.elements_len, Metadata, ctx.builder),
            );
        }
    };

    const gop = self.metadata_map.getOrPutAssumeCapacityAdapted(
        Key{ .elements = elements },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.appendAssumeCapacity(.{
            .tag = .tuple,
            .data = self.addMetadataExtraAssumeCapacity(Metadata.Tuple{
                .elements_len = @intCast(elements.len),
            }),
        });
        self.metadata_extra.appendSliceAssumeCapacity(@ptrCast(elements));
    }
    return @enumFromInt(gop.index);
}

fn strTupleAssumeCapacity(
    self: *Builder,
    str: MetadataString,
    elements: []const Metadata,
) Metadata {
    const Key = struct {
        str: MetadataString,
        elements: []const Metadata,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = comptime std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(Metadata.Tag.tuple)));
            hasher.update(std.mem.sliceAsBytes(key.elements));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (.str_tuple != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.metadataExtraDataTrail(Metadata.StrTuple, rhs_data);
            return rhs_extra.data.str == lhs_key.str and std.mem.eql(
                Metadata,
                lhs_key.elements,
                rhs_extra.trail.next(rhs_extra.data.elements_len, Metadata, ctx.builder),
            );
        }
    };

    const gop = self.metadata_map.getOrPutAssumeCapacityAdapted(
        Key{ .str = str, .elements = elements },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.appendAssumeCapacity(.{
            .tag = .str_tuple,
            .data = self.addMetadataExtraAssumeCapacity(Metadata.StrTuple{
                .str = str,
                .elements_len = @intCast(elements.len),
            }),
        });
        self.metadata_extra.appendSliceAssumeCapacity(@ptrCast(elements));
    }
    return @enumFromInt(gop.index);
}

fn metadataModuleFlagAssumeCapacity(
    self: *Builder,
    behavior: Metadata,
    name: MetadataString,
    constant: Metadata,
) Metadata {
    return self.metadataSimpleAssumeCapacity(.module_flag, Metadata.ModuleFlag{
        .behavior = behavior,
        .name = name,
        .constant = constant,
    });
}

fn debugLocalVarAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.local_var, Metadata.LocalVar{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .ty = ty,
    });
}

fn debugParameterAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    arg_no: u32,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.parameter, Metadata.Parameter{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .ty = ty,
        .arg_no = arg_no,
    });
}

fn debugGlobalVarAssumeCapacity(
    self: *Builder,
    name: MetadataString,
    linkage_name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    variable: Variable.Index,
    options: Metadata.GlobalVar.Options,
) Metadata {
    assert(!self.strip);
    return self.metadataDistinctAssumeCapacity(
        if (options.local) .@"global_var local" else .global_var,
        Metadata.GlobalVar{
            .name = name,
            .linkage_name = linkage_name,
            .file = file,
            .scope = scope,
            .line = line,
            .ty = ty,
            .variable = variable,
        },
    );
}

fn debugGlobalVarExpressionAssumeCapacity(
    self: *Builder,
    variable: Metadata,
    expression: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadataSimpleAssumeCapacity(.global_var_expression, Metadata.GlobalVarExpression{
        .variable = variable,
        .expression = expression,
    });
}

fn metadataConstantAssumeCapacity(self: *Builder, constant: Constant) Metadata {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant) u32 {
            var hasher = comptime std.hash.Wyhash.init(std.hash.uint32(@intFromEnum(Metadata.Tag.constant)));
            hasher.update(std.mem.asBytes(&key));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Constant, _: void, rhs_index: usize) bool {
            if (Metadata.Tag.constant != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data: Constant = @enumFromInt(ctx.builder.metadata_items.items(.data)[rhs_index]);
            return rhs_data == lhs_key;
        }
    };

    const gop = self.metadata_map.getOrPutAssumeCapacityAdapted(
        constant,
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.appendAssumeCapacity(.{
            .tag = .constant,
            .data = @intFromEnum(constant),
        });
    }
    return @enumFromInt(gop.index);
}

pub const Producer = struct {
    name: []const u8,
    version: std.SemanticVersion,
};

pub fn toBitcode(self: *Builder, allocator: Allocator, producer: Producer) bitcode_writer.Error![]const u32 {
    const BitcodeWriter = bitcode_writer.BitcodeWriter(&.{ Type, FunctionAttributes });
    var bitcode = BitcodeWriter.init(allocator, .{
        std.math.log2_int_ceil(usize, self.type_items.items.len),
        std.math.log2_int_ceil(usize, 1 + self.function_attributes_set.count()),
    });
    errdefer bitcode.deinit();

    // Write LLVM IR magic
    try bitcode.writeBits(ir.MAGIC, 32);

    var record: std.ArrayListUnmanaged(u64) = .empty;
    defer record.deinit(self.gpa);

    // IDENTIFICATION_BLOCK
    {
        const Identification = ir.Identification;
        var identification_block = try bitcode.enterTopBlock(Identification);

        const producer_str = try std.fmt.allocPrint(self.gpa, "{s} {d}.{d}.{d}", .{
            producer.name,
            producer.version.major,
            producer.version.minor,
            producer.version.patch,
        });
        defer self.gpa.free(producer_str);

        try identification_block.writeAbbrev(Identification.Version{ .string = producer_str });
        try identification_block.writeAbbrev(Identification.Epoch{ .epoch = 0 });

        try identification_block.end();
    }

    // MODULE_BLOCK
    {
        const Module = ir.Module;
        var module_block = try bitcode.enterTopBlock(Module);

        try module_block.writeAbbrev(Module.Version{});

        if (self.target_triple.slice(self)) |triple| {
            try module_block.writeAbbrev(Module.String{
                .code = 2,
                .string = triple,
            });
        }

        if (self.data_layout.slice(self)) |data_layout| {
            try module_block.writeAbbrev(Module.String{
                .code = 3,
                .string = data_layout,
            });
        }

        if (self.source_filename.slice(self)) |source_filename| {
            try module_block.writeAbbrev(Module.String{
                .code = 16,
                .string = source_filename,
            });
        }

        if (self.module_asm.items.len != 0) {
            try module_block.writeAbbrev(Module.String{
                .code = 4,
                .string = self.module_asm.items,
            });
        }

        // TYPE_BLOCK
        {
            var type_block = try module_block.enterSubBlock(ir.Type, true);

            try type_block.writeAbbrev(ir.Type.NumEntry{ .num = @intCast(self.type_items.items.len) });

            for (self.type_items.items, 0..) |item, i| {
                const ty: Type = @enumFromInt(i);

                switch (item.tag) {
                    .simple => try type_block.writeAbbrev(ir.Type.Simple{ .code = @truncate(item.data) }),
                    .integer => try type_block.writeAbbrev(ir.Type.Integer{ .width = item.data }),
                    .structure,
                    .packed_structure,
                    => |kind| {
                        const is_packed = switch (kind) {
                            .structure => false,
                            .packed_structure => true,
                            else => unreachable,
                        };
                        var extra = self.typeExtraDataTrail(Type.Structure, item.data);
                        try type_block.writeAbbrev(ir.Type.StructAnon{
                            .is_packed = is_packed,
                            .types = extra.trail.next(extra.data.fields_len, Type, self),
                        });
                    },
                    .named_structure => {
                        const extra = self.typeExtraData(Type.NamedStructure, item.data);
                        try type_block.writeAbbrev(ir.Type.StructName{
                            .string = extra.id.slice(self).?,
                        });

                        switch (extra.body) {
                            .none => try type_block.writeAbbrev(ir.Type.Opaque{}),
                            else => {
                                const real_struct = self.type_items.items[@intFromEnum(extra.body)];
                                const is_packed: bool = switch (real_struct.tag) {
                                    .structure => false,
                                    .packed_structure => true,
                                    else => unreachable,
                                };

                                var real_extra = self.typeExtraDataTrail(Type.Structure, real_struct.data);
                                try type_block.writeAbbrev(ir.Type.StructNamed{
                                    .is_packed = is_packed,
                                    .types = real_extra.trail.next(real_extra.data.fields_len, Type, self),
                                });
                            },
                        }
                    },
                    .array,
                    .small_array,
                    => try type_block.writeAbbrev(ir.Type.Array{
                        .len = ty.aggregateLen(self),
                        .child = ty.childType(self),
                    }),
                    .vector,
                    .scalable_vector,
                    => try type_block.writeAbbrev(ir.Type.Vector{
                        .len = ty.aggregateLen(self),
                        .child = ty.childType(self),
                    }),
                    .pointer => try type_block.writeAbbrev(ir.Type.Pointer{
                        .addr_space = ty.pointerAddrSpace(self),
                    }),
                    .target => {
                        var extra = self.typeExtraDataTrail(Type.Target, item.data);
                        try type_block.writeAbbrev(ir.Type.StructName{
                            .string = extra.data.name.slice(self).?,
                        });

                        const types = extra.trail.next(extra.data.types_len, Type, self);
                        const ints = extra.trail.next(extra.data.ints_len, u32, self);

                        try type_block.writeAbbrev(ir.Type.Target{
                            .num_types = extra.data.types_len,
                            .types = types,
                            .ints = ints,
                        });
                    },
                    .function, .vararg_function => |kind| {
                        const is_vararg = switch (kind) {
                            .function => false,
                            .vararg_function => true,
                            else => unreachable,
                        };
                        var extra = self.typeExtraDataTrail(Type.Function, item.data);
                        try type_block.writeAbbrev(ir.Type.Function{
                            .is_vararg = is_vararg,
                            .return_type = extra.data.ret,
                            .param_types = extra.trail.next(extra.data.params_len, Type, self),
                        });
                    },
                }
            }

            try type_block.end();
        }

        var attributes_set: std.AutoArrayHashMapUnmanaged(struct {
            attributes: Attributes,
            index: u32,
        }, void) = .{};
        defer attributes_set.deinit(self.gpa);

        // PARAMATTR_GROUP_BLOCK
        {
            const ParamattrGroup = ir.ParamattrGroup;

            var paramattr_group_block = try module_block.enterSubBlock(ParamattrGroup, true);

            for (self.function_attributes_set.keys()) |func_attributes| {
                for (func_attributes.slice(self), 0..) |attributes, i| {
                    const attributes_slice = attributes.slice(self);
                    if (attributes_slice.len == 0) continue;

                    const attr_gop = try attributes_set.getOrPut(self.gpa, .{
                        .attributes = attributes,
                        .index = @intCast(i),
                    });

                    if (attr_gop.found_existing) continue;

                    record.clearRetainingCapacity();
                    try record.ensureUnusedCapacity(self.gpa, 2);

                    record.appendAssumeCapacity(attr_gop.index);
                    record.appendAssumeCapacity(switch (i) {
                        0 => 0xffffffff,
                        else => i - 1,
                    });

                    for (attributes_slice) |attr_index| {
                        const kind = attr_index.getKind(self);
                        switch (attr_index.toAttribute(self)) {
                            .zeroext,
                            .signext,
                            .inreg,
                            .@"noalias",
                            .nocapture,
                            .nofree,
                            .nest,
                            .returned,
                            .nonnull,
                            .swiftself,
                            .swiftasync,
                            .swifterror,
                            .immarg,
                            .noundef,
                            .allocalign,
                            .allocptr,
                            .readnone,
                            .readonly,
                            .writeonly,
                            .alwaysinline,
                            .builtin,
                            .cold,
                            .convergent,
                            .disable_sanitizer_information,
                            .fn_ret_thunk_extern,
                            .hot,
                            .inlinehint,
                            .jumptable,
                            .minsize,
                            .naked,
                            .nobuiltin,
                            .nocallback,
                            .noduplicate,
                            .noimplicitfloat,
                            .@"noinline",
                            .nomerge,
                            .nonlazybind,
                            .noprofile,
                            .skipprofile,
                            .noredzone,
                            .noreturn,
                            .norecurse,
                            .willreturn,
                            .nosync,
                            .nounwind,
                            .nosanitize_bounds,
                            .nosanitize_coverage,
                            .null_pointer_is_valid,
                            .optforfuzzing,
                            .optnone,
                            .optsize,
                            .returns_twice,
                            .safestack,
                            .sanitize_address,
                            .sanitize_memory,
                            .sanitize_thread,
                            .sanitize_hwaddress,
                            .sanitize_memtag,
                            .speculative_load_hardening,
                            .speculatable,
                            .ssp,
                            .sspstrong,
                            .sspreq,
                            .strictfp,
                            .nocf_check,
                            .shadowcallstack,
                            .mustprogress,
                            .no_sanitize_address,
                            .no_sanitize_hwaddress,
                            .sanitize_address_dyninit,
                            => {
                                try record.ensureUnusedCapacity(self.gpa, 2);
                                record.appendAssumeCapacity(0);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                            },
                            .byval,
                            .byref,
                            .preallocated,
                            .inalloca,
                            .sret,
                            .elementtype,
                            => |ty| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(6);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(@intFromEnum(ty));
                            },
                            .@"align",
                            .alignstack,
                            => |alignment| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(alignment.toByteUnits() orelse 0);
                            },
                            .dereferenceable,
                            .dereferenceable_or_null,
                            => |size| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(size);
                            },
                            .nofpclass => |fpclass| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(@as(u32, @bitCast(fpclass)));
                            },
                            .allockind => |allockind| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(@as(u32, @bitCast(allockind)));
                            },

                            .allocsize => |allocsize| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(@bitCast(allocsize.toLlvm()));
                            },
                            .memory => |memory| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(@as(u32, @bitCast(memory)));
                            },
                            .uwtable => |uwtable| if (uwtable != .none) {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(@intFromEnum(uwtable));
                            },
                            .vscale_range => |vscale_range| {
                                try record.ensureUnusedCapacity(self.gpa, 3);
                                record.appendAssumeCapacity(1);
                                record.appendAssumeCapacity(@intFromEnum(kind));
                                record.appendAssumeCapacity(@bitCast(vscale_range.toLlvm()));
                            },
                            .string => |string_attr| {
                                const string_attr_kind_slice = string_attr.kind.slice(self).?;
                                const string_attr_value_slice = if (string_attr.value != .none)
                                    string_attr.value.slice(self).?
                                else
                                    null;

                                try record.ensureUnusedCapacity(
                                    self.gpa,
                                    2 + string_attr_kind_slice.len + if (string_attr_value_slice) |slice| slice.len + 1 else 0,
                                );
                                record.appendAssumeCapacity(if (string_attr.value == .none) 3 else 4);
                                for (string_attr.kind.slice(self).?) |c| {
                                    record.appendAssumeCapacity(c);
                                }
                                record.appendAssumeCapacity(0);
                                if (string_attr_value_slice) |slice| {
                                    for (slice) |c| {
                                        record.appendAssumeCapacity(c);
                                    }
                                    record.appendAssumeCapacity(0);
                                }
                            },
                            .none => unreachable,
                        }
                    }

                    try paramattr_group_block.writeUnabbrev(3, record.items);
                }
            }

            try paramattr_group_block.end();
        }

        // PARAMATTR_BLOCK
        {
            const Paramattr = ir.Paramattr;
            var paramattr_block = try module_block.enterSubBlock(Paramattr, true);

            for (self.function_attributes_set.keys()) |func_attributes| {
                const func_attributes_slice = func_attributes.slice(self);
                record.clearRetainingCapacity();
                try record.ensureUnusedCapacity(self.gpa, func_attributes_slice.len);
                for (func_attributes_slice, 0..) |attributes, i| {
                    const attributes_slice = attributes.slice(self);
                    if (attributes_slice.len == 0) continue;

                    const group_index = attributes_set.getIndex(.{
                        .attributes = attributes,
                        .index = @intCast(i),
                    }).?;
                    record.appendAssumeCapacity(@intCast(group_index));
                }

                try paramattr_block.writeAbbrev(Paramattr.Entry{ .group_indices = record.items });
            }

            try paramattr_block.end();
        }

        var globals: std.AutoArrayHashMapUnmanaged(Global.Index, void) = .empty;
        defer globals.deinit(self.gpa);
        try globals.ensureUnusedCapacity(
            self.gpa,
            self.variables.items.len +
                self.functions.items.len +
                self.aliases.items.len,
        );

        for (self.variables.items) |variable| {
            if (variable.global.getReplacement(self) != .none) continue;

            globals.putAssumeCapacity(variable.global, {});
        }

        for (self.functions.items) |function| {
            if (function.global.getReplacement(self) != .none) continue;

            globals.putAssumeCapacity(function.global, {});
        }

        for (self.aliases.items) |alias| {
            if (alias.global.getReplacement(self) != .none) continue;

            globals.putAssumeCapacity(alias.global, {});
        }

        const ConstantAdapter = struct {
            const ConstantAdapter = @This();
            builder: *const Builder,
            globals: *const std.AutoArrayHashMapUnmanaged(Global.Index, void),

            pub fn get(adapter: @This(), param: anytype, comptime field_name: []const u8) @TypeOf(param) {
                _ = field_name;
                return switch (@TypeOf(param)) {
                    Constant => @enumFromInt(adapter.getConstantIndex(param)),
                    else => param,
                };
            }

            pub fn getConstantIndex(adapter: ConstantAdapter, constant: Constant) u32 {
                return switch (constant.unwrap()) {
                    .constant => |c| c + adapter.numGlobals(),
                    .global => |global| @intCast(adapter.globals.getIndex(global.unwrap(adapter.builder)).?),
                };
            }

            pub fn numConstants(adapter: ConstantAdapter) u32 {
                return @intCast(adapter.globals.count() + adapter.builder.constant_items.len);
            }

            pub fn numGlobals(adapter: ConstantAdapter) u32 {
                return @intCast(adapter.globals.count());
            }
        };

        const constant_adapter = ConstantAdapter{
            .builder = self,
            .globals = &globals,
        };

        // Globals
        {
            var section_map: std.AutoArrayHashMapUnmanaged(String, void) = .empty;
            defer section_map.deinit(self.gpa);
            try section_map.ensureUnusedCapacity(self.gpa, globals.count());

            for (self.variables.items) |variable| {
                if (variable.global.getReplacement(self) != .none) continue;

                const section = blk: {
                    if (variable.section == .none) break :blk 0;
                    const gop = section_map.getOrPutAssumeCapacity(variable.section);
                    if (!gop.found_existing) {
                        try module_block.writeAbbrev(Module.String{
                            .code = 5,
                            .string = variable.section.slice(self).?,
                        });
                    }
                    break :blk gop.index + 1;
                };

                const initid = if (variable.init == .no_init)
                    0
                else
                    (constant_adapter.getConstantIndex(variable.init) + 1);

                const strtab = variable.global.strtab(self);

                const global = variable.global.ptrConst(self);
                try module_block.writeAbbrev(Module.Variable{
                    .strtab_offset = strtab.offset,
                    .strtab_size = strtab.size,
                    .type_index = global.type,
                    .is_const = .{
                        .is_const = switch (variable.mutability) {
                            .global => false,
                            .constant => true,
                        },
                        .addr_space = global.addr_space,
                    },
                    .initid = initid,
                    .linkage = global.linkage,
                    .alignment = variable.alignment.toLlvm(),
                    .section = section,
                    .visibility = global.visibility,
                    .thread_local = variable.thread_local,
                    .unnamed_addr = global.unnamed_addr,
                    .externally_initialized = global.externally_initialized,
                    .dllstorageclass = global.dll_storage_class,
                    .preemption = global.preemption,
                });
            }

            for (self.functions.items) |func| {
                if (func.global.getReplacement(self) != .none) continue;

                const section = blk: {
                    if (func.section == .none) break :blk 0;
                    const gop = section_map.getOrPutAssumeCapacity(func.section);
                    if (!gop.found_existing) {
                        try module_block.writeAbbrev(Module.String{
                            .code = 5,
                            .string = func.section.slice(self).?,
                        });
                    }
                    break :blk gop.index + 1;
                };

                const paramattr_index = if (self.function_attributes_set.getIndex(func.attributes)) |index|
                    index + 1
                else
                    0;

                const strtab = func.global.strtab(self);

                const global = func.global.ptrConst(self);
                try module_block.writeAbbrev(Module.Function{
                    .strtab_offset = strtab.offset,
                    .strtab_size = strtab.size,
                    .type_index = global.type,
                    .call_conv = func.call_conv,
                    .is_proto = func.instructions.len == 0,
                    .linkage = global.linkage,
                    .paramattr = paramattr_index,
                    .alignment = func.alignment.toLlvm(),
                    .section = section,
                    .visibility = global.visibility,
                    .unnamed_addr = global.unnamed_addr,
                    .dllstorageclass = global.dll_storage_class,
                    .preemption = global.preemption,
                    .addr_space = global.addr_space,
                });
            }

            for (self.aliases.items) |alias| {
                if (alias.global.getReplacement(self) != .none) continue;

                const strtab = alias.global.strtab(self);

                const global = alias.global.ptrConst(self);
                try module_block.writeAbbrev(Module.Alias{
                    .strtab_offset = strtab.offset,
                    .strtab_size = strtab.size,
                    .type_index = global.type,
                    .addr_space = global.addr_space,
                    .aliasee = constant_adapter.getConstantIndex(alias.aliasee),
                    .linkage = global.linkage,
                    .visibility = global.visibility,
                    .thread_local = alias.thread_local,
                    .unnamed_addr = global.unnamed_addr,
                    .dllstorageclass = global.dll_storage_class,
                    .preemption = global.preemption,
                });
            }
        }

        // CONSTANTS_BLOCK
        {
            const Constants = ir.Constants;
            var constants_block = try module_block.enterSubBlock(Constants, true);

            var current_type: Type = .none;
            const tags = self.constant_items.items(.tag);
            const datas = self.constant_items.items(.data);
            for (0..self.constant_items.len) |index| {
                record.clearRetainingCapacity();
                const constant: Constant = @enumFromInt(index);
                const constant_type = constant.typeOf(self);
                if (constant_type != current_type) {
                    try constants_block.writeAbbrev(Constants.SetType{ .type_id = constant_type });
                    current_type = constant_type;
                }
                const data = datas[index];
                switch (tags[index]) {
                    .null,
                    .zeroinitializer,
                    .none,
                    => try constants_block.writeAbbrev(Constants.Null{}),
                    .undef => try constants_block.writeAbbrev(Constants.Undef{}),
                    .poison => try constants_block.writeAbbrev(Constants.Poison{}),
                    .positive_integer,
                    .negative_integer,
                    => |tag| {
                        const extra: *align(@alignOf(std.math.big.Limb)) Constant.Integer =
                            @ptrCast(self.constant_limbs.items[data..][0..Constant.Integer.limbs]);
                        const bigint: std.math.big.int.Const = .{
                            .limbs = self.constant_limbs
                                .items[data + Constant.Integer.limbs ..][0..extra.limbs_len],
                            .positive = switch (tag) {
                                .positive_integer => true,
                                .negative_integer => false,
                                else => unreachable,
                            },
                        };
                        const bit_count = extra.type.scalarBits(self);
                        const val: i64 = if (bit_count <= 64)
                            bigint.toInt(i64) catch unreachable
                        else if (bigint.toInt(u64)) |val|
                            @bitCast(val)
                        else |_| {
                            const limbs = try record.addManyAsSlice(
                                self.gpa,
                                std.math.divCeil(u24, bit_count, 64) catch unreachable,
                            );
                            bigint.writeTwosComplement(std.mem.sliceAsBytes(limbs), .little);
                            for (limbs) |*limb| {
                                const val = std.mem.littleToNative(i64, @bitCast(limb.*));
                                limb.* = @bitCast(if (val >= 0)
                                    val << 1 | 0
                                else
                                    -%val << 1 | 1);
                            }
                            try constants_block.writeUnabbrev(5, record.items);
                            continue;
                        };
                        try constants_block.writeAbbrev(Constants.Integer{
                            .value = @bitCast(if (val >= 0)
                                val << 1 | 0
                            else
                                -%val << 1 | 1),
                        });
                    },
                    .half,
                    .bfloat,
                    => try constants_block.writeAbbrev(Constants.Half{ .value = @truncate(data) }),
                    .float => try constants_block.writeAbbrev(Constants.Float{ .value = data }),
                    .double => {
                        const extra = self.constantExtraData(Constant.Double, data);
                        try constants_block.writeAbbrev(Constants.Double{
                            .value = (@as(u64, extra.hi) << 32) | extra.lo,
                        });
                    },
                    .x86_fp80 => {
                        const extra = self.constantExtraData(Constant.Fp80, data);
                        try constants_block.writeAbbrev(Constants.Fp80{
                            .hi = @as(u64, extra.hi) << 48 | @as(u64, extra.lo_hi) << 16 |
                                extra.lo_lo >> 16,
                            .lo = @truncate(extra.lo_lo),
                        });
                    },
                    .fp128,
                    .ppc_fp128,
                    => {
                        const extra = self.constantExtraData(Constant.Fp128, data);
                        try constants_block.writeAbbrev(Constants.Fp128{
                            .lo = @as(u64, extra.lo_hi) << 32 | @as(u64, extra.lo_lo),
                            .hi = @as(u64, extra.hi_hi) << 32 | @as(u64, extra.hi_lo),
                        });
                    },
                    .array,
                    .vector,
                    .structure,
                    .packed_structure,
                    => {
                        var extra = self.constantExtraDataTrail(Constant.Aggregate, data);
                        const len: u32 = @intCast(extra.data.type.aggregateLen(self));
                        const values = extra.trail.next(len, Constant, self);

                        try constants_block.writeAbbrevAdapted(
                            Constants.Aggregate{ .values = values },
                            constant_adapter,
                        );
                    },
                    .splat => {
                        const ConstantsWriter = @TypeOf(constants_block);
                        const extra = self.constantExtraData(Constant.Splat, data);
                        const vector_len = extra.type.vectorLen(self);
                        const c = constant_adapter.getConstantIndex(extra.value);

                        try bitcode.writeBits(
                            ConstantsWriter.abbrevId(Constants.Aggregate),
                            ConstantsWriter.abbrev_len,
                        );
                        try bitcode.writeVBR(vector_len, 6);
                        for (0..vector_len) |_| {
                            try bitcode.writeBits(c, Constants.Aggregate.ops[1].array_fixed);
                        }
                    },
                    .string => {
                        const str: String = @enumFromInt(data);
                        if (str == .none) {
                            try constants_block.writeAbbrev(Constants.Null{});
                        } else {
                            const slice = str.slice(self).?;
                            if (slice.len > 0 and slice[slice.len - 1] == 0)
                                try constants_block.writeAbbrev(Constants.CString{ .string = slice[0 .. slice.len - 1] })
                            else
                                try constants_block.writeAbbrev(Constants.String{ .string = slice });
                        }
                    },
                    .bitcast,
                    .inttoptr,
                    .ptrtoint,
                    .addrspacecast,
                    .trunc,
                    => |tag| {
                        const extra = self.constantExtraData(Constant.Cast, data);
                        try constants_block.writeAbbrevAdapted(Constants.Cast{
                            .type_index = extra.type,
                            .val = extra.val,
                            .opcode = tag.toCastOpcode(),
                        }, constant_adapter);
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
                        const extra = self.constantExtraData(Constant.Binary, data);
                        try constants_block.writeAbbrevAdapted(Constants.Binary{
                            .opcode = tag.toBinaryOpcode(),
                            .lhs = extra.lhs,
                            .rhs = extra.rhs,
                        }, constant_adapter);
                    },
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => |tag| {
                        var extra = self.constantExtraDataTrail(Constant.GetElementPtr, data);
                        const indices = extra.trail.next(extra.data.info.indices_len, Constant, self);
                        try record.ensureUnusedCapacity(self.gpa, 1 + 2 + 2 * indices.len);

                        record.appendAssumeCapacity(@intFromEnum(extra.data.type));

                        record.appendAssumeCapacity(@intFromEnum(extra.data.base.typeOf(self)));
                        record.appendAssumeCapacity(constant_adapter.getConstantIndex(extra.data.base));

                        for (indices) |i| {
                            record.appendAssumeCapacity(@intFromEnum(i.typeOf(self)));
                            record.appendAssumeCapacity(constant_adapter.getConstantIndex(i));
                        }

                        try constants_block.writeUnabbrev(switch (tag) {
                            .getelementptr => 12,
                            .@"getelementptr inbounds" => 20,
                            else => unreachable,
                        }, record.items);
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
                        const extra = self.constantExtraData(Constant.Assembly, data);

                        const assembly_slice = extra.assembly.slice(self).?;
                        const constraints_slice = extra.constraints.slice(self).?;

                        try record.ensureUnusedCapacity(self.gpa, 4 + assembly_slice.len + constraints_slice.len);

                        record.appendAssumeCapacity(@intFromEnum(extra.type));
                        record.appendAssumeCapacity(switch (tag) {
                            .@"asm" => 0,
                            .@"asm sideeffect" => 0b0001,
                            .@"asm sideeffect alignstack" => 0b0011,
                            .@"asm sideeffect inteldialect" => 0b0101,
                            .@"asm sideeffect alignstack inteldialect" => 0b0111,
                            .@"asm sideeffect unwind" => 0b1001,
                            .@"asm sideeffect alignstack unwind" => 0b1011,
                            .@"asm sideeffect inteldialect unwind" => 0b1101,
                            .@"asm sideeffect alignstack inteldialect unwind" => 0b1111,
                            .@"asm alignstack" => 0b0010,
                            .@"asm inteldialect" => 0b0100,
                            .@"asm alignstack inteldialect" => 0b0110,
                            .@"asm unwind" => 0b1000,
                            .@"asm alignstack unwind" => 0b1010,
                            .@"asm inteldialect unwind" => 0b1100,
                            .@"asm alignstack inteldialect unwind" => 0b1110,
                            else => unreachable,
                        });

                        record.appendAssumeCapacity(assembly_slice.len);
                        for (assembly_slice) |c| record.appendAssumeCapacity(c);

                        record.appendAssumeCapacity(constraints_slice.len);
                        for (constraints_slice) |c| record.appendAssumeCapacity(c);

                        try constants_block.writeUnabbrev(30, record.items);
                    },
                    .blockaddress => {
                        const extra = self.constantExtraData(Constant.BlockAddress, data);
                        try constants_block.writeAbbrev(Constants.BlockAddress{
                            .type_id = extra.function.typeOf(self),
                            .function = constant_adapter.getConstantIndex(extra.function.toConst(self)),
                            .block = @intFromEnum(extra.block),
                        });
                    },
                    .dso_local_equivalent,
                    .no_cfi,
                    => |tag| {
                        const function: Function.Index = @enumFromInt(data);
                        try constants_block.writeAbbrev(Constants.DsoLocalEquivalentOrNoCfi{
                            .code = switch (tag) {
                                .dso_local_equivalent => 27,
                                .no_cfi => 29,
                                else => unreachable,
                            },
                            .type_id = function.typeOf(self),
                            .function = constant_adapter.getConstantIndex(function.toConst(self)),
                        });
                    },
                }
            }

            try constants_block.end();
        }

        // METADATA_KIND_BLOCK
        {
            const MetadataKindBlock = ir.MetadataKindBlock;
            var metadata_kind_block = try module_block.enterSubBlock(MetadataKindBlock, true);

            inline for (@typeInfo(ir.FixedMetadataKind).@"enum".fields) |field| {
                // don't include `dbg` in stripped functions
                if (!(self.strip and std.mem.eql(u8, field.name, "dbg"))) {
                    try metadata_kind_block.writeAbbrev(MetadataKindBlock.Kind{
                        .id = field.value,
                        .name = field.name,
                    });
                }
            }

            try metadata_kind_block.end();
        }

        const MetadataAdapter = struct {
            builder: *const Builder,
            constant_adapter: ConstantAdapter,

            pub fn init(
                builder: *const Builder,
                const_adapter: ConstantAdapter,
            ) @This() {
                return .{
                    .builder = builder,
                    .constant_adapter = const_adapter,
                };
            }

            pub fn get(adapter: @This(), value: anytype, comptime field_name: []const u8) @TypeOf(value) {
                _ = field_name;
                const Ty = @TypeOf(value);
                return switch (Ty) {
                    Metadata => @enumFromInt(adapter.getMetadataIndex(value)),
                    MetadataString => @enumFromInt(adapter.getMetadataStringIndex(value)),
                    Constant => @enumFromInt(adapter.constant_adapter.getConstantIndex(value)),
                    else => value,
                };
            }

            pub fn getMetadataIndex(adapter: @This(), metadata: Metadata) u32 {
                if (metadata == .none) return 0;
                return @intCast(adapter.builder.metadata_string_map.count() +
                    @intFromEnum(metadata.unwrap(adapter.builder)) - 1);
            }

            pub fn getMetadataStringIndex(_: @This(), metadata_string: MetadataString) u32 {
                return @intFromEnum(metadata_string);
            }
        };

        const metadata_adapter = MetadataAdapter.init(self, constant_adapter);

        // METADATA_BLOCK
        {
            const MetadataBlock = ir.MetadataBlock;
            var metadata_block = try module_block.enterSubBlock(MetadataBlock, true);

            const MetadataBlockWriter = @TypeOf(metadata_block);

            // Emit all MetadataStrings
            if (self.metadata_string_map.count() > 1) {
                const strings_offset, const strings_size = blk: {
                    var strings_offset: u32 = 0;
                    var strings_size: u32 = 0;
                    for (1..self.metadata_string_map.count()) |metadata_string_index| {
                        const metadata_string: MetadataString = @enumFromInt(metadata_string_index);
                        const slice = metadata_string.slice(self);
                        strings_offset += bitcode.bitsVBR(@as(u32, @intCast(slice.len)), 6);
                        strings_size += @intCast(slice.len * 8);
                    }
                    break :blk .{
                        std.mem.alignForward(u32, strings_offset, 32) / 8,
                        std.mem.alignForward(u32, strings_size, 32) / 8,
                    };
                };

                try bitcode.writeBits(
                    comptime MetadataBlockWriter.abbrevId(MetadataBlock.Strings),
                    MetadataBlockWriter.abbrev_len,
                );

                try bitcode.writeVBR(@as(u32, @intCast(self.metadata_string_map.count() - 1)), 6);
                try bitcode.writeVBR(strings_offset, 6);

                try bitcode.writeVBR(strings_size + strings_offset, 6);

                try bitcode.alignTo32();

                for (1..self.metadata_string_map.c```
